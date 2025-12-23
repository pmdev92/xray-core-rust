use crate::common::address::Address;
use crate::common::buffer_manager::BufferHandle;
use crate::common::constants::MAX_UDP_BUFFER_CAPACITY;
use crate::common::net_location::NetLocation;
use crate::core::io::AsyncXrayUdpStream;
use crate::core::transport::XrayTransport;
use crate::outbound::socks5::protocol;
use bytes::Bytes;
use futures::{Sink, Stream};
use std::io;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use tokio::io::ReadBuf;
use tokio::net::UdpSocket;

pub(crate) struct Socks5UdpStream {
    stream: Box<dyn XrayTransport>,
    net_location: Arc<NetLocation>,
    udp_socket: UdpSocket,
    buffer_manager: Box<dyn BufferHandle>,
    flushed: bool,
    data: Option<Bytes>,
}
impl Socks5UdpStream {
    pub async fn new(
        context: Arc<crate::Context>,
        net_location: Arc<NetLocation>,
        stream: Box<dyn XrayTransport>,
        udp_socket: UdpSocket,
    ) -> Result<Self, io::Error> {
        let mut buffer_manager = context
            .get_buffer_manager()
            .get_buffer(MAX_UDP_BUFFER_CAPACITY)
            .await?;
        Ok(Self {
            net_location,
            stream,
            udp_socket,
            buffer_manager,
            flushed: true,
            data: None,
        })
    }
}

impl Stream for Socks5UdpStream {
    type Item = Bytes;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let Self {
            ref mut udp_socket,
            ref mut buffer_manager,
            ..
        } = *self;
        let buf_slice = buffer_manager.data();
        let mut rb = ReadBuf::new(buf_slice);
        match ready!(udp_socket.poll_recv_from(cx, &mut rb)) {
            Ok(_src) => {
                let sock_udp_packet = rb.filled().to_vec();
                let len = sock_udp_packet.len();
                if sock_udp_packet[0] != 0 || sock_udp_packet[1] != 0 && sock_udp_packet[2] != 0 {
                    return Poll::Ready(None);
                }
                let Ok(target_location_udp) = read_target_location_udp(&sock_udp_packet) else {
                    return Poll::Ready(None);
                };
                let (end_index, _) = target_location_udp;
                let socks_udp_data = sock_udp_packet[end_index..len].to_vec();
                Poll::Ready(Some(Bytes::from(socks_udp_data)))
            }
            Err(_) => Poll::Ready(None),
        }
    }
}

impl Sink<Bytes> for Socks5UdpStream {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if !self.flushed {
            match <Self as Sink<Bytes>>::poll_flush(self, cx)? {
                Poll::Ready(()) => {}
                Poll::Pending => return Poll::Pending,
            }
        }

        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        let pin = self.get_mut();
        pin.data = Some(item);
        pin.flushed = false;
        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.flushed {
            return Poll::Ready(Ok(()));
        }

        let Self {
            ref mut udp_socket,
            data: ref mut pkt,
            ..
        } = *self;

        if pkt.is_some() {
            let bytes = pkt.as_ref().unwrap();
            let n = ready!(udp_socket.poll_send(cx, bytes))?;
            let wrote_all = n == bytes.len();
            self.data = None;
            self.flushed = true;

            let res = if wrote_all {
                Ok(())
            } else {
                Err(io::Error::other(
                    "failed to send all data, only sent {n} bytes",
                ))
            };
            Poll::Ready(res)
        } else {
            Poll::Ready(Err(io::Error::other("no packet to send")))
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(<Self as Sink<Bytes>>::poll_flush(self, cx))?;
        Poll::Ready(Ok(()))
    }
}

impl AsyncXrayUdpStream for Socks5UdpStream {}

fn read_target_location_udp(buffer: &Vec<u8>) -> io::Result<(usize, NetLocation)> {
    let address_type = buffer[3];
    let start_index = 4;
    match address_type {
        protocol::address_type::TYPE_IPV4 => {
            let end_index = start_index + 6;
            let address_bytes = &buffer[start_index..end_index];
            let v4addr = Ipv4Addr::new(
                address_bytes[0],
                address_bytes[1],
                address_bytes[2],
                address_bytes[3],
            );
            let port = u16::from_be_bytes(
                address_bytes[4..6]
                    .try_into()
                    .map_err(|_| io::Error::from(ErrorKind::Other))?,
            );
            Ok((end_index, NetLocation::new(Address::Ipv4(v4addr), port)))
        }
        protocol::address_type::TYPE_IPV6 => {
            let end_index = start_index + 18;
            let address_bytes = &buffer[start_index..end_index];
            let v6addr = Ipv6Addr::new(
                u16::from_be_bytes(
                    address_bytes[0..2]
                        .try_into()
                        .map_err(|err| io::Error::new(ErrorKind::Other, err))?,
                ),
                u16::from_be_bytes(
                    address_bytes[2..4]
                        .try_into()
                        .map_err(|err| io::Error::new(ErrorKind::Other, err))?,
                ),
                u16::from_be_bytes(
                    address_bytes[4..6]
                        .try_into()
                        .map_err(|err| io::Error::new(ErrorKind::Other, err))?,
                ),
                u16::from_be_bytes(
                    address_bytes[6..8]
                        .try_into()
                        .map_err(|err| io::Error::new(ErrorKind::Other, err))?,
                ),
                u16::from_be_bytes(
                    address_bytes[8..10]
                        .try_into()
                        .map_err(|err| io::Error::new(ErrorKind::Other, err))?,
                ),
                u16::from_be_bytes(
                    address_bytes[10..12]
                        .try_into()
                        .map_err(|err| io::Error::new(ErrorKind::Other, err))?,
                ),
                u16::from_be_bytes(
                    address_bytes[12..14]
                        .try_into()
                        .map_err(|err| io::Error::new(ErrorKind::Other, err))?,
                ),
                u16::from_be_bytes(
                    address_bytes[14..16]
                        .try_into()
                        .map_err(|err| io::Error::new(ErrorKind::Other, err))?,
                ),
            );

            let port = u16::from_be_bytes(
                address_bytes[16..18]
                    .try_into()
                    .map_err(|err| io::Error::new(ErrorKind::Other, err))?,
            );

            Ok((end_index, NetLocation::new(Address::Ipv6(v6addr), port)))
        }
        protocol::address_type::TYPE_DOMAIN_NAME => {
            let address_len = buffer[start_index] as usize;
            let end_index = start_index + 1 + address_len + 2;
            let address_bytes = &buffer[start_index + 1..end_index];
            let address_str = match std::str::from_utf8(&address_bytes[0..address_len]) {
                Ok(s) => s,
                Err(e) => {
                    return Err(io::Error::new(
                        ErrorKind::InvalidData,
                        format!("Failed to decode address: {}", e),
                    ));
                }
            };

            let port = u16::from_be_bytes(
                address_bytes[address_len..address_len + 2]
                    .try_into()
                    .map_err(|err| io::Error::new(ErrorKind::Other, err))?,
            );

            // Although this is supposed to be a hostname, some clients will pass
            // ipv4 and ipv6 addresses as well, so parse it rather than directly
            // using Address:Hostname enum.
            Ok((
                end_index,
                NetLocation::new(Address::from(address_str)?, port),
            ))
        }
        _ => Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!("Unknown address type: {}", address_type),
        )),
    }
}
