use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::common::utils::get_address_and_port_len;
use crate::core::io::AsyncXrayUdpStream;
use crate::outbound::shadowsocks::protocol::{Cipher, DecodeResult, PacketLen};
use bytes::{Buf, Bytes, BytesMut};
use futures::{Sink, Stream};
use tls_parser::nom::AsBytes;

pub(crate) struct ShadowSocksUdpStream {
    cipher: Box<dyn Cipher>,
    udp_socket: Box<dyn AsyncXrayUdpStream>,
    port: Vec<u8>,
    address: Vec<u8>,
    read_buffer: BytesMut,
    encoded_buffer: BytesMut,
    decoded_buffer: BytesMut,
    flushed: bool,
    data: Option<Bytes>,
}

impl ShadowSocksUdpStream {
    pub fn new(
        cipher: Box<dyn Cipher>,
        udp_socket: Box<dyn AsyncXrayUdpStream>,
        port: Vec<u8>,
        address: Vec<u8>,
    ) -> ShadowSocksUdpStream {
        Self {
            cipher,
            udp_socket,
            port,
            address,
            read_buffer: Default::default(),
            encoded_buffer: Default::default(),
            decoded_buffer: Default::default(),
            flushed: true,
            data: None,
        }
    }
}

impl Stream for ShadowSocksUdpStream {
    type Item = Bytes;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if !self.decoded_buffer.is_empty() {
            let mut data = self.decoded_buffer.split();
            let address_and_port_len = match get_address_and_port_len(data.as_bytes()) {
                Ok(n) => n,
                Err(_) => return Poll::Ready(None),
            };
            data.advance(address_and_port_len);
            let payload = data.as_bytes();
            return Poll::Ready(Some(Bytes::copy_from_slice(payload)));
        }

        if !self.read_buffer.is_empty() {
            let mut decoded: Option<DecodeResult> = None;
            match self.cipher.next_data_len() {
                PacketLen::NotMatter => {
                    let packet = self.read_buffer.split();
                    let result = self.cipher.decode_data(packet.as_bytes());
                    let decoded_result = match result {
                        Ok(result) => result,
                        Err(_) => {
                            return Poll::Ready(None);
                        }
                    };
                    decoded = Some(decoded_result);
                }
                PacketLen::Must(len) => {
                    if self.read_buffer.len() >= len {
                        let packet = self.read_buffer.split_to(len);
                        let result = self.cipher.decode_data(packet.as_bytes());
                        let decoded_result = match result {
                            Ok(result) => result,
                            Err(_) => {
                                return Poll::Ready(None);
                            }
                        };
                        decoded = Some(decoded_result);
                    }
                }
            }

            if let Some(DecodeResult::Data(bytes)) = decoded {
                self.decoded_buffer.extend_from_slice(bytes.as_slice());
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        }

        match std::task::ready!(Pin::new(&mut self.udp_socket).poll_next(cx)) {
            Some(datagram) => {
                self.read_buffer.extend_from_slice(&datagram);
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            None => Poll::Ready(None),
        }
    }
}

impl Sink<Bytes> for ShadowSocksUdpStream {
    type Error = io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if !self.flushed {
            match self.as_mut().poll_flush(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            }
        }
        Pin::new(&mut self.udp_socket).poll_ready(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        let mut address_and_port = Vec::with_capacity(self.address.len() + self.port.len());
        address_and_port.extend_from_slice(&self.address);
        address_and_port.extend_from_slice(&self.port);
        self.cipher.buffer_address_and_port(&address_and_port);
        let encrypted_packet = self.cipher.encode_data(&item).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("encode ss udp data: {e:?}"),
            )
        })?;

        self.data = Some(Bytes::from(encrypted_packet));
        self.flushed = false;
        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.flushed {
            return Pin::new(&mut self.udp_socket).poll_flush(cx);
        }
        if let Some(pkt) = self.data.take() {
            match Pin::new(&mut self.udp_socket).poll_ready(cx) {
                Poll::Pending => {
                    self.data = Some(pkt);
                    return Poll::Pending;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {}
            }
            if let Err(e) = Pin::new(&mut self.udp_socket).start_send(pkt) {
                return Poll::Ready(Err(e));
            }
        }
        match Pin::new(&mut self.udp_socket).poll_flush(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {
                self.flushed = true;
                Poll::Ready(Ok(()))
            }
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        Pin::new(&mut self.udp_socket).poll_close(cx)
    }
}
impl AsyncXrayUdpStream for ShadowSocksUdpStream {}

// impl Stream for ShadowSocksUdpStream {
//     type Item = Bytes;
//     fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
//         let Self {
//             ref mut udp_socket,
//             ref mut decoded_buffer,
//             ref mut read_buffer,
//             ref mut cipher,
//             ..
//         } = *self;
//         if !decoded_buffer.is_empty() {
//             let mut data = self.decoded_buffer.split();
//             let address_and_port_len = get_address_and_port_len(data.as_bytes());
//             let address_and_port_len = match address_and_port_len {
//                 Ok(address_and_port_len) => address_and_port_len,
//                 Err(_) => {
//                     return Poll::Ready(None);
//                 }
//             };
//             data.advance(address_and_port_len);
//             let data = data.as_bytes();
//             return Poll::Ready(Some(Bytes::from(data.to_vec())));
//         }
//
//         if !read_buffer.is_empty() {
//             let mut data: Option<DecodeResult> = None;
//             match cipher.next_data_len() {
//                 PacketLen::NotMatter => {
//                     let packet = read_buffer.split();
//                     let result = cipher.decode_data(packet.as_bytes());
//                     let decoded = match result {
//                         Ok(result) => result,
//                         Err(_) => {
//                             return Poll::Ready(None);
//                         }
//                     };
//                     data = Some(decoded);
//                 }
//                 PacketLen::Must(len) => {
//                     if read_buffer.len() >= len {
//                         let packet = read_buffer.split_to(len);
//                         let result = cipher.decode_data(packet.as_bytes());
//                         let decoded = match result {
//                             Ok(result) => result,
//                             Err(_) => {
//                                 return Poll::Ready(None);
//                             }
//                         };
//                         data = Some(decoded);
//                     }
//                 }
//             }
//             if let Some(data) = data {
//                 if let DecodeResult::Data(result) = data {
//                     decoded_buffer.extend_from_slice(result.as_slice());
//                 }
//                 cx.waker().wake_by_ref();
//                 return Poll::Pending;
//             }
//         }
//
//         match std::task::ready!(Pin::new(udp_socket).poll_next(cx)) {
//             Some(data) => {
//                 read_buffer.extend_from_slice(&data);
//                 cx.waker().wake_by_ref();
//                 Poll::Pending
//             }
//             None => Poll::Ready(None),
//         }
//     }
// }

// impl Sink<Bytes> for ShadowSocksUdpStream {
//     type Error = io::Error;
//
//     fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
//         if !self.flushed {
//             match <Self as Sink<Bytes>>::poll_flush(self, cx)? {
//                 Poll::Ready(()) => {}
//                 Poll::Pending => return Poll::Pending,
//             }
//         }
//
//         Poll::Ready(Ok(()))
//     }
//
//     fn start_send(mut self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
//         let Self {
//             ref mut address,
//             ref mut port,
//             ref mut cipher,
//             ref mut data,
//             ref mut flushed,
//             ..
//         } = *self;
//
//         let mut address_and_port_bytes = Vec::new();
//         address_and_port_bytes.extend_from_slice(address);
//         address_and_port_bytes.extend_from_slice(port);
//         cipher.buffer_address_and_port(address_and_port_bytes.as_slice());
//         let encrypted_packet = cipher.encode_data(&item)?;
//
//         *data = Some(Bytes::from(encrypted_packet));
//         *flushed = false;
//         Ok(())
//     }
//
//     fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
//         if self.flushed {
//             return Poll::Ready(Ok(()));
//         }
//
//         let Self {
//             ref mut udp_socket,
//             data: ref mut pkt,
//             ..
//         } = *self;
//
//         if pkt.is_some() {
//             let bytes = pkt.as_ref().unwrap();
//             let n = std::task::ready!(udp_socket.poll(cx, bytes))?;
//             let wrote_all = n == bytes.len();
//             self.data = None;
//             self.flushed = true;
//
//             let res = if wrote_all {
//                 Ok(())
//             } else {
//                 Err(io::Error::other(
//                     "failed to send all data, only sent {n} bytes",
//                 ))
//             };
//             Poll::Ready(res)
//         } else {
//             Poll::Ready(Err(io::Error::other("no packet to send")))
//         }
//     }
//
//     fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
//         std::task::ready!(<Self as Sink<Bytes>>::poll_flush(self, cx))?;
//         Poll::Ready(Ok(()))
//     }
// }
