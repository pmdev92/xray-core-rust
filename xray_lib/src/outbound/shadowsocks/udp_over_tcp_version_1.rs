use std::io;
use std::io::ErrorKind;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, BytesMut};
use futures::ready;
use tls_parser::nom::AsBytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::common::address::Address;
use crate::common::vec::vec_allocate;
use crate::core::io::AsyncXrayTcpStream;
use crate::core::transport::XrayTransport;
use crate::outbound::shadowsocks::protocol::{Cipher, DecodeResult, PacketLen};
use crate::outbound::shadowsocks::tcp::{TcpWriteState, UdpOverTcpReadState};

const MAGIC_DOMAIN: &str = "sp.udp-over-tcp.arpa";

pub(crate) struct ShadowSocksUdpOverTcpVersion1Stream {
    pub(crate) cipher: Box<dyn Cipher>,
    pub(crate) transport: Box<dyn XrayTransport>,
    pub(crate) write_state: TcpWriteState,
    pub(crate) read_state: UdpOverTcpReadState,
    pub(crate) port: Vec<u8>,
    pub(crate) address: Vec<u8>,
    pub(crate) read_buffer: BytesMut,
    pub(crate) decoded_buffer: BytesMut,
}

impl AsyncRead for ShadowSocksUdpOverTcpVersion1Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let error = io::Error::new(
            ErrorKind::InvalidData,
            "shadow socks udp over tcp tcp read error",
        );

        if !self.decoded_buffer.is_empty() {
            return match self.read_state {
                UdpOverTcpReadState::ReadAddressAndPort => {
                    if (self.decoded_buffer.remaining() < 1) {
                        return Poll::Ready(Err(error));
                    }
                    let address_type = self.decoded_buffer.get_u8();
                    if address_type == 0 {
                        if (self.decoded_buffer.remaining() < 4) {
                            return Poll::Ready(Err(error));
                        }
                        let _ = self.decoded_buffer.split_to(4);
                    } else if address_type == 1 {
                        if (self.decoded_buffer.remaining() < 16) {
                            return Poll::Ready(Err(error));
                        }
                        let _ = self.decoded_buffer.split_to(16);
                    } else if address_type == 2 {
                        if (self.decoded_buffer.remaining() < 1) {
                            return Poll::Ready(Err(error));
                        }
                        let address_len = self.decoded_buffer.get_u8();
                        if (self.decoded_buffer.remaining() < address_len as usize) {
                            return Poll::Ready(Err(error));
                        }
                        let _ = self.decoded_buffer.split_to(address_len as usize);
                    } else {
                        return Poll::Ready(Err(error));
                    }
                    if (self.decoded_buffer.remaining() < 2) {
                        return Poll::Ready(Err(error));
                    }
                    let _ = self.decoded_buffer.split_to(2);
                    self.read_state = UdpOverTcpReadState::ReadLength;
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                UdpOverTcpReadState::ReadLength => {
                    if (self.decoded_buffer.remaining() < 2) {
                        return Poll::Ready(Err(error));
                    }
                    let length = self.decoded_buffer.get_u16();
                    self.read_state = UdpOverTcpReadState::ReadData(length);
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                UdpOverTcpReadState::ReadData(length) => {
                    if (self.decoded_buffer.remaining() < length as usize) {
                        return Poll::Ready(Err(error));
                    }
                    let result = self.decoded_buffer.split_to(length as usize);
                    self.read_state = UdpOverTcpReadState::ReadAddressAndPort;
                    buf.put_slice(result.as_bytes());
                    Poll::Ready(Ok(()))
                }
            };
        }
        if !self.read_buffer.is_empty() {
            let mut data: Option<DecodeResult> = None;
            match self.cipher.next_data_len() {
                PacketLen::NotMatter => {
                    let packet = self.read_buffer.split();
                    data = Some(self.cipher.decode_data(packet.as_bytes())?);
                }
                PacketLen::Must(len) => {
                    if self.read_buffer.len() >= len {
                        let packet = self.read_buffer.split_to(len);
                        data = Some(self.cipher.decode_data(packet.as_bytes())?);
                    }
                }
            }
            if let Some(data) = data {
                if let DecodeResult::Data(result) = data {
                    self.decoded_buffer.extend_from_slice(result.as_slice());
                }
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        }
        let mut buffer_vev = vec_allocate(buf.capacity());
        let mut buffer = ReadBuf::new(&mut buffer_vev);
        let result = ready!(Pin::new(&mut self.transport).poll_read(cx, &mut buffer));

        return match result {
            Ok(_) => {
                self.read_buffer.extend_from_slice(buffer.filled());
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(err) => {
                let message = format!("{{shadow socks tcp read message error: {}}}", err);
                let error = io::Error::new(err.kind(), message);
                Poll::Ready(Err(error))
            }
        };
    }
}

impl AsyncWrite for ShadowSocksUdpOverTcpVersion1Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        if let TcpWriteState::WriteAddressAndPort = self.write_state {
            let mut address_and_port_bytes = Vec::new();
            let address = Address::from(MAGIC_DOMAIN).unwrap();
            let port = vec![0u8, 0u8];
            address_and_port_bytes.extend_from_slice(&address.to_socks_trojan_bytes());
            address_and_port_bytes.extend_from_slice(&port);
            self.cipher
                .buffer_address_and_port(address_and_port_bytes.as_slice());
            self.write_state = TcpWriteState::WriteTcpData;

            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let mut new_address = self.address.to_vec();
        if new_address[0] == 1u8 {
            new_address[0] = 0;
        } else if new_address[0] == 4u8 {
            new_address[0] = 1;
        } else if new_address[0] == 3u8 {
            new_address[0] = 2;
        }

        let mut new_data = vec![];
        new_data.extend_from_slice(&new_address);
        new_data.extend_from_slice(&self.port);
        let len: u16 = buf.len() as u16;
        new_data.extend_from_slice(&len.to_be_bytes());
        new_data.extend_from_slice(buf);
        let encoded_bytes = self.cipher.encode_data(new_data.as_slice())?;
        let result = ready!(Pin::new(&mut self.transport).poll_write(cx, encoded_bytes.as_slice()));
        return match result {
            Ok(_) => Poll::Ready(Ok(buf.len())),
            Err(err) => {
                let message = format!(
                    "{{shadow-socks-write-state: {:?}, message: {}}}",
                    self.write_state, err
                );
                Poll::Ready(Err(io::Error::new(ErrorKind::BrokenPipe, message)))
            }
        };
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        return Pin::new(&mut self.get_mut().transport).poll_flush(cx);
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        return Pin::new(&mut self.get_mut().transport).poll_shutdown(cx);
    }
}

impl AsyncXrayTcpStream for ShadowSocksUdpOverTcpVersion1Stream {}
