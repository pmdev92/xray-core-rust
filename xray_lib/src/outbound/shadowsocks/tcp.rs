use std::io;
use std::io::ErrorKind;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{BufMut, BytesMut};
use futures::ready;
use tls_parser::nom::AsBytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::common::vec::vec_allocate;
use crate::core::io::AsyncXrayTcpStream;
use crate::core::transport::XrayTransport;
use crate::outbound::shadowsocks::protocol::{Cipher, DecodeResult, PacketLen};

pub(crate) struct ShadowSocksTcpStream {
    pub(crate) cipher: Box<dyn Cipher>,
    pub(crate) transport: Box<dyn XrayTransport>,
    pub(crate) write_state: TcpWriteState,
    pub(crate) port: Vec<u8>,
    pub(crate) address: Vec<u8>,
    pub(crate) read_buffer: BytesMut,
    pub(crate) decoded_buffer: BytesMut,
    pub(crate) write_buffer: BytesMut,
}
#[derive(PartialEq, Debug)]
pub(crate) enum UdpOverTcpReadState {
    ReadAddressAndPort,
    ReadLength,
    ReadData(u16),
}

#[derive(PartialEq, Debug)]
pub(crate) enum TcpWriteState {
    WriteAddressAndPort,
    WriteTcpData,
}

impl AsyncRead for ShadowSocksTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.decoded_buffer.is_empty() {
            let mut result: BytesMut = BytesMut::new();
            if buf.remaining() >= self.decoded_buffer.len() {
                result = self.decoded_buffer.split();
            } else {
                result = self.decoded_buffer.split_to(buf.remaining());
            }
            buf.put_slice(result.as_bytes());
            return Poll::Ready(Ok(()));
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

impl AsyncWrite for ShadowSocksTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        if let TcpWriteState::WriteAddressAndPort = self.write_state {
            let mut address_and_port_bytes = Vec::new();
            address_and_port_bytes.extend_from_slice(&self.address);
            address_and_port_bytes.extend_from_slice(&self.port);
            self.cipher
                .buffer_address_and_port(address_and_port_bytes.as_slice());
            self.write_state = TcpWriteState::WriteTcpData;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }

        if !self.write_buffer.is_empty() {
            let data = self.write_buffer.as_ref().to_vec();
            let result = ready!(Pin::new(&mut self.transport).poll_write(cx, data.as_slice()));
            return match result {
                Ok(_) => {
                    self.write_buffer.clear();
                    Poll::Ready(Ok(buf.len()))
                }
                Err(err) => {
                    let message = format!(
                        "{{shadow-socks-write-state: {:?}, message: {}}}",
                        self.write_state, err
                    );
                    Poll::Ready(Err(io::Error::new(ErrorKind::BrokenPipe, message)))
                }
            };
        }
        let encoded_bytes = self.cipher.encode_data(buf)?;
        self.write_buffer.put_slice(encoded_bytes.as_slice());
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        return Pin::new(&mut self.get_mut().transport).poll_flush(cx);
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        return Pin::new(&mut self.get_mut().transport).poll_shutdown(cx);
    }
}

impl AsyncXrayTcpStream for ShadowSocksTcpStream {}
