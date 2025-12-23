use std::fmt::Debug;
use std::io;
use std::io::ErrorKind;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;
use byteorder::{BigEndian, ByteOrder};
use bytes::{Buf, Bytes, BytesMut};
use dns_message_parser::Dns;
use futures_util::ready;
use log::{error, trace};
use sha2::{Digest, Sha224};
use tls_parser::nom::AsBytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::common::address::Address;
use crate::common::hex::encode_hex;
use crate::common::net_location::NetLocation;
use crate::common::udp::TcpDatagramWrapper;
use crate::common::vec::vec_allocate;
use crate::core::io::{AsyncXrayTcpStream, AsyncXrayUdpStream};
use crate::core::outbound::Outbound;
use crate::core::transport::{Transport, XrayTransport};
use crate::outbound::trojan::config::TrojanSettings;

pub mod config;

pub struct TrojanOutbound {
    address: String,
    port: u16,
    password: String,
    transport: Box<dyn Transport>,
}

const CLRF: u16 = 0x0D0A;

impl TrojanOutbound {
    pub fn new(trojan_settings: TrojanSettings, transport: Box<dyn Transport>) -> Self {
        let mut hasher = Sha224::new();
        hasher.update(&trojan_settings.password);
        let result = encode_hex(hasher.finalize().as_slice());
        trace!("trojan outbound address is {}", trojan_settings.address);
        trace!("trojan outbound port is {}", trojan_settings.port);
        trace!("trojan outbound password is {}", trojan_settings.password);
        Self {
            address: trojan_settings.address,
            port: trojan_settings.port,
            password: result,
            transport,
        }
    }
}

#[async_trait]
impl Outbound for TrojanOutbound {
    async fn dial_tcp(
        &self,
        context: Arc<crate::core::context::Context>,
        detour: Option<String>,
        net_location: Arc<NetLocation>,
    ) -> Result<Box<dyn AsyncXrayTcpStream>, io::Error> {
        return self
            .get_trojan_stream(context, detour, TrojanCmd::Tcp, net_location)
            .await;
    }

    async fn dial_udp(
        &self,
        context: Arc<crate::core::context::Context>,
        detour: Option<String>,
        net_location: Arc<NetLocation>,
    ) -> Result<Box<dyn AsyncXrayUdpStream>, io::Error> {
        let stream = self
            .get_trojan_stream(context.clone(), detour, TrojanCmd::Udp, net_location)
            .await?;
        Ok(TcpDatagramWrapper::new(context, stream).await?)
    }
}

impl TrojanOutbound {
    async fn get_trojan_stream(
        &self,
        context: Arc<crate::core::context::Context>,
        detour: Option<String>,
        cmd: TrojanCmd,
        net_location: Arc<NetLocation>,
    ) -> Result<Box<dyn AsyncXrayTcpStream>, io::Error> {
        let address = Address::from(&self.address)?;
        let server_location = Arc::new(NetLocation::new(address, self.port));
        let transport = self
            .transport
            .dial(context, detour, server_location)
            .await?;

        let password = self.password.clone();

        let port_bytes = net_location.port().to_be_bytes().to_vec();

        let address_bytes: Vec<u8> = net_location.address().to_socks_trojan_bytes();

        let mut read_state = ReadState::ReadTcpData;
        if cmd == TrojanCmd::Udp {
            read_state = ReadState::ReadUdpAddressType;
        }
        return Ok(Box::new(TrojanStream {
            transport,
            read_state,
            write_state: WriteState::WriteHeader,
            password,
            cmd: cmd as u8,
            port: port_bytes,
            address: address_bytes,
            read_buffer: BytesMut::new(),
        }));
    }
}

// doc https://github.com/trojan-gfw/trojan/blob/master/docs/protocol.md
struct TrojanStream {
    transport: Box<dyn XrayTransport>,
    read_state: ReadState,
    write_state: WriteState,
    password: String,
    cmd: u8,
    port: Vec<u8>,
    address: Vec<u8>,

    read_buffer: BytesMut,
}

#[derive(PartialEq, Copy, Clone, Debug)]
enum TrojanCmd {
    Tcp = 1,
    Udp = 3,
}

#[derive(PartialEq, Debug)]
enum ReadState {
    ReadUdpAddressType,
    ReadUdpAddressTypeHostLen,
    ReadUdpDataLength(u8),
    ReadUdpData(u16),
    ReadTcpData,
}

#[derive(PartialEq, Debug)]
enum WriteState {
    WriteHeader,
    WriteUdpData,
    WriteTcpData,
}

impl AsyncRead for TrojanStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.read_buffer.is_empty() {
            if let ReadState::ReadUdpAddressType = self.read_state {
                if self.read_buffer.len() >= 1 {
                    let mut data = self.read_buffer.split_to(1);
                    let address_type = data.get_u8();
                    if address_type == 1 {
                        self.read_state = ReadState::ReadUdpDataLength(4);
                    } else if address_type == 3 {
                        self.read_state = ReadState::ReadUdpAddressTypeHostLen;
                    } else if address_type == 4 {
                        self.read_state = ReadState::ReadUdpDataLength(16);
                    } else {
                        return Poll::Ready(Err(io::Error::new(
                            ErrorKind::InvalidData,
                            "trojan udp address type is invalid",
                        )));
                    }
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
            }
            if let ReadState::ReadUdpAddressTypeHostLen = self.read_state {
                if self.read_buffer.len() >= 1 {
                    let mut data = self.read_buffer.split_to(1);
                    let address_len = data.get_u8();
                    self.read_state = ReadState::ReadUdpDataLength(address_len);
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
            }
            if let ReadState::ReadUdpDataLength(address_len) = self.read_state {
                let address_len = address_len as usize;
                let length = address_len + 2 + 2 + 2;
                if self.read_buffer.len() >= length {
                    let bytes = self.read_buffer.split_to(length);
                    let length =
                        BigEndian::read_u16(&bytes.as_bytes()[bytes.len() - 4..bytes.len() - 2]);
                    self.read_state = ReadState::ReadUdpData(length);
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
            }
            if let ReadState::ReadUdpData(length) = self.read_state {
                let length = length as usize;
                if self.read_buffer.len() >= length {
                    let udp_data = self.read_buffer.split_to(length);
                    buf.put_slice(udp_data.as_bytes());
                    self.read_state = ReadState::ReadUdpAddressType;
                    return Poll::Ready(Ok(()));
                }
            }
            if let ReadState::ReadTcpData = self.read_state {
                let tcp_data = self.read_buffer.split();
                buf.put_slice(tcp_data.as_bytes());
                return Poll::Ready(Ok(()));
            }
        }
        //read data from transport
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
                let message = format!(
                    "{{trojan-read-state: {:?}, message: {}}}",
                    self.read_state, err
                );
                let error = io::Error::new(err.kind(), message);
                Poll::Ready(Err(error))
            }
        };
    }
}

impl AsyncWrite for TrojanStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        if let WriteState::WriteHeader = self.write_state {
            let mut header_bytes = self.password.as_bytes().to_vec();
            let clrf_bytes = CLRF.to_be_bytes();
            let cmd = [self.cmd];
            header_bytes.extend_from_slice(&clrf_bytes);
            header_bytes.extend_from_slice(&cmd);
            header_bytes.extend_from_slice(&self.address);
            header_bytes.extend_from_slice(&self.port);
            header_bytes.extend_from_slice(&clrf_bytes);
            // let length = header_bytes.len();
            let result = ready!(Pin::new(&mut self.transport).poll_write(cx, &header_bytes));
            return match result {
                Ok(_) => {
                    // if count != length {
                    //     let message = format!("{{trojan-write-state: {:?}, message: trojan header write length error}}", self.write_state);
                    //     return Poll::Ready(Err(s2n_quic_io::Error::new(ErrorKind::BrokenPipe, message)));
                    // }
                    if self.cmd == 1 {
                        //CONNECT X'01'
                        self.write_state = WriteState::WriteTcpData;
                    } else {
                        self.write_state = WriteState::WriteUdpData;
                    }
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Err(err) => Poll::Ready(Err(err)),
            };
        }
        if let WriteState::WriteUdpData = self.write_state {
            let len_buf = (buf.len() as u16).to_be_bytes();
            let clrf_bytes = CLRF.to_be_bytes();
            let mut new_buf = Vec::new();
            new_buf.extend_from_slice(&self.address);
            new_buf.extend_from_slice(&self.port);
            new_buf.extend_from_slice(&len_buf);
            new_buf.extend_from_slice(&clrf_bytes);
            new_buf.extend_from_slice(&buf);
            let result = ready!(Pin::new(&mut self.transport).poll_write(cx, &new_buf));
            return match result {
                Ok(_) => {
                    // if count != new_buf.len() {
                    //     let message = format!("{{trojan-write-state: {:?}, message: trojan udp packet write length error}}", self.write_state);
                    //     return Poll::Ready(Err(s2n_quic_io::Error::new(ErrorKind::BrokenPipe, message)));
                    // }
                    Poll::Ready(Ok(buf.len()))
                }
                Err(err) => {
                    let message = format!(
                        "{{vless-write-state: {:?}, message: {}}}",
                        self.write_state, err
                    );
                    let error = io::Error::new(err.kind(), message);
                    Poll::Ready(Err(error))
                }
            };
        }
        let result = ready!(Pin::new(&mut self.transport).poll_write(cx, buf));
        return match result {
            Ok(size) => Poll::Ready(Ok(size)),
            Err(err) => {
                let message = format!(
                    "{{tojan-write-state: {:?}, message: {}}}",
                    self.write_state, err
                );
                let error = io::Error::new(err.kind(), message);
                Poll::Ready(Err(error))
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

impl AsyncXrayTcpStream for TrojanStream {}
