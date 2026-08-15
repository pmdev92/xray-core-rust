use std::any::{type_name, Any};
use std::fmt::Debug;
use std::io;
use std::io::ErrorKind;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use async_trait::async_trait;
use byteorder::{BigEndian, ByteOrder};
use bytes::{Buf, BytesMut};
use futures::ready;
use log::{error, trace};
use s2n_codec::zerocopy::IntoBytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::common::address::Address;
use crate::common::net_location::NetLocation;
use crate::common::uuid::get_uuid;
use crate::common::vec::vec_allocate;
use crate::core::inbound::AsyncStream;
use crate::core::outbound::{Outbound, XrayOutboundStream};
use crate::core::transport::{Transport, XrayTransport};
use crate::dialer::Dialer;
use crate::outbound::vless::config::VlessSettings;
use crate::outbound::vless::encryption::aead::VlessAead;
use crate::outbound::vless::encryption::client::{ClientInstance, EncryptedTransport};
use crate::outbound::vless::encryption::xor::XorState;
use crate::security::tls::TlsSecurityStream;
use crate::transport::tcp::TcpTransportStream;

pub mod config;
pub mod encryption;

pub struct VlessOutbound {
    address: String,
    port: u16,
    uuid: Arc<Vec<u8>>,
    transport: Box<dyn Transport>,
    encryption: Option<Arc<ClientInstance>>,
}

impl VlessOutbound {
    pub fn new(vless_settings: VlessSettings, transport: Box<dyn Transport>) -> Self {
        let uuid_vec = get_uuid(vless_settings.id.clone());
        let uuid = Arc::new(uuid_vec);
        trace!("vless outbound address is {}", vless_settings.address);
        trace!("vless outbound port is {}", vless_settings.port);
        trace!("vless outbound uuid is {}", vless_settings.id);

        // Parse encryption from config string
        let encryption = match &vless_settings.encryption {
            Some(enc) => match encryption::parse_encryption(enc) {
                Ok(Some(ci)) => {
                    trace!("vless encryption enabled (ML-KEM-768 + X25519)");
                    Some(Arc::new(ci))
                }
                Ok(None) => None,
                Err(e) => {
                    error!("vless encryption parse failed: {}", e);
                    None
                }
            },
            None => None,
        };

        Self {
            address: vless_settings.address,
            port: vless_settings.port,
            uuid,
            transport,
            encryption,
        }
    }
}

#[async_trait]
impl Outbound for VlessOutbound {
    async fn dial_tcp(
        &self,
        _context: Arc<crate::core::context::Context>,
        dialer: Arc<Dialer>,
        net_location: Arc<NetLocation>,
    ) -> Result<Box<dyn XrayOutboundStream>, io::Error> {
        self.get_vless_stream(dialer, Instruction::Tcp, net_location)
            .await
    }

    async fn dial_udp(
        &self,
        _context: Arc<crate::core::context::Context>,
        dialer: Arc<Dialer>,
        net_location: Arc<NetLocation>,
    ) -> Result<Box<dyn XrayOutboundStream>, io::Error> {
        return self
            .get_vless_stream(dialer, Instruction::Udp, net_location)
            .await;
    }
}

impl VlessOutbound {
    async fn get_vless_stream(
        &self,
        dialer: Arc<Dialer>,
        instruction: Instruction,
        net_location: Arc<NetLocation>,
    ) -> Result<Box<dyn XrayOutboundStream>, io::Error> {
        let address = Address::from(&self.address)?;
        let server_location = Arc::new(NetLocation::new(address, self.port));

        trace!("vless: dialing transport to {}", self.address);
        let dial_start = Instant::now();
        let mut transport = self.transport.dial(dialer, server_location).await?;
        let dial_elapsed = dial_start.elapsed();
        trace!("vless: transport connected in {:?}", dial_elapsed);
        if dial_elapsed.as_millis() > 1000 {
            log::warn!("vless: slow transport dial took {:?}", dial_elapsed);
        }

        // Perform encryption handshake and wrap transport if configured
        let transport: Box<dyn XrayTransport> = if let Some(ref enc) = self.encryption {
            let start = Instant::now();
            let result = enc.handshake(&mut transport, true).await?;
            let elapsed = start.elapsed();
            trace!("vless encryption handshake in {:?}", elapsed);
            Box::new(EncryptedTransport::new(transport, result))
        } else {
            transport
        };

        let uuid = self.uuid.clone().to_vec();

        let port_bytes = net_location.port().to_be_bytes().to_vec();

        let address_bytes: Vec<u8> = net_location.address().to_vmess_vless_bytes();

        trace!("vless: header sent to {}:{}", self.address, self.port);

        Ok(Box::new(VlessStream {
            transport,
            read_state: ReadState::ReadVersion,
            write_state: WriteState::WriteHeader,
            auth: uuid,
            instruction: instruction as u8,
            port: port_bytes,
            address: address_bytes,
            is_tcp: instruction == Instruction::Tcp,
            read_buffer: BytesMut::new(),
        }))
    }
}

struct VlessStream {
    transport: Box<dyn XrayTransport>,
    read_state: ReadState,
    write_state: WriteState,
    auth: Vec<u8>,
    instruction: u8,
    port: Vec<u8>,
    address: Vec<u8>,
    is_tcp: bool,
    read_buffer: BytesMut,
}

#[derive(PartialEq, Copy, Clone)]
enum Instruction {
    Tcp = 1,
    Udp = 2,
}

#[derive(PartialEq, Debug)]
enum ReadState {
    ReadVersion,
    ReadAdditionalInformationLength,
    ReadAdditionalInformation(u8),
    ReadUdpDataLength,
    ReadUdpData(u16),
    ReadTcpData,
}

#[derive(PartialEq, Debug)]
enum WriteState {
    WriteHeader,
    WriteUdpData,
    WriteTcpData,
}
macro_rules! check_read_eof {
    ($rb:expr, $msg:expr) => {
        if $rb.filled().is_empty() {
            return Poll::Ready(Err(io::Error::new(ErrorKind::UnexpectedEof, $msg)));
        }
    };
}
impl AsyncRead for VlessStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.read_buffer.is_empty() {
                match &mut self.read_state {
                    ReadState::ReadVersion => {
                        if self.read_buffer.len() >= 1 {
                            let _ = self.read_buffer.split_to(1);
                            self.read_state = ReadState::ReadAdditionalInformationLength;
                            continue;
                        }
                    }
                    ReadState::ReadAdditionalInformationLength => {
                        if self.read_buffer.len() >= 1 {
                            let count = self.read_buffer.split_to(1).get_u8();
                            if count > 0 {
                                self.read_state = ReadState::ReadAdditionalInformation(count);
                            } else {
                                if self.is_tcp {
                                    self.read_state = ReadState::ReadTcpData;
                                } else {
                                    self.read_state = ReadState::ReadUdpDataLength;
                                }
                            }
                            continue;
                        }
                    }
                    ReadState::ReadAdditionalInformation(length) => {
                        let length = *length as usize;
                        if self.read_buffer.len() >= length {
                            let _ = self.read_buffer.split_to(length);
                            if self.is_tcp {
                                self.read_state = ReadState::ReadTcpData;
                            } else {
                                self.read_state = ReadState::ReadUdpDataLength;
                            }
                            continue;
                        }
                    }
                    ReadState::ReadUdpDataLength => {
                        if self.read_buffer.len() >= 2 {
                            let bytes = self.read_buffer.split_to(2);
                            let length = BigEndian::read_u16(bytes.as_bytes());
                            self.read_state = ReadState::ReadUdpData(length);
                            continue;
                        }
                    }
                    ReadState::ReadUdpData(length) => {
                        let length = *length as usize;
                        if self.read_buffer.len() >= length {
                            let udp_data = self.read_buffer.split_to(length);
                            buf.put_slice(udp_data.as_bytes());
                            self.read_state = ReadState::ReadUdpDataLength;
                            return Poll::Ready(Ok(()));
                        }
                    }
                    ReadState::ReadTcpData => {
                        let n = self.read_buffer.len().min(buf.remaining());
                        let data = &self.read_buffer.split_to(n);
                        buf.put_slice(data);
                        return Poll::Ready(Ok(()));
                    }
                }
            }

            let len = match &self.read_state {
                ReadState::ReadVersion => 1usize,
                ReadState::ReadAdditionalInformationLength => 1usize,
                ReadState::ReadAdditionalInformation(length) => *length as usize,
                ReadState::ReadUdpDataLength => 2usize,
                ReadState::ReadUdpData(length) => *length as usize,
                ReadState::ReadTcpData => buf.capacity(),
            };

            //read data from transport
            let mut buffer_vev = vec_allocate(len);
            let mut buffer = ReadBuf::new(&mut buffer_vev);
            let result = ready!(Pin::new(&mut self.transport).poll_read(cx, &mut buffer));
            match result {
                Ok(_) => {
                    if buffer.filled().len() == 0 {
                        let message = "vless read zero bytes".to_string();
                        let error = io::Error::new(ErrorKind::BrokenPipe, message);
                        return Poll::Ready(Err(error));
                    }
                    self.read_buffer.extend_from_slice(buffer.filled());
                    continue;
                }
                Err(err) => {
                    let message = format!(
                        "{{vless-read-state: {:?}, message: {}}}",
                        self.read_state, err
                    );
                    let error = io::Error::new(err.kind(), message);
                    return Poll::Ready(Err(error));
                }
            }
        }
    }
}

impl AsyncWrite for VlessStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        loop {
            return match &mut self.write_state {
                WriteState::WriteHeader => {
                    let version = [0];
                    let additional_information_length = 0u8.to_be_bytes();
                    let instruction = [self.instruction];
                    let mut header_bytes = Vec::new();
                    header_bytes.extend_from_slice(&version);
                    header_bytes.extend_from_slice(&self.auth);
                    header_bytes.extend_from_slice(additional_information_length.as_slice());
                    header_bytes.extend_from_slice(&instruction);
                    header_bytes.extend_from_slice(&self.port);
                    header_bytes.extend_from_slice(&self.address);
                    let result =
                        ready!(Pin::new(&mut self.transport).poll_write(cx, &header_bytes));
                    match result {
                        Ok(_) => {
                            if self.is_tcp {
                                self.write_state = WriteState::WriteTcpData;
                            } else {
                                self.write_state = WriteState::WriteUdpData;
                            }
                            continue;
                        }
                        Err(err) => {
                            let message = format!(
                                "{{vless-write-state: {:?}, message: {}}}",
                                self.write_state, err
                            );
                            Poll::Ready(Err(io::Error::new(ErrorKind::BrokenPipe, message)))
                        }
                    }
                }
                WriteState::WriteUdpData => {
                    let len_buf = (buf.len() as u16).to_be_bytes();
                    let mut new_buf = Vec::new();
                    new_buf.extend_from_slice(&len_buf);
                    new_buf.extend_from_slice(&buf);
                    let result = ready!(Pin::new(&mut self.transport).poll_write(cx, &new_buf));
                    match result {
                        Ok(count) => {
                            if count != new_buf.len() {
                                let message = format!("{{vless-write-state: {:?}, message: vless udp packet write length error}}", self.write_state);
                                return Poll::Ready(Err(io::Error::new(
                                    ErrorKind::BrokenPipe,
                                    message,
                                )));
                            }
                            Poll::Ready(Ok(buf.len()))
                        }
                        Err(err) => {
                            let message = format!(
                                "{{vless-write-state: {:?}, message: {}}}",
                                self.write_state, err
                            );
                            Poll::Ready(Err(io::Error::new(ErrorKind::BrokenPipe, message)))
                        }
                    }
                }
                WriteState::WriteTcpData => {
                    let result = ready!(Pin::new(&mut self.transport).poll_write(cx, buf));
                    match result {
                        Ok(size) => Poll::Ready(Ok(size)),
                        Err(err) => {
                            let message = format!(
                                "{{vless-write-state: {:?}, message: {}}}",
                                self.write_state, err
                            );
                            Poll::Ready(Err(io::Error::new(ErrorKind::BrokenPipe, message)))
                        }
                    }
                }
            };
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        return Pin::new(&mut self.get_mut().transport).poll_flush(cx);
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        return Pin::new(&mut self.get_mut().transport).poll_shutdown(cx);
    }
}

impl AsyncStream for VlessStream {}

impl XrayOutboundStream for VlessStream {}
