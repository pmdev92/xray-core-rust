use std::any::{Any, type_name};
use std::cmp::PartialEq;
use std::fmt::Debug;
use std::io;
use std::io::ErrorKind;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use crate::common::address::Address;
use crate::common::net_location::NetLocation;
use crate::common::udp::TcpDatagramWrapper;
use crate::common::uuid::get_uuid;
use crate::common::vec::vec_allocate;
use crate::core::io::{AsyncXrayTcpStream, AsyncXrayUdpStream};
use crate::core::outbound::Outbound;
use crate::core::transport::{Transport, XrayTransport};
use crate::outbound::vless::config::VlessSettings;
use crate::outbound::vless::encryption::client::{ClientInstance, EncryptedTransport};
use crate::outbound::vless::flow::{VlessFlow, get_vless_addons};
use crate::outbound::vless::mux::VlessMuxStream;
use crate::outbound::vless::util::get_global_id;
use crate::outbound::vless::xtls::VisionStream;
use crate::security::tls::TlsSecurity;
use crate::transport::tcp::{TcpTransport, TcpTransportStream};
use crate::transport::websocket::WebsocketTransport;
use async_trait::async_trait;
use byteorder::{BigEndian, ByteOrder};
use bytes::{Buf, BytesMut};
use futures::ready;
use futures_util::future::err;
use log::{error, trace};
use tls_parser::nom::AsBytes;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::task::id;

pub mod config;
mod encryption;
mod flow;
mod mux;
mod util;
mod xtls;

pub struct VlessOutbound {
    address: String,
    port: u16,
    uuid: Arc<Vec<u8>>,
    flow: VlessFlow,
    transport: Box<dyn Transport>,
    encryption: Option<Arc<ClientInstance>>,
}

impl VlessOutbound {
    pub fn new(vless_settings: VlessSettings, transport: Box<dyn Transport>) -> Self {
        let uuid_vec = get_uuid(vless_settings.id.clone());
        let uuid = Arc::new(uuid_vec);
        let mut flow = VlessFlow::from(vless_settings.flow.clone());
        trace!("vless outbound address is {}", vless_settings.address);
        trace!("vless outbound port is {}", vless_settings.port);
        trace!("vless outbound uuid is {}", vless_settings.id);
        trace!("vless outbound flow is {}", flow);
        match flow.clone() {
            VlessFlow::XtlsRprxVision | VlessFlow::XtlsRprxVisionUdp => {
                let any: &dyn Any = transport.as_ref() as &dyn Any;
                if let None = any.downcast_ref::<TcpTransport>() {
                    flow = VlessFlow::None;
                    error!("vless flow only support tcp transport");
                }
            }
            _ => {}
        }

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
            flow,
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
        context: Arc<crate::core::context::Context>,
        detour: Option<String>,
        net_location: Arc<NetLocation>,
    ) -> Result<Box<dyn AsyncXrayTcpStream>, io::Error> {
        self.get_vless_stream_tcp(context, detour, net_location)
            .await
    }

    async fn dial_udp(
        &self,
        context: Arc<crate::core::context::Context>,
        detour: Option<String>,
        net_location: Arc<NetLocation>,
    ) -> Result<Box<dyn AsyncXrayUdpStream>, io::Error> {
        let stream = self
            .get_vless_stream_udp(context.clone(), detour, net_location)
            .await?;

        Ok(TcpDatagramWrapper::new(context, stream).await?)
    }
}

impl VlessOutbound {
    async fn get_vless_stream_tcp(
        &self,
        context: Arc<crate::core::context::Context>,
        detour: Option<String>,
        net_location: Arc<NetLocation>,
    ) -> Result<Box<dyn AsyncXrayTcpStream>, io::Error> {
        let address = Address::from(&self.address)?;
        let server_location = Arc::new(NetLocation::new(address, self.port));
        let mut transport = match self.flow {
            VlessFlow::None => {
                self.transport
                    .dial(context, detour, server_location)
                    .await?
            }
            VlessFlow::XtlsRprxVision | VlessFlow::XtlsRprxVisionUdp => {
                let any: &dyn Any = self.transport.as_ref() as &dyn Any;
                let tls = any.downcast_ref::<TcpTransport>().unwrap();
                tls.dial_xtls(context, detour, server_location).await?
            }
        };

        // Perform encryption handshake and wrap transport if configured
        let mut transport: Box<dyn XrayTransport> = if let Some(ref enc) = self.encryption {
            let result = enc.handshake(&mut transport, true).await?;
            Box::new(EncryptedTransport::new(transport, result))
        } else {
            transport
        };

        let uuid = self.uuid.clone().to_vec();

        let port_bytes = net_location.port().to_be_bytes().to_vec();

        let address_bytes: Vec<u8> = net_location.address().to_vmess_vless_bytes();

        let version = [0];
        let additional_information_length = get_vless_addons(self.flow.clone());
        let mut header_bytes = Vec::new();
        header_bytes.extend_from_slice(&version);
        header_bytes.extend_from_slice(&uuid);
        header_bytes.extend_from_slice(additional_information_length.as_slice());
        header_bytes.extend_from_slice(&[Instruction::Tcp as u8]);
        header_bytes.extend_from_slice(&port_bytes);
        header_bytes.extend_from_slice(&address_bytes);
        transport.write_all(header_bytes.as_slice()).await?;

        let mut transport = match self.flow {
            VlessFlow::None => transport,
            VlessFlow::XtlsRprxVision | VlessFlow::XtlsRprxVisionUdp => {
                Box::new(VisionStream::new(transport, self.uuid.clone()))
            }
        };

        Ok(Box::new(VlessStream {
            transport,
            read_state: ReadState::ReadVersion,
            write_state: WriteState::WriteTcpData,
            auth: uuid,
            port: port_bytes,
            address: address_bytes,
            is_tcp: true,
            flow: self.flow.clone(),
            read_buffer: BytesMut::new(),
        }))
    }
    async fn get_vless_stream_udp(
        &self,
        context: Arc<crate::core::context::Context>,
        detour: Option<String>,
        net_location: Arc<NetLocation>,
    ) -> Result<Box<dyn AsyncXrayTcpStream>, io::Error> {
        if net_location.port == 443 && self.flow == VlessFlow::XtlsRprxVision {
            return Err(io::Error::other("XTLS rejected UDP/443 traffic"));
        }

        let address = Address::from(&self.address)?;
        let server_location = Arc::new(NetLocation::new(address, self.port));
        let mut transport = match self.flow {
            VlessFlow::None => {
                self.transport
                    .dial(context, detour, server_location)
                    .await?
            }
            VlessFlow::XtlsRprxVision | VlessFlow::XtlsRprxVisionUdp => {
                let any: &dyn Any = self.transport.as_ref() as &dyn Any;
                let tls = any.downcast_ref::<TcpTransport>().unwrap();
                tls.dial_xtls(context, detour, server_location).await?
            }
        };

        let mut instruction = match self.flow {
            VlessFlow::None => Instruction::Udp,
            VlessFlow::XtlsRprxVision | VlessFlow::XtlsRprxVisionUdp => Instruction::Mux,
        };

        let port_bytes = net_location.port().to_be_bytes().to_vec();
        let address_bytes: Vec<u8> = net_location.address().to_vmess_vless_bytes();
        let uuid = self.uuid.clone().to_vec();
        let version = [0];
        let additional_information_length = get_vless_addons(self.flow.clone());
        let mut header_bytes = Vec::new();
        header_bytes.extend_from_slice(&version);
        header_bytes.extend_from_slice(&uuid);
        header_bytes.extend_from_slice(additional_information_length.as_slice());
        header_bytes.extend_from_slice(&[instruction as u8]);

        match self.flow {
            VlessFlow::None => {
                header_bytes.extend_from_slice(&port_bytes);
                header_bytes.extend_from_slice(&address_bytes);
            }
            _ => {}
        };

        transport.write_all(header_bytes.as_slice()).await?;

        let transport: Box<dyn AsyncXrayTcpStream> = match self.flow {
            VlessFlow::None => Box::new(VlessStream {
                transport,
                read_state: ReadState::ReadVersion,
                write_state: WriteState::WriteUdpData,
                auth: uuid,
                port: port_bytes,
                address: address_bytes,
                is_tcp: false,
                flow: self.flow.clone(),
                read_buffer: BytesMut::new(),
            }),
            VlessFlow::XtlsRprxVision | VlessFlow::XtlsRprxVisionUdp => Box::new(
                VlessMuxStream::new(transport, self.uuid.clone(), net_location, get_global_id()),
            ),
        };
        return Ok(transport);
    }
}

struct VlessStream {
    transport: Box<dyn AsyncXrayTcpStream>,
    read_state: ReadState,
    write_state: WriteState,
    auth: Vec<u8>,
    port: Vec<u8>,
    address: Vec<u8>,
    is_tcp: bool,
    flow: VlessFlow,
    read_buffer: BytesMut,
}

#[derive(PartialEq, Copy, Clone)]
enum Instruction {
    Tcp = 1,
    Udp = 2,
    Mux = 3,
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
    WriteUdpData,
    WriteTcpData,
}

impl AsyncRead for VlessStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.read_buffer.is_empty() {
                if let ReadState::ReadVersion = self.read_state {
                    if self.read_buffer.len() >= 1 {
                        let _ = self.read_buffer.split_to(1);
                        self.read_state = ReadState::ReadAdditionalInformationLength;
                        continue;
                    }
                }
                if let ReadState::ReadAdditionalInformationLength = self.read_state {
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
                if let ReadState::ReadAdditionalInformation(length) = self.read_state {
                    let length = length as usize;
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
                if let ReadState::ReadUdpDataLength = self.read_state {
                    if self.read_buffer.len() >= 2 {
                        let bytes = self.read_buffer.split_to(2);
                        let length = BigEndian::read_u16(bytes.as_bytes());
                        self.read_state = ReadState::ReadUdpData(length);
                        continue;
                    }
                }
                if let ReadState::ReadUdpData(length) = self.read_state {
                    let length = length as usize;
                    if self.read_buffer.len() >= length {
                        let udp_data = self.read_buffer.split_to(length);
                        buf.put_slice(udp_data.as_bytes());
                        self.read_state = ReadState::ReadUdpDataLength;
                        return Poll::Ready(Ok(()));
                    }
                }
                if let ReadState::ReadTcpData = self.read_state {
                    let mut tcp_data = self.read_buffer.split();
                    buf.put_slice(tcp_data.as_ref());
                    return Poll::Ready(Ok(()));
                }
            }

            let cast_to_raw = match &self.read_state {
                ReadState::ReadVersion => true,
                ReadState::ReadAdditionalInformationLength => true,
                ReadState::ReadAdditionalInformation(_) => true,
                ReadState::ReadUdpDataLength => false,
                ReadState::ReadUdpData(_) => false,
                ReadState::ReadTcpData => false,
            };

            let len = match &self.read_state {
                ReadState::ReadVersion => 1usize,
                ReadState::ReadAdditionalInformationLength => 1usize,
                ReadState::ReadAdditionalInformation(length) => *length as usize,
                ReadState::ReadUdpDataLength => 2usize,
                ReadState::ReadUdpData(length) => *length as usize,
                ReadState::ReadTcpData => buf.capacity(),
            };

            let raw_stream: &mut Box<dyn AsyncXrayTcpStream> = if cast_to_raw {
                let raw_stream: &mut Box<dyn AsyncXrayTcpStream> = match self.flow {
                    VlessFlow::None => &mut self.transport,
                    _ => {
                        let any = self.transport.deref_mut() as &mut dyn Any;
                        any.downcast_mut::<VisionStream>()
                            .expect("vision stream")
                            .as_raw_stream()
                    }
                };
                raw_stream
            } else {
                &mut self.transport
            };

            //read data from transport
            let mut buffer_vev = vec_allocate(len);
            let mut buffer = ReadBuf::new(&mut buffer_vev);
            let result = ready!(Pin::new(raw_stream).poll_read(cx, &mut buffer));
            match result {
                Ok(_) => {
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
                WriteState::WriteUdpData => {
                    let len_buf = (buf.len() as u16).to_be_bytes();
                    let mut new_buf = Vec::new();
                    new_buf.extend_from_slice(&len_buf);
                    new_buf.extend_from_slice(&buf);
                    let result = ready!(Pin::new(&mut self.transport).poll_write(cx, &new_buf));
                    match result {
                        Ok(count) => {
                            if count != new_buf.len() {
                                let message = format!(
                                    "{{vless-write-state: {:?}, message: vless udp packet write length error}}",
                                    self.write_state
                                );
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
        Pin::new(&mut self.get_mut().transport).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().transport).poll_shutdown(cx)
    }
}

impl AsyncXrayTcpStream for VlessStream {}
