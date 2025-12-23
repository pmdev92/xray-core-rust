use std::any::{type_name, Any};
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
use crate::outbound::vless::flow::{get_vless_addons, VlessFlow};
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

        Self {
            address: vless_settings.address,
            port: vless_settings.port,
            flow,
            uuid,
            transport,
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
        return self
            .get_vless_stream_tcp(context, detour, net_location)
            .await;
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

        let mut transport: Box<dyn AsyncXrayTcpStream> = match self.flow {
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
    // WriteHeader,
    WriteUdpData,
    WriteTcpData,
}

impl AsyncRead for VlessStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.read_buffer.is_empty() {
            if let ReadState::ReadVersion = self.read_state {
                if self.read_buffer.len() >= 1 {
                    let _ = self.read_buffer.split_to(1);
                    self.read_state = ReadState::ReadAdditionalInformationLength;
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
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
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
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
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
            }
            if let ReadState::ReadUdpDataLength = self.read_state {
                if self.read_buffer.len() >= 2 {
                    let bytes = self.read_buffer.split_to(2);
                    let length = BigEndian::read_u16(bytes.as_bytes());
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
        let mut cast_to_raw = false;
        let mut read_count = buf.capacity();
        match &self.read_state {
            ReadState::ReadVersion => {
                read_count = 1;
                cast_to_raw = true;
            }
            ReadState::ReadAdditionalInformationLength => {
                read_count = 1;
                cast_to_raw = true;
            }
            ReadState::ReadAdditionalInformation(length) => {
                read_count = length.clone() as usize;
                cast_to_raw = true;
            }
            ReadState::ReadUdpDataLength => {}
            ReadState::ReadUdpData(_) => {}
            ReadState::ReadTcpData => {}
        }

        //read data from transport
        let mut buffer_vev = vec_allocate(read_count);
        let mut buffer = ReadBuf::new(&mut buffer_vev);
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

        let result = ready!(Pin::new(raw_stream).poll_read(cx, &mut buffer));
        return match result {
            Ok(_) => {
                self.read_buffer.extend_from_slice(buffer.filled());
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(err) => {
                let message = format!(
                    "{{vless-read-state: {:?}, message: {}}}",
                    self.read_state, err
                );
                let error = io::Error::new(err.kind(), message);
                Poll::Ready(Err(error))
            }
        };
    }
}

impl AsyncWrite for VlessStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        if let WriteState::WriteUdpData = self.write_state {
            let len_buf = (buf.len() as u16).to_be_bytes();
            let mut new_buf = Vec::new();
            new_buf.extend_from_slice(&len_buf);
            new_buf.extend_from_slice(&buf);
            let result = ready!(Pin::new(&mut self.transport).poll_write(cx, &new_buf));
            return match result {
                Ok(_) => {
                    // if count != new_buf.len() {
                    //     let message = format!("{{vless-write-state: {:?}, message: vless udp packet write length error}}", self.write_state);
                    //     return Poll::Ready(Err(s2n_quic_io::Error::new(ErrorKind::BrokenPipe, message)));
                    // }
                    Poll::Ready(Ok(buf.len()))
                }
                Err(err) => {
                    let message = format!(
                        "{{vless-write-state: {:?}, message: {}}}",
                        self.write_state, err
                    );
                    Poll::Ready(Err(io::Error::new(ErrorKind::BrokenPipe, message)))
                }
            };
        }

        let result = ready!(Pin::new(&mut self.transport).poll_write(cx, buf));
        return match result {
            Ok(size) => Poll::Ready(Ok(size)),
            Err(err) => {
                let message = format!(
                    "{{vless-write-state: {:?}, message: {}}}",
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

impl AsyncXrayTcpStream for VlessStream {}
