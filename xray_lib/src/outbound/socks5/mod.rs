pub mod config;
mod protocol;
mod tcp;
mod udp;

use crate::common::address::Address;
use crate::common::net_location::NetLocation;
use crate::core::io::{AsyncXrayTcpStream, AsyncXrayUdpStream};
use crate::core::outbound::Outbound;
use crate::core::transport::{Transport, XrayTransport};
use crate::outbound::socks5::config::Socks5Settings;
use crate::outbound::socks5::protocol::auth_methods::NO_AUTH;
use crate::outbound::socks5::protocol::response_code::SUCCESS;
use crate::outbound::socks5::protocol::socks_command::{CONNECT, UDP_ASSOSIATE};
use crate::outbound::socks5::protocol::{RESERVED, SOCKS_VERSION};
use crate::outbound::socks5::tcp::Socks5TcpStream;
use crate::outbound::socks5::udp::Socks5UdpStream;
use async_trait::async_trait;
use bytes::BytesMut;
use futures_util::future::err;
use log::{error, trace, warn};
use std::any::{type_name, Any};
use std::fmt::{format, Debug};
use std::io;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

pub struct Socks5Outbound {
    address: String,
    port: u16,
    transport: Box<dyn Transport>,
}

impl Socks5Outbound {
    pub fn new(
        socks5_settings: Socks5Settings,
        transport: Box<dyn Transport>,
    ) -> Result<Self, io::Error> {
        trace!("socks5 outbound address is {}", socks5_settings.address);
        trace!("socks5 outbound port is {}", socks5_settings.port);

        Ok(Self {
            address: socks5_settings.address,
            port: socks5_settings.port,
            transport,
        })
    }
}

#[async_trait]
impl Outbound for Socks5Outbound {
    async fn dial_tcp(
        &self,
        context: Arc<crate::core::context::Context>,
        detour: Option<String>,
        net_location: Arc<NetLocation>,
    ) -> Result<Box<dyn AsyncXrayTcpStream>, io::Error> {
        let address = Address::from(&self.address)?;
        let server_location = Arc::new(NetLocation::new(address, self.port));
        let mut transport = self
            .transport
            .dial(context, detour, server_location.clone())
            .await?;

        //version auth_methods_count auths
        let data = [SOCKS_VERSION, 1, NO_AUTH];
        transport.write_all(&data).await?;
        //version selected_auth
        let mut data = [0u8; 2];
        transport.read_exact(&mut data).await?;
        if data[0] != SOCKS_VERSION {
            warn!("unsupported socks 5 version:  {}", data[0]);
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!("unsupported socks 5 version: {}", data[0]),
            ));
        }
        if data[1] != NO_AUTH {
            warn!("unsupported socks 5 auth:  {}", data[1]);
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!("unsupported socks 5 auth: {}", data[1]),
            ));
        }
        //version method reserved
        let data = [SOCKS_VERSION, CONNECT, RESERVED];
        transport.write_all(&data).await?;
        let address_bytes: Vec<u8> = net_location.address().to_socks_trojan_bytes();
        transport.write_all(&address_bytes).await?;
        let port_bytes = net_location.port().to_be_bytes().to_vec();
        transport.write_all(&port_bytes).await?;

        //version result reserved
        let mut data = [0u8; 3];
        transport.read_exact(&mut data).await?;
        if data[0] != SOCKS_VERSION {
            warn!("unsupported socks 5 version:  {}", data[0]);
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!("unsupported socks 5 version: {}", data[0]),
            ));
        }
        if data[1] != SUCCESS {
            warn!("socks 5 connect failed:  {}", data[1]);
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!("socks 5 connect failed: {}", data[0]),
            ));
        }
        if data[2] != SUCCESS {
            warn!("socks 5 reserved not match:  {}", data[2]);
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!("socks 5 reserved not match: {}", data[2]),
            ));
        }
        let socks5_server_address = read_target_location(&mut transport).await?;
        if socks5_server_address.port != server_location.port {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "mismatch socks5 server port: {} {}",
                    socks5_server_address.port, server_location.port
                ),
            ));
        }
        if !server_location.address.is_hostname() {
            if socks5_server_address.address != server_location.address {
                return Err(io::Error::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "mismatch socks5 server address: {} {}",
                        server_location.address.to_string(),
                        socks5_server_address.address.to_string()
                    ),
                ));
            }
        }

        Ok(Box::new(Socks5TcpStream::new(transport)))
    }

    async fn dial_udp(
        &self,
        context: Arc<crate::core::context::Context>,
        detour: Option<String>,
        net_location: Arc<NetLocation>,
    ) -> Result<Box<dyn AsyncXrayUdpStream>, io::Error> {
        let address = Address::from(&self.address)?;
        let server_location = Arc::new(NetLocation::new(address, self.port));
        let mut transport = self
            .transport
            .dial(context.clone(), detour, server_location.clone())
            .await?;
        //version auth_methods_count auths
        let data = [SOCKS_VERSION, 1, NO_AUTH];
        transport.write_all(&data).await?;
        //version selected_auth
        let mut data = [0u8; 2];
        transport.read_exact(&mut data).await?;
        if data[0] != SOCKS_VERSION {
            warn!("unsupported socks 5 version:  {}", data[0]);
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!("unsupported socks 5 version: {}", data[0]),
            ));
        }
        if data[1] != NO_AUTH {
            warn!("unsupported socks 5 auth:  {}", data[1]);
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!("unsupported socks 5 auth: {}", data[1]),
            ));
        }
        //version method reserved
        let data = [SOCKS_VERSION, UDP_ASSOSIATE, RESERVED];
        transport.write_all(&data).await?;
        let address_bytes: Vec<u8> = net_location.address().to_socks_trojan_bytes();
        transport.write_all(&address_bytes).await?;
        let port_bytes = net_location.port().to_be_bytes().to_vec();
        transport.write_all(&port_bytes).await?;

        //version result reserved
        let mut data = [0u8; 3];
        transport.read_exact(&mut data).await?;
        if data[0] != SOCKS_VERSION {
            warn!("unsupported socks 5 version:  {}", data[0]);
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!("unsupported socks 5 version: {}", data[0]),
            ));
        }
        if data[1] != SUCCESS {
            warn!("socks 5 connect failed:  {}", data[1]);
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!("socks 5 connect failed: {}", data[0]),
            ));
        }
        if data[2] != SUCCESS {
            warn!("socks 5 reserved not match:  {}", data[2]);
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!("socks 5 reserved not match: {}", data[2]),
            ));
        }
        let socks5_udp_server_address = read_target_location(&mut transport).await?;

        let socket_addr = socks5_udp_server_address
            .to_socket_addr(context.clone())
            .await?;
        let local_addr = if socket_addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let udp_socket = UdpSocket::bind(local_addr).await?;
        let _ = udp_socket.connect(socket_addr.clone()).await?;
        Ok(Box::new(
            Socks5UdpStream::new(context, net_location, transport, udp_socket).await?,
        ))
    }
}

async fn read_target_location(stream: &mut Box<dyn XrayTransport>) -> io::Result<NetLocation> {
    let mut data = [0u8; 1];

    stream.read_exact(&mut data).await?;

    let address_type = data[0];
    match address_type {
        protocol::address_type::TYPE_IPV4 => {
            let mut address_bytes = [0u8; 6];
            stream.read_exact(&mut address_bytes).await?;
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

            Ok(NetLocation::new(Address::Ipv4(v4addr), port))
        }
        protocol::address_type::TYPE_IPV6 => {
            let mut address_bytes = [0u8; 18];
            stream.read_exact(&mut address_bytes).await?;

            let v6addr = Ipv6Addr::new(
                u16::from_be_bytes(
                    address_bytes[0..2]
                        .try_into()
                        .map_err(|_| io::Error::from(ErrorKind::Other))?,
                ),
                u16::from_be_bytes(
                    address_bytes[2..4]
                        .try_into()
                        .map_err(|_| io::Error::from(ErrorKind::Other))?,
                ),
                u16::from_be_bytes(
                    address_bytes[4..6]
                        .try_into()
                        .map_err(|_| io::Error::from(ErrorKind::Other))?,
                ),
                u16::from_be_bytes(
                    address_bytes[6..8]
                        .try_into()
                        .map_err(|_| io::Error::from(ErrorKind::Other))?,
                ),
                u16::from_be_bytes(
                    address_bytes[8..10]
                        .try_into()
                        .map_err(|_| io::Error::from(ErrorKind::Other))?,
                ),
                u16::from_be_bytes(
                    address_bytes[10..12]
                        .try_into()
                        .map_err(|_| io::Error::from(ErrorKind::Other))?,
                ),
                u16::from_be_bytes(
                    address_bytes[12..14]
                        .try_into()
                        .map_err(|_| io::Error::from(ErrorKind::Other))?,
                ),
                u16::from_be_bytes(
                    address_bytes[14..16]
                        .try_into()
                        .map_err(|_| io::Error::from(ErrorKind::Other))?,
                ),
            );

            let port = u16::from_be_bytes(
                address_bytes[16..18]
                    .try_into()
                    .map_err(|_| io::Error::from(ErrorKind::Other))?,
            );

            Ok(NetLocation::new(Address::Ipv6(v6addr), port))
        }
        protocol::address_type::TYPE_DOMAIN_NAME => {
            stream.read_exact(&mut data).await?;
            let address_len = data[0] as usize;
            let mut address_bytes = vec![0u8; address_len + 2];
            stream.read_exact(&mut address_bytes).await?;

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
                    .map_err(|_| io::Error::from(ErrorKind::Other))?,
            );

            // Although this is supposed to be a hostname, some clients will pass
            // ipv4 and ipv6 addresses as well, so parse it rather than directly
            // using Address:Hostname enum.
            Ok(NetLocation::new(Address::from(address_str)?, port))
        }
        _ => Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!("Unknown address type: {}", address_type),
        )),
    }
}
