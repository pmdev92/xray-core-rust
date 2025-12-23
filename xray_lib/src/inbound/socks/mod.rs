use io::ErrorKind;
use std;
use std::collections::HashMap;
use std::io;
use std::io::Error;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::Deref;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::future::join_all;
use futures_util::{SinkExt, StreamExt};
use log::{error, info, warn};
use tokio::io::{AsyncReadExt, AsyncWriteExt, Sink, WriteHalf};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc::Receiver;
use tokio::sync::mpsc::Sender;
use tokio::task::JoinHandle;
use tokio::time::sleep;

use crate::common::address::Address;
use crate::common::buffer::copy;
use crate::common::constants::MAX_UDP_BUFFER_CAPACITY;
use crate::common::net_location::NetLocation;
use crate::common::udp::get_udp_open_port;
use crate::common::vec::vec_allocate;
use crate::core::context::Context;
use crate::core::dispatcher::Dispatcher;
use crate::core::inbound::{InboundConfig, InboundTcp};
use crate::core::io::{AsyncXrayTcpStream, AsyncXrayUdpStream};
use crate::core::router::Network;
use crate::core::session::Session;
use crate::core::sniffer::Sniffer;
use crate::inbound::nat_manager::NatManager;
use crate::inbound::socks::config::Socks5InboundSettings;
use crate::inbound::InboundProtocol;

pub mod config;
pub(crate) mod protocol;
pub(crate) mod udp;

#[derive(Debug)]
pub struct Socks5Inbound {
    pub net_location: NetLocation,
}

impl Socks5Inbound {
    pub fn new(inbound_config: Socks5InboundSettings) -> Self {
        let Ok(address) = Address::from(&inbound_config.listen) else {
            panic!("socks 5 inbound address is invalid");
        };
        let net_location = NetLocation::new(address, inbound_config.port);
        Self { net_location }
    }
    async fn process_socket(
        &self,
        session: Session,
        context: Arc<Context>,
        socket: TcpStream,
    ) -> Result<bool, io::Error> {
        let stream = Box::new(socket);
        let result = self.process_tcp(session, context, stream).await;
        match result {
            Ok(_) => Ok(true),
            Err(err) => Err(err),
        }
    }

    async fn process_tcp(
        &self,
        session: Session,
        context: Arc<Context>,
        mut tcp_stream: Box<TcpStream>,
    ) -> Result<bool, io::Error> {
        let mut data = [0u8; 2];
        tcp_stream.read_exact(&mut data).await?;
        if data[0] != protocol::SOCKS_VERSION {
            warn!("unsupported socks 5 version:  {}", data[0]);
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!("unsupported socks 5 version: {}", data[0]),
            ));
        }

        let method_len = data[1] as usize;

        if method_len < 1 {
            warn!("invalid socks 5 method length:  {}", data[0]);
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!("invalid socks 5 method length: {}", method_len),
            ));
        }
        let mut methods = vec![0u8; method_len];
        tcp_stream.read_exact(&mut methods).await?;

        let supported_method = protocol::auth_methods::NO_AUTH;

        if methods
            .into_iter()
            .find(move |method| *method == supported_method)
            .is_none()
        {
            warn!("Supported SOCKS method not found");
            // Write response: [VER_SOCKS5, no auth method]
            let response_data = [protocol::SOCKS_VERSION, protocol::auth_methods::NO_METHODS];
            tcp_stream.write_all(&response_data).await?;
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "Supported SOCKS method not found",
            ));
        }

        // Write response: [VER_SOCKS5, <selected method>]
        let response_data = [protocol::SOCKS_VERSION, protocol::auth_methods::NO_AUTH];
        tcp_stream.write_all(&response_data).await?;

        let mut connection_request = [0u8; 3];
        tcp_stream.read_exact(&mut connection_request).await?;
        if connection_request[0] != protocol::SOCKS_VERSION {
            warn!("invalid socks 5 version: {}", connection_request[0]);
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!("invalid socks 5 version: {}", connection_request[0]),
            ));
        }

        let command = connection_request[1];
        if command != protocol::socks_command::UDP_ASSOSIATE
            && command != protocol::socks_command::CONNECT
        {
            warn!("socks 5 command is not supported {}", command);
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!("socks 5 command is not supported {}", command),
            ));
        }

        if connection_request[2] != 0x0 {
            warn!("invalid socks5 reserved bit");
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "invalid socks5 reserved bit",
            ));
        }
        let target_location = read_target_location(&mut tcp_stream).await?;

        // info!("accept to {}",target_location);
        if command == protocol::socks_command::CONNECT {
            let mut success_response_bytes = vec![
                protocol::SOCKS_VERSION,
                protocol::response_code::SUCCESS,
                protocol::RESERVED,
            ];

            let Ok(local_address) = tcp_stream.local_addr() else {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "socks 5 connect command local address is invalid",
                ));
            };
            let Ok(address) = Address::from(&local_address.ip().to_string()) else {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "socks 5 connect command local address ip is invalid",
                ));
            };
            let local_net_location = NetLocation::new(address, local_address.port());
            let mut server_location_vec = write_server_location_to_vec(&local_net_location);
            success_response_bytes.append(&mut server_location_vec);
            tcp_stream
                .write_all(success_response_bytes.as_slice())
                .await?;
            let outbound_stream = Sniffer::route_tcp(
                session.clone(),
                context.clone(),
                Arc::new(target_location.clone()),
                &mut tcp_stream,
            )
            .await?;

            let (outbound_read, outbound_write) = tokio::io::split(outbound_stream);
            let (inbound_read, inbound_write) = tokio::io::split(tcp_stream);
            let context_clone = context.clone();

            let (download_end_tx, download_end_rx) = tokio::sync::mpsc::channel::<()>(32);
            let (upload_end_tx, upload_end_rx) = tokio::sync::mpsc::channel::<()>(32);

            let write_handler = tokio::spawn(async move {
                let mut outbound_read = outbound_read;
                let mut inbound_write = inbound_write;
                let _count = copy(
                    upload_end_rx,
                    context_clone,
                    &mut outbound_read,
                    &mut inbound_write,
                )
                .await;

                let _ = download_end_tx.send(()).await;
            });
            let context_clone = context.clone();
            let read_handler = tokio::spawn(async move {
                let mut inbound_read = inbound_read;
                let mut outbound_write = outbound_write;
                let _count = copy(
                    download_end_rx,
                    context_clone,
                    &mut inbound_read,
                    &mut outbound_write,
                )
                .await;
                let _ = upload_end_tx.send(()).await;
            });

            let mut handles = Vec::new();
            handles.push(read_handler);
            handles.push(write_handler);
            join_all(handles).await;
            drop(session);
            return Ok(true);
        }
        if command == protocol::socks_command::UDP_ASSOSIATE {
            let local_address = tcp_stream.local_addr()?;
            let port = get_udp_open_port(&local_address.ip().to_string())
                .await
                .ok_or(io::Error::from(ErrorKind::InvalidInput))?;
            let local_udp_net_location = Arc::new(NetLocation::new(
                Address::from(&local_address.ip().to_string())?,
                port,
            ));

            let local_udp_net_location_clone = local_udp_net_location.clone();
            let (sender_timeout, mut receiver_timeout) = tokio::sync::mpsc::channel::<()>(1);
            let session_clone = session.clone();
            tokio::spawn(async move {
                let Ok(socket_addr) = local_udp_net_location_clone
                    .to_socket_addr(context.clone())
                    .await
                else {
                    return;
                };
                let Ok(udp_socket) = UdpSocket::bind(socket_addr).await else {
                    return;
                };
                let nat = NatManager::new(
                    context,
                    session_clone,
                    udp_socket,
                    socket_addr,
                    sender_timeout,
                    None,
                );
                nat.start().await;
            });
            let success_response: OnceLock<Box<[u8]>> = OnceLock::new();
            let connection_success_response = success_response.get_or_init(|| {
                let mut response_bytes = vec![
                    protocol::SOCKS_VERSION,
                    protocol::response_code::SUCCESS,
                    protocol::RESERVED,
                ];
                let mut server_location_vec = write_server_location_to_vec(&local_udp_net_location);
                response_bytes.append(&mut server_location_vec);
                response_bytes.into_boxed_slice()
            });
            tcp_stream.write_all(&connection_success_response).await?;
            let mut buffer = [0u8; 1];
            tokio::select! {
                _ = tcp_stream.read(&mut buffer) => {
                },
                _ = receiver_timeout.recv() => {
                  let _ = tcp_stream.shutdown().await;
                }
            }
            drop(session);
            return Ok(true);
        }
        Ok(true)
    }
}

#[async_trait]
impl InboundTcp for Socks5Inbound {
    async fn start(self: Box<Self>, context: Arc<Context>) -> Result<(), Error> {
        let result = self.net_location.to_socket_addr(context.clone()).await;
        let socket_addr = match result {
            Ok(socket_addr) => socket_addr,
            Err(err) => {
                warn!("{}", err);
                return Err(Error::from(err));
            }
        };
        let socks_clone = Arc::new(self);
        let handler_tcp = tokio::spawn(async move {
            let result = TcpListener::bind(socket_addr).await;
            match result {
                Ok(listener) => {
                    let socket_addr = match listener.local_addr() {
                        Ok(ip) => ip,
                        Err(err) => {
                            warn!("{}", err);
                            return;
                        }
                    };
                    info!(
                        "listen on ip address {} and port number {}",
                        socket_addr.ip(),
                        socket_addr.port()
                    );
                    loop {
                        let (socket, _) = match listener.accept().await {
                            Ok(result) => result,
                            Err(err) => {
                                warn!("{}", err);
                                continue;
                            }
                        };
                        if !context.can_accept() {
                            warn!("platform reject accept new connection.");
                            continue;
                        }
                        let session_manager = context.get_session_manager().add_new_session().await;
                        let session_manager = match session_manager {
                            Ok(session_manager) => Arc::new(session_manager),
                            Err(err) => {
                                warn!("{}", err);
                                continue;
                            }
                        };

                        let session = Session::new(
                            session_manager,
                            InboundProtocol::SOCKS,
                            Network::Tcp,
                            socket.local_addr().ok(),
                            socket.peer_addr().ok(),
                        );

                        let socks_clone = socks_clone.clone();
                        let context_clone = context.clone();
                        tokio::spawn(async move {
                            let result = socks_clone
                                .process_socket(session, context_clone, socket)
                                .await;
                            match result {
                                Ok(_) => {}
                                Err(e) => {
                                    info!("process_socket result error {:?}", e)
                                }
                            }
                        });
                    }
                }
                Err(err) => {
                    error!("bind tcp listener error: {}", err);
                }
            }
        });
        let _ = handler_tcp.await;
        Ok(())
    }
}

async fn read_target_location(stream: &mut Box<TcpStream>) -> io::Result<NetLocation> {
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

fn write_server_location_to_vec(location: &NetLocation) -> Vec<u8> {
    let (address, port) = location.components();
    let mut vec = match address {
        Address::Ipv4(v4addr) => {
            let mut vec = Vec::with_capacity(7);
            vec.push(protocol::address_type::TYPE_IPV4);
            vec.extend_from_slice(&v4addr.octets());
            vec
        }
        Address::Ipv6(v6addr) => {
            let mut vec = Vec::with_capacity(19);
            vec.push(protocol::address_type::TYPE_IPV6);
            vec.extend_from_slice(&v6addr.octets());
            vec
        }
        Address::Hostname(domain_name) => {
            let domain_name_bytes = domain_name.as_bytes();
            let mut vec = Vec::with_capacity(4 + domain_name_bytes.len());
            vec.push(protocol::address_type::TYPE_DOMAIN_NAME);
            vec.push(domain_name_bytes.len() as u8);
            vec.extend_from_slice(domain_name_bytes);
            vec
        }
    };

    vec.push((port >> 8) as u8);
    vec.push((port & 0xff) as u8);
    vec
}
