use std::fmt::Write;
use std::io;
use std::io::{Error, ErrorKind};
use std::net::{AddrParseError, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use futures_util::AsyncWriteExt;
use h3::client::SendRequest;
use log::{error, info, trace, warn};
use quinn_proto::coding::Codec;
use quinn_proto::VarInt;
use rand::Rng;
use s2n_quic::stream::BidirectionalStream;
use s2n_quic_core::connection::Limits;
use tls_parser::nom::Parser;
use tokio::io::AsyncReadExt;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_util::time::FutureExt;

use crate::common::net_location::NetLocation;
use crate::common::udp::TcpDatagramWrapper;
use crate::common::vec::vec_allocate;
use crate::core::context::Context;
use crate::core::io::{AsyncXrayTcpStream, AsyncXrayUdpStream};
use crate::core::outbound::Outbound;
use crate::core::transport::{Transport, XrayTransport};
use crate::outbound::quinn_hysteria2::config::HysteriaQuinnSettings;
use crate::outbound::quinn_hysteria2::handler::Hysteria2OutboundHandler;
use crate::outbound::quinn_hysteria2::tcp_stream::Hysteria2TcpStream;
use crate::outbound::quinn_hysteria2::udp_stream::Hysteria2UdpStream;
use crate::outbound::quinn_hysteria2::varint::decode;
use crate::outbound::quinn_tuic::protocol::packet::error;
use crate::security::tls::config::TlsConfig;
use crate::security::tls::verify::TlsNoCertVerifier;

pub mod config;
pub(crate) mod handler;
pub(crate) mod salamander;
pub(crate) mod tcp_stream;

pub(crate) mod udp;
pub(crate) mod udp_api;
pub(crate) mod udp_stream;
pub(crate) mod varint;

pub struct HysteriaQuinnOutbound {
    handler: Mutex<Hysteria2OutboundHandler>,
    options: Hysteria2S2nQuicOptions,
}

#[derive(Debug, Clone)]
pub(crate) struct Hysteria2S2nQuicOptions {
    auth: String,
    server_address: String,
    server_port: u16,
    tls_client_config: ClientConfig,
    server_name: String,
    obfs_type: String,
    obfs_password: String,
    hop_enable: bool,
    hop_ports: Vec<u16>,
    hop_intervals: u32,
    up_bandwidth: u64,
    down_bandwidth: u64,
    timeout: u64,
    quic_max_idle_timeout: Option<u64>,
    quic_max_keep_alive_period: Option<u64>,
}

impl HysteriaQuinnOutbound {
    pub fn new(hysteria2_settings: HysteriaQuinnSettings) -> Self {
        let obfs_type = hysteria2_settings
            .obfs_type
            .clone()
            .unwrap_or("-".to_string());
        let obfs_password = hysteria2_settings
            .obfs_password
            .clone()
            .unwrap_or("-".to_string());
        trace!(
            "quinn_hysteria2 outbound address is {}",
            hysteria2_settings.address
        );
        trace!(
            "quinn_hysteria2 outbound port is {}",
            hysteria2_settings.port
        );
        trace!(
            "quinn_hysteria2 outbound password is {}",
            hysteria2_settings.password
        );
        trace!("quinn_hysteria2 outbound obfs type is {}", obfs_type);
        trace!(
            "quinn_hysteria2 outbound obfs password is {}",
            obfs_password
        );

        let mut tls_client_config: ClientConfig;

        if hysteria2_settings.tls_config.verify.unwrap_or(true) {
            let mut root_cert_store = RootCertStore::empty();
            root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            tls_client_config = ClientConfig::builder()
                .with_root_certificates(root_cert_store)
                .with_no_client_auth();
        } else {
            tls_client_config = ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(TlsNoCertVerifier {}))
                .with_no_client_auth();
        }
        tls_client_config.enable_early_data = true;
        tls_client_config.alpn_protocols = vec![b"h3".into()];
        let hop_ports = hysteria2_settings.hop_ports.unwrap_or("".to_string());
        let mut hop_enable = false;

        let mut hop_ports_vec: Vec<u16> = vec![];
        let hop_ports = hop_ports.split(",");
        for ports in hop_ports {
            let ports = ports.trim();
            if (ports.contains("-")) {
                let ports = ports.split("-");
                let ports = ports.collect::<Vec<&str>>();
                let port1 = ports[0].parse::<u16>().unwrap_or(0);
                let port2 = ports[1].parse::<u16>().unwrap_or(0);
                if (ports.len() == 2 && port2 > port1) {
                    for port in port1..=port2 {
                        if (port != 0 && !hop_ports_vec.contains(&port)) {
                            hop_ports_vec.push(port);
                        }
                    }
                }
            } else {
                let port = ports.parse::<u16>().unwrap_or(0);
                if (port != 0 && !hop_ports_vec.contains(&port)) {
                    hop_ports_vec.push(port);
                }
            }
        }
        if (hop_ports_vec.len() > 0) {
            hop_enable = true;
        }

        Self {
            handler: Mutex::new(Hysteria2OutboundHandler::new()),
            options: Hysteria2S2nQuicOptions {
                server_name: hysteria2_settings.tls_config.server_name,
                auth: hysteria2_settings.password,
                server_address: hysteria2_settings.address,
                server_port: hysteria2_settings.port,
                tls_client_config,
                obfs_type,
                obfs_password,
                hop_enable,
                hop_ports: hop_ports_vec,
                hop_intervals: hysteria2_settings.hop_intervals.unwrap_or(30),
                up_bandwidth: hysteria2_settings.up_bandwidth.unwrap_or(0),
                down_bandwidth: hysteria2_settings.down_bandwidth.unwrap_or(0),
                quic_max_idle_timeout: hysteria2_settings.quic_max_idle_timeout,
                quic_max_keep_alive_period: hysteria2_settings.quic_max_keep_alive_period,
                timeout: 5,
            },
        }
    }
}

#[async_trait]
impl Outbound for HysteriaQuinnOutbound {
    async fn dial_tcp(
        &self,
        context: Arc<Context>,
        detour: Option<String>,
        net_location: Arc<NetLocation>,
    ) -> Result<Box<dyn AsyncXrayTcpStream>, Error> {
        trace!("dial tcp to {}", net_location.to_hysteria2_str());
        let (counter, connection_closer, (mut send_stream, mut receive_stream)) = {
            let (counter, connection_closer, result) = {
                let mut handler = self.handler.lock().await;
                let hysteria2_connection_result =
                    handler.open_stream(context, detour, &self.options).await;
                let hysteria2_connection = match hysteria2_connection_result {
                    Ok(hysteria2_connection_result) => hysteria2_connection_result,
                    Err(error) => {
                        warn!(
                            "dial tcp to {} error {}",
                            net_location.to_hysteria2_str(),
                            error
                        );
                        return Err(error);
                    }
                };
                let connection_closer = hysteria2_connection.get_connection_closer();
                (
                    hysteria2_connection.hysteria2_counter,
                    connection_closer,
                    hysteria2_connection.connection.open_bi().await,
                )
            };
            match result {
                Ok(result) => (counter, connection_closer, result),
                Err(error) => {
                    connection_closer.close_stream();
                    return Err(error.into());
                }
            }
        };
        let address = net_location.to_hysteria2_str();
        let tcp_request = VarInt::from_u64(0x401u64).map_err(|err| to_io_error(err.to_string()))?;
        let address_len =
            VarInt::from_u64(address.len() as u64).map_err(|err| to_io_error(err.to_string()))?;
        let padding_len = VarInt::from_u64(0u64).map_err(|err| to_io_error(err.to_string()))?;
        let mut data = BytesMut::new();
        tcp_request.encode(&mut data);
        address_len.encode(&mut data);
        data.write_str(address.as_str())
            .map_err(|err| to_io_error(err.to_string()))?;
        padding_len.encode(&mut data);

        let result = send_stream.write(data.freeze().to_vec().as_slice()).await;
        match result {
            Ok(_) => {}
            Err(err) => {
                connection_closer.close_stream();
                return Err(err.into());
            }
        }

        let mut buffer = [0u8; 1];
        let result = receive_stream.read_exact(buffer.as_mut_slice()).await;
        match result {
            Ok(_) => {}
            Err(err) => {
                connection_closer.close_stream();
                return Err(Error::new(ErrorKind::BrokenPipe, err));
            }
        }
        if buffer[0] != 0 {
            return Err(Error::new(
                ErrorKind::ConnectionAborted,
                format!(
                    "server abort the tcp connection to {}",
                    net_location.to_hysteria2_str()
                ),
            ));
        }
        let message_len = decode(&mut receive_stream).await?;
        let mut buffer: Vec<u8> = vec_allocate(message_len.into_inner() as usize);
        let result = receive_stream.read_exact(buffer.as_mut_slice()).await;
        match result {
            Ok(_) => {}
            Err(err) => {
                connection_closer.close_stream();
                return Err(Error::new(ErrorKind::BrokenPipe, err));
            }
        }
        let padding_len = decode(&mut receive_stream).await?;
        let mut buffer: Vec<u8> = vec_allocate(padding_len.into_inner() as usize);
        let result = receive_stream.read_exact(buffer.as_mut_slice()).await;
        match result {
            Ok(_) => {}
            Err(err) => {
                connection_closer.close_stream();
                return Err(Error::new(ErrorKind::BrokenPipe, err));
            }
        }
        Ok(Box::new(Hysteria2TcpStream {
            counter,
            address,
            send_stream,
            receive_stream,
            read_buffer: Default::default(),
            write_buffer: Default::default(),
            read_closed: false,
        }))
    }

    async fn dial_udp(
        &self,
        context: Arc<Context>,
        detour: Option<String>,
        net_location: Arc<NetLocation>,
    ) -> Result<Box<dyn AsyncXrayUdpStream>, io::Error> {
        trace!("dial udp to {}", net_location.to_hysteria2_str());
        let address = net_location.to_hysteria2_str();
        let mut handler = self.handler.lock().await;
        let udp_stream_result = handler
            .get_udp(context.clone(), detour, &self.options, address)
            .await;
        let udp_stream = match udp_stream_result {
            Ok(udp_stream) => udp_stream,
            Err(error) => {
                warn!(
                    "dial udp to {} error {}",
                    net_location.to_hysteria2_str(),
                    error
                );
                return Err(error);
            }
        };
        Ok(TcpDatagramWrapper::new(context, Box::new(udp_stream)).await?)
    }
}

pub(crate) fn to_io_error(message: String) -> io::Error {
    io::Error::new(ErrorKind::InvalidInput, message)
}
