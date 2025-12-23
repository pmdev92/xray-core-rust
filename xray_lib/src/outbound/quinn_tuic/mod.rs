use std::fmt::Write;
use std::io;
use std::io::{Error, ErrorKind};
use std::net::{AddrParseError, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use futures_util::AsyncWriteExt;
use h3::client::SendRequest;
use log::{error, info, trace};
use quinn::{RecvStream, SendStream};
use quinn_proto::coding::Codec;
use quinn_proto::{ConnectionError, VarInt};
use rand::Rng;
use s2n_quic::stream::BidirectionalStream;
use s2n_quic_core::connection::Limits;
use tls_parser::nom::Parser;
use tokio::io::AsyncReadExt;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::error::Elapsed;
use tokio::time::timeout;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_util::time::FutureExt;
use uuid::Uuid;

use crate::common::net_location::NetLocation;
use crate::common::udp::TcpDatagramWrapper;
use crate::common::vec::vec_allocate;
use crate::core::context::Context;
use crate::core::io::{AsyncXrayTcpStream, AsyncXrayUdpStream};
use crate::core::outbound::Outbound;
use crate::core::transport::{Transport, XrayTransport};
use crate::outbound::quinn_tuic::config::TuicQuinnSettings;
use crate::outbound::quinn_tuic::handler::{TuicHandlerInner, TuicOutboundHandler};
use crate::outbound::quinn_tuic::protocol::connect::Connect;
use crate::outbound::quinn_tuic::protocol::ToCommand;
use crate::outbound::quinn_tuic::tcp_stream::TuicTcpStream;
use crate::security::tls::config::TlsConfig;
use crate::security::tls::verify::TlsNoCertVerifier;
use protocol::enums::{CongestionControl, UdpRelayMode};

pub mod config;
pub(crate) mod handler;
pub(crate) mod protocol;
pub(crate) mod tcp_stream;
pub(crate) mod udp_api;
pub(crate) mod udp_stream;
pub struct TuicQuinnOutbound {
    handler: Mutex<TuicOutboundHandler>,
    options: TuicOptions,
}

#[derive(Debug, Clone)]
pub(crate) struct TuicOptions {
    server_address: String,
    server_port: u16,
    tls_client_config: ClientConfig,
    server_name: String,
    password: Vec<u8>,
    uuid: Vec<u8>,
    heartbeat: u64,
    timeout: u64,
    udp_relay_mode: UdpRelayMode,
    congestion_control: CongestionControl,
}
impl TuicQuinnOutbound {
    pub fn new(tuic_settings: TuicQuinnSettings) -> Result<Self, io::Error> {
        trace!("tuic outbound address is {}", tuic_settings.address);
        trace!("tuic outbound port is {}", tuic_settings.port);
        trace!("tuic outbound password is {}", tuic_settings.password);
        trace!("tuic outbound uuid is {}", tuic_settings.uuid);

        let mut tls_client_config: ClientConfig;

        if tuic_settings.tls_config.verify.unwrap_or(true) {
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
        if tuic_settings.tls_config.zero_rtt.unwrap_or(false) {
            tls_client_config.enable_early_data = true;
        }
        if tuic_settings.tls_config.disable_sni.unwrap_or(false) {
            tls_client_config.enable_sni = false;
        }
        match tuic_settings.tls_config.alpn {
            None => {}
            Some(alpn) => {
                let bytes: Vec<Vec<u8>> = alpn.into_iter().map(|s| s.into_bytes()).collect();
                tls_client_config.alpn_protocols = bytes;
            }
        }

        let uuid = Uuid::parse_str(tuic_settings.uuid.as_str())
            .map_err(|err| to_io_error(err.to_string()))?
            .as_bytes()
            .to_vec();

        let mut heartbeat_string = tuic_settings.heartbeat.unwrap_or("10s".to_string());
        let mut heartbeat = heartbeat_string
            .trim_end_matches(|c: char| !c.is_numeric())
            .parse::<u64>()
            .unwrap_or(10);
        if heartbeat <= 0 {
            heartbeat = 1;
        }
        if heartbeat > 100 {
            heartbeat = 100;
        }
        let mut udp_relay_mode = UdpRelayMode::Native;
        if tuic_settings
            .udp_relay_mode
            .unwrap_or("".into())
            .to_lowercase()
            == "quic"
        {
            udp_relay_mode = UdpRelayMode::Quic;
        }

        let mut congestion_control = CongestionControl::Bbr;
        let congestion_control_string = tuic_settings
            .congestion_control
            .unwrap_or("".into())
            .to_lowercase();
        if congestion_control_string == "cubic" {
            congestion_control = CongestionControl::Cubic;
        }
        if congestion_control_string == "newreno" {
            congestion_control = CongestionControl::NewReno;
        }

        Ok(Self {
            handler: Mutex::new(TuicOutboundHandler::new()),
            options: TuicOptions {
                server_address: tuic_settings.address,
                server_port: tuic_settings.port,
                tls_client_config,
                server_name: tuic_settings.tls_config.server_name,
                password: tuic_settings.password.as_bytes().to_vec(),
                uuid,
                heartbeat,
                congestion_control,
                udp_relay_mode,
                timeout: 5,
            },
        })
    }
}
#[async_trait]
impl Outbound for TuicQuinnOutbound {
    async fn dial_tcp(
        &self,
        context: Arc<Context>,
        detour: Option<String>,
        net_location: Arc<NetLocation>,
    ) -> Result<Box<dyn AsyncXrayTcpStream>, Error> {
        trace!("dial tcp to {}", net_location.to_tuic_str());
        let (counter, connection_closer, (mut send_stream, mut receive_stream)) = {
            let (counter, connection_closer, result) = {
                let mut handler = self.handler.lock().await;
                let result = handler.open_stream(context, detour, &self.options).await;
                let result = match result {
                    Ok(result) => result,
                    Err(err) => {
                        return Err(err.into());
                    }
                };
                let connection_closer = result.get_connection_closer();
                (
                    result.tuic_counter,
                    connection_closer,
                    result.connection.open_bi().await,
                )
            };
            match result {
                Ok(result) => (counter, connection_closer, result),
                Err(err) => {
                    connection_closer.close_stream();
                    return Err(err.into());
                }
            }
        };
        let connect_bytes = Connect::new(net_location).to_command_bytes();
        let result = send_stream.write(&connect_bytes[..]).await;

        match result {
            Ok(_) => {}
            Err(err) => {
                connection_closer.close_stream();
                return Err(err.into());
            }
        }
        Ok(Box::new(TuicTcpStream {
            counter,
            send_stream,
            receive_stream,
        }))
    }

    async fn dial_udp(
        &self,
        context: Arc<Context>,
        detour: Option<String>,
        net_location: Arc<NetLocation>,
    ) -> Result<Box<dyn AsyncXrayUdpStream>, Error> {
        trace!("dial udp to {}", net_location.to_tuic_str());
        let mut handler = self.handler.lock().await;
        let udp_stream = handler
            .get_udp(context.clone(), detour, &self.options, net_location)
            .await?;
        Ok(TcpDatagramWrapper::new(context, Box::new(udp_stream)).await?)
    }
}

pub(crate) fn to_io_error(message: String) -> io::Error {
    io::Error::new(ErrorKind::InvalidInput, message)
}
