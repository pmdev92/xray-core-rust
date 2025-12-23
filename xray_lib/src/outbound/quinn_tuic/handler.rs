use bytes::{Bytes, BytesMut};
use futures_util::AsyncWriteExt;
use h3::client::SendRequest;
use http::{Method, Request};
use log::{debug, error, info, trace, warn};

use quinn_proto::crypto::rustls::QuicClientConfig;

use crate::common::address::Address;
use crate::common::net_location::NetLocation;
use crate::core::context::Context;

use crate::outbound::quinn_tuic::protocol::authenticate::Authenticate;
use crate::outbound::quinn_tuic::protocol::enums::{CongestionControl, UdpRelayMode};
use crate::outbound::quinn_tuic::protocol::heartbeat::Heartbeat;
use crate::outbound::quinn_tuic::protocol::ToCommand;
use crate::outbound::quinn_tuic::udp_api::UdpApi;
use crate::outbound::quinn_tuic::udp_stream::TuicUdpStream;
use crate::outbound::quinn_tuic::{to_io_error, TuicOptions};
use aes::cipher::typenum::op;
use bitvec::macros::internal::funty::Fundamental;
use quinn_proto::congestion::{BbrConfig, CubicConfig, NewRenoConfig};
use quinn_proto::{TransportConfig, VarInt};
use rand::distributions::{Alphanumeric, DistString};
use rand::Rng;
use std::collections::{HashMap, VecDeque};
use std::io::{Error, ErrorKind};
use std::net::{AddrParseError, SocketAddr};
use std::ops::Deref;
use std::sync::atomic::{AtomicI32, AtomicU32};
use std::sync::{atomic, Arc};
use std::task::{ready, Waker};
use std::time::{Duration, Instant};
use std::{future, io};
use tls_parser::nom::error::context;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, MutexGuard, RwLock, TryLockError};
use tokio::time::{sleep, timeout};
use uuid::{uuid, Uuid};

pub(crate) struct TuicCounter {
    counter: Arc<AtomicI32>,
}
impl Clone for TuicCounter {
    fn clone(&self) -> Self {
        self.counter.fetch_add(1, atomic::Ordering::SeqCst);
        TuicCounter {
            counter: self.counter.clone(),
        }
    }
}
impl Drop for TuicCounter {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, atomic::Ordering::SeqCst);
    }
}

#[derive(Clone)]
pub(crate) struct TuicConnection {
    pub(crate) udp_api: Arc<UdpApi>,
    pub(crate) connection: quinn::Connection,
    pub(crate) tuic_counter: TuicCounter,
    closed: Arc<Mutex<bool>>,
    last_server_heartbeat_timestamp: Arc<Mutex<Instant>>,
}

impl TuicConnection {
    pub fn get_connection_closer(&self) -> TuicConnectionCloser {
        TuicConnectionCloser::new(self.closed.clone())
    }
}

#[derive(Clone)]
pub(crate) struct TuicConnectionCloser {
    closed: Arc<Mutex<bool>>,
}

impl TuicConnectionCloser {
    fn new(closed: Arc<Mutex<bool>>) -> Self {
        Self { closed }
    }
    pub fn close_stream(self) {
        let close = self.closed.clone();
        tokio::spawn(async move {
            let mut value = close.lock().await;
            if value.deref() == &false {
                warn!("mark tuic  connection as closed");
                *value = true;
            }
        });
    }
}

pub(crate) struct TuicHandlerInner {
    connection: Option<TuicConnection>,
}

pub(crate) struct TuicOutboundHandler {
    inner: Arc<RwLock<TuicHandlerInner>>,
    endpoint: Option<Arc<quinn::Endpoint>>,
}
impl TuicOutboundHandler {
    pub fn new() -> Self {
        let inner = TuicHandlerInner { connection: None };
        TuicOutboundHandler {
            inner: Arc::new(RwLock::new(inner)),
            endpoint: None,
        }
    }

    pub(crate) async fn open_stream(
        &mut self,
        context: Arc<Context>,
        detour: Option<String>,
        options: &TuicOptions,
    ) -> io::Result<TuicConnection> {
        {
            let inner = self.inner.clone();
            let mut mutex = inner.deref().read().await;
            match mutex.connection.as_ref() {
                None => {}
                Some(connection) => {
                    let connection_clone = connection.clone();
                    if let None = connection_clone.connection.close_reason() {
                        let last_server_heartbeat_timestamp = connection_clone
                            .last_server_heartbeat_timestamp
                            .as_ref()
                            .lock()
                            .await
                            .clone();
                        let duration = Instant::now() - last_server_heartbeat_timestamp;
                        let heartbeat = options.heartbeat.clone();
                        if duration > Duration::from_secs(heartbeat) {
                            *connection.closed.lock().await = true;
                        }
                        if *connection.closed.lock().await == false {
                            debug!("use exists tuic connection");
                            return Ok(connection_clone);
                        }
                    }
                }
            };
        }

        let address = Address::from(&options.server_address)?;
        let server_location = Arc::new(NetLocation::new(address, options.server_port));
        debug!("establish tuic connection with to {}", server_location);
        let (endpoint, address) = Self::create_endpoint_quinn(
            context,
            detour,
            server_location.clone(),
            options,
            self.endpoint.clone(),
        )
        .await?;
        self.endpoint = Some(endpoint.clone());
        let connecting = endpoint
            .connect(address, options.server_name.as_str())
            .map_err(|e: quinn_proto::ConnectError| to_io_error(e.to_string()))?;

        let connection = timeout(Duration::from_secs(options.timeout), connecting)
            .await
            .map_err(|_| to_io_error("tuic connect timed out".to_string()))?
            .map_err(|e: quinn_proto::ConnectionError| to_io_error(e.to_string()))?;
        debug!("tuic new connection to {} established", server_location);
        let token = TuicOutboundHandler::export_keying_material(
            &connection,
            options.uuid.clone().as_slice(),
            options.password.clone().as_slice(),
        );

        let authenticate = Authenticate::new(
            <[u8; 16]>::try_from(options.uuid.clone().as_slice()).unwrap(),
            token,
        );

        let mut authenticate_bytes = authenticate.to_command_bytes();

        let mut uni_stream = connection.open_uni().await?;
        let _ = uni_stream.write(authenticate_bytes.as_ref()).await?;
        let tuic_counter = TuicCounter {
            counter: Arc::new(AtomicI32::new(0)),
        };
        let last_server_heartbeat_timestamp = Arc::new(Mutex::new(Instant::now()));
        let tuic_connection = TuicConnection {
            udp_api: UdpApi::new(
                connection.clone(),
                options.udp_relay_mode.clone(),
                last_server_heartbeat_timestamp.clone(),
            ),
            connection,
            closed: Arc::new(Mutex::new(false)),
            tuic_counter,
            last_server_heartbeat_timestamp: last_server_heartbeat_timestamp.clone(),
        };
        let tuic_connection_clone = tuic_connection.clone();
        self.inner.write().await.connection = Some(tuic_connection);

        let inner_clone_1 = self.inner.clone();
        let inner_clone_2 = self.inner.clone();
        let heartbeat = options.heartbeat.clone();
        tokio::spawn(async move {
            loop {
                sleep(Duration::from_secs(heartbeat)).await;
                if let Some(result) = inner_clone_1.read().await.connection.as_ref() {
                    if (*result.closed.lock().await == false) {
                        let bytes = Heartbeat::new().to_command_bytes();
                        let send_result = result.connection.clone().send_datagram_wait(bytes).await;
                        match send_result {
                            Ok(_) => {
                                continue;
                            }
                            Err(_) => {}
                        }
                    }
                }
                let mut inner_helper = inner_clone_1.deref().write().await;
                let connection = inner_helper.connection.take();
                if let Some(mut result) = connection {
                    *result.closed.lock().await = true;
                    result.connection.close(VarInt::from(0u8), &vec![]);
                }
                warn!("tuic connection closed");
                break;
            }
        });
        tokio::spawn(async move {
            loop {
                sleep(Duration::from_secs(10)).await;
                if let Some(result) = inner_clone_2.read().await.connection.as_ref() {
                    let count = result.tuic_counter.counter.load(atomic::Ordering::Acquire);
                    if (count != 0 && *result.closed.lock().await == false) {
                        continue;
                    }
                }
                let mut inner_helper = inner_clone_2.deref().write().await;
                let connection = inner_helper.connection.take();
                if let Some(mut result) = connection {
                    *result.closed.lock().await = true;
                    result.connection.close(VarInt::from(0u8), &vec![]);
                }
                warn!("tuic connection not used and closed");
                break;
            }
        });
        Ok(tuic_connection_clone)
    }
    fn export_keying_material(
        connection: &quinn::Connection,
        uuid: &[u8],
        password: &[u8],
    ) -> [u8; 32] {
        let mut buf = [0; 32];
        if let Err(err) = connection.export_keying_material(&mut buf, uuid, password) {
            warn!("export keying material error {:#?}", err);
            buf = [0; 32];
        }
        buf
    }

    pub(crate) async fn get_udp(
        &mut self,
        context: Arc<Context>,
        detour: Option<String>,
        options: &TuicOptions,
        address: Arc<NetLocation>,
    ) -> io::Result<TuicUdpStream> {
        let result = self.open_stream(context, detour, options).await?;
        {
            let inner = self.inner.clone();
            let mutex = inner.deref().read().await;
            let mut handle = mutex.connection.as_ref();
            match handle {
                None => {}
                Some(connection) => {
                    if *connection.closed.lock().await == false {
                        debug!("use exists tuic udp connection");
                        return Ok(TuicUdpStream::new(
                            result.tuic_counter,
                            connection.udp_api.clone(),
                            address,
                        )
                        .await);
                    }
                }
            }
        }
        Err(Error::new(
            ErrorKind::BrokenPipe,
            "The tuic connection not exists",
        ))
    }

    pub(crate) async fn close_stream(&mut self) {
        warn!("connection tuic connection as closed");
        let inner = self.inner.clone();
        let mut inner_helper = inner.deref().write().await;
        let item = inner_helper.connection.as_mut();
        match item {
            None => {}
            Some(item) => {
                *item.closed.lock().await = true;
            }
        }
    }

    async fn create_endpoint_quinn(
        context: Arc<Context>,
        detour: Option<String>,
        server_location: Arc<NetLocation>,
        options: &TuicOptions,
        endpoint: Option<Arc<quinn::Endpoint>>,
    ) -> io::Result<(Arc<quinn::Endpoint>, SocketAddr)> {
        let server_address = context.dial_udp_proxy(detour, server_location).await?;
        if let Some(endpoint) = endpoint {
            return Ok((endpoint, server_address));
        }

        let bind: SocketAddr = if server_address.is_ipv6() {
            "[::]:0"
                .parse()
                .map_err(|err| to_io_error(format!("{:?}", err)))?
        } else {
            "0.0.0.0:0"
                .parse()
                .map_err(|err| to_io_error(format!("{:?}", err)))?
        };

        let mut client_config = quinn::ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(options.tls_client_config.clone()).unwrap(),
        ));

        let mut transport_config = TransportConfig::default();
        transport_config
            .max_idle_timeout(Some(
                Duration::from_secs(options.heartbeat * 4)
                    .try_into()
                    .unwrap(),
            ))
            .datagram_receive_buffer_size(Some(128 * 1024))
            .datagram_send_buffer_size(128 * 1024)
            .send_window(128 * 1024)
            .receive_window(VarInt::from(128 * 1024u32))
            .stream_receive_window(VarInt::from(128 * 1024u32));

        match options.congestion_control {
            CongestionControl::Cubic => {
                transport_config.congestion_controller_factory(Arc::new(CubicConfig::default()))
            }
            CongestionControl::NewReno => {
                transport_config.congestion_controller_factory(Arc::new(NewRenoConfig::default()))
            }
            CongestionControl::Bbr => {
                transport_config.congestion_controller_factory(Arc::new(BbrConfig::default()))
            }
        };
        client_config.transport_config(Arc::new(transport_config));
        let mut endpoint = context.bind_endpoint(bind).await?;
        endpoint.set_default_client_config(client_config);
        Ok((Arc::new(endpoint), server_address))
    }
}
