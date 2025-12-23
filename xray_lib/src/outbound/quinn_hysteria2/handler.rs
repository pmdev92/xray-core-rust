use crate::common::address::Address;
use crate::common::net_location::NetLocation;
use crate::core::context::Context;
use crate::outbound::quinn_hysteria2::udp::UDPMessage;
use crate::outbound::quinn_hysteria2::udp_api::UdpApi;
use crate::outbound::quinn_hysteria2::udp_stream::Hysteria2UdpStream;
use crate::outbound::quinn_hysteria2::{salamander, to_io_error, Hysteria2S2nQuicOptions};
use bytes::Bytes;
use futures_util::FutureExt;
use h3::client::SendRequest;
use http::{Method, Request};
use log::{debug, error, info, warn};
use quinn::{udp, AsyncTimer, AsyncUdpSocket, Connection, Runtime, TokioRuntime};
use quinn_proto::crypto::rustls::QuicClientConfig;
use quinn_proto::{EndpointConfig, IdleTimeout, MtuDiscoveryConfig, TransportConfig, VarInt};
use rand::distributions::{Alphanumeric, DistString};
use rand::Rng;
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::io::{Error, ErrorKind};
use std::net::{AddrParseError, SocketAddr};
use std::ops::Deref;
use std::pin::Pin;
use std::sync::atomic::AtomicI32;
use std::sync::{atomic, Arc};
use std::task::Waker;
use std::time::{Duration, Instant};
use std::{future, io};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, MutexGuard, RwLock, TryLockError};
use tokio::time::{sleep, sleep_until, timeout};

pub(crate) struct Hysteria2Counter {
    counter: Arc<AtomicI32>,
}

impl Clone for Hysteria2Counter {
    fn clone(&self) -> Self {
        self.counter.fetch_add(1, atomic::Ordering::SeqCst);
        Hysteria2Counter {
            counter: self.counter.clone(),
        }
    }
}

impl Drop for Hysteria2Counter {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, atomic::Ordering::SeqCst);
    }
}

#[derive(Clone)]
pub(crate) struct Hysteria2Connection {
    pub(crate) udp_api: Arc<UdpApi>,
    pub(crate) connection: Connection,
    pub(crate) support_udp: bool,
    pub(crate) hysteria2_counter: Hysteria2Counter,
    instant: Option<Instant>,
    closed: Arc<Mutex<bool>>,
}

impl Hysteria2Connection {
    pub fn get_connection_closer(&self) -> Hysteria2ConnectionCloser {
        Hysteria2ConnectionCloser::new(self.closed.clone())
    }
}

#[derive(Clone)]
pub(crate) struct Hysteria2ConnectionCloser {
    closed: Arc<Mutex<bool>>,
}

impl Hysteria2ConnectionCloser {
    fn new(closed: Arc<Mutex<bool>>) -> Self {
        Self { closed }
    }
    pub fn close_stream(self) {
        let close = self.closed.clone();
        tokio::spawn(async move {
            let mut value = close.lock().await;
            if value.deref() == &false {
                warn!("mark hysteria 2 connection as closed");
                *value = true;
            }
        });
    }
}

pub(crate) struct Hysteria2OutboundHandlerInner {
    pub(crate) connection: Option<Hysteria2Connection>,
    guard: Option<SendRequest<h3_quinn::OpenStreams, Bytes>>,
}

pub(crate) struct Hysteria2OutboundHandler {
    pub(crate) inner: Arc<RwLock<Hysteria2OutboundHandlerInner>>,
    endpoint: Option<Arc<quinn::Endpoint>>,
}

impl Hysteria2OutboundHandler {
    pub fn new() -> Self {
        let inner = Hysteria2OutboundHandlerInner {
            connection: None,
            guard: None,
        };
        Hysteria2OutboundHandler {
            inner: Arc::new(RwLock::new(inner)),
            endpoint: None,
        }
    }

    pub(crate) async fn open_stream(
        &mut self,
        context: Arc<Context>,
        detour: Option<String>,
        options: &Hysteria2S2nQuicOptions,
    ) -> io::Result<Hysteria2Connection> {
        {
            let inner = self.inner.clone();
            let mut mutex = inner.deref().read().await;
            match mutex.connection.as_ref() {
                None => {}
                Some(connection) => {
                    let connection_clone = connection.clone();
                    if let None = connection_clone.connection.close_reason() {
                        if *connection.closed.lock().await == false {
                            if (connection.instant.is_some()) {
                                if (Instant::now() < connection.instant.unwrap()) {
                                    debug!("use exists hysteria 2 connection");
                                    return Ok(connection_clone);
                                }
                            } else {
                                debug!("use exists hysteria 2 connection");
                                return Ok(connection_clone);
                            }
                        }
                    }
                }
            };
        }

        let mut port = options.server_port;
        if (options.hop_enable) {
            let len = options.hop_ports.len();
            let random_number = rand::thread_rng().gen_range(0..len);
            port = options.hop_ports[random_number];
        }

        let address = Address::from(&options.server_address)?;
        let server_location = Arc::new(NetLocation::new(address, port));

        debug!("establish hysteria2 connection to {}", server_location);
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

        let conn = timeout(Duration::from_secs(options.timeout), connecting)
            .await
            .map_err(|_| to_io_error("hysteria 2 connect timed out".to_string()))?
            .map_err(|e: quinn_proto::ConnectionError| to_io_error(e.to_string()))?;

        debug!(
            "hysteria2 new connection to {} established",
            server_location
        );

        let connection = conn.clone();
        let quinn_conn = h3_quinn::Connection::new(conn);
        let (mut driver, mut send_request) = h3::client::new(quinn_conn)
            .await
            .map_err(|err| to_io_error(err.to_string()))?;
        let random_number: u8 = rand::thread_rng().gen_range(1..255u8);
        let hysteria_padding =
            Alphanumeric.sample_string(&mut rand::thread_rng(), random_number as usize);
        let rx = options.down_bandwidth * 1024 * 1024 / 8;
        let req = Request::builder()
            .method(Method::POST)
            .uri("https://hysteria/auth")
            .header("Hysteria-Auth", options.auth.clone())
            .header("Hysteria-CC-RX", rx.to_string())
            .header("Hysteria-Padding", hysteria_padding)
            .body(())
            .map_err(|err| to_io_error(err.to_string()))?;
        let mut stream = send_request
            .send_request(req)
            .await
            .map_err(|err| to_io_error(err.to_string()))?;

        let response = stream
            .recv_response()
            .await
            .map_err(|err| to_io_error(err.to_string()))?;
        if response.status() != 233 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "quinn_hysteria2 server status code is not 233",
            ));
        }
        let headers = response.headers();
        let support_udp = headers["hysteria-udp"].to_str().unwrap_or("") == "true";

        let connection_clone = connection.clone();

        let udp_api = UdpApi::new(connection_clone);

        let mut instant = None;

        if (options.hop_enable) {
            let mut delay = options.hop_intervals;
            if (delay < 10) {
                delay = 10;
            }
            instant = Some(Instant::now() + Duration::from_secs(delay as u64));
        }
        let hysteria2_counter = Hysteria2Counter {
            counter: Arc::new(AtomicI32::new(0)),
        };
        let hysteria2_connection = Hysteria2Connection {
            support_udp,
            udp_api,
            connection,
            hysteria2_counter,
            instant,
            closed: Arc::new(Mutex::new(false)),
        };
        let hysteria2_connection_clone = hysteria2_connection.clone();
        self.inner.write().await.connection = Some(hysteria2_connection);
        self.inner.write().await.guard = Some(send_request);

        let inner_clone = self.inner.clone();
        tokio::spawn(async move {
            let _ = future::poll_fn(|cx| driver.poll_close(cx)).await;
            let mut inner_helper = inner_clone.deref().write().await;
            let _ = inner_helper.connection.take();
            let _ = inner_helper.guard.take();
            warn!("hysteria2 connection closed");
        });

        let inner_clone_2 = self.inner.clone();
        tokio::spawn(async move {
            loop {
                sleep(Duration::from_secs(10)).await;
                if let Some(result) = inner_clone_2.read().await.connection.as_ref() {
                    let count = result
                        .hysteria2_counter
                        .counter
                        .load(atomic::Ordering::Acquire);
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
                warn!("hysteria2 connection not used and closed");
                break;
            }
        });

        Ok(hysteria2_connection_clone)
    }

    pub(crate) async fn get_udp(
        &mut self,
        context: Arc<Context>,
        detour: Option<String>,
        options: &Hysteria2S2nQuicOptions,
        address: String,
    ) -> io::Result<Hysteria2UdpStream> {
        let connection = self.open_stream(context, detour, options).await?;
        if connection.support_udp {
            return Ok(Hysteria2UdpStream::new(
                connection.hysteria2_counter,
                connection.udp_api.clone(),
                address,
            )
            .await);
        }
        Err(Error::new(
            ErrorKind::InvalidInput,
            "The hysteria 2 connection not support UDP",
        ))
    }

    async fn create_endpoint_quinn(
        context: Arc<Context>,
        detour: Option<String>,
        server_location: Arc<NetLocation>,
        options: &Hysteria2S2nQuicOptions,
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
            .keep_alive_interval(Some(Duration::from_secs(
                options.quic_max_keep_alive_period.unwrap_or(10),
            )))
            .max_idle_timeout(Some(
                Duration::from_secs(options.quic_max_idle_timeout.unwrap_or(30))
                    .try_into()
                    .unwrap(),
            ))
            .datagram_receive_buffer_size(Some(128 * 1024))
            .datagram_send_buffer_size(128 * 1024)
            .send_window(128 * 1024)
            .receive_window(VarInt::from(128 * 1024u32))
            .stream_receive_window(VarInt::from(128 * 1024u32));

        client_config.transport_config(Arc::new(transport_config));

        let mut endpoint = if options.obfs_type.clone() == "salamander" {
            let socket: std::net::UdpSocket = context.bind_sdt_udp(bind).await?;
            // let socket = std::net::UdpSocket::bind(bind.clone())?;
            let obfs =
                salamander::Salamander::new(socket, options.obfs_password.clone().into_bytes())?;

            quinn::Endpoint::new_with_abstract_socket(
                EndpointConfig::default(),
                None,
                Arc::new(obfs),
                Arc::new(TokioRuntime),
            )?
        } else {
            context.bind_endpoint(bind).await?
        };
        endpoint.set_default_client_config(client_config);
        Ok((Arc::new(endpoint), server_address))
    }
}
