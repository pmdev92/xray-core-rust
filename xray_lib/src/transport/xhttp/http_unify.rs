use crate::common::net_location::NetLocation;
use crate::core::context::Context;
use crate::core::io::AsyncXrayTcpStream;
use crate::core::security::Security;
use crate::security::tls::verify::TlsNoCertVerifier;
use crate::transport::xhttp::protocol::HttpVersion;
use async_trait::async_trait;
use bytes::{Buf, Bytes};
use h3::client::SendRequest as H3SendRequest;
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use hyper::client::conn::{http1, http2};
use hyper_util::rt::TokioIo;
use log::warn;
use quinn_proto::crypto::rustls::QuicClientConfig;
use quinn_proto::{TransportConfig, VarInt};
use reqwest::Body;
use std::io::{Error, ErrorKind};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::{Mutex, mpsc};
use tokio_rustls::rustls::ClientConfig;

pub struct UnifiedResponse {
    pub status: StatusCode,
    pub rx: mpsc::Receiver<Result<Bytes, Error>>,
}

#[async_trait]
pub trait HttpUnify: Send + Sync {
    async fn send_request_unify(&mut self, req: Request<Body>) -> Result<UnifiedResponse, Error>;
    fn is_closed_unify(&self) -> bool;
    fn can_clone(&self) -> bool;
    fn clone_unify(&self) -> Result<Box<dyn HttpUnify>, Error>;
}

fn incoming_to_unified(response: hyper::Response<hyper::body::Incoming>) -> UnifiedResponse {
    let status = response.status();
    let (tx, rx) = mpsc::channel::<Result<Bytes, Error>>(10);
    tokio::spawn(async move {
        let mut body = response.into_body();
        loop {
            match body.frame().await {
                Some(Ok(frame)) => {
                    if let Some(data) = frame.data_ref() {
                        if tx.send(Ok(data.clone())).await.is_err() {
                            break;
                        }
                    }
                }
                Some(Err(e)) => {
                    let _ = tx
                        .send(Err(Error::new(ErrorKind::Other, e.to_string())))
                        .await;
                    break;
                }
                None => break,
            }
        }
    });
    UnifiedResponse { status, rx }
}

pub(crate) struct H1Unify {
    sender: http1::SendRequest<Body>,
}

impl H1Unify {
    pub fn new(sender: http1::SendRequest<Body>) -> Self {
        Self { sender }
    }
}

#[async_trait]
impl HttpUnify for H1Unify {
    async fn send_request_unify(&mut self, req: Request<Body>) -> Result<UnifiedResponse, Error> {
        let response = self
            .sender
            .send_request(req)
            .await
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
        Ok(incoming_to_unified(response))
    }
    fn is_closed_unify(&self) -> bool {
        self.sender.is_closed()
    }
    fn can_clone(&self) -> bool {
        false
    }
    fn clone_unify(&self) -> Result<Box<dyn HttpUnify>, Error> {
        Err(Error::new(ErrorKind::Other, "Cannot clone http/1.1"))
    }
}

pub(crate) struct H2Unify {
    sender: http2::SendRequest<Body>,
}

impl H2Unify {
    pub fn new(sender: http2::SendRequest<Body>) -> Self {
        Self { sender }
    }
}

#[async_trait]
impl HttpUnify for H2Unify {
    async fn send_request_unify(&mut self, req: Request<Body>) -> Result<UnifiedResponse, Error> {
        let response = self
            .sender
            .send_request(req)
            .await
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
        Ok(incoming_to_unified(response))
    }
    fn is_closed_unify(&self) -> bool {
        self.sender.is_closed()
    }
    fn can_clone(&self) -> bool {
        true
    }
    fn clone_unify(&self) -> Result<Box<dyn HttpUnify>, Error> {
        Ok(Box::new(H2Unify {
            sender: self.sender.clone(),
        }))
    }
}

pub(crate) struct H3Unify {
    send_request: Arc<Mutex<H3SendRequest<h3_quinn::OpenStreams, Bytes>>>,
    closed: Arc<AtomicBool>,
}

impl H3Unify {
    pub fn new(send_request: H3SendRequest<h3_quinn::OpenStreams, Bytes>) -> Self {
        Self {
            send_request: Arc::new(Mutex::new(send_request)),
            closed: Arc::new(AtomicBool::new(false)),
        }
    }
}

#[async_trait]
impl HttpUnify for H3Unify {
    async fn send_request_unify(&mut self, req: Request<Body>) -> Result<UnifiedResponse, Error> {
        let (parts, body) = req.into_parts();
        let h3_req = Request::from_parts(parts, ());
        let mut guard = self.send_request.lock().await;
        let mut stream = guard
            .send_request(h3_req)
            .await
            .map_err(|e| Error::new(ErrorKind::Other, format!("h3 send_request: {}", e)))?;
        drop(guard);
        let (mut send_stream, mut recv_stream) = stream.split();
        tokio::spawn(async move {
            let mut body = body;
            loop {
                match body.frame().await {
                    Some(Ok(frame)) => {
                        if let Some(data) = frame.data_ref() {
                            if !data.is_empty() {
                                if let Err(e) = send_stream.send_data(data.clone()).await {
                                    warn!("h3 send_data error: {}", e);
                                    break;
                                }
                            }
                        }
                    }
                    Some(Err(e)) => {
                        warn!("h3 body read error: {}", e);
                        break;
                    }
                    None => break,
                }
            }
            if let Err(e) = send_stream.finish().await {
                warn!("h3 finish error: {}", e);
            }
        });
        let h3_response = recv_stream
            .recv_response()
            .await
            .map_err(|e| Error::new(ErrorKind::Other, format!("h3 recv_response: {}", e)))?;
        let status = h3_response.status();
        let (tx, rx) = mpsc::channel::<Result<Bytes, Error>>(10);
        tokio::spawn(async move {
            loop {
                match recv_stream.recv_data().await {
                    Ok(Some(mut data)) => {
                        let chunk = data.copy_to_bytes(data.remaining());
                        if tx.send(Ok(chunk)).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        warn!("h3 recv_data error: {}", e);
                        let _ = tx
                            .send(Err(Error::new(ErrorKind::Other, format!("h3: {}", e))))
                            .await;
                        break;
                    }
                }
            }
        });
        Ok(UnifiedResponse { status, rx })
    }
    fn is_closed_unify(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }
    fn can_clone(&self) -> bool {
        true
    }
    fn clone_unify(&self) -> Result<Box<dyn HttpUnify>, Error> {
        Ok(Box::new(H3Unify {
            send_request: self.send_request.clone(),
            closed: self.closed.clone(),
        }))
    }
}

pub async fn open_http_unify(
    context: Arc<Context>,
    detour: Option<String>,
    server_net_location: Arc<NetLocation>,
    http_version: HttpVersion,
    security: Arc<Option<Box<dyn Security>>>,
) -> Result<Box<dyn HttpUnify>, Error> {
    match http_version {
        HttpVersion::V1 => open_http1_sender(context, detour, server_net_location, security).await,
        HttpVersion::V2 => open_http2_sender(context, detour, server_net_location, security).await,
        HttpVersion::V1_2 => {
            open_http1_2_sender(context, detour, server_net_location, security).await
        }
        HttpVersion::V3 => open_http3_sender(context, detour, server_net_location, security).await,
    }
}

async fn open_http1_sender(
    context: Arc<Context>,
    detour: Option<String>,
    server_net_location: Arc<NetLocation>,
    security: Arc<Option<Box<dyn Security>>>,
) -> Result<Box<dyn HttpUnify>, Error> {
    let connection = context.dial_tcp(detour, server_net_location).await?;
    let connection: Box<dyn AsyncXrayTcpStream> = match security.as_ref() {
        None => connection,
        Some(security) => {
            security.add_alpn("http/1.1".to_string()).await;
            security.dial(connection).await?
        }
    };
    let connection = TokioIo::new(connection);
    let (sender, connection) = http1::handshake(connection)
        .await
        .map_err(|e| Error::new(ErrorKind::Other, e))?;
    tokio::spawn(async move {
        if let Err(err) = connection.await {
            warn!("x-http http/1.1 connection error: {:?}", err);
        }
    });
    Ok(Box::new(H1Unify::new(sender)))
}

async fn open_http2_sender(
    context: Arc<Context>,
    detour: Option<String>,
    server_net_location: Arc<NetLocation>,
    security: Arc<Option<Box<dyn Security>>>,
) -> Result<Box<dyn HttpUnify>, Error> {
    let connection = context.dial_tcp(detour, server_net_location).await?;
    let connection: Box<dyn AsyncXrayTcpStream> = match security.as_ref() {
        None => connection,
        Some(security) => {
            security.add_alpn("h2".to_string()).await;
            security.dial(connection).await?
        }
    };
    let connection = TokioIo::new(connection);
    let executor = hyper_util::rt::tokio::TokioExecutor::new();
    let (sender, connection) = http2::handshake(executor, connection)
        .await
        .map_err(|e| Error::new(ErrorKind::Other, e))?;
    tokio::spawn(async move {
        if let Err(err) = connection.await {
            warn!("x-http h2 connection error: {:?}", err);
        }
    });
    Ok(Box::new(H2Unify::new(sender)))
}

async fn open_http1_2_sender(
    context: Arc<Context>,
    detour: Option<String>,
    server_net_location: Arc<NetLocation>,
    security: Arc<Option<Box<dyn Security>>>,
) -> Result<Box<dyn HttpUnify>, Error> {
    let connection = context.dial_tcp(detour, server_net_location).await?;
    let (is_h2, connection): (bool, Box<dyn AsyncXrayTcpStream>) = match security.as_ref() {
        None => (false, connection),
        Some(security) => {
            security.add_alpn("http/1.1".to_string()).await;
            security.add_alpn("h2".to_string()).await;
            let con = security.dial(connection).await?;
            (con.is_h2(), con)
        }
    };
    let connection = TokioIo::new(connection);
    if is_h2 {
        let executor = hyper_util::rt::tokio::TokioExecutor::new();
        let (sender, connection) = http2::handshake(executor, connection)
            .await
            .map_err(|e| Error::new(ErrorKind::Other, e))?;
        tokio::spawn(async move {
            if let Err(err) = connection.await {
                warn!("x-http h2 connection error: {:?}", err);
            }
        });
        Ok(Box::new(H2Unify::new(sender)))
    } else {
        let (sender, connection) = http1::handshake(connection)
            .await
            .map_err(|e| Error::new(ErrorKind::Other, e))?;

        tokio::spawn(async move {
            if let Err(err) = connection.await {
                warn!("x-http http/1.1 connection error: {:?}", err);
            }
        });
        Ok(Box::new(H1Unify::new(sender)))
    }
}

async fn open_http3_sender(
    context: Arc<Context>,
    detour: Option<String>,
    server_net_location: Arc<NetLocation>,
    security: Arc<Option<Box<dyn Security>>>,
) -> Result<Box<dyn HttpUnify>, Error> {
    let server_address = context.dial_udp_proxy(detour, server_net_location).await?;

    let mut tls_config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(TlsNoCertVerifier {}))
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![b"h3".into()];

    let server_name = security
        .as_ref()
        .as_ref()
        .and_then(|s| s.get_domain())
        .unwrap_or("localhost".to_string());

    let mut client_config = quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(tls_config)
            .map_err(|e| Error::new(ErrorKind::Other, format!("QuicClientConfig: {:?}", e)))?,
    ));
    let mut transport_config = TransportConfig::default();
    transport_config
        .keep_alive_interval(Some(Duration::from_secs(10)))
        .max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()))
        .send_window(4 * 1024 * 1024)
        .receive_window(VarInt::from(4 * 1024 * 1024u32))
        .stream_receive_window(VarInt::from(4 * 1024 * 1024u32));
    client_config.transport_config(Arc::new(transport_config));

    let bind: std::net::SocketAddr = if server_address.is_ipv6() {
        "[::]:0"
            .parse()
            .map_err(|e| Error::new(ErrorKind::Other, format!("{:?}", e)))?
    } else {
        "0.0.0.0:0"
            .parse()
            .map_err(|e| Error::new(ErrorKind::Other, format!("{:?}", e)))?
    };

    let mut endpoint = quinn::Endpoint::client(bind)?;
    endpoint.set_default_client_config(client_config);

    let conn = endpoint
        .connect(server_address, &server_name)
        .map_err(|e| Error::new(ErrorKind::Other, format!("h3 connect: {}", e)))?
        .await
        .map_err(|e| Error::new(ErrorKind::Other, format!("h3 connection: {}", e)))?;

    let quinn_conn = h3_quinn::Connection::new(conn);
    let (mut driver, send_request) = h3::client::new(quinn_conn)
        .await
        .map_err(|e| Error::new(ErrorKind::Other, format!("h3 client new: {}", e)))?;

    let closed = Arc::new(AtomicBool::new(false));
    let closed_clone = closed.clone();
    tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        closed_clone.store(true, Ordering::Relaxed);
        warn!("x-http h3 connection closed");
    });

    Ok(Box::new(H3Unify {
        send_request: Arc::new(Mutex::new(send_request)),
        closed,
    }))
}
