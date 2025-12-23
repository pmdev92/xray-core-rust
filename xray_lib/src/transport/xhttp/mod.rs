use crate::common::net_location::NetLocation;
use crate::core::io::AsyncXrayTcpStream;
use crate::core::security::{Security, XraySecurity};
use crate::core::stream::StreamSettings;
use crate::core::transport::{Transport, XrayTransport};
use crate::stream::get_stream;
use crate::transport::xhttp::config::XHttpConfig;
use crate::transport::xhttp::http_unify::HttpUnify;
use crate::transport::xhttp::protocol::{Http, Mode, USER_AGENT};
use async_trait::async_trait;
use blake3::IncrementCounter::No;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use chrono::Utc;
use futures::{Sink, Stream};
use futures_util::TryStreamExt;
use http::{HeaderName, HeaderValue, Request, Response, Uri};
use http_body_util::{BodyExt, BodyStream, Empty};
use hyper::body::Incoming;
use hyper::client::conn;
use hyper::client::conn::http2::SendRequest;
use hyper::client::conn::{http1, http2};
use hyper::service::Service;
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::rt::TokioIo;
use log::{error, info, warn};
use rand::Rng;
use reqwest::Body;
use s2n_quic::provider::io::TryInto;
use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::io::{Error, ErrorKind};
use std::ops::{Deref, RangeInclusive};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tls_parser::nom::AsBytes;
use tokio::io::{
    duplex, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream,
    ReadBuf,
};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
use tokio_util::io::ReaderStream;
use uuid::Uuid;

mod chunk_stream;
pub mod config;
mod http_unify;
mod protocol;

pub struct XHttpTransport {
    inner: Arc<XHttpTransportInner>,
    host: Option<String>,
    path: Option<String>,
    mode: Option<String>,
    stream_settings: Arc<Option<StreamSettings>>,
    security: Arc<Option<Box<dyn Security>>>,
}

impl XHttpTransport {
    pub fn new(
        stream_settings: Option<StreamSettings>,
        x_http_config: Option<XHttpConfig>,
        security: Option<Box<dyn Security>>,
    ) -> Self {
        let stream_settings = Arc::new(stream_settings);
        let security = Arc::new(security);
        match x_http_config {
            None => {
                let inner = XHttpTransportInner {
                    stream_settings: stream_settings.clone(),
                    security: security.clone(),
                    query: None,
                    headers: None,
                    x_padding_bytes: RangeInclusive::new(100, 1000),
                    packet_up_interval_ms: None,
                    no_grpc_header: Some(false),
                    sender: Mutex::new(None),
                };
                XHttpTransport {
                    inner: Arc::new(inner),
                    host: None,
                    path: None,
                    mode: None,
                    stream_settings: stream_settings.clone(),
                    security: security.clone(),
                }
            }
            Some(x_http_config) => {
                let mut qeury = None;
                let path = x_http_config.path.unwrap_or("/".to_string());
                let (path, query_string) = match path.split_once('?') {
                    Some((p, q)) => (p.to_string(), Some(q.to_string())),
                    None => (path, None),
                };

                if let Some(query_string) = query_string {
                    let parsed: HashMap<_, _> = form_urlencoded::parse(query_string.as_bytes())
                        .into_owned()
                        .collect();
                    qeury = Some(parsed);
                }

                let inner = XHttpTransportInner {
                    stream_settings: stream_settings.clone(),
                    security: security.clone(),
                    headers: x_http_config.headers.clone(),
                    query: qeury,
                    x_padding_bytes: RangeInclusive::new(
                        x_http_config.x_padding_bytes_min.unwrap_or(100),
                        x_http_config.x_padding_bytes_min.unwrap_or(1000),
                    ),
                    no_grpc_header: x_http_config.no_grpc_header.clone(),
                    packet_up_interval_ms: x_http_config.packet_up_interval_ms,
                    sender: Mutex::new(None),
                };
                XHttpTransport {
                    inner: Arc::new(inner),
                    host: x_http_config.host.clone(),
                    path: Some(path),
                    mode: x_http_config.mode.clone(),
                    stream_settings: stream_settings.clone(),
                    security: security.clone(),
                }
            }
        }
    }
}

impl XHttpTransport {
    pub fn decide_http_version(&self) -> Http {
        match self.stream_settings.as_ref() {
            None => Http::V1,
            Some(stream_settings) => {
                if stream_settings.security == "reality" {
                    return Http::V2;
                }
                if stream_settings.security == "tls" {
                    match stream_settings.tls_settings.as_ref() {
                        None => {}
                        Some(tls_settings) => {
                            if let Some(alpn) = &tls_settings.alpn {
                                if alpn.len() > 0 {
                                    return Http::V2;
                                }
                                if alpn[0] == "http1/1" {
                                    return Http::V1;
                                }
                                if alpn[0] == "h3" {
                                    return Http::V3;
                                }
                            }
                        }
                    }
                    return Http::V2;
                }
                Http::V1
            }
        }
    }
    pub fn decide_mode(&self) -> Mode {
        let mode = self.mode.clone().unwrap_or("auto".to_string());
        if mode == "packet-up" {
            return Mode::PacketUp;
        }
        if mode == "stream-up" {
            return Mode::StreamUp;
        }
        if mode == "stream-one" {
            return Mode::StreamOne;
        }
        Mode::PacketUp
    }
    pub fn is_secure(&self) -> bool {
        match self.stream_settings.as_ref() {
            None => false,
            Some(stream_settings) => {
                if stream_settings.security == "reality" {
                    return true;
                }
                if stream_settings.security == "tls" {
                    return true;
                }
                false
            }
        }
    }
}

struct MyConn {
    stream: DuplexStream,
}

impl Connection for MyConn {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

impl AsyncRead for MyConn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for MyConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

struct MyConnector {
    client_stream: DuplexStream,
}

#[async_trait]
impl Transport for XHttpTransport {
    async fn dial(
        &self,
        context: Arc<crate::core::context::Context>,
        detour: Option<String>,
        server_net_location: Arc<NetLocation>,
    ) -> Result<Box<dyn XrayTransport>, Error> {
        let http_version = self.decide_http_version();
        info!("x-http http_version: {}", http_version);
        let mode = self.decide_mode();
        info!("x-http mode: {}", mode);
        let uuid = match mode {
            Mode::PacketUp => Uuid::new_v4().to_string(),
            Mode::StreamUp => Uuid::new_v4().to_string(),
            Mode::StreamOne => "".to_string(),
        };

        let host = self.host.clone().unwrap_or("".to_string()).to_string();
        let mut path = self.path.clone().unwrap_or("/".to_string()).to_string();

        if !path.starts_with("/") {
            path = format!("/{}", path);
        }
        if path.ends_with("/") {
            path.pop();
        }
        let uri = format!("{}/{}", path, uuid);
        let url = if self.is_secure() {
            format!("https://{}{}", host, uri)
        } else {
            format!("http://{}{}", host, uri)
        };
        info!("x-http url: {}", url);

        let (download_link, upload_link) = match mode {
            Mode::PacketUp => {
                let download_link = self
                    .inner
                    .open_stream_down(
                        context.clone(),
                        detour.clone(),
                        server_net_location.clone(),
                        http_version.clone(),
                        host.clone(),
                        uri.clone(),
                        url.clone(),
                    )
                    .await?;
                let upload_link = self
                    .inner
                    .open_post_packet(
                        context.clone(),
                        detour.clone(),
                        server_net_location.clone(),
                        http_version,
                        host.clone(),
                        uri.clone(),
                        url.clone(),
                    )
                    .await?;
                (download_link, upload_link)
            }
            Mode::StreamUp => {
                let download_link = self
                    .inner
                    .open_stream_down(
                        context.clone(),
                        detour.clone(),
                        server_net_location.clone(),
                        http_version.clone(),
                        host.clone(),
                        uri.clone(),
                        url.clone(),
                    )
                    .await?;
                let upload_link = self
                    .inner
                    .open_stream_up(
                        context.clone(),
                        detour.clone(),
                        server_net_location.clone(),
                        http_version,
                        host.clone(),
                        uri.clone(),
                        url.clone(),
                    )
                    .await?;
                (download_link, upload_link)
            }
            Mode::StreamOne => {
                self.inner
                    .open_stream_one(
                        context.clone(),
                        detour.clone(),
                        server_net_location.clone(),
                        http_version,
                        host.clone(),
                        uri.clone(),
                        url.clone(),
                    )
                    .await?
            }
        };

        let tcp_transport = XHttpStreamUp {
            download: download_link,
            upload: upload_link,
            read_buffer: BytesMut::new(),
            future_write: None,
        };
        Ok(Box::new(tcp_transport))
    }
}

pub struct XHttpStreamUp {
    upload: Sender<Vec<u8>>,
    download: Receiver<Result<Bytes, Error>>,
    read_buffer: BytesMut,
    future_write: Option<Pin<Box<dyn Future<Output = ()> + Send + Sync>>>,
}

impl AsyncRead for XHttpStreamUp {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.read_buffer.is_empty() {
            if buf.capacity() > self.read_buffer.len() {
                let data = self.read_buffer.split();
                buf.put_slice(data.as_ref())
            } else {
                let data = self.read_buffer.split_to(buf.capacity());
                buf.put_slice(data.as_ref())
            }
            return Poll::Ready(Ok(()));
        }

        let result = std::task::ready!(Pin::new(&mut self.download).poll_recv(cx))
            .ok_or(Error::new(ErrorKind::Other, "stream closed"))?;
        match result {
            Ok(data) => {
                self.read_buffer.extend_from_slice(&data);
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(err) => Poll::Ready(Err(err)),
        }
    }
}

impl AsyncWrite for XHttpStreamUp {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        if self.future_write.is_none() {
            let future = self.upload.clone();
            let aaa = buf.to_vec();
            let handle = Box::pin(async move {
                let _ = future.send(aaa).await;
            });
            self.future_write = Some(handle);
        }
        let future = self
            .future_write
            .as_mut()
            .ok_or_else(|| Error::new(ErrorKind::Other, "future write not set"))?;
        let _ = std::task::ready!(Pin::new(future).poll(cx));
        self.future_write = None;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        if self.future_write.is_none() {
            let future = self.upload.clone();
            let data = vec![];
            let handle = Box::pin(async move {
                let _ = future.send(data).await;
            });
            self.future_write = Some(handle);
        }
        let future = self
            .future_write
            .as_mut()
            .ok_or_else(|| Error::new(ErrorKind::Other, "future write not set"))?;
        let _ = std::task::ready!(Pin::new(future).poll(cx));
        self.future_write = None;
        Poll::Ready(Ok(()))
    }
}

impl AsyncXrayTcpStream for XHttpStreamUp {}

impl XrayTransport for XHttpStreamUp {}

struct XHttpTransportInner {
    query: Option<HashMap<String, String>>,
    headers: Option<HashMap<String, String>>,
    x_padding_bytes: RangeInclusive<usize>,
    packet_up_interval_ms: Option<usize>,
    no_grpc_header: Option<bool>,
    stream_settings: Arc<Option<StreamSettings>>,
    security: Arc<Option<Box<dyn Security>>>,
    sender: Mutex<Option<Arc<Box<dyn HttpUnify>>>>,
}

impl XHttpTransportInner {
    async fn open_http_sender(
        &self,
        context: Arc<crate::core::context::Context>,
        detour: Option<String>,
        server_net_location: Arc<NetLocation>,
        version: Http,
    ) -> Result<Box<dyn HttpUnify>, Error> {
        {
            let sender = self.sender.lock().await;
            match sender.as_ref() {
                None => {}
                Some(sender) => {
                    if !sender.is_closed_unify() {
                        return Ok(sender.clone_unify()?);
                    }
                }
            }
        }
        let mut sender: Result<Box<dyn HttpUnify>, Error> = match version {
            Http::V1 => {
                let sender = self
                    .open_http1_sender(context, detour, server_net_location)
                    .await?;
                return Ok(sender);
            }
            Http::V2 => {
                self.open_http2_sender(context, detour, server_net_location)
                    .await
            }
            Http::V3 => {
                unimplemented!("h3 xhttp")
            }
        };
        let sender = sender?;
        {
            self.sender
                .lock()
                .await
                .replace(Arc::from(sender.clone_unify()?));
        }
        Ok(sender)
    }
    async fn open_http2_sender(
        &self,
        context: Arc<crate::core::context::Context>,
        detour: Option<String>,
        server_net_location: Arc<NetLocation>,
    ) -> Result<Box<dyn HttpUnify>, Error> {
        let connection = context.dial_tcp(detour, server_net_location).await?;
        let connection: Box<dyn AsyncXrayTcpStream> = match self.security.as_ref() {
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
                warn!("connection error: {:?}", err);
            }
        });
        Ok(Box::new(sender))
    }
    async fn open_http1_sender(
        &self,
        context: Arc<crate::core::context::Context>,
        detour: Option<String>,
        server_net_location: Arc<NetLocation>,
    ) -> Result<Box<dyn HttpUnify>, Error> {
        let connection = context.dial_tcp(detour, server_net_location).await?;
        let connection: Box<dyn AsyncXrayTcpStream> = match self.security.as_ref() {
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
                warn!("x-http connection error: {:?}", err);
            }
        });
        Ok(Box::new(sender))
    }

    async fn open_stream_down(
        &self,
        context: Arc<crate::core::context::Context>,
        detour: Option<String>,
        server_net_location: Arc<NetLocation>,
        version: Http,
        host: String,
        uri: String,
        url: String,
    ) -> Result<Receiver<Result<Bytes, Error>>, Error> {
        let mut sender = self
            .open_http_sender(context, detour, server_net_location, version)
            .await?;

        let mut builder = http::Request::builder()
            .method("GET")
            .uri(self.add_query(uri))
            .header("Host", host)
            .header("User-Agent", USER_AGENT)
            .header("Transfer-Encoding", "chunked")
            .header("Accept-Encoding", "gzip")
            .header("Connection", "close");

        builder = self.add_request_headers(url, builder);
        let req = builder
            .body(Body::wrap(Empty::<Bytes>::new()))
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
        let mut response = {
            sender
                .send_request_unify(req)
                .await
                .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?
        };
        if response.status() != 200 {
            return Err(Error::new(
                ErrorKind::Other,
                format!("x-http unexpected status {}", response.status()),
            ));
        }

        let (mut tx, rx) = mpsc::channel::<Result<Bytes, Error>>(10);

        tokio::spawn(async move {
            while let Some(result) = response.frame().await {
                match result {
                    Ok(frame) => {
                        let data = frame.data_ref();
                        match data {
                            None => {
                                break;
                            }
                            Some(data) => {
                                let result = tx.send(Ok(data.clone())).await;
                                match result {
                                    Ok(_) => {}
                                    Err(_) => {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    Err(_) => {
                        break;
                    }
                }
            }
        });
        Ok(rx)
    }

    async fn open_stream_up(
        &self,
        context: Arc<crate::core::context::Context>,
        detour: Option<String>,
        server_net_location: Arc<NetLocation>,
        version: Http,
        host: String,
        uri: String,
        url: String,
    ) -> Result<Sender<Vec<u8>>, Error> {
        let mut sender = self
            .open_http_sender(context, detour, server_net_location, version)
            .await?;

        let mut builder = http::Request::builder()
            .method("POST")
            .uri(self.add_query(uri))
            .header("Host", host)
            .header("User-Agent", USER_AGENT)
            .header("Transfer-Encoding", "chunked")
            .header("Accept-Encoding", "gzip")
            .header("Connection", "close");
        builder = self.add_request_headers(url, builder);
        if !self.no_grpc_header.unwrap_or(false) {
            builder = builder.header("Content-Type", "application/grpc");
        }
        let (mut tx_hyper, rx_hyper) = mpsc::channel::<Result<Bytes, Error>>(10);

        let stream = Body::wrap_stream(ReceiverStream::new(rx_hyper));
        let body = BodyStream::new(stream);
        let req = builder
            .body(Body::wrap(body))
            .map_err(|e| Error::new(ErrorKind::Other, e))?;

        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(10);
        tokio::spawn(async move {
            while let Some(chunk) = rx.recv().await {
                let _ = tx_hyper.send(Ok(Bytes::from(chunk))).await;
            }
        });

        tokio::spawn(async move {
            let mut response = {
                sender
                    .send_request_unify(req)
                    .await
                    .map_err(|e| Error::new(ErrorKind::Other, e))
            };
            let mut response = match response {
                Ok(response) => response,
                Err(_) => {
                    return;
                }
            };
            warn!(
                "{}",
                format!("x-http unexpected status {}", response.status())
            );
            while let Some(_) = response.frame().await {}
        });
        Ok(tx)
    }
    async fn open_stream_one(
        &self,
        context: Arc<crate::core::context::Context>,
        detour: Option<String>,
        server_net_location: Arc<NetLocation>,
        version: Http,
        host: String,
        uri: String,
        url: String,
    ) -> Result<(Receiver<Result<Bytes, Error>>, Sender<Vec<u8>>), Error> {
        let mut sender = self
            .open_http_sender(context, detour, server_net_location, version)
            .await?;

        let mut builder = http::Request::builder()
            .method("POST")
            .uri(self.add_query(uri))
            .header("Host", host)
            .header("User-Agent", USER_AGENT)
            .header("Transfer-Encoding", "chunked")
            .header("Accept-Encoding", "gzip")
            .header("Connection", "close");
        builder = self.add_request_headers(url, builder);
        if !self.no_grpc_header.unwrap_or(false) {
            builder = builder.header("Content-Type", "application/grpc");
        }
        let (mut tx_hyper, rx_hyper) = mpsc::channel::<Result<Bytes, Error>>(10);

        let stream = Body::wrap_stream(ReceiverStream::new(rx_hyper));
        let body = BodyStream::new(stream);
        let req = builder
            .body(Body::wrap(body))
            .map_err(|e| Error::new(ErrorKind::Other, e))?;

        let mut response = {
            sender
                .send_request_unify(req)
                .await
                .map_err(|e| Error::new(ErrorKind::Other, e))?
        };
        if response.status() != 200 {
            return Err(Error::new(
                ErrorKind::Other,
                format!("x-http unexpected status {}", response.status()),
            ));
        }

        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(10);
        tokio::spawn(async move {
            while let Some(chunk) = rx.recv().await {
                let _ = tx_hyper.send(Ok(Bytes::from(chunk))).await;
            }
        });

        let (mut tx1, rx1) = mpsc::channel::<Result<Bytes, Error>>(10);

        tokio::spawn(async move {
            while let Some(result) = response.frame().await {
                match result {
                    Ok(frame) => {
                        let data = frame.data_ref();
                        match data {
                            None => {
                                break;
                            }
                            Some(data) => {
                                let result = tx1.send(Ok(data.clone())).await;
                                match result {
                                    Ok(_) => {}
                                    Err(_) => {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    Err(_) => {
                        break;
                    }
                }
            }
        });
        Ok((rx1, tx))
    }
    async fn post_packet(
        &self,
        context: Arc<crate::core::context::Context>,
        detour: Option<String>,
        server_net_location: Arc<NetLocation>,
        version: Http,
        host: String,
        uri: String,
        url: String,
        data: Bytes,
    ) -> Result<(), Error> {
        let mut sender = self
            .open_http_sender(context, detour, server_net_location, version)
            .await?;
        let mut builder = http::Request::builder()
            .method("POST")
            .uri(self.add_query(uri))
            .header("Host", host)
            .header("User-Agent", USER_AGENT)
            .header("Content-Length", data.len())
            .header("Accept-Encoding", "gzip")
            .header("Connection", "close");
        builder = self.add_request_headers(url, builder);
        let req = builder
            .body(Body::from(data))
            .map_err(|e| Error::new(ErrorKind::Other, e))?;
        let mut response = {
            sender
                .send_request_unify(req)
                .await
                .map_err(|e| Error::new(ErrorKind::Other, e))?
        };
        if response.status() != 200 {
            return Err(Error::new(
                ErrorKind::Other,
                format!("x-http unexpected status {}", response.status()),
            ));
        }
        Ok(())
    }

    async fn open_post_packet(
        self: &Arc<Self>,
        context: Arc<crate::core::context::Context>,
        detour: Option<String>,
        server_net_location: Arc<NetLocation>,
        version: Http,
        host: String,
        uri: String,
        url: String,
    ) -> Result<Sender<Vec<u8>>, Error> {
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(10);
        let packet_up_interval_micro = self.packet_up_interval_ms.unwrap_or(30) * 1000;
        let self_clone = self.clone();
        tokio::spawn(async move {
            let mut last_write = 0i64;
            let mut seq = 0usize;
            loop {
                let uri_seg = format!("{}/{}", uri, seq);
                let url_seg = format!("{}/{}", url, seq);
                seq = seq + 1;
                let current = last_write + packet_up_interval_micro as i64;
                let diff = current - Utc::now().timestamp_micros();
                if diff > 0 {
                    sleep(Duration::from_micros(diff as u64)).await;
                }
                let chunk = if let Some(chunk) = rx.recv().await {
                    if chunk.len() == 0 {
                        break;
                    }
                    chunk
                } else {
                    break;
                };
                last_write = Utc::now().timestamp_micros();
                let self_clone_clone = self_clone.clone();
                let server_net_location_clone = server_net_location.clone();
                let version_clone = version.clone();
                let host_clone = host.clone();
                let dialer_clone = context.clone();
                let detour_clone = detour.clone();
                tokio::spawn(async move {
                    let _ = self_clone_clone
                        .post_packet(
                            dialer_clone,
                            detour_clone,
                            server_net_location_clone,
                            version_clone,
                            host_clone,
                            uri_seg,
                            url_seg,
                            Bytes::from(chunk),
                        )
                        .await;
                });
            }
        });
        Ok(tx)
    }

    pub fn add_request_headers(
        &self,
        url: String,
        mut builder: http::request::Builder,
    ) -> http::request::Builder {
        match self.headers.as_ref() {
            None => {}
            Some(headers) => {
                for (key, value) in headers {
                    let k = key.to_string();
                    let v = value.to_string();
                    builder = builder.header(
                        HeaderName::from_str(k.as_str()).unwrap(),
                        HeaderValue::from_str(v.as_str()).unwrap(),
                    );
                }
            }
        }
        let padding_len = self.get_random_padding();
        let padding = "X".repeat(padding_len);
        let referer = format!("{}?x_padding={}", url, padding);
        builder = builder.header("Referer", HeaderValue::from_str(referer.as_str()).unwrap());
        builder
    }
    pub fn add_query(&self, uri: String) -> String {
        let mut uri = format!("{}?", uri);
        match &self.query {
            None => {}
            Some(query) => {
                for (key, value) in query {
                    uri = format!("{}{}={}&", uri, key, value);
                }
            }
        }
        let padding_len = self.get_random_padding();
        let padding = "X".repeat(padding_len);
        let uri = format!("{}x_padding={}", uri, padding);
        uri
    }
    fn get_random_padding(&self) -> usize {
        let (start, end) = (*self.x_padding_bytes.start(), *self.x_padding_bytes.end());
        let mut rng = rand::thread_rng();
        rng.gen_range(start..=end)
    }
}
