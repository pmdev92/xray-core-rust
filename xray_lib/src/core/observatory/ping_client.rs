use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant},
};

use crate::common::address::Address;
use crate::common::net_location::NetLocation;
use crate::core::context::Context;
use bytes::Bytes;
use http_body_util::Empty;
use hyper::{Method, Request, Response, Uri, body::Incoming, client::conn::http1, header::HOST};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::{
    TlsConnector,
    rustls::{ClientConfig, RootCertStore, pki_types::ServerName},
};

pub struct PingClient {
    context: Arc<Context>,
    destination: Uri,
    timeout: Option<Duration>,
    stream_factory: Arc<dyn Fn(Arc<Context>, String, u16) -> StreamFuture + Send + Sync>,
}

impl PingClient {
    pub fn new_direct(
        context: Arc<Context>,
        destination: String,
        timeout: Option<Duration>,
    ) -> Result<Self, BoxError> {
        let destination = destination.parse::<Uri>()?;
        let stream_factory = Arc::new(
            |context: Arc<Context>, host: String, port: u16| -> StreamFuture {
                Box::pin(async move {
                    let stream = TcpStream::connect((host, port)).await?;
                    Ok(Box::pin(stream) as BoxStream)
                })
            },
        );

        Ok(Self {
            context,
            destination,
            timeout,
            stream_factory,
        })
    }

    pub fn new_tagged(
        context: Arc<Context>,
        tag: String,
        destination: String,
        timeout: Option<Duration>,
    ) -> Result<Self, BoxError> {
        let destination = destination.parse::<Uri>()?;
        let tag = Arc::new(tag);
        let stream_factory = Arc::new({
            let tag = Arc::clone(&tag);
            move |context: Arc<Context>, host: String, port: u16| -> StreamFuture {
                let tag = Arc::clone(&tag);
                Box::pin(async move {
                    let target_location =
                        Arc::new(NetLocation::new(Address::from(&host).unwrap(), port));
                    let item = context
                        .clone()
                        .get_dispatcher()
                        .get_with_tag(context.clone(), tag.to_string())
                        .await
                        .ok_or_else(|| {
                            BoxError::from(format!(
                                "no outbound with tag '{}' found in outbounds",
                                tag
                            ))
                        })?;
                    let result = item
                        .outbound
                        .dial_tcp(context.clone(), item.detour, target_location)
                        .await?;
                    Ok(Box::pin(result) as BoxStream)
                })
            }
        });

        Ok(Self {
            context,
            destination,
            timeout,
            stream_factory,
        })
    }

    pub async fn measure_delay(&self) -> Result<Duration, BoxError> {
        match self.timeout {
            None => self.exec_request().await,
            Some(t) => timeout(t, self.exec_request()).await?,
        }
    }
    async fn exec_request(&self) -> Result<Duration, BoxError> {
        let host = self
            .destination
            .host()
            .ok_or("destination has no host")?
            .to_string();

        let is_https = self.destination.scheme_str() == Some("https");

        let port = self
            .destination
            .port_u16()
            .unwrap_or(if is_https { 443 } else { 80 });

        let start = Instant::now();

        let stream = (self.stream_factory)(self.context.clone(), host.clone(), port);

        let stream = stream.await?;
        let stream: BoxStream = if is_https {
            let mut root_cert_store = RootCertStore::empty();
            root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let config = ClientConfig::builder()
                .with_root_certificates(root_cert_store)
                .with_no_client_auth();
            let connector = TlsConnector::from(Arc::new(config));
            let server_name = ServerName::try_from(host.to_owned())?;
            Box::pin(connector.connect(server_name, stream).await?)
        } else {
            stream
        };

        let io = TokioIo::new(stream);

        let (mut sender, connection) = http1::handshake(io).await?;

        tokio::spawn(async move {
            let _ = connection.await;
        });

        let path = self
            .destination
            .path_and_query()
            .map(|x| x.as_str())
            .unwrap_or("/");

        let request = Request::builder()
            .method(Method::HEAD)
            .uri(path)
            .header(HOST, host)
            .body(Empty::<Bytes>::new())?;

        let response: Response<Incoming> = sender.send_request(request).await?;

        let elapsed = start.elapsed();
        if !response.status().is_success() {
            return Err(format!("HTTP status: {}", response.status()).into());
        }
        Ok(elapsed)
    }
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;

type BoxStream = Pin<Box<dyn AsyncReadWrite>>;

trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

type StreamFuture = Pin<Box<dyn Future<Output = Result<BoxStream, BoxError>> + Send>>;
