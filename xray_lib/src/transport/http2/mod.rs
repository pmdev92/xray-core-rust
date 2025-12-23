use std::future::Future;
use std::io;
use std::io::{Error, ErrorKind};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use crate::common::constants::MAX_TCP_BUFFER_CAPACITY;
use crate::common::net_location::NetLocation;
use crate::core::io::AsyncXrayTcpStream;
use crate::core::security::Security;
use crate::core::stream::StreamSettings;
use crate::core::transport::{Transport, XrayTransport};
use crate::stream::exact::ExactWriteStream;
use crate::stream::get_stream;
use crate::transport::http2::config::HttpConfig;
use async_trait::async_trait;
use blake3::IncrementCounter::No;
use bytes::{Bytes, BytesMut};
use futures_util::future::err;
use futures_util::ready;
use h2::client::ResponseFuture;
use h2::{client, RecvStream, SendStream};
use http::{Request, Response, Uri, Version};
use log::{error, trace};
use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

pub mod config;

pub struct Http2Transport {
    security: Option<Box<dyn Security>>,
    host: Option<String>,
    path: Option<String>,
    stream_settings: Option<StreamSettings>,
    client: Arc<Mutex<Option<h2::client::SendRequest<Bytes>>>>,
}

impl Http2Transport {
    pub fn new(
        stream_settings: Option<StreamSettings>,
        http_config: Option<HttpConfig>,
        security: Option<Box<dyn Security>>,
    ) -> Self {
        match http_config {
            None => Self {
                stream_settings,
                security,
                host: None,
                path: None,
                client: Arc::new(Mutex::new(None)),
            },
            Some(http_config) => Self {
                stream_settings,
                security,
                host: http_config.host.clone(),
                path: http_config.path.clone(),
                client: Arc::new(Mutex::new(None)),
            },
        }
    }
}

#[async_trait]
impl Transport for Http2Transport {
    async fn dial(
        &self,
        context: Arc<crate::core::context::Context>,
        detour: Option<String>,
        server_net_location: Arc<NetLocation>,
    ) -> Result<Box<dyn XrayTransport>, io::Error> {
        let connection = get_stream(
            context,
            detour,
            self.stream_settings.clone(),
            server_net_location.clone(),
        )
        .await?;

        let host = match &self.host {
            None => server_net_location.address.to_string(),
            Some(host) => host.clone(),
        };
        let path = match &self.path {
            None => "/".to_string(),
            Some(path) => path.clone(),
        };
        trace!("http/2 transport host is {}", host);
        trace!("http/2 transport path is {}", path);

        match &self.security {
            None => {
                let mut client = {
                    let client_clone = self.client.clone();
                    let mut result = client_clone.lock().await;
                    let client = match result.as_ref() {
                        Some(client) => client.clone(),
                        None => {
                            let (mut client, h2) = client::handshake(connection)
                                .await
                                .map_err(|err| io::Error::new(ErrorKind::Other, err.to_string()))?;
                            let clone = self.client.clone();
                            *result = Some(client.clone());
                            tokio::spawn(async move {
                                let _ = h2.await;
                                *clone.lock().await = None;
                            });
                            client
                        }
                    };
                    client
                };

                let uri = Uri::builder()
                    .scheme("http")
                    .authority(host)
                    .path_and_query(path)
                    .build()
                    .map_err(|err| io::Error::new(ErrorKind::Other, err.to_string()))?;

                let request = Request::builder()
                    .uri(uri)
                    .version(Version::HTTP_2)
                    .method("GET")
                    .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.75 Safari/537.36")
                    .header("Accept-Encoding", "gzip, deflate")
                    .header("Pragma", "no-cache")
                    .header("Type", "http")
                    .body(())
                    .map_err(|err| io::Error::new(ErrorKind::Other, err.to_string()))?;

                let (response, sender) = client
                    .send_request(request, false)
                    .map_err(|err| io::Error::new(ErrorKind::Other, err.to_string()))?;

                let http2_stream = Http2Stream {
                    response: Some(response),
                    receiver: None,
                    sender,
                    buffer: BytesMut::new(),
                    future: None,
                };
                Ok(Box::new(http2_stream))
            }
            Some(security) => {
                let mut client = {
                    let client_clone = self.client.clone();
                    let mut result = client_clone.lock().await;
                    let client = match result.as_ref() {
                        Some(client) => client.clone(),
                        None => {
                            security.add_alpn("h2".to_string()).await;
                            let connection = security.dial(connection).await?;
                            let (mut client, h2) = client::handshake(connection)
                                .await
                                .map_err(|err| io::Error::new(ErrorKind::Other, err.to_string()))?;
                            let clone = self.client.clone();
                            *result = Some(client.clone());
                            tokio::spawn(async move {
                                let _ = h2.await;
                                *clone.lock().await = None;
                            });
                            client
                        }
                    };
                    client
                };

                let uri = Uri::builder()
                    .scheme("https")
                    .authority(host)
                    .path_and_query(path)
                    .build()
                    .map_err(|err| io::Error::new(ErrorKind::Other, err.to_string()))?;

                let request = Request::builder()
                    .uri(uri)
                    .version(Version::HTTP_2)
                    .method("GET")
                    .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.75 Safari/537.36")
                    .header("Accept-Encoding", "gzip, deflate")
                    .header("Pragma", "no-cache")
                    .header("Type", "http")
                    .body(())
                    .map_err(|err| io::Error::new(ErrorKind::Other, err.to_string()))?;

                let (response, sender) = client
                    .send_request(request, false)
                    .map_err(|err| io::Error::new(ErrorKind::Other, err.to_string()))?;

                let http2_stream = Http2Stream {
                    response: Some(response),
                    receiver: None,
                    sender,
                    buffer: BytesMut::new(),
                    future: None,
                };
                Ok(Box::new(http2_stream))
            }
        }
    }
}

struct Http2Stream {
    response: Option<ResponseFuture>,
    receiver: Option<RecvStream>,
    sender: SendStream<Bytes>,
    buffer: BytesMut,
    future: Option<
        Pin<
            Box<
                dyn Future<Output = Result<http::response::Response<RecvStream>, std::io::Error>>
                    + Send
                    + Sync,
            >,
        >,
    >,
}

impl AsyncRead for Http2Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.response.is_some() {
            let response = self.response.take().unwrap();

            let handle = Box::pin(async move {
                response
                    .await
                    .map_err(|err| io::Error::new(ErrorKind::Other, err.to_string()))
            });
            self.future = Some(handle);
        }
        if self.future.is_some() {
            let future = self.future.as_mut().unwrap();
            let result = std::task::ready!(Pin::new(future).poll(cx));
            match result {
                Ok(result) => {
                    self.receiver = Some(result.into_body());
                }
                Err(_) => {
                    return Poll::Ready(Err(io::Error::from(ErrorKind::BrokenPipe)));
                }
            }
            self.future = None;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }

        if !self.buffer.is_empty() {
            let to_read = std::cmp::min(buf.remaining(), self.buffer.len());
            let data = self.buffer.split_to(to_read);
            buf.put_slice(&data[..to_read]);
            return Poll::Ready(Ok(()));
        };

        if self.receiver.is_some() {
            let result = {
                let receiver = self.receiver.as_mut().unwrap();
                ready!(receiver.poll_data(cx))
            };
            return match result {
                None => Poll::Ready(Err(io::Error::from(ErrorKind::BrokenPipe))),
                Some(result) => match result {
                    Ok(data) => {
                        if data.len() == 0 {
                            return Poll::Ready(Err(io::Error::from(ErrorKind::BrokenPipe)));
                        }
                        let receiver = self.receiver.as_mut().unwrap();
                        let result = receiver.flow_control().release_capacity(data.len());
                        if let Err(e) = result {
                            return Poll::Ready(Err(Error::new(
                                ErrorKind::BrokenPipe,
                                format!("{:?}", e),
                            )));
                        }
                        self.buffer.extend_from_slice(&data[..]);
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    Err(_) => Poll::Ready(Err(io::Error::from(ErrorKind::BrokenPipe))),
                },
            };
        }

        Poll::Ready(Err(io::Error::from(ErrorKind::BrokenPipe)))
    }
}

impl AsyncWrite for Http2Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        self.sender.reserve_capacity(buf.len());
        let result = ready!(self.sender.poll_capacity(cx));
        return match result {
            Some(Ok(to_write)) => {
                let result = self
                    .sender
                    .send_data(Bytes::from(buf[..to_write].to_owned()), false);
                match result {
                    Ok(_) => Poll::Ready(Ok(buf.len())),
                    Err(e) => Poll::Ready(Err(io::Error::new(ErrorKind::BrokenPipe, e))),
                }
            }
            _ => Poll::Ready(Err(io::Error::from(ErrorKind::BrokenPipe))),
        };
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        let result = self.sender.send_data(Bytes::new(), true).map_or_else(
            |e| Err(io::Error::new(ErrorKind::BrokenPipe, e)),
            |_| Ok(()),
        );
        return Poll::Ready(result);
    }
}

impl AsyncXrayTcpStream for Http2Stream {}

impl XrayTransport for Http2Stream {}
