use std::any::Any;
use std::io;
use std::io::{Error, ErrorKind};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;
use bytes::BytesMut;
use futures::{ready, Sink, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{client_async, WebSocketStream};

use crate::common::net_location::NetLocation;
use crate::core::io::AsyncXrayTcpStream;
use crate::core::security::{Security, XraySecurity};
use crate::core::stream::StreamSettings;
use crate::core::transport::{Transport, XrayTransport};

use crate::stream::get_stream;
use crate::transport::websocket::config::WebsocketConfig;

pub mod config;

pub struct WebsocketTransport {
    security: Option<Box<dyn Security>>,
    host: Option<String>,
    path: Option<String>,
    stream_settings: Option<StreamSettings>,
}

impl WebsocketTransport {
    pub fn new(
        stream_settings: Option<StreamSettings>,
        websocket_config: Option<WebsocketConfig>,
        security: Option<Box<dyn Security>>,
    ) -> Self {
        match websocket_config {
            None => Self {
                stream_settings,
                security,
                host: None,
                path: None,
            },
            Some(websocket_config) => Self {
                stream_settings,
                security,
                host: websocket_config.host.clone(),
                path: websocket_config.path.clone(),
            },
        }
    }
}

#[async_trait]
impl Transport for WebsocketTransport {
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
        // trace!("websocket transport host is {}",host);
        let path = match &self.path {
            None => "/".to_string(),
            Some(path) => path.clone(),
        };
        // trace!("websocket transport path is {}",path);
        return match &self.security {
            None => {
                let url = format!("ws://{}:{}{}", host, server_net_location.port, path);
                let websocket = client_async(url, connection)
                    .await
                    .map_err(|err| Error::new(ErrorKind::ConnectionRefused, err))?;
                let (connection, _) = websocket;
                let websocket_transport = WebsocketStream {
                    connection,
                    read_buffer: BytesMut::new(),
                    shutdown_state: 0,
                };
                Ok(Box::new(websocket_transport))
            }
            Some(security) => {
                let connection = security.dial(connection).await?;
                let url = format!("wss://{}:{}{}", host, server_net_location.port, path);
                let websocket = client_async(url, connection)
                    .await
                    .map_err(|err| Error::new(ErrorKind::ConnectionRefused, err))?;
                let (connection, _) = websocket;
                let websocket_transport = WebsocketStream {
                    connection,
                    read_buffer: BytesMut::new(),
                    shutdown_state: 0,
                };
                Ok(Box::new(websocket_transport))
            }
        };
    }
}

struct WebsocketStream<T: AsyncRead + AsyncWrite + Send + Sync + Unpin> {
    connection: WebSocketStream<T>,
    read_buffer: BytesMut,
    shutdown_state: u8,
}

impl<T: AsyncRead + AsyncWrite + Send + Sync + Unpin> AsyncRead for WebsocketStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), Error>> {
        if !self.read_buffer.is_empty() {
            let to_read = std::cmp::min(buf.remaining(), self.read_buffer.len());
            let data = self.read_buffer.split_to(to_read);
            buf.put_slice(&data[..to_read]);
            return Poll::Ready(Ok(()));
        };
        let result = ready!(Pin::new(&mut self.connection).poll_next(cx));
        let message = match result {
            None => {
                return Poll::Ready(Err(Error::new(
                    ErrorKind::BrokenPipe,
                    "unreachable websocket message",
                )));
            }
            Some(result) => match result {
                Ok(message) => message,
                Err(err) => {
                    return Poll::Ready(Err(Error::new(ErrorKind::BrokenPipe, err)));
                }
            },
        };
        return match message {
            Message::Binary(binary) => {
                if binary.len() < buf.remaining() {
                    buf.put_slice(&binary);
                    Poll::Ready(Ok(()))
                } else {
                    self.read_buffer.extend_from_slice(&binary);
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
            Message::Close(_) => Poll::Ready(Ok(())),
            _ => Poll::Ready(Err(Error::new(
                ErrorKind::BrokenPipe,
                "unsupported websocket message type",
            ))),
        };
    }
}

impl<T: AsyncRead + AsyncWrite + Send + Sync + Unpin> AsyncWrite for WebsocketStream<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        let result = ready!(Pin::new(&mut self.connection).poll_ready(cx));
        match result {
            Ok(_) => {}
            Err(err) => {
                return Poll::Ready(Err(Error::new(ErrorKind::BrokenPipe, err)));
            }
        }
        let message = Message::Binary(bytes::Bytes::copy_from_slice(buf));
        let result = Pin::new(&mut self.connection).start_send(message);
        return match result {
            Ok(_) => Poll::Ready(Ok(buf.len())),
            Err(err) => Poll::Ready(Err(Error::new(ErrorKind::BrokenPipe, err))),
        };
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let result = ready!(Pin::new(&mut self.connection).poll_flush(cx));
        match result {
            Ok(_) => Poll::Ready(Ok(())),
            Err(err) => Poll::Ready(Err(Error::new(ErrorKind::BrokenPipe, err))),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        if self.shutdown_state == 0 {
            let result = ready!(Pin::new(&mut self.connection).poll_ready(cx));
            match result {
                Ok(_) => {}
                Err(err) => {
                    return Poll::Ready(Err(Error::new(ErrorKind::BrokenPipe, err)));
                }
            }
            let message = Message::Close(None);
            let _ = Pin::new(&mut self.connection).start_send(message);
            self.shutdown_state = 1;
        }
        if self.shutdown_state == 1 {
            let result = ready!(Pin::new(&mut self.connection).poll_close(cx));
            self.shutdown_state = 2;
            return match result {
                Ok(_) => Poll::Ready(Ok(())),
                Err(err) => Poll::Ready(Err(Error::new(ErrorKind::BrokenPipe, err))),
            };
        }

        Poll::Ready(Err(Error::new(
            ErrorKind::BrokenPipe,
            "already shutdown websocket connection",
        )))
    }
}

impl<T: AsyncRead + AsyncWrite + Send + Sync + Unpin + Any> AsyncXrayTcpStream
    for WebsocketStream<T>
{
}

impl<T: AsyncRead + AsyncWrite + Send + Sync + Unpin + Any> XrayTransport for WebsocketStream<T> {}
