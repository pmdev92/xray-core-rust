use std::future::Future;
use std::io;
use std::io::ErrorKind;
use std::ops::Deref;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures_util::ready;
use h2::{client, RecvStream, SendStream};
use http::{Request, Uri, Version};
use log::trace;
use prost::encoding::{decode_varint, encode_varint};
use tls_parser::nom::AsBytes;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::common::net_location::NetLocation;
use crate::core::io::AsyncXrayTcpStream;
use crate::core::security::{Security, XraySecurity};
use crate::core::stream::StreamSettings;
use crate::core::transport::{Transport, XrayTransport};
use crate::stream::get_stream;
use crate::transport::grpc::config::GrpcConfig;

pub mod config;

pub struct GrpcTransport {
    security: Option<Box<dyn Security>>,
    service_name: Option<String>,
    stream_settings: Option<StreamSettings>,
}

impl GrpcTransport {
    pub fn new(
        stream_settings: Option<StreamSettings>,
        grpc_config: Option<GrpcConfig>,
        security: Option<Box<dyn Security>>,
    ) -> Self {
        match grpc_config {
            None => {
                panic!("grpc must have a settings");
            }
            Some(grpc_config) => Self {
                stream_settings,
                security,
                service_name: grpc_config.service_name.clone(),
            },
        }
    }
}

#[async_trait]
impl Transport for GrpcTransport {
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
        let mut host = server_net_location.address.to_string();
        if let Some(security) = &self.security {
            if let Some(domain) = security.get_domain() {
                host = domain;
            }
        }
        trace!("grpc transport host is {}", host);

        let mut path = "//Tun".to_string();
        if let Some(mut service_name) = self.service_name.clone() {
            if !service_name.starts_with("/") {
                service_name = format!("/{}", service_name);
            }
            let parts = service_name.split("/");
            let parts: Vec<&str> = parts.collect();
            let parts: Vec<&str> = parts
                .into_iter()
                .filter(|item| {
                    return item != &"";
                })
                .collect();

            if parts.len() == 1 {
                path = format!("/{}/Tun", parts[0]);
            } else if parts.len() > 1 {
                path = "".to_string();
                for part in parts {
                    let helper = format!("/{}", part);
                    path.push_str(helper.as_str());
                }
            }
        }
        trace!("grpc transport path is {}", path);
        match &self.security {
            None => {
                let (mut client, h2) = client::handshake(connection)
                    .await
                    .map_err(|err| io::Error::new(ErrorKind::Other, err.to_string()))?;
                let uri = Uri::builder()
                    .scheme("http")
                    .authority(host)
                    .path_and_query(path)
                    .build()
                    .map_err(|err| io::Error::new(ErrorKind::Other, err.to_string()))?;

                let request = Request::builder()
                    .uri(uri)
                    .version(Version::HTTP_2)
                    .method("POST")
                    .header("content-type", "application/grpc")
                    .header("user-agent", "grpc-go/1.46.0")
                    .body(())
                    .map_err(|err| io::Error::new(ErrorKind::Other, err.to_string()))?;

                let (response, sender) = client
                    .send_request(request, false)
                    .map_err(|err| io::Error::new(ErrorKind::Other, err.to_string()))?;

                tokio::spawn(async move {
                    let _ = h2.await;
                });
                let http2_stream = GrpcStream {
                    response,
                    receiver: None,
                    sender,
                    raw_buffer: BytesMut::new(),
                    buffer: BytesMut::new(),
                    remaining_read: 0,
                };
                Ok(Box::new(http2_stream))
            }
            Some(security) => {
                security.add_alpn("h2".to_string()).await;
                let connection = security.dial(connection).await?;
                let (mut client, h2) = client::handshake(connection)
                    .await
                    .map_err(|err| io::Error::new(ErrorKind::Other, err.to_string()))?;
                let uri = Uri::builder()
                    .scheme("https")
                    .authority(host)
                    .path_and_query(path)
                    .build()
                    .map_err(|err| io::Error::new(ErrorKind::Other, err.to_string()))?;
                let request = Request::builder()
                    .uri(uri)
                    .version(Version::HTTP_2)
                    .method("POST")
                    .header("content-type", "application/grpc")
                    .header("user-agent", "grpc-go/1.46.0")
                    .body(())
                    .map_err(|err| io::Error::new(ErrorKind::Other, err.to_string()))?;

                let (response, sender) = client
                    .send_request(request, false)
                    .map_err(|err| io::Error::new(ErrorKind::Other, err.to_string()))?;

                tokio::spawn(async move {
                    let _ = h2.await;
                });
                let http2_stream = GrpcStream {
                    response,
                    receiver: None,
                    sender,
                    raw_buffer: BytesMut::new(),
                    buffer: BytesMut::new(),
                    remaining_read: 0,
                };

                Ok(Box::new(http2_stream))
            }
        }
    }
}

struct GrpcStream {
    response: client::ResponseFuture,
    receiver: Option<RecvStream>,
    sender: SendStream<Bytes>,
    raw_buffer: BytesMut,
    buffer: BytesMut,
    remaining_read: usize,
}

impl GrpcStream {
    fn reserve_send_capacity(&mut self, data: &[u8]) {
        let mut buf = [0u8; 10];
        let mut buf = &mut buf[..];
        encode_varint(data.len() as u64, &mut buf);
        self.sender
            .reserve_capacity(6 + 10 - buf.len() + data.len());
    }

    fn encode_buf(&self, data: &[u8]) -> Bytes {
        let mut buf = BytesMut::with_capacity(16 + data.len());
        let grpc_header = [0u8; 5];
        buf.put_slice(&grpc_header[..]);
        buf.put_u8(0x0a);
        encode_varint(data.len() as u64, &mut buf);
        let payload_len = ((buf.len() - 5 + data.len()) as u32).to_be_bytes();
        buf[1..5].copy_from_slice(&payload_len[..4]);
        buf.put_slice(data);
        buf.freeze()
    }
}

impl AsyncRead for GrpcStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.receiver.is_none() {
            let result = ready!(Pin::new(&mut self.response).poll(cx));
            match result {
                Ok(response) => {
                    self.receiver = Some(response.into_body());
                }
                Err(error) => {
                    return Poll::Ready(Err(io::Error::new(ErrorKind::BrokenPipe, error)));
                }
            }
        }
        if !self.raw_buffer.is_empty() {
            if self.remaining_read > 0 {
                if self.raw_buffer.len() > self.remaining_read {
                    let len = self.remaining_read;
                    let data = self.raw_buffer.split_to(len);
                    self.buffer.extend_from_slice(data.as_bytes());
                    self.remaining_read = 0;
                } else {
                    let len = self.raw_buffer.len();
                    let data = self.raw_buffer.split();
                    self.buffer.extend_from_slice(data.as_bytes());
                    self.remaining_read = self.remaining_read - len;
                }
            }
            while self.raw_buffer.len() > 6 {
                self.raw_buffer.advance(6);
                let result = decode_varint(&mut self.raw_buffer);
                match result {
                    Err(error) => {
                        return Poll::Ready(Err(io::Error::new(ErrorKind::BrokenPipe, error)));
                    }
                    Ok(len) => {
                        if len as usize > self.raw_buffer.len() {
                            let remaining = self.raw_buffer.len();
                            self.remaining_read = len as usize - remaining;
                            let data = self.raw_buffer.split();
                            self.buffer.extend_from_slice(data.as_bytes());
                            break;
                        } else {
                            let data = self.raw_buffer.split_to(len as usize);
                            self.buffer.extend_from_slice(data.as_bytes());
                        }
                    }
                };
            }
        }
        if self.remaining_read == 0 || buf.remaining() < self.buffer.len() {
            if !self.buffer.is_empty() {
                let to_read = std::cmp::min(buf.remaining(), self.buffer.len());
                let data = self.buffer.split_to(to_read);
                buf.put_slice(&data[..to_read]);
                return Poll::Ready(Ok(()));
            }
        }
        match ready!(
            Pin::new(&mut self.receiver)
                .as_pin_mut()
                .unwrap()
                .poll_data(cx)
        ) {
            Some(Ok(data)) => {
                self.raw_buffer.put_slice(data.as_bytes());
                let result = self
                    .receiver
                    .as_mut()
                    .unwrap()
                    .flow_control()
                    .release_capacity(data.len())
                    .map_or_else(
                        |e| Err(io::Error::new(ErrorKind::ConnectionReset, e)),
                        |_| Ok(()),
                    );
                match result {
                    Ok(_ok) => {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    Err(err) => Poll::Ready(Err(err)),
                }
            }
            _ => {
                // self.sender.
                Poll::Ready(Ok(()))
                // let string = format!("grpc none remaining_read {}", self.remaining_read);
                // Poll::Ready(Err(s2n_quic_io::Error::new(ErrorKind::BrokenPipe, string)))
            }
        }
    }
}

impl AsyncWrite for GrpcStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        self.reserve_send_capacity(buf);
        let result = ready!(self.sender.poll_capacity(cx));
        match result {
            None => {}
            Some(result) => match result {
                Ok(_) => {}
                Err(err) => {
                    return Poll::Ready(Err(io::Error::new(ErrorKind::BrokenPipe, err)));
                }
            },
        }

        let encoded_buf = self.encode_buf(buf);
        let result = self.sender.send_data(encoded_buf, false);
        return match result {
            Ok(_) => Poll::Ready(Ok(buf.len())),
            Err(err) => Poll::Ready(Err(io::Error::new(ErrorKind::BrokenPipe, err))),
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
        // self.task.abort();
        Poll::Ready(result)

        // Poll::Ready(Ok(()))
    }
}

impl AsyncXrayTcpStream for GrpcStream {}

impl XrayTransport for GrpcStream {}
