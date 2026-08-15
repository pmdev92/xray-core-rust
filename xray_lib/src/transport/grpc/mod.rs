use std::io;
use std::io::ErrorKind;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use crate::common::net_location::NetLocation;
use crate::core::io::AsyncXrayTcpStream;
use crate::core::security::Security;
use crate::core::stream::StreamSettings;
use crate::core::transport::{Transport, XrayTransport};
use crate::stream::get_stream;
use crate::transport::grpc::config::GrpcConfig;
use async_trait::async_trait;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use h2::{RecvStream, SendStream, client};
use http::{Request, Uri, Version};
use log::{error, trace};
use prost::encoding::{decode_varint, encode_varint};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Mutex;

pub mod config;

pub struct GrpcTransport {
    security: Option<Box<dyn Security>>,
    service_name: Option<String>,
    stream_settings: Option<StreamSettings>,
    client: Arc<Mutex<Option<h2::client::SendRequest<Bytes>>>>,
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
                client: Arc::new(Mutex::new(None)),
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

        let mut path = "//Tun".to_string();
        if let Some(mut service_name) = self.service_name.clone() {
            if !service_name.starts_with("/") {
                service_name = format!("/{}", service_name);
            }
            let parts: Vec<&str> = service_name
                .split("/")
                .filter(|item| !item.is_empty())
                .collect();

            if parts.len() == 1 {
                path = format!("/{}/Tun", parts[0]);
            } else if parts.len() > 1 {
                path = "".to_string();
                for part in parts {
                    path.push_str(&format!("/{}", part));
                }
            }
        }

        match &self.security {
            None => {
                let client = {
                    let client_clone = self.client.clone();
                    let mut result = client_clone.lock().await;
                    match result.as_ref() {
                        Some(client) => {
                            trace!("grpc use exist connection");
                            client.clone()
                        }
                        None => {
                            trace!("grpc transport host is {}", host);
                            trace!("grpc transport path is {}", path);
                            let mut builder = client::Builder::new();
                            builder
                                .initial_window_size(1024 * 1024)
                                .initial_connection_window_size(2 * 1024 * 1024);
                            let (mut client, h2) = builder
                                .handshake(connection)
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
                    }
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
                    .method("POST")
                    .header("content-type", "application/grpc")
                    .header("user-agent", "grpc-go/1.46.0")
                    .body(())
                    .map_err(|err| io::Error::new(ErrorKind::Other, err.to_string()))?;

                let (response, sender) = {
                    let mut client = client;
                    client
                        .send_request(request, false)
                        .map_err(|err| io::Error::new(ErrorKind::Other, err.to_string()))?
                };

                Ok(Box::new(GrpcStream {
                    response,
                    receiver: None,
                    sender,
                    raw_buffer: BytesMut::new(),
                    buffer: BytesMut::new(),
                }))
            }

            Some(security) => {
                let client = {
                    let client_clone = self.client.clone();
                    let mut result = client_clone.lock().await;
                    match result.as_ref() {
                        Some(client) => {
                            trace!("grpc use exist connection");
                            client.clone()
                        }
                        None => {
                            trace!("grpc transport host is {}", host);
                            trace!("grpc transport path is {}", path);
                            security.add_alpn("h2".to_string()).await;
                            security.add_alpn("http/1.1".to_string()).await;
                            let connection = security.dial(connection).await?;
                            let mut builder = client::Builder::new();
                            builder
                                .initial_window_size(1024 * 1024)
                                .initial_connection_window_size(2 * 1024 * 1024);
                            let (mut client, h2) = builder
                                .handshake(connection)
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
                    }
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
                    .method("POST")
                    .header("content-type", "application/grpc")
                    .header("user-agent", "grpc-go/1.46.0")
                    .body(())
                    .map_err(|err| io::Error::new(ErrorKind::Other, err.to_string()))?;

                let (response, sender) = {
                    let mut client = client;
                    client
                        .send_request(request, false)
                        .map_err(|err| io::Error::new(ErrorKind::Other, err.to_string()))?
                };

                Ok(Box::new(GrpcStream {
                    response,
                    receiver: None,
                    sender,
                    raw_buffer: BytesMut::new(),
                    buffer: BytesMut::new(),
                }))
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
}

impl GrpcStream {
    const MAX_WRITE_PAYLOAD: usize = 16 * 1024;

    fn encoded_len(payload_len: usize) -> usize {
        let mut value = payload_len as u64;
        let mut varint_len = 1;
        while value >= 0x80 {
            value >>= 7;
            varint_len += 1;
        }
        6 + varint_len + payload_len
    }

    fn payload_for_capacity(capacity: usize, max_payload: usize) -> usize {
        let mut payload_len = max_payload.min(capacity.saturating_sub(7));
        while payload_len > 0 && Self::encoded_len(payload_len) > capacity {
            payload_len -= 1;
        }
        payload_len
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

    fn decode_next_message(&mut self) -> io::Result<bool> {
        const GRPC_HEADER_LEN: usize = 5;
        const MAX_GRPC_MESSAGE_LEN: usize = 64 * 1024 * 1024;

        if self.raw_buffer.len() < GRPC_HEADER_LEN {
            return Ok(false);
        }

        let compression_flag = self.raw_buffer[0];
        if compression_flag != 0 {
            error!(
                "grpc decode failed: unsupported compression flag={}",
                compression_flag
            );
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "compressed gRPC messages are not supported",
            ));
        }

        let message_len = u32::from_be_bytes([
            self.raw_buffer[1],
            self.raw_buffer[2],
            self.raw_buffer[3],
            self.raw_buffer[4],
        ]) as usize;

        if message_len > MAX_GRPC_MESSAGE_LEN {
            error!("grpc decode failed: message too large={}", message_len);
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "gRPC message is too large",
            ));
        }

        let frame_len = GRPC_HEADER_LEN
            .checked_add(message_len)
            .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "invalid gRPC frame length"))?;

        if self.raw_buffer.len() < frame_len {
            return Ok(false);
        }

        self.raw_buffer.advance(GRPC_HEADER_LEN);
        let mut message = self.raw_buffer.split_to(message_len);

        if message.is_empty() || message.get_u8() != 0x0a {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "invalid gRPC protobuf payload",
            ));
        }

        let payload_len = decode_varint(&mut message)
            .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?
            as usize;

        if payload_len != message.len() {
            error!(
                "grpc decode failed: protobuf payload length={}, remaining={}",
                payload_len,
                message.len()
            );
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "invalid gRPC protobuf payload length",
            ));
        }

        trace!(
            "grpc decoded message: frame_payload={} bytes, proxy_payload={} bytes",
            message_len, payload_len
        );
        self.buffer = message.split_to(payload_len);
        Ok(true)
    }
}

impl AsyncRead for GrpcStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        if self.receiver.is_none() {
            let response = match Pin::new(&mut self.response).poll(cx) {
                Poll::Pending => {
                    trace!("grpc download: waiting for response headers");
                    return Poll::Pending;
                }
                Poll::Ready(r) => r,
            };
            match response {
                Ok(response) => {
                    trace!(
                        "grpc download: response headers received, status={}",
                        response.status()
                    );
                    self.receiver = Some(response.into_body());
                }
                Err(error) => {
                    error!("grpc download: response failed: {}", error);
                    return Poll::Ready(Err(io::Error::new(ErrorKind::BrokenPipe, error)));
                }
            }
        }

        loop {
            if !self.buffer.is_empty() {
                let to_read = buf.remaining().min(self.buffer.len());
                let data = self.buffer.split_to(to_read);
                buf.put_slice(&data);
                trace!("grpc download: delivered {} proxy bytes", to_read);
                return Poll::Ready(Ok(()));
            }

            match self.decode_next_message() {
                Ok(true) => continue,
                Ok(false) => {}
                Err(error) => {
                    error!("grpc download: decode failed: {}", error);
                    return Poll::Ready(Err(error));
                }
            }

            let data = match Pin::new(self.receiver.as_mut().unwrap()).poll_data(cx) {
                Poll::Pending => {
                    trace!(
                        "grpc download: waiting for DATA, buffered={} bytes",
                        self.raw_buffer.len()
                    );
                    return Poll::Pending;
                }
                Poll::Ready(Some(Ok(data))) => data,
                Poll::Ready(Some(Err(error))) => {
                    error!("grpc download: DATA error: {}", error);
                    return Poll::Ready(Err(io::Error::new(ErrorKind::BrokenPipe, error)));
                }
                Poll::Ready(None) if self.raw_buffer.is_empty() => {
                    trace!("grpc download: response body ended cleanly");
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(None) => {
                    error!(
                        "grpc download: response ended with incomplete frame, buffered={} bytes",
                        self.raw_buffer.len()
                    );
                    return Poll::Ready(Err(io::Error::new(
                        ErrorKind::UnexpectedEof,
                        "incomplete gRPC frame",
                    )));
                }
            };

            let data_len = data.len();
            self.raw_buffer.extend_from_slice(&data);
            trace!(
                "grpc download: received DATA={} bytes, buffered={} bytes",
                data_len,
                self.raw_buffer.len()
            );

            if let Err(error) = self
                .receiver
                .as_mut()
                .unwrap()
                .flow_control()
                .release_capacity(data_len)
            {
                error!("grpc download: release capacity failed: {}", error);
                return Poll::Ready(Err(io::Error::new(ErrorKind::ConnectionReset, error)));
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
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let desired_payload = buf.len().min(Self::MAX_WRITE_PAYLOAD);
        let desired_capacity = Self::encoded_len(desired_payload);
        self.sender.reserve_capacity(desired_capacity);
        trace!(
            "grpc upload: requested={} bytes, chunk={} bytes, frame={} bytes, available={}",
            buf.len(),
            desired_payload,
            desired_capacity,
            self.sender.capacity()
        );

        loop {
            match self.sender.poll_capacity(cx) {
                Poll::Pending => {
                    trace!(
                        "grpc upload: waiting for capacity, available={}",
                        self.sender.capacity()
                    );
                    return Poll::Pending;
                }
                Poll::Ready(None) => {
                    error!("grpc upload: send stream closed while waiting for capacity");
                    return Poll::Ready(Err(io::Error::new(
                        ErrorKind::BrokenPipe,
                        "gRPC send stream is closed",
                    )));
                }
                Poll::Ready(Some(Err(error))) => {
                    error!("grpc upload: capacity error: {}", error);
                    return Poll::Ready(Err(io::Error::new(ErrorKind::BrokenPipe, error)));
                }
                Poll::Ready(Some(Ok(granted))) => {
                    trace!(
                        "grpc upload: capacity granted={}, available={}",
                        granted,
                        self.sender.capacity()
                    );
                }
            }

            let payload_len = Self::payload_for_capacity(self.sender.capacity(), desired_payload);
            if payload_len == 0 {
                trace!(
                    "grpc upload: capacity cannot fit a frame yet, available={}",
                    self.sender.capacity()
                );
                self.sender.reserve_capacity(desired_capacity);
                continue;
            }

            let encoded_buf = self.encode_buf(&buf[..payload_len]);
            let frame_len = encoded_buf.len();
            return match self.sender.send_data(encoded_buf, false) {
                Ok(()) => {
                    trace!(
                        "grpc upload: sent proxy_payload={} bytes, frame={} bytes",
                        payload_len, frame_len
                    );
                    Poll::Ready(Ok(payload_len))
                }
                Err(error) => {
                    error!("grpc upload: send_data failed: {}", error);
                    Poll::Ready(Err(io::Error::new(ErrorKind::BrokenPipe, error)))
                }
            };
        }
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
        Poll::Ready(result)
    }
}

impl AsyncXrayTcpStream for GrpcStream {}

impl XrayTransport for GrpcStream {}
