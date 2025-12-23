use std::any::Any;
use std::collections::HashMap;
use std::io;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use async_trait::async_trait;
use bytes::BytesMut;
use tls_parser::nom::AsBytes;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::common::header::parse_headers;
use crate::common::net_location::NetLocation;
use crate::core::io::AsyncXrayTcpStream;
use crate::core::security::{Security, XraySecurity};
use crate::core::stream::StreamSettings;
use crate::core::transport::{Transport, XrayTransport};
use crate::security::reality::RealitySecurity;
use crate::security::tls::xtls::TlsXtlsSecurityStream;
use crate::security::tls::TlsSecurity;
use crate::stream::get_stream;
use crate::transport::tcp::config::{RequestConfig, TcpConfig};

pub mod config;

pub struct TcpTransport {
    security: Option<Box<dyn Security>>,
    is_http: bool,
    request: Option<RequestConfig>,
    stream_settings: Option<StreamSettings>,
}

impl TcpTransport {
    pub fn new(
        stream_settings: Option<StreamSettings>,
        tcp_config: Option<TcpConfig>,
        security: Option<Box<dyn Security>>,
    ) -> Self {
        let mut is_http = false;
        let mut request: Option<RequestConfig> = None;
        match tcp_config {
            None => {}
            Some(tcp_config) => {
                let t = tcp_config.r#type.clone().unwrap_or("none".to_string());
                request = tcp_config.request.clone();
                if t == "http" {
                    is_http = true;
                }
            }
        }
        Self {
            stream_settings,
            security,
            is_http,
            request,
        }
    }
}

impl TcpTransport {
    fn make_request(
        &self,
        method: String,
        path: String,
        version: String,
        mut headers: HashMap<String, String>,
    ) -> String {
        let default_host = "www.bing.com";
        let default_user_agent =
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0";
        let default_accept =
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8";
        let default_accept_encoding = "gzip, deflate, br";
        let default_accept_language = "en-US,en;q=0.5";
        let default_connection = "keep-alive";
        let default_pragma = "no-cache";
        let mut header_string = "".to_string();
        let (key, value) = headers
            .remove_entry("Host")
            .unwrap_or(("Host".to_string(), default_host.to_string()));
        header_string.push_str(format!("{}: {}\r\n", key, value).as_str());

        let (key, value) = headers
            .remove_entry("User-Agent")
            .unwrap_or(("User-Agent".to_string(), default_user_agent.to_string()));
        header_string.push_str(format!("{}: {}\r\n", key, value).as_str());

        let (key, value) = headers
            .remove_entry("Accept")
            .unwrap_or(("Accept".to_string(), default_accept.to_string()));
        header_string.push_str(format!("{}: {}\r\n", key, value).as_str());

        let (key, value) = headers.remove_entry("Accept-Language").unwrap_or((
            "Accept-Language".to_string(),
            default_accept_language.to_string(),
        ));
        header_string.push_str(format!("{}: {}\r\n", key, value).as_str());

        let (key, value) = headers.remove_entry("Accept-Encoding").unwrap_or((
            "Accept-Encoding".to_string(),
            default_accept_encoding.to_string(),
        ));
        header_string.push_str(format!("{}: {}\r\n", key, value).as_str());

        let (key, value) = headers
            .remove_entry("Connection")
            .unwrap_or(("Connection".to_string(), default_connection.to_string()));
        header_string.push_str(format!("{}: {}\r\n", key, value).as_str());

        let (key, value) = headers
            .remove_entry("Pragma")
            .unwrap_or(("Pragma".to_string(), default_pragma.to_string()));
        header_string.push_str(format!("{}: {}\r\n", key, value).as_str());

        for (key, value) in &headers {
            let header = format!("{}: {}\r\n", key, value);
            header_string.push_str(header.as_str());
        }

        let request = format!(
            "{} {} HTTP/{}\r\n{}\r\n",
            method, path, version, header_string
        );
        return request;
    }
    fn get_request(&self) -> String {
        let request = match &self.request {
            None => {
                let method = "GET".to_string();
                let path = "/".to_string();
                let version = "1.1".to_string();
                let headers_map: HashMap<String, String> = HashMap::new();
                return self.make_request(method, path, version, headers_map);
            }
            Some(request) => request.clone(),
        };
        let method = request.method.unwrap_or("GET".to_string()).to_uppercase();
        let path = request.path.unwrap_or("/".to_string());
        let version = request.version.unwrap_or("1.1".to_string());
        let headers_map = parse_headers(request.headers);

        self.make_request(method, path, version, headers_map)
    }

    pub async fn dial_xtls(
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
        let mut http_request_header_buffer = BytesMut::new();
        if self.is_http {
            let request = self.get_request();
            http_request_header_buffer.extend_from_slice(request.as_bytes());
        }
        if let Some(security) = self.security.as_ref() {
            let any: &dyn Any = security.deref() as &dyn Any;
            let mut connection: Option<Box<dyn XraySecurity>> =
                if let Some(tls) = any.downcast_ref::<TlsSecurity>() {
                    Some(tls.dial_xtls(connection).await?)
                } else if let Some(tls) = any.downcast_ref::<RealitySecurity>() {
                    Some(tls.dial_xtls(connection).await?)
                } else {
                    None
                };
            if let Some(connection) = connection {
                let tcp_transport = TcpTransportStream {
                    connection,
                    is_xtls: true,
                    is_http: false,
                    is_http_request_end: false,
                    is_http_response_end: false,
                    buffer: BytesMut::new(),
                    http_response_header_buffer: BytesMut::new(),
                    http_request_header_buffer,
                };
                return Ok(Box::new(tcp_transport));
            }
        }

        Err(io::Error::new(
            io::ErrorKind::Other,
            "xtl must have security",
        ))
    }
}

#[async_trait]
impl Transport for TcpTransport {
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
        let mut http_request_header_buffer = BytesMut::new();
        if self.is_http {
            let request = self.get_request();
            http_request_header_buffer.extend_from_slice(request.as_bytes());
        }

        match &self.security {
            None => {
                let tcp_transport = TcpTransportStream {
                    connection,
                    is_xtls: false,
                    is_http: self.is_http,
                    is_http_request_end: false,
                    is_http_response_end: false,
                    buffer: BytesMut::new(),
                    http_response_header_buffer: BytesMut::new(),
                    http_request_header_buffer,
                };
                Ok(Box::new(tcp_transport))
            }
            Some(security) => {
                let mut connection = security.dial(connection).await?;
                let tcp_transport = TcpTransportStream {
                    connection,
                    is_xtls: false,
                    is_http: self.is_http.clone(),
                    is_http_request_end: false,
                    is_http_response_end: false,
                    buffer: BytesMut::new(),
                    http_response_header_buffer: BytesMut::new(),
                    http_request_header_buffer,
                };
                Ok(Box::new(tcp_transport))
            }
        }
    }
}

pub struct TcpTransportStream {
    connection: Box<dyn AsyncXrayTcpStream>,
    is_xtls: bool,
    is_http: bool,
    is_http_request_end: bool,
    is_http_response_end: bool,
    buffer: BytesMut,
    http_response_header_buffer: BytesMut,
    http_request_header_buffer: BytesMut,
}

impl TcpTransportStream {
    pub fn get_raw_stream(&mut self) -> &mut Box<dyn AsyncXrayTcpStream> {
        if self.is_xtls {
            let any: &mut dyn Any = self.connection.deref_mut() as &mut dyn Any;
            let tls_stream = any
                .downcast_mut::<TlsXtlsSecurityStream>()
                .expect("tls stream");
            return tls_stream.get_raw_stream();
        }
        return &mut self.connection;
    }
}

impl AsyncRead for TcpTransportStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.is_http && !self.is_http_response_end {
            let mut data = [0u8; 8 * 1024].to_vec();
            let mut buffer = ReadBuf::new(&mut data);
            let result = ready!(Pin::new(&mut self.connection).poll_read(cx, &mut buffer));
            return match result {
                Ok(_) => {
                    let helper = [13u8, 10, 13, 10];
                    let found = find_subsequence(buffer.filled(), helper.as_ref());
                    let size = match found {
                        None => {
                            self.http_response_header_buffer
                                .extend_from_slice(buffer.filled());
                            cx.waker().wake_by_ref();
                            return Poll::Pending;
                        }
                        Some(found) => found + 4,
                    };
                    let (response, data) = buffer.filled().split_at(size);
                    self.http_response_header_buffer.extend_from_slice(response);
                    self.buffer.extend_from_slice(data);
                    self.is_http_response_end = true;
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Err(err) => Poll::Ready(Err(err)),
            };
        }
        if !self.buffer.is_empty() {
            let to_read = buf.remaining();
            if to_read <= self.buffer.len() {
                let data = self.buffer.split_to(to_read);
                buf.put_slice(data.as_bytes());
                return Poll::Ready(Ok(()));
            }
            let data = self.buffer.split();
            buf.put_slice(data.as_bytes());
            return Poll::Ready(Ok(()));
        }

        let result = ready!(Pin::new(&mut self.connection).poll_read(cx, buf));
        return match result {
            Ok(_) => Poll::Ready(Ok(())),
            Err(err) => Poll::Ready(Err(err)),
        };
    }
}

impl AsyncWrite for TcpTransportStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        if self.is_http && !self.is_http_request_end {
            let request = self.http_request_header_buffer.as_bytes().to_vec();
            let result = ready!(Pin::new(&mut self.connection).poll_write(cx, request.as_slice()));
            match result {
                Ok(size) => {
                    let _ = self.http_request_header_buffer.split_to(size);
                    if self.http_request_header_buffer.is_empty() {
                        self.is_http_request_end = true;
                    } else {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Err(err) => {
                    return Poll::Ready(Err(err));
                }
            }
        }

        let result = ready!(Pin::new(&mut self.connection).poll_write(cx, buf));
        return match result {
            Ok(_size) => Poll::Ready(Ok(buf.len())),
            Err(err) => Poll::Ready(Err(err)),
        };
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        return Pin::new(&mut self.connection).poll_flush(cx);
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        return Pin::new(&mut self.connection).poll_shutdown(cx);
    }
}

impl AsyncXrayTcpStream for TcpTransportStream {}
impl XrayTransport for TcpTransportStream {}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
