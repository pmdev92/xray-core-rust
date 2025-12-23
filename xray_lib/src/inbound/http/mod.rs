use io::ErrorKind;
use std;
use std::collections::HashMap;
use std::io;
use std::io::Error;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::Deref;
use std::pin::{Pin, pin};
use std::str::FromStr;
use std::sync::{Arc, Mutex, OnceLock};
use std::task::Poll;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use digest::consts::U16;
use futures_util::future::{BoxFuture, join_all};
use http::{HeaderName, HeaderValue, Method, Request, Response, Version};
use http_body_util::combinators::BoxBody;
use hyper::body::Incoming;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use log::{error, info, warn};
use socket2::TcpKeepalive;
use tls_parser::nom::AsBytes;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc::Receiver;
use tokio::sync::mpsc::Sender;
use tokio::task::JoinHandle;
use tokio::time::sleep;

use crate::common::address::Address;
use crate::common::buffer::copy;
use crate::common::constants::MAX_UDP_BUFFER_CAPACITY;
use crate::common::net_location::NetLocation;
use crate::common::udp::get_udp_open_port;
use crate::common::vec::vec_allocate;
use crate::core::context::Context;
use crate::core::dispatcher::Dispatcher;
use crate::core::inbound::{InboundConfig, InboundTcp};
use crate::core::router::Network;
use crate::core::session::Session;
use crate::core::sniffer::Sniffer;
use crate::inbound::InboundProtocol;
use crate::inbound::http::config::HttpInboundSettings;
use crate::inbound::http::protocol::{
    apply_keep_alive, get_http_response_400, get_http_response_503, parse_host, parse_u16,
    read_handle_1xx_http_response, read_http_request, remove_keep_alive, request_to_bytes,
    response_to_bytes,
};

pub mod config;
mod protocol;

#[derive(Debug)]
pub struct HttpInbound {
    pub net_location: NetLocation,
}

impl HttpInbound {
    pub fn new(inbound_config: HttpInboundSettings) -> Self {
        let Ok(address) = Address::from(&inbound_config.listen) else {
            panic!("http inbound address is invalid");
        };

        let net_location = NetLocation::new(address, inbound_config.port);
        Self { net_location }
    }
    async fn process_socket(
        &self,
        session: Session,
        context: Arc<Context>,
        socket: TcpStream,
    ) -> Result<bool, io::Error> {
        let stream = Box::new(socket);
        let result = self.process_tcp(session, context, stream).await;
        match result {
            Ok(_) => Ok(true),
            Err(err) => Err(err),
        }
    }

    async fn process_tcp(
        &self,
        session: Session,
        context: Arc<Context>,
        mut tcp_stream: Box<TcpStream>,
    ) -> Result<(), Error> {
        loop {
            tcp_stream = apply_keep_alive(tcp_stream)?;

            let mut request = read_http_request(&mut tcp_stream).await?;

            let mut default_port = 80u16;
            if request.uri().to_string().starts_with("https") {
                default_port = 443
            }
            let default: HeaderValue = HeaderValue::from_str("").unwrap();
            let mut host = request
                .headers()
                .get("Host")
                .unwrap_or(&default)
                .to_str()
                .unwrap_or("");

            if host == "" {
                host = request.uri().host().unwrap_or("");
            }
            tcp_stream = remove_keep_alive(tcp_stream)?;
            let destination = parse_host(host.to_string(), default_port)?;

            if request.method() == Method::CONNECT {
                return self
                    .handle_connect(session, tcp_stream, context, destination)
                    .await;
            }
            let mut proxy_connection = request
                .headers()
                .get("Proxy-Connection")
                .unwrap_or(&default)
                .to_str()
                .unwrap_or("");
            let keep_alive = proxy_connection == "keep-alive";
            let result = self
                .handle_other(
                    session.clone(),
                    request,
                    tcp_stream,
                    context.clone(),
                    destination,
                )
                .await;
            if let Ok((result, stream)) = result {
                tcp_stream = stream;
                if result && keep_alive {
                    continue;
                }
                break;
            } else {
                return Err(Error::new(ErrorKind::Other, "http handle other error"));
            }
        }
        Ok(())
    }

    async fn handle_other(
        &self,
        session: Session,
        mut request: Request<()>,
        mut tcp_stream: Box<TcpStream>,
        context: Arc<Context>,
        destination: NetLocation,
    ) -> Result<(bool, Box<TcpStream>), io::Error> {
        if request.uri().host().unwrap_or("") == "" {
            let response = get_http_response_400();
            let bytes = response_to_bytes(response);
            let _ = tcp_stream.write_all(&bytes).await;
            let _ = tcp_stream.flush().await;
            let _ = tcp_stream.shutdown().await;
            return Ok((false, tcp_stream));
        }
        let default: HeaderValue = HeaderValue::from_str("").unwrap();
        let host = request.uri().host().unwrap_or("").to_string();
        if host.len() > 0 {
            request
                .headers_mut()
                .insert("Host", HeaderValue::from_str(&host).unwrap());
        }
        request.headers_mut().remove("Proxy-Connection");
        request.headers_mut().remove("Proxy-Authenticate");
        request.headers_mut().remove("Proxy-Authorization");
        request.headers_mut().remove("TE");
        request.headers_mut().remove("Trailers");
        request.headers_mut().remove("Transfer-Encoding");
        request.headers_mut().remove("Upgrade");
        let mut connections = request
            .headers()
            .get("Connection")
            .unwrap_or(&default)
            .to_str()
            .unwrap_or("")
            .to_string();

        request.headers_mut().remove("Connection");

        if connections.len() > 0 {
            for h in connections.split(',') {
                let key = h.trim();
                request.headers_mut().remove(key);
            }
        }

        let user_agent = request
            .headers()
            .get("User-Agent")
            .unwrap_or(&default)
            .to_str()
            .unwrap_or("")
            .to_string();
        if user_agent == "" {
            request
                .headers_mut()
                .insert("User-Agent", HeaderValue::from_str("").unwrap());
        }
        let outbound_stream =
            Sniffer::route_tcp_no_sniff(session, context.clone(), Arc::new(destination.clone()))
                .await?;

        let (mut outbound_read, mut outbound_write) = tokio::io::split(outbound_stream);
        let (mut inbound_read, mut inbound_write) = tokio::io::split(tcp_stream);

        let (download_end_tx, download_end_rx) = tokio::sync::mpsc::channel::<()>(32);
        let (upload_end_tx, upload_end_rx) = tokio::sync::mpsc::channel::<()>(32);
        let context_clone = context.clone();
        let write_handler = tokio::spawn(async move {
            let mut keep_alive_response = false;
            let result =
                read_handle_1xx_http_response(&mut outbound_read, &mut inbound_write).await;

            if let Ok(mut response) = result {
                let content_length = response
                    .headers
                    .get("Content-Length")
                    .unwrap_or(&default)
                    .to_str()
                    .unwrap_or("")
                    .to_string();
                if content_length != "" && content_length != "0" {
                    response.headers.insert(
                        HeaderName::from_lowercase(b"proxy-connection").unwrap(),
                        HeaderValue::from_static("keep-alive"),
                    );
                    response.headers.insert(
                        HeaderName::from_lowercase(b"connection").unwrap(),
                        HeaderValue::from_static("keep-alive"),
                    );
                    response.headers.insert(
                        HeaderName::from_lowercase(b"keep-alive").unwrap(),
                        HeaderValue::from_static("timeout=60"),
                    );
                    keep_alive_response = true;
                }
                let bytes = response_to_bytes(response);
                let _ = inbound_write.write(&bytes).await;
            } else {
                let response = get_http_response_503();
                let bytes = response_to_bytes(response);
                let _ = inbound_write.write_all(&bytes).await;
                let _ = inbound_write.flush().await;
            }
            let _count = copy(
                upload_end_rx,
                context_clone,
                &mut outbound_read,
                &mut inbound_write,
            )
            .await;
            let _ = download_end_tx.send(()).await;

            return (keep_alive_response, inbound_write);
        });
        let context_clone = context.clone();
        let read_handler = tokio::spawn(async move {
            let bytes = request_to_bytes(request);
            let _ = outbound_write.write(&bytes).await;
            let _count = copy(
                download_end_rx,
                context_clone,
                &mut inbound_read,
                &mut outbound_write,
            )
            .await;
            let _ = upload_end_tx.send(()).await;
            return inbound_read;
        });

        let read_half = read_handler.await?;
        let (keep_alive_response, write_half) = write_handler.await?;

        Ok((keep_alive_response, read_half.unsplit(write_half)))
    }

    async fn handle_connect(
        &self,
        session: Session,
        mut tcp_stream: Box<TcpStream>,
        context: Arc<Context>,
        destination: NetLocation,
    ) -> Result<(), io::Error> {
        tcp_stream
            .write_all("HTTP/1.1 200 Connection established\r\n\r\n".as_bytes())
            .await?;

        let outbound_stream = Sniffer::route_tcp(
            session,
            context.clone(),
            Arc::new(destination.clone()),
            &mut tcp_stream,
        )
        .await?;
        let (outbound_read, outbound_write) = tokio::io::split(outbound_stream);
        let (inbound_read, inbound_write) = tokio::io::split(tcp_stream);

        let (download_end_tx, download_end_rx) = tokio::sync::mpsc::channel::<()>(32);
        let (upload_end_tx, upload_end_rx) = tokio::sync::mpsc::channel::<()>(32);

        let context_clone = context.clone();
        let write_handler = tokio::spawn(async move {
            let mut outbound_read = outbound_read;
            let mut inbound_write = inbound_write;
            let _count = copy(
                upload_end_rx,
                context_clone,
                &mut outbound_read,
                &mut inbound_write,
            )
            .await;
            let _ = download_end_tx.send(()).await;
        });

        let context_clone = context.clone();
        let read_handler = tokio::spawn(async move {
            let mut inbound_read = inbound_read;
            let mut outbound_write = outbound_write;
            let _count = copy(
                download_end_rx,
                context_clone,
                &mut inbound_read,
                &mut outbound_write,
            )
            .await;
            let _ = upload_end_tx.send(()).await;
        });

        let mut handles = Vec::new();
        handles.push(read_handler);
        handles.push(write_handler);
        join_all(handles).await;
        Ok(())
    }
}

#[async_trait]
impl InboundTcp for HttpInbound {
    async fn start(self: Box<Self>, context: Arc<Context>) -> Result<(), Error> {
        let result = self.net_location.to_socket_addr(context.clone()).await;
        let socket_addr = match result {
            Ok(socket_addr) => socket_addr,
            Err(err) => {
                error!("{}", err);
                return Err(Error::from(err));
            }
        };
        let socks_clone = Arc::new(self);
        let handler_tcp = tokio::spawn(async move {
            let result = TcpListener::bind(socket_addr).await;
            match result {
                Ok(listener) => {
                    let socket_addr = match listener.local_addr() {
                        Ok(ip) => ip,
                        Err(err) => {
                            error!("{}", err);
                            return;
                        }
                    };
                    info!(
                        "listen on ip address {} and port number {}",
                        socket_addr.ip(),
                        socket_addr.port()
                    );
                    loop {
                        let (socket, _) = match listener.accept().await {
                            Ok(result) => result,
                            Err(err) => {
                                warn!("{}", err);
                                continue;
                            }
                        };
                        if !context.can_accept() {
                            warn!("platform reject accept new connection.");
                            continue;
                        }
                        let session_manager = context.get_session_manager().add_new_session().await;
                        let session_manager = match session_manager {
                            Ok(session_manager) => Arc::new(session_manager),
                            Err(err) => {
                                warn!("{}", err);
                                continue;
                            }
                        };

                        let session = Session::new(
                            session_manager,
                            InboundProtocol::HTTP,
                            Network::Tcp,
                            socket.local_addr().ok(),
                            socket.peer_addr().ok(),
                        );

                        let socks_clone = socks_clone.clone();
                        let context_clone = context.clone();
                        tokio::spawn(async move {
                            let _ = socks_clone
                                .process_socket(session, context_clone, socket)
                                .await;
                        });
                    }
                }
                Err(err) => {
                    error!("bind tcp listener error: {}", err);
                }
            }
        });
        let _ = handler_tcp.await;
        Ok(())
    }
}

#[derive(Debug)]
struct HttpResponse {
    version: String,
    status_code: u16,
    reason_phrase: String,
    headers: HashMap<HeaderName, HeaderValue>,
}
