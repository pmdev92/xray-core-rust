use crate::common::buffer_manager::BufferManager;
use crate::common::net_location::NetLocation;
use crate::common::session_manager::SessionManager;
use crate::config::config::MemoryConfig;
use crate::core::dispatcher::Dispatcher;
use crate::core::streams::{XrayTcpStream, XrayUdpStream};
use log::{debug, error};
use quinn::default_runtime;
use quinn_proto::EndpointConfig;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::io;
use std::io::Error;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::ops::Deref;
#[cfg(target_os = "android")]
use std::os::fd::AsRawFd;
use std::sync::{Arc, MutexGuard};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tokio::sync::{mpsc, Mutex};
use tokio::time::Instant;

use crate::common::udp::UdpConnection;
use crate::core::io::{AsyncXrayTcpStream, AsyncXrayUdpStream};
use crate::ContextPlatform;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use quinn::{
    udp::{RecvMeta, Transmit}, AsyncUdpSocket,
    TokioRuntime,
};
use rand::Rng;
use std::fmt::{Debug, Formatter};
use std::pin::Pin;
use std::{
    io::IoSliceMut,
    ops::DerefMut,
    task::{Context as AAA, Poll},
};
use tokio::io::AsyncWriteExt;

pub struct Context {
    con_manager: Arc<SessionManager>,
    buffer_manager: Arc<BufferManager>,
    dispatcher: Arc<Dispatcher>,
    platform: Option<Box<dyn ContextPlatform>>,
}

impl Context {
    pub fn new(
        memory_config: &Option<MemoryConfig>,
        dispatcher: Dispatcher,
        platform: Option<Box<dyn ContextPlatform>>,
    ) -> Context {
        let mut limit = 200;
        if let Some(memory_config) = memory_config {
            limit = memory_config.max;
        }
        let buffer_manager = BufferManager::new(limit);
        let con_manager = SessionManager::new(limit);
        Self {
            con_manager,
            buffer_manager,
            dispatcher: Arc::new(dispatcher),
            platform,
        }
    }

    pub fn get_dispatcher(&self) -> Arc<Dispatcher> {
        self.dispatcher.clone()
    }
    pub fn get_buffer_manager(&self) -> Arc<BufferManager> {
        self.buffer_manager.clone()
    }
    pub fn get_session_manager(&self) -> Arc<SessionManager> {
        self.con_manager.clone()
    }

    pub fn can_accept(&self) -> bool {
        if let Some(platform) = &self.platform {
            return platform.can_accept();
        }
        true
    }
    fn protect(&self, id: u64) {
        if let Some(platform) = &self.platform {
            platform.android_protect_fd(id)
        }
    }

    pub async fn destroy(&self) {
        self.dispatcher.destroy().await;
    }

    pub async fn connect_tokio_tcp(&self, address: SocketAddr) -> Result<TcpStream, Error> {
        let socket = match address {
            SocketAddr::V4(_) => TcpSocket::new_v4()?,
            SocketAddr::V6(_) => TcpSocket::new_v6()?,
        };

        #[cfg(target_os = "android")]
        {
            let fd = socket.as_raw_fd();
            self.protect(fd as u64);
        }

        let stream = socket.connect(address).await?;
        Ok(stream)
    }
    pub async fn bind_endpoint(
        self: &Arc<Self>,
        address: SocketAddr,
    ) -> Result<quinn::Endpoint, Error> {
        let socket = Socket::new(
            Domain::for_address(address),
            Type::DGRAM,
            Some(Protocol::UDP),
        )?;
        if address.is_ipv6() {
            if let Err(e) = socket.set_only_v6(false) {
                debug!("{:?} unable to make socket dual-stack", e);
            }
        }
        #[cfg(target_os = "android")]
        {
            let fd = socket.as_raw_fd();
            self.protect(fd as u64);
        }
        socket.set_nonblocking(true)?;
        let tokio_udp_socket = UdpSocket::from_std(socket.into())?;
        let _ = tokio_udp_socket.connect(address).await?;
        let runtime = default_runtime().ok_or_else(|| Error::other("no async runtime found"))?;
        quinn::Endpoint::new_with_abstract_socket(
            EndpointConfig::default(),
            None,
            runtime.wrap_udp_socket(tokio_udp_socket.into_std()?)?,
            runtime,
        )
    }

    pub async fn bind_sdt_udp(&self, address: SocketAddr) -> Result<std::net::UdpSocket, Error> {
        let socket = Socket::new(
            Domain::for_address(address),
            Type::DGRAM,
            Some(Protocol::UDP),
        )?;
        if address.is_ipv6() {
            if let Err(e) = socket.set_only_v6(false) {
                debug!("{:?} unable to make socket dual-stack", e);
            }
        }
        #[cfg(target_os = "android")]
        {
            let fd = socket.as_raw_fd();
            self.protect(fd as u64);
        }
        socket.bind(&address.into())?;
        socket.set_nonblocking(true)?;
        Ok(socket.into())
    }
    pub async fn bind_tokio_udp(&self, address: SocketAddr) -> Result<UdpSocket, Error> {
        let socket = Socket::new(
            Domain::for_address(address),
            Type::DGRAM,
            Some(Protocol::UDP),
        )?;
        if address.is_ipv6() {
            if let Err(e) = socket.set_only_v6(false) {
                debug!("{:?} unable to make socket dual-stack", e);
            }
        }
        #[cfg(target_os = "android")]
        {
            let fd = socket.as_raw_fd();
            self.protect(fd as u64);
        }
        socket.bind(&address.into())?;
        socket.set_nonblocking(true)?;
        Ok(UdpSocket::from_std(socket.into())?)
    }

    pub async fn dial_tcp(
        self: &Arc<Self>,
        detour: Option<String>,
        net_location: Arc<NetLocation>,
    ) -> Result<Box<dyn AsyncXrayTcpStream>, Error> {
        if let Some(detour) = &detour {
            let dispatcher = self.get_dispatcher();
            let item = dispatcher.get_with_tag(detour.clone()).await;
            if let Some(item) = item {
                return item
                    .outbound
                    .dial_tcp(self.clone(), item.detour, net_location)
                    .await;
            }
        }

        let dialer_stream = XrayTcpStream::new(net_location, self.clone()).await?;
        Ok(Box::new(dialer_stream))
    }

    pub async fn dial_udp(
        self: &Arc<Self>,
        detour: Option<String>,
        net_location: Arc<NetLocation>,
    ) -> Result<Box<dyn AsyncXrayUdpStream>, Error> {
        if let Some(detour) = &detour {
            let dispatcher = self.get_dispatcher();
            let item = dispatcher.get_with_tag(detour.clone()).await;
            if let Some(item) = item {
                return item
                    .outbound
                    .dial_udp(self.clone(), item.detour, net_location)
                    .await;
            }
        }
        let dialer_stream = XrayUdpStream::new(net_location, self.clone()).await?;
        Ok(Box::new(dialer_stream))
    }

    pub async fn dial_udp_proxy(
        self: &Arc<Self>,
        detour: Option<String>,
        net_location: Arc<NetLocation>,
    ) -> Result<SocketAddr, Error> {
        if let None = &detour {
            return Ok(net_location.to_socket_addr(self.clone()).await?);
        }
        let context_clone = self.clone();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let local_addr = socket.local_addr()?;
        tokio::spawn(async move {
            let connections: Arc<Mutex<HashMap<SocketAddr, UdpConnection>>> =
                Arc::new(Mutex::new(HashMap::new()));
            let mut buf = [0u8; 1500];
            loop {
                let result = socket.recv_from(&mut buf).await;
                let (len, addr) = match result {
                    Ok(result) => result,
                    Err(_) => {
                        continue;
                    }
                };
                let data = bytes::Bytes::from(buf[..len].to_vec());
                let socket_clone = socket.clone();
                let connections_clone = connections.clone();
                let detour_clone = detour.clone();
                let net_location_clone = net_location.clone();
                let context_clone_clone = context_clone.clone();
                tokio::spawn(async move {
                    let connections_clone_1 = connections_clone.clone();
                    let connections_clone_2 = connections_clone.clone();
                    let connections_for_monitor = connections_clone.clone();
                    let mut connections_guard = connections_clone.lock().await;
                    if let Some(udp_connection) = connections_guard.get(&addr) {
                        let _ = udp_connection.get_sender_as_mut().send(data).await;
                    } else {
                        let stream = context_clone_clone
                            .clone()
                            .dial_udp(detour_clone, net_location_clone)
                            .await;
                        let stream = match stream {
                            Ok(stream) => stream,
                            Err(_) => return,
                        };
                        let (mut outbound_write, mut outbound_read) = stream.split();
                        let (tx, mut rx) = mpsc::channel::<Bytes>(100);
                        if let Err(_) = outbound_write.send(data).await {
                            return;
                        }
                        let last_used = Arc::new(Mutex::new(Instant::now()));
                        connections_guard
                            .insert(addr, UdpConnection::new(tx.clone(), last_used.clone()));
                        tokio::spawn(async move {
                            loop {
                                tokio::time::sleep(Duration::from_secs(10)).await;
                                {
                                    let mut guard = connections_for_monitor.lock().await;
                                    let item = guard.get(&addr);
                                    if let Some(item) = item {
                                        let last = item.get_last_used();
                                        let last = last.lock().await;
                                        let now = Instant::now();
                                        let duration = now.duration_since(*last);
                                        if duration > Duration::from_secs(180) {
                                            guard.remove(&addr);
                                        }
                                    }
                                }
                            }
                        });
                        let last_used_clone = last_used.clone();
                        // TCP -> UDP
                        tokio::spawn(async move {
                            loop {
                                let data: Option<Bytes> = outbound_read.next().await;
                                match data {
                                    None => {
                                        let mut guard = connections_clone_1.lock().await;
                                        guard.remove(&addr);
                                        break;
                                    }
                                    Some(bytes) => {
                                        {
                                            let mut t = last_used_clone.lock().await;
                                            *t = Instant::now();
                                        }
                                        let _ = socket_clone.send_to(&bytes, addr).await;
                                    }
                                }
                            }
                        });
                        let last_used_clone = last_used.clone();
                        // UDP -> TCP
                        tokio::spawn(async move {
                            while let Some(msg) = rx.recv().await {
                                if let Err(_) = outbound_write.send(msg).await {
                                    let mut guard = connections_clone_2.lock().await;
                                    guard.remove(&addr);
                                    break;
                                }
                                {
                                    let mut t = last_used_clone.lock().await;
                                    *t = Instant::now();
                                }
                            }
                        });
                    }
                });
            }
        });
        Ok(local_addr)
    }
}
