use crate::common::constants::MAX_UDP_BUFFER_CAPACITY;
use crate::common::net_location::NetLocation;
use crate::core::context::Context;
use crate::core::io::AsyncXrayUdpStream;
use crate::core::router::Network;
use crate::core::session::Session;
use crate::core::sniffer::Sniffer;
use crate::inbound::socks::udp::{Sock5UdpStream, Socks5UDPCodec};
use crate::inbound::InboundProtocol;
use bytes::Bytes;
use futures::{Sink, Stream};
use futures_util::stream::SplitSink;
use futures_util::{SinkExt, StreamExt};
use log::{error, trace, warn};
use std::collections::HashMap;
use std::fmt::Debug;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncWriteExt, WriteHalf};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use tokio_util::udp::UdpFramed;
pub type AnyInboundDatagram = Box<dyn InboundDatagram>;
pub trait InboundDatagram:
    Stream<Item = NatUdpPacket> + Sink<NatUdpPacket, Error = io::Error> + Send + Sync + Unpin + Debug
{
}
#[derive(Clone, Debug)]
pub struct NatUdpPacket {
    pub(crate) data: Vec<u8>,
    pub(crate) src_addr: NetLocation,
    pub(crate) dst_addr: NetLocation,
}

impl NatUdpPacket {
    pub(crate) fn new(data: Vec<u8>, src_addr: NetLocation, dst_addr: NetLocation) -> Self {
        Self {
            data,
            src_addr,
            dst_addr,
        }
    }
}

pub(crate) struct NatManager {
    local_addr: SocketAddr,
    connections: HashMap<Arc<NetLocation>, SplitSink<Box<dyn AsyncXrayUdpStream>, Bytes>>,
    tasks: Vec<JoinHandle<()>>,
    socket: Sock5UdpStream,
    timeout_sender: Sender<()>,
    session: Session,
    context: Arc<Context>,
    timeout: u64,
}

impl NatManager {
    pub fn new(
        context: Arc<Context>,
        session: Session,
        socket: UdpSocket,
        local_addr: SocketAddr,
        timeout_sender: Sender<()>,
        timeout: Option<u64>,
    ) -> Self {
        let framed = UdpFramed::new(socket, Socks5UDPCodec);
        let socket = Sock5UdpStream {
            socket: framed,
            context: context.clone(),
        };
        Self {
            local_addr,
            socket,
            timeout_sender,
            connections: Default::default(),
            session,
            context,
            tasks: vec![],
            timeout: timeout.unwrap_or(30),
        }
    }

    pub async fn start(mut self) {
        let (mut local_writer, mut local_reader) = self.socket.split();
        let (remote_receiver_writer, mut remote_receiver_reader) =
            tokio::sync::mpsc::channel::<NatUdpPacket>(32);
        let t1 = tokio::spawn(async move {
            while let Some(packet) = remote_receiver_reader.recv().await {
                match local_writer.send(packet).await {
                    Ok(_) => {}
                    Err(err) => {
                        error!(
                            "{} failed to send packet to local: {}",
                            self.local_addr, err
                        );
                    }
                }
            }
            trace!(
                "Nat UDP session remote -> local finished for {}",
                self.local_addr,
            );
        });
        while let Ok(packet) = timeout(Duration::from_secs(self.timeout), local_reader.next()).await
        {
            if let Some(mut packet) = packet {
                let target_location = Arc::new(packet.dst_addr);
                let outer = self.connections.get_mut(&target_location);
                match outer {
                    Some(outbound_write) => {
                        let _ = outbound_write.send(bytes::Bytes::from(packet.data)).await;
                        let result = outbound_write.flush().await;
                        match result {
                            Ok(_) => {}
                            Err(err) => {
                                warn!("{} socks udp write error {}", self.local_addr, err);
                                self.connections.remove(&target_location);
                            }
                        }
                    }
                    None => {
                        let session = Session::new(
                            self.session.get_new_session(),
                            InboundProtocol::SOCKS,
                            Network::Udp,
                            packet.src_addr.to_socket_addr_native().ok(),
                            target_location.to_socket_addr_native().ok(),
                        );
                        let outbound = Sniffer::route_udp(
                            session,
                            self.context.clone(),
                            target_location.clone(),
                            &packet.data,
                        )
                        .await;
                        let stream = match outbound {
                            Ok(stream) => stream,
                            Err(err) => {
                                warn!("{}", err);
                                return;
                            }
                        };
                        let local = packet.src_addr.clone();
                        let dst = target_location.clone();
                        let (mut outbound_write, mut outbound_read) = stream.split();
                        let remote_receiver_writer_clone = remote_receiver_writer.clone();
                        let task = tokio::spawn(async move {
                            loop {
                                let result: Option<Bytes> = outbound_read.next().await;
                                match result {
                                    Some(read) => {
                                        let packet = NatUdpPacket {
                                            data: read.to_vec(),
                                            src_addr: local.clone(),
                                            dst_addr: dst.as_ref().clone(),
                                        };
                                        let result =
                                            remote_receiver_writer_clone.send(packet).await;
                                        match result {
                                            Ok(_) => {}
                                            Err(err) => {
                                                warn!(
                                                    "{} socks udp read error {}",
                                                    self.local_addr, err
                                                );
                                                break;
                                            }
                                        }
                                    }
                                    None => {
                                        break;
                                    }
                                }
                            }
                        });
                        let result = outbound_write.send(bytes::Bytes::from(packet.data)).await;
                        match result {
                            Ok(_) => {}
                            Err(err) => {
                                warn!("{} socks udp write error {}", self.local_addr, err);
                            }
                        }
                        self.connections.insert(target_location, outbound_write);
                        self.tasks.push(task);
                    }
                }
            }
        }
        let _ = self.timeout_sender.send(()).await;
        for handler in self.tasks {
            handler.abort();
        }
        drop(remote_receiver_writer);
        let _ = t1.await;
        trace!(
            "Nat UDP session local -> remote finished for {}",
            self.local_addr,
        );
    }
}
