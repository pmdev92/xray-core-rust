use crate::common::constants::MAX_UDP_BUFFER_CAPACITY;
use crate::common::net_location::NetLocation;
use crate::outbound::quinn_tuic::protocol::dissociate::Dissociate;
use crate::outbound::quinn_tuic::protocol::enums::UdpRelayMode;
use crate::outbound::quinn_tuic::protocol::packet::{Packet, PacketDeFragmenter};
use crate::outbound::quinn_tuic::protocol::ToCommand;
use crate::outbound::quinn_tuic::to_io_error;
use bytes::Bytes;
use log::{error, info, warn};
use quinn::ReadError;
use std::collections::{HashMap, VecDeque};
use std::io;
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, AtomicU32};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Instant;
use tokio::io::AsyncReadExt;

pub(crate) struct UdpApi {
    connection: quinn::Connection,
    udp_sessions: Arc<tokio::sync::Mutex<HashMap<u16, UdpSession>>>,
    mode: UdpRelayMode,
}

struct UdpSession {
    pub recv_tx: tokio::sync::mpsc::Sender<bytes::Bytes>,
    pub defragger: PacketDeFragmenter,
}
impl UdpSession {
    pub fn feed(&mut self, pkt: Packet) -> Option<Packet> {
        self.defragger.feed(pkt)
    }

    fn new(recv_tx: tokio::sync::mpsc::Sender<bytes::Bytes>) -> UdpSession {
        Self {
            recv_tx,
            defragger: PacketDeFragmenter::default(),
        }
    }

    pub fn free_expired(&mut self) {
        self.defragger.free_expired()
    }
}

impl UdpApi {
    pub fn new(
        connection: quinn::Connection,
        mode: UdpRelayMode,
        last_server_heartbeat_timestamp: Arc<tokio::sync::Mutex<Instant>>,
    ) -> Arc<Self> {
        let api = Arc::new(UdpApi {
            connection,
            udp_sessions: Arc::new(Default::default()),
            mode,
        });
        api.clone().spawn_receiver(last_server_heartbeat_timestamp);
        api
    }

    fn spawn_receiver(
        self: Arc<Self>,
        last_server_heartbeat_timestamp: Arc<tokio::sync::Mutex<Instant>>,
    ) {
        match self.mode {
            UdpRelayMode::Native => {
                tokio::spawn(
                    self.clone()
                        .run_receiver_native(last_server_heartbeat_timestamp),
                );
            }
            UdpRelayMode::Quic => {
                tokio::spawn(
                    self.clone()
                        .run_receiver_native(last_server_heartbeat_timestamp),
                );
                tokio::spawn(self.clone().run_receiver_quic());
            }
        }
    }

    async fn run_receiver_native(
        self: Arc<Self>,
        last_server_heartbeat_timestamp: Arc<tokio::sync::Mutex<Instant>>,
    ) {
        let err = loop {
            match self.connection.read_datagram().await {
                Ok(bytes) => {
                    let cloned_time = last_server_heartbeat_timestamp.clone();
                    if bytes.as_ref() == [5, 4] {
                        tokio::spawn(async move {
                            *cloned_time.as_ref().lock().await = Instant::now();
                        });
                        continue;
                    }
                    self.clone().received_bytes(bytes).await
                }
                Err(e) => {
                    warn!("tuic read datagram error: {}", e);
                    break e;
                }
            }
        };
        warn!("tuic connection error: {:?}", err);
        warn!("tuic udp read loop closed");
    }

    async fn run_receiver_quic(self: Arc<Self>) {
        let err = loop {
            let stream = self.connection.accept_uni().await;
            let mut stream = match stream {
                Err(e) => break to_io_error(format!("{:?}", e)),
                Ok(stream) => stream,
            };

            let recv_result = stream.read_to_end(2000).await;

            match recv_result {
                Ok(recv_result) => {
                    let bytes = Bytes::from(recv_result);
                    self.clone().received_bytes(bytes).await;
                }
                Err(e) => {
                    warn!("tuic read datagram error: {}", e);
                    break to_io_error(format!("{:?}", e));
                }
            }
        };
        warn!("tuic connection error: {:?}", err);
        warn!("tuic udp read loop closed");
    }

    pub async fn received_bytes(self: Arc<Self>, bytes: bytes::Bytes) {
        let pkt = Packet::decode(bytes);
        let pkt = match pkt {
            Ok(pkt) => pkt,
            Err(error) => {
                warn!("tuic udp packet decode error: {:?}", error);
                return;
            }
        };
        let assoc_id = pkt.assoc_id;
        let mut udp_sessions = self.udp_sessions.lock().await;
        match udp_sessions.get_mut(&assoc_id) {
            Some(udp_session) => {
                if let Some(pkt) = udp_session.feed(pkt) {
                    let _ = udp_session.recv_tx.send(bytes::Bytes::from(pkt.data)).await;
                }
            }
            _ => {
                warn!("tuic udp session not found: {}", assoc_id);
            }
        }
        for udp_session in udp_sessions.values_mut() {
            udp_session.free_expired();
        }
    }

    pub async fn new_udp_session(
        self: Arc<Self>,
        send_rx: tokio::sync::mpsc::Receiver<bytes::Bytes>,
        recv_tx: tokio::sync::mpsc::Sender<bytes::Bytes>,
        assoc_id: u16,
        address: Arc<NetLocation>,
    ) {
        let udp_sessions = self.udp_sessions.clone();
        udp_sessions
            .lock()
            .await
            .insert(assoc_id, UdpSession::new(recv_tx));
        tokio::spawn(async move {
            // capture vars
            let mut send_rx = send_rx;
            // use u32 to avoid overflow
            let next_pkt_id = AtomicU32::new(0);
            while let Some(bytes) = send_rx.recv().await {
                let packet_id = next_pkt_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let packet_id = (packet_id % u16::MAX as u32) as u16;
                let packet = Packet::new(assoc_id, packet_id, address.clone(), bytes.to_vec());
                let mut fragments = packet.fragment(packet_id, 1300);
                for fragment in fragments {
                    if let Err(e) = self.send(&fragment).await {
                        warn!("error in outgoing of tuic ,msg: {:?}", e);
                        break;
                    }
                }
            }
            info!("tuic closing UDP session {} {}", assoc_id, address);
            let _ = udp_sessions.lock().await.remove(&assoc_id);
        });
    }

    pub(crate) async fn dissociate(&self, dissociate: Dissociate) -> Result<(), io::Error> {
        let result = self
            .connection
            .send_datagram_wait(dissociate.to_command_bytes())
            .await;
        match result {
            Ok(_) => Ok(()),
            Err(error) => Err(io::Error::new(io::ErrorKind::Other, format!("{}", error))),
        }
    }

    pub(crate) async fn send(&self, udp_message: &Packet) -> Result<(), io::Error> {
        match self.mode {
            UdpRelayMode::Native => {
                let result = self.send_native(udp_message).await;
                result
            }
            UdpRelayMode::Quic => {
                let result = self.send_quic(udp_message).await;
                result
            }
        }
    }
    async fn send_native(&self, udp_message: &Packet) -> Result<(), io::Error> {
        let bytes = udp_message.encode();
        let result = self.connection.send_datagram_wait(bytes).await;
        match result {
            Ok(_) => Ok(()),
            Err(error) => Err(io::Error::new(io::ErrorKind::Other, format!("{}", error))),
        }
    }
    async fn send_quic(&self, udp_message: &Packet) -> Result<(), io::Error> {
        let connection = self.connection.clone();
        let result = connection.open_uni().await;
        match result {
            Ok(mut stream) => {
                let mut bytes = udp_message.encode();

                let result = stream.write(&bytes.to_vec()).await;
                match result {
                    Ok(_) => Ok(()),
                    Err(error) => Err(io::Error::new(io::ErrorKind::Other, format!("{}", error))),
                }
            }
            Err(error) => Err(io::Error::new(io::ErrorKind::Other, format!("{}", error))),
        }
    }
}
