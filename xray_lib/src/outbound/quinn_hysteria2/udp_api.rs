use crate::outbound::quinn_hysteria2::udp::{UDPMessage, UDPMessageDeFragmenter};
use blake3::IncrementCounter::No;
use bytes::BytesMut;
use log::{error, info, warn};
use std::collections::{HashMap, VecDeque};
use std::io;
use std::io::Error;
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, AtomicU32};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use uuid::Bytes;

pub(crate) struct UdpApi {
    connection: quinn::Connection,
    udp_sessions: Arc<tokio::sync::Mutex<HashMap<u32, UdpSession>>>,
    error: Arc<Mutex<Option<io::Error>>>,
}
struct UdpSession {
    pub recv_tx: tokio::sync::mpsc::Sender<bytes::Bytes>,
    pub defragger: UDPMessageDeFragmenter,
}
impl UdpSession {
    pub fn feed(&mut self, pkt: UDPMessage) -> Option<UDPMessage> {
        self.defragger.feed(pkt)
    }
}

impl UdpSession {
    fn new(recv_tx: tokio::sync::mpsc::Sender<bytes::Bytes>) -> UdpSession {
        Self {
            recv_tx,
            defragger: UDPMessageDeFragmenter::default(),
        }
    }
}

impl UdpApi {
    pub fn new(connection: quinn::Connection) -> Arc<Self> {
        let api = Arc::new(UdpApi {
            connection,
            udp_sessions: Arc::new(Default::default()),
            error: Arc::new(Mutex::new(None)),
        });
        tokio::spawn(Self::spawn_receiver(api.clone()));
        api
    }

    async fn spawn_receiver(self: Arc<Self>) {
        let err = loop {
            tokio::select! {
                res = self.connection.read_datagram() => {
                    match res {
                        Ok(bytes) => self.clone().received_bytes(bytes).await,
                        Err(e) => {
                            error!("hysteria2 read datagram error: {}", e);
                            break e;
                        }
                    }
                }
            }
        };
        warn!("hysteria2 connection error: {:?}", err);
    }

    pub async fn received_bytes(self: Arc<Self>, bytes: bytes::Bytes) {
        let pkt = UDPMessage::decode(bytes);
        let pkt = match pkt {
            Ok(pkt) => pkt,
            Err(error) => {
                warn!("hysteria2 udp packet decode error: {:?}", error);
                return;
            }
        };
        let session_id = pkt.session_id;
        let mut udp_sessions = self.udp_sessions.lock().await;
        match udp_sessions.get_mut(&session_id) {
            Some(udp_session) => {
                if let Some(pkt) = udp_session.feed(pkt) {
                    let _ = udp_session.recv_tx.send(bytes::Bytes::from(pkt.data)).await;
                }
            }
            _ => {
                warn!("hysteria2 udp session not found: {}", session_id);
            }
        }
    }
}

impl UdpApi {
    pub async fn new_udp_session(
        self: Arc<Self>,
        send_rx: tokio::sync::mpsc::Receiver<bytes::Bytes>,
        recv_tx: tokio::sync::mpsc::Sender<bytes::Bytes>,
        session_id: u32,
        address: String,
    ) {
        let udp_sessions = self.udp_sessions.clone();
        udp_sessions
            .lock()
            .await
            .insert(session_id, UdpSession::new(recv_tx));
        tokio::spawn(async move {
            // capture vars
            let mut send_rx = send_rx;
            // use u32 to avoid overflow
            let next_pkt_id = AtomicU32::new(0);
            while let Some(bytes) = send_rx.recv().await {
                let packet_id = next_pkt_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let packet_id = (packet_id % u16::MAX as u32) as u16;
                let udp_message = UDPMessage::new(session_id, packet_id, address.clone(), bytes);
                let mut fragments = udp_message.fragment(1000);
                for fragment in fragments {
                    if let Err(e) = self.send(&fragment).await {
                        warn!("error in outgoing of Hysteria2 ,msg: {:?}", e);
                        break;
                    }
                }
            }
            info!("hysteria2 closing UDP session {}", session_id);
            let _ = udp_sessions.lock().await.remove(&session_id);
        });
    }

    async fn send(&self, udp_message: &UDPMessage) -> Result<(), io::Error> {
        {
            let mut error = self.error.lock();
            match error {
                Ok(error) => {
                    if let Some(error) = error.deref() {
                        return Err(io::Error::new(io::ErrorKind::Other, format!("{}", error)));
                    }
                }
                Err(error) => {
                    return Err(io::Error::new(io::ErrorKind::Other, format!("{}", error)));
                }
            };
        }
        let bytes = udp_message.encode();
        let result = self.connection.send_datagram_wait(bytes).await;
        match result {
            Ok(_) => Ok(()),
            Err(error) => Err(io::Error::new(io::ErrorKind::Other, format!("{}", error))),
        }
    }
}
