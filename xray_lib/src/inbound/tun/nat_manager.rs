// use std::collections::HashMap;
// use std::fmt;
// use std::net::SocketAddr;
// use std::sync::Arc;
// use std::time::{Duration, Instant};
//
// use crate::common::constants::MAX_UDP_BUFFER_CAPACITY;
// use crate::common::net_location::NetLocation;
// use Arc<crate::core::context::Context>;
// use crate::core::router::Network;
// use crate::core::sniffer::Sniffer;
// use futures::future::{abortable, BoxFuture};
// use log::{debug, error, trace, warn};
// use tokio::io::{AsyncReadExt, AsyncWriteExt};
// use tokio::sync::{
//     mpsc::{self, Sender},
//     oneshot, Mutex, MutexGuard,
// };
//
// type SessionMap = HashMap<UdpSession, (Sender<UdpPacket>, oneshot::Sender<bool>, Instant)>;
//
// pub struct NatManager {
//     sessions: Arc<Mutex<SessionMap>>,
//     context: Context,
//     timeout_check_task: Mutex<Option<BoxFuture<'static, ()>>>,
// }
//
// impl NatManager {
//     pub fn new(context: Context) -> Self {
//         let sessions: Arc<Mutex<SessionMap>> = Arc::new(Mutex::new(HashMap::new()));
//         let sessions2 = sessions.clone();
//
//         // The task is lazy, will not run until any sessions added.
//         let timeout_check_task: BoxFuture<'static, ()> = Box::pin(async move {
//             loop {
//                 let mut sessions = sessions2.lock().await;
//                 let n_total = sessions.len();
//                 let now = Instant::now();
//                 let mut to_be_remove = Vec::new();
//                 for (key, val) in sessions.iter() {
//                     //*option::UDP_SESSION_TIMEOUT => 30
//                     if now.duration_since(val.2).as_secs() >= 30 {
//                         to_be_remove.push(key.to_owned());
//                     }
//                 }
//                 for key in to_be_remove.iter() {
//                     if let Some(sess) = sessions.remove(key) {
//                         // Sends a signal to abort downlink task, uplink task will
//                         // end automatically when we drop the channel's tx side upon
//                         // session removal.
//                         if let Err(e) = sess.1.send(true) {
//                             debug!("failed to send abort signal on session {:?}: {}", key, e);
//                         }
//                         debug!("udp session {:?} ended", key);
//                     }
//                 }
//                 drop(to_be_remove); // drop explicitly
//                 let n_remaining = sessions.len();
//                 let n_removed = n_total - n_remaining;
//                 drop(sessions); // release the lock
//                 if n_removed > 0 {
//                     debug!(
//                         "removed {} nat sessions, remaining {} sessions",
//                         n_removed, n_remaining
//                     );
//                 }
//                 //   *option::UDP_SESSION_TIMEOUT_CHECK_INTERVAL, => 10
//                 tokio::time::sleep(Duration::from_secs(10)).await;
//             }
//         });
//
//         NatManager {
//             sessions,
//             context,
//             timeout_check_task: Mutex::new(Some(timeout_check_task)),
//         }
//     }
//
//     fn _send(&self, guard: &mut MutexGuard<'_, SessionMap>, session: &UdpSession, pkt: UdpPacket) {
//         if let Some(sess) = guard.get_mut(session) {
//             if let Err(err) = sess.0.try_send(pkt) {
//                 trace!("send uplink packet failed {}", err);
//             }
//             sess.2 = Instant::now();
//         } else {
//             error!("no nat association found");
//         }
//     }
//
//     pub async fn send<'a>(&self, client_ch_tx: &Sender<UdpPacket>, udp_packet: UdpPacket) {
//         let session = UdpSession {
//             source: udp_packet.src_addr.clone(),
//             destination: udp_packet.dst_addr.clone(),
//         };
//         let mut guard = self.sessions.lock().await;
//         if guard.contains_key(&session) {
//             self._send(&mut guard, &session, udp_packet);
//             return;
//         }
//         self.add_session(session, &udp_packet, client_ch_tx.clone(), &mut guard)
//             .await;
//         self._send(&mut guard, &session, udp_packet);
//
//         drop(guard);
//     }
//
//     pub async fn add_session<'a>(
//         &self,
//         session: UdpSession,
//         udp_packet: &UdpPacket,
//         client_ch_tx: Sender<UdpPacket>,
//         guard: &mut MutexGuard<'a, SessionMap>,
//     ) {
//         let data = &udp_packet.data;
//
//         // Runs the lazy task for session cleanup job, this task will run only once.
//         if let Some(task) = self.timeout_check_task.lock().await.take() {
//             tokio::spawn(task);
//         }
//         //*crate::option::UDP_UPLINK_CHANNEL_SIZE => 256
//         let (target_ch_tx, mut target_ch_rx) = mpsc::channel(256);
//         let (downlink_abort_tx, downlink_abort_rx) = oneshot::channel();
//
//         guard.insert(session, (target_ch_tx, downlink_abort_tx, Instant::now()));
//
//         let context = self.context.clone();
//         let sessions = self.sessions.clone();
//
//         let socket = Sniffer::route_udp(
//             context.clone(),
//             Arc::new(NetLocation::from_ip_addr(
//                 session.destination.ip().clone(),
//                 session.destination.port().clone(),
//             )),
//             data,
//         )
//         .await;
//         let clone = self.context.clone();
//         // Spawns a new task for dispatching to avoid blocking the current task,
//         // because we have stream type transports for UDP traffic, establishing a
//         // TCP stream would block the task.
//         tokio::spawn(async move {
//             // new socket to communicate with the target.
//             let socket = match socket {
//                 Ok(s) => s,
//                 Err(e) => {
//                     debug!("dispatch {:?} failed: {}", &session, e);
//                     sessions.lock().await.remove(&session);
//                     return;
//                 }
//             };
//             let (mut target_sock_recv, mut target_sock_send) = tokio::io::split(socket);
//
//             // downlink
//             let downlink_task = async move {
//                 //2
//                 // let mut buf = vec![0u8; *crate::option::DATAGRAM_BUFFER_SIZE * 1024];
//                 // let mut buf = vec![0u8; MAX_UDP_BUFFER_CAPACITY];
//                 let mut buffer_manager = clone
//                     .get_buffer_manager()
//                     .get_buffer(MAX_UDP_BUFFER_CAPACITY);
//                 let mut buf = buffer_manager.data();
//                 loop {
//                     let result = target_sock_recv.read(&mut buf).await;
//                     match result {
//                         Err(err) => {
//                             debug!(
//                                 "Failed to receive downlink packets on session {:?}: {}",
//                                 &session, err
//                             );
//                             break;
//                         }
//                         Ok(n) => {
//                             // trace!("outbound received UDP packet");
//                             let pkt = UdpPacket::new(
//                                 buf[..n].to_vec(),
//                                 session.destination.clone(),
//                                 session.source.clone(),
//                             );
//                             if let Err(err) = client_ch_tx.send(pkt).await {
//                                 debug!(
//                                     "Failed to send downlink packets on session {:?}: {}",
//                                     &session, err
//                                 );
//                                 break;
//                             }
//                             // activity update
//                             {
//                                 let mut sessions = sessions.lock().await;
//                                 if let Some(sess) = sessions.get_mut(&session) {
//                                     if session.destination.port() == 53 {
//                                         sess.2.checked_sub(Duration::from_secs(30));
//                                     //      *option::UDP_SESSION_TIMEOUT =>30
//                                     } else {
//                                         sess.2 = Instant::now();
//                                     }
//                                 }
//                             }
//                         }
//                     }
//                 }
//                 sessions.lock().await.remove(&session);
//             };
//
//             let (downlink_task, downlink_task_handle) = abortable(downlink_task);
//             tokio::spawn(downlink_task);
//
//             // Runs a task to receive the abort signal.
//             tokio::spawn(async move {
//                 let _ = downlink_abort_rx.await;
//                 downlink_task_handle.abort();
//             });
//
//             // uplink
//             tokio::spawn(async move {
//                 while let Some(pkt) = target_ch_rx.recv().await {
//                     // trace!(
//                     //     "outbound send UDP packet: dst {}, {} bytes",
//                     //     &pkt.dst_addr,
//                     //     pkt.data.len()
//                     // );
//                     if let Err(e) = target_sock_send.write(&pkt.data).await {
//                         debug!(
//                             "Failed to send uplink packets on session {:?} to {}: {:?}",
//                             &session, &pkt.dst_addr, e
//                         );
//                         break;
//                     }
//                     if let Err(e) = target_sock_send.flush().await {
//                         debug!(
//                             "Failed to send uplink packets on session {:?} to {}: {:?}",
//                             &session, &pkt.dst_addr, e
//                         );
//                         break;
//                     }
//                 }
//                 if let Err(e) = target_sock_send.shutdown().await {
//                     debug!("Failed to close outbound datagram {:?}: {}", &session, e);
//                 }
//             });
//         });
//     }
// }
//
// #[derive(Debug, Clone, Eq, Hash, PartialEq, Copy)]
// pub struct UdpSession {
//     pub source: SocketAddr,
//     pub destination: SocketAddr,
// }
//
// #[derive(Debug, Clone)]
// pub struct UdpPacket {
//     pub data: Vec<u8>,
//     pub src_addr: SocketAddr,
//     pub dst_addr: SocketAddr,
// }
//
// impl UdpPacket {
//     pub fn new(data: Vec<u8>, src_addr: SocketAddr, dst_addr: SocketAddr) -> Self {
//         Self {
//             data,
//             src_addr,
//             dst_addr,
//         }
//     }
// }
//
// impl std::fmt::Display for UdpPacket {
//     fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
//         write!(
//             f,
//             "{} <-> {}, {} bytes",
//             self.src_addr,
//             self.dst_addr,
//             self.data.len()
//         )
//     }
// }
