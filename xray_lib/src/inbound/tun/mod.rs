// pub mod config;
// mod nat_manager;
//
// use crate::common::address::Address;
// use crate::common::buffer::copy;
// use crate::common::net_location::NetLocation;
// use crate::common::udp::get_udp_open_port;
// use Arc<crate::core::context::Context>;
// use crate::core::inbound::InboundTcp;
// use crate::core::outbound::XrayOutboundStream;
// use crate::core::sniffer::Sniffer;
// use crate::inbound::socks::config::Socks5InboundSettings;
// use crate::inbound::socks::Socks5Inbound;
// use crate::inbound::tun::config::TunInboundSettings;
// use crate::inbound::tun::nat_manager::{NatManager, UdpPacket};
// use crate::Runner;
// use async_trait::async_trait;
// use futures_util::future::join_all;
// use futures_util::{SinkExt, StreamExt};
// use log::{error, warn};
// use netstack_lwip::NetStack;
// use std;
// use std::collections::HashMap;
// use std::io;
// use std::io::ErrorKind;
// use std::net::SocketAddr;
// use std::os::fd::RawFd;
// use std::pin::Pin;
// use std::sync::{Arc, OnceLock};
// use tokio::io::{AsyncReadExt, AsyncWriteExt, WriteHalf};
// use tokio::net::{TcpStream, UdpSocket};
// use tokio::sync::mpsc::{Receiver, Sender};
//
// #[derive(Debug)]
// pub struct TunInbound {
//     pub fd: Option<u32>,
//     pub auto: Option<bool>,
// }
//
// impl TunInbound {
//     pub fn new(inbound_config: TunInboundSettings) -> Self {
//         Self {
//             fd: inbound_config.fd,
//             auto: inbound_config.auto,
//         }
//     }
// }
//
// #[async_trait]
// impl InboundTcp for TunInbound {
//     async fn start(self: Box<Self>, context: Context) -> Result<(), io::Error> {
//         //sudo route add -net 192.168.1.10/32 192.168.1.1
//         //sudo route change -inet default -interface utun255
//         //sudo route delete -inet default -interface utun255
//         let mut cfg = tun::Configuration::default();
//         if self.auto.is_none() && self.fd.is_none() {
//             return Err(io::Error::new(
//                 ErrorKind::InvalidData,
//                 "tun mode must be set",
//             ));
//         }
//         if let Some(fd) = self.fd {
//             cfg.raw_fd(fd as RawFd);
//             cfg.platform_config(|p_cfg| {
//                 p_cfg.packet_information(true);
//             });
//         } else {
//             cfg.tun_name("utun255")
//                 .address("10.10.10.10")
//                 .destination("10.10.10.1")
//                 .mtu(9000)
//                 .netmask("255.255.255.255");
//
//             cfg.up();
//         }
//
//         let tun = tun::create_as_async(&cfg)
//             .map_err(|err| io::Error::new(ErrorKind::InvalidData, err.to_string()))?;
//
//         let framed = tun.into_framed();
//         let (mut tun_sink, mut tun_stream) = framed.split();
//
//         // let (stack, mut tcp_listener, udp_socket) = netstack::NetStack::with_buffer_size(
//         //     *crate::option::NETSTACK_OUTPUT_CHANNEL_SIZE, 512
//         //     *crate::option::NETSTACK_UDP_UPLINK_CHANNEL_SIZE, 256
//         // )?;
//
//         let (stack, mut tcp_listener, udp_socket) = NetStack::with_buffer_size(512, 256)
//             .map_err(|e| io::Error::new(ErrorKind::InvalidData, e.to_string()))?;
//         let (mut stack_sink, mut stack_stream) = stack.split();
//
//         let mut futs: Vec<Runner> = Vec::new();
//
//         // Reads packet from stack and sends to TUN.
//         futs.push(Box::pin(async move {
//             while let Some(pkt) = stack_stream.next().await {
//                 match pkt {
//                     Ok(pkt) => {
//                         // println!("stack_stream {:?}", pkt);
//                         if let Err(e) = tun_sink.send(pkt).await {
//                             error!("Sending packet to TUN failed: {}", e);
//                             return;
//                         }
//                     }
//                     Err(e) => {
//                         error!("Net stack error: {}", e);
//                         return;
//                     }
//                 }
//             }
//         }));
//
//         // Reads packet from TUN and sends to stack.
//         futs.push(Box::pin(async move {
//             while let Some(pkt) = tun_stream.next().await {
//                 match pkt {
//                     Ok(pkt) => {
//                         // println!("tun {:?}", pkt);
//                         if let Err(e) = stack_sink.send(pkt).await {
//                             error!("Sending packet to NetStack failed: {}", e);
//                             return;
//                         }
//                     }
//                     Err(e) => {
//                         error!("TUN error: {}", e);
//                         return;
//                     }
//                 }
//             }
//         }));
//         let context_clone = context.clone();
//         let tun = Arc::new(self);
//         let tun_clone = tun.clone();
//         // Extracts TCP connections from stack and sends them to the dispatcher.
//         futs.push(Box::pin(async move {
//             while let Some((stream, local_addr, remote_addr)) = tcp_listener.next().await {
//                 let context = context_clone.clone();
//                 let tun = tun_clone.clone();
//                 tokio::spawn(async move {
//                     let _ = tun.process_socket(context, stream, remote_addr).await;
//                 });
//             }
//         }));
//
//         // Receive and send UDP packets between netstack and NAT manager. The NAT
//         // manager would maintain UDP sessions and send them to the dispatcher.
//         let context_clone = context.clone();
//         let tun_clone = tun.clone();
//         futs.push(Box::pin(async move {
//             tun_clone
//                 .handle_inbound_datagram(context_clone, udp_socket)
//                 .await;
//         }));
//         futures::future::select_all(futs).await;
//
//         Ok(())
//     }
// }
//
// impl TunInbound {
//     async fn process_socket(
//         &self,
//         context: Context,
//         socket: Pin<Box<netstack_lwip::TcpStream>>,
//         remote_addr: SocketAddr,
//     ) -> Result<bool, io::Error> {
//         let result = self.process_tcp(context, socket, remote_addr).await;
//         match result {
//             Ok(_) => Ok(true),
//             Err(err) => Err(err),
//         }
//     }
//
//     async fn process_tcp(
//         &self,
//         context: Context,
//         mut tcp_stream: Pin<Box<netstack_lwip::TcpStream>>,
//         remote_addr: SocketAddr,
//     ) -> Result<bool, io::Error> {
//         let target_location = NetLocation::from_ip_addr(remote_addr.ip(), remote_addr.port());
//         let outbound_stream = Sniffer::route_tcp(
//             context.clone(),
//             Arc::new(target_location.clone()),
//             &mut tcp_stream,
//         )
//         .await?;
//         let (outbound_read, outbound_write) = tokio::io::split(outbound_stream);
//         let (inbound_read, inbound_write) = tokio::io::split(tcp_stream);
//         let context_clone = context.clone();
//         let write_handler = tokio::spawn(async move {
//             let mut outbound_read = outbound_read;
//             let mut inbound_write = inbound_write;
//             let _count = copy(context_clone, &mut outbound_read, &mut inbound_write).await;
//         });
//         let context_clone = context.clone();
//         let read_handler = tokio::spawn(async move {
//             let mut inbound_read = inbound_read;
//             let mut outbound_write = outbound_write;
//             let _count = copy(context_clone, &mut inbound_read, &mut outbound_write).await;
//         });
//
//         let mut handles = Vec::new();
//         handles.push(read_handler);
//         handles.push(write_handler);
//         join_all(handles).await;
//         return Ok(true);
//     }
//
//     async fn handle_inbound_datagram(
//         &self,
//         context: Context,
//         udp_socket: Pin<Box<netstack_lwip::UdpSocket>>,
//     ) {
//         let nat_manager = NatManager::new(context);
//
//         // The socket to receive/send packets from/to the net stack.
//         let (ls, mut lr) = udp_socket.split();
//         let ls = Arc::new(ls);
//
//         //*crate::option::UDP_DOWNLINK_CHANNEL_SIZE => 256
//         // The channel for sending back datagrams from NAT manager to net stack.
//         let (l_tx, mut l_rx): (Sender<UdpPacket>, Receiver<UdpPacket>) =
//             tokio::sync::mpsc::channel(256);
//
//         // Receive datagrams from NAT manager and send back to net stack.
//         let ls_cloned = ls.clone();
//         tokio::spawn(async move {
//             while let Some(pkt) = l_rx.recv().await {
//                 if let Err(e) = ls_cloned.send_to(&pkt.data[..], &pkt.src_addr, &pkt.dst_addr) {
//                     warn!("A packet failed to send to the net stack: {}", e);
//                 }
//             }
//         });
//
//         // Accept datagrams from net stack and send to NAT manager.
//         loop {
//             match lr.recv_from().await {
//                 Err(e) => {
//                     warn!("Failed to accept a datagram from net stack: {}", e);
//                 }
//                 Ok((data, src_addr, dst_addr)) => {
//                     let pkt = UdpPacket::new(data, src_addr, dst_addr);
//                     nat_manager.send(&l_tx, pkt).await;
//                 }
//             }
//         }
//     }
// }
