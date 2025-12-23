use crate::common::constants::{MAX_TCP_BUFFER_CAPACITY, MAX_UDP_BUFFER_CAPACITY};
use crate::common::net_location::NetLocation;
use crate::common::vec::vec_allocate;
use crate::core::context::Context;
use crate::core::dispatcher::Dispatcher;
use crate::core::io::{AsyncXrayTcpStream, AsyncXrayUdpStream};
use crate::core::router::{Network, RouteLocation};
use crate::core::session::Session;
use crate::core::sniffer::protocols::dns::Dns;
use crate::core::sniffer::protocols::http::Http;
use crate::core::sniffer::protocols::quic::Quic;
use crate::core::sniffer::protocols::tls::Tls;
use log::{error, info, warn};
use once_cell::sync::Lazy;
use std::fmt::{Debug, Display, Formatter};
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio::time::sleep;

pub(crate) mod protocols;
pub struct Sniffer {}

impl Sniffer {
    fn get_tcp_sniffers() -> Vec<fn(&[u8]) -> (bool, Option<SniffResult>)> {
        let sniffers: Vec<fn(&[u8]) -> (bool, Option<SniffResult>)> =
            vec![Http::sniff, Tls::sniff, Dns::sniff];
        sniffers
    }
    fn get_udp_sniffers() -> Vec<fn(&[u8]) -> (bool, Option<SniffResult>)> {
        let sniffers: Vec<fn(&[u8]) -> (bool, Option<SniffResult>)> = vec![Dns::sniff, Quic::sniff];
        sniffers
    }

    pub async fn route_tcp<T: 'static + AsyncRead + Unpin + Send + Sync>(
        session: Session,
        context: Arc<Context>,
        target_location: Arc<NetLocation>,
        stream: &mut T,
    ) -> Result<Box<dyn AsyncXrayTcpStream>, io::Error> {
        let dispatcher = context.get_dispatcher();
        if !dispatcher.have_any_matcher() {
            let route_location = RouteLocation::new(Network::Tcp, target_location.clone(), None);
            let item = dispatcher
                .get_routed_outbound(session, route_location)
                .await;
            return match item {
                Some(item) => {
                    let result = item
                        .outbound
                        .dial_tcp(context.clone(), item.detour, target_location.clone())
                        .await;
                    match result {
                        Ok(stream) => Ok(stream),
                        Err(error) => {
                            warn!(
                                "route tcp error target location: {} message:\"{}\"",
                                target_location.clone(),
                                error
                            );
                            Err(error)
                        }
                    }
                }
                None => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "no available outbounds for route",
                )),
            };
        }
        let mut buffer_manager = context
            .get_buffer_manager()
            .get_buffer(MAX_TCP_BUFFER_CAPACITY)
            .await?;
        let mut buffer = buffer_manager.data();
        let result = stream.read(&mut buffer).await;
        match result {
            Ok(read) => {
                let data = &buffer[..read];
                let mut sniff_result: Option<SniffResult> = None;
                for sniffer in Sniffer::get_tcp_sniffers() {
                    let (ok, result) = sniffer(data);
                    if ok {
                        sniff_result = result;
                        break;
                    }
                }
                if let Some(sniff) = &sniff_result {
                    info!(
                        "sniffed domain for target location {} is {}",
                        target_location.to_string(),
                        sniff
                    );
                }
                let route_location =
                    RouteLocation::new(Network::Tcp, target_location.clone(), sniff_result);
                let item = dispatcher
                    .get_routed_outbound(session, route_location)
                    .await;
                match item {
                    Some(item) => {
                        let result = item
                            .outbound
                            .dial_tcp(context.clone(), item.detour, target_location.clone())
                            .await;
                        match result {
                            Ok(mut outbound_stream) => {
                                let _ = outbound_stream.write(data).await;
                                let _ = outbound_stream.flush().await;
                                Ok(outbound_stream)
                            }
                            Err(error) => {
                                warn!(
                                    "route tcp error target location: {} message:\"{}\"",
                                    target_location.clone(),
                                    error
                                );
                                Err(error)
                            }
                        }
                    }
                    None => Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "no available outbounds for route",
                    )),
                }
            }
            Err(err) => Err(err),
        }
    }

    pub async fn route_tcp_no_sniff(
        session: Session,
        context: Arc<Context>,
        target_location: Arc<NetLocation>,
    ) -> Result<Box<dyn AsyncXrayTcpStream>, io::Error> {
        let dispatcher = context.get_dispatcher();
        if !dispatcher.have_any_matcher() {
            let route_location = RouteLocation::new(Network::Tcp, target_location.clone(), None);
            let item = dispatcher
                .get_routed_outbound(session, route_location)
                .await;
            return match item {
                Some(item) => {
                    let result = item
                        .outbound
                        .dial_tcp(context.clone(), item.detour, target_location.clone())
                        .await;
                    match result {
                        Ok(stream) => Ok(stream),
                        Err(error) => {
                            warn!(
                                "route tcp error target location: {} message:\"{}\"",
                                target_location.clone(),
                                error
                            );
                            Err(error)
                        }
                    }
                }
                None => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "no available outbounds for route",
                )),
            };
        }
        let route_location = RouteLocation::new(Network::Tcp, target_location.clone(), None);
        let item = dispatcher
            .get_routed_outbound(session, route_location)
            .await;
        match item {
            Some(item) => {
                let result = item
                    .outbound
                    .dial_tcp(context.clone(), item.detour, target_location.clone())
                    .await;
                match result {
                    Ok(mut outbound_stream) => Ok(outbound_stream),
                    Err(error) => {
                        warn!(
                            "route tcp error target location: {} message:\"{}\"",
                            target_location.clone(),
                            error
                        );
                        Err(error)
                    }
                }
            }
            None => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "no available outbounds for route",
            )),
        }
    }

    pub async fn route_udp_no_sniff(
        session: Session,
        context: Arc<Context>,
        target_location: Arc<NetLocation>,
    ) -> Result<Box<dyn AsyncXrayUdpStream>, io::Error> {
        let dispatcher = context.get_dispatcher();
        if !dispatcher.have_any_matcher() {
            let route_location = RouteLocation::new(Network::Udp, target_location.clone(), None);
            let item = dispatcher
                .get_routed_outbound(session, route_location)
                .await;
            return match item {
                Some(item) => {
                    let result = item
                        .outbound
                        .dial_udp(context.clone(), item.detour, target_location.clone())
                        .await;
                    match result {
                        Ok(stream) => Ok(stream),
                        Err(error) => {
                            warn!(
                                "route udp error target location: {} message:\"{}\"",
                                target_location.clone(),
                                error
                            );
                            Err(error)
                        }
                    }
                }
                None => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "no available outbounds for route",
                )),
            };
        }

        let route_location = RouteLocation::new(Network::Udp, target_location.clone(), None);
        let item = dispatcher
            .get_routed_outbound(session, route_location)
            .await;
        match item {
            Some(item) => {
                let result = item
                    .outbound
                    .dial_udp(context.clone(), item.detour, target_location.clone())
                    .await;
                match result {
                    Ok(outbound_stream) => Ok(outbound_stream),
                    Err(error) => {
                        warn!(
                            "route udp error target location: {} message:\"{}\"",
                            target_location.clone(),
                            error
                        );
                        Err(error)
                    }
                }
            }
            None => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "no available outbounds for route",
            )),
        }
    }
    pub async fn route_udp(
        session: Session,
        context: Arc<Context>,
        target_location: Arc<NetLocation>,
        packet: &Vec<u8>,
    ) -> Result<Box<dyn AsyncXrayUdpStream>, io::Error> {
        let dispatcher = context.get_dispatcher();
        if !dispatcher.have_any_matcher() {
            let route_location = RouteLocation::new(Network::Udp, target_location.clone(), None);
            let item = dispatcher
                .get_routed_outbound(session, route_location)
                .await;
            return match item {
                Some(item) => {
                    let result = item
                        .outbound
                        .dial_udp(context.clone(), item.detour, target_location.clone())
                        .await;
                    match result {
                        Ok(stream) => Ok(stream),
                        Err(error) => {
                            warn!(
                                "route udp error target location: {} message:\"{}\"",
                                target_location.clone(),
                                error
                            );
                            Err(error)
                        }
                    }
                }
                None => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "no available outbounds for route",
                )),
            };
        }
        //need to sniff
        let mut sniff_result: Option<SniffResult> = None;
        for sniffer in Sniffer::get_udp_sniffers() {
            let (ok, result) = sniffer(&packet);
            if ok {
                sniff_result = result;
                break;
            }
        }
        if let Some(sniff) = &sniff_result {
            info!(
                "sniffed domain for target location {} is {}",
                target_location.to_string(),
                sniff
            );
        }
        let route_location =
            RouteLocation::new(Network::Udp, target_location.clone(), sniff_result);
        let item = dispatcher
            .get_routed_outbound(session, route_location)
            .await;
        match item {
            Some(item) => {
                let result = item
                    .outbound
                    .dial_udp(context.clone(), item.detour, target_location.clone())
                    .await;
                match result {
                    Ok(outbound_stream) => Ok(outbound_stream),
                    Err(error) => {
                        warn!(
                            "route udp error target location: {} message:\"{}\"",
                            target_location.clone(),
                            error
                        );
                        Err(error)
                    }
                }
            }
            None => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "no available outbounds for route",
            )),
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum SniffProtocol {
    Http,
    Tls,
    Quic,
    Dns,
}
impl TryFrom<&str> for SniffProtocol {
    type Error = io::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if (value.to_lowercase() == "http") {
            return Ok(SniffProtocol::Http);
        }
        if (value.to_lowercase() == "tls") {
            return Ok(SniffProtocol::Tls);
        }
        if (value.to_lowercase() == "quic") {
            return Ok(SniffProtocol::Quic);
        }
        if (value.to_lowercase() == "dns") {
            return Ok(SniffProtocol::Dns);
        }
        Err(io::Error::from(io::ErrorKind::InvalidInput))
    }
}
impl Display for SniffProtocol {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SniffProtocol::Http => {
                let _ = f.write_str("http");
            }
            SniffProtocol::Tls => {
                let _ = f.write_str("tls");
            }
            SniffProtocol::Quic => {
                let _ = f.write_str("quic");
            }
            SniffProtocol::Dns => {
                let _ = f.write_str("dns");
            }
        }

        return Ok(());
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct SniffResult {
    pub protocol: SniffProtocol,
    pub domains: Vec<String>,
}

impl Display for SniffResult {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let _ = f.write_str("{ protocol: ");
        let _ = f.write_str(self.protocol.to_string().as_str());
        let _ = f.write_str(", domains: [");

        for (domain, is_last_element) in self
            .domains
            .iter()
            .enumerate()
            .map(|(i, w)| (w, i == self.domains.len() - 1))
        {
            let _ = f.write_str(domain);
            if !is_last_element {
                let _ = f.write_str(",");
            }
        }
        let _ = f.write_str("]}");
        Ok(())
    }
}

pub trait SnifferProtocol {
    fn sniff(data: &[u8]) -> (bool, Option<SniffResult>);
}
