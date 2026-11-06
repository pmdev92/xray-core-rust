use crate::common::net_location::NetLocation;
use crate::core::context::Context;
use crate::core::io::{AsyncXrayTcpStream, AsyncXrayUdpStream};
use crate::core::outbound::Outbound;
use async_trait::async_trait;
use bytes::Bytes;
use futures_util::{Sink, Stream};
use hickory_proto::op::{Header, Message, Query};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable, BinEncoder};
use log::{debug, error, info};
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use tokio::sync::mpsc;

pub struct DnsOutbound;

pub struct DnsUdpStream {
    context: Arc<Context>,
    tx: mpsc::UnboundedSender<Vec<u8>>,
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    dns_manager: Option<Arc<crate::core::dns::DnsManager>>,
}

impl DnsOutbound {
    pub fn new() -> Self {
        Self
    }

    fn parse_dns_queries(packet: &[u8]) -> Option<(Message, String, Vec<RecordType>)> {
        match Message::from_bytes(packet) {
            Ok(message) => {
                let name = message.queries.get(0).map(|q| q.name.clone())?;

                let mut types = vec![];
                for query in message.queries.iter() {
                    match query.query_type {
                        RecordType::A | RecordType::AAAA => types.push(query.query_type.clone()),
                        _ => {}
                    }
                }
                if types.len() == 0 {
                    return None;
                }
                debug!(
                    "DNS query parsed to query domain: {}, types: {:?}",
                    name.to_string(),
                    types
                );
                Some((message, name.to_string(), types))
            }
            Err(e) => {
                error!("DNS: failed to parse query packet: {}", e);
                None
            }
        }
    }

    fn build_response_packet(
        mut message: Message,
        domain: &str,
        ips: Vec<String>,
    ) -> Option<Vec<u8>> {
        let name = Name::from_ascii(domain).ok()?;

        for (ip) in ips {
            let ip: IpAddr = ip.parse().ok()?;
            let rdata = match ip {
                IpAddr::V4(ip) => RData::A(ip.into()),
                IpAddr::V6(ip) => RData::AAAA(ip.into()),
            };
            let record = Record::from_rdata(name.clone(), 60, rdata);
            message.add_answer(record);
        }

        let mut buffer = Vec::new();

        let mut encoder = BinEncoder::new(&mut buffer);

        message.emit(&mut encoder).ok()?;

        Some(buffer)
    }
}

impl Stream for DnsUdpStream {
    type Item = Bytes;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(response)) => {
                debug!(
                    "DNS UDP stream returning response: {} bytes",
                    response.len()
                );
                Poll::Ready(Some(Bytes::from(response)))
            }
            Poll::Ready(None) => {
                debug!("DNS UDP stream ended");
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Sink<Bytes> for DnsUdpStream {
    type Error = io::Error;

    fn poll_ready(
        self: Pin<&mut Self>,
        _cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(mut self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        let context = self.context.clone();
        let query_packet = item.to_vec();

        if let Some((message, domain, types)) = DnsOutbound::parse_dns_queries(&query_packet) {
            debug!(
                "DNS UDP received query for domain: {}, types: {:?}",
                domain, types
            );

            let dns_manager_clone = self.dns_manager.clone();
            let tx = self.tx.clone();
            tokio::spawn(async move {
                if let Some(dns_manager) = dns_manager_clone {
                    debug!("DNS: resolving domain: {}", domain);
                    match dns_manager
                        .resolve_queries(context, domain.clone(), types)
                        .await
                    {
                        Some(ips) => {
                            debug!("DNS: resolved domain {} to {:?}", domain, ips);
                            if let Some(response_packet) =
                                DnsOutbound::build_response_packet(message, domain.as_str(), ips)
                            {
                                info!(
                                    "DNS: built response packet ({} bytes)",
                                    response_packet.len()
                                );
                                if let Err(e) = tx.send(response_packet) {
                                    error!("DNS: failed to send response through channel: {}", e);
                                }
                            }
                        }
                        None => {
                            error!("DNS: failed to resolve {}", domain);
                        }
                    }
                } else {
                    error!("DNS: dns_manager not available");
                }
            });
        } else {
            error!("DNS: failed to parse DNS query packet");
        }
        Ok(())
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(
        self: Pin<&mut Self>,
        _cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncXrayUdpStream for DnsUdpStream {}

#[async_trait]
impl Outbound for DnsOutbound {
    async fn dial_tcp(
        &self,
        _context: Arc<Context>,
        _detour: Option<String>,
        _net_location: Arc<NetLocation>,
    ) -> io::Result<Box<dyn AsyncXrayTcpStream>> {
        Err(io::Error::new(
            io::ErrorKind::Other,
            "DNS outbound only supports UDP",
        ))
    }

    async fn dial_udp(
        &self,
        context: Arc<Context>,
        _detour: Option<String>,
        _net_location: Arc<NetLocation>,
    ) -> io::Result<Box<dyn AsyncXrayUdpStream>> {
        debug!("DNS outbound UDP dial");

        let dns_manager = context
            .get_dns_manager()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "DNS manager not available"))?;

        info!("DNS outbound initialized");

        let (tx, rx) = mpsc::unbounded_channel();

        let stream = DnsUdpStream {
            context,
            tx,
            rx,
            dns_manager: Some(dns_manager),
        };
        Ok(Box::new(stream))
    }
}
