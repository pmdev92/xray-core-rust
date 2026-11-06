use crate::core::context::Context;
use crate::core::dns::cache::DnsCache;
use crate::core::dns::client::DnsClient;
use crate::core::dns::config::DnsConfig;
use crate::core::dns::resolver::DnsResolver;
use futures_util::future::BoxFuture;
use hickory_proto::op::{Message, Query};
use hickory_proto::rr::RecordType::{A, AAAA};
use hickory_proto::rr::{DNSClass, Name, RecordData, RecordType};
use hickory_proto::serialize::binary::BinEncodable;
use log::{debug, error, info, trace, warn};
use rand::prelude::SliceRandom;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct DnsManager {
    resolver: Arc<RwLock<DnsResolver>>,
    cache: Option<Arc<DnsCache>>,
}

impl DnsManager {
    pub fn new(config: DnsConfig) -> Self {
        info!("Initializing DNS Manager");

        let cache = config.cache.as_ref().and_then(|cache_config| {
            if cache_config.enabled {
                let ttl = cache_config.ttl.unwrap_or(3600);
                let max_entries = cache_config.max_entries.unwrap_or(1000);
                info!("DNS Cache enabled - max_entries: {}", max_entries);
                Some(Arc::new(DnsCache::new(ttl, max_entries)))
            } else {
                info!("DNS Cache disabled");
                None
            }
        });

        let servers_count = config.servers.len();
        let rules_count = config.rules.as_ref().map(|r| r.len()).unwrap_or(0);

        info!(
            "DNS Manager configured with {} servers and {} rules",
            servers_count, rules_count
        );

        let resolver = DnsResolver::new(config);

        Self {
            resolver: Arc::new(RwLock::new(resolver)),
            cache,
        }
    }
    pub fn resolve_queries(
        &self,
        context: Arc<Context>,
        domain: String,
        types: Vec<RecordType>,
    ) -> BoxFuture<Option<Vec<String>>> {
        Box::pin(async move {
            debug!(
                "DNS resolve request for domain: {}, queries: {:?}",
                domain, types
            );
            if let Some(cache) = &self.cache {
                if let Some(cached) = cache.get(domain.as_str()).await {
                    debug!("DNS cache hit for {}: {:?}", domain, cached);
                    return Some(cached);
                }
            }

            debug!(
                "DNS cache miss for domain: {:?}, type:{:?} ,resolving...",
                domain, types
            );

            let resolver = self.resolver.read().await;
            if let Some(server) = resolver.find_server_for_domain(domain.as_str()) {
                let server_clone = server.clone();
                drop(resolver);

                debug!(
                    "DNS querying server: {} ({}://{}:{})",
                    server_clone.tag.as_ref().unwrap_or(&"default".to_string()),
                    format!("{:?}", server_clone.protocol).to_lowercase(),
                    server_clone.address,
                    server_clone.port
                );
                let name = Name::from_utf8(if domain.ends_with('.') {
                    domain.clone()
                } else {
                    format!("{}.", domain)
                })
                .ok()?;
                match Self::build_dns_query_message(&name, types) {
                    Ok(message) => match DnsClient::query(context, &server_clone, &message).await {
                        Ok(response) => {
                            // trace!("DNS resolved for {}: message {:?}", domain, message);
                            // trace!("DNS resolved for {}: response {:?}", domain, response);
                            let mut ips = vec![];
                            for answer in response.answers {
                                if name.to_string() == answer.name.to_string()
                                    && answer.dns_class == DNSClass::IN
                                {
                                    let ip = answer.data.to_string();
                                    ips.push(ip);
                                }
                            }
                            debug!("DNS resolved for {} is {:?}", domain, ips);
                            if ips.len() == 0 {
                                return None;
                            }
                            if let Some(cache) = &self.cache {
                                cache.set(domain.to_string(), ips.clone()).await;
                                debug!("DNS result for {} cached", domain);
                            }
                            return Some(ips);
                        }
                        Err(e) => {
                            error!(
                                "DNS query failed for {} on server {}: {}",
                                domain, server_clone.address, e
                            );
                        }
                    },
                    Err(e) => {
                        error!("DNS: failed to build query packet: {}", e);
                    }
                }
            } else {
                warn!("DNS: no suitable server found for domain {}", domain);
            }
            warn!("DNS failed to resolve domain {}", domain);
            None
        })
    }
    pub async fn resolve_ip(
        &self,
        context: Arc<Context>,
        domain: String,
        types: Vec<RecordType>,
    ) -> Option<IpAddr> {
        let result = self
            .resolve_queries(context.clone(), domain.clone(), types)
            .await;
        if let Some(result) = result {
            let mut ip_v4: Option<Ipv4Addr> = None;
            let mut ip_v6: Option<Ipv6Addr> = None;
            if let Some(ip) = result.iter().next() {
                let ip = IpAddr::from_str(ip.as_str());
                if let Ok(ip) = ip {
                    match ip {
                        IpAddr::V4(v4) => {
                            if ip_v4.is_none() {
                                return Some(v4.clone().into());
                            }
                        }
                        IpAddr::V6(v6) => {
                            if ip_v6.is_none() {
                                return Some(v6.clone().into());
                            }
                        }
                    }
                }
            }
        }
        None
    }

    fn extract_first_ip(response: &[u8]) -> Option<String> {
        if response.len() < 12 {
            return None;
        }

        let ancount = u16::from_be_bytes([response[6], response[7]]);
        if ancount == 0 {
            return None;
        }

        let mut pos = 12;

        while pos < response.len() {
            let len = response[pos] as usize;
            if len == 0 {
                break;
            }
            pos += len + 1;
        }

        pos += 4;

        if pos >= response.len() {
            return None;
        }

        pos += 10;

        if pos + 4 > response.len() {
            return None;
        }

        if response[pos] != 0 || response[pos + 1] != 1 {
            return None;
        }

        pos += 2;

        if pos + 4 > response.len() {
            return None;
        }

        let ip = format!(
            "{}.{}.{}.{}",
            response[pos],
            response[pos + 1],
            response[pos + 2],
            response[pos + 3]
        );

        Some(ip)
    }

    fn build_dns_query_message(name: &Name, types: Vec<RecordType>) -> Result<Message, String> {
        let mut message = Message::query();

        message.metadata.recursion_desired = true;
        message.metadata.checking_disabled = false;

        for query_type in types {
            let query = Query::query(name.clone(), query_type);
            message.add_query(query);
        }
        Ok(message)
    }

    pub async fn cleanup_cache(&self) {
        if let Some(cache) = &self.cache {
            debug!("Starting DNS cache cleanup");
            cache.cleanup_expired().await;
            debug!("DNS cache cleanup completed");
        }
    }
}

impl Clone for DnsManager {
    fn clone(&self) -> Self {
        debug!("Cloning DNS Manager");
        Self {
            resolver: self.resolver.clone(),
            cache: self.cache.clone(),
        }
    }
}
