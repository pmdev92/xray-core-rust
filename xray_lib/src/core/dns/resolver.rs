use crate::common::geo::{DomainRuleMatcher, GeoPatternParser};
use crate::core::dns::cache::DnsCache;
use crate::core::dns::config::{DnsConfig, DnsRule, DnsServer};
use log::{debug, error, warn};
use std::sync::Arc;

pub struct DnsResolver {
    servers: Vec<DnsServer>,
    cache: Option<Arc<DnsCache>>,
    rules: Vec<DnsRuleWithMatcher>,
}

pub(crate) struct DnsRuleWithMatcher {
    pub matcher: DomainRuleMatcher,
    pub server: String,
}

impl DnsResolver {
    pub fn new(config: DnsConfig) -> Self {
        let cache = config.cache.as_ref().and_then(|cache_config| {
            if cache_config.enabled {
                Some(Arc::new(DnsCache::new(
                    cache_config.ttl.unwrap_or(3600),
                    cache_config.max_entries.unwrap_or(1000),
                )))
            } else {
                None
            }
        });

        let rules = config.rules.unwrap_or_default();
        let rules_with_matcher = rules
            .into_iter()
            .map(|rule| {
                let mut domain_patterns = Vec::new();
                let mut geos = Vec::new();

                if let Some(domains) = rule.domain {
                    for domain in domains {
                        if let Some((path, code)) =
                            GeoPatternParser::parse_geodomain_pattern(&domain)
                        {
                            geos.push((path, code));
                        } else {
                            domain_patterns.push(domain);
                        }
                    }
                }
                DnsRuleWithMatcher {
                    matcher: DomainRuleMatcher::new(domain_patterns, geos),
                    server: rule.server,
                }
            })
            .collect();

        Self {
            servers: config.servers,
            cache,
            rules: rules_with_matcher,
        }
    }

    pub fn find_server_for_domain(&self, domain: &str) -> Option<&DnsServer> {
        for rule in &self.rules {
            if rule.matcher.matches(domain) {
                debug!(
                    "DNS rule for {} matched with server {}",
                    domain, rule.server
                );
                let result = self.servers.iter().find(|s| {
                    s.tag.as_ref().map(|t| t == &rule.server).unwrap_or(false)
                        || s.address == rule.server
                });
                match result {
                    None => {
                        warn!("DNS server with tag {} not exists", rule.server);
                    }
                    Some(result) => return Some(result),
                }
            }
        }
        debug!("DNS rule for {} not found. use first dns server", domain);
        self.servers.first()
    }

    pub fn get_cache(&self) -> Option<Arc<DnsCache>> {
        self.cache.clone()
    }

    pub fn get_server(&self, tag: &str) -> Option<&DnsServer> {
        self.servers
            .iter()
            .find(|s| s.tag.as_ref().map(|t| t == tag).unwrap_or(false) || s.address == tag)
    }

    pub fn get_servers(&self) -> &[DnsServer] {
        &self.servers
    }
}
