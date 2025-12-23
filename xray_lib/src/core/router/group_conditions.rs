use crate::core::router::config::RuleConfig;
use crate::core::router::domain::DomainMatcher;
use crate::core::router::ip::IpMatcher;
use crate::core::router::network::NetworkMatcher;
use crate::core::router::not_match_matcher::CacheMatchMatcher;
use crate::core::router::port::PortMatcher;
use crate::core::router::protocol::ProtocolMatcher;
use crate::core::router::{Apply, RouteLocation};
use std::sync::{Arc, Mutex};

pub struct GroupConditions {
    pub(crate) outbound_tag: String,
    matchers: Vec<Box<dyn Apply>>,
    chach_matchers: Mutex<Vec<CacheMatchMatcher>>,
}

impl Apply for GroupConditions {
    fn apply(&self, route_location: Arc<RouteLocation>) -> bool {
        {
            let not_found_matchers = self.chach_matchers.lock();
            match not_found_matchers {
                Ok(mut not_found_matchers) => {
                    for not_found_matcher in not_found_matchers.iter() {
                        let result = not_found_matcher.apply(route_location.clone());
                        match result {
                            None => {}
                            Some(result) => {
                                return result;
                            }
                        }
                    }
                }
                Err(_) => {}
            }
        }
        let mut result = true;
        for matcher in self.matchers.iter() {
            if !matcher.apply(route_location.clone()) {
                result = false;
            }
        }
        {
            let not_found_matchers = self.chach_matchers.lock();
            match not_found_matchers {
                Ok(mut not_found_matchers) => {
                    not_found_matchers
                        .push(CacheMatchMatcher::new((*route_location).clone(), result));
                }
                Err(_) => {}
            }
        }

        result
    }
}

impl GroupConditions {
    pub fn new(rule: &RuleConfig) -> Self {
        let mut group_rules = Self {
            outbound_tag: rule.outbound_tag.to_string(),
            matchers: Vec::new(),
            chach_matchers: Mutex::new(vec![]),
        };
        match &rule.protocol {
            None => {}
            Some(rules) => {
                group_rules
                    .matchers
                    .push(Box::new(ProtocolMatcher::new(rules)));
            }
        }
        match &rule.network {
            None => {}
            Some(network_rules) => {
                group_rules
                    .matchers
                    .push(Box::new(NetworkMatcher::new(network_rules)));
            }
        }

        match &rule.port {
            None => {}
            Some(port_rules) => {
                group_rules
                    .matchers
                    .push(Box::new(PortMatcher::new(port_rules)));
            }
        }

        match &rule.domain {
            None => {}
            Some(domain_rules) => {
                group_rules
                    .matchers
                    .push(Box::new(DomainMatcher::new(domain_rules)));
            }
        }

        match &rule.ip {
            None => {}
            Some(ip_rules) => {
                group_rules
                    .matchers
                    .push(Box::new(IpMatcher::new(ip_rules)));
            }
        }
        //todo implement source(ip,port) network(udp,tcp) and other xray rules
        group_rules
    }

    pub fn get_outbound_tag(&self) -> String {
        self.outbound_tag.clone()
    }
}
