use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use crate::common::geo::GeoPatternParser;
use crate::core::router::ip::cidr_matcher::CidrMatcher;
use crate::core::router::ip::geo_ip_matcher::GeoIpMatcher;
use crate::core::router::{Apply, RouteLocation};
use log::warn;

mod cidr_matcher;
pub mod geo_ip_matcher;

pub(crate) struct IpMatcher {
    matchers: Vec<Box<dyn Apply>>,
}

impl Apply for IpMatcher {
    fn apply(&self, route_location: Arc<RouteLocation>) -> bool {
        for matcher in self.matchers.iter() {
            if matcher.apply(route_location.clone()) {
                return true;
            }
        }
        false
    }
}

impl IpMatcher {
    pub fn new(raw_rules: &Vec<String>) -> Self {
        let mut rules: Vec<Box<dyn Apply>> = Vec::new();
        for rule in raw_rules {
            if rule.contains("geo:") {
                if let Some((path, code)) = GeoPatternParser::parse_geoip_pattern(rule) {
                    let helper = GeoIpMatcher::new(path, code);
                    rules.push(Box::new(helper));
                } else {
                    warn!("router rule ip `{}` parse error", rule);
                }
            } else {
                let cidr = cidr::IpCidr::from_str(rule.as_str());
                match cidr {
                    Ok(cidr) => {
                        let cidr = CidrMatcher::new(cidr);
                        rules.push(Box::new(cidr));
                    }
                    Err(err) => {
                        warn!("router ip rule `{}` parse error: {}", rule, err);
                    }
                }
            }
        }
        Self { matchers: rules }
    }
}
