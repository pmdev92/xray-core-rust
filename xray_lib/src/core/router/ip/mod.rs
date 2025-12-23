use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

use log::warn;

use crate::common::geo;
use crate::core::router::ip::cidr_matcher::CidrMatcher;
use crate::core::router::ip::geo_ip_matcher::{GeoIPCIDRIter, GeoIpMatcher};
use crate::core::router::{Apply, RouteLocation};

mod cidr_matcher;
mod geo_ip_matcher;

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
                let path_code = rule.replace("geo:", "").clone();
                let path_code = path_code.split(",").collect::<Vec<&str>>();
                if path_code.len() != 2 {
                    continue;
                }
                let path = path_code[0];
                let code = path_code[1];
                let helper = GeoIpMatcher::new(path.to_string(), code.to_string());
                rules.push(Box::new(helper));
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
