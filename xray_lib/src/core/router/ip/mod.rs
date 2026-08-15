use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use crate::common::asset::get_asset_location;
use crate::common::geo;
use crate::core::router::ip::cidr_matcher::CidrMatcher;
use crate::core::router::ip::geo_ip_matcher::{GeoIPCIDRIter, GeoIpMatcher};
use crate::core::router::{Apply, RouteLocation};
use log::warn;

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
                let geo = rule.replace("geo:", "").clone();
                let geo = geo.split(",").collect::<Vec<&str>>();
                if geo.len() < 1 || geo.len() > 2 {
                    warn!("router rule domain `{}` parse error", rule);
                    continue;
                }
                let mut file = "";
                let mut code = "";

                if geo.len() == 1 {
                    file = "geoip.dat";
                    code = geo[0];
                } else if geo.len() == 2 {
                    file = geo[0];
                    code = geo[1];
                }

                let path = if Path::new(file).is_relative() {
                    get_asset_location(file).to_string_lossy().into_owned()
                } else {
                    file.to_string()
                };

                let helper = GeoIpMatcher::new(path, code.to_string());
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
