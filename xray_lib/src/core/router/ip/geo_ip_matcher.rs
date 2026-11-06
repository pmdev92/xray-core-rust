use crate::common::geo::GeoIPCIDRIter;
use crate::core::router::{Apply, RouteLocation};
use crate::protos::router::domain::Type;
use std::sync::Arc;

pub(crate) struct GeoIpMatcher {
    path: String,
    code: String,
}
impl GeoIpMatcher {
    pub fn new(path: String, code: String) -> Self {
        Self { path, code }
    }
}
impl Apply for GeoIpMatcher {
    fn apply(&self, route_location: Arc<RouteLocation>) -> bool {
        let cidrs = match GeoIPCIDRIter::open(&self.path, &self.code) {
            Ok(cidrs) => cidrs,
            Err(error) => {
                error!("{}", error);
                return false;
            }
        };

        for cidr in cidrs {
            let mut helper: Option<Box<dyn Apply>> = None;
            let mut ip = None;
            if cidr.ip.len() == 4 {
                let ip_v4: std::result::Result<[u8; 4], _> = cidr.ip.try_into();
                match ip_v4 {
                    Ok(ip_v4) => {
                        ip = Some(IpAddr::from(ip_v4));
                    }
                    Err(_) => {}
                }
            } else if cidr.ip.len() == 16 {
                let ip_v6: std::result::Result<[u8; 16], _> = cidr.ip.try_into();
                match ip_v6 {
                    Ok(ip_v6) => {
                        ip = Some(IpAddr::from(ip_v6));
                    }
                    Err(_) => {}
                }
            }
            match ip {
                None => {}
                Some(ip) => {
                    let prefix = cidr.prefix as u8;
                    let cidr = cidr::IpCidr::new(ip, prefix);
                    match cidr {
                        Ok(cidr) => {
                            helper = Some(Box::new(CidrMatcher::new(cidr)));
                        }
                        Err(err) => {
                            warn!(
                                "router ip `{}` prefix `{}` parse error: {}",
                                ip, prefix, err
                            );
                        }
                    }
                }
            }
            if let Some(matcher) = helper {
                let result = matcher.apply(route_location.clone());
                if result {
                    return result;
                }
            }
        }
        false
    }
}
use crate::core::router::ip::cidr_matcher::CidrMatcher;
use log::{error, warn};
use std::net::IpAddr;
