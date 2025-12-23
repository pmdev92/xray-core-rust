use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

use cidr::IpCidr;

use crate::core::router::{Apply, RouteLocation};

pub(crate) struct CidrMatcher {
    cidr: IpCidr,
}
impl CidrMatcher {
    pub fn new(cidr: IpCidr) -> Self {
        Self { cidr }
    }
}

impl Apply for CidrMatcher {
    fn apply(&self, route_location: Arc<RouteLocation>) -> bool {
        if !route_location.target_location.address.is_hostname() {
            let domain = route_location.target_location.address.to_string().clone();
            let ip_address = IpAddr::from_str(domain.as_str());
            match ip_address {
                Ok(ip_address) => {
                    return self.cidr.contains(&ip_address);
                }
                Err(_) => {}
            }
        }
        return false;
    }
}
