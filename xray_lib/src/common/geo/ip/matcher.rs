use crate::common::address::Address;
use crate::common::geo::ip::GeoIPCIDRIter;
use crate::core::router::RouteLocation;
use log::warn;
use std::net::IpAddr;
use std::sync::Arc;

/// Helper to check if IP from RouteLocation matches geo IP patterns
pub struct GeoIpMatcherHelper;

impl GeoIpMatcherHelper {
    /// Check if destination IP in route_location matches geo patterns
    pub fn matches(
        route_location: &Arc<RouteLocation>,
        geo_ip_matchers: &[(String, String)],
    ) -> bool {
        // Get destination IP from route_location
        let ip = match &route_location.target_location.address {
            Address::Ipv4(ipv4) => IpAddr::V4(*ipv4),
            Address::Ipv6(ipv6) => IpAddr::V6(*ipv6),
            Address::Hostname(_) => return false,
        };

        // Check each geo IP pattern
        for (path, code) in geo_ip_matchers {
            match GeoIPCIDRIter::open(path, code) {
                Ok(cidrs) => {
                    for cidr in cidrs {
                        if Self::ip_matches_cidr(&ip, &cidr) {
                            return true;
                        }
                    }
                }
                Err(error) => {
                    warn!("Failed to open geo file {}: {}", path, error);
                }
            }
        }
        false
    }

    /// Check if IP matches a CIDR block
    fn ip_matches_cidr(ip: &IpAddr, cidr: &crate::protos::router::CIDR) -> bool {
        let mut cidr_ip = None;

        if cidr.ip.len() == 4 {
            let ip_v4: std::result::Result<[u8; 4], _> = cidr.ip[..].try_into();
            match ip_v4 {
                Ok(ip_v4) => {
                    cidr_ip = Some(IpAddr::from(ip_v4));
                }
                Err(_) => {}
            }
        } else if cidr.ip.len() == 16 {
            let ip_v6: std::result::Result<[u8; 16], _> = cidr.ip[..].try_into();
            match ip_v6 {
                Ok(ip_v6) => {
                    cidr_ip = Some(IpAddr::from(ip_v6));
                }
                Err(_) => {}
            }
        }

        match cidr_ip {
            None => false,
            Some(cidr_ip_addr) => {
                let prefix = cidr.prefix as u8;
                match cidr::IpCidr::new(cidr_ip_addr, prefix) {
                    Ok(cidr_block) => cidr_block.contains(ip),
                    Err(_) => false,
                }
            }
        }
    }
}
