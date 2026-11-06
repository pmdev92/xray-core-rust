use crate::common::geo::domain::{DomainMatcher, GeoSiteDomainIter};
use crate::core::router::RouteLocation;
use log::{error, warn};
use std::sync::Arc;

/// Helper to check if domain from RouteLocation matches rules
pub struct RouterDomainMatcher;

impl RouterDomainMatcher {
    /// Check if domain in route_location matches domain patterns and geo patterns
    pub fn matches(
        route_location: &Arc<RouteLocation>,
        domain_patterns: &[String],
        geo_domain_matchers: &[(String, String)],
    ) -> bool {
        // Get domain from route_location
        let domain = Self::get_domain(route_location);
        if domain.is_empty() {
            return false;
        }

        let mut domain_matched = false;

        // Check domain patterns first
        for pattern in domain_patterns {
            if DomainMatcher::matches_pattern(pattern, &domain) {
                domain_matched = true;
                break;
            }
        }

        // If domain pattern matched or no domain patterns, check geo
        if domain_matched || domain_patterns.is_empty() {
            if geo_domain_matchers.is_empty() {
                // No geo patterns, domain patterns decided
                return domain_matched;
            }

            // Check geo patterns
            for (path, code) in geo_domain_matchers {
                match GeoSiteDomainIter::open(path, code) {
                    Ok(domains) => {
                        for geo_domain in domains {
                            if DomainMatcher::matches(&domain, &geo_domain) {
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
        } else {
            false
        }
    }

    /// Extract domain from RouteLocation
    fn get_domain(route_location: &Arc<RouteLocation>) -> String {
        // First try to get from sniff result
        if let Some(sniff_result) = &route_location.sniff_result {
            if !sniff_result.domains.is_empty() {
                return sniff_result.domains[0].clone();
            }
        }

        // Then try to get from target_location if it's a hostname
        if route_location.target_location.address.is_hostname() {
            route_location.target_location.address.to_string()
        } else {
            String::new()
        }
    }
}
