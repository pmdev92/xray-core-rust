use crate::common::geo::GeoPatternParser;
use crate::core::router::{Apply, RouteLocation};
use log::warn;
use std::sync::Arc;

mod full_domain_matcher;
pub mod geo_domain_matcher;
mod partial_matcher;
mod regular_expression_matcher;
mod sub_domain_matcher;

pub(crate) struct DomainMatcher {
    domain_patterns: Vec<String>,
    geo_domain_matchers: Vec<(String, String)>, // (path, code) pairs
}

impl Apply for DomainMatcher {
    fn apply(&self, route_location: Arc<RouteLocation>) -> bool {
        if !route_location.target_location.address.is_hostname() {
            match &route_location.sniff_result {
                None => {
                    return false;
                }
                Some(sniff) => {
                    if sniff.domains.len() == 0 {
                        return false;
                    }
                }
            }
        }

        use crate::common::geo::RouterDomainMatcher;
        RouterDomainMatcher::matches(
            &route_location,
            &self.domain_patterns,
            &self.geo_domain_matchers,
        )
    }
}

impl DomainMatcher {
    pub fn new(raw_rules: &Vec<String>) -> Self {
        let mut domain_patterns = Vec::new();
        let mut geo_domain_matchers = Vec::new();

        for rule in raw_rules {
            if let Some((path, code)) = GeoPatternParser::parse_geodomain_pattern(rule) {
                geo_domain_matchers.push((path, code));
            } else {
                domain_patterns.push(rule.clone());
            }
        }

        Self {
            domain_patterns,
            geo_domain_matchers,
        }
    }
}
