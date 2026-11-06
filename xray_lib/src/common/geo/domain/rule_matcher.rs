use crate::common::geo::domain::{DomainMatcher, GeoSiteDomainIter};
use log::{error, warn};

/// Helper struct to match domain patterns and geo patterns
pub struct DomainRuleMatcher {
    pub domain_patterns: Vec<String>,
    pub geos: Vec<(String, String)>, // (path, code) pairs
}

impl DomainRuleMatcher {
    pub fn new(domain_patterns: Vec<String>, geos: Vec<(String, String)>) -> Self {
        Self {
            domain_patterns,
            geos,
        }
    }

    /// Check if domain matches this rule
    /// Returns true if domain matches either domain patterns or geo patterns
    pub fn matches(&self, domain: &str) -> bool {
        let mut domain_matched = false;

        // Check domain patterns first
        for pattern in &self.domain_patterns {
            if DomainMatcher::matches_pattern(pattern, domain) {
                domain_matched = true;
                break;
            }
        }

        // If domain pattern matched or no domain patterns, check geo
        if domain_matched || self.domain_patterns.is_empty() {
            if self.geos.is_empty() {
                // No geo patterns, domain patterns decided
                return domain_matched;
            }

            // Check geo patterns
            for (path, code) in &self.geos {
                match GeoSiteDomainIter::open(path, code) {
                    Ok(domains) => {
                        for geo_domain in domains {
                            if DomainMatcher::matches(domain, &geo_domain) {
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
}
