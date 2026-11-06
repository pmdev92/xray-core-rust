use crate::protos::router::Domain;
use crate::protos::router::domain::Type;

pub struct DomainMatcher;

impl DomainMatcher {
    /// Match a domain against a geo domain pattern
    pub fn matches(domain: &str, geo_domain: &Domain) -> bool {
        match geo_domain.type_.enum_value() {
            Ok(domain_type) => match domain_type {
                Type::Plain => {
                    // Partial match (keyword)
                    domain.contains(&geo_domain.value)
                }
                Type::Regex => {
                    // Regex match
                    match regex::Regex::new(&geo_domain.value) {
                        Ok(re) => re.is_match(domain),
                        Err(_) => false,
                    }
                }
                Type::Domain => {
                    // Sub-domain match
                    if geo_domain.value == domain {
                        return true;
                    }
                    if domain.ends_with(&format!(".{}", geo_domain.value)) {
                        return true;
                    }
                    false
                }
                Type::Full => {
                    // Full domain match
                    geo_domain.value == domain
                }
            },
            Err(_) => false,
        }
    }

    /// Match a domain against a string pattern (for non-geo rules)
    /// Supports multiple pattern types:
    /// - "*" : match all domains
    /// - "example.com" : exact match
    /// - "*.example.com" : wildcard match
    /// - "regexp:pattern" : regex match
    /// - "full:example.com" : full domain match
    /// - "domain:example.com" : subdomain match
    /// - "keyword:pattern" : keyword match
    pub fn matches_pattern(pattern: &str, domain: &str) -> bool {
        // Match all
        if pattern == "*" {
            return true;
        }

        // Regex pattern
        if pattern.starts_with("regexp:") {
            let regex_pattern = &pattern[7..];
            match regex::Regex::new(regex_pattern) {
                Ok(re) => return re.is_match(domain),
                Err(_) => return false,
            }
        }

        // Full domain match
        if pattern.starts_with("full:") {
            let full_pattern = &pattern[5..];
            return domain == full_pattern;
        }

        // Sub-domain match
        if pattern.starts_with("domain:") {
            let domain_pattern = &pattern[7..];
            if domain == domain_pattern {
                return true;
            }
            if domain.ends_with(&format!(".{}", domain_pattern)) {
                return true;
            }
            return false;
        }

        // Keyword/partial match
        if pattern.starts_with("keyword:") {
            let keyword = &pattern[8..];
            return domain.contains(keyword);
        }

        // Wildcard match
        if pattern.starts_with("*.") {
            let suffix = &pattern[2..];
            return domain.ends_with(suffix) || domain == suffix;
        }

        // Exact match (default)
        domain == pattern
    }
}
