use std::sync::Arc;

use regex::Regex;

use crate::core::router::{Apply, RouteLocation};

pub(crate) struct RegularExpressionMatcher {
    pub(super) condition: String,
}
impl RegularExpressionMatcher {
    pub fn new(condition: String) -> Self {
        Self { condition }
    }
}
impl Apply for RegularExpressionMatcher {
    fn apply(&self, route_location: Arc<RouteLocation>) -> bool {
        let result = Regex::new(&self.condition.clone());
        match result {
            Ok(regex) => {
                if route_location.target_location.address.is_hostname() {
                    let domain = route_location.target_location.address.to_string().clone();
                    if regex.is_match(&domain) {
                        return true;
                    }
                }
                match &route_location.sniff_result {
                    None => {}
                    Some(sniff_result) => {
                        if sniff_result.domains.len() > 0 {
                            for domain in sniff_result.domains.iter() {
                                if regex.is_match(&domain) {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
            Err(_) => {}
        }
        return false;
    }
}
