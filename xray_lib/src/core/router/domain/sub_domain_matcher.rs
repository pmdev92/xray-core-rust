use std::sync::Arc;

use crate::core::router::{Apply, RouteLocation};

pub(crate) struct SubDomainMatcher {
    pub(super) condition: String,
}
impl SubDomainMatcher {
    pub fn new(condition: String) -> Self {
        Self { condition }
    }
}
impl Apply for SubDomainMatcher {
    fn apply(&self, route_location: Arc<RouteLocation>) -> bool {
        let helper = ".".to_owned() + &self.condition;

        if route_location.target_location.address.is_hostname() {
            let domain = route_location.target_location.address.to_string().clone();
            if domain == self.condition {
                return true;
            }
            if domain.ends_with(&helper) {
                return true;
            }
        }
        match &route_location.sniff_result {
            None => {}
            Some(sniff_result) => {
                if sniff_result.domains.len() > 0 {
                    for domain in sniff_result.domains.iter() {
                        if domain == &self.condition {
                            return true;
                        }
                        if domain.ends_with(&helper) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }
}
