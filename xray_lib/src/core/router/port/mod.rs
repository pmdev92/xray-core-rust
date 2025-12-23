use std::sync::Arc;

use crate::core::router::{Apply, RouteLocation};

pub(crate) struct PortMatcher {
    ports: Vec<u16>,
}

impl Apply for PortMatcher {
    fn apply(&self, route_location: Arc<RouteLocation>) -> bool {
        for port in &self.ports {
            if route_location.target_location.port == port.clone() {
                return true;
            }
        }
        false
    }
}

impl PortMatcher {
    pub fn new(raw_rules: &Vec<u16>) -> Self {
        Self {
            ports: raw_rules.clone(),
        }
    }
}
