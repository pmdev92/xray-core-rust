use std::io;
use std::sync::Arc;

use crate::core::router::{Apply, Network, RouteLocation};

pub(crate) struct NetworkMatcher {
    networks: Vec<Network>,
}

impl Apply for NetworkMatcher {
    fn apply(&self, route_location: Arc<RouteLocation>) -> bool {
        for network in &self.networks {
            if route_location.network == network.clone() {
                return true;
            }
        }
        false
    }
}

impl NetworkMatcher {
    pub fn new(raw_rules: &Vec<String>) -> Self {
        let mut networks: Vec<Network> = vec![];
        for network in raw_rules {
            let result: Result<Network, io::Error> = network.as_str().try_into();
            match result {
                Ok(result) => {
                    networks.push(result);
                }
                Err(_) => {}
            }
        }
        Self { networks }
    }
}
