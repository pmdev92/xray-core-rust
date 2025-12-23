use crate::core::router::{Apply, RouteLocation};
use crate::core::sniffer::SniffProtocol;
use std::io;
use std::sync::Arc;

pub(crate) struct ProtocolMatcher {
    protocols: Vec<SniffProtocol>,
}

impl Apply for ProtocolMatcher {
    fn apply(&self, route_location: Arc<RouteLocation>) -> bool {
        match &route_location.sniff_result {
            Some(sniff_result) => {
                for protocols in &self.protocols {
                    if sniff_result.protocol == protocols.clone() {
                        return true;
                    }
                }
            }
            None => {}
        }

        false
    }
}

impl ProtocolMatcher {
    pub fn new(raw_rules: &Vec<String>) -> Self {
        let mut protocols: Vec<SniffProtocol> = vec![];
        for protocol in raw_rules {
            let result: Result<SniffProtocol, io::Error> = protocol.as_str().try_into();
            match result {
                Ok(result) => {
                    protocols.push(result);
                }
                Err(_) => {}
            }
        }
        Self { protocols }
    }
}
