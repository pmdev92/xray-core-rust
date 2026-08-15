use std::collections::BTreeSet;
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
    pub fn new(rules: String) -> Self {
        let rules = parse_u16_list(rules);
        Self { ports: rules }
    }
}

fn parse_u16_list(input: String) -> Vec<u16> {
    fn inner(input: String) -> Result<Vec<u16>, ()> {
        let mut set = BTreeSet::new();

        for part in input.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            if let Some((start, end)) = part.split_once('-') {
                let start: u16 = start.trim().parse().map_err(|_| ())?;
                let end: u16 = end.trim().parse().map_err(|_| ())?;

                if start > end {
                    return Err(());
                }

                for v in start..=end {
                    set.insert(v);
                }
            } else {
                let value: u16 = part.parse().map_err(|_| ())?;
                set.insert(value);
            }
        }

        Ok(set.into_iter().collect())
    }

    inner(input).unwrap_or_default()
}
