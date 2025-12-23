use std::sync::Arc;

use crate::core::router::config::RouterConfig;
use crate::core::router::group_conditions::GroupConditions;
use crate::core::router::{Apply, RouteLocation};

pub struct Router {
    pub matchers: Vec<GroupConditions>,
}

impl Router {
    pub fn have_any_matcher(&self) -> bool {
        self.matchers.len() > 0
    }
    pub fn new(router_config: &Option<RouterConfig>) -> Self {
        let mut router = Self {
            matchers: Vec::new(),
        };
        match router_config {
            None => {}
            Some(router_config) => match &router_config.rules {
                None => {}
                Some(rules) => {
                    for rule_config in rules {
                        router.matchers.push(GroupConditions::new(rule_config));
                    }
                }
            },
        }
        return router;
    }

    pub fn get_outbound_tag(&self, route_location: Arc<RouteLocation>) -> Option<String> {
        for matcher in self.matchers.iter() {
            if matcher.apply(route_location.clone()) {
                return Some(matcher.outbound_tag.clone());
            }
        }
        return None;
    }
}
