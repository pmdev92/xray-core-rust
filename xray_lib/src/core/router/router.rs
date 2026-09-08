use crate::core::context::Context;
use crate::core::router::balancer::Balancer;
use crate::core::router::config::RouterConfig;
use crate::core::router::group_conditions::GroupConditions;
use crate::core::router::{Apply, RouteLocation};
use log::{info, trace, warn};
use std::collections::HashMap;
use std::sync::Arc;

pub struct Router {
    pub balancers: HashMap<String, Balancer>,
    pub matchers: Vec<GroupConditions>,
}

impl Router {
    pub fn have_any_matcher(&self) -> bool {
        self.matchers.len() > 0
    }
    pub fn new(router_config: &Option<RouterConfig>) -> Self {
        let mut router = Self {
            balancers: HashMap::new(),
            matchers: Vec::new(),
        };
        if let Some(router_config) = router_config {
            if let Some(balancers) = &router_config.balancers {
                for balancer_config in balancers {
                    let balancer = Balancer::new(balancer_config);
                    router
                        .balancers
                        .insert(balancer_config.tag.clone(), balancer);
                }
            }

            if let Some(rules) = &router_config.rules {
                for rule_config in rules {
                    router.matchers.push(GroupConditions::new(rule_config));
                }
            }
        }
        router
    }

    pub async fn get_outbound_tag(
        &self,
        context: Arc<Context>,
        route_location: Arc<RouteLocation>,
    ) -> Option<String> {
        trace!(
            "router: matching {} against {} rules",
            route_location,
            self.matchers.len()
        );
        for (i, matcher) in self.matchers.iter().enumerate() {
            if matcher.apply(route_location.clone()) {
                if let Some(tag) = &matcher.outbound_tag {
                    info!("router: rule #{} matched -> outbound_tag={}", i + 1, tag);
                    return Some(tag.clone());
                }
                if let Some(balancer_tag) = &matcher.balancer_tag {
                    let balancer = self.balancers.get(balancer_tag);
                    if let Some(balancer) = balancer {
                        let tag = balancer.balance_outbound_tag(context.clone()).await;
                        info!(
                            "router: rule #{} matched -> balancer_tag={} -> outbound_tag={:?}",
                            i + 1,
                            balancer_tag,
                            tag
                        );
                        return Some(tag.0);
                    } else {
                        warn!(
                            "router: balancer tag `{}` not exists in router balancer list",
                            balancer_tag
                        );
                    }
                }
            }
        }
        trace!("router: no rule matched for {}", route_location);
        None
    }
}
