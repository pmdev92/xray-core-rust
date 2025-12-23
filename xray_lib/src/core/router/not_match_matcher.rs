use crate::core::router::RouteLocation;
use std::sync::Arc;

pub(crate) struct CacheMatchMatcher {
    pub(crate) route_location: RouteLocation,
    pub(crate) result: bool,
}
impl CacheMatchMatcher {
    pub fn new(route_location: RouteLocation, result: bool) -> Self {
        Self {
            route_location,
            result,
        }
    }

    pub(crate) fn apply(&self, route_location: Arc<RouteLocation>) -> Option<bool> {
        if *route_location == self.route_location {
            return Some(self.result.clone());
        }
        None
    }
}
