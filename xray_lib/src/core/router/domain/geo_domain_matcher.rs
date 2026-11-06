use crate::common::geo::GeoSiteDomainIter;
use crate::core::router::domain::full_domain_matcher::FullDomainMatcher;
use crate::core::router::domain::partial_matcher::PartialMatcher;
use crate::core::router::domain::regular_expression_matcher::RegularExpressionMatcher;
use crate::core::router::domain::sub_domain_matcher::SubDomainMatcher;
use crate::core::router::{Apply, RouteLocation};
use crate::protos::router::domain::Type;
use std::sync::Arc;

pub(crate) struct GeoDomainMatcher {
    path: String,
    code: String,
}
impl GeoDomainMatcher {
    pub fn new(path: String, code: String) -> Self {
        Self { path, code }
    }
}
impl Apply for GeoDomainMatcher {
    fn apply(&self, route_location: Arc<RouteLocation>) -> bool {
        let domains = match GeoSiteDomainIter::open(&self.path, &self.code) {
            Ok(domains) => domains,
            Err(error) => {
                error!("{}", error);
                return false;
            }
        };

        for domain in domains {
            let mut helper: Option<Box<dyn Apply>> = None;
            match domain.type_.enum_value() {
                Ok(domain_type) => match domain_type {
                    Type::Plain => {
                        helper = Some(Box::new(PartialMatcher::new(domain.value.clone())));
                    }
                    Type::Regex => {
                        helper = Some(Box::new(RegularExpressionMatcher::new(
                            domain.value.clone(),
                        )));
                    }
                    Type::Domain => {
                        helper = Some(Box::new(SubDomainMatcher::new(domain.value.clone())));
                    }
                    Type::Full => {
                        helper = Some(Box::new(FullDomainMatcher::new(domain.value.clone())));
                    }
                },
                Err(_) => {}
            }
            if let Some(matcher) = helper {
                let result = matcher.apply(route_location.clone());
                if result {
                    return result;
                }
            }
        }
        false
    }
}
use log::error;
