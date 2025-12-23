use crate::core::router::domain::full_domain_matcher::FullDomainMatcher;
use crate::core::router::domain::geo_domain_matcher::GeoDomainMatcher;
use crate::core::router::domain::partial_matcher::PartialMatcher;
use crate::core::router::domain::regular_expression_matcher::RegularExpressionMatcher;
use crate::core::router::domain::sub_domain_matcher::SubDomainMatcher;
use crate::core::router::{Apply, RouteLocation};
use std::sync::Arc;

mod full_domain_matcher;
mod geo_domain_matcher;
mod partial_matcher;
mod regular_expression_matcher;
mod sub_domain_matcher;

pub(crate) struct DomainMatcher {
    matchers: Vec<Box<dyn Apply>>,
}

impl Apply for DomainMatcher {
    fn apply(&self, route_location: Arc<RouteLocation>) -> bool {
        if !route_location.target_location.address.is_hostname() {
            match &route_location.sniff_result {
                None => {
                    return false;
                }
                Some(sniff) => {
                    if sniff.domains.len() == 0 {
                        return false;
                    }
                }
            }
        }

        for matcher in self.matchers.iter() {
            if matcher.apply(route_location.clone()) {
                return true;
            }
        }
        false
    }
}

impl DomainMatcher {
    pub fn new(raw_rules: &Vec<String>) -> Self {
        let mut rules: Vec<Box<dyn Apply>> = Vec::new();
        for rule in raw_rules {
            if rule.starts_with("geo:") {
                let path_code = rule.replace("geo:", "").clone();
                let path_code = path_code.split(",").collect::<Vec<&str>>();
                if path_code.len() != 2 {
                    continue;
                }
                let path = path_code[0];
                let code = path_code[1];
                let helper = GeoDomainMatcher::new(path.to_string(), code.to_string());
                rules.push(Box::new(helper));
            } else if rule.starts_with("regexp:") {
                let helper = RegularExpressionMatcher::new(rule.replace("regexp:", "").clone());
                rules.push(Box::new(helper));
            } else if rule.starts_with("full:") {
                let helper = FullDomainMatcher::new(rule.replace("full:", "").clone());
                rules.push(Box::new(helper));
            } else if rule.starts_with("domain:") {
                let helper = SubDomainMatcher::new(rule.replace("domain:", "").clone());

                rules.push(Box::new(helper));
            } else if rule.starts_with("keyword:") {
                let helper = PartialMatcher::new(rule.replace("keyword:", "").clone());

                rules.push(Box::new(helper));
            } else {
                let helper = PartialMatcher::new(rule.clone());
                rules.push(Box::new(helper));
            }
        }
        Self { matchers: rules }
    }
}
