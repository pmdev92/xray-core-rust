use std::env;
use std::path::{Path, PathBuf};
use crate::core::router::domain::full_domain_matcher::FullDomainMatcher;
use crate::core::router::domain::geo_domain_matcher::GeoDomainMatcher;
use crate::core::router::domain::partial_matcher::PartialMatcher;
use crate::core::router::domain::regular_expression_matcher::RegularExpressionMatcher;
use crate::core::router::domain::sub_domain_matcher::SubDomainMatcher;
use crate::core::router::{Apply, RouteLocation};
use std::sync::Arc;
use log::warn;
use crate::common::asset::get_asset_location;

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
                let geo = rule.replace("geo:", "").clone();
                let geo = geo.split(",").collect::<Vec<&str>>();
                if geo.len()<1 || geo.len()>2 {
                    warn!("router rule domain `{}` parse error", rule);
                    continue;
                }
                let mut file = "";
                let mut code = "";

                if geo.len() == 1 {
                     file = "geosite.dat";
                     code = geo[0];
                }else if geo.len() == 2 {
                     file = geo[0];
                     code = geo[1];
                }

                let path = if Path::new(file).is_relative() {
                    get_asset_location(file).to_string_lossy().into_owned()
                }else {
                    file.to_string()
                };

                let helper = GeoDomainMatcher::new(path, code.to_string());
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


