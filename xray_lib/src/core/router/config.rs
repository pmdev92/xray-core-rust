use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RouterConfig {
    pub balancers: Option<Vec<BalancerConfig>>,
    pub rules: Option<Vec<RuleConfig>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BalancerConfig {
    pub tag: String,
    pub fallback_outbound_tag: String,
    pub observatory_tag: Option<String>,
    pub outbound_selector: Vec<String>,
    pub strategy: BalancerStrategy,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BalancerStrategy {
    pub method: String,
    pub settings: Option<Box<RawValue>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RuleConfig {
    pub protocol: Option<Vec<String>>,
    pub network: Option<Vec<String>>,
    pub port: Option<String>,
    pub domain: Option<Vec<String>>,
    pub ip: Option<Vec<String>>,
    pub outbound_tag: Option<String>,
    pub balancer_tag: Option<String>,
}
