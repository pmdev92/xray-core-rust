use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RouterConfig {
    pub rules: Option<Vec<RuleConfig>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RuleConfig {
    pub protocol: Option<Vec<String>>,
    pub network: Option<Vec<String>>,
    pub port: Option<String>,
    pub domain: Option<Vec<String>>,
    pub ip: Option<Vec<String>>,
    pub outbound_tag: String,
}
