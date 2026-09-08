use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct StrategyLeastLoadConfig {
    pub costs: Option<Vec<StrategyWeight>>,
    pub baselines: Option<Vec<String>>,
    pub expected: Option<usize>,
    pub max_rtt: Option<String>,
    pub tolerance: Option<f64>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StrategyWeight {
    pub regexp: bool,
    pub r#match: String,
    pub value: f64,
}
