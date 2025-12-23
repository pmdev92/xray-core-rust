use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StatsConfig {
    pub enable: bool,
}

impl StatsConfig {
    pub fn default() -> Self {
        StatsConfig { enable: false }
    }
}
