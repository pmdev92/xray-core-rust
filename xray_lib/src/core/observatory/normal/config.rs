use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct NormalObservationConfig {
    pub destination: Option<String>,
    pub interval: Option<String>,
    pub enable_concurrency: Option<bool>,
}
