use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct BrustObservationConfig {
    pub destination: Option<String>,
    pub connectivity: Option<String>,
    pub interval: Option<String>,
    pub timeout: Option<String>,
    pub sampling_count: Option<usize>,
    pub request_check_all: Option<bool>,
}
