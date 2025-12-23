use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FragmentConfig {
    pub packets_from: u64,
    pub packets_to: u64,
    pub length_min: u64,
    pub length_max: u64,
    pub interval_min: u64,
    pub interval_max: u64,
}
