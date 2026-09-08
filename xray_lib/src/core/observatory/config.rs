use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ObservationConfig {
    pub settings: Option<Box<RawValue>>,
    pub method: String,
    pub selector: Vec<String>,
    pub tag: Option<String>,
}
