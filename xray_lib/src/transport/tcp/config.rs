use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TcpConfig {
    pub r#type: Option<String>,
    pub request: Option<RequestConfig>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RequestConfig {
    pub version: Option<String>,
    pub method: Option<String>,
    pub path: Option<String>,
    pub headers: Option<Box<RawValue>>,
}
