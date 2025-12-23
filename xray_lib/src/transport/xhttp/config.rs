use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct XHttpConfig {
    pub host: Option<String>,
    pub path: Option<String>,
    pub mode: Option<String>,
    pub headers: Option<HashMap<String, String>>,
    pub no_grpc_header: Option<bool>,
    pub x_padding_bytes_min: Option<usize>,
    pub x_padding_bytes_max: Option<usize>,
    pub packet_up_interval_ms: Option<usize>,
}
