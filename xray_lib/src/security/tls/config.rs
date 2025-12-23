use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TlsConfig {
    pub server_name: String,
    pub verify: Option<bool>,
    pub is_early_data: Option<bool>,
    pub early_data_len: Option<usize>,
    pub alpn: Option<Vec<String>>,
}
