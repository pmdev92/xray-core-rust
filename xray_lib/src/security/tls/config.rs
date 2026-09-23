use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TlsConfig {
    pub server_name: String,
    pub verify: Option<bool>,
    pub is_early_data: Option<bool>,
    pub early_data_len: Option<usize>,
    pub alpn: Option<Vec<String>>,
    pub pinned_peer_cert_sha256: Option<Vec<String>>,
    pub verify_peer_cert_by_name: Option<Vec<String>>,
    pub ech_config_list: Option<String>,
}
