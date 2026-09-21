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
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum VerifyMode {
    False,
    True,
    PinnedPeerCertSha256,
    VerifyPeerCertByName,
}

impl Default for VerifyMode {
    fn default() -> Self {
        VerifyMode::False
    }
}
