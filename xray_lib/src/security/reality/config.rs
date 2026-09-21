use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RealityConfig {
    pub server_name: String,
    pub public_key: String,
    pub short_id: String,

    pub version_x: Option<u8>,
    pub version_y: Option<u8>,
    pub version_z: Option<u8>,
    pub is_early_data: Option<bool>,
    pub early_data_len: Option<usize>,
    pub alpn: Option<Vec<String>>,
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
