use crate::common::serde::uint_range::UIntRange;
use crate::security::reality::config::RealityConfig;
use crate::security::tls::config::TlsConfig;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct XHttpConfig {
    pub host: Option<String>,
    pub path: Option<String>,
    pub mode: Option<String>,
    pub extra: Option<Box<XHttpConfigExtra>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct XHttpConfigExtra {
    pub headers: Option<HashMap<String, String>>,
    pub no_grpc_header: Option<bool>,
    pub x_padding_bytes: Option<UIntRange>,
    pub x_padding_obfs_mode: Option<bool>,
    pub x_padding_key: Option<String>,
    pub x_padding_header: Option<String>,
    pub x_padding_placement: Option<String>,
    pub x_padding_method: Option<String>,
    pub sc_max_each_post_bytes: Option<UIntRange>,
    pub sc_min_posts_interval_ms: Option<UIntRange>,
    pub uplink_http_method: Option<String>,
    pub uplink_data_placement: Option<String>,
    pub uplink_data_key: Option<String>,
    pub uplink_chunk_size: Option<UIntRange>,
    pub session_placement: Option<String>,
    pub session_key: Option<String>,
    pub seq_placement: Option<String>,
    pub seq_key: Option<String>,
    pub xmux: Option<XmuxConfig>,
    pub download_settings: Option<XHttpConfigDownloadSettings>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct XmuxConfig {
    pub max_concurrency: Option<UIntRange>,
    pub max_connections: Option<UIntRange>,
    pub c_max_reuse_times: Option<UIntRange>,
    pub h_max_request_times: Option<UIntRange>,
    pub h_max_reusable_secs: Option<UIntRange>,
    pub h_keep_alive_period: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct XHttpConfigDownloadSettings {
    pub address: String,
    pub port: u16,
    pub transport: String,
    pub security: String,
    pub tls_settings: Option<TlsConfig>,
    pub reality_settings: Option<RealityConfig>,
    pub x_http_settings: Option<XHttpConfig>,
}
