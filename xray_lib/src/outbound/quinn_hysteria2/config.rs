use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct HysteriaQuinnSettings {
    pub address: String,
    pub port: u16,
    pub password: String,
    pub obfs_type: Option<String>,
    pub obfs_password: Option<String>,
    pub tls_config: Hysteria2TlsSettings,
    pub hop_ports: Option<String>,
    pub hop_intervals: Option<u32>,
    pub up_bandwidth: Option<u64>,
    pub down_bandwidth: Option<u64>,
    pub quic_max_idle_timeout: Option<u64>,
    pub quic_max_keep_alive_period: Option<u64>,
    pub quic_with_stream_data_window: Option<u64>,
    pub quic_with_connection_data_window: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Hysteria2TlsSettings {
    pub server_name: String,
    pub verify: Option<bool>,
}
