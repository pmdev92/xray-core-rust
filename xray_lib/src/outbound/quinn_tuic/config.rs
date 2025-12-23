use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct TuicQuinnSettings {
    pub address: String,
    pub port: u16,
    pub password: String,
    pub uuid: String,
    pub tls_config: TuicTlsSettings,
    pub heartbeat: Option<String>,
    pub congestion_control: Option<String>,
    pub udp_relay_mode: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TuicTlsSettings {
    pub server_name: String,
    pub verify: Option<bool>,
    pub alpn: Option<Vec<String>>,
    pub disable_sni: Option<bool>,
    pub zero_rtt: Option<bool>,
}
