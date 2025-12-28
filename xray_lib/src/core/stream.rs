use serde::{Deserialize, Serialize};

use crate::security::reality::config::RealityConfig;
use crate::security::tls::config::TlsConfig;
use crate::stream::fragment::config::FragmentConfig;
use crate::transport::grpc::config::GrpcConfig;
use crate::transport::http2::config::HttpConfig;
use crate::transport::http_upgrade::config::HttpUpgradeConfig;
use crate::transport::tcp::config::TcpConfig;
use crate::transport::websocket::config::WebsocketConfig;
use crate::transport::xhttp::config::XHttpConfig;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StreamSettings {
    pub transport: String,
    pub security: String,
    pub tls_settings: Option<TlsConfig>,
    pub reality_settings: Option<RealityConfig>,
    pub tcp_settings: Option<TcpConfig>,
    pub httpupgrade_settings: Option<HttpUpgradeConfig>,
    pub ws_settings: Option<WebsocketConfig>,
    pub xhttp_settings: Option<XHttpConfig>,
    pub http_settings: Option<HttpConfig>,
    pub grpc_settings: Option<GrpcConfig>,
    pub fragment_settings: Option<FragmentConfig>,
}

impl StreamSettings {
    pub fn new(transport: &str, security: &str) -> StreamSettings {
        Self {
            transport: transport.to_string(),
            security: security.to_string(),
            tls_settings: None,
            reality_settings: None,
            tcp_settings: None,
            ws_settings: None,
            xhttp_settings: None,
            http_settings: None,
            grpc_settings: None,
            httpupgrade_settings: None,
            fragment_settings: None,
        }
    }
}
