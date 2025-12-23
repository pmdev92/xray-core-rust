use crate::config::log::LogConfig;
use crate::config::stats::StatsConfig;
use crate::core::dispatcher::DispatcherItem;
use crate::core::inbound::{InboundConfig, InboundTcp};
use crate::core::outbound::{Outbound, OutboundConfig};
use crate::core::router::config::RouterConfig;
use crate::core::router::router::Router;
use crate::core::security::Security;
use crate::core::transport::Transport;
use crate::inbound::http::config::HttpInboundSettings;
use crate::inbound::http::HttpInbound;
use crate::inbound::socks::config::Socks5InboundSettings;
use crate::inbound::socks::Socks5Inbound;
use crate::outbound::block::BlockOutbound;
use crate::outbound::direct::DirectOutbound;
use crate::outbound::quinn_hysteria2::config::HysteriaQuinnSettings;
use crate::outbound::quinn_hysteria2::HysteriaQuinnOutbound;
use crate::outbound::quinn_tuic::config::TuicQuinnSettings;
use crate::outbound::quinn_tuic::TuicQuinnOutbound;
use crate::outbound::shadowsocks::config::ShadowSocksSettings;
use crate::outbound::shadowsocks::ShadowSocksOutbound;
use crate::outbound::socks5::config::Socks5Settings;
use crate::outbound::socks5::Socks5Outbound;
use crate::outbound::trojan::config::TrojanSettings;
use crate::outbound::trojan::TrojanOutbound;
use crate::outbound::vless::config::VlessSettings;
use crate::outbound::vless::VlessOutbound;
use crate::outbound::vmess::config::VmessSettings;
use crate::outbound::vmess::VmessOutbound;
use crate::security::reality::RealitySecurity;
use crate::security::tls::TlsSecurity;
use crate::transport::grpc::GrpcTransport;
use crate::transport::http2::Http2Transport;
use crate::transport::http_hpgrade::HttpUpgradeTransport;
use crate::transport::tcp::TcpTransport;
use crate::transport::websocket::WebsocketTransport;
use crate::transport::xhttp::XHttpTransport;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use std::io;
use std::io::ErrorKind;
use std::sync::Arc;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    pub memory: Option<MemoryConfig>,
    pub log: Option<LogConfig>,
    pub inbounds: Vec<InboundConfig>,
    pub outbounds: Vec<OutboundConfig>,
    pub router: Option<RouterConfig>,
    pub stats: Option<StatsConfig>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MemoryConfig {
    pub max: usize,
}

impl Config {
    pub(crate) fn build_inbounds(&self) -> io::Result<Vec<Box<dyn InboundTcp>>> {
        let mut inbounds: Vec<Box<dyn InboundTcp>> = vec![];
        for inbounds_config in self.inbounds.iter() {
            let inbound_instance: Box<dyn InboundTcp> = match inbounds_config.protocol.as_str() {
                // "tun" => {
                //     let Some(setting) = &inbounds_config.settings else {
                //         let error = io::Error::new(
                //             ErrorKind::InvalidData,
                //             "tun inbound must have setting".to_string(),
                //         );
                //         return Err(error);
                //     };
                //     let result: io::Result<TunInboundSettings> =
                //         serde_json::from_str(setting.get())
                //             .map_err(|err| io::Error::new(ErrorKind::InvalidData, err.to_string()));
                //     let Ok(setting) = result else {
                //         return Err(result.err().unwrap());
                //     };
                //
                //     Box::new(TunInbound::new(setting))
                // }
                "socks" => {
                    let Some(setting) = &inbounds_config.settings else {
                        let error = io::Error::new(
                            ErrorKind::InvalidData,
                            "socks 5 inbound must have setting".to_string(),
                        );
                        return Err(error);
                    };
                    let result: io::Result<Socks5InboundSettings> =
                        serde_json::from_str(setting.get())
                            .map_err(|err| io::Error::new(ErrorKind::InvalidData, err.to_string()));
                    let Ok(setting) = result else {
                        return Err(result.err().unwrap());
                    };

                    Box::new(Socks5Inbound::new(setting))
                }
                "http" => {
                    let Some(setting) = &inbounds_config.settings else {
                        let error = io::Error::new(
                            ErrorKind::InvalidData,
                            "http inbound must have setting".to_string(),
                        );
                        return Err(error);
                    };
                    let result: io::Result<HttpInboundSettings> =
                        serde_json::from_str(setting.get())
                            .map_err(|err| io::Error::new(ErrorKind::InvalidData, err.to_string()));
                    let Ok(setting) = result else {
                        return Err(result.err().unwrap());
                    };

                    Box::new(HttpInbound::new(setting))
                }
                _ => {
                    panic!("inbound not valid")
                }
            };
            inbounds.push(inbound_instance);
        }
        Ok(inbounds)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ServerEndpoint<'a> {
    pub address: String,
    pub port: u32,
    #[serde(borrow)]
    pub user: Option<Vec<&'a RawValue>>,
}

impl Config {
    pub fn to_json_string(&self) -> serde_json::Result<String> {
        return serde_json::to_string_pretty(self);
    }

    pub fn build_outbounds(&self) -> io::Result<Vec<DispatcherItem>> {
        let mut outbounds: Vec<DispatcherItem> = vec![];

        for outbound_config in self.outbounds.iter() {
            let mut transport: Option<Box<dyn Transport>> = None;
            match &outbound_config.stream_settings {
                None => {
                    transport = Some(Box::new(TcpTransport::new(
                        outbound_config.stream_settings.clone(),
                        None,
                        None,
                    )));
                }
                Some(stream_setting) => {
                    let mut security_setting: Option<Box<dyn Security>> = None;
                    match stream_setting.security.as_str() {
                        "tls" => match &stream_setting.tls_settings {
                            None => {
                                return Err(io::Error::new(
                                    ErrorKind::InvalidData,
                                    "the tls security must have tls_settings".to_string(),
                                ));
                            }
                            Some(tls_setting) => {
                                security_setting = Some(Box::new(TlsSecurity::new(tls_setting)));
                            }
                        },
                        "reality" => match &stream_setting.reality_settings {
                            None => {
                                return Err(io::Error::new(
                                    ErrorKind::InvalidData,
                                    "the reality security must have reality_settings".to_string(),
                                ));
                            }
                            Some(reality_setting) => {
                                security_setting =
                                    Some(Box::new(RealitySecurity::new(reality_setting)));
                            }
                        },
                        _ => {}
                    }

                    match stream_setting.transport.as_str() {
                        "tcp" => {
                            transport = Some(Box::new(TcpTransport::new(
                                outbound_config.stream_settings.clone(),
                                stream_setting.tcp_settings.clone(),
                                security_setting,
                            )));
                        }
                        "xhttp" => {
                            transport = Some(Box::new(XHttpTransport::new(
                                outbound_config.stream_settings.clone(),
                                stream_setting.x_http_settings.clone(),
                                security_setting,
                            )));
                        }
                        "ws" => {
                            transport = Some(Box::new(WebsocketTransport::new(
                                outbound_config.stream_settings.clone(),
                                stream_setting.ws_settings.clone(),
                                security_setting,
                            )));
                        }
                        "http_upgrade" => {
                            transport = Some(Box::new(HttpUpgradeTransport::new(
                                outbound_config.stream_settings.clone(),
                                stream_setting.http_upgrade_settings.clone(),
                                security_setting,
                            )));
                        }
                        "http" => {
                            transport = Some(Box::new(Http2Transport::new(
                                outbound_config.stream_settings.clone(),
                                stream_setting.http_settings.clone(),
                                security_setting,
                            )));
                        }
                        "grpc" => {
                            transport = Some(Box::new(GrpcTransport::new(
                                outbound_config.stream_settings.clone(),
                                stream_setting.grpc_settings.clone(),
                                security_setting,
                            )));
                        }
                        _ => {}
                    }
                }
            }

            let outbound_instance = match outbound_config.protocol.as_str() {
                "tuic" => {
                    let Some(setting) = &outbound_config.settings else {
                        let error = io::Error::new(
                            ErrorKind::InvalidData,
                            "tuic outbound must have setting".to_string(),
                        );
                        return Err(error);
                    };
                    let result: io::Result<TuicQuinnSettings> = serde_json::from_str(setting.get())
                        .map_err(|err| io::Error::new(ErrorKind::InvalidData, err.to_string()));

                    let Ok(tuic_setting) = result else {
                        return Err(result.err().unwrap());
                    };

                    let outbound: Box<Arc<dyn Outbound>> =
                        Box::new(Arc::new(TuicQuinnOutbound::new(tuic_setting)?));
                    outbound
                }
                "quinn_tuic" => {
                    let Some(setting) = &outbound_config.settings else {
                        let error = io::Error::new(
                            ErrorKind::InvalidData,
                            "tuic outbound must have setting".to_string(),
                        );
                        return Err(error);
                    };
                    let result: io::Result<TuicQuinnSettings> = serde_json::from_str(setting.get())
                        .map_err(|err| io::Error::new(ErrorKind::InvalidData, err.to_string()));

                    let Ok(tuic_setting) = result else {
                        return Err(result.err().unwrap());
                    };

                    let outbound: Box<Arc<dyn Outbound>> =
                        Box::new(Arc::new(TuicQuinnOutbound::new(tuic_setting)?));
                    outbound
                }
                "hysteria2" => {
                    let Some(setting) = &outbound_config.settings else {
                        let error = io::Error::new(
                            ErrorKind::InvalidData,
                            "hysteria2 outbound must have setting".to_string(),
                        );
                        return Err(error);
                    };
                    let result: io::Result<HysteriaQuinnSettings> =
                        serde_json::from_str(setting.get())
                            .map_err(|err| io::Error::new(ErrorKind::InvalidData, err.to_string()));

                    let Ok(hysteria2_setting) = result else {
                        return Err(result.err().unwrap());
                    };

                    let outbound: Box<Arc<dyn Outbound>> =
                        Box::new(Arc::new(HysteriaQuinnOutbound::new(hysteria2_setting)));
                    outbound
                }
                "quinn_hysteria2" => {
                    let Some(setting) = &outbound_config.settings else {
                        let error = io::Error::new(
                            ErrorKind::InvalidData,
                            "hysteria2 outbound must have setting".to_string(),
                        );
                        return Err(error);
                    };
                    let result: io::Result<HysteriaQuinnSettings> =
                        serde_json::from_str(setting.get())
                            .map_err(|err| io::Error::new(ErrorKind::InvalidData, err.to_string()));

                    let Ok(hysteria2_setting) = result else {
                        return Err(result.err().unwrap());
                    };

                    let outbound: Box<Arc<dyn Outbound>> =
                        Box::new(Arc::new(HysteriaQuinnOutbound::new(hysteria2_setting)));
                    outbound
                }
                "freedom" => {
                    let outbound: Box<Arc<dyn Outbound>> =
                        Box::new(Arc::new(DirectOutbound::new()));
                    outbound
                }
                "block" => {
                    let outbound: Box<Arc<dyn Outbound>> = Box::new(Arc::new(BlockOutbound::new()));
                    outbound
                }
                "vmess" => {
                    let Some(transport) = transport else {
                        let error = io::Error::new(
                            ErrorKind::InvalidData,
                            "vmess outbound must have transport".to_string(),
                        );
                        return Err(error);
                    };

                    let Some(setting) = &outbound_config.settings else {
                        let error = io::Error::new(
                            ErrorKind::InvalidData,
                            "vmess outbound must have setting".to_string(),
                        );
                        return Err(error);
                    };
                    let result: io::Result<VmessSettings> = serde_json::from_str(setting.get())
                        .map_err(|err| io::Error::new(ErrorKind::InvalidData, err.to_string()));

                    let Ok(vmess_setting) = result else {
                        return Err(result.err().unwrap());
                    };

                    let outbound: Box<Arc<dyn Outbound>> =
                        Box::new(Arc::new(VmessOutbound::new(vmess_setting, transport)));
                    outbound
                }
                "vless" => {
                    let Some(transport) = transport else {
                        let error = io::Error::new(
                            ErrorKind::InvalidData,
                            "vless outbound must have transport".to_string(),
                        );
                        return Err(error);
                    };

                    let Some(setting) = &outbound_config.settings else {
                        let error = io::Error::new(
                            ErrorKind::InvalidData,
                            "vless outbound must have setting".to_string(),
                        );
                        return Err(error);
                    };
                    let result: io::Result<VlessSettings> = serde_json::from_str(setting.get())
                        .map_err(|err| io::Error::new(ErrorKind::InvalidData, err.to_string()));

                    let Ok(vless_setting) = result else {
                        return Err(result.err().unwrap());
                    };

                    let outbound: Box<Arc<dyn Outbound>> =
                        Box::new(Arc::new(VlessOutbound::new(vless_setting, transport)));
                    outbound
                }
                "trojan" => {
                    let Some(transport) = transport else {
                        let error = io::Error::new(
                            ErrorKind::InvalidData,
                            "vless outbound must have transport".to_string(),
                        );
                        return Err(error);
                    };

                    let Some(setting) = &outbound_config.settings else {
                        let error = io::Error::new(
                            ErrorKind::InvalidData,
                            "vless outbound must have setting".to_string(),
                        );
                        return Err(error);
                    };
                    let result: io::Result<TrojanSettings> = serde_json::from_str(setting.get())
                        .map_err(|err| io::Error::new(ErrorKind::InvalidData, err.to_string()));

                    let Ok(trojan_setting) = result else {
                        return Err(result.err().unwrap());
                    };

                    let outbound: Box<Arc<dyn Outbound>> =
                        Box::new(Arc::new(TrojanOutbound::new(trojan_setting, transport)));
                    outbound
                }
                "shadowsocks" => {
                    let Some(transport) = transport else {
                        let error = io::Error::new(
                            ErrorKind::InvalidData,
                            "shadow socks outbound must have transport".to_string(),
                        );
                        return Err(error);
                    };

                    let Some(setting) = &outbound_config.settings else {
                        let error = io::Error::new(
                            ErrorKind::InvalidData,
                            "shadow socks outbound must have setting".to_string(),
                        );
                        return Err(error);
                    };
                    let result: io::Result<ShadowSocksSettings> =
                        serde_json::from_str(setting.get())
                            .map_err(|err| io::Error::new(ErrorKind::InvalidData, err.to_string()));

                    let Ok(shadow_socks_settings) = result else {
                        return Err(result.err().unwrap());
                    };
                    let result = ShadowSocksOutbound::new(shadow_socks_settings, transport)?;
                    let outbound: Box<Arc<dyn Outbound>> = Box::new(Arc::new(result));
                    outbound
                }
                "socks5" => {
                    let Some(transport) = transport else {
                        let error = io::Error::new(
                            ErrorKind::InvalidData,
                            "socks outbound must have transport".to_string(),
                        );
                        return Err(error);
                    };

                    let Some(setting) = &outbound_config.settings else {
                        let error = io::Error::new(
                            ErrorKind::InvalidData,
                            "socks outbound must have setting".to_string(),
                        );
                        return Err(error);
                    };
                    let result: io::Result<Socks5Settings> = serde_json::from_str(setting.get())
                        .map_err(|err| io::Error::new(ErrorKind::InvalidData, err.to_string()));

                    let Ok(socks5_settings) = result else {
                        return Err(result.err().unwrap());
                    };
                    let result = Socks5Outbound::new(socks5_settings, transport)?;
                    let outbound: Box<Arc<dyn Outbound>> = Box::new(Arc::new(result));
                    outbound
                }
                _ => {
                    panic!("outbound not valid")
                }
            };
            outbounds.push(DispatcherItem::new(
                outbound_config.tag.clone(),
                outbound_config.detour.clone(),
                outbound_instance,
            ));
        }
        return Ok(outbounds);
    }

    pub fn build_router(&self) -> io::Result<Router> {
        return Ok(Router::new(&self.router));
    }
}
