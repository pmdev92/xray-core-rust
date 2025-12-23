// use base64::prelude::BASE64_STANDARD_NO_PAD;
// use base64::Engine;
// use serde_json::value::RawValue;
// use std::collections::HashMap;
// use url::Url;
//
// use xray_lib::core::inbound::InboundConfig;
// use xray_lib::core::outbound::OutboundConfig;
// use xray_lib::core::stream::*;
// use xray_lib::inbound::socks::config::Socks5InboundSettings;
// use xray_lib::security::reality::config::*;
// use xray_lib::security::tls::config::*;
// use xray_lib::stream::fragment::config::FragmentConfig;
//
// pub fn parse_url(config_link: String) -> Option<xray_lib::config::config::Config> {
//     let url = Url::parse(config_link.as_str()).ok()?;
//     let mut query_strings: HashMap<String, String> = HashMap::new();
//     for (key, val) in url.query_pairs() {
//         query_strings.insert(key.to_string(), val.to_string());
//     }
//     let outbound = parse_protocol(&url, parse_query_string(&url, &query_strings)).unwrap();
//     let socks5_settings = Socks5InboundSettings {
//         port: 4080,
//         listen: "127.0.0.1".to_string(),
//     };
//     let socks5_settings = Some(serde_json::value::to_raw_value(&socks5_settings).unwrap());
//
//     let config = xray_lib::config::config::Config {
//         memory: None,
//         log: None,
//         inbounds: vec![InboundConfig {
//             settings: socks5_settings,
//             protocol: "socks".to_string(),
//             tag: None,
//         }],
//         outbounds: vec![outbound],
//         router: None,
//         stats: None,
//     };
//     return Some(config);
// }
//
// fn parse_query_string(url: &Url, query_strings: &HashMap<String, String>) -> StreamSettings {
//     let empty = "".to_string();
//     let security_type = query_strings.get("security").unwrap_or(&empty).as_str();
//     let mut security = "";
//
//     let sni = url.domain().unwrap_or("").to_string();
//     let sni = query_strings.get("sni").cloned().unwrap_or_else(|| sni);
//     let alpn = None;
//     let alpn = match query_strings.get("alpn").cloned() {
//         None => alpn,
//         Some(alpn) => Some(alpn.split(',').map(str::to_string).collect::<Vec<String>>()),
//     };
//     let tls_settings = match security_type {
//         "tls" => {
//             security = "tls";
//             Some(TlsConfig {
//                 server_name: sni.clone(),
//                 verify: Some(false),
//                 alpn,
//             })
//         }
//         _ => None,
//     };
//     let reality_settings = match security_type {
//         "reality" => {
//             security = "reality";
//             Some(RealityConfig {
//                 public_key: query_strings.get("pbk").unwrap_or(&empty).to_string(),
//                 short_id: query_strings.get("sid").unwrap_or(&empty).to_string(),
//                 server_name: sni.clone(),
//                 version_x: None,
//                 version_y: None,
//                 version_z: None,
//             })
//         }
//         _ => None,
//     };
//
//     let stream_type = query_strings.get("type").unwrap_or(&empty).as_str();
//
//     let mut stream_settings = match stream_type {
//         "tcp" => {
//             let mut stream_settings = StreamSettings::new("tcp", security);
//             stream_settings.tcp_settings = Some(xray_lib::transport::tcp::config::TcpConfig {
//                 r#type: None,
//                 request: None,
//             });
//             stream_settings
//         }
//         "ws" => {
//             let mut stream_settings = StreamSettings::new("ws", security);
//             stream_settings.ws_settings =
//                 Some(xray_lib::transport::websocket::config::WebsocketConfig {
//                     host: query_strings.get("host").cloned(),
//                     path: query_strings.get("path").cloned(),
//                 });
//             stream_settings
//         }
//         "http" => {
//             let mut stream_settings = StreamSettings::new("http", security);
//             stream_settings.http_settings = Some(xray_lib::transport::http2::config::HttpConfig {
//                 host: query_strings.get("host").cloned(),
//                 path: query_strings.get("path").cloned(),
//             });
//             stream_settings
//         }
//         "grpc" => {
//             let mut stream_settings = StreamSettings::new("grpc", security);
//             stream_settings.grpc_settings = Some(xray_lib::transport::grpc::config::GrpcConfig {
//                 service_name: query_strings.get("path").cloned(),
//             });
//             stream_settings
//         }
//         _ => StreamSettings::new("tcp", security),
//     };
//     let mut fragment_settings: Option<FragmentConfig> = None;
//     let fragment = query_strings.get("fragment").unwrap_or(&empty).as_str();
//     if !fragment.is_empty() {
//         let parts = fragment.split(",");
//         let collection = parts.collect::<Vec<&str>>();
//         if collection.len() == 3 {
//             let mut settings = FragmentConfig {
//                 packets_from: 0,
//                 packets_to: 1,
//                 length_min: 100,
//                 length_max: 150,
//                 interval_min: 10,
//                 interval_max: 15,
//             };
//             let interval = collection[0].split("-").collect::<Vec<&str>>();
//             if interval.len() == 2 {
//                 settings.interval_min = interval[0].parse::<u64>().unwrap_or(10);
//                 settings.interval_max = interval[1].parse::<u64>().unwrap_or(15);
//             }
//             let count = collection[1].split("-").collect::<Vec<&str>>();
//             if count.len() == 2 {
//                 settings.length_min = count[0].parse::<u64>().unwrap_or(100);
//                 settings.length_max = count[1].parse::<u64>().unwrap_or(150);
//             }
//             let packets = collection[2].split("-").collect::<Vec<&str>>();
//
//             if packets.len() == 2 {
//                 settings.packets_from = packets[0].parse::<u64>().unwrap_or(0);
//                 settings.packets_to = packets[1].parse::<u64>().unwrap_or(1);
//             }
//
//             fragment_settings = Some(settings);
//         }
//     }
//     stream_settings.tls_settings = tls_settings;
//     stream_settings.reality_settings = reality_settings;
//     stream_settings.fragment_settings = fragment_settings;
//
//     stream_settings
// }
// fn parse_protocol(url: &Url, stream_settings: StreamSettings) -> Option<OutboundConfig> {
//     let tag = Some("proxy".to_string());
//     let mut outbound = OutboundConfig {
//         tag,
//         protocol: url.scheme().to_string(),
//         settings: None,
//         stream_settings: Some(stream_settings),
//         detour: None,
//     };
//
//     match url.scheme() {
//         "vless" => {
//             let setting = xray_lib::outbound::vless::config::VlessSettings {
//                 address: url.domain().unwrap().to_string(),
//                 port: url.port().unwrap().to_string().parse().unwrap(),
//                 id: url.username().to_string(),
//                 flow: None,
//             };
//             let result = RawValue::from_string(serde_json::to_string(&setting).unwrap()).unwrap();
//             outbound.settings = Some(result);
//             Some(outbound)
//         }
//         "trojan" => {
//             let setting = xray_lib::outbound::trojan::config::TrojanSettings {
//                 address: url.domain().unwrap().to_string(),
//                 port: url.port().unwrap().to_string().parse().unwrap(),
//                 password: url.username().to_string(),
//             };
//             let result = RawValue::from_string(serde_json::to_string(&setting).unwrap()).unwrap();
//             outbound.settings = Some(result);
//             Some(outbound)
//         }
//         "ss" => {
//             outbound.protocol = "shadowsocks".to_string();
//             let user = url.username();
//             let user = BASE64_STANDARD_NO_PAD.decode(user.as_bytes()).unwrap();
//             let user = String::from_utf8_lossy(user.as_slice());
//             let user = user.split(":");
//             let user = user.collect::<Vec<&str>>();
//             let setting = xray_lib::outbound::shadowsocks::config::ShadowSocksSettings {
//                 address: url.domain().unwrap().to_string(),
//                 port: url.port().unwrap().to_string().parse().unwrap(),
//                 method: user[0].to_string(),
//                 password: user[1].to_string(),
//                 uot: None,
//                 uot_version: None,
//                 uot_is_connect: None,
//             };
//             let result = RawValue::from_string(serde_json::to_string(&setting).unwrap()).unwrap();
//             outbound.settings = Some(result);
//             Some(outbound)
//         }
//         _ => None,
//     }
// }
