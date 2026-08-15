use crate::common::url_builder::UrlBuilder;
use crate::core::security::Security;
use crate::security::tls::config::TlsConfig;
use crate::transport::xhttp::config::{XHttpConfig, XHttpConfigExtra};
use crate::transport::xhttp::padding::XPaddingSettings;
use crate::transport::xhttp::xmux;
use crate::transport::xhttp::xmux::XmuxSettings;
use std::collections::HashMap;
use std::fmt::Display;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

pub const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36";
pub const PLACEMENT_QUERY_IN_HEADER: &str = "queryInHeader";
pub const PLACEMENT_COOKIE: &str = "cookie";
pub const PLACEMENT_HEADER: &str = "header";
pub const PLACEMENT_QUERY: &str = "query";
pub const PLACEMENT_PATH: &str = "path";
pub const PLACEMENT_BODY: &str = "body";
pub const METHOD_REPEAT_X: &str = "repeat-x";
pub const METHOD_TOKENISH: &str = "tokenish";
pub const CHARSET_BASE62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
pub const AVG_HUFFMAN_BYTES_PER_CHAR_BASE62: f64 = 0.8;
pub const VALIDATION_TOLERANCE: i32 = 2;
pub const XHTTP_PADDING_MIN: usize = 100;
pub const XHTTP_PADDING_MAX: usize = 1000;

#[derive(Debug, Clone)]
pub enum HttpVersion {
    V1,
    V2,
    V1_2,
    V3,
}

impl Display for HttpVersion {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            HttpVersion::V1 => fmt.write_str("HTTP/1.1")?,
            HttpVersion::V2 => fmt.write_str("HTTP/2")?,
            HttpVersion::V1_2 => {
                fmt.write_str("HTTP/1.1 & HTTP/2")?;
            }
            HttpVersion::V3 => fmt.write_str("HTTP/3")?,
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum Mode {
    PacketUp,
    StreamUp,
    StreamOne,
}

impl Display for Mode {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            Mode::PacketUp => fmt.write_str("packet-up")?,
            Mode::StreamUp => fmt.write_str("stream-up")?,
            Mode::StreamOne => fmt.write_str("stream-one")?,
        }
        Ok(())
    }
}

pub(crate) struct XhttpSettings {
    pub(crate) id: Uuid,
    pub(crate) x_mux_settings: XmuxSettings,
    pub(crate) http_version: HttpVersion,
    pub(crate) is_secure: bool,
    pub(crate) host: String,
    pub(crate) path: String,
    pub(crate) query: Option<HashMap<String, String>>,
    pub(crate) headers: Option<HashMap<String, String>>,
    pub(crate) padding: XPaddingSettings,
    pub(crate) packet_up_max_each_post_bytes: Option<usize>,
    pub(crate) packet_up_interval_ms: Option<usize>,
    pub(crate) no_grpc_header: Option<bool>,
    pub(crate) uplink_http_method: String,
    pub(crate) uplink_data_placement: String,
    pub(crate) uplink_data_key: String,
    pub(crate) uplink_chunk_size_min: usize,
    pub(crate) uplink_chunk_size_max: usize,
    pub(crate) session_placement: String,
    pub(crate) session_key: String,
    pub(crate) seq_placement: String,
    pub(crate) seq_key: String,
}

impl XhttpSettings {
    pub fn get_url_builder(&self) -> UrlBuilder {
        let mut base = UrlBuilder::new();
        base.host(self.host.as_str());
        base.path(self.path.as_str());
        if self.is_secure {
            base.scheme("https");
        } else {
            base.scheme("http");
        }
        if let Some(q) = self.query.as_ref() {
            for (key, value) in q {
                base.query(key.as_str(), value.as_str());
            }
        }
        base
    }

    pub fn parse(
        xhttp_config: Option<XHttpConfig>,
        http_version: HttpVersion,
        is_secure: bool,
    ) -> Self {
        let mut host = "".to_string();
        let mut path = "/".to_string();
        let mut x_mux_settings = XmuxSettings::default();
        let mut headers: Option<HashMap<String, String>> = None;
        let mut padding: XPaddingSettings = Default::default();
        let mut packet_up_max_each_post_bytes: Option<usize> = None;
        let mut no_grpc_header: Option<bool> = None;
        let mut packet_up_interval_ms: Option<usize> = None;
        let mut uplink_http_method = "POST".to_string();
        let mut uplink_data_placement = "body".to_string();
        let mut uplink_data_key = "x_data".to_string();
        let mut uplink_chunk_size_min: usize = 2 * 1024;
        let mut uplink_chunk_size_max: usize = 3 * 1024;
        let mut session_placement = "path".to_string();
        let mut session_key = "x_session".to_string();
        let mut seq_placement = "path".to_string();
        let mut seq_key = "x_seq".to_string();

        if let Some(xhttp_config) = xhttp_config {
            host = xhttp_config.host.unwrap_or(host);
            path = xhttp_config.path.unwrap_or(path);
            if let Some(extra) = xhttp_config.extra {
                if let Some(mux) = extra.xmux.as_ref() {
                    x_mux_settings = XmuxSettings::from_config(mux);
                }
                headers = extra.headers;
                no_grpc_header = extra.no_grpc_header;
                if let Some(ref v) = extra.sc_max_each_post_bytes {
                    packet_up_max_each_post_bytes = Some(v.max());
                }
                if let Some(ref v) = extra.sc_min_posts_interval_ms {
                    packet_up_interval_ms = Some(v.min());
                }
                if let Some(v) = extra.x_padding_bytes {
                    padding.min_bytes = v.min();
                    padding.max_bytes = v.max();
                }
                if let Some(v) = extra.x_padding_obfs_mode {
                    padding.obfs_mode = v;
                }
                if let Some(v) = extra.x_padding_key {
                    padding.key = v;
                }
                if let Some(v) = extra.x_padding_header {
                    padding.header = v;
                }
                if let Some(v) = extra.x_padding_placement {
                    padding.placement = v;
                }
                if let Some(v) = extra.x_padding_method {
                    padding.method = v;
                }
                if let Some(v) = extra.uplink_http_method {
                    uplink_http_method = v;
                }
                if let Some(v) = extra.uplink_data_placement {
                    uplink_data_placement = v;
                }
                if let Some(v) = extra.uplink_data_key {
                    uplink_data_key = v;
                }
                if let Some(v) = extra.uplink_chunk_size {
                    uplink_chunk_size_min = v.min();
                    uplink_chunk_size_max = v.max();
                }
                if let Some(v) = extra.session_placement {
                    session_placement = v;
                }
                if let Some(v) = extra.session_key {
                    session_key = v;
                }
                if let Some(v) = extra.seq_placement {
                    seq_placement = v;
                }
                if let Some(v) = extra.seq_key {
                    seq_key = v;
                }
            }
        }

        let query = get_query(&path);
        Self {
            id: Uuid::new_v4(),
            x_mux_settings,
            http_version,
            is_secure,
            host,
            path,
            query,
            headers,
            padding,
            packet_up_max_each_post_bytes,
            packet_up_interval_ms,
            no_grpc_header,
            uplink_http_method,
            uplink_data_placement,
            uplink_data_key,
            uplink_chunk_size_min,
            uplink_chunk_size_max,
            session_placement,
            session_key,
            seq_placement,
            seq_key,
        }
    }
}

pub(crate) struct UploadSettings {
    pub(crate) security: Arc<Option<Box<dyn Security>>>,
    pub(crate) mux_manager: Arc<Mutex<xmux::XmuxManager>>,
    pub(crate) xhttp_settings: Arc<XhttpSettings>,
}

pub(crate) struct DownloadSettings {
    pub(crate) address: Option<String>,
    pub(crate) port: Option<u16>,
    pub(crate) security: Arc<Option<Box<dyn Security>>>,
    pub(crate) mux_manager: Arc<Mutex<xmux::XmuxManager>>,
    pub(crate) xhttp_settings: Arc<XhttpSettings>,
}

impl DownloadSettings {
    pub fn parse(
        xhttp_config_extra: Option<Box<XHttpConfigExtra>>,
        upload_settings: &UploadSettings,
    ) -> Self {
        if let Some(extra) = xhttp_config_extra {
            if let Some(dl) = extra.download_settings {
                use crate::security::reality::RealitySecurity;
                use crate::security::tls::TlsSecurity;

                let download_security: Arc<Option<Box<dyn Security>>> = match dl.security.as_str() {
                    "tls" => match &dl.tls_settings {
                        None => Arc::new(None),
                        Some(tls) => {
                            Arc::new(Some(Box::new(TlsSecurity::new(tls)) as Box<dyn Security>))
                        }
                    },
                    "reality" => match &dl.reality_settings {
                        None => Arc::new(None),
                        Some(r) => {
                            Arc::new(Some(Box::new(RealitySecurity::new(r)) as Box<dyn Security>))
                        }
                    },
                    _ => Arc::new(None),
                };

                let is_secure = download_security.is_some();
                let xhttp_settings =
                    XhttpSettings::parse(dl.x_http_settings, HttpVersion::V2, is_secure);
                let mux = xmux::XmuxManager::new(&xhttp_settings.x_mux_settings);

                return Self {
                    address: Some(dl.address),
                    port: Some(dl.port),
                    security: download_security,
                    mux_manager: mux,
                    xhttp_settings: Arc::new(xhttp_settings),
                };
            }
        }

        Self {
            address: None,
            port: None,
            security: upload_settings.security.clone(),
            mux_manager: upload_settings.mux_manager.clone(),
            xhttp_settings: upload_settings.xhttp_settings.clone(),
        }
    }
}

pub(crate) fn decide_mode(mode: Option<String>) -> Mode {
    let mode = mode.unwrap_or("auto".to_string());
    if mode == "packet-up" {
        return Mode::PacketUp;
    }
    if mode == "stream-up" {
        return Mode::StreamUp;
    }
    if mode == "stream-one" {
        return Mode::StreamOne;
    }
    Mode::PacketUp
}

pub(crate) fn decide_http_version(
    security_type: Option<String>,
    tls_config: Option<TlsConfig>,
) -> HttpVersion {
    match security_type.as_ref() {
        None => HttpVersion::V1,
        Some(s) => {
            if s == "reality" {
                return HttpVersion::V1_2;
            }
            if s == "tls" {
                if let Some(tls) = tls_config.as_ref() {
                    if let Some(alpn) = &tls.alpn {
                        if alpn.len() > 0 {
                            return HttpVersion::V1_2;
                        }
                        if alpn[0] == "http/1.1" {
                            return HttpVersion::V1;
                        }
                        if alpn[0] == "h2" {
                            return HttpVersion::V2;
                        }
                        if alpn[0] == "h3" {
                            return HttpVersion::V3;
                        }
                    }
                }
                return HttpVersion::V1_2;
            }
            HttpVersion::V1
        }
    }
}

pub(crate) fn is_secure_link(security_type: Option<String>) -> bool {
    match security_type.as_ref() {
        None => false,
        Some(s) => s == "reality" || s == "tls",
    }
}

pub(crate) fn get_query(path: &str) -> Option<HashMap<String, String>> {
    if let Some((_, q)) = path.split_once('?') {
        let parsed: HashMap<_, _> = form_urlencoded::parse(q.as_bytes()).into_owned().collect();
        return Some(parsed);
    }
    None
}
