use crate::common::net_location::NetLocation;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::io;
use std::str::FromStr;
use std::sync::Arc;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DnsConfig {
    pub servers: Vec<DnsServer>,
    pub cache: Option<DnsCacheConfig>,
    pub rules: Option<Vec<DnsRule>>,
}

#[derive(Debug, Clone)]
pub struct DnsServer {
    pub address: String,
    pub port: u16,
    pub protocol: DnsProtocol,
    pub path: Option<String>,
    pub tag: Option<String>,
    pub outbound: Option<String>,
}

impl Serialize for DnsServer {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeMap;

        let mut map = serializer.serialize_map(None)?;

        map.serialize_entry("address", &self.url())?;

        if let Some(tag) = &self.tag {
            map.serialize_entry("tag", tag)?;
        }

        if let Some(outbound) = &self.outbound {
            map.serialize_entry("outbound", outbound)?;
        }

        map.end()
    }
}
impl<'de> Deserialize<'de> for DnsServer {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawDnsServer {
            address: String,
            path: Option<String>,
            tag: Option<String>,
            outbound: Option<String>,
        }

        let raw = RawDnsServer::deserialize(deserializer)?;

        let (mut protocol, address, port, url_path) = DnsServer::from_url(&raw.address)
            .ok_or_else(|| serde::de::Error::custom("Invalid DNS server address"))?;

        let path = raw.path.or(url_path);

        match &mut protocol {
            DnsProtocol::Https(protocol_path) | DnsProtocol::H3(protocol_path) => {
                if let Some(path) = &path {
                    *protocol_path = path.clone();
                }
            }
            _ => {}
        }

        Ok(Self {
            address,
            port,
            protocol,
            path,
            tag: raw.tag,
            outbound: raw.outbound,
        })
    }
}
impl DnsServer {
    pub fn net_location(&self) -> io::Result<Arc<NetLocation>> {
        Ok(Arc::new(NetLocation::from_str(
            format!("{}:{}", self.address, self.port).as_str(),
            None,
        )?))
    }

    fn url(&self) -> String {
        let scheme = match &self.protocol {
            DnsProtocol::Udp => "udp",

            DnsProtocol::Tcp => "tcp",

            DnsProtocol::Tls => "tls",

            DnsProtocol::Https(_) => "https",

            DnsProtocol::Quic => "quic",

            DnsProtocol::H3(_) => "h3",
        };

        let host = if self.address.contains(':') {
            format!("[{}]", self.address)
        } else {
            self.address.clone()
        };

        let default_port = self.protocol.default_port();

        let mut url = if self.port == default_port {
            format!("{}://{}", scheme, host)
        } else {
            format!("{}://{}:{}", scheme, host, self.port)
        };

        match &self.protocol {
            DnsProtocol::Https(default_path) | DnsProtocol::H3(default_path) => {
                let path = self.path.as_deref().unwrap_or(default_path);

                if !path.is_empty() {
                    url.push_str(path);
                }
            }

            _ => {}
        }
        url
    }

    pub fn from_url(url: &str) -> Option<(DnsProtocol, String, u16, Option<String>)> {
        let url_lower = url.to_lowercase();

        if url_lower.starts_with("udp://") {
            Self::parse_url(url, "udp://", DnsProtocol::Udp, 53)
        } else if url_lower.starts_with("tcp://") {
            Self::parse_url(url, "tcp://", DnsProtocol::Tcp, 53)
        } else if url_lower.starts_with("tls://") {
            Self::parse_url(url, "tls://", DnsProtocol::Tls, 853)
        } else if url_lower.starts_with("https://") {
            Self::parse_url_with_path(url, "https://", DnsProtocol::Https("".to_string()), 443)
        } else if url_lower.starts_with("quic://") {
            Self::parse_url(url, "quic://", DnsProtocol::Quic, 853)
        } else if url_lower.starts_with("h3://") {
            Self::parse_url_with_path(url, "h3://", DnsProtocol::H3("".to_string()), 443)
        } else {
            Self::parse_url(url, "", DnsProtocol::Udp, 53)
        }
    }

    fn parse_url(
        url: &str,
        prefix: &str,
        protocol: DnsProtocol,
        default_port: u16,
    ) -> Option<(DnsProtocol, String, u16, Option<String>)> {
        let rest = url.strip_prefix(prefix)?;
        let host_and_port = rest.split('/').next()?;

        Self::parse_host_port(host_and_port, default_port)
            .map(|(host, port)| (protocol, host, port, None))
    }

    fn parse_url_with_path(
        url: &str,
        prefix: &str,
        protocol: DnsProtocol,
        default_port: u16,
    ) -> Option<(DnsProtocol, String, u16, Option<String>)> {
        let rest = url.strip_prefix(prefix)?;
        let mut parts = rest.split('/');

        let host_and_port = parts.next()?;
        let path_parts: Vec<&str> = parts.collect();
        let path = if !path_parts.is_empty() {
            Some(format!("/{}", path_parts.join("/")))
        } else {
            Some("/dns-query".to_string())
        };

        Self::parse_host_port(host_and_port, default_port)
            .map(|(host, port)| (protocol, host, port, path))
    }

    fn parse_host_port(host_and_port: &str, default_port: u16) -> Option<(String, u16)> {
        if host_and_port.starts_with('[') {
            let end = host_and_port.find(']')?;
            let host = host_and_port[1..end].to_string();
            let rest = &host_and_port[end + 1..];
            if rest.starts_with(':') {
                let port_str = &rest[1..];
                port_str.parse().ok().map(|port| (host, port))
            } else {
                Some((host, default_port))
            }
        } else {
            let parts: Vec<&str> = host_and_port.split(':').collect();
            match parts.len() {
                2 => {
                    let host = parts[0].to_string();
                    parts[1].parse().ok().map(|port| (host, port))
                }
                1 => Some((host_and_port.to_string(), default_port)),
                _ => None,
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum DnsProtocol {
    Udp,
    Tcp,
    Tls,
    Https(String),
    Quic,
    H3(String),
}

impl DnsProtocol {
    pub fn default_port(&self) -> u16 {
        match self {
            DnsProtocol::Udp | DnsProtocol::Tcp => 53,
            DnsProtocol::Tls | DnsProtocol::Quic => 853,
            DnsProtocol::Https(_) | DnsProtocol::H3(_) => 443,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DnsCacheConfig {
    pub enabled: bool,
    pub ttl: Option<u32>,
    pub max_entries: Option<usize>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DnsRule {
    pub domain: Option<Vec<String>>,
    pub server: String,
}

impl Default for DnsCacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ttl: Some(3600),
            max_entries: Some(1000),
        }
    }
}
