use base64::Engine;
use hickory_resolver::config::{ConnectionConfig, GOOGLE, NameServerConfig, ProtocolConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::rdata::svcb::{SvcParamKey, SvcParamValue};
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::{Resolver, config::ResolverConfig};
use log::{debug, error, trace};
use std::io;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct EchQuery {
    pub domain: Option<String>,
    pub protocol: EchProtocol,
    pub host: String,
    pub port: u16,
}

#[derive(Clone, Debug)]
pub enum EchProtocol {
    Udp,
    Tcp,
    Tls,
    Https { path: String },
    Quic,
    H3 { path: String },
}

pub async fn resolve_ech(raw: &str, server_name: &str) -> io::Result<Vec<u8>> {
    let Some(query) = parse_query(Some(raw))? else {
        return decode_base64(raw);
    };
    let resolved = resolve_query(&query, server_name).await;

    match resolved? {
        Some(bytes) => Ok(bytes),
        None => Err(io::Error::new(
            ErrorKind::NotFound,
            "no ECH config found in DNS",
        )),
    }
}
fn decode_base64(raw: &str) -> io::Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(raw)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(raw))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(raw))
        .map_err(|err| {
            io::Error::new(
                ErrorKind::InvalidData,
                format!("invalid base64 ech_config_list: {err}"),
            )
        })
}
fn parse_query(raw: Option<&str>) -> io::Result<Option<EchQuery>> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    let (domain, rest) = split_domain_prefix(raw);
    if let Some(rest) = rest.strip_prefix("udp://") {
        let (host, port) = split_host_port(rest, 53)?;
        if host.is_empty() {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "ech query server host is empty",
            ));
        }
        return Ok(Some(EchQuery {
            domain: domain.map(|s| s.to_string()),
            protocol: EchProtocol::Udp,
            host,
            port,
        }));
    }

    if let Some(rest) = rest.strip_prefix("tcp://") {
        let (host, port) = split_host_port(rest, 53)?;

        if host.is_empty() {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "ech query server host is empty",
            ));
        }
        return Ok(Some(EchQuery {
            domain: domain.map(|s| s.to_string()),
            protocol: EchProtocol::Tcp,
            host,
            port,
        }));
    }

    if let Some(rest) = rest.strip_prefix("tls://") {
        let (host, port) = split_host_port(rest, 853)?;
        if host.is_empty() {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "ech query server host is empty",
            ));
        }
        return Ok(Some(EchQuery {
            domain: domain.map(|s| s.to_string()),
            protocol: EchProtocol::Tls,
            host,
            port,
        }));
    }

    if let Some(rest) = rest.strip_prefix("https://") {
        let (host_path, port) = split_host_path_port(rest, 443)?;
        let (host, path) = split_host_and_path(&host_path)?;
        if host.is_empty() {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "ech query server host is empty",
            ));
        }
        return Ok(Some(EchQuery {
            domain: domain.map(|s| s.to_string()),
            protocol: EchProtocol::Https {
                path: if path.is_empty() {
                    "/dns-query".to_string()
                } else {
                    path.to_string()
                },
            },
            host,
            port,
        }));
    }

    if let Some(rest) = rest.strip_prefix("h3://") {
        let (host_path, port) = split_host_path_port(rest, 443)?;
        let (host, path) = split_host_and_path(&host_path)?;
        if host.is_empty() {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "ech query server host is empty",
            ));
        }
        return Ok(Some(EchQuery {
            domain: domain.map(|s| s.to_string()),
            protocol: EchProtocol::H3 {
                path: if path.is_empty() {
                    "/dns-query".to_string()
                } else {
                    path.to_string()
                },
            },
            host,
            port,
        }));
    }

    if let Some(rest) = rest.strip_prefix("quic://") {
        let (host, port) = split_host_port(rest, 853)?;
        if host.is_empty() {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "ech query server host is empty",
            ));
        }
        return Ok(Some(EchQuery {
            domain: domain.map(|s| s.to_string()),
            protocol: EchProtocol::Quic,
            host,
            port,
        }));
    }

    Ok(None)
}
async fn resolve_query(query: &EchQuery, server_name: &str) -> io::Result<Option<Vec<u8>>> {
    let domain = match &query.domain {
        Some(domain) => domain.clone(),
        None => server_name.to_string(),
    };
    if domain.is_empty() {
        return Ok(None);
    }

    let bytes = fetch_query(query, &domain).await?;
    Ok(Some(bytes))
}
async fn fetch_query(query: &EchQuery, domain: &str) -> io::Result<Vec<u8>> {
    let addr = resolve_socket_addr(&query.host, query.port)?;

    let mut connection = match &query.protocol {
        EchProtocol::Udp => ConnectionConfig::udp(),
        EchProtocol::Tcp => ConnectionConfig::tcp(),
        EchProtocol::Tls => ConnectionConfig::tls(Arc::from(query.host.as_str())),
        EchProtocol::Https { path } => ConnectionConfig::https(
            Arc::from(query.host.as_str()),
            Some(Arc::from(path.as_str())),
        ),
        EchProtocol::Quic => ConnectionConfig::quic(Arc::from(query.host.as_str())),
        EchProtocol::H3 { path } => ConnectionConfig::h3(
            Arc::from(query.host.as_str()),
            Some(Arc::from(path.as_str())),
        ),
    };
    connection.port = query.port;

    let mut name_servers = vec![];
    let ns = NameServerConfig::new(addr.ip(), false, vec![connection]);
    name_servers.push(ns);

    let config = ResolverConfig::from_parts(None, vec![], name_servers);

    let resolver = Resolver::builder_with_config(config, TokioRuntimeProvider::default())
        .build()
        .unwrap();

    let response = resolver
        .lookup(domain, RecordType::HTTPS)
        .await
        .map_err(|e| io::Error::new(ErrorKind::Other, format!("dns query failed: {e}")))?;
    for record in response.answers().iter() {
        if let RData::HTTPS(https) = &record.data {
            for (key, value) in &https.svc_params {
                if *key == SvcParamKey::EchConfigList {
                    if let SvcParamValue::EchConfigList(cfg) = value {
                        let bytes = cfg.0.clone();
                        trace!("resolved ECHConfigList from DNS ({} bytes)", bytes.len());
                        return Ok(bytes);
                    }
                }
            }
        }
    }

    Err(io::Error::new(
        ErrorKind::NotFound,
        "no ECH config in response",
    ))
}
fn resolve_socket_addr(host: &str, port: u16) -> io::Result<SocketAddr> {
    if let Ok(addr) = format!("{host}:{port}").parse::<SocketAddr>() {
        return Ok(addr);
    }
    use std::net::ToSocketAddrs;
    let mut addrs = format!("{host}:{port}")
        .to_socket_addrs()
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e.to_string()))?;
    addrs
        .next()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "no address for ech dns server"))
}

fn split_domain_prefix(raw: &str) -> (Option<&str>, &str) {
    if let Some((domain, rest)) = raw.split_once('+') {
        return (Some(domain), rest);
    }
    (None, raw)
}

fn split_host_port(authority: &str, default_port: u16) -> io::Result<(String, u16)> {
    if authority.is_empty() {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "ech query server is empty",
        ));
    }

    // IPv6 literal: [::1]:53
    if let Some(rest) = authority.strip_prefix('[') {
        let Some((host, tail)) = rest.split_once(']') else {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "invalid ipv6 ech query server",
            ));
        };
        let port = match tail.strip_prefix(':') {
            Some(p) => parse_port(p)?,
            None => default_port,
        };
        return Ok((host.to_string(), port));
    }

    match authority.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => {
            Ok((host.to_string(), parse_port(port)?))
        }
        _ => Ok((authority.to_string(), default_port)),
    }
}

fn parse_port(raw: &str) -> io::Result<u16> {
    raw.parse::<u16>().map_err(|_| {
        io::Error::new(
            ErrorKind::InvalidData,
            format!("invalid ech query port: {raw}"),
        )
    })
}

fn split_host_path_port(authority: &str, default_port: u16) -> io::Result<(String, u16)> {
    if authority.is_empty() {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "ech query server is empty",
        ));
    }

    if let Some(rest) = authority.strip_prefix('[') {
        if let Some((host, tail)) = rest.split_once(']') {
            let (path, port) = match tail.strip_prefix(':') {
                Some(port_str) if port_str.chars().all(|c| c.is_ascii_digit()) => {
                    let port = parse_port(port_str)?;
                    ("", port)
                }
                Some(port_path) => {
                    if let Some(idx) = port_path.find('/') {
                        let port_str = &port_path[..idx];
                        if port_str.is_empty() || !port_str.chars().all(|c| c.is_ascii_digit()) {
                            (port_path, default_port)
                        } else {
                            let port = parse_port(port_str)?;
                            (port_path, port)
                        }
                    } else {
                        (port_path, default_port)
                    }
                }
                None => ("", default_port),
            };
            return Ok((
                format!("[{}]{}", host, if path.is_empty() { "" } else { path }),
                port,
            ));
        }
    }

    if let Some(idx) = authority.rfind(':') {
        let (host_path, port_str) = authority.split_at(idx);
        let port_str = &port_str[1..];

        if port_str.chars().all(|c| c.is_ascii_digit()) && !port_str.is_empty() {
            let port = parse_port(port_str)?;
            return Ok((host_path.to_string(), port));
        }
    }

    Ok((authority.to_string(), default_port))
}

fn split_host_and_path(host_path: &str) -> io::Result<(String, String)> {
    if let Some(idx) = host_path.find('/') {
        Ok((host_path[..idx].to_string(), host_path[idx..].to_string()))
    } else {
        Ok((host_path.to_string(), String::new()))
    }
}
