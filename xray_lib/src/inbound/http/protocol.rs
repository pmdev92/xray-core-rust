use crate::common::address::Address;
use crate::common::net_location::NetLocation;
use crate::core::io::AsyncXrayTcpStream;
use crate::inbound::http::HttpResponse;
use http::{HeaderName, HeaderValue, Method, Request, Version};
use socket2::TcpKeepalive;
use std::collections::HashMap;
use std::io;
use std::io::ErrorKind;
use std::str::FromStr;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, ReadHalf, WriteHalf};
use tokio::net::TcpStream;

pub(crate) fn parse_host(host: String, default_port: u16) -> Result<NetLocation, std::io::Error> {
    let mut port = default_port;

    let host_port = split_host_port(&host);
    if let None = host_port {
        return Err(io::Error::new(ErrorKind::InvalidData, "invalid host"));
    }
    let (host, parsed_port) = host_port.unwrap();
    if let Some(port_str) = parsed_port {
        if port_str.len() > 0 {
            port = parse_u16(&port_str)?;
        }
    }
    let address = Address::from(&host)?;
    Ok(NetLocation::new(address, port))
}
fn split_host_port(s: &str) -> Option<(String, Option<String>)> {
    if s.starts_with('[') {
        // IPv6 format: [::1] or [::1]:8080
        if let Some(end_bracket) = s.find(']') {
            let host = s[1..end_bracket].to_string();
            let port_part = &s[end_bracket + 1..];
            if port_part.starts_with(':') && port_part.len() > 1 {
                return Some((host, Some(port_part[1..].to_string())));
            } else {
                return Some((host, None));
            }
        }
        None
    } else {
        // IPv4 or hostname
        if let Some(idx) = s.rfind(':') {
            let (host, port) = s.split_at(idx);
            if !port[1..].is_empty() {
                Some((host.to_string(), Some(port[1..].to_string())))
            } else {
                Some((host.to_string(), None))
            }
        } else {
            Some((s.to_string(), None))
        }
    }
}
pub(crate) fn parse_u16(raw_port: &str) -> Result<u16, std::io::Error> {
    let int_port: u16 = raw_port
        .parse()
        .map_err(|err| io::Error::new(ErrorKind::InvalidData, err))?;
    Ok(int_port)
}

pub(crate) fn apply_keep_alive(tcp_stream: Box<TcpStream>) -> io::Result<Box<TcpStream>> {
    #[cfg(not(target_os = "windows"))]
    {
        let socket = socket2::Socket::from(tcp_stream.into_std()?);
        socket.set_tcp_keepalive(
            &TcpKeepalive::new()
                .with_time(Duration::from_secs(10))
                .with_interval(Duration::from_secs(1))
                .with_retries(3),
        )?;

        let tcp_stream = Box::new(TcpStream::from_std(socket.into())?);
        return Ok(tcp_stream);
    }
    #[cfg(target_os = "windows")]
    {
        let socket = socket2::Socket::from(tcp_stream.into_std()?);
        socket.set_tcp_keepalive(
            &TcpKeepalive::new()
                .with_time(Duration::from_secs(10))
                .with_interval(Duration::from_secs(1)),
        )?;
        let tcp_stream = Box::new(TcpStream::from_std(socket.into())?);
        return Ok(tcp_stream);
    }
}
pub(crate) fn remove_keep_alive(tcp_stream: Box<TcpStream>) -> io::Result<Box<TcpStream>> {
    let socket = socket2::Socket::from(tcp_stream.into_std()?);
    socket.set_keepalive(false)?;
    let tcp_stream = Box::new(TcpStream::from_std(socket.into())?);
    Ok(tcp_stream)
}

pub(crate) fn request_to_bytes(req: Request<()>) -> Vec<u8> {
    let mut out = Vec::new();

    let method = req.method();
    let uri = req.uri();
    let version_str = match req.version() {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_11 => "HTTP/1.1",
        Version::HTTP_2 => "HTTP/2.0",
        Version::HTTP_3 => "HTTP/3.0",
        _ => "HTTP/1.1",
    };
    out.extend_from_slice(format!("{method} {uri} {version_str}\r\n").as_bytes());
    for (name, value) in req.headers() {
        out.extend_from_slice(format!("{}: {}\r\n", name, value.to_str().unwrap_or("")).as_bytes());
    }
    out.extend_from_slice(b"\r\n");

    out
}
pub(crate) fn response_to_bytes(response: HttpResponse) -> Vec<u8> {
    let mut out = Vec::new();

    let version = response.version;
    let status = response.status_code;
    let reason_phrase = response.reason_phrase;

    out.extend_from_slice(format!("{version} {status} {reason_phrase}\r\n").as_bytes());
    for (name, value) in response.headers {
        out.extend_from_slice(format!("{}: {}\r\n", name, value.to_str().unwrap_or("")).as_bytes());
    }
    out.extend_from_slice(b"\r\n");

    out
}
pub(crate) async fn read_http_request(
    tcp_stream: &mut Box<TcpStream>,
) -> Result<Request<()>, io::Error> {
    let mut reader = BufReader::new(tcp_stream);
    let mut lines = reader.lines();
    let request_line = lines.next_line().await?.unwrap_or_default();
    let mut first_parts = request_line.split_whitespace();
    let method = Method::from_str(
        first_parts
            .next()
            .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "Missing method"))?,
    )
    .map_err(|err| io::Error::new(ErrorKind::InvalidData, err))?;
    let uri = first_parts
        .next()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "Missing URI"))?;

    let version_str = first_parts.next().unwrap_or("");
    if version_str != "HTTP/1.1" {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "Invalid HTTP Version",
        ));
    }

    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .version(Version::HTTP_11);
    while let Some(line) = lines.next_line().await? {
        if line.is_empty() {
            break;
        }
        if let Some((key, value)) = line.split_once(": ") {
            if let Ok(header_name) = HeaderName::from_str(key) {
                if let Ok(header_value) = HeaderValue::from_str(value) {
                    builder = builder.header(header_name, header_value);
                }
            }
        }
    }

    let request = builder
        .body(())
        .map_err(|err| io::Error::new(ErrorKind::InvalidData, err))?;

    Ok(request)
}

pub(crate) async fn read_http_response(
    raw_reader: &mut ReadHalf<Box<dyn AsyncXrayTcpStream>>,
) -> Result<HttpResponse, io::Error> {
    let mut reader = BufReader::new(raw_reader);
    let mut lines = reader.lines();
    let status_line = lines.next_line().await?.unwrap_or_default();
    let mut status_parts = status_line.splitn(3, ' ');

    let version = status_parts
        .next()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "Missing Version"))?
        .to_string();

    let status_code = status_parts
        .next()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "Missing Status Code"))?;
    let reason_phrase = status_parts.next().unwrap_or("").to_string();
    let status_code = parse_u16(status_code)?;
    let mut headers = HashMap::new();
    while let Some(line) = lines.next_line().await? {
        if line.is_empty() {
            break;
        }
        if let Some((key, value)) = line.split_once(": ") {
            if let Ok(header_name) = HeaderName::from_str(key) {
                if let Ok(header_value) = HeaderValue::from_str(value) {
                    headers.insert(header_name, header_value);
                }
            }
        }
    }
    let response = HttpResponse {
        version,
        status_code,
        reason_phrase,
        headers,
    };
    Ok(response)
}
pub(crate) async fn read_handle_1xx_http_response(
    raw_reader: &mut ReadHalf<Box<dyn AsyncXrayTcpStream>>,
    writer: &mut WriteHalf<Box<TcpStream>>,
) -> Result<HttpResponse, io::Error> {
    let response = read_http_response(raw_reader).await?;

    if response.status_code < 200 && response.status_code >= 100 {
        let bytes = response_to_bytes(response);
        let _ = writer.write(&bytes).await;
        return read_http_response(raw_reader).await;
    }
    Ok(response)
}

pub(crate) fn get_http_response_503() -> HttpResponse {
    let mut headers = HashMap::new();
    headers.insert(
        HeaderName::from_lowercase(b"connection").unwrap(),
        HeaderValue::from_static("close"),
    );
    headers.insert(
        HeaderName::from_lowercase(b"proxy-connection").unwrap(),
        HeaderValue::from_static("close"),
    );

    HttpResponse {
        version: "HTTP/1.1".to_string(),
        status_code: 503,
        reason_phrase: "Service Unavailable".to_string(),
        headers,
    }
}
pub(crate) fn get_http_response_400() -> HttpResponse {
    let mut headers = HashMap::new();
    headers.insert(
        HeaderName::from_static("Connection"),
        HeaderValue::from_static("close"),
    );
    headers.insert(
        HeaderName::from_static("Proxy-Connection"),
        HeaderValue::from_static("close"),
    );

    HttpResponse {
        version: "HTTP/1.1".to_string(),
        status_code: 400,
        reason_phrase: "Bad Request".to_string(),
        headers,
    }
}
