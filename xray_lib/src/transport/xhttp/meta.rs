use crate::common::url_builder::UrlBuilder;
use crate::transport::xhttp::padding;
use crate::transport::xhttp::padding::XPaddingSettings;
use crate::transport::xhttp::protocol::{
    PLACEMENT_COOKIE, PLACEMENT_HEADER, PLACEMENT_PATH, PLACEMENT_QUERY, USER_AGENT,
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http::request::Builder;
use http::{HeaderName, HeaderValue};
use rand::Rng;
use std::collections::HashMap;
use std::str::FromStr;

pub fn apply_session_to_request(
    builder: Builder,
    url_builder: &mut UrlBuilder,
    session_id: &str,
    session_placement: &str,
    session_key: &str,
) -> Builder {
    if session_id.is_empty() {
        return builder;
    }
    match session_placement {
        PLACEMENT_PATH => {
            url_builder.append_path(session_id);
            builder
        }
        PLACEMENT_QUERY => {
            url_builder.query(session_key, session_id);
            builder
        }
        PLACEMENT_HEADER => builder.header(
            session_key,
            HeaderValue::from_str(session_id).unwrap_or(HeaderValue::from_static("")),
        ),
        PLACEMENT_COOKIE => {
            let cookie = format!("{}={}", session_key, session_id);
            builder.header(
                "Cookie",
                HeaderValue::from_str(&cookie).unwrap_or(HeaderValue::from_static("")),
            )
        }
        _ => builder,
    }
}

pub fn apply_seq_to_request(
    builder: Builder,
    url_builder: &mut UrlBuilder,
    seq: &str,
    placement: &str,
    key: &str,
) -> Builder {
    if seq.is_empty() {
        return builder;
    }
    match placement {
        PLACEMENT_PATH => {
            url_builder.append_path(seq);
            builder
        }
        PLACEMENT_QUERY => {
            url_builder.query(key, seq);
            builder
        }
        PLACEMENT_HEADER => builder.header(
            key,
            HeaderValue::from_str(seq).unwrap_or(HeaderValue::from_static("")),
        ),
        PLACEMENT_COOKIE => {
            let cookie = format!("{}={}", key, seq);
            builder.header(
                "Cookie",
                HeaderValue::from_str(&cookie).unwrap_or(HeaderValue::from_static("")),
            )
        }
        _ => builder,
    }
}

pub fn apply_data_to_headers(
    mut builder: Builder,
    data: &[u8],
    key: &str,
    chunk_size_min: usize,
    chunk_size_max: usize,
) -> Builder {
    let encoded = URL_SAFE_NO_PAD.encode(data);
    let mut remaining = encoded.as_str();
    let mut i = 0;
    let mut rng = rand::thread_rng();
    while !remaining.is_empty() {
        let chunk_size = rng
            .gen_range(chunk_size_min..=chunk_size_max)
            .min(remaining.len());
        let (chunk, rest) = remaining.split_at(chunk_size);
        remaining = rest;
        let header_key = format!("{}-{}", key, i);
        builder = builder.header(
            header_key.as_str(),
            HeaderValue::from_str(chunk).unwrap_or(HeaderValue::from_static("")),
        );
        i += 1;
    }
    builder
}

pub fn apply_data_to_cookies(
    mut builder: Builder,
    data: &[u8],
    key: &str,
    chunk_size_min: usize,
    chunk_size_max: usize,
) -> Builder {
    let encoded = URL_SAFE_NO_PAD.encode(data);
    let mut remaining = encoded.as_str();
    let mut i = 0;
    let mut rng = rand::thread_rng();
    while !remaining.is_empty() {
        let chunk_size = rng
            .gen_range(chunk_size_min..=chunk_size_max)
            .min(remaining.len());
        let (chunk, rest) = remaining.split_at(chunk_size);
        remaining = rest;
        let cookie_val = format!("{}_{}", key, i);
        let cookie = format!("{}={}", cookie_val, chunk);
        builder = builder.header(
            "Cookie",
            HeaderValue::from_str(&cookie).unwrap_or(HeaderValue::from_static("")),
        );
        i += 1;
    }
    builder
}

pub fn build_request(
    session_id: &str,
    method: &str,
    mut url_builder: UrlBuilder,
    headers: &Option<HashMap<String, String>>,
    padding_settings: &XPaddingSettings,
    session_placement: &str,
    session_key: &str,
    no_grpc_header: bool,
    is_upload: bool,
) -> Builder {
    let mut builder = http::Request::builder()
        .method(method)
        .header("Host", url_builder.get_host())
        .header("User-Agent", USER_AGENT)
        .header("Accept", "*/*")
        .header("Accept-Language", "en-US,en;q=0.9")
        .header("Accept-Encoding", "gzip")
        .header("Cache-Control", "no-cache")
        .header("Pragma", "no-cache")
        .header("Sec-Fetch-Dest", "empty")
        .header("Sec-Fetch-Mode", "cors")
        .header("Sec-Fetch-Site", "same-origin")
        .header("Priority", "u=1, i")
        .header("Connection", "close");

    if is_upload {
        builder = builder.header("Transfer-Encoding", "chunked");
        if !no_grpc_header {
            builder = builder.header("Content-Type", "application/grpc");
        }
    }

    if let Some(hdrs) = headers {
        for (key, value) in hdrs {
            builder = builder.header(
                HeaderName::from_str(key.as_str()).unwrap(),
                HeaderValue::from_str(value.as_str()).unwrap(),
            );
        }
    }

    builder = apply_session_to_request(
        builder,
        &mut url_builder,
        session_id,
        session_placement,
        session_key,
    );
    builder = padding::apply_padding_to_request(builder, &mut url_builder, padding_settings);
    builder = builder.uri(url_builder.get_uri());
    builder
}

pub fn build_packet_request(
    session_id: &str,
    method: &str,
    mut url_builder: UrlBuilder,
    headers: &Option<HashMap<String, String>>,
    padding_settings: &XPaddingSettings,
    session_placement: &str,
    session_key: &str,
    seq_str: &str,
    seq_placement: &str,
    seq_key: &str,
) -> Builder {
    let mut builder = http::Request::builder()
        .method(method)
        .header("Host", url_builder.get_host())
        .header("User-Agent", USER_AGENT)
        .header("Accept", "*/*")
        .header("Accept-Language", "en-US,en;q=0.9")
        .header("Accept-Encoding", "gzip")
        .header("Cache-Control", "no-cache")
        .header("Pragma", "no-cache")
        .header("Sec-Fetch-Dest", "empty")
        .header("Sec-Fetch-Mode", "cors")
        .header("Sec-Fetch-Site", "same-origin")
        .header("Priority", "u=1, i")
        .header("Connection", "close");

    if let Some(hdrs) = headers {
        for (key, value) in hdrs {
            builder = builder.header(
                HeaderName::from_str(key.as_str()).unwrap(),
                HeaderValue::from_str(value.as_str()).unwrap(),
            );
        }
    }

    builder = apply_session_to_request(
        builder,
        &mut url_builder,
        session_id,
        session_placement,
        session_key,
    );
    builder = apply_seq_to_request(builder, &mut url_builder, seq_str, seq_placement, seq_key);
    builder = padding::apply_padding_to_request(builder, &mut url_builder, padding_settings);
    builder = builder.uri(url_builder.get_uri());
    builder
}
