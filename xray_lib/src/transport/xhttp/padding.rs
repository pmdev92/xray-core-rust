use super::huffman_table::huffman_encode_length;
use crate::common::url_builder::UrlBuilder;
use crate::transport::xhttp::protocol::{
    AVG_HUFFMAN_BYTES_PER_CHAR_BASE62, CHARSET_BASE62, METHOD_REPEAT_X, METHOD_TOKENISH,
    PLACEMENT_COOKIE, PLACEMENT_HEADER, PLACEMENT_QUERY, PLACEMENT_QUERY_IN_HEADER,
    VALIDATION_TOLERANCE, XHTTP_PADDING_MAX, XHTTP_PADDING_MIN,
};
use http::HeaderValue;
use http::request::Builder;
use rand::Rng;

#[derive(Debug, Clone)]
pub struct XPaddingSettings {
    pub min_bytes: usize,
    pub max_bytes: usize,
    pub obfs_mode: bool,
    pub key: String,
    pub header: String,
    pub placement: String,
    pub method: String,
}

impl Default for XPaddingSettings {
    fn default() -> Self {
        Self {
            min_bytes: XHTTP_PADDING_MIN,
            max_bytes: XHTTP_PADDING_MAX,
            obfs_mode: false,
            key: "x_padding".to_string(),
            header: "Referer".to_string(),
            placement: PLACEMENT_QUERY_IN_HEADER.to_string(),
            method: METHOD_REPEAT_X.to_string(),
        }
    }
}

impl XPaddingSettings {
    pub fn random_length(&self) -> usize {
        rand::thread_rng().gen_range(self.min_bytes..=self.max_bytes)
    }
}

pub fn generate_padding(method: &str, length: usize) -> String {
    if length == 0 {
        return String::new();
    }
    match method {
        METHOD_TOKENISH => {
            let result = generate_tokenish_padding_base62(length);
            if result.is_empty() {
                "X".repeat(length)
            } else {
                result
            }
        }
        _ => "X".repeat(length),
    }
}

fn rand_string_from_charset(n: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..n)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET_BASE62.len());
            CHARSET_BASE62[idx] as char
        })
        .collect()
}

fn generate_tokenish_padding_base62(target_huffman_bytes: usize) -> String {
    let n = (target_huffman_bytes as f64 / AVG_HUFFMAN_BYTES_PER_CHAR_BASE62).ceil() as usize;
    let n = n.max(1);
    let mut result = rand_string_from_charset(n);
    let mut adjust_char = b'X';
    for _ in 0..150 {
        let current_length = huffman_encode_length(&result) as i32;
        let diff = current_length - target_huffman_bytes as i32;
        if diff.abs() <= VALIDATION_TOLERANCE {
            return result;
        }
        if diff < 0 {
            result.push(adjust_char as char);
            adjust_char = if adjust_char == b'X' { b'Z' } else { b'X' };
        } else {
            if result.len() <= 1 {
                return result;
            }
            result.pop();
        }
    }
    result
}

pub fn apply_padding_to_request(
    builder: Builder,
    url_builder: &mut UrlBuilder,
    settings: &XPaddingSettings,
) -> Builder {
    if settings.obfs_mode {
        match settings.placement.as_str() {
            PLACEMENT_HEADER => apply_as_header(builder, settings),
            PLACEMENT_QUERY_IN_HEADER => apply_as_query_in_header(builder, url_builder, settings),
            PLACEMENT_COOKIE => {
                let length = settings.random_length();
                let padding_value = generate_padding(&settings.method, length);
                apply_as_cookie(builder, &settings.key, &padding_value)
            }
            PLACEMENT_QUERY => {
                apply_padding_to_query(url_builder, settings);
                builder
            }
            _ => apply_as_query_in_header(builder, url_builder, settings),
        }
    } else {
        apply_as_query_in_header(builder, url_builder, settings)
    }
}

pub fn apply_padding_to_query(url: &mut UrlBuilder, settings: &XPaddingSettings) {
    let length = settings.random_length();
    let padding_value = generate_padding(&settings.method, length);
    url.query(settings.key.as_str(), padding_value.as_str());
}

fn apply_as_header(builder: Builder, settings: &XPaddingSettings) -> Builder {
    let length = settings.random_length();
    let padding_value = generate_padding(&settings.method, length);
    builder.header(
        &settings.header,
        HeaderValue::from_str(padding_value.as_str()).unwrap_or(HeaderValue::from_static("")),
    )
}

fn apply_as_query_in_header(
    builder: Builder,
    url_builder: &UrlBuilder,
    settings: &XPaddingSettings,
) -> Builder {
    let length = settings.random_length();
    let padding_value = generate_padding(&settings.method, length);
    let mut url = url_builder.clone();
    url.query(settings.key.as_str(), padding_value.as_str());
    let referer = url.build();
    builder.header(
        &settings.header,
        HeaderValue::from_str(&referer).unwrap_or(HeaderValue::from_static("")),
    )
}

fn apply_as_cookie(builder: Builder, key: &str, value: &str) -> Builder {
    let cookie = format!("{}={}", key, value);
    builder.header(
        "Cookie",
        HeaderValue::from_str(&cookie).unwrap_or(HeaderValue::from_static("")),
    )
}
