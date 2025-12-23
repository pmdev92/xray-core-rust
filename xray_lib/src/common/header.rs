use std::collections::HashMap;

use convert_case::{Case, Casing};
use log::error;
use serde_json::value::RawValue;

pub fn parse_headers(headers: Option<Box<RawValue>>) -> HashMap<String, String> {
    let mut result_headers: HashMap<String, String> = HashMap::new();
    match headers {
        None => {}
        Some(headers) => {
            let hash_map: serde_json::error::Result<HashMap<String, String>> =
                serde_json::from_str(headers.get());
            match hash_map {
                Ok(hash_map) => {
                    for (key, value) in hash_map {
                        result_headers.insert(key.to_case(Case::Train), value);
                    }
                }
                Err(err) => {
                    error!("parse headers error : {}", err);
                }
            }
        }
    }
    return result_headers;
}
