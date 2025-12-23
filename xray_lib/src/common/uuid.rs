use std::io::Write;

use sha1::{Digest, Sha1};
use uuid::Uuid;

use crate::common::hex::decode_hex;

pub fn get_uuid(text: String) -> Vec<u8> {
    if text.len() == 32 {
        let result = decode_hex(&text);
        match result {
            Ok(result) => {
                return result;
            }
            Err(_) => {}
        }
    }
    let uuid = Uuid::try_parse(text.as_str());
    match uuid {
        Ok(uuid) => {
            return uuid.as_u128().to_be_bytes().to_vec();
        }
        Err(_) => {}
    }
    let bytes = text.as_bytes();
    let zero = [0u8; 16];
    let mut hasher = Sha1::new();
    let _ = hasher.write(&zero);
    let _ = hasher.write(bytes);
    let mut result = hasher.finalize()[..16].to_vec();
    result[6] = (result[6] & 0x0f) | (5 << 4);
    result[8] = result[8] & (0xff >> 2) | (0x02 << 6);
    return result;
}
