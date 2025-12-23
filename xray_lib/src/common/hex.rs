use std::fmt::Write;
use std::num::ParseIntError;

pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

pub fn encode_hex(bytes: &[u8]) -> String {
    let mut string = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        let data = format!("{:02x}", byte);
        let _ = string.write_str(&data);
    }
    return string;
}
