use std::io::{Error, ErrorKind};

/// TLS-like record header: [content_type=23, major=3, minor=3, len_hi, len_lo]
pub const HEADER_SIZE: usize = 5;
pub const MAX_PAYLOAD: usize = 8192;
pub const TAG_SIZE: usize = 16;
pub const MAX_NONCE: [u8; 12] = [0xFF; 12];

/// Encode a TLS-like header with given payload length (includes tag)
pub fn encode_header(buf: &mut [u8], payload_len: usize) {
    buf[0] = 23; // application_data
    buf[1] = 3; // TLS 1.2 major
    buf[2] = 3; // TLS 1.2 minor
    buf[3] = (payload_len >> 8) as u8;
    buf[4] = payload_len as u8;
}

/// Decode a TLS-like header, returns payload length
pub fn decode_header(buf: &[u8; 5]) -> Result<usize, Error> {
    let len = ((buf[3] as usize) << 8) | (buf[4] as usize);
    if buf[0] != 23 || buf[1] != 3 || buf[2] != 3 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("invalid header: {:?}", buf),
        ));
    }
    // TLS 1.3 max: 16384 + 256 = 16640, min: 1 + 16 = 17
    if len < 17 || len > 16640 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("invalid header: {:?}", buf),
        ));
    }
    Ok(len)
}

/// Encode a 2-byte big-endian length
pub fn encode_length(len: usize) -> [u8; 2] {
    [(len >> 8) as u8, len as u8]
}

/// Decode a 2-byte big-endian length
pub fn decode_length(buf: &[u8]) -> usize {
    ((buf[0] as usize) << 8) | (buf[1] as usize)
}

/// Increment a 12-byte nonce (big-endian increment from LSB)
pub fn increment_nonce(nonce: &mut [u8; 12]) {
    for i in (0..12).rev() {
        nonce[i] = nonce[i].wrapping_add(1);
        if nonce[i] != 0 {
            break;
        }
    }
}

/// Check if nonce has reached max value
pub fn is_max_nonce(nonce: &[u8; 12]) -> bool {
    nonce == &MAX_NONCE
}
