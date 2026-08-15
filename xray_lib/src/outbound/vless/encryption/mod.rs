//! VLESS Encryption — Hybrid PQ key exchange + AEAD stream encryption
//!
//! Protocol:
//! - Key Exchange: ML-KEM-768 (post-quantum) + X25519 (classic)
//! - AEAD: AES-256-GCM (if HW support) or ChaCha20-Poly1305
//! - KDF: Blake3 DeriveKey
//! - XOR mode: AES-256-CTR on TLS-like headers
//! - Frame format: [23, 3, 3, len_hi, len_lo] + AEAD(payload) + tag(16)
//! - Max payload per frame: 8192 bytes
//! - Nonce: 12 bytes, incremented per frame, key rotation at max nonce

use std::io::{self, ErrorKind};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

pub mod aead;
pub mod client;
pub mod common;
pub mod xor;

use client::ClientInstance;

/// Parse the encryption config string from VLESS account settings.
///
/// Format: `"mlkem768x25519plus.<mode>.<rtt>.<padding_or_key>..."`
///
/// - `mode`: `"native"` → xor_mode=0, `"xorpub"` → xor_mode=1, `"random"` → xor_mode=2
/// - `rtt`: `"1rtt"` → seconds=0, `"0rtt"` → seconds=1
/// - Segments with `len < 20` → padding config parts (joined by ".")
/// - Segments with `len >= 20` → base64url-encoded NFS public keys (must decode to 32 or 1184 bytes)
///
/// Returns `None` if encryption is "none" or empty.
/// Returns `Err` if format is invalid.
pub fn parse_encryption(enc: &str) -> Result<Option<ClientInstance>, io::Error> {
    if enc.is_empty() || enc == "none" {
        return Ok(None);
    }

    let parts: Vec<&str> = enc.split('.').collect();
    if parts.len() < 4 || parts[0] != "mlkem768x25519plus" {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!("unsupported encryption: {}", enc),
        ));
    }

    let xor_mode: u32 = match parts[1] {
        "native" => 0,
        "xorpub" => 1,
        "random" => 2,
        _ => {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!("unsupported encryption mode: {}", parts[1]),
            ));
        }
    };

    let seconds: u32 = match parts[2] {
        "1rtt" => 0,
        "0rtt" => 1,
        _ => {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!("unsupported rtt mode: {}", parts[2]),
            ));
        }
    };

    // Separate padding segments (len < 20) from key segments (len >= 20)
    let mut padding_parts: Vec<&str> = Vec::new();
    let mut nfs_pkeys_bytes: Vec<Vec<u8>> = Vec::new();

    for seg in &parts[3..] {
        if seg.len() < 20 {
            padding_parts.push(seg);
        } else {
            let decoded = URL_SAFE_NO_PAD.decode(seg).map_err(|e| {
                io::Error::new(ErrorKind::InvalidInput, format!("bad base64 key: {}", e))
            })?;
            if decoded.len() != 32 && decoded.len() != 1184 {
                return Err(io::Error::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "invalid key length: {} (expected 32 or 1184)",
                        decoded.len()
                    ),
                ));
            }
            nfs_pkeys_bytes.push(decoded);
        }
    }

    let mut padding = padding_parts.join(".");
    if padding.is_empty() {
        padding = "100-111-1111.75-0-111.50-0-3333".to_string();
    }
    if nfs_pkeys_bytes.is_empty() {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "no NFS public keys found in encryption string",
        ));
    }

    let instance = ClientInstance::new(nfs_pkeys_bytes, xor_mode, seconds, &padding)?;

    Ok(Some(instance))
}
