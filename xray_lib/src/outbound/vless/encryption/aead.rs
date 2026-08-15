use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce as AesNonce};
use blake3;
use chacha20poly1305::ChaCha20Poly1305;
use std::io::{Error, ErrorKind};

use super::common::{increment_nonce, is_max_nonce};

/// AEAD wrapper supporting both AES-256-GCM and ChaCha20-Poly1305.
/// Nonce auto-increments per operation.
pub struct VlessAead {
    cipher: AeadCipher,
    pub nonce: [u8; 12],
}

enum AeadCipher {
    Aes(Aes256Gcm),
    Chacha(ChaCha20Poly1305),
}

impl VlessAead {
    /// Create new AEAD. Key is derived via Blake3 DeriveKey from context + key material.
    pub fn new(context: &[u8], key_material: &[u8], use_aes: bool) -> Self {
        let derived_key = blake3::derive_key(
            unsafe { std::str::from_utf8_unchecked(context) },
            key_material,
        );

        let cipher = if use_aes {
            AeadCipher::Aes(Aes256Gcm::new_from_slice(&derived_key).unwrap())
        } else {
            AeadCipher::Chacha(ChaCha20Poly1305::new_from_slice(&derived_key).unwrap())
        };

        Self {
            cipher,
            nonce: [0u8; 12],
        }
    }

    /// Encrypt plaintext with optional AAD. Auto-increments nonce.
    /// Returns ciphertext + tag appended.
    pub fn seal(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
        increment_nonce(&mut self.nonce);
        let result = match &self.cipher {
            AeadCipher::Aes(c) => c.encrypt(
                AesNonce::from_slice(&self.nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            ),
            AeadCipher::Chacha(c) => c.encrypt(
                chacha20poly1305::Nonce::from_slice(&self.nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            ),
        };
        result.map_err(|e| Error::new(ErrorKind::Other, format!("seal error: {}", e)))
    }

    /// Decrypt ciphertext (includes tag at end) with optional AAD. Auto-increments nonce.
    pub fn open(&mut self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
        increment_nonce(&mut self.nonce);
        let result = match &self.cipher {
            AeadCipher::Aes(c) => c.decrypt(
                AesNonce::from_slice(&self.nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            ),
            AeadCipher::Chacha(c) => c.decrypt(
                chacha20poly1305::Nonce::from_slice(&self.nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            ),
        };
        result.map_err(|e| Error::new(ErrorKind::Other, format!("aead open error: {}", e)))
    }

    /// Check if nonce is at max and key rotation is needed
    pub fn needs_rotation(&self) -> bool {
        is_max_nonce(&self.nonce)
    }
}
