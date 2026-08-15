use aes::cipher::{KeyIvInit, StreamCipher};
use aes::Aes256;
use blake3;

type Aes256Ctr = ctr::Ctr128BE<Aes256>;

/// Create an AES-256-CTR stream cipher for XOR mode.
/// Key is derived via Blake3 with context "VLESS".
pub fn new_ctr(key: &[u8], iv: &[u8]) -> Aes256Ctr {
    let derived_key = blake3::derive_key("VLESS", key);
    // IV must be 16 bytes for AES-CTR
    let mut iv_padded = [0u8; 16];
    let copy_len = iv.len().min(16);
    iv_padded[..copy_len].copy_from_slice(&iv[..copy_len]);
    Aes256Ctr::new(&derived_key.into(), &iv_padded.into())
}

/// XOR wrapper that encrypts/decrypts headers using AES-CTR.
pub struct XorState {
    ctr: Aes256Ctr,
}

impl XorState {
    pub fn new(key: &[u8], iv: &[u8]) -> Self {
        Self {
            ctr: new_ctr(key, iv),
        }
    }

    pub fn apply(&mut self, data: &mut [u8]) {
        self.ctr.apply_keystream(&mut data[..]);
    }
}
