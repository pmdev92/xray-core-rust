use std::io;
use std::io::ErrorKind;
use std::sync::Arc;

use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use md5::Digest;
use sha2::Sha256;

use crate::common::vec::vec_allocate;
use crate::outbound::shadowsocks::cipher_aead::CipherAead;
use crate::outbound::shadowsocks::cipher_none::CipherNone;
use crate::outbound::shadowsocks::cipher_tcp_aead_2022::CipherTcpAead2022;
use crate::outbound::shadowsocks::cipher_udp_aead_2022::CipherUdpAead2022;
use crate::outbound::shadowsocks::ShadowSocksMethod;

pub(crate) trait Cipher: Send + Sync {
    fn buffer_address_and_port(&mut self, address_and_port: &[u8]);
    fn encode_data(&mut self, data: &[u8]) -> Result<Vec<u8>, io::Error>;
    fn next_data_len(&mut self) -> PacketLen;
    fn decode_data(&mut self, data: &[u8]) -> Result<DecodeResult, io::Error>;
}

#[derive(Debug)]
pub enum DecodeResult {
    Skip,
    Data(Vec<u8>),
}

pub enum PacketLen {
    NotMatter,
    Must(usize),
}

pub(crate) fn new_shadowsocks_tcp_cipher(
    method: ShadowSocksMethod,
    password: Arc<Vec<u8>>,
) -> Result<Box<dyn Cipher>, io::Error> {
    let cipher: Box<dyn Cipher> = match method {
        ShadowSocksMethod::None => Box::new(CipherNone::new()),
        ShadowSocksMethod::Aes256Gcm => Box::new(CipherAead::new_aes_256_gcm(password, false)),
        ShadowSocksMethod::Aes192Gcm => Box::new(CipherAead::new_aes_192_gcm(password, false)),
        ShadowSocksMethod::Aes128Gcm => Box::new(CipherAead::new_aes_128_gcm(password, false)),
        ShadowSocksMethod::Chacha20Poly1305 => {
            Box::new(CipherAead::new_chacha20_poly1305(password, false)?)
        }
        ShadowSocksMethod::XChaCha20Poly1305 => {
            Box::new(CipherAead::new_xchacha20_poly1305(password, false)?)
        }
        ShadowSocksMethod::Blake3Aes256Gcm => {
            Box::new(CipherTcpAead2022::new_aes_256_gcm(password)?)
        }
        ShadowSocksMethod::Blake3Aes128Gcm => {
            Box::new(CipherTcpAead2022::new_aes_128_gcm(password)?)
        }
        ShadowSocksMethod::Blake3Chacha20Poly1305 => {
            Box::new(CipherTcpAead2022::new_chacha20_poly1305(password)?)
        }
    };
    return Ok(cipher);
}

pub(crate) fn new_shadowsocks_udp_cipher(
    method: ShadowSocksMethod,
    password: Arc<Vec<u8>>,
) -> Result<Box<dyn Cipher>, io::Error> {
    let cipher: Box<dyn Cipher> = match method {
        ShadowSocksMethod::None => Box::new(CipherNone::new()),
        ShadowSocksMethod::Aes256Gcm => Box::new(CipherAead::new_aes_256_gcm(password, true)),
        ShadowSocksMethod::Aes192Gcm => Box::new(CipherAead::new_aes_192_gcm(password, true)),
        ShadowSocksMethod::Aes128Gcm => Box::new(CipherAead::new_aes_128_gcm(password, true)),
        ShadowSocksMethod::Chacha20Poly1305 => {
            Box::new(CipherAead::new_chacha20_poly1305(password, true)?)
        }
        ShadowSocksMethod::XChaCha20Poly1305 => {
            Box::new(CipherAead::new_xchacha20_poly1305(password, true)?)
        }
        ShadowSocksMethod::Blake3Aes256Gcm => {
            Box::new(CipherUdpAead2022::new_aes_256_gcm(password)?)
        }
        ShadowSocksMethod::Blake3Aes128Gcm => {
            Box::new(CipherUdpAead2022::new_aes_128_gcm(password)?)
        }
        ShadowSocksMethod::Blake3Chacha20Poly1305 => {
            Box::new(CipherUdpAead2022::new_chacha20_poly1305(password)?)
        }
    };
    return Ok(cipher);
}

pub(crate) fn ss2022_password_to_key(
    password: &[u8],
    len: usize,
) -> Result<Vec<Vec<u8>>, io::Error> {
    let password = String::from_utf8_lossy(password).to_string();
    let parts = password.split(":");
    let parts: Vec<&str> = parts.collect();
    let mut result: Vec<Vec<u8>> = vec![];
    for part in parts {
        let decoded = BASE64_STANDARD.decode(part);
        match decoded {
            Ok(mut decoded) => {
                if decoded.len() < len {
                    return Err(io::Error::new(ErrorKind::InvalidData, format!("shadow socks 2022 outbound config error: password must have {} bytes len", len)));
                }
                decoded = if decoded.len() > len {
                    let mut hasher = Sha256::new();
                    hasher.update(decoded);
                    hasher.finalize().to_vec()
                } else {
                    decoded
                };
                result.push(decoded[..len].to_vec());
            }
            Err(_) => {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "shadow socks 2022 outbound config error: unable to base 64 decode of shadowsocks password"))
            }
        };
    }
    if result.len() == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "shadow socks 2022 outbound config error: unable to base 64 decode of shadowsocks password"));
    }

    return Ok(result);
}

pub(crate) fn ss2022_sub_key(salt: &[u8], key: &[u8], sub_key_len: usize) -> Vec<u8> {
    let context_str: &str = "shadowsocks 2022 session subkey";
    let mut key_material = vec_allocate(key.len() + salt.len());
    key_material[0..key.len()].copy_from_slice(key);
    key_material[key.len()..].copy_from_slice(salt);
    let mut hasher = blake3::Hasher::new_derive_key(context_str);
    hasher.update(&key_material);
    let mut output_reader = hasher.finalize_xof();
    let mut sub_key = vec_allocate(sub_key_len);
    output_reader.fill(&mut sub_key);
    sub_key
}

pub(crate) fn ss_password_to_key(password: &[u8], key: &mut [u8]) {
    use md5::Md5;
    let key_len = key.len();

    let mut last_digest: Option<[u8; 16]> = None;

    let mut offset = 0usize;
    while offset < key_len {
        let mut m = Md5::new();
        if let Some(digest) = last_digest {
            m.update(&digest);
        }
        m.update(password);
        let digest = m.finalize();
        let amt = std::cmp::min(key_len - offset, 16);
        key[offset..offset + amt].copy_from_slice(&digest[..amt]);
        offset += 16;
        last_digest = Some(digest.into());
    }
}

pub(crate) fn ss_sub_key(iv: &[u8], key: &[u8]) -> [u8; 64] {
    use hkdf::Hkdf;
    use sha1::Sha1;
    let ikm = key;
    let mut okm = [0u8; 64];
    let hk = Hkdf::<Sha1>::new(Some(iv), ikm);
    hk.expand(b"ss-subkey", &mut okm)
        .expect("ss hkdf sha1 failed");
    okm
}

pub(crate) fn generate_iv(iv_len: usize) -> Vec<u8> {
    let mut iv = vec_allocate(iv_len);
    random_buffer(&mut iv);
    iv[0..iv_len].to_vec()
}

pub(crate) fn random_buffer(iv: &mut [u8]) {
    if iv.is_empty() {
        return;
    }
    let mut rng = rand::thread_rng();
    loop {
        rand::Rng::fill(&mut rng, iv);
        let is_zeros = iv.iter().all(|&x| x == 0);
        if !is_zeros {
            break;
        }
    }
}

pub(crate) fn to_io_error(message: String) -> io::Error {
    return io::Error::new(ErrorKind::InvalidInput, message);
}
pub(crate) fn xor(a: &Vec<u8>, b: &Vec<u8>) -> Vec<u8> {
    let c = a.iter().zip(b.iter()).map(|(&x1, &x2)| x1 ^ x2).collect();
    c
}
