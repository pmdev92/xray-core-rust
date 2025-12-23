use std::io;
use std::sync::Arc;

use aes::cipher::consts::U12;
use aes::Aes192;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, Aes256Gcm, AesGcm, Key, KeyInit, Nonce};
use bytes::BytesMut;
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use tls_parser::nom::AsBytes;

use crate::common::vec::vec_allocate;
use crate::outbound::shadowsocks::protocol::{
    generate_iv, ss_password_to_key, ss_sub_key, to_io_error, Cipher, DecodeResult, PacketLen,
};

const MAX_PAYLOAD_LEN: usize = 16383;
pub enum AeadMethod {
    Aes256Gcm(Aes256Gcm),
    Aes192Gcm(AesGcm<Aes192, U12>),
    Aes128Gcm(Aes128Gcm),
    Chacha20Poly1305(ChaCha20Poly1305),
    XChaCha20Poly1305(XChaCha20Poly1305),
}

pub(crate) struct CipherAead {
    key_len: usize,
    iv_len: usize,

    nonce_len: usize,
    tag_len: usize,
    address_and_port: BytesMut,
    key: Arc<Vec<u8>>,
    write_iv: Arc<Vec<u8>>,
    write_nonce: Vec<u8>,
    read_nonce: Vec<u8>,
    write_cipher: AeadMethod,
    read_cipher: Option<AeadMethod>,
    state: State,
    is_udp: bool,
    iv_sent: bool,
}
impl CipherAead {
    pub fn new_aes_256_gcm(password: Arc<Vec<u8>>, is_udp: bool) -> Self {
        let key_len = 32;
        let iv_len = 32;
        let nonce_len = 12;
        let tag_len = 16;
        let iv = generate_iv(iv_len);
        let mut key = vec_allocate(key_len);
        ss_password_to_key(password.as_slice(), &mut key);
        let sub_key = ss_sub_key(iv.as_slice(), key.as_slice());
        let aead_key = Key::<Aes256Gcm>::from_slice(&sub_key[..key_len]);
        let cipher = AeadMethod::Aes256Gcm(Aes256Gcm::new(aead_key));
        Self::new(key_len, iv_len, nonce_len, tag_len, is_udp, key, iv, cipher)
    }

    pub fn new_aes_192_gcm(password: Arc<Vec<u8>>, is_udp: bool) -> Self {
        let key_len = 24;
        let iv_len = 24;
        let nonce_len = 12;
        let tag_len = 16;
        let iv = generate_iv(iv_len);
        let mut key = vec_allocate(key_len);
        ss_password_to_key(password.as_slice(), &mut key);
        let sub_key = ss_sub_key(iv.as_slice(), key.as_slice());
        let aead_key = Key::<AesGcm<Aes192, U12>>::from_slice(&sub_key[..key_len]);
        let cipher = AeadMethod::Aes192Gcm(AesGcm::new(aead_key));
        Self::new(key_len, iv_len, nonce_len, tag_len, is_udp, key, iv, cipher)
    }

    pub fn new_aes_128_gcm(password: Arc<Vec<u8>>, is_udp: bool) -> Self {
        let key_len = 16;
        let iv_len = 16;
        let nonce_len = 12;
        let tag_len = 16;
        let iv = generate_iv(iv_len);
        let mut key = vec_allocate(key_len);
        ss_password_to_key(password.as_slice(), &mut key);
        let sub_key = ss_sub_key(iv.as_slice(), key.as_slice());
        let aead_key = Key::<Aes128Gcm>::from_slice(&sub_key[..key_len]);
        let cipher = AeadMethod::Aes128Gcm(Aes128Gcm::new(aead_key));
        Self::new(key_len, iv_len, nonce_len, tag_len, is_udp, key, iv, cipher)
    }
    pub fn new_chacha20_poly1305(password: Arc<Vec<u8>>, is_udp: bool) -> Result<Self, io::Error> {
        let key_len = 32;
        let iv_len = 32;
        let nonce_len = 12;
        let tag_len = 16;
        let iv = generate_iv(iv_len);
        let mut key = vec_allocate(key_len);
        ss_password_to_key(password.as_slice(), &mut key);
        let sub_key = ss_sub_key(iv.as_slice(), key.as_slice());
        let cipher = AeadMethod::Chacha20Poly1305(
            ChaCha20Poly1305::new_from_slice(&sub_key[..key_len])
                .map_err(|err| to_io_error(err.to_string()))?,
        );
        Ok(Self::new(
            key_len, iv_len, nonce_len, tag_len, is_udp, key, iv, cipher,
        ))
    }
    pub fn new_xchacha20_poly1305(password: Arc<Vec<u8>>, is_udp: bool) -> Result<Self, io::Error> {
        let key_len = 32;
        let iv_len = 32;
        let nonce_len = 24;
        let tag_len = 16;
        let iv = generate_iv(iv_len);
        let mut key = vec_allocate(key_len);
        ss_password_to_key(password.as_slice(), &mut key);
        let sub_key = ss_sub_key(iv.as_slice(), key.as_slice());
        let cipher = AeadMethod::XChaCha20Poly1305(
            XChaCha20Poly1305::new_from_slice(&sub_key[..key_len])
                .map_err(|err| to_io_error(err.to_string()))?,
        );
        Ok(Self::new(
            key_len, iv_len, nonce_len, tag_len, is_udp, key, iv, cipher,
        ))
    }
    fn new(
        key_len: usize,
        iv_len: usize,
        nonce_len: usize,
        tag_len: usize,
        is_udp: bool,
        key: Vec<u8>,
        iv: Vec<u8>,
        cipher: AeadMethod,
    ) -> Self {
        CipherAead {
            key_len,
            iv_len,
            nonce_len,
            tag_len,
            address_and_port: BytesMut::new(),
            read_cipher: None,
            write_cipher: cipher,
            key: Arc::new(key),
            write_iv: Arc::new(iv),
            write_nonce: vec![0u8; nonce_len],
            read_nonce: vec![0u8; nonce_len],
            state: State::ReadIv,
            is_udp,
            iv_sent: false,
        }
    }

    fn encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>, io::Error> {
        let mut result = match &self.write_cipher {
            AeadMethod::Aes256Gcm(cipher) => {
                let nonce = Nonce::from_slice(&self.write_nonce[..self.nonce_len]);
                cipher
                    .encrypt(nonce, aes_gcm::aead::Payload::from(&data[..]))
                    .map_err(|err| to_io_error(err.to_string()))?
            }
            AeadMethod::Aes192Gcm(cipher) => {
                let nonce = Nonce::from_slice(&self.write_nonce[..self.nonce_len]);
                cipher
                    .encrypt(nonce, aes_gcm::aead::Payload::from(&data[..]))
                    .map_err(|err| to_io_error(err.to_string()))?
            }
            AeadMethod::Aes128Gcm(cipher) => {
                let nonce = Nonce::from_slice(&self.write_nonce[..self.nonce_len]);
                cipher
                    .encrypt(nonce, aes_gcm::aead::Payload::from(&data[..]))
                    .map_err(|err| to_io_error(err.to_string()))?
            }
            AeadMethod::Chacha20Poly1305(cipher) => {
                let nonce = Nonce::from_slice(&self.write_nonce[..self.nonce_len]);
                cipher
                    .encrypt(nonce, aes_gcm::aead::Payload::from(&data[..]))
                    .map_err(|err| to_io_error(err.to_string()))?
            }
            AeadMethod::XChaCha20Poly1305(cipher) => {
                let nonce = Nonce::from_slice(&self.write_nonce[..self.nonce_len]);
                cipher
                    .encrypt(nonce, aes_gcm::aead::Payload::from(&data[..]))
                    .map_err(|err| to_io_error(err.to_string()))?
            }
        };
        if !self.is_udp {
            self.increase_write_nonce();
        }
        return Ok(result);
    }
    fn decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>, io::Error> {
        let mut result = match &self.read_cipher {
            None => {
                vec![]
            }
            Some(cipher) => match cipher {
                AeadMethod::Aes256Gcm(cipher) => {
                    let nonce = Nonce::from_slice(&self.read_nonce[..self.nonce_len]);
                    cipher
                        .decrypt(nonce, aes_gcm::aead::Payload::from(&data[..]))
                        .map_err(|err| to_io_error(err.to_string()))?
                }
                AeadMethod::Aes192Gcm(cipher) => {
                    let nonce = Nonce::from_slice(&self.read_nonce[..self.nonce_len]);
                    cipher
                        .decrypt(nonce, aes_gcm::aead::Payload::from(&data[..]))
                        .map_err(|err| to_io_error(err.to_string()))?
                }
                AeadMethod::Aes128Gcm(cipher) => {
                    let nonce = Nonce::from_slice(&self.read_nonce[..self.nonce_len]);
                    cipher
                        .decrypt(nonce, aes_gcm::aead::Payload::from(&data[..]))
                        .map_err(|err| to_io_error(err.to_string()))?
                }
                AeadMethod::Chacha20Poly1305(cipher) => {
                    let nonce = Nonce::from_slice(&self.read_nonce[..self.nonce_len]);
                    cipher
                        .decrypt(nonce, aes_gcm::aead::Payload::from(&data[..]))
                        .map_err(|err| to_io_error(err.to_string()))?
                }
                AeadMethod::XChaCha20Poly1305(cipher) => {
                    let nonce = Nonce::from_slice(&self.read_nonce[..self.nonce_len]);
                    cipher
                        .decrypt(nonce, aes_gcm::aead::Payload::from(&data[..]))
                        .map_err(|err| to_io_error(err.to_string()))?
                }
            },
        };
        if !self.is_udp {
            self.increase_read_nonce();
        }

        return Ok(result);
    }

    #[inline]
    fn increase_write_nonce(&mut self) {
        let mut c = self.write_nonce[0] as u16 + 1;
        self.write_nonce[0] = c as u8;
        c >>= 8;
        let mut n = 1;
        while n < self.nonce_len {
            c += self.write_nonce[n] as u16;
            self.write_nonce[n] = c as u8;
            c >>= 8;
            n += 1;
        }
    }

    #[inline]
    fn increase_read_nonce(&mut self) {
        let mut c = self.read_nonce[0] as u16 + 1;
        self.read_nonce[0] = c as u8;
        c >>= 8;
        let mut n = 1;
        while n < self.nonce_len {
            c += self.read_nonce[n] as u16;
            self.read_nonce[n] = c as u8;
            c >>= 8;
            n += 1;
        }
    }

    fn encode_udp_packet(&mut self, data: &[u8]) -> Result<Vec<u8>, io::Error> {
        return self.encrypt(&data[..]);
    }
    fn encode_tcp_packet(&mut self, data: &[u8]) -> Result<Vec<u8>, io::Error> {
        let mut data = BytesMut::from(data);
        let mut result = vec![];
        loop {
            let chunk = if data.len() > MAX_PAYLOAD_LEN {
                data.split_to(MAX_PAYLOAD_LEN)
            } else {
                data.split()
            };
            let len = chunk.len() as u16;
            let len_packet = len.to_be_bytes();
            let mut encrypted_len_packet = self.encrypt(&len_packet[..])?;
            let mut encrypted_packet = self.encrypt(chunk.as_bytes())?;
            result.append(&mut encrypted_len_packet);
            result.append(&mut encrypted_packet);
            if data.is_empty() {
                break;
            }
        }
        return Ok(result);
    }
}

impl Cipher for CipherAead {
    fn buffer_address_and_port(&mut self, address_and_port: &[u8]) {
        self.address_and_port.extend_from_slice(address_and_port);
    }

    fn encode_data(&mut self, data: &[u8]) -> Result<Vec<u8>, io::Error> {
        let mut new_data = vec![];
        if !self.address_and_port.is_empty() {
            new_data.extend_from_slice(self.address_and_port.split().as_bytes())
        }
        new_data.extend_from_slice(data);
        let encrypted = if self.is_udp {
            self.encode_udp_packet(new_data.as_slice())?
        } else {
            self.encode_tcp_packet(new_data.as_slice())?
        };
        return if self.iv_sent && !self.is_udp {
            Ok(encrypted)
        } else {
            self.iv_sent = true;
            let mut result = vec![];
            result.extend_from_slice(self.write_iv.as_slice());
            result.extend_from_slice(encrypted.as_slice());
            Ok(result)
        };
    }

    fn next_data_len(&mut self) -> PacketLen {
        return match self.state {
            State::ReadIv => PacketLen::Must(self.iv_len),
            State::ReadLength => PacketLen::Must(2 + self.tag_len),
            State::ReadTcpData(usize) => PacketLen::Must(usize + self.tag_len),
            State::ReadUdpData => PacketLen::NotMatter,
        };
    }

    fn decode_data(&mut self, data: &[u8]) -> Result<DecodeResult, io::Error> {
        return match self.state {
            State::ReadIv => {
                let iv = &data[..self.iv_len];
                let sub_key = ss_sub_key(iv, self.key.as_slice());
                match self.write_cipher {
                    AeadMethod::Aes256Gcm(_) => {
                        let aead_key = Key::<Aes256Gcm>::from_slice(&sub_key[0..self.key_len]);
                        self.read_cipher = Some(AeadMethod::Aes256Gcm(Aes256Gcm::new(aead_key)));
                    }
                    AeadMethod::Aes192Gcm(_) => {
                        let aead_key =
                            Key::<AesGcm<Aes192, U12>>::from_slice(&sub_key[0..self.key_len]);
                        self.read_cipher = Some(AeadMethod::Aes192Gcm(AesGcm::new(aead_key)));
                    }
                    AeadMethod::Aes128Gcm(_) => {
                        let aead_key = Key::<Aes128Gcm>::from_slice(&sub_key[0..self.key_len]);
                        self.read_cipher = Some(AeadMethod::Aes128Gcm(Aes128Gcm::new(aead_key)));
                    }
                    AeadMethod::Chacha20Poly1305(_) => {
                        self.read_cipher = Some(AeadMethod::Chacha20Poly1305(
                            ChaCha20Poly1305::new_from_slice(&sub_key[0..self.key_len])
                                .map_err(|err| to_io_error(err.to_string()))?,
                        ));
                    }
                    AeadMethod::XChaCha20Poly1305(_) => {
                        self.read_cipher = Some(AeadMethod::XChaCha20Poly1305(
                            XChaCha20Poly1305::new_from_slice(&sub_key[0..self.key_len])
                                .map_err(|err| to_io_error(err.to_string()))?,
                        ));
                    }
                }
                if self.is_udp {
                    self.state = State::ReadUdpData;
                } else {
                    self.state = State::ReadLength;
                }

                Ok(DecodeResult::Skip)
            }
            State::ReadLength => {
                let length_packet = self.decrypt(&data[..])?;
                let data_length = (length_packet[0] as usize) * 256 + (length_packet[1] as usize);
                self.state = State::ReadTcpData(data_length);
                Ok(DecodeResult::Skip)
            }
            State::ReadTcpData(_) => {
                let result = self.decrypt(&data[..])?;
                self.state = State::ReadLength;
                Ok(DecodeResult::Data(result))
            }
            State::ReadUdpData => {
                let result = self.decrypt(&data[..])?;
                self.state = State::ReadIv;
                Ok(DecodeResult::Data(result))
            }
        };
    }
}

pub enum State {
    ReadIv,
    ReadLength,
    ReadTcpData(usize),
    ReadUdpData,
}
