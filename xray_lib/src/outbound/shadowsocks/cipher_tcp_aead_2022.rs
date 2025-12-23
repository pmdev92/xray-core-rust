use std::io;
use std::io::ErrorKind;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use aes::cipher::generic_array::GenericArray;
use aes::cipher::BlockEncrypt;
use aes::{Aes128, Aes256};
use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, Aes256Gcm, Key, KeyInit, Nonce};
use bytes::BytesMut;
use chacha20poly1305::ChaCha20Poly1305;
use rand::Rng;
use tls_parser::nom::AsBytes;

use crate::outbound::shadowsocks::protocol::{
    generate_iv, ss2022_password_to_key, ss2022_sub_key, to_io_error, Cipher, DecodeResult,
    PacketLen,
};

const MAX_PAYLOAD_LEN: usize = 65535;
const MAX_PADDING_LEN: u16 = 900;

pub enum TcpAeadMethod2022 {
    Aes256Gcm(Aes256Gcm),
    Aes128Gcm(Aes128Gcm),
    Chacha20Poly1305(ChaCha20Poly1305),
}

pub(crate) struct CipherTcpAead2022 {
    key_len: usize,
    iv_len: usize,
    nonce_len: usize,
    tag_len: usize,
    address_and_port: BytesMut,
    keys: Arc<Vec<Vec<u8>>>,
    keys_hash: Arc<Vec<Vec<u8>>>,
    write_iv: Arc<Vec<u8>>,
    write_nonce: Vec<u8>,
    read_nonce: Vec<u8>,
    write_cipher: TcpAeadMethod2022,
    read_cipher: Option<TcpAeadMethod2022>,
    read_state: ReadState,
    iv_sent: bool,
    header_sent: bool,
    padding_len: u16,
}
impl CipherTcpAead2022 {
    pub fn new_aes_256_gcm(password: Arc<Vec<u8>>) -> Result<Self, io::Error> {
        let key_len = 32;
        let iv_len = 32;
        let nonce_len = 12;
        let tag_len = 16;
        let iv = generate_iv(iv_len);
        let keys = ss2022_password_to_key(password.as_slice(), key_len)?;
        let sub_key = ss2022_sub_key(iv.as_slice(), keys[keys.len() - 1].as_slice(), key_len);
        let aead_key = Key::<Aes256Gcm>::from_slice(&sub_key[..key_len]);
        let cipher = TcpAeadMethod2022::Aes256Gcm(Aes256Gcm::new(aead_key));
        return Ok(Self::new(
            key_len, iv_len, nonce_len, tag_len, keys, iv, cipher,
        ));
    }

    pub fn new_aes_128_gcm(password: Arc<Vec<u8>>) -> Result<Self, io::Error> {
        let key_len = 16;
        let iv_len = 16;
        let nonce_len = 12;
        let tag_len = 16;
        let iv = generate_iv(iv_len);
        let keys = ss2022_password_to_key(password.as_slice(), key_len)?;
        let sub_key = ss2022_sub_key(iv.as_slice(), keys[keys.len() - 1].as_slice(), key_len);
        let aead_key = Key::<Aes128Gcm>::from_slice(&sub_key[..key_len]);
        let cipher = TcpAeadMethod2022::Aes128Gcm(Aes128Gcm::new(aead_key));
        return Ok(Self::new(
            key_len, iv_len, nonce_len, tag_len, keys, iv, cipher,
        ));
    }

    pub fn new_chacha20_poly1305(password: Arc<Vec<u8>>) -> Result<Self, io::Error> {
        let key_len = 32;
        let iv_len = 32;
        let nonce_len = 12;
        let tag_len = 16;
        let iv = generate_iv(iv_len);
        let keys = ss2022_password_to_key(password.as_slice(), key_len)?;
        let sub_key = ss2022_sub_key(iv.as_slice(), keys[keys.len() - 1].as_slice(), key_len);
        let cipher = TcpAeadMethod2022::Chacha20Poly1305(
            ChaCha20Poly1305::new_from_slice(&sub_key[..key_len])
                .map_err(|err| to_io_error(err.to_string()))?,
        );
        return Ok(Self::new(
            key_len, iv_len, nonce_len, tag_len, keys, iv, cipher,
        ));
    }
    fn new(
        key_len: usize,
        iv_len: usize,
        nonce_len: usize,
        tag_len: usize,
        keys: Vec<Vec<u8>>,
        iv: Vec<u8>,
        cipher: TcpAeadMethod2022,
    ) -> Self {
        let mut keys_hash: Vec<Vec<u8>> = vec![];
        for key in &keys {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&key);
            let hash = hasher.finalize();
            keys_hash.push(hash.as_bytes()[..16].to_vec());
        }

        return CipherTcpAead2022 {
            key_len,
            iv_len,
            nonce_len,
            tag_len,
            address_and_port: BytesMut::new(),
            read_cipher: None,
            write_cipher: cipher,
            keys: Arc::new(keys),
            keys_hash: Arc::new(keys_hash),
            write_iv: Arc::new(iv),
            write_nonce: vec![0u8; nonce_len],
            read_nonce: vec![0u8; nonce_len],
            read_state: ReadState::ReadIv,
            iv_sent: false,
            header_sent: false,
            padding_len: rand::thread_rng().gen_range(0..MAX_PADDING_LEN),
        };
    }
    fn encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>, io::Error> {
        let mut result = match &self.write_cipher {
            TcpAeadMethod2022::Aes256Gcm(cipher) => {
                let nonce = Nonce::from_slice(&self.write_nonce[..self.nonce_len]);
                cipher
                    .encrypt(nonce, aes_gcm::aead::Payload::from(&data[..]))
                    .map_err(|err| to_io_error(err.to_string()))?
            }
            TcpAeadMethod2022::Aes128Gcm(cipher) => {
                let nonce = Nonce::from_slice(&self.write_nonce[..self.nonce_len]);
                cipher
                    .encrypt(nonce, aes_gcm::aead::Payload::from(&data[..]))
                    .map_err(|err| to_io_error(err.to_string()))?
            }
            TcpAeadMethod2022::Chacha20Poly1305(cipher) => {
                let nonce = Nonce::from_slice(&self.write_nonce[..self.nonce_len]);
                cipher
                    .encrypt(nonce, aes_gcm::aead::Payload::from(&data[..]))
                    .map_err(|err| to_io_error(err.to_string()))?
            }
        };
        self.increase_write_nonce();
        return Ok(result);
    }
    fn decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>, io::Error> {
        let mut result = match &self.read_cipher {
            None => {
                vec![]
            }
            Some(cipher) => match cipher {
                TcpAeadMethod2022::Aes256Gcm(cipher) => {
                    let nonce = Nonce::from_slice(&self.read_nonce[..self.nonce_len]);
                    cipher
                        .decrypt(nonce, aes_gcm::aead::Payload::from(&data[..]))
                        .map_err(|err| to_io_error(err.to_string()))?
                }
                TcpAeadMethod2022::Aes128Gcm(cipher) => {
                    let nonce = Nonce::from_slice(&self.read_nonce[..self.nonce_len]);
                    cipher
                        .decrypt(nonce, aes_gcm::aead::Payload::from(&data[..]))
                        .map_err(|err| to_io_error(err.to_string()))?
                }
                TcpAeadMethod2022::Chacha20Poly1305(cipher) => {
                    let nonce = Nonce::from_slice(&self.read_nonce[..self.nonce_len]);
                    cipher
                        .decrypt(nonce, aes_gcm::aead::Payload::from(&data[..]))
                        .map_err(|err| to_io_error(err.to_string()))?
                }
            },
        };
        self.increase_read_nonce();
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

    fn encode_tcp_packet(&mut self, data: &[u8]) -> Result<Vec<u8>, io::Error> {
        let mut data = BytesMut::from(data);
        let mut result = vec![];
        loop {
            let chunk = if data.len() > MAX_PAYLOAD_LEN {
                data.split_to(MAX_PAYLOAD_LEN)
            } else {
                data.split()
            };
            let mut encrypted_header_or_len_packet = if self.header_sent {
                let len = chunk.len() as u16;
                let len_packet = len.to_be_bytes();
                self.encrypt(&len_packet[..])?
            } else {
                self.header_sent = true;
                let len = chunk.len() as u16;
                let len_packet = len.to_be_bytes();
                let mut header_packet = vec![0u8];
                let since_the_epoch = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|err| to_io_error(err.to_string()))?
                    .as_secs();
                header_packet.extend_from_slice(&since_the_epoch.to_be_bytes()[..]);
                header_packet.extend_from_slice(&len_packet[..]);
                self.encrypt(&header_packet[..])?
            };
            result.append(&mut encrypted_header_or_len_packet);
            let mut encrypted_packet = self.encrypt(chunk.as_bytes())?;
            result.append(&mut encrypted_packet);
            if data.is_empty() {
                break;
            }
        }
        return Ok(result);
    }
    fn generate_extensible_identity_headers(&mut self) -> Vec<u8> {
        if self.keys.len() == 1 {
            return vec![];
        }
        let mut result = vec![];
        let mut i = 0;
        for key in self.keys.as_slice() {
            let mut key_material = vec![];
            key_material.extend_from_slice(key);
            key_material.extend_from_slice(self.write_iv.as_slice());
            let mut hasher = blake3::Hasher::new_derive_key("shadowsocks 2022 identity subkey");
            hasher.update(&key_material);
            let identity_subkey = hasher.finalize().as_bytes().to_vec();
            let plaintext = &self.keys_hash[i + 1];
            match self.write_cipher {
                TcpAeadMethod2022::Aes256Gcm(_) => {
                    let mut block = GenericArray::from_slice(&plaintext[..16]).clone();
                    let aes_key = Key::<Aes256>::from_slice(&identity_subkey[..32]);
                    let c = Aes256::new(aes_key);
                    c.encrypt_block(&mut block);
                    result.extend_from_slice(block.as_slice());
                }
                TcpAeadMethod2022::Aes128Gcm(_) => {
                    let mut block = GenericArray::from_slice(&plaintext[..16]).clone();
                    let aes_key = Key::<Aes128>::from_slice(&identity_subkey[..16]);
                    let c = Aes128::new(aes_key);
                    c.encrypt_block(&mut block);
                    result.extend_from_slice(block.as_slice());
                }
                TcpAeadMethod2022::Chacha20Poly1305(_) => {}
            }
            i = i + 1;
            if i == self.keys.len() - 1 {
                break;
            }
        }
        return result;
    }
}

impl Cipher for CipherTcpAead2022 {
    fn buffer_address_and_port(&mut self, address_and_port: &[u8]) {
        self.address_and_port.extend_from_slice(address_and_port);
    }

    fn encode_data(&mut self, data: &[u8]) -> Result<Vec<u8>, io::Error> {
        let mut new_data = vec![];
        if !self.address_and_port.is_empty() {
            new_data.extend_from_slice(self.address_and_port.split().as_bytes());
            let padding_len = self.padding_len.to_be_bytes();
            new_data.extend_from_slice(&padding_len[..]);
            let mut padding_bytes = vec![0u8; self.padding_len as usize];
            for i in 0..(self.padding_len as usize) {
                padding_bytes[i] = rand::thread_rng().gen_range(0..255);
            }
            new_data.extend_from_slice(&padding_bytes[..]);
        }
        new_data.extend_from_slice(data);
        let encrypted = self.encode_tcp_packet(new_data.as_slice())?;

        return if self.iv_sent {
            Ok(encrypted)
        } else {
            self.iv_sent = true;
            let mut result = vec![];
            result.extend_from_slice(self.write_iv.as_slice());

            result.extend_from_slice(self.generate_extensible_identity_headers().as_slice());

            result.extend_from_slice(encrypted.as_slice());
            Ok(result)
        };
    }
    fn next_data_len(&mut self) -> PacketLen {
        return match self.read_state {
            ReadState::ReadIv => PacketLen::Must(self.iv_len),
            ReadState::ReadHeader => PacketLen::Must(1 + 8 + self.iv_len + 2 + self.tag_len),
            ReadState::ReadLength => PacketLen::Must(2 + self.tag_len),
            ReadState::ReadTcpData(usize) => PacketLen::Must(usize + self.tag_len),
        };
    }

    fn decode_data(&mut self, data: &[u8]) -> Result<DecodeResult, io::Error> {
        return match self.read_state {
            ReadState::ReadIv => {
                let iv = &data[..self.iv_len];
                let sub_key =
                    ss2022_sub_key(iv, self.keys[self.keys.len() - 1].as_slice(), self.key_len);
                match self.write_cipher {
                    TcpAeadMethod2022::Aes256Gcm(_) => {
                        let aead_key = Key::<Aes256Gcm>::from_slice(&sub_key[0..self.key_len]);
                        self.read_cipher =
                            Some(TcpAeadMethod2022::Aes256Gcm(Aes256Gcm::new(aead_key)));
                    }
                    TcpAeadMethod2022::Aes128Gcm(_) => {
                        let aead_key = Key::<Aes128Gcm>::from_slice(&sub_key[0..self.key_len]);
                        self.read_cipher =
                            Some(TcpAeadMethod2022::Aes128Gcm(Aes128Gcm::new(aead_key)));
                    }
                    TcpAeadMethod2022::Chacha20Poly1305(_) => {
                        self.read_cipher = Some(TcpAeadMethod2022::Chacha20Poly1305(
                            ChaCha20Poly1305::new_from_slice(&sub_key[0..self.key_len])
                                .map_err(|err| to_io_error(err.to_string()))?,
                        ));
                    }
                }
                self.read_state = ReadState::ReadHeader;

                Ok(DecodeResult::Skip)
            }
            ReadState::ReadHeader => {
                let header_packet = self.decrypt(&data[..])?;
                let iv = &header_packet[1 + 8..1 + 8 + self.iv_len];
                if self.write_iv.as_slice() != iv {
                    return Err(io::Error::new(
                        ErrorKind::InvalidData,
                        "shadow socks 2022 server response iv not equal to client",
                    ));
                }
                let data_length = (header_packet[1 + 8 + self.iv_len] as usize) * 256
                    + (header_packet[1 + 8 + self.iv_len + 1] as usize);
                self.read_state = ReadState::ReadTcpData(data_length);
                Ok(DecodeResult::Skip)
            }
            ReadState::ReadLength => {
                let length_packet = self.decrypt(&data[..])?;
                let data_length = (length_packet[0] as usize) * 256 + (length_packet[1] as usize);
                self.read_state = ReadState::ReadTcpData(data_length);
                Ok(DecodeResult::Skip)
            }
            ReadState::ReadTcpData(_) => {
                let result = self.decrypt(&data[..])?;
                self.read_state = ReadState::ReadLength;
                Ok(DecodeResult::Data(result))
            }
        };
    }
}

pub enum ReadState {
    ReadIv,
    ReadHeader,
    ReadLength,
    ReadTcpData(usize),
}
