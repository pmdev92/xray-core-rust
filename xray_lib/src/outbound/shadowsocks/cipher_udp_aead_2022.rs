use std::io;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt};
use aes::{Aes128, Aes256};
use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, Aes256Gcm, Key, KeyInit, Nonce};
use bitvec::macros::internal::funty::Numeric;
use bytes::BytesMut;
use chacha20poly1305::XChaCha20Poly1305;
use rand::Rng;
use tls_parser::nom::AsBytes;

use crate::outbound::shadowsocks::protocol::{
    generate_iv, ss2022_password_to_key, ss2022_sub_key, to_io_error, xor, Cipher, DecodeResult,
    PacketLen,
};

const MAX_PADDING_LEN: u16 = 900;
pub enum UdpAeadMethod2022 {
    Aes256Gcm(Aes256Gcm),
    Aes128Gcm(Aes128Gcm),
    XChacha20Poly1305(XChaCha20Poly1305, Vec<u8>),
}

pub enum UdpHeaderMethod2022 {
    Aes256Gcm(aes::Aes256, aes::Aes256),
    Aes128Gcm(aes::Aes128, aes::Aes128),
    Chacha20Poly1305,
}

pub(crate) struct CipherUdpAead2022 {
    key_len: usize,
    tag_len: usize,
    address_and_port: BytesMut,
    keys: Arc<Vec<Vec<u8>>>,
    keys_hash: Arc<Vec<Vec<u8>>>,
    header_cipher: UdpHeaderMethod2022,
    body_write_cipher: UdpAeadMethod2022,
    body_read_cipher: Option<UdpAeadMethod2022>,
    read_state: ReadState,
    padding_len: u16,
    write_session_id: u64,
    write_packet_id: u64,
    read_session_id: u64,
    read_packet_id: u64,
}
impl CipherUdpAead2022 {
    pub fn new_aes_256_gcm(password: Arc<Vec<u8>>) -> Result<Self, io::Error> {
        let key_len = 32;
        let tag_len = 16;
        let session_id = rand::thread_rng().gen_range(0..u64::MAX);
        let keys = ss2022_password_to_key(password.as_slice(), key_len)?;

        let sub_key = ss2022_sub_key(
            &session_id.to_be_bytes(),
            keys[keys.len() - 1].as_slice(),
            key_len,
        );
        let aead_key = Key::<Aes256Gcm>::from_slice(&sub_key[..key_len]);
        let body_cipher = UdpAeadMethod2022::Aes256Gcm(Aes256Gcm::new(aead_key));

        let aes_encrypt_key = Key::<aes::Aes256>::from_slice(&keys[0][..key_len]);
        let aes_decrypt_key = Key::<aes::Aes256>::from_slice(&keys[keys.len() - 1][..key_len]);
        let header_cipher = UdpHeaderMethod2022::Aes256Gcm(
            aes::Aes256::new(aes_encrypt_key),
            aes::Aes256::new(aes_decrypt_key),
        );

        return Ok(Self::new(
            key_len,
            tag_len,
            keys,
            session_id,
            header_cipher,
            body_cipher,
        ));
    }

    pub fn new_aes_128_gcm(password: Arc<Vec<u8>>) -> Result<Self, io::Error> {
        let key_len = 16;
        let tag_len = 16;
        let session_id = rand::thread_rng().gen_range(0..u64::MAX);
        let keys = ss2022_password_to_key(password.as_slice(), key_len)?;
        let sub_key = ss2022_sub_key(
            &session_id.to_be_bytes(),
            keys[keys.len() - 1].as_slice(),
            key_len,
        );
        let aead_key = Key::<Aes128Gcm>::from_slice(&sub_key[..key_len]);
        let body_cipher = UdpAeadMethod2022::Aes128Gcm(Aes128Gcm::new(aead_key));

        let aes_encrypt_key = Key::<aes::Aes128>::from_slice(&keys[0][..key_len]);
        let aes_decrypt_key = Key::<aes::Aes128>::from_slice(&keys[keys.len() - 1][..key_len]);
        let header_cipher = UdpHeaderMethod2022::Aes128Gcm(
            aes::Aes128::new(aes_encrypt_key),
            aes::Aes128::new(aes_decrypt_key),
        );

        return Ok(Self::new(
            key_len,
            tag_len,
            keys,
            session_id,
            header_cipher,
            body_cipher,
        ));
    }
    pub fn new_chacha20_poly1305(password: Arc<Vec<u8>>) -> Result<Self, io::Error> {
        let key_len = 32;
        let tag_len = 16;
        let session_id = rand::thread_rng().gen_range(0..u64::MAX);
        let keys = ss2022_password_to_key(password.as_slice(), key_len)?;

        let body_cipher = UdpAeadMethod2022::XChacha20Poly1305(
            XChaCha20Poly1305::new_from_slice(&keys[keys.len() - 1][..key_len])
                .map_err(|err| to_io_error(err.to_string()))?,
            vec![],
        );
        let header_cipher = UdpHeaderMethod2022::Chacha20Poly1305;

        return Ok(Self::new(
            key_len,
            tag_len,
            keys,
            session_id,
            header_cipher,
            body_cipher,
        ));
    }

    fn new(
        key_len: usize,
        tag_len: usize,
        keys: Vec<Vec<u8>>,
        session_id: u64,
        header_cipher: UdpHeaderMethod2022,
        body_cipher: UdpAeadMethod2022,
    ) -> Self {
        let mut keys_hash: Vec<Vec<u8>> = vec![];
        for key in &keys {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&key);
            let hash = hasher.finalize();
            keys_hash.push(hash.as_bytes()[..16].to_vec());
        }
        return CipherUdpAead2022 {
            key_len,
            tag_len,
            address_and_port: BytesMut::new(),
            body_read_cipher: None,
            body_write_cipher: body_cipher,
            header_cipher,
            keys: Arc::new(keys),
            keys_hash: Arc::new(keys_hash),
            read_state: ReadState::ReadHeader,
            padding_len: rand::thread_rng().gen_range(0..MAX_PADDING_LEN),
            write_session_id: session_id,
            write_packet_id: 0,
            read_session_id: 0,
            read_packet_id: 0,
        };
    }

    fn encrypt_udp(&mut self, data: &[u8]) -> Result<Vec<u8>, io::Error> {
        let mut session_id_packet_id = vec![];
        session_id_packet_id.extend_from_slice(&self.write_session_id.to_be_bytes());
        session_id_packet_id.extend_from_slice(&self.write_packet_id.to_be_bytes());
        let header = match &self.header_cipher {
            UdpHeaderMethod2022::Aes256Gcm(cipher, _) => {
                let mut block = GenericArray::from_slice(&session_id_packet_id[..16]).clone();
                cipher.encrypt_block(&mut block);
                block.as_slice().to_vec()
            }
            UdpHeaderMethod2022::Aes128Gcm(cipher, _) => {
                let mut block = GenericArray::from_slice(&session_id_packet_id[..16]).clone();
                cipher.encrypt_block(&mut block);
                block.as_slice().to_vec()
            }
            UdpHeaderMethod2022::Chacha20Poly1305 => generate_iv(24),
        };

        let body = match &self.body_write_cipher {
            UdpAeadMethod2022::Aes256Gcm(cipher) => {
                let nonce = Nonce::from_slice(&session_id_packet_id[4..16]);
                cipher
                    .encrypt(nonce, aes_gcm::aead::Payload::from(&data[..]))
                    .map_err(|err| to_io_error(err.to_string()))?
            }
            UdpAeadMethod2022::Aes128Gcm(cipher) => {
                let nonce = Nonce::from_slice(&session_id_packet_id[4..16]);
                cipher
                    .encrypt(nonce, aes_gcm::aead::Payload::from(&data[..]))
                    .map_err(|err| to_io_error(err.to_string()))?
            }
            UdpAeadMethod2022::XChacha20Poly1305(cipher, _) => {
                let nonce = Nonce::from_slice(&header[0..24]);
                let mut extended_data = vec![];
                extended_data.extend_from_slice(session_id_packet_id.as_slice());
                extended_data.extend_from_slice(data);
                cipher
                    .encrypt(nonce, aes_gcm::aead::Payload::from(&extended_data[..]))
                    .map_err(|err| to_io_error(err.to_string()))?
            }
        };
        let mut result = vec![];
        result.extend_from_slice(header.as_slice());
        result.extend_from_slice(
            self.generate_extensible_identity_headers(session_id_packet_id)
                .as_slice(),
        );
        result.extend_from_slice(body.as_slice());
        return Ok(result);
    }
    fn decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>, io::Error> {
        let mut separate_header = vec![];
        separate_header.extend_from_slice(&self.read_session_id.to_be_bytes());
        separate_header.extend_from_slice(&self.read_packet_id.to_be_bytes());

        let mut result = match &self.body_read_cipher {
            None => {
                vec![]
            }
            Some(cipher) => match cipher {
                UdpAeadMethod2022::Aes256Gcm(cipher) => {
                    let nonce = Nonce::from_slice(&separate_header[4..16]);
                    cipher
                        .decrypt(nonce, aes_gcm::aead::Payload::from(&data[..]))
                        .map_err(|err| to_io_error(err.to_string()))?
                }
                UdpAeadMethod2022::Aes128Gcm(cipher) => {
                    let nonce = Nonce::from_slice(&separate_header[4..16]);
                    cipher
                        .decrypt(nonce, aes_gcm::aead::Payload::from(&data[..]))
                        .map_err(|err| to_io_error(err.to_string()))?
                }
                UdpAeadMethod2022::XChacha20Poly1305(cipher, nonce) => {
                    let nonce = Nonce::from_slice(nonce);
                    let result = cipher
                        .decrypt(nonce, aes_gcm::aead::Payload::from(&data[..]))
                        .map_err(|err| to_io_error(err.to_string()))?;
                    let session_id: [u8; 8] = <[u8; 8]>::try_from(&result[..8])
                        .map_err(|err| to_io_error(err.to_string()))?;
                    let read_session_id = u64::from_be_bytes(session_id);
                    let packet_id: [u8; 8] = <[u8; 8]>::try_from(&result[8..16])
                        .map_err(|err| to_io_error(err.to_string()))?;
                    let read_packet_id = u64::from_be_bytes(packet_id);
                    self.read_session_id = read_session_id;
                    self.read_packet_id = read_packet_id;
                    result[16..].to_vec()
                }
            },
        };
        let start = 1 + 8 + 8;
        let padding_len: [u8; 2] = <[u8; 2]>::try_from(&result.as_slice()[start..start + 2])
            .map_err(|err| to_io_error(err.to_string()))?;
        let padding_len = u16::from_be_bytes(padding_len) as usize;
        return Ok(result[1 + 8 + 8 + 2 + padding_len..].to_vec());
    }

    fn encode_udp_packet(&mut self, data: &[u8]) -> Result<Vec<u8>, io::Error> {
        return self.encrypt_udp(&data[..]);
    }

    fn generate_extensible_identity_headers(&mut self, session_id_packet_id: Vec<u8>) -> Vec<u8> {
        if self.keys.len() == 1 {
            return vec![];
        }
        let mut result = vec![];
        let mut i = 0;
        for key in self.keys.as_slice() {
            let plaintext = xor(&self.keys_hash[i + 1], &session_id_packet_id);
            match self.body_write_cipher {
                UdpAeadMethod2022::Aes256Gcm(_) => {
                    let mut block = GenericArray::from_slice(&plaintext[..16]).clone();
                    let aes_key = Key::<Aes256>::from_slice(&key[..32]);
                    let c = Aes256::new(aes_key);
                    c.encrypt_block(&mut block);
                    result.extend_from_slice(block.as_slice());
                }
                UdpAeadMethod2022::Aes128Gcm(_) => {
                    let mut block = GenericArray::from_slice(&plaintext[..16]).clone();
                    let aes_key = Key::<Aes128>::from_slice(&key[..16]);
                    let c = Aes128::new(aes_key);
                    c.encrypt_block(&mut block);
                    result.extend_from_slice(block.as_slice());
                }
                UdpAeadMethod2022::XChacha20Poly1305(_, _) => {}
            }
            i = i + 1;
            if i == self.keys.len() - 1 {
                break;
            }
        }
        return result;
    }
}

impl Cipher for CipherUdpAead2022 {
    fn buffer_address_and_port(&mut self, address_and_port: &[u8]) {
        self.address_and_port.extend_from_slice(address_and_port);
    }

    fn encode_data(&mut self, data: &[u8]) -> Result<Vec<u8>, io::Error> {
        let mut new_data = vec![];
        if !self.address_and_port.is_empty() {
            let client = vec![0];
            new_data.extend_from_slice(&client);
            let since_the_epoch = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|err| to_io_error(err.to_string()))?
                .as_secs();
            new_data.extend_from_slice(&since_the_epoch.to_be_bytes()[..]);
            let padding_len = self.padding_len.to_be_bytes();
            new_data.extend_from_slice(&padding_len[..]);
            let mut padding_bytes = vec![0u8; self.padding_len as usize];
            for i in 0..(self.padding_len as usize) {
                padding_bytes[i] = rand::thread_rng().gen_range(0..255);
            }
            new_data.extend_from_slice(&padding_bytes[..]);
            new_data.extend_from_slice(self.address_and_port.split().as_bytes());
        }
        new_data.extend_from_slice(data);
        let encrypted = self.encode_udp_packet(new_data.as_slice());
        self.write_packet_id += 1;
        return encrypted;
    }
    fn next_data_len(&mut self) -> PacketLen {
        return match self.read_state {
            ReadState::ReadHeader => match self.header_cipher {
                UdpHeaderMethod2022::Aes256Gcm(_, _) | UdpHeaderMethod2022::Aes128Gcm(_, _) => {
                    PacketLen::Must(16)
                }
                UdpHeaderMethod2022::Chacha20Poly1305 => PacketLen::Must(24),
            },
            ReadState::ReadBody => PacketLen::NotMatter,
        };
    }

    fn decode_data(&mut self, data: &[u8]) -> Result<DecodeResult, io::Error> {
        return match self.read_state {
            ReadState::ReadHeader => {
                match &self.header_cipher {
                    UdpHeaderMethod2022::Aes256Gcm(_, cipher) => {
                        let mut block = GenericArray::from_slice(&data[..16]).clone();
                        cipher.decrypt_block(&mut block);
                        block.as_slice().to_vec();
                        let session_id: [u8; 8] = <[u8; 8]>::try_from(&block.as_slice()[..8])
                            .map_err(|err| to_io_error(err.to_string()))?;
                        let read_session_id = u64::from_be_bytes(session_id);
                        let packet_id: [u8; 8] = <[u8; 8]>::try_from(&block.as_slice()[8..16])
                            .map_err(|err| to_io_error(err.to_string()))?;
                        let read_packet_id = u64::from_be_bytes(packet_id);
                        self.read_session_id = read_session_id;
                        self.read_packet_id = read_packet_id;
                        let sub_key = ss2022_sub_key(
                            &read_session_id.to_be_bytes(),
                            self.keys[self.keys.len() - 1].as_slice(),
                            self.key_len,
                        );
                        let aead_key = Key::<Aes256Gcm>::from_slice(&sub_key[..self.key_len]);
                        let body_cipher = UdpAeadMethod2022::Aes256Gcm(Aes256Gcm::new(aead_key));
                        self.body_read_cipher = Some(body_cipher);
                    }
                    UdpHeaderMethod2022::Aes128Gcm(_, cipher) => {
                        let mut block = GenericArray::from_slice(&data[..16]).clone();
                        cipher.decrypt_block(&mut block);
                        block.as_slice().to_vec();
                        let session_id: [u8; 8] = <[u8; 8]>::try_from(&block.as_slice()[..8])
                            .map_err(|err| to_io_error(err.to_string()))?;
                        let read_session_id = u64::from_be_bytes(session_id);
                        let packet_id: [u8; 8] = <[u8; 8]>::try_from(&block.as_slice()[8..16])
                            .map_err(|err| to_io_error(err.to_string()))?;
                        let read_packet_id = u64::from_be_bytes(packet_id);
                        self.read_session_id = read_session_id;
                        self.read_packet_id = read_packet_id;
                        let sub_key = ss2022_sub_key(
                            &read_session_id.to_be_bytes(),
                            self.keys[self.keys.len() - 1].as_slice(),
                            self.key_len,
                        );
                        let aead_key = Key::<Aes128Gcm>::from_slice(&sub_key[..self.key_len]);
                        let body_cipher = UdpAeadMethod2022::Aes128Gcm(Aes128Gcm::new(aead_key));
                        self.body_read_cipher = Some(body_cipher);
                    }
                    UdpHeaderMethod2022::Chacha20Poly1305 => {
                        let cipher = XChaCha20Poly1305::new_from_slice(
                            &self.keys[self.keys.len() - 1][..self.key_len],
                        )
                        .map_err(|err| to_io_error(err.to_string()))?;
                        self.body_read_cipher = Some(UdpAeadMethod2022::XChacha20Poly1305(
                            cipher,
                            data[..24].to_vec(),
                        ));
                    }
                }
                self.read_state = ReadState::ReadBody;
                Ok(DecodeResult::Skip)
            }

            ReadState::ReadBody => {
                let result = self.decrypt(&data[..])?;
                self.read_state = ReadState::ReadHeader;
                Ok(DecodeResult::Data(result))
            }
        };
    }
}

pub enum ReadState {
    ReadHeader,
    ReadBody,
}
