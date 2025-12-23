use std::hash::Hasher;
use std::io;
use std::io::ErrorKind;
use std::ops::Deref;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use aes::Aes128;
use aes_gcm::aead::consts::U12;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, AesGcm, Key, KeyInit, Nonce};
use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use chacha20::ChaCha20;
use chacha20poly1305::{ChaCha20Poly1305, ChaChaPoly1305};
use futures::ready;
use log::{error, trace};
use rand::random;
use tls_parser::nom::AsBytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::common::address::Address;
use crate::common::hex::decode_hex;
use crate::common::md5::md5;
use crate::common::net_location::NetLocation;
use crate::common::udp::TcpDatagramWrapper;
use crate::common::uuid::get_uuid;
use crate::common::vec::vec_allocate;
use crate::core::io::{AsyncXrayTcpStream, AsyncXrayUdpStream};
use crate::core::outbound::Outbound;
use crate::core::transport::{Transport, XrayTransport};
use crate::outbound::vmess::aead::seal_vmess_aead_header;
use crate::outbound::vmess::config::VmessSettings;
use crate::outbound::vmess::fnv1a::Fnv1aHasher;
use crate::outbound::vmess::kdf::{
    vmess_kdf_1_one_shot, KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_IV,
    KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_KEY, KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_IV,
    KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_KEY,
};
use crate::outbound::vmess::protocol::{
    generate_iv, generate_key, generate_respv, random_buffer,
    VmessInstruction, VmessReadState, VmessSecurity, VmessWriteState, AES_128_GCM_SECURITY_NUM, CHACHA20POLY1305_SECURITY_NUM,
    NONE_SECURITY_NUM, OPT_CHUNK_STREAM, VERSION,
};

mod aead;
pub mod config;
mod fnv1a;
mod kdf;
pub mod protocol;

pub struct VmessOutbound {
    address: String,
    port: u16,
    uuid: Arc<Vec<u8>>,
    transport: Box<dyn Transport>,
    security: String,
}

impl VmessOutbound {
    pub fn new(vmess_settings: VmessSettings, transport: Box<dyn Transport>) -> Self {
        let uuid_vec = get_uuid(vmess_settings.id.clone());
        let uuid = Arc::new(uuid_vec);
        trace!("vmess outbound address is {}", vmess_settings.address);
        trace!("vmess outbound port is {}", vmess_settings.port);
        trace!("vmess outbound uuid is {}", vmess_settings.id);
        Self {
            address: vmess_settings.address,
            port: vmess_settings.port,
            uuid,
            transport,
            security: vmess_settings.security,
        }
    }
}

#[async_trait]
impl Outbound for VmessOutbound {
    async fn dial_tcp(
        &self,
        context: Arc<crate::core::context::Context>,
        detour: Option<String>,
        net_location: Arc<NetLocation>,
    ) -> Result<Box<dyn AsyncXrayTcpStream>, io::Error> {
        return self
            .get_vmess_stream(context, detour, VmessInstruction::Tcp, net_location)
            .await;
    }

    async fn dial_udp(
        &self,
        context: Arc<crate::core::context::Context>,
        detour: Option<String>,
        net_location: Arc<NetLocation>,
    ) -> Result<Box<dyn AsyncXrayUdpStream>, io::Error> {
        let stream = self
            .get_vmess_stream(context.clone(), detour, VmessInstruction::Udp, net_location)
            .await?;
        Ok(TcpDatagramWrapper::new(context, stream).await?)
    }
}

impl VmessOutbound {
    async fn get_vmess_stream(
        &self,
        context: Arc<crate::core::context::Context>,
        detour: Option<String>,
        instruction: VmessInstruction,
        net_location: Arc<NetLocation>,
    ) -> Result<Box<dyn AsyncXrayTcpStream>, io::Error> {
        let address = Address::from(&self.address)?;
        let server_location = Arc::new(NetLocation::new(address, self.port));
        let transport = self
            .transport
            .dial(context, detour, server_location)
            .await?;
        let uuid = self.uuid.clone().to_vec();
        let vmess_key_write = Arc::new(generate_key());
        let vmess_iv_write = Arc::new(generate_iv());
        let vmess_key_read = decode_hex(&sha256::digest(vmess_key_write.clone().as_slice()))
            .map_err(|err| io::Error::new(ErrorKind::Other, err));
        let vmess_key_read = match vmess_key_read {
            Ok(key) => Arc::new(key[..16].to_vec()),
            Err(err) => {
                return Err(err);
            }
        };
        let vmess_iv_read = decode_hex(&sha256::digest(vmess_iv_write.clone().as_slice()))
            .map_err(|err| io::Error::new(ErrorKind::Other, err));
        let vmess_iv_read = match vmess_iv_read {
            Ok(iv) => Arc::new(iv[..16].to_vec()),
            Err(err) => {
                return Err(err);
            }
        };
        let security_number: u8;
        let security: VmessSecurity;

        let mut aes_write_aead: Option<AesGcm<Aes128, U12>> = None;
        let mut aes_read_aead: Option<AesGcm<Aes128, U12>> = None;
        let mut chacha_write_aead: Option<ChaChaPoly1305<ChaCha20>> = None;
        let mut chacha_read_aead: Option<ChaChaPoly1305<ChaCha20>> = None;
        match self.security.as_str() {
            "none" => {
                security_number = NONE_SECURITY_NUM;
                security = VmessSecurity::None;
            }
            "zero" => {
                security_number = NONE_SECURITY_NUM;
                security = VmessSecurity::None;
            }
            "auto" | "aes-128-gcm" => {
                security_number = AES_128_GCM_SECURITY_NUM;
                security = VmessSecurity::Aes128Gcm;
                let key = vmess_key_write.deref().clone();
                let key = Key::<Aes128Gcm>::from_slice(&key[..16]);
                aes_write_aead = Some(Aes128Gcm::new(key));
                let key = vmess_key_read.deref().clone();
                let key = Key::<Aes128Gcm>::from_slice(&key[..16]);
                aes_read_aead = Some(Aes128Gcm::new(key));
            }
            "chacha20-poly1305" => {
                security_number = CHACHA20POLY1305_SECURITY_NUM;
                security = VmessSecurity::ChaCha20Poly1305;
                let req_body_key = vmess_key_write.deref().clone();
                let mut key = [0u8; 32];
                let tmp = md5!(&req_body_key);
                key[0..16].copy_from_slice(&tmp);
                let tmp = md5!(md5!(&req_body_key));
                key[16..32].copy_from_slice(&tmp);
                chacha_write_aead = Some(ChaCha20Poly1305::new_from_slice(&key).unwrap());

                let res_body_key = vmess_key_read.deref().clone();
                let mut key = [0u8; 32];
                let tmp = md5!(&res_body_key);
                key[0..16].copy_from_slice(&tmp);
                let tmp = md5!(md5!(&res_body_key));
                key[16..32].copy_from_slice(&tmp);
                chacha_read_aead = Some(ChaCha20Poly1305::new_from_slice(&key).unwrap());
            }
            _ => {
                error!("unsupported vmess security");
                panic!();
            }
        }

        return Ok(Box::new(VmessStream {
            aes_write_aead,
            aes_read_aead,
            chacha_write_aead,
            chacha_read_aead,
            transport,
            read_state: VmessReadState::ReadHeaderLength,
            write_state: VmessWriteState::WriteHeader,
            auth: uuid,
            instruction: instruction as u8,
            net_location,
            vmess_key_write,
            vmess_iv_write,
            vmess_key_read,
            vmess_iv_read,
            vmess_response_authentication_value: Arc::new(generate_respv()),
            vmess_security_u8: Arc::new(security_number),
            vmess_security: security,
            read_buffer: BytesMut::new(),
            decrypted_read_buffer: BytesMut::new(),
            write_counter: 0,
            read_counter: 0,
            is_shutdown: false,
        }));
    }
}

struct VmessStream {
    aes_write_aead: Option<AesGcm<Aes128, U12>>,
    aes_read_aead: Option<AesGcm<Aes128, U12>>,
    chacha_write_aead: Option<ChaChaPoly1305<ChaCha20>>,
    chacha_read_aead: Option<ChaChaPoly1305<ChaCha20>>,
    transport: Box<dyn XrayTransport>,
    read_state: VmessReadState,
    write_state: VmessWriteState,
    auth: Vec<u8>,
    instruction: u8,
    net_location: Arc<NetLocation>,
    vmess_key_write: Arc<Vec<u8>>,
    vmess_iv_write: Arc<Vec<u8>>,
    vmess_key_read: Arc<Vec<u8>>,
    vmess_iv_read: Arc<Vec<u8>>,
    vmess_response_authentication_value: Arc<u8>,
    vmess_security_u8: Arc<u8>,
    vmess_security: VmessSecurity,
    read_buffer: BytesMut,
    decrypted_read_buffer: BytesMut,
    write_counter: u16,
    read_counter: u16,
    is_shutdown: bool,
}

impl VmessStream {
    pub fn create_header_data(&self, uuid: Vec<u8>, net_location: Arc<NetLocation>) -> Vec<u8> {
        let mut buf = BytesMut::new();
        buf.put_u8(VERSION);
        buf.put(&self.vmess_iv_write[..]);
        buf.put(&self.vmess_key_write[..]);
        buf.put_u8(*self.vmess_response_authentication_value);
        buf.put_u8(OPT_CHUNK_STREAM);
        let x = random::<u8>() % 16;
        // let x = 0;
        buf.put_u8((x << 4) | *self.vmess_security_u8.clone());
        buf.put_u8(0);
        buf.put_u8(self.instruction);

        let port = net_location.port().to_be_bytes();
        let _ = buf.put(port.as_slice());
        let address_bytes = net_location.address().to_vmess_vless_bytes();
        let _ = buf.put(address_bytes.as_slice());
        if x > 0 {
            let mut padding = [0u8; 16];
            random_buffer(&mut padding);
            buf.put(&padding[0..x as usize]);
        }
        let mut hasher = Fnv1aHasher::default();
        hasher.write(&buf);
        buf.put_u32(hasher.finish() as u32);

        let cmd_key = md5!(&uuid.to_vec(), b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
        seal_vmess_aead_header(&cmd_key, &buf).to_vec()
    }
    pub fn decode_header_len(&self, data: Vec<u8>) -> Result<usize, io::Error> {
        let header_key = vmess_kdf_1_one_shot(
            &self.vmess_key_read[..16],
            KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_KEY,
        );
        let header_iv = vmess_kdf_1_one_shot(
            &self.vmess_iv_read[..16],
            KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_IV,
        );
        let key = Key::<Aes128Gcm>::from_slice(&header_key[..16]);
        let nonce = Nonce::from_slice(&header_iv[..12]);
        let aead = Aes128Gcm::new(key);
        let result = aead
            .decrypt(nonce, data.as_slice())
            .map_err(|err| io::Error::new(ErrorKind::Other, err.to_string()));
        return match result {
            Ok(data) => {
                let length = ((data[0] as u16) << 8) | data[1] as u16;
                Ok(length as usize)
            }
            Err(err) => Err(err),
        };
    }
    pub fn decode_header_data(&self, data: Vec<u8>) -> Result<Vec<u8>, io::Error> {
        let payload_key = vmess_kdf_1_one_shot(
            &self.vmess_key_read[..16],
            KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_KEY,
        );
        let payload_iv = vmess_kdf_1_one_shot(
            &self.vmess_iv_read[..16],
            KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_IV,
        );
        let key = Key::<Aes128Gcm>::from_slice(&payload_key[..16]);
        let nonce = Nonce::from_slice(&payload_iv[..12]);
        let aead = Aes128Gcm::new(key);
        let result = aead
            .decrypt(nonce, data.as_slice())
            .map_err(|err| io::Error::new(ErrorKind::Other, err.to_string()));
        return match result {
            Ok(data) => Ok(data),
            Err(err) => Err(err),
        };
    }
    pub fn encrypt_data(&mut self, data: &[u8]) -> Result<Vec<u8>, io::Error> {
        let result = match self.vmess_security {
            VmessSecurity::None => Ok(data.to_vec()),
            VmessSecurity::Aes128Gcm => {
                let mut iv = self.write_counter.to_be_bytes().to_vec();
                let iv_chunked = &self.vmess_iv_write[2..12];
                iv.extend(iv_chunked);
                let nonce = Nonce::from_slice(&iv[..12]);
                let aead = match &self.aes_write_aead {
                    None => {
                        return Err(io::Error::from(ErrorKind::Other));
                    }
                    Some(aead) => aead,
                };
                let result = aead
                    .encrypt(nonce, data)
                    .map_err(|err| io::Error::new(ErrorKind::Other, err.to_string()));
                match result {
                    Ok(data) => Ok(data),
                    Err(err) => Err(err),
                }
            }
            VmessSecurity::ChaCha20Poly1305 => {
                let mut iv = self.write_counter.to_be_bytes().to_vec();
                let iv_chunked = &self.vmess_iv_write[2..12];
                iv.extend(iv_chunked);
                let nonce = Nonce::from_slice(&iv[..12]);
                let aead = match &self.chacha_write_aead {
                    None => {
                        return Err(io::Error::from(ErrorKind::Other));
                    }
                    Some(aead) => aead,
                };

                let result = aead
                    .encrypt(nonce, data)
                    .map_err(|err| io::Error::new(ErrorKind::Other, err.to_string()));
                match result {
                    Ok(data) => Ok(data),
                    Err(err) => Err(err),
                }
            }
        };

        return result;
    }
    pub fn decrypt_data(&mut self, data: &[u8]) -> Result<Vec<u8>, io::Error> {
        let result = match self.vmess_security {
            VmessSecurity::None => Ok(data.to_vec()),
            VmessSecurity::Aes128Gcm => {
                let mut iv = self.read_counter.to_be_bytes().to_vec();
                let iv_chunked = &self.vmess_iv_read[2..12];
                iv.extend(iv_chunked);
                let nonce = Nonce::from_slice(&iv[..12]);
                let aead = match &self.aes_read_aead {
                    None => {
                        return Err(io::Error::from(ErrorKind::Other));
                    }
                    Some(aead) => aead,
                };

                let result = aead
                    .decrypt(nonce, data)
                    .map_err(|err| io::Error::new(ErrorKind::Other, err.to_string()));
                match result {
                    Ok(data) => Ok(data),
                    Err(err) => Err(err),
                }
            }
            VmessSecurity::ChaCha20Poly1305 => {
                let mut iv = self.read_counter.to_be_bytes().to_vec();
                let iv_chunked = &self.vmess_iv_read[2..12];
                iv.extend(iv_chunked);
                let nonce = Nonce::from_slice(&iv[..12]);
                let aead = match &self.chacha_read_aead {
                    None => {
                        return Err(io::Error::from(ErrorKind::Other));
                    }
                    Some(aead) => aead,
                };
                let result = aead
                    .decrypt(nonce, data)
                    .map_err(|err| io::Error::new(ErrorKind::Other, err.to_string()));
                match result {
                    Ok(data) => Ok(data),
                    Err(err) => Err(err),
                }
            }
        };

        return result;
    }
}

impl AsyncRead for VmessStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.decrypted_read_buffer.is_empty() {
            let to_read = std::cmp::min(buf.remaining(), self.decrypted_read_buffer.len());
            let date = self.decrypted_read_buffer.split_to(to_read);
            buf.put_slice(date.as_bytes());
            return Poll::Ready(Ok(()));
        };

        if !self.read_buffer.is_empty() {
            if let VmessReadState::ReadHeaderLength = self.read_state {
                if self.read_buffer.len() >= 18 {
                    let data = self.read_buffer.split_to(18);
                    let result = self.decode_header_len(data.to_vec());
                    return match result {
                        Ok(length) => {
                            self.read_state = VmessReadState::ReadHeader(length);
                            cx.waker().wake_by_ref();
                            Poll::Pending
                        }
                        Err(err) => {
                            let message = format!(
                                "{{vmess-read-state: {:?}, message: {}}}",
                                self.read_state, err
                            );
                            let error = io::Error::new(err.kind(), message);
                            Poll::Ready(Err(error))
                        }
                    };
                }
            }
            if let VmessReadState::ReadHeader(length) = self.read_state {
                let length = 16 + length;
                if self.read_buffer.len() >= length {
                    let data = self.read_buffer.split_to(length);
                    let result = self.decode_header_data(data.to_vec());
                    return match result {
                        Ok(data) => {
                            if data.len() < 4 {
                                let message = format!(
                                    "{{vmess-read-state: {:?}, message: vmess header is less than 4 bytes}}",
                                    self.read_state
                                );
                                return Poll::Ready(Err(io::Error::new(
                                    ErrorKind::InvalidData,
                                    message,
                                )));
                            }
                            if self.vmess_response_authentication_value.deref().clone() != data[0] {
                                let message = format!(
                                    "{{vmess-read-state: {:?}, message: vmess response authentication value is not match the request}}",
                                    self.read_state
                                );
                                return Poll::Ready(Err(io::Error::new(
                                    ErrorKind::InvalidData,
                                    message,
                                )));
                            }
                            self.read_state = VmessReadState::ReadDataLength;
                            cx.waker().wake_by_ref();
                            Poll::Pending
                        }
                        Err(err) => {
                            let message = format!(
                                "{{vmess-read-state: {:?}, message: {}}}",
                                self.read_state, err
                            );
                            let error = io::Error::new(err.kind(), message);
                            Poll::Ready(Err(error))
                        }
                    };
                }
            }
            if let VmessReadState::ReadDataLength = self.read_state {
                if self.read_buffer.len() >= 2 {
                    let data = self.read_buffer.split_to(2);
                    let length = ((data[0] as u16) << 8) | data[1] as u16;
                    self.read_state = VmessReadState::ReadData(length);
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
            }
            if let VmessReadState::ReadData(length) = self.read_state {
                let length = length as usize;
                if self.read_buffer.len() >= length {
                    let data = self.read_buffer.split_to(length);
                    let result = self.decrypt_data(data.as_bytes());
                    return match result {
                        Ok(data) => {
                            self.read_counter = self.read_counter.wrapping_add(1);
                            self.decrypted_read_buffer.put_slice(data.as_slice());
                            self.read_state = VmessReadState::ReadDataLength;
                            cx.waker().wake_by_ref();
                            Poll::Pending
                        }
                        Err(err) => {
                            let message = format!(
                                "{{vmess-read-state: {:?}, message: {}}}",
                                self.read_state, err
                            );
                            let error = io::Error::new(err.kind(), message);
                            Poll::Ready(Err(error))
                        }
                    };
                }
            }
        };

        //read data from transport
        let mut buffer_vev = vec_allocate(buf.capacity());
        let mut buffer = ReadBuf::new(&mut buffer_vev);
        let result = ready!(Pin::new(&mut self.transport).poll_read(cx, &mut buffer));
        return match result {
            Ok(_) => {
                self.read_buffer.extend_from_slice(buffer.filled());
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(err) => {
                let message = format!(
                    "{{vmess-read-state: {:?}, message: {}}}",
                    self.read_state, err
                );
                let error = io::Error::new(err.kind(), message);
                Poll::Ready(Err(error))
            }
        };
    }
}

impl AsyncWrite for VmessStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        if let VmessWriteState::WriteHeader = self.write_state {
            let header_data = self.create_header_data(self.auth.clone(), self.net_location.clone());
            let result = ready!(Pin::new(&mut self.transport).poll_write(cx, &header_data));
            return match result {
                Ok(_) => {
                    // if count == 0 {
                    //     return Poll::Ready(Err(s2n_quic_io::Error::from(ErrorKind::BrokenPipe)));
                    // }
                    self.write_state = VmessWriteState::Done;
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Err(err) => {
                    let message = format!(
                        "{{vmess-write-state: {:?}, message: {}}}",
                        self.write_state, err
                    );
                    let error = io::Error::new(err.kind(), message);
                    Poll::Ready(Err(error))
                }
            };
        }
        let result = self.encrypt_data(buf);
        return match result {
            Ok(encrypted_data) => {
                let mut data = (encrypted_data.len() as u16).to_be_bytes().to_vec();
                data.extend(encrypted_data);
                let result = ready!(Pin::new(&mut self.transport).poll_write(cx, data.as_slice()));
                match result {
                    Ok(_) => {
                        self.write_counter = self.write_counter.wrapping_add(1);
                        Poll::Ready(Ok(buf.len()))
                    }
                    Err(err) => {
                        let message = format!(
                            "{{vmess-write-state: {:?}, message: {}}}",
                            self.write_state, err
                        );
                        let error = io::Error::new(err.kind(), message);
                        Poll::Ready(Err(error))
                    }
                }
            }
            Err(err) => {
                let message = format!(
                    "{{vmess-write-state: {:?}, message: {}}}",
                    self.write_state, err
                );
                let error = io::Error::new(err.kind(), message);
                Poll::Ready(Err(error))
            }
        };
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        return Pin::new(&mut self.get_mut().transport).poll_flush(cx);
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let this = self.get_mut();
        if !this.is_shutdown {
            let buf: Vec<u8> = vec![];
            let result = this.encrypt_data(buf.as_slice());
            match result {
                Ok(encrypted_data) => {
                    let mut data = (encrypted_data.len() as u16).to_be_bytes().to_vec();
                    data.extend(encrypted_data);
                    let result =
                        ready!(Pin::new(&mut this.transport).poll_write(cx, data.as_slice()));
                    match result {
                        Ok(_) => {
                            this.write_counter = this.write_counter.wrapping_add(1);
                        }
                        Err(_) => {}
                    }
                }
                Err(_) => {}
            };
        }
        this.is_shutdown = true;
        return Pin::new(&mut this.transport).poll_shutdown(cx);
    }
}

impl AsyncXrayTcpStream for VmessStream {}
