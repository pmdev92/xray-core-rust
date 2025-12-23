use std::any::{type_name, Any};
use std::fmt::{format, Debug};
use std::io;
use std::io::ErrorKind;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use aes::cipher::consts::U12;
use aes::Aes192;
use aes_gcm::{Aes128Gcm, Aes256Gcm, AesGcm};
use async_trait::async_trait;
use byteorder::{BigEndian, ByteOrder};
use bytes::{Buf, BytesMut};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use futures::ready;
use log::{error, trace};
use tls_parser::nom::AsBytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use uuid::uuid;

use crate::common::address;
use crate::common::address::Address;
use crate::common::net_location::NetLocation;
use crate::common::udp::TcpDatagramWrapper;
use crate::common::uuid::get_uuid;
use crate::common::vec::vec_allocate;
use crate::core::io::{AsyncXrayTcpStream, AsyncXrayUdpStream};
use crate::core::outbound::Outbound;
use crate::core::transport::{Transport, XrayTransport};
use crate::outbound::shadowsocks::config::ShadowSocksSettings;
use crate::outbound::shadowsocks::protocol::{
    new_shadowsocks_tcp_cipher, new_shadowsocks_udp_cipher, ss2022_password_to_key, Cipher,
};
use crate::outbound::shadowsocks::tcp::{ShadowSocksTcpStream, TcpWriteState, UdpOverTcpReadState};
use crate::outbound::shadowsocks::udp::ShadowSocksUdpStream;
use crate::outbound::shadowsocks::udp_over_tcp_version_1::ShadowSocksUdpOverTcpVersion1Stream;
use crate::outbound::shadowsocks::udp_over_tcp_version_2::ShadowSocksUdpOverTcpVersion2Stream;
use crate::outbound::vless::config::VlessSettings;
use crate::outbound::vless::VlessOutbound;
use crate::transport::tcp::TcpTransportStream;

mod cipher_aead;
mod cipher_none;
mod cipher_tcp_aead_2022;
mod cipher_udp_aead_2022;
pub mod config;
mod protocol;
mod tcp;
mod udp;
mod udp_over_tcp_version_1;
mod udp_over_tcp_version_2;

#[derive(Clone, Copy)]
pub enum ShadowSocksMethod {
    None,
    Aes256Gcm,
    Aes192Gcm,
    Aes128Gcm,
    Chacha20Poly1305,
    XChaCha20Poly1305,
    Blake3Aes256Gcm,
    Blake3Aes128Gcm,
    Blake3Chacha20Poly1305,
}
pub struct ShadowSocksOutbound {
    address: String,
    port: u16,
    method: ShadowSocksMethod,
    password: Arc<Vec<u8>>,
    transport: Box<dyn Transport>,
    uot: bool,
    uot_version: i32,
    uot_is_connect: bool,
}

impl ShadowSocksOutbound {
    pub fn new(
        shadow_socks_settings: ShadowSocksSettings,
        transport: Box<dyn Transport>,
    ) -> Result<Self, io::Error> {
        let password_vec = shadow_socks_settings.password.as_bytes().to_vec();
        trace!(
            "shadow socks outbound address is {}",
            shadow_socks_settings.address
        );
        trace!(
            "shadow socks outbound port is {}",
            shadow_socks_settings.port
        );
        trace!(
            "shadow socks outbound password is {}",
            shadow_socks_settings.password
        );
        trace!(
            "shadow socks outbound method is {}",
            shadow_socks_settings.method
        );

        let method = match shadow_socks_settings.method.as_str() {
            "none" => ShadowSocksMethod::None,
            "aes-256-gcm" => ShadowSocksMethod::Aes256Gcm,
            "aes-192-gcm" => ShadowSocksMethod::Aes192Gcm,
            "aes-128-gcm" => ShadowSocksMethod::Aes128Gcm,
            "chacha20-poly1305" | "chacha20-ietf-poly1305" => ShadowSocksMethod::Chacha20Poly1305,
            "xchacha20-poly1305" | "xchacha20-ietf-poly1305" => {
                ShadowSocksMethod::XChaCha20Poly1305
            }
            "2022-blake3-aes-256-gcm" => {
                ss2022_password_to_key(shadow_socks_settings.password.as_bytes(), 32)?;
                ShadowSocksMethod::Blake3Aes256Gcm
            }
            "2022-blake3-aes-128-gcm" => {
                ss2022_password_to_key(shadow_socks_settings.password.as_bytes(), 16)?;
                ShadowSocksMethod::Blake3Aes128Gcm
            }
            "2022-blake3-chacha20-poly1305" | "2022-blake3-chacha20-ietf-poly1305" => {
                let keys = ss2022_password_to_key(shadow_socks_settings.password.as_bytes(), 32)?;
                if keys.len() > 1 {
                    return Err(io::Error::new(
                        ErrorKind::InvalidData,
                        "the cipher `{}` not supported multi password in shadowsocks outbound",
                    ));
                }
                ShadowSocksMethod::Blake3Chacha20Poly1305
            }
            _ => {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    format!(
                        "the cipher `{}` not supported in shadowsocks outbound",
                        shadow_socks_settings.method
                    ),
                ));
            }
        };
        let mut uot = false;
        let mut uot_version = 2;
        let mut uot_is_connect = true;
        if let Some(value) = shadow_socks_settings.uot {
            uot = value;
        }
        if let Some(value) = shadow_socks_settings.uot_version {
            if value == 1 {
                uot_version = 1;
            }
        }
        if let Some(value) = shadow_socks_settings.uot_is_connect {
            uot_is_connect = value;
        }
        Ok(Self {
            address: shadow_socks_settings.address,
            port: shadow_socks_settings.port,
            password: Arc::new(password_vec),
            method,
            transport,
            uot,
            uot_version,
            uot_is_connect,
        })
    }
}

#[async_trait]
impl Outbound for ShadowSocksOutbound {
    async fn dial_tcp(
        &self,
        context: Arc<crate::core::context::Context>,
        detour: Option<String>,
        net_location: Arc<NetLocation>,
    ) -> Result<Box<dyn AsyncXrayTcpStream>, io::Error> {
        let address = Address::from(&self.address)?;
        let server_location = Arc::new(NetLocation::new(address, self.port));

        let transport = self
            .transport
            .dial(context, detour, server_location)
            .await?;

        let port_bytes = net_location.port().to_be_bytes().to_vec();

        let address_bytes: Vec<u8> = net_location.address().to_socks_trojan_bytes();

        let cipher: Box<dyn Cipher> =
            new_shadowsocks_tcp_cipher(self.method, self.password.clone())?;

        return Ok(Box::new(ShadowSocksTcpStream {
            cipher,
            transport,
            write_state: TcpWriteState::WriteAddressAndPort,
            port: port_bytes,
            address: address_bytes,
            read_buffer: BytesMut::new(),
            decoded_buffer: BytesMut::new(),
            write_buffer: BytesMut::new(),
        }));
    }

    async fn dial_udp(
        &self,
        context: Arc<crate::core::context::Context>,
        detour: Option<String>,
        net_location: Arc<NetLocation>,
    ) -> Result<Box<dyn AsyncXrayUdpStream>, io::Error> {
        return if self.uot {
            let address = Address::from(&self.address)?;
            let server_location = Arc::new(NetLocation::new(address, self.port));

            let transport = self
                .transport
                .dial(context.clone(), detour, server_location)
                .await?;

            let port_bytes = net_location.port().to_be_bytes().to_vec();

            let address_bytes: Vec<u8> = net_location.address().to_socks_trojan_bytes();

            let cipher: Box<dyn Cipher> =
                new_shadowsocks_tcp_cipher(self.method, self.password.clone())?;
            if self.uot_version == 1 {
                let stream = Box::new(ShadowSocksUdpOverTcpVersion1Stream {
                    cipher,
                    transport,
                    write_state: TcpWriteState::WriteAddressAndPort,
                    read_state: UdpOverTcpReadState::ReadAddressAndPort,
                    port: port_bytes,
                    address: address_bytes,
                    read_buffer: BytesMut::new(),
                    decoded_buffer: BytesMut::new(),
                });

                Ok(TcpDatagramWrapper::new(context, stream).await?)
            } else {
                let stream = Box::new(ShadowSocksUdpOverTcpVersion2Stream {
                    is_connect: self.uot_is_connect,
                    connect_packed_sent: false,
                    cipher,
                    transport,
                    write_state: TcpWriteState::WriteAddressAndPort,
                    read_state: UdpOverTcpReadState::ReadAddressAndPort,
                    port: port_bytes,
                    address: address_bytes,
                    read_buffer: BytesMut::new(),
                    decoded_buffer: BytesMut::new(),
                });
                Ok(TcpDatagramWrapper::new(context, stream).await?)
            }
        } else {
            let address = Address::from(&self.address)?;
            let server_location = Arc::new(NetLocation::new(address, self.port));

            let udp_stream = context.dial_udp(detour, server_location).await?;

            let port_bytes = net_location.port().to_be_bytes().to_vec();

            let address_bytes: Vec<u8> = net_location.address().to_socks_trojan_bytes();

            let cipher: Box<dyn Cipher> =
                new_shadowsocks_udp_cipher(self.method, self.password.clone())?;
            let stream = Box::new(ShadowSocksUdpStream::new(
                cipher,
                udp_stream,
                port_bytes,
                address_bytes,
            ));
            Ok(stream)
        };
    }
}
