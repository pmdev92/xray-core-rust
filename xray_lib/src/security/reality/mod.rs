use std::io;
use std::io::{Error, ErrorKind};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use crate::common::hex::decode_hex;
use crate::core::io::AsyncXrayTcpStream;
use crate::core::security::{Security, XraySecurity};
use crate::security::reality::config::RealityConfig;
use crate::security::reality::tls::RealitySecurityStream;
use crate::security::reality::verify::RealityNoCertVerifier;
use crate::security::reality::xtls::RealityXtlsSecurityStream;
use crate::security::tls::tls::TlsSecurityStream;
use crate::security::tls::verify::TlsNoCertVerifier;
use crate::security::tls::xtls::TlsXtlsSecurityStream;
use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use bytes::BytesMut;
use chrono::Utc;
use futures::ready;
use log::{error, trace};
use reality_tokio_rustls::client::TlsStream;
use reality_tokio_rustls::rustls::client::ClientConfig;
use reality_tokio_rustls::rustls::pki_types::ServerName;
use reality_tokio_rustls::rustls::ClientConnection;
use reality_tokio_rustls::TlsConnector;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Mutex, RwLock};

pub mod config;
mod tls;
mod verify;
mod xtls;

#[derive(Debug)]
pub struct RealitySecurity {
    server_name: String,
    is_early_data: bool,
    early_data_len: usize,
    client_config: RwLock<Arc<ClientConfig>>,
}

impl RealitySecurity {
    pub fn new(config: &RealityConfig) -> Self {
        let public_key = match URL_SAFE_NO_PAD.decode(&config.public_key) {
            Ok(public_key) => public_key,
            Err(err) => {
                error!("{}", err);
                panic!()
            }
        };
        if public_key.len() != 32 {
            error!("reality public key is invalid");
            panic!()
        }
        let short_id = decode_hex(&config.short_id);
        let short_id = match short_id {
            Ok(short_id) => short_id,
            Err(err) => {
                error!("{}", err);
                panic!()
            }
        };
        if short_id.len() > 8 {
            error!("reality short id hex string length is more than 8 bytes");
            panic!()
        }
        let version_x = config.version_x.unwrap_or(1);
        let version_y = config.version_x.unwrap_or(8);
        let version_z = config.version_x.unwrap_or(6);

        let mut client_config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(RealityNoCertVerifier {}))
            .with_no_client_auth();
        client_config.add_reality(
            public_key.clone(),
            short_id.clone(),
            version_x.clone(),
            version_y.clone(),
            version_z.clone(),
        );
        let client_config = Arc::new(client_config);
        let is_early_data = config.is_early_data.unwrap_or(false);
        let mut early_data_len = 0;
        if is_early_data {
            if early_data_len == 0 {
                early_data_len = 2560
            }
            if early_data_len > 2560 {
                early_data_len = 2560
            }
        }
        Self {
            server_name: config.server_name.clone(),
            is_early_data,
            early_data_len,
            client_config: RwLock::new(client_config),
        }
    }

    pub async fn dial_xtls(
        &self,
        stream: Box<dyn AsyncXrayTcpStream + Send + Sync>,
    ) -> Result<Box<RealityXtlsSecurityStream>, io::Error> {
        let config = self.client_config.read().await.clone();
        let xtls = RealityXtlsSecurityStream::new(
            self.server_name.clone(),
            config,
            stream,
            self.is_early_data.clone(),
            self.early_data_len,
        )?;
        Ok(Box::new(xtls))
    }
}

#[async_trait]
impl Security for RealitySecurity {
    async fn dial(
        &self,
        stream: Box<dyn AsyncXrayTcpStream + Send + Sync>,
    ) -> Result<Box<dyn XraySecurity>, io::Error> {
        let config = self.client_config.read().await.clone();

        let reality = RealitySecurityStream::new(
            self.server_name.clone(),
            config,
            stream,
            self.is_early_data,
            self.early_data_len,
        );
        Ok(Box::new(reality))
    }

    fn get_domain(&self) -> Option<String> {
        Some(self.server_name.clone())
    }

    async fn add_alpn(&self, alpn_string: String) {
        let needle = alpn_string.into_bytes();
        let mut cfg_arc = self.client_config.write().await;
        let cfg = Arc::make_mut(&mut *cfg_arc);
        let exists = cfg.alpn_protocols.iter().any(|p| p == &needle);
        if !exists {
            cfg.alpn_protocols.push(needle);
        }
    }
}
