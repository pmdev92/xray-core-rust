use crate::core::io::AsyncXrayTcpStream;
use crate::core::security::{Security, XraySecurity};
use crate::security::tls::config::TlsConfig;
use crate::security::tls::tls::TlsSecurityStream;
use crate::security::tls::xtls::TlsXtlsSecurityStream;
use async_trait::async_trait;
use bytes::BytesMut;
use std::io;
use std::io::{BufRead, Error, Read, Write};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::RwLock;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use verify::TlsNoCertVerifier;

pub mod config;

pub mod tls;
mod tls_new;
pub mod verify;
pub mod xtls;

#[derive(Debug)]
pub struct TlsSecurity {
    server_name: String,
    is_early_data: bool,
    early_data_len: usize,
    client_config: RwLock<Arc<ClientConfig>>,
}

impl TlsSecurity {
    pub fn new(config: &TlsConfig) -> Self {
        let mut client_config: ClientConfig;
        let verify = config.verify.unwrap_or(true);
        let alpn_list = config.alpn.clone().unwrap_or_default();
        if verify {
            let mut root_store = RootCertStore::empty();
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            client_config = ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();
        } else {
            client_config = ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(TlsNoCertVerifier {}))
                .with_no_client_auth();
        }
        client_config.enable_early_data = true;
        if !alpn_list.is_empty() {
            client_config.alpn_protocols = alpn_list.into_iter().map(|s| s.into_bytes()).collect();
        }
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
    ) -> Result<Box<TlsXtlsSecurityStream>, io::Error> {
        let config = self.client_config.read().await.clone();
        let xtls = TlsXtlsSecurityStream::new(
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
impl Security for TlsSecurity {
    async fn dial(
        &self,
        stream: Box<dyn AsyncXrayTcpStream + Send + Sync>,
    ) -> Result<Box<dyn XraySecurity>, Error> {
        let config = self.client_config.read().await.clone();

        let tcp = TlsSecurityStream::new(
            self.server_name.clone(),
            config,
            stream,
            self.is_early_data,
            self.early_data_len,
        );
        Ok(Box::new(tcp))
    }

    fn get_domain(&self) -> Option<String> {
        return Some(self.server_name.clone());
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

pub(crate) struct OldTlsSecurityStream {
    connection: tokio_rustls::client::TlsStream<Box<dyn AsyncXrayTcpStream + Send + Sync>>,
    read_buffer: BytesMut,
}
