use crate::core::io::AsyncXrayTcpStream;
use crate::core::security::{Security, XraySecurity};
use crate::security::cert_verifier::CertVerifier;
use crate::security::skip_cert_verifier::SkipCertVerifier;
use crate::security::tls::config::TlsConfig;
use crate::security::tls::tls::TlsSecurityStream;
use crate::security::tls::xtls::TlsXtlsSecurityStream;
use async_trait::async_trait;
use base64::Engine;
use bytes::BytesMut;
use log::error;
use rustls_pki_types::EchConfigListBytes;
use std::io;
use std::io::ErrorKind::Other;
use std::io::{BufRead, Error, ErrorKind, Read, Write};
use std::ops::Deref;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::RwLock;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::rustls::RootCertStore;
use tokio_rustls::rustls::client::{EchConfig, EchMode};
use tokio_rustls::rustls::crypto::aws_lc_rs;
use tokio_rustls::rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES;

pub mod config;

mod ech;
pub mod tls;
mod tls_new;
pub mod xtls;

#[derive(Debug)]
pub struct TlsSecurity {
    server_name: String,
    is_early_data: bool,
    early_data_len: usize,
    client_config: RwLock<Option<Arc<ClientConfig>>>,
    config: TlsConfig,
}

impl TlsSecurity {
    pub fn new(config: &TlsConfig) -> io::Result<Self> {
        let is_early_data = config.is_early_data.unwrap_or(false);
        let mut early_data_len = config.early_data_len.unwrap_or(2560);
        if is_early_data {
            if early_data_len == 0 {
                early_data_len = 2560
            }
            if early_data_len > 2560 {
                early_data_len = 2560
            }
        }

        Ok(Self {
            server_name: config.server_name.clone(),
            is_early_data,
            early_data_len,
            client_config: RwLock::new(None),
            config: config.clone(),
        })
    }

    pub async fn dial_xtls(
        &self,
        stream: Box<dyn AsyncXrayTcpStream + Send + Sync>,
    ) -> Result<Box<TlsXtlsSecurityStream>, Error> {
        let config = self.get_config().await?;
        let xtls = TlsXtlsSecurityStream::new(
            self.server_name.clone(),
            config,
            stream,
            self.is_early_data.clone(),
            self.early_data_len,
        )?;
        Ok(Box::new(xtls))
    }
    async fn get_config(&self) -> io::Result<Arc<ClientConfig>> {
        if self.client_config.read().await.is_none() {
            self.client_config
                .write()
                .await
                .replace(self.build_config().await?);
        }
        let mut config_write = self.client_config.read().await;
        if let Some(config) = config_write.deref() {
            return Ok(config.clone());
        }
        Err(Error::new(Other, "there is no config set"))
    }
    async fn build_config(&self) -> io::Result<Arc<ClientConfig>> {
        let builder = match self.build_ech_mode().await? {
            Some(ech_mode) => {
                ClientConfig::builder_with_provider(aws_lc_rs::default_provider().into())
                    .with_ech(ech_mode)
                    .map_err(|err| {
                        Error::new(
                            ErrorKind::InvalidData,
                            format!("unable to configure ech: {err}"),
                        )
                    })?
            }
            None => ClientConfig::builder(),
        };
        let mut client_config: ClientConfig;
        let verify = self.config.verify.unwrap_or(true);
        let alpn_list = self.config.alpn.clone().unwrap_or_default();
        if verify {
            let has_pinned = self
                .config
                .pinned_peer_cert_sha256
                .as_ref()
                .map_or(false, |v| !v.is_empty());
            let has_name = self
                .config
                .verify_peer_cert_by_name
                .as_ref()
                .map_or(false, |v| !v.is_empty());
            if has_pinned || has_name {
                let mut root_store = RootCertStore::empty();
                root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                let verifier = CertVerifier::new(
                    root_store,
                    self.config.pinned_peer_cert_sha256.clone(),
                    self.config.verify_peer_cert_by_name.clone(),
                    self.config.server_name.clone(),
                );
                client_config = builder
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(verifier))
                    .with_no_client_auth();
            } else {
                let mut root_store = RootCertStore::empty();
                root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                client_config = builder
                    .with_root_certificates(root_store)
                    .with_no_client_auth();
            }
        } else {
            client_config = builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(SkipCertVerifier {}))
                .with_no_client_auth();
        }

        client_config.enable_early_data = self.is_early_data.clone();
        if !alpn_list.is_empty() {
            client_config.alpn_protocols = alpn_list.into_iter().map(|s| s.into_bytes()).collect();
        }
        return Ok(Arc::new(client_config));
    }

    async fn build_ech_mode(&self) -> io::Result<Option<EchMode>> {
        let Some(encoded) = self.config.ech_config_list.as_ref() else {
            return Ok(None);
        };
        if encoded.is_empty() {
            return Ok(None);
        }
        let bytes = ech::resolve_ech(encoded, &self.config.server_name).await?;
        let list = EchConfigListBytes::from(bytes);
        let ech_config = EchConfig::new(list, ALL_SUPPORTED_SUITES).map_err(|err| {
            Error::new(ErrorKind::InvalidData, format!("invalid ech config: {err}"))
        })?;
        Ok(Some(EchMode::Enable(ech_config)))
    }
}

#[async_trait]
impl Security for TlsSecurity {
    async fn dial(
        &self,
        stream: Box<dyn AsyncXrayTcpStream + Send + Sync>,
    ) -> Result<Box<dyn XraySecurity>, Error> {
        let config = self.get_config().await?;
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
        Some(self.server_name.clone())
    }

    async fn add_alpn(&self, alpn_string: String) {
        let needle = alpn_string.into_bytes();
        let mut config = self.get_config().await;
        if let Ok(mut config) = config {
            let mut config = config.deref().clone();
            let exists = config.alpn_protocols.iter().any(|p| p == &needle);
            if !exists {
                config.alpn_protocols.push(needle);
            }
            self.client_config.write().await.replace(Arc::new(config));
        }
    }
}

pub(crate) struct OldTlsSecurityStream {
    connection: tokio_rustls::client::TlsStream<Box<dyn AsyncXrayTcpStream + Send + Sync>>,
    read_buffer: BytesMut,
}
