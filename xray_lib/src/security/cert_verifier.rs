use crate::common::hex::decode_hex;

use log::{error, trace};
use rustls_pki_types::ServerName::DnsName;
use s2n_quic_core::ct::ConstantTimeEq;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio_rustls::rustls::client::WebPkiServerVerifier;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{DigitallySignedStruct, Error, RootCertStore, SignatureScheme, crypto};

use x509_parser::prelude::{FromDer, X509Certificate};

#[derive(Debug, Clone, PartialEq, Eq)]
enum VerifyResult {
    CertNotFound,
    FoundLeaf,
    FoundCA,
}

#[derive(Debug, Clone)]
pub struct CertVerifier {
    roots: RootCertStore,
    pinned_peer_cert_sha256: Option<Vec<Vec<u8>>>,
    verify_peer_cert_by_name: Option<Vec<String>>,
    server_name: String,
}

impl CertVerifier {
    pub fn new(
        roots: RootCertStore,
        pinned_peer_cert_sha256: Option<Vec<String>>,
        verify_peer_cert_by_name: Option<Vec<String>>,
        server_name: String,
    ) -> Self {
        let pinned_peer_cert_sha256 = pinned_peer_cert_sha256.map(|pins| {
            pins.into_iter()
                .filter_map(|pin| decode_hex(&pin).ok())
                .filter(|pin| !pin.is_empty())
                .collect::<Vec<_>>()
        });

        Self {
            roots,
            pinned_peer_cert_sha256,
            verify_peer_cert_by_name,
            server_name,
        }
    }

    fn verify_chain(
        &self,
        certs: &[CertificateDer<'_>],
        pinned: &[Vec<u8>],
    ) -> (VerifyResult, Option<Vec<u8>>) {
        if certs.is_empty() {
            return (VerifyResult::CertNotFound, None);
        }

        let leaf_hash = sha256_cert(&certs[0]);

        for pin in pinned {
            if leaf_hash.as_slice().ct_eq(pin.as_slice()).into() {
                return (VerifyResult::FoundLeaf, None);
            }
        }

        for cert in certs.iter().skip(1) {
            let cert_hash = sha256_cert(cert);
            if !pinned
                .iter()
                .any(|pin| cert_hash.as_slice().ct_eq(pin.as_slice()).into())
            {
                continue;
            }
            let is_ca = match X509Certificate::from_der(cert.as_ref()) {
                Ok((_, parsed_cert)) => parsed_cert.is_ca(),

                Err(_) => false,
            };
            if is_ca {
                return (VerifyResult::FoundCA, Some(cert.as_ref().to_vec()));
            }
        }
        (VerifyResult::CertNotFound, None)
    }

    fn verify_peer_cert_name(&self) -> bool {
        let names = match &self.verify_peer_cert_by_name {
            Some(names) if !names.is_empty() => names,
            _ => return true,
        };

        names
            .iter()
            .any(|name| self.server_name == *name || self.server_name.contains(name))
    }
}

impl ServerCertVerifier for CertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let mut certs = Vec::with_capacity(intermediates.len() + 1);

        certs.push(end_entity.clone());

        for cert in intermediates {
            certs.push(cert.clone());
        }

        let mut verify_result = VerifyResult::CertNotFound;
        let mut verified_cert: Option<Vec<u8>> = None;
        if let Some(pinned) = &self.pinned_peer_cert_sha256 {
            (verify_result, verified_cert) = self.verify_chain(&certs, pinned);
            trace!("tls verify ({:?})", verify_result);
            if let VerifyResult::FoundLeaf = verify_result {
                trace!("tls verify with pinned peed cert found leaf");
                return Ok(ServerCertVerified::assertion());
            }
            if let VerifyResult::CertNotFound = verify_result {
                return Err(Error::General(
                    "server certificate does not match any pinned certificate".to_string(),
                ));
            }
        };

        if let Some(names) = &self.verify_peer_cert_by_name {
            let verifier = WebPkiServerVerifier::builder(Arc::new(self.roots.clone()))
                .build()
                .map_err(|err| {
                    Error::General(format!(
                        "failed to build WebPki certificate verifier: {err}"
                    ))
                })?;
            for name in names {
                let server_name = ServerName::try_from(name.as_str());
                if let Ok(server_name) = server_name {
                    let result =
                        verifier.verify_server_cert(&certs[0], &certs[1..], &server_name, &[], now);
                    if let Ok(_) = result {
                        trace!("verify server certificate with name {:?}", server_name);
                        return Ok(ServerCertVerified::assertion());
                    }
                }
            }
            if verify_result == VerifyResult::FoundCA {
                return Err(Error::General(
                    "peer cert is invalid (against pinned CA and verifyPeerCertByName)".into(),
                ));
            }
            return Err(Error::General(
                "peer cert is invalid (against root CAs and verifyPeerCertByName)".into(),
            ));
        };

        if let VerifyResult::FoundCA = verify_result {
            let ca = verified_cert
                .ok_or_else(|| Error::General("pinned CA certificate is missing".to_string()))?;

            let mut roots = RootCertStore::empty();
            let ca = CertificateDer::from(ca.to_vec());
            roots.add(ca).map_err(|err| {
                Error::General(format!("failed to add pinned CA to root store: {err}"))
            })?;

            let verifier = WebPkiServerVerifier::builder(Arc::new(roots))
                .build()
                .map_err(|err| {
                    Error::General(format!(
                        "failed to build WebPki certificate verifier: {err}"
                    ))
                })?;
            let result = verifier.verify_server_cert(&certs[0], &certs[1..], server_name, &[], now);
            return match result {
                Ok(_) => {
                    trace!("verify server certificate with ca");
                    Ok(ServerCertVerified::assertion())
                }
                Err(_) => Err(Error::General(
                    "peer cert is invalid (against pinned CA and server name)".into(),
                )),
            };
        };
        Err(Error::General("peer cert is invalid".into()))
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

fn sha256_cert(cert: &CertificateDer<'_>) -> Vec<u8> {
    let mut hasher = Sha256::new();

    hasher.update(cert.as_ref());

    hasher.finalize().to_vec()
}
