use tls_parser::TlsMessage::Handshake;
use tls_parser::{
    parse_tls_client_hello_extensions, parse_tls_plaintext, SNIType, TlsExtension,
    TlsMessageHandshake,
};

use crate::core::sniffer::{SniffProtocol, SniffResult, SnifferProtocol};

pub struct Tls {}

impl SnifferProtocol for Tls {
    fn sniff(data: &[u8]) -> (bool, Option<SniffResult>) {
        let res = parse_tls_plaintext(&data);
        match res {
            Ok((_, record)) => {
                if record.msg.len() > 0 {
                    if let Handshake(message) = record.msg[0].clone() {
                        if let TlsMessageHandshake::ClientHello(client_hello) = message.clone() {
                            if let Some(extensions_bytes) = client_hello.ext {
                                let result = parse_tls_client_hello_extensions(extensions_bytes);
                                match result {
                                    Ok((_, extensions)) => {
                                        for extension in extensions {
                                            if let TlsExtension::SNI(sni_vec) = extension {
                                                let mut count = 0;
                                                let mut result = SniffResult {
                                                    protocol: SniffProtocol::Tls,
                                                    domains: Vec::new(),
                                                };
                                                for sni in sni_vec {
                                                    if sni.0 == SNIType(0) {
                                                        count += 1;
                                                        result.domains.push(
                                                            String::from_utf8_lossy(sni.1)
                                                                .to_string(),
                                                        );
                                                    }
                                                }
                                                if count > 0 {
                                                    return (true, Some(result));
                                                }
                                            }
                                        }
                                    }
                                    Err(_) => {}
                                }
                            }
                        }
                    }
                }
            }
            Err(_) => {}
        }
        return (false, None);
    }
}
