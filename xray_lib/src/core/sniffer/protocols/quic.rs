use s2n_codec::DecoderValueMut;
use s2n_quic_core::connection::id::ConnectionInfo;
use s2n_quic_core::crypto::InitialKey;
use s2n_quic_core::frame::{Frame, FrameMut};
use s2n_quic_core::inet::SocketAddress;
use s2n_quic_core::packet::interceptor::DecoderBufferMut;
use s2n_quic_core::packet::number::PacketNumberSpace;
use s2n_quic_core::packet::ProtectedPacket;
use s2n_quic_core::packet::ProtectedPacket::Initial;
use tls_parser::TlsMessage::Handshake;
use tls_parser::{
    parse_tls_client_hello_extensions, parse_tls_message_handshake, SNIType, TlsExtension,
    TlsMessageHandshake,
};

use crate::core::sniffer::{SniffProtocol, SniffResult, SnifferProtocol};

const VERSION_DRAFT29: u32 = 0xff00001d;
const VERSION1: u32 = 0x1;

pub struct Quic {}

impl SnifferProtocol for Quic {
    fn sniff(data: &[u8]) -> (bool, Option<SniffResult>) {
        let mut is_found = false;
        let mut sniff_result = SniffResult {
            protocol: SniffProtocol::Quic,
            domains: Vec::new(),
        };

        let mut crypto_packet = None;
        let mut data = data.to_vec();
        let mut decoder_buffer = DecoderBufferMut::new(data.as_mut_slice());
        let remote_address = SocketAddress::default();
        let connection_info = ConnectionInfo::new(&remote_address);
        while let Ok((packet, remaining)) =
            ProtectedPacket::decode(decoder_buffer, &connection_info, &20)
        {
            is_found = true;
            match packet {
                Initial(packet) => {
                    let dcid = packet.destination_connection_id().to_vec();
                    let (key, header_key) =
                        s2n_quic_crypto::initial::InitialKey::new_server(dcid.as_slice());

                    let packet = packet.unprotect(
                        &header_key,
                        PacketNumberSpace::Initial.new_packet_number(Default::default()),
                    );
                    let packet = match packet {
                        Ok(packet) => packet,
                        Err(_) => {
                            return (false, None);
                        }
                    };

                    let packet = packet.decrypt(&key);
                    let packet = match packet {
                        Ok(packet) => packet,
                        Err(_) => {
                            return (false, None);
                        }
                    };

                    let mut buffer = packet.payload;

                    loop {
                        let result = FrameMut::decode_mut(buffer);
                        match result {
                            Ok((frame, remaining)) => {
                                match frame {
                                    Frame::Crypto(crypto) => {
                                        crypto_packet = Some(crypto);
                                        break;
                                    }
                                    _ => {}
                                }
                                buffer = remaining;
                            }
                            Err(_) => {
                                break;
                            }
                        }
                    }
                }
                _ => {}
            }
            decoder_buffer = remaining;
        }
        let tls_record = match crypto_packet {
            None => {
                if is_found {
                    return (true, Some(sniff_result));
                } else {
                    return (false, None);
                }
            }
            Some(crypto_packet) => crypto_packet.data.as_less_safe_slice().to_vec(),
        };
        let result = parse_tls_message_handshake(tls_record.as_slice());
        match result {
            Ok((_, message)) => {
                if let Handshake(message) = message.clone() {
                    if let TlsMessageHandshake::ClientHello(client_hello) = message.clone() {
                        if let Some(extensions_bytes) = client_hello.ext {
                            let result = parse_tls_client_hello_extensions(extensions_bytes);

                            match result {
                                Ok((_, extensions)) => {
                                    for extension in extensions {
                                        if let TlsExtension::SNI(sni_vec) = extension {
                                            let mut count = 0;
                                            for sni in sni_vec {
                                                if sni.0 == SNIType(0) {
                                                    count += 1;
                                                    sniff_result.domains.push(
                                                        String::from_utf8_lossy(sni.1).to_string(),
                                                    );
                                                }
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
            Err(_) => {}
        }
        return (true, Some(sniff_result));
    }
}
