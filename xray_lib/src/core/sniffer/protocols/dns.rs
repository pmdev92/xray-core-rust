use crate::core::sniffer::{SniffProtocol, SniffResult, SnifferProtocol};
use bytes::Bytes;

pub struct Dns {}

impl SnifferProtocol for Dns {
    fn sniff(data: &[u8]) -> (bool, Option<SniffResult>) {
        let bytes = Bytes::copy_from_slice(&data[..]);

        let result = dns_message_parser::Dns::decode(bytes);
        match result {
            Ok(dns) => {
                let mut domains = vec![];
                for question in dns.questions {
                    let mut domain = question.domain_name.to_string();
                    if (domain.len() > 0) {
                        domain.pop();
                    }
                    domains.push(domain);
                }
                let result = SniffResult {
                    protocol: SniffProtocol::Dns,
                    domains,
                };
                return (true, Some(result));
            }
            Err(_) => {}
        }

        (false, None)
    }
}
