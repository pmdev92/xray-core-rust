use std::io;

use bytes::BytesMut;
use tls_parser::nom::AsBytes;

use crate::outbound::shadowsocks::protocol::{Cipher, DecodeResult, PacketLen};

pub(crate) struct CipherNone {
    address_and_port: BytesMut,
}
impl CipherNone {
    pub(crate) fn new() -> Self {
        return Self {
            address_and_port: BytesMut::new(),
        };
    }
}

impl Cipher for CipherNone {
    fn buffer_address_and_port(&mut self, address_and_port: &[u8]) {
        self.address_and_port.extend_from_slice(address_and_port);
    }

    fn encode_data(&mut self, data: &[u8]) -> Result<Vec<u8>, io::Error> {
        if !self.address_and_port.is_empty() {
            let address_and_port = self.address_and_port.split();
            let mut result = vec![];
            result.extend_from_slice(address_and_port.as_bytes());
            result.extend_from_slice(data);
            return Ok(result);
        }
        return Ok(data.to_vec());
    }

    fn next_data_len(&mut self) -> PacketLen {
        return PacketLen::NotMatter;
    }

    fn decode_data(&mut self, data: &[u8]) -> Result<DecodeResult, io::Error> {
        return Ok(DecodeResult::Data(data.to_vec()));
    }
}
