use bytes::{Buf, BufMut, Bytes, BytesMut};
use log::warn;
use quinn_proto::coding::Codec;
use quinn_proto::VarInt;
use std::collections::VecDeque;
use std::io;
use std::io::Write;

#[derive(Clone, Debug)]
pub(crate) struct UDPMessage {
    pub(crate) session_id: u32,
    pub(crate) packet_id: u16,
    pub(crate) fragment_id: u8,
    pub(crate) fragment_count: u8,
    pub(crate) address_length: VarInt,
    pub(crate) address: String,
    pub(crate) data: Vec<u8>,
}

impl UDPMessage {
    pub fn new(session_id: u32, packet_id: u16, address: String, data: Bytes) -> UDPMessage {
        let address_length = VarInt::from_u64(address.len() as u64).unwrap_or(VarInt::from_u32(0));
        Self {
            session_id,
            packet_id,
            fragment_id: 0,
            fragment_count: 1,
            address_length,
            address,
            data: data.to_vec(),
        }
    }

    pub fn header_size(&self) -> usize {
        let mut header_size = 4usize + 2 + 1 + 1;

        let mut bytes = BytesMut::new();
        let address_length =
            VarInt::from_u64(self.address.len() as u64).unwrap_or(VarInt::from_u32(0));

        address_length.encode(&mut bytes);

        header_size = header_size + bytes.len();

        let address_length = self.address.len();
        header_size = header_size + address_length;

        header_size
    }

    pub fn size(&self) -> usize {
        self.header_size() + self.data.len()
    }

    pub fn encode(&self) -> Bytes {
        let mut bytes = BytesMut::new();
        bytes.put_u32(self.session_id);
        bytes.put_u16(self.packet_id);
        bytes.put_u8(self.fragment_id);
        bytes.put_u8(self.fragment_count);
        self.address_length.encode(&mut bytes);

        let mut writer = bytes.writer();
        let _ = writer.write(self.address.as_bytes());
        let _ = writer.write(&self.data);
        writer.into_inner().freeze()
    }

    pub fn decode(mut bytes: Bytes) -> Result<UDPMessage, io::Error> {
        let len = bytes.len();
        let error = io::Error::new(io::ErrorKind::InvalidData, "invalid udp message bytes");
        let session_id = if (bytes.remaining() > 4) {
            bytes.get_u32()
        } else {
            return Err(error);
        };
        let packet_id = if (bytes.remaining() > 2) {
            bytes.get_u16()
        } else {
            return Err(error);
        };

        let fragment_id = if (bytes.remaining() > 1) {
            bytes.get_u8()
        } else {
            return Err(error);
        };
        let fragment_count = if (bytes.remaining() > 1) {
            bytes.get_u8()
        } else {
            return Err(error);
        };

        let address_length = VarInt::decode(&mut bytes);
        let address_length = match address_length {
            Ok(address_length) => address_length,
            Err(_) => {
                return Err(error);
            }
        };

        let address_length_usize = address_length.into_inner() as usize;
        let mut all = BytesMut::new();
        all.extend_from_slice(&bytes[..]);
        if (all.len() < address_length_usize) {
            return Err(error);
        }
        let address = all.split_to(address_length_usize);
        let address = std::str::from_utf8(&address[..]);
        let address = match address {
            Ok(address) => address.to_string(),
            Err(_) => {
                return Err(error);
            }
        };
        let data = all.to_vec();
        Ok(UDPMessage {
            session_id,
            packet_id,
            fragment_id,
            fragment_count,
            address_length,
            address,
            data,
        })
    }

    pub fn fragment(&self, max_len: usize) -> Vec<UDPMessage> {
        let mut full_data = BytesMut::from(self.data.as_slice());
        let max_data_size = if (max_len < self.header_size()) {
            self.header_size() + 5
        } else {
            max_len - self.header_size()
        };
        let fragment_count = ((self.data.len() / max_data_size) + 1) as u8;
        let mut result: VecDeque<UDPMessage> = VecDeque::new();
        for i in 0..fragment_count {
            let fragment_data = full_data.split_to(max_data_size.min(full_data.len()));
            let current = Self {
                session_id: self.session_id.clone(),
                packet_id: self.packet_id.clone(),
                fragment_id: i,
                fragment_count,
                address_length: self.address_length.clone(),
                address: self.address.clone(),
                data: fragment_data.to_vec(),
            };
            result.push_back(current);
        }
        result.into()
    }
}

#[derive(Default)]
pub struct UDPMessageDeFragmenter {
    pub pkt_id: u16,
    pub frags: Vec<Option<UDPMessage>>,
    pub cnt: u16,
}

impl UDPMessageDeFragmenter {
    pub fn feed(&mut self, pkt: UDPMessage) -> Option<UDPMessage> {
        if pkt.fragment_count == 1 {
            return Some(pkt);
        }
        if pkt.fragment_count <= pkt.fragment_id {
            warn!(
                "invalid frag, id, count: {}, {}",
                pkt.fragment_id, pkt.fragment_count
            );
            return None;
        }
        let frag_id = pkt.fragment_id as usize;

        if pkt.packet_id != self.pkt_id || pkt.fragment_count as usize != self.frags.len() {
            // new packet, overwrite the old one
            // if the new packet frags is 1, should already return
            self.pkt_id = pkt.packet_id;
            self.frags.clear();
            self.frags.resize(pkt.fragment_count as usize, None);
            self.cnt = 0;
            self.frags[frag_id] = Some(pkt);
            self.cnt += 1;
        } else if frag_id < self.frags.len() && self.frags[frag_id].is_none() {
            self.frags[frag_id] = Some(pkt);
            self.cnt += 1;
            if self.cnt as usize == self.frags.len() {
                // now we have all fragments
                let frags = std::mem::take(&mut self.frags);
                let mut iters = frags.into_iter().map(|x| x.unwrap());
                let mut pkt0 = iters.next().unwrap();
                pkt0.fragment_count = 1;
                pkt0.fragment_id = 0;
                for pkt in iters {
                    pkt0.data.extend_from_slice(&pkt.data);
                }
                return Some(pkt0);
            }
        }
        None
    }
}
