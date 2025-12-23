use bytes::{Buf, BufMut, Bytes, BytesMut};
use log::{error, warn};
use std::collections::VecDeque;
use std::io;
use std::io::Write;
use std::sync::Arc;
use std::time::Instant;
use tls_parser::nom::AsBytes;

use crate::common::net_location::NetLocation;
use crate::outbound::quinn_tuic::protocol::VERSION;

#[derive(Clone, Debug)]
pub(crate) struct Packet {
    pub(crate) assoc_id: u16,
    pub(crate) packet_id: u16,
    pub(crate) fragment_id: u8,
    pub(crate) fragment_total: u8,
    pub(crate) size: u16,
    pub(crate) address: Arc<NetLocation>,
    pub(crate) data: Vec<u8>,
    pub(crate) time: Instant,
}

impl Packet {
    const TYPE_CODE: u8 = 0x02;

    pub fn new(assoc_id: u16, packet_id: u16, address: Arc<NetLocation>, data: Vec<u8>) -> Packet {
        Self {
            assoc_id,
            packet_id,
            fragment_id: 0,
            fragment_total: 1,
            size: data.len() as u16,
            address,
            data,
            time: Instant::now(),
        }
    }

    pub fn header_size(&self) -> usize {
        let mut header_size = 2usize + 2 + 1 + 1 + 1 + self.address.to_tuic_bytes().len();
        header_size
    }

    pub fn size(&self) -> usize {
        self.header_size() + self.data.len()
    }

    pub fn encode(&self) -> Bytes {
        let mut bytes = BytesMut::new();
        bytes.put_u8(VERSION);
        bytes.put_u8(Packet::TYPE_CODE);
        bytes.put_u16(self.assoc_id);
        bytes.put_u16(self.packet_id);
        bytes.put_u8(self.fragment_total);
        bytes.put_u8(self.fragment_id);
        bytes.put_u16(self.size);

        let mut writer = bytes.writer();
        let _ = writer.write(self.address.to_tuic_bytes().as_bytes());
        let _ = writer.write(self.data.as_slice());
        writer.into_inner().freeze()
    }

    pub fn decode(mut bytes: Bytes) -> Result<Packet, io::Error> {
        let version = if (bytes.remaining() > 1) {
            bytes.get_u8()
        } else {
            return Err(error(
                "udp packet get version remaining buffer size is less than 1".to_string(),
            ));
        };
        if version != 5 {
            return Err(error("udp packet get version is invalid".to_string()));
        }

        let code = if (bytes.remaining() > 1) {
            bytes.get_u8()
        } else {
            return Err(error(
                "udp packet get code remaining buffer size is less than 1".to_string(),
            ));
        };
        if code != 2 {
            return Err(error("udp packet get code is invalid".to_string()));
        }

        let assoc_id = if (bytes.remaining() > 2) {
            bytes.get_u16()
        } else {
            return Err(error(
                "udp packet get assoc_id remaining buffer size is less than 2".to_string(),
            ));
        };
        let packet_id = if (bytes.remaining() > 2) {
            bytes.get_u16()
        } else {
            return Err(error(
                "udp packet get packet_id remaining buffer size is less than 2".to_string(),
            ));
        };

        let fragment_total = if (bytes.remaining() > 1) {
            bytes.get_u8()
        } else {
            return Err(error(
                "udp packet get fragment_total remaining buffer size is less than 1".to_string(),
            ));
        };
        let fragment_id = if (bytes.remaining() > 1) {
            bytes.get_u8()
        } else {
            return Err(error(
                "udp packet get fragment_id remaining buffer size is less than 1".to_string(),
            ));
        };
        let size = if (bytes.remaining() > 2) {
            bytes.get_u16()
        } else {
            return Err(error(
                "udp packet get size remaining buffer size is less than 2".to_string(),
            ));
        };
        let tuic_address = NetLocation::parse_tuic(&mut bytes);
        let tuic_address = match tuic_address {
            Ok(tuic_address) => tuic_address,
            Err(error) => {
                return Err(error);
            }
        };
        let data = bytes.to_vec();
        if data.len() != size as usize {
            return Err(error(
                format!(
                    "udp packet get data remaining buffer size is less than {}",
                    size
                )
                .to_string(),
            ));
        }
        Ok(Packet {
            assoc_id,
            packet_id,
            fragment_total,
            fragment_id,
            address: Arc::new(tuic_address),
            size,
            data,
            time: Instant::now(),
        })
    }

    pub fn fragment(&self, packet_id: u16, max_len: usize) -> Vec<Packet> {
        let mut full_data = BytesMut::from(self.data.as_slice());
        let max_data_size = if (max_len < self.header_size()) {
            self.header_size() + 5
        } else {
            max_len - self.header_size()
        };
        let fragment_count = ((self.data.len() / max_data_size) + 1) as u8;
        let mut result: VecDeque<Packet> = VecDeque::new();
        for i in 0..fragment_count {
            let fragment_data = if (full_data.len() > max_data_size) {
                full_data.split_to(max_data_size)
            } else {
                full_data.split()
            };
            let current = Self {
                assoc_id: self.assoc_id.clone(),
                packet_id,
                fragment_id: i,
                fragment_total: fragment_count,
                size: fragment_data.len() as u16,
                address: self.address.clone(),
                data: fragment_data.to_vec(),
                time: Instant::now(),
            };
            result.push_back(current);
        }
        result.into()
    }
}

pub fn error(message: String) -> io::Error {
    return io::Error::new(io::ErrorKind::InvalidData, message);
}

#[derive(Default)]
pub struct PacketDeFragmenter {
    pub pkt_id: u16,
    pub frags: Vec<Option<Packet>>,
    pub cnt: u16,
}

impl PacketDeFragmenter {
    pub fn feed(&mut self, pkt: Packet) -> Option<Packet> {
        if pkt.fragment_total == 1 {
            return Some(pkt);
        }
        if pkt.fragment_total <= pkt.fragment_id {
            warn!(
                "invalid frag, id, count: {}, {}",
                pkt.fragment_id, pkt.fragment_total
            );
            return None;
        }
        let frag_id = pkt.fragment_id as usize;

        if pkt.packet_id != self.pkt_id || pkt.fragment_total as usize != self.frags.len() {
            // new packet, overwrite the old one
            // if the new packet frags is 1, should already return
            self.pkt_id = pkt.packet_id;
            self.frags.clear();
            self.frags.resize(pkt.fragment_total as usize, None);
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
                pkt0.fragment_total = 1;
                pkt0.fragment_id = 0;
                for pkt in iters {
                    pkt0.data.extend_from_slice(&pkt.data);
                }
                return Some(pkt0);
            }
        }
        None
    }
    pub fn free_expired(&mut self) {
        let mut to_remove = false;
        for frag in self.frags.iter() {
            if let Some(packet) = frag {
                if Instant::now().duration_since(packet.time).as_secs() > 60 {
                    to_remove = true;
                    break;
                };
            }
        }
        self.frags.clear();
    }
}
