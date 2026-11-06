use crate::protos::router::CIDR;
use log::error;
use protobuf::CodedInputStream;
use std::fs::File;
use std::io;
use std::io::{BufReader, ErrorKind, Result};

/// Iterator for reading GeoIP CIDR blocks from geoip.dat file
pub struct GeoIPCIDRIter {
    cidrs: Vec<CIDR>,
    index: usize,
}

impl GeoIPCIDRIter {
    pub fn open(path: &str, code: &str) -> Result<Self> {
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);
        let cidrs = Self::load_cidrs(&mut reader, code)?;
        Ok(Self { cidrs, index: 0 })
    }

    fn load_cidrs(reader: &mut BufReader<File>, code: &str) -> Result<Vec<CIDR>> {
        let mut cis = CodedInputStream::new(reader);
        let mut cidrs = Vec::new();

        // Find the right section for this code
        while !cis.eof()? {
            let tag = cis.read_raw_tag_or_eof()?.unwrap_or(0);
            if tag != 10 {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "parse geo ip list tag is invalid",
                ));
            }
            let len = cis.read_raw_varint64()?;
            let pos1 = cis.pos();
            let tag = cis.read_raw_tag_or_eof()?.unwrap_or(0);
            if tag != 10 {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "parse geo ip tag is invalid",
                ));
            }
            let name = cis.read_string()?;
            if name.eq_ignore_ascii_case(code) {
                // Found the right section, read all CIDRs
                loop {
                    let tag = cis.read_raw_tag_or_eof()?;
                    if tag.is_none() || tag == Some(10) {
                        break;
                    }
                    if tag != Some(18) {
                        break;
                    }
                    match cis.read_message::<CIDR>() {
                        Ok(cidr) => cidrs.push(cidr),
                        Err(_) => break,
                    }
                }
                return Ok(cidrs);
            }
            let pos2 = cis.pos();
            cis.skip_raw_bytes((len - (pos2 - pos1)) as u32)?;
        }
        Ok(cidrs)
    }
}

impl Iterator for GeoIPCIDRIter {
    type Item = CIDR;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.cidrs.len() {
            let cidr = self.cidrs[self.index].clone();
            self.index += 1;
            Some(cidr)
        } else {
            None
        }
    }
}
