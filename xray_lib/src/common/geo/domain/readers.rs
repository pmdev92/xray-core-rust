use crate::protos::router::Domain;
use log::error;
use protobuf::CodedInputStream;
use std::fs::File;
use std::io;
use std::io::{BufReader, ErrorKind, Result};

/// Iterator for reading GeoSite domains from geosite.dat file.
pub struct GeoSiteDomainIter {
    domains: Vec<Domain>,
    index: usize,
}

impl GeoSiteDomainIter {
    pub fn open(path: &str, code: &str) -> Result<Self> {
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);
        let domains = Self::load_domains(&mut reader, code)?;
        Ok(Self { domains, index: 0 })
    }

    fn load_domains(reader: &mut BufReader<File>, code: &str) -> Result<Vec<Domain>> {
        let mut cis = CodedInputStream::new(reader);
        let mut domains = Vec::new();

        // Find the right section for this code
        while !cis.eof()? {
            let tag = cis.read_raw_tag_or_eof()?.unwrap_or(0);
            if tag != 10 {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "parse geo site list tag is invalid",
                ));
            }
            let len = cis.read_raw_varint64()?;
            let pos1 = cis.pos();
            let tag = cis.read_raw_tag_or_eof()?.unwrap_or(0);
            if tag != 10 {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "parse geo site tag is invalid",
                ));
            }
            let name = cis.read_string()?;
            if name.eq_ignore_ascii_case(code) {
                // Found the right section, read all domains
                loop {
                    let tag = cis.read_raw_tag_or_eof()?;
                    if tag.is_none() || tag == Some(10) {
                        break;
                    }
                    if tag != Some(18) {
                        break;
                    }
                    match cis.read_message::<Domain>() {
                        Ok(domain) => domains.push(domain),
                        Err(_) => break,
                    }
                }
                return Ok(domains);
            }
            let pos2 = cis.pos();
            cis.skip_raw_bytes((len - (pos2 - pos1)) as u32)?;
        }
        Ok(domains)
    }
}

impl Iterator for GeoSiteDomainIter {
    type Item = Domain;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.domains.len() {
            let domain = self.domains[self.index].clone();
            self.index += 1;
            Some(domain)
        } else {
            None
        }
    }
}
