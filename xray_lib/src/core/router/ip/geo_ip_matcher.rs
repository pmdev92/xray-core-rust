use crate::core::router::{Apply, RouteLocation};
use crate::protos::router::domain::Type;
use std::sync::{Arc, LockResult, Mutex};

pub(crate) struct GeoIpMatcher {
    path: String,
    code: String,
}
impl GeoIpMatcher {
    pub fn new(path: String, code: String) -> Self {
        Self { path, code }
    }
}
impl Apply for GeoIpMatcher {
    fn apply(&self, route_location: Arc<RouteLocation>) -> bool {
        let file = File::open(&self.path);
        let file = match file {
            Ok(file) => file,
            Err(error) => {
                error!("{}", error);
                return false;
            }
        };
        let mut reader = BufReader::new(file);
        let cidrs = GeoIPCIDRIter::new(&mut reader, &self.code);
        let cidrs = match cidrs {
            Ok(cidrs) => cidrs,
            Err(error) => {
                error!("{}", error);
                return false;
            }
        };

        for cidr in cidrs {
            let mut helper: Option<Box<dyn Apply>> = None;
            let mut ip = None;
            if cidr.ip.len() == 4 {
                let ip_v4: std::result::Result<[u8; 4], _> = cidr.ip.try_into();
                match ip_v4 {
                    Ok(ip_v4) => {
                        ip = Some(IpAddr::from(ip_v4));
                    }
                    Err(_) => {}
                }
            } else if cidr.ip.len() == 16 {
                let ip_v6: std::result::Result<[u8; 16], _> = cidr.ip.try_into();
                match ip_v6 {
                    Ok(ip_v6) => {
                        ip = Some(IpAddr::from(ip_v6));
                    }
                    Err(_) => {}
                }
            }
            match ip {
                None => {}
                Some(ip) => {
                    let prefix = cidr.prefix as u8;
                    let cidr = cidr::IpCidr::new(ip, prefix);
                    match cidr {
                        Ok(cidr) => {
                            helper = Some(Box::new(CidrMatcher::new(cidr)));
                        }
                        Err(err) => {
                            warn!(
                                "router ip `{}` prefix `{}` parse error: {}",
                                ip, prefix, err
                            );
                        }
                    }
                }
            }
            if let Some(matcher) = helper {
                let result = matcher.apply(route_location.clone());
                if result {
                    return result;
                }
            }
        }
        false
    }
}
use crate::core::router::ip::cidr_matcher::CidrMatcher;
use crate::protos::router::{Domain, GeoSite, GeoSiteList, CIDR};
use byteorder::ReadBytesExt;
use bytes::Buf;
use log::{error, warn};
use prost::encoding::encode_varint;
use protobuf::{CodedInputStream, Message};
use std::collections::VecDeque;
use std::fs::File;
use std::io;
use std::io::{BufRead, BufReader, ErrorKind, Read, Result, Seek, SeekFrom};
use std::net::IpAddr;

pub struct GeoIPCIDRIter<'a> {
    cis: CodedInputStream<'a>,
}

impl<'a> GeoIPCIDRIter<'a> {
    pub fn new(reader: &'a mut BufReader<File>, code: &str) -> Result<Self> {
        let mut cis = CodedInputStream::new(reader);
        let mut finded = false;
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
                finded = true;
                break;
            }
            let pos2 = cis.pos();

            cis.skip_raw_bytes((len - (pos2 - pos1)) as u32)?;
        }
        Ok(Self { cis })
    }

    fn fetch_next_cidr(&mut self) -> Result<CIDR> {
        let tag = self.cis.read_raw_tag_or_eof()?;
        match tag {
            None => {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "parse geo ip cidr tag is invalid",
                ));
            }
            Some(tag) => {
                if tag != 18 {
                    return Err(io::Error::new(
                        ErrorKind::InvalidData,
                        "parse geo ip cidr tag is invalid",
                    ));
                }
            }
        }
        let cidr: CIDR = self.cis.read_message()?;
        Ok(cidr)
    }
}

impl<'a> Iterator for GeoIPCIDRIter<'a> {
    type Item = CIDR;

    fn next(&mut self) -> Option<Self::Item> {
        let cidr = self.fetch_next_cidr();
        match cidr {
            Ok(cidr) => Some(cidr),
            Err(_) => None,
        }
    }
}
