use crate::core::router::domain::full_domain_matcher::FullDomainMatcher;
use crate::core::router::domain::partial_matcher::PartialMatcher;
use crate::core::router::domain::regular_expression_matcher::RegularExpressionMatcher;
use crate::core::router::domain::sub_domain_matcher::SubDomainMatcher;
use crate::core::router::{Apply, RouteLocation};
use crate::protos::router::domain::Type;
use std::sync::{Arc, LockResult, Mutex};

pub(crate) struct GeoDomainMatcher {
    path: String,
    code: String,
}
impl GeoDomainMatcher {
    pub fn new(path: String, code: String) -> Self {
        Self { path, code }
    }
}
impl Apply for GeoDomainMatcher {
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
        let domains = GeoSiteDomainIter::new(&mut reader, &self.code);
        let domains = match domains {
            Ok(domains) => domains,
            Err(error) => {
                error!("{}", error);
                return false;
            }
        };

        for domain in domains {
            let mut helper: Option<Box<dyn Apply>> = None;
            match domain.type_.enum_value() {
                Ok(domain_type) => match domain_type {
                    Type::Plain => {
                        helper = Some(Box::new(PartialMatcher::new(domain.value.clone())));
                    }
                    Type::Regex => {
                        helper = Some(Box::new(RegularExpressionMatcher::new(
                            domain.value.clone(),
                        )));
                    }
                    Type::Domain => {
                        helper = Some(Box::new(SubDomainMatcher::new(domain.value.clone())));
                    }
                    Type::Full => {
                        helper = Some(Box::new(FullDomainMatcher::new(domain.value.clone())));
                    }
                },
                Err(_) => {}
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
use crate::protos::router::{Domain, GeoSite, GeoSiteList};
use byteorder::ReadBytesExt;
use bytes::Buf;
use log::error;
use prost::encoding::encode_varint;
use protobuf::{CodedInputStream, Message};
use std::collections::VecDeque;
use std::fs::File;
use std::io;
use std::io::{BufRead, BufReader, ErrorKind, Read, Result, Seek, SeekFrom};

pub struct GeoSiteDomainIter<'a> {
    cis: CodedInputStream<'a>,
}

impl<'a> GeoSiteDomainIter<'a> {
    pub fn new(reader: &'a mut BufReader<File>, code: &str) -> Result<Self> {
        let mut cis = CodedInputStream::new(reader);
        let mut finded = false;
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
                finded = true;
                break;
            }
            let pos2 = cis.pos();

            cis.skip_raw_bytes((len - (pos2 - pos1)) as u32)?;
        }
        Ok(Self { cis })
    }

    fn fetch_next_domains(&mut self) -> Result<Domain> {
        let tag = self.cis.read_raw_tag_or_eof()?;
        match tag {
            None => {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "parse geo site domain tag is invalid",
                ));
            }
            Some(tag) => {
                if tag != 18 {
                    return Err(io::Error::new(
                        ErrorKind::InvalidData,
                        "parse geo site domain tag is invalid",
                    ));
                }
            }
        }
        let domain: Domain = self.cis.read_message()?;
        Ok(domain)
    }
}

impl<'a> Iterator for GeoSiteDomainIter<'a> {
    type Item = Domain;

    fn next(&mut self) -> Option<Self::Item> {
        let domain = self.fetch_next_domains();
        match domain {
            Ok(domain) => Some(domain),
            Err(_) => None,
        }
    }
}
