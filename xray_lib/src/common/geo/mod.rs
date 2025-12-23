use std::io::ErrorKind;
use std::{fs, io};

use bytes::Buf;
use protobuf::CodedInputStream;

use crate::protos::router::{GeoIP, GeoSite};

pub fn parse_geo_ip(path: &str, code: &str) -> GeoIP {
    let mut geo_ip = GeoIP::default();
    let code = code.to_uppercase();
    let data = fs::read(path);
    match data {
        Ok(data) => {
            let mut data = find(data, code.as_bytes().to_vec());
            match data {
                Ok(data) => {
                    let mut data = data.reader();
                    use ::protobuf::Message;
                    let mut stream = CodedInputStream::new(&mut data);
                    let _ = geo_ip.merge_from(&mut stream);
                }
                Err(_) => {}
            }
        }
        Err(_) => {}
    }

    return geo_ip;
}

pub fn parse_geo_site(path: &str, code: &str) -> GeoSite {
    let mut deo_site = GeoSite::default();
    let code = code.to_uppercase();

    let data = fs::read(path);
    match data {
        Ok(data) => {
            let mut data = find(data, code.as_bytes().to_vec());
            match data {
                Ok(data) => {
                    let mut data = data.reader();
                    use ::protobuf::Message;
                    let mut stream = CodedInputStream::new(&mut data);
                    let _ = deo_site.merge_from(&mut stream);
                }
                Err(_) => {}
            }
        }
        Err(_) => {}
    }
    return deo_site;
}

fn find(mut data: Vec<u8>, code: Vec<u8>) -> Result<Vec<u8>, io::Error> {
    let code_length = code.len();

    if code_length == 0 {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "1- parse geo site country code is invalid",
        ));
    }
    let mut j = 0;
    loop {
        j += 1;
        let mut data_length = data.len();
        if data_length < 2 {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "2- parse geo site data is invalid",
            ));
        }
        let (x, y) = decode_var_int(&data[1..]);
        if x == 0 && y == 0 {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "3- parse geo site data is invalid",
            ));
        }

        let head_length = 1 + y;
        let body_length = x;

        data_length -= head_length;
        if data_length < body_length {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "4- parse geo site data is invalid",
            ));
        }
        data = data[head_length..].to_vec();
        if data[1] as usize == code_length {
            let mut i = 0;
            while i < code_length && data[2 + i] == code[i] {
                if i + 1 == code_length {
                    return Ok(data[..body_length].to_vec());
                }
                i += 1;
            }
        }
        if data_length == body_length {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "5- parse geo site data is invalid",
            ));
        }
        data = data[body_length..].to_vec();
    }
}

fn decode_var_int(data: &[u8]) -> (usize, usize) {
    let mut n: usize = 0;
    let mut x: usize = 0;
    for shift in (0..64).step_by(7) {
        if n >= data.len() {
            return (0, 0);
        }
        let b = data[n] as usize;
        n += 1;
        x |= (b & 0x7F) << shift;
        if (b & 0x80) == 0 {
            return (x, n);
        }
    }
    return (0, 0);
}
