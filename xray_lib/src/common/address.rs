use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum Address {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Hostname(String),
}

impl Address {
    pub const UNSPECIFIED: Self = Address::Ipv4(Ipv4Addr::UNSPECIFIED);
    pub fn from(s: &str) -> std::io::Result<Self> {
        let mut dots = 0;
        let mut possible_ipv4 = true;
        let mut possible_ipv6 = true;
        let mut possible_hostname = true;
        for b in s.as_bytes().iter() {
            let c = *b;
            if c == b':' {
                possible_ipv4 = false;
                possible_hostname = false;
                break;
            } else if c == b'.' {
                possible_ipv6 = false;
                dots += 1;
                if dots > 3 {
                    // can only be a hostname.
                    break;
                }
            } else if (c >= b'A' && c <= b'F') || (c >= b'a' && c <= b'f') {
                possible_ipv4 = false;
            } else if c < b'0' || c > b'9' {
                possible_ipv4 = false;
                possible_ipv6 = false;
                break;
            }
        }

        if possible_ipv4 && dots == 3 {
            if let Ok(addr) = s.parse::<Ipv4Addr>() {
                return Ok(Address::Ipv4(addr));
            }
        }

        if possible_ipv6 {
            if let Ok(addr) = s.parse::<Ipv6Addr>() {
                return Ok(Address::Ipv6(addr));
            }
        }

        if possible_hostname {
            return Ok(Address::Hostname(s.to_string()));
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Failed to parse address: {}", s),
        ))
    }
    pub fn is_ipv6(&self) -> bool {
        matches!(self, Address::Ipv6(_))
    }

    pub fn is_hostname(&self) -> bool {
        matches!(self, Address::Hostname(_))
    }

    pub fn hostname(&self) -> String {
        match self {
            Address::Hostname(hostname) => hostname.to_string(),
            Address::Ipv4(v4) => v4.to_string(),
            Address::Ipv6(v6) => format!("[{}]", v6.to_string()),
        }
    }

    pub fn to_vmess_vless_bytes(&self) -> Vec<u8> {
        let mut address_bytes: Vec<u8> = Vec::new();
        match self {
            Address::Ipv4(address) => {
                address_bytes.push(1);

                address_bytes.append(&mut address.octets().to_vec());
            }
            Address::Hostname(address) => {
                address_bytes.push(2);
                address_bytes.push(address.len() as u8);
                address_bytes.append(&mut address.as_bytes().to_vec());
            }
            Address::Ipv6(address) => {
                address_bytes.push(3);
                address_bytes.append(&mut address.octets().to_vec());
            }
        }

        return address_bytes;
    }
    pub fn to_socks_trojan_bytes(&self) -> Vec<u8> {
        let mut address_bytes: Vec<u8> = Vec::new();
        match self {
            Address::Ipv4(address) => {
                address_bytes.push(1);

                address_bytes.append(&mut address.octets().to_vec());
            }
            Address::Hostname(address) => {
                address_bytes.push(3);
                address_bytes.push(address.len() as u8);
                address_bytes.append(&mut address.as_bytes().to_vec());
            }
            Address::Ipv6(address) => {
                address_bytes.push(4);
                address_bytes.append(&mut address.octets().to_vec());
            }
        }

        return address_bytes;
    }
    pub fn to_tuic_bytes(&self) -> Vec<u8> {
        let mut address_bytes: Vec<u8> = Vec::new();
        match self {
            Address::Ipv4(address) => {
                address_bytes.push(1);

                address_bytes.append(&mut address.octets().to_vec());
            }
            Address::Hostname(address) => {
                address_bytes.push(0);
                address_bytes.push(address.len() as u8);
                address_bytes.append(&mut address.as_bytes().to_vec());
            }
            Address::Ipv6(address) => {
                address_bytes.push(2);
                address_bytes.append(&mut address.octets().to_vec());
            }
        }

        return address_bytes;
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Address::Ipv4(i) => write!(f, "{}", i),
            Address::Ipv6(i) => write!(f, "{}", i),
            Address::Hostname(h) => write!(f, "{}", h),
        }
    }
}
