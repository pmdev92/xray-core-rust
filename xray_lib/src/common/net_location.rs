use crate::common::address::Address;
use crate::common::vec::vec_allocate;
use crate::core::context::Context;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use hickory_resolver::config::ResolverConfig;
use hickory_resolver::proto::runtime::iocompat::AsyncIoTokioAsStd;
use hickory_resolver::proto::runtime::{RuntimeProvider, TokioHandle, TokioTime};
use hickory_resolver::Resolver;
use std::future::Future;
use std::io::{ErrorKind, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use std::{fmt, io};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct NetLocation {
    pub(crate) address: Address,
    pub(crate) port: u16,
}

impl NetLocation {
    pub(crate) fn parse_socks5(bytes: &mut BytesMut) -> Result<NetLocation, io::Error> {
        if bytes.remaining() < 2 {
            return Err(io::Error::other("invalid buf"));
        }
        let address_type = bytes.get_u8();

        match address_type {
            crate::inbound::socks::protocol::address_type::TYPE_IPV4 => {
                if bytes.remaining() < 4 + 2 {
                    return Err(io::Error::other("invalid buf"));
                }
                let addr = Ipv4Addr::from(bytes.get_u32());
                let port = bytes.get_u16();

                Ok(NetLocation::new(Address::Ipv4(addr), port))
            }
            crate::inbound::socks::protocol::address_type::TYPE_IPV6 => {
                if bytes.remaining() < 16 + 2 {
                    return Err(io::Error::other("invalid buf"));
                }
                let v6addr = Ipv6Addr::from(bytes.get_u128());
                let port = bytes.get_u16();
                Ok(NetLocation::new(Address::Ipv6(v6addr), port))
            }
            crate::inbound::socks::protocol::address_type::TYPE_DOMAIN_NAME => {
                let domain_len = bytes.get_u8() as usize;
                if bytes.remaining() < domain_len {
                    return Err(io::Error::other("invalid buf"));
                }
                let mut buf = vec![0u8; domain_len];
                bytes.copy_to_slice(&mut buf);
                let port = bytes.get_u16();
                let address_str = match String::from_utf8(buf) {
                    Ok(s) => s,
                    Err(e) => {
                        return Err(io::Error::new(
                            ErrorKind::InvalidData,
                            format!("Failed to decode address: {}", e),
                        ));
                    }
                };

                // Although this is supposed to be a hostname, some clients will pass
                // ipv4 and ipv6 addresses as well, so parse it rather than directly
                // using Address:Hostname enum.
                Ok(NetLocation::new(Address::from(address_str.as_str())?, port))
            }
            _ => Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!("Unknown address type: {}", address_type),
            )),
        }
    }

    pub(crate) fn parse_tuic(bytes: &mut Bytes) -> Result<NetLocation, io::Error> {
        let error = io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid udp message address bytes",
        );
        let address_type = if (bytes.remaining() > 1) {
            bytes.get_u8()
        } else {
            return Err(error);
        };
        match address_type {
            0 => {
                if (bytes.remaining() < 1) {
                    return Err(error);
                }
                let address_length = bytes.get_u8() as usize;

                if (bytes.remaining() < address_length) {
                    return Err(error);
                }
                let mut address: Vec<u8> = vec_allocate(address_length);
                bytes.reader().read_exact(&mut address)?;

                let address = Address::Hostname(String::from_utf8_lossy(&address).to_string());
                if (bytes.remaining() < 2) {
                    return Err(error);
                }
                let port = bytes.get_u16();

                return Ok(NetLocation::new(address, port));
            }
            1 => {
                if (bytes.remaining() < 6) {
                    return Err(error);
                }
                let address = bytes.get_u32();
                let address = Address::Ipv4(Ipv4Addr::from(address));
                let port = bytes.get_u16();
                return Ok(NetLocation::new(address, port));
            }
            2 => {
                if (bytes.remaining() < 18) {
                    return Err(error);
                }
                let address = bytes.get_u128();
                let address = Address::Ipv6(Ipv6Addr::from(address));
                let port = bytes.get_u16();
                return Ok(NetLocation::new(address, port));
            }
            255 => {
                if (bytes.remaining() < 2) {
                    return Err(error);
                }
                let address = Address::UNSPECIFIED;
                let port = 0;
                return Ok(NetLocation::new(address, port));
            }
            _ => {}
        }

        Err(error)
    }
}

impl NetLocation {
    pub const UNSPECIFIED: Self = NetLocation::new(Address::UNSPECIFIED, 0);

    pub const fn new(address: Address, port: u16) -> Self {
        Self { address, port }
    }

    pub fn is_unspecified(&self) -> bool {
        self == &Self::UNSPECIFIED
    }

    pub fn from_str(s: &str, default_port: Option<u16>) -> io::Result<Self> {
        let (address_str, port, expect_ipv6) = match s.rfind(':') {
            Some(i) => {
                // The ':' could be from an ipv6 address.
                match s[i + 1..].parse::<u16>() {
                    Ok(port) => (&s[0..i], Some(port), false),
                    Err(_) => (s, default_port, true),
                }
            }
            None => (s, default_port, false),
        };

        let address = Address::from(address_str)?;
        if expect_ipv6 && !address.is_ipv6() {
            return Err(io::Error::new(io::ErrorKind::Other, "Invalid location"));
        }

        let port = port.ok_or_else(|| io::Error::new(io::ErrorKind::Other, "No port"))?;

        Ok(Self { address, port })
    }

    pub fn from_ip_addr(ip: IpAddr, port: u16) -> Self {
        let address = match ip {
            IpAddr::V4(addr) => Address::Ipv4(addr),
            IpAddr::V6(addr) => Address::Ipv6(addr),
        };
        Self { address, port }
    }

    pub fn components(&self) -> (&Address, u16) {
        (&self.address, self.port)
    }

    pub fn unwrap_components(self) -> (Address, u16) {
        (self.address, self.port)
    }

    pub fn address(&self) -> &Address {
        &self.address
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub async fn to_socket_addr(&self, context: Arc<Context>) -> Result<SocketAddr, io::Error> {
        match self.address {
            Address::Ipv6(ref addr) => Ok(SocketAddr::new(IpAddr::V6(*addr), self.port)),
            Address::Ipv4(ref addr) => Ok(SocketAddr::new(IpAddr::V4(*addr), self.port)),
            Address::Hostname(ref domain) => {
                if !is_android() {
                    return format!("{}:{}", domain, self.port)
                        .to_socket_addrs()?
                        .next()
                        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "dns lookup failed"));
                }

                let resolver = Resolver::builder_with_config(
                    ResolverConfig::google(),
                    MyTokioConnectionProvider::new(MyProvider::new(context.clone())),
                )
                .build();
                let response = resolver.lookup_ip(domain).await?;
                let mut ip_v4: Option<Ipv4Addr> = None;
                let mut ip_v6: Option<Ipv6Addr> = None;
                if let Some(ip) = response.iter().next() {
                    match ip {
                        IpAddr::V4(v4) => {
                            if ip_v4.is_none() {
                                ip_v4 = Some(v4.clone());
                            }
                        }
                        IpAddr::V6(v6) => {
                            if ip_v6.is_none() {
                                ip_v6 = Some(v6.clone());
                            }
                        }
                    }
                }

                if let Some(ip_v4) = ip_v4 {
                    return Ok(SocketAddr::new(IpAddr::V4(ip_v4), self.port));
                }
                if let Some(ip_v6) = ip_v6 {
                    return Ok(SocketAddr::new(IpAddr::V6(ip_v6), self.port));
                }
                Err(io::Error::new(
                    ErrorKind::InvalidData,
                    format!("cannot resolve ip address of {}", domain,),
                ))
            }
        }
    }

    pub fn to_socket_addr_native(&self) -> Result<SocketAddr, io::Error> {
        match self.address {
            Address::Ipv6(ref addr) => Ok(SocketAddr::new(IpAddr::V6(*addr), self.port)),
            Address::Ipv4(ref addr) => Ok(SocketAddr::new(IpAddr::V4(*addr), self.port)),
            Address::Hostname(ref domain) => format!("{}:{}", domain, self.port)
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "dns lookup failed")),
        }
    }

    pub fn to_hysteria2_str(&self) -> String {
        match self.address {
            Address::Ipv6(ref addr) => {
                let domain = IpAddr::V6(*addr).to_string();
                format!("{}:{}", domain, self.port).to_string()
            }
            Address::Ipv4(ref addr) => {
                let domain = IpAddr::V4(*addr).to_string();
                format!("{}:{}", domain, self.port).to_string()
            }
            Address::Hostname(ref domain) => format!("{}:{}", domain, self.port).to_string(),
        }
    }
    pub fn to_tuic_str(&self) -> String {
        match self.address {
            Address::Ipv6(ref addr) => {
                let domain = IpAddr::V6(*addr).to_string();
                format!("{}:{}", domain, self.port).to_string()
            }
            Address::Ipv4(ref addr) => {
                let domain = IpAddr::V4(*addr).to_string();
                format!("{}:{}", domain, self.port).to_string()
            }
            Address::Hostname(ref domain) => format!("{}:{}", domain, self.port).to_string(),
        }
    }
    pub fn to_tuic_bytes(&self) -> Bytes {
        let mut buf = bytes::BytesMut::new();
        let address_bytes = self.address().to_tuic_bytes();
        let _ = buf.put(address_bytes.as_slice());
        let port = self.port().to_be_bytes();
        let _ = buf.put(port.as_slice());
        buf.freeze()
    }
    pub fn to_socks_bytes(&self) -> Bytes {
        let mut buf = bytes::BytesMut::new();
        let address_bytes = self.address().to_socks_trojan_bytes();
        let _ = buf.put(address_bytes.as_slice());
        let port = self.port().to_be_bytes();
        let _ = buf.put(port.as_slice());
        buf.freeze()
    }
}

impl fmt::Display for NetLocation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.address, self.port)
    }
}

impl From<SocketAddr> for NetLocation {
    fn from(value: SocketAddr) -> Self {
        match value {
            SocketAddr::V4(address) => {
                return NetLocation::new(Address::Ipv4(address.ip().clone()), address.port());
            }
            SocketAddr::V6(address) => {
                return NetLocation::new(Address::Ipv6(address.ip().clone()), address.port());
            }
        }
    }
}

pub type MyTokioConnectionProvider = hickory_resolver::name_server::GenericConnector<MyProvider>;

#[derive(Clone)]
struct MyProvider {
    handle: TokioHandle,
    context: Arc<Context>,
}
impl MyProvider {
    pub fn new(context: Arc<Context>) -> Self {
        Self {
            handle: TokioHandle::default(),
            context,
        }
    }
}
impl RuntimeProvider for MyProvider {
    type Handle = TokioHandle;
    type Timer = TokioTime;
    type Udp = UdpSocket;
    type Tcp = AsyncIoTokioAsStd<TcpStream>;

    fn create_handle(&self) -> Self::Handle {
        self.handle.clone()
    }

    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
        bind_addr: Option<SocketAddr>,
        wait_for: Option<Duration>,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Tcp>>>> {
        let context = self.context.clone();
        Box::pin(async move {
            let future = context.connect_tokio_tcp(server_addr);
            let wait_for = wait_for.unwrap_or_else(|| Duration::from_secs(5));
            match timeout(wait_for, future).await {
                Ok(Ok(socket)) => Ok(AsyncIoTokioAsStd(socket)),
                Ok(Err(e)) => Err(e),
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("connection to {server_addr:?} timed out after {wait_for:?}"),
                )),
            }
        })
    }

    fn bind_udp(
        &self,
        local_addr: SocketAddr,
        server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = std::io::Result<Self::Udp>>>> {
        let context = self.context.clone();
        Box::pin(async move {
            let udp_socket = context.bind_tokio_udp(local_addr).await?;
            Ok(udp_socket)
        })
    }
}
fn is_android() -> bool {
    std::env::consts::OS == "android"
}
