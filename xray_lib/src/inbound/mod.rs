use std::fmt;
use std::fmt::{Display, Formatter};

pub mod http;
mod nat_manager;
pub mod socks;
pub mod tun;

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub enum InboundProtocol {
    SOCKS,
    HTTP,
}
impl Display for InboundProtocol {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            InboundProtocol::SOCKS => write!(f, "SOCKS"),
            InboundProtocol::HTTP => write!(f, "HTTP"),
        }
    }
}
