use crate::common::net_location::NetLocation;
use crate::outbound::quinn_tuic::protocol::{ToCommand, VERSION};
use bytes::{BufMut, Bytes};
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct Connect {
    addr: Arc<NetLocation>,
}

impl Connect {
    const TYPE_CODE: u8 = 0x01;

    pub const fn new(addr: Arc<NetLocation>) -> Self {
        Self { addr }
    }
}
impl ToCommand for Connect {
    fn to_command_bytes(&self) -> Bytes {
        let mut buf = bytes::BytesMut::new();
        buf.put_u8(VERSION);
        buf.put_u8(Connect::TYPE_CODE);
        let address_bytes = self.addr.address().to_tuic_bytes();
        let _ = buf.put(address_bytes.as_slice());
        let port = self.addr.port().to_be_bytes();
        let _ = buf.put(port.as_slice());
        buf.freeze()
    }
}
