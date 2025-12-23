use crate::outbound::quinn_tuic::protocol::{ToCommand, VERSION};
use bytes::{BufMut, Bytes};
#[derive(Clone, Debug)]
pub struct Authenticate {
    pub(crate) uuid: [u8; 16],
    pub(crate) token: [u8; 32],
}

impl Authenticate {
    const TYPE_CODE: u8 = 0x00;

    pub const fn new(uuid: [u8; 16], token: [u8; 32]) -> Self {
        Self { uuid, token }
    }
}

impl ToCommand for Authenticate {
    fn to_command_bytes(&self) -> Bytes {
        let mut buf = bytes::BytesMut::new();
        buf.put_u8(VERSION);
        buf.put_u8(Authenticate::TYPE_CODE);
        buf.put_slice(&self.uuid);
        buf.put_slice(&self.token);
        buf.freeze()
    }
}
