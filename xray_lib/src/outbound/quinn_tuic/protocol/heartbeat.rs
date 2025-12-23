use crate::outbound::quinn_tuic::protocol::{ToCommand, VERSION};
use bytes::{BufMut, Bytes};

/// Command `Heartbeat`
/// ```plain
/// +-+
/// | |
/// +-+
/// | |
/// +-+
/// ```
#[derive(Clone, Debug)]
pub struct Heartbeat;

impl Heartbeat {
    pub(crate) const TYPE_CODE: u8 = 0x04;

    /// Creates a new `Heartbeat` command
    pub const fn new() -> Self {
        Self
    }
}
impl ToCommand for Heartbeat {
    fn to_command_bytes(&self) -> Bytes {
        let mut buf = bytes::BytesMut::new();
        buf.put_u8(VERSION);
        buf.put_u8(Heartbeat::TYPE_CODE);
        buf.freeze()
    }
}
