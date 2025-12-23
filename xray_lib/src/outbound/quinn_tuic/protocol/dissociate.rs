use crate::outbound::quinn_tuic::protocol::heartbeat::Heartbeat;
use crate::outbound::quinn_tuic::protocol::{ToCommand, VERSION};
use bytes::{BufMut, Bytes};

/// Command `Dissociate`
///
/// ```plain
/// +----------+
/// | ASSOC_ID |
/// +----------+
/// |    2     |
/// +----------+
/// ```
///
/// where:
///
/// - `ASSOC_ID` - UDP relay session ID
#[derive(Clone, Debug, Copy)]
pub struct Dissociate {
    assoc_id: u16,
}

impl Dissociate {
    const TYPE_CODE: u8 = 0x03;

    /// Creates a new `Dissociate` command
    pub const fn new(assoc_id: u16) -> Self {
        Self { assoc_id }
    }
}
impl ToCommand for Dissociate {
    fn to_command_bytes(&self) -> Bytes {
        let mut buf = bytes::BytesMut::new();
        buf.put_u8(VERSION);
        buf.put_u8(Heartbeat::TYPE_CODE);
        buf.put_u16(self.assoc_id);
        buf.freeze()
    }
}
