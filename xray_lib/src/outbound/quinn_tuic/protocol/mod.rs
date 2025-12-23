use bytes::Bytes;
use std::fmt::Display;

pub(crate) mod authenticate;
pub(crate) mod connect;
pub(crate) mod dissociate;
pub(crate) mod heartbeat;
pub(crate) mod packet;

pub(crate) mod enums;

pub const VERSION: u8 = 0x05;

pub(crate) trait ToCommand {
    fn to_command_bytes(&self) -> Bytes;
}
