use std::fmt::Display;

pub const USER_AGENT: &str = "hyper-1.6.0";

#[derive(Debug, Clone)]
pub enum Http {
    V1,
    V2,
    V3,
}
impl Display for Http {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            Http::V1 => {
                fmt.write_str("HTTP/1.1")?;
            }
            Http::V2 => {
                fmt.write_str("HTTP/2")?;
            }
            Http::V3 => {
                fmt.write_str("HTTP/3")?;
            }
        }
        Ok(())
    }
}
#[derive(Debug, Clone)]
pub enum Mode {
    PacketUp,
    StreamUp,
    StreamOne,
}
impl Display for Mode {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            Mode::PacketUp => {
                fmt.write_str("packet-up")?;
            }
            Mode::StreamUp => {
                fmt.write_str("stream-up")?;
            }
            Mode::StreamOne => {
                fmt.write_str("stream-one")?;
            }
        }
        Ok(())
    }
}
