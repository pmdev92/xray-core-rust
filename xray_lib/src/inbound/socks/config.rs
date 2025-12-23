use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Socks5InboundSettings {
    pub port: u16,
    pub listen: String,
}
