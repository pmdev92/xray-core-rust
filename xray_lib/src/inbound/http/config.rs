use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct HttpInboundSettings {
    pub port: u16,
    pub listen: String,
}
