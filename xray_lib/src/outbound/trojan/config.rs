use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct TrojanSettings {
    pub address: String,
    pub port: u16,
    pub password: String,
}
