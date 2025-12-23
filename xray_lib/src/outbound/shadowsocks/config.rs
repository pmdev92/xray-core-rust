use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct ShadowSocksSettings {
    pub address: String,
    pub port: u16,
    pub method: String,
    pub password: String,
    pub uot: Option<bool>,
    pub uot_version: Option<i32>,
    pub uot_is_connect: Option<bool>,
}
