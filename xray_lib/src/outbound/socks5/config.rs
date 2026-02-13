use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Socks5Settings {
    pub address: String,
    pub port: u16,

    pub username: Option<String>,
    pub password: Option<String>,
}
