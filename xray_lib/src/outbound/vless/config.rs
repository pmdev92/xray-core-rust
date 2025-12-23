use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct VlessSettings {
    pub address: String,
    pub port: u16,
    pub id: String,
    pub flow: Option<String>,
}
