use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VlessSettings {
    pub address: String,
    pub port: u16,
    pub id: String,

    pub encryption: Option<String>,
}
