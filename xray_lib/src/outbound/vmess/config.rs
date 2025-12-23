use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct VmessSettings {
    pub address: String,
    pub port: u16,
    pub id: String,
    pub security: String,
}
