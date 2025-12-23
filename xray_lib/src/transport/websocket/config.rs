use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WebsocketConfig {
    pub host: Option<String>,
    pub path: Option<String>,
}
