use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HttpUpgradeConfig {
    pub host: Option<String>,
    pub path: Option<String>,
}
