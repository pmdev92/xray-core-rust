use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LogConfig {
    pub level: Option<String>,
}

impl LogConfig {
    pub fn default() -> Self {
        LogConfig {
            level: Some("trace".to_string()),
        }
    }
}
