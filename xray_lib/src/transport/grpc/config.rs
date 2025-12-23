use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GrpcConfig {
    pub service_name: Option<String>,
}
