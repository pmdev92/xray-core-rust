use std::io;
use std::io::ErrorKind;

use crate::config::config::Config;

pub mod config;
pub mod log;
pub mod stats;

pub fn parse_config_json(config_json: String) -> Result<Config, io::Error> {
    let result: serde_json::error::Result<Config> = serde_json::from_str(&config_json);
    return match result {
        Ok(config) => Ok(config),
        Err(err) => {
            return Err(io::Error::new(ErrorKind::Other, err));
        }
    };
}
