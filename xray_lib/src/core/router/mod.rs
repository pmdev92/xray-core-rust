use crate::common::net_location::NetLocation;
use crate::core::sniffer::SniffResult;
use std::fmt::{self, Display, Formatter};
use std::io;
use std::sync::Arc;

pub mod config;
pub mod domain;
mod group_conditions;
pub mod ip;
pub mod network;
mod not_match_matcher;
pub mod port;
pub mod protocol;
pub mod router;

pub trait Apply: Send + Sync {
    fn apply(&self, route_location: Arc<RouteLocation>) -> bool;
}

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub enum Network {
    Tcp,
    Udp,
}

impl Display for Network {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Network::Tcp => write!(f, "TCP"),
            Network::Udp => write!(f, "UDP"),
        }
    }
}

impl TryFrom<&str> for Network {
    type Error = io::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if (value.to_lowercase() == "tcp") {
            return Ok(Network::Tcp);
        }
        if (value.to_lowercase() == "udp") {
            return Ok(Network::Udp);
        }
        Err(io::Error::from(io::ErrorKind::InvalidInput))
    }
}
#[derive(PartialEq, Clone)]
pub struct RouteLocation {
    pub(crate) network: Network,
    pub(crate) target_location: Arc<NetLocation>,
    pub(crate) sniff_result: Option<SniffResult>,
}

impl RouteLocation {
    pub fn new(
        network: Network,
        target_location: Arc<NetLocation>,
        sniff_result: Option<SniffResult>,
    ) -> Arc<RouteLocation> {
        return Arc::new(Self {
            network,
            target_location,
            sniff_result,
        });
    }
}

impl Display for RouteLocation {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let target = self.target_location.to_string();
        let _ = f.write_str("{ location: ");
        let _ = f.write_str(&target.to_string());

        match &self.sniff_result {
            None => {}
            Some(sniff_result) => {
                let _ = f.write_str(" , sniff_domains: ");
                let _ = f.write_str(&sniff_result.to_string());
            }
        }
        let _ = f.write_str(" }");
        return Ok(());
    }
}
