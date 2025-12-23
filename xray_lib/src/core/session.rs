use crate::core::router::Network;
use crate::inbound::InboundProtocol;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::OwnedSemaphorePermit;

#[derive(Debug, Clone)]
pub struct Session {
    session: Arc<OwnedSemaphorePermit>,
    protocol: InboundProtocol,
    network: Network,
    local_address: Option<SocketAddr>,
    remote_address: Option<SocketAddr>,
}

impl Session {
    pub fn new(
        session: Arc<OwnedSemaphorePermit>,
        protocol: InboundProtocol,
        network: Network,
        local_address: Option<SocketAddr>,
        remote_address: Option<SocketAddr>,
    ) -> Self {
        Self {
            session,
            protocol,
            network,
            local_address,
            remote_address,
        }
    }

    pub fn get_new_session(&self) -> Arc<OwnedSemaphorePermit> {
        self.session.clone()
    }
}

impl Display for Session {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let local = self
            .local_address
            .map(|a| a.to_string())
            .unwrap_or_else(|| "N/A".to_string());

        let remote = self
            .remote_address
            .map(|a| a.to_string())
            .unwrap_or_else(|| "N/A".to_string());

        write!(
            f,
            "{{ protocol: {}, network: {}, local: {}, remote: {} }}",
            self.protocol, self.network, local, remote,
        )
    }
}
