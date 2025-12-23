use log::error;
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::sleep;

pub struct SessionManager {
    sem: Arc<Semaphore>,
}

impl SessionManager {
    pub(crate) fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            sem: Arc::new(Semaphore::new(limit)),
        })
    }

    pub async fn add_new_session(self: &Arc<Self>) -> Result<OwnedSemaphorePermit, io::Error> {
        let permit = self
            .sem
            .clone()
            .acquire_owned()
            .await
            .map_err(|error| io::Error::new(io::ErrorKind::Other, format!("{}", error)))?;
        Ok(permit)
    }
}
