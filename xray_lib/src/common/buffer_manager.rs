use log::error;
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::sleep;

pub struct BufferManager {
    sem: Arc<Semaphore>,
}

impl BufferManager {
    pub(crate) fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            sem: Arc::new(Semaphore::new(limit)),
        })
    }

    pub async fn get_buffer(
        self: &Arc<Self>,
        size: usize,
    ) -> Result<Box<dyn BufferHandle>, io::Error> {
        let permit = self
            .sem
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "failed to acquire permit"))?;
        Ok(Box::new(MemoryBufferHandle::new(permit, size)))
    }
}

struct MemoryBufferHandle {
    permit: OwnedSemaphorePermit,
    buffer: Vec<u8>,
}
impl MemoryBufferHandle {
    fn new(permit: OwnedSemaphorePermit, size: usize) -> MemoryBufferHandle {
        let buffer = vec![0u8; size];

        MemoryBufferHandle { permit, buffer }
    }
}
impl BufferHandle for MemoryBufferHandle {
    fn data(&mut self) -> &mut [u8] {
        self.buffer.as_mut()
    }
}

pub trait BufferHandle: Send + Sync {
    fn data(&mut self) -> &mut [u8];
}
