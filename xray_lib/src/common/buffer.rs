use crate::common::constants::MAX_TCP_BUFFER_CAPACITY;
use crate::core::context::Context;
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync;
use tokio::sync::mpsc::Receiver;
use tokio::time::timeout;

pub async fn copy<T: AsyncRead, U: AsyncWrite>(
    mut receiver: Receiver<()>,
    context: Arc<Context>,
    reader: &mut ReadHalf<T>,
    writer: &mut WriteHalf<U>,
) -> Result<(), io::Error> {
    loop {
        let mut buffer_manager = context
            .get_buffer_manager()
            .get_buffer(MAX_TCP_BUFFER_CAPACITY)
            .await?;
        let mut buffer = buffer_manager.data();
        let result = timeout(Duration::from_secs(10), reader.read(buffer)).await;
        let read_count = match result {
            Ok(result) => result?,
            Err(_) => {
                let closed_result = receiver.try_recv();
                match closed_result {
                    Err(sync::mpsc::error::TryRecvError::Empty) => {
                        continue;
                    }
                    _ => {
                        break;
                    }
                }
            }
        };
        let _ = writer.write_all(&buffer[..read_count]).await?;
        let _ = writer.flush().await?;
        if read_count == 0 {
            break;
        }
    }
    writer.shutdown().await?;
    return Ok(());
}
