use crate::common::constants::MAX_TCP_BUFFER_CAPACITY;
use crate::common::vec::vec_allocate;
use crate::core::context::Context;
use log;
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync;
use tokio::sync::mpsc::Receiver;
use tokio::time::timeout;

pub async fn copy<T: AsyncRead, U: AsyncWrite>(
    mut receiver: Receiver<()>,
    _context: Arc<Context>,
    reader: &mut ReadHalf<T>,
    writer: &mut WriteHalf<U>,
) -> Result<(), io::Error> {
    let mut buf_size = MAX_TCP_BUFFER_CAPACITY;
    const MIN_BUF: usize = 4 * 1024;
    const MAX_BUF: usize = 64 * 1024;
    let mut full_count: u8 = 0;

    loop {
        let mut buffer: Vec<u8> = vec_allocate(buf_size);
        let result = timeout(Duration::from_secs(10), reader.read(&mut buffer)).await;
        let read_count = match result {
            Ok(result) => {
                let count = result?;

                count
            }
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
        if read_count == 0 {
            break;
        }
        let write_start = std::time::Instant::now();
        let _ = writer.write_all(&buffer[..read_count]).await?;
        let write_elapsed = write_start.elapsed();
        if read_count < buf_size {
            let _ = writer.flush().await?;
        }

        if read_count >= buf_size {
            full_count += 1;
            if full_count >= 2 {
                buf_size = (buf_size * 3).min(MAX_BUF);
                full_count = 0;
            }
        } else {
            buf_size = (buf_size / 3).max(MIN_BUF);
            full_count = 0;
        }

        if read_count == 0 {
            break;
        }
    }
    writer.shutdown().await?;
    Ok(())
}
