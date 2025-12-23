use crate::common::net_location::NetLocation;
use crate::core::dispatcher::DispatcherItem;
use crate::core::io::{AsyncXrayTcpStream, AsyncXrayUdpStream};
use crate::core::outbound::Outbound;
use crate::core::statistics_manager::StatisticsManager;
use async_trait::async_trait;
use bytes::Bytes;
use futures::{ready, Sink, Stream};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct StatisticsOutbound {
    item: DispatcherItem,
    statistics_manager: Arc<StatisticsManager>,
}

impl StatisticsOutbound {
    pub fn new(item: DispatcherItem, statistics_manager: Arc<StatisticsManager>) -> Self {
        Self {
            item,
            statistics_manager,
        }
    }
}

#[async_trait]
impl Outbound for StatisticsOutbound {
    async fn dial_tcp(
        &self,
        context: Arc<crate::core::context::Context>,
        detour: Option<String>,
        net_location: Arc<NetLocation>,
    ) -> Result<Box<dyn AsyncXrayTcpStream>, io::Error> {
        let result = self
            .item
            .outbound
            .dial_tcp(context.clone(), detour, net_location)
            .await;
        match result {
            Ok(ok) => {
                let stream = Box::new(StatisticsStream {
                    stream: ok,
                    statistics_manager: self.statistics_manager.clone(),
                });
                Ok(stream)
            }
            Err(error) => Err(error),
        }
    }

    async fn dial_udp(
        &self,
        context: Arc<crate::core::context::Context>,
        detour: Option<String>,
        net_location: Arc<NetLocation>,
    ) -> Result<Box<dyn AsyncXrayUdpStream>, io::Error> {
        let result = self
            .item
            .outbound
            .dial_udp(context.clone(), detour, net_location)
            .await;
        match result {
            Ok(stream) => {
                let stream = StatisticsUdpStream::new(stream, self.statistics_manager.clone());
                Ok(stream)
            }
            Err(error) => Err(error),
        }
    }
}

struct StatisticsStream {
    stream: Box<dyn AsyncXrayTcpStream>,
    statistics_manager: Arc<StatisticsManager>,
}

impl AsyncRead for StatisticsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let result = ready!(Pin::new(&mut self.stream).poll_read(cx, buf));
        match result {
            Ok(_) => {
                self.statistics_manager.push_downloaded(buf.filled().len());
                Poll::Ready(Ok(()))
            }
            Err(error) => Poll::Ready(Err(error)),
        }
    }
}

impl AsyncWrite for StatisticsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let result = ready!(Pin::new(&mut self.stream).poll_write(cx, buf));
        match result {
            Ok(count) => {
                self.statistics_manager.push_uploaded(count);
                Poll::Ready(Ok(count))
            }
            Err(error) => Poll::Ready(Err(error)),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl AsyncXrayTcpStream for StatisticsStream {}

pub struct StatisticsUdpStream {
    stream: Box<dyn AsyncXrayUdpStream>,
    statistics_manager: Arc<StatisticsManager>,
    pending_uploaded: usize,
}

impl StatisticsUdpStream {
    pub fn new(
        stream: Box<dyn AsyncXrayUdpStream>,
        statistics_manager: Arc<StatisticsManager>,
    ) -> Box<dyn AsyncXrayUdpStream> {
        let s = StatisticsUdpStream {
            stream,
            statistics_manager,
            pending_uploaded: 0,
        };
        Box::new(s)
    }
}

impl Stream for StatisticsUdpStream {
    type Item = Bytes;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let inner = &mut self.stream;
        match Pin::new(inner).poll_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(bytes)) => {
                self.statistics_manager.push_downloaded(bytes.len());
                Poll::Ready(Some(bytes))
            }
        }
    }
}

impl Sink<Bytes> for StatisticsUdpStream {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        Pin::new(&mut this.stream).poll_ready(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        let len = item.len();
        Pin::new(&mut self.stream).start_send(item)?;
        self.pending_uploaded = self.pending_uploaded.saturating_add(len);
        Ok(())
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let res = Pin::new(&mut self.stream).poll_flush(cx);
        match res {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {
                if self.pending_uploaded != 0 {
                    self.statistics_manager.push_uploaded(self.pending_uploaded);
                    self.pending_uploaded = 0;
                }
                Poll::Ready(Ok(()))
            }
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let res = Pin::new(&mut self.stream).poll_close(cx);
        match res {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {
                if self.pending_uploaded != 0 {
                    self.statistics_manager.push_uploaded(self.pending_uploaded);
                    self.pending_uploaded = 0;
                }
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl AsyncXrayUdpStream for StatisticsUdpStream {}
