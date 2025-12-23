use crate::common::net_location::NetLocation;
use crate::core::io::AsyncXrayTcpStream;
use crate::stream::exact::ExactWriteStream;
use crate::stream::fragment::config::FragmentConfig;
use bytes::{BufMut, BytesMut};
use rand::Rng;
use std::future::Future;
use std::io;
use std::ops::Add;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use std::time::Duration;
use tls_parser::nom::AsBytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{sleep_until, Instant, Sleep};

pub mod config;
pub struct FragmentStream {
    stream: Box<dyn AsyncXrayTcpStream + Send + Sync>,
    fragment_config: FragmentConfig,
    counter: u64,
    delay: Pin<Box<Sleep>>,
    state: FragmentState,
    data: BytesMut,
    data_len: usize,
    write_len: usize,
    is_tls: bool,
    tls_record_len: u64,
    tls_structure: BytesMut,
    tls_data: BytesMut,
}

impl FragmentStream {
    pub async fn new(
        context: Arc<crate::core::context::Context>,
        detour: Option<String>,
        server_net_location: Arc<NetLocation>,
        fragment_config: FragmentConfig,
    ) -> Result<Box<dyn AsyncXrayTcpStream + Send + Sync>, io::Error> {
        let stream = ExactWriteStream::new(context, detour, server_net_location).await?;
        let instant = Instant::now().add(Duration::from_millis(100));
        Ok(Box::new(Self {
            delay: Box::pin(sleep_until(instant)),
            stream,
            fragment_config: fragment_config.clone(),
            counter: 0,
            state: FragmentState::Store,
            data: BytesMut::new(),
            data_len: 0,
            write_len: 0,
            is_tls: false,
            tls_record_len: 0,
            tls_structure: BytesMut::new(),
            tls_data: BytesMut::new(),
        }))
    }

    fn sleep(&mut self, delay: u64) {
        self.delay = Box::pin(sleep_until(Instant::now() + Duration::from_millis(delay)));
        self.state = FragmentState::Sleep;
    }

    fn generate_delay(&mut self) -> u64 {
        rand_between(
            self.fragment_config.interval_min,
            self.fragment_config.interval_max,
        )
    }

    fn generate_write_count(&mut self) -> usize {
        rand_between(
            self.fragment_config.length_min,
            self.fragment_config.length_max,
        ) as usize
    }
}

impl AsyncRead for FragmentStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        ready!(Pin::new(&mut self.stream).poll_read(cx, buf));
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for FragmentStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        match self.state.clone() {
            FragmentState::Store => {
                self.counter += 1;
                self.data.extend_from_slice(buf);
                self.data_len = buf.len();
                self.write_len = 0;
                self.state = FragmentState::Handle;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            FragmentState::Handle => {
                if self.fragment_config.packets_from == 0 && self.fragment_config.packets_to == 1 {
                    if self.counter != 1
                        || self.data_len <= 5
                        || (!self.is_tls && self.data.as_bytes()[0] != 22)
                    {
                        self.write_len += self.data.len();
                        self.state = FragmentState::Write(self.data.split(), 0);
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    if !self.is_tls {
                        self.is_tls = true;
                        let b3 = (self.data.as_bytes()[3] as u64) << 8;
                        let b4 = self.data.as_bytes()[4] as u64;
                        self.tls_record_len = 5 + (b3 | b4);
                        self.tls_structure = self.data.split_to(3);
                        _ = self.data.split_to(2);
                        let size = (self.tls_record_len - 5) as usize;
                        self.tls_data = self.data.split_to(size);
                        self.write_len += 5;
                    }
                    if self.tls_data.len() == 0 {
                        if self.data.len() == 0 {
                            self.state = FragmentState::Store;
                        } else {
                            self.write_len += self.data.len();
                            self.state = FragmentState::Write(self.data.split(), 0);
                        }
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    let mut count: usize = self.generate_write_count();
                    if count > self.tls_data.len() {
                        count = self.tls_data.len()
                    }
                    let mut to_write = BytesMut::new();
                    to_write.extend_from_slice(self.tls_structure.as_ref());
                    let b31 = (count >> 8) as u8;
                    let b41 = (count) as u8;
                    to_write.put_u8(b31);
                    to_write.put_u8(b41);
                    to_write.extend_from_slice(self.tls_data.split_to(count).as_ref());
                    self.write_len += to_write.len() - 5;
                    self.state = FragmentState::Write(to_write, self.generate_delay());
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }

                if self.fragment_config.packets_from != 0
                    && (self.counter < self.fragment_config.packets_from
                        || self.counter > self.fragment_config.packets_to)
                {
                    self.write_len += self.data.len();
                    self.state = FragmentState::Write(self.data.split(), 0);
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }

                let mut count: usize = self.generate_write_count();
                if count > self.data.len() {
                    count = self.data.len()
                }
                let bytes = self.data.split_to(count);
                self.write_len += bytes.len();
                self.state = FragmentState::Write(bytes, self.generate_delay());
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            FragmentState::Write(bytes, delay) => {
                ready!(Pin::new(&mut self.stream).poll_write(cx, bytes.as_bytes()));
                if delay > 0u64 {
                    self.sleep(delay.clone());
                } else {
                    self.state = FragmentState::Wake;
                }
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            FragmentState::Sleep => {
                ready!(Pin::new(&mut self.delay).poll(cx));
                self.state = FragmentState::Wake;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            FragmentState::Wake => {
                if self.write_len >= self.data_len {
                    self.state = FragmentState::Store;
                    return Poll::Ready(Ok(self.data_len));
                }
                self.state = FragmentState::Handle;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
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
impl AsyncXrayTcpStream for FragmentStream {}

fn rand_between(left: u64, right: u64) -> u64 {
    if left >= right {
        return left;
    }
    rand::thread_rng().gen_range(left..right)
}

#[derive(Clone)]
enum FragmentState {
    Store,
    Handle,
    Write(BytesMut, u64),
    Sleep,
    Wake,
}
