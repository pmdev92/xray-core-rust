// use bytes::{Buf, BytesMut};
// use std::io;
// use std::io::ErrorKind;
// use std::pin::Pin;
// use std::sync::Arc;
// use std::task::{ready, Context, Poll};
// use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
//
// use crate::common::net_location::NetLocation;
// use crate::core::inbound::AsyncStream;
// use crate::core::outbound::XrayOutboundStream;
// use crate::dialer::Dialer;
//
// pub struct ZeroReadStream {
//     stream: Box<dyn XrayOutboundStream>,
//     read_zero: bool,
//     write_buffer: BytesMut,
// }
//
// impl ZeroReadStream {
//     pub async fn new(
//         dialer: Arc<Dialer>,
//         server_net_location: Arc<NetLocation>,
//     ) -> Result<Box<dyn AsyncStream + Send + Sync>, io::Error> {
//         let stream = dialer.dial_tcp(server_net_location).await?;
//         Ok(Box::new(Self {
//             stream,
//             read_zero: false,
//             write_buffer: Default::default(),
//         }))
//     }
// }
//
// impl AsyncRead for ZeroReadStream {
//     fn poll_read(
//         mut self: Pin<&mut Self>,
//         cx: &mut Context<'_>,
//         buf: &mut ReadBuf<'_>,
//     ) -> Poll<io::Result<()>> {
//         let result = ready!(Pin::new(&mut self.stream).poll_read(cx, buf));
//         match result {
//             Ok(_) => {
//                 let len = buf.filled().len();
//                 if len == 0 {
//                     if self.read_zero {
//                         return Poll::Ready(Err(io::Error::new(
//                             ErrorKind::BrokenPipe,
//                             "read exact bytes",
//                         )));
//                     }
//                     self.read_zero = true;
//                 } else {
//                     self.read_zero = false;
//                 }
//                 Poll::Ready(Ok(()))
//             }
//             Err(err) => Poll::Ready(Err(err)),
//         }
//     }
// }
//
// impl AsyncWrite for ZeroReadStream {
//     fn poll_write(
//         mut self: Pin<&mut Self>,
//         cx: &mut Context<'_>,
//         buf: &[u8],
//     ) -> Poll<Result<usize, io::Error>> {
//         if self.write_buffer.is_empty() {
//             self.write_buffer.extend_from_slice(buf);
//         }
//         let all = self.write_buffer.split();
//         let result = ready!(Pin::new(&mut self.stream).poll_write(cx, &all));
//         return match result {
//             Ok(size) => {
//                 if all.len() == size {
//                     return Poll::Ready(Ok(buf.len()));
//                 }
//                 self.write_buffer.extend_from_slice(all[size..]);
//                 cx.waker().wake_by_ref();
//                 return Poll::Pending;
//             }
//             Err(error) => Poll::Ready(Err(error)),
//         };
//     }
//
//     fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
//         Pin::new(&mut self.stream).poll_flush(cx)
//     }
//
//     fn poll_shutdown(
//         mut self: Pin<&mut Self>,
//         cx: &mut Context<'_>,
//     ) -> Poll<Result<(), io::Error>> {
//         Pin::new(&mut self.stream).poll_shutdown(cx)
//     }
// }
//
// impl AsyncStream for ZeroReadStream {}
