use crate::common::net_location::NetLocation;
use crate::inbound::nat_manager::NatUdpPacket;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures::{Sink, SinkExt, Stream, StreamExt};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio_util::codec::{Decoder, Encoder};
use tokio_util::udp::UdpFramed;

pub struct Socks5UDPCodec;

impl Encoder<(Bytes, NetLocation)> for Socks5UDPCodec {
    type Error = std::io::Error;

    fn encode(
        &mut self,
        item: (Bytes, NetLocation),
        dst: &mut BytesMut,
    ) -> Result<(), Self::Error> {
        let socks_address = item.1.to_socks_bytes();
        dst.reserve(3 + socks_address.len() + item.0.len());
        dst.put_slice(&[0x0, 0x0, 0x0]);
        dst.put_slice(socks_address.as_ref());
        dst.put_slice(item.0.as_ref());
        Ok(())
    }
}

impl Decoder for Socks5UDPCodec {
    type Item = (NetLocation, BytesMut);
    type Error = std::io::Error;

    fn decode(&mut self, data: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // error!("decode {:?}", data);
        if data.len() < 3 {
            return Ok(None);
        }

        if data[2] != 0 {
            return Err(std::io::Error::other("socks5 not support fragmentation"));
        }
        data.advance(3);
        let address = NetLocation::parse_socks5(data)?;
        let packet = std::mem::take(data);
        Ok(Some((address, packet)))
    }
}

pub struct Sock5UdpStream {
    pub socket: UdpFramed<Socks5UDPCodec>,
    pub context: Arc<crate::Context>,
}

impl Stream for Sock5UdpStream {
    type Item = NatUdpPacket;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let pin = self.get_mut();
        match pin.socket.poll_next_unpin(cx) {
            Poll::Ready(item) => match item {
                None => Poll::Ready(None),
                Some(item) => match item {
                    Ok(((dst, pkt), src)) => Poll::Ready(Some(NatUdpPacket::new(
                        pkt.to_vec(),
                        NetLocation::from(src),
                        dst,
                    ))),
                    Err(_) => Poll::Ready(None),
                },
            },
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Sink<NatUdpPacket> for Sock5UdpStream {
    type Error = std::io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let pin = self.get_mut();
        pin.socket.poll_ready_unpin(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: NatUdpPacket) -> Result<(), Self::Error> {
        // error!("start_send");
        let pin = self.get_mut();
        pin.socket.start_send_unpin((
            (item.data.into(), item.dst_addr).into(),
            item.src_addr.to_socket_addr_native()?,
        ))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let pin = self.get_mut();
        pin.socket.poll_flush_unpin(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let pin = self.get_mut();
        pin.socket.poll_close_unpin(cx)
    }
}
