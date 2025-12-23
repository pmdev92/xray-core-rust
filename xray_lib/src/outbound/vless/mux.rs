use crate::common::net_location::NetLocation;
use crate::common::vec::vec_allocate;
use crate::core::io::AsyncXrayTcpStream;
use crate::core::transport::{Transport, XrayTransport};
use crate::outbound::vless::flow::VlessFlow;
use crate::outbound::vless::xtls::VisionStream;
use crate::outbound::vless::{ReadState, VlessStream};
use blake3::IncrementCounter::No;
use byteorder::{BigEndian, ByteOrder};
use bytes::{Buf, BufMut, BytesMut};
use digest::typenum::op;
use futures::ready;
use log::error;
use s2n_codec::zerocopy::IntoBytes;
use socket2::InterfaceIndexOrAddress::Address;
use std::any::Any;
use std::io;
use std::io::{Cursor, Error, ErrorKind};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::DerefMut;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Debug)]
pub struct MuxCoolLong {
    pub cmd: u8,
    pub opt: u8,
    pub net_type: Option<u8>,
    pub net_location: Option<Arc<NetLocation>>,
    pub global_id: Option<[u8; 8]>,
}

impl MuxCoolLong {
    pub fn new(
        cmd: u8,
        opt: u8,
        net_type: u8,
        net_location: Arc<NetLocation>,
        global_id: Option<[u8; 8]>,
    ) -> Self {
        Self {
            cmd,
            opt,
            net_type: Some(net_type),
            net_location: Some(net_location),
            global_id,
        }
    }

    /// Write to buffer
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        // xudp id always to be 0
        buf.put_u8(0);
        buf.put_u8(0);
        buf.put_u8(self.cmd);
        buf.put_u8(self.opt);
        if let Some(net_type) = self.net_type {
            buf.put_u8(net_type);
        }
        if let Some(net_location) = self.net_location.clone() {
            buf.put_u16(net_location.port);
            buf.put_slice(&net_location.address.to_vmess_vless_bytes());
        }

        if let Some(id) = self.global_id {
            buf.put_slice(&id);
        }
    }

    /// Get length of bytes
    pub fn serialized_len(&self) -> usize {
        let net_len = if let Some(_) = &self.net_type { 1 } else { 0 };
        let address_len = if let Some(net_location) = self.net_location.clone() {
            let len = net_location.port.as_bytes().len()
                + net_location.address.to_vmess_vless_bytes().len();
            len
        } else {
            0
        };
        let global_id = if self.global_id.is_some() { 8 } else { 0 };
        // ID CMD OPT net_len address_len global_id
        2 + 1 + 1 + net_len + address_len + global_id
    }

    pub fn read_from<T: AsRef<[u8]>>(cur: &mut Cursor<T>) -> Result<Self, io::Error> {
        if cur.remaining() < 8 {
            return Err(io::Error::other("Invalid Mux Cool Packets"));
        }
        // id
        cur.get_u16();
        let cmd = cur.get_u8();
        let opt = cur.get_u8();
        let mut net_type = None;
        let mut net_location = None;
        if opt == 1 {
            net_type = Some(cur.get_u8());
            let port = cur.get_u16();
            let addr_type = cur.get_u8();
            let addr = match addr_type {
                address_type::IPV4 => {
                    if cur.remaining() < 4 {
                        return Err(io::Error::other("Invalid Mux Cool Packets"));
                    }
                    let addr = Ipv4Addr::from(cur.get_u32());
                    crate::common::address::Address::Ipv4(addr)
                }
                address_type::IPV6 => {
                    if cur.remaining() < 16 {
                        return Err(io::Error::other("Invalid Mux Cool Packets"));
                    }
                    let addr = Ipv6Addr::from(cur.get_u128());
                    crate::common::address::Address::Ipv6(addr)
                }
                address_type::DOMAIN => {
                    if cur.remaining() < 1 {
                        return Err(io::Error::other("Invalid Mux Cool Packets"));
                    }
                    let len = cur.get_u8() as usize;
                    if cur.remaining() < len {
                        return Err(io::Error::other("Invalid Mux Cool Packets"));
                    }
                    let mut buf = vec![0u8; len];
                    cur.copy_to_slice(&mut buf);
                    let addr = String::from_utf8(buf)
                        .map_err(|_| io::Error::other("Invalid Mux Cool Packets"))?;
                    crate::common::address::Address::Hostname(addr)
                }
                _ => return Err(io::Error::other("Invalid Mux Cool Packets")),
            };
            net_location = Some(Arc::new(NetLocation::new(addr, port)))
        }
        Ok(Self {
            cmd,
            opt,
            net_type,
            net_location,
            global_id: None,
        })
    }
}

pub(crate) struct VlessMuxStream {
    stream: Box<dyn AsyncXrayTcpStream>,
    net_location: Arc<NetLocation>,
    is_new: bool,
    read_buffer: BytesMut,
    global_id: [u8; 8],
    read_state: MuxReadState,
}

impl VlessMuxStream {
    pub fn new(
        stream: Box<dyn XrayTransport>,
        id: Arc<Vec<u8>>,
        net_location: Arc<NetLocation>,
        global_id: [u8; 8],
    ) -> Self {
        Self {
            stream: Box::new(VisionStream::new(stream, id)),
            is_new: true,
            read_buffer: Default::default(),
            net_location,
            global_id,
            read_state: MuxReadState::ReadVersion,
        }
    }
}

impl AsyncRead for VlessMuxStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.read_buffer.is_empty() {
            if let MuxReadState::ReadVersion = self.read_state {
                if self.read_buffer.len() >= 1 {
                    let _ = self.read_buffer.split_to(1);
                    self.read_state = MuxReadState::ReadAdditionalInformationLength;
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
            }
            if let MuxReadState::ReadAdditionalInformationLength = self.read_state {
                if self.read_buffer.len() >= 1 {
                    let count = self.read_buffer.split_to(1).get_u8();
                    if count > 0 {
                        self.read_state = MuxReadState::ReadAdditionalInformation(count);
                    } else {
                        self.read_state = MuxReadState::ReadMuxLength;
                    }
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
            }
            if let MuxReadState::ReadAdditionalInformation(length) = self.read_state {
                let length = length as usize;
                if self.read_buffer.len() >= length {
                    let _ = self.read_buffer.split_to(length);
                    self.read_state = MuxReadState::ReadMuxLength;
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
            }

            if let MuxReadState::ReadMuxLength = self.read_state {
                if self.read_buffer.len() >= 2 {
                    let bytes = self.read_buffer.split_to(2);
                    let length = BigEndian::read_u16(bytes.as_bytes());
                    self.read_state = MuxReadState::ReadMux(length);
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
            }

            if let MuxReadState::ReadMux(length) = self.read_state {
                let length = length as usize;
                if self.read_buffer.len() >= length {
                    let mux_data = self.read_buffer.split_to(length);
                    let mux = MuxCoolLong::read_from(&mut Cursor::new(mux_data.as_bytes()))?;
                    if mux.cmd == mux_command::KEEP
                        && mux.opt == 1
                        && mux.net_type == Some(request_command::UDP)
                    {
                        self.read_state = MuxReadState::ReadUdpDataLength;
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    if mux.cmd == mux_command::KEEP_ALIVE {
                        self.read_state = MuxReadState::ReadMuxLength;
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    return Err(Error::from(ErrorKind::UnexpectedEof)).into();
                    error!("mux {:?}", mux);
                }
            }

            if let MuxReadState::ReadUdpDataLength = self.read_state {
                if self.read_buffer.len() >= 2 {
                    let bytes = self.read_buffer.split_to(2);
                    let length = BigEndian::read_u16(bytes.as_bytes());
                    self.read_state = MuxReadState::ReadUdpData(length);
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
            }
            if let MuxReadState::ReadUdpData(length) = self.read_state {
                let length = length as usize;
                if self.read_buffer.len() >= length {
                    let udp_data = self.read_buffer.split_to(length);
                    buf.put_slice(udp_data.as_bytes());
                    self.read_state = MuxReadState::ReadMuxLength;
                    return Poll::Ready(Ok(()));
                }
            }
        }

        let mut cast_to_raw = false;
        let mut read_count = buf.capacity();
        match &self.read_state {
            MuxReadState::ReadVersion => {
                read_count = 1;
                cast_to_raw = true;
            }
            MuxReadState::ReadAdditionalInformationLength => {
                read_count = 1;
                cast_to_raw = true;
            }
            MuxReadState::ReadAdditionalInformation(length) => {
                read_count = length.clone() as usize;
                cast_to_raw = true;
            }
            _ => {}
        }
        //read data from transport
        let mut buffer_vev = vec_allocate(read_count);
        let mut buffer = ReadBuf::new(&mut buffer_vev);

        let stream: &mut Box<dyn AsyncXrayTcpStream> = if cast_to_raw {
            let any = self.stream.deref_mut() as &mut dyn Any;
            any.downcast_mut::<VisionStream>()
                .expect("vision stream")
                .as_raw_stream()
        } else {
            &mut self.stream
        };

        let result = ready!(Pin::new(stream).poll_read(cx, &mut buffer));
        return match result {
            Ok(_) => {
                self.read_buffer.extend_from_slice(buffer.filled());
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(err) => {
                let message = format!(
                    "{{vless-mux-read-state: {:?}, message: {}}}",
                    self.read_state, err
                );
                let error = io::Error::new(err.kind(), message);
                Poll::Ready(Err(error))
            }
        };
    }
}
impl AsyncWrite for VlessMuxStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        let mux_cool = if self.is_new {
            self.is_new = false;
            MuxCoolLong::new(
                mux_command::NEW,
                1,
                request_command::UDP,
                self.net_location.clone(),
                Some(self.global_id),
            )
        } else {
            MuxCoolLong::new(
                mux_command::KEEP,
                1,
                request_command::UDP,
                self.net_location.clone(),
                None,
            )
        };

        let mux_cool_len = mux_cool.serialized_len();

        let mut buffer = BytesMut::with_capacity(mux_cool_len + 2 + buf.len() + 2);
        buffer.put_u8((mux_cool_len >> 8) as u8);
        buffer.put_u8(mux_cool_len as u8);
        mux_cool.write_to_buf(&mut buffer);

        buffer.put_u8((buf.len() >> 8) as u8);
        buffer.put_u8(buf.len() as u8);
        buffer.put_slice(buf);

        Pin::new(&mut self.stream).poll_write(cx, &buffer)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        return Poll::Ready(Ok(()));
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        return Poll::Ready(Ok(()));
    }
}

impl AsyncXrayTcpStream for VlessMuxStream {}

const VLESS_VERSION: u8 = 0;
mod address_type {
    pub const IPV4: u8 = 1;
    pub const DOMAIN: u8 = 2;
    pub const IPV6: u8 = 3;
}
mod mux_command {
    pub const NEW: u8 = 1;
    pub const KEEP: u8 = 2;
    pub const END: u8 = 3;
    pub const KEEP_ALIVE: u8 = 4;
}
mod request_command {
    pub const TCP: u8 = 1;
    pub const UDP: u8 = 2;
    pub const MUX: u8 = 3;
}

#[derive(PartialEq, Debug)]
enum MuxReadState {
    ReadVersion,
    ReadAdditionalInformationLength,
    ReadAdditionalInformation(u8),
    ReadMuxLength,
    ReadMux(u16),
    ReadUdpDataLength,
    ReadUdpData(u16),
}
