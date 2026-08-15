use std::{
    io::IoSliceMut,
    sync::Arc,
    task::{Context, Poll},
};

use blake2::{Blake2b, Digest};
use bytes::{BufMut, Bytes, BytesMut};
use digest::consts::U32;
use futures::ready;
use quinn::{
    AsyncUdpSocket, TokioRuntime,
    udp::{RecvMeta, Transmit},
};

pub const SALAMANDER_SALT_SIZE: usize = 8;

type Blake2b256 = Blake2b<U32>;

pub struct SalamanderObfs {
    hasher: Blake2b256,
}

impl SalamanderObfs {
    pub fn new(key: Vec<u8>) -> Self {
        let mut hasher = Blake2b256::new();
        hasher.update(&key);
        Self { hasher }
    }

    #[inline]
    fn obfs(&self, salt: &[u8], data: &mut [u8]) {
        let mut hasher = self.hasher.clone();
        hasher.update(salt);
        let key: [u8; 32] = hasher.finalize().into();
        for (i, b) in data.iter_mut().enumerate() {
            *b ^= key[i & 31];
        }
    }

    pub fn encrypt(&self, data: &[u8]) -> Bytes {
        let salt: [u8; SALAMANDER_SALT_SIZE] = rand::random();
        let mut res = BytesMut::with_capacity(SALAMANDER_SALT_SIZE + data.len());
        res.extend_from_slice(&salt);

        let mut hasher = self.hasher.clone();
        hasher.update(&salt);
        let key: [u8; 32] = hasher.finalize().into();

        for (i, b) in data.iter().enumerate() {
            res.put_u8(*b ^ key[i & 31]);
        }
        res.freeze()
    }

    #[inline]
    pub fn decrypt(&self, packet: &mut [u8]) {
        if packet.len() <= SALAMANDER_SALT_SIZE {
            return;
        }
        let (salt, payload) = packet.split_at_mut(SALAMANDER_SALT_SIZE);
        self.obfs(salt, payload);
    }
}

pub struct Salamander {
    inner: Arc<dyn AsyncUdpSocket>,
    obfs: SalamanderObfs,
}

impl Salamander {
    pub fn new(socket: std::net::UdpSocket, key: Vec<u8>) -> std::io::Result<Self> {
        use quinn::Runtime;
        let inner = TokioRuntime.wrap_udp_socket(socket)?;
        Ok(Self {
            inner,
            obfs: SalamanderObfs::new(key),
        })
    }
}

impl std::fmt::Debug for Salamander {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.fmt(f)
    }
}

impl AsyncUdpSocket for Salamander {
    fn create_io_poller(self: Arc<Self>) -> std::pin::Pin<Box<dyn quinn::UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> std::io::Result<()> {
        let mut v = transmit.to_owned();
        let encrypted = self.obfs.encrypt(v.contents);
        v.contents = encrypted.as_ref();
        self.inner.try_send(&v)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<std::io::Result<usize>> {
        let packet_nums = ready!(self.inner.poll_recv(cx, bufs, meta))?;

        for (buf, meta) in bufs.iter_mut().zip(meta.iter_mut()).take(packet_nums) {
            if meta.len <= SALAMANDER_SALT_SIZE {
                meta.len = 0;
                continue;
            }
            let packet = &mut buf[..meta.len];
            self.obfs.decrypt(packet);
            let payload_len = meta.len - SALAMANDER_SALT_SIZE;
            packet.copy_within(SALAMANDER_SALT_SIZE..meta.len, 0);
            meta.len = payload_len;
            meta.stride = payload_len;
        }

        Poll::Ready(Ok(packet_nums))
    }

    fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.inner.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }
}
