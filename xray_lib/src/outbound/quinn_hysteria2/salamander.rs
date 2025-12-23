use std::{
    io::IoSliceMut,
    ops::DerefMut,
    sync::Arc,
    task::{Context, Poll},
};

use blake2::{Blake2b, Digest};
use bytes::{BufMut, Bytes, BytesMut};
use digest::consts::U32;
use futures::ready;
use quinn::{
    udp::{RecvMeta, Transmit},
    AsyncUdpSocket, TokioRuntime,
};
use rand::Rng;

type Blake2b256 = Blake2b<U32>;

struct SalamanderObfs {
    key: Vec<u8>,
}

impl SalamanderObfs {
    /// create a new obfs
    ///
    /// new() should init a blake2b256 hasher with key to reduce calculation,
    /// but rust-analyzer can't recognize its type
    pub fn new(key: Vec<u8>) -> Self {
        Self { key }
    }

    pub fn obfs(&self, sale: &[u8], data: &mut [u8]) {
        let mut hasher = Blake2b256::new();
        hasher.update(&self.key);
        hasher.update(sale);
        let res: [u8; 32] = hasher.finalize().into();

        data.iter_mut().enumerate().for_each(|(i, v)| {
            *v ^= res[i % 32];
        });
    }

    fn encrypt(&self, data: &mut [u8]) -> Bytes {
        // let salt: [u8; 8] = rand::rng().random();
        let salt = rand::thread_rng().r#gen::<[u8; 8]>().to_vec();
        let mut res = BytesMut::with_capacity(8 + data.len());
        res.put_slice(&salt);
        self.obfs(&salt, data);
        res.put_slice(data);

        res.freeze()
    }

    fn decrypt(&self, data: &mut [u8]) {
        assert!(data.len() > 8, "data len must > 8");

        let (salt, data) = data.split_at_mut(8);
        self.obfs(salt, data);
        // data.advance(8); // sadlly IoSliceMut::advance is unstable
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

        std::io::Result::Ok(Self {
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
    fn create_io_poller(self: std::sync::Arc<Self>) -> std::pin::Pin<Box<dyn quinn::UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> std::io::Result<()> {
        let mut v = transmit.to_owned();
        // TODO: encrypt in place
        let x = self.obfs.encrypt(&mut v.contents.to_vec());
        v.contents = &x;
        self.inner.try_send(&v)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<std::io::Result<usize>> {
        // the number of udp packets received
        let packet_nums = ready!(self.inner.poll_recv(cx, bufs, meta))?;

        bufs.iter_mut()
            .zip(meta.iter_mut())
            // first step take and then filter
            .take(packet_nums)
            .filter(|(_, meta)| meta.len > 8)
            .for_each(|(buf, meta)| {
                let x = &mut buf.deref_mut()[..meta.len];
                self.obfs.decrypt(x);
                let data = x[8..].to_vec();
                // unsafe {
                //     //  because IoSliceMut is transparent and .0 is also transparent, so it is a &[u8]
                //     let b: IoSliceMut<'_> = std::mem::transmute(data);
                //     *v = b;
                // }
                // // MUST update meta.len
                // meta.len -= 8;

                meta.len = data.len();
                meta.stride = data.len();
                // crate::outbound::quinn_hysteria2::salamander_udp_socket::zero_me(bufs[i].as_mut());
                buf[..data.len()].copy_from_slice(data.as_slice());
            });

        Poll::Ready(Ok(packet_nums))
    }

    fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.inner.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}
