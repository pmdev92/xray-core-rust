use crate::outbound::quinn_hysteria2::salamander::{Salamander, SALAMANDER_SALT_SIZE};
use bytes::{BufMut, Bytes, BytesMut};
use parking_lot::Mutex;
use parking_lot::lock_api::MutexGuard;
use parking_lot::RawMutex;
use quinn::udp::{RecvMeta, Transmit};
use quinn::AsyncUdpSocket;
use rand::rngs::OsRng;
use rand::{Rng, RngCore};
use std::collections::HashMap;
use std::fmt::Debug;
use std::io::IoSliceMut;
use std::sync::{
    atomic::{AtomicU32, Ordering},
    Arc, OnceLock,
};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::time::{self, Instant};

const GECKO_MAX_PER_SOURCE: usize = 8;
const GECKO_MAX_PER_REASSEMBLY: usize = 4096;
const GECKO_FLAG_FRAGMENT: u8 = 0x80;
const GECKO_HEADER_SIZE: usize = 5;
const GECKO_MIN_CHUNKS: usize = 2;
const GECKO_MAX_CHUNKS: usize = 8;
const GECKO_TTL: Duration = Duration::from_secs(8);

#[derive(Hash, Eq, PartialEq, Clone, Copy)]
struct Key {
    addr: std::net::SocketAddr,
    msg_id: u8,
}

struct Entry {
    chunks: Vec<Option<Vec<u8>>>,
    received: usize,
    total: usize,
    created: Instant,
}

struct GeckoInner {
    reassembly: HashMap<Key, Entry>,
    per_source: HashMap<std::net::SocketAddr, usize>,
}

pub struct Gecko {
    salamander: Arc<Salamander>,
    msg_id: AtomicU32,
    gecko_inner: Mutex<GeckoInner>,
    min_packet_len: usize,
    max_packet_len: usize,
    gc_started: OnceLock<()>,
}

impl Gecko {
    pub fn new(
        socket: std::net::UdpSocket,
        key: Vec<u8>,
        min_packet_len: Option<usize>,
        max_packet_len: Option<usize>,
    ) -> std::io::Result<Arc<Self>> {
        let gecko = Self {
            salamander: Arc::new(Salamander::new(socket, key)?),
            msg_id: AtomicU32::new(1),
            gecko_inner: Mutex::new(GeckoInner {
                reassembly: Default::default(),
                per_source: Default::default(),
            }),
            min_packet_len: min_packet_len.unwrap_or(512),
            max_packet_len: max_packet_len.unwrap_or(1200),
            gc_started: Default::default(),
        };
        let gecko = Arc::new(gecko);
        gecko.start_gc();
        Ok(gecko)
    }

    #[inline]
    fn is_long_header(buf: &[u8]) -> bool {
        !buf.is_empty() && (buf[0] & 0x80) != 0
    }

    #[inline]
    fn next_msg_id(&self) -> u8 {
        self.msg_id.fetch_add(1, Ordering::Relaxed) as u8
    }

    #[inline]
    fn rand_int_n(&self, n: usize) -> usize {
        if n <= 1 {
            return 0;
        }
        let mut b = [0u8; 4];
        OsRng.fill_bytes(&mut b);
        (u32::from_be_bytes(b) as usize) % n
    }

    #[inline]
    fn random_chunks(&self) -> usize {
        GECKO_MIN_CHUNKS + self.rand_int_n(GECKO_MAX_CHUNKS - GECKO_MIN_CHUNKS + 1)
    }

    pub fn random_pad_len(&self, chunk_len: usize) -> u16 {
        let base = SALAMANDER_SALT_SIZE + GECKO_HEADER_SIZE + chunk_len;
        let mut min = self.min_packet_len;
        if base > min {
            min = base;
        }
        if min > self.max_packet_len {
            return 0;
        }
        let mut rng = rand::thread_rng();
        let extra_range = self.max_packet_len - min + 1;
        let random_extra = rng.gen_range(0..extra_range);
        let pad = (min - base) + random_extra;
        pad as u16
    }
}

impl Gecko {
    fn encode_frame(
        &self,
        msg_id: u8,
        idx: u8,
        total: u8,
        pad: u16,
        payload: &[u8],
    ) -> Option<Bytes> {
        if total < GECKO_MIN_CHUNKS as u8 || total > GECKO_MAX_CHUNKS as u8 {
            return None;
        }
        if idx >= total {
            return None;
        }
        let mut buf = BytesMut::with_capacity(GECKO_HEADER_SIZE + pad as usize + payload.len());
        buf.put_u8(GECKO_FLAG_FRAGMENT);
        buf.put_u8(msg_id);
        buf.put_u8((idx << 4) | (total & 0x0f));
        buf.put_u16(pad);
        if pad > 0 {
            let start = buf.len();
            buf.resize(start + pad as usize, 0);
            OsRng.fill_bytes(&mut buf[start..start + pad as usize]);
        }
        buf.extend_from_slice(payload);
        Some(buf.freeze())
    }

    fn fragment(&self, packet: &[u8]) -> Vec<Bytes> {
        let chunks = self.random_chunks();
        let chunk_size = packet.len() / chunks;
        let msg_id = self.next_msg_id();
        let mut out = Vec::with_capacity(chunks);
        for i in 0..chunks {
            let start = i * chunk_size;
            if start >= packet.len() {
                break;
            }
            let end = if i < chunks - 1 { start + chunk_size } else { packet.len() };
            let chunk = &packet[start..end];
            let pad = self.random_pad_len(chunk.len());
            if let Some(frame) = self.encode_frame(msg_id, i as u8, chunks as u8, pad, chunk) {
                out.push(frame);
            }
        }
        out
    }
}

impl Gecko {
    fn reassemble(&self, addr: std::net::SocketAddr, buf: &[u8]) -> Option<Vec<u8>> {
        if buf.len() < GECKO_HEADER_SIZE {
            return None;
        }
        if buf[0] & GECKO_FLAG_FRAGMENT == 0 {
            return Some(buf.to_vec());
        }
        let msg_id = buf[1];
        let idx = (buf[2] >> 4) as usize;
        let total = (buf[2] & 0x0f) as usize;
        if total < GECKO_MIN_CHUNKS || total > GECKO_MAX_CHUNKS {
            return None;
        }
        if idx >= total {
            return None;
        }
        let padding_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
        let payload_start = GECKO_HEADER_SIZE + padding_len;
        if buf.len() < payload_start {
            return None;
        }
        let payload = &buf[payload_start..];
        let key = Key { addr, msg_id };
        let mut inner = self.gecko_inner.lock();
        let is_new = !inner.reassembly.contains_key(&key);
        if is_new {
            let count = inner.per_source.entry(addr).or_insert(0);
            if *count >= GECKO_MAX_PER_SOURCE {
                return None;
            }
            *count += 1;
            if inner.reassembly.len() >= GECKO_MAX_PER_REASSEMBLY {
                self.evict_oldest(&mut inner);
            }
        }
        let entry = inner.reassembly.entry(key).or_insert_with(|| Entry {
            chunks: vec![None; total],
            received: 0,
            total,
            created: Instant::now(),
        });
        if entry.total != total {
            return None;
        }
        if entry.chunks[idx].is_none() {
            entry.chunks[idx] = Some(payload.to_vec());
            entry.received += 1;
        }
        if entry.received != entry.total {
            return None;
        }
        let mut out = Vec::new();
        for c in entry.chunks.iter_mut() {
            if let Some(v) = c.take() {
                out.extend_from_slice(&v);
            }
        }
        self.drop_entry(&key, &mut inner);
        Some(out)
    }
}

impl Gecko {
    fn start_gc(self: &Arc<Self>) {
        if self.gc_started.set(()).is_err() {
            return;
        }
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut ticker = time::interval(GECKO_TTL / 2);
            loop {
                ticker.tick().await;
                let Some(gecko) = weak.upgrade() else {
                    return;
                };
                let mut inner = gecko.gecko_inner.lock();
                gecko.gc_expired(Instant::now(), &mut inner);
            }
        });
    }

    fn gc_expired(&self, time: Instant, inner: &mut MutexGuard<RawMutex, GeckoInner>) {
        let mut keys: Vec<Key> = Vec::new();
        for (key, value) in inner.reassembly.iter() {
            if time.duration_since(value.created) >= GECKO_TTL {
                keys.push(*key);
            }
        }
        for key in keys {
            self.drop_entry(&key, inner);
        }
    }

    fn drop_entry(&self, key: &Key, inner: &mut MutexGuard<RawMutex, GeckoInner>) {
        if inner.reassembly.remove(key).is_none() {
            return;
        }
        match inner.per_source.get_mut(&key.addr) {
            Some(count) => {
                *count -= 1;
                if *count == 0 {
                    inner.per_source.remove(&key.addr);
                }
            }
            None => {}
        }
    }

    fn evict_oldest(&self, inner: &mut MutexGuard<RawMutex, GeckoInner>) {
        let mut oldest_key: Option<Key> = None;
        let mut oldest_time: Option<Instant> = None;
        for (key, value) in inner.reassembly.iter() {
            match oldest_time {
                None => {
                    oldest_key = Some(*key);
                    oldest_time = Some(value.created);
                }
                Some(instant) => {
                    if value.created < instant {
                        oldest_key = Some(*key);
                        oldest_time = Some(value.created);
                    }
                }
            }
        }
        if let Some(key) = oldest_key {
            self.drop_entry(&key, inner);
        }
    }
}

impl Debug for Gecko {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.salamander.fmt(f)
    }
}

impl AsyncUdpSocket for Gecko {
    fn create_io_poller(self: Arc<Self>) -> std::pin::Pin<Box<dyn quinn::UdpPoller>> {
        self.salamander.clone().create_io_poller()
    }

    fn try_send(&self, tx: &Transmit) -> std::io::Result<()> {
        if !Self::is_long_header(tx.contents) {
            return self.salamander.try_send(tx);
        }
        let packets = self.fragment(tx.contents);
        log::trace!("gecko: fragmenting {} bytes into {} chunks", tx.contents.len(), packets.len());
        let mut transmit = tx.to_owned();
        for packet in &packets {
            transmit.contents = packet;
            self.salamander.try_send(&transmit)?;
        }
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<std::io::Result<usize>> {
        let mut out = 0;
        loop {
            let n = std::task::ready!(self.salamander.poll_recv(cx, bufs, meta))?;
            for i in 0..n {
                let len = meta[i].len;
                let addr = meta[i].addr;
                if let Some(pkt) = self.reassemble(addr, &bufs[i][..len]) {
                    if out >= bufs.len() {
                        break;
                    }
                    log::trace!("gecko: reassembled packet {} bytes from {}", pkt.len(), addr);
                    let dst = &mut bufs[out];
                    let copy = pkt.len().min(dst.len());
                    dst[..copy].copy_from_slice(&pkt[..copy]);
                    meta[out].len = copy;
                    meta[out].stride = copy;
                    meta[out].addr = addr;
                    out += 1;
                }
            }
            if out > 0 {
                break;
            }
        }
        Poll::Ready(Ok(out))
    }

    fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.salamander.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        self.salamander.may_fragment()
    }
}
