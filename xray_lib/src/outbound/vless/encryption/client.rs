//! VLESS Encryption Client — Hybrid PQ key exchange (ML-KEM-768 + X25519)
//!
//! Rust port of Xray-core/proxy/vless/encryption/client.go
//!
//! Supports:
//! - 1-RTT: Full handshake with ML-KEM-768 + X25519 key exchange
//! - 0-RTT: Session resumption using cached PFS key + ticket
//! - XOR mode 2: AES-CTR header obfuscation
//! - Configurable padding for traffic pattern obfuscation
macro_rules! check_read_eof {
    ($rb:expr, $msg:expr) => {
        if $rb.filled().is_empty() {
            return Poll::Ready(Err(Error::new(ErrorKind::UnexpectedEof, $msg)));
        }
    };
}

use std::io::{self, Error, ErrorKind};
use std::time::{Duration, Instant};

use aes::Aes256;
use aes::cipher::{KeyIvInit, StreamCipher};
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce as AesNonce};
use blake3;
use chacha20poly1305::ChaCha20Poly1305;
use ml_kem::MlKem768;
use ml_kem::kem::{Decapsulate, Encapsulate, Kem};
use rand::rngs::OsRng;
use rand::{Rng, RngCore};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

use super::aead::VlessAead;
use super::common::{MAX_NONCE, decode_header, decode_length, encode_length};
use super::xor::{XorState, new_ctr};

type Aes256Ctr = ctr::Ctr128BE<Aes256>;

// ─── Constants ───────────────────────────────────────────────────────────────

/// ML-KEM-768 encapsulation key size
const MLKEM768_EK_SIZE: usize = 1184;
/// ML-KEM-768 ciphertext size
const MLKEM768_CT_SIZE: usize = 1088;
/// X25519 public key size
const X25519_KEY_SIZE: usize = 32;
/// AEAD tag size
const TAG_SIZE: usize = 16;
/// Encrypted length field = 2 bytes plaintext + 16 bytes tag
const ENCRYPTED_LENGTH_SIZE: usize = 18;

// ─── NFS Public Key ──────────────────────────────────────────────────────────

#[derive(Debug)]
enum NfsPublicKey {
    X25519(X25519PublicKey),
    MlKem768(Vec<u8>), // raw encapsulation key bytes (1184 bytes)
}

// ─── Padding ─────────────────────────────────────────────────────────────────

/// Parse padding config string. Format: "prob-min-max.prob-min-max..."
/// Even-indexed = lengths, odd-indexed = gaps (ms).
pub fn parse_padding(
    padding: &str,
    padding_lens: &mut Vec<[i64; 3]>,
    padding_gaps: &mut Vec<[i64; 3]>,
) -> Result<(), Error> {
    if padding.is_empty() {
        return Ok(());
    }
    let mut max_len: i64 = 0;
    for (i, s) in padding.split('.').enumerate() {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() < 3 || parts.iter().any(|p| p.is_empty()) {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("invalid padding parameter: {}", s),
            ));
        }
        let y: [i64; 3] = [
            parts[0]
                .parse()
                .map_err(|e| Error::new(ErrorKind::InvalidInput, e))?,
            parts[1]
                .parse()
                .map_err(|e| Error::new(ErrorKind::InvalidInput, e))?,
            parts[2]
                .parse()
                .map_err(|e| Error::new(ErrorKind::InvalidInput, e))?,
        ];
        if i == 0 && (y[0] < 100 || y[1] < 35 || y[2] < 35) {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "first padding length must not be smaller than 35",
            ));
        }
        if i % 2 == 0 {
            padding_lens.push(y);
            max_len += y[1].max(y[2]);
        } else {
            padding_gaps.push(y);
        }
    }
    if max_len > 18 + 65535 {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "total padding length must not be larger than 65553",
        ));
    }
    Ok(())
}

fn create_padding(
    padding_lens: &[[i64; 3]],
    padding_gaps: &[[i64; 3]],
) -> (usize, Vec<usize>, Vec<Duration>) {
    let mut rng = rand::thread_rng();
    let pl = if padding_lens.is_empty() {
        vec![[100i64, 111, 1111], [50, 0, 3333]]
    } else {
        padding_lens.to_vec()
    };
    let pg = if padding_gaps.is_empty() {
        vec![[75i64, 0, 111]]
    } else {
        padding_gaps.to_vec()
    };
    let mut total: usize = 0;
    let mut lens = Vec::new();
    for y in &pl {
        let l = if y[0] >= rng.gen_range(0..=100) {
            rng.gen_range(y[1]..=y[2]) as usize
        } else {
            0
        };
        lens.push(l);
        total += l;
    }
    let mut gaps = Vec::new();
    for y in &pg {
        let g = if y[0] >= rng.gen_range(0..=100) {
            rng.gen_range(y[1]..=y[2]) as u64
        } else {
            0
        };
        gaps.push(Duration::from_millis(g));
    }
    (total, lens, gaps)
}

// ─── Session State ───────────────────────────────────────────────────────────

struct SessionState {
    expire: Instant,
    pfs_key: Vec<u8>,
    ticket: Vec<u8>,
}

// ─── ClientInstance ──────────────────────────────────────────────────────────

pub struct ClientInstance {
    nfs_pkeys: Vec<NfsPublicKey>,
    nfs_pkeys_bytes: Vec<Vec<u8>>,
    hash32s: Vec<[u8; 32]>,
    relays_length: usize,
    xor_mode: u32,
    seconds: u32,
    padding_lens: Vec<[i64; 3]>,
    padding_gaps: Vec<[i64; 3]>,
    session: RwLock<Option<SessionState>>,
}

impl ClientInstance {
    pub fn new(
        nfs_pkeys_bytes: Vec<Vec<u8>>,
        xor_mode: u32,
        seconds: u32,
        padding: &str,
    ) -> Result<Self, Error> {
        if nfs_pkeys_bytes.is_empty() {
            return Err(Error::new(ErrorKind::InvalidInput, "empty nfs public keys"));
        }
        let mut nfs_pkeys = Vec::with_capacity(nfs_pkeys_bytes.len());
        let mut hash32s = Vec::with_capacity(nfs_pkeys_bytes.len());
        let mut relays_length: usize = 0;

        for k in &nfs_pkeys_bytes {
            if k.len() == 32 {
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(k);
                nfs_pkeys.push(NfsPublicKey::X25519(X25519PublicKey::from(bytes)));
                relays_length += 32 + 32;
            } else {
                nfs_pkeys.push(NfsPublicKey::MlKem768(k.clone()));
                relays_length += MLKEM768_CT_SIZE + 32;
            }
            hash32s.push(blake3::hash(k).into());
        }
        relays_length -= 32; // last key has no trailing hash

        let mut padding_lens = Vec::new();
        let mut padding_gaps = Vec::new();
        parse_padding(padding, &mut padding_lens, &mut padding_gaps)?;

        Ok(Self {
            nfs_pkeys,
            nfs_pkeys_bytes,
            hash32s,
            relays_length,
            xor_mode,
            seconds,
            padding_lens,
            padding_gaps,
            session: RwLock::new(None),
        })
    }

    /// Perform the encryption handshake.
    pub async fn handshake<C: AsyncRead + AsyncWrite + Unpin>(
        &self,
        conn: &mut C,
        use_aes: bool,
    ) -> Result<HandshakeResult, Error> {
        let iv_relays_len = 16 + self.relays_length;
        let pfs_exchange_len =
            ENCRYPTED_LENGTH_SIZE + MLKEM768_EK_SIZE + X25519_KEY_SIZE + TAG_SIZE;
        let (pad_len, mut pad_lens, pad_gaps) =
            create_padding(&self.padding_lens, &self.padding_gaps);

        let total = iv_relays_len + pfs_exchange_len + pad_len;
        let mut hello = vec![0u8; total];

        // Generate IV (16 random bytes)
        OsRng.fill_bytes(&mut hello[..16]);
        let iv = hello[..16].to_vec();

        // Build relay chain
        let nfs_key = self.build_relays(&mut hello[16..iv_relays_len], &iv)?;
        let mut nfs_aead = VlessAead::new(&iv, &nfs_key, use_aes);

        // ── 0-RTT check ──────────────────────────────────────────────────
        if self.seconds > 0 {
            let guard = self.session.read().await;
            if let Some(ref s) = *guard {
                if Instant::now() < s.expire {
                    let pfs_key = s.pfs_key.clone();
                    let ticket = s.ticket.clone();
                    drop(guard);

                    let mut united_key = pfs_key;
                    united_key.extend_from_slice(&nfs_key);

                    let enc_len = nfs_aead.seal(&encode_length(32), &[])?;
                    hello[iv_relays_len..iv_relays_len + 18].copy_from_slice(&enc_len);

                    let enc_ticket = nfs_aead.seal(&ticket, &[])?;
                    hello[iv_relays_len + 18..iv_relays_len + 50].copy_from_slice(&enc_ticket);

                    let pre_write = hello[..iv_relays_len + 50].to_vec();
                    let aead = VlessAead::new(
                        &hello[iv_relays_len + 18..iv_relays_len + 50],
                        &united_key,
                        use_aes,
                    );
                    let xor_out = if self.xor_mode == 2 {
                        Some(XorState::new(&united_key, &iv))
                    } else {
                        None
                    };
                    let xor_in = if self.xor_mode == 2 {
                        Some(XorState::new(&united_key, &[0u8; 16]))
                    } else {
                        None
                    };

                    return Ok(HandshakeResult {
                        pre_write: Some(pre_write),
                        aead,
                        peer_aead: None,
                        united_key,
                        use_aes,
                        xor_out,
                        xor_in,
                        peer_padding: None,
                        is_zero_rtt: true,
                        iv,
                    });
                }
            }
        }

        // ── 1-RTT: generate PFS keypairs ─────────────────────────────────
        let (mlkem_dk, mlkem_ek) = MlKem768::generate_keypair();
        let x25519_secret = EphemeralSecret::random_from_rng(OsRng);
        let x25519_pub = X25519PublicKey::from(&x25519_secret);

        // pfs_public_key = ek_bytes || x25519_pub
        let ek_bytes_arr = ml_kem::kem::KeyExport::to_bytes(&mlkem_ek);
        let ek_bytes: &[u8] = ek_bytes_arr.as_ref();
        let mut pfs_pub_key = Vec::with_capacity(MLKEM768_EK_SIZE + X25519_KEY_SIZE);
        pfs_pub_key.extend_from_slice(ek_bytes);
        pfs_pub_key.extend_from_slice(x25519_pub.as_bytes());

        // Encrypt length
        let content_len = pfs_exchange_len - ENCRYPTED_LENGTH_SIZE;

        let enc_len = nfs_aead.seal(&encode_length(content_len), &[])?;

        hello[iv_relays_len..iv_relays_len + 18].copy_from_slice(&enc_len);

        // Encrypt PFS public key
        let enc_pfs = nfs_aead.seal(&pfs_pub_key, &[])?;

        hello[iv_relays_len + 18..iv_relays_len + pfs_exchange_len].copy_from_slice(&enc_pfs);

        // Encrypt padding
        if pad_len > 0 {
            let ps = iv_relays_len + pfs_exchange_len;
            let enc_pl = nfs_aead.seal(&encode_length(pad_len - 18), &[])?;
            hello[ps..ps + 18].copy_from_slice(&enc_pl);
            // random fill + encrypt padding body
            OsRng.fill_bytes(&mut hello[ps + 18..ps + pad_len - TAG_SIZE]);
            let body = hello[ps + 18..ps + pad_len - TAG_SIZE].to_vec();
            let enc_body = nfs_aead.seal(&body, &[])?;
            hello[ps + 18..ps + 18 + enc_body.len()].copy_from_slice(&enc_body);
        }

        // Send fragmented
        pad_lens[0] += iv_relays_len + pfs_exchange_len;
        let mut off = 0;
        for (i, &l) in pad_lens.iter().enumerate() {
            if l > 0 && off < hello.len() {
                let end = (off + l).min(hello.len());
                conn.write_all(&hello[off..end]).await?;
                off = end;
            }
            if i < pad_gaps.len() && !pad_gaps[i].is_zero() {
                tokio::time::sleep(pad_gaps[i]).await;
            }
        }

        // ── Read server PFS response (MaxNonce decrypt) ──────────────────
        let srv_pfs_len = MLKEM768_CT_SIZE + X25519_KEY_SIZE + TAG_SIZE;
        let mut enc_srv_pfs = vec![0u8; srv_pfs_len];
        conn.read_exact(&mut enc_srv_pfs).await?;

        let dec_pfs = open_with_nonce(&nfs_key, &iv, use_aes, &MAX_NONCE, &enc_srv_pfs, &[])?;
        // ── Derive shared secrets ────────────────────────────────────────
        // ML-KEM-768 decapsulate
        let ct_bytes = &dec_pfs[..MLKEM768_CT_SIZE];
        let ct = ml_kem::kem::Ciphertext::<MlKem768>::try_from(ct_bytes)
            .map_err(|_| Error::new(ErrorKind::InvalidData, "invalid ML-KEM ciphertext length"))?;

        let mlkem_ss = mlkem_dk.decapsulate(&ct);

        // X25519 ECDH
        let mut peer_x_bytes = [0u8; 32];
        peer_x_bytes.copy_from_slice(&dec_pfs[MLKEM768_CT_SIZE..MLKEM768_CT_SIZE + 32]);
        let peer_x_pk = X25519PublicKey::from(peer_x_bytes);
        let x_ss = x25519_secret.diffie_hellman(&peer_x_pk);

        // pfs_key = mlkem_ss || x25519_ss
        let mut pfs_key = Vec::with_capacity(64);
        pfs_key.extend_from_slice(mlkem_ss.as_slice());
        pfs_key.extend_from_slice(x_ss.as_bytes());

        // united_key = pfs_key || nfs_key
        let mut united_key = pfs_key.clone();
        united_key.extend_from_slice(&nfs_key);

        let aead = VlessAead::new(&pfs_pub_key, &united_key, use_aes);
        let mut peer_aead = VlessAead::new(
            &dec_pfs[..MLKEM768_CT_SIZE + X25519_KEY_SIZE],
            &united_key,
            use_aes,
        );

        // ── Read encrypted ticket ────────────────────────────────────────
        let mut enc_ticket = vec![0u8; 32];
        conn.read_exact(&mut enc_ticket).await?;
        let dec_ticket = peer_aead.open(&enc_ticket, &[])?;
        let secs = decode_length(&dec_ticket);
        if self.seconds > 0 && secs > 0 {
            let mut guard = self.session.write().await;
            *guard = Some(SessionState {
                expire: Instant::now() + Duration::from_secs(secs as u64),
                pfs_key,
                ticket: dec_ticket[..16].to_vec(),
            });
        }

        // ── Read peer padding length ─────────────────────────────────────
        let mut enc_plen = vec![0u8; ENCRYPTED_LENGTH_SIZE];
        conn.read_exact(&mut enc_plen).await?;
        let dec_plen = peer_aead.open(&enc_plen, &[])?;
        let peer_pad_len = decode_length(&dec_plen);

        // ── XOR mode 2 ──────────────────────────────────────────────────
        let xor_out = if self.xor_mode == 2 {
            Some(XorState::new(&united_key, &iv))
        } else {
            None
        };
        let xor_in = if self.xor_mode == 2 {
            Some(XorState::new(&united_key, &dec_ticket[..16]))
        } else {
            None
        };

        Ok(HandshakeResult {
            pre_write: None,
            aead,
            peer_aead: Some(peer_aead),
            united_key,
            use_aes,
            xor_out,
            xor_in,
            peer_padding: Some(vec![0u8; peer_pad_len]),
            is_zero_rtt: false,
            iv,
        })
    }
    /// Build relay chain: key exchange with each NFS key.
    fn build_relays(&self, relays: &mut [u8], iv: &[u8]) -> Result<Vec<u8>, Error> {
        let mut nfs_key: Vec<u8> = Vec::new();
        let mut last_ctr: Option<Aes256Ctr> = None;
        let mut offset = 0;

        for j in 0..self.nfs_pkeys.len() {
            let index: usize;
            match &self.nfs_pkeys[j] {
                NfsPublicKey::X25519(peer_pk) => {
                    index = 32;
                    let secret = EphemeralSecret::random_from_rng(OsRng);
                    let our_pk = X25519PublicKey::from(&secret);
                    relays[offset..offset + 32].copy_from_slice(our_pk.as_bytes());
                    let shared = secret.diffie_hellman(peer_pk);
                    nfs_key = shared.as_bytes().to_vec();
                }
                NfsPublicKey::MlKem768(ek_bytes) => {
                    index = MLKEM768_CT_SIZE;
                    let ek_key =
                        ml_kem::array::Array::try_from(ek_bytes.as_slice()).map_err(|_| {
                            Error::new(
                                ErrorKind::InvalidData,
                                "invalid ML-KEM-768 encapsulation key length",
                            )
                        })?;
                    let ek = ml_kem::EncapsulationKey::<MlKem768>::new(&ek_key).map_err(|_| {
                        Error::new(
                            ErrorKind::InvalidData,
                            "invalid ML-KEM-768 encapsulation key",
                        )
                    })?;
                    let (ct, ss) = ek.encapsulate();
                    relays[offset..offset + MLKEM768_CT_SIZE].copy_from_slice(ct.as_slice());
                    nfs_key = ss.as_slice().to_vec();
                }
            }

            // XOR obfuscation
            if self.xor_mode > 0 {
                let mut ctr = new_ctr(&self.nfs_pkeys_bytes[j], iv);
                ctr.apply_keystream(&mut relays[offset..offset + index]);
            }

            // Chain with previous CTR
            if let Some(ref mut prev) = last_ctr {
                prev.apply_keystream(&mut relays[offset..offset + 32]);
            }

            if j == self.nfs_pkeys.len() - 1 {
                break;
            }

            // Write next key hash
            last_ctr = Some(new_ctr(&nfs_key, iv));
            let ho = offset + index;
            relays[ho..ho + 32].copy_from_slice(&self.hash32s[j + 1]);
            if let Some(ref mut c) = last_ctr {
                c.apply_keystream(&mut relays[ho..ho + 32]);
            }
            offset += index + 32;
        }
        Ok(nfs_key)
    }
}

// ─── HandshakeResult ─────────────────────────────────────────────────────────

pub struct HandshakeResult {
    pub pre_write: Option<Vec<u8>>,
    pub aead: VlessAead,
    pub peer_aead: Option<VlessAead>,
    pub united_key: Vec<u8>,
    pub use_aes: bool,
    pub xor_out: Option<XorState>,
    pub xor_in: Option<XorState>,
    pub peer_padding: Option<Vec<u8>>,
    pub is_zero_rtt: bool,
    pub iv: Vec<u8>,
}

// ─── Helper: decrypt with explicit nonce ─────────────────────────────────────

fn open_with_nonce(
    key_material: &[u8],
    context: &[u8],
    use_aes: bool,
    nonce: &[u8; 12],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, Error> {
    let dk = blake3::derive_key(
        unsafe { std::str::from_utf8_unchecked(context) },
        key_material,
    );
    let payload = aes_gcm::aead::Payload {
        msg: ciphertext,
        aad,
    };
    let result = if use_aes {
        let c = Aes256Gcm::new_from_slice(&dk).unwrap();
        c.decrypt(AesNonce::from_slice(nonce), payload)
    } else {
        let c = ChaCha20Poly1305::new_from_slice(&dk).unwrap();
        c.decrypt(chacha20poly1305::Nonce::from_slice(nonce), payload)
    };
    result.map_err(|e| Error::new(ErrorKind::InvalidData, format!("decrypt: {}", e)))
}

// ─── EncryptedTransport ──────────────────────────────────────────────────────

use crate::core::io::AsyncXrayTcpStream;
use crate::core::transport::XrayTransport;
use crate::outbound::vless::VlessStream;
use bytes::{Buf, BytesMut};
use futures::ready;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::ReadBuf;
use tokio::sync::RwLock;

enum ReadState {
    Idle,
    ZeroRttRandom {
        buf: [u8; 16],
        pos: usize,
    },

    Padding {
        buf: Vec<u8>,
        pos: usize,
    },

    Header {
        buf: [u8; 5],
        pos: usize,
    },

    Payload {
        header: [u8; 5],
        buf: Vec<u8>,
        pos: usize,
    },
}

/// Async transport wrapper that applies AEAD encryption/decryption.
/// Wraps an inner transport and uses HandshakeResult for framing.
pub struct EncryptedTransport {
    inner: Box<dyn XrayTransport>,
    result: HandshakeResult,
    pre_write_done: bool,
    peer_padding_done: bool,

    read_state: ReadState,
    read_buffer: BytesMut,

    write_buffer: BytesMut,
    to_write_size: usize,
}

impl EncryptedTransport {
    pub fn new(inner: Box<dyn XrayTransport>, result: HandshakeResult) -> Self {
        let pwd = result.pre_write.is_none();
        let ppd = result.peer_padding.is_none();
        Self {
            inner,
            result,
            pre_write_done: pwd,
            peer_padding_done: ppd,
            read_state: ReadState::Idle,
            read_buffer: BytesMut::new(),
            write_buffer: BytesMut::new(),
            to_write_size: 0,
        }
    }
}

impl AsyncWrite for EncryptedTransport {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        loop {
            if !this.write_buffer.is_empty() {
                // Write the entire buffer to inner transport
                let data = this.write_buffer.as_ref();
                let result = ready!(Pin::new(&mut this.inner).poll_write(cx, data));
                match result {
                    Ok(n) => {
                        this.write_buffer.advance(n);
                        if this.write_buffer.is_empty() {
                            return Poll::Ready(Ok(this.to_write_size));
                        }
                    }
                    Err(err) => {
                        let message = format!("{{vless encrypt write error:  {}}}", err);
                        return Poll::Ready(Err(io::Error::new(ErrorKind::BrokenPipe, message)));
                    }
                };
            }

            // Encrypt one frame at a time (max 8192 bytes payload)
            let n = buf.len().min(super::common::MAX_PAYLOAD);
            this.to_write_size = n;
            let chunk = &buf[..n];

            let rotate = this.result.aead.needs_rotation();
            let mut frame = vec![0u8; super::common::HEADER_SIZE];
            super::common::encode_header(&mut frame, n + TAG_SIZE);

            let ct = match this.result.aead.seal(chunk, &frame) {
                Ok(c) => c,
                Err(e) => return Poll::Ready(Err(e)),
            };
            frame.extend_from_slice(&ct);

            if rotate {
                this.result.aead =
                    VlessAead::new(&frame, &this.result.united_key, this.result.use_aes);
            }
            if let Some(ref mut xor) = this.result.xor_out {
                xor.apply(&mut frame[..super::common::HEADER_SIZE]);
            }

            // Prepend pre_write on first write (0-RTT)
            let data = if !this.pre_write_done {
                this.pre_write_done = true;
                if let Some(pre) = this.result.pre_write.take() {
                    let mut combined = pre;
                    combined.extend_from_slice(&frame);
                    combined
                } else {
                    frame
                }
            } else {
                frame
            };

            this.write_buffer.extend_from_slice(&data);
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl AsyncRead for EncryptedTransport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;

        loop {
            if !this.read_buffer.is_empty() {
                let n = this.read_buffer.len().min(buf.remaining());
                buf.put_slice(&this.read_buffer.split_to(n));
                return Poll::Ready(Ok(()));
            }

            match &mut this.read_state {
                ReadState::ZeroRttRandom { buf, pos } => {
                    let mut rb = ReadBuf::new(&mut buf[*pos..]);

                    match ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb)) {
                        Ok(()) => {
                            check_read_eof!(rb, "unexpected eof while reading zero rtt random");
                            *pos += rb.filled().len();
                            if *pos < 16 {
                                continue;
                            }
                            this.result.peer_aead = Some(VlessAead::new(
                                buf,
                                &this.result.united_key,
                                this.result.use_aes,
                            ));
                            if this.result.xor_in.is_some() {
                                this.result.xor_in =
                                    Some(XorState::new(&this.result.united_key, buf));
                            }
                            this.read_state = ReadState::Idle;
                        }
                        Err(e) => return Poll::Ready(Err(e)),
                    }
                }

                ReadState::Padding { buf, pos } => {
                    let mut rb = ReadBuf::new(&mut buf[*pos..]);

                    match ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb)) {
                        Ok(()) => {
                            check_read_eof!(rb, "unexpected eof while reading padding bytes");
                            *pos += rb.filled().len();
                            if *pos < buf.len() {
                                continue;
                            }
                            if let Some(ref mut aead) = this.result.peer_aead {
                                let _ = aead.open(buf, &[]);
                            }
                            this.peer_padding_done = true;
                            this.read_state = ReadState::Idle;
                        }
                        Err(e) => return Poll::Ready(Err(e)),
                    }
                }

                ReadState::Header { buf: hdr, pos } => {
                    let mut rb = ReadBuf::new(&mut hdr[*pos..]);

                    match ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb)) {
                        Ok(()) => {
                            check_read_eof!(rb, "unexpected eof while reading heading bytes");
                            *pos += rb.filled().len();

                            if *pos < 5 {
                                continue;
                            }

                            if let Some(ref mut xor) = this.result.xor_in {
                                xor.apply(hdr);
                            }

                            let len = match decode_header(hdr) {
                                Ok(v) => v,
                                Err(e) => {
                                    return Poll::Ready(Err(Error::new(
                                        ErrorKind::InvalidData,
                                        format!("header decode {}", e),
                                    )));
                                }
                            };

                            this.read_state = ReadState::Payload {
                                header: *hdr,
                                buf: vec![0u8; len],
                                pos: 0,
                            };
                        }
                        Err(e) => return Poll::Ready(Err(e)),
                    }
                }

                ReadState::Payload {
                    header,
                    buf: data,
                    pos,
                } => {
                    let mut rb = ReadBuf::new(&mut data[*pos..]);
                    match ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb)) {
                        Ok(()) => {
                            check_read_eof!(rb, "unexpected eof while reading payload bytes");
                            *pos += rb.filled().len();

                            if *pos < data.len() {
                                continue;
                            }

                            let peer = match this.result.peer_aead.as_mut() {
                                Some(v) => v,
                                None => {
                                    return Poll::Ready(Err(Error::new(
                                        ErrorKind::Other,
                                        "missing peer aead",
                                    )));
                                }
                            };

                            let rotate = peer.needs_rotation();

                            let ctx = if rotate {
                                let mut c = header.to_vec();
                                c.extend_from_slice(data);
                                Some(c)
                            } else {
                                None
                            };

                            let plain = match peer.open(data, header) {
                                Ok(v) => v,
                                Err(e) => return Poll::Ready(Err(e)),
                            };

                            if let Some(c) = ctx {
                                this.result.peer_aead = Some(VlessAead::new(
                                    &c,
                                    &this.result.united_key,
                                    this.result.use_aes,
                                ));
                            }
                            this.read_buffer.extend_from_slice(&plain);
                            this.read_state = ReadState::Idle;
                            continue;
                        }

                        Err(e) => return Poll::Ready(Err(e)),
                    };
                }
                ReadState::Idle => {
                    if this.result.is_zero_rtt && this.result.peer_aead.is_none() {
                        this.read_state = ReadState::ZeroRttRandom {
                            buf: [0u8; 16],
                            pos: 0,
                        };
                    } else if !this.peer_padding_done {
                        if let Some(p) = this.result.peer_padding.take() {
                            this.read_state = ReadState::Padding { buf: p, pos: 0 };
                        } else {
                            this.peer_padding_done = true;
                        }
                    } else {
                        this.read_state = ReadState::Header {
                            buf: [0u8; 5],
                            pos: 0,
                        };
                    }
                }
            }
        }
    }
}

impl AsyncXrayTcpStream for EncryptedTransport {}

impl XrayTransport for EncryptedTransport {}
