use std::collections::{HashMap, VecDeque};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Key, Nonce, Tag};
use chacha20poly1305::ChaCha20Poly1305;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use parking_lot::Mutex;
use rand::RngCore;
use sha2::{Digest, Sha256, Sha384, Sha512};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use x25519_dalek::{PublicKey, StaticSecret};

use super::reality_hello::{build_client_hello, patch_session_id, FingerprintProfile};
use super::BoxStream;

type HmacSha512 = Hmac<Sha512>;
type HmacSha256 = Hmac<Sha256>;
type HmacSha384 = Hmac<Sha384>;

const MAX_TLS_CIPHERTEXT_LEN: usize = 16384 + 256;
const MAX_HANDSHAKE_BUFFER: usize = 65536;
const OID_MLDSA65: [u8; 11] = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12];

#[derive(Clone, Debug)]
pub struct RealityClientConfig {
    pub server_name: String,
    pub public_key: [u8; 32],
    pub short_id: Vec<u8>,
    pub fingerprint: String,
    pub alpn: Vec<String>,
    pub mldsa65_verify: String,
}

#[derive(Clone)]
pub struct RealityServerConfig {
    pub private_key: [u8; 32],
    pub short_ids: Vec<(Vec<u8>, usize)>,
    pub server_names: Vec<String>,
    pub dest: String,
    pub max_time_diff_ms: u64,
    pub mldsa65_seed: String,
    pub replay_cache: Arc<RealityReplayCache>,
}

struct ReplayCacheInner {
    seen: HashMap<[u8; 32], Instant>,
    order: VecDeque<([u8; 32], Instant)>,
}

pub struct RealityReplayCache {
    inner: Mutex<ReplayCacheInner>,
}

impl RealityReplayCache {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(ReplayCacheInner {
                seen: HashMap::new(),
                order: VecDeque::new(),
            }),
        }
    }

    pub fn check_and_insert(&self, sid: [u8; 32], ttl: Duration) -> bool {
        let now = Instant::now();
        let mut guard = self.inner.lock();
        while let Some(&(front_sid, front_exp)) = guard.order.front() {
            if front_exp > now && guard.seen.len() < 16384 {
                break;
            }
            guard.order.pop_front();
            if guard.seen.get(&front_sid) == Some(&front_exp) {
                guard.seen.remove(&front_sid);
            }
        }
        if let Some(&exp) = guard.seen.get(&sid) {
            if exp > now {
                return false;
            }
        }
        let exp = now + ttl;
        guard.seen.insert(sid, exp);
        guard.order.push_back((sid, exp));
        if guard.order.len() > 32768 {
            let seen_ref = &guard.seen;
            let mut filtered = VecDeque::with_capacity(seen_ref.len());
            for &(k, e) in &guard.order {
                if seen_ref.get(&k) == Some(&e) {
                    filtered.push_back((k, e));
                }
            }
            guard.order = filtered;
        }
        true
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tls13Cipher {
    Aes128GcmSha256,
    Aes256GcmSha384,
    ChaCha20Poly1305Sha256,
}

impl Tls13Cipher {
    fn from_id(id: u16) -> Option<Self> {
        match id {
            0x1301 => Some(Self::Aes128GcmSha256),
            0x1302 => Some(Self::Aes256GcmSha384),
            0x1303 => Some(Self::ChaCha20Poly1305Sha256),
            _ => None,
        }
    }

    fn id(self) -> u16 {
        match self {
            Self::Aes128GcmSha256 => 0x1301,
            Self::Aes256GcmSha384 => 0x1302,
            Self::ChaCha20Poly1305Sha256 => 0x1303,
        }
    }

    fn key_len(self) -> usize {
        match self {
            Self::Aes128GcmSha256 => 16,
            Self::Aes256GcmSha384 => 32,
            Self::ChaCha20Poly1305Sha256 => 32,
        }
    }

    fn hash_len(self) -> usize {
        match self {
            Self::Aes256GcmSha384 => 48,
            _ => 32,
        }
    }

    fn empty_hash(self) -> Vec<u8> {
        match self {
            Self::Aes256GcmSha384 => Sha384::digest([]).to_vec(),
            _ => Sha256::digest([]).to_vec(),
        }
    }
}

enum CipherKey {
    Aes128(Aes128Gcm),
    Aes256(Aes256Gcm),
    ChaCha(ChaCha20Poly1305),
}

impl CipherKey {
    fn new(cipher: Tls13Cipher, key: &[u8]) -> io::Result<Self> {
        match cipher {
            Tls13Cipher::Aes128GcmSha256 => Ok(Self::Aes128(
                Aes128Gcm::new_from_slice(key)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "aes128 key"))?,
            )),
            Tls13Cipher::Aes256GcmSha384 => Ok(Self::Aes256(
                Aes256Gcm::new_from_slice(key)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "aes256 key"))?,
            )),
            Tls13Cipher::ChaCha20Poly1305Sha256 => Ok(Self::ChaCha(
                ChaCha20Poly1305::new_from_slice(key)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "chacha key"))?,
            )),
        }
    }

    fn seal_in_place(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> io::Result<[u8; 16]> {
        let n = Nonce::from_slice(nonce);
        let tag = match self {
            Self::Aes128(c) => c
                .encrypt_in_place_detached(n, aad, buf)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "aes128 encrypt"))?,
            Self::Aes256(c) => c
                .encrypt_in_place_detached(n, aad, buf)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "aes256 encrypt"))?,
            Self::ChaCha(c) => c
                .encrypt_in_place_detached(chacha20poly1305::Nonce::from_slice(nonce), aad, buf)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "chacha encrypt"))?,
        };
        let mut out = [0u8; 16];
        out.copy_from_slice(tag.as_slice());
        Ok(out)
    }

    fn open_in_place(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
        tag_bytes: &[u8; 16],
    ) -> io::Result<()> {
        let n = Nonce::from_slice(nonce);
        let tag = Tag::from_slice(tag_bytes);
        match self {
            Self::Aes128(c) => c
                .decrypt_in_place_detached(n, aad, buf, tag)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "aes128 decrypt")),
            Self::Aes256(c) => c
                .decrypt_in_place_detached(n, aad, buf, tag)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "aes256 decrypt")),
            Self::ChaCha(c) => c
                .decrypt_in_place_detached(
                    chacha20poly1305::Nonce::from_slice(nonce),
                    aad,
                    buf,
                    chacha20poly1305::Tag::from_slice(tag_bytes),
                )
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "chacha decrypt")),
        }
    }
}

struct TrafficCipher {
    key: CipherKey,
    iv: [u8; 12],
    seq: u64,
}

impl TrafficCipher {
    fn from_traffic_secret(cipher: Tls13Cipher, secret: &[u8]) -> io::Result<Self> {
        let key_bytes = hkdf_expand_label(cipher, secret, b"key", b"", cipher.key_len());
        let iv_vec = hkdf_expand_label(cipher, secret, b"iv", b"", 12);
        let mut iv = [0u8; 12];
        iv.copy_from_slice(&iv_vec);
        let key = CipherKey::new(cipher, &key_bytes)?;
        Ok(Self { key, iv, seq: 0 })
    }

    fn next_nonce(&mut self) -> io::Result<[u8; 12]> {
        if self.seq == u64::MAX {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "TLS record sequence overflow",
            ));
        }
        let mut nonce = self.iv;
        let seq_bytes = self.seq.to_be_bytes();
        for i in 0..8 {
            nonce[4 + i] ^= seq_bytes[i];
        }
        self.seq += 1;
        Ok(nonce)
    }

    fn seal_record(&mut self, inner_content_type: u8, plaintext: &[u8]) -> io::Result<Vec<u8>> {
        let mut record = Vec::with_capacity(5 + plaintext.len() + 17);
        self.seal_record_into(&mut record, inner_content_type, plaintext)?;
        Ok(record)
    }

    fn seal_record_into(
        &mut self,
        out: &mut Vec<u8>,
        inner_content_type: u8,
        plaintext: &[u8],
    ) -> io::Result<()> {
        let encrypted_len = plaintext.len() + 1 + 16;
        if encrypted_len > MAX_TLS_CIPHERTEXT_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TLS plaintext too large",
            ));
        }
        let aad = [
            0x17u8,
            0x03,
            0x03,
            ((encrypted_len >> 8) & 0xff) as u8,
            (encrypted_len & 0xff) as u8,
        ];
        out.reserve(5 + encrypted_len);
        out.extend_from_slice(&aad);
        let body_start = out.len();
        out.extend_from_slice(plaintext);
        out.push(inner_content_type);
        let nonce = self.next_nonce()?;
        let tag = self.key.seal_in_place(&nonce, &aad, &mut out[body_start..])?;
        out.extend_from_slice(&tag);
        Ok(())
    }

    fn open_record(&mut self, header: &[u8; 5], ciphertext: &[u8]) -> io::Result<(u8, Vec<u8>)> {
        let mut buf = ciphertext.to_vec();
        let (content_type, plain_len) = self.open_record_in_place(header, &mut buf)?;
        buf.truncate(plain_len);
        Ok((content_type, buf))
    }

    fn open_record_in_place(
        &mut self,
        header: &[u8; 5],
        ciphertext: &mut [u8],
    ) -> io::Result<(u8, usize)> {
        if ciphertext.len() < 17 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TLS record ciphertext too short",
            ));
        }
        let body_len = ciphertext.len() - 16;
        let (body, tag_slice) = ciphertext.split_at_mut(body_len);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(tag_slice);
        let nonce = self.next_nonce()?;
        self.key.open_in_place(&nonce, header, body, &tag)?;
        let mut end = body_len;
        while end > 0 && body[end - 1] == 0 {
            end -= 1;
        }
        if end == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TLS inner plaintext missing content type",
            ));
        }
        let content_type = body[end - 1];
        Ok((content_type, end - 1))
    }
}

fn hkdf_extract(cipher: Tls13Cipher, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    match cipher {
        Tls13Cipher::Aes256GcmSha384 => {
            let (prk, _) = Hkdf::<Sha384>::extract(Some(salt), ikm);
            prk.to_vec()
        }
        _ => {
            let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
            prk.to_vec()
        }
    }
}

fn hkdf_expand_label(
    cipher: Tls13Cipher,
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    len: usize,
) -> Vec<u8> {
    let full_label_len = 6 + label.len();
    let mut info = Vec::with_capacity(2 + 1 + full_label_len + 1 + context.len());
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push(full_label_len as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(context.len() as u8);
    info.extend_from_slice(context);

    let mut out = vec![0u8; len];
    match cipher {
        Tls13Cipher::Aes256GcmSha384 => {
            let hk = Hkdf::<Sha384>::from_prk(secret).expect("valid PRK len");
            hk.expand(&info, &mut out).expect("valid HKDF expand len");
        }
        _ => {
            let hk = Hkdf::<Sha256>::from_prk(secret).expect("valid PRK len");
            hk.expand(&info, &mut out).expect("valid HKDF expand len");
        }
    }
    out
}

fn derive_secret(cipher: Tls13Cipher, secret: &[u8], label: &[u8], transcript_hash: &[u8]) -> Vec<u8> {
    hkdf_expand_label(cipher, secret, label, transcript_hash, cipher.hash_len())
}

struct Transcript {
    sha256: Sha256,
    sha384: Sha384,
    cipher: Option<Tls13Cipher>,
}

impl Transcript {
    fn new() -> Self {
        Self {
            sha256: Sha256::new(),
            sha384: Sha384::new(),
            cipher: None,
        }
    }

    fn set_cipher(&mut self, c: Tls13Cipher) {
        self.cipher = Some(c);
    }

    fn update(&mut self, data: &[u8]) {
        self.sha256.update(data);
        self.sha384.update(data);
    }

    fn current_hash(&self) -> Vec<u8> {
        match self.cipher.unwrap_or(Tls13Cipher::Aes128GcmSha256) {
            Tls13Cipher::Aes256GcmSha384 => self.sha384.clone().finalize().to_vec(),
            _ => self.sha256.clone().finalize().to_vec(),
        }
    }
}

struct KeySchedule {
    cipher: Tls13Cipher,
    handshake_secret: Vec<u8>,
    client_handshake_traffic_secret: Vec<u8>,
    server_handshake_traffic_secret: Vec<u8>,
}

impl KeySchedule {
    fn compute(cipher: Tls13Cipher, shared_secret: &[u8], hello_hash: &[u8]) -> Self {
        let zero = vec![0u8; cipher.hash_len()];
        let early_secret = hkdf_extract(cipher, &zero, &zero);
        let derived_0 = derive_secret(cipher, &early_secret, b"derived", &cipher.empty_hash());
        let handshake_secret = hkdf_extract(cipher, &derived_0, shared_secret);
        let c_hs = derive_secret(cipher, &handshake_secret, b"c hs traffic", hello_hash);
        let s_hs = derive_secret(cipher, &handshake_secret, b"s hs traffic", hello_hash);
        Self {
            cipher,
            handshake_secret,
            client_handshake_traffic_secret: c_hs,
            server_handshake_traffic_secret: s_hs,
        }
    }

    fn compute_app_secrets(&self, server_finished_hash: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let zero = vec![0u8; self.cipher.hash_len()];
        let derived_1 = derive_secret(
            self.cipher,
            &self.handshake_secret,
            b"derived",
            &self.cipher.empty_hash(),
        );
        let master_secret = hkdf_extract(self.cipher, &derived_1, &zero);
        let c_ap = derive_secret(
            self.cipher,
            &master_secret,
            b"c ap traffic",
            server_finished_hash,
        );
        let s_ap = derive_secret(
            self.cipher,
            &master_secret,
            b"s ap traffic",
            server_finished_hash,
        );
        (c_ap, s_ap)
    }
}

fn compute_finished_verify_data(
    cipher: Tls13Cipher,
    base_key: &[u8],
    transcript_hash: &[u8],
) -> Vec<u8> {
    let finished_key = hkdf_expand_label(cipher, base_key, b"finished", b"", cipher.hash_len());
    match cipher {
        Tls13Cipher::Aes256GcmSha384 => {
            let mut mac = <HmacSha384 as Mac>::new_from_slice(&finished_key).expect("HMAC key");
            mac.update(transcript_hash);
            mac.finalize().into_bytes().to_vec()
        }
        _ => {
            let mut mac = <HmacSha256 as Mac>::new_from_slice(&finished_key).expect("HMAC key");
            mac.update(transcript_hash);
            mac.finalize().into_bytes().to_vec()
        }
    }
}

fn derive_reality_auth_key(shared: &[u8; 32], salt20: &[u8]) -> io::Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(salt20), shared);
    let mut auth_key = [0u8; 32];
    hk.expand(b"REALITY", &mut auth_key)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "HKDF expand failed"))?;
    Ok(auth_key)
}

fn encrypt_reality_session_id(
    auth_key: &[u8; 32],
    nonce12: &[u8],
    plaintext16: &[u8; 16],
    aad: &[u8],
) -> io::Result<[u8; 32]> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(auth_key));
    let mut buf = *plaintext16;
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(nonce12), aad, &mut buf)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "AES-GCM encrypt failed"))?;
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&buf);
    out[16..].copy_from_slice(tag.as_slice());
    Ok(out)
}

fn decrypt_reality_session_id(
    auth_key: &[u8; 32],
    nonce12: &[u8],
    ciphertext32: &[u8; 32],
    aad: &[u8],
) -> io::Result<[u8; 16]> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(auth_key));
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&ciphertext32[..16]);
    let tag = Tag::from_slice(&ciphertext32[16..]);
    if cipher
        .decrypt_in_place_detached(Nonce::from_slice(nonce12), aad, &mut buf, tag)
        .is_ok()
    {
        return Ok(buf);
    }
    buf.copy_from_slice(&ciphertext32[..16]);
    cipher
        .decrypt_in_place_detached(Nonce::from_slice(nonce12), b"", &mut buf, tag)
        .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "invalid reality session_id"))?;
    Ok(buf)
}

async fn read_tls_record<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> io::Result<([u8; 5], Vec<u8>)> {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).await?;
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    if len > MAX_TLS_CIPHERTEXT_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("TLS record length {} exceeds limit", len),
        ));
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await?;
    Ok((header, body))
}

pub async fn reality_connect<S>(mut inner: S, cfg: &RealityClientConfig) -> io::Result<BoxStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut rng_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut rng_bytes);
    let eph_secret = StaticSecret::from(rng_bytes);
    let eph_public = PublicKey::from(&eph_secret);

    let mut client_random = [0u8; 32];
    rand::rng().fill_bytes(&mut client_random);

    let server_pub = PublicKey::from(cfg.public_key);
    let shared = eph_secret.diffie_hellman(&server_pub);
    if shared.as_bytes().iter().all(|&b| b == 0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "REALITY X25519 low-order point",
        ));
    }
    let auth_key = derive_reality_auth_key(shared.as_bytes(), &client_random[..20])?;

    let mut sid_plain = [0u8; 16];
    sid_plain[0] = 1;
    sid_plain[1] = 8;
    sid_plain[2] = 0;
    sid_plain[3] = 0;
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
    sid_plain[4..8].copy_from_slice(&now_secs.to_be_bytes());
    let copy_len = cfg.short_id.len().min(8);
    sid_plain[8..8 + copy_len].copy_from_slice(&cfg.short_id[..copy_len]);

    let profile = FingerprintProfile::parse(&cfg.fingerprint);
    let alpn_refs: Vec<&str> = cfg.alpn.iter().map(|s| s.as_str()).collect();
    let zero_sid = [0u8; 32];
    let mut hello = build_client_hello(
        profile,
        &cfg.server_name,
        &client_random,
        &zero_sid,
        eph_public.as_bytes(),
        &alpn_refs,
    );
    let aad = &hello.record[5..];
    let encrypted_sid =
        encrypt_reality_session_id(&auth_key, &client_random[20..32], &sid_plain, aad)?;
    patch_session_id(&mut hello, &encrypted_sid);

    let mut transcript = Transcript::new();
    transcript.update(&hello.record[5..]);

    inner.write_all(&hello.record).await?;
    inner.flush().await?;

    let (sh_hdr, sh_body) = read_tls_record(&mut inner).await?;
    if sh_hdr[0] != 0x16 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("expected ServerHello handshake record, got 0x{:02x}", sh_hdr[0]),
        ));
    }
    let sh = parse_server_hello(&sh_body)?;
    let cipher = Tls13Cipher::from_id(sh.cipher_suite).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported cipher suite 0x{:04x}", sh.cipher_suite),
        )
    })?;
    transcript.set_cipher(cipher);
    transcript.update(&sh_body);

    if sh.key_share_group != 0x001d || sh.key_share_bytes.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported server key_share group",
        ));
    }
    let mut srv_pub_arr = [0u8; 32];
    srv_pub_arr.copy_from_slice(&sh.key_share_bytes);
    let srv_pub = PublicKey::from(srv_pub_arr);
    let hs_shared = eph_secret.diffie_hellman(&srv_pub);

    let hello_hash = transcript.current_hash();
    let keys = KeySchedule::compute(cipher, hs_shared.as_bytes(), &hello_hash);
    let mut s_hs_cipher =
        TrafficCipher::from_traffic_secret(cipher, &keys.server_handshake_traffic_secret)?;
    let mut c_hs_cipher =
        TrafficCipher::from_traffic_secret(cipher, &keys.client_handshake_traffic_secret)?;

    let mut hs_buf: Vec<u8> = Vec::new();
    let mut verified_ed25519_pub: Option<[u8; 32]> = None;
    let mut cert_signature_verified = false;
    let mut server_finished_ok = false;

    while !server_finished_ok {
        let (hdr, body) = read_tls_record(&mut inner).await?;
        match hdr[0] {
            0x14 => continue,
            0x17 => {
                let (inner_ct, plain) = s_hs_cipher.open_record(&hdr, &body)?;
                if inner_ct == 0x15 {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "REALITY server sent alert",
                    ));
                }
                if inner_ct != 0x16 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unexpected inner content type during handshake",
                    ));
                }
                hs_buf.extend_from_slice(&plain);
                if hs_buf.len() > MAX_HANDSHAKE_BUFFER {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "handshake buffer exceeded",
                    ));
                }
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unexpected TLS record type 0x{:02x}", other),
                ));
            }
        }

        while hs_buf.len() >= 4 {
            let msg_type = hs_buf[0];
            let msg_len =
                ((hs_buf[1] as usize) << 16) | ((hs_buf[2] as usize) << 8) | (hs_buf[3] as usize);
            if hs_buf.len() < 4 + msg_len {
                break;
            }
            let full_msg: Vec<u8> = hs_buf.drain(..4 + msg_len).collect();
            let msg_body = &full_msg[4..];

            match msg_type {
                0x08 => {
                    transcript.update(&full_msg);
                }
                0x0b => {
                    let ed_pub =
                        verify_reality_certificate(msg_body, &auth_key, &cfg.mldsa65_verify)?;
                    verified_ed25519_pub = Some(ed_pub);
                    transcript.update(&full_msg);
                }
                0x0f => {
                    let ed_pub = verified_ed25519_pub.ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "CertificateVerify before Certificate",
                        )
                    })?;
                    let th = transcript.current_hash();
                    verify_server_cert_verify(msg_body, &ed_pub, &th)?;
                    cert_signature_verified = true;
                    transcript.update(&full_msg);
                }
                0x14 => {
                    if !cert_signature_verified {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "Server Finished before CertificateVerify",
                        ));
                    }
                    let expected_verify = compute_finished_verify_data(
                        cipher,
                        &keys.server_handshake_traffic_secret,
                        &transcript.current_hash(),
                    );
                    if msg_body.ct_eq(&expected_verify).unwrap_u8() != 1 {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "Server Finished verify_data mismatch",
                        ));
                    }
                    transcript.update(&full_msg);
                    server_finished_ok = true;
                }
                _ => {
                    transcript.update(&full_msg);
                }
            }
        }
    }

    let server_finished_hash = transcript.current_hash();
    let (c_ap_secret, s_ap_secret) = keys.compute_app_secrets(&server_finished_hash);

    let client_verify = compute_finished_verify_data(
        cipher,
        &keys.client_handshake_traffic_secret,
        &server_finished_hash,
    );
    let mut fin_msg = Vec::with_capacity(4 + client_verify.len());
    fin_msg.push(0x14);
    let vlen = client_verify.len();
    fin_msg.push(((vlen >> 16) & 0xff) as u8);
    fin_msg.push(((vlen >> 8) & 0xff) as u8);
    fin_msg.push((vlen & 0xff) as u8);
    fin_msg.extend_from_slice(&client_verify);

    let ccs_record: [u8; 6] = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
    let fin_record = c_hs_cipher.seal_record(0x16, &fin_msg)?;
    let mut flight = Vec::with_capacity(ccs_record.len() + fin_record.len());
    flight.extend_from_slice(&ccs_record);
    flight.extend_from_slice(&fin_record);
    inner.write_all(&flight).await?;
    inner.flush().await?;

    let write_cipher = TrafficCipher::from_traffic_secret(cipher, &c_ap_secret)?;
    let read_cipher = TrafficCipher::from_traffic_secret(cipher, &s_ap_secret)?;

    Ok(Box::new(RealityTlsStream::new(
        inner,
        read_cipher,
        write_cipher,
    )))
}

pub async fn reality_accept(
    mut inner: TcpStream,
    cfg: &RealityServerConfig,
) -> io::Result<Option<BoxStream>> {
    let mut hdr = [0u8; 5];
    if let Err(e) = inner.read_exact(&mut hdr).await {
        return Err(e);
    }
    let rec_len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
    if hdr[0] != 0x16 || rec_len > MAX_TLS_CIPHERTEXT_LEN || rec_len < 44 {
        let mut raw = hdr.to_vec();
        let mut rest = vec![0u8; rec_len.min(4096)];
        if let Ok(n) = inner.read(&mut rest).await {
            raw.extend_from_slice(&rest[..n]);
        }
        fallback_or_close(inner, raw, &cfg.dest).await;
        return Ok(None);
    }
    let mut hs_msg = vec![0u8; rec_len];
    if let Err(e) = inner.read_exact(&mut hs_msg).await {
        return Err(e);
    }
    let mut raw_record = Vec::with_capacity(5 + rec_len);
    raw_record.extend_from_slice(&hdr);
    raw_record.extend_from_slice(&hs_msg);

    let ch = match parse_client_hello(&hs_msg) {
        Ok(c) => c,
        Err(_) => {
            fallback_or_close(inner, raw_record, &cfg.dest).await;
            return Ok(None);
        }
    };

    if !cfg.server_names.is_empty()
        && !cfg
            .server_names
            .iter()
            .any(|s| s.eq_ignore_ascii_case(&ch.sni))
    {
        fallback_or_close(inner, raw_record, &cfg.dest).await;
        return Ok(None);
    }

    let srv_static = StaticSecret::from(cfg.private_key);
    let cli_pub = PublicKey::from(ch.x25519_pub);
    let shared = srv_static.diffie_hellman(&cli_pub);
    if shared.as_bytes().iter().all(|&b| b == 0) {
        fallback_or_close(inner, raw_record, &cfg.dest).await;
        return Ok(None);
    }

    let auth_key = match derive_reality_auth_key(shared.as_bytes(), &ch.client_random[..20]) {
        Ok(k) => k,
        Err(_) => {
            fallback_or_close(inner, raw_record, &cfg.dest).await;
            return Ok(None);
        }
    };

    let mut aad = hs_msg.clone();
    aad[ch.sid_offset..ch.sid_offset + 32].fill(0);
    let sid_plain = match decrypt_reality_session_id(
        &auth_key,
        &ch.client_random[20..32],
        &ch.session_id,
        &aad,
    ) {
        Ok(p) => p,
        Err(_) => {
            fallback_or_close(inner, raw_record, &cfg.dest).await;
            return Ok(None);
        }
    };

    if !validate_reality_sid(
        &sid_plain,
        &ch.session_id,
        &cfg.short_ids,
        cfg.max_time_diff_ms,
        &cfg.replay_cache,
    ) {
        fallback_or_close(inner, raw_record, &cfg.dest).await;
        return Ok(None);
    }

    let cipher = ch
        .cipher_suites
        .iter()
        .filter_map(|&id| Tls13Cipher::from_id(id))
        .next()
        .unwrap_or(Tls13Cipher::Aes128GcmSha256);

    let mut srv_eph_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut srv_eph_bytes);
    let srv_eph_secret = StaticSecret::from(srv_eph_bytes);
    let srv_eph_pub = PublicKey::from(&srv_eph_secret);
    let hs_shared = srv_eph_secret.diffie_hellman(&cli_pub);

    let mut server_random = [0u8; 32];
    rand::rng().fill_bytes(&mut server_random);

    let sh_msg = build_server_hello(
        &server_random,
        &ch.session_id,
        cipher.id(),
        srv_eph_pub.as_bytes(),
    );
    let mut transcript = Transcript::new();
    transcript.set_cipher(cipher);
    transcript.update(&hs_msg);
    transcript.update(&sh_msg);

    let hello_hash = transcript.current_hash();
    let keys = KeySchedule::compute(cipher, hs_shared.as_bytes(), &hello_hash);
    let mut s_hs_cipher =
        TrafficCipher::from_traffic_secret(cipher, &keys.server_handshake_traffic_secret)?;
    let mut c_hs_cipher =
        TrafficCipher::from_traffic_secret(cipher, &keys.client_handshake_traffic_secret)?;

    let mut sh_record = Vec::with_capacity(5 + sh_msg.len());
    sh_record.extend_from_slice(&[0x16, 0x03, 0x03]);
    sh_record.extend_from_slice(&(sh_msg.len() as u16).to_be_bytes());
    sh_record.extend_from_slice(&sh_msg);

    let ccs_record: [u8; 6] = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];

    let ee_msg = build_encrypted_extensions(&ch.alpn);
    transcript.update(&ee_msg);

    let mut ed_seed = [0u8; 32];
    rand::rng().fill_bytes(&mut ed_seed);
    let ed_signing = SigningKey::from_bytes(&ed_seed);
    let ed_pub = ed_signing.verifying_key().to_bytes();

    let mut mac = <HmacSha512 as Mac>::new_from_slice(&auth_key)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "HMAC key"))?;
    mac.update(&ed_pub);
    let hmac_bytes = mac.finalize().into_bytes();
    let mut hmac_sig = [0u8; 64];
    hmac_sig.copy_from_slice(&hmac_bytes);

    let mldsa_sig = if !cfg.mldsa65_seed.trim().is_empty() {
        let sig = crate::model::sign_mldsa65(&cfg.mldsa65_seed, &ed_pub)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        Some(sig)
    } else {
        None
    };

    let cert_der = build_reality_cert_der(&ed_pub, &hmac_sig, mldsa_sig.as_deref());
    let cert_msg = build_certificate_msg(&cert_der);
    transcript.update(&cert_msg);

    let cv_hash = transcript.current_hash();
    let cv_msg = build_certificate_verify_msg(&ed_signing, &cv_hash);
    transcript.update(&cv_msg);

    let fin_verify = compute_finished_verify_data(
        cipher,
        &keys.server_handshake_traffic_secret,
        &transcript.current_hash(),
    );
    let mut fin_msg = Vec::with_capacity(4 + fin_verify.len());
    fin_msg.push(0x14);
    let vlen = fin_verify.len();
    fin_msg.push(((vlen >> 16) & 0xff) as u8);
    fin_msg.push(((vlen >> 8) & 0xff) as u8);
    fin_msg.push((vlen & 0xff) as u8);
    fin_msg.extend_from_slice(&fin_verify);
    transcript.update(&fin_msg);

    let server_finished_hash = transcript.current_hash();
    let (c_ap_secret, s_ap_secret) = keys.compute_app_secrets(&server_finished_hash);

    let mut hs_plain =
        Vec::with_capacity(ee_msg.len() + cert_msg.len() + cv_msg.len() + fin_msg.len());
    hs_plain.extend_from_slice(&ee_msg);
    hs_plain.extend_from_slice(&cert_msg);
    hs_plain.extend_from_slice(&cv_msg);
    hs_plain.extend_from_slice(&fin_msg);
    let enc_hs_record = s_hs_cipher.seal_record(0x16, &hs_plain)?;

    let mut flight = Vec::with_capacity(sh_record.len() + ccs_record.len() + enc_hs_record.len());
    flight.extend_from_slice(&sh_record);
    flight.extend_from_slice(&ccs_record);
    flight.extend_from_slice(&enc_hs_record);
    inner.write_all(&flight).await?;
    inner.flush().await?;

    let expected_client_fin = compute_finished_verify_data(
        cipher,
        &keys.client_handshake_traffic_secret,
        &server_finished_hash,
    );

    loop {
        let (rhdr, rbody) = read_tls_record(&mut inner).await?;
        if rhdr[0] == 0x14 {
            continue;
        }
        if rhdr[0] != 0x17 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "expected encrypted client Finished",
            ));
        }
        let (ct, plain) = c_hs_cipher.open_record(&rhdr, &rbody)?;
        if ct != 0x16 || plain.len() < 4 || plain[0] != 0x14 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid client Finished message",
            ));
        }
        let flen = ((plain[1] as usize) << 16) | ((plain[2] as usize) << 8) | (plain[3] as usize);
        if plain.len() < 4 + flen {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated client Finished",
            ));
        }
        if plain[4..4 + flen].ct_eq(&expected_client_fin).unwrap_u8() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "client Finished mismatch",
            ));
        }
        break;
    }

    let write_cipher = TrafficCipher::from_traffic_secret(cipher, &s_ap_secret)?;
    let read_cipher = TrafficCipher::from_traffic_secret(cipher, &c_ap_secret)?;

    Ok(Some(Box::new(RealityTlsStream::new(
        inner,
        read_cipher,
        write_cipher,
    ))))
}

fn validate_reality_sid(
    sid_plain: &[u8; 16],
    encrypted_sid: &[u8; 32],
    short_ids: &[(Vec<u8>, usize)],
    max_time_diff_ms: u64,
    replay_cache: &RealityReplayCache,
) -> bool {
    let ts = u32::from_be_bytes([sid_plain[4], sid_plain[5], sid_plain[6], sid_plain[7]]) as i64;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let max_diff_sec = if max_time_diff_ms > 0 {
        (max_time_diff_ms / 1000).max(1) as i64
    } else {
        120
    };
    if (now - ts).abs() > max_diff_sec {
        return false;
    }
    let sid_bytes = &sid_plain[8..16];
    if !short_ids.is_empty() {
        let mut matched = false;
        for (allowed, n) in short_ids {
            let len = (*n).min(8).min(allowed.len());
            if sid_bytes[..len] == allowed[..len] && sid_bytes[len..].iter().all(|&b| b == 0) {
                matched = true;
                break;
            }
        }
        if !matched {
            return false;
        }
    }
    let ttl = Duration::from_secs((max_diff_sec as u64) * 2 + 30);
    replay_cache.check_and_insert(*encrypted_sid, ttl)
}

async fn fallback_or_close(mut client: TcpStream, initial_bytes: Vec<u8>, dest: &str) {
    let dest = dest.trim().to_string();
    if dest.is_empty() {
        let _ = client.shutdown().await;
        return;
    }
    tokio::spawn(async move {
        if let Ok(Ok(mut remote)) =
            tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&dest)).await
        {
            if remote.write_all(&initial_bytes).await.is_ok() {
                let _ = tokio::time::timeout(
                    Duration::from_secs(60),
                    tokio::io::copy_bidirectional(&mut client, &mut remote),
                )
                .await;
            }
        }
        let _ = client.shutdown().await;
    });
}

struct ParsedClientHello {
    client_random: [u8; 32],
    session_id: [u8; 32],
    sid_offset: usize,
    cipher_suites: Vec<u16>,
    sni: String,
    alpn: Vec<String>,
    x25519_pub: [u8; 32],
}

fn parse_client_hello(hs_msg: &[u8]) -> io::Result<ParsedClientHello> {
    if hs_msg.len() < 42 || hs_msg[0] != 0x01 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not ClientHello"));
    }
    let body_len = ((hs_msg[1] as usize) << 16) | ((hs_msg[2] as usize) << 8) | (hs_msg[3] as usize);
    if hs_msg.len() < 4 + body_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated ClientHello",
        ));
    }
    let mut pos = 6usize; // skip msg_type(1) + len(3) + version(2)
    let mut client_random = [0u8; 32];
    client_random.copy_from_slice(&hs_msg[pos..pos + 32]);
    pos += 32;
    let sid_len = hs_msg[pos] as usize;
    pos += 1;
    if sid_len != 32 || pos + 32 > hs_msg.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ClientHello session_id not 32 bytes",
        ));
    }
    let sid_offset = pos;
    let mut session_id = [0u8; 32];
    session_id.copy_from_slice(&hs_msg[pos..pos + 32]);
    pos += 32;

    if pos + 2 > hs_msg.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "no cipher suites"));
    }
    let cs_len = u16::from_be_bytes([hs_msg[pos], hs_msg[pos + 1]]) as usize;
    pos += 2;
    if pos + cs_len > hs_msg.len() || cs_len % 2 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid cipher suites",
        ));
    }
    let mut cipher_suites = Vec::with_capacity(cs_len / 2);
    for chunk in hs_msg[pos..pos + cs_len].chunks_exact(2) {
        cipher_suites.push(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    pos += cs_len;

    if pos >= hs_msg.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "no compression"));
    }
    let comp_len = hs_msg[pos] as usize;
    pos += 1 + comp_len;
    if pos + 2 > hs_msg.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "no extensions"));
    }
    let exts_len = u16::from_be_bytes([hs_msg[pos], hs_msg[pos + 1]]) as usize;
    pos += 2;
    if pos + exts_len > hs_msg.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated extensions",
        ));
    }
    let exts_end = pos + exts_len;
    let mut sni = String::new();
    let mut alpn = Vec::new();
    let mut x25519_pub: Option<[u8; 32]> = None;

    while pos + 4 <= exts_end {
        let ext_type = u16::from_be_bytes([hs_msg[pos], hs_msg[pos + 1]]);
        let ext_len = u16::from_be_bytes([hs_msg[pos + 2], hs_msg[pos + 3]]) as usize;
        pos += 4;
        if pos + ext_len > exts_end {
            break;
        }
        let ext_data = &hs_msg[pos..pos + ext_len];
        pos += ext_len;

        match ext_type {
            0x0000 => {
                if ext_data.len() >= 5 && ext_data[2] == 0 {
                    let name_len = u16::from_be_bytes([ext_data[3], ext_data[4]]) as usize;
                    if 5 + name_len <= ext_data.len() {
                        if let Ok(s) = std::str::from_utf8(&ext_data[5..5 + name_len]) {
                            sni = s.to_string();
                        }
                    }
                }
            }
            0x0010 => {
                if ext_data.len() >= 2 {
                    let mut apos = 2usize;
                    while apos < ext_data.len() {
                        let plen = ext_data[apos] as usize;
                        apos += 1;
                        if apos + plen <= ext_data.len() {
                            if let Ok(p) = std::str::from_utf8(&ext_data[apos..apos + plen]) {
                                alpn.push(p.to_string());
                            }
                        }
                        apos += plen;
                    }
                }
            }
            0x0033 => {
                if ext_data.len() >= 2 {
                    let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                    let mut kpos = 2usize;
                    let kend = (2 + list_len).min(ext_data.len());
                    while kpos + 4 <= kend {
                        let group = u16::from_be_bytes([ext_data[kpos], ext_data[kpos + 1]]);
                        let klen =
                            u16::from_be_bytes([ext_data[kpos + 2], ext_data[kpos + 3]]) as usize;
                        kpos += 4;
                        if kpos + klen > kend {
                            break;
                        }
                        if group == 0x001d && klen == 32 {
                            let mut pk = [0u8; 32];
                            pk.copy_from_slice(&ext_data[kpos..kpos + 32]);
                            x25519_pub = Some(pk);
                        }
                        kpos += klen;
                    }
                }
            }
            _ => {}
        }
    }

    let x25519_pub = x25519_pub.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing X25519 key_share")
    })?;

    Ok(ParsedClientHello {
        client_random,
        session_id,
        sid_offset,
        cipher_suites,
        sni,
        alpn,
        x25519_pub,
    })
}

struct ParsedServerHello {
    cipher_suite: u16,
    key_share_group: u16,
    key_share_bytes: Vec<u8>,
}

fn parse_server_hello(record_body: &[u8]) -> io::Result<ParsedServerHello> {
    if record_body.len() < 42 || record_body[0] != 0x02 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a ServerHello message",
        ));
    }
    let hs_len =
        ((record_body[1] as usize) << 16) | ((record_body[2] as usize) << 8) | (record_body[3] as usize);
    if record_body.len() < 4 + hs_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ServerHello truncated",
        ));
    }
    let body = &record_body[4..4 + hs_len];
    let mut pos = 34usize;
    if pos >= body.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "short ServerHello"));
    }
    let sid_len = body[pos] as usize;
    pos += 1 + sid_len;
    if pos + 3 > body.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ServerHello missing cipher",
        ));
    }
    let cipher_suite = u16::from_be_bytes([body[pos], body[pos + 1]]);
    pos += 3;
    if pos + 2 > body.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ServerHello missing extensions",
        ));
    }
    let exts_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    if pos + exts_len > body.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ServerHello extensions truncated",
        ));
    }
    let exts_end = pos + exts_len;
    let mut selected_version = 0u16;
    let mut key_share_group = 0u16;
    let mut key_share_bytes = Vec::new();
    while pos + 4 <= exts_end {
        let ext_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let ext_len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        pos += 4;
        if pos + ext_len > exts_end {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ServerHello ext truncated",
            ));
        }
        let ext_body = &body[pos..pos + ext_len];
        pos += ext_len;
        match ext_type {
            0x002b if ext_body.len() == 2 => {
                selected_version = u16::from_be_bytes([ext_body[0], ext_body[1]]);
            }
            0x0033 if ext_body.len() >= 4 => {
                key_share_group = u16::from_be_bytes([ext_body[0], ext_body[1]]);
                let klen = u16::from_be_bytes([ext_body[2], ext_body[3]]) as usize;
                if 4 + klen == ext_body.len() {
                    key_share_bytes = ext_body[4..4 + klen].to_vec();
                }
            }
            _ => {}
        }
    }
    if selected_version != 0x0304 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Server did not negotiate TLS 1.3",
        ));
    }
    Ok(ParsedServerHello {
        cipher_suite,
        key_share_group,
        key_share_bytes,
    })
}

fn build_server_hello(
    server_random: &[u8; 32],
    session_id: &[u8; 32],
    cipher_suite: u16,
    srv_x25519_pub: &[u8; 32],
) -> Vec<u8> {
    let mut body = Vec::with_capacity(96);
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(server_random);
    body.push(32);
    body.extend_from_slice(session_id);
    body.extend_from_slice(&cipher_suite.to_be_bytes());
    body.push(0x00); // compression

    let mut exts = Vec::with_capacity(48);
    // supported_versions (0x002b) -> 0x0304
    exts.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
    // key_share (0x0033) -> group 0x001d, len 32
    exts.extend_from_slice(&[0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20]);
    exts.extend_from_slice(srv_x25519_pub);

    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);

    let mut msg = Vec::with_capacity(4 + body.len());
    msg.push(0x02);
    let len = body.len();
    msg.push(((len >> 16) & 0xff) as u8);
    msg.push(((len >> 8) & 0xff) as u8);
    msg.push((len & 0xff) as u8);
    msg.extend_from_slice(&body);
    msg
}

fn build_encrypted_extensions(client_alpn: &[String]) -> Vec<u8> {
    let selected = client_alpn
        .iter()
        .find(|a| a.as_str() == "h2" || a.as_str() == "http/1.1");
    let mut exts = Vec::new();
    if let Some(proto) = selected {
        let pb = proto.as_bytes();
        let list_len = 1 + pb.len();
        let ext_len = 2 + list_len;
        exts.extend_from_slice(&0x0010u16.to_be_bytes());
        exts.extend_from_slice(&(ext_len as u16).to_be_bytes());
        exts.extend_from_slice(&(list_len as u16).to_be_bytes());
        exts.push(pb.len() as u8);
        exts.extend_from_slice(pb);
    }
    let body_len = 2 + exts.len();
    let mut msg = Vec::with_capacity(4 + body_len);
    msg.push(0x08);
    msg.push(((body_len >> 16) & 0xff) as u8);
    msg.push(((body_len >> 8) & 0xff) as u8);
    msg.push((body_len & 0xff) as u8);
    msg.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    msg.extend_from_slice(&exts);
    msg
}

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + content.len());
    out.push(tag);
    let len = content.len();
    if len < 128 {
        out.push(len as u8);
    } else if len < 256 {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push(((len >> 8) & 0xff) as u8);
        out.push((len & 0xff) as u8);
    }
    out.extend_from_slice(content);
    out
}

fn build_reality_cert_der(
    ed_pub: &[u8; 32],
    hmac_sig: &[u8; 64],
    mldsa_sig: Option<&[u8]>,
) -> Vec<u8> {
    let mut tbs_items = Vec::new();
    // version v3: [0] EXPLICIT INTEGER 2
    tbs_items.extend_from_slice(&[0xa0, 0x03, 0x02, 0x01, 0x02]);
    // serialNumber: INTEGER 1
    tbs_items.extend_from_slice(&[0x02, 0x01, 0x01]);
    // signature: AlgorithmIdentifier Ed25519 (1.3.101.112)
    tbs_items.extend_from_slice(&[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70]);
    // issuer: SEQUENCE {}
    tbs_items.extend_from_slice(&[0x30, 0x00]);
    // validity: SEQUENCE { UTCTime, UTCTime }
    tbs_items.extend_from_slice(&[
        0x30, 0x1e, 0x17, 0x0d, b'2', b'4', b'0', b'1', b'0', b'1', b'0', b'0', b'0', b'0', b'0',
        b'0', b'Z', 0x17, 0x0d, b'3', b'4', b'0', b'1', b'0', b'1', b'0', b'0', b'0', b'0', b'0',
        b'0', b'Z',
    ]);
    // subject: SEQUENCE {}
    tbs_items.extend_from_slice(&[0x30, 0x00]);
    // subjectPublicKeyInfo: SEQUENCE { alg Ed25519, BIT STRING (0x00 + ed_pub) }
    tbs_items.extend_from_slice(&[
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ]);
    tbs_items.extend_from_slice(ed_pub);

    if let Some(msig) = mldsa_sig {
        let mut ext_entry = Vec::new();
        ext_entry.extend_from_slice(&OID_MLDSA65);
        ext_entry.extend_from_slice(&der_tlv(0x04, msig));
        let ext_seq = der_tlv(0x30, &ext_entry);
        let exts_seq = der_tlv(0x30, &ext_seq);
        let exts_explicit = der_tlv(0xa3, &exts_seq);
        tbs_items.extend_from_slice(&exts_explicit);
    }

    let tbs = der_tlv(0x30, &tbs_items);
    let mut cert_items = Vec::with_capacity(tbs.len() + 80);
    cert_items.extend_from_slice(&tbs);
    // signatureAlgorithm Ed25519
    cert_items.extend_from_slice(&[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70]);
    // signatureValue BIT STRING (0x00 + 64B hmac_sig)
    cert_items.extend_from_slice(&[0x03, 0x41, 0x00]);
    cert_items.extend_from_slice(hmac_sig);

    der_tlv(0x30, &cert_items)
}

fn build_certificate_msg(cert_der: &[u8]) -> Vec<u8> {
    // context(1B=0) + cert_list_len(3B) + [cert_len(3B) + cert_der + ext_len(2B=0)]
    let entry_len = 3 + cert_der.len() + 2;
    let body_len = 1 + 3 + entry_len;
    let mut msg = Vec::with_capacity(4 + body_len);
    msg.push(0x0b);
    msg.push(((body_len >> 16) & 0xff) as u8);
    msg.push(((body_len >> 8) & 0xff) as u8);
    msg.push((body_len & 0xff) as u8);
    msg.push(0x00); // context len 0
    msg.push(((entry_len >> 16) & 0xff) as u8);
    msg.push(((entry_len >> 8) & 0xff) as u8);
    msg.push((entry_len & 0xff) as u8);
    let clen = cert_der.len();
    msg.push(((clen >> 16) & 0xff) as u8);
    msg.push(((clen >> 8) & 0xff) as u8);
    msg.push((clen & 0xff) as u8);
    msg.extend_from_slice(cert_der);
    msg.extend_from_slice(&[0x00, 0x00]); // extensions len 0
    msg
}

fn build_certificate_verify_msg(ed_signing: &SigningKey, transcript_hash: &[u8]) -> Vec<u8> {
    let mut verify_input = Vec::with_capacity(64 + 33 + 1 + transcript_hash.len());
    verify_input.extend_from_slice(&[0x20u8; 64]);
    verify_input.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    verify_input.push(0x00);
    verify_input.extend_from_slice(transcript_hash);
    let sig = ed_signing.sign(&verify_input).to_bytes();

    let body_len = 4 + sig.len();
    let mut msg = Vec::with_capacity(4 + body_len);
    msg.push(0x0f);
    msg.push(((body_len >> 16) & 0xff) as u8);
    msg.push(((body_len >> 8) & 0xff) as u8);
    msg.push((body_len & 0xff) as u8);
    msg.extend_from_slice(&0x0807u16.to_be_bytes());
    msg.extend_from_slice(&(sig.len() as u16).to_be_bytes());
    msg.extend_from_slice(&sig);
    msg
}

fn verify_reality_certificate(
    cert_msg_body: &[u8],
    auth_key: &[u8; 32],
    mldsa65_verify: &str,
) -> io::Result<[u8; 32]> {
    if cert_msg_body.len() < 4 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Cert msg short"));
    }
    let ctx_len = cert_msg_body[0] as usize;
    if cert_msg_body.len() < 1 + ctx_len + 3 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Cert list short"));
    }
    let pos = 1 + ctx_len + 3;
    if cert_msg_body.len() < pos + 3 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "No cert entry"));
    }
    let cert_len = ((cert_msg_body[pos] as usize) << 16)
        | ((cert_msg_body[pos + 1] as usize) << 8)
        | (cert_msg_body[pos + 2] as usize);
    if cert_msg_body.len() < pos + 3 + cert_len {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Cert truncated"));
    }
    let cert_der = &cert_msg_body[pos + 3..pos + 3 + cert_len];

    let spki_prefix: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    let pub_pos = cert_der
        .windows(spki_prefix.len())
        .position(|w| w == spki_prefix)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "REALITY cert not Ed25519",
            )
        })?;
    let key_start = pub_pos + spki_prefix.len();
    if cert_der.len() < key_start + 32 || cert_der.len() < 67 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Cert key short"));
    }
    let mut ed_pub = [0u8; 32];
    ed_pub.copy_from_slice(&cert_der[key_start..key_start + 32]);

    let sig_hdr_pos = cert_der.len() - 67;
    if cert_der[sig_hdr_pos..sig_hdr_pos + 3] != [0x03, 0x41, 0x00] {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "REALITY cert signature BIT STRING mismatch",
        ));
    }
    let cert_sig = &cert_der[sig_hdr_pos + 3..];

    let mut mac = <HmacSha512 as Mac>::new_from_slice(auth_key)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "HMAC key"))?;
    mac.update(&ed_pub);
    let expected_sig = mac.finalize().into_bytes();

    if cert_sig.ct_eq(expected_sig.as_slice()).unwrap_u8() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "REALITY certificate HMAC-SHA512 mismatch",
        ));
    }

    if !mldsa65_verify.trim().is_empty() {
        let mldsa_sig = extract_mldsa_ext_from_cert(cert_der).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "REALITY certificate missing ML-DSA-65 extension",
            )
        })?;
        if !crate::model::verify_mldsa65(mldsa65_verify, &ed_pub, mldsa_sig) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "REALITY certificate ML-DSA-65 signature invalid",
            ));
        }
    }

    Ok(ed_pub)
}

fn extract_mldsa_ext_from_cert(cert_der: &[u8]) -> Option<&[u8]> {
    let oid_pos = cert_der
        .windows(OID_MLDSA65.len())
        .position(|w| w == OID_MLDSA65)?;
    let mut pos = oid_pos + OID_MLDSA65.len();
    if pos >= cert_der.len() || cert_der[pos] != 0x04 {
        return None;
    }
    pos += 1;
    if pos >= cert_der.len() {
        return None;
    }
    let len_byte = cert_der[pos];
    pos += 1;
    let len = if len_byte < 128 {
        len_byte as usize
    } else if len_byte == 0x81 {
        if pos >= cert_der.len() {
            return None;
        }
        let l = cert_der[pos] as usize;
        pos += 1;
        l
    } else if len_byte == 0x82 {
        if pos + 2 > cert_der.len() {
            return None;
        }
        let l = ((cert_der[pos] as usize) << 8) | (cert_der[pos + 1] as usize);
        pos += 2;
        l
    } else {
        return None;
    };
    if pos + len > cert_der.len() {
        return None;
    }
    Some(&cert_der[pos..pos + len])
}

fn verify_server_cert_verify(
    cv_body: &[u8],
    ed_pub: &[u8; 32],
    transcript_hash: &[u8],
) -> io::Result<()> {
    if cv_body.len() < 4 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "CV short"));
    }
    let sig_scheme = u16::from_be_bytes([cv_body[0], cv_body[1]]);
    let sig_len = u16::from_be_bytes([cv_body[2], cv_body[3]]) as usize;
    if sig_scheme != 0x0807 || sig_len != 64 || cv_body.len() < 4 + sig_len {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Invalid Ed25519 CertificateVerify",
        ));
    }
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&cv_body[4..68]);
    let signature = Signature::from_bytes(&sig_bytes);
    let vk = VerifyingKey::from_bytes(ed_pub)
        .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "invalid Ed25519 pubkey"))?;

    let mut verify_input = Vec::with_capacity(64 + 33 + 1 + transcript_hash.len());
    verify_input.extend_from_slice(&[0x20u8; 64]);
    verify_input.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    verify_input.push(0x00);
    verify_input.extend_from_slice(transcript_hash);

    vk.verify(&verify_input, &signature).map_err(|_| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Ed25519 CertificateVerify signature invalid",
        )
    })
}

pub struct RealityTlsStream<S> {
    inner: S,
    read_cipher: TrafficCipher,
    write_cipher: TrafficCipher,
    read_raw_buf: Vec<u8>,
    read_raw_pos: usize,
    read_plain_buf: Vec<u8>,
    read_plain_pos: usize,
    write_cipher_buf: Vec<u8>,
    write_cipher_pos: usize,
    pending_write_len: usize,
    eof: bool,
}

impl<S> RealityTlsStream<S> {
    fn new(inner: S, read_cipher: TrafficCipher, write_cipher: TrafficCipher) -> Self {
        Self {
            inner,
            read_cipher,
            write_cipher,
            read_raw_buf: Vec::with_capacity(65536),
            read_raw_pos: 0,
            read_plain_buf: Vec::with_capacity(32768),
            read_plain_pos: 0,
            write_cipher_buf: Vec::with_capacity(65536 + 128),
            write_cipher_pos: 0,
            pending_write_len: 0,
            eof: false,
        }
    }

    fn poll_flush_write_buf(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>
    where
        S: AsyncWrite + Unpin,
    {
        while self.write_cipher_pos < self.write_cipher_buf.len() {
            let remaining = &self.write_cipher_buf[self.write_cipher_pos..];
            match Pin::new(&mut self.inner).poll_write(cx, remaining) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "TLS write zero",
                    )))
                }
                Poll::Ready(Ok(n)) => {
                    self.write_cipher_pos += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.write_cipher_buf.clear();
        self.write_cipher_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for RealityTlsStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut produced = false;
        loop {
            if this.read_plain_pos < this.read_plain_buf.len() {
                let avail = &this.read_plain_buf[this.read_plain_pos..];
                let to_copy = avail.len().min(buf.remaining());
                buf.put_slice(&avail[..to_copy]);
                this.read_plain_pos += to_copy;
                if this.read_plain_pos >= this.read_plain_buf.len() {
                    this.read_plain_buf.clear();
                    this.read_plain_pos = 0;
                }
                produced = true;
                if buf.remaining() == 0 {
                    return Poll::Ready(Ok(()));
                }
            }
            if this.eof {
                return Poll::Ready(Ok(()));
            }

            let raw_avail = this.read_raw_buf.len() - this.read_raw_pos;
            if raw_avail >= 5 {
                let base = this.read_raw_pos;
                let rlen =
                    u16::from_be_bytes([this.read_raw_buf[base + 3], this.read_raw_buf[base + 4]])
                        as usize;
                if rlen > MAX_TLS_CIPHERTEXT_LEN {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "TLS record length overflow",
                    )));
                }
                if raw_avail >= 5 + rlen {
                    let mut header = [0u8; 5];
                    header.copy_from_slice(&this.read_raw_buf[base..base + 5]);
                    let rec_start = base + 5;
                    let rec_end = rec_start + rlen;
                    this.read_raw_pos = rec_end;
                    match header[0] {
                        0x14 => {
                            if this.read_raw_pos == this.read_raw_buf.len() {
                                this.read_raw_buf.clear();
                                this.read_raw_pos = 0;
                            }
                            continue;
                        }
                        0x17 => {
                            let (inner_ct, plain_len) = this.read_cipher.open_record_in_place(
                                &header,
                                &mut this.read_raw_buf[rec_start..rec_end],
                            )?;
                            match inner_ct {
                                0x17 => {
                                    if plain_len > 0 {
                                        let plain_slice =
                                            &this.read_raw_buf[rec_start..rec_start + plain_len];
                                        let direct = plain_slice.len().min(buf.remaining());
                                        if direct > 0 {
                                            buf.put_slice(&plain_slice[..direct]);
                                            produced = true;
                                        }
                                        if direct < plain_slice.len() {
                                            this.read_plain_buf.clear();
                                            this.read_plain_buf
                                                .extend_from_slice(&plain_slice[direct..]);
                                            this.read_plain_pos = 0;
                                        }
                                    }
                                    if this.read_raw_pos == this.read_raw_buf.len() {
                                        this.read_raw_buf.clear();
                                        this.read_raw_pos = 0;
                                        if this.read_raw_buf.capacity() > 256 * 1024 {
                                            this.read_raw_buf.shrink_to(65536);
                                        }
                                    }
                                    if buf.remaining() == 0
                                        || this.read_plain_pos < this.read_plain_buf.len()
                                    {
                                        return Poll::Ready(Ok(()));
                                    }
                                    continue;
                                }
                                0x15 => {
                                    let plain =
                                        &this.read_raw_buf[rec_start..rec_start + plain_len];
                                    if plain.len() >= 2 && plain[1] == 0 {
                                        this.eof = true;
                                        return Poll::Ready(Ok(()));
                                    }
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::ConnectionReset,
                                        "TLS fatal alert",
                                    )));
                                }
                                0x16 => {
                                    if this.read_raw_pos == this.read_raw_buf.len() {
                                        this.read_raw_buf.clear();
                                        this.read_raw_pos = 0;
                                    }
                                    continue;
                                }
                                _ => {
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        "Unexpected TLS inner content type",
                                    )));
                                }
                            }
                        }
                        0x15 => {
                            this.eof = true;
                            return Poll::Ready(Ok(()));
                        }
                        _ => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "Unexpected outer TLS record",
                            )));
                        }
                    }
                }
            }

            if produced {
                return Poll::Ready(Ok(()));
            }

            if this.read_raw_pos > 0 {
                this.read_raw_buf.copy_within(this.read_raw_pos.., 0);
                let rem = this.read_raw_buf.len() - this.read_raw_pos;
                this.read_raw_buf.truncate(rem);
                this.read_raw_pos = 0;
                if this.read_raw_buf.capacity() > 256 * 1024 && rem < 16384 {
                    this.read_raw_buf.shrink_to(65536);
                }
            }

            let mut tmp = [0u8; 32768];
            let mut rbuf = ReadBuf::new(&mut tmp);
            match Pin::new(&mut this.inner).poll_read(cx, &mut rbuf) {
                Poll::Ready(Ok(())) => {
                    let filled = rbuf.filled();
                    if filled.is_empty() {
                        this.eof = true;
                        if this.read_raw_pos == this.read_raw_buf.len() {
                            return Poll::Ready(Ok(()));
                        }
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "TLS record truncated on EOF",
                        )));
                    }
                    this.read_raw_buf.extend_from_slice(filled);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for RealityTlsStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.write_cipher_pos < this.write_cipher_buf.len() {
            match this.poll_flush_write_buf(cx) {
                Poll::Ready(Ok(())) => {
                    if this.pending_write_len > 0 {
                        let written = std::mem::replace(&mut this.pending_write_len, 0);
                        return Poll::Ready(Ok(written));
                    }
                }
                Poll::Ready(Err(e)) => {
                    this.pending_write_len = 0;
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let batch_len = buf.len().min(65536);
        this.write_cipher_buf.clear();
        this.write_cipher_pos = 0;
        this.pending_write_len = batch_len;
        for chunk in buf[..batch_len].chunks(16384) {
            if let Err(e) = this
                .write_cipher
                .seal_record_into(&mut this.write_cipher_buf, 0x17, chunk)
            {
                this.pending_write_len = 0;
                return Poll::Ready(Err(e));
            }
        }
        match this.poll_flush_write_buf(cx) {
            Poll::Ready(Ok(())) => {
                let written = std::mem::replace(&mut this.pending_write_len, 0);
                Poll::Ready(Ok(written))
            }
            Poll::Ready(Err(e)) => {
                this.pending_write_len = 0;
                Poll::Ready(Err(e))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Poll::Pending = this.poll_flush_write_buf(cx) {
            return Poll::Pending;
        }
        this.pending_write_len = 0;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.write_cipher_buf.is_empty() {
            if let Ok(alert_rec) = this.write_cipher.seal_record(0x15, &[0x01, 0x00]) {
                this.write_cipher_buf = alert_rec;
                this.write_cipher_pos = 0;
            }
        }
        if let Poll::Pending = this.poll_flush_write_buf(cx) {
            return Poll::Pending;
        }
        this.pending_write_len = 0;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_cache_rejects_duplicates_and_evicts_fifo_at_capacity() {
        let cache = RealityReplayCache::new();
        let mut first = [0u8; 32];
        first[0] = 1;
        assert!(cache.check_and_insert(first, Duration::from_secs(60)));
        assert!(!cache.check_and_insert(first, Duration::from_secs(60)));

        for i in 1..16384u32 {
            let mut sid = [0u8; 32];
            sid[..4].copy_from_slice(&i.to_be_bytes());
            assert!(cache.check_and_insert(sid, Duration::from_secs(60)));
        }
        // Capacity (16384) reached; inserting one more evicts `first` in O(1)
        let mut extra = [0xffu8; 32];
        extra[0] = 0xfe;
        assert!(cache.check_and_insert(extra, Duration::from_secs(60)));
        assert!(cache.check_and_insert(first, Duration::from_secs(60)));
    }
}
