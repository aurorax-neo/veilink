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
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{EncapsulationKey, MlKem768};
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
/// Xray-core REALITY certificate ML-DSA-65 extension OID `{0, 0}` (`06 01 00`).
const OID_MLDSA65_REALITY: [u8; 3] = [0x06, 0x01, 0x00];
const OID_MLDSA65_LEGACY: [u8; 11] =
    [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12];

#[derive(Clone, Debug)]
pub struct RealityClientConfig {
    pub server_name: String,
    pub public_key: [u8; 32],
    pub short_id: Vec<u8>,
    pub fingerprint: String,
    pub alpn: Vec<String>,
    pub mldsa65_verify: String,
    pub spider_x: String,
    pub spider_y: Vec<u64>,
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
        self.seal_record_padded_into(out, inner_content_type, plaintext, 0)
    }

    fn seal_record_padded_into(
        &mut self,
        out: &mut Vec<u8>,
        inner_content_type: u8,
        plaintext: &[u8],
        zero_pad_len: usize,
    ) -> io::Result<()> {
        let encrypted_len = plaintext
            .len()
            .saturating_add(1)
            .saturating_add(zero_pad_len)
            .saturating_add(16);
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
        if zero_pad_len > 0 {
            out.resize(out.len() + zero_pad_len, 0);
        }
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

pub async fn reality_connect<S>(inner: S, cfg: &RealityClientConfig) -> io::Result<BoxStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    Ok(Box::new(reality_connect_stream(inner, cfg).await?))
}

pub async fn reality_connect_stream<S>(
    mut inner: S,
    cfg: &RealityClientConfig,
) -> io::Result<RealityTlsStream<S>>
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
    // Xray-core protocol version marker [26, 11, 9, 0]
    sid_plain[0] = 26;
    sid_plain[1] = 11;
    sid_plain[2] = 9;
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

    let hs_shared_bytes: Vec<u8> = match sh.key_share_group {
        0x11ec if sh.key_share_bytes.len() == 1120 => {
            let Some(ref mlkem_dk) = hello.mlkem_dk else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Server selected X25519MLKEM768 without client PQ share",
                ));
            };
            let mlkem_ss = mlkem_dk
                .decapsulate_slice(&sh.key_share_bytes[..1088])
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "X25519MLKEM768 decapsulation failed",
                    )
                })?;
            let mut srv_pub_arr = [0u8; 32];
            srv_pub_arr.copy_from_slice(&sh.key_share_bytes[1088..1120]);
            let x_ss = eph_secret.diffie_hellman(&PublicKey::from(srv_pub_arr));
            if x_ss.as_bytes().iter().all(|&b| b == 0) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "X25519MLKEM768 low-order point",
                ));
            }
            let mut combined = Vec::with_capacity(64);
            combined.extend_from_slice(mlkem_ss.as_slice());
            combined.extend_from_slice(x_ss.as_bytes());
            combined
        }
        0x001d if sh.key_share_bytes.len() == 32 => {
            let mut srv_pub_arr = [0u8; 32];
            srv_pub_arr.copy_from_slice(&sh.key_share_bytes);
            let x_ss = eph_secret.diffie_hellman(&PublicKey::from(srv_pub_arr));
            if x_ss.as_bytes().iter().all(|&b| b == 0) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "X25519 low-order point",
                ));
            }
            x_ss.as_bytes().to_vec()
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported server key_share group",
            ));
        }
    };

    let hello_hash = transcript.current_hash();
    let keys = KeySchedule::compute(cipher, &hs_shared_bytes, &hello_hash);
    let mut s_hs_cipher =
        TrafficCipher::from_traffic_secret(cipher, &keys.server_handshake_traffic_secret)?;
    let mut c_hs_cipher =
        TrafficCipher::from_traffic_secret(cipher, &keys.client_handshake_traffic_secret)?;

    let mut hs_buf: Vec<u8> = Vec::new();
    let mut verified_ed25519_pub: Option<[u8; 32]> = None;
    let mut fallback_cert_chain: Vec<Vec<u8>> = Vec::new();
    let mut reality_auth_err: Option<io::Error> = None;
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
                    match verify_reality_certificate(
                        msg_body,
                        &auth_key,
                        &cfg.mldsa65_verify,
                        &hello.record[5..],
                        &sh_body,
                    ) {
                        Ok(ed_pub) => {
                            verified_ed25519_pub = Some(ed_pub);
                        }
                        Err(err) => {
                            if !cfg.spider_x.trim().is_empty() {
                                fallback_cert_chain = extract_cert_chain_ders(msg_body);
                            }
                            if fallback_cert_chain.is_empty() {
                                return Err(err);
                            }
                            reality_auth_err = Some(err);
                        }
                    }
                    transcript.update(&full_msg);
                }
                0x0f => {
                    if let Some(ed_pub) = verified_ed25519_pub {
                        let th = transcript.current_hash();
                        verify_server_cert_verify(msg_body, &ed_pub, &th)?;
                        cert_signature_verified = true;
                    } else if reality_auth_err.is_some() {
                        cert_signature_verified = true;
                    } else {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "CertificateVerify before Certificate",
                        ));
                    }
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

    let mut tls_stream = RealityTlsStream::new(inner, read_cipher, write_cipher);

    if let Some(auth_err) = reality_auth_err {
        // Fallback server presented a non-REALITY X.509 certificate: perform SpiderX/SpiderY
        // HTTP camouflage crawl before closing cleanly, matching Xray REALITY client behavior.
        let _ = tokio::time::timeout(
            Duration::from_secs(3),
            run_spider_camouflage(&mut tls_stream, cfg, &fallback_cert_chain),
        )
        .await;
        let _ = tls_stream.shutdown().await;
        return Err(auth_err);
    }

    Ok(tls_stream)
}

async fn run_spider_camouflage<S: AsyncRead + AsyncWrite + Unpin>(
    tls_stream: &mut RealityTlsStream<S>,
    cfg: &RealityClientConfig,
    cert_chain: &[Vec<u8>],
) -> io::Result<()> {
    if cert_chain.is_empty() {
        return Ok(());
    }
    let path = if cfg.spider_x.trim().starts_with('/') {
        cfg.spider_x.trim()
    } else {
        "/"
    };
    let host = if cfg.server_name.trim().is_empty() {
        "localhost"
    } else {
        cfg.server_name.trim()
    };
    if let Some(&initial_ms) = cfg.spider_y.first() {
        if initial_ms > 0 {
            tokio::time::sleep(Duration::from_millis(initial_ms.min(1000))).await;
        }
    }
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nConnection: close\r\n\r\n",
        path,
        host,
        super::xhttp::DEFAULT_USER_AGENT
    );
    tls_stream.write_all(req.as_bytes()).await?;
    tls_stream.flush().await?;
    let mut buf = [0u8; 4096];
    let mut total = 0usize;
    while total < 32768 {
        let n = tls_stream.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        total += n;
    }
    if let Some(&after_ms) = cfg.spider_y.get(1) {
        if after_ms > 0 {
            tokio::time::sleep(Duration::from_millis(after_ms.min(1000))).await;
        }
    }
    Ok(())
}

pub async fn reality_accept(
    inner: TcpStream,
    cfg: &RealityServerConfig,
) -> io::Result<Option<BoxStream>> {
    Ok(reality_accept_stream(inner, cfg)
        .await?
        .map(|s| Box::new(s) as BoxStream))
}

pub async fn reality_accept_stream(
    mut inner: TcpStream,
    cfg: &RealityServerConfig,
) -> io::Result<Option<RealityTlsStream<TcpStream>>> {
    let dest_trimmed = cfg.dest.trim().to_string();
    let connect_dest = async {
        if dest_trimmed.is_empty() {
            return None;
        }
        match tokio::time::timeout(
            Duration::from_millis(2500),
            TcpStream::connect(&dest_trimmed),
        )
        .await
        {
            Ok(Ok(s)) => {
                let _ = s.set_nodelay(true);
                Some(s)
            }
            _ => None,
        }
    };
    let read_initial = async {
        let mut hdr = [0u8; 5];
        inner.read_exact(&mut hdr).await?;
        let rec_len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
        if hdr[0] != 0x16 || rec_len > MAX_TLS_CIPHERTEXT_LEN || rec_len < 44 {
            let mut raw = hdr.to_vec();
            let mut rest = vec![0u8; rec_len.min(4096)];
            if let Ok(n) = inner.read(&mut rest).await {
                raw.extend_from_slice(&rest[..n]);
            }
            return Ok::<Result<Vec<u8>, Vec<u8>>, io::Error>(Err(raw));
        }
        let mut hs_msg = vec![0u8; rec_len];
        inner.read_exact(&mut hs_msg).await?;
        let mut raw_record = Vec::with_capacity(5 + rec_len);
        raw_record.extend_from_slice(&hdr);
        raw_record.extend_from_slice(&hs_msg);
        Ok(Ok(raw_record))
    };

    let (initial_res, dest_conn) = tokio::join!(read_initial, connect_dest);
    let raw_record = match initial_res? {
        Ok(rec) => rec,
        Err(raw) => {
            fallback_with_conn(inner, dest_conn, raw, &dest_trimmed).await;
            return Ok(None);
        }
    };
    let hs_msg = raw_record[5..].to_vec();

    let ch = match parse_client_hello(&hs_msg) {
        Ok(c) => c,
        Err(_) => {
            fallback_with_conn(inner, dest_conn, raw_record, &dest_trimmed).await;
            return Ok(None);
        }
    };

    if !cfg.server_names.is_empty()
        && !cfg
            .server_names
            .iter()
            .any(|s| s.eq_ignore_ascii_case(&ch.sni))
    {
        fallback_with_conn(inner, dest_conn, raw_record, &dest_trimmed).await;
        return Ok(None);
    }

    let srv_static = StaticSecret::from(cfg.private_key);
    let cli_pub = PublicKey::from(ch.x25519_pub);
    let shared = srv_static.diffie_hellman(&cli_pub);
    if shared.as_bytes().iter().all(|&b| b == 0) {
        fallback_with_conn(inner, dest_conn, raw_record, &dest_trimmed).await;
        return Ok(None);
    }

    let auth_key = match derive_reality_auth_key(shared.as_bytes(), &ch.client_random[..20]) {
        Ok(k) => k,
        Err(_) => {
            fallback_with_conn(inner, dest_conn, raw_record, &dest_trimmed).await;
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
            fallback_with_conn(inner, dest_conn, raw_record, &dest_trimmed).await;
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
        fallback_with_conn(inner, dest_conn, raw_record, &dest_trimmed).await;
        return Ok(None);
    }

    let mirrored = mirror_dest_server_flight(dest_conn, &raw_record, &ch.cipher_suites).await;

    let cipher = mirrored
        .as_ref()
        .map(|m| m.cipher)
        .or_else(|| {
            ch.cipher_suites
                .iter()
                .filter_map(|&id| Tls13Cipher::from_id(id))
                .next()
        })
        .unwrap_or(Tls13Cipher::Aes128GcmSha256);

    let mut srv_eph_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut srv_eph_bytes);
    let srv_eph_secret = StaticSecret::from(srv_eph_bytes);
    let srv_eph_pub = PublicKey::from(&srv_eph_secret);

    let want_pq = match mirrored.as_ref().map(|m| m.selected_group) {
        Some(0x11ec) => ch.mlkem768_share.is_some(),
        Some(0x001d) => false,
        _ => ch.mlkem768_share.is_some(),
    };

    let (selected_group, srv_ks_bytes, hs_shared_bytes) = if want_pq {
        let (ref ek_bytes, ref pq_x_pub) = ch.mlkem768_share.unwrap();
        let ek = EncapsulationKey::<MlKem768>::new(ek_bytes.into()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid client ML-KEM-768 encapsulation key",
            )
        })?;
        let (ct, mlkem_ss) = ek.encapsulate();
        let x_ss = srv_eph_secret.diffie_hellman(&PublicKey::from(*pq_x_pub));
        if x_ss.as_bytes().iter().all(|&b| b == 0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "REALITY handshake X25519 low-order point",
            ));
        }
        let mut ks = Vec::with_capacity(1120);
        ks.extend_from_slice(ct.as_slice());
        ks.extend_from_slice(srv_eph_pub.as_bytes());
        let mut ss = Vec::with_capacity(64);
        ss.extend_from_slice(mlkem_ss.as_slice());
        ss.extend_from_slice(x_ss.as_bytes());
        (0x11ecu16, ks, ss)
    } else {
        let hs_shared = srv_eph_secret.diffie_hellman(&cli_pub);
        if hs_shared.as_bytes().iter().all(|&b| b == 0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "REALITY handshake X25519 low-order point",
            ));
        }
        (
            0x001du16,
            srv_eph_pub.as_bytes().to_vec(),
            hs_shared.as_bytes().to_vec(),
        )
    };

    let mut server_random = [0u8; 32];
    rand::rng().fill_bytes(&mut server_random);

    let sh_ext_order = mirrored
        .as_ref()
        .map(|m| m.ext_order.as_slice())
        .unwrap_or(&[0x002b, 0x0033]);
    let sh_msg = build_server_hello_ordered_group(
        &server_random,
        &ch.session_id,
        cipher.id(),
        selected_group,
        &srv_ks_bytes,
        sh_ext_order,
    );
    let mut transcript = Transcript::new();
    transcript.set_cipher(cipher);
    transcript.update(&hs_msg);
    transcript.update(&sh_msg);

    let hello_hash = transcript.current_hash();
    let keys = KeySchedule::compute(cipher, &hs_shared_bytes, &hello_hash);
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
    let hmac_bytes = mac.clone().finalize().into_bytes();
    let mut hmac_sig = [0u8; 64];
    hmac_sig.copy_from_slice(&hmac_bytes);

    let mldsa_sig = if !cfg.mldsa65_seed.trim().is_empty() {
        mac.update(&hs_msg);
        mac.update(&sh_msg);
        let transcript_mac = mac.finalize().into_bytes();
        let sig = crate::model::sign_mldsa65(&cfg.mldsa65_seed, transcript_mac.as_slice())
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

    let enc_hs_records = seal_mirrored_server_handshake(
        &mut s_hs_cipher,
        &hs_plain,
        mirrored.as_ref().map(|m| m.enc_record_lens.as_slice()),
    )?;

    let mut flight =
        Vec::with_capacity(sh_record.len() + ccs_record.len() + enc_hs_records.len());
    flight.extend_from_slice(&sh_record);
    flight.extend_from_slice(&ccs_record);
    flight.extend_from_slice(&enc_hs_records);
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

    let mut write_cipher = TrafficCipher::from_traffic_secret(cipher, &s_ap_secret)?;
    let read_cipher = TrafficCipher::from_traffic_secret(cipher, &c_ap_secret)?;

    if ch.psk_dhe_ke {
        let nst_msg = build_new_session_ticket_msg();
        if let Ok(nst_rec) = write_cipher.seal_record(0x16, &nst_msg) {
            let _ = inner.write_all(&nst_rec).await;
            let _ = inner.flush().await;
        }
    }

    Ok(Some(RealityTlsStream::new(
        inner,
        read_cipher,
        write_cipher,
    )))
}

fn build_new_session_ticket_msg() -> Vec<u8> {
    let mut rand_buf = [0u8; 64];
    rand::rng().fill_bytes(&mut rand_buf);
    let ticket_len = 32 + (rand_buf[0] as usize % 24);
    let body_len = 4 + 4 + 1 + 8 + 2 + ticket_len + 2;
    let mut msg = Vec::with_capacity(4 + body_len);
    msg.push(0x04); // NewSessionTicket
    msg.push(((body_len >> 16) & 0xff) as u8);
    msg.push(((body_len >> 8) & 0xff) as u8);
    msg.push((body_len & 0xff) as u8);
    msg.extend_from_slice(&7200u32.to_be_bytes()); // ticket_lifetime
    msg.extend_from_slice(&rand_buf[1..5]); // ticket_age_add
    msg.push(8); // ticket_nonce len
    msg.extend_from_slice(&rand_buf[5..13]);
    msg.extend_from_slice(&(ticket_len as u16).to_be_bytes());
    msg.extend_from_slice(&rand_buf[8..8 + ticket_len]);
    msg.extend_from_slice(&[0x00, 0x00]); // extensions len = 0
    msg
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
    if max_time_diff_ms > 0 {
        let max_diff_sec = (max_time_diff_ms / 1000).max(1) as i64;
        if (now - ts).abs() > max_diff_sec {
            return false;
        }
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
    let window_sec = if max_time_diff_ms > 0 {
        (max_time_diff_ms / 1000).max(1)
    } else {
        180
    };
    let ttl = Duration::from_secs(window_sec * 2 + 30);
    replay_cache.check_and_insert(*encrypted_sid, ttl)
}

async fn fallback_with_conn(
    mut client: TcpStream,
    preconnected: Option<TcpStream>,
    initial_bytes: Vec<u8>,
    dest: &str,
) {
    let dest = dest.trim().to_string();
    if dest.is_empty() && preconnected.is_none() {
        let _ = client.shutdown().await;
        return;
    }
    tokio::spawn(async move {
        let remote_opt = match preconnected {
            Some(s) => Some(s),
            None => match tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&dest))
                .await
            {
                Ok(Ok(s)) => {
                    let _ = s.set_nodelay(true);
                    Some(s)
                }
                _ => None,
            },
        };
        if let Some(mut remote) = remote_opt {
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

const TLS13_HRR_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

struct MirroredDestFlight {
    cipher: Tls13Cipher,
    selected_group: u16,
    ext_order: Vec<u16>,
    enc_record_lens: Vec<usize>,
}

async fn mirror_dest_server_flight(
    dest_conn: Option<TcpStream>,
    client_hello_record: &[u8],
    offered_ciphers: &[u16],
) -> Option<MirroredDestFlight> {
    let mut remote = dest_conn?;
    tokio::time::timeout(
        Duration::from_millis(1500),
        remote.write_all(client_hello_record),
    )
    .await
    .ok()?
    .ok()?;
    let _ = remote.flush().await;

    let (sh_hdr, sh_body) =
        tokio::time::timeout(Duration::from_millis(2000), read_tls_record(&mut remote))
            .await
            .ok()?
            .ok()?;
    if sh_hdr[0] != 0x16 {
        return None;
    }
    let (cipher_id, selected_group, ext_order) = parse_dest_server_hello(&sh_body)?;
    if !offered_ciphers.contains(&cipher_id) {
        return None;
    }
    let cipher = Tls13Cipher::from_id(cipher_id)?;

    let mut enc_record_lens = Vec::with_capacity(4);
    let mut total_ct = 0usize;
    while enc_record_lens.len() < 8 && total_ct < 32768 {
        let wait = if enc_record_lens.is_empty() {
            Duration::from_millis(1500)
        } else {
            Duration::from_millis(80)
        };
        let Ok(Ok((hdr, body))) = tokio::time::timeout(wait, read_tls_record(&mut remote)).await
        else {
            break;
        };
        match hdr[0] {
            0x14 => continue,
            0x17 => {
                if (18..=MAX_TLS_CIPHERTEXT_LEN).contains(&body.len()) {
                    total_ct += body.len();
                    enc_record_lens.push(body.len());
                } else {
                    break;
                }
            }
            _ => break,
        }
    }
    let _ = remote.shutdown().await;
    Some(MirroredDestFlight {
        cipher,
        selected_group,
        ext_order,
        enc_record_lens,
    })
}

fn parse_dest_server_hello(record_body: &[u8]) -> Option<(u16, u16, Vec<u16>)> {
    if record_body.len() < 42 || record_body[0] != 0x02 {
        return None;
    }
    let hs_len = ((record_body[1] as usize) << 16)
        | ((record_body[2] as usize) << 8)
        | (record_body[3] as usize);
    if record_body.len() < 4 + hs_len {
        return None;
    }
    let body = &record_body[4..4 + hs_len];
    if body.len() < 35 || body[2..34] == TLS13_HRR_RANDOM {
        return None;
    }
    let mut pos = 34usize;
    let sid_len = body[pos] as usize;
    pos += 1 + sid_len;
    if pos + 5 > body.len() {
        return None;
    }
    let cipher_suite = u16::from_be_bytes([body[pos], body[pos + 1]]);
    pos += 3;
    let exts_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    if pos + exts_len > body.len() {
        return None;
    }
    let exts_end = pos + exts_len;
    let mut selected_version = 0u16;
    let mut selected_group = 0u16;
    let mut ext_order = Vec::with_capacity(2);
    while pos + 4 <= exts_end {
        let ext_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let ext_len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        pos += 4;
        if pos + ext_len > exts_end {
            return None;
        }
        let ext_body = &body[pos..pos + ext_len];
        pos += ext_len;
        match ext_type {
            0x002b if ext_body.len() == 2 => {
                selected_version = u16::from_be_bytes([ext_body[0], ext_body[1]]);
                ext_order.push(0x002b);
            }
            0x0033 if ext_body.len() >= 4 => {
                let group = u16::from_be_bytes([ext_body[0], ext_body[1]]);
                if group == 0x001d || group == 0x11ec {
                    selected_group = group;
                }
                ext_order.push(0x0033);
            }
            _ => {}
        }
    }
    if selected_version != 0x0304 || selected_group == 0 {
        return None;
    }
    Some((cipher_suite, selected_group, ext_order))
}

fn seal_mirrored_server_handshake(
    cipher: &mut TrafficCipher,
    hs_plain: &[u8],
    mirrored_ct_lens: Option<&[usize]>,
) -> io::Result<Vec<u8>> {
    if let Some(lens) = mirrored_ct_lens {
        if !lens.is_empty()
            && lens.len() <= hs_plain.len()
            && lens.iter().all(|&l| (18..=MAX_TLS_CIPHERTEXT_LEN).contains(&l))
        {
            let caps: Vec<usize> = lens.iter().map(|&l| l - 17).collect();
            let cap_sum: usize = caps.iter().sum();
            if cap_sum >= hs_plain.len() {
                let mut out = Vec::with_capacity(lens.iter().map(|&l| 5 + l).sum());
                let mut offset = 0usize;
                for (i, &cap) in caps.iter().enumerate() {
                    let rem = hs_plain.len() - offset;
                    let records_after = caps.len() - 1 - i;
                    let take = if records_after == 0 {
                        rem
                    } else {
                        (rem - records_after).min(cap)
                    };
                    let zero_pad = cap - take;
                    cipher.seal_record_padded_into(
                        &mut out,
                        0x16,
                        &hs_plain[offset..offset + take],
                        zero_pad,
                    )?;
                    offset += take;
                }
                return Ok(out);
            }
        }
    }

    let mut pad_len = 0usize;
    let natural_ct = hs_plain.len() + 17;
    if natural_ct < 2048 {
        let mut rnd = [0u8; 2];
        rand::rng().fill_bytes(&mut rnd);
        let target_ct = 2176 + (u16::from_be_bytes(rnd) as usize % 512);
        pad_len = target_ct.saturating_sub(natural_ct);
    }
    let mut out = Vec::with_capacity(5 + natural_ct + pad_len);
    cipher.seal_record_padded_into(&mut out, 0x16, hs_plain, pad_len)?;
    Ok(out)
}

struct ParsedClientHello {
    client_random: [u8; 32],
    session_id: [u8; 32],
    sid_offset: usize,
    cipher_suites: Vec<u16>,
    sni: String,
    alpn: Vec<String>,
    x25519_pub: [u8; 32],
    mlkem768_share: Option<([u8; 1184], [u8; 32])>,
    psk_dhe_ke: bool,
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
    let mut pos = 6usize;
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
    let mut mlkem768_share: Option<([u8; 1184], [u8; 32])> = None;
    let mut psk_dhe_ke = false;

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
            0x002d => {
                if !ext_data.is_empty() {
                    let mlen = (ext_data[0] as usize).min(ext_data.len().saturating_sub(1));
                    if ext_data[1..1 + mlen].contains(&0x01) {
                        psk_dhe_ke = true;
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
                        } else if group == 0x11ec && klen == 1216 {
                            let mut ek = [0u8; 1184];
                            let mut pk = [0u8; 32];
                            ek.copy_from_slice(&ext_data[kpos..kpos + 1184]);
                            pk.copy_from_slice(&ext_data[kpos + 1184..kpos + 1216]);
                            mlkem768_share = Some((ek, pk));
                        }
                        kpos += klen;
                    }
                }
            }
            _ => {}
        }
    }

    let x25519_pub = x25519_pub
        .or_else(|| mlkem768_share.as_ref().map(|(_, pk)| *pk))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing X25519 key_share"))?;

    Ok(ParsedClientHello {
        client_random,
        session_id,
        sid_offset,
        cipher_suites,
        sni,
        alpn,
        x25519_pub,
        mlkem768_share,
        psk_dhe_ke,
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

#[cfg(test)]
fn build_server_hello_ordered(
    server_random: &[u8; 32],
    session_id: &[u8; 32],
    cipher_suite: u16,
    srv_x25519_pub: &[u8; 32],
    ext_order: &[u16],
) -> Vec<u8> {
    build_server_hello_ordered_group(
        server_random,
        session_id,
        cipher_suite,
        0x001d,
        srv_x25519_pub,
        ext_order,
    )
}

fn build_server_hello_ordered_group(
    server_random: &[u8; 32],
    session_id: &[u8; 32],
    cipher_suite: u16,
    group_id: u16,
    srv_key_share: &[u8],
    ext_order: &[u16],
) -> Vec<u8> {
    let mut body = Vec::with_capacity(96 + srv_key_share.len());
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(server_random);
    body.push(32);
    body.extend_from_slice(session_id);
    body.extend_from_slice(&cipher_suite.to_be_bytes());
    body.push(0x00);

    let ks_ext_len = (4 + srv_key_share.len()) as u16;
    let ks_len = srv_key_share.len() as u16;
    let mut exts = Vec::with_capacity(16 + srv_key_share.len());
    let mut wrote_vers = false;
    let mut wrote_ks = false;
    for &ext_id in ext_order {
        if ext_id == 0x002b && !wrote_vers {
            exts.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
            wrote_vers = true;
        } else if ext_id == 0x0033 && !wrote_ks {
            exts.extend_from_slice(&0x0033u16.to_be_bytes());
            exts.extend_from_slice(&ks_ext_len.to_be_bytes());
            exts.extend_from_slice(&group_id.to_be_bytes());
            exts.extend_from_slice(&ks_len.to_be_bytes());
            exts.extend_from_slice(srv_key_share);
            wrote_ks = true;
        }
    }
    if !wrote_vers {
        exts.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
    }
    if !wrote_ks {
        exts.extend_from_slice(&0x0033u16.to_be_bytes());
        exts.extend_from_slice(&ks_ext_len.to_be_bytes());
        exts.extend_from_slice(&group_id.to_be_bytes());
        exts.extend_from_slice(&ks_len.to_be_bytes());
        exts.extend_from_slice(srv_key_share);
    }

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

fn read_der_tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    if input.len() < 2 {
        return None;
    }
    let tag = input[0];
    let b1 = input[1];
    let (hdr_len, len) = if b1 < 128 {
        (2usize, b1 as usize)
    } else if b1 == 0x81 {
        if input.len() < 3 {
            return None;
        }
        (3usize, input[2] as usize)
    } else if b1 == 0x82 {
        if input.len() < 4 {
            return None;
        }
        (4usize, ((input[2] as usize) << 8) | (input[3] as usize))
    } else if b1 == 0x83 {
        if input.len() < 5 {
            return None;
        }
        (
            5usize,
            ((input[2] as usize) << 16) | ((input[3] as usize) << 8) | (input[4] as usize),
        )
    } else {
        return None;
    };
    if input.len() < hdr_len + len {
        return None;
    }
    Some((tag, &input[hdr_len..hdr_len + len], &input[hdr_len + len..]))
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
        ext_entry.extend_from_slice(&OID_MLDSA65_REALITY);
        ext_entry.extend_from_slice(&der_tlv(0x04, msig));
        let ext_seq = der_tlv(0x30, &ext_entry);
        let exts_seq = der_tlv(0x30, &ext_seq);
        let exts_explicit = der_tlv(0xa3, &exts_seq);
        tbs_items.extend_from_slice(&exts_explicit);
    }

    let tbs = der_tlv(0x30, &tbs_items);
    let mut cert_items = Vec::with_capacity(tbs.len() + 80);
    cert_items.extend_from_slice(&tbs);
    cert_items.extend_from_slice(&[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70]);
    cert_items.extend_from_slice(&[0x03, 0x41, 0x00]);
    cert_items.extend_from_slice(hmac_sig);

    der_tlv(0x30, &cert_items)
}

fn build_certificate_msg(cert_der: &[u8]) -> Vec<u8> {
    let entry_len = 3 + cert_der.len() + 2;
    let body_len = 1 + 3 + entry_len;
    let mut msg = Vec::with_capacity(4 + body_len);
    msg.push(0x0b);
    msg.push(((body_len >> 16) & 0xff) as u8);
    msg.push(((body_len >> 8) & 0xff) as u8);
    msg.push((body_len & 0xff) as u8);
    msg.push(0x00);
    msg.push(((entry_len >> 16) & 0xff) as u8);
    msg.push(((entry_len >> 8) & 0xff) as u8);
    msg.push((entry_len & 0xff) as u8);
    let clen = cert_der.len();
    msg.push(((clen >> 16) & 0xff) as u8);
    msg.push(((clen >> 8) & 0xff) as u8);
    msg.push((clen & 0xff) as u8);
    msg.extend_from_slice(cert_der);
    msg.extend_from_slice(&[0x00, 0x00]);
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

fn extract_cert_chain_ders(cert_msg_body: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    if cert_msg_body.len() < 4 {
        return out;
    }
    let ctx_len = cert_msg_body[0] as usize;
    if cert_msg_body.len() < 1 + ctx_len + 3 {
        return out;
    }
    let list_pos = 1 + ctx_len;
    let list_len = ((cert_msg_body[list_pos] as usize) << 16)
        | ((cert_msg_body[list_pos + 1] as usize) << 8)
        | (cert_msg_body[list_pos + 2] as usize);
    let mut pos = list_pos + 3;
    let end = (pos + list_len).min(cert_msg_body.len());
    while pos + 3 <= end {
        let clen = ((cert_msg_body[pos] as usize) << 16)
            | ((cert_msg_body[pos + 1] as usize) << 8)
            | (cert_msg_body[pos + 2] as usize);
        pos += 3;
        if pos + clen + 2 > end {
            break;
        }
        out.push(cert_msg_body[pos..pos + clen].to_vec());
        pos += clen;
        let elen = u16::from_be_bytes([cert_msg_body[pos], cert_msg_body[pos + 1]]) as usize;
        pos += 2 + elen;
    }
    out
}

fn verify_reality_certificate(
    cert_msg_body: &[u8],
    auth_key: &[u8; 32],
    mldsa65_verify: &str,
    client_hello_hs: &[u8],
    server_hello_hs: &[u8],
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
    let expected_sig = mac.clone().finalize().into_bytes();

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
        mac.update(client_hello_hs);
        mac.update(server_hello_hs);
        let transcript_mac = mac.finalize().into_bytes();
        if !crate::model::verify_mldsa65(mldsa65_verify, transcript_mac.as_slice(), mldsa_sig) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "REALITY certificate ML-DSA-65 signature invalid",
            ));
        }
    }

    Ok(ed_pub)
}

/// Parses X.509 `Certificate -> TBSCertificate -> [3] EXPLICIT (0xa3) -> Extensions[0].extnValue`
/// regardless of OID (supporting Xray `{0, 0}` `[0x06, 0x01, 0x00]` as well as NIST ML-DSA-65 OID).
fn extract_mldsa_ext_from_cert(cert_der: &[u8]) -> Option<&[u8]> {
    if let Some((0x30, cert_body, _)) = read_der_tlv(cert_der) {
        if let Some((0x30, mut tbs_rem, _)) = read_der_tlv(cert_body) {
            while !tbs_rem.is_empty() {
                let (tag, val, next) = read_der_tlv(tbs_rem)?;
                tbs_rem = next;
                if tag == 0xa3 {
                    let (0x30, exts_body, _) = read_der_tlv(val)? else {
                        return None;
                    };
                    let (0x30, mut ext0, _) = read_der_tlv(exts_body)? else {
                        return None;
                    };
                    // extnID OBJECT IDENTIFIER (0x06)
                    let (0x06, _oid, after_oid) = read_der_tlv(ext0)? else {
                        return None;
                    };
                    ext0 = after_oid;
                    // Optional critical BOOLEAN (0x01)
                    if ext0.first().copied() == Some(0x01) {
                        let (_, _, after_crit) = read_der_tlv(ext0)?;
                        ext0 = after_crit;
                    }
                    // extnValue OCTET STRING (0x04)
                    let (0x04, octets, _) = read_der_tlv(ext0)? else {
                        return None;
                    };
                    return Some(octets);
                }
            }
        }
    }

    // Fallback scan for legacy OID if non-standard wrapper
    let oid_pos = cert_der
        .windows(OID_MLDSA65_LEGACY.len())
        .position(|w| w == OID_MLDSA65_LEGACY)?;
    let (0x04, octets, _) = read_der_tlv(&cert_der[oid_pos + OID_MLDSA65_LEGACY.len()..])? else {
        return None;
    };
    Some(octets)
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
    write_raw_passthrough: bool,
    read_raw_passthrough: bool,
    sent_close_notify: bool,
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
            write_raw_passthrough: false,
            read_raw_passthrough: false,
            sent_close_notify: false,
            eof: false,
        }
    }

    pub fn enable_raw_write(&mut self) {
        self.write_raw_passthrough = true;
    }

    pub fn enable_raw_read(&mut self) {
        self.read_raw_passthrough = true;
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
                return Poll::Ready(Ok(()));
            }
            if this.read_raw_passthrough {
                if this.read_raw_pos < this.read_raw_buf.len() {
                    let avail = &this.read_raw_buf[this.read_raw_pos..];
                    let to_copy = avail.len().min(buf.remaining());
                    buf.put_slice(&avail[..to_copy]);
                    this.read_raw_pos += to_copy;
                    if this.read_raw_pos >= this.read_raw_buf.len() {
                        this.read_raw_buf.clear();
                        this.read_raw_pos = 0;
                    }
                    return Poll::Ready(Ok(()));
                }
                return Pin::new(&mut this.inner).poll_read(cx, buf);
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
                                    // Yield after each decrypted ApplicationData record so upper
                                    // layers (e.g. XTLS Vision 0x02) can switch to raw TCP before
                                    // subsequent unencrypted records in `read_raw_buf` are read.
                                    if produced {
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
        if this.write_raw_passthrough {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
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
        match this.poll_flush_write_buf(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => {
                this.pending_write_len = 0;
                return Poll::Ready(Err(e));
            }
            Poll::Pending => return Poll::Pending,
        }
        this.pending_write_len = 0;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.write_raw_passthrough && !this.sent_close_notify {
            match this.poll_flush_write_buf(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => {
                    this.pending_write_len = 0;
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => return Poll::Pending,
            }
            this.pending_write_len = 0;
            this.sent_close_notify = true;
            if let Ok(alert_rec) = this.write_cipher.seal_record(0x15, &[0x01, 0x00]) {
                this.write_cipher_buf = alert_rec;
                this.write_cipher_pos = 0;
            }
        }
        match this.poll_flush_write_buf(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => {
                this.pending_write_len = 0;
                return Poll::Ready(Err(e));
            }
            Poll::Pending => return Poll::Pending,
        }
        this.pending_write_len = 0;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::reality_hello::build_client_hello_with_options;

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
        let mut extra = [0xffu8; 32];
        extra[0] = 0xfe;
        assert!(cache.check_and_insert(extra, Duration::from_secs(60)));
        assert!(cache.check_and_insert(first, Duration::from_secs(60)));
    }

    #[test]
    fn validate_sid_zero_max_time_diff_disables_clock_skew_while_blocking_replay() {
        let cache = RealityReplayCache::new();
        let short_ids = vec![(vec![0x01, 0x02, 0x03, 0x04, 0, 0, 0, 0], 4usize)];
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;
        let skewed_ts = now.wrapping_sub(3600);
        let mut sid_plain = [0u8; 16];
        sid_plain[0..4].copy_from_slice(&[26, 11, 9, 0]);
        sid_plain[4..8].copy_from_slice(&skewed_ts.to_be_bytes());
        sid_plain[8..12].copy_from_slice(&[0x01, 0x02, 0x03, 0x04]);

        let enc_sid_1 = [0x11u8; 32];
        assert!(!validate_reality_sid(
            &sid_plain,
            &enc_sid_1,
            &short_ids,
            180_000,
            &cache
        ));
        assert!(validate_reality_sid(
            &sid_plain,
            &enc_sid_1,
            &short_ids,
            0,
            &cache
        ));
        assert!(!validate_reality_sid(
            &sid_plain,
            &enc_sid_1,
            &short_ids,
            0,
            &cache
        ));
    }

    #[test]
    fn chrome_client_hello_includes_pq_key_share_alpn_and_padding_rules() {
        let random = [0x42u8; 32];
        let sid = [0x24u8; 32];
        let x25519_pub = [0x33u8; 32];

        // 1. Default Chrome includes X25519MLKEM768 (0x11ec) 1216-byte hybrid PQ share
        let pq_hello = build_client_hello(
            FingerprintProfile::Chrome,
            "www.cloudflare.com",
            &random,
            &sid,
            &x25519_pub,
            &["h2", "http/1.1"],
        );
        let parsed_pq = parse_client_hello(&pq_hello.record[5..]).expect("valid PQ ClientHello");
        assert_eq!(
            parsed_pq.alpn,
            vec!["h2".to_string(), "http/1.1".to_string()]
        );
        assert!(
            parsed_pq.mlkem768_share.is_some(),
            "Chrome ClientHello must include X25519MLKEM768 (0x11ec) share"
        );
        assert!(parsed_pq.psk_dhe_ke);

        // 2. Classic (<512B) Chrome places 0x0015 padding immediately before trailing GREASE
        let classic_hello = build_client_hello_with_options(
            FingerprintProfile::Chrome,
            "www.cloudflare.com",
            &random,
            &sid,
            &x25519_pub,
            &["h2", "http/1.1"],
            false,
        );
        let hs = &classic_hello.record[5..];
        let mut pos = 6 + 32;
        let sid_len = hs[pos] as usize;
        pos += 1 + sid_len;
        let cs_len = u16::from_be_bytes([hs[pos], hs[pos + 1]]) as usize;
        pos += 2 + cs_len;
        let comp_len = hs[pos] as usize;
        pos += 1 + comp_len;
        let ext_total = u16::from_be_bytes([hs[pos], hs[pos + 1]]) as usize;
        pos += 2;
        let end = pos + ext_total;
        let mut ext_types = Vec::new();
        while pos + 4 <= end {
            let et = u16::from_be_bytes([hs[pos], hs[pos + 1]]);
            let el = u16::from_be_bytes([hs[pos + 2], hs[pos + 3]]) as usize;
            ext_types.push(et);
            pos += 4 + el;
        }
        assert_eq!(pos, end);
        assert!(ext_types.contains(&0x0010), "ALPN extension must be present");
        if let Some(pad_idx) = ext_types.iter().position(|&t| t == 0x0015) {
            assert_eq!(
                pad_idx + 2,
                ext_types.len(),
                "Chrome padding extension (0x0015) must immediately precede trailing GREASE"
            );
            let last_ext = *ext_types.last().unwrap();
            assert_eq!(last_ext & 0x0f0f, 0x0a0a, "final extension must be GREASE");
        } else {
            panic!("expected Chrome ClientHello < 512B body to include padding extension 0x0015");
        }
    }

    #[tokio::test]
    async fn reality_accept_mirrors_dest_server_hello_and_splices_unauthorized_probes() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::net::TcpListener;

        let dest_hits = Arc::new(AtomicUsize::new(0));
        let dest_hits_srv = dest_hits.clone();
        let dest_ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dest_addr = dest_ln.local_addr().unwrap();

        let dest_task = tokio::spawn(async move {
            while let Ok((mut s, _)) = dest_ln.accept().await {
                dest_hits_srv.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut hdr = [0u8; 5];
                    if s.read_exact(&mut hdr).await.is_err() {
                        return;
                    }
                    if hdr[0] != 0x16 {
                        let mut rest = [0u8; 256];
                        let _ = tokio::time::timeout(Duration::from_millis(50), s.read(&mut rest))
                            .await;
                        let _ = s.write_all(b"HTTP/1.1 200 OK\r\n\r\ncover-site").await;
                        let _ = s.shutdown().await;
                        return;
                    }
                    let rec_len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
                    let mut ch_hs = vec![0u8; rec_len];
                    if s.read_exact(&mut ch_hs).await.is_err() {
                        return;
                    }
                    let sid_len = ch_hs.get(38).copied().unwrap_or(0) as usize;
                    let mut sid = [0u8; 32];
                    if sid_len == 32 && ch_hs.len() >= 39 + 32 {
                        sid.copy_from_slice(&ch_hs[39..71]);
                    }
                    let sh = build_server_hello_ordered(
                        &[0x55u8; 32],
                        &sid,
                        0x1302,
                        &[0x77u8; 32],
                        &[0x0033, 0x002b],
                    );
                    let mut flight = Vec::new();
                    flight.extend_from_slice(&[0x16, 0x03, 0x03]);
                    flight.extend_from_slice(&(sh.len() as u16).to_be_bytes());
                    flight.extend_from_slice(&sh);
                    flight.extend_from_slice(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);
                    for rec_len in [48usize, 3210, 96] {
                        flight.extend_from_slice(&[0x17, 0x03, 0x03]);
                        flight.extend_from_slice(&(rec_len as u16).to_be_bytes());
                        flight.extend_from_slice(&vec![0xaa; rec_len]);
                    }
                    let _ = s.write_all(&flight).await;
                    let _ = s.flush().await;
                    let mut sink = [0u8; 64];
                    let _ = s.read(&mut sink).await;
                });
            }
        });

        let (mldsa_seed, mldsa_verify) = super::super::generate_mldsa65().unwrap();
        let srv_priv_bytes = [0x21u8; 32];
        let srv_static = StaticSecret::from(srv_priv_bytes);
        let srv_pub_bytes = *PublicKey::from(&srv_static).as_bytes();

        let srv_cfg = Arc::new(RealityServerConfig {
            private_key: srv_priv_bytes,
            short_ids: vec![(vec![0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0], 4)],
            server_names: vec!["www.microsoft.com".to_string()],
            dest: dest_addr.to_string(),
            max_time_diff_ms: 180_000,
            mldsa65_seed: mldsa_seed,
            replay_cache: Arc::new(RealityReplayCache::new()),
        });

        let srv_ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let srv_addr = srv_ln.local_addr().unwrap();
        let srv_cfg_loop = srv_cfg.clone();
        let srv_task = tokio::spawn(async move {
            while let Ok((tcp, _)) = srv_ln.accept().await {
                let c = srv_cfg_loop.clone();
                tokio::spawn(async move {
                    if let Ok(Some(mut tls)) = reality_accept(tcp, &c).await {
                        let mut buf = [0u8; 4];
                        if tls.read_exact(&mut buf).await.is_ok() && &buf == b"ping" {
                            let _ = tls.write_all(b"pong").await;
                            let _ = tls.flush().await;
                        }
                    }
                });
            }
        });

        let cli_cfg = RealityClientConfig {
            server_name: "www.microsoft.com".to_string(),
            public_key: srv_pub_bytes,
            short_id: vec![0xde, 0xad, 0xbe, 0xef],
            fingerprint: "chrome".to_string(),
            alpn: vec!["h2".to_string(), "http/1.1".to_string()],
            mldsa65_verify: mldsa_verify,
            spider_x: "/".to_string(),
            spider_y: vec![5, 10],
        };
        let tcp_auth = TcpStream::connect(srv_addr).await.unwrap();
        let mut tls_auth = reality_connect(tcp_auth, &cli_cfg).await.unwrap();
        assert_eq!(
            dest_hits.load(Ordering::SeqCst),
            1,
            "REALITY server must dial dest during authorized handshake mirroring"
        );
        tls_auth.write_all(b"ping").await.unwrap();
        tls_auth.flush().await.unwrap();
        let mut reply = [0u8; 4];
        tls_auth.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"pong");

        let mut tcp_probe = TcpStream::connect(srv_addr).await.unwrap();
        tcp_probe
            .write_all(b"GET / HTTP/1.1\r\nHost: www.microsoft.com\r\n\r\n")
            .await
            .unwrap();
        let mut probe_resp = Vec::new();
        tcp_probe.read_to_end(&mut probe_resp).await.unwrap();
        assert!(
            String::from_utf8_lossy(&probe_resp).contains("cover-site"),
            "unauthorized probe must transparently receive real dest response"
        );
        assert_eq!(dest_hits.load(Ordering::SeqCst), 2);

        srv_task.abort();
        dest_task.abort();
    }
}
