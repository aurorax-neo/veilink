use std::collections::{HashMap, HashSet};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use aes::Aes256;
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce, Tag};
use chacha20poly1305::ChaCha20Poly1305;
use ctr::cipher::{KeyIvInit, StreamCipher};
use ml_kem::kem::{Decapsulate, Encapsulate, Kem, KeyExport};
use ml_kem::{DecapsulationKey, EncapsulationKey, MlKem768};
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::task::AbortHandle;
use x25519_dalek::{PublicKey, StaticSecret};

use super::BoxStream;

pub type Aes256Ctr = ctr::Ctr128BE<Aes256>;

pub const X25519_LEN: usize = 32;
pub const MLKEM768_EK_LEN: usize = 1184;
pub const MLKEM768_CT_LEN: usize = 1088;
pub const TAG_LEN: usize = 16;

const MAX_NONCE: [u8; 12] = [0xFF; 12];
const WRITE_CHUNK: usize = 16384 - 5 - TAG_LEN;
const MAX_WRITE_BATCH: usize = 4 * WRITE_CHUNK;

fn derive_key(ctx: &[u8], key_material: &[u8]) -> [u8; 32] {
    use blake3::hazmat::HasherExt;
    let context_key = blake3_ctx::context_key(ctx);
    let mut hasher = blake3::Hasher::new_from_context_key(&context_key);
    hasher.update(key_material);
    *hasher.finalize().as_bytes()
}

mod blake3_ctx {
    const CHUNK_LEN: usize = 1024;
    const BLOCK_LEN: usize = 64;
    const IV: [u32; 8] = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB,
        0x5BE0CD19,
    ];
    const MSG_SCHEDULE: [[usize; 16]; 7] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
        [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
        [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
        [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
        [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
        [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
    ];
    const CHUNK_START: u8 = 1;
    const CHUNK_END: u8 = 1 << 1;
    const PARENT: u8 = 1 << 2;
    const ROOT: u8 = 1 << 3;
    const DERIVE_KEY_CONTEXT: u8 = 1 << 5;

    #[inline(always)]
    fn g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
        state[a] = state[a].wrapping_add(state[b]).wrapping_add(x);
        state[d] = (state[d] ^ state[a]).rotate_right(16);
        state[c] = state[c].wrapping_add(state[d]);
        state[b] = (state[b] ^ state[c]).rotate_right(12);
        state[a] = state[a].wrapping_add(state[b]).wrapping_add(y);
        state[d] = (state[d] ^ state[a]).rotate_right(8);
        state[c] = state[c].wrapping_add(state[d]);
        state[b] = (state[b] ^ state[c]).rotate_right(7);
    }

    fn round(state: &mut [u32; 16], msg: &[u32; 16], round: usize) {
        let schedule = MSG_SCHEDULE[round];
        g(state, 0, 4, 8, 12, msg[schedule[0]], msg[schedule[1]]);
        g(state, 1, 5, 9, 13, msg[schedule[2]], msg[schedule[3]]);
        g(state, 2, 6, 10, 14, msg[schedule[4]], msg[schedule[5]]);
        g(state, 3, 7, 11, 15, msg[schedule[6]], msg[schedule[7]]);
        g(state, 0, 5, 10, 15, msg[schedule[8]], msg[schedule[9]]);
        g(state, 1, 6, 11, 12, msg[schedule[10]], msg[schedule[11]]);
        g(state, 2, 7, 8, 13, msg[schedule[12]], msg[schedule[13]]);
        g(state, 3, 4, 9, 14, msg[schedule[14]], msg[schedule[15]]);
    }

    fn compress(
        cv: [u32; 8],
        block: &[u8; 64],
        counter: u64,
        block_len: u8,
        flags: u8,
    ) -> [u32; 8] {
        let mut words = [0u32; 16];
        for (w, b) in words.iter_mut().zip(block.chunks_exact(4)) {
            *w = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        }
        let mut state = [
            cv[0],
            cv[1],
            cv[2],
            cv[3],
            cv[4],
            cv[5],
            cv[6],
            cv[7],
            IV[0],
            IV[1],
            IV[2],
            IV[3],
            counter as u32,
            (counter >> 32) as u32,
            u32::from(block_len),
            u32::from(flags),
        ];
        for r in 0..7 {
            round(&mut state, &words, r);
        }
        let mut out = [0u32; 8];
        for i in 0..8 {
            out[i] = state[i] ^ state[i + 8];
        }
        out
    }

    struct Node {
        cv: [u32; 8],
        block: [u8; 64],
        block_len: u8,
        counter: u64,
        flags: u8,
    }

    impl Node {
        fn cv_bytes(&self) -> [u8; 32] {
            words_to_bytes(compress(
                self.cv,
                &self.block,
                self.counter,
                self.block_len,
                self.flags,
            ))
        }
        fn root_bytes(&self) -> [u8; 32] {
            words_to_bytes(compress(
                self.cv,
                &self.block,
                self.counter,
                self.block_len,
                self.flags | ROOT,
            ))
        }
    }

    fn words_to_bytes(w: [u32; 8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (b, word) in out.chunks_exact_mut(4).zip(w.iter()) {
            b.copy_from_slice(&word.to_le_bytes());
        }
        out
    }

    fn chunk_node(chunk: &[u8], counter: u64) -> Node {
        let mut cv = IV;
        let blocks = chunk.len().div_ceil(BLOCK_LEN).max(1);
        let buffered = blocks - 1;
        for i in 0..buffered {
            let mut block = [0u8; BLOCK_LEN];
            block.copy_from_slice(&chunk[i * BLOCK_LEN..(i + 1) * BLOCK_LEN]);
            let flags = DERIVE_KEY_CONTEXT | if i == 0 { CHUNK_START } else { 0 };
            cv = compress(cv, &block, counter, BLOCK_LEN as u8, flags);
        }
        let mut block = [0u8; BLOCK_LEN];
        let tail = &chunk[buffered * BLOCK_LEN..];
        block[..tail.len()].copy_from_slice(tail);
        Node {
            cv,
            block,
            block_len: tail.len() as u8,
            counter,
            flags: DERIVE_KEY_CONTEXT | CHUNK_END | if buffered == 0 { CHUNK_START } else { 0 },
        }
    }

    fn parent_node(left: &[u8; 32], right: &[u8; 32]) -> Node {
        let mut block = [0u8; 64];
        block[..32].copy_from_slice(left);
        block[32..].copy_from_slice(right);
        Node {
            cv: IV,
            block,
            block_len: 64,
            counter: 0,
            flags: DERIVE_KEY_CONTEXT | PARENT,
        }
    }

    pub(super) fn context_key(ctx: &[u8]) -> [u8; 32] {
        let mut stack: Vec<Node> = Vec::new();
        let chunks: Vec<&[u8]> = if ctx.is_empty() {
            vec![&[]]
        } else {
            ctx.chunks(CHUNK_LEN).collect()
        };
        for (i, chunk) in chunks.iter().enumerate() {
            let mut node = chunk_node(chunk, i as u64);
            let mut total = i as u64 + 1;
            while total.is_multiple_of(2) {
                let left = stack.pop().expect("cv stack has a subtree to merge");
                node = parent_node(&left.cv_bytes(), &node.cv_bytes());
                total >>= 1;
            }
            stack.push(node);
        }
        loop {
            let node = stack.pop().expect("at least one chunk exists");
            match stack.pop() {
                None => return node.root_bytes(),
                Some(left) => {
                    let merged = parent_node(&left.cv_bytes(), &node.cv_bytes());
                    if stack.is_empty() {
                        return merged.root_bytes();
                    }
                    stack.push(merged);
                }
            }
        }
    }
}

fn blake3_sum256(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

fn new_ctr(key: &[u8], iv: &[u8; 16]) -> Aes256Ctr {
    let k = blake3::derive_key("VLESS", key);
    Aes256Ctr::new((&k).into(), iv.into())
}

enum CipherImpl {
    Aes(Box<Aes256Gcm>),
    ChaCha(Box<ChaCha20Poly1305>),
}

impl CipherImpl {
    fn seal_detached(&self, nonce: &[u8; 12], ad: &[u8], data: &mut [u8]) -> [u8; TAG_LEN] {
        let tag = match self {
            Self::Aes(c) => c
                .encrypt_in_place_detached(Nonce::from_slice(nonce), ad, data)
                .expect("AES-256-GCM seal"),
            Self::ChaCha(c) => c
                .encrypt_in_place_detached(Nonce::from_slice(nonce), ad, data)
                .expect("ChaCha20-Poly1305 seal"),
        };
        let mut out = [0u8; TAG_LEN];
        out.copy_from_slice(&tag);
        out
    }

    fn open_slice_trailing(
        &self,
        nonce: &[u8; 12],
        ad: &[u8],
        buf: &mut [u8],
    ) -> Result<usize, ()> {
        if buf.len() < TAG_LEN {
            return Err(());
        }
        let split = buf.len() - TAG_LEN;
        let (data, tag_slice) = buf.split_at_mut(split);
        let tag = Tag::from_slice(tag_slice);
        let res = match self {
            Self::Aes(c) => c.decrypt_in_place_detached(Nonce::from_slice(nonce), ad, data, tag),
            Self::ChaCha(c) => c.decrypt_in_place_detached(Nonce::from_slice(nonce), ad, data, tag),
        };
        if res.is_err() {
            return Err(());
        }
        Ok(split)
    }

    fn open_trailing(&self, nonce: &[u8; 12], ad: &[u8], buf: &mut Vec<u8>) -> Result<(), ()> {
        let split = self.open_slice_trailing(nonce, ad, buf)?;
        buf.truncate(split);
        Ok(())
    }
}

struct Aead {
    cipher: CipherImpl,
    nonce: [u8; 12],
}

impl Aead {
    fn new(ctx: &[u8], key: &[u8], use_aes: bool) -> Self {
        let k = derive_key(ctx, key);
        let cipher = if use_aes {
            CipherImpl::Aes(Box::new(Aes256Gcm::new((&k).into())))
        } else {
            CipherImpl::ChaCha(Box::new(ChaCha20Poly1305::new((&k).into())))
        };
        Self {
            cipher,
            nonce: [0u8; 12],
        }
    }

    fn increment_nonce(&mut self) {
        for i in 0..12 {
            let idx = 11 - i;
            self.nonce[idx] = self.nonce[idx].wrapping_add(1);
            if self.nonce[idx] != 0 {
                break;
            }
        }
    }

    fn is_exhausted(&self) -> bool {
        self.nonce == MAX_NONCE
    }

    fn encrypt(&self, nonce: &[u8; 12], plaintext: &[u8], ad: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(plaintext.len() + TAG_LEN);
        out.extend_from_slice(plaintext);
        let tag = self.cipher.seal_detached(nonce, ad, &mut out);
        out.extend_from_slice(&tag);
        out
    }

    fn decrypt(&self, nonce: &[u8; 12], ct: &[u8], ad: &[u8]) -> Result<Vec<u8>, ()> {
        let mut out = ct.to_vec();
        self.cipher.open_trailing(nonce, ad, &mut out)?;
        Ok(out)
    }

    fn seal(&mut self, plaintext: &[u8]) -> Vec<u8> {
        self.increment_nonce();
        let nonce = self.nonce;
        self.encrypt(&nonce, plaintext, &[])
    }

    fn seal_ad_append(&mut self, plaintext: &[u8], ad: &[u8], out: &mut Vec<u8>) {
        self.increment_nonce();
        let nonce = self.nonce;
        let start = out.len();
        out.extend_from_slice(plaintext);
        let tag = self.cipher.seal_detached(&nonce, ad, &mut out[start..]);
        out.extend_from_slice(&tag);
    }

    fn seal_max(&self, plaintext: &[u8]) -> Vec<u8> {
        self.encrypt(&MAX_NONCE, plaintext, &[])
    }

    fn open(&mut self, ct: &[u8]) -> Result<Vec<u8>, ()> {
        self.increment_nonce();
        let nonce = self.nonce;
        self.decrypt(&nonce, ct, &[])
    }

    fn open_ad_slice(&mut self, ct: &mut [u8], ad: &[u8]) -> Result<usize, ()> {
        self.increment_nonce();
        let nonce = self.nonce;
        self.cipher.open_slice_trailing(&nonce, ad, ct)
    }

    fn open_max(&self, ct: &[u8]) -> Result<Vec<u8>, ()> {
        self.decrypt(&MAX_NONCE, ct, &[])
    }
}

fn encode_length(l: usize) -> [u8; 2] {
    [(l >> 8) as u8, l as u8]
}

fn decode_length(b: &[u8]) -> usize {
    ((b[0] as usize) << 8) | (b[1] as usize)
}

fn encode_header(l: usize) -> [u8; 5] {
    [23, 3, 3, (l >> 8) as u8, l as u8]
}

fn decode_header(h: &[u8; 5]) -> Result<usize, io::Error> {
    let mut l = ((h[3] as usize) << 8) | (h[4] as usize);
    if h[0] != 23 || h[1] != 3 || h[2] != 3 {
        l = 0;
    }
    if !(17..=16640).contains(&l) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "vless-encryption: invalid record header",
        ));
    }
    Ok(l)
}

#[derive(Default, Clone)]
struct Padding {
    lens: Vec<[i64; 3]>,
    gaps: Vec<[i64; 3]>,
}

fn parse_padding_spec(padding: &str) -> Result<Padding, String> {
    let (lens_i32, gaps_i32) = super::parse_padding(padding)?;
    Ok(Padding {
        lens: lens_i32
            .into_iter()
            .map(|a| [i64::from(a[0]), i64::from(a[1]), i64::from(a[2])])
            .collect(),
        gaps: gaps_i32
            .into_iter()
            .map(|a| [i64::from(a[0]), i64::from(a[1]), i64::from(a[2])])
            .collect(),
    })
}

fn create_padding(p: &Padding) -> (usize, Vec<usize>, Vec<Duration>) {
    let (lens_spec, gaps_spec) = if p.lens.is_empty() {
        (vec![[100, 111, 1111], [50, 0, 3333]], vec![[75, 0, 111]])
    } else {
        (p.lens.clone(), p.gaps.clone())
    };
    let mut lens = Vec::with_capacity(lens_spec.len());
    let mut length = 0usize;
    for y in &lens_spec {
        let mut l = 0i64;
        if y[0] >= rand_between(0, 100) {
            l = rand_between(y[1], y[2]);
        }
        lens.push(l as usize);
        length += l as usize;
    }
    let mut gaps = Vec::with_capacity(gaps_spec.len());
    for y in &gaps_spec {
        let mut g = 0i64;
        if y[0] >= rand_between(0, 100) {
            g = rand_between(y[1], y[2]);
        }
        gaps.push(Duration::from_millis(g.max(0) as u64));
    }
    (length, lens, gaps)
}

fn rand_between(from: i64, to: i64) -> i64 {
    if to <= from {
        return from;
    }
    from + (rand::random::<u64>() % (to - from) as u64) as i64
}

fn random_array<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut b);
    b
}

fn concat(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(a.len() + b.len());
    v.extend_from_slice(a);
    v.extend_from_slice(b);
    v
}

#[derive(Clone)]
#[allow(dead_code)]
enum ServerKey {
    X25519(StaticSecret, [u8; 32]),
    MlKem(Box<DecapsulationKey<MlKem768>>, Vec<u8>),
}

#[allow(dead_code)]
impl ServerKey {
    fn public_bytes(&self) -> Vec<u8> {
        match self {
            Self::X25519(_, pk) => pk.to_vec(),
            Self::MlKem(_, ek) => ek.clone(),
        }
    }
}

struct ServerSession {
    pfs_key: Vec<u8>,
    expire: Instant,
    seen_nfs: HashSet<[u8; 32]>,
}

pub struct ServerInstance {
    keys: Vec<ServerKey>,
    nfs_pkeys_bytes: Vec<Vec<u8>>,
    hash32s: Vec<[u8; 32]>,
    relays_length: usize,
    xor_mode: u32,
    seconds_from: i64,
    seconds_to: i64,
    padding: Padding,
    sessions: Mutex<HashMap<[u8; 16], ServerSession>>,
}

impl ServerInstance {
    pub fn from_raw(raw: &str) -> Result<Option<Arc<Self>>, String> {
        let Some(spec) = super::parse_vless_key(raw, false)? else {
            return Ok(None);
        };
        let mut keys = Vec::with_capacity(spec.keys.len());
        let mut nfs_pkeys_bytes = Vec::with_capacity(spec.keys.len());
        let mut hash32s = Vec::with_capacity(spec.keys.len());
        let mut relays_length = 0usize;
        for raw_key in &spec.keys {
            if raw_key.len() == 32 {
                let arr: [u8; 32] = raw_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| "invalid X25519 key".to_string())?;
                let sk = StaticSecret::from(arr);
                let pk = PublicKey::from(&sk).to_bytes();
                relays_length += X25519_LEN + 32;
                hash32s.push(blake3_sum256(&pk));
                nfs_pkeys_bytes.push(pk.to_vec());
                keys.push(ServerKey::X25519(sk, pk));
            } else if raw_key.len() == 64 {
                let seed_arr: [u8; 64] = raw_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| "invalid ML-KEM-768 seed".to_string())?;
                let dk = DecapsulationKey::<MlKem768>::from_seed(seed_arr.into());
                let ek_bytes = dk.encapsulation_key().to_bytes().as_slice().to_vec();
                relays_length += MLKEM768_CT_LEN + 32;
                hash32s.push(blake3_sum256(&ek_bytes));
                nfs_pkeys_bytes.push(ek_bytes.clone());
                keys.push(ServerKey::MlKem(Box::new(dk), ek_bytes));
            } else {
                return Err("unsupported VLESS decryption".to_string());
            }
        }
        relays_length -= 32;
        Ok(Some(Arc::new(Self {
            keys,
            nfs_pkeys_bytes,
            hash32s,
            relays_length,
            xor_mode: spec.xor,
            seconds_from: spec.from,
            seconds_to: spec.to,
            padding: parse_padding_spec(&spec.padding)?,
            sessions: Mutex::new(HashMap::new()),
        })))
    }

    pub async fn handshake(&self, mut stream: BoxStream) -> Result<BoxStream, String> {
        let mut use_aes = true;
        let mut iv_and_relays = vec![0u8; 16 + self.relays_length];
        stream
            .read_exact(&mut iv_and_relays)
            .await
            .map_err(|e| e.to_string())?;
        let iv: [u8; 16] = iv_and_relays[..16].try_into().unwrap();
        let mut relays = iv_and_relays[16..].to_vec();

        let mut nfs_key: Vec<u8> = Vec::new();
        let mut last_ctr: Option<Aes256Ctr> = None;
        let mut pos = 0usize;
        let n = self.keys.len();
        for (j, key) in self.keys.iter().enumerate() {
            if let Some(lc) = last_ctr.as_mut() {
                lc.apply_keystream(&mut relays[pos..pos + 32]);
            }
            let index = match key {
                ServerKey::X25519(..) => X25519_LEN,
                ServerKey::MlKem(..) => MLKEM768_CT_LEN,
            };
            if self.xor_mode > 0 {
                new_ctr(&self.nfs_pkeys_bytes[j], &iv)
                    .apply_keystream(&mut relays[pos..pos + index]);
            }
            match key {
                ServerKey::X25519(sk, _) => {
                    let peer: [u8; 32] = relays[pos..pos + X25519_LEN].try_into().unwrap();
                    if peer[31] > 127 {
                        return Err("X25519 public key high bit set".to_string());
                    }
                    let shared = sk.diffie_hellman(&PublicKey::from(peer));
                    if shared.as_bytes().iter().all(|&b| b == 0) {
                        return Err("X25519 low-order point".to_string());
                    }
                    nfs_key = shared.to_bytes().to_vec();
                }
                ServerKey::MlKem(dk, _) => {
                    nfs_key = dk
                        .decapsulate_slice(&relays[pos..pos + MLKEM768_CT_LEN])
                        .map_err(|_| "ML-KEM decapsulation failed".to_string())?
                        .as_slice()
                        .to_vec();
                }
            }
            if j == n - 1 {
                break;
            }
            let mut lc = new_ctr(&nfs_key, &iv);
            let hash_pos = pos + index;
            lc.apply_keystream(&mut relays[hash_pos..hash_pos + 32]);
            if relays[hash_pos..hash_pos + 32] != self.hash32s[j + 1] {
                return Err("unexpected relay hash32".to_string());
            }
            last_ctr = Some(lc);
            pos += index + 32;
        }

        let mut nfs_aead = Aead::new(&iv, &nfs_key, use_aes);
        let mut enc_length = [0u8; 18];
        stream
            .read_exact(&mut enc_length)
            .await
            .map_err(|e| e.to_string())?;
        let dec = match nfs_aead.open(&enc_length) {
            Ok(d) => d,
            Err(()) => {
                use_aes = !use_aes;
                nfs_aead = Aead::new(&iv, &nfs_key, use_aes);
                nfs_aead
                    .open(&enc_length)
                    .map_err(|_| "length AEAD open failed".to_string())?
            }
        };
        let length = decode_length(&dec[..2]);
        if length == 32 {
            return self
                .handshake_0rtt(stream, iv, nfs_aead, nfs_key, use_aes)
                .await;
        }

        if length < MLKEM768_EK_LEN + X25519_LEN + TAG_LEN {
            return Err("PFS key exchange too short".to_string());
        }
        let mut enc_pfs = vec![0u8; length];
        stream
            .read_exact(&mut enc_pfs)
            .await
            .map_err(|e| e.to_string())?;
        let client_pfs = nfs_aead
            .open(&enc_pfs)
            .map_err(|_| "client PFS AEAD open failed".to_string())?;
        let ek_arr: &[u8; MLKEM768_EK_LEN] = client_pfs[..MLKEM768_EK_LEN]
            .try_into()
            .map_err(|_| "bad client ML-KEM key".to_string())?;
        let client_ek = EncapsulationKey::<MlKem768>::new(ek_arr.into())
            .map_err(|_| "bad client ML-KEM key".to_string())?;
        let (ct, mlkem_shared) = client_ek.encapsulate();
        let peer_x: [u8; 32] = client_pfs[MLKEM768_EK_LEN..MLKEM768_EK_LEN + X25519_LEN]
            .try_into()
            .unwrap();
        let x_sk = StaticSecret::from(random_array::<32>());
        let x_shared = x_sk.diffie_hellman(&PublicKey::from(peer_x)).to_bytes();
        if x_shared.iter().all(|&b| b == 0) {
            return Err("PFS X25519 low-order point".to_string());
        }

        let mut pfs_key = Vec::with_capacity(64);
        pfs_key.extend_from_slice(mlkem_shared.as_slice());
        pfs_key.extend_from_slice(&x_shared);
        let mut server_pfs_public = Vec::with_capacity(MLKEM768_CT_LEN + X25519_LEN);
        server_pfs_public.extend_from_slice(ct.as_slice());
        server_pfs_public.extend_from_slice(&PublicKey::from(&x_sk).to_bytes());

        let united_key = concat(&pfs_key, &nfs_key);
        let mut aead = Aead::new(&server_pfs_public, &united_key, use_aes);
        let peer_aead = Aead::new(&client_pfs[..MLKEM768_EK_LEN + X25519_LEN], &united_key, use_aes);

        let mut ticket = random_array::<16>();
        let seconds = if self.seconds_to == 0 {
            self.seconds_from * rand_between(50, 100) / 100
        } else {
            rand_between(self.seconds_from, self.seconds_to)
        };
        ticket[..2].copy_from_slice(&encode_length(seconds.max(0) as usize));
        if seconds > 0 {
            let mut map = self.sessions.lock();
            let now = Instant::now();
            map.retain(|_, s| s.expire > now);
            if map.len() >= 4096 {
                if let Some(evict_key) = map
                    .iter()
                    .min_by_key(|(_, s)| s.expire)
                    .map(|(k, _)| *k)
                {
                    map.remove(&evict_key);
                }
            }
            if map.len() < 4096 {
                map.insert(
                    ticket,
                    ServerSession {
                        pfs_key: pfs_key.clone(),
                        expire: now + Duration::from_secs(seconds as u64 + 60),
                        seen_nfs: HashSet::new(),
                    },
                );
            }
        }

        let (padding_length, mut padding_lens, padding_gaps) = create_padding(&self.padding);
        let mut server_hello = Vec::new();
        server_hello.extend_from_slice(&nfs_aead.seal_max(&server_pfs_public));
        server_hello.extend_from_slice(&aead.seal(&ticket));
        server_hello.extend_from_slice(&aead.seal(&encode_length(padding_length - 18)));
        server_hello.extend_from_slice(&aead.seal(&vec![0u8; padding_length - 18 - TAG_LEN]));

        let pfs_exchange_len = MLKEM768_CT_LEN + X25519_LEN + TAG_LEN;
        padding_lens[0] += pfs_exchange_len + 32;
        let mut rest = server_hello.as_slice();
        for (i, &l) in padding_lens.iter().enumerate() {
            if l > 0 {
                let take = l.min(rest.len());
                stream
                    .write_all(&rest[..take])
                    .await
                    .map_err(|e| e.to_string())?;
                rest = &rest[take..];
            }
            if let Some(gap) = padding_gaps.get(i) {
                if !gap.is_zero() {
                    tokio::time::sleep(*gap).await;
                }
            }
        }
        if !rest.is_empty() {
            stream.write_all(rest).await.map_err(|e| e.to_string())?;
        }
        stream.flush().await.map_err(|e| e.to_string())?;

        let mut enc_len2 = [0u8; 18];
        stream
            .read_exact(&mut enc_len2)
            .await
            .map_err(|e| e.to_string())?;
        let dec2 = nfs_aead
            .open(&enc_len2)
            .map_err(|_| "client padding length open failed".to_string())?;
        let mut pad = vec![0u8; decode_length(&dec2[..2])];
        stream
            .read_exact(&mut pad)
            .await
            .map_err(|e| e.to_string())?;
        nfs_aead
            .open(&pad)
            .map_err(|_| "client padding open failed".to_string())?;

        let (write_ctr, read_ctr) = if self.xor_mode == 2 {
            (
                Some(new_ctr(&united_key, &ticket)),
                Some(new_ctr(&united_key, &iv)),
            )
        } else {
            (None, None)
        };

        Ok(spawn_relay(
            stream,
            DataPhase {
                aead,
                peer_aead: Some(peer_aead),
                united_key,
                use_aes,
                pre_write: Vec::new(),
                peer_padding_len: 0,
                write_ctr,
                read_ctr,
                xor: self.xor_mode == 2,
                reset_cache: None,
            },
        ))
    }

    async fn handshake_0rtt(
        &self,
        mut stream: BoxStream,
        iv: [u8; 16],
        mut nfs_aead: Aead,
        nfs_key: Vec<u8>,
        use_aes: bool,
    ) -> Result<BoxStream, String> {
        if self.seconds_from == 0 && self.seconds_to == 0 {
            return Err("0-RTT is not allowed".to_string());
        }
        let mut enc_ticket = [0u8; 32];
        stream
            .read_exact(&mut enc_ticket)
            .await
            .map_err(|e| e.to_string())?;
        let ticket = nfs_aead
            .open(&enc_ticket)
            .map_err(|_| "0-RTT ticket open failed".to_string())?;
        let ticket_arr: [u8; 16] = ticket[..16].try_into().unwrap();
        let nfs_arr: [u8; 32] = nfs_key
            .as_slice()
            .try_into()
            .map_err(|_| "invalid nfs key length".to_string())?;
        let pfs_key = {
            let mut map = self.sessions.lock();
            let now = Instant::now();
            match map.get_mut(&ticket_arr) {
                Some(sess) if sess.expire > now => {
                    if sess.seen_nfs.len() >= 8192 {
                        map.remove(&ticket_arr);
                        None
                    } else {
                        if !sess.seen_nfs.insert(nfs_arr) {
                            return Err("0-RTT replay detected".to_string());
                        }
                        Some(sess.pfs_key.clone())
                    }
                }
                _ => None,
            }
        };
        let Some(pfs_key) = pfs_key else {
            let noise_len = rand_between(1279, 2279) as usize;
            let mut noise = vec![0u8; noise_len];
            loop {
                rand::RngCore::fill_bytes(&mut rand::rng(), &mut noise);
                let hdr0: [u8; 5] = noise[..5].try_into().unwrap();
                let hdr16: [u8; 5] = noise[16..21].try_into().unwrap();
                if decode_header(&hdr0).is_err() && decode_header(&hdr16).is_err() {
                    break;
                }
            }
            let _ = stream.write_all(&noise).await;
            let _ = stream.flush().await;
            let _ = stream.shutdown().await;
            return Err("expired ticket".to_string());
        };

        let united_key = concat(&pfs_key, &nfs_key);
        let pre_write = random_array::<16>().to_vec();
        let aead = Aead::new(&pre_write, &united_key, use_aes);
        let peer_aead = Aead::new(&enc_ticket, &united_key, use_aes);

        let (write_ctr, read_ctr) = if self.xor_mode == 2 {
            let sr: [u8; 16] = pre_write[..16].try_into().unwrap();
            (
                Some(new_ctr(&united_key, &sr)),
                Some(new_ctr(&united_key, &iv)),
            )
        } else {
            (None, None)
        };

        Ok(spawn_relay(
            stream,
            DataPhase {
                aead,
                peer_aead: Some(peer_aead),
                united_key,
                use_aes,
                pre_write,
                peer_padding_len: 0,
                write_ctr,
                read_ctr,
                xor: self.xor_mode == 2,
                reset_cache: None,
            },
        ))
    }
}

enum NfsKey {
    X25519(PublicKey),
    MlKem(Box<EncapsulationKey<MlKem768>>),
}

#[derive(Default)]
struct TicketCache {
    expire: Option<Instant>,
    pfs_key: Vec<u8>,
    ticket: Vec<u8>,
}

pub struct ClientInstance {
    nfs_keys: Vec<NfsKey>,
    nfs_keys_bytes: Vec<Vec<u8>>,
    hash32s: Vec<[u8; 32]>,
    relays_length: usize,
    xor_mode: u32,
    seconds: u32,
    padding: Padding,
    use_aes: bool,
    cache: Arc<Mutex<TicketCache>>,
}

impl ClientInstance {
    pub fn from_raw(raw: &str) -> Result<Option<Arc<Self>>, String> {
        let Some(spec) = super::parse_vless_key(raw, true)? else {
            return Ok(None);
        };
        let mut nfs_keys = Vec::with_capacity(spec.keys.len());
        let mut hash32s = Vec::with_capacity(spec.keys.len());
        let mut relays_length = 0usize;
        for k in &spec.keys {
            if k.len() == X25519_LEN {
                let arr: [u8; 32] = k.as_slice().try_into().unwrap();
                nfs_keys.push(NfsKey::X25519(PublicKey::from(arr)));
                relays_length += X25519_LEN + 32;
            } else if k.len() == MLKEM768_EK_LEN {
                let arr: &[u8; MLKEM768_EK_LEN] = k
                    .as_slice()
                    .try_into()
                    .map_err(|_| "invalid ML-KEM-768 encapsulation key".to_string())?;
                let ek = EncapsulationKey::<MlKem768>::new(arr.into())
                    .map_err(|_| "invalid ML-KEM-768 encapsulation key".to_string())?;
                nfs_keys.push(NfsKey::MlKem(Box::new(ek)));
                relays_length += MLKEM768_CT_LEN + 32;
            } else {
                return Err("unsupported VLESS encryption".to_string());
            }
            hash32s.push(blake3_sum256(k));
        }
        relays_length -= 32;
        Ok(Some(Arc::new(Self {
            nfs_keys,
            nfs_keys_bytes: spec.keys,
            hash32s,
            relays_length,
            xor_mode: spec.xor,
            seconds: spec.seconds,
            padding: parse_padding_spec(&spec.padding)?,
            use_aes: true,
            cache: Arc::new(Mutex::new(TicketCache::default())),
        })))
    }

    pub fn has_cached_ticket(&self) -> bool {
        if self.seconds == 0 {
            return false;
        }
        let cache = self.cache.lock();
        matches!(cache.expire, Some(exp) if Instant::now() < exp)
    }

    pub fn invalidate_ticket(&self) {
        self.cache.lock().expire = None;
    }

    pub async fn handshake(&self, mut stream: BoxStream) -> Result<BoxStream, String> {
        let use_aes = self.use_aes;
        let iv: [u8; 16] = random_array();
        let mut relays = vec![0u8; self.relays_length];
        let mut nfs_key: Vec<u8> = Vec::new();
        let mut last_ctr: Option<Aes256Ctr> = None;
        let mut pos = 0usize;
        let n = self.nfs_keys.len();
        for (j, key) in self.nfs_keys.iter().enumerate() {
            let index = match key {
                NfsKey::X25519(server_pub) => {
                    let mut sk = StaticSecret::from(random_array::<32>());
                    let mut my_pub = PublicKey::from(&sk).to_bytes();
                    for _ in 0..8 {
                        if my_pub[31] <= 127 {
                            break;
                        }
                        let cand = StaticSecret::from(random_array::<32>());
                        let pub_b = PublicKey::from(&cand).to_bytes();
                        sk = cand;
                        my_pub = pub_b;
                    }
                    relays[pos..pos + X25519_LEN].copy_from_slice(&my_pub);
                    let shared = sk.diffie_hellman(server_pub);
                    if shared.as_bytes().iter().all(|&b| b == 0) {
                        return Err("X25519 low-order point".to_string());
                    }
                    nfs_key = shared.to_bytes().to_vec();
                    X25519_LEN
                }
                NfsKey::MlKem(ek) => {
                    let (ct, shared) = ek.encapsulate();
                    relays[pos..pos + MLKEM768_CT_LEN].copy_from_slice(ct.as_slice());
                    nfs_key = shared.as_slice().to_vec();
                    MLKEM768_CT_LEN
                }
            };
            if self.xor_mode > 0 {
                new_ctr(&self.nfs_keys_bytes[j], &iv)
                    .apply_keystream(&mut relays[pos..pos + index]);
            }
            if let Some(lc) = last_ctr.as_mut() {
                lc.apply_keystream(&mut relays[pos..pos + 32]);
            }
            if j == n - 1 {
                break;
            }
            let mut lc = new_ctr(&nfs_key, &iv);
            let mut hash = self.hash32s[j + 1];
            lc.apply_keystream(&mut hash);
            relays[pos + index..pos + index + 32].copy_from_slice(&hash);
            last_ctr = Some(lc);
            pos += index + 32;
        }

        let mut nfs_aead = Aead::new(&iv, &nfs_key, use_aes);
        let iv_and_relays = 16 + self.relays_length;

        if self.seconds > 0 {
            let cached = {
                let cache = self.cache.lock();
                match cache.expire {
                    Some(exp) if Instant::now() < exp => {
                        Some((cache.pfs_key.clone(), cache.ticket.clone()))
                    }
                    _ => None,
                }
            };
            if let Some((pfs_key, ticket)) = cached {
                let mut pre_write = Vec::with_capacity(iv_and_relays + 18 + 32);
                pre_write.extend_from_slice(&iv);
                pre_write.extend_from_slice(&relays);
                pre_write.extend_from_slice(&nfs_aead.seal(&encode_length(32)));
                let enc_ticket = nfs_aead.seal(&ticket);
                pre_write.extend_from_slice(&enc_ticket);

                let united_key = concat(&pfs_key, &nfs_key);
                let aead = Aead::new(&enc_ticket, &united_key, use_aes);
                let write_ctr = (self.xor_mode == 2).then(|| new_ctr(&united_key, &iv));

                return Ok(spawn_relay(
                    stream,
                    DataPhase {
                        aead,
                        peer_aead: None,
                        united_key,
                        use_aes,
                        pre_write,
                        peer_padding_len: 0,
                        write_ctr,
                        read_ctr: None,
                        xor: self.xor_mode == 2,
                        reset_cache: Some(Arc::clone(&self.cache)),
                    },
                ));
            }
        }

        let pfs_key_exchange_len = 18 + MLKEM768_EK_LEN + X25519_LEN + TAG_LEN;
        let (mlkem_dk, mlkem_ek) = MlKem768::generate_keypair();
        let mlkem_ek_bytes = mlkem_ek.to_bytes();
        let x_sk = StaticSecret::from(random_array::<32>());
        let x_pub = PublicKey::from(&x_sk).to_bytes();
        let mut pfs_public_key = Vec::with_capacity(MLKEM768_EK_LEN + X25519_LEN);
        pfs_public_key.extend_from_slice(mlkem_ek_bytes.as_slice());
        pfs_public_key.extend_from_slice(&x_pub);

        let mut client_hello = Vec::new();
        client_hello.extend_from_slice(&iv);
        client_hello.extend_from_slice(&relays);
        client_hello.extend_from_slice(&nfs_aead.seal(&encode_length(pfs_key_exchange_len - 18)));
        client_hello.extend_from_slice(&nfs_aead.seal(&pfs_public_key));

        let (padding_length, mut padding_lens, padding_gaps) = create_padding(&self.padding);
        let pad_body = vec![0u8; padding_length - 18 - TAG_LEN];
        client_hello.extend_from_slice(&nfs_aead.seal(&encode_length(padding_length - 18)));
        client_hello.extend_from_slice(&nfs_aead.seal(&pad_body));

        padding_lens[0] += iv_and_relays + pfs_key_exchange_len;
        let mut rest = client_hello.as_slice();
        for (i, &l) in padding_lens.iter().enumerate() {
            if l > 0 {
                let take = l.min(rest.len());
                stream
                    .write_all(&rest[..take])
                    .await
                    .map_err(|e| e.to_string())?;
                rest = &rest[take..];
            }
            if let Some(gap) = padding_gaps.get(i) {
                if !gap.is_zero() {
                    tokio::time::sleep(*gap).await;
                }
            }
        }
        if !rest.is_empty() {
            stream.write_all(rest).await.map_err(|e| e.to_string())?;
        }
        stream.flush().await.map_err(|e| e.to_string())?;

        let mut enc_pfs_pub = vec![0u8; MLKEM768_CT_LEN + X25519_LEN + TAG_LEN];
        stream
            .read_exact(&mut enc_pfs_pub)
            .await
            .map_err(|e| e.to_string())?;
        let dec = nfs_aead
            .open_max(&enc_pfs_pub)
            .map_err(|_| "server PFS key AEAD open failed".to_string())?;
        let mlkem_shared = mlkem_dk
            .decapsulate_slice(&dec[..MLKEM768_CT_LEN])
            .map_err(|_| "ML-KEM-768 decapsulation failed".to_string())?;
        let peer_x: [u8; 32] = dec[MLKEM768_CT_LEN..MLKEM768_CT_LEN + X25519_LEN]
            .try_into()
            .unwrap();
        let x_shared = x_sk.diffie_hellman(&PublicKey::from(peer_x)).to_bytes();
        if x_shared.iter().all(|&b| b == 0) {
            return Err("PFS X25519 low-order point".to_string());
        }

        let mut pfs_key = Vec::with_capacity(64);
        pfs_key.extend_from_slice(mlkem_shared.as_slice());
        pfs_key.extend_from_slice(&x_shared);
        let united_key = concat(&pfs_key, &nfs_key);

        let aead = Aead::new(&pfs_public_key, &united_key, use_aes);
        let mut peer_aead = Aead::new(&dec, &united_key, use_aes);

        let mut enc_ticket = [0u8; 32];
        stream
            .read_exact(&mut enc_ticket)
            .await
            .map_err(|e| e.to_string())?;
        let ticket = peer_aead
            .open(&enc_ticket)
            .map_err(|_| "ticket AEAD open failed".to_string())?;
        let seconds = decode_length(&ticket[..2]);
        if self.seconds > 0 && seconds > 0 {
            let mut cache = self.cache.lock();
            cache.expire = Some(Instant::now() + Duration::from_secs(seconds as u64));
            cache.pfs_key = pfs_key.clone();
            cache.ticket = ticket.clone();
        }

        let mut enc_length = [0u8; 18];
        stream
            .read_exact(&mut enc_length)
            .await
            .map_err(|e| e.to_string())?;
        let dec_len = peer_aead
            .open(&enc_length)
            .map_err(|_| "padding length AEAD open failed".to_string())?;
        let peer_padding_len = decode_length(&dec_len[..2]);

        let (write_ctr, read_ctr) = if self.xor_mode == 2 {
            let ticket_iv: [u8; 16] = ticket[..16].try_into().unwrap();
            (
                Some(new_ctr(&united_key, &iv)),
                Some(new_ctr(&united_key, &ticket_iv)),
            )
        } else {
            (None, None)
        };

        Ok(spawn_relay(
            stream,
            DataPhase {
                aead,
                peer_aead: Some(peer_aead),
                united_key,
                use_aes,
                pre_write: Vec::new(),
                peer_padding_len,
                write_ctr,
                read_ctr,
                xor: self.xor_mode == 2,
                reset_cache: None,
            },
        ))
    }
}

struct DataPhase {
    aead: Aead,
    peer_aead: Option<Aead>,
    united_key: Vec<u8>,
    use_aes: bool,
    pre_write: Vec<u8>,
    peer_padding_len: usize,
    write_ctr: Option<Aes256Ctr>,
    read_ctr: Option<Aes256Ctr>,
    xor: bool,
    reset_cache: Option<Arc<Mutex<TicketCache>>>,
}

pub struct TaskedDuplex {
    inner: DuplexStream,
    read_abort: AbortHandle,
    _write_abort: AbortHandle,
}

impl TaskedDuplex {
    pub fn new(inner: DuplexStream, tasks: Vec<tokio::task::JoinHandle<()>>) -> Self {
        let mut it = tasks.into_iter();
        let w_abort = it
            .next()
            .map(|h| h.abort_handle())
            .unwrap_or_else(|| tokio::spawn(async {}).abort_handle());
        let r_abort = it
            .next()
            .map(|h| h.abort_handle())
            .unwrap_or_else(|| tokio::spawn(async {}).abort_handle());
        Self {
            inner,
            read_abort: r_abort,
            _write_abort: w_abort,
        }
    }
}

impl Drop for TaskedDuplex {
    fn drop(&mut self) {
        // Only abort reader immediately; dropping `self.inner` yields EOF on `peer_rd`
        // so `write_task` can flush trailing chunks / `0\r\n\r\n` cleanly before exiting.
        self.read_abort.abort();
    }
}

impl AsyncRead for TaskedDuplex {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for TaskedDuplex {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn spawn_relay(stream: BoxStream, dp: DataPhase) -> BoxStream {
    let DataPhase {
        aead,
        peer_aead,
        united_key,
        use_aes,
        pre_write,
        peer_padding_len,
        write_ctr,
        read_ctr,
        xor,
        reset_cache,
    } = dp;
    Box::new(VlessEncStream {
        inner: stream,
        aead,
        peer_aead,
        united_key,
        use_aes,
        pre_write,
        peer_padding_len,
        write_ctr,
        read_ctr,
        xor,
        reset_cache,
        first_record_ok: false,
        pending_rec_hdr: None,
        read_raw_buf: Vec::with_capacity(65536),
        read_raw_pos: 0,
        read_plain_buf: Vec::with_capacity(32768),
        read_plain_pos: 0,
        write_buf: Vec::with_capacity(65536 + 128),
        write_pos: 0,
        pending_write_len: 0,
        eof: false,
    })
}

struct VlessEncStream {
    inner: BoxStream,
    aead: Aead,
    peer_aead: Option<Aead>,
    united_key: Vec<u8>,
    use_aes: bool,
    pre_write: Vec<u8>,
    peer_padding_len: usize,
    write_ctr: Option<Aes256Ctr>,
    read_ctr: Option<Aes256Ctr>,
    xor: bool,
    reset_cache: Option<Arc<Mutex<TicketCache>>>,
    first_record_ok: bool,
    pending_rec_hdr: Option<([u8; 5], usize)>,
    read_raw_buf: Vec<u8>,
    read_raw_pos: usize,
    read_plain_buf: Vec<u8>,
    read_plain_pos: usize,
    write_buf: Vec<u8>,
    write_pos: usize,
    pending_write_len: usize,
    eof: bool,
}

impl VlessEncStream {
    fn invalidate_cache(&mut self) {
        if let Some(ref cache) = self.reset_cache {
            cache.lock().expire = None;
        }
    }

    fn poll_drain_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.write_pos < self.write_buf.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.write_buf[self.write_pos..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "vless-encryption: write zero",
                    )))
                }
                Poll::Ready(Ok(n)) => {
                    self.write_pos += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.write_buf.clear();
        self.write_pos = 0;
        if self.write_buf.capacity() > 256 * 1024 {
            self.write_buf.shrink_to(65536 + 128);
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for VlessEncStream {
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

            if this.peer_aead.is_none() {
                let raw_avail = this.read_raw_buf.len() - this.read_raw_pos;
                if raw_avail >= 16 {
                    let mut sr = [0u8; 16];
                    sr.copy_from_slice(
                        &this.read_raw_buf[this.read_raw_pos..this.read_raw_pos + 16],
                    );
                    this.read_raw_pos += 16;
                    if this.xor {
                        this.read_ctr = Some(new_ctr(&this.united_key, &sr));
                    }
                    this.peer_aead = Some(Aead::new(&sr, &this.united_key, this.use_aes));
                    if this.read_raw_pos == this.read_raw_buf.len() {
                        this.read_raw_buf.clear();
                        this.read_raw_pos = 0;
                    }
                }
            }

            if this.peer_aead.is_some() && this.peer_padding_len > 0 {
                let raw_avail = this.read_raw_buf.len() - this.read_raw_pos;
                if raw_avail >= this.peer_padding_len {
                    let plen = this.peer_padding_len;
                    let start = this.read_raw_pos;
                    this.read_raw_pos += plen;
                    this.peer_padding_len = 0;
                    if this
                        .peer_aead
                        .as_mut()
                        .unwrap()
                        .open_ad_slice(&mut this.read_raw_buf[start..start + plen], &[])
                        .is_err()
                    {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "vless-encryption: server padding open failed",
                        )));
                    }
                    if this.read_raw_pos == this.read_raw_buf.len() {
                        this.read_raw_buf.clear();
                        this.read_raw_pos = 0;
                    }
                }
            }

            if this.peer_aead.is_some() && this.peer_padding_len == 0 {
                if this.pending_rec_hdr.is_none() {
                    let raw_avail = this.read_raw_buf.len() - this.read_raw_pos;
                    if raw_avail >= 5 {
                        let mut hdr = [0u8; 5];
                        hdr.copy_from_slice(
                            &this.read_raw_buf[this.read_raw_pos..this.read_raw_pos + 5],
                        );
                        this.read_raw_pos += 5;
                        if let Some(ctr) = this.read_ctr.as_mut() {
                            ctr.apply_keystream(&mut hdr);
                        }
                        match decode_header(&hdr) {
                            Ok(l) => {
                                this.pending_rec_hdr = Some((hdr, l));
                            }
                            Err(e) => {
                                if !this.first_record_ok {
                                    this.invalidate_cache();
                                }
                                return Poll::Ready(Err(e));
                            }
                        }
                    }
                }

                if let Some((hdr, body_len)) = this.pending_rec_hdr {
                    let raw_avail = this.read_raw_buf.len() - this.read_raw_pos;
                    if raw_avail >= body_len {
                        this.pending_rec_hdr = None;
                        let rec_start = this.read_raw_pos;
                        let rec_end = rec_start + body_len;
                        this.read_raw_pos = rec_end;
                        let rekey = this.peer_aead.as_ref().unwrap().is_exhausted().then(|| {
                            let mut ctx = Vec::with_capacity(5 + body_len);
                            ctx.extend_from_slice(&hdr);
                            ctx.extend_from_slice(&this.read_raw_buf[rec_start..rec_end]);
                            Aead::new(&ctx, &this.united_key, this.use_aes)
                        });
                        let Ok(plain_len) = this
                            .peer_aead
                            .as_mut()
                            .unwrap()
                            .open_ad_slice(&mut this.read_raw_buf[rec_start..rec_end], &hdr)
                        else {
                            if !this.first_record_ok {
                                this.invalidate_cache();
                            }
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "vless-encryption: record AEAD open failed",
                            )));
                        };
                        this.first_record_ok = true;
                        if let Some(next) = rekey {
                            this.peer_aead = Some(next);
                        }
                        if plain_len > 0 {
                            let plain_slice = &this.read_raw_buf[rec_start..rec_start + plain_len];
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
                        if buf.remaining() == 0 || this.read_plain_pos < this.read_plain_buf.len()
                        {
                            return Poll::Ready(Ok(()));
                        }
                        continue;
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
                        if !this.first_record_ok {
                            this.invalidate_cache();
                        }
                        if this.peer_aead.is_none()
                            || this.peer_padding_len > 0
                            || this.pending_rec_hdr.is_some()
                            || this.read_raw_pos < this.read_raw_buf.len()
                        {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "vless-encryption: record truncated on EOF",
                            )));
                        }
                        return Poll::Ready(Ok(()));
                    }
                    this.read_raw_buf.extend_from_slice(filled);
                }
                Poll::Ready(Err(e)) => {
                    if !this.first_record_ok {
                        this.invalidate_cache();
                    }
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for VlessEncStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.write_pos < this.write_buf.len() {
            match this.poll_drain_write(cx) {
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

        let batch_len = buf.len().min(MAX_WRITE_BATCH);
        this.write_buf.clear();
        this.write_pos = 0;
        this.pending_write_len = batch_len;
        if !this.pre_write.is_empty() {
            this.write_buf.extend_from_slice(&this.pre_write);
            this.pre_write.clear();
        }
        for body in buf[..batch_len].chunks(WRITE_CHUNK) {
            let header = encode_header(body.len() + TAG_LEN);
            let exhausted = this.aead.is_exhausted();
            let header_start = this.write_buf.len();
            this.write_buf.extend_from_slice(&header);
            this.aead.seal_ad_append(body, &header, &mut this.write_buf);
            if exhausted {
                let mut ctx = Vec::with_capacity(this.write_buf.len() - header_start);
                ctx.extend_from_slice(&this.write_buf[header_start..]);
                this.aead = Aead::new(&ctx, &this.united_key, this.use_aes);
            }
            if let Some(ctr) = this.write_ctr.as_mut() {
                ctr.apply_keystream(&mut this.write_buf[header_start..header_start + 5]);
            }
        }

        match this.poll_drain_write(cx) {
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
        match this.poll_drain_write(cx) {
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
        match this.poll_drain_write(cx) {
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct SlicedStream<S> {
        inner: S,
        max_read: usize,
        max_write: usize,
    }

    impl<S: AsyncRead + Unpin> AsyncRead for SlicedStream<S> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let cap = buf.remaining().min(self.max_read);
            let mut tmp = vec![0u8; cap];
            let mut rbuf = ReadBuf::new(&mut tmp);
            match Pin::new(&mut self.inner).poll_read(cx, &mut rbuf) {
                Poll::Ready(Ok(())) => {
                    buf.put_slice(rbuf.filled());
                    Poll::Ready(Ok(()))
                }
                other => other,
            }
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for SlicedStream<S> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let cap = buf.len().min(self.max_write);
            Pin::new(&mut self.inner).poll_write(cx, &buf[..cap])
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    #[tokio::test]
    async fn vless_enc_stream_fragmented_duplex_flush_and_half_dead_write_error() {
        let (x_dec, x_enc, pq_dec, pq_enc) = crate::tunnel::generate_vless_enc().unwrap();
        let pairs = [
            (x_dec, x_enc),
            (
                pq_dec.replacen(".native.", ".random.", 1),
                pq_enc.replacen(".native.", ".random.", 1),
            ),
        ];
        for (dec_raw, enc_raw) in pairs {
            let srv = ServerInstance::from_raw(&dec_raw).unwrap().unwrap();
            let cli = ClientInstance::from_raw(&enc_raw).unwrap().unwrap();

            // 1. Prime-sliced concurrent full-duplex with backpressure & immediate drop after shutdown
            let (c_raw, s_raw) = tokio::io::duplex(4096);
            let c_sliced = SlicedStream {
                inner: c_raw,
                max_read: 137,
                max_write: 211,
            };
            let s_sliced = SlicedStream {
                inner: s_raw,
                max_read: 149,
                max_write: 193,
            };
            let payload_up: Vec<u8> = (0..90_000usize).map(|i| (i.wrapping_mul(31)) as u8).collect();
            let payload_dn: Vec<u8> = (0..75_000usize).map(|i| (i.wrapping_mul(17)) as u8).collect();
            let expected_up = payload_up.clone();
            let expected_dn = payload_dn.clone();

            let srv_c = srv.clone();
            let srv_task = tokio::spawn(async move {
                let s = srv_c.handshake(Box::new(s_sliced)).await.unwrap();
                let (mut sr, mut sw) = tokio::io::split(s);
                let w_task = tokio::spawn(async move {
                    for chunk in payload_dn.chunks(313) {
                        sw.write_all(chunk).await.unwrap();
                    }
                    sw.flush().await.unwrap();
                    sw.shutdown().await.unwrap();
                });
                let mut got = vec![0u8; expected_up.len()];
                sr.read_exact(&mut got).await.unwrap();
                assert_eq!(got, expected_up);
                w_task.await.unwrap();
                // Dropping `sr`/`sw` right after `shutdown()` must never truncate the tail record
            });

            let c = cli.handshake(Box::new(c_sliced)).await.unwrap();
            let (mut cr, mut cw) = tokio::io::split(c);
            let cw_task = tokio::spawn(async move {
                for chunk in payload_up.chunks(277) {
                    cw.write_all(chunk).await.unwrap();
                }
                cw.flush().await.unwrap();
            });
            let mut got_dn = Vec::new();
            cr.read_to_end(&mut got_dn).await.unwrap();
            assert_eq!(got_dn, expected_dn);
            cw_task.await.unwrap();
            srv_task.await.unwrap();

            // 2. Half-dead underlying socket: writes must fail immediately instead of buffering 256 KiB
            cli.invalidate_ticket();
            let (c_raw2, s_raw2) = tokio::io::duplex(4096);
            let srv_c2 = srv.clone();
            let srv_hs = tokio::spawn(async move { srv_c2.handshake(Box::new(s_raw2)).await.unwrap() });
            let mut c2 = cli.handshake(Box::new(c_raw2)).await.unwrap();
            let s2 = srv_hs.await.unwrap();
            drop(s2);
            let write_err = c2.write_all(&[0xabu8; 1024]).await;
            assert!(
                write_err.is_err(),
                "VlessEncStream must surface broken peer immediately on write"
            );
        }
    }

    #[tokio::test]
    async fn vless_enc_0rtt_server_restart_invalidates_client_ticket_and_recovers() {
        let (_, _, pq_dec, pq_enc) = crate::tunnel::generate_vless_enc().unwrap();
        let dec_raw = pq_dec.replacen(".native.", ".xorpub.", 1);
        let enc_raw = pq_enc.replacen(".native.", ".xorpub.", 1);

        let srv1 = ServerInstance::from_raw(&dec_raw).unwrap().unwrap();
        let cli = ClientInstance::from_raw(&enc_raw).unwrap().unwrap();
        assert!(!cli.has_cached_ticket());

        // Session 1: 1-RTT caches ticket
        {
            let (cr, sr) = tokio::io::duplex(65536);
            let s_fut = {
                let srv = srv1.clone();
                tokio::spawn(async move {
                    let mut s = srv.handshake(Box::new(sr)).await.unwrap();
                    let mut b = [0u8; 4];
                    s.read_exact(&mut b).await.unwrap();
                    assert_eq!(&b, b"ping");
                    s.write_all(b"pong").await.unwrap();
                    s.flush().await.unwrap();
                })
            };
            let mut c = cli.handshake(Box::new(cr)).await.unwrap();
            assert!(cli.has_cached_ticket());
            c.write_all(b"ping").await.unwrap();
            c.flush().await.unwrap();
            let mut resp = [0u8; 4];
            c.read_exact(&mut resp).await.unwrap();
            assert_eq!(&resp, b"pong");
            s_fut.await.unwrap();
        }

        // Session 2: valid 0-RTT succeeds against srv1
        {
            let (cr, sr) = tokio::io::duplex(65536);
            let s_fut = {
                let srv = srv1.clone();
                tokio::spawn(async move {
                    let mut s = srv.handshake(Box::new(sr)).await.unwrap();
                    let mut b = [0u8; 5];
                    s.read_exact(&mut b).await.unwrap();
                    assert_eq!(&b, b"0rtt!");
                    s.write_all(b"ok200").await.unwrap();
                    s.flush().await.unwrap();
                })
            };
            let mut c = cli.handshake(Box::new(cr)).await.unwrap();
            c.write_all(b"0rtt!").await.unwrap();
            c.flush().await.unwrap();
            let mut resp = [0u8; 5];
            c.read_exact(&mut resp).await.unwrap();
            assert_eq!(&resp, b"ok200");
            s_fut.await.unwrap();
        }

        // Simulate server restart: srv2 has identical keys, empty 0-RTT session map
        let srv2 = ServerInstance::from_raw(&dec_raw).unwrap().unwrap();
        {
            let (cr, sr) = tokio::io::duplex(65536);
            let s_fut = {
                let srv = srv2.clone();
                tokio::spawn(async move { srv.handshake(Box::new(sr)).await })
            };
            let mut c = cli.handshake(Box::new(cr)).await.unwrap();
            c.write_all(b"stale").await.unwrap();
            c.flush().await.unwrap();
            let mut resp = [0u8; 2];
            assert!(
                c.read_exact(&mut resp).await.is_err(),
                "client must detect 0-RTT rejection noise immediately"
            );
            assert!(
                !cli.has_cached_ticket(),
                "client must invalidate stale 0-RTT ticket upon rejection"
            );
            assert_eq!(s_fut.await.unwrap().err().as_deref(), Some("expired ticket"));
        }

        // Next dial automatically performs 1-RTT against srv2 and caches a fresh ticket
        {
            let (cr, sr) = tokio::io::duplex(65536);
            let s_fut = {
                let srv = srv2.clone();
                tokio::spawn(async move {
                    let mut s = srv.handshake(Box::new(sr)).await.unwrap();
                    let mut b = [0u8; 5];
                    s.read_exact(&mut b).await.unwrap();
                    assert_eq!(&b, b"fresh");
                    s.write_all(b"ready").await.unwrap();
                    s.flush().await.unwrap();
                })
            };
            let mut c = cli.handshake(Box::new(cr)).await.unwrap();
            assert!(cli.has_cached_ticket());
            c.write_all(b"fresh").await.unwrap();
            c.flush().await.unwrap();
            let mut resp = [0u8; 5];
            c.read_exact(&mut resp).await.unwrap();
            assert_eq!(&resp, b"ready");
            s_fut.await.unwrap();
        }
    }
}
