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
use tokio::io::{
    duplex, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, ReadHalf,
    WriteHalf,
};
use tokio::task::AbortHandle;
use x25519_dalek::{PublicKey, StaticSecret};

use super::BoxStream;

pub type Aes256Ctr = ctr::Ctr128BE<Aes256>;

pub const X25519_LEN: usize = 32;
pub const MLKEM768_EK_LEN: usize = 1184;
pub const MLKEM768_CT_LEN: usize = 1088;
pub const TAG_LEN: usize = 16;

const MAX_NONCE: [u8; 12] = [0xFF; 12];
const RELAY_BUF: usize = 256 * 1024;
const MAX_CHUNK: usize = 16384;
const MAX_RECORD_BODY: usize = 16_640;

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

    fn open_trailing(&self, nonce: &[u8; 12], ad: &[u8], buf: &mut Vec<u8>) -> Result<(), ()> {
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

    fn open_ad_in_place(&mut self, ct: &mut Vec<u8>, ad: &[u8]) -> Result<(), ()> {
        self.increment_nonce();
        let nonce = self.nonce;
        self.cipher.open_trailing(&nonce, ad, ct)
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
                    nfs_key = sk
                        .diffie_hellman(&PublicKey::from(peer))
                        .to_bytes()
                        .to_vec();
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
                        return Err("0-RTT ticket replay window exhausted".to_string());
                    }
                    if !sess.seen_nfs.insert(nfs_arr) {
                        return Err("0-RTT replay detected".to_string());
                    }
                    Some(sess.pfs_key.clone())
                }
                _ => None,
            }
        };
        let Some(pfs_key) = pfs_key else {
            let noise_len = rand_between(1279, 2279) as usize;
            let mut noise = vec![0u8; noise_len];
            loop {
                rand::RngCore::fill_bytes(&mut rand::rng(), &mut noise);
                let hdr: [u8; 5] = noise[..5].try_into().unwrap();
                if decode_header(&hdr).is_err() {
                    break;
                }
            }
            let _ = stream.write_all(&noise).await;
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
                    let mut my_pub = [0u8; 32];
                    let mut sk = StaticSecret::from(random_array::<32>());
                    for _ in 0..8 {
                        let cand = StaticSecret::from(random_array::<32>());
                        let pub_b = PublicKey::from(&cand).to_bytes();
                        if pub_b[31] <= 127 {
                            sk = cand;
                            my_pub = pub_b;
                            break;
                        }
                    }
                    relays[pos..pos + X25519_LEN].copy_from_slice(&my_pub);
                    nfs_key = sk.diffie_hellman(server_pub).to_bytes().to_vec();
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
    write_abort: AbortHandle,
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
            write_abort: w_abort,
        }
    }
}

impl Drop for TaskedDuplex {
    fn drop(&mut self) {
        self.read_abort.abort();
        self.write_abort.abort();
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
    let (client, proxy) = duplex(RELAY_BUF);
    let (rd, wr) = tokio::io::split(stream);
    let (proxy_rd, proxy_wr) = tokio::io::split(proxy);

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

    let read_key = united_key.clone();
    let read_task = tokio::spawn(read_loop(
        rd,
        proxy_wr,
        peer_aead,
        read_ctr,
        xor,
        peer_padding_len,
        read_key,
        use_aes,
        reset_cache,
    ));
    let write_task = tokio::spawn(write_loop(
        wr, proxy_rd, aead, write_ctr, pre_write, united_key, use_aes,
    ));

    let read_abort = read_task.abort_handle();
    let write_abort = write_task.abort_handle();
    let write_abort_sup = write_abort.clone();
    tokio::spawn(async move {
        let clean_eof = matches!(read_task.await, Ok(true));
        if !clean_eof {
            write_abort_sup.abort();
        }
    });

    Box::new(TaskedDuplex {
        inner: client,
        read_abort,
        write_abort,
    })
}

#[allow(clippy::too_many_arguments)]
async fn read_loop(
    rd: ReadHalf<BoxStream>,
    mut proxy_wr: WriteHalf<DuplexStream>,
    peer_aead: Option<Aead>,
    mut read_ctr: Option<Aes256Ctr>,
    xor: bool,
    peer_padding_len: usize,
    united_key: Vec<u8>,
    use_aes: bool,
    reset_cache: Option<Arc<Mutex<TicketCache>>>,
) -> bool {
    let mut rd = tokio::io::BufReader::with_capacity(64 * 1024, rd);
    let mut first_record_ok = false;
    let invalidate = |reset_cache: &Option<Arc<Mutex<TicketCache>>>| {
        if let Some(cache) = reset_cache {
            cache.lock().expire = None;
        }
    };

    let mut peer_aead = match peer_aead {
        Some(a) => a,
        None => {
            let mut sr = [0u8; 16];
            if rd.read_exact(&mut sr).await.is_err() {
                invalidate(&reset_cache);
                let _ = proxy_wr.shutdown().await;
                return false;
            }
            if xor {
                read_ctr = Some(new_ctr(&united_key, &sr));
            }
            Aead::new(&sr, &united_key, use_aes)
        }
    };

    if peer_padding_len > 0 {
        let mut pad = vec![0u8; peer_padding_len];
        if rd.read_exact(&mut pad).await.is_err() {
            let _ = proxy_wr.shutdown().await;
            return false;
        }
        if peer_aead.open(&pad).is_err() {
            let _ = proxy_wr.shutdown().await;
            return false;
        }
    }

    let mut clean_eof = false;
    let mut data = Vec::with_capacity(MAX_RECORD_BODY);
    loop {
        let mut hdr = [0u8; 5];
        match rd.read(&mut hdr).await {
            Ok(0) => {
                clean_eof = true;
                break;
            }
            Ok(n) => {
                if rd.read_exact(&mut hdr[n..]).await.is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
        if let Some(ctr) = read_ctr.as_mut() {
            ctr.apply_keystream(&mut hdr);
        }
        let Ok(l) = decode_header(&hdr) else {
            if !first_record_ok {
                invalidate(&reset_cache);
            }
            break;
        };
        data.resize(l, 0);
        if rd.read_exact(&mut data).await.is_err() {
            break;
        }
        let rekey = peer_aead.is_exhausted().then(|| {
            let mut ctx = Vec::with_capacity(5 + data.len());
            ctx.extend_from_slice(&hdr);
            ctx.extend_from_slice(&data);
            Aead::new(&ctx, &united_key, use_aes)
        });
        if peer_aead.open_ad_in_place(&mut data, &hdr).is_err() {
            if !first_record_ok {
                invalidate(&reset_cache);
            }
            break;
        }
        first_record_ok = true;
        if let Some(next) = rekey {
            peer_aead = next;
        }
        if proxy_wr.write_all(&data).await.is_err() {
            break;
        }
    }
    let _ = proxy_wr.shutdown().await;
    clean_eof
}

async fn write_loop(
    mut wr: WriteHalf<BoxStream>,
    mut proxy_rd: ReadHalf<DuplexStream>,
    mut aead: Aead,
    mut write_ctr: Option<Aes256Ctr>,
    pre_write: Vec<u8>,
    united_key: Vec<u8>,
    use_aes: bool,
) {
    let mut buf = vec![0u8; 64 * 1024];
    let mut out = Vec::with_capacity(pre_write.len() + 4 * (5 + MAX_CHUNK + TAG_LEN));
    let mut first_record = true;
    loop {
        let n = match proxy_rd.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        out.clear();
        if first_record {
            out.extend_from_slice(&pre_write);
            first_record = false;
        }
        for body in buf[..n].chunks(MAX_CHUNK) {
            let header = encode_header(body.len() + TAG_LEN);
            let exhausted = aead.is_exhausted();
            let header_start = out.len();
            out.extend_from_slice(&header);
            aead.seal_ad_append(body, &header, &mut out);
            if exhausted {
                let mut ctx = Vec::with_capacity(out.len() - header_start);
                ctx.extend_from_slice(&out[header_start..]);
                aead = Aead::new(&ctx, &united_key, use_aes);
            }
            if let Some(ctr) = write_ctr.as_mut() {
                ctr.apply_keystream(&mut out[header_start..header_start + 5]);
            }
        }
        if wr.write_all(&out).await.is_err() || wr.flush().await.is_err() {
            break;
        }
    }
    let _ = wr.shutdown().await;
}
