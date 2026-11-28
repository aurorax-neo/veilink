use std::collections::{HashMap, HashSet};
use std::io::{BufReader, Cursor};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use fips204::ml_dsa_65;
use fips204::traits::{KeyGen, SerDes};
use ml_kem::{DecapsulationKey, EncapsulationKey, KeyExport, MlKem768};
use rand::RngCore;
use regex::Regex;
use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

pub mod hysteria2;
pub mod mux_proto;
pub mod reality;
pub mod reality_hello;
pub mod vision;
pub mod vless_enc;
pub mod xhttp;

pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}
pub type BoxStream = Box<dyn AsyncStream>;
pub type BoxRead = Box<dyn AsyncRead + Unpin + Send>;
pub type BoxWrite = Box<dyn AsyncWrite + Unpin + Send>;

fn split_tunnel_stream(stream: BoxStream) -> (BoxRead, BoxWrite) {
    let (rd, wr) = tokio::io::split(stream);
    (
        Box::new(tokio::io::BufReader::with_capacity(65536, rd)),
        Box::new(wr),
    )
}

use crate::logring::Ring;
use crate::model::{
    self, bandwidth_bytes, Binding, ConnectEndpoint, Hysteria2, LocalTLS, Mapping, Node, Reality,
    Snapshot, XHTTP,
};

type TunnelLogger = Option<(Arc<Ring>, String, String)>;

fn log_tunnel(logger: &TunnelLogger, level: &str, msg: String) {
    if let Some((ref ring, ref node_id, _)) = logger {
        ring.push_entry("node", node_id, level, msg);
    }
}

pub const FRAME_OPEN: u8 = 1;
pub const FRAME_DATA: u8 = 2;
pub const FRAME_HALF: u8 = 3;
pub const FRAME_RESET: u8 = 4;
pub const FRAME_PING: u8 = 5;
pub const FRAME_PONG: u8 = 6;
pub const FRAME_DIAL_APP: u8 = 7;
pub const FRAME_DIAL_MUX: u8 = 8;

pub const MAX_PAYLOAD: usize = 32 << 10;
pub const MAX_STREAMS: usize = 512;
const STREAM_CHAN_CAP: usize = 256;
const SESSION_DATA_CHAN_CAP: usize = 256;
const SESSION_CTRL_CHAN_CAP: usize = 2048;
const MAX_BINDING_SESSIONS: usize = 64;
const PING_INTERVAL: Duration = Duration::from_secs(8);
const PING_SUSPECT_MS: u64 = 1_500;
const OPPORTUNISTIC_PING_IDLE_MS: u64 = 1_000;
const SESSION_FRESH_RX_MS: u64 = 18_000;
const SESSION_READ_TIMEOUT: Duration = Duration::from_secs(25);
const SESSION_READ_TIMEOUT_MS: u64 = 25_000;
const SESSION_STALE_RX_MS: u64 = 28_000;
const SESSION_WRITE_SLICE: Duration = Duration::from_secs(10);
const STREAM_OPEN_IDLE_MS: u64 = 300_000;
const STREAM_HALF_CLOSE_IDLE_MS: u64 = 60_000;
const STREAM_SOCKET_WRITE_TIMEOUT: Duration = Duration::from_secs(15);
const DEMUX_SINGLE_SEND_TIMEOUT: Duration = Duration::from_secs(3);
const DEMUX_MULTI_SEND_TIMEOUT: Duration = Duration::from_millis(500);
const DNS_CACHE_TTL: Duration = Duration::from_secs(60);
const MAX_DNS_CACHE_ENTRIES: usize = 1024;
const FRAME_HDR_LEN: usize = 7;
const OPTIMAL_DATA_CHUNK: usize = (16 << 10) - FRAME_HDR_LEN;

const FLOW_VISION: &str = "xtls-rprx-vision";
const VLESS_SCHEME: &str = "mlkem768x25519plus";
const VLESS_PLAIN: &str = "none";
const XHTTP_MAX_DATA_CHUNKS: usize = 32;

fn mono_now_ms() -> u64 {
    static EPOCH: OnceLock<std::time::Instant> = OnceLock::new();
    60_000
        + EPOCH
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_millis() as u64
}

pub struct BandwidthLimiter {
    rate: f64,
    burst: f64,
    state: parking_lot::Mutex<LimiterState>,
}

struct LimiterState {
    tokens: f64,
    last: std::time::Instant,
}

impl BandwidthLimiter {
    pub fn new(rate_bps: u64) -> Arc<Self> {
        Self::with_burst_div(rate_bps, 20)
    }

    pub fn with_burst_div(rate_bps: u64, burst_div: u64) -> Arc<Self> {
        let rate = rate_bps as f64;
        let div = burst_div.max(1) as f64;
        let burst = if rate_bps == 0 {
            0.0
        } else {
            (rate / div).max(1.0)
        };
        Arc::new(Self {
            rate,
            burst,
            state: parking_lot::Mutex::new(LimiterState {
                tokens: burst,
                last: std::time::Instant::now(),
            }),
        })
    }

    pub fn read_size(&self, max_len: usize) -> usize {
        if self.rate <= 0.0 {
            return max_len;
        }
        let chunk = ((self.rate / 20.0) as usize).clamp(1, 32 << 10);
        max_len.min(chunk)
    }

    pub async fn wait(&self, n: usize) {
        if n == 0 || self.rate <= 0.0 {
            return;
        }
        let wait_dur = {
            let mut st = self.state.lock();
            let now = std::time::Instant::now();
            let elapsed = now.saturating_duration_since(st.last).as_secs_f64();
            st.last = now;
            st.tokens = (st.tokens + elapsed * self.rate).min(self.burst);
            st.tokens -= n as f64;
            if st.tokens >= 0.0 {
                Duration::ZERO
            } else {
                Duration::from_secs_f64((-st.tokens) / self.rate)
            }
        };
        if !wait_dur.is_zero() {
            tokio::time::sleep(wait_dur).await;
        }
    }
}

fn configure_tcp_stream(tcp: &TcpStream) {
    let _ = tcp.set_nodelay(true);
    let sock_ref = socket2::SockRef::from(tcp);
    let ka = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(20))
        .with_interval(Duration::from_secs(10));
    let _ = sock_ref.set_tcp_keepalive(&ka);
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficBytes {
    pub up: u64,
    pub down: u64,
}

#[derive(Default)]
struct TrafficInner {
    totals: HashMap<String, TrafficBytes>,
    active: Option<HashSet<String>>,
}

#[derive(Default)]
pub struct Traffic {
    inner: Mutex<TrafficInner>,
}

impl Traffic {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&self, id: &str, up: usize, down: usize) {
        if up == 0 && down == 0 {
            return;
        }
        let mut g = self.inner.lock().unwrap();
        if let Some(ref active) = g.active {
            if !active.contains(id) {
                return;
            }
        }
        let entry = g.totals.entry(id.to_string()).or_default();
        const MAX: u64 = (1u64 << 53) - 1;
        if up > 0 {
            entry.up = entry.up.saturating_add(up as u64).min(MAX);
        }
        if down > 0 {
            entry.down = entry.down.saturating_add(down as u64).min(MAX);
        }
    }

    pub fn snapshot(&self) -> HashMap<String, TrafficBytes> {
        self.inner.lock().unwrap().totals.clone()
    }

    pub fn prepare_active(&self, mappings: &[Mapping], server: bool) {
        let mut g = self.inner.lock().unwrap();
        let active = g.active.get_or_insert_with(HashSet::new);
        if server {
            for m in mappings {
                if m.enabled {
                    active.insert(m.id.clone());
                }
            }
        }
    }

    pub fn set_active(&self, mappings: &[Mapping], server: bool) {
        let mut g = self.inner.lock().unwrap();
        let mut active = HashSet::new();
        if server {
            for m in mappings {
                if m.enabled {
                    active.insert(m.id.clone());
                }
            }
        }
        g.totals.retain(|k, _| active.contains(k));
        g.active = Some(active);
    }
}

pub fn xhttp_effective_mode(x: &XHTTP, reality_enabled: bool) -> &'static str {
    match x.mode.as_str() {
        "packet-up" => "packet-up",
        "stream-up" => "stream-up",
        "stream-one" => "stream-one",
        "" | "auto" => {
            if reality_enabled {
                if !x.download_endpoint_id.is_empty() {
                    "stream-up"
                } else {
                    "stream-one"
                }
            } else {
                "packet-up"
            }
        }
        _ => "packet-up",
    }
}

pub fn host_ok(h: &str) -> bool {
    if h.parse::<IpAddr>().is_ok() {
        return true;
    }
    if h.is_empty() || h.len() > 253 || h.to_ascii_lowercase() != h {
        return false;
    }
    for p in h.split('.') {
        if p.is_empty() || p.len() > 63 || p.starts_with('-') || p.ends_with('-') {
            return false;
        }
        if !p
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        {
            return false;
        }
    }
    true
}

pub fn listen_host(h: &str) -> &str {
    if h.is_empty() {
        "127.0.0.1"
    } else {
        h
    }
}

pub fn port_ok(p: i64) -> bool {
    (1..=65535).contains(&p)
}

fn identifier_ok(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.is_empty() || bytes.len() > 128 {
        return false;
    }
    let first = bytes[0];
    if !(first.is_ascii_alphanumeric() || first == b'_' || first == b'-') {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|&c| c.is_ascii_alphanumeric() || c == b'_' || c == b'.' || c == b'-')
}

fn uuid_ok(s: &str) -> bool {
    let re =
        Regex::new(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
            .unwrap();
    re.is_match(s)
}

fn parse_cert_key_pair(cert_pem: &str, key_pem: &str) -> Result<(), String> {
    let mut cert_reader = BufReader::new(Cursor::new(cert_pem.as_bytes()));
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "invalid data-plane certificate or key PEM".to_string())?;
    if certs.is_empty() {
        return Err("invalid data-plane certificate or key PEM".to_string());
    }
    let mut key_reader = BufReader::new(Cursor::new(key_pem.as_bytes()));
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|_| "invalid data-plane certificate or key PEM".to_string())?
        .ok_or_else(|| "invalid data-plane certificate or key PEM".to_string())?;
    let provider = rustls::crypto::ring::default_provider();
    provider
        .key_provider
        .load_private_key(key)
        .map_err(|_| "invalid data-plane certificate or key PEM".to_string())?;
    Ok(())
}

fn check_roots(ca_pem: &str) -> Result<(), String> {
    if ca_pem.is_empty() {
        return Ok(());
    }
    let mut reader = BufReader::new(Cursor::new(ca_pem.as_bytes()));
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "ca_pem contains no valid certificates".to_string())?;
    if certs.is_empty() {
        return Err("ca_pem contains no valid certificates".to_string());
    }
    Ok(())
}

pub fn check_exclusive(role: &str, local: &LocalTLS) -> Result<(), String> {
    let reality = local.reality.enabled();
    let hy = local.hysteria2.enabled();
    let certs =
        !local.cert_pem.is_empty() || !local.key_pem.is_empty() || !local.ca_pem.is_empty();
    if reality && hy {
        return Err("REALITY and Hysteria2 cannot both be set".to_string());
    }
    if reality && certs {
        return Err("REALITY cannot be combined with data-plane certificate PEM".to_string());
    }
    if local.cert_pem.is_empty() != local.key_pem.is_empty() {
        return Err("data-plane certificate and key must be paired".to_string());
    }
    if role == "server" && hy && (local.cert_pem.is_empty() || local.key_pem.is_empty()) {
        return Err("Hysteria2 requires cert_pem and key_pem".to_string());
    }
    if hy && local.hysteria2.password.len() > 128 {
        return Err("Hysteria2 password must be at most 128 bytes".to_string());
    }
    if !local.cert_pem.is_empty() {
        parse_cert_key_pair(&local.cert_pem, &local.key_pem)?;
    }
    check_roots(&local.ca_pem)?;
    Ok(())
}

fn normalize_flow(raw: &str) -> Result<&'static str, String> {
    let trimmed = raw.trim();
    match trimmed {
        "" | VLESS_PLAIN => Ok(""),
        FLOW_VISION | "xtls-rprx-vision-udp443" => Ok(FLOW_VISION),
        _ => Err(format!("unsupported VLESS flow {:?}", trimmed)),
    }
}

fn decryption_enabled(raw: &str) -> bool {
    let text = raw.trim();
    !text.is_empty() && text != VLESS_PLAIN
}

fn validate_flow(c: &LocalTLS) -> Result<(), String> {
    let flow = c.flow.trim();
    if flow.is_empty() || flow == "none" {
        return Ok(());
    }
    if c.effective_protocol() != "vless"
        || c.xhttp.enabled()
        || c.transport_security == "plain"
        || (!c.reality.enabled() && c.transport_security != "tls")
    {
        return Err("Vision requires VLESS TCP with TLS or REALITY".to_string());
    }
    Ok(())
}

fn check_protocol(c: &LocalTLS) -> Result<(), String> {
    validate_flow(c)?;
    match c.effective_protocol() {
        "vless" => {
            if c.hysteria2.enabled() {
                return Err("vless cannot contain hysteria2 settings".to_string());
            }
        }
        "hysteria2" => {
            if !c.hysteria2.enabled() {
                return Err("hysteria2 requires a password".to_string());
            }
            if c.reality.enabled() {
                return Err("REALITY and Hysteria2 cannot both be set".to_string());
            }
            if c.xhttp.enabled() {
                return Err("Hysteria2 cannot use XHTTP".to_string());
            }
            if c.transport_security == "plain" {
                return Err("Hysteria2 cannot use plain security".to_string());
            }
            if !c.flow.is_empty() && c.flow != "none" {
                return Err("Hysteria2 cannot use Vision".to_string());
            }
            if !c.encryption.is_empty() || !c.decryption.is_empty() {
                return Err("Hysteria2 cannot use VLESS Encryption/decryption".to_string());
            }
        }
        _ => return Err("protocol must be vless or hysteria2".to_string()),
    }
    Ok(())
}

fn xhttp_meta_placement(value: &str) -> &str {
    if value.is_empty() {
        "path"
    } else {
        value
    }
}

fn xhttp_meta_key<'a>(key: &'a str, fallback: &'a str) -> &'a str {
    if !key.is_empty() {
        key
    } else {
        fallback
    }
}

fn xhttp_session_table(x: &XHTTP) -> &str {
    match x.session_id_table.as_str() {
        "base62" => "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "hex" => "0123456789abcdef",
        other => other,
    }
}

fn safe_xhttp_meta_query_key(key: &str) -> bool {
    if key.is_empty() || key.len() > 40 || key == "x_padding" {
        return false;
    }
    key.bytes()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
}

fn safe_xhttp_meta_cookie_key(key: &str) -> bool {
    key.starts_with("x_") && safe_xhttp_meta_query_key(key)
}

fn safe_xhttp_meta_header_key(key: &str) -> bool {
    if key.len() <= "X-Veilink-".len() || key.len() > 48 || !key.starts_with("X-Veilink-") {
        return false;
    }
    if !key["X-Veilink-".len()..]
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || c == b'-')
    {
        return false;
    }
    for reserved in ["X-Veilink-EOF", "X-Veilink-Upload-Complete"] {
        if key.eq_ignore_ascii_case(reserved) {
            return false;
        }
    }
    true
}

fn xhttp_session_key(x: &XHTTP) -> &str {
    if xhttp_meta_placement(&x.session_id_placement) == "header" {
        xhttp_meta_key(&x.session_id_key, "X-Veilink-Session")
    } else {
        xhttp_meta_key(&x.session_id_key, "x_session")
    }
}

fn xhttp_sequence_key(x: &XHTTP) -> &str {
    if xhttp_meta_placement(&x.seq_placement) == "header" {
        xhttp_meta_key(&x.seq_key, "X-Veilink-Seq")
    } else {
        xhttp_meta_key(&x.seq_key, "x_seq")
    }
}

fn check_xhttp_meta(x: &XHTTP, mode: &str) -> Result<(), String> {
    for (placement_raw, key) in [
        (&x.session_id_placement, &x.session_id_key),
        (&x.seq_placement, &x.seq_key),
    ] {
        let placement = xhttp_meta_placement(placement_raw);
        match placement {
            "path" => {
                if !key.is_empty() {
                    return Err("xhttp path metadata cannot have a key".to_string());
                }
            }
            "query" => {
                if !key.is_empty() && !safe_xhttp_meta_query_key(key) {
                    return Err("invalid xhttp query metadata key".to_string());
                }
            }
            "cookie" => {
                if !key.is_empty() && !safe_xhttp_meta_cookie_key(key) {
                    return Err("xhttp metadata cookies must use a private x_ key".to_string());
                }
            }
            "header" => {
                if !key.is_empty() && !safe_xhttp_meta_header_key(key) {
                    return Err("invalid xhttp metadata header key".to_string());
                }
            }
            _ => {
                return Err(
                    "xhttp metadata placement must be path, query, header or cookie".to_string(),
                )
            }
        }
    }
    if mode != "packet-up" && (!x.seq_placement.is_empty() || !x.seq_key.is_empty()) {
        return Err("xhttp sequence metadata requires packet-up".to_string());
    }
    if mode == "stream-one"
        && (!x.session_id_placement.is_empty()
            || !x.session_id_key.is_empty()
            || !x.session_id_table.is_empty()
            || x.session_id_length != 0)
    {
        return Err("xhttp stream-one has no session ID metadata".to_string());
    }
    if xhttp_meta_placement(&x.session_id_placement) == xhttp_meta_placement(&x.seq_placement)
        && xhttp_meta_placement(&x.session_id_placement) != "path"
        && xhttp_session_key(x).eq_ignore_ascii_case(xhttp_sequence_key(x))
    {
        return Err("xhttp metadata keys must differ".to_string());
    }
    if x.session_id_table.is_empty() && x.session_id_length == 0 {
        return Ok(());
    }
    if x.session_id_table.is_empty() || !(24..=64).contains(&x.session_id_length) {
        return Err("xhttp custom session ID requires table and length 24-64".to_string());
    }
    let table = xhttp_session_table(x);
    if table.len() < 16
        || table.len() > 64
        || (x.session_id_length as f64) * (table.len() as f64).log2() < 128.0
    {
        return Err("xhttp session ID must retain at least 128 bits of entropy".to_string());
    }
    let mut seen = [false; 256];
    for &c in table.as_bytes() {
        if !(c.is_ascii_alphanumeric() || c == b'-' || c == b'_') || seen[c as usize] {
            return Err(
                "xhttp session table must contain unique URL-safe ASCII characters".to_string(),
            );
        }
        seen[c as usize] = true;
    }
    Ok(())
}

fn xhttp_padding_placement(x: &XHTTP) -> &str {
    if x.padding_placement.is_empty() {
        "query_in_header"
    } else {
        &x.padding_placement
    }
}

fn xhttp_padding_key(x: &XHTTP) -> &str {
    if x.padding_key.is_empty() {
        "x_padding"
    } else {
        &x.padding_key
    }
}

fn xhttp_padding_header(x: &XHTTP) -> &str {
    if !x.padding_header.is_empty() {
        &x.padding_header
    } else if xhttp_padding_placement(x) == "query_in_header" {
        "Referer"
    } else {
        "X-Padding"
    }
}

fn httpguts_valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-')
}

fn check_xhttp_padding(x: &XHTTP, mut mode: &str) -> Result<(), String> {
    if !x.padding_obfs_mode {
        if !x.padding_placement.is_empty()
            || !x.padding_key.is_empty()
            || !x.padding_header.is_empty()
            || !x.padding_method.is_empty()
        {
            return Err("xhttp padding options require padding_obfs_mode".to_string());
        }
        return Ok(());
    }
    if mode.is_empty() || mode == "auto" {
        mode = "packet-up";
    }
    let p = xhttp_padding_placement(x);
    match p {
        "query_in_header" | "query" | "header" | "cookie" => {}
        _ => return Err("invalid xhttp padding_placement".to_string()),
    }
    if !x.padding_method.is_empty()
        && x.padding_method != "repeat-x"
        && x.padding_method != "tokenish"
    {
        return Err("invalid xhttp padding_method".to_string());
    }
    if !x.padding_key.is_empty() && p != "query_in_header" && p != "query" && p != "cookie" {
        return Err("xhttp padding_key not used by placement".to_string());
    }
    if !x.padding_header.is_empty() && p != "query_in_header" && p != "header" {
        return Err("xhttp padding_header not used by placement".to_string());
    }
    let key = xhttp_padding_key(x);
    if p == "cookie" {
        if key != "x_padding" && !safe_xhttp_meta_cookie_key(key) {
            return Err("invalid private xhttp padding cookie key".to_string());
        }
    } else if (p == "query" || p == "query_in_header")
        && !safe_xhttp_meta_query_key(key)
        && key != "x_padding"
    {
        return Err("invalid xhttp padding query key".to_string());
    }
    let mut meta_fields = Vec::new();
    if mode != "stream-one" {
        meta_fields.push((
            xhttp_meta_placement(&x.session_id_placement),
            xhttp_session_key(x),
        ));
    }
    if mode == "packet-up" {
        meta_fields.push((xhttp_meta_placement(&x.seq_placement), xhttp_sequence_key(x)));
    }
    if p == "query" || p == "cookie" || p == "query_in_header" {
        for (f_placement, f_key) in &meta_fields {
            if *f_key == key && (p == "query_in_header" || p == *f_placement) {
                return Err("xhttp padding key collides with metadata".to_string());
            }
        }
    }
    if p == "header" || p == "query_in_header" {
        let header = xhttp_padding_header(x);
        let lower = header.to_ascii_lowercase();
        let valid_custom = lower.starts_with("x-custom-") && lower.len() > "x-custom-".len();
        if !((p == "query_in_header" && lower == "referer")
            || lower == "x-padding"
            || valid_custom)
            || !httpguts_valid_header_name(header)
        {
            return Err("invalid or reserved xhttp padding header".to_string());
        }
        for (_, f_key) in &meta_fields {
            if header.eq_ignore_ascii_case(f_key) {
                return Err("xhttp padding header collides with metadata".to_string());
            }
        }
        let headers = x.headers.entries()?;
        if headers.keys().any(|k| k.eq_ignore_ascii_case(header)) {
            return Err("xhttp padding header collides with custom headers".to_string());
        }
    }
    Ok(())
}

fn check_xhttp_buffer(x: &XHTTP, mode: &str) -> Result<(), String> {
    if !(0..=32).contains(&x.max_buffered_posts) || !(0..=8).contains(&x.max_concurrent_posts) {
        return Err("xhttp buffered/concurrent posts out of range".to_string());
    }
    if (x.max_buffered_posts != 0 || x.max_concurrent_posts != 0) && mode != "packet-up" {
        return Err("xhttp buffered/concurrent posts require packet-up".to_string());
    }
    if x.max_concurrent_posts > x.max_buffered_posts + 1 {
        return Err("xhttp concurrent posts exceed buffer window".to_string());
    }
    Ok(())
}

fn xhttp_data_placement(x: &XHTTP) -> &str {
    if x.uplink_data_placement.is_empty() {
        "body"
    } else {
        &x.uplink_data_placement
    }
}

fn xhttp_data_key(x: &XHTTP) -> &str {
    if !x.uplink_data_key.is_empty() {
        &x.uplink_data_key
    } else if xhttp_data_placement(x) == "header" {
        "X-Veilink-Data"
    } else {
        "x_data"
    }
}

fn xhttp_post_size(x: &XHTTP) -> usize {
    if x.max_each_post_bytes > 0 {
        x.max_each_post_bytes as usize
    } else {
        32 << 10
    }
}

fn xhttp_post_maximum(x: &XHTTP) -> usize {
    if x.post_bytes_max > 0 {
        x.post_bytes_max as usize
    } else {
        xhttp_post_size(x)
    }
}

fn xhttp_padding_minimum(x: &XHTTP) -> i64 {
    if x.padding_bytes > 0 {
        x.padding_bytes
    } else {
        100
    }
}

fn xhttp_padding_maximum(x: &XHTTP) -> i64 {
    if x.padding_max_bytes > 0 {
        x.padding_max_bytes
    } else {
        xhttp_padding_minimum(x)
    }
}

fn xhttp_server_header_limit(x: &XHTTP) -> i64 {
    if x.server_max_header_bytes > 0 {
        x.server_max_header_bytes
    } else {
        8 << 10
    }
}

fn xhttp_data_chunk_size(x: &XHTTP) -> usize {
    if x.uplink_chunk_size > 0 {
        x.uplink_chunk_size as usize
    } else if xhttp_data_placement(x) == "header" {
        4096
    } else if xhttp_data_placement(x) == "cookie" {
        3072
    } else {
        xhttp_post_maximum(x)
    }
}

fn xhttp_upload_limit(x: &XHTTP) -> usize {
    if xhttp_data_placement(x) == "body" {
        return xhttp_post_maximum(x);
    }
    let mut budget =
        xhttp_server_header_limit(x) as isize - 2048 - xhttp_padding_maximum(x) as isize;
    if let Ok(headers) = x.headers.entries() {
        for (key, value) in headers {
            budget -= (key.len() + value.len() + 36) as isize;
        }
    }
    let size = xhttp_data_chunk_size(x);
    if size == 0 || budget <= 0 {
        return 0;
    }
    let (mut low, mut high) = (0usize, xhttp_post_maximum(x));
    while low < high {
        let n = low + (high - low + 1) / 2;
        let encoded = (n * 4).div_ceil(3);
        let chunks = encoded.div_ceil(size);
        let cost = encoded + chunks * (xhttp_data_key(x).len() + 40);
        if chunks <= XHTTP_MAX_DATA_CHUNKS && (cost as isize) <= budget {
            low = n;
        } else {
            high = n - 1;
        }
    }
    low
}

fn check_xhttp_data(x: &XHTTP, mode: &str) -> Result<(), String> {
    let p = xhttp_data_placement(x);
    let mut key = x.uplink_data_key.as_str();
    if !x.uplink_data_placement.is_empty() && p != "body" && p != "header" && p != "cookie" {
        return Err("xhttp uplink_data_placement must be body, header or cookie".to_string());
    }
    if (!x.uplink_data_placement.is_empty() || !key.is_empty() || x.uplink_chunk_size != 0)
        && mode != "packet-up"
    {
        return Err("xhttp uplink data settings require packet-up".to_string());
    }
    if p == "header" {
        if key.is_empty() {
            key = "X-Veilink-Data";
        }
        let re = Regex::new(r"^X-Veilink-[A-Za-z0-9-]{1,48}$").unwrap();
        if !re.is_match(key) || key.eq_ignore_ascii_case("X-Veilink-EOF") {
            return Err(
                "xhttp header uplink data key must be a private X-Veilink header".to_string(),
            );
        }
    }
    if p == "cookie" {
        if key.is_empty() {
            key = "x_data";
        }
        let re = Regex::new(r"^x_[a-z0-9_]{1,48}$").unwrap();
        if !re.is_match(key) {
            return Err("xhttp cookie uplink data key must use private x_ name".to_string());
        }
    }
    if x.uplink_chunk_size != 0 && !(64..=8192).contains(&x.uplink_chunk_size) {
        return Err("xhttp uplink_chunk_size must be 64-8192".to_string());
    }
    if p == "body" && (!x.uplink_data_key.is_empty() || x.uplink_chunk_size != 0) {
        return Err("xhttp body placement cannot configure a data key or chunk size".to_string());
    }
    if p == "header" || p == "cookie" {
        let prefix = if p == "header" {
            format!("{}-", xhttp_data_key(x)).to_ascii_lowercase()
        } else {
            format!("{}_", xhttp_data_key(x))
        };
        for (f_placement, f_key) in [
            (
                xhttp_meta_placement(&x.session_id_placement),
                xhttp_session_key(x),
            ),
            (xhttp_meta_placement(&x.seq_placement), xhttp_sequence_key(x)),
            ("header", "X-Veilink-EOF"),
            ("header", "X-Veilink-Upload-Complete"),
        ] {
            let name = if p == "header" {
                f_key.to_ascii_lowercase()
            } else {
                f_key.to_string()
            };
            if f_placement == p && name.starts_with(&prefix) {
                return Err("xhttp data chunk keys collide with metadata".to_string());
            }
        }
        if p == "cookie"
            && x.padding_obfs_mode
            && xhttp_padding_placement(x) == "cookie"
            && xhttp_padding_key(x).starts_with(&prefix)
        {
            return Err("xhttp data chunk keys collide with padding".to_string());
        }
    }
    if p != "body" && xhttp_upload_limit(x) == 0 {
        return Err("xhttp uplink data has no room within the request header budget".to_string());
    }
    Ok(())
}

fn check_xhttp_mux(x: &XHTTP) -> Result<(), String> {
    let m = &x.xmux;
    if m.max_concurrency < 0
        || m.max_connections < 0
        || m.c_max_reuse_times < 0
        || m.h_max_request_times < 0
        || m.h_max_reusable_secs < 0
        || m.keep_alive_period < 0
    {
        return Err("xhttp xmux values cannot be negative".to_string());
    }
    if m.max_concurrency > 1024
        || m.max_connections > 128
        || m.c_max_reuse_times > 100000
        || m.h_max_request_times > 100000
        || m.h_max_reusable_secs > 86400
        || m.keep_alive_period > 3600
    {
        return Err("xhttp xmux value exceeds limit".to_string());
    }
    Ok(())
}

fn check_xhttp_stream_policy(x: &XHTTP, mode: &str) -> Result<(), String> {
    let (min, max) = (x.stream_up_server_secs, x.stream_up_server_max_secs);
    if min == 0 && max == 0 {
        return Ok(());
    }
    if mode != "stream-up"
        || !(1..=300).contains(&min)
        || !(0..=300).contains(&max)
        || (max != 0 && max < min)
    {
        return Err(
            "xhttp stream-up server interval requires stream-up and 1-300 seconds with ordered bounds"
                .to_string(),
        );
    }
    Ok(())
}

fn canonical_xhttp_path(p: &str) -> bool {
    if p.len() > 256 || !p.starts_with('/') || !p.ends_with('/') || p.contains("//") {
        return false;
    }
    if !p
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || c == b'/' || c == b'_' || c == b'-')
    {
        return false;
    }
    for seg in p.split('/') {
        if seg == "." || seg == ".." {
            return false;
        }
    }
    true
}

pub fn check_transport_security(local: &LocalTLS) -> Result<(), String> {
    check_protocol(local)?;
    match local.transport_security.as_str() {
        "" | "tls" | "plain" => {}
        _ => return Err("transport_security must be tls or plain".to_string()),
    }
    if local.transport_security == "plain" && (local.reality.enabled() || local.hysteria2.enabled())
    {
        return Err(
            "plain transport_security cannot be combined with REALITY or Hysteria2".to_string(),
        );
    }
    let x = &local.xhttp;
    if x.enabled() {
        if x.mode != "packet-up"
            && x.mode != "stream-up"
            && x.mode != "stream-one"
            && x.mode != "auto"
        {
            return Err("xhttp mode must be packet-up, stream-up, stream-one or auto".to_string());
        }
        let mode = xhttp_effective_mode(x, local.reality.enabled());
        check_xhttp_meta(x, mode)?;
        check_xhttp_padding(x, mode)?;
        check_xhttp_buffer(x, mode)?;
        check_xhttp_data(x, mode)?;
        check_xhttp_mux(x)?;
        if !x.download_endpoint_id.is_empty() && mode == "stream-one" {
            return Err("xhttp download_endpoint_id requires packet-up or stream-up".to_string());
        }
        check_xhttp_stream_policy(x, mode)?;
        if !x.host.is_empty()
            && (!host_ok(&x.host)
                || !x.host.contains('.')
                || x.host.contains([':', '[', ']']))
        {
            return Err(
                "xhttp host must be a lowercase DNS name or IPv4 address without a port"
                    .to_string(),
            );
        }
        x.headers.entries()?;
        if !x.uplink_http_method.is_empty()
            && x.uplink_http_method != "POST"
            && x.uplink_http_method != "PUT"
            && x.uplink_http_method != "OPTIONS"
        {
            return Err("xhttp uplink_http_method must be POST, PUT or OPTIONS".to_string());
        }
        if !x.http_version.is_empty()
            && x.http_version != "1.1"
            && x.http_version != "2"
            && x.http_version != "3"
        {
            return Err("xhttp http_version must be 1.1, 2 or 3".to_string());
        }
        if x.http_version == "3"
            && (!x.tls || local.reality.enabled() || local.transport_security != "tls")
        {
            return Err("xhttp HTTP/3 requires direct HTTPS and TLS origin".to_string());
        }
        if mode != "packet-up" && x.http_version == "1.1" {
            return Err("xhttp streaming requires HTTP/2 or HTTP/3".to_string());
        }
        if x.http_version == "2"
            && !x.tls
            && !local.reality.enabled()
            && (mode != "packet-up" || local.transport_security != "plain")
        {
            return Err(
                "xhttp h2c requires packet-up, direct HTTP and plain origin with VLESS encryption"
                    .to_string(),
            );
        }
        if mode != "packet-up"
            && !local.reality.enabled()
            && (!x.tls || local.transport_security != "tls")
        {
            return Err(
                "xhttp streaming modes require direct HTTPS with HTTP/2 or HTTP/3 and TLS origin (or REALITY)"
                    .to_string(),
            );
        }
        if mode == "packet-up" && x.no_grpc_header {
            return Err("xhttp no_grpc_header applies only to streaming modes".to_string());
        }
        if mode != "packet-up" && x.max_each_post_bytes != 0 {
            return Err("xhttp max_each_post_bytes applies only to packet-up".to_string());
        }
        if x.max_each_post_bytes != 0 && !(1024..=32768).contains(&x.max_each_post_bytes) {
            return Err("xhttp max_each_post_bytes must be 1024-32768".to_string());
        }
        if x.post_bytes_max != 0
            && (mode != "packet-up"
                || x.max_each_post_bytes == 0
                || x.post_bytes_max < x.max_each_post_bytes
                || x.post_bytes_max > 32768)
        {
            return Err(
                "xhttp post_bytes_max requires packet-up and max_each_post_bytes <= post_bytes_max <= 32768"
                    .to_string(),
            );
        }
        if x.min_posts_interval_ms != 0
            && (mode != "packet-up" || !(1..=1000).contains(&x.min_posts_interval_ms))
        {
            return Err(
                "xhttp min_posts_interval_ms requires packet-up and 1-1000 ms".to_string(),
            );
        }
        if x.max_posts_interval_ms != 0
            && (mode != "packet-up"
                || x.min_posts_interval_ms == 0
                || x.max_posts_interval_ms < x.min_posts_interval_ms
                || x.max_posts_interval_ms > 1000)
        {
            return Err(
                "xhttp max_posts_interval_ms requires packet-up and min_posts_interval_ms <= max_posts_interval_ms <= 1000"
                    .to_string(),
            );
        }
        if x.request_timeout_seconds != 0 && !(5..=60).contains(&x.request_timeout_seconds) {
            return Err("xhttp request_timeout_seconds must be 5-60".to_string());
        }
        if x.padding_bytes != 0 && !(1..=1000).contains(&x.padding_bytes) {
            return Err("xhttp padding_bytes must be 1-1000".to_string());
        }
        if x.padding_max_bytes != 0
            && (!(1..=1000).contains(&x.padding_max_bytes)
                || x.padding_max_bytes < xhttp_padding_minimum(x))
        {
            return Err(
                "xhttp padding_max_bytes must be between padding_bytes (default 100) and 1000"
                    .to_string(),
            );
        }
        if x.server_max_header_bytes != 0
            && !(8192..=32768).contains(&x.server_max_header_bytes)
        {
            return Err("xhttp server_max_header_bytes must be 8192-32768".to_string());
        }
        if !canonical_xhttp_path(&x.path) {
            return Err(
                "xhttp path must be canonical, begin and end with /, and contain only letters, digits, /, _ or - (maximum 256 bytes)"
                    .to_string(),
            );
        }
        if !local.flow.is_empty() && local.flow != "none" {
            return Err("xhttp cannot be combined with Vision".to_string());
        }
        if local.reality.enabled() && x.tls {
            return Err("xhttp with REALITY must disable xhttp TLS".to_string());
        }
    }
    Ok(())
}

pub fn require_transport_security(local: &LocalTLS) -> Result<(), String> {
    check_transport_security(local)?;
    if local.transport_security.is_empty() && !local.reality.enabled() && !local.hysteria2.enabled()
    {
        return Err("transport_security is required: tls or plain".to_string());
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct CryptSpec {
    xor: u32,
    from: i64,
    to: i64,
    seconds: u32,
    padding: String,
    keys: Vec<Vec<u8>>,
}

fn parse_padding(padding: &str) -> Result<(Vec<[i32; 3]>, Vec<[i32; 3]>), String> {
    if padding.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }
    let mut lens = Vec::new();
    let mut gaps = Vec::new();
    let mut total = 0i32;
    for (i, piece) in padding.split('.').enumerate() {
        let item: Vec<&str> = piece.split('-').collect();
        if item.len() != 3 {
            return Err("invalid VLESS padding".to_string());
        }
        let mut y = [0i32; 3];
        for n in 0..3 {
            y[n] = item[n]
                .parse::<i32>()
                .map_err(|_| "invalid VLESS padding".to_string())?;
            if y[n] < 0 {
                return Err("invalid VLESS padding".to_string());
            }
        }
        if y[1] > y[2] {
            return Err("invalid VLESS padding".to_string());
        }
        if i == 0 && (y[0] < 100 || y[1] < 35 || y[2] < 35) {
            return Err("invalid VLESS padding".to_string());
        }
        if i % 2 == 0 {
            lens.push(y);
            total += y[2];
        } else {
            gaps.push(y);
        }
    }
    if total > 18 + 65535 {
        return Err("invalid VLESS padding".to_string());
    }
    Ok((lens, gaps))
}

fn parse_vless_key(raw: &str, client: bool) -> Result<Option<CryptSpec>, String> {
    let raw = raw.trim();
    if raw.is_empty() || raw == VLESS_PLAIN {
        return Ok(None);
    }
    let label = if client { "encryption" } else { "decryption" };
    let bad = || format!("unsupported VLESS {}", label);
    let parts: Vec<&str> = raw.split('.').collect();
    if parts.len() < 4 || parts[0] != VLESS_SCHEME {
        return Err(bad());
    }
    let mut spec = CryptSpec {
        xor: 0,
        from: 0,
        to: 0,
        seconds: 0,
        padding: String::new(),
        keys: Vec::new(),
    };
    match parts[1] {
        "native" => {}
        "xorpub" => spec.xor = 1,
        "random" => spec.xor = 2,
        _ => return Err(bad()),
    }
    if client {
        match parts[2] {
            "1rtt" => {}
            "0rtt" => spec.seconds = 1,
            _ => return Err(bad()),
        }
    } else {
        let trimmed = parts[2].strip_suffix('s').unwrap_or(parts[2]);
        let span: Vec<&str> = trimmed.splitn(2, '-').collect();
        let from = span[0].parse::<i64>().map_err(|_| bad())?;
        if from < 0 {
            return Err(bad());
        }
        spec.from = from;
        if span.len() == 2 {
            let to = span[1].parse::<i64>().map_err(|_| bad())?;
            if to < from {
                return Err(bad());
            }
            spec.to = to;
        }
    }
    for &part in &parts[3..] {
        if part.len() < 20 {
            if !spec.keys.is_empty() {
                return Err(bad());
            }
            if !spec.padding.is_empty() {
                spec.padding.push('.');
            }
            spec.padding.push_str(part);
            continue;
        }
        let key = URL_SAFE_NO_PAD.decode(part).map_err(|_| bad())?;
        if (client && key.len() != 32 && key.len() != 1184)
            || (!client && key.len() != 32 && key.len() != 64)
        {
            return Err(bad());
        }
        if client && key.len() == 1184 {
            let arr: &[u8; 1184] = key.as_slice().try_into().map_err(|_| bad())?;
            let _ = EncapsulationKey::<MlKem768>::new(arr.into()).map_err(|_| bad())?;
        } else if !client && key.len() == 64 {
            let seed_arr: [u8; 64] = key.as_slice().try_into().map_err(|_| bad())?;
            let _ = DecapsulationKey::<MlKem768>::from_seed(seed_arr.into());
        }
        spec.keys.push(key);
    }
    if spec.keys.is_empty() {
        return Err(bad());
    }
    parse_padding(&spec.padding)?;
    Ok(Some(spec))
}

pub fn check_vless(role: &str, local: &LocalTLS) -> Result<(), String> {
    check_transport_security(local)?;
    if local.effective_protocol() == "hysteria2" {
        return Ok(());
    }
    if role == "server" {
        require_transport_security(local)?;
    }
    if local.transport_security == "plain" {
        if role == "server" && (!local.cert_pem.is_empty() || !local.key_pem.is_empty()) {
            return Err("plain transport_security cannot use server TLS certificate PEM".to_string());
        }
        if (role == "server" && !decryption_enabled(&local.decryption))
            || (role == "client" && !decryption_enabled(&local.encryption))
        {
            return Err("plain transport_security requires VLESS encryption".to_string());
        }
    }
    if local.xhttp.enabled()
        && !local.xhttp.tls
        && !local.reality.enabled()
        && ((role == "server" && !decryption_enabled(&local.decryption))
            || (role == "client" && !decryption_enabled(&local.encryption)))
    {
        return Err("xhttp HTTP dial candidates require VLESS encryption".to_string());
    }
    let flow = normalize_flow(&local.flow)?;
    if !flow.is_empty() {
        if local.hysteria2.enabled() {
            return Err("Vision requires TCP TLS or REALITY, not Hysteria2".to_string());
        }
        if !local.reality.enabled() && local.transport_security == "plain" {
            return Err("Vision requires TCP TLS or REALITY, not raw TCP encryption".to_string());
        }
    }
    if decryption_enabled(&local.decryption) && decryption_enabled(&local.encryption) {
        return Err("decryption and encryption cannot both be set".to_string());
    }
    match role {
        "server" => {
            if decryption_enabled(&local.encryption) {
                return Err("server accepts decryption, not encryption".to_string());
            }
            parse_vless_key(&local.decryption, false)?;
            Ok(())
        }
        "client" => {
            if decryption_enabled(&local.decryption) {
                return Err("client accepts encryption, not decryption".to_string());
            }
            parse_vless_key(&local.encryption, true)?;
            Ok(())
        }
        _ => Ok(()),
    }
}

fn decode_key(s: &str) -> Result<[u8; 32], String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("missing X25519 key".to_string());
    }
    let b = if s.contains(['+', '/', '=']) {
        STANDARD.decode(s)
    } else {
        URL_SAFE_NO_PAD.decode(s)
    }
    .map_err(|_| "X25519 key must be 32 bytes in base64".to_string())?;
    b.try_into()
        .map_err(|_| "X25519 key must be 32 bytes in base64".to_string())
}

fn decode_mldsa_verify(value: &str) -> Result<Vec<u8>, String> {
    let data = URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| STANDARD.decode(value))
        .map_err(|_| "expected base64 encoding of 1952 bytes".to_string())?;
    if data.len() != 1952 {
        return Err("expected base64 encoding of 1952 bytes".to_string());
    }
    Ok(data)
}

fn parse_short_ids(single: &str, list: &str) -> Result<Vec<[u8; 8]>, String> {
    let mut parts = Vec::new();
    if !list.trim().is_empty() {
        parts.extend(list.split(','));
    }
    if !single.trim().is_empty() {
        parts.push(single);
    }
    if parts.is_empty() {
        return Err("REALITY short id required".to_string());
    }
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for p in parts {
        let p = p.trim();
        if p.len() > 16 || p.len() % 2 != 0 {
            return Err(format!(
                "REALITY short id {:?} must be 0 to 16 hex characters",
                p
            ));
        }
        let raw = hex::decode(p).map_err(|_| format!("REALITY short id {:?} must be hex", p))?;
        let mut id = [0u8; 8];
        id[..raw.len()].copy_from_slice(&raw);
        if seen.insert(id) {
            out.push(id);
        }
    }
    Ok(out)
}

fn check_dest(dest: &str) -> Result<(), String> {
    let dest = dest.trim();
    let (host, port) = dest
        .rsplit_once(':')
        .ok_or_else(|| "REALITY dest must be host:port".to_string())?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return Err("REALITY dest must be host:port".to_string());
    }
    let n = port
        .parse::<i64>()
        .map_err(|_| "REALITY dest must be host:port".to_string())?;
    if !port_ok(n) {
        return Err("REALITY dest must be host:port".to_string());
    }
    Ok(())
}

fn parse_go_duration_non_negative(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(Duration::from_secs(180));
    }
    if s.starts_with('-') {
        return Err("REALITY max_time_diff must be a non-negative duration".to_string());
    }
    if s == "0" {
        return Ok(Duration::ZERO);
    }
    let mut rest = s;
    let mut total_nanos: u128 = 0;
    let mut matched = false;
    while !rest.is_empty() {
        let num_end = rest
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .ok_or_else(|| "REALITY max_time_diff must be a non-negative duration".to_string())?;
        if num_end == 0 {
            return Err("REALITY max_time_diff must be a non-negative duration".to_string());
        }
        let num_str = &rest[..num_end];
        let val: f64 = num_str
            .parse()
            .map_err(|_| "REALITY max_time_diff must be a non-negative duration".to_string())?;
        rest = &rest[num_end..];
        let unit_end = rest.find(|c: char| c.is_ascii_digit()).unwrap_or(rest.len());
        let unit = &rest[..unit_end];
        rest = &rest[unit_end..];
        let mult: f64 = match unit {
            "ns" => 1.0,
            "us" | "µs" => 1_000.0,
            "ms" => 1_000_000.0,
            "s" => 1_000_000_000.0,
            "m" => 60.0 * 1_000_000_000.0,
            "h" => 3600.0 * 1_000_000_000.0,
            _ => return Err("REALITY max_time_diff must be a non-negative duration".to_string()),
        };
        total_nanos = total_nanos.saturating_add((val * mult) as u128);
        matched = true;
    }
    if !matched {
        return Err("REALITY max_time_diff must be a non-negative duration".to_string());
    }
    Ok(Duration::from_nanos(total_nanos.min(u64::MAX as u128) as u64))
}

pub fn reality_names(r: &Reality, fallback: &str) -> Result<Vec<String>, String> {
    let parts: Vec<&str> = if !r.server_names.trim().is_empty() {
        r.server_names.split(',').collect()
    } else if !fallback.trim().is_empty() {
        vec![fallback]
    } else {
        Vec::new()
    };
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for p in parts {
        let p = p.trim().to_ascii_lowercase();
        if !host_ok(&p) || p.parse::<IpAddr>().is_ok() || !p.contains('.') {
            return Err(format!("REALITY server name {:?} is invalid", p));
        }
        if seen.insert(p.clone()) {
            out.push(p);
        }
    }
    if out.is_empty() {
        return Err("REALITY server name required".to_string());
    }
    Ok(out)
}

fn check_fingerprint(name: &str) -> Result<(), String> {
    match name.trim().to_ascii_lowercase().as_str() {
        "" | "chrome" | "firefox" | "safari" | "ios" | "edge" => Ok(()),
        _ => Err(format!("unsupported REALITY fingerprint {:?}", name)),
    }
}

fn check_spider_x(raw: &str) -> Result<(), String> {
    let s = raw.trim();
    if s.is_empty() {
        return Ok(());
    }
    if !s.starts_with('/') || s.len() > 256 || s.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err("REALITY spider_x must start with '/' and contain no whitespace".to_string());
    }
    Ok(())
}

fn parse_spider_y(raw: &str) -> Result<Vec<u64>, String> {
    let s = raw.trim();
    if s.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for part in s.split(',') {
        let p = part.trim();
        if p.is_empty() {
            return Err("REALITY spider_y contains an empty delay entry".to_string());
        }
        let v = p
            .parse::<u64>()
            .map_err(|_| "REALITY spider_y must be comma-separated milliseconds (0-10000)".to_string())?;
        if v > 10_000 {
            return Err("REALITY spider_y delay must be at most 10000 ms".to_string());
        }
        out.push(v);
    }
    if out.len() > 10 {
        return Err("REALITY spider_y supports at most 10 entries".to_string());
    }
    Ok(out)
}

pub fn check_reality_server(r: &Reality, fallback: &str) -> Result<(), String> {
    check_dest(&r.dest)?;
    check_spider_x(&r.spider_x)?;
    parse_spider_y(&r.spider_y)?;
    let private = decode_key(&r.private_key).map_err(|e| format!("REALITY private key: {}", e))?;
    if !r.mldsa65_seed.is_empty() {
        let parsed = model::parse_mldsa65_private(&r.mldsa65_seed)
            .map_err(|e| format!("REALITY ML-DSA-65 seed: {}", e))?;
        if parsed.seed == Some(private) || parsed.sk_bytes.as_slice() == private.as_slice() {
            return Err("REALITY ML-DSA-65 seed must differ from X25519 private key".to_string());
        }
        if !r.mldsa65_verify.is_empty() {
            let verify = decode_mldsa_verify(&r.mldsa65_verify)
                .map_err(|e| format!("REALITY ML-DSA-65 verify: {}", e))?;
            if !parsed.pk_bytes.is_empty() {
                if verify != parsed.pk_bytes {
                    return Err("REALITY ML-DSA-65 public key does not match seed".to_string());
                }
            } else {
                let probe_msg = b"veilink mldsa65 pair check";
                let sig = model::sign_mldsa65(&r.mldsa65_seed, probe_msg)
                    .map_err(|e| format!("REALITY ML-DSA-65 seed: {}", e))?;
                if !model::verify_mldsa65(&r.mldsa65_verify, probe_msg, &sig) {
                    return Err("REALITY ML-DSA-65 public key does not match seed".to_string());
                }
            }
        } else if parsed.pk_bytes.is_empty() {
            return Err(
                "REALITY legacy 4032-byte ML-DSA-65 key requires explicit mldsa65_verify"
                    .to_string(),
            );
        }
    } else if !r.mldsa65_verify.is_empty() {
        return Err("REALITY ML-DSA-65 verify requires a server seed".to_string());
    }
    parse_short_ids(&r.short_id, &r.short_ids)?;
    parse_go_duration_non_negative(&r.max_time_diff)?;
    if r.server_names.trim().is_empty() && fallback.trim().is_empty() {
        return Ok(());
    }
    reality_names(r, fallback)?;
    Ok(())
}

pub fn check_reality_client(r: &Reality) -> Result<(), String> {
    if !r.private_key.trim().is_empty()
        || !r.dest.trim().is_empty()
        || !r.short_ids.trim().is_empty()
        || !r.mldsa65_seed.is_empty()
    {
        return Err(
            "client REALITY accepts public_key, short_id and fingerprint only".to_string(),
        );
    }
    decode_key(&r.public_key).map_err(|e| format!("REALITY public key: {}", e))?;
    parse_short_ids(&r.short_id, "")?;
    if !r.mldsa65_verify.is_empty() {
        decode_mldsa_verify(&r.mldsa65_verify)
            .map_err(|e| format!("REALITY ML-DSA-65 verify: {}", e))?;
    }
    check_spider_x(&r.spider_x)?;
    parse_spider_y(&r.spider_y)?;
    check_fingerprint(&r.fingerprint)
}

pub fn check_bootstrap(role: &str, local: &LocalTLS) -> Result<(), String> {
    check_exclusive(role, local)?;
    check_vless(role, local)?;
    match role {
        "server" => {
            if local.reality.enabled() {
                return check_reality_server(&local.reality, "");
            }
            if !local.hysteria2.enabled() && local.transport_security == "plain" {
                return Ok(());
            }
            if local.cert_pem.is_empty() || local.key_pem.is_empty() {
                return Err("server data TLS certificate and key required".to_string());
            }
            Ok(())
        }
        "client" => {
            if local.reality.enabled() {
                return check_reality_client(&local.reality);
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

pub fn derive_client_tunnel(
    client: &LocalTLS,
    server: &LocalTLS,
    node: &Node,
) -> Result<LocalTLS, String> {
    require_transport_security(server)?;
    if !client.is_zero() {
        return Err("client-local tunnel overrides are not allowed".to_string());
    }
    let mut result = model::derive_client_tunnel(server, node);
    if !server.decryption.is_empty() {
        if parse_vless_key(&server.decryption, false)?.is_some() {
            let derived = model::derive_vless_encryption(&server.decryption);
            if derived.is_empty() {
                return Err("unsupported VLESS decryption".to_string());
            }
            result.encryption = derived;
        } else {
            result.encryption = server.decryption.trim().to_string();
        }
    }
    validate_client_template(&result)?;
    Ok(result)
}

pub fn validate_client_template(result: &LocalTLS) -> Result<(), String> {
    if !result.cert_pem.is_empty()
        || !result.key_pem.is_empty()
        || !result.listen_host.is_empty()
        || !result.decryption.is_empty()
        || !result.reality.private_key.is_empty()
        || !result.reality.dest.is_empty()
        || !result.reality.short_ids.is_empty()
        || !result.reality.mldsa65_seed.is_empty()
    {
        return Err("client template contains server-only settings".to_string());
    }
    check_bootstrap("client", result)?;
    parse_vless_key(&result.encryption, true)?;
    Ok(())
}

pub fn public_peer_tunnel(server: &LocalTLS, node: &Node) -> Result<LocalTLS, String> {
    let mut peer = derive_client_tunnel(&LocalTLS::default(), server, node)?;
    peer.cert_pem.clear();
    peer.key_pem.clear();
    peer.hysteria2 = Hysteria2::default();
    Ok(peer)
}

pub fn generate_x25519() -> Result<(String, String), String> {
    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);
    let secret = StaticSecret::from(seed);
    let public = X25519Public::from(&secret);
    Ok((
        URL_SAFE_NO_PAD.encode(secret.to_bytes()),
        URL_SAFE_NO_PAD.encode(public.as_bytes()),
    ))
}

pub fn generate_mldsa65() -> Result<(String, String), String> {
    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);
    let (pk, _sk) = ml_dsa_65::KG::keygen_from_seed(&seed);
    let pub_bytes = pk.into_bytes();
    Ok((
        URL_SAFE_NO_PAD.encode(seed),
        URL_SAFE_NO_PAD.encode(pub_bytes.as_slice()),
    ))
}

fn vless_dot(mode: &str, ticket: &str, key: &[u8]) -> String {
    format!(
        "{}.{}.{}.{}",
        VLESS_SCHEME,
        mode,
        ticket,
        URL_SAFE_NO_PAD.encode(key)
    )
}

pub fn generate_vless_enc() -> Result<(String, String, String, String), String> {
    let mut chosen_priv = None;
    let mut chosen_pub = None;
    for _ in 0..8 {
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        let secret = StaticSecret::from(seed);
        let public = X25519Public::from(&secret);
        if public.as_bytes()[31] <= 127 {
            chosen_priv = Some(secret.to_bytes());
            chosen_pub = Some(*public.as_bytes());
            break;
        }
    }
    let priv_bytes =
        chosen_priv.ok_or_else(|| "VLESS encryption could not generate an X25519 key".to_string())?;
    let pub_bytes = chosen_pub.unwrap();
    let x_dec = vless_dot("native", "600s", &priv_bytes);
    let x_enc = vless_dot("native", "0rtt", &pub_bytes);

    let mut kem_seed = [0u8; 64];
    rand::rng().fill_bytes(&mut kem_seed);
    let dk = DecapsulationKey::<MlKem768>::from_seed(kem_seed.into());
    let ek_bytes = dk.encapsulation_key().to_bytes();
    let pq_dec = vless_dot("native", "600s", &kem_seed);
    let pq_enc = vless_dot("native", "0rtt", ek_bytes.as_slice());
    Ok((x_dec, x_enc, pq_dec, pq_enc))
}

fn idle_server(s: &Snapshot, local: &LocalTLS) -> bool {
    let mut unconfigured = local.clone();
    unconfigured.listen_host.clear();
    unconfigured.listen_port = 0;
    s.node.role == "server" && s.bindings.is_empty() && s.mappings.is_empty() && unconfigured.is_zero()
}

pub fn enabled_endpoints(gateway: &Node) -> Vec<ConnectEndpoint> {
    let mut endpoints = gateway.connect_endpoints.clone();
    if endpoints.is_empty() && !gateway.address.is_empty() && gateway.port > 0 {
        endpoints.push(ConnectEndpoint {
            id: "primary".to_string(),
            name: "primary".to_string(),
            host: gateway.address.clone(),
            port: gateway.port,
            enabled: true,
        });
    }
    endpoints
        .into_iter()
        .filter(|ep| ep.enabled && host_ok(&ep.host) && port_ok(ep.port))
        .collect()
}

fn binding_gateway(mut gateway: Node, b: &Binding) -> Result<Node, String> {
    if gateway.id != b.server_id {
        return Err("binding references a foreign gateway".to_string());
    }
    let all_endpoints = enabled_endpoints(&gateway);
    let mut down_endpoint: Option<ConnectEndpoint> = None;
    if !gateway.tunnel.xhttp.download_endpoint_id.is_empty() {
        for ep in &all_endpoints {
            if ep.id == gateway.tunnel.xhttp.download_endpoint_id {
                down_endpoint = Some(ep.clone());
                break;
            }
        }
        if down_endpoint.is_none() {
            return Err(
                "xhttp download endpoint is not an enabled authorized gateway endpoint".to_string(),
            );
        }
    }
    if b.connect_endpoint_id.is_empty() {
        return Ok(gateway);
    }
    let endpoints = if gateway.connect_endpoints.is_empty() {
        all_endpoints
    } else {
        gateway.connect_endpoints.clone()
    };
    let mut selected: Option<ConnectEndpoint> = None;
    let mut matches = 0;
    for ep in endpoints {
        if ep.id == b.connect_endpoint_id {
            selected = Some(ep);
            matches += 1;
        }
    }
    let selected = selected.ok_or_else(|| {
        "binding connect endpoint is missing, disabled or invalid".to_string()
    })?;
    if matches != 1 || !selected.enabled || !host_ok(&selected.host) || !port_ok(selected.port) {
        return Err("binding connect endpoint is missing, disabled or invalid".to_string());
    }
    let mut next_eps = vec![selected.clone()];
    if let Some(down) = down_endpoint {
        if down.id != selected.id {
            next_eps.push(down);
        }
    }
    gateway.connect_endpoints = next_eps;
    Ok(gateway)
}

fn gateway_client_config(local: &LocalTLS, gateway: &Node) -> Result<LocalTLS, String> {
    if !local.is_zero() {
        return Err("client-local tunnel overrides are not allowed".to_string());
    }
    let config = gateway.tunnel.clone();
    require_transport_security(&config)?;
    validate_client_template(&config)?;
    if config.reality.enabled() {
        reality_names(&config.reality, &gateway.address)?;
    }
    Ok(config)
}

fn mapping_net(network: &str) -> &str {
    if network == "udp" {
        "udp"
    } else {
        "tcp"
    }
}

pub fn validate(s: &Snapshot, local: &LocalTLS) -> Result<(), String> {
    let bad = |msg: &str| Err(format!("invalid snapshot: {}", msg));
    if s.node.role == "client"
        && (!local.is_zero() || !s.node.tunnel.is_zero() || s.node.client_tunnel.is_some())
    {
        return bad("client-local tunnel settings are not allowed; use gateway templates");
    }
    if let Err(e) = check_exclusive(&s.node.role, local) {
        return bad(&e);
    }
    if !idle_server(s, local) && (s.node.role != "client" || s.bindings.is_empty()) {
        if let Err(e) = check_bootstrap(&s.node.role, local) {
            return bad(&e);
        }
    }
    if local.reality.enabled()
        && (!local.cert_pem.is_empty() || !local.key_pem.is_empty() || !local.ca_pem.is_empty())
    {
        return bad("REALITY cannot be combined with data-plane certificate PEM");
    }
    if s.revision < 0
        || !identifier_ok(&s.node.id)
        || s.node.revoked
        || (s.node.role != "server" && s.node.role != "client")
    {
        return bad("node or revision");
    }
    let mut gateways = HashMap::new();
    for n in &s.nodes {
        if !identifier_ok(&n.id) || n.role != "server" || n.revoked {
            return bad("related gateway");
        }
        if gateways.insert(n.id.clone(), n.clone()).is_some() {
            return bad("duplicate gateway");
        }
    }
    if s.node.role == "server" {
        gateways.insert(s.node.id.clone(), s.node.clone());
    }
    let mut bindings = HashMap::new();
    let mut domains = HashSet::new();
    let mut users = HashSet::new();
    let mut pairs = HashSet::new();
    for b in &s.bindings {
        if !identifier_ok(&b.id)
            || !identifier_ok(&b.server_id)
            || !identifier_ok(&b.client_id)
            || !uuid_ok(&b.uuid)
            || !host_ok(&b.domain)
            || b.domain.parse::<IpAddr>().is_ok()
            || !b.domain.contains('.')
        {
            return bad("binding identity or domain");
        }
        let pair = (
            b.server_id.clone(),
            b.client_id.clone(),
            b.connect_endpoint_id.clone(),
        );
        if bindings.contains_key(&b.id)
            || domains.contains(&b.domain)
            || users.contains(&b.uuid.to_ascii_lowercase())
            || pairs.contains(&pair)
        {
            return bad("duplicate binding, domain, identity or association");
        }
        if (s.node.role == "server" && b.server_id != s.node.id)
            || (s.node.role == "client" && b.client_id != s.node.id)
        {
            return bad("foreign binding");
        }
        let n = gateways
            .get(&b.server_id)
            .cloned()
            .ok_or_else(|| "invalid snapshot: missing gateway".to_string())?;
        let n = match binding_gateway(n, b) {
            Ok(g) => g,
            Err(e) => return bad(&e),
        };
        if s.node.role == "client" && enabled_endpoints(&n).is_empty() {
            return bad("gateway has no enabled connect endpoint");
        }
        if s.node.role == "client" {
            if let Err(e) = gateway_client_config(local, &n) {
                return bad(&format!("gateway {}: {}", n.id, e));
            }
        }
        if s.node.role == "client" && !n.tunnel.xhttp.download_endpoint_id.is_empty() {
            let found = enabled_endpoints(&n)
                .iter()
                .any(|ep| ep.id == n.tunnel.xhttp.download_endpoint_id);
            if !found {
                return bad("xhttp download endpoint is not an enabled authorized gateway endpoint");
            }
        }
        bindings.insert(b.id.clone(), b.clone());
        domains.insert(b.domain.clone());
        users.insert(b.uuid.to_ascii_lowercase());
        pairs.insert(pair);
    }

    let mut listeners: Vec<(String, i64, String)> = Vec::new();
    if s.node.role == "server" {
        let listen_port = local.listen_port;
        if !s.bindings.is_empty() && !port_ok(listen_port) {
            return bad("transport listen port");
        }
        if listen_host(&local.listen_host).parse::<IpAddr>().is_err() {
            return bad("transport listen IP");
        }
        if !s.bindings.is_empty() {
            if local.reality.enabled() {
                if let Err(e) = check_reality_server(&local.reality, &s.node.address) {
                    return bad(&e);
                }
            } else if (local.hysteria2.enabled() || local.transport_security == "tls")
                && (local.cert_pem.is_empty() || local.key_pem.is_empty())
            {
                return bad("server TLS certificate and key required");
            }
            let network = if local.hysteria2.enabled()
                || (local.xhttp.enabled() && local.xhttp.http_version == "3")
            {
                "udp"
            } else {
                "tcp"
            };
            listeners.push((
                listen_host(&local.listen_host).to_string(),
                listen_port,
                network.to_string(),
            ));
        }
    }

    let mut ids = HashSet::new();
    let mut names = HashSet::new();
    for m in &s.mappings {
        if let Err(e) = bandwidth_bytes(&m.bandwidth_limit) {
            return bad(&e);
        }
        if let Err(e) = m.effective_mux_type() {
            return bad(&e);
        }
        if !identifier_ok(&m.id)
            || m.name.trim().is_empty()
            || ids.contains(&m.id)
            || names.contains(&m.name)
        {
            return bad("mapping ID or name");
        }
        ids.insert(m.id.clone());
        names.insert(m.name.clone());
        let b = match bindings.get(&m.binding_id) {
            Some(b) => b,
            None => return bad("mapping references missing binding"),
        };
        if m.connect_endpoint_id != b.connect_endpoint_id {
            return bad("mapping connect endpoint differs from binding");
        }
        if !(1..=32).contains(&m.pool) {
            return bad("mapping pool must be from 1 to 32");
        }
        if !m.network.is_empty() && m.network != "tcp" && m.network != "udp" {
            return bad("mapping network");
        }
        if !port_ok(m.listen_port)
            || !port_ok(m.target_port)
            || !host_ok(&m.target_host)
            || listen_host(&m.listen_host).parse::<IpAddr>().is_err()
        {
            return bad("mapping host or port");
        }
        if domains.contains(&m.target_host) {
            return bad("target overlaps reverse control domain");
        }
        if m.enabled && s.node.role == "server" {
            let h = listen_host(&m.listen_host).to_string();
            let ip: IpAddr = h.parse().unwrap();
            let network = mapping_net(&m.network).to_string();
            for (eh, ep, en) in &listeners {
                let eip: IpAddr = eh.parse().unwrap();
                if *en == network
                    && *ep == m.listen_port
                    && (ip == eip || ip.is_unspecified() || eip.is_unspecified())
                {
                    return bad("overlapping listeners");
                }
            }
            listeners.push((h, m.listen_port, network));
        }
    }
    if s.node.role == "client" && s.bindings.is_empty() && local.reality.enabled() {
        if let Err(e) = check_reality_client(&local.reality) {
            return bad(&e);
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct PolicyInbound {
    tag: String,
    listen: String,
    port: i64,
}

#[derive(Serialize)]
struct PolicyMuxSetting {
    enabled: bool,
}

#[derive(Serialize)]
struct PolicyOutbound {
    protocol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    tag: Option<String>,
    #[serde(rename = "allowInsecure", skip_serializing_if = "Option::is_none")]
    allow_insecure: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mux: Option<PolicyMuxSetting>,
}

#[derive(Serialize)]
struct PolicyRule {
    #[serde(rename = "inboundTag", skip_serializing_if = "Vec::is_empty")]
    inbound_tag: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    user: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    domain: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    network: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<String>,
    #[serde(rename = "outboundTag")]
    outbound_tag: String,
}

#[derive(Serialize)]
struct PolicyRouting {
    rules: Vec<PolicyRule>,
}

#[derive(Serialize)]
struct PolicyDoc {
    inbounds: Vec<PolicyInbound>,
    outbounds: Vec<PolicyOutbound>,
    routing: PolicyRouting,
}

fn ordered_snapshot(mut s: Snapshot) -> Snapshot {
    s.nodes.sort_by(|a, b| a.id.cmp(&b.id));
    s.bindings.sort_by(|a, b| a.id.cmp(&b.id));
    s.mappings.sort_by(|a, b| a.id.cmp(&b.id));
    s
}

fn binding_mux(mappings: &[Mapping], binding: &str) -> bool {
    mappings
        .iter()
        .any(|m| m.enabled && m.binding_id == binding && mapping_net(&m.network) == "tcp" && m.mux)
}

pub fn build(s: &Snapshot, local: &LocalTLS) -> Result<Vec<u8>, String> {
    let s = ordered_snapshot(s.clone());
    validate(&s, local)?;
    let mut doc = PolicyDoc {
        inbounds: Vec::new(),
        outbounds: vec![PolicyOutbound {
            protocol: "blackhole".to_string(),
            tag: Some("reject".to_string()),
            allow_insecure: None,
            mux: None,
        }],
        routing: PolicyRouting { rules: Vec::new() },
    };
    if s.node.role == "server" && !s.bindings.is_empty() {
        doc.inbounds.push(PolicyInbound {
            tag: "transport".to_string(),
            listen: listen_host(&local.listen_host).to_string(),
            port: local.listen_port,
        });
    }
    for b in &s.bindings {
        if s.node.role == "server" {
            doc.routing.rules.push(PolicyRule {
                inbound_tag: vec!["transport".to_string()],
                user: vec![b.uuid.to_ascii_lowercase()],
                domain: vec![format!("full:{}", b.domain)],
                network: Some("tcp".to_string()),
                port: Some("0".to_string()),
                outbound_tag: format!("portal-{}", b.id),
            });
        } else {
            let mut protocol = "vless".to_string();
            for gateway in &s.nodes {
                if gateway.id == b.server_id {
                    protocol = gateway.tunnel.effective_protocol().to_string();
                    break;
                }
            }
            doc.outbounds.push(PolicyOutbound {
                protocol,
                tag: Some(format!("tunnel-{}", b.id)),
                allow_insecure: Some(false),
                mux: Some(PolicyMuxSetting {
                    enabled: binding_mux(&s.mappings, &b.id),
                }),
            });
            doc.routing.rules.push(PolicyRule {
                inbound_tag: vec![format!("bridge-{}", b.id)],
                user: Vec::new(),
                domain: vec![format!("full:{}", b.domain)],
                network: Some("tcp".to_string()),
                port: Some("0".to_string()),
                outbound_tag: format!("tunnel-{}", b.id),
            });
        }
    }
    for m in &s.mappings {
        if !m.enabled {
            continue;
        }
        let domain = if m.target_host.parse::<IpAddr>().is_ok() {
            vec![format!("ip:{}", m.target_host)]
        } else {
            vec![format!("full:{}", m.target_host)]
        };
        if s.node.role == "server" {
            let tag = format!("mapping-{}", m.id);
            doc.inbounds.push(PolicyInbound {
                tag: tag.clone(),
                listen: listen_host(&m.listen_host).to_string(),
                port: m.listen_port,
            });
            doc.routing.rules.push(PolicyRule {
                inbound_tag: vec![tag],
                user: Vec::new(),
                domain,
                network: Some("tcp".to_string()),
                port: Some(m.target_port.to_string()),
                outbound_tag: format!("portal-{}", m.binding_id),
            });
        } else {
            doc.routing.rules.push(PolicyRule {
                inbound_tag: vec![format!("bridge-{}", m.binding_id)],
                user: Vec::new(),
                domain,
                network: Some("tcp".to_string()),
                port: Some(m.target_port.to_string()),
                outbound_tag: "authorized".to_string(),
            });
        }
    }
    doc.routing.rules.push(PolicyRule {
        inbound_tag: Vec::new(),
        user: Vec::new(),
        domain: Vec::new(),
        network: Some("tcp,udp".to_string()),
        port: None,
        outbound_tag: "reject".to_string(),
    });
    serde_json::to_vec(&doc).map_err(|e| e.to_string())
}

fn same_configuration(a: &Snapshot, b: &Snapshot) -> bool {
    fn canonical(s: &Snapshot) -> Snapshot {
        let mut s = ordered_snapshot(s.clone());
        s.revision = 0;
        fn clear_status(n: &mut Node) {
            n.name.clear();
            n.mode.clear();
            n.desired_revision = 0;
            n.applied_revision = 0;
            n.exported_revision = 0;
            n.last_seen = 0;
            n.error.clear();
            for ep in &mut n.connect_endpoints {
                ep.name.clear();
            }
        }
        clear_status(&mut s.node);
        for n in &mut s.nodes {
            clear_status(n);
        }
        for m in &mut s.mappings {
            m.name.clear();
        }
        s
    }
    canonical(a) == canonical(b)
}

fn idle_snapshot(s: &Snapshot) -> bool {
    if !s.bindings.is_empty() {
        return false;
    }
    !s.mappings.iter().any(|m| m.enabled)
}

// VLESS v0 + Veilink Multiplexing Framing Helpers
pub fn parse_uuid(text: &str) -> Result<[u8; 16], String> {
    let clean = text.replace('-', "");
    let raw = hex::decode(clean).map_err(|_| "invalid uuid".to_string())?;
    raw.try_into().map_err(|_| "invalid uuid".to_string())
}

pub async fn write_vless<W: AsyncWrite + Unpin>(
    w: &mut W,
    id: [u8; 16],
    host: &str,
    port: u16,
) -> Result<(), String> {
    write_vless_with_flow(w, id, host, port, "").await
}

fn encode_vless_request_into(
    buf: &mut Vec<u8>,
    id: [u8; 16],
    host: &str,
    port: u16,
    flow: &str,
) -> Result<(), String> {
    let addons = vision::encode_flow(flow);
    if addons.len() > 255 {
        return Err("vless addons too large".to_string());
    }
    buf.reserve(32 + addons.len() + host.len());
    buf.push(0); // version 0
    buf.extend_from_slice(&id);
    buf.push(addons.len() as u8);
    buf.extend_from_slice(&addons);
    buf.push(1); // cmd = TCP
    buf.extend_from_slice(&port.to_be_bytes());
    if let Ok(ip) = host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => {
                buf.push(1);
                buf.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                buf.push(3);
                buf.extend_from_slice(&v6.octets());
            }
        }
    } else {
        if host.is_empty() || host.len() > 253 {
            return Err("invalid address".to_string());
        }
        buf.push(2);
        buf.push(host.len() as u8);
        buf.extend_from_slice(host.as_bytes());
    }
    Ok(())
}

pub async fn write_vless_with_flow<W: AsyncWrite + Unpin>(
    w: &mut W,
    id: [u8; 16],
    host: &str,
    port: u16,
    flow: &str,
) -> Result<(), String> {
    let mut buf = Vec::with_capacity(64 + host.len());
    encode_vless_request_into(&mut buf, id, host, port, flow)?;
    w.write_all(&buf).await.map_err(|e| e.to_string())
}

pub async fn read_vless<R: AsyncRead + Unpin>(
    r: &mut R,
) -> Result<([u8; 16], String, u16), String> {
    let (id, host, port, _) = read_vless_with_flow(r).await?;
    Ok((id, host, port))
}

pub async fn read_vless_with_flow<R: AsyncRead + Unpin>(
    r: &mut R,
) -> Result<([u8; 16], String, u16, String), String> {
    let mut head = [0u8; 18];
    r.read_exact(&mut head).await.map_err(|e| e.to_string())?;
    if head[0] != 0 {
        return Err("unsupported vless version".to_string());
    }
    let mut id = [0u8; 16];
    id.copy_from_slice(&head[1..17]);
    let addons = head[17] as usize;
    let mut flow = String::new();
    if addons > 0 {
        let mut addon_buf = vec![0u8; addons];
        r.read_exact(&mut addon_buf)
            .await
            .map_err(|e| e.to_string())?;
        flow = vision::decode_flow(&addon_buf)?;
    }
    let mut rest = [0u8; 4];
    r.read_exact(&mut rest).await.map_err(|e| e.to_string())?;
    if rest[0] != 1 {
        return Err("only tcp is supported".to_string());
    }
    let port = u16::from_be_bytes([rest[1], rest[2]]);
    let host = match rest[3] {
        1 => {
            let mut ip = [0u8; 4];
            r.read_exact(&mut ip).await.map_err(|e| e.to_string())?;
            IpAddr::from(ip).to_string()
        }
        3 => {
            let mut ip = [0u8; 16];
            r.read_exact(&mut ip).await.map_err(|e| e.to_string())?;
            IpAddr::from(ip).to_string()
        }
        2 => {
            let mut len = [0u8; 1];
            r.read_exact(&mut len).await.map_err(|e| e.to_string())?;
            let n = len[0] as usize;
            if n == 0 || n > 253 {
                return Err("invalid domain".to_string());
            }
            let mut domain = vec![0u8; n];
            r.read_exact(&mut domain).await.map_err(|e| e.to_string())?;
            String::from_utf8(domain).map_err(|_| "invalid domain".to_string())?
        }
        _ => return Err("invalid address type".to_string()),
    };
    Ok((id, host, port, flow))
}

pub fn encode_xudp(pkt: &[u8]) -> Vec<u8> {
    mux_proto::encode_xudp_keep(0, pkt)
}

pub fn decode_xudp(frame: &[u8]) -> Result<&[u8], String> {
    mux_proto::decode_xudp_packet(frame).map(|d| d.payload)
}

pub async fn write_frame<W: AsyncWrite + Unpin>(
    w: &mut W,
    kind: u8,
    id: u32,
    payload: &[u8],
) -> Result<(), String> {
    if payload.len() > MAX_PAYLOAD {
        return Err("frame too large".to_string());
    }
    if payload.is_empty() {
        let mut head = [0u8; 7];
        head[0] = kind;
        head[1..5].copy_from_slice(&id.to_be_bytes());
        head[5..7].copy_from_slice(&0u16.to_be_bytes());
        w.write_all(&head).await.map_err(|e| e.to_string())?;
    } else {
        let mut buf = Vec::with_capacity(7 + payload.len());
        append_frame(&mut buf, kind, id, payload)?;
        w.write_all(&buf).await.map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[inline]
fn append_frame(buf: &mut Vec<u8>, kind: u8, id: u32, payload: &[u8]) -> Result<(), String> {
    if payload.len() > MAX_PAYLOAD {
        return Err("frame too large".to_string());
    }
    buf.reserve(FRAME_HDR_LEN + payload.len());
    buf.push(kind);
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    buf.extend_from_slice(payload);
    Ok(())
}

pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<(u8, u32, Vec<u8>), String> {
    let mut head = [0u8; 7];
    r.read_exact(&mut head).await.map_err(|e| e.to_string())?;
    let kind = head[0];
    let id = u32::from_be_bytes([head[1], head[2], head[3], head[4]]);
    let len = u16::from_be_bytes([head[5], head[6]]) as usize;
    if len > MAX_PAYLOAD {
        return Err("frame too large".to_string());
    }
    let mut payload = vec![0u8; len];
    if len > 0 {
        r.read_exact(&mut payload).await.map_err(|e| e.to_string())?;
    }
    Ok((kind, id, payload))
}


#[derive(Clone)]
struct SessionSender {
    ctrl_tx: mpsc::Sender<(u8, u32, Vec<u8>)>,
    data_tx: mpsc::Sender<(u8, u32, Vec<u8>)>,
}

impl SessionSender {
    fn new(
        ctrl_tx: mpsc::Sender<(u8, u32, Vec<u8>)>,
        data_tx: mpsc::Sender<(u8, u32, Vec<u8>)>,
    ) -> Self {
        Self { ctrl_tx, data_tx }
    }

    #[inline]
    fn is_closed(&self) -> bool {
        self.ctrl_tx.is_closed() || self.data_tx.is_closed()
    }

    #[inline]
    async fn send_ctrl(&self, kind: u8, id: u32, payload: Vec<u8>) -> Result<(), ()> {
        self.ctrl_tx.send((kind, id, payload)).await.map_err(|_| ())
    }

    #[inline]
    fn send_ctrl_bg(&self, kind: u8, id: u32, payload: Vec<u8>) {
        if let Err(mpsc::error::TrySendError::Full(item)) =
            self.ctrl_tx.try_send((kind, id, payload))
        {
            if let Ok(rt) = tokio::runtime::Handle::try_current() {
                let tx = self.ctrl_tx.clone();
                rt.spawn(async move {
                    let _ = tx.send(item).await;
                });
            }
        }
    }

    #[inline]
    async fn send_data(&self, kind: u8, id: u32, payload: Vec<u8>) -> Result<(), ()> {
        self.data_tx.send((kind, id, payload)).await.map_err(|_| ())
    }
}

#[derive(Clone)]
struct SessionHandle {
    sender: SessionSender,
    data_max_cap: usize,
    streams: Arc<Mutex<HashMap<u32, mpsc::Sender<(u8, Vec<u8>)>>>>,
    next_id: Arc<AtomicU32>,
    last_rx_ms: Arc<AtomicU64>,
    unanswered_pings: Arc<AtomicU32>,
    ping_sent_ms: Arc<AtomicU64>,
    active_streams: Arc<AtomicUsize>,
    killed: Arc<AtomicBool>,
    kill_tx: watch::Sender<bool>,
}

impl SessionHandle {
    fn new(
        ctrl_tx: mpsc::Sender<(u8, u32, Vec<u8>)>,
        data_tx: mpsc::Sender<(u8, u32, Vec<u8>)>,
        streams: Arc<Mutex<HashMap<u32, mpsc::Sender<(u8, Vec<u8>)>>>>,
    ) -> (Self, watch::Receiver<bool>) {
        let data_max_cap = data_tx.max_capacity();
        let (kill_tx, kill_rx) = watch::channel(false);
        (
            Self {
                sender: SessionSender::new(ctrl_tx, data_tx),
                data_max_cap,
                streams,
                next_id: Arc::new(AtomicU32::new(1)),
                last_rx_ms: Arc::new(AtomicU64::new(mono_now_ms())),
                unanswered_pings: Arc::new(AtomicU32::new(0)),
                ping_sent_ms: Arc::new(AtomicU64::new(0)),
                active_streams: Arc::new(AtomicUsize::new(0)),
                killed: Arc::new(AtomicBool::new(false)),
                kill_tx,
            },
            kill_rx,
        )
    }

    #[inline]
    fn is_closed(&self) -> bool {
        self.killed.load(Ordering::Relaxed) || self.sender.is_closed()
    }

    fn evict(&self) {
        self.killed.store(true, Ordering::Relaxed);
        let _ = self.kill_tx.send(true);
        self.streams.lock().unwrap().clear();
        self.active_streams.store(0, Ordering::Relaxed);
    }

    #[inline]
    fn touch_rx(&self) {
        self.last_rx_ms.store(mono_now_ms(), Ordering::Relaxed);
        self.unanswered_pings.store(0, Ordering::Relaxed);
        self.ping_sent_ms.store(0, Ordering::Relaxed);
    }

    #[inline]
    fn note_ping_sent(&self) {
        let prev = self.unanswered_pings.fetch_add(1, Ordering::Relaxed);
        if prev == 0 {
            self.ping_sent_ms.store(mono_now_ms(), Ordering::Relaxed);
        }
    }

    #[inline]
    fn maybe_probe_on_open(&self) {
        let now = mono_now_ms();
        if now.saturating_sub(self.last_rx_ms.load(Ordering::Relaxed)) >= OPPORTUNISTIC_PING_IDLE_MS
            && self
                .unanswered_pings
                .compare_exchange(0, 1, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            self.ping_sent_ms.store(now, Ordering::Relaxed);
            self.sender.send_ctrl_bg(FRAME_PING, 0, Vec::new());
        }
    }

    #[inline]
    fn is_suspect(&self, now_ms: u64) -> bool {
        let unans = self.unanswered_pings.load(Ordering::Relaxed);
        if unans >= 2 {
            return true;
        }
        if unans == 1 {
            let sent = self.ping_sent_ms.load(Ordering::Relaxed);
            if sent > 0 && now_ms.saturating_sub(sent) > PING_SUSPECT_MS {
                return true;
            }
        }
        false
    }

    #[inline]
    fn load_score(&self) -> usize {
        let active = self.active_streams.load(Ordering::Relaxed);
        let queued = self.data_max_cap.saturating_sub(self.sender.data_tx.capacity());
        active.saturating_mul(4).saturating_add(queued)
    }

    fn open_stream(&self) -> Option<(u32, mpsc::Receiver<(u8, Vec<u8>)>)> {
        if self.is_closed() {
            return None;
        }
        let mut map = self.streams.lock().unwrap();
        if map.len() >= MAX_STREAMS {
            self.active_streams.store(map.len(), Ordering::Relaxed);
            return None;
        }
        let mut id = self.next_id.fetch_add(1, Ordering::Relaxed);
        while id == 0 || map.contains_key(&id) {
            id = self.next_id.fetch_add(1, Ordering::Relaxed);
        }
        let (tx, rx) = mpsc::channel(STREAM_CHAN_CAP);
        map.insert(id, tx);
        self.active_streams.store(map.len(), Ordering::Relaxed);
        Some((id, rx))
    }

    fn close_stream(&self, id: u32) {
        let mut map = self.streams.lock().unwrap();
        map.remove(&id);
        self.active_streams.store(map.len(), Ordering::Relaxed);
    }
}

type SessionMap = Arc<Mutex<HashMap<String, Vec<SessionHandle>>>>;

/// Selects the healthiest, least-loaded session for a binding.
fn pick_session(sessions: &SessionMap, binding_id: &str) -> Option<SessionHandle> {
    static RR: AtomicUsize = AtomicUsize::new(0);
    let now_ms = mono_now_ms();
    let guard = sessions.lock().unwrap();
    let list = guard.get(binding_id)?;
    let alive: Vec<&SessionHandle> = list
        .iter()
        .filter(|h| !h.is_closed() && h.active_streams.load(Ordering::Relaxed) < MAX_STREAMS)
        .collect();
    if alive.is_empty() {
        return None;
    }
    let has_healthy_fresh = alive.iter().any(|h| {
        now_ms.saturating_sub(h.last_rx_ms.load(Ordering::Relaxed)) <= SESSION_FRESH_RX_MS
            && !h.is_suspect(now_ms)
    });
    let has_any_fresh = alive.iter().any(|h| {
        now_ms.saturating_sub(h.last_rx_ms.load(Ordering::Relaxed)) <= SESSION_FRESH_RX_MS
    });
    let start = RR.fetch_add(1, Ordering::Relaxed);
    let n = alive.len();
    let mut best: Option<&SessionHandle> = None;
    let mut best_score = usize::MAX;
    for offset in 0..n {
        let h = alive[(start + offset) % n];
        let is_fresh =
            now_ms.saturating_sub(h.last_rx_ms.load(Ordering::Relaxed)) <= SESSION_FRESH_RX_MS;
        let suspect = h.is_suspect(now_ms);
        if has_healthy_fresh && (!is_fresh || suspect) {
            continue;
        }
        if !has_healthy_fresh && has_any_fresh && !is_fresh {
            continue;
        }
        let ping_penalty = if suspect {
            (h.unanswered_pings.load(Ordering::Relaxed) as usize).saturating_mul(256)
        } else {
            0
        };
        let score = h.load_score().saturating_add(ping_penalty);
        if score < best_score {
            best_score = score;
            best = Some(h);
            if score == 0 {
                break;
            }
        }
    }
    best.or_else(|| alive.first().copied()).cloned()
}

/// Unregister a finished session and drop its stream senders so that every
/// mapping task bound to it observes EOF. Returns true when the binding has
/// no live session left.
#[cfg(test)]
fn remove_session(sessions: &SessionMap, binding_id: &str, handle: &SessionHandle) -> bool {
    remove_session_sync_linked(sessions, None, binding_id, handle).0
}

fn remove_session_sync_linked(
    sessions: &SessionMap,
    linked: Option<&Mutex<HashSet<String>>>,
    binding_id: &str,
    handle: &SessionHandle,
) -> (bool, bool) {
    handle.evict();
    let mut stale_evicted = Vec::new();
    let (empty, unlinked) = {
        let mut map = sessions.lock().unwrap();
        let now_ms = mono_now_ms();
        let is_empty = if let Some(list) = map.get_mut(binding_id) {
            let mut kept = Vec::with_capacity(list.len());
            for h in list.drain(..) {
                if Arc::ptr_eq(&h.streams, &handle.streams) {
                    continue;
                }
                if h.is_closed()
                    || now_ms.saturating_sub(h.last_rx_ms.load(Ordering::Relaxed))
                        > SESSION_STALE_RX_MS
                {
                    stale_evicted.push(h);
                } else {
                    kept.push(h);
                }
            }
            *list = kept;
            if list.is_empty() {
                map.remove(binding_id);
                true
            } else {
                false
            }
        } else {
            true
        };
        let unl = if is_empty {
            linked
                .map(|lk| lk.lock().unwrap().remove(binding_id))
                .unwrap_or(false)
        } else {
            false
        };
        (is_empty, unl)
    };
    for h in stale_evicted {
        h.evict();
    }
    (empty, unlinked)
}

fn spawn_session_writer(
    mut wr: BoxWrite,
    mut ctrl_rx: mpsc::Receiver<(u8, u32, Vec<u8>)>,
    mut data_rx: mpsc::Receiver<(u8, u32, Vec<u8>)>,
    last_rx_ms: Arc<AtomicU64>,
    mut conn_stop: watch::Receiver<bool>,
    mut kill_rx: Option<watch::Receiver<bool>>,
    write_done_tx: watch::Sender<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut write_buf = Vec::with_capacity(65536);
        let mut pending_data: Option<(u8, u32, Vec<u8>)> = None;
        loop {
            write_buf.clear();
            let first = if let Ok(item) = ctrl_rx.try_recv() {
                Some(item)
            } else if let Some(item) = pending_data.take() {
                Some(item)
            } else {
                tokio::select! {
                    biased;
                    msg = ctrl_rx.recv() => match msg {
                        Some(m) => Some(m),
                        None => data_rx.recv().await,
                    },
                    msg = data_rx.recv() => msg,
                }
            };
            let Some((kind, id, payload)) = first else {
                break;
            };
            if append_frame(&mut write_buf, kind, id, &payload).is_err() {
                continue;
            }
            while let Ok((k, i, p)) = ctrl_rx.try_recv() {
                let _ = append_frame(&mut write_buf, k, i, &p);
                if write_buf.len() >= 65536 {
                    break;
                }
            }
            while write_buf.len() < 65536 {
                if let Ok((k, i, p)) = ctrl_rx.try_recv() {
                    let _ = append_frame(&mut write_buf, k, i, &p);
                    continue;
                }
                let next_data = pending_data.take().or_else(|| data_rx.try_recv().ok());
                let Some((k, i, p)) = next_data else {
                    break;
                };
                if p.len() > MAX_PAYLOAD {
                    continue;
                }
                if !write_buf.is_empty() && write_buf.len() + FRAME_HDR_LEN + p.len() > 65536 {
                    pending_data = Some((k, i, p));
                    break;
                }
                let _ = append_frame(&mut write_buf, k, i, &p);
            }
            if write_buf.is_empty() {
                continue;
            }
            let mut write_fut = std::pin::pin!(async {
                wr.write_all(&write_buf).await?;
                wr.flush().await
            });
            let mut write_ok = false;
            loop {
                tokio::select! {
                    res = &mut write_fut => {
                        write_ok = res.is_ok();
                        break;
                    }
                    _ = conn_stop.changed() => {
                        break;
                    }
                    _ = async {
                        match kill_rx.as_mut() {
                            Some(krx) => {
                                let _ = krx.changed().await;
                            }
                            None => std::future::pending::<()>().await,
                        }
                    } => {
                        break;
                    }
                    _ = tokio::time::sleep(SESSION_WRITE_SLICE) => {
                        if mono_now_ms().saturating_sub(last_rx_ms.load(Ordering::Relaxed))
                            > SESSION_READ_TIMEOUT_MS
                        {
                            break;
                        }
                    }
                }
            }
            if !write_ok {
                break;
            }
            if write_buf.capacity() > 256 * 1024 {
                write_buf.shrink_to(65536);
            }
        }
        let _ = write_done_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), wr.shutdown()).await;
    })
}

async fn demux_stream_frame(
    kind: u8,
    id: u32,
    payload: Vec<u8>,
    streams_map: &Mutex<HashMap<u32, mpsc::Sender<(u8, Vec<u8>)>>>,
    active_streams: Option<&AtomicUsize>,
    sender: &SessionSender,
) {
    if kind == FRAME_RESET {
        let removed = {
            let mut map = streams_map.lock().unwrap();
            let r = map.remove(&id);
            if let Some(cnt) = active_streams {
                cnt.store(map.len(), Ordering::Relaxed);
            }
            r
        };
        if let Some(s) = removed {
            let _ = s.try_send((kind, payload));
        }
        return;
    }
    let (stream_tx, stream_count) = {
        let map = streams_map.lock().unwrap();
        (map.get(&id).cloned(), map.len())
    };
    let Some(s) = stream_tx else {
        return;
    };
    match s.try_send((kind, payload)) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full(item)) => {
            let wait_dur = if stream_count <= 1 {
                DEMUX_SINGLE_SEND_TIMEOUT
            } else {
                DEMUX_MULTI_SEND_TIMEOUT
            };
            if tokio::time::timeout(wait_dur, s.send(item)).await.is_err() {
                {
                    let mut map = streams_map.lock().unwrap();
                    map.remove(&id);
                    if let Some(cnt) = active_streams {
                        cnt.store(map.len(), Ordering::Relaxed);
                    }
                }
                sender.send_ctrl_bg(FRAME_RESET, id, Vec::new());
            }
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            let mut map = streams_map.lock().unwrap();
            map.remove(&id);
            if let Some(cnt) = active_streams {
                cnt.store(map.len(), Ordering::Relaxed);
            }
        }
    }
}

struct ServerTransportHandle {
    local: LocalTLS,
    bindings: Arc<parking_lot::RwLock<Vec<Binding>>>,
    stop_tx: watch::Sender<bool>,
    listeners: Vec<std::net::TcpListener>,
    udp_sockets: Vec<std::net::UdpSocket>,
    quic_endpoints: Vec<quinn::Endpoint>,
    tasks: Vec<tokio::task::AbortHandle>,
}

impl ServerTransportHandle {
    fn stop(&mut self) {
        let _ = self.stop_tx.send(true);
        for ep in self.quic_endpoints.drain(..) {
            ep.close(0u32.into(), b"shutdown");
            if let Ok(dummy) = std::net::UdpSocket::bind("127.0.0.1:0") {
                let _ = ep.rebind(dummy);
            }
        }
        for t in self.tasks.drain(..) {
            t.abort();
        }
        for ln in &self.listeners {
            let _ = socket2::SockRef::from(ln).shutdown(std::net::Shutdown::Both);
        }
        self.listeners.clear();
        self.udp_sockets.clear();
    }
}

type LiveLimiter = Arc<parking_lot::RwLock<Arc<BandwidthLimiter>>>;
type Hy2UdpRouteMap = Arc<
    Mutex<HashMap<u32, (SocketAddr, Arc<tokio::net::UdpSocket>, String, LiveLimiter)>>,
>;

struct ServerMappingHandle {
    listen_key: (String, i64, String, bool),
    route: Arc<parking_lot::RwLock<Mapping>>,
    up_limiter: LiveLimiter,
    dn_limiter: LiveLimiter,
    raw_limit: String,
    stop_tx: watch::Sender<bool>,
    listener: Option<std::net::TcpListener>,
    udp_socket: Option<std::net::UdpSocket>,
    task: Option<tokio::task::AbortHandle>,
}

impl ServerMappingHandle {
    fn stop(&mut self) {
        let _ = self.stop_tx.send(true);
        if let Some(t) = self.task.take() {
            t.abort();
        }
        if let Some(ref ln) = self.listener {
            let _ = socket2::SockRef::from(ln).shutdown(std::net::Shutdown::Both);
        }
        self.listener = None;
        self.udp_socket = None;
    }
}

struct ServerRuntime {
    transport: Option<ServerTransportHandle>,
    mappings: HashMap<String, ServerMappingHandle>,
    sessions: SessionMap,
    pending_apps: PendingAppMap,
    mux_pool: MuxPoolMap,
    mux_notify: Arc<tokio::sync::Notify>,
    hy2_sessions: Arc<Mutex<HashMap<String, Vec<Arc<hysteria2::Hy2ServerSession>>>>>,
    hy2_udp_routes: Hy2UdpRouteMap,
    app_req_seq: Arc<AtomicU32>,
    hy2_udp_sid_seq: Arc<AtomicU32>,
}

impl ServerRuntime {
    fn new() -> Self {
        Self {
            transport: None,
            mappings: HashMap::new(),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            pending_apps: Arc::new(Mutex::new(HashMap::new())),
            mux_pool: Arc::new(Mutex::new(HashMap::new())),
            mux_notify: Arc::new(tokio::sync::Notify::new()),
            hy2_sessions: Arc::new(Mutex::new(HashMap::new())),
            hy2_udp_routes: Arc::new(Mutex::new(HashMap::new())),
            app_req_seq: Arc::new(AtomicU32::new(1)),
            hy2_udp_sid_seq: Arc::new(AtomicU32::new(1)),
        }
    }

    fn evict_removed_bindings(
        &self,
        keep_ids: &HashSet<String>,
        linked: &Mutex<HashSet<String>>,
        state_notify: &tokio::sync::Notify,
    ) {
        let mut evicted_handles = Vec::new();
        {
            let mut sg = self.sessions.lock().unwrap();
            sg.retain(|bid, list| {
                if keep_ids.contains(bid) {
                    true
                } else {
                    evicted_handles.extend(list.drain(..));
                    false
                }
            });
        }
        for h in evicted_handles {
            h.evict();
        }
        {
            let mut hg = self.hy2_sessions.lock().unwrap();
            hg.retain(|bid, list| {
                if keep_ids.contains(bid) {
                    true
                } else {
                    for s in list.drain(..) {
                        s.conn.close(0u32.into(), b"binding removed");
                    }
                    false
                }
            });
        }
        self.mux_pool
            .lock()
            .unwrap()
            .retain(|(bid, _), _| keep_ids.contains(bid));
        self.pending_apps
            .lock()
            .unwrap()
            .retain(|(bid, _), _| keep_ids.contains(bid));
        let mut unlinked_any = false;
        {
            let mut lg = linked.lock().unwrap();
            let before = lg.len();
            lg.retain(|bid| keep_ids.contains(bid));
            if lg.len() != before {
                unlinked_any = true;
            }
        }
        if unlinked_any {
            state_notify.notify_waiters();
        }
    }

    fn stop_all(&mut self, linked: &Mutex<HashSet<String>>) {
        for (_, mut mh) in self.mappings.drain() {
            mh.stop();
        }
        if let Some(mut th) = self.transport.take() {
            th.stop();
        }
        let empty = HashSet::new();
        let dummy_notify = tokio::sync::Notify::new();
        self.evict_removed_bindings(&empty, linked, &dummy_notify);
        self.hy2_udp_routes.lock().unwrap().clear();
    }
}

struct ClientSharedTable {
    mappings: parking_lot::RwLock<Vec<Mapping>>,
    limiters: parking_lot::RwLock<HashMap<String, (String, Arc<BandwidthLimiter>)>>,
}

impl ClientSharedTable {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            mappings: parking_lot::RwLock::new(Vec::new()),
            limiters: parking_lot::RwLock::new(HashMap::new()),
        })
    }

    fn sync(&self, next: &[Mapping]) {
        {
            let mut lg = self.limiters.write();
            let enabled_ids: HashSet<&str> = next
                .iter()
                .filter(|m| m.enabled)
                .map(|m| m.id.as_str())
                .collect();
            lg.retain(|id, _| enabled_ids.contains(id.as_str()));
            for m in next {
                if !m.enabled {
                    continue;
                }
                let reuse = lg
                    .get(&m.id)
                    .is_some_and(|(raw, _)| raw == &m.bandwidth_limit);
                if !reuse {
                    let rate_bps = bandwidth_bytes(&m.bandwidth_limit).unwrap_or(0) as u64;
                    lg.insert(
                        m.id.clone(),
                        (m.bandwidth_limit.clone(), BandwidthLimiter::new(rate_bps)),
                    );
                }
            }
        }
        *self.mappings.write() = next.to_vec();
    }

    fn limiter_for_id(&self, id: &str) -> Arc<BandwidthLimiter> {
        if let Some((_, lim)) = self.limiters.read().get(id) {
            return lim.clone();
        }
        BandwidthLimiter::new(0)
    }

    fn limiter_for(&self, m: &Mapping) -> Arc<BandwidthLimiter> {
        if let Some((_, lim)) = self.limiters.read().get(&m.id) {
            return lim.clone();
        }
        let rate_bps = bandwidth_bytes(&m.bandwidth_limit).unwrap_or(0) as u64;
        BandwidthLimiter::new(rate_bps)
    }

    fn find_dial_app(
        &self,
        binding_id: &str,
        host: &str,
        port: i64,
    ) -> Option<(Mapping, Arc<BandwidthLimiter>)> {
        let m = self
            .mappings
            .read()
            .iter()
            .find(|m| {
                m.enabled
                    && m.binding_id == binding_id
                    && mapping_net(&m.network) == "tcp"
                    && m.effective_mux_type().unwrap_or_default().is_empty()
                    && m.target_host == host
                    && m.target_port == port
            })
            .cloned()?;
        let lim = self.limiter_for(&m);
        Some((m, lim))
    }

    fn allow_mux_proto(&self, binding_id: &str, proto_str: &str) -> bool {
        self.mappings.read().iter().any(|m| {
            m.enabled
                && m.binding_id == binding_id
                && mapping_net(&m.network) == "tcp"
                && m.effective_mux_type().unwrap_or_default() == proto_str
        })
    }

    fn find_mux_substream(
        &self,
        binding_id: &str,
        proto_str: &str,
        host: &str,
        port: i64,
    ) -> Option<(Mapping, Arc<BandwidthLimiter>)> {
        let m = self
            .mappings
            .read()
            .iter()
            .find(|m| {
                m.enabled
                    && m.binding_id == binding_id
                    && mapping_net(&m.network) == "tcp"
                    && m.effective_mux_type().unwrap_or_default() == proto_str
                    && m.target_host == host
                    && m.target_port == port
            })
            .cloned()?;
        let lim = self.limiter_for(&m);
        Some((m, lim))
    }

    fn find_frame_open(
        &self,
        binding_id: &str,
        host: &str,
        port: i64,
        has_meta: bool,
        req_net: &str,
        req_mux: &str,
    ) -> Option<(Mapping, Arc<BandwidthLimiter>)> {
        let m = self
            .mappings
            .read()
            .iter()
            .find(|m| {
                if !m.enabled
                    || m.binding_id != binding_id
                    || m.target_host != host
                    || m.target_port != port
                {
                    return false;
                }
                if has_meta {
                    let m_net = mapping_net(&m.network);
                    let m_mux = m.effective_mux_type().unwrap_or_default();
                    m_net == req_net && m_mux == req_mux
                } else {
                    true
                }
            })
            .cloned()?;
        let lim = self.limiter_for(&m);
        Some((m, lim))
    }

    fn find_hy2_udp(
        &self,
        binding_id: &str,
        host: &str,
        port: i64,
    ) -> Option<(Mapping, Arc<BandwidthLimiter>)> {
        let m = self
            .mappings
            .read()
            .iter()
            .find(|m| {
                m.enabled
                    && m.binding_id == binding_id
                    && mapping_net(&m.network) == "udp"
                    && m.target_host == host
                    && m.target_port == port
            })
            .cloned()?;
        let lim = self.limiter_for(&m);
        Some((m, lim))
    }
}

#[derive(Clone, PartialEq)]
struct ClientBindingSpec {
    binding: Binding,
    eps: Vec<ConnectEndpoint>,
    client_cfg: LocalTLS,
    gw_addr: String,
}

struct ClientWorkerHandle {
    stop_tx: watch::Sender<bool>,
    abort: tokio::task::AbortHandle,
}

struct ClientBindingGroup {
    spec: ClientBindingSpec,
    vless_enc_cli: Option<Arc<vless_enc::ClientInstance>>,
    active_workers: Arc<AtomicUsize>,
    workers: Vec<ClientWorkerHandle>,
}

impl ClientBindingGroup {
    fn stop_all(&mut self, linked: &Mutex<HashSet<String>>, state_notify: &tokio::sync::Notify) {
        for w in self.workers.drain(..) {
            let _ = w.stop_tx.send(true);
            w.abort.abort();
        }
        self.active_workers.store(0, Ordering::SeqCst);
        if linked.lock().unwrap().remove(&self.spec.binding.id) {
            state_notify.notify_waiters();
        }
    }
}

struct ClientRuntime {
    shared: Arc<ClientSharedTable>,
    groups: HashMap<String, ClientBindingGroup>,
}

impl ClientRuntime {
    fn new() -> Self {
        Self {
            shared: ClientSharedTable::new(),
            groups: HashMap::new(),
        }
    }

    fn stop_all(&mut self, linked: &Mutex<HashSet<String>>, state_notify: &tokio::sync::Notify) {
        for (_, mut grp) in self.groups.drain() {
            grp.stop_all(linked, state_notify);
        }
        self.shared.sync(&[]);
    }
}

struct RunningInstance {
    role: String,
    linked: Arc<Mutex<HashSet<String>>>,
    server: ServerRuntime,
    client: ClientRuntime,
}

impl RunningInstance {
    fn new(role: &str) -> Self {
        Self {
            role: role.to_string(),
            linked: Arc::new(Mutex::new(HashSet::new())),
            server: ServerRuntime::new(),
            client: ClientRuntime::new(),
        }
    }

    fn stop(&mut self) {
        let dummy_notify = tokio::sync::Notify::new();
        self.server.stop_all(&self.linked);
        self.client.stop_all(&self.linked, &dummy_notify);
        self.linked.lock().unwrap().clear();
    }
}

fn bind_tcp_with_retry(addr: &str) -> std::io::Result<std::net::TcpListener> {
    let sa = resolve_socket_addr_io(addr)?;
    let sock = socket2::Socket::new(
        socket2::Domain::for_address(sa),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    let _ = sock.set_reuse_address(true);
    #[cfg(unix)]
    let _ = sock.set_reuse_port(true);
    sock.bind(&sa.into())?;
    sock.listen(1024)?;
    Ok(sock.into())
}

fn bind_udp_with_retry(addr: &str) -> std::io::Result<std::net::UdpSocket> {
    let sa = resolve_socket_addr_io(addr)?;
    let sock = socket2::Socket::new(
        socket2::Domain::for_address(sa),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    let _ = sock.set_reuse_address(true);
    #[cfg(unix)]
    let _ = sock.set_reuse_port(true);
    let _ = sock.set_recv_buffer_size(4 * 1024 * 1024);
    let _ = sock.set_send_buffer_size(4 * 1024 * 1024);
    sock.bind(&sa.into())?;
    Ok(sock.into())
}

fn resolve_socket_addr_io(addr: &str) -> std::io::Result<SocketAddr> {
    if let Ok(sa) = addr.parse::<SocketAddr>() {
        return Ok(sa);
    }
    addr.to_socket_addrs()?
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid address"))
}

pub(crate) fn fast_crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    static PROVIDER: OnceLock<Arc<rustls::crypto::CryptoProvider>> = OnceLock::new();
    PROVIDER
        .get_or_init(|| {
            let mut p = rustls::crypto::ring::default_provider();
            p.cipher_suites = vec![
                rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256,
                rustls::crypto::ring::cipher_suite::TLS13_AES_256_GCM_SHA384,
                rustls::crypto::ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
                rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                rustls::crypto::ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                rustls::crypto::ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                rustls::crypto::ring::cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            ];
            Arc::new(p)
        })
        .clone()
}

fn build_tls_server_config(local: &LocalTLS) -> Result<Arc<rustls::ServerConfig>, String> {
    let (certs, key) = hysteria2::load_cert_and_key(&local.cert_pem, &local.key_pem)?;
    let provider = fast_crypto_provider();
    let is_vision = normalize_flow(&local.flow).unwrap_or_default() == FLOW_VISION;
    let builder = if is_vision {
        rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| e.to_string())?
    } else {
        rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
    };
    let mut cfg = builder
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| e.to_string())?;
    cfg.alpn_protocols = if local.xhttp.enabled() {
        match xhttp::xhttp_effective_http_version(&local.xhttp, false) {
            "1.1" => vec![b"http/1.1".to_vec()],
            "2" => vec![b"h2".to_vec()],
            _ => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        }
    } else {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    };
    Ok(Arc::new(cfg))
}

fn build_tls_client_config_with_sni(
    local: &LocalTLS,
    enable_sni: bool,
) -> Result<Arc<rustls::ClientConfig>, String> {
    let provider = fast_crypto_provider();
    let is_vision = normalize_flow(&local.flow).unwrap_or_default() == FLOW_VISION;
    let builder = if is_vision {
        rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| e.to_string())?
    } else {
        rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
    };
    let roots: Arc<rustls::RootCertStore> = if !local.ca_pem.trim().is_empty() {
        let mut custom = rustls::RootCertStore::empty();
        let mut reader = BufReader::new(local.ca_pem.as_bytes());
        for cert in rustls_pemfile::certs(&mut reader) {
            let cert = cert.map_err(|e| e.to_string())?;
            custom.add(cert).map_err(|e| e.to_string())?;
        }
        if custom.is_empty() {
            return Err("no valid CA certificates found in ca_pem".to_string());
        }
        Arc::new(custom)
    } else {
        static DEFAULT_ROOTS: OnceLock<Arc<rustls::RootCertStore>> = OnceLock::new();
        DEFAULT_ROOTS
            .get_or_init(|| {
                let mut store = rustls::RootCertStore::empty();
                store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                Arc::new(store)
            })
            .clone()
    };
    let mut cfg = builder.with_root_certificates(roots).with_no_client_auth();
    cfg.alpn_protocols = if local.xhttp.enabled() {
        match xhttp::xhttp_effective_http_version(&local.xhttp, false) {
            "1.1" => vec![b"http/1.1".to_vec()],
            "2" => vec![b"h2".to_vec()],
            _ => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        }
    } else {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    };
    cfg.enable_sni = enable_sni;
    Ok(Arc::new(cfg))
}

fn build_reality_server_cfg(local: &LocalTLS) -> Result<reality::RealityServerConfig, String> {
    let private_key = decode_key(&local.reality.private_key)?;
    let mut short_ids = Vec::new();
    let mut parts = Vec::new();
    if !local.reality.short_ids.trim().is_empty() {
        parts.extend(local.reality.short_ids.split(','));
    }
    if !local.reality.short_id.trim().is_empty() {
        parts.push(local.reality.short_id.as_str());
    }
    for p in parts {
        let p = p.trim();
        if let Ok(raw) = hex::decode(p) {
            let len = raw.len().min(8);
            let mut buf = vec![0u8; 8];
            buf[..len].copy_from_slice(&raw[..len]);
            short_ids.push((buf, len));
        }
    }
    let server_names = reality_names(&local.reality, "").unwrap_or_default();
    let max_time_diff_ms = parse_go_duration_non_negative(&local.reality.max_time_diff)
        .unwrap_or(Duration::from_secs(180))
        .as_millis() as u64;
    Ok(reality::RealityServerConfig {
        private_key,
        short_ids,
        server_names,
        dest: local.reality.dest.trim().to_string(),
        max_time_diff_ms,
        mldsa65_seed: local.reality.mldsa65_seed.trim().to_string(),
        replay_cache: Arc::new(reality::RealityReplayCache::new()),
    })
}

fn build_reality_client_cfg(
    local: &LocalTLS,
    gw_addr: &str,
    domain: &str,
) -> Result<reality::RealityClientConfig, String> {
    let public_key = decode_key(&local.reality.public_key)?;
    let short_id = hex::decode(local.reality.short_id.trim()).unwrap_or_default();
    let names = reality_names(&local.reality, gw_addr).unwrap_or_default();
    let server_name = names
        .first()
        .cloned()
        .unwrap_or_else(|| domain.trim().to_string());
    let alpn = if local.xhttp.enabled() {
        match xhttp::xhttp_effective_http_version(&local.xhttp, true) {
            "1.1" => vec!["http/1.1".to_string()],
            "2" => vec!["h2".to_string()],
            _ => vec!["h2".to_string(), "http/1.1".to_string()],
        }
    } else {
        vec!["h2".to_string(), "http/1.1".to_string()]
    };
    let spider_y = parse_spider_y(&local.reality.spider_y).unwrap_or_default();
    Ok(reality::RealityClientConfig {
        server_name,
        public_key,
        short_id,
        fingerprint: local.reality.fingerprint.clone(),
        alpn,
        mldsa65_verify: local.reality.mldsa65_verify.trim().to_string(),
        spider_x: local.reality.spider_x.trim().to_string(),
        spider_y,
    })
}

async fn accept_outer_vision_inner(
    tcp_stream: TcpStream,
    local: &LocalTLS,
    tls_server_cfg: Option<Arc<rustls::ServerConfig>>,
    reality_cfg: Option<reality::RealityServerConfig>,
) -> Option<vision::VisionInner> {
    let is_vision = normalize_flow(&local.flow).unwrap_or_default() == FLOW_VISION;
    if local.reality.enabled() {
        let rcfg = reality_cfg?;
        match tokio::time::timeout(
            Duration::from_secs(10),
            reality::reality_accept_stream(tcp_stream, &rcfg),
        )
        .await
        {
            Ok(Ok(Some(s))) => Some(vision::VisionInner::Reality(Box::new(s))),
            _ => None,
        }
    } else if !local.cert_pem.is_empty()
        && !local.key_pem.is_empty()
        && (local.transport_security == "tls" || (local.xhttp.enabled() && local.xhttp.tls))
    {
        let cfg = tls_server_cfg?;
        if is_vision && !local.xhttp.enabled() {
            match tokio::time::timeout(
                Duration::from_secs(10),
                vision::RustlsSpliceStream::accept(tcp_stream, cfg),
            )
            .await
            {
                Ok(Ok(s)) => Some(vision::VisionInner::Rustls(Box::new(s))),
                _ => None,
            }
        } else {
            let acceptor = tokio_rustls::TlsAcceptor::from(cfg);
            match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tcp_stream)).await {
                Ok(Ok(s)) => Some(vision::VisionInner::Boxed(Box::new(s))),
                _ => None,
            }
        }
    } else {
        Some(vision::VisionInner::Boxed(Box::new(tcp_stream)))
    }
}

async fn connect_outer_vision_inner(
    remote_addr: SocketAddr,
    local: LocalTLS,
    binding: Binding,
    gw_addr: String,
) -> Result<vision::VisionInner, String> {
    let cert_verify_name = if !gw_addr.trim().is_empty() {
        gw_addr.trim().to_string()
    } else if !binding.domain.trim().is_empty() {
        binding.domain.trim().to_string()
    } else {
        "localhost".to_string()
    };

    let tcp = tokio::time::timeout(Duration::from_secs(8), TcpStream::connect(remote_addr))
        .await
        .map_err(|_| "tcp connect timeout".to_string())?
        .map_err(|e| e.to_string())?;
    configure_tcp_stream(&tcp);

    let is_vision = normalize_flow(&local.flow).unwrap_or_default() == FLOW_VISION;
    if local.reality.enabled() {
        let rcfg = build_reality_client_cfg(&local, &gw_addr, &binding.domain)?;
        let s = tokio::time::timeout(
            Duration::from_secs(8),
            reality::reality_connect_stream(tcp, &rcfg),
        )
        .await
        .map_err(|_| "reality handshake timeout".to_string())?
        .map_err(|e| e.to_string())?;
        Ok(vision::VisionInner::Reality(Box::new(s)))
    } else if local.transport_security == "tls" || (local.xhttp.enabled() && local.xhttp.tls) {
        let cfg_sni = build_tls_client_config_with_sni(&local, true)?;
        let server_name = ServerName::try_from(cert_verify_name)
            .unwrap_or_else(|_| ServerName::try_from("localhost".to_string()).unwrap());
        if is_vision && !local.xhttp.enabled() {
            let first_try = tokio::time::timeout(
                Duration::from_secs(8),
                vision::RustlsSpliceStream::connect(tcp, cfg_sni, server_name.clone()),
            )
            .await;
            match first_try {
                Ok(Ok(s)) => Ok(vision::VisionInner::Rustls(Box::new(s))),
                _ => {
                    let tcp2 = tokio::time::timeout(
                        Duration::from_secs(8),
                        TcpStream::connect(remote_addr),
                    )
                    .await
                    .map_err(|_| "tcp connect timeout".to_string())?
                    .map_err(|e| e.to_string())?;
                    configure_tcp_stream(&tcp2);
                    let cfg_no_sni = build_tls_client_config_with_sni(&local, false)?;
                    let s2 = tokio::time::timeout(
                        Duration::from_secs(8),
                        vision::RustlsSpliceStream::connect(tcp2, cfg_no_sni, server_name),
                    )
                    .await
                    .map_err(|_| "tls handshake timeout".to_string())?
                    .map_err(|e| e.to_string())?;
                    Ok(vision::VisionInner::Rustls(Box::new(s2)))
                }
            }
        } else {
            let connector = tokio_rustls::TlsConnector::from(cfg_sni);
            let first_try = tokio::time::timeout(
                Duration::from_secs(8),
                connector.connect(server_name.clone(), tcp),
            )
            .await;
            let s = match first_try {
                Ok(Ok(s)) => s,
                _ => {
                    let tcp2 = tokio::time::timeout(
                        Duration::from_secs(8),
                        TcpStream::connect(remote_addr),
                    )
                    .await
                    .map_err(|_| "tcp connect timeout".to_string())?
                    .map_err(|e| e.to_string())?;
                    configure_tcp_stream(&tcp2);
                    let no_sni_connector = tokio_rustls::TlsConnector::from(
                        build_tls_client_config_with_sni(&local, false)?,
                    );
                    tokio::time::timeout(
                        Duration::from_secs(8),
                        no_sni_connector.connect(server_name, tcp2),
                    )
                    .await
                    .map_err(|_| "tls handshake timeout".to_string())?
                    .map_err(|e| e.to_string())?
                }
            };
            Ok(vision::VisionInner::Boxed(Box::new(s)))
        }
    } else {
        Ok(vision::VisionInner::Boxed(Box::new(tcp)))
    }
}

async fn connect_outer_stream(
    remote_addr: SocketAddr,
    local: LocalTLS,
    binding: Binding,
    gw_addr: String,
) -> Result<BoxStream, String> {
    Ok(connect_outer_vision_inner(remote_addr, local, binding, gw_addr)
        .await?
        .into_box_stream())
}

type PendingAppMap = Arc<Mutex<HashMap<(String, u32), tokio::sync::oneshot::Sender<BoxStream>>>>;
type MuxPoolMap = Arc<Mutex<HashMap<(String, String), Vec<Arc<mux_proto::SingMuxOpener>>>>>;

async fn accept_reverse_subchannel(
    mut stream: BoxStream,
    port: u16,
    binding: &Binding,
    pending_apps: &PendingAppMap,
    mux_pool: &MuxPoolMap,
    mux_notify: &Arc<tokio::sync::Notify>,
) {
    match port {
        mux_proto::PORT_APPLICATION => {
            let mut hdr = [0u8; 26];
            if tokio::time::timeout(Duration::from_secs(8), stream.read_exact(&mut hdr))
                .await
                .map_or(true, |r| r.is_err())
            {
                return;
            }
            if &hdr[..22] != mux_proto::APP_STREAM_PREFACE {
                return;
            }
            let req_id = u32::from_be_bytes([hdr[22], hdr[23], hdr[24], hdr[25]]);
            let tx_opt = pending_apps
                .lock()
                .unwrap()
                .remove(&(binding.id.clone(), req_id));
            if let Some(tx) = tx_opt {
                let _ = tx.send(stream);
            }
        }
        mux_proto::PORT_SING_MUX => {
            let mut hdr = [0u8; 21];
            if tokio::time::timeout(Duration::from_secs(8), stream.read_exact(&mut hdr))
                .await
                .map_or(true, |r| r.is_err())
            {
                return;
            }
            if &hdr[..19] != mux_proto::SING_MUX_PREFACE || hdr[19] != 0x00 {
                return;
            }
            let Some(proto) = mux_proto::SingMuxProto::from_wire_byte(hdr[20]) else {
                return;
            };
            let Ok(opener) = mux_proto::SingMuxOpener::new(stream, proto).await else {
                return;
            };
            {
                let mut g = mux_pool.lock().unwrap();
                let list = g
                    .entry((binding.id.clone(), proto.as_str().to_string()))
                    .or_default();
                list.retain(|o| !o.is_closed());
                while list.len() >= 16 {
                    list.remove(0);
                }
                list.push(opener);
            }
            mux_notify.notify_waiters();
        }
        _ => {}
    }
}

#[allow(clippy::too_many_arguments)]
async fn serve_vless_session(
    mut outer: vision::VisionInner,
    local: LocalTLS,
    vless_dec: Option<Arc<vless_enc::ServerInstance>>,
    bindings: Vec<Binding>,
    sessions: SessionMap,
    pending_apps: PendingAppMap,
    mux_pool: MuxPoolMap,
    mux_notify: Arc<tokio::sync::Notify>,
    linked: Arc<Mutex<HashSet<String>>>,
    state_notify: Arc<tokio::sync::Notify>,
    logger: TunnelLogger,
    mut conn_stop: watch::Receiver<bool>,
) {
    if *conn_stop.borrow() {
        return;
    }
    if let Some(dec) = vless_dec {
        let raw_stream = outer.into_box_stream();
        tokio::select! {
            _ = conn_stop.changed() => return,
            res = tokio::time::timeout(Duration::from_secs(8), dec.handshake(raw_stream)) => {
                match res {
                    Ok(Ok(s)) => outer = vision::VisionInner::Boxed(s),
                    Ok(Err(e)) => {
                        let lvl = if e == "expired ticket" { "INFO" } else { "WARN" };
                        log_tunnel(
                            &logger,
                            lvl,
                            format!("server vless decryption handshake rejected role=server err={}", e),
                        );
                        return;
                    }
                    Err(_) => {
                        log_tunnel(
                            &logger,
                            "WARN",
                            "server vless decryption handshake timeout role=server".to_string(),
                        );
                        return;
                    }
                }
            }
        }
    }

    struct VisionInnerIo<'a>(&'a mut vision::VisionInner);
    impl AsyncRead for VisionInnerIo<'_> {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            match &mut *self.0 {
                vision::VisionInner::Boxed(s) => std::pin::Pin::new(s).poll_read(cx, buf),
                vision::VisionInner::Reality(s) => std::pin::Pin::new(s).poll_read(cx, buf),
                vision::VisionInner::Rustls(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            }
        }
    }
    impl AsyncWrite for VisionInnerIo<'_> {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            match &mut *self.0 {
                vision::VisionInner::Boxed(s) => std::pin::Pin::new(s).poll_write(cx, buf),
                vision::VisionInner::Reality(s) => std::pin::Pin::new(s).poll_write(cx, buf),
                vision::VisionInner::Rustls(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            }
        }
        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            match &mut *self.0 {
                vision::VisionInner::Boxed(s) => std::pin::Pin::new(s).poll_flush(cx),
                vision::VisionInner::Reality(s) => std::pin::Pin::new(s).poll_flush(cx),
                vision::VisionInner::Rustls(s) => std::pin::Pin::new(s).poll_flush(cx),
            }
        }
        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            match &mut *self.0 {
                vision::VisionInner::Boxed(s) => std::pin::Pin::new(s).poll_shutdown(cx),
                vision::VisionInner::Reality(s) => std::pin::Pin::new(s).poll_shutdown(cx),
                vision::VisionInner::Rustls(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            }
        }
    }

    let (uuid_bytes, domain, port, client_flow) = tokio::select! {
        _ = conn_stop.changed() => return,
        res = tokio::time::timeout(Duration::from_secs(8), async {
            let mut io = VisionInnerIo(&mut outer);
            read_vless_with_flow(&mut io).await
        }) => {
            match res {
                Ok(Ok(v)) => v,
                Ok(Err(e)) => {
                    log_tunnel(
                        &logger,
                        "WARN",
                        format!("server vless request header failed role=server err={}", e),
                    );
                    return;
                }
                Err(_) => {
                    log_tunnel(
                        &logger,
                        "WARN",
                        "server vless request header timeout role=server".to_string(),
                    );
                    return;
                }
            }
        }
    };
    let expected_flow = normalize_flow(&local.flow).unwrap_or_default();
    if client_flow != expected_flow {
        log_tunnel(
            &logger,
            "WARN",
            format!(
                "server vless flow mismatch role=server expected={} got={}",
                expected_flow, client_flow
            ),
        );
        return;
    }
    let Some(binding) = bindings
        .iter()
        .find(|b| {
            parse_uuid(&b.uuid).ok() == Some(uuid_bytes)
                && b.domain.eq_ignore_ascii_case(&domain)
        })
        .cloned()
    else {
        log_tunnel(
            &logger,
            "WARN",
            format!(
                "server vless binding not matched role=server domain={}",
                domain
            ),
        );
        return;
    };
    let stream: BoxStream = if expected_flow == FLOW_VISION {
        let mut resp_flight = Vec::with_capacity(1500);
        resp_flight.extend_from_slice(&[0, 0]);
        vision::append_initial_camouflage(&mut resp_flight, &uuid_bytes);
        {
            let mut io = VisionInnerIo(&mut outer);
            if io.write_all(&resp_flight).await.is_err() || io.flush().await.is_err() {
                return;
            }
        }
        vision::wrap_vision_inner_started(outer, uuid_bytes)
    } else {
        let mut s = outer.into_box_stream();
        if s.write_all(&[0, 0]).await.is_err() || s.flush().await.is_err() {
            return;
        }
        s
    };

    if port == mux_proto::PORT_APPLICATION || port == mux_proto::PORT_SING_MUX {
        accept_reverse_subchannel(
            stream,
            port,
            &binding,
            &pending_apps,
            &mux_pool,
            &mux_notify,
        )
        .await;
        return;
    }

    serve_established_session(
        stream,
        binding,
        sessions,
        Some(pending_apps),
        linked,
        state_notify,
        logger,
        conn_stop,
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn serve_established_session(
    stream: BoxStream,
    binding: Binding,
    sessions: SessionMap,
    pending_apps: Option<PendingAppMap>,
    linked: Arc<Mutex<HashSet<String>>>,
    state_notify: Arc<tokio::sync::Notify>,
    logger: TunnelLogger,
    mut conn_stop: watch::Receiver<bool>,
) {
    if *conn_stop.borrow() {
        return;
    }
    let (ctrl_tx, ctrl_rx) = mpsc::channel::<(u8, u32, Vec<u8>)>(SESSION_CTRL_CHAN_CAP);
    let (data_tx, data_rx) = mpsc::channel::<(u8, u32, Vec<u8>)>(SESSION_DATA_CHAN_CAP);
    let streams_map: Arc<Mutex<HashMap<u32, mpsc::Sender<(u8, Vec<u8>)>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let (handle, mut kill_rx) = SessionHandle::new(ctrl_tx, data_tx, streams_map.clone());
    let mut to_evict = Vec::new();
    let newly_linked = {
        let now_ms = mono_now_ms();
        let mut guard = sessions.lock().unwrap();
        let list = guard.entry(binding.id.clone()).or_default();
        let mut kept = Vec::with_capacity(list.len() + 1);
        for h in list.drain(..) {
            if h.is_closed()
                || now_ms.saturating_sub(h.last_rx_ms.load(Ordering::Relaxed))
                    > SESSION_STALE_RX_MS
            {
                to_evict.push(h);
            } else {
                kept.push(h);
            }
        }
        while kept.len() >= MAX_BINDING_SESSIONS {
            if let Some((oldest_idx, _)) = kept
                .iter()
                .enumerate()
                .min_by_key(|(_, h)| h.last_rx_ms.load(Ordering::Relaxed))
            {
                to_evict.push(kept.remove(oldest_idx));
            } else {
                break;
            }
        }
        kept.push(handle.clone());
        *list = kept;
        linked.lock().unwrap().insert(binding.id.clone())
    };
    for h in to_evict {
        h.evict();
    }
    if newly_linked {
        log_tunnel(
            &logger,
            "INFO",
            format!(
                "server tunnel session established role=server binding_id={} client_id={}",
                binding.id, binding.client_id
            ),
        );
        state_notify.notify_waiters();
    }
    let (mut rd, wr) = split_tunnel_stream(stream);
    let (write_done_tx, mut write_done_rx) = watch::channel(false);
    let write_task = spawn_session_writer(
        wr,
        ctrl_rx,
        data_rx,
        handle.last_rx_ms.clone(),
        conn_stop.clone(),
        Some(kill_rx.clone()),
        write_done_tx,
    );
    let handle_ping = handle.clone();
    let ping_task = tokio::spawn(async move {
        let mut ping_interval = tokio::time::interval(PING_INTERVAL);
        ping_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ping_interval.tick().await;
        loop {
            ping_interval.tick().await;
            handle_ping.note_ping_sent();
            if handle_ping
                .sender
                .send_ctrl(FRAME_PING, 0, Vec::new())
                .await
                .is_err()
            {
                break;
            }
        }
    });
    loop {
        tokio::select! {
            _ = conn_stop.changed() => break,
            _ = kill_rx.changed() => break,
            _ = write_done_rx.changed() => break,
            frame = tokio::time::timeout(SESSION_READ_TIMEOUT, read_frame(&mut rd)) => {
                let Ok(Ok((kind, id, payload))) = frame else { break };
                handle.touch_rx();
                match kind {
                    FRAME_PING => {
                        handle.sender.send_ctrl_bg(FRAME_PONG, 0, Vec::new());
                    }
                    FRAME_PONG => {}
                    FRAME_DATA | FRAME_HALF | FRAME_RESET => {
                        if kind == FRAME_RESET {
                            if let Some(ref pa) = pending_apps {
                                pa.lock().unwrap().remove(&(binding.id.clone(), id));
                            }
                        }
                        demux_stream_frame(
                            kind,
                            id,
                            payload,
                            &streams_map,
                            Some(&handle.active_streams),
                            &handle.sender,
                        )
                        .await;
                    }
                    _ => break,
                }
            }
        }
    }
    ping_task.abort();
    write_task.abort();
    let (was_last, unlinked) =
        remove_session_sync_linked(&sessions, Some(&linked), &binding.id, &handle);
    if unlinked {
        state_notify.notify_waiters();
    }
    if was_last {
        log_tunnel(
            &logger,
            "INFO",
            format!(
                "server tunnel session closed role=server binding_id={} client_id={}",
                binding.id, binding.client_id
            ),
        );
    }
}

fn start_server_transport(
    bindings_init: &[Binding],
    local: &LocalTLS,
    server: &ServerRuntime,
    traffic: Arc<Traffic>,
    linked: Arc<Mutex<HashSet<String>>>,
    state_notify: Arc<tokio::sync::Notify>,
    logger: TunnelLogger,
) -> Result<ServerTransportHandle, String> {
    let (stop_tx, stop_rx) = watch::channel(false);
    let bindings_live = Arc::new(parking_lot::RwLock::new(bindings_init.to_vec()));
    let mut listeners = Vec::new();
    let mut udp_sockets = Vec::new();
    let mut quic_endpoints = Vec::new();
    let mut tasks = Vec::new();

    let mut transport_ln: Option<std::net::TcpListener> = None;
    let mut transport_udp: Option<std::net::UdpSocket> = None;
    let addr = format!("{}:{}", listen_host(&local.listen_host), local.listen_port);
    if local.hysteria2.enabled() || (local.xhttp.enabled() && local.xhttp.http_version == "3") {
        let sock = bind_udp_with_retry(&addr)
            .map_err(|e| format!("bind transport udp {}: {}", addr, e))?;
        if let Ok(cloned) = sock.try_clone() {
            transport_udp = Some(cloned);
        }
        udp_sockets.push(sock);
        if local.xhttp.enabled() {
            if let Ok(ln) = bind_tcp_with_retry(&addr) {
                if let Ok(cloned) = ln.try_clone() {
                    transport_ln = Some(cloned);
                }
                listeners.push(ln);
            }
        }
    } else {
        let ln = bind_tcp_with_retry(&addr)
            .map_err(|e| format!("bind transport tcp {}: {}", addr, e))?;
        if let Ok(cloned) = ln.try_clone() {
            transport_ln = Some(cloned);
        }
        listeners.push(ln);
    }
    log_tunnel(
        &logger,
        "INFO",
        format!(
            "server tunnel listening role=server protocol={} addr={}",
            local.effective_protocol(),
            addr
        ),
    );

    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        let shared_xhttp_state = if local.xhttp.enabled() {
            Some(xhttp::XhttpServerState::new())
        } else {
            None
        };
        if local.hysteria2.enabled() {
            if let Some(std_udp) = transport_udp {
                let server_cfg = hysteria2::build_quic_server_config(local)?;
                if let Ok(quic_ep) = quinn::Endpoint::new(
                    quinn::EndpointConfig::default(),
                    Some(server_cfg),
                    std_udp,
                    Arc::new(quinn::TokioRuntime),
                ) {
                    quic_endpoints.push(quic_ep.clone());
                    let bindings_ref = bindings_live.clone();
                    let local_clone = local.clone();
                    let sessions_clone = server.sessions.clone();
                    let pending_apps_c = server.pending_apps.clone();
                    let mux_pool_c = server.mux_pool.clone();
                    let mux_notify_c = server.mux_notify.clone();
                    let hy2_sessions_c = server.hy2_sessions.clone();
                    let hy2_udp_routes_c = server.hy2_udp_routes.clone();
                    let traffic_hy2 = traffic.clone();
                    let linked_clone = linked.clone();
                    let notify_clone = state_notify.clone();
                    let logger_clone = logger.clone();
                    let mut rx = stop_rx.clone();
                    let jh = handle.spawn(async move {
                        loop {
                            tokio::select! {
                                _ = rx.changed() => {
                                    quic_ep.close(0x100u32.into(), b"shutdown");
                                    break;
                                }
                                inc = quic_ep.accept() => {
                                    let Some(incoming) = inc else { break };
                                    let bindings_snap = bindings_ref.read().clone();
                                    let local_c = local_clone.clone();
                                    let sessions = sessions_clone.clone();
                                    let pa = pending_apps_c.clone();
                                    let mp = mux_pool_c.clone();
                                    let mn = mux_notify_c.clone();
                                    let hs_map = hy2_sessions_c.clone();
                                    let udp_routes = hy2_udp_routes_c.clone();
                                    let t_hy2 = traffic_hy2.clone();
                                    let linked = linked_clone.clone();
                                    let notify_c = notify_clone.clone();
                                    let log_c = logger_clone.clone();
                                    let mut conn_stop = rx.clone();
                                    tokio::spawn(async move {
                                        let Ok(Ok(conn)) = tokio::time::timeout(
                                            Duration::from_secs(10),
                                            incoming,
                                        ).await else {
                                            return;
                                        };
                                        let Ok(hy2_sess) =
                                            hysteria2::hy2_accept_authenticated(conn, &local_c, &bindings_snap).await
                                        else {
                                            return;
                                        };
                                        let binding_id = hy2_sess.binding.id.clone();
                                        {
                                            let mut g = hs_map.lock().unwrap();
                                            let list = g.entry(binding_id.clone()).or_default();
                                            list.retain(|x| x.conn.close_reason().is_none());
                                            list.push(hy2_sess.clone());
                                        }
                                        let dgram_conn = hy2_sess.conn.clone();
                                        let mut dgram_stop = conn_stop.clone();
                                        let dgram_task = tokio::spawn(async move {
                                            let mut defrag = hysteria2::Hy2UdpDefragmenter::new();
                                            loop {
                                                tokio::select! {
                                                    _ = dgram_stop.changed() => break,
                                                    dg_res = dgram_conn.read_datagram() => {
                                                        let Ok(dg) = dg_res else { break };
                                                        if let Some((sid, _addr, payload)) = defrag.push(&dg) {
                                                            let route = udp_routes.lock().unwrap().get(&sid).cloned();
                                                            if let Some((peer_sa, sock, mid, dn_lim_ref)) = route {
                                                                let cur_lim = dn_lim_ref.read().clone();
                                                                cur_lim.wait(payload.len()).await;
                                                                t_hy2.add(&mid, 0, payload.len());
                                                                let _ = sock.send_to(&payload, peer_sa).await;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        });
                                        loop {
                                            tokio::select! {
                                                _ = conn_stop.changed() => break,
                                                accepted = hysteria2::hy2_accept_tcp_stream(&hy2_sess) => {
                                                    let Ok((stream, _host, port)) = accepted else {
                                                        if hy2_sess.conn.close_reason().is_some() {
                                                            break;
                                                        }
                                                        continue;
                                                    };
                                                    let b_st = hy2_sess.binding.clone();
                                                    let s_st = sessions.clone();
                                                    let pa_st = pa.clone();
                                                    let mp_st = mp.clone();
                                                    let mn_st = mn.clone();
                                                    let l_st = linked.clone();
                                                    let n_st = notify_c.clone();
                                                    let lg_st = log_c.clone();
                                                    let cs_st = conn_stop.clone();
                                                    tokio::spawn(async move {
                                                        if port == mux_proto::PORT_APPLICATION
                                                            || port == mux_proto::PORT_SING_MUX
                                                        {
                                                            accept_reverse_subchannel(
                                                                stream, port, &b_st, &pa_st, &mp_st, &mn_st,
                                                            )
                                                            .await;
                                                        } else {
                                                            serve_established_session(
                                                                stream,
                                                                b_st,
                                                                s_st,
                                                                Some(pa_st),
                                                                l_st,
                                                                n_st,
                                                                lg_st,
                                                                cs_st,
                                                            )
                                                            .await;
                                                        }
                                                    });
                                                }
                                            }
                                        }
                                        dgram_task.abort();
                                        let mut g = hs_map.lock().unwrap();
                                        if let Some(list) = g.get_mut(&binding_id) {
                                            list.retain(|x| !Arc::ptr_eq(x, &hy2_sess) && x.conn.close_reason().is_none());
                                            if list.is_empty() {
                                                g.remove(&binding_id);
                                            }
                                        }
                                    });
                                }
                            }
                        }
                    });
                    tasks.push(jh.abort_handle());
                }
            }
        } else if local.xhttp.enabled() && local.xhttp.http_version == "3" {
            if let (Some(std_udp), Some(xs_root)) = (transport_udp, shared_xhttp_state.clone()) {
                let server_cfg = hysteria2::build_quic_server_config(local)?;
                let vless_dec_h3 = vless_enc::ServerInstance::from_raw(&local.decryption)?;
                if let Ok(quic_ep) = quinn::Endpoint::new(
                    quinn::EndpointConfig::default(),
                    Some(server_cfg),
                    std_udp,
                    Arc::new(quinn::TokioRuntime),
                ) {
                    quic_endpoints.push(quic_ep.clone());
                    let bindings_ref = bindings_live.clone();
                    let local_clone = local.clone();
                    let sessions_clone = server.sessions.clone();
                    let pending_apps_c = server.pending_apps.clone();
                    let mux_pool_c = server.mux_pool.clone();
                    let mux_notify_c = server.mux_notify.clone();
                    let linked_clone = linked.clone();
                    let notify_clone = state_notify.clone();
                    let logger_clone = logger.clone();
                    let mut rx = stop_rx.clone();
                    let jh = handle.spawn(async move {
                        loop {
                            tokio::select! {
                                _ = rx.changed() => {
                                    quic_ep.close(0x100u32.into(), b"shutdown");
                                    break;
                                }
                                inc = quic_ep.accept() => {
                                    let Some(incoming) = inc else { break };
                                    let bindings_ref_c = bindings_ref.clone();
                                    let local_c = local_clone.clone();
                                    let sessions = sessions_clone.clone();
                                    let pa = pending_apps_c.clone();
                                    let mp = mux_pool_c.clone();
                                    let mn = mux_notify_c.clone();
                                    let linked = linked_clone.clone();
                                    let notify_c = notify_clone.clone();
                                    let log_c = logger_clone.clone();
                                    let v_dec = vless_dec_h3.clone();
                                    let xs_conn = xs_root.clone();
                                    let mut conn_stop = rx.clone();
                                    tokio::spawn(async move {
                                        let Ok(Ok(conn)) = tokio::time::timeout(
                                            Duration::from_secs(10),
                                            incoming,
                                        ).await else {
                                            return;
                                        };
                                        let Ok(Ok(uni_abort)) = tokio::time::timeout(
                                            Duration::from_secs(5),
                                            hysteria2::init_h3_connection(&conn),
                                        )
                                        .await
                                        else {
                                            conn.close(0x100u32.into(), b"h3 control err");
                                            return;
                                        };
                                        loop {
                                            tokio::select! {
                                                _ = conn_stop.changed() => {
                                                    conn.close(0x100u32.into(), b"shutdown");
                                                    break;
                                                }
                                                bi = conn.accept_bi() => {
                                                    let Ok((send, recv)) = bi else { break };
                                                    let conn_st = conn.clone();
                                                    let local_st = local_c.clone();
                                                    let local_in = local_c.clone();
                                                    let xs_st = xs_conn.clone();
                                                    let b_ref_st = bindings_ref_c.clone();
                                                    let s_st = sessions.clone();
                                                    let pa_st = pa.clone();
                                                    let mp_st = mp.clone();
                                                    let mn_st = mn.clone();
                                                    let l_st = linked.clone();
                                                    let n_st = notify_c.clone();
                                                    let lg_st = log_c.clone();
                                                    let vd_st = v_dec.clone();
                                                    let cs_st = conn_stop.clone();
                                                    let mut stop_st = conn_stop.clone();
                                                    tokio::spawn(async move {
                                                        tokio::select! {
                                                            _ = stop_st.changed() => {}
                                                            _ = xhttp::handle_xhttp_h3_stream(
                                                                send,
                                                                recv,
                                                                conn_st,
                                                                local_st,
                                                                xs_st,
                                                                move |tunnel_stream| {
                                                                    let b = b_ref_st.read().clone();
                                                                    let s = s_st.clone();
                                                                    let pa_i = pa_st.clone();
                                                                    let mp_i = mp_st.clone();
                                                                    let mn_i = mn_st.clone();
                                                                    let l = l_st.clone();
                                                                    let n = n_st.clone();
                                                                    let cs = cs_st.clone();
                                                                    let vd = vd_st.clone();
                                                                    let lc = local_in.clone();
                                                                    let lg = lg_st.clone();
                                                                    tokio::spawn(async move {
                                                                        serve_vless_session(
                                                                            vision::VisionInner::Boxed(tunnel_stream),
                                                                            lc,
                                                                            vd,
                                                                            b,
                                                                            s,
                                                                            pa_i,
                                                                            mp_i,
                                                                            mn_i,
                                                                            l,
                                                                            n,
                                                                            lg,
                                                                            cs,
                                                                        )
                                                                        .await;
                                                                    });
                                                                },
                                                            ) => {}
                                                        }
                                                    });
                                                }
                                            }
                                        }
                                        uni_abort.abort();
                                    });
                                }
                            }
                        }
                    });
                    tasks.push(jh.abort_handle());
                }
            }
        }

        if let Some(std_ln) = transport_ln {
            let _ = std_ln.set_nonblocking(true);
            if let Ok(tokio_ln) = TcpListener::from_std(std_ln) {
                let bindings_ref = bindings_live.clone();
                let sessions_clone = server.sessions.clone();
                let pending_apps_c = server.pending_apps.clone();
                let mux_pool_c = server.mux_pool.clone();
                let mux_notify_c = server.mux_notify.clone();
                let linked_clone = linked.clone();
                let notify_clone = state_notify.clone();
                let local_clone = local.clone();
                let tls_server_cfg = if !local.reality.enabled()
                    && !local.cert_pem.is_empty()
                    && !local.key_pem.is_empty()
                    && (local.transport_security == "tls" || (local.xhttp.enabled() && local.xhttp.tls))
                {
                    Some(build_tls_server_config(local)?)
                } else {
                    None
                };
                let reality_cfg = if local.reality.enabled() {
                    Some(build_reality_server_cfg(local)?)
                } else {
                    None
                };
                let vless_dec = vless_enc::ServerInstance::from_raw(&local.decryption)?;
                let xhttp_state = shared_xhttp_state;
                let logger_clone = logger.clone();
                let mut rx = stop_rx.clone();
                let conn_sem = Arc::new(tokio::sync::Semaphore::new(4096));
                let jh = handle.spawn(async move {
                    loop {
                        tokio::select! {
                            _ = rx.changed() => break,
                            accepted = tokio_ln.accept() => {
                                let Ok((tcp_stream, _)) = accepted else { break };
                                let Ok(permit) = conn_sem.clone().try_acquire_owned() else {
                                    drop(tcp_stream);
                                    continue;
                                };
                                configure_tcp_stream(&tcp_stream);
                                let bindings_ref_c = bindings_ref.clone();
                                let sessions = sessions_clone.clone();
                                let pa = pending_apps_c.clone();
                                let mp = mux_pool_c.clone();
                                let mn = mux_notify_c.clone();
                                let linked = linked_clone.clone();
                                let notify_c = notify_clone.clone();
                                let local_c = local_clone.clone();
                                let tls_scfg = tls_server_cfg.clone();
                                let r_cfg = reality_cfg.clone();
                                let v_dec = vless_dec.clone();
                                let x_state = xhttp_state.clone();
                                let log_c = logger_clone.clone();
                                let conn_stop = rx.clone();
                                tokio::spawn(async move {
                                    let _permit = permit;
                                    let mut outer_stop = conn_stop.clone();
                                    if *outer_stop.borrow() {
                                        return;
                                    }
                                    let Some(outer_stream) =
                                        accept_outer_vision_inner(tcp_stream, &local_c, tls_scfg, r_cfg).await
                                    else {
                                        return;
                                    };
                                    if let Some(xs) = x_state {
                                        let local_inner = local_c.clone();
                                        let log_inner = log_c.clone();
                                        let notify_inner = notify_c.clone();
                                        tokio::select! {
                                            _ = outer_stop.changed() => {}
                                            _ = xhttp::handle_xhttp_server_conn(
                                                outer_stream.into_box_stream(),
                                                local_c,
                                                xs,
                                                move |tunnel_stream| {
                                                    let b = bindings_ref_c.read().clone();
                                                    let s = sessions.clone();
                                                    let pa_i = pa.clone();
                                                    let mp_i = mp.clone();
                                                    let mn_i = mn.clone();
                                                    let l = linked.clone();
                                                    let n = notify_inner.clone();
                                                    let cs = conn_stop.clone();
                                                    let vd = v_dec.clone();
                                                    let lc = local_inner.clone();
                                                    let lg = log_inner.clone();
                                                    tokio::spawn(async move {
                                                        serve_vless_session(
                                                            vision::VisionInner::Boxed(tunnel_stream),
                                                            lc,
                                                            vd,
                                                            b,
                                                            s,
                                                            pa_i,
                                                            mp_i,
                                                            mn_i,
                                                            l,
                                                            n,
                                                            lg,
                                                            cs,
                                                        )
                                                        .await;
                                                    });
                                                },
                                            ) => {}
                                        }
                                    } else {
                                        let bindings_snap = bindings_ref_c.read().clone();
                                        serve_vless_session(
                                            outer_stream,
                                            local_c,
                                            v_dec,
                                            bindings_snap,
                                            sessions,
                                            pa,
                                            mp,
                                            mn,
                                            linked,
                                            notify_c,
                                            log_c,
                                            conn_stop,
                                        )
                                        .await;
                                    }
                                });
                            }
                        }
                    }
                });
                tasks.push(jh.abort_handle());
            }
        }
    }

    Ok(ServerTransportHandle {
        local: local.clone(),
        bindings: bindings_live,
        stop_tx,
        listeners,
        udp_sockets,
        quic_endpoints,
        tasks,
    })
}

fn start_server_mapping(
    m: &Mapping,
    is_hy2_server: bool,
    server: &ServerRuntime,
    traffic: Arc<Traffic>,
    state_notify: Arc<tokio::sync::Notify>,
) -> Result<ServerMappingHandle, String> {
    let net = mapping_net(&m.network).to_string();
    let host_key = listen_host(&m.listen_host).to_string();
    let addr = format!("{}:{}", host_key, m.listen_port);
    let listen_key = (host_key, m.listen_port, net.clone(), is_hy2_server);
    let (stop_tx, stop_rx) = watch::channel(false);
    let route = Arc::new(parking_lot::RwLock::new(m.clone()));
    let rate_bps = bandwidth_bytes(&m.bandwidth_limit).unwrap_or(0) as u64;
    let up_limiter: LiveLimiter = Arc::new(parking_lot::RwLock::new(BandwidthLimiter::new(rate_bps)));
    let dn_limiter: LiveLimiter = Arc::new(parking_lot::RwLock::new(BandwidthLimiter::new(rate_bps)));

    if net == "udp" {
        let sock = bind_udp_with_retry(&addr)
            .map_err(|e| format!("bind mapping udp {}: {}", addr, e))?;
        let std_udp = sock.try_clone().map_err(|e| format!("clone udp {}: {}", addr, e))?;
        let task = if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let _ = std_udp.set_nonblocking(true);
            if let Ok(tokio_udp) = tokio::net::UdpSocket::from_std(std_udp) {
                let udp_sock = Arc::new(tokio_udp);
                let sessions_clone = server.sessions.clone();
                let hy2_sessions_u = server.hy2_sessions.clone();
                let hy2_routes_u = server.hy2_udp_routes.clone();
                let hy2_sid_gen = server.hy2_udp_sid_seq.clone();
                let traffic_clone = traffic.clone();
                let route_ref = route.clone();
                let up_lim_ref = up_limiter.clone();
                let dn_lim_ref = dn_limiter.clone();
                let mut rx = stop_rx.clone();
                let jh = handle.spawn(async move {
                    let mut xudp_base_key = [0u8; 32];
                    rand::rng().fill_bytes(&mut xudp_base_key);
                    let mut peer_streams: HashMap<SocketAddr, mpsc::Sender<Vec<u8>>> = HashMap::new();
                    let mut peer_hy2_sids: HashMap<SocketAddr, (u32, std::time::Instant)> = HashMap::new();
                    let mut last_target: Option<(String, String, i64)> = None;
                    let mut hy2_pkt_id: u16 = 0;
                    let mut next_xudp_sid: u16 = 1;
                    let mut buf = vec![0u8; 65535];
                    loop {
                        tokio::select! {
                            _ = rx.changed() => break,
                            recv_res = udp_sock.recv_from(&mut buf) => {
                                let Ok((n, peer_addr)) = recv_res else { break };
                                let m_cur = route_ref.read().clone();
                                let cur_target = (
                                    m_cur.binding_id.clone(),
                                    m_cur.target_host.clone(),
                                    m_cur.target_port,
                                );
                                if last_target.as_ref() != Some(&cur_target) {
                                    peer_streams.clear();
                                    if !peer_hy2_sids.is_empty() {
                                        let mut rg = hy2_routes_u.lock().unwrap();
                                        for (_, (sid, _)) in peer_hy2_sids.drain() {
                                            rg.remove(&sid);
                                        }
                                    }
                                    last_target = Some(cur_target);
                                }
                                if is_hy2_server {
                                    let hy2_sess_opt = {
                                        let mut g = hy2_sessions_u.lock().unwrap();
                                        g.get_mut(&m_cur.binding_id).and_then(|list| {
                                            list.retain(|x| x.conn.close_reason().is_none());
                                            list.first().cloned()
                                        })
                                    };
                                    if let Some(hy2_sess) = hy2_sess_opt {
                                        let now_inst = std::time::Instant::now();
                                        if peer_hy2_sids.len() >= 1024 && !peer_hy2_sids.contains_key(&peer_addr) {
                                            let mut expired_sids = Vec::new();
                                            peer_hy2_sids.retain(|_, (sid, ts)| {
                                                if now_inst.saturating_duration_since(*ts) < Duration::from_secs(60) {
                                                    true
                                                } else {
                                                    expired_sids.push(*sid);
                                                    false
                                                }
                                            });
                                            if !expired_sids.is_empty() {
                                                let mut rg = hy2_routes_u.lock().unwrap();
                                                for sid in expired_sids {
                                                    rg.remove(&sid);
                                                }
                                            }
                                        }
                                        let sid = match peer_hy2_sids.get_mut(&peer_addr) {
                                            Some((sid, ts)) => {
                                                *ts = now_inst;
                                                *sid
                                            }
                                            None => {
                                                let mut sid = hy2_sid_gen.fetch_add(1, Ordering::Relaxed);
                                                if sid == 0 {
                                                    sid = hy2_sid_gen.fetch_add(1, Ordering::Relaxed);
                                                }
                                                peer_hy2_sids.insert(peer_addr, (sid, now_inst));
                                                hy2_routes_u.lock().unwrap().insert(
                                                    sid,
                                                    (peer_addr, udp_sock.clone(), m_cur.id.clone(), dn_lim_ref.clone()),
                                                );
                                                sid
                                            }
                                        };
                                        let cur_up = up_lim_ref.read().clone();
                                        cur_up.wait(n).await;
                                        traffic_clone.add(&m_cur.id, n, 0);
                                        hy2_pkt_id = hy2_pkt_id.wrapping_add(1);
                                        let target_addr = hysteria2::format_hy2_addr(
                                            &m_cur.target_host,
                                            m_cur.target_port as u16,
                                        );
                                        let max_dg = hy2_sess.conn.max_datagram_size().unwrap_or(1200);
                                        for dg in hysteria2::encode_hy2_udp_datagrams(
                                            sid,
                                            hy2_pkt_id,
                                            &target_addr,
                                            &buf[..n],
                                            max_dg,
                                        ) {
                                            let _ = hy2_sess.conn.send_datagram(dg);
                                        }
                                        continue;
                                    }
                                }

                                if n + 64 > MAX_PAYLOAD {
                                    continue;
                                }
                                let pkt = buf[..n].to_vec();
                                if let Some(tx) = peer_streams.get(&peer_addr) {
                                    match tx.try_send(pkt.clone()) {
                                        Ok(()) => {
                                            traffic_clone.add(&m_cur.id, n, 0);
                                            continue;
                                        }
                                        Err(mpsc::error::TrySendError::Full(_)) => {
                                            continue;
                                        }
                                        Err(mpsc::error::TrySendError::Closed(_)) => {
                                            peer_streams.remove(&peer_addr);
                                        }
                                    }
                                }
                                if peer_streams.len() >= 64 {
                                    peer_streams.retain(|_, tx| !tx.is_closed());
                                    if peer_streams.len() >= 4096 {
                                        continue;
                                    }
                                }
                                let Some(sess) = pick_session(&sessions_clone, &m_cur.binding_id) else { continue };
                                let Some((stream_id, mut in_rx)) = sess.open_stream() else { continue };
                                let xudp_sid = next_xudp_sid;
                                next_xudp_sid = next_xudp_sid.wrapping_add(1).max(1);
                                let global_id = mux_proto::compute_xudp_global_id(peer_addr, &xudp_base_key);
                                let (pkt_tx, mut pkt_rx) = mpsc::channel::<Vec<u8>>(256);
                                let _ = pkt_tx.try_send(pkt);
                                traffic_clone.add(&m_cur.id, n, 0);
                                peer_streams.insert(peer_addr, pkt_tx);
                                let m_clone = m_cur;
                                let udp_reply = udp_sock.clone();
                                let traffic_down = traffic_clone.clone();
                                let up_lim = up_lim_ref.clone();
                                let dn_lim = dn_lim_ref.clone();
                                tokio::spawn(async move {
                                    let meta = format!("{}\0udp\0", m_clone.target_host);
                                    let mut open_payload = Vec::with_capacity(2 + meta.len());
                                    open_payload.extend_from_slice(&(m_clone.target_port as u16).to_be_bytes());
                                    open_payload.extend_from_slice(meta.as_bytes());
                                    sess.maybe_probe_on_open();
                                    if sess
                                        .sender
                                        .send_ctrl(FRAME_OPEN, stream_id, open_payload)
                                        .await
                                        .is_err()
                                    {
                                        sess.close_stream(stream_id);
                                        return;
                                    }
                                    let sender_up = sess.sender.clone();
                                    let target_host = m_clone.target_host.clone();
                                    let target_port = m_clone.target_port as u16;
                                    let up_task = tokio::spawn(async move {
                                        let mut sent_new = false;
                                        while let Some(dg) = pkt_rx.recv().await {
                                            let cur_up = up_lim.read().clone();
                                            cur_up.wait(dg.len()).await;
                                            let xudp = if !sent_new {
                                                sent_new = true;
                                                let Ok(f) = mux_proto::encode_xudp_new(
                                                    xudp_sid,
                                                    &target_host,
                                                    target_port,
                                                    &dg,
                                                    Some(global_id),
                                                ) else {
                                                    break;
                                                };
                                                f
                                            } else {
                                                mux_proto::encode_xudp_keep(xudp_sid, &dg)
                                            };
                                            if xudp.len() > MAX_PAYLOAD {
                                                continue;
                                            }
                                            if sender_up
                                                .send_data(FRAME_DATA, stream_id, xudp)
                                                .await
                                                .is_err()
                                            {
                                                break;
                                            }
                                        }
                                        let end_f = mux_proto::encode_xudp_end(xudp_sid);
                                        let _ = sender_up.send_data(FRAME_DATA, stream_id, end_f).await;
                                    });
                                    loop {
                                        match tokio::time::timeout(Duration::from_secs(30), in_rx.recv()).await {
                                            Ok(Some((FRAME_DATA, data))) => {
                                                let Ok(dec) = mux_proto::decode_xudp_packet(&data) else {
                                                    break;
                                                };
                                                if dec.status == mux_proto::XUDP_STATUS_END {
                                                    break;
                                                }
                                                if !dec.payload.is_empty() {
                                                    let cur_dn = dn_lim.read().clone();
                                                    cur_dn.wait(dec.payload.len()).await;
                                                    traffic_down.add(&m_clone.id, 0, dec.payload.len());
                                                    let _ = udp_reply.send_to(dec.payload, peer_addr).await;
                                                }
                                            }
                                            _ => break,
                                        }
                                    }
                                    up_task.abort();
                                    sess.close_stream(stream_id);
                                    sess.sender.send_ctrl_bg(FRAME_RESET, stream_id, Vec::new());
                                });
                            }
                        }
                    }
                });
                Some(jh.abort_handle())
            } else {
                None
            }
        } else {
            None
        };

        Ok(ServerMappingHandle {
            listen_key,
            route,
            up_limiter,
            dn_limiter,
            raw_limit: m.bandwidth_limit.clone(),
            stop_tx,
            listener: None,
            udp_socket: Some(sock),
            task,
        })
    } else {
        let ln = bind_tcp_with_retry(&addr)
            .map_err(|e| format!("bind mapping tcp {}: {}", addr, e))?;
        let std_ln = ln.try_clone().map_err(|e| format!("clone tcp {}: {}", addr, e))?;
        let task = if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let _ = std_ln.set_nonblocking(true);
            if let Ok(tokio_ln) = TcpListener::from_std(std_ln) {
                let sessions_clone = server.sessions.clone();
                let pending_apps_c = server.pending_apps.clone();
                let mux_pool_c = server.mux_pool.clone();
                let mux_notify_c = server.mux_notify.clone();
                let app_seq_c = server.app_req_seq.clone();
                let traffic_clone = traffic.clone();
                let notify_map = state_notify.clone();
                let route_ref = route.clone();
                let up_lim_ref = up_limiter.clone();
                let dn_lim_ref = dn_limiter.clone();
                let mut rx = stop_rx.clone();
                let jh = handle.spawn(async move {
                    loop {
                        tokio::select! {
                            _ = rx.changed() => break,
                            accepted = tokio_ln.accept() => {
                                let Ok((pub_stream, _)) = accepted else { break };
                                configure_tcp_stream(&pub_stream);
                                let m_clone = route_ref.read().clone();
                                let mux_t = m_clone.effective_mux_type().unwrap_or_default();
                                let sessions_req = sessions_clone.clone();
                                let pa_req = pending_apps_c.clone();
                                let mp_req = mux_pool_c.clone();
                                let mn_req = mux_notify_c.clone();
                                let seq_req = app_seq_c.clone();
                                let notify_req = notify_map.clone();
                                let mut stop_req = rx.clone();
                                let traffic_conn = traffic_clone.clone();
                                let up_lim = up_lim_ref.clone();
                                let dn_lim = dn_lim_ref.clone();
                                tokio::spawn(async move {
                                    let mut sess_opt = pick_session(&sessions_req, &m_clone.binding_id);
                                    if sess_opt.is_none() {
                                        let deadline = tokio::time::Instant::now() + Duration::from_millis(1500);
                                        while tokio::time::Instant::now() < deadline {
                                            let notified = notify_req.notified();
                                            tokio::select! {
                                                _ = stop_req.changed() => return,
                                                _ = notified => {}
                                                _ = tokio::time::sleep(Duration::from_millis(50)) => {}
                                            }
                                            sess_opt = pick_session(&sessions_req, &m_clone.binding_id);
                                            if sess_opt.is_some() {
                                                break;
                                            }
                                        }
                                    }
                                    let Some(sess) = sess_opt else { return };
                                    sess.maybe_probe_on_open();

                                    let remote_stream: BoxStream = if mux_t.is_empty() {
                                        let mut req_id = seq_req.fetch_add(1, Ordering::Relaxed);
                                        if req_id == 0 {
                                            req_id = seq_req.fetch_add(1, Ordering::Relaxed);
                                        }
                                        let (tx, rx_app) = tokio::sync::oneshot::channel();
                                        pa_req
                                            .lock()
                                            .unwrap()
                                            .insert((m_clone.binding_id.clone(), req_id), tx);
                                        let mut dial_payload = Vec::with_capacity(2 + m_clone.target_host.len());
                                        dial_payload.extend_from_slice(&(m_clone.target_port as u16).to_be_bytes());
                                        dial_payload.extend_from_slice(m_clone.target_host.as_bytes());
                                        if sess
                                            .sender
                                            .send_ctrl(FRAME_DIAL_APP, req_id, dial_payload)
                                            .await
                                            .is_err()
                                        {
                                            pa_req
                                                .lock()
                                                .unwrap()
                                                .remove(&(m_clone.binding_id.clone(), req_id));
                                            return;
                                        }
                                        match tokio::select! {
                                            _ = stop_req.changed() => Err(()),
                                            res = tokio::time::timeout(Duration::from_secs(8), rx_app) => {
                                                res.map_err(|_| ()).and_then(|r| r.map_err(|_| ()))
                                            }
                                        } {
                                            Ok(s) => s,
                                            Err(()) => {
                                                pa_req
                                                    .lock()
                                                    .unwrap()
                                                    .remove(&(m_clone.binding_id.clone(), req_id));
                                                return;
                                            }
                                        }
                                    } else {
                                        let desired_pool = m_clone.pool.clamp(1, 16) as usize;
                                        let Some(opener) = acquire_mux_opener(
                                            &mp_req,
                                            &mn_req,
                                            &sess,
                                            &m_clone.binding_id,
                                            &mux_t,
                                            desired_pool,
                                            &mut stop_req,
                                        )
                                        .await
                                        else {
                                            return;
                                        };
                                        match opener
                                            .open_tcp_substream(
                                                &m_clone.target_host,
                                                m_clone.target_port as u16,
                                            )
                                            .await
                                        {
                                            Ok(sub) => sub,
                                            Err(_) => {
                                                {
                                                    let mut g = mp_req.lock().unwrap();
                                                    if let Some(list) = g.get_mut(&(
                                                        m_clone.binding_id.clone(),
                                                        mux_t.clone(),
                                                    )) {
                                                        list.retain(|o| !Arc::ptr_eq(o, &opener) && !o.is_closed());
                                                    }
                                                }
                                                let Some(retry_op) = acquire_mux_opener(
                                                    &mp_req,
                                                    &mn_req,
                                                    &sess,
                                                    &m_clone.binding_id,
                                                    &mux_t,
                                                    desired_pool,
                                                    &mut stop_req,
                                                )
                                                .await
                                                else {
                                                    return;
                                                };
                                                match retry_op
                                                    .open_tcp_substream(
                                                        &m_clone.target_host,
                                                        m_clone.target_port as u16,
                                                    )
                                                    .await
                                                {
                                                    Ok(sub) => sub,
                                                    Err(_) => return,
                                                }
                                            }
                                        }
                                    };

                                    relay_raw_streams_gateway(
                                        pub_stream,
                                        remote_stream,
                                        up_lim,
                                        dn_lim,
                                        traffic_conn,
                                        &m_clone.id,
                                    )
                                    .await;
                                });
                            }
                        }
                    }
                });
                Some(jh.abort_handle())
            } else {
                None
            }
        } else {
            None
        };

        Ok(ServerMappingHandle {
            listen_key,
            route,
            up_limiter,
            dn_limiter,
            raw_limit: m.bandwidth_limit.clone(),
            stop_tx,
            listener: Some(ln),
            udp_socket: None,
            task,
        })
    }
}

fn reconcile_server(
    inst: &mut RunningInstance,
    s: &Snapshot,
    local: &LocalTLS,
    traffic: Arc<Traffic>,
    state_notify: Arc<tokio::sync::Notify>,
    logger: TunnelLogger,
) -> Result<(), String> {
    let need_transport = !s.node.disabled && !s.bindings.is_empty();
    let keep_bids: HashSet<String> = if need_transport {
        s.bindings.iter().map(|b| b.id.clone()).collect()
    } else {
        HashSet::new()
    };

    // 1. Reconcile transport core ONLY if transport config changed or toggled on/off.
    let reuse_transport = need_transport
        && inst
            .server
            .transport
            .as_ref()
            .is_some_and(|t| t.local == *local);
    if reuse_transport {
        if let Some(ref th) = inst.server.transport {
            *th.bindings.write() = s.bindings.clone();
        }
        inst.server
            .evict_removed_bindings(&keep_bids, &inst.linked, &state_notify);
    } else {
        if let Some(mut old_t) = inst.server.transport.take() {
            old_t.stop();
        }
        let empty = HashSet::new();
        inst.server
            .evict_removed_bindings(&empty, &inst.linked, &state_notify);
        if need_transport {
            let th = start_server_transport(
                &s.bindings,
                local,
                &inst.server,
                traffic.clone(),
                inst.linked.clone(),
                state_notify.clone(),
                logger,
            )?;
            inst.server.transport = Some(th);
        }
    }

    // 2. Reconcile per-mapping listeners in complete isolation (keyed by mapping.id).
    let is_hy2_server = local.hysteria2.enabled();
    let mut desired: HashMap<String, &Mapping> = HashMap::new();
    if !s.node.disabled {
        for m in &s.mappings {
            if m.enabled {
                desired.insert(m.id.clone(), m);
            }
        }
    }

    let mut to_stop_ids = Vec::new();
    for (mid, existing) in &inst.server.mappings {
        match desired.get(mid) {
            Some(m) => {
                let key = (
                    listen_host(&m.listen_host).to_string(),
                    m.listen_port,
                    mapping_net(&m.network).to_string(),
                    is_hy2_server,
                );
                if existing.listen_key != key {
                    to_stop_ids.push(mid.clone());
                }
            }
            None => to_stop_ids.push(mid.clone()),
        }
    }
    for mid in &to_stop_ids {
        if let Some(mut mh) = inst.server.mappings.remove(mid) {
            mh.stop();
        }
        inst.server
            .hy2_udp_routes
            .lock()
            .unwrap()
            .retain(|_, (_, _, route_mid, _)| route_mid != mid);
    }

    // Update kept mappings in-place (zero listener drop; live rate-limit & target updates)
    for (mid, mh) in inst.server.mappings.iter_mut() {
        if let Some(m) = desired.get(mid) {
            *mh.route.write() = (*m).clone();
            if mh.raw_limit != m.bandwidth_limit {
                let rate_bps = bandwidth_bytes(&m.bandwidth_limit).unwrap_or(0) as u64;
                *mh.up_limiter.write() = BandwidthLimiter::new(rate_bps);
                *mh.dn_limiter.write() = BandwidthLimiter::new(rate_bps);
                mh.raw_limit = m.bandwidth_limit.clone();
            }
        }
    }

    // Bind & spawn ONLY newly added or rebound mappings
    let mut started_new = Vec::new();
    for m in &s.mappings {
        if s.node.disabled || !m.enabled || inst.server.mappings.contains_key(&m.id) {
            continue;
        }
        match start_server_mapping(m, is_hy2_server, &inst.server, traffic.clone(), state_notify.clone()) {
            Ok(mh) => {
                started_new.push(m.id.clone());
                inst.server.mappings.insert(m.id.clone(), mh);
            }
            Err(err) => {
                for new_id in started_new {
                    if let Some(mut mh) = inst.server.mappings.remove(&new_id) {
                        mh.stop();
                    }
                }
                return Err(err);
            }
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn spawn_client_worker(
    handle: &tokio::runtime::Handle,
    worker_idx: usize,
    spec: &ClientBindingSpec,
    vless_enc_cli: Option<Arc<vless_enc::ClientInstance>>,
    shared: Arc<ClientSharedTable>,
    active_workers: Arc<AtomicUsize>,
    linked: Arc<Mutex<HashSet<String>>>,
    state_notify: Arc<tokio::sync::Notify>,
    logger: TunnelLogger,
) -> ClientWorkerHandle {
    let (stop_tx, mut rx) = watch::channel(false);
    let b_clone = spec.binding.clone();
    let eps_clone = spec.eps.clone();
    let cfg_clone = spec.client_cfg.clone();
    let gw_addr = spec.gw_addr.clone();
    let enc_cli = vless_enc_cli;
    let workers_ref = active_workers;
    let linked_clone = linked;
    let notify_clone = state_notify;
    let log_c = logger;

    let jh = handle.spawn(async move {
        let Ok(uuid_bytes) = parse_uuid(&b_clone.uuid) else { return };
        let mut ep_cursor = worker_idx;
        let mut fail_streak = 0u32;
        let mut ever_connected = false;
        loop {
            if *rx.borrow() {
                break;
            }
            let dial_ep = &eps_clone[ep_cursor % eps_clone.len()];
            ep_cursor = ep_cursor.wrapping_add(1);

            let maybe_connected: Result<
                (BoxStream, ClientSubchannelDialer, Option<tokio::task::AbortHandle>),
                String,
            > = if cfg_clone.hysteria2.enabled() {
                match resolve_socket_addrs(&dial_ep.host, dial_ep.port).await {
                    Ok(addrs) => {
                        let mut last_e = String::from("no hy2 remote addresses");
                        let mut ok_res = None;
                        for sa in addrs {
                            match hysteria2::hy2_connect_session(sa, &cfg_clone, &b_clone, &gw_addr)
                                .await
                            {
                                Ok(hy2_sess) => {
                                    match hy2_sess
                                        .open_tcp_stream(
                                            b_clone.domain.trim(),
                                            mux_proto::PORT_CONTROL,
                                        )
                                        .await
                                    {
                                        Ok(ctrl_s) => {
                                            let udp_abort =
                                                if hy2_sess.udp_supported {
                                                    Some(spawn_hy2_client_udp_responder(
                                                        hy2_sess.clone(),
                                                        b_clone.clone(),
                                                        shared.clone(),
                                                        rx.clone(),
                                                    ))
                                                } else {
                                                    None
                                                };
                                            let dialer = ClientSubchannelDialer::Hy2(
                                                hy2_sess,
                                                b_clone.clone(),
                                            );
                                            ok_res = Some((ctrl_s, dialer, udp_abort));
                                            break;
                                        }
                                        Err(e) => last_e = e,
                                    }
                                }
                                Err(e) => last_e = e,
                            }
                        }
                        match ok_res {
                            Some(v) => Ok(v),
                            None => {
                                invalidate_dns_cache(&dial_ep.host, dial_ep.port);
                                Err(last_e)
                            }
                        }
                    }
                    Err(e) => Err(e),
                }
            } else {
                dial_client_session(
                    dial_ep,
                    &eps_clone,
                    &cfg_clone,
                    &b_clone,
                    uuid_bytes,
                    &gw_addr,
                    enc_cli.clone(),
                )
                .await
                .map(|ctrl_s| {
                    let dialer = ClientSubchannelDialer::Vless {
                        dial_ep: dial_ep.clone(),
                        all_eps: eps_clone.clone(),
                        client_cfg: cfg_clone.clone(),
                        binding: b_clone.clone(),
                        uuid_bytes,
                        gw_addr: gw_addr.clone(),
                        vless_enc_cli: enc_cli.clone(),
                    };
                    (ctrl_s, dialer, None)
                })
            };

            match maybe_connected {
                Ok((stream, sub_dialer, hy2_udp_abort)) => {
                    let prev_fails = fail_streak;
                    fail_streak = 0;
                    let (prev_workers, newly_linked) = {
                        let mut lg = linked_clone.lock().unwrap();
                        let prev = workers_ref.fetch_add(1, Ordering::SeqCst);
                        let ins = lg.insert(b_clone.id.clone());
                        (prev, ins)
                    };
                    if (worker_idx == 0 && !ever_connected)
                        || (prev_workers == 0 && prev_fails > 0)
                    {
                        ever_connected = true;
                        log_tunnel(
                            &log_c,
                            "INFO",
                            format!(
                                "client tunnel connected role=client id={} node_id={} network={} addr={} port={}",
                                b_clone.id,
                                b_clone.server_id,
                                cfg_clone.effective_protocol(),
                                dial_ep.host,
                                dial_ep.port
                            ),
                        );
                    }
                    if newly_linked {
                        notify_clone.notify_waiters();
                    }
                    let (ctrl_tx, ctrl_rx) =
                        mpsc::channel::<(u8, u32, Vec<u8>)>(SESSION_CTRL_CHAN_CAP);
                    let (data_tx, data_rx) =
                        mpsc::channel::<(u8, u32, Vec<u8>)>(SESSION_DATA_CHAN_CAP);
                    let sender = SessionSender::new(ctrl_tx, data_tx);
                    let last_rx_ms = Arc::new(AtomicU64::new(mono_now_ms()));
                    let streams_map: Arc<Mutex<HashMap<u32, mpsc::Sender<(u8, Vec<u8>)>>>> =
                        Arc::new(Mutex::new(HashMap::new()));
                    let (mut rd, wr) = split_tunnel_stream(stream);
                    let (write_done_tx, mut write_done_rx) = watch::channel(false);
                    let write_task = spawn_session_writer(
                        wr,
                        ctrl_rx,
                        data_rx,
                        last_rx_ms.clone(),
                        rx.clone(),
                        None,
                        write_done_tx,
                    );
                    let sender_ping = sender.clone();
                    let ping_task = tokio::spawn(async move {
                        let mut ping_interval = tokio::time::interval(PING_INTERVAL);
                        ping_interval
                            .set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                        ping_interval.tick().await;
                        loop {
                            ping_interval.tick().await;
                            if sender_ping
                                .send_ctrl(FRAME_PING, 0, Vec::new())
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                    });
                    loop {
                        tokio::select! {
                            _ = rx.changed() => break,
                            _ = write_done_rx.changed() => break,
                            frame = tokio::time::timeout(SESSION_READ_TIMEOUT, read_frame(&mut rd)) => {
                                let Ok(Ok((kind, id, payload))) = frame else { break };
                                last_rx_ms.store(mono_now_ms(), Ordering::Relaxed);
                                match kind {
                                    FRAME_PING => {
                                        sender.send_ctrl_bg(FRAME_PONG, 0, Vec::new());
                                    }
                                    FRAME_PONG => {}
                                    FRAME_DIAL_APP => {
                                        handle_client_dial_app(
                                            id,
                                            payload,
                                            &b_clone,
                                            &shared,
                                            &sender,
                                            sub_dialer.clone(),
                                        );
                                    }
                                    FRAME_DIAL_MUX => {
                                        handle_client_dial_mux(
                                            payload,
                                            &b_clone,
                                            &shared,
                                            sub_dialer.clone(),
                                            rx.clone(),
                                        );
                                    }
                                    FRAME_OPEN => {
                                        handle_client_frame_open(
                                            id,
                                            payload,
                                            &b_clone,
                                            &shared,
                                            &sender,
                                            &streams_map,
                                        );
                                    }
                                    FRAME_DATA | FRAME_HALF | FRAME_RESET => {
                                        demux_stream_frame(
                                            kind,
                                            id,
                                            payload,
                                            &streams_map,
                                            None,
                                            &sender,
                                        )
                                        .await;
                                    }
                                    _ => break,
                                }
                            }
                        }
                    }
                    if let Some(ab) = hy2_udp_abort {
                        ab.abort();
                    }
                    ping_task.abort();
                    write_task.abort();
                    drop(sender);
                    streams_map.lock().unwrap().clear();
                    let (rem_workers, unlinked) = {
                        let mut lg = linked_clone.lock().unwrap();
                        let prev = workers_ref.fetch_sub(1, Ordering::SeqCst);
                        let rem = prev.saturating_sub(1);
                        let unl = if rem == 0 {
                            lg.remove(&b_clone.id)
                        } else {
                            false
                        };
                        (rem, unl)
                    };
                    if unlinked {
                        notify_clone.notify_waiters();
                    }
                    if rem_workers == 0 && !*rx.borrow() {
                        log_tunnel(
                            &log_c,
                            "INFO",
                            format!(
                                "client tunnel session closed; reconnecting role=client id={} node_id={}",
                                b_clone.id, b_clone.server_id
                            ),
                        );
                    }
                }
                Err(err) => {
                    fail_streak = fail_streak.saturating_add(1);
                    if worker_idx == 0 && (fail_streak == 1 || fail_streak % 10 == 0) {
                        log_tunnel(
                            &log_c,
                            "WARN",
                            format!(
                                "client tunnel connection failed; backing off role=client id={} node_id={} attempt={} network={} addr={} port={} err={}",
                                b_clone.id,
                                b_clone.server_id,
                                fail_streak,
                                cfg_clone.effective_protocol(),
                                dial_ep.host,
                                dial_ep.port,
                                err
                            ),
                        );
                    }
                }
            }
            let retry_delay = if fail_streak <= eps_clone.len() as u32 {
                Duration::from_millis(50)
            } else {
                let exp = (fail_streak - eps_clone.len() as u32).min(6);
                Duration::from_millis((50u64 << exp).min(5000))
            };
            tokio::select! {
                _ = rx.changed() => break,
                _ = tokio::time::sleep(retry_delay) => {}
            }
        }
    });

    ClientWorkerHandle {
        stop_tx,
        abort: jh.abort_handle(),
    }
}

fn reconcile_client(
    inst: &mut RunningInstance,
    s: &Snapshot,
    local: &LocalTLS,
    state_notify: Arc<tokio::sync::Notify>,
    logger: TunnelLogger,
) -> Result<(), String> {
    if s.node.disabled || s.bindings.is_empty() {
        inst.client.stop_all(&inst.linked, &state_notify);
        return Ok(());
    }

    // Atomically refresh dynamic mapping routing & bandwidth limiters in-place
    // so existing tunnel sessions and active streams never drop!
    inst.client.shared.sync(&s.mappings);

    let mut desired: HashMap<String, (ClientBindingSpec, usize)> = HashMap::new();
    for b in &s.bindings {
        let Some(gw) = s.nodes.iter().find(|n| n.id == b.server_id).cloned() else {
            continue;
        };
        let Ok(bound_gw) = binding_gateway(gw, b) else {
            continue;
        };
        let eps = enabled_endpoints(&bound_gw);
        if eps.is_empty() {
            continue;
        }
        let Ok(client_cfg) = gateway_client_config(local, &bound_gw) else {
            continue;
        };
        let pool_count = s
            .mappings
            .iter()
            .filter(|m| m.enabled && m.binding_id == b.id)
            .map(|m| m.pool.clamp(1, 32) as usize)
            .max()
            .unwrap_or(1);
        desired.insert(
            b.id.clone(),
            (
                ClientBindingSpec {
                    binding: b.clone(),
                    eps,
                    client_cfg,
                    gw_addr: bound_gw.address.clone(),
                },
                pool_count,
            ),
        );
    }

    // Stop ONLY removed bindings or bindings whose server transport config changed
    let mut to_stop = Vec::new();
    for (bid, grp) in &inst.client.groups {
        match desired.get(bid) {
            Some((spec, _)) if &grp.spec == spec => {}
            _ => to_stop.push(bid.clone()),
        }
    }
    for bid in to_stop {
        if let Some(mut grp) = inst.client.groups.remove(&bid) {
            grp.stop_all(&inst.linked, &state_notify);
        }
    }

    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return Ok(());
    };

    for (bid, (spec, pool_count)) in desired {
        if let Some(grp) = inst.client.groups.get_mut(&bid) {
            let cur_len = grp.workers.len();
            if pool_count > cur_len {
                for worker_idx in cur_len..pool_count {
                    let w = spawn_client_worker(
                        &handle,
                        worker_idx,
                        &grp.spec,
                        grp.vless_enc_cli.clone(),
                        inst.client.shared.clone(),
                        grp.active_workers.clone(),
                        inst.linked.clone(),
                        state_notify.clone(),
                        logger.clone(),
                    );
                    grp.workers.push(w);
                }
            } else if pool_count < cur_len {
                // Gracefully signal surplus workers to exit so active_workers decrements cleanly
                // while keeping workers 0..pool_count continuously connected!
                for w in grp.workers.drain(pool_count..) {
                    let _ = w.stop_tx.send(true);
                }
            }
        } else {
            let vless_enc_cli = vless_enc::ClientInstance::from_raw(&spec.client_cfg.encryption)?;
            let active_workers = Arc::new(AtomicUsize::new(0));
            let mut workers = Vec::with_capacity(pool_count);
            for worker_idx in 0..pool_count {
                workers.push(spawn_client_worker(
                    &handle,
                    worker_idx,
                    &spec,
                    vless_enc_cli.clone(),
                    inst.client.shared.clone(),
                    active_workers.clone(),
                    inst.linked.clone(),
                    state_notify.clone(),
                    logger.clone(),
                ));
            }
            inst.client.groups.insert(
                bid,
                ClientBindingGroup {
                    spec,
                    vless_enc_cli,
                    active_workers,
                    workers,
                },
            );
        }
    }

    Ok(())
}

fn reconcile_instance(
    inst: &mut RunningInstance,
    s: &Snapshot,
    local: &LocalTLS,
    traffic: Arc<Traffic>,
    state_notify: Arc<tokio::sync::Notify>,
    logger: TunnelLogger,
) -> Result<(), String> {
    validate(s, local)?;
    if s.node.role == "server" {
        reconcile_server(inst, s, local, traffic, state_notify, logger)
    } else if s.node.role == "client" {
        reconcile_client(inst, s, local, state_notify, logger)
    } else {
        Ok(())
    }
}

fn dns_cache_map(
) -> &'static parking_lot::Mutex<HashMap<(String, i64), (Vec<SocketAddr>, std::time::Instant)>> {
    static DNS_CACHE: OnceLock<
        parking_lot::Mutex<HashMap<(String, i64), (Vec<SocketAddr>, std::time::Instant)>>,
    > = OnceLock::new();
    DNS_CACHE.get_or_init(|| parking_lot::Mutex::new(HashMap::new()))
}

fn invalidate_dns_cache(host: &str, port: i64) {
    dns_cache_map()
        .lock()
        .remove(&(host.to_ascii_lowercase(), port));
}

async fn resolve_socket_addrs(host: &str, port: i64) -> Result<Vec<SocketAddr>, String> {
    let addr_str = if host.contains(':') && !host.starts_with('[') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    };
    if let Ok(sa) = addr_str.parse::<SocketAddr>() {
        return Ok(vec![sa]);
    }

    let cache = dns_cache_map();
    let key = (host.to_ascii_lowercase(), port);
    {
        let guard = cache.lock();
        if let Some((cached, at)) = guard.get(&key) {
            if at.elapsed() < DNS_CACHE_TTL && !cached.is_empty() {
                return Ok(cached.clone());
            }
        }
    }

    let addrs: Vec<SocketAddr> =
        match tokio::time::timeout(Duration::from_secs(5), tokio::net::lookup_host(&addr_str)).await
        {
            Ok(Ok(iter)) => {
                let v: Vec<SocketAddr> = iter.collect();
                if v.is_empty() {
                    crate::node::udp_dns_lookup_addrs(&addr_str)
                        .await
                        .map_err(|e| format!("{:?}", e))?
                } else {
                    v
                }
            }
            _ => crate::node::udp_dns_lookup_addrs(&addr_str)
                .await
                .map_err(|e| format!("{:?}", e))?,
        };
    if addrs.is_empty() {
        return Err(format!("unable to resolve {}", addr_str));
    }
    {
        let mut guard = cache.lock();
        if guard.len() >= MAX_DNS_CACHE_ENTRIES {
            guard.retain(|_, (_, at)| at.elapsed() < DNS_CACHE_TTL);
            if guard.len() >= MAX_DNS_CACHE_ENTRIES {
                guard.clear();
            }
        }
        guard.insert(key, (addrs.clone(), std::time::Instant::now()));
    }
    Ok(addrs)
}

async fn resolve_socket_addr(host: &str, port: i64) -> Result<SocketAddr, String> {
    let addrs = resolve_socket_addrs(host, port).await?;
    Ok(addrs[0])
}

#[derive(Clone)]
enum ClientSubchannelDialer {
    Hy2(Arc<hysteria2::Hy2ClientSession>, Binding),
    Vless {
        dial_ep: ConnectEndpoint,
        all_eps: Vec<ConnectEndpoint>,
        client_cfg: LocalTLS,
        binding: Binding,
        uuid_bytes: [u8; 16],
        gw_addr: String,
        vless_enc_cli: Option<Arc<vless_enc::ClientInstance>>,
    },
}

impl ClientSubchannelDialer {
    async fn dial_port(&self, port: u16) -> Result<BoxStream, String> {
        match self {
            Self::Hy2(sess, binding) => sess.open_tcp_stream(binding.domain.trim(), port).await,
            Self::Vless {
                dial_ep,
                all_eps,
                client_cfg,
                binding,
                uuid_bytes,
                gw_addr,
                vless_enc_cli,
            } => {
                dial_vless_session_port(
                    dial_ep,
                    all_eps,
                    client_cfg,
                    binding,
                    *uuid_bytes,
                    gw_addr,
                    vless_enc_cli.clone(),
                    port,
                )
                .await
            }
        }
    }
}

async fn acquire_mux_opener(
    mux_pool: &MuxPoolMap,
    mux_notify: &Arc<tokio::sync::Notify>,
    sess: &SessionHandle,
    binding_id: &str,
    mux_type: &str,
    desired_pool: usize,
    stop_rx: &mut watch::Receiver<bool>,
) -> Option<Arc<mux_proto::SingMuxOpener>> {
    static MUX_RR: AtomicUsize = AtomicUsize::new(0);
    let key = (binding_id.to_string(), mux_type.to_string());
    let mut requested = false;

    let check_existing = |need_more: &mut bool| -> Option<Arc<mux_proto::SingMuxOpener>> {
        let mut g = mux_pool.lock().unwrap();
        let list = g.entry(key.clone()).or_default();
        list.retain(|o| !o.is_closed());
        *need_more = list.len() < desired_pool;
        if list.is_empty() {
            None
        } else {
            let idx = MUX_RR.fetch_add(1, Ordering::Relaxed) % list.len();
            Some(list[idx].clone())
        }
    };

    let mut need_more = false;
    if let Some(existing) = check_existing(&mut need_more) {
        if need_more {
            sess.sender
                .send_ctrl_bg(FRAME_DIAL_MUX, 0, mux_type.as_bytes().to_vec());
        }
        return Some(existing);
    }

    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    while tokio::time::Instant::now() < deadline {
        let notified = mux_notify.notified();
        if !requested {
            requested = true;
            if sess
                .sender
                .send_ctrl(FRAME_DIAL_MUX, 0, mux_type.as_bytes().to_vec())
                .await
                .is_err()
            {
                return None;
            }
        }
        if let Some(found) = check_existing(&mut need_more) {
            return Some(found);
        }
        tokio::select! {
            _ = stop_rx.changed() => return None,
            _ = notified => {}
            _ = tokio::time::sleep(Duration::from_millis(100)) => {}
        }
        if let Some(found) = check_existing(&mut need_more) {
            return Some(found);
        }
    }
    None
}

async fn relay_raw_streams_gateway(
    pub_stream: TcpStream,
    remote_stream: BoxStream,
    up_lim: LiveLimiter,
    dn_lim: LiveLimiter,
    traffic: Arc<Traffic>,
    mapping_id: &str,
) {
    let (mut pr, mut pw) = pub_stream.into_split();
    let (mut rr, mut rw) = tokio::io::split(remote_stream);
    let last_active_ms = Arc::new(AtomicU64::new(mono_now_ms()));
    let half_closed = Arc::new(AtomicBool::new(false));

    let up_active = last_active_ms.clone();
    let up_half = half_closed.clone();
    let t_up = traffic.clone();
    let mid_up = mapping_id.to_string();
    let up_fut = async move {
        let mut buf = vec![0u8; 32768];
        loop {
            let cur_lim = up_lim.read().clone();
            let read_cap = cur_lim.read_size(buf.len());
            match tokio::time::timeout(Duration::from_secs(15), pr.read(&mut buf[..read_cap])).await {
                Ok(Ok(0)) => {
                    up_half.store(true, Ordering::Relaxed);
                    let _ = rw.shutdown().await;
                    break;
                }
                Ok(Ok(n)) => {
                    up_active.store(mono_now_ms(), Ordering::Relaxed);
                    cur_lim.wait(n).await;
                    t_up.add(&mid_up, n, 0);
                    if tokio::time::timeout(STREAM_SOCKET_WRITE_TIMEOUT, async {
                        rw.write_all(&buf[..n]).await?;
                        rw.flush().await
                    })
                    .await
                    .map_or(true, |r| r.is_err())
                    {
                        break;
                    }
                }
                Ok(Err(_)) => break,
                Err(_) => {
                    let idle = if up_half.load(Ordering::Relaxed) {
                        STREAM_HALF_CLOSE_IDLE_MS
                    } else {
                        STREAM_OPEN_IDLE_MS
                    };
                    if mono_now_ms().saturating_sub(up_active.load(Ordering::Relaxed)) >= idle {
                        break;
                    }
                }
            }
        }
    };

    let dn_active = last_active_ms;
    let dn_half = half_closed;
    let mid_dn = mapping_id.to_string();
    let dn_fut = async move {
        let mut buf = vec![0u8; 32768];
        loop {
            let cur_lim = dn_lim.read().clone();
            let read_cap = cur_lim.read_size(buf.len());
            match tokio::time::timeout(Duration::from_secs(15), rr.read(&mut buf[..read_cap])).await {
                Ok(Ok(0)) => {
                    dn_half.store(true, Ordering::Relaxed);
                    let _ = pw.shutdown().await;
                    break;
                }
                Ok(Ok(n)) => {
                    dn_active.store(mono_now_ms(), Ordering::Relaxed);
                    cur_lim.wait(n).await;
                    traffic.add(&mid_dn, 0, n);
                    if tokio::time::timeout(STREAM_SOCKET_WRITE_TIMEOUT, pw.write_all(&buf[..n]))
                        .await
                        .map_or(true, |r| r.is_err())
                    {
                        break;
                    }
                }
                Ok(Err(_)) => break,
                Err(_) => {
                    let idle = if dn_half.load(Ordering::Relaxed) {
                        STREAM_HALF_CLOSE_IDLE_MS
                    } else {
                        STREAM_OPEN_IDLE_MS
                    };
                    if mono_now_ms().saturating_sub(dn_active.load(Ordering::Relaxed)) >= idle {
                        break;
                    }
                }
            }
        }
    };

    let _ = tokio::join!(up_fut, dn_fut);
}

async fn relay_raw_streams_client(
    target_stream: TcpStream,
    tunnel_stream: BoxStream,
    shared: Arc<ClientSharedTable>,
    mapping_id: String,
) {
    let (mut tr, mut tw) = target_stream.into_split();
    let (mut rr, mut rw) = tokio::io::split(tunnel_stream);
    let last_active_ms = Arc::new(AtomicU64::new(mono_now_ms()));
    let half_closed = Arc::new(AtomicBool::new(false));

    let rt_active = last_active_ms.clone();
    let rt_half = half_closed.clone();
    let target_to_tunnel = async move {
        let mut buf = vec![0u8; 32768];
        loop {
            let cur_lim = shared.limiter_for_id(&mapping_id);
            let read_cap = cur_lim.read_size(buf.len());
            match tokio::time::timeout(Duration::from_secs(15), tr.read(&mut buf[..read_cap])).await {
                Ok(Ok(0)) => {
                    rt_half.store(true, Ordering::Relaxed);
                    let _ = rw.shutdown().await;
                    break;
                }
                Ok(Ok(n)) => {
                    rt_active.store(mono_now_ms(), Ordering::Relaxed);
                    cur_lim.wait(n).await;
                    if tokio::time::timeout(STREAM_SOCKET_WRITE_TIMEOUT, async {
                        rw.write_all(&buf[..n]).await?;
                        rw.flush().await
                    })
                    .await
                    .map_or(true, |r| r.is_err())
                    {
                        break;
                    }
                }
                Ok(Err(_)) => break,
                Err(_) => {
                    let idle = if rt_half.load(Ordering::Relaxed) {
                        STREAM_HALF_CLOSE_IDLE_MS
                    } else {
                        STREAM_OPEN_IDLE_MS
                    };
                    if mono_now_ms().saturating_sub(rt_active.load(Ordering::Relaxed)) >= idle {
                        break;
                    }
                }
            }
        }
    };

    let tt_active = last_active_ms;
    let tt_half = half_closed;
    let tunnel_to_target = async move {
        let mut buf = vec![0u8; 32768];
        loop {
            match tokio::time::timeout(Duration::from_secs(15), rr.read(&mut buf)).await {
                Ok(Ok(0)) => {
                    tt_half.store(true, Ordering::Relaxed);
                    let _ = tw.shutdown().await;
                    break;
                }
                Ok(Ok(n)) => {
                    tt_active.store(mono_now_ms(), Ordering::Relaxed);
                    if tokio::time::timeout(STREAM_SOCKET_WRITE_TIMEOUT, tw.write_all(&buf[..n]))
                        .await
                        .map_or(true, |r| r.is_err())
                    {
                        break;
                    }
                }
                Ok(Err(_)) => break,
                Err(_) => {
                    let idle = if tt_half.load(Ordering::Relaxed) {
                        STREAM_HALF_CLOSE_IDLE_MS
                    } else {
                        STREAM_OPEN_IDLE_MS
                    };
                    if mono_now_ms().saturating_sub(tt_active.load(Ordering::Relaxed)) >= idle {
                        break;
                    }
                }
            }
        }
    };

    let _ = tokio::join!(target_to_tunnel, tunnel_to_target);
}

fn spawn_hy2_client_udp_responder(
    hy2_sess: Arc<hysteria2::Hy2ClientSession>,
    binding: Binding,
    shared: Arc<ClientSharedTable>,
    mut stop_rx: watch::Receiver<bool>,
) -> tokio::task::AbortHandle {
    tokio::spawn(async move {
        let mut defrag = hysteria2::Hy2UdpDefragmenter::new();
        let mut sessions: HashMap<u32, mpsc::Sender<Vec<u8>>> = HashMap::new();
        loop {
            tokio::select! {
                _ = stop_rx.changed() => break,
                dg_res = hy2_sess.conn.read_datagram() => {
                    let Ok(dg) = dg_res else { break };
                    let Some((sid, addr_str, payload)) = defrag.push(&dg) else {
                        continue;
                    };
                    if let Some(tx) = sessions.get(&sid) {
                        match tx.try_send(payload.clone()) {
                            Ok(()) => continue,
                            Err(mpsc::error::TrySendError::Full(_)) => continue,
                            Err(mpsc::error::TrySendError::Closed(_)) => {
                                sessions.remove(&sid);
                            }
                        }
                    }
                    let Ok((host, port)) = hysteria2::parse_hy2_addr(&addr_str) else {
                        continue;
                    };
                    let Some((m, _)) = shared.find_hy2_udp(&binding.id, &host, port as i64) else {
                        continue;
                    };
                    if sessions.len() >= 256 {
                        sessions.retain(|_, tx| !tx.is_closed());
                        if sessions.len() >= 2048 {
                            continue;
                        }
                    }
                    let mid = m.id.clone();
                    let shared_lim = shared.clone();
                    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(256);
                    let _ = tx.try_send(payload);
                    sessions.insert(sid, tx);
                    let sess_c = hy2_sess.clone();
                    tokio::spawn(async move {
                        let Ok(target_sa) = resolve_socket_addr(&host, port as i64).await else {
                            return;
                        };
                        let bind_sa: SocketAddr = if target_sa.is_ipv6() {
                            "[::]:0".parse().unwrap()
                        } else {
                            "0.0.0.0:0".parse().unwrap()
                        };
                        let Ok(udp_sock) = tokio::net::UdpSocket::bind(bind_sa).await else {
                            return;
                        };
                        if udp_sock.connect(target_sa).await.is_err() {
                            return;
                        }
                        let udp_arc = Arc::new(udp_sock);
                        let udp_recv = udp_arc.clone();
                        let sess_reply = sess_c.clone();
                        let addr_reply = addr_str.clone();
                        let read_task = tokio::spawn(async move {
                            let mut buf = vec![0u8; 65535];
                            let mut pkt_id: u16 = 0;
                            while let Ok(Ok(n)) =
                                tokio::time::timeout(Duration::from_secs(30), udp_recv.recv(&mut buf)).await
                            {
                                shared_lim.limiter_for_id(&mid).wait(n).await;
                                pkt_id = pkt_id.wrapping_add(1);
                                let max_dg = sess_reply.max_datagram_size();
                                for out_dg in hysteria2::encode_hy2_udp_datagrams(
                                    sid,
                                    pkt_id,
                                    &addr_reply,
                                    &buf[..n],
                                    max_dg,
                                ) {
                                    let _ = sess_reply.conn.send_datagram(out_dg);
                                }
                            }
                        });
                        while let Ok(Some(pkt)) =
                            tokio::time::timeout(Duration::from_secs(60), rx.recv()).await
                        {
                            if udp_arc.send(&pkt).await.is_err() {
                                break;
                            }
                        }
                        read_task.abort();
                    });
                }
            }
        }
    })
    .abort_handle()
}

async fn dial_client_session(
    dial_ep: &ConnectEndpoint,
    all_eps: &[ConnectEndpoint],
    client_cfg: &LocalTLS,
    binding: &Binding,
    uuid_bytes: [u8; 16],
    gw_addr: &str,
    vless_enc_cli: Option<Arc<vless_enc::ClientInstance>>,
) -> Result<BoxStream, String> {
    dial_vless_session_port(
        dial_ep,
        all_eps,
        client_cfg,
        binding,
        uuid_bytes,
        gw_addr,
        vless_enc_cli,
        mux_proto::PORT_CONTROL,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn dial_vless_session_port(
    dial_ep: &ConnectEndpoint,
    all_eps: &[ConnectEndpoint],
    client_cfg: &LocalTLS,
    binding: &Binding,
    uuid_bytes: [u8; 16],
    gw_addr: &str,
    vless_enc_cli: Option<Arc<vless_enc::ClientInstance>>,
    port: u16,
) -> Result<BoxStream, String> {
    let remote_addrs = resolve_socket_addrs(&dial_ep.host, dial_ep.port).await?;
    let mut last_err = String::from("no candidate remote addresses");
    for remote_addr in remote_addrs {
        match dial_client_session_addr(
            remote_addr,
            all_eps,
            client_cfg,
            binding,
            uuid_bytes,
            gw_addr,
            vless_enc_cli.clone(),
            port,
        )
        .await
        {
            Ok(s) => return Ok(s),
            Err(e) => last_err = e,
        }
    }
    invalidate_dns_cache(&dial_ep.host, dial_ep.port);
    Err(last_err)
}

#[allow(clippy::too_many_arguments)]
async fn dial_client_session_addr(
    remote_addr: SocketAddr,
    all_eps: &[ConnectEndpoint],
    client_cfg: &LocalTLS,
    binding: &Binding,
    uuid_bytes: [u8; 16],
    gw_addr: &str,
    vless_enc_cli: Option<Arc<vless_enc::ClientInstance>>,
    port: u16,
) -> Result<BoxStream, String> {
    let cached_pfs = vless_enc_cli
        .as_ref()
        .and_then(|c| c.cached_ticket_pfs_key());
    match dial_client_session_once(
        remote_addr,
        all_eps,
        client_cfg,
        binding,
        uuid_bytes,
        gw_addr,
        vless_enc_cli.clone(),
        port,
    )
    .await
    {
        Ok(s) => Ok(s),
        Err(_first_err) if cached_pfs.is_some() => {
            if let (Some(ref enc), Some(ref pfs)) = (&vless_enc_cli, &cached_pfs) {
                enc.invalidate_ticket_if_pfs(pfs);
            }
            dial_client_session_once(
                remote_addr,
                all_eps,
                client_cfg,
                binding,
                uuid_bytes,
                gw_addr,
                vless_enc_cli,
                port,
            )
            .await
        }
        Err(e) => Err(e),
    }
}

#[allow(clippy::too_many_arguments)]
async fn dial_client_session_once(
    remote_addr: SocketAddr,
    all_eps: &[ConnectEndpoint],
    client_cfg: &LocalTLS,
    binding: &Binding,
    uuid_bytes: [u8; 16],
    gw_addr: &str,
    vless_enc_cli: Option<Arc<vless_enc::ClientInstance>>,
    port: u16,
) -> Result<BoxStream, String> {
    if client_cfg.hysteria2.enabled() {
        let sess = hysteria2::hy2_connect_session(remote_addr, client_cfg, binding, gw_addr).await?;
        return sess.open_tcp_stream(binding.domain.trim(), port).await;
    }

    let mut outer = if client_cfg.xhttp.enabled() {
        let dn_target = if !client_cfg.xhttp.download_endpoint_id.is_empty() {
            if let Some(dn_ep) = all_eps
                .iter()
                .find(|e| e.id == client_cfg.xhttp.download_endpoint_id)
            {
                resolve_socket_addr(&dn_ep.host, dn_ep.port)
                    .await
                    .ok()
                    .map(|sa| (sa, client_cfg.clone()))
            } else {
                None
            }
        } else {
            None
        };
        let gw_owned = gw_addr.to_string();
        let x_stream = tokio::time::timeout(
            Duration::from_secs(20),
            xhttp::xhttp_client_connect(
                remote_addr,
                client_cfg,
                dn_target,
                binding,
                gw_addr,
                move |sa, lcfg, b| {
                    let g = gw_owned.clone();
                    async move { connect_outer_stream(sa, lcfg, b, g).await }
                },
            ),
        )
        .await
        .map_err(|_| "xhttp connect timeout".to_string())??;
        vision::VisionInner::Boxed(x_stream)
    } else {
        connect_outer_vision_inner(
            remote_addr,
            client_cfg.clone(),
            binding.clone(),
            gw_addr.to_string(),
        )
        .await?
    };

    if let Some(enc) = vless_enc_cli {
        let enc_s = tokio::time::timeout(Duration::from_secs(8), enc.handshake(outer.into_box_stream()))
            .await
            .map_err(|_| "vless encryption handshake timeout".to_string())?
            .map_err(|e| e.to_string())?;
        outer = vision::VisionInner::Boxed(enc_s);
    }

    struct VisionInnerIo<'a>(&'a mut vision::VisionInner);
    impl AsyncRead for VisionInnerIo<'_> {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            match &mut *self.0 {
                vision::VisionInner::Boxed(s) => std::pin::Pin::new(s).poll_read(cx, buf),
                vision::VisionInner::Reality(s) => std::pin::Pin::new(s).poll_read(cx, buf),
                vision::VisionInner::Rustls(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            }
        }
    }
    impl AsyncWrite for VisionInnerIo<'_> {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            match &mut *self.0 {
                vision::VisionInner::Boxed(s) => std::pin::Pin::new(s).poll_write(cx, buf),
                vision::VisionInner::Reality(s) => std::pin::Pin::new(s).poll_write(cx, buf),
                vision::VisionInner::Rustls(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            }
        }
        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            match &mut *self.0 {
                vision::VisionInner::Boxed(s) => std::pin::Pin::new(s).poll_flush(cx),
                vision::VisionInner::Reality(s) => std::pin::Pin::new(s).poll_flush(cx),
                vision::VisionInner::Rustls(s) => std::pin::Pin::new(s).poll_flush(cx),
            }
        }
        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            match &mut *self.0 {
                vision::VisionInner::Boxed(s) => std::pin::Pin::new(s).poll_shutdown(cx),
                vision::VisionInner::Reality(s) => std::pin::Pin::new(s).poll_shutdown(cx),
                vision::VisionInner::Rustls(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            }
        }
    }

    let flow = normalize_flow(&client_cfg.flow).unwrap_or_default();
    {
        let mut io = VisionInnerIo(&mut outer);
        if flow == FLOW_VISION {
            let mut init_flight = Vec::with_capacity(1500);
            encode_vless_request_into(&mut init_flight, uuid_bytes, &binding.domain, port, flow)?;
            vision::append_initial_camouflage(&mut init_flight, &uuid_bytes);
            io.write_all(&init_flight).await.map_err(|e| e.to_string())?;
        } else {
            write_vless_with_flow(&mut io, uuid_bytes, &binding.domain, port, flow).await?;
        }
        io.flush().await.map_err(|e| e.to_string())?;

        let mut resp = [0u8; 2];
        tokio::time::timeout(Duration::from_secs(8), io.read_exact(&mut resp))
            .await
            .map_err(|_| "vless response timeout".to_string())?
            .map_err(|e| e.to_string())?;
        if resp != [0, 0] {
            return Err("invalid vless response header".to_string());
        }
    }

    if flow == FLOW_VISION {
        Ok(vision::wrap_vision_inner_started(outer, uuid_bytes))
    } else {
        Ok(outer.into_box_stream())
    }
}

fn handle_client_dial_app(
    req_id: u32,
    payload: Vec<u8>,
    binding: &Binding,
    shared: &Arc<ClientSharedTable>,
    sender: &SessionSender,
    sub_dialer: ClientSubchannelDialer,
) {
    if payload.len() < 3 {
        sender.send_ctrl_bg(FRAME_RESET, req_id, Vec::new());
        return;
    }
    let port = u16::from_be_bytes([payload[0], payload[1]]) as i64;
    let Ok(host) = String::from_utf8(payload[2..].to_vec()) else {
        sender.send_ctrl_bg(FRAME_RESET, req_id, Vec::new());
        return;
    };
    let Some((m, _)) = shared.find_dial_app(&binding.id, &host, port) else {
        sender.send_ctrl_bg(FRAME_RESET, req_id, Vec::new());
        return;
    };
    let mid = m.id.clone();
    let shared_c = shared.clone();
    let sender_fail = sender.clone();

    tokio::spawn(async move {
        let target_fut = async {
            let addrs = resolve_socket_addrs(&host, port).await?;
            let s = tokio::time::timeout(Duration::from_secs(8), TcpStream::connect(addrs.as_slice()))
                .await
                .map_err(|_| "target connect timeout".to_string())?
                .map_err(|e| e.to_string())?;
            configure_tcp_stream(&s);
            Ok::<TcpStream, String>(s)
        };
        let app_fut = sub_dialer.dial_port(mux_proto::PORT_APPLICATION);

        let Ok((target_stream, mut app_stream)) = tokio::try_join!(target_fut, app_fut) else {
            sender_fail.send_ctrl_bg(FRAME_RESET, req_id, Vec::new());
            return;
        };

        let mut hdr = Vec::with_capacity(26);
        hdr.extend_from_slice(mux_proto::APP_STREAM_PREFACE);
        hdr.extend_from_slice(&req_id.to_be_bytes());
        if tokio::time::timeout(Duration::from_secs(8), async {
            app_stream.write_all(&hdr).await?;
            app_stream.flush().await
        })
        .await
        .map_or(true, |r| r.is_err())
        {
            sender_fail.send_ctrl_bg(FRAME_RESET, req_id, Vec::new());
            return;
        }

        relay_raw_streams_client(target_stream, app_stream, shared_c, mid).await;
    });
}

fn handle_client_dial_mux(
    payload: Vec<u8>,
    binding: &Binding,
    shared: &Arc<ClientSharedTable>,
    sub_dialer: ClientSubchannelDialer,
    mut stop_rx: watch::Receiver<bool>,
) {
    let Ok(mux_type_str) = std::str::from_utf8(&payload) else {
        return;
    };
    let Some(proto) = mux_proto::SingMuxProto::from_mux_type(mux_type_str) else {
        return;
    };
    if !shared.allow_mux_proto(&binding.id, proto.as_str()) {
        return;
    }

    let binding_c = binding.clone();
    let shared_c = shared.clone();

    tokio::spawn(async move {
        let Ok(mut mux_stream) = sub_dialer.dial_port(mux_proto::PORT_SING_MUX).await else {
            return;
        };
        let mut hdr = Vec::with_capacity(21);
        hdr.extend_from_slice(mux_proto::SING_MUX_PREFACE);
        hdr.push(0x00);
        hdr.push(proto as u8);
        if tokio::time::timeout(Duration::from_secs(8), async {
            mux_stream.write_all(&hdr).await?;
            mux_stream.flush().await
        })
        .await
        .map_or(true, |r| r.is_err())
        {
            return;
        }

        tokio::select! {
            _ = stop_rx.changed() => {}
            _ = mux_proto::serve_sing_mux_responder(mux_stream, proto, move |mut sub| {
                let b_sub = binding_c.clone();
                let s_sub = shared_c.clone();
                tokio::spawn(async move {
                    let Ok(Ok((host, port, is_udp))) = tokio::time::timeout(
                        Duration::from_secs(8),
                        mux_proto::read_sing_mux_stream_request(&mut sub),
                    )
                    .await
                    else {
                        return;
                    };
                    if is_udp {
                        let _ = mux_proto::write_sing_mux_stream_response(&mut sub, Some("udp unsupported on tcp mux")).await;
                        return;
                    }
                    let Some((m, _)) = s_sub.find_mux_substream(&b_sub.id, proto.as_str(), &host, port as i64) else {
                        let _ = mux_proto::write_sing_mux_stream_response(&mut sub, Some("mapping not authorized")).await;
                        return;
                    };
                    let Ok(addrs) = resolve_socket_addrs(&host, port as i64).await else {
                        let _ = mux_proto::write_sing_mux_stream_response(&mut sub, Some("dns failed")).await;
                        return;
                    };
                    let Ok(Ok(target_stream)) = tokio::time::timeout(
                        Duration::from_secs(8),
                        TcpStream::connect(addrs.as_slice()),
                    )
                    .await
                    else {
                        let _ = mux_proto::write_sing_mux_stream_response(&mut sub, Some("connect failed")).await;
                        return;
                    };
                    configure_tcp_stream(&target_stream);
                    if mux_proto::write_sing_mux_stream_response(&mut sub, None)
                        .await
                        .is_err()
                    {
                        return;
                    }
                    relay_raw_streams_client(target_stream, sub, s_sub, m.id).await;
                });
            }) => {}
        }
    });
}

fn handle_client_frame_open(
    id: u32,
    payload: Vec<u8>,
    binding: &Binding,
    shared: &Arc<ClientSharedTable>,
    sender: &SessionSender,
    streams_map: &Arc<Mutex<HashMap<u32, mpsc::Sender<(u8, Vec<u8>)>>>>,
) {
    if payload.len() < 3 {
        sender.send_ctrl_bg(FRAME_RESET, id, Vec::new());
        return;
    }
    let port = u16::from_be_bytes([payload[0], payload[1]]) as i64;
    let Ok(raw_meta) = String::from_utf8(payload[2..].to_vec()) else {
        sender.send_ctrl_bg(FRAME_RESET, id, Vec::new());
        return;
    };
    let mut parts = raw_meta.split('\0');
    let host = parts.next().unwrap_or("").to_string();
    let req_net = parts.next().unwrap_or("tcp");
    let req_mux = parts.next().unwrap_or("");
    let has_meta = raw_meta.contains('\0');

    let Some((matched_m, _)) = shared.find_frame_open(&binding.id, &host, port, has_meta, req_net, req_mux) else {
        sender.send_ctrl_bg(FRAME_RESET, id, Vec::new());
        return;
    };
    let mid_lim = matched_m.id.clone();
    let shared_lim = shared.clone();

    let (stx, mut srx) = mpsc::channel::<(u8, Vec<u8>)>(STREAM_CHAN_CAP);
    streams_map.lock().unwrap().insert(id, stx);
    let sender_back = sender.clone();
    let streams_done = streams_map.clone();

    if req_net == "udp" {
        tokio::spawn(async move {
            let Ok(target_sa) = resolve_socket_addr(&host, port).await else {
                streams_done.lock().unwrap().remove(&id);
                sender_back.send_ctrl_bg(FRAME_RESET, id, Vec::new());
                return;
            };
            let bind_sa: SocketAddr = if target_sa.is_ipv6() {
                "[::]:0".parse().unwrap()
            } else {
                "0.0.0.0:0".parse().unwrap()
            };
            let Ok(udp_sock) = tokio::net::UdpSocket::bind(bind_sa).await else {
                streams_done.lock().unwrap().remove(&id);
                sender_back.send_ctrl_bg(FRAME_RESET, id, Vec::new());
                return;
            };
            if udp_sock.connect(target_sa).await.is_err() {
                streams_done.lock().unwrap().remove(&id);
                sender_back.send_ctrl_bg(FRAME_RESET, id, Vec::new());
                return;
            };
            let udp_arc = Arc::new(udp_sock);
            let udp_recv = udp_arc.clone();
            let sender_read = sender_back.clone();
            let shared_read = shared_lim.clone();
            let mid_read = mid_lim.clone();
            let xudp_sid_shared = Arc::new(std::sync::atomic::AtomicU16::new(0));
            let xudp_sid_reply = xudp_sid_shared.clone();
            let read_target = tokio::spawn(async move {
                let mut buf = vec![0u8; 65535];
                while let Ok(Ok(n)) =
                    tokio::time::timeout(Duration::from_secs(30), udp_recv.recv(&mut buf)).await
                {
                    shared_read.limiter_for_id(&mid_read).wait(n).await;
                    let sid = xudp_sid_reply.load(Ordering::Relaxed);
                    let xudp = mux_proto::encode_xudp_keep(sid, &buf[..n]);
                    if xudp.len() > MAX_PAYLOAD {
                        continue;
                    }
                    if sender_read.send_data(FRAME_DATA, id, xudp).await.is_err() {
                        break;
                    }
                }
            });
            while let Ok(Some((k, data))) =
                tokio::time::timeout(Duration::from_secs(60), srx.recv()).await
            {
                match k {
                    FRAME_DATA => {
                        let Ok(dec) = mux_proto::decode_xudp_packet(&data) else {
                            break;
                        };
                        xudp_sid_shared.store(dec.session_id, Ordering::Relaxed);
                        if dec.status == mux_proto::XUDP_STATUS_END {
                            break;
                        }
                        if let Some((ref req_h, req_p)) = dec.target {
                            if req_h != &host || req_p as i64 != port {
                                break;
                            }
                        }
                        if !dec.payload.is_empty() && udp_arc.send(dec.payload).await.is_err() {
                            break;
                        }
                    }
                    _ => break,
                }
            }
            read_target.abort();
            streams_done.lock().unwrap().remove(&id);
            sender_back.send_ctrl_bg(FRAME_RESET, id, Vec::new());
        });
    } else {
        tokio::spawn(async move {
            let Ok(target_addrs) = resolve_socket_addrs(&host, port).await else {
                streams_done.lock().unwrap().remove(&id);
                sender_back.send_ctrl_bg(FRAME_RESET, id, Vec::new());
                return;
            };
            let Ok(Ok(target_stream)) =
                tokio::time::timeout(
                    Duration::from_secs(8),
                    TcpStream::connect(target_addrs.as_slice()),
                )
                .await
            else {
                streams_done.lock().unwrap().remove(&id);
                sender_back.send_ctrl_bg(FRAME_RESET, id, Vec::new());
                return;
            };
            configure_tcp_stream(&target_stream);
            let (mut tr, mut tw) = target_stream.into_split();
            let sender_read = sender_back.clone();
            let shared_read = shared_lim.clone();
            let mid_read = mid_lim.clone();
            let last_active_ms = Arc::new(AtomicU64::new(mono_now_ms()));
            let any_half_closed = Arc::new(AtomicBool::new(false));
            let rt_active = last_active_ms.clone();
            let rt_half = any_half_closed.clone();
            let mut read_target = tokio::spawn(async move {
                let mut buf = vec![0u8; OPTIMAL_DATA_CHUNK];
                loop {
                    let cur_lim = shared_read.limiter_for_id(&mid_read);
                    let read_cap = cur_lim.read_size(buf.len());
                    match tokio::time::timeout(Duration::from_secs(15), tr.read(&mut buf[..read_cap])).await {
                        Ok(Ok(0)) => {
                            rt_half.store(true, Ordering::Relaxed);
                            let _ = sender_read.send_data(FRAME_HALF, id, Vec::new()).await;
                            break;
                        }
                        Ok(Ok(n)) => {
                            rt_active.store(mono_now_ms(), Ordering::Relaxed);
                            cur_lim.wait(n).await;
                            if sender_read
                                .send_data(FRAME_DATA, id, buf[..n].to_vec())
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        Ok(Err(_)) => {
                            sender_read.send_ctrl_bg(FRAME_RESET, id, Vec::new());
                            break;
                        }
                        Err(_) => {
                            let idle_limit = if rt_half.load(Ordering::Relaxed) {
                                STREAM_HALF_CLOSE_IDLE_MS
                            } else {
                                STREAM_OPEN_IDLE_MS
                            };
                            if mono_now_ms().saturating_sub(rt_active.load(Ordering::Relaxed))
                                >= idle_limit
                            {
                                sender_read.send_ctrl_bg(FRAME_RESET, id, Vec::new());
                                break;
                            }
                        }
                    }
                }
            });
            let mut peer_reset = false;
            let mut half_closed = false;
            loop {
                match tokio::time::timeout(Duration::from_secs(15), srx.recv()).await {
                    Ok(Some((k, data))) => match k {
                        FRAME_DATA => {
                            last_active_ms.store(mono_now_ms(), Ordering::Relaxed);
                            if tokio::time::timeout(
                                STREAM_SOCKET_WRITE_TIMEOUT,
                                tw.write_all(&data),
                            )
                            .await
                            .map_or(true, |r| r.is_err())
                            {
                                break;
                            }
                        }
                        FRAME_HALF => {
                            half_closed = true;
                            any_half_closed.store(true, Ordering::Relaxed);
                            let _ = tw.shutdown().await;
                            break;
                        }
                        FRAME_RESET => {
                            peer_reset = true;
                            break;
                        }
                        _ => break,
                    },
                    Ok(None) => break,
                    Err(_) => {
                        let idle_limit = if any_half_closed.load(Ordering::Relaxed) {
                            STREAM_HALF_CLOSE_IDLE_MS
                        } else {
                            STREAM_OPEN_IDLE_MS
                        };
                        if mono_now_ms().saturating_sub(last_active_ms.load(Ordering::Relaxed))
                            >= idle_limit
                        {
                            break;
                        }
                    }
                }
            }
            if half_closed && !peer_reset {
                tokio::select! {
                    _ = &mut read_target => {}
                    _ = async {
                        while let Some((k, _)) = srx.recv().await {
                            if k == FRAME_RESET {
                                break;
                            }
                        }
                    } => {
                        peer_reset = true;
                        read_target.abort();
                    }
                }
            } else {
                read_target.abort();
            }
            drop(srx);
            streams_done.lock().unwrap().remove(&id);
            if !peer_reset && !half_closed {
                sender_back.send_ctrl_bg(FRAME_RESET, id, Vec::new());
            }
        });
    }
}

struct RuntimeState {
    local: LocalTLS,
    instance: Option<RunningInstance>,
    good: Option<Snapshot>,
    good_local: LocalTLS,
    document: Vec<u8>,
    revision: i64,
    high_water: i64,
    closed: bool,
}

pub struct Runtime {
    state: Mutex<RuntimeState>,
    traffic: Arc<Traffic>,
    state_notify: Arc<tokio::sync::Notify>,
    logger: Mutex<TunnelLogger>,
}

impl Runtime {
    pub fn new(local: LocalTLS) -> Self {
        Self {
            state: Mutex::new(RuntimeState {
                local,
                instance: None,
                good: None,
                good_local: LocalTLS::default(),
                document: Vec::new(),
                revision: -1,
                high_water: -1,
                closed: false,
            }),
            traffic: Arc::new(Traffic::new()),
            state_notify: Arc::new(tokio::sync::Notify::new()),
            logger: Mutex::new(None),
        }
    }

    pub fn set_logger(&self, ring: Arc<Ring>, node_id: String, role: String) {
        *self.logger.lock().unwrap() = Some((ring, node_id, role));
    }

    pub fn traffic(&self) -> Arc<Traffic> {
        self.traffic.clone()
    }

    pub async fn state_notified(&self) {
        self.state_notify.notified().await;
    }

    pub fn linked_bindings(&self) -> Vec<String> {
        let g = self.state.lock().unwrap();
        if let Some(ref inst) = g.instance {
            let mut ids: Vec<String> = inst.linked.lock().unwrap().iter().cloned().collect();
            ids.sort();
            ids
        } else {
            Vec::new()
        }
    }

    pub fn revision(&self) -> i64 {
        self.state.lock().unwrap().revision
    }

    pub fn close(&self) -> Result<(), String> {
        let mut g = self.state.lock().unwrap();
        g.closed = true;
        g.revision = -1;
        if let Some(mut inst) = g.instance.take() {
            inst.stop();
        }
        Ok(())
    }

    pub fn apply(&self, s: Snapshot) -> Result<(), String> {
        let mut g = self.state.lock().unwrap();
        if g.closed {
            return Err("tunnel runtime is closed".to_string());
        }
        if s.revision < g.high_water {
            return Err(format!(
                "stale revision {} (last successful {})",
                s.revision, g.high_water
            ));
        }
        let effective = s.node.tunnel.merge(&g.local);
        let document = build(&s, &effective)?;
        let same = g
            .good
            .as_ref()
            .map(|good| same_configuration(good, &s) && g.good_local == effective)
            .unwrap_or(false);
        if s.revision == g.high_water && !same {
            return Err("revision reused with different configuration".to_string());
        }
        if g.instance.is_some() && same && document == g.document {
            g.revision = s.revision;
            g.high_water = s.revision;
            return Ok(());
        }
        let old_revision = g.revision;
        let logger = self.logger.lock().unwrap().clone();
        self.traffic
            .prepare_active(&s.mappings, s.node.role == "server");

        let mut inst = match g.instance.take() {
            Some(existing) if existing.role == s.node.role => existing,
            Some(mut existing) => {
                existing.stop();
                RunningInstance::new(&s.node.role)
            }
            None => RunningInstance::new(&s.node.role),
        };

        match reconcile_instance(
            &mut inst,
            &s,
            &effective,
            self.traffic.clone(),
            self.state_notify.clone(),
            logger.clone(),
        ) {
            Ok(()) => {
                self.traffic
                    .set_active(&s.mappings, s.node.role == "server");
                g.instance = Some(inst);
                g.good = Some(s.clone());
                g.good_local = effective;
                g.document = document;
                g.revision = s.revision;
                g.high_water = s.revision;
                self.state_notify.notify_waiters();
                Ok(())
            }
            Err(err) => {
                if idle_snapshot(&s) {
                    inst.stop();
                    self.traffic.set_active(&[], false);
                    return Err(format!("stop listeners: {}", err));
                }
                if let Some(good) = g.good.clone() {
                    let good_local = g.good_local.clone();
                    match reconcile_instance(
                        &mut inst,
                        &good,
                        &good_local,
                        self.traffic.clone(),
                        self.state_notify.clone(),
                        logger,
                    ) {
                        Ok(()) => {
                            self.traffic
                                .set_active(&good.mappings, good.node.role == "server");
                            g.instance = Some(inst);
                            g.revision = if old_revision < 0 {
                                g.high_water
                            } else {
                                old_revision
                            };
                            return Err(format!(
                                "start failed (restored revision {}): {}",
                                g.revision, err
                            ));
                        }
                        Err(rollback_err) => {
                            inst.stop();
                            self.traffic.set_active(&[], false);
                            return Err(format!(
                                "start failed: {}; rollback failed: {}",
                                err, rollback_err
                            ));
                        }
                    }
                }
                inst.stop();
                self.traffic.set_active(&[], false);
                Err(format!("start tunnel: {}", err))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Reality, XHTTP};

    fn test_session() -> (
        SessionHandle,
        (
            mpsc::Receiver<(u8, u32, Vec<u8>)>,
            mpsc::Receiver<(u8, u32, Vec<u8>)>,
        ),
    ) {
        let (ctrl_tx, ctrl_rx) = mpsc::channel(4);
        let (data_tx, data_rx) = mpsc::channel(4);
        let (h, _kill_rx) =
            SessionHandle::new(ctrl_tx, data_tx, Arc::new(Mutex::new(HashMap::new())));
        (h, (ctrl_rx, data_rx))
    }

    #[test]
    fn test_session_cleanup_releases_streams_and_handles() {
        let sessions: SessionMap = Arc::new(Mutex::new(HashMap::new()));
        let (old, old_rx) = test_session();
        let (cur, _cur_rx) = test_session();
        sessions
            .lock()
            .unwrap()
            .insert("b".to_string(), vec![old.clone(), cur.clone()]);

        let (id, _rx) = cur.open_stream().unwrap();
        cur.close_stream(id);
        assert!(cur.streams.lock().unwrap().is_empty());

        // A dead writer must never be picked for new mapping connections.
        drop(_cur_rx);
        let picked = pick_session(&sessions, "b").unwrap();
        assert!(Arc::ptr_eq(&picked.streams, &old.streams));

        let (_id, mut stream_rx) = old.open_stream().unwrap();
        // Removing the last live session also prunes the closed one.
        assert!(remove_session(&sessions, "b", &old));
        assert!(old.streams.lock().unwrap().is_empty());
        assert!(matches!(
            stream_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Disconnected)
        ));
        drop(old_rx);
        assert!(sessions.lock().unwrap().get("b").is_none());
        assert!(pick_session(&sessions, "b").is_none());
    }

    #[test]
    fn test_xhttp_effective_mode_auto_matrix() {
        let mut x = XHTTP {
            path: "/veilink/".to_string(),
            mode: "auto".to_string(),
            ..Default::default()
        };
        assert_eq!(xhttp_effective_mode(&x, false), "packet-up");
        assert_eq!(xhttp_effective_mode(&x, true), "stream-one");
        x.download_endpoint_id = "ep-down".to_string();
        assert_eq!(xhttp_effective_mode(&x, true), "stream-up");
    }

    #[test]
    fn test_xhttp_auto_with_reality_validates() {
        let (priv_k, pub_k) = generate_x25519().unwrap();
        let local = LocalTLS {
            protocol: "vless".to_string(),
            transport_security: "tls".to_string(),
            reality: Reality {
                dest: "example.com:443".to_string(),
                private_key: priv_k,
                public_key: pub_k,
                short_id: "0102030405060708".to_string(),
                server_names: "example.com".to_string(),
                ..Default::default()
            },
            xhttp: XHTTP {
                path: "/veilink/".to_string(),
                mode: "auto".to_string(),
                tls: false,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(check_bootstrap("server", &local).is_ok());
    }

    fn reserve_free_tcp_port() -> i64 {
        let ln = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        ln.local_addr().unwrap().port() as i64
    }

    fn reserve_free_udp_port() -> i64 {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.local_addr().unwrap().port() as i64
    }

    fn generate_test_cert(domain: &str) -> (String, String, String) {
        let mut ca_params = rcgen::CertificateParams::new(vec!["Veilink Test Root CA".to_string()]).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let ca_kp = rcgen::KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_kp).unwrap();

        let mut ee_params = rcgen::CertificateParams::new(vec![
            domain.to_string(),
            "localhost".to_string(),
            "127.0.0.1".to_string(),
        ])
        .unwrap();
        ee_params.is_ca = rcgen::IsCa::NoCa;
        ee_params.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let ee_kp = rcgen::KeyPair::generate().unwrap();
        let ee_cert = ee_params.signed_by(&ee_kp, &ca_cert, &ca_kp).unwrap();
        (ca_cert.pem(), ee_cert.pem(), ee_kp.serialize_pem())
    }

    #[derive(Clone)]
    struct MatrixMappingSpec {
        name: &'static str,
        network: &'static str,
        mux: bool,
        mux_type: &'static str,
    }

    fn all_mapping_specs() -> Vec<MatrixMappingSpec> {
        vec![
            MatrixMappingSpec {
                name: "off",
                network: "tcp",
                mux: false,
                mux_type: "",
            },
            MatrixMappingSpec {
                name: "smux",
                network: "tcp",
                mux: true,
                mux_type: "smux",
            },
            MatrixMappingSpec {
                name: "yamux",
                network: "tcp",
                mux: true,
                mux_type: "yamux",
            },
            MatrixMappingSpec {
                name: "h2mux",
                network: "tcp",
                mux: true,
                mux_type: "h2mux",
            },
            MatrixMappingSpec {
                name: "udp",
                network: "udp",
                mux: false,
                mux_type: "",
            },
        ]
    }

    async fn run_matrix_case(
        transport_name: &str,
        mut server_local: LocalTLS,
        mspec: &MatrixMappingSpec,
    ) {
        let domain = "edge.matrix.example.com";
        let transport_port = if server_local.hysteria2.enabled()
            || (server_local.xhttp.enabled() && server_local.xhttp.http_version.trim() == "3")
        {
            reserve_free_udp_port()
        } else {
            reserve_free_tcp_port()
        };
        server_local.listen_host = "127.0.0.1".to_string();
        server_local.listen_port = transport_port;

        let (target_port, _echo_guard) = if mspec.network == "udp" {
            let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let port = sock.local_addr().unwrap().port() as i64;
            let handle = tokio::spawn(async move {
                let mut buf = vec![0u8; 65535];
                while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
                    let _ = sock.send_to(&buf[..n], peer).await;
                }
            });
            (port, handle)
        } else {
            let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = ln.local_addr().unwrap().port() as i64;
            let handle = tokio::spawn(async move {
                while let Ok((mut s, _)) = ln.accept().await {
                    tokio::spawn(async move {
                        let (mut r, mut w) = s.split();
                        let _ = tokio::io::copy(&mut r, &mut w).await;
                        let _ = w.shutdown().await;
                    });
                }
            });
            (port, handle)
        };

        let listen_port = if mspec.network == "udp" {
            reserve_free_udp_port()
        } else {
            reserve_free_tcp_port()
        };

        let srv_node_for_server = Node {
            id: "srv-1".to_string(),
            name: "srv-1".to_string(),
            role: "server".to_string(),
            address: "127.0.0.1".to_string(),
            port: transport_port,
            connect_endpoints: vec![ConnectEndpoint {
                id: "ep-1".to_string(),
                name: "primary".to_string(),
                host: "127.0.0.1".to_string(),
                port: transport_port,
                enabled: true,
            }],
            tunnel: server_local.clone(),
            ..Default::default()
        };
        let client_template = derive_client_tunnel(&LocalTLS::default(), &server_local, &srv_node_for_server)
            .unwrap_or_else(|e| panic!("{}/{}: derive_client_tunnel failed: {}", transport_name, mspec.name, e));
        let mut srv_node_for_client = srv_node_for_server.clone();
        srv_node_for_client.tunnel = client_template;

        let cli_node = Node {
            id: "cli-1".to_string(),
            name: "cli-1".to_string(),
            role: "client".to_string(),
            address: "127.0.0.1".to_string(),
            port: 19001,
            ..Default::default()
        };
        let binding = Binding {
            id: "bind-1".to_string(),
            server_id: "srv-1".to_string(),
            client_id: "cli-1".to_string(),
            uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            domain: domain.to_string(),
            ..Default::default()
        };
        let mapping = Mapping {
            id: "map-1".to_string(),
            name: format!("{}-{}", transport_name, mspec.name),
            binding_id: "bind-1".to_string(),
            server_id: "srv-1".to_string(),
            client_id: "cli-1".to_string(),
            listen_host: "127.0.0.1".to_string(),
            listen_port,
            target_host: "127.0.0.1".to_string(),
            target_port,
            network: mspec.network.to_string(),
            pool: 2,
            mux: mspec.mux,
            mux_type: mspec.mux_type.to_string(),
            enabled: true,
            ..Default::default()
        };

        let srv_snap = Snapshot {
            revision: 1,
            node: srv_node_for_server,
            nodes: vec![],
            bindings: vec![binding.clone()],
            mappings: vec![mapping.clone()],
        };
        let cli_snap = Snapshot {
            revision: 1,
            node: cli_node,
            nodes: vec![srv_node_for_client],
            bindings: vec![binding],
            mappings: vec![mapping],
        };

        let srv_rt = Runtime::new(server_local);
        srv_rt
            .apply(srv_snap)
            .unwrap_or_else(|e| panic!("{}/{}: srv apply failed: {}", transport_name, mspec.name, e));

        let cli_rt = Runtime::new(LocalTLS::default());
        cli_rt
            .apply(cli_snap)
            .unwrap_or_else(|e| panic!("{}/{}: cli apply failed: {}", transport_name, mspec.name, e));

        let mut ready = false;
        for _ in 0..80 {
            if srv_rt.linked_bindings().contains(&"bind-1".to_string())
                && cli_rt.linked_bindings().contains(&"bind-1".to_string())
            {
                ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            ready,
            "{}/{}: tunnel did not become linked within timeout",
            transport_name, mspec.name
        );

        let mut join_set = Vec::new();
        for peer_idx in 0..3usize {
            let tname = transport_name.to_string();
            let mname = mspec.name.to_string();
            let is_udp = mspec.network == "udp";
            join_set.push(tokio::spawn(async move {
                if is_udp {
                    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
                    sock.connect(format!("127.0.0.1:{}", listen_port))
                        .await
                        .unwrap();
                    let mut payload = vec![0u8; 1024];
                    for (i, b) in payload.iter_mut().enumerate() {
                        *b = ((i + peer_idx * 31) & 0xff) as u8;
                    }
                    sock.send(&payload).await.unwrap();
                    let mut recv_buf = vec![0u8; 2048];
                    let n = tokio::time::timeout(Duration::from_secs(5), sock.recv(&mut recv_buf))
                        .await
                        .unwrap_or_else(|_| panic!("{}/{}: peer {} udp recv timeout", tname, mname, peer_idx))
                        .unwrap();
                    assert_eq!(&recv_buf[..n], payload.as_slice(), "{}/{}: udp payload mismatch", tname, mname);
                } else {
                    let mut conn = TcpStream::connect(format!("127.0.0.1:{}", listen_port))
                        .await
                        .unwrap();
                    let mut payload = vec![0u8; 64 * 1024];
                    for (i, b) in payload.iter_mut().enumerate() {
                        *b = ((i * 7 + peer_idx * 17) & 0xff) as u8;
                    }
                    conn.write_all(&payload).await.unwrap();
                    conn.shutdown().await.unwrap();
                    let mut echoed = Vec::with_capacity(payload.len());
                    tokio::time::timeout(Duration::from_secs(8), conn.read_to_end(&mut echoed))
                        .await
                        .unwrap_or_else(|_| panic!("{}/{}: peer {} tcp read timeout", tname, mname, peer_idx))
                        .unwrap();
                    assert_eq!(echoed.len(), payload.len(), "{}/{}: tcp length mismatch", tname, mname);
                    assert_eq!(echoed, payload, "{}/{}: tcp payload mismatch", tname, mname);
                }
            }));
        }
        for j in join_set {
            j.await.unwrap();
        }

        let _ = cli_rt.close();
        let _ = srv_rt.close();
        _echo_guard.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_full_protocol_matrix_round_trip() {
        let domain = "edge.matrix.example.com";
        let (ca_pem, cert_pem, key_pem) = generate_test_cert(domain);
        let (x_priv, x_pub) = generate_x25519().unwrap();
        let (_x_dec, _x_enc, pq_dec, _pq_enc) = generate_vless_enc().unwrap();
        let (mldsa_seed, mldsa_verify) = generate_mldsa65().unwrap();

        let reality_base = Reality {
            dest: "127.0.0.1:443".to_string(),
            private_key: x_priv.clone(),
            public_key: x_pub.clone(),
            short_id: "0102030405060708".to_string(),
            server_names: domain.to_string(),
            fingerprint: "chrome".to_string(),
            max_time_diff: "2m".to_string(),
            ..Default::default()
        };

        let mut reality_mldsa = reality_base.clone();
        reality_mldsa.mldsa65_seed = mldsa_seed;
        reality_mldsa.mldsa65_verify = mldsa_verify;

        let transports: Vec<(&str, LocalTLS)> = vec![
            // === Original 15 profiles from protocol_matrix_test.go (15 x 5 = 75 cases) ===
            // 1. tls / enc=false / vision=false
            (
                "tls/enc=false/vision=false",
                LocalTLS {
                    protocol: "vless".to_string(),
                    transport_security: "tls".to_string(),
                    cert_pem: cert_pem.clone(),
                    key_pem: key_pem.clone(),
                    ca_pem: ca_pem.clone(),
                    ..Default::default()
                },
            ),
            // 2. reality / enc=false / vision=false
            (
                "reality/enc=false/vision=false",
                LocalTLS {
                    protocol: "vless".to_string(),
                    transport_security: "tls".to_string(),
                    reality: reality_base.clone(),
                    ..Default::default()
                },
            ),
            // 3. plain / enc=true / vision=false
            (
                "plain/enc=true/vision=false",
                LocalTLS {
                    protocol: "vless".to_string(),
                    transport_security: "plain".to_string(),
                    decryption: pq_dec.clone(),
                    ..Default::default()
                },
            ),
            // 4. hysteria2 / enc=false / vision=false
            (
                "hysteria2/enc=false/vision=false",
                LocalTLS {
                    protocol: "hysteria2".to_string(),
                    transport_security: "tls".to_string(),
                    cert_pem: cert_pem.clone(),
                    key_pem: key_pem.clone(),
                    ca_pem: ca_pem.clone(),
                    hysteria2: Hysteria2 {
                        password: "matrix-hy2-password".to_string(),
                    },
                    ..Default::default()
                },
            ),
            // 5. tls / enc=true / vision=false
            (
                "tls/enc=true/vision=false",
                LocalTLS {
                    protocol: "vless".to_string(),
                    transport_security: "tls".to_string(),
                    cert_pem: cert_pem.clone(),
                    key_pem: key_pem.clone(),
                    ca_pem: ca_pem.clone(),
                    decryption: pq_dec.clone(),
                    ..Default::default()
                },
            ),
            // 6. reality / enc=true / vision=false
            (
                "reality/enc=true/vision=false",
                LocalTLS {
                    protocol: "vless".to_string(),
                    transport_security: "tls".to_string(),
                    decryption: pq_dec.clone(),
                    reality: reality_base.clone(),
                    ..Default::default()
                },
            ),
            // 7. tls / enc=false / vision=true
            (
                "tls/enc=false/vision=true",
                LocalTLS {
                    protocol: "vless".to_string(),
                    transport_security: "tls".to_string(),
                    cert_pem: cert_pem.clone(),
                    key_pem: key_pem.clone(),
                    ca_pem: ca_pem.clone(),
                    flow: FLOW_VISION.to_string(),
                    ..Default::default()
                },
            ),
            // 8. reality / enc=false / vision=true
            (
                "reality/enc=false/vision=true",
                LocalTLS {
                    protocol: "vless".to_string(),
                    transport_security: "tls".to_string(),
                    flow: FLOW_VISION.to_string(),
                    reality: reality_base.clone(),
                    ..Default::default()
                },
            ),
            // 9. tls / enc=true / vision=true
            (
                "tls/enc=true/vision=true",
                LocalTLS {
                    protocol: "vless".to_string(),
                    transport_security: "tls".to_string(),
                    cert_pem: cert_pem.clone(),
                    key_pem: key_pem.clone(),
                    ca_pem: ca_pem.clone(),
                    decryption: pq_dec.clone(),
                    flow: FLOW_VISION.to_string(),
                    ..Default::default()
                },
            ),
            // 10. reality / enc=true / vision=true
            (
                "reality/enc=true/vision=true",
                LocalTLS {
                    protocol: "vless".to_string(),
                    transport_security: "tls".to_string(),
                    decryption: pq_dec.clone(),
                    flow: FLOW_VISION.to_string(),
                    reality: reality_base.clone(),
                    ..Default::default()
                },
            ),
            // 11. xhttp-https / enc=false / vision=false (packet-up)
            (
                "xhttp-https/enc=false/packet-up",
                LocalTLS {
                    protocol: "vless".to_string(),
                    transport_security: "tls".to_string(),
                    cert_pem: cert_pem.clone(),
                    key_pem: key_pem.clone(),
                    ca_pem: ca_pem.clone(),
                    xhttp: XHTTP {
                        path: "/veilink/".to_string(),
                        mode: "packet-up".to_string(),
                        tls: true,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            ),
            // 12. xhttp-https / enc=true / vision=false (packet-up)
            (
                "xhttp-https/enc=true/packet-up",
                LocalTLS {
                    protocol: "vless".to_string(),
                    transport_security: "tls".to_string(),
                    cert_pem: cert_pem.clone(),
                    key_pem: key_pem.clone(),
                    ca_pem: ca_pem.clone(),
                    decryption: pq_dec.clone(),
                    xhttp: XHTTP {
                        path: "/veilink/".to_string(),
                        mode: "packet-up".to_string(),
                        tls: true,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            ),
            // 13. xhttp-http / enc=true / vision=false (packet-up)
            (
                "xhttp-http/enc=true/packet-up",
                LocalTLS {
                    protocol: "vless".to_string(),
                    transport_security: "plain".to_string(),
                    decryption: pq_dec.clone(),
                    xhttp: XHTTP {
                        path: "/veilink/".to_string(),
                        mode: "packet-up".to_string(),
                        tls: false,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            ),
            // 14. xhttp-reality / enc=false / vision=false (packet-up)
            (
                "xhttp-reality/enc=false/packet-up",
                LocalTLS {
                    protocol: "vless".to_string(),
                    transport_security: "tls".to_string(),
                    reality: reality_base.clone(),
                    xhttp: XHTTP {
                        path: "/veilink/".to_string(),
                        mode: "packet-up".to_string(),
                        tls: false,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            ),
            // 15. xhttp-reality / enc=true / vision=false (packet-up)
            (
                "xhttp-reality/enc=true/packet-up",
                LocalTLS {
                    protocol: "vless".to_string(),
                    transport_security: "tls".to_string(),
                    decryption: pq_dec.clone(),
                    reality: reality_base.clone(),
                    xhttp: XHTTP {
                        path: "/veilink/".to_string(),
                        mode: "packet-up".to_string(),
                        tls: false,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            ),
            // === Extended XHTTP modes (stream-one, stream-up, auto, dual-endpoint) & REALITY ML-DSA-65 ===
            (
                "xhttp-https-stream-one",
                LocalTLS {
                    protocol: "vless".to_string(),
                    transport_security: "tls".to_string(),
                    cert_pem: cert_pem.clone(),
                    key_pem: key_pem.clone(),
                    ca_pem: ca_pem.clone(),
                    xhttp: XHTTP {
                        path: "/veilink/".to_string(),
                        mode: "stream-one".to_string(),
                        tls: true,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            ),
            (
                "xhttp-https-stream-up",
                LocalTLS {
                    protocol: "vless".to_string(),
                    transport_security: "tls".to_string(),
                    cert_pem: cert_pem.clone(),
                    key_pem: key_pem.clone(),
                    ca_pem: ca_pem.clone(),
                    xhttp: XHTTP {
                        path: "/veilink/".to_string(),
                        mode: "stream-up".to_string(),
                        tls: true,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            ),
            (
                "xhttp-reality-stream-one",
                LocalTLS {
                    protocol: "vless".to_string(),
                    transport_security: "tls".to_string(),
                    reality: reality_base.clone(),
                    xhttp: XHTTP {
                        path: "/veilink/".to_string(),
                        mode: "stream-one".to_string(),
                        tls: false,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            ),
            (
                "xhttp-reality-stream-up",
                LocalTLS {
                    protocol: "vless".to_string(),
                    transport_security: "tls".to_string(),
                    reality: reality_base.clone(),
                    xhttp: XHTTP {
                        path: "/veilink/".to_string(),
                        mode: "stream-up".to_string(),
                        tls: false,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            ),
            (
                "xhttp-http-auto",
                LocalTLS {
                    protocol: "vless".to_string(),
                    transport_security: "plain".to_string(),
                    decryption: pq_dec.clone(),
                    xhttp: XHTTP {
                        path: "/veilink/".to_string(),
                        mode: "auto".to_string(),
                        tls: false,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            ),
            (
                "xhttp-https-auto",
                LocalTLS {
                    protocol: "vless".to_string(),
                    transport_security: "tls".to_string(),
                    cert_pem: cert_pem.clone(),
                    key_pem: key_pem.clone(),
                    ca_pem: ca_pem.clone(),
                    xhttp: XHTTP {
                        path: "/veilink/".to_string(),
                        mode: "auto".to_string(),
                        tls: true,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            ),
            (
                "xhttp-reality-auto",
                LocalTLS {
                    protocol: "vless".to_string(),
                    transport_security: "tls".to_string(),
                    reality: reality_base.clone(),
                    xhttp: XHTTP {
                        path: "/veilink/".to_string(),
                        mode: "auto".to_string(),
                        tls: false,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            ),
            (
                "xhttp-https-auto-download-ep",
                LocalTLS {
                    protocol: "vless".to_string(),
                    transport_security: "tls".to_string(),
                    cert_pem: cert_pem.clone(),
                    key_pem: key_pem.clone(),
                    ca_pem: ca_pem.clone(),
                    xhttp: XHTTP {
                        path: "/veilink/".to_string(),
                        mode: "auto".to_string(),
                        tls: true,
                        download_endpoint_id: "ep-1".to_string(),
                        ..Default::default()
                    },
                    ..Default::default()
                },
            ),
            (
                "vless-tcp-reality-mldsa65",
                LocalTLS {
                    protocol: "vless".to_string(),
                    transport_security: "tls".to_string(),
                    reality: reality_mldsa.clone(),
                    ..Default::default()
                },
            ),
            // === Explicit HTTP/2 (h2 + h2c prior-knowledge), RFC 9114 HTTP/3 (QUIC), & full PQ+MLDSA+Vision ===
            (
                "xhttp-h2c-prior-knowledge/enc=true/packet-up",
                LocalTLS {
                    protocol: "vless".to_string(),
                    transport_security: "plain".to_string(),
                    decryption: pq_dec.clone(),
                    xhttp: XHTTP {
                        path: "/veilink/".to_string(),
                        mode: "packet-up".to_string(),
                        tls: false,
                        http_version: "2".to_string(),
                        ..Default::default()
                    },
                    ..Default::default()
                },
            ),
            (
                "xhttp-https-h2/enc=false/packet-up",
                LocalTLS {
                    protocol: "vless".to_string(),
                    transport_security: "tls".to_string(),
                    cert_pem: cert_pem.clone(),
                    key_pem: key_pem.clone(),
                    ca_pem: ca_pem.clone(),
                    xhttp: XHTTP {
                        path: "/veilink/".to_string(),
                        mode: "packet-up".to_string(),
                        tls: true,
                        http_version: "2".to_string(),
                        ..Default::default()
                    },
                    ..Default::default()
                },
            ),
            (
                "xhttp-reality-h2/enc=true/packet-up",
                LocalTLS {
                    protocol: "vless".to_string(),
                    transport_security: "tls".to_string(),
                    decryption: pq_dec.clone(),
                    reality: reality_base.clone(),
                    xhttp: XHTTP {
                        path: "/veilink/".to_string(),
                        mode: "packet-up".to_string(),
                        tls: false,
                        http_version: "2".to_string(),
                        ..Default::default()
                    },
                    ..Default::default()
                },
            ),
            (
                "xhttp-h3-quic/enc=false/packet-up",
                LocalTLS {
                    protocol: "vless".to_string(),
                    transport_security: "tls".to_string(),
                    cert_pem: cert_pem.clone(),
                    key_pem: key_pem.clone(),
                    ca_pem: ca_pem.clone(),
                    xhttp: XHTTP {
                        path: "/veilink/".to_string(),
                        mode: "packet-up".to_string(),
                        tls: true,
                        http_version: "3".to_string(),
                        ..Default::default()
                    },
                    ..Default::default()
                },
            ),
            (
                "xhttp-h3-quic/enc=false/stream-one",
                LocalTLS {
                    protocol: "vless".to_string(),
                    transport_security: "tls".to_string(),
                    cert_pem: cert_pem.clone(),
                    key_pem: key_pem.clone(),
                    ca_pem: ca_pem.clone(),
                    xhttp: XHTTP {
                        path: "/veilink/".to_string(),
                        mode: "stream-one".to_string(),
                        tls: true,
                        http_version: "3".to_string(),
                        ..Default::default()
                    },
                    ..Default::default()
                },
            ),
            (
                "xhttp-h3-quic/enc=true/stream-up",
                LocalTLS {
                    protocol: "vless".to_string(),
                    transport_security: "tls".to_string(),
                    cert_pem: cert_pem.clone(),
                    key_pem: key_pem.clone(),
                    ca_pem: ca_pem.clone(),
                    decryption: pq_dec.clone(),
                    xhttp: XHTTP {
                        path: "/veilink/".to_string(),
                        mode: "stream-up".to_string(),
                        tls: true,
                        http_version: "3".to_string(),
                        ..Default::default()
                    },
                    ..Default::default()
                },
            ),
            (
                "vless-reality-mldsa65/enc=true/vision=true",
                LocalTLS {
                    protocol: "vless".to_string(),
                    transport_security: "tls".to_string(),
                    decryption: pq_dec.clone(),
                    flow: FLOW_VISION.to_string(),
                    reality: reality_mldsa,
                    ..Default::default()
                },
            ),
        ];

        let mapping_specs = all_mapping_specs();
        for (tname, tcfg) in &transports {
            for mspec in &mapping_specs {
                run_matrix_case(tname, tcfg.clone(), mspec).await;
            }
        }
    }

    #[tokio::test]
    async fn security_hardening_hy2_ca_and_xhttp_limits() {
        // 1. Hysteria2 client without CA must reject self-signed server certificate
        let (_ca_pem, cert_pem, key_pem) = generate_test_cert("localhost");
        let srv_tls = LocalTLS {
            protocol: "hysteria2".into(),
            transport_security: "tls".into(),
            cert_pem,
            key_pem,
            hysteria2: Hysteria2 {
                password: "secret".into(),
            },
            ..Default::default()
        };
        let srv_cfg = hysteria2::build_quic_server_config(&srv_tls).unwrap();
        let std_udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        std_udp.set_nonblocking(true).unwrap();
        let srv_addr = std_udp.local_addr().unwrap();
        let srv_ep = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(srv_cfg),
            std_udp,
            Arc::new(quinn::TokioRuntime),
        )
        .unwrap();
        let srv_task = tokio::spawn(async move {
            if let Some(inc) = srv_ep.accept().await {
                let _ = inc.await;
            }
        });

        // Client with empty ca_pem uses system roots -> must reject untrusted self-signed cert
        let cli_no_ca = LocalTLS {
            protocol: "hysteria2".into(),
            transport_security: "tls".into(),
            hysteria2: Hysteria2 {
                password: "secret".into(),
            },
            ..Default::default()
        };
        let binding = Binding {
            id: "b1".into(),
            server_id: "s1".into(),
            client_id: "c1".into(),
            connect_endpoint_id: String::new(),
            domain: "localhost".into(),
            uuid: "8a5eb68f-5317-4e1a-a673-1284e763fb62".into(),
        };
        let res = hysteria2::hy2_connect(srv_addr, &cli_no_ca, &binding, "localhost").await;
        assert!(
            res.is_err(),
            "Hysteria2 client without CA must reject self-signed server cert"
        );
        srv_task.abort();

        // Invalid non-empty ca_pem with no certificates must return Err
        let bad_ca = LocalTLS {
            ca_pem: "not-a-pem".into(),
            ..Default::default()
        };
        assert!(hysteria2::build_quic_client_config(&bad_ca).is_err());

        // 2. XHTTP SID validation and session cap
        assert!(xhttp::is_valid_xhttp_sid("abc-123_DEF"));
        assert!(!xhttp::is_valid_xhttp_sid(""));
        assert!(!xhttp::is_valid_xhttp_sid("../etc/passwd"));
        assert!(!xhttp::is_valid_xhttp_sid(&"a".repeat(129)));

        // 3. Legacy 4032-byte ML-DSA-65 private key validation requires mldsa65_verify
        let (_, x_pub) = generate_x25519().unwrap();
        let (x_priv, _) = generate_x25519().unwrap();
        let _ = x_pub;
        let (mldsa_seed, mldsa_verify) = generate_mldsa65().unwrap();
        let parsed = model::parse_mldsa65_private(&mldsa_seed).unwrap();
        let legacy_sk_b64 = URL_SAFE_NO_PAD.encode(&parsed.sk_bytes);
        let r_missing_verify = Reality {
            dest: "example.com:443".into(),
            private_key: x_priv.clone(),
            short_id: "01020304".into(),
            mldsa65_seed: legacy_sk_b64.clone(),
            mldsa65_verify: String::new(),
            ..Default::default()
        };
        assert!(check_reality_server(&r_missing_verify, "example.com").is_err());
        let r_with_verify = Reality {
            mldsa65_verify: mldsa_verify,
            ..r_missing_verify
        };
        assert!(check_reality_server(&r_with_verify, "example.com").is_ok());
    }

    #[test]
    fn session_handle_open_stream_skips_zero_and_existing_ids_on_wraparound() {
        let (ctrl_tx, _ctrl_rx) = mpsc::channel(8);
        let (data_tx, _data_rx) = mpsc::channel(8);
        let (handle, _kill_rx) =
            SessionHandle::new(ctrl_tx, data_tx, Arc::new(Mutex::new(HashMap::new())));
        let (id1, _rx1) = handle.open_stream().unwrap();
        assert_eq!(id1, 1);
        assert_eq!(handle.active_streams.load(Ordering::Relaxed), 1);
        // Simulate counter wrap-around back to u32::MAX -> 0 -> 1 (already active) -> 2
        handle.next_id.store(u32::MAX, Ordering::Relaxed);
        let (id_max, _rx_max) = handle.open_stream().unwrap();
        assert_eq!(id_max, u32::MAX);
        let (id_next, _rx_next) = handle.open_stream().unwrap();
        assert_eq!(id_next, 2);
        assert_eq!(handle.active_streams.load(Ordering::Relaxed), 3);
        assert!(handle.streams.lock().unwrap().contains_key(&1));
        handle.close_stream(id1);
        assert_eq!(handle.active_streams.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn pick_session_prefers_fresh_and_least_loaded_session() {
        let _ = mono_now_ms();
        let (c_stale, _crx_stale) = mpsc::channel(SESSION_CTRL_CHAN_CAP);
        let (d_stale, _drx_stale) = mpsc::channel(SESSION_DATA_CHAN_CAP);
        let (stale, _k_stale) =
            SessionHandle::new(c_stale, d_stale, Arc::new(Mutex::new(HashMap::new())));
        // Simulate a zombie session whose last RX was 30s ago (> SESSION_FRESH_RX_MS)
        let now = mono_now_ms();
        stale
            .last_rx_ms
            .store(now.saturating_sub(30_000), Ordering::Relaxed);

        let (c_busy, _crx_busy) = mpsc::channel(SESSION_CTRL_CHAN_CAP);
        let (d_busy, _drx_busy) = mpsc::channel(SESSION_DATA_CHAN_CAP);
        let (busy, _k_busy) =
            SessionHandle::new(c_busy, d_busy, Arc::new(Mutex::new(HashMap::new())));
        busy.touch_rx();
        let (_sid1, _srx1) = busy.open_stream().unwrap();
        let (_sid2, _srx2) = busy.open_stream().unwrap();

        let (c_idle, _crx_idle) = mpsc::channel(SESSION_CTRL_CHAN_CAP);
        let (d_idle, _drx_idle) = mpsc::channel(SESSION_DATA_CHAN_CAP);
        let (idle, _k_idle) =
            SessionHandle::new(c_idle, d_idle, Arc::new(Mutex::new(HashMap::new())));
        idle.touch_rx();

        let sessions: SessionMap = Arc::new(Mutex::new(HashMap::new()));
        sessions.lock().unwrap().insert(
            "b1".to_string(),
            vec![stale.clone(), busy.clone(), idle.clone()],
        );

        for _ in 0..6 {
            let picked = pick_session(&sessions, "b1").unwrap();
            assert!(
                Arc::ptr_eq(&picked.streams, &idle.streams),
                "pick_session must skip stale session and prefer idle fresh session over busy session"
            );
        }
    }

    #[test]
    fn reality_client_cfg_always_advertises_alpn_and_180s_default_window() {
        let (priv_k, pub_k) = generate_x25519().unwrap();
        let local = LocalTLS {
            protocol: "vless".to_string(),
            reality: Reality {
                dest: "www.cloudflare.com:443".to_string(),
                private_key: priv_k,
                public_key: pub_k,
                short_id: "01020304".to_string(),
                server_names: "www.cloudflare.com".to_string(),
                max_time_diff: String::new(),
                ..Default::default()
            },
            ..Default::default()
        };
        let cli_cfg = build_reality_client_cfg(&local, "www.cloudflare.com", "tun.local").unwrap();
        assert_eq!(
            cli_cfg.alpn,
            vec!["h2".to_string(), "http/1.1".to_string()],
            "non-XHTTP REALITY ClientHello must advertise browser ALPN"
        );
        let srv_cfg = build_reality_server_cfg(&local).unwrap();
        assert_eq!(srv_cfg.max_time_diff_ms, 180_000);

        let mut local_zero = local.clone();
        local_zero.reality.max_time_diff = "0".to_string();
        let srv_zero = build_reality_server_cfg(&local_zero).unwrap();
        assert_eq!(srv_zero.max_time_diff_ms, 0);
    }

    #[tokio::test]
    async fn session_writer_prioritizes_control_ahead_of_data_and_skips_oversized() {
        let (ctrl_tx, ctrl_rx) = mpsc::channel(SESSION_CTRL_CHAN_CAP);
        let (data_tx, data_rx) = mpsc::channel(SESSION_DATA_CHAN_CAP);
        let (client_io, mut server_io) = tokio::io::duplex(512 * 1024);
        let last_rx_ms = Arc::new(AtomicU64::new(mono_now_ms()));
        let (_stop_tx, stop_rx) = watch::channel(false);
        let (done_tx, _done_rx) = watch::channel(false);

        // Pre-fill data_tx with multiple data frames, an oversized data frame, and a trailing FRAME_HALF
        for idx in 0..8u32 {
            data_tx
                .try_send((FRAME_DATA, 1, vec![idx as u8; 8192]))
                .unwrap();
        }
        data_tx
            .try_send((FRAME_DATA, 99, vec![0xffu8; MAX_PAYLOAD + 100]))
            .unwrap();
        data_tx
            .try_send((FRAME_HALF, 1, Vec::new()))
            .unwrap();

        // Enqueue control frames while data_tx already has 8 frames waiting
        ctrl_tx.try_send((FRAME_PONG, 0, Vec::new())).unwrap();
        ctrl_tx.try_send((FRAME_OPEN, 2, b"\x00\x50127.0.0.1".to_vec())).unwrap();

        let writer = spawn_session_writer(
            Box::new(client_io),
            ctrl_rx,
            data_rx,
            last_rx_ms,
            stop_rx,
            None,
            done_tx,
        );
        drop(ctrl_tx);
        drop(data_tx);

        let mut kinds = Vec::new();
        while let Ok(f) = read_frame(&mut server_io).await {
            kinds.push((f.0, f.1));
        }
        writer.await.unwrap();

        // Control frames must come out ahead of all queued data frames
        assert_eq!(kinds[0], (FRAME_PONG, 0));
        assert_eq!(kinds[1], (FRAME_OPEN, 2));
        // Oversized stream 99 frame must be skipped without killing the session, and FRAME_HALF must be last
        assert!(!kinds.iter().any(|&(_, id)| id == 99));
        assert_eq!(kinds.len(), 2 + 8 + 1);
        assert_eq!(*kinds.last().unwrap(), (FRAME_HALF, 1));
    }

    #[tokio::test]
    async fn demux_multi_stream_isolates_stalled_consumer_and_emits_reset() {
        let (ctrl_tx, mut ctrl_rx) = mpsc::channel(SESSION_CTRL_CHAN_CAP);
        let (data_tx, _data_rx) = mpsc::channel(SESSION_DATA_CHAN_CAP);
        let sender = SessionSender::new(ctrl_tx, data_tx);
        let streams_map: Mutex<HashMap<u32, mpsc::Sender<(u8, Vec<u8>)>>> =
            Mutex::new(HashMap::new());
        let active = AtomicUsize::new(2);

        let (stalled_tx, _stalled_rx) = mpsc::channel(1);
        stalled_tx.try_send((FRAME_DATA, vec![1u8; 16])).unwrap(); // now full!
        let (healthy_tx, mut healthy_rx) = mpsc::channel(8);
        {
            let mut m = streams_map.lock().unwrap();
            m.insert(10, stalled_tx);
            m.insert(20, healthy_tx);
        }

        let t0 = std::time::Instant::now();
        demux_stream_frame(
            FRAME_DATA,
            10,
            vec![2u8; 16],
            &streams_map,
            Some(&active),
            &sender,
        )
        .await;
        let elapsed = t0.elapsed();
        assert!(
            elapsed < Duration::from_millis(1200),
            "multi-stream demux should cap stalled stream wait around 500ms, got {:?}",
            elapsed
        );
        assert!(!streams_map.lock().unwrap().contains_key(&10));
        assert_eq!(active.load(Ordering::Relaxed), 1);

        let reset_msg = ctrl_rx.try_recv().expect("FRAME_RESET must be queued on ctrl_tx");
        assert_eq!(reset_msg.0, FRAME_RESET);
        assert_eq!(reset_msg.1, 10);

        demux_stream_frame(
            FRAME_DATA,
            20,
            b"ok".to_vec(),
            &streams_map,
            Some(&active),
            &sender,
        )
        .await;
        assert_eq!(healthy_rx.recv().await.unwrap(), (FRAME_DATA, b"ok".to_vec()));
    }

    #[test]
    fn pick_session_skips_suspect_unanswered_ping_and_syncs_linked_atomically() {
        let _ = mono_now_ms();
        let (c1, _cr1) = mpsc::channel(SESSION_CTRL_CHAN_CAP);
        let (d1, _dr1) = mpsc::channel(SESSION_DATA_CHAN_CAP);
        let (zombie, _k1) = SessionHandle::new(c1, d1, Arc::new(Mutex::new(HashMap::new())));
        zombie.touch_rx();
        // Simulate session with recent last_rx_ms (< 18s) but an unanswered ping sent 2s ago (> 1.5s)
        zombie.unanswered_pings.store(1, Ordering::Relaxed);
        zombie
            .ping_sent_ms
            .store(mono_now_ms().saturating_sub(2_000), Ordering::Relaxed);

        let (c2, _cr2) = mpsc::channel(SESSION_CTRL_CHAN_CAP);
        let (d2, _dr2) = mpsc::channel(SESSION_DATA_CHAN_CAP);
        let (healthy, _k2) = SessionHandle::new(c2, d2, Arc::new(Mutex::new(HashMap::new())));
        healthy.touch_rx();

        let sessions: SessionMap = Arc::new(Mutex::new(HashMap::new()));
        let linked = Mutex::new(HashSet::from(["b-sync".to_string()]));
        sessions
            .lock()
            .unwrap()
            .insert("b-sync".to_string(), vec![zombie.clone(), healthy.clone()]);

        for _ in 0..8 {
            let picked = pick_session(&sessions, "b-sync").unwrap();
            assert!(
                Arc::ptr_eq(&picked.streams, &healthy.streams),
                "pick_session must bypass session with overdue unanswered ping"
            );
        }

        // Removing `zombie` while `healthy` remains must keep `linked` intact
        let (was_last, unlinked) =
            remove_session_sync_linked(&sessions, Some(&linked), "b-sync", &zombie);
        assert!(!was_last);
        assert!(!unlinked);
        assert!(linked.lock().unwrap().contains("b-sync"));

        // Removing `healthy` removes the last session and atomically clears `linked`
        let (was_last2, unlinked2) =
            remove_session_sync_linked(&sessions, Some(&linked), "b-sync", &healthy);
        assert!(was_last2);
        assert!(unlinked2);
        assert!(!linked.lock().unwrap().contains("b-sync"));
    }

    #[tokio::test]
    async fn vless_reality_vision_encryption_0rtt_auto_recovers_after_server_restart() {
        let (priv_k, pub_k) = generate_x25519().unwrap();
        let (_, _, dec_raw, enc_raw) = generate_vless_enc().unwrap();

        let uuid_str = "550e8400-e29b-41d4-a716-446655440099".to_string();
        let uuid_bytes = parse_uuid(&uuid_str).unwrap();
        let binding = Binding {
            id: "bind-0rtt".to_string(),
            server_id: "srv-1".to_string(),
            client_id: "cli-1".to_string(),
            uuid: uuid_str,
            domain: "tun.internal".to_string(),
            ..Default::default()
        };
        let srv_local = LocalTLS {
            protocol: "vless".to_string(),
            flow: FLOW_VISION.to_string(),
            decryption: dec_raw.clone(),
            reality: Reality {
                dest: "127.0.0.1:9".to_string(),
                private_key: priv_k,
                short_id: "0102030405060708".to_string(),
                server_names: "www.cloudflare.com".to_string(),
                ..Default::default()
            },
            ..Default::default()
        };
        let cli_local = LocalTLS {
            protocol: "vless".to_string(),
            flow: FLOW_VISION.to_string(),
            encryption: enc_raw,
            reality: Reality {
                public_key: pub_k,
                short_id: "0102030405060708".to_string(),
                server_names: "www.cloudflare.com".to_string(),
                fingerprint: "chrome".to_string(),
                ..Default::default()
            },
            ..Default::default()
        };

        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = ln.local_addr().unwrap();
        let active_dec: Arc<Mutex<Arc<vless_enc::ServerInstance>>> = Arc::new(Mutex::new(
            vless_enc::ServerInstance::from_raw(&dec_raw).unwrap().unwrap(),
        ));
        let active_dec_srv = active_dec.clone();
        let rcfg = build_reality_server_cfg(&srv_local).unwrap();
        let srv_local_c = srv_local.clone();
        let binding_srv = binding.clone();

        let accept_loop = tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = ln.accept().await else { break };
                let rcfg_c = rcfg.clone();
                let dec_c = active_dec_srv.lock().unwrap().clone();
                let local_c = srv_local_c.clone();
                let b_c = binding_srv.clone();
                tokio::spawn(async move {
                    let Some(mut s) = accept_outer_vision_inner(tcp, &local_c, None, Some(rcfg_c))
                        .await
                        .map(|v| v.into_box_stream())
                    else {
                        return;
                    };
                    s = match dec_c.handshake(s).await {
                        Ok(s) => s,
                        Err(_) => return,
                    };
                    let Ok((u, dom, _, fl)) = read_vless_with_flow(&mut s).await else {
                        return;
                    };
                    if u != parse_uuid(&b_c.uuid).unwrap()
                        || !dom.eq_ignore_ascii_case(&b_c.domain)
                        || fl != FLOW_VISION
                    {
                        return;
                    }
                    if s.write_all(&[0, 0]).await.is_err() || s.flush().await.is_err() {
                        return;
                    }
                    let mut vs = vision::wrap_vision_stream(s, u, false);
                    let Ok((kind, id, payload)) = read_frame(&mut vs).await else {
                        return;
                    };
                    let _ = write_frame(&mut vs, kind, id, &payload).await;
                    let _ = vs.flush().await;
                    let _ = vs.shutdown().await;
                });
            }
        });

        let enc_cli = vless_enc::ClientInstance::from_raw(&cli_local.encryption)
            .unwrap()
            .unwrap();
        let eps = vec![ConnectEndpoint {
            id: "ep1".to_string(),
            host: "127.0.0.1".to_string(),
            port: listen_addr.port() as i64,
            enabled: true,
            ..Default::default()
        }];

        // 1. Initial 1-RTT connection populates client 0-RTT ticket
        {
            let mut cs = dial_client_session_addr(
                listen_addr,
                &eps,
                &cli_local,
                &binding,
                uuid_bytes,
                "www.cloudflare.com",
                Some(enc_cli.clone()),
                mux_proto::PORT_CONTROL,
            )
            .await
            .expect("1-RTT dial should succeed");
            assert!(enc_cli.has_cached_ticket());
            write_frame(&mut cs, FRAME_DATA, 7, b"hello-1rtt")
                .await
                .unwrap();
            cs.flush().await.unwrap();
            let (k, id, data) = read_frame(&mut cs).await.unwrap();
            assert_eq!((k, id, data.as_slice()), (FRAME_DATA, 7, b"hello-1rtt".as_slice()));
        }

        // 2. Subsequent connection uses cached 0-RTT ticket
        {
            let mut cs = dial_client_session_addr(
                listen_addr,
                &eps,
                &cli_local,
                &binding,
                uuid_bytes,
                "www.cloudflare.com",
                Some(enc_cli.clone()),
                mux_proto::PORT_CONTROL,
            )
            .await
            .expect("0-RTT dial should succeed");
            write_frame(&mut cs, FRAME_DATA, 8, b"hello-0rtt")
                .await
                .unwrap();
            cs.flush().await.unwrap();
            let (k, id, data) = read_frame(&mut cs).await.unwrap();
            assert_eq!((k, id, data.as_slice()), (FRAME_DATA, 8, b"hello-0rtt".as_slice()));
        }

        // 3. Simulate server restart wiping server-side 0-RTT tickets; single dial must auto-fallback to 1-RTT
        *active_dec.lock().unwrap() = vless_enc::ServerInstance::from_raw(&dec_raw).unwrap().unwrap();
        assert!(enc_cli.has_cached_ticket());
        {
            let mut cs = dial_client_session_addr(
                listen_addr,
                &eps,
                &cli_local,
                &binding,
                uuid_bytes,
                "www.cloudflare.com",
                Some(enc_cli.clone()),
                mux_proto::PORT_CONTROL,
            )
            .await
            .expect("dial after server restart must transparently fallback from 0-RTT to 1-RTT");
            assert!(
                enc_cli.has_cached_ticket(),
                "1-RTT fallback must refresh cached 0-RTT ticket"
            );
            write_frame(&mut cs, FRAME_DATA, 9, b"recovered!")
                .await
                .unwrap();
            cs.flush().await.unwrap();
            let (k, id, data) = read_frame(&mut cs).await.unwrap();
            assert_eq!((k, id, data.as_slice()), (FRAME_DATA, 9, b"recovered!".as_slice()));
        }

        accept_loop.abort();
    }

    #[tokio::test]
    async fn vision_coalesces_initial_camouflage_flights_and_rejects_mismatched_uuid() {
        let uuid_ok = parse_uuid("550e8400-e29b-41d4-a716-4466554400aa").unwrap();
        let uuid_bad = parse_uuid("550e8400-e29b-41d4-a716-4466554400bb").unwrap();

        // 1. Client initial flight must coalesce VLESS header + Vision long padding (> 900B)
        let mut cli_flight = Vec::new();
        encode_vless_request_into(&mut cli_flight, uuid_ok, "tun.example.com", 0, FLOW_VISION)
            .unwrap();
        let bare_hdr_len = cli_flight.len();
        assert!(bare_hdr_len < 100);
        vision::append_initial_camouflage(&mut cli_flight, &uuid_ok);
        assert!(
            cli_flight.len() >= bare_hdr_len + 21 + 900,
            "Vision client flight must coalesce VLESS header with >=900B initial padding, got {}",
            cli_flight.len()
        );

        // 2. Server initial flight must coalesce [0, 0] + Vision long padding (> 900B)
        let mut srv_flight = vec![0x00, 0x00];
        vision::append_initial_camouflage(&mut srv_flight, &uuid_ok);
        assert!(
            srv_flight.len() >= 2 + 21 + 900,
            "Vision server flight must coalesce [0, 0] with >=900B initial padding, got {}",
            srv_flight.len()
        );

        // 3. VisionStream started after coalesced flight exchanges payload cleanly, and rejects wrong UUID
        let (c_raw, mut s_raw) = tokio::io::duplex(64 * 1024);
        let mut c_box: BoxStream = Box::new(c_raw);
        c_box.write_all(&cli_flight).await.unwrap();
        c_box.flush().await.unwrap();

        let (got_u, got_dom, _, got_fl) = read_vless_with_flow(&mut s_raw).await.unwrap();
        assert_eq!(got_u, uuid_ok);
        assert_eq!(got_dom, "tun.example.com");
        assert_eq!(got_fl, FLOW_VISION);

        let mut s_box: BoxStream = Box::new(s_raw);
        s_box.write_all(&srv_flight).await.unwrap();
        s_box.flush().await.unwrap();
        let mut srv_vs_bad = vision::wrap_vision_stream_started(s_box, uuid_bad);

        let mut resp2 = [0u8; 2];
        c_box.read_exact(&mut resp2).await.unwrap();
        assert_eq!(resp2, [0, 0]);
        let mut cli_vs = vision::wrap_vision_stream_started(c_box, uuid_ok);

        cli_vs.write_all(b"ping").await.unwrap();
        cli_vs.flush().await.unwrap();

        // First Vision frame arrived in cli_flight with uuid_ok while srv_vs_bad expects uuid_bad -> InvalidData
        let mut buf = [0u8; 16];
        let err = srv_vs_bad
            .read(&mut buf)
            .await
            .expect_err("VisionStream must reject frame carrying mismatched user UUID");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn reality_mldsa65_transcript_signature_rejects_mismatched_verify_key() {
        let (x_priv, x_pub) = generate_x25519().unwrap();
        let (seed_a, verify_a) = generate_mldsa65().unwrap();
        let (_seed_b, verify_b) = generate_mldsa65().unwrap();

        let srv_local = LocalTLS {
            protocol: "vless".to_string(),
            reality: Reality {
                dest: "127.0.0.1:9".to_string(),
                private_key: x_priv,
                short_id: "01020304".to_string(),
                server_names: "www.cloudflare.com".to_string(),
                mldsa65_seed: seed_a,
                ..Default::default()
            },
            ..Default::default()
        };
        let srv_cfg = build_reality_server_cfg(&srv_local).unwrap();
        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap();
        let srv_task = tokio::spawn(async move {
            while let Ok((tcp, _)) = ln.accept().await {
                let c = srv_cfg.clone();
                tokio::spawn(async move {
                    if let Ok(Some(mut s)) = reality::reality_accept(tcp, &c).await {
                        let _ = s.write_all(b"ok").await;
                        let _ = s.flush().await;
                    }
                });
            }
        });

        // Matching mldsa65_verify succeeds
        let mut cli_ok = LocalTLS {
            protocol: "vless".to_string(),
            reality: Reality {
                public_key: x_pub.clone(),
                short_id: "01020304".to_string(),
                server_names: "www.cloudflare.com".to_string(),
                mldsa65_verify: verify_a,
                ..Default::default()
            },
            ..Default::default()
        };
        let cfg_ok = build_reality_client_cfg(&cli_ok, "www.cloudflare.com", "tun.local").unwrap();
        let tcp1 = TcpStream::connect(addr).await.unwrap();
        let mut s1 = reality::reality_connect(tcp1, &cfg_ok)
            .await
            .expect("matching ML-DSA-65 transcript signature must succeed");
        let mut two = [0u8; 2];
        s1.read_exact(&mut two).await.unwrap();
        assert_eq!(&two, b"ok");

        // Mismatched mldsa65_verify must fail verification
        cli_ok.reality.mldsa65_verify = verify_b;
        let cfg_bad = build_reality_client_cfg(&cli_ok, "www.cloudflare.com", "tun.local").unwrap();
        let tcp2 = TcpStream::connect(addr).await.unwrap();
        assert!(
            reality::reality_connect(tcp2, &cfg_bad).await.is_err(),
            "mismatched ML-DSA-65 verify key must fail REALITY Certificate verification"
        );

        srv_task.abort();
    }

    #[tokio::test]
    async fn xhttp_put_method_host_headers_cors_and_post_slicing_round_trip() {
        let gw_domain = "edge.matrix.example.com";
        let custom_host = "cdn.front.example.net";
        let (ca_pem, cert_pem, key_pem) = generate_test_cert(gw_domain);
        let hdrs = model::XHTTPHeaders::parse_raw(br#"{"X-Custom-Route":"alpha-9"}"#).unwrap();

        let mut srv_local = LocalTLS {
            protocol: "vless".to_string(),
            transport_security: "tls".to_string(),
            cert_pem,
            key_pem,
            ca_pem: ca_pem.clone(),
            xhttp: XHTTP {
                path: "/veilink/".to_string(),
                mode: "packet-up".to_string(),
                tls: true,
                http_version: "1.1".to_string(),
                host: custom_host.to_string(),
                headers: hdrs,
                uplink_http_method: "PUT".to_string(),
                max_each_post_bytes: 2048,
                post_bytes_max: 4096,
                min_posts_interval_ms: 1,
                max_posts_interval_ms: 3,
                ..Default::default()
            },
            ..Default::default()
        };

        // Run full end-to-end TCP round-trip while TLS cert SAN is gw_domain != xhttp.host
        let mspec = MatrixMappingSpec {
            name: "smux",
            network: "tcp",
            mux: true,
            mux_type: "smux",
        };
        let transport_port = reserve_free_tcp_port();
        srv_local.listen_host = "127.0.0.1".to_string();
        srv_local.listen_port = transport_port;

        // Also spin up a standalone XHTTP server listener to probe Host/Header 404 & OPTIONS CORS preflight
        let probe_ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let probe_addr = probe_ln.local_addr().unwrap();
        let probe_local = srv_local.clone();
        let probe_tls =
            tokio_rustls::TlsAcceptor::from(build_tls_server_config(&probe_local).unwrap());
        let probe_state = xhttp::XhttpServerState::new();
        let probe_task = tokio::spawn(async move {
            while let Ok((tcp, _)) = probe_ln.accept().await {
                let acc = probe_tls.clone();
                let lc = probe_local.clone();
                let st = probe_state.clone();
                tokio::spawn(async move {
                    if let Ok(tls_s) = acc.accept(tcp).await {
                        xhttp::handle_xhttp_server_conn(Box::new(tls_s), lc, st, |_| {}).await;
                    }
                });
            }
        });

        let cli_tls = tokio_rustls::TlsConnector::from(
            build_tls_client_config_with_sni(
                &LocalTLS {
                    ca_pem,
                    xhttp: XHTTP {
                        path: "/veilink/".to_string(),
                        mode: "packet-up".to_string(),
                        tls: true,
                        http_version: "1.1".to_string(),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                true,
            )
            .unwrap(),
        );

        // 1. Mismatched Host header -> 404
        {
            let tcp = TcpStream::connect(probe_addr).await.unwrap();
            let sni = ServerName::try_from(gw_domain.to_string()).unwrap();
            let mut tls = cli_tls.connect(sni, tcp).await.unwrap();
            tls.write_all(
                b"PUT /veilink/sid1/0 HTTP/1.1\r\nHost: wrong.example.net\r\nX-Custom-Route: alpha-9\r\nContent-Length: 0\r\n\r\n",
            )
            .await
            .unwrap();
            let mut rbuf = [0u8; 256];
            let n = tls.read(&mut rbuf).await.unwrap();
            let head = String::from_utf8_lossy(&rbuf[..n]);
            assert!(head.starts_with("HTTP/1.1 404"), "got: {}", head);
        }

        // 2. Valid Host + custom header + OPTIONS CORS preflight -> 200 with Access-Control-Allow-Methods: PUT
        {
            let tcp = TcpStream::connect(probe_addr).await.unwrap();
            let sni = ServerName::try_from(gw_domain.to_string()).unwrap();
            let mut tls = cli_tls.connect(sni, tcp).await.unwrap();
            let req = format!(
                "OPTIONS /veilink/ HTTP/1.1\r\nHost: {}\r\nX-Custom-Route: alpha-9\r\nOrigin: https://app.example.com\r\nAccess-Control-Request-Method: PUT\r\n\r\n",
                custom_host
            );
            tls.write_all(req.as_bytes()).await.unwrap();
            let mut rbuf = [0u8; 512];
            let n = tls.read(&mut rbuf).await.unwrap();
            let head = String::from_utf8_lossy(&rbuf[..n]);
            assert!(head.starts_with("HTTP/1.1 200"), "got: {}", head);
            assert!(
                head.to_ascii_lowercase()
                    .contains("access-control-allow-methods: put"),
                "got: {}",
                head
            );
        }
        probe_task.abort();

        // 3. Full Runtime round-trip with gw_addr = gw_domain (TLS SAN) while xhttp.host = custom_host
        let echo_ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_port = echo_ln.local_addr().unwrap().port() as i64;
        let echo_guard = tokio::spawn(async move {
            while let Ok((mut s, _)) = echo_ln.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                    let _ = w.shutdown().await;
                });
            }
        });
        let listen_port = reserve_free_tcp_port();
        let srv_node = Node {
            id: "srv-put".to_string(),
            name: "srv-put".to_string(),
            role: "server".to_string(),
            address: gw_domain.to_string(),
            port: transport_port,
            connect_endpoints: vec![ConnectEndpoint {
                id: "ep-1".to_string(),
                name: "primary".to_string(),
                host: "127.0.0.1".to_string(),
                port: transport_port,
                enabled: true,
            }],
            tunnel: srv_local.clone(),
            ..Default::default()
        };
        let mut srv_for_cli = srv_node.clone();
        srv_for_cli.tunnel =
            derive_client_tunnel(&LocalTLS::default(), &srv_local, &srv_node).unwrap();
        let binding = Binding {
            id: "bind-put".to_string(),
            server_id: "srv-put".to_string(),
            client_id: "cli-put".to_string(),
            uuid: "550e8400-e29b-41d4-a716-4466554400cc".to_string(),
            domain: gw_domain.to_string(),
            ..Default::default()
        };
        let mapping = Mapping {
            id: "map-put".to_string(),
            name: "put-smux".to_string(),
            binding_id: "bind-put".to_string(),
            server_id: "srv-put".to_string(),
            client_id: "cli-put".to_string(),
            listen_host: "127.0.0.1".to_string(),
            listen_port,
            target_host: "127.0.0.1".to_string(),
            target_port,
            network: mspec.network.to_string(),
            pool: 1,
            mux: mspec.mux,
            mux_type: mspec.mux_type.to_string(),
            enabled: true,
            ..Default::default()
        };

        let srv_rt = Runtime::new(srv_local);
        srv_rt
            .apply(Snapshot {
                revision: 1,
                node: srv_node,
                nodes: vec![],
                bindings: vec![binding.clone()],
                mappings: vec![mapping.clone()],
            })
            .unwrap();
        let cli_rt = Runtime::new(LocalTLS::default());
        cli_rt
            .apply(Snapshot {
                revision: 1,
                node: Node {
                    id: "cli-put".to_string(),
                    role: "client".to_string(),
                    ..Default::default()
                },
                nodes: vec![srv_for_cli],
                bindings: vec![binding],
                mappings: vec![mapping],
            })
            .unwrap();

        for _ in 0..80 {
            if srv_rt.linked_bindings().contains(&"bind-put".to_string())
                && cli_rt.linked_bindings().contains(&"bind-put".to_string())
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let mut conn = TcpStream::connect(format!("127.0.0.1:{}", listen_port))
            .await
            .unwrap();
        let payload = vec![0x5au8; 24 * 1024]; // spans multiple 2048..4096B PUT slices
        conn.write_all(&payload).await.unwrap();
        conn.shutdown().await.unwrap();
        let mut echoed = Vec::new();
        conn.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(echoed, payload);

        let _ = cli_rt.close();
        let _ = srv_rt.close();
        echo_guard.abort();
    }

    #[tokio::test]
    async fn udp_burst_preserves_client_nat_port_without_recreating_stream() {
        let domain = "edge.matrix.example.com";
        let (ca_pem, cert_pem, key_pem) = generate_test_cert(domain);
        let transport_port = reserve_free_tcp_port();
        let listen_port = reserve_free_udp_port();

        let target_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_port = target_sock.local_addr().unwrap().port() as i64;
        let seen_ports: Arc<Mutex<HashSet<u16>>> = Arc::new(Mutex::new(HashSet::new()));
        let seen_c = seen_ports.clone();
        let echo_task = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((n, peer)) = target_sock.recv_from(&mut buf).await {
                seen_c.lock().unwrap().insert(peer.port());
                let _ = target_sock.send_to(&buf[..n], peer).await;
            }
        });

        let srv_local = LocalTLS {
            protocol: "vless".to_string(),
            transport_security: "tls".to_string(),
            listen_host: "127.0.0.1".to_string(),
            listen_port: transport_port,
            cert_pem,
            key_pem,
            ca_pem,
            ..Default::default()
        };
        let srv_node = Node {
            id: "srv-udp".to_string(),
            role: "server".to_string(),
            address: "127.0.0.1".to_string(),
            port: transport_port,
            connect_endpoints: vec![ConnectEndpoint {
                id: "ep-1".to_string(),
                host: "127.0.0.1".to_string(),
                port: transport_port,
                enabled: true,
                ..Default::default()
            }],
            tunnel: srv_local.clone(),
            ..Default::default()
        };
        let mut srv_for_cli = srv_node.clone();
        srv_for_cli.tunnel =
            derive_client_tunnel(&LocalTLS::default(), &srv_local, &srv_node).unwrap();
        let binding = Binding {
            id: "bind-udp".to_string(),
            server_id: "srv-udp".to_string(),
            client_id: "cli-udp".to_string(),
            uuid: "550e8400-e29b-41d4-a716-4466554400dd".to_string(),
            domain: domain.to_string(),
            ..Default::default()
        };
        let mapping = Mapping {
            id: "map-udp".to_string(),
            name: "udp-burst".to_string(),
            binding_id: "bind-udp".to_string(),
            server_id: "srv-udp".to_string(),
            client_id: "cli-udp".to_string(),
            listen_host: "127.0.0.1".to_string(),
            listen_port,
            target_host: "127.0.0.1".to_string(),
            target_port,
            network: "udp".to_string(),
            pool: 1,
            enabled: true,
            ..Default::default()
        };

        let srv_rt = Runtime::new(srv_local);
        srv_rt
            .apply(Snapshot {
                revision: 1,
                node: srv_node,
                nodes: vec![],
                bindings: vec![binding.clone()],
                mappings: vec![mapping.clone()],
            })
            .unwrap();
        let cli_rt = Runtime::new(LocalTLS::default());
        cli_rt
            .apply(Snapshot {
                revision: 1,
                node: Node {
                    id: "cli-udp".to_string(),
                    role: "client".to_string(),
                    ..Default::default()
                },
                nodes: vec![srv_for_cli],
                bindings: vec![binding],
                mappings: vec![mapping],
            })
            .unwrap();

        for _ in 0..80 {
            if srv_rt.linked_bindings().contains(&"bind-udp".to_string())
                && cli_rt.linked_bindings().contains(&"bind-udp".to_string())
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        let cli_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        cli_sock
            .connect(format!("127.0.0.1:{}", listen_port))
            .await
            .unwrap();

        // Fire 320 UDP datagrams back-to-back (> 256 channel depth) from the same UDP peer
        for seq in 0..320u32 {
            let _ = cli_sock.send(&seq.to_be_bytes()).await;
        }
        let mut rbuf = [0u8; 64];
        let mut got_any = 0usize;
        while let Ok(Ok(_)) =
            tokio::time::timeout(Duration::from_millis(300), cli_sock.recv(&mut rbuf)).await
        {
            got_any += 1;
        }
        assert!(got_any > 0, "expected UDP burst responses");
        assert_eq!(
            seen_ports.lock().unwrap().len(),
            1,
            "UDP burst from one peer must preserve a single client NAT source port"
        );

        let _ = cli_rt.close();
        let _ = srv_rt.close();
        echo_task.abort();
    }

    #[tokio::test]
    async fn hot_apply_isolates_unrelated_mappings_and_bindings_under_active_traffic() {
        let echo_ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_port = echo_ln.local_addr().unwrap().port() as i64;
        let echo_task = tokio::spawn(async move {
            while let Ok((mut s, _)) = echo_ln.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                    let _ = w.shutdown().await;
                });
            }
        });

        let (dec_cfg, _, _, _) = generate_vless_enc().unwrap();
        let tp1 = reserve_free_tcp_port();
        let tp2 = reserve_free_tcp_port();
        let m1_port = reserve_free_tcp_port();
        let m2_port = reserve_free_tcp_port();
        let m2_port_edited = reserve_free_tcp_port();
        let m3_port = reserve_free_tcp_port();

        let make_srv = |id: &str, tp: i64, dec: &str| -> (Node, LocalTLS) {
            let local = LocalTLS {
                protocol: "vless".to_string(),
                transport_security: "plain".to_string(),
                decryption: dec.to_string(),
                listen_host: "127.0.0.1".to_string(),
                listen_port: tp,
                ..Default::default()
            };
            let srv = Node {
                id: id.to_string(),
                name: id.to_string(),
                role: "server".to_string(),
                address: "127.0.0.1".to_string(),
                port: tp,
                connect_endpoints: vec![ConnectEndpoint {
                    id: "ep-1".to_string(),
                    name: "primary".to_string(),
                    host: "127.0.0.1".to_string(),
                    port: tp,
                    enabled: true,
                }],
                tunnel: local.clone(),
                ..Default::default()
            };
            (srv, local)
        };

        let (srv1, srv1_local) = make_srv("srv-1", tp1, &dec_cfg);
        let mut srv1_for_cli = srv1.clone();
        srv1_for_cli.tunnel = derive_client_tunnel(&LocalTLS::default(), &srv1_local, &srv1).unwrap();

        let (dec_cfg2, _, _, _) = generate_vless_enc().unwrap();
        let (srv2, srv2_local) = make_srv("srv-2", tp2, &dec_cfg2);
        let mut srv2_for_cli = srv2.clone();
        srv2_for_cli.tunnel = derive_client_tunnel(&LocalTLS::default(), &srv2_local, &srv2).unwrap();

        let cli = Node {
            id: "cli-1".to_string(),
            name: "cli-1".to_string(),
            role: "client".to_string(),
            ..Default::default()
        };
        let bind1 = Binding {
            id: "bind-1".to_string(),
            server_id: "srv-1".to_string(),
            client_id: "cli-1".to_string(),
            uuid: "550e8400-e29b-41d4-a716-446655440011".to_string(),
            domain: "b1.veilink.internal".to_string(),
            ..Default::default()
        };
        let bind2 = Binding {
            id: "bind-2".to_string(),
            server_id: "srv-2".to_string(),
            client_id: "cli-1".to_string(),
            uuid: "550e8400-e29b-41d4-a716-446655440022".to_string(),
            domain: "b2.veilink.internal".to_string(),
            ..Default::default()
        };
        let m1 = Mapping {
            id: "map-1".to_string(),
            name: "m1".to_string(),
            binding_id: "bind-1".to_string(),
            server_id: "srv-1".to_string(),
            client_id: "cli-1".to_string(),
            pool: 1,
            listen_host: "127.0.0.1".to_string(),
            listen_port: m1_port,
            target_host: "127.0.0.1".to_string(),
            target_port,
            network: "tcp".to_string(),
            enabled: true,
            ..Default::default()
        };

        let srv1_rt = Runtime::new(LocalTLS::default());
        let srv2_rt = Runtime::new(LocalTLS::default());
        let cli_rt = Runtime::new(LocalTLS::default());

        srv1_rt
            .apply(Snapshot {
                revision: 1,
                node: srv1.clone(),
                nodes: vec![srv1.clone()],
                bindings: vec![bind1.clone()],
                mappings: vec![m1.clone()],
            })
            .unwrap();
        cli_rt
            .apply(Snapshot {
                revision: 1,
                node: cli.clone(),
                nodes: vec![srv1_for_cli.clone()],
                bindings: vec![bind1.clone()],
                mappings: vec![m1.clone()],
            })
            .unwrap();

        for _ in 0..80 {
            if srv1_rt.linked_bindings().contains(&"bind-1".to_string())
                && cli_rt.linked_bindings().contains(&"bind-1".to_string())
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(srv1_rt.linked_bindings().contains(&"bind-1".to_string()));

        // Open a persistent TCP connection on Mapping 1 BEFORE adding/editing Mapping 2 & Server 2
        let mut persistent = TcpStream::connect(format!("127.0.0.1:{}", m1_port))
            .await
            .unwrap();
        persistent.write_all(b"phase-0").await.unwrap();
        let mut buf = [0u8; 7];
        persistent.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"phase-0");

        // 1. Add Mapping 2 (smux, pool=2) on the SAME (srv-1, cli-1) binding
        let m2 = Mapping {
            id: "map-2".to_string(),
            name: "m2".to_string(),
            binding_id: "bind-1".to_string(),
            server_id: "srv-1".to_string(),
            client_id: "cli-1".to_string(),
            pool: 2,
            mux: true,
            mux_type: "smux".to_string(),
            listen_host: "127.0.0.1".to_string(),
            listen_port: m2_port,
            target_host: "127.0.0.1".to_string(),
            target_port,
            network: "tcp".to_string(),
            enabled: true,
            ..Default::default()
        };
        srv1_rt
            .apply(Snapshot {
                revision: 2,
                node: srv1.clone(),
                nodes: vec![srv1.clone()],
                bindings: vec![bind1.clone()],
                mappings: vec![m1.clone(), m2.clone()],
            })
            .unwrap();
        cli_rt
            .apply(Snapshot {
                revision: 2,
                node: cli.clone(),
                nodes: vec![srv1_for_cli.clone()],
                bindings: vec![bind1.clone()],
                mappings: vec![m1.clone(), m2.clone()],
            })
            .unwrap();

        // bind-1 MUST remain linked immediately without a single drop, and persistent stream MUST stay alive!
        assert!(srv1_rt.linked_bindings().contains(&"bind-1".to_string()));
        assert!(cli_rt.linked_bindings().contains(&"bind-1".to_string()));
        persistent.write_all(b"phase-1").await.unwrap();
        persistent.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"phase-1");

        // Verify newly added Mapping 2 works immediately
        let mut s2 = TcpStream::connect(format!("127.0.0.1:{}", m2_port))
            .await
            .unwrap();
        s2.write_all(b"map2-ok").await.unwrap();
        s2.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"map2-ok");
        drop(s2);

        // 2. Edit Mapping 2 (change listen port + switch smux -> yamux)
        let mut m2_edited = m2.clone();
        m2_edited.listen_port = m2_port_edited;
        m2_edited.mux_type = "yamux".to_string();
        srv1_rt
            .apply(Snapshot {
                revision: 3,
                node: srv1.clone(),
                nodes: vec![srv1.clone()],
                bindings: vec![bind1.clone()],
                mappings: vec![m1.clone(), m2_edited.clone()],
            })
            .unwrap();
        cli_rt
            .apply(Snapshot {
                revision: 3,
                node: cli.clone(),
                nodes: vec![srv1_for_cli.clone()],
                bindings: vec![bind1.clone()],
                mappings: vec![m1.clone(), m2_edited.clone()],
            })
            .unwrap();

        assert!(srv1_rt.linked_bindings().contains(&"bind-1".to_string()));
        assert!(cli_rt.linked_bindings().contains(&"bind-1".to_string()));
        persistent.write_all(b"phase-2").await.unwrap();
        persistent.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"phase-2");

        let mut s2_new = TcpStream::connect(format!("127.0.0.1:{}", m2_port_edited))
            .await
            .unwrap();
        s2_new.write_all(b"yamuxok").await.unwrap();
        s2_new.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"yamuxok");
        drop(s2_new);

        // 3. Add a completely separate Server 2 + binding 2 on the same Client
        let m3 = Mapping {
            id: "map-3".to_string(),
            name: "m3".to_string(),
            binding_id: "bind-2".to_string(),
            server_id: "srv-2".to_string(),
            client_id: "cli-1".to_string(),
            pool: 1,
            listen_host: "127.0.0.1".to_string(),
            listen_port: m3_port,
            target_host: "127.0.0.1".to_string(),
            target_port,
            network: "tcp".to_string(),
            enabled: true,
            ..Default::default()
        };
        srv2_rt
            .apply(Snapshot {
                revision: 1,
                node: srv2.clone(),
                nodes: vec![srv2.clone()],
                bindings: vec![bind2.clone()],
                mappings: vec![m3.clone()],
            })
            .unwrap();
        cli_rt
            .apply(Snapshot {
                revision: 4,
                node: cli.clone(),
                nodes: vec![srv1_for_cli.clone(), srv2_for_cli.clone()],
                bindings: vec![bind1.clone(), bind2.clone()],
                mappings: vec![m1.clone(), m2_edited.clone(), m3.clone()],
            })
            .unwrap();

        // bind-1 stays uninterrupted while bind-2 connects
        assert!(cli_rt.linked_bindings().contains(&"bind-1".to_string()));
        persistent.write_all(b"phase-3").await.unwrap();
        persistent.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"phase-3");

        for _ in 0..80 {
            if srv2_rt.linked_bindings().contains(&"bind-2".to_string())
                && cli_rt.linked_bindings().contains(&"bind-2".to_string())
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(srv2_rt.linked_bindings().contains(&"bind-2".to_string()));
        let mut s3 = TcpStream::connect(format!("127.0.0.1:{}", m3_port))
            .await
            .unwrap();
        s3.write_all(b"srv2-ok").await.unwrap();
        s3.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"srv2-ok");

        drop(s3);
        drop(persistent);
        let _ = cli_rt.close();
        let _ = srv1_rt.close();
        let _ = srv2_rt.close();
        echo_task.abort();
    }

    #[tokio::test]
    async fn bandwidth_limit_enforces_upload_and_download_even_with_shared_target() {
        // Target server: reads 1 byte ('U' = upload sink, 'D' = download source) then transfers 512 KiB
        let target_ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_port = target_ln.local_addr().unwrap().port() as i64;
        const TRANSFER_BYTES: usize = 512 * 1024;
        let target_task = tokio::spawn(async move {
            while let Ok((mut s, _)) = target_ln.accept().await {
                tokio::spawn(async move {
                    let mut mode = [0u8; 1];
                    if s.read_exact(&mut mode).await.is_err() {
                        return;
                    }
                    if mode[0] == b'U' {
                        let mut rem = TRANSFER_BYTES;
                        let mut buf = vec![0u8; 32768];
                        while rem > 0 {
                            let Ok(n) = s.read(&mut buf).await else { return };
                            if n == 0 {
                                return;
                            }
                            rem = rem.saturating_sub(n);
                        }
                        let _ = s.write_all(b"OK").await;
                    } else if mode[0] == b'D' {
                        let chunk = vec![0x5Au8; 32768];
                        let mut rem = TRANSFER_BYTES;
                        while rem > 0 {
                            let n = rem.min(chunk.len());
                            if s.write_all(&chunk[..n]).await.is_err() {
                                return;
                            }
                            rem -= n;
                        }
                        let _ = s.shutdown().await;
                    }
                });
            }
        });

        let (dec_cfg, _, _, _) = generate_vless_enc().unwrap();
        let tp = reserve_free_tcp_port();
        let unlimited_port = reserve_free_tcp_port();
        let limited_port = reserve_free_tcp_port();
        let srv_local = LocalTLS {
            protocol: "vless".to_string(),
            transport_security: "plain".to_string(),
            decryption: dec_cfg,
            listen_host: "127.0.0.1".to_string(),
            listen_port: tp,
            ..Default::default()
        };
        let srv = Node {
            id: "srv-bw".to_string(),
            name: "srv-bw".to_string(),
            role: "server".to_string(),
            address: "127.0.0.1".to_string(),
            port: tp,
            connect_endpoints: vec![ConnectEndpoint {
                id: "ep-1".to_string(),
                name: "primary".to_string(),
                host: "127.0.0.1".to_string(),
                port: tp,
                enabled: true,
            }],
            tunnel: srv_local.clone(),
            ..Default::default()
        };
        let mut srv_for_cli = srv.clone();
        srv_for_cli.tunnel = derive_client_tunnel(&LocalTLS::default(), &srv_local, &srv).unwrap();
        let cli = Node {
            id: "cli-bw".to_string(),
            name: "cli-bw".to_string(),
            role: "client".to_string(),
            ..Default::default()
        };
        let bind = Binding {
            id: "bind-bw".to_string(),
            server_id: "srv-bw".to_string(),
            client_id: "cli-bw".to_string(),
            uuid: "550e8400-e29b-41d4-a716-446655440099".to_string(),
            domain: "bw.veilink.internal".to_string(),
            ..Default::default()
        };
        // Sibling mapping pointing to the EXACT SAME target_host:target_port, with NO limit!
        let m_unlimited = Mapping {
            id: "map-unlim".to_string(),
            name: "unlim".to_string(),
            binding_id: "bind-bw".to_string(),
            server_id: "srv-bw".to_string(),
            client_id: "cli-bw".to_string(),
            pool: 1,
            listen_host: "127.0.0.1".to_string(),
            listen_port: unlimited_port,
            target_host: "127.0.0.1".to_string(),
            target_port,
            network: "tcp".to_string(),
            enabled: true,
            ..Default::default()
        };
        // Limited mapping: 8Mbps (= 1,000,000 B/s), so 512 KiB (524,288 B) must take ~470ms..900ms!
        let m_limited = Mapping {
            id: "map-lim".to_string(),
            name: "lim".to_string(),
            binding_id: "bind-bw".to_string(),
            server_id: "srv-bw".to_string(),
            client_id: "cli-bw".to_string(),
            pool: 1,
            bandwidth_limit: "8Mbps".to_string(),
            listen_host: "127.0.0.1".to_string(),
            listen_port: limited_port,
            target_host: "127.0.0.1".to_string(),
            target_port,
            network: "tcp".to_string(),
            enabled: true,
            ..Default::default()
        };

        let srv_rt = Runtime::new(LocalTLS::default());
        let cli_rt = Runtime::new(LocalTLS::default());
        srv_rt
            .apply(Snapshot {
                revision: 1,
                node: srv.clone(),
                nodes: vec![srv.clone()],
                bindings: vec![bind.clone()],
                mappings: vec![m_unlimited.clone(), m_limited.clone()],
            })
            .unwrap();
        cli_rt
            .apply(Snapshot {
                revision: 1,
                node: cli.clone(),
                nodes: vec![srv_for_cli.clone()],
                bindings: vec![bind.clone()],
                mappings: vec![m_unlimited.clone(), m_limited.clone()],
            })
            .unwrap();

        for _ in 0..80 {
            if srv_rt.linked_bindings().contains(&"bind-bw".to_string())
                && cli_rt.linked_bindings().contains(&"bind-bw".to_string())
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }

        // Measure Upload on limited mapping (8Mbps -> 512 KiB >= 380ms)
        let t0 = std::time::Instant::now();
        let mut s_up = TcpStream::connect(format!("127.0.0.1:{}", limited_port))
            .await
            .unwrap();
        s_up.write_all(b"U").await.unwrap();
        s_up.write_all(&vec![0xABu8; TRANSFER_BYTES]).await.unwrap();
        let mut ack = [0u8; 2];
        s_up.read_exact(&mut ack).await.unwrap();
        assert_eq!(&ack, b"OK");
        let up_dur = t0.elapsed();
        assert!(
            up_dur >= Duration::from_millis(380) && up_dur <= Duration::from_millis(2500),
            "8Mbps upload of 512KiB out of expected range: {:?}",
            up_dur
        );

        // Measure Download on limited mapping (shared target with unlimited mapping! Server dn_lim MUST enforce 8Mbps!)
        let t1 = std::time::Instant::now();
        let mut s_dn = TcpStream::connect(format!("127.0.0.1:{}", limited_port))
            .await
            .unwrap();
        s_dn.write_all(b"D").await.unwrap();
        let mut got = 0usize;
        let mut rbuf = vec![0u8; 32768];
        while got < TRANSFER_BYTES {
            let n = s_dn.read(&mut rbuf).await.unwrap();
            assert!(n > 0);
            got += n;
        }
        let dn_dur = t1.elapsed();
        assert!(
            dn_dur >= Duration::from_millis(380) && dn_dur <= Duration::from_millis(2500),
            "8Mbps download of 512KiB (shared target) out of expected range: {:?}",
            dn_dur
        );

        let _ = cli_rt.close();
        let _ = srv_rt.close();
        target_task.abort();
    }
}
