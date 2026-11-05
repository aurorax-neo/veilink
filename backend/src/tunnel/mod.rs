use std::collections::{HashMap, HashSet};
use std::io::{BufReader, Cursor};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
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

pub const MAX_PAYLOAD: usize = 32 << 10;
pub const MAX_STREAMS: usize = 512;
const FRAME_HDR_LEN: usize = 7;
const OPTIMAL_DATA_CHUNK: usize = (16 << 10) - FRAME_HDR_LEN;

const FLOW_VISION: &str = "xtls-rprx-vision";
const VLESS_SCHEME: &str = "mlkem768x25519plus";
const VLESS_PLAIN: &str = "none";
const XHTTP_MAX_DATA_CHUNKS: usize = 32;

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
        return Ok(Duration::from_secs(60));
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

pub fn check_reality_server(r: &Reality, fallback: &str) -> Result<(), String> {
    check_dest(&r.dest)?;
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
            let network = if local.hysteria2.enabled() {
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
            n.desired_revision = 0;
            n.applied_revision = 0;
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

pub async fn write_vless_with_flow<W: AsyncWrite + Unpin>(
    w: &mut W,
    id: [u8; 16],
    host: &str,
    port: u16,
    flow: &str,
) -> Result<(), String> {
    let addons = vision::encode_flow(flow);
    if addons.len() > 255 {
        return Err("vless addons too large".to_string());
    }
    let mut buf = Vec::with_capacity(32 + addons.len() + host.len());
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
    let mut out = Vec::with_capacity(8 + pkt.len());
    out.extend_from_slice(&[0x00, 0x04, 0x00, 0x01, 0x02, 0x02]);
    out.extend_from_slice(&(pkt.len() as u16).to_be_bytes());
    out.extend_from_slice(pkt);
    out
}

pub fn decode_xudp(frame: &[u8]) -> &[u8] {
    if frame.len() >= 8 && frame[0..2] == [0x00, 0x04] && frame[4] == 0x02 && frame[5] == 0x02 {
        let plen = u16::from_be_bytes([frame[6], frame[7]]) as usize;
        if 8 + plen <= frame.len() {
            return &frame[8..8 + plen];
        }
    }
    frame
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
struct SessionHandle {
    tx: mpsc::Sender<(u8, u32, Vec<u8>)>,
    streams: Arc<Mutex<HashMap<u32, mpsc::Sender<(u8, Vec<u8>)>>>>,
    next_id: Arc<AtomicU32>,
}

impl SessionHandle {
    fn open_stream(&self) -> Option<(u32, mpsc::Receiver<(u8, Vec<u8>)>)> {
        let mut map = self.streams.lock().unwrap();
        if map.len() >= MAX_STREAMS {
            return None;
        }
        let mut id = self.next_id.fetch_add(1, Ordering::Relaxed);
        while id == 0 || map.contains_key(&id) {
            id = self.next_id.fetch_add(1, Ordering::Relaxed);
        }
        let (tx, rx) = mpsc::channel(256);
        map.insert(id, tx);
        Some((id, rx))
    }

    fn close_stream(&self, id: u32) {
        self.streams.lock().unwrap().remove(&id);
    }
}

type SessionMap = Arc<Mutex<HashMap<String, Vec<SessionHandle>>>>;

/// Most recent session for a binding whose writer is still alive.
fn pick_session(sessions: &SessionMap, binding_id: &str) -> Option<SessionHandle> {
    static RR: AtomicUsize = AtomicUsize::new(0);
    let guard = sessions.lock().unwrap();
    let list = guard.get(binding_id)?;
    let alive: Vec<&SessionHandle> = list.iter().filter(|h| !h.tx.is_closed()).collect();
    if alive.is_empty() {
        return None;
    }
    let idx = RR.fetch_add(1, Ordering::Relaxed) % alive.len();
    Some(alive[idx].clone())
}

/// Unregister a finished session and drop its stream senders so that every
/// mapping task bound to it observes EOF. Returns true when the binding has
/// no live session left.
fn remove_session(sessions: &SessionMap, binding_id: &str, handle: &SessionHandle) -> bool {
    handle.streams.lock().unwrap().clear();
    let mut map = sessions.lock().unwrap();
    let Some(list) = map.get_mut(binding_id) else {
        return true;
    };
    list.retain(|h| !Arc::ptr_eq(&h.streams, &handle.streams) && !h.tx.is_closed());
    if list.is_empty() {
        map.remove(binding_id);
        true
    } else {
        false
    }
}

struct RunningInstance {
    stop_tx: watch::Sender<bool>,
    linked: Arc<Mutex<HashSet<String>>>,
    listeners: Vec<std::net::TcpListener>,
    udp_sockets: Vec<std::net::UdpSocket>,
    quic_endpoints: Vec<quinn::Endpoint>,
    tasks: Vec<tokio::task::AbortHandle>,
}

impl RunningInstance {
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

fn build_tls_acceptor(local: &LocalTLS) -> Result<tokio_rustls::TlsAcceptor, String> {
    let (certs, key) = hysteria2::load_cert_and_key(&local.cert_pem, &local.key_pem)?;
    let provider = fast_crypto_provider();
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| e.to_string())?;
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(cfg)))
}

fn build_tls_connector(local: &LocalTLS) -> Result<tokio_rustls::TlsConnector, String> {
    let provider = fast_crypto_provider();
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?;
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
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(tokio_rustls::TlsConnector::from(Arc::new(cfg)))
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
        .unwrap_or(Duration::from_secs(60))
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
        vec!["h2".to_string(), "http/1.1".to_string()]
    } else {
        Vec::new()
    };
    Ok(reality::RealityClientConfig {
        server_name,
        public_key,
        short_id,
        fingerprint: local.reality.fingerprint.clone(),
        alpn,
        mldsa65_verify: local.reality.mldsa65_verify.trim().to_string(),
    })
}

async fn accept_outer_stream(
    tcp_stream: TcpStream,
    local: &LocalTLS,
    tls_acceptor: Option<tokio_rustls::TlsAcceptor>,
    reality_cfg: Option<reality::RealityServerConfig>,
) -> Option<BoxStream> {
    if local.reality.enabled() {
        let rcfg = reality_cfg?;
        match tokio::time::timeout(
            Duration::from_secs(10),
            reality::reality_accept(tcp_stream, &rcfg),
        )
        .await
        {
            Ok(Ok(Some(s))) => Some(s),
            _ => None,
        }
    } else if !local.cert_pem.is_empty()
        && !local.key_pem.is_empty()
        && (local.transport_security == "tls" || (local.xhttp.enabled() && local.xhttp.tls))
    {
        let acceptor = tls_acceptor?;
        match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tcp_stream)).await {
            Ok(Ok(s)) => Some(Box::new(s)),
            _ => None,
        }
    } else {
        Some(Box::new(tcp_stream))
    }
}

async fn connect_outer_stream(
    remote_addr: SocketAddr,
    local: LocalTLS,
    binding: Binding,
    gw_addr: String,
) -> Result<BoxStream, String> {
    let tcp = tokio::time::timeout(Duration::from_secs(8), TcpStream::connect(remote_addr))
        .await
        .map_err(|_| "tcp connect timeout".to_string())?
        .map_err(|e| e.to_string())?;
    let _ = tcp.set_nodelay(true);

    if local.reality.enabled() {
        let rcfg = build_reality_client_cfg(&local, &gw_addr, &binding.domain)?;
        let s = tokio::time::timeout(Duration::from_secs(8), reality::reality_connect(tcp, &rcfg))
            .await
            .map_err(|_| "reality handshake timeout".to_string())?
            .map_err(|e| e.to_string())?;
        Ok(s)
    } else if local.transport_security == "tls" || (local.xhttp.enabled() && local.xhttp.tls) {
        let connector = build_tls_connector(&local)?;
        let sni_str = if !local.xhttp.host.trim().is_empty() {
            local.xhttp.host.trim().to_string()
        } else if !gw_addr.trim().is_empty() {
            gw_addr.trim().to_string()
        } else if !binding.domain.trim().is_empty() {
            binding.domain.trim().to_string()
        } else {
            "localhost".to_string()
        };
        let server_name = ServerName::try_from(sni_str)
            .unwrap_or_else(|_| ServerName::try_from("localhost".to_string()).unwrap());
        let s = tokio::time::timeout(Duration::from_secs(8), connector.connect(server_name, tcp))
            .await
            .map_err(|_| "tls handshake timeout".to_string())?
            .map_err(|e| e.to_string())?;
        Ok(Box::new(s))
    } else {
        Ok(Box::new(tcp))
    }
}

async fn serve_vless_session(
    mut stream: BoxStream,
    local: LocalTLS,
    vless_dec: Option<Arc<vless_enc::ServerInstance>>,
    bindings: Vec<Binding>,
    sessions: SessionMap,
    linked: Arc<Mutex<HashSet<String>>>,
    logger: TunnelLogger,
    mut conn_stop: watch::Receiver<bool>,
) {
    if *conn_stop.borrow() {
        return;
    }
    if let Some(dec) = vless_dec {
        tokio::select! {
            _ = conn_stop.changed() => return,
            res = tokio::time::timeout(Duration::from_secs(8), dec.handshake(stream)) => {
                match res {
                    Ok(Ok(s)) => stream = s,
                    _ => return,
                }
            }
        }
    }
    let (uuid_bytes, domain, _port, client_flow) = tokio::select! {
        _ = conn_stop.changed() => return,
        res = tokio::time::timeout(Duration::from_secs(8), read_vless_with_flow(&mut stream)) => {
            match res {
                Ok(Ok(v)) => v,
                _ => return,
            }
        }
    };
    let expected_flow = normalize_flow(&local.flow).unwrap_or_default();
    if !expected_flow.is_empty() && client_flow != expected_flow {
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
        return;
    };
    if stream.write_all(&[0, 0]).await.is_err() || stream.flush().await.is_err() {
        return;
    }
    if expected_flow == FLOW_VISION {
        stream = vision::wrap_vision_stream(stream, uuid_bytes, false);
    }
    serve_established_session(stream, binding, sessions, linked, logger, conn_stop).await;
}

async fn serve_established_session(
    stream: BoxStream,
    binding: Binding,
    sessions: SessionMap,
    linked: Arc<Mutex<HashSet<String>>>,
    logger: TunnelLogger,
    mut conn_stop: watch::Receiver<bool>,
) {
    if *conn_stop.borrow() {
        return;
    }
    if linked.lock().unwrap().insert(binding.id.clone()) {
        log_tunnel(
            &logger,
            "INFO",
            format!(
                "server tunnel session established role=server binding_id={} client_id={}",
                binding.id, binding.client_id
            ),
        );
    }
    let (tx, mut out_rx) = mpsc::channel::<(u8, u32, Vec<u8>)>(256);
    let streams_map: Arc<Mutex<HashMap<u32, mpsc::Sender<(u8, Vec<u8>)>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let handle = SessionHandle {
        tx: tx.clone(),
        streams: streams_map.clone(),
        next_id: Arc::new(AtomicU32::new(1)),
    };
    sessions
        .lock()
        .unwrap()
        .entry(binding.id.clone())
        .or_default()
        .push(handle.clone());
    let (mut rd, mut wr) = split_tunnel_stream(stream);
    let write_task = tokio::spawn(async move {
        let mut write_buf = Vec::with_capacity(65536);
        while let Some((kind, id, payload)) = out_rx.recv().await {
            write_buf.clear();
            if append_frame(&mut write_buf, kind, id, &payload).is_err() {
                break;
            }
            while write_buf.len() < 65536 {
                let Ok((k, i, p)) = out_rx.try_recv() else { break };
                if append_frame(&mut write_buf, k, i, &p).is_err() {
                    let _ = wr.shutdown().await;
                    return;
                }
            }
            if wr.write_all(&write_buf).await.is_err() || wr.flush().await.is_err() {
                break;
            }
        }
        let _ = wr.shutdown().await;
    });
    loop {
        tokio::select! {
            _ = conn_stop.changed() => break,
            frame = read_frame(&mut rd) => {
                let Ok((kind, id, payload)) = frame else { break };
                match kind {
                    FRAME_PING => {
                        let _ = tx.send((FRAME_PONG, 0, Vec::new())).await;
                    }
                    FRAME_PONG => {}
                    FRAME_DATA | FRAME_HALF | FRAME_RESET => {
                        if kind == FRAME_RESET {
                            if let Some(s) = streams_map.lock().unwrap().remove(&id) {
                                let _ = s.try_send((kind, payload));
                            }
                        } else {
                            let sender = streams_map.lock().unwrap().get(&id).cloned();
                            if let Some(s) = sender {
                                if tokio::time::timeout(
                                    Duration::from_secs(10),
                                    s.send((kind, payload)),
                                )
                                .await
                                .is_err()
                                {
                                    streams_map.lock().unwrap().remove(&id);
                                    let _ = tx.try_send((FRAME_RESET, id, Vec::new()));
                                }
                            }
                        }
                    }
                    _ => break,
                }
            }
        }
    }
    write_task.abort();
    drop(tx);
    if remove_session(&sessions, &binding.id, &handle) {
        linked.lock().unwrap().remove(&binding.id);
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

fn start_instance(
    s: &Snapshot,
    local: &LocalTLS,
    traffic: Arc<Traffic>,
    logger: TunnelLogger,
) -> Result<RunningInstance, String> {
    validate(s, local)?;
    let (stop_tx, stop_rx) = watch::channel(false);
    let linked = Arc::new(Mutex::new(HashSet::new()));
    let mut listeners = Vec::new();
    let mut udp_sockets = Vec::new();
    let mut quic_endpoints = Vec::new();
    let mut tasks = Vec::new();
    let sessions: SessionMap = Arc::new(Mutex::new(HashMap::new()));

    if s.node.role == "server" {
        let mut transport_ln: Option<std::net::TcpListener> = None;
        let mut transport_udp: Option<std::net::UdpSocket> = None;
        if !s.bindings.is_empty() {
            let addr = format!("{}:{}", listen_host(&local.listen_host), local.listen_port);
            if local.hysteria2.enabled() || (local.xhttp.enabled() && local.xhttp.http_version == "3")
            {
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
        }
        let mut mapping_tcp_lns: Vec<(Mapping, std::net::TcpListener)> = Vec::new();
        let mut mapping_udp_socks: Vec<(Mapping, std::net::UdpSocket)> = Vec::new();
        for m in &s.mappings {
            if !m.enabled {
                continue;
            }
            let addr = format!("{}:{}", listen_host(&m.listen_host), m.listen_port);
            if mapping_net(&m.network) == "udp" {
                let sock = bind_udp_with_retry(&addr)
                    .map_err(|e| format!("bind mapping udp {}: {}", addr, e))?;
                if let Ok(cloned) = sock.try_clone() {
                    mapping_udp_socks.push((m.clone(), cloned));
                }
                udp_sockets.push(sock);
            } else {
                let ln = bind_tcp_with_retry(&addr)
                    .map_err(|e| format!("bind mapping tcp {}: {}", addr, e))?;
                if let Ok(cloned) = ln.try_clone() {
                    mapping_tcp_lns.push((m.clone(), cloned));
                }
                listeners.push(ln);
            }
        }

        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            if local.hysteria2.enabled() {
                if let Some(std_udp) = transport_udp {
                    let server_cfg = hysteria2::build_quic_server_config(local)?;
                    {
                        if let Ok(quic_ep) = quinn::Endpoint::new(
                            quinn::EndpointConfig::default(),
                            Some(server_cfg),
                            std_udp,
                            Arc::new(quinn::TokioRuntime),
                        ) {
                            quic_endpoints.push(quic_ep.clone());
                            let bindings = s.bindings.clone();
                            let local_clone = local.clone();
                            let sessions_clone = sessions.clone();
                            let linked_clone = linked.clone();
                            let logger_clone = logger.clone();
                            let mut rx = stop_rx.clone();
                            let jh = handle.spawn(async move {
                                loop {
                                    tokio::select! {
                                        _ = rx.changed() => {
                                            quic_ep.close(0u32.into(), b"shutdown");
                                            break;
                                        }
                                        inc = quic_ep.accept() => {
                                            let Some(incoming) = inc else { break };
                                            let bindings = bindings.clone();
                                            let local_c = local_clone.clone();
                                            let sessions = sessions_clone.clone();
                                            let linked = linked_clone.clone();
                                            let log_c = logger_clone.clone();
                                            let conn_stop = rx.clone();
                                            tokio::spawn(async move {
                                                let Ok(conn) = incoming.await else { return };
                                                let Ok((stream, binding)) =
                                                    hysteria2::hy2_accept_connection(conn, &local_c, &bindings).await
                                                else {
                                                    return;
                                                };
                                                serve_established_session(stream, binding, sessions, linked, log_c, conn_stop).await;
                                            });
                                        }
                                    }
                                }
                            });
                            tasks.push(jh.abort_handle());
                        }
                    }
                }
            }

            if let Some(std_ln) = transport_ln {
                let _ = std_ln.set_nonblocking(true);
                if let Ok(tokio_ln) = TcpListener::from_std(std_ln) {
                    let bindings = s.bindings.clone();
                    let sessions_clone = sessions.clone();
                    let linked_clone = linked.clone();
                    let local_clone = local.clone();
                    let tls_acceptor = if !local.reality.enabled()
                        && !local.cert_pem.is_empty()
                        && !local.key_pem.is_empty()
                        && (local.transport_security == "tls" || (local.xhttp.enabled() && local.xhttp.tls))
                    {
                        Some(build_tls_acceptor(local)?)
                    } else {
                        None
                    };
                    let reality_cfg = if local.reality.enabled() {
                        Some(build_reality_server_cfg(local)?)
                    } else {
                        None
                    };
                    let vless_dec = vless_enc::ServerInstance::from_raw(&local.decryption)?;
                    let xhttp_state = if local.xhttp.enabled() {
                        Some(xhttp::XhttpServerState::new())
                    } else {
                        None
                    };
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
                                    let _ = tcp_stream.set_nodelay(true);
                                    let bindings = bindings.clone();
                                    let sessions = sessions_clone.clone();
                                    let linked = linked_clone.clone();
                                    let local_c = local_clone.clone();
                                    let tls_acc = tls_acceptor.clone();
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
                                            accept_outer_stream(tcp_stream, &local_c, tls_acc, r_cfg).await
                                        else {
                                            return;
                                        };
                                        if let Some(xs) = x_state {
                                            let local_inner = local_c.clone();
                                            let log_inner = log_c.clone();
                                            tokio::select! {
                                                _ = outer_stop.changed() => {}
                                                _ = xhttp::handle_xhttp_server_conn(
                                                    outer_stream,
                                                    local_c,
                                                    xs,
                                                    move |tunnel_stream| {
                                                        let b = bindings.clone();
                                                        let s = sessions.clone();
                                                        let l = linked.clone();
                                                        let cs = conn_stop.clone();
                                                        let vd = v_dec.clone();
                                                        let lc = local_inner.clone();
                                                        let lg = log_inner.clone();
                                                        tokio::spawn(async move {
                                                            serve_vless_session(tunnel_stream, lc, vd, b, s, l, lg, cs).await;
                                                        });
                                                    },
                                                ) => {}
                                            }
                                        } else {
                                            serve_vless_session(
                                                outer_stream,
                                                local_c,
                                                v_dec,
                                                bindings,
                                                sessions,
                                                linked,
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

            for (m, std_ln) in mapping_tcp_lns {
                let _ = std_ln.set_nonblocking(true);
                if let Ok(tokio_ln) = TcpListener::from_std(std_ln) {
                    let sessions_clone = sessions.clone();
                    let traffic_clone = traffic.clone();
                    let mut rx = stop_rx.clone();
                    let jh = handle.spawn(async move {
                        let rate_bps = bandwidth_bytes(&m.bandwidth_limit).unwrap_or(0) as u64;
                        let mux_type = m.effective_mux_type().unwrap_or_default();
                        loop {
                            tokio::select! {
                                _ = rx.changed() => break,
                                accepted = tokio_ln.accept() => {
                                    let Ok((pub_stream, _)) = accepted else { break };
                                    let _ = pub_stream.set_nodelay(true);
                                    let Some(sess) = pick_session(&sessions_clone, &m.binding_id) else { continue };
                                    let Some((stream_id, mut in_rx)) = sess.open_stream() else { continue };
                                    let m_clone = m.clone();
                                    let traffic_conn = traffic_clone.clone();
                                    let mux_t = mux_type.clone();
                                    tokio::spawn(async move {
                                        let meta = if mux_t.is_empty() {
                                            m_clone.target_host.clone()
                                        } else {
                                            format!("{}\0tcp\0{}", m_clone.target_host, mux_t)
                                        };
                                        let mut open_payload = Vec::with_capacity(2 + meta.len());
                                        open_payload.extend_from_slice(&(m_clone.target_port as u16).to_be_bytes());
                                        open_payload.extend_from_slice(meta.as_bytes());
                                        if sess.tx.send((FRAME_OPEN, stream_id, open_payload)).await.is_err() {
                                            sess.close_stream(stream_id);
                                            return;
                                        }
                                        let (mut pr, mut pw) = pub_stream.into_split();
                                        let tx_up = sess.tx.clone();
                                        let t_up = traffic_conn.clone();
                                        let mid_up = m_clone.id.clone();
                                        let up_task = tokio::spawn(async move {
                                            let mut buf = vec![0u8; OPTIMAL_DATA_CHUNK];
                                            loop {
                                                match pr.read(&mut buf).await {
                                                    Ok(0) => {
                                                        let _ = tx_up.send((FRAME_HALF, stream_id, Vec::new())).await;
                                                        break;
                                                    }
                                                    Ok(n) => {
                                                        t_up.add(&mid_up, n, 0);
                                                        if tx_up.send((FRAME_DATA, stream_id, buf[..n].to_vec())).await.is_err() {
                                                            break;
                                                        }
                                                        if rate_bps > 0 {
                                                            let sleep_us = ((n as u64) * 1_000_000) / rate_bps;
                                                            if sleep_us > 1000 {
                                                                tokio::time::sleep(Duration::from_micros(sleep_us)).await;
                                                            }
                                                        }
                                                    }
                                                    Err(_) => {
                                                        let _ = tx_up.send((FRAME_RESET, stream_id, Vec::new())).await;
                                                        break;
                                                    }
                                                }
                                            }
                                        });
                                        // Peer already dropped the stream only when it sent RESET; otherwise
                                        // tell it to release its side (half-close is treated as full close here).
                                        let mut remote_reset = false;
                                        let mut half_closed = false;
                                        while let Some((kind, data)) = in_rx.recv().await {
                                            match kind {
                                                FRAME_DATA => {
                                                    traffic_conn.add(&m_clone.id, 0, data.len());
                                                    if pw.write_all(&data).await.is_err() {
                                                        break;
                                                    }
                                                    if rate_bps > 0 {
                                                        let sleep_us = ((data.len() as u64) * 1_000_000) / rate_bps;
                                                        if sleep_us > 1000 {
                                                            tokio::time::sleep(Duration::from_micros(sleep_us)).await;
                                                        }
                                                    }
                                                }
                                                FRAME_HALF => {
                                                    half_closed = true;
                                                    let _ = pw.shutdown().await;
                                                    break;
                                                }
                                                FRAME_RESET => {
                                                    remote_reset = true;
                                                    break;
                                                }
                                                _ => break,
                                            }
                                        }
                                        if half_closed && !remote_reset {
                                            let _ = tokio::time::timeout(Duration::from_secs(10), up_task).await;
                                        } else {
                                            up_task.abort();
                                        }
                                        sess.close_stream(stream_id);
                                        if !remote_reset && !half_closed {
                                            let _ = sess.tx.send((FRAME_RESET, stream_id, Vec::new())).await;
                                        }
                                    });
                                }
                            }
                        }
                    });
                    tasks.push(jh.abort_handle());
                }
            }

            for (m, std_udp) in mapping_udp_socks {
                let _ = std_udp.set_nonblocking(true);
                if let Ok(tokio_udp) = tokio::net::UdpSocket::from_std(std_udp) {
                    let udp_sock = Arc::new(tokio_udp);
                    let sessions_clone = sessions.clone();
                    let traffic_clone = traffic.clone();
                    let mut rx = stop_rx.clone();
                    let jh = handle.spawn(async move {
                        let mut peer_streams: HashMap<SocketAddr, mpsc::Sender<Vec<u8>>> =
                            HashMap::new();
                        let mut buf = vec![0u8; 65535];
                        loop {
                            tokio::select! {
                                _ = rx.changed() => break,
                                recv_res = udp_sock.recv_from(&mut buf) => {
                                    let Ok((n, peer_addr)) = recv_res else { break };
                                    let pkt = buf[..n].to_vec();
                                    if let Some(tx) = peer_streams.get(&peer_addr) {
                                        if tx.try_send(pkt.clone()).is_ok() {
                                            traffic_clone.add(&m.id, n, 0);
                                            continue;
                                        }
                                        peer_streams.remove(&peer_addr);
                                    }
                                    if peer_streams.len() >= 1024 {
                                        peer_streams.retain(|_, tx| !tx.is_closed());
                                        if peer_streams.len() >= 4096 {
                                            continue;
                                        }
                                    }
                                    let Some(sess) = pick_session(&sessions_clone, &m.binding_id) else { continue };
                                    let Some((stream_id, mut in_rx)) = sess.open_stream() else { continue };
                                    let (pkt_tx, mut pkt_rx) = mpsc::channel::<Vec<u8>>(64);
                                    let _ = pkt_tx.try_send(pkt);
                                    traffic_clone.add(&m.id, n, 0);
                                    peer_streams.insert(peer_addr, pkt_tx);
                                    let m_clone = m.clone();
                                    let udp_reply = udp_sock.clone();
                                    let traffic_down = traffic_clone.clone();
                                    tokio::spawn(async move {
                                        let meta = format!("{}\0udp\0", m_clone.target_host);
                                        let mut open_payload = Vec::with_capacity(2 + meta.len());
                                        open_payload.extend_from_slice(&(m_clone.target_port as u16).to_be_bytes());
                                        open_payload.extend_from_slice(meta.as_bytes());
                                        if sess.tx.send((FRAME_OPEN, stream_id, open_payload)).await.is_err() {
                                            sess.close_stream(stream_id);
                                            return;
                                        }
                                        let tx_up = sess.tx.clone();
                                        let up_task = tokio::spawn(async move {
                                            while let Some(dg) = pkt_rx.recv().await {
                                                let xudp = encode_xudp(&dg);
                                                if tx_up.send((FRAME_DATA, stream_id, xudp)).await.is_err() {
                                                    break;
                                                }
                                            }
                                        });
                                        loop {
                                            match tokio::time::timeout(Duration::from_secs(30), in_rx.recv()).await {
                                                Ok(Some((FRAME_DATA, data))) => {
                                                    let raw_dg = decode_xudp(&data);
                                                    traffic_down.add(&m_clone.id, 0, raw_dg.len());
                                                    let _ = udp_reply.send_to(raw_dg, peer_addr).await;
                                                }
                                                _ => break,
                                            }
                                        }
                                        up_task.abort();
                                        sess.close_stream(stream_id);
                                        let _ = sess.tx.send((FRAME_RESET, stream_id, Vec::new())).await;
                                    });
                                }
                            }
                        }
                    });
                    tasks.push(jh.abort_handle());
                }
            }
        }
    } else if s.node.role == "client" && !s.bindings.is_empty() {
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
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
                let vless_enc_cli = vless_enc::ClientInstance::from_raw(&client_cfg.encryption)?;
                let pool_count = s
                    .mappings
                    .iter()
                    .filter(|m| m.enabled && m.binding_id == b.id)
                    .map(|m| m.pool.clamp(1, 32) as usize)
                    .max()
                    .unwrap_or(1);
                let active_workers = Arc::new(AtomicUsize::new(0));

                for worker_idx in 0..pool_count {
                    let b_clone = b.clone();
                    let mappings = s.mappings.clone();
                    let linked_clone = linked.clone();
                    let eps_clone = eps.clone();
                    let cfg_clone = client_cfg.clone();
                    let gw_addr = bound_gw.address.clone();
                    let enc_cli = vless_enc_cli.clone();
                    let workers_ref = active_workers.clone();
                    let log_c = logger.clone();
                    let mut rx = stop_rx.clone();
                    handle.spawn(async move {
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

                            let maybe_stream = dial_client_session(
                                dial_ep,
                                &eps_clone,
                                &cfg_clone,
                                &b_clone,
                                uuid_bytes,
                                &gw_addr,
                                enc_cli.clone(),
                            )
                            .await;

                            match maybe_stream {
                                Ok(stream) => {
                                    let prev_fails = fail_streak;
                                    fail_streak = 0;
                                    let prev_workers = workers_ref.fetch_add(1, Ordering::SeqCst);
                                    linked_clone.lock().unwrap().insert(b_clone.id.clone());
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
                                let (tx, mut out_rx) = mpsc::channel::<(u8, u32, Vec<u8>)>(256);
                                let streams_map: Arc<
                                    Mutex<HashMap<u32, mpsc::Sender<(u8, Vec<u8>)>>>,
                                > = Arc::new(Mutex::new(HashMap::new()));
                                let (mut rd, mut wr) = split_tunnel_stream(stream);
                                let write_task = tokio::spawn(async move {
                                    let mut write_buf = Vec::with_capacity(65536);
                                    while let Some((kind, id, payload)) = out_rx.recv().await {
                                        write_buf.clear();
                                        if append_frame(&mut write_buf, kind, id, &payload).is_err() {
                                            break;
                                        }
                                        while write_buf.len() < 65536 {
                                            let Ok((k, i, p)) = out_rx.try_recv() else { break };
                                            if append_frame(&mut write_buf, k, i, &p).is_err() {
                                                let _ = wr.shutdown().await;
                                                return;
                                            }
                                        }
                                        if wr.write_all(&write_buf).await.is_err()
                                            || wr.flush().await.is_err()
                                        {
                                            break;
                                        }
                                    }
                                    let _ = wr.shutdown().await;
                                });
                                loop {
                                    tokio::select! {
                                        _ = rx.changed() => break,
                                        frame = read_frame(&mut rd) => {
                                            let Ok((kind, id, payload)) = frame else { break };
                                            match kind {
                                                FRAME_PING => {
                                                    let _ = tx.send((FRAME_PONG, 0, Vec::new())).await;
                                                }
                                                FRAME_OPEN => {
                                                    handle_client_frame_open(
                                                        id,
                                                        payload,
                                                        &b_clone,
                                                        &mappings,
                                                        &tx,
                                                        &streams_map,
                                                    );
                                                }
                                                FRAME_DATA | FRAME_HALF | FRAME_RESET => {
                                                    if kind == FRAME_RESET {
                                                        if let Some(s) = streams_map.lock().unwrap().remove(&id) {
                                                            let _ = s.try_send((kind, payload));
                                                        }
                                                    } else {
                                                        let sender = streams_map.lock().unwrap().get(&id).cloned();
                                                        if let Some(s) = sender {
                                                            if tokio::time::timeout(
                                                                Duration::from_secs(10),
                                                                s.send((kind, payload)),
                                                            )
                                                            .await
                                                            .is_err()
                                                            {
                                                                streams_map.lock().unwrap().remove(&id);
                                                                let _ = tx.try_send((FRAME_RESET, id, Vec::new()));
                                                            }
                                                        }
                                                    }
                                                }
                                                _ => {}
                                            }
                                        }
                                    }
                                }
                                write_task.abort();
                                streams_map.lock().unwrap().clear();
                                if workers_ref.fetch_sub(1, Ordering::SeqCst) == 1 {
                                    linked_clone.lock().unwrap().remove(&b_clone.id);
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
                }
            }
        }
    }

    Ok(RunningInstance {
        stop_tx,
        linked,
        listeners,
        udp_sockets,
        quic_endpoints,
        tasks,
    })
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
    let addrs: Vec<SocketAddr> = tokio::time::timeout(Duration::from_secs(5), tokio::net::lookup_host(&addr_str))
        .await
        .map_err(|_| format!("dns lookup timeout for {}", addr_str))?
        .map_err(|e| e.to_string())?
        .collect();
    if addrs.is_empty() {
        return Err(format!("unable to resolve {}", addr_str));
    }
    Ok(addrs)
}

async fn resolve_socket_addr(host: &str, port: i64) -> Result<SocketAddr, String> {
    let addrs = resolve_socket_addrs(host, port).await?;
    Ok(addrs[0])
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
        )
        .await
        {
            Ok(s) => return Ok(s),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

async fn dial_client_session_addr(
    remote_addr: SocketAddr,
    all_eps: &[ConnectEndpoint],
    client_cfg: &LocalTLS,
    binding: &Binding,
    uuid_bytes: [u8; 16],
    gw_addr: &str,
    vless_enc_cli: Option<Arc<vless_enc::ClientInstance>>,
) -> Result<BoxStream, String> {
    if client_cfg.hysteria2.enabled() {
        return hysteria2::hy2_connect(remote_addr, client_cfg, binding, gw_addr).await;
    }

    let mut stream = if client_cfg.xhttp.enabled() {
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
        xhttp::xhttp_client_connect(
            remote_addr,
            client_cfg,
            dn_target,
            binding,
            move |sa, lcfg, b| {
                let g = gw_owned.clone();
                async move { connect_outer_stream(sa, lcfg, b, g).await }
            },
        )
        .await?
    } else {
        connect_outer_stream(remote_addr, client_cfg.clone(), binding.clone(), gw_addr.to_string())
            .await?
    };

    if let Some(enc) = vless_enc_cli {
        stream = tokio::time::timeout(Duration::from_secs(8), enc.handshake(stream))
            .await
            .map_err(|_| "vless encryption handshake timeout".to_string())?
            .map_err(|e| e.to_string())?;
    }

    let flow = normalize_flow(&client_cfg.flow).unwrap_or_default();
    write_vless_with_flow(&mut stream, uuid_bytes, &binding.domain, 0, &flow).await?;
    stream.flush().await.map_err(|e| e.to_string())?;

    let mut resp = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(8), stream.read_exact(&mut resp))
        .await
        .map_err(|_| "vless response timeout".to_string())?
        .map_err(|e| e.to_string())?;
    if resp != [0, 0] {
        return Err("invalid vless response header".to_string());
    }

    if flow == FLOW_VISION {
        stream = vision::wrap_vision_stream(stream, uuid_bytes, true);
    }
    Ok(stream)
}

fn handle_client_frame_open(
    id: u32,
    payload: Vec<u8>,
    binding: &Binding,
    mappings: &[Mapping],
    tx: &mpsc::Sender<(u8, u32, Vec<u8>)>,
    streams_map: &Arc<Mutex<HashMap<u32, mpsc::Sender<(u8, Vec<u8>)>>>>,
) {
    if payload.len() < 3 {
        let tx_c = tx.clone();
        tokio::spawn(async move {
            let _ = tx_c.send((FRAME_RESET, id, Vec::new())).await;
        });
        return;
    }
    let port = u16::from_be_bytes([payload[0], payload[1]]) as i64;
    let Ok(raw_meta) = String::from_utf8(payload[2..].to_vec()) else {
        let tx_c = tx.clone();
        tokio::spawn(async move {
            let _ = tx_c.send((FRAME_RESET, id, Vec::new())).await;
        });
        return;
    };
    let mut parts = raw_meta.split('\0');
    let host = parts.next().unwrap_or("").to_string();
    let req_net = parts.next().unwrap_or("tcp");
    let req_mux = parts.next().unwrap_or("");
    let has_meta = raw_meta.contains('\0');

    let authorized = mappings.iter().any(|m| {
        if !m.enabled
            || m.binding_id != binding.id
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
    });
    if !authorized {
        let tx_c = tx.clone();
        tokio::spawn(async move {
            let _ = tx_c.send((FRAME_RESET, id, Vec::new())).await;
        });
        return;
    }

    let (stx, mut srx) = mpsc::channel::<(u8, Vec<u8>)>(256);
    streams_map.lock().unwrap().insert(id, stx);
    let tx_back = tx.clone();
    let streams_done = streams_map.clone();

    if req_net == "udp" {
        tokio::spawn(async move {
            let Ok(target_sa) = resolve_socket_addr(&host, port).await else {
                streams_done.lock().unwrap().remove(&id);
                let _ = tx_back.send((FRAME_RESET, id, Vec::new())).await;
                return;
            };
            let bind_sa: SocketAddr = if target_sa.is_ipv6() {
                "[::]:0".parse().unwrap()
            } else {
                "0.0.0.0:0".parse().unwrap()
            };
            let Ok(udp_sock) = tokio::net::UdpSocket::bind(bind_sa).await else {
                streams_done.lock().unwrap().remove(&id);
                let _ = tx_back.send((FRAME_RESET, id, Vec::new())).await;
                return;
            };
            if udp_sock.connect(target_sa).await.is_err() {
                streams_done.lock().unwrap().remove(&id);
                let _ = tx_back.send((FRAME_RESET, id, Vec::new())).await;
                return;
            };
            let udp_arc = Arc::new(udp_sock);
            let udp_recv = udp_arc.clone();
            let tx_read = tx_back.clone();
            let read_target = tokio::spawn(async move {
                let mut buf = vec![0u8; 65535];
                while let Ok(Ok(n)) =
                    tokio::time::timeout(Duration::from_secs(30), udp_recv.recv(&mut buf)).await
                {
                    let xudp = encode_xudp(&buf[..n]);
                    if tx_read.send((FRAME_DATA, id, xudp)).await.is_err() {
                        break;
                    }
                }
            });
            while let Some((k, data)) = srx.recv().await {
                match k {
                    FRAME_DATA => {
                        let raw_dg = decode_xudp(&data);
                        if udp_arc.send(raw_dg).await.is_err() {
                            break;
                        }
                    }
                    _ => break,
                }
            }
            read_target.abort();
            streams_done.lock().unwrap().remove(&id);
        });
    } else {
        tokio::spawn(async move {
            let Ok(target_addrs) = resolve_socket_addrs(&host, port).await else {
                streams_done.lock().unwrap().remove(&id);
                let _ = tx_back.send((FRAME_RESET, id, Vec::new())).await;
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
                let _ = tx_back.send((FRAME_RESET, id, Vec::new())).await;
                return;
            };
            let _ = target_stream.set_nodelay(true);
            let (mut tr, mut tw) = target_stream.into_split();
            let tx_read = tx_back.clone();
            let read_target = tokio::spawn(async move {
                let mut buf = vec![0u8; OPTIMAL_DATA_CHUNK];
                loop {
                    match tr.read(&mut buf).await {
                        Ok(0) => {
                            let _ = tx_read.send((FRAME_HALF, id, Vec::new())).await;
                            break;
                        }
                        Ok(n) => {
                            if tx_read.send((FRAME_DATA, id, buf[..n].to_vec())).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => {
                            let _ = tx_read.send((FRAME_RESET, id, Vec::new())).await;
                            break;
                        }
                    }
                }
            });
            let mut peer_reset = false;
            let mut half_closed = false;
            while let Some((k, data)) = srx.recv().await {
                match k {
                    FRAME_DATA => {
                        if tw.write_all(&data).await.is_err() {
                            break;
                        }
                    }
                    FRAME_HALF => {
                        half_closed = true;
                        let _ = tw.shutdown().await;
                        break;
                    }
                    FRAME_RESET => {
                        peer_reset = true;
                        break;
                    }
                    _ => break,
                }
            }
            if half_closed && !peer_reset {
                let _ = tokio::time::timeout(Duration::from_secs(10), read_target).await;
            } else {
                read_target.abort();
            }
            streams_done.lock().unwrap().remove(&id);
            if !peer_reset && !half_closed {
                let _ = tx_back.send((FRAME_RESET, id, Vec::new())).await;
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
            logger: Mutex::new(None),
        }
    }

    pub fn set_logger(&self, ring: Arc<Ring>, node_id: String, role: String) {
        *self.logger.lock().unwrap() = Some((ring, node_id, role));
    }

    pub fn traffic(&self) -> Arc<Traffic> {
        self.traffic.clone()
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
        if let Some(mut inst) = g.instance.take() {
            inst.stop();
            g.revision = -1;
        }
        let logger = self.logger.lock().unwrap().clone();
        self.traffic
            .prepare_active(&s.mappings, s.node.role == "server");
        match start_instance(&s, &effective, self.traffic.clone(), logger.clone()) {
            Ok(instance) => {
                self.traffic
                    .set_active(&s.mappings, s.node.role == "server");
                g.instance = Some(instance);
                g.good = Some(s.clone());
                g.good_local = effective;
                g.document = document;
                g.revision = s.revision;
                g.high_water = s.revision;
                Ok(())
            }
            Err(err) => {
                if idle_snapshot(&s) {
                    self.traffic.set_active(&[], false);
                    return Err(format!("stop listeners: {}", err));
                }
                if let Some(good) = g.good.clone() {
                    let good_local = g.good_local.clone();
                    match start_instance(&good, &good_local, self.traffic.clone(), logger) {
                        Ok(restored) => {
                            self.traffic
                                .set_active(&good.mappings, good.node.role == "server");
                            g.instance = Some(restored);
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
                            self.traffic.set_active(&[], false);
                            return Err(format!(
                                "start failed: {}; rollback failed: {}",
                                err, rollback_err
                            ));
                        }
                    }
                }
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

    fn test_session() -> (SessionHandle, mpsc::Receiver<(u8, u32, Vec<u8>)>) {
        let (tx, rx) = mpsc::channel(4);
        let h = SessionHandle {
            tx,
            streams: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(AtomicU32::new(1)),
        };
        (h, rx)
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
        let transport_port = if server_local.hysteria2.enabled() {
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
                    reality: reality_base,
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
        let (tx, _rx) = mpsc::channel(8);
        let handle = SessionHandle {
            tx,
            streams: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(AtomicU32::new(1)),
        };
        let (id1, _rx1) = handle.open_stream().unwrap();
        assert_eq!(id1, 1);
        // Simulate counter wrap-around back to u32::MAX -> 0 -> 1 (already active) -> 2
        handle.next_id.store(u32::MAX, Ordering::Relaxed);
        let (id_max, _rx_max) = handle.open_stream().unwrap();
        assert_eq!(id_max, u32::MAX);
        let (id_next, _rx_next) = handle.open_stream().unwrap();
        assert_eq!(id_next, 2);
        assert!(handle.streams.lock().unwrap().contains_key(&1));
    }
}
