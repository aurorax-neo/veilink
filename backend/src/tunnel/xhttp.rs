use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use bytes::Bytes;
use parking_lot::Mutex;
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::sync::mpsc;

use super::vless_enc::TaskedDuplex;
use super::{xhttp_effective_mode, BoxStream};
use crate::model::{Binding, LocalTLS, XHTTP};

const MAX_XHTTP_SESSIONS: usize = 1024;
const MAX_XHTTP_REORDER_WINDOW: usize = 64;
const MAX_XHTTP_BODY_BYTES: usize = 4 * 1024 * 1024;
const H2_STREAM_WINDOW: u32 = 4 * 1024 * 1024;
const H2_CONN_WINDOW: u32 = 16 * 1024 * 1024;
pub const DEFAULT_USER_AGENT: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36 Electron/35.1.2";

const BASE62_CHARS: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

pub fn xhttp_effective_http_version(x: &XHTTP, reality_enabled: bool) -> &'static str {
    match x.http_version.as_str() {
        "1.1" => "1.1",
        "2" => "2",
        "3" => "3",
        _ => {
            let mode = xhttp_effective_mode(x, reality_enabled);
            if mode == "packet-up" {
                "1.1"
            } else {
                "2"
            }
        }
    }
}

fn effective_uplink_method(local: &LocalTLS) -> &'static str {
    match local.xhttp.uplink_http_method.as_str() {
        "PUT" => "PUT",
        "OPTIONS" => "OPTIONS",
        _ => "POST",
    }
}

fn effective_request_timeout(local: &LocalTLS) -> Duration {
    if (5..=60).contains(&local.xhttp.request_timeout_seconds) {
        Duration::from_secs(local.xhttp.request_timeout_seconds as u64)
    } else {
        Duration::from_secs(15)
    }
}

fn downlink_content_type(local: &LocalTLS) -> Option<&'static str> {
    if local.xhttp.no_sse_header {
        None
    } else {
        Some("text/event-stream")
    }
}

fn stream_uplink_content_type(local: &LocalTLS) -> Option<&'static str> {
    if local.xhttp.no_grpc_header {
        None
    } else {
        Some("application/grpc")
    }
}

fn effective_padding_bounds(x: &XHTTP) -> (usize, usize) {
    let min_l = if x.padding_bytes > 0 {
        x.padding_bytes as usize
    } else {
        100
    };
    let max_l = if x.padding_max_bytes > 0 && (x.padding_max_bytes as usize) >= min_l {
        x.padding_max_bytes as usize
    } else if x.padding_bytes > 0 {
        min_l
    } else {
        1000
    };
    (min_l, max_l)
}

fn generate_xhttp_padding(x: &XHTTP) -> String {
    let (min_l, max_l) = effective_padding_bounds(x);
    let n = if max_l <= min_l {
        min_l
    } else {
        let mut b = [0u8; 4];
        rand::rng().fill_bytes(&mut b);
        min_l + (u32::from_be_bytes(b) as usize % (max_l - min_l + 1))
    };
    if x.padding_obfs_mode && x.padding_method == "tokenish" {
        let mut raw = vec![0u8; n];
        rand::rng().fill_bytes(&mut raw);
        raw.into_iter()
            .map(|v| BASE62_CHARS[(v as usize) % BASE62_CHARS.len()] as char)
            .collect()
    } else {
        "X".repeat(n)
    }
}

fn xhttp_meta_placement(value: &str) -> &str {
    if value.is_empty() {
        "path"
    } else {
        value
    }
}

fn xhttp_session_key(x: &XHTTP) -> &str {
    if !x.session_id_key.is_empty() {
        &x.session_id_key
    } else if xhttp_meta_placement(&x.session_id_placement) == "header" {
        "X-Veilink-Session"
    } else {
        "x_session"
    }
}

fn xhttp_seq_key(x: &XHTTP) -> &str {
    if !x.seq_key.is_empty() {
        &x.seq_key
    } else if xhttp_meta_placement(&x.seq_placement) == "header" {
        "X-Veilink-Seq"
    } else {
        "x_seq"
    }
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

fn xhttp_data_chunk_size(x: &XHTTP) -> usize {
    if x.uplink_chunk_size > 0 {
        x.uplink_chunk_size as usize
    } else if xhttp_data_placement(x) == "header" {
        4096
    } else if xhttp_data_placement(x) == "cookie" {
        3072
    } else {
        32768
    }
}

fn generate_session_id(x: &XHTTP) -> String {
    if x.session_id_table.is_empty() && x.session_id_length == 0 {
        return uuid::Uuid::new_v4().to_string();
    }
    let table: &[u8] = match x.session_id_table.as_str() {
        "base62" => BASE62_CHARS,
        "hex" => b"0123456789abcdef",
        other => other.as_bytes(),
    };
    let len = (x.session_id_length as usize).clamp(24, 64);
    let mut rnd = vec![0u8; len];
    rand::rng().fill_bytes(&mut rnd);
    rnd.into_iter()
        .map(|b| table[(b as usize) % table.len()] as char)
        .collect()
}

fn effective_upload_cap(local: &LocalTLS) -> usize {
    if xhttp_data_placement(&local.xhttp) == "body" {
        return 32768;
    }
    let hdr_limit = if local.xhttp.server_max_header_bytes > 0 {
        local.xhttp.server_max_header_bytes as isize
    } else {
        8192
    };
    let (_, max_pad) = effective_padding_bounds(&local.xhttp);
    let mut budget = hdr_limit - 2048 - max_pad as isize;
    if let Ok(entries) = local.xhttp.headers.entries() {
        for (k, v) in entries {
            budget -= (k.len() + v.len() + 36) as isize;
        }
    }
    let csize = xhttp_data_chunk_size(&local.xhttp);
    if csize == 0 || budget <= 0 {
        return 1024;
    }
    let dkey_len = xhttp_data_key(&local.xhttp).len();
    let max_p = if local.xhttp.post_bytes_max > 0 {
        local.xhttp.post_bytes_max as usize
    } else if local.xhttp.max_each_post_bytes > 0 {
        local.xhttp.max_each_post_bytes as usize
    } else {
        32768
    };
    let (mut low, mut high) = (0usize, max_p);
    while low < high {
        let n = low + (high - low + 1) / 2;
        let encoded = (n * 4).div_ceil(3);
        let chunks = encoded.div_ceil(csize);
        let cost = encoded + chunks * (dkey_len + 40);
        if chunks <= 32 && (cost as isize) <= budget {
            low = n;
        } else {
            high = n - 1;
        }
    }
    low.max(256)
}

fn sample_post_size(local: &LocalTLS) -> usize {
    let cap = effective_upload_cap(local);
    let min_b = if local.xhttp.max_each_post_bytes > 0 {
        (local.xhttp.max_each_post_bytes as usize).clamp(256, cap)
    } else {
        cap
    };
    let max_b = if local.xhttp.post_bytes_max > 0 {
        (local.xhttp.post_bytes_max as usize).clamp(min_b, cap)
    } else {
        min_b
    };
    if max_b <= min_b {
        return min_b;
    }
    let mut b = [0u8; 4];
    rand::rng().fill_bytes(&mut b);
    min_b + (u32::from_be_bytes(b) as usize % (max_b - min_b + 1))
}

fn sample_post_interval_ms(local: &LocalTLS) -> u64 {
    let min_ms = local.xhttp.min_posts_interval_ms.max(0) as u64;
    if min_ms == 0 {
        return 0;
    }
    let max_ms = if local.xhttp.max_posts_interval_ms > 0 {
        (local.xhttp.max_posts_interval_ms as u64).max(min_ms)
    } else {
        min_ms
    };
    if max_ms <= min_ms {
        return min_ms;
    }
    let mut b = [0u8; 4];
    rand::rng().fill_bytes(&mut b);
    min_ms + (u32::from_be_bytes(b) as u64 % (max_ms - min_ms + 1))
}

fn sample_stream_up_keepalive(x: &XHTTP) -> Option<Duration> {
    if x.stream_up_server_secs <= 0 {
        return None;
    }
    let min_s = x.stream_up_server_secs as u64;
    let max_s = if x.stream_up_server_max_secs >= x.stream_up_server_secs {
        x.stream_up_server_max_secs as u64
    } else {
        min_s
    };
    if max_s <= min_s {
        return Some(Duration::from_secs(min_s));
    }
    let mut b = [0u8; 4];
    rand::rng().fill_bytes(&mut b);
    Some(Duration::from_secs(
        min_s + (u32::from_be_bytes(b) as u64 % (max_s - min_s + 1)),
    ))
}

fn is_reserved_custom_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "host"
            | "connection"
            | "keep-alive"
            | "proxy-connection"
            | "transfer-encoding"
            | "upgrade"
            | "content-length"
            | "te"
            | "trailer"
    )
}

fn collect_xhttp_header_pairs(local: &LocalTLS) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    let mut has_ua = false;
    if let Ok(entries) = local.xhttp.headers.entries() {
        for (k, v) in entries {
            if is_reserved_custom_header(&k) {
                continue;
            }
            if k.eq_ignore_ascii_case("user-agent") {
                has_ua = true;
            }
            pairs.push((k, v));
        }
    }
    if !has_ua {
        pairs.insert(0, ("User-Agent".to_string(), DEFAULT_USER_AGENT.to_string()));
    }
    pairs
}

#[cfg(test)]
fn format_xhttp_headers(local: &LocalTLS) -> String {
    let mut out = String::new();
    for (k, v) in collect_xhttp_header_pairs(local) {
        out.push_str(&k);
        out.push_str(": ");
        out.push_str(&v);
        out.push_str("\r\n");
    }
    out
}

pub fn normalize_xhttp_path(raw: &str) -> String {
    let t = raw.trim();
    if t.is_empty() {
        return "/".to_string();
    }
    if t.starts_with('/') {
        t.to_string()
    } else {
        format!("/{}", t)
    }
}

fn join_xhttp_subpath(base: &str, segments: &[String]) -> String {
    if segments.is_empty() {
        return base.to_string();
    }
    let joined = segments.join("/");
    if base == "/" {
        format!("/{}", joined)
    } else if base.ends_with('/') {
        format!("{}{}", base, joined)
    } else {
        format!("{}/{}", base, joined)
    }
}

fn extract_xhttp_subpath<'a>(path_only: &'a str, base_path: &str) -> Option<&'a str> {
    let base_trimmed = base_path.trim_end_matches('/');
    if base_trimmed.is_empty() {
        return Some(path_only.trim_start_matches('/').trim_end_matches('/'));
    }
    let rest = path_only.strip_prefix(base_trimmed)?;
    if rest.is_empty() || rest == "/" {
        return Some("");
    }
    let after = rest.strip_prefix('/')?;
    Some(after.trim_end_matches('/'))
}

struct BuiltClientReqParts {
    uri_path_and_query: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

#[allow(clippy::too_many_arguments)]
fn build_client_req_parts(
    scheme: &str,
    host: &str,
    base_path: &str,
    local: &LocalTLS,
    sid: Option<&str>,
    seq: Option<u64>,
    uplink_payload: Option<&[u8]>,
    is_eof: bool,
    explicit_content_type: Option<&str>,
) -> BuiltClientReqParts {
    let x = &local.xhttp;
    let mut path_segs: Vec<String> = Vec::new();
    let mut query_pairs: Vec<(String, String)> = Vec::new();
    let mut headers = collect_xhttp_header_pairs(local);
    let mut cookies: Vec<(String, String)> = Vec::new();

    if let Some(s) = sid {
        match xhttp_meta_placement(&x.session_id_placement) {
            "query" => query_pairs.push((xhttp_session_key(x).to_string(), s.to_string())),
            "header" => headers.push((xhttp_session_key(x).to_string(), s.to_string())),
            "cookie" => cookies.push((xhttp_session_key(x).to_string(), s.to_string())),
            _ => path_segs.push(s.to_string()),
        }
    }

    if let Some(q) = seq {
        let qs = q.to_string();
        match xhttp_meta_placement(&x.seq_placement) {
            "query" => query_pairs.push((xhttp_seq_key(x).to_string(), qs)),
            "header" => headers.push((xhttp_seq_key(x).to_string(), qs)),
            "cookie" => cookies.push((xhttp_seq_key(x).to_string(), qs)),
            _ => path_segs.push(qs),
        }
    }

    if is_eof {
        headers.push(("X-Veilink-EOF".to_string(), "1".to_string()));
    }

    let mut body = Vec::new();
    let mut final_ct = explicit_content_type.map(|s| s.to_string());
    if let Some(data) = uplink_payload {
        match xhttp_data_placement(x) {
            "header" => {
                if !data.is_empty() {
                    let encoded = URL_SAFE_NO_PAD.encode(data);
                    let csize = xhttp_data_chunk_size(x);
                    let key_prefix = xhttp_data_key(x);
                    for (idx, chunk) in encoded.as_bytes().chunks(csize).enumerate() {
                        headers.push((
                            format!("{}-{}", key_prefix, idx),
                            String::from_utf8_lossy(chunk).into_owned(),
                        ));
                    }
                }
                final_ct = None;
            }
            "cookie" => {
                if !data.is_empty() {
                    let encoded = URL_SAFE_NO_PAD.encode(data);
                    let csize = xhttp_data_chunk_size(x);
                    let key_prefix = xhttp_data_key(x);
                    for (idx, chunk) in encoded.as_bytes().chunks(csize).enumerate() {
                        cookies.push((
                            format!("{}_{}", key_prefix, idx),
                            String::from_utf8_lossy(chunk).into_owned(),
                        ));
                    }
                }
                final_ct = None;
            }
            _ => {
                body.extend_from_slice(data);
            }
        }
    }

    let pad = generate_xhttp_padding(x);
    if x.padding_obfs_mode {
        match xhttp_padding_placement(x) {
            "query" => query_pairs.push((xhttp_padding_key(x).to_string(), pad.clone())),
            "header" => headers.push((xhttp_padding_header(x).to_string(), pad.clone())),
            "cookie" => cookies.push((xhttp_padding_key(x).to_string(), pad.clone())),
            _ => {}
        }
    }

    let path_str = join_xhttp_subpath(base_path, &path_segs);
    let uri_path_and_query = if query_pairs.is_empty() {
        path_str
    } else {
        let qs: Vec<String> = query_pairs
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect();
        format!("{}?{}", path_str, qs.join("&"))
    };

    // Default Xray non-obfs mode AND `query_in_header` obfs mode place `?x_padding=...` in `Referer`
    if !x.padding_obfs_mode || xhttp_padding_placement(x) == "query_in_header" {
        let hdr_name = if x.padding_obfs_mode {
            xhttp_padding_header(x)
        } else {
            "Referer"
        };
        let pkey = if x.padding_obfs_mode {
            xhttp_padding_key(x)
        } else {
            "x_padding"
        };
        let sep = if uri_path_and_query.contains('?') {
            '&'
        } else {
            '?'
        };
        let val = if hdr_name.eq_ignore_ascii_case("referer") {
            format!(
                "{}://{}{}{}{}={}",
                scheme, host, uri_path_and_query, sep, pkey, pad
            )
        } else {
            format!("?{}={}", pkey, pad)
        };
        headers.push((hdr_name.to_string(), val));
    }

    if let Some(ct) = final_ct {
        headers.push(("Content-Type".to_string(), ct));
    }

    if !cookies.is_empty() {
        let joined: Vec<String> = cookies
            .into_iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect();
        headers.push(("Cookie".to_string(), joined.join("; ")));
    }

    BuiltClientReqParts {
        uri_path_and_query,
        headers,
        body,
    }
}

fn parse_query_map(query: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        if let Some((k, v)) = pair.split_once('=') {
            map.insert(k.to_string(), v.to_string());
        }
    }
    map
}

fn parse_cookie_map(headers: &HashMap<String, String>) -> HashMap<String, String> {
    let mut out = HashMap::new();
    if let Some(raw) = headers.get("cookie") {
        for part in raw.split(';') {
            let trimmed = part.trim();
            if let Some((k, v)) = trimmed.split_once('=') {
                out.insert(k.trim().to_string(), v.trim().to_string());
            }
        }
    }
    out
}

fn server_response_padding_header(local: &LocalTLS) -> (String, String) {
    let x = &local.xhttp;
    let pad = generate_xhttp_padding(x);
    if x.padding_obfs_mode && xhttp_padding_placement(x) == "cookie" {
        (
            "set-cookie".to_string(),
            format!("{}={}; Path=/; HttpOnly", xhttp_padding_key(x), pad),
        )
    } else if x.padding_obfs_mode && xhttp_padding_placement(x) == "header" {
        (xhttp_padding_header(x).to_ascii_lowercase(), pad)
    } else {
        ("x-padding".to_string(), pad)
    }
}

fn validate_incoming_padding(
    x: &XHTTP,
    query_map: &HashMap<String, String>,
    cookies: &HashMap<String, String>,
    headers: &HashMap<String, String>,
) -> bool {
    let (min_l, max_l) = effective_padding_bounds(x);
    let check_len = |s: &str| s.len() >= min_l && s.len() <= max_l;

    let extract_query_in_hdr = |hdr_name: &str, pkey: &str| -> Option<String> {
        let hv = headers.get(&hdr_name.to_ascii_lowercase())?;
        let q = hv.split_once('?').map(|(_, q)| q).unwrap_or(hv.as_str());
        parse_query_map(q).remove(pkey)
    };

    if x.padding_obfs_mode {
        let pkey = xhttp_padding_key(x);
        match xhttp_padding_placement(x) {
            "query" => query_map.get(pkey).is_some_and(|v| check_len(v)),
            "cookie" => cookies.get(pkey).is_some_and(|v| check_len(v)),
            "header" => headers
                .get(&xhttp_padding_header(x).to_ascii_lowercase())
                .is_some_and(|v| check_len(v)),
            _ => extract_query_in_hdr(xhttp_padding_header(x), pkey)
                .is_some_and(|v| check_len(&v)),
        }
    } else {
        if let Some(v) = extract_query_in_hdr("referer", "x_padding") {
            return check_len(&v);
        }
        if let Some(v) = query_map.get("x_padding") {
            return check_len(v);
        }
        if let Some(v) = headers.get("x-padding") {
            return check_len(v);
        }
        false
    }
}

fn validate_request_host_and_headers(
    local: &LocalTLS,
    req_host: &str,
    _req_headers: &HashMap<String, String>,
) -> bool {
    let expected_host = local.xhttp.host.trim();
    if !expected_host.is_empty() {
        let clean_host = if let Some(stripped) = req_host.strip_prefix('[') {
            stripped.split(']').next().unwrap_or(req_host)
        } else {
            req_host.split(':').next().unwrap_or(req_host)
        };
        if !clean_host.eq_ignore_ascii_case(expected_host) {
            return false;
        }
    }
    true
}

enum ParsedXhttpRoute {
    StreamOne,
    DownlinkGet { sid: String },
    StreamUp { sid: String },
    PacketUp {
        sid: String,
        seq: u64,
        header_or_cookie_data: Option<Vec<u8>>,
        explicit_eof: bool,
    },
}

fn parse_xhttp_route(
    method: &str,
    raw_uri: &str,
    headers: &HashMap<String, String>,
    local: &LocalTLS,
) -> Result<ParsedXhttpRoute, u16> {
    let x = &local.xhttp;
    let (path_only, query_str) = raw_uri
        .split_once('?')
        .map(|(p, q)| (p, q))
        .unwrap_or((raw_uri, ""));
    let base_path = normalize_xhttp_path(&x.path);
    let Some(sub) = extract_xhttp_subpath(path_only, &base_path) else {
        return Err(404);
    };

    let query_map = parse_query_map(query_str);
    let cookies = parse_cookie_map(headers);
    if !validate_incoming_padding(x, &query_map, &cookies, headers) {
        return Err(400);
    }

    let mut path_parts: VecDeque<&str> = if sub.is_empty() {
        VecDeque::new()
    } else {
        sub.split('/').collect()
    };

    let eff_mode = xhttp_effective_mode(x, local.reality.enabled());
    let expected_method = effective_uplink_method(local);

    if eff_mode == "stream-one" && method == expected_method && path_parts.is_empty() {
        return Ok(ParsedXhttpRoute::StreamOne);
    }

    let sid_opt: Option<String> = match xhttp_meta_placement(&x.session_id_placement) {
        "query" => query_map.get(xhttp_session_key(x)).cloned(),
        "header" => headers
            .get(&xhttp_session_key(x).to_ascii_lowercase())
            .cloned(),
        "cookie" => cookies.get(xhttp_session_key(x)).cloned(),
        _ => path_parts.pop_front().map(|s| s.to_string()),
    };

    if method == "GET" {
        let sid = sid_opt.ok_or(400u16)?;
        if !path_parts.is_empty() || !is_valid_xhttp_sid(&sid) {
            return Err(400);
        }
        return Ok(ParsedXhttpRoute::DownlinkGet { sid });
    }

    if method != expected_method {
        return Err(400);
    }

    if sid_opt.is_none() && path_parts.is_empty() {
        return Ok(ParsedXhttpRoute::StreamOne);
    }
    let sid = sid_opt.ok_or(400u16)?;
    if !is_valid_xhttp_sid(&sid) {
        return Err(400);
    }

    let seq_raw_opt: Option<String> = match xhttp_meta_placement(&x.seq_placement) {
        "query" => query_map.get(xhttp_seq_key(x)).cloned(),
        "header" => headers.get(&xhttp_seq_key(x).to_ascii_lowercase()).cloned(),
        "cookie" => cookies.get(xhttp_seq_key(x)).cloned(),
        _ => path_parts.pop_front().map(|s| s.to_string()),
    };

    if !path_parts.is_empty() {
        return Err(400);
    }

    if let Some(seq_str) = seq_raw_opt {
        let seq = seq_str.parse::<u64>().map_err(|_| 400u16)?;
        let explicit_eof = headers
            .get("x-veilink-eof")
            .is_some_and(|v| v.trim() == "1");
        let header_or_cookie_data = match xhttp_data_placement(x) {
            "header" => {
                let prefix = xhttp_data_key(x).to_ascii_lowercase();
                let mut b64 = String::new();
                for idx in 0..32 {
                    let key = format!("{}-{}", prefix, idx);
                    if let Some(chunk) = headers.get(&key) {
                        b64.push_str(chunk.trim());
                    } else {
                        break;
                    }
                }
                let decoded = if b64.is_empty() {
                    Vec::new()
                } else {
                    URL_SAFE_NO_PAD.decode(b64.as_bytes()).map_err(|_| 400u16)?
                };
                Some(decoded)
            }
            "cookie" => {
                let prefix = xhttp_data_key(x);
                let mut b64 = String::new();
                for idx in 0..32 {
                    let key = format!("{}_{}", prefix, idx);
                    if let Some(chunk) = cookies.get(&key) {
                        b64.push_str(chunk.trim());
                    } else {
                        break;
                    }
                }
                let decoded = if b64.is_empty() {
                    Vec::new()
                } else {
                    URL_SAFE_NO_PAD.decode(b64.as_bytes()).map_err(|_| 400u16)?
                };
                Some(decoded)
            }
            _ => None,
        };
        Ok(ParsedXhttpRoute::PacketUp {
            sid,
            seq,
            header_or_cookie_data,
            explicit_eof,
        })
    } else {
        Ok(ParsedXhttpRoute::StreamUp { sid })
    }
}

pub fn is_valid_xhttp_sid(sid: &str) -> bool {
    !sid.is_empty()
        && sid.len() <= 128
        && sid
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

pub struct XhttpServerState {
    sessions: Mutex<HashMap<String, Arc<XhttpSession>>>,
    epoch: Instant,
}

struct XhttpSession {
    up_tx: mpsc::Sender<SessionPacket>,
    dn_rx: tokio::sync::Mutex<Option<tokio::io::ReadHalf<DuplexStream>>>,
    dn_taken: AtomicBool,
    up_done: AtomicBool,
    dn_done: AtomicBool,
    last_active_ms: AtomicU64,
}

enum SessionPacket {
    SeqData(u64, Vec<u8>),
    SeqEof(u64),
    StreamData(Vec<u8>),
    StreamEof,
}

impl XhttpSession {
    fn touch(&self, epoch: &Instant) {
        let ms = epoch.elapsed().as_millis() as u64;
        self.last_active_ms.store(ms, Ordering::Relaxed);
    }
}

impl XhttpServerState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            sessions: Mutex::new(HashMap::new()),
            epoch: Instant::now(),
        })
    }

    fn get_or_create_session<F>(
        self: &Arc<Self>,
        sid: &str,
        reorder_window: usize,
        on_new_stream: F,
    ) -> Option<Arc<XhttpSession>>
    where
        F: FnOnce(BoxStream),
    {
        if !is_valid_xhttp_sid(sid) {
            return None;
        }
        let reorder_cap = reorder_window.clamp(1, MAX_XHTTP_REORDER_WINDOW);
        let now_ms = self.epoch.elapsed().as_millis() as u64;
        let mut map = self.sessions.lock();
        if map.len() >= 16 {
            map.retain(|_, s| {
                if s.up_tx.is_closed() {
                    return false;
                }
                let max_idle_ms = if s.dn_taken.load(Ordering::Relaxed) {
                    120_000
                } else {
                    15_000
                };
                now_ms.saturating_sub(s.last_active_ms.load(Ordering::Relaxed)) < max_idle_ms
            });
        }
        if let Some(existing) = map.get(sid) {
            existing.touch(&self.epoch);
            return Some(existing.clone());
        }
        if map.len() >= MAX_XHTTP_SESSIONS {
            map.retain(|_, s| {
                if s.up_tx.is_closed() {
                    return false;
                }
                let max_idle_ms = if s.dn_taken.load(Ordering::Relaxed) {
                    120_000
                } else {
                    15_000
                };
                now_ms.saturating_sub(s.last_active_ms.load(Ordering::Relaxed)) < max_idle_ms
            });
            if map.len() >= MAX_XHTTP_SESSIONS {
                return None;
            }
        }

        let (server_stream, bridge_stream) = tokio::io::duplex(256 * 1024);
        let (dn_read, mut up_write) = tokio::io::split(bridge_stream);
        let (up_tx, mut up_rx) = mpsc::channel::<SessionPacket>(64);
        let state_weak = Arc::downgrade(self);
        let sid_owned = sid.to_string();
        let sess = Arc::new(XhttpSession {
            up_tx,
            dn_rx: tokio::sync::Mutex::new(Some(dn_read)),
            dn_taken: AtomicBool::new(false),
            up_done: AtomicBool::new(false),
            dn_done: AtomicBool::new(false),
            last_active_ms: AtomicU64::new(now_ms),
        });
        let sess_weak = Arc::downgrade(&sess);

        tokio::spawn(async move {
            let mut next_seq = 0u64;
            let mut pending: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
            let mut eof_seq: Option<u64> = None;
            let mut abort_session = false;
            loop {
                let pkt = match tokio::time::timeout(Duration::from_secs(15), up_rx.recv()).await {
                    Ok(Some(p)) => p,
                    Ok(None) => break,
                    Err(_) => {
                        if let (Some(st), Some(s)) = (state_weak.upgrade(), sess_weak.upgrade()) {
                            let now = st.epoch.elapsed().as_millis() as u64;
                            let max_idle_ms = if s.dn_taken.load(Ordering::Relaxed) {
                                120_000
                            } else {
                                15_000
                            };
                            if now.saturating_sub(s.last_active_ms.load(Ordering::Relaxed))
                                >= max_idle_ms
                            {
                                abort_session = true;
                                break;
                            }
                            continue;
                        } else {
                            abort_session = true;
                            break;
                        }
                    }
                };
                match pkt {
                    SessionPacket::StreamData(data) => {
                        if up_write.write_all(&data).await.is_err() {
                            abort_session = true;
                            break;
                        }
                    }
                    SessionPacket::SeqData(seq, data) => {
                        if seq < next_seq {
                            continue;
                        }
                        if seq.saturating_sub(next_seq) >= reorder_cap as u64
                            || pending.len() >= reorder_cap
                        {
                            abort_session = true;
                            break;
                        }
                        pending.insert(seq, data);
                        while let Some(chunk) = pending.remove(&next_seq) {
                            next_seq += 1;
                            if up_write.write_all(&chunk).await.is_err() {
                                abort_session = true;
                                break;
                            }
                        }
                        if abort_session {
                            break;
                        }
                        if eof_seq == Some(next_seq) {
                            let _ = up_write.shutdown().await;
                            break;
                        }
                    }
                    SessionPacket::SeqEof(at_seq) => {
                        eof_seq = Some(at_seq);
                        if eof_seq == Some(next_seq) {
                            let _ = up_write.shutdown().await;
                            break;
                        }
                    }
                    SessionPacket::StreamEof => {
                        let _ = up_write.shutdown().await;
                        break;
                    }
                }
            }
            let _ = up_write.shutdown().await;
            if let (Some(st), Some(s)) = (state_weak.upgrade(), sess_weak.upgrade()) {
                s.up_done.store(true, Ordering::SeqCst);
                let dn_taken = s.dn_taken.load(Ordering::SeqCst);
                let dn_done = s.dn_done.load(Ordering::SeqCst);
                if abort_session || !dn_taken || dn_done {
                    st.remove_session_arc(&sid_owned, &s);
                }
            }
        });

        map.insert(sid.to_string(), sess.clone());
        drop(map);

        on_new_stream(Box::new(server_stream));
        Some(sess)
    }

    fn remove_session(&self, sid: &str) {
        self.sessions.lock().remove(sid);
    }

    fn remove_session_arc(&self, sid: &str, sess: &Arc<XhttpSession>) {
        let mut map = self.sessions.lock();
        if map.get(sid).is_some_and(|cur| Arc::ptr_eq(cur, sess)) {
            map.remove(sid);
        }
    }

    fn finish_downlink(&self, sid: &str, sess: &Arc<XhttpSession>, force_abort: bool) {
        sess.dn_done.store(true, Ordering::SeqCst);
        if force_abort || sess.up_done.load(Ordering::SeqCst) {
            self.remove_session_arc(sid, sess);
        }
    }

    #[cfg(test)]
    pub fn session_count(&self) -> usize {
        self.sessions.lock().len()
    }
}

struct PrefixedStream {
    prefix: Vec<u8>,
    pos: usize,
    inner: BoxStream,
}

impl AsyncRead for PrefixedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.pos < self.prefix.len() {
            let rem = &self.prefix[self.pos..];
            let n = rem.len().min(buf.remaining());
            buf.put_slice(&rem[..n]);
            self.pos += n;
            if self.pos >= self.prefix.len() {
                self.prefix.clear();
                self.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PrefixedStream {
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

async fn h2_send_chunk(send: &mut h2::SendStream<Bytes>, mut data: &[u8]) -> io::Result<()> {
    while !data.is_empty() {
        let want = data.len().min(65536);
        send.reserve_capacity(want);
        let cap = match std::future::poll_fn(|cx| send.poll_capacity(cx)).await {
            Some(Ok(c)) if c > 0 => c.min(data.len()),
            _ => return Err(io::Error::new(io::ErrorKind::BrokenPipe, "h2 send closed")),
        };
        send.send_data(Bytes::copy_from_slice(&data[..cap]), false)
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e.to_string()))?;
        data = &data[cap..];
    }
    Ok(())
}

pub async fn handle_xhttp_server_conn<F>(
    mut conn: BoxStream,
    local: LocalTLS,
    state: Arc<XhttpServerState>,
    on_tunnel_stream: F,
) where
    F: Fn(BoxStream) + Send + Sync + 'static,
{
    let mut peek4 = [0u8; 4];
    let first_n = match tokio::time::timeout(Duration::from_secs(60), conn.read(&mut peek4)).await {
        Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return,
        Ok(Ok(n)) => n,
    };
    let mut init_buf = peek4[..first_n].to_vec();
    while init_buf.len() < 4 && b"PRI "[..init_buf.len()] == init_buf[..] {
        let mut one = [0u8; 4];
        let need = 4 - init_buf.len();
        match tokio::time::timeout(Duration::from_secs(10), conn.read(&mut one[..need])).await {
            Ok(Ok(n)) if n > 0 => init_buf.extend_from_slice(&one[..n]),
            _ => return,
        }
    }

    let on_tunnel_stream = Arc::new(on_tunnel_stream);
    let max_header_bytes = if (8192..=32768).contains(&local.xhttp.server_max_header_bytes) {
        local.xhttp.server_max_header_bytes as usize
    } else {
        8192
    };

    if init_buf.starts_with(b"PRI ") {
        let prefixed = PrefixedStream {
            prefix: init_buf,
            pos: 0,
            inner: conn,
        };
        let mut builder = h2::server::Builder::new();
        builder
            .initial_window_size(H2_STREAM_WINDOW)
            .initial_connection_window_size(H2_CONN_WINDOW)
            .max_concurrent_streams(256)
            .max_header_list_size(max_header_bytes as u32);
        let Ok(Ok(mut h2_conn)) =
            tokio::time::timeout(Duration::from_secs(15), builder.handshake(prefixed)).await
        else {
            return;
        };
        while let Some(Ok((req, respond))) = h2_conn.accept().await {
            let local_c = local.clone();
            let state_c = state.clone();
            let cb_c = on_tunnel_stream.clone();
            tokio::spawn(async move {
                handle_xhttp_h2_stream(req, respond, local_c, state_c, cb_c).await;
            });
        }
        let _ = tokio::time::timeout(
            Duration::from_secs(5),
            std::future::poll_fn(|cx| h2_conn.poll_closed(cx)),
        )
        .await;
        return;
    }

    let reorder_win = if local.xhttp.max_buffered_posts > 0 {
        local.xhttp.max_buffered_posts as usize
    } else {
        MAX_XHTTP_REORDER_WINDOW
    };
    let dn_ctype = downlink_content_type(&local);
    let (mut rd, mut wr) = tokio::io::split(conn);
    let mut read_buf: Vec<u8> = Vec::with_capacity(8192);
    read_buf.extend_from_slice(&init_buf);

    loop {
        let req = match tokio::time::timeout(
            Duration::from_secs(60),
            read_http_request_head(&mut rd, &mut read_buf, max_header_bytes),
        )
        .await
        {
            Ok(Ok(Some(r))) => r,
            _ => break,
        };

        if !validate_request_host_and_headers(&local, &req.host, &req.headers) {
            let _ = wr
                .write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
            break;
        }

        let cors_origin = req
            .headers
            .get("origin")
            .map(|s| s.as_str())
            .unwrap_or("*");

        if req.method == "OPTIONS" && req.headers.contains_key("access-control-request-method") {
            let acrm = req
                .headers
                .get("access-control-request-method")
                .map(|s| s.as_str())
                .unwrap_or("*");
            let acrh = req
                .headers
                .get("access-control-request-headers")
                .map(|s| s.as_str())
                .unwrap_or("*");
            let preflight = format!(
                "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: {}\r\nAccess-Control-Allow-Methods: {}\r\nAccess-Control-Allow-Headers: {}\r\nCache-Control: no-store\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n",
                cors_origin, acrm, acrh
            );
            if wr.write_all(preflight.as_bytes()).await.is_err() || wr.flush().await.is_err() {
                break;
            }
            continue;
        }

        let route = match parse_xhttp_route(&req.method, &req.path, &req.headers, &local) {
            Ok(r) => r,
            Err(404) => {
                let _ = wr
                    .write_all(
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await;
                break;
            }
            Err(_) => {
                let _ = wr
                    .write_all(
                        b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await;
                break;
            }
        };

        let (pad_hdr_k, pad_hdr_v) = server_response_padding_header(&local);
        let ct_line = dn_ctype
            .map(|ct| format!("Content-Type: {}\r\n", ct))
            .unwrap_or_default();

        match route {
            ParsedXhttpRoute::StreamOne => {
                let resp_hdr = format!(
                    "HTTP/1.1 200 OK\r\n{}Transfer-Encoding: chunked\r\nCache-Control: no-store\r\nAccess-Control-Allow-Origin: {}\r\nX-Accel-Buffering: no\r\n{}: {}\r\n\r\n",
                    ct_line, cors_origin, pad_hdr_k, pad_hdr_v
                );
                if wr.write_all(resp_hdr.as_bytes()).await.is_err() || wr.flush().await.is_err() {
                    break;
                }
                let stream = wrap_chunked_duplex(rd, wr, read_buf);
                on_tunnel_stream(stream);
                return;
            }
            ParsedXhttpRoute::DownlinkGet { sid } => {
                let cb = on_tunnel_stream.clone();
                let Some(sess) = state.get_or_create_session(&sid, reorder_win, move |s| cb(s))
                else {
                    let _ = wr
                        .write_all(
                            b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await;
                    break;
                };
                let mut dn_guard = sess.dn_rx.lock().await;
                let Some(mut dn_reader) = dn_guard.take() else {
                    let _ = wr
                        .write_all(b"HTTP/1.1 409 Conflict\r\nContent-Length: 0\r\n\r\n")
                        .await;
                    break;
                };
                sess.dn_taken.store(true, Ordering::SeqCst);
                drop(dn_guard);

                let resp_hdr = format!(
                    "HTTP/1.1 200 OK\r\n{}Transfer-Encoding: chunked\r\nCache-Control: no-store\r\nAccess-Control-Allow-Origin: {}\r\nX-Accel-Buffering: no\r\n{}: {}\r\n\r\n",
                    ct_line, cors_origin, pad_hdr_k, pad_hdr_v
                );
                if wr.write_all(resp_hdr.as_bytes()).await.is_err() || wr.flush().await.is_err() {
                    state.finish_downlink(&sid, &sess, true);
                    break;
                }
                let mut chunk_buf = vec![0u8; 65520];
                let mut scratch = Vec::with_capacity(65536);
                let mut dn_errored = false;
                loop {
                    match dn_reader.read(&mut chunk_buf).await {
                        Ok(0) => {
                            if wr.write_all(b"0\r\n\r\n").await.is_err() || wr.flush().await.is_err()
                            {
                                dn_errored = true;
                            }
                            break;
                        }
                        Ok(n) => {
                            sess.touch(&state.epoch);
                            if write_http_chunk(&mut wr, &chunk_buf[..n], &mut scratch)
                                .await
                                .is_err()
                            {
                                dn_errored = true;
                                break;
                            }
                        }
                        Err(_) => {
                            dn_errored = true;
                            break;
                        }
                    }
                }
                state.finish_downlink(&sid, &sess, dn_errored);
                return;
            }
            ParsedXhttpRoute::StreamUp { sid } => {
                let cb = on_tunnel_stream.clone();
                let Some(sess) = state.get_or_create_session(&sid, reorder_win, move |s| cb(s))
                else {
                    let _ = wr
                        .write_all(
                            b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await;
                    break;
                };
                // Send 200 OK immediately so HTTP/1.1 proxies and clients never stall waiting for headers.
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nCache-Control: no-store\r\nAccess-Control-Allow-Origin: {}\r\n{}: {}\r\n\r\n",
                    cors_origin, pad_hdr_k, pad_hdr_v
                );
                if wr.write_all(resp.as_bytes()).await.is_err() || wr.flush().await.is_err() {
                    break;
                }

                let mut scratch = Vec::with_capacity(2048);
                if req.chunked {
                    loop {
                        let ka_opt = sample_stream_up_keepalive(&local.xhttp);
                        tokio::select! {
                            chunk_res = read_http_chunk(&mut rd, &mut read_buf) => {
                                match chunk_res {
                                    Ok(Some(chunk)) => {
                                        sess.touch(&state.epoch);
                                        if sess.up_tx.send(SessionPacket::StreamData(chunk)).await.is_err() {
                                            break;
                                        }
                                    }
                                    _ => break,
                                }
                            }
                            _ = async {
                                match ka_opt {
                                    Some(d) => tokio::time::sleep(d).await,
                                    None => std::future::pending::<()>().await,
                                }
                            } => {
                                let ka_pad = generate_xhttp_padding(&local.xhttp);
                                if write_http_chunk(&mut wr, ka_pad.as_bytes(), &mut scratch).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                } else if req.content_length > 0 {
                    if let Ok(body) =
                        read_exact_with_buf(&mut rd, &mut read_buf, req.content_length).await
                    {
                        sess.touch(&state.epoch);
                        let _ = sess.up_tx.send(SessionPacket::StreamData(body)).await;
                    }
                }
                let _ = sess.up_tx.send(SessionPacket::StreamEof).await;
                let _ = wr.write_all(b"0\r\n\r\n").await;
                let _ = wr.flush().await;
                return;
            }
            ParsedXhttpRoute::PacketUp {
                sid,
                seq,
                header_or_cookie_data,
                explicit_eof,
            } => {
                let cb = on_tunnel_stream.clone();
                let Some(sess) = state.get_or_create_session(&sid, reorder_win, move |s| cb(s))
                else {
                    let _ = wr
                        .write_all(
                            b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await;
                    break;
                };
                let body = if req.chunked {
                    let mut all = Vec::new();
                    let mut over_limit = false;
                    while let Ok(Some(c)) = read_http_chunk(&mut rd, &mut read_buf).await {
                        if all.len().saturating_add(c.len()) > MAX_XHTTP_BODY_BYTES {
                            over_limit = true;
                            break;
                        }
                        all.extend_from_slice(&c);
                    }
                    if over_limit {
                        state.remove_session(&sid);
                        break;
                    }
                    all
                } else if req.content_length > 0 {
                    match read_exact_with_buf(&mut rd, &mut read_buf, req.content_length).await {
                        Ok(b) => b,
                        Err(_) => break,
                    }
                } else {
                    Vec::new()
                };

                let payload = header_or_cookie_data.unwrap_or(body);
                if explicit_eof || payload.is_empty() {
                    if !payload.is_empty() {
                        sess.touch(&state.epoch);
                        if sess
                            .up_tx
                            .send(SessionPacket::SeqData(seq, payload))
                            .await
                            .is_err()
                        {
                            break;
                        }
                        let _ = sess.up_tx.send(SessionPacket::SeqEof(seq + 1)).await;
                    } else {
                        let _ = sess.up_tx.send(SessionPacket::SeqEof(seq)).await;
                    }
                } else {
                    sess.touch(&state.epoch);
                    if sess
                        .up_tx
                        .send(SessionPacket::SeqData(seq, payload))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }

                let resp = format!(
                    "HTTP/1.1 200 OK\r\nCache-Control: no-store\r\nAccess-Control-Allow-Origin: {}\r\nContent-Length: 0\r\nConnection: keep-alive\r\n{}: {}\r\n\r\n",
                    cors_origin, pad_hdr_k, pad_hdr_v
                );
                if wr.write_all(resp.as_bytes()).await.is_err() || wr.flush().await.is_err() {
                    break;
                }
            }
        }
    }
}

async fn handle_xhttp_h2_stream<F>(
    req: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    local: LocalTLS,
    state: Arc<XhttpServerState>,
    on_tunnel_stream: Arc<F>,
) where
    F: Fn(BoxStream) + Send + Sync + 'static,
{
    let send_empty_status = |respond: &mut h2::server::SendResponse<Bytes>, status: u16| {
        if let Ok(r) = http::Response::builder().status(status).body(()) {
            let _ = respond.send_response(r, true);
        }
    };

    let mut hdr_map: HashMap<String, String> = HashMap::new();
    for (k, v) in req.headers() {
        if let Ok(s) = v.to_str() {
            let key = k.as_str().to_ascii_lowercase();
            if key == "cookie" {
                if let Some(prev) = hdr_map.get_mut(&key) {
                    prev.push_str("; ");
                    prev.push_str(s);
                    continue;
                }
            }
            hdr_map.insert(key, s.to_string());
        }
    }
    let req_host = req
        .uri()
        .authority()
        .map(|a| a.as_str())
        .or_else(|| hdr_map.get("host").map(|s| s.as_str()))
        .unwrap_or("");
    if !validate_request_host_and_headers(&local, req_host, &hdr_map) {
        send_empty_status(&mut respond, 404);
        return;
    }

    let cors_origin = hdr_map
        .get("origin")
        .cloned()
        .unwrap_or_else(|| "*".to_string());
    let method = req.method().as_str().to_ascii_uppercase();
    if method == "OPTIONS" && hdr_map.contains_key("access-control-request-method") {
        let acrm = hdr_map
            .get("access-control-request-method")
            .cloned()
            .unwrap_or_else(|| "*".to_string());
        let acrh = hdr_map
            .get("access-control-request-headers")
            .cloned()
            .unwrap_or_else(|| "*".to_string());
        if let Ok(resp) = http::Response::builder()
            .status(200)
            .header("access-control-allow-origin", cors_origin)
            .header("access-control-allow-methods", acrm)
            .header("access-control-allow-headers", acrh)
            .header("cache-control", "no-store")
            .body(())
        {
            let _ = respond.send_response(resp, true);
        }
        return;
    }

    let raw_uri = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());

    let route = match parse_xhttp_route(&method, &raw_uri, &hdr_map, &local) {
        Ok(r) => r,
        Err(status) => {
            send_empty_status(&mut respond, status);
            return;
        }
    };

    let reorder_win = if local.xhttp.max_buffered_posts > 0 {
        local.xhttp.max_buffered_posts as usize
    } else {
        MAX_XHTTP_REORDER_WINDOW
    };
    let dn_ctype = downlink_content_type(&local);
    let (pad_hdr_k, pad_hdr_v) = server_response_padding_header(&local);
    let mut recv_body = req.into_body();

    match route {
        ParsedXhttpRoute::StreamOne => {
            let mut b = http::Response::builder()
                .status(200)
                .header("cache-control", "no-store")
                .header("access-control-allow-origin", cors_origin)
                .header("x-accel-buffering", "no")
                .header(pad_hdr_k.as_str(), pad_hdr_v.as_str());
            if let Some(ct) = dn_ctype {
                b = b.header("content-type", ct);
            }
            let Ok(resp) = b.body(()) else { return };
            let Ok(send_body) = respond.send_response(resp, false) else {
                return;
            };
            on_tunnel_stream(wrap_h2_duplex(recv_body, send_body));
        }
        ParsedXhttpRoute::DownlinkGet { sid } => {
            let cb = on_tunnel_stream.clone();
            let Some(sess) = state.get_or_create_session(&sid, reorder_win, move |s| cb(s)) else {
                send_empty_status(&mut respond, 503);
                return;
            };
            let mut dn_guard = sess.dn_rx.lock().await;
            let Some(mut dn_reader) = dn_guard.take() else {
                send_empty_status(&mut respond, 409);
                return;
            };
            sess.dn_taken.store(true, Ordering::SeqCst);
            drop(dn_guard);

            let mut b = http::Response::builder()
                .status(200)
                .header("cache-control", "no-store")
                .header("access-control-allow-origin", cors_origin)
                .header("x-accel-buffering", "no")
                .header(pad_hdr_k.as_str(), pad_hdr_v.as_str());
            if let Some(ct) = dn_ctype {
                b = b.header("content-type", ct);
            }
            let Ok(resp) = b.body(()) else {
                state.finish_downlink(&sid, &sess, true);
                return;
            };
            let Ok(mut send_body) = respond.send_response(resp, false) else {
                state.finish_downlink(&sid, &sess, true);
                return;
            };
            let mut chunk_buf = vec![0u8; 65536];
            let mut dn_errored = false;
            loop {
                match dn_reader.read(&mut chunk_buf).await {
                    Ok(0) => {
                        if send_body.send_data(Bytes::new(), true).is_err() {
                            dn_errored = true;
                        }
                        break;
                    }
                    Ok(n) => {
                        sess.touch(&state.epoch);
                        if h2_send_chunk(&mut send_body, &chunk_buf[..n]).await.is_err() {
                            dn_errored = true;
                            break;
                        }
                    }
                    Err(_) => {
                        dn_errored = true;
                        break;
                    }
                }
            }
            state.finish_downlink(&sid, &sess, dn_errored);
        }
        ParsedXhttpRoute::StreamUp { sid } => {
            let cb = on_tunnel_stream.clone();
            let Some(sess) = state.get_or_create_session(&sid, reorder_win, move |s| cb(s)) else {
                send_empty_status(&mut respond, 503);
                return;
            };
            let mut maybe_send_body = http::Response::builder()
                .status(200)
                .header("cache-control", "no-store")
                .header("access-control-allow-origin", cors_origin)
                .header(pad_hdr_k.as_str(), pad_hdr_v.as_str())
                .body(())
                .ok()
                .and_then(|r| respond.send_response(r, false).ok());

            loop {
                let ka_opt = sample_stream_up_keepalive(&local.xhttp);
                tokio::select! {
                    chunk_opt = recv_body.data() => {
                        match chunk_opt {
                            Some(Ok(chunk)) => {
                                let _ = recv_body.flow_control().release_capacity(chunk.len());
                                if !chunk.is_empty() {
                                    sess.touch(&state.epoch);
                                    if sess
                                        .up_tx
                                        .send(SessionPacket::StreamData(chunk.to_vec()))
                                        .await
                                        .is_err()
                                    {
                                        break;
                                    }
                                }
                            }
                            _ => break,
                        }
                    }
                    _ = async {
                        match ka_opt {
                            Some(d) => tokio::time::sleep(d).await,
                            None => std::future::pending::<()>().await,
                        }
                    } => {
                        if let Some(ref mut sb) = maybe_send_body {
                            let ka = generate_xhttp_padding(&local.xhttp);
                            if h2_send_chunk(sb, ka.as_bytes()).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            }
            let _ = sess.up_tx.send(SessionPacket::StreamEof).await;
            if let Some(mut sb) = maybe_send_body {
                let _ = sb.send_data(Bytes::new(), true);
            }
        }
        ParsedXhttpRoute::PacketUp {
            sid,
            seq,
            header_or_cookie_data,
            explicit_eof,
        } => {
            let cb = on_tunnel_stream.clone();
            let Some(sess) = state.get_or_create_session(&sid, reorder_win, move |s| cb(s)) else {
                send_empty_status(&mut respond, 503);
                return;
            };
            let mut all = Vec::new();
            while let Some(Ok(chunk)) = recv_body.data().await {
                let _ = recv_body.flow_control().release_capacity(chunk.len());
                if all.len().saturating_add(chunk.len()) > MAX_XHTTP_BODY_BYTES {
                    state.remove_session(&sid);
                    send_empty_status(&mut respond, 413);
                    return;
                }
                all.extend_from_slice(&chunk);
            }
            let payload = header_or_cookie_data.unwrap_or(all);
            if explicit_eof || payload.is_empty() {
                if !payload.is_empty() {
                    sess.touch(&state.epoch);
                    if sess
                        .up_tx
                        .send(SessionPacket::SeqData(seq, payload))
                        .await
                        .is_err()
                    {
                        send_empty_status(&mut respond, 500);
                        return;
                    }
                    let _ = sess.up_tx.send(SessionPacket::SeqEof(seq + 1)).await;
                } else {
                    let _ = sess.up_tx.send(SessionPacket::SeqEof(seq)).await;
                }
            } else {
                sess.touch(&state.epoch);
                if sess
                    .up_tx
                    .send(SessionPacket::SeqData(seq, payload))
                    .await
                    .is_err()
                {
                    send_empty_status(&mut respond, 500);
                    return;
                }
            }
            if let Ok(resp) = http::Response::builder()
                .status(200)
                .header("cache-control", "no-store")
                .header("access-control-allow-origin", cors_origin)
                .header(pad_hdr_k.as_str(), pad_hdr_v.as_str())
                .body(())
            {
                let _ = respond.send_response(resp, true);
            }
        }
    }
}

async fn dial_h2_client(
    conn: BoxStream,
    timeout_dur: Duration,
) -> Result<(h2::client::SendRequest<Bytes>, Arc<AtomicBool>), String> {
    let mut builder = h2::client::Builder::new();
    builder
        .initial_window_size(H2_STREAM_WINDOW)
        .initial_connection_window_size(H2_CONN_WINDOW);
    let (sender, h2_conn) = tokio::time::timeout(timeout_dur, builder.handshake(conn))
        .await
        .map_err(|_| "xhttp h2 handshake timeout".to_string())?
        .map_err(|e| format!("xhttp h2 handshake: {}", e))?;
    let dead = Arc::new(AtomicBool::new(false));
    let dead_c = dead.clone();
    tokio::spawn(async move {
        let _ = h2_conn.await;
        dead_c.store(true, Ordering::Relaxed);
    });
    Ok((sender, dead))
}

struct PooledH2Conn {
    sender: h2::client::SendRequest<Bytes>,
    dead: Arc<AtomicBool>,
    created_at: Instant,
    requests: AtomicU64,
    active_streams: Arc<AtomicUsize>,
}

impl PooledH2Conn {
    fn is_usable(&self, local: &LocalTLS) -> bool {
        if self.dead.load(Ordering::Relaxed) {
            return false;
        }
        let m = &local.xhttp.xmux;
        if m.h_max_reusable_secs > 0
            && self.created_at.elapsed() >= Duration::from_secs(m.h_max_reusable_secs as u64)
        {
            return false;
        }
        let max_reqs = if m.h_max_request_times > 0 {
            m.h_max_request_times as u64
        } else if m.c_max_reuse_times > 0 {
            m.c_max_reuse_times as u64
        } else {
            0
        };
        if max_reqs > 0 && self.requests.load(Ordering::Relaxed) >= max_reqs {
            return false;
        }
        if m.max_concurrency > 0
            && self.active_streams.load(Ordering::Relaxed) >= m.max_concurrency as usize
        {
            return false;
        }
        true
    }
}

struct H2XmuxPool {
    conns: tokio::sync::Mutex<Vec<Arc<PooledH2Conn>>>,
}

impl H2XmuxPool {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            conns: tokio::sync::Mutex::new(Vec::new()),
        })
    }

    async fn acquire<F, Fut>(
        &self,
        addr: SocketAddr,
        local: &LocalTLS,
        binding: &Binding,
        timeout_dur: Duration,
        connect_transport: &F,
    ) -> Result<(h2::client::SendRequest<Bytes>, super::hysteria2::ActiveStreamGuard), String>
    where
        F: Fn(SocketAddr, LocalTLS, Binding) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<BoxStream, String>> + Send + 'static,
    {
        let max_conns = if local.xhttp.xmux.max_connections > 0 {
            (local.xhttp.xmux.max_connections as usize).clamp(1, 32)
        } else {
            4
        };
        let mut guard = self.conns.lock().await;
        guard.retain(|c| !c.dead.load(Ordering::Relaxed));
        for entry in guard.iter() {
            if entry.is_usable(local) {
                if let Ok(ready) = entry.sender.clone().ready().await {
                    entry.requests.fetch_add(1, Ordering::Relaxed);
                    entry.active_streams.fetch_add(1, Ordering::Relaxed);
                    return Ok((
                        ready,
                        super::hysteria2::ActiveStreamGuard(entry.active_streams.clone()),
                    ));
                }
                entry.dead.store(true, Ordering::Relaxed);
            }
        }
        guard.retain(|c| !c.dead.load(Ordering::Relaxed));

        let raw = connect_transport(addr, local.clone(), binding.clone()).await?;
        let (mut sender, dead) = dial_h2_client(raw, timeout_dur).await?;
        sender = sender.ready().await.map_err(|e| e.to_string())?;
        let active_streams = Arc::new(AtomicUsize::new(1));
        let active_guard = super::hysteria2::ActiveStreamGuard(active_streams.clone());
        let entry = Arc::new(PooledH2Conn {
            sender: sender.clone(),
            dead,
            created_at: Instant::now(),
            requests: AtomicU64::new(1),
            active_streams,
        });
        while guard.len() >= max_conns {
            guard.remove(0);
        }
        guard.push(entry);
        Ok((sender, active_guard))
    }
}

fn build_h2_request_from_parts(
    method: &str,
    scheme: &str,
    authority: &str,
    parts: &BuiltClientReqParts,
) -> Result<http::Request<()>, String> {
    let uri = format!("{}://{}{}", scheme, authority, parts.uri_path_and_query);
    let mut b = http::Request::builder().method(method).uri(&uri);
    for (k, v) in &parts.headers {
        b = b.header(k.as_str(), v.as_str());
    }
    b.body(()).map_err(|e| e.to_string())
}

fn build_h3_headers_from_parts(
    method: &str,
    authority: &str,
    parts: &BuiltClientReqParts,
) -> Vec<(String, String)> {
    let mut hdrs = Vec::with_capacity(4 + parts.headers.len());
    hdrs.push((":method".to_string(), method.to_string()));
    hdrs.push((":scheme".to_string(), "https".to_string()));
    hdrs.push((":authority".to_string(), authority.to_string()));
    hdrs.push((":path".to_string(), parts.uri_path_and_query.clone()));
    for (k, v) in &parts.headers {
        hdrs.push((k.to_ascii_lowercase(), v.clone()));
    }
    hdrs
}

async fn write_h3_hdr_pairs(
    send: &mut quinn::SendStream,
    pairs: &[(String, String)],
) -> Result<(), String> {
    let refs: Vec<(&str, &str)> = pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    super::hysteria2::write_h3_headers_frame(send, &refs).await
}

async fn send_h3_empty_status(send: &mut quinn::SendStream, status: &str) {
    let _ = super::hysteria2::write_h3_headers_frame(send, &[(":status", status)]).await;
    let _ = send.finish();
}

pub async fn handle_xhttp_h3_stream<F>(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    conn: quinn::Connection,
    local: LocalTLS,
    state: Arc<XhttpServerState>,
    on_tunnel_stream: F,
) where
    F: Fn(BoxStream) + Send + Sync + 'static,
{
    let Ok(Ok(raw_hdrs)) = tokio::time::timeout(
        Duration::from_secs(15),
        super::hysteria2::read_h3_headers_decoded(&mut recv),
    )
    .await
    else {
        return;
    };

    let mut method = String::new();
    let mut raw_path = String::from("/");
    let mut authority = String::new();
    let mut hdr_map: HashMap<String, String> = HashMap::new();
    for (k, v) in raw_hdrs {
        match k.as_str() {
            ":method" => method = v.to_ascii_uppercase(),
            ":path" => raw_path = v,
            ":authority" => authority = v,
            _ => {
                if k == "cookie" {
                    if let Some(prev) = hdr_map.get_mut("cookie") {
                        prev.push_str("; ");
                        prev.push_str(&v);
                        continue;
                    }
                }
                hdr_map.insert(k, v);
            }
        }
    }
    let req_host = if !authority.is_empty() {
        authority.as_str()
    } else {
        hdr_map.get("host").map(|s| s.as_str()).unwrap_or("")
    };

    if !validate_request_host_and_headers(&local, req_host, &hdr_map) {
        send_h3_empty_status(&mut send, "404").await;
        return;
    }

    let cors_origin = hdr_map
        .get("origin")
        .map(|s| s.as_str())
        .unwrap_or("*")
        .to_string();

    if method == "OPTIONS" && hdr_map.contains_key("access-control-request-method") {
        let acrm = hdr_map
            .get("access-control-request-method")
            .map(|s| s.as_str())
            .unwrap_or("*");
        let acrh = hdr_map
            .get("access-control-request-headers")
            .map(|s| s.as_str())
            .unwrap_or("*");
        let _ = super::hysteria2::write_h3_headers_frame(
            &mut send,
            &[
                (":status", "200"),
                ("access-control-allow-origin", &cors_origin),
                ("access-control-allow-methods", acrm),
                ("access-control-allow-headers", acrh),
                ("cache-control", "no-store"),
            ],
        )
        .await;
        let _ = send.finish();
        return;
    }

    let route = match parse_xhttp_route(&method, &raw_path, &hdr_map, &local) {
        Ok(r) => r,
        Err(status) => {
            send_h3_empty_status(&mut send, &status.to_string()).await;
            return;
        }
    };

    let reorder_win = if local.xhttp.max_buffered_posts > 0 {
        local.xhttp.max_buffered_posts as usize
    } else {
        MAX_XHTTP_REORDER_WINDOW
    };
    let dn_ctype = downlink_content_type(&local);
    let (pad_hdr_k, pad_hdr_v) = server_response_padding_header(&local);
    let on_tunnel_stream = Arc::new(on_tunnel_stream);

    let build_dn_resp_hdrs = || -> Vec<(String, String)> {
        let mut h = vec![
            (":status".to_string(), "200".to_string()),
            ("cache-control".to_string(), "no-store".to_string()),
            ("access-control-allow-origin".to_string(), cors_origin.clone()),
            ("x-accel-buffering".to_string(), "no".to_string()),
            (pad_hdr_k.clone(), pad_hdr_v.clone()),
        ];
        if let Some(ct) = dn_ctype {
            h.insert(1, ("content-type".to_string(), ct.to_string()));
        }
        h
    };

    match route {
        ParsedXhttpRoute::StreamOne => {
            let hdrs = build_dn_resp_hdrs();
            if write_h3_hdr_pairs(&mut send, &hdrs).await.is_err() {
                return;
            }
            on_tunnel_stream(Box::new(super::hysteria2::H3BodyStream::new(
                Some(send),
                recv,
                conn,
                None,
            )));
        }
        ParsedXhttpRoute::DownlinkGet { sid } => {
            let cb = on_tunnel_stream.clone();
            let Some(sess) = state.get_or_create_session(&sid, reorder_win, move |s| cb(s)) else {
                send_h3_empty_status(&mut send, "503").await;
                return;
            };
            let mut dn_guard = sess.dn_rx.lock().await;
            let Some(mut dn_reader) = dn_guard.take() else {
                send_h3_empty_status(&mut send, "409").await;
                return;
            };
            sess.dn_taken.store(true, Ordering::SeqCst);
            drop(dn_guard);

            let hdrs = build_dn_resp_hdrs();
            if write_h3_hdr_pairs(&mut send, &hdrs).await.is_err() {
                state.finish_downlink(&sid, &sess, true);
                return;
            }
            let mut chunk_buf = vec![0u8; 65520];
            let mut dn_errored = false;
            loop {
                match dn_reader.read(&mut chunk_buf).await {
                    Ok(0) => {
                        if send.finish().is_err() {
                            dn_errored = true;
                        }
                        break;
                    }
                    Ok(n) => {
                        sess.touch(&state.epoch);
                        if super::hysteria2::write_h3_data_frame(&mut send, &chunk_buf[..n])
                            .await
                            .is_err()
                        {
                            dn_errored = true;
                            break;
                        }
                    }
                    Err(_) => {
                        dn_errored = true;
                        break;
                    }
                }
            }
            state.finish_downlink(&sid, &sess, dn_errored);
        }
        ParsedXhttpRoute::StreamUp { sid } => {
            let cb = on_tunnel_stream.clone();
            let Some(sess) = state.get_or_create_session(&sid, reorder_win, move |s| cb(s)) else {
                send_h3_empty_status(&mut send, "503").await;
                return;
            };
            let _ = super::hysteria2::write_h3_headers_frame(
                &mut send,
                &[
                    (":status", "200"),
                    ("cache-control", "no-store"),
                    ("access-control-allow-origin", &cors_origin),
                    (&pad_hdr_k, &pad_hdr_v),
                ],
            )
            .await;
            loop {
                let ka_opt = sample_stream_up_keepalive(&local.xhttp);
                tokio::select! {
                    chunk_res = super::hysteria2::read_h3_data_frame(&mut recv) => {
                        match chunk_res {
                            Ok(Some(chunk)) => {
                                sess.touch(&state.epoch);
                                if sess
                                    .up_tx
                                    .send(SessionPacket::StreamData(chunk))
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                            }
                            _ => break,
                        }
                    }
                    _ = async {
                        match ka_opt {
                            Some(d) => tokio::time::sleep(d).await,
                            None => std::future::pending::<()>().await,
                        }
                    } => {
                        let ka = generate_xhttp_padding(&local.xhttp);
                        if super::hysteria2::write_h3_data_frame(&mut send, ka.as_bytes()).await.is_err() {
                            break;
                        }
                    }
                }
            }
            let _ = sess.up_tx.send(SessionPacket::StreamEof).await;
            let _ = send.finish();
        }
        ParsedXhttpRoute::PacketUp {
            sid,
            seq,
            header_or_cookie_data,
            explicit_eof,
        } => {
            let cb = on_tunnel_stream.clone();
            let Some(sess) = state.get_or_create_session(&sid, reorder_win, move |s| cb(s)) else {
                send_h3_empty_status(&mut send, "503").await;
                return;
            };
            let mut all = Vec::new();
            while let Ok(Some(chunk)) = super::hysteria2::read_h3_data_frame(&mut recv).await {
                if all.len().saturating_add(chunk.len()) > MAX_XHTTP_BODY_BYTES {
                    state.remove_session(&sid);
                    send_h3_empty_status(&mut send, "413").await;
                    return;
                }
                all.extend_from_slice(&chunk);
            }
            let payload = header_or_cookie_data.unwrap_or(all);
            if explicit_eof || payload.is_empty() {
                if !payload.is_empty() {
                    sess.touch(&state.epoch);
                    if sess
                        .up_tx
                        .send(SessionPacket::SeqData(seq, payload))
                        .await
                        .is_err()
                    {
                        send_h3_empty_status(&mut send, "500").await;
                        return;
                    }
                    let _ = sess.up_tx.send(SessionPacket::SeqEof(seq + 1)).await;
                } else {
                    let _ = sess.up_tx.send(SessionPacket::SeqEof(seq)).await;
                }
            } else {
                sess.touch(&state.epoch);
                if sess
                    .up_tx
                    .send(SessionPacket::SeqData(seq, payload))
                    .await
                    .is_err()
                {
                    send_h3_empty_status(&mut send, "500").await;
                    return;
                }
            }
            let _ = super::hysteria2::write_h3_headers_frame(
                &mut send,
                &[
                    (":status", "200"),
                    ("cache-control", "no-store"),
                    ("access-control-allow-origin", &cors_origin),
                    (&pad_hdr_k, &pad_hdr_v),
                ],
            )
            .await;
            let _ = send.finish();
        }
    }
}

fn format_h1_request_head(method: &str, host: &str, parts: &BuiltClientReqParts, extra_lines: &str) -> Vec<u8> {
    use std::io::Write as _;
    let mut out = Vec::with_capacity(512 + parts.body.len());
    let _ = write!(
        out,
        "{} {} HTTP/1.1\r\nHost: {}\r\n",
        method, parts.uri_path_and_query, host
    );
    for (k, v) in &parts.headers {
        let _ = write!(out, "{}: {}\r\n", k, v);
    }
    out.extend_from_slice(extra_lines.as_bytes());
    out.extend_from_slice(b"\r\n");
    if !parts.body.is_empty() {
        out.extend_from_slice(&parts.body);
    }
    out
}

pub async fn xhttp_client_connect<F, Fut>(
    up_addr: SocketAddr,
    local: &LocalTLS,
    dn_target: Option<(SocketAddr, LocalTLS)>,
    binding: &Binding,
    gw_addr: &str,
    connect_transport: F,
) -> Result<BoxStream, String>
where
    F: Fn(SocketAddr, LocalTLS, Binding) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<BoxStream, String>> + Send + 'static,
{
    let eff_mode = xhttp_effective_mode(&local.xhttp, local.reality.enabled());
    let eff_http_ver = xhttp_effective_http_version(&local.xhttp, local.reality.enabled());
    let req_timeout = effective_request_timeout(local);
    let up_method = effective_uplink_method(local);
    let up_base = normalize_xhttp_path(&local.xhttp.path);
    let up_host = if !local.xhttp.host.trim().is_empty() {
        local.xhttp.host.trim().to_string()
    } else if !binding.domain.trim().is_empty() {
        binding.domain.trim().to_string()
    } else {
        "localhost".to_string()
    };

    if eff_http_ver == "3" {
        return xhttp_client_connect_h3(
            up_addr,
            local,
            dn_target,
            binding,
            gw_addr,
            eff_mode,
            req_timeout,
            up_method,
            &up_base,
            &up_host,
        )
        .await;
    }

    if eff_http_ver == "2" {
        return xhttp_client_connect_h2(
            up_addr,
            local,
            dn_target,
            binding,
            connect_transport,
            eff_mode,
            req_timeout,
            up_method,
            &up_base,
            &up_host,
        )
        .await;
    }

    let scheme = if local.xhttp.tls || local.reality.enabled() {
        "https"
    } else {
        "http"
    };
    let stream_ct = stream_uplink_content_type(local);

    if eff_mode == "stream-one" {
        let conn = connect_transport(up_addr, local.clone(), binding.clone()).await?;
        let (mut rd, mut wr) = tokio::io::split(conn);
        let parts = build_client_req_parts(
            scheme,
            &up_host,
            &up_base,
            local,
            None,
            None,
            None,
            false,
            stream_ct,
        );
        let req_bytes = format_h1_request_head(
            up_method,
            &up_host,
            &parts,
            "Transfer-Encoding: chunked\r\n",
        );
        wr.write_all(&req_bytes).await.map_err(|e| e.to_string())?;
        wr.flush().await.map_err(|e| e.to_string())?;

        let mut read_buf = Vec::with_capacity(4096);
        let status =
            tokio::time::timeout(req_timeout, read_http_response_head(&mut rd, &mut read_buf))
                .await
                .map_err(|_| "xhttp stream-one response timeout".to_string())??;
        if status != 200 {
            return Err(format!("xhttp stream-one unexpected status {}", status));
        }
        return Ok(wrap_chunked_duplex(rd, wr, read_buf));
    }

    let sid = generate_session_id(&local.xhttp);
    let (dn_addr, dn_ep) = dn_target.unwrap_or_else(|| (up_addr, local.clone()));
    let dn_scheme = if dn_ep.xhttp.tls || dn_ep.reality.enabled() {
        "https"
    } else {
        "http"
    };
    let dn_base = normalize_xhttp_path(&dn_ep.xhttp.path);
    let dn_host = if !dn_ep.xhttp.host.trim().is_empty() {
        dn_ep.xhttp.host.trim().to_string()
    } else if !binding.domain.trim().is_empty() {
        binding.domain.trim().to_string()
    } else {
        "localhost".to_string()
    };

    let dn_conn = connect_transport(dn_addr, dn_ep.clone(), binding.clone()).await?;
    let (mut dn_rd, mut dn_wr) = tokio::io::split(dn_conn);
    let get_parts = build_client_req_parts(
        dn_scheme,
        &dn_host,
        &dn_base,
        &dn_ep,
        Some(&sid),
        None,
        None,
        false,
        None,
    );
    let get_bytes = format_h1_request_head("GET", &dn_host, &get_parts, "");
    dn_wr
        .write_all(&get_bytes)
        .await
        .map_err(|e| e.to_string())?;
    dn_wr.flush().await.map_err(|e| e.to_string())?;

    if eff_mode == "stream-up" {
        let up_conn = connect_transport(up_addr, local.clone(), binding.clone()).await?;
        let (mut up_rd, mut up_wr) = tokio::io::split(up_conn);
        let post_parts = build_client_req_parts(
            scheme,
            &up_host,
            &up_base,
            local,
            Some(&sid),
            None,
            None,
            false,
            stream_ct,
        );
        let post_bytes = format_h1_request_head(
            up_method,
            &up_host,
            &post_parts,
            "Transfer-Encoding: chunked\r\n",
        );
        up_wr
            .write_all(&post_bytes)
            .await
            .map_err(|e| e.to_string())?;
        up_wr.flush().await.map_err(|e| e.to_string())?;

        tokio::spawn(async move {
            let mut discard = [0u8; 4096];
            while let Ok(n) = up_rd.read(&mut discard).await {
                if n == 0 {
                    break;
                }
            }
        });

        let mut dn_buf = Vec::with_capacity(4096);
        let status =
            tokio::time::timeout(req_timeout, read_http_response_head(&mut dn_rd, &mut dn_buf))
                .await
                .map_err(|_| "xhttp stream-up GET response timeout".to_string())??;
        if status != 200 {
            return Err(format!("xhttp stream-up GET unexpected status {}", status));
        }
        return Ok(wrap_chunked_duplex_keep(dn_rd, up_wr, dn_buf, dn_wr));
    }

    let mut dn_buf = Vec::with_capacity(4096);
    let dn_status =
        tokio::time::timeout(req_timeout, read_http_response_head(&mut dn_rd, &mut dn_buf))
            .await
            .map_err(|_| "xhttp packet-up GET response timeout".to_string())??;
    if dn_status != 200 {
        return Err(format!(
            "xhttp packet-up GET unexpected status {}",
            dn_status
        ));
    }

    let connect_transport = Arc::new(connect_transport);
    let up_conn = connect_transport(up_addr, local.clone(), binding.clone()).await?;
    let (mut up_rd, mut up_wr) = tokio::io::split(up_conn);

    let (local_stream, peer_stream) = tokio::io::duplex(256 * 1024);
    let (mut peer_rd, mut peer_wr) = tokio::io::split(peer_stream);

    let max_buf_cap = effective_upload_cap(local).clamp(256, 32768);
    let max_in_flight = if local.xhttp.max_concurrent_posts > 0 {
        (local.xhttp.max_concurrent_posts as usize).clamp(1, 8)
    } else {
        8
    };
    let ep_clone = local.clone();
    let binding_clone = binding.clone();
    let connect_up = Arc::clone(&connect_transport);
    let (write_failed_tx, mut write_failed_rx) = tokio::sync::watch::channel(false);

    let write_task = tokio::spawn(async move {
        let mut seq = 0u64;
        let mut buf = vec![0u8; max_buf_cap];
        let mut up_resp_buf = Vec::with_capacity(4096);
        let mut unacked: VecDeque<(u64, Vec<u8>, bool)> = VecDeque::with_capacity(max_in_flight);
        let mut peer_eof = false;

        let build_h1_post = |pkt_seq: u64, data: &[u8], is_eof_pkt: bool| -> Vec<u8> {
            let ct = if !data.is_empty() && xhttp_data_placement(&ep_clone.xhttp) == "body" {
                Some("application/octet-stream")
            } else {
                None
            };
            let parts = build_client_req_parts(
                scheme,
                &up_host,
                &up_base,
                &ep_clone,
                Some(&sid),
                Some(pkt_seq),
                Some(data),
                is_eof_pkt,
                ct,
            );
            let extra = format!(
                "Content-Length: {}\r\nConnection: keep-alive\r\n",
                parts.body.len()
            );
            format_h1_request_head(up_method, &up_host, &parts, &extra)
        };

        loop {
            if peer_eof && unacked.is_empty() {
                break;
            }
            let chunk_target = sample_post_size(&ep_clone).min(buf.len());
            let mut need_reconnect = false;
            tokio::select! {
                read_res = peer_rd.read(&mut buf[..chunk_target]), if !peer_eof && unacked.len() < max_in_flight => {
                    match read_res {
                        Ok(0) => {
                            peer_eof = true;
                            let pkt_seq = seq;
                            seq += 1;
                            let wire = build_h1_post(pkt_seq, &[], true);
                            unacked.push_back((pkt_seq, Vec::new(), true));
                            if tokio::time::timeout(req_timeout, async {
                                up_wr.write_all(&wire).await?;
                                up_wr.flush().await
                            })
                            .await
                            .map_or(true, |r| r.is_err())
                            {
                                need_reconnect = true;
                            }
                        }
                        Ok(n) => {
                            let pkt_seq = seq;
                            seq += 1;
                            let payload = buf[..n].to_vec();
                            let wire = build_h1_post(pkt_seq, &payload, false);
                            unacked.push_back((pkt_seq, payload, false));
                            if tokio::time::timeout(req_timeout, async {
                                up_wr.write_all(&wire).await?;
                                up_wr.flush().await
                            })
                            .await
                            .map_or(true, |r| r.is_err())
                            {
                                need_reconnect = true;
                            } else {
                                let interval_ms = sample_post_interval_ms(&ep_clone);
                                if interval_ms > 0 {
                                    tokio::time::sleep(Duration::from_millis(interval_ms)).await;
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }
                resp_res = tokio::time::timeout(req_timeout, read_http_response_head(&mut up_rd, &mut up_resp_buf)), if !unacked.is_empty() => {
                    match resp_res {
                        Ok(Ok(200)) => {
                            unacked.pop_front();
                        }
                        _ => {
                            need_reconnect = true;
                        }
                    }
                }
            }

            if need_reconnect {
                if peer_eof && unacked.iter().all(|(_, _, eof)| *eof) {
                    break;
                }
                let mut reconnected = false;
                for _ in 0..3 {
                    if let Ok(new_conn) =
                        connect_up(up_addr, ep_clone.clone(), binding_clone.clone()).await
                    {
                        let (new_rd, mut new_wr) = tokio::io::split(new_conn);
                        let mut replay_ok = true;
                        for (pkt_seq, payload, is_eof_pkt) in &unacked {
                            let wire = build_h1_post(*pkt_seq, payload, *is_eof_pkt);
                            if tokio::time::timeout(req_timeout, async {
                                new_wr.write_all(&wire).await?;
                                new_wr.flush().await
                            })
                            .await
                            .map_or(true, |r| r.is_err())
                            {
                                replay_ok = false;
                                break;
                            }
                        }
                        if replay_ok {
                            up_rd = new_rd;
                            up_wr = new_wr;
                            up_resp_buf.clear();
                            reconnected = true;
                            break;
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                if !reconnected {
                    break;
                }
            }
        }
        if !peer_eof {
            let _ = write_failed_tx.send(true);
        }
        let _ = tokio::time::timeout(Duration::from_secs(2), up_wr.shutdown()).await;
    });

    let write_abort = write_task.abort_handle();
    let read_task = tokio::spawn(async move {
        let _keep_dn_wr = dn_wr;
        let mut read_errored = false;
        loop {
            tokio::select! {
                _ = write_failed_rx.changed() => {
                    if *write_failed_rx.borrow() {
                        read_errored = true;
                        break;
                    }
                }
                chunk_res = read_http_chunk(&mut dn_rd, &mut dn_buf) => {
                    match chunk_res {
                        Ok(Some(chunk)) => {
                            if peer_wr.write_all(&chunk).await.is_err() {
                                break;
                            }
                        }
                        Ok(None) => break,
                        Err(_) => {
                            read_errored = true;
                            break;
                        }
                    }
                }
            }
        }
        if read_errored {
            write_abort.abort();
        }
        let _ = peer_wr.shutdown().await;
    });

    Ok(Box::new(TaskedDuplex::new(
        local_stream,
        vec![write_task, read_task],
    )))
}

#[allow(clippy::too_many_arguments)]
async fn xhttp_client_connect_h3(
    up_addr: SocketAddr,
    local: &LocalTLS,
    dn_target: Option<(SocketAddr, LocalTLS)>,
    binding: &Binding,
    gw_addr: &str,
    eff_mode: &'static str,
    req_timeout: Duration,
    up_method: &'static str,
    up_base: &str,
    up_host: &str,
) -> Result<BoxStream, String> {
    let sni = if !gw_addr.trim().is_empty() {
        gw_addr.trim().to_string()
    } else if !binding.domain.trim().is_empty() {
        binding.domain.trim().to_string()
    } else {
        "localhost".to_string()
    };
    let stream_ct = stream_uplink_content_type(local);

    if eff_mode == "stream-one" {
        let (mut send, mut recv, conn, guard) =
            super::hysteria2::xhttp_h3_open_bi(up_addr, local, &sni).await?;
        let parts = build_client_req_parts(
            "https",
            up_host,
            up_base,
            local,
            None,
            None,
            None,
            false,
            stream_ct,
        );
        let req_hdrs = build_h3_headers_from_parts(up_method, up_host, &parts);
        write_h3_hdr_pairs(&mut send, &req_hdrs).await?;
        let resp_hdrs = tokio::time::timeout(
            req_timeout,
            super::hysteria2::read_h3_headers_decoded(&mut recv),
        )
        .await
        .map_err(|_| "xhttp h3 stream-one response timeout".to_string())??;
        let status = resp_hdrs
            .iter()
            .find(|(k, _)| k == ":status")
            .map(|(_, v)| v.as_str())
            .unwrap_or("");
        if status != "200" {
            return Err(format!("xhttp h3 stream-one unexpected status {:?}", status));
        }
        return Ok(Box::new(super::hysteria2::H3BodyStream::new(
            Some(send),
            recv,
            conn,
            Some(Box::new(guard)),
        )));
    }

    let sid = generate_session_id(&local.xhttp);
    let (dn_addr, dn_ep) = dn_target.unwrap_or_else(|| (up_addr, local.clone()));
    let dn_base = normalize_xhttp_path(&dn_ep.xhttp.path);
    let dn_host = if !dn_ep.xhttp.host.trim().is_empty() {
        dn_ep.xhttp.host.trim().to_string()
    } else if !binding.domain.trim().is_empty() {
        binding.domain.trim().to_string()
    } else {
        "localhost".to_string()
    };

    let (mut dn_send, mut dn_recv, dn_conn, dn_guard) =
        super::hysteria2::xhttp_h3_open_bi(dn_addr, &dn_ep, &sni).await?;
    let get_parts = build_client_req_parts(
        "https",
        &dn_host,
        &dn_base,
        &dn_ep,
        Some(&sid),
        None,
        None,
        false,
        None,
    );
    let get_hdrs = build_h3_headers_from_parts("GET", &dn_host, &get_parts);
    write_h3_hdr_pairs(&mut dn_send, &get_hdrs).await?;
    let _ = dn_send.finish();

    if eff_mode == "stream-up" {
        let (mut up_send, mut up_recv, up_conn, up_guard) =
            super::hysteria2::xhttp_h3_open_bi(up_addr, local, &sni).await?;
        let post_parts = build_client_req_parts(
            "https",
            up_host,
            up_base,
            local,
            Some(&sid),
            None,
            None,
            false,
            stream_ct,
        );
        let post_hdrs = build_h3_headers_from_parts(up_method, up_host, &post_parts);
        write_h3_hdr_pairs(&mut up_send, &post_hdrs).await?;
        tokio::spawn(async move {
            let _ = super::hysteria2::read_h3_headers_decoded(&mut up_recv).await;
            while let Ok(Some(_)) = super::hysteria2::read_h3_data_frame(&mut up_recv).await {}
        });

        let dn_resp_hdrs = tokio::time::timeout(
            req_timeout,
            super::hysteria2::read_h3_headers_decoded(&mut dn_recv),
        )
        .await
        .map_err(|_| "xhttp h3 stream-up GET response timeout".to_string())??;
        let status = dn_resp_hdrs
            .iter()
            .find(|(k, _)| k == ":status")
            .map(|(_, v)| v.as_str())
            .unwrap_or("");
        if status != "200" {
            return Err(format!(
                "xhttp h3 stream-up GET unexpected status {:?}",
                status
            ));
        }
        return Ok(Box::new(super::hysteria2::H3BodyStream::new(
            Some(up_send),
            dn_recv,
            dn_conn,
            Some(Box::new((up_conn, dn_guard, up_guard))),
        )));
    }

    let dn_resp_hdrs = tokio::time::timeout(
        req_timeout,
        super::hysteria2::read_h3_headers_decoded(&mut dn_recv),
    )
    .await
    .map_err(|_| "xhttp h3 packet-up GET response timeout".to_string())??;
    let status = dn_resp_hdrs
        .iter()
        .find(|(k, _)| k == ":status")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    if status != "200" {
        return Err(format!(
            "xhttp h3 packet-up GET unexpected status {:?}",
            status
        ));
    }

    let (local_stream, peer_stream) = tokio::io::duplex(256 * 1024);
    let (mut peer_rd, mut peer_wr) = tokio::io::split(peer_stream);
    let max_buf_cap = effective_upload_cap(local).clamp(256, 32768);
    let max_conc = if local.xhttp.max_concurrent_posts > 0 {
        (local.xhttp.max_concurrent_posts as usize).clamp(1, 8)
    } else {
        4
    };
    let ep_clone = local.clone();
    let up_base_owned = up_base.to_string();
    let up_host_owned = up_host.to_string();
    let (write_failed_tx, mut write_failed_rx) = tokio::sync::watch::channel(false);

    let write_task = tokio::spawn(async move {
        let mut seq = 0u64;
        let mut buf = vec![0u8; max_buf_cap];
        let sem = Arc::new(tokio::sync::Semaphore::new(max_conc));
        let mut in_flight = tokio::task::JoinSet::new();

        loop {
            let chunk_target = sample_post_size(&ep_clone).min(buf.len());
            let (payload, is_eof_pkt) = match peer_rd.read(&mut buf[..chunk_target]).await {
                Ok(0) => (Vec::new(), true),
                Ok(n) => (buf[..n].to_vec(), false),
                Err(_) => break,
            };
            let pkt_seq = seq;
            seq += 1;

            let Ok(permit) = sem.clone().acquire_owned().await else {
                break;
            };
            let ep_p = ep_clone.clone();
            let base_p = up_base_owned.clone();
            let host_p = up_host_owned.clone();
            let sid_p = sid.clone();
            let sni_p = sni.clone();
            let wf_tx = write_failed_tx.clone();

            in_flight.spawn(async move {
                let _permit = permit;
                let ct = if !payload.is_empty() && xhttp_data_placement(&ep_p.xhttp) == "body" {
                    Some("application/octet-stream")
                } else {
                    None
                };
                let mut delivered = false;
                for attempt in 0..3 {
                    if attempt > 0 {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                    let Ok((mut send, mut recv, _c, _g)) =
                        super::hysteria2::xhttp_h3_open_bi(up_addr, &ep_p, &sni_p).await
                    else {
                        continue;
                    };
                    let parts = build_client_req_parts(
                        "https",
                        &host_p,
                        &base_p,
                        &ep_p,
                        Some(&sid_p),
                        Some(pkt_seq),
                        Some(&payload),
                        is_eof_pkt,
                        ct,
                    );
                    let hdrs = build_h3_headers_from_parts(up_method, &host_p, &parts);
                    if write_h3_hdr_pairs(&mut send, &hdrs).await.is_err() {
                        continue;
                    }
                    if !parts.body.is_empty()
                        && super::hysteria2::write_h3_data_frame(&mut send, &parts.body)
                            .await
                            .is_err()
                    {
                        continue;
                    }
                    let _ = send.finish();
                    if let Ok(Ok(rh)) = tokio::time::timeout(
                        req_timeout,
                        super::hysteria2::read_h3_headers_decoded(&mut recv),
                    )
                    .await
                    {
                        if rh.iter().any(|(k, v)| k == ":status" && v == "200") {
                            delivered = true;
                            break;
                        }
                    }
                }
                if !delivered && !is_eof_pkt {
                    let _ = wf_tx.send(true);
                }
                delivered
            });

            if is_eof_pkt {
                while in_flight.join_next().await.is_some() {}
                break;
            }
            if *write_failed_tx.borrow() {
                break;
            }
            let interval_ms = sample_post_interval_ms(&ep_clone);
            if interval_ms > 0 {
                tokio::time::sleep(Duration::from_millis(interval_ms)).await;
            }
        }
    });

    let write_abort = write_task.abort_handle();
    let read_task = tokio::spawn(async move {
        let _keep_dn = (dn_conn, dn_guard);
        let mut read_errored = false;
        loop {
            tokio::select! {
                _ = write_failed_rx.changed() => {
                    if *write_failed_rx.borrow() {
                        read_errored = true;
                        break;
                    }
                }
                chunk_res = super::hysteria2::read_h3_data_frame(&mut dn_recv) => {
                    match chunk_res {
                        Ok(Some(chunk)) => {
                            if !chunk.is_empty() && peer_wr.write_all(&chunk).await.is_err() {
                                break;
                            }
                        }
                        Ok(None) => break,
                        Err(_) => {
                            read_errored = true;
                            break;
                        }
                    }
                }
            }
        }
        if read_errored {
            write_abort.abort();
        }
        let _ = peer_wr.shutdown().await;
    });

    Ok(Box::new(TaskedDuplex::new(
        local_stream,
        vec![write_task, read_task],
    )))
}

#[allow(clippy::too_many_arguments)]
async fn xhttp_client_connect_h2<F, Fut>(
    up_addr: SocketAddr,
    local: &LocalTLS,
    dn_target: Option<(SocketAddr, LocalTLS)>,
    binding: &Binding,
    connect_transport: F,
    eff_mode: &'static str,
    req_timeout: Duration,
    up_method: &'static str,
    up_base: &str,
    up_host: &str,
) -> Result<BoxStream, String>
where
    F: Fn(SocketAddr, LocalTLS, Binding) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<BoxStream, String>> + Send + 'static,
{
    let scheme = if local.xhttp.tls || local.reality.enabled() {
        "https"
    } else {
        "http"
    };
    let stream_ct = stream_uplink_content_type(local);
    let connect_transport = Arc::new(connect_transport);
    let up_pool = H2XmuxPool::new();

    if eff_mode == "stream-one" {
        let (mut h2_sender, guard) = up_pool
            .acquire(up_addr, local, binding, req_timeout, &*connect_transport)
            .await?;
        let parts = build_client_req_parts(
            scheme,
            up_host,
            up_base,
            local,
            None,
            None,
            None,
            false,
            stream_ct,
        );
        let req = build_h2_request_from_parts(up_method, scheme, up_host, &parts)?;
        let (resp_fut, send_body) = h2_sender
            .send_request(req, false)
            .map_err(|e| e.to_string())?;
        let resp = tokio::time::timeout(req_timeout, resp_fut)
            .await
            .map_err(|_| "xhttp h2 stream-one response timeout".to_string())?
            .map_err(|e| e.to_string())?;
        if resp.status().as_u16() != 200 {
            return Err(format!(
                "xhttp h2 stream-one unexpected status {}",
                resp.status()
            ));
        }
        return Ok(wrap_h2_duplex_keep(resp.into_body(), send_body, guard));
    }

    let sid = generate_session_id(&local.xhttp);
    let shared_ep = dn_target.is_none();
    let (dn_addr, dn_ep) = dn_target.unwrap_or_else(|| (up_addr, local.clone()));
    let dn_scheme = if dn_ep.xhttp.tls || dn_ep.reality.enabled() {
        "https"
    } else {
        "http"
    };
    let dn_base = normalize_xhttp_path(&dn_ep.xhttp.path);
    let dn_host = if !dn_ep.xhttp.host.trim().is_empty() {
        dn_ep.xhttp.host.trim().to_string()
    } else if !binding.domain.trim().is_empty() {
        binding.domain.trim().to_string()
    } else {
        "localhost".to_string()
    };

    let dn_pool = if shared_ep {
        up_pool.clone()
    } else {
        H2XmuxPool::new()
    };

    let (mut dn_sender, dn_guard) = dn_pool
        .acquire(dn_addr, &dn_ep, binding, req_timeout, &*connect_transport)
        .await?;
    let get_parts = build_client_req_parts(
        dn_scheme,
        &dn_host,
        &dn_base,
        &dn_ep,
        Some(&sid),
        None,
        None,
        false,
        None,
    );
    let get_req = build_h2_request_from_parts("GET", dn_scheme, &dn_host, &get_parts)?;
    let (get_resp_fut, _get_send) = dn_sender
        .send_request(get_req, true)
        .map_err(|e| e.to_string())?;

    if eff_mode == "stream-up" {
        let (mut up_sender, up_guard) = up_pool
            .acquire(up_addr, local, binding, req_timeout, &*connect_transport)
            .await?;
        let post_parts = build_client_req_parts(
            scheme,
            up_host,
            up_base,
            local,
            Some(&sid),
            None,
            None,
            false,
            stream_ct,
        );
        let post_req = build_h2_request_from_parts(up_method, scheme, up_host, &post_parts)?;
        let (up_resp_fut, up_send_body) = up_sender
            .send_request(post_req, false)
            .map_err(|e| e.to_string())?;
        tokio::spawn(async move {
            if let Ok(resp) = up_resp_fut.await {
                let mut b = resp.into_body();
                while let Some(Ok(c)) = b.data().await {
                    let _ = b.flow_control().release_capacity(c.len());
                }
            }
        });

        let get_resp = tokio::time::timeout(req_timeout, get_resp_fut)
            .await
            .map_err(|_| "xhttp h2 stream-up GET response timeout".to_string())?
            .map_err(|e| e.to_string())?;
        if get_resp.status().as_u16() != 200 {
            return Err(format!(
                "xhttp h2 stream-up GET unexpected status {}",
                get_resp.status()
            ));
        }
        return Ok(wrap_h2_duplex_keep(
            get_resp.into_body(),
            up_send_body,
            (dn_guard, up_guard, dn_pool, up_pool),
        ));
    }

    let get_resp = tokio::time::timeout(req_timeout, get_resp_fut)
        .await
        .map_err(|_| "xhttp h2 packet-up GET response timeout".to_string())?
        .map_err(|e| e.to_string())?;
    if get_resp.status().as_u16() != 200 {
        return Err(format!(
            "xhttp h2 packet-up GET unexpected status {}",
            get_resp.status()
        ));
    }
    let mut dn_recv_body = get_resp.into_body();

    let (local_stream, peer_stream) = tokio::io::duplex(256 * 1024);
    let (mut peer_rd, mut peer_wr) = tokio::io::split(peer_stream);
    let max_buf_cap = effective_upload_cap(local).clamp(256, 32768);
    let max_conc = if local.xhttp.max_concurrent_posts > 0 {
        (local.xhttp.max_concurrent_posts as usize).clamp(1, 8)
    } else {
        4
    };
    let ep_clone = local.clone();
    let binding_clone = binding.clone();
    let connect_up = Arc::clone(&connect_transport);
    let up_base_owned = up_base.to_string();
    let up_host_owned = up_host.to_string();
    let up_pool_writer = up_pool.clone();
    let (write_failed_tx, mut write_failed_rx) = tokio::sync::watch::channel(false);

    let write_task = tokio::spawn(async move {
        let mut seq = 0u64;
        let mut buf = vec![0u8; max_buf_cap];
        let sem = Arc::new(tokio::sync::Semaphore::new(max_conc));
        let mut in_flight = tokio::task::JoinSet::new();

        loop {
            let chunk_target = sample_post_size(&ep_clone).min(buf.len());
            let (payload, is_eof_pkt) = match peer_rd.read(&mut buf[..chunk_target]).await {
                Ok(0) => (Vec::new(), true),
                Ok(n) => (buf[..n].to_vec(), false),
                Err(_) => break,
            };
            let pkt_seq = seq;
            seq += 1;

            let Ok(permit) = sem.clone().acquire_owned().await else {
                break;
            };
            let ep_p = ep_clone.clone();
            let bind_p = binding_clone.clone();
            let base_p = up_base_owned.clone();
            let host_p = up_host_owned.clone();
            let sid_p = sid.clone();
            let pool_p = up_pool_writer.clone();
            let conn_fn = connect_up.clone();
            let wf_tx = write_failed_tx.clone();

            in_flight.spawn(async move {
                let _permit = permit;
                let ct = if !payload.is_empty() && xhttp_data_placement(&ep_p.xhttp) == "body" {
                    Some("application/octet-stream")
                } else {
                    None
                };
                let mut delivered = false;
                for attempt in 0..3 {
                    if attempt > 0 {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                    let Ok((mut sender, _g)) = pool_p
                        .acquire(up_addr, &ep_p, &bind_p, req_timeout, &*conn_fn)
                        .await
                    else {
                        continue;
                    };
                    let parts = build_client_req_parts(
                        scheme,
                        &host_p,
                        &base_p,
                        &ep_p,
                        Some(&sid_p),
                        Some(pkt_seq),
                        Some(&payload),
                        is_eof_pkt,
                        ct,
                    );
                    let Ok(req) = build_h2_request_from_parts(up_method, scheme, &host_p, &parts)
                    else {
                        break;
                    };
                    if parts.body.is_empty() {
                        if let Ok((rf, _)) = sender.send_request(req, true) {
                            if let Ok(Ok(r)) = tokio::time::timeout(req_timeout, rf).await {
                                if r.status().as_u16() == 200 {
                                    delivered = true;
                                    break;
                                }
                            }
                        }
                    } else if let Ok((rf, mut sb)) = sender.send_request(req, false) {
                        if h2_send_chunk(&mut sb, &parts.body).await.is_ok()
                            && sb.send_data(Bytes::new(), true).is_ok()
                        {
                            if let Ok(Ok(r)) = tokio::time::timeout(req_timeout, rf).await {
                                if r.status().as_u16() == 200 {
                                    delivered = true;
                                    break;
                                }
                            }
                        }
                    }
                }
                if !delivered && !is_eof_pkt {
                    let _ = wf_tx.send(true);
                }
                delivered
            });

            if is_eof_pkt {
                while in_flight.join_next().await.is_some() {}
                break;
            }
            if *write_failed_tx.borrow() {
                break;
            }
            let interval_ms = sample_post_interval_ms(&ep_clone);
            if interval_ms > 0 {
                tokio::time::sleep(Duration::from_millis(interval_ms)).await;
            }
        }
    });

    let write_abort = write_task.abort_handle();
    let read_task = tokio::spawn(async move {
        let _keep_dn = (dn_sender, dn_guard, dn_pool);
        let mut read_errored = false;
        loop {
            tokio::select! {
                _ = write_failed_rx.changed() => {
                    if *write_failed_rx.borrow() {
                        read_errored = true;
                        break;
                    }
                }
                chunk_res = dn_recv_body.data() => {
                    match chunk_res {
                        Some(Ok(chunk)) => {
                            let _ = dn_recv_body.flow_control().release_capacity(chunk.len());
                            if !chunk.is_empty() && peer_wr.write_all(&chunk).await.is_err() {
                                break;
                            }
                        }
                        Some(Err(_)) => {
                            read_errored = true;
                            break;
                        }
                        None => break,
                    }
                }
            }
        }
        if read_errored {
            write_abort.abort();
        }
        let _ = peer_wr.shutdown().await;
    });

    Ok(Box::new(TaskedDuplex::new(
        local_stream,
        vec![write_task, read_task],
    )))
}

fn wrap_h2_duplex(recv_body: h2::RecvStream, send_body: h2::SendStream<Bytes>) -> BoxStream {
    wrap_h2_duplex_keep(recv_body, send_body, ())
}

fn wrap_h2_duplex_keep<K>(
    mut recv_body: h2::RecvStream,
    mut send_body: h2::SendStream<Bytes>,
    keep: K,
) -> BoxStream
where
    K: Send + 'static,
{
    let keep = Arc::new(Mutex::new(keep));
    let keep_w = keep.clone();
    let (local_stream, peer_stream) = tokio::io::duplex(256 * 1024);
    let (mut peer_rd, mut peer_wr) = tokio::io::split(peer_stream);
    let (write_failed_tx, mut write_failed_rx) = tokio::sync::watch::channel(false);

    let write_task = tokio::spawn(async move {
        let _keep = keep_w;
        let mut buf = vec![0u8; 65536];
        let mut clean_eof = false;
        loop {
            match peer_rd.read(&mut buf).await {
                Ok(0) => {
                    clean_eof = true;
                    let _ = send_body.send_data(Bytes::new(), true);
                    break;
                }
                Ok(n) => {
                    if h2_send_chunk(&mut send_body, &buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        if !clean_eof {
            let _ = write_failed_tx.send(true);
            send_body.send_reset(h2::Reason::CANCEL);
        }
    });

    let write_abort = write_task.abort_handle();
    let read_task = tokio::spawn(async move {
        let _keep = keep;
        let mut read_errored = false;
        loop {
            tokio::select! {
                _ = write_failed_rx.changed() => {
                    if *write_failed_rx.borrow() {
                        read_errored = true;
                        break;
                    }
                }
                chunk_res = recv_body.data() => {
                    match chunk_res {
                        Some(Ok(chunk)) => {
                            let _ = recv_body.flow_control().release_capacity(chunk.len());
                            if !chunk.is_empty() && peer_wr.write_all(&chunk).await.is_err() {
                                break;
                            }
                        }
                        Some(Err(_)) => {
                            read_errored = true;
                            break;
                        }
                        None => break,
                    }
                }
            }
        }
        if read_errored {
            write_abort.abort();
        }
        let _ = peer_wr.shutdown().await;
    });

    Box::new(TaskedDuplex::new(local_stream, vec![write_task, read_task]))
}

fn wrap_chunked_duplex<R, W>(rd: R, wr: W, read_buf: Vec<u8>) -> BoxStream
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    wrap_chunked_duplex_keep(rd, wr, read_buf, ())
}

fn wrap_chunked_duplex_keep<R, W, K>(
    mut rd: R,
    mut wr: W,
    mut read_buf: Vec<u8>,
    keep: K,
) -> BoxStream
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
    K: Send + 'static,
{
    let keep = Arc::new(Mutex::new(keep));
    let keep_w = keep.clone();
    let (local_stream, peer_stream) = tokio::io::duplex(256 * 1024);
    let (mut peer_rd, mut peer_wr) = tokio::io::split(peer_stream);
    let (write_failed_tx, mut write_failed_rx) = tokio::sync::watch::channel(false);

    let write_task = tokio::spawn(async move {
        let _keep = keep_w;
        let mut buf = vec![0u8; 65520];
        let mut scratch = Vec::with_capacity(65536);
        let mut clean_eof = false;
        loop {
            match peer_rd.read(&mut buf).await {
                Ok(0) => {
                    clean_eof = true;
                    let _ = tokio::time::timeout(Duration::from_secs(2), async {
                        wr.write_all(b"0\r\n\r\n").await?;
                        wr.flush().await
                    })
                    .await;
                    break;
                }
                Ok(n) => {
                    if write_http_chunk(&mut wr, &buf[..n], &mut scratch)
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        if !clean_eof {
            let _ = write_failed_tx.send(true);
        }
        let _ = tokio::time::timeout(Duration::from_secs(2), wr.shutdown()).await;
    });

    let write_abort = write_task.abort_handle();
    let read_task = tokio::spawn(async move {
        let _keep = keep;
        let mut read_errored = false;
        loop {
            tokio::select! {
                _ = write_failed_rx.changed() => {
                    if *write_failed_rx.borrow() {
                        read_errored = true;
                        break;
                    }
                }
                chunk_res = read_http_chunk(&mut rd, &mut read_buf) => {
                    match chunk_res {
                        Ok(Some(chunk)) => {
                            if peer_wr.write_all(&chunk).await.is_err() {
                                break;
                            }
                        }
                        Ok(None) => break,
                        Err(_) => {
                            read_errored = true;
                            break;
                        }
                    }
                }
            }
        }
        if read_errored {
            write_abort.abort();
        }
        let _ = peer_wr.shutdown().await;
    });

    Box::new(TaskedDuplex::new(local_stream, vec![write_task, read_task]))
}

struct HttpReqHead {
    method: String,
    path: String,
    host: String,
    content_length: usize,
    chunked: bool,
    headers: HashMap<String, String>,
}

async fn read_http_request_head<R: AsyncRead + Unpin>(
    rd: &mut R,
    buf: &mut Vec<u8>,
    max_header_bytes: usize,
) -> io::Result<Option<HttpReqHead>> {
    let header_end = loop {
        if let Some(pos) = find_crlf_crlf(buf) {
            break pos;
        }
        if buf.len() > max_header_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP request header too large",
            ));
        }
        let mut tmp = [0u8; 4096];
        let n = rd.read(&mut tmp).await?;
        if n == 0 {
            if buf.is_empty() {
                return Ok(None);
            }
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Incomplete HTTP request header",
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
    };

    let head_str = String::from_utf8_lossy(&buf[..header_end]).into_owned();
    let consumed = header_end + 4;
    let rem = buf.len() - consumed;
    if rem > 0 {
        buf.copy_within(consumed.., 0);
    }
    buf.truncate(rem);
    let mut lines = head_str.split("\r\n");
    let req_line = lines.next().unwrap_or("");
    let mut parts = req_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_ascii_uppercase();
    let path = parts.next().unwrap_or("/").to_string();
    if method.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid HTTP request line",
        ));
    }

    let mut content_length = 0usize;
    let mut chunked = false;
    let mut host = String::new();
    let mut headers: HashMap<String, String> = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim().to_ascii_lowercase();
            let v = v.trim();
            if k == "host" {
                host = v.to_string();
            } else if k == "content-length" {
                let parsed = v.parse::<usize>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid Content-Length")
                })?;
                if parsed > MAX_XHTTP_BODY_BYTES {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Content-Length exceeds limit",
                    ));
                }
                content_length = parsed;
            } else if k == "transfer-encoding" && v.to_ascii_lowercase().contains("chunked") {
                chunked = true;
            }
            if k == "cookie" {
                if let Some(prev) = headers.get_mut("cookie") {
                    prev.push_str("; ");
                    prev.push_str(v);
                    continue;
                }
            }
            headers.insert(k, v.to_string());
        }
    }

    Ok(Some(HttpReqHead {
        method,
        path,
        host,
        content_length,
        chunked,
        headers,
    }))
}

async fn read_http_response_head<R: AsyncRead + Unpin>(
    rd: &mut R,
    buf: &mut Vec<u8>,
) -> Result<u16, String> {
    let header_end = loop {
        if let Some(pos) = find_crlf_crlf(buf) {
            break pos;
        }
        if buf.len() > 32 * 1024 {
            return Err("HTTP response header too large".to_string());
        }
        let mut tmp = [0u8; 4096];
        let n = rd.read(&mut tmp).await.map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("EOF reading HTTP response header".to_string());
        }
        buf.extend_from_slice(&tmp[..n]);
    };
    let head_str = String::from_utf8_lossy(&buf[..header_end]);
    let status_line = head_str.lines().next().unwrap_or("").to_string();
    drop(head_str);
    let consumed = header_end + 4;
    let rem = buf.len() - consumed;
    if rem > 0 {
        buf.copy_within(consumed.., 0);
    }
    buf.truncate(rem);
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    Ok(status)
}

async fn write_http_chunk<W: AsyncWrite + Unpin>(
    wr: &mut W,
    data: &[u8],
    scratch: &mut Vec<u8>,
) -> io::Result<()> {
    if data.is_empty() {
        return Ok(());
    }
    use std::io::Write as _;
    scratch.clear();
    let _ = write!(scratch, "{:x}\r\n", data.len());
    scratch.extend_from_slice(data);
    scratch.extend_from_slice(b"\r\n");
    wr.write_all(scratch).await?;
    wr.flush().await
}

async fn read_http_chunk<R: AsyncRead + Unpin>(
    rd: &mut R,
    buf: &mut Vec<u8>,
) -> io::Result<Option<Vec<u8>>> {
    let line_end = loop {
        if let Some(pos) = find_crlf(buf) {
            break pos;
        }
        if buf.len() > 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP chunk header line too long",
            ));
        }
        let mut tmp = [0u8; 32768];
        let n = rd.read(&mut tmp).await?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&tmp[..n]);
    };

    let size_hex = String::from_utf8_lossy(&buf[..line_end])
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_string();
    let consumed = line_end + 2;
    let rem = buf.len() - consumed;
    if rem > 0 {
        buf.copy_within(consumed.., 0);
    }
    buf.truncate(rem);
    let chunk_size = usize::from_str_radix(&size_hex, 16)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid chunk size"))?;

    if chunk_size == 0 {
        let _ = read_exact_with_buf(rd, buf, 2).await;
        return Ok(None);
    }
    if chunk_size > MAX_XHTTP_BODY_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "chunk size too large",
        ));
    }
    let mut data = read_exact_with_buf(rd, buf, chunk_size + 2).await?;
    data.truncate(chunk_size);
    Ok(Some(data))
}

async fn read_exact_with_buf<R: AsyncRead + Unpin>(
    rd: &mut R,
    buf: &mut Vec<u8>,
    n: usize,
) -> io::Result<Vec<u8>> {
    if buf.len() < n && n <= MAX_XHTTP_BODY_BYTES {
        buf.reserve(n - buf.len());
    }
    let mut tmp = [0u8; 16384];
    while buf.len() < n {
        let got = rd.read(&mut tmp).await?;
        if got == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unexpected EOF in HTTP body",
            ));
        }
        buf.extend_from_slice(&tmp[..got]);
    }
    if buf.len() == n && buf.capacity() <= 256 * 1024 {
        return Ok(std::mem::take(buf));
    }
    let out = buf[..n].to_vec();
    let rem = buf.len() - n;
    if rem > 0 {
        buf.copy_within(n.., 0);
    }
    buf.truncate(rem);
    if buf.capacity() > 256 * 1024 && buf.len() < 16384 {
        buf.shrink_to(65536);
    }
    Ok(out)
}

fn find_crlf_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::XHTTPHeaders;

    #[test]
    fn format_xhttp_headers_uses_default_user_agent_and_respects_override() {
        let mut local = LocalTLS::default();
        let default_hdrs = format_xhttp_headers(&local);
        assert_eq!(
            default_hdrs,
            format!("User-Agent: {}\r\n", DEFAULT_USER_AGENT)
        );
        assert!(!default_hdrs.contains("veilink/1.0"));

        local.xhttp.headers = XHTTPHeaders::parse_raw(
            br#"{"User-Agent":"CustomClient/2.0","X-Custom-Route":"east"}"#,
        )
        .expect("valid custom headers");
        let custom_hdrs = format_xhttp_headers(&local);
        assert_eq!(
            custom_hdrs,
            "User-Agent: CustomClient/2.0\r\nX-Custom-Route: east\r\n"
        );
    }

    #[test]
    fn xhttp_referer_padding_and_obfs_placements_roundtrip() {
        // 1. Default non-obfs mode places x_padding in Referer query and preserves trailing `/`
        let mut local = LocalTLS::default();
        local.xhttp.path = "/veilink/".to_string();
        local.xhttp.mode = "stream-one".to_string();
        let parts = build_client_req_parts(
            "https",
            "cdn.example.com",
            &normalize_xhttp_path(&local.xhttp.path),
            &local,
            None,
            None,
            None,
            false,
            Some("application/grpc"),
        );
        assert_eq!(parts.uri_path_and_query, "/veilink/");
        let mut hmap = HashMap::new();
        for (k, v) in &parts.headers {
            hmap.insert(k.to_ascii_lowercase(), v.clone());
        }
        let referer = hmap.get("referer").expect("Referer header must carry x_padding");
        assert!(referer.starts_with("https://cdn.example.com/veilink/?x_padding=X"));
        assert!(!hmap.contains_key("x-padding"));
        assert!(matches!(
            parse_xhttp_route("POST", &parts.uri_path_and_query, &hmap, &local),
            Ok(ParsedXhttpRoute::StreamOne)
        ));

        // 2. Obfs mode with cookie session_id, header seq, tokenish query padding, and cookie uplink data
        local.xhttp.mode = "packet-up".to_string();
        local.xhttp.session_id_placement = "cookie".to_string();
        local.xhttp.session_id_key = "x_sid".to_string();
        local.xhttp.session_id_table = "base62".to_string();
        local.xhttp.session_id_length = 32;
        local.xhttp.seq_placement = "header".to_string();
        local.xhttp.seq_key = "X-Veilink-Seq".to_string();
        local.xhttp.uplink_data_placement = "cookie".to_string();
        local.xhttp.uplink_data_key = "x_payload".to_string();
        local.xhttp.uplink_chunk_size = 64;
        local.xhttp.padding_obfs_mode = true;
        local.xhttp.padding_placement = "query".to_string();
        local.xhttp.padding_key = "p_tok".to_string();
        local.xhttp.padding_method = "tokenish".to_string();
        local.xhttp.padding_bytes = 120;
        local.xhttp.padding_max_bytes = 180;

        let sid = generate_session_id(&local.xhttp);
        assert_eq!(sid.len(), 32);
        let raw_payload = b"hello xhttp cookie chunked uplink payload 0123456789abcdef!";
        let obfs_parts = build_client_req_parts(
            "https",
            "cdn.example.com",
            &normalize_xhttp_path(&local.xhttp.path),
            &local,
            Some(&sid),
            Some(7),
            Some(raw_payload),
            false,
            None,
        );
        assert!(obfs_parts.body.is_empty());
        assert!(obfs_parts.uri_path_and_query.starts_with("/veilink/?p_tok="));
        let mut obfs_hmap = HashMap::new();
        for (k, v) in &obfs_parts.headers {
            obfs_hmap.insert(k.to_ascii_lowercase(), v.clone());
        }
        match parse_xhttp_route("POST", &obfs_parts.uri_path_and_query, &obfs_hmap, &local) {
            Ok(ParsedXhttpRoute::PacketUp {
                sid: got_sid,
                seq: got_seq,
                header_or_cookie_data: Some(got_data),
                explicit_eof,
            }) => {
                assert_eq!(got_sid, sid);
                assert_eq!(got_seq, 7);
                assert_eq!(got_data, raw_payload);
                assert!(!explicit_eof);
            }
            other => panic!("unexpected route parse result: {:?}", other.err()),
        }
    }
}
