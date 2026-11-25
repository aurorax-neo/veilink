use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

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

fn downlink_content_type(local: &LocalTLS) -> &'static str {
    if local.xhttp.no_sse_header {
        "application/octet-stream"
    } else {
        "text/event-stream"
    }
}

fn stream_uplink_content_type(local: &LocalTLS) -> &'static str {
    if local.xhttp.no_grpc_header {
        "application/octet-stream"
    } else {
        "application/grpc"
    }
}

fn sample_post_size(local: &LocalTLS) -> usize {
    let min_b = if local.xhttp.max_each_post_bytes > 0 {
        (local.xhttp.max_each_post_bytes as usize).clamp(1024, 32768)
    } else {
        32768
    };
    let max_b = if local.xhttp.post_bytes_max > 0 {
        (local.xhttp.post_bytes_max as usize).clamp(min_b, 32768)
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

fn format_xhttp_headers(local: &LocalTLS) -> String {
    let mut out = String::new();
    let mut has_ua = false;
    if let Ok(entries) = local.xhttp.headers.entries() {
        for (k, v) in entries {
            if k.eq_ignore_ascii_case("user-agent") {
                has_ua = true;
            }
            out.push_str(&k);
            out.push_str(": ");
            out.push_str(&v);
            out.push_str("\r\n");
        }
    }
    if !has_ua {
        out.insert_str(0, &format!("User-Agent: {}\r\n", DEFAULT_USER_AGENT));
    }
    out
}

fn collect_xhttp_header_pairs(local: &LocalTLS) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    let mut has_ua = false;
    if let Ok(entries) = local.xhttp.headers.entries() {
        for (k, v) in entries {
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
    last_active_ms: AtomicU64,
}

enum SessionPacket {
    SeqData(u64, Vec<u8>),
    StreamData(Vec<u8>),
    Eof,
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
            last_active_ms: AtomicU64::new(now_ms),
        });
        let sess_weak = Arc::downgrade(&sess);

        tokio::spawn(async move {
            let mut next_seq = 0u64;
            let mut pending: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
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
                    }
                    SessionPacket::Eof => {
                        let _ = up_write.shutdown().await;
                        break;
                    }
                }
            }
            let _ = up_write.shutdown().await;
            let dn_taken = sess_weak
                .upgrade()
                .map(|s| s.dn_taken.load(Ordering::Relaxed))
                .unwrap_or(false);
            if abort_session || !dn_taken {
                if let Some(st) = state_weak.upgrade() {
                    st.remove_session(&sid_owned);
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

    #[cfg(test)]
    pub fn session_count(&self) -> usize {
        self.sessions.lock().len()
    }
}

pub fn normalize_xhttp_path(raw: &str) -> String {
    let t = raw.trim();
    if t.is_empty() {
        return "/".to_string();
    }
    let with_slash = if t.starts_with('/') {
        t.to_string()
    } else {
        format!("/{}", t)
    };
    if with_slash.len() > 1 {
        with_slash.trim_end_matches('/').to_string()
    } else {
        with_slash
    }
}

fn random_xhttp_padding(min_len: i64, max_len: i64) -> String {
    let min_l = if min_len > 0 { min_len as usize } else { 100 };
    let max_l = if max_len > 0 && (max_len as usize) >= min_l {
        max_len as usize
    } else {
        min_l
    };
    if max_l <= min_l {
        return "X".repeat(min_l);
    }
    let span = max_l - min_l + 1;
    let mut b = [0u8; 2];
    rand::rng().fill_bytes(&mut b);
    let n = min_l + (u16::from_be_bytes(b) as usize % span);
    "X".repeat(n)
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

    let base_path = normalize_xhttp_path(&local.xhttp.path);
    let expected_method = effective_uplink_method(&local);
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
            let origin = req
                .headers
                .get("origin")
                .map(|s| s.as_str())
                .unwrap_or("*");
            let preflight = format!(
                "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: {}\r\nAccess-Control-Allow-Methods: {}\r\nAccess-Control-Allow-Headers: {}\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n",
                origin, acrm, acrh
            );
            if wr.write_all(preflight.as_bytes()).await.is_err() || wr.flush().await.is_err() {
                break;
            }
            continue;
        }

        let path_only = req.path.split('?').next().unwrap_or(&req.path);
        let sub = if base_path == "/" {
            path_only.trim_start_matches('/')
        } else if let Some(rest) = path_only.strip_prefix(&base_path) {
            if !rest.is_empty() && !rest.starts_with('/') {
                let _ = wr
                    .write_all(
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await;
                break;
            }
            rest.trim_start_matches('/')
        } else {
            let _ = wr
                .write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
            break;
        };
        let sub = sub.trim_end_matches('/');
        let pad = random_xhttp_padding(local.xhttp.padding_bytes, local.xhttp.padding_max_bytes);

        if req.method == expected_method && sub.is_empty() {
            // stream-one: full-duplex chunked request & response
            let resp_hdr = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nTransfer-Encoding: chunked\r\nCache-Control: no-store\r\nX-Accel-Buffering: no\r\nX-Padding: {}\r\n\r\n",
                dn_ctype, pad
            );
            if wr.write_all(resp_hdr.as_bytes()).await.is_err() {
                break;
            }
            if wr.flush().await.is_err() {
                break;
            }
            let stream = wrap_chunked_duplex(rd, wr, read_buf);
            on_tunnel_stream(stream);
            return;
        } else if req.method == "GET" && !sub.is_empty() && !sub.contains('/') {
            // stream-up or packet-up downlink GET
            let sid = sub.to_string();
            if !is_valid_xhttp_sid(&sid) {
                let _ = wr
                    .write_all(
                        b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await;
                break;
            }
            let cb = on_tunnel_stream.clone();
            let Some(sess) = state.get_or_create_session(&sid, reorder_win, move |s| cb(s)) else {
                let _ = wr
                    .write_all(
                        b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await;
                break;
            };
            let mut dn_guard = sess.dn_rx.lock().await;
            let mut dn_reader = match dn_guard.take() {
                Some(r) => r,
                None => {
                    let _ = wr
                        .write_all(b"HTTP/1.1 409 Conflict\r\nContent-Length: 0\r\n\r\n")
                        .await;
                    break;
                }
            };
            sess.dn_taken.store(true, Ordering::Relaxed);
            drop(dn_guard);

            let resp_hdr = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nTransfer-Encoding: chunked\r\nCache-Control: no-store\r\nX-Accel-Buffering: no\r\nX-Padding: {}\r\n\r\n",
                dn_ctype, pad
            );
            if wr.write_all(resp_hdr.as_bytes()).await.is_err() {
                state.remove_session(&sid);
                break;
            }
            if wr.flush().await.is_err() {
                state.remove_session(&sid);
                break;
            }
            let mut chunk_buf = vec![0u8; 65520];
            let mut scratch = Vec::with_capacity(65536);
            loop {
                match dn_reader.read(&mut chunk_buf).await {
                    Ok(0) => {
                        let _ = wr.write_all(b"0\r\n\r\n").await;
                        let _ = wr.flush().await;
                        break;
                    }
                    Ok(n) => {
                        sess.touch(&state.epoch);
                        if write_http_chunk(&mut wr, &chunk_buf[..n], &mut scratch)
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            state.remove_session(&sid);
            return;
        } else if req.method == expected_method && !sub.is_empty() && !sub.contains('/') {
            // stream-up uplink POST/PUT/OPTIONS (chunked or content-length stream)
            let sid = sub.to_string();
            if !is_valid_xhttp_sid(&sid) {
                let _ = wr
                    .write_all(
                        b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await;
                break;
            }
            let cb = on_tunnel_stream.clone();
            let Some(sess) = state.get_or_create_session(&sid, reorder_win, move |s| cb(s)) else {
                let _ = wr
                    .write_all(
                        b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await;
                break;
            };
            if req.chunked {
                while let Ok(Some(chunk)) = read_http_chunk(&mut rd, &mut read_buf).await {
                    sess.touch(&state.epoch);
                    if sess.up_tx.send(SessionPacket::StreamData(chunk)).await.is_err() {
                        break;
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
            let _ = sess.up_tx.send(SessionPacket::Eof).await;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Padding: {}\r\n\r\n",
                pad
            );
            let _ = wr.write_all(resp.as_bytes()).await;
            let _ = wr.flush().await;
            return;
        } else if req.method == expected_method && sub.contains('/') {
            // packet-up POST/PUT/OPTIONS /<base>/<sid>/<seq>
            let mut parts = sub.splitn(2, '/');
            let sid = parts.next().unwrap_or("");
            let seq_str = parts.next().unwrap_or("");
            if !is_valid_xhttp_sid(sid) {
                let _ = wr
                    .write_all(
                        b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await;
                break;
            }
            let seq: u64 = match seq_str.parse() {
                Ok(s) => s,
                Err(_) => {
                    let _ = wr
                        .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                        .await;
                    break;
                }
            };
            let cb = on_tunnel_stream.clone();
            let Some(sess) = state.get_or_create_session(sid, reorder_win, move |s| cb(s)) else {
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
                    state.remove_session(sid);
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

            if body.is_empty() {
                let _ = sess.up_tx.send(SessionPacket::Eof).await;
            } else {
                sess.touch(&state.epoch);
                if sess.up_tx.send(SessionPacket::SeqData(seq, body)).await.is_err() {
                    break;
                }
            }

            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\nX-Padding: {}\r\n\r\n",
                pad
            );
            if wr.write_all(resp.as_bytes()).await.is_err() {
                break;
            }
            if wr.flush().await.is_err() {
                break;
            }
        } else {
            let _ = wr
                .write_all(
                    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
            break;
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

    let mut hdr_map = HashMap::new();
    for (k, v) in req.headers() {
        if let Ok(s) = v.to_str() {
            hdr_map.insert(k.as_str().to_ascii_lowercase(), s.to_string());
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
        let origin = hdr_map
            .get("origin")
            .cloned()
            .unwrap_or_else(|| "*".to_string());
        if let Ok(resp) = http::Response::builder()
            .status(200)
            .header("access-control-allow-origin", origin)
            .header("access-control-allow-methods", acrm)
            .header("access-control-allow-headers", acrh)
            .body(())
        {
            let _ = respond.send_response(resp, true);
        }
        return;
    }

    let base_path = normalize_xhttp_path(&local.xhttp.path);
    let expected_method = effective_uplink_method(&local);
    let reorder_win = if local.xhttp.max_buffered_posts > 0 {
        local.xhttp.max_buffered_posts as usize
    } else {
        MAX_XHTTP_REORDER_WINDOW
    };
    let dn_ctype = downlink_content_type(&local);
    let path_only = req.uri().path();
    let sub = if base_path == "/" {
        path_only.trim_start_matches('/')
    } else if let Some(rest) = path_only.strip_prefix(&base_path) {
        if !rest.is_empty() && !rest.starts_with('/') {
            send_empty_status(&mut respond, 404);
            return;
        }
        rest.trim_start_matches('/')
    } else {
        send_empty_status(&mut respond, 404);
        return;
    };
    let sub = sub.trim_end_matches('/').to_string();
    let pad = random_xhttp_padding(local.xhttp.padding_bytes, local.xhttp.padding_max_bytes);
    let mut recv_body = req.into_body();

    if method == expected_method && sub.is_empty() {
        // stream-one over HTTP/2
        let Ok(resp) = http::Response::builder()
            .status(200)
            .header("content-type", dn_ctype)
            .header("cache-control", "no-store")
            .header("x-accel-buffering", "no")
            .header("x-padding", pad)
            .body(())
        else {
            return;
        };
        let Ok(send_body) = respond.send_response(resp, false) else {
            return;
        };
        let stream = wrap_h2_duplex(recv_body, send_body);
        on_tunnel_stream(stream);
    } else if method == "GET" && !sub.is_empty() && !sub.contains('/') {
        // downlink GET over HTTP/2
        if !is_valid_xhttp_sid(&sub) {
            send_empty_status(&mut respond, 400);
            return;
        }
        let cb = on_tunnel_stream.clone();
        let Some(sess) = state.get_or_create_session(&sub, reorder_win, move |s| cb(s)) else {
            send_empty_status(&mut respond, 503);
            return;
        };
        let mut dn_guard = sess.dn_rx.lock().await;
        let Some(mut dn_reader) = dn_guard.take() else {
            send_empty_status(&mut respond, 409);
            return;
        };
        sess.dn_taken.store(true, Ordering::Relaxed);
        drop(dn_guard);

        let Ok(resp) = http::Response::builder()
            .status(200)
            .header("content-type", dn_ctype)
            .header("cache-control", "no-store")
            .header("x-accel-buffering", "no")
            .header("x-padding", pad)
            .body(())
        else {
            state.remove_session(&sub);
            return;
        };
        let Ok(mut send_body) = respond.send_response(resp, false) else {
            state.remove_session(&sub);
            return;
        };
        let mut chunk_buf = vec![0u8; 65536];
        loop {
            match dn_reader.read(&mut chunk_buf).await {
                Ok(0) => {
                    let _ = send_body.send_data(Bytes::new(), true);
                    break;
                }
                Ok(n) => {
                    sess.touch(&state.epoch);
                    if h2_send_chunk(&mut send_body, &chunk_buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        state.remove_session(&sub);
    } else if method == expected_method && !sub.is_empty() && !sub.contains('/') {
        // stream-up uplink over HTTP/2
        if !is_valid_xhttp_sid(&sub) {
            send_empty_status(&mut respond, 400);
            return;
        }
        let cb = on_tunnel_stream.clone();
        let Some(sess) = state.get_or_create_session(&sub, reorder_win, move |s| cb(s)) else {
            send_empty_status(&mut respond, 503);
            return;
        };
        // Immediately send 200 OK headers so reverse proxies & client stream cleanly
        let maybe_send_body = http::Response::builder()
            .status(200)
            .header("cache-control", "no-store")
            .header("x-padding", pad)
            .body(())
            .ok()
            .and_then(|r| respond.send_response(r, false).ok());

        while let Some(Ok(chunk)) = recv_body.data().await {
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
        let _ = sess.up_tx.send(SessionPacket::Eof).await;
        if let Some(mut sb) = maybe_send_body {
            let _ = sb.send_data(Bytes::new(), true);
        }
    } else if method == expected_method && sub.contains('/') {
        // packet-up over HTTP/2
        let mut parts = sub.splitn(2, '/');
        let sid = parts.next().unwrap_or("");
        let seq_str = parts.next().unwrap_or("");
        if !is_valid_xhttp_sid(sid) {
            send_empty_status(&mut respond, 400);
            return;
        }
        let Ok(seq) = seq_str.parse::<u64>() else {
            send_empty_status(&mut respond, 400);
            return;
        };
        let cb = on_tunnel_stream.clone();
        let Some(sess) = state.get_or_create_session(sid, reorder_win, move |s| cb(s)) else {
            send_empty_status(&mut respond, 503);
            return;
        };
        let mut all = Vec::new();
        while let Some(Ok(chunk)) = recv_body.data().await {
            let _ = recv_body.flow_control().release_capacity(chunk.len());
            if all.len().saturating_add(chunk.len()) > MAX_XHTTP_BODY_BYTES {
                state.remove_session(sid);
                send_empty_status(&mut respond, 413);
                return;
            }
            all.extend_from_slice(&chunk);
        }
        if all.is_empty() {
            let _ = sess.up_tx.send(SessionPacket::Eof).await;
        } else {
            sess.touch(&state.epoch);
            if sess.up_tx.send(SessionPacket::SeqData(seq, all)).await.is_err() {
                send_empty_status(&mut respond, 500);
                return;
            }
        }
        if let Ok(resp) = http::Response::builder()
            .status(200)
            .header("x-padding", pad)
            .body(())
        {
            let _ = respond.send_response(resp, true);
        }
    } else {
        send_empty_status(&mut respond, 400);
    }
}

async fn dial_h2_client(
    conn: BoxStream,
    timeout_dur: Duration,
) -> Result<h2::client::SendRequest<Bytes>, String> {
    let mut builder = h2::client::Builder::new();
    builder
        .initial_window_size(H2_STREAM_WINDOW)
        .initial_connection_window_size(H2_CONN_WINDOW);
    let (sender, h2_conn) = tokio::time::timeout(timeout_dur, builder.handshake(conn))
        .await
        .map_err(|_| "xhttp h2 handshake timeout".to_string())?
        .map_err(|e| format!("xhttp h2 handshake: {}", e))?;
    tokio::spawn(async move {
        let _ = h2_conn.await;
    });
    Ok(sender)
}

fn build_h2_request(
    method: &str,
    scheme: &str,
    authority: &str,
    path: &str,
    local: &LocalTLS,
    content_type: Option<&str>,
) -> Result<http::Request<()>, String> {
    let uri = format!("{}://{}{}", scheme, authority, path);
    let pad = random_xhttp_padding(local.xhttp.padding_bytes, local.xhttp.padding_max_bytes);
    let mut b = http::Request::builder()
        .method(method)
        .uri(&uri)
        .header("x-padding", pad);
    if let Some(ct) = content_type {
        b = b.header("content-type", ct);
    }
    for (k, v) in collect_xhttp_header_pairs(local) {
        b = b.header(k.as_str(), v.as_str());
    }
    b.body(()).map_err(|e| e.to_string())
}

fn build_h3_request_headers(
    method: &str,
    authority: &str,
    path: &str,
    local: &LocalTLS,
    content_type: Option<&str>,
) -> Vec<(String, String)> {
    let pad = random_xhttp_padding(local.xhttp.padding_bytes, local.xhttp.padding_max_bytes);
    let mut hdrs = Vec::with_capacity(8);
    hdrs.push((":method".to_string(), method.to_string()));
    hdrs.push((":scheme".to_string(), "https".to_string()));
    hdrs.push((":authority".to_string(), authority.to_string()));
    hdrs.push((":path".to_string(), path.to_string()));
    hdrs.push(("x-padding".to_string(), pad));
    if let Some(ct) = content_type {
        hdrs.push(("content-type".to_string(), ct.to_string()));
    }
    for (k, v) in collect_xhttp_header_pairs(local) {
        hdrs.push((k.to_ascii_lowercase(), v));
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
    let mut hdr_map = HashMap::new();
    for (k, v) in raw_hdrs {
        match k.as_str() {
            ":method" => method = v.to_ascii_uppercase(),
            ":path" => raw_path = v,
            ":authority" => authority = v,
            _ => {
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

    if method == "OPTIONS" && hdr_map.contains_key("access-control-request-method") {
        let acrm = hdr_map
            .get("access-control-request-method")
            .map(|s| s.as_str())
            .unwrap_or("*");
        let acrh = hdr_map
            .get("access-control-request-headers")
            .map(|s| s.as_str())
            .unwrap_or("*");
        let origin = hdr_map.get("origin").map(|s| s.as_str()).unwrap_or("*");
        let _ = super::hysteria2::write_h3_headers_frame(
            &mut send,
            &[
                (":status", "200"),
                ("access-control-allow-origin", origin),
                ("access-control-allow-methods", acrm),
                ("access-control-allow-headers", acrh),
            ],
        )
        .await;
        let _ = send.finish();
        return;
    }

    let base_path = normalize_xhttp_path(&local.xhttp.path);
    let expected_method = effective_uplink_method(&local);
    let reorder_win = if local.xhttp.max_buffered_posts > 0 {
        local.xhttp.max_buffered_posts as usize
    } else {
        MAX_XHTTP_REORDER_WINDOW
    };
    let dn_ctype = downlink_content_type(&local);
    let path_only = raw_path.split('?').next().unwrap_or(&raw_path);
    let sub = if base_path == "/" {
        path_only.trim_start_matches('/')
    } else if let Some(rest) = path_only.strip_prefix(&base_path) {
        if !rest.is_empty() && !rest.starts_with('/') {
            send_h3_empty_status(&mut send, "404").await;
            return;
        }
        rest.trim_start_matches('/')
    } else {
        send_h3_empty_status(&mut send, "404").await;
        return;
    };
    let sub = sub.trim_end_matches('/').to_string();
    let pad = random_xhttp_padding(local.xhttp.padding_bytes, local.xhttp.padding_max_bytes);
    let on_tunnel_stream = Arc::new(on_tunnel_stream);

    if method == expected_method && sub.is_empty() {
        if super::hysteria2::write_h3_headers_frame(
            &mut send,
            &[
                (":status", "200"),
                ("content-type", dn_ctype),
                ("cache-control", "no-store"),
                ("x-accel-buffering", "no"),
                ("x-padding", &pad),
            ],
        )
        .await
        .is_err()
        {
            return;
        }
        on_tunnel_stream(Box::new(super::hysteria2::H3BodyStream::new(
            Some(send),
            recv,
            conn,
            None,
        )));
    } else if method == "GET" && !sub.is_empty() && !sub.contains('/') {
        if !is_valid_xhttp_sid(&sub) {
            send_h3_empty_status(&mut send, "400").await;
            return;
        }
        let cb = on_tunnel_stream.clone();
        let Some(sess) = state.get_or_create_session(&sub, reorder_win, move |s| cb(s)) else {
            send_h3_empty_status(&mut send, "503").await;
            return;
        };
        let mut dn_guard = sess.dn_rx.lock().await;
        let Some(mut dn_reader) = dn_guard.take() else {
            send_h3_empty_status(&mut send, "409").await;
            return;
        };
        sess.dn_taken.store(true, Ordering::Relaxed);
        drop(dn_guard);

        if super::hysteria2::write_h3_headers_frame(
            &mut send,
            &[
                (":status", "200"),
                ("content-type", dn_ctype),
                ("cache-control", "no-store"),
                ("x-accel-buffering", "no"),
                ("x-padding", &pad),
            ],
        )
        .await
        .is_err()
        {
            state.remove_session(&sub);
            return;
        }
        let mut chunk_buf = vec![0u8; 65520];
        loop {
            match dn_reader.read(&mut chunk_buf).await {
                Ok(0) => {
                    let _ = send.finish();
                    break;
                }
                Ok(n) => {
                    sess.touch(&state.epoch);
                    if super::hysteria2::write_h3_data_frame(&mut send, &chunk_buf[..n])
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        state.remove_session(&sub);
    } else if method == expected_method && !sub.is_empty() && !sub.contains('/') {
        if !is_valid_xhttp_sid(&sub) {
            send_h3_empty_status(&mut send, "400").await;
            return;
        }
        let cb = on_tunnel_stream.clone();
        let Some(sess) = state.get_or_create_session(&sub, reorder_win, move |s| cb(s)) else {
            send_h3_empty_status(&mut send, "503").await;
            return;
        };
        let _ = super::hysteria2::write_h3_headers_frame(
            &mut send,
            &[
                (":status", "200"),
                ("cache-control", "no-store"),
                ("x-padding", &pad),
            ],
        )
        .await;
        while let Ok(Some(chunk)) = super::hysteria2::read_h3_data_frame(&mut recv).await {
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
        let _ = sess.up_tx.send(SessionPacket::Eof).await;
        let _ = send.finish();
    } else if method == expected_method && sub.contains('/') {
        let mut parts = sub.splitn(2, '/');
        let sid = parts.next().unwrap_or("");
        let seq_str = parts.next().unwrap_or("");
        if !is_valid_xhttp_sid(sid) {
            send_h3_empty_status(&mut send, "400").await;
            return;
        }
        let Ok(seq) = seq_str.parse::<u64>() else {
            send_h3_empty_status(&mut send, "400").await;
            return;
        };
        let cb = on_tunnel_stream.clone();
        let Some(sess) = state.get_or_create_session(sid, reorder_win, move |s| cb(s)) else {
            send_h3_empty_status(&mut send, "503").await;
            return;
        };
        let mut all = Vec::new();
        while let Ok(Some(chunk)) = super::hysteria2::read_h3_data_frame(&mut recv).await {
            if all.len().saturating_add(chunk.len()) > MAX_XHTTP_BODY_BYTES {
                state.remove_session(sid);
                send_h3_empty_status(&mut send, "413").await;
                return;
            }
            all.extend_from_slice(&chunk);
        }
        if all.is_empty() {
            let _ = sess.up_tx.send(SessionPacket::Eof).await;
        } else {
            sess.touch(&state.epoch);
            if sess.up_tx.send(SessionPacket::SeqData(seq, all)).await.is_err() {
                send_h3_empty_status(&mut send, "500").await;
                return;
            }
        }
        let _ = super::hysteria2::write_h3_headers_frame(
            &mut send,
            &[(":status", "200"), ("x-padding", &pad)],
        )
        .await;
        let _ = send.finish();
    } else {
        send_h3_empty_status(&mut send, "400").await;
    }
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

    let pad = random_xhttp_padding(local.xhttp.padding_bytes, local.xhttp.padding_max_bytes);
    let up_headers = format_xhttp_headers(local);
    let stream_ct = stream_uplink_content_type(local);

    if eff_mode == "stream-one" {
        let conn = connect_transport(up_addr, local.clone(), binding.clone()).await?;
        let (mut rd, mut wr) = tokio::io::split(conn);
        let req = format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\n{}Content-Type: {}\r\nTransfer-Encoding: chunked\r\nX-Padding: {}\r\n\r\n",
            up_method, up_base, up_host, up_headers, stream_ct, pad
        );
        wr.write_all(req.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        wr.flush().await.map_err(|e| e.to_string())?;

        let mut read_buf = Vec::with_capacity(4096);
        let status = tokio::time::timeout(req_timeout, read_http_response_head(&mut rd, &mut read_buf))
            .await
            .map_err(|_| "xhttp stream-one response timeout".to_string())??;
        if status != 200 {
            return Err(format!("xhttp stream-one unexpected status {}", status));
        }
        return Ok(wrap_chunked_duplex(rd, wr, read_buf));
    }

    let sid = uuid::Uuid::new_v4().to_string();
    let (dn_addr, dn_ep) = dn_target.unwrap_or_else(|| (up_addr, local.clone()));
    let dn_base = normalize_xhttp_path(&dn_ep.xhttp.path);
    let dn_host = if !dn_ep.xhttp.host.trim().is_empty() {
        dn_ep.xhttp.host.trim().to_string()
    } else if !binding.domain.trim().is_empty() {
        binding.domain.trim().to_string()
    } else {
        "localhost".to_string()
    };

    let dn_conn = connect_transport(dn_addr, dn_ep.clone(), binding.clone()).await?;
    let dn_headers = format_xhttp_headers(&dn_ep);
    let (mut dn_rd, mut dn_wr) = tokio::io::split(dn_conn);
    let get_path = if dn_base == "/" {
        format!("/{}", sid)
    } else {
        format!("{}/{}", dn_base, sid)
    };
    let get_req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\n{}X-Padding: {}\r\n\r\n",
        get_path, dn_host, dn_headers, pad
    );
    dn_wr
        .write_all(get_req.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    dn_wr.flush().await.map_err(|e| e.to_string())?;

    if eff_mode == "stream-up" {
        let up_conn = connect_transport(up_addr, local.clone(), binding.clone()).await?;
        let (mut up_rd, mut up_wr) = tokio::io::split(up_conn);
        let post_path = if up_base == "/" {
            format!("/{}", sid)
        } else {
            format!("{}/{}", up_base, sid)
        };
        let post_req = format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\n{}Content-Type: {}\r\nTransfer-Encoding: chunked\r\nX-Padding: {}\r\n\r\n",
            up_method, post_path, up_host, up_headers, stream_ct, pad
        );
        up_wr
            .write_all(post_req.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        up_wr.flush().await.map_err(|e| e.to_string())?;

        // Drain any TLS post-handshake records / server uplink response padding
        tokio::spawn(async move {
            let mut discard = [0u8; 4096];
            while let Ok(n) = up_rd.read(&mut discard).await {
                if n == 0 {
                    break;
                }
            }
        });

        let mut dn_buf = Vec::with_capacity(4096);
        let status = tokio::time::timeout(req_timeout, read_http_response_head(&mut dn_rd, &mut dn_buf))
            .await
            .map_err(|_| "xhttp stream-up GET response timeout".to_string())??;
        if status != 200 {
            return Err(format!("xhttp stream-up GET unexpected status {}", status));
        }
        return Ok(wrap_chunked_duplex_keep(dn_rd, up_wr, dn_buf, dn_wr));
    }

    // packet-up mode (HTTP/1.1 or HTTP/3 stream)
    let mut dn_buf = Vec::with_capacity(4096);
    let dn_status = tokio::time::timeout(req_timeout, read_http_response_head(&mut dn_rd, &mut dn_buf))
        .await
        .map_err(|_| "xhttp packet-up GET response timeout".to_string())??;
    if dn_status != 200 {
        return Err(format!("xhttp packet-up GET unexpected status {}", dn_status));
    }

    let connect_transport = Arc::new(connect_transport);
    let up_conn = connect_transport(up_addr, local.clone(), binding.clone()).await?;
    let (mut up_rd, mut up_wr) = tokio::io::split(up_conn);

    let (local_stream, peer_stream) = tokio::io::duplex(256 * 1024);
    let (mut peer_rd, mut peer_wr) = tokio::io::split(peer_stream);

    let max_buf_cap = if local.xhttp.post_bytes_max > 0 {
        (local.xhttp.post_bytes_max as usize).clamp(1024, 32768)
    } else if local.xhttp.max_each_post_bytes > 0 {
        (local.xhttp.max_each_post_bytes as usize).clamp(1024, 32768)
    } else {
        32768
    };
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
        use std::io::Write as _;
        let mut seq = 0u64;
        let mut buf = vec![0u8; max_buf_cap];
        let mut post_buf = Vec::with_capacity(max_buf_cap + 1024);
        let mut up_resp_buf = Vec::with_capacity(4096);
        let mut unacked: VecDeque<(u64, Vec<u8>)> = VecDeque::with_capacity(max_in_flight);
        let mut peer_eof = false;

        let format_post = |post_buf: &mut Vec<u8>, pkt_seq: u64, data: &[u8]| {
            let post_path = if up_base == "/" {
                format!("/{}/{}", sid, pkt_seq)
            } else {
                format!("{}/{}/{}", up_base, sid, pkt_seq)
            };
            let pad_s =
                random_xhttp_padding(ep_clone.xhttp.padding_bytes, ep_clone.xhttp.padding_max_bytes);
            post_buf.clear();
            if data.is_empty() {
                let _ = write!(
                    post_buf,
                    "{} {} HTTP/1.1\r\nHost: {}\r\n{}Content-Length: 0\r\nConnection: keep-alive\r\nX-Padding: {}\r\n\r\n",
                    up_method, post_path, up_host, up_headers, pad_s
                );
            } else {
                let _ = write!(
                    post_buf,
                    "{} {} HTTP/1.1\r\nHost: {}\r\n{}Content-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: keep-alive\r\nX-Padding: {}\r\n\r\n",
                    up_method, post_path, up_host, up_headers, data.len(), pad_s
                );
                post_buf.extend_from_slice(data);
            }
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
                            unacked.push_back((pkt_seq, Vec::new()));
                            format_post(&mut post_buf, pkt_seq, &[]);
                            if tokio::time::timeout(req_timeout, async {
                                up_wr.write_all(&post_buf).await?;
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
                            format_post(&mut post_buf, pkt_seq, &payload);
                            unacked.push_back((pkt_seq, payload));
                            if tokio::time::timeout(req_timeout, async {
                                up_wr.write_all(&post_buf).await?;
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
                if peer_eof && unacked.iter().all(|(_, p)| p.is_empty()) {
                    break;
                }
                let mut reconnected = false;
                for _ in 0..3 {
                    if let Ok(new_conn) =
                        connect_up(up_addr, ep_clone.clone(), binding_clone.clone()).await
                    {
                        let (new_rd, mut new_wr) = tokio::io::split(new_conn);
                        let mut replay_ok = true;
                        for (pkt_seq, payload) in &unacked {
                            format_post(&mut post_buf, *pkt_seq, payload);
                            if tokio::time::timeout(req_timeout, async {
                                new_wr.write_all(&post_buf).await?;
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
        loop {
            tokio::select! {
                _ = write_failed_rx.changed() => {
                    if *write_failed_rx.borrow() {
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
                        _ => break,
                    }
                }
            }
        }
        write_abort.abort();
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
        let (mut send, mut recv, conn) =
            super::hysteria2::xhttp_h3_open_bi(up_addr, local, &sni).await?;
        let req_hdrs =
            build_h3_request_headers(up_method, up_host, up_base, local, Some(stream_ct));
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
            None,
        )));
    }

    let sid = uuid::Uuid::new_v4().to_string();
    let (dn_addr, dn_ep) = dn_target.unwrap_or_else(|| (up_addr, local.clone()));
    let dn_base = normalize_xhttp_path(&dn_ep.xhttp.path);
    let dn_host = if !dn_ep.xhttp.host.trim().is_empty() {
        dn_ep.xhttp.host.trim().to_string()
    } else if !binding.domain.trim().is_empty() {
        binding.domain.trim().to_string()
    } else {
        "localhost".to_string()
    };
    let get_path = if dn_base == "/" {
        format!("/{}", sid)
    } else {
        format!("{}/{}", dn_base, sid)
    };

    let (mut dn_send, mut dn_recv, dn_conn) =
        super::hysteria2::xhttp_h3_open_bi(dn_addr, &dn_ep, &sni).await?;
    let get_hdrs = build_h3_request_headers("GET", &dn_host, &get_path, &dn_ep, None);
    write_h3_hdr_pairs(&mut dn_send, &get_hdrs).await?;
    let _ = dn_send.finish();

    if eff_mode == "stream-up" {
        let post_path = if up_base == "/" {
            format!("/{}", sid)
        } else {
            format!("{}/{}", up_base, sid)
        };
        let (mut up_send, mut up_recv, up_conn) =
            super::hysteria2::xhttp_h3_open_bi(up_addr, local, &sni).await?;
        let post_hdrs =
            build_h3_request_headers(up_method, up_host, &post_path, local, Some(stream_ct));
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
            Some(Box::new(up_conn)),
        )));
    }

    // packet-up over RFC 9114 HTTP/3
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
    let max_buf_cap = if local.xhttp.post_bytes_max > 0 {
        (local.xhttp.post_bytes_max as usize).clamp(1024, 32768)
    } else if local.xhttp.max_each_post_bytes > 0 {
        (local.xhttp.max_each_post_bytes as usize).clamp(1024, 32768)
    } else {
        32768
    };
    let ep_clone = local.clone();
    let up_base_owned = up_base.to_string();
    let up_host_owned = up_host.to_string();
    let (write_failed_tx, mut write_failed_rx) = tokio::sync::watch::channel(false);

    let write_task = tokio::spawn(async move {
        let mut seq = 0u64;
        let mut buf = vec![0u8; max_buf_cap];
        let mut peer_eof = false;

        loop {
            let chunk_target = sample_post_size(&ep_clone).min(buf.len());
            let payload = match peer_rd.read(&mut buf[..chunk_target]).await {
                Ok(0) => {
                    peer_eof = true;
                    Vec::new()
                }
                Ok(n) => buf[..n].to_vec(),
                Err(_) => break,
            };
            let pkt_seq = seq;
            seq += 1;
            let post_path = if up_base_owned == "/" {
                format!("/{}/{}", sid, pkt_seq)
            } else {
                format!("{}/{}/{}", up_base_owned, sid, pkt_seq)
            };
            let ct = if payload.is_empty() {
                None
            } else {
                Some("application/octet-stream")
            };

            let mut delivered = false;
            for attempt in 0..3 {
                if attempt > 0 {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                let Ok((mut send, mut recv, _c)) =
                    super::hysteria2::xhttp_h3_open_bi(up_addr, &ep_clone, &sni).await
                else {
                    continue;
                };
                let hdrs = build_h3_request_headers(
                    up_method,
                    &up_host_owned,
                    &post_path,
                    &ep_clone,
                    ct,
                );
                if write_h3_hdr_pairs(&mut send, &hdrs).await.is_err() {
                    continue;
                }
                if !payload.is_empty()
                    && super::hysteria2::write_h3_data_frame(&mut send, &payload)
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

            if !delivered {
                if !peer_eof {
                    let _ = write_failed_tx.send(true);
                }
                break;
            }
            if peer_eof {
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
        let _keep_dn_conn = dn_conn;
        loop {
            tokio::select! {
                _ = write_failed_rx.changed() => {
                    if *write_failed_rx.borrow() {
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
                        _ => break,
                    }
                }
            }
        }
        write_abort.abort();
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

    if eff_mode == "stream-one" {
        let conn = connect_transport(up_addr, local.clone(), binding.clone()).await?;
        let mut h2_sender = dial_h2_client(conn, req_timeout).await?;
        h2_sender = h2_sender.ready().await.map_err(|e| e.to_string())?;
        let req = build_h2_request(up_method, scheme, up_host, up_base, local, Some(stream_ct))?;
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
        return Ok(wrap_h2_duplex(resp.into_body(), send_body));
    }

    let sid = uuid::Uuid::new_v4().to_string();
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

    let dn_raw_conn = connect_transport(dn_addr, dn_ep.clone(), binding.clone()).await?;
    let mut dn_sender = dial_h2_client(dn_raw_conn, req_timeout).await?;
    dn_sender = dn_sender.ready().await.map_err(|e| e.to_string())?;
    let get_path = if dn_base == "/" {
        format!("/{}", sid)
    } else {
        format!("{}/{}", dn_base, sid)
    };
    let get_req = build_h2_request("GET", dn_scheme, &dn_host, &get_path, &dn_ep, None)?;
    let (get_resp_fut, _get_send) = dn_sender
        .send_request(get_req, true)
        .map_err(|e| e.to_string())?;

    let mut up_sender = if shared_ep {
        dn_sender.clone()
    } else {
        let up_raw = connect_transport(up_addr, local.clone(), binding.clone()).await?;
        dial_h2_client(up_raw, req_timeout).await?
    };

    if eff_mode == "stream-up" {
        up_sender = up_sender.ready().await.map_err(|e| e.to_string())?;
        let post_path = if up_base == "/" {
            format!("/{}", sid)
        } else {
            format!("{}/{}", up_base, sid)
        };
        let post_req = build_h2_request(
            up_method,
            scheme,
            up_host,
            &post_path,
            local,
            Some(stream_ct),
        )?;
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
        return Ok(wrap_h2_duplex(get_resp.into_body(), up_send_body));
    }

    // packet-up over HTTP/2 (including h2c prior-knowledge)
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
    let max_buf_cap = if local.xhttp.post_bytes_max > 0 {
        (local.xhttp.post_bytes_max as usize).clamp(1024, 32768)
    } else if local.xhttp.max_each_post_bytes > 0 {
        (local.xhttp.max_each_post_bytes as usize).clamp(1024, 32768)
    } else {
        32768
    };
    let ep_clone = local.clone();
    let binding_clone = binding.clone();
    let connect_up = Arc::new(connect_transport);
    let up_base_owned = up_base.to_string();
    let up_host_owned = up_host.to_string();
    let (write_failed_tx, mut write_failed_rx) = tokio::sync::watch::channel(false);

    let write_task = tokio::spawn(async move {
        let mut seq = 0u64;
        let mut buf = vec![0u8; max_buf_cap];
        let mut peer_eof = false;

        loop {
            let chunk_target = sample_post_size(&ep_clone).min(buf.len());
            let payload = match peer_rd.read(&mut buf[..chunk_target]).await {
                Ok(0) => {
                    peer_eof = true;
                    Vec::new()
                }
                Ok(n) => buf[..n].to_vec(),
                Err(_) => break,
            };
            let pkt_seq = seq;
            seq += 1;
            let post_path = if up_base_owned == "/" {
                format!("/{}/{}", sid, pkt_seq)
            } else {
                format!("{}/{}/{}", up_base_owned, sid, pkt_seq)
            };

            let mut delivered = false;
            for attempt in 0..3 {
                if attempt > 0 {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    let Ok(new_raw) =
                        connect_up(up_addr, ep_clone.clone(), binding_clone.clone()).await
                    else {
                        continue;
                    };
                    let Ok(new_s) = dial_h2_client(new_raw, req_timeout).await else {
                        continue;
                    };
                    up_sender = new_s;
                }
                let Ok(ready_s) = up_sender.clone().ready().await else {
                    continue;
                };
                up_sender = ready_s;
                let ct = if payload.is_empty() {
                    None
                } else {
                    Some("application/octet-stream")
                };
                let Ok(req) = build_h2_request(
                    up_method,
                    scheme,
                    &up_host_owned,
                    &post_path,
                    &ep_clone,
                    ct,
                ) else {
                    break;
                };
                if payload.is_empty() {
                    if let Ok((rf, _)) = up_sender.send_request(req, true) {
                        if let Ok(Ok(r)) = tokio::time::timeout(req_timeout, rf).await {
                            if r.status().as_u16() == 200 {
                                delivered = true;
                                break;
                            }
                        }
                    }
                } else if let Ok((rf, mut sb)) = up_sender.send_request(req, false) {
                    if h2_send_chunk(&mut sb, &payload).await.is_ok()
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

            if !delivered {
                if !peer_eof {
                    let _ = write_failed_tx.send(true);
                }
                break;
            }
            if peer_eof {
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
        let _keep_dn_sender = dn_sender;
        loop {
            tokio::select! {
                _ = write_failed_rx.changed() => {
                    if *write_failed_rx.borrow() {
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
                        _ => break,
                    }
                }
            }
        }
        write_abort.abort();
        let _ = peer_wr.shutdown().await;
    });

    Ok(Box::new(TaskedDuplex::new(
        local_stream,
        vec![write_task, read_task],
    )))
}

fn wrap_h2_duplex(mut recv_body: h2::RecvStream, mut send_body: h2::SendStream<Bytes>) -> BoxStream {
    let (local_stream, peer_stream) = tokio::io::duplex(256 * 1024);
    let (mut peer_rd, mut peer_wr) = tokio::io::split(peer_stream);
    let (write_failed_tx, mut write_failed_rx) = tokio::sync::watch::channel(false);

    let write_task = tokio::spawn(async move {
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
        loop {
            tokio::select! {
                _ = write_failed_rx.changed() => {
                    if *write_failed_rx.borrow() {
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
                        _ => break,
                    }
                }
            }
        }
        write_abort.abort();
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

fn wrap_chunked_duplex_keep<R, W, K>(mut rd: R, mut wr: W, mut read_buf: Vec<u8>, keep: K) -> BoxStream
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
    K: Send + 'static,
{
    let (local_stream, peer_stream) = tokio::io::duplex(256 * 1024);
    let (mut peer_rd, mut peer_wr) = tokio::io::split(peer_stream);
    let (write_failed_tx, mut write_failed_rx) = tokio::sync::watch::channel(false);

    let write_task = tokio::spawn(async move {
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
        loop {
            tokio::select! {
                _ = write_failed_rx.changed() => {
                    if *write_failed_rx.borrow() {
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
                        _ => break,
                    }
                }
            }
        }
        write_abort.abort();
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
    let mut headers = HashMap::new();
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
}
