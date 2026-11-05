use std::collections::{BTreeMap, HashMap};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::sync::mpsc;

use crate::model::{Binding, LocalTLS};
use super::vless_enc::TaskedDuplex;
use super::{xhttp_effective_mode, BoxStream};

const MAX_XHTTP_SESSIONS: usize = 1024;
const MAX_XHTTP_REORDER_WINDOW: usize = 64;
const MAX_XHTTP_BODY_BYTES: usize = 4 * 1024 * 1024;

pub fn is_valid_xhttp_sid(sid: &str) -> bool {
    !sid.is_empty()
        && sid.len() <= 128
        && sid
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

pub struct XhttpServerState {
    sessions: Mutex<HashMap<String, Arc<XhttpSession>>>,
}

struct XhttpSession {
    up_tx: mpsc::Sender<SessionPacket>,
    dn_rx: tokio::sync::Mutex<Option<tokio::io::ReadHalf<DuplexStream>>>,
    dn_taken: AtomicBool,
    created_at: Instant,
}

enum SessionPacket {
    SeqData(u64, Vec<u8>),
    StreamData(Vec<u8>),
    Eof,
}

impl XhttpServerState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            sessions: Mutex::new(HashMap::new()),
        })
    }

    fn get_or_create_session<F>(
        self: &Arc<Self>,
        sid: &str,
        on_new_stream: F,
    ) -> Option<Arc<XhttpSession>>
    where
        F: FnOnce(BoxStream),
    {
        if !is_valid_xhttp_sid(sid) {
            return None;
        }
        let now = Instant::now();
        let mut map = self.sessions.lock();
        if map.len() >= 256 {
            map.retain(|_, s| {
                let max_age = if s.dn_taken.load(Ordering::Relaxed) {
                    Duration::from_secs(120)
                } else {
                    Duration::from_secs(15)
                };
                now.duration_since(s.created_at) < max_age
            });
        }
        if let Some(existing) = map.get(sid) {
            return Some(existing.clone());
        }
        if map.len() >= MAX_XHTTP_SESSIONS {
            map.retain(|_, s| {
                let max_age = if s.dn_taken.load(Ordering::Relaxed) {
                    Duration::from_secs(120)
                } else {
                    Duration::from_secs(15)
                };
                now.duration_since(s.created_at) < max_age
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

        tokio::spawn(async move {
            let mut next_seq = 0u64;
            let mut pending: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
            let mut abort_session = false;
            while let Some(pkt) = up_rx.recv().await {
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
                        if seq.saturating_sub(next_seq) >= MAX_XHTTP_REORDER_WINDOW as u64
                            || pending.len() >= MAX_XHTTP_REORDER_WINDOW
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
            if abort_session {
                if let Some(st) = state_weak.upgrade() {
                    st.remove_session(&sid_owned);
                }
            }
        });

        let sess = Arc::new(XhttpSession {
            up_tx,
            dn_rx: tokio::sync::Mutex::new(Some(dn_read)),
            dn_taken: AtomicBool::new(false),
            created_at: now,
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
    let min_l = if min_len <= 0 { 64 } else { min_len as usize };
    let max_l = if (max_len as usize) <= min_l {
        min_l + 64
    } else {
        max_len as usize
    };
    let span = max_l.saturating_sub(min_l).max(1);
    let mut b = [0u8; 2];
    rand::rng().fill_bytes(&mut b);
    let n = min_l + (u16::from_be_bytes(b) as usize % span);
    "X".repeat(n)
}

pub async fn handle_xhttp_server_conn<F>(
    conn: BoxStream,
    local: LocalTLS,
    state: Arc<XhttpServerState>,
    on_tunnel_stream: F,
) where
    F: Fn(BoxStream) + Send + Sync + 'static,
{
    let on_tunnel_stream = Arc::new(on_tunnel_stream);
    let base_path = normalize_xhttp_path(&local.xhttp.path);
    let max_header_bytes = if (8192..=32768).contains(&local.xhttp.server_max_header_bytes) {
        local.xhttp.server_max_header_bytes as usize
    } else {
        8192
    };
    let (mut rd, mut wr) = tokio::io::split(conn);
    let mut read_buf: Vec<u8> = Vec::with_capacity(8192);

    loop {
        let req = match tokio::time::timeout(
            Duration::from_secs(15),
            read_http_request_head(&mut rd, &mut read_buf, max_header_bytes),
        )
        .await
        {
            Ok(Ok(Some(r))) => r,
            _ => break,
        };

        let path_only = req.path.split('?').next().unwrap_or(&req.path);
        let sub = if base_path == "/" {
            path_only.trim_start_matches('/')
        } else if let Some(rest) = path_only.strip_prefix(&base_path) {
            rest.trim_start_matches('/')
        } else {
            let _ = wr
                .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await;
            break;
        };
        let sub = sub.trim_end_matches('/');
        let pad = random_xhttp_padding(local.xhttp.padding_bytes, local.xhttp.padding_max_bytes);

        if req.method == "POST" && sub.is_empty() {
            // stream-one: full-duplex chunked request & response
            let resp_hdr = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\nCache-Control: no-store\r\nX-Padding: {}\r\n\r\n",
                pad
            );
            if wr.write_all(resp_hdr.as_bytes()).await.is_err() {
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
                    .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await;
                break;
            }
            let cb = on_tunnel_stream.clone();
            let Some(sess) = state.get_or_create_session(&sid, move |s| cb(s)) else {
                let _ = wr
                    .write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
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
                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\nCache-Control: no-store\r\nX-Padding: {}\r\n\r\n",
                pad
            );
            if wr.write_all(resp_hdr.as_bytes()).await.is_err() {
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
        } else if req.method == "POST" && !sub.is_empty() && !sub.contains('/') {
            // stream-up uplink POST (chunked or content-length stream)
            let sid = sub.to_string();
            if !is_valid_xhttp_sid(&sid) {
                let _ = wr
                    .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await;
                break;
            }
            let cb = on_tunnel_stream.clone();
            let Some(sess) = state.get_or_create_session(&sid, move |s| cb(s)) else {
                let _ = wr
                    .write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await;
                break;
            };
            if req.chunked {
                while let Ok(Some(chunk)) = read_http_chunk(&mut rd, &mut read_buf).await {
                    if sess.up_tx.send(SessionPacket::StreamData(chunk)).await.is_err() {
                        break;
                    }
                }
            } else if req.content_length > 0 {
                if let Ok(body) =
                    read_exact_with_buf(&mut rd, &mut read_buf, req.content_length).await
                {
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
        } else if req.method == "POST" && sub.contains('/') {
            // packet-up POST /<base>/<sid>/<seq>
            let mut parts = sub.splitn(2, '/');
            let sid = parts.next().unwrap_or("");
            let seq_str = parts.next().unwrap_or("");
            if !is_valid_xhttp_sid(sid) {
                let _ = wr
                    .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
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
            let Some(sess) = state.get_or_create_session(sid, move |s| cb(s)) else {
                let _ = wr
                    .write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
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
            if read_buf.is_empty() && wr.flush().await.is_err() {
                break;
            }
        } else {
            let _ = wr
                .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await;
            break;
        }
    }
}

pub async fn xhttp_client_connect<F, Fut>(
    up_addr: SocketAddr,
    local: &LocalTLS,
    dn_target: Option<(SocketAddr, LocalTLS)>,
    binding: &Binding,
    connect_transport: F,
) -> Result<BoxStream, String>
where
    F: Fn(SocketAddr, LocalTLS, Binding) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<BoxStream, String>> + Send + 'static,
{
    let eff_mode = if dn_target.is_some()
        && (local.xhttp.mode.is_empty() || local.xhttp.mode == "auto")
    {
        "stream-up"
    } else {
        xhttp_effective_mode(&local.xhttp, local.reality.enabled())
    };
    let up_base = normalize_xhttp_path(&local.xhttp.path);
    let up_host = if !local.xhttp.host.trim().is_empty() {
        local.xhttp.host.trim().to_string()
    } else if !binding.domain.trim().is_empty() {
        binding.domain.trim().to_string()
    } else {
        "localhost".to_string()
    };
    let pad = random_xhttp_padding(local.xhttp.padding_bytes, local.xhttp.padding_max_bytes);

    if eff_mode == "stream-one" {
        let conn = connect_transport(up_addr, local.clone(), binding.clone()).await?;
        let (mut rd, mut wr) = tokio::io::split(conn);
        let req = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: veilink/1.0\r\nTransfer-Encoding: chunked\r\nX-Padding: {}\r\n\r\n",
            up_base, up_host, pad
        );
        wr.write_all(req.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        wr.flush().await.map_err(|e| e.to_string())?;

        let mut read_buf = Vec::with_capacity(4096);
        let status = read_http_response_head(&mut rd, &mut read_buf).await?;
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
    let (mut dn_rd, mut dn_wr) = tokio::io::split(dn_conn);
    let get_path = if dn_base == "/" {
        format!("/{}", sid)
    } else {
        format!("{}/{}", dn_base, sid)
    };
    let get_req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: veilink/1.0\r\nX-Padding: {}\r\n\r\n",
        get_path, dn_host, pad
    );
    dn_wr
        .write_all(get_req.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    dn_wr.flush().await.map_err(|e| e.to_string())?;

    if eff_mode == "stream-up" {
        let up_conn = connect_transport(up_addr, local.clone(), binding.clone()).await?;
        let (mut _up_rd, mut up_wr) = tokio::io::split(up_conn);
        let post_path = if up_base == "/" {
            format!("/{}", sid)
        } else {
            format!("{}/{}", up_base, sid)
        };
        let post_req = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: veilink/1.0\r\nTransfer-Encoding: chunked\r\nX-Padding: {}\r\n\r\n",
            post_path, up_host, pad
        );
        up_wr
            .write_all(post_req.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        up_wr.flush().await.map_err(|e| e.to_string())?;

        let mut dn_buf = Vec::with_capacity(4096);
        let status = read_http_response_head(&mut dn_rd, &mut dn_buf).await?;
        if status != 200 {
            return Err(format!("xhttp stream-up GET unexpected status {}", status));
        }
        return Ok(wrap_chunked_duplex(dn_rd, up_wr, dn_buf));
    }

    // packet-up mode
    let up_conn = connect_transport(up_addr, local.clone(), binding.clone()).await?;
    let (mut up_rd, mut up_wr) = tokio::io::split(up_conn);

    let mut dn_buf = Vec::with_capacity(4096);
    let (local_stream, peer_stream) = tokio::io::duplex(256 * 1024);
    let (mut peer_rd, mut peer_wr) = tokio::io::split(peer_stream);

    let max_post_size = if local.xhttp.max_each_post_bytes > 0 {
        (local.xhttp.max_each_post_bytes as usize).clamp(4096, 1024 * 1024)
    } else {
        65536
    };
    let min_interval_ms = local.xhttp.min_posts_interval_ms.max(0) as u64;
    let ep_clone = local.clone();

    let inflight = Arc::new(tokio::sync::Semaphore::new(16));
    let inflight_ack = inflight.clone();
    let up_ack_task = tokio::spawn(async move {
        let mut up_resp_buf = Vec::with_capacity(4096);
        while let Ok(200) = read_http_response_head(&mut up_rd, &mut up_resp_buf).await {
            inflight_ack.add_permits(1);
        }
        inflight_ack.close();
    });

    let write_task = tokio::spawn(async move {
        use std::io::Write as _;
        let _ack_guard = up_ack_task;
        let mut seq = 0u64;
        let mut buf = vec![0u8; max_post_size];
        let mut post_buf = Vec::with_capacity(max_post_size + 1024);
        loop {
            match peer_rd.read(&mut buf).await {
                Ok(0) => {
                    let Ok(permit) = inflight.acquire().await else {
                        break;
                    };
                    permit.forget();
                    let post_path = if up_base == "/" {
                        format!("/{}/{}", sid, seq)
                    } else {
                        format!("{}/{}/{}", up_base, sid, seq)
                    };
                    let pad_s =
                        random_xhttp_padding(ep_clone.xhttp.padding_bytes, ep_clone.xhttp.padding_max_bytes);
                    let hdr = format!(
                        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Length: 0\r\nConnection: keep-alive\r\nX-Padding: {}\r\n\r\n",
                        post_path, up_host, pad_s
                    );
                    let _ = up_wr.write_all(hdr.as_bytes()).await;
                    let _ = up_wr.flush().await;
                    let _ = tokio::time::timeout(
                        Duration::from_secs(5),
                        inflight.acquire_many(16),
                    )
                    .await;
                    break;
                }
                Ok(n) => {
                    let Ok(permit) = inflight.acquire().await else {
                        break;
                    };
                    permit.forget();
                    let post_path = if up_base == "/" {
                        format!("/{}/{}", sid, seq)
                    } else {
                        format!("{}/{}/{}", up_base, sid, seq)
                    };
                    seq += 1;
                    let pad_s =
                        random_xhttp_padding(ep_clone.xhttp.padding_bytes, ep_clone.xhttp.padding_max_bytes);
                    post_buf.clear();
                    let _ = write!(
                        &mut post_buf,
                        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: keep-alive\r\nX-Padding: {}\r\n\r\n",
                        post_path, up_host, n, pad_s
                    );
                    post_buf.extend_from_slice(&buf[..n]);
                    if up_wr.write_all(&post_buf).await.is_err() {
                        break;
                    }
                    if up_wr.flush().await.is_err() {
                        break;
                    }
                    if min_interval_ms > 0 {
                        tokio::time::sleep(Duration::from_millis(min_interval_ms)).await;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let read_task = tokio::spawn(async move {
        let _keep_dn_wr = dn_wr;
        match read_http_response_head(&mut dn_rd, &mut dn_buf).await {
            Ok(200) => {}
            _ => {
                let _ = peer_wr.shutdown().await;
                return;
            }
        }
        while let Ok(Some(chunk)) = read_http_chunk(&mut dn_rd, &mut dn_buf).await {
            if peer_wr.write_all(&chunk).await.is_err() {
                break;
            }
        }
        let _ = peer_wr.shutdown().await;
    });

    Ok(Box::new(TaskedDuplex::new(
        local_stream,
        vec![write_task, read_task],
    )))
}

fn wrap_chunked_duplex<R, W>(mut rd: R, mut wr: W, mut read_buf: Vec<u8>) -> BoxStream
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (local_stream, peer_stream) = tokio::io::duplex(256 * 1024);
    let (mut peer_rd, mut peer_wr) = tokio::io::split(peer_stream);

    let write_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 65520];
        let mut scratch = Vec::with_capacity(65536);
        loop {
            match peer_rd.read(&mut buf).await {
                Ok(0) => {
                    let _ = wr.write_all(b"0\r\n\r\n").await;
                    let _ = wr.flush().await;
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
    });

    let read_task = tokio::spawn(async move {
        while let Ok(Some(chunk)) = read_http_chunk(&mut rd, &mut read_buf).await {
            if peer_wr.write_all(&chunk).await.is_err() {
                break;
            }
        }
        let _ = peer_wr.shutdown().await;
    });

    Box::new(TaskedDuplex::new(local_stream, vec![write_task, read_task]))
}

struct HttpReqHead {
    method: String,
    path: String,
    content_length: usize,
    chunked: bool,
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

    let head_bytes: Vec<u8> = buf.drain(..header_end + 4).collect();
    let head_str = String::from_utf8_lossy(&head_bytes[..header_end]);
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
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim().to_ascii_lowercase();
            let v = v.trim();
            if k == "content-length" {
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
        }
    }

    Ok(Some(HttpReqHead {
        method,
        path,
        content_length,
        chunked,
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
    let head_bytes: Vec<u8> = buf.drain(..header_end + 4).collect();
    let head_str = String::from_utf8_lossy(&head_bytes[..header_end]);
    let status_line = head_str.lines().next().unwrap_or("");
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

    let line_bytes: Vec<u8> = buf.drain(..line_end + 2).collect();
    let line_str = String::from_utf8_lossy(&line_bytes[..line_end]);
    let size_hex = line_str.split(';').next().unwrap_or("").trim();
    let chunk_size = usize::from_str_radix(size_hex, 16)
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
    while buf.len() < n {
        let mut tmp = [0u8; 32768];
        let got = rd.read(&mut tmp).await?;
        if got == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unexpected EOF in HTTP body",
            ));
        }
        buf.extend_from_slice(&tmp[..got]);
    }
    Ok(buf.drain(..n).collect())
}

fn find_crlf_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}
