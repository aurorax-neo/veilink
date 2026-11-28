use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rand::RngCore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

use super::BoxStream;
use crate::model::{Binding, LocalTLS};

const H3_STREAM_TYPE_CONTROL: u64 = 0x00;
const H3_FRAME_DATA: u64 = 0x00;
const H3_FRAME_HEADERS: u64 = 0x01;
const H3_FRAME_CANCEL_PUSH: u64 = 0x03;
const H3_FRAME_SETTINGS: u64 = 0x04;
const H3_FRAME_PUSH_PROMISE: u64 = 0x05;
const H3_FRAME_GOAWAY: u64 = 0x07;
const H3_FRAME_MAX_PUSH_ID: u64 = 0x0d;
const H3_NO_ERROR: u32 = 0x100;

const HY2_FRAME_TCP_REQUEST: u64 = 0x401;
const HY2_MAX_PADDING_LEN: usize = 4096;
const HY2_PADDING_CHARS: &[u8] =
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

const QUIC_STREAM_RWND: u32 = 8 * 1024 * 1024;
const QUIC_CONN_RWND: u32 = 20 * 1024 * 1024;
const QUIC_SEND_WND: u64 = 16 * 1024 * 1024;
const QUIC_DGRAM_BUF: usize = 4 * 1024 * 1024;

pub fn format_hy2_addr(host: &str, port: u16) -> String {
    let h = host.trim();
    if h.contains(':') && !h.starts_with('[') {
        format!("[{}]:{}", h, port)
    } else {
        format!("{}:{}", h, port)
    }
}

pub fn parse_hy2_addr(addr: &str) -> Result<(String, u16), String> {
    let trimmed = addr.trim();
    if let Some(rest) = trimmed.strip_prefix('[') {
        let (host, after) = rest
            .split_once(']')
            .ok_or_else(|| "invalid bracketed IPv6 address".to_string())?;
        let port_str = after
            .strip_prefix(':')
            .ok_or_else(|| "missing port in bracketed IPv6 address".to_string())?;
        let port = port_str
            .parse::<u16>()
            .map_err(|_| "invalid port in address".to_string())?;
        return Ok((host.to_string(), port));
    }
    let (host, port_str) = trimmed
        .rsplit_once(':')
        .ok_or_else(|| "missing port in hysteria2 address".to_string())?;
    let port = port_str
        .parse::<u16>()
        .map_err(|_| "invalid port in hysteria2 address".to_string())?;
    Ok((host.to_string(), port))
}

pub struct QuicBidiStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    conn: quinn::Connection,
    endpoint: Option<quinn::Endpoint>,
    uni_abort: Option<tokio::task::AbortHandle>,
    keep: Option<Arc<dyn Send + Sync>>,
    owns_conn: bool,
}

impl Drop for QuicBidiStream {
    fn drop(&mut self) {
        let _ = self.send.finish();
        if self.owns_conn {
            let conn = self.conn.clone();
            let ep = self.endpoint.take();
            let uni = self.uni_abort.take();
            if let Ok(rt) = tokio::runtime::Handle::try_current() {
                rt.spawn(async move {
                    tokio::time::sleep(Duration::from_millis(150)).await;
                    if let Some(ab) = uni {
                        ab.abort();
                    }
                    conn.close(H3_NO_ERROR.into(), b"closed");
                    if let Some(e) = ep {
                        e.close(H3_NO_ERROR.into(), b"closed");
                    }
                });
            } else {
                if let Some(ab) = uni {
                    ab.abort();
                }
                conn.close(H3_NO_ERROR.into(), b"closed");
                if let Some(e) = ep {
                    e.close(H3_NO_ERROR.into(), b"closed");
                }
            }
        }
        let _ = self.keep.take();
    }
}

impl AsyncRead for QuicBidiStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicBidiStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.send)
            .poll_write(cx, buf)
            .map_err(io::Error::from)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send)
            .poll_flush(cx)
            .map_err(io::Error::from)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let _ = self.send.finish();
        Pin::new(&mut self.send)
            .poll_shutdown(cx)
            .map_err(io::Error::from)
    }
}

fn build_quic_transport_config() -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    transport.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    transport.max_concurrent_bidi_streams(1024u32.into());
    transport.max_concurrent_uni_streams(256u32.into());
    transport.stream_receive_window(QUIC_STREAM_RWND.into());
    transport.receive_window(QUIC_CONN_RWND.into());
    transport.send_window(QUIC_SEND_WND);
    transport.datagram_receive_buffer_size(Some(QUIC_DGRAM_BUF));
    transport.datagram_send_buffer_size(QUIC_DGRAM_BUF);
    if let Ok(idle) = Duration::from_secs(30).try_into() {
        transport.max_idle_timeout(Some(idle));
    }
    transport.keep_alive_interval(Some(Duration::from_secs(8)));
    transport
}

pub fn build_quic_server_config(local: &LocalTLS) -> Result<quinn::ServerConfig, String> {
    let (certs, key) = load_cert_and_key(&local.cert_pem, &local.key_pem)?;
    let provider = super::fast_crypto_provider();
    let mut tls_cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| e.to_string())?;
    tls_cfg.alpn_protocols = vec![b"h3".to_vec()];
    tls_cfg.max_early_data_size = u32::MAX;

    let quic_tls = QuicServerConfig::try_from(tls_cfg).map_err(|e| e.to_string())?;
    let mut server_cfg = quinn::ServerConfig::with_crypto(Arc::new(quic_tls));
    server_cfg.transport_config(Arc::new(build_quic_transport_config()));
    Ok(server_cfg)
}

pub fn build_quic_client_config(local: &LocalTLS) -> Result<quinn::ClientConfig, String> {
    let provider = super::fast_crypto_provider();
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?;

    let roots: Arc<rustls::RootCertStore> = if !local.ca_pem.trim().is_empty() {
        let mut roots = rustls::RootCertStore::empty();
        let mut reader = io::BufReader::new(local.ca_pem.as_bytes());
        for cert in rustls_pemfile::certs(&mut reader) {
            let cert = cert.map_err(|e| e.to_string())?;
            roots.add(cert).map_err(|e| e.to_string())?;
        }
        if roots.is_empty() {
            return Err("no valid CA certificates found in ca_pem".to_string());
        }
        Arc::new(roots)
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
    let mut tls_cfg = builder.with_root_certificates(roots).with_no_client_auth();
    tls_cfg.alpn_protocols = vec![b"h3".to_vec()];

    let quic_tls = QuicClientConfig::try_from(tls_cfg).map_err(|e| e.to_string())?;
    let mut client_cfg = quinn::ClientConfig::new(Arc::new(quic_tls));
    client_cfg.transport_config(Arc::new(build_quic_transport_config()));
    Ok(client_cfg)
}

pub fn load_cert_and_key(
    cert_pem: &str,
    key_pem: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), String> {
    let mut cert_reader = io::BufReader::new(cert_pem.as_bytes());
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("parse cert pem: {}", e))?;
    if certs.is_empty() {
        return Err("no certificates found in cert_pem".to_string());
    }
    let mut key_reader = io::BufReader::new(key_pem.as_bytes());
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| format!("parse key pem: {}", e))?
        .ok_or_else(|| "no private key found in key_pem".to_string())?;
    Ok((certs, key))
}

fn create_quic_client_endpoint(
    remote_addr: SocketAddr,
    local: &LocalTLS,
) -> Result<quinn::Endpoint, String> {
    let client_cfg = build_quic_client_config(local)?;
    let bind_addr: SocketAddr = if remote_addr.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };
    let udp_sock = {
        let sock = socket2::Socket::new(
            socket2::Domain::for_address(bind_addr),
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .map_err(|e| e.to_string())?;
        let _ = sock.set_recv_buffer_size(4 * 1024 * 1024);
        let _ = sock.set_send_buffer_size(4 * 1024 * 1024);
        sock.bind(&bind_addr.into()).map_err(|e| e.to_string())?;
        std::net::UdpSocket::from(sock)
    };
    let mut quic_ep = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        udp_sock,
        Arc::new(quinn::TokioRuntime),
    )
    .map_err(|e| e.to_string())?;
    quic_ep.set_default_client_config(client_cfg);
    Ok(quic_ep)
}

pub async fn init_h3_connection(
    conn: &quinn::Connection,
) -> Result<tokio::task::AbortHandle, String> {
    start_h3_control_streams(conn)
        .await
        .map_err(|(maybe_ab, e)| {
            if let Some(ab) = maybe_ab {
                ab.abort();
            }
            e
        })
}

struct PooledH3Entry {
    conn: quinn::Connection,
    endpoint: quinn::Endpoint,
    uni_abort: tokio::task::AbortHandle,
    created_at: Instant,
    requests: AtomicU64,
    active_streams: Arc<AtomicUsize>,
}

impl PooledH3Entry {
    fn is_usable(&self, local: &LocalTLS) -> bool {
        if self.conn.close_reason().is_some() {
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

    fn shutdown(&self) {
        self.uni_abort.abort();
        self.conn.close(H3_NO_ERROR.into(), b"xmux rotate");
        self.endpoint.close(H3_NO_ERROR.into(), b"xmux rotate");
    }
}

pub struct ActiveStreamGuard(pub Arc<AtomicUsize>);

impl Drop for ActiveStreamGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

pub async fn xhttp_h3_open_bi(
    remote_addr: SocketAddr,
    local: &LocalTLS,
    sni: &str,
) -> Result<
    (
        quinn::SendStream,
        quinn::RecvStream,
        quinn::Connection,
        ActiveStreamGuard,
    ),
    String,
> {
    type PoolKey = (SocketAddr, String, [u8; 32]);
    type Slot = Arc<tokio::sync::Mutex<Vec<Arc<PooledH3Entry>>>>;
    static H3_POOL: OnceLock<parking_lot::Mutex<HashMap<PoolKey, Slot>>> = OnceLock::new();

    let ca_hash: [u8; 32] = *blake3::hash(local.ca_pem.trim().as_bytes()).as_bytes();
    let key: PoolKey = (remote_addr, sni.to_string(), ca_hash);
    let pool = H3_POOL.get_or_init(|| parking_lot::Mutex::new(HashMap::new()));

    let slot: Slot = {
        let mut g = pool.lock();
        if g.len() >= 128 && !g.contains_key(&key) {
            g.retain(|_, sl| {
                if let Ok(mut guard) = sl.try_lock() {
                    guard.retain(|e| {
                        if e.conn.close_reason().is_some() {
                            e.shutdown();
                            false
                        } else {
                            true
                        }
                    });
                    !guard.is_empty()
                } else {
                    true
                }
            });
        }
        g.entry(key)
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(Vec::new())))
            .clone()
    };

    let max_conns = if local.xhttp.xmux.max_connections > 0 {
        (local.xhttp.xmux.max_connections as usize).clamp(1, 32)
    } else {
        4
    };

    let mut list = slot.lock().await;
    let mut kept = Vec::with_capacity(list.len());
    let mut opened = None;
    for entry in list.drain(..) {
        if opened.is_none() && entry.is_usable(local) {
            if let Ok(Ok((send, recv))) =
                tokio::time::timeout(Duration::from_secs(5), entry.conn.open_bi()).await
            {
                entry.requests.fetch_add(1, Ordering::Relaxed);
                entry.active_streams.fetch_add(1, Ordering::Relaxed);
                let guard = ActiveStreamGuard(entry.active_streams.clone());
                let conn = entry.conn.clone();
                kept.push(entry);
                opened = Some((send, recv, conn, guard));
                continue;
            }
            entry.shutdown();
        } else if entry.conn.close_reason().is_none() {
            if entry.active_streams.load(Ordering::Relaxed) > 0 {
                kept.push(entry);
            } else {
                entry.shutdown();
            }
        } else {
            entry.shutdown();
        }
    }
    *list = kept;
    if let Some(res) = opened {
        return Ok(res);
    }

    let quic_ep = create_quic_client_endpoint(remote_addr, local)?;
    let connecting = quic_ep.connect(remote_addr, sni).map_err(|e| {
        quic_ep.close(H3_NO_ERROR.into(), b"connect err");
        e.to_string()
    })?;
    let conn = match tokio::time::timeout(Duration::from_secs(8), connecting).await {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => {
            quic_ep.close(H3_NO_ERROR.into(), b"handshake err");
            return Err(format!("xhttp h3 connect: {}", e));
        }
        Err(_) => {
            quic_ep.close(H3_NO_ERROR.into(), b"timeout");
            return Err("xhttp h3 connect timeout".to_string());
        }
    };
    let uni_abort = match tokio::time::timeout(Duration::from_secs(5), init_h3_connection(&conn))
        .await
    {
        Ok(Ok(ab)) => ab,
        Ok(Err(e)) => {
            conn.close(H3_NO_ERROR.into(), b"h3 control err");
            quic_ep.close(H3_NO_ERROR.into(), b"h3 control err");
            return Err(format!("xhttp h3 control stream: {}", e));
        }
        Err(_) => {
            conn.close(H3_NO_ERROR.into(), b"h3 control timeout");
            quic_ep.close(H3_NO_ERROR.into(), b"h3 control timeout");
            return Err("xhttp h3 control stream timeout".to_string());
        }
    };
    let (send, recv) = match tokio::time::timeout(Duration::from_secs(5), conn.open_bi()).await {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => {
            uni_abort.abort();
            conn.close(H3_NO_ERROR.into(), b"open_bi err");
            quic_ep.close(H3_NO_ERROR.into(), b"open_bi err");
            return Err(e.to_string());
        }
        Err(_) => {
            uni_abort.abort();
            conn.close(H3_NO_ERROR.into(), b"open_bi timeout");
            quic_ep.close(H3_NO_ERROR.into(), b"open_bi timeout");
            return Err("xhttp h3 open_bi timeout".to_string());
        }
    };
    let active_streams = Arc::new(AtomicUsize::new(1));
    let guard = ActiveStreamGuard(active_streams.clone());
    let entry = Arc::new(PooledH3Entry {
        conn: conn.clone(),
        endpoint: quic_ep,
        uni_abort,
        created_at: Instant::now(),
        requests: AtomicU64::new(1),
        active_streams,
    });
    while list.len() >= max_conns {
        let evicted = list.remove(0);
        if evicted.active_streams.load(Ordering::Relaxed) == 0 {
            evicted.shutdown();
        }
    }
    list.push(entry);
    Ok((send, recv, conn, guard))
}

/// Authenticated multi-stream + UDP-datagram Hysteria2 client QUIC session.
pub struct Hy2ClientSession {
    pub conn: quinn::Connection,
    endpoint: quinn::Endpoint,
    uni_abort: tokio::task::AbortHandle,
    pub udp_supported: bool,
}

impl Drop for Hy2ClientSession {
    fn drop(&mut self) {
        self.uni_abort.abort();
        self.conn.close(H3_NO_ERROR.into(), b"closed");
        self.endpoint.close(H3_NO_ERROR.into(), b"closed");
    }
}

impl Hy2ClientSession {
    pub fn is_closed(&self) -> bool {
        self.conn.close_reason().is_some()
    }

    pub fn max_datagram_size(&self) -> usize {
        self.conn.max_datagram_size().unwrap_or(1200)
    }

    pub async fn open_tcp_stream(
        self: &Arc<Self>,
        host: &str,
        port: u16,
    ) -> Result<BoxStream, String> {
        let (mut send, mut recv) = tokio::time::timeout(Duration::from_secs(8), self.conn.open_bi())
            .await
            .map_err(|_| "hy2 open_bi timeout".to_string())?
            .map_err(|e| e.to_string())?;
        let addr = format_hy2_addr(host, port);
        let req_pad = random_padding(64, 512);
        let mut req_buf = Vec::with_capacity(16 + addr.len() + req_pad.len());
        append_varint(&mut req_buf, HY2_FRAME_TCP_REQUEST);
        append_varint(&mut req_buf, addr.len() as u64);
        req_buf.extend_from_slice(addr.as_bytes());
        append_varint(&mut req_buf, req_pad.len() as u64);
        req_buf.extend_from_slice(req_pad.as_bytes());
        send.write_all(&req_buf)
            .await
            .map_err(|e| e.to_string())?;

        let hs = tokio::time::timeout(Duration::from_secs(8), async {
            let mut status_byte = [0u8; 1];
            recv.read_exact(&mut status_byte)
                .await
                .map_err(|e| e.to_string())?;
            let msg_len = read_varint(&mut recv).await? as usize;
            if msg_len > 4096 {
                return Err("hy2 response message too long".to_string());
            }
            let mut msg_buf = vec![0u8; msg_len];
            if msg_len > 0 {
                recv.read_exact(&mut msg_buf)
                    .await
                    .map_err(|e| e.to_string())?;
            }
            let pad_len = read_varint(&mut recv).await? as usize;
            if pad_len > HY2_MAX_PADDING_LEN {
                return Err("hy2 response padding too long".to_string());
            }
            if pad_len > 0 {
                let mut pad_buf = vec![0u8; pad_len];
                recv.read_exact(&mut pad_buf)
                    .await
                    .map_err(|e| e.to_string())?;
            }
            if status_byte[0] != 0x00 {
                return Err(format!(
                    "hy2 tcp request rejected: {}",
                    String::from_utf8_lossy(&msg_buf)
                ));
            }
            Ok(())
        })
        .await
        .map_err(|_| "hy2 tcp response timeout".to_string())?;
        hs?;

        let keep: Arc<dyn Send + Sync> = Arc::clone(self) as Arc<dyn Send + Sync>;
        Ok(Box::new(QuicBidiStream {
            send,
            recv,
            conn: self.conn.clone(),
            endpoint: None,
            uni_abort: None,
            keep: Some(keep),
            owns_conn: false,
        }))
    }
}

pub async fn hy2_connect_session(
    remote_addr: SocketAddr,
    local: &LocalTLS,
    binding: &Binding,
    gw_addr: &str,
) -> Result<Arc<Hy2ClientSession>, String> {
    let quic_ep = create_quic_client_endpoint(remote_addr, local)?;

    let sni = if !gw_addr.trim().is_empty() {
        gw_addr.trim().to_string()
    } else if !binding.domain.trim().is_empty() {
        binding.domain.trim().to_string()
    } else {
        "localhost".to_string()
    };

    let connecting = quic_ep.connect(remote_addr, &sni).map_err(|e| {
        quic_ep.close(H3_NO_ERROR.into(), b"connect err");
        e.to_string()
    })?;
    let conn = match tokio::time::timeout(Duration::from_secs(8), connecting).await {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => {
            quic_ep.close(H3_NO_ERROR.into(), b"handshake err");
            return Err(format!("hy2 connect: {}", e));
        }
        Err(_) => {
            quic_ep.close(H3_NO_ERROR.into(), b"timeout");
            return Err("hy2 connect timeout".to_string());
        }
    };

    let hs_res = tokio::time::timeout(Duration::from_secs(10), async {
        let uni_abort = start_h3_control_streams(&conn).await?;

        let (mut auth_send, mut auth_recv) = conn
            .open_bi()
            .await
            .map_err(|e| (Some(uni_abort.clone()), e.to_string()))?;
        let pad = random_padding(256, 2048);
        let req_headers = encode_qpack_field_section(&[
            (":method", "POST"),
            (":scheme", "https"),
            (":path", "/auth"),
            (":authority", "hysteria"),
            ("hysteria-auth", binding.uuid.trim()),
            ("hysteria-cc-rx", "0"),
            ("hysteria-padding", &pad),
        ]);
        if let Err(e) = write_h3_frame(&mut auth_send, H3_FRAME_HEADERS, &req_headers).await {
            return Err((Some(uni_abort), e));
        }
        let _ = auth_send.finish();

        let fpayload = match read_h3_headers_frame(&mut auth_recv).await {
            Ok(p) => p,
            Err(e) => return Err((Some(uni_abort), e)),
        };
        let resp_headers = match decode_qpack_field_section(&fpayload) {
            Ok(h) => h,
            Err(e) => return Err((Some(uni_abort), e)),
        };
        let status = resp_headers
            .iter()
            .find(|(k, _)| k == ":status")
            .map(|(_, v)| v.as_str())
            .unwrap_or("");
        if status != "233" {
            return Err((
                Some(uni_abort),
                format!("hysteria2 auth rejected with status {:?}", status),
            ));
        }
        let udp_supported = resp_headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("hysteria-udp"))
            .map(|(_, v)| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        Ok((uni_abort, udp_supported))
    })
    .await;

    match hs_res {
        Ok(Ok((uni_abort, udp_supported))) => Ok(Arc::new(Hy2ClientSession {
            conn,
            endpoint: quic_ep,
            uni_abort,
            udp_supported,
        })),
        Ok(Err((maybe_abort, err))) => {
            if let Some(ab) = maybe_abort {
                ab.abort();
            }
            conn.close(H3_NO_ERROR.into(), b"handshake err");
            quic_ep.close(H3_NO_ERROR.into(), b"handshake err");
            Err(err)
        }
        Err(_) => {
            conn.close(H3_NO_ERROR.into(), b"handshake timeout");
            quic_ep.close(H3_NO_ERROR.into(), b"handshake timeout");
            Err("hy2 protocol handshake timeout".to_string())
        }
    }
}

pub async fn hy2_connect(
    remote_addr: SocketAddr,
    local: &LocalTLS,
    binding: &Binding,
    gw_addr: &str,
) -> Result<BoxStream, String> {
    let sess = hy2_connect_session(remote_addr, local, binding, gw_addr).await?;
    sess.open_tcp_stream(binding.domain.trim(), 0).await
}

/// Authenticated multi-stream + UDP-datagram Hysteria2 server QUIC session.
pub struct Hy2ServerSession {
    pub conn: quinn::Connection,
    pub binding: Binding,
    uni_abort: tokio::task::AbortHandle,
}

impl Drop for Hy2ServerSession {
    fn drop(&mut self) {
        self.uni_abort.abort();
    }
}

pub async fn hy2_accept_authenticated(
    conn: quinn::Connection,
    _local: &LocalTLS,
    bindings: &[Binding],
) -> Result<Arc<Hy2ServerSession>, String> {
    let conn_ref = conn.clone();
    let hs_res = tokio::time::timeout(Duration::from_secs(10), async move {
        let uni_abort = start_h3_control_streams(&conn_ref).await?;

        let (mut auth_send, mut auth_recv) = conn_ref
            .accept_bi()
            .await
            .map_err(|e| (Some(uni_abort.clone()), e.to_string()))?;
        let fpayload = match read_h3_headers_frame(&mut auth_recv).await {
            Ok(p) => p,
            Err(e) => return Err((Some(uni_abort), e)),
        };
        let headers = match decode_qpack_field_section(&fpayload) {
            Ok(h) => h,
            Err(e) => return Err((Some(uni_abort), e)),
        };
        let method = headers
            .iter()
            .find(|(k, _)| k == ":method")
            .map(|(_, v)| v.as_str())
            .unwrap_or("");
        let path = headers
            .iter()
            .find(|(k, _)| k == ":path")
            .map(|(_, v)| v.as_str())
            .unwrap_or("");
        let auth_val = headers
            .iter()
            .find(|(k, _)| k == "hysteria-auth")
            .map(|(_, v)| v.as_str())
            .unwrap_or("");
        if method != "POST" || path != "/auth" || auth_val.is_empty() {
            return Err((
                Some(uni_abort),
                "invalid hysteria2 auth request".to_string(),
            ));
        }

        let mut matched_binding: Option<Binding> = None;
        for b in bindings {
            let cand = b.uuid.trim().as_bytes();
            let got = auth_val.trim().as_bytes();
            if cand.len() == got.len() && cand.ct_eq(got).unwrap_u8() == 1 {
                matched_binding = Some(b.clone());
                break;
            }
        }
        let binding = match matched_binding {
            Some(b) => b,
            None => {
                let resp = encode_qpack_field_section(&[(":status", "404")]);
                let _ = write_h3_frame(&mut auth_send, H3_FRAME_HEADERS, &resp).await;
                let _ = auth_send.finish();
                return Err((Some(uni_abort), "hysteria2 auth uuid mismatch".to_string()));
            }
        };

        let resp_pad = random_padding(256, 2048);
        let resp_headers = encode_qpack_field_section(&[
            (":status", "233"),
            ("hysteria-udp", "true"),
            ("hysteria-cc-rx", "auto"),
            ("hysteria-padding", &resp_pad),
        ]);
        if let Err(e) = write_h3_frame(&mut auth_send, H3_FRAME_HEADERS, &resp_headers).await {
            return Err((Some(uni_abort), e));
        }
        let _ = auth_send.finish();
        Ok((binding, uni_abort))
    })
    .await;

    match hs_res {
        Ok(Ok((binding, uni_abort))) => Ok(Arc::new(Hy2ServerSession {
            conn,
            binding,
            uni_abort,
        })),
        Ok(Err((maybe_abort, err))) => {
            if let Some(ab) = maybe_abort {
                ab.abort();
            }
            conn.close(H3_NO_ERROR.into(), b"reject");
            Err(err)
        }
        Err(_) => {
            conn.close(H3_NO_ERROR.into(), b"timeout");
            Err("hy2 accept timeout".to_string())
        }
    }
}

pub async fn hy2_accept_tcp_stream(
    sess: &Arc<Hy2ServerSession>,
) -> Result<(BoxStream, String, u16), String> {
    let (mut send, mut recv) = sess.conn.accept_bi().await.map_err(|e| e.to_string())?;
    let hs = tokio::time::timeout(Duration::from_secs(8), async {
        let req_type = read_varint(&mut recv).await?;
        if req_type != HY2_FRAME_TCP_REQUEST {
            return Err(format!("unexpected hy2 stream type 0x{:x}", req_type));
        }
        let addr_len = read_varint(&mut recv).await? as usize;
        if addr_len == 0 || addr_len > 2048 {
            return Err("invalid hy2 address length".to_string());
        }
        let mut addr_buf = vec![0u8; addr_len];
        recv.read_exact(&mut addr_buf)
            .await
            .map_err(|e| e.to_string())?;
        let pad_len = read_varint(&mut recv).await? as usize;
        if pad_len > HY2_MAX_PADDING_LEN {
            return Err("hy2 request padding too long".to_string());
        }
        if pad_len > 0 {
            let mut pad_buf = vec![0u8; pad_len];
            recv.read_exact(&mut pad_buf)
                .await
                .map_err(|e| e.to_string())?;
        }
        let addr_str = String::from_utf8_lossy(&addr_buf);
        let (host, port) = parse_hy2_addr(&addr_str)?;
        if !host.eq_ignore_ascii_case(sess.binding.domain.trim()) {
            let err_resp = [0x01u8, 0x00, 0x00];
            let _ = send.write_all(&err_resp).await;
            return Err(format!("hy2 domain mismatch: got {}", host));
        }

        let ok_pad = random_padding(128, 1024);
        let mut ok_resp = Vec::with_capacity(4 + ok_pad.len());
        ok_resp.push(0x00);
        append_varint(&mut ok_resp, 0);
        append_varint(&mut ok_resp, ok_pad.len() as u64);
        ok_resp.extend_from_slice(ok_pad.as_bytes());
        send.write_all(&ok_resp).await.map_err(|e| e.to_string())?;
        Ok((host, port))
    })
    .await
    .map_err(|_| "hy2 tcp stream header timeout".to_string())?;
    let (host, port) = hs?;

    let keep: Arc<dyn Send + Sync> = Arc::clone(sess) as Arc<dyn Send + Sync>;
    Ok((
        Box::new(QuicBidiStream {
            send,
            recv,
            conn: sess.conn.clone(),
            endpoint: None,
            uni_abort: None,
            keep: Some(keep),
            owns_conn: false,
        }),
        host,
        port,
    ))
}

pub async fn hy2_accept_connection(
    conn: quinn::Connection,
    local: &LocalTLS,
    bindings: &[Binding],
) -> Result<(BoxStream, Binding), String> {
    let sess = hy2_accept_authenticated(conn, local, bindings).await?;
    let binding = sess.binding.clone();
    let (stream, _, _) = hy2_accept_tcp_stream(&sess).await?;
    Ok((stream, binding))
}

// ============================================================================
// Hysteria2 Native QUIC UDP Datagram Framing & Fragmentation (RFC 9221 + HY2)
// Wire: [SessionID:4B BE][PacketID:2B BE][FragID:1B][FragCount:1B][AddrLen:varint][Addr][Data]
// ============================================================================

fn varint_encoded_len(v: u64) -> usize {
    if v <= 63 {
        1
    } else if v <= 16383 {
        2
    } else if v <= 1073741823 {
        4
    } else {
        8
    }
}

fn read_varint_slice(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        return None;
    }
    let mut val = (first & 0x3f) as u64;
    for &b in &buf[1..len] {
        val = (val << 8) | (b as u64);
    }
    Some((val, len))
}

pub fn encode_hy2_udp_datagrams(
    session_id: u32,
    packet_id: u16,
    addr: &str,
    payload: &[u8],
    max_dgram_size: usize,
) -> Vec<Bytes> {
    let addr_bytes = addr.as_bytes();
    let hdr_len = 4 + 2 + 1 + 1 + varint_encoded_len(addr_bytes.len() as u64) + addr_bytes.len();
    let max_chunk = max_dgram_size.saturating_sub(hdr_len).max(64);

    if payload.is_empty() {
        let mut out = Vec::with_capacity(hdr_len);
        out.extend_from_slice(&session_id.to_be_bytes());
        out.extend_from_slice(&packet_id.to_be_bytes());
        out.push(0);
        out.push(1);
        append_varint(&mut out, addr_bytes.len() as u64);
        out.extend_from_slice(addr_bytes);
        return vec![Bytes::from(out)];
    }

    let frag_count = payload.len().div_ceil(max_chunk);
    if frag_count > 255 {
        return Vec::new();
    }
    let mut dgrams = Vec::with_capacity(frag_count);
    for (frag_id, chunk) in payload.chunks(max_chunk).enumerate() {
        let mut out = Vec::with_capacity(hdr_len + chunk.len());
        out.extend_from_slice(&session_id.to_be_bytes());
        out.extend_from_slice(&packet_id.to_be_bytes());
        out.push(frag_id as u8);
        out.push(frag_count as u8);
        append_varint(&mut out, addr_bytes.len() as u64);
        out.extend_from_slice(addr_bytes);
        out.extend_from_slice(chunk);
        dgrams.push(Bytes::from(out));
    }
    dgrams
}

struct PartialHy2Udp {
    addr: String,
    frag_count: u8,
    received: usize,
    total_bytes: usize,
    frags: Vec<Option<Vec<u8>>>,
    created_at: Instant,
}

#[derive(Default)]
pub struct Hy2UdpDefragmenter {
    pending: HashMap<(u32, u16), PartialHy2Udp>,
}

impl Hy2UdpDefragmenter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, dgram: &[u8]) -> Option<(u32, String, Vec<u8>)> {
        if dgram.len() < 9 {
            return None;
        }
        let session_id = u32::from_be_bytes([dgram[0], dgram[1], dgram[2], dgram[3]]);
        let packet_id = u16::from_be_bytes([dgram[4], dgram[5]]);
        let frag_id = dgram[6];
        let frag_count = dgram[7];
        if frag_count == 0 || frag_id >= frag_count {
            return None;
        }
        let (addr_len_u64, vlen) = read_varint_slice(&dgram[8..])?;
        let addr_len = addr_len_u64 as usize;
        let addr_start = 8 + vlen;
        if addr_len > 2048 || dgram.len() < addr_start + addr_len {
            return None;
        }
        let addr = std::str::from_utf8(&dgram[addr_start..addr_start + addr_len])
            .ok()?
            .to_string();
        let data = &dgram[addr_start + addr_len..];

        if frag_count == 1 {
            return Some((session_id, addr, data.to_vec()));
        }

        let now = Instant::now();
        if self.pending.len() >= 128 {
            self.pending
                .retain(|_, p| now.saturating_duration_since(p.created_at) < Duration::from_secs(5));
            if self.pending.len() >= 256 {
                self.pending.clear();
            }
        }

        let key = (session_id, packet_id);
        let entry = self.pending.entry(key).or_insert_with(|| PartialHy2Udp {
            addr: addr.clone(),
            frag_count,
            received: 0,
            total_bytes: 0,
            frags: vec![None; frag_count as usize],
            created_at: now,
        });
        if entry.frag_count != frag_count {
            self.pending.remove(&key);
            return None;
        }
        let slot = &mut entry.frags[frag_id as usize];
        if slot.is_none() {
            if entry.total_bytes.saturating_add(data.len()) > 65535 {
                self.pending.remove(&key);
                return None;
            }
            entry.total_bytes += data.len();
            entry.received += 1;
            *slot = Some(data.to_vec());
        }
        if entry.received == frag_count as usize {
            let done = self.pending.remove(&key)?;
            let mut full = Vec::with_capacity(done.total_bytes);
            for f in done.frags.into_iter().flatten() {
                full.extend_from_slice(&f);
            }
            return Some((session_id, done.addr, full));
        }
        None
    }
}

async fn start_h3_control_streams(
    conn: &quinn::Connection,
) -> Result<tokio::task::AbortHandle, (Option<tokio::task::AbortHandle>, String)> {
    let mut uni = conn.open_uni().await.map_err(|e| (None, e.to_string()))?;
    let mut buf = Vec::with_capacity(8);
    append_varint(&mut buf, H3_STREAM_TYPE_CONTROL);
    append_varint(&mut buf, H3_FRAME_SETTINGS);
    append_varint(&mut buf, 0);
    uni.write_all(&buf).await.map_err(|e| (None, e.to_string()))?;

    let conn_clone = conn.clone();
    let jh = tokio::spawn(async move {
        while let Ok(mut recv) = conn_clone.accept_uni().await {
            tokio::spawn(async move {
                let mut discard = [0u8; 1024];
                while let Ok(Some(n)) = recv.read(&mut discard).await {
                    if n == 0 {
                        break;
                    }
                }
            });
        }
    });
    Ok(jh.abort_handle())
}

pub async fn write_h3_headers_frame(
    send: &mut quinn::SendStream,
    headers: &[(&str, &str)],
) -> Result<(), String> {
    let encoded = encode_qpack_field_section(headers);
    write_h3_frame(send, H3_FRAME_HEADERS, &encoded).await
}

pub async fn read_h3_headers_decoded(
    recv: &mut quinn::RecvStream,
) -> Result<Vec<(String, String)>, String> {
    let payload = read_h3_headers_frame(recv).await?;
    decode_qpack_field_section(&payload)
}

pub async fn write_h3_data_frame(send: &mut quinn::SendStream, data: &[u8]) -> io::Result<()> {
    if data.is_empty() {
        return Ok(());
    }
    let mut hdr = Vec::with_capacity(16);
    append_varint(&mut hdr, H3_FRAME_DATA);
    append_varint(&mut hdr, data.len() as u64);
    send.write_all(&hdr).await.map_err(io::Error::from)?;
    send.write_all(data).await.map_err(io::Error::from)
}

fn is_forbidden_h3_request_frame(ftype: u64) -> bool {
    matches!(
        ftype,
        0x02 | H3_FRAME_CANCEL_PUSH
            | H3_FRAME_SETTINGS
            | H3_FRAME_PUSH_PROMISE
            | 0x06
            | H3_FRAME_GOAWAY
            | 0x08
            | 0x09
            | H3_FRAME_MAX_PUSH_ID
    )
}

pub async fn read_h3_data_frame(recv: &mut quinn::RecvStream) -> io::Result<Option<Vec<u8>>> {
    loop {
        let mut first = [0u8; 1];
        match recv.read(&mut first).await.map_err(io::Error::from)? {
            None | Some(0) => return Ok(None),
            Some(_) => {}
        }
        let type_len = 1usize << (first[0] >> 6);
        let mut ftype = (first[0] & 0x3f) as u64;
        if type_len > 1 {
            let mut rest = [0u8; 7];
            recv.read_exact(&mut rest[..type_len - 1])
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::UnexpectedEof, e))?;
            for &b in &rest[..type_len - 1] {
                ftype = (ftype << 8) | (b as u64);
            }
        }
        let flen = read_varint(recv)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))? as usize;
        if is_forbidden_h3_request_frame(ftype) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("forbidden H3 frame 0x{:x} on request stream", ftype),
            ));
        }
        if ftype == H3_FRAME_DATA {
            if flen > 16 * 1024 * 1024 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "H3 DATA frame exceeds 16 MiB",
                ));
            }
            if flen == 0 {
                continue;
            }
            let mut data = vec![0u8; flen];
            recv.read_exact(&mut data)
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::UnexpectedEof, e))?;
            return Ok(Some(data));
        }
        if flen > 65536 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "H3 non-DATA frame too large",
            ));
        }
        if flen > 0 {
            let mut skip = vec![0u8; flen];
            recv.read_exact(&mut skip)
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::UnexpectedEof, e))?;
        }
    }
}

pub struct H3BodyStream {
    send: Option<quinn::SendStream>,
    recv: quinn::RecvStream,
    _conn: quinn::Connection,
    _keep: Option<Box<dyn Send + Sync>>,
    hdr_buf: [u8; 16],
    hdr_len: usize,
    rem_payload: usize,
    skip_mode: bool,
    eof: bool,
    write_buf: Vec<u8>,
    write_pos: usize,
    pending_write_len: usize,
}

impl H3BodyStream {
    pub fn new(
        send: Option<quinn::SendStream>,
        recv: quinn::RecvStream,
        conn: quinn::Connection,
        keep: Option<Box<dyn Send + Sync>>,
    ) -> Self {
        Self {
            send,
            recv,
            _conn: conn,
            _keep: keep,
            hdr_buf: [0u8; 16],
            hdr_len: 0,
            rem_payload: 0,
            skip_mode: false,
            eof: false,
            write_buf: Vec::with_capacity(65536),
            write_pos: 0,
            pending_write_len: 0,
        }
    }

    fn poll_drain_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(ref mut send) = self.send else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "H3 stream is read-only",
            )));
        };
        while self.write_pos < self.write_buf.len() {
            match Pin::new(&mut *send)
                .poll_write(cx, &self.write_buf[self.write_pos..])
                .map_err(io::Error::from)
            {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "H3 send stream write zero",
                    )));
                }
                Poll::Ready(Ok(n)) => self.write_pos += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.write_buf.clear();
        self.write_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl Drop for H3BodyStream {
    fn drop(&mut self) {
        if self.write_pos == self.write_buf.len() {
            if let Some(ref mut send) = self.send {
                let _ = send.finish();
            }
        }
    }
}

fn decode_varint_bytes(b: &[u8]) -> u64 {
    let mut val = (b[0] & 0x3f) as u64;
    for &x in &b[1..] {
        val = (val << 8) | (x as u64);
    }
    val
}

impl AsyncRead for H3BodyStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let this = self.get_mut();
        loop {
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            if this.rem_payload > 0 {
                if this.skip_mode {
                    let mut discard = [0u8; 4096];
                    let cap = this.rem_payload.min(discard.len());
                    let mut rbuf = ReadBuf::new(&mut discard[..cap]);
                    match Pin::new(&mut this.recv).poll_read(cx, &mut rbuf) {
                        Poll::Ready(Ok(())) => {
                            let n = rbuf.filled().len();
                            if n == 0 {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "EOF skipping H3 extension frame",
                                )));
                            }
                            this.rem_payload -= n;
                            continue;
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                } else if buf.remaining() <= this.rem_payload {
                    let before = buf.filled().len();
                    match Pin::new(&mut this.recv).poll_read(cx, buf) {
                        Poll::Ready(Ok(())) => {
                            let n = buf.filled().len() - before;
                            if n == 0 {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "EOF inside H3 DATA frame",
                                )));
                            }
                            this.rem_payload -= n;
                            return Poll::Ready(Ok(()));
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                } else {
                    let mut scratch = [0u8; 32768];
                    let cap = this.rem_payload.min(scratch.len()).min(buf.remaining());
                    let mut sub = ReadBuf::new(&mut scratch[..cap]);
                    match Pin::new(&mut this.recv).poll_read(cx, &mut sub) {
                        Poll::Ready(Ok(())) => {
                            let filled = sub.filled();
                            if filled.is_empty() {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "EOF inside H3 DATA frame",
                                )));
                            }
                            this.rem_payload -= filled.len();
                            buf.put_slice(filled);
                            return Poll::Ready(Ok(()));
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }

            let type_vlen = if this.hdr_len == 0 {
                1
            } else {
                1usize << (this.hdr_buf[0] >> 6)
            };
            if this.hdr_len < type_vlen {
                let mut rbuf = ReadBuf::new(&mut this.hdr_buf[this.hdr_len..type_vlen]);
                match Pin::new(&mut this.recv).poll_read(cx, &mut rbuf) {
                    Poll::Ready(Ok(())) => {
                        let n = rbuf.filled().len();
                        if n == 0 {
                            if this.hdr_len == 0 {
                                this.eof = true;
                                return Poll::Ready(Ok(()));
                            }
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "truncated H3 frame type varint",
                            )));
                        }
                        this.hdr_len += n;
                        continue;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            let total_hdr = if this.hdr_len == type_vlen {
                type_vlen + 1
            } else {
                type_vlen + (1usize << (this.hdr_buf[type_vlen] >> 6))
            };
            if this.hdr_len < total_hdr {
                let mut rbuf = ReadBuf::new(&mut this.hdr_buf[this.hdr_len..total_hdr]);
                match Pin::new(&mut this.recv).poll_read(cx, &mut rbuf) {
                    Poll::Ready(Ok(())) => {
                        let n = rbuf.filled().len();
                        if n == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "truncated H3 frame length varint",
                            )));
                        }
                        this.hdr_len += n;
                        continue;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }

            let ftype = decode_varint_bytes(&this.hdr_buf[..type_vlen]);
            let flen_u64 = decode_varint_bytes(&this.hdr_buf[type_vlen..total_hdr]);
            this.hdr_len = 0;

            if is_forbidden_h3_request_frame(ftype) {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unexpected H3 frame 0x{:x} on request stream", ftype),
                )));
            }
            if ftype == H3_FRAME_DATA {
                if flen_u64 > 16 * 1024 * 1024 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "H3 DATA frame exceeds 16 MiB",
                    )));
                }
                this.rem_payload = flen_u64 as usize;
                this.skip_mode = false;
            } else {
                if flen_u64 > 65536 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "H3 extension/trailer frame exceeds 64 KiB",
                    )));
                }
                this.rem_payload = flen_u64 as usize;
                this.skip_mode = true;
            }
        }
    }
}

impl AsyncWrite for H3BodyStream {
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
        let n = buf.len().min(65520);
        this.write_buf.clear();
        this.write_pos = 0;
        this.pending_write_len = n;
        append_varint(&mut this.write_buf, H3_FRAME_DATA);
        append_varint(&mut this.write_buf, n as u64);
        this.write_buf.extend_from_slice(&buf[..n]);
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
        let Some(ref mut send) = this.send else {
            return Poll::Ready(Ok(()));
        };
        Pin::new(send).poll_flush(cx).map_err(io::Error::from)
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
        if let Some(ref mut send) = this.send {
            let _ = send.finish();
        }
        Poll::Ready(Ok(()))
    }
}

async fn write_h3_frame(
    send: &mut quinn::SendStream,
    frame_type: u64,
    payload: &[u8],
) -> Result<(), String> {
    let mut buf = Vec::with_capacity(16 + payload.len());
    append_varint(&mut buf, frame_type);
    append_varint(&mut buf, payload.len() as u64);
    buf.extend_from_slice(payload);
    send.write_all(&buf).await.map_err(|e| e.to_string())
}

async fn read_h3_headers_frame(recv: &mut quinn::RecvStream) -> Result<Vec<u8>, String> {
    for _ in 0..16 {
        let (ftype, payload) = read_h3_frame(recv).await?;
        match ftype {
            H3_FRAME_HEADERS => return Ok(payload),
            f if is_forbidden_h3_request_frame(f) || f == H3_FRAME_DATA => {
                return Err(format!("unexpected H3 frame 0x{:x} before HEADERS", ftype));
            }
            _ => {
                // RFC 9114 §7.2.8: unknown extension / GREASE frames must be ignored.
            }
        }
    }
    Err("too many extension frames before H3 HEADERS".to_string())
}

async fn read_h3_frame(recv: &mut quinn::RecvStream) -> Result<(u64, Vec<u8>), String> {
    let frame_type = read_varint(recv).await?;
    let length = read_varint(recv).await? as usize;
    if length > 64 * 1024 {
        return Err(format!("H3 frame too large: {}", length));
    }
    let mut payload = vec![0u8; length];
    if length > 0 {
        recv.read_exact(&mut payload)
            .await
            .map_err(|e| e.to_string())?;
    }
    Ok((frame_type, payload))
}

const QPACK_STATIC_TABLE: [(&str, &str); 99] = [
    (":authority", ""),
    (":path", "/"),
    ("age", "0"),
    ("content-disposition", ""),
    ("content-length", "0"),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("referer", ""),
    ("set-cookie", ""),
    (":method", "CONNECT"),
    (":method", "DELETE"),
    (":method", "GET"),
    (":method", "HEAD"),
    (":method", "OPTIONS"),
    (":method", "POST"),
    (":method", "PUT"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "103"),
    (":status", "200"),
    (":status", "304"),
    (":status", "404"),
    (":status", "503"),
    ("accept", "*/*"),
    ("accept", "application/dns-message"),
    ("accept-encoding", "gzip, deflate, br"),
    ("accept-ranges", "bytes"),
    ("access-control-allow-headers", "cache-control"),
    ("access-control-allow-headers", "content-type"),
    ("access-control-allow-origin", "*"),
    ("cache-control", "max-age=0"),
    ("cache-control", "max-age=2592000"),
    ("cache-control", "max-age=604800"),
    ("cache-control", "no-cache"),
    ("cache-control", "no-store"),
    ("cache-control", "public, max-age=31536000"),
    ("content-encoding", "br"),
    ("content-encoding", "gzip"),
    ("content-type", "application/dns-message"),
    ("content-type", "application/javascript"),
    ("content-type", "application/json"),
    ("content-type", "application/x-www-form-urlencoded"),
    ("content-type", "image/gif"),
    ("content-type", "image/jpeg"),
    ("content-type", "image/png"),
    ("content-type", "text/css"),
    ("content-type", "text/html; charset=utf-8"),
    ("content-type", "text/plain"),
    ("content-type", "text/plain;charset=utf-8"),
    ("range", "bytes=0-"),
    ("strict-transport-security", "max-age=31536000"),
    ("strict-transport-security", "max-age=31536000; includesubdomains"),
    ("strict-transport-security", "max-age=31536000; includesubdomains; preload"),
    ("vary", "accept-encoding"),
    ("vary", "origin"),
    ("x-content-type-options", "nosniff"),
    ("x-xss-protection", "1; mode=block"),
    (":status", "100"),
    (":status", "204"),
    (":status", "206"),
    (":status", "302"),
    (":status", "400"),
    (":status", "403"),
    (":status", "421"),
    (":status", "425"),
    (":status", "500"),
    ("accept-language", ""),
    ("access-control-allow-credentials", "FALSE"),
    ("access-control-allow-credentials", "TRUE"),
    ("access-control-allow-headers", "*"),
    ("access-control-allow-methods", "get"),
    ("access-control-allow-methods", "get, post, options"),
    ("access-control-allow-methods", "options"),
    ("access-control-expose-headers", "content-length"),
    ("access-control-request-headers", "content-type"),
    ("access-control-request-method", "get"),
    ("access-control-request-method", "post"),
    ("alt-svc", "clear"),
    ("authorization", ""),
    ("content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"),
    ("early-data", "1"),
    ("expect-ct", ""),
    ("forwarded", ""),
    ("if-range", ""),
    ("origin", ""),
    ("purpose", "prefetch"),
    ("server", ""),
    ("timing-allow-origin", "*"),
    ("upgrade-insecure-requests", "1"),
    ("user-agent", ""),
    ("x-forwarded-for", ""),
    ("x-frame-options", "deny"),
    ("x-frame-options", "sameorigin"),
];

const HUFFMAN_CODES: [u32; 256] = [
    0x1ff8, 0x7fffd8, 0xfffffe2, 0xfffffe3, 0xfffffe4, 0xfffffe5, 0xfffffe6, 0xfffffe7, 0xfffffe8,
    0xffffea, 0x3ffffffc, 0xfffffe9, 0xfffffea, 0x3ffffffd, 0xfffffeb, 0xfffffec, 0xfffffed,
    0xfffffee, 0xfffffef, 0xffffff0, 0xffffff1, 0xffffff2, 0x3ffffffe, 0xffffff3, 0xffffff4,
    0xffffff5, 0xffffff6, 0xffffff7, 0xffffff8, 0xffffff9, 0xffffffa, 0xffffffb, 0x14, 0x3f8,
    0x3f9, 0xffa, 0x1ff9, 0x15, 0xf8, 0x7fa, 0x3fa, 0x3fb, 0xf9, 0x7fb, 0xfa, 0x16, 0x17, 0x18,
    0x0, 0x1, 0x2, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x5c, 0xfb, 0x7ffc, 0x20, 0xffb,
    0x3fc, 0x1ffa, 0x21, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
    0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0xfc, 0x73, 0xfd, 0x1ffb, 0x7fff0,
    0x1ffc, 0x3ffc, 0x22, 0x7ffd, 0x3, 0x23, 0x4, 0x24, 0x5, 0x25, 0x26, 0x27, 0x6, 0x74, 0x75,
    0x28, 0x29, 0x2a, 0x7, 0x2b, 0x76, 0x2c, 0x8, 0x9, 0x2d, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7ffe,
    0x7fc, 0x3ffd, 0x1ffd, 0xffffffc, 0xfffe6, 0x3fffd2, 0xfffe7, 0xfffe8, 0x3fffd3, 0x3fffd4,
    0x3fffd5, 0x7fffd9, 0x3fffd6, 0x7fffda, 0x7fffdb, 0x7fffdc, 0x7fffdd, 0x7fffde, 0xffffeb,
    0x7fffdf, 0xffffec, 0xffffed, 0x3fffd7, 0x7fffe0, 0xffffee, 0x7fffe1, 0x7fffe2, 0x7fffe3,
    0x7fffe4, 0x1fffdc, 0x3fffd8, 0x7fffe5, 0x3fffd9, 0x7fffe6, 0x7fffe7, 0xffffef, 0x3fffda,
    0x1fffdd, 0xfffe9, 0x3fffdb, 0x3fffdc, 0x7fffe8, 0x7fffe9, 0x1fffde, 0x7fffea, 0x3fffdd,
    0x3fffde, 0xfffff0, 0x1fffdf, 0x3fffdf, 0x7fffeb, 0x7fffec, 0x1fffe0, 0x1fffe1, 0x3fffe0,
    0x1fffe2, 0x7fffed, 0x3fffe1, 0x7fffee, 0x7fffef, 0xfffea, 0x3fffe2, 0x3fffe3, 0x3fffe4,
    0x7ffff0, 0x3fffe5, 0x3fffe6, 0x7ffff1, 0x3ffffe0, 0x3ffffe1, 0xfffeb, 0x7fff1, 0x3fffe7,
    0x7ffff2, 0x3fffe8, 0x1ffffec, 0x3ffffe2, 0x3ffffe3, 0x3ffffe4, 0x7ffffde, 0x7ffffdf,
    0x3ffffe5, 0xfffff1, 0x1ffffed, 0x7fff2, 0x1fffe3, 0x3ffffe6, 0x7ffffe0, 0x7ffffe1, 0x3ffffe7,
    0x7ffffe2, 0xfffff2, 0x1fffe4, 0x1fffe5, 0x3ffffe8, 0x3ffffe9, 0xffffffd, 0x7ffffe3, 0x7ffffe4,
    0x7ffffe5, 0xfffec, 0xfffff3, 0xfffed, 0x1fffe6, 0x3fffe9, 0x1fffe7, 0x1fffe8, 0x7ffff3,
    0x3fffea, 0x3fffeb, 0x1ffffee, 0x1ffffef, 0xfffff4, 0xfffff5, 0x3ffffea, 0x7ffff4, 0x3ffffeb,
    0x7ffffe6, 0x3ffffec, 0x3ffffed, 0x7ffffe7, 0x7ffffe8, 0x7ffffe9, 0x7ffffea, 0x7ffffeb,
    0xffffffe, 0x7ffffec, 0x7ffffed, 0x7ffffee, 0x7ffffef, 0x7fffff0, 0x3ffffee,
];

const HUFFMAN_LENS: [u8; 256] = [
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 30, 28,
    28, 28, 28, 28, 28, 28, 28, 28, 6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6, 5, 5,
    5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10, 13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6, 15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6,
    6, 5, 6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28, 20, 22, 20, 20, 22, 22, 22, 23, 22,
    23, 23, 23, 23, 23, 24, 23, 24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24, 22,
    21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23, 21, 21, 22, 21, 23, 22, 23, 23, 20,
    22, 22, 22, 23, 22, 22, 23, 26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25, 19,
    21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27, 20, 24, 20, 21, 22, 21, 21, 23, 22,
    22, 25, 25, 24, 24, 26, 23, 26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
];

#[derive(Clone, Copy)]
struct HuffNode {
    children: [u16; 2],
    sym: Option<u8>,
}

fn huffman_trie() -> &'static [HuffNode] {
    static TRIE: OnceLock<Vec<HuffNode>> = OnceLock::new();
    TRIE.get_or_init(|| {
        let mut nodes = vec![HuffNode {
            children: [0, 0],
            sym: None,
        }];
        for sym in 0..256usize {
            let code = HUFFMAN_CODES[sym];
            let len = HUFFMAN_LENS[sym];
            let mut cur = 0usize;
            for bit_pos in (0..len).rev() {
                let bit = ((code >> bit_pos) & 1) as usize;
                let next = nodes[cur].children[bit] as usize;
                if next == 0 {
                    let idx = nodes.len();
                    nodes.push(HuffNode {
                        children: [0, 0],
                        sym: None,
                    });
                    nodes[cur].children[bit] = idx as u16;
                    cur = idx;
                } else {
                    cur = next;
                }
            }
            nodes[cur].sym = Some(sym as u8);
        }
        nodes
    })
}

pub(crate) fn decode_qpack_huffman(src: &[u8]) -> Result<Vec<u8>, String> {
    let trie = huffman_trie();
    let mut out = Vec::with_capacity(src.len().saturating_mul(2).min(65536));
    let mut cur = 0usize;
    let mut pad_bits = 0u8;
    let mut all_ones = true;
    for &byte in src {
        for shift in (0..8).rev() {
            let bit = ((byte >> shift) & 1) as usize;
            let next = trie[cur].children[bit] as usize;
            if next == 0 {
                return Err("invalid QPACK Huffman sequence".to_string());
            }
            if let Some(sym) = trie[next].sym {
                if out.len() >= 65536 {
                    return Err("QPACK Huffman string too long".to_string());
                }
                out.push(sym);
                cur = 0;
                pad_bits = 0;
                all_ones = true;
            } else {
                cur = next;
                pad_bits = pad_bits.saturating_add(1);
                if bit == 0 {
                    all_ones = false;
                }
            }
        }
    }
    if cur != 0 && (!all_ones || pad_bits > 7) {
        return Err("invalid QPACK Huffman EOS padding".to_string());
    }
    Ok(out)
}

fn decode_qpack_string(
    data: &[u8],
    pos: &mut usize,
    prefix_bits: u8,
    huff_mask: u8,
) -> Result<String, String> {
    if *pos >= data.len() {
        return Err("truncated QPACK string".to_string());
    }
    let is_huff = (data[*pos] & huff_mask) != 0;
    let (slen, used) = decode_prefixed_int(&data[*pos..], prefix_bits)?;
    *pos += used;
    if slen > 65536 || *pos + slen > data.len() {
        return Err("QPACK string truncated or too long".to_string());
    }
    let raw = &data[*pos..*pos + slen];
    *pos += slen;
    let bytes = if is_huff {
        decode_qpack_huffman(raw)?
    } else {
        raw.to_vec()
    };
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

pub(crate) fn encode_qpack_field_section(headers: &[(&str, &str)]) -> Vec<u8> {
    let mut out = vec![0x00, 0x00];
    for (name, value) in headers {
        let nb = name.to_ascii_lowercase();
        let nb = nb.as_bytes();
        let vb = value.as_bytes();
        encode_prefixed_int(&mut out, 0x20, 3, nb.len());
        out.extend_from_slice(nb);
        encode_prefixed_int(&mut out, 0x00, 7, vb.len());
        out.extend_from_slice(vb);
    }
    out
}

pub(crate) fn decode_qpack_field_section(data: &[u8]) -> Result<Vec<(String, String)>, String> {
    if data.len() < 2 {
        return Err("QPACK field section too short".to_string());
    }
    let mut pos = 0usize;
    let (ric, n1) = decode_prefixed_int(&data[pos..], 8)?;
    pos += n1;
    if ric != 0 {
        return Err(
            "QPACK dynamic table references not allowed (MAX_TABLE_CAPACITY=0)".to_string(),
        );
    }
    let (_, n2) = decode_prefixed_int(&data[pos..], 7)?;
    pos += n2;

    let mut out = Vec::new();
    while pos < data.len() {
        if out.len() >= 256 {
            return Err("too many QPACK header fields".to_string());
        }
        let b = data[pos];
        if (b & 0x80) != 0 {
            if (b & 0x40) == 0 {
                return Err("QPACK dynamic indexed field not allowed".to_string());
            }
            let (idx, used) = decode_prefixed_int(&data[pos..], 6)?;
            pos += used;
            let &(k, v) = QPACK_STATIC_TABLE
                .get(idx)
                .ok_or_else(|| format!("QPACK static index {} out of range", idx))?;
            out.push((k.to_string(), v.to_string()));
        } else if (b & 0xc0) == 0x40 {
            if (b & 0x10) == 0 {
                return Err("QPACK dynamic name reference not allowed".to_string());
            }
            let (idx, used) = decode_prefixed_int(&data[pos..], 4)?;
            pos += used;
            let &(k, _) = QPACK_STATIC_TABLE
                .get(idx)
                .ok_or_else(|| format!("QPACK static name index {} out of range", idx))?;
            let val = decode_qpack_string(data, &mut pos, 7, 0x80)?;
            out.push((k.to_string(), val));
        } else if (b & 0xe0) == 0x20 {
            let name = decode_qpack_string(data, &mut pos, 3, 0x08)?.to_ascii_lowercase();
            let val = decode_qpack_string(data, &mut pos, 7, 0x80)?;
            out.push((name, val));
        } else {
            return Err(format!("unsupported QPACK representation 0x{:02x}", b));
        }
    }
    Ok(out)
}

fn encode_prefixed_int(out: &mut Vec<u8>, mask: u8, prefix_bits: u8, mut val: usize) {
    let max_prefix = (1usize << prefix_bits) - 1;
    if val < max_prefix {
        out.push(mask | (val as u8));
        return;
    }
    out.push(mask | (max_prefix as u8));
    val -= max_prefix;
    while val >= 128 {
        out.push(((val & 0x7f) as u8) | 0x80);
        val >>= 7;
    }
    out.push(val as u8);
}

fn decode_prefixed_int(buf: &[u8], prefix_bits: u8) -> Result<(usize, usize), String> {
    if buf.is_empty() {
        return Err("empty buffer for prefixed int".to_string());
    }
    let max_prefix = (1usize << prefix_bits) - 1;
    let mut val = (buf[0] as usize) & max_prefix;
    if val < max_prefix {
        return Ok((val, 1));
    }
    let mut shift = 0u32;
    let mut idx = 1usize;
    while idx < buf.len() {
        let b = buf[idx];
        idx += 1;
        val += ((b & 0x7f) as usize) << shift;
        if (b & 0x80) == 0 {
            return Ok((val, idx));
        }
        shift += 7;
        if shift > 28 {
            return Err("QPACK integer overflow".to_string());
        }
    }
    Err("truncated QPACK integer".to_string())
}

pub fn append_varint(out: &mut Vec<u8>, v: u64) {
    if v <= 63 {
        out.push(v as u8);
    } else if v <= 16383 {
        out.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes());
    } else if v <= 1073741823 {
        out.extend_from_slice(&((v as u32) | 0x80000000).to_be_bytes());
    } else {
        out.extend_from_slice(&(v | 0xc000000000000000).to_be_bytes());
    }
}

pub async fn read_varint<R: AsyncRead + Unpin>(r: &mut R) -> Result<u64, String> {
    let mut first = [0u8; 1];
    r.read_exact(&mut first).await.map_err(|e| e.to_string())?;
    let prefix = first[0] >> 6;
    let len = 1usize << prefix;
    let mut val = (first[0] & 0x3f) as u64;
    if len > 1 {
        let mut rest = [0u8; 7];
        r.read_exact(&mut rest[..len - 1])
            .await
            .map_err(|e| e.to_string())?;
        for &b in &rest[..len - 1] {
            val = (val << 8) | (b as u64);
        }
    }
    Ok(val)
}

fn random_padding(min_len: usize, max_len: usize) -> String {
    let span = max_len.saturating_sub(min_len).max(1);
    let mut b = [0u8; 2];
    rand::rng().fill_bytes(&mut b);
    let n = min_len + (u16::from_be_bytes(b) as usize % span);
    let mut raw = vec![0u8; n];
    rand::rng().fill_bytes(&mut raw);
    raw.into_iter()
        .map(|x| HY2_PADDING_CHARS[(x as usize) % HY2_PADDING_CHARS.len()] as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qpack_decodes_static_table_and_rfc7541_huffman() {
        let huff_example: [u8; 12] = [
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ];
        assert_eq!(
            decode_qpack_huffman(&huff_example).unwrap(),
            b"www.example.com"
        );

        let mut section = vec![
            0x00,
            0x00,
            0xc0 | 20,
            0xc0 | 23,
            0xc0 | 25,
            0x50 | 0,
            0x80 | (huff_example.len() as u8),
        ];
        section.extend_from_slice(&huff_example);

        let decoded = decode_qpack_field_section(&section).unwrap();
        assert_eq!(
            decoded,
            vec![
                (":method".to_string(), "POST".to_string()),
                (":scheme".to_string(), "https".to_string()),
                (":status".to_string(), "200".to_string()),
                (":authority".to_string(), "www.example.com".to_string()),
            ]
        );

        assert!(decode_qpack_field_section(&[0x01, 0x00, 0x80]).is_err());
    }

    #[test]
    fn hy2_udp_datagram_fragmentation_and_reassembly_roundtrip() {
        let payload: Vec<u8> = (0..4096).map(|i| (i * 7 % 251) as u8).collect();
        let dgrams = encode_hy2_udp_datagrams(0x1234_5678, 42, "[2001:db8::1]:5353", &payload, 1100);
        assert!(dgrams.len() >= 4);

        let mut defrag = Hy2UdpDefragmenter::new();
        // Deliver out of order
        for dg in dgrams.iter().skip(1) {
            assert!(defrag.push(dg).is_none());
        }
        let (sid, addr, reassembled) = defrag.push(&dgrams[0]).expect("reassembled UDP packet");
        assert_eq!(sid, 0x1234_5678);
        assert_eq!(addr, "[2001:db8::1]:5353");
        assert_eq!(reassembled, payload);
        assert_eq!(
            parse_hy2_addr(&addr).unwrap(),
            ("2001:db8::1".to_string(), 5353)
        );
    }
}
