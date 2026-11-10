use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> std::io::Result<()> {
    Ok(())
}
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use rand::{Rng, RngCore};
use rustls::pki_types::{CertificateDer, ServerName};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::buildinfo;
use crate::config::Config;
use crate::control::{
    EnrollRequest, EnrollResponse, EventsRequest, EventsResponse, PullRequest, TrafficBytesPayload,
    PATH_ENROLL, PATH_EVENTS, PATH_PULL,
};
use crate::tunnel::xhttp::DEFAULT_USER_AGENT;
use crate::logring::Ring;
use crate::model::{LocalTLS, Snapshot};
use crate::tunnel::Runtime;

pub const ERR_CREDENTIAL_REJECTED: &str =
    "node credential rejected; local state wiped; administrator must re-enroll";

#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    #[error("{ERR_CREDENTIAL_REJECTED}")]
    CredentialRejected,
    #[error("{0}")]
    Other(String),
}

#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    #[error("credential rejected")]
    Rejected,
    #[error("invalid request: {0}")]
    Invalid(String),
    #[error("transport error: {0}")]
    Transport(String),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiskState {
    pub node_id: String,
    pub master: String,
    pub credential: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<Snapshot>,
}

pub fn save_disk_state(path: &Path, state: &DiskState) -> Result<(), String> {
    let bytes = serde_json::to_vec(state).map_err(|e| e.to_string())?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp_name = format!(".state-{}", rand::rng().random::<u64>());
    let tmp_path = parent.join(tmp_name);

    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut file = opts.open(&tmp_path).map_err(|e| e.to_string())?;
    if let Err(e) = set_mode(&tmp_path, 0o600)
        .and_then(|_| file.write_all(&bytes))
        .and_then(|_| file.sync_all())
    {
        let _ = fs::remove_file(&tmp_path);
        return Err(e.to_string());
    }
    drop(file);
    if let Err(e) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e.to_string());
    }
    if let Ok(dir) = File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}

fn wipe_state(path: &Path, st: &mut DiskState) -> Result<(), String> {
    st.credential.clear();
    st.snapshot = None;
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("credential rejected; local state removal failed".to_string()),
    }
}

pub fn configuration_quiesced(snap: Option<&Snapshot>) -> bool {
    let Some(s) = snap else {
        return false;
    };
    if s.node.disabled {
        return true;
    }
    if !s.bindings.is_empty() {
        return false;
    }
    !s.mappings.iter().any(|m| m.enabled)
}

enum PooledConn {
    Http1(hyper::client::conn::http1::SendRequest<Full<Bytes>>),
    Http2(hyper::client::conn::http2::SendRequest<Full<Bytes>>),
}

impl PooledConn {
    async fn ready(&mut self) -> Result<(), ControlError> {
        match self {
            PooledConn::Http1(s) => s
                .ready()
                .await
                .map_err(|e| ControlError::Transport(e.to_string())),
            PooledConn::Http2(s) => s
                .ready()
                .await
                .map_err(|e| ControlError::Transport(e.to_string())),
        }
    }
}

#[derive(Clone)]
pub struct HttpControlClient {
    scheme: String,
    connect_addr: String,
    host_header: String,
    server_name: String,
    base_path: String,
    tls_config: Option<Arc<rustls::ClientConfig>>,
    tls_config_h1: Option<Arc<rustls::ClientConfig>>,
    tls_config_no_sni: Option<Arc<rustls::ClientConfig>>,
    prefer_no_sni: Arc<AtomicBool>,
    conn_pool: Arc<tokio::sync::Mutex<Option<PooledConn>>>,
}

impl HttpControlClient {
    pub fn new(c: &Config) -> Result<Self, String> {
        let raw = c.master_addr.trim();
        let (scheme, connect_addr, host_header, default_sni, base_path) =
            if raw.starts_with("http://") || raw.starts_with("https://") {
                let u = Url::parse(raw).map_err(|e| format!("invalid master_addr: {}", e))?;
                let sch = u.scheme().to_string();
                let host = u
                    .host_str()
                    .ok_or_else(|| "missing host in master_addr".to_string())?
                    .to_string();
                let port = u.port_or_known_default().unwrap_or(80);
                let connect = if host.contains(':') && !host.starts_with('[') {
                    format!("[{}]:{}", host, port)
                } else {
                    format!("{}:{}", host, port)
                };
                let hdr_host = if !c.control_server_name.trim().is_empty() {
                    c.control_server_name.trim().to_string()
                } else {
                    host.clone()
                };
                let host_hdr = match u.port() {
                    Some(p) => format!("{}:{}", hdr_host, p),
                    None => hdr_host,
                };
                let sni = host
                    .strip_prefix('[')
                    .and_then(|s| s.strip_suffix(']'))
                    .unwrap_or(&host)
                    .to_string();
                let bp = u.path().trim_end_matches('/').to_string();
                (sch, connect, host_hdr, sni, bp)
            } else {
                let sch = if c.control_ca.is_empty() && c.control_server_name.is_empty() {
                    "http".to_string()
                } else {
                    "https".to_string()
                };
                let (host_only, port_only) = split_host_port_opt(raw);
                let host_hdr = if !c.control_server_name.is_empty() {
                    let sni_host = c.control_server_name.trim();
                    match port_only.as_deref() {
                        Some(p) if !p.is_empty() && p != "443" && p != "80" => {
                            if sni_host.contains(':') && !sni_host.starts_with('[') {
                                format!("[{}]:{}", sni_host, p)
                            } else {
                                format!("{}:{}", sni_host, p)
                            }
                        }
                        _ => sni_host.to_string(),
                    }
                } else {
                    raw.to_string()
                };
                (
                    sch,
                    raw.to_string(),
                    host_hdr,
                    host_only,
                    String::new(),
                )
            };

        let server_name = if !c.control_server_name.is_empty() {
            c.control_server_name.clone()
        } else {
            default_sni
        };

        let (tls_config, tls_config_h1, tls_config_no_sni) = if scheme == "https" {
            let mut root_store = rustls::RootCertStore::empty();
            if !c.control_ca.is_empty() {
                let pem_bytes =
                    fs::read(&c.control_ca).map_err(|e| format!("read control_ca: {}", e))?;
                let mut reader = std::io::BufReader::new(&pem_bytes[..]);
                let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| "invalid control CA".to_string())?;
                if certs.is_empty() {
                    return Err("invalid control CA".to_string());
                }
                let (added, _) = root_store.add_parsable_certificates(certs);
                if added == 0 {
                    return Err("invalid control CA".to_string());
                }
            } else {
                root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                for sys_ca in ["/etc/ssl/certs/ca-certificates.crt", "/etc/ssl/cert.pem"] {
                    if let Ok(pem_bytes) = fs::read(sys_ca) {
                        let mut reader = std::io::BufReader::new(&pem_bytes[..]);
                        let certs: Vec<CertificateDer<'static>> =
                            rustls_pemfile::certs(&mut reader)
                                .filter_map(Result::ok)
                                .collect();
                        if !certs.is_empty() {
                            let _ = root_store.add_parsable_certificates(certs);
                        }
                    }
                }
            }
            let mut cfg_h2 = rustls::ClientConfig::builder()
                .with_root_certificates(root_store.clone())
                .with_no_client_auth();
            cfg_h2.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

            let mut cfg_h1 = rustls::ClientConfig::builder()
                .with_root_certificates(root_store.clone())
                .with_no_client_auth();
            cfg_h1.alpn_protocols = vec![b"http/1.1".to_vec()];

            let mut cfg_no_sni = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            cfg_no_sni.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            cfg_no_sni.enable_sni = false;
            (
                Some(Arc::new(cfg_h2)),
                Some(Arc::new(cfg_h1)),
                Some(Arc::new(cfg_no_sni)),
            )
        } else {
            (None, None, None)
        };

        Ok(Self {
            scheme,
            connect_addr,
            host_header,
            server_name,
            base_path,
            tls_config,
            tls_config_h1,
            tls_config_no_sni,
            prefer_no_sni: Arc::new(AtomicBool::new(false)),
            conn_pool: Arc::new(tokio::sync::Mutex::new(None)),
        })
    }

    pub async fn post_json<Req: Serialize, Resp: DeserializeOwned>(
        &self,
        path: &str,
        payload: &Req,
        timeout_dur: Duration,
    ) -> Result<Resp, ControlError> {
        let body_bytes =
            serde_json::to_vec(payload).map_err(|e| ControlError::Invalid(e.to_string()))?;
        if body_bytes.len() > (64 << 10) {
            return Err(ControlError::Invalid(
                "request exceeds 64KiB limit".to_string(),
            ));
        }
        let full_path = if self.base_path.is_empty() {
            path.to_string()
        } else {
            format!("{}{}", self.base_path, path)
        };

        let fut = async {
            let mut pool_guard = self.conn_pool.lock().await;
            let mut outcome = None;

            if let Some(mut pooled) = pool_guard.take() {
                if pooled.ready().await.is_ok() {
                    if let Ok(res) = self
                        .send_on_conn(&mut pooled, &full_path, &body_bytes)
                        .await
                    {
                        *pool_guard = Some(pooled);
                        outcome = Some(res);
                    }
                }
            }

            let (status, auth_rejected, resp_bytes) = match outcome {
                Some(res) => res,
                None => {
                    let mut last_err =
                        ControlError::Transport("control connection failed".to_string());
                    let mut connected_res = None;
                    for attempt in 0..3 {
                        let force_h1 = attempt == 2;
                        match self.open_pooled_conn(force_h1).await {
                            Ok(mut pooled) => {
                                match self
                                    .send_on_conn(&mut pooled, &full_path, &body_bytes)
                                    .await
                                {
                                    Ok(res) => {
                                        *pool_guard = Some(pooled);
                                        connected_res = Some(res);
                                        break;
                                    }
                                    Err(e) => {
                                        last_err = e;
                                    }
                                }
                            }
                            Err(e) => {
                                last_err = e;
                            }
                        }
                        if attempt + 1 < 3 {
                            tokio::time::sleep(Duration::from_millis(150 * (attempt as u64 + 1)))
                                .await;
                        }
                    }
                    match connected_res {
                        Some(res) => res,
                        None => return Err(last_err),
                    }
                }
            };

            match status.as_u16() {
                200 => serde_json::from_slice::<Resp>(&resp_bytes)
                    .map_err(|e| ControlError::Invalid(e.to_string())),
                401 if auth_rejected || is_master_auth_error(&resp_bytes) => {
                    Err(ControlError::Rejected)
                }
                400 => Err(ControlError::Invalid("bad request".to_string())),
                code => Err(ControlError::Transport(format!("HTTP {}", code))),
            }
        };

        tokio::time::timeout(timeout_dur, fut)
            .await
            .map_err(|_| ControlError::Transport("request timeout".to_string()))?
    }

    async fn connect_tcp(&self, prefer_clean_dns: bool) -> Result<TcpStream, ControlError> {
        let mut addrs: Vec<SocketAddr> = if let Ok(sa) = self.connect_addr.parse::<SocketAddr>() {
            vec![sa]
        } else if prefer_clean_dns {
            match udp_dns_lookup_addrs(&self.connect_addr).await {
                Ok(v) if !v.is_empty() => v,
                _ => tokio::time::timeout(
                    Duration::from_secs(5),
                    tokio::net::lookup_host(&self.connect_addr),
                )
                .await
                .map_err(|_| ControlError::Transport("dns lookup timeout".to_string()))?
                .map_err(|e| ControlError::Transport(e.to_string()))?
                .collect(),
            }
        } else {
            match tokio::time::timeout(
                Duration::from_secs(5),
                tokio::net::lookup_host(&self.connect_addr),
            )
            .await
            {
                Ok(Ok(iter)) => {
                    let v: Vec<SocketAddr> = iter.collect();
                    if v.is_empty() {
                        udp_dns_lookup_addrs(&self.connect_addr).await?
                    } else {
                        v
                    }
                }
                _ => udp_dns_lookup_addrs(&self.connect_addr).await?,
            }
        };
        if addrs.is_empty() {
            return Err(ControlError::Transport(
                "no resolved control addresses".to_string(),
            ));
        }
        addrs.sort_by_key(|a| if a.is_ipv4() { 0 } else { 1 });
        let mut last_err = None;
        for addr in addrs {
            match tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
                Ok(Ok(tcp)) => {
                    let _ = tcp.set_nodelay(true);
                    let sock_ref = socket2::SockRef::from(&tcp);
                    let ka = socket2::TcpKeepalive::new()
                        .with_time(Duration::from_secs(30))
                        .with_interval(Duration::from_secs(10));
                    let _ = sock_ref.set_tcp_keepalive(&ka);
                    return Ok(tcp);
                }
                Ok(Err(e)) => last_err = Some(ControlError::Transport(e.to_string())),
                Err(_) => {
                    last_err = Some(ControlError::Transport("tcp connect timeout".to_string()))
                }
            }
        }
        Err(last_err.unwrap_or_else(|| ControlError::Transport("tcp connect failed".to_string())))
    }

    async fn open_pooled_conn(&self, force_h1: bool) -> Result<PooledConn, ControlError> {
        let use_no_sni_first = self.prefer_no_sni.load(Ordering::Relaxed);
        let tcp = self.connect_tcp(use_no_sni_first).await?;
        let tls_opt = if use_no_sni_first {
            self.tls_config_no_sni.as_ref().or(self.tls_config.as_ref())
        } else if force_h1 {
            self.tls_config_h1.as_ref().or(self.tls_config.as_ref())
        } else {
            self.tls_config.as_ref()
        };
        if let Some(tls_cfg) = tls_opt {
            let connector = TlsConnector::from(Arc::clone(tls_cfg));
            let sni = ServerName::try_from(self.server_name.clone())
                .map_err(|_| ControlError::Transport("invalid control server name".to_string()))?;
            let first_try = tokio::time::timeout(
                Duration::from_secs(6),
                connector.connect(sni.clone(), tcp),
            )
            .await;
            let tls_stream = match first_try {
                Ok(Ok(s)) => s,
                first_err => {
                    // Carrier DPI walls may inject TCP RST when ClientHello contains a blocked SNI.
                    // Retry with SNI-less ClientHello (or normal SNI if prefer_no_sni was cached) while
                    // still verifying the server certificate against `sni` and routing via HTTP Host.
                    let fallback_cfg = if use_no_sni_first {
                        if force_h1 {
                            self.tls_config_h1.as_ref().or(self.tls_config.as_ref())
                        } else {
                            self.tls_config.as_ref()
                        }
                    } else {
                        self.tls_config_no_sni.as_ref()
                    };
                    if let Some(alt_cfg) = fallback_cfg {
                        let tcp2 = self.connect_tcp(!use_no_sni_first).await?;
                        let alt_connector = TlsConnector::from(Arc::clone(alt_cfg));
                        let s = tokio::time::timeout(
                            Duration::from_secs(6),
                            alt_connector.connect(sni, tcp2),
                        )
                        .await
                        .map_err(|_| ControlError::Transport("tls handshake timeout".to_string()))?
                        .map_err(|e| ControlError::Transport(e.to_string()))?;
                        self.prefer_no_sni
                            .store(!use_no_sni_first, Ordering::Relaxed);
                        s
                    } else {
                        return match first_err {
                            Err(_) => Err(ControlError::Transport(
                                "tls handshake timeout".to_string(),
                            )),
                            Ok(Err(e)) => Err(ControlError::Transport(e.to_string())),
                            Ok(Ok(_)) => unreachable!(),
                        };
                    }
                }
            };
            let is_h2 = tls_stream.get_ref().1.alpn_protocol() == Some(b"h2");
            let io = TokioIo::new(tls_stream);
            if is_h2 {
                let mut builder = hyper::client::conn::http2::Builder::new(TokioExecutor::new());
                builder
                    .timer(TokioTimer::new())
                    .keep_alive_interval(Some(Duration::from_secs(20)))
                    .keep_alive_timeout(Duration::from_secs(10))
                    .keep_alive_while_idle(true);
                let (sender, conn) = builder
                    .handshake(io)
                    .await
                    .map_err(|e| ControlError::Transport(e.to_string()))?;
                tokio::spawn(async move {
                    let _ = conn.await;
                });
                Ok(PooledConn::Http2(sender))
            } else {
                let (sender, conn) = hyper::client::conn::http1::handshake(io)
                    .await
                    .map_err(|e| ControlError::Transport(e.to_string()))?;
                tokio::spawn(async move {
                    let _ = conn.await;
                });
                Ok(PooledConn::Http1(sender))
            }
        } else {
            let io = TokioIo::new(tcp);
            let (sender, conn) = hyper::client::conn::http1::handshake(io)
                .await
                .map_err(|e| ControlError::Transport(e.to_string()))?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            Ok(PooledConn::Http1(sender))
        }
    }

    async fn send_on_conn(
        &self,
        conn: &mut PooledConn,
        full_path: &str,
        body_bytes: &[u8],
    ) -> Result<(hyper::StatusCode, bool, Vec<u8>), ControlError> {
        let res = match conn {
            PooledConn::Http2(sender) => {
                let uri = format!("{}://{}{}", self.scheme, self.host_header, full_path);
                let req = Request::builder()
                    .method("POST")
                    .uri(&uri)
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .header("User-Agent", DEFAULT_USER_AGENT)
                    .header("Content-Length", body_bytes.len().to_string())
                    .body(Full::new(Bytes::copy_from_slice(body_bytes)))
                    .map_err(|e| ControlError::Transport(e.to_string()))?;
                sender
                    .send_request(req)
                    .await
                    .map_err(|e| ControlError::Transport(e.to_string()))?
            }
            PooledConn::Http1(sender) => {
                let req = Request::builder()
                    .method("POST")
                    .uri(full_path)
                    .header("Host", &self.host_header)
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .header("User-Agent", DEFAULT_USER_AGENT)
                    .header("Connection", "keep-alive")
                    .header("Content-Length", body_bytes.len().to_string())
                    .body(Full::new(Bytes::copy_from_slice(body_bytes)))
                    .map_err(|e| ControlError::Transport(e.to_string()))?;
                sender
                    .send_request(req)
                    .await
                    .map_err(|e| ControlError::Transport(e.to_string()))?
            }
        };
        let status = res.status();
        let auth_rejected = res
            .headers()
            .get("x-veilink-auth-rejected")
            .and_then(|v| v.to_str().ok())
            == Some("1");
        let limited = http_body_util::Limited::new(res.into_body(), 4 << 20);
        let collected = limited
            .collect()
            .await
            .map_err(|e| ControlError::Transport(e.to_string()))?
            .to_bytes();
        Ok((status, auth_rejected, collected.to_vec()))
    }
}

pub(crate) fn is_master_auth_error(bytes: &[u8]) -> bool {
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(bytes) {
        if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
            return err == "authentication required" || err == "credential_rejected";
        }
    }
    false
}

fn split_host_port_opt(addr: &str) -> (String, Option<String>) {
    if let Some(rest) = addr.strip_prefix('[') {
        if let Some((h, after)) = rest.split_once(']') {
            let port = after.strip_prefix(':').map(|p| p.to_string());
            return (h.to_string(), port);
        }
    }
    if let Some((h, p)) = addr.rsplit_once(':') {
        return (h.to_string(), Some(p.to_string()));
    }
    (addr.to_string(), None)
}

pub(crate) async fn udp_dns_lookup_addrs(host_port: &str) -> Result<Vec<SocketAddr>, ControlError> {
    let (host, port_opt) = split_host_port_opt(host_port);
    let port: u16 = port_opt
        .as_deref()
        .unwrap_or("443")
        .parse()
        .map_err(|_| ControlError::Transport("invalid port".to_string()))?;
    if let Ok(ip) = host.parse::< std::net::IpAddr >() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let query = build_dns_a_query(&host)
        .ok_or_else(|| ControlError::Transport("invalid dns host".to_string()))?;
    for dns_srv in ["119.29.29.29:53", "180.76.76.76:53", "1.1.1.1:53"] {
        let Ok(sock) = tokio::net::UdpSocket::bind("0.0.0.0:0").await else {
            continue;
        };
        if sock.send_to(&query, dns_srv).await.is_err() {
            continue;
        }
        let mut buf = [0u8; 512];
        if let Ok(Ok((n, _))) =
            tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut buf)).await
        {
            let ips = parse_dns_a_response(&buf[..n]);
            if !ips.is_empty() {
                return Ok(ips
                    .into_iter()
                    .map(|ip| SocketAddr::new(std::net::IpAddr::V4(ip), port))
                    .collect());
            }
        }
    }
    Err(ControlError::Transport(
        "dns lookup failed across all resolvers".to_string(),
    ))
}

fn build_dns_a_query(domain: &str) -> Option<Vec<u8>> {
    let domain = domain.trim_end_matches('.');
    if domain.is_empty() {
        return None;
    }
    let mut pkt = Vec::with_capacity(64);
    pkt.extend_from_slice(&[0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in domain.split('.') {
        let b = label.as_bytes();
        if b.is_empty() || b.len() > 63 {
            return None;
        }
        pkt.push(b.len() as u8);
        pkt.extend_from_slice(b);
    }
    pkt.push(0);
    pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    Some(pkt)
}

fn skip_dns_name(buf: &[u8], mut pos: usize) -> Option<usize> {
    let mut jumps = 0;
    loop {
        let b = *buf.get(pos)?;
        if b == 0 {
            return Some(pos + 1);
        }
        if (b & 0xC0) == 0xC0 {
            let _ = *buf.get(pos + 1)?;
            return Some(pos + 2);
        }
        if (b & 0xC0) != 0 {
            return None;
        }
        pos = pos.checked_add(1 + b as usize)?;
        jumps += 1;
        if jumps > 64 || pos > buf.len() {
            return None;
        }
    }
}

fn parse_dns_a_response(buf: &[u8]) -> Vec<std::net::Ipv4Addr> {
    if buf.len() < 12 || (buf[3] & 0x0F) != 0 {
        return Vec::new();
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    let mut pos = 12;
    for _ in 0..qdcount {
        let Some(next) = skip_dns_name(buf, pos) else {
            return Vec::new();
        };
        pos = next + 4;
        if pos > buf.len() {
            return Vec::new();
        }
    }
    let mut out = Vec::new();
    for _ in 0..ancount {
        let Some(next) = skip_dns_name(buf, pos) else {
            break;
        };
        pos = next;
        if pos + 10 > buf.len() {
            break;
        }
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let rclass = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]);
        let rdlen = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > buf.len() {
            break;
        }
        if rtype == 1 && rclass == 1 && rdlen == 4 {
            out.push(std::net::Ipv4Addr::new(
                buf[pos],
                buf[pos + 1],
                buf[pos + 2],
                buf[pos + 3],
            ));
        }
        pos += rdlen;
    }
    out
}
pub fn build_heartbeat_request(
    node_id: &str,
    credential: &str,
    revision: i64,
    failed: bool,
    ring: Option<&Ring>,
    links: Option<Vec<String>>,
    traffic: Option<(String, u64, HashMap<String, TrafficBytesPayload>)>,
) -> Result<EventsRequest, String> {
    let applied_revision = if revision < 0 { 0 } else { revision };
    let error = if failed {
        "apply failed".to_string()
    } else {
        String::new()
    };
    let (traffic_epoch, traffic_seq, traffic_map) = match traffic {
        Some((epoch, seq, map)) if map.len() <= 128 => (epoch, seq, Some(map)),
        _ => (String::new(), 0, None),
    };
    let mut req = EventsRequest {
        node_id: node_id.to_string(),
        credential: credential.to_string(),
        applied_revision,
        error,
        software_version: buildinfo::version().to_string(),
        software_commit: buildinfo::commit().to_string(),
        links,
        traffic: traffic_map,
        traffic_epoch,
        traffic_seq,
        logs: Vec::new(),
    };
    let base_len = serde_json::to_vec(&req)
        .map_err(|e| e.to_string())?
        .len();
    if base_len > (64 << 10) {
        return Err("heartbeat identity exceeds size limit".to_string());
    }
    if let Some(r) = ring {
        for entry in r.drain() {
            req.logs.push(entry);
            let encoded_len = serde_json::to_vec(&req).map(|v| v.len()).unwrap_or(usize::MAX);
            if encoded_len > (60 << 10) {
                req.logs.pop();
                break;
            }
        }
    }
    Ok(req)
}

pub async fn run(cancel: CancellationToken, c: Config, role: &str) -> Result<(), NodeError> {
    run_with_ring(cancel, c, role, None).await
}

pub fn parse_bootstrap_state(raw: &str) -> Result<DiskState, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("empty bootstrap state".to_string());
    }
    let bytes = if trimmed.starts_with('{') {
        trimmed.as_bytes().to_vec()
    } else if Path::new(trimmed).is_file() {
        let file_bytes =
            fs::read(trimmed).map_err(|e| format!("read bootstrap state file: {}", e))?;
        let file_str = String::from_utf8_lossy(&file_bytes);
        let ft = file_str.trim();
        if ft.starts_with('{') {
            ft.as_bytes().to_vec()
        } else {
            decode_base64_flexible(ft)?
        }
    } else {
        decode_base64_flexible(trimmed)?
    };
    if let Ok(mut ds) = serde_json::from_slice::<DiskState>(&bytes) {
        if ds.node_id.is_empty() {
            if let Some(ref snap) = ds.snapshot {
                ds.node_id = snap.node.id.clone();
            }
        }
        if !ds.node_id.is_empty() && ds.snapshot.is_some() {
            return Ok(ds);
        }
    }
    if let Ok(snap) = serde_json::from_slice::<Snapshot>(&bytes) {
        if !snap.node.id.is_empty() {
            return Ok(DiskState {
                node_id: snap.node.id.clone(),
                master: String::new(),
                credential: String::new(),
                snapshot: Some(snap),
            });
        }
    }
    Err("invalid bootstrap state payload".to_string())
}

fn decode_base64_flexible(s: &str) -> Result<Vec<u8>, String> {
    let compact: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&compact)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(&compact))
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(&compact))
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(&compact))
        .map_err(|e| format!("invalid base64 bootstrap state: {}", e))
}

pub async fn run_with_ring(
    cancel: CancellationToken,
    mut c: Config,
    role: &str,
    external_ring: Option<Arc<Ring>>,
) -> Result<(), NodeError> {
    c.validate(role).map_err(NodeError::Other)?;
    let boot_opt = if !c.bootstrap_state.trim().is_empty() {
        let b = parse_bootstrap_state(&c.bootstrap_state).map_err(NodeError::Other)?;
        if c.node_id.is_empty() {
            c.node_id = b.node_id.clone();
        } else if !b.node_id.is_empty() && b.node_id != c.node_id {
            return Err(NodeError::Other(
                "bootstrap state node_id mismatch".to_string(),
            ));
        }
        if c.master_addr.is_empty() && !b.master.is_empty() {
            c.master_addr = b.master.clone();
        }
        Some(b)
    } else {
        None
    };
    if c.node_id.is_empty() {
        return Err(NodeError::Other("node_id required".to_string()));
    }

    let is_embedded = external_ring.is_some();
    let ring = external_ring.unwrap_or_else(|| Arc::new(Ring::new(1000)));
    ring.push_entry(
        "node",
        &c.node_id,
        "INFO",
        &format!("node starting role={} node_id={}", role, c.node_id),
    );

    let offline_master = c.master_addr.trim().is_empty()
        || c.master_addr.trim().eq_ignore_ascii_case("offline")
        || c.master_addr.trim().eq_ignore_ascii_case("none");
    let client_opt = if offline_master {
        None
    } else {
        Some(HttpControlClient::new(&c).map_err(NodeError::Other)?)
    };

    fs::create_dir_all(&c.state_dir).map_err(|e| NodeError::Other(e.to_string()))?;
    set_mode(Path::new(&c.state_dir), 0o700)
        .map_err(|e| NodeError::Other(e.to_string()))?;

    let state_path = PathBuf::from(&c.state_dir).join("state.json");
    let mut st = DiskState {
        node_id: c.node_id.clone(),
        master: c.master_addr.clone(),
        credential: String::new(),
        snapshot: None,
    };
    if let Ok(bytes) = fs::read(&state_path) {
        let mut parsed: DiskState = serde_json::from_slice(&bytes)
            .map_err(|_| NodeError::Other("local state identity mismatch or corruption".to_string()))?;
        if parsed.node_id != c.node_id
            || (boot_opt.is_none() && !offline_master && parsed.master != c.master_addr)
        {
            return Err(NodeError::Other(
                "local state identity mismatch or corruption".to_string(),
            ));
        }
        if !c.master_addr.is_empty() {
            parsed.master = c.master_addr.clone();
        }
        set_mode(&state_path, 0o600)
            .map_err(|e| NodeError::Other(e.to_string()))?;
        st = parsed;
    }
    if let Some(boot) = boot_opt {
        let mut updated = !state_path.exists();
        if !boot.credential.is_empty() && st.credential.is_empty() {
            st.credential = boot.credential;
            updated = true;
        }
        if let Some(boot_snap) = boot.snapshot {
            let should_apply_boot = match st.snapshot.as_ref() {
                Some(cur) => boot_snap.revision >= cur.revision,
                None => true,
            };
            if should_apply_boot {
                if st.snapshot.as_ref() != Some(&boot_snap) {
                    updated = true;
                }
                st.snapshot = Some(boot_snap);
            }
        }
        if !c.master_addr.is_empty() && st.master != c.master_addr {
            st.master = c.master_addr.clone();
            updated = true;
        }
        if updated {
            save_disk_state(&state_path, &st).map_err(NodeError::Other)?;
        }
    }

    let runtime = Arc::new(Runtime::new(LocalTLS::default()));
    runtime.set_logger(Arc::clone(&ring), c.node_id.clone(), role.to_string());

    let applied_revision = Arc::new(AtomicI64::new(-1));
    let apply_failed = Arc::new(AtomicBool::new(false));
    let connected = Arc::new(AtomicBool::new(false));
    let traffic_seq = Arc::new(AtomicU64::new(0));
    let traffic_epoch = if role == "server" {
        let mut ep = [0u8; 16];
        rand::rng().fill_bytes(&mut ep);
        hex::encode(ep)
    } else {
        String::new()
    };

    if let Some(ref snap) = st.snapshot {
        if snap.node.id != c.node_id || snap.node.role != role {
            let _ = runtime.close();
            return Err(NodeError::Other(
                "cached node identity mismatch".to_string(),
            ));
        }
        match runtime.apply(snap.clone()) {
            Ok(()) => {
                applied_revision.store(runtime.revision(), Ordering::SeqCst);
                apply_failed.store(false, Ordering::SeqCst);
                if configuration_quiesced(Some(snap)) {
                    ring.push_entry(
                        "node",
                        &c.node_id,
                        "INFO",
                        &format!(
                            "tunnel stopped; configuration sync idle until the node is enabled role={} revision={}",
                            role, snap.revision
                        ),
                    );
                } else {
                    ring.push_entry(
                        "node",
                        &c.node_id,
                        "INFO",
                        &format!(
                            "runtime configuration applied role={} revision={}",
                            role, snap.revision
                        ),
                    );
                }
            }
            Err(err) => {
                apply_failed.store(true, Ordering::SeqCst);
                ring.push_entry(
                    "node",
                    &c.node_id,
                    "WARN",
                    &format!(
                        "runtime configuration apply failed role={} revision={} err={}",
                        role, snap.revision, err
                    ),
                );
            }
        }
    }

    let mut backoff = Duration::from_secs(1);

    let Some(client) = client_opt else {
        if st.snapshot.is_none() {
            let _ = runtime.close();
            return Err(NodeError::Other(
                "offline mode requires bootstrap_state or cached snapshot".to_string(),
            ));
        }
        ring.push_entry(
            "node",
            &c.node_id,
            "INFO",
            &format!(
                "running in standalone offline mode with exported runtime configuration role={} node_id={}",
                role, c.node_id
            ),
        );
        cancel.cancelled().await;
        let _ = runtime.close();
        return Ok(());
    };

    while !cancel.is_cancelled() {
        if st.credential.is_empty() {
            if c.enroll_token.is_empty() {
                if st.snapshot.is_some() {
                    ring.push_entry(
                        "node",
                        &c.node_id,
                        "INFO",
                        &format!(
                            "running with exported snapshot without control credential role={} node_id={}",
                            role, c.node_id
                        ),
                    );
                    cancel.cancelled().await;
                    break;
                }
                let _ = runtime.close();
                return Err(NodeError::Other(
                    "enrollment token required for first start".to_string(),
                ));
            }
            let enroll_req = EnrollRequest {
                node_id: c.node_id.clone(),
                token: c.enroll_token.clone(),
            };
            match client
                .post_json::<_, EnrollResponse>(PATH_ENROLL, &enroll_req, Duration::from_secs(10))
                .await
            {
                Ok(resp) => {
                    if resp.credential.is_empty() {
                        let _ = runtime.close();
                        return Err(NodeError::Other(
                            "empty enrollment credential".to_string(),
                        ));
                    }
                    st.credential = resp.credential;
                    if save_disk_state(&state_path, &st).is_err() {
                        let _ = runtime.close();
                        return Err(NodeError::Other(
                            "cannot persist node credential".to_string(),
                        ));
                    }
                    ring.push_entry(
                        "node",
                        &c.node_id,
                        "INFO",
                        &format!("node enrolled; credential saved role={} node_id={}", role, c.node_id),
                    );
                }
                Err(ControlError::Rejected) => {
                    let _ = runtime.close();
                    wipe_state(&state_path, &mut st).map_err(NodeError::Other)?;
                    return Err(NodeError::CredentialRejected);
                }
                Err(e) => {
                    if wait_backoff(&cancel, &mut backoff, &ring, &c.node_id, role, st.snapshot.as_ref(), &e.to_string()).await {
                        break;
                    }
                    continue;
                }
            }
        }

        let cycle_res = run_control_cycle(
            &cancel,
            &client,
            &c,
            role,
            is_embedded,
            &mut st,
            &state_path,
            &runtime,
            &ring,
            &applied_revision,
            &apply_failed,
            &connected,
            &traffic_epoch,
            &traffic_seq,
        )
        .await;

        match cycle_res {
            Ok(()) => {
                backoff = Duration::from_secs(1);
            }
            Err(ControlError::Rejected) => {
                let _ = runtime.close();
                wipe_state(&state_path, &mut st).map_err(NodeError::Other)?;
                return Err(NodeError::CredentialRejected);
            }
            Err(e) => {
                if cancel.is_cancelled() {
                    break;
                }
                connected.store(false, Ordering::SeqCst);
                if wait_backoff(
                    &cancel,
                    &mut backoff,
                    &ring,
                    &c.node_id,
                    role,
                    st.snapshot.as_ref(),
                    &e.to_string(),
                )
                .await
                {
                    break;
                }
            }
        }
    }

    let _ = runtime.close();
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_control_cycle(
    cancel: &CancellationToken,
    client: &HttpControlClient,
    c: &Config,
    role: &str,
    is_embedded: bool,
    st: &mut DiskState,
    state_path: &Path,
    runtime: &Arc<Runtime>,
    ring: &Arc<Ring>,
    applied_revision: &AtomicI64,
    apply_failed: &AtomicBool,
    connected: &AtomicBool,
    traffic_epoch: &str,
    traffic_seq: &AtomicU64,
) -> Result<(), ControlError> {
    let mut first = true;
    let mut wait_ms = 0u64;
    let mut post_apply_watch = false;
    let mut expected_bindings = 0usize;
    let drain_ring = if is_embedded { None } else { Some(ring.as_ref()) };

    while !cancel.is_cancelled() {
        let current_links = runtime.linked_bindings();
        let links = Some(current_links.clone());
        let traffic_payload = if role == "server" {
            let snap = runtime.traffic().snapshot();
            if snap.len() <= 128 {
                let mut map = HashMap::with_capacity(snap.len());
                for (k, v) in snap {
                    map.insert(
                        k,
                        TrafficBytesPayload {
                            up: v.up,
                            down: v.down,
                        },
                    );
                }
                let seq = traffic_seq.fetch_add(1, Ordering::Relaxed) + 1;
                Some((traffic_epoch.to_string(), seq, map))
            } else {
                None
            }
        } else {
            None
        };

        let hb_req = build_heartbeat_request(
            &c.node_id,
            &st.credential,
            applied_revision.load(Ordering::SeqCst),
            apply_failed.load(Ordering::SeqCst),
            drain_ring,
            links,
            traffic_payload,
        )
        .map_err(ControlError::Invalid)?;

        let events_path = if wait_ms > 0 {
            format!("{}?wait_ms={}", PATH_EVENTS, wait_ms)
        } else {
            PATH_EVENTS.to_string()
        };
        let timeout_dur = Duration::from_millis(wait_ms + 10_000);

        let ev_resp: EventsResponse = tokio::select! {
            _ = cancel.cancelled() => {
                if !hb_req.logs.is_empty() {
                    ring.append_batch(&hb_req.logs);
                }
                return Ok(());
            }
            res = client.post_json(&events_path, &hb_req, timeout_dur) => {
                match res {
                    Ok(v) => v,
                    Err(e) => {
                        if !hb_req.logs.is_empty() {
                            ring.append_batch(&hb_req.logs);
                        }
                        return Err(e);
                    }
                }
            }
        };

        if ev_resp.revision < 0 || ev_resp.revision > 9_007_199_254_740_991 {
            return Err(ControlError::Invalid("invalid desired revision".to_string()));
        }

        let current_rev = applied_revision.load(Ordering::SeqCst);
        let need_pull = first
            || ev_resp.revision > current_rev
            || apply_failed.load(Ordering::SeqCst);

        if need_pull {
            first = false;
            let pull_req = PullRequest {
                node_id: c.node_id.clone(),
                credential: st.credential.clone(),
            };
            let snap: Snapshot = tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                res = client.post_json(PATH_PULL, &pull_req, Duration::from_secs(10)) => res?,
            };
            if snap.node.id != c.node_id || snap.node.role != role || snap.node.revoked {
                return Err(ControlError::Rejected);
            }
            if snap.revision < current_rev {
                return Err(ControlError::Invalid("stale snapshot".to_string()));
            }
            if !connected.swap(true, Ordering::SeqCst) {
                ring.push_entry(
                    "node",
                    &c.node_id,
                    "INFO",
                    &format!("control connection established role={} node_id={}", role, c.node_id),
                );
            }
            let prev_rev = current_rev;
            let was_failed = apply_failed.load(Ordering::SeqCst);
            match runtime.apply(snap.clone()) {
                Ok(()) => {
                    let new_rev = runtime.revision();
                    applied_revision.store(new_rev, Ordering::SeqCst);
                    apply_failed.store(false, Ordering::SeqCst);
                    expected_bindings = snap.bindings.len();
                    post_apply_watch = expected_bindings > 0;
                    let snapshot_changed = st.snapshot.as_ref() != Some(&snap) || !state_path.exists();
                    st.snapshot = Some(snap.clone());
                    if snapshot_changed && save_disk_state(state_path, st).is_err() {
                        apply_failed.store(true, Ordering::SeqCst);
                        return Err(ControlError::Transport(
                            "cannot persist runtime cache".to_string(),
                        ));
                    }
                    if prev_rev != new_rev || was_failed {
                        if configuration_quiesced(Some(&snap)) {
                            ring.push_entry(
                                "node",
                                &c.node_id,
                                "INFO",
                                &format!(
                                    "tunnel stopped; configuration sync idle until the node is enabled role={} revision={}",
                                    role, snap.revision
                                ),
                            );
                        } else {
                            ring.push_entry(
                                "node",
                                &c.node_id,
                                "INFO",
                                &format!(
                                    "runtime configuration applied role={} revision={}",
                                    role, snap.revision
                                ),
                            );
                        }
                    }
                }
                Err(err) => {
                    applied_revision.store(runtime.revision(), Ordering::SeqCst);
                    apply_failed.store(true, Ordering::SeqCst);
                    expected_bindings = 0;
                    post_apply_watch = false;
                    ring.push_entry(
                        "node",
                        &c.node_id,
                        "WARN",
                        &format!(
                            "runtime configuration apply failed role={} revision={} err={}",
                            role, snap.revision, err
                        ),
                    );
                }
            }
            // Immediately report updated applied_revision & link state on next iteration while keeping long-poll active
            wait_ms = 0;
        } else if ev_resp.refresh {
            wait_ms = 0;
        } else if post_apply_watch {
            post_apply_watch = false;
            if runtime.linked_bindings().len() < expected_bindings {
                tokio::select! {
                    _ = cancel.cancelled() => return Ok(()),
                    _ = runtime.state_notified() => {
                        tokio::time::sleep(Duration::from_millis(15)).await;
                    }
                    _ = tokio::time::sleep(Duration::from_millis(250)) => {}
                }
            }
            wait_ms = if runtime.linked_bindings() != current_links
                || (!is_embedded && !ring.is_empty())
            {
                0
            } else {
                1_000
            };
        } else if runtime.linked_bindings() != current_links
            || (!is_embedded && !ring.is_empty())
        {
            wait_ms = 0;
        } else {
            wait_ms = 1_000;
        }
    }

    Ok(())
}

async fn wait_backoff(
    cancel: &CancellationToken,
    backoff: &mut Duration,
    ring: &Ring,
    node_id: &str,
    role: &str,
    snapshot: Option<&Snapshot>,
    err_msg: &str,
) -> bool {
    if configuration_quiesced(snapshot) {
        ring.push_entry(
            "node",
            node_id,
            "WARN",
            &format!(
                "control connection unavailable; tunnel remains stopped role={} err={}",
                role, err_msg
            ),
        );
    } else {
        ring.push_entry(
            "node",
            node_id,
            "WARN",
            &format!(
                "control connection unavailable; retaining last successful configuration role={} err={}",
                role, err_msg
            ),
        );
    }
    let jitter_ms = rand::rng().random_range(0..=(backoff.as_millis() as u64 / 2 + 1));
    let delay = *backoff + Duration::from_millis(jitter_ms);
    tokio::select! {
        _ = cancel.cancelled() => return true,
        _ = tokio::time::sleep(delay) => {}
    }
    if *backoff < Duration::from_secs(30) {
        *backoff = (*backoff * 2).min(Duration::from_secs(30));
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn test_parse_dns_cname_and_a_response() {
        let mut pkt = build_dns_a_query("vl.vekt.cc.cd").unwrap();
        // Turn query into response: QR=1, RCODE=0, QDCOUNT=1, ANCOUNT=2
        pkt[2] = 0x81;
        pkt[3] = 0x80;
        pkt[6] = 0x00;
        pkt[7] = 0x02;
        // Answer 1: CNAME (type 5) pointing to tfa.vekt.cc.cd
        pkt.extend_from_slice(&[
            0xC0, 0x0C, // name pointer
            0x00, 0x05, // TYPE CNAME
            0x00, 0x01, // CLASS IN
            0x00, 0x00, 0x01, 0x2C, // TTL
            0x00, 0x06, // RDLENGTH
            3, b't', b'f', b'a', 0xC0, 0x0F, // tfa.vekt.cc.cd
        ]);
        // Answer 2: A (type 1) = 36.138.249.195
        pkt.extend_from_slice(&[
            0xC0, 0x0C, // name pointer
            0x00, 0x01, // TYPE A
            0x00, 0x01, // CLASS IN
            0x00, 0x00, 0x01, 0x2C, // TTL
            0x00, 0x04, // RDLENGTH 4
            36, 138, 249, 195,
        ]);
        let ips = parse_dns_a_response(&pkt);
        assert_eq!(ips, vec![std::net::Ipv4Addr::new(36, 138, 249, 195)]);
    }

    #[tokio::test]
    async fn test_control_client_sni_rst_fallback() {
        let cert = rcgen::generate_simple_self_signed(vec![
            "*.vekt.cc.cd".to_string(),
            "vekt.cc.cd".to_string(),
        ])
        .unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();
        let tmp = tempfile::tempdir().unwrap();
        let ca_path = tmp.path().join("ca.pem");
        std::fs::write(&ca_path, &cert_pem).unwrap();

        let certs: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut std::io::BufReader::new(cert_pem.as_bytes()))
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
        let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(key_pem.as_bytes()))
            .unwrap()
            .unwrap();
        let mut srv_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        srv_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(srv_cfg));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let sni_rst_count = Arc::new( std::sync::atomic::AtomicUsize::new(0) );
        let sni_rst_clone = Arc::clone(&sni_rst_count);

        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    break;
                };
                let mut peek_buf = [0u8; 1024];
                let n = tcp.peek(&mut peek_buf).await.unwrap_or(0);
                if peek_buf[..n]
                    .windows(b"vl.vekt.cc.cd".len())
                    .any(|w| w == b"vl.vekt.cc.cd")
                {
                    sni_rst_clone.fetch_add(1, Ordering::SeqCst);
                    // Simulate TCP RST by enabling linger=0 and dropping
                    let sock_ref = socket2::SockRef::from(&tcp);
                    let _ = sock_ref.set_linger(Some(Duration::ZERO));
                    drop(tcp);
                    continue;
                }
                let acc = acceptor.clone();
                tokio::spawn(async move {
                    if let Ok(mut tls) = acc.accept(tcp).await {
                        let mut req_buf = vec![0u8; 4096];
                        let n = tls.read(&mut req_buf).await.unwrap_or(0);
                        let req_str = String::from_utf8_lossy(&req_buf[..n]);
                        assert!(
                            req_str
                                .to_ascii_lowercase()
                                .contains(&format!("host: vl.vekt.cc.cd:{}", addr.port()))
                        );
                        let body = r#"{"revision":42,"refresh":false}"#;
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = tls.write_all(resp.as_bytes()).await;
                        let _ = tls.flush().await;
                    }
                });
            }
        });

        let cfg = Config {
            master_addr: format!("https://{}", addr),
            node_id: "node-1".to_string(),
            state_dir: tmp.path().to_string_lossy().to_string(),
            control_ca: ca_path.to_string_lossy().to_string(),
            control_server_name: "vl.vekt.cc.cd".to_string(),
            ..Config::default()
        };
        let client = HttpControlClient::new(&cfg).unwrap();
        let req = serde_json::json!({"hello": "world"});
        let resp: EventsResponse = client
            .post_json("/api/v1/node/events", &req, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(resp.revision, 42);
        assert_eq!(sni_rst_count.load(Ordering::SeqCst), 1);
        assert!(client.prefer_no_sni.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn test_offline_bootstrap_state_runs_tunnel_when_hub_unreachable() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("veilink.db");
        let key_path = tmp.path().join("veilink.key");
        let store = crate::store::Store::open(
            db_path.to_str().unwrap(),
            key_path.to_str().unwrap(),
        )
        .unwrap();

        // Pick free ports for tunnel server, mapping listen, and target echo server
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo_listener.local_addr().unwrap().port() as i64;
        tokio::spawn(async move {
            while let Ok((mut s, _)) = echo_listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    if let Ok(n) = s.read(&mut buf).await {
                        let _ = s.write_all(&buf[..n]).await;
                    }
                });
            }
        });

        let tun_port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port() as i64
        };
        let map_port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port() as i64
        };

        let (dec_str, _, _, _) = crate::tunnel::generate_vless_enc().unwrap();
        let srv_tunnel = LocalTLS {
            listen_host: "127.0.0.1".to_string(),
            listen_port: tun_port,
            transport_security: "plain".to_string(),
            decryption: dec_str,
            ..Default::default()
        };

        store
            .save_node(crate::model::Node {
                id: "srv-offline".to_string(),
                name: "srv-offline".to_string(),
                role: "server".to_string(),
                address: "127.0.0.1".to_string(),
                port: tun_port,
                connect_endpoints: vec![crate::model::ConnectEndpoint {
                    id: "ep-1".to_string(),
                    name: "local".to_string(),
                    host: "127.0.0.1".to_string(),
                    port: tun_port,
                    enabled: true,
                }],
                tunnel: srv_tunnel,
                ..Default::default()
            })
            .unwrap();
        store
            .save_node(crate::model::Node {
                id: "cli-offline".to_string(),
                name: "cli-offline".to_string(),
                role: "client".to_string(),
                ..Default::default()
            })
            .unwrap();
        store
            .save_mapping(crate::model::Mapping {
                id: "map-offline".to_string(),
                name: "map-offline".to_string(),
                server_id: "srv-offline".to_string(),
                client_id: "cli-offline".to_string(),
                connect_endpoint_id: "ep-1".to_string(),
                listen_host: "127.0.0.1".to_string(),
                listen_port: map_port,
                target_host: "127.0.0.1".to_string(),
                target_port: echo_port,
                network: "tcp".to_string(),
                pool: 1,
                enabled: true,
                ..Default::default()
            })
            .unwrap();

        // Export offline bootstrap states from Hub while Hub itself will NOT be reachable by nodes
        let (srv_cred, srv_snap) = store.ensure_credential_and_snapshot("srv-offline").unwrap();
        let (cli_cred, cli_snap) = store.ensure_credential_and_snapshot("cli-offline").unwrap();

        let srv_boot = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&DiskState {
                node_id: "srv-offline".to_string(),
                master: "http://127.0.0.1:9".to_string(),
                credential: srv_cred,
                snapshot: Some(srv_snap),
            })
            .unwrap(),
        );
        let cli_boot = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&DiskState {
                node_id: "cli-offline".to_string(),
                master: "http://127.0.0.1:9".to_string(),
                credential: cli_cred,
                snapshot: Some(cli_snap),
            })
            .unwrap(),
        );

        let cancel = CancellationToken::new();
        let srv_cfg = Config {
            master_addr: "http://127.0.0.1:9".to_string(),
            node_id: "srv-offline".to_string(),
            state_dir: tmp.path().join("srv-state").to_string_lossy().to_string(),
            bootstrap_state: srv_boot,
            ..Config::default()
        };
        let cli_cfg = Config {
            master_addr: "http://127.0.0.1:9".to_string(),
            node_id: "cli-offline".to_string(),
            state_dir: tmp.path().join("cli-state").to_string_lossy().to_string(),
            bootstrap_state: cli_boot,
            ..Config::default()
        };

        let c1 = cancel.clone();
        let srv_jh = tokio::spawn(async move { run(c1, srv_cfg, "server").await });
        let c2 = cancel.clone();
        let cli_jh = tokio::spawn(async move { run(c2, cli_cfg, "client").await });

        // Wait until tunnel links up and mapped port responds
        let mut ok = false;
        for _ in 0..40 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if let Ok(mut s) = TcpStream::connect(("127.0.0.1", map_port as u16)).await {
                if s.write_all(b"offline-bootstrap-ping").await.is_ok() {
                    let mut buf = [0u8; 64];
                    if let Ok(Ok(n)) =
                        tokio::time::timeout(Duration::from_secs(2), s.read(&mut buf)).await
                    {
                        if &buf[..n] == b"offline-bootstrap-ping" {
                            ok = true;
                            break;
                        }
                    }
                }
            }
        }
        cancel.cancel();
        let _ = srv_jh.await;
        let _ = cli_jh.await;
        assert!(ok, "tunnel should work via exported bootstrap_state even when hub is unreachable");
    }
}
