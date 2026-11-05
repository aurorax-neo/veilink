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
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::rt::TokioIo;
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

#[derive(Clone)]
pub struct HttpControlClient {
    #[allow(dead_code)]
    scheme: String,
    connect_addr: String,
    host_header: String,
    server_name: String,
    base_path: String,
    tls_config: Option<Arc<rustls::ClientConfig>>,
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
                let host_hdr = match u.port() {
                    Some(p) => format!("{}:{}", host, p),
                    None => host.clone(),
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
                let host_only = split_host(raw);
                (
                    sch,
                    raw.to_string(),
                    raw.to_string(),
                    host_only,
                    String::new(),
                )
            };

        let server_name = if !c.control_server_name.is_empty() {
            c.control_server_name.clone()
        } else {
            default_sni
        };

        let tls_config = if scheme == "https" {
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
            }
            let cfg = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            Some(Arc::new(cfg))
        } else {
            None
        };

        Ok(Self {
            scheme,
            connect_addr,
            host_header,
            server_name,
            base_path,
            tls_config,
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
            let tcp = TcpStream::connect(&self.connect_addr)
                .await
                .map_err(|e| ControlError::Transport(e.to_string()))?;
            let _ = tcp.set_nodelay(true);

            let req = Request::builder()
                .method("POST")
                .uri(&full_path)
                .header("Host", &self.host_header)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .header("Content-Length", body_bytes.len().to_string())
                .body(Full::new(Bytes::from(body_bytes)))
                .map_err(|e| ControlError::Transport(e.to_string()))?;

            let (status, auth_rejected, resp_bytes) = if let Some(ref tls_cfg) = self.tls_config {
                let connector = TlsConnector::from(Arc::clone(tls_cfg));
                let sni = ServerName::try_from(self.server_name.clone())
                    .map_err(|_| ControlError::Transport("invalid control server name".to_string()))?;
                let tls_stream = connector
                    .connect(sni, tcp)
                    .await
                    .map_err(|e| ControlError::Transport(e.to_string()))?;
                send_http1_request(tls_stream, req).await?
            } else {
                send_http1_request(tcp, req).await?
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
}

async fn send_http1_request<S>(
    stream: S,
    req: Request<Full<Bytes>>,
) -> Result<(hyper::StatusCode, bool, Vec<u8>), ControlError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| ControlError::Transport(e.to_string()))?;
    let conn_task = tokio::spawn(async move {
        let _ = conn.await;
    });
    let res = sender
        .send_request(req)
        .await
        .map_err(|e| ControlError::Transport(e.to_string()))?;
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
    conn_task.abort();
    Ok((status, auth_rejected, collected.to_vec()))
}

pub(crate) fn is_master_auth_error(bytes: &[u8]) -> bool {
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(bytes) {
        if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
            return err == "authentication required" || err == "credential_rejected";
        }
    }
    false
}

fn split_host(addr: &str) -> String {
    if let Some(rest) = addr.strip_prefix('[') {
        if let Some((h, _)) = rest.split_once(']') {
            return h.to_string();
        }
    }
    if let Some((h, _)) = addr.rsplit_once(':') {
        return h.to_string();
    }
    addr.to_string()
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

pub async fn run_with_ring(
    cancel: CancellationToken,
    c: Config,
    role: &str,
    external_ring: Option<Arc<Ring>>,
) -> Result<(), NodeError> {
    c.validate(role).map_err(NodeError::Other)?;
    let ring = external_ring.unwrap_or_else(|| Arc::new(Ring::new(1000)));
    ring.push_entry(
        "node",
        &c.node_id,
        "INFO",
        &format!("node starting role={} node_id={}", role, c.node_id),
    );

    let client = HttpControlClient::new(&c).map_err(NodeError::Other)?;

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
        let parsed: DiskState = serde_json::from_slice(&bytes)
            .map_err(|_| NodeError::Other("local state identity mismatch or corruption".to_string()))?;
        if parsed.node_id != c.node_id || parsed.master != c.master_addr {
            return Err(NodeError::Other(
                "local state identity mismatch or corruption".to_string(),
            ));
        }
        set_mode(&state_path, 0o600)
            .map_err(|e| NodeError::Other(e.to_string()))?;
        st = parsed;
    }

    let runtime = Arc::new(Runtime::new(LocalTLS::default()));

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
            }
            Err(_) => {
                apply_failed.store(true, Ordering::SeqCst);
            }
        }
    }

    let mut backoff = Duration::from_secs(1);

    while !cancel.is_cancelled() {
        if st.credential.is_empty() {
            if c.enroll_token.is_empty() {
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

    while !cancel.is_cancelled() {
        let links = Some(runtime.linked_bindings());
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
            Some(ring.as_ref()),
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
            _ = cancel.cancelled() => return Ok(()),
            res = client.post_json(&events_path, &hb_req, timeout_dur) => res?,
        };

        if ev_resp.revision < 0 || ev_resp.revision > 9_007_199_254_740_991 {
            return Err(ControlError::Invalid("invalid desired revision".to_string()));
        }

        let current_rev = applied_revision.load(Ordering::SeqCst);
        let need_pull =
            first || ev_resp.revision > current_rev || apply_failed.load(Ordering::SeqCst);

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
            wait_ms = 2_000;
        } else {
            wait_ms = 2_000;
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
