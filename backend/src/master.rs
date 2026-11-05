use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::ConnectInfo;
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder as AutoConnBuilder;
use hyper_util::service::TowerToHyperService;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

use crate::config::{self, Config};
use crate::httpapi::{Api, WebPersistConfig};
use crate::logring::Ring;
use crate::model::{ConnectEndpoint, LocalTLS, Node};
use crate::node::{self, DiskState, NodeError};
use crate::store::{Store, StoreError};

pub async fn run(cancel: CancellationToken, c: Config) -> Result<(), String> {
    if c.database.is_empty() || c.deployment_key.is_empty() {
        return Err("database and deployment_key bootstrap paths required".to_string());
    }
    let store = Arc::new(
        Store::open(&c.database, &c.deployment_key).map_err(|e| e.to_string())?,
    );
    let (mut c, commit_config) = config::resolve_master(c)?;
    let ring = Arc::new(Ring::new(2000));

    let mode = c.scheme.clone();
    let tls_acceptor = if mode == "https" {
        let tls_cfg = load_server_tls_config(&c.cert_file, &c.key_file)?;
        Some(TlsAcceptor::from(Arc::new(tls_cfg)))
    } else {
        None
    };

    let listener = TcpListener::bind(&c.listen_addr)
        .await
        .map_err(|e| e.to_string())?;
    if let Ok(bound) = listener.local_addr() {
        if c.listen_addr.ends_with(":0") {
            c.listen_addr = bound.to_string();
        }
    }

    let api = Api::new(
        Arc::clone(&store),
        mode == "http",
        Some(Arc::clone(&ring)),
        WebPersistConfig {
            db_path: c.database.clone(),
            html_dir: c.html_dir.clone(),
        },
    );
    let router = api.into_router();

    commit_config()?;

    ring.push_entry(
        "master",
        "",
        "INFO",
        &format!("master started addr={} scheme={}", c.listen_addr, mode),
    );

    let child_cancel = cancel.child_token();
    let embedded_handle = if c.embedded_server.enabled {
        let emb_cancel = child_cancel.clone();
        let emb_cfg = c.clone();
        let emb_store = Arc::clone(&store);
        let emb_ring = Arc::clone(&ring);
        Some(tokio::spawn(async move {
            if let Err(err) =
                run_embedded_server(emb_cancel.clone(), emb_cfg, emb_store, Some(emb_ring.clone()))
                    .await
            {
                if !emb_cancel.is_cancelled() {
                    emb_ring.push_entry(
                        "master",
                        "",
                        "ERROR",
                        &format!("embedded server failed error={}", err),
                    );
                }
            }
        }))
    } else {
        None
    };

    let conn_limit = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    let mut conns = tokio::task::JoinSet::new();
    loop {
        while conns.try_join_next().is_some() {}
        tokio::select! {
            _ = cancel.cancelled() => {
                break;
            }
            accept_res = listener.accept() => {
                let (tcp, peer_addr) = match accept_res {
                    Ok(v) => v,
                    Err(_) => {
                        // Avoid a hot loop on persistent errors such as EMFILE.
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                };
                let Ok(permit) = Arc::clone(&conn_limit).try_acquire_owned() else {
                    drop(tcp);
                    continue;
                };
                let _ = tcp.set_nodelay(true);
                let router = router.clone();
                let tls_acceptor = tls_acceptor.clone();
                conns.spawn(async move {
                    let _permit = permit;
                    let svc = tower::service_fn(move |mut req: Request<hyper::body::Incoming>| {
                        req.extensions_mut().insert(ConnectInfo(peer_addr));
                        let router = router.clone();
                        async move {
                            let req = req.map(axum::body::Body::new);
                            router.oneshot(req).await
                        }
                    });
                    let hyper_svc = TowerToHyperService::new(svc);
                    let mut builder = AutoConnBuilder::new(TokioExecutor::new());
                    builder
                        .http1()
                        .timer(TokioTimer::new())
                        .header_read_timeout(Duration::from_secs(15));
                    builder
                        .http2()
                        .timer(TokioTimer::new())
                        .keep_alive_interval(Some(Duration::from_secs(30)))
                        .keep_alive_timeout(Duration::from_secs(15));
                    if let Some(acceptor) = tls_acceptor {
                        let handshake = tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await;
                        if let Ok(Ok(tls_stream)) = handshake {
                            let io = TokioIo::new(IdleTimeoutIo::new(tls_stream, CONN_IDLE_TIMEOUT));
                            let _ = builder.serve_connection_with_upgrades(io, hyper_svc).await;
                        }
                    } else {
                        let io = TokioIo::new(IdleTimeoutIo::new(tcp, CONN_IDLE_TIMEOUT));
                        let _ = builder.serve_connection_with_upgrades(io, hyper_svc).await;
                    }
                });
            }
        }
    }

    child_cancel.cancel();
    // Give in-flight requests a bounded window, then drop remaining connections.
    let _ = tokio::time::timeout(SHUTDOWN_DRAIN, async {
        while conns.join_next().await.is_some() {}
    })
    .await;
    conns.abort_all();
    if let Some(handle) = embedded_handle {
        let _ = handle.await;
    }
    Ok(())
}

const MAX_CONNECTIONS: usize = 4096;
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const CONN_IDLE_TIMEOUT: Duration = Duration::from_secs(75);
const SHUTDOWN_DRAIN: Duration = Duration::from_secs(5);

struct IdleTimeoutIo<S> {
    inner: S,
    timeout: Duration,
    sleep: Pin<Box<tokio::time::Sleep>>,
}

impl<S: Unpin> IdleTimeoutIo<S> {
    fn new(inner: S, timeout: Duration) -> Self {
        Self {
            inner,
            timeout,
            sleep: Box::pin(tokio::time::sleep(timeout)),
        }
    }

    fn reset_timer(&mut self) {
        self.sleep
            .as_mut()
            .reset(tokio::time::Instant::now() + self.timeout);
    }
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for IdleTimeoutIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            std::task::Poll::Ready(Ok(())) => {
                if buf.filled().len() > before {
                    this.reset_timer();
                }
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
            std::task::Poll::Pending => {
                if this.sleep.as_mut().poll(cx).is_ready() {
                    std::task::Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "connection idle timeout",
                    )))
                } else {
                    std::task::Poll::Pending
                }
            }
        }
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for IdleTimeoutIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(cx, buf) {
            std::task::Poll::Ready(Ok(n)) => {
                if n > 0 {
                    this.reset_timer();
                }
                std::task::Poll::Ready(Ok(n))
            }
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
            std::task::Poll::Pending => {
                if this.sleep.as_mut().poll(cx).is_ready() {
                    std::task::Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "connection idle timeout",
                    )))
                } else {
                    std::task::Poll::Pending
                }
            }
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

fn load_server_tls_config(cert_file: &str, key_file: &str) -> Result<rustls::ServerConfig, String> {
    let cert_bytes = fs::read(cert_file).map_err(|e| format!("read cert_file: {}", e))?;
    let key_bytes = fs::read(key_file).map_err(|e| format!("read key_file: {}", e))?;
    let mut cert_reader = std::io::BufReader::new(&cert_bytes[..]);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("parse cert_file: {}", e))?;
    if certs.is_empty() {
        return Err("no certificates found in cert_file".to_string());
    }
    let mut key_reader = std::io::BufReader::new(&key_bytes[..]);
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| format!("parse key_file: {}", e))?
        .ok_or_else(|| "no private key found in key_file".to_string())?;

    let mut cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("invalid tls keypair: {}", e))?;
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(cfg)
}

pub fn embedded_node(c: &Config, s: &Store) -> Result<Node, String> {
    let name = if c.embedded_server.name.is_empty() {
        "default".to_string()
    } else {
        c.embedded_server.name.clone()
    };
    let port = if c.embedded_server.port == 0 {
        8444
    } else {
        c.embedded_server.port
    };
    let mut addr = c.embedded_server.address.clone();
    if addr.is_empty() {
        let (h, _) = split_host_port(&c.listen_addr);
        if h.is_empty() || h == "0.0.0.0" || h == "::" {
            addr = "127.0.0.1".to_string();
        } else {
            addr = h;
        }
    }
    let n = s
        .ensure_embedded_node(Node {
            name,
            role: "server".to_string(),
            address: addr.clone(),
            port,
            tunnel: LocalTLS {
                listen_port: port,
                ..Default::default()
            },
            connect_endpoints: vec![ConnectEndpoint {
                id: "primary".to_string(),
                name: "启动参数默认接入".to_string(),
                host: addr,
                port,
                enabled: true,
                ..Default::default()
            }],
            ..Default::default()
        })
        .map_err(|e| format!("failed to auto-register embedded server node: {}", e))?;

    let (_, listen_port_str) = split_host_port(&c.listen_addr);
    let listen_port: i64 = listen_port_str.parse().unwrap_or(0);
    let actual_port = if n.tunnel.listen_port > 0 {
        n.tunnel.listen_port
    } else {
        n.port
    };
    if actual_port == listen_port && listen_port != 0 {
        return Err(format!(
            "embedded server port {} collides with master listen_addr",
            actual_port
        ));
    }
    Ok(n)
}

pub fn embedded_config(c: &Config, n: &Node) -> Config {
    let mut master_addr = c.listen_addr.clone();
    let (bind_host, bind_port) = split_host_port(&c.listen_addr);
    if !bind_port.is_empty() {
        if bind_host.is_empty() || bind_host == "0.0.0.0" {
            master_addr = format!("127.0.0.1:{}", bind_port);
        } else if bind_host == "::" {
            master_addr = format!("[::1]:{}", bind_port);
        }
    }
    let (control_ca, control_sni) = if c.scheme == "https" {
        let ca = if c.control_ca.is_empty() {
            c.cert_file.clone()
        } else {
            c.control_ca.clone()
        };
        (ca, c.control_server_name.clone())
    } else {
        (String::new(), String::new())
    };
    let state_dir = if c.embedded_server.state_dir.is_empty() {
        Path::new(&c.state_dir)
            .join("embedded-server")
            .to_string_lossy()
            .into_owned()
    } else {
        c.embedded_server.state_dir.clone()
    };
    Config {
        master_addr,
        control_ca,
        control_server_name: control_sni,
        node_id: n.id.clone(),
        state_dir,
        ..Default::default()
    }
}

pub async fn run_embedded_server(
    cancel: CancellationToken,
    c: Config,
    s: Arc<Store>,
    ring: Option<Arc<Ring>>,
) -> Result<(), String> {
    let n = embedded_node(&c, &s)?;
    supervise_embedded(
        cancel.clone(),
        || {
            let cancel = cancel.clone();
            let c = c.clone();
            let s = Arc::clone(&s);
            let n = n.clone();
            let ring = ring.clone();
            async move { run_embedded_attempt(cancel, c, s, n, ring).await }
        },
        Duration::from_secs(1),
    )
    .await
}

pub async fn supervise_embedded<F, Fut>(
    cancel: CancellationToken,
    mut run_fn: F,
    delay: Duration,
) -> Result<(), String>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<(), NodeError>>,
{
    let mut window = Instant::now();
    let mut retries = 0usize;
    loop {
        if cancel.is_cancelled() {
            return Ok(());
        }
        let res = run_fn().await;
        if cancel.is_cancelled() {
            return Ok(());
        }
        match res {
            Ok(()) => return Ok(()),
            Err(NodeError::CredentialRejected) => {
                if window.elapsed() >= Duration::from_secs(60) {
                    window = Instant::now();
                    retries = 0;
                }
                if retries >= 3 {
                    return Err(format!(
                        "embedded authentication recovery exhausted: {}",
                        node::ERR_CREDENTIAL_REJECTED
                    ));
                }
                let wait = delay * (1u32 << retries);
                retries += 1;
                tokio::select! {
                    _ = cancel.cancelled() => return Ok(()),
                    _ = tokio::time::sleep(wait) => {}
                }
            }
            Err(NodeError::Other(msg)) => return Err(msg),
        }
    }
}

pub async fn run_embedded_attempt(
    cancel: CancellationToken,
    c: Config,
    s: Arc<Store>,
    n: Node,
    ring: Option<Arc<Ring>>,
) -> Result<(), NodeError> {
    let nodes = s.nodes().map_err(|e| NodeError::Other(e.to_string()))?;
    let mut count = 0usize;
    for current in &nodes {
        if current.embedded {
            if current.id != n.id || current.role != "server" || current.revoked {
                return Err(NodeError::Other(
                    "embedded database identity mismatch or revocation".to_string(),
                ));
            }
            count += 1;
        }
    }
    if count != 1 {
        return Err(NodeError::Other(
            "embedded database identity missing or ambiguous".to_string(),
        ));
    }

    let mut srv_config = embedded_config(&c, &n);
    let state_path = PathBuf::from(&srv_config.state_dir).join("state.json");
    let mut cached = DiskState {
        node_id: n.id.clone(),
        master: srv_config.master_addr.clone(),
        credential: String::new(),
        snapshot: None,
    };
    match fs::read(&state_path) {
        Ok(body) => {
            let parsed: DiskState = serde_json::from_slice(&body).map_err(|_| {
                NodeError::Other("embedded node state identity mismatch or corruption".to_string())
            })?;
            if parsed.node_id != n.id || parsed.master != srv_config.master_addr {
                return Err(NodeError::Other(
                    "embedded node state identity mismatch or corruption".to_string(),
                ));
            }
            if let Some(ref snap) = parsed.snapshot {
                if snap.node.id != n.id || snap.node.role != "server" {
                    return Err(NodeError::Other(
                        "embedded cached node identity mismatch".to_string(),
                    ));
                }
            }
            cached = parsed;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(NodeError::Other(format!(
                "cannot read embedded node state: {}",
                e
            )))
        }
    }

    if !cached.credential.is_empty() {
        if let Err(err) = s.snapshot(&n.id, &cached.credential) {
            if !matches!(err, StoreError::Auth) {
                return Err(NodeError::Other(format!(
                    "cannot validate embedded credential: {}",
                    err
                )));
            }
            cached.credential.clear();
            cached.snapshot = None;
            node::save_disk_state(&state_path, &cached).map_err(|e| {
                NodeError::Other(format!("cannot reset expired embedded credential: {}", e))
            })?;
        }
    }

    if cached.credential.is_empty() {
        let token = s
            .enroll_token(&n.id, Duration::from_secs(60))
            .map_err(|e| {
                NodeError::Other(format!(
                    "failed to issue enrollment token for embedded server: {}",
                    e
                ))
            })?;
        srv_config.enroll_token = token;
        let watch_store = Arc::clone(&s);
        let watch_id = n.id.clone();
        let watch_path = state_path.clone();
        let watch_cancel = cancel.clone();
        tokio::spawn(async move {
            for _ in 0..30 {
                tokio::select! {
                    _ = watch_cancel.cancelled() => {
                        let _ = watch_store.revoke_enroll_token(&watch_id);
                        return;
                    }
                    _ = tokio::time::sleep(Duration::from_millis(200)) => {
                        if let Ok(data) = fs::read(&watch_path) {
                            if let Ok(st) = serde_json::from_slice::<DiskState>(&data) {
                                if !st.credential.is_empty() {
                                    let _ = watch_store.revoke_enroll_token(&watch_id);
                                    return;
                                }
                            }
                        }
                    }
                }
            }
            let _ = watch_store.revoke_enroll_token(&watch_id);
        });
    }

    let res = node::run_with_ring(cancel, srv_config, "server", ring).await;
    let _ = s.revoke_enroll_token(&n.id);
    res
}

fn split_host_port(addr: &str) -> (String, String) {
    if let Ok(sa) = addr.parse::<SocketAddr>() {
        return (sa.ip().to_string(), sa.port().to_string());
    }
    if let Some(rest) = addr.strip_prefix('[') {
        if let Some((h, p)) = rest.split_once("]:") {
            return (h.to_string(), p.to_string());
        }
    }
    if let Some((h, p)) = addr.rsplit_once(':') {
        return (h.to_string(), p.to_string());
    }
    (addr.to_string(), String::new())
}
use std::future::Future;
use std::pin::Pin;

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn idle_timeout_io_closes_inactive_stream() {
        let (mut a, _b) = tokio::io::duplex(1024);
        let mut wrapped = IdleTimeoutIo::new(&mut a, Duration::from_millis(40));
        let mut buf = [0u8; 16];
        let err = wrapped.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn idle_timeout_io_resets_on_write_activity() {
        let (a, mut b) = tokio::io::duplex(1024);
        let mut wrapped = IdleTimeoutIo::new(a, Duration::from_millis(80));
        let reader = tokio::spawn(async move {
            let mut tmp = [0u8; 16];
            while b.read(&mut tmp).await.unwrap_or(0) > 0 {}
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        wrapped.write_all(b"ping").await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        wrapped.write_all(b"pong").await.unwrap();
        drop(wrapped);
        reader.await.unwrap();
    }
}
