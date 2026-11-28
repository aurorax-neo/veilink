use std::collections::HashMap;
use std::convert::Infallible;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::{Body, Bytes};
use axum::extract::ConnectInfo;
use axum::http::{header, Method, Request, Response, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{TimeZone, Utc};
use futures_util::StreamExt;
use parking_lot::Mutex;
use rand::RngCore;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
    Ia5String, IsCa, KeyPair, KeyUsagePurpose, SanType, SerialNumber, PKCS_ECDSA_P256_SHA256,
};
use rust_embed::RustEmbed;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use url::Url;

use crate::auth::{AuthError, AuthStore, KeyRole, KeyStore, ROLE_ADMIN, ROLE_READONLY};
use crate::buildinfo;
use crate::config::{self, MasterConfigUpdate};
use crate::control::{
    EnrollRequest, EnrollResponse, EventsRequest, EventsResponse, PullRequest, PATH_ENROLL,
    PATH_EVENTS, PATH_PULL,
};
use crate::logring::{Entry as LogEntry, NodeRing, Ring};
use crate::model::{LocalTLS, Mapping, Node};
use crate::store::{ReportedNode, SoftwareReport, Store, StoreError, TrafficBytes};
use crate::tunnel;

#[derive(RustEmbed)]
#[folder = "internal/webui/dist"]
struct EmbeddedWebAssets;

#[derive(Debug, Clone, Default)]
pub struct WebPersistConfig {
    pub db_path: String,
    pub html_dir: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebStatus {
    pub mode: String,
    pub active_version: String,
    pub serving: bool,
    pub prebundled: bool,
}

#[derive(Clone)]
pub struct WebManager {
    dir: String,
    serving: bool,
}

impl WebManager {
    pub fn new(html_dir: String) -> Self {
        let mut wm = Self {
            dir: html_dir,
            serving: false,
        };
        if wm.ensure().is_ok() {
            wm.serving = true;
        }
        wm
    }

    pub fn ensure(&self) -> Result<String, String> {
        if !self.dir.is_empty() {
            let index_path = Path::new(&self.dir).join("index.html");
            let meta = fs::metadata(&index_path)
                .map_err(|e| format!("bundled web unavailable: {}", e))?;
            if !meta.is_file() || meta.len() == 0 {
                return Err("bundled web index.html must be a nonempty regular file".to_string());
            }
            return Ok(self.dir.clone());
        }
        match EmbeddedWebAssets::get("index.html") {
            Some(file) if !file.data.is_empty() => Ok("embedded".to_string()),
            _ => Err("embedded web index.html must be a nonempty regular file".to_string()),
        }
    }

    pub fn status(&self) -> WebStatus {
        WebStatus {
            mode: "builtin".to_string(),
            active_version: self.version(),
            serving: self.serving,
            prebundled: true,
        }
    }

    pub fn version(&self) -> String {
        buildinfo::version().to_string()
    }

    pub fn read_file(&self, rel_path: &str) -> Option<Vec<u8>> {
        if !self.serving {
            return None;
        }
        let clean = clean_relative_path(rel_path)?;
        if !self.dir.is_empty() {
            let base = fs::canonicalize(&self.dir).ok()?;
            let full = base.join(&clean);
            let canon = fs::canonicalize(&full).ok()?;
            if !canon.starts_with(&base) {
                return None;
            }
            if let Ok(meta) = fs::metadata(&canon) {
                if meta.is_file() {
                    return fs::read(&canon).ok();
                }
            }
            return None;
        }
        EmbeddedWebAssets::get(&clean).map(|f| f.data.into_owned())
    }
}

fn clean_relative_path(raw: &str) -> Option<String> {
    let trimmed = raw.trim_start_matches('/');
    if trimmed.is_empty() || trimmed == "." {
        return None;
    }
    let mut parts = Vec::new();
    for seg in trimmed.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            parts.pop();
            continue;
        }
        parts.push(seg);
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("/"))
    }
}

fn content_type_for_path(path: &str) -> &'static str {
    let ext = Path::new(path)
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match ext.as_str() {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "application/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" | "map" => "application/json; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "ico" => "image/x-icon",
        "webp" => "image/webp",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

#[derive(Clone, Debug)]
pub struct StreamEvent {
    pub event_type: String,
    pub data_json: String,
}

const MAX_STREAM_SUBS: usize = 64;

pub struct StreamHub {
    tx: broadcast::Sender<StreamEvent>,
    active_subs: Mutex<usize>,
}

impl StreamHub {
    pub fn new() -> Arc<Self> {
        let (tx, _) = broadcast::channel(256);
        Arc::new(Self {
            tx,
            active_subs: Mutex::new(0),
        })
    }

    pub fn publish<T: Serialize>(&self, event_type: &str, data: &T) {
        if let Ok(data_json) = serde_json::to_string(data) {
            let _ = self.tx.send(StreamEvent {
                event_type: event_type.to_string(),
                data_json,
            });
        }
    }
}

struct SubGuard {
    hub: Arc<StreamHub>,
}

impl Drop for SubGuard {
    fn drop(&mut self) {
        let mut count = self.hub.active_subs.lock();
        *count = count.saturating_sub(1);
    }
}

const MAX_STREAM_TOKENS: usize = 128;

pub struct StreamTokenStore {
    tokens: Mutex<HashMap<String, i64>>,
}

impl StreamTokenStore {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            tokens: Mutex::new(HashMap::new()),
        })
    }

    pub fn issue(&self) -> Option<String> {
        let now = Utc::now().timestamp();
        let mut map = self.tokens.lock();
        map.retain(|_, exp| now <= *exp);
        if map.len() >= MAX_STREAM_TOKENS {
            return None;
        }
        let mut raw = [0u8; 16];
        rand::rng().fill_bytes(&mut raw);
        let tok = format!("st_{}", hex::encode(raw));
        map.insert(tok.clone(), now + 60);
        Some(tok)
    }

    pub fn consume(&self, tok: &str) -> bool {
        if tok.is_empty() {
            return false;
        }
        let now = Utc::now().timestamp();
        let mut map = self.tokens.lock();
        match map.remove(tok) {
            Some(exp) => now <= exp,
            None => false,
        }
    }
}

struct FailWindow {
    limit: usize,
    window: Duration,
    hits: Mutex<HashMap<String, Vec<Instant>>>,
}

impl FailWindow {
    fn new(limit: usize, window: Duration) -> Self {
        Self {
            limit,
            window,
            hits: Mutex::new(HashMap::new()),
        }
    }

    fn allow(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut hits = self.hits.lock();
        if hits.len() > 512 {
            hits.retain(|_, times| {
                times.retain(|at| now.duration_since(*at) < self.window);
                !times.is_empty()
            });
        }
        let entry = hits.entry(key.to_string()).or_default();
        entry.retain(|at| now.duration_since(*at) < self.window);
        if entry.len() >= self.limit {
            return false;
        }
        entry.push(now);
        true
    }
}

#[derive(Clone)]
pub struct Api {
    store: Arc<Store>,
    #[allow(dead_code)]
    insecure: bool,
    ring: Option<Arc<Ring>>,
    node_ring: Option<NodeRing>,
    key_store: KeyStore,
    auth_store: AuthStore,
    web_manager: WebManager,
    stream_hub: Arc<StreamHub>,
    token_store: Arc<StreamTokenStore>,
    web_persist: WebPersistConfig,
    auth_fails: Arc<FailWindow>,
}

impl Api {
    pub fn new(
        store: Arc<Store>,
        insecure_loopback: bool,
        ring: Option<Arc<Ring>>,
        web_persist: WebPersistConfig,
    ) -> Self {
        let key_store = KeyStore::new(store.db());
        if let Err(err) = key_store.migrate() {
            let msg = format!("初始化 api_keys 表失败: {err}");
            eprintln!("veilink master: {msg}");
            if let Some(ref r) = ring {
                r.push_entry("master", "", "ERROR", &msg);
            }
        }
        let auth_store = AuthStore::new(store.db());
        if let Err(err) = auth_store.migrate() {
            let msg = format!("初始化 admin_accounts 表失败: {err}");
            eprintln!("veilink master: {msg}");
            if let Some(ref r) = ring {
                r.push_entry("master", "", "ERROR", &msg);
            }
        } else {
            match auth_store.ensure_install_secret(&web_persist.db_path) {
                Ok(Some((secret, secret_path))) => {
                    let path_text = secret_path
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "<in-memory>".to_string());
                    eprintln!(
                        "\n======================================================================\n\
                         Veilink 首次安装引导（Install Lock 已启用，防访客抢注）\n\
                         初始化安全令牌 (Install Secret): {secret}\n\
                         令牌文件路径: {path_text}\n\
                         请在 Web 控制台首次安装引导中输入此一次性令牌，注册唯一管理员邮箱与密码。\n\
                         完成注册后安全令牌将自动销毁，公开注册入口永久锁定。\n\
                         ======================================================================\n"
                    );
                    if let Some(ref r) = ring {
                        r.push_entry(
                            "master",
                            "",
                            "INFO",
                            &format!(
                                "first-time setup required; install secret written to {path_text}"
                            ),
                        );
                    }
                }
                Ok(None) => {}
                Err(err) => {
                    let msg = format!("生成初始化安全令牌失败: {err}");
                    eprintln!("veilink master: {msg}");
                    if let Some(ref r) = ring {
                        r.push_entry("master", "", "ERROR", &msg);
                    }
                }
            }
        }
        let web_manager = WebManager::new(web_persist.html_dir.clone());
        if !web_manager.serving {
            if let Some(ref r) = ring {
                r.push_entry(
                    "master",
                    "",
                    "ERROR",
                    "内置前端资源不可用，Web 请求将返回 503",
                );
            }
        }
        let node_ring = ring.as_ref().map(|r| NodeRing::new((**r).clone()));
        Self {
            store,
            insecure: insecure_loopback,
            ring,
            node_ring,
            key_store,
            auth_store,
            web_manager,
            stream_hub: StreamHub::new(),
            token_store: StreamTokenStore::new(),
            web_persist,
            auth_fails: Arc::new(FailWindow::new(30, Duration::from_secs(60))),
        }
    }

    pub fn into_router(self) -> axum::Router {
        let api = Arc::new(self);
        axum::Router::new().fallback(move |req: Request<Body>| {
            let api = Arc::clone(&api);
            async move { api.handle(req).await }
        })
    }

    pub async fn handle(&self, req: Request<Body>) -> Response<Body> {
        let method = req.method().clone();
        let path = req.uri().path().to_string();
        let raw_query = req.uri().query().unwrap_or("").to_string();

        // 1. Health check (unauthenticated)
        if path == "/healthz" || path == "/api/health" {
            return json_response(
                StatusCode::OK,
                &serde_json::json!({ "status": "ok" }),
                path.starts_with("/api/"),
            );
        }

        // 2. Version contract (unauthenticated)
        if path == "/api/version" {
            return json_response(
                StatusCode::OK,
                &serde_json::json!({
                    "api_version": "v1",
                    "backend_version": buildinfo::version(),
                    "web_version": self.web_manager.version(),
                    "web_mode": "builtin",
                }),
                true,
            );
        }

        // 3. Pure HTTP Control Plane (Node <-> Master, Nginx reverse-proxy friendly)
        if path == PATH_ENROLL
            || path == "/api/v1/control/enroll"
            || path == PATH_PULL
            || path == "/api/v1/control/pull"
            || path == PATH_EVENTS
            || path == "/api/v1/control/events"
        {
            return self.serve_control(req, &method, &path, &raw_query).await;
        }

        // 4. Legacy /api/* -> /api/v1/* redirect (301 for GET/HEAD, 308 for methods with body)
        if path.starts_with("/api/") && !path.starts_with("/api/v1/") {
            let target = format!("/api/v1{}", &path["/api".len()..]);
            let status = if method == Method::GET || method == Method::HEAD {
                StatusCode::MOVED_PERMANENTLY
            } else {
                StatusCode::PERMANENT_REDIRECT
            };
            let mut resp = Response::builder()
                .status(status)
                .header(header::LOCATION, target)
                .body(Body::empty())
                .unwrap();
            set_security_headers(resp.headers_mut(), false);
            return resp;
        }

        let is_api = path.starts_with("/api/");

        // 4.5 Public Auth & First-Time Setup endpoints (unauthenticated, rate-limited)
        if path == "/api/v1/auth/status"
            || path == "/api/v1/auth/setup"
            || path == "/api/v1/auth/login"
        {
            return self.serve_public_auth(req, &method, &path).await;
        }

        // 5. Session / API Key authentication (except GET /api/v1/stream which uses one-time token)
        let is_sse = path == "/api/v1/stream" && method == Method::GET;
        let mut role: KeyRole = String::new();
        if !is_sse {
            if let Some(r) = self.authenticate(&req) {
                role = r;
            } else if is_api {
                let ip = client_ip(&req);
                if !self.auth_fails.allow(&ip) {
                    return failure_response(StatusCode::TOO_MANY_REQUESTS, true);
                }
                return failure_response(StatusCode::UNAUTHORIZED, true);
            }
        }

        // 5.5 Authenticated Account & Session endpoints (/api/v1/auth/*)
        if path.starts_with("/api/v1/auth/") {
            return self.serve_authed_auth(req, &method, &path, &role).await;
        }

        // 6. SSE stream & token endpoints
        if path == "/api/v1/stream" && method == Method::GET {
            let params = parse_query(&raw_query);
            let tok = params.get("token").map(|s| s.as_str()).unwrap_or("");
            let authed = self.token_store.consume(tok) || self.authenticate(&req).is_some();
            if !authed {
                return failure_response(StatusCode::UNAUTHORIZED, true);
            }
            return self.serve_sse(&raw_query);
        }
        if path == "/api/v1/stream/token" && method == Method::POST {
            match self.token_store.issue() {
                Some(token) => {
                    return json_response(
                        StatusCode::OK,
                        &serde_json::json!({
                            "token": token,
                            "expires_in": 60,
                        }),
                        true,
                    );
                }
                None => return failure_response(StatusCode::TOO_MANY_REQUESTS, true),
            }
        }

        // 7. Key management (/api/v1/keys*)
        if path == "/api/v1/keys" || path.starts_with("/api/v1/keys/") {
            return self.serve_keys(req, &method, &path, &role).await;
        }

        // 8. Builtin Web status (/api/v1/web/config)
        if path == "/api/v1/web/config" {
            if role != ROLE_ADMIN {
                return failure_response(StatusCode::FORBIDDEN, true);
            }
            if method == Method::GET {
                return json_response(StatusCode::OK, &self.web_manager.status(), true);
            }
            return failure_response(StatusCode::NOT_FOUND, true);
        }

        // 9. Master general config (/api/v1/master/config)
        if path == "/api/v1/master/config" {
            if role != ROLE_ADMIN {
                return failure_response(StatusCode::FORBIDDEN, true);
            }
            if method == Method::GET {
                match config::get_master_config_view(&self.web_persist.db_path) {
                    Ok(view) => return json_response(StatusCode::OK, &view, true),
                    Err(_) => return failure_response(StatusCode::INTERNAL_SERVER_ERROR, true),
                }
            }
            if method == Method::POST {
                let upd: MasterConfigUpdate = match decode_json_body(req, 64 << 10).await {
                    Ok(v) => v,
                    Err(resp) => return resp,
                };
                match config::update_master_config(&self.web_persist.db_path, upd) {
                    Ok(need_restart) => {
                        return json_response(
                            StatusCode::OK,
                            &serde_json::json!({
                                "ok": true,
                                "need_restart": need_restart,
                            }),
                            true,
                        );
                    }
                    Err(e) => {
                        return json_response(
                            StatusCode::BAD_REQUEST,
                            &serde_json::json!({ "error": e }),
                            true,
                        );
                    }
                }
            }
            return failure_response(StatusCode::METHOD_NOT_ALLOWED, true);
        }

        // 10. Business API (/api/v1/*)
        if path.starts_with("/api/v1/") {
            return self
                .serve_api(req, &method, &path, &raw_query, &role)
                .await;
        }

        // 11. Static frontend assets
        if self.web_manager.serving {
            if let Some(bytes) = self.web_manager.read_file(&path) {
                let ctype = content_type_for_path(&path);
                let mut resp = Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, ctype)
                    .header(header::CACHE_CONTROL, "no-cache")
                    .body(Body::from(bytes))
                    .unwrap();
                set_security_headers(resp.headers_mut(), false);
                return resp;
            }
            let has_ext = Path::new(&path).extension().is_some();
            if path.starts_with("/assets/") || has_ext {
                let mut resp = Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .header(header::CACHE_CONTROL, "no-cache")
                    .body(Body::from("404 page not found\n"))
                    .unwrap();
                set_security_headers(resp.headers_mut(), false);
                return resp;
            }
            if let Some(index_bytes) = self.web_manager.read_file("index.html") {
                let mut resp = Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
                    .header(header::CACHE_CONTROL, "no-cache")
                    .body(Body::from(index_bytes))
                    .unwrap();
                set_security_headers(resp.headers_mut(), false);
                return resp;
            }
        }

        json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &serde_json::json!({
                "error": "内置 Web 资源不可用，请检查可执行文件是否完整。"
            }),
            false,
        )
    }

    fn extract_session_token(&self, req: &Request<Body>) -> Option<String> {
        if let Some(bearer) = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
        {
            let trimmed = bearer.trim();
            if trimmed.starts_with("vls_") {
                return Some(trimmed.to_string());
            }
        }
        if !Self::cookie_csrf_allowed(req) {
            return None;
        }
        if let Some(cookie_hdr) = req.headers().get(header::COOKIE).and_then(|v| v.to_str().ok()) {
            for part in cookie_hdr.split(';') {
                if let Some((k, v)) = part.trim().split_once('=') {
                    if k.trim() == "veilink_session" {
                        let val = v.trim();
                        if val.starts_with("vls_") {
                            return Some(val.to_string());
                        }
                    }
                }
            }
        }
        None
    }

    /// Block cross-site and same-site subdomain CSRF when authenticating solely
    /// via the `veilink_session` cookie on state-mutating HTTP methods.
    fn cookie_csrf_allowed(req: &Request<Body>) -> bool {
        if matches!(
            *req.method(),
            Method::GET | Method::HEAD | Method::OPTIONS
        ) {
            return true;
        }
        if let Some(sfs) = req
            .headers()
            .get("Sec-Fetch-Site")
            .and_then(|v| v.to_str().ok())
        {
            let sfs = sfs.trim();
            if !sfs.eq_ignore_ascii_case("same-origin") && !sfs.eq_ignore_ascii_case("none") {
                return false;
            }
        }
        if let Some(origin_raw) = req.headers().get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
            let origin_raw = origin_raw.trim();
            if origin_raw.eq_ignore_ascii_case("null") {
                return false;
            }
            let Ok(origin_url) = Url::parse(origin_raw) else {
                return false;
            };
            let Some(host_hdr) = req.headers().get(header::HOST).and_then(|v| v.to_str().ok()) else {
                return false;
            };
            let Some(origin_host) = origin_url.host_str() else {
                return false;
            };
            let origin_authority = match origin_url.port() {
                Some(p) => {
                    if origin_host.contains(':') && !origin_host.starts_with('[') {
                        format!("[{origin_host}]:{p}")
                    } else {
                        format!("{origin_host}:{p}")
                    }
                }
                None => {
                    if origin_host.contains(':') && !origin_host.starts_with('[') {
                        format!("[{origin_host}]")
                    } else {
                        origin_host.to_string()
                    }
                }
            };
            let host_trimmed = host_hdr.trim();
            let default_port_authority = match origin_url.scheme() {
                "https" => format!("{origin_authority}:443"),
                "http" => format!("{origin_authority}:80"),
                _ => String::new(),
            };
            if !host_trimmed.eq_ignore_ascii_case(&origin_authority)
                && (default_port_authority.is_empty()
                    || !host_trimmed.eq_ignore_ascii_case(&default_port_authority))
            {
                return false;
            }
        }
        true
    }

    fn is_secure_request(&self, req: &Request<Body>) -> bool {
        if !self.insecure {
            return true;
        }
        let peer = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0.ip().to_string())
            .unwrap_or_else(|| "127.0.0.1".to_string());
        if !is_trusted_proxy_ip(&peer) {
            return false;
        }
        req.headers()
            .get("X-Forwarded-Proto")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.eq_ignore_ascii_case("https"))
    }

    fn session_cookie_header(token: &str, max_age_secs: i64, secure: bool) -> String {
        let sec = if secure { "; Secure" } else { "" };
        format!(
            "veilink_session={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age={max_age_secs}{sec}"
        )
    }

    fn authenticate(&self, req: &Request<Body>) -> Option<KeyRole> {
        if let Some(sess_tok) = self.extract_session_token(req) {
            if let Some(ident) = self.auth_store.validate_session(&sess_tok) {
                return Some(ident.role);
            }
        }
        let mut key = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .unwrap_or("");
        if key.is_empty() {
            key = req
                .headers()
                .get("X-API-Key")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
        }
        if key.is_empty() {
            return None;
        }
        self.key_store.validate(key)
    }

    async fn serve_public_auth(
        &self,
        req: Request<Body>,
        method: &Method,
        path: &str,
    ) -> Response<Body> {
        let secure = self.is_secure_request(&req);
        let ip = client_ip(&req);

        if path == "/api/v1/auth/status" {
            if *method != Method::GET {
                return failure_response(StatusCode::METHOD_NOT_ALLOWED, true);
            }
            let installed = self.auth_store.is_installed();
            let authed_session = self
                .extract_session_token(&req)
                .and_then(|t| self.auth_store.validate_session(&t));
            let user_json = if let Some(ref _sess) = authed_session {
                self.auth_store
                    .account_info()
                    .ok()
                    .flatten()
                    .map(|(acc, active_sessions)| {
                        serde_json::json!({
                            "email": acc.email,
                            "created_at": acc.created_at,
                            "updated_at": acc.updated_at,
                            "last_login": acc.last_login,
                            "active_sessions": active_sessions,
                        })
                    })
            } else {
                None
            };
            let secret_hint_path = crate::auth::install_secret_path(&self.web_persist.db_path)
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "/data/.install_secret".to_string());
            return json_response(
                StatusCode::OK,
                &serde_json::json!({
                    "installed": installed,
                    "locked": installed,
                    "single_admin_only": true,
                    "secret_file_hint": if installed { "" } else { secret_hint_path.as_str() },
                    "authenticated": authed_session.is_some(),
                    "user": user_json,
                }),
                true,
            );
        }

        if path == "/api/v1/auth/setup" {
            if *method != Method::POST {
                return failure_response(StatusCode::METHOD_NOT_ALLOWED, true);
            }
            if self.auth_store.is_installed() {
                return json_response(
                    StatusCode::FORBIDDEN,
                    &serde_json::json!({ "error": AuthError::AlreadyInstalled.to_string() }),
                    true,
                );
            }
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct SetupReq {
                install_secret: String,
                email: String,
                password: String,
            }
            let body: SetupReq = match decode_json_body(req, 16 << 10).await {
                Ok(v) => v,
                Err(resp) => return resp,
            };
            match self.auth_store.setup_admin(
                &self.web_persist.db_path,
                &body.install_secret,
                &body.email,
                &body.password,
            ) {
                Ok((acc, token)) => {
                    if let Some(ref r) = self.ring {
                        r.push_entry(
                            "master",
                            "",
                            "INFO",
                            &format!("initial admin registered and setup locked email={}", acc.email),
                        );
                    }
                    let mut resp = json_response(
                        StatusCode::CREATED,
                        &serde_json::json!({
                            "ok": true,
                            "token": token,
                            "user": {
                                "email": acc.email,
                                "created_at": acc.created_at,
                                "updated_at": acc.updated_at,
                                "last_login": acc.last_login,
                                "active_sessions": 1,
                            },
                        }),
                        true,
                    );
                    if let Ok(hv) = header::HeaderValue::from_str(&Self::session_cookie_header(
                        &token,
                        7 * 24 * 3600,
                        secure,
                    )) {
                        resp.headers_mut().insert(header::SET_COOKIE, hv);
                    }
                    return resp;
                }
                Err(err @ AuthError::AlreadyInstalled) => {
                    return json_response(
                        StatusCode::FORBIDDEN,
                        &serde_json::json!({ "error": err.to_string() }),
                        true,
                    );
                }
                Err(err @ AuthError::InvalidInstallSecret) => {
                    if !self.auth_fails.allow(&ip) {
                        return failure_response(StatusCode::TOO_MANY_REQUESTS, true);
                    }
                    return json_response(
                        StatusCode::UNAUTHORIZED,
                        &serde_json::json!({ "error": err.to_string() }),
                        true,
                    );
                }
                Err(err @ AuthError::InvalidEmail(_)) | Err(err @ AuthError::InvalidPassword(_)) => {
                    return json_response(
                        StatusCode::BAD_REQUEST,
                        &serde_json::json!({ "error": err.to_string() }),
                        true,
                    );
                }
                Err(err) => {
                    return json_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &serde_json::json!({ "error": err.to_string() }),
                        true,
                    );
                }
            }
        }

        if path == "/api/v1/auth/login" {
            if *method != Method::POST {
                return failure_response(StatusCode::METHOD_NOT_ALLOWED, true);
            }
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct LoginReq {
                email: String,
                password: String,
            }
            let body: LoginReq = match decode_json_body(req, 16 << 10).await {
                Ok(v) => v,
                Err(resp) => return resp,
            };
            match self.auth_store.login(&body.email, &body.password) {
                Ok((acc, token)) => {
                    let active_sessions = self
                        .auth_store
                        .account_info()
                        .ok()
                        .flatten()
                        .map(|(_, c)| c)
                        .unwrap_or(1);
                    let mut resp = json_response(
                        StatusCode::OK,
                        &serde_json::json!({
                            "ok": true,
                            "token": token,
                            "user": {
                                "email": acc.email,
                                "created_at": acc.created_at,
                                "updated_at": acc.updated_at,
                                "last_login": acc.last_login,
                                "active_sessions": active_sessions,
                            },
                        }),
                        true,
                    );
                    if let Ok(hv) = header::HeaderValue::from_str(&Self::session_cookie_header(
                        &token,
                        7 * 24 * 3600,
                        secure,
                    )) {
                        resp.headers_mut().insert(header::SET_COOKIE, hv);
                    }
                    return resp;
                }
                Err(err @ AuthError::NotInstalled) => {
                    return json_response(
                        StatusCode::CONFLICT,
                        &serde_json::json!({ "error": err.to_string() }),
                        true,
                    );
                }
                Err(err @ AuthError::InvalidCredentials) => {
                    if !self.auth_fails.allow(&ip) {
                        return failure_response(StatusCode::TOO_MANY_REQUESTS, true);
                    }
                    return json_response(
                        StatusCode::UNAUTHORIZED,
                        &serde_json::json!({ "error": err.to_string() }),
                        true,
                    );
                }
                Err(err) => {
                    return json_response(
                        StatusCode::BAD_REQUEST,
                        &serde_json::json!({ "error": err.to_string() }),
                        true,
                    );
                }
            }
        }

        failure_response(StatusCode::NOT_FOUND, true)
    }

    async fn serve_authed_auth(
        &self,
        req: Request<Body>,
        method: &Method,
        path: &str,
        role: &str,
    ) -> Response<Body> {
        let secure = self.is_secure_request(&req);
        let sess_tok = self.extract_session_token(&req);

        if path == "/api/v1/auth/me" && *method == Method::GET {
            return match self.auth_store.account_info() {
                Ok(Some((acc, active_sessions))) => json_response(
                    StatusCode::OK,
                    &serde_json::json!({
                        "email": acc.email,
                        "role": role,
                        "created_at": acc.created_at,
                        "updated_at": acc.updated_at,
                        "last_login": acc.last_login,
                        "active_sessions": active_sessions,
                    }),
                    true,
                ),
                Ok(None) => failure_response(StatusCode::NOT_FOUND, true),
                Err(_) => failure_response(StatusCode::INTERNAL_SERVER_ERROR, true),
            };
        }

        if path == "/api/v1/auth/logout" && *method == Method::POST {
            if let Some(ref tok) = sess_tok {
                self.auth_store.logout_session(tok);
            }
            let mut resp = json_response(StatusCode::OK, &serde_json::json!({ "ok": true }), true);
            if let Ok(hv) =
                header::HeaderValue::from_str(&Self::session_cookie_header("", 0, secure))
            {
                resp.headers_mut().insert(header::SET_COOKIE, hv);
            }
            return resp;
        }

        if role != ROLE_ADMIN {
            return failure_response(StatusCode::FORBIDDEN, true);
        }

        if path == "/api/v1/auth/password" && *method == Method::POST {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct ChangePasswordReq {
                current_password: String,
                new_password: String,
                #[serde(default)]
                revoke_other_sessions: bool,
            }
            let body: ChangePasswordReq = match decode_json_body(req, 16 << 10).await {
                Ok(v) => v,
                Err(resp) => return resp,
            };
            return match self.auth_store.change_password(
                &body.current_password,
                &body.new_password,
                sess_tok.as_deref(),
                body.revoke_other_sessions,
            ) {
                Ok(revoked) => json_response(
                    StatusCode::OK,
                    &serde_json::json!({ "ok": true, "revoked_sessions": revoked }),
                    true,
                ),
                Err(AuthError::InvalidCredentials) => json_response(
                    StatusCode::BAD_REQUEST,
                    &serde_json::json!({ "error": "当前密码不正确" }),
                    true,
                ),
                Err(err) => json_response(
                    StatusCode::BAD_REQUEST,
                    &serde_json::json!({ "error": err.to_string() }),
                    true,
                ),
            };
        }

        if path == "/api/v1/auth/email" && *method == Method::POST {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct ChangeEmailReq {
                current_password: String,
                new_email: String,
            }
            let body: ChangeEmailReq = match decode_json_body(req, 16 << 10).await {
                Ok(v) => v,
                Err(resp) => return resp,
            };
            return match self
                .auth_store
                .change_email(&body.current_password, &body.new_email)
            {
                Ok(acc) => json_response(
                    StatusCode::OK,
                    &serde_json::json!({
                        "ok": true,
                        "email": acc.email,
                        "updated_at": acc.updated_at,
                    }),
                    true,
                ),
                Err(AuthError::InvalidCredentials) => json_response(
                    StatusCode::BAD_REQUEST,
                    &serde_json::json!({ "error": "当前密码不正确" }),
                    true,
                ),
                Err(err) => json_response(
                    StatusCode::BAD_REQUEST,
                    &serde_json::json!({ "error": err.to_string() }),
                    true,
                ),
            };
        }

        if path == "/api/v1/auth/sessions/revoke-others" && *method == Method::POST {
            let revoked = sess_tok
                .as_deref()
                .map(|t| self.auth_store.revoke_other_sessions(t))
                .unwrap_or(0);
            return json_response(
                StatusCode::OK,
                &serde_json::json!({ "ok": true, "revoked_sessions": revoked }),
                true,
            );
        }

        failure_response(StatusCode::NOT_FOUND, true)
    }

    async fn serve_control(
        &self,
        req: Request<Body>,
        method: &Method,
        path: &str,
        raw_query: &str,
    ) -> Response<Body> {
        if *method != Method::POST {
            return failure_response(StatusCode::METHOD_NOT_ALLOWED, true);
        }
        let ip = client_ip(&req);
        let auth_rejected = |fails: &FailWindow, peer_ip: &str| -> Response<Body> {
            if !fails.allow(peer_ip) {
                return failure_response(StatusCode::TOO_MANY_REQUESTS, true);
            }
            let mut resp = failure_response(StatusCode::UNAUTHORIZED, true);
            resp.headers_mut().insert(
                "X-Veilink-Auth-Rejected",
                header::HeaderValue::from_static("1"),
            );
            resp
        };
        match path {
            PATH_ENROLL | "/api/v1/control/enroll" => {
                let body: EnrollRequest = match decode_json_body(req, 64 << 10).await {
                    Ok(v) => v,
                    Err(resp) => return resp,
                };
                match self.store.enroll(&body.node_id, &body.token) {
                    Ok(credential) => {
                        self.stream_hub.publish(
                            "node",
                            &serde_json::json!({ "id": body.node_id }),
                        );
                        json_response(
                            StatusCode::OK,
                            &EnrollResponse { credential },
                            true,
                        )
                    }
                    Err(StoreError::Auth) => auth_rejected(&self.auth_fails, &ip),
                    Err(StoreError::Invalid(_)) => failure_response(StatusCode::BAD_REQUEST, true),
                    Err(_) => failure_response(StatusCode::INTERNAL_SERVER_ERROR, true),
                }
            }
            PATH_PULL | "/api/v1/control/pull" => {
                let body: PullRequest = match decode_json_body(req, 64 << 10).await {
                    Ok(v) => v,
                    Err(resp) => return resp,
                };
                match self.store.snapshot(&body.node_id, &body.credential) {
                    Ok(snap) => json_response(StatusCode::OK, &snap, true),
                    Err(StoreError::Auth) => auth_rejected(&self.auth_fails, &ip),
                    Err(StoreError::Invalid(_)) => failure_response(StatusCode::BAD_REQUEST, true),
                    Err(_) => failure_response(StatusCode::INTERNAL_SERVER_ERROR, true),
                }
            }
            PATH_EVENTS | "/api/v1/control/events" => {
                let body: EventsRequest = match decode_json_body(req, 64 << 10).await {
                    Ok(v) => v,
                    Err(resp) => return resp,
                };
                if body.applied_revision < 0 || body.applied_revision > 9_007_199_254_740_991 {
                    return failure_response(StatusCode::BAD_REQUEST, true);
                }
                let mut rev = match self.store.heartbeat_software(
                    &body.node_id,
                    &body.credential,
                    body.applied_revision,
                    !body.error.is_empty(),
                    SoftwareReport {
                        software_version: body.software_version.clone(),
                        software_commit: body.software_commit.clone(),
                    },
                ) {
                    Ok(r) => r,
                    Err(StoreError::Auth) => return auth_rejected(&self.auth_fails, &ip),
                    Err(StoreError::Invalid(_)) => {
                        return failure_response(StatusCode::BAD_REQUEST, true)
                    }
                    Err(_) => return failure_response(StatusCode::INTERNAL_SERVER_ERROR, true),
                };

                let empty_links: &[String] = &[];
                let link_slice: &[String] = body.links.as_ref().map_or(empty_links, |v| {
                    if v.len() > 64 {
                        &v[..64]
                    } else {
                        &v[..]
                    }
                });
                if let Err(e) =
                    self.store
                        .report_links(&body.node_id, &body.credential, link_slice)
                {
                    return match e {
                        StoreError::Auth => auth_rejected(&self.auth_fails, &ip),
                        StoreError::Invalid(_) => failure_response(StatusCode::BAD_REQUEST, true),
                        _ => failure_response(StatusCode::INTERNAL_SERVER_ERROR, true),
                    };
                }

                if let Some(ref traffic_map) = body.traffic {
                    if body.traffic_epoch.is_empty()
                        || body.traffic_seq < 1
                        || body.traffic_seq > 9_007_199_254_740_991
                        || traffic_map.len() > 128
                    {
                        return failure_response(StatusCode::BAD_REQUEST, true);
                    }
                    let mut totals = HashMap::with_capacity(traffic_map.len());
                    for (mapping_id, pair) in traffic_map {
                        if pair.up > 9_007_199_254_740_991 || pair.down > 9_007_199_254_740_991 {
                            return failure_response(StatusCode::BAD_REQUEST, true);
                        }
                        totals.insert(
                            mapping_id.clone(),
                            TrafficBytes {
                                up_bytes: pair.up,
                                down_bytes: pair.down,
                            },
                        );
                    }
                    if let Err(e) = self.store.report_traffic(
                        &body.node_id,
                        &body.credential,
                        &body.traffic_epoch,
                        body.traffic_seq,
                        totals,
                    ) {
                        match e {
                            StoreError::Invalid(_) => {}
                            StoreError::Auth => {
                                return auth_rejected(&self.auth_fails, &ip)
                            }
                            _ => return failure_response(StatusCode::INTERNAL_SERVER_ERROR, true),
                        }
                    }
                }

                if !body.logs.is_empty() {
                    if let Some(ref nr) = self.node_ring {
                        nr.ingest(&body.node_id, &body.logs);
                    }
                    self.stream_hub.publish(
                        "log",
                        &serde_json::json!({ "source": "node", "node_id": body.node_id }),
                    );
                }
                self.stream_hub.publish(
                    "node",
                    &serde_json::json!({
                        "id": body.node_id,
                        "node_id": body.node_id,
                        "applied_revision": body.applied_revision,
                    }),
                );
                if body.links.is_some() || body.traffic.is_some() {
                    self.stream_hub.publish(
                        "tunnel",
                        &serde_json::json!({ "node_id": body.node_id }),
                    );
                    self.stream_hub.publish(
                        "stats",
                        &serde_json::json!({ "node_id": body.node_id }),
                    );
                }

                let params = parse_query(raw_query);
                let wait_ms = params
                    .get("wait_ms")
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0)
                    .min(25_000);

                let mut refresh = self.store.take_pending_refresh(&body.node_id);
                if !refresh && wait_ms > 0 && rev == body.applied_revision {
                    let mut sub = self.store.subscribe(&body.node_id);
                    if self.store.take_pending_refresh(&body.node_id) {
                        refresh = true;
                    } else {
                        match self.store.snapshot(&body.node_id, &body.credential) {
                            Ok(snap) => {
                                if snap.revision != rev {
                                    rev = snap.revision;
                                    refresh = true;
                                }
                            }
                            Err(StoreError::Auth) => {
                                return auth_rejected(&self.auth_fails, &ip)
                            }
                            Err(StoreError::Invalid(_)) => {
                                return failure_response(StatusCode::BAD_REQUEST, true)
                            }
                            Err(_) => {
                                return failure_response(StatusCode::INTERNAL_SERVER_ERROR, true)
                            }
                        }
                    }
                    if !refresh {
                        if let Ok(Some(_)) =
                            tokio::time::timeout(Duration::from_millis(wait_ms), sub.rx.recv())
                                .await
                        {
                            let _ = self.store.take_pending_refresh(&body.node_id);
                            match self.store.snapshot(&body.node_id, &body.credential) {
                                Ok(snap) => {
                                    rev = snap.revision;
                                    refresh = true;
                                }
                                Err(StoreError::Auth) => {
                                    return auth_rejected(&self.auth_fails, &ip)
                                }
                                Err(StoreError::Invalid(_)) => {
                                    return failure_response(StatusCode::BAD_REQUEST, true)
                                }
                                Err(_) => {
                                    return failure_response(
                                        StatusCode::INTERNAL_SERVER_ERROR,
                                        true,
                                    )
                                }
                            }
                        }
                    }
                }

                json_response(
                    StatusCode::OK,
                    &EventsResponse {
                        revision: rev,
                        refresh,
                    },
                    true,
                )
            }
            _ => failure_response(StatusCode::NOT_FOUND, true),
        }
    }

    fn serve_sse(&self, raw_query: &str) -> Response<Body> {
        {
            let mut active = self.stream_hub.active_subs.lock();
            if *active >= MAX_STREAM_SUBS {
                return Response::builder()
                    .status(StatusCode::TOO_MANY_REQUESTS)
                    .body(Body::from("too many streams\n"))
                    .unwrap();
            }
            *active += 1;
        }
        let guard = SubGuard {
            hub: Arc::clone(&self.stream_hub),
        };
        let params = parse_query(raw_query);
        let filter_types: Option< Vec<String> > = params.get("types").and_then(|s| {
            let v: Vec<String> = s
                .split(',')
                .map(|p| p.trim().to_string())
                .filter(|p| !p.is_empty())
                .collect();
            if v.is_empty() {
                None
            } else {
                Some(v)
            }
        });

        let rx = self.stream_hub.tx.subscribe();
        let initial = format!("event: hello\ndata: {{\"time\":{}}}\n\n", Utc::now().timestamp());
        let s = async_stream(guard, rx, filter_types, initial);
        let mut resp = Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/event-stream")
            .header(header::CACHE_CONTROL, "no-cache")
            .header(header::CONNECTION, "keep-alive")
            .header("X-Accel-Buffering", "no")
            .body(Body::from_stream(s))
            .unwrap();
        set_security_headers(resp.headers_mut(), false);
        resp
    }

    async fn serve_keys(
        &self,
        req: Request<Body>,
        method: &Method,
        path: &str,
        role: &str,
    ) -> Response<Body> {
        if role != ROLE_ADMIN {
            return failure_response(StatusCode::FORBIDDEN, true);
        }
        if path == "/api/v1/keys" && *method == Method::GET {
            return match self.key_store.list() {
                Ok(keys) => json_response(StatusCode::OK, &keys, true),
                Err(_) => failure_response(StatusCode::INTERNAL_SERVER_ERROR, true),
            };
        }
        if path == "/api/v1/keys" && *method == Method::POST {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct CreateKeyReq {
                #[serde(default)]
                name: String,
                #[serde(default)]
                role: String,
            }
            let body: CreateKeyReq = match decode_json_body(req, 64 << 10).await {
                Ok(v) => v,
                Err(resp) => return resp,
            };
            let target_role = if body.role.is_empty() || body.role == ROLE_ADMIN {
                ROLE_ADMIN
            } else if body.role == ROLE_READONLY {
                ROLE_READONLY
            } else {
                return failure_response(StatusCode::BAD_REQUEST, true);
            };
            return match self.key_store.create_named(&body.name, target_role) {
                Ok((plaintext, final_name)) => json_response(
                    StatusCode::CREATED,
                    &serde_json::json!({
                        "key": plaintext,
                        "name": final_name,
                        "role": target_role,
                    }),
                    true,
                ),
                Err(_) => failure_response(StatusCode::BAD_REQUEST, true),
            };
        }
        if let Some(id_str) = path.strip_prefix("/api/v1/keys/") {
            if *method == Method::DELETE {
                let id: i64 = match id_str.parse() {
                    Ok(v) => v,
                    Err(_) => return failure_response(StatusCode::BAD_REQUEST, true),
                };
                return match self.key_store.revoke(id) {
                    Ok(()) => json_response(StatusCode::OK, &serde_json::json!({ "ok": true }), true),
                    Err(_) => failure_response(StatusCode::BAD_REQUEST, true),
                };
            }
        }
        failure_response(StatusCode::NOT_FOUND, true)
    }

    async fn serve_api(
        &self,
        req: Request<Body>,
        method: &Method,
        path: &str,
        raw_query: &str,
        role: &str,
    ) -> Response<Body> {
        if *method != Method::GET && role != ROLE_ADMIN {
            return failure_response(StatusCode::FORBIDDEN, true);
        }
        let trimmed = path.strip_prefix("/api/v1/").unwrap_or("");
        let p: Vec<&str> = trimmed.split('/').collect();
        let id = if p.len() > 1 { p[1] } else { "" };

        match p[0] {
            "logs" => {
                if *method == Method::GET && p.len() == 1 {
                    let q = parse_query(raw_query);
                    let source = q.get("source").map(|s| s.as_str()).unwrap_or("");
                    let node_id = q.get("node_id").map(|s| s.as_str()).unwrap_or("");
                    let level = q.get("level").map(|s| s.as_str()).unwrap_or("");
                    let mut limit = 200usize;
                    if let Some(ls) = q.get("limit") {
                        if let Ok(n) = ls.parse::<usize>() {
                            if n > 0 {
                                limit = n;
                            }
                        }
                    }
                    if limit > 2000 {
                        limit = 2000;
                    }
                    let entries: Vec<LogEntry> = match self.ring {
                        Some(ref r) => r.query(source, node_id, level, limit),
                        None => Vec::new(),
                    };
                    json_response(StatusCode::OK, &entries, true)
                } else {
                    failure_response(StatusCode::NOT_FOUND, true)
                }
            }
            "traffic" => {
                if *method == Method::GET && p.len() == 1 {
                    match self.store.traffic_rows() {
                        Ok(rows) => json_response(StatusCode::OK, &rows, true),
                        Err(_) => failure_response(StatusCode::BAD_REQUEST, true),
                    }
                } else {
                    failure_response(StatusCode::NOT_FOUND, true)
                }
            }
            "stats" => {
                if *method == Method::GET && p.len() == 1 {
                    match self.compute_stats() {
                        Ok(v) => json_response(StatusCode::OK, &v, true),
                        Err(_) => failure_response(StatusCode::BAD_REQUEST, true),
                    }
                } else {
                    failure_response(StatusCode::NOT_FOUND, true)
                }
            }
            "nodes" => {
                if p.len() == 3 && (p[2] == "join" || p[2] == "enroll") {
                    let nodes = match self.store.nodes() {
                        Ok(v) => v,
                        Err(_) => return failure_response(StatusCode::BAD_REQUEST, true),
                    };
                    for n in &nodes {
                        if n.id == id && n.embedded {
                            return failure_response(StatusCode::BAD_REQUEST, true);
                        }
                    }
                }
                if p.len() == 2 && id == "generate" {
                    if *method != Method::POST {
                        return failure_response(StatusCode::NOT_FOUND, true);
                    }
                    return serve_generate(req).await;
                }
                if *method == Method::GET && p.len() == 1 {
                    return match self.store.reported_nodes() {
                        Ok(mut nodes) => {
                            if role != ROLE_ADMIN {
                                for n in &mut nodes {
                                    *n = redact_reported(n.clone());
                                }
                            }
                            json_response(StatusCode::OK, &nodes, true)
                        }
                        Err(_) => failure_response(StatusCode::BAD_REQUEST, true),
                    };
                }
                if (*method == Method::POST && p.len() == 1)
                    || (*method == Method::PUT && p.len() == 2)
                {
                    let val: serde_json::Value = match decode_json_body(req, 512 << 10).await {
                        Ok(v) => v,
                        Err(resp) => return resp,
                    };
                    if let Some(obj) = val.as_object() {
                        if obj.contains_key("client_tunnel") && !obj["client_tunnel"].is_null() {
                            return failure_response(StatusCode::BAD_REQUEST, true);
                        }
                    }
                    let mut node: Node = match serde_json::from_value(val) {
                        Ok(n) => n,
                        Err(_) => return failure_response(StatusCode::BAD_REQUEST, true),
                    };
                    node.id = id.to_string();
                    let mut hb_rx = self.store.subscribe_heartbeat();
                    let had_listener = self.store.has_active_listener(id);
                    return match self.store.save_node(node) {
                        Ok(saved) => {
                            if had_listener {
                                self.wait_node_heartbeat(&mut hb_rx, id, Duration::from_millis(150))
                                    .await;
                            }
                            let latest = self
                                .store
                                .nodes()
                                .ok()
                                .and_then(|list| list.into_iter().find(|n| n.id == saved.id))
                                .unwrap_or(saved);
                            self.log_mgmt("nodes", method.as_str(), id);
                            json_response(StatusCode::OK, &latest, true)
                        }
                        Err(_) => failure_response(StatusCode::BAD_REQUEST, true),
                    };
                }
                if *method == Method::DELETE && p.len() == 2 {
                    return match self.store.remove_node(id, true) {
                        Ok(()) => {
                            self.log_mgmt("nodes", method.as_str(), id);
                            json_response(StatusCode::OK, &serde_json::json!({ "ok": true }), true)
                        }
                        Err(_) => failure_response(StatusCode::BAD_REQUEST, true),
                    };
                }
                if *method == Method::POST && p.len() == 3 && p[2] == "refresh" {
                    #[derive(Deserialize)]
                    #[serde(deny_unknown_fields)]
                    struct EmptyObj {}
                    if let Err(resp) = decode_json_body::<EmptyObj>(req, 64 << 10).await {
                        return resp;
                    }
                    let mut hb_rx = self.store.subscribe_heartbeat();
                    return match self.store.request_refresh(id) {
                        Ok(connected) => {
                            let reported = if connected {
                                self.wait_node_heartbeat(&mut hb_rx, id, Duration::from_millis(600))
                                    .await
                            } else {
                                false
                            };
                            self.log_mgmt("nodes", method.as_str(), id);
                            json_response(
                                StatusCode::OK,
                                &serde_json::json!({ "connected": connected, "reported": reported }),
                                true,
                            )
                        }
                        Err(_) => failure_response(StatusCode::BAD_REQUEST, true),
                    };
                }
                if *method == Method::POST && p.len() == 3 && p[2] == "revoke" {
                    return match self.store.remove_node(id, false) {
                        Ok(()) => {
                            self.log_mgmt("nodes", method.as_str(), id);
                            json_response(StatusCode::OK, &serde_json::json!({ "ok": true }), true)
                        }
                        Err(_) => failure_response(StatusCode::BAD_REQUEST, true),
                    };
                }
                if *method == Method::POST && p.len() == 3 && p[2] == "reset-credential" {
                    return match self.store.reset_credential(id) {
                        Ok(()) => {
                            self.log_mgmt("nodes", method.as_str(), id);
                            json_response(StatusCode::OK, &serde_json::json!({ "ok": true }), true)
                        }
                        Err(_) => failure_response(StatusCode::BAD_REQUEST, true),
                    };
                }
                if *method == Method::POST && p.len() == 3 && p[2] == "disabled" {
                    #[derive(Deserialize)]
                    #[serde(deny_unknown_fields)]
                    struct DisabledInput {
                        #[serde(default)]
                        disabled: bool,
                    }
                    let input: DisabledInput = match decode_json_body(req, 64 << 10).await {
                        Ok(v) => v,
                        Err(resp) => return resp,
                    };
                    let mut hb_rx = self.store.subscribe_heartbeat();
                    let had_listener = self.store.has_active_listener(id);
                    return match self.store.set_node_disabled(id, input.disabled) {
                        Ok(()) => {
                            if had_listener {
                                self.wait_node_heartbeat(&mut hb_rx, id, Duration::from_millis(150))
                                    .await;
                            }
                            self.log_mgmt("nodes", method.as_str(), id);
                            json_response(
                                StatusCode::OK,
                                &serde_json::json!({
                                    "connected": self.store.control_connected(id),
                                }),
                                true,
                            )
                        }
                        Err(_) => failure_response(StatusCode::BAD_REQUEST, true),
                    };
                }
                if *method == Method::POST && p.len() == 3 && p[2] == "join" {
                    return self.serve_join(req, id).await;
                }
                if *method == Method::POST && p.len() == 3 && p[2] == "offline" {
                    return self.serve_offline_export(req, id).await;
                }
                if *method == Method::DELETE && p.len() == 3 && p[2] == "enroll" {
                    return match self.store.revoke_enroll_token(id) {
                        Ok(()) => {
                            json_response(StatusCode::OK, &serde_json::json!({ "ok": true }), true)
                        }
                        Err(_) => failure_response(StatusCode::BAD_REQUEST, true),
                    };
                }
                if *method == Method::POST && p.len() == 3 && p[2] == "enroll" {
                    #[derive(Deserialize)]
                    #[serde(deny_unknown_fields)]
                    struct EnrollInput {
                        #[serde(default)]
                        ttl_seconds: i64,
                    }
                    let mut input: EnrollInput = match decode_json_body(req, 64 << 10).await {
                        Ok(v) => v,
                        Err(resp) => return resp,
                    };
                    if input.ttl_seconds == 0 {
                        input.ttl_seconds = 3600;
                    }
                    if input.ttl_seconds < 1 || input.ttl_seconds > 86400 {
                        return failure_response(StatusCode::BAD_REQUEST, true);
                    }
                    return match self
                        .store
                        .enroll_token(id, Duration::from_secs(input.ttl_seconds as u64))
                    {
                        Ok(token) => json_response(
                            StatusCode::OK,
                            &serde_json::json!({ "token": token }),
                            true,
                        ),
                        Err(_) => failure_response(StatusCode::BAD_REQUEST, true),
                    };
                }
                failure_response(StatusCode::NOT_FOUND, true)
            }
            "mappings" => {
                if p.len() == 2 && id == "status" && (*method != Method::GET || !raw_query.is_empty())
                {
                    return failure_response(StatusCode::NOT_FOUND, true);
                }
                if *method == Method::GET && p.len() == 1 {
                    return match self.store.mappings() {
                        Ok(mut list) => {
                            for m in &mut list {
                                m.binding_id.clear();
                            }
                            json_response(StatusCode::OK, &list, true)
                        }
                        Err(_) => failure_response(StatusCode::BAD_REQUEST, true),
                    };
                }
                if *method == Method::GET && p.len() == 2 && id == "status" {
                    return match self.store.mapping_statuses() {
                        Ok(statuses) => json_response(StatusCode::OK, &statuses, true),
                        Err(_) => failure_response(StatusCode::BAD_REQUEST, true),
                    };
                }
                if (*method == Method::POST && p.len() == 1)
                    || (*method == Method::PUT && p.len() == 2)
                {
                    let mut m: Mapping = match decode_json_body(req, 64 << 10).await {
                        Ok(v) => v,
                        Err(resp) => return resp,
                    };
                    m.id = id.to_string();
                    let srv_id = m.server_id.clone();
                    let cli_id = m.client_id.clone();
                    let mut hb_rx = self.store.subscribe_heartbeat();
                    let wait_srv = self.store.has_active_listener(&srv_id);
                    let wait_cli = self.store.has_active_listener(&cli_id);
                    return match self.store.save_mapping(m) {
                        Ok(mut saved) => {
                            if wait_srv || wait_cli {
                                let _ = tokio::time::timeout(Duration::from_millis(150), async {
                                    let mut got_srv = !wait_srv;
                                    let mut got_cli = !wait_cli;
                                    while !(got_srv && got_cli) {
                                        match hb_rx.recv().await {
                                            Ok(nid) => {
                                                if nid == srv_id {
                                                    got_srv = true;
                                                }
                                                if nid == cli_id {
                                                    got_cli = true;
                                                }
                                            }
                                            Err(_) => break,
                                        }
                                    }
                                })
                                .await;
                            }
                            saved.binding_id.clear();
                            self.log_mgmt("mappings", method.as_str(), id);
                            json_response(StatusCode::OK, &saved, true)
                        }
                        Err(_) => failure_response(StatusCode::BAD_REQUEST, true),
                    };
                }
                if *method == Method::DELETE && p.len() == 2 {
                    return match self.store.delete_mapping(id) {
                        Ok(()) => {
                            self.log_mgmt("mappings", method.as_str(), id);
                            json_response(StatusCode::OK, &serde_json::json!({ "ok": true }), true)
                        }
                        Err(_) => failure_response(StatusCode::BAD_REQUEST, true),
                    };
                }
                failure_response(StatusCode::NOT_FOUND, true)
            }
            "audit" => {
                if *method == Method::GET && p.len() == 1 {
                    match self.store.audit() {
                        Ok(items) => json_response(StatusCode::OK, &items, true),
                        Err(_) => failure_response(StatusCode::BAD_REQUEST, true),
                    }
                } else {
                    failure_response(StatusCode::NOT_FOUND, true)
                }
            }
            _ => failure_response(StatusCode::NOT_FOUND, true),
        }
    }

    fn compute_stats(&self) -> Result<serde_json::Value, StoreError> {
        let nodes = self.store.nodes()?;
        let mappings = self.store.mappings()?;
        let now = Utc::now().timestamp();
        let online = nodes
            .iter()
            .filter(|n| {
                !n.revoked
                    && !n.is_offline()
                    && n.last_seen > 0
                    && now + 10 >= n.last_seen
                    && (now - n.last_seen) < 90
            })
            .count();
        let offline_mode = nodes
            .iter()
            .filter(|n| !n.revoked && n.is_offline())
            .count();
        let enabled_mappings = mappings.iter().filter(|m| m.enabled).count();
        Ok(serde_json::json!({
            "total_nodes": nodes.len(),
            "online_nodes": online,
            "offline_nodes": offline_mode,
            "total_mappings": mappings.len(),
            "enabled_mappings": enabled_mappings,
        }))
    }

    async fn wait_node_heartbeat(
        &self,
        hb_rx: &mut broadcast::Receiver<String>,
        id: &str,
        timeout: Duration,
    ) -> bool {
        tokio::time::timeout(timeout, async {
            while let Ok(nid) = hb_rx.recv().await {
                if nid == id {
                    return true;
                }
            }
            false
        })
        .await
        .unwrap_or(false)
    }

    fn log_mgmt(&self, resource: &str, method: &str, id: &str) {
        if let Some(ref r) = self.ring {
            r.push_entry(
                "master",
                "",
                "INFO",
                &format!(
                    "management operation completed resource={} method={} id={}",
                    resource, method, id
                ),
            );
        }
        self.stream_hub.publish(
            "log",
            &serde_json::json!({ "source": "master", "resource": resource, "id": id }),
        );
        self.stream_hub.publish(
            "stats",
            &serde_json::json!({ "resource": resource, "id": id }),
        );
        if resource == "nodes" {
            self.stream_hub
                .publish("node", &serde_json::json!({ "id": id }));
        } else if resource == "mappings" {
            self.stream_hub
                .publish("tunnel", &serde_json::json!({ "id": id }));
        }
    }

    async fn serve_join(&self, req: Request<Body>, id: &str) -> Response<Body> {
        const DEFAULT_JOIN_TTL: i64 = 86_400;
        const MAX_JOIN_TTL: i64 = 604_800;

        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct JoinInput {
            #[serde(default)]
            master_url: String,
            #[serde(default)]
            ttl_seconds: i64,
            #[serde(default)]
            reset_credential: bool,
        }

        let mut input: JoinInput = match decode_json_body(req, 64 << 10).await {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        if input.ttl_seconds == 0 {
            input.ttl_seconds = DEFAULT_JOIN_TTL;
        }
        let (address, server_name) = match join_address(&input.master_url) {
            Ok(v) => v,
            Err(_) => return failure_response(StatusCode::BAD_REQUEST, true),
        };
        if input.ttl_seconds < 1 || input.ttl_seconds > MAX_JOIN_TTL {
            return failure_response(StatusCode::BAD_REQUEST, true);
        }
        let nodes = match self.store.nodes() {
            Ok(v) => v,
            Err(_) => return failure_response(StatusCode::INTERNAL_SERVER_ERROR, true),
        };
        let mut node_role = String::new();
        for n in &nodes {
            if n.id == id && !n.revoked && !n.embedded && !n.is_offline() {
                node_role = n.role.clone();
                break;
            }
        }
        if node_role != "client" && node_role != "server" {
            return failure_response(StatusCode::BAD_REQUEST, true);
        }
        let ttl_dur = Duration::from_secs(input.ttl_seconds as u64);
        let token = if input.reset_credential {
            match self.store.reset_credential_and_enroll(id, ttl_dur) {
                Ok(t) => t,
                Err(_) => return failure_response(StatusCode::BAD_REQUEST, true),
            }
        } else {
            match self.store.enroll_token(id, ttl_dur) {
                Ok(t) => t,
                Err(_) => return failure_response(StatusCode::BAD_REQUEST, true),
            }
        };
        let (credential, snapshot) = match self.store.ensure_credential_and_snapshot(id) {
            Ok(v) => v,
            Err(_) => return failure_response(StatusCode::BAD_REQUEST, true),
        };
        let disk_state = crate::node::DiskState {
            node_id: id.to_string(),
            master: address.clone(),
            credential,
            snapshot: Some(snapshot),
        };
        let state_bytes = match serde_json::to_vec(&disk_state) {
            Ok(b) => b,
            Err(_) => return failure_response(StatusCode::INTERNAL_SERVER_ERROR, true),
        };
        let state_json = serde_json::to_string_pretty(&disk_state).unwrap_or_default();
        let bootstrap_state =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&state_bytes);

        let mut hasher = Sha256::new();
        hasher.update(id.as_bytes());
        let digest = hasher.finalize();
        let app = format!("veilink-{}-{}", node_role, hex::encode(&digest[..16]));
        let root = format!("/opt/docker/{}", app);
        let cfg_dir = format!("{}/config", root);
        let data_dir = format!("{}/data", root);
        let prepare = format!(
            "mkdir -p {} {} && chown -R 65532:65532 {} {} && chmod 700 {} {}",
            shell_quote(&cfg_dir),
            shell_quote(&data_dir),
            shell_quote(&cfg_dir),
            shell_quote(&data_dir),
            shell_quote(&cfg_dir),
            shell_quote(&data_dir)
        );
        let mut command = format!(
            "docker run -itd --restart unless-stopped --name {}",
            shell_quote(&app)
        );
        if node_role == "server" {
            command.push_str(" --net host");
        }
        command.push_str(&format!(
            " -v {} -v {} -e TZ=Asia/Shanghai ghcr.io/aurorax-neo/veilink:latest {}",
            shell_quote(&format!("{}:/config:ro", cfg_dir)),
            shell_quote(&format!("{}:/data", data_dir)),
            node_role
        ));
        for (flag, value) in [
            ("-master-addr", address.as_str()),
            ("-node-id", id),
            ("-enroll-token", token.as_str()),
            ("-state-dir", "/data/state"),
        ] {
            command.push_str(&format!(" {} {}", flag, shell_quote(value)));
        }
        if !server_name.is_empty() {
            command.push_str(&format!(" -control-server-name {}", shell_quote(&server_name)));
        }
        let offline_command = format!("{} -bootstrap-state {}", command, shell_quote(&bootstrap_state));
        let mut binary_command = format!(
            "veilink {} -master-addr {} -node-id {} -enroll-token {} -state-dir '/var/lib/veilink'",
            node_role,
            shell_quote(&address),
            shell_quote(id),
            shell_quote(&token),
        );
        if !server_name.is_empty() {
            binary_command
                .push_str(&format!(" -control-server-name {}", shell_quote(&server_name)));
        }
        let mut offline_binary_command = format!(
            "veilink {} -master-addr {} -node-id {} -enroll-token {} -state-dir '/data/state'",
            node_role,
            shell_quote(&address),
            shell_quote(id),
            shell_quote(&token),
        );
        if !server_name.is_empty() {
            offline_binary_command
                .push_str(&format!(" -control-server-name {}", shell_quote(&server_name)));
        }
        offline_binary_command.push_str(&format!(
            " -bootstrap-state {}",
            shell_quote(&bootstrap_state)
        ));
        let mut warning = "命令包含持久有效的节点接入令牌，可能出现在 shell 历史和 Docker inspect 的容器参数中；请勿分享或记录日志。".to_string();
        if server_name.is_empty() {
            warning.push_str("HTTP/h2c 管理连接不加密，仅用于可信网络；必须填写节点实际可达的 Master 地址，不能用另一台主机的 127.0.0.1。");
        } else {
            warning.push_str(&format!(
                "私有 Master CA 时，请将证书放入 {}/ca.pem，并在角色子命令后添加 -control-ca /config/ca.pem；不要关闭 TLS 验证。",
                cfg_dir
            ));
        }
        let expires_at = Utc::now().timestamp() + input.ttl_seconds;
        json_response(
            StatusCode::OK,
            &serde_json::json!({
                "prepare": prepare,
                "command": command,
                "binary_command": binary_command,
                "offline_command": offline_command,
                "offline_binary_command": offline_binary_command,
                "bootstrap_state": bootstrap_state,
                "state_json": state_json,
                "token": token,
                "expires_at": expires_at,
                "warning": warning,
            }),
            true,
        )
    }

    async fn serve_offline_export(&self, req: Request<Body>, id: &str) -> Response<Body> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct EmptyObj {}

        let bytes = match axum::body::to_bytes(req.into_body(), 64 << 10).await {
            Ok(b) => b,
            Err(_) => return failure_response(StatusCode::BAD_REQUEST, true),
        };
        if !bytes.iter().all(|b| b.is_ascii_whitespace()) {
            let mut de = serde_json::Deserializer::from_slice(&bytes);
            if EmptyObj::deserialize(&mut de).is_err() || de.end().is_err() {
                return failure_response(StatusCode::BAD_REQUEST, true);
            }
        }

        let (snapshot, changed) = match self.store.export_offline_snapshot(id) {
            Ok(v) => v,
            Err(_) => return failure_response(StatusCode::BAD_REQUEST, true),
        };
        let node_role = snapshot.node.role.clone();
        let disk_state = crate::node::DiskState {
            node_id: id.to_string(),
            master: "offline".to_string(),
            credential: String::new(),
            snapshot: Some(snapshot.clone()),
        };
        let state_bytes = match serde_json::to_vec(&disk_state) {
            Ok(b) => b,
            Err(_) => return failure_response(StatusCode::INTERNAL_SERVER_ERROR, true),
        };
        let state_json = serde_json::to_string_pretty(&disk_state).unwrap_or_default();
        let offline_state = URL_SAFE_NO_PAD.encode(&state_bytes);

        let mut hasher = Sha256::new();
        hasher.update(id.as_bytes());
        let digest = hasher.finalize();
        let short_hex = hex::encode(&digest[..16]);
        let app = format!("veilink-{}-{}", node_role, short_hex);
        let root = format!("/opt/docker/{}", app);
        let cfg_dir = format!("{}/config", root);
        let data_dir = format!("{}/data", root);
        let cfg_file = format!("{}/offline-state.json", cfg_dir);
        let prepare = format!(
            "mkdir -p {} {} && chown -R 65532:65532 {} {} && chmod 700 {} {}",
            shell_quote(&cfg_dir),
            shell_quote(&data_dir),
            shell_quote(&cfg_dir),
            shell_quote(&data_dir),
            shell_quote(&cfg_dir),
            shell_quote(&data_dir)
        );
        let mut docker_base = format!(
            "docker run -itd --restart unless-stopped --name {}",
            shell_quote(&app)
        );
        if node_role == "server" {
            docker_base.push_str(" --net host");
        }
        docker_base.push_str(&format!(
            " -v {} -v {} -e TZ=Asia/Shanghai ghcr.io/aurorax-neo/veilink:latest {} -master-addr 'offline' -node-id {} -state-dir '/data/state'",
            shell_quote(&format!("{}:/config:ro", cfg_dir)),
            shell_quote(&format!("{}:/data", data_dir)),
            node_role,
            shell_quote(id),
        ));
        let command = format!("{} -offline-state {}", docker_base, shell_quote(&offline_state));
        let file_command = format!("{} -offline-state '/config/offline-state.json'", docker_base);
        let binary_command = format!(
            "veilink {} -master-addr 'offline' -node-id {} -state-dir '/var/lib/veilink' -offline-state '/etc/veilink/offline-state.json'",
            node_role,
            shell_quote(id),
        );
        let inline_binary_command = format!(
            "veilink {} -master-addr 'offline' -node-id {} -state-dir '/var/lib/veilink' -offline-state {}",
            node_role,
            shell_quote(id),
            shell_quote(&offline_state),
        );
        let filename = format!(
            "veilink-{}-{}-r{}.json",
            node_role,
            &short_hex[..8],
            snapshot.revision
        );
        if changed {
            self.log_mgmt("nodes", "POST", id);
        }
        json_response(
            StatusCode::OK,
            &serde_json::json!({
                "mode": "offline",
                "node_id": id,
                "role": node_role,
                "revision": snapshot.revision,
                "exported_revision": snapshot.revision,
                "filename": filename,
                "config_path": cfg_file,
                "prepare": prepare,
                "command": command,
                "file_command": file_command,
                "binary_command": binary_command,
                "inline_binary_command": inline_binary_command,
                "offline_state": offline_state,
                "state_json": state_json,
            }),
            true,
        )
    }
}

fn async_stream(
    guard: SubGuard,
    rx: broadcast::Receiver<StreamEvent>,
    filter_types: Option<Vec<String>>,
    initial: String,
) -> impl futures_util::Stream<Item = Result<Bytes, Infallible>> {
    let init_stream = futures_util::stream::once(async move { Ok(Bytes::from(initial)) });
    let bcast = BroadcastStream::new(rx).filter_map(move |item| {
        let filter_types = filter_types.clone();
        async move {
            match item {
                Ok(ev) => {
                    if let Some(ref allowed) = filter_types {
                        if !allowed.iter().any(|t| t == &ev.event_type) {
                            return None;
                        }
                    }
                    Some(Ok(Bytes::from(format!(
                        "event: {}\ndata: {}\n\n",
                        ev.event_type, ev.data_json
                    ))))
                }
                Err(_) => None,
            }
        }
    });
    let ping_stream = futures_util::stream::unfold(
        tokio::time::interval(Duration::from_secs(25)),
        |mut interval| async move {
            interval.tick().await;
            Some((Ok(Bytes::from_static(b": ping\n\n")), interval))
        },
    )
    .skip(1);

    let merged = futures_util::stream::select(bcast, ping_stream);
    init_stream.chain(merged). inspect(move |_| {
        let _keep = &guard;
    })
}

async fn serve_generate(req: Request<Body>) -> Response<Body> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct GenerationRequest {
        #[serde(default)]
        role: String,
        #[serde(default)]
        kind: String,
        #[serde(default)]
        host: String,
        #[serde(default)]
        mode: String,
        #[serde(default)]
        authentication: String,
        #[serde(default)]
        ttl_days: Option<i32>,
    }

    let mut input: GenerationRequest = match decode_json_body(req, 4 << 10).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    if input.role != "server"
        || (input.kind != "vless" && (!input.mode.is_empty() || !input.authentication.is_empty()))
        || (input.kind != "certificate" && (!input.host.is_empty() || input.ttl_days.is_some()))
    {
        return failure_response(StatusCode::BAD_REQUEST, true);
    }
    match input.kind.as_str() {
        "reality" => match tunnel::generate_x25519() {
            Ok((private_key, public_key)) => {
                let short_id = generate_short_id();
                json_response(
                    StatusCode::OK,
                    &serde_json::json!({
                        "private_key": private_key,
                        "public_key": public_key,
                        "short_id": short_id,
                    }),
                    true,
                )
            }
            Err(_) => failure_response(StatusCode::INTERNAL_SERVER_ERROR, true),
        },
        "short_id" => json_response(
            StatusCode::OK,
            &serde_json::json!({
                "short_id": generate_short_id(),
            }),
            true,
        ),
        "mldsa65" => match tunnel::generate_mldsa65() {
            Ok((private_key, public_key)) => json_response(
                StatusCode::OK,
                &serde_json::json!({
                    "private_key": private_key,
                    "public_key": public_key,
                }),
                true,
            ),
            Err(_) => failure_response(StatusCode::INTERNAL_SERVER_ERROR, true),
        },
        "vless" => {
            if input.mode.is_empty() {
                input.mode = "native".to_string();
            }
            if input.authentication.is_empty() {
                input.authentication = "x25519".to_string();
            }
            if !matches!(input.mode.as_str(), "native" | "xorpub" | "random")
                || !matches!(input.authentication.as_str(), "x25519" | "mlkem768")
            {
                return failure_response(StatusCode::BAD_REQUEST, true);
            }
            match tunnel::generate_vless_enc() {
                Ok((mut dec, mut enc, pq_dec, pq_enc)) => {
                    if input.authentication == "mlkem768" {
                        dec = pq_dec;
                        enc = pq_enc;
                    }
                    let dec = match generation_vless_mode(&dec, &input.mode) {
                        Ok(v) => v,
                        Err(_) => return failure_response(StatusCode::INTERNAL_SERVER_ERROR, true),
                    };
                    let enc = match generation_vless_mode(&enc, &input.mode) {
                        Ok(v) => v,
                        Err(_) => return failure_response(StatusCode::INTERNAL_SERVER_ERROR, true),
                    };
                    json_response(
                        StatusCode::OK,
                        &serde_json::json!({
                            "decryption": dec,
                            "encryption": enc,
                        }),
                        true,
                    )
                }
                Err(_) => failure_response(StatusCode::INTERNAL_SERVER_ERROR, true),
            }
        }
        "hysteria2" => {
            let mut password = [0u8; 32];
            rand::rng().fill_bytes(&mut password);
            json_response(
                StatusCode::OK,
                &serde_json::json!({
                    "password": URL_SAFE_NO_PAD.encode(password),
                }),
                true,
            )
        }
        "certificate" => {
            let days = input.ttl_days.unwrap_or(30);
            if !(1..=365).contains(&days) || !valid_generation_host(&input.host) {
                return failure_response(StatusCode::BAD_REQUEST, true);
            }
            match generate_certificate(&input.host, days) {
                Ok(map) => json_response(StatusCode::OK, &map, true),
                Err(_) => failure_response(StatusCode::INTERNAL_SERVER_ERROR, true),
            }
        }
        _ => failure_response(StatusCode::BAD_REQUEST, true),
    }
}

fn generate_short_id() -> String {
    let mut id = [0u8; 8];
    rand::rng().fill_bytes(&mut id);
    hex::encode(id)
}

fn generation_vless_mode(value: &str, mode: &str) -> Result<String, &'static str> {
    let mut parts: Vec<&str> = value.split('.').collect();
    if parts.len() != 4
        || parts[0] != "mlkem768x25519plus"
        || parts[1] != "native"
        || !matches!(mode, "native" | "xorpub" | "random")
    {
        return Err("unexpected VLESS generation grammar");
    }
    parts[1] = mode;
    Ok(parts.join("."))
}

fn valid_generation_host(name: &str) -> bool {
    if name.parse::<IpAddr>().is_ok() {
        return true;
    }
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    for label in name.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        {
            return false;
        }
    }
    true
}

fn generate_certificate(name: &str, days: i32) -> Result<HashMap<String, String>, String> {
    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|e| e.to_string())?;
    let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|e| e.to_string())?;

    let now_ts = Utc::now().timestamp();
    let not_before_ts = now_ts - 300;
    let expires_ts = now_ts + i64::from(days) * 86_400;

    let mut ca_params = CertificateParams::default();
    let mut ca_dn = DistinguishedName::new();
    ca_dn.push(DnType::CommonName, "Veilink local generated CA");
    ca_params.distinguished_name = ca_dn;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params.not_before = rcgen::date_time_ymd(1970, 1, 1) + Duration::from_secs(not_before_ts as u64);
    ca_params.not_after = rcgen::date_time_ymd(1970, 1, 1) + Duration::from_secs(expires_ts as u64);
    let mut ca_serial = [0u8; 16];
    rand::rng().fill_bytes(&mut ca_serial);
    ca_serial[0] &= 0x7f;
    ca_serial[0] |= 0x01;
    ca_params.serial_number = Some(SerialNumber::from_slice(&ca_serial));

    let ca_cert = ca_params.self_signed(&ca_key).map_err(|e| e.to_string())?;

    let mut leaf_params = CertificateParams::default();
    let mut leaf_dn = DistinguishedName::new();
    leaf_dn.push(DnType::CommonName, name);
    leaf_params.distinguished_name = leaf_dn;
    leaf_params.is_ca = IsCa::NoCa;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    leaf_params.not_before =
        rcgen::date_time_ymd(1970, 1, 1) + Duration::from_secs(not_before_ts as u64);
    leaf_params.not_after =
        rcgen::date_time_ymd(1970, 1, 1) + Duration::from_secs(expires_ts as u64);
    let mut leaf_serial = [0u8; 16];
    rand::rng().fill_bytes(&mut leaf_serial);
    leaf_serial[0] &= 0x7f;
    leaf_serial[0] |= 0x01;
    leaf_params.serial_number = Some(SerialNumber::from_slice(&leaf_serial));

    if let Ok(ip) = name.parse::<IpAddr>() {
        leaf_params.subject_alt_names = vec![SanType::IpAddress(ip)];
    } else {
        let ia5 = Ia5String::try_from(name.to_string()).map_err(|e| e.to_string())?;
        leaf_params.subject_alt_names = vec![SanType::DnsName(ia5)];
    }

    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &ca_cert, &ca_key)
        .map_err(|e| e.to_string())?;

    let expires_dt = Utc
        .timestamp_opt(expires_ts, 0)
        .single()
        .unwrap()
        .with_timezone(&crate::auth::shanghai_tz());
    let mut out = HashMap::new();
    out.insert("cert_pem".to_string(), leaf_cert.pem());
    out.insert("key_pem".to_string(), leaf_key.serialize_pem());
    out.insert("ca_pem".to_string(), ca_cert.pem());
    out.insert(
        "expires_at".to_string(),
        expires_dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, false),
    );
    Ok(out)
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\"'\"'"))
}

fn join_address(raw: &str) -> Result<(String, String), &'static str> {
    if raw.is_empty() || raw.chars().any(|c| matches!(c, '\r' | '\n' | '\t' | ' ')) {
        return Err("master_url must be an HTTP or HTTPS origin");
    }
    let rest = if let Some(r) = raw.strip_prefix("https://") {
        ("https", r)
    } else if let Some(r) = raw.strip_prefix("http://") {
        ("http", r)
    } else {
        return Err("master_url must be an HTTP or HTTPS origin");
    };
    if rest.1.contains('?') || rest.1.contains('#') || rest.1.contains('@') {
        return Err("master_url must be an HTTP or HTTPS origin");
    }
    let u = Url::parse(raw).map_err(|_| "master_url must be an HTTP or HTTPS origin")?;
    if (u.scheme() != "http" && u.scheme() != "https")
        || !u.username().is_empty()
        || u.password().is_some()
        || (u.path() != "/" && !u.path().is_empty())
        || u.query().is_some()
        || u.fragment().is_some()
    {
        return Err("master_url must be an HTTP or HTTPS origin");
    }
    let host_raw = u
        .host_str()
        .ok_or("master_url must be an HTTP or HTTPS origin")?;
    let host = host_raw
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host_raw);
    if host.is_empty() {
        return Err("master_url must be an HTTP or HTTPS origin");
    }
    if host.parse::<IpAddr>().is_err() {
        if !host
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'.')
        {
            return Err("invalid hostname");
        }
    }
    let port = match u.port() {
        Some(0) => return Err("invalid port"),
        Some(p) => p,
        None => {
            if rest.0 == "https" {
                443
            } else {
                80
            }
        }
    };
    let server_name = if rest.0 == "https" {
        host.to_string()
    } else {
        String::new()
    };
    let addr = if host.contains(':') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    };
    Ok((addr, server_name))
}

fn redact_reported(mut n: ReportedNode) -> ReportedNode {
    n.node.tunnel = redact_tunnel(n.node.tunnel);
    if let Some(ct) = n.node.client_tunnel {
        n.node.client_tunnel = Some(redact_tunnel(ct));
    }
    n
}

fn redact_tunnel(mut t: LocalTLS) -> LocalTLS {
    t.key_pem.clear();
    t.decryption.clear();
    t.reality.private_key.clear();
    t.reality.mldsa65_seed.clear();
    t.hysteria2.password.clear();
    t
}

fn client_ip(req: &Request<Body>) -> String {
    let host = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip().to_string())
        .unwrap_or_else(|| "127.0.0.1".to_string());
    let xff = req
        .headers()
        .get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok());
    resolve_client_ip(&host, xff)
}

/// Only trust X-Forwarded-For from a loopback or explicitly configured reverse
/// proxy (`VEILINK_TRUSTED_PROXIES`), and only its last hop: that entry is
/// appended by the proxy itself and cannot be forged by the client.
pub(crate) fn resolve_client_ip(peer: &str, xff: Option<&str>) -> String {
    if !is_trusted_proxy_ip(peer) {
        return peer.to_string();
    }
    xff.and_then(|v| v.rsplit(',').next())
        .map(str::trim)
        .filter(|v| v.parse::<std::net::IpAddr>().is_ok())
        .map(str::to_string)
        .unwrap_or_else(|| peer.to_string())
}

fn is_trusted_proxy_ip(peer: &str) -> bool {
    if peer == "127.0.0.1" || peer == "::1" {
        return true;
    }
    if let Ok(raw) = std::env::var("VEILINK_TRUSTED_PROXIES") {
        for entry in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            if entry == "*" || entry == peer {
                return true;
            }
        }
    }
    false
}

fn parse_query(raw: &str) -> HashMap<String, String> {
    if raw.is_empty() {
        return HashMap::new();
    }
    url::form_urlencoded::parse(raw.as_bytes())
        .into_owned()
        .collect()
}

async fn decode_json_body<T: DeserializeOwned>(
    req: Request<Body>,
    limit: usize,
) -> Result<T, Response<Body>> {
    let ct = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !ct.starts_with("application/json") {
        return Err(failure_response(StatusCode::BAD_REQUEST, true));
    }
    let bytes = match axum::body::to_bytes(req.into_body(), limit).await {
        Ok(b) => b,
        Err(_) => return Err(failure_response(StatusCode::BAD_REQUEST, true)),
    };
    let mut de = serde_json::Deserializer::from_slice(&bytes);
    let value = match T::deserialize(&mut de) {
        Ok(v) => v,
        Err(_) => return Err(failure_response(StatusCode::BAD_REQUEST, true)),
    };
    if de.end().is_err() {
        return Err(failure_response(StatusCode::BAD_REQUEST, true));
    }
    Ok(value)
}

fn set_security_headers(headers: &mut axum::http::HeaderMap, no_store: bool) {
    headers.insert(
        "X-Content-Type-Options",
        header::HeaderValue::from_static("nosniff"),
    );
    headers.insert("X-Frame-Options", header::HeaderValue::from_static("DENY"));
    headers.insert(
        "Referrer-Policy",
        header::HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        "Content-Security-Policy",
        header::HeaderValue::from_static(
            "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        ),
    );
    if no_store {
        headers.insert(
            header::CACHE_CONTROL,
            header::HeaderValue::from_static("no-store"),
        );
    }
    if let Ok(val) = header::HeaderValue::from_str(&Utc::now().timestamp_millis().to_string()) {
        headers.insert("X-Server-Time-Ms", val);
    }
}

fn json_response<T: Serialize>(
    status: StatusCode,
    value: &T,
    no_store: bool,
) -> Response<Body> {
    let mut body = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
    body.push(b'\n');
    let mut resp = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap();
    set_security_headers(resp.headers_mut(), no_store);
    resp
}

fn failure_response(status: StatusCode, no_store: bool) -> Response<Body> {
    let text = match status {
        StatusCode::BAD_REQUEST => "invalid request or conflicting resource",
        StatusCode::UNAUTHORIZED => "authentication required",
        StatusCode::FORBIDDEN => "forbidden",
        StatusCode::NOT_FOUND => "not found",
        StatusCode::TOO_MANY_REQUESTS => "too many requests",
        _ => "request failed",
    };
    json_response(status, &serde_json::json!({ "error": text }), no_store)
}

pub fn validate_embedded_web_dir(path: &PathBuf) -> bool {
    path.join("index.html").is_file()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Node;
    use crate::node::is_master_auth_error;

    #[test]
    fn xff_trusts_only_last_hop_from_loopback() {
        // Client-forged leading entries must not change the rate-limit key.
        assert_eq!(resolve_client_ip("127.0.0.1", Some("1.1.1.1, 203.0.113.9")), "203.0.113.9");
        assert_eq!(resolve_client_ip("::1", Some("203.0.113.9")), "203.0.113.9");
        assert_eq!(resolve_client_ip("127.0.0.1", Some("not-an-ip")), "127.0.0.1");
        assert_eq!(resolve_client_ip("127.0.0.1", None), "127.0.0.1");
        assert_eq!(resolve_client_ip("198.51.100.7", Some("1.1.1.1")), "198.51.100.7");
    }

    #[tokio::test]
    async fn control_plane_rate_limits_bruteforce_and_preserves_repeatable_enroll() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("veilink.db").to_string_lossy().to_string();
        let key_path = tmp.path().join("master.key").to_string_lossy().to_string();
        let store = Arc::new(Store::open(&db_path, &key_path).unwrap());
        let node = store
            .save_node(Node {
                id: "node-1".into(),
                name: "node-1".into(),
                role: "client".into(),
                ..Default::default()
            })
            .unwrap();

        // TTL > 7 days must be rejected
        assert!(store
            .enroll_token(&node.id, Duration::from_secs(8 * 86400))
            .is_err());

        // Valid TTL issues token and writes audit record
        let token = store
            .enroll_token(&node.id, Duration::from_secs(3600))
            .unwrap();
        let token_again = store
            .enroll_token(&node.id, Duration::from_secs(3600))
            .unwrap();
        assert_eq!(token, token_again, "repeated enroll_token calls must return the persistent token");
        let audits = store.audit().unwrap();
        assert!(audits.iter().any(|a| a.action == "node.enroll.token" && a.object == node.id));

        let api = Api::new(
            Arc::clone(&store),
            true,
            None,
            WebPersistConfig {
                db_path,
                html_dir: String::new(),
            },
        );

        // Repeatable enrollment within TTL returns the same permanent credential
        for _ in 0..2 {
            let req = Request::builder()
                .method(Method::POST)
                .uri(PATH_ENROLL)
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&EnrollRequest {
                        node_id: node.id.clone(),
                        token: token.clone(),
                    })
                    .unwrap(),
                ))
                .unwrap();
            let resp = api.handle(req).await;
            assert_eq!(resp.status(), StatusCode::OK);
        }

        // Legacy /api/* GET -> 301, POST -> 308
        let get_legacy = Request::builder()
            .method(Method::GET)
            .uri("/api/nodes")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            api.handle(get_legacy).await.status(),
            StatusCode::MOVED_PERMANENTLY
        );
        let post_legacy = Request::builder()
            .method(Method::POST)
            .uri("/api/nodes")
            .body(Body::from("{}"))
            .unwrap();
        assert_eq!(
            api.handle(post_legacy).await.status(),
            StatusCode::PERMANENT_REDIRECT
        );

        // Control-plane auth failures include X-Veilink-Auth-Rejected header and trigger 429 after 30 tries
        for i in 0..31 {
            let bad_req = Request::builder()
                .method(Method::POST)
                .uri(PATH_ENROLL)
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&EnrollRequest {
                        node_id: node.id.clone(),
                        token: "wrong-token".into(),
                    })
                    .unwrap(),
                ))
                .unwrap();
            let resp = api.handle(bad_req).await;
            if i < 30 {
                assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
                assert_eq!(
                    resp.headers()
                        .get("X-Veilink-Auth-Rejected")
                        .and_then(|v| v.to_str().ok()),
                    Some("1")
                );
                let body_bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
                assert!(is_master_auth_error(&body_bytes));
            } else {
                assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
            }
        }

        // Proxy HTML 401/403 must not be mistaken for Master credential rejection
        assert!(!is_master_auth_error(b"<html>401 Authorization Required</html>"));
        assert!(!is_master_auth_error(b"{\"error\":\"forbidden\"}"));
    }

    #[tokio::test]
    async fn email_password_setup_lock_and_session_flow() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("veilink.db").to_string_lossy().to_string();
        let key_path = tmp.path().join("master.key").to_string_lossy().to_string();
        let store = Arc::new(Store::open(&db_path, &key_path).unwrap());
        let api = Api::new(
            Arc::clone(&store),
            true,
            None,
            WebPersistConfig {
                db_path: db_path.clone(),
                html_dir: String::new(),
            },
        );

        // 1. Fresh install reports installed=false and generated .install_secret on disk
        let st_resp = api
            .handle(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/v1/auth/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(st_resp.status(), StatusCode::OK);
        let st_json: serde_json::Value =
            serde_json::from_slice(&axum::body::to_bytes(st_resp.into_body(), 4096).await.unwrap())
                .unwrap();
        assert_eq!(st_json["installed"], false);
        assert_eq!(st_json["locked"], false);

        let secret_path = tmp.path().join(".install_secret");
        assert!(secret_path.is_file());
        let real_secret = std::fs::read_to_string(&secret_path).unwrap().trim().to_string();

        // 2. Visitor with wrong secret is rejected (401)
        let bad_secret = api
            .handle(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/auth/setup")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "install_secret": "VLK-FAKE-0000-0000-0000",
                            "email": "attacker@example.com",
                            "password": "Password123!"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await;
        assert_eq!(bad_secret.status(), StatusCode::UNAUTHORIZED);

        // 3. Non-email username is rejected (400)
        let bad_email = api
            .handle(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/auth/setup")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "install_secret": real_secret,
                            "email": "not-an-email",
                            "password": "Password123!"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await;
        assert_eq!(bad_email.status(), StatusCode::BAD_REQUEST);

        // 4. Legitimate setup succeeds (201), sets HttpOnly cookie, deletes .install_secret
        let ok_setup = api
            .handle(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/auth/setup")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "install_secret": real_secret,
                            "email": "admin@veilink.io",
                            "password": "Password123!"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await;
        assert_eq!(ok_setup.status(), StatusCode::CREATED);
        let cookie_hdr = ok_setup
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(cookie_hdr.contains("veilink_session=vls_"));
        assert!(cookie_hdr.contains("HttpOnly"));
        assert!(!secret_path.exists());
        let setup_body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(ok_setup.into_body(), 4096).await.unwrap(),
        )
        .unwrap();
        let token = setup_body["token"].as_str().unwrap().to_string();

        // 5. Repeat registration is permanently locked (403)
        let locked_setup = api
            .handle(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/auth/setup")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "install_secret": real_secret,
                            "email": "second@veilink.io",
                            "password": "Password123!"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await;
        assert_eq!(locked_setup.status(), StatusCode::FORBIDDEN);

        // 6. Authenticated /api/v1/auth/me & /api/v1/stats succeed using Bearer session token
        let me_resp = api
            .handle(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/v1/auth/me")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(me_resp.status(), StatusCode::OK);
        let me_json: serde_json::Value =
            serde_json::from_slice(&axum::body::to_bytes(me_resp.into_body(), 4096).await.unwrap())
                .unwrap();
        assert_eq!(me_json["email"], "admin@veilink.io");

        // 7. Cookie-only CSRF guard blocks cross-site / same-site subdomain POST, while allowing same-origin
        let csrf_sub = api
            .handle(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/auth/logout")
                    .header(header::COOKIE, format!("veilink_session={token}"))
                    .header("Sec-Fetch-Site", "same-site")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(csrf_sub.status(), StatusCode::UNAUTHORIZED);

        let csrf_origin = api
            .handle(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/auth/logout")
                    .header(header::COOKIE, format!("veilink_session={token}"))
                    .header(header::HOST, "panel.veilink.io")
                    .header(header::ORIGIN, "https://other.veilink.io")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(csrf_origin.status(), StatusCode::UNAUTHORIZED);

        // 8. Same-origin Cookie logout invalidates session
        let out_resp = api
            .handle(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/auth/logout")
                    .header(header::COOKIE, format!("veilink_session={token}"))
                    .header(header::HOST, "panel.veilink.io:8843")
                    .header(header::ORIGIN, "https://panel.veilink.io:8843")
                    .header("Sec-Fetch-Site", "same-origin")
                    .header("X-Forwarded-Proto", "https")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(out_resp.status(), StatusCode::OK);
        assert!(out_resp
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("; Secure"));
        let after_logout = api
            .handle(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/v1/stats")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(after_logout.status(), StatusCode::UNAUTHORIZED);

        // 9. Re-login with email + password succeeds; untrusted peer X-Forwarded-Proto does not force Secure cookie
        let mut untrusted_login_req = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/auth/login")
            .header("Content-Type", "application/json")
            .header("X-Forwarded-Proto", "https")
            .body(Body::from(
                serde_json::json!({
                    "email": "admin@veilink.io",
                    "password": "Password123!"
                })
                .to_string(),
            ))
            .unwrap();
        untrusted_login_req.extensions_mut().insert(ConnectInfo(
            "203.0.113.9:40000".parse::<SocketAddr>().unwrap(),
        ));
        let login_resp = api.handle(untrusted_login_req).await;
        assert_eq!(login_resp.status(), StatusCode::OK);
        assert!(!login_resp
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("; Secure"));
    }

    #[tokio::test]
    async fn offline_node_export_api_rejects_online_join_and_tracks_stats() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("veilink.db").to_string_lossy().to_string();
        let key_path = tmp.path().join("master.key").to_string_lossy().to_string();
        let store = Arc::new(Store::open(&db_path, &key_path).unwrap());
        let api = Api::new(
            Arc::clone(&store),
            true,
            None,
            WebPersistConfig {
                db_path: db_path.clone(),
                html_dir: String::new(),
            },
        );
        // Trigger .install_secret creation via /api/v1/auth/status
        let _ = api
            .handle(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/v1/auth/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        let secret = std::fs::read_to_string(tmp.path().join(".install_secret"))
            .unwrap()
            .trim()
            .to_string();
        let setup_resp = api
            .handle(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/auth/setup")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "install_secret": secret,
                            "email": "ops@veilink.io",
                            "password": "Password123!"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await;
        let setup_json: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(setup_resp.into_body(), 4096).await.unwrap(),
        )
        .unwrap();
        let auth_hdr = format!("Bearer {}", setup_json["token"].as_str().unwrap());

        // Create an offline client via POST /api/v1/nodes
        let create_resp = api
            .handle(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/nodes")
                    .header(header::AUTHORIZATION, &auth_hdr)
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "name": "Airgap-Edge",
                            "role": "client",
                            "mode": "offline",
                            "address": "",
                            "port": 0
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await;
        assert_eq!(create_resp.status(), StatusCode::OK);
        let created: Node = serde_json::from_slice(
            &axum::body::to_bytes(create_resp.into_body(), 8192).await.unwrap(),
        )
        .unwrap();
        assert_eq!(created.mode, "offline");

        // Online /join must be rejected for offline nodes
        let join_resp = api
            .handle(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("/api/v1/nodes/{}/join", created.id))
                    .header(header::AUTHORIZATION, &auth_hdr)
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"master_url":"https://hub.veilink.io:8443"}"#))
                    .unwrap(),
            )
            .await;
        assert_eq!(join_resp.status(), StatusCode::BAD_REQUEST);

        // Offline /offline endpoint returns standalone commands without enroll-token and updates exported_revision
        let off_resp = api
            .handle(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("/api/v1/nodes/{}/offline", created.id))
                    .header(header::AUTHORIZATION, &auth_hdr)
                    .header("Content-Type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await;
        assert_eq!(off_resp.status(), StatusCode::OK);
        let off_json: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(off_resp.into_body(), 64 << 10).await.unwrap(),
        )
        .unwrap();
        let cmd = off_json["command"].as_str().unwrap();
        assert!(cmd.contains("-master-addr 'offline'"));
        assert!(cmd.contains("-offline-state "));
        assert!(!cmd.contains("-enroll-token"));
        let state_disk: crate::node::DiskState =
            serde_json::from_str(off_json["state_json"].as_str().unwrap()).unwrap();
        assert_eq!(state_disk.master, "offline");
        assert!(state_disk.credential.is_empty());
        assert!(state_disk.snapshot.is_some());

        let stats_resp = api
            .handle(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/v1/stats")
                    .header(header::AUTHORIZATION, &auth_hdr)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        let stats_json: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(stats_resp.into_body(), 4096).await.unwrap(),
        )
        .unwrap();
        assert_eq!(stats_json["offline_nodes"], 1);
        assert_eq!(stats_json["online_nodes"], 0);
    }
}
