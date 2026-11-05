use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use chrono::{DateTime, FixedOffset, Utc};
use parking_lot::Mutex;
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

use crate::model::{Binding, ConnectEndpoint, LocalTLS, Mapping, Node, Snapshot};
use crate::{auth, config, dbbackup, tunnel};

pub const SCHEMA_VERSION: i64 = 6;
const MAX_TRAFFIC_ENTRIES: usize = 128;
const MAX_TRAFFIC_BYTE: u64 = (1u64 << 53) - 1;
const HEARTBEAT_PERSIST_INTERVAL: i64 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    Auth,
    Invalid(String),
    RegistrationClosed,
    Other(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auth => write!(f, "unauthorized"),
            Self::Invalid(msg) => {
                if msg.is_empty() {
                    write!(f, "invalid request or conflicting resource")
                } else {
                    write!(f, "{msg}")
                }
            }
            Self::RegistrationClosed => write!(f, "registration is closed"),
            Self::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Other(e.to_string())
    }
}

impl From<std::io::Error> for StoreError {
    fn from(e: std::io::Error) -> Self {
        Self::Other(e.to_string())
    }
}

impl From<anyhow::Error> for StoreError {
    fn from(e: anyhow::Error) -> Self {
        Self::Other(e.to_string())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SoftwareReport {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub software_version: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub software_commit: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReportedNode {
    #[serde(flatten)]
    pub node: Node,
    #[serde(flatten)]
    pub software: SoftwareReport,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrafficBytes {
    pub up_bytes: u64,
    pub down_bytes: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrafficRow {
    pub mapping_id: String,
    pub up_bytes: u64,
    pub down_bytes: u64,
    pub reported_at: Option<DateTime<FixedOffset>>,
    pub has_transfer: bool,
}

#[derive(Debug, Clone, Default)]
struct TrafficNode {
    epoch: String,
    seq: u64,
    seen: HashSet<String>,
    totals: HashMap<String, TrafficBytes>,
    at: DateTime<FixedOffset>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct MappingEndpointStatus {
    pub acknowledged: bool,
    pub reason: String,
    pub linked: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct MappingStatus {
    pub server: MappingEndpointStatus,
    pub client: MappingEndpointStatus,
}

#[derive(Debug, Clone, Default)]
struct MappingAck {
    policy: String,
    failed: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Audit {
    pub at: i64,
    pub action: String,
    pub object: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    #[serde(rename = "Revision", alias = "revision", default)]
    revision: i64,
    #[serde(rename = "Nodes", alias = "nodes", default)]
    nodes: BTreeMap<String, Node>,
    #[serde(rename = "Bindings", alias = "bindings", default)]
    bindings: BTreeMap<String, Binding>,
    #[serde(rename = "Mappings", alias = "mappings", default)]
    mappings: BTreeMap<String, Mapping>,
    #[serde(
        rename = "Secrets",
        alias = "secrets",
        default,
        serialize_with = "serialize_secrets",
        deserialize_with = "deserialize_secrets"
    )]
    secrets: BTreeMap<String, Vec<u8>>,
}

fn serialize_secrets<S>(
    secrets: &BTreeMap<String, Vec<u8>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut encoded = BTreeMap::new();
    for (k, v) in secrets {
        encoded.insert(
            k.clone(),
            base64::engine::general_purpose::STANDARD.encode(v),
        );
    }
    encoded.serialize(serializer)
}

fn deserialize_secrets<'de, D>(deserializer: D) -> Result<BTreeMap<String, Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw: Option<BTreeMap<String, serde_json::Value>> = Option::deserialize(deserializer)?;
    let Some(map) = raw else {
        return Err(serde::de::Error::custom("incomplete persisted configuration"));
    };
    let mut out = BTreeMap::new();
    for (k, v) in map {
        match v {
            serde_json::Value::String(s) => {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(s.as_bytes())
                    .map_err(serde::de::Error::custom)?;
                out.insert(k, bytes);
            }
            serde_json::Value::Array(arr) => {
                let mut bytes = Vec::with_capacity(arr.len());
                for item in arr {
                    let b = item
                        .as_u64()
                        .and_then(|n| u8::try_from(n).ok())
                        .ok_or_else(|| serde::de::Error::custom("invalid byte array in secrets"))?;
                    bytes.push(b);
                }
                out.insert(k, bytes);
            }
            _ => return Err(serde::de::Error::custom("invalid secret value")),
        }
    }
    Ok(out)
}

struct StoreInner {
    db: Arc<Mutex<Connection>>,
    key: Vec<u8>,
    software: HashMap<String, SoftwareReport>,
    listeners: HashMap<u64, (String, mpsc::Sender<i64>)>,
    next_listener_id: u64,
    pending_refresh: HashSet<String>,
    refresh_waiting: HashSet<String>,
    heartbeat_tx: tokio::sync::broadcast::Sender<String>,
    traffic: HashMap<String, TrafficNode>,
    mapping_acks: HashMap<String, HashMap<String, MappingAck>>,
    links: HashMap<String, HashSet<String>>,
}

#[derive(Clone)]
pub struct Store {
    inner: Arc<Mutex<StoreInner>>,
    db: Arc<Mutex<Connection>>,
}

pub struct Subscription {
    store: Store,
    id: u64,
    pub rx: mpsc::Receiver<i64>,
}

impl Drop for Subscription {
    fn drop(&mut self) {
        let mut g = self.store.inner.lock();
        g.listeners.remove(&self.id);
    }
}

impl Store {
    pub fn open(path: &str, key_path: &str) -> Result<Self, StoreError> {
        if let Some(dir) = Path::new(path).parent() {
            if !dir.as_os_str().is_empty() {
                fs::create_dir_all(dir)?;
                set_dir_perm_0700(dir);
            }
        }
        if let Some(dir) = Path::new(key_path).parent() {
            if !dir.as_os_str().is_empty() {
                fs::create_dir_all(dir)?;
                set_dir_perm_0700(dir);
            }
        }
        let key = match fs::read(key_path) {
            Ok(k) => k,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if let Ok(meta) = fs::metadata(path) {
                    if meta.len() > 0 {
                        return Err(StoreError::Other(
                            "deployment key missing for an existing database; restore the original key before startup"
                                .to_string(),
                        ));
                    }
                }
                let mut new_key = vec![0u8; 32];
                rand::rng().fill_bytes(&mut new_key);
                let mut f = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(key_path)?;
                use std::io::Write;
                f.write_all(&new_key)?;
                f.sync_all()?;
                new_key
            }
            Err(e) => return Err(e.into()),
        };
        if key.len() != 32 {
            return Err(StoreError::Other(
                "deployment key must be 32 bytes".to_string(),
            ));
        }
        set_file_perm_0600(Path::new(key_path))?;
        {
            let _f = OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .open(path)?;
        }
        set_file_perm_0600(Path::new(path))?;

        let mut conn = Connection::open(path)?;
        initialize_schema(&mut conn)?;
        migrate_previous_release(&mut conn, path, &key)?;
        conn.execute("UPDATE credentials SET expires=0 WHERE expires>0", [])?;

        let db = Arc::new(Mutex::new(conn));
        let (heartbeat_tx, _) = tokio::sync::broadcast::channel(128);
        Ok(Self {
            db: db.clone(),
            inner: Arc::new(Mutex::new(StoreInner {
                db,
                key,
                software: HashMap::new(),
                listeners: HashMap::new(),
                next_listener_id: 1,
                pending_refresh: HashSet::new(),
                refresh_waiting: HashSet::new(),
                heartbeat_tx,
                traffic: HashMap::new(),
                mapping_acks: HashMap::new(),
                links: HashMap::new(),
            })),
        })
    }

    pub fn open_existing(path: &str, key_path: &str) -> Result<Self, StoreError> {
        let meta = fs::metadata(path)?;
        if !meta.is_file() || meta.len() == 0 {
            return Err(StoreError::Invalid(String::new()));
        }
        let key = fs::read(key_path)?;
        if key.len() != 32 {
            return Err(StoreError::Invalid(String::new()));
        }
        let conn = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        let version: i64 = conn
            .query_row("SELECT version FROM schema_version", [], |r| r.get(0))
            .map_err(|_| StoreError::Other("unsupported or missing database schema".to_string()))?;
        if version != SCHEMA_VERSION {
            return Err(StoreError::Other(
                "unsupported or missing database schema".to_string(),
            ));
        }
        conn.execute_batch("PRAGMA busy_timeout=5000;")?;
        let db = Arc::new(Mutex::new(conn));
        let (heartbeat_tx, _) = tokio::sync::broadcast::channel(128);
        Ok(Self {
            db: db.clone(),
            inner: Arc::new(Mutex::new(StoreInner {
                db,
                key,
                software: HashMap::new(),
                listeners: HashMap::new(),
                next_listener_id: 1,
                pending_refresh: HashSet::new(),
                refresh_waiting: HashSet::new(),
                heartbeat_tx,
                traffic: HashMap::new(),
                mapping_acks: HashMap::new(),
                links: HashMap::new(),
            })),
        })
    }

    pub fn db(&self) -> Arc<Mutex<Connection>> {
        self.db.clone()
    }

    pub fn subscribe(&self, node_id: &str) -> Subscription {
        let mut g = self.inner.lock();
        let id = g.next_listener_id;
        g.next_listener_id += 1;
        let (tx, rx) = mpsc::channel(1);
        g.listeners.insert(id, (node_id.to_string(), tx));
        Subscription {
            store: self.clone(),
            id,
            rx,
        }
    }

    pub fn take_pending_refresh(&self, node_id: &str) -> bool {
        let mut g = self.inner.lock();
        g.pending_refresh.remove(node_id)
    }

    pub fn subscribe_heartbeat(&self) -> tokio::sync::broadcast::Receiver<String> {
        let g = self.inner.lock();
        g.heartbeat_tx.subscribe()
    }

    pub fn has_active_listener(&self, id: &str) -> bool {
        let g = self.inner.lock();
        g.listeners.values().any(|(nid, _)| nid == id)
    }

    pub fn request_refresh(&self, id: &str) -> Result<bool, StoreError> {
        let mut g = self.inner.lock();
        let st = load_from_conn(&g.db.lock())?;
        let Some(n) = st.nodes.get(id) else {
            return Err(StoreError::Invalid(String::new()));
        };
        if n.revoked {
            return Err(StoreError::Invalid(String::new()));
        }
        let now = Utc::now().timestamp();
        let has_listener = g.listeners.values().any(|(nid, _)| nid == id);
        let recent_seen = n.last_seen > 0 && now >= n.last_seen && (now - n.last_seen) < 30;
        let connected = has_listener || recent_seen;
        g.pending_refresh.insert(id.to_string());
        g.refresh_waiting.insert(id.to_string());
        let mut affected = HashSet::new();
        affected.insert(id.to_string());
        notify_locked(&g.listeners, n.desired_revision, &affected);
        Ok(connected)
    }

    pub fn control_connected(&self, id: &str) -> bool {
        let g = self.inner.lock();
        if g.listeners.values().any(|(nid, _)| nid == id) {
            return true;
        }
        if let Ok(st) = load_from_conn(&g.db.lock()) {
            if let Some(n) = st.nodes.get(id) {
                let now = Utc::now().timestamp();
                if !n.revoked && n.last_seen > 0 && now >= n.last_seen && (now - n.last_seen) < 30 {
                    return true;
                }
            }
        }
        false
    }

    pub fn find_node_by_name(&self, name: &str) -> Result<Option<Node>, StoreError> {
        let g = self.inner.lock();
        let st = load_from_conn(&g.db.lock())?;
        Ok(st.nodes.values().find(|n| n.name == name).cloned())
    }

    pub fn nodes(&self) -> Result<Vec<Node>, StoreError> {
        let g = self.inner.lock();
        let st = load_from_conn(&g.db.lock())?;
        let mut out: Vec<Node> = st.nodes.into_values().collect();
        out.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.id.cmp(&b.id)));
        Ok(out)
    }

    pub fn reported_nodes(&self) -> Result<Vec<ReportedNode>, StoreError> {
        let g = self.inner.lock();
        let st = load_from_conn(&g.db.lock())?;
        let mut out: Vec<ReportedNode> = st
            .nodes
            .into_values()
            .map(|n| {
                let sw = g.software.get(&n.id).cloned().unwrap_or_default();
                ReportedNode {
                    node: n,
                    software: sw,
                }
            })
            .collect();
        out.sort_by(|a, b| {
            a.node
                .name
                .cmp(&b.node.name)
                .then_with(|| a.node.id.cmp(&b.node.id))
        });
        Ok(out)
    }

    pub fn save_node(&self, n: Node) -> Result<Node, StoreError> {
        self.save_node_internal(n, false)
    }

    pub fn ensure_embedded_node(&self, mut seed: Node) -> Result<Node, StoreError> {
        if seed.role != "server" {
            return Err(StoreError::Invalid(String::new()));
        }
        seed.id.clear();
        self.save_node_internal(seed, true)
    }

    fn save_node_internal(&self, mut n: Node, embedded: bool) -> Result<Node, StoreError> {
        if n.id.is_empty() {
            n.id = auth::token();
        }
        let action_id = n.id.clone();
        let mut saved_node = n.clone();
        self.mutate("node.save", &action_id, |st, _key| {
            if embedded {
                let mut existing: Option<Node> = None;
                for candidate in st.nodes.values() {
                    if candidate.embedded {
                        if existing.is_some() {
                            return Err(StoreError::Invalid(String::new()));
                        }
                        existing = Some(candidate.clone());
                    }
                }
                if let Some(ex) = existing {
                    if ex.role != "server" || ex.revoked {
                        return Err(StoreError::Invalid(String::new()));
                    }
                    n = ex;
                }
            }
            let was_embedded = st.nodes.get(&n.id).map(|o| o.embedded).unwrap_or(false);
            if !embedded && n.embedded && !was_embedded {
                return Err(StoreError::Invalid(String::new()));
            }
            n.embedded = embedded;
            if n.role == "client" && (n.tunnel != LocalTLS::default() || n.client_tunnel.is_some())
            {
                return Err(StoreError::Invalid(String::new()));
            }
            validate_tunnel(&n.role, &n.tunnel)?;
            if n.name.is_empty() || n.name.len() > 128 || (n.role != "server" && n.role != "client")
            {
                return Err(StoreError::Invalid(String::new()));
            }
            if n.role == "server" {
                if !host_ok(&n.address)
                    || !(1..=65535).contains(&n.port)
                    || validate_connect_endpoints(&n).is_err()
                {
                    return Err(StoreError::Invalid(String::new()));
                }
                n.connect_endpoints = connect_endpoints(&n);
            }
            if let Some(old) = st.nodes.get(&n.id) {
                if old.role != n.role || old.revoked {
                    return Err(StoreError::Invalid(String::new()));
                }
                n.applied_revision = old.applied_revision;
                n.last_seen = old.last_seen;
                n.error = old.error.clone();
                n.embedded = old.embedded || embedded;
                n.disabled = old.disabled;
            }
            if n.role == "server" {
                if !n.tunnel.reality.private_key.is_empty() {
                    let public = crate::model::derive_x25519_public(&n.tunnel.reality.private_key);
                    if !n.tunnel.reality.public_key.is_empty()
                        && n.tunnel.reality.public_key != public
                    {
                        return Err(StoreError::Invalid(String::new()));
                    }
                    n.tunnel.reality.public_key = public;
                }
                let paired = client_template(&n)?;
                n.client_tunnel = paired;
            }
            n.revoked = false;
            st.nodes.insert(n.id.clone(), n.clone());
            validate_state(st)?;
            saved_node = st.nodes.get(&n.id).cloned().unwrap_or(n.clone());
            Ok(())
        })?;
        let g = self.inner.lock();
        let st = load_from_conn(&g.db.lock())?;
        Ok(st.nodes.get(&saved_node.id).cloned().unwrap_or(saved_node))
    }

    pub fn set_node_disabled(&self, id: &str, disabled: bool) -> Result<(), StoreError> {
        self.mutate("node.disable", id, |st, _key| {
            let Some(mut n) = st.nodes.get(id).cloned() else {
                return Err(StoreError::Invalid(String::new()));
            };
            if n.revoked {
                return Err(StoreError::Invalid(String::new()));
            }
            n.disabled = disabled;
            st.nodes.insert(id.to_string(), n);
            Ok(())
        })
    }

    pub fn remove_node(&self, id: &str, remove: bool) -> Result<(), StoreError> {
        let res = self.mutate_with(
            "node.revoke",
            id,
            |st, _key| {
                let Some(mut n) = st.nodes.get(id).cloned() else {
                    return Err(StoreError::Invalid(String::new()));
                };
                if n.embedded {
                    return Err(StoreError::Invalid(String::new()));
                }
                n.revoked = true;
                st.nodes.insert(id.to_string(), n);
                if remove {
                    st.nodes.remove(id);
                    let bids: Vec<String> = st
                        .bindings
                        .iter()
                        .filter(|(_, b)| b.server_id == id || b.client_id == id)
                        .map(|(bid, _)| bid.clone())
                        .collect();
                    for bid in bids {
                        remove_binding(st, &bid);
                    }
                }
                st.secrets.remove(&enrollment_credential_key(id));
                Ok(())
            },
            Some(Box::new(|tx: &Transaction| {
                tx.execute("DELETE FROM credentials WHERE node=?1", params![id])?;
                tx.execute("DELETE FROM enroll WHERE node=?1", params![id])?;
                Ok(())
            })),
        );
        if res.is_ok() {
            let mut g = self.inner.lock();
            g.software.remove(id);
        }
        res
    }

    pub fn revoke_enroll_token(&self, id: &str) -> Result<(), StoreError> {
        let g = self.inner.lock();
        let mut conn = g.db.lock();
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM enroll WHERE node=?1", params![id])?;
        tx.execute(
            "INSERT INTO audit VALUES(?1,?2,?3)",
            params![Utc::now().timestamp(), "node.enroll.revoke", id],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn enroll_token(&self, id: &str, ttl: Duration) -> Result<String, StoreError> {
        let g = self.inner.lock();
        let mut conn = g.db.lock();
        let st = load_from_conn(&conn)?;
        let Some(n) = st.nodes.get(id) else {
            return Err(StoreError::Invalid(String::new()));
        };
        if n.revoked || ttl.is_zero() || ttl > Duration::from_secs(7 * 86400) {
            return Err(StoreError::Invalid(String::new()));
        }
        let tok = auth::token();
        let now = Utc::now().timestamp();
        let expires = now + ttl.as_secs() as i64;
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT OR REPLACE INTO enroll VALUES(?1,?2,?3)",
            params![id, auth::hash(&tok), expires],
        )?;
        tx.execute(
            "INSERT INTO audit VALUES(?1,?2,?3)",
            params![now, "node.enroll.token", id],
        )?;
        tx.commit()?;
        Ok(tok)
    }

    pub fn reset_credential(&self, id: &str) -> Result<(), StoreError> {
        self.rotate_credential(id, None).map(|_| ())
    }

    pub fn reset_credential_and_enroll(
        &self,
        id: &str,
        ttl: Duration,
    ) -> Result<String, StoreError> {
        if ttl.is_zero() || ttl > Duration::from_secs(7 * 86400) {
            return Err(StoreError::Invalid(String::new()));
        }
        self.rotate_credential(id, Some(ttl))
    }

    fn rotate_credential(&self, id: &str, ttl: Option<Duration>) -> Result<String, StoreError> {
        let g = self.inner.lock();
        let mut conn = g.db.lock();
        let mut st = load_from_conn(&conn)?;
        let Some(n) = st.nodes.get(id) else {
            return Err(StoreError::Invalid(String::new()));
        };
        if n.embedded {
            return Err(StoreError::Invalid(String::new()));
        }
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM credentials WHERE node=?1", params![id])?;
        tx.execute("DELETE FROM enroll WHERE node=?1", params![id])?;
        st.secrets.remove(&enrollment_credential_key(id));
        let body = serde_json::to_vec(&st).map_err(|e| StoreError::Other(e.to_string()))?;
        tx.execute("UPDATE config SET data=?1 WHERE id=1", params![&body])?;
        let mut tok = String::new();
        let now = Utc::now().timestamp();
        if let Some(d) = ttl {
            tok = auth::token();
            let expires = now + d.as_secs() as i64;
            tx.execute(
                "INSERT OR REPLACE INTO enroll VALUES(?1,?2,?3)",
                params![id, auth::hash(&tok), expires],
            )?;
        }
        tx.execute(
            "INSERT INTO audit VALUES(?1,?2,?3)",
            params![now, "node.credential.reset", id],
        )?;
        tx.commit()?;
        Ok(tok)
    }

    pub fn enroll(&self, id: &str, token: &str) -> Result<String, StoreError> {
        let g = self.inner.lock();
        let mut conn = g.db.lock();
        let tx = conn.transaction()?;
        let now = Utc::now().timestamp();
        let count = tx.execute(
            "UPDATE enroll SET hash=hash WHERE node=?1 AND hash=?2 AND expires>?3",
            params![id, auth::hash(token), now],
        )?;
        if count != 1 {
            return Err(StoreError::Auth);
        }
        let raw: Vec<u8> = tx.query_row("SELECT data FROM config WHERE id=1", [], |r| r.get(0))?;
        let mut st: State =
            serde_json::from_slice(&raw).map_err(|e| StoreError::Other(e.to_string()))?;
        let Some(n) = st.nodes.get(id) else {
            return Err(StoreError::Auth);
        };
        if n.revoked {
            return Err(StoreError::Auth);
        }
        let existing_cred: Option<(String, i64)> = tx
            .query_row(
                "SELECT hash,expires FROM credentials WHERE node=?1",
                params![id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((cred_hash, _)) = existing_cred {
            let Some(sealed) = st.secrets.get(&enrollment_credential_key(id)) else {
                return Err(StoreError::Other(
                    "existing credential is hash-only; reusable enrollment cannot replace an active credential"
                        .to_string(),
                ));
            };
            let credential = auth::open(&g.key, sealed).map_err(|_| StoreError::Auth)?;
            if auth::hash(&credential) != cred_hash {
                return Err(StoreError::Auth);
            }
            tx.commit()?;
            return Ok(credential);
        }
        let credential = auth::token();
        let sealed = auth::seal(&g.key, &credential)?;
        st.secrets.insert(enrollment_credential_key(id), sealed);
        tx.execute(
            "INSERT OR REPLACE INTO credentials(node,hash,expires) VALUES(?1,?2,0)",
            params![id, auth::hash(&credential)],
        )?;
        let body = serde_json::to_vec(&st).map_err(|e| StoreError::Other(e.to_string()))?;
        tx.execute("UPDATE config SET data=?1 WHERE id=1", params![&body])?;
        tx.commit()?;
        Ok(credential)
    }

    pub fn snapshot(&self, id: &str, credential: &str) -> Result<Snapshot, StoreError> {
        let g = self.inner.lock();
        let conn = g.db.lock();
        let st = load_from_conn(&conn)?;
        if !authorized(&conn, &st, id, credential) {
            return Err(StoreError::Auth);
        }
        let mut current_node = st.nodes.get(id).cloned().ok_or(StoreError::Auth)?;
        current_node.client_tunnel = None;
        if current_node.role == "client" {
            current_node.tunnel = LocalTLS::default();
        }
        let mut out = Snapshot {
            revision: current_node.desired_revision,
            node: current_node.clone(),
            nodes: Vec::new(),
            bindings: Vec::new(),
            mappings: Vec::new(),
        };
        if current_node.disabled {
            return Ok(out);
        }
        let mut peers = BTreeMap::new();
        for (bid, b) in &st.bindings {
            let Some(a) = st.nodes.get(&b.server_id) else {
                continue;
            };
            let Some(c) = st.nodes.get(&b.client_id) else {
                continue;
            };
            if a.revoked
                || c.revoked
                || a.disabled
                || c.disabled
                || (b.server_id != id && b.client_id != id)
            {
                continue;
            }
            if !valid_endpoint_selection(a, &b.connect_endpoint_id) {
                return Err(StoreError::Invalid(String::new()));
            }
            let secret = st
                .secrets
                .get(bid)
                .ok_or_else(|| StoreError::Invalid(String::new()))?;
            let mut b_copy = b.clone();
            b_copy.uuid = auth::open(&g.key, secret)?;
            out.bindings.push(b_copy.clone());
            peers.insert(b.server_id.clone(), true);
            for m in st.mappings.values() {
                if m.binding_id == *bid {
                    if !mapping_matches_binding(m, &b_copy) {
                        return Err(StoreError::Invalid(String::new()));
                    }
                    out.mappings.push(m.clone());
                }
            }
        }
        for peer_id in peers.keys() {
            let mut peer_node = st
                .nodes
                .get(peer_id)
                .cloned()
                .ok_or_else(|| StoreError::Invalid(String::new()))?;
            if id != peer_id {
                peer_node.tunnel = public_tunnel(&peer_node)?;
                peer_node.tunnel.listen_host.clear();
                peer_node.tunnel.listen_port = 0;
            }
            peer_node.client_tunnel = None;
            out.nodes.push(peer_node);
        }
        Ok(out)
    }

    pub fn heartbeat(
        &self,
        id: &str,
        credential: &str,
        applied: i64,
        failed: bool,
    ) -> Result<i64, StoreError> {
        self.heartbeat_software(id, credential, applied, failed, SoftwareReport::default())
    }

    pub fn heartbeat_software(
        &self,
        id: &str,
        credential: &str,
        applied: i64,
        failed: bool,
        software: SoftwareReport,
    ) -> Result<i64, StoreError> {
        let mut g = self.inner.lock();
        let mut st = {
            let conn = g.db.lock();
            let st = load_from_conn(&conn)?;
            if !authorized(&conn, &st, id, credential) {
                return Err(StoreError::Auth);
            }
            st
        };
        if !valid_software_label(&software.software_version)
            || !valid_software_label(&software.software_commit)
        {
            return Err(StoreError::Invalid(String::new()));
        }
        let mut n = st
            .nodes
            .get(id)
            .cloned()
            .ok_or_else(|| StoreError::Auth)?;
        if applied < 0 || applied > n.desired_revision {
            return Err(StoreError::Invalid(String::new()));
        }
        let refreshed = g.refresh_waiting.remove(id);
        let now = Utc::now().timestamp();
        let error = if failed {
            "runtime configuration application failed".to_string()
        } else {
            String::new()
        };
        // Skip rewriting the whole state when nothing but a fresh last_seen changed;
        // the debounce stays well inside the 30s/90s online windows.
        let unchanged = !refreshed
            && n.applied_revision == applied
            && n.error == error
            && n.last_seen > 0
            && now >= n.last_seen
            && now - n.last_seen < HEARTBEAT_PERSIST_INTERVAL;
        n.applied_revision = applied;
        n.last_seen = now;
        n.error = error;
        let desired = n.desired_revision;
        st.nodes.insert(id.to_string(), n);
        if !unchanged {
            let body = serde_json::to_vec(&st).map_err(|e| StoreError::Other(e.to_string()))?;
            let conn = g.db.lock();
            conn.execute("UPDATE config SET data=?1 WHERE id=1", params![&body])?;
        }
        g.software.insert(id.to_string(), software);
        for (mid, m) in &st.mappings {
            if !m.enabled || (id != m.server_id && id != m.client_id) {
                continue;
            }
            let policy = mapping_policy(&st, m);
            let entry = g.mapping_acks.entry(mid.clone()).or_default();
            let old = entry.get(id).cloned().unwrap_or_default();
            if !failed && applied == desired {
                entry.insert(
                    id.to_string(),
                    MappingAck {
                        policy,
                        failed: false,
                    },
                );
            } else if failed && old.policy != policy {
                entry.insert(
                    id.to_string(),
                    MappingAck {
                        policy,
                        failed: true,
                    },
                );
            }
        }
        let _ = g.heartbeat_tx.send(id.to_string());
        Ok(desired)
    }

    pub fn report_links(
        &self,
        id: &str,
        credential: &str,
        bindings: &[String],
    ) -> Result<(), StoreError> {
        let slice = if bindings.len() > 64 {
            &bindings[..64]
        } else {
            bindings
        };
        let mut g = self.inner.lock();
        let st = {
            let conn = g.db.lock();
            let st = load_from_conn(&conn)?;
            if !authorized(&conn, &st, id, credential) {
                return Err(StoreError::Auth);
            }
            st
        };
        let allowed: HashSet<String> = st
            .bindings
            .values()
            .filter(|b| b.server_id == id || b.client_id == id)
            .map(|b| b.id.clone())
            .collect();
        let mut next = HashSet::new();
        for bid in slice {
            if !bid.is_empty() && bid.len() <= 80 && allowed.contains(bid) {
                next.insert(bid.clone());
            }
        }
        g.links.insert(id.to_string(), next);
        Ok(())
    }

    pub fn report_traffic(
        &self,
        id: &str,
        credential: &str,
        epoch: &str,
        seq: u64,
        totals: HashMap<String, TrafficBytes>,
    ) -> Result<(), StoreError> {
        let mut g = self.inner.lock();
        let st = {
            let conn = g.db.lock();
            let st = load_from_conn(&conn)?;
            if !authorized(&conn, &st, id, credential) {
                return Err(StoreError::Auth);
            }
            st
        };
        let Some(node) = st.nodes.get(id) else {
            return Err(StoreError::Invalid(String::new()));
        };
        if node.role != "server"
            || epoch.len() != 32
            || seq == 0
            || totals.len() > MAX_TRAFFIC_ENTRIES
            || !epoch
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err(StoreError::Invalid(String::new()));
        }
        for (mid, v) in &totals {
            let Some(m) = st.mappings.get(mid) else {
                return Err(StoreError::Invalid(String::new()));
            };
            if !m.enabled
                || m.server_id != id
                || v.up_bytes > MAX_TRAFFIC_BYTE
                || v.down_bytes > MAX_TRAFFIC_BYTE
                || v.up_bytes.saturating_add(v.down_bytes) == 0
            {
                return Err(StoreError::Invalid(String::new()));
            }
        }
        let mut prev = g.traffic.get(id).cloned().unwrap_or_default();
        if prev.seen.contains(epoch) && prev.epoch != epoch {
            return Err(StoreError::Invalid(String::new()));
        }
        if prev.epoch == epoch {
            if seq <= prev.seq {
                return Err(StoreError::Invalid(String::new()));
            }
            for (mid, v) in &totals {
                let old = prev.totals.get(mid).copied().unwrap_or_default();
                if v.up_bytes < old.up_bytes || v.down_bytes < old.down_bytes {
                    return Err(StoreError::Invalid(String::new()));
                }
            }
            for mid in prev.totals.keys() {
                if !totals.contains_key(mid) {
                    if let Some(m) = st.mappings.get(mid) {
                        if m.enabled && m.server_id == id {
                            return Err(StoreError::Invalid(String::new()));
                        }
                    }
                }
            }
        }
        if prev.seen.len() >= 32 {
            let keep = prev.epoch.clone();
            prev.seen.clear();
            if !keep.is_empty() {
                prev.seen.insert(keep);
            }
        }
        prev.seen.insert(epoch.to_string());
        prev.epoch = epoch.to_string();
        prev.seq = seq;
        prev.totals = totals;
        prev.at = Utc::now().with_timezone(&crate::auth::shanghai_tz());
        g.traffic.insert(id.to_string(), prev);
        Ok(())
    }

    pub fn traffic_rows(&self) -> Result<Vec<TrafficRow>, StoreError> {
        let g = self.inner.lock();
        let st = load_from_conn(&g.db.lock())?;
        let mut rows = Vec::with_capacity(st.mappings.len());
        for m in st.mappings.values() {
            if !m.enabled {
                continue;
            }
            let mut row = TrafficRow {
                mapping_id: m.id.clone(),
                ..Default::default()
            };
            let revoked = st
                .nodes
                .get(&m.server_id)
                .map(|n| n.revoked)
                .unwrap_or(true);
            if !revoked {
                if let Some(report) = g.traffic.get(&m.server_id) {
                    if let Some(v) = report.totals.get(&m.id) {
                        row.up_bytes = v.up_bytes;
                        row.down_bytes = v.down_bytes;
                        row.reported_at = Some(report.at);
                        row.has_transfer = v.up_bytes > 0 || v.down_bytes > 0;
                    }
                }
            }
            rows.push(row);
        }
        rows.sort_by(|a, b| a.mapping_id.cmp(&b.mapping_id));
        Ok(rows)
    }

    pub fn mappings(&self) -> Result<Vec<Mapping>, StoreError> {
        let g = self.inner.lock();
        let st = load_from_conn(&g.db.lock())?;
        let mut out: Vec<Mapping> = st.mappings.into_values().collect();
        out.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.id.cmp(&b.id)));
        Ok(out)
    }

    pub fn mapping_statuses(&self) -> Result<BTreeMap<String, MappingStatus>, StoreError> {
        let g = self.inner.lock();
        let st = load_from_conn(&g.db.lock())?;
        let mut out = BTreeMap::new();
        let now = Utc::now().timestamp();
        for (id, m) in &st.mappings {
            let policy = mapping_policy(&st, m);
            let endpoint = |node_id: &str| -> MappingEndpointStatus {
                let mut status = MappingEndpointStatus {
                    acknowledged: false,
                    reason: "unknown".to_string(),
                    linked: false,
                };
                let Some(n) = st.nodes.get(node_id) else {
                    status.reason = "node_unavailable".to_string();
                    return status;
                };
                if !n.revoked && !n.disabled && n.last_seen > 0 && now - n.last_seen < 90 {
                    if let Some(links) = g.links.get(node_id) {
                        if links.contains(&m.binding_id) {
                            status.linked = true;
                        }
                    }
                }
                if n.revoked {
                    status.reason = "node_unavailable".to_string();
                    return status;
                }
                if !m.enabled {
                    status.reason = "disabled".to_string();
                    return status;
                }
                let Some(ack) = g.mapping_acks.get(id).and_then(|acks| acks.get(node_id)) else {
                    return status;
                };
                if ack.policy != policy {
                    return status;
                }
                if ack.failed {
                    status.reason = "apply_failed".to_string();
                    return status;
                }
                status.acknowledged = true;
                status.reason = "acknowledged".to_string();
                status
            };
            out.insert(
                id.clone(),
                MappingStatus {
                    server: endpoint(&m.server_id),
                    client: endpoint(&m.client_id),
                },
            );
        }
        Ok(out)
    }

    pub fn save_mapping(&self, mut m: Mapping) -> Result<Mapping, StoreError> {
        m.bandwidth_limit = m.bandwidth_limit.trim().to_string();
        if let Ok(0) = crate::model::bandwidth_bytes(&m.bandwidth_limit) {
            m.bandwidth_limit.clear();
        }
        let network = m.network.trim().to_ascii_lowercase();
        if !network.is_empty() && network != "tcp" && network != "udp" {
            return Err(StoreError::Invalid(String::new()));
        }
        m.network = mapping_net(&network).to_string();
        let mux_type = m
            .effective_mux_type()
            .map_err(|_| StoreError::Invalid(String::new()))?;
        m.mux_type = mux_type;
        if !m.binding_id.is_empty()
            || m.server_id.is_empty()
            || m.client_id.is_empty()
            || !(1..=32).contains(&m.pool)
        {
            return Err(StoreError::Invalid(String::new()));
        }
        if m.id.is_empty() {
            m.id = auth::token();
        }
        let action_id = m.id.clone();
        let mut saved = m.clone();
        self.mutate("mapping.save", &action_id, |st, key| {
            let old = st.mappings.get(&m.id).cloned();
            if !valid_pair(st, &m.server_id, &m.client_id) {
                return Err(StoreError::Invalid(String::new()));
            }
            let srv = st.nodes.get(&m.server_id).unwrap();
            if !valid_endpoint_selection(srv, &m.connect_endpoint_id) {
                return Err(StoreError::Invalid(String::new()));
            }
            for b in st.bindings.values() {
                if mapping_matches_binding(&m, b) {
                    m.binding_id = b.id.clone();
                    break;
                }
            }
            if m.binding_id.is_empty() {
                let b = create_binding(
                    st,
                    key,
                    &m.server_id,
                    &m.client_id,
                    &m.connect_endpoint_id,
                )?;
                m.binding_id = b.id;
            }
            st.mappings.insert(m.id.clone(), m.clone());
            validate_state(st)?;
            if let Some(old_m) = old {
                if !old_m.binding_id.is_empty() && old_m.binding_id != m.binding_id {
                    cleanup_binding(st, &old_m.binding_id);
                }
            }
            saved = m.clone();
            Ok(())
        })?;
        Ok(saved)
    }

    pub fn delete_mapping(&self, id: &str) -> Result<(), StoreError> {
        self.mutate("mapping.delete", id, |st, _key| {
            let Some(m) = st.mappings.remove(id) else {
                return Err(StoreError::Invalid(String::new()));
            };
            cleanup_binding(st, &m.binding_id);
            Ok(())
        })
    }

    pub fn audit(&self) -> Result<Vec<Audit>, StoreError> {
        let g = self.inner.lock();
        let conn = g.db.lock();
        let mut stmt =
            conn.prepare("SELECT at,action,object FROM audit ORDER BY rowid DESC LIMIT 500")?;
        let rows = stmt.query_map([], |row| {
            let mut a = Audit {
                at: row.get(0)?,
                action: row.get(1)?,
                object: row.get(2)?,
            };
            if a.action == "admin.rename" {
                a.object.clear();
            }
            Ok(a)
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    fn mutate<F>(&self, action: &str, id: &str, f: F) -> Result<(), StoreError>
    where
        F: FnOnce(&mut State, &[u8]) -> Result<(), StoreError>,
    {
        self.mutate_with(action, id, f, None)
    }

    fn mutate_with<F>(
        &self,
        action: &str,
        id: &str,
        f: F,
        extra: Option<Box<dyn FnOnce(&Transaction) -> Result<(), StoreError> + '_>>,
    ) -> Result<(), StoreError>
    where
        F: FnOnce(&mut State, &[u8]) -> Result<(), StoreError>,
    {
        let mut g = self.inner.lock();
        let key = g.key.clone();
        let before = load_from_conn(&g.db.lock())?;
        let mut st = before.clone();
        f(&mut st, &key)?;
        let affected = affected_nodes(&before, &st);
        st.revision += 1;
        let rev = st.revision;
        for (node_id, n) in st.nodes.iter_mut() {
            n.desired_revision = before
                .nodes
                .get(node_id)
                .map(|o| o.desired_revision)
                .unwrap_or(0);
            if affected.contains(node_id) {
                n.desired_revision = rev;
            }
        }
        let body = serde_json::to_vec(&st).map_err(|e| StoreError::Other(e.to_string()))?;
        {
            let mut conn = g.db.lock();
            let tx = conn.transaction()?;
            if let Some(ex) = extra {
                ex(&tx)?;
            }
            tx.execute("UPDATE config SET data=?1 WHERE id=1", params![&body])?;
            tx.execute(
                "INSERT INTO audit VALUES(?1,?2,?3)",
                params![Utc::now().timestamp(), action, id],
            )?;
            tx.commit()?;
        }
        notify_locked(&g.listeners, rev, &affected);
        let mids: Vec<String> = g.mapping_acks.keys().cloned().collect();
        for mid in mids {
            let Some(m) = st.mappings.get(&mid) else {
                g.mapping_acks.remove(&mid);
                continue;
            };
            let policy = mapping_policy(&st, m);
            if let Some(endpoints) = g.mapping_acks.get_mut(&mid) {
                endpoints.retain(|node_id, ack| {
                    ack.policy == policy && (node_id == &m.server_id || node_id == &m.client_id)
                });
            }
        }
        for (mid, old_m) in &before.mappings {
            let drop_traffic = match st.mappings.get(mid) {
                Some(new_m) => !new_m.enabled || old_m.server_id != new_m.server_id,
                None => true,
            };
            if drop_traffic {
                for report in g.traffic.values_mut() {
                    report.totals.remove(mid);
                }
            }
        }
        Ok(())
    }
}

fn set_dir_perm_0700(_path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(_path, fs::Permissions::from_mode(0o700));
    }
}

fn set_file_perm_0600(_path: &Path) -> Result<(), StoreError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(_path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn initialize_schema(conn: &mut Connection) -> Result<(), StoreError> {
    let tables: i64 = conn.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
        [],
        |r| r.get(0),
    )?;
    if tables != 0 {
        let res: Result<(i64, i64), _> = conn.query_row(
            "SELECT count(*), COALESCE(max(version),0) FROM schema_version",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        );
        match res {
            Ok((1, v)) if v == SCHEMA_VERSION || v == 5 => {}
            _ => {
                return Err(StoreError::Other(format!(
                    "unsupported database schema: expected version 5 or {SCHEMA_VERSION}; back up before any explicit reset; unknown schemas cannot be automatically migrated"
                )));
            }
        }
    }
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")?;
    if tables != 0 {
        return Ok(());
    }
    let tx = conn.transaction()?;
    tx.execute_batch(
        "CREATE TABLE schema_version(version INTEGER PRIMARY KEY);
         CREATE TABLE config(id INTEGER PRIMARY KEY CHECK(id=1),data BLOB NOT NULL CHECK(json_valid(data)));
         CREATE TABLE admin(username TEXT PRIMARY KEY,password TEXT NOT NULL);
         CREATE TABLE credentials(node TEXT PRIMARY KEY,hash TEXT NOT NULL,expires INTEGER NOT NULL);
         CREATE TABLE enroll(node TEXT PRIMARY KEY,hash TEXT NOT NULL,expires INTEGER NOT NULL);
         CREATE TABLE audit(at INTEGER NOT NULL,action TEXT NOT NULL,object TEXT NOT NULL);",
    )?;
    tx.execute("INSERT INTO schema_version VALUES(?1)", params![SCHEMA_VERSION])?;
    let st = State::default();
    let body = serde_json::to_vec(&st).map_err(|e| StoreError::Other(e.to_string()))?;
    tx.execute("INSERT INTO config VALUES(1,?1)", params![&body])?;
    tx.commit()?;
    Ok(())
}

fn migrate_previous_release(
    conn: &mut Connection,
    path: &str,
    key: &[u8],
) -> Result<(), StoreError> {
    let version: i64 = conn.query_row("SELECT version FROM schema_version", [], |r| r.get(0))?;
    if version == SCHEMA_VERSION {
        return Ok(());
    }
    if version != 5 {
        return Err(StoreError::Other(
            "unsupported database migration".to_string(),
        ));
    }
    let previous: Vec<u8> = conn.query_row("SELECT data FROM config WHERE id=1", [], |r| r.get(0))?;
    let raw_val: serde_json::Value = serde_json::from_slice(&previous)
        .map_err(|e| StoreError::Other(format!("invalid persisted configuration: {e}")))?;
    if let Some(obj) = raw_val.as_object() {
        for req_key in ["Nodes", "Bindings", "Mappings", "Secrets"] {
            if obj.get(req_key).is_none_or(|v| v.is_null()) {
                return Err(StoreError::Other(
                    "incomplete persisted configuration".to_string(),
                ));
            }
        }
    }
    let mut st: State = serde_json::from_slice(&previous)
        .map_err(|e| StoreError::Other(format!("invalid persisted configuration: {e}")))?;
    if st.revision < 0 {
        return Err(StoreError::Other(
            "incomplete persisted configuration".to_string(),
        ));
    }
    let before = st.clone();
    let ids: Vec<String> = st.nodes.keys().cloned().collect();
    for id in ids {
        let mut node = st.nodes.get(&id).unwrap().clone();
        if node.id != id {
            return Err(StoreError::Invalid(String::new()));
        }
        if node.role == "server" {
            let mut candidate = node.clone();
            candidate.client_tunnel = None;
            let paired = client_template(&candidate)
                .map_err(|e| StoreError::Other(format!("cannot migrate server {:?}: {e}", id)))?;
            if let (Some(cur_ct), Some(paired_ct)) = (&node.client_tunnel, &paired) {
                if cur_ct != paired_ct {
                    let mut legacy = paired_ct.clone();
                    legacy.reality.mldsa65_verify.clear();
                    if node.tunnel.reality.mldsa65_seed.is_empty()
                        || !node.tunnel.reality.mldsa65_verify.is_empty()
                        || cur_ct != &legacy
                    {
                        return Err(StoreError::Other(format!(
                            "cannot migrate custom client_tunnel for server {:?}: invalid request",
                            id
                        )));
                    }
                }
            }
            if node.client_tunnel.is_some() && paired.is_none() {
                return Err(StoreError::Invalid(String::new()));
            }
            node.client_tunnel = paired;
        } else if node.role != "client"
            || node.client_tunnel.is_some()
            || node.tunnel != LocalTLS::default()
        {
            return Err(StoreError::Invalid(String::new()));
        }
        st.nodes.insert(id, node);
    }
    for (id, sealed) in &st.secrets {
        if let Err(e) = auth::open(key, sealed) {
            return Err(StoreError::Other(format!(
                "cannot decrypt existing secret {:?}; restore the original deployment key: {e}",
                id
            )));
        }
    }
    for (id, binding) in &st.bindings {
        let srv_ok = st
            .nodes
            .get(&binding.server_id)
            .map(|n| n.role == "server")
            .unwrap_or(false);
        let cli_ok = st
            .nodes
            .get(&binding.client_id)
            .map(|n| n.role == "client")
            .unwrap_or(false);
        if binding.id != *id || !binding.uuid.is_empty() || !srv_ok || !cli_ok {
            return Err(StoreError::Invalid(String::new()));
        }
        let Some(secret) = st.secrets.get(id) else {
            return Err(StoreError::Other(format!(
                "missing or corrupt binding secret {:?}",
                id
            )));
        };
        auth::open(key, secret).map_err(|e| {
            StoreError::Other(format!("missing or corrupt binding secret {:?}: {e}", id))
        })?;
    }
    for (id, mapping) in &st.mappings {
        if mapping.id != *id {
            return Err(StoreError::Invalid(String::new()));
        }
    }
    validate_state(&st)
        .map_err(|e| StoreError::Other(format!("cannot migrate persisted mappings: {e}")))?;
    let affected = affected_nodes(&before, &st);
    if !affected.is_empty() {
        st.revision += 1;
        let rev = st.revision;
        for id in affected {
            if let Some(n) = st.nodes.get_mut(&id) {
                n.desired_revision = rev;
            }
        }
    }
    let body = serde_json::to_vec(&st).map_err(|e| StoreError::Other(e.to_string()))?;
    let has_master: i64 = conn.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='master_config'",
        [],
        |r| r.get(0),
    )?;
    let mut master_previous: Option<Vec<u8>> = None;
    let mut master_body: Option<Vec<u8>> = None;
    if has_master != 0 {
        master_previous = conn
            .query_row("SELECT data FROM master_config WHERE id=1", [], |r| r.get(0))
            .optional()?;
        if let Some(ref mp) = master_previous {
            let (upgraded, _) = config::upgrade_master_document(mp)
                .map_err(|e| StoreError::Other(format!("cannot migrate master configuration: {e}")))?;
            master_body = Some(upgraded);
        }
    }
    let _backup = dbbackup::create(conn, path, key)
        .map_err(|e| StoreError::Other(format!("pre-upgrade backup: {e}")))?;
    let tx = conn.transaction()?;
    let n1 = tx.execute(
        "UPDATE schema_version SET version=?1 WHERE version=5",
        params![SCHEMA_VERSION],
    )?;
    let n2 = tx.execute(
        "UPDATE config SET data=?1 WHERE id=1 AND data=?2",
        params![&body, &previous],
    )?;
    if n1 != 1 || n2 != 1 {
        return Err(StoreError::Other(
            "database changed during migration; retry startup".to_string(),
        ));
    }
    if let (Some(mb), Some(mp)) = (&master_body, &master_previous) {
        let n3 = tx.execute(
            "UPDATE master_config SET data=?1 WHERE id=1 AND data=?2",
            params![mb, mp],
        )?;
        if n3 != 1 {
            return Err(StoreError::Other(
                "database changed during migration; retry startup".to_string(),
            ));
        }
    }
    tx.commit()?;
    Ok(())
}

fn load_from_conn(conn: &Connection) -> Result<State, StoreError> {
    let b: Vec<u8> = conn.query_row("SELECT data FROM config WHERE id=1", [], |r| r.get(0))?;
    let st: State = serde_json::from_slice(&b).map_err(|e| {
        StoreError::Other(format!(
            "unsupported persisted configuration: {e}; back up before explicitly resetting obsolete data"
        ))
    })?;
    for node in st.nodes.values() {
        if node.role == "server" {
            public_tunnel(node).map_err(|e| {
                StoreError::Other(format!(
                    "unsupported persisted configuration: server {:?} has invalid or custom client_tunnel: {e}; back up before explicitly resetting obsolete data",
                    node.id
                ))
            })?;
        }
    }
    Ok(st)
}

fn authorized(conn: &Connection, st: &State, id: &str, credential: &str) -> bool {
    let Some(n) = st.nodes.get(id) else {
        return false;
    };
    if n.revoked || credential.is_empty() {
        return false;
    }
    let stored: Option<String> = conn
        .query_row(
            "SELECT hash FROM credentials WHERE node=?1",
            params![id],
            |r| r.get(0),
        )
        .optional()
        .ok()
        .flatten();
    stored.as_deref() == Some(&auth::hash(credential))
}

fn notify_locked(
    listeners: &HashMap<u64, (String, mpsc::Sender<i64>)>,
    revision: i64,
    affected: &HashSet<String>,
) {
    for (node_id, tx) in listeners.values() {
        if affected.contains(node_id) {
            let _ = tx.try_send(revision);
        }
    }
}

fn enrollment_credential_key(id: &str) -> String {
    format!("credential:{id}")
}

fn valid_software_label(s: &str) -> bool {
    s.len() <= 128
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'_' | b'+'))
}

fn node_runtime_config(mut n: Node) -> Node {
    n.name.clear();
    n.desired_revision = 0;
    n.applied_revision = 0;
    n.last_seen = 0;
    n.error.clear();
    for ep in &mut n.connect_endpoints {
        ep.name.clear();
    }
    n
}

fn node_config_equal(a: &Node, b: &Node) -> bool {
    node_runtime_config(a.clone()) == node_runtime_config(b.clone())
}

fn server_client_config_equal(a: &Node, b: &Node) -> bool {
    let a = node_runtime_config(a.clone());
    let b = node_runtime_config(b.clone());
    a.address == b.address
        && a.port == b.port
        && a.connect_endpoints == b.connect_endpoints
        && a.client_tunnel == b.client_tunnel
}

fn binding_peers(st: &State, node_id: &str) -> HashSet<String> {
    let mut peers = HashSet::new();
    for b in st.bindings.values() {
        if b.server_id == node_id {
            peers.insert(b.client_id.clone());
        }
        if b.client_id == node_id {
            peers.insert(b.server_id.clone());
        }
    }
    peers
}

fn mapping_config_equal(a: &Mapping, b: &Mapping) -> bool {
    let mut a = a.clone();
    let mut b = b.clone();
    a.name.clear();
    b.name.clear();
    a == b
}

fn affected_nodes(before: &State, after: &State) -> HashSet<String> {
    let mut affected = HashSet::new();
    for (id, n) in &before.nodes {
        if after.nodes.get(id).is_none_or(|next| !node_config_equal(n, next)) {
            affected.insert(id.clone());
        }
    }
    for (id, n) in &after.nodes {
        if before.nodes.get(id).is_none_or(|old| !node_config_equal(old, n)) {
            affected.insert(id.clone());
        }
    }
    for (id, b) in &before.bindings {
        let changed = after.bindings.get(id).is_none_or(|next| next != b);
        if changed {
            affected.insert(b.server_id.clone());
            affected.insert(b.client_id.clone());
            if let Some(next) = after.bindings.get(id) {
                affected.insert(next.server_id.clone());
                affected.insert(next.client_id.clone());
            }
        }
    }
    for (id, b) in &after.bindings {
        if before.bindings.get(id).is_none_or(|old| old != b) {
            affected.insert(b.server_id.clone());
            affected.insert(b.client_id.clone());
        }
    }
    for (id, m) in &before.mappings {
        let changed = after
            .mappings
            .get(id)
            .is_none_or(|next| !mapping_config_equal(m, next));
        if changed {
            if let Some(b) = before.bindings.get(&m.binding_id) {
                affected.insert(b.server_id.clone());
                affected.insert(b.client_id.clone());
            }
            if let Some(next) = after.mappings.get(id) {
                if let Some(b) = after.bindings.get(&next.binding_id) {
                    affected.insert(b.server_id.clone());
                    affected.insert(b.client_id.clone());
                }
            }
        }
    }
    for (id, m) in &after.mappings {
        if before
            .mappings
            .get(id)
            .is_none_or(|old| !mapping_config_equal(old, m))
        {
            if let Some(b) = after.bindings.get(&m.binding_id) {
                affected.insert(b.server_id.clone());
                affected.insert(b.client_id.clone());
            }
        }
    }
    for (id, old) in &before.nodes {
        if let Some(next) = after.nodes.get(id) {
            if node_config_equal(old, next) {
                continue;
            }
            if old.revoked != next.revoked
                || old.disabled != next.disabled
                || (old.role == "server" && !server_client_config_equal(old, next))
            {
                for peer in binding_peers(before, id) {
                    affected.insert(peer);
                }
                for peer in binding_peers(after, id) {
                    affected.insert(peer);
                }
            }
        } else {
            for peer in binding_peers(before, id) {
                affected.insert(peer);
            }
            for peer in binding_peers(after, id) {
                affected.insert(peer);
            }
        }
    }
    affected
}

fn mapping_policy(st: &State, m: &Mapping) -> String {
    let mut b = st.bindings.get(&m.binding_id).cloned().unwrap_or_default();
    b.uuid.clear();
    let mut pool = 0i64;
    let mut mux_set = BTreeMap::new();
    for other in st.mappings.values() {
        if other.binding_id != m.binding_id || !other.enabled {
            continue;
        }
        if other.pool > pool {
            pool = other.pool;
        }
        if other.mux {
            mux_set.insert(other.mux_type.clone(), true);
        }
    }
    let types: Vec<String> = mux_set.into_keys().collect();
    let mut m_clean = m.clone();
    m_clean.name.clear();
    let srv = st
        .nodes
        .get(&m.server_id)
        .cloned()
        .map(node_runtime_config)
        .unwrap_or_default();
    let cli = st
        .nodes
        .get(&m.client_id)
        .cloned()
        .map(node_runtime_config)
        .unwrap_or_default();
    #[derive(Serialize)]
    struct PolicyDoc {
        mapping: Mapping,
        binding: Binding,
        server: Node,
        client: Node,
        pool: i64,
        mux: Vec<String>,
    }
    let data = serde_json::to_vec(&PolicyDoc {
        mapping: m_clean,
        binding: b,
        server: srv,
        client: cli,
        pool,
        mux: types,
    })
    .unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(&data);
    hex::encode(hasher.finalize())
}

fn connect_endpoints(n: &Node) -> Vec<ConnectEndpoint> {
    if !n.connect_endpoints.is_empty() {
        return n.connect_endpoints.clone();
    }
    if n.address.is_empty() || n.port == 0 {
        return Vec::new();
    }
    vec![ConnectEndpoint {
        id: "primary".to_string(),
        name: "首选".to_string(),
        host: n.address.clone(),
        port: n.port,
        enabled: true,
    }]
}

fn valid_endpoint_selection(n: &Node, id: &str) -> bool {
    if id.is_empty() {
        return true;
    }
    let mut matches = 0usize;
    let mut valid = false;
    for ep in connect_endpoints(n) {
        if ep.id == id {
            matches += 1;
            valid = ep.enabled && host_ok(&ep.host) && (1..=65535).contains(&ep.port);
        }
    }
    matches == 1 && valid
}

fn validate_connect_endpoints(n: &Node) -> Result<(), StoreError> {
    let mut seen = HashSet::new();
    let mut enabled = 0usize;
    for ep in connect_endpoints(n) {
        if ep.id.is_empty()
            || ep.id.len() > 128
            || !seen.insert(ep.id.clone())
            || ep.name.is_empty()
            || ep.name.len() > 128
            || !host_ok(&ep.host)
            || !(1..=65535).contains(&ep.port)
        {
            return Err(StoreError::Invalid(String::new()));
        }
        if ep.enabled {
            enabled += 1;
        }
    }
    if enabled == 0 {
        return Err(StoreError::Invalid(String::new()));
    }
    Ok(())
}

pub fn host_ok(h: &str) -> bool {
    if h.parse::<IpAddr>().is_ok() {
        return true;
    }
    if h.is_empty() || h.len() > 253 || h.to_ascii_lowercase() != h {
        return false;
    }
    for label in h.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        {
            return false;
        }
    }
    true
}

fn listen_host_for_store(h: &str) -> &str {
    if h.is_empty() {
        "127.0.0.1"
    } else {
        h
    }
}

fn listen_overlap(a: &str, b: &str) -> bool {
    let Ok(a_ip) = listen_host_for_store(a).parse::<IpAddr>() else {
        return false;
    };
    let Ok(b_ip) = listen_host_for_store(b).parse::<IpAddr>() else {
        return false;
    };
    a_ip == b_ip || a_ip.is_unspecified() || b_ip.is_unspecified()
}

fn mapping_net(s: &str) -> &str {
    if s.trim().eq_ignore_ascii_case("udp") {
        "udp"
    } else {
        "tcp"
    }
}

fn mapping_matches_binding(m: &Mapping, b: &Binding) -> bool {
    m.server_id == b.server_id
        && m.client_id == b.client_id
        && m.connect_endpoint_id == b.connect_endpoint_id
}

fn valid_pair(st: &State, server_id: &str, client_id: &str) -> bool {
    let Some(srv) = st.nodes.get(server_id) else {
        return false;
    };
    let Some(cli) = st.nodes.get(client_id) else {
        return false;
    };
    srv.role == "server" && cli.role == "client" && !srv.revoked && !cli.revoked
}

fn create_binding(
    st: &mut State,
    key: &[u8],
    server_id: &str,
    client_id: &str,
    endpoint_id: &str,
) -> Result<Binding, StoreError> {
    let id = auth::token();
    let domain = format!("b-{}.veilink.internal", &auth::hash(&id).to_ascii_lowercase()[..24]);
    let mut u = [0u8; 16];
    rand::rng().fill_bytes(&mut u);
    u[6] = (u[6] & 15) | 64;
    u[8] = (u[8] & 63) | 128;
    let uuid = format!(
        "{}-{}-{}-{}-{}",
        hex::encode(&u[0..4]),
        hex::encode(&u[4..6]),
        hex::encode(&u[6..8]),
        hex::encode(&u[8..10]),
        hex::encode(&u[10..16])
    );
    let secret = auth::seal(key, &uuid)?;
    let b = Binding {
        id: id.clone(),
        server_id: server_id.to_string(),
        client_id: client_id.to_string(),
        connect_endpoint_id: endpoint_id.to_string(),
        uuid: String::new(),
        domain,
    };
    st.bindings.insert(id.clone(), b.clone());
    st.secrets.insert(id, secret);
    Ok(b)
}

fn cleanup_binding(st: &mut State, id: &str) {
    if st.mappings.values().any(|m| m.binding_id == id) {
        return;
    }
    st.bindings.remove(id);
    st.secrets.remove(id);
}

fn remove_binding(st: &mut State, id: &str) {
    st.bindings.remove(id);
    st.secrets.remove(id);
    st.mappings.retain(|_, m| m.binding_id != id);
}

fn validate_state(st: &State) -> Result<(), StoreError> {
    let mut pairs = HashSet::new();
    for b in st.bindings.values() {
        let pair = (
            b.server_id.clone(),
            b.client_id.clone(),
            b.connect_endpoint_id.clone(),
        );
        let Some(srv) = st.nodes.get(&b.server_id) else {
            return Err(StoreError::Invalid(String::new()));
        };
        if !pairs.insert(pair) || !valid_endpoint_selection(srv, &b.connect_endpoint_id) {
            return Err(StoreError::Invalid(String::new()));
        }
    }
    for (id, m) in &st.mappings {
        if crate::model::bandwidth_bytes(&m.bandwidth_limit).is_err()
            || m.effective_mux_type().is_err()
        {
            return Err(StoreError::Invalid(String::new()));
        }
        let Some(b) = st.bindings.get(&m.binding_id) else {
            return Err(StoreError::Invalid(String::new()));
        };
        if m.name.is_empty()
            || m.name.len() > 128
            || (!m.network.is_empty() && m.network != "tcp" && m.network != "udp")
            || !(1..=65535).contains(&m.listen_port)
            || !(1..=65535).contains(&m.target_port)
            || !host_ok(&m.target_host)
            || m.listen_host.parse::<IpAddr>().is_err()
        {
            return Err(StoreError::Invalid(String::new()));
        }
        let srv_role = st
            .nodes
            .get(&b.server_id)
            .map(|n| n.role.as_str())
            .unwrap_or("");
        let cli_role = st
            .nodes
            .get(&b.client_id)
            .map(|n| n.role.as_str())
            .unwrap_or("");
        if !mapping_matches_binding(m, b)
            || !(1..=32).contains(&m.pool)
            || srv_role != "server"
            || cli_role != "client"
        {
            return Err(StoreError::Invalid(String::new()));
        }
        let n = st.nodes.get(&b.server_id).unwrap();
        if n.tunnel == LocalTLS::default() || validate_tunnel("server", &n.tunnel).is_err() {
            return Err(StoreError::Invalid(String::new()));
        }
        if n.tunnel.listen_port == 0 {
            return Err(StoreError::Invalid(String::new()));
        }
        let transport_net = if n.tunnel.hysteria2.enabled() {
            "udp"
        } else {
            "tcp"
        };
        let transport_host = listen_host_for_store(&n.tunnel.listen_host);
        if m.enabled
            && mapping_net(&m.network) == transport_net
            && m.listen_port == n.tunnel.listen_port
            && listen_overlap(&m.listen_host, transport_host)
        {
            return Err(StoreError::Invalid(String::new()));
        }
        for (oid, o) in &st.mappings {
            if oid != id && m.enabled && o.enabled {
                let o_srv = st
                    .bindings
                    .get(&o.binding_id)
                    .map(|ob| ob.server_id.as_str())
                    .unwrap_or("");
                if o_srv == b.server_id
                    && o.listen_port == m.listen_port
                    && mapping_net(&o.network) == mapping_net(&m.network)
                    && listen_overlap(&o.listen_host, &m.listen_host)
                {
                    return Err(StoreError::Invalid(String::new()));
                }
            }
        }
    }
    Ok(())
}

pub fn validate_tunnel(role: &str, local: &LocalTLS) -> Result<(), StoreError> {
    if role != "server" && role != "client" {
        return Err(StoreError::Invalid(String::new()));
    }
    let mut unconfigured = local.clone();
    unconfigured.listen_host.clear();
    unconfigured.listen_port = 0;
    if unconfigured == LocalTLS::default() {
        return Ok(());
    }
    match local.flow.trim() {
        "" | "none" | "xtls-rprx-vision" | "xtls-rprx-vision-udp443" => {}
        _ => return Err(StoreError::Invalid(String::new())),
    }
    if local.cert_pem.len() > (64 << 10)
        || local.key_pem.len() > (64 << 10)
        || local.ca_pem.len() > (64 << 10)
    {
        return Err(StoreError::Invalid(String::new()));
    }
    if !local.cert_pem.is_empty() || !local.key_pem.is_empty() {
        config::validate_tls_keypair_pem(&local.cert_pem, &local.key_pem)
            .map_err(|_| StoreError::Invalid(String::new()))?;
    }
    if !local.ca_pem.is_empty() {
        validate_strict_ca_pem(&local.ca_pem)?;
    }
    if role == "client"
        && (!local.decryption.is_empty()
            || !local.key_pem.is_empty()
            || !local.cert_pem.is_empty()
            || !local.listen_host.is_empty()
            || local.listen_port != 0
            || !local.reality.private_key.is_empty()
            || !local.reality.dest.is_empty()
            || !local.reality.short_ids.is_empty())
    {
        return Err(StoreError::Invalid(String::new()));
    }
    if role == "server" && !local.encryption.is_empty() && local.encryption != "none" {
        return Err(StoreError::Invalid(String::new()));
    }
    if !local.listen_host.is_empty() && local.listen_host.parse::<IpAddr>().is_err() {
        return Err(StoreError::Invalid(String::new()));
    }
    if !(0..=65535).contains(&local.listen_port) {
        return Err(StoreError::Invalid(String::new()));
    }
    if role == "server" {
        tunnel::check_bootstrap(role, local).map_err(|_| StoreError::Invalid(String::new()))?;
        tunnel::derive_client_tunnel(&LocalTLS::default(), local, &Node::default())
            .map_err(|_| StoreError::Invalid(String::new()))?;
    } else {
        tunnel::validate_client_template(local).map_err(|_| StoreError::Invalid(String::new()))?;
    }
    if !local.reality.private_key.is_empty()
        && crate::model::derive_x25519_public(&local.reality.private_key).is_empty()
    {
        return Err(StoreError::Invalid(String::new()));
    }
    let flow = local.flow.trim();
    if local.hysteria2.enabled()
        && (local.reality.enabled() || (!flow.is_empty() && flow != "none"))
    {
        return Err(StoreError::Invalid(String::new()));
    }
    if role == "server"
        && !flow.is_empty()
        && flow != "none"
        && !local.reality.enabled()
        && (local.cert_pem.is_empty() || local.key_pem.is_empty())
    {
        return Err(StoreError::Invalid(String::new()));
    }
    Ok(())
}

pub fn validate_strict_ca_pem(ca_pem: &str) -> Result<(), StoreError> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let mut remaining = ca_pem.trim();
    if remaining.is_empty() {
        return Err(StoreError::Invalid(String::new()));
    }
    while !remaining.is_empty() {
        if !remaining.starts_with(BEGIN) {
            return Err(StoreError::Invalid(String::new()));
        }
        let Some(end_idx) = remaining.find(END) else {
            return Err(StoreError::Invalid(String::new()));
        };
        let end_at = end_idx + END.len();
        let first = &remaining[..end_at];
        if first[BEGIN.len()..].contains("-----BEGIN") {
            return Err(StoreError::Invalid(String::new()));
        }
        let body = first[BEGIN.len()..end_idx].trim();
        // Reject PEM headers (like `Proc-Type: ...`)
        if body.lines().any(|line| line.contains(':')) {
            return Err(StoreError::Invalid(String::new()));
        }
        let mut reader = std::io::Cursor::new(first.as_bytes());
        let items: Vec<_> = rustls_pemfile::read_all(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| StoreError::Invalid(String::new()))?;
        if items.len() != 1 {
            return Err(StoreError::Invalid(String::new()));
        }
        match &items[0] {
            rustls_pemfile::Item::X509Certificate(der) => {
                if der.is_empty() {
                    return Err(StoreError::Invalid(String::new()));
                }
                let mut root_store = rustls::RootCertStore::empty();
                root_store
                    .add(der.clone())
                    .map_err(|_| StoreError::Invalid(String::new()))?;
            }
            _ => return Err(StoreError::Invalid(String::new())),
        }
        remaining = remaining[end_at..].trim();
    }
    Ok(())
}

fn client_template(server: &Node) -> Result<Option<LocalTLS>, StoreError> {
    let mut unconfigured = server.tunnel.clone();
    unconfigured.listen_host.clear();
    unconfigured.listen_port = 0;
    if unconfigured == LocalTLS::default() {
        if server.client_tunnel.is_some() {
            return Err(StoreError::Invalid(String::new()));
        }
        return Ok(None);
    }
    if !server.tunnel.xhttp.download_endpoint_id.is_empty() {
        let mode = server.tunnel.xhttp.mode.as_str();
        if !mode.is_empty() && mode != "packet-up" && mode != "auto" && mode != "stream-up" {
            return Err(StoreError::Invalid(String::new()));
        }
        if !valid_endpoint_selection(server, &server.tunnel.xhttp.download_endpoint_id) {
            return Err(StoreError::Invalid(String::new()));
        }
    }
    validate_tunnel("server", &server.tunnel)?;
    let derived = tunnel::derive_client_tunnel(&LocalTLS::default(), &server.tunnel, server)
        .map_err(|_| StoreError::Invalid(String::new()))?;
    if !server.tunnel.reality.private_key.is_empty()
        && derived.reality.public_key
            != crate::model::derive_x25519_public(&server.tunnel.reality.private_key)
    {
        return Err(StoreError::Invalid(String::new()));
    }
    if let Some(ref ct) = server.client_tunnel {
        if ct != &derived {
            return Err(StoreError::Invalid(
                "client_tunnel is read-only and must equal the derived configuration".to_string(),
            ));
        }
    }
    validate_tunnel("client", &derived)?;
    if derived.reality.enabled() {
        let mut effective = server.tunnel.clone();
        if effective.reality.server_names.trim().is_empty() {
            effective.reality.server_names = server.address.clone();
        }
        tunnel::check_bootstrap("server", &effective)
            .map_err(|_| StoreError::Invalid(String::new()))?;
        let mut ids = server.tunnel.reality.short_ids.clone();
        if !server.tunnel.reality.short_id.is_empty() {
            ids.push(',');
            ids.push_str(&server.tunnel.reality.short_id);
        }
        if !listed(&derived.reality.short_id, &ids) {
            return Err(StoreError::Invalid(String::new()));
        }
        let names = if server.tunnel.reality.server_names.trim().is_empty() {
            &server.address
        } else {
            &server.tunnel.reality.server_names
        };
        for name in derived.reality.server_names.split(',') {
            if !listed(name, names) {
                return Err(StoreError::Invalid(String::new()));
            }
        }
    }
    Ok(Some(derived))
}

fn listed(value: &str, list: &str) -> bool {
    list.split(',')
        .any(|item| value.trim().eq_ignore_ascii_case(item.trim()))
}

fn public_tunnel(server: &Node) -> Result<LocalTLS, StoreError> {
    let validated = client_template(server)?;
    match (validated, &server.client_tunnel) {
        (None, None) => Ok(LocalTLS::default()),
        (Some(v), Some(ct)) if &v == ct => Ok(ct.clone()),
        _ => Err(StoreError::Invalid(String::new())),
    }
}
