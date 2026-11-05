use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::Write;
use std::net::IpAddr;
use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::dbbackup;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EmbeddedServerConfig {
    #[serde(rename = "Enabled", alias = "enabled", default)]
    pub enabled: bool,
    #[serde(rename = "Name", alias = "name", default)]
    pub name: String,
    #[serde(rename = "Address", alias = "address", default)]
    pub address: String,
    #[serde(rename = "Port", alias = "port", default)]
    pub port: i64,
    #[serde(rename = "StateDir", alias = "state_dir", default)]
    pub state_dir: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(rename = "Database", alias = "database", default, skip_serializing)]
    pub database: String,
    #[serde(
        rename = "DeploymentKey",
        alias = "deployment_key",
        default,
        skip_serializing
    )]
    pub deployment_key: String,
    #[serde(rename = "ListenAddr", alias = "listen_addr", default)]
    pub listen_addr: String,
    #[serde(rename = "HTMLDir", alias = "html_dir", default, skip_serializing)]
    pub html_dir: String,
    #[serde(rename = "CertFile", alias = "cert_file", default)]
    pub cert_file: String,
    #[serde(rename = "KeyFile", alias = "key_file", default)]
    pub key_file: String,
    #[serde(rename = "Scheme", alias = "scheme", default)]
    pub scheme: String,
    #[serde(rename = "StateDir", alias = "state_dir", default)]
    pub state_dir: String,
    #[serde(rename = "ControlCA", alias = "control_ca", default)]
    pub control_ca: String,
    #[serde(rename = "ControlServerName", alias = "control_server_name", default)]
    pub control_server_name: String,
    #[serde(rename = "MasterAddr", alias = "master_addr", default)]
    pub master_addr: String,
    #[serde(rename = "NodeID", alias = "node_id", default)]
    pub node_id: String,
    #[serde(
        rename = "EnrollToken",
        alias = "enroll_token",
        default,
        skip_serializing
    )]
    pub enroll_token: String,
    #[serde(rename = "EmbeddedServer", alias = "embedded_server", default)]
    pub embedded_server: EmbeddedServerConfig,

    #[serde(skip)]
    pub explicit: HashMap<String, bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MasterConfigUpdate {
    #[serde(default)]
    pub listen_addr: Option<String>,
    #[serde(default)]
    pub scheme: Option<String>,
    #[serde(default)]
    pub cert_file: Option<String>,
    #[serde(default)]
    pub key_file: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct MasterConfigView {
    #[serde(default)]
    pub listen_addr: String,
    #[serde(default)]
    pub scheme: String,
    #[serde(default)]
    pub cert_file: String,
    #[serde(default)]
    pub key_file: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseFlagsError {
    Help,
    Error(String),
}

impl std::fmt::Display for ParseFlagsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Help => write!(f, "flag: help requested"),
            Self::Error(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for ParseFlagsError {}

pub fn defaults() -> Config {
    Config {
        database: "/data/veilink.db".to_string(),
        deployment_key: "/data/veilink.key".to_string(),
        listen_addr: "127.0.0.1:2545".to_string(),
        scheme: "http".to_string(),
        state_dir: "/data/state".to_string(),
        embedded_server: EmbeddedServerConfig {
            enabled: true,
            ..Default::default()
        },
        explicit: HashMap::new(),
        ..Default::default()
    }
}

pub fn parse_flags(role: &str, args: &[String]) -> Result<Config, ParseFlagsError> {
    let mut sink = std::io::stderr();
    parse_flags_output(role, args, &mut sink)
}

pub fn parse_flags_output(
    role: &str,
    args: &[String],
    mut out: impl Write,
) -> Result<Config, ParseFlagsError> {
    let mut c = defaults();
    c.explicit.insert("__parsed".to_string(), true);
    if !matches!(role, "master" | "server" | "client") {
        return Err(ParseFlagsError::Error("unknown command".to_string()));
    }
    let mut i = 0;
    while i < args.len() {
        let raw = &args[i];
        if raw == "--" {
            if i + 1 < args.len() {
                return Err(ParseFlagsError::Error(
                    "unexpected positional arguments".to_string(),
                ));
            }
            break;
        }
        if !raw.starts_with('-') || raw == "-" {
            return Err(ParseFlagsError::Error(
                "unexpected positional arguments".to_string(),
            ));
        }
        let trimmed = raw.trim_start_matches('-');
        if trimmed == "h" || trimmed == "help" {
            let _ = writeln!(
                out,
                "Usage: veilink {role} [flags]\nTunnel settings are managed in the Master Web UI, not local flags: TLS needs a certificate matching the endpoint host and a trusted CA; plain requires VLESS Encryption; REALITY needs matching public key/Short ID/name; Hysteria2 needs UDP, TLS and a shared password. Vision requires TCP + TLS/REALITY and may use encrypted fallback. -control-ca trusts Master HTTPS only, not tunnel TLS."
            );
            return Err(ParseFlagsError::Help);
        }
        let (name, inline_val) = match trimmed.split_once('=') {
            Some((n, v)) => (n, Some(v.to_string())),
            None => (trimmed, None),
        };

        let next_string = |inline: Option<String>, idx: &mut usize| -> Result<String, ParseFlagsError> {
            if let Some(v) = inline {
                return Ok(v);
            }
            if *idx + 1 >= args.len() {
                return Err(ParseFlagsError::Error(format!(
                    "flag needs an argument: -{name}"
                )));
            }
            *idx += 1;
            Ok(args[*idx].clone())
        };

        match (role, name) {
            ("master", "database") => {
                c.database = next_string(inline_val, &mut i)?;
                c.explicit.insert("database".to_string(), true);
            }
            ("master", "deployment-key") => {
                c.deployment_key = next_string(inline_val, &mut i)?;
                c.explicit.insert("deployment_key".to_string(), true);
            }
            ("master", "listen-addr") => {
                c.listen_addr = next_string(inline_val, &mut i)?;
                c.explicit.insert("listen_addr".to_string(), true);
            }
            ("master", "scheme") => {
                c.scheme = next_string(inline_val, &mut i)?;
                c.explicit.insert("scheme".to_string(), true);
            }
            ("master", "cert-file") => {
                c.cert_file = next_string(inline_val, &mut i)?;
                c.explicit.insert("cert_file".to_string(), true);
            }
            ("master", "key-file") => {
                c.key_file = next_string(inline_val, &mut i)?;
                c.explicit.insert("key_file".to_string(), true);
            }
            ("master", "html-dir") => {
                c.html_dir = next_string(inline_val, &mut i)?;
                c.explicit.insert("html_dir".to_string(), true);
            }
            ("master", "state-dir") | ("server", "state-dir") | ("client", "state-dir") => {
                c.state_dir = next_string(inline_val, &mut i)?;
                c.explicit.insert("state_dir".to_string(), true);
            }
            ("master", "control-ca") | ("server", "control-ca") | ("client", "control-ca") => {
                c.control_ca = next_string(inline_val, &mut i)?;
                c.explicit.insert("control_ca".to_string(), true);
            }
            ("master", "control-server-name")
            | ("server", "control-server-name")
            | ("client", "control-server-name") => {
                c.control_server_name = next_string(inline_val, &mut i)?;
                c.explicit.insert("control_server_name".to_string(), true);
            }
            ("master", "embedded-server-enabled") => {
                let val = match inline_val {
                    Some(s) => parse_bool_flag(&s).ok_or_else(|| {
                        ParseFlagsError::Error(format!(
                            "invalid boolean value {:?} for -embedded-server-enabled",
                            s
                        ))
                    })?,
                    None => {
                        if i + 1 < args.len() && !args[i + 1].starts_with('-') {
                            if let Some(b) = parse_bool_flag(&args[i + 1]) {
                                i += 1;
                                b
                            } else {
                                return Err(ParseFlagsError::Error(
                                    "unexpected positional arguments".to_string(),
                                ));
                            }
                        } else {
                            true
                        }
                    }
                };
                c.embedded_server.enabled = val;
                c.explicit
                    .insert("embedded_server.enabled".to_string(), true);
            }
            ("master", "embedded-server-name") => {
                c.embedded_server.name = next_string(inline_val, &mut i)?;
                c.explicit.insert("embedded_server.name".to_string(), true);
            }
            ("master", "embedded-server-address") => {
                c.embedded_server.address = next_string(inline_val, &mut i)?;
                c.explicit
                    .insert("embedded_server.address".to_string(), true);
            }
            ("master", "embedded-server-port") => {
                let s = next_string(inline_val, &mut i)?;
                let p: i64 = s.parse().map_err(|_| {
                    ParseFlagsError::Error(format!(
                        "invalid value {:?} for flag -embedded-server-port",
                        s
                    ))
                })?;
                c.embedded_server.port = p;
                c.explicit.insert("embedded_server.port".to_string(), true);
            }
            ("master", "embedded-server-state-dir") => {
                c.embedded_server.state_dir = next_string(inline_val, &mut i)?;
                c.explicit
                    .insert("embedded_server.state_dir".to_string(), true);
            }
            ("server", "master-addr") | ("client", "master-addr") => {
                c.master_addr = next_string(inline_val, &mut i)?;
                c.explicit.insert("master_addr".to_string(), true);
            }
            ("server", "node-id") | ("client", "node-id") => {
                c.node_id = next_string(inline_val, &mut i)?;
                c.explicit.insert("node_id".to_string(), true);
            }
            ("server", "enroll-token") | ("client", "enroll-token") => {
                c.enroll_token = next_string(inline_val, &mut i)?;
                c.explicit.insert("enroll_token".to_string(), true);
            }
            _ => {
                let msg = format!("flag provided but not defined: -{name}");
                let _ = writeln!(out, "{msg}");
                return Err(ParseFlagsError::Error(msg));
            }
        }
        i += 1;
    }
    Ok(c)
}

fn parse_bool_flag(s: &str) -> Option<bool> {
    match s.to_ascii_lowercase().as_str() {
        "1" | "t" | "true" => Some(true),
        "0" | "f" | "false" => Some(false),
        _ => None,
    }
}

impl Config {
    pub fn validate(&self, role: &str) -> Result<(), String> {
        let exp_scheme = self.explicit.get("scheme").copied().unwrap_or(false);
        if (self.scheme.is_empty() && exp_scheme)
            || (!self.scheme.is_empty() && self.scheme != "http" && self.scheme != "https")
        {
            return Err("scheme must be http or https".to_string());
        }
        if role == "master" {
            if self.database.is_empty() || self.deployment_key.is_empty() {
                return Err("database and deployment_key bootstrap paths required".to_string());
            }
            if self.scheme == "https" && (self.cert_file.is_empty() || self.key_file.is_empty()) {
                return Err("HTTPS cert_file and key_file required".to_string());
            }
            let (listen_host, listen_port_str) = split_host_port(&self.listen_addr)?;
            if !valid_listen_host(&listen_host) {
                return Err(
                    "master listen_addr host must be an IP address or valid hostname".to_string(),
                );
            }
            let listen_port: i64 = listen_port_str.parse().map_err(|_| {
                "master listen_addr must have a numeric port from 0 to 65535".to_string()
            })?;
            if !(0..=65535).contains(&listen_port) {
                return Err(
                    "master listen_addr must have a numeric port from 0 to 65535".to_string(),
                );
            }
            if !self.html_dir.is_empty() {
                let index = Path::new(&self.html_dir).join("index.html");
                match fs::metadata(&index) {
                    Ok(meta) if meta.is_file() => {}
                    _ => return Err("html_dir must contain index.html".to_string()),
                }
            }
            if self.embedded_server.enabled {
                if !(0..=65535).contains(&self.embedded_server.port) {
                    return Err("embedded_server port out of range".to_string());
                }
                let srv_port = if self.embedded_server.port == 0 {
                    8444
                } else {
                    self.embedded_server.port
                };
                if srv_port == listen_port {
                    return Err(
                        "embedded_server port collides with master listen_addr".to_string()
                    );
                }
            }
            return Ok(());
        }
        if role != "server" && role != "client" {
            return Err("invalid role".to_string());
        }
        if self.master_addr.is_empty() || self.node_id.is_empty() || self.state_dir.is_empty() {
            return Err("master_addr, node_id and state_dir required".to_string());
        }
        if !self.cert_file.is_empty()
            || !self.key_file.is_empty()
            || self.explicit.get("cert_file").copied().unwrap_or(false)
            || self.explicit.get("key_file").copied().unwrap_or(false)
        {
            return Err(
                "cert_file and key_file are master-only; configure tunnel certificates in Web"
                    .to_string(),
            );
        }
        Ok(())
    }
}

pub fn split_host_port(addr: &str) -> Result<(String, String), String> {
    if let Some(rest) = addr.strip_prefix('[') {
        let Some((host, port_part)) = rest.split_once(']') else {
            return Err(format!("missing ']' in address {addr}"));
        };
        let Some(port) = port_part.strip_prefix(':') else {
            return Err(format!("missing port in address {addr}"));
        };
        if host.contains('[') || host.contains(']') {
            return Err(format!("unexpected brackets in address {addr}"));
        }
        return Ok((host.to_string(), port.to_string()));
    }
    let Some((host, port)) = addr.rsplit_once(':') else {
        return Err(format!("address {addr}: missing port in address"));
    };
    if host.contains(':') {
        return Err(format!("address {addr}: too many colons in address"));
    }
    Ok((host.to_string(), port.to_string()))
}

pub fn join_host_port(host: &str, port: impl std::fmt::Display) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

pub fn valid_listen_host(h: &str) -> bool {
    if h.is_empty() {
        return true;
    }
    if h.parse::<IpAddr>().is_ok() {
        return true;
    }
    if h.len() > 253 {
        return false;
    }
    for label in h.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return false;
        }
    }
    true
}

pub fn upgrade_master_document(raw: &[u8]) -> Result<(Vec<u8>, bool), String> {
    let val: serde_json::Value =
        serde_json::from_slice(raw).map_err(|e| format!("invalid json: {e}"))?;
    let Some(obj) = val.as_object() else {
        return Err("master configuration must be an object".to_string());
    };
    let mut doc: BTreeMap<String, serde_json::Value> =
        obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    let mut changed = false;
    let keys: Vec<String> = doc.keys().cloned().collect();
    for key in keys {
        let norm = key.to_ascii_lowercase().replace('_', "");
        if matches!(
            norm.as_str(),
            "webmode" | "webversion" | "webmirror" | "webmirrors" | "frontendurl" | "htmldir"
        ) {
            doc.remove(&key);
            changed = true;
        }
    }
    let body = if changed {
        serde_json::to_vec(&doc).map_err(|e| e.to_string())?
    } else {
        raw.to_vec()
    };
    let _c: Config = serde_json::from_slice(&body).map_err(|e| e.to_string())?;
    Ok((body, changed))
}

pub fn get_master_config_view(db_path: &str) -> Result<MasterConfigView, String> {
    let conn = Connection::open(db_path).map_err(|e| e.to_string())?;
    conn.execute_batch("PRAGMA busy_timeout=5000")
        .map_err(|e| e.to_string())?;
    let data: Vec<u8> = conn
        .query_row("SELECT data FROM master_config WHERE id=1", [], |r| r.get(0))
        .map_err(|e| e.to_string())?;
    let cfg: Config = serde_json::from_slice(&data).map_err(|e| e.to_string())?;
    Ok(MasterConfigView {
        listen_addr: cfg.listen_addr,
        scheme: cfg.scheme,
        cert_file: cfg.cert_file,
        key_file: cfg.key_file,
    })
}

pub fn update_master_config(
    db_path: &str,
    update: MasterConfigUpdate,
) -> Result<Vec<String>, String> {
    let conn = Connection::open(db_path).map_err(|e| e.to_string())?;
    conn.execute_batch(
        "PRAGMA busy_timeout=5000;
         CREATE TABLE IF NOT EXISTS master_config(id INTEGER PRIMARY KEY CHECK(id=1), data BLOB NOT NULL);",
    )
    .map_err(|e| e.to_string())?;
    let data: Vec<u8> = conn
        .query_row("SELECT data FROM master_config WHERE id=1", [], |r| r.get(0))
        .map_err(|e| e.to_string())?;
    let mut doc: BTreeMap<String, serde_json::Value> =
        serde_json::from_slice(&data).map_err(|e| e.to_string())?;
    doc.remove("HTMLDir");
    doc.remove("html_dir");
    let mut need_restart = Vec::new();
    if let Some(v) = update.listen_addr {
        doc.insert("ListenAddr".to_string(), serde_json::Value::String(v));
        need_restart.push("ListenAddr".to_string());
    }
    if let Some(v) = update.scheme {
        doc.insert("Scheme".to_string(), serde_json::Value::String(v));
        need_restart.push("Scheme".to_string());
    }
    if let Some(v) = update.cert_file {
        doc.insert("CertFile".to_string(), serde_json::Value::String(v));
        need_restart.push("CertFile".to_string());
    }
    if let Some(v) = update.key_file {
        doc.insert("KeyFile".to_string(), serde_json::Value::String(v));
        need_restart.push("KeyFile".to_string());
    }
    let body = serde_json::to_vec(&doc).map_err(|e| e.to_string())?;
    let mut cfg: Config =
        serde_json::from_slice(&body).map_err(|e| format!("master configuration: {e}"))?;
    cfg.database = db_path.to_string();
    cfg.deployment_key = "configured".to_string();
    cfg.validate("master")?;
    if cfg.scheme == "https" {
        validate_tls_keypair_files(&cfg.cert_file, &cfg.key_file)
            .map_err(|e| format!("master control TLS: {e}"))?;
    }
    let n = conn
        .execute(
            "UPDATE master_config SET data=?1 WHERE id=1 AND data=?2",
            params![&body, &data],
        )
        .map_err(|e| e.to_string())?;
    if n != 1 {
        return Err("master configuration changed concurrently".to_string());
    }
    Ok(need_restart)
}

pub fn persist_master(local: Config) -> Result<Config, String> {
    let (effective, commit) = resolve_master(local)?;
    commit()?;
    Ok(effective)
}

pub fn resolve_master(
    local: Config,
) -> Result<(Config, Box<dyn FnOnce() -> Result<(), String> + Send>), String> {
    if local.database.is_empty() || local.deployment_key.is_empty() {
        return Err("database and deployment_key bootstrap paths required".to_string());
    }
    let conn = Connection::open(&local.database).map_err(|e| e.to_string())?;
    conn.execute_batch(
        "PRAGMA busy_timeout=5000;
         CREATE TABLE IF NOT EXISTS master_config(id INTEGER PRIMARY KEY CHECK(id=1), data BLOB NOT NULL);",
    )
    .map_err(|e| e.to_string())?;
    let mut effective = defaults();
    let previous: Option<Vec<u8>> = conn
        .query_row("SELECT data FROM master_config WHERE id=1", [], |r| r.get(0))
        .optional()
        .map_err(|e| e.to_string())?;
    let found = previous.is_some();
    let mut migrating = false;
    if let Some(ref prev_bytes) = previous {
        let (upgraded, changed) = upgrade_master_document(prev_bytes)
            .map_err(|e| format!("invalid persisted master configuration: {e}"))?;
        migrating = changed;
        effective = serde_json::from_slice(&upgraded)
            .map_err(|e| format!("invalid persisted master configuration: {e}"))?;
        overlay_explicit(&mut effective, &local);
    } else {
        overlay_explicit(&mut effective, &local);
    }
    effective.explicit = local.explicit.clone();
    effective.database = local.database.clone();
    effective.deployment_key = local.deployment_key.clone();
    effective.enroll_token = local.enroll_token.clone();
    effective.html_dir = local.html_dir.clone();
    if effective.scheme.is_empty() && !effective.explicit.get("scheme").copied().unwrap_or(false) {
        effective.scheme = "http".to_string();
    }
    effective
        .validate("master")
        .map_err(|e| format!("master configuration: {e}"))?;
    if effective.scheme == "https" {
        validate_tls_keypair_files(&effective.cert_file, &effective.key_file)
            .map_err(|e| format!("master control TLS: {e}"))?;
        if effective.embedded_server.enabled {
            let ca = if effective.control_ca.is_empty() {
                &effective.cert_file
            } else {
                &effective.control_ca
            };
            validate_ca_file(ca).map_err(|e| format!("embedded control CA: {e}"))?;
        }
    }
    let mut doc: BTreeMap<String, serde_json::Value> = serde_json::to_value(&effective)
        .and_then(serde_json::from_value)
        .map_err(|e| e.to_string())?;
    doc.remove("Database");
    doc.remove("DeploymentKey");
    doc.remove("EnrollToken");
    doc.remove("HTMLDir");
    doc.remove("html_dir");
    let body = serde_json::to_vec(&doc).map_err(|e| e.to_string())?;
    let db_path = local.database.clone();
    let key_path = local.deployment_key.clone();
    let commit = Box::new(move || -> Result<(), String> {
        let conn = Connection::open(&db_path).map_err(|e| e.to_string())?;
        conn.execute_batch("PRAGMA busy_timeout=5000")
            .map_err(|e| e.to_string())?;
        if migrating {
            let key = fs::read(&key_path).unwrap_or_default();
            dbbackup::create(&conn, &db_path, &key)
                .map_err(|e| format!("pre-upgrade backup: {e}"))?;
        }
        let changed = if found {
            conn.execute(
                "UPDATE master_config SET data=?1 WHERE id=1 AND data=?2",
                params![&body, previous.as_deref().unwrap_or(&[])],
            )
            .map_err(|e| e.to_string())?
        } else {
            conn.execute(
                "INSERT INTO master_config(id,data) VALUES(1,?1) ON CONFLICT(id) DO NOTHING",
                params![&body],
            )
            .map_err(|e| e.to_string())?
        };
        if changed != 1 {
            return Err("master configuration changed during startup; retry startup".to_string());
        }
        Ok(())
    });
    Ok((effective, commit))
}

fn overlay_explicit(dst: &mut Config, src: &Config) {
    let all = !src.explicit.contains_key("__parsed") && src.explicit.is_empty();
    let exp = |k: &str| all || src.explicit.get(k).copied().unwrap_or(false);
    if exp("listen_addr") {
        dst.listen_addr = src.listen_addr.clone();
    }
    if exp("scheme") {
        dst.scheme = src.scheme.clone();
    }
    if exp("cert_file") {
        dst.cert_file = src.cert_file.clone();
    }
    if exp("key_file") {
        dst.key_file = src.key_file.clone();
    }
    if exp("state_dir") {
        dst.state_dir = src.state_dir.clone();
    }
    if exp("control_ca") {
        dst.control_ca = src.control_ca.clone();
    }
    if exp("control_server_name") {
        dst.control_server_name = src.control_server_name.clone();
    }
    if exp("master_addr") {
        dst.master_addr = src.master_addr.clone();
    }
    if exp("node_id") {
        dst.node_id = src.node_id.clone();
    }
    if exp("embedded_server.enabled") {
        dst.embedded_server.enabled = src.embedded_server.enabled;
    }
    if exp("embedded_server.name") {
        dst.embedded_server.name = src.embedded_server.name.clone();
    }
    if exp("embedded_server.address") {
        dst.embedded_server.address = src.embedded_server.address.clone();
    }
    if exp("embedded_server.port") {
        dst.embedded_server.port = src.embedded_server.port;
    }
    if exp("embedded_server.state_dir") {
        dst.embedded_server.state_dir = src.embedded_server.state_dir.clone();
    }
}

pub fn validate_tls_keypair_files(cert_file: &str, key_file: &str) -> Result<(), String> {
    let cert_pem = fs::read_to_string(cert_file).map_err(|e| e.to_string())?;
    let key_pem = fs::read_to_string(key_file).map_err(|e| e.to_string())?;
    validate_tls_keypair_pem(&cert_pem, &key_pem)
}

pub fn validate_tls_keypair_pem(cert_pem: &str, key_pem: &str) -> Result<(), String> {
    let mut cert_reader = std::io::Cursor::new(cert_pem.as_bytes());
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    if certs.is_empty() {
        return Err("no certificates found in PEM".to_string());
    }
    let mut key_reader = std::io::Cursor::new(key_pem.as_bytes());
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "no private key found in PEM".to_string())?;
    let provider = rustls::crypto::ring::default_provider();
    let signing_key = provider
        .key_provider
        .load_private_key(key)
        .map_err(|e| format!("invalid private key: {e}"))?;
    let certified = rustls::sign::CertifiedKey::new(certs, signing_key);
    certified
        .keys_match()
        .map_err(|e| format!("certificate and private key do not match: {e}"))?;
    Ok(())
}

pub fn validate_ca_file(ca_file: &str) -> Result<(), String> {
    let pem = fs::read_to_string(ca_file).map_err(|e| e.to_string())?;
    let mut reader = std::io::Cursor::new(pem.as_bytes());
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    if certs.is_empty() {
        return Err("invalid certificate PEM".to_string());
    }
    Ok(())
}
