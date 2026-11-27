use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use chrono::{DateTime, FixedOffset, NaiveDateTime, Utc};
use hmac::{Hmac, Mac};
use parking_lot::Mutex;
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub fn token() -> String {
    let mut b = [0u8; 32];
    rand::rng().fill_bytes(&mut b);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

pub fn hash(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn seal(key: &[u8], s: &str) -> anyhow::Result<Vec<u8>> {
    if key.len() != 32 {
        anyhow::bail!("AES-256 key must be 32 bytes");
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut nonce_bytes = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, s.as_bytes())
        .map_err(|e| anyhow::anyhow!("seal failed: {e}"))?;
    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn open(key: &[u8], b: &[u8]) -> anyhow::Result<String> {
    if key.len() != 32 {
        anyhow::bail!("AES-256 key must be 32 bytes");
    }
    // 12-byte nonce + 16-byte GCM tag.
    if b.len() < 28 {
        anyhow::bail!("invalid ciphertext");
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| anyhow::anyhow!("{e}"))?;
    let nonce = Nonce::from_slice(&b[..12]);
    let plaintext = cipher
        .decrypt(nonce, &b[12..])
        .map_err(|_| anyhow::anyhow!("invalid ciphertext"))?;
    String::from_utf8(plaintext).map_err(|e| e.into())
}

pub type KeyRole = String;
pub const ROLE_ADMIN: &str = "admin";
pub const ROLE_READONLY: &str = "readonly";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct APIKey {
    pub id: i64,
    pub name: String,
    #[serde(skip_serializing, default)]
    pub key_hash: String,
    pub key_prefix: String,
    pub role: KeyRole,
    pub created_at: DateTime<FixedOffset>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used: Option<DateTime<FixedOffset>>,
}

pub fn shanghai_tz() -> FixedOffset {
    FixedOffset::east_opt(8 * 3600).expect("valid UTC+8 offset")
}

pub fn generate_api_key() -> String {
    let mut b = [0u8; 32];
    rand::rng().fill_bytes(&mut b);
    format!("vlk_{}", hex::encode(b))
}

#[derive(Clone)]
pub struct KeyStore {
    db: Arc<Mutex<Connection>>,
    // key_hash -> last time last_used was persisted; debounces per-request writes.
    touched: Arc<Mutex<std::collections::HashMap<String, std::time::Instant>>>,
}

const LAST_USED_DEBOUNCE: std::time::Duration = std::time::Duration::from_secs(300);

impl KeyStore {
    pub fn new(db: Arc<Mutex<Connection>>) -> Self {
        Self {
            db,
            touched: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }

    fn should_touch(&self, key_hash: &str) -> bool {
        let now = std::time::Instant::now();
        let mut touched = self.touched.lock();
        if touched
            .get(key_hash)
            .is_some_and(|t| now.duration_since(*t) < LAST_USED_DEBOUNCE)
        {
            return false;
        }
        if touched.len() > 4096 {
            touched.retain(|_, t| now.duration_since(*t) < LAST_USED_DEBOUNCE);
        }
        touched.insert(key_hash.to_string(), now);
        true
    }

    pub fn migrate(&self) -> anyhow::Result<()> {
        let conn = self.db.lock();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                key_hash TEXT NOT NULL UNIQUE,
                key_prefix TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'admin',
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                last_used DATETIME
            );
            CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);",
        )?;
        Ok(())
    }

    pub fn legacy_admin_pending(&self) -> anyhow::Result<bool> {
        let conn = self.db.lock();
        let admin_count: i64 = match conn.query_row("SELECT COUNT(*) FROM admin", [], |r| r.get(0))
        {
            Ok(c) => c,
            Err(e) if e.to_string().to_lowercase().contains("no such table") => return Ok(false),
            Err(e) => return Err(e.into()),
        };
        if admin_count == 0 {
            return Ok(false);
        }
        let key_count: i64 = conn.query_row("SELECT COUNT(*) FROM api_keys", [], |r| r.get(0))?;
        Ok(key_count == 0)
    }

    pub fn commit_legacy_migration(&self, mut out: impl Write) -> anyhow::Result<()> {
        let mut conn = self.db.lock();
        let tx = conn.transaction()?;
        let admin_count: i64 = match tx.query_row("SELECT COUNT(*) FROM admin", [], |r| r.get(0)) {
            Ok(c) => c,
            Err(e) if e.to_string().to_lowercase().contains("no such table") => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        if admin_count == 0 {
            return Ok(());
        }
        let key_count: i64 = tx.query_row("SELECT COUNT(*) FROM api_keys", [], |r| r.get(0))?;
        if key_count > 0 {
            return Ok(());
        }
        let plaintext = generate_api_key();
        tx.execute(
            "INSERT INTO api_keys (name, key_hash, key_prefix, role) VALUES (?1, ?2, ?3, ?4)",
            params![
                "migrated-admin",
                hash(&plaintext),
                &plaintext[..8],
                ROLE_ADMIN
            ],
        )?;
        writeln!(out, "Migrated API key (shown only once):\n{plaintext}")?;
        tx.commit()?;
        Ok(())
    }

    pub fn create(&self, name: &str, role: &str) -> anyhow::Result<String> {
        let (plaintext, _) = self.create_named(name, role)?;
        Ok(plaintext)
    }

    pub fn create_named(&self, name: &str, role: &str) -> anyhow::Result<(String, String)> {
        let plaintext = generate_api_key();
        let conn = self.db.lock();
        let final_name = if name.trim().is_empty() {
            next_available_key_name(&conn)
        } else {
            name.trim().to_string()
        };
        conn.execute(
            "INSERT INTO api_keys (name, key_hash, key_prefix, role) VALUES (?1, ?2, ?3, ?4)",
            params![&final_name, hash(&plaintext), &plaintext[..8], role],
        )?;
        Ok((plaintext, final_name))
    }

    pub fn validate(&self, key: &str) -> Option<KeyRole> {
        if key.is_empty() {
            return None;
        }
        let h = hash(key);
        let conn = self.db.lock();
        let role: Option<String> = conn
            .query_row(
                "SELECT role FROM api_keys WHERE key_hash = ?1",
                params![&h],
                |r| r.get(0),
            )
            .optional()
            .ok()
            .flatten();
        if role.is_some() && self.should_touch(&h) {
            let _ = conn.execute(
                "UPDATE api_keys SET last_used = CURRENT_TIMESTAMP WHERE key_hash = ?1",
                params![&h],
            );
        }
        role
    }

    pub fn list(&self) -> anyhow::Result<Vec<APIKey>> {
        let conn = self.db.lock();
        let mut stmt = conn.prepare(
            "SELECT id, name, key_prefix, role, created_at, last_used FROM api_keys ORDER BY id",
        )?;
        let rows = stmt.query_map([], |row| {
            let created_raw: String = row.get(4)?;
            let last_raw: Option<String> = row.get(5)?;
            Ok(APIKey {
                id: row.get(0)?,
                name: row.get(1)?,
                key_hash: String::new(),
                key_prefix: row.get(2)?,
                role: row.get(3)?,
                created_at: parse_sqlite_time(&created_raw),
                last_used: last_raw.as_deref().map(parse_sqlite_time),
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn count(&self) -> i64 {
        let conn = self.db.lock();
        conn.query_row("SELECT COUNT(*) FROM api_keys", [], |r| r.get(0))
            .unwrap_or(0)
    }

    pub fn next_auto_name(&self) -> String {
        let conn = self.db.lock();
        next_available_key_name(&conn)
    }

    pub fn revoke(&self, id: i64) -> anyhow::Result<()> {
        let conn = self.db.lock();
        let n = conn.execute(
            "DELETE FROM api_keys
             WHERE id = ?1
               AND (role <> 'admin' OR (SELECT COUNT(*) FROM api_keys WHERE role = 'admin') > 1)",
            params![id],
        )?;
        if n == 1 {
            return Ok(());
        }
        let role: Option<String> = conn
            .query_row("SELECT role FROM api_keys WHERE id = ?1", params![id], |r| {
                r.get(0)
            })
            .optional()?;
        match role.as_deref() {
            Some(ROLE_ADMIN) => anyhow::bail!("cannot revoke the last admin key"),
            _ => anyhow::bail!("api key not found"),
        }
    }
}

// ============================================================================
// Single-Administrator Email + Password Auth & Nginx-UI-style Install Lock
// ============================================================================

#[cfg(test)]
const PBKDF2_ITERATIONS: u32 = 10_000;
#[cfg(not(test))]
const PBKDF2_ITERATIONS: u32 = 210_000;

const SESSION_TTL_SECS: i64 = 7 * 24 * 3600;
const INSTALL_SECRET_ALPHABET: &[u8] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
// Static dummy hash used for constant-time timing mitigation when email does not exist.
const DUMMY_PASSWORD_HASH: &str =
    "pbkdf2_sha256$10000$00112233445566778899aabbccddeeff$0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdminAccount {
    pub email: String,
    pub created_at: DateTime<FixedOffset>,
    pub updated_at: DateTime<FixedOffset>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_login: Option<DateTime<FixedOffset>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionIdentity {
    pub email: String,
    pub role: KeyRole,
    pub token_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    NotInstalled,
    AlreadyInstalled,
    InvalidInstallSecret,
    InvalidEmail(String),
    InvalidPassword(String),
    InvalidCredentials,
    Internal(String),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotInstalled => write!(f, "系统尚未初始化，请先完成首次安装注册"),
            Self::AlreadyInstalled => write!(f, "系统已完成初始化，已永久禁止公开注册"),
            Self::InvalidInstallSecret => {
                write!(f, "初始化安全令牌无效，请核对服务端日志或 .install_secret 文件")
            }
            Self::InvalidEmail(m) => write!(f, "{m}"),
            Self::InvalidPassword(m) => write!(f, "{m}"),
            Self::InvalidCredentials => write!(f, "管理员邮箱或密码不正确"),
            Self::Internal(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for AuthError {}

pub fn validate_email(raw: &str) -> Result<String, AuthError> {
    let normalized = raw.trim().to_ascii_lowercase();
    if normalized.is_empty() || normalized.len() > 254 {
        return Err(AuthError::InvalidEmail("请输入有效的管理员邮箱地址".into()));
    }
    if normalized.bytes().any(|b| b.is_ascii_whitespace() || b < 0x21 || b > 0x7e) {
        return Err(AuthError::InvalidEmail("邮箱地址不能包含空格或非法字符".into()));
    }
    let Some((local, domain)) = normalized.split_once('@') else {
        return Err(AuthError::InvalidEmail("用户名必须是有效的电子邮箱格式".into()));
    };
    if domain.contains('@') || local.is_empty() || local.len() > 64 || domain.len() < 3 || domain.len() > 253 {
        return Err(AuthError::InvalidEmail("用户名必须是有效的电子邮箱格式".into()));
    }
    if local.starts_with('.') || local.ends_with('.') || local.contains("..") {
        return Err(AuthError::InvalidEmail("邮箱前缀格式无效".into()));
    }
    if !local
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"._%+-".contains(&b))
    {
        return Err(AuthError::InvalidEmail("邮箱前缀包含不支持的字符".into()));
    }
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 {
        return Err(AuthError::InvalidEmail("邮箱域名须包含顶级后缀，例如 admin@example.com".into()));
    }
    for label in &labels {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(AuthError::InvalidEmail("邮箱域名格式无效".into()));
        }
    }
    let tld = labels.last().unwrap_or(&"");
    if tld.len() < 2 || !tld.bytes().all(|b| b.is_ascii_alphabetic()) {
        return Err(AuthError::InvalidEmail("邮箱顶级域名无效".into()));
    }
    Ok(normalized)
}

pub fn validate_password(password: &str) -> Result<(), AuthError> {
    if password.len() < 8 {
        return Err(AuthError::InvalidPassword("密码长度至少需要 8 位".into()));
    }
    if password.len() > 128 {
        return Err(AuthError::InvalidPassword("密码长度不能超过 128 位".into()));
    }
    if password.trim().is_empty() {
        return Err(AuthError::InvalidPassword("密码不能全为空白字符".into()));
    }
    Ok(())
}

fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8; 32]) {
    type HmacSha256 = Hmac<Sha256>;
    let mut u = [0u8; 32];
    let mut mac = <HmacSha256 as Mac>::new_from_slice(password).expect("HMAC accepts any key length");
    mac.update(salt);
    mac.update(&1u32.to_be_bytes());
    u.copy_from_slice(&mac.finalize().into_bytes());
    let mut t = u;
    for _ in 1..iterations {
        let mut step =
            <HmacSha256 as Mac>::new_from_slice(password).expect("HMAC accepts any key length");
        step.update(&u);
        u.copy_from_slice(&step.finalize().into_bytes());
        for (dst, src) in t.iter_mut().zip(u.iter()) {
            *dst ^= *src;
        }
    }
    out.copy_from_slice(&t);
}

pub fn hash_password(password: &str) -> String {
    let mut salt = [0u8; 16];
    rand::rng().fill_bytes(&mut salt);
    let mut dk = [0u8; 32];
    pbkdf2_hmac_sha256(password.as_bytes(), &salt, PBKDF2_ITERATIONS, &mut dk);
    format!(
        "pbkdf2_sha256${}${}${}",
        PBKDF2_ITERATIONS,
        hex::encode(salt),
        hex::encode(dk)
    )
}

pub fn verify_password(password: &str, stored: &str) -> bool {
    let parts: Vec<&str> = stored.split('$').collect();
    if parts.len() != 4 || parts[0] != "pbkdf2_sha256" {
        return false;
    }
    let Ok(iters) = parts[1].parse::<u32>() else {
        return false;
    };
    if iters < 1_000 || iters > 2_000_000 {
        return false;
    }
    let (Ok(salt), Ok(expected)) = (hex::decode(parts[2]), hex::decode(parts[3])) else {
        return false;
    };
    if salt.len() < 8 || expected.len() != 32 {
        return false;
    }
    let mut dk = [0u8; 32];
    pbkdf2_hmac_sha256(password.as_bytes(), &salt, iters, &mut dk);
    bool::from(dk.ct_eq(&expected[..]))
}

pub fn generate_install_secret() -> String {
    let mut raw = [0u8; 16];
    rand::rng().fill_bytes(&mut raw);
    let mut chars = String::with_capacity(23);
    chars.push_str("VLK");
    for (i, b) in raw.iter().enumerate() {
        if i % 4 == 0 {
            chars.push('-');
        }
        let idx = (*b as usize) % INSTALL_SECRET_ALPHABET.len();
        chars.push(INSTALL_SECRET_ALPHABET[idx] as char);
    }
    chars
}

pub fn generate_session_token() -> String {
    let mut b = [0u8; 32];
    rand::rng().fill_bytes(&mut b);
    format!("vls_{}", hex::encode(b))
}

pub fn generate_recovery_password() -> String {
    const ALPHA: &[u8] = b"23456789abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ!@#$%";
    let mut raw = [0u8; 20];
    rand::rng().fill_bytes(&mut raw);
    raw.iter()
        .map(|b| ALPHA[(*b as usize) % ALPHA.len()] as char)
        .collect()
}

pub fn install_secret_path(db_path: &str) -> Option<PathBuf> {
    let trimmed = db_path.trim();
    if trimmed.is_empty() || trimmed == ":memory:" || trimmed.starts_with("file::memory:") {
        return None;
    }
    let parent = Path::new(trimmed)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    Some(parent.join(".install_secret"))
}

fn write_secret_file(path: &Path, secret: &str) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    writeln!(file, "{secret}")?;
    file.flush()?;
    Ok(())
}

fn record_auth_audit(tx: &rusqlite::Connection, action: &str, object: &str) {
    let now = Utc::now().timestamp();
    let _ = tx.execute(
        "INSERT INTO audit VALUES(?1, ?2, ?3)",
        params![now, action, object],
    );
}

#[derive(Clone)]
pub struct AuthStore {
    db: Arc<Mutex<Connection>>,
    install_secret: Arc<Mutex<Option<String>>>,
    touched: Arc<Mutex<std::collections::HashMap<String, std::time::Instant>>>,
}

impl AuthStore {
    pub fn new(db: Arc<Mutex<Connection>>) -> Self {
        Self {
            db,
            install_secret: Arc::new(Mutex::new(None)),
            touched: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }

    pub fn migrate(&self) -> anyhow::Result<()> {
        let conn = self.db.lock();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS admin_accounts (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                last_login DATETIME
            );
            CREATE TABLE IF NOT EXISTS admin_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_hash TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                expires_at INTEGER NOT NULL,
                last_used DATETIME
            );
            CREATE INDEX IF NOT EXISTS idx_admin_sessions_hash ON admin_sessions(token_hash);",
        )?;
        Ok(())
    }

    pub fn is_installed(&self) -> bool {
        let conn = self.db.lock();
        conn.query_row("SELECT COUNT(*) FROM admin_accounts", [], |r| r.get::<_, i64>(0))
            .unwrap_or(0)
            > 0
    }

    pub fn ensure_install_secret(
        &self,
        db_path: &str,
    ) -> anyhow::Result<Option<(String, Option<PathBuf>)>> {
        let path = install_secret_path(db_path);
        if self.is_installed() {
            *self.install_secret.lock() = None;
            if let Some(ref p) = path {
                let _ = fs::remove_file(p);
            }
            return Ok(None);
        }

        let mut guard = self.install_secret.lock();
        if let Some(ref existing) = *guard {
            return Ok(Some((existing.clone(), path)));
        }

        if let Some(ref p) = path {
            if let Ok(content) = fs::read_to_string(p) {
                let trimmed = content.trim();
                if trimmed.len() >= 16 && trimmed.len() <= 128 {
                    *guard = Some(trimmed.to_string());
                    return Ok(Some((trimmed.to_string(), Some(p.clone()))));
                }
            }
        }

        let fresh = generate_install_secret();
        if let Some(ref p) = path {
            write_secret_file(p, &fresh)?;
        }
        *guard = Some(fresh.clone());
        Ok(Some((fresh, path)))
    }

    pub fn current_install_secret(&self) -> Option<String> {
        self.install_secret.lock().clone()
    }

    pub fn verify_install_secret(&self, candidate: &str) -> bool {
        let guard = self.install_secret.lock();
        let Some(ref expected) = *guard else {
            return false;
        };
        let norm_cand = candidate.trim().to_ascii_uppercase();
        let norm_exp = expected.trim().to_ascii_uppercase();
        if norm_cand.len() != norm_exp.len() || norm_cand.is_empty() {
            return false;
        }
        bool::from(norm_cand.as_bytes().ct_eq(norm_exp.as_bytes()))
    }

    pub fn setup_admin(
        &self,
        db_path: &str,
        install_secret: &str,
        email_raw: &str,
        password: &str,
    ) -> Result<(AdminAccount, String), AuthError> {
        if self.is_installed() {
            return Err(AuthError::AlreadyInstalled);
        }
        if !self.verify_install_secret(install_secret) {
            return Err(AuthError::InvalidInstallSecret);
        }
        let email = validate_email(email_raw)?;
        validate_password(password)?;
        let pw_hash = hash_password(password);
        let raw_token = generate_session_token();
        let tok_hash = hash(&raw_token);
        let expires_at = Utc::now().timestamp() + SESSION_TTL_SECS;

        let account = {
            let mut conn = self.db.lock();
            let tx = conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|e| AuthError::Internal(e.to_string()))?;
            let count: i64 = tx
                .query_row("SELECT COUNT(*) FROM admin_accounts", [], |r| r.get(0))
                .map_err(|e| AuthError::Internal(e.to_string()))?;
            if count > 0 {
                return Err(AuthError::AlreadyInstalled);
            }
            tx.execute(
                "INSERT INTO admin_accounts (id, email, password_hash, last_login)
                 VALUES (1, ?1, ?2, CURRENT_TIMESTAMP)",
                params![&email, &pw_hash],
            )
            .map_err(|e| AuthError::Internal(e.to_string()))?;
            tx.execute(
                "INSERT INTO admin_sessions (token_hash, email, expires_at, last_used)
                 VALUES (?1, ?2, ?3, CURRENT_TIMESTAMP)",
                params![&tok_hash, &email, expires_at],
            )
            .map_err(|e| AuthError::Internal(e.to_string()))?;
            record_auth_audit(&tx, "auth.setup", &email);
            let acc = tx
                .query_row(
                    "SELECT email, created_at, updated_at, last_login FROM admin_accounts WHERE id = 1",
                    [],
                    |row| {
                        let created_raw: String = row.get(1)?;
                        let updated_raw: String = row.get(2)?;
                        let last_raw: Option<String> = row.get(3)?;
                        Ok(AdminAccount {
                            email: row.get(0)?,
                            created_at: parse_sqlite_time(&created_raw),
                            updated_at: parse_sqlite_time(&updated_raw),
                            last_login: last_raw.as_deref().map(parse_sqlite_time),
                        })
                    },
                )
                .map_err(|e| AuthError::Internal(e.to_string()))?;
            tx.commit().map_err(|e| AuthError::Internal(e.to_string()))?;
            acc
        };

        // Permanently lock installer and self-destruct .install_secret
        *self.install_secret.lock() = None;
        if let Some(path) = install_secret_path(db_path) {
            let _ = fs::remove_file(path);
        }
        Ok((account, raw_token))
    }

    pub fn login(
        &self,
        email_raw: &str,
        password: &str,
    ) -> Result<(AdminAccount, String), AuthError> {
        if !self.is_installed() {
            return Err(AuthError::NotInstalled);
        }
        let email = email_raw.trim().to_ascii_lowercase();
        let stored: Option<(String, String)> = {
            let conn = self.db.lock();
            conn.query_row(
                "SELECT email, password_hash FROM admin_accounts WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|e| AuthError::Internal(e.to_string()))?
        };
        let Some((db_email, db_hash)) = stored else {
            return Err(AuthError::NotInstalled);
        };

        let email_match = !email.is_empty()
            && email.len() == db_email.len()
            && bool::from(email.as_bytes().ct_eq(db_email.as_bytes()));
        let pw_ok = if email_match {
            verify_password(password, &db_hash)
        } else {
            let _ = verify_password(password, DUMMY_PASSWORD_HASH);
            false
        };
        if !email_match || !pw_ok {
            return Err(AuthError::InvalidCredentials);
        }

        let raw_token = generate_session_token();
        let tok_hash = hash(&raw_token);
        let now = Utc::now().timestamp();
        let expires_at = now + SESSION_TTL_SECS;

        let conn = self.db.lock();
        let _ = conn.execute(
            "DELETE FROM admin_sessions WHERE expires_at <= ?1",
            params![now],
        );
        conn.execute(
            "INSERT INTO admin_sessions (token_hash, email, expires_at, last_used)
             VALUES (?1, ?2, ?3, CURRENT_TIMESTAMP)",
            params![&tok_hash, &db_email, expires_at],
        )
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        let _ = conn.execute(
            "UPDATE admin_accounts SET last_login = CURRENT_TIMESTAMP WHERE id = 1",
            [],
        );
        let acc = conn
            .query_row(
                "SELECT email, created_at, updated_at, last_login FROM admin_accounts WHERE id = 1",
                [],
                |row| {
                    let created_raw: String = row.get(1)?;
                    let updated_raw: String = row.get(2)?;
                    let last_raw: Option<String> = row.get(3)?;
                    Ok(AdminAccount {
                        email: row.get(0)?,
                        created_at: parse_sqlite_time(&created_raw),
                        updated_at: parse_sqlite_time(&updated_raw),
                        last_login: last_raw.as_deref().map(parse_sqlite_time),
                    })
                },
            )
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok((acc, raw_token))
    }

    fn should_touch(&self, tok_hash: &str) -> bool {
        let now = std::time::Instant::now();
        let mut touched = self.touched.lock();
        if touched
            .get(tok_hash)
            .is_some_and(|t| now.duration_since(*t) < LAST_USED_DEBOUNCE)
        {
            return false;
        }
        if touched.len() > 2048 {
            touched.retain(|_, t| now.duration_since(*t) < LAST_USED_DEBOUNCE);
        }
        touched.insert(tok_hash.to_string(), now);
        true
    }

    pub fn validate_session(&self, raw_token: &str) -> Option<SessionIdentity> {
        if !raw_token.starts_with("vls_") || raw_token.len() < 32 {
            return None;
        }
        let tok_hash = hash(raw_token);
        let now = Utc::now().timestamp();
        let conn = self.db.lock();
        let email: Option<String> = conn
            .query_row(
                "SELECT a.email
                 FROM admin_sessions s
                 JOIN admin_accounts a ON a.id = 1
                 WHERE s.token_hash = ?1 AND s.expires_at > ?2",
                params![&tok_hash, now],
                |r| r.get(0),
            )
            .optional()
            .ok()
            .flatten();
        if let Some(email) = email {
            if self.should_touch(&tok_hash) {
                let _ = conn.execute(
                    "UPDATE admin_sessions SET last_used = CURRENT_TIMESTAMP WHERE token_hash = ?1",
                    params![&tok_hash],
                );
            }
            return Some(SessionIdentity {
                email,
                role: ROLE_ADMIN.to_string(),
                token_hash: tok_hash,
            });
        }
        None
    }

    pub fn logout_session(&self, raw_token: &str) {
        if raw_token.is_empty() {
            return;
        }
        let tok_hash = hash(raw_token);
        let conn = self.db.lock();
        let _ = conn.execute(
            "DELETE FROM admin_sessions WHERE token_hash = ?1",
            params![&tok_hash],
        );
    }

    pub fn revoke_other_sessions(&self, keep_raw_token: &str) -> usize {
        let tok_hash = hash(keep_raw_token);
        let conn = self.db.lock();
        conn.execute(
            "DELETE FROM admin_sessions WHERE token_hash <> ?1",
            params![&tok_hash],
        )
        .unwrap_or(0)
    }

    pub fn account_info(&self) -> anyhow::Result<Option<(AdminAccount, i64)>> {
        let now = Utc::now().timestamp();
        let conn = self.db.lock();
        let acc: Option<AdminAccount> = conn
            .query_row(
                "SELECT email, created_at, updated_at, last_login FROM admin_accounts WHERE id = 1",
                [],
                |row| {
                    let created_raw: String = row.get(1)?;
                    let updated_raw: String = row.get(2)?;
                    let last_raw: Option<String> = row.get(3)?;
                    Ok(AdminAccount {
                        email: row.get(0)?,
                        created_at: parse_sqlite_time(&created_raw),
                        updated_at: parse_sqlite_time(&updated_raw),
                        last_login: last_raw.as_deref().map(parse_sqlite_time),
                    })
                },
            )
            .optional()?;
        let Some(acc) = acc else {
            return Ok(None);
        };
        let active_sessions: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM admin_sessions WHERE expires_at > ?1",
                params![now],
                |r| r.get(0),
            )
            .unwrap_or(0);
        Ok(Some((acc, active_sessions)))
    }

    pub fn change_password(
        &self,
        current_password: &str,
        new_password: &str,
        keep_raw_token: Option<&str>,
        revoke_others: bool,
    ) -> Result<usize, AuthError> {
        validate_password(new_password)?;
        let (email, stored_hash): (String, String) = {
            let conn = self.db.lock();
            conn.query_row(
                "SELECT email, password_hash FROM admin_accounts WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|e| AuthError::Internal(e.to_string()))?
            .ok_or(AuthError::NotInstalled)?
        };
        if !verify_password(current_password, &stored_hash) {
            return Err(AuthError::InvalidCredentials);
        }
        let next_hash = hash_password(new_password);
        let conn = self.db.lock();
        conn.execute(
            "UPDATE admin_accounts SET password_hash = ?1, updated_at = CURRENT_TIMESTAMP WHERE id = 1",
            params![&next_hash],
        )
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        record_auth_audit(&conn, "auth.password.change", &email);
        let revoked = if revoke_others {
            if let Some(tok) = keep_raw_token {
                let keep_hash = hash(tok);
                conn.execute(
                    "DELETE FROM admin_sessions WHERE token_hash <> ?1",
                    params![&keep_hash],
                )
                .unwrap_or(0)
            } else {
                conn.execute("DELETE FROM admin_sessions", []).unwrap_or(0)
            }
        } else {
            0
        };
        Ok(revoked)
    }

    pub fn change_email(
        &self,
        current_password: &str,
        new_email_raw: &str,
    ) -> Result<AdminAccount, AuthError> {
        let new_email = validate_email(new_email_raw)?;
        let stored_hash: String = {
            let conn = self.db.lock();
            conn.query_row(
                "SELECT password_hash FROM admin_accounts WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| AuthError::Internal(e.to_string()))?
            .ok_or(AuthError::NotInstalled)?
        };
        if !verify_password(current_password, &stored_hash) {
            return Err(AuthError::InvalidCredentials);
        }
        let conn = self.db.lock();
        conn.execute(
            "UPDATE admin_accounts SET email = ?1, updated_at = CURRENT_TIMESTAMP WHERE id = 1",
            params![&new_email],
        )
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        let _ = conn.execute(
            "UPDATE admin_sessions SET email = ?1",
            params![&new_email],
        );
        record_auth_audit(&conn, "auth.email.change", &new_email);
        let acc = conn
            .query_row(
                "SELECT email, created_at, updated_at, last_login FROM admin_accounts WHERE id = 1",
                [],
                |row| {
                    let created_raw: String = row.get(1)?;
                    let updated_raw: String = row.get(2)?;
                    let last_raw: Option<String> = row.get(3)?;
                    Ok(AdminAccount {
                        email: row.get(0)?,
                        created_at: parse_sqlite_time(&created_raw),
                        updated_at: parse_sqlite_time(&updated_raw),
                        last_login: last_raw.as_deref().map(parse_sqlite_time),
                    })
                },
            )
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(acc)
    }

    pub fn cli_reset_password(
        &self,
        new_email: Option<&str>,
        new_password: Option<&str>,
    ) -> Result<(String, String), AuthError> {
        let password = match new_password {
            Some(p) if !p.is_empty() => {
                validate_password(p)?;
                p.to_string()
            }
            _ => generate_recovery_password(),
        };
        let pw_hash = hash_password(&password);
        let conn = self.db.lock();
        let existing_email: Option<String> = conn
            .query_row("SELECT email FROM admin_accounts WHERE id = 1", [], |r| r.get(0))
            .optional()
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        let final_email = match (new_email.filter(|s| !s.trim().is_empty()), existing_email) {
            (Some(raw), _) => validate_email(raw)?,
            (None, Some(cur)) => cur,
            (None, None) => return Err(AuthError::NotInstalled),
        };
        conn.execute(
            "INSERT INTO admin_accounts (id, email, password_hash)
             VALUES (1, ?1, ?2)
             ON CONFLICT(id) DO UPDATE SET
               email = excluded.email,
               password_hash = excluded.password_hash,
               updated_at = CURRENT_TIMESTAMP",
            params![&final_email, &pw_hash],
        )
        .map_err(|e| AuthError::Internal(e.to_string()))?;
        let _ = conn.execute("DELETE FROM admin_sessions", []);
        record_auth_audit(&conn, "auth.password.reset", &final_email);
        Ok((final_email, password))
    }
}

fn parse_sqlite_time(s: &str) -> DateTime<FixedOffset> {
    let tz = shanghai_tz();
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return dt.with_timezone(&tz);
    }
    if let Ok(naive) = NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S") {
        return DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc).with_timezone(&tz);
    }
    Utc::now().with_timezone(&tz)
}

fn next_available_key_name(conn: &Connection) -> String {
    let start: i64 = conn
        .query_row(
            "SELECT COALESCE(MAX(id), 0) + 1 FROM api_keys",
            [],
            |r| r.get(0),
        )
        .unwrap_or(1)
        .max(1);
    let mut idx = start;
    loop {
        let candidate = format!("key-{idx}");
        let exists: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM api_keys WHERE name = ?1",
                params![&candidate],
                |r| r.get(0),
            )
            .optional()
            .ok()
            .flatten();
        if exists.is_none() {
            return candidate;
        }
        idx += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_rejects_short_ciphertext() {
        let key = [7u8; 32];
        assert!(open(&key, &[0u8; 27]).is_err());
        let sealed = seal(&key, "secret").unwrap();
        assert_eq!(open(&key, &sealed).unwrap(), "secret");
    }

    #[test]
    fn validate_debounces_last_used_writes() {
        let db = Arc::new(Mutex::new(Connection::open_in_memory().unwrap()));
        let ks = KeyStore::new(db.clone());
        ks.migrate().unwrap();
        let key = ks.create("k", ROLE_ADMIN).unwrap();
        assert!(ks.validate(&key).is_some());
        db.lock()
            .execute("UPDATE api_keys SET last_used = NULL", [])
            .unwrap();
        assert!(ks.validate(&key).is_some());
        let last: Option<String> = db
            .lock()
            .query_row("SELECT last_used FROM api_keys", [], |r| r.get(0))
            .unwrap();
        assert!(last.is_none());
    }

    #[test]
    fn auto_name_avoids_collision_after_revoking_earlier_key() {
        let db = Arc::new(Mutex::new(Connection::open_in_memory().unwrap()));
        let ks = KeyStore::new(db);
        ks.migrate().unwrap();
        let (_, n1) = ks.create_named("", ROLE_ADMIN).unwrap();
        let (_, n2) = ks.create_named("", ROLE_ADMIN).unwrap();
        assert_eq!(n1, "key-1");
        assert_eq!(n2, "key-2");
        let keys = ks.list().unwrap();
        ks.revoke(keys[0].id).unwrap();
        let (_, n3) = ks.create_named("", ROLE_ADMIN).unwrap();
        assert_eq!(n3, "key-3");
    }

    #[test]
    fn auth_store_enforces_email_install_lock_and_single_admin() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("veilink.db").to_string_lossy().to_string();
        let conn = Arc::new(Mutex::new(Connection::open(&db_path).unwrap()));
        let auth = AuthStore::new(conn);
        auth.migrate().unwrap();

        assert!(!auth.is_installed());
        let (secret, secret_path) = auth.ensure_install_secret(&db_path).unwrap().unwrap();
        assert!(secret.starts_with("VLK-"));
        assert!(secret_path.as_ref().unwrap().is_file());

        // Visitor without valid secret must be rejected
        assert_eq!(
            auth.setup_admin(&db_path, "VLK-WRONG-TOKEN", "admin@example.com", "StrongPass123!")
                .unwrap_err(),
            AuthError::InvalidInstallSecret
        );
        // Non-email username must be rejected
        assert!(matches!(
            auth.setup_admin(&db_path, &secret, "admin-no-domain", "StrongPass123!"),
            Err(AuthError::InvalidEmail(_))
        ));
        // Short password must be rejected
        assert!(matches!(
            auth.setup_admin(&db_path, &secret, "admin@example.com", "short"),
            Err(AuthError::InvalidPassword(_))
        ));

        // Legitimate first-time setup succeeds, locks installer, and deletes .install_secret
        let (acc, tok) = auth
            .setup_admin(&db_path, &secret, "Admin@Example.COM", "StrongPass123!")
            .unwrap();
        assert_eq!(acc.email, "admin@example.com");
        assert!(tok.starts_with("vls_"));
        assert!(auth.is_installed());
        assert!(!secret_path.unwrap().exists());
        assert!(auth.validate_session(&tok).is_some());

        // Second setup attempt is permanently locked
        assert_eq!(
            auth.setup_admin(&db_path, &secret, "attacker@example.com", "StrongPass123!")
                .unwrap_err(),
            AuthError::AlreadyInstalled
        );

        // Login with email + password works; wrong password fails
        assert_eq!(
            auth.login("admin@example.com", "WrongPass!").unwrap_err(),
            AuthError::InvalidCredentials
        );
        let (logged, tok2) = auth.login("ADMIN@example.com", "StrongPass123!").unwrap();
        assert_eq!(logged.email, "admin@example.com");
        assert!(auth.validate_session(&tok2).is_some());

        // Change password & revoke other sessions
        let revoked = auth
            .change_password("StrongPass123!", "NewStrongPass456!", Some(&tok2), true)
            .unwrap();
        assert_eq!(revoked, 1);
        assert!(auth.validate_session(&tok).is_none());
        assert!(auth.validate_session(&tok2).is_some());

        // Change email
        let updated = auth
            .change_email("NewStrongPass456!", "owner@veilink.io")
            .unwrap();
        assert_eq!(updated.email, "owner@veilink.io");
        assert_eq!(auth.validate_session(&tok2).unwrap().email, "owner@veilink.io");
    }
}
