use std::io::Write;
use std::sync::Arc;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use chrono::{DateTime, FixedOffset, NaiveDateTime, Utc};
use parking_lot::Mutex;
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
}
