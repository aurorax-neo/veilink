use std::sync::Arc;

use chrono::Utc;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

const DEFAULT_CAPACITY: usize = 2000;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    #[serde(default)]
    pub at: i64,
    #[serde(default)]
    pub level: String,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub source: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub node_id: String,
}

#[derive(Clone)]
pub struct Ring {
    inner: Arc<Mutex<RingInner>>,
}

struct RingInner {
    cap: usize,
    buf: Vec<Entry>,
    pos: usize,
    full: bool,
}

impl Ring {
    pub fn new(capacity: usize) -> Self {
        let cap = if capacity == 0 {
            DEFAULT_CAPACITY
        } else {
            capacity
        };
        Self {
            inner: Arc::new(Mutex::new(RingInner {
                cap,
                buf: vec![Entry::default(); cap],
                pos: 0,
                full: false,
            })),
        }
    }

    pub fn append(&self, entry: Entry) {
        let mut g = self.inner.lock();
        let pos = g.pos;
        g.buf[pos] = entry;
        g.pos = (pos + 1) % g.cap;
        if g.pos == 0 {
            g.full = true;
        }
    }

    pub fn append_batch(&self, entries: &[Entry]) {
        let mut g = self.inner.lock();
        for e in entries {
            let pos = g.pos;
            g.buf[pos] = e.clone();
            g.pos = (pos + 1) % g.cap;
            if g.pos == 0 {
                g.full = true;
            }
        }
    }

    pub fn query(&self, source: &str, node_id: &str, level: &str, limit: usize) -> Vec<Entry> {
        let ordered = {
            let g = self.inner.lock();
            let n = if g.full { g.cap } else { g.pos };
            let mut v = Vec::with_capacity(n);
            if g.full {
                v.extend_from_slice(&g.buf[g.pos..]);
                v.extend_from_slice(&g.buf[..g.pos]);
            } else {
                v.extend_from_slice(&g.buf[..g.pos]);
            }
            v
        };
        let limit = if limit == 0 || limit > ordered.len() {
            ordered.len()
        } else {
            limit
        };
        let mut out = Vec::with_capacity(limit);
        for e in ordered.into_iter().rev() {
            if out.len() >= limit {
                break;
            }
            if !source.is_empty() && e.source != source {
                continue;
            }
            if !node_id.is_empty() && e.node_id != node_id {
                continue;
            }
            if !level.is_empty() && e.level != level {
                continue;
            }
            out.push(e);
        }
        out
    }

    pub fn drain(&self) -> Vec<Entry> {
        let mut g = self.inner.lock();
        let n = if g.full { g.cap } else { g.pos };
        if n == 0 {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(n);
        if g.full {
            out.extend_from_slice(&g.buf[g.pos..]);
            out.extend_from_slice(&g.buf[..g.pos]);
        } else {
            out.extend_from_slice(&g.buf[..g.pos]);
        }
        g.pos = 0;
        g.full = false;
        out
    }

    pub fn log_event(&self, source: &str, node_id: &str, level: &str, message: impl Into<String>) {
        let msg = clean_text(&message.into(), 1024);
        let lvl = match level.trim().to_ascii_uppercase().as_str() {
            "DEBUG" | "INFO" | "WARN" | "ERROR" => level.trim().to_ascii_uppercase(),
            _ => "INFO".to_string(),
        };
        let now = Utc::now().timestamp();
        eprintln!("level={lvl} source={source} msg={msg}");
        self.append(Entry {
            at: now,
            level: lvl,
            message: msg,
            source: source.to_string(),
            node_id: node_id.to_string(),
        });
    }

    pub fn push_entry(&self, source: &str, node_id: &str, level: &str, message: impl Into<String>) {
        self.log_event(source, node_id, level, message);
    }
}

#[derive(Clone)]
pub struct NodeRing {
    ring: Ring,
}

impl NodeRing {
    pub fn new(ring: Ring) -> Self {
        Self { ring }
    }

    pub fn ingest(&self, node_id: &str, entries: &[Entry]) {
        let take = entries.len().min(100);
        let mut clean = Vec::with_capacity(take);
        let now = Utc::now().timestamp();
        for entry in entries.iter().take(take) {
            let lvl = match entry.level.trim().to_ascii_uppercase().as_str() {
                "DEBUG" | "INFO" | "WARN" | "ERROR" => entry.level.trim().to_ascii_uppercase(),
                _ => "INFO".to_string(),
            };
            clean.push(Entry {
                at: if entry.at == 0 { now } else { entry.at },
                level: lvl,
                message: clean_text(&entry.message, 1024),
                source: "node".to_string(),
                node_id: node_id.to_string(),
            });
        }
        self.ring.append_batch(&clean);
    }
}

pub fn clean_text(s: &str, limit: usize) -> String {
    let mut out = String::with_capacity(s.len().min(limit.max(64)));
    for (idx, ch) in s.chars().enumerate() {
        if limit > 0 && idx >= limit {
            break;
        }
        if (ch as u32) < 32 || (ch as u32) == 127 {
            out.push(' ');
        } else {
            out.push(ch);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ring_query_and_drain() {
        let ring = Ring::new(2);
        ring.log_event("master", "", "ERROR", "pull state failed");
        ring.log_event("node", "n1", "WARN", "retry in 2s");
        ring.log_event("master", "", "INFO", "ready");

        let items = ring.query("", "", "", 10);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].message, "ready");
        assert_eq!(items[1].node_id, "n1");
        let drained = ring.drain();
        assert_eq!(drained.len(), 2);
        assert!(ring.drain().is_empty());
    }
}
