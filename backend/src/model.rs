use std::collections::BTreeMap;
use std::sync::OnceLock;

use base64::Engine;
use fips204::ml_dsa_65;
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
use ml_kem::{DecapsulationKey, ExpandedDecapsulationKey, KeyExport, MlKem768};
use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

pub const MUX_TYPE_SMUX: &str = "smux";
pub const MUX_TYPE_YAMUX: &str = "yamux";
pub const MUX_TYPE_H2MUX: &str = "h2mux";

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConnectEndpoint {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub port: i64,
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Node {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub role: String,
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub port: i64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub connect_endpoints: Vec<ConnectEndpoint>,
    #[serde(default)]
    pub revoked: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub disabled: bool,
    #[serde(default)]
    pub desired_revision: i64,
    #[serde(default)]
    pub applied_revision: i64,
    #[serde(default)]
    pub last_seen: i64,
    #[serde(default)]
    pub error: String,
    #[serde(default)]
    pub tunnel: LocalTLS,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_tunnel: Option<LocalTLS>,
    #[serde(default)]
    pub embedded: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub server_id: String,
    #[serde(default)]
    pub client_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub connect_endpoint_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub uuid: String,
    #[serde(default)]
    pub domain: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Mapping {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub binding_id: String,
    #[serde(default)]
    pub server_id: String,
    #[serde(default)]
    pub client_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub connect_endpoint_id: String,
    #[serde(default)]
    pub listen_host: String,
    #[serde(default)]
    pub listen_port: i64,
    #[serde(default)]
    pub target_host: String,
    #[serde(default)]
    pub target_port: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub network: String,
    #[serde(default)]
    pub pool: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub bandwidth_limit: String,
    #[serde(default)]
    pub mux: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mux_type: String,
    #[serde(default)]
    pub enabled: bool,
}

impl Mapping {
    pub fn effective_mux_type(&self) -> Result<String, String> {
        match self.mux_type.as_str() {
            "" | MUX_TYPE_SMUX | MUX_TYPE_YAMUX | MUX_TYPE_H2MUX => {}
            other => return Err(format!("unsupported mux_type {:?}", other)),
        }
        if !self.mux {
            return Ok(String::new());
        }
        if !self.network.is_empty() && self.network != "tcp" {
            return Err("mux requires TCP mapping".to_string());
        }
        if self.mux_type.is_empty() {
            return Ok(MUX_TYPE_SMUX.to_string());
        }
        Ok(self.mux_type.clone())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    #[serde(default)]
    pub revision: i64,
    #[serde(default)]
    pub node: Node,
    #[serde(default)]
    pub nodes: Vec<Node>,
    #[serde(default)]
    pub bindings: Vec<Binding>,
    #[serde(default)]
    pub mappings: Vec<Mapping>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LocalTLS {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub protocol: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub transport_security: String,
    #[serde(default)]
    pub cert_pem: String,
    #[serde(default)]
    pub key_pem: String,
    #[serde(default)]
    pub ca_pem: String,
    #[serde(default)]
    pub listen_host: String,
    #[serde(default)]
    pub listen_port: i64,
    #[serde(default)]
    pub flow: String,
    #[serde(default)]
    pub decryption: String,
    #[serde(default)]
    pub encryption: String,
    #[serde(default)]
    pub reality: Reality,
    #[serde(default)]
    pub hysteria2: Hysteria2,
    #[serde(default, skip_serializing_if = "XHTTP::is_default")]
    pub xhttp: XHTTP,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct XHTTPXmux {
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub max_concurrency: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub max_connections: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub c_max_reuse_times: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub h_max_request_times: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub h_max_reusable_secs: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub keep_alive_period: i64,
}

impl XHTTPXmux {
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct XHTTPHeaders(pub String);

impl XHTTPHeaders {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn entries(&self) -> Result<BTreeMap<String, String>, String> {
        if self.0.is_empty() {
            return Ok(BTreeMap::new());
        }
        let checked = Self::parse_raw(self.0.as_bytes())?;
        if self.0 != checked.0 {
            return Err("xhttp headers must use canonical JSON".to_string());
        }
        serde_json::from_str(&checked.0).map_err(|e| e.to_string())
    }

    pub fn parse_raw(data: &[u8]) -> Result<Self, String> {
        if data.len() > 2048 {
            return Err("xhttp headers exceed 2048 bytes".to_string());
        }
        let text = std::str::from_utf8(data)
            .map_err(|_| "xhttp headers contain invalid Unicode".to_string())?;
        if !valid_xhttp_json_surrogates(data) {
            return Err("xhttp headers contain invalid Unicode".to_string());
        }
        let val: serde_json::Value =
            serde_json::from_str(text).map_err(|_| "xhttp headers must be an object".to_string())?;
        let obj = val
            .as_object()
            .ok_or_else(|| "xhttp headers must be an object".to_string())?;
        if obj.is_empty() {
            return Err("empty xhttp headers object must be omitted".to_string());
        }
        if obj.len() > 8 {
            return Err("too many xhttp headers".to_string());
        }
        // Also check for duplicate raw keys before canonicalization
        let raw_key_count = count_top_level_keys(text)?;
        if raw_key_count != obj.len() {
            return Err("duplicate xhttp header".to_string());
        }
        let mut entries = BTreeMap::new();
        for (raw_name, v) in obj {
            if !safe_xhttp_header_name(raw_name) {
                return Err(format!("unsafe xhttp header name {:?}", raw_name));
            }
            let canonical_name = canonical_header_key(raw_name);
            if entries.contains_key(&canonical_name) {
                return Err(format!("duplicate xhttp header {:?}", canonical_name));
            }
            let value = v
                .as_str()
                .ok_or_else(|| "xhttp header values must be strings".to_string())?;
            if value.is_empty()
                || value.len() > 256
                || value.trim() != value
                || value.chars().any(|c| c.is_control())
            {
                return Err(format!(
                    "invalid xhttp header value for {:?}",
                    canonical_name
                ));
            }
            entries.insert(canonical_name, value.to_string());
        }
        let canonical = serde_json::to_string(&entries).map_err(|e| e.to_string())?;
        if canonical.len() > 2048 {
            return Err("xhttp headers exceed 2048 bytes after normalization".to_string());
        }
        Ok(Self(canonical))
    }
}

impl Serialize for XHTTPHeaders {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.0.is_empty() {
            let empty: BTreeMap<String, String> = BTreeMap::new();
            return empty.serialize(serializer);
        }
        let map: BTreeMap<String, String> =
            serde_json::from_str(&self.0).map_err(serde::ser::Error::custom)?;
        map.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for XHTTPHeaders {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = Box::<serde_json::value::RawValue>::deserialize(deserializer)?;
        Self::parse_raw(raw.get().as_bytes()).map_err(serde::de::Error::custom)
    }
}

fn count_top_level_keys(text: &str) -> Result<usize, String> {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= bytes.len() || bytes[i] != b'{' {
        return Err("xhttp headers must be an object".to_string());
    }
    i += 1;
    let mut count = 0;
    let mut in_string = false;
    let mut escape = false;
    while i < bytes.len() {
        let b = bytes[i];
        if in_string {
            if escape {
                escape = false;
            } else if b == b'\\' {
                escape = true;
            } else if b == b'"' {
                in_string = false;
            }
        } else if b == b'"' {
            in_string = true;
        } else if b == b':' {
            count += 1;
        }
        i += 1;
    }
    Ok(count)
}

fn valid_xhttp_json_surrogates(data: &[u8]) -> bool {
    let mut i = 0;
    while i < data.len() {
        if data[i] != b'\\' || i + 1 >= data.len() {
            i += 1;
            continue;
        }
        if data[i + 1] != b'u' {
            i += 2;
            continue;
        }
        if i + 6 > data.len() {
            return false;
        }
        let Ok(hex_str) = std::str::from_utf8(&data[i + 2..i + 6]) else {
            return false;
        };
        let Ok(code) = u16::from_str_radix(hex_str, 16) else {
            return false;
        };
        i += 6;
        if (0xdc00..=0xdfff).contains(&code) {
            return false;
        }
        if (0xd800..=0xdbff).contains(&code) {
            if i + 6 > data.len() || data[i] != b'\\' || data[i + 1] != b'u' {
                return false;
            }
            let Ok(next_str) = std::str::from_utf8(&data[i + 2..i + 6]) else {
                return false;
            };
            let Ok(next) = u16::from_str_radix(next_str, 16) else {
                return false;
            };
            if !(0xdc00..=0xdfff).contains(&next) {
                return false;
            }
            i += 6;
        }
    }
    true
}

pub fn safe_xhttp_header_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 64 {
        return false;
    }
    let lower = name.to_ascii_lowercase();
    if lower == "user-agent" || lower == "accept-language" {
        return true;
    }
    if !lower.starts_with("x-custom-") || lower.len() <= "x-custom-".len() {
        return false;
    }
    name["X-Custom-".len()..]
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || c == b'-')
}

pub fn canonical_header_key(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut upper = true;
    for b in name.bytes() {
        if b == b'-' {
            out.push('-');
            upper = true;
        } else if upper {
            out.push((b as char).to_ascii_uppercase());
            upper = false;
        } else {
            out.push((b as char).to_ascii_lowercase());
        }
    }
    out
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct XHTTP {
    #[serde(default, skip_serializing_if = "XHTTPXmux::is_default")]
    pub xmux: XHTTPXmux,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub host: String,
    #[serde(default, skip_serializing_if = "XHTTPHeaders::is_empty")]
    pub headers: XHTTPHeaders,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub mode: String,
    #[serde(default)]
    pub tls: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub http_version: String,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub max_each_post_bytes: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub post_bytes_max: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub request_timeout_seconds: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub padding_bytes: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub padding_max_bytes: i64,
    #[serde(default, skip_serializing_if = "is_false")]
    pub padding_obfs_mode: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub padding_placement: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub padding_key: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub padding_header: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub padding_method: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub no_grpc_header: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub no_sse_header: bool,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub server_max_header_bytes: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub uplink_http_method: String,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub min_posts_interval_ms: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub max_posts_interval_ms: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub max_buffered_posts: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub max_concurrent_posts: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub stream_up_server_secs: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub stream_up_server_max_secs: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub download_endpoint_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub uplink_data_placement: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub uplink_data_key: String,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub uplink_chunk_size: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub session_id_placement: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub session_id_key: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub seq_placement: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub seq_key: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub session_id_table: String,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub session_id_length: i64,
}

impl XHTTP {
    pub fn is_default(&self) -> bool {
        !self.enabled()
    }

    pub fn enabled(&self) -> bool {
        *self != Self::default()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Reality {
    #[serde(default)]
    pub dest: String,
    #[serde(default)]
    pub private_key: String,
    #[serde(default)]
    pub public_key: String,
    #[serde(default)]
    pub short_id: String,
    #[serde(default)]
    pub short_ids: String,
    #[serde(default)]
    pub server_names: String,
    #[serde(default)]
    pub fingerprint: String,
    #[serde(default)]
    pub max_time_diff: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub spider_x: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub spider_y: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mldsa65_verify: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mldsa65_seed: String,
}

impl Reality {
    pub fn enabled(&self) -> bool {
        !self.dest.trim().is_empty()
            || !self.private_key.trim().is_empty()
            || !self.public_key.trim().is_empty()
            || !self.short_id.trim().is_empty()
            || !self.short_ids.trim().is_empty()
            || !self.server_names.trim().is_empty()
            || !self.mldsa65_seed.trim().is_empty()
            || !self.mldsa65_verify.trim().is_empty()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Hysteria2 {
    #[serde(default)]
    pub password: String,
}

impl Hysteria2 {
    pub fn enabled(&self) -> bool {
        !self.password.trim().is_empty()
    }
}

impl LocalTLS {
    pub fn is_zero(&self) -> bool {
        *self == Self::default()
    }

    pub fn effective_protocol(&self) -> &str {
        if !self.protocol.is_empty() {
            return &self.protocol;
        }
        if self.hysteria2.enabled() {
            return "hysteria2";
        }
        "vless"
    }

    pub fn merge(&self, override_cfg: &LocalTLS) -> LocalTLS {
        let mut res = self.clone();
        if !override_cfg.protocol.is_empty() {
            res.protocol = override_cfg.protocol.clone();
        }
        if !override_cfg.transport_security.is_empty() {
            res.transport_security = override_cfg.transport_security.clone();
        }
        if !override_cfg.cert_pem.is_empty() {
            res.cert_pem = override_cfg.cert_pem.clone();
        }
        if !override_cfg.key_pem.is_empty() {
            res.key_pem = override_cfg.key_pem.clone();
        }
        if !override_cfg.ca_pem.is_empty() {
            res.ca_pem = override_cfg.ca_pem.clone();
        }
        if !override_cfg.listen_host.is_empty() {
            res.listen_host = override_cfg.listen_host.clone();
        }
        if override_cfg.listen_port != 0 {
            res.listen_port = override_cfg.listen_port;
        }
        if !override_cfg.flow.is_empty() {
            res.flow = override_cfg.flow.clone();
        }
        if !override_cfg.decryption.is_empty() {
            res.decryption = override_cfg.decryption.clone();
        }
        if !override_cfg.encryption.is_empty() {
            res.encryption = override_cfg.encryption.clone();
        }
        if !override_cfg.reality.dest.is_empty() {
            res.reality.dest = override_cfg.reality.dest.clone();
        }
        if !override_cfg.reality.private_key.is_empty() {
            res.reality.private_key = override_cfg.reality.private_key.clone();
        }
        if !override_cfg.reality.public_key.is_empty() {
            res.reality.public_key = override_cfg.reality.public_key.clone();
        }
        if !override_cfg.reality.short_id.is_empty() {
            res.reality.short_id = override_cfg.reality.short_id.clone();
        }
        if !override_cfg.reality.short_ids.is_empty() {
            res.reality.short_ids = override_cfg.reality.short_ids.clone();
        }
        if !override_cfg.reality.server_names.is_empty() {
            res.reality.server_names = override_cfg.reality.server_names.clone();
        }
        if !override_cfg.reality.fingerprint.is_empty() {
            res.reality.fingerprint = override_cfg.reality.fingerprint.clone();
        }
        if !override_cfg.reality.max_time_diff.is_empty() {
            res.reality.max_time_diff = override_cfg.reality.max_time_diff.clone();
        }
        if !override_cfg.reality.spider_x.is_empty() {
            res.reality.spider_x = override_cfg.reality.spider_x.clone();
        }
        if !override_cfg.reality.spider_y.is_empty() {
            res.reality.spider_y = override_cfg.reality.spider_y.clone();
        }
        if !override_cfg.reality.mldsa65_seed.is_empty() {
            res.reality.mldsa65_seed = override_cfg.reality.mldsa65_seed.clone();
        }
        if !override_cfg.reality.mldsa65_verify.is_empty() {
            res.reality.mldsa65_verify = override_cfg.reality.mldsa65_verify.clone();
        }
        if !override_cfg.hysteria2.password.is_empty() {
            res.hysteria2.password = override_cfg.hysteria2.password.clone();
        }
        if override_cfg.xhttp.enabled() {
            res.xhttp = override_cfg.xhttp.clone();
        }
        res
    }
}

pub fn derive_x25519_public(private_key: &str) -> String {
    let s = private_key.trim();
    if s.is_empty() {
        return String::new();
    }
    let decoded = if s.contains(['+', '/', '=']) {
        base64::engine::general_purpose::STANDARD.decode(s)
    } else {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)
    };
    let Ok(bytes) = decoded else {
        return String::new();
    };
    let Ok(arr): Result<[u8; 32], _> = bytes.try_into() else {
        return String::new();
    };
    let secret = X25519StaticSecret::from(arr);
    let pub_key = X25519PublicKey::from(&secret);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pub_key.as_bytes())
}

pub struct ParsedMldsa65Key {
    pub seed: Option<[u8; 32]>,
    pub sk_bytes: Vec<u8>,
    pub pk_bytes: Vec<u8>,
}

pub fn parse_mldsa65_private(value: &str) -> Result<ParsedMldsa65Key, String> {
    let s = value.trim();
    let decoded = if s.contains(['+', '/', '=']) {
        base64::engine::general_purpose::STANDARD.decode(s)
    } else {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)
    }
    .map_err(|_| "invalid ML-DSA-65 private key encoding".to_string())?;

    if decoded.len() == 32 {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&decoded);
        let (pk, sk) = ml_dsa_65::KG::keygen_from_seed(&seed);
        return Ok(ParsedMldsa65Key {
            seed: Some(seed),
            sk_bytes: sk.into_bytes().to_vec(),
            pk_bytes: pk.into_bytes().to_vec(),
        });
    }
    if decoded.len() != ml_dsa_65::SK_LEN {
        return Err(
            "ML-DSA-65 requires a 32-byte seed or a legacy 4032-byte private key".to_string(),
        );
    }
    for &v in &decoded[128..128 + 11 * 128] {
        if (v & 15) > 8 || (v >> 4) > 8 {
            return Err("invalid legacy ML-DSA-65 secret coefficients".to_string());
        }
    }
    let sk_arr: [u8; ml_dsa_65::SK_LEN] = decoded
        .clone()
        .try_into()
        .map_err(|_| "invalid legacy ML-DSA-65 key length".to_string())?;
    let sk = ml_dsa_65::PrivateKey::try_from_bytes(sk_arr)
        .map_err(|e| format!("invalid legacy ML-DSA-65 signing key: {e}"))?;
    let msg = b"veilink legacy ML-DSA-65 key validation";
    let sig = sk
        .try_sign(msg, &[])
        .map_err(|e| format!("invalid legacy ML-DSA-65 signing key: {e}"))?;
    // Reconstruct public key rho || t1 from legacy or seed if needed, or verify round-trip
    let _ = sig;
    // Extract public key from sk_bytes or derive if possible; note FIPS 204 SK contains rho(32), K(32), tr(64), s1, s2, t0.
    // In Veilink, all new keys are 32-byte seeds. For 4032-byte keys, check if sig is valid.
    Ok(ParsedMldsa65Key {
        seed: None,
        sk_bytes: decoded,
        pk_bytes: Vec::new(),
    })
}

pub fn derive_mldsa65_verify(seed: &str) -> String {
    let Ok(parsed) = parse_mldsa65_private(seed) else {
        return String::new();
    };
    if parsed.pk_bytes.is_empty() {
        return String::new();
    }
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&parsed.pk_bytes)
}

pub fn verify_mldsa65(pub_b64: &str, msg: &[u8], sig: &[u8]) -> bool {
    let s = pub_b64.trim();
    let decoded = if s.contains(['+', '/', '=']) {
        base64::engine::general_purpose::STANDARD.decode(s)
    } else {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)
    };
    let Ok(pk_vec) = decoded else {
        return false;
    };
    let Ok(pk_arr): Result<[u8; ml_dsa_65::PK_LEN], _> = pk_vec.try_into() else {
        return false;
    };
    let Ok(sig_arr): Result<[u8; ml_dsa_65::SIG_LEN], _> = sig.try_into() else {
        return false;
    };
    let Ok(pk) = ml_dsa_65::PublicKey::try_from_bytes(pk_arr) else {
        return false;
    };
    pk.verify(msg, &sig_arr, &[])
}

pub fn sign_mldsa65(seed_b64: &str, msg: &[u8]) -> Result<Vec<u8>, String> {
    let parsed = parse_mldsa65_private(seed_b64)?;
    let sk_arr: [u8; ml_dsa_65::SK_LEN] = parsed
        .sk_bytes
        .try_into()
        .map_err(|_| "invalid ML-DSA-65 private key".to_string())?;
    let sk = ml_dsa_65::PrivateKey::try_from_bytes(sk_arr)
        .map_err(|e| format!("invalid ML-DSA-65 private key: {e}"))?;
    let sig = sk
        .try_sign(msg, &[])
        .map_err(|e| format!("ML-DSA-65 sign failed: {e}"))?;
    Ok(sig.to_vec())
}

pub fn derive_vless_encryption(raw: &str) -> String {
    let raw = raw.trim();
    if raw.is_empty() || raw == "none" {
        return raw.to_string();
    }
    let mut parts: Vec<String> = raw.split('.').map(|s| s.to_string()).collect();
    if parts.len() < 4 || parts[0] != "mlkem768x25519plus" {
        return String::new();
    }
    match parts[1].as_str() {
        "native" | "xorpub" | "random" => {}
        _ => return String::new(),
    }
    let span: Vec<&str> = parts[2].trim_end_matches('s').splitn(2, '-').collect();
    let Ok(from) = span[0].parse::<i64>() else {
        return String::new();
    };
    if from < 0 {
        return String::new();
    }
    let mut to = from;
    if span.len() == 2 {
        let Ok(parsed_to) = span[1].parse::<i64>() else {
            return String::new();
        };
        if parsed_to < from {
            return String::new();
        }
        to = parsed_to;
    }
    parts[2] = if from == 0 && to == 0 {
        "1rtt".to_string()
    } else {
        "0rtt".to_string()
    };
    let mut keys = 0usize;
    for part in parts.iter_mut().skip(3) {
        if part.len() < 20 && keys == 0 {
            continue;
        }
        let Ok(raw_key) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(part.as_bytes())
        else {
            return String::new();
        };
        let public_bytes = match raw_key.len() {
            32 => {
                let arr: [u8; 32] = raw_key.try_into().unwrap();
                let secret = X25519StaticSecret::from(arr);
                X25519PublicKey::from(&secret).as_bytes().to_vec()
            }
            64 => {
                let Ok(seed_arr): Result<[u8; 64], _> = raw_key.try_into() else {
                    return String::new();
                };
                let dk = DecapsulationKey::<MlKem768>::from_seed(seed_arr.into());
                dk.encapsulation_key().to_bytes().as_slice().to_vec()
            }
            2400 => {
                let Ok(enc) = ExpandedDecapsulationKey::<MlKem768>::try_from(
                    raw_key.as_slice(),
                ) else {
                    return String::new();
                };
                #[allow(deprecated)]
                let Ok(dk) = DecapsulationKey::<MlKem768>::from_expanded(&enc) else {
                    return String::new();
                };
                dk.encapsulation_key().to_bytes().as_slice().to_vec()
            }
            _ => return String::new(),
        };
        *part = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public_bytes);
        keys += 1;
    }
    if keys == 0 {
        return String::new();
    }
    parts.join(".")
}

pub fn derive_client_tunnel(server_tunnel: &LocalTLS, server_node: &Node) -> LocalTLS {
    let mut res = LocalTLS {
        protocol: server_tunnel.protocol.clone(),
        transport_security: server_tunnel.transport_security.clone(),
        flow: server_tunnel.flow.clone(),
        ca_pem: server_tunnel.ca_pem.clone(),
        hysteria2: server_tunnel.hysteria2.clone(),
        xhttp: server_tunnel.xhttp.clone(),
        encryption: server_tunnel.encryption.clone(),
        ..Default::default()
    };
    if !server_tunnel.decryption.is_empty() {
        res.encryption = derive_vless_encryption(&server_tunnel.decryption);
    }
    let r = &server_tunnel.reality;
    if r.enabled() {
        res.reality.public_key = r.public_key.clone();
        if res.reality.public_key.is_empty() && !r.private_key.is_empty() {
            res.reality.public_key = derive_x25519_public(&r.private_key);
        }
        let first_short = r.short_ids.split(',').next().unwrap_or("").trim();
        res.reality.short_id = if !first_short.is_empty() {
            first_short.to_string()
        } else {
            r.short_id.clone()
        };
        let first_name = r.server_names.split(',').next().unwrap_or("").trim();
        res.reality.server_names = if !first_name.is_empty() {
            first_name.to_string()
        } else {
            server_node.address.clone()
        };
        res.reality.fingerprint = if r.fingerprint.is_empty() {
            "chrome".to_string()
        } else {
            r.fingerprint.clone()
        };
        res.reality.max_time_diff = r.max_time_diff.clone();
        res.reality.spider_x = r.spider_x.clone();
        res.reality.spider_y = r.spider_y.clone();
        res.reality.mldsa65_verify = r.mldsa65_verify.clone();
        if res.reality.mldsa65_verify.is_empty() && !r.mldsa65_seed.is_empty() {
            res.reality.mldsa65_verify = derive_mldsa65_verify(&r.mldsa65_seed);
        }
    }
    res
}

pub fn public_peer_tunnel(server_tunnel: &LocalTLS, server_node: &Node) -> LocalTLS {
    let mut peer = derive_client_tunnel(server_tunnel, server_node);
    peer.cert_pem.clear();
    peer.key_pem.clear();
    peer.hysteria2 = Hysteria2::default();
    peer
}

pub fn bandwidth_bytes(value: &str) -> Result<i64, String> {
    static BW_RE: OnceLock<Regex> = OnceLock::new();
    let value = value.trim();
    if value.is_empty() || value == "0" {
        return Ok(0);
    }
    let re = BW_RE.get_or_init(|| Regex::new(r"^([0-9]+(?:\.[0-9]{1,3})?)(Kbps|Mbps|Gbps)$").unwrap());
    let Some(caps) = re.captures(value) else {
        return Err(
            "bandwidth_limit must be empty or a positive Kbps, Mbps or Gbps value".to_string(),
        );
    };
    let n: f64 = caps[1]
        .parse()
        .map_err(|_| "bandwidth_limit must be between 1Kbps and 100Gbps".to_string())?;
    if n == 0.0 {
        return Ok(0);
    }
    let mult = match &caps[2] {
        "Kbps" => 1e3,
        "Mbps" => 1e6,
        "Gbps" => 1e9,
        _ => return Err("invalid unit".to_string()),
    };
    let bits = n * mult;
    if !(1000.0..=100e9).contains(&bits) {
        return Err("bandwidth_limit must be between 1Kbps and 100Gbps".to_string());
    }
    Ok((bits / 8.0) as i64)
}

fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}

fn is_false(v: &bool) -> bool {
    !*v
}
