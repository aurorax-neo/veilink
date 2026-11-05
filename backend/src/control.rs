use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::logring::Entry as LogEntry;

pub const PATH_ENROLL: &str = "/api/control/enroll";
pub const PATH_PULL: &str = "/api/control/pull";
pub const PATH_EVENTS: &str = "/api/control/events";

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EnrollRequest {
    #[serde(default)]
    pub node_id: String,
    #[serde(default)]
    pub token: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EnrollResponse {
    #[serde(default)]
    pub credential: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PullRequest {
    #[serde(default)]
    pub node_id: String,
    #[serde(default)]
    pub credential: String,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrafficBytesPayload {
    #[serde(default)]
    pub up: u64,
    #[serde(default)]
    pub down: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EventsRequest {
    #[serde(default)]
    pub node_id: String,
    #[serde(default)]
    pub credential: String,
    #[serde(default)]
    pub applied_revision: i64,
    #[serde(default)]
    pub error: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub software_version: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub software_commit: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub links: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traffic: Option<HashMap<String, TrafficBytesPayload>>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub traffic_epoch: String,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub traffic_seq: u64,
    #[serde(default)]
    pub logs: Vec<LogEntry>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EventsResponse {
    #[serde(default)]
    pub revision: i64,
    #[serde(default, skip_serializing_if = "is_false")]
    pub refresh: bool,
}

fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

fn is_false(v: &bool) -> bool {
    !*v
}
