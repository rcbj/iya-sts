// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! ONE AUDIT ROW, as `common/audit.js`'s `record()` writes it and as the
//! store keeps it (`audit.events`): the members in Node's order, so a ring
//! Rust writes and a ring Node wrote are the same JSON, and a 1.x ring
//! read back after the upgrade is these rows unchanged.
//!
//! `prev` and `mac` are optional because rows written before the chain
//! (#1552) have no `prev`, and a row written with no key-encryption key has
//! no checksum; [`AuditRow::mac_fields`] checks each the way it was
//! written.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value as Json};

/// A row of the ring.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditRow {
    #[serde(default)]
    pub seq: i64,
    #[serde(default)]
    pub origin: String,
    #[serde(default)]
    pub at: i64,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub outcome: String,
    #[serde(rename = "errorCode", default)]
    pub error_code: String,
    #[serde(default)]
    pub actor: String,
    #[serde(rename = "actorForm", default)]
    pub actor_form: String,
    #[serde(default)]
    pub target: String,
    #[serde(default)]
    pub protocol: String,
    #[serde(default)]
    pub channel: String,
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub detail: Map<String, Json>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
}

const LEGACY_MAC_FIELDS: &[&str] = &[
    "seq",
    "origin",
    "at",
    "category",
    "action",
    "actor",
    "actorForm",
    "target",
    "outcome",
    "summary",
    "address",
    "errorCode",
];

impl AuditRow {
    /// The text `rowMac()` digests: `JSON.stringify` of the checksummed
    /// members in order, `prev` last where the row has one. A hot path
    /// (every row written and every row checked): no span.
    pub fn mac_text(&self) -> String {
        let mut values: Vec<Json> = LEGACY_MAC_FIELDS
            .iter()
            .map(|field| self.member(field))
            .collect();
        if let Some(prev) = &self.prev {
            values.push(Json::from(prev.clone()));
        }
        Json::Array(values).to_string()
    }

    fn member(&self, field: &str) -> Json {
        match field {
            "seq" => Json::from(self.seq),
            "origin" => Json::from(self.origin.clone()),
            "at" => Json::from(self.at),
            "category" => Json::from(self.category.clone()),
            "action" => Json::from(self.action.clone()),
            "actor" => Json::from(self.actor.clone()),
            "actorForm" => Json::from(self.actor_form.clone()),
            "target" => Json::from(self.target.clone()),
            "outcome" => Json::from(self.outcome.clone()),
            "summary" => Json::from(self.summary.clone()),
            "address" => Json::from(self.address.clone()),
            "errorCode" => Json::from(self.error_code.clone()),
            _ => Json::Null,
        }
    }

    /// The row as JSON, in Node's member order.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn to_json(&self) -> Json {
        serde_json::to_value(self).unwrap_or(Json::Null)
    }
}
