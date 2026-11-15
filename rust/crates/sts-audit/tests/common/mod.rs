// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! What the two vector tests share: the vectors, the comparison, the
//! frozen clock and the keystore's keyed digest.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)] // tests

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

use serde_json::Value as Json;
use sts_audit::log::{Clock, KeyedDigest};

pub fn vectors() -> Option<Json> {
    let dir = std::env::var("STS_CRYPTO_VECTORS").ok()?;
    let dir = std::path::Path::new(&dir);
    if let Ok(text) = std::fs::read_to_string(dir.join("auditmail-node.json"))
    {
        let all: Json = serde_json::from_str(&text).unwrap();
        return Some(all["audit"].clone());
    }
    let text = std::fs::read_to_string(dir.join("audit-only.json")).ok()?;
    Some(serde_json::from_str(&text).unwrap())
}

/// Numbers compared by value: Node writes `5000`, a model's `f64` `5000.0`.
pub fn norm(v: &Json) -> Json {
    match v {
        Json::Number(n) => {
            let f = n.as_f64().unwrap();
            if f.fract() == 0.0 && f.abs() < 9e15 {
                Json::from(f as i64)
            } else {
                Json::from(f)
            }
        }
        Json::Array(a) => Json::Array(a.iter().map(norm).collect()),
        Json::Object(m) => Json::Object(
            m.iter().map(|(k, v)| (k.clone(), norm(v))).collect(),
        ),
        other => other.clone(),
    }
}

pub fn same(what: &str, rust: &Json, node: &Json) {
    let (r, n) = (norm(rust), norm(node));
    assert!(r == n, "{}\n rust: {}\n node: {}", what, r, n);
}

pub struct Frozen(pub Arc<AtomicI64>);

impl Clock for Frozen {
    fn now_ms(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

pub struct Keys(pub Arc<sts_store::keystore::DataKeys>);

impl KeyedDigest for Keys {
    fn keyed_digest(&self, label: &str, text: &str) -> Option<String> {
        self.0.keyed_digest(label, text)
    }
}

