// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE DELEGATION REGISTER's write half (`common/delegation.js`'s
//! `record()`, rule 3l): one row per act of delegation or impersonation,
//! in Node's store and Node's shape, so `/admin/delegation` and
//! `GET /admin-api/delegation` — Node's, on the same store — list an
//! exchange this runtime performed beside one Node did.
//!
//! The store is `delegation.acts`, a per-realm array declared `merge:
//! 'own'`: each process writes only its own acts, and the readers merge
//! every origin's on the way out. A row is `{ seq, origin, at, protocol,
//! type, typeLabel, mode, spec, policed, outcome, initial, intermediary,
//! target, authorizedBy, reason, consumed, produced, sessionId, note,
//! chainKey }`, each party `{ key, presented, application, what }` with
//! `key` the identity funnel's (`identityKeyOf()`).
//!
//! WHAT REPLACED WHAT. Node numbers a row from a block of `seq` leased from
//! the store (`seq_allocator.ts`); here the caller hands the next number in
//! ([`DelegationActs::seq`]), and the runtime's is this process's own
//! counter — unique within the process, rising, and told apart from
//! another process's by `origin`, which is what Node's `merged()` breaks a
//! tie on. Recording never fails the protocol: nothing here can throw,
//! which is the guarantee Node's `STS-REG-0033` catch gives.

use std::sync::Arc;

use serde_json::{json, Map, Value as Json};
use sts_core::realm_lifecycle::RealmLifecycle;
use sts_core::realm_store::{Merge, RealmVec, StoreHandles, StoreSpec};
use sts_core::settings::Settings;

/// The handle the acts are written under.
pub const HANDLE: &str = "delegation.acts";

/// `TYPES` (the rows this port records): `(type, protocol, mode, label,
/// spec, policed)`.
const TYPES: &[(&str, &str, &str, &str, &str, bool)] = &[
    (
        "oauth-impersonation",
        "OAuth 2.0",
        "impersonation",
        "Token exchange — impersonation",
        "RFC 8693 §1.1",
        true,
    ),
    (
        "oauth-delegation",
        "OAuth 2.0",
        "delegation",
        "Token exchange — delegation",
        "RFC 8693 §4.1",
        true,
    ),
];

/// The register.
pub struct DelegationActs {
    pub settings: Arc<Settings>,
    pub acts: RealmVec<Json>,
    /// The next `seq`.
    pub seq: Arc<dyn Fn() -> i64 + Send + Sync>,
    /// `processOrigin()`: this process's stable origin in the store.
    pub origin: Arc<dyn Fn() -> String + Send + Sync>,
    /// `identityKeyOf(presented)`.
    pub identity_key: Arc<dyn Fn(&str) -> String + Send + Sync>,
    pub now_ms: Arc<dyn Fn() -> i64 + Send + Sync>,
}

fn text(v: Option<&Json>) -> String {
    match v {
        None | Some(Json::Null) => String::new(),
        other => crate::js::string_of(other).trim().to_string(),
    }
}

impl DelegationActs {
    /// Declares the store as Node declares it (`realms.arr({ persist:
    /// 'delegation.acts', merge: 'own' })`), before the store opens.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn declare(
        lifecycle: &Arc<RealmLifecycle>,
        handles: &Arc<StoreHandles>,
    ) -> RealmVec<Json> {
        let spec = StoreSpec {
            merge: Merge::Own,
            ..StoreSpec::persisted(HANDLE)
        };
        RealmVec::new(lifecycle, handles, spec, 0)
    }

    /// `party(detail)`.
    fn party(&self, detail: Option<&Json>) -> Json {
        let empty = json!({});
        let info = detail.unwrap_or(&empty);
        let presented = text(info.get("presented"));
        json!({
            "key": if presented.is_empty() { String::new() }
                   else { (self.identity_key)(&presented) },
            "presented": presented,
            "application": text(info.get("application")),
            "what": text(info.get("what")),
        })
    }

    /// `credentials(list)`: each `{ kind, identifier, note }`, the empty
    /// ones left out.
    fn credentials(list: Option<&Json>) -> Json {
        let items: Vec<Json> = match list {
            Some(Json::Array(a)) => a.clone(),
            None | Some(Json::Null) => Vec::new(),
            Some(one) => vec![one.clone()],
        };
        Json::Array(
            items
                .iter()
                .filter(|one| crate::js::truthy(Some(one)))
                .map(|one| {
                    json!({
                        "kind": text(one.get("kind")),
                        "identifier": text(one.get("identifier")),
                        "note": text(one.get("note")),
                    })
                })
                .filter(|c| {
                    c["kind"] != "" || c["identifier"] != "" || c["note"] != ""
                })
                .collect(),
        )
    }

    /// `maxRecords()`.
    fn max_records(&self) -> usize {
        let n = crate::grants::setting_number(
            &self.settings,
            "delegation.maxRecords",
        );
        if n.is_finite() && n >= 1.0 {
            n as usize
        } else {
            1
        }
    }

    /// `record(detail)`: the row, as it was stored.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn record(&self, info: &Json) -> Json {
        let kind = text(info.get("type"));
        let known = TYPES.iter().find(|t| t.0 == kind);
        if known.is_none() {
            tracing::warn!(
                "delegation: \"{}\" is not one of the types this store knows \
                 ({}). The act is recorded as given, which is how one \
                 mechanism comes to be listed under two spellings — fix the \
                 caller or add a row to TYPES.",
                kind,
                TYPES.iter().map(|t| t.0).collect::<Vec<_>>().join(", ")
            );
        }
        let outcome = match text(info.get("outcome")).as_str() {
            "refused" => "refused",
            _ => "issued",
        };
        let protocol = {
            let p = text(info.get("protocol"));
            if p.is_empty() {
                known.map(|k| k.1.to_string()).unwrap_or_default()
            } else {
                p
            }
        };
        let mut row = Map::new();
        row.insert("seq".into(), json!((self.seq)()));
        row.insert("origin".into(), json!((self.origin)()));
        row.insert("at".into(), json!((self.now_ms)()));
        row.insert("protocol".into(), json!(protocol));
        row.insert("type".into(), json!(kind));
        row.insert(
            "typeLabel".into(),
            json!(known.map_or(kind.as_str(), |k| k.3)),
        );
        row.insert("mode".into(), json!(known.map_or("", |k| k.2)));
        row.insert("spec".into(), json!(known.map_or("", |k| k.4)));
        row.insert("policed".into(), json!(known.is_some_and(|k| k.5)));
        row.insert("outcome".into(), json!(outcome));
        row.insert("initial".into(), self.party(info.get("initial")));
        row.insert("intermediary".into(), self.party(info.get("intermediary")));
        row.insert("target".into(), self.party(info.get("target")));
        row.insert(
            "authorizedBy".into(),
            json!(text(info.get("authorizedBy"))),
        );
        row.insert("reason".into(), json!(text(info.get("reason"))));
        row.insert("consumed".into(), Self::credentials(info.get("consumed")));
        row.insert("produced".into(), Self::credentials(info.get("produced")));
        row.insert("sessionId".into(), json!(text(info.get("sessionId"))));
        row.insert("note".into(), json!(text(info.get("note"))));
        let at = |p: &Json| {
            ["key", "presented", "application"]
                .iter()
                .map(|k| p[*k].as_str().unwrap_or(""))
                .find(|v| !v.is_empty())
                .unwrap_or("(none)")
                .to_string()
        };
        let chain = [
            kind.clone(),
            at(&row["initial"]),
            at(&row["intermediary"]),
            at(&row["target"]),
        ]
        .join(" | ");
        row.insert("chainKey".into(), json!(chain));
        let row = Json::Object(row);
        let cap = self.max_records();
        self.acts.with_mut(|rows| {
            rows.push_back(row.clone());
            while rows.len() > cap {
                rows.pop_front();
            }
        });
        let intermediary = &row["intermediary"];
        let target = &row["target"];
        let named = |p: &Json, keys: &[&str]| {
            keys.iter()
                .map(|k| p[*k].as_str().unwrap_or(""))
                .find(|v| !v.is_empty())
                .unwrap_or("")
                .to_string()
        };
        let reached = named(target, &["application", "presented"]);
        tracing::info!(
            "delegation: {} {} — {} {}{}{}{}",
            protocol,
            row["typeLabel"].as_str().unwrap_or(""),
            {
                let n = named(intermediary, &["presented", "application"]);
                if n.is_empty() {
                    "something".to_string()
                } else {
                    n
                }
            },
            if outcome == "issued" {
                "acted for "
            } else {
                "was REFUSED acting for "
            },
            {
                let p = row["initial"]["presented"].as_str().unwrap_or("");
                if p.is_empty() {
                    "(nobody named)".to_string()
                } else {
                    p.to_string()
                }
            },
            if reached.is_empty() {
                String::new()
            } else {
                format!(" at {}", reached)
            },
            {
                let r = row["reason"].as_str().unwrap_or("");
                if r.is_empty() {
                    String::new()
                } else {
                    format!(" — {}", r)
                }
            }
        );
        row
    }
}
