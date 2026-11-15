// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! WHAT A REALM ADMINISTRATOR MAY NOT DO (`admin-ui/admin_scope.ts`'s
//! `refusalFor()`, #32): a realm's own administrator is confined to it, so
//! the pages about the whole service, the acts naming another realm or the
//! service's branch, and the settings that name the whole service are
//! refused to a realm's token. The gate asks this for a token that is not
//! the default realm's ([`crate::gate`], STS-API-0112).
//!
//! The service pages and the service-only settings are Node's own lists,
//! exported with the other tables. A setting is service-only when it is
//! per-process, named in `SERVICE_SETTING_KEYS` or under one of
//! `SERVICE_SETTING_PREFIXES`.
//!
//! NOT PORTED: the scheduler's `run` rule for a job of the whole service
//! (the scheduler's jobs are not in this runtime; a `step-down` and a run
//! naming another realm are refused as Node refuses them), and the risk
//! rules that look a dataset up in the risk catalogue (`accept-terms` is).

use serde_json::Value as Json;
use sts_core::settings::{rows, Settings};

use crate::tables::tables;

/// `refusalFor()`'s answer: its code and its sentence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// `service_page`, `service_action` or `service_setting`.
    pub reason: &'static str,
    pub detail: String,
    /// The settings refused, for `service_setting`.
    pub settings: Vec<String>,
}

/// `String(body.x || '').trim()`.
fn field(body: &Json, key: &str) -> String {
    match body.get(key) {
        None | Some(Json::Null) | Some(Json::Bool(false)) => String::new(),
        Some(Json::String(s)) => s.trim().to_string(),
        Some(other) => other.to_string().trim().to_string(),
    }
}

/// A query member's first value, trimmed.
fn query_field(query: Option<&Json>, key: &str) -> String {
    match query.and_then(|q| q.get(key)) {
        Some(Json::Array(a)) => a
            .first()
            .map(|v| field(&serde_json::json!({ "v": v }), "v"))
            .unwrap_or_default(),
        Some(v) => field(&serde_json::json!({ "v": v }), "v"),
        None => String::new(),
    }
}

/// `under(path, prefix)`: the prefix, or below it at a segment boundary.
fn under(path: &str, prefix: &str) -> bool {
    path == prefix || path.starts_with(&format!("{}/", prefix))
}

/// `pageIsService(path)`.
#[tracing::instrument(level = "trace")]
pub fn page_is_service(path: &str) -> bool {
    tables().service_pages.iter().any(|p| under(path, p))
}

/// `settingIsServiceOnly(key)`.
#[tracing::instrument(level = "trace")]
pub fn setting_is_service_only(key: &str) -> bool {
    let t = tables();
    Settings::is_per_process(key)
        || t.service_setting_keys.iter().any(|k| k == key)
        || t.service_setting_prefixes
            .iter()
            .any(|p| key.starts_with(p.as_str()))
}

/// `serviceSettingsIn(body)`: every known setting a body names that a
/// realm administrator may not write — the body's members, then `key`.
#[tracing::instrument(level = "trace", skip_all)]
pub fn service_settings_in(body: &Json) -> Vec<String> {
    let mut named: Vec<String> = Vec::new();
    let mut add = |key: &str| {
        let known = rows().iter().any(|r| r.key == key);
        if known
            && setting_is_service_only(key)
            && !named.iter().any(|n| n == key)
        {
            named.push(key.to_string());
        }
    };
    if let Some(o) = body.as_object() {
        for k in o.keys() {
            add(k);
        }
    }
    if let Some(Json::String(k)) = body.get("key") {
        add(k.trim());
    }
    named
}

/// `realmNamed(query, realmId)`: a page reading `?realm=` another realm.
fn realm_named(query: Option<&Json>, realm_id: &str) -> String {
    let id = query_field(query, "realm");
    if !id.is_empty() && id != realm_id {
        format!(
            "That page names the \"{}\" realm, and a realm administrator of \
             \"{}\" may read that realm only.",
            id, realm_id
        )
    } else {
        String::new()
    }
}

/// `tlsServerKeyRule(body)`.
fn tls_server_key_rule(body: &Json) -> String {
    if field(body, "key") == "tls-server" {
        "The TLS listener's private key belongs to the process, which every \
         realm shares."
            .to_string()
    } else {
        String::new()
    }
}

/// `serviceActions[path](body, realmId)`.
fn service_action(path: &str, body: &Json, realm_id: &str) -> String {
    let action = field(body, "action");
    match path {
        "/admin/realms" => {
            if action == "create" || action == "remove" {
                return "Creating or removing a trust realm is a service \
                        administrator's act."
                    .into();
            }
            let id = field(body, "id");
            if !id.is_empty() && id != realm_id {
                return format!(
                    "That action names the \"{}\" realm, and a realm \
                     administrator of \"{}\" may change that realm only.",
                    id, realm_id
                );
            }
            String::new()
        }
        "/admin/pki" => {
            let scope = field(body, "scope");
            if action == "build-root" {
                return "Replacing the service Root re-certifies every realm's \
                        branch, so it is a service administrator's act."
                    .into();
            }
            if scope.starts_with('*') {
                return format!(
                    "That action names the \"{}\" branch, which belongs to \
                     the whole service rather than to a realm.",
                    scope
                );
            }
            String::new()
        }
        "/admin/scheduler" => {
            if action == "step-down" {
                return "Handing the scheduler to another node is a service \
                        administrator's act."
                    .into();
            }
            if action == "run" {
                let named = field(body, "realm");
                if !named.is_empty() && named != realm_id {
                    return format!(
                        "That run names the \"{}\" realm, and a realm \
                         administrator of \"{}\" may run jobs in that realm \
                         only.",
                        named, realm_id
                    );
                }
            }
            String::new()
        }
        "/admin/risk" if action == "accept-terms" => {
            "A provider's terms are accepted for the whole service, so that \
             is a service administrator's act."
                .into()
        }
        "/admin/kerberos/trusts" => {
            let mirrored = matches!(body.get("mirror"), Some(Json::Bool(true)))
                || field(body, "mirror") == "true";
            if action == "pair" || (action == "rotate-key" && mirrored) {
                return format!(
                    "{} writes the partner trust realm's record as well, and \
                     a realm administrator of \"{}\" may change that realm \
                     only.",
                    if action == "pair" {
                        "Pairing a trust"
                    } else {
                        "Rotating both sides of a trust"
                    },
                    realm_id
                );
            }
            String::new()
        }
        "/admin/keys/export" => tls_server_key_rule(body),
        "/admin/keys" if action == "export" => tls_server_key_rule(body),
        _ => String::new(),
    }
}

/// `refusalFor({ authority: 'realm', identityRealm }, path, body, query)`:
/// why a realm administrator of `realm_id` may not do this, or `None`.
#[tracing::instrument(level = "debug", skip(body, query))]
pub fn refusal_for(
    realm_id: &str,
    path: &str,
    body: Option<&Json>,
    query: Option<&Json>,
) -> Option<Refusal> {
    if page_is_service(path) {
        return Some(Refusal {
            reason: "service_page",
            detail: format!(
                "{} is about the whole service, which a realm administrator \
                 of \"{}\" does not administer.",
                path, realm_id
            ),
            settings: Vec::new(),
        });
    }
    let read = match path {
        "/admin/risk" | "/admin/risk-scoring" | "/admin/realms" => {
            realm_named(query, realm_id)
        }
        _ => String::new(),
    };
    if !read.is_empty() {
        return Some(Refusal {
            reason: "service_action",
            detail: read,
            settings: Vec::new(),
        });
    }
    let body = body?;
    let why = service_action(path, body, realm_id);
    if !why.is_empty() {
        return Some(Refusal {
            reason: "service_action",
            detail: why,
            settings: Vec::new(),
        });
    }
    let settings = service_settings_in(body);
    if settings.is_empty() {
        return None;
    }
    Some(Refusal {
        reason: "service_setting",
        detail: format!(
            "A realm administrator may not change {}: {} the whole service \
             rather than the \"{}\" realm.",
            settings.join(", "),
            if settings.len() == 1 {
                "it names"
            } else {
                "they name"
            },
            realm_id
        ),
        settings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_service_page_is_refused_and_a_realm_page_is_not() {
        let r = refusal_for("acme", "/admin/persistence", None, None);
        assert_eq!(r.map(|r| r.reason), Some("service_page"));
        assert!(refusal_for("acme", "/admin/acme", None, None).is_none());
    }

    #[test]
    fn another_realm_or_the_service_branch_is_refused() {
        let other = json!({ "action": "set", "id": "beta" });
        let r = refusal_for("acme", "/admin/realms", Some(&other), None)
            .map(|r| r.detail);
        assert_eq!(
            r.as_deref(),
            Some(
                "That action names the \"beta\" realm, and a realm \
                 administrator of \"acme\" may change that realm only."
            )
        );
        let root = json!({ "action": "build-root" });
        assert!(refusal_for("acme", "/admin/pki", Some(&root), None).is_some());
        let read = json!({ "realm": "beta" });
        assert!(
            refusal_for("acme", "/admin/realms", None, Some(&read)).is_some()
        );
    }
}
