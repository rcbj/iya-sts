// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE IDENTITY REGISTER, WRITTEN (`common/admin_stats.js`'s
//! `recordAuthentication(detail)`, `userRecord()` and `identityOf()`;
//! #444, phase 5, the `apis4` slice).
//!
//! Every accepted credential reaches the register through ONE funnel in
//! Node, `recordAuthentication()`, and the session core calls it at
//! `startSession()` (`sts_authn::ports::Records`). Here it is the port the
//! session core's token revocation forwards to
//! (`sts_oauth::minted::SessionTokens::inner`), so a sign-in Rust accepts
//! writes the same `admin_stats.users` row Node writes: the person's key
//! (a `urn:uuid:` subject resolved to its person, a realm-qualified name
//! split at its last `@`, the name an entry is filed under where the
//! directory holds one), the forms and realms they were presented in, the
//! count by protocol and method, the last fifty events, and the instants.
//! The store's handle is declared here, before the store opens, and the
//! management API's views READ the same map (`admin_views.rs`).
//!
//! NOT PORTED, and what happens meanwhile: the user observer Node tells
//! of the authentication (the directory learning of a person in
//! development, which this runtime's sign-in path does not create), the
//! application register's own count (`applications.recordAuthentication()`
//! — an application's `appAuthentications` is not moved by a Rust
//! sign-in), and the register's process counters (`nums`). The audit row
//! goes to the log, as this runtime's other audit rows do.

use std::sync::Arc;

use serde_json::{json, Map, Value as Json};
use sts_authn::ports::People as _;
use sts_core::realm_lifecycle::RealmLifecycle;
use sts_core::realm_store::{Merge, RealmMap, StoreHandles, StoreSpec};

/// `admin_stats.users`' handle.
pub const USERS_HANDLE: &str = "admin_stats.users";
/// `MAX_USERS`.
const MAX_USERS: usize = 2000;
/// `MAX_EVENTS_PER_USER`.
const MAX_EVENTS_PER_USER: usize = 50;
/// `SUBJECT_PREFIX`.
const SUBJECT_PREFIX: &str = "urn:sts:user:";

/// `identityOf(value)`'s answer.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Identity {
    pub key: String,
    pub name: String,
    pub realm: String,
    pub form: String,
    pub unresolved: bool,
}

/// The identity register's writer.
pub struct IdentityRecords {
    users: RealmMap<Json>,
    directory: Arc<sts_authn_api::wiring::DirectoryPorts>,
}

// `DN_SHAPED`: `^[A-Za-z][A-Za-z0-9-]*=`.
fn dn_shaped(text: &str) -> bool {
    let mut chars = text.chars();
    if !chars.next().is_some_and(|c| c.is_ascii_alphabetic()) {
        return false;
    }
    match text.split_once('=') {
        Some((name, _)) => {
            name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        }
        None => false,
    }
}

// `DID_SHAPED`: `^did:[a-z0-9]+:` (case-insensitive).
fn did_shaped(text: &str) -> bool {
    text.len() > 4
        && text[..4].eq_ignore_ascii_case("did:")
        && text[4..].split_once(':').is_some_and(|(m, _)| {
            !m.is_empty() && m.chars().all(|c| c.is_ascii_alphanumeric())
        })
}

// `claimText(value)`: a string as it is, a number or a boolean as text,
// anything else empty.
fn claim_text(value: Option<&Json>) -> String {
    match value {
        Some(Json::String(s)) => s.clone(),
        Some(Json::Number(n)) => n.to_string(),
        Some(Json::Bool(b)) => b.to_string(),
        _ => String::new(),
    }
}

fn bump(map: &mut Json, key: &str) {
    if let Some(o) = map.as_object_mut() {
        let n = o.get(key).and_then(Json::as_i64).unwrap_or(0) + 1;
        o.insert(key.into(), json!(n));
    }
}

impl IdentityRecords {
    /// Declares the register's store as Node declares it (`persist:
    /// 'admin_stats.users', merge: 'own'`), before the store opens.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn declare(
        lifecycle: &Arc<RealmLifecycle>,
        handles: &Arc<StoreHandles>,
        directory: Arc<sts_authn_api::wiring::DirectoryPorts>,
    ) -> IdentityRecords {
        let spec = StoreSpec {
            merge: Merge::Own,
            ..StoreSpec::persisted(USERS_HANDLE)
        };
        IdentityRecords {
            users: RealmMap::new(lifecycle, handles, spec),
            directory,
        }
    }

    /// The map, for the views that read it.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn users(&self) -> RealmMap<Json> {
        self.users.clone()
    }

    /// `identityOf(value)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn identity_of(&self, value: &str) -> Identity {
        let text = value.trim().to_string();
        if text.is_empty() {
            return Identity::default();
        }
        let rest = text.strip_prefix(SUBJECT_PREFIX).unwrap_or(&text);
        if rest.len() >= 9 && rest[..9].eq_ignore_ascii_case("urn:uuid:") {
            let named = self.directory.name_for_subject(rest);
            if named.is_empty() {
                return Identity {
                    key: rest.to_string(),
                    name: rest.to_string(),
                    realm: String::new(),
                    form: text.clone(),
                    unresolved: true,
                };
            }
            return Identity {
                key: named.clone(),
                name: named,
                realm: String::new(),
                form: text.clone(),
                unresolved: false,
            };
        }
        let at = if dn_shaped(rest) || did_shaped(rest) {
            None
        } else {
            rest.rfind('@').filter(|a| *a > 0)
        };
        let (key, realm) = match at {
            Some(a) => (rest[..a].to_string(), rest[a + 1..].to_string()),
            None => (rest.to_string(), String::new()),
        };
        Identity {
            key: key.clone(),
            name: key,
            realm,
            form: text.clone(),
            unresolved: false,
        }
    }

    // `userRecord(identity)`: the record, made (the oldest forgotten at
    // the cap) where the register has none.
    fn user_record(&self, identity: &Identity) -> Json {
        let here = self.users.in_realm(&sts_core::realm::current_id());
        if let Some(found) = here.get(&identity.key) {
            return found;
        }
        if here.len() >= MAX_USERS {
            if let Some(oldest) = here.keys().into_iter().next() {
                here.delete(&oldest);
            }
        }
        let record = json!({
            "key": identity.key, "name": identity.name,
            "forms": {}, "realms": {}, "protocols": {},
            "events": [], "eventsForgotten": 0,
            "authentications": 0, "firstAt": 0, "lastAt": 0,
            "isClient": false,
        });
        here.set(&identity.key, record.clone());
        record
    }

    /// `recordAuthentication(detail)`: one accepted credential recorded;
    /// the record, or `None` for an empty identity.
    #[tracing::instrument(level = "debug", skip(self, info, address))]
    pub fn record(&self, info: &Json, address: &str) -> Option<Json> {
        let mut identity = self.identity_of(&claim_text(info.get("presented")));
        if identity.key.is_empty() {
            return None;
        }
        let truthy = |k: &str| {
            info.get(k).is_some_and(|v| {
                !matches!(v, Json::Null | Json::Bool(false))
                    && v.as_str() != Some("")
            })
        };
        if truthy("federation") {
            let form = identity.form.clone();
            if let (Some(tilde), Some(at)) = (form.find('~'), form.find('@')) {
                if tilde > 0 && at > tilde {
                    identity.key = form.clone();
                    identity.name = form;
                    identity.realm = String::new();
                }
            }
        }
        // The name the person's entry is filed under, where the directory
        // holds one (`existingUserEntry()`, `personNameOf()`).
        if !identity.form.is_empty() {
            let sub = self.directory.subject_for_name(&identity.form);
            let filed = if sub.is_empty() {
                String::new()
            } else {
                self.directory.name_for_subject(&sub)
            };
            if !filed.is_empty() {
                identity.key = filed.clone();
                identity.name = filed;
                identity.realm = String::new();
            }
        }
        let now = chrono::Utc::now().timestamp_millis();
        let mut record = self.user_record(&identity);
        bump(&mut record["forms"], &identity.form);
        if !identity.realm.is_empty() {
            bump(&mut record["realms"], &identity.realm);
        }
        if truthy("isClient") {
            record["isClient"] = json!(true);
        }
        let protocol = match claim_text(info.get("protocol")) {
            p if p.is_empty() => "unstated".to_string(),
            p => p,
        };
        if record["protocols"].get(&protocol).is_none() {
            record["protocols"][&protocol] = json!({
                "protocol": protocol, "count": 0, "methods": {},
                "firstAt": now, "lastAt": 0,
            });
        }
        let method = match claim_text(info.get("method")) {
            m if m.is_empty() => "unstated".to_string(),
            m => m,
        };
        let is_client = record["isClient"] == json!(true);
        let subject = match claim_text(info.get("sub")) {
            s if !s.is_empty() => s,
            _ if is_client => String::new(),
            _ => self.directory.subject_for_name(&identity.key),
        };
        {
            let family = &mut record["protocols"][&protocol];
            let count = family["count"].as_i64().unwrap_or(0) + 1;
            family["count"] = json!(count);
            bump(&mut family["methods"], &method);
            family["lastAt"] = json!(now);
        }
        let total = record["authentications"].as_i64().unwrap_or(0) + 1;
        record["authentications"] = json!(total);
        if record["firstAt"].as_i64().unwrap_or(0) == 0 {
            record["firstAt"] = json!(now);
        }
        record["lastAt"] = json!(now);
        let address = match claim_text(info.get("address")) {
            a if !a.is_empty() => a,
            _ => address.to_string(),
        };
        let amr: Vec<String> = info
            .get("amr")
            .and_then(Json::as_array)
            .map(|a| a.iter().map(|v| claim_text(Some(v))).collect())
            .unwrap_or_default();
        let mut event = Map::new();
        event.insert("at".into(), json!(now));
        event.insert("protocol".into(), json!(protocol));
        event.insert("method".into(), json!(method));
        event.insert("presented".into(), json!(identity.form));
        event.insert("realm".into(), json!(identity.realm));
        event.insert("sub".into(), json!(subject));
        event.insert("address".into(), json!(address));
        event.insert(
            "client_id".into(),
            json!(claim_text(info.get("client_id"))),
        );
        event.insert("amr".into(), json!(amr.join(", ")));
        event.insert("acr".into(), json!(claim_text(info.get("acr"))));
        event.insert(
            "sessionId".into(),
            json!(claim_text(info.get("sessionId"))),
        );
        event.insert("note".into(), json!(claim_text(info.get("note"))));
        if let Some(events) = record["events"].as_array_mut() {
            events.push(Json::Object(event));
            if events.len() > MAX_EVENTS_PER_USER {
                events.remove(0);
                let forgotten =
                    record["eventsForgotten"].as_i64().unwrap_or(0) + 1;
                record["eventsForgotten"] = json!(forgotten);
            }
        }
        let here = self.users.in_realm(&sts_core::realm::current_id());
        here.set(&identity.key, record.clone());
        let line = format!(
            "admin: {} authenticated through {} ({}). {} time(s) so far; {} \
             user(s) known.",
            identity.key,
            protocol,
            method,
            total,
            here.len()
        );
        if total == 1 || total % 100 == 0 {
            tracing::info!("{line}");
        } else {
            tracing::debug!("{line}");
        }
        tracing::info!(
            "audit: {}",
            json!({
                "action": "authentication", "actor": identity.key,
                "actorForm": identity.form, "protocol": protocol,
                "channel": "internal", "address": address,
                "target": claim_text(info.get("sessionId")),
                "summary": format!("{} authenticated through {} ({})",
                                   identity.key, protocol, method),
                "detail": {
                    "method": method, "presented": identity.form,
                    "realm": identity.realm, "sub": subject,
                    "client_id": claim_text(info.get("client_id")),
                    "application": claim_text(info.get("application")),
                    "amr": amr.join(", "),
                    "acr": claim_text(info.get("acr")),
                    "sessionId": claim_text(info.get("sessionId")),
                    "isClient": is_client,
                    "authenticationsSoFar": total,
                    "note": claim_text(info.get("note")),
                },
            })
        );
        Some(record)
    }
}

impl sts_authn::ports::Records for IdentityRecords {
    fn record_authentication(
        &self,
        record: &Json,
        request: Option<&sts_authn::ports::Request>,
    ) {
        self.record(record, request.map_or("", |r| r.address.as_str()));
    }

    fn revoke_session_tokens(
        &self,
        _sid: &str,
        _revokes_access: bool,
        _reason: &str,
        _opts: &Json,
        _tags: &[String],
    ) -> usize {
        // The token register's (`SessionTokens`), which wraps this one.
        0
    }

    fn record_account_choice(&self, kind: &str, n: Option<u64>) {
        // `recordAccountChoice()`'s counters are the register's process
        // counters, not ported (see the module comment).
        tracing::debug!("admin: an account choice ({}, {:?}).", kind, n);
    }
}
