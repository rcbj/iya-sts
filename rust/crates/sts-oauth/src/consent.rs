// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE CONSENT REGISTER AND THE CONSENT SCREEN (`common/consent.ts`,
//! `oauth-oidc/consent_screen.ts`, rule 4c), in Node's stores and with
//! Node's sentences and codes.
//!
//! * **What has been agreed is on the person's own entry** —
//!   `oauthConsent`, one value per scope, `<GeneralizedTime> <scope>
//!   <client_id>` (`consentValueOf()`), written through the directory
//!   ([`ConsentDirectory`], `ldap_server.js`'s `addConsentValues()`), so a
//!   consent a Node beside this runtime recorded is the one honoured here,
//!   and one recorded here is the one `/admin-api/consent` lists. An
//!   application's `oauthGlobalConsent` consents for everybody; the scopes
//!   it answered for a person are noted in `oauthConsentApplied`
//!   (`noteApplied()`, #537).
//! * **The pending question** is `consent_screen.pending`, per realm, the
//!   record Node mints (`beginConsent()`), keyed by an unguessable id; the
//!   page is the sign-in surface's bundle drawn from the view
//!   ([`ConsentScreen::view`]) and the answer is `POST
//!   /authn-api/consent/{id}` ([`ConsentScreen::act`]), the record spent
//!   either way.
//! * **A public client's one-time Allow** (ASVS 5.0.0 10.7.1) is
//!   `authorization_details.consented`, keyed `<username> <client>
//!   <digest>` with `scope:` digests, as `authorization_details.ts` keeps
//!   it.
//!
//! WHAT IS NOT HERE, and what is answered meanwhile: RFC 9396 details (this
//! runtime reads no `authorization_details`, so no detail is ever asked
//! about and no limit lowered), the issuance gate's consent stage
//! (`gate.checkScopes()`, whose default policy is the rule ported here: a
//! scope needs an answer where consent is required and nothing covers it).
//! The audit rows go into the request's ring (`sts_http::call_log::audit`),
//! to the log where there is none.

use std::sync::Arc;

use serde_json::{json, Value as Json};
use sts_authn::ports::Request;
use sts_core::errors::{codes, ErrorCode};
use sts_core::realm_lifecycle::RealmLifecycle;
use sts_core::realm_store::{
    expiry_field, RealmMap, Retain, StoreHandles, StoreSpec,
};
use sts_core::settings::Settings;

use crate::authorize::SignOn;
use crate::clients::Clients;

/// `USER_ATTRIBUTE`.
pub const USER_ATTRIBUTE: &str = "oauthConsent";

/// `APPLIED_ATTRIBUTE` (#537).
pub const APPLIED_ATTRIBUTE: &str = "oauthConsentApplied";

/// `CONSENT_PATH`.
pub const CONSENT_PATH: &str = "/oauth2/consent";

/// `CONSENT_TTL_MS`: the fallback where `authn.pendingTtlS` is unset.
const CONSENT_TTL_MS: f64 = 10.0 * 60.0 * 1000.0;

/// `SSO_SIGN_IN_SCOPE` (ASVS 5.0.0 7.6.2).
const SSO_SIGN_IN_SCOPE: &str = "urn:iya-sts:scope:sign-in";

/// `applications.HOSTED_SURFACE_CLIENT_IDS`: this service's own
/// applications, which `alwaysAsks()` never forces.
const HOSTED: [&str; 4] = [
    "sts-admin-console",
    "sts-user-portal",
    "sts-report",
    "sts-debugger-ui",
];

/// The store a consent is filed in: the person's entry under ou=users
/// (`ldap_server.js`'s consent hooks). The key is already normalised
/// ([`ConsentRegister::identity_key_of`]).
pub trait ConsentDirectory: Send + Sync {
    /// `consentValuesOf(key, attribute)`: the values, or `None` for an
    /// identity with no entry.
    fn values_of(&self, key: &str, attribute: &str) -> Option<Vec<String>>;
    /// `addConsentValues(key, values, attribute)`: `Ok(changed)`, or
    /// `Err(reason)` (`noEntry`) where there is nothing to write to.
    fn add_values(
        &self,
        key: &str,
        attribute: &str,
        values: &[String],
    ) -> Result<bool, String>;
    /// `subjectNameOf(sub)`: the name a `urn:uuid:` subject files under.
    fn name_for_subject(&self, sub: &str) -> String;
}

fn s(v: Option<&Json>) -> String {
    crate::js::string_of(v)
}

/// One parsed consent value (`parseConsentValue()`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Agreed {
    pub at: String,
    pub scope: String,
    pub client: String,
}

/// `CONSENT_STAMP`: fourteen digits and a `Z`.
fn is_stamp(text: &str) -> bool {
    text.len() == 15
        && text.ends_with('Z')
        && text[..14].bytes().all(|b| b.is_ascii_digit())
}

/// The register: what is agreed, and which of a request's scopes are
/// outstanding.
pub struct ConsentRegister {
    pub settings: Arc<Settings>,
    pub clients: Arc<dyn Clients>,
    pub directory: Arc<dyn ConsentDirectory>,
    /// `authorization_details.consented`: a one-time Allow, by digest.
    pub answers: RealmMap<Json>,
    pub now_ms: Arc<dyn Fn() -> f64 + Send + Sync>,
}

impl ConsentRegister {
    /// Declares `authorization_details.consented` (before the store opens).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn declare_answers(
        lifecycle: &Arc<RealmLifecycle>,
        handles: &Arc<StoreHandles>,
    ) -> RealmMap<Json> {
        RealmMap::new(
            lifecycle,
            handles,
            StoreSpec {
                expires_at: Some(expiry_field(Some("expires"), 1.0)),
                ..StoreSpec::persisted("authorization_details.consented")
            },
        )
    }

    /// `generalizedTime(when)`.
    #[tracing::instrument(level = "trace")]
    pub fn generalized_time(ms: f64) -> String {
        chrono::DateTime::from_timestamp_millis(ms as i64)
            .unwrap_or_default()
            .format("%Y%m%d%H%M%SZ")
            .to_string()
    }

    /// `consentValueOf(scope, clientId, when)`.
    #[tracing::instrument(level = "trace")]
    pub fn consent_value_of(scope: &str, client_id: &str, ms: f64) -> String {
        format!(
            "{} {} {}",
            Self::generalized_time(ms),
            scope.trim(),
            client_id.trim()
        )
    }

    /// `parseConsentValue(value)`: two splits, the client the rest; a
    /// value whose first field is not a GeneralizedTime is no consent.
    #[tracing::instrument(level = "trace")]
    pub fn parse_consent_value(value: &str) -> Option<Agreed> {
        let text = value.trim();
        let (at, rest) = text.split_once(' ')?;
        let (scope, client) = rest.split_once(' ')?;
        if !is_stamp(at) || scope.is_empty() {
            return None;
        }
        Some(Agreed {
            at: at.to_string(),
            scope: scope.to_string(),
            client: client.to_string(),
        })
    }

    /// `identityKeyOf(value)` (`admin_stats.js`): a subject by the name it
    /// files under, a principal by its part before the last `@` — unless
    /// the value is a DN or a DID, taken whole.
    #[tracing::instrument(level = "trace", skip(self))]
    pub fn identity_key_of(&self, value: &str) -> String {
        let text = value.trim();
        let rest = text.strip_prefix("urn:sts:user:").unwrap_or(text);
        if rest.len() >= 9 && rest[..9].eq_ignore_ascii_case("urn:uuid:") {
            let named = self.directory.name_for_subject(rest);
            return if named.is_empty() {
                rest.to_string()
            } else {
                named
            };
        }
        let dn = rest.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
            && rest.split_once('=').is_some_and(|(n, _)| {
                n.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            });
        let did = rest.len() > 4
            && rest[..4].eq_ignore_ascii_case("did:")
            && rest[4..].split_once(':').is_some_and(|(m, _)| {
                !m.is_empty() && m.chars().all(|c| c.is_ascii_alphanumeric())
            });
        if !dn && !did {
            if let Some(at) = rest.rfind('@').filter(|a| *a > 0) {
                return rest[..at].to_string();
            }
        }
        rest.to_string()
    }

    /// `scopesOf(scope)`: deduplicated, in the order asked.
    #[tracing::instrument(level = "trace")]
    pub fn scopes_of(scope: &str) -> Vec<String> {
        let mut seen: Vec<String> = Vec::new();
        for one in scope.split_whitespace() {
            if !seen.iter().any(|s| s == one) {
                seen.push(one.to_string());
            }
        }
        seen
    }

    /// `fapi.v1()`: FAPI 1.0, which makes the screen compulsory and a
    /// global consent no answer (#138).
    fn fapi_v1(&self) -> bool {
        let profile =
            crate::authorization_servers::fapi_profile(&self.settings);
        matches!(profile.as_str(), "1-baseline" | "1-advanced")
    }

    /// `required()`: `oauth2.consentRequired`, or FAPI 1.0.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn required(&self) -> bool {
        self.settings.value_of("oauth2.consentRequired").as_bool()
            || self.fapi_v1()
    }

    /// `alwaysAsks(clientId)`: a public client that is not one of this
    /// service's own, where `oauth2.consentAlwaysForPublicClients` says so.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn always_asks(&self, client_id: &str) -> bool {
        if HOSTED.contains(&client_id)
            || !self
                .settings
                .value_of("oauth2.consentAlwaysForPublicClients")
                .as_bool()
        {
            return false;
        }
        let meta = self.clients.client_config_of(client_id);
        s(meta.get("token_endpoint_auth_method")) == "none"
    }

    /// `globalConsentsOf(clientId)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn global_consents_of(&self, client_id: &str) -> Vec<String> {
        self.clients.global_consents_of(client_id)
    }

    /// `consentsOf(username)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn consents_of(&self, username: &str) -> Vec<Agreed> {
        let key = self.identity_key_of(username);
        if key.is_empty() {
            return Vec::new();
        }
        self.directory
            .values_of(&key, USER_ATTRIBUTE)
            .unwrap_or_default()
            .iter()
            .filter_map(|v| Self::parse_consent_value(v))
            .collect()
    }

    /// `outstanding({ username, clientId, scope, all, answered })`: the
    /// rows of every scope asked, and those still needing an answer.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn outstanding(
        &self,
        username: &str,
        client_id: &str,
        scope: &str,
        all: bool,
        answered: bool,
    ) -> Outstanding {
        let client_id = client_id.trim();
        let wanted = Self::scopes_of(scope);
        let all = all || (!answered && self.always_asks(client_id));
        let global = if !self.fapi_v1() {
            self.global_consents_of(client_id)
        } else {
            Vec::new()
        };
        let held: Vec<Agreed> = self
            .consents_of(username)
            .into_iter()
            .filter(|one| one.client == client_id)
            .collect();
        let did_claim = matches!(
            self.settings.value_of("oauth2.didClaim"),
            sts_core::settings::SettingValue::Bool(true)
        );
        let rows: Vec<Json> = wanted
            .iter()
            .map(|scope| {
                let mine = held.iter().find(|one| &one.scope == scope);
                json!({
                    "scope": scope,
                    "consented": mine.is_some(),
                    "global": global.contains(scope),
                    "at": mine.map(|m| m.at.clone()).unwrap_or_default(),
                    "permission": self.clients.permission_row(scope)
                        .unwrap_or(Json::Null),
                    "releasesDid": scope == "did" && did_claim,
                    "signsIn": scope == SSO_SIGN_IN_SCOPE,
                })
            })
            .collect();
        // THE DEFAULT POLICY OF THE CONSENT STAGE (#305): a scope needs an
        // answer where nothing covers it — the person's own, a global
        // consent, or this request's spent Allow.
        let outstanding: Vec<Json> = rows
            .iter()
            .filter(|one| {
                all || !(one["consented"] == json!(true)
                    || one["global"] == json!(true)
                    || answered)
            })
            .cloned()
            .collect();
        Outstanding { rows, outstanding }
    }

    /// `record(username, clientId, scopes)`: one value per scope, one
    /// instant for the batch. `(stored, reason)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn record(
        &self,
        username: &str,
        client_id: &str,
        scopes: &[String],
    ) -> (bool, String) {
        let key = self.identity_key_of(username);
        let who = client_id.trim();
        let list: Vec<&String> =
            scopes.iter().filter(|s| !s.is_empty()).collect();
        if key.is_empty() || who.is_empty() || list.is_empty() {
            return (false, String::new());
        }
        let now = (self.now_ms)();
        let values: Vec<String> = list
            .iter()
            .map(|scope| Self::consent_value_of(scope, who, now))
            .collect();
        match self.directory.add_values(&key, USER_ATTRIBUTE, &values) {
            Ok(_) => {
                tracing::info!(
                    "consent: \"{}\" agreed that \"{}\" may ask for {} on \
                     their behalf. It is on their entry as {}, so the next \
                     sign-in does not ask.",
                    key,
                    who,
                    list.iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", "),
                    USER_ATTRIBUTE
                );
                (true, String::new())
            }
            Err(reason) => {
                tracing::warn!(
                    "{}ldap: \"{}\" has no entry in this realm, so the \
                     consent they gave was not recorded. They will be asked \
                     again. This is what ldap.autoCreateUsers being off \
                     looks like from the consent screen.",
                    sts_core::log::tag(codes::STS_LDAP_0040),
                    key
                );
                tracing::warn!(
                    "{}consent: \"{}\"'s consent for \"{}\" was not written \
                     down ({}).",
                    sts_core::log::tag(codes::STS_REG_0030),
                    key,
                    who,
                    reason
                );
                (false, reason)
            }
        }
    }

    /// `noteApplied(username, clientId, scopes)` (#537): the scopes a
    /// global consent answered, written the first time only.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn note_applied(
        &self,
        username: &str,
        client_id: &str,
        scopes: &[String],
    ) {
        let who = client_id.trim();
        let key = self.identity_key_of(username);
        let list: Vec<&String> =
            scopes.iter().filter(|s| !s.is_empty()).collect();
        if key.is_empty() || who.is_empty() || list.is_empty() {
            return;
        }
        let held: Vec<String> = self
            .directory
            .values_of(&key, APPLIED_ATTRIBUTE)
            .unwrap_or_default()
            .iter()
            .filter_map(|v| Self::parse_consent_value(v))
            .filter(|one| one.client == who)
            .map(|one| one.scope)
            .collect();
        let fresh: Vec<&String> =
            list.into_iter().filter(|s| !held.contains(s)).collect();
        if fresh.is_empty() {
            return;
        }
        let now = (self.now_ms)();
        let values: Vec<String> = fresh
            .iter()
            .map(|scope| Self::consent_value_of(scope, who, now))
            .collect();
        if let Err(reason) =
            self.directory.add_values(&key, APPLIED_ATTRIBUTE, &values)
        {
            tracing::warn!(
                "{}consent: the global consent \"{}\" carries for {} \
                 answered for \"{}\", and it could not be recorded on their \
                 entry ({}), so /portal/consents will not list it.",
                sts_core::log::tag(codes::STS_REG_0342),
                who,
                fresh
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
                key,
                reason
            );
        }
    }

    /// `scopeAnswerDigestOf(scope)`: `scope:` and the SHA-256, base64url,
    /// of the sorted, deduplicated scopes as JSON.
    #[tracing::instrument(level = "trace")]
    pub fn scope_answer_digest_of(scope: &str) -> String {
        let mut list: Vec<String> = Vec::new();
        for one in scope.split_whitespace() {
            if !list.iter().any(|l| l == one) {
                list.push(one.to_string());
            }
        }
        list.sort();
        let text = serde_json::to_string(&list).unwrap_or_default();
        let digest = sts_crypto::jws_alg::Hash::Sha256.digest(text.as_bytes());
        format!("scope:{}", sts_crypto::b64::encode(&digest))
    }

    fn answer_key(username: &str, client_id: &str, digest: &str) -> String {
        format!("{} {} {}", username, client_id, digest)
    }

    fn pending_ttl_ms(&self) -> f64 {
        let seconds = self.settings.value_of("authn.pendingTtlS").as_int();
        if seconds > 0 {
            (seconds as f64) * 1000.0
        } else {
            CONSENT_TTL_MS
        }
    }

    /// `noteConsented(username, clientId, digest, null)`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn note_consented(
        &self,
        username: &str,
        client_id: &str,
        digest: &str,
    ) {
        let now = (self.now_ms)();
        self.answers
            .in_realm(&sts_core::realm::current_id())
            .retain(|_, held| crate::js::to_number(&held["expires"]) >= now);
        self.answers.set(
            &Self::answer_key(username, client_id, digest),
            json!({ "expires": (now + self.pending_ttl_ms()) as i64,
                    "lowered": null }),
        );
    }

    /// `consumeConsented(username, clientId, digest)`: spent either way.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn consume_consented(
        &self,
        username: &str,
        client_id: &str,
        digest: &str,
    ) -> bool {
        let key = Self::answer_key(username, client_id, digest);
        let Some(held) = self.answers.get(&key) else {
            return false;
        };
        self.answers.delete(&key);
        crate::js::to_number(&held["expires"]) >= (self.now_ms)()
    }
}

/// `outstanding()`'s answer.
#[derive(Debug, Clone, Default)]
pub struct Outstanding {
    /// Every scope asked, with what covers it.
    pub rows: Vec<Json>,
    /// Those needing an answer.
    pub outstanding: Vec<Json>,
}

impl Outstanding {
    /// `names`: the outstanding scopes.
    #[tracing::instrument(level = "trace", skip(self))]
    pub fn names(&self) -> Vec<String> {
        self.outstanding.iter().map(|o| s(o.get("scope"))).collect()
    }
}

/// What an answer does (`consentAct()`).
#[derive(Debug, Clone, PartialEq)]
pub enum ActOutcome {
    /// Refused, the record left alone: 400, the sentence, the code.
    Refused { code: ErrorCode, why: String },
    /// Back to the authorization request: `target` (the record's
    /// `returnTo`, a refusal on `consent_error`), for `username`.
    Back {
        target: String,
        username: String,
        code: Option<ErrorCode>,
    },
}

/// The screen: the pending records, the three checks, the view and the
/// answer.
pub struct ConsentScreen {
    pub register: Arc<ConsentRegister>,
    pub pending: RealmMap<Json>,
    pub sign_on: Arc<dyn SignOn>,
    /// `authn.clientDisplay(clientId)` (#1300).
    pub client_display: Arc<dyn Fn(&str) -> Json + Send + Sync>,
    pub random_id: Arc<dyn Fn(usize) -> String + Send + Sync>,
}

impl ConsentScreen {
    /// Declares `consent_screen.pending` (before the store opens).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn declare_pending(
        lifecycle: &Arc<RealmLifecycle>,
        handles: &Arc<StoreHandles>,
    ) -> RealmMap<Json> {
        RealmMap::new(
            lifecycle,
            handles,
            StoreSpec {
                retain: Retain::Age,
                expires_at: Some(expiry_field(Some("expires"), 1.0)),
                ..StoreSpec::persisted("consent_screen.pending")
            },
        )
    }

    fn now(&self) -> f64 {
        (self.register.now_ms)()
    }

    /// `uiLocalesOf(returnTo)`.
    fn ui_locales_of(return_to: &str) -> String {
        let Some((_, query)) = return_to.split_once('?') else {
            return String::new();
        };
        crate::js::form_decode(query)
            .into_iter()
            .find(|(k, _)| k == "ui_locales")
            .map(|(_, v)| v)
            .unwrap_or_default()
    }

    /// `beginConsent(opts)`: mints the pending record and answers the
    /// path the browser is sent to. `Err` where `returnTo` is not a path
    /// on this service.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn begin(&self, info: &Json) -> Result<String, String> {
        let return_to = s(info.get("returnTo"));
        if !return_to.starts_with('/') || return_to.starts_with("//") {
            return Err(format!(
                "beginConsent() needs a path on this service to return to, \
                 not \"{}\".",
                return_to
            ));
        }
        let list = |name: &str| match info.get(name) {
            Some(Json::Array(a)) => Json::Array(a.clone()),
            _ => json!([]),
        };
        let client_id = s(info.get("clientId"));
        let client_name = match s(info.get("clientName")) {
            n if n.is_empty() => client_id.clone(),
            n => n,
        };
        let ui = match s(info.get("uiLocales")) {
            u if u.is_empty() => Self::ui_locales_of(&return_to),
            u => u,
        };
        let protocol = match s(info.get("protocol")) {
            p if p.is_empty() => "OAuth 2.0 / OIDC".to_string(),
            p => p,
        };
        let now = self.now();
        let id = (self.random_id)(18);
        let record = json!({
            "id": id,
            "returnTo": return_to,
            "username": s(info.get("username")),
            "clientId": client_id,
            "clientName": client_name,
            "scopes": list("scopes"),
            "resources": list("resources"),
            "already": list("already"),
            "details": list("details"),
            "authorizationDetails": list("authorizationDetails"),
            "detailsDigest": s(info.get("detailsDigest")),
            "scopeAnswerDigest": s(info.get("scopeAnswerDigest")),
            "rawAuthorizationDetails": list("rawAuthorizationDetails"),
            "protocol": protocol,
            "uiLocales": ui,
            "expires": (now + self.register.pending_ttl_ms()) as i64,
        });
        self.pending.set(&id, record.clone());
        self.pending
            .in_realm(&sts_core::realm::current_id())
            .retain(|_, v| crate::js::to_number(&v["expires"]) >= now);
        let names: Vec<String> = record["scopes"]
            .as_array()
            .map(|l| l.iter().map(|o| s(o.get("scope"))).collect())
            .unwrap_or_default();
        tracing::info!(
            "consent: \"{}\" is being asked whether \"{}\" may have {} on \
             their behalf. Nothing is issued until they answer; {} is where \
             they come back to.",
            s(record.get("username")),
            client_id,
            names.join(", "),
            return_to
        );
        Ok(format!(
            "{}?consent={}",
            CONSENT_PATH,
            crate::js::encode_uri_component(&id)
        ))
    }

    /// `pendingFor(id)`: the record, an expired one dropped.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn pending_for(&self, id: &str) -> Option<Json> {
        let record = self.pending.get(id)?;
        if crate::js::to_number(&record["expires"]) < self.now() {
            self.pending.delete(id);
            return None;
        }
        Some(record)
    }

    /// `consentIdentity(value)`.
    fn identity(&self, value: &str) -> String {
        self.register.identity_key_of(value)
    }

    /// `answeredBy(req, record)`: `Ok(who)`, or `Err((why, who))` with
    /// `why` `nosession` or `mismatch`.
    fn answered_by(
        &self,
        request: &Request,
        record: &Json,
    ) -> Result<String, (&'static str, String)> {
        self.sign_on
            .hint_account(request, &s(record.get("username")));
        let Some(session) = self.sign_on.session_of(request) else {
            return Err(("nosession", String::new()));
        };
        let here = self
            .identity(&s(session.get("user").and_then(|u| u.get("username"))));
        if here != self.identity(&s(record.get("username"))) {
            return Err(("mismatch", here));
        }
        Ok(here)
    }

    /// `claimForBrowser(id, sessionId, req)` (#1454): an unclaimed record is
    /// claimed only by the session of the person it was asked of.
    #[tracing::instrument(level = "debug", skip(self, request))]
    pub fn claim_for_browser(
        &self,
        id: &str,
        session_id: &str,
        request: &Request,
    ) -> bool {
        let Some(mut record) = self.pending.get(id) else {
            return true;
        };
        let held = s(record.get("browserSession"));
        if session_id.is_empty() {
            return held.is_empty();
        }
        if held.is_empty() {
            if self.answered_by(request, &record).is_err() {
                return false;
            }
            record["browserSession"] = json!(session_id);
            self.pending.set(id, record);
            return true;
        }
        held == session_id
    }

    /// `askedOf(req, id, answering)`: the record a request may see or
    /// answer, or the code and sentence of why not.
    #[tracing::instrument(level = "debug", skip(self, request))]
    pub fn asked_of(
        &self,
        request: &Request,
        id: &str,
        answering: bool,
    ) -> Result<Json, (ErrorCode, String)> {
        let Some(record) = self.pending_for(id) else {
            return Err((
                codes::STS_OAUTH_0149,
                if answering {
                    "This consent form has expired, or it has already been \
                     answered. Start the request again from the application \
                     that sent you here."
                } else {
                    "There is no consent waiting under that id, or it has \
                     expired. Start the request again from the application \
                     that sent you here — nothing was issued and nothing \
                     was recorded."
                }
                .to_string(),
            ));
        };
        match self.answered_by(request, &record) {
            Ok(_) => Ok(record),
            Err(("nosession", _)) => Err((
                codes::STS_OAUTH_0150,
                if answering {
                    "Nobody is signed in here any more, so this answer \
                     belongs to nobody. Nothing was recorded."
                } else {
                    "Nobody is signed in here any more, so there is nobody \
                     to record an answer for. Start the request again from \
                     the application that sent you here."
                }
                .to_string(),
            )),
            Err((_, who)) => {
                let asked = s(record.get("username"));
                Err((
                    codes::STS_OAUTH_0151,
                    if answering {
                        format!(
                            "This consent was asked of \"{}\" and this \
                             browser is signed in as \"{}\". Nothing was \
                             recorded.",
                            asked, who
                        )
                    } else {
                        format!(
                            "This consent was asked of \"{}\" and the \
                             session in this browser belongs to \"{}\". It \
                             is refused rather than recorded against \
                             whoever happens to be signed in, which is the \
                             one failure at this door that would write \
                             something untrue into the directory.",
                            asked, who
                        )
                    },
                ))
            }
        }
    }

    /// `consentView(req, record)`: every fact the page is drawn from.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn view(&self, base: &str, record: &Json) -> Json {
        let client_id = s(record.get("clientId"));
        let arr = |name: &str| {
            record
                .get(name)
                .and_then(Json::as_array)
                .cloned()
                .unwrap_or_default()
        };
        let ttl = self
            .register
            .clients
            .setting_for(&client_id, "oauth2.refreshTokenTtlS")
            .map(|v| crate::js::to_number(&v))
            .unwrap_or_else(|| {
                self.register
                    .settings
                    .value_of("oauth2.refreshTokenTtlS")
                    .as_int() as f64
            });
        let scopes: Vec<Json> = arr("scopes")
            .iter()
            .map(|one| {
                let p = one.get("permission").filter(|p| p.is_object());
                let or_empty = |v: Option<&Json>| match v {
                    None | Some(Json::Null) => json!(""),
                    Some(Json::String(t)) if t.is_empty() => json!(""),
                    Some(x) => x.clone(),
                };
                json!({
                    "scope": s(one.get("scope")),
                    "permission": p.map(|p| json!({
                        "description": or_empty(p.get("description")),
                        "name": or_empty(p.get("name")),
                        "identifier": or_empty(p.get("identifier")),
                        "baseUri": or_empty(p.get("baseUri")),
                    })).unwrap_or(Json::Null),
                    "releasesDid": one.get("releasesDid") == Some(&json!(true)),
                    "signsIn": one.get("signsIn") == Some(&json!(true)),
                })
            })
            .collect();
        let already: Vec<Json> = arr("already")
            .iter()
            .map(|one| {
                json!({
                    "scope": s(one.get("scope")),
                    "global": crate::js::truthy(one.get("global")),
                    "at": s(one.get("at")),
                })
            })
            .collect();
        let details: Vec<Json> = arr("details")
            .iter()
            .map(|d| {
                json!({
                    "label": s(d.get("label")),
                    "value": s(d.get("value")),
                    "note": if crate::js::truthy(d.get("note")) {
                        s(d.get("note"))
                    } else {
                        String::new()
                    },
                })
            })
            .collect();
        json!({
            "consent": true,
            "username": s(record.get("username")),
            "base": base,
            "client": { "id": client_id,
                        "name": s(record.get("clientName")) },
            "clientDisplay": (self.client_display)(&client_id),
            "resources": record.get("resources").cloned()
                .unwrap_or(json!([])),
            "lifetimeHours": (ttl / 3600.0).round() as i64,
            "scopes": scopes,
            "authorizationDetails": [],
            "already": already,
            "limits": [],
            "attribute": USER_ATTRIBUTE,
            "protocol": s(record.get("protocol")),
            "details": details,
        })
    }

    /// `consentAct(req, res, id, body)`: Allow or Deny, the record spent
    /// either way, before anything is written.
    #[tracing::instrument(level = "debug", skip(self, request))]
    pub fn act(&self, request: &Request, id: &str, action: &str) -> ActOutcome {
        let record = match self.asked_of(request, id, true) {
            Ok(r) => r,
            Err((code, why)) => return ActOutcome::Refused { code, why },
        };
        self.pending.delete(&s(record.get("id")));
        let username = s(record.get("username"));
        let client_id = s(record.get("clientId"));
        let scopes: Vec<String> = record["scopes"]
            .as_array()
            .map(|l| l.iter().map(|o| s(o.get("scope"))).collect())
            .unwrap_or_default();
        let return_to = s(record.get("returnTo"));
        if action != "allow" {
            let row = json!({
                "action": "consent.deny",
                "actor": username,
                "target": client_id,
                "protocol": "OAuth 2.0 / OIDC",
                "channel": "http",
                "outcome": "refused",
                "errorCode": codes::STS_OAUTH_0152.as_str(),
                "detail": format!("refused {}", scopes.join(", ")),
            });
            if !sts_http::call_log::audit(&row) {
                tracing::info!(
                    "{}audit: {}",
                    sts_core::log::tag(codes::STS_OAUTH_0152),
                    row
                );
            }
            tracing::info!(
                "consent: \"{}\" refused \"{}\" the scope(s) {}. Nothing was \
                 recorded and nothing was issued; the client is told \
                 access_denied.",
                username,
                client_id,
                scopes.join(", ")
            );
            let sep = if return_to.contains('?') { '&' } else { '?' };
            let target = format!(
                "{}{}consent_error={}&consent_error_description={}",
                return_to,
                sep,
                crate::js::encode_uri_component("access_denied"),
                crate::js::encode_uri_component(&format!(
                    "The user did not consent to {}.",
                    scopes.join(" ")
                ))
            );
            return ActOutcome::Back {
                target,
                username,
                code: Some(codes::STS_OAUTH_0152),
            };
        }
        let digest = s(record.get("scopeAnswerDigest"));
        if !digest.is_empty() {
            self.register.note_consented(&username, &client_id, &digest);
        }
        let (stored, reason) =
            self.register.record(&username, &client_id, &scopes);
        let protocol = match s(record.get("protocol")) {
            p if p.is_empty() => "OAuth 2.0 / OIDC".to_string(),
            p => p,
        };
        let detail = format!(
            "consented {}{}",
            scopes.join(", "),
            if stored {
                String::new()
            } else {
                format!(
                    " (not written down: {}, so they will be asked again)",
                    if reason.is_empty() {
                        "no entry"
                    } else {
                        &reason
                    }
                )
            }
        );
        let row = json!({
            "action": "consent.grant",
            "actor": username,
            "target": client_id,
            "protocol": protocol,
            "channel": "http",
            "outcome": if stored { "success" } else { "warning" },
            "detail": detail,
        });
        if !sts_http::call_log::audit(&row) {
            tracing::info!("audit: {}", row);
        }
        ActOutcome::Back {
            target: return_to,
            username,
            code: None,
        }
    }
}
