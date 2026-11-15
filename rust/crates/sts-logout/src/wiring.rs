// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE COMPOSITION ROOT'S ONE CALL (`common/protocol_stack.ts`'s `23a`,
//! second to last): the sign-out built over what the runtime holds, its
//! routes, and the `/authn-api` door's page operations filled.
//!
//! WHAT EACH PORT IS ANSWERED WITH TODAY, and who fills it later:
//!
//! * the SESSION is `sts-authn`'s `Sessions` ([`SessionsPort`]) — every
//!   end through `end_session_by_id()`, so the RFC 9700 refresh rule, the
//!   product revocation of the session's access tokens (#1449), CAEP and
//!   the audit row are the session core's, exactly as in Node;
//! * the TOKENS are `sts-oauth`'s register where the runtime holds one
//!   ([`TokensPort`]): listed by holder, revoked into the ONE revocation
//!   set; the artifact register (assertions, tickets, SVIDs — the identity
//!   register's slice) holds nothing here yet;
//! * every other family answers as Node answers where that family has
//!   nothing configured ([`Unported`]): no relying party can be notified
//!   (the front-channel targets and the Logout Tokens are the OAuth
//!   slice's, part two; WS-Federation, SAML and federation are their
//!   phases'), no code, no pre-authorized code, no wallet row, no GNAP or
//!   OAuth grant, no PCT, no directory connection, and a KDC that knows
//!   no principal. A family with nothing configured lists nothing, so the
//!   page says what the runtime can see — and a row Node wrote for one of
//!   them (an `oidcClients` member on a session) ends with its session.

use std::sync::Arc;

use serde_json::{json, Map, Value};
use sts_authn::ports::{People, Request, Response};
use sts_authn::Sessions;
use sts_core::mode::Mode;
use sts_core::realm::RealmRegistry;
use sts_core::settings::{SettingValue, Settings};

use crate::door::{SignOutDoor, SignOutPages};
use crate::js::{or_empty, string_of, truthy};
use crate::logout::{Logout, LogoutDeps};
use crate::ports::*;

/// A setting as Node's `config.value()` answers it.
fn json_of(value: SettingValue) -> Value {
    match value {
        SettingValue::Text(t) => Value::String(t),
        SettingValue::Int(n) => json!(n),
        SettingValue::Bool(b) => Value::Bool(b),
        SettingValue::List(l) => json!(l),
    }
}

fn now_ms() -> f64 {
    chrono::Utc::now().timestamp_millis() as f64
}

/// The session core's request, with the door's.
fn request_of(asked: &Asked) -> &Request {
    &asked.request
}

fn into_reply(reply: &mut Reply, response: Response) {
    reply.cookies.extend(response.cookies);
}

/// `authn/authn.ts`, over `sts-authn`'s `Sessions`.
pub struct SessionsPort {
    pub sessions: Arc<Sessions>,
    pub begin: Arc<dyn Fn(&Value) -> String + Send + Sync>,
}

impl AuthnPort for SessionsPort {
    // The session window (#350) is not in this runtime: every session is
    // in the one in-memory map, so the walk is the read.
    fn session_window_on(&self) -> bool {
        false
    }

    fn sessions_held_under(
        &self,
        username: &str,
        subject: &str,
    ) -> Option<Vec<Value>> {
        Some(
            self.sessions
                .store()
                .entries()
                .into_iter()
                .map(|(_, v)| v)
                .filter(|s| {
                    let user = s.get("user");
                    or_empty(user.and_then(|u| u.get("username"))) == username
                        || (!subject.is_empty()
                            && or_empty(user.and_then(|u| u.get("sub")))
                                == subject)
                })
                .collect(),
        )
    }

    fn sessions_matching(&self) -> Option<Vec<Value>> {
        let now = now_ms();
        Some(
            self.sessions
                .store()
                .entries()
                .into_iter()
                .map(|(_, v)| v)
                .filter(|s| {
                    self.sessions.session_ended(Some(s), now).is_empty()
                })
                .collect(),
        )
    }

    fn session_by_id(&self, id: &str) -> Option<Value> {
        self.sessions.session_by_id(id)
    }

    fn session_view(&self, session: &Value) -> Value {
        let view = sts_authn::record::view(session.as_object());
        serde_json::to_value(view).unwrap_or(Value::Null)
    }

    fn session_started_at(&self, session: &Value) -> f64 {
        self.sessions.session_started_at(session) as f64
    }

    fn end_session_by_id(&self, id: &str, via: &str, entity: &str) -> bool {
        self.sessions.end_session_by_id(id, via, entity).is_some()
    }

    fn note_session_changed(&self, session: &Value) {
        let sid = string_of(session.get("id"));
        let replacement = session.as_object().cloned().unwrap_or_default();
        if !self
            .sessions
            .note_session_changed(&sid, |o| *o = replacement)
        {
            tracing::debug!("logout: the session {} had gone.", sid);
        }
    }

    fn rewrite_session(&self, session: &Value) {
        self.note_session_changed(session);
    }

    fn multiple_accounts(&self) -> bool {
        self.sessions.multiple_accounts()
    }

    fn hint_account_key(&self, asked: &Asked, key: &str) {
        self.sessions.hint_account_key(request_of(asked), key);
    }

    fn hint_account(&self, asked: &Asked, hint: &Value) {
        self.sessions.hint_account(request_of(asked), hint);
    }

    fn session_of(&self, asked: &Asked) -> Option<Value> {
        self.sessions.session_of(request_of(asked), false)
    }

    fn signed_in_accounts(&self, asked: &Asked) -> Vec<Value> {
        self.sessions.signed_in_accounts(request_of(asked))
    }

    fn after_account_sign_out(&self, asked: &Asked, reply: &mut Reply) {
        let mut response = Response::default();
        let _moved = self
            .sessions
            .after_account_sign_out(request_of(asked), &mut response);
        into_reply(reply, response);
    }

    fn clear_session_cookie(&self, reply: &mut Reply) {
        let mut response = Response::default();
        self.sessions.clear_session_cookie(&mut response, "");
        into_reply(reply, response);
    }

    fn clear_site_data_after_sign_out(&self, asked: &Asked, reply: &mut Reply) {
        if self
            .sessions
            .clear_site_data_after_sign_out(request_of(asked))
        {
            reply
                .headers
                .push(("clear-site-data".into(), "\"storage\"".into()));
        }
    }

    fn arrival(&self, asked: &Asked, reply: &mut Reply) {
        let request = request_of(asked);
        self.sessions.touch_arrival_session(request);
        if self
            .sessions
            .cookie_session(Some(request), "sts_session")
            .is_some()
        {
            return;
        }
        let mut response = Response::default();
        if self
            .sessions
            .start_arrival_session(request, &mut response, "arrival")
            .is_none()
        {
            tracing::debug!("logout: no arrival session was started.");
        }
        into_reply(reply, response);
    }

    fn begin_authentication(
        &self,
        opts: &Value,
        _asked: Option<&Asked>,
    ) -> String {
        (self.begin)(opts)
    }

    fn last_authenticated_at(&self, session: &Value) -> f64 {
        sts_authn::record::last_authenticated_at(session.as_object()) as f64
    }

    fn session_names_factor(&self, session: &Value, factor: &Value) -> bool {
        let kind = or_empty(factor.get("kind"));
        let print = if kind == "webauthn" {
            credential_fingerprint(&or_empty(factor.get("credentialId")))
        } else {
            String::new()
        };
        if kind.is_empty() || (kind == "webauthn" && print.is_empty()) {
            return false;
        }
        let events = session
            .get("events")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        events.iter().any(|event| {
            let given = event
                .get("context")
                .and_then(|c| c.get("credential"))
                .cloned()
                .unwrap_or(Value::Null);
            let was = or_empty(given.get("kind"));
            match kind.as_str() {
                "webauthn" => {
                    was == "webauthn"
                        && or_empty(given.get("fingerprint")) == print
                }
                "email" => {
                    was.starts_with("email-")
                        && event
                            .get("amr")
                            .and_then(Value::as_array)
                            .is_some_and(|a| a.len() > 1)
                }
                _ => was == kind,
            }
        })
    }
}

/// `credentialFingerprint(id)`: base64url of its SHA-256.
fn credential_fingerprint(identifier: &str) -> String {
    if identifier.is_empty() {
        return String::new();
    }
    sts_crypto::b64::encode(
        &sts_crypto::jws_alg::Hash::Sha256.digest(identifier.as_bytes()),
    )
}

/// `identityOf(value).key` (`common/admin_stats.js`): a `urn:uuid:` subject
/// is its person's name where it resolves; a realm-qualified name is the
/// name; a DN or a DID is itself.
pub struct IdentityKeys {
    pub people: Arc<dyn People>,
}

impl IdentityKeys {
    fn of(&self, value: &str) -> (String, bool) {
        let text = value.trim();
        if text.is_empty() {
            return (String::new(), false);
        }
        let rest = text.strip_prefix("urn:sts:user:").unwrap_or(text);
        if rest.len() >= 9 && rest[..9].eq_ignore_ascii_case("urn:uuid:") {
            let named = self.people.name_for_subject(rest);
            if named.is_empty() {
                return (rest.to_string(), true);
            }
            return (named, false);
        }
        let dn = {
            let mut c = rest.chars();
            matches!(c.next(), Some(ch) if ch.is_ascii_alphabetic())
                && rest.split_once('=').is_some_and(|(n, _)| {
                    n.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
                })
        };
        let did = rest.len() > 4
            && rest[..4].eq_ignore_ascii_case("did:")
            && rest[4..].split_once(':').is_some_and(|(m, _)| {
                !m.is_empty() && m.chars().all(|c| c.is_ascii_alphanumeric())
            });
        if !dn && !did {
            if let Some(at) = rest.rfind('@').filter(|a| *a > 0) {
                return (rest[..at].to_string(), false);
            }
        }
        (rest.to_string(), false)
    }

    /// `identityKeyOf(value)`.
    // A hot path: once per row and per record; no span.
    pub fn key_of(&self, value: &str) -> String {
        self.of(value).0
    }

    /// `holderKeyOf(username, sub)`.
    // A hot path: once per row and per record; no span.
    pub fn holder_key_of(&self, username: &str, sub: &str) -> String {
        if sub.len() >= 9 && sub[..9].eq_ignore_ascii_case("urn:uuid:") {
            let (key, unresolved) = self.of(sub);
            if !key.is_empty() && !unresolved {
                return key;
            }
        }
        self.key_of(if username.is_empty() { sub } else { username })
    }
}

/// `common/admin_stats.js` over `sts-oauth`'s token register.
pub struct TokensPort {
    pub keys: IdentityKeys,
    pub register: Option<Arc<sts_oauth::minted::TokenRegister>>,
    pub settings: Arc<Settings>,
}

impl TokensPort {
    /// `tokenStateOf(record, now)`.
    fn state_of(&self, record: &Value, now: f64) -> &'static str {
        let skew = self.settings.value_of("oauth2.clockSkewS").as_int() as f64
            * 1000.0;
        let exp = crate::js::number_or_zero(record.get("exp"));
        let nbf = crate::js::number_or_zero(record.get("nbf"));
        if truthy(record.get("revoked")) {
            return "revoked";
        }
        if exp != 0.0 && exp * 1000.0 + skew <= now {
            return "expired";
        }
        if nbf != 0.0 && nbf * 1000.0 - skew > now {
            return "not yet valid";
        }
        if exp == 0.0 {
            return "no expiry stated";
        }
        "valid"
    }
}

impl StatsPort for TokensPort {
    fn holder_key_of(&self, username: &Value, sub: &Value) -> String {
        self.keys
            .holder_key_of(&or_empty(Some(username)), &or_empty(Some(sub)))
    }

    fn identity_key_of(&self, name: &str) -> String {
        self.keys.key_of(name)
    }

    fn holdings_of(&self, keys: &[String]) -> Map<String, Value> {
        let mut out = Map::new();
        for k in keys {
            out.insert(k.clone(), json!({ "tokens": [], "artifacts": [] }));
        }
        let Some(register) = &self.register else {
            return out;
        };
        // THE REGISTER'S ROWS, READ THROUGH ITS ONE WALK: `revoke_where()`
        // hands its predicate every revocable, unrevoked row — the only
        // rows the `token` family lists — and a predicate that answers
        // false revokes none of them. `sts-oauth` offers no listing of its
        // own yet (the OAuth slice's, part two).
        let seen = std::sync::Mutex::new(Vec::new());
        {
            let collect = |record: &Value| -> bool {
                if let Ok(mut s) = seen.lock() {
                    s.push(record.clone());
                }
                false
            };
            let realm = sts_core::realm::current_id();
            let none =
                register.revoke_where(&realm, &collect, "", now_ms() as i64);
            debug_assert_eq!(none, 0);
        }
        let rows = seen.into_inner().unwrap_or_default();
        let now = now_ms();
        for record in rows {
            let key = self.holder_key_of(
                record.get("username").unwrap_or(&Value::Null),
                record.get("sub").unwrap_or(&Value::Null),
            );
            if let Some(held) = out.get_mut(&key) {
                let mut row = Map::new();
                row.insert("state".into(), json!(self.state_of(&record, now)));
                if let Value::Object(o) = &record {
                    for (k, v) in o {
                        row.insert(k.clone(), v.clone());
                    }
                }
                if let Some(Value::Array(list)) = held.get_mut("tokens") {
                    list.push(Value::Object(row));
                }
            }
        }
        out
    }

    fn revoke(&self, jti: &str, why: &str, _opts: &Value) -> bool {
        match &self.register {
            Some(r) => r.revoke(
                &sts_core::realm::current_id(),
                jti,
                why,
                false,
                now_ms() as i64,
            ),
            None => false,
        }
    }

    // The artifact register (assertions, tickets, SVIDs, credentials) is
    // the identity register's, not in this runtime: nothing is listed, so
    // nothing is asked for by key.
    fn artifact_by_key(&self, _key: &str) -> Option<Value> {
        None
    }

    fn revoke_artifact(&self, _record: &Value, _why: &str) -> bool {
        false
    }
}

/// The families not in this runtime yet, answered as Node answers where
/// each has nothing configured.
pub struct Unported {
    pub settings: Arc<Settings>,
}

impl FrontChannelPort for Unported {
    // What rides on the session is read from it, so the row says so.
    fn clients_of(&self, session: &Value) -> Vec<Value> {
        session
            .get("oidcClients")
            .and_then(Value::as_object)
            .map(|o| o.keys().map(|k| json!(k)).collect())
            .unwrap_or_default()
    }

    fn notifications_for(&self, _session: &Value, _issuer: &str) -> Vec<Value> {
        Vec::new()
    }

    fn render(&self, _notifications: &[Value]) -> String {
        String::new()
    }

    fn frame_origins_of(&self, _notifications: &[Value]) -> Vec<String> {
        Vec::new()
    }
}

impl BackchannelPort for Unported {
    fn mark(&self) -> Value {
        Value::Null
    }

    fn plan(&self, _session: &Value, _opts: &Value) -> Vec<Value> {
        Vec::new()
    }

    fn dispatch(&self, _planned: &[Value]) {}

    fn deliveries_for(&self, _ids: &[String], _mark: &Value) -> Vec<Value> {
        Vec::new()
    }

    fn summarize(&self, _rows: &[Value]) -> String {
        String::new()
    }

    fn render(&self, _rows: &[Value]) -> String {
        String::new()
    }
}

impl WsFedPort for Unported {
    fn cleanup_targets_for(&self, _session: &Value) -> Vec<Value> {
        Vec::new()
    }
}

impl Saml2Port for Unported {
    fn logout_targets_for(&self, _session: &Value) -> Vec<Value> {
        Vec::new()
    }
}

impl FederationSloPort for Unported {
    fn can_tell_partner(&self, _held: &Value) -> Value {
        json!({ "ok": false,
                "why": "this runtime has no federation sign-out yet" })
    }

    fn partner_logout_for(&self, _session: &Value, _base: &str) -> Value {
        json!({ "ok": false,
                "why": "this runtime has no federation sign-out yet" })
    }

    fn render_partner_logouts(&self, _targets: &[Value]) -> String {
        String::new()
    }
}

impl OAuth2Port for Unported {
    fn outstanding_codes_for(&self, _key: &str) -> Vec<Value> {
        Vec::new()
    }

    fn drop_code(&self, _code: &str) {}

    // The default authorization server's issuer is the realm's base.
    fn issuer_of(&self, base: &str) -> String {
        base.to_string()
    }
}

impl Oid4vcPort for Unported {
    fn pre_authorized_codes(&self) -> Vec<(String, Value)> {
        Vec::new()
    }

    fn delete_pre_authorized_code(&self, _digest: &str) {}

    fn sign_ins_awaiting_collection(&self) -> Vec<Value> {
        Vec::new()
    }

    fn withdraw_sign_in(&self, _state: &str, _why: &str) -> bool {
        false
    }

    fn rows_for_subject(&self, _subject: &str) -> Vec<Value> {
        Vec::new()
    }

    fn disown(&self, _key: &str, _why: &str) -> bool {
        false
    }
}

impl Krb5Port for Unported {
    fn realm(&self) -> String {
        self.settings.value_of("krb5.realm").as_str().to_string()
    }

    fn kerberos_realm_of(&self) -> Value {
        json!({ "enabled": self.settings.value_of("krb5.enabled").as_bool() })
    }

    fn signed_out_at(&self, _names: &[String], _realm: &str) -> Value {
        Value::Null
    }

    fn find(&self, _names: &[String], _realm: &str) -> Value {
        Value::Null
    }

    fn sign_out(&self, _names: &[String], _realm: &str) -> Value {
        Value::Null
    }
}

impl LdapPort for Unported {
    fn bound_connections(&self) -> Vec<Value> {
        Vec::new()
    }

    fn drop_connections_for(&self, _key: &str) -> Vec<Value> {
        Vec::new()
    }

    fn sign_out_across_cluster(&self, _key: &str) -> Value {
        Value::Null
    }
}

impl GnapPort for Unported {
    fn grants_by_key(&self, keys: &[String]) -> Map<String, Value> {
        keys.iter().map(|k| (k.clone(), json!([]))).collect()
    }

    fn is_live(&self, _grant: &Value) -> bool {
        false
    }

    fn grants_held_by(&self, _key: &str) -> Vec<Value> {
        Vec::new()
    }

    fn live_tokens_of(&self, _grant: &Value) -> Vec<Value> {
        Vec::new()
    }

    fn end_grant(&self, _grant: &Value, _opts: &Value) -> bool {
        false
    }
}

impl GrantsPort for Unported {
    fn list(&self) -> Vec<Value> {
        Vec::new()
    }

    fn revoke(&self, _id: &str, _key: &str, _by: &str, _entity: &str) -> Value {
        json!({ "ok": false })
    }
}

impl UmaPort for Unported {
    fn pcts_of(&self, _subject: &str) -> Vec<Value> {
        Vec::new()
    }

    fn delete_pct(&self, _key: &str) -> bool {
        false
    }
}

/// The settings, the mode, the realm, the directory's resolver, the
/// secret, the clock.
pub struct Host {
    pub settings: Arc<Settings>,
    pub mode: Arc<Mode>,
    pub registry: Arc<RealmRegistry>,
    pub people: Arc<dyn People>,
    pub secret: Vec<u8>,
}

impl HostPort for Host {
    fn setting(&self, key: &str) -> Value {
        json_of(self.settings.value_of(key))
    }

    fn opens_test_controls(&self) -> bool {
        self.mode.opens_test_controls()
    }

    fn verifies_credentials(&self) -> bool {
        self.mode.verifies_credentials()
    }

    // `sts-audit` is not in the runtime yet: the row goes to the log, as
    // the sign-in surface's do.
    fn audit(&self, row: &Value) {
        tracing::info!("audit: {}", row);
    }

    fn audit_failure(&self, code: &str, row: &Value) {
        tracing::info!("audit: {} {}", code, row);
    }

    fn subject_for_name(&self, name: &str) -> String {
        self.people.subject_for_name(name)
    }

    fn name_for_subject(&self, subject: &str) -> String {
        self.people.name_for_subject(subject)
    }

    fn result_secret(&self) -> Vec<u8> {
        self.secret.clone()
    }

    // One cell: a no-op, as Node's is in single-cell mode.
    fn subject_terminated(&self, _realm: &str, _key: &str) {}

    // No OpenID Provider Commands are configured in this runtime.
    fn person_signed_out(&self, _key: &str) {}

    fn realm_id(&self) -> String {
        sts_core::realm::current_id()
    }

    fn realm_prefix(&self) -> String {
        self.registry.current_prefix()
    }

    fn now_ms(&self) -> f64 {
        now_ms()
    }
}

/// The `logout-result` cluster secret (`cluster/cluster_secrets.ts`): the
/// environment's `STS_LOGOUT_RESULT_SECRET`, or 32 random bytes made for
/// this process, as text whose UTF-8 is the key.
fn result_secret() -> Vec<u8> {
    if let Ok(text) = std::env::var("STS_LOGOUT_RESULT_SECRET") {
        if !text.is_empty() {
            return text.into_bytes();
        }
    }
    let bytes = sts_crypto::random::random_bytes(32).unwrap_or_default();
    sts_crypto::b64::encode(&bytes).into_bytes()
}

/// What the composition root hands [`LogoutStack::build`].
pub struct LogoutParts {
    pub settings: Arc<Settings>,
    pub mode: Arc<Mode>,
    pub registry: Arc<RealmRegistry>,
    pub sessions: Arc<Sessions>,
    pub people: Arc<dyn People>,
    pub tokens: Option<Arc<sts_oauth::minted::TokenRegister>>,
    /// The sign-in surface's pending store, which `beginAuthentication()`
    /// writes a sign-in into.
    pub pending: sts_core::realm_store::RealmMap<Value>,
    pub http: Arc<sts_http::HttpLayer>,
    pub surfaces: Arc<sts_http::surfaces::SurfaceHost>,
}

/// The sign-out, built.
pub struct LogoutStack {
    pub logout: Arc<Logout>,
    pub door: Arc<SignOutDoor>,
}

/// `beginAuthentication(opts)` for a sign-out's sign-in: the pending
/// record of a sign-in no application asked for — the password screen,
/// nothing narrowed, no federation (`beginAuthenticationHere()` with no
/// application) — and the screen's address. Member for member the record
/// Node's own writes for `/logout` (probed in the tests image: `restart`
/// null, `mechanismSource` `default`, `federation` null), so the
/// unchanged sign-in bundle draws its screen. The authentication
/// policy's per-application mechanisms (`mechanismFor()`), which an
/// application-less sign-in never consults, are the policy slice's.
fn begin_with(
    pending: sts_core::realm_store::RealmMap<Value>,
    settings: Arc<Settings>,
) -> Arc<dyn Fn(&Value) -> String + Send + Sync> {
    Arc::new(move |opts: &Value| {
        let bytes = sts_crypto::random::random_bytes(18).unwrap_or_default();
        let id = sts_crypto::b64::encode(&bytes);
        let ttl = settings.value_of("authn.pendingTtlS").as_int().max(1) as f64
            * 1000.0;
        let record = json!({
            "id": id,
            "restart": null,
            "returnTo": opts.get("returnTo"),
            "details": opts.get("details").cloned().unwrap_or(json!([])),
            "hint": or_empty(opts.get("hint")),
            "lockedUsername": "",
            "allowedMechanisms": [],
            "forceMfa": false,
            "forceKey": false,
            "phishingClass": "",
            "forcePasswordless": false,
            "integrated": false,
            "walletDoor": false,
            "mechanism": "password",
            "mechanismSource": "default",
            "mechanismVia": "",
            "mechanismProblem": "",
            "protocol": or_empty(opts.get("protocol")),
            "application": "",
            "uiLocales": "",
            "reauthentication": "",
            "federation": null,
            "expires": crate::js::num(now_ms() + ttl),
        });
        pending.set(&id, record);
        format!(
            "/authn/login?authn={}",
            crate::js::encode_uri_component(&id)
        )
    })
}

impl LogoutStack {
    /// Builds the sign-out over the runtime's parts.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn build(parts: LogoutParts) -> LogoutStack {
        let unported = Arc::new(Unported {
            settings: parts.settings.clone(),
        });
        let deps = LogoutDeps {
            authn: Arc::new(SessionsPort {
                sessions: parts.sessions.clone(),
                begin: begin_with(
                    parts.pending.clone(),
                    parts.settings.clone(),
                ),
            }),
            stats: Arc::new(TokensPort {
                keys: IdentityKeys {
                    people: parts.people.clone(),
                },
                register: parts.tokens.clone(),
                settings: parts.settings.clone(),
            }),
            frontchannel: unported.clone(),
            backchannel: unported.clone(),
            wsfed: unported.clone(),
            saml2: unported.clone(),
            federation_slo: unported.clone(),
            oauth2: unported.clone(),
            oid4vc: unported.clone(),
            krb5: unported.clone(),
            ldap: unported.clone(),
            gnap: unported.clone(),
            grants: unported.clone(),
            uma: unported,
            host: Arc::new(Host {
                settings: parts.settings.clone(),
                mode: parts.mode.clone(),
                registry: parts.registry.clone(),
                people: parts.people.clone(),
                secret: result_secret(),
            }),
        };
        let logout = Arc::new(Logout::new(deps));
        let door = Arc::new(SignOutDoor {
            logout: logout.clone(),
            surfaces: parts.surfaces,
            http: parts.http,
            settings: parts.settings,
        });
        LogoutStack { logout, door }
    }

    /// Fills the `/authn-api` door's page operations and answers the
    /// router to merge.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn mount(&self, api: &sts_authn_api::door::AuthnApi) -> axum::Router {
        api.set_sign_out(Arc::new(SignOutPages {
            logout: self.logout.clone(),
        }));
        self.door.router()
    }
}
