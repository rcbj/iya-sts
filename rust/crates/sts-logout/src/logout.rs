// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! `Logout` (`logout/logout.ts`): THE MODEL — one row per live thing, read
//! from its owner — the inventory, the termination in ending order, the
//! batch forms, and the narrower doors over it (a person's grants, the
//! sessions a removed credential signed in, a partner's or a bound
//! session's end).
//!
//! **IT HOLDS NO STATE OF ITS OWN (rule 3m).** Node's `this.index` — one
//! read of the big stores for a whole set of people, alive only for the
//! synchronous call that built it — is an [`Index`] passed down that call
//! here, so two requests on two tasks can never see each other's.
//!
//! Every port is called in Node's order with Node's arguments; that is
//! what `tests/node_vectors.rs` holds it to.

use std::collections::HashSet;
use std::sync::Arc;

use serde_json::{json, Map, Value};
use sts_core::errors::codes;

use crate::families::{self, Family, FAMILIES};
use crate::js::{self, concat, num, number_or_zero, or_empty, text, truthy};
use crate::js::{put, slice16, string_of, Object};
use crate::ports::*;

/// Every port the sign-out reads and ends through.
#[derive(Clone)]
pub struct LogoutDeps {
    pub authn: Arc<dyn AuthnPort>,
    pub stats: Arc<dyn StatsPort>,
    pub frontchannel: Arc<dyn FrontChannelPort>,
    pub backchannel: Arc<dyn BackchannelPort>,
    pub wsfed: Arc<dyn WsFedPort>,
    pub saml2: Arc<dyn Saml2Port>,
    pub federation_slo: Arc<dyn FederationSloPort>,
    pub oauth2: Arc<dyn OAuth2Port>,
    pub oid4vc: Arc<dyn Oid4vcPort>,
    pub krb5: Arc<dyn Krb5Port>,
    pub ldap: Arc<dyn LdapPort>,
    pub gnap: Arc<dyn GnapPort>,
    pub grants: Arc<dyn GrantsPort>,
    pub uma: Arc<dyn UmaPort>,
    pub host: Arc<dyn HostPort>,
}

/// `withIndex()`'s index: each big store read once for a set of keys.
#[derive(Debug, Clone, Default)]
pub struct Index {
    keys: HashSet<String>,
    sessions: Map<String, Value>,
    holdings: Map<String, Value>,
    wallet: Map<String, Value>,
    gnap: Map<String, Value>,
    oauth_grants: Map<String, Value>,
}

impl Index {
    fn covers(&self, key: &str) -> bool {
        self.keys.contains(key)
    }
}

/// `contextFor()`: what every collector and termination is handed, built
/// once per act so no two families disagree about what is live.
#[derive(Debug, Clone, Default)]
pub struct Ctx {
    pub key: String,
    pub sessions: Vec<Value>,
    pub issuer: String,
    pub by: String,
    pub initiating_entity: String,
    pub notifications: Vec<Value>,
    pub cleanups: Vec<Value>,
    pub logout_requests: Vec<Value>,
    pub partner_logouts: Vec<Value>,
    pub base: String,
    pub browser: bool,
    pub ending_sessions: HashSet<String>,
    holdings: Option<Value>,
    oauth_grants: Option<Vec<Value>>,
    index: Option<Arc<Index>>,
}

/// `terminate()`'s options.
#[derive(Debug, Clone, Default)]
pub struct TerminateOptions {
    pub issuer: String,
    pub by: String,
    pub actor: String,
    pub initiating_entity: String,
    pub channel: String,
    pub base: String,
    pub browser: bool,
    /// `providerCommand: false`.
    pub no_provider_command: bool,
    pub spare_credentials: bool,
    pub quiet: bool,
}

/// One family's `terminate()` answer.
struct Outcome {
    ok: bool,
    message: String,
    pending: bool,
}

fn ok(message: String) -> Outcome {
    Outcome {
        ok: true,
        message,
        pending: false,
    }
}

fn no(message: impl Into<String>) -> Outcome {
    Outcome {
        ok: false,
        message: message.into(),
        pending: false,
    }
}

/// A member of a JSON object, or null.
fn at<'a>(v: &'a Value, key: &str) -> &'a Value {
    v.get(key).unwrap_or(&Value::Null)
}

/// A member as a list (`x || []`).
fn list_of(v: Option<&Value>) -> Vec<Value> {
    match v {
        Some(Value::Array(a)) => a.clone(),
        _ => Vec::new(),
    }
}

fn s(text: &str) -> Value {
    Value::String(text.to_string())
}

/// The protocol-independent sign-out.
pub struct Logout {
    pub deps: LogoutDeps,
}

impl Logout {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(deps: LogoutDeps) -> Logout {
        Logout { deps }
    }

    /// `handleFor(secret)`: an opaque, stable handle for a row whose
    /// natural key is a CREDENTIAL — `sha256(secret)` in hex, 16 long.
    // A hot path: once per code row; no span.
    pub fn handle_for(secret: &str) -> String {
        let hex = sts_crypto::sigstore::sha256_hex(secret.as_bytes());
        hex[..16].to_string()
    }

    fn setting(&self, key: &str) -> Value {
        self.deps.host.setting(key)
    }

    /// `maxRows()`.
    fn max_rows(&self) -> f64 {
        number_or_zero(Some(&self.setting("logout.maxRows")))
    }

    /// `anyUserAllowed()`: only where the test controls are open AND the
    /// setting allows it.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn any_user_allowed(&self) -> bool {
        self.deps.host.opens_test_controls()
            && truthy(Some(&self.setting("logout.anyUser")))
    }

    /// `row(family, kind, handle, detail)`: the one shape every family
    /// produces, Node's members in Node's order, `detail` assigned over it.
    // A hot path: once per row; no span.
    pub fn row(family: &str, kind: &Value, handle: &str, detail: Object) -> Object {
        let mut o = Object::new();
        o.insert("id".into(), json!(format!("{}:{}", family, handle)));
        o.insert("family".into(), json!(family));
        o.insert("kind".into(), kind.clone());
        o.insert("handle".into(), json!(handle));
        o.insert("label".into(), json!(""));
        o.insert("detail".into(), json!(""));
        o.insert("startedAt".into(), json!(0));
        o.insert("expiresAt".into(), json!(0));
        o.insert("terminable".into(), json!(true));
        o.insert("why".into(), json!(""));
        o.insert("sessionId".into(), json!(""));
        for (k, v) in detail {
            o.insert(k, v);
        }
        o
    }

    // -----------------------------------------------------------------
    // The sessions an identity holds.
    // -----------------------------------------------------------------

    fn holder_key(&self, username: &Value, sub: &Value) -> String {
        self.deps.stats.holder_key_of(username, sub)
    }

    /// `holderKeyOf()` of a session's own user, as Node passes it.
    fn session_holder(&self, session: &Value) -> String {
        let user = at(session, "user");
        let username = s(&or_empty(user.get("username")));
        let sub = s(&or_empty(user.get("sub")));
        self.holder_key(&username, &sub)
    }

    fn by_auth_time(list: &mut [Value]) {
        list.sort_by(|a, b| {
            let x = number_or_zero(b.get("authTime"));
            let y = number_or_zero(a.get("authTime"));
            x.partial_cmp(&y).unwrap_or(std::cmp::Ordering::Equal)
        });
    }

    /// `sessionsByKey(keys)`: the walk, or each key from the index while
    /// the session window is on.
    fn sessions_by_key(
        &self,
        keys: &[String],
    ) -> Result<Map<String, Value>, String> {
        let mut out: Map<String, Value> = Map::new();
        for k in keys {
            out.insert(k.clone(), json!([]));
        }
        if self.deps.authn.session_window_on() {
            let wanted: Vec<String> = out.keys().cloned().collect();
            for k in wanted {
                if k.is_empty() {
                    continue;
                }
                let one = self.sessions_of_one(&k)?;
                out.insert(k.clone(), Value::Array(one));
            }
            return Ok(out);
        }
        let Some(matched) = self.deps.authn.sessions_matching() else {
            return Err("the sessions could not be read".into());
        };
        for session in matched {
            let key = self.session_holder(&session);
            if let Some(Value::Array(list)) = out.get_mut(&key) {
                list.push(session);
            }
        }
        for (_, list) in out.iter_mut() {
            if let Value::Array(l) = list {
                Logout::by_auth_time(l);
            }
        }
        Ok(out)
    }

    fn subject_of_key(&self, key: &str) -> String {
        if key.len() >= 9 && key[..9].eq_ignore_ascii_case("urn:uuid:") {
            key.to_string()
        } else {
            self.deps.host.subject_for_name(key)
        }
    }

    /// `sessionsOfOne(key)`: two indexed columns, then the walk's rule.
    fn sessions_of_one(&self, key: &str) -> Result<Vec<Value>, String> {
        let subject = self.subject_of_key(key);
        let Some(found) = self.deps.authn.sessions_held_under(key, &subject)
        else {
            return Err("the sessions could not be read".into());
        };
        let mut mine: Vec<Value> = found
            .into_iter()
            .filter(|session| self.session_holder(session) == key)
            .collect();
        Logout::by_auth_time(&mut mine);
        Ok(mine)
    }

    fn sessions_for_key(
        &self,
        key: &str,
        index: Option<&Arc<Index>>,
    ) -> Result<Vec<Value>, String> {
        if let Some(i) = index.filter(|i| i.covers(key)) {
            return Ok(list_of(i.sessions.get(key)));
        }
        let by = self.sessions_by_key(&[key.to_string()])?;
        Ok(list_of(by.get(key)))
    }

    /// `withIndex(keys, fn, oneByIndex)`: the index built for `keys`, or
    /// the outer one where it covers them.
    fn with_index(
        &self,
        keys: &[String],
        outer: Option<&Arc<Index>>,
        one_by_index: bool,
    ) -> Result<Arc<Index>, String> {
        if let Some(o) = outer.filter(|o| keys.iter().all(|k| o.covers(k))) {
            return Ok(o.clone());
        }
        let sessions = if one_by_index && keys.len() == 1 {
            let mut m = Map::new();
            m.insert(
                keys[0].clone(),
                Value::Array(self.sessions_of_one(&keys[0])?),
            );
            m
        } else {
            self.sessions_by_key(keys)?
        };
        let holdings = self.deps.stats.holdings_of(keys);
        let wallet = self.wallet_rows_by_key(keys);
        let gnap = self.deps.gnap.grants_by_key(keys);
        let oauth_grants = self.oauth_grants_by_key(keys);
        Ok(Arc::new(Index {
            keys: keys.iter().cloned().collect(),
            sessions,
            holdings,
            wallet,
            gnap,
            oauth_grants,
        }))
    }

    fn indexed<'a>(ctx: &'a Ctx) -> Option<&'a Arc<Index>> {
        ctx.index.as_ref().filter(|i| i.covers(&ctx.key))
    }

    /// `holdingsFor(ctx)`: the person's token and artifact records.
    fn holdings_for(&self, ctx: &mut Ctx) -> Value {
        if let Some(i) = Logout::indexed(ctx) {
            return i.holdings.get(&ctx.key).cloned().unwrap_or(Value::Null);
        }
        if ctx.holdings.is_none() {
            let got = self.deps.stats.holdings_of(&[ctx.key.clone()]);
            ctx.holdings =
                Some(got.get(&ctx.key).cloned().unwrap_or(Value::Null));
        }
        ctx.holdings.clone().unwrap_or(Value::Null)
    }

    fn gnap_grants_for(&self, ctx: &Ctx) -> Vec<Value> {
        if let Some(i) = Logout::indexed(ctx) {
            return list_of(i.gnap.get(&ctx.key))
                .into_iter()
                .filter(|g| self.deps.gnap.is_live(g))
                .collect();
        }
        self.deps.gnap.grants_held_by(&ctx.key)
    }

    fn oauth_grants_by_key(&self, keys: &[String]) -> Map<String, Value> {
        let mut out: Map<String, Value> = Map::new();
        for k in keys {
            out.insert(k.clone(), json!([]));
        }
        for row in self.deps.grants.list() {
            let sub = or_empty(row.get("subject"));
            let name = self.deps.host.name_for_subject(&sub);
            let key = self.holder_key(&s(&name), &s(&sub));
            if let Some(Value::Array(list)) = out.get_mut(&key) {
                list.push(row);
            }
        }
        out
    }

    fn oauth_grants_for(&self, ctx: &mut Ctx) -> Vec<Value> {
        if let Some(i) = Logout::indexed(ctx) {
            return list_of(i.oauth_grants.get(&ctx.key));
        }
        if ctx.oauth_grants.is_none() {
            let by = self.oauth_grants_by_key(&[ctx.key.clone()]);
            ctx.oauth_grants = Some(list_of(by.get(&ctx.key)));
        }
        ctx.oauth_grants.clone().unwrap_or_default()
    }

    fn wallet_rows_by_key(&self, keys: &[String]) -> Map<String, Value> {
        let mut out: Map<String, Value> = Map::new();
        for k in keys {
            out.insert(k.clone(), json!([]));
        }
        let wanted: Vec<String> = out.keys().cloned().collect();
        for key in wanted {
            let subject = self.subject_of_key(&key);
            if subject.is_empty() {
                continue;
            }
            let mut mine = Vec::new();
            for row in self.deps.oid4vc.rows_for_subject(&subject) {
                let rs = string_of(row.get("subject"));
                let name = self.deps.host.name_for_subject(&rs);
                let held = self.holder_key(
                    &s(&name),
                    row.get("subject").unwrap_or(&Value::Null),
                );
                if held == key {
                    mine.push(row);
                }
            }
            out.insert(key, Value::Array(mine));
        }
        out
    }

    fn wallet_rows_for(&self, ctx: &Ctx) -> Vec<Value> {
        if let Some(i) = Logout::indexed(ctx) {
            return list_of(i.wallet.get(&ctx.key));
        }
        let by = self.wallet_rows_by_key(&[ctx.key.clone()]);
        list_of(by.get(&ctx.key))
    }

    /// `contextFor(key, issuer, by, initiatingEntity)`.
    fn context_for(
        &self,
        key: &str,
        issuer: &str,
        by: &str,
        entity: &str,
        index: Option<&Arc<Index>>,
    ) -> Result<Ctx, String> {
        let sessions = self.sessions_for_key(key, index)?;
        Ok(Ctx {
            key: key.to_string(),
            sessions,
            issuer: issuer.to_string(),
            by: by.to_string(),
            initiating_entity: entity.to_string(),
            index: index.cloned(),
            ..Ctx::default()
        })
    }

    /// The session object a termination edits, mirrored onto the copy
    /// `ctx.sessions` holds: Node's are ONE object, edited once.
    fn mirror(ctx: &mut Ctx, session: &Value) {
        let id = at(session, "id");
        for one in ctx.sessions.iter_mut() {
            if at(one, "id") == id {
                *one = session.clone();
            }
        }
    }

    // -----------------------------------------------------------------
    // collect(): each family's rows.
    // -----------------------------------------------------------------

    fn collect(&self, id: &str, ctx: &mut Ctx) -> Result<Vec<Object>, String> {
        match id {
            "session" => Ok(self.collect_session(ctx)),
            "oidc-rp" => Ok(self.collect_oidc_rp(ctx)),
            "wsfed-rp" => Ok(self.collect_wsfed(ctx)),
            "saml2-sp" => Ok(self.collect_saml2(ctx)),
            "federation-partner" => Ok(self.collect_partner(ctx)),
            "oauth-grant" => Ok(self.collect_oauth_grant(ctx)),
            "token" => Ok(self.collect_token(ctx)),
            "code" => Ok(self.collect_code(ctx)),
            "vci-code" => Ok(self.collect_vci_code(ctx)),
            "wallet-signin" => Ok(self.collect_wallet_signin(ctx)),
            "wallet-credential" => self.collect_wallet_credential(ctx),
            "gnap" => Ok(self.collect_gnap(ctx)),
            "uma" => Ok(self.collect_uma(ctx)),
            "ldap" => Ok(self.collect_ldap(ctx)),
            "krb5" => self.collect_krb5(ctx),
            "issued" => Ok(self.collect_issued(ctx)),
            _ => Ok(Vec::new()),
        }
    }

    fn collect_session(&self, ctx: &Ctx) -> Vec<Object> {
        let authn = &self.deps.authn;
        ctx.sessions
            .iter()
            .map(|session| {
                let view = authn.session_view(session);
                let mut rides = Vec::new();
                let oidc = self.deps.frontchannel.clients_of(session).len();
                let realms = js::object_of(session.get("wsfedRealms")).len();
                let sps =
                    js::object_of(session.get("saml2ServiceProviders")).len();
                if oidc > 0 {
                    rides.push(format!(
                        "{} OIDC relying part{}",
                        oidc,
                        if oidc == 1 { "y" } else { "ies" }
                    ));
                }
                if realms > 0 {
                    rides.push(format!(
                        "{} WS-Federation realm{}",
                        realms,
                        if realms == 1 { "" } else { "s" }
                    ));
                }
                if sps > 0 {
                    rides.push(format!(
                        "{} SAML 2.0 service provider{}",
                        sps,
                        if sps == 1 { "" } else { "s" }
                    ));
                }
                let methods = js::strings(view.get("methods")).join(", ");
                let username = or_empty(view.get("username"));
                let acr = or_empty(view.get("assuranceLevel"));
                let detail = format!(
                    "signed in as {} ({}, acr {}){}",
                    if username.is_empty() { "?" } else { &username },
                    if methods.is_empty() {
                        "no amr recorded"
                    } else {
                        &methods
                    },
                    if acr.is_empty() { "none" } else { &acr },
                    if rides.is_empty() {
                        "; nothing signed into on it".to_string()
                    } else {
                        format!("; carries {}", rides.join(", "))
                    }
                );
                let vid = string_of(view.get("id"));
                let mut d = Object::new();
                d.insert("label".into(), at(&view, "id").clone());
                d.insert("detail".into(), json!(detail));
                d.insert(
                    "startedAt".into(),
                    num(authn.session_started_at(session)),
                );
                d.insert(
                    "expiresAt".into(),
                    if truthy(view.get("expires")) {
                        at(&view, "expires").clone()
                    } else {
                        json!(0)
                    },
                );
                d.insert("sessionId".into(), at(&view, "id").clone());
                Logout::row("session", &s("sign-on session"), &vid, d)
            })
            .collect()
    }

    fn collect_oidc_rp(&self, ctx: &Ctx) -> Vec<Object> {
        let mut rows = Vec::new();
        for session in &ctx.sessions {
            let sid = string_of(session.get("id"));
            for note in
                self.deps.frontchannel.notifications_for(session, &ctx.issuer)
            {
                let client = string_of(note.get("clientId"));
                let detail = if truthy(note.get("url")) {
                    Some(json!(format!(
                        "will be notified at {}{}",
                        concat(note.get("uri")),
                        if truthy(note.get("sessionRequired")) {
                            " with iss and sid"
                        } else {
                            " without iss or sid, as registered"
                        }
                    )))
                } else {
                    note.get("why").cloned()
                };
                let mut d = Object::new();
                put(&mut d, "label", note.get("clientId").cloned());
                put(&mut d, "detail", detail);
                d.insert("sessionId".into(), at(session, "id").clone());
                d.insert("terminable".into(), json!(true));
                rows.push(Logout::row(
                    "oidc-rp",
                    &s("relying party"),
                    &format!("{}|{}", sid, client),
                    d,
                ));
            }
        }
        rows
    }

    fn collect_wsfed(&self, ctx: &Ctx) -> Vec<Object> {
        let mut rows = Vec::new();
        for session in &ctx.sessions {
            let sid = string_of(session.get("id"));
            for (i, target) in self
                .deps
                .wsfed
                .cleanup_targets_for(session)
                .into_iter()
                .enumerate()
            {
                let realm = concat(target.get("realm"));
                let handle = if i > 0 {
                    format!("{}|{}|{}", sid, realm, i)
                } else {
                    format!("{}|{}", sid, realm)
                };
                let mut d = Object::new();
                put(&mut d, "label", target.get("realm").cloned());
                d.insert(
                    "detail".into(),
                    json!(if truthy(target.get("url")) {
                        format!("cleanup goes to {}", text(at(&target, "url")))
                    } else {
                        "this realm supplied no wreply, so there is nowhere \
                         to send a cleanup request"
                            .to_string()
                    }),
                );
                d.insert("sessionId".into(), at(session, "id").clone());
                rows.push(Logout::row("wsfed-rp", &s("realm"), &handle, d));
            }
        }
        rows
    }

    fn collect_saml2(&self, ctx: &Ctx) -> Vec<Object> {
        let mut rows = Vec::new();
        for session in &ctx.sessions {
            let sid = string_of(session.get("id"));
            for target in self.deps.saml2.logout_targets_for(session) {
                let entity = concat(target.get("entityId"));
                let mut d = Object::new();
                put(&mut d, "label", target.get("entityId").cloned());
                d.insert(
                    "detail".into(),
                    json!(if truthy(target.get("url")) {
                        format!(
                            "a LogoutRequest is ready for {}",
                            concat(target.get("from"))
                        )
                    } else {
                        "no SingleLogoutService is known for it, so there \
                         is nowhere to send a LogoutRequest"
                            .to_string()
                    }),
                );
                d.insert("sessionId".into(), at(session, "id").clone());
                rows.push(Logout::row(
                    "saml2-sp",
                    &s("service provider"),
                    &format!("{}|{}", sid, entity),
                    d,
                ));
            }
        }
        rows
    }

    fn collect_partner(&self, ctx: &Ctx) -> Vec<Object> {
        let mut rows = Vec::new();
        for session in &ctx.sessions {
            let held = at(session, "fedPartnerSession");
            if !truthy(Some(held)) || !truthy(held.get("relationship")) {
                continue;
            }
            let can = self.deps.federation_slo.can_tell_partner(held);
            let why = if !truthy(can.get("ok")) {
                format!("the partner cannot be told: {}", concat(can.get("why")))
            } else if ctx.browser {
                String::new()
            } else {
                "the partner is told only from the person's own sign-out \
                 (/logout), because it is their browser that goes there"
                    .to_string()
            };
            let relationship = text(at(held, "relationship"));
            let protocol = or_empty(held.get("protocol"));
            let mut d = Object::new();
            d.insert("label".into(), at(held, "relationship").clone());
            d.insert(
                "detail".into(),
                json!(format!(
                    "signed in through {} ({}){}",
                    relationship,
                    if protocol.is_empty() { "?" } else { &protocol },
                    if why.is_empty() {
                        "; the partner will be offered its own sign-out"
                            .to_string()
                    } else {
                        format!("; {}", why)
                    }
                )),
            );
            d.insert("sessionId".into(), at(session, "id").clone());
            d.insert("terminable".into(), json!(why.is_empty()));
            d.insert("why".into(), json!(why));
            rows.push(Logout::row(
                "federation-partner",
                &s("federation partner"),
                &format!("{}|{}", string_of(session.get("id")), relationship),
                d,
            ));
        }
        rows
    }

    fn collect_oauth_grant(&self, ctx: &mut Ctx) -> Vec<Object> {
        self.oauth_grants_for(ctx)
            .iter()
            .map(|row| {
                let scopes: Vec<String> = list_of(row.get("scopes"))
                    .iter()
                    .map(|one| or_empty(one.get("scope")))
                    .filter(|x| !x.is_empty())
                    .collect();
                let scopes = scopes.join(" ");
                let grant = string_of(row.get("grantId"));
                let tokens = if truthy(row.get("tokens")) {
                    text(at(row, "tokens"))
                } else {
                    "0".into()
                };
                let mut d = Object::new();
                d.insert("label".into(), json!(or_empty(row.get("clientId"))));
                d.insert(
                    "detail".into(),
                    json!(format!(
                        "grant {}…{}, {} token(s) recorded under it",
                        slice16(&grant, 8),
                        if scopes.is_empty() {
                            String::new()
                        } else {
                            format!(", scope {}", scopes)
                        },
                        tokens
                    )),
                );
                d.insert(
                    "startedAt".into(),
                    num(number_or_zero(row.get("created_at")) * 1000.0),
                );
                d.insert(
                    "expiresAt".into(),
                    num(number_or_zero(row.get("expires_at")) * 1000.0),
                );
                Logout::row("oauth-grant", &s("grant"), &grant, d)
            })
            .collect()
    }

    /// `IssuedToken.fromRecord(record)` (#1579): the register row read as
    /// the model says it means (`sts_model::IssuedToken::FIELDS`).
    fn issued_token(record: &Value) -> Object {
        let pick = |k: &str| record.get(k).cloned().unwrap_or(Value::Null);
        let client = match record.get("client_id") {
            Some(Value::Array(a)) => a.first().cloned().unwrap_or(Value::Null),
            Some(v) => v.clone(),
            None => Value::Null,
        };
        let mut t = Object::new();
        t.insert("id".into(), pick("jti"));
        t.insert("kind".into(), pick("kind"));
        t.insert("clientId".into(), client);
        t.insert("scope".into(), pick("scope"));
        t.insert("expires".into(), pick("exp"));
        t.insert("sessionId".into(), pick("sessionId"));
        t.insert("issuedAt".into(), pick("issuedAt"));
        t.insert("revocable".into(), pick("revocable"));
        t.insert("dpopThumbprint".into(), pick("jkt"));
        t.insert("state".into(), pick("state"));
        t
    }

    fn collect_token(&self, ctx: &mut Ctx) -> Vec<Object> {
        let detail = self.holdings_for(ctx);
        if !truthy(Some(&detail)) {
            return Vec::new();
        }
        list_of(detail.get("tokens"))
            .iter()
            .map(Logout::issued_token)
            .filter(|t| {
                let state = string_of(t.get("state"));
                truthy(t.get("revocable"))
                    && state != "revoked"
                    && state != "expired"
            })
            .map(|t| {
                let kind = concat(t.get("kind"));
                let id = concat(t.get("id"));
                let client = or_empty(t.get("clientId"));
                let session = or_empty(t.get("sessionId"));
                let mut d = Object::new();
                d.insert("label".into(), json!(format!("{} {}", kind, id)));
                d.insert(
                    "detail".into(),
                    json!(format!(
                        "for {}{}{}{}",
                        if client.is_empty() { "no client" } else { &client },
                        if truthy(t.get("scope")) {
                            format!(", scope {}", text(&t["scope"]))
                        } else {
                            String::new()
                        },
                        if truthy(t.get("dpopThumbprint")) {
                            ", DPoP-bound"
                        } else {
                            ""
                        },
                        if session.is_empty() {
                            ", issued with no browser session".to_string()
                        } else {
                            format!(", issued on session {}", session)
                        }
                    )),
                );
                d.insert(
                    "startedAt".into(),
                    if truthy(t.get("issuedAt")) {
                        t["issuedAt"].clone()
                    } else {
                        json!(0)
                    },
                );
                d.insert(
                    "expiresAt".into(),
                    num(number_or_zero(t.get("expires")) * 1000.0),
                );
                d.insert("sessionId".into(), json!(session));
                Logout::row(
                    "token",
                    t.get("kind").unwrap_or(&Value::Null),
                    &id,
                    d,
                )
            })
            .collect()
    }

    fn collect_code(&self, ctx: &Ctx) -> Vec<Object> {
        self.deps
            .oauth2
            .outstanding_codes_for(&ctx.key)
            .iter()
            .map(|code| {
                let client = or_empty(code.get("clientId"));
                let redirect = or_empty(code.get("redirectUri"));
                let mut d = Object::new();
                d.insert(
                    "label".into(),
                    json!(format!(
                        "a code for {}",
                        if client.is_empty() { "no client" } else { &client }
                    )),
                );
                d.insert(
                    "detail".into(),
                    json!(format!(
                        "redirect_uri {}{}",
                        if redirect.is_empty() { "(none)" } else { &redirect },
                        if truthy(code.get("scope")) {
                            format!(", scope {}", text(&code["scope"]))
                        } else {
                            String::new()
                        }
                    )),
                );
                for (k, from) in [("startedAt", "issuedAt"), ("expiresAt", "expiresAt")]
                {
                    d.insert(
                        k.into(),
                        if truthy(code.get(from)) {
                            code[from].clone()
                        } else {
                            json!(0)
                        },
                    );
                }
                d.insert(
                    "sessionId".into(),
                    json!(or_empty(code.get("sessionId"))),
                );
                put(&mut d, "secret", code.get("code").cloned());
                Logout::row(
                    "code",
                    &s("authorization code"),
                    &Logout::handle_for(&string_of(code.get("code"))),
                    d,
                )
            })
            .collect()
    }

    /// The pre-authorized codes this key holds, as `[digest, record]`.
    fn vci_codes_of(&self, ctx: &Ctx) -> Vec<(String, Value)> {
        let mut out = Vec::new();
        for (digest, record) in self.deps.oid4vc.pre_authorized_codes() {
            let user = at(&record, "user");
            let username = s(&or_empty(user.get("username")));
            let sub = user.get("sub").cloned().unwrap_or(Value::Null);
            if self.holder_key(&username, &sub) != ctx.key {
                continue;
            }
            out.push((digest, record));
        }
        out
    }

    fn collect_vci_code(&self, ctx: &Ctx) -> Vec<Object> {
        let now = self.deps.host.now_ms();
        let mut rows = Vec::new();
        for (code, record) in self.vci_codes_of(ctx) {
            if truthy(record.get("expires"))
                && number_or_zero(record.get("expires")) < now
            {
                continue;
            }
            let configs = js::strings(record.get("configurationIds"));
            let mut d = Object::new();
            // `'… for ' + list.join(', ') || 'a credential'`: the
            // concatenation is never empty, so the fallback never applies
            // (a Node defect, ported).
            d.insert(
                "label".into(),
                json!(format!(
                    "a pre-authorized code for {}",
                    configs.join(", ")
                )),
            );
            d.insert(
                "detail".into(),
                json!(format!(
                    "{}{}",
                    if truthy(record.get("txCodeDigest")) {
                        "a transaction code is required with it"
                    } else {
                        "no transaction code"
                    },
                    if truthy(record.get("deferred")) {
                        "; the credential is issued deferred"
                    } else {
                        ""
                    }
                )),
            );
            d.insert(
                "expiresAt".into(),
                if truthy(record.get("expires")) {
                    record["expires"].clone()
                } else {
                    json!(0)
                },
            );
            d.insert("secret".into(), json!(code));
            rows.push(Logout::row(
                "vci-code",
                &s("pre-authorized code"),
                &Logout::handle_for(&code),
                d,
            ));
        }
        rows
    }

    fn wallet_signins_of(&self, ctx: &Ctx) -> Vec<Value> {
        self.deps
            .oid4vc
            .sign_ins_awaiting_collection()
            .into_iter()
            .filter(|one| {
                self.holder_key(at(one, "username"), at(one, "subject"))
                    == ctx.key
            })
            .collect()
    }

    fn collect_wallet_signin(&self, ctx: &Ctx) -> Vec<Object> {
        self.wallet_signins_of(ctx)
            .iter()
            .map(|one| {
                let decided = or_empty(one.get("decidedAt"));
                let mut d = Object::new();
                d.insert(
                    "label".into(),
                    json!("a wallet sign-in waiting for its browser"),
                );
                d.insert(
                    "detail".into(),
                    json!(format!("presentation accepted {}", decided)),
                );
                d.insert(
                    "expiresAt".into(),
                    if truthy(one.get("expires")) {
                        one["expires"].clone()
                    } else {
                        json!(0)
                    },
                );
                put(&mut d, "secret", one.get("state").cloned());
                Logout::row(
                    "wallet-signin",
                    &s("wallet sign-in"),
                    &Logout::handle_for(&string_of(one.get("state"))),
                    d,
                )
            })
            .collect()
    }

    fn collect_wallet_credential(
        &self,
        ctx: &Ctx,
    ) -> Result<Vec<Object>, String> {
        let mut rows = Vec::new();
        let mut seen = HashSet::new();
        for row in self.wallet_rows_for(ctx) {
            let handle = Logout::handle_for(&format!(
                "wallet-credential|{}",
                concat(row.get("key"))
            ));
            if !seen.insert(handle.clone()) {
                continue;
            }
            let n = list_of(row.get("credentials")).len();
            let mut d = Object::new();
            d.insert(
                "label".into(),
                json!(format!(
                    "{} credential{}",
                    concat(row.get("format")),
                    if n > 1 {
                        format!("s ({})", n)
                    } else {
                        String::new()
                    }
                )),
            );
            d.insert(
                "detail".into(),
                json!(format!(
                    "bound to key {}…, issued {}",
                    slice16(&string_of(row.get("jkt")), 12),
                    js::iso(js::number(row.get("issuedAt")))?
                )),
            );
            for k in ["issuedAt", "expiresAt"] {
                let to = if k == "issuedAt" { "startedAt" } else { k };
                d.insert(
                    to.into(),
                    if truthy(row.get(k)) {
                        row[k].clone()
                    } else {
                        json!(0)
                    },
                );
            }
            put(&mut d, "secret", row.get("key").cloned());
            d.insert(
                "why".into(),
                json!(
                    "ending this stops it signing anybody in at \
                     /authn/wallet and sets its status INVALID. The \
                     credential stays in the wallet."
                ),
            );
            rows.push(Logout::row(
                "wallet-credential",
                &s("wallet credential"),
                &handle,
                d,
            ));
        }
        Ok(rows)
    }

    fn collect_gnap(&self, ctx: &Ctx) -> Vec<Object> {
        self.gnap_grants_for(ctx)
            .iter()
            .map(|grant| {
                let live = self.deps.gnap.live_tokens_of(grant);
                let ro = at(grant, "ro");
                let session = if truthy(Some(ro)) && truthy(ro.get("sessionId"))
                {
                    text(&ro["sessionId"])
                } else {
                    String::new()
                };
                let client = at(grant, "client");
                let mut d = Object::new();
                d.insert(
                    "label".into(),
                    json!(or_empty(client.get("identifier"))),
                );
                d.insert(
                    "detail".into(),
                    json!(format!(
                        "{}, {} live access token(s){}",
                        concat(grant.get("state")),
                        live.len(),
                        if !session.is_empty() {
                            format!(", approved on session {}", session)
                        } else if truthy(grant.get("derivedFrom")) {
                            ", derived by a resource server".to_string()
                        } else {
                            ", approved with no browser session".to_string()
                        }
                    )),
                );
                d.insert(
                    "startedAt".into(),
                    num(number_or_zero(grant.get("createdAt")) * 1000.0),
                );
                d.insert("expiresAt".into(), json!(0));
                d.insert("sessionId".into(), json!(session));
                Logout::row(
                    "gnap",
                    &s("grant"),
                    &string_of(grant.get("id")),
                    d,
                )
            })
            .collect()
    }

    fn collect_uma(&self, ctx: &Ctx) -> Vec<Object> {
        let subject = self.deps.host.subject_for_name(&ctx.key);
        if subject.is_empty() {
            return Vec::new();
        }
        self.deps
            .uma
            .pcts_of(&subject)
            .iter()
            .map(|pct| {
                let client = or_empty(pct.get("client"));
                let mut d = Object::new();
                d.insert("label".into(), json!(client));
                d.insert(
                    "detail".into(),
                    json!(format!("claims gathered for the client {}", client)),
                );
                d.insert(
                    "startedAt".into(),
                    num(number_or_zero(pct.get("issuedAt")) * 1000.0),
                );
                d.insert(
                    "expiresAt".into(),
                    num(number_or_zero(pct.get("expiresAt")) * 1000.0),
                );
                Logout::row("uma", &s("pct"), &string_of(pct.get("key")), d)
            })
            .collect()
    }

    fn collect_ldap(&self, ctx: &Ctx) -> Vec<Object> {
        let on = truthy(Some(&self.setting("logout.ldapDisconnect")));
        self.deps
            .ldap
            .bound_connections()
            .iter()
            .filter(|c| {
                truthy(c.get("key")) && string_of(c.get("key")) == ctx.key
            })
            .map(|c| {
                let bound = format!(
                    "bound on {}{}",
                    if truthy(c.get("secure")) {
                        "LDAPS "
                    } else {
                        "plain "
                    },
                    concat(c.get("port"))
                );
                let mut d = Object::new();
                put(&mut d, "label", c.get("dn").cloned());
                if !on {
                    d.insert("terminable".into(), json!(false));
                    d.insert("detail".into(), json!(bound));
                    d.insert(
                        "why".into(),
                        json!(
                            "logout.ldapDisconnect is off, so this logout \
                             leaves directory connections alone. Turn it on \
                             to have them closed."
                        ),
                    );
                } else {
                    let node = if truthy(c.get("nodeName")) {
                        text(&c["nodeName"])
                    } else {
                        concat(c.get("node"))
                    };
                    d.insert(
                        "detail".into(),
                        json!(format!(
                            "{}, connection {}{}",
                            bound,
                            concat(c.get("id")),
                            if truthy(c.get("remote")) {
                                format!(", on node {}", node)
                            } else {
                                String::new()
                            }
                        )),
                    );
                }
                Logout::row(
                    "ldap",
                    &s("connection"),
                    &concat(c.get("id")),
                    d,
                )
            })
            .collect()
    }

    fn krb5_row(
        handle: &str,
        terminable: bool,
        detail: String,
        why: &str,
        started: Option<f64>,
    ) -> Object {
        let mut d = Object::new();
        d.insert("label".into(), json!(handle));
        if let Some(at) = started {
            d.insert("startedAt".into(), num(at));
        }
        if !terminable {
            d.insert("terminable".into(), json!(false));
        }
        d.insert("detail".into(), json!(detail));
        if !why.is_empty() {
            d.insert("why".into(), json!(why));
        }
        Logout::row("krb5", &s("ticket-granting tickets"), handle, d)
    }

    fn collect_krb5(&self, ctx: &Ctx) -> Result<Vec<Object>, String> {
        if ctx.key.is_empty() {
            return Ok(Vec::new());
        }
        let krb5 = &self.deps.krb5;
        let realm = krb5.realm();
        if !truthy(krb5.kerberos_realm_of().get("enabled")) {
            return Ok(vec![Logout::krb5_row(
                &ctx.key,
                false,
                "this trust realm has no KDC".into(),
                "Kerberos is off in this trust realm (krb5.enabled), so it \
                 has issued no ticket and there is no principal to stamp a \
                 sign-out instant on.",
                None,
            )]);
        }
        let names = [ctx.key.clone()];
        let already = krb5.signed_out_at(&names, &realm);
        let principal = krb5.find(&names, &realm);
        let handle = format!("{}@{}", ctx.key, realm);
        let instant = || -> Result<String, String> {
            js::iso(js::parse_iso(&already))
        };
        if !truthy(Some(&principal)) {
            return Ok(vec![Logout::krb5_row(
                &handle,
                false,
                "no such principal in this KDC".into(),
                "nothing has authenticated to this KDC as that name, so \
                 there is no principal to stamp a sign-out instant on. One \
                 appears the first time an AS-REQ names it.",
                None,
            )]);
        }
        let set = truthy(Some(&already));
        if !truthy(Some(&self.setting("logout.kerberosSignOut"))) {
            let detail = if set {
                format!("signed out at {}", instant()?)
            } else {
                "no sign-out instant is set".into()
            };
            return Ok(vec![Logout::krb5_row(
                &handle,
                false,
                detail,
                "logout.kerberosSignOut is off, so this logout leaves the \
                 KDC alone and a ticket-granting ticket already issued goes \
                 on working. Turn it on to have older tickets refused.",
                None,
            )]);
        }
        let detail = if set {
            format!(
                "already signed out at {}; ending it again moves the \
                 instant to now, which catches any ticket issued since",
                instant()?
            )
        } else {
            "every ticket-granting ticket authenticated before now will be \
             refused at the KDC"
                .into()
        };
        let started = if set { js::parse_iso(&already) } else { 0.0 };
        Ok(vec![Logout::krb5_row(&handle, true, detail, "", Some(started))])
    }

    fn collect_issued(&self, ctx: &mut Ctx) -> Vec<Object> {
        let detail = self.holdings_for(ctx);
        if !truthy(Some(&detail)) {
            return Vec::new();
        }
        list_of(detail.get("artifacts"))
            .iter()
            .filter(|r| {
                let state = string_of(r.get("state"));
                state != "expired" && state != "revoked"
            })
            .map(|record| {
                let kind = concat(record.get("kind"));
                let handle = if truthy(record.get("key")) {
                    text(&record["key"])
                } else {
                    Logout::handle_for(&format!(
                        "{}|{}|{}",
                        kind,
                        or_empty(record.get("id")),
                        if truthy(record.get("issuedAt")) {
                            text(&record["issuedAt"])
                        } else {
                            "0".into()
                        }
                    ))
                };
                let mut d = Object::new();
                d.insert(
                    "label".into(),
                    json!(format!(
                        "{}{}",
                        kind,
                        if truthy(record.get("id")) {
                            format!(" {}", text(&record["id"]))
                        } else {
                            String::new()
                        }
                    )),
                );
                d.insert(
                    "detail".into(),
                    json!(format!(
                        "{}{}",
                        if truthy(record.get("audience")) {
                            format!("for {}", text(&record["audience"]))
                        } else {
                            "no audience recorded".into()
                        },
                        if truthy(record.get("state")) {
                            format!(", {}", text(&record["state"]))
                        } else {
                            String::new()
                        }
                    )),
                );
                for (k, from) in
                    [("startedAt", "issuedAt"), ("expiresAt", "expiresAt")]
                {
                    d.insert(
                        k.into(),
                        if truthy(record.get(from)) {
                            record[from].clone()
                        } else {
                            json!(0)
                        },
                    );
                }
                d.insert("terminable".into(), json!(true));
                d.insert(
                    "why".into(),
                    json!(
                        "ending this marks it revoked in this service's own \
                         record. THE HOLDER IS NOT TOLD and cannot be: \
                         nothing consults this service when it is presented, \
                         so it goes on working until it expires. CAEP is the \
                         one channel that can carry the news to a receiver \
                         that subscribed."
                    ),
                );
                Logout::row(
                    "issued",
                    record.get("kind").unwrap_or(&Value::Null),
                    &handle,
                    d,
                )
            })
            .collect()
    }

    // -----------------------------------------------------------------
    // terminate(): each family's end of one row.
    // -----------------------------------------------------------------

    fn handle_parts(row: &Object) -> (String, String) {
        let handle = string_of(row.get("handle"));
        let mut parts = handle.splitn(2, '|');
        let first = parts.next().unwrap_or("").to_string();
        let rest = parts.next().unwrap_or("").to_string();
        (first, rest)
    }

    fn end_row(&self, id: &str, r: &Object, ctx: &mut Ctx) -> Result<Outcome, String> {
        let handle = string_of(r.get("handle"));
        let by_or = |ctx: &Ctx, d: &str| -> String {
            if ctx.by.is_empty() {
                d.to_string()
            } else {
                ctx.by.clone()
            }
        };
        match id {
            "session" => {
                let ended = self.deps.authn.end_session_by_id(
                    &handle,
                    &by_or(ctx, "the protocol-independent logout"),
                    &ctx.initiating_entity,
                );
                Ok(if ended {
                    ok(format!("the sign-on session {} was ended", handle))
                } else {
                    no(format!(
                        "there was no session {} to end; it had already \
                         expired or already been signed out",
                        handle
                    ))
                })
            }
            "oidc-rp" => Ok(self.end_oidc_rp(r, ctx)),
            "wsfed-rp" => Ok(self.end_wsfed(r, ctx)),
            "saml2-sp" => Ok(self.end_saml2(r, ctx)),
            "federation-partner" => {
                let (sid, _) = Logout::handle_parts(r);
                let Some(session) = self.deps.authn.session_by_id(&sid) else {
                    return Ok(no(
                        "the session that partner signed in has already ended",
                    ));
                };
                let built = self
                    .deps
                    .federation_slo
                    .partner_logout_for(&session, &ctx.base);
                if !truthy(built.get("ok")) {
                    return Ok(no(format!(
                        "the partner cannot be told: {}",
                        concat(built.get("why"))
                    )));
                }
                let target = at(&built, "target").clone();
                ctx.partner_logouts.push(target.clone());
                Ok(ok(format!(
                    "the sign-out at {} is on the page: {}",
                    concat(target.get("label")),
                    concat(target.get("what"))
                )))
            }
            "oauth-grant" => {
                let held = self.oauth_grants_for(ctx).into_iter().any(|row| {
                    string_of(row.get("grantId")) == handle
                });
                if !held {
                    return Ok(no("that grant has already been revoked or \
                                  has expired"));
                }
                let entity = if ctx.initiating_entity.is_empty() {
                    "admin".to_string()
                } else {
                    ctx.initiating_entity.clone()
                };
                let done = self.deps.grants.revoke(
                    &handle,
                    &ctx.key,
                    &by_or(ctx, "a sign-out"),
                    &entity,
                );
                if let Some(list) = ctx.oauth_grants.as_mut() {
                    list.retain(|row| string_of(row.get("grantId")) != handle);
                }
                Ok(if truthy(Some(&done)) && truthy(done.get("ok")) {
                    ok(format!(
                        "the grant of {} was revoked, and {} token(s) with it",
                        concat(done.get("clientId")),
                        concat(done.get("revoked"))
                    ))
                } else {
                    no("that grant has already been revoked")
                })
            }
            "token" => {
                let opts = if ctx.initiating_entity.is_empty() {
                    Value::Null
                } else {
                    json!({ "initiatingEntity": ctx.initiating_entity })
                };
                let first = self.deps.stats.revoke(
                    &handle,
                    "a protocol-independent logout at /logout",
                    &opts,
                );
                Ok(ok(if first {
                    format!("the token with jti {} is revoked", handle)
                } else {
                    format!("the token with jti {} was already revoked", handle)
                }))
            }
            "code" => {
                let found = self
                    .deps
                    .oauth2
                    .outstanding_codes_for(&ctx.key)
                    .into_iter()
                    .find(|code| {
                        Logout::handle_for(&string_of(code.get("code")))
                            == handle
                    });
                let Some(code) = found else {
                    return Ok(no("that authorization code has already been \
                                  redeemed or has expired, so there is \
                                  nothing left to end"));
                };
                self.deps.oauth2.drop_code(&string_of(code.get("code")));
                let client = or_empty(code.get("clientId"));
                Ok(ok(format!(
                    "an authorization code for {} was discarded and can no \
                     longer be redeemed",
                    if client.is_empty() { "no client" } else { &client }
                )))
            }
            "vci-code" => {
                let mut found = String::new();
                for (code, _) in self.vci_codes_of(ctx) {
                    if Logout::handle_for(&code) == handle {
                        found = code;
                    }
                }
                if found.is_empty() {
                    return Ok(no("that pre-authorized code has already been \
                                  redeemed or has expired, so there is \
                                  nothing left to end"));
                }
                self.deps.oid4vc.delete_pre_authorized_code(&found);
                Ok(ok("a pre-authorized code was discarded; the Credential \
                       Offer it came from can no longer be redeemed"
                    .into()))
            }
            "wallet-signin" => {
                let found = self.wallet_signins_of(ctx).into_iter().find(|one| {
                    Logout::handle_for(&string_of(one.get("state"))) == handle
                });
                let withdrawn = match found {
                    Some(one) => self.deps.oid4vc.withdraw_sign_in(
                        &string_of(one.get("state")),
                        "a sign-out",
                    ),
                    None => false,
                };
                Ok(if withdrawn {
                    ok("a wallet sign-in was withdrawn before its browser \
                        collected it"
                        .into())
                } else {
                    no("that wallet sign-in has already been collected or \
                        has expired, so there is nothing left to end")
                })
            }
            "wallet-credential" => {
                let found = self.wallet_rows_for(ctx).into_iter().find(|row| {
                    Logout::handle_for(&format!(
                        "wallet-credential|{}",
                        concat(row.get("key"))
                    )) == handle
                });
                let disowned = match found {
                    Some(row) => self.deps.oid4vc.disown(
                        &string_of(row.get("key")),
                        &by_or(ctx, "a global sign-out"),
                    ),
                    None => false,
                };
                Ok(if disowned {
                    ok("a wallet credential was disowned: it no longer \
                        signs anybody in here, and its status is INVALID"
                        .into())
                } else {
                    no("that wallet credential has already been disowned or \
                        has expired")
                })
            }
            "gnap" => {
                let Some(grant) = self
                    .gnap_grants_for(ctx)
                    .into_iter()
                    .find(|g| string_of(g.get("id")) == handle)
                else {
                    return Ok(no("that GNAP grant has already been revoked \
                                  or finalized"));
                };
                let tokens = list_of(grant.get("tokens")).len();
                let opts = json!({
                    "why": format!("ended by {}",
                        by_or(ctx, "a protocol-independent sign-out")),
                    "actor": ctx.key,
                    "via": by_or(ctx, "the /logout endpoint"),
                    "initiatingEntity": ctx.initiating_entity,
                });
                let ended = self.deps.gnap.end_grant(&grant, &opts);
                Ok(if ended {
                    ok(format!(
                        "the GNAP grant {} of {} is finalized and its {} \
                         token(s) are revoked",
                        concat(grant.get("id")),
                        concat(at(&grant, "client").get("identifier")),
                        tokens
                    ))
                } else {
                    no("that GNAP grant had already been finalized")
                })
            }
            "uma" => {
                let gone = self.deps.uma.delete_pct(&handle);
                Ok(if gone {
                    ok(format!(
                        "the persisted claims token held by {} is ended",
                        concat(r.get("label"))
                    ))
                } else {
                    no("that persisted claims token had already ended")
                })
            }
            "ldap" => {
                let dropped: Vec<Value> = self
                    .deps
                    .ldap
                    .drop_connections_for(&ctx.key)
                    .into_iter()
                    .filter(|one| concat(one.get("id")) == handle)
                    .collect();
                if let Some(first) =
                    dropped.first().filter(|d| truthy(d.get("remote")))
                {
                    let node = if truthy(first.get("nodeName")) {
                        text(&first["nodeName"])
                    } else {
                        concat(first.get("node"))
                    };
                    return Ok(Outcome {
                        ok: true,
                        pending: true,
                        message: format!(
                            "the directory connection {} bound as {} is on \
                             node {}, which was instructed to close it; the \
                             instruction is committed with this sign-out \
                             and that node closes the socket when it \
                             applies it, normally within a second — this \
                             answer does not wait for it",
                            handle,
                            concat(first.get("dn")),
                            node
                        ),
                    });
                }
                Ok(ok(match dropped.first() {
                    Some(d) => format!(
                        "the directory connection {} bound as {} was closed",
                        handle,
                        concat(d.get("dn"))
                    ),
                    None => format!(
                        "the directory connection {} was already closed",
                        handle
                    ),
                }))
            }
            "krb5" => {
                let krb5 = &self.deps.krb5;
                if !truthy(krb5.kerberos_realm_of().get("enabled")) {
                    return Ok(no("Kerberos is off in this trust realm, so it \
                                  has issued no ticket and there is nothing \
                                  to sign out."));
                }
                let realm = krb5.realm();
                let p = krb5.sign_out(&[ctx.key.clone()], &realm);
                if !truthy(Some(&p)) {
                    return Ok(no(format!(
                        "this KDC has no principal named {}@{}, so there was \
                         nothing to sign out",
                        ctx.key, realm
                    )));
                }
                let name = js::strings(p.get("name")).join("/");
                Ok(ok(format!(
                    "{}@{} signed out at {}; a TGS-REQ presenting an older \
                     ticket is now refused KDC_ERR_TGT_REVOKED. A service \
                     ticket already in a cache still works against the \
                     service that accepts it.",
                    name,
                    concat(p.get("realm")),
                    js::iso(js::parse_iso(at(&p, "signedOutAt")))?
                )))
            }
            "issued" => {
                let Some(record) = self.deps.stats.artifact_by_key(&handle)
                else {
                    return Ok(no("that credential is no longer in the \
                                  issued register — it has been forgotten \
                                  to the cap since this list was drawn, at \
                                  which point this service has no position \
                                  on it left to state"));
                };
                let first = self
                    .deps
                    .stats
                    .revoke_artifact(&record, &by_or(ctx, "a global sign-out"));
                Ok(ok(format!(
                    "{}{}{} revoked in this service's record. The holder \
                     has NOT been told and cannot be by this act",
                    if first { "marked " } else { "was already marked " },
                    concat(record.get("kind")),
                    if truthy(record.get("id")) {
                        format!(" {}", text(&record["id"]))
                    } else {
                        String::new()
                    }
                )))
            }
            _ => Ok(no("no answer")),
        }
    }

    fn end_oidc_rp(&self, r: &Object, ctx: &mut Ctx) -> Outcome {
        let (sid, client) = Logout::handle_parts(r);
        let Some(mut session) = self.deps.authn.session_by_id(&sid) else {
            return no("the session that relying party was signed into on \
                       has already ended, which signed it out too");
        };
        let note = self
            .deps
            .frontchannel
            .notifications_for(&session, &ctx.issuer)
            .into_iter()
            .find(|one| string_of(one.get("clientId")) == client);
        if let Some(n) = &note {
            ctx.notifications.push(n.clone());
        }
        let notified = note.as_ref().filter(|n| truthy(n.get("url")));
        let session_id = string_of(session.get("id"));
        if ctx.ending_sessions.contains(&session_id) {
            return ok(format!(
                "{} on session {}{}, and is sent a back-channel Logout Token \
                 by the end of the session itself",
                client,
                session_id,
                match notified {
                    Some(n) => format!(" is notified at {}", concat(n.get("uri"))),
                    None => " has nowhere to be notified in a browser".into(),
                }
            ));
        }
        let via = if ctx.by.is_empty() {
            "the protocol-independent logout".to_string()
        } else {
            ctx.by.clone()
        };
        let told = self.deps.backchannel.plan(
            &session,
            &json!({ "via": via, "clients": [client], "issuer": ctx.issuer,
                     "trigger": "forget" }),
        );
        self.deps.backchannel.dispatch(&told);
        if let Some(Value::Object(clients)) = session.get_mut("oidcClients") {
            clients.shift_remove(&client);
            self.deps.authn.note_session_changed(&session);
            Logout::mirror(ctx, &session);
        }
        ok(format!(
            "{} was forgotten on session {}{}{}",
            client,
            session_id,
            match notified {
                Some(n) => format!(" and notified at {}", concat(n.get("uri"))),
                None => " (there was nowhere to notify it)".into(),
            },
            match told.first() {
                Some(t) => format!(
                    "; a back-channel Logout Token was queued for {}",
                    concat(t.get("uri"))
                ),
                None => String::new(),
            }
        ))
    }

    /// The WS-Federation and SAML rows: the target built before the entry
    /// is forgotten, because the list it is built from is what goes.
    fn end_rider(
        &self,
        r: &Object,
        ctx: &mut Ctx,
        member: &str,
        key_of: &str,
        saml: bool,
    ) -> Outcome {
        let (sid, name) = Logout::handle_parts(r);
        let Some(mut session) = self.deps.authn.session_by_id(&sid) else {
            return no(if saml {
                "the session that service provider was signed into on has \
                 already ended, which took its logout list with it"
            } else {
                "the session that realm was signed into on has already \
                 ended, which took its cleanup list with it"
            });
        };
        let targets = if saml {
            self.deps.saml2.logout_targets_for(&session)
        } else {
            self.deps.wsfed.cleanup_targets_for(&session)
        };
        let target = targets
            .into_iter()
            .find(|one| string_of(one.get(key_of)) == name);
        if let Some(t) = &target {
            if saml {
                ctx.logout_requests.push(t.clone());
            } else {
                ctx.cleanups.push(t.clone());
            }
        }
        if let Some(Value::Object(list)) = session.get_mut(member) {
            list.shift_remove(&name);
            self.deps.authn.rewrite_session(&session);
            Logout::mirror(ctx, &session);
        }
        let sent = target.as_ref().is_some_and(|t| truthy(t.get("url")));
        let id = string_of(session.get("id"));
        ok(if saml {
            format!(
                "{} was forgotten on session {}{}",
                name,
                id,
                if sent {
                    "; the LogoutRequest for it is on the page and has to be \
                     sent by following the link"
                } else {
                    " (there is nowhere to send a LogoutRequest)"
                }
            )
        } else {
            format!(
                "{} was forgotten on session {}{}",
                name,
                id,
                if sent {
                    " and a cleanup request was sent"
                } else {
                    " (there was nowhere to send a cleanup request)"
                }
            )
        })
    }

    fn end_wsfed(&self, r: &Object, ctx: &mut Ctx) -> Outcome {
        self.end_rider(r, ctx, "wsfedRealms", "realm", false)
    }

    fn end_saml2(&self, r: &Object, ctx: &mut Ctx) -> Outcome {
        self.end_rider(r, ctx, "saml2ServiceProviders", "entityId", true)
    }

    // -----------------------------------------------------------------
    // The inventory and the termination.
    // -----------------------------------------------------------------

    fn audit_failure(&self, code: &str, channel: &str, key: &str, summary: String, detail: Value) {
        self.deps.host.audit_failure(
            code,
            &json!({ "protocol": "Logout", "channel": channel, "target": key,
                     "outcome": "error", "summary": summary,
                     "detail": detail }),
        );
    }

    /// `inventoryFor(key, issuer)`: everything an identity still holds,
    /// family by family, capped in what is DRAWN (`logout.maxRows`), never
    /// in what a termination reaches.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn inventory_for(&self, key: &str, issuer: &str) -> Result<Value, String> {
        self.inventory_in(key, issuer, None)
    }

    fn inventory_in(
        &self,
        key: &str,
        issuer: &str,
        index: Option<&Arc<Index>>,
    ) -> Result<Value, String> {
        let mut ctx = self.context_for(key, issuer, "", "", index)?;
        let cap = self.max_rows();
        let mut families = Vec::new();
        let (mut total, mut listed) = (0usize, 0usize);
        for family in FAMILIES {
            let (rows, failure) = match self.collect(family.id, &mut ctx) {
                Ok(rows) => (rows, String::new()),
                Err(e) => {
                    tracing::warn!(
                        "{}logout: the {} family could not be read: {}",
                        sts_core::log::tag(codes::STS_LOGOUT_0004),
                        family.id,
                        e
                    );
                    self.audit_failure(
                        codes::STS_LOGOUT_0004.as_str(),
                        "internal",
                        &ctx.key,
                        format!(
                            "The {} family could not be read for a sign-out \
                             inventory",
                            family.id
                        ),
                        json!({ "family": family.id, "why": e }),
                    );
                    (Vec::new(), e)
                }
            };
            total += rows.len();
            let room = (cap - listed as f64).max(0.0) as usize;
            let shown: Vec<Value> = rows
                .iter()
                .take(room)
                .map(|r| {
                    let mut copy = r.clone();
                    copy.shift_remove("secret");
                    Value::Object(copy)
                })
                .collect();
            listed += shown.len();
            families.push(json!({
                "id": family.id, "label": family.label,
                "protocol": family.protocol, "spec": family.spec,
                "what": family.what, "terminable": true,
                "rows": shown, "held": rows.len(),
                "notListed": rows.len() - shown.len(), "failure": failure,
            }));
        }
        Ok(json!({
            "key": ctx.key, "sessions": ctx.sessions.len(),
            "families": families, "total": total, "listed": listed,
            "notListed": total - listed, "maxRows": num(cap),
            "at": num(self.deps.host.now_ms()),
        }))
    }

    /// `allRows(ctx)`: every row, WITH its secret.
    fn all_rows(&self, ctx: &mut Ctx) -> Vec<Object> {
        let mut out = Vec::new();
        for family in FAMILIES {
            match self.collect(family.id, ctx) {
                Ok(rows) => out.extend(rows),
                Err(e) => {
                    tracing::warn!(
                        "{}logout: the {} family could not be read while \
                         terminating: {}",
                        sts_core::log::tag(codes::STS_LOGOUT_0005),
                        family.id,
                        e
                    );
                    self.audit_failure(
                        codes::STS_LOGOUT_0005.as_str(),
                        "internal",
                        &ctx.key,
                        format!(
                            "The {} family could not be read while signing \
                             out",
                            family.id
                        ),
                        json!({ "family": family.id, "why": e }),
                    );
                }
            }
        }
        out
    }

    /// `heldIds(key)`: the ids of what a later `terminate()` could end.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn held_ids(&self, key: &str) -> Result<Vec<String>, String> {
        let all = self.held_ids_for(&[key.to_string()])?;
        Ok(all.into_iter().next().map(|(_, v)| v).unwrap_or_default())
    }

    /// `heldIdsFor(keys)`, each big store read once for the set (#351).
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn held_ids_for(
        &self,
        keys: &[String],
    ) -> Result<Vec<(String, Vec<String>)>, String> {
        let index = self.with_index(keys, None, true)?;
        let mut out = Vec::new();
        for key in keys {
            let mut ctx = self.context_for(key, "", "", "", Some(&index))?;
            let ids = self
                .all_rows(&mut ctx)
                .into_iter()
                .filter(|r| truthy(r.get("terminable")))
                .map(|r| string_of(r.get("id")))
                .collect();
            out.push((key.clone(), ids));
        }
        Ok(out)
    }

    /// `terminateEach(list, opts)`: one `terminate()` per identity over one
    /// read of the big stores.
    #[tracing::instrument(level = "debug", skip(self, list, opts))]
    pub fn terminate_each(
        &self,
        list: &[(String, Vec<String>)],
        opts: &TerminateOptions,
    ) -> Result<Vec<Value>, String> {
        let keys: Vec<String> = list.iter().map(|(k, _)| k.clone()).collect();
        let index = self.with_index(&keys, None, false)?;
        list.iter()
            .map(|(key, selection)| {
                self.terminate_in(key, selection, opts, Some(&index))
            })
            .collect()
    }

    fn leaves_credential(family: &Family, row: &Object) -> bool {
        family.id == "wallet-credential"
            || (family.id == "issued"
                && string_of(row.get("kind")).starts_with("Credential ("))
    }

    /// `terminate(key, selection, opts)`: every row for a GLOBAL sign-out
    /// (an empty selection), or the rows selected — collected AGAIN, never
    /// taken from a drawn page, and ended in each family's `end_order`,
    /// the session last.
    #[tracing::instrument(level = "debug", skip(self, opts))]
    pub fn terminate(
        &self,
        key: &str,
        selection: &[String],
        opts: &TerminateOptions,
    ) -> Result<Value, String> {
        self.terminate_in(key, selection, opts, None)
    }

    fn terminate_in(
        &self,
        key: &str,
        selection: &[String],
        opts: &TerminateOptions,
        index: Option<&Arc<Index>>,
    ) -> Result<Value, String> {
        let host = &self.deps.host;
        let mark = self.deps.backchannel.mark();
        let mut ctx = self.context_for(
            key,
            &opts.issuer,
            &opts.by,
            &opts.initiating_entity,
            index,
        )?;
        ctx.base = opts.base.clone();
        ctx.browser = opts.browser && !ctx.base.is_empty();
        let channel = if opts.channel.is_empty() {
            "http"
        } else {
            opts.channel.as_str()
        };
        let wanted: Vec<String> =
            selection.iter().filter(|s| !s.is_empty()).cloned().collect();
        let global = wanted.is_empty();
        if global {
            host.subject_terminated(&host.realm_id(), key);
        }
        let wanted_set: HashSet<&String> = wanted.iter().collect();
        let mut unknown: Vec<String> = Vec::new();
        for id in &wanted {
            if !unknown.contains(id) {
                unknown.push(id.clone());
            }
        }
        for session in &ctx.sessions {
            let sid = string_of(session.get("id"));
            if global || wanted_set.contains(&format!("session:{}", sid)) {
                ctx.ending_sessions.insert(sid);
            }
        }
        let mut done: Vec<Value> = Vec::new();
        let mut skipped: Vec<Value> = Vec::new();
        for family in families::in_ending_order() {
            let rows = match self.collect(family.id, &mut ctx) {
                Ok(rows) => rows,
                Err(e) => {
                    tracing::warn!(
                        "{}logout: the {} family could not be read while \
                         terminating: {}",
                        sts_core::log::tag(codes::STS_LOGOUT_0005),
                        family.id,
                        e
                    );
                    self.audit_failure(
                        codes::STS_LOGOUT_0005.as_str(),
                        channel,
                        &ctx.key,
                        format!(
                            "The {} family could not be read while signing \
                             out",
                            family.id
                        ),
                        json!({ "family": family.id, "why": e }),
                    );
                    skipped.push(json!({
                        "id": format!("{}:*", family.id), "family": family.id,
                        "message": format!("this family could not be read: {}", e),
                    }));
                    continue;
                }
            };
            for r in rows {
                let rid = string_of(r.get("id"));
                let sid = string_of(r.get("sessionId"));
                let with_session = family.ends_with_session
                    && !sid.is_empty()
                    && ctx.ending_sessions.contains(&sid);
                if !global && !wanted_set.contains(&rid) && !with_session {
                    continue;
                }
                unknown.retain(|u| *u != rid);
                let kind = r.get("kind").cloned().unwrap_or(Value::Null);
                let label = r.get("label").cloned().unwrap_or(Value::Null);
                if global
                    && opts.spare_credentials
                    && Logout::leaves_credential(family, &r)
                {
                    skipped.push(json!({
                        "id": rid, "family": family.id, "kind": kind,
                        "label": label,
                        "message": "a sign-out at /logout leaves verifiable \
                                    credentials and the DIDs they are bound \
                                    to alone. Tick this row to end it.",
                    }));
                    continue;
                }
                if !truthy(r.get("terminable")) {
                    let why = or_empty(r.get("why"));
                    skipped.push(json!({
                        "id": rid, "family": family.id, "kind": kind,
                        "label": label,
                        "message": if why.is_empty() {
                            "this cannot be ended".to_string()
                        } else {
                            why
                        },
                    }));
                    continue;
                }
                let outcome = match self.end_row(family.id, &r, &mut ctx) {
                    Ok(o) => o,
                    Err(e) => {
                        tracing::warn!(
                            "{}logout: ending {} failed: {}",
                            sts_core::log::tag(codes::STS_LOGOUT_0006),
                            rid,
                            e
                        );
                        self.audit_failure(
                            codes::STS_LOGOUT_0006.as_str(),
                            channel,
                            &ctx.key,
                            format!(
                                "Ending one {} item during a sign-out failed",
                                family.id
                            ),
                            json!({ "family": family.id,
                                    "kind": or_empty(r.get("kind")),
                                    "why": e }),
                        );
                        no(format!("ending this failed: {}", e))
                    }
                };
                let mut entry = json!({
                    "id": rid, "family": family.id, "kind": kind,
                    "label": label, "message": outcome.message,
                });
                if outcome.pending {
                    entry["pending"] = json!(true);
                }
                if outcome.ok {
                    done.push(entry);
                } else {
                    skipped.push(entry);
                }
            }
        }
        let mut across = Vec::new();
        if global
            && truthy(Some(&self.setting("logout.ldapDisconnect")))
            && !ctx.key.is_empty()
        {
            let instructed = self.deps.ldap.sign_out_across_cluster(&ctx.key);
            if truthy(Some(&instructed)) {
                across.push(json!({
                    "family": "ldap", "at": at(&instructed, "at"),
                    "message": format!(
                        "every other node was instructed to close the \
                         directory connections bound as {}; each does when \
                         it applies the change log, after this answer",
                        ctx.key),
                }));
            }
        }
        let ids: Vec<String> =
            ctx.sessions.iter().map(|s| string_of(s.get("id"))).collect();
        let deliveries = self.deps.backchannel.deliveries_for(&ids, &mark);
        let summary = self.deps.backchannel.summarize(&deliveries);
        let mut families_done: Vec<String> = Vec::new();
        for one in &done {
            let f = string_of(one.get("family"));
            if !families_done.contains(&f) {
                families_done.push(f);
            }
        }
        let scope = if global { "global" } else { "selected" };
        host.audit(&json!({
            "action": if global { "logout.global" } else { "logout.selective" },
            "outcome": if done.is_empty() { "refused" } else { "success" },
            "errorCode": if done.is_empty() {
                codes::STS_LOGOUT_0007.as_str()
            } else {
                ""
            },
            "actor": if opts.actor.is_empty() { &ctx.key } else { &opts.actor },
            "protocol": "Logout",
            "channel": channel,
            "target": ctx.key,
            "summary": format!("{} for {} ended {} of {} live item(s)",
                if global { "a global logout" } else { "a selective logout" },
                ctx.key, done.len(), done.len() + skipped.len()),
            "detail": {
                "scope": scope,
                "requested": if global {
                    "everything".to_string()
                } else {
                    wanted.len().to_string()
                },
                "ended": done.len().to_string(),
                "couldNotEnd": skipped.len().to_string(),
                "namedNothing": unknown.len().to_string(),
                "families": families_done.join(", "),
                "by": if opts.by.is_empty() {
                    "the /logout endpoint"
                } else {
                    opts.by.as_str()
                },
            },
        }));
        let message = format!(
            "{}{}: {} item(s) ended{}{}.{}{}",
            if global { "Global logout for " } else { "Logout for " },
            ctx.key,
            done.len(),
            if skipped.is_empty() {
                String::new()
            } else {
                format!(", {} that could not be", skipped.len())
            },
            if unknown.is_empty() {
                String::new()
            } else {
                format!(", {} that named nothing", unknown.len())
            },
            if across.is_empty() {
                ""
            } else {
                " Other nodes were instructed to close this identity's \
                 directory connections and do so as they apply the change \
                 log."
            },
            if summary.is_empty() {
                String::new()
            } else {
                format!(" {}", summary)
            }
        );
        let mut result = json!({
            "ok": true, "key": ctx.key, "scope": scope,
            "terminated": done, "skipped": skipped, "unknown": unknown,
            "notifications": ctx.notifications, "cleanups": ctx.cleanups,
            "logoutRequests": ctx.logout_requests,
            "partnerLogouts": ctx.partner_logouts,
            "backchannel": deliveries, "message": message,
        });
        if !across.is_empty() {
            result["acrossCluster"] = Value::Array(across);
        }
        if opts.quiet {
            tracing::debug!("logout: {}", message);
        } else {
            tracing::info!("logout: {}", message);
        }
        if global && !opts.no_provider_command && !ctx.key.is_empty() {
            host.person_signed_out(&ctx.key);
        }
        Ok(result)
    }

    /// `revokeGrantsOf(key, opts)` (#432): a person's grants and tokens and
    /// NOTHING ELSE; nothing held is nothing ended, never a global
    /// sign-out. `session_ids` narrows it to what those sessions were
    /// issued.
    #[tracing::instrument(level = "debug", skip(self, opts))]
    pub fn revoke_grants_of(
        &self,
        key: &str,
        session_ids: Option<&[String]>,
        opts: &TerminateOptions,
    ) -> Result<Value, String> {
        let narrowed = session_ids.is_some();
        let sessions: HashSet<&String> =
            session_ids.unwrap_or(&[]).iter().collect();
        let families: &[&str] = if narrowed {
            &["token", "code", "gnap"]
        } else {
            &["oauth-grant", "token", "code", "gnap"]
        };
        let ids: Vec<String> = if key.is_empty() {
            Vec::new()
        } else {
            let mut ctx = self.context_for(key, "", "", "", None)?;
            self.all_rows(&mut ctx)
                .into_iter()
                .filter(|r| {
                    let sid = string_of(r.get("sessionId"));
                    families.contains(&string_of(r.get("family")).as_str())
                        && truthy(r.get("terminable"))
                        && (!narrowed
                            || (!sid.is_empty() && sessions.contains(&sid)))
                })
                .map(|r| string_of(r.get("id")))
                .collect()
        };
        if ids.is_empty() {
            return Ok(json!({ "ok": true, "key": key, "scope": "selected",
                "terminated": [], "skipped": [], "unknown": [],
                "message": format!("Nothing to revoke for {}.", key) }));
        }
        let mut o = opts.clone();
        o.no_provider_command = true;
        self.terminate(key, &ids, &o)
    }

    /// `endFactorSessions(username, factor, opts)` (#722): the sessions a
    /// removed credential signed in, with the tokens and codes issued on
    /// them; every other session stays.
    #[tracing::instrument(level = "debug", skip(self, opts))]
    pub fn end_factor_sessions(
        &self,
        username: &str,
        factor: &Value,
        opts: &TerminateOptions,
    ) -> Value {
        let kind = or_empty(factor.get("kind"));
        let key = if username.is_empty() {
            String::new()
        } else {
            self.deps.stats.identity_key_of(username)
        };
        let none = json!({ "ok": true, "sessionsEnded": 0, "itemsEnded": 0,
                           "failed": 0, "sessionIds": [], "message": "" });
        if key.is_empty() || kind.is_empty() {
            return none;
        }
        let channel = if opts.channel.is_empty() {
            "http".to_string()
        } else {
            opts.channel.clone()
        };
        let mut ended: Vec<String> = Vec::new();
        let attempt = (|| -> Result<Option<Value>, String> {
            let mut ctx = self.context_for(&key, "", "", "", None)?;
            for session in &ctx.sessions {
                if self.deps.authn.session_names_factor(session, factor) {
                    ended.push(string_of(session.get("id")));
                }
            }
            if ended.is_empty() {
                return Ok(None);
            }
            let mut selection: Vec<String> =
                ended.iter().map(|id| format!("session:{}", id)).collect();
            for r in self.all_rows(&mut ctx) {
                let fam = string_of(r.get("family"));
                let sid = string_of(r.get("sessionId"));
                if (fam == "token" || fam == "code")
                    && truthy(r.get("terminable"))
                    && !sid.is_empty()
                    && ended.contains(&sid)
                {
                    selection.push(string_of(r.get("id")));
                }
            }
            let mut o = opts.clone();
            o.no_provider_command = true;
            self.terminate(&key, &selection, &o).map(Some)
        })();
        let result = match attempt {
            Ok(None) => return none,
            Ok(Some(r)) => r,
            Err(e) => {
                tracing::error!(
                    "{}logout: ending the sessions a removed {} credential \
                     of {} signed in threw: {}",
                    sts_core::log::tag(codes::STS_AUTHN_0371),
                    kind,
                    username,
                    e
                );
                self.audit_failure(
                    codes::STS_AUTHN_0371.as_str(),
                    &channel,
                    &key,
                    "The sessions a removed credential signed in could not \
                     be ended"
                        .into(),
                    json!({ "factor": kind, "why": e }),
                );
                return json!({ "ok": false, "sessionsEnded": 0,
                    "itemsEnded": 0, "failed": ended.len(),
                    "sessionIds": [],
                    "message": "The sessions it signed in could not be ended." });
            }
        };
        let still: Vec<String> = ended
            .iter()
            .filter(|id| self.deps.authn.session_by_id(id).is_some())
            .cloned()
            .collect();
        if !still.is_empty() {
            tracing::warn!(
                "{}logout: {} session(s) a removed {} credential of {} \
                 signed in are still live after the sign-out; the removal \
                 stands.",
                sts_core::log::tag(codes::STS_AUTHN_0370),
                still.len(),
                kind,
                username
            );
            self.audit_failure(
                codes::STS_AUTHN_0370.as_str(),
                &channel,
                &key,
                format!(
                    "{} session(s) a removed credential signed in could not \
                     be ended",
                    still.len()
                ),
                json!({ "factor": kind, "sessions": still.join(", ") }),
            );
        }
        let gone: Vec<String> =
            ended.iter().filter(|id| !still.contains(id)).cloned().collect();
        json!({ "ok": still.is_empty(), "sessionsEnded": gone.len(),
            "itemsEnded": list_of(result.get("terminated")).len(),
            "failed": still.len(), "sessionIds": gone,
            "message": format!("{} session(s) it signed in ended{}.",
                gone.len(),
                if still.is_empty() {
                    String::new()
                } else {
                    format!(", {} could not be", still.len())
                }) })
    }

    /// `endOneSession(session, options)`: the session and the relying
    /// parties riding on it — never the partner's row, never the person's
    /// other sessions.
    fn end_one_session(
        &self,
        session: &Value,
        opts: TerminateOptions,
    ) -> Result<Value, String> {
        let key = self.session_holder(session);
        let mut ctx = self.context_for(&key, &opts.issuer, "", "", None)?;
        let sid = string_of(session.get("id"));
        let riding = ["oidc-rp", "wsfed-rp", "saml2-sp"];
        let mut selection = vec![format!("session:{}", sid)];
        for r in self.all_rows(&mut ctx) {
            if string_of(r.get("sessionId")) == sid
                && riding.contains(&string_of(r.get("family")).as_str())
            {
                selection.push(string_of(r.get("id")));
            }
        }
        let o = TerminateOptions {
            issuer: opts.issuer,
            by: opts.by.clone(),
            actor: opts.by,
            initiating_entity: opts.initiating_entity,
            channel: opts.channel,
            ..TerminateOptions::default()
        };
        self.terminate(&key, &selection, &o)
    }

    /// `endPartnerSession(session, opts)` (#167).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn end_partner_session(
        &self,
        session: &Value,
        opts: &TerminateOptions,
    ) -> Result<Value, String> {
        let mut o = opts.clone();
        if o.initiating_entity.is_empty() {
            o.initiating_entity = "user".into();
        }
        if o.channel.is_empty() {
            o.channel = "http".into();
        }
        self.end_one_session(session, o)
    }

    /// `endBoundSession(session, opts)` (#725).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn end_bound_session(
        &self,
        session: &Value,
        opts: &TerminateOptions,
    ) -> Result<Value, String> {
        let mut o = opts.clone();
        o.issuer = String::new();
        if o.by.is_empty() {
            o.by = "a device-bound session refresh".into();
        }
        if o.initiating_entity.is_empty() {
            o.initiating_entity = "policy".into();
        }
        if o.channel.is_empty() {
            o.channel = "http".into();
        }
        self.end_one_session(session, o)
    }

    /// `describedFamilies()`: the prose, for the console and the API.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn described_families(&self) -> Vec<Value> {
        FAMILIES
            .iter()
            .map(|f| {
                json!({ "id": f.id, "label": f.label, "protocol": f.protocol,
                        "spec": f.spec, "what": f.what, "terminable": true })
            })
            .collect()
    }
}
