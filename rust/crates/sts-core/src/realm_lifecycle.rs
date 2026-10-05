// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! A trust realm's life (`common/realms.js`): created, its settings changed
//! one at a time or whole, marked as retiring, and removed with everything
//! it held.
//!
//! * **A realm's settings are a layer over the service's** — the realm
//!   layer of [`Settings`], answered here. A realm can never carry a
//!   `realms.*` setting (how it was reached) or a per-process one (a property
//!   of the OS process, which one realm's value would set for every realm),
//!   and every writing door asks the same predicate.
//! * **What a write would mean is asked IN the realm it would land in**, with
//!   the value in place: a candidate realm whose overrides are the realm's
//!   plus the write, so a product-mode realm refuses a development-only
//!   value (`STS-CORE-0103`) whatever the service's mode.
//! * **Names that must be distinct are seeded from the realm's domain** —
//!   entityIDs, issuers, the SPIFFE trust domain, the Kerberos realm — and
//!   the things that bind sockets or mint credentials another service will
//!   believe are seeded OFF (Kerberos, SPIFFE, its listeners and admins).
//! * **A realm is removed in four steps (#262)**: marked retiring (refusing
//!   new sign-ins and issuance, `STS-CORE-0121`), each owner's `mark`, then
//!   `announce` and `deliver` bounded by `realms.removalDeliveryTimeoutS`,
//!   then the stores purged. What was not delivered is reported, never
//!   waited for past the bound.
//! * **A restored or replicated realm is not asked** the rules between
//!   settings: the process that made the change already was, and refusing
//!   it here would leave two processes holding different realms.
//!
//! Rules another module owns — Kerberos realm names, a realm's listener,
//! the certificate authority's pinned signers — are [`RealmRule`]s that
//! module registers; this module knows none of them by name.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use chrono::{TimeZone, Utc};
use serde_json::{Map, Value as Json};

use crate::errors::{codes, ErrorCode};
use crate::log::tag;
use crate::mode::Mode;
use crate::realm::{
    self, normalize_domain, Realm, RealmRegistry, Refusals, DEFAULT_ID,
};
use crate::settings::{RealmLayer, Settings};

/// How long past its delivery bound a retiring realm is still "in
/// progress" rather than "interrupted".
pub const RETIRING_GRACE_MS: f64 = 30_000.0;

pub type Overrides = Map<String, Json>;
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// What happened to a realm, for whoever watches (the store writes the
/// registry down; the certificate authority builds a branch for a realm
/// created here and not for one only restored).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealmEvent {
    pub id: String,
    /// `create`, `update`, `set-override`, `clear-override`, `retire`,
    /// `remove`.
    pub what: &'static str,
    pub restored: bool,
    pub created_at: Option<i64>,
}

/// A rule between a realm's settings that another module owns: the realm's
/// overrides as they would be after the write, and as they are.
pub trait RealmRule: Send + Sync {
    fn problem(
        &self,
        id: &str,
        after: &Overrides,
        before: &Overrides,
    ) -> Option<(ErrorCode, String)>;
}

/// What a removal owes before the realm goes.
pub struct RetireContext {
    pub realm_id: String,
    /// Milliseconds since the epoch, by the lifecycle's clock.
    pub deadline: f64,
    pub via: String,
    pub initiating_entity: String,
    /// What could not be delivered: `(what, count)`.
    pub undelivered: Mutex<Vec<(String, u64)>>,
}

/// An owner's part in a removal, by name. Each step is optional.
pub trait Retirer: Send + Sync {
    fn name(&self) -> &str;
    /// Marks what the realm holds as ending (bounded).
    fn mark<'a>(
        &'a self,
        _id: &'a str,
        _ctx: &'a RetireContext,
    ) -> Option<BoxFuture<'a, Result<(), String>>> {
        None
    }
    /// Announces the end, synchronously.
    fn announce(&self, _id: &str, _ctx: &RetireContext) -> Result<(), String> {
        Ok(())
    }
    /// Delivers what is owed (bounded).
    fn deliver<'a>(
        &'a self,
        _id: &'a str,
        _ctx: &'a RetireContext,
    ) -> Option<BoxFuture<'a, Result<(), String>>> {
        None
    }
}

/// What a removal could not finish, reported with the removal.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Retirement {
    pub late: Vec<String>,
    pub failed: Vec<String>,
    pub undelivered: Vec<(String, u64)>,
    pub bound_seconds: i64,
}

/// A realm being removed, as the pages and refusals describe it.
#[derive(Clone, Debug, PartialEq)]
pub struct RetiringState {
    pub since: f64,
    pub since_iso: String,
    pub in_progress: bool,
    pub finishes_by: f64,
    pub why: String,
    pub finish: String,
}

/// A refusal as Node's `{ ok: false, errors }` with its code.
pub type Refused = Refusals;

fn refused(code: ErrorCode, errors: Vec<String>) -> Refused {
    Refusals {
        code: Some(code),
        sentences: errors,
    }
}

fn iso(ms: f64) -> String {
    Utc.timestamp_millis_opt(ms as i64)
        .single()
        .map(|t| t.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())
        .unwrap_or_default()
}

/// `String(v)` of a setting's value.
fn text_of(v: &Json) -> String {
    match v {
        Json::Null => String::new(),
        Json::String(s) => s.clone(),
        other => other.to_string(),
    }
}

thread_local! {
    // The candidate realm a write is asked in: every step between setting it
    // and the answer is synchronous, so a value on the thread is right.
    static CANDIDATE: RefCell<Option<Arc<HashMap<String, Json>>>> = const { RefCell::new(None) };
}

struct Held {
    overrides: Overrides,
    /// The same, as the settings' realm layer reads it: rebuilt on each
    /// write so a read copies nothing.
    layer: Arc<HashMap<String, Json>>,
    retiring_since: f64,
}

impl Held {
    fn new(overrides: Overrides) -> Held {
        let layer = Arc::new(
            overrides
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        );
        Held {
            overrides,
            layer,
            retiring_since: 0.0,
        }
    }

    fn rebuild(&mut self) {
        self.layer = Arc::new(
            self.overrides
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        );
    }
}

type Builder = Arc<dyn Fn(&str, &Arc<Realm>) + Send + Sync>;
type Watcher = Arc<dyn Fn(&RealmEvent) + Send + Sync>;
type Purge = Arc<dyn Fn(&str) + Send + Sync>;

/// Every realm's life, and the realm layer of the settings.
pub struct RealmLifecycle {
    registry: Arc<RealmRegistry>,
    settings: Arc<Settings>,
    mode: Arc<Mode>,
    held: RwLock<HashMap<String, Held>>,
    retiring_here: Mutex<HashSet<String>>,
    retired: Mutex<HashSet<String>>,
    builders: RwLock<Vec<Builder>>,
    watchers: RwLock<Vec<Watcher>>,
    purges: RwLock<Vec<Purge>>,
    retirers: RwLock<Vec<Arc<dyn Retirer>>>,
    rules: RwLock<Vec<Arc<dyn RealmRule>>>,
    clock: Arc<dyn Fn() -> f64 + Send + Sync>,
}

/// The names that must be distinct, from the realm's domain.
fn named_by_realm(
    domain: &str,
    id: &str,
    base: impl Fn(&str) -> String,
) -> Vec<(&'static str, Json)> {
    let client = base("oid4vp.clientId");
    vec![
        (
            "saml2.entityId",
            Json::String(format!("urn:{}:idp", domain)),
        ),
        (
            "saml11.providerId",
            Json::String(format!("urn:{}:idp:saml11", domain)),
        ),
        (
            "wsfed.entityId",
            Json::String(format!("urn:{}:sts", domain)),
        ),
        (
            "wstrust.issuer",
            Json::String(format!("urn:{}:sts", domain)),
        ),
        ("saml.issuer", Json::String(format!("urn:{}:sts", domain))),
        (
            "oid4vp.clientId",
            Json::String(if client.is_empty() {
                String::new()
            } else {
                format!("{}-{}", client, id)
            }),
        ),
        ("spiffe.trustDomain", Json::String(domain.to_string())),
        ("krb5.realm", Json::String(domain.to_uppercase())),
    ]
}

/// `/tmp/spire-agent/public/api.sock` for the default realm becomes
/// `/tmp/spire-agent/public/acme/api.sock`: two realms cannot bind one path.
fn socket_path_for(base: &str, id: &str) -> String {
    if base.is_empty() {
        return String::new();
    }
    match base.rfind('/') {
        None => format!("{}-{}", id, base),
        Some(cut) => format!("{}/{}{}", &base[..cut], id, &base[cut..]),
    }
}

impl RealmLifecycle {
    /// The lifecycle over a registry, installed as the settings' realm
    /// layer.
    pub fn new(
        registry: Arc<RealmRegistry>,
        settings: Arc<Settings>,
        mode: Arc<Mode>,
    ) -> Arc<RealmLifecycle> {
        RealmLifecycle::with_clock(
            registry,
            settings,
            mode,
            Arc::new(crate::time::now_ms_f64),
        )
    }

    /// The same, with the clock a retiring state is measured by.
    pub fn with_clock(
        registry: Arc<RealmRegistry>,
        settings: Arc<Settings>,
        mode: Arc<Mode>,
        clock: Arc<dyn Fn() -> f64 + Send + Sync>,
    ) -> Arc<RealmLifecycle> {
        let me = Arc::new(RealmLifecycle {
            registry,
            settings: settings.clone(),
            mode,
            held: RwLock::new(HashMap::new()),
            retiring_here: Mutex::new(HashSet::new()),
            retired: Mutex::new(HashSet::new()),
            builders: RwLock::new(Vec::new()),
            watchers: RwLock::new(Vec::new()),
            purges: RwLock::new(Vec::new()),
            retirers: RwLock::new(Vec::new()),
            rules: RwLock::new(Vec::new()),
            clock,
        });
        if !settings.set_realm_layer(me.clone()) {
            tracing::warn!("realms: the settings already had a realm layer; this lifecycle's is not it.");
        }
        me
    }

    fn now(&self) -> f64 {
        (self.clock)()
    }

    pub fn registry(&self) -> &Arc<RealmRegistry> {
        &self.registry
    }

    /// The mode the realms are served in.
    pub fn mode(&self) -> &Arc<Mode> {
        &self.mode
    }

    // -----------------------------------------------------------------
    // Hooks.
    // -----------------------------------------------------------------

    /// A store that builds itself for each new realm.
    pub fn on_create(&self, f: Builder) {
        self.builders
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .push(f);
    }

    /// A watcher of every change.
    pub fn on_change(&self, f: Watcher) {
        self.watchers
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .push(f);
    }

    /// A store that purges a removed realm.
    pub fn on_remove(&self, f: Purge) {
        self.purges
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .push(f);
    }

    /// An owner's part in a removal.
    pub fn on_retire(&self, r: Arc<dyn Retirer>) {
        self.retirers
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .push(r);
    }

    /// A rule between a realm's settings that another module owns.
    pub fn add_rule(&self, r: Arc<dyn RealmRule>) {
        self.rules
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .push(r);
    }

    fn changed(
        &self,
        id: &str,
        what: &'static str,
        restored: bool,
        created_at: Option<i64>,
    ) {
        let event = RealmEvent {
            id: id.to_string(),
            what,
            restored,
            created_at,
        };
        let watchers = self
            .watchers
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        for w in watchers {
            if catch_unwind(AssertUnwindSafe(|| w(&event))).is_err() {
                tracing::warn!(
                    "{}realms: a change watcher failed for \"{}\" ({}).",
                    tag(codes::STS_CORE_0018),
                    id,
                    what
                );
            }
        }
    }

    // -----------------------------------------------------------------
    // Reading.
    // -----------------------------------------------------------------

    /// A restored realm reports when it was really defined, not when this
    /// process last started.
    pub fn set_created_at(&self, id: &str, ms: i64) {
        if let Some(realm) = self.registry.get(id).filter(|r| !r.builtin) {
            let mut next = (*realm).clone();
            next.created_at = Some(ms);
            self.registry.insert(next);
        }
    }

    /// A defined realm's overrides; `None` for the default realm (which
    /// carries none: it IS the service) and for one not defined.
    pub fn overrides(&self, id: &str) -> Option<Overrides> {
        self.held
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(id)
            .map(|h| h.overrides.clone())
    }

    /// The realm row as it is written down: everything but `builtin`.
    pub fn row(&self, id: &str) -> Option<Json> {
        let realm = self.registry.get(id).filter(|r| !r.builtin)?;
        let held = self.held.read().unwrap_or_else(PoisonError::into_inner);
        let h = held.get(id)?;
        let mut row = Map::new();
        row.insert("id".into(), Json::String(realm.id.clone()));
        row.insert("name".into(), Json::String(realm.name.clone()));
        row.insert(
            "description".into(),
            Json::String(realm.description.clone()),
        );
        row.insert("domain".into(), Json::String(realm.domain.clone()));
        row.insert(
            "createdAt".into(),
            realm.created_at.map_or(Json::Null, Json::from),
        );
        row.insert("overrides".into(), Json::Object(h.overrides.clone()));
        row.insert(
            "retiringSince".into(),
            if h.retiring_since > 0.0 {
                Json::from(h.retiring_since)
            } else {
                Json::Null
            },
        );
        Some(Json::Object(row))
    }

    /// Every realm row but the default's, in the registry's order.
    pub fn rows(&self) -> Vec<Json> {
        self.registry
            .list()
            .iter()
            .filter_map(|r| self.row(&r.id))
            .collect()
    }

    /// Whether a removed realm's rows are refused (it was removed and not
    /// defined again).
    pub fn accepts_rows(&self, id: &str) -> bool {
        !self
            .retired
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(id)
    }

    // -----------------------------------------------------------------
    // The checks.
    // -----------------------------------------------------------------

    /// Why a realm may not carry `key = raw`, and the code.
    pub fn check_realm_override(
        &self,
        key: &str,
        raw: &Json,
    ) -> Option<(ErrorCode, String)> {
        if key.starts_with("realms.") {
            return Some((
                codes::STS_CORE_0014,
                format!(
                    "\"{}\" cannot be set on one realm: it is what decides whether realms exist and where they \
                     are found, so a realm carrying it would be changing how it was reached half way through the \
                     request that reached it. Set it on the service as a whole — /admin/oauth2, or POST \
                     /admin-api/config/set.",
                    key
                ),
            ));
        }
        if Settings::is_per_process(key) {
            return Some((
                codes::STS_CORE_0015,
                format!(
                    "\"{}\" cannot be set on one realm: it is a property of this OS PROCESS rather than of how a \
                     realm behaves, so a realm carrying it would be setting it for every other realm as well. Set \
                     it on the service as a whole — /admin/config, or POST /admin-api/config/set.",
                    key
                ),
            ));
        }
        self.settings
            .check_override(key, raw, Some(true))
            .map(|r| (r.code, r.problem))
    }

    fn check_overrides(&self, overrides: &Overrides) -> Refused {
        let mut out = Refusals::default();
        for (key, raw) in overrides {
            if let Some((code, problem)) = self.check_realm_override(key, raw) {
                out.code.get_or_insert(code);
                out.sentences.push(problem);
            }
        }
        out
    }

    /// Runs `f` with a candidate realm whose overrides are `overrides` as
    /// the ambient realm's.
    fn in_candidate<R>(
        &self,
        overrides: &Overrides,
        f: impl FnOnce() -> R,
    ) -> R {
        let map: HashMap<String, Json> = overrides
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let saved = CANDIDATE.with(|c| c.replace(Some(Arc::new(map))));
        let answer = catch_unwind(AssertUnwindSafe(f));
        CANDIDATE.with(|c| *c.borrow_mut() = saved);
        match answer {
            Ok(a) => a,
            Err(p) => std::panic::resume_unwind(p),
        }
    }

    /// The mode's refusals of `writes`, asked in the realm with them in place.
    fn mode_write_problems(
        &self,
        current: &Overrides,
        writes: &Overrides,
    ) -> Refused {
        let mut merged = current.clone();
        for (k, v) in writes {
            merged.insert(k.clone(), v.clone());
        }
        self.in_candidate(&merged, || {
            let mut out = Refusals::default();
            for (key, raw) in writes {
                if let Some(r) = self.mode.write_problem(key, raw) {
                    out.code.get_or_insert(r.code);
                    out.sentences.push(r.problem);
                }
            }
            out
        })
    }

    /// Clearing `pki.pinnedSigners` on a realm falls back to the service's
    /// value, which the mode is asked about in the realm as it would be.
    fn pinned_signer_clear_problems(
        &self,
        before: &Overrides,
        after: &Overrides,
    ) -> Refused {
        let key = "pki.pinnedSigners";
        if !before.contains_key(key) || after.contains_key(key) {
            return Refusals::default();
        }
        self.in_candidate(after, || {
            let falls_back =
                Json::String(self.settings.value_of(key).as_str().to_string());
            match self.mode.check_write(key, &falls_back, Some(true)) {
                Some(r) => refused(r.code, vec![r.problem]),
                None => Refusals::default(),
            }
        })
    }

    fn rule_problem(
        &self,
        id: &str,
        after: &Overrides,
        before: &Overrides,
    ) -> Option<Refused> {
        let rules = self
            .rules
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        rules
            .iter()
            .find_map(|r| r.problem(id, after, before))
            .map(|(code, problem)| refused(code, vec![problem]))
    }

    /// The names and defaults a new realm starts with.
    pub fn seeded(&self, id: &str, domain: &str) -> Overrides {
        // Read OUTSIDE any realm: the process's value, not the value of the
        // realm whose request is creating this one.
        let base = |key: &str| {
            realm::run_sync(self.registry.default_realm(), || {
                text_of(&setting_json(&self.settings, key))
            })
        };
        let mut out = Overrides::new();
        for (key, value) in named_by_realm(domain, id, base) {
            if value.as_str().is_some_and(|s| !s.is_empty()) {
                out.insert(key.to_string(), value);
            }
        }
        let seeded: [(&str, Json, bool); 9] = [
            ("krb5.enabled", Json::Bool(false), false),
            ("spiffe.enabled", Json::Bool(false), false),
            (
                "spiffe.workloadSocket",
                Json::String(socket_path_for(
                    &base("spiffe.workloadSocket"),
                    id,
                )),
                false,
            ),
            (
                "spiffe.serverSocket",
                Json::String(socket_path_for(&base("spiffe.serverSocket"), id)),
                false,
            ),
            ("spiffe.workloadPort", Json::from(0), false),
            ("spiffe.serverPort", Json::from(0), false),
            ("spiffe.adminIds", Json::String(String::new()), true),
            ("spiffe.brokerPort", Json::from(0), false),
            ("spiffe.brokers", Json::String(String::new()), true),
        ];
        for (key, value, keep_empty) in seeded {
            if value != Json::String(String::new()) || keep_empty {
                out.insert(key.to_string(), value);
            }
        }
        out
    }

    // -----------------------------------------------------------------
    // Creating and changing.
    // -----------------------------------------------------------------

    /// Defines a realm, builds its stores and announces it. `restored`: a
    /// realm read back from the store or another process, which is not asked
    /// the rules between settings.
    pub fn create(
        &self,
        id: &str,
        name: &str,
        description: &str,
        domain: &str,
        overrides: &Overrides,
        restored: bool,
    ) -> Result<Arc<Realm>, Refused> {
        let id = id.trim().to_lowercase();
        let errors = self.registry.validate_id(&id);
        if !errors.sentences.is_empty() {
            return Err(errors);
        }
        let asked = normalize_domain(domain);
        let domain = if asked.is_empty() {
            normalize_domain(&format!(
                "{}.{}",
                id,
                self.registry.domain_of(&self.registry.default_realm())
            ))
        } else {
            asked
        };
        let errors = self.registry.validate_domain(&domain, &id);
        if !errors.sentences.is_empty() {
            return Err(errors);
        }
        let errors = self.check_overrides(overrides);
        if !errors.sentences.is_empty() {
            return Err(errors);
        }
        let seeded = self.seeded(&id, &domain);
        if !restored {
            let mut errors =
                self.mode_write_problems(&Overrides::new(), overrides);
            if !errors.sentences.is_empty() {
                errors.code.get_or_insert(codes::STS_CORE_0103);
                return Err(errors);
            }
            let mut after = seeded.clone();
            for (k, v) in overrides {
                after.insert(k.clone(), v.clone());
            }
            if let Some(r) = self.rule_problem(&id, &after, &Overrides::new()) {
                return Err(r);
            }
        }
        let mut all = seeded;
        for (k, v) in overrides {
            all.insert(k.clone(), v.clone());
        }
        let name = name.trim();
        let realm = Realm {
            id: id.clone(),
            name: if name.is_empty() {
                id.clone()
            } else {
                name.to_string()
            },
            description: description.trim().to_string(),
            builtin: false,
            created_at: Some(self.now() as i64),
            domain,
        };
        self.held
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id.clone(), Held::new(all));
        let realm = self.registry.insert(realm);
        self.retired
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&id);
        tracing::info!(
            "realms: \"{}\" defined; its endpoints are under {}/.",
            id,
            self.registry.prefix_of(&realm)
        );
        // After the row is written: a builder may read the realm back, and
        // one that fails leaves a realm that exists rather than half of one.
        let builders = self
            .builders
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        for b in builders {
            if catch_unwind(AssertUnwindSafe(|| b(&id, &realm))).is_err() {
                tracing::warn!(
                    "{}realms: a store could not build itself for \"{}\".",
                    tag(codes::STS_CORE_0019),
                    id
                );
            }
        }
        self.changed(&id, "create", restored, None);
        Ok(realm)
    }

    fn not_defined(id: &str) -> Refused {
        refused(
            codes::STS_CORE_0013,
            vec![format!("No realm called \"{}\" is defined.", id)],
        )
    }

    /// Changes a realm's name, description or whole override object. The
    /// domain is fixed at creation; `replicated` marks another process's
    /// change, which may also carry its retiring mark.
    #[allow(clippy::too_many_arguments)]
    pub fn update(
        &self,
        id: &str,
        name: Option<&str>,
        description: Option<&str>,
        overrides: Option<&Overrides>,
        domain: Option<&str>,
        replicated: bool,
        retiring_since: Option<f64>,
    ) -> Result<Arc<Realm>, Refused> {
        let Some(realm) = self.registry.get(id).filter(|r| !r.builtin) else {
            return Err(RealmLifecycle::not_defined(id));
        };
        if let Some(d) = domain.filter(|d| !d.is_empty()) {
            if normalize_domain(d) != realm.domain {
                return Err(refused(
                    codes::STS_CORE_0101,
                    vec![format!(
                        "The \"{}\" realm's domain is {} and is fixed when the realm is created: it is in every DN \
                         in its directory, every SPIFFE ID its authority issued and every key its KDC holds. Remove \
                         the realm and create it again under the new domain.",
                        realm.id, realm.domain
                    )],
                ));
            }
        }
        let before = self.overrides(&realm.id).unwrap_or_default();
        if let Some(next) = overrides {
            let errors = self.check_overrides(next);
            if !errors.sentences.is_empty() {
                return Err(errors);
            }
            if !replicated {
                let mode = self.mode_write_problems(&Overrides::new(), next);
                let pinned = self.pinned_signer_clear_problems(&before, next);
                if !mode.sentences.is_empty() || !pinned.sentences.is_empty() {
                    let code = mode
                        .code
                        .or(pinned.code)
                        .unwrap_or(codes::STS_CORE_0103);
                    return Err(refused(
                        code,
                        mode.sentences
                            .into_iter()
                            .chain(pinned.sentences)
                            .collect(),
                    ));
                }
                if let Some(r) = self.rule_problem(&realm.id, next, &before) {
                    return Err(r);
                }
            }
        }
        {
            let mut held =
                self.held.write().unwrap_or_else(PoisonError::into_inner);
            if let Some(h) = held.get_mut(&realm.id) {
                if let Some(next) = overrides {
                    h.overrides = next.clone();
                    h.rebuild();
                }
                // The retiring mark arrives only on a replicated update, and
                // only ever sets it.
                if replicated
                    && retiring_since.is_some_and(|s| s > 0.0)
                    && h.retiring_since <= 0.0
                {
                    h.retiring_since = retiring_since.unwrap_or(0.0);
                    tracing::info!(
                        "realms: \"{}\" is being removed by another process; new sign-ins and issuance in it are \
                         refused here too.",
                        realm.id
                    );
                }
            }
        }
        let mut next = (*realm).clone();
        if let Some(n) = name {
            let n = n.trim();
            next.name = if n.is_empty() {
                realm.id.clone()
            } else {
                n.to_string()
            };
        }
        if let Some(d) = description {
            next.description = d.trim().to_string();
        }
        let realm = self.registry.insert(next);
        tracing::info!("realms: \"{}\" updated.", realm.id);
        self.changed(&realm.id, "update", false, None);
        Ok(realm)
    }

    /// Sets one setting on one realm.
    pub fn set_override(
        &self,
        id: &str,
        key: &str,
        raw: Json,
    ) -> Result<(), Refused> {
        let Some(before) = self.overrides(id) else {
            return Err(RealmLifecycle::not_defined(id));
        };
        if let Some((code, problem)) = self.check_realm_override(key, &raw) {
            return Err(refused(code, vec![problem]));
        }
        let mut write = Overrides::new();
        write.insert(key.to_string(), raw.clone());
        let mut mode = self.mode_write_problems(&before, &write);
        if !mode.sentences.is_empty() {
            mode.code.get_or_insert(codes::STS_CORE_0103);
            return Err(mode);
        }
        let mut after = before.clone();
        after.insert(key.to_string(), raw.clone());
        if let Some(r) = self.rule_problem(id, &after, &before) {
            return Err(r);
        }
        if let Some(h) = self
            .held
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .get_mut(id)
        {
            h.overrides.insert(key.to_string(), raw);
            h.rebuild();
        }
        tracing::info!("realms: \"{}\" sets {}.", id, key);
        self.changed(id, "set-override", false, None);
        Ok(())
    }

    /// Clears one setting on one realm, so it comes from the service again.
    pub fn clear_override(&self, id: &str, key: &str) -> Result<(), Refused> {
        let Some(before) = self.overrides(id) else {
            return Err(RealmLifecycle::not_defined(id));
        };
        if !before.contains_key(key) {
            return Err(refused(
                codes::STS_CORE_0016,
                vec![format!(
                    "\"{}\" is not set on realm \"{}\"; it already comes from what the whole service is configured \
                     with.",
                    key, id
                )],
            ));
        }
        let mut after = before.clone();
        after.shift_remove(key);
        let mut pinned = self.pinned_signer_clear_problems(&before, &after);
        if !pinned.sentences.is_empty() {
            pinned.code.get_or_insert(codes::STS_PKI_0215);
            return Err(pinned);
        }
        if let Some(r) = self.rule_problem(id, &after, &before) {
            return Err(r);
        }
        if let Some(h) = self
            .held
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .get_mut(id)
        {
            h.overrides.shift_remove(key);
            h.rebuild();
        }
        tracing::info!("realms: \"{}\" no longer sets {}.", id, key);
        self.changed(id, "clear-override", false, None);
        Ok(())
    }

    // -----------------------------------------------------------------
    // Retiring and removing (#262).
    // -----------------------------------------------------------------

    fn removal_bound_ms(&self) -> f64 {
        let s = realm::run_sync(self.registry.default_realm(), || {
            self.settings
                .value_of("realms.removalDeliveryTimeoutS")
                .as_int()
        });
        (s.max(0) as f64) * 1000.0
    }

    /// Whether the realm is being removed.
    pub fn is_retiring(&self, id: &str) -> bool {
        self.held
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(id)
            .is_some_and(|h| h.retiring_since > 0.0)
    }

    /// A realm being removed, or `None`.
    pub fn retiring_state(&self, id: &str) -> Option<RetiringState> {
        let since = self
            .held
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(id)?
            .retiring_since;
        if since <= 0.0 {
            return None;
        }
        let finishes_by = since + self.removal_bound_ms() + RETIRING_GRACE_MS;
        let in_progress = self
            .retiring_here
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(id)
            || self.now() < finishes_by;
        let since_iso = iso(since);
        Some(RetiringState {
            since,
            in_progress,
            finishes_by,
            why: if in_progress {
                format!(
                    "The trust realm \"{}\" is being removed (the removal began at {}), so nothing new is signed in \
                     or issued in it.",
                    id, since_iso
                )
            } else {
                format!(
                    "The trust realm \"{}\" was being removed from {}, and that removal was interrupted before it \
                     finished — the process doing it stopped. Nothing new is signed in or issued in it until an \
                     administrator finishes the removal.",
                    id, since_iso
                )
            },
            finish: if in_progress {
                format!(
                    "Wait: the removal finishes by itself by {}.",
                    iso(finishes_by)
                )
            } else {
                format!(
                    "Remove the realm again — the Remove button on its page under /admin/realms, or POST \
                     /admin-api/realms/remove with {{\"id\": \"{}\"}}, from another realm. That ends what is still \
                     live in it, reports its people purged, and removes it.",
                    id
                )
            },
            since_iso,
        })
    }

    /// The refusal of anything new in a retiring realm (`STS-CORE-0121`).
    pub fn retiring_refusal(&self, id: &str) -> Option<(ErrorCode, String)> {
        if !self.is_retiring(id) {
            return None;
        }
        let why = self.retiring_state(id).map_or_else(
            || format!("The trust realm \"{}\" is being removed, so nothing new is signed in or issued in it.", id),
            |s| s.why,
        );
        Some((codes::STS_CORE_0121, why))
    }

    fn mark_retiring(&self, id: &str) {
        {
            let mut held =
                self.held.write().unwrap_or_else(PoisonError::into_inner);
            let Some(h) = held.get_mut(id) else {
                return;
            };
            if h.retiring_since > 0.0 {
                return;
            }
            h.retiring_since = self.now();
        }
        tracing::info!(
            "{}realms: \"{}\" is being removed; new sign-ins and issuance in it are refused from now on.",
            tag(codes::STS_CORE_0121),
            id
        );
        self.changed(id, "retire", false, None);
    }

    /// Removes a realm the way an administrator does: marked, its owners'
    /// steps within the bound, then removed whatever was left undelivered.
    pub async fn retire(
        &self,
        id: &str,
        via: Option<&str>,
        initiating_entity: Option<&str>,
    ) -> Result<(Arc<Realm>, Retirement), Refused> {
        let Some(realm) = self.registry.get(id).filter(|r| !r.builtin) else {
            return self.remove(id).map(|r| (r, Retirement::default()));
        };
        let already = self.retiring_state(&realm.id);
        if let Some(state) = already.as_ref().filter(|s| s.in_progress) {
            tracing::info!(
                "{}realms: a second removal of \"{}\" was refused: the one begun at {} is still in progress.",
                tag(codes::STS_CORE_0122),
                realm.id,
                state.since_iso
            );
            return Err(refused(
                codes::STS_CORE_0122,
                vec![format!(
                    "The trust realm \"{}\" is already being removed (since {}). {}",
                    realm.id, state.since_iso, state.finish
                )],
            ));
        }
        if let Some(state) = already {
            tracing::warn!(
                "{}realms: finishing the removal of \"{}\", which was begun at {} and interrupted.",
                tag(codes::STS_CORE_0123),
                realm.id,
                state.since_iso
            );
        }
        self.retiring_here
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(realm.id.clone());
        let out = self.retire_marked(&realm, via, initiating_entity).await;
        self.retiring_here
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&realm.id);
        out
    }

    async fn retire_marked(
        &self,
        realm: &Arc<Realm>,
        via: Option<&str>,
        initiating_entity: Option<&str>,
    ) -> Result<(Arc<Realm>, Retirement), Refused> {
        let bound = self.removal_bound_ms();
        let ctx = RetireContext {
            realm_id: realm.id.clone(),
            deadline: self.now() + bound,
            via: via.map_or_else(
                || format!("the removal of the trust realm \"{}\"", realm.id),
                str::to_string,
            ),
            initiating_entity: initiating_entity.unwrap_or("admin").to_string(),
            undelivered: Mutex::new(Vec::new()),
        };
        let mut failed = Vec::new();
        let mut late = Vec::new();
        self.mark_retiring(&realm.id);
        let retirers = self
            .retirers
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let left = |me: &RealmLifecycle| {
            std::time::Duration::from_millis(
                (ctx.deadline - me.now()).max(0.0) as u64
            )
        };
        for hook in &retirers {
            if let Some(work) =
                realm::run_sync(realm.clone(), || hook.mark(&realm.id, &ctx))
            {
                match tokio::time::timeout(
                    left(self),
                    realm::run(realm.clone(), work),
                )
                .await
                {
                    Err(_) => late.push(format!("{} (mark)", hook.name())),
                    Ok(Err(e)) => {
                        failed.push(format!("{} (mark): {}", hook.name(), e))
                    }
                    Ok(Ok(())) => {}
                }
            }
        }
        realm::run_sync(realm.clone(), || {
            for hook in &retirers {
                if let Err(e) = hook.announce(&realm.id, &ctx) {
                    failed.push(format!("{} (announce): {}", hook.name(), e));
                }
            }
        });
        for hook in &retirers {
            if let Some(work) =
                realm::run_sync(realm.clone(), || hook.deliver(&realm.id, &ctx))
            {
                match tokio::time::timeout(
                    left(self),
                    realm::run(realm.clone(), work),
                )
                .await
                {
                    Err(_) => late.push(hook.name().to_string()),
                    Ok(Err(e)) => {
                        failed.push(format!("{} (deliver): {}", hook.name(), e))
                    }
                    Ok(Ok(())) => {}
                }
            }
        }
        let undelivered: Vec<(String, u64)> = ctx
            .undelivered
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|(_, n)| *n > 0)
            .cloned()
            .collect();
        if !failed.is_empty() || !late.is_empty() || !undelivered.is_empty() {
            tracing::error!(
                "{}realms: before \"{}\" was removed, not everything it owed was delivered within \
                 realms.removalDeliveryTimeoutS ({} s){}{}{}. The realm is removed anyway, and what was queued for \
                 it goes with it.",
                tag(codes::STS_CORE_0120),
                realm.id,
                (bound / 1000.0).round(),
                if late.is_empty() { String::new() } else { format!("; still waiting: {}", late.join(", ")) },
                if undelivered.is_empty() {
                    String::new()
                } else {
                    format!(
                        "; undelivered: {}",
                        undelivered.iter().map(|(w, n)| format!("{} {}", n, w)).collect::<Vec<_>>().join(", ")
                    )
                },
                if failed.is_empty() { String::new() } else { format!("; failed: {}", failed.join("; ")) }
            );
        }
        let removed = self.remove(&realm.id)?;
        Ok((
            removed,
            Retirement {
                late,
                failed,
                undelivered,
                bound_seconds: (bound / 1000.0).round() as i64,
            },
        ))
    }

    /// Removes a realm and purges every store of it, at once.
    pub fn remove(&self, id: &str) -> Result<Arc<Realm>, Refused> {
        let Some(realm) = self.registry.get(id).filter(|r| !r.builtin) else {
            return Err(RealmLifecycle::not_defined(id));
        };
        self.registry.forget(&realm.id);
        self.held
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&realm.id);
        self.retired
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(realm.id.clone());
        let purges = self
            .purges
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        for p in purges {
            if catch_unwind(AssertUnwindSafe(|| p(&realm.id))).is_err() {
                tracing::warn!(
                    "{}realms: a store refused to purge \"{}\".",
                    tag(codes::STS_CORE_0020),
                    realm.id
                );
            }
        }
        tracing::info!(
            "realms: \"{}\" removed, with everything it held.",
            realm.id
        );
        self.changed(&realm.id, "remove", false, realm.created_at);
        Ok(realm)
    }
}

/// A setting's value as JSON, for the seeded names.
fn setting_json(settings: &Settings, key: &str) -> Json {
    use crate::settings::SettingValue;
    match settings.value_of(key) {
        SettingValue::Text(t) => Json::String(t),
        SettingValue::Int(n) => Json::from(n),
        SettingValue::Bool(b) => Json::Bool(b),
        SettingValue::List(l) => Json::String(l.join(",")),
    }
}

impl RealmLayer for RealmLifecycle {
    fn ambient_overrides(&self) -> Option<Arc<HashMap<String, Json>>> {
        if let Some(candidate) = CANDIDATE.with(|c| c.borrow().clone()) {
            return Some(candidate);
        }
        let id = realm::current_id();
        if id == DEFAULT_ID {
            return None;
        }
        let held = self.held.read().unwrap_or_else(PoisonError::into_inner);
        held.get(&id).map(|h| h.layer.clone())
    }
}
