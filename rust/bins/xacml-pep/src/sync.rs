// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The PDP client: register, pull, heartbeat. **THE PULL IS THE CONTRACT.**
//! A port of `xacml-pep/sync.js`.
//!
//! * **Registering is optional.** It buys a row on the PDP's console and an
//!   address for the nudge, not the ability to decide. It is retried on the
//!   poll timer until it works, logged at `warn` once and at `debug` after.
//! * **The nudge and the heartbeat are optional.**
//! * **A failed pull KEEPS the last good policy set** and enforcement goes
//!   on, marked stale: a PDP outage that denied everything everywhere would
//!   be the worse failure. A PEP that has NEVER pulled is a different state,
//!   reported as `loaded: false`.
//! * **THE AUTHZEN CATALOGUE IS PULLED BESIDE THE POLICIES** (#1179), from
//!   `GET /xacml/pep/authzen-catalogue`, with a sync token of its own and
//!   the same rule: a failed pull keeps the last good catalogue. Every row
//!   is read again through this container's own grammar
//!   (`authzen_catalogue.rs`), as every policy is read again through its
//!   own engine. The policy pull is still the one the timers back off on;
//!   a catalogue that cannot be pulled changes what AuthZEN answers and
//!   nothing about `/protected`. A catalogue change does not nudge — the
//!   service's nudge is about the policy repository — so it converges on
//!   the poll.
//! * **AND THE AUTHZEN CALLERS AFTER THE CATALOGUE** (#1189), from `GET
//!   /xacml/pep/authzen-callers`: who the service admits to its AuthZEN API
//!   now, by the SHA-256 of each certificate, with the name a policy sees
//!   and the application scope. Its own token, the same rule — a failed
//!   pull keeps the last good list — and every entry read again by this
//!   container's own grammar (`parse_pulled_callers()`), never taken on
//!   trust. It converges on the poll too: a caller the service stops
//!   admitting is admitted here until the next one.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use reqwest::Method;
use serde_json::{json, Value};
use sts_core::log::tag;
use sts_core::time::iso_now;
use sts_xacml::pdp::Repository;
use sts_xacml::policy::PolicyNode;
use sts_xacml::xml;

use crate::authzen_catalogue::{self, Row};
use crate::enforce::Outcome;
use crate::options::Options;
use crate::pdp_client::{Body, PdpClient};

/// What this PEP decides with, replaced WHOLE on a successful pull so the
/// root and the repository can never disagree mid-decision.
#[derive(Default)]
pub struct Policies {
    pub root: Option<PolicyNode>,
    pub repository: Repository,
    /// The document the PDP marked as the root would not load HERE. The
    /// service answers a root that will not load as a fault
    /// (`STS-XACML-0012`), so the AuthZEN endpoints do too, rather than
    /// reading it as "no root" and answering false.
    pub root_refused: bool,
}

/// The realm's AuthZEN settings, as the catalogue carries them — the
/// service's defaults until one is pulled, and for any member a PDP did
/// not send.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthzenSettings {
    pub enabled: bool,
    pub resolve_subject_types: Vec<String>,
    pub batch_enabled: bool,
    pub max_evaluations: usize,
    pub max_body_bytes: usize,
    pub return_reasons: bool,
}

impl Default for AuthzenSettings {
    fn default() -> AuthzenSettings {
        AuthzenSettings {
            enabled: true,
            resolve_subject_types: vec!["user".to_string()],
            batch_enabled: true,
            max_evaluations: 64,
            max_body_bytes: 262_144,
            return_reasons: false,
        }
    }
}

impl AuthzenSettings {
    /// Reads the `settings` a pulled catalogue carries, member by member,
    /// within the service's own bounds for each.
    pub fn of(said: &Value) -> AuthzenSettings {
        let d = AuthzenSettings::default();
        let number = |key: &str, low: u64, high: u64, fallback: usize| {
            said[key]
                .as_u64()
                .filter(|n| (low..=high).contains(n))
                .map_or(fallback, |n| n as usize)
        };
        AuthzenSettings {
            enabled: said["enabled"].as_bool().unwrap_or(d.enabled),
            resolve_subject_types: said["resolveSubjectTypes"]
                .as_array()
                .map(|list| {
                    list.iter()
                        .filter_map(Value::as_str)
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                })
                .unwrap_or(d.resolve_subject_types),
            batch_enabled: said["batchEnabled"]
                .as_bool()
                .unwrap_or(d.batch_enabled),
            max_evaluations: number("maxEvaluations", 1, 1000, 64),
            max_body_bytes: number("maxBodyBytes", 1024, 5_242_880, 262_144),
            return_reasons: said["returnReasons"]
                .as_bool()
                .unwrap_or(d.return_reasons),
        }
    }
}

/// The AuthZEN catalogue this PEP holds, replaced WHOLE on a successful
/// pull, as the policies are.
#[derive(Debug, Clone, Default)]
pub struct Catalogue {
    /// A catalogue was pulled at least once.
    pub loaded: bool,
    pub sync_token: String,
    /// The realm the PDP answered in: the trusted `urn:sts:xacml:realm`.
    pub realm: String,
    /// The realm has its `sts-authzen-api` object, without which the API
    /// is off there.
    pub api_object: bool,
    pub rows: Arc<Vec<Row>>,
    pub settings: AuthzenSettings,
    /// Rows this container's grammar refused, and values the PDP left out.
    pub refused: Vec<String>,
    pub left_out: u64,
    pub last_pull_at: String,
    pub last_pull_ok: bool,
    pub last_pull_why: String,
}

/// One caller the service admits to its AuthZEN API, as the pull carries it
/// (#1189): the name a policy sees as `urn:sts:xacml:authzen:caller`, the
/// SHA-256 of every certificate the service's door resolves to it, its
/// application scope, and the endpoints its access-control policy admits
/// it to (`evaluation`, `evaluations`).
#[derive(Debug, Clone, PartialEq)]
pub struct PulledCaller {
    pub name: String,
    pub sha256: Vec<String>,
    pub applications: Vec<String>,
    pub endpoints: Vec<String>,
}

/// The AuthZEN caller list this PEP holds, replaced WHOLE on a successful
/// pull, as the catalogue is.
#[derive(Debug, Clone, Default)]
pub struct Callers {
    /// A list was pulled at least once. Until then `PEP_AUTHZEN_CALLERS`,
    /// when it is set, decides alone, and when it is not the edge answers
    /// 503.
    pub loaded: bool,
    pub sync_token: String,
    /// The realm's `authzen.callerAuthentication`: only `mtls` admits a
    /// certificate alone, so any other door admits nobody here.
    pub door: String,
    pub callers: Arc<Vec<PulledCaller>>,
    /// The service said its list was cut (`STS-AUTHZEN-0061` there).
    pub truncated: bool,
    /// Entries this container's grammar refused.
    pub refused: Vec<String>,
    pub last_pull_at: String,
    pub last_pull_ok: bool,
    pub last_pull_why: String,
}

/// The endpoint names a pulled caller may be admitted to.
pub const CALLER_ENDPOINTS: [&str; 2] = ["evaluation", "evaluations"];

/// Reads a pulled caller list STRICTLY, as `parse_callers()` reads
/// `PEP_AUTHZEN_CALLERS`: an entry that is not a name, at least one 64-digit
/// SHA-256, at most 64 applications of at most 256 characters and endpoints
/// from `CALLER_ENDPOINTS` is LEFT OUT and named, so a defect admits nobody
/// rather than somebody. Answers the door, the callers, and the problems.
pub fn parse_pulled_callers(
    said: &Value,
) -> (String, Vec<PulledCaller>, Vec<String>) {
    let door = said["door"].as_str().unwrap_or("").to_string();
    let mut out: Vec<PulledCaller> = Vec::new();
    let mut problems = Vec::new();
    let entries = said["callers"].as_array().cloned().unwrap_or_default();
    for (i, entry) in entries.iter().enumerate() {
        let name = entry["name"].as_str().unwrap_or("").trim().to_string();
        let sha256: Option<Vec<String>> =
            entry["certificates"].as_array().and_then(|list| {
                list.iter()
                    .map(|one| {
                        one["sha256"]
                            .as_str()
                            .and_then(crate::options::fingerprint_of)
                    })
                    .collect::<Option<Vec<String>>>()
                    .filter(|l| !l.is_empty() && l.len() <= 64)
            });
        let applications: Option<Vec<String>> =
            entry["applications"].as_array().and_then(|list| {
                list.iter()
                    .map(|one| {
                        one.as_str()
                            .filter(|s| {
                                !s.is_empty()
                                    && s.chars().count() <= 256
                                    && !s.chars().any(char::is_control)
                            })
                            .map(str::to_string)
                    })
                    .collect::<Option<Vec<String>>>()
                    .filter(|l| l.len() <= 64)
            });
        let endpoints: Option<Vec<String>> =
            entry["endpoints"].as_array().and_then(|list| {
                list.iter()
                    .map(|one| {
                        one.as_str()
                            .filter(|e| CALLER_ENDPOINTS.contains(e))
                            .map(str::to_string)
                    })
                    .collect::<Option<Vec<String>>>()
            });
        match (name.is_empty(), sha256, applications, endpoints) {
            (false, Some(sha256), Some(applications), Some(endpoints)) => {
                let named_twice = sha256
                    .iter()
                    .find(|fp| out.iter().any(|c| c.sha256.contains(fp)));
                if let Some(fp) = named_twice {
                    // The service names a certificate once (it resolves to
                    // one entry); two entries naming it is a defect, and
                    // the second is not believed.
                    problems.push(format!(
                        "entry {} names the certificate {} an earlier \
                         entry names, and is left out",
                        i, fp
                    ));
                } else {
                    out.push(PulledCaller {
                        name,
                        sha256,
                        applications,
                        endpoints,
                    });
                }
            }
            _ => problems.push(format!(
                "entry {} is not {{ \"name\", \"certificates\": 1 to 64 \
                 {{ \"sha256\" }}, \"applications\": at most 64 strings, \
                 \"endpoints\" }} and is left out",
                i
            )),
        }
    }
    (door, out, problems)
}

/// What the AuthZEN endpoints have answered, cumulative in this process —
/// kept apart from the enforcement counters the heartbeat reports, because
/// these decisions are ENFORCED by the caller, in its own process.
#[derive(Clone, Copy, Default)]
struct AuthzenCounters {
    decisions: u64,
    permitted: u64,
    denied: u64,
    errors: u64,
}

/// Everything about the current holding.
#[derive(Clone, Default)]
struct Held {
    loaded: bool,
    sync_token: String,
    policies: Arc<Policies>,
    policy_count: usize,
    last_pull_at: String,
    last_pull_ok: bool,
    last_pull_why: String,
    last_change_cause: String,
    last_change_at: String,
    last_nudge_at: String,
    last_nudge_result: String,
    refused: Vec<(String, String)>,
}

#[derive(Clone, Default)]
struct Registration {
    registered: bool,
    name: String,
    attempts: u32,
    authenticated: Option<bool>,
    why: String,
    notify: Option<Value>,
}

/// This PEP's own counters, cumulative in this process.
#[derive(Clone, Copy, Default)]
struct Counters {
    decisions: u64,
    allowed: u64,
    refused: u64,
    undischargeable: u64,
}

struct State {
    held: Held,
    catalogue: Catalogue,
    callers: Callers,
    last_callers_kept_why: String,
    authzen: AuthzenCounters,
    last_catalogue_kept_why: String,
    registration: Registration,
    counters: Counters,
    /// The reason the last failed pull gave, so a repeat is not warned twice.
    last_kept_why: String,
}

/// The register / pull / heartbeat client and what it holds.
pub struct Sync {
    client: PdpClient,
    options: Options,
    state: Mutex<State>,
}

/// What a pull, a register or a heartbeat answers its caller.
pub struct HeartbeatResult {
    pub ok: bool,
    pub current: bool,
}

impl Sync {
    pub fn new(client: PdpClient, options: Options) -> Sync {
        let held = Held {
            last_pull_why: "No pull has been attempted yet.".into(),
            ..Held::default()
        };
        Sync {
            client,
            options,
            state: Mutex::new(State {
                held,
                registration: Registration {
                    why: "Not attempted yet.".into(),
                    ..Registration::default()
                },
                counters: Counters::default(),
                last_kept_why: String::new(),
                catalogue: Catalogue {
                    last_pull_why: "No pull has been attempted yet.".into(),
                    ..Catalogue::default()
                },
                callers: Callers {
                    last_pull_why: "No pull has been attempted yet.".into(),
                    ..Callers::default()
                },
                last_callers_kept_why: String::new(),
                authzen: AuthzenCounters::default(),
                last_catalogue_kept_why: String::new(),
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        // A poisoned lock means a panic while holding it; the state is still
        // the best this PEP has, so it is taken back rather than abandoned.
        match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// What the PEP decides with, and whether anything is loaded.
    pub fn current(&self) -> (Arc<Policies>, bool) {
        let state = self.lock();
        (state.held.policies.clone(), state.held.loaded)
    }

    /// Whether a policy pull has ever LOADED anything — "this PEP has
    /// never pulled" and "it pulled and there is no root" are different
    /// answers on the AuthZEN endpoints, as they are on `GET /`.
    pub fn ever_loaded(&self) -> bool {
        !self.lock().held.last_change_at.is_empty()
    }

    /// The AuthZEN catalogue held now.
    pub fn catalogue(&self) -> Catalogue {
        self.lock().catalogue.clone()
    }

    /// The AuthZEN caller list held now (#1189).
    pub fn callers(&self) -> Callers {
        self.lock().callers.clone()
    }

    /// One AuthZEN answer: `Some(decision)`, or `None` for an error.
    pub fn count_authzen(&self, decision: Option<bool>) {
        let mut state = self.lock();
        state.authzen.decisions += 1;
        match decision {
            Some(true) => state.authzen.permitted += 1,
            Some(false) => state.authzen.denied += 1,
            None => state.authzen.errors += 1,
        }
    }

    /// `authzen.catalogue` and `authzen.answered` on `GET /`.
    pub fn authzen_json(&self) -> Value {
        let state = self.lock();
        let c = &state.catalogue;
        let a = state.authzen;
        let p = &state.callers;
        json!({
            // COUNTS, NEVER NAMES (#1189). `GET /` answers whoever reaches
            // this container; the list it counts is the service's, which
            // only a holder of REMOTE_PEPS may read there.
            "pulledCallers": {
                "loaded": p.loaded,
                "syncToken": p.sync_token,
                "door": p.door,
                "callers": p.callers.len(),
                "certificates": p.callers.iter()
                    .map(|c| c.sha256.len()).sum::<usize>(),
                "truncatedByThePdp": p.truncated,
                "refused": p.refused,
                "lastPullAt": p.last_pull_at,
                "lastPullOk": p.last_pull_ok,
                "lastPullWhy": p.last_pull_why
            },
            "catalogue": {
                "loaded": c.loaded,
                "syncToken": c.sync_token,
                "realm": c.realm,
                "apiObject": c.api_object,
                "rows": c.rows.len(),
                "refused": c.refused,
                "leftOutByThePdp": c.left_out,
                "settings": {
                    "enabled": c.settings.enabled,
                    "resolveSubjectTypes": c.settings.resolve_subject_types,
                    "batchEnabled": c.settings.batch_enabled,
                    "maxEvaluations": c.settings.max_evaluations,
                    "maxBodyBytes": c.settings.max_body_bytes,
                    "returnReasons": c.settings.return_reasons
                },
                "lastPullAt": c.last_pull_at,
                "lastPullOk": c.last_pull_ok,
                "lastPullWhy": c.last_pull_why
            },
            "answered": { "decisions": a.decisions, "true": a.permitted,
                          "false": a.denied, "errors": a.errors }
        })
    }

    pub fn sync_token(&self) -> String {
        self.lock().held.sync_token.clone()
    }

    pub fn last_pull_at(&self) -> String {
        self.lock().held.last_pull_at.clone()
    }

    pub fn count_decision(&self, outcome: &Outcome) {
        let mut state = self.lock();
        state.counters.decisions += 1;
        if outcome.allowed {
            state.counters.allowed += 1;
        } else {
            state.counters.refused += 1;
        }
        if !outcome.undischargeable.is_empty() {
            state.counters.undischargeable += 1;
        }
    }

    /// `holding` on `GET /`: the root's IDENTIFIER, never the parsed tree.
    pub fn holding_json(&self) -> Value {
        let held = self.lock().held.clone();
        holding_of(&held)
    }

    pub fn registration_json(&self) -> Value {
        let r = self.lock().registration.clone();
        if !r.registered {
            return json!({ "registered": false, "name": r.name,
                           "attempts": r.attempts, "why": r.why });
        }
        json!({ "registered": true, "name": r.name, "attempts": r.attempts,
                "authenticated": r.authenticated.unwrap_or(false),
                "why": r.why, "notify": r.notify.unwrap_or(Value::Null) })
    }

    pub fn counters_json(&self) -> Value {
        let c = self.lock().counters;
        json!({ "decisions": c.decisions, "allowed": c.allowed,
                "refused": c.refused, "undischargeable": c.undischargeable })
    }

    // -----------------------------------------------------------------------
    // REGISTER. Best effort, always.
    // -----------------------------------------------------------------------
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn register(&self) {
        let attempts = self.lock().registration.attempts + 1;
        let first = attempts == 1;
        let o = &self.options;
        let answer = self
            .client
            .call(
                Method::POST,
                "/xacml/pep/register",
                Some(Body::Json(json!({
                    "name": o.name, "notifyUrl": o.notify_url,
                    "bias": o.bias.as_str(), "resource": o.resource,
                    "version": o.version, "description": o.description
                }))),
            )
            .await;
        let complain = |code: &str, why: &str| {
            if first {
                tracing::warn!("{}xacml-pep: {}", tag(code), why);
            } else {
                tracing::debug!("{}xacml-pep: {}", tag(code), why);
            }
        };
        if let Some(error) = &answer.error {
            let why = format!(
                "Could not reach the PDP to register: {}. THIS PEP STILL \
                 ENFORCES — registering buys a row on the PDP console and an \
                 address for the nudge, not the ability to decide. It is \
                 retried on every poll (attempt {}).",
                error, attempts
            );
            complain("STS-XPEP-0015", &why);
            self.lock().registration = Registration {
                name: o.name.clone(),
                attempts,
                why,
                ..Registration::default()
            };
            return;
        }
        if answer.status != 200 && answer.status != 201 {
            let said = answer.error_description().unwrap_or_else(|| {
                if answer.text.is_empty() {
                    format!("the PDP answered {}", answer.status)
                } else {
                    answer.text.clone()
                }
            });
            let why = format!(
                "The PDP refused the registration ({}): {} Registering buys \
                 a row on the PDP console and an address for the nudge, not \
                 the ability to decide — but the PULL needs the same \
                 credential, since GET /xacml/pep/policies requires the \
                 REMOTE_PEPS role. So a refusal about a certificate or that \
                 role will have refused the pull as well, and one about \
                 anything else will not: holding.lastPullWhy is what says \
                 which happened here. It is retried on every poll (attempt \
                 {}).",
                answer.status, said, attempts
            );
            complain("STS-XPEP-0016", &why);
            self.lock().registration = Registration {
                name: o.name.clone(),
                attempts,
                why,
                ..Registration::default()
            };
            return;
        }
        let said = answer.json.unwrap_or(Value::Null);
        let name = said["name"].as_str().unwrap_or(&o.name).to_string();
        let authenticated = said["authenticated"].as_bool().unwrap_or(false);
        let why = if authenticated {
            format!("Registered over mutual TLS as \"{}\".", name)
        } else {
            format!(
                "Registered as \"{}\" WITHOUT a client certificate; the PDP \
                 has marked this row unauthenticated and is right to.",
                name
            )
        };
        let notify = said.get("notify").filter(|n| !n.is_null()).cloned();
        let mut line = format!("xacml-pep: {}", why);
        if attempts > 1 {
            line.push_str(&format!(
                " It took {} attempts — this PEP was up before its PDP was, \
                 or before the realm it polls existed, and the retry on the \
                 poll timer is what closed the gap.",
                attempts
            ));
        }
        if let Some(n) = &notify {
            if n["usable"].as_bool() == Some(false) {
                line.push_str(&format!(
                    " The PDP will NOT nudge this PEP: {} That costs one \
                     polling interval of latency and nothing else.",
                    n["why"].as_str().unwrap_or("")
                ));
            }
        }
        tracing::info!("{}", line);
        self.lock().registration = Registration {
            registered: true,
            name,
            attempts,
            authenticated: Some(authenticated),
            why,
            notify,
        };
    }

    /// Register again if it has not worked yet. A successful registration
    /// is never repeated.
    pub async fn register_if_needed(&self) {
        if !self.lock().registration.registered {
            self.register().await;
        }
    }

    // -----------------------------------------------------------------------
    // PULL. The one thing that has to work. `cause` (`start`, `poll`,
    // `nudge`, `heartbeat`) is recorded only by a pull that LOADS a change.
    // -----------------------------------------------------------------------
    #[tracing::instrument(level = "debug", skip(self))]
    pub async fn pull(&self, cause: &str) -> bool {
        let changed_before = self.lock().held.last_change_at.clone();
        self.pull_once(cause).await;
        self.pull_catalogue().await;
        self.pull_callers().await;
        let mut state = self.lock();
        if cause == "nudge" {
            state.held.last_nudge_at = iso_now();
            state.held.last_nudge_result = if !state.held.last_pull_ok {
                "failed"
            } else if state.held.last_change_at != changed_before {
                "changed"
            } else {
                "unchanged"
            }
            .to_string();
        }
        state.held.last_pull_ok
    }

    async fn pull_once(&self, cause: &str) {
        let (token, name) = {
            let state = self.lock();
            (state.held.sync_token.clone(), self.options.name.clone())
        };
        let query = if token.is_empty() {
            format!("?pep={}", encode(&name))
        } else {
            format!("?since={}&pep={}", encode(&token), encode(&name))
        };
        let answer = self
            .client
            .call(Method::GET, &format!("/xacml/pep/policies{}", query), None)
            .await;
        if let Some(error) = &answer.error {
            self.keep(
                &format!("Could not reach the PDP: {}", error),
                "STS-XPEP-0017",
            );
            return;
        }
        if answer.status == 304 {
            // UNCHANGED IS A SUCCESSFUL PULL, and moves `lastPullAt`.
            let mut state = self.lock();
            state.held.last_pull_at = iso_now();
            state.held.last_pull_ok = true;
            state.last_kept_why.clear();
            state.held.last_pull_why =
                "Unchanged; this copy is current.".into();
            return;
        }
        if answer.status != 200 {
            let detail = answer
                .error_description()
                .map(|d| format!(": {}", d))
                .unwrap_or_default();
            self.keep(
                &format!("The PDP answered {}{}.", answer.status, detail),
                "STS-XPEP-0018",
            );
            return;
        }
        let Some(said) = answer.json.filter(|j| j["policies"].is_array())
        else {
            self.keep(
                "The PDP answered 200 with something that is not a \
                       policy set. Keeping the previous one.",
                "STS-XPEP-0019",
            );
            return;
        };
        self.load(&said, cause);
    }

    /// Parses and STATICALLY VALIDATES every pulled document with this PEP's
    /// own engine — never taken on trust because the PDP accepted it.
    fn load(&self, said: &Value, cause: &str) {
        let rows = said["policies"].as_array().cloned().unwrap_or_default();
        let mut repository = HashMap::new();
        let mut refused = Vec::new();
        let mut root = None;
        let mut root_refused = false;
        for row in &rows {
            let document = row["document"].as_str().unwrap_or("");
            match xml::parse_policy(document) {
                Ok(parsed) => {
                    if let Some(id) = row["policyId"].as_str() {
                        repository.insert(id.to_string(), parsed.clone());
                    }
                    if row["isRoot"].as_bool() == Some(true) {
                        root = Some(parsed);
                    }
                }
                // Left out and NAMED: enforcing half a document is worse
                // than not having it.
                Err(error) => {
                    if row["isRoot"].as_bool() == Some(true) {
                        root_refused = true;
                    }
                    refused.push((
                        row["name"].as_str().unwrap_or("").to_string(),
                        error.message,
                    ))
                }
            }
        }
        // Exactly one policy is unambiguously the root — restated, so this
        // PEP cannot decide differently from the PDP about where to start.
        if root.is_none() && rows.len() == 1 && refused.is_empty() {
            root =
                xml::parse_policy(rows[0]["document"].as_str().unwrap_or(""))
                    .ok();
        }
        let count = rows.len();
        let token = match &said["syncToken"] {
            Value::String(s) => s.clone(),
            Value::Null => String::new(),
            other => other.to_string(),
        };
        let has_root = root.is_some();
        let why = if has_root {
            format!("Pulled {} policy(ies).", count)
        } else {
            format!(
                "Pulled {} policy(ies) and NONE IS THE ROOT, so there is \
                 nothing to start evaluation from and every decision is \
                 NotApplicable. The bias then decides, which for a \
                 deny-biased PEP means refusing everything.",
                count
            )
        };
        if !refused.is_empty() {
            let list: Vec<String> = refused
                .iter()
                .map(|(name, why)| format!("{} ({})", name, why))
                .collect();
            tracing::warn!(
                "{}xacml-pep: {} of {} pulled policy(ies) would not load here \
                 and were left out: {}",
                tag("STS-XPEP-0020"),
                refused.len(),
                count,
                list.join("; ")
            );
        }
        let now = iso_now();
        let mut state = self.lock();
        state.last_kept_why.clear();
        let previous = state.held.clone();
        state.held = Held {
            loaded: has_root,
            sync_token: token,
            policies: Arc::new(Policies {
                root,
                repository,
                root_refused,
            }),
            policy_count: count,
            last_pull_at: now.clone(),
            last_pull_ok: true,
            last_pull_why: why.clone(),
            last_change_cause: if cause.is_empty() { "unnamed" } else { cause }
                .to_string(),
            last_change_at: now,
            last_nudge_at: previous.last_nudge_at,
            last_nudge_result: previous.last_nudge_result,
            refused,
        };
        tracing::info!(
            "{}xacml-pep: pulled {} policy(ies), token {}. {}",
            if has_root {
                String::new()
            } else {
                tag("STS-XPEP-0021")
            },
            count,
            state.held.sync_token,
            why
        );
    }

    /// A failed pull keeps what is held. `lastPullAt` is NOT touched: it
    /// means "when did this PEP last confirm it was current", and `stale` is
    /// computed from that gap.
    fn keep(&self, why: &str, code: &str) {
        let mut state = self.lock();
        state.held.last_pull_ok = false;
        state.held.last_pull_why = if state.held.loaded {
            format!(
                "{} KEEPING the {} policy(ies) pulled at {} and going on \
                 enforcing them — a PDP outage that denied everything \
                 everywhere would be a worse failure than a stale copy. This \
                 PEP reports itself stale on GET / and the PDP shows it as \
                 stale too.",
                why, state.held.policy_count, state.held.last_pull_at
            )
        } else {
            format!(
                "{} NOTHING IS HELD, so there is no policy to enforce: every \
                 decision is NotApplicable and the bias decides. That is a \
                 different state from a stale copy and is reported as \
                 loaded: false.",
                why
            )
        };
        // A state change is a warning and a repeat is not.
        if state.last_kept_why != why {
            state.last_kept_why = why.to_string();
            tracing::warn!(
                "{}xacml-pep: {}",
                tag(code),
                state.held.last_pull_why
            );
        }
    }

    // -----------------------------------------------------------------------
    // THE AUTHZEN CATALOGUE (#1179). Pulled after every policy pull, with
    // its own token; a failure keeps what is held.
    // -----------------------------------------------------------------------
    async fn pull_catalogue(&self) {
        let token = self.lock().catalogue.sync_token.clone();
        let query = if token.is_empty() {
            String::new()
        } else {
            format!("?since={}", encode(&token))
        };
        let answer = self
            .client
            .call(
                Method::GET,
                &format!("/xacml/pep/authzen-catalogue{}", query),
                None,
            )
            .await;
        if let Some(error) = &answer.error {
            self.keep_catalogue(
                &format!("Could not reach the PDP: {}", error),
                "STS-XPEP-0040",
            );
            return;
        }
        if answer.status == 304 {
            let mut state = self.lock();
            state.catalogue.last_pull_at = iso_now();
            state.catalogue.last_pull_ok = true;
            state.catalogue.last_pull_why =
                "Unchanged; this catalogue is current.".into();
            state.last_catalogue_kept_why.clear();
            return;
        }
        if answer.status != 200 {
            let detail = answer
                .error_description()
                .map(|d| format!(": {}", d))
                .unwrap_or_default();
            let older = if answer.status == 404 {
                " A PDP older than #1179 has no catalogue endpoint."
            } else {
                ""
            };
            self.keep_catalogue(
                &format!(
                    "The PDP answered {} to the catalogue pull{}.{}",
                    answer.status, detail, older
                ),
                "STS-XPEP-0041",
            );
            return;
        }
        let Some(said) = answer.json.filter(|j| j["rows"].is_array()) else {
            self.keep_catalogue(
                "The PDP answered 200 with something that is not an \
                 AuthZEN catalogue.",
                "STS-XPEP-0041",
            );
            return;
        };
        self.load_catalogue(&said);
    }

    /// Reads every pulled row through this container's own grammar: a row
    /// it refuses is left out and named, never mapped with.
    fn load_catalogue(&self, said: &Value) {
        let values = said["rows"].as_array().cloned().unwrap_or_default();
        let mut rows: Vec<Row> = Vec::new();
        let mut refused = Vec::new();
        for value in &values {
            match authzen_catalogue::parse(value) {
                Ok(row) => {
                    if rows.iter().any(|r| {
                        r.object == row.object && r.property == row.property
                    }) {
                        refused.push(format!(
                            "{}.{} has more than one row; the first is used",
                            row.object, row.property
                        ));
                    } else {
                        rows.push(row);
                    }
                }
                Err(problem) => refused
                    .push(format!("{} ({})", problem.problem, problem.code)),
            }
        }
        if !refused.is_empty() {
            tracing::warn!(
                "{}xacml-pep: {} of {} pulled AuthZEN catalogue row(s) were \
                 refused by this container's grammar and left out, so those \
                 properties are undeclared here: {}",
                tag("STS-XPEP-0042"),
                refused.len(),
                values.len(),
                refused.join("; ")
            );
        }
        let token = said["syncToken"].as_str().unwrap_or("").to_string();
        let count = rows.len();
        let mut state = self.lock();
        state.last_catalogue_kept_why.clear();
        state.catalogue = Catalogue {
            loaded: true,
            sync_token: token.clone(),
            realm: said["realm"].as_str().unwrap_or("").to_string(),
            api_object: said["apiObject"].is_string(),
            rows: Arc::new(rows),
            settings: AuthzenSettings::of(&said["settings"]),
            refused,
            left_out: said["leftOut"].as_u64().unwrap_or(0),
            last_pull_at: iso_now(),
            last_pull_ok: true,
            last_pull_why: format!("Pulled {} catalogue row(s).", count),
        };
        tracing::info!(
            "xacml-pep: pulled the AuthZEN catalogue: {} row(s), token {}.",
            count,
            token
        );
    }

    /// A failed catalogue pull keeps what is held, and warns once per
    /// distinct reason.
    fn keep_catalogue(&self, why: &str, code: &str) {
        let mut state = self.lock();
        state.catalogue.last_pull_ok = false;
        state.catalogue.last_pull_why = if state.catalogue.loaded {
            format!(
                "{} KEEPING the catalogue pulled at {}, so AuthZEN goes on \
                 mapping as it did.",
                why, state.catalogue.last_pull_at
            )
        } else {
            format!(
                "{} NO CATALOGUE IS HELD, so the AuthZEN endpoints answer \
                 503: a request cannot be mapped as the service maps it.",
                why
            )
        };
        if state.last_catalogue_kept_why != why {
            state.last_catalogue_kept_why = why.to_string();
            tracing::warn!(
                "{}xacml-pep: {}",
                tag(code),
                state.catalogue.last_pull_why
            );
        }
    }

    // -----------------------------------------------------------------------
    // THE AUTHZEN CALLERS (#1189). Pulled after the catalogue, with its own
    // token; a failure keeps what is held.
    // -----------------------------------------------------------------------
    async fn pull_callers(&self) {
        let token = self.lock().callers.sync_token.clone();
        let query = if token.is_empty() {
            String::new()
        } else {
            format!("?since={}", encode(&token))
        };
        let answer = self
            .client
            .call(
                Method::GET,
                &format!("/xacml/pep/authzen-callers{}", query),
                None,
            )
            .await;
        if let Some(error) = &answer.error {
            self.keep_callers(
                &format!("Could not reach the PDP: {}", error),
                "STS-XPEP-0047",
            );
            return;
        }
        if answer.status == 304 {
            let mut state = self.lock();
            state.callers.last_pull_at = iso_now();
            state.callers.last_pull_ok = true;
            state.callers.last_pull_why =
                "Unchanged; this caller list is current.".into();
            state.last_callers_kept_why.clear();
            return;
        }
        if answer.status != 200 {
            let detail = answer
                .error_description()
                .map(|d| format!(": {}", d))
                .unwrap_or_default();
            let older = if answer.status == 404 {
                " A PDP older than #1189 has no caller endpoint."
            } else {
                ""
            };
            self.keep_callers(
                &format!(
                    "The PDP answered {} to the caller pull{}.{}",
                    answer.status, detail, older
                ),
                "STS-XPEP-0048",
            );
            return;
        }
        let Some(said) = answer.json.filter(|j| j["callers"].is_array()) else {
            self.keep_callers(
                "The PDP answered 200 with something that is not an \
                 AuthZEN caller list.",
                "STS-XPEP-0048",
            );
            return;
        };
        self.load_callers(&said);
    }

    /// Reads every pulled entry through this container's own grammar: an
    /// entry it refuses is left out and named, never admitted.
    fn load_callers(&self, said: &Value) {
        let (door, callers, refused) = parse_pulled_callers(said);
        if !refused.is_empty() {
            tracing::warn!(
                "{}xacml-pep: {} pulled AuthZEN caller(s) were refused by \
                 this container's grammar and left out, so they are not \
                 admitted here: {}",
                tag("STS-XPEP-0049"),
                refused.len(),
                refused.join("; ")
            );
        }
        let token = said["syncToken"].as_str().unwrap_or("").to_string();
        let count = callers.len();
        let mut state = self.lock();
        state.last_callers_kept_why.clear();
        state.callers = Callers {
            loaded: true,
            sync_token: token.clone(),
            door: door.clone(),
            callers: Arc::new(callers),
            truncated: said["truncated"].as_bool().unwrap_or(false),
            refused,
            last_pull_at: iso_now(),
            last_pull_ok: true,
            last_pull_why: format!("Pulled {} caller(s).", count),
        };
        tracing::info!(
            "xacml-pep: pulled the AuthZEN callers: {} caller(s), door {}, \
             token {}.",
            count,
            door,
            token
        );
    }

    /// A failed caller pull keeps what is held, and warns once per distinct
    /// reason.
    fn keep_callers(&self, why: &str, code: &str) {
        let configured = self.options.authzen_callers_configured;
        let mut state = self.lock();
        state.callers.last_pull_ok = false;
        state.callers.last_pull_why = if state.callers.loaded {
            format!(
                "{} KEEPING the caller list pulled at {}, so the edge PDP \
                 goes on admitting as it did.",
                why, state.callers.last_pull_at
            )
        } else if configured {
            format!(
                "{} NO CALLER LIST IS HELD, so PEP_AUTHZEN_CALLERS alone \
                 decides who may ask until one is.",
                why
            )
        } else {
            format!(
                "{} NO CALLER LIST IS HELD and PEP_AUTHZEN_CALLERS is not \
                 set, so the AuthZEN endpoints answer 503.",
                why
            )
        };
        if state.last_callers_kept_why != why {
            state.last_callers_kept_why = why.to_string();
            tracing::warn!(
                "{}xacml-pep: {}",
                tag(code),
                state.callers.last_pull_why
            );
        }
    }

    // -----------------------------------------------------------------------
    // HEARTBEAT. What this PEP has enforced, so a person can see it.
    // -----------------------------------------------------------------------
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn heartbeat(&self) -> HeartbeatResult {
        let (token, count, c) = {
            let state = self.lock();
            (
                state.held.sync_token.clone(),
                state.held.policy_count,
                state.counters,
            )
        };
        let o = &self.options;
        let answer = self
            .client
            .call(
                Method::POST,
                "/xacml/pep/heartbeat",
                Some(Body::Json(json!({
                    "name": o.name, "syncToken": token, "policyCount": count,
                    "decisions": c.decisions, "allowed": c.allowed,
                    "refused": c.refused,
                    "undischargeable": c.undischargeable,
                    "bias": o.bias.as_str(), "resource": o.resource,
                    "version": o.version, "notifyUrl": o.notify_url
                }))),
            )
            .await;
        if answer.error.is_some() || answer.status != 200 {
            // Debug, not warn: a PEP that cannot REPORT is still enforcing.
            tracing::debug!(
                "{}xacml-pep: heartbeat not delivered: {}",
                tag(if answer.error.is_some() {
                    "STS-XPEP-0022"
                } else {
                    "STS-XPEP-0023"
                }),
                answer.error.unwrap_or_else(|| answer.status.to_string())
            );
            return HeartbeatResult {
                ok: false,
                current: false,
            };
        }
        let current = answer
            .json
            .as_ref()
            .and_then(|j| j["current"].as_bool())
            .unwrap_or(false);
        if !current {
            tracing::info!(
                "xacml-pep: the PDP says this copy is not the \
                            current one. Pulling."
            );
        }
        HeartbeatResult { ok: true, current }
    }
}

fn holding_of(held: &Held) -> Value {
    let root = held
        .policies
        .root
        .as_ref()
        .map(|r| {
            Value::String(if r.id().is_empty() {
                "(unnamed)".into()
            } else {
                r.id().into()
            })
        })
        .unwrap_or(Value::Null);
    let refused: Vec<Value> = held
        .refused
        .iter()
        .map(|(name, why)| json!({ "name": name, "why": why }))
        .collect();
    json!({
        "loaded": held.loaded,
        "syncToken": held.sync_token,
        "root": root,
        "policyCount": held.policy_count,
        "lastPullAt": held.last_pull_at,
        "lastPullOk": held.last_pull_ok,
        "lastPullWhy": held.last_pull_why,
        "lastChangeCause": held.last_change_cause,
        "lastChangeAt": held.last_change_at,
        "lastNudgeAt": held.last_nudge_at,
        "lastNudgeResult": held.last_nudge_result,
        "refused": refused
    })
}

/// JavaScript's `encodeURIComponent`.
pub fn encode(text: &str) -> String {
    let mut out = String::new();
    for byte in text.bytes() {
        let keep = byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')'
            );
        if keep {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{:02X}", byte));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pulled list is read strictly (#1189): a well-formed entry is
    /// kept with its digests lower-cased; an entry with no certificate, a
    /// digest that is not one, an endpoint this edge does not serve, an
    /// application list that is not strings, or no name is left out and
    /// named; and a certificate two entries name is believed of the first.
    #[test]
    fn pulled_callers_are_read_strictly() {
        let fp = "AB".repeat(32);
        let said = json!({
            "door": "mtls",
            "callers": [
                { "name": "uid=a,ou=users", "applications": ["todo-app"],
                  "certificates": [{ "sha256": fp, "source": "stored" }],
                  "endpoints": ["evaluation", "evaluations"] },
                { "name": "uid=b,ou=users", "applications": [],
                  "certificates": [], "endpoints": ["evaluation"] },
                { "name": "uid=c,ou=users", "applications": [],
                  "certificates": [{ "sha256": "nothex" }],
                  "endpoints": ["evaluation"] },
                { "name": "uid=d,ou=users", "applications": [],
                  "certificates": [{ "sha256": "cd".repeat(32) }],
                  "endpoints": ["search"] },
                { "name": "uid=e,ou=users", "applications": [1],
                  "certificates": [{ "sha256": "ef".repeat(32) }],
                  "endpoints": [] },
                { "name": "", "applications": [],
                  "certificates": [{ "sha256": "01".repeat(32) }],
                  "endpoints": [] },
                { "name": "uid=f,ou=users", "applications": [],
                  "certificates": [{ "sha256": "ab".repeat(32) }],
                  "endpoints": ["evaluation"] }
            ]
        });
        let (door, callers, problems) = parse_pulled_callers(&said);
        assert_eq!(door, "mtls");
        assert_eq!(callers.len(), 1);
        assert_eq!(callers[0].name, "uid=a,ou=users");
        assert_eq!(callers[0].sha256, vec!["ab".repeat(32)]);
        assert_eq!(callers[0].applications, ["todo-app"]);
        assert_eq!(callers[0].endpoints, ["evaluation", "evaluations"]);
        assert_eq!(problems.len(), 6, "{:?}", problems);
        let (none, nothing, refused) = parse_pulled_callers(&json!({}));
        assert!(none.is_empty() && nothing.is_empty() && refused.is_empty());
    }
}
