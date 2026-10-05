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

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use reqwest::Method;
use serde_json::{json, Value};
use sts_core::log::tag;
use sts_core::time::iso_now;
use sts_xacml::pdp::Repository;
use sts_xacml::policy::PolicyNode;
use sts_xacml::xml;

use crate::enforce::Outcome;
use crate::options::Options;
use crate::pdp_client::{Body, PdpClient};

/// What this PEP decides with, replaced WHOLE on a successful pull so the
/// root and the repository can never disagree mid-decision.
#[derive(Default)]
pub struct Policies {
    pub root: Option<PolicyNode>,
    pub repository: Repository,
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
                Err(error) => refused.push((
                    row["name"].as_str().unwrap_or("").to_string(),
                    error.message,
                )),
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
            policies: Arc::new(Policies { root, repository }),
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
