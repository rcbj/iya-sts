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
//! * **THE CATALOGUE NAMES THE APPLICATIONS THAT ENFORCE FINE-GRAINED
//!   AUTHORIZATION** (#564, P7): `fgaApplications`, whose evaluations the
//!   edge FORWARDS to the service rather than deciding from the root. It is
//!   inside the catalogue's token, so a switch flip is pulled on the next
//!   poll. A member that is not a list of identifiers refuses the WHOLE
//!   catalogue (`STS-XPEP-0059`), keeping the one held: which evaluations
//!   must be forwarded cannot be told from it, and guessing "none" would
//!   decide an enforcing application from the root.
//! * **AND THE REVERSE PROXY'S CONFIGURATION AFTER THE CALLERS** (#1760),
//!   from `GET /xacml/pep/proxy`, with its own sync token, `?since=` and
//!   `If-None-Match`. The same rule: a failed pull keeps the last good
//!   configuration (`STS-XPEP-0060`, `-0061`). The document is read again
//!   by D2's own rules (`proxy_config.rs`) and refused WHOLE when one part
//!   does not validate (`STS-XPEP-0062`): a route table loaded in part
//!   forwards what nobody configured. It converges on the poll, unnudged.
//! * **AND THIS PEP'S OWN SETTINGS FIRST OF ALL** (#1760), from `GET
//!   /xacml/pep/settings`: what an administrator set on the PEP's console
//!   page, with its own sync token, `?since=` and `If-None-Match`. A failed
//!   pull keeps what is held (`STS-XPEP-0100`); an older service's 404 is
//!   the environment in force, said once (`STS-XPEP-0101`); each value is
//!   read again by `settings.rs` and one that fails is left to the
//!   environment (`STS-XPEP-0102`). Pulled first so the timers, the
//!   timeouts and the bias the rest of the round uses are the new ones.

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
use crate::credential::Resource;
use crate::enforce::Outcome;
use crate::options::Options;
use crate::pdp_client::{Body, PdpClient};
use crate::proxy_config::{self, Mechanism, Pulled};
use crate::rp_session::Stores;
use crate::settings::Managed;

/// What this PEP decides with, replaced WHOLE on a successful pull so the
/// root and the repository can never disagree mid-decision.
#[derive(Default)]
pub struct Policies {
    pub root: Option<PolicyNode>,
    pub repository: Repository,
    /// Every entry that loaded, by its NAME (#1760): what a proxy route's
    /// `authorization.policy` names and is decided by, never the root. The
    /// repository stays keyed by PolicyId, which is what a
    /// PolicyIdReference names. A name two rows carry is in neither — a
    /// route naming it is refused rather than decided by whichever came
    /// last.
    pub by_name: HashMap<String, PolicyNode>,
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
    /// The realm's `authzen.obligationsProfile` (#1177, #1205). Absent on
    /// an older service's catalogue means on, which is that setting's
    /// default: an edge that handed obligations while the realm had turned
    /// the profile off would be wider than the service.
    pub obligations_profile: bool,
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
            obligations_profile: true,
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
            obligations_profile: said["obligationsProfile"]
                .as_bool()
                .unwrap_or(d.obligations_profile),
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
    /// The applications that enforce fine-grained authorization (#564):
    /// an evaluation about one of them is FORWARDED to the service.
    pub fga_applications: Arc<Vec<String>>,
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

/// The reverse proxy's configuration this PEP holds (#1760), replaced
/// WHOLE on a successful pull.
#[derive(Debug, Clone, Default)]
pub struct ProxyHolding {
    /// A configuration answer was loaded at least once.
    pub loaded: bool,
    pub sync_token: String,
    pub etag: String,
    pub pulled: Arc<Pulled>,
    pub last_pull_at: String,
    pub last_pull_ok: bool,
    pub last_pull_why: String,
}

/// THE PROXY BEFORE ITS FIRST CONFIGURATION (rcbj, 2026-11-15): every
/// request is answered 503 with `Retry-After`, and the log carries the state
/// change and a summary at most once per [`WAITING_SUMMARY_EVERY`], never a
/// line per request (`STS-XPEP-0118`).
#[derive(Debug, Clone, Default)]
struct ProxyWaiting {
    /// Answered 503 since the start.
    refused: u64,
    /// Of those, since the last line about them.
    unreported: u64,
    /// When the last line about them was written.
    last_line: Option<std::time::Instant>,
}

/// How often, at most, the proxy says it is still waiting for its first
/// configuration while requests go on arriving.
pub const WAITING_SUMMARY_EVERY: std::time::Duration =
    std::time::Duration::from_secs(60);

/// The settings pull's state (#1760).
#[derive(Debug, Clone, Default)]
struct SettingsHolding {
    sync_token: String,
    etag: String,
    last_pull_at: String,
    last_pull_ok: bool,
    last_pull_why: String,
    /// The service answered 404: it has no settings endpoint (an older
    /// service), so the environment is in force. Said once.
    not_offered: bool,
    /// The listeners the service defines for this PEP (#1760), as pulled:
    /// the `listeners` member, or null for none. `listeners.rs` reads it.
    listeners: Value,
    /// The four environment listeners' tuning. Null until a pull sends
    /// `environmentTuning`; applying null changes no pool.
    environment_tuning: Value,
}

/// What the reverse proxy has answered, cumulative in this process: by
/// status, and how many reached the application.
#[derive(Debug, Clone, Default)]
struct ProxyCounters {
    requests: u64,
    forwarded: u64,
    by_status: std::collections::BTreeMap<u16, u64>,
    sign_ins: u64,
    sessions_ended: u64,
}

/// The endpoint names a pulled caller may be admitted to.
pub const CALLER_ENDPOINTS: [&str; 2] = ["evaluation", "evaluations"];

/// Reads a pulled caller list STRICTLY, as `parse_callers()` reads
/// `PEP_AUTHZEN_CALLERS`: an entry that is not a name, at least one 64-digit
/// The catalogue's `fgaApplications` (#564, P7): the applications that
/// enforce fine-grained authorization. ABSENT is an empty list — a service
/// that does not send it predates fine-grained authorization, so no
/// application there enforces it. PRESENT, it must be an array of non-empty
/// strings of at most 256 characters, or the whole catalogue is refused:
/// an entry left out here would be an enforcing application decided from
/// the root, so unlike a caller entry nothing is dropped and carried on.
pub fn parse_fga_applications(said: &Value) -> Result<Vec<String>, String> {
    let Some(given) = said.get("fgaApplications") else {
        return Ok(Vec::new());
    };
    let refused = || {
        "The PDP's AuthZEN catalogue carried an fgaApplications member \
         that is not an array of application identifiers, so which \
         evaluations must be forwarded to it cannot be told; the catalogue \
         is refused whole."
            .to_string()
    };
    let list = given.as_array().ok_or_else(refused)?;
    let mut out = Vec::new();
    for one in list {
        let id = one
            .as_str()
            .filter(|s| !s.is_empty() && s.chars().count() <= 256)
            .ok_or_else(refused)?;
        out.push(id.to_string());
    }
    Ok(out)
}

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
    /// Of the decisions, those the service made, forwarded (#564).
    forwarded: u64,
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
    proxy: ProxyHolding,
    last_proxy_kept_why: String,
    proxy_counters: ProxyCounters,
    /// The requests the proxy answered 503 because no configuration has
    /// been received since this process started (`STS-XPEP-0118`).
    proxy_waiting: ProxyWaiting,
    /// (relying parties, CAEP/RISC receivers) the proxy holds, as of its
    /// last reconcile.
    relying_parties: (usize, usize),
    settings: SettingsHolding,
    last_settings_kept_why: String,
    /// When the last FULL pull was started (a Sync from the console,
    /// 2026-11-16), so one is honoured at most once a poll interval.
    last_full_pull: Option<std::time::Instant>,
}

/// What `GET /` asks the proxy's relying parties about their CAEP/RISC
/// streams (`rp_set::RpSet::signals_json`), set by the proxy at start.
/// The same shape asks the streams one by one for the heartbeat
/// (`streams_json`), and every listener what it is doing (#1760).
pub type SignalsReporter = Arc<dyn Fn() -> Value + Send + std::marker::Sync>;

/// The register / pull / heartbeat client and what it holds.
pub struct Sync {
    client: PdpClient,
    options: Options,
    state: Mutex<State>,
    signals_reporter: Mutex<Option<SignalsReporter>>,
    /// One row per CAEP/RISC stream, for the heartbeat only (#1760): it
    /// names the client, which `GET /` never does.
    streams_reporter: Mutex<Option<SignalsReporter>>,
    /// Every listener and what it is doing, for the heartbeat (#1760).
    listeners_reporter: Mutex<Option<SignalsReporter>>,
    /// The reverse proxy's sign-ins and sessions (#1760): here so that
    /// `GET /` can count them.
    pub proxy_sessions: Arc<Stores>,
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
        let proxy_sessions = Arc::new(Stores::new(
            options.proxy_max_sessions,
            options.proxy_session_ttl_ms,
        ));
        Sync {
            client,
            options,
            proxy_sessions,
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
                proxy: ProxyHolding {
                    last_pull_why: "No pull has been attempted yet.".into(),
                    ..ProxyHolding::default()
                },
                last_proxy_kept_why: String::new(),
                proxy_counters: ProxyCounters::default(),
                proxy_waiting: ProxyWaiting::default(),
                relying_parties: (0, 0),
                settings: SettingsHolding {
                    last_pull_why: "No pull has been attempted yet.".into(),
                    ..SettingsHolding::default()
                },
                last_settings_kept_why: String::new(),
                last_full_pull: None,
            }),
            signals_reporter: Mutex::new(None),
            streams_reporter: Mutex::new(None),
            listeners_reporter: Mutex::new(None),
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

    /// The name registration reported, once it has succeeded and the name
    /// is not blank (#1760 phase 3). Before that, nothing: a receiver
    /// built then sends no `X-Iya-Pep-Name` and keeps the untagged stream.
    /// The name is the one the service folded and answered, not a second
    /// reading of `PEP_NAME`.
    pub fn registered_name(&self) -> Option<String> {
        let state = self.lock();
        let reg = &state.registration;
        if !reg.registered {
            return None;
        }
        let name = reg.name.trim();
        if name.is_empty() {
            None
        } else {
            Some(name.to_string())
        }
    }

    /// The AuthZEN catalogue held now.
    pub fn catalogue(&self) -> Catalogue {
        self.lock().catalogue.clone()
    }

    /// The AuthZEN caller list held now (#1189).
    pub fn callers(&self) -> Callers {
        self.lock().callers.clone()
    }

    /// The client this PEP pulls with — the AuthZEN forward (#564) goes
    /// through it, so it presents the same certificate and verifies the PDP
    /// the same way.
    pub fn client(&self) -> &PdpClient {
        &self.client
    }

    /// One forwarded AuthZEN evaluation (#564), counted beside
    /// [`Sync::count_authzen`], which counts it too.
    pub fn count_forwarded(&self) {
        self.lock().authzen.forwarded += 1;
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
                // A COUNT, for the reason above: which applications
                // enforce is the service's to tell a REMOTE_PEPS holder.
                "fgaApplications": c.fga_applications.len(),
                "refused": c.refused,
                "leftOutByThePdp": c.left_out,
                "settings": {
                    "enabled": c.settings.enabled,
                    "resolveSubjectTypes": c.settings.resolve_subject_types,
                    "batchEnabled": c.settings.batch_enabled,
                    "maxEvaluations": c.settings.max_evaluations,
                    "maxBodyBytes": c.settings.max_body_bytes,
                    "returnReasons": c.settings.return_reasons,
                    "obligationsProfile": c.settings.obligations_profile
                },
                "lastPullAt": c.last_pull_at,
                "lastPullOk": c.last_pull_ok,
                "lastPullWhy": c.last_pull_why
            },
            "answered": { "decisions": a.decisions, "true": a.permitted,
                          "false": a.denied, "errors": a.errors,
                          "forwarded": a.forwarded }
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
        // What is IN FORCE (#1760): the environment's until the settings
        // pull brings the service's, which the heartbeat then reports.
        let now = o.now();
        let mut body = json!({
            "name": o.name,
            "notifyUrl":
                crate::options::advertised_notify_url(&now.notify_url),
            "bias": now.bias.as_str(), "resource": now.resource,
            "version": o.version, "description": now.description
        });
        // `hostname` (#1760): the name the realm's default listener
        // certificate then carries, so the derived notify URL resolves on
        // a fresh install. Only when it is a DNS name; an older service
        // ignores it.
        if let Some(host) = crate::options::reported_hostname() {
            body["hostname"] = json!(host);
        }
        let answer = self
            .client
            .call_authorized(
                Resource::Pep,
                Method::POST,
                "/xacml/pep/register",
                Some(Body::Json(body)),
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
        // THE CREDENTIAL IT WAS ACTUALLY MADE ON (rcbj, 2026-11-16): a
        // token, a client certificate, or neither — never "mutual TLS" of a
        // registration made on a token.
        let on = self.client.credential().used_on(answer.no_token.as_deref());
        let why = if authenticated {
            format!("Registered as \"{}\" on {}.", name, on)
        } else {
            format!(
                "Registered as \"{}\" on {}, and the PDP could not name \
                 this PEP from it; it has marked this row unauthenticated \
                 and is right to.",
                name, on
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
        self.pull_round(cause, false).await
    }

    /// A FULL pull (a Sync from the console, 2026-11-16): every document
    /// asked for without its token or ETag, so the PDP sends each one whole
    /// and this PEP loads it again, where an ordinary round is answered 304
    /// for what it already holds.
    #[tracing::instrument(level = "debug", skip(self))]
    pub async fn pull_full(&self, cause: &str) -> bool {
        self.pull_round(cause, true).await
    }

    /// Whether a full pull may start now, and if so records that it did:
    /// at most one a poll interval, because the nudge that asks for one is
    /// not authenticated and each one has the PDP send every document.
    pub fn claim_full_pull(&self) -> bool {
        let floor = std::time::Duration::from_millis(
            self.options.now().poll_interval_ms,
        );
        let now = std::time::Instant::now();
        let mut state = self.lock();
        let free = match state.last_full_pull {
            Some(at) => now.duration_since(at) >= floor,
            None => true,
        };
        if free {
            state.last_full_pull = Some(now);
        }
        free
    }

    async fn pull_round(&self, cause: &str, full: bool) -> bool {
        let changed_before = self.lock().held.last_change_at.clone();
        self.pull_settings(full).await;
        self.pull_once(cause, full).await;
        self.pull_catalogue(full).await;
        self.pull_callers(full).await;
        if self.options.proxy_enabled {
            self.pull_proxy(full).await;
        }
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

    // -----------------------------------------------------------------------
    // THE SETTINGS (#1760). See the header: first in every round, its own
    // token, a failure keeps what is held, an older service's 404 is the
    // environment.
    // -----------------------------------------------------------------------
    async fn pull_settings(&self, full: bool) {
        let (token, etag) = if full {
            (String::new(), String::new())
        } else {
            let state = self.lock();
            (
                state.settings.sync_token.clone(),
                state.settings.etag.clone(),
            )
        };
        let query = if token.is_empty() {
            String::new()
        } else {
            format!("?since={}", encode(&token))
        };
        let headers: Vec<(&str, String)> = if etag.is_empty() {
            Vec::new()
        } else {
            vec![("If-None-Match", etag)]
        };
        let answer = self
            .client
            .call_authorized_with(
                Resource::Pep,
                Method::GET,
                &format!("/xacml/pep/settings{}", query),
                None,
                &headers,
                None,
            )
            .await;
        if let Some(error) = &answer.error {
            self.keep_settings(
                &format!("Could not reach the PDP: {}", error),
                "STS-XPEP-0100",
            );
            return;
        }
        if answer.status == 304 {
            let mut state = self.lock();
            state.settings.last_pull_at = iso_now();
            state.settings.last_pull_ok = true;
            state.settings.last_pull_why =
                "Unchanged; these settings are current.".into();
            state.last_settings_kept_why.clear();
            return;
        }
        if answer.status == 404 {
            // AN OLDER SERVICE (before #1760's settings): nothing is
            // managed there, so the environment is in force — and what an
            // earlier pull applied from a newer one is dropped, since that
            // service is not the one answering now.
            let first = {
                let mut state = self.lock();
                let first = !state.settings.not_offered;
                state.settings = SettingsHolding {
                    last_pull_at: iso_now(),
                    last_pull_ok: true,
                    last_pull_why: "The PDP has no settings endpoint (it \
                                    is older than this PEP), so every \
                                    setting is the environment's or the \
                                    default."
                        .into(),
                    not_offered: true,
                    ..SettingsHolding::default()
                };
                first
            };
            if first {
                tracing::info!(
                    "{}xacml-pep: the PDP has no GET /xacml/pep/settings (it \
                     is older than this PEP); every setting is the \
                     environment's or the default.",
                    tag("STS-XPEP-0101")
                );
                self.options.managed.apply(Managed::default());
                self.apply_settings_effects();
            }
            return;
        }
        if answer.status != 200 {
            let detail = answer
                .error_description()
                .map(|d| format!(": {}", d))
                .unwrap_or_default();
            self.keep_settings(
                &format!(
                    "The PDP answered {} to the settings pull{}.",
                    answer.status, detail
                ),
                "STS-XPEP-0100",
            );
            return;
        }
        let Some(said) = answer.json.filter(Value::is_object) else {
            self.keep_settings(
                "The PDP answered 200 to the settings pull with something \
                 that is not a JSON object.",
                "STS-XPEP-0100",
            );
            return;
        };
        self.receive_settings(&said, answer.etag);
    }

    /// One pulled settings answer, applied. Apart from the transport so a
    /// test can hand it a document.
    pub fn receive_settings(&self, said: &Value, etag: Option<String>) {
        let token = said["syncToken"].as_str().unwrap_or("").to_string();
        let configured = said["configured"].as_bool().unwrap_or(false);
        let managed = Managed::parse(
            &token,
            configured,
            if configured {
                &said["settings"]
            } else {
                &Value::Null
            },
        );
        let count = managed.values.len();
        self.options.managed.apply(managed);
        {
            let mut state = self.lock();
            state.last_settings_kept_why.clear();
            state.settings = SettingsHolding {
                sync_token: token.clone(),
                etag: etag.unwrap_or_default(),
                last_pull_at: iso_now(),
                last_pull_ok: true,
                last_pull_why: if configured {
                    format!("Pulled {} setting(s) set by the service.", count)
                } else {
                    "The service sets nothing for this PEP; every setting is \
                     the environment's or the default."
                        .into()
                },
                not_offered: false,
                listeners: said["listeners"].clone(),
                environment_tuning: said["environmentTuning"].clone(),
            };
        }
        tracing::info!(
            "xacml-pep: settings pulled, token {}: {} set by the service.",
            token,
            count
        );
        self.apply_settings_effects();
    }

    /// What a change of settings must reach that does not read `now()` at
    /// its use: the PDP client's timeout and body bound, the proxy session
    /// store's bounds, and the log's level. Everything else reads `now()`.
    pub fn apply_settings_effects(&self) {
        let now = self.options.now();
        self.client.set_limits(now.timeout_ms, now.max_body_bytes);
        self.proxy_sessions
            .set_limits(now.proxy_max_sessions, now.proxy_session_ttl_ms);
        sts_core::log::set_level(sts_core::log::parse_level(&now.log_level));
    }

    /// A failed settings pull keeps what is held, warned once per reason.
    fn keep_settings(&self, why: &str, code: &str) {
        let mut state = self.lock();
        state.settings.last_pull_ok = false;
        state.settings.last_pull_why = format!(
            "{} KEEPING the settings held{}.",
            why,
            if state.settings.sync_token.is_empty() {
                " (none from the service: the environment's are in force)"
                    .to_string()
            } else {
                format!(", pulled at {}", state.settings.last_pull_at)
            }
        );
        if state.last_settings_kept_why != why {
            state.last_settings_kept_why = why.to_string();
            tracing::warn!(
                "{}xacml-pep: {}",
                tag(code),
                state.settings.last_pull_why
            );
        }
    }

    /// `settings` on `GET /`: the pull's state and every value in force.
    pub fn settings_json(&self) -> Value {
        let s = self.lock().settings.clone();
        let mut report = self.options.settings_report();
        report["lastPullAt"] = json!(s.last_pull_at);
        report["lastPullOk"] = json!(s.last_pull_ok);
        report["lastPullWhy"] = json!(s.last_pull_why);
        report["offered"] = json!(!s.not_offered);
        report["configured"] = json!(self.options.managed.current().configured);
        report
    }

    async fn pull_once(&self, cause: &str, full: bool) {
        let (token, name) = {
            let state = self.lock();
            let token = if full {
                String::new()
            } else {
                state.held.sync_token.clone()
            };
            (token, self.options.name.clone())
        };
        let query = if token.is_empty() {
            format!("?pep={}", encode(&name))
        } else {
            format!("?since={}&pep={}", encode(&token), encode(&name))
        };
        let answer = self
            .client
            .call_authorized(
                Resource::Pep,
                Method::GET,
                &format!("/xacml/pep/policies{}", query),
                None,
            )
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
        let on = self.client.credential().used_on(answer.no_token.as_deref());
        self.load(&said, cause, &on);
    }

    /// Parses and STATICALLY VALIDATES every pulled document with this PEP's
    /// own engine — never taken on trust because the PDP accepted it.
    fn load(&self, said: &Value, cause: &str, on: &str) {
        let rows = said["policies"].as_array().cloned().unwrap_or_default();
        let mut repository = HashMap::new();
        let mut by_name: HashMap<String, PolicyNode> = HashMap::new();
        let mut names_twice: Vec<String> = Vec::new();
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
                    if let Some(name) =
                        row["name"].as_str().filter(|n| !n.is_empty())
                    {
                        if by_name
                            .insert(name.to_string(), parsed.clone())
                            .is_some()
                        {
                            names_twice.push(name.to_string());
                        }
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
        // A name that is not unique names nothing. The service keeps names
        // unique per realm, so it cannot happen there; if it does, a route
        // naming it is refused (`STS-XPEP-0117`, which says so) rather than
        // decided by whichever row came last.
        for name in &names_twice {
            by_name.remove(name);
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
                by_name,
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
            "{}xacml-pep: pulled {} policy(ies) on {}, token {}. {}",
            if has_root {
                String::new()
            } else {
                tag("STS-XPEP-0021")
            },
            count,
            on,
            state.held.sync_token,
            why
        );
    }

    /// A pulled policy set handed straight in, for a test that has no PDP.
    #[cfg(test)]
    pub fn load_for_test(&self, said: &Value) {
        self.load(said, "test", "a test");
    }

    /// A pulled AuthZEN catalogue handed straight in, for a test that has
    /// no PDP.
    #[cfg(test)]
    pub fn load_catalogue_for_test(&self, said: &Value) {
        self.load_catalogue(said);
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
    async fn pull_catalogue(&self, full: bool) {
        let token = if full {
            String::new()
        } else {
            self.lock().catalogue.sync_token.clone()
        };
        let query = if token.is_empty() {
            String::new()
        } else {
            format!("?since={}", encode(&token))
        };
        let answer = self
            .client
            .call_authorized(
                Resource::Pep,
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
        let fga_applications = match parse_fga_applications(said) {
            Ok(list) => list,
            Err(why) => {
                self.keep_catalogue(&why, "STS-XPEP-0059");
                return;
            }
        };
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
            fga_applications: Arc::new(fga_applications),
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
    async fn pull_callers(&self, full: bool) {
        let token = if full {
            String::new()
        } else {
            self.lock().callers.sync_token.clone()
        };
        let query = if token.is_empty() {
            String::new()
        } else {
            format!("?since={}", encode(&token))
        };
        let answer = self
            .client
            .call_authorized(
                Resource::Pep,
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
    // THE REVERSE PROXY'S CONFIGURATION (#1760). Pulled after the callers,
    // with its own token and ETag; a failure keeps what is held.
    // -----------------------------------------------------------------------
    async fn pull_proxy(&self, full: bool) {
        let (token, etag) = if full {
            (String::new(), String::new())
        } else {
            let state = self.lock();
            (state.proxy.sync_token.clone(), state.proxy.etag.clone())
        };
        let query = if token.is_empty() {
            String::new()
        } else {
            format!("?since={}", encode(&token))
        };
        let headers: Vec<(&str, String)> = if etag.is_empty() {
            Vec::new()
        } else {
            vec![("If-None-Match", etag)]
        };
        let answer = self
            .client
            .call_authorized_with(
                Resource::Pep,
                Method::GET,
                &format!("/xacml/pep/proxy{}", query),
                None,
                &headers,
                None,
            )
            .await;
        if let Some(error) = &answer.error {
            self.keep_proxy(
                &format!("Could not reach the PDP: {}", error),
                "STS-XPEP-0060",
            );
            return;
        }
        if answer.status == 304 {
            let mut state = self.lock();
            state.proxy.last_pull_at = iso_now();
            state.proxy.last_pull_ok = true;
            state.proxy.last_pull_why =
                "Unchanged; this configuration is current.".into();
            state.last_proxy_kept_why.clear();
            return;
        }
        if answer.status != 200 {
            let detail = answer
                .error_description()
                .map(|d| format!(": {}", d))
                .unwrap_or_default();
            let older = if answer.status == 404 {
                " A PDP older than #1760 has no proxy configuration endpoint."
            } else {
                ""
            };
            self.keep_proxy(
                &format!(
                    "The PDP answered {} to the proxy configuration pull{}.{}",
                    answer.status, detail, older
                ),
                "STS-XPEP-0061",
            );
            return;
        }
        let Some(said) = answer.json else {
            self.keep_proxy(
                "The PDP answered 200 to the proxy configuration pull with \
                 something that is not JSON.",
                "STS-XPEP-0061",
            );
            return;
        };
        self.receive_proxy(&said, answer.etag);
    }

    /// One pulled answer: loaded whole, or refused whole and the held one
    /// kept. Apart from the transport so a test can hand it a document.
    pub fn receive_proxy(&self, said: &Value, etag: Option<String>) {
        match proxy_config::parse_pulled(said) {
            Ok(pulled) => self.load_proxy(pulled, etag),
            Err(why) => self.keep_proxy(
                &format!(
                    "The proxy configuration the PDP sent was refused whole: \
                     {}. Nothing of it is used.",
                    why
                ),
                "STS-XPEP-0062",
            ),
        }
    }

    fn load_proxy(&self, pulled: Pulled, etag: Option<String>) {
        let routes = pulled.proxy.as_ref().map_or(0, |p| p.routes.len());
        let why = match pulled.active() {
            Some(_) => {
                format!("Pulled a proxy configuration of {} route(s).", routes)
            }
            None if pulled.configured => "Pulled a proxy configuration that \
                is switched off (enabled: false); the proxy answers 404, \
                and a browser's / is the start page."
                .to_string(),
            None => "The PDP holds no proxy configuration for this PEP; the \
                     proxy answers 404, and a browser's / is the start page."
                .to_string(),
        };
        let mut state = self.lock();
        state.last_proxy_kept_why.clear();
        tracing::info!("xacml-pep: {} Token {}.", why, pulled.sync_token);
        // THE STATE CHANGE: the first configuration since the start ends
        // the 503s of STS-XPEP-0118, said once with their count.
        if !state.proxy.loaded && state.proxy_waiting.refused > 0 {
            let line = format!(
                "xacml-pep: the reverse proxy received its first \
                 configuration since it started; {} request(s) were \
                 answered 503 (STS-XPEP-0118) while it waited.",
                state.proxy_waiting.refused
            );
            tracing::info!("{}", line);
            #[cfg(test)]
            crate::proxy::logged::note(&line);
        }
        state.proxy = ProxyHolding {
            loaded: true,
            sync_token: pulled.sync_token.clone(),
            etag: etag.unwrap_or_default(),
            pulled: Arc::new(pulled),
            last_pull_at: iso_now(),
            last_pull_ok: true,
            last_pull_why: why,
        };
    }

    /// A failed proxy pull keeps what is held, and warns once per distinct
    /// reason.
    fn keep_proxy(&self, why: &str, code: &str) {
        let mut state = self.lock();
        state.proxy.last_pull_ok = false;
        state.proxy.last_pull_why = if state.proxy.loaded {
            format!(
                "{} KEEPING the configuration pulled at {}, so the proxy \
                 goes on routing as it did.",
                why, state.proxy.last_pull_at
            )
        } else {
            format!(
                "{} NO CONFIGURATION HAS BEEN RECEIVED since the start, so \
                 the proxy answers 503 with Retry-After to everything.",
                why
            )
        };
        if state.last_proxy_kept_why != why {
            state.last_proxy_kept_why = why.to_string();
            tracing::warn!(
                "{}xacml-pep: {}",
                tag(code),
                state.proxy.last_pull_why
            );
        }
    }

    /// The configuration in force now.
    pub fn proxy(&self) -> Arc<Pulled> {
        self.lock().proxy.pulled.clone()
    }

    /// The configuration in force now, and whether ANY configuration
    /// answer has been loaded since this process started — read under one
    /// lock, so a pull landing between the two cannot be half seen. Not
    /// received yet is the 503 of `STS-XPEP-0118`; received and empty or
    /// switched off is the 404 of `STS-XPEP-0065`.
    pub fn proxy_received(&self) -> (Arc<Pulled>, bool) {
        let state = self.lock();
        (state.proxy.pulled.clone(), state.proxy.loaded)
    }

    /// One request answered 503 before the first configuration. Logged
    /// when the state is first met, then as a count at most once per
    /// [`WAITING_SUMMARY_EVERY`] — a browser retrying, a health probe of
    /// the application or a crawler would otherwise write a line each.
    /// No `instrument`: it runs on every such request.
    pub fn note_waiting(&self) {
        let mut state = self.lock();
        let why = state.proxy.last_pull_why.clone();
        let w = &mut state.proxy_waiting;
        w.refused += 1;
        w.unreported += 1;
        let now = std::time::Instant::now();
        let first = w.last_line.is_none();
        if !first
            && w.last_line.is_some_and(|at| {
                now.duration_since(at) < WAITING_SUMMARY_EVERY
            })
        {
            return;
        }
        let line = if first {
            format!(
                "{}xacml-pep: the reverse proxy has received no \
                 configuration since it started, so it answers 503 with \
                 Retry-After to every request until the first pull \
                 succeeds. A count follows at most once a minute. The \
                 last pull: {}",
                tag("STS-XPEP-0118"),
                why
            )
        } else {
            format!(
                "{}xacml-pep: the reverse proxy is still waiting for its \
                 first configuration: {} request(s) answered 503 in the \
                 last {}s, {} since the start. The last pull: {}",
                tag("STS-XPEP-0118"),
                w.unreported,
                w.last_line.map_or(0, |at| now.duration_since(at).as_secs()),
                w.refused,
                why
            )
        };
        w.unreported = 0;
        w.last_line = Some(now);
        tracing::warn!("{}", line);
        #[cfg(test)]
        crate::proxy::logged::note(&line);
    }

    /// One answer of the reverse proxy, counted.
    pub fn count_proxy(&self, status: u16, forwarded: bool) {
        let mut state = self.lock();
        let c = &mut state.proxy_counters;
        c.requests += 1;
        if forwarded {
            c.forwarded += 1;
        }
        *c.by_status.entry(status).or_insert(0) += 1;
    }

    pub fn set_signals_reporter(&self, reporter: SignalsReporter) {
        *self
            .signals_reporter
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(reporter);
    }

    pub fn set_streams_reporter(&self, reporter: SignalsReporter) {
        *self
            .streams_reporter
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(reporter);
    }

    pub fn set_listeners_reporter(&self, reporter: SignalsReporter) {
        *self
            .listeners_reporter
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(reporter);
    }

    /// The listeners the last settings pull defined (#1760): null for none,
    /// which is also an older service's answer.
    pub fn listener_definitions(&self) -> Value {
        self.lock().settings.listeners.clone()
    }

    /// The pull's `environmentTuning`, or null when the service sent none.
    pub fn environment_tuning(&self) -> Value {
        self.lock().settings.environment_tuning.clone()
    }

    pub fn set_relying_parties(&self, counts: (usize, usize)) {
        self.lock().relying_parties = counts;
    }

    pub fn count_sign_in(&self) {
        self.lock().proxy_counters.sign_ins += 1;
    }

    pub fn count_session_ended(&self) {
        self.lock().proxy_counters.sessions_ended += 1;
    }

    /// `proxy` on `GET /`: COUNTS, never a route, a URL or a credential —
    /// `GET /` answers whoever reaches the container.
    pub fn proxy_json(&self) -> Value {
        let (live, pending) = self.proxy_sessions.counts();
        // Asked before this module's own lock is taken: the reporter takes
        // the relying parties' locks, never this one.
        let signals = self
            .signals_reporter
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .map_or(Value::Null, |report| report());
        let state = self.lock();
        let h = &state.proxy;
        let c = &state.proxy_counters;
        let active = h.pulled.active();
        let mut mechanisms = serde_json::Map::new();
        for m in [
            Mechanism::Session,
            Mechanism::OAuth2,
            Mechanism::Saml2,
            Mechanism::Basic,
        ] {
            let n = active
                .map_or(0, |p| p.routes.iter().filter(|r| r.allows(m)).count());
            mechanisms.insert(m.as_str().into(), json!(n));
        }
        let by_status: serde_json::Map<String, Value> = c
            .by_status
            .iter()
            .map(|(k, v)| (k.to_string(), json!(v)))
            .collect();
        let o = &self.options;
        json!({
            "enabled": o.proxy_enabled,
            "ports": { "http": o.proxy_port, "https": o.proxy_https_port },
            "loaded": h.loaded,
            "configured": h.pulled.configured,
            "active": active.is_some(),
            "syncToken": h.sync_token,
            "routes": active.map_or(0, |p| p.routes.len()),
            "publicRoutes": active
                .map_or(0, |p| {
                    p.routes.iter().filter(|r| r.is_public()).count()
                }),
            "routesByMechanism": mechanisms,
            "unusableRoutes": active.map_or(0, |p| {
                p.routes
                    .iter()
                    .filter(|r| !r.is_public() && !r.resolved.usable)
                    .count()
            }),
            "sessionClients": h.pulled.realm.clients.len(),
            "relyingParties": state.relying_parties.0,
            "signalsReceivers": state.relying_parties.1,
            "signals": signals,
            "signingCertificates": h.pulled.realm.signing_certificates.len(),
            "lastPullAt": h.last_pull_at,
            "lastPullOk": h.last_pull_ok,
            "lastPullWhy": h.last_pull_why,
            "answered": {
                "requests": c.requests,
                "forwarded": c.forwarded,
                "byStatus": by_status,
                "signIns": c.sign_ins,
                "sessionsEnded": c.sessions_ended
            },
            "sessions": { "live": live, "signInsInFlight": pending,
                          "max": o.now().proxy_max_sessions },
            "what": "A reverse proxy in front of one application, on ports \
                     of its own: deny-by-default over the route table pulled \
                     from the service, each route's mechanism verified here \
                     where it can be and at the service where it cannot, and \
                     the decision made here against the policy this PEP \
                     holds. Counts only: the routes and the upstream are the \
                     service's to show."
        })
    }

    // -----------------------------------------------------------------------
    // HEARTBEAT. What this PEP has enforced, so a person can see it.
    // -----------------------------------------------------------------------
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn heartbeat(&self) -> HeartbeatResult {
        // THE REVERSE PROXY'S SIGNAL-STREAM HEALTH (#1760): the same counts
        // and ages `GET /`'s `proxy.signals` reports, so the service can
        // draw them on the PEP's row. Only when a proxy built the reporter;
        // a PEP with no proxy sends no `signals` member at all, and the
        // service keeps the row's "not reported". An older service ignores
        // a member it does not read, so this costs it nothing. Asked before
        // this module's lock is taken, as `proxy_json()` does.
        let signals = self
            .signals_reporter
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .map(|report| report());
        // ONE ROW PER STREAM (#1760), beside the counts: on the heartbeat
        // only, which goes to the service over mutual TLS, since a row names
        // the client its stream serves.
        let streams = self
            .streams_reporter
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .map(|report| report());
        // EVERY LISTENER AND WHAT IT IS DOING (#1760). An older service
        // ignores the member.
        let listeners = self
            .listeners_reporter
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .map(|report| report());
        let (token, count, c) = {
            let state = self.lock();
            (
                state.held.sync_token.clone(),
                state.held.policy_count,
                state.counters,
            )
        };
        let o = &self.options;
        let now = o.now();
        // `settings` (#1760): every setting's value in force and whether it
        // is the service's, the environment's or the default, with the
        // settings token it was applied from — so the PEP's page can say
        // whether this PEP holds what was set. An older service ignores it.
        let mut body = json!({
            "name": o.name, "syncToken": token, "policyCount": count,
            "decisions": c.decisions, "allowed": c.allowed,
            "refused": c.refused,
            "undischargeable": c.undischargeable,
            "bias": now.bias.as_str(), "resource": now.resource,
            "version": o.version,
            "notifyUrl": crate::options::advertised_notify_url(&now.notify_url),
            "settings": o.settings_report()
        });
        if let Some(mut signals) = signals {
            if let Some(streams) = streams {
                signals["streams"] = streams;
            }
            body["signals"] = signals;
        }
        if let Some(listeners) = listeners {
            body["listeners"] = listeners;
        }
        // `hostname` (#1760), as on the registration: absent keeps what
        // the service holds.
        if let Some(host) = crate::options::reported_hostname() {
            body["hostname"] = json!(host);
        }
        let answer = self
            .client
            .call_authorized(
                Resource::Pep,
                Method::POST,
                "/xacml/pep/heartbeat",
                Some(Body::Json(body)),
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

    /// `fgaApplications` (#564, P7): absent is none (a service older than
    /// fine-grained authorization); a list of identifiers is read as it
    /// is; anything else refuses the whole catalogue rather than dropping
    /// an entry, which would decide that application from the root.
    #[test]
    fn fga_applications_are_read_whole_or_not_at_all() {
        assert_eq!(parse_fga_applications(&json!({})), Ok(Vec::new()));
        assert_eq!(
            parse_fga_applications(&json!({ "fgaApplications": ["a", "b"] })),
            Ok(vec!["a".to_string(), "b".to_string()])
        );
        assert_eq!(
            parse_fga_applications(&json!({ "fgaApplications": [] })),
            Ok(Vec::new())
        );
        for bad in [
            json!({ "fgaApplications": "a" }),
            json!({ "fgaApplications": null }),
            json!({ "fgaApplications": ["a", 1] }),
            json!({ "fgaApplications": ["a", ""] }),
            json!({ "fgaApplications": ["x".repeat(257)] }),
        ] {
            assert!(parse_fga_applications(&bad).is_err(), "{}", bad);
        }
    }

    // -----------------------------------------------------------------------
    // THE SETTINGS PULL (#1760), against a mock service on a loopback
    // socket: applied, kept on a failure, the environment's on a 404.
    // -----------------------------------------------------------------------
    type Answer = Arc<Mutex<(u16, Value, Vec<String>)>>;

    async fn settings_service(answer: Answer) -> String {
        let socket =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let app = axum::Router::new().route(
            "/xacml/pep/settings",
            axum::routing::get(move |uri: axum::http::Uri| {
                let answer = answer.clone();
                async move {
                    let mut held = answer.lock().unwrap();
                    held.2.push(uri.query().unwrap_or("").to_string());
                    let status =
                        axum::http::StatusCode::from_u16(held.0).unwrap();
                    (status, axum::Json(held.1.clone()))
                }
            }),
        );
        tokio::spawn(async move {
            axum::serve(socket, app).await.unwrap();
        });
        format!("http://127.0.0.1:{}", port)
    }

    fn settings_sync(base: &str) -> Sync {
        let mut options = Options::from_env("0.0.0");
        options.pdp_url = base.to_string();
        options.bias = crate::options::Bias::DenyBiased;
        options.poll_interval_ms = 15000;
        options.timeout_ms = 5000;
        options.proxy_max_sessions = 10000;
        let client = PdpClient::new(&options).unwrap();
        Sync::new(client, options)
    }

    // A SYNC FROM THE CONSOLE (2026-11-16): a full pull asks without its
    // token, and one is claimed at most once a poll interval.
    #[tokio::test]
    async fn a_full_pull_asks_without_its_token_once_an_interval() {
        let answer: Answer = Arc::new(Mutex::new((
            200,
            json!({ "syncToken": "s1", "pep": "pep-1", "configured": true,
                    "settings": {} }),
            Vec::new(),
        )));
        let sync = settings_sync(&settings_service(answer.clone()).await);
        sync.pull_settings(false).await;
        sync.pull_settings(false).await;
        sync.pull_settings(true).await;
        let asked = answer.lock().unwrap().2.clone();
        assert_eq!(
            asked,
            vec!["".to_string(), "since=s1".to_string(), "".to_string()]
        );
        assert!(sync.claim_full_pull());
        assert!(!sync.claim_full_pull());
    }

    #[tokio::test]
    async fn the_service_settings_win_and_a_404_is_the_environment() {
        let answer: Answer = Arc::new(Mutex::new((
            200,
            json!({ "syncToken": "s1", "pep": "pep-1", "configured": true,
                    "settings": { "bias": "permit-biased",
                                  "pollIntervalMs": 2000, "timeoutMs": 900,
                                  "maxBodyBytes": 65536,
                                  "proxyMaxSessions": 7,
                                  "logLevel": "debug",
                                  "aNewerSetting": true } }),
            Vec::new(),
        )));
        let sync = settings_sync(&settings_service(answer.clone()).await);
        // Before any pull: the environment's.
        assert_eq!(sync.options.now().poll_interval_ms, 15000);
        sync.pull_settings(false).await;
        let now = sync.options.now();
        assert_eq!(now.bias, crate::options::Bias::PermitBiased);
        assert_eq!(now.poll_interval_ms, 2000);
        assert_eq!(now.log_level, "debug");
        // The parts that hold a bound of their own were handed it.
        assert_eq!(sync.client.limits(), (900, 65536));
        let report = sync.settings_json();
        assert_eq!(report["token"], "s1");
        assert_eq!(report["values"]["bias"]["source"], "service");
        assert_ne!(
            report["values"]["heartbeatIntervalMs"]["source"],
            "service"
        );
        assert_eq!(report["configured"], true);
        // The next pull asks with the token, and a 304 keeps what is held.
        answer.lock().unwrap().0 = 304;
        sync.pull_settings(false).await;
        assert!(answer.lock().unwrap().2[1].contains("since=s1"));
        assert_eq!(sync.options.now().poll_interval_ms, 2000);
        // A failure keeps it too.
        answer.lock().unwrap().0 = 500;
        sync.pull_settings(false).await;
        let bias = sync.options.now().bias;
        assert_eq!(bias, crate::options::Bias::PermitBiased);
        assert!(!sync.lock().settings.last_pull_ok);
        // An older service: no endpoint, so the environment is in force.
        answer.lock().unwrap().0 = 404;
        sync.pull_settings(false).await;
        let now = sync.options.now();
        assert_eq!(now.bias, crate::options::Bias::DenyBiased);
        assert_eq!(now.poll_interval_ms, 15000);
        assert_eq!(sync.client.limits(), (5000, 4 * 1024 * 1024));
        assert_eq!(sync.settings_json()["offered"], false);
    }

    #[tokio::test]
    async fn nothing_set_and_a_refused_value_fall_back_to_the_environment() {
        let answer: Answer = Arc::new(Mutex::new((
            200,
            json!({ "syncToken": "s2", "configured": true,
                    "settings": { "pollIntervalMs": 5, "bias": "loud",
                                  "heartbeatIntervalMs": 3000 } }),
            Vec::new(),
        )));
        let sync = settings_sync(&settings_service(answer.clone()).await);
        sync.pull_settings(false).await;
        let now = sync.options.now();
        assert_eq!(now.poll_interval_ms, 15000, "out of bounds is refused");
        assert_eq!(now.bias, crate::options::Bias::DenyBiased);
        assert_eq!(now.heartbeat_interval_ms, 3000, "the rest applies");
        // The service sets nothing any more: every setting goes back.
        *answer.lock().unwrap() = (
            200,
            json!({ "syncToken": "s3", "configured": false, "note": "x" }),
            Vec::new(),
        );
        sync.pull_settings(false).await;
        assert_ne!(sync.options.now().heartbeat_interval_ms, 3000);
        assert_eq!(sync.settings_json()["configured"], false);
    }

    /// Every round pulls the settings, whatever the other pulls answer.
    #[tokio::test]
    async fn every_round_pulls_the_settings_first() {
        let answer: Answer = Arc::new(Mutex::new((
            200,
            json!({ "syncToken": "r1", "configured": true,
                    "settings": { "heartbeatIntervalMs": 4000 } }),
            Vec::new(),
        )));
        let sync = settings_sync(&settings_service(answer).await);
        sync.pull("poll").await;
        assert_eq!(sync.options.now().heartbeat_interval_ms, 4000);
    }
}
