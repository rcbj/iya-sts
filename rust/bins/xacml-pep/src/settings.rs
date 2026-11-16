// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE SETTINGS THE SERVICE MANAGES (#1760): everything about this PEP an
//! administrator may change on its console page, pulled from `GET
//! /xacml/pep/settings` and applied while the process runs.
//!
//! * **THE PRECEDENCE IS SERVICE, THEN ENVIRONMENT, THEN DEFAULT.** A value
//!   the service set wins; a setting it did not set is the environment
//!   variable that always configured it; a variable that is unset is the
//!   built-in default. So every variable that configured this container
//!   before keeps doing so wherever the service is silent.
//! * **WHAT IS NOT HERE IS BOOTSTRAP**: the PDP's URL, this PEP's name, its
//!   client certificate, key and anchors, the files its TLS stacks read and
//!   the ports it binds. Those are needed before the first pull, or name
//!   something on this container's own disk, and stay in the environment
//!   (`xacml-pep/CLAUDE.md`, *Configuration*).
//! * **AN OLDER SERVICE HAS NO SUCH ENDPOINT**: its 404 is the environment
//!   in force, said once (`STS-XPEP-0101`). **A NEWER SERVICE MAY SEND A
//!   MEMBER THIS PEP DOES NOT KNOW**, which is ignored rather than refused,
//!   so a service can grow a setting without stranding every older PEP.
//! * **EVERY VALUE IS READ AGAIN HERE**, by the same bounds the service
//!   validated it with. One that fails is LEFT OUT and named
//!   (`STS-XPEP-0102`) — the setting is then the environment's — never the
//!   whole document: unlike a route table, one setting does not change what
//!   another means. **The one exception is a `notifyUrl` that is not https**
//!   (2026-11-14): it is REJECTED, and the PEP advertises no notify URL
//!   rather than fall back (`notify_rejected()`, `STS-XPEP-0113`).
//! * **A FAILED PULL KEEPS WHAT IS HELD** (`STS-XPEP-0100`), as every pull
//!   here does.
//!
//! The table below is the service's `xacml/xacml_pep_settings.ts` `SETTINGS`
//! in this language; `tests/xacml_pep_settings.js` holds the two to the same
//! keys, variables and bounds.

use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, RwLock};

use serde_json::{json, Map, Value};
use sts_core::log::tag;

/// What a setting is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// An integer in `min..=max`.
    Int(u64, u64),
    Bool,
    /// One of a closed set.
    Enum(&'static [&'static str]),
    /// Text of at most this many characters, no control character.
    Text(usize),
    /// An absolute http(s) URL with no user name or fragment, or empty.
    Url,
    /// An https origin with no path, query or fragment, or empty.
    Origin,
}

/// One row: the member the service sends, the variable it replaces, and
/// what it is.
#[derive(Debug, Clone, Copy)]
pub struct Row {
    pub key: &'static str,
    pub env: &'static str,
    pub kind: Kind,
}

pub const BIASES: &[&str] = &["deny-biased", "permit-biased"];
pub const LOG_LEVELS: &[&str] =
    &["trace", "debug", "info", "warn", "error", "fatal"];

const DAY_MS: u64 = 86_400_000;

/// EVERY SETTING THE SERVICE MAY MANAGE, in the order the console draws
/// them. The bounds are the service's.
pub const SETTINGS: &[Row] = &[
    Row {
        key: "description",
        env: "PEP_DESCRIPTION",
        kind: Kind::Text(1024),
    },
    Row {
        key: "resource",
        env: "PEP_RESOURCE",
        kind: Kind::Text(2048),
    },
    Row {
        key: "notifyUrl",
        env: "PEP_NOTIFY_URL",
        kind: Kind::Url,
    },
    Row {
        key: "bias",
        env: "PEP_BIAS",
        kind: Kind::Enum(BIASES),
    },
    Row {
        key: "pip",
        env: "PEP_PIP",
        kind: Kind::Bool,
    },
    Row {
        key: "pollIntervalMs",
        env: "PEP_POLL_INTERVAL_MS",
        kind: Kind::Int(1000, DAY_MS),
    },
    Row {
        key: "heartbeatIntervalMs",
        env: "PEP_HEARTBEAT_INTERVAL_MS",
        kind: Kind::Int(1000, DAY_MS),
    },
    Row {
        key: "backoffMaxMs",
        env: "PEP_BACKOFF_MAX_MS",
        kind: Kind::Int(1000, DAY_MS),
    },
    Row {
        key: "timeoutMs",
        env: "PEP_TIMEOUT_MS",
        kind: Kind::Int(100, 120_000),
    },
    Row {
        key: "maxBodyBytes",
        env: "PEP_MAX_BODY_BYTES",
        kind: Kind::Int(1024, 104_857_600),
    },
    Row {
        key: "httpsReloadIntervalMs",
        env: "PEP_HTTPS_RELOAD_INTERVAL_MS",
        kind: Kind::Int(1000, 3_600_000),
    },
    Row {
        key: "logLevel",
        env: "PEP_LOG_LEVEL",
        kind: Kind::Enum(LOG_LEVELS),
    },
    Row {
        key: "authzen",
        env: "PEP_AUTHZEN",
        kind: Kind::Bool,
    },
    Row {
        key: "authzenPdpIdentifier",
        env: "PEP_AUTHZEN_PDP_IDENTIFIER",
        kind: Kind::Origin,
    },
    Row {
        key: "authzenForwardTimeoutMs",
        env: "PEP_AUTHZEN_FORWARD_TIMEOUT_MS",
        kind: Kind::Int(1, 120_000),
    },
    Row {
        key: "proxySessionRecheckMs",
        env: "PEP_PROXY_SESSION_RECHECK_MS",
        kind: Kind::Int(0, 3_600_000),
    },
    Row {
        key: "proxySessionTtlMs",
        env: "PEP_PROXY_SESSION_TTL_MS",
        kind: Kind::Int(1000, 30 * DAY_MS),
    },
    Row {
        key: "proxyMaxSessions",
        env: "PEP_PROXY_MAX_SESSIONS",
        kind: Kind::Int(1, 1_000_000),
    },
    Row {
        key: "proxyMaxAccounts",
        env: "PEP_PROXY_MAX_ACCOUNTS",
        kind: Kind::Int(1, 32),
    },
    Row {
        key: "proxyJwksTtlMs",
        env: "PEP_PROXY_JWKS_TTL_MS",
        kind: Kind::Int(0, DAY_MS),
    },
    Row {
        key: "proxyUpstreamInsecure",
        env: "PEP_PROXY_UPSTREAM_INSECURE",
        kind: Kind::Bool,
    },
    Row {
        key: "proxyRpAllowInsecure",
        env: "PEP_PROXY_RP_ALLOW_INSECURE",
        kind: Kind::Bool,
    },
    Row {
        key: "proxySignalsPollMs",
        env: "PEP_PROXY_SIGNALS_POLL_MS",
        kind: Kind::Int(100, 3_600_000),
    },
    Row {
        key: "proxySignalsStaleMs",
        env: "PEP_PROXY_SIGNALS_STALE_MS",
        kind: Kind::Int(1, DAY_MS),
    },
    Row {
        key: "proxyStripCookies",
        env: "PEP_PROXY_STRIP_COOKIES",
        kind: Kind::Text(1024),
    },
];

/// The row of a member, or `None` for one this PEP does not know.
pub fn row_of(key: &str) -> Option<&'static Row> {
    SETTINGS.iter().find(|row| row.key == key)
}

fn text_ok(text: &str, max: usize) -> bool {
    text.chars().count() <= max && !text.chars().any(char::is_control)
}

/// An absolute http(s) URL with no user name, password or fragment.
fn url_ok(text: &str) -> bool {
    if text.is_empty() {
        return true;
    }
    reqwest::Url::parse(text).is_ok_and(|url| {
        // HTTPS ONLY (2026-11-14): the one URL row is `notifyUrl`, and
        // the service nudges over https alone.
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
            && text_ok(text, 2048)
    })
}

/// One pulled value read by its row: the value, or why not.
pub fn check(row: &Row, value: &Value) -> Result<Value, String> {
    match row.kind {
        Kind::Int(min, max) => match value.as_u64() {
            Some(n) if (min..=max).contains(&n) => Ok(json!(n)),
            _ => Err(format!(
                "{} must be an integer from {} to {}",
                row.key, min, max
            )),
        },
        Kind::Bool => value
            .as_bool()
            .map(Value::Bool)
            .ok_or_else(|| format!("{} must be true or false", row.key)),
        Kind::Enum(values) => match value.as_str() {
            Some(s) if values.contains(&s) => Ok(json!(s)),
            _ => {
                Err(format!("{} must be one of {}", row.key, values.join(", ")))
            }
        },
        Kind::Text(max) => match value.as_str() {
            Some(s) if text_ok(s, max) => Ok(json!(s)),
            _ => Err(format!(
                "{} must be text of at most {} characters with no control \
                 character",
                row.key, max
            )),
        },
        Kind::Url => match value.as_str() {
            Some(s) if url_ok(s) => Ok(json!(s)),
            _ => Err(format!(
                "{} must be an absolute https URL with no user name or \
                 fragment: the nudge is sent over https only",
                row.key
            )),
        },
        Kind::Origin => match value.as_str() {
            Some("") => Ok(json!("")),
            Some(s) => crate::options::pdp_identifier_of(s)
                .map(Value::String)
                .ok_or_else(|| {
                    format!("{} must be an https origin with no path", row.key)
                }),
            None => Err(format!("{} must be a string", row.key)),
        },
    }
}

/// What the service set, read again here: the values that passed, the
/// members refused (each named), and the members this PEP does not know.
#[derive(Debug, Clone, Default)]
pub struct Managed {
    /// The pull's sync token; empty when nothing was ever pulled.
    pub token: String,
    /// Whether the service holds a settings document for this PEP.
    pub configured: bool,
    pub values: BTreeMap<&'static str, Value>,
    pub refused: Vec<String>,
    pub unknown: Vec<String>,
    /// A `notifyUrl` the service sent that is not an https URL (an older
    /// service's stored `http://` one): REJECTED rather than refused, so
    /// it is not a fallback to the environment either — this PEP then
    /// advertises no notify URL at all (`options::Options::notify_in_force`,
    /// `STS-XPEP-0113`).
    pub rejected_notify: Option<String>,
}

/// Whether a notify URL somebody SET is rejected (2026-11-14, rcbj: "If an
/// http:// URL is given and is not allowed per configuration, it should be
/// rejected"): a non-empty value that is not an https URL. The nudge is
/// sent over https only and nothing allows http any more
/// (`xacml.pepNotifyAllowHttp` is retired), so an `http://` one is always
/// rejected. Empty is "not set", never rejected.
pub fn notify_rejected(text: &str) -> bool {
    let trimmed = text.trim();
    !trimmed.is_empty()
        && !trimmed
            .get(..8)
            .is_some_and(|s| s.eq_ignore_ascii_case("https://"))
}

impl Managed {
    /// Reads `settings` as the pull carries it.
    pub fn parse(token: &str, configured: bool, said: &Value) -> Managed {
        let mut out = Managed {
            token: token.to_string(),
            configured,
            ..Managed::default()
        };
        let Some(members) = said.as_object() else {
            return out;
        };
        for (key, value) in members {
            match row_of(key) {
                None => out.unknown.push(key.clone()),
                Some(row)
                    if row.key == DERIVED_KEY
                        && value.as_str().is_some_and(notify_rejected) =>
                {
                    out.rejected_notify =
                        value.as_str().map(|s| s.trim().to_string());
                }
                Some(row) => match check(row, value) {
                    Ok(value) => {
                        out.values.insert(row.key, value);
                    }
                    Err(why) => out.refused.push(why),
                },
            }
        }
        out
    }

    pub fn u64(&self, key: &str) -> Option<u64> {
        self.values.get(key).and_then(Value::as_u64)
    }

    pub fn bool(&self, key: &str) -> Option<bool> {
        self.values.get(key).and_then(Value::as_bool)
    }

    pub fn str(&self, key: &str) -> Option<String> {
        self.values
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_string)
    }
}

/// The settings the service sent, shared by every clone of the options so
/// each reader sees a change the moment the pull applies it.
#[derive(Debug, Default)]
pub struct Held {
    current: RwLock<Arc<Managed>>,
    /// The variables that were set (non-empty) when this process started,
    /// so a value can say whether it is the environment's or the default.
    env_set: HashSet<&'static str>,
    /// THE NOTIFY URL THIS PEP DERIVED (2026-11-14, rcbj: "The PEP should
    /// attempt to derive the notify URL"): `https://<host>:<PEP_HTTPS_PORT>
    /// /notify` from the HTTPS listener certificate it serves, empty while
    /// it serves none. In force only where neither the service nor
    /// `PEP_NOTIFY_URL` set one (`options::derive_notify_url`).
    derived_notify: RwLock<String>,
}

/// The one setting a value may be DERIVED for, below the environment and
/// above the default.
pub const DERIVED_KEY: &str = "notifyUrl";

impl Held {
    /// Records which of the variables were set.
    pub fn from_env() -> Held {
        let env_set = SETTINGS
            .iter()
            .filter(|row| {
                std::env::var(row.env).is_ok_and(|v| !v.trim().is_empty())
            })
            .map(|row| row.env)
            .collect();
        Held {
            current: RwLock::new(Arc::new(Managed::default())),
            env_set,
            derived_notify: RwLock::new(String::new()),
        }
    }

    /// A holder as `from_env()` would make it with exactly these variables
    /// set, for a test.
    #[cfg(test)]
    pub fn with_env_set(envs: &[&'static str]) -> Held {
        Held {
            env_set: envs.iter().copied().collect(),
            ..Held::default()
        }
    }

    /// The notify URL derived from the served certificate, empty for none.
    pub fn derived_notify(&self) -> String {
        match self.derived_notify.read() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Replaces the derived notify URL; answers whether it changed.
    pub fn set_derived_notify(&self, url: &str) -> bool {
        let mut guard = match self.derived_notify.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if *guard == url {
            return false;
        }
        *guard = url.to_string();
        true
    }

    /// Whether the service set a (non-empty) value for this row. The
    /// service never sends an empty one (an empty box is "not set"
    /// there), and an empty `notifyUrl` read as set would hide the
    /// derived one behind nothing.
    fn service_sets(&self, row: &Row) -> bool {
        let current = self.current();
        if row.key == DERIVED_KEY && current.rejected_notify.is_some() {
            // Set, and rejected: still the service's, never a fallback.
            return true;
        }
        match current.values.get(row.key) {
            None => false,
            Some(value) => {
                row.key != DERIVED_KEY
                    || value.as_str().is_some_and(|s| !s.trim().is_empty())
            }
        }
    }

    pub fn current(&self) -> Arc<Managed> {
        match self.current.read() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Replaces what is held, and names what was refused or unknown.
    pub fn apply(&self, managed: Managed) {
        for why in &managed.refused {
            tracing::warn!(
                "{}xacml-pep: the service sent a setting this PEP refuses \
                 ({}); the environment's value, or the default, is used for \
                 it.",
                tag("STS-XPEP-0102"),
                why
            );
        }
        if !managed.unknown.is_empty() {
            tracing::info!(
                "xacml-pep: the service sent setting(s) this PEP does not \
                 know and ignores: {}. A newer service than this PEP.",
                managed.unknown.join(", ")
            );
        }
        let mut guard = match self.current.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        *guard = Arc::new(managed);
    }

    /// Where a setting's value comes from now.
    /// The precedence is service, environment, then — for `notifyUrl`
    /// alone — derived, then default.
    pub fn source(&self, row: &Row) -> &'static str {
        if self.service_sets(row) {
            "service"
        } else if self.env_set.contains(row.env) {
            "environment"
        } else if row.key == DERIVED_KEY && !self.derived_notify().is_empty() {
            "derived"
        } else {
            "default"
        }
    }
}

/// The value of each setting in force, as `GET /` and the heartbeat report
/// it: `{ token, values: { key: { value, source } } }`. Counts and closed
/// values only, apart from the two texts an operator wrote (the
/// description and the resource).
pub fn report(held: &Held, values: &Map<String, Value>) -> Value {
    let mut out = Map::new();
    for row in SETTINGS {
        if let Some(value) = values.get(row.key) {
            out.insert(
                row.key.to_string(),
                json!({ "value": value, "source": held.source(row) }),
            );
        }
    }
    json!({ "token": held.current().token, "values": out })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pulled_value_is_read_by_its_row() {
        let said = json!({
            "pollIntervalMs": 2000, "bias": "permit-biased",
            "timeoutMs": 50, "logLevel": "loud", "pip": "yes",
            "notifyUrl": "https://u:p@pep.example/notify",
            "authzenPdpIdentifier": "https://pdp.example/",
            "description": "line\nbreak", "aNewerSetting": 1
        });
        let managed = Managed::parse("t1", true, &said);
        assert_eq!(managed.u64("pollIntervalMs"), Some(2000));
        assert_eq!(managed.str("bias").as_deref(), Some("permit-biased"));
        assert_eq!(
            managed.str("authzenPdpIdentifier").as_deref(),
            Some("https://pdp.example")
        );
        // Out of bounds, not in the closed set, the wrong type, a user
        // name in a URL and a control character: each left out, named.
        for key in ["timeoutMs", "logLevel", "pip", "notifyUrl", "description"]
        {
            assert!(!managed.values.contains_key(key), "{} kept", key);
        }
        assert_eq!(managed.refused.len(), 5);
        assert_eq!(managed.unknown, ["aNewerSetting"]);
    }

    #[test]
    fn the_source_follows_the_precedence() {
        let held = Held::default();
        let row = row_of("bias").unwrap();
        assert_eq!(held.source(row), "default");
        let held = Held {
            env_set: [row.env].into_iter().collect(),
            ..Held::default()
        };
        assert_eq!(held.source(row), "environment");
        held.apply(Managed::parse(
            "t",
            true,
            &json!({ "bias": "permit-biased" }),
        ));
        assert_eq!(held.source(row), "service");
    }

    #[test]
    fn every_row_names_a_pep_variable_once() {
        let mut keys = HashSet::new();
        let mut envs = HashSet::new();
        for row in SETTINGS {
            assert!(row.env.starts_with("PEP_"));
            assert!(keys.insert(row.key) && envs.insert(row.env));
        }
    }
}
