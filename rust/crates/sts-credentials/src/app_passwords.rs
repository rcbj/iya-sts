// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! App passwords as a MECHANISM: a port of `common/app_passwords.ts` and
//! `common/app_password_doors.js` (`common/CLAUDE.md` 3ax) — the five
//! password-only doors one may be scoped to, its shape (twenty-four
//! characters of base32's thirty-two, the first four its id), and its
//! hash. The records on a person's entry, and the door that accepts one in
//! place of a password, are the store's ([`crate::credentials`]).

use std::sync::Arc;

use serde_json::{json, Value as Json};
use sts_crypto::secrets::verify_secret;

use crate::js;
use crate::ports::Environment;

/// The alphabet a password is drawn from.
pub const ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
/// How many leading characters are its id.
pub const ID_LENGTH: usize = 4;
/// Its length.
pub const LENGTH: usize = 24;
/// The printed group.
const GROUP: usize = 4;
/// The longest name.
pub const MAX_NAME: usize = 64;

/// One password-only door: `(id, label, what it takes)`.
pub const DOORS: [(&str, &str, &str); 5] = [
    (
        "ldap",
        "LDAP bind",
        "an LDAP simple bind on 389 or 636 (RFC 4513)",
    ),
    (
        "wstrust",
        "WS-Trust",
        "a WS-Security UsernameToken sent to the security token service",
    ),
    ("scim", "SCIM", "HTTP Basic at /scim/v2 (RFC 7617)"),
    (
        "ssf",
        "Shared Signals",
        "HTTP Basic at the /ssf endpoints (RFC 7617)",
    ),
    (
        "est",
        "EST",
        "HTTP Basic at /.well-known/est (RFC 7030 section 3.2.3)",
    ),
];

/// The ids of the doors, in the table's order.
#[tracing::instrument(level = "debug", skip_all)]
pub fn door_ids() -> Vec<&'static str> {
    DOORS.iter().map(|d| d.0).collect()
}

fn door_index(id: &str) -> Option<usize> {
    DOORS.iter().position(|d| d.0 == id)
}

/// `scopeOf()`'s answer.
#[derive(Debug, Clone, PartialEq)]
pub struct Scope {
    pub ok: bool,
    pub doors: Vec<String>,
    pub bad: Vec<String>,
}

/// `generate()`'s answer.
#[derive(Debug, Clone, PartialEq)]
pub struct Made {
    pub id: String,
    pub password: String,
    pub printed: String,
}

/// The mechanism.
pub struct AppPasswords {
    env: Arc<dyn Environment>,
}

impl AppPasswords {
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(env: Arc<dyn Environment>) -> AppPasswords {
        AppPasswords { env }
    }

    /// `settings()`: `appPasswords.enabled` unless false, and
    /// `maxPerPerson` 1–50, else 10.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn settings(&self) -> Json {
        let asked = js::number(&self.env.setting("appPasswords.maxPerPerson"));
        let enabled = self.env.setting("appPasswords.enabled") != json!(false);
        let most = if asked.is_finite() && asked >= 1.0 {
            asked.floor().min(50.0)
        } else {
            10.0
        };
        json!({ "enabled": enabled, "maxPerPerson": js::num(most) })
    }

    /// `isDoor(door)`.
    #[tracing::instrument(level = "debug")]
    pub fn is_door(door: &str) -> bool {
        door_index(door).is_some()
    }

    /// `passwordAloneDoors()`: `authn.passwordAloneDoors`, the doors where
    /// a second-factor person's password alone is still accepted.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn password_alone_doors(&self) -> Vec<String> {
        let asked = self.env.setting("authn.passwordAloneDoors");
        let list: Vec<String> = match &asked {
            Json::Array(items) => items.iter().map(js::string).collect(),
            other => js::string_or(Some(other), "")
                .split(',')
                .map(str::to_string)
                .collect(),
        };
        list.iter()
            .map(|one| js::trim(one).to_lowercase())
            .filter(|one| door_index(one).is_some())
            .collect()
    }

    /// `scopeOf(asked)`: the doors named, deduplicated and in the table's
    /// order, and those that are no door.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn scope_of(asked: &Json) -> Scope {
        let raw: Vec<Json> = match asked {
            Json::Array(items) => items.clone(),
            Json::Null => vec![Json::String(String::new())],
            other => js::string(other)
                .split(',')
                .map(|s| Json::String(s.to_string()))
                .collect(),
        };
        let mut doors: Vec<String> = Vec::new();
        let mut bad: Vec<String> = Vec::new();
        for one in &raw {
            let id = js::trim(&match one {
                Json::Null => String::new(),
                v => js::string(v),
            })
            .to_lowercase();
            if id.is_empty() {
                continue;
            }
            if door_index(&id).is_none() {
                bad.push(id);
            } else if !doors.contains(&id) {
                doors.push(id);
            }
        }
        doors.sort_by_key(|d| door_index(d));
        Scope {
            ok: !doors.is_empty() && bad.is_empty(),
            doors,
            bad,
        }
    }

    /// `nameOf(asked)`: trimmed, 1–64 characters, no control character;
    /// else empty.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn name_of(asked: &Json) -> String {
        let text = js::trim(&match asked {
            Json::Null => String::new(),
            v => js::string(v),
        })
        .to_string();
        let n = js::length(&text);
        if n > 0 && n <= MAX_NAME && !js::has_control(&text) {
            text
        } else {
            String::new()
        }
    }

    /// `generate(taken)`: twenty-four characters whose id no held password
    /// already has, in fifty draws at most.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn generate(&self, taken: &[String]) -> Made {
        let alphabet = ALPHABET.as_bytes();
        let mut password = String::new();
        for _ in 0..50 {
            password.clear();
            for _ in 0..LENGTH {
                let at = self.env.random_int(0, alphabet.len() as u64) as usize;
                password.push(alphabet[at.min(alphabet.len() - 1)] as char);
            }
            if !taken.iter().any(|t| *t == password[..ID_LENGTH]) {
                break;
            }
        }
        Made {
            id: password[..ID_LENGTH].to_string(),
            printed: AppPasswords::printed(&password),
            password,
        }
    }

    /// `printed(password)`: groups of four, dash-separated.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn printed(password: &str) -> String {
        let chars: Vec<char> = password.chars().collect();
        chars
            .chunks(GROUP)
            .map(|c| c.iter().collect::<String>())
            .collect::<Vec<_>>()
            .join("-")
    }

    /// `normalise(text)`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn normalise(text: &str) -> String {
        js::without_spaces_and_dashes(&js::upper(text))
    }

    /// `wellFormed(text)`: exactly the shape this service prints.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn well_formed(text: &str) -> bool {
        let value = AppPasswords::normalise(text);
        js::length(&value) == LENGTH
            && value.chars().all(|c| ALPHABET.contains(c))
    }

    /// `idOf(text)`: its id, or empty for a value of another shape.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn id_of(text: &str) -> String {
        if AppPasswords::well_formed(text) {
            AppPasswords::normalise(text)[..ID_LENGTH].to_string()
        } else {
            String::new()
        }
    }

    /// `hash(password)`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn hash(&self, password: &str) -> String {
        self.env.hash_secret(&AppPasswords::normalise(password))
    }

    /// `matchesHash(presented, stored)`.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn matches_hash(presented: &str, stored: &str) -> bool {
        verify_secret(&AppPasswords::normalise(presented), stored)
    }

    /// `doorLabel(id)`.
    #[tracing::instrument(level = "debug")]
    pub fn door_label(id: &str) -> String {
        DOORS
            .iter()
            .find(|d| d.0 == id)
            .map_or_else(|| id.to_string(), |d| d.1.to_string())
    }
}
