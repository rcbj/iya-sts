// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE TWO MODE REPORTS: `GET /oauth2/rfc9700` (`oauth2_bcp.js`'s
//! `state()`) and `GET /oauth2/oauth21` (`oauth21.js`'s `state()`) — what
//! each mode enforces, published rather than left to be read out of the
//! code, member for member Node's, pretty-printed as
//! `JSON.stringify(state, null, 2)` with `Cache-Control: no-store`.
//!
//! THE ROWS ARE NODE'S TABLES, NOT A COPY OF THEM: `tables/oauth_reports.json`
//! is written by `tests/tools/export-rust-tables.js` from `REQUIREMENTS`
//! and the reports' constant sentences, and `tests/rust_tables.js` fails on
//! any difference. A row whose `enforced` or `note` depends on the settings
//! is exported evaluated under every combination of the four settings it
//! reads (`global.https`, `oauth2.allowImplicitTokenResponses`,
//! `oauth2.accessTokenRequireDpop`, `oauth2.accessTokenRequireMtls`), and
//! is answered here from the combination in force.
//!
//! The rest is computed as Node computes it: which flag turned the mode
//! on, the settings block (as stored, and `oauth2.breakIdTokenNonce` as in
//! force), `sender_constraints.state()`, the waiver list (#1295), the
//! scheme, and the counts of what is remembered.

use std::sync::OnceLock;

use serde_json::{json, Map, Value as Json};
use sts_core::mode::Mode;
use sts_core::settings::{SettingValue, Settings};

/// The export.
const TABLES: &str = include_str!("../tables/oauth_reports.json");

fn tables() -> &'static Json {
    static PARSED: OnceLock<Json> = OnceLock::new();
    PARSED.get_or_init(|| serde_json::from_str(TABLES).unwrap_or(Json::Null))
}

/// What the report counts, read by the caller off its stores.
#[derive(Debug, Clone, Copy, Default)]
pub struct Remembered {
    pub transactions: usize,
    pub client_assertions: usize,
    pub refresh_tokens: usize,
    pub refresh_families: usize,
}

/// `clientAuth.METHODS`: `none`, the symmetric methods, the asymmetric.
fn methods() -> Vec<&'static str> {
    let mut out = vec!["none"];
    out.extend_from_slice(&crate::client_auth::SYMMETRIC_METHODS);
    out.extend_from_slice(&crate::client_auth::ASYMMETRIC_METHODS);
    out
}

/// The two reports over the settings in force.
pub struct Reports<'a> {
    pub settings: &'a Settings,
    pub mode: &'a Mode,
}

impl Reports<'_> {
    fn flag(&self, key: &str) -> bool {
        self.settings.value_of(key).as_bool()
    }

    fn fapi(&self) -> String {
        crate::authorization_servers::fapi_profile(self.settings)
    }

    /// `oauth21.enabled()`.
    fn oauth21(&self) -> bool {
        self.flag("oauth2.oauth21")
    }

    /// `bcp.enabled()`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn bcp_enabled(&self) -> bool {
        self.flag("oauth2.rfc9700")
            || self.oauth21()
            || !self.fapi().is_empty()
            || self.mode.enforces_oauth_security_bcp()
    }

    /// `implicitWaived()`.
    fn implicit_waived(&self) -> bool {
        self.flag("oauth2.allowImplicitTokenResponses")
            && !self.oauth21()
            && self.fapi().is_empty()
    }

    /// `fapi.forbidsRotation()`: FAPI 2.0.
    fn forbids_rotation(&self) -> bool {
        matches!(self.fapi().as_str(), "2-security" | "2-message-signing")
    }

    /// The key of the combination in force: `https|implicit|dpop|mtls`.
    fn combination(&self) -> String {
        let bit = |on: bool| if on { "1" } else { "0" };
        [
            bit(self.flag("global.https")),
            bit(self.implicit_waived()),
            bit(self.flag("oauth2.accessTokenRequireDpop")),
            bit(self.flag("oauth2.accessTokenRequireMtls")),
        ]
        .join("|")
    }

    /// A field as exported: a value, or `{ computed: { <combination>: … } }`.
    fn field(&self, value: &Json, key: &str) -> Json {
        match value.get("computed") {
            Some(by) => by.get(key).cloned().unwrap_or(Json::Null),
            None => value.clone(),
        }
    }

    /// `dynamicRegistrationTokenResponseTypes()`: each value's words
    /// sorted, empty and repeated values dropped.
    fn dynamic_types(&self) -> Vec<String> {
        let raw = self
            .settings
            .value_of("oauth2.dynamicRegistrationTokenResponseTypes");
        let items: Vec<String> = match raw {
            SettingValue::List(list) => list,
            other => other.as_str().split(',').map(str::to_string).collect(),
        };
        let mut out: Vec<String> = Vec::new();
        for one in items {
            let mut words: Vec<&str> = one.split_whitespace().collect();
            words.sort_unstable();
            let joined = words.join(" ");
            if !joined.is_empty() && !out.contains(&joined) {
                out.push(joined);
            }
        }
        out
    }

    fn list_setting(&self, key: &str) -> Json {
        match self.settings.value_of(key) {
            SettingValue::List(list) => json!(list),
            _ => json!([]),
        }
    }

    /// `rotationRequired()`.
    fn rotation_required(&self) -> bool {
        if self.forbids_rotation() {
            return self.flag("oauth2.refreshTokenRotation");
        }
        self.bcp_enabled() || self.flag("oauth2.refreshTokenRotation")
    }

    /// `rotationSource()`.
    fn rotation_source(&self) -> Json {
        if self.forbids_rotation() {
            return if self.flag("oauth2.refreshTokenRotation") {
                json!(
                    "oauth2.refreshTokenRotation (FAPI 2.0 forbids rotation \
                     otherwise)"
                )
            } else {
                Json::Null
            };
        }
        if self.flag("oauth2.rfc9700") {
            return json!("RFC 9700 mode");
        }
        if self.oauth21() {
            return json!("OAuth 2.1 mode");
        }
        if !self.fapi().is_empty() {
            return json!(format!(
                "oauth2.fapi={} (it implies RFC 9700 mode)",
                self.fapi()
            ));
        }
        if self.mode.enforces_oauth_security_bcp() {
            return json!("product mode (it enforces RFC 9700)");
        }
        if self.flag("oauth2.refreshTokenRotation") {
            return json!("oauth2.refreshTokenRotation");
        }
        Json::Null
    }

    /// `senderConstraints.state()`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn sender_constraints(&self) -> Json {
        json!({
            "rotation": {
                "required": self.rotation_required(),
                "source": self.rotation_source(),
                "setting": "oauth2.refreshTokenRotation",
            },
            "refreshTokenRequireDpop":
                self.flag("oauth2.refreshTokenRequireDpop"),
            "refreshTokenRequireMtls":
                self.flag("oauth2.refreshTokenRequireMtls"),
            "accessTokenRequireDpop":
                self.flag("oauth2.accessTokenRequireDpop"),
            "accessTokenRequireMtls":
                self.flag("oauth2.accessTokenRequireMtls"),
            "note": tables()["sender_constraints_note"],
        })
    }

    /// `waivers()` (#1295).
    fn waivers(&self) -> Json {
        if !self.bcp_enabled() || !self.implicit_waived() {
            return json!([]);
        }
        json!([{
            "requirement": "no-implicit",
            "section": "RFC 9700 2.1.2",
            "level": "SHOULD NOT",
            "setting": "oauth2.allowImplicitTokenResponses",
            "perApplication": true,
            "attribute": "oauthAllowedTokenResponseTypes",
            "dynamicRegistration": {
                "setting": "oauth2.dynamicRegistrationTokenResponseTypes",
                "value": self.dynamic_types(),
            },
        }])
    }

    /// `bcp.state()`: the RFC 9700 report.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn rfc9700(&self, remembered: Remembered) -> Json {
        let t = &tables()["rfc9700"];
        let on = self.bcp_enabled();
        let tls = self.flag("global.https");
        let meaning = &t["what_it_means"][if on {
            if tls {
                "on|1"
            } else {
                "on|0"
            }
        } else {
            "off"
        }];
        let enabled_by = if !on {
            String::new()
        } else if self.flag("oauth2.rfc9700") {
            "oauth2.rfc9700".into()
        } else if self.oauth21() {
            "oauth2.oauth21".into()
        } else if !self.fapi().is_empty() {
            format!("oauth2.fapi={}", self.fapi())
        } else {
            "global.mode=product".into()
        };
        let fapi = self.fapi();
        let break_nonce = !self.mode.enforces_oauth_security_bcp()
            && self.flag("oauth2.breakIdTokenNonce");
        let mut settings = Map::new();
        let mut put = |k: &str, v: Json| {
            settings.insert(k.to_string(), v);
        };
        put("oauth2.rfc9700", json!(self.flag("oauth2.rfc9700")));
        put("oauth2.oauth21", json!(self.oauth21()));
        put(
            "oauth2.fapi",
            if fapi.is_empty() {
                Json::Null
            } else {
                json!(fapi)
            },
        );
        put(
            "oauth2.redirectUris",
            self.list_setting("oauth2.redirectUris"),
        );
        put(
            "oauth2.loopbackPortWildcard",
            json!(self.flag("oauth2.loopbackPortWildcard") || self.oauth21()),
        );
        put(
            "oauth2.allowImplicitTokenResponses",
            json!(self.flag("oauth2.allowImplicitTokenResponses")),
        );
        put(
            "oauth2.dynamicRegistrationTokenResponseTypes",
            json!(self.dynamic_types()),
        );
        put("global.https", json!(tls));
        put("oauth2.breakIdTokenNonce", json!(break_nonce));
        for key in [
            "oauth2.refreshTokenRotation",
            "oauth2.refreshTokenRequireDpop",
            "oauth2.refreshTokenRequireMtls",
            "oauth2.accessTokenRequireDpop",
            "oauth2.accessTokenRequireMtls",
        ] {
            put(key, json!(self.flag(key)));
        }
        let key = self.combination();
        let requirements: Vec<Json> = t["requirements"]
            .as_array()
            .map(|rows| {
                rows.iter()
                    .map(|row| {
                        json!({
                            "id": row["id"],
                            "section": row["section"],
                            "level": row["level"],
                            "applies_to": row["applies_to"],
                            "title": row["title"],
                            "enforced": self.field(&row["enforced"], &key),
                            "note": self.field(&row["note"], &key),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        json!({
            "rfc": t["rfc"],
            "url": t["url"],
            "enabled": on,
            "what_it_means": meaning,
            "enabled_by": enabled_by,
            "settings": settings,
            "sender_constraints": self.sender_constraints(),
            "waived": self.waivers(),
            "authorization_endpoint_scheme": if tls { "https" } else { "http" },
            "scope": t["scope"],
            "transactions_remembered": remembered.transactions,
            "client_assertions_remembered": remembered.client_assertions,
            "client_authentication_methods_verified": methods(),
            "refresh_tokens_remembered": remembered.refresh_tokens,
            "refresh_families": remembered.refresh_families,
            "requirements": requirements,
        })
    }

    /// `oauth21.state()`: the OAuth 2.1 report.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn oauth21_state(&self) -> Json {
        let t = &tables()["oauth21"];
        let on = self.oauth21();
        json!({
            "specification": t["specification"],
            "draft": t["draft"],
            "url": t["url"],
            "status": t["status"],
            "enabled": on,
            "implies": t["implies"],
            "what_it_means": t["what_it_means"][if on { "on" } else { "off" }],
            "settings": {
                "oauth2.oauth21": on,
                "oauth2.rfc9700": self.flag("oauth2.rfc9700"),
                "oauth2.authorizationCodeTtlS":
                    self.settings.value_of("oauth2.authorizationCodeTtlS")
                        .as_int(),
                "oauth2.loopbackPortWildcard":
                    self.flag("oauth2.loopbackPortWildcard"),
                "oauth2.refreshTokenRotation":
                    self.flag("oauth2.refreshTokenRotation"),
                "oauth2.refreshTokenRequireDpop":
                    self.flag("oauth2.refreshTokenRequireDpop"),
                "oauth2.refreshTokenRequireMtls":
                    self.flag("oauth2.refreshTokenRequireMtls"),
            },
            "exemptions": t["exemptions"],
            "requirements": t["requirements"],
        })
    }
}

/// A report as Node sends it: 200, `application/json`, `no-store`, the
/// state pretty-printed.
#[tracing::instrument(level = "debug", skip_all)]
pub fn answer(state: &Json) -> crate::answer::Answer {
    let mut a = crate::answer::Answer::new(
        200,
        crate::answer::Body::Raw(
            serde_json::to_string_pretty(state).unwrap_or_default(),
        ),
    );
    a.set("Content-Type", "application/json; charset=utf-8");
    a.set("Cache-Control", "no-store");
    a
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)] // tests

    use super::*;

    #[test]
    fn the_export_holds_both_tables() {
        let t = tables();
        assert!(t["rfc9700"]["requirements"].as_array().unwrap().len() > 30);
        assert!(!t["oauth21"]["requirements"].as_array().unwrap().is_empty());
        let computed = t["rfc9700"]["requirements"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["enforced"].get("computed").is_some())
            .count();
        assert!(computed >= 5, "{}", computed);
    }
}
