// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! CUSTOM LISTENERS (#472; a realm's own, #99, is one):
//! `common/listener_map.js`'s `parseListeners()` and the half of
//! `stateProblem()` that decides whether a socket can be bound — each
//! listener well formed, its id and port its own, none on one of the
//! process's fixed sockets.
//!
//! What is NOT here yet, and where it goes: `listeners.applications` (which
//! hosted application answers on which listener, `common/app.js`'s
//! STS-TLS-0047 and STS-TLS-0041 refusals), the advertised base an
//! application's URLs are built on, the cookie-domain rule and the
//! `/admin-api` confirm rule. They read the catalogue of hosted
//! applications and the realm registry's own values, which arrive with the
//! HTTP layer's routing and the management API (phase 4). The runtime
//! marks every request with the listener it arrived on
//! ([`crate::ConnectionFacts::listener`]) so that routing can ask.

use serde_json::{Map, Value as Json};
use sts_core::errors::{codes, ErrorCode};
use sts_core::settings::{row, Settings};

/// The built-in listener.
pub const MAIN: &str = "main";

/// Ids a listener may not take (`RESERVED_IDS`).
pub const RESERVED_IDS: &[&str] = &[
    "main",
    "ldap",
    "ldaps",
    "debugger",
    "kdc",
    "revocation",
    "spiffe-workload",
    "spiffe-server",
    "spiffe-broker",
    "cell",
    "default",
];

/// The process's own sockets, by the setting naming each port
/// (`PROCESS_PORT_SETTINGS`): a custom listener may be on none of them.
pub const PROCESS_PORT_SETTINGS: &[&str] = &[
    "global.port",
    "pki.httpPort",
    "debugger.port",
    "krb5.kdcPort",
    "ldap.port",
    "ldap.tlsPort",
    "spiffe.workloadPort",
    "spiffe.serverPort",
    "spiffe.brokerPort",
    "cells.port",
];

const KNOWN: &[&str] = &[
    "id",
    "port",
    "publicBaseUrl",
    "hostnames",
    "certificateFile",
    "privateKeyFile",
    "clientAuth",
    "tls",
    "label",
];

/// One listener definition, normalised.
#[derive(Debug, Clone, PartialEq)]
pub struct ListenerDefinition {
    pub id: String,
    /// The realm that owns it; the default realm's id for the service's.
    pub owner: String,
    pub port: u16,
    pub label: String,
    pub public_base_url: String,
    pub host: String,
    pub hostnames: Vec<String>,
    pub certificate_file: String,
    pub private_key_file: String,
    pub client_auth: String,
    pub tls: Map<String, Json>,
}

impl ListenerDefinition {
    /// What makes its socket (`signatureOf()`): a change to any of these
    /// rebinds; the TLS block and client authentication apply in place.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn socket_signature(&self) -> String {
        serde_json::json!({
            "owner": self.owner, "port": self.port,
            "hostnames": self.hostnames,
            "certificateFile": self.certificate_file,
            "privateKeyFile": self.private_key_file,
        })
        .to_string()
    }
}

/// A refusal: Node's sentence and its code.
#[derive(Debug, Clone, PartialEq)]
pub struct DefinitionRefusal {
    pub code: ErrorCode,
    pub message: String,
}

fn refuse(code: ErrorCode, message: String) -> DefinitionRefusal {
    DefinitionRefusal { code, message }
}

/// The per-listener settings the main port has, by short name, with the
/// service-wide row each overrides (`TLS_FIELDS`, read from the table).
#[tracing::instrument(level = "debug", skip_all)]
pub fn tls_fields() -> Vec<(String, String)> {
    sts_core::settings::rows()
        .iter()
        .filter_map(|r| {
            let name = r.key.strip_prefix("listenerMain.")?;
            let base = ["tls.", "http."]
                .iter()
                .map(|p| format!("{}{}", p, name))
                .find(|k| row(k).is_some())?;
            Some((name.to_string(), base))
        })
        .collect()
}

fn origin_problem(where_: &str, base: &str) -> Option<DefinitionRefusal> {
    let ok = url::Url::parse(base).ok().is_some_and(|u| {
        u.scheme() == "https"
            && u.username().is_empty()
            && u.password().is_none()
            && (u.path() == "/" || u.path().is_empty())
            && u.query().is_none()
            && u.fragment().is_none()
    });
    if ok {
        return None;
    }
    Some(refuse(
        codes::STS_CORE_0146,
        format!(
            "{}'s publicBaseUrl must be an https origin with no path, query or user — https://idp.example.com \
             or https://idp.example.com:8443 — and \"{}\" is not. A realm's /realm/<id> prefix is added after it.",
            where_, base
        ),
    ))
}

fn id_ok(id: &str) -> bool {
    let mut chars = id.chars();
    let first_ok = chars.next().is_some_and(|c| c.is_ascii_lowercase());
    first_ok
        && id.len() <= 32
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// `parseListeners(raw, owner)`: the normalised definitions, and the first
/// refusal found.
#[tracing::instrument(level = "debug", skip(raw))]
pub fn parse_listeners(
    raw: &str,
    owner: &str,
) -> (Vec<ListenerDefinition>, Option<DefinitionRefusal>) {
    let mut out = Vec::new();
    let text = raw.trim();
    if text.is_empty() {
        return (out, None);
    }
    let setting = if owner.is_empty() || owner == "default" {
        "listeners.custom"
    } else {
        "listeners.realm"
    };
    let list: Json = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(e) => {
            return (
                out,
                Some(refuse(
                    codes::STS_CORE_0153,
                    format!("{} is not JSON: {}", setting, e),
                )),
            )
        }
    };
    let Some(list) = list.as_array() else {
        return (
            out,
            Some(refuse(
                codes::STS_CORE_0153,
                format!(
                    "{} must be a JSON array of listener definitions.",
                    setting
                ),
            )),
        );
    };
    let fields = tls_fields();
    let mut seen: Vec<String> = Vec::new();
    for (i, one) in list.iter().enumerate() {
        let id_text = one.get("id").and_then(Json::as_str).unwrap_or("");
        let where_ = format!(
            "listener {} in {}",
            if id_text.is_empty() {
                format!("#{}", i + 1)
            } else {
                format!("\"{}\"", id_text)
            },
            setting
        );
        let problem =
            |message: String| Some(refuse(codes::STS_CORE_0153, message));
        let Some(obj) = one.as_object() else {
            return (out, problem(format!("{} is not an object.", where_)));
        };
        let unknown: Vec<&str> = obj
            .keys()
            .map(String::as_str)
            .filter(|k| !KNOWN.contains(k))
            .collect();
        if !unknown.is_empty() {
            return (
                out,
                problem(format!(
                    "{} has a member this service does not know: {}. A listener takes {}.",
                    where_,
                    unknown.join(", "),
                    KNOWN.join(", ")
                )),
            );
        }
        if !id_ok(id_text) || RESERVED_IDS.contains(&id_text) {
            return (
                out,
                problem(format!(
                    "{} needs an id of lower-case letters, digits and hyphens, starting with a letter, at \
                     most 32 long, and none of {}.",
                    where_,
                    RESERVED_IDS.join(", ")
                )),
            );
        }
        if seen.iter().any(|s| s == id_text) {
            return (
                out,
                problem(format!(
                    "{} defines the listener \"{}\" twice.",
                    setting, id_text
                )),
            );
        }
        seen.push(id_text.to_string());
        let port = obj.get("port").and_then(Json::as_i64).unwrap_or(0);
        let Ok(port) = u16::try_from(port) else {
            return (
                out,
                problem(format!("{} needs a port from 1 to 65535.", where_)),
            );
        };
        if port == 0 {
            return (
                out,
                problem(format!("{} needs a port from 1 to 65535.", where_)),
            );
        }
        let base = obj
            .get("publicBaseUrl")
            .and_then(Json::as_str)
            .unwrap_or("")
            .to_string();
        if let Some(bad) = origin_problem(&where_, &base) {
            return (out, Some(bad));
        }
        let hostnames = match obj.get("hostnames") {
            None => Vec::new(),
            Some(Json::Array(a))
                if a.iter().all(|h| {
                    h.as_str().is_some_and(|s| !s.trim().is_empty())
                }) =>
            {
                a.iter()
                    .filter_map(Json::as_str)
                    .map(|s| s.trim().to_string())
                    .collect()
            }
            Some(_) => {
                return (
                    out,
                    problem(format!(
                        "{}'s hostnames must be an array of DNS names.",
                        where_
                    )),
                )
            }
        };
        let file = |k: &str| {
            obj.get(k)
                .and_then(Json::as_str)
                .unwrap_or("")
                .trim()
                .to_string()
        };
        let certificate_file = file("certificateFile");
        let private_key_file = file("privateKeyFile");
        if certificate_file.is_empty() != private_key_file.is_empty() {
            return (
                out,
                problem(format!(
                    "{} names a {}: both or neither.",
                    where_,
                    if certificate_file.is_empty() {
                        "privateKeyFile and no certificateFile"
                    } else {
                        "certificateFile and no privateKeyFile"
                    }
                )),
            );
        }
        let client_auth = obj
            .get("clientAuth")
            .and_then(Json::as_str)
            .unwrap_or("optional")
            .to_string();
        if !["none", "optional", "required"].contains(&client_auth.as_str()) {
            return (
                out,
                problem(format!(
                    "{}'s clientAuth is one of none, optional, required.",
                    where_
                )),
            );
        }
        let tls = match obj.get("tls") {
            None => Map::new(),
            Some(Json::Object(m)) => m.clone(),
            Some(_) => {
                return (
                    out,
                    problem(format!("{}'s tls must be an object.", where_)),
                )
            }
        };
        let strange: Vec<&str> = tls
            .keys()
            .map(String::as_str)
            .filter(|k| !fields.iter().any(|(n, _)| n == k))
            .collect();
        if !strange.is_empty() {
            return (
                out,
                problem(format!(
                    "{}'s tls has a setting no listener carries: {}. It takes {}.",
                    where_,
                    strange.join(", "),
                    fields
                        .iter()
                        .map(|(n, _)| n.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )),
            );
        }
        for (name, value) in &tls {
            let inherits = match value {
                Json::Null => true,
                Json::String(s) => s.is_empty() || s == "inherit",
                Json::Number(n) => n.as_i64() == Some(-1),
                _ => false,
            };
            if inherits {
                continue;
            }
            let Some((_, base)) = fields.iter().find(|(n, _)| n == name) else {
                continue;
            };
            let raw = match value {
                Json::String(s) if s == "on" => Json::Bool(true),
                Json::String(s) if s == "off" => Json::Bool(false),
                Json::Array(a) => Json::String(
                    a.iter()
                        .filter_map(Json::as_str)
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                other => other.clone(),
            };
            if let Some(why) = row(base).and_then(|r| r.check(&raw)) {
                return (
                    out,
                    problem(format!(
                        "{}'s tls.{} is not a value {} takes: {}.",
                        where_, name, base, why
                    )),
                );
            }
        }
        let host = url::Url::parse(&base)
            .ok()
            .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
            .unwrap_or_default();
        out.push(ListenerDefinition {
            id: id_text.to_string(),
            owner: owner.to_string(),
            port,
            label: obj
                .get("label")
                .and_then(Json::as_str)
                .unwrap_or(id_text)
                .to_string(),
            public_base_url: base.trim_end_matches('/').to_string(),
            hostnames: if hostnames.is_empty() && !host.is_empty() {
                vec![host.clone()]
            } else {
                hostnames
            },
            host,
            certificate_file,
            private_key_file,
            client_auth,
            tls,
        });
    }
    (out, None)
}

/// The service's listeners (`listeners.custom`) and the socket rules of
/// `stateProblem()`: none on a fixed socket's port, none sharing a port.
/// Fatal at startup (`STS-CORE-0157`, `startupProblem()`).
#[tracing::instrument(level = "debug", skip_all)]
pub fn service_listeners(
    settings: &Settings,
) -> Result<Vec<ListenerDefinition>, DefinitionRefusal> {
    let raw = settings.value_of("listeners.custom");
    let (list, problem) = parse_listeners(raw.as_str(), "");
    if let Some(p) = problem {
        return Err(p);
    }
    let mut ports: Vec<(u16, String)> = Vec::new();
    for key in PROCESS_PORT_SETTINGS {
        if row(key).is_none() {
            continue;
        }
        let p = settings.value_of(key).as_int();
        if let Ok(p) = u16::try_from(p) {
            if p > 0 {
                ports.push((p, (*key).to_string()));
            }
        }
    }
    for one in &list {
        if let Some((_, by)) = ports.iter().find(|(p, _)| *p == one.port) {
            return Err(refuse(
                codes::STS_CORE_0153,
                format!(
                    "listener \"{}\" is on port {}, which {} already names.",
                    one.id, one.port, by
                ),
            ));
        }
        ports.push((one.port, format!("listener \"{}\"", one.id)));
    }
    Ok(list)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)] // tests

    use std::collections::HashMap;

    use serde_json::json;

    use super::*;

    #[test]
    fn a_well_formed_listener_is_normalised() {
        let (list, problem) = parse_listeners(
            r#"[{"id":"mtls","port":9443,"publicBaseUrl":"https://idp.example.com:9443/",
                 "clientAuth":"required","tls":{"disableTls12":"off"}}]"#,
            "",
        );
        assert!(problem.is_none(), "{:?}", problem);
        assert_eq!(list[0].hostnames, vec!["idp.example.com"]);
        assert_eq!(list[0].public_base_url, "https://idp.example.com:9443");
    }

    #[test]
    fn reserved_ids_and_strange_members_are_refused() {
        for bad in [
            r#"[{"id":"main","port":1,"publicBaseUrl":"https://a.example"}]"#,
            r#"[{"id":"x","port":0,"publicBaseUrl":"https://a.example"}]"#,
            r#"[{"id":"x","port":2,"publicBaseUrl":"http://a.example"}]"#,
            r#"[{"id":"x","port":2,"publicBaseUrl":"https://a.example","colour":1}]"#,
            r#"[{"id":"x","port":2,"publicBaseUrl":"https://a.example","tls":{"nope":1}}]"#,
            r#"[{"id":"x","port":2,"publicBaseUrl":"https://a.example","certificateFile":"a"}]"#,
            "{}",
        ] {
            assert!(parse_listeners(bad, "").1.is_some(), "{}", bad);
        }
    }

    #[test]
    fn a_listener_on_the_main_port_is_refused() {
        let s = Settings::new(
            json!({ "listeners": { "custom":
                r#"[{"id":"x","port":8081,"publicBaseUrl":"https://a.example"}]"# } }),
            HashMap::new(),
        );
        let err = service_listeners(&s).err().unwrap();
        assert!(err.message.contains("global.port"));
    }
}
