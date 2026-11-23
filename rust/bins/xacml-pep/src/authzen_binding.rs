// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! WHICH TUPLES ARE THE TOKEN-EXCHANGE BINDING'S, CLASSIFIED AS THE SERVICE
//! CLASSIFIES THEM (#1181, #1205). `authzen/authzen_exchange.ts`'s `plan()`
//! and `strayContext()`, and `authzen/authzen.ts`'s `evaluateOne()`, decide
//! what each item of a request is; this file decides the same thing from
//! the settings the catalogue carries (`sync.rs`), so the edge refuses
//! exactly what the service would answer by the binding's fixed rules, and
//! evaluates exactly what the service would evaluate.
//!
//! * **The binding ON** (`authzen.tokenExchange`): every gate (resource
//!   type `audience`, action `issue:<token type>:<grant>`, whatever the
//!   grant) and every scope tuple (`protected_resource`), lone or not, is
//!   the binding's; so is a tuple whose resource type the realm declares as
//!   an `authorization_details` type, when the request also carries a
//!   token-exchange gate (`issue:<registered token type>:token_exchange`).
//!   This edge holds neither delegation nor the directory, so it answers
//!   each 501 (`STS-XPEP-0140`). A lone scope in particular is a fixed
//!   false at the service (`STS-AUTHZEN-0105`); evaluated here as ordinary
//!   it could be true.
//! * **The binding OFF**: no tuple is the binding's, and each is evaluated
//!   as any other.
//! * **Either way**, a tuple that is not the binding's but names a context
//!   member the binding reads is refused 400 `STS-AUTHZEN-0101`, with the
//!   service's sentence.
//! * **A catalogue that does not say** (an older service) is read CLOSED:
//!   the binding on, every other resource type beside a gate a detail, and
//!   every well-formed token type a token-exchange gate's. A 501 decides
//!   nothing; an ordinary evaluation of a tuple the service keeps could
//!   widen.
//!
//! `xacml-pep/authzen_cases.json`'s `binding` cases hold this file and the
//! service's to the same answers (`tests/authzen_map.js` S5).

use serde_json::Value;

use crate::authzen_catalogue::BINDING_CONTEXT;
use crate::sync::AuthzenSettings;

/// The resource type of a gate tuple.
const GATE_RESOURCE: &str = "audience";

/// The resource type of a scope tuple.
const SCOPE_RESOURCE: &str = "protected_resource";

/// The grant segment a token-exchange gate names.
const GRANT: &str = "token_exchange";

/// What one tuple is, for this edge.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Classified {
    /// One of the binding's tuples, and why: 501 (`STS-XPEP-0140`).
    Binding(&'static str),
    /// Not the binding's, but naming a context member it reads: 400
    /// (`STS-AUTHZEN-0101`), with this sentence.
    Stray(String),
    /// An ordinary evaluation.
    Ordinary,
}

impl Classified {
    /// The short word the shared case table names this by.
    #[cfg(test)]
    pub(crate) fn word(&self) -> &'static str {
        match self {
            Classified::Binding(_) => "binding",
            Classified::Stray(_) => "stray",
            Classified::Ordinary => "ordinary",
        }
    }
}

fn entity_str<'a>(body: &'a Value, entity: &str, member: &str) -> &'a str {
    body.get(entity)
        .and_then(Value::as_object)
        .and_then(|object| object.get(member))
        .and_then(Value::as_str)
        .unwrap_or("")
}

/// `issue:<token type>:<grant>`, each segment `[a-z][a-z0-9_]{0,20}` (the
/// service's `GATE_ACTION`): the token type and the grant, when it is one.
fn gate_parts(name: &str) -> Option<(&str, &str)> {
    let mut parts = name.split(':');
    if parts.next() != Some("issue") {
        return None;
    }
    let token_type = parts.next()?;
    let grant = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    (gate_segment(token_type) && gate_segment(grant))
        .then_some((token_type, grant))
}

fn gate_segment(text: &str) -> bool {
    let mut chars = text.chars();
    if !matches!(chars.next(), Some(c) if c.is_ascii_lowercase()) {
        return false;
    }
    let mut rest = 0usize;
    for c in chars {
        if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') {
            return false;
        }
        rest += 1;
        if rest > 20 {
            return false;
        }
    }
    true
}

/// A gate of any grant: an audience resource whose action is
/// `issue:<token type>:<grant>`.
fn is_gate(body: &Value) -> bool {
    entity_str(body, "resource", "type") == GATE_RESOURCE
        && gate_parts(entity_str(body, "action", "name")).is_some()
}

/// A token-exchange gate: the grant `token_exchange` and a token type the
/// service's registry names (any, when the catalogue did not send it). Only
/// such a gate makes the details beside it the exchange's.
fn is_exchange_gate(body: &Value, settings: &AuthzenSettings) -> bool {
    if entity_str(body, "resource", "type") != GATE_RESOURCE {
        return false;
    }
    let Some((token_type, grant)) =
        gate_parts(entity_str(body, "action", "name"))
    else {
        return false;
    };
    grant == GRANT
        && settings
            .token_types
            .as_ref()
            .is_none_or(|types| types.iter().any(|one| one == token_type))
}

/// The first context member the binding reads that this body names, in the
/// service's order. A member present with `null` is named, as there.
fn binding_member(body: &Value) -> Option<&'static str> {
    let context = body.get("context").and_then(Value::as_object)?;
    BINDING_CONTEXT
        .iter()
        .copied()
        .find(|name| context.contains_key(*name))
}

/// The service's `strayContext()` sentence, word for word.
fn stray_message(member: &str, on: bool) -> String {
    format!(
        "context.{} is read by the OAuth token-exchange binding's fixed \
         rules, and only on its gate, scope and authorization-detail tuples \
         (resource.type audience, protected_resource, or a declared \
         authorization_details type beside a gate){}",
        member,
        if on {
            "."
        } else {
            "; the binding is off in this realm (authzen.tokenExchange)."
        }
    )
}

/// Classifies every item of one request, defaults merged (`None` for an
/// item that could not be merged, which is no gate). One evaluation is a
/// request of one item.
pub(crate) fn classify(
    bodies: &[Option<&Value>],
    settings: &AuthzenSettings,
) -> Vec<Classified> {
    let on = settings.token_exchange;
    let exchange = on
        && bodies
            .iter()
            .flatten()
            .any(|body| is_exchange_gate(body, settings));
    bodies
        .iter()
        .map(|body| {
            let Some(body) = body else {
                return Classified::Ordinary;
            };
            if on {
                let resource_type = entity_str(body, "resource", "type");
                if resource_type == SCOPE_RESOURCE {
                    return Classified::Binding("a scope");
                }
                if is_gate(body) {
                    return Classified::Binding("a gate");
                }
                let declared =
                    settings.detail_types.as_ref().is_none_or(|types| {
                        types.iter().any(|one| one == resource_type)
                    });
                if exchange
                    && !resource_type.is_empty()
                    && resource_type != GATE_RESOURCE
                    && declared
                {
                    return Classified::Binding("a detail");
                }
            }
            match binding_member(body) {
                Some(member) => Classified::Stray(stray_message(member, on)),
                None => Classified::Ordinary,
            }
        })
        .collect()
}

/// The 501's message for a binding tuple.
pub(crate) fn binding_message(why: &str) -> String {
    format!(
        "The OAuth token-exchange binding is answered by the service, which \
         holds delegation and the directory. This edge PDP does not answer \
         its tuples ({}).",
        why
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn on() -> AuthzenSettings {
        AuthzenSettings {
            token_exchange: true,
            detail_types: Some(vec!["payment_initiation".into()]),
            token_types: Some(vec!["access_token".into(), "jwt".into()]),
            ..AuthzenSettings::default()
        }
    }

    fn off() -> AuthzenSettings {
        AuthzenSettings {
            token_exchange: false,
            ..on()
        }
    }

    fn words(
        bodies: &[Value],
        settings: &AuthzenSettings,
    ) -> Vec<&'static str> {
        let items: Vec<Option<&Value>> = bodies.iter().map(Some).collect();
        classify(&items, settings)
            .iter()
            .map(Classified::word)
            .collect()
    }

    fn gate(action: &str) -> Value {
        json!({ "subject": { "type": "user", "id": "alice" },
                "action": { "name": action },
                "resource": { "type": "audience", "id": "https://api" } })
    }

    fn typed(kind: &str) -> Value {
        json!({ "subject": { "type": "user", "id": "alice" },
                "action": { "name": "read" },
                "resource": { "type": kind, "id": "x" } })
    }

    /// The shared table's `binding` cases, as the service answers them.
    #[test]
    fn agrees_with_the_shared_binding_cases() {
        let table = crate::authzen_map::tests::shared_cases();
        let cases = table["binding"].as_array().unwrap();
        assert!(cases.len() >= 10);
        for case in cases {
            let settings = AuthzenSettings::of(&case["settings"]);
            let bodies = case["items"].as_array().unwrap();
            let got = words(bodies, &settings);
            let expected: Vec<String> =
                serde_json::from_value(case["kinds"].clone()).unwrap();
            assert_eq!(got, expected, "{}", case["what"]);
        }
    }

    /// An older service's catalogue, which names none of the three, is
    /// read closed: the binding on, any type beside any well-formed
    /// token-exchange gate a detail.
    #[test]
    fn an_absent_setting_is_read_closed() {
        let settings = AuthzenSettings::of(&json!({}));
        assert!(settings.token_exchange);
        assert!(settings.detail_types.is_none());
        assert!(settings.token_types.is_none());
        assert!(!settings.obligations_profile);
        assert_eq!(
            words(&[typed("protected_resource")], &settings),
            ["binding"]
        );
        assert_eq!(
            words(
                &[gate("issue:made_up:token_exchange"), typed("anything")],
                &settings
            ),
            ["binding", "binding"]
        );
        // A list that is not a list of strings is not a list.
        let settings = AuthzenSettings::of(&json!({
            "tokenExchange": true, "tokenExchangeDetailTypes": [1] }));
        assert!(settings.detail_types.is_none());
    }

    #[test]
    fn the_gate_names_its_token_type_first() {
        assert_eq!(
            gate_parts("issue:access_token:token_exchange"),
            Some(("access_token", "token_exchange"))
        );
        assert_eq!(gate_parts("issue:access-token:token_exchange"), None);
        assert_eq!(gate_parts("issue:a:b:c"), None);
        assert!(is_exchange_gate(&gate("issue:jwt:token_exchange"), &on()));
        assert!(!is_exchange_gate(
            &gate("issue:saml2:token_exchange"),
            &on()
        ));
        assert!(!is_exchange_gate(&gate("issue:jwt:other_grant"), &on()));
        assert!(
            words(&[gate("issue:jwt:other_grant")], &off()) == ["ordinary"]
        );
    }

    #[test]
    fn a_stray_member_says_whether_the_binding_is_off() {
        let mut body = typed("document");
        body["context"] = json!({ "may_act": null, "act": {} });
        let items = [Some(&body)];
        let Classified::Stray(said) = &classify(&items, &off())[0] else {
            panic!("not stray");
        };
        assert!(said.starts_with("context.act is read"));
        assert!(said.ends_with("(authzen.tokenExchange)."));
        let Classified::Stray(said) = &classify(&items, &on())[0] else {
            panic!("not stray");
        };
        assert!(said.ends_with("beside a gate)."));
    }
}
