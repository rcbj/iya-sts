// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! AN AUTHZEN ACCESS EVALUATION, AS AN XACML REQUEST, AND ITS DECISION BACK
//! — PORTED (#1179). A port of `authzen/authzen_map.ts`, which argues every
//! rule; PURE, as that file is: no I/O, no route, no store.
//!
//! **ONE REQUEST IS MAPPED ONE WAY IN BOTH PLACES.** The same members
//! refused, the same identifiers, the same value rules (the row's datatype
//! wins; `null` refused; an array only for a `bag` row; a nested object only
//! through declared dotted rows; an undeclared property refused in every
//! mode; absent and empty kept apart by the trusted `supplied` bag), the
//! same codes and statuses, and the request built by `sts-xacml`'s
//! `AuthorizationRequest::authzen()`, the port of `xacml_request.js`'s.
//! `xacml-pep/authzen_cases.json` is the one table both are held to.
//!
//! **THE RESULT IS FAIL-CLOSED** (decision 8 on #563): `true` only on a
//! Permit carrying nothing this PDP cannot discharge — `enforce.rs`
//! deny-biased, whatever `PEP_BIAS` says, because the bias is this PEP's
//! rule for `/protected` and the AuthZEN caller enforces the answer itself.
//! Deny, NotApplicable and an Indeterminate over a missing attribute are an
//! ordinary `false`; an Indeterminate over a processing or syntax error, or
//! a root policy this container would not load, is a FAULT — a 500, or a
//! batch item's `context.error` — never a denial.
//! `urn:sts:xacml:obligation:log` is the one obligation discharged.
//!
//! **WHAT IS NOT BYTE-FOR-BYTE THE SERVICE'S**: the sentence a refusal
//! carries when a STRING will not parse at the row's datatype quotes this
//! engine's error rather than the JavaScript one's, and `reason_admin` is
//! `enforce.rs`'s sentence rather than `xacml.ts`'s. Neither decides
//! anything; the code, the status and the decision are the contract.

use serde_json::{json, Map, Value};
use sts_xacml::builder::{
    AuthorizationRequest, AuthzenAttribute, AuthzenFacts,
};
use sts_xacml::datatypes::DataTypes;
use sts_xacml::model::{types, Decision, StatusCode};
use sts_xacml::request::{Request, Response};
use sts_xacml::value::js_number_string;

use crate::authzen_catalogue::{
    js_keys, js_length, js_slice, Row, RESERVED_CONTEXT, TYPE_NAMES,
};
use crate::enforce::Outcome as Enforcement;

/// The longest a type, an id or a name may be.
pub const MAX_TEXT: usize = 1024;

/// The longest a string property's value may be.
const MAX_VALUE: usize = 8192;

/// The most values a bag may carry.
const MAX_BAG: usize = 256;

/// A request that cannot be evaluated.
#[derive(Debug, Clone, PartialEq)]
pub struct Refusal {
    pub status: u16,
    pub code: &'static str,
    pub message: String,
}

/// One evaluation, read and checked.
#[derive(Debug, Clone, PartialEq)]
pub struct Evaluation {
    pub subject_type: String,
    pub subject_id: String,
    pub action_name: String,
    pub resource_type: String,
    pub resource_id: String,
    pub application: String,
    pub attributes: Vec<AuthzenAttribute>,
    pub supplied: Vec<String>,
}

/// What the adapter knows about the caller, written as trusted facts.
pub struct Trusted<'a> {
    pub realm: &'a str,
    pub caller: &'a str,
    pub application: &'a str,
}

/// A decision mapped back.
#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    pub fault: bool,
    pub decision: bool,
    pub xacml_decision: String,
    pub why: String,
    pub undischargeable: Vec<String>,
    pub discharged: Vec<String>,
    pub advice: Vec<Value>,
}

fn refused(code: &'static str, message: String) -> Refusal {
    Refusal {
        status: 400,
        code,
        message,
    }
}

/// The first member of an object that is not in a list, cut short.
fn stray(object: &Map<String, Value>, allowed: &[&str]) -> Option<String> {
    js_keys(object)
        .into_iter()
        .find(|key| !allowed.contains(&key.as_str()))
        .map(|key| js_slice(key, 64))
}

/// Reads one access evaluation request (section 5) against the realm's
/// catalogue rows, as `AuthzenMap.read()` does.
pub fn read(body: &Value, rows: &[Row]) -> Result<Evaluation, Refusal> {
    let Some(given) = body.as_object() else {
        return Err(refused(
            "STS-AUTHZEN-0001",
            "An access evaluation request is a JSON object with subject, \
             action, resource and optionally context."
                .into(),
        ));
    };
    if let Some(key) =
        stray(given, &["subject", "action", "resource", "context"])
    {
        return Err(refused(
            "STS-AUTHZEN-0009",
            format!(
                "An access evaluation request has no member \"{}\"; it takes \
                 subject, action, resource and context.",
                key
            ),
        ));
    }
    let shapes: [(&str, &[&str], &[&str]); 3] = [
        ("subject", &["type", "id"], &["type", "id", "properties"]),
        ("action", &["name"], &["name", "properties"]),
        ("resource", &["type", "id"], &["type", "id", "properties"]),
    ];
    let mut parts: Vec<Vec<String>> = Vec::new();
    for (name, required, members) in shapes {
        let Some(object) = given.get(name) else {
            let joined = required.join(&format!(" and {}.", name));
            return Err(refused(
                "STS-AUTHZEN-0002",
                format!(
                    "The request has no {}, which AuthZEN requires ({}.{}).",
                    name, name, joined
                ),
            ));
        };
        let Some(object) = object.as_object() else {
            return Err(refused(
                "STS-AUTHZEN-0003",
                format!("{} must be a JSON object.", name),
            ));
        };
        if let Some(key) = stray(object, members) {
            return Err(refused(
                "STS-AUTHZEN-0009",
                format!(
                    "{} has no member \"{}\"; it takes {}.",
                    name,
                    key,
                    members.join(", ")
                ),
            ));
        }
        let mut values = Vec::new();
        for member in required {
            let value = object.get(*member);
            let missing = match value {
                None | Some(Value::Null) => true,
                Some(Value::String(s)) => s.is_empty(),
                _ => false,
            };
            if missing {
                return Err(refused(
                    "STS-AUTHZEN-0002",
                    format!(
                        "{}.{} is required, and a non-empty string.",
                        name, member
                    ),
                ));
            }
            match value.and_then(Value::as_str) {
                Some(text) if js_length(text) <= MAX_TEXT => {
                    values.push(text.to_string())
                }
                _ => {
                    return Err(refused(
                        "STS-AUTHZEN-0003",
                        format!(
                            "{}.{} must be a string of at most {} characters.",
                            name, member, MAX_TEXT
                        ),
                    ))
                }
            }
        }
        if let Some(properties) = object.get("properties") {
            if !properties.is_object() {
                return Err(refused(
                    "STS-AUTHZEN-0003",
                    format!("{}.properties must be a JSON object.", name),
                ));
            }
        }
        parts.push(values);
    }
    let empty = Map::new();
    let context = match given.get("context") {
        None => &empty,
        Some(Value::Object(map)) => map,
        Some(_) => {
            return Err(refused(
                "STS-AUTHZEN-0003",
                "context must be a JSON object.".into(),
            ))
        }
    };
    let mut application = String::new();
    if let Some(asked) = context.get("application") {
        match asked.as_str() {
            Some(text) if !text.is_empty() && js_length(text) <= MAX_TEXT => {
                application = text.to_string()
            }
            _ => {
                return Err(refused(
                    "STS-AUTHZEN-0003",
                    "context.application must be a non-empty string naming \
                     one of the applications this caller is scoped to."
                        .into(),
                ))
            }
        }
    }
    let mut supplied: Vec<String> = [
        "subject.type",
        "subject.id",
        "action.name",
        "resource.type",
        "resource.id",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    if !application.is_empty() {
        supplied.push("context.application".into());
    }
    let mut attributes = Vec::new();
    let properties_of = |name: &str| -> Map<String, Value> {
        given
            .get(name)
            .and_then(|o| o.get("properties"))
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default()
    };
    let mut context_rest = Map::new();
    for key in js_keys(context) {
        if !RESERVED_CONTEXT.contains(&key.as_str()) {
            if let Some(value) = context.get(key) {
                context_rest.insert(key.clone(), value.clone());
            }
        }
    }
    let walked = [
        ("subject", properties_of("subject"), "subject.properties."),
        ("action", properties_of("action"), "action.properties."),
        (
            "resource",
            properties_of("resource"),
            "resource.properties.",
        ),
        ("context", context_rest, "context."),
    ];
    for (object, members, shown) in &walked {
        walk(
            object,
            members,
            "",
            shown,
            rows,
            &mut attributes,
            &mut supplied,
            0,
        )?;
    }
    let mut parts = parts.into_iter();
    let subject = parts.next().unwrap_or_default();
    let action = parts.next().unwrap_or_default();
    let resource = parts.next().unwrap_or_default();
    let at = |list: &Vec<String>, i: usize| -> String {
        list.get(i).cloned().unwrap_or_default()
    };
    Ok(Evaluation {
        subject_type: at(&subject, 0),
        subject_id: at(&subject, 1),
        action_name: at(&action, 0),
        resource_type: at(&resource, 0),
        resource_id: at(&resource, 1),
        application,
        attributes,
        supplied,
    })
}

/// Walks one object's members against the catalogue, mapping each declared
/// one and refusing the rest.
#[allow(clippy::too_many_arguments)]
fn walk(
    object: &str,
    value: &Map<String, Value>,
    prefix: &str,
    shown: &str,
    rows: &[Row],
    out: &mut Vec<AuthzenAttribute>,
    supplied: &mut Vec<String>,
    depth: usize,
) -> Result<(), Refusal> {
    for key in js_keys(value) {
        let path = if prefix.is_empty() {
            key.clone()
        } else {
            format!("{}.{}", prefix, key)
        };
        let named = format!("{}{}", shown, path);
        let member = value.get(key).unwrap_or(&Value::Null);
        let row = rows
            .iter()
            .find(|one| one.object == object && one.property == path);
        let branch = row.is_none()
            && rows.iter().any(|one| {
                one.object == object
                    && one.property.starts_with(&format!("{}.", path))
            });
        if row.is_none() && !(branch && member.is_object()) {
            return Err(refused(
                "STS-AUTHZEN-0004",
                format!(
                    "{} is not in this realm's AuthZEN attribute catalogue, \
                     and an undeclared property is refused in every mode. An \
                     administrator declares it on the sts-authzen-api \
                     application.",
                    js_slice(&named, 200)
                ),
            ));
        }
        if member.is_null() {
            return Err(refused(
                "STS-AUTHZEN-0005",
                format!(
                    "{} is null, which is neither an empty value nor an \
                     absent one. Leave the member out, or send a value.",
                    js_slice(&named, 200)
                ),
            ));
        }
        supplied.push(named.clone());
        let Some(row) = row else {
            if depth + 1 > 8 {
                return Err(refused(
                    "STS-AUTHZEN-0008",
                    format!("{} is nested too deeply.", js_slice(&named, 200)),
                ));
            }
            let empty = Map::new();
            let deeper = member.as_object().unwrap_or(&empty);
            walk(object, deeper, &path, shown, rows, out, supplied, depth + 1)?;
            continue;
        };
        let lexical = values_of(row, member, &named)?;
        out.push(AuthzenAttribute {
            category: row.category.clone(),
            attribute_id: row.attribute_id.clone(),
            data_type: row.data_type.clone(),
            values: lexical,
        });
    }
    Ok(())
}

/// A JSON value's `typeof`, for a message.
fn type_of(value: &Value) -> &'static str {
    match value {
        Value::String(_) => "string",
        Value::Number(_) => "number",
        Value::Bool(_) => "boolean",
        _ => "object",
    }
}

/// Converts one member's JSON value to the lexical values its row sends.
fn values_of(
    row: &Row,
    member: &Value,
    named: &str,
) -> Result<Vec<String>, Refusal> {
    let shown = js_slice(named, 200);
    if member.is_object() {
        return Err(refused(
            "STS-AUTHZEN-0008",
            format!(
                "{} is an object, and its row sends one {}. A nested object \
                 reaches a request only through rows for its own members \
                 ({}.<member>).",
                shown,
                if row.multiplicity == "bag" {
                    "bag of values"
                } else {
                    "value"
                },
                shown
            ),
        ));
    }
    if member.is_array() && row.multiplicity != "bag" {
        return Err(refused(
            "STS-AUTHZEN-0007",
            format!(
                "{} is an array, and its row sends a single value. A row \
                 whose multiplicity is bag takes an array.",
                shown
            ),
        ));
    }
    let list: Vec<&Value> = match member {
        Value::Array(items) => items.iter().collect(),
        other => vec![other],
    };
    if list.len() > MAX_BAG {
        return Err(refused(
            "STS-AUTHZEN-0007",
            format!("{} carries more than {} values.", shown, MAX_BAG),
        ));
    }
    let mut lexical = Vec::new();
    for one in list {
        if one.is_null() {
            return Err(refused(
                "STS-AUTHZEN-0005",
                format!("{} holds a null, which is not a value.", shown),
            ));
        }
        if one.is_object() || one.is_array() {
            return Err(refused(
                "STS-AUTHZEN-0008",
                format!(
                    "{} holds an object or an array; a bag is of scalars.",
                    shown
                ),
            ));
        }
        let Some(text) = lexical_of(&row.data_type, one) else {
            return Err(refused(
                "STS-AUTHZEN-0006",
                format!(
                    "{} is a JSON {}, and its row sends {}. {}",
                    shown,
                    type_of(one),
                    type_name(&row.data_type),
                    type_advice(&row.data_type)
                ),
            ));
        };
        if let Err(error) = DataTypes::standard().parse(&row.data_type, &text) {
            return Err(refused(
                "STS-AUTHZEN-0006",
                format!(
                    "{} is not a valid {}: {}",
                    shown,
                    type_name(&row.data_type),
                    js_slice(&error.message, 200)
                ),
            ));
        }
        lexical.push(text);
    }
    Ok(lexical)
}

/// The largest integer a JavaScript number holds exactly.
const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

/// The lexical form of one JSON scalar at a datatype, or `None` when that
/// JSON type may not reach it. A string reaches every type (parsed after);
/// a boolean only a boolean; a number only an integer — and then only a
/// whole one — or a double. A number is read as JavaScript reads it, a
/// double, so `3.0` is the whole number 3 and an integer past 2^53 is not
/// one exactly.
fn lexical_of(type_uri: &str, value: &Value) -> Option<String> {
    match value {
        Value::String(text) => {
            if js_length(text) > MAX_VALUE {
                None
            } else {
                Some(text.clone())
            }
        }
        Value::Bool(b) => (type_uri == types::BOOLEAN).then(|| b.to_string()),
        Value::Number(number) => {
            let n = number.as_f64()?;
            if !n.is_finite() {
                return None;
            }
            if type_uri == types::INTEGER {
                let whole = n.fract() == 0.0 && n.abs() <= MAX_SAFE_INTEGER;
                return whole.then(|| js_number_string(n));
            }
            (type_uri == types::DOUBLE).then(|| js_number_string(n))
        }
        _ => None,
    }
}

/// A datatype's short name, for a message.
fn type_name(type_uri: &str) -> String {
    TYPE_NAMES
        .iter()
        .find(|(_, uri)| *uri == type_uri)
        .map(|(name, _)| name.to_string())
        .unwrap_or_else(|| type_uri.to_string())
}

/// What a caller should send for a datatype, for a message.
fn type_advice(type_uri: &str) -> &'static str {
    if type_uri == types::BOOLEAN {
        "Send true or false."
    } else if type_uri == types::INTEGER {
        "Send a whole number; a fraction is refused."
    } else if type_uri == types::DOUBLE {
        "Send a number."
    } else if type_uri == types::STRING {
        "Send a string; a number or a boolean is not quietly one."
    } else {
        "Send a string in its lexical form."
    }
}

/// Builds the XACML request for one evaluation, through the one builder.
pub fn request(evaluation: &Evaluation, trusted: &Trusted) -> Request {
    let facts = AuthzenFacts {
        subject_type: evaluation.subject_type.clone(),
        subject_id: evaluation.subject_id.clone(),
        action_name: evaluation.action_name.clone(),
        resource_type: evaluation.resource_type.clone(),
        resource_id: evaluation.resource_id.clone(),
        realm: trusted.realm.to_string(),
        caller: trusted.caller.to_string(),
        application: trusted.application.to_string(),
        supplied: evaluation.supplied.clone(),
        attributes: evaluation.attributes.clone(),
    };
    AuthorizationRequest::default().authzen(&facts).build()
}

/// Maps the engine's answer and its deny-biased enforcement to an AuthZEN
/// decision, fail-closed. `root_fault` is a root policy this container
/// would not load — the service's `STS-XACML-0012`.
pub fn outcome(
    answer: &Response,
    enforcement: &Enforcement,
    root_fault: bool,
) -> Outcome {
    let fault = root_fault
        || (answer.decision == Decision::Indeterminate
            && matches!(
                answer.status.code,
                StatusCode::ProcessingError | StatusCode::SyntaxError
            ));
    let why = if fault {
        let said = answer
            .status
            .message
            .clone()
            .unwrap_or_else(|| answer.status.code.uri().to_string());
        format!(
            "The PDP could not evaluate the request: {}",
            js_slice(&said, 300)
        )
    } else {
        enforcement.why.clone()
    };
    let advice = answer
        .advice
        .iter()
        .map(|one| {
            let attributes: Vec<Value> = one
                .assignments
                .iter()
                .map(|a| json!({ "id": a.attribute_id, "value": a.lexical }))
                .collect();
            json!({ "id": one.id, "attributes": attributes })
        })
        .collect();
    Outcome {
        fault,
        decision: !fault && enforcement.allowed,
        xacml_decision: answer.decision.as_str().to_string(),
        why,
        undischargeable: enforcement.undischargeable.clone(),
        discharged: enforcement.discharged.clone(),
        advice,
    }
}

/// The `context` a decision carries when `authzen.returnReasons` is on:
/// explanatory, and kept apart from `decision`, which alone says whether to
/// allow (section 5.5).
pub fn reasons(outcome: &Outcome) -> Value {
    let mut out = json!({
        "xacml_decision": outcome.xacml_decision,
        "reason_admin": { "en": outcome.why }
    });
    if let Some(map) = out.as_object_mut() {
        if !outcome.undischargeable.is_empty() {
            map.insert(
                "undischargeable_obligations".into(),
                json!(outcome.undischargeable),
            );
        }
        if !outcome.advice.is_empty() {
            map.insert("advice".into(), Value::Array(outcome.advice.clone()));
        }
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::authzen_catalogue::parse;
    use crate::enforce::Enforcer;
    use crate::options::Bias;
    use sts_xacml::model::{attribute, category};
    use sts_xacml::request::{ResolvedObligation, Status};

    /// `xacml-pep/authzen_cases.json`, the table this file and
    /// `authzen/authzen_map.ts` are both held to.
    pub(crate) fn shared_cases() -> Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../xacml-pep/authzen_cases.json"
        );
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    fn shared_rows(table: &Value) -> Vec<Row> {
        table["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| parse(value).unwrap())
            .collect()
    }

    fn values_in(built: &Request, cat: &str, id: &str) -> Vec<String> {
        built
            .categories
            .iter()
            .filter(|c| c.category == cat)
            .flat_map(|c| &c.attributes)
            .filter(|a| a.attribute_id == id)
            .flat_map(|a| a.values.iter().map(|v| v.lexical.clone()))
            .collect()
    }

    /// Every request in the shared table, refused with the service's code
    /// or accepted, and — where the table says — supplied and mapped as the
    /// service maps it.
    #[test]
    fn agrees_with_the_shared_request_cases() {
        let table = shared_cases();
        let rows = shared_rows(&table);
        let cases = table["requests"].as_array().unwrap();
        assert!(cases.len() >= 30);
        for case in cases {
            let read = read(&case["body"], &rows);
            let code = match &read {
                Ok(_) => "",
                Err(refusal) => refusal.code,
            };
            assert_eq!(
                code,
                case["code"].as_str().unwrap(),
                "{}",
                case["what"]
            );
            if let Err(refusal) = &read {
                assert_eq!(refusal.status, 400, "{}", case["what"]);
            }
            if let (Ok(evaluation), Some(expected)) =
                (&read, case.get("supplied"))
            {
                let expected: Vec<String> =
                    serde_json::from_value(expected.clone()).unwrap();
                assert_eq!(evaluation.supplied, expected, "{}", case["what"]);
            }
            if let (Ok(evaluation), Some(expected)) =
                (&read, case.get("attributes"))
            {
                let got: Vec<Value> = evaluation
                    .attributes
                    .iter()
                    .map(|a| {
                        json!({ "attributeId": a.attribute_id,
                                     "values": a.values })
                    })
                    .collect();
                assert_eq!(&Value::Array(got), expected, "{}", case["what"]);
            }
        }
    }

    /// B: the built request, through the port of the one builder.
    #[test]
    fn builds_the_request_the_service_builds() {
        let table = shared_cases();
        let rows = shared_rows(&table);
        let body = json!({
            "subject": { "type": "user", "id": "alice",
                         "properties": { "department": "eng",
                                         "clearance": 4 } },
            "action": { "name": "read" },
            "resource": { "type": "document", "id": "doc-1",
                          "properties": { "classification": "internal" } },
            "context": { "application": "portal",
                         "source_ip": "192.0.2.25" }
        });
        let evaluation = read(&body, &rows).unwrap();
        let built = request(
            &evaluation,
            &Trusted {
                realm: "acme",
                caller: "cn=pep-1,ou=users,dc=acme",
                application: "portal",
            },
        );
        use sts_xacml::builder::vocabulary as v;
        let s = category::ACCESS_SUBJECT;
        let e = category::ENVIRONMENT;
        assert_eq!(values_in(&built, s, attribute::SUBJECT_ID), ["alice"]);
        assert_eq!(
            values_in(&built, category::ACTION, attribute::ACTION_ID),
            ["read"]
        );
        assert_eq!(
            values_in(&built, category::RESOURCE, attribute::RESOURCE_ID),
            ["doc-1"]
        );
        assert_eq!(values_in(&built, s, v::AUTHZEN_SUBJECT_TYPE), ["user"]);
        assert_eq!(
            values_in(&built, category::RESOURCE, v::AUTHZEN_RESOURCE_TYPE),
            ["document"]
        );
        assert_eq!(values_in(&built, e, v::PROTOCOL), ["authzen"]);
        assert_eq!(values_in(&built, e, v::REALM), ["acme"]);
        assert_eq!(
            values_in(&built, e, v::AUTHZEN_CALLER),
            ["cn=pep-1,ou=users,dc=acme"]
        );
        assert_eq!(values_in(&built, e, v::AUTHZEN_APPLICATION), ["portal"]);
        assert_eq!(values_in(&built, s, "urn:example:clearance"), ["4"]);
        assert_eq!(
            values_in(&built, e, "urn:example:source-ip"),
            ["192.0.2.25"]
        );
        let clearance = built
            .categories
            .iter()
            .flat_map(|c| &c.attributes)
            .find(|a| a.attribute_id == "urn:example:clearance")
            .unwrap();
        assert_eq!(clearance.values[0].type_uri, types::INTEGER);
        let supplied = values_in(&built, e, v::AUTHZEN_SUPPLIED);
        assert!(supplied.contains(&"context.application".to_string()));
        let department = "subject.properties.department".to_string();
        assert!(supplied.contains(&department));
        // An empty realm is left out rather than sent as "".
        let bare = request(
            &evaluation,
            &Trusted {
                realm: "",
                caller: "c",
                application: "",
            },
        );
        assert!(values_in(&bare, e, v::REALM).is_empty());
    }

    fn answer(
        decision: Decision,
        code: StatusCode,
        obligations: &[&str],
    ) -> Response {
        Response {
            decision,
            status: Status {
                code,
                message: None,
            },
            obligations: obligations
                .iter()
                .map(|id| ResolvedObligation {
                    id: id.to_string(),
                    assignments: Vec::new(),
                })
                .collect(),
            advice: Vec::new(),
            policy_identifiers: Vec::new(),
        }
    }

    /// D: the decision, fail-closed — the service's D1 to D9.
    #[test]
    fn maps_the_decision_fail_closed() {
        let enforcer = Enforcer::new(Bias::DenyBiased);
        let map = |a: &Response, root_fault: bool| {
            outcome(
                a,
                &enforcer.enforce(a.decision, &a.obligations),
                root_fault,
            )
        };
        let ok = StatusCode::Ok;
        let permit = map(&answer(Decision::Permit, ok, &[]), false);
        assert!(!permit.fault && permit.decision);
        let deny = map(&answer(Decision::Deny, ok, &[]), false);
        assert!(!deny.fault && !deny.decision);
        let none = map(&answer(Decision::NotApplicable, ok, &[]), false);
        assert!(!none.fault && !none.decision);
        let missing = map(
            &answer(Decision::Indeterminate, StatusCode::MissingAttribute, &[]),
            false,
        );
        assert!(!missing.fault && !missing.decision);
        let fault = map(
            &answer(Decision::Indeterminate, StatusCode::ProcessingError, &[]),
            false,
        );
        assert!(fault.fault && !fault.decision);
        let syntax = map(
            &answer(Decision::Indeterminate, StatusCode::SyntaxError, &[]),
            false,
        );
        assert!(syntax.fault);
        let marked = map(&answer(Decision::Indeterminate, ok, &[]), true);
        assert!(marked.fault, "a root policy that would not load");
        let obliged = map(
            &answer(Decision::Permit, ok, &["urn:example:obligation:notify"]),
            false,
        );
        assert!(!obliged.fault && !obliged.decision);
        assert_eq!(obliged.undischargeable, ["urn:example:obligation:notify"]);
        let logged = map(
            &answer(Decision::Permit, ok, &["urn:sts:xacml:obligation:log"]),
            false,
        );
        assert!(logged.decision);
        let why = reasons(&obliged);
        assert_eq!(why["xacml_decision"], "Permit");
        assert_eq!(
            why["undischargeable_obligations"].as_array().unwrap().len(),
            1
        );
        assert!(why["reason_admin"]["en"].is_string());
    }

    #[test]
    fn numbers_are_read_as_javascript_reads_them() {
        assert_eq!(lexical_of(types::INTEGER, &json!(3.0)).unwrap(), "3");
        assert!(lexical_of(types::INTEGER, &json!(1.5)).is_none());
        assert!(
            lexical_of(types::INTEGER, &json!(9007199254740993u64)).is_none()
        );
        assert_eq!(lexical_of(types::DOUBLE, &json!(2.5)).unwrap(), "2.5");
        assert_eq!(lexical_of(types::DOUBLE, &json!(1e21)).unwrap(), "1e+21");
        assert!(lexical_of(types::STRING, &json!(3)).is_none());
        assert!(lexical_of(types::STRING, &json!(true)).is_none());
        assert_eq!(lexical_of(types::BOOLEAN, &json!(true)).unwrap(), "true");
    }
}
