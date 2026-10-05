// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The JSON Profile of XACML 3.0 (v1.1): a decision REQUEST read into the
//! model and a RESPONSE written from it. A port of `xacml/xacml_json.js`,
//! whose header argues the profile; what matters here is the same four
//! traps and the same refusals.
//!
//! **The profile defines no policy syntax**, so this module reads and writes
//! no policies — they stay XML (or ALFA).
//!
//! 1. **The datatype is optional and inferred from the JSON type**, and a
//!    number is a double only when its TEXT has a fractional part or an
//!    exponent (section 3.3.3), so `5.0` is a double and `5` an integer.
//!    The Node reader re-scans the body with a regular expression to recover
//!    that text, because `JSON.parse` returns `5` for both; `serde_json`
//!    keeps it — a number written with `.` or an exponent is an `f64`, any
//!    other is an integer — so nothing is re-scanned here, and a number
//!    inside an array is typed as surely as a bare one (the Node scan saw
//!    only the bare ones). One edge differs and is stated: an integer beyond
//!    the 64-bit range arrives as an `f64` and is inferred a double, where
//!    Node inferred an integer from the text and then lost its digits anyway.
//! 2. **The category has shorthand names** (section 4.2.1), and a request
//!    may use them and the generic `Category` array at once.
//! 3. **The datatype may be a short name** (section 3.3.2), built from the
//!    datatype table's own names so the two cannot disagree.
//! 4. **A value that is an array is a BAG**, not a value of an array type.
//!
//! **Refused, as a syntax error the caller sees as a 400**: a body that is
//! not JSON or has no `Request` object, a category that is not an object, a
//! `Category` entry with no `CategoryId`, an attribute with no string
//! `AttributeId`, an unknown `DataType`, a `Value` that is an object, and a
//! value with no type that none can be inferred for. A request the POLICY
//! cannot decide is a different thing — a 200 carrying an Indeterminate.

use serde_json::{json, Map, Value as Json};

use crate::datatypes::DataTypes;
use crate::model::{canonical_type, category, types, StatusCode};
use crate::model::{XacmlError, XacmlResult};
use crate::request::{
    PolicyIdentifier, Request, RequestAttribute, RequestCategory, RequestValue,
    ResolvedObligation, Response,
};
use crate::value::js_number_string;

/// The shorthand category names (section 4.2.1), in the order a request's
/// members are read.
pub const SHORTHAND_CATEGORY: [(&str, &str); 8] = [
    ("AccessSubject", category::ACCESS_SUBJECT),
    ("RecipientSubject", category::RECIPIENT_SUBJECT),
    ("IntermediarySubject", category::INTERMEDIARY_SUBJECT),
    ("Codebase", category::CODEBASE),
    ("RequestingMachine", category::REQUESTING_MACHINE),
    ("Resource", category::RESOURCE),
    ("Action", category::ACTION),
    ("Environment", category::ENVIRONMENT),
];

/// A `DataType` member — a datatype URI or a short name — to a canonical
/// datatype URI; `None` when it is neither.
pub fn resolve_type(name: &str) -> Option<String> {
    if name.is_empty() {
        return None;
    }
    let table = DataTypes::standard();
    if table.get(name).is_some() {
        return Some(canonical_type(name).to_string());
    }
    table
        .all()
        .find(|row| row.name() == name)
        .map(|row| row.uri().to_string())
}

/// Every short name, sorted, for the refusal that lists them.
fn short_names() -> Vec<&'static str> {
    let mut names: Vec<&'static str> =
        DataTypes::standard().all().map(|row| row.name()).collect();
    names.sort_unstable();
    names
}

/// The datatype of a value that declared none, from its JSON type (trap 1).
/// A string is a string: the profile does not sniff one for a date, and
/// neither does this.
pub fn infer_type(raw: &Json) -> Option<&'static str> {
    match raw {
        Json::Bool(_) => Some(types::BOOLEAN),
        Json::Number(n) if n.is_f64() => Some(types::DOUBLE),
        Json::Number(_) => Some(types::INTEGER),
        Json::String(_) => Some(types::STRING),
        _ => None,
    }
}

/// The lexical form a JSON value denotes: a boolean is `true`/`false`, a
/// number its decimal text as JavaScript writes it, `null` the empty string.
fn lexical_of(raw: &Json) -> String {
    match raw {
        Json::Null => String::new(),
        Json::Bool(b) => b.to_string(),
        Json::String(text) => text.clone(),
        Json::Number(n) => match n.as_f64() {
            Some(f) if n.is_f64() => js_number_string(f),
            _ => n.to_string(),
        },
        other => other.to_string(),
    }
}

fn as_list(source: &Json) -> Vec<&Json> {
    match source {
        Json::Array(items) => items.iter().collect(),
        one => vec![one],
    }
}

/// A member that is present and not `null`, `false`, `0` or `""` — the
/// Node reader's truthiness test, kept so the two read one request alike.
fn present<'a>(object: &'a Map<String, Json>, key: &str) -> Option<&'a Json> {
    object.get(key).filter(|value| match value {
        Json::Null | Json::Bool(false) => false,
        Json::String(text) => !text.is_empty(),
        Json::Number(n) => n.as_f64() != Some(0.0),
        _ => true,
    })
}

fn read_attribute(source: &Json) -> XacmlResult<RequestAttribute> {
    let Json::Object(source) = source else {
        return Err(XacmlError::syntax("An Attribute must be an object."));
    };
    let attribute_id = match present(source, "AttributeId") {
        Some(Json::String(id)) => id.clone(),
        _ => {
            return Err(XacmlError::syntax(
                "An Attribute must carry a string AttributeId.",
            ))
        }
    };
    let declared = match present(source, "DataType") {
        None => None,
        Some(given) => {
            let text = match given {
                Json::String(text) => text.clone(),
                other => other.to_string(),
            };
            match resolve_type(&text) {
                Some(uri) => Some(uri),
                None => {
                    return Err(XacmlError::syntax(format!(
                        "Unknown DataType \"{}\" on attribute \"{}\". Use a \
                         XACML datatype URI or one of its short names ({}).",
                        text,
                        attribute_id,
                        short_names().join(", ")
                    )))
                }
            }
        }
    };
    let raw = source.get("Value").unwrap_or(&Json::Null);
    let mut values = Vec::new();
    for one in as_list(raw) {
        if one.is_object() || one.is_array() {
            return Err(XacmlError::syntax(format!(
                "The Value of attribute \"{}\" is an object. XACML has no \
                 structured datatype reachable this way; use Content and an \
                 AttributeSelector instead.",
                attribute_id
            )));
        }
        let type_uri = match &declared {
            Some(uri) => uri.clone(),
            None => match infer_type(one) {
                Some(uri) => uri.to_string(),
                None => {
                    return Err(XacmlError::syntax(format!(
                        "The Value of attribute \"{}\" has no DataType and \
                         none can be inferred from it.",
                        attribute_id
                    )))
                }
            },
        };
        values.push(RequestValue {
            type_uri,
            lexical: lexical_of(one),
        });
    }
    Ok(RequestAttribute {
        attribute_id,
        issuer: match present(source, "Issuer") {
            Some(Json::String(issuer)) => Some(issuer.clone()),
            _ => None,
        },
        include_in_result: source.get("IncludeInResult")
            == Some(&Json::Bool(true)),
        values,
    })
}

fn read_categories(
    category_id: Option<&str>,
    source: &Json,
    into: &mut Vec<RequestCategory>,
) -> XacmlResult<()> {
    for one in as_list(source) {
        let Json::Object(one) = one else {
            return Err(XacmlError::syntax("A category must be an object."));
        };
        let attributes = match present(one, "Attribute") {
            Some(list) => as_list(list)
                .into_iter()
                .map(read_attribute)
                .collect::<XacmlResult<Vec<_>>>()?,
            None => Vec::new(),
        };
        let id = category_id
            .map(str::to_string)
            .or_else(|| {
                one.get("CategoryId")
                    .and_then(Json::as_str)
                    .map(str::to_string)
            })
            .unwrap_or_default();
        into.push(RequestCategory {
            category: id,
            id: present(one, "Id")
                .and_then(Json::as_str)
                .map(str::to_string),
            // <Content> reaches the profile as a string and is carried
            // unparsed, exactly as the XML reader keeps only its presence.
            has_content: present(one, "Content").is_some(),
            attributes,
        });
    }
    Ok(())
}

/// Reads a JSON Profile request into the engine's [`Request`].
pub fn parse_request(body: &str) -> XacmlResult<Request> {
    let parsed: Json = serde_json::from_str(body).map_err(|error| {
        XacmlError::syntax(format!("The request is not valid JSON: {}", error))
    })?;
    read_request(&parsed)
}

/// The same, from a document already parsed.
pub fn read_request(parsed: &Json) -> XacmlResult<Request> {
    let request = match parsed.get("Request") {
        Some(Json::Object(request)) => request,
        _ => {
            return Err(XacmlError::syntax(
                "A JSON Profile request is an object with a \"Request\" \
                 member.",
            ))
        }
    };
    let mut categories = Vec::new();
    // The shorthand names first, then the generic array. Duplicates are left
    // as duplicates: two of one category is a legal request (the Multiple
    // Decision Profile's scheme 2.3), and merging them would change what a
    // policy sees.
    for (name, uri) in SHORTHAND_CATEGORY {
        if let Some(source) = present(request, name) {
            read_categories(Some(uri), source, &mut categories)?;
        }
    }
    if let Some(list) = present(request, "Category") {
        for one in as_list(list) {
            let named = one
                .as_object()
                .and_then(|entry| present(entry, "CategoryId"))
                .is_some();
            if !named {
                return Err(XacmlError::syntax(
                    "An entry in \"Category\" must carry a CategoryId.",
                ));
            }
            read_categories(None, one, &mut categories)?;
        }
    }
    Ok(Request {
        return_policy_id_list: request.get("ReturnPolicyIdList")
            == Some(&Json::Bool(true)),
        combined_decision: request.get("CombinedDecision")
            == Some(&Json::Bool(true)),
        categories,
    })
}

/// The short name where there is one: what the profile's own examples use
/// and what a reader of a response can act on.
fn short_name_of(uri: &str) -> String {
    DataTypes::standard()
        .get(uri)
        .map(|row| row.name().to_string())
        .unwrap_or_else(|| uri.to_string())
}

fn write_obligation(obligation: &ResolvedObligation) -> Json {
    let mut written = Map::new();
    written.insert("Id".into(), obligation.id.clone().into());
    if !obligation.assignments.is_empty() {
        let assignments = obligation
            .assignments
            .iter()
            .map(|one| {
                let mut assignment = Map::new();
                assignment.insert(
                    "AttributeId".into(),
                    one.attribute_id.clone().into(),
                );
                assignment.insert("Value".into(), one.lexical.clone().into());
                assignment.insert(
                    "DataType".into(),
                    short_name_of(&one.type_uri).into(),
                );
                if let Some(category) = &one.category {
                    assignment
                        .insert("Category".into(), category.clone().into());
                }
                if let Some(issuer) = &one.issuer {
                    assignment.insert("Issuer".into(), issuer.clone().into());
                }
                Json::Object(assignment)
            })
            .collect();
        written.insert("AttributeAssignment".into(), Json::Array(assignments));
    }
    Json::Object(written)
}

fn reference_of(one: &PolicyIdentifier) -> Json {
    json!({ "Id": one.id, "Version": one.version })
}

/// Writes the PDP's answer as a JSON Profile response, `{ "Response":
/// [result] }`. The status message is carried only on a status that is not
/// ok — beside a Permit or a Deny it would read as a caveat, and there is
/// none.
pub fn write_response(response: &Response) -> Json {
    let mut result = Map::new();
    result.insert("Decision".into(), response.decision.as_str().into());
    let mut status = Map::new();
    status.insert(
        "StatusCode".into(),
        json!({ "Value": response.status.code.uri() }),
    );
    if response.status.code != StatusCode::Ok {
        if let Some(message) = &response.status.message {
            status.insert("StatusMessage".into(), message.clone().into());
        }
    }
    result.insert("Status".into(), Json::Object(status));
    if !response.obligations.is_empty() {
        result.insert(
            "Obligations".into(),
            response.obligations.iter().map(write_obligation).collect(),
        );
    }
    if !response.advice.is_empty() {
        result.insert(
            "AssociatedAdvice".into(),
            response.advice.iter().map(write_obligation).collect(),
        );
    }
    if !response.policy_identifiers.is_empty() {
        let mut list = Map::new();
        let policies: Vec<Json> = response
            .policy_identifiers
            .iter()
            .filter(|one| !one.is_policy_set)
            .map(reference_of)
            .collect();
        let sets: Vec<Json> = response
            .policy_identifiers
            .iter()
            .filter(|one| one.is_policy_set)
            .map(reference_of)
            .collect();
        if !policies.is_empty() {
            list.insert("PolicyIdReference".into(), Json::Array(policies));
        }
        if !sets.is_empty() {
            list.insert("PolicySetIdReference".into(), Json::Array(sets));
        }
        result.insert("PolicyIdentifierList".into(), Json::Object(list));
    }
    json!({ "Response": [Json::Object(result)] })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Decision;
    use crate::pdp::{EvaluationOptions, Pdp};
    use crate::request::{ResolvedAssignment, Status};
    use crate::value::Value;

    #[test]
    fn integers_and_doubles_are_told_apart_by_their_text() {
        let request = parse_request(
            r#"{"Request":{"Resource":{"Attribute":[
                {"AttributeId":"a","Value":5},
                {"AttributeId":"b","Value":5.0},
                {"AttributeId":"c","Value":[1, 2.5e1, true, "x"]}]}}}"#,
        )
        .unwrap();
        let attributes = &request.categories[0].attributes;
        assert_eq!(request.categories[0].category, category::RESOURCE);
        assert_eq!(attributes[0].values[0].type_uri, types::INTEGER);
        assert_eq!(attributes[0].values[0].lexical, "5");
        assert_eq!(attributes[1].values[0].type_uri, types::DOUBLE);
        assert_eq!(attributes[1].values[0].lexical, "5");
        let bag: Vec<(&str, &str)> = attributes[2]
            .values
            .iter()
            .map(|v| (v.type_uri.as_str(), v.lexical.as_str()))
            .collect();
        assert_eq!(
            bag,
            [
                (types::INTEGER, "1"),
                (types::DOUBLE, "25"),
                (types::BOOLEAN, "true"),
                (types::STRING, "x")
            ]
        );
    }

    #[test]
    fn short_names_shorthand_and_generic_categories() {
        let request = parse_request(
            r#"{"Request":{"ReturnPolicyIdList":true,
              "AccessSubject":[{"Attribute":{"AttributeId":"d",
                 "DataType":"dayTimeDuration","Value":"PT1H",
                 "IncludeInResult":true,"Issuer":"me"}}],
              "Category":[{"CategoryId":"urn:x:c","Id":"one","Content":"<a/>"},
                          {"CategoryId":"urn:x:c"}]}}"#,
        )
        .unwrap();
        assert!(request.return_policy_id_list);
        assert!(!request.combined_decision);
        let order: Vec<&str> = request
            .categories
            .iter()
            .map(|c| c.category.as_str())
            .collect();
        assert_eq!(order, [category::ACCESS_SUBJECT, "urn:x:c", "urn:x:c"]);
        let attribute = &request.categories[0].attributes[0];
        assert_eq!(attribute.values[0].type_uri, types::DAYTIME_DURATION);
        assert!(attribute.include_in_result);
        assert_eq!(attribute.issuer.as_deref(), Some("me"));
        assert_eq!(request.categories[1].id.as_deref(), Some("one"));
        assert!(request.categories[1].has_content);
        assert!(!request.categories[2].has_content);
    }

    #[test]
    fn the_refusals_are_syntax_errors() {
        for body in [
            "not json",
            "[]",
            r#"{"Request":5}"#,
            r#"{"Request":{"Resource":5}}"#,
            r#"{"Request":{"Category":[{"Attribute":[]}]}}"#,
            r#"{"Request":{"Resource":{"Attribute":{"Value":1}}}}"#,
            r#"{"Request":{"Resource":{"Attribute":
                {"AttributeId":"a","DataType":"nope","Value":1}}}}"#,
            r#"{"Request":{"Resource":{"Attribute":
                {"AttributeId":"a","Value":{"x":1}}}}}"#,
            r#"{"Request":{"Resource":{"Attribute":{"AttributeId":"a"}}}}"#,
        ] {
            let error = parse_request(body).unwrap_err();
            assert_eq!(error.status, StatusCode::SyntaxError, "{}", body);
        }
    }

    #[test]
    fn a_declared_type_takes_a_null_value_as_empty() {
        let request = parse_request(
            r#"{"Request":{"Action":{"Attribute":
                {"AttributeId":"a","DataType":"string"}}}}"#,
        )
        .unwrap();
        assert_eq!(request.categories[0].attributes[0].values[0].lexical, "");
    }

    #[test]
    fn writes_the_response() {
        let response = Response {
            decision: Decision::Permit,
            status: Status {
                code: StatusCode::Ok,
                message: Some("ignored on a Permit".into()),
            },
            obligations: vec![ResolvedObligation {
                id: "urn:o".into(),
                assignments: vec![ResolvedAssignment {
                    attribute_id: "urn:a".into(),
                    category: None,
                    issuer: Some("i".into()),
                    type_uri: types::INTEGER.into(),
                    value: Value::String("7".into()),
                    lexical: "7".into(),
                }],
            }],
            advice: vec![ResolvedObligation {
                id: "urn:v".into(),
                assignments: vec![],
            }],
            policy_identifiers: vec![
                PolicyIdentifier {
                    is_policy_set: true,
                    id: "s".into(),
                    version: "1.0".into(),
                },
                PolicyIdentifier {
                    is_policy_set: false,
                    id: "p".into(),
                    version: "2".into(),
                },
            ],
        };
        let written = write_response(&response);
        assert_eq!(
            written,
            json!({"Response":[{
              "Decision":"Permit",
              "Status":{"StatusCode":
                {"Value":"urn:oasis:names:tc:xacml:1.0:status:ok"}},
              "Obligations":[{"Id":"urn:o","AttributeAssignment":[
                {"AttributeId":"urn:a","Value":"7","DataType":"integer",
                 "Issuer":"i"}]}],
              "AssociatedAdvice":[{"Id":"urn:v"}],
              "PolicyIdentifierList":{
                "PolicyIdReference":[{"Id":"p","Version":"2"}],
                "PolicySetIdReference":[{"Id":"s","Version":"1.0"}]}}]})
        );
    }

    #[test]
    fn an_indeterminate_carries_its_message_end_to_end() {
        let policy = crate::xml::parse_policy(
            r#"<Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
                 PolicyId="p" Version="1.0"
                 RuleCombiningAlgId="urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-overrides">
               <Target/>
               <Rule RuleId="r" Effect="Permit">
                 <Condition>
                   <Apply FunctionId="urn:oasis:names:tc:xacml:1.0:function:integer-equal">
                     <Apply FunctionId="urn:oasis:names:tc:xacml:1.0:function:integer-one-and-only">
                       <AttributeDesignator MustBePresent="false"
                         Category="urn:oasis:names:tc:xacml:3.0:attribute-category:resource"
                         AttributeId="n"
                         DataType="http://www.w3.org/2001/XMLSchema#integer"/>
                     </Apply>
                     <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#integer">5</AttributeValue>
                   </Apply>
                 </Condition>
               </Rule>
             </Policy>"#,
        )
        .unwrap();
        let pdp = Pdp::new();
        let options = EvaluationOptions::default();
        let permit = parse_request(
            r#"{"Request":{"Resource":{"Attribute":
                {"AttributeId":"n","Value":5}}}}"#,
        )
        .unwrap();
        assert_eq!(
            pdp.evaluate(&policy, &permit, &options).decision,
            Decision::Permit
        );
        // 5.0 is a double, so the integer designator finds an empty bag.
        let double = parse_request(
            r#"{"Request":{"Resource":{"Attribute":
                {"AttributeId":"n","Value":5.0}}}}"#,
        )
        .unwrap();
        let written = write_response(&pdp.evaluate(&policy, &double, &options));
        assert_eq!(written["Response"][0]["Decision"], "Indeterminate");
        assert!(written["Response"][0]["Status"]["StatusMessage"].is_string());
    }
}
