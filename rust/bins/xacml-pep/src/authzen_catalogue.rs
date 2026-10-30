// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE AUTHZEN ATTRIBUTE CATALOGUE'S GRAMMAR, PORTED (#1179). A port of
//! `authzen/authzen_catalogue.ts`, which argues every rule; this file
//! restates only what a reader of the Rust needs.
//!
//! The edge PDP maps an AuthZEN request onto XACML by the realm's
//! catalogue, PULLED from `GET /xacml/pep/authzen-catalogue` beside the
//! policies. Every pulled row is read again through [`parse`] — never taken
//! on trust because the service sent it, as `sync.rs` re-validates every
//! pulled policy with this container's own engine — so a row that maps a
//! property onto a RESERVED identifier cannot reach a request here even if
//! it reached the wire.
//!
//! **The reserved identifiers, and why.** A request-supplied attribute
//! suppresses the PIP (the engine asks the resolver only for a designator
//! the request carried no VALUE for), so a row onto `urn:sts:xacml:role`
//! would let a caller name the roles of the subject it asks about. Refused:
//! all of `urn:sts:xacml:` (case-insensitively), subject-id, resource-id,
//! action-id and the three current-time attributes, `context.application`,
//! the context members the token-exchange binding reads (#1181), and a bare
//! LDAP-shaped name in any subject category.
//!
//! `xacml-pep/authzen_cases.json` holds this file and the service's to the
//! same cases (`tests/authzen_map.js` S, and this file's own test).

use regex::Regex;
use serde_json::{Map, Value};
use sts_xacml::model::{attribute, category, types};

/// One row of the catalogue, as [`parse`] answers it: the category and the
/// datatype as URIs, the defaults written in.
#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    pub object: String,
    pub property: String,
    pub attribute_id: String,
    pub category: String,
    pub data_type: String,
    pub multiplicity: String,
    pub description: String,
}

/// Why a value is not a row: the code the service gives the same value,
/// and the sentence.
#[derive(Debug, Clone, PartialEq)]
pub struct Problem {
    pub code: &'static str,
    pub problem: String,
}

/// The four objects an AuthZEN request carries properties on.
pub const OBJECTS: [&str; 4] = ["subject", "resource", "action", "context"];

/// The context members the adapter reads itself.
pub const RESERVED_CONTEXT: [&str; 1] = ["application"];

/// The context members the service's OAuth token-exchange binding reads by
/// fixed rules (#1181), which a row may add to but never override: refused
/// at the write there, so refused here too, and a pulled catalogue never
/// carries one. This container does not implement the binding; a request
/// naming one of them here is an undeclared property.
pub const BINDING_CONTEXT: [&str; 11] = [
    "client_id",
    "acr",
    "amr",
    "auth_time",
    "cnf",
    "jti",
    "subject_token_type",
    "actor_token_type",
    "subject_token",
    "act",
    "may_act",
];

/// This service's own namespace: everything in it is reserved.
const RESERVED_PREFIX: &str = "urn:sts:xacml:";

/// The members a row may carry.
const KNOWN: [&str; 7] = [
    "object",
    "property",
    "attributeId",
    "category",
    "dataType",
    "multiplicity",
    "description",
];

/// The deepest a dotted path may go, and the longest identifier.
const MAX_DEPTH: usize = 6;
const MAX_ID_LENGTH: usize = 512;

/// The categories a row may name, by short name, in the service's order.
pub const CATEGORY_NAMES: [(&str, &str); 8] = [
    ("access-subject", category::ACCESS_SUBJECT),
    ("recipient-subject", category::RECIPIENT_SUBJECT),
    ("intermediary-subject", category::INTERMEDIARY_SUBJECT),
    ("codebase", category::CODEBASE),
    ("requesting-machine", category::REQUESTING_MACHINE),
    ("resource", category::RESOURCE),
    ("action", category::ACTION),
    ("environment", category::ENVIRONMENT),
];

/// The datatypes a row may name, by short name: every one the engine has
/// but `xpathExpression`, which a JSON value cannot carry.
pub const TYPE_NAMES: [(&str, &str); 16] = [
    ("string", types::STRING),
    ("boolean", types::BOOLEAN),
    ("integer", types::INTEGER),
    ("double", types::DOUBLE),
    ("time", types::TIME),
    ("date", types::DATE),
    ("dateTime", types::DATETIME),
    ("dayTimeDuration", types::DAYTIME_DURATION),
    ("yearMonthDuration", types::YEARMONTH_DURATION),
    ("anyURI", types::ANYURI),
    ("hexBinary", types::HEXBINARY),
    ("base64Binary", types::BASE64BINARY),
    ("rfc822Name", types::RFC822NAME),
    ("x500Name", types::X500NAME),
    ("dnsName", types::DNSNAME),
    ("ipAddress", types::IPADDRESS),
];

/// The subject categories, where a bare name is a directory attribute.
const SUBJECT_CATEGORIES: [&str; 5] = [
    category::ACCESS_SUBJECT,
    category::RECIPIENT_SUBJECT,
    category::INTERMEDIARY_SUBJECT,
    category::CODEBASE,
    category::REQUESTING_MACHINE,
];

/// XACML's own identifiers the adapter fills, or the PDP supplies.
const RESERVED_IDS: [&str; 6] = [
    attribute::SUBJECT_ID,
    attribute::RESOURCE_ID,
    attribute::ACTION_ID,
    attribute::CURRENT_TIME,
    attribute::CURRENT_DATE,
    attribute::CURRENT_DATETIME,
];

/// JavaScript's `String.prototype.trim()`: Unicode white space and the
/// byte-order mark, which Rust's `trim()` leaves.
pub fn js_trim(text: &str) -> &str {
    text.trim_matches(|c: char| c.is_whitespace() || c == '\u{feff}')
}

/// JavaScript's `/\s/`: white space or the byte-order mark.
pub fn js_space(c: char) -> bool {
    c.is_whitespace() || c == '\u{feff}'
}

/// A string's JavaScript `length`, in UTF-16 code units.
pub fn js_length(text: &str) -> usize {
    text.encode_utf16().count()
}

/// JavaScript's `slice(0, n)`, in UTF-16 code units, never cutting a
/// character in two (where JavaScript would leave half a surrogate pair).
pub fn js_slice(text: &str, n: usize) -> String {
    let mut units = 0;
    let mut out = String::new();
    for c in text.chars() {
        units += c.len_utf16();
        if units > n {
            break;
        }
        out.push(c);
    }
    out
}

/// `Object.keys()` order: the canonical array-index names first, ascending,
/// then every other member in insertion order — so a request with two
/// problems is refused for the same one in both places.
pub fn js_keys(object: &Map<String, Value>) -> Vec<&String> {
    let index = |key: &str| -> Option<u64> {
        if key.is_empty()
            || (key.len() > 1 && key.starts_with('0'))
            || !key.bytes().all(|b| b.is_ascii_digit())
        {
            return None;
        }
        key.parse::<u64>().ok().filter(|n| *n < 4_294_967_295)
    };
    let mut numbered: Vec<(u64, &String)> = object
        .keys()
        .filter_map(|key| index(key).map(|n| (n, key)))
        .collect();
    numbered.sort_by_key(|(n, _)| *n);
    let mut out: Vec<&String> = numbered.into_iter().map(|(_, k)| k).collect();
    out.extend(object.keys().filter(|key| index(key).is_none()));
    out
}

fn segment_pattern() -> Option<Regex> {
    Regex::new(r"^[A-Za-z0-9_$@:-]{1,64}$").ok()
}

fn bare_name(id: &str) -> bool {
    Regex::new(r"^[A-Za-z][A-Za-z0-9;-]*$")
        .map(|re| re.is_match(id))
        .unwrap_or(false)
}

/// Why an attribute identifier is reserved in a category, or `None`.
pub fn reserved_problem(
    attribute_id: &str,
    category_uri: &str,
) -> Option<String> {
    let id = attribute_id;
    if id.to_lowercase().starts_with(RESERVED_PREFIX) {
        return Some(format!(
            "\"{}\" is in this service's own namespace ({}), where every \
             trusted fact lives — the roles, the realm, the protocol, the \
             caller and its application. A request-supplied attribute \
             suppresses the PIP, so a row mapping onto one would let a \
             caller forge it",
            id, RESERVED_PREFIX
        ));
    }
    if RESERVED_IDS.contains(&id) {
        return Some(format!(
            "\"{}\" is filled by the adapter from subject.id, action.name or \
             resource.id, or supplied by the PDP, and from nothing else",
            id
        ));
    }
    if SUBJECT_CATEGORIES.contains(&category_uri) && bare_name(id) {
        return Some(format!(
            "\"{}\" in a subject category is read as the subject's directory \
             attribute, and for a subject this realm resolves the directory \
             is authoritative. Send the property under an identifier of your \
             own, such as urn:example:{}",
            id, id
        ));
    }
    None
}

fn refused(problem: String) -> Result<Row, Problem> {
    Err(Problem {
        code: "STS-AUTHZEN-0010",
        problem,
    })
}

/// Reads one value as a catalogue row, or says why it is not one: a JSON
/// object, or the text of one, exactly as `authzen_catalogue.ts`'s
/// `parse()` reads it.
pub fn parse(value: &Value) -> Result<Row, Problem> {
    let parsed;
    let given = match value {
        Value::String(text) => match serde_json::from_str::<Value>(text) {
            Ok(v) => {
                parsed = v;
                &parsed
            }
            Err(error) => {
                return refused(format!(
                    "a catalogue row is a JSON object, and this is not JSON: \
                     {}",
                    error
                ))
            }
        },
        other => other,
    };
    let Some(given) = given.as_object() else {
        return refused(
            "a catalogue row is a JSON object with object, property, \
             attributeId, and optionally category, dataType and multiplicity"
                .to_string(),
        );
    };
    let unknown: Vec<String> = js_keys(given)
        .into_iter()
        .filter(|key| !KNOWN.contains(&key.as_str()))
        .map(|key| format!("\"{}\"", js_slice(key, 40)))
        .collect();
    if !unknown.is_empty() {
        return refused(format!(
            "a catalogue row has no member {}; it takes {}",
            unknown.join(", "),
            KNOWN.join(", ")
        ));
    }
    let text = |key: &str| -> String {
        given
            .get(key)
            .and_then(Value::as_str)
            .map(|s| js_trim(s).to_string())
            .unwrap_or_default()
    };
    let object = text("object");
    if !OBJECTS.contains(&object.as_str()) {
        return refused(format!(
            "object must be one of {}",
            OBJECTS.join(", ")
        ));
    }
    let property = text("property");
    let segments: Vec<&str> = if property.is_empty() {
        Vec::new()
    } else {
        property.split('.').collect()
    };
    let segment_ok = segment_pattern();
    let well_formed = segment_ok
        .as_ref()
        .is_some_and(|re| segments.iter().all(|one| re.is_match(one)));
    if segments.is_empty() || segments.len() > MAX_DEPTH || !well_formed {
        return refused(format!(
            "property must be a member name, or a dotted path of at most {} \
             names, each of letters, digits, _ $ @ : or -",
            MAX_DEPTH
        ));
    }
    if object == "context" && RESERVED_CONTEXT.contains(&segments[0]) {
        return Err(Problem {
            code: "STS-AUTHZEN-0011",
            problem: format!(
                "context.{} is read by the adapter to choose the caller's \
                 application, and the application a policy sees is the \
                 trusted urn:sts:xacml:authzen:application",
                segments[0]
            ),
        });
    }
    if object == "context" && BINDING_CONTEXT.contains(&segments[0]) {
        return Err(Problem {
            code: "STS-AUTHZEN-0011",
            problem: format!(
                "context.{} is read by the OAuth token-exchange binding's \
                 fixed conversion rules, which a catalogue row may add to \
                 but never override",
                segments[0]
            ),
        });
    }
    let attribute_id = text("attributeId");
    if attribute_id.is_empty()
        || js_length(&attribute_id) > MAX_ID_LENGTH
        || attribute_id.chars().any(js_space)
    {
        return refused(format!(
            "attributeId must be a non-empty identifier with no white space, \
             at most {} characters",
            MAX_ID_LENGTH
        ));
    }
    let category_text = text("category");
    let mut category_uri = OBJECTS
        .iter()
        .position(|o| *o == object)
        .map(|i| {
            [
                category::ACCESS_SUBJECT,
                category::RESOURCE,
                category::ACTION,
                category::ENVIRONMENT,
            ][i]
        })
        .unwrap_or(category::ENVIRONMENT)
        .to_string();
    if !category_text.is_empty() {
        let found = CATEGORY_NAMES
            .iter()
            .find(|(name, uri)| *name == category_text || *uri == category_text)
            .map(|(_, uri)| uri.to_string());
        match found {
            Some(uri) => category_uri = uri,
            None => {
                let names: Vec<&str> =
                    CATEGORY_NAMES.iter().map(|(n, _)| *n).collect();
                return refused(format!(
                    "category must be one of {}, or its XACML URI",
                    names.join(", ")
                ));
            }
        }
    }
    let type_text = {
        let t = text("dataType");
        if t.is_empty() {
            "string".to_string()
        } else {
            t
        }
    };
    let Some(data_type) = TYPE_NAMES
        .iter()
        .find(|(name, uri)| *name == type_text || *uri == type_text)
        .map(|(_, uri)| uri.to_string())
    else {
        let names: Vec<&str> = TYPE_NAMES.iter().map(|(n, _)| *n).collect();
        return refused(format!(
            "dataType must be one of {}, or its URI",
            names.join(", ")
        ));
    };
    let multiplicity = {
        let m = text("multiplicity");
        if m.is_empty() {
            "single".to_string()
        } else {
            m
        }
    };
    if multiplicity != "single" && multiplicity != "bag" {
        return refused("multiplicity must be single or bag".to_string());
    }
    if let Some(problem) = reserved_problem(&attribute_id, &category_uri) {
        let code = if SUBJECT_CATEGORIES.contains(&category_uri.as_str())
            && bare_name(&attribute_id)
        {
            "STS-AUTHZEN-0012"
        } else {
            "STS-AUTHZEN-0011"
        };
        return Err(Problem { code, problem });
    }
    Ok(Row {
        object,
        property: segments.join("."),
        attribute_id,
        category: category_uri,
        data_type,
        multiplicity,
        description: js_slice(&text("description"), 500),
    })
}

/// Every value read: a value that is not a row, and a second row for one
/// object and property, left out and named — as `rowsOf()` does.
pub fn rows_of(values: &[Value]) -> (Vec<Row>, Vec<String>) {
    let mut rows: Vec<Row> = Vec::new();
    let mut problems = Vec::new();
    for value in values {
        match parse(value) {
            Err(problem) => problems.push(problem.problem),
            Ok(row) => {
                if rows.iter().any(|r| {
                    r.object == row.object && r.property == row.property
                }) {
                    problems.push(format!(
                        "{}.{} has more than one row; the first is used",
                        row.object, row.property
                    ));
                } else {
                    rows.push(row);
                }
            }
        }
    }
    (rows, problems)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The shared table's catalogue half: the same values, the same codes,
    /// as `tests/authzen_map.js` S holds the service to.
    #[test]
    fn agrees_with_the_shared_catalogue_cases() {
        let table = crate::authzen_map::tests::shared_cases();
        let cases = table["catalogue"].as_array().unwrap();
        assert!(cases.len() >= 15);
        for case in cases {
            let code = match parse(&case["value"]) {
                Ok(_) => String::new(),
                Err(problem) => problem.code.to_string(),
            };
            assert_eq!(
                code,
                case["code"].as_str().unwrap(),
                "{}",
                case["what"]
            );
        }
    }

    #[test]
    fn a_row_takes_its_defaults_as_uris() {
        let row = parse(&json!({ "object": "resource",
            "property": "classification", "attributeId": "urn:example:c" }))
        .unwrap();
        assert_eq!(row.category, category::RESOURCE);
        assert_eq!(row.data_type, types::STRING);
        assert_eq!(row.multiplicity, "single");
        let named = parse(&json!(
            "{\"object\":\"context\",\"property\":\"when\",\
             \"attributeId\":\"urn:example:when\",\"category\":\
             \"environment\",\"dataType\":\"dateTime\",\
             \"multiplicity\":\"bag\"}"
        ))
        .unwrap();
        assert_eq!(named.data_type, types::DATETIME);
        assert_eq!(named.category, category::ENVIRONMENT);
    }

    #[test]
    fn a_second_row_and_a_non_row_are_left_out_and_named() {
        let (rows, problems) = rows_of(&[
            json!({ "object": "resource", "property": "x",
                    "attributeId": "u:1" }),
            json!({ "object": "resource", "property": "x",
                    "attributeId": "u:2" }),
            json!("garbage"),
        ]);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].attribute_id, "u:1");
        assert_eq!(problems.len(), 2);
    }

    #[test]
    fn keys_are_read_in_javascript_order() {
        let value = json!({ "b": 1, "10": 1, "a": 1, "2": 1, "01": 1 });
        let keys: Vec<&str> = js_keys(value.as_object().unwrap())
            .into_iter()
            .map(String::as_str)
            .collect();
        assert_eq!(keys, ["2", "10", "b", "a", "01"]);
    }
}
