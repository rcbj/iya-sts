// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE SAML MODEL (`saml/saml_model.ts` over `common/xml_model.ts`, #1579):
//! `models/generated/saml.json`, the very file the Node service reads,
//! copied here by `tests/tools/regenerate-model-docs.sh` and read whole.
//!
//! * [`term`] and [`terms`] — a vocabulary's values (a binding, a status, a
//!   NameID format), those a flag marks in the model's order;
//! * [`read`] — a parsed element's attributes the model marks `read`, an
//!   xs:boolean true for "true" or "1" after its whitespace is collapsed;
//! * [`attributes`] and [`children`] — THE WRITERS' ORDER: a start tag's
//!   attributes in the model's order (a fixed value always, an empty one
//!   omitted) and the child elements' text joined in the model's order.
//!
//! A name the model does not declare is a builder out of step with its
//! model. Node throws; here it is a panic-free `debug_assert!` and the part
//! is dropped, because the Rust builders are held to Node's bytes by the
//! vectors, which is where such a mistake shows.

use std::sync::LazyLock;

use serde_json::Value as Json;
use sts_xml::dom::{Document, NodeId};

static MODEL: LazyLock<Json> = LazyLock::new(|| {
    serde_json::from_str(include_str!("generated/saml.json"))
        .unwrap_or(Json::Null)
});

/// The model, as generated.
#[tracing::instrument(level = "debug", skip_all)]
pub fn model() -> &'static Json {
    &MODEL
}

fn vocabulary(id: &str) -> &'static Json {
    &MODEL["vocabularies"][id]
}

fn message(id: &str) -> &'static Json {
    &MODEL["messages"][id]
}

fn list(v: &'static Json) -> &'static [Json] {
    v.as_array().map(Vec::as_slice).unwrap_or(&[])
}

// A hot path of every builder: no span.
/// `SamlModel.term(id, name)`: one term's value, `""` when the model has
/// none by that name.
pub fn term(id: &str, name: &str) -> &'static str {
    list(&vocabulary(id)["terms"])
        .iter()
        .find(|t| t["name"].as_str() == Some(name))
        .and_then(|t| t["value"].as_str())
        .unwrap_or("")
}

/// `SamlModel.terms(id, flag)`: the values of the terms a flag marks (every
/// term with none), in the model's order.
#[tracing::instrument(level = "debug")]
pub fn terms(id: &str, flag: Option<&str>) -> Vec<&'static str> {
    list(&vocabulary(id)["terms"])
        .iter()
        .filter(|t| match flag {
            None => true,
            Some(f) => match &t[f] {
                Json::Bool(b) => *b,
                Json::Null => false,
                Json::String(s) => !s.is_empty(),
                Json::Number(n) => n.as_f64().is_some_and(|x| x != 0.0),
                _ => true,
            },
        })
        .filter_map(|t| t["value"].as_str())
        .collect()
}

/// `XmlModel.booleanTrue()`.
#[tracing::instrument(level = "debug")]
pub fn boolean_true(raw: &str) -> bool {
    let t = raw.trim();
    t == "true" || t == "1"
}

/// One attribute as [`read`] answers it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Read {
    Text(String),
    Bool(bool),
}

impl Read {
    /// The text ('' for a boolean).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn text(&self) -> &str {
        match self {
            Read::Text(t) => t,
            Read::Bool(_) => "",
        }
    }

    /// The boolean (false for text).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn truth(&self) -> bool {
        matches!(self, Read::Bool(true))
    }
}

/// `SamlModel.read(id, element)`: the attributes the model marks `read`,
/// by each one's name in the model, in the model's order.
#[tracing::instrument(level = "debug", skip_all)]
pub fn read(
    id: &str,
    doc: &Document,
    element: Option<NodeId>,
) -> Vec<(String, Read)> {
    list(&message(id)["attributes"])
        .iter()
        .filter(|a| a["read"].as_bool() == Some(true))
        .map(|a| {
            let xml = a["xml"].as_str().unwrap_or("");
            let raw = element
                .and_then(|e| doc.element(e))
                .and_then(|e| e.attr(xml))
                .unwrap_or("")
                .to_string();
            let name = a["name"].as_str().unwrap_or("").to_string();
            if a["reading"].as_str() == Some("boolean") {
                (name, Read::Bool(boolean_true(&raw)))
            } else {
                (name, Read::Text(raw))
            }
        })
        .collect()
}

/// `XmlModel.escape()`: `helpers.xmlEscape()`'s five characters.
// A hot path of every builder: no span.
pub fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// `SamlModel.attributes(id, values)`: ` Name="value"` for each declared
/// attribute this service writes, in the model's order — a fixed value
/// always, nothing for a value that is absent or empty.
// A hot path of every builder: no span.
pub fn attributes(id: &str, values: &[(&str, &str)]) -> String {
    let declared = list(&message(id)["attributes"]);
    debug_assert!(values.iter().all(|(name, _)| declared.iter().any(|a| a
        ["name"]
        .as_str()
        == Some(name)
        && a["written"].as_bool() != Some(false))));
    let mut out = String::new();
    for a in declared {
        if a["written"].as_bool() == Some(false) {
            continue;
        }
        let name = a["name"].as_str().unwrap_or("");
        let value = match &a["fixed"] {
            Json::Null => values
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, v)| (*v).to_string())
                .unwrap_or_default(),
            Json::String(s) => s.clone(),
            other => other.to_string(),
        };
        if value.is_empty() {
            continue;
        }
        out.push_str(&format!(
            " {}=\"{}\"",
            a["xml"].as_str().unwrap_or(""),
            escape(&value)
        ));
    }
    out
}

/// `SamlModel.children(id, parts)`: each child's text joined in the
/// model's order.
// A hot path of every builder: no span.
pub fn children(id: &str, parts: &[(&str, &str)]) -> String {
    let declared = list(&message(id)["elements"]);
    debug_assert!(parts.iter().all(|(name, _)| declared.iter().any(|e| e
        ["name"]
        .as_str()
        == Some(name)
        && e["written"].as_bool() != Some(false))));
    let mut out = String::new();
    for e in declared {
        let name = e["name"].as_str().unwrap_or("");
        if let Some((_, text)) = parts.iter().find(|(n, _)| *n == name) {
            out.push_str(text);
        }
    }
    out
}

/// The namespaces and bindings this crate names, from the model.
pub mod ns {
    use super::term;

    /// `NS_SAMLP`.
    #[tracing::instrument(level = "debug")]
    pub fn samlp() -> &'static str {
        term("saml2.namespace", "protocol")
    }

    /// `NS_SAML`.
    #[tracing::instrument(level = "debug")]
    pub fn saml() -> &'static str {
        term("saml2.namespace", "assertion")
    }

    /// `NS_MD`.
    #[tracing::instrument(level = "debug")]
    pub fn md() -> &'static str {
        term("saml2.namespace", "metadata")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_model_is_loaded() {
        assert!(model()["messages"]["saml2.Assertion"].is_object());
        assert_eq!(ns::saml(), "urn:oasis:names:tc:SAML:2.0:assertion");
        assert_eq!(
            term("saml2.confirmation", "bearer"),
            "urn:oasis:names:tc:SAML:2.0:cm:bearer"
        );
    }
}
