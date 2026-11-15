// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! A directory entry as the domain model says it means
//! (`common/domain_map.ts`'s `DomainMap.fromEntry()`, `fieldOf()` and
//! `missing()`).
//!
//! The answer is JSON in the concept's field order, exactly the object Node
//! makes, and [`DomainMap::typed`] turns it into the concept's
//! `sts_model::domain` struct (D15). A field marked secret is left out
//! unless the caller names it by path; a value that cannot be what the
//! field says is left out, not guessed at.
//!
//! **ONE-WAY, AS NODE'S IS.** `models/CLAUDE.md`: a register's own codec
//! turns an entry into its record and back, and a concept is one-way. So
//! there is no `toEntry()` here either; the way back is the register's.

use serde::de::DeserializeOwned;
use serde_json::{Map, Number, Value as Json};

use crate::entry::Attributes;
use crate::model::{Concept, ConceptField, DirectoryModel};

/// What an entry alone cannot say (`FromOptions`).
#[derive(Debug, Clone, Default)]
pub struct FromOptions<'a> {
    /// Secret fields asked for by path, `oauth.clientSecrets`.
    pub secrets: Vec<String>,
    /// A derived field's value, by the field's name.
    pub derived: Vec<(String, Json)>,
    /// Another directory object's attributes, by that object's id.
    pub on: Vec<(String, &'a Attributes)>,
}

/// Why a concept could not be made.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DomainMapError {
    #[error("No domain model is named {0}")]
    NoSuchConcept(String),
    #[error("No stored field {field} in {concept}")]
    NoSuchField { concept: String, field: String },
    #[error("{0}")]
    Shape(String),
}

/// Turns directory entries into domain concepts.
#[derive(Debug, Clone, Copy)]
pub struct DomainMap<'m> {
    model: &'m DirectoryModel,
}

impl Default for DomainMap<'static> {
    fn default() -> Self {
        DomainMap {
            model: DirectoryModel::get(),
        }
    }
}

impl<'m> DomainMap<'m> {
    // A HOT PATH: asked by every handler and every rule, so no span.
    /// Over a model other than the built-in one.
    pub fn over(model: &'m DirectoryModel) -> DomainMap<'m> {
        DomainMap { model }
    }

    /// `valuesOf()`: an attribute's values, its name compared in any case,
    /// the first key that matches winning, as `Object.keys().find()` does.
    // A HOT PATH: once per field of every concept made.
    pub fn values_of(attributes: &Attributes, name: &str) -> Vec<String> {
        let wanted = name.to_lowercase();
        attributes
            .iter()
            .find(|(k, _)| k.to_lowercase() == wanted)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    }

    /// `typed()`: one stored value as the field's type, or `None`.
    // A HOT PATH, as `values_of()`.
    pub fn typed_value(kind: &str, value: &str) -> Option<Json> {
        match kind {
            "boolean" => match value.to_lowercase().as_str() {
                "true" => Some(Json::Bool(true)),
                "false" => Some(Json::Bool(false)),
                _ => None,
            },
            "integer" => integer(value),
            "dateTime" => generalized_to_iso(value).map(Json::String),
            _ => Some(Json::String(value.to_string())),
        }
    }

    /// `fromEntry()`: a concept from an entry.
    #[tracing::instrument(level = "debug", skip(self, attributes, options))]
    pub fn from_entry(
        &self,
        name: &str,
        attributes: &Attributes,
        options: &FromOptions<'_>,
    ) -> Result<Json, DomainMapError> {
        let concept = self
            .model
            .concept(name)
            .ok_or_else(|| DomainMapError::NoSuchConcept(name.to_string()))?;
        let mut out = Map::new();
        self.fill(concept, attributes, options, "", &mut out)?;
        Ok(Json::Object(out))
    }

    fn fill(
        &self,
        concept: &Concept,
        attributes: &Attributes,
        options: &FromOptions<'_>,
        path: &str,
        out: &mut Map<String, Json>,
    ) -> Result<(), DomainMapError> {
        for field in &concept.fields {
            let here = if path.is_empty() {
                field.name.clone()
            } else {
                format!("{path}.{}", field.name)
            };
            if field.embedded {
                let inner = field.concept.as_deref().unwrap_or("");
                let nested = self.model.concept(inner).ok_or_else(|| {
                    DomainMapError::NoSuchConcept(inner.into())
                })?;
                let mut map = Map::new();
                self.fill(nested, attributes, options, &here, &mut map)?;
                if !map.is_empty() {
                    out.insert(field.name.clone(), Json::Object(map));
                }
                continue;
            }
            if field.derived.is_some() {
                if let Some((_, v)) =
                    options.derived.iter().find(|(k, _)| *k == field.name)
                {
                    out.insert(field.name.clone(), v.clone());
                }
                continue;
            }
            let Some(from) = &field.from else { continue };
            if from.secret && !options.secrets.contains(&here) {
                continue;
            }
            if let Some(v) = self.read(field, attributes, options) {
                out.insert(field.name.clone(), v);
            }
        }
        Ok(())
    }

    // One stored field read and typed, as both `fromEntry()` and
    // `fieldOf()` read it.
    fn read(
        &self,
        field: &ConceptField,
        attributes: &Attributes,
        options: &FromOptions<'_>,
    ) -> Option<Json> {
        let from = field.from.as_ref()?;
        let empty = Attributes::new();
        let source = match &from.on {
            Some(on) => options
                .on
                .iter()
                .find(|(k, _)| k == on)
                .map(|(_, a)| *a)
                .unwrap_or(&empty),
            None => attributes,
        };
        let values: Vec<Json> = Self::values_of(source, &from.attr)
            .iter()
            .filter_map(|v| Self::typed_value(&field.kind, v))
            .collect();
        if values.is_empty() {
            None
        } else if field.array {
            Some(Json::Array(values))
        } else {
            values.into_iter().next()
        }
    }

    /// `fieldOf()`: one stored field of a concept, a secret one answered
    /// because the caller named it.
    #[tracing::instrument(level = "debug", skip(self, attributes, options))]
    pub fn field_of(
        &self,
        name: &str,
        field: &str,
        attributes: &Attributes,
        options: &FromOptions<'_>,
    ) -> Result<Option<Json>, DomainMapError> {
        let found = self
            .model
            .concept(name)
            .and_then(|c| c.fields.iter().find(|f| f.name == field))
            .filter(|f| f.from.is_some())
            .ok_or_else(|| DomainMapError::NoSuchField {
                concept: name.to_string(),
                field: field.to_string(),
            })?;
        Ok(self.read(found, attributes, options))
    }

    /// `missing()`: the required fields a concept came out without.
    #[tracing::instrument(level = "debug", skip(self, value))]
    pub fn missing(&self, name: &str, value: &Json) -> Vec<String> {
        let Some(concept) = self.model.concept(name) else {
            return Vec::new();
        };
        concept
            .fields
            .iter()
            .filter(|f| !f.optional && value.get(&f.name).is_none())
            .map(|f| f.name.clone())
            .collect()
    }

    /// The concept as its generated `sts_model::domain` type.
    #[tracing::instrument(level = "debug", skip(value))]
    pub fn typed<T: DeserializeOwned>(
        value: &Json,
    ) -> Result<T, DomainMapError> {
        serde_json::from_value(value.clone())
            .map_err(|e| DomainMapError::Shape(e.to_string()))
    }
}

// `/^-?\d+$/` then `Number(value)`: an integer beyond i64 is the double JS
// makes of it.
fn integer(value: &str) -> Option<Json> {
    let digits = value.strip_prefix('-').unwrap_or(value);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if let Ok(n) = value.parse::<i64>() {
        return Some(Json::Number(Number::from(n)));
    }
    value
        .parse::<f64>()
        .ok()
        .and_then(Number::from_f64)
        .map(Json::Number)
}

// `GENERALIZED_TIME`: `YYYYMMDDHHMM[SS][.fff]Z` as ISO 8601, seconds `00`
// when absent.
fn generalized_to_iso(value: &str) -> Option<String> {
    let body = value.strip_suffix('Z')?;
    let (main, fraction) = match body.find('.') {
        Some(at) => (&body[..at], Some(&body[at + 1..])),
        None => (body, None),
    };
    if let Some(f) = fraction {
        if f.is_empty() || !f.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
    }
    if !(main.len() == 12 || main.len() == 14)
        || !main.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let seconds = if main.len() == 14 {
        &main[12..14]
    } else {
        "00"
    };
    Some(format!(
        "{}-{}-{}T{}:{}:{}Z",
        &main[0..4],
        &main[4..6],
        &main[6..8],
        &main[8..10],
        &main[10..12],
        seconds
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_generalized_time_is_iso() {
        assert_eq!(
            generalized_to_iso("20260101120000Z").as_deref(),
            Some("2026-01-01T12:00:00Z")
        );
        assert_eq!(
            generalized_to_iso("202601011200Z").as_deref(),
            Some("2026-01-01T12:00:00Z")
        );
        assert_eq!(
            generalized_to_iso("20260101120000.5Z").as_deref(),
            Some("2026-01-01T12:00:00Z")
        );
        assert!(generalized_to_iso("2026").is_none());
    }
}
