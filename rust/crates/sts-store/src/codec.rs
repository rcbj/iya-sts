// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! A directory entry as a database row (`persistence/directory_codec.js`).
//!
//! The DN stays readable, and so do the lookup columns every query reads a
//! VALUE through: `name_keys` (the `uid` values, lower-cased), `mail_keys`,
//! `uuid_keys` (`entryUUID` and its aliases), `class_keys`, `value_keys`
//! (`attr:<name>` of the attributes looked up by exact value) and
//! `attr_names`.
//!
//! **Where nothing durable seals, nothing is sealed** (development, a key
//! that dies with the process): the attributes go in as the JSON object
//! they are, and each lookup column holds `<kind>\n<value>` in the clear.
//! This is that form. The sealed form — the attributes one blob under the
//! realm's `directory` data key, each lookup a keyed digest — arrives with
//! the keystore; until then a sealed row does not open here and is reported
//! (`STS-STORE-0072`), never taken for an absent one.

use indexmap::IndexMap;
use serde_json::{json, Map, Value as Json};

/// The attributes `value_keys` indexes, compared exactly as written.
pub const VALUE_INDEXED: &[&str] = &[
    "uid",
    "didsubject",
    "spiffesubject",
    "x509subject",
    "federationlink",
];

/// The lookup columns of one entry.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Index {
    pub name_keys: Vec<String>,
    pub mail_keys: Vec<String>,
    pub uuid_keys: Vec<String>,
    pub class_keys: Vec<String>,
    pub value_keys: Vec<String>,
    pub attr_names: Vec<String>,
}

fn values_of(attrs: &IndexMap<String, Vec<String>>, name: &str) -> Vec<String> {
    attrs
        .iter()
        .filter(|(k, _)| k.to_lowercase() == name)
        .flat_map(|(_, v)| v.iter().cloned())
        .collect()
}

fn unique(list: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for one in list {
        if !out.contains(&one) {
            out.push(one);
        }
    }
    out
}

fn lookup(kind: &str, value: &str) -> String {
    format!("{}\n{}", kind, value)
}

fn lowered(list: Vec<String>) -> Vec<String> {
    list.into_iter().map(|v| v.to_lowercase()).collect()
}

/// `indexOf()`, unsealed.
pub fn index_of(attrs: &IndexMap<String, Vec<String>>) -> Index {
    let keyed = |kind: &str, list: Vec<String>| {
        unique(list).iter().map(|v| lookup(kind, v)).collect()
    };
    let mut value_keys = Vec::new();
    for name in VALUE_INDEXED {
        for one in unique(values_of(attrs, name)) {
            value_keys.push(lookup(&format!("attr:{}", name), &one));
        }
    }
    let mut uuids = values_of(attrs, "entryuuid");
    uuids.extend(values_of(attrs, "stsentryuuidalias"));
    Index {
        name_keys: keyed("name", lowered(values_of(attrs, "uid"))),
        mail_keys: keyed("mail", lowered(values_of(attrs, "mail"))),
        uuid_keys: keyed("uuid", lowered(uuids)),
        class_keys: keyed("class", lowered(values_of(attrs, "objectclass"))),
        value_keys,
        attr_names: unique(attrs.keys().map(|k| k.to_lowercase()).collect()),
    }
}

/// The `attrs` column for an entry's attributes, unsealed.
pub fn seal_attributes(attrs: &IndexMap<String, Vec<String>>) -> Json {
    json!(attrs)
}

/// The attributes of an `attrs` column, or `None` for a sealed blob this
/// process cannot open.
pub fn open_attributes(stored: &Json) -> Option<IndexMap<String, Vec<String>>> {
    match stored {
        Json::Null => Some(IndexMap::new()),
        Json::Object(map) => Some(attributes_of(map)),
        _ => None,
    }
}

fn attributes_of(map: &Map<String, Json>) -> IndexMap<String, Vec<String>> {
    let text = |v: &Json| match v {
        Json::String(s) => s.clone(),
        other => other.to_string(),
    };
    map.iter()
        .filter(|(_, v)| !v.is_null())
        .map(|(k, v)| {
            let values = match v {
                Json::Array(a) => a.iter().map(text).collect(),
                other => vec![text(other)],
            };
            (k.clone(), values)
        })
        .collect()
}
