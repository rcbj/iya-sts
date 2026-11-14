// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! A directory entry as a database row (`persistence/directory_codec.js`).
//!
//! **A directory entry is stored SEALED** (#391 phase 6, #222): where a
//! durable key-encryption key is held, an entry's attributes are ONE blob
//! under its realm's `directory` data key, `{ "dn": <dn_key>, "a":
//! <attributes> }` sealed and stored as a JSON string in `attrs`. The DN
//! stays readable, and so does every lookup that is a DN. **The blob names
//! its DN**, and an open refuses a blob whose DN is not its row's, so a blob
//! copied onto another row does not open as that entry.
//!
//! The lookups that read a VALUE are columns this codec computes, each a
//! KEYED DIGEST (`keyedDigest('directory-index', kind + '\n' + value)`), so
//! an exact match is still one indexed probe and nothing in the column says
//! what it matched:
//!
//! * `name_keys`: the `uid` values and the live `stsPseudonym` values
//!   (#644), lower-cased;
//! * `mail_keys`: `mail`, lower-cased;
//! * `uuid_keys`: `entryUUID` and its aliases, lower-cased;
//! * `class_keys`: the GROUP object classes only ([`CLASS_INDEXED`], schema
//!   version 18), lower-cased;
//! * `value_keys`: `attr:<name>` of [`VALUE_INDEXED`], as written, with two
//!   derived keys: `usercertificatesha256` (the SHA-256 of each stored
//!   certificate's DER, #1061) and `grantinggroup` (each value of a granting
//!   attribute trimmed and lower-cased, and a DN also normalised, #1306);
//! * `attr_names`: the attribute NAMES, in the clear;
//! * `dek_keys` (#623): `{ <dek id>: <count> }`, the blob's own data key
//!   once and the key of every value sealed inside the attributes once per
//!   value — what the re-encryption job finds an entry by.
//!
//! **Where nothing durable seals, nothing is sealed** (development, a key
//! that dies with the process): the attributes go in as the JSON object
//! they are, and each lookup holds `<kind>\n<value>` in the clear. Every
//! reader takes either shape, as Node's does, so the two can meet in one
//! table.

use std::sync::Arc;

use indexmap::IndexMap;
use serde_json::{json, Map, Value as Json};

use crate::keystore::DataKeys;

/// The data-key label an entry's blob is sealed under (`LABEL`).
pub const LABEL: &str = "directory";

/// The keyed digests' label (`DIGEST_LABEL`).
pub const DIGEST_LABEL: &str = "directory-index";

/// The attributes `value_keys` indexes, compared exactly as written; the
/// last two are derived keys no entry carries as an attribute.
pub const VALUE_INDEXED: &[&str] = &[
    "uid",
    "didsubject",
    "spiffesubject",
    "x509subject",
    "federationlink",
    "stsdevicekeythumbprint",
    "stsdevicesecrethash",
    "stsdevicecredentialid",
    "owner",
    "usercertificatesha256",
    "grantinggroup",
];

/// The attributes that confer something on the members of the group they
/// name (#358, #607), whose values `grantinggroup` keys.
pub const GRANTING_ATTRIBUTES: &[&str] = &[
    "rolemembergroup",
    "owner",
    "appowner",
    "stsserviceaccountowner",
    "appdelegationsubjectgroup",
    "fedsubjectgroup",
];

/// The names a stored certificate is held under: RFC 4523's type with
/// RFC 4522's `;binary` option, and the bare type.
pub const CERTIFICATE_ATTRIBUTES: &[&str] =
    &["usercertificate;binary", "usercertificate"];

/// The object classes `class_keys` holds: the group classes, and only
/// those (#618 phase 2).
pub const CLASS_INDEXED: &[&str] = &[
    "groupofnames",
    "groupofuniquenames",
    "posixgroup",
    "groupofurls",
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

type Attributes = IndexMap<String, Vec<String>>;

fn values_of(attrs: &Attributes, name: &str) -> Vec<String> {
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

fn lowered(list: Vec<String>) -> Vec<String> {
    list.into_iter().map(|v| v.to_lowercase()).collect()
}

/// `certificateDerOf()`: the DER of one stored `userCertificate` value —
/// base64 of the DER, or a PEM block — or `None` for anything else.
pub fn certificate_der_of(value: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let pem = value.find(BEGIN).and_then(|start| {
        let rest = &value[start + BEGIN.len()..];
        rest.find(END).map(|end| &rest[..end])
    });
    let body: String = pem
        .unwrap_or(value)
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let digits = body.trim_end_matches('=');
    if digits.is_empty()
        || body.len() - digits.len() > 2
        || !digits
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/')
    {
        return None;
    }
    // Node's Buffer.from(…, 'base64') is lenient about padding and trailing
    // bits; so is this engine.
    let der = base64::engine::general_purpose::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::GeneralPurposeConfig::new()
            .with_decode_padding_mode(
                base64::engine::DecodePaddingMode::Indifferent,
            )
            .with_decode_allow_trailing_bits(true),
    )
    .decode(digits)
    .ok()?;
    // A DER certificate is a SEQUENCE; anything else cannot be presented.
    (der.len() > 16 && der[0] == 0x30).then_some(der)
}

/// `certificateDigestsOf()`: the SHA-256 digests, lower-case hex, of the
/// certificates an entry stores, each once.
pub fn certificate_digests_of(attrs: &Attributes) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for name in CERTIFICATE_ATTRIBUTES {
        for one in values_of(attrs, name) {
            if let Some(der) = certificate_der_of(&one) {
                let hex: String = sts_crypto::jws_alg::Hash::Sha256
                    .digest(&der)
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect();
                if !out.contains(&hex) {
                    out.push(hex);
                }
            }
        }
    }
    out
}

/// A value written as a DN (`DN_SHAPED`): an attribute type and `=` at the
/// front.
fn dn_shaped(text: &str) -> bool {
    let Some((head, _)) = text.split_once('=') else {
        return false;
    };
    let mut chars = head.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// `grantingKeysOf()`: the value trimmed and lower-cased, and for a
/// DN-shaped value each RDN trimmed and lower-cased as well.
pub fn granting_keys_of(value: &str) -> Vec<String> {
    let text = value.trim();
    let mut out = Vec::new();
    if !text.is_empty() {
        out.push(text.to_lowercase());
        if dn_shaped(text) {
            let dn = text
                .split(',')
                .map(|p| p.trim().to_lowercase())
                .collect::<Vec<_>>()
                .join(",");
            if !out.contains(&dn) {
                out.push(dn);
            }
        }
    }
    out
}

/// `grantingGroupKeysOf()`: every granting value's keys, each once.
pub fn granting_group_keys_of(attrs: &Attributes) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for name in GRANTING_ATTRIBUTES {
        for one in values_of(attrs, name) {
            for key in granting_keys_of(&one) {
                if !out.contains(&key) {
                    out.push(key);
                }
            }
        }
    }
    out
}

/// The data-key ids of every value sealed inside a text (`SEALED_VALUE`):
/// `$aesgcm$2$<id>$…$…$…` or the same with `aessiv`, found as the global
/// regular expression finds them.
fn sealed_value_ids(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let id_char =
        |c: u8| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-');
    let b64_char =
        |c: u8| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'=');
    let mut out = Vec::new();
    let mut at = 0;
    while let Some(found) = text[at..].find("$aes") {
        let start = at + found;
        at = start + 1;
        let mut i = start + 4;
        if !(text[i..].starts_with("gcm$2$") || text[i..].starts_with("siv$2$"))
        {
            continue;
        }
        i += 6;
        let id_start = i;
        while i < bytes.len() && id_char(bytes[i]) {
            i += 1;
        }
        let id_end = i;
        let mut ok = id_end > id_start;
        for _ in 0..3 {
            if !ok {
                break;
            }
            if i < bytes.len() && bytes[i] == b'$' {
                i += 1;
                while i < bytes.len() && b64_char(bytes[i]) {
                    i += 1;
                }
            } else {
                ok = false;
            }
        }
        if ok {
            out.push(text[id_start..id_end].to_string());
            at = i;
        }
    }
    out
}

/// The entry codec one driver uses, over the process's data keys.
#[derive(Clone)]
pub struct EntryCodec {
    keys: Arc<DataKeys>,
}

impl EntryCodec {
    /// A codec that seals where `keys` are durable.
    pub fn new(keys: Arc<DataKeys>) -> EntryCodec {
        EntryCodec { keys }
    }

    /// A codec that seals nothing: the plaintext form.
    pub fn plain() -> EntryCodec {
        EntryCodec::new(DataKeys::none())
    }

    /// `sealing()`: whether values written now are sealed — a durable
    /// key-encryption key (`persists() && sealed()`). A per-run key would
    /// write digests the next run cannot reproduce.
    pub fn sealing(&self) -> bool {
        self.keys.stores_deks() && self.keys.sealed()
    }

    /// The data keys this codec seals with.
    pub fn keys(&self) -> &Arc<DataKeys> {
        &self.keys
    }

    /// `lookupOf()`: one value's lookup form — its keyed digest under
    /// `kind`, or `<kind>\n<value>` where nothing seals, so one value of two
    /// attributes is two lookups either way.
    pub fn lookup_of(&self, kind: &str, value: &str) -> String {
        let text = format!("{}\n{}", kind, value);
        if self.sealing() {
            if let Some(digest) = self.keys.keyed_digest(DIGEST_LABEL, &text) {
                return digest;
            }
        }
        text
    }

    /// `indexOf()`: the lookup columns of an entry's attributes.
    pub fn index_of(&self, attrs: &Attributes) -> Index {
        let keyed = |kind: &str, list: Vec<String>| -> Vec<String> {
            unique(list)
                .iter()
                .map(|v| self.lookup_of(kind, v))
                .collect()
        };
        let mut value_keys = Vec::new();
        for name in VALUE_INDEXED {
            let values = match *name {
                "usercertificatesha256" => certificate_digests_of(attrs),
                "grantinggroup" => granting_group_keys_of(attrs),
                other => unique(values_of(attrs, other)),
            };
            let kind = format!("attr:{}", name);
            for one in values {
                value_keys.push(self.lookup_of(&kind, &one));
            }
        }
        let mut names = values_of(attrs, "uid");
        names.extend(values_of(attrs, "stspseudonym"));
        let mut uuids = values_of(attrs, "entryuuid");
        uuids.extend(values_of(attrs, "stsentryuuidalias"));
        let classes: Vec<String> = lowered(values_of(attrs, "objectclass"))
            .into_iter()
            .filter(|c| CLASS_INDEXED.contains(&c.as_str()))
            .collect();
        Index {
            name_keys: keyed("name", lowered(names)),
            mail_keys: keyed("mail", lowered(values_of(attrs, "mail"))),
            uuid_keys: keyed("uuid", lowered(uuids)),
            class_keys: keyed("class", classes),
            value_keys,
            attr_names: unique(
                attrs.keys().map(|k| k.to_lowercase()).collect(),
            ),
        }
    }

    /// Makes the realms' `directory` data keys ahead of a flush that will
    /// seal entries of them (`prepareKeys()`), so the key rows are written
    /// before the entries sealed under them. How many realms hold a key.
    pub fn prepare_keys(&self, realms: &[String]) -> usize {
        if !self.sealing() {
            return 0;
        }
        realms
            .iter()
            .filter(|r| self.keys.ensure_dek(LABEL, r))
            .count()
    }

    /// `sealAttributes()`: the `attrs` column — the sealed blob, a JSON
    /// string, or the attributes themselves.
    pub fn seal_attributes(
        &self,
        realm: &str,
        dn_key: &str,
        attrs: &Attributes,
    ) -> Json {
        if !self.sealing() {
            return json!(attrs);
        }
        let blob = json!({ "dn": dn_key, "a": attrs }).to_string();
        match self.keys.seal(&blob, LABEL, realm) {
            Some(sealed) => Json::String(sealed),
            // Node's seal answers null and the row carries null: a write
            // that cannot seal is never written in the clear.
            None => Json::Null,
        }
    }

    /// `openAttributes()`: the attributes of an `attrs` column, or `None`
    /// for a blob that does not open here or names another DN.
    pub fn open_attributes(
        &self,
        dn_key: &str,
        stored: &Json,
    ) -> Option<Attributes> {
        match stored {
            Json::Null => Some(IndexMap::new()),
            Json::Object(map) => Some(attributes_of(map)),
            Json::String(blob) => {
                let text = self.keys.open(blob, LABEL)?;
                let parsed: Json = serde_json::from_str(&text).ok()?;
                let dn = match parsed.get("dn") {
                    Some(Json::String(s)) => s.clone(),
                    Some(other) => other.to_string(),
                    None => "undefined".to_string(),
                };
                if dn != dn_key {
                    return None;
                }
                match parsed.get("a") {
                    Some(Json::Object(map)) => Some(attributes_of(map)),
                    _ => Some(IndexMap::new()),
                }
            }
            _ => None,
        }
    }

    /// `dekKeysOf()`: `{ <dek id>: <values> }` for `dek_keys` — the blob's
    /// own key once, and every value sealed inside the attributes once per
    /// value; `{}` for an entry holding nothing sealed.
    pub fn dek_keys_of(attrs: &Attributes, stored: &Json) -> Json {
        let mut out: Map<String, Json> = Map::new();
        let mut add = |id: &str| {
            if id.is_empty() {
                return;
            }
            let n = out.get(id).and_then(Json::as_u64).unwrap_or(0);
            out.insert(id.to_string(), json!(n + 1));
        };
        if let Json::String(blob) = stored {
            if let Some(id) = sts_crypto::secrets::dek_id_of(blob) {
                add(id);
            }
        }
        for id in sealed_value_ids(&json!(attrs).to_string()) {
            add(&id);
        }
        Json::Object(out)
    }
}

fn attributes_of(map: &Map<String, Json>) -> Attributes {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sealed_value_is_found_as_the_regular_expression_finds_it() {
        let text = "[\"$aesgcm$2$k1$aa$bb$cc\",\"$aessiv$2$k.2$$$x\",\
                    \"$aesgcm$3$no$a$b$c\",\"$aesgcm$2$$a$b$c\",\
                    \"$aesgcm$2$k3$a$b\"]";
        assert_eq!(sealed_value_ids(text), vec!["k1", "k.2"]);
    }

    #[test]
    fn granting_keys_normalise_a_dn() {
        assert_eq!(
            granting_keys_of("  CN=Admins, OU=Groups "),
            vec!["cn=admins, ou=groups", "cn=admins,ou=groups"]
        );
        assert_eq!(granting_keys_of("Admins"), vec!["admins"]);
        assert!(granting_keys_of("  ").is_empty());
    }
}
