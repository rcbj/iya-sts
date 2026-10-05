// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Two nodes writing one directory entry, and what survives
//! (`persistence/directory_merge.js`, #46 section 3).
//!
//! **A three-way merge, because the flush already holds all three sides**:
//! BASE (the shadow: the entry as this process last wrote or applied it),
//! MINE (the live entry the change produced) and THEIRS (the row in the
//! store, read under `SELECT … FOR UPDATE` in the flush's own transaction).
//!
//! An attribute only one side changed takes that side. One both changed is
//! merged by VALUE where it is a list — theirs, minus what mine removed,
//! plus what mine added — and otherwise MINE wins, because a password or a
//! registration document that came out as the union of two writes would be
//! two credentials or no document. Which attribute is a list is [`SINGLE`],
//! [`MULTI`] and one rule: anything else is a list if any side holds more
//! than one value.
//!
//! **`entryUUID` decides whether two writes are one entry**: a different
//! entry at the same DN makes the first committed win (`STS-STORE-0052`); a
//! row gone from the store that this process had seen was deleted elsewhere
//! and the delete wins (`STS-STORE-0053`), unless mine is a re-creation; two
//! independent creations keep theirs plus what mine holds besides.
//!
//! A hot path: once per attribute of every row a flush writes, so nothing
//! here logs.

use indexmap::IndexMap;
use serde_json::{json, Value as Json};

use crate::model::StoredEntry;

/// Always whole-valued: when both sides changed one, mine wins.
pub const SINGLE: &[&str] = &[
    "userpassword",
    "pwdhistory",
    "pwdchangedtime",
    "ststotpcredential",
    "stsbackupcodes",
    "stsactivationtoken",
    "stsactivationexpires",
    "appregistrationjson",
    "stsapppassword",
    "stsidaverification",
    "stsselfissuedsubject",
    "stsdevicesecrethash",
    "stsdevicesession",
    "stscibausercode",
    "stsdevicecompliancechange",
    "stsdevicestatuschange",
    "stsdeviceenrolment",
    "stsdeviceriskchange",
    "stsoidfedkind",
    "stsoidfedentityid",
    "stsoidfeddata",
    "stsoidfedkeys",
];

/// Always merged by value: lists this service appends to itself.
pub const MULTI: &[&str] = &[
    "member",
    "uniquemember",
    "memberof",
    "objectclass",
    "description",
    "oauthconsent",
    "stswebauthncredential",
    "x509subject",
    "didsubject",
    "spiffesubject",
    "authnmethod",
    "federationattribute",
    "federationissuer",
    "federationrelationship",
    "federationlink",
    "stsdevicekey",
    "stsdevicekeythumbprint",
    "stsdevicecredentialid",
    "stsoidfedevent",
];

type Attributes = IndexMap<String, Vec<String>>;

/// What the merge decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Write mine as it is: nothing of theirs is lost by doing so.
    Mine,
    /// Write the merged entry, which differs from mine.
    Merged,
    /// The store's entry wins whole: write nothing, adopt it here.
    Theirs,
    /// Another node deleted it: write nothing, remove it here.
    Deleted,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Mine => "mine",
            Outcome::Merged => "merged",
            Outcome::Theirs => "theirs",
            Outcome::Deleted => "deleted",
        }
    }
}

/// An outcome and the entry it names (none for `Deleted`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Merge {
    pub outcome: Outcome,
    pub entry: Option<StoredEntry>,
}

fn uuid_of(entry: &StoredEntry) -> String {
    entry
        .attributes
        .get("entryuuid")
        .and_then(|v| v.first())
        .map(|v| v.to_lowercase())
        .unwrap_or_default()
}

fn count_of(values: Option<&Vec<String>>) -> usize {
    values.map_or(0, Vec::len)
}

/// `x || y || null` over two optional strings, `''` being falsy.
fn either(a: &Option<String>, b: &Option<String>) -> Option<String> {
    a.as_ref()
        .filter(|s| !s.is_empty())
        .or(b.as_ref().filter(|s| !s.is_empty()))
        .cloned()
}

/// The later `modifiedAt`, mine on a tie (generalized time sorts as text).
fn later_modified(mine: &StoredEntry, theirs: &StoredEntry) -> Option<String> {
    let m = mine.modified_at.as_deref().unwrap_or("");
    let t = theirs.modified_at.as_deref().unwrap_or("");
    let pick = if m >= t {
        &mine.modified_at
    } else {
        &theirs.modified_at
    };
    pick.as_ref().filter(|s| !s.is_empty()).cloned()
}

/// Theirs, minus what mine removed from base, plus what mine added to it —
/// in theirs' order with mine's additions after, so two nodes merging the
/// same pair produce the same list. `None` when nothing is left.
pub fn merge_values(
    base: Option<&[String]>,
    mine: Option<&[String]>,
    theirs: Option<&[String]>,
) -> Option<Vec<String>> {
    let b = base.unwrap_or_default();
    let m = mine.unwrap_or_default();
    let removed: Vec<&String> = b.iter().filter(|v| !m.contains(v)).collect();
    let mut out: Vec<String> = theirs
        .unwrap_or_default()
        .iter()
        .filter(|v| !removed.contains(v))
        .cloned()
        .collect();
    for v in m.iter().filter(|v| !b.contains(v)) {
        if !out.contains(v) {
            out.push(v.clone());
        }
    }
    (!out.is_empty()).then_some(out)
}

fn is_list(name: &str, sides: [Option<&Vec<String>>; 3]) -> bool {
    MULTI.contains(&name) || sides.iter().any(|s| count_of(*s) > 1)
}

fn merge_attributes(
    b: &Attributes,
    m: &Attributes,
    t: &Attributes,
) -> Attributes {
    let mut names: Vec<&String> = Vec::new();
    for side in [m, t, b] {
        for name in side.keys() {
            if !names.contains(&name) {
                names.push(name);
            }
        }
    }
    let mut out = Attributes::new();
    for name in names {
        let (bv, mv, tv) = (b.get(name), m.get(name), t.get(name));
        let value = if mv == bv {
            tv.cloned()
        } else if tv == bv || mv == tv {
            mv.cloned()
        } else if name == "modifytimestamp" {
            let first =
                |v: Option<&Vec<String>>| v.and_then(|x| x.first()).cloned();
            if first(mv).unwrap_or_default() > first(tv).unwrap_or_default() {
                mv.cloned()
            } else {
                tv.cloned()
            }
        } else if name == "createtimestamp" || name == "entryuuid" {
            tv.or(mv).cloned()
        } else if SINGLE.contains(&name.as_str()) {
            mv.cloned()
        } else if is_list(name, [bv, mv, tv]) {
            merge_values(
                bv.map(Vec::as_slice),
                mv.map(Vec::as_slice),
                tv.map(Vec::as_slice),
            )
        } else {
            mv.cloned()
        };
        if let Some(v) = value {
            out.insert(name.clone(), v);
        }
    }
    out
}

/// Two independent creations of one entry: theirs, committed first, plus
/// what mine holds that theirs does not. `Theirs` when mine adds nothing.
fn merge_creations(mine: &StoredEntry, theirs: &StoredEntry) -> Merge {
    let (m, t) = (&mine.attributes, &theirs.attributes);
    let mut out = t.clone();
    for (name, mv) in m {
        if matches!(
            name.as_str(),
            "entryuuid" | "createtimestamp" | "modifytimestamp"
        ) {
            continue;
        }
        match t.get(name) {
            None => {
                out.insert(name.clone(), mv.clone());
            }
            Some(tv) if is_list(name, [None, Some(mv), Some(tv)]) => {
                match merge_values(Some(&[]), Some(mv), Some(tv)) {
                    Some(v) => {
                        out.insert(name.clone(), v);
                    }
                    // `out[name] = undefined`: the key stays and
                    // JSON.stringify drops it.
                    None => {
                        out.shift_remove(name);
                    }
                }
            }
            Some(_) => {}
        }
    }
    if out == *t {
        return Merge {
            outcome: Outcome::Theirs,
            entry: Some(theirs.clone()),
        };
    }
    Merge {
        outcome: Outcome::Merged,
        entry: Some(StoredEntry {
            dn: theirs.dn.clone(),
            attributes: out,
            created_at: either(&theirs.created_at, &mine.created_at),
            modified_at: later_modified(mine, theirs),
            origin: either(&theirs.origin, &mine.origin),
        }),
    }
}

/// The one question: what survives this process's write of an entry meeting
/// the row in the store. `base` is `None` when this process believed the DN
/// held nothing, `theirs` when the store holds nothing.
pub fn merge_entry(
    base: Option<&StoredEntry>,
    mine: Option<&StoredEntry>,
    theirs: Option<&StoredEntry>,
) -> Merge {
    let Some(mine) = mine else {
        return Merge {
            outcome: Outcome::Deleted,
            entry: None,
        };
    };
    let keep_mine = || Merge {
        outcome: Outcome::Mine,
        entry: Some(mine.clone()),
    };
    let mu = uuid_of(mine);
    let Some(theirs) = theirs else {
        let Some(base) = base else {
            return keep_mine();
        };
        let bu = uuid_of(base);
        if !mu.is_empty() && !bu.is_empty() && mu != bu {
            // Deleted and added again HERE, inside one flush.
            return keep_mine();
        }
        return Merge {
            outcome: Outcome::Deleted,
            entry: None,
        };
    };
    let tu = uuid_of(theirs);
    let empty = Attributes::new();
    let base_attributes = match base {
        None => {
            if !mu.is_empty() && !tu.is_empty() && mu != tu {
                return merge_creations(mine, theirs);
            }
            &empty
        }
        Some(base) => {
            let bu = uuid_of(base);
            if !bu.is_empty() && !tu.is_empty() && tu != bu {
                return Merge {
                    outcome: Outcome::Theirs,
                    entry: Some(theirs.clone()),
                };
            }
            if !bu.is_empty() && !mu.is_empty() && mu != bu {
                return keep_mine();
            }
            &base.attributes
        }
    };
    let attributes =
        merge_attributes(base_attributes, &mine.attributes, &theirs.attributes);
    if attributes == mine.attributes {
        return keep_mine();
    }
    Merge {
        outcome: Outcome::Merged,
        entry: Some(StoredEntry {
            dn: mine.dn.clone(),
            attributes,
            created_at: either(&theirs.created_at, &mine.created_at),
            modified_at: later_modified(mine, theirs),
            origin: either(&theirs.origin, &mine.origin),
        }),
    }
}

/// An entry as a live one is serialised: `dn, attributes, createdAt,
/// modifiedAt`, then `origin` only when there is one. The shadow compares
/// these strings.
pub fn entry_json(entry: &StoredEntry) -> Json {
    let mut out = json!({
        "dn": entry.dn,
        "attributes": entry.attributes,
        "createdAt": entry.created_at,
        "modifiedAt": entry.modified_at,
    });
    if let Some(origin) = entry.origin.as_ref().filter(|o| !o.is_empty()) {
        out["origin"] = json!(origin);
    }
    out
}

/// `canonicalJson()`: an entry read out of the store in the key order a live
/// entry has, `modifiedAt` falling back to `createdAt`.
pub fn canonical_json(entry: &StoredEntry) -> String {
    let created = either(&entry.created_at, &None);
    let modified = either(&entry.modified_at, &created);
    let mut out = json!({
        "dn": entry.dn,
        "attributes": entry.attributes,
        "createdAt": created,
        "modifiedAt": modified,
    });
    if let Some(origin) = entry.origin.as_ref().filter(|o| !o.is_empty()) {
        out["origin"] = json!(origin);
    }
    out.to_string()
}

/// An entry back from its JSON (`dn`, `attributes`, `createdAt`,
/// `modifiedAt`, `origin`), a scalar attribute value read as one value.
pub fn entry_of_json(v: &Json) -> Option<StoredEntry> {
    let text = |k: &str| v.get(k).and_then(Json::as_str).map(str::to_string);
    let mut attributes = Attributes::new();
    if let Some(map) = v.get("attributes").and_then(Json::as_object) {
        for (name, values) in map {
            let list = match values {
                Json::Array(a) => a.iter().map(js_text).collect(),
                Json::Null => continue,
                other => vec![js_text(other)],
            };
            attributes.insert(name.clone(), list);
        }
    }
    Some(StoredEntry {
        dn: text("dn")?,
        attributes,
        origin: text("origin"),
        created_at: text("createdAt"),
        modified_at: text("modifiedAt"),
    })
}

/// `String(v)` for a JSON scalar.
fn js_text(v: &Json) -> String {
    match v {
        Json::String(s) => s.clone(),
        other => other.to_string(),
    }
}
