// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! `common/pki_merge.js`: the three-way merge of a `pki:<scope>` row
//! another writer stored underneath this one (#46), so that a Rust node
//! and a Node node writing the same certificate authority lose nothing.
//!
//! * a tier (`root`, `intermediate`) and each Issuing CA is FIRST WRITER
//!   WINS: a conflict keeps theirs and says it was lost;
//! * the revocation lists, the issued register and the stored objects are
//!   UNIONS — a revocation is never lost, a released hold is;
//! * a CRL number never goes back, and two increments both count;
//! * a slot's certificate one writer replaced is kept in the register as a
//!   DISPLACED record, so its serial still answers OCSP and its CRL entry
//!   still reaches a validator;
//! * and a row may never publish a certificate its own CRL calls revoked
//!   (`liveAgain()`, which the keystore applies to every row it seals).
//!
//! Every value is the JSON Node wrote: `same()` is `canonical()`'s
//! key-sorted comparison, and an absent member is JavaScript's
//! `undefined`, distinct from `null`.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde_json::{Map, Value as Json};

use crate::x509::time;

/// The tiers a row holds one of.
const TIER_MEMBERS: [&str; 2] = ["root", "intermediate"];
/// The tiers a row holds a map of.
const TIER_MAP_MEMBERS: [&str; 1] = ["issuing"];
/// The one use case whose displaced certificates an `x5u` may still name.
const PUBLISHED_USE_CASE: &str = "jose";
/// `PUBLISHED_PER_SLOT`.
pub const PUBLISHED_PER_SLOT: usize = 8;

/// `canonical()`: JSON with every object's keys sorted, `(undefined)`
/// for an absent value.
#[tracing::instrument(level = "debug", skip_all)]
pub fn canonical(value: Option<&Json>) -> String {
    fn sorted(v: &Json) -> Json {
        match v {
            Json::Object(map) => {
                let keys: BTreeMap<&String, Json> =
                    map.iter().map(|(k, v)| (k, sorted(v))).collect();
                Json::Object(
                    keys.into_iter().map(|(k, v)| (k.clone(), v)).collect(),
                )
            }
            Json::Array(list) => Json::Array(list.iter().map(sorted).collect()),
            other => other.clone(),
        }
    }
    match value {
        None => "(undefined)".to_string(),
        Some(v) => sorted(v).to_string(),
    }
}

fn same(a: Option<&Json>, b: Option<&Json>) -> bool {
    canonical(a) == canonical(b)
}

/// `normalSerial()`: lower-case hex, leading zeros dropped, `0` for none.
#[tracing::instrument(level = "debug", skip_all)]
pub fn normal_serial(text: &str) -> String {
    let hex: String = text
        .to_ascii_lowercase()
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect();
    let trimmed = hex.trim_start_matches('0');
    if trimmed.is_empty() {
        "0".to_string()
    } else {
        trimmed.to_string()
    }
}

fn str_of<'a>(v: &'a Json, key: &str) -> &'a str {
    v.get(key).and_then(Json::as_str).unwrap_or("")
}

fn ms_of(text: &str) -> Option<i64> {
    DateTime::parse_from_rfc3339(text)
        .ok()
        .map(|t| t.with_timezone(&Utc).timestamp_millis())
}

fn pick<'a>(
    base: Option<&'a Json>,
    mine: Option<&'a Json>,
    theirs: Option<&'a Json>,
) -> (Option<&'a Json>, bool) {
    if same(mine, base) {
        return (theirs, false);
    }
    if same(theirs, base) || same(mine, theirs) {
        return (mine, false);
    }
    (theirs, true)
}

fn keys_of(objects: &[Option<&Json>]) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for object in objects.iter().flatten() {
        if let Some(map) = object.as_object() {
            for key in map.keys() {
                if seen.insert(key.clone()) {
                    out.push(key.clone());
                }
            }
        }
    }
    out
}

/// `displacedRecord()`: a slot's replaced certificate as a register row.
#[tracing::instrument(level = "debug", skip_all)]
pub fn displaced_record(slot: &str, record: &Json, now_ms: i64) -> Json {
    let use_case = match str_of(record, "useCase") {
        "" => slot.split(':').next().unwrap_or("").to_string(),
        one => one.to_string(),
    };
    let created = record
        .get("createdAt")
        .and_then(Json::as_f64)
        .filter(|n| *n != 0.0)
        .map_or(now_ms, |n| n as i64);
    let issued_at = DateTime::from_timestamp_millis(created)
        .map(|t| time::iso(&t))
        .unwrap_or_default();
    let mut out = Map::new();
    out.insert("serialHex".into(), record["serialHex"].clone());
    out.insert("subject".into(), Json::from(str_of(record, "subject")));
    out.insert("notAfter".into(), Json::from(str_of(record, "notAfter")));
    out.insert("identifier".into(), Json::from(slot));
    out.insert("subjectKind".into(), Json::from("displaced"));
    out.insert("purpose".into(), Json::from(format!("displaced:{}", slot)));
    out.insert("useCase".into(), Json::from(use_case.clone()));
    out.insert("issuedAt".into(), Json::from(issued_at));
    let pem = str_of(record, "certificatePem");
    let thumb = str_of(record, "thumbprint");
    if use_case == PUBLISHED_USE_CASE && !pem.is_empty() && !thumb.is_empty() {
        out.insert("thumbprint".into(), Json::from(thumb.to_lowercase()));
        out.insert("certificatePem".into(), Json::from(pem));
        out.insert(
            "chainPem".into(),
            record
                .get("chainPem")
                .cloned()
                .unwrap_or_else(|| Json::Array(Vec::new())),
        );
        let own = match str_of(record, "slot") {
            "" => slot.split(':').skip(1).collect::<Vec<_>>().join(":"),
            one => one.to_string(),
        };
        out.insert("slot".into(), Json::from(own));
    }
    Json::Object(out)
}

/// `trimPublished()`: no more than eight certificates per slot keep the
/// document an `x5u` names; the rest keep their serial only.
#[tracing::instrument(level = "debug", skip_all)]
pub fn trim_published(register: Vec<Json>) -> Vec<Json> {
    let mut order: Vec<(usize, String, String)> = register
        .iter()
        .enumerate()
        .filter(|(_, one)| !str_of(one, "certificatePem").is_empty())
        .map(|(i, one)| {
            (
                i,
                str_of(one, "issuedAt").to_string(),
                str_of(one, "identifier").to_string(),
            )
        })
        .collect();
    order.sort_by(|a, b| b.1.cmp(&a.1));
    let mut kept: BTreeMap<String, usize> = BTreeMap::new();
    let mut strip = BTreeSet::new();
    for (i, _, slot) in order {
        let n = kept.entry(slot).or_insert(0);
        *n += 1;
        if *n > PUBLISHED_PER_SLOT {
            strip.insert(i);
        }
    }
    register
        .into_iter()
        .enumerate()
        .map(|(i, mut one)| {
            if strip.contains(&i) {
                if let Some(map) = one.as_object_mut() {
                    for k in
                        ["thumbprint", "certificatePem", "chainPem", "slot"]
                    {
                        map.remove(k);
                    }
                }
            }
            one
        })
        .collect()
}

fn merge_keyed(
    base: Option<&Json>,
    mine: Option<&Json>,
    theirs: Option<&Json>,
    on_conflict: &mut dyn FnMut(&str, Option<&Json>),
) -> Map<String, Json> {
    let mut out = Map::new();
    for key in keys_of(&[theirs, mine, base]) {
        let b = base.and_then(|o| o.get(&key));
        let m = mine.and_then(|o| o.get(&key));
        let t = theirs.and_then(|o| o.get(&key));
        let (value, conflict) = pick(b, m, t);
        if conflict {
            on_conflict(&key, m);
        }
        if let Some(v) = value {
            out.insert(key, v.clone());
        }
    }
    out
}

fn by_member(list: Option<&Json>, member: &str, serial: bool) -> Json {
    let mut out = Map::new();
    for one in list.and_then(Json::as_array).into_iter().flatten() {
        let key = match one.get(member) {
            Some(Json::String(s)) if serial && !s.is_empty() => {
                normal_serial(s)
            }
            Some(Json::String(s)) if !serial => s.clone(),
            Some(Json::Number(n)) if !serial => n.to_string(),
            _ => continue,
        };
        out.insert(key, one.clone());
    }
    Json::Object(out)
}

fn merge_objects(
    base: Option<&Json>,
    mine: Option<&Json>,
    theirs: Option<&Json>,
) -> Json {
    let (b, m, t) = (
        by_member(base, "id", false),
        by_member(mine, "id", false),
        by_member(theirs, "id", false),
    );
    let merged = merge_keyed(Some(&b), Some(&m), Some(&t), &mut |_, _| {});
    Json::Array(
        keys_of(&[Some(&t), Some(&m)])
            .into_iter()
            .filter_map(|id| merged.get(&id).cloned())
            .collect(),
    )
}

fn merge_issued(
    mine: Option<&Json>,
    theirs: Option<&Json>,
    extra: &[Json],
    now_ms: i64,
) -> Json {
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    let mut out: Vec<Json> = Vec::new();
    let empty = Vec::new();
    let lists = [
        theirs.and_then(Json::as_array).unwrap_or(&empty),
        mine.and_then(Json::as_array).unwrap_or(&empty),
        &extra.to_vec(),
    ];
    for list in lists {
        for one in list {
            let serial = str_of(one, "serialHex");
            if serial.is_empty() {
                continue;
            }
            let key =
                format!("{}/{}", normal_serial(serial), str_of(one, "useCase"));
            if let Some(&i) = seen.get(&key) {
                if !str_of(one, "certificatePem").is_empty()
                    && str_of(&out[i], "certificatePem").is_empty()
                {
                    out[i] = one.clone();
                }
                continue;
            }
            let after = str_of(one, "notAfter");
            if !after.is_empty() && ms_of(after).is_some_and(|t| t <= now_ms) {
                continue;
            }
            seen.insert(key, out.len());
            out.push(one.clone());
        }
    }
    Json::Array(trim_published(out))
}

fn merge_revoked_list(
    base: Option<&Json>,
    mine: Option<&Json>,
    theirs: Option<&Json>,
) -> Vec<Json> {
    let (b, m, t) = (
        by_member(base, "serialHex", true),
        by_member(mine, "serialHex", true),
        by_member(theirs, "serialHex", true),
    );
    let mut out = Vec::new();
    for serial in keys_of(&[Some(&t), Some(&m), Some(&b)]) {
        let in_base = b.get(&serial);
        let in_mine = m.get(&serial);
        let in_theirs = t.get(&serial);
        let hold =
            in_base.is_some_and(|x| str_of(x, "reason") == "certificateHold");
        // A RELEASED HOLD stays released: one side dropped it, the other
        // left it as it was.
        if hold
            && in_mine.is_none()
            && (in_theirs.is_none() || same(in_theirs, in_base))
        {
            continue;
        }
        if hold && in_theirs.is_none() && same(in_mine, in_base) {
            continue;
        }
        let mut candidates: Vec<&Json> = [in_theirs, in_mine, in_base]
            .into_iter()
            .flatten()
            .collect();
        if candidates.is_empty() {
            continue;
        }
        // The EARLIEST moment wins: a validator may act on the first one
        // it was told about.
        candidates.sort_by_key(|x| ms_of(str_of(x, "revokedAt")).unwrap_or(0));
        let chosen = match (in_theirs, in_mine) {
            (Some(t), Some(m)) if !same(Some(t), Some(m)) => candidates[0],
            _ => in_theirs.or(in_mine).or(in_base).unwrap_or(candidates[0]),
        };
        out.push(chosen.clone());
    }
    out
}

fn merge_revoked(
    base: Option<&Json>,
    mine: Option<&Json>,
    theirs: Option<&Json>,
) -> Json {
    let mut out = Map::new();
    for ca in keys_of(&[theirs, mine, base]) {
        let get = |o: Option<&Json>| o.and_then(|o| o.get(&ca)).cloned();
        let (b, m, t) = (get(base), get(mine), get(theirs));
        let list = merge_revoked_list(b.as_ref(), m.as_ref(), t.as_ref());
        if !list.is_empty() || m.is_some() || t.is_some() {
            out.insert(ca, Json::Array(list));
        }
    }
    Json::Object(out)
}

fn number(v: Option<&Json>) -> f64 {
    v.and_then(Json::as_f64).unwrap_or(0.0)
}

fn int_json(n: f64) -> Json {
    if n.fract() == 0.0 && n.abs() < 9.0e15 {
        Json::from(n as i64)
    } else {
        Json::from(n)
    }
}

fn merge_crl_numbers(
    base: Option<&Json>,
    mine: Option<&Json>,
    theirs: Option<&Json>,
) -> Json {
    let mut out = Map::new();
    for ca in keys_of(&[theirs, mine, base]) {
        let was = number(base.and_then(|o| o.get(&ca)));
        let m = number(mine.and_then(|o| o.get(&ca)));
        let t = number(theirs.and_then(|o| o.get(&ca)));
        let n = if m > was && t > was {
            t + (m - was)
        } else {
            m.max(t).max(was)
        };
        out.insert(ca, int_json(n));
    }
    Json::Object(out)
}

fn merge_count(
    base: Option<&Json>,
    mine: Option<&Json>,
    theirs: Option<&Json>,
) -> Option<Json> {
    if same(mine, base) {
        return theirs.cloned();
    }
    if same(theirs, base) {
        return mine.cloned();
    }
    let (was, m, t) = (number(base), number(mine), number(theirs));
    Some(int_json(if m < was || t < was {
        m.min(t)
    } else {
        t + (m - was)
    }))
}

fn live_tier_serials(row: &Json) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut note = |tier: &Json| {
        let s = str_of(tier, "serialHex");
        if !s.is_empty() {
            out.insert(normal_serial(s));
        }
    };
    for member in TIER_MEMBERS {
        if let Some(t) = row.get(member) {
            note(t);
        }
    }
    for member in TIER_MAP_MEMBERS {
        if let Some(map) = row.get(member).and_then(Json::as_object) {
            map.values().for_each(&mut note);
        }
    }
    out
}

/// One revocation `live_again()` dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dropped {
    pub ca: String,
    pub serial_hex: String,
    pub reason: String,
}

/// `liveAgain()` (`dropRevocationsOfLiveTiers`): a row may not publish a
/// certificate its own CRL calls revoked. Answers what was dropped.
#[tracing::instrument(level = "debug", skip_all)]
pub fn live_again(row: &mut Json) -> Vec<Dropped> {
    let live = live_tier_serials(row);
    let mut dropped = Vec::new();
    if let Some(lists) = row.get_mut("revoked").and_then(Json::as_object_mut) {
        for (ca, list) in lists.iter_mut() {
            let Some(items) = list.as_array() else {
                continue;
            };
            let kept: Vec<Json> = items
                .iter()
                .filter(|one| {
                    let s = str_of(one, "serialHex");
                    if !s.is_empty() && live.contains(&normal_serial(s)) {
                        dropped.push(Dropped {
                            ca: ca.clone(),
                            serial_hex: s.to_string(),
                            reason: str_of(one, "reason").to_string(),
                        });
                        false
                    } else {
                        true
                    }
                })
                .cloned()
                .collect();
            *list = Json::Array(kept);
        }
    }
    dropped
}

/// `orphanedSlots()`: slot certificates whose signer is no longer their
/// use case's Issuing CA.
#[tracing::instrument(level = "debug", skip_all)]
pub fn orphaned_slots(row: &Json) -> Vec<String> {
    let Some(certs) = row.get("certs").and_then(Json::as_object) else {
        return Vec::new();
    };
    certs
        .iter()
        .filter(|(_, record)| {
            if record
                .get("pinnedSigner")
                .and_then(|p| p.get("operatorCertificate"))
                .is_some_and(|v| !v.is_null() && v != &Json::Bool(false))
            {
                return false;
            }
            let ca = row
                .get("issuing")
                .and_then(|i| i.get(str_of(record, "useCase")));
            let signer = record
                .get("chainPem")
                .and_then(Json::as_array)
                .and_then(|c| c.first())
                .and_then(Json::as_str)
                .unwrap_or("");
            match ca.map(|c| str_of(c, "certificatePem")) {
                Some(pem) if !pem.is_empty() && !signer.is_empty() => {
                    signer != pem
                }
                _ => false,
            }
        })
        .map(|(k, _)| k.clone())
        .collect()
}

/// What `merge()` answers.
#[derive(Debug, Clone)]
pub struct Merged {
    pub row: Json,
    /// The members (and `certs.<slot>`, `issuing.<id>`) where theirs won.
    pub lost: Vec<String>,
    pub displaced: usize,
    pub published: Vec<Dropped>,
    pub orphaned: Vec<String>,
}

/// `merge(base, mine, theirs)`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn merge(
    base: Option<&Json>,
    mine: &Json,
    theirs: Option<&Json>,
    now_ms: i64,
) -> Merged {
    let empty = Json::Object(Map::new());
    let b = base.unwrap_or(&empty);
    let t = theirs.unwrap_or(&empty);
    let m = mine;
    let mut lost = Vec::new();
    let mut displaced: Vec<Json> = Vec::new();
    let mut row = Map::new();
    for member in keys_of(&[Some(t), Some(m), Some(b)]) {
        let (bm, mm, tm) = (b.get(&member), m.get(&member), t.get(&member));
        match member.as_str() {
            "tiers" | "issuedKeyPairs" => {}
            "revoked" => {
                row.insert(member, merge_revoked(bm, mm, tm));
            }
            "crlNumbers" => {
                row.insert(member, merge_crl_numbers(bm, mm, tm));
            }
            "objects" => {
                row.insert(member, merge_objects(bm, mm, tm));
            }
            "issuedCount" => {
                if let Some(count) = merge_count(bm, mm, tm) {
                    row.insert(member, count);
                }
            }
            "certs" => {
                let certs = merge_keyed(bm, mm, tm, &mut |slot, was| {
                    lost.push(format!("certs.{}", slot));
                    if let Some(was) = was {
                        if !str_of(was, "serialHex").is_empty() {
                            displaced.push(displaced_record(slot, was, now_ms));
                        }
                    }
                });
                if mm.is_some() || tm.is_some() {
                    row.insert(member, Json::Object(certs));
                }
            }
            one if TIER_MAP_MEMBERS.contains(&one) => {
                let name = one.to_string();
                let merged = merge_keyed(bm, mm, tm, &mut |key, _| {
                    lost.push(format!("{}.{}", name, key));
                });
                if mm.is_some() || tm.is_some() {
                    row.insert(member, Json::Object(merged));
                }
            }
            one => {
                let (value, conflict) = pick(bm, mm, tm);
                if conflict && TIER_MEMBERS.contains(&one) {
                    lost.push(one.to_string());
                }
                if let Some(v) = value {
                    row.insert(member, v.clone());
                }
            }
        }
    }
    let (mi, ti) = (m.get("issuedKeyPairs"), t.get("issuedKeyPairs"));
    if mi.is_some() || ti.is_some() || !displaced.is_empty() {
        row.insert(
            "issuedKeyPairs".into(),
            merge_issued(mi, ti, &displaced, now_ms),
        );
    }
    let mut row = Json::Object(row);
    let published = live_again(&mut row);
    let orphaned = orphaned_slots(&row);
    Merged {
        row,
        lost,
        displaced: displaced.len(),
        published,
        orphaned,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)] // tests

    use serde_json::json;

    use super::*;

    #[test]
    fn revocations_are_a_union_and_the_first_tier_wins() {
        let base = json!({ "intermediate": { "serialHex": "01" },
                           "revoked": {}, "crlNumbers": { "jose": 1 } });
        let mine = json!({ "intermediate": { "serialHex": "02" },
            "revoked": { "jose": [{ "serialHex": "aa",
                "revokedAt": "2026-01-01T00:00:00.000Z" }] },
            "crlNumbers": { "jose": 2 } });
        let theirs = json!({ "intermediate": { "serialHex": "03" },
            "revoked": { "jose": [{ "serialHex": "bb",
                "revokedAt": "2026-01-01T00:00:00.000Z" }] },
            "crlNumbers": { "jose": 3 } });
        let out = merge(Some(&base), &mine, Some(&theirs), 0);
        assert_eq!(out.row["intermediate"]["serialHex"], "03");
        assert_eq!(out.lost, vec!["intermediate".to_string()]);
        assert_eq!(out.row["revoked"]["jose"].as_array().unwrap().len(), 2);
        assert_eq!(out.row["crlNumbers"]["jose"], 4);
    }

    #[test]
    fn a_live_tier_is_never_on_its_own_list() {
        let mut row = json!({ "intermediate": { "serialHex": "0abc" },
            "revoked": { "root": [{ "serialHex": "abc" }] } });
        let dropped = live_again(&mut row);
        assert_eq!(dropped.len(), 1);
        assert!(row["revoked"]["root"].as_array().unwrap().is_empty());
    }
}
