// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The directory against Node: `directory-node.json`, which
//! `tests/tools/directory-vectors.js` writes by driving `ldap_server.js` in
//! process over the in-memory store. Rust starts from Node's state after
//! the seed (the seed is not this crate's), runs every operation, and must
//! answer each as Node did — the entries a search sent, in order and
//! spelt, a compare's answer, or the refusal's class, result code, sentence
//! and STS code — and change exactly the entries Node changed, attribute
//! order included. Then every entry of the end state is made into each
//! concept, and each person's subject is resolved both ways.
//!
//! Two kinds of value are Node's own clock and randomness: a generalized
//! time this run stamped (compared as "a generalized time"), and a random
//! `entryUUID` (compared through a bijection, so a value carried through a
//! modify or a rename must be the same value, and a subject must name the
//! entry that holds it). The role register's own rewrites (`roles.js`,
//! another slice's) are counted and left out.
//!
//! With `STS_WRITE_VECTORS=1` this writes `directory-rust.json` for
//! `tests/rust_crypto_vectors.js`. The directory is `STS_CRYPTO_VECTORS`,
//! never committed; with it unset this test says so and passes.

#![allow(clippy::unwrap_used, clippy::expect_used)] // a test file

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value as Json};
use sts_directory::directory::{Change, Operation, Request};
use sts_directory::ports::{Clock, DirectorySettings, FixedSettings, UuidSource};
use sts_directory::{Attributes, Directory, DirectoryModel, DomainMap, Entry, EntryExt, FromOptions};

struct TestClock;
impl Clock for TestClock {
    fn generalized_time(&self) -> String {
        "20261114000000Z".to_string()
    }
}

struct CountingUuids(AtomicU64);
impl UuidSource for CountingUuids {
    fn random_uuid(&self) -> String {
        let n = self.0.fetch_add(1, Ordering::SeqCst);
        format!("{:08x}-0000-4000-8000-{:012x}", n, n)
    }
}

struct Settings(Mutex<FixedSettings>);
impl DirectorySettings for Settings {
    fn max_entries(&self) -> i64 {
        self.0.lock().unwrap().max_entries
    }
    fn size_limit(&self) -> i64 {
        self.0.lock().unwrap().size_limit
    }
    fn bootstrap_username(&self) -> String {
        self.0.lock().unwrap().bootstrap_username.clone()
    }
    fn self_writable_attributes(&self) -> Vec<String> {
        Vec::new()
    }
    fn directory_readable_attributes(&self) -> Vec<String> {
        Vec::new()
    }
    fn group_members_readable(&self) -> bool {
        false
    }
    fn security_group(&self) -> String {
        String::new()
    }
}

fn strings(v: &Json) -> Vec<String> {
    v.as_array()
        .map(|a| a.iter().map(|x| x.as_str().unwrap_or("").to_string()).collect())
        .unwrap_or_default()
}

fn entry_of(v: &Json) -> Entry {
    let mut attributes = Attributes::new();
    for (name, values) in v["attributes"].as_object().unwrap() {
        attributes.insert(name.clone(), strings(values));
    }
    Entry {
        dn: v["dn"].as_str().unwrap().to_string(),
        attributes,
        origin: v["origin"].as_str().map(str::to_string),
        created_at: v["createdAt"].as_str().map(str::to_string),
        modified_at: v["modifiedAt"].as_str().map(str::to_string),
    }
}

fn json_of(e: &Entry) -> Json {
    let attributes: serde_json::Map<String, Json> =
        e.attributes.iter().map(|(k, v)| (k.clone(), json!(v))).collect();
    let mut out = json!({ "dn": e.dn, "attributes": attributes });
    for (k, v) in [("origin", &e.origin), ("createdAt", &e.created_at), ("modifiedAt", &e.modified_at)] {
        if let Some(s) = v {
            out[k] = json!(s);
        }
    }
    out
}

fn uuid_v4ish(s: &str) -> bool {
    let b = s.as_bytes();
    s.len() == 36
        && b[8] == b'-'
        && b[13] == b'-'
        && b[18] == b'-'
        && b[23] == b'-'
        && b[14] == b'4'
        && s.chars().all(|c| c == '-' || c.is_ascii_hexdigit())
}

fn generalized(s: &str) -> bool {
    s.len() == 15 && s.ends_with('Z') && s[..14].bytes().all(|b| b.is_ascii_digit())
}

/// Node's random UUIDs and Rust's, paired as they are met.
#[derive(Default)]
struct Pairing {
    node_to_rust: HashMap<String, String>,
    rust_to_node: HashMap<String, String>,
}

impl Pairing {
    fn same_uuid(&mut self, node: &str, rust: &str) -> bool {
        match (self.node_to_rust.get(node), self.rust_to_node.get(rust)) {
            (Some(r), Some(n)) => r == rust && n == node,
            (None, None) => {
                self.node_to_rust.insert(node.to_string(), rust.to_string());
                self.rust_to_node.insert(rust.to_string(), node.to_string());
                true
            }
            _ => false,
        }
    }

    // Two JSON values the same up to the clock and the random UUIDs. The
    // key order of an object is part of the value.
    fn same(&mut self, node: &Json, rust: &Json, key: &str) -> bool {
        match (node, rust) {
            (Json::String(a), Json::String(b)) => {
                if a == b {
                    return true;
                }
                let time_key = matches!(
                    key.to_lowercase().as_str(),
                    "createtimestamp" | "modifytimestamp" | "pwdchangedtime" | "createdat" | "modifiedat"
                );
                if time_key && generalized(a) && generalized(b) {
                    return true;
                }
                let (pa, ua) = a.split_at(a.len().saturating_sub(36));
                let (pb, ub) = b.split_at(b.len().saturating_sub(36));
                pa == pb && uuid_v4ish(ua) && uuid_v4ish(ub) && self.same_uuid(ua, ub)
            }
            (Json::Array(a), Json::Array(b)) => {
                a.len() == b.len() && a.iter().zip(b).all(|(x, y)| self.same(x, y, key))
            }
            (Json::Object(a), Json::Object(b)) => {
                // A search entry's `{ type, values }`: the values are the
                // type's.
                let ty = a.get("type").and_then(Json::as_str).unwrap_or("").to_string();
                a.len() == b.len()
                    && a.iter().zip(b).all(|((ka, va), (kb, vb))| {
                        let inner = if ka == "values" && !ty.is_empty() { ty.as_str() } else { ka.as_str() };
                        ka == kb && self.same(va, vb, inner)
                    })
            }
            // A concept's ISO instant from a stamped time.
            (Json::Null, Json::Null) => true,
            _ => node == rust,
        }
    }

    fn to_rust(&self, node: &str) -> String {
        let (p, u) = node.split_at(node.len().saturating_sub(36));
        match self.node_to_rust.get(u) {
            Some(r) => format!("{p}{r}"),
            None => node.to_string(),
        }
    }
}

fn request_of(op: &str, shape: &Json) -> Request {
    let operation = match op {
        "add" => Operation::Add {
            attributes: shape["attributes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|a| (a["type"].as_str().unwrap().to_string(), strings(&a["values"])))
                .collect(),
        },
        "modify" => Operation::Modify {
            changes: shape["changes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|c| Change {
                    operation: c["operation"].as_str().unwrap().to_string(),
                    attribute: c["modification"]["type"].as_str().unwrap().to_string(),
                    values: strings(&c["modification"]["values"]),
                })
                .collect(),
        },
        "del" => Operation::Delete,
        "modifyDN" => Operation::ModifyDn {
            new_rdn: shape["newRdn"].as_str().unwrap().to_string(),
            new_superior: shape["newSuperior"].as_str().unwrap_or("").to_string(),
            delete_old_rdn: shape["deleteOldRdn"].as_bool().unwrap_or(false),
        },
        "compare" => Operation::Compare {
            attribute: shape["attribute"].as_str().unwrap().to_string(),
            value: shape["value"].as_str().unwrap().to_string(),
        },
        _ => Operation::Search {
            scope: shape["scope"].as_i64().unwrap_or(2),
            filter: shape["filter"].as_str().unwrap().to_string(),
            attributes: strings(&shape["attributes"]),
            size_limit: shape["sizeLimit"].as_i64().unwrap_or(0),
        },
    };
    Request {
        dn: shape["dn"].as_str().unwrap().to_string(),
        bound_dn: shape["boundDn"].as_str().unwrap_or("").to_string(),
        encrypted: shape["channel"].as_str() == Some("ldaps"),
        operation,
    }
}

fn snapshot(d: &Directory) -> Vec<(String, String, Json)> {
    d.realms()
        .iter()
        .flat_map(|t| t.entries.iter().map(|(k, e)| (t.id.clone(), k.clone(), json_of(e))))
        .collect()
}

// The changes an operation made, as the builder lists them: each realm's
// added or altered entries in the store's order after, then the removed.
fn changes(before: &[(String, String, Json)], after: &[(String, String, Json)], realms: &[String]) -> Vec<Json> {
    let mut out = Vec::new();
    for realm in realms {
        let was: HashMap<&str, &Json> =
            before.iter().filter(|(r, _, _)| r == realm).map(|(_, k, e)| (k.as_str(), e)).collect();
        let now: HashMap<&str, &Json> =
            after.iter().filter(|(r, _, _)| r == realm).map(|(_, k, e)| (k.as_str(), e)).collect();
        for (r, k, e) in after.iter().filter(|(r, _, _)| r == realm) {
            match was.get(k.as_str()) {
                Some(old) if *old == e => {}
                old => out.push(json!({ "realm": r, "key": k, "before": old.cloned(), "after": e })),
            }
        }
        for (r, k, e) in before.iter().filter(|(r, _, _)| r == realm) {
            if !now.contains_key(k.as_str()) {
                out.push(json!({ "realm": r, "key": k, "before": e, "after": null }));
            }
        }
    }
    out
}

fn register_change(c: &Json) -> bool {
    c["key"].as_str().is_some_and(|k| k.contains(",ou=roles,"))
}

#[test]
fn the_directory_is_nodes() {
    let Ok(dir) = std::env::var("STS_CRYPTO_VECTORS") else {
        eprintln!("STS_CRYPTO_VECTORS is not set: directory-node.json is not checked");
        return;
    };
    let path = std::path::Path::new(&dir);
    let v: Json = serde_json::from_str(&std::fs::read_to_string(path.join("directory-node.json")).unwrap()).unwrap();
    let mut failures: Vec<String> = Vec::new();
    let mut checked = 0usize;
    let mut check = |ok: bool, what: String| {
        checked += 1;
        if !ok {
            failures.push(what);
        }
    };

    // The spellings the model does not carry.
    let pinned: Vec<String> = sts_directory::model::CREDENTIAL_CLAIM_SPELLINGS.iter().map(|s| s.to_string()).collect();
    check(strings(&v["outsideSpellings"]) == pinned, "the credential claim catalogue's spellings".into());

    let settings = Arc::new(Settings(Mutex::new(FixedSettings {
        max_entries: v["settings"]["maxEntries"].as_i64().unwrap(),
        size_limit: v["settings"]["sizeLimit"].as_i64().unwrap(),
        bootstrap_username: v["settings"]["bootstrapUsername"].as_str().unwrap().to_string(),
        ..FixedSettings::default()
    })));
    let defaults = (settings.max_entries(), settings.size_limit());
    let mut d = Directory::new(v["bases"]["base"].as_str().unwrap())
        .with_settings(settings.clone())
        .with_clock(Arc::new(TestClock), Arc::new(CountingUuids(AtomicU64::new(1))));
    let realm_ids: Vec<String> = v["realms"].as_array().unwrap().iter().map(|r| r["id"].as_str().unwrap().to_string()).collect();
    for r in v["realms"].as_array().unwrap() {
        d.add_realm(r["id"].as_str().unwrap(), r["base"].as_str().unwrap());
    }
    for id in &realm_ids {
        let rows: Vec<Entry> = v["initial"][id].as_array().unwrap().iter().map(|row| entry_of(&row["entry"])).collect();
        d.restore(id, rows);
    }
    let mut pairing = Pairing::default();
    let mut register_changes = 0;
    for (i, op) in v["operations"].as_array().unwrap().iter().enumerate() {
        let name = op["operation"].as_str().unwrap();
        if name == "setting" {
            let mut s = settings.0.lock().unwrap();
            let value = op["value"].as_str().and_then(|x| x.parse::<i64>().ok());
            match op["key"].as_str().unwrap() {
                "ldap.maxEntries" => s.max_entries = value.unwrap_or(defaults.0),
                "ldap.sizeLimit" => s.size_limit = value.unwrap_or(defaults.1),
                _ => {}
            }
            continue;
        }
        let shape = &op["shape"];
        let request = request_of(name, shape);
        let before = snapshot(&d);
        let outcome = d.perform(&request);
        let after = snapshot(&d);
        let label = format!("#{i} {name} {}", request.dn);
        let node = &op["result"];
        let error = outcome.error.as_ref().map(|e| {
            json!({ "name": e.name, "resultCode": e.result_code, "message": e.message,
                    "code": e.code.map(|c| c.as_str()).unwrap_or("") })
        });
        check(error.as_ref().unwrap_or(&Json::Null) == &node["error"], format!("{label}: refusal {} against Node's {}", error.unwrap_or(Json::Null), node["error"]));
        let compared = outcome.compared.map(Json::Bool).unwrap_or(Json::Null);
        check(compared == node["endArg"], format!("{label}: compare {compared} against {}", node["endArg"]));
        let sent: Vec<Json> = outcome
            .entries
            .iter()
            .map(|e| {
                json!({ "objectName": e.object_name,
                        "attributes": e.attributes.iter().map(|(t, v)| json!({ "type": t, "values": v })).collect::<Vec<_>>() })
            })
            .collect();
        let ok = pairing.same(&node["entries"], &Json::Array(sent.clone()), "");
        check(ok, format!("{label}: entries {} against Node's {}", Json::Array(sent), node["entries"]));
        let mine: Vec<Json> = changes(&before, &after, &realm_ids).into_iter().filter(|c| !register_change(c)).collect();
        let theirs: Vec<Json> = op["changes"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|c| {
                let reg = register_change(c);
                if reg {
                    register_changes += 1;
                }
                !reg
            })
            .cloned()
            .collect();
        let ok = pairing.same(&Json::Array(theirs.clone()), &Json::Array(mine.clone()), "");
        check(ok, format!("{label}: changes {} against Node's {}", Json::Array(mine), Json::Array(theirs)));
    }

    // The end state as concepts.
    let model = DirectoryModel::get();
    let map = DomainMap::default();
    let node_concepts: HashMap<(String, String, String), &Json> = v["concepts"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| !c["key"].as_str().unwrap_or("").contains(",ou=roles,"))
        .map(|c| ((c["realm"].as_str().unwrap().into(), c["key"].as_str().unwrap().into(), c["concept"].as_str().unwrap().into()), c))
        .collect();
    let mut made = 0;
    let mut written_concepts = Vec::new();
    let mut written_entries = Vec::new();
    for tree in d.realms() {
        for (key, entry) in &tree.entries {
            if entry.entry_uuid().starts_with("0000") || entry.entry_uuid().chars().nth(14) == Some('4') {
                written_entries.push(json!({ "realm": tree.id, "dn": entry.dn, "attributes": json_of(entry)["attributes"] }));
            }
            // A role entry is the role register's to write (`roles.js`):
            // what it stores is that register's, not this directory's.
            if key.contains(",ou=roles,") {
                continue;
            }
            for concept in model.concepts.iter().filter(|c| c.entry.is_some()) {
                let options = FromOptions {
                    derived: vec![("realm".to_string(), json!(tree.id))],
                    on: vec![("operational".to_string(), &entry.attributes)],
                    ..FromOptions::default()
                };
                let plain = map.from_entry(&concept.name, &entry.attributes, &options).unwrap();
                let secrets = secret_paths(model, &concept.name, "");
                let named = if secrets.is_empty() {
                    plain.clone()
                } else {
                    map.from_entry(&concept.name, &entry.attributes, &FromOptions { secrets: secrets.clone(), ..options.clone() }).unwrap()
                };
                let trivial = plain.as_object().map(|o| o.len() <= 1).unwrap_or(true) && named == plain;
                let theirs = node_concepts.get(&(tree.id.clone(), key.clone(), concept.name.clone()));
                if trivial {
                    check(theirs.is_none(), format!("{}/{key} {}: Node made one", tree.id, concept.name));
                    continue;
                }
                made += 1;
                let mut row = json!({ "realm": tree.id, "key": key, "concept": concept.name, "attributes": json_of(entry)["attributes"], "value": plain });
                if named != plain {
                    row["secrets"] = json!(secrets);
                    row["withSecrets"] = named.clone();
                }
                written_concepts.push(row);
                let Some(theirs) = theirs else {
                    check(false, format!("{}/{key} {}: Node made none", tree.id, concept.name));
                    continue;
                };
                check(pairing.same(&theirs["value"], &plain, ""), format!("{}/{key} {}: {plain} against {}", tree.id, concept.name, theirs["value"]));
                let missing = json!(map.missing(&concept.name, &plain));
                check(missing == theirs["missing"], format!("{}/{key} {}: missing {missing}", tree.id, concept.name));
                if named != plain {
                    check(pairing.same(&theirs["withSecrets"], &named, ""), format!("{}/{key} {}: with secrets {named} against {}", tree.id, concept.name, theirs["withSecrets"]));
                }
                // And the generated type takes it whole, where nothing it
                // requires is missing.
                if concept.name == "Group" && map.missing("Group", &plain).is_empty() {
                    check(DomainMap::typed::<sts_model::domain::Group>(&plain).is_ok(), format!("{}/{key}: a sts_model Group", tree.id));
                }
                if concept.name == "User" && map.missing("User", &plain).is_empty() {
                    check(DomainMap::typed::<sts_model::domain::User>(&plain).is_ok(), format!("{}/{key}: a sts_model User", tree.id));
                }
            }
        }
    }
    check(made == node_concepts.len(), format!("{made} concepts made, Node made {}", node_concepts.len()));

    // The subjects.
    for row in v["subjects"].as_array().unwrap() {
        let realm = row["realm"].as_str().unwrap();
        let name = pairing.to_rust(row["name"].as_str().unwrap());
        let subject = d.subject_for_name(realm, &name);
        let back = if subject.is_empty() { d.name_for_subject(realm, &name) } else { d.name_for_subject(realm, &subject) };
        check(pairing.same(&row["subject"], &json!(subject), ""), format!("{realm} {name}: subject {subject} against {}", row["subject"]));
        check(back == row["back"].as_str().unwrap(), format!("{realm} {name}: name {back} against {}", row["back"]));
    }

    eprintln!("directory: {checked} checks, {} failed; {register_changes} role-register change(s) left to that register", failures.len());
    for f in failures.iter().take(40) {
        eprintln!("  {f}");
    }
    if std::env::var("STS_WRITE_VECTORS").as_deref() == Ok("1") {
        std::fs::write(
            path.join("directory-rust.json"),
            serde_json::to_string(&json!({ "concepts": written_concepts, "entries": written_entries })).unwrap(),
        )
        .unwrap();
    }
    assert!(failures.is_empty(), "{} of {checked} directory checks failed", failures.len());
}

fn secret_paths(model: &DirectoryModel, name: &str, prefix: &str) -> Vec<String> {
    let mut out = Vec::new();
    let Some(concept) = model.concept(name) else { return out };
    for field in &concept.fields {
        let here = if prefix.is_empty() { field.name.clone() } else { format!("{prefix}.{}", field.name) };
        if field.embedded {
            out.extend(secret_paths(model, field.concept.as_deref().unwrap_or(""), &here));
        } else if field.from.as_ref().is_some_and(|f| f.secret) {
            out.push(here);
        }
    }
    out
}
