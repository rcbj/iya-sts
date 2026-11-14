// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The LDAP wire layer against Node: `ldap-wire-node.json`, which
//! `tests/tools/ldap-wire-vectors.js` writes by feeding every PDU of its
//! corpus to a real node-ldapjs server front (`STS_ONLY=ldap-wire`).
//!
//! * every request corpus entry (hand-written PDUs, framing cases, every
//!   truncation of four PDUs, seeded byte mutations of a third of the
//!   rest): the same events in the same order — the request handed to the
//!   handlers, decoded to the same structure and re-encoded to the same
//!   bytes (or the same refusal to re-encode), the same answer the
//!   library writes itself, the connection destroyed — and the same bytes
//!   left pending. Where Node HANGS, Rust must report `Stalled`;
//! * DN parsing, printing, comparing; the service's DN helpers; filter
//!   strings and filter BER (tree, text, BER, refusal sentence); both
//!   escapers; every response the service sends; the error classes.
//!
//! With `STS_WRITE_VECTORS=1` the second test writes `ldap-wire-rust.json`
//! — a corpus Rust built and the events its front made of it, responses,
//! filters and DNs Rust wrote — which `tests/rust_crypto_vectors.js` holds
//! to node-ldapjs. The directory is `STS_CRYPTO_VECTORS`, never committed;
//! unset, these tests say so and pass.

#![allow(clippy::unwrap_used)] // a test file

use serde_json::{json, Map, Value as Json};
use std::path::PathBuf;
use sts_ldap::attribute::Attribute;
use sts_ldap::ber::Reader;
use sts_ldap::control::Control;
use sts_ldap::dn::{Dn, RdnValue};
use sts_ldap::filter::{escape_bytes, escape_str, Filter, JsStr};
use sts_ldap::js;
use sts_ldap::message::{
    ExtendedValue, Message, Operation, ResultMessage, SearchEntry, SearchReference,
};
use sts_ldap::{dn, result_codes, service_dn, Connection, Event, Fault, FrontOptions};

fn dir() -> Option<PathBuf> {
    std::env::var_os("STS_CRYPTO_VECTORS").map(PathBuf::from)
}

fn load() -> Option<Json> {
    let d = dir()?;
    let p = d.join("ldap-wire-node.json");
    if !p.exists() {
        eprintln!("no {}: nothing to check", p.display());
        return None;
    }
    Some(serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap())
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}

fn undef() -> Json {
    json!({ "undefined": true })
}

fn jsstr(v: &JsStr) -> Json {
    match v {
        JsStr::Undefined => undef(),
        JsStr::Null => Json::Null,
        JsStr::Str(s) => json!(s),
    }
}

fn opt<T: serde::Serialize>(v: &Option<T>) -> Json {
    match v {
        Some(x) => json!(x),
        None => Json::Null,
    }
}

// ---- the harness's describers, field for field ------------------------

fn filter_json(f: &Filter) -> Json {
    let mut o = Map::new();
    o.insert("type".into(), json!(f.type_name()));
    match f {
        Filter::And(c) | Filter::Or(c) => {
            o.insert("clauses".into(), c.iter().map(filter_json).collect());
        }
        Filter::Not(i) => {
            o.insert("filter".into(), filter_json(i));
        }
        Filter::Presence { attribute } => {
            o.insert("attribute".into(), json!(attribute));
        }
        Filter::Substring {
            attribute,
            initial,
            any,
            last,
        } => {
            o.insert("attribute".into(), json!(attribute));
            o.insert("initial".into(), jsstr(initial));
            o.insert("any".into(), any.iter().map(opt).collect());
            o.insert("final".into(), jsstr(last));
        }
        Filter::Extensible {
            attribute,
            rule,
            value,
            dn_attributes,
        } => {
            o.insert("attribute".into(), opt(attribute));
            o.insert("rule".into(), jsstr(rule));
            o.insert("value".into(), json!(value));
            o.insert("dnAttributes".into(), json!(dn_attributes));
        }
        Filter::Equality { attribute, raw } => {
            o.insert("attribute".into(), json!(attribute));
            o.insert("value".into(), json!(Filter::equality_value(raw)));
        }
        Filter::GreaterOrEqual { attribute, value }
        | Filter::LessOrEqual { attribute, value }
        | Filter::Approximate { attribute, value } => {
            o.insert("attribute".into(), json!(attribute));
            o.insert("value".into(), json!(value));
        }
    }
    Json::Object(o)
}

fn hexv(b: &[u8]) -> Json {
    json!({ "hex": js::hex(b) })
}

fn control_json(c: &Control) -> Json {
    let value = match c {
        Control::Generic { value, .. } => match value {
            Some(v) => hexv(v),
            None => Json::Null,
        },
        Control::PagedResults { size, cookie, .. } => {
            json!({ "size": opt(size), "cookie": hexv(cookie) })
        }
        Control::PersistentSearch {
            change_types,
            changes_only,
            return_ecs,
            ..
        } => json!({ "changeTypes": opt(change_types),
                     "changesOnly": changes_only, "returnECs": return_ecs }),
        Control::EntryChangeNotification {
            change_type,
            previous_dn,
            change_number,
            ..
        } => {
            let mut o = Map::new();
            o.insert("changeType".into(), opt(change_type));
            if let Some(p) = previous_dn {
                o.insert("previousDN".into(), jsstr(p));
            }
            if let Some(n) = change_number {
                o.insert("changeNumber".into(), opt(n));
            }
            Json::Object(o)
        }
        Control::PasswordPolicy { value: p, .. } => {
            let mut o = Map::new();
            if let Some(v) = p.time_before_expiration {
                o.insert("timeBeforeExpiration".into(), opt(&v));
            }
            if let Some(v) = p.grace_authns_remaining {
                o.insert("graceAuthNsRemaining".into(), opt(&v));
            }
            if let Some(v) = p.error {
                o.insert("error".into(), opt(&v));
            }
            Json::Object(o)
        }
        Control::SortRequest { keys, .. } => match keys {
            None => undef(),
            Some(keys) => keys
                .iter()
                .map(|k| {
                    let mut o = Map::new();
                    o.insert("attributeType".into(), opt(&k.attribute_type));
                    if let Some(r) = &k.ordering_rule {
                        o.insert("orderingRule".into(), opt(r));
                    }
                    if let Some(r) = k.reverse_order {
                        o.insert("reverseOrder".into(), json!(r));
                    }
                    Json::Object(o)
                })
                .collect(),
        },
        Control::SortResponse {
            result,
            failed_attribute,
        } => {
            let mut o = Map::new();
            if let Some(r) = result {
                o.insert("result".into(), opt(r));
            }
            if let Some(f) = failed_attribute {
                o.insert("failedAttribute".into(), opt(f));
            }
            Json::Object(o)
        }
    };
    json!({ "type": jsstr(&c.oid()), "criticality": c.criticality(), "value": value })
}

fn attribute_json(a: &Attribute) -> Json {
    json!({ "type": a.attr_type, "values": a.values(),
            "buffers": a.buffers.iter().map(|b| js::hex(b)).collect::<Vec<_>>() })
}

fn request_json(m: &Message) -> Json {
    let mut o = Map::new();
    o.insert("messageId".into(), json!(m.message_id));
    o.insert("protocolOp".into(), json!(m.protocol_op()));
    o.insert("type".into(), json!(m.type_name()));
    o.insert(
        "controls".into(),
        m.controls.iter().map(control_json).collect(),
    );
    match &m.operation {
        Operation::Bind(b) => {
            o.insert("version".into(), json!(b.version));
            o.insert("name".into(), opt(&b.name));
            if b.sasl.is_some() {
                o.insert("authentication".into(), json!("sasl"));
            }
            o.insert("credentials".into(), opt(&b.credentials));
            if let Some(s) = &b.sasl {
                o.insert("mechanism".into(), json!(s.mechanism));
                o.insert(
                    "saslCredentials".into(),
                    match &s.credentials {
                        Some(c) => json!(js::hex(c)),
                        None => Json::Null,
                    },
                );
            }
        }
        Operation::Search(s) => {
            o.insert("baseObject".into(), json!(s.base_object.to_text()));
            o.insert("scope".into(), json!(s.scope_name()));
            o.insert("derefAliases".into(), json!(s.deref_aliases));
            o.insert("sizeLimit".into(), json!(s.size_limit));
            o.insert("timeLimit".into(), json!(s.time_limit));
            o.insert("typesOnly".into(), json!(s.types_only));
            o.insert("filter".into(), json!(s.filter.to_text().unwrap()));
            o.insert("filterTree".into(), filter_json(&s.filter));
            o.insert("attributes".into(), json!(s.attributes));
        }
        Operation::Add(a) => {
            o.insert("entry".into(), json!(a.entry.as_ref().unwrap().to_text()));
            o.insert(
                "attributes".into(),
                a.attributes.iter().map(attribute_json).collect(),
            );
        }
        Operation::Modify(md) => {
            o.insert(
                "object".into(),
                json!(md.object_dn.as_ref().unwrap().to_text()),
            );
            o.insert(
                "changes".into(),
                md.changes
                    .iter()
                    .map(|c| {
                        json!({ "operation": c.operation_name(),
                                "modification": attribute_json(&c.modification) })
                    })
                    .collect(),
            );
        }
        Operation::ModifyDn(d) => {
            o.insert("entry".into(), json!(d.entry.to_text()));
            o.insert("newRdn".into(), json!(d.new_rdn.to_text()));
            o.insert("deleteOldRdn".into(), json!(d.delete_old_rdn));
            o.insert(
                "newSuperior".into(),
                match &d.new_superior {
                    Some(s) => json!(s.to_text()),
                    None => undef(),
                },
            );
        }
        Operation::Compare(c) => {
            o.insert("entry".into(), json!(c.entry.as_ref().unwrap().to_text()));
            o.insert("attribute".into(), json!(c.attribute));
            o.insert("value".into(), json!(c.value));
        }
        Operation::Delete { entry } => {
            o.insert("entry".into(), json!(entry.as_ref().unwrap().to_text()));
        }
        Operation::Extended(e) => {
            o.insert("requestName".into(), json!(e.request_name));
            let _ = matches!(e.request_value, ExtendedValue::Absent);
        }
        Operation::Abandon { abandon_id } => {
            o.insert("abandonId".into(), json!(abandon_id));
        }
        Operation::Unbind | Operation::Response(_) => {}
    }
    Json::Object(o)
}

/// The harness's `front()` over Rust's connection.
fn front(chunks: &[Vec<u8>]) -> Json {
    let mut c = Connection::new(FrontOptions::default());
    let mut events = Vec::new();
    let mut hung = false;
    for chunk in chunks {
        if c.is_closed() {
            break;
        }
        for e in c.feed(chunk) {
            events.push(match e {
                Event::Dispatch(m) => json!({
                    "dispatch": request_json(&m),
                    "reencoded": match m.to_ber() {
                        Ok(b) => json!(js::hex(&b)),
                        Err(f) => json!({ "error": f.message() }),
                    }
                }),
                Event::Write(b) => json!({ "write": js::hex(&b) }),
                Event::Destroy => json!({ "destroy": true }),
                Event::Stalled => {
                    hung = true;
                    json!({ "hang": true })
                }
                Event::Thrown(m) => json!({ "thrown": m }),
            });
        }
        if c.is_stalled() {
            break;
        }
    }
    let pending = if hung { 0 } else { c.pending() };
    json!({ "events": events, "pending": pending })
}

// ---- the other answers ------------------------------------------------

fn dn_case(input: &str) -> Json {
    match Dn::parse(input) {
        Ok(d) => {
            let rdns: Vec<Json> = d
                .rdns()
                .iter()
                .map(|r| {
                    r.attributes()
                        .iter()
                        .map(|(k, v)| match v {
                            RdnValue::Text(t) => json!([k, t]),
                            RdnValue::Hex(b) => json!([k, hexv(b)]),
                        })
                        .collect()
                })
                .collect();
            json!({ "input": input, "ok": true, "text": d.to_text(),
                    "rdns": rdns, "length": d.len() })
        }
        Err(Fault::Stalled) => json!({ "input": input, "hang": true }),
        Err(Fault::Thrown(e)) => json!({ "input": input, "ok": false, "error": e }),
    }
}

fn filter_answer(mut out: Map<String, Json>, f: Result<Filter, Fault>) -> Json {
    match f {
        Err(e) => {
            out.insert("ok".into(), json!(false));
            out.insert("error".into(), json!(e.message()));
        }
        Ok(f) => {
            out.insert("ok".into(), json!(true));
            out.insert("tree".into(), filter_json(&f));
            match f.to_text() {
                Ok(t) => out.insert("text".into(), json!(t)),
                Err(e) => out.insert("textError".into(), json!(e.message())),
            };
            match f.to_ber() {
                Ok(b) => out.insert("ber".into(), json!(js::hex(&b))),
                Err(e) => out.insert("berError".into(), json!(e.message())),
            };
        }
    }
    Json::Object(out)
}

fn s_of(v: &Json) -> Option<&str> {
    v.as_str()
}

fn result_op(kind: &str) -> u8 {
    match kind {
        "bind" => 0x61,
        "add" => 0x69,
        "delete" => 0x6b,
        "modify" => 0x67,
        "modifyDn" => 0x6d,
        "compare" => 0x6f,
        "searchDone" => 0x65,
        "extended" => 0x78,
        k => panic!("kind {k}"),
    }
}

fn response_hex(r: &Json) -> Json {
    let kind = r["kind"].as_str().unwrap();
    let id = r["messageId"].as_i64().unwrap() as i32;
    match kind {
        "searchEntry" => {
            let attrs: Vec<Attribute> = r["attributes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|a| {
                    let vals: Vec<String> = a["values"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| v.as_str().unwrap().to_string())
                        .collect();
                    Attribute::from_strings(a["type"].as_str().unwrap(), &vals)
                })
                .collect();
            let e = SearchEntry {
                message_id: id,
                object_name: r["objectName"].as_str().unwrap().to_string(),
                attributes: attrs,
            };
            match e.to_ber() {
                Ok(b) => json!({ "hex": js::hex(&b) }),
                Err(f) => json!({ "error": f.message() }),
            }
        }
        "searchReference" => {
            let uris: Vec<String> = r["uris"]
                .as_array()
                .unwrap()
                .iter()
                .map(|u| u.as_str().unwrap().to_string())
                .collect();
            let b = SearchReference {
                message_id: id,
                uris,
            }
            .to_ber()
            .unwrap();
            json!({ "hex": js::hex(&b) })
        }
        k => {
            let m = ResultMessage {
                message_id: id,
                protocol_op: result_op(k),
                status: r["status"].as_i64().unwrap() as i32,
                matched_dn: s_of(&r["matchedDN"]).unwrap_or("").to_string(),
                diagnostic_message: s_of(&r["diagnosticMessage"]).unwrap_or("").to_string(),
                referrals: r["referrals"]
                    .as_array()
                    .map(|a| a.iter().map(|x| x.as_str().unwrap().to_string()).collect())
                    .unwrap_or_default(),
                response_name: s_of(&r["responseName"]).map(str::to_string),
                response_value: s_of(&r["responseValue"]).map(str::to_string),
            };
            json!({ "hex": js::hex(&m.to_ber().unwrap()) })
        }
    }
}

fn nullable(v: &Json) -> Option<&str> {
    v.as_str()
}

#[test]
fn node_vectors() {
    let Some(v) = load() else {
        eprintln!("STS_CRYPTO_VECTORS unset: the LDAP wire vectors are not checked");
        return;
    };
    let mut failures = Vec::new();
    let mut fail = |what: String| failures.push(what);
    let mut counts = std::collections::BTreeMap::new();

    for r in v["requests"].as_array().unwrap() {
        let chunks: Vec<Vec<u8>> = r["chunks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| unhex(c.as_str().unwrap()))
            .collect();
        let got = front(&chunks);
        let want = json!({ "events": r["events"], "pending": r["pending"] });
        *counts.entry("requests").or_insert(0) += 1;
        if got != want {
            fail(format!(
                "request {}:\n  node {}\n  rust {}",
                r["name"], want, got
            ));
        }
    }

    for d in v["dns"].as_array().unwrap() {
        let got = dn_case(d["input"].as_str().unwrap());
        *counts.entry("dns").or_insert(0) += 1;
        if &got != d {
            fail(format!("dn: node {d}\n  rust {got}"));
        }
    }
    for p in v["dnPairs"].as_array().unwrap() {
        let a = Dn::parse(p["a"].as_str().unwrap()).unwrap();
        let b = Dn::parse(p["b"].as_str().unwrap()).unwrap();
        let got = json!({ "a": p["a"], "b": p["b"], "equals": a.equals(&b),
                          "parentOf": a.parent_of(&b), "childOf": a.child_of(&b) });
        *counts.entry("dnPairs").or_insert(0) += 1;
        if &got != p {
            fail(format!("dn pair: node {p}\n  rust {got}"));
        }
    }

    let sd = &v["serviceDn"];
    let one = |name: &str, f: &dyn Fn(Option<&str>) -> Json| -> Vec<String> {
        sd[name]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|row| {
                let got = f(nullable(&row[0]));
                (got != row[1]).then(|| format!("{name}({}): node {} rust {got}", row[0], row[1]))
            })
            .collect()
    };
    let mut service = Vec::new();
    service.extend(one("normalizeDn", &|x| json!(service_dn::normalize_dn(x))));
    service.extend(one("parentDn", &|x| json!(service_dn::parent_dn(x))));
    service.extend(one("splitRdns", &|x| json!(service_dn::split_rdns(x))));
    service.extend(one("rdnPairs", &|x| {
        service_dn::rdn_pairs(x)
            .iter()
            .map(|p| json!({ "attribute": p.attribute, "value": p.value }))
            .collect()
    }));
    service.extend(one("escapeDnValue", &|x| json!(service_dn::escape_dn_value(x))));
    service.extend(one("unescapeDnValue", &|x| json!(service_dn::unescape_dn_value(x))));
    service.extend(one("nameUsableInDn", &|x| json!(service_dn::name_usable_in_dn(x))));
    for row in sd["isUnder"].as_array().unwrap() {
        let (a, b) = (nullable(&row[0]), nullable(&row[1]));
        let got = json!([row[0], row[1], service_dn::is_under(a, b),
                         service_dn::depth_under(a, b)]);
        if &got != row {
            service.push(format!("isUnder: node {row} rust {got}"));
        }
    }
    *counts.entry("serviceDn").or_insert(0) += 1;
    for s in service {
        fail(s);
    }

    for f in v["filters"].as_array().unwrap() {
        let input = f["input"].as_str().unwrap();
        let mut out = Map::new();
        out.insert("input".into(), json!(input));
        let got = filter_answer(out, Filter::parse(input));
        *counts.entry("filters").or_insert(0) += 1;
        if &got != f {
            fail(format!("filter: node {f}\n  rust {got}"));
        }
    }
    for f in v["filterBers"].as_array().unwrap() {
        let bytes = unhex(f["hex"].as_str().unwrap());
        let mut out = Map::new();
        out.insert("hex".into(), f["hex"].clone());
        let got = filter_answer(out, Filter::parse_ber(&mut Reader::new(&bytes)));
        *counts.entry("filterBers").or_insert(0) += 1;
        if &got != f {
            fail(format!("filter ber: node {f}\n  rust {got}"));
        }
    }

    let esc = &v["escapes"];
    for e in esc["filter"].as_array().unwrap() {
        let input = e["input"].as_str().unwrap();
        let got = match escape_str(input) {
            Ok(s) => json!({ "input": input, "ok": true, "value": s }),
            Err(f) => json!({ "input": input, "ok": false, "error": f.message() }),
        };
        *counts.entry("escapes").or_insert(0) += 1;
        if &got != e {
            fail(format!("escape: node {e}\n  rust {got}"));
        }
    }
    for e in esc["filterBuffers"].as_array().unwrap() {
        let bytes = unhex(e["hex"].as_str().unwrap());
        let got = match escape_bytes(&bytes) {
            Ok(s) => json!({ "hex": e["hex"], "ok": true, "value": s }),
            Err(f) => json!({ "hex": e["hex"], "ok": false, "error": f.message() }),
        };
        *counts.entry("escapes").or_insert(0) += 1;
        if &got != e {
            fail(format!("escape buffer: node {e}\n  rust {got}"));
        }
    }
    for e in esc["dn"].as_array().unwrap() {
        let input = e["input"].as_str().unwrap();
        let got = json!({ "input": input, "value": dn::escape_value(input) });
        *counts.entry("escapes").or_insert(0) += 1;
        if &got != e {
            fail(format!("dn escape: node {e}\n  rust {got}"));
        }
    }

    for r in v["responses"].as_array().unwrap() {
        let got = response_hex(r);
        let want = match r.get("hex") {
            Some(h) => json!({ "hex": h }),
            None => json!({ "error": r["error"] }),
        };
        *counts.entry("responses").or_insert(0) += 1;
        if got != want {
            fail(format!("response: node {r}\n  rust {got}"));
        }
    }

    let classes = result_codes::error_classes();
    let node_errors = v["errors"].as_array().unwrap();
    if classes.len() != node_errors.len() {
        fail(format!(
            "error classes: node {} rust {}",
            node_errors.len(),
            classes.len()
        ));
    }
    for (c, e) in classes.iter().zip(node_errors) {
        let got = json!({ "name": c.name, "code": c.code, "message": c.name,
                          "withMessage": "why", "text": result_codes::message(c.code) });
        *counts.entry("errors").or_insert(0) += 1;
        if &got != e {
            fail(format!("error: node {e}\n  rust {got}"));
        }
    }

    eprintln!("checked {counts:?}");
    let n = failures.len();
    for f in failures.iter().take(40) {
        eprintln!("{f}\n");
    }
    assert_eq!(n, 0, "{n} disagreements with Node");
}

// ---- the other direction ----------------------------------------------

#[test]
fn write_rust_vectors() {
    if std::env::var_os("STS_WRITE_VECTORS").is_none() {
        return;
    }
    let Some(v) = load() else {
        return;
    };
    // A corpus of Rust's own: each request Node dispatched, RE-ENCODED BY
    // RUST, then byte mutations of those from a seed Node's corpus did
    // not use, so Node is shown PDUs it has not seen.
    let mut corpus: Vec<(String, Vec<Vec<u8>>)> = Vec::new();
    for r in v["requests"].as_array().unwrap() {
        for e in r["events"].as_array().unwrap() {
            if e.get("dispatch").is_some() {
                if let Some(h) = e["reencoded"].as_str() {
                    corpus.push((format!("rust {}", r["name"]), vec![unhex(h)]));
                }
            }
        }
    }
    let mut seed: u32 = 0x5eed_1da9;
    let mut rnd = |n: usize| {
        seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12345);
        ((seed >> 8) as usize) % n
    };
    let base: Vec<(String, Vec<u8>)> = corpus
        .iter()
        .filter(|(_, c)| c[0].len() < 400)
        .map(|(n, c)| (n.clone(), c[0].clone()))
        .collect();
    for (name, pdu) in base.iter().step_by(2) {
        for k in 0..8 {
            let mut copy = pdu.clone();
            let at = rnd(copy.len());
            copy[at] = match rnd(3) {
                0 => rnd(256) as u8,
                1 => copy[at].wrapping_add(1),
                _ => [0x00, 0x80, 0xff, 0x30, 0x04, 0x84][rnd(6)],
            };
            corpus.push((format!("{name} mutated #{k} [{at}]"), vec![copy]));
        }
    }
    let requests: Vec<Json> = corpus
        .iter()
        .map(|(name, chunks)| {
            let out = front(chunks);
            json!({ "name": name,
                    "chunks": chunks.iter().map(|c| js::hex(c)).collect::<Vec<_>>(),
                    "events": out["events"], "pending": out["pending"] })
        })
        .collect();
    let responses: Vec<Json> = v["responses"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            let mut o = r.as_object().unwrap().clone();
            o.remove("hex");
            o.remove("error");
            let got = response_hex(r);
            for (k, x) in got.as_object().unwrap() {
                o.insert(k.clone(), x.clone());
            }
            Json::Object(o)
        })
        .collect();
    // Filters Rust printed and wrote: Node must parse the text back to
    // the same text and write the same BER.
    let mut filters = Vec::new();
    for f in v["filters"].as_array().unwrap() {
        if let Ok(parsed) = Filter::parse(f["input"].as_str().unwrap()) {
            if let (Ok(t), Ok(b)) = (parsed.to_text(), parsed.to_ber()) {
                filters.push(json!({ "text": t, "ber": js::hex(&b) }));
            }
        }
    }
    let dns: Vec<Json> = v["dns"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|d| {
            let t = Dn::parse(d["input"].as_str()?).ok()?.to_text();
            Some(json!({ "text": t }))
        })
        .collect();
    let out = json!({ "requests": requests, "responses": responses,
                      "filters": filters, "dns": dns });
    let p = dir().unwrap().join("ldap-wire-rust.json");
    std::fs::write(&p, serde_json::to_string(&out).unwrap()).unwrap();
    eprintln!("wrote {} ({} requests)", p.display(), requests.len());
}
