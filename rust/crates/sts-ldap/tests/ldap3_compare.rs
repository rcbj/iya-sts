// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Where `ldap3_proto` (Kanidm's codec, rust/DESIGN.md section 7) and
//! node-ldapjs differ, measured on `ldap-wire-node.json` — the reason
//! `sts-ldap` is a port and not a wrapper (its `lib.rs` says so).
//!
//! For every single-read corpus entry: does each side decode the PDU, and
//! when both do and Node handed it on, does `ldap3_proto` write back the
//! bytes node-ldapjs's `toBer()` writes? For every response the service
//! sends: does `ldap3_proto` read node-ldapjs's bytes and write them again
//! unchanged? For every filter string: does each side parse it? The
//! answer is printed as counts and named cases; the test fails only if
//! the two ever agree everywhere, which would mean the port is no longer
//! needed and this crate should be revisited.

#![allow(clippy::unwrap_used)] // a test file

use bytes::BytesMut;
use ldap3_proto::proto::LdapMsg;
use ldap3_proto::LdapCodec;
use serde_json::Value as Json;
use std::collections::BTreeMap;
use std::path::PathBuf;
use tokio_util::codec::{Decoder, Encoder};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// `Some(Ok(msg))`, `Some(Err)` refused, `None` incomplete.
fn decode(bytes: &[u8]) -> Option<Result<LdapMsg, String>> {
    let mut buf = BytesMut::from(bytes);
    match LdapCodec::default().decode(&mut buf) {
        Ok(Some(m)) => Some(Ok(m)),
        Ok(None) => None,
        Err(e) => Some(Err(e.to_string())),
    }
}

fn encode(m: LdapMsg) -> Vec<u8> {
    let mut buf = BytesMut::new();
    LdapCodec::default().encode(m, &mut buf).unwrap();
    buf.to_vec()
}

#[test]
fn where_ldap3_proto_differs_from_node_ldapjs() {
    let Some(dir) = std::env::var_os("STS_CRYPTO_VECTORS").map(PathBuf::from)
    else {
        eprintln!("STS_CRYPTO_VECTORS unset: nothing compared");
        return;
    };
    let p = dir.join("ldap-wire-node.json");
    if !p.exists() {
        return;
    }
    let v: Json =
        serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    let mut named: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    let mut note = |k: &'static str, name: String| {
        *counts.entry(k).or_insert(0) += 1;
        named.entry(k).or_default().push(name);
    };

    for r in v["requests"].as_array().unwrap() {
        let chunks = r["chunks"].as_array().unwrap();
        if chunks.len() != 1 {
            continue;
        }
        let name = r["name"].as_str().unwrap().to_string();
        let bytes = unhex(chunks[0].as_str().unwrap());
        let events = r["events"].as_array().unwrap();
        let first = events.first();
        let node_destroys = first.is_some_and(|e| e.get("destroy").is_some());
        let node_hangs = first.is_some_and(|e| e.get("hang").is_some());
        let node_pending =
            events.is_empty() && r["pending"].as_u64() != Some(0);
        let node_decodes = !node_destroys && !node_hangs && !node_pending;
        match decode(&bytes) {
            None if node_pending => note("both wait for more bytes", name),
            None => note("ldap3 waits for more bytes, node does not", name),
            Some(Err(_)) if node_decodes => {
                note("node decodes, ldap3 refuses", name)
            }
            Some(Err(_)) if node_hangs => {
                note("node hangs, ldap3 refuses", name)
            }
            Some(Err(_)) if node_pending => {
                note("node waits, ldap3 refuses", name)
            }
            Some(Err(_)) => note("both refuse", name),
            Some(Ok(_)) if node_destroys => {
                note("node refuses, ldap3 decodes", name)
            }
            Some(Ok(_)) if node_hangs => {
                note("node hangs, ldap3 decodes", name)
            }
            Some(Ok(_)) if node_pending => {
                note("node waits, ldap3 decodes", name)
            }
            Some(Ok(m)) => {
                let node = first
                    .and_then(|e| e.get("reencoded"))
                    .and_then(Json::as_str)
                    .map(str::to_string);
                match node {
                    None => note("both decode (node answers it itself)", name),
                    Some(n) if n == hex(&encode(m)) => {
                        note("both decode, same bytes", name)
                    }
                    Some(_) => {
                        note("both decode, ldap3 writes other bytes", name)
                    }
                }
            }
        }
    }

    for r in v["responses"].as_array().unwrap() {
        let Some(h) = r["hex"].as_str() else {
            continue;
        };
        let name = format!("{} {}", r["kind"], r["messageId"]);
        match decode(&unhex(h)) {
            Some(Ok(m)) if hex(&encode(m.clone())) == h => {
                note("response: ldap3 reads and writes node's bytes", name);
            }
            Some(Ok(_)) => note("response: ldap3 writes other bytes", name),
            _ => note("response: ldap3 cannot read node's bytes", name),
        }
    }

    for f in v["filters"].as_array().unwrap() {
        let input = f["input"].as_str().unwrap();
        let node = f["ok"].as_bool().unwrap();
        let mine = ldap3_proto::parse_ldap_filter_str(input).is_ok();
        let k = match (node, mine) {
            (true, true) => "filter string: both parse",
            (false, false) => "filter string: both refuse",
            (true, false) => "filter string: node parses, ldap3 refuses",
            (false, true) => "filter string: node refuses, ldap3 parses",
        };
        note(k, input.to_string());
    }

    for (k, n) in &counts {
        let names = &named[k];
        let shown: Vec<&String> = names.iter().take(12).collect();
        eprintln!("{n:5}  {k}\n       {shown:?}");
    }
    let agree = [
        "both wait for more bytes",
        "both refuse",
        "both decode, same bytes",
        "both decode (node answers it itself)",
        "response: ldap3 reads and writes node's bytes",
        "filter string: both parse",
        "filter string: both refuse",
    ];
    let differ: usize = counts
        .iter()
        .filter(|(k, _)| !agree.contains(k))
        .map(|(_, n)| n)
        .sum();
    eprintln!("{differ} cases where ldap3_proto and node-ldapjs differ");
    assert!(
        differ > 0,
        "ldap3_proto now agrees with node-ldapjs everywhere"
    );
}
