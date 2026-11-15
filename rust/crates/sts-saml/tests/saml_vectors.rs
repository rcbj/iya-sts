// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! SAML 2.0 against Node, both ways: `saml-node.json`, which
//! `tests/tools/saml-vectors.js` writes, and — with `STS_WRITE_VECTORS` —
//! `saml-rust.json`, which `tests/rust_crypto_vectors.js` checks in Node.
//!
//! * every assertion Node built is built here into the same bytes, and
//!   signed here with the realm's key into the same signed bytes (RSA);
//! * the Status, the Response, signed and not, the same bytes;
//! * the bindings: the decoded messages, the stripped signatures, the
//!   SimpleSign form (the same signature), the POST page and its shell;
//!   the Redirect URL's message read back the same (the DEFLATE stream is
//!   another library's), its signature verifying with the realm's
//!   certificate;
//! * every AuthnRequest read as Node read it, and every refusal in Node's
//!   words but a parser's own;
//! * the artifacts: minted from Node's handles into Node's artifacts, the
//!   foreign test, the row key and the row Node stored read and written
//!   back unchanged.
//!
//! The directory is `STS_CRYPTO_VECTORS`, never committed; with it unset
//! this test says so and passes.

#![allow(clippy::unwrap_used)] // a test file

use serde_json::{json, Value as Json};
use sts_crypto::xmldsig::{self, Placement, XmlPolicy};
use sts_saml::artifact::{self, StoredArtifact};
use sts_saml::assertion::{
    self, AssertionOptions, AttributeRow, Delegate, Instants,
    SubjectConfirmation, XmlSigner,
};
use sts_saml::binding::{self, PostNote, QuerySigner};
use sts_saml::request;
use sts_saml::response::{self, ResponseOptions};

fn s(v: &Json) -> &str {
    v.as_str().unwrap_or("")
}

fn strings(v: &Json) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

fn policy_of(v: &Json) -> XmlPolicy {
    let b = |k: &str| v[k].as_bool().unwrap_or(false);
    XmlPolicy {
        sha1_allowed: b("sha1Allowed"),
        broken_algorithms: b("brokenAlgorithms"),
        signature_algorithms: strings(&v["signatureAlgorithms"]),
        accepted_signature_algorithms: strings(
            &v["acceptedSignatureAlgorithms"],
        ),
        accepted_digest_algorithms: strings(&v["acceptedDigestAlgorithms"]),
        pqc_only: b("pqcOnly"),
        jose_signing_algorithms: strings(&v["joseSigningAlgorithms"]),
        jose_accepted_algorithms: strings(&v["joseAcceptedAlgorithms"]),
        omits_unapproved_curves: b("omitsUnapprovedCurves"),
    }
}

fn rows_of(list: &Json) -> Vec<AttributeRow> {
    list.as_array()
        .map(|list| {
            list.iter()
                .map(|a| AttributeRow {
                    name: s(&a["name"]).to_string(),
                    name_format: s(&a["nameFormat"]).to_string(),
                    friendly_name: s(&a["friendlyName"]).to_string(),
                    values: match &a["values"] {
                        Json::Array(v) => v
                            .iter()
                            .map(|x| x.as_str().unwrap_or("").to_string())
                            .collect(),
                        _ => vec![s(&a["value"]).to_string()],
                    },
                })
                .collect()
        })
        .unwrap_or_default()
}

fn options_of(o: &Json, custom: &Json) -> AssertionOptions {
    AssertionOptions {
        attributes: rows_of(&o["attributes"]),
        custom: rows_of(custom),
        authn_context_class_ref: s(&o["authnContextClassRef"]).to_string(),
        name_id_format: s(&o["nameIdFormat"]).to_string(),
        name_id_value: o["nameIdValue"].as_str().map(String::from),
        subject_confirmation: o["subjectConfirmation"].as_object().map(|c| {
            SubjectConfirmation {
                recipient: c["recipient"].as_str().unwrap_or("").into(),
                in_response_to: c["inResponseTo"].as_str().unwrap_or("").into(),
                not_on_or_after: c
                    .get("notOnOrAfter")
                    .and_then(Json::as_str)
                    .unwrap_or("")
                    .into(),
            }
        }),
        session_index: s(&o["sessionIndex"]).to_string(),
        authn_instant: s(&o["authnInstant"]).to_string(),
        issuer: "https://idp.vectors.example".to_string(),
        attribute_query: o["attributeQuery"].as_bool().unwrap_or(false),
        name_qualifier: s(&o["nameQualifier"]).to_string(),
        sp_name_qualifier: s(&o["spNameQualifier"]).to_string(),
        delegates: o["delegates"]
            .as_array()
            .map(|list| {
                list.iter()
                    .map(|d| Delegate {
                        name_id: s(&d["nameId"]).to_string(),
                        format: s(&d["format"]).to_string(),
                        instant: s(&d["instant"]).to_string(),
                    })
                    .collect()
            })
            .unwrap_or_default(),
    }
}

/// A query parameter of a URL, decoded.
fn param(url: &str, name: &str) -> String {
    let query = url.split_once('?').map(|q| q.1).unwrap_or("");
    query
        .split('&')
        .find_map(|p| p.strip_prefix(&format!("{}=", name)))
        .map(percent_decode)
        .unwrap_or_default()
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let h = u8::from_str_radix(&s[i + 1..i + 3], 16).unwrap();
            out.push(h);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap()
}

/// The fake translator's string for a key (`saml-vectors.js`'s `T`).
fn t(key: &str, vars: Option<Json>) -> String {
    match vars {
        Some(v) => format!("[{} {}]", key, serde_json::to_string(&v).unwrap()),
        None => format!("[{}]", key),
    }
}

#[test]
fn node_saml_vectors_both_ways() {
    let Some(dir) = std::env::var("STS_CRYPTO_VECTORS")
        .ok()
        .map(std::path::PathBuf::from)
    else {
        eprintln!("STS_CRYPTO_VECTORS is not set; no SAML vectors");
        return;
    };
    let file = dir.join("saml-node.json");
    if !file.exists() {
        eprintln!("{} is missing; no SAML vectors", file.display());
        return;
    }
    let v: Json =
        serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    let sv = &v["signer"];
    let signer = XmlSigner {
        private_key_pem: s(&sv["privateKeyPem"]).to_string(),
        cert_pem: s(&sv["certPem"]).to_string(),
        chain_pem: strings(&sv["chainPem"]),
        sig_alg: s(&sv["sigAlg"]).to_string(),
        c14n_alg: s(&sv["c14nAlg"]).to_string(),
        policy: policy_of(&sv["policy"]),
    };
    let mut failures: Vec<String> = Vec::new();
    let mut fail = |what: String| failures.push(what);
    let mut signed_out = Vec::new();
    let mut checked = 0;

    // The assertions.
    for a in v["assertions"].as_array().unwrap() {
        let name = s(&a["name"]);
        let at = Instants {
            id: s(&a["instants"]["id"]).into(),
            now: s(&a["instants"]["now"]).into(),
            not_before: s(&a["instants"]["notBefore"]).into(),
            not_on_or_after: s(&a["instants"]["notOnOrAfter"]).into(),
        };
        let ours = assertion::build_unsigned(
            s(&a["subject"]),
            s(&a["audience"]),
            &at,
            &options_of(&a["opts"], &a["custom"]),
        );
        checked += 2;
        if ours != s(&a["unsigned"]) {
            let node = s(&a["unsigned"]);
            let at = node
                .bytes()
                .zip(ours.bytes())
                .position(|(x, y)| x != y)
                .unwrap_or(node.len().min(ours.len()));
            let from = at.saturating_sub(60);
            fail(format!(
                "assertion {} at {}:\n  node {}\n  rust {}",
                name,
                at,
                &node[from..(at + 120).min(node.len())],
                &ours[from..(at + 120).min(ours.len())]
            ));
            continue;
        }
        let signed = signer.sign(&ours, Placement::AfterIssuer).unwrap();
        if signed != s(&a["signed"]) {
            fail(format!(
                "signed assertion {}:\n  node {}\n  rust {}",
                name, a["signed"], signed
            ));
        }
        signed_out.push(json!({ "name": name, "element": "Assertion",
                                "xml": signed, "certPem": signer.cert_pem }));
    }

    // The Status and the Response.
    for r in v["responses"].as_array().unwrap() {
        checked += 1;
        if s(&r["kind"]) == "status" {
            let ours = response::status_element(
                s(&r["code"]),
                s(&r["sub"]),
                s(&r["message"]),
            );
            if ours != s(&r["xml"]) {
                fail(format!("status:\n  node {}\n  rust {}", r["xml"], ours));
            }
            continue;
        }
        let o = ResponseOptions {
            id: s(&r["id"]).into(),
            issue_instant: s(&r["issueInstant"]).into(),
            destination: s(&r["destination"]).into(),
            in_response_to: s(&r["inResponseTo"]).into(),
            issuer: s(&r["issuer"]).into(),
            status: s(&r["status"]).into(),
            assertion: s(&r["assertion"]).into(),
            ..ResponseOptions::default()
        };
        let signed = r["signed"].as_bool().unwrap();
        let ours = response::build_response(&o, signed.then_some(&signer)).xml;
        if ours != s(&r["xml"]) {
            fail(format!("response:\n  node {}\n  rust {}", r["xml"], ours));
        }
        signed_out.push(json!({ "name": "the Response", "element": "Response",
                                "xml": ours, "certPem": signer.cert_pem }));
    }

    // The bindings.
    let b = &v["bindings"];
    for d in b["decoded"].as_array().unwrap() {
        checked += 1;
        let ours = binding::decode_message(s(&d["encoded"]));
        if ours != s(&d["decoded"]) {
            fail(format!(
                "decoded {}: {:?} vs {:?}",
                d["name"], d["decoded"], ours
            ));
        }
    }
    for d in b["stripped"].as_array().unwrap() {
        checked += 1;
        let ours = binding::without_enveloped_signature(s(&d["xml"]));
        if ours != s(&d["stripped"]) {
            fail(format!(
                "stripped {}:\n  node {}\n  rust {}",
                d["name"], d["stripped"], ours
            ));
        }
    }
    for d in b["redirects"].as_array().unwrap() {
        checked += 1;
        let ours = binding::redirect_url_for(
            s(&d["destination"]),
            "SAMLResponse",
            s(&d["xml"]),
            s(&d["relayState"]),
            Some(&signer as &dyn QuerySigner),
        );
        let node = s(&d["url"]);
        let message =
            |u: &str| binding::decode_message(&param(u, "SAMLResponse"));
        let prefix =
            |u: &str| u.split_once("SAMLResponse=").unwrap().0.to_string();
        if message(&ours) != message(node)
            || param(&ours, "RelayState") != param(node, "RelayState")
            || param(&ours, "SigAlg") != param(node, "SigAlg")
            || prefix(&ours) != prefix(node)
        {
            fail(format!(
                "redirect {}:\n  node {}\n  rust {}",
                d["name"], node, ours
            ));
        }
        // The signature is over what Rust sends, and verifies with the
        // realm's certificate.
        let signed_part = ours
            .split_once('?')
            .unwrap()
            .1
            .split("&Signature=")
            .next()
            .unwrap()
            .to_string();
        let signed_part = if s(&d["destination"]).contains('?') {
            signed_part.split_once('&').unwrap().1.to_string()
        } else {
            signed_part
        };
        let verdict = xmldsig::verify_query_string(
            &signed_part,
            Some(&param(&ours, "Signature")),
            &param(&ours, "SigAlg"),
            Some(&signer.cert_pem),
            &signer.policy,
        );
        if !verdict.ok {
            fail(format!("redirect {}: {}", d["name"], verdict.why));
        }
    }
    for d in b["simpleSign"].as_array().unwrap() {
        checked += 1;
        let (message, extra) = binding::simple_sign_fields(
            "SAMLResponse",
            s(&d["xml"]),
            s(&d["relayState"]),
            Some(&signer as &dyn QuerySigner),
        );
        let ours =
            json!(extra.iter().map(|(a, b)| json!([a, b])).collect::<Vec<_>>());
        if message != s(&d["message"]) || ours != d["extra"] {
            fail(format!("simpleSign: {} vs {}", d["extra"], ours));
        }
    }
    for p in b["pages"].as_array().unwrap() {
        checked += 2;
        let relay = s(&p["relayState"]);
        let message = s(&p["message"]);
        let destination = s(&p["destination"]);
        let note = PostNote {
            title: s(&p["title"]).into(),
            sub: s(&p["sub"]).into(),
            continue_label: t("handoff.saml2.continueToSp", None),
            posting_to: t(
                "handoff.common.postingTo",
                Some(json!({ "destination": destination })),
            ),
            field_line: t(
                "handoff.common.field",
                Some(json!({ "field": "SAMLResponse",
                             "length": message.encode_utf16().count() })),
            ),
            relay_line: if relay.is_empty() {
                t("handoff.saml2.relayStateNone", None)
            } else {
                t(
                    "handoff.saml2.relayStateEchoed",
                    Some(json!({ "relayState": relay })),
                )
            },
            autopost_line: t(
                "handoff.common.autopost",
                Some(json!({ "script": "/saml2/autopost.js" })),
            ),
        };
        let extra: Vec<(String, String)> = p["extra"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| (s(&e[0]).to_string(), s(&e[1]).to_string()))
            .collect();
        let inner = binding::post_binding_page(
            destination,
            s(&p["field"]),
            message,
            relay,
            &note,
            &extra,
        );
        if inner != s(&p["inner"]) {
            fail(format!(
                "post page:\n  node {}\n  rust {}",
                p["inner"], inner
            ));
        }
        let title = if s(&p["title"]) == "t" {
            "t"
        } else {
            "A <title>"
        };
        let body = if title == "t" { "" } else { "<p>x</p>" };
        let page = binding::page(title, body, "");
        if page != s(&p["page"]) {
            fail(format!("page:\n  node {}\n  rust {}", p["page"], page));
        }
    }

    // The AuthnRequests.
    for r in v["requests"].as_array().unwrap() {
        checked += 1;
        let node = &r["read"];
        let ours = request::read_authn_request(s(&r["xml"]));
        let got = match ours {
            Err(why) => json!({ "ok": false, "why": why }),
            Ok(a) => {
                let mut m = json!({
                    "ok": true, "xml": a.xml, "id": a.id,
                    "version": a.version, "issueInstant": a.issue_instant,
                    "destination": a.destination,
                    "forceAuthn": a.force_authn, "isPassive": a.is_passive,
                    "protocolBinding": a.protocol_binding,
                    "acsIndex": a.acs_index, "acsUrl": a.acs_url,
                    "issuer": a.issuer, "nameIdFormat": a.name_id_format,
                    "allowCreate": a.allow_create,
                    "subjectHint": a.subject_hint,
                    "subjectHintFormat": a.subject_hint_format,
                    "requestedAuthnContexts": a.requested_authn_contexts,
                    "signed": a.signed,
                    "signingCertificate": a.signing_certificate,
                });
                for (k, val) in a.other {
                    m[k] = json!(val);
                }
                m
            }
        };
        // A malformed document's sentence is the parser's own after
        // Node's prefix.
        let words = |j: &Json| {
            let mut j = j.clone();
            if let Some(w) = j["why"].as_str() {
                if let Some(at) = w.find("not well-formed XML: ") {
                    j["why"] = json!(w[..at].to_string());
                }
            }
            j
        };
        if words(&got) != words(node) {
            fail(format!(
                "request {}:\n  node {}\n  rust {}",
                r["name"], node, got
            ));
        }
    }

    // The artifacts.
    let a = &v["artifacts"];
    let mut minted_out = Vec::new();
    for m in a["minted"].as_array().unwrap() {
        checked += 1;
        let node = s(&m["artifact"]);
        let handle = &binding::node_base64(node)[24..];
        let index = m["index"].as_u64().unwrap() as u16;
        let ours = artifact::artifact_of(s(&m["issuer"]), index, handle);
        if ours != node {
            fail(format!("artifact: {} vs {}", node, ours));
        }
        minted_out.push(json!({ "issuer": m["issuer"], "index": index,
            "artifact": artifact::mint(s(&m["issuer"]), index) }));
    }
    for f in a["foreign"].as_array().unwrap() {
        checked += 1;
        if artifact::is_foreign(s(&f["artifact"]), s(&f["issuer"]))
            != f["foreign"].as_bool().unwrap()
        {
            fail(format!("foreign {}", f["name"]));
        }
    }
    let mut keys_out = Vec::new();
    for k in a["keys"].as_array().unwrap() {
        checked += 1;
        if artifact::row_key(s(&k["artifact"])) != s(&k["key"]) {
            fail(format!("row key of {}", k["artifact"]));
        }
        keys_out.push(json!({ "artifact": k["artifact"],
                              "key": artifact::row_key(s(&k["artifact"])) }));
    }
    let location = s(&a["location"]);
    let art = param(location, "SAMLart");
    for row in a["rows"].as_array().unwrap() {
        checked += 2;
        let read = StoredArtifact::from_json(&row["value"]).unwrap();
        if read.to_json() != row["value"]
            || serde_json::to_string(&read.to_json()).unwrap()
                != serde_json::to_string(&row["value"]).unwrap()
        {
            fail(format!("row: {} vs {}", row["value"], read.to_json()));
        }
        if artifact::row_key(&art) != s(&row["key"]) {
            fail(format!("the row's key: {} vs {}", row["key"], art));
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} differ from Node:\n{}",
        failures.len(),
        checked,
        failures.join("\n")
    );
    if std::env::var("STS_WRITE_VECTORS").is_ok() {
        std::fs::write(
            dir.join("saml-rust.json"),
            serde_json::to_string_pretty(&json!({
                "signed": signed_out,
                "keys": keys_out,
                "minted": minted_out,
            }))
            .unwrap(),
        )
        .unwrap();
    }
}
