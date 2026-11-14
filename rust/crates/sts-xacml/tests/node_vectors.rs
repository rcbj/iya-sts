// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The engine against Node as it is now: `xacml-node.json`, which
//! `tests/tools/xacml-vectors.js` writes with Node's own engine, templates,
//! builder and access PEP (`STS_ONLY=xacml node tests/tools/crypto-vectors.js`,
//! in the tests image). Held to it:
//!
//! * every policy document of the OASIS suite reads here exactly when it
//!   reads in Node, and is WRITTEN byte for byte as Node writes it; one Node
//!   refuses is refused with the same status and sentence;
//! * a document carrying a declaration is refused in Node's sentence;
//! * every policy the service builds — each template under its defaults and
//!   each parameter changed, a UMA owner's shares — written by Node, reads
//!   and writes back identically here; and the access-control document this
//!   crate builds itself is, read and written, Node's document;
//! * every request the builder is asked for is the request Node's builds;
//! * every access question gets Node's request, decision and sentence.
//!
//! With `STS_WRITE_VECTORS=1` it writes what this crate produced as
//! `xacml-rust.json`, which `tests/rust_crypto_vectors.js` holds to Node.
//! The directory is `STS_CRYPTO_VECTORS`, never committed; with it unset
//! this test says so and passes.

#![allow(clippy::unwrap_used)] // a test file

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::{json, Map, Value as Json};
use sts_xacml::access::{
    self, AccessRequestObject, OwnedObject, Parameters, Question, ReportObject,
};
use sts_xacml::builder::{
    self, vocabulary, AuthorizationRequest, AuthzenApproval, AuthzenAttribute,
    AuthzenFacts, Fact, FgaFacts, UmaFacts, UmaParty, UmaResource,
};
use sts_xacml::datatypes::DataTypes;
use sts_xacml::pdp::{AttributeResolver, EvaluationOptions};
use sts_xacml::policy::Designator;
use sts_xacml::request::Request;
use sts_xacml::value::Value;
use sts_xacml::xml::{parse_policy, write_policy};

fn text(v: &Json) -> String {
    match v {
        Json::String(s) => s.clone(),
        Json::Null => String::new(),
        Json::Bool(b) => b.to_string(),
        Json::Number(n) => n.to_string(),
        other => other.to_string(),
    }
}

fn texts(v: &Json) -> Vec<String> {
    v.as_array()
        .map(|a| a.iter().map(text).collect())
        .unwrap_or_default()
}

fn optional(v: &Json) -> Option<String> {
    if v.is_null() {
        None
    } else {
        Some(text(v))
    }
}

/// A request in the shape Node's `build()` answers.
fn request_json(r: &Request) -> Json {
    json!({
        "returnPolicyIdList": r.return_policy_id_list,
        "combinedDecision": r.combined_decision,
        "categories": r.categories.iter().map(|c| json!({
            "category": c.category,
            "id": c.id,
            "content": Json::Null,
            "attributes": c.attributes.iter().map(|a| json!({
                "attributeId": a.attribute_id,
                "issuer": a.issuer,
                "includeInResult": a.include_in_result,
                "values": a.values.iter().map(|v| json!({
                    "type": v.type_uri, "lexical": v.lexical,
                })).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
    })
}

fn rows_of(v: &Json) -> Vec<AuthzenAttribute> {
    v.as_array()
        .map(|rows| {
            rows.iter()
                .map(|row| AuthzenAttribute {
                    category: text(&row["category"]),
                    attribute_id: text(&row["attributeId"]),
                    data_type: text(&row["dataType"]),
                    values: texts(&row["values"]),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn authzen_facts(f: &Json) -> AuthzenFacts {
    let approval = &f["approval"];
    AuthzenFacts {
        subject_type: text(&f["subject"]["type"]),
        subject_id: text(&f["subject"]["id"]),
        action_name: text(&f["action"]["name"]),
        resource_type: text(&f["resource"]["type"]),
        resource_id: text(&f["resource"]["id"]),
        realm: text(&f["realm"]),
        caller: text(&f["caller"]),
        application: text(&f["application"]),
        supplied: texts(&f["supplied"]),
        attributes: rows_of(&f["attributes"]),
        approval: approval.is_object().then(|| AuthzenApproval {
            approval_id: text(&approval["approvalId"]),
            approved_until: text(&approval["approvedUntil"]),
            approver: text(&approval["approver"]),
        }),
    }
}

fn fga_facts(f: &Json) -> FgaFacts {
    FgaFacts {
        realm: text(&f["realm"]),
        protocol: text(&f["protocol"]),
        subject_id: text(&f["subject"]["id"]),
        subject_kind: optional(&f["subject"]["kind"]),
        client_id: text(&f["clientId"]),
        application: text(&f["application"]),
        detail_type: text(&f["detailType"]),
        definition_digest: text(&f["definitionDigest"]),
        stage: text(&f["stage"]),
        action: text(&f["action"]),
        resource_id: text(&f["resourceId"]),
        grant_type: text(&f["grantType"]),
        supplied: texts(&f["supplied"]),
        attributes: rows_of(&f["attributes"]),
    }
}

fn uma_facts(f: &Json) -> UmaFacts {
    let r = &f["resource"];
    let p = &f["requestingParty"];
    let mut claims = BTreeMap::new();
    if let Some(given) = f["claims"].as_object() {
        for (name, values) in given {
            claims.insert(name.clone(), texts(values));
        }
    }
    let mut settings = BTreeMap::new();
    if let Some(given) = f["settings"].as_object() {
        for (key, value) in given {
            settings.insert(
                key.clone(),
                match value {
                    Json::Null => None,
                    Json::Bool(b) => Some(Fact::Boolean(*b)),
                    other => Some(Fact::Text(text(other))),
                },
            );
        }
    }
    UmaFacts {
        realm: text(&f["realm"]),
        layer: text(&f["layer"]),
        stage: text(&f["stage"]),
        resource: UmaResource {
            id: text(&r["id"]),
            resource_type: text(&r["type"]),
            resource_server: text(&r["resourceServer"]),
            resource_server_declared: r["resourceServerDeclared"] == true,
            owner: text(&r["owner"]),
            owner_kind: text(&r["ownerKind"]),
        },
        scope: text(&f["scope"]),
        requesting_party: UmaParty {
            id: text(&p["id"]),
            kind: optional(&p["kind"]),
            known: p["known"] == true,
            is_owner: p["isOwner"] == true,
            claim_source: text(&p["claimSource"]),
            claim_issuer: text(&p["claimIssuer"]),
            claim_issuer_declared: p["claimIssuerDeclared"].as_bool(),
            acr: text(&p["acr"]),
            groups: texts(&p["groups"]),
        },
        client_id: text(&f["clientId"]),
        client_grant_declared: f["clientGrantDeclared"] == true,
        claims,
        ticket_age_s: f["ticketAgeS"].as_f64(),
        rpt_presented: f["rptPresented"] == true,
        mode: text(&f["mode"]),
        settings,
    }
}

/// One `ops` row: the base methods, one call at a time.
fn run_ops(options: &Json, ops: &Json) -> Request {
    let mut b = AuthorizationRequest::new(
        options["includeInResult"] != false,
        options["dropEmpty"] == true,
        options["returnPolicyIdList"] != false,
    );
    for op in ops.as_array().unwrap() {
        let name = op[0].as_str().unwrap();
        let a = |i: usize| text(&op[i]);
        let o = |i: usize| optional(&op[i]);
        match name {
            "principal" => {
                b.principal(&a(1), o(2).as_deref());
            }
            "roles" => {
                b.roles(texts(&op[1]));
            }
            "target" => {
                b.target(&a(1), o(2).as_deref());
            }
            "requestedAction" => {
                b.requested_action(&a(1));
            }
            "requestedScopes" => {
                b.requested_scopes(texts(&op[1]));
            }
            "client" => {
                b.client(o(1).as_deref());
            }
            "audience" => {
                b.audience(texts(&op[1]));
            }
            "protocol" => {
                b.protocol(o(1).as_deref());
            }
            "grantType" => {
                b.grant_type(o(1).as_deref());
            }
            "mode" => {
                b.mode(o(1).as_deref());
            }
            "stage" => {
                b.stage(o(1).as_deref());
            }
            "setting" => {
                let value = match &op[2] {
                    Json::Null => None,
                    Json::Bool(v) => Some(Fact::Boolean(*v)),
                    other => Some(Fact::Text(text(other))),
                };
                b.setting(&a(1), value);
            }
            "intermediary" => {
                b.intermediary(&a(1));
            }
            "category" => {
                b.category(&a(1));
            }
            other => panic!("no such builder method {}", other),
        }
    }
    b.build()
}

fn build_row(row: &Json) -> Request {
    let mut b = AuthorizationRequest::default();
    match row["method"].as_str().unwrap() {
        "ops" => return run_ops(&row["options"], &row["ops"]),
        "authzen" => {
            b.authzen(&authzen_facts(&row["facts"]));
        }
        "fga" => {
            b.fga(&fga_facts(&row["facts"]));
        }
        "fgaAccess" => {
            b.authzen(&authzen_facts(&row["authzen"]))
                .fga_access(&text(&row["facts"]["application"]));
        }
        "uma" => {
            b.uma(&uma_facts(&row["facts"]));
        }
        other => panic!("no such builder row {}", other),
    }
    b.build()
}

fn question(asked: &Json) -> Question {
    let s = &asked["subject"];
    let owned = &asked["ownedObject"];
    let report = &asked["reportObject"];
    let ask = &asked["accessRequestObject"];
    Question {
        resource: text(&asked["resource"]),
        action: text(&asked["action"]),
        owner: optional(&asked["owner"]),
        subject: text(&s["name"]),
        label: text(&s["label"]),
        kind: optional(&s["kind"]),
        authenticated: s["authenticated"] != false,
        required_all_roles: texts(&asked["requiredAllRoles"]),
        owned_object: owned.is_object().then(|| OwnedObject {
            kind: text(&owned["kind"]),
            id: text(&owned["id"]),
            action: text(&owned["action"]),
            required_role: text(&owned["requiredRole"]),
            attributes: texts(&owned["attributes"]),
            person: text(&owned["person"]),
        }),
        report_object: report.is_object().then(|| ReportObject {
            kind: text(&report["kind"]),
            owner: text(&report["owner"]),
            groups: texts(&report["groups"]),
            person: text(&report["person"]),
        }),
        access_request_object: ask.is_object().then(|| AccessRequestObject {
            id: text(&ask["id"]),
            requester: text(&ask["requester"]),
            subject: text(&ask["subject"]),
            subject_type: text(&ask["subjectType"]),
            action: text(&ask["action"]),
            resource: text(&ask["resource"]),
            resource_type: text(&ask["resourceType"]),
            application: text(&ask["application"]),
            eligible: ask["eligible"] == true,
            door: text(&ask["door"]),
            approver_identity: texts(&ask["approverIdentity"]),
        }),
    }
}

/// The PIP's answers, as the question gives them.
struct Pip(Vec<AuthzenAttribute>);

impl AttributeResolver for Pip {
    fn resolve(&self, designator: &Designator) -> Vec<Value> {
        self.0
            .iter()
            .filter(|row| {
                row.category == designator.category
                    && row.attribute_id == designator.attribute_id
                    && row.data_type == designator.data_type
            })
            .flat_map(|row| row.values.iter())
            .filter_map(|lexical| {
                DataTypes::standard()
                    .parse(&designator.data_type, lexical)
                    .ok()
            })
            .collect()
    }
}

fn answers_of(v: &Json) -> BTreeMap<String, String> {
    v.as_object()
        .map(|m| m.iter().map(|(k, v)| (k.clone(), text(v))).collect())
        .unwrap_or_default()
}

#[test]
fn the_engine_answers_as_node_does() {
    let Ok(dir) = std::env::var("STS_CRYPTO_VECTORS") else {
        eprintln!(
            "STS_CRYPTO_VECTORS is not set: xacml-node.json is not checked"
        );
        return;
    };
    let v: Json = serde_json::from_str(
        &std::fs::read_to_string(Path::new(&dir).join("xacml-node.json"))
            .unwrap(),
    )
    .unwrap();
    let suite_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../xacml/conformance");
    let mut failures: Vec<String> = Vec::new();
    let mut checked = BTreeMap::<&str, usize>::new();
    let mut out = Map::new();

    // THE SUITE: read and written, or refused, as Node does.
    let mut suite_out = Vec::new();
    for row in v["suite"].as_array().unwrap() {
        let path = text(&row["path"]);
        let source = std::fs::read_to_string(suite_root.join(&path)).unwrap();
        *checked.entry("suite").or_default() += 1;
        match (parse_policy(&source), row.get("written")) {
            (Ok(policy), Some(written)) => {
                let mine = write_policy(&policy);
                if mine != text(written) {
                    failures
                        .push(format!("suite {}: written differently", path));
                }
                suite_out.push(json!({ "path": path, "written": mine }));
            }
            (Ok(_), None) => failures.push(format!(
                "suite {}: read here, refused in Node: {}",
                path, row["refused"]["message"]
            )),
            (Err(e), Some(_)) => failures.push(format!(
                "suite {}: refused here, read in Node: {}",
                path, e.message
            )),
            (Err(e), None) => {
                let refused = &row["refused"];
                if e.message != text(&refused["message"])
                    || (!refused["status"].is_null()
                        && e.status.uri() != text(&refused["status"]))
                {
                    failures.push(format!(
                        "suite {}: refused as {} \"{}\", Node {} \"{}\"",
                        path,
                        e.status.uri(),
                        e.message,
                        refused["status"],
                        text(&refused["message"])
                    ));
                }
                suite_out.push(json!({ "path": path,
                    "refused": { "message": e.message } }));
            }
        }
    }
    out.insert("suite".into(), Json::Array(suite_out));

    // A DECLARATION, refused before anything is read.
    for row in v["declared"].as_array().unwrap() {
        *checked.entry("declared").or_default() += 1;
        match parse_policy(&text(&row["text"])) {
            Ok(_) => failures.push(format!("declared {} read", row["text"])),
            Err(e) => {
                if e.message != text(&row["refused"]["message"]) {
                    failures.push(format!(
                        "declared {}: \"{}\"",
                        row["text"], e.message
                    ));
                }
            }
        }
    }

    // THE SERVICE'S OWN POLICIES, and the access-control document as this
    // crate builds it.
    let mut service_out = Vec::new();
    for row in v["service"].as_array().unwrap() {
        let template = text(&row["template"]);
        *checked.entry("service").or_default() += 1;
        let Some(written) = row.get("written").map(text) else {
            failures.push(format!("service {}: Node refused it", template));
            continue;
        };
        if written != text(&row["rewritten"]) {
            failures.push(format!(
                "service {} {}: Node's writer is not a fixed point",
                template, row["answers"]
            ));
        }
        match parse_policy(&written) {
            Ok(policy) => {
                if write_policy(&policy) != written {
                    failures.push(format!(
                        "service {} {}: written back differently",
                        template, row["answers"]
                    ));
                }
            }
            Err(e) => failures.push(format!(
                "service {} {}: does not read: {}",
                template, row["answers"], e.message
            )),
        }
        if template == access::DEFAULT_NAME {
            *checked.entry("access document").or_default() += 1;
            let p = Parameters::from_answers(&answers_of(&row["answers"]));
            let document = access::document(&template, &p);
            match parse_policy(&document) {
                Ok(policy) => {
                    let mine = write_policy(&policy);
                    if mine != written {
                        failures.push(format!(
                            "access document {}: not Node's\n{}\n{}",
                            row["answers"], mine, written
                        ));
                    }
                    service_out.push(json!({ "template": template,
                        "answers": row["answers"], "document": document,
                        "written": mine }));
                }
                Err(e) => failures.push(format!(
                    "access document {}: does not read: {}",
                    row["answers"], e.message
                )),
            }
        }
    }
    out.insert("service".into(), Json::Array(service_out));

    // THE BUILDER.
    let r = &v["requests"];
    let vocab = r["vocabulary"].as_object().unwrap();
    let mine = vocabulary_table();
    *checked.entry("vocabulary").or_default() += vocab.len();
    if vocab.len() != mine.len() {
        failures.push(format!(
            "vocabulary: Node has {}, Rust {}",
            vocab.len(),
            mine.len()
        ));
    }
    for (name, uri) in vocab {
        if mine.get(name.as_str()).copied() != uri.as_str() {
            failures.push(format!(
                "vocabulary {}: {:?}",
                name,
                mine.get(name.as_str())
            ));
        }
    }
    let lists: [(&str, &[&str]); 6] = [
        ("subjectKinds", &builder::SUBJECT_KINDS),
        ("fgaStages", &builder::FGA_STAGES),
        ("fgaIssuanceStages", &builder::FGA_ISSUANCE_STAGES),
        ("umaLayers", &builder::UMA_LAYERS),
        ("umaStages", &builder::UMA_STAGES),
        ("umaClaimSources", &builder::UMA_CLAIM_SOURCES),
    ];
    for (name, list) in lists {
        if texts(&r[name]) != list {
            failures.push(format!("{}: {:?}", name, list));
        }
    }
    let constants = [
        ("FGA_GRANT_ACTION", builder::FGA_GRANT_ACTION),
        ("UMA_PERMISSION_ACTION", builder::UMA_PERMISSION_ACTION),
        ("UMA_FGA_ACTION", builder::UMA_FGA_ACTION),
        ("UMA_GRANT_TYPE", builder::UMA_GRANT_TYPE),
    ];
    for (name, value) in constants {
        if text(&r["constants"][name]) != value {
            failures.push(format!("{}: {}", name, value));
        }
    }
    let mut requests_out = Vec::new();
    for (i, row) in r["rows"].as_array().unwrap().iter().enumerate() {
        *checked.entry("requests").or_default() += 1;
        let built = request_json(&build_row(row));
        // PINNED: Node's `authzen()` spells a missing action name or
        // resource id `"undefined"`; this crate sends `""` (builder.rs's
        // `authzen()` argues it). Equal but for that, it is the known
        // disagreement, counted, and anything else still fails.
        let pinned = row["method"] != "ops"
            && row["built"]
                .to_string()
                .contains("\"lexical\":\"undefined\"")
            && serde_json::from_str::<Json>(
                &row["built"]
                    .to_string()
                    .replace("\"lexical\":\"undefined\"", "\"lexical\":\"\""),
            )
            .ok()
                == Some(built.clone());
        if pinned {
            *checked.entry("requests pinned (undefined)").or_default() += 1;
        } else if built != row["built"] {
            failures.push(format!(
                "request {} ({}): built\n{}\nNode\n{}",
                i, row["method"], built, row["built"]
            ));
        }
        requests_out.push(json!({ "row": i, "built": built }));
    }
    out.insert("requests".into(), Json::Array(requests_out));

    // THE ACCESS PEP.
    let name = text(&v["access"]["name"]);
    let policy = access::built_in(&name, &Parameters::default()).unwrap();
    let mut access_out = Vec::new();
    for (i, row) in v["access"]["rows"].as_array().unwrap().iter().enumerate() {
        *checked.entry("access").or_default() += 1;
        let q = question(&row["asked"]);
        let held = texts(&row["held"]);
        let required = texts(&row["required"]);
        let built = request_json(&access::request(&q, &held, &required));
        if built != row["request"] {
            failures.push(format!(
                "access {}: request\n{}\nNode\n{}",
                i, built, row["request"]
            ));
        }
        let pip = Pip(rows_of(&row["asked"]["pip"]));
        let options = EvaluationOptions {
            resolver: Some(&pip),
            ..EvaluationOptions::default()
        };
        let answer =
            access::decide_with(&policy, &q, &held, &required, &options);
        if answer.allowed != (row["allowed"] == true)
            || answer.decision.as_str() != text(&row["decision"])
            || answer.why != text(&row["why"])
        {
            failures.push(format!(
                "access {}: {} {} \"{}\", Node {} {} \"{}\"",
                i,
                answer.allowed,
                answer.decision.as_str(),
                answer.why,
                row["allowed"],
                row["decision"],
                text(&row["why"])
            ));
        }
        access_out.push(json!({ "row": i, "request": built,
            "allowed": answer.allowed, "decision": answer.decision.as_str(),
            "why": answer.why }));
    }
    out.insert("access".into(), Json::Array(access_out));

    eprintln!("checked against Node: {:?}", checked);
    if std::env::var("STS_WRITE_VECTORS").as_deref() == Ok("1") {
        std::fs::write(
            Path::new(&dir).join("xacml-rust.json"),
            serde_json::to_string(&Json::Object(out)).unwrap(),
        )
        .unwrap();
    }
    assert!(
        failures.is_empty(),
        "{} disagreement(s) with Node:\n{}",
        failures.len(),
        failures
            .iter()
            .take(40)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// Every identifier `vocabulary` declares, by name — the table Node's
/// `VOCABULARY` is compared with, whole.
fn vocabulary_table() -> BTreeMap<&'static str, &'static str> {
    let source = include_str!("../src/builder.rs");
    let start = source.find("pub mod vocabulary {").unwrap();
    let end = start + source[start..].find("\n}\n").unwrap();
    let mut table = BTreeMap::new();
    let block = &source[start..end];
    let mut rest = block;
    while let Some(at) = rest.find("pub const ") {
        rest = &rest[at + "pub const ".len()..];
        let name_end = rest.find(':').unwrap();
        let name = &rest[..name_end];
        let open = rest.find('"').unwrap();
        let close = open + 1 + rest[open + 1..].find('"').unwrap();
        let uri = &rest[open + 1..close];
        table.insert(name, uri);
        rest = &rest[close..];
    }
    // A spot check that the table is the module's, not just its text.
    assert_eq!(table.get("ROLE").copied(), Some(vocabulary::ROLE));
    assert_eq!(
        table.get("UMA_RPT_PRESENTED").copied(),
        Some(vocabulary::UMA_RPT_PRESENTED)
    );
    table
}
