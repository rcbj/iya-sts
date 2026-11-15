// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The application register against Node: `applications-node.json`, which
//! `tests/tools/applications-vectors.js` records by driving Node's
//! `common/applications.js` over its in-memory directory. The Rust
//! directory starts from the entries Node's started from, and every step is
//! made again here: the same answer (sentence for sentence), the same code,
//! the same entries under `ou=applications` afterwards, and the same
//! effects — the audit rows, the credential changes, the FGA hooks — in the
//! same order. What Node read outside the register (settings, the mode, a
//! parse) is answered from what it recorded; the random bytes a step drew
//! are handed back in order.
//!
//! With `STS_WRITE_VECTORS=1` the test writes `applications-rust.json`: the
//! entries Rust's register ended with and its view of each, which
//! `tests/rust_crypto_vectors.js` reads back through Node's register.
//!
//! The directory is `STS_CRYPTO_VECTORS`, never committed; unset, the test
//! says so and passes.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use indexmap::IndexMap;
use serde_json::{json, Map, Value};
use sts_core::errors::ErrorCode;
use sts_directory::ports::{generalized_time_of, Clock};
use sts_directory::{Directory, Entry};
use sts_registers::applications::actions::{ActionPorts, NoActionPorts};
use sts_registers::applications::{
    AppEffects, AppEnv, ApplicationRegistry, FgaLifecycle, Record,
};

fn vectors() -> Option<Value> {
    let dir = std::env::var("STS_CRYPTO_VECTORS").ok()?;
    let path = std::path::Path::new(&dir).join("applications-node.json");
    let text = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str(&text).ok()
}

/// The environment, answered from what Node read.
struct Replay {
    now: Arc<AtomicI64>,
    v: Value,
    random: Mutex<Vec<(String, bool)>>,
}

impl Replay {
    fn listed<'a>(&'a self, list: &str) -> &'a [Value] {
        self.v[list].as_array().map(Vec::as_slice).unwrap_or(&[])
    }
}

impl AppEnv for Replay {
    fn now_ms(&self) -> i64 {
        self.now.load(Ordering::SeqCst)
    }

    fn setting(&self, key: &str) -> Value {
        self.v["settings"].get(key).cloned().unwrap_or(Value::Null)
    }

    fn mode(&self, predicate: &str) -> bool {
        self.v["modes"][predicate].as_bool().unwrap_or(false)
    }

    fn parse_as(&self, key: &str, raw: &str) -> Result<Value, String> {
        let found = self.listed("parses").iter().find(|p| {
            p["key"].as_str() == Some(key) && p["raw"].as_str() == Some(raw)
        });
        match found {
            Some(p) if p["answer"]["ok"] == json!(true) => {
                Ok(p["answer"]["value"].clone())
            }
            Some(p) => Err(p["answer"]["problem"]
                .as_str()
                .unwrap_or("")
                .to_string()),
            None => Err(format!("(Node never parsed {key}={raw})")),
        }
    }

    fn allows_value(&self, key: &str, value: &Value) -> bool {
        self.listed("allows")
            .iter()
            .find(|a| a["key"].as_str() == Some(key) && &a["value"] == value)
            .map(|a| a["answer"] == json!(true))
            .unwrap_or(true)
    }

    fn write_refusal_reason(&self, key: &str) -> String {
        self.v["refusalReasons"][key].as_str().unwrap_or("").to_string()
    }

    fn random_bytes(&self, n: usize) -> Vec<u8> {
        let mut held = self.random.lock().unwrap();
        for (hex, used) in held.iter_mut() {
            if !*used && hex.len() == n * 2 {
                *used = true;
                return (0..n)
                    .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
                    .collect();
            }
        }
        panic!("Node drew no {n} random bytes here");
    }

    fn sha256_hex(&self, text: &str) -> String {
        let mut d = sts_crypto::raw_sig::Sha256Digester::new().unwrap();
        d.update(text.as_bytes()).unwrap();
        d.hex().unwrap()
    }

    fn is_sealed(&self, _value: &str) -> bool {
        false
    }

    fn keystore_persists(&self) -> bool {
        self.v["persists"] == json!(true)
    }

    fn seals_client_secrets(&self) -> bool {
        false
    }

    fn seal(&self, _text: &str, _label: &str) -> Option<String> {
        None
    }

    fn open(&self, _text: &str, _label: &str) -> Option<String> {
        None
    }

    fn in_force(&self, key: &str, value: &Value) -> Value {
        self.listed("inForce")
            .iter()
            .find(|a| a["key"].as_str() == Some(key) && &a["value"] == value)
            .map(|a| a["answer"].clone())
            .unwrap_or_else(|| value.clone())
    }
}

/// The effects, recorded as Node's builder records them.
#[derive(Default)]
struct Effects {
    seen: Mutex<Vec<Value>>,
    scope_kept: Vec<Value>,
    ssf_events: Vec<Value>,
    kerberos_realms: Vec<Value>,
}

impl Effects {
    fn push(&self, row: Value) {
        self.seen.lock().unwrap().push(row);
    }

    fn take(&self) -> Vec<Value> {
        std::mem::take(&mut *self.seen.lock().unwrap())
    }
}

impl AppEffects for Effects {
    fn audit(&self, row: &Value) {
        self.push(json!({ "kind": "audit", "row": row }));
    }

    fn failure(&self, code: ErrorCode, row: &Value) {
        self.push(json!({ "kind": "failure", "code": code.as_str(),
                          "row": row }));
    }

    fn credential_changed(&self, notice: &Value) {
        self.push(json!({ "kind": "credentialChanged", "notice": notice }));
    }

    fn certificate_changed(&self, notice: &Value) {
        self.push(json!({ "kind": "certificateChanged", "notice": notice }));
    }

    fn application_removed(&self, identifier: &str, dn: &str, via: &str) {
        self.push(json!({ "kind": "applicationRemoved",
                          "identifier": identifier, "dn": dn, "via": via }));
    }

    fn end_gnap_grants(&self, _: &str, _: bool, _: &Value) -> i64 {
        0
    }

    fn claims_fan_out(
        &self,
        identifier: &str,
        attribute: &str,
        removed: &str,
        _audience: &str,
    ) {
        self.push(json!({
            "kind": "claimsFanOut",
            "reasonAdmin": format!(
                "\"{removed}\" is no longer granted through {attribute} on \
                 \"{identifier}\""
            ),
        }));
    }

    fn scope_kept(&self, scope: &str, identifier: &str) -> bool {
        self.scope_kept
            .iter()
            .find(|s| {
                s["scope"].as_str() == Some(scope)
                    && s["identifier"].as_str() == Some(identifier)
            })
            .map(|s| s["kept"] == json!(true))
            .unwrap_or(true)
    }

    fn certificate_registration_problem(
        &self,
        _usage: &str,
        _der: &[u8],
    ) -> Option<(String, ErrorCode)> {
        None
    }

    fn dial_problem(&self, _url: &str) -> String {
        String::new()
    }

    fn ssf_event_known(&self, uri: &str) -> bool {
        self.ssf_events.contains(&json!(uri))
    }

    fn kerberos_accepts_realm(&self, realm: &str) -> bool {
        self.kerberos_realms.contains(&json!(realm))
    }
}

/// The FGA slot, recorded as Node's builder records it.
struct Fga(Arc<Effects>);

impl FgaLifecycle for Fga {
    fn created(&self, identifier: &str, actor: &str) -> Value {
        self.0.push(json!({ "kind": "fga", "which": "created",
                            "identifier": identifier, "actor": actor,
                            "policy": "" }));
        json!({ "ok": true })
    }

    fn deleted(&self, identifier: &str, actor: &str, policy: &str) -> Value {
        self.0.push(json!({ "kind": "fga", "which": "deleted",
                            "identifier": identifier, "actor": actor,
                            "policy": policy }));
        json!({ "ok": true })
    }
}

struct FixedClock(Arc<AtomicI64>);

impl Clock for FixedClock {
    fn generalized_time(&self) -> String {
        generalized_time_of(self.0.load(Ordering::SeqCst).div_euclid(1000))
    }
}

fn entry_of(v: &Value) -> Entry {
    let mut attributes = IndexMap::new();
    for (k, vals) in v["attributes"].as_object().unwrap() {
        attributes.insert(
            k.clone(),
            vals.as_array()
                .unwrap()
                .iter()
                .map(|s| s.as_str().unwrap().to_string())
                .collect(),
        );
    }
    let text = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
    Entry {
        dn: v["dn"].as_str().unwrap().to_string(),
        attributes,
        origin: text("origin"),
        created_at: text("createdAt"),
        modified_at: text("modifiedAt"),
    }
}

fn json_of(e: &Entry) -> Value {
    let mut out = Map::new();
    out.insert("dn".into(), json!(e.dn));
    out.insert("attributes".into(), json!(e.attributes));
    if let Some(o) = &e.origin {
        out.insert("origin".into(), json!(o));
    }
    if let Some(c) = &e.created_at {
        out.insert("createdAt".into(), json!(c));
    }
    if let Some(m) = &e.modified_at {
        out.insert("modifiedAt".into(), json!(m));
    }
    Value::Object(out)
}

// Every `entryUUID`, however spelt, is the directory's random choice.
fn masked(v: &Value) -> Value {
    match v {
        Value::Object(o) => Value::Object(
            o.iter()
                .map(|(k, x)| {
                    if k.eq_ignore_ascii_case("entryuuid") {
                        (k.clone(), json!("(uuid)"))
                    } else {
                        (k.clone(), masked(x))
                    }
                })
                .collect(),
        ),
        Value::Array(l) => Value::Array(l.iter().map(masked).collect()),
        other => other.clone(),
    }
}

fn record_json(r: &Record) -> Value {
    json!({
        "identifier": r.identifier, "label": r.label, "name": r.name,
        "kinds": r.kinds, "protocols": r.protocols,
        "description": r.description, "firstAt": r.first_at,
        "lastAt": r.last_at, "authentications": r.authentications,
        "sessions": [], "users": [], "sessionCount": r.session_count,
        "userCount": r.user_count, "registered": r.registered,
        "fields": Value::Object(r.fields.clone()),
    })
}

fn reg_now(reg: &ApplicationRegistry) -> i64 {
    reg.env().now_ms()
}

fn s(v: &Value) -> String {
    v.as_str().unwrap_or("").to_string()
}

fn run_step(
    reg: &ApplicationRegistry,
    dir: &Arc<Mutex<Directory>>,
    ports: &dyn ActionPorts,
    op: &str,
    a: &[Value],
    node_settings: &Value,
) -> Option<(Value, Option<ErrorCode>)> {
    let marked = |m: sts_registers::outcome::Outcome| Some((m.answer, m.code));
    let plain = |v: Value| Some((v, None));
    match op {
        "seen" => plain(reg.seen(&a[0]).map(|r| record_json(&r)).unwrap_or(Value::Null)),
        "create" => marked(reg.create_application(&a[0])),
        "update" => marked(reg.update_application(&s(&a[0]), &a[1])),
        "confirmReturnAddress" => {
            marked(reg.confirm_return_address(&s(&a[0]), &a[1]))
        }
        "discardReturnAddress" => {
            marked(reg.discard_return_address(&s(&a[0]), &a[1]))
        }
        "addOwner" => marked(reg.add_owner(&s(&a[0]), &s(&a[1]))),
        "removeOwner" => marked(reg.remove_owner(&s(&a[0]), &s(&a[1]))),
        "ownerProtected" => plain(json!(reg.owner_protected(&s(&a[0])))),
        "setOwnerProtected" => marked(
            reg.set_owner_protected(&s(&a[0]), a[1] == json!(true)),
        ),
        "renameOwner" => plain(json!(reg.rename_owner(&s(&a[0]), &s(&a[1])))),
        "forgetOwner" => plain(json!(reg.forget_owner(&s(&a[0])))),
        "addClientSecret" => marked(reg.add_client_secret(&s(&a[0]), &a[1])),
        "removeClientSecret" => {
            marked(reg.remove_client_secret(&s(&a[0]), &a[1]))
        }
        "rotateClientSecret" => {
            marked(reg.rotate_client_secret(&s(&a[0]), &a[1]))
        }
        "regenerateClientSecret" => {
            marked(reg.regenerate_client_secret(&s(&a[0]), &a[1]))
        }
        "setFgaState" => marked(reg.set_fga_state(&s(&a[0]), &a[1], &a[2])),
        "fgaStateOf" => plain(reg.fga_state_of(&s(&a[0]))),
        "applicationsEnforcingFga" => {
            plain(json!(reg.applications_enforcing_fga()))
        }
        "get" => plain(reg.get(&s(&a[0])).unwrap_or(Value::Null)),
        "forClientId" => plain(reg.for_client_id(&s(&a[0])).unwrap_or(Value::Null)),
        "everyForClientId" => plain(json!(reg.every_for_client_id(&s(&a[0])))),
        "forAudience" => plain(reg.for_audience(&s(&a[0])).unwrap_or(Value::Null)),
        "forAppliesTo" => {
            plain(reg.for_applies_to(&s(&a[0])).unwrap_or(Value::Null))
        }
        "forServicePrincipal" => {
            plain(reg.for_service_principal(&s(&a[0])).unwrap_or(Value::Null))
        }
        "forPermission" => {
            plain(reg.for_permission(&s(&a[0])).unwrap_or(Value::Null))
        }
        "roleGatingFor" => {
            plain(reg.role_gating_for(&s(&a[0])).unwrap_or(Value::Null))
        }
        "holdsPermission" => {
            plain(json!(reg.holds_permission(&s(&a[0]), &s(&a[1]))))
        }
        "allowedScopesOf" => plain(
            reg.allowed_scopes_of(&s(&a[0]))
                .map(|l| json!(l))
                .unwrap_or(Value::Null),
        ),
        "isResourceServer" => plain(json!(reg.is_resource_server(&s(&a[0])))),
        "requiredRolesOf" => plain(json!(reg.required_roles_of(&s(&a[0])))),
        "applicationsNamingPolicy" => plain(json!(
            reg.applications_naming_policy(&s(&a[0]), &s(&a[1]))
        )),
        "applicationsDeclaredFor" => {
            plain(json!(reg.applications_declared_for(&s(&a[0]))))
        }
        "ownerValues" => plain(json!(reg.owner_values())),
        "count" => plain(json!(reg.count())),
        "list" => plain(json!(reg.list())),
        "isInternalIdentifier" => {
            plain(json!(reg.is_internal_identifier(&s(&a[0]))))
        }
        "deleteApplication" => marked(reg.delete_application(&s(&a[0]), &a[1])),
        "action" => {
            let protocols = a[1].as_array().map(|l| {
                l.iter().map(|x| s(x)).collect::<Vec<String>>()
            });
            marked(reg.applications_action(&a[0], protocols, "vector-admin", ports))
        }
        "listJson" => plain(reg.applications_list_json(
            a[0].as_object().unwrap(),
            // The page's settings block is sts-mgmt-api's, and is proved
            // there; Node's is handed in.
            node_settings.clone(),
        )),
        "rename" => {
            let mut d = dir.lock().unwrap();
            let base = d.realms()[0].base.clone();
            let old = format!("cn={},ou=applications,{}", s(&a[0]), base);
            let mut moved = d.remove_entry(0, &old, "an LDAP modify DN").unwrap();
            moved.dn = format!("cn=renamed-saml11,ou=applications,{}", base);
            // `adoptEntry()`: the entry as it was, stamped now.
            let at = generalized_time_of(reg_now(reg).div_euclid(1000));
            moved.created_at = Some(at.clone());
            moved.modified_at = Some(at);
            let dn = moved.dn.clone();
            d.restore("default", vec![moved]);
            plain(json!({ "dn": dn }))
        }
        _ => None,
    }
}

#[test]
fn the_application_register_answers_as_node_does() {
    let Some(v) = vectors() else {
        eprintln!("STS_CRYPTO_VECTORS has no applications-node.json; skipped");
        return;
    };
    let now = Arc::new(AtomicI64::new(v["start"].as_i64().unwrap()));
    let base = s(&v["base"]);
    let mut directory = Directory::new(&base)
        .with_clock(
            Arc::new(FixedClock(now.clone())),
            Arc::new(sts_directory::ports::CryptoUuids),
        );
    directory.restore(
        "default",
        v["initial"].as_array().unwrap().iter().map(entry_of).collect(),
    );
    let dir = Arc::new(Mutex::new(directory));
    let replay = Arc::new(Replay {
        now: now.clone(),
        v: v.clone(),
        random: Mutex::new(Vec::new()),
    });
    let effects = Arc::new(Effects {
        seen: Mutex::new(Vec::new()),
        scope_kept: v["scopeKept"].as_array().cloned().unwrap_or_default(),
        ssf_events: v["ssfEvents"].as_array().cloned().unwrap_or_default(),
        kerberos_realms: v["kerberosRealms"]
            .as_array()
            .cloned()
            .unwrap_or_default(),
    });
    let reg = ApplicationRegistry::new(
        Some(dir.clone()),
        replay.clone(),
        effects.clone(),
    );
    reg.set_fga_lifecycle(Some(Arc::new(Fga(effects.clone()))));
    let ports = NoActionPorts;
    let mut failures: Vec<String> = Vec::new();
    let mut ran = 0;
    for (i, step) in v["steps"].as_array().unwrap().iter().enumerate() {
        let op = s(&step["op"]);
        let args = step["args"].as_array().cloned().unwrap_or_default();
        now.store(step["now"].as_i64().unwrap(), Ordering::SeqCst);
        *replay.random.lock().unwrap() = step["random"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| (s(h), false))
            .collect();
        effects.take();
        let Some((answer, code)) = run_step(
            &reg,
            &dir,
            &ports,
            &op,
            &args,
            &step["answer"]["settings"],
        )
        else {
            continue;
        };
        // The end of the turn: the credential changes announced.
        reg.flush_credential_writes();
        ran += 1;
        let what = format!("step {i} ({op} {})", step["args"]);
        if masked(&answer) != masked(&step["answer"]) {
            failures.push(format!(
                "{what}: the answer\n  node {}\n  rust {}",
                masked(&step["answer"]),
                masked(&answer)
            ));
        }
        let code = code.map(|c| json!(c.as_str())).unwrap_or(Value::Null);
        if code != step["code"] {
            failures.push(format!(
                "{what}: the code — node {}, rust {}",
                step["code"], code
            ));
        }
        let got = effects.take();
        if masked(&json!(got)) != masked(&step["effects"]) {
            failures.push(format!(
                "{what}: the effects\n  node {}\n  rust {}",
                masked(&step["effects"]),
                masked(&json!(got))
            ));
        }
        let entries: Vec<Value> = {
            let d = dir.lock().unwrap();
            let container = format!("ou=applications,{}", base).to_lowercase();
            d.realms()[0]
                .entries
                .values()
                .filter(|e| {
                    e.dn.to_lowercase().ends_with(&format!(",{container}"))
                })
                .map(json_of)
                .collect()
        };
        if masked(&json!(entries)) != masked(&step["entries"]) {
            failures.push(format!(
                "{what}: the entries\n  node {}\n  rust {}",
                masked(&step["entries"]),
                masked(&json!(entries))
            ));
        }
    }
    if std::env::var("STS_WRITE_VECTORS").is_ok_and(|w| w == "1") {
        let d = dir.lock().unwrap();
        let container = format!("ou=applications,{}", base).to_lowercase();
        let rows: Vec<Value> = d.realms()[0]
            .entries
            .values()
            .filter(|e| e.dn.to_lowercase().ends_with(&format!(",{container}")))
            .cloned()
            .collect::<Vec<Entry>>()
            .into_iter()
            .map(|e| {
                let identifier = e
                    .attributes
                    .get("appidentifier")
                    .and_then(|l| l.first())
                    .cloned()
                    .unwrap_or_default();
                let mut row = json_of(&e);
                row["identifier"] = json!(identifier);
                row
            })
            .collect();
        drop(d);
        let rows: Vec<Value> = rows
            .into_iter()
            .map(|mut row| {
                row["view"] = reg.get(&s(&row["identifier"])).unwrap_or(Value::Null);
                row
            })
            .collect();
        let dir_out = std::env::var("STS_CRYPTO_VECTORS").unwrap();
        std::fs::write(
            std::path::Path::new(&dir_out).join("applications-rust.json"),
            serde_json::to_string(&json!({ "entries": rows })).unwrap(),
        )
        .unwrap();
    }
    assert!(ran > 0, "no step was replayed");
    assert!(
        failures.is_empty(),
        "{} of {} steps differ from Node:\n{}",
        failures.len(),
        ran,
        failures.join("\n")
    );
}
