// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The sign-out against Node: `logout-node.json`, which
//! `tests/tools/logout-vectors.js` records by driving Node's own `Logout`
//! over a fake of every module it reads, each call recorded. Each step is
//! replayed here against a Rust `Logout` whose every port answers with
//! what Node's port answered: the Rust crate must make the SAME calls, in
//! the same order, with the same arguments — which sessions it ends and
//! with what words and initiating entity, which tokens it revokes, which
//! relying parties it plans for, which cookies it clears, what it audits —
//! and give the same answer.
//!
//! It also opens the result Node sealed, draws the fan-out Node drew, and
//! with `STS_WRITE_VECTORS=1` writes `logout-rust.json`: a result this
//! crate sealed, which `tests/rust_crypto_vectors.js` opens with Node's.
//!
//! The directory is `STS_CRYPTO_VECTORS`, never committed; unset, the test
//! says so and passes.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::{Arc, Mutex};

use serde_json::{json, Map, Value};
use sts_logout::ports::*;
use sts_logout::{Logout, LogoutDeps, TerminateOptions};

fn vectors() -> Option<(Value, std::path::PathBuf)> {
    let dir =
        std::path::PathBuf::from(std::env::var("STS_CRYPTO_VECTORS").ok()?);
    let text = std::fs::read_to_string(dir.join("logout-node.json")).ok()?;
    // The generator's stdout may carry the service's log lines.
    let text: String = text
        .lines()
        .filter(|l| !l.starts_with("{\"name\""))
        .collect::<Vec<_>>()
        .join("\n");
    Some((serde_json::from_str(&text).ok()?, dir))
}

/// Every port, answered from one step's recording.
struct Replay {
    calls: Mutex<Vec<Value>>,
    at: Mutex<usize>,
    problems: Mutex<Vec<String>>,
    settings: Value,
    product: bool,
    now: f64,
    realm: String,
    prefix: String,
    secret: String,
}

impl Replay {
    fn new(v: &Value, case: &Value, step: &Value) -> Replay {
        Replay {
            calls: Mutex::new(
                step["calls"].as_array().cloned().unwrap_or_default(),
            ),
            at: Mutex::new(0),
            problems: Mutex::new(Vec::new()),
            settings: case["settings"].clone(),
            product: case["product"].as_bool().unwrap_or(false),
            now: v["now"].as_f64().unwrap(),
            realm: v["realm"].as_str().unwrap_or("").to_string(),
            prefix: v["prefix"].as_str().unwrap_or("").to_string(),
            secret: v["secret"].as_str().unwrap().to_string(),
        }
    }

    fn call(&self, port: &str, method: &str, args: Value) -> Value {
        let calls = self.calls.lock().unwrap();
        let mut at = self.at.lock().unwrap();
        let Some(next) = calls.get(*at) else {
            self.problems.lock().unwrap().push(format!(
                "Rust called {}.{}({}) after Node's last call",
                port, method, args
            ));
            return Value::Null;
        };
        *at += 1;
        if next["port"] != json!(port)
            || next["method"] != json!(method)
            || next["args"] != args
        {
            self.problems.lock().unwrap().push(format!(
                "call {}: Rust {}.{}({}) where Node {}.{}({})",
                *at - 1,
                port,
                method,
                args,
                next["port"].as_str().unwrap_or(""),
                next["method"].as_str().unwrap_or(""),
                next["args"]
            ));
        }
        next["answer"].clone()
    }

    fn peek_is(&self, port: &str, method: &str) -> bool {
        let calls = self.calls.lock().unwrap();
        let at = self.at.lock().unwrap();
        calls.get(*at).is_some_and(|n| {
            n["port"] == json!(port) && n["method"] == json!(method)
        })
    }

    fn finish(&self) -> Vec<String> {
        let mut out = self.problems.lock().unwrap().clone();
        let calls = self.calls.lock().unwrap();
        let at = *self.at.lock().unwrap();
        if at < calls.len() {
            out.push(format!(
                "Node went on to {} more call(s), the next {}.{}({})",
                calls.len() - at,
                calls[at]["port"].as_str().unwrap_or(""),
                calls[at]["method"].as_str().unwrap_or(""),
                calls[at]["args"]
            ));
        }
        out
    }
}

fn truthy(v: &Value) -> bool {
    sts_logout::js::truthy(Some(v))
}

fn list(v: Value) -> Vec<Value> {
    v.as_array().cloned().unwrap_or_default()
}

fn opt(v: Value) -> Option<Value> {
    if v.is_null() {
        None
    } else {
        Some(v)
    }
}

fn text(v: Value) -> String {
    sts_logout::js::string_of(Some(&v))
}

fn map(v: Value) -> Map<String, Value> {
    v.as_object().cloned().unwrap_or_default()
}

const REQ: &str = "[request]";
const RES: &str = "[response]";

impl AuthnPort for Replay {
    fn session_window_on(&self) -> bool {
        truthy(&self.call("authn", "sessionWindowOn", json!([])))
    }
    fn sessions_held_under(&self, u: &str, s: &str) -> Option<Vec<Value>> {
        opt(self.call("authn", "sessionsHeldUnder", json!([u, s]))).map(list)
    }
    fn sessions_matching(&self) -> Option<Vec<Value>> {
        opt(self.call("authn", "sessionsMatching", json!([null]))).map(list)
    }
    fn session_by_id(&self, id: &str) -> Option<Value> {
        opt(self.call("authn", "sessionById", json!([id])))
    }
    fn session_view(&self, s: &Value) -> Value {
        self.call("authn", "sessionView", json!([s]))
    }
    fn session_started_at(&self, s: &Value) -> f64 {
        self.call("authn", "sessionStartedAt", json!([s]))
            .as_f64()
            .unwrap_or(0.0)
    }
    fn end_session_by_id(&self, id: &str, via: &str, e: &str) -> bool {
        truthy(&self.call("authn", "endSessionById", json!([id, via, e])))
    }
    fn note_session_changed(&self, s: &Value) {
        self.call("authn", "noteSessionChanged", json!([s]));
    }
    fn rewrite_session(&self, _s: &Value) {}
    fn multiple_accounts(&self) -> bool {
        truthy(&self.call("authn", "multipleAccounts", json!([])))
    }
    fn hint_account_key(&self, _a: &Asked, key: &str) {
        self.call("authn", "hintAccountKey", json!([REQ, key]));
    }
    fn hint_account(&self, _a: &Asked, hint: &Value) {
        self.call("authn", "hintAccount", json!([REQ, hint]));
    }
    fn session_of(&self, _a: &Asked) -> Option<Value> {
        opt(self.call("authn", "sessionOf", json!([REQ])))
    }
    fn signed_in_accounts(&self, _a: &Asked) -> Vec<Value> {
        list(self.call("authn", "signedInAccounts", json!([REQ])))
    }
    fn after_account_sign_out(&self, _a: &Asked, _r: &mut Reply) {
        self.call("authn", "afterAccountSignOut", json!([REQ, RES]));
    }
    fn clear_session_cookie(&self, _r: &mut Reply) {
        self.call("authn", "clearSessionCookie", json!([RES]));
    }
    fn clear_site_data_after_sign_out(&self, _a: &Asked, _r: &mut Reply) {
        self.call("authn", "clearSiteDataAfterSignOut", json!([REQ, RES]));
    }
    fn arrival(&self, _a: &Asked, _r: &mut Reply) {}
    fn begin_authentication(
        &self,
        opts: &Value,
        asked: Option<&Asked>,
    ) -> String {
        let mut o = opts.clone();
        if asked.is_some() {
            o["request"] = json!(REQ);
        }
        text(self.call("authn", "beginAuthentication", json!([o])))
    }
    fn last_authenticated_at(&self, s: &Value) -> f64 {
        self.call("authn", "lastAuthenticatedAt", json!([s]))
            .as_f64()
            .unwrap_or(0.0)
    }
    fn session_names_factor(&self, s: &Value, f: &Value) -> bool {
        truthy(&self.call("authn", "sessionNamesFactor", json!([s, f])))
    }
}

impl StatsPort for Replay {
    fn holder_key_of(&self, u: &Value, s: &Value) -> String {
        text(self.call("stats", "holderKeyOf", json!([u, s])))
    }
    fn identity_key_of(&self, n: &str) -> String {
        text(self.call("stats", "identityKeyOf", json!([n])))
    }
    fn holdings_of(&self, keys: &[String]) -> Map<String, Value> {
        map(self.call("stats", "holdingsOf", json!([keys])))
    }
    fn revoke(&self, jti: &str, why: &str, opts: &Value) -> bool {
        truthy(&self.call("stats", "revoke", json!([jti, why, opts])))
    }
    fn artifact_by_key(&self, key: &str) -> Option<Value> {
        opt(self.call("stats", "artifactByKey", json!([key])))
    }
    fn revoke_artifact(&self, r: &Value, why: &str) -> bool {
        truthy(&self.call("stats", "revokeArtifact", json!([r, why])))
    }
}

impl FrontChannelPort for Replay {
    fn clients_of(&self, s: &Value) -> Vec<Value> {
        list(self.call("frontchannel", "clientsOf", json!([s])))
    }
    fn notifications_for(&self, s: &Value, i: &str) -> Vec<Value> {
        list(self.call("frontchannel", "notificationsFor", json!([s, i])))
    }
    fn render(&self, n: &[Value]) -> String {
        text(self.call("frontchannel", "render", json!([n])))
    }
    fn frame_origins_of(&self, n: &[Value]) -> Vec<String> {
        list(self.call("frontchannel", "frameOriginsOf", json!([n])))
            .into_iter()
            .map(text)
            .collect()
    }
}

impl BackchannelPort for Replay {
    fn mark(&self) -> Value {
        self.call("backchannel", "mark", json!([]))
    }
    fn plan(&self, s: &Value, o: &Value) -> Vec<Value> {
        list(self.call("backchannel", "plan", json!([s, o])))
    }
    fn dispatch(&self, p: &[Value]) {
        self.call("backchannel", "dispatch", json!([p]));
    }
    fn deliveries_for(&self, ids: &[String], m: &Value) -> Vec<Value> {
        list(self.call("backchannel", "deliveriesFor", json!([ids, m])))
    }
    fn summarize(&self, r: &[Value]) -> String {
        text(self.call("backchannel", "summarize", json!([r])))
    }
    fn render(&self, r: &[Value]) -> String {
        text(self.call("backchannel", "render", json!([r])))
    }
}

impl WsFedPort for Replay {
    fn cleanup_targets_for(&self, s: &Value) -> Vec<Value> {
        list(self.call("wsfed", "cleanupTargetsFor", json!([s])))
    }
}

impl Saml2Port for Replay {
    fn logout_targets_for(&self, s: &Value) -> Vec<Value> {
        list(self.call("saml2Sso", "logoutTargetsFor", json!([s])))
    }
}

impl FederationSloPort for Replay {
    fn can_tell_partner(&self, h: &Value) -> Value {
        self.call("federationSlo", "canTellPartner", json!([h]))
    }
    fn partner_logout_for(&self, s: &Value, b: &str) -> Value {
        self.call("federationSlo", "partnerLogoutFor", json!([s, b]))
    }
    fn render_partner_logouts(&self, t: &[Value]) -> String {
        text(self.call("federationSlo", "renderPartnerLogouts", json!([t])))
    }
}

impl OAuth2Port for Replay {
    fn outstanding_codes_for(&self, k: &str) -> Vec<Value> {
        list(self.call("oauth2", "outstandingCodesFor", json!([k])))
    }
    fn drop_code(&self, c: &str) {
        self.call("oauth2", "dropCode", json!([c]));
    }
    fn issuer_of(&self, b: &str) -> String {
        text(self.call("oauth2", "issuerOf", json!([b])))
    }
}

impl Oid4vcPort for Replay {
    fn pre_authorized_codes(&self) -> Vec<(String, Value)> {
        list(self.call("vcOffers", "preAuthorizedCodes", json!([])))
            .into_iter()
            .map(|p| (text(p[0].clone()), p[1].clone()))
            .collect()
    }
    fn delete_pre_authorized_code(&self, d: &str) {
        self.call("vcOffers", "deleteDigest", json!([d]));
    }
    fn sign_ins_awaiting_collection(&self) -> Vec<Value> {
        list(self.call("vcVerifier", "signInsAwaitingCollection", json!([])))
    }
    fn withdraw_sign_in(&self, s: &str, w: &str) -> bool {
        truthy(&self.call("vcVerifier", "withdrawSignIn", json!([s, w])))
    }
    fn rows_for_subject(&self, s: &str) -> Vec<Value> {
        list(self.call("vcIssued", "rowsForSubject", json!([s])))
    }
    fn disown(&self, k: &str, w: &str) -> bool {
        truthy(&self.call("vcIssued", "disown", json!([k, w])))
    }
}

impl Krb5Port for Replay {
    fn realm(&self) -> String {
        text(self.call("krb5Principals", "REALM", json!([])))
    }
    fn kerberos_realm_of(&self) -> Value {
        self.call("krb5Principals", "kerberosRealmOf", json!([]))
    }
    fn signed_out_at(&self, n: &[String], r: &str) -> Value {
        self.call("krb5Principals", "signedOutAt", json!([n, r]))
    }
    fn find(&self, n: &[String], r: &str) -> Value {
        self.call("krb5Principals", "find", json!([n, r]))
    }
    fn sign_out(&self, n: &[String], r: &str) -> Value {
        self.call("krb5Principals", "signOut", json!([n, r]))
    }
}

impl LdapPort for Replay {
    fn bound_connections(&self) -> Vec<Value> {
        list(self.call("ldapServer", "boundConnections", json!([])))
    }
    fn drop_connections_for(&self, k: &str) -> Vec<Value> {
        list(self.call("ldapServer", "dropConnectionsFor", json!([k])))
    }
    fn sign_out_across_cluster(&self, k: &str) -> Value {
        self.call("ldapServer", "signOutAcrossCluster", json!([k]))
    }
}

impl GnapPort for Replay {
    fn grants_by_key(&self, k: &[String]) -> Map<String, Value> {
        map(self.call("gnapRevocation", "grantsByKey", json!([k])))
    }
    fn is_live(&self, g: &Value) -> bool {
        truthy(&self.call("gnapRevocation", "isLive", json!([g])))
    }
    fn grants_held_by(&self, k: &str) -> Vec<Value> {
        list(self.call("gnapRevocation", "grantsHeldBy", json!([k])))
    }
    fn live_tokens_of(&self, g: &Value) -> Vec<Value> {
        list(self.call("gnapRevocation", "liveTokensOf", json!([g])))
    }
    fn end_grant(&self, g: &Value, o: &Value) -> bool {
        truthy(&self.call("gnapRevocation", "endGrant", json!([g, o])))
    }
}

impl GrantsPort for Replay {
    fn list(&self) -> Vec<Value> {
        list(self.call("grantManagement", "list", json!([])))
    }
    fn revoke(&self, id: &str, k: &str, b: &str, e: &str) -> Value {
        self.call("grantManagement", "revoke", json!([id, k, b, e]))
    }
}

impl UmaPort for Replay {
    fn pcts_of(&self, s: &str) -> Vec<Value> {
        list(self.call("uma", "pctsOf", json!([s])))
    }
    fn delete_pct(&self, k: &str) -> bool {
        truthy(&self.call("uma", "deletePct", json!([k, true])))
    }
}

impl HostPort for Replay {
    fn setting(&self, key: &str) -> Value {
        match self.settings.get(key) {
            Some(v) => v.clone(),
            None => {
                self.problems.lock().unwrap().push(format!(
                    "a setting the vectors do not hold: {}",
                    key
                ));
                Value::Null
            }
        }
    }
    fn opens_test_controls(&self) -> bool {
        !self.product
    }
    fn verifies_credentials(&self) -> bool {
        self.product
    }
    fn audit(&self, row: &Value) {
        self.call("audit", "audit", json!([row]));
    }
    fn audit_failure(&self, code: &str, row: &Value) {
        self.call("audit", "failure", json!([code, row]));
    }
    fn subject_for_name(&self, n: &str) -> String {
        text(self.call("people", "subjectForName", json!([n])))
    }
    fn name_for_subject(&self, s: &str) -> String {
        text(self.call("people", "nameForSubject", json!([s])))
    }
    fn result_secret(&self) -> Vec<u8> {
        self.secret.as_bytes().to_vec()
    }
    fn subject_terminated(&self, r: &str, k: &str) {
        self.call("cells", "subjectTerminated", json!([r, k]));
    }
    // Node sends it only where `provider_commands` is loaded.
    fn person_signed_out(&self, k: &str) {
        if self.peek_is("providerCommands", "personSignedOut") {
            self.call("providerCommands", "personSignedOut", json!([k]));
        }
    }
    fn realm_id(&self) -> String {
        self.realm.clone()
    }
    fn realm_prefix(&self) -> String {
        self.prefix.clone()
    }
    fn now_ms(&self) -> f64 {
        self.now
    }
}

fn deps_of(r: Arc<Replay>) -> LogoutDeps {
    LogoutDeps {
        authn: r.clone(),
        stats: r.clone(),
        frontchannel: r.clone(),
        backchannel: r.clone(),
        wsfed: r.clone(),
        saml2: r.clone(),
        federation_slo: r.clone(),
        oauth2: r.clone(),
        oid4vc: r.clone(),
        krb5: r.clone(),
        ldap: r.clone(),
        gnap: r.clone(),
        grants: r.clone(),
        uma: r.clone(),
        host: r,
    }
}

fn options_of(o: &Value) -> TerminateOptions {
    let s =
        |k: &str| o.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    TerminateOptions {
        issuer: s("issuer"),
        by: s("by"),
        actor: s("actor"),
        initiating_entity: s("initiatingEntity"),
        channel: s("channel"),
        base: s("base"),
        browser: o.get("browser") == Some(&json!(true)),
        no_provider_command: o.get("providerCommand") == Some(&json!(false)),
        spare_credentials: truthy(
            o.get("spareCredentials").unwrap_or(&Value::Null),
        ),
        quiet: truthy(o.get("quiet").unwrap_or(&Value::Null)),
    }
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| a.iter().map(|x| text(x.clone())).collect())
        .unwrap_or_default()
}

fn answered(a: sts_logout::signout::Answered) -> Value {
    let mut out = json!({ "status": a.status, "json": a.json });
    if let Some(code) = a.code {
        out["code"] = json!(code);
    }
    // Node's object is { status, code, json } with `code` only where set.
    let mut ordered = Map::new();
    ordered.insert("status".into(), out["status"].clone());
    if let Some(c) = out.get("code") {
        ordered.insert("code".into(), c.clone());
    }
    ordered.insert("json".into(), out["json"].clone());
    Value::Object(ordered)
}

fn subject_json(s: &sts_logout::signout::Subject) -> Value {
    if s.refused {
        return json!({ "refused": true, "asked": s.asked });
    }
    if s.key.is_empty() {
        return json!({});
    }
    if s.named {
        return json!({ "username": s.username, "key": s.key, "named": true });
    }
    json!({ "username": s.username, "key": s.key, "session": s.session })
}

fn run(logout: &Logout, step: &Value) -> Result<Value, String> {
    let a = &step["args"];
    let asked = Asked {
        query: map(step["query"].clone()),
        base: "https://sts.example".into(),
        ..Asked::default()
    };
    let mut reply = Reply::default();
    let body = map(a.get("body").cloned().unwrap_or(json!({})));
    match step["op"].as_str().unwrap() {
        "inventoryFor" => logout.inventory_for(
            a["key"].as_str().unwrap(),
            a["issuer"].as_str().unwrap_or(""),
        ),
        "terminate" => logout.terminate(
            a["key"].as_str().unwrap(),
            &strings(&a["selection"]),
            &options_of(&a["opts"]),
        ),
        "heldIds" => logout
            .held_ids(a["key"].as_str().unwrap())
            .map(|ids| json!(ids)),
        "heldIdsFor" => logout.held_ids_for(&strings(&a["keys"])).map(|all| {
            Value::Object(all.into_iter().map(|(k, v)| (k, json!(v))).collect())
        }),
        "terminateEach" => {
            let items: Vec<(String, Vec<String>)> = a["list"]
                .as_array()
                .unwrap()
                .iter()
                .map(|one| {
                    (text(one["key"].clone()), strings(&one["selection"]))
                })
                .collect();
            logout
                .terminate_each(&items, &options_of(&a["opts"]))
                .map(Value::Array)
        }
        "revokeGrantsOf" => {
            let ids = a["opts"].get("sessionIds").map(strings);
            let ids = a.get("sessionIds").map(strings).or(ids);
            logout.revoke_grants_of(
                a["key"].as_str().unwrap(),
                ids.as_deref(),
                &options_of(&a["opts"]),
            )
        }
        "endFactorSessions" => Ok(logout.end_factor_sessions(
            a["username"].as_str().unwrap(),
            &a["factor"],
            &options_of(&a["opts"]),
        )),
        "endPartnerSession" => {
            logout.end_partner_session(&a["session"], &options_of(&a["opts"]))
        }
        "signOutView" => logout.sign_out_view(&asked).map(answered),
        "signOutAct" => {
            logout.sign_out_act(&asked, &mut reply, &body).map(answered)
        }
        "signOutAccountsAct" => logout
            .sign_out_accounts_act(&asked, &mut reply, &body)
            .map(answered),
        "subjectOf" => {
            Ok(subject_json(&logout.subject_of(&asked, Some(&body))))
        }
        other => Err(format!("no such op {}", other)),
    }
}

/// The sealed result's member that a seal-time `exp` makes differ.
fn without_seal(v: &Value) -> Value {
    let mut v = v.clone();
    if let Some(form) = v.pointer_mut("/json/form/fields/result") {
        *form = json!("[sealed]");
    }
    v
}

#[test]
fn every_act_makes_nodes_calls_and_gives_nodes_answer() {
    let Some((v, dir)) = vectors() else {
        eprintln!("STS_CRYPTO_VECTORS has no logout-node.json; skipped.");
        return;
    };
    let mut failures = Vec::new();
    let mut steps = 0;
    for case in v["cases"].as_array().unwrap() {
        for step in case["steps"].as_array().unwrap() {
            steps += 1;
            let r = Arc::new(Replay::new(&v, case, step));
            let logout = Logout::new(deps_of(r.clone()));
            let got = run(&logout, step);
            let label = format!(
                "{} / {}",
                case["name"].as_str().unwrap(),
                step["name"].as_str().unwrap()
            );
            match (&got, step["threw"].as_str()) {
                (Err(e), Some(t)) if e == t => {}
                (Err(e), _) => {
                    failures.push(format!("{}: Rust threw {}", label, e))
                }
                (Ok(_), Some(t)) => {
                    failures.push(format!("{}: Node threw {}", label, t))
                }
                (Ok(answer), None) => {
                    if without_seal(answer) != without_seal(&step["answer"]) {
                        failures.push(format!(
                            "{}: the answer differs\n  rust {}\n  node {}",
                            label, answer, step["answer"]
                        ));
                    }
                }
            }
            for p in r.finish() {
                failures.push(format!("{}: {}", label, p));
            }
        }
    }
    // THE SEALED RESULT, opened, and the fan-out of one, drawn.
    let sealed = &v["sealed"];
    let r = Arc::new(Replay::new(&v, &json!({ "settings": {} }), &json!({})));
    let logout = Logout::new(deps_of(r));
    match logout.open_result(sealed["sealed"].as_str().unwrap()) {
        Ok(result) if result == sealed["result"] => {}
        other => failures.push(format!("Node's sealed result: {:?}", other)),
    }
    let fan = Logout::new(fan_deps(Arc::new(FanStub::of(&v))))
        .fan_out_of(&[&sealed["result"]]);
    let policy: Map<String, Value> = fan
        .policy
        .iter()
        .map(|(k, x)| (k.clone(), json!(x)))
        .collect();
    if json!({ "html": fan.html, "policy": policy }) != sealed["fanOut"] {
        failures.push(format!(
            "the fan-out differs\n  rust {}\n  node {}",
            json!({ "html": fan.html, "policy": policy }),
            sealed["fanOut"]
        ));
    }
    if std::env::var("STS_WRITE_VECTORS").ok().as_deref() == Some("1") {
        let result = sealed["result"].clone();
        let seal = logout.seal_result(&result);
        let stored = sealed["result"].clone();
        let out = json!({ "now": v["now"], "secret": v["secret"],
            "sealed": seal, "result": {
                "key": stored["key"], "scope": stored["scope"],
                "message": stored["message"],
                "terminated": stored["terminated"],
                "skipped": stored["skipped"], "unknown": stored["unknown"],
                "notifications": stored["notifications"],
                "cleanups": stored["cleanups"],
                "logoutRequests": stored["logoutRequests"],
                "partnerLogouts": stored["partnerLogouts"],
                "backchannel": stored["backchannel"] } });
        std::fs::write(
            dir.join("logout-rust.json"),
            serde_json::to_string_pretty(&out).unwrap(),
        )
        .unwrap();
    }
    assert!(
        failures.is_empty(),
        "{} of {} step(s) differ from Node:\n{}",
        failures.len(),
        steps,
        failures.join("\n")
    );
    eprintln!("logout: {} step(s) replayed against Node's.", steps);
}

/// The fan-out's three port answers, as the vectors' fakes draw them.
struct FanStub {
    inner: Replay,
}

impl FanStub {
    fn of(v: &Value) -> FanStub {
        FanStub {
            inner: Replay::new(v, &json!({ "settings": {} }), &json!({})),
        }
    }
}

impl FrontChannelPort for FanStub {
    fn clients_of(&self, _s: &Value) -> Vec<Value> {
        Vec::new()
    }
    fn notifications_for(&self, _s: &Value, _i: &str) -> Vec<Value> {
        Vec::new()
    }
    fn render(&self, n: &[Value]) -> String {
        let frames: String = n
            .iter()
            .map(|one| match one["url"].as_str() {
                Some(u) if !u.is_empty() => {
                    format!("<iframe src=\"{}\"></iframe>", u)
                }
                _ => String::new(),
            })
            .collect();
        format!("<h2>Front-channel</h2>{}", frames)
    }
    fn frame_origins_of(&self, n: &[Value]) -> Vec<String> {
        n.iter()
            .filter_map(|one| one["url"].as_str().filter(|u| !u.is_empty()))
            .map(|u| {
                let rest = u.split_once("://").map_or("", |(_, r)| r);
                let host = rest.split(['/', '?', '#']).next().unwrap_or("");
                format!(
                    "{}://{}",
                    u.split("://").next().unwrap_or(""),
                    host.to_ascii_lowercase()
                )
            })
            .collect()
    }
}

impl BackchannelPort for FanStub {
    fn mark(&self) -> Value {
        Value::Null
    }
    fn plan(&self, _s: &Value, _o: &Value) -> Vec<Value> {
        Vec::new()
    }
    fn dispatch(&self, _p: &[Value]) {}
    fn deliveries_for(&self, _i: &[String], _m: &Value) -> Vec<Value> {
        Vec::new()
    }
    fn summarize(&self, _r: &[Value]) -> String {
        String::new()
    }
    fn render(&self, r: &[Value]) -> String {
        if r.is_empty() {
            String::new()
        } else {
            format!("<h2>Back-channel</h2><p>{}</p>", r.len())
        }
    }
}

macro_rules! via_inner {
    ($tr:ident { $($body:tt)* }) => {
        impl $tr for FanStub { $($body)* }
    };
}

via_inner!(AuthnPort {
    fn session_window_on(&self) -> bool { self.inner.session_window_on() }
    fn sessions_held_under(&self, u: &str, s: &str) -> Option<Vec<Value>> { self.inner.sessions_held_under(u, s) }
    fn sessions_matching(&self) -> Option<Vec<Value>> { self.inner.sessions_matching() }
    fn session_by_id(&self, id: &str) -> Option<Value> { self.inner.session_by_id(id) }
    fn session_view(&self, s: &Value) -> Value { self.inner.session_view(s) }
    fn session_started_at(&self, s: &Value) -> f64 { self.inner.session_started_at(s) }
    fn end_session_by_id(&self, id: &str, v: &str, e: &str) -> bool { self.inner.end_session_by_id(id, v, e) }
    fn note_session_changed(&self, s: &Value) { self.inner.note_session_changed(s) }
    fn rewrite_session(&self, s: &Value) { self.inner.rewrite_session(s) }
    fn multiple_accounts(&self) -> bool { self.inner.multiple_accounts() }
    fn hint_account_key(&self, a: &Asked, k: &str) { self.inner.hint_account_key(a, k) }
    fn hint_account(&self, a: &Asked, h: &Value) { self.inner.hint_account(a, h) }
    fn session_of(&self, a: &Asked) -> Option<Value> { self.inner.session_of(a) }
    fn signed_in_accounts(&self, a: &Asked) -> Vec<Value> { self.inner.signed_in_accounts(a) }
    fn after_account_sign_out(&self, a: &Asked, r: &mut Reply) { self.inner.after_account_sign_out(a, r) }
    fn clear_session_cookie(&self, r: &mut Reply) { self.inner.clear_session_cookie(r) }
    fn clear_site_data_after_sign_out(&self, a: &Asked, r: &mut Reply) { self.inner.clear_site_data_after_sign_out(a, r) }
    fn arrival(&self, a: &Asked, r: &mut Reply) { self.inner.arrival(a, r) }
    fn begin_authentication(&self, o: &Value, a: Option<&Asked>) -> String { self.inner.begin_authentication(o, a) }
    fn last_authenticated_at(&self, s: &Value) -> f64 { self.inner.last_authenticated_at(s) }
    fn session_names_factor(&self, s: &Value, f: &Value) -> bool { self.inner.session_names_factor(s, f) }
});

fn fan_deps(stub: Arc<FanStub>) -> LogoutDeps {
    let inner: Arc<Replay> = Arc::new(Replay {
        calls: Mutex::new(Vec::new()),
        at: Mutex::new(0),
        problems: Mutex::new(Vec::new()),
        settings: json!({}),
        product: false,
        now: stub.inner.now,
        realm: stub.inner.realm.clone(),
        prefix: stub.inner.prefix.clone(),
        secret: stub.inner.secret.clone(),
    });
    LogoutDeps {
        authn: stub.clone(),
        stats: inner.clone(),
        frontchannel: stub.clone(),
        backchannel: stub,
        wsfed: inner.clone(),
        saml2: inner.clone(),
        federation_slo: inner.clone(),
        oauth2: inner.clone(),
        oid4vc: inner.clone(),
        krb5: inner.clone(),
        ldap: inner.clone(),
        gnap: inner.clone(),
        grants: inner.clone(),
        uma: inner.clone(),
        host: inner,
    }
}

#[test]
fn fan_deps_build() {
    let v = json!({ "now": 0.0, "secret": "s", "realm": "", "prefix": "" });
    let stub = Arc::new(FanStub::of(&v));
    let logout = Logout::new(fan_deps(stub));
    assert!(logout.fan_out_of(&[&json!({})]).html.is_empty());
}
