// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The mail channel against Node: `auditmail-node.json`'s `mail`, which
//! `tests/tools/mail-vectors.js` writes from `common/mail*.ts`. Every
//! answer must be Node's: the language chain and order, every template's
//! verdict and Node's sentence, every message rendered and wrapped in
//! every language, every raw message composed and DKIM-signed byte for
//! byte, every refusal with its code and its sentence, and the requests
//! the uses hand the channel.
//!
//! With `STS_WRITE_VECTORS=1` it writes `mail-rust.json` — messages Rust
//! composed and signed — which `tests/rust_crypto_vectors.js` verifies in
//! Node. The directory is `STS_CRYPTO_VECTORS`, never committed; unset,
//! these tests say so and pass.

#![allow(clippy::unwrap_used, clippy::expect_used)] // a test file

use serde_json::{Map, Value as Json};
use sts_mail::templates::{Parts, Templates};

fn vectors() -> Option<Json> {
    let dir = std::env::var("STS_CRYPTO_VECTORS").ok()?;
    let path = std::path::Path::new(&dir).join("auditmail-node.json");
    let Ok(text) = std::fs::read_to_string(&path) else {
        eprintln!("no {}: nothing checked", path.display());
        return None;
    };
    let all: Json = serde_json::from_str(&text).unwrap();
    Some(all["mail"].clone())
}

fn s(v: &Json) -> &str {
    v.as_str().unwrap_or("")
}

fn parts(v: &Json) -> Parts {
    Parts::from_json(v)
}

fn parts_json(p: &Parts) -> Json {
    serde_json::json!({ "subject": p.subject, "text": p.text, "html": p.html })
}

#[test]
fn templates_are_nodes() {
    let Some(v) = vectors() else {
        return;
    };
    let t = Templates::get().unwrap();
    let v = &v["templates"];
    let mut checked = 0;
    for one in v["chain"].as_array().unwrap() {
        let got = t.chain_for(s(&one[0]));
        assert_eq!(serde_json::json!(got), one[1], "chain of {}", one[0]);
        checked += 1;
    }
    for one in v["order"].as_array().unwrap() {
        let got = Templates::language_order(s(&one[0]), s(&one[1]));
        assert_eq!(serde_json::json!(got), one[2], "order of {}", one[0]);
        checked += 1;
    }
    for one in v["placeholders"].as_array().unwrap() {
        let got = Templates::placeholders(s(&one[0]));
        assert_eq!(serde_json::json!(got), one[1]);
        checked += 1;
    }
    for one in v["plain"].as_array().unwrap() {
        let text = sts_mail::js::text_or_empty(Some(&one[0]));
        assert_eq!(sts_mail::templates::plain(&text), s(&one[1]));
        checked += 1;
    }
    for one in v["builtInLanguages"].as_array().unwrap() {
        let got = t.built_in_languages(s(&one[0]));
        assert_eq!(serde_json::json!(got), one[1], "languages of {}", one[0]);
        checked += 1;
    }
    for one in v["reasons"].as_array().unwrap() {
        assert_eq!(t.reason_for(s(&one[0]), s(&one[1])), s(&one[2]));
        checked += 1;
    }
    for one in v["problems"].as_array().unwrap() {
        let id = s(&one["id"]);
        let spec = t.built_in(id);
        let given = if one["parts"].is_null() {
            match t.built_in_for(id, s(&one["lang"])) {
                Some((p, _)) => p,
                None => Parts::of(spec.unwrap()),
            }
        } else {
            parts(&one["parts"])
        };
        assert_eq!(
            Templates::problem(spec, &given),
            s(&one["problem"]),
            "problem of {} {} {:?}",
            id,
            s(&one["lang"]),
            one["parts"]
        );
        checked += 1;
    }
    for one in v["rendered"].as_array().unwrap() {
        let id = s(&one["id"]);
        let lang = s(&one["lang"]);
        let spec = t.built_in(id).unwrap();
        let (body_parts, chosen) = t
            .built_in_for(id, lang)
            .unwrap_or_else(|| (Parts::of(spec), "en".to_string()));
        assert_eq!(chosen, s(&one["chosen"]), "{} {}", id, lang);
        let values: Map<String, Json> =
            one["values"].as_object().unwrap().clone();
        let body = Templates::render(&body_parts, &values);
        assert_eq!(parts_json(&body), one["body"], "{} {}", id, lang);
        let layout = t.built_in("layout").unwrap();
        let (layout_parts, layout_lang) = t
            .built_in_for("layout", &chosen)
            .unwrap_or_else(|| (Parts::of(layout), "en".to_string()));
        assert_eq!(layout_lang, s(&one["layoutLang"]));
        let mut with = values.clone();
        with.insert(
            "reason".into(),
            Json::String(t.reason_for(&spec.category, &layout_lang)),
        );
        let wrapped = Templates::wrap(&layout_parts, &body, &with);
        assert_eq!(parts_json(&wrapped), one["wrapped"], "{} {}", id, lang);
        assert_eq!(
            Templates::html_document(&wrapped.html, &chosen),
            s(&one["document"])
        );
        checked += 1;
    }
    eprintln!("templates: {} checks", checked);
}

// ---------------------------------------------------------------------------
// THE CHANNEL: Node's script replayed against the Rust channel, every
// send's answer, the message its transport was handed and its audit rows
// compared; and every raw message Node sent recomposed and re-signed from
// the message it was made from, byte for byte.
// ---------------------------------------------------------------------------

use std::collections::VecDeque;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use sts_mail::channel::*;
use sts_mail::compose::OutMessage;
use sts_mail::transports::*;

struct Dir {
    entries: Map<String, Json>,
    groups: Map<String, Json>,
}

impl Directory for Dir {
    fn person_entry(&self, u: &str) -> Option<Map<String, Json>> {
        self.entries.get(u).and_then(Json::as_object).cloned()
    }
    fn group_entry(&self, dn: &str) -> Option<Map<String, Json>> {
        self.groups.get(dn).and_then(Json::as_object).cloned()
    }
}

struct Realm(Json);

impl RealmInfo for Realm {
    fn id(&self) -> String {
        s(&self.0["id"]).to_string()
    }
    fn name(&self) -> String {
        s(&self.0["name"]).to_string()
    }
    fn domain(&self) -> String {
        s(&self.0["domain"]).to_string()
    }
    fn prefix(&self) -> String {
        s(&self.0["prefix"]).to_string()
    }
}

struct AlwaysClaims(Arc<AtomicI64>);

impl Claims for AlwaysClaims {
    fn claim<'a>(&'a self, _: &'a str, _: &'a str, _: i64, _: &'a str)
        -> BoxFuture<'a, ClaimAnswer> {
        let at = self.0.load(Ordering::SeqCst);
        Box::pin(async move { ClaimAnswer { ok: true, reason: String::new(),
                                            claimed_at: at } })
    }
}

#[derive(Default)]
struct Resolver(Mutex<Vec<Json>>);

impl ValueResolver for Resolver {
    fn resolve(&self, given: &Map<String, Json>, langs: &[String])
        -> Map<String, Json> {
        let mut held = self.0.lock().unwrap();
        let at = held.iter().position(|r| {
            r["given"] == Json::Object(given.clone())
                && r["langs"] == serde_json::json!(langs)
        });
        match at {
            Some(i) => held.remove(i)["made"].as_object().cloned().unwrap(),
            None => panic!("no resolution for {:?} in {:?}", given, langs),
        }
    }
}

struct En;

impl LocalePolicy for En {
    fn default_locale_for(&self, _: &str, _: &str) -> String {
        "en".into()
    }
}

struct NoLinks;

impl LinkBases for NoLinks {
    fn advertised_base(&self, _: &str) -> Option<String> {
        None
    }
}

#[derive(Default)]
struct Audits(Mutex<Vec<Json>>);

impl AuditSink for Audits {
    fn audit(&self, event: Json) {
        self.0.lock().unwrap().push(event);
    }
}

struct Secrets(Mutex<String>);

impl MailSecrets for Secrets {
    fn read(&self, which: Secret) -> BoxFuture<'_, Option<String>> {
        let out = match which {
            Secret::DkimKey => Some(self.0.lock().unwrap().clone()),
            Secret::SmtpPassword => Some("smtp-secret".into()),
            _ => None,
        };
        Box::pin(async move { out })
    }
}

#[derive(Default)]
struct Relay {
    sent: Mutex<Vec<Vec<u8>>>,
    fail: Mutex<VecDeque<SmtpFailure>>,
}

impl SmtpRelay for Relay {
    fn send<'a>(&'a self, _: &'a str, _: &'a str, raw: &'a [u8])
        -> BoxFuture<'a, Result<SmtpAccepted, SmtpFailure>> {
        Box::pin(async move {
            if let Some(f) = self.fail.lock().unwrap().pop_front() {
                return Err(f);
            }
            self.sent.lock().unwrap().push(raw.to_vec());
            Ok(SmtpAccepted { message_id: "<relay@x>".into(),
                              response: "250 2.0.0 OK".into(),
                              rejected: vec![] })
        })
    }
}

struct Relays(Arc<Relay>, Mutex<Vec<SmtpOptions>>);

impl RelayFactory for Relays {
    fn open(&self, options: &SmtpOptions) -> Arc<dyn SmtpRelay> {
        self.1.lock().unwrap().push(options.clone());
        self.0.clone()
    }
}

struct NoClouds;

impl CloudFactory for NoClouds {
    fn client(&self, _: Cloud, _: &Json, _: Option<&str>)
        -> Result<Arc<dyn CloudMail>, SendError> {
        Err(SendError::new("no cloud here",
                           sts_core::errors::codes::STS_MAIL_0005, false))
    }
}

struct NoFiles;

impl FileReader for NoFiles {
    fn read(&self, path: &str) -> Result<String, String> {
        Err(format!("no file {}", path))
    }
}

/// Records the message every transport is handed.
struct Recording(Builder, Arc<Mutex<Vec<OutMessage>>>);

struct RecordingTransport(Arc<dyn Transport>, Arc<Mutex<Vec<OutMessage>>>);

impl Transport for RecordingTransport {
    fn name(&self) -> &str {
        self.0.name()
    }
    fn send<'a>(&'a self, m: &'a OutMessage)
        -> BoxFuture<'a, Result<Sent, SendError>> {
        self.1.lock().unwrap().push(m.clone());
        self.0.send(m)
    }
}

impl TransportBuilder for Recording {
    fn build<'a>(&'a self, cfg: &'a Json)
        -> BoxFuture<'a, Result<Arc<dyn Transport>, SendError>> {
        Box::pin(async move {
            let made = self.0.build(cfg).await?;
            let wrapped: Arc<dyn Transport> =
                Arc::new(RecordingTransport(made, self.1.clone()));
            Ok(wrapped)
        })
    }
}

fn handed_json(m: &OutMessage) -> Json {
    let date = chrono::DateTime::from_timestamp_millis(m.date_ms).unwrap()
        .format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    serde_json::json!({ "from": m.from, "fromName": m.from_name, "to": m.to,
        "subject": m.subject, "text": m.text, "html": m.html,
        "messageId": m.message_id, "date": date, "lang": m.lang })
}

fn message_of(v: &Json) -> OutMessage {
    let date = chrono::DateTime::parse_from_rfc3339(s(&v["date"])).unwrap()
        .timestamp_millis();
    OutMessage { from: s(&v["from"]).into(), from_name: s(&v["fromName"]).into(),
        to: s(&v["to"]).into(), subject: s(&v["subject"]).into(),
        text: s(&v["text"]).into(), html: s(&v["html"]).into(),
        message_id: s(&v["messageId"]).into(), date_ms: date,
        lang: s(&v["lang"]).into() }
}

fn ids_of(send: &Json) -> Vec<String> {
    send["result"]["queued"].as_array().map(|q| q.iter()
        .map(|v| s(&v["id"]).to_string()).collect()).unwrap_or_default()
}

fn act(r: Result<Json, ActRefusal>) -> Json {
    match r {
        Ok(v) => serde_json::json!({ "result": v, "code": "" }),
        Err(e) => serde_json::json!({ "result": { "ok": false,
            "errors": e.errors }, "code": e.code.as_str() }),
    }
}

struct World {
    mail: Arc<Mail>,
    settings: Arc<sts_core::settings::Settings>,
    clock: Arc<AtomicI64>,
    audits: Arc<Audits>,
    handed: Arc<Mutex<Vec<OutMessage>>>,
    relay: Arc<Relay>,
    relays: Arc<Relays>,
    resolver: Arc<Resolver>,
    secrets: Arc<Secrets>,
    ids: Arc<Mutex<VecDeque<String>>>,
}

fn world(v: &Json) -> World {
    let settings = Arc::new(sts_core::settings::Settings::new(
        serde_json::json!({ "global": { "https": true, "port": 8081,
            "host": "0.0.0.0", "domain": "example.com" } }),
        Default::default()));
    let mode = Arc::new(sts_core::mode::Mode::new(settings.clone()));
    let clock = Arc::new(AtomicI64::new(v["t0"].as_i64().unwrap()));
    let audits = Arc::new(Audits::default());
    let handed = Arc::new(Mutex::new(Vec::new()));
    let relay = Arc::new(Relay::default());
    let relays = Arc::new(Relays(relay.clone(), Mutex::new(Vec::new())));
    let resolver = Arc::new(Resolver::default());
    let secrets = Arc::new(Secrets(Mutex::new(
        s(&v["keys"]["rsa"]["privateKeyPem"]).to_string())));
    let ids: Arc<Mutex<VecDeque<String>>> = Arc::new(Mutex::new(
        VecDeque::new()));
    let c1 = clock.clone();
    let c2 = clock.clone();
    let c3 = clock.clone();
    let id_queue = ids.clone();
    let builder = Builder { secrets: secrets.clone(), relays: relays.clone(),
        clouds: Arc::new(NoClouds), files: Arc::new(NoFiles),
        clock: Arc::new(move || c1.load(Ordering::SeqCst)),
        boundary: Arc::new(|| "0123456789abcdef".to_string()) };
    let holder = v["retry"]["dead"]["holder"].as_str().unwrap_or("")
        .to_string();
    let deps = MailDeps {
        settings: settings.clone(), mode,
        store: Arc::new(MemoryStore::default()),
        directory: Arc::new(Dir {
            entries: v["entries"].as_object().unwrap().clone(),
            groups: v["groups"].as_object().unwrap().clone() }),
        realm: Arc::new(Realm(v["realm"].clone())),
        claims: Arc::new(AlwaysClaims(c2)),
        resolver: resolver.clone(), locales: Arc::new(En),
        links: Arc::new(NoLinks), audit: audits.clone(),
        transports: Arc::new(Recording(builder, handed.clone())),
        administrators: Arc::new(|| vec!["ann".into(), "nomail".into(),
                                         "sven".into()]),
        now: Arc::new(move || c3.load(Ordering::SeqCst)),
        id: Arc::new(move || id_queue.lock().unwrap().pop_front()
            .unwrap_or_else(|| "no-id-left".into())),
        holder,
    };
    World { mail: Arc::new(Mail::new(deps)), settings, clock, audits, handed,
            relay, relays, resolver, secrets, ids }
}

fn same(what: &str, rust: &Json, node: &Json, failures: &mut Vec<String>) {
    if rust != node {
        failures.push(format!("{}:\n  rust {}\n  node {}", what, rust, node));
    }
}

#[tokio::test]
async fn the_channel_is_nodes() {
    let Some(v) = vectors() else {
        return;
    };
    let w = world(&v);
    let sends = v["sends"].as_array().unwrap();
    let mut failures: Vec<String> = Vec::new();
    let mut checked = 0;
    for op in v["script"].as_array().unwrap() {
        match s(&op["op"]) {
            "set" => {
                if let Err(e) = w.settings.set_override(s(&op["key"]),
                                                        op["value"].clone()) {
                    eprintln!("set {} refused here: {}", op["key"], e.problem);
                }
                if op["key"] == "mail.dkimAlgorithm" {
                    let key = if op["value"] == "ed25519-sha256" { "ed25519" }
                              else { "rsa" };
                    *w.secrets.0.lock().unwrap() =
                        s(&v["keys"][key]["privateKeyPem"]).to_string();
                }
            }
            "now" => w.clock.store(op["at"].as_i64().unwrap(), Ordering::SeqCst),
            "fail" => {
                for f in op["failures"].as_array().unwrap() {
                    w.relay.fail.lock().unwrap().push_back(SmtpFailure {
                        code: String::new(),
                        response_code: f["responseCode"].as_u64().unwrap_or(0)
                            as u16,
                        response: s(&f["response"]).into(),
                        message: "relay says no".into() });
                }
            }
            "send" => {
                let one = &sends[op["index"].as_u64().unwrap() as usize];
                let label = s(&one["label"]);
                w.ids.lock().unwrap().extend(ids_of(one));
                w.resolver.0.lock().unwrap().extend(
                    one["resolutions"].as_array().unwrap().iter().cloned());
                let a0 = w.audits.0.lock().unwrap().len();
                let h0 = w.handed.lock().unwrap().len();
                let req = SendRequest::from_json(&one["request"]);
                let result = if label.starts_with("pending address") {
                    w.mail.send_to_pending_address(&req)
                } else if label == "pseudonym" {
                    w.mail.send_to_pseudonym_address(&req)
                } else if label == "former address" {
                    w.mail.send_to_former_address(&req)
                } else {
                    w.mail.send(&req)
                };
                w.mail.dispatch(&result.queued).await;
                same(&format!("{} result", label), &result.to_json(),
                     &one["result"], &mut failures);
                let handed: Vec<Json> = w.handed.lock().unwrap()[h0..]
                    .iter().map(handed_json).collect();
                same(&format!("{} handed", label), &Json::Array(handed),
                     &one["handed"], &mut failures);
                let audits = Json::Array(w.audits.0.lock().unwrap()[a0..]
                    .to_vec());
                same(&format!("{} audits", label), &audits, &one["audits"],
                     &mut failures);
                checked += 3;
            }
            "mark" => {
                checked += 1;
                mark(&w, &v, s(&op["name"]), &mut failures).await;
            }
            other => panic!("unknown op {}", other),
        }
    }
    let opened = w.relays.1.lock().unwrap().clone();
    let node_opened = v["transportOptions"].as_array().unwrap();
    for (r, n) in opened.iter().zip(node_opened) {
        let rust = serde_json::json!({ "host": r.host, "port": r.port,
            "secure": r.implicit_tls, "requireTLS": r.require_tls,
            "servername": r.server_name, "minVersion": r.min_tls,
            "timeout": r.timeout_ms });
        same("transport options", &rust, n, &mut failures);
        checked += 1;
    }
    eprintln!("channel: {} checks, {} failures", checked, failures.len());
    for f in failures.iter().take(15) {
        eprintln!("{}", f);
    }
    assert!(failures.is_empty(), "{} channel failures", failures.len());
}

async fn mark(w: &World, v: &Json, name: &str, failures: &mut Vec<String>) {
    let m = &w.mail;
    match name {
        "declined" => {
            let got = Json::Array(vec![
                act(m.set_declined("declines", "notification", true,
                                   "declines")),
                act(m.set_declined("declines", "security", true, "")),
                act(m.set_declined("declines", "account", true, "")),
                act(m.set_declined("declines", "bogus", true, "")),
            ]);
            same("declined", &got, &v["declined"], failures);
        }
        "retry" => {
            let r = &v["retry"];
            let id = s(&r["id"]);
            let swept = m.sweep().await;
            same("swept", &swept, &r["swept"], failures);
            same("dead", &m.message(id).unwrap_or(Json::Null), &r["dead"],
                 failures);
            let h0 = w.handed.lock().unwrap().len();
            let retried = m.retry(id, "admin");
            if let Ok(row) = &retried {
                m.dispatch(&[row["row"].clone()]).await;
            }
            same("retried", &act(retried)["result"], &r["retried"], failures);
            same("again", &m.message(id).unwrap_or(Json::Null), &r["again"],
                 failures);
            let not_there = act(m.retry("nope", ""));
            same("notThere", &not_there["result"], &r["notThere"], failures);
            same("notThereCode", &not_there["code"], &r["notThereCode"],
                 failures);
            let first = ids_of(&v["sends"][0]);
            same("notDead", &act(m.retry(&first[0], ""))["result"],
                 &r["notDead"], failures);
            let handed: Vec<Json> = w.handed.lock().unwrap()[h0..].iter()
                .map(handed_json).collect();
            same("retry handed", &Json::Array(handed), &r["handed"], failures);
        }
        "linkBase0" => same("linkBase0", &serde_json::json!(m.link_base()),
                            &v["linkBases"][0], failures),
        "linkBase1" => same("linkBase1", &serde_json::json!(m.link_base()),
                            &v["linkBases"][1], failures),
        "captureWrite" => {
            // The write rule that refuses `capture` in product is the
            // settings slice's (`modeWriteProblem()`), not this crate's.
            eprintln!("captureWrite: Node {}", v["captureWriteRefused"]);
        }
        "productStartup" => same("productStartup",
            &serde_json::json!(m.startup_problem().await),
            &v["productStartup"], failures),
        "productOverCapture" => {
            let set = w.settings.set_override("global.mode",
                                              serde_json::json!("product"));
            same("productOverCapture", &serde_json::json!(set.is_ok()),
                 &v["productOverCapture"]["ok"], failures);
        }
        "captureInProduct" => {
            let got = match m.transport().await {
                Ok(_) => Json::Null,
                Err(e) => serde_json::json!({ "code": e.code.as_str(),
                                              "message": e.message }),
            };
            same("captureInProduct", &got, &v["captureInProduct"], failures);
        }
        "startupProblem" => same("startupProblem",
            &serde_json::json!(m.startup_problem().await),
            &v["startupProblem"], failures),
        "effective" => same("effective", &serde_json::json!(
            [m.effective_transport(), m.available()]), &v["effective"],
            failures),
        "saved" => {
            let own = serde_json::json!({ "subject": "Own {{service}}",
                "text": "Own {{link}} {{username}}",
                "html": "<p>Own <a href=\"{{link}}\">go</a></p>" });
            let got = Json::Array(vec![
                act(m.save_template("password-reset", "fr-ca", &own, "admin")),
                act(m.save_template("password-reset", "FR", &own, "admin")),
                act(m.save_template("nope", "fr", &own, "")),
                act(m.save_template("password-reset", "fr_CA", &own, "")),
                act(m.save_template("password-reset", "fr",
                    &serde_json::json!({ "subject": "x" }), "")),
                act(m.save_template("layout", "sv", &serde_json::json!({
                    "subject": "[{{realm}}] {{subject}}",
                    "text": "{{content}}\n-- {{reason}}",
                    "html": "<div>{{content}}</div>" }), "")),
                act(m.reset_template("password-reset", "de", "")),
                act(m.reset_template("nope", "fr", "")),
            ]);
            same("saved", &got, &v["saved"], failures);
        }
        "templateViews" => {
            let got = serde_json::json!([
                m.template_view("password-reset", "FR-CA"),
                m.template_view("password-reset", "en"),
                m.template_view("x", "en")]);
            same("templateViews", &got, &v["templateViews"], failures);
        }
        "resetBack" => same("resetBack",
            &act(m.reset_template("password-reset", "fr", ""))["result"],
            &v["resetBack"], failures),
        "listTemplates" => same("listTemplates",
            &Json::Array(m.list_templates()), &v["listTemplates"], failures),
        "uses" => {}
        other => panic!("unknown mark {}", other),
    }
}

/// Every raw message Node sent: recomposed from the message the transport
/// was handed, with Node's boundary and the signature's `t=`, and signed —
/// byte for byte.
#[test]
fn every_raw_message_is_nodes() {
    let Some(v) = vectors() else {
        return;
    };
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;
    let re = regex::Regex::new(r#"boundary="--_NmP-([0-9a-f]{16})-Part_1""#)
        .unwrap();
    let t_re = regex::Regex::new(r"; t=(\d+);").unwrap();
    let a_re = regex::Regex::new(r"DKIM-Signature: v=1; a=([a-z0-9-]+);")
        .unwrap();
    let mut checked = 0;
    let mut written = Vec::new();
    for one in v["sends"].as_array().unwrap() {
        let handed = one["handed"].as_array().unwrap();
        let raws = one["raw"].as_array().unwrap();
        // A failed attempt is handed and not sent: match by Message-ID.
        for raw in raws {
            let bytes = b64.decode(s(&raw["raw"])).unwrap();
            let text = String::from_utf8_lossy(&bytes).to_string();
            let msg = handed.iter().map(message_of).find(|m| {
                text.contains(&format!("Message-ID: {}", m.message_id))
            }).unwrap();
            let boundary = &re.captures(&text).unwrap()[1];
            let dkim = a_re.captures(&text).map(|a| {
                let alg = a[1].to_string();
                let key = if alg == "ed25519-sha256" { "ed25519" } else { "rsa" };
                (Dkim { domain: "example.com".into(), selector: "s2026".into(),
                        algorithm: alg,
                        private_key_pem: s(&v["keys"][key]["privateKeyPem"])
                            .into() },
                 key.to_string())
            });
            let t: i64 = t_re.captures(&text).map(|c| c[1].parse().unwrap())
                .unwrap_or(0);
            let made = raw_message(&msg, dkim.as_ref().map(|d| &d.0),
                                   boundary, t * 1000).unwrap();
            if made != bytes {
                let skip = |b: &[u8]| {
                    let t = String::from_utf8_lossy(b).to_string();
                    if t.starts_with("DKIM-Signature:") {
                        t.split_once("\r\n").map(|x| x.1.to_string())
                            .unwrap_or(t)
                    } else {
                        t
                    }
                };
                let (mine, text) = (skip(&made), skip(&bytes));
                let dir = std::env::var("STS_CRYPTO_VECTORS").unwrap();
                std::fs::write(format!("{}/diff-rust.txt", dir), &mine).ok();
                std::fs::write(format!("{}/diff-node.txt", dir), &text).ok();
                let at = mine.chars().zip(text.chars())
                    .position(|(a, b)| a != b).unwrap_or(0);
                panic!("{}: raw differs at {}:\nrust …{}\nnode …{}",
                       s(&one["label"]),
                       at, mine.chars().skip(at.saturating_sub(700)).take(800)
                           .collect::<String>(),
                       text.chars().skip(at.saturating_sub(700)).take(800)
                           .collect::<String>());
            }
            if let Some((_, key)) = &dkim {
                if written.len() < 40 {
                    written.push(serde_json::json!({
                        "label": s(&one["label"]), "raw": b64.encode(&made),
                        "publicKeyPem": v["keys"][key]["publicKeyPem"] }));
                }
            }
            checked += 1;
        }
    }
    eprintln!("raw messages: {} byte for byte", checked);
    assert!(checked > 300);
    if std::env::var("STS_WRITE_VECTORS").as_deref() == Ok("1") {
        let dir = std::env::var("STS_CRYPTO_VECTORS").unwrap();
        std::fs::write(std::path::Path::new(&dir).join("mail-rust.json"),
                       serde_json::to_string(&serde_json::json!({
                           "signed": written })).unwrap()).unwrap();
    }
}
