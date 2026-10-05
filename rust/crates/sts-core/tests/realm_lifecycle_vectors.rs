// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! A trust realm's life against Node: `realm-lifecycle-node.json`, which
//! `tests/tools/crypto-vectors.js` writes with `common/realms.js` itself.
//! The same steps — realms created and refused, a setting set and cleared,
//! a realm updated whole, a product-mode realm refusing a development-only
//! value, a realm retired and removed — must give Node's answer, sentence
//! and code, and leave the same realms with the same seeded overrides.
//!
//! The directory is `STS_CRYPTO_VECTORS`, never committed; with it unset
//! this test says so and passes.

#![allow(clippy::unwrap_used)] // a test file

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::{json, Map, Value as Json};
use sts_core::mode::Mode;
use sts_core::realm::{RealmEnvironment, RealmRegistry, Refusals};
use sts_core::realm_lifecycle::RealmLifecycle;
use sts_core::settings::Settings;

struct Env(Arc<Settings>);

impl RealmEnvironment for Env {
    fn enabled(&self) -> bool {
        true
    }
    fn path_segment(&self) -> String {
        self.0.value_of("realms.pathSegment").as_str().to_string()
    }
    fn global_domain(&self) -> String {
        self.0.value_of("global.domain").as_str().to_string()
    }
    fn reserved(&self) -> Vec<String> {
        Vec::new()
    }
    fn est_labels(&self) -> Vec<String> {
        Vec::new()
    }
}

fn answer<T>(r: Result<T, Refusals>) -> Json {
    match r {
        Ok(_) => json!({ "ok": true, "errors": [], "code": null }),
        Err(e) => json!({ "ok": false, "errors": e.sentences,
                          "code": e.code.map(|c| c.as_ref().to_string()) }),
    }
}

fn obj(v: &Json) -> Map<String, Json> {
    v.as_object().cloned().unwrap_or_default()
}

fn s<'a>(v: &'a Json, k: &str) -> &'a str {
    v[k].as_str().unwrap_or("")
}

#[tokio::test]
async fn a_realms_life_is_nodes() {
    let Ok(dir) = std::env::var("STS_CRYPTO_VECTORS") else {
        eprintln!("STS_CRYPTO_VECTORS is not set: realm-lifecycle-node.json is not checked");
        return;
    };
    let v: Json = serde_json::from_str(
        &std::fs::read_to_string(
            std::path::Path::new(&dir).join("realm-lifecycle-node.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let settings = Arc::new(Settings::new(Json::Null, HashMap::new()));
    let mode = Arc::new(Mode::new(settings.clone()));
    let registry =
        Arc::new(RealmRegistry::new(Arc::new(Env(settings.clone()))));
    let life = RealmLifecycle::new(registry.clone(), settings, mode);
    let mut failures = Vec::new();
    let listed = |life: &RealmLifecycle| -> Json {
        json!(registry
            .list()
            .iter()
            .filter(|r| !r.builtin)
            .map(|r| json!({ "id": r.id, "name": r.name, "description": r.description,
                             "domain": r.domain, "overrides": life.overrides(&r.id),
                             "retiring": life.is_retiring(&r.id) }))
            .collect::<Vec<_>>())
    };
    for step in v["steps"].as_array().unwrap() {
        let id = s(step, "id");
        let got = match s(step, "op") {
            "create" => answer(life.create(
                id,
                s(step, "name"),
                s(step, "description"),
                s(step, "domain"),
                &obj(&step["overrides"]),
                false,
            )),
            "set" => answer(life.set_override(
                id,
                s(step, "key"),
                step["raw"].clone(),
            )),
            "clear" => answer(life.clear_override(id, s(step, "key"))),
            "update" => {
                let c = &step["changes"];
                let overrides = c.get("overrides").map(obj);
                answer(life.update(
                    id,
                    c["name"].as_str(),
                    c["description"].as_str(),
                    overrides.as_ref(),
                    c["domain"].as_str(),
                    false,
                    None,
                ))
            }
            "retire" => {
                let before = listed(&life);
                if before != v["before"] {
                    failures.push(format!(
                        "before the removal:\n  rust {}\n  node {}",
                        before, v["before"]
                    ));
                }
                answer(life.retire(id, None, None).await)
            }
            "remove" => answer(life.remove(id)),
            other => panic!("unknown step {}", other),
        };
        if got != step["result"] {
            failures.push(format!(
                "{} {} {}:\n  rust {}\n  node {}",
                s(step, "op"),
                id,
                s(step, "key"),
                got,
                step["result"]
            ));
        }
    }
    let after = listed(&life);
    if after != v["after"] {
        failures
            .push(format!("after:\n  rust {}\n  node {}", after, v["after"]));
    }
    assert!(
        failures.is_empty(),
        "{} differences:\n{}",
        failures.len(),
        failures.join("\n")
    );
    eprintln!(
        "{} steps as Node takes them",
        v["steps"].as_array().unwrap().len()
    );
}

struct Owner {
    name: &'static str,
    marks: std::sync::Mutex<Vec<String>>,
}

impl sts_core::realm_lifecycle::Retirer for Owner {
    fn name(&self) -> &str {
        self.name
    }
    fn mark<'a>(
        &'a self,
        id: &'a str,
        _ctx: &'a sts_core::realm_lifecycle::RetireContext,
    ) -> Option<sts_core::realm_lifecycle::BoxFuture<'a, Result<(), String>>>
    {
        // The realm is ambient while an owner's step runs.
        self.marks.lock().unwrap().push(format!(
            "{}={}",
            id,
            sts_core::realm::current_id()
        ));
        Some(Box::pin(async { Ok(()) }))
    }
    fn announce(
        &self,
        _id: &str,
        ctx: &sts_core::realm_lifecycle::RetireContext,
    ) -> Result<(), String> {
        if self.name == "mail" {
            ctx.undelivered
                .lock()
                .unwrap()
                .push(("messages".to_string(), 3));
            return Err("the relay refused".to_string());
        }
        Ok(())
    }
    fn deliver<'a>(
        &'a self,
        _id: &'a str,
        _ctx: &'a sts_core::realm_lifecycle::RetireContext,
    ) -> Option<sts_core::realm_lifecycle::BoxFuture<'a, Result<(), String>>>
    {
        if self.name == "logout" {
            return Some(Box::pin(async {
                tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
                Ok(())
            }));
        }
        None
    }
}

#[tokio::test(start_paused = true)]
async fn a_removal_marks_announces_delivers_and_goes_anyway() {
    let settings = Arc::new(Settings::new(
        json!({ "realms": { "removalDeliveryTimeoutS": 2 } }),
        HashMap::new(),
    ));
    let mode = Arc::new(Mode::new(settings.clone()));
    let registry =
        Arc::new(RealmRegistry::new(Arc::new(Env(settings.clone()))));
    let now = Arc::new(std::sync::Mutex::new(1_000_000.0));
    let clock = now.clone();
    let life = RealmLifecycle::with_clock(
        registry.clone(),
        settings.clone(),
        mode,
        Arc::new(move || *clock.lock().unwrap()),
    );
    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen = events.clone();
    life.on_change(Arc::new(move |e| {
        seen.lock().unwrap().push(format!("{}:{}", e.what, e.id))
    }));
    let purged = Arc::new(std::sync::Mutex::new(Vec::new()));
    let p = purged.clone();
    life.on_remove(Arc::new(move |id| p.lock().unwrap().push(id.to_string())));
    let logout = Arc::new(Owner {
        name: "logout",
        marks: Default::default(),
    });
    let mail = Arc::new(Owner {
        name: "mail",
        marks: Default::default(),
    });
    life.on_retire(logout.clone());
    life.on_retire(mail.clone());
    life.create("acme", "", "", "", &Map::new(), false).unwrap();

    // A realm's own setting is what a read inside it answers.
    life.set_override("acme", "saml2.entityId", json!("urn:x"))
        .unwrap();
    let acme = registry.get("acme").unwrap();
    assert_eq!(
        sts_core::realm::run_sync(acme, || settings
            .value_of("saml2.entityId")
            .as_str()
            .to_string()),
        "urn:x"
    );
    assert_ne!(settings.value_of("saml2.entityId").as_str(), "urn:x");

    let (_, report) = life.retire("acme", None, None).await.unwrap();
    assert_eq!(report.late, vec!["logout"]);
    assert_eq!(report.failed, vec!["mail (announce): the relay refused"]);
    assert_eq!(report.undelivered, vec![("messages".to_string(), 3)]);
    assert_eq!(report.bound_seconds, 2);
    assert_eq!(*logout.marks.lock().unwrap(), vec!["acme=acme"]);
    assert_eq!(*purged.lock().unwrap(), vec!["acme"]);
    assert!(registry.get("acme").is_none());
    assert!(!life.accepts_rows("acme"));
    assert_eq!(
        *events.lock().unwrap(),
        vec![
            "create:acme",
            "set-override:acme",
            "retire:acme",
            "remove:acme"
        ]
    );

    // A mark another process made: refused while in progress, interrupted
    // once the bound and the grace have passed.
    life.create("beta", "", "", "", &Map::new(), false).unwrap();
    assert!(life.accepts_rows("beta"));
    life.update("beta", None, None, None, None, true, Some(1_000_000.0))
        .unwrap();
    let (code, why) = life.retiring_refusal("beta").unwrap();
    assert_eq!(code.as_ref(), "STS-CORE-0121");
    assert!(why.contains("is being removed"));
    let refused = life.retire("beta", None, None).await.unwrap_err();
    assert_eq!(refused.code.unwrap().as_ref(), "STS-CORE-0122");
    *now.lock().unwrap() += 2_000.0 + 30_001.0;
    let state = life.retiring_state("beta").unwrap();
    assert!(!state.in_progress && state.why.contains("interrupted"));
    life.retire("beta", None, None).await.unwrap();
    assert!(registry.get("beta").is_none());
}
