// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The settings and the mode against Node: `settings-mode-node.json`, which
//! `tests/tools/settings-mode-probes.js` writes by asking `common/config.js`
//! and `common/mode.js` — every row in both modes, with nothing set, with
//! each of a set of raw values in a realm's overrides and in the
//! environment, and a list of scenarios with every derived default, every
//! predicate and the whole `/admin/mode` report. Every answer here must be
//! Node's, sentence and code included.
//!
//! The directory is `STS_CORE_VECTORS`, never committed; with it unset this
//! test says so and passes.
//!
//!   node tests/tools/settings-mode-probes.js
//!   STS_CORE_VECTORS=tests/vectors/sts-core \
//!     cargo test -p sts-core --test settings_mode_vectors

#![allow(clippy::unwrap_used)] // a test file

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value as Json};
use sts_core::errors::ErrorCode;
use sts_core::mode::{Mode, OAuthBcpWaivers};
use sts_core::settings::{RealmLayer, Refusal, SettingValue, Settings};

/// The ambient realm as the probe tool holds it: one map, or none.
#[derive(Default)]
struct Ambient(Mutex<Option<Arc<HashMap<String, Json>>>>);

impl Ambient {
    fn set(&self, map: Option<HashMap<String, Json>>) {
        *self.0.lock().unwrap() = map.map(Arc::new);
    }
}

impl RealmLayer for Ambient {
    fn ambient_overrides(&self) -> Option<Arc<HashMap<String, Json>>> {
        self.0.lock().unwrap().clone()
    }
}

struct Waivers(Vec<Json>);

impl OAuthBcpWaivers for Waivers {
    fn waivers(&self) -> Vec<Json> {
        self.0.clone()
    }
}

fn to_json(value: &SettingValue) -> Json {
    match value {
        SettingValue::Text(text) => json!(text),
        SettingValue::Int(n) => json!(n),
        SettingValue::Bool(b) => json!(b),
        SettingValue::List(list) => json!(list),
    }
}

/// The JSON a value is written as by `JSON.stringify()`, for comparing a
/// number that is an integer to one that is not (Node writes 3 for 3.0).
fn same(a: &Json, b: &Json) -> bool {
    match (a, b) {
        (Json::Number(x), Json::Number(y)) => x.as_f64() == y.as_f64(),
        (Json::Array(x), Json::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(p, q)| same(p, q))
        }
        (Json::Object(x), Json::Object(y)) => {
            x.len() == y.len()
                && x.iter().all(|(k, v)| y.get(k).is_some_and(|w| same(v, w)))
        }
        _ => a == b,
    }
}

/// THE ONE DIFFERENCE THAT IS NOT A DEFECT: an integer row given more
/// digits than an `i64` holds. JavaScript's `parseInt()` keeps a double
/// (`1.2345678901234569e+23`); a row's value here is an `i64`, and the
/// coercion saturates at its bound. Only a row without a `max` accepts
/// such a value at all, and nothing reads one as other than "forever".
fn saturated(rust: &Json, node: &Json) -> bool {
    let (Some(r), Some(n)) = (rust.as_i64(), node.as_f64()) else {
        return false;
    };
    n.abs() > i64::MAX as f64
        && (r == i64::MAX || r == i64::MIN)
        && (r > 0) == (n > 0.0)
}

struct Probe {
    saturated: usize,
    strings: Vec<String>,
    failures: Vec<String>,
    by_kind: BTreeMap<String, usize>,
    checked: usize,
}

impl Probe {
    fn text(&self, index: &Json) -> Json {
        match index {
            Json::Number(n) => {
                json!(self.strings[n.as_u64().unwrap() as usize])
            }
            other => other.clone(),
        }
    }

    /// A refusal as the probe tool writes it: `[problem, code]` or null.
    fn refusal(&self, node: &Json) -> Json {
        match node {
            Json::Array(pair) => json!([self.text(&pair[0]), pair[1]]),
            _ => Json::Null,
        }
    }

    fn check(&mut self, kind: &str, what: &str, rust: &Json, node: &Json) {
        self.checked += 1;
        if same(rust, node) {
            return;
        }
        if saturated(rust, node) {
            self.saturated += 1;
            return;
        }
        *self.by_kind.entry(kind.to_string()).or_default() += 1;
        if self.failures.len() < 60 {
            self.failures.push(format!(
                "{} {}:\n    rust {}\n    node {}",
                kind, what, rust, node
            ));
        }
    }
}

fn answer(refusal: Option<Refusal>) -> Json {
    match refusal {
        Some(r) => json!([r.problem, code(r.code)]),
        None => Json::Null,
    }
}

fn code(code: ErrorCode) -> String {
    code.to_string()
}

fn env_of(map: &Json) -> HashMap<String, String> {
    map.as_object()
        .map(|m| {
            m.iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
                .collect()
        })
        .unwrap_or_default()
}

fn map_of(map: &Json) -> Option<HashMap<String, Json>> {
    map.as_object()
        .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
}

#[test]
fn settings_and_mode_as_node_answers() {
    let Ok(dir) = std::env::var("STS_CORE_VECTORS") else {
        eprintln!(
            "STS_CORE_VECTORS is not set: settings-mode-node.json is not \
             checked"
        );
        return;
    };
    let dir = std::path::Path::new(&dir);
    let read = |name: &str| -> Json {
        serde_json::from_str(&std::fs::read_to_string(dir.join(name)).unwrap())
            .unwrap()
    };
    let v = read("settings-mode-node.json");
    let operator = read("appconfig.json");
    let keys: Vec<String> = v["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k.as_str().unwrap().to_string())
        .collect();
    let mut p = Probe {
        saturated: 0,
        strings: v["strings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_string())
            .collect(),
        failures: Vec::new(),
        by_kind: BTreeMap::new(),
        checked: 0,
    };

    for (m, probes) in v["modes"].as_object().unwrap() {
        let base: HashMap<String, String> =
            [("STS_MODE".to_string(), m.clone())].into();
        let ambient = Arc::new(Ambient::default());
        let settings = Arc::new(Settings::new(operator.clone(), base.clone()));
        settings.set_realm_layer(ambient.clone());
        let mode = Mode::new(settings.clone());

        for (i, node) in
            probes["baseline"].as_array().unwrap().iter().enumerate()
        {
            let key = &keys[i];
            let what = format!("{} {}", m, key);
            let source = json!(settings.source_named(key).as_str());
            p.check("baseline source", &what, &source, &node[0]);
            let value = to_json(&settings.value_of(key));
            p.check("baseline value", &what, &value, &node[1]);
            let text = json!(settings.text_named(key));
            let want = p.text(&node[2]);
            p.check("baseline text", &what, &text, &want);
            let in_force = to_json(&mode.value_in_force(key));
            p.check("baseline inForce", &what, &in_force, &node[3]);
        }

        for (i, row) in probes["realm"].as_array().unwrap().iter().enumerate() {
            let key = &keys[i];
            for node in row.as_array().unwrap() {
                let raw = &node["raw"];
                let what = format!("{} {} = {}", m, key, raw);
                ambient.set(Some([(key.clone(), raw.clone())].into()));
                let source = json!(settings.source_named(key).as_str());
                p.check("realm source", &what, &source, &node["source"]);
                let value = settings.value_of(key);
                p.check("realm value", &what, &to_json(&value), &node["value"]);
                let allows = json!(mode.allows_value(key, &value));
                p.check("realm allows", &what, &allows, &node["allows"]);
                let in_force = to_json(&mode.in_force(key, value, "probe"));
                p.check("realm inForce", &what, &in_force, &node["inForce"]);
                let rust = answer(settings.check_override(key, raw, None));
                let want = p.refusal(&node["realm"]);
                p.check("checkOverride in a realm", &what, &rust, &want);
                let rust =
                    answer(settings.check_override(key, raw, Some(false)));
                let want = p.refusal(&node["realmAsProcess"]);
                p.check("checkOverride(false) in a realm", &what, &rust, &want);
                let rust = answer(mode.check_write(key, raw, None));
                let want = p.refusal(&node["realmWrite"]);
                p.check("checkWrite in a realm", &what, &rust, &want);
                ambient.set(None);
                let rust = answer(settings.check_override(key, raw, None));
                let want = p.refusal(&node["process"]);
                p.check("checkOverride", &what, &rust, &want);
                let rust = answer(mode.check_write(key, raw, None));
                let want = p.refusal(&node["processWrite"]);
                p.check("checkWrite", &what, &rust, &want);
                let rust = answer(mode.write_problem(key, raw));
                let want = p.refusal(&node["mode"]);
                p.check("modeWriteProblem", &what, &rust, &want);
            }
        }

        for (i, row) in probes["env"].as_array().unwrap().iter().enumerate() {
            let key = &keys[i];
            for node in row.as_array().unwrap() {
                let name = node[0].as_str().unwrap();
                let raw = node[1].as_str().unwrap();
                let what = format!("{} {} {}={:?}", m, key, name, raw);
                let mut env = base.clone();
                env.insert(name.to_string(), raw.to_string());
                let s = Settings::new(operator.clone(), env);
                let source = json!(s.source_named(key).as_str());
                p.check("env source", &what, &source, &node[2]);
                let value = to_json(&s.value_of(key));
                p.check("env value", &what, &value, &node[3]);
            }
        }
    }

    {
        let settings = Settings::new(operator.clone(), HashMap::new());
        let mode = Mode::new(Arc::new(Settings::new(
            operator.clone(),
            HashMap::new(),
        )));
        for node in v["notRows"].as_array().unwrap() {
            let key = node[0].as_str().unwrap();
            let raw = json!("x");
            let rust = answer(settings.check_override(key, &raw, None));
            let want = p.refusal(&node[1]);
            p.check("not a row: checkOverride", key, &rust, &want);
            let rust = answer(mode.check_write(key, &raw, None));
            let want = p.refusal(&node[2]);
            p.check("not a row: checkWrite", key, &rust, &want);
        }
    }

    for one in v["scenarios"].as_array().unwrap() {
        let what = format!("{} / {}", one["mode"], one["name"]);
        let ambient = Arc::new(Ambient::default());
        let settings =
            Arc::new(Settings::new(operator.clone(), env_of(&one["env"])));
        settings.set_realm_layer(ambient.clone());
        for (key, raw) in one["process"].as_object().unwrap() {
            settings.set_override(key, raw.clone()).unwrap();
        }
        ambient.set(map_of(&one["realm"]));
        let mode = Mode::new(settings.clone());
        let waivers = one["bcpWaivers"].as_array().unwrap().clone();
        mode.set_bcp_waivers(Arc::new(Waivers(waivers)));
        for (key, node) in one["derived"].as_object().unwrap() {
            let what = format!("{} {}", what, key);
            let source = json!(settings.source_named(key).as_str());
            p.check("derived source", &what, &source, &node[0]);
            let value = to_json(&settings.value_of(key));
            p.check("derived value", &what, &value, &node[1]);
            let text = json!(settings.text_named(key));
            let want = p.text(&node[2]);
            p.check("derived text", &what, &text, &want);
        }
        let base = json!(settings.management_api_base_url());
        let want = &one["managementApiBaseUrl"];
        p.check("managementApiBaseUrl", &what, &base, want);
        for (name, node) in one["predicates"].as_object().unwrap() {
            let rust = mode.answer(name).unwrap_or(json!("(unanswered)"));
            p.check("predicate", &format!("{} {}", what, name), &rust, node);
        }
        let rust = json!(mode.cleartext_startup_problem(true));
        p.check(
            "cleartext with https",
            &what,
            &rust,
            &one["cleartextWithHttps"],
        );
        let report = mode.report();
        let want = &one["report"];
        for field in ["mode", "isProduct", "notYet"] {
            p.check(
                "report",
                &format!("{} {}", what, field),
                &report[field],
                &want[field],
            );
        }
        for list in ["requirements", "developmentOnlySettings"] {
            let rust = report[list].as_array().unwrap();
            let node = want[list].as_array().unwrap();
            let count = format!("{} {} count", what, list);
            p.check("report", &count, &json!(rust.len()), &json!(node.len()));
            for (r, n) in rust.iter().zip(node) {
                let id = n.get("id").or_else(|| n.get("key")).unwrap();
                p.check("report", &format!("{} {} {}", what, list, id), r, n);
            }
        }
        ambient.set(None);
    }

    eprintln!(
        "settings and mode: {} answers checked against Node, {} differ; \
         {} integers beyond an i64 saturate (see saturated())",
        p.checked,
        p.by_kind.values().sum::<usize>(),
        p.saturated
    );
    assert!(
        p.by_kind.is_empty(),
        "differences by kind: {:#?}\nfirst ones:\n{}",
        p.by_kind,
        p.failures.join("\n")
    );
}
