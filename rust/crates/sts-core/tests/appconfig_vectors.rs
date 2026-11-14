// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Appconfig files against Node: `settings-files-node.json`, which
//! `tests/tools/settings-mode-probes.js` writes by starting `common/config.js`
//! on each file as its `CONFIG_FILE` — the shipped `env/*.js` and
//! `env/*.json`, and written ones in every form an operator might use.
//! Each is loaded here through `sts_core::appconfig` (QuickJS) and must
//! answer as Node did: the same exports, the same value, source and text
//! for every row, the same refusal on stderr (STS-CORE-0001, 0105, 0108)
//! and the same warnings (STS-CORE-0176 and the drift audit).
//!
//! Where an engine's own words differ — V8's and QuickJS's sentence for a
//! syntax error, node's "Require stack" under a missing module — the
//! refusal is compared up to the reason and on its first line.
//!
//! It also holds `env/defaults.js`, evaluated, to the compiled table: the
//! Rust defaults layer IS that file only while every non-derived row's
//! default is the value the file carries.
//!
//!   node tests/tools/settings-mode-probes.js
//!   STS_CORE_VECTORS=$PWD/tests/vectors/sts-core \
//!     cargo test -p sts-core --test appconfig_vectors

#![allow(clippy::unwrap_used)] // a test file

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde_json::{json, Value as Json};
use sts_core::appconfig;
use sts_core::settings::{rows, SettingValue, Settings};
use sts_core::startup::{self, Files};

fn to_json(value: &SettingValue) -> Json {
    match value {
        SettingValue::Text(text) => json!(text),
        SettingValue::Int(n) => json!(n),
        SettingValue::Bool(b) => json!(b),
        SettingValue::List(list) => json!(list),
    }
}

/// Numbers compared as JavaScript holds them (3 and 3.0 are one number).
fn same(a: &Json, b: &Json) -> bool {
    match (a, b) {
        (Json::Number(x), Json::Number(y)) => x.as_f64() == y.as_f64(),
        (Json::Array(x), Json::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(p, q)| same(p, q))
        }
        (Json::Object(x), Json::Object(y)) => {
            x.len() == y.len()
                && x.iter()
                    .zip(y.iter())
                    .all(|((k, v), (l, w))| k == l && same(v, w))
        }
        _ => a == b,
    }
}

fn dig<'a>(root: &'a Json, dotted: &str) -> Option<&'a Json> {
    let mut node = root;
    for part in dotted.split('.') {
        node = node.as_object()?.get(part)?;
    }
    Some(node)
}

struct Failures(Vec<String>, usize);

impl Failures {
    fn check(&mut self, what: String, ok: bool, detail: impl Fn() -> String) {
        self.1 += 1;
        if !ok && self.0.len() < 40 {
            self.0.push(format!("{}:\n    {}", what, detail()));
        }
    }
}

const LOAD_PREFIX: &str = "could not be loaded: ";

#[test]
fn appconfig_files_as_node_loads_them() {
    let Ok(dir) = std::env::var("STS_CORE_VECTORS") else {
        eprintln!(
            "STS_CORE_VECTORS is not set: settings-files-node.json is not \
             checked"
        );
        return;
    };
    let text = std::fs::read_to_string(
        Path::new(&dir).join("settings-files-node.json"),
    )
    .unwrap();
    let v: Json = serde_json::from_str(&text).unwrap();
    let root = PathBuf::from(v["root"].as_str().unwrap());
    let mut f = Failures(Vec::new(), 0);
    let mut defaults_checked = 0;
    let cases = v["cases"].as_array().unwrap();
    for case in cases {
        let name = format!("{} {}", case["file"], case["env"]);
        let mut env: HashMap<String, String> = case["env"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
            .collect();
        if let Some(given) = case["given"].as_str() {
            env.insert("CONFIG_FILE".into(), given.to_string());
        }
        let node_status = case["status"].as_i64().unwrap();
        let stderr = case["stderr"].as_str().unwrap();
        let loaded = match appconfig::load(&root, &env) {
            Err(refusal) => {
                // The engine's reason: the sentence up to it must be
                // node's, and the reason's first line too unless it is a
                // syntax error, which each engine words its own way.
                let cut = |s: &str| -> String {
                    let at = s
                        .find(LOAD_PREFIX)
                        .map_or(0, |i| i + LOAD_PREFIX.len());
                    let (head, rest) = s.split_at(at);
                    let first = rest.lines().next().unwrap_or("");
                    if case["file"]
                        .as_str()
                        .unwrap_or("")
                        .ends_with("syntax.js")
                    {
                        head.to_string()
                    } else {
                        format!("{}{}", head, first)
                    }
                };
                f.check(
                    format!("{} refused", name),
                    node_status == 1 && cut(&refusal) == cut(stderr),
                    || {
                        format!(
                            "rust {:?}\n    node {:?} ({})",
                            refusal, stderr, node_status
                        )
                    },
                );
                continue;
            }
            Ok(loaded) => loaded,
        };
        let settings = Settings::new(loaded.operator.clone(), env.clone());
        let files = Files::new(loaded.config_file.clone(), &root);
        let checked = startup::refuse_replaced_settings(&settings, &files)
            .and_then(|_| {
                startup::refuse_malformed_settings(&settings, &files)
            });
        if node_status != 0 {
            f.check(
                format!("{} refused at start", name),
                checked.as_ref().err().map(String::as_str) == Some(stderr),
                || format!("rust {:?}\n    node {:?}", checked, stderr),
            );
            continue;
        }
        let mut warnings = match checked {
            Ok(w) => w,
            Err(e) => {
                f.check(format!("{} started", name), false, || e.clone());
                continue;
            }
        };
        warnings.extend(startup::audit_warnings(&loaded.operator, &files));
        let node = &case["loaded"];
        f.check(
            format!("{} CONFIG_FILE", name),
            json!(loaded.config_file) == node["configFile"],
            || {
                format!(
                    "rust {:?}\n    node {}",
                    loaded.config_file, node["configFile"]
                )
            },
        );
        f.check(
            format!("{} exports", name),
            same(&loaded.operator, &node["exports"]),
            || {
                format!(
                    "rust {}\n    node {}",
                    loaded.operator, node["exports"]
                )
            },
        );
        f.check(
            format!("{} warnings", name),
            json!(warnings) == case["warnings"],
            || format!("rust {:?}\n    node {}", warnings, case["warnings"]),
        );
        for (row, want) in
            rows().iter().zip(node["baseline"].as_array().unwrap())
        {
            let got = json!([
                settings.source_named(row.key).as_str(),
                to_json(&settings.value_of(row.key)),
                settings.text_named(row.key)
            ]);
            f.check(format!("{} {}", name, row.key), same(&got, want), || {
                format!("rust {}\n    node {}", got, want)
            });
        }
        if case["file"] == "./env/defaults.js" {
            for row in rows() {
                let held = dig(&loaded.operator, row.dotted());
                let want = row.defaults_file_value();
                defaults_checked += 1;
                f.check(
                    format!("env/defaults.js {}", row.key),
                    match (held, &want) {
                        (Some(h), Some(w)) => same(h, w),
                        (None, None) => true,
                        _ => false,
                    },
                    || format!("file {:?}\n    table {:?}", held, want),
                );
            }
        }
    }
    eprintln!(
        "appconfig files: {} cases, {} answers checked against Node \
         ({} rows of env/defaults.js against the compiled table), {} differ",
        cases.len(),
        f.1,
        defaults_checked,
        f.0.len()
    );
    assert!(
        defaults_checked > 0,
        "env/defaults.js was not among the cases"
    );
    assert!(f.0.is_empty(), "first differences:\n{}", f.0.join("\n"));
}
