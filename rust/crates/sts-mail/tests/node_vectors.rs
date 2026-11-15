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
