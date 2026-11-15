// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The validation guard (`common/validation.js`'s `guard()`): the two
//! things no caller of any protocol this service speaks ever sends,
//! refused before any route — a query parameter NAMED `constructor` or
//! `prototype` (`STS-HTTP-0010`), and a control character in a query
//! value (`STS-HTTP-0011`). A REPEATED parameter is deliberately not
//! refused here; that module argues why.
//!
//! **THE QUERY IS READ AS EXPRESS 4 READS IT** (`qs`, its "extended"
//! parser), because the guard sees what that parser made: `__proto__` is
//! dropped before anything sees it (so it is never refused — it is not
//! there), `a[]=x` and `a[0]=x` are a list whose strings are checked,
//! `a[b]=x` is an object and is not, and the keys are visited in a
//! JavaScript object's order — integer-like keys first, ascending.

use axum::http::StatusCode;
use axum::response::Response;
use sts_core::errors::codes;

use crate::cors::form_decode;

/// What a key holds once `qs` has read it.
enum Held {
    Strings(Vec<String>),
    Object,
}

/// `qs.parse()` reduced to what the guard reads: each top-level key with
/// its string values, or `Object` for a nested one.
fn parsed(query: &str) -> Vec<(String, Held)> {
    let mut out: Vec<(String, Held)> = Vec::new();
    for pair in query.split('&').take(1000).filter(|p| !p.is_empty()) {
        let (k, v) = match pair.find("]=") {
            Some(at) => (&pair[..=at], &pair[at + 2..]),
            None => pair.split_once('=').unwrap_or((pair, "")),
        };
        let key = form_decode(k);
        let value = form_decode(v);
        let (root, rest) = match key.find('[') {
            Some(at) if at > 0 && key[at..].contains(']') => {
                (key[..at].to_string(), Some(key[at..].to_string()))
            }
            _ => (key.clone(), None),
        };
        if root == "__proto__" || root.is_empty() {
            continue;
        }
        let list = match &rest {
            None => true,
            Some(r) => {
                let inner = r.trim_start_matches('[');
                let index = inner.split(']').next().unwrap_or("");
                index.is_empty()
                    || (index.bytes().all(|b| b.is_ascii_digit())
                        && index.parse::<usize>().is_ok_and(|n| n <= 20))
            }
        };
        let slot = out.iter_mut().find(|(k, _)| *k == root);
        match (slot, list) {
            (Some((_, Held::Strings(values))), true) => values.push(value),
            (Some((_, held)), false) => *held = Held::Object,
            (Some((_, Held::Object)), true) => {}
            (None, true) => out.push((root, Held::Strings(vec![value]))),
            (None, false) => out.push((root, Held::Object)),
        }
    }
    // A JavaScript object's key order: array indices first, ascending.
    let index = |k: &str| {
        (!k.is_empty()
            && k.bytes().all(|b| b.is_ascii_digit())
            && (k == "0" || !k.starts_with('0')))
        .then(|| k.parse::<u64>().ok())
        .flatten()
    };
    let mut numbered: Vec<(String, Held)> = Vec::new();
    let mut named: Vec<(String, Held)> = Vec::new();
    for one in out {
        if index(&one.0).is_some() {
            numbered.push(one);
        } else {
            named.push(one);
        }
    }
    numbered.sort_by_key(|(k, _)| index(k));
    numbered.extend(named);
    numbered
}

/// The guard's refusal for a query, or `None` to pass it on.
#[tracing::instrument(level = "debug", skip_all)]
pub fn refusal(method: &str, path: &str, query: &str) -> Option<Response> {
    for (key, held) in parsed(query) {
        let (code, kind, detail) = if key == "constructor" || key == "prototype"
        {
            (
                codes::STS_HTTP_0010,
                "polluting-key",
                format!(
                    "the parameter name \"{}\" is refused everywhere in this \
                     service.",
                    key
                ),
            )
        } else {
            let Held::Strings(values) = held else {
                continue;
            };
            let control = values
                .iter()
                .any(|v| v.chars().any(|c| (c as u32) < 0x20 || c == '\x7f'));
            if !control {
                continue;
            }
            (
                codes::STS_HTTP_0011,
                "control-character",
                format!(
                    "the value of \"{}\" contains a control character. A \
                     carriage return or newline in a query parameter reaches \
                     a response header, a log line or a directory query as a \
                     second instruction rather than as text.",
                    key
                ),
            )
        };
        tracing::warn!(
            "validation: refused a request to {} {} — {} on \"{}\".",
            method,
            path,
            kind,
            key
        );
        let mut response = crate::text(format!(
            "Bad Request: {}\n\nThis is refused before any endpoint sees it, \
             in development mode and product mode alike, because no caller \
             of any protocol this service speaks sends it.\n",
            detail
        ));
        *response.status_mut() = StatusCode::BAD_REQUEST;
        return Some(crate::mark(response, code));
    }
    None
}
