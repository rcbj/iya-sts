// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! Sigstore and TUF: `common/crypto.js` section 11 (#170) — what the SPIFFE
//! docker attestor needs to believe a cosign signature and the sigstore
//! trust root.
//!
//! * TWO CANONICAL JSON FORMS, which are not the same thing:
//!   securesystemslib's OLPC form ([`olpc_canonical_json`]: sorted keys, no
//!   whitespace, only `"` and `\` escaped, integers only) that TUF signs,
//!   and RFC 8785 JCS ([`jcs_canonical_json`]) that a Rekor SET is signed
//!   over. JCS is JavaScript's own serialization of strings and numbers, so
//!   [`js_number`] is ECMAScript's `Number::toString` and [`js_string`] is
//!   `JSON.stringify` of a string; keys sort by UTF-16 code units in both.
//! * [`verify_threshold_signatures`]: TUF's rule — at least `threshold`
//!   distinct keyids of the role, each a key the role names, each signature
//!   verifying over the canonical bytes.
//! * [`verify_rekor_set`]: cosign's `VerifySET()`.
//! * [`dsse_pae`], [`verify_with_public_key`] and the SPKI / PEM helpers.

use std::collections::BTreeSet;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use openssl::hash::{hash, MessageDigest};
use serde_json::{Map, Value as Json};

use crate::raw_sig::{self, EcdsaEncoding, RawFamily, RawHash, RawScheme};

/// JavaScript's `<` on strings: UTF-16 code units.
fn utf16_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

fn sorted_keys(map: &Map<String, Json>) -> Vec<&String> {
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort_by(|a, b| utf16_cmp(a, b));
    keys
}

/// ECMAScript's `Number::toString(10)` for a finite double.
pub fn js_number(x: f64) -> String {
    if x == 0.0 {
        return "0".to_string();
    }
    if x < 0.0 {
        return format!("-{}", js_number(-x));
    }
    // Rust's `{:e}` is the shortest round-trip digits, as ECMAScript asks.
    let sci = format!("{:e}", x);
    let (mantissa, exp) = sci.split_once('e').unwrap_or((&sci, "0"));
    let digits: String =
        mantissa.chars().filter(char::is_ascii_digit).collect();
    let digits = digits.trim_end_matches('0');
    let digits = if digits.is_empty() { "0" } else { digits };
    let k = digits.len() as i64;
    let n = exp.parse::<i64>().unwrap_or(0) + 1;
    if k <= n && n <= 21 {
        return format!("{}{}", digits, "0".repeat((n - k) as usize));
    }
    if 0 < n && n <= 21 {
        return format!("{}.{}", &digits[..n as usize], &digits[n as usize..]);
    }
    if -6 < n && n <= 0 {
        return format!("0.{}{}", "0".repeat((-n) as usize), digits);
    }
    let e = n - 1;
    let sign = if e < 0 { '-' } else { '+' };
    if k == 1 {
        format!("{}e{}{}", digits, sign, e.abs())
    } else {
        format!("{}.{}e{}{}", &digits[..1], &digits[1..], sign, e.abs())
    }
}

/// A JSON number as JavaScript would have read and written it.
fn number_of(n: &serde_json::Number) -> f64 {
    n.as_f64().unwrap_or(0.0)
}

/// `JSON.stringify` of a string.
pub fn js_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32))
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// securesystemslib's canonical JSON (OLPC), what a TUF signature covers;
/// an error for a value with no canonical form (a non-integer number).
pub fn olpc_canonical_json(value: &Json) -> Result<String, String> {
    Ok(match value {
        Json::Null => "null".to_string(),
        Json::Bool(b) => b.to_string(),
        Json::Number(n) => {
            let x = number_of(n);
            if x.fract() != 0.0 || !x.is_finite() {
                return Err(
                    "canonical JSON has no floating-point numbers".to_string()
                );
            }
            js_number(x)
        }
        Json::String(s) => {
            format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
        }
        Json::Array(a) => {
            let parts: Result<Vec<String>, String> =
                a.iter().map(olpc_canonical_json).collect();
            format!("[{}]", parts?.join(","))
        }
        Json::Object(m) => {
            let mut parts = Vec::new();
            for k in sorted_keys(m) {
                parts.push(format!(
                    "{}:{}",
                    olpc_canonical_json(&Json::String(k.clone()))?,
                    olpc_canonical_json(&m[k])?
                ));
            }
            format!("{{{}}}", parts.join(","))
        }
    })
}

/// RFC 8785 (JCS) canonical JSON.
pub fn jcs_canonical_json(value: &Json) -> String {
    match value {
        Json::Null => "null".to_string(),
        Json::Bool(b) => b.to_string(),
        Json::Number(n) => js_number(number_of(n)),
        Json::String(s) => js_string(s),
        Json::Array(a) => format!(
            "[{}]",
            a.iter()
                .map(jcs_canonical_json)
                .collect::<Vec<_>>()
                .join(",")
        ),
        Json::Object(m) => format!(
            "{{{}}}",
            sorted_keys(m)
                .into_iter()
                .map(|k| format!(
                    "{}:{}",
                    js_string(k),
                    jcs_canonical_json(&m[k])
                ))
                .collect::<Vec<_>>()
                .join(",")
        ),
    }
}

/// `Buffer.from(text, 'base64')`: the characters up to the first `=`,
/// six bits each, a trailing partial byte dropped.
fn node_base64(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in text.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => break,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

/// `Buffer.from(text, 'hex')`: whole pairs, stopping at the first that is
/// not hex.
fn node_hex(text: &str) -> Vec<u8> {
    let b = text.as_bytes();
    let mut out = Vec::new();
    for pair in b.chunks_exact(2) {
        match std::str::from_utf8(pair)
            .ok()
            .and_then(|p| u8::from_str_radix(p, 16).ok())
        {
            Some(v) if pair.iter().all(u8::is_ascii_hexdigit) => out.push(v),
            _ => break,
        }
    }
    out
}

/// JavaScript's `String(x)` of a JSON value, for a keyid.
fn js_string_of(v: &Json) -> String {
    match v {
        Json::String(s) => s.clone(),
        Json::Number(n) => js_number(number_of(n)),
        Json::Bool(b) => b.to_string(),
        Json::Null => "null".to_string(),
        Json::Array(a) => a
            .iter()
            .map(|x| {
                if x.is_null() {
                    String::new()
                } else {
                    js_string_of(x)
                }
            })
            .collect::<Vec<_>>()
            .join(","),
        Json::Object(_) => "[object Object]".to_string(),
    }
}

/// JavaScript truthiness of a JSON value.
fn truthy(v: Option<&Json>) -> bool {
    match v {
        None | Some(Json::Null) => false,
        Some(Json::Bool(b)) => *b,
        Some(Json::Number(n)) => number_of(n) != 0.0,
        Some(Json::String(s)) => !s.is_empty(),
        Some(_) => true,
    }
}

/// The DER SubjectPublicKeyInfo of a `PUBLIC KEY` PEM or a bare base64
/// body, when it is a key something here verifies with.
pub fn spki_from_public_key_pem(pem: &str) -> Option<Vec<u8>> {
    let begin = "-----BEGIN PUBLIC KEY-----";
    let end = "-----END PUBLIC KEY-----";
    let body = match (pem.find(begin), pem.find(end)) {
        (Some(a), Some(b)) if b > a => &pem[a + begin.len()..b],
        _ => pem,
    };
    let body: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    if body.is_empty()
        || !body
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='))
    {
        return None;
    }
    let der = node_base64(&body);
    (!raw_sig::public_key_from_spki(&der).kind.is_empty()).then_some(der)
}

/// A DER SubjectPublicKeyInfo as cosign writes it in PEM.
pub fn public_key_pem_of_spki(spki: &[u8]) -> String {
    let b64 = STANDARD.encode(spki);
    let lines: Vec<&str> = b64
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect();
    format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        lines.join("\n")
    )
}

/// One signature under a key held as an SPKI, with cosign's scheme for the
/// key's kind: ECDSA with SHA-256 (DER unless `p1363`), RSA PKCS#1 v1.5
/// with SHA-256, EdDSA, and the post-quantum families.
pub fn verify_with_public_key(
    spki: &[u8],
    data: &[u8],
    signature: &[u8],
    p1363: bool,
) -> bool {
    let key = raw_sig::public_key_from_spki(spki);
    let scheme = match key.kind {
        "ec" => RawScheme::new(RawFamily::Ecdsa, Some(RawHash::Sha256))
            .with_encoding(if p1363 {
                EcdsaEncoding::P1363
            } else {
                EcdsaEncoding::Der
            }),
        "rsa" => RawScheme::new(RawFamily::RsaPkcs1, Some(RawHash::Sha256)),
        "ed25519" | "ed448" => RawScheme::new(RawFamily::EdDsa, None),
        "pq" => RawScheme::new(RawFamily::PostQuantum, None),
        _ => return false,
    };
    raw_sig::verify_raw_signature(&scheme, &key, data, signature)
}

/// A TUF key (`{ keytype, scheme, keyval: { public } }`) as an SPKI: an
/// Ed25519 key's hex wrapped in RFC 8410's prefix, a PEM read.
pub fn tuf_key_spki(key: &Json) -> Option<Vec<u8>> {
    let kind = key.get("keytype").and_then(Json::as_str).unwrap_or("");
    let public = key
        .pointer("/keyval/public")
        .and_then(Json::as_str)
        .unwrap_or("");
    if kind == "ed25519"
        && public.len() == 64
        && public.chars().all(|c| c.is_ascii_hexdigit())
    {
        let mut out = vec![
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21,
            0x00,
        ];
        out.extend(
            (0..64).step_by(2).map(|i| {
                u8::from_str_radix(&public[i..i + 2], 16).unwrap_or(0)
            }),
        );
        return Some(out);
    }
    if [
        "ecdsa",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "rsa",
        "sigstore-oidc",
    ]
    .contains(&kind)
        || public.contains("BEGIN PUBLIC KEY")
    {
        return spki_from_public_key_pem(public);
    }
    None
}

/// TUF's verdict on one role.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Threshold {
    pub ok: bool,
    pub valid: usize,
    /// As JavaScript's `Number()` read it, NaN included.
    pub threshold: f64,
}

/// `verifyThresholdSignatures()`: at least `threshold` distinct keyids of
/// the role verified over the OLPC form of `signed`.
pub fn verify_threshold_signatures(
    signed: &Json,
    signatures: &Json,
    keys: &Json,
    role: &Json,
) -> Threshold {
    // `Number(role.threshold || 0)`.
    let threshold = match role.get("threshold") {
        t if !truthy(t) => 0.0,
        Some(Json::Number(n)) => number_of(n),
        Some(Json::Bool(_)) => 1.0,
        Some(Json::String(s)) => {
            let s = s.trim();
            if s.is_empty() {
                0.0
            } else {
                s.parse::<f64>().unwrap_or(f64::NAN)
            }
        }
        Some(Json::Array(a)) if a.len() == 1 => js_string_of(&a[0])
            .trim()
            .parse::<f64>()
            .unwrap_or(f64::NAN),
        _ => f64::NAN,
    };
    let refused = Threshold {
        ok: false,
        valid: 0,
        threshold,
    };
    if !threshold.is_finite() || threshold.fract() != 0.0 || threshold < 1.0 {
        return refused;
    }
    let allowed: Vec<String> = match role.get("keyids") {
        Some(Json::Array(a)) if truthy(role.get("keyids")) => {
            a.iter().map(js_string_of).collect()
        }
        _ => Vec::new(),
    };
    let Ok(bytes) = olpc_canonical_json(signed) else {
        return refused;
    };
    let mut counted = BTreeSet::new();
    for sig in signatures.as_array().into_iter().flatten() {
        let keyid = if truthy(sig.get("keyid")) {
            sig.get("keyid").map(js_string_of).unwrap_or_default()
        } else {
            String::new()
        };
        if keyid.is_empty()
            || counted.contains(&keyid)
            || !allowed.contains(&keyid)
        {
            continue;
        }
        let Some(spki) = keys.get(&keyid).and_then(tuf_key_spki) else {
            continue;
        };
        let hex = if truthy(sig.get("sig")) {
            sig.get("sig").map(js_string_of).unwrap_or_default()
        } else {
            String::new()
        };
        if hex.is_empty() || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            continue;
        }
        if verify_with_public_key(
            &spki,
            bytes.as_bytes(),
            &node_hex(&hex),
            false,
        ) {
            counted.insert(keyid);
        }
    }
    let valid = counted.len();
    Threshold {
        ok: valid as f64 >= threshold,
        valid,
        threshold,
    }
}

/// A trusted Rekor log: its id (the SHA-256 of its key, hex) and its key.
pub struct RekorLog {
    pub log_id_hex: String,
    pub spki: Vec<u8>,
}

/// cosign's `VerifySET()`: `None` when the signed entry timestamp verifies,
/// otherwise why not.
pub fn verify_rekor_set(
    payload: &Json,
    set: &[u8],
    logs: &[RekorLog],
) -> Option<String> {
    let log_id = if truthy(payload.get("logID")) {
        payload.get("logID").map(js_string_of).unwrap_or_default()
    } else {
        String::new()
    }
    .to_lowercase();
    let Some(trusted) =
        logs.iter().find(|l| l.log_id_hex.to_lowercase() == log_id)
    else {
        return Some(format!(
            "rekor log public key not found for payload (log ID {})",
            log_id
        ));
    };
    let mut fields = Map::new();
    for name in ["body", "integratedTime", "logIndex", "logID"] {
        if let Some(v) = payload.get(name) {
            fields.insert(name.to_string(), v.clone());
        }
    }
    let canonical = jcs_canonical_json(&Json::Object(fields));
    if verify_with_public_key(&trusted.spki, canonical.as_bytes(), set, false) {
        None
    } else {
        Some("unable to verify SET".to_string())
    }
}

/// DSSE v1's pre-authentication encoding.
pub fn dsse_pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "DSSEv1 {} {} {} ",
        payload_type.len(),
        payload_type,
        payload.len()
    )
    .into_bytes();
    out.extend_from_slice(payload);
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Lower-case hex SHA-256.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hash(MessageDigest::sha256(), bytes)
        .map(|d| hex(&d))
        .unwrap_or_default()
}

/// Lower-case hex SHA-512.
pub fn sha512_hex(bytes: &[u8]) -> String {
    hash(MessageDigest::sha512(), bytes)
        .map(|d| hex(&d))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn numbers_as_javascript_writes_them() {
        for (x, want) in [
            (0.0, "0"),
            (1.0, "1"),
            (-1.5, "-1.5"),
            (1e21, "1e+21"),
            (1e20, "100000000000000000000"),
            (123456789.0, "123456789"),
            (0.000001, "0.000001"),
            (0.0000001, "1e-7"),
            (1.5e-7, "1.5e-7"),
            (0.1, "0.1"),
            (5e-324, "5e-324"),
            (1.7976931348623157e308, "1.7976931348623157e+308"),
            (123.456, "123.456"),
        ] {
            assert_eq!(js_number(x), want, "{}", x);
        }
    }

    #[test]
    fn the_two_canonical_forms_differ() {
        let v =
            json!({"b": "x\ny", "a": [1, true, null], "\u{e9}": "\u{1F600}"});
        assert_eq!(
            olpc_canonical_json(&v).unwrap(),
            "{\"a\":[1,true,null],\"b\":\"x\ny\",\"\u{e9}\":\"\u{1F600}\"}"
        );
        assert_eq!(
            jcs_canonical_json(&v),
            "{\"a\":[1,true,null],\"b\":\"x\\ny\",\"\u{e9}\":\"\u{1F600}\"}"
        );
        assert!(olpc_canonical_json(&json!(1.5)).is_err());
    }

    #[test]
    fn pae() {
        assert_eq!(dsse_pae("t", b"ab"), b"DSSEv1 1 t 2 ab");
    }
}
