// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! DKIM (RFC 6376, RFC 8463) for the mail channel: `common/crypto.js`
//! section 12 (#63) — relaxed/relaxed only, `rsa-sha256` with at least 2048
//! bits (RFC 8301) and `ed25519-sha256` (PureEdDSA over the SHA-256 of the
//! canonical header data, not over the data).
//!
//! **A PORT, NOT `mail-auth`**, which DESIGN.md first named: both
//! algorithms are deterministic, so a port signs the same BYTES Node does,
//! and the canonicalization — the part two implementations disagree on —
//! is Node's own. The message is handled as bytes, as Node handles it as a
//! `binary` string; JavaScript's `trim()` and `\s` over such a string also
//! strip 0xA0, and so do [`js_trim`] and [`js_space`].
//!
//! The verifier is for this service's own tests and the console's "is my
//! key the one DNS publishes" check — this service receives no mail.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use openssl::hash::{hash, MessageDigest};
use openssl::pkey::{Id, PKey, PKeyRef, Private};
use openssl::sign::{Signer, Verifier};

use crate::error::{CryptoError, CryptoResult};

/// The DKIM algorithms this service signs with.
pub const DKIM_ALGORITHMS: [&str; 2] = ["rsa-sha256", "ed25519-sha256"];

/// The headers signed when present, in this order.
const SIGNED_HEADERS: [&str; 12] = [
    "from",
    "reply-to",
    "subject",
    "date",
    "to",
    "cc",
    "message-id",
    "mime-version",
    "content-type",
    "content-transfer-encoding",
    "in-reply-to",
    "references",
];

/// JavaScript's `trim()` over a `binary` string.
fn js_space(b: u8) -> bool {
    matches!(b, b'\t' | b'\n' | 0x0b | 0x0c | b'\r' | b' ' | 0xa0)
}

fn js_trim(s: &[u8]) -> &[u8] {
    let start = s.iter().position(|&b| !js_space(b)).unwrap_or(s.len());
    let end = s
        .iter()
        .rposition(|&b| !js_space(b))
        .map_or(start, |e| e + 1);
    &s[start..end.max(start)]
}

/// Runs of space and tab to one space.
fn squeeze(line: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(line.len());
    let mut in_run = false;
    for &b in line {
        if b == b' ' || b == b'\t' {
            if !in_run {
                out.push(b' ');
            }
            in_run = true;
        } else {
            out.push(b);
            in_run = false;
        }
    }
    out
}

/// Section 3.4.4's relaxed body.
pub fn relaxed_body(body: &[u8]) -> Vec<u8> {
    // \r?\n -> \r\n, then split on \r\n: a lone \r stays in its line.
    let mut lines: Vec<Vec<u8>> = vec![Vec::new()];
    let mut i = 0;
    while i < body.len() {
        if body[i] == b'\n' {
            lines.push(Vec::new());
        } else if body[i] == b'\r' && body.get(i + 1) == Some(&b'\n') {
            lines.push(Vec::new());
            i += 1;
        } else if let Some(l) = lines.last_mut() {
            l.push(body[i]);
        }
        i += 1;
    }
    let mut lines: Vec<Vec<u8>> = lines
        .into_iter()
        .map(|l| {
            let mut s = squeeze(&l);
            while s.last() == Some(&b' ') {
                s.pop();
            }
            s
        })
        .collect();
    while lines.last().is_some_and(Vec::is_empty) {
        lines.pop();
    }
    if lines.is_empty() {
        return Vec::new();
    }
    let mut out = lines.join(&b"\r\n"[..]);
    out.extend_from_slice(b"\r\n");
    out
}

/// Section 3.4.2's relaxed header: `name:value`.
pub fn relaxed_header(name: &[u8], value: &[u8]) -> Vec<u8> {
    // Unfold: a newline (\r?\n) followed by space or tab is removed.
    let mut unfolded = Vec::with_capacity(value.len());
    let mut i = 0;
    while i < value.len() {
        let nl = if value[i] == b'\r' && value.get(i + 1) == Some(&b'\n') {
            2
        } else if value[i] == b'\n' {
            1
        } else {
            0
        };
        if nl > 0 && matches!(value.get(i + nl), Some(b' ' | b'\t')) {
            i += nl;
            continue;
        }
        unfolded.push(value[i]);
        i += 1;
    }
    let mut out: Vec<u8> = js_trim(name).to_ascii_lowercase();
    out.push(b':');
    out.extend_from_slice(js_trim(&squeeze(&unfolded)));
    out
}

struct Field {
    name: Vec<u8>,
    value: Vec<u8>,
}

/// `dkimSplitMessage()`: the header fields, folding kept, and the body.
fn split_message(raw: &[u8]) -> (Vec<Field>, Vec<u8>) {
    // The first \r?\n\r?\n.
    let mut at = None;
    let mut i = 0;
    while i < raw.len() {
        let first = if raw[i] == b'\r' && raw.get(i + 1) == Some(&b'\n') {
            2
        } else if raw[i] == b'\n' {
            1
        } else {
            0
        };
        if first > 0 {
            let j = i + first;
            let second = if raw.get(j) == Some(&b'\r')
                && raw.get(j + 1) == Some(&b'\n')
            {
                2
            } else if raw.get(j) == Some(&b'\n') {
                1
            } else {
                0
            };
            if second > 0 {
                at = Some((i, j + second));
                break;
            }
        }
        i += 1;
    }
    let (head, body) = match at {
        Some((h, b)) => (&raw[..h], raw[b..].to_vec()),
        None => (raw, Vec::new()),
    };
    // Split on \r?\n not followed by space or tab.
    let mut lines: Vec<Vec<u8>> = vec![Vec::new()];
    let mut i = 0;
    while i < head.len() {
        let nl = if head[i] == b'\r' && head.get(i + 1) == Some(&b'\n') {
            2
        } else if head[i] == b'\n' {
            1
        } else {
            0
        };
        if nl > 0 && !matches!(head.get(i + nl), Some(b' ' | b'\t')) {
            lines.push(Vec::new());
            i += nl;
            continue;
        }
        if let Some(l) = lines.last_mut() {
            l.push(head[i]);
        }
        i += 1;
    }
    let fields = lines
        .into_iter()
        .filter_map(|line| {
            let colon = line.iter().position(|&b| b == b':')?;
            (colon > 0).then(|| Field {
                name: line[..colon].to_vec(),
                value: line[colon + 1..].to_vec(),
            })
        })
        .collect();
    (fields, body)
}

fn last_of<'a>(fields: &'a [Field], name: &str) -> Option<&'a Field> {
    fields
        .iter()
        .rev()
        .find(|f| js_trim(&f.name).eq_ignore_ascii_case(name.as_bytes()))
}

fn dns_labels(domain: &str) -> bool {
    let labels: Vec<&str> = domain.split('.').collect();
    labels.len() >= 2 && labels.iter().all(|l| label_ok(l, false))
}

fn label_ok(l: &str, selector: bool) -> bool {
    let b = l.as_bytes();
    !b.is_empty()
        && b[0].is_ascii_lowercase() | b[0].is_ascii_digit()
        && (b[b.len() - 1].is_ascii_lowercase()
            || b[b.len() - 1].is_ascii_digit())
        && b.iter().all(|&c| {
            c.is_ascii_lowercase()
                || c.is_ascii_digit()
                || c == b'-'
                || (selector && (c == b'.' || c == b'_'))
        })
}

/// The options `dkimSign()` takes.
pub struct DkimOptions<'a> {
    pub selector: &'a str,
    pub domain: &'a str,
    /// `rsa-sha256` when `None`.
    pub algorithm: Option<&'a str>,
    /// Seconds since the epoch; now when `None`.
    pub timestamp: Option<u64>,
}

fn sign_data(
    algorithm: &str,
    key: &PKeyRef<Private>,
    data: &[u8],
) -> CryptoResult<Vec<u8>> {
    if algorithm == "rsa-sha256" {
        let mut s = Signer::new(MessageDigest::sha256(), key)?;
        return Ok(s.sign_oneshot_to_vec(data)?);
    }
    let digest = hash(MessageDigest::sha256(), data)?;
    let mut s = Signer::new_without_digest(key)?;
    Ok(s.sign_oneshot_to_vec(&digest)?)
}

/// `dkimSign()`: the complete `DKIM-Signature:` field, without a trailing
/// CRLF, for the caller to put in front of the message.
pub fn dkim_sign(
    raw: &[u8],
    key: &PKeyRef<Private>,
    o: &DkimOptions,
) -> CryptoResult<String> {
    let algorithm = o.algorithm.unwrap_or("rsa-sha256");
    if !DKIM_ALGORITHMS.contains(&algorithm) {
        return Err(CryptoError::new(format!(
            "DKIM algorithm \"{}\" is not one of {}",
            algorithm,
            DKIM_ALGORITHMS.join(", ")
        )));
    }
    let domain = o.domain.trim().to_lowercase();
    let selector = o.selector.trim().to_lowercase();
    if !dns_labels(&domain) || !label_ok(&selector, true) {
        return Err(CryptoError::new(
            "a DKIM signature needs a domain (d=) and a selector (s=) that are DNS labels",
        ));
    }
    if algorithm == "rsa-sha256" {
        let bits = if key.id() == Id::RSA { key.bits() } else { 0 };
        if bits < 2048 {
            return Err(CryptoError::new(format!(
                "rsa-sha256 needs an RSA key of at least 2048 bits (RFC 8301); this key is {}{}",
                key_type(key),
                if bits > 0 {
                    format!(", {} bits", bits)
                } else {
                    String::new()
                }
            )));
        }
    } else if key.id() != Id::ED25519 {
        return Err(CryptoError::new(format!(
            "ed25519-sha256 needs an Ed25519 key; this key is {}",
            key_type(key)
        )));
    }
    let (fields, body) = split_message(raw);
    let body_hash =
        STANDARD.encode(hash(MessageDigest::sha256(), &relaxed_body(&body))?);
    if last_of(&fields, "from").is_none() {
        return Err(CryptoError::new(
            "a DKIM signature must cover From (RFC 6376 section 5.4), and the message has none",
        ));
    }
    let signed: Vec<&str> = SIGNED_HEADERS
        .iter()
        .copied()
        .filter(|n| last_of(&fields, n).is_some())
        .collect();
    let timestamp = o.timestamp.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    });
    let tags = format!(
        "v=1; a={}; c=relaxed/relaxed; d={}; s={}; t={}; h={}; bh={}; b=",
        algorithm,
        domain,
        selector,
        timestamp,
        signed.join(":"),
        body_hash
    );
    let mut data = Vec::new();
    for name in &signed {
        if let Some(f) = last_of(&fields, name) {
            data.extend(relaxed_header(name.as_bytes(), &f.value));
            data.extend_from_slice(b"\r\n");
        }
    }
    data.extend(relaxed_header(b"DKIM-Signature", tags.as_bytes()));
    let signature = sign_data(algorithm, key, &data)?;
    Ok(format!(
        "DKIM-Signature: {}{}",
        tags,
        STANDARD.encode(signature)
    ))
}

fn key_type<T>(key: &PKeyRef<T>) -> &'static str {
    match key.id() {
        Id::RSA => "rsa",
        Id::EC => "ec",
        Id::ED25519 => "ed25519",
        Id::ED448 => "ed448",
        _ => "unknown",
    }
}

/// `dkimVerify()`: `Ok(())`, or why the signature on a message does not
/// verify against the selector's public key.
pub fn dkim_verify(
    raw: &[u8],
    public_key_pem: &str,
) -> Result<(), &'static str> {
    let (fields, body) = split_message(raw);
    let Some(field) = fields
        .iter()
        .find(|f| js_trim(&f.name).eq_ignore_ascii_case(b"dkim-signature"))
    else {
        return Err("no DKIM-Signature field");
    };
    // Unfold (a newline and the space after it go), then the tags.
    let mut flat = Vec::new();
    let v = &field.value;
    let mut i = 0;
    while i < v.len() {
        let nl = if v[i] == b'\r' && v.get(i + 1) == Some(&b'\n') {
            2
        } else if v[i] == b'\n' {
            1
        } else {
            0
        };
        if nl > 0 && matches!(v.get(i + nl), Some(b' ' | b'\t')) {
            i += nl + 1;
            continue;
        }
        flat.push(v[i]);
        i += 1;
    }
    let mut tags: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for part in flat.split(|&b| b == b';') {
        if let Some(eq) =
            part.iter().position(|&b| b == b'=').filter(|&e| e > 0)
        {
            let key = js_trim(&part[..eq]).to_vec();
            let value: Vec<u8> = part[eq + 1..]
                .iter()
                .copied()
                .filter(|&b| !js_space(b))
                .collect();
            match tags.iter_mut().find(|(k, _)| *k == key) {
                Some(t) => t.1 = value,
                None => tags.push((key, value)),
            }
        }
    }
    let tag = |name: &str| {
        tags.iter()
            .find(|(k, _)| k == name.as_bytes())
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };
    let body_hash = hash(MessageDigest::sha256(), &relaxed_body(&body))
        .map(|d| STANDARD.encode(d).into_bytes())
        .unwrap_or_default();
    if body_hash != tag("bh") {
        return Err("the body hash does not match bh=");
    }
    let without_b = strip_b(&field.value);
    let mut data = Vec::new();
    let h = tag("h");
    for name in h.split(|&b| b == b':') {
        let lowered =
            String::from_utf8_lossy(js_trim(name)).to_ascii_lowercase();
        if let Some(f) = fields.iter().rev().find(|f| {
            String::from_utf8_lossy(js_trim(&f.name)).to_ascii_lowercase()
                == lowered
        }) {
            data.extend(relaxed_header(name, &f.value));
            data.extend_from_slice(b"\r\n");
        }
    }
    data.extend(relaxed_header(b"DKIM-Signature", &without_b));
    let signature = STANDARD.decode(tag("b")).unwrap_or_default();
    let ok = (|| -> Result<bool, openssl::error::ErrorStack> {
        let key = PKey::public_key_from_pem(public_key_pem.as_bytes())?;
        if tag("a") == b"ed25519-sha256" {
            let digest = hash(MessageDigest::sha256(), &data)?;
            Verifier::new_without_digest(&key)?
                .verify_oneshot(&signature, &digest)
        } else {
            Verifier::new(MessageDigest::sha256(), &key)?
                .verify_oneshot(&signature, &data)
        }
    })()
    .unwrap_or(false);
    if ok {
        Ok(())
    } else {
        Err("the signature does not verify")
    }
}

/// `value.replace(/(;\s*b=)[^;]*$/, '$1')`: the b= tag's value emptied when
/// it is the last tag.
fn strip_b(value: &[u8]) -> Vec<u8> {
    let Some(last_semi) = value.iter().rposition(|&b| b == b';') else {
        return value.to_vec();
    };
    let rest = &value[last_semi + 1..];
    let ws = rest.iter().take_while(|&&b| js_space(b)).count();
    if rest.get(ws) == Some(&b'b') && rest.get(ws + 1) == Some(&b'=') {
        return value[..last_semi + 1 + ws + 2].to_vec();
    }
    value.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::rsa::Rsa;

    const MESSAGE: &[u8] = b"From: Iya <noreply@example.com>\r\nTo: a@b.example\r\nSubject:  Hello\r\n\tthere \r\n\r\nBody  line \r\n\r\n\r\n";

    #[test]
    fn relaxed_canonicalization() {
        assert_eq!(relaxed_body(b"a  b \r\n\r\n"), b"a b\r\n");
        assert_eq!(relaxed_body(b""), b"");
        assert_eq!(relaxed_body(b"\r\n\r\n"), b"");
        assert_eq!(
            relaxed_header(b"Subject", b"  Hello\r\n\tthere "),
            b"subject:Hello there"
        );
    }

    #[test]
    fn both_algorithms_round_trip() {
        let rsa = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let ed = PKey::generate_ed25519().unwrap();
        for (alg, key) in [("rsa-sha256", &rsa), ("ed25519-sha256", &ed)] {
            let field = dkim_sign(
                MESSAGE,
                key,
                &DkimOptions {
                    selector: "s1",
                    domain: "example.com",
                    algorithm: Some(alg),
                    timestamp: Some(1),
                },
            )
            .unwrap();
            let mut signed = format!("{}\r\n", field).into_bytes();
            signed.extend_from_slice(MESSAGE);
            let pem =
                String::from_utf8(key.public_key_to_pem().unwrap()).unwrap();
            assert_eq!(dkim_verify(&signed, &pem), Ok(()), "{}", alg);
            let tampered =
                String::from_utf8(signed).unwrap().replace("Body", "Bxdy");
            assert!(dkim_verify(tampered.as_bytes(), &pem).is_err());
        }
        let small = PKey::from_rsa(Rsa::generate(1024).unwrap()).unwrap();
        let o = DkimOptions {
            selector: "s1",
            domain: "example.com",
            algorithm: None,
            timestamp: None,
        };
        assert!(dkim_sign(MESSAGE, &small, &o).is_err());
        assert!(dkim_sign(b"To: x@y.example\r\n\r\nx", &rsa, &o).is_err());
    }
}
