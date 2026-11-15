// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE BINDINGS (saml-bindings-2.0-os; `saml2_sso.ts`'s `decodeMessage()`,
//! `encodeRedirect()`, `encodePost()`, `withoutEnvelopedSignature()`,
//! `redirectUrlFor()`, `simpleSignFields()` and `postBindingPage()`).
//!
//! * a message ARRIVING is base64, and DEFLATEd on the Redirect binding:
//!   [`decode_message`] reads plain XML (a first byte of `<`) as it is, and
//!   inflates anything else under `validation.inflate()`'s ceiling, handing
//!   back the bytes as text when they are not DEFLATE data or inflate past
//!   it, so the parse refuses them as it refuses any malformed message;
//! * a message LEAVING on the Redirect binding has its enveloped signature
//!   taken off and the query string signed instead (section 3.4.4.1), in the
//!   order that section fixes; on SimpleSign the octets are the raw XML.
//!
//! ONE DIFFERENCE IN BYTES, AND IT CHANGES NOTHING A RECEIVER READS: the
//! DEFLATE stream is `flate2`'s, not zlib's, so a Redirect URL's
//! `SAMLResponse` is a different (equally valid) compression of the same
//! XML; the signature is over what is sent, so it verifies wherever Node's
//! does. The vectors compare the inflated message.

use std::io::{Read as _, Write as _};

use base64::Engine;

use crate::model::escape;

/// `validation.CAP.LARGE`: the inflate ceiling.
pub const INFLATE_MAX: usize = 1_048_576;

/// `Buffer.from(text, 'base64')`: both alphabets, anything else skipped,
/// the end at the first `=`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn node_base64(text: &str) -> Vec<u8> {
    let mut bits: u32 = 0;
    let mut count = 0;
    let mut out = Vec::new();
    for c in text.chars() {
        let v = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32 + 26,
            '0'..='9' => c as u32 - '0' as u32 + 52,
            '+' | '-' => 62,
            '/' | '_' => 63,
            '=' => break,
            _ => continue,
        };
        bits = (bits << 6) | v;
        count += 1;
        if count == 4 {
            out.extend([(bits >> 16) as u8, (bits >> 8) as u8, bits as u8]);
            bits = 0;
            count = 0;
        }
    }
    match count {
        2 => out.push((bits >> 4) as u8),
        3 => out.extend([(bits >> 10) as u8, (bits >> 2) as u8]),
        _ => {}
    }
    out
}

/// `buf.toString('utf8')`: invalid sequences become U+FFFD.
fn utf8(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// `validation.inflate(buf, what)`: raw DEFLATE with a ceiling, `None` for
/// data that is not DEFLATE or inflates past it.
#[tracing::instrument(level = "debug", skip_all)]
pub fn inflate(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut decoder =
        flate2::read::DeflateDecoder::new(bytes).take(INFLATE_MAX as u64 + 1);
    decoder.read_to_end(&mut out).ok()?;
    if out.len() > INFLATE_MAX {
        return None;
    }
    Some(out)
}

/// `decodeMessage(encoded)`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn decode_message(encoded: &str) -> String {
    let buf = node_base64(encoded);
    if buf.first() == Some(&b'<') {
        return utf8(&buf);
    }
    match inflate(&buf) {
        Some(inflated) => utf8(&inflated),
        None => utf8(&buf),
    }
}

/// `encodeRedirect(xml)`: raw DEFLATE, then base64.
#[tracing::instrument(level = "debug", skip_all)]
pub fn encode_redirect(xml: &str) -> String {
    let mut enc = flate2::write::DeflateEncoder::new(
        Vec::new(),
        flate2::Compression::new(6),
    );
    let bytes = enc
        .write_all(xml.as_bytes())
        .and_then(|_| enc.finish())
        .unwrap_or_default();
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// `encodePost(xml)`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn encode_post(xml: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(xml.as_bytes())
}

/// `encodeURIComponent()`.
#[tracing::instrument(level = "debug", skip_all)]
pub fn encode_uri_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')'
            )
        {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

fn is_name_start(c: u8) -> bool {
    c.is_ascii_alphabetic() || c == b'_'
}

fn is_name(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-')
}

/// The end of an element whose start tag begins at `at` and whose local
/// name is `local` (any prefix): the index after its first matching end
/// tag, lazily as `[\s\S]*?<\/(?:p:)?local>` finds it. `None` when the tag
/// at `at` is not `<(p:)?local\b`.
fn element_span(xml: &str, at: usize, local: &str) -> Option<usize> {
    let b = xml.as_bytes();
    if b.get(at) != Some(&b'<') {
        return None;
    }
    let mut i = at + 1;
    // An optional prefix.
    let name_at = {
        let mut j = i;
        if b.get(j).is_some_and(|&c| is_name_start(c)) {
            j += 1;
            while b.get(j).is_some_and(|&c| is_name(c)) {
                j += 1;
            }
            if b.get(j) == Some(&b':') {
                j + 1
            } else {
                i
            }
        } else {
            i
        }
    };
    i = name_at;
    if b.get(i..i + local.len()) != Some(local.as_bytes()) {
        return None;
    }
    i += local.len();
    // `\b`: the next character is not a word character.
    if b.get(i)
        .is_some_and(|&c| c.is_ascii_alphanumeric() || c == b'_')
    {
        return None;
    }
    // The first `</(p:)?local>` after it.
    let mut k = i;
    while let Some(rel) = xml[k..].find("</") {
        let close = k + rel;
        let mut n = close + 2;
        if b.get(n).is_some_and(|&c| is_name_start(c)) {
            let mut j = n + 1;
            while b.get(j).is_some_and(|&c| is_name(c)) {
                j += 1;
            }
            if b.get(j) == Some(&b':') {
                n = j + 1;
            }
        }
        if b.get(n..n + local.len()) == Some(local.as_bytes())
            && b.get(n + local.len()) == Some(&b'>')
        {
            return Some(n + local.len() + 1);
        }
        // Without the prefix: `</local>`.
        if b.get(close + 2..close + 2 + local.len()) == Some(local.as_bytes())
            && b.get(close + 2 + local.len()) == Some(&b'>')
        {
            return Some(close + 3 + local.len());
        }
        k = close + 2;
    }
    None
}

/// `withoutEnvelopedSignature(xml)`: the ds:Signature right after the
/// root's start tag (or after its Issuer) taken out, as Node's pattern
/// takes it; a signature anywhere else — inside the assertion — is left.
#[tracing::instrument(level = "debug", skip_all)]
pub fn without_enveloped_signature(xml: &str) -> String {
    let Some(start_end) = xml.find('>').map(|i| i + 1) else {
        return xml.to_string();
    };
    let skip_ws = |mut i: usize| {
        while xml
            .as_bytes()
            .get(i)
            .is_some_and(|c| c.is_ascii_whitespace())
        {
            i += 1;
        }
        i
    };
    // `(?:\s*<Issuer…</Issuer>)?` then `\s*<Signature…</Signature>`.
    let try_from = |kept: usize| -> Option<String> {
        let at = skip_ws(kept);
        let end = element_span(xml, at, "Signature")?;
        Some(format!("{}{}", &xml[..kept], &xml[end..]))
    };
    let after_issuer = element_span(xml, skip_ws(start_end), "Issuer");
    if let Some(issuer_end) = after_issuer {
        if let Some(out) = try_from(issuer_end) {
            return out;
        }
    }
    try_from(start_end).unwrap_or_else(|| xml.to_string())
}

/// The detached signature over a query string or SimpleSign octets
/// (`crypto.signQueryString()` with the realm's key).
pub trait QuerySigner {
    /// The SignatureMethod URI the realm signs with.
    fn sig_alg(&self) -> String;
    /// The base64 signature over `octets`.
    fn sign(&self, octets: &str, sig_alg: &str) -> Result<String, String>;
}

/// `redirectUrlFor(destination, field, xml, relayState, sp)`: `signer` is
/// the realm's when `saml2.signResponse` holds for the service provider.
#[tracing::instrument(level = "debug", skip_all)]
pub fn redirect_url_for(
    destination: &str,
    field: &str,
    xml: &str,
    relay_state: &str,
    signer: Option<&dyn QuerySigner>,
) -> String {
    let mut qs = format!(
        "{}={}",
        field,
        encode_uri_component(&encode_redirect(&without_enveloped_signature(
            xml
        )))
    );
    if !relay_state.is_empty() {
        qs.push_str(&format!(
            "&RelayState={}",
            encode_uri_component(relay_state)
        ));
    }
    if let Some(s) = signer {
        let sig_alg = s.sig_alg();
        qs.push_str(&format!("&SigAlg={}", encode_uri_component(&sig_alg)));
        let signature = s.sign(&qs, &sig_alg).unwrap_or_default();
        qs.push_str(&format!(
            "&Signature={}",
            encode_uri_component(&signature)
        ));
    }
    format!(
        "{}{}{}",
        destination,
        if destination.contains('?') { '&' } else { '?' },
        qs
    )
}

/// `simpleSignFields(field, xml, relayState, sp)`: the form's message and,
/// when signed, `SigAlg` and `Signature` over the raw XML's octets.
#[tracing::instrument(level = "debug", skip_all)]
pub fn simple_sign_fields(
    field: &str,
    xml: &str,
    relay_state: &str,
    signer: Option<&dyn QuerySigner>,
) -> (String, Vec<(String, String)>) {
    let bare = without_enveloped_signature(xml);
    let message = encode_post(&bare);
    let mut extra = Vec::new();
    if let Some(s) = signer {
        let sig_alg = s.sig_alg();
        let octets = format!(
            "{}={}{}&SigAlg={}",
            field,
            bare,
            if relay_state.is_empty() {
                String::new()
            } else {
                format!("&RelayState={}", relay_state)
            },
            sig_alg
        );
        extra.push(("SigAlg".to_string(), sig_alg.clone()));
        extra.push((
            "Signature".to_string(),
            s.sign(&octets, &sig_alg).unwrap_or_default(),
        ));
    }
    (message, extra)
}

/// The words a POST-binding page carries (`note`), already translated.
#[derive(Clone, Debug, Default)]
pub struct PostNote {
    pub title: String,
    /// HTML, as Node passes it.
    pub sub: String,
    /// `handoff.saml2.continueToSp`, HTML.
    pub continue_label: String,
    /// `handoff.common.postingTo` with the destination, HTML.
    pub posting_to: String,
    /// `handoff.common.field` with the field and length, HTML.
    pub field_line: String,
    /// `handoff.saml2.relayStateEchoed` or `relayStateNone`, HTML.
    pub relay_line: String,
    /// `handoff.common.autopost` with the script, HTML.
    pub autopost_line: String,
}

/// `/saml2/autopost.js`.
pub const AUTOPOST_PATH: &str = "/saml2/autopost.js";

/// `postBindingPage(destination, field, message, relayState, note, extra)`:
/// the page's inner HTML — a real form and a real button, which with the
/// script blocked is the whole mechanism.
#[tracing::instrument(level = "debug", skip_all)]
pub fn post_binding_page(
    destination: &str,
    field: &str,
    message: &str,
    relay_state: &str,
    note: &PostNote,
    extra: &[(String, String)],
) -> String {
    let mut out = format!(
        "<h1>{}</h1><p class=\"sub\">{}</p><form method=\"post\" \
         action=\"{}\" id=\"saml2-form\"><input type=\"hidden\" \
         name=\"{}\" value=\"{}\">",
        escape(&note.title),
        note.sub,
        escape(destination),
        field,
        escape(message)
    );
    if !relay_state.is_empty() {
        out.push_str(&format!(
            "<input type=\"hidden\" name=\"RelayState\" value=\"{}\">",
            escape(relay_state)
        ));
    }
    for (name, value) in extra {
        out.push_str(&format!(
            "<input type=\"hidden\" name=\"{}\" value=\"{}\">",
            name,
            escape(value)
        ));
    }
    out.push_str(&format!(
        "<div class=\"row\"><button type=\"submit\">{}</button></div></form>\
         <div class=\"meta\"><div>{}</div><div>{}</div><div>{}</div><div>{}\
         </div></div><script src=\"{}\"></script>",
        note.continue_label,
        note.posting_to,
        note.field_line,
        note.relay_line,
        note.autopost_line,
        AUTOPOST_PATH
    ));
    out
}

/// `/saml2/autopost.js`'s text, the one script the page names
/// (`AUTOPOST_SCRIPT` in `saml2_sso.ts`).
pub const AUTOPOST_SCRIPT: &str = "(function () {\n  var f = document.\
    getElementById(\"saml2-form\");\n  if (f) { f.submit(); }\n})();\n";

/// `page(title, inner, t)`'s style sheet, inline because `app.js` sets
/// `default-src 'none'` with `style-src 'unsafe-inline'` here.
const PAGE_STYLE: &str = "body{font-family:system-ui,-apple-system,\"Segoe UI\",Arial,sans-serif;background:#f4f4f7;margin:0;padding:2rem;color:#222;line-height:1.45}.card{background:#fff;border:1px solid #d5d5dd;border-radius:10px;padding:24px 28px;max-width:56rem;margin:0 auto;box-shadow:0 6px 24px rgba(0,0,0,.08)}h1{font-size:1.3em;margin:0 0 4px;color:#12107c}h2{font-size:1em;margin:1.4em 0 .4em}p.sub{color:#666;font-size:.85em;margin:0 0 18px}.row{display:flex;gap:10px;margin-top:20px}button{padding:9px 14px;border-radius:5px;border:1px solid #12107c;background:#12107c;color:#fff;font-size:.95em;cursor:pointer}button.secondary{background:#fff;color:#12107c}.err{background:#fdecea;border:1px solid #f5c6c2;color:#b00020;padding:8px 10px;border-radius:5px;font-size:.9em;margin-bottom:12px}.ok{background:#e8f5e9;border:1px solid #a5d6a7;padding:8px 10px;border-radius:5px;font-size:.9em;margin-bottom:12px}table{border-collapse:collapse;width:100%;margin:.5rem 0 1rem;font-size:.85em}th,td{border:1px solid #ddd;padding:.35rem .55rem;text-align:left;vertical-align:top}th{background:#f0f0f5}.pass{color:#0b6b4f;font-weight:600;white-space:nowrap}.fail{color:#b00020;font-weight:600;white-space:nowrap}.meta{margin-top:18px;padding-top:12px;border-top:1px solid #eee;font-size:.78em;color:#666;word-break:break-all}.meta div{margin:3px 0}pre{background:#f4f4f8;border:1px solid #e2e2ea;border-radius:5px;padding:.6rem;font-size:.75rem;overflow-x:auto;white-space:pre-wrap;word-break:break-all}code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.85em;background:#f4f4f8;padding:.1rem .25rem;border-radius:3px;word-break:break-all}a{color:#12107c}ul{margin:.3em 0;padding-left:1.2em}li{margin:.2em 0}";

/// `page(title, inner, t)`: the one shell, `wsfed.ts`'s. `html_attributes`
/// is `PageLocale.htmlAttributes(t)` for a translated page, ` lang="en"`
/// for one that is not.
#[tracing::instrument(level = "debug", skip_all)]
pub fn page(title: &str, inner: &str, html_attributes: &str) -> String {
    format!(
        "<!DOCTYPE html>\n<html{}><head><meta charset=\"utf-8\"><meta \
         name=\"viewport\" content=\"width=device-width, \
         initial-scale=1\"><title>{}</title><style>{}</style></head><body>\
         <div class=\"card\">{}</div></body></html>\n",
        if html_attributes.is_empty() {
            " lang=\"en\""
        } else {
            html_attributes
        },
        escape(title),
        PAGE_STYLE,
        inner
    )
}
