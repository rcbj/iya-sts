// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE COOKIE: `<sid>.<handle>`, AND ONLY THE HANDLE IS A SECRET (2026-09-14).
//!
//! `session.id` IS the `sid` and never changes; the HANDLE is minted by
//! [`mint_handle`], rotated on every re-authentication and on an arrival's
//! upgrade, and the store holds only its SHA-256 (`handleHash`), so a copy
//! of the store or a row printed on a console page is no way into anybody's
//! session. A cookie with no handle is refused, and so is a row with no
//! `handleHash`: relying-party and API rows live in the same store and
//! their ids are printed on `/admin/sessions`.
//!
//! Inside the service the cookie is `sts_session`; between the socket and a
//! browser in product mode it is `__Host-sts_session` (or `__Secure-` with
//! `authn.cookieDomain`), which `sts-http`'s `cookie_wire` writes and
//! strips — `common/cookie_wire.ts`'s rule, applied where the socket is,
//! so nothing here names a prefix.

use serde_json::{json, Value};

use crate::js::Object;
use crate::record::SESSION_COOKIE;

/// `decodeURIComponent()`: `%XX` sequences as UTF-8; anything malformed is
/// JavaScript's `URIError`, whose message this is.
fn decode_uri_component(text: &str) -> Result<String, String> {
    let bytes = text.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'%' {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        let hex = text.get(i + 1..i + 3).ok_or("URI malformed")?;
        let b = u8::from_str_radix(hex, 16).map_err(|_| "URI malformed")?;
        out.push(b);
        i += 3;
    }
    String::from_utf8(out).map_err(|_| "URI malformed".to_string())
}

/// `cookiesOf(req)`: a request's Cookie header as a map of name to decoded
/// value; a later cookie of one name wins. An `Err` is Node's `URIError`
/// on a malformed percent escape (see [`crate::Sessions::session_of`]).
// A hot path: every session read parses the header; no span.
pub fn cookies_of(header: &str) -> Result<Object, String> {
    let mut out = Object::new();
    for part in header.split(';') {
        let Some(i) = part.find('=') else {
            continue;
        };
        if i == 0 {
            continue;
        }
        let name = part[..i].trim().to_string();
        let value = decode_uri_component(part[i + 1..].trim())?;
        out.insert(name, json!(value));
    }
    Ok(out)
}

/// The value of one cookie, or '' (a malformed header reads as none).
// A hot path, as cookies_of(); no span.
pub fn cookie_value(header: &str, name: &str) -> String {
    match cookies_of(header) {
        Ok(all) => match all.get(name) {
            Some(Value::String(v)) => v.clone(),
            _ => String::new(),
        },
        Err(e) => {
            tracing::debug!("authn: a Cookie header did not parse: {}", e);
            String::new()
        }
    }
}

/// `handleHashOf(handle)`: base64url SHA-256, what the row stores.
// A hot path: every session read compares one; no span.
pub fn handle_hash_of(handle: &str) -> String {
    sts_crypto::b64::encode(
        &sts_crypto::jws_alg::Hash::Sha256.digest(handle.as_bytes()),
    )
}

/// `stsCrypto.constantTimeEquals()` of two texts.
fn same(a: &str, b: &str) -> bool {
    sts_crypto::secrets::constant_time_equals(a.as_bytes(), b.as_bytes())
}

/// `mintSessionHandle(session)`: a fresh handle, its hash and instant on
/// the row, and a new OP browser state (#121) minted with it; answers the
/// cookie VALUE. The caller writes the row back through the store.
#[tracing::instrument(level = "debug", skip(session, random_id))]
pub fn mint_handle(
    session: &mut Object,
    now_ms: f64,
    random_id: impl Fn(usize) -> String,
) -> String {
    let handle = random_id(24);
    session.insert("handleHash".into(), json!(handle_hash_of(&handle)));
    session.insert("handleIssuedAt".into(), crate::js::num(now_ms));
    session.insert("browserState".into(), json!(random_id(24)));
    let id = crate::js::or_empty(session.get("id"));
    format!("{}.{}", id, handle)
}

/// `sessionCookieLine(name, value)`: the attributes every session cookie is
/// written with. The sign-on cookie carries `authn.cookieDomain` when set
/// (#472); a hosted surface's own stays host-only.
#[tracing::instrument(level = "debug", skip(value, domain))]
pub fn cookie_line(
    name: &str,
    value: &str,
    domain: &str,
    https: bool,
) -> String {
    format!(
        "{}={}; Path=/; HttpOnly; SameSite=Lax{}{}",
        name,
        value,
        if name == SESSION_COOKIE { domain } else { "" },
        if https { "; Secure" } else { "" }
    )
}

/// `clearSessionCookie()`'s line: the same Path, Domain and Secure, or it
/// would clear nothing.
#[tracing::instrument(level = "debug", skip(domain))]
pub fn clear_line(name: &str, domain: &str, https: bool) -> String {
    format!(
        "{}=; Path=/; Max-Age=0{}{}",
        name,
        if name == SESSION_COOKIE { domain } else { "" },
        if https { "; Secure" } else { "" }
    )
}

/// What a cookie names: the sid, and the handle it presents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Presented {
    pub id: String,
    pub handle: String,
}

/// The `<sid>.<handle>` of a cookie value, or `None` for a bare id, an
/// empty handle or no cookie.
// A hot path, as cookies_of(); no span.
pub fn presented(value: &str) -> Option<Presented> {
    let dot = value.find('.')?;
    if dot == 0 || dot == value.len() - 1 {
        return None;
    }
    Some(Presented {
        id: value[..dot].to_string(),
        handle: value[dot + 1..].to_string(),
    })
}

/// Whether a row holds the handle a cookie presents.
// A hot path, as cookies_of(); no span.
pub fn holds_handle(session: &Object, handle: &str) -> bool {
    match session.get("handleHash") {
        Some(Value::String(h)) if !h.is_empty() => {
            same(&handle_hash_of(handle), h)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cookie_header_parses_as_node_parses_it() {
        let c = cookies_of("sts_session=abc.def; other=2").unwrap();
        assert_eq!(c["sts_session"], "abc.def");
        assert_eq!(cookies_of("a=%41%20b").unwrap()["a"], "A b");
        assert!(cookies_of("x=%E0%A4%A").is_err());
        assert!(cookies_of("=v; noequals").unwrap().is_empty());
    }

    #[test]
    fn a_bare_id_presents_no_handle() {
        assert!(presented("abc").is_none());
        assert!(presented("abc.").is_none());
        assert!(presented(".abc").is_none());
        assert_eq!(presented("a.b.c").unwrap().handle, "b.c");
    }
}
