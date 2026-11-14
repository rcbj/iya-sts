// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! WHAT THE REVERSE PROXY DOES TO A REQUEST BEFORE ANYTHING DECIDES ON IT
//! (#1760): the path normalised or refused, and the headers that may not
//! cross in either direction. Pure; `proxy.rs` calls it.
//!
//! **THE PATH IS NORMALISED BEFORE IT IS MATCHED, AND THE NORMALISED PATH
//! IS WHAT IS FORWARDED** — never the raw one — so the route that decided
//! and the resource the application serves are the same string. What could
//! make them differ is refused (400): a `.` or `..` segment, `//`, a
//! backslash, a NUL or any control character, an invalid percent-escape,
//! and an ENCODED `.`, `/`, `\` or NUL (`%2e`, `%2f`, `%5c`, `%00`), which
//! an application decoding its path would read as traversal the route
//! table never saw. An escape of an UNRESERVED character (RFC 3986 section
//! 2.3) is DECODED, which section 6.2.2.2 says changes nothing — so
//! `/%61pi` is matched, and forwarded, as `/api`, and cannot slip past an
//! exact route to a prefix route behind it. Every other escape is kept,
//! its hex upper-cased.

use axum::http::{HeaderMap, HeaderName, HeaderValue};

use crate::proxy_config::Route;

/// The proxy's own session cookie (D5).
pub const SESSION_COOKIE: &str = "iya_pep_session";

/// Why a path was refused.
pub type PathRefusal = &'static str;

fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// The request path, normalised, or why not. `raw` is the path as it
/// arrived (percent-encoded, no query).
pub fn normalise_path(raw: &str) -> Result<String, PathRefusal> {
    if !raw.starts_with('/') {
        return Err("the path does not start with /");
    }
    let bytes = raw.as_bytes();
    let mut out = String::with_capacity(raw.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\\' {
            return Err("the path holds a backslash");
        }
        if b < 0x20 || b == 0x7f {
            return Err("the path holds a control character");
        }
        if b >= 0x80 {
            return Err("the path holds a byte that is not ASCII");
        }
        if b != b'%' {
            out.push(b as char);
            i += 1;
            continue;
        }
        let (Some(hi), Some(lo)) = (
            bytes.get(i + 1).copied().and_then(hex_value),
            bytes.get(i + 2).copied().and_then(hex_value),
        ) else {
            return Err("the path holds an invalid percent-escape");
        };
        let v = hi * 16 + lo;
        match v {
            b'.' => return Err("the path holds an encoded . (%2e)"),
            b'/' => return Err("the path holds an encoded / (%2f)"),
            b'\\' => return Err("the path holds an encoded \\ (%5c)"),
            0 => return Err("the path holds an encoded NUL (%00)"),
            _ if v < 0x20 || v == 0x7f => {
                return Err("the path holds an encoded control character")
            }
            _ if v.is_ascii_alphanumeric()
                || v == b'-'
                || v == b'_'
                || v == b'~' =>
            {
                out.push(v as char)
            }
            _ => out.push_str(&format!("%{:02X}", v)),
        }
        i += 3;
    }
    if out.contains("//") {
        return Err("the path holds //");
    }
    if out.split('/').any(|s| s == "." || s == "..") {
        return Err("the path holds a . or .. segment");
    }
    Ok(out)
}

/// The hop-by-hop headers (RFC 9110 section 7.6.1), and those `Connection`
/// names. A `Proxy-*` header is one too: it is addressed to a proxy.
fn hop_by_hop(headers: &HeaderMap) -> Vec<String> {
    let mut names: Vec<String> = [
        "connection",
        "keep-alive",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    for value in headers.get_all("connection") {
        if let Ok(text) = value.to_str() {
            for token in text.split(',') {
                let token = token.trim().to_ascii_lowercase();
                if !token.is_empty() {
                    names.push(token);
                }
            }
        }
    }
    names
}

fn is_hop_by_hop(name: &str, listed: &[String]) -> bool {
    name.starts_with("proxy-") || listed.iter().any(|l| l == name)
}

/// The `Cookie` header without the proxy's own cookie, or `None` when
/// nothing is left.
pub fn cookie_without(value: &str, name: &str) -> Option<String> {
    let kept: Vec<&str> = value
        .split(';')
        .map(str::trim)
        .filter(|pair| !pair.is_empty())
        .filter(|pair| pair.split('=').next().map(str::trim) != Some(name))
        .collect();
    if kept.is_empty() {
        None
    } else {
        Some(kept.join("; "))
    }
}

/// A cookie's value, from every `Cookie` header.
pub fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    for value in headers.get_all("cookie") {
        let Ok(text) = value.to_str() else {
            continue;
        };
        for pair in text.split(';') {
            let mut parts = pair.trim().splitn(2, '=');
            if parts.next().map(str::trim) == Some(name) {
                if let Some(v) = parts.next() {
                    return Some(v.trim().to_string());
                }
            }
        }
    }
    None
}

/// The request headers that may reach the application: hop-by-hop gone,
/// every forwarding header the CLIENT sent gone (they are set fresh by the
/// caller), `Host` gone (the upstream's is the client library's), any
/// header named like the route's identity headers gone, and — unless the
/// route forwards credentials — `Authorization` and the proxy's own cookie.
pub fn forward_headers(incoming: &HeaderMap, route: &Route) -> HeaderMap {
    let listed = hop_by_hop(incoming);
    let identity: Vec<&str> = [&route.subject_header, &route.mechanism_header]
        .iter()
        .filter_map(|h| h.as_ref().map(HeaderName::as_str))
        .collect();
    let mut out = HeaderMap::new();
    for (name, value) in incoming {
        let n = name.as_str();
        if is_hop_by_hop(n, &listed)
            || n == "host"
            || n == "forwarded"
            || n.starts_with("x-forwarded-")
            || identity.contains(&n)
        {
            continue;
        }
        if !route.forward_credentials {
            if n == "authorization" {
                continue;
            }
            if n == "cookie" {
                let rest = value
                    .to_str()
                    .ok()
                    .and_then(|v| cookie_without(v, SESSION_COOKIE));
                if let Some(v) =
                    rest.and_then(|r| HeaderValue::from_str(&r).ok())
                {
                    out.append(name.clone(), v);
                }
                continue;
            }
        }
        out.append(name.clone(), value.clone());
    }
    out
}

/// The response headers that may reach the client: hop-by-hop gone.
pub fn response_headers(incoming: &HeaderMap) -> HeaderMap {
    let listed = hop_by_hop(incoming);
    let mut out = HeaderMap::new();
    for (name, value) in incoming {
        if !is_hop_by_hop(name.as_str(), &listed) {
            out.append(name.clone(), value.clone());
        }
    }
    out
}

/// A browser: a GET or HEAD that accepts HTML.
pub fn is_browser(method: &str, headers: &HeaderMap) -> bool {
    (method == "GET" || method == "HEAD")
        && headers
            .get_all("accept")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .any(|v| v.to_ascii_lowercase().contains("text/html"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy_config::{Match, Mechanism};

    #[test]
    fn traversal_and_its_spellings_are_refused() {
        for bad in [
            "/a/../b",
            "/a/./b",
            "/..",
            "/a//b",
            "//a",
            "/a/%2e%2e/b",
            "/a/%2E%2e/b",
            "/a/.%2e/b",
            "/a%2fb",
            "/a%2Fb",
            "/a%2eb",
            "/a/%2E",
            "/a%5cb",
            "/a\\b",
            "/a%00b",
            "/a%0ab",
            "/a%zz",
            "/a%4",
            "/a%",
            "a/b",
            "/a\u{1}b",
        ] {
            assert!(normalise_path(bad).is_err(), "{} was accepted", bad);
        }
    }

    #[test]
    fn unreserved_escapes_are_decoded_and_others_kept() {
        assert_eq!(normalise_path("/%61pi/x").unwrap(), "/api/x");
        assert_eq!(normalise_path("/a%20b").unwrap(), "/a%20b");
        assert_eq!(normalise_path("/a%3bb").unwrap(), "/a%3Bb");
        assert_eq!(normalise_path("/").unwrap(), "/");
        assert_eq!(normalise_path("/api/").unwrap(), "/api/");
        assert_eq!(normalise_path("/a.b/.c").unwrap(), "/a.b/.c");
    }

    fn route(forward: bool) -> Route {
        Route {
            id: "api".into(),
            path: "/api".into(),
            matching: Match::Prefix,
            methods: Vec::new(),
            public: false,
            mechanisms: vec![Mechanism::OAuth2],
            application: "a".into(),
            signals: true,
            resolved: Default::default(),
            resource: String::new(),
            action: String::new(),
            subject_header: Some(HeaderName::from_static("x-remote-user")),
            mechanism_header: Some(HeaderName::from_static("x-remote-auth")),
            forward_credentials: forward,
        }
    }

    #[test]
    fn credentials_forwarding_and_hop_by_hop_headers_are_stripped() {
        let mut h = HeaderMap::new();
        for (n, v) in [
            ("authorization", "Bearer secret"),
            ("cookie", "a=1; iya_pep_session=xyz; b=2"),
            ("connection", "close, x-private"),
            ("x-private", "1"),
            ("keep-alive", "timeout=5"),
            ("proxy-authorization", "Basic x"),
            ("te", "trailers"),
            ("trailer", "x"),
            ("transfer-encoding", "chunked"),
            ("upgrade", "websocket"),
            ("x-forwarded-for", "6.6.6.6"),
            ("x-forwarded-host", "evil"),
            ("forwarded", "for=6.6.6.6"),
            ("host", "pep"),
            ("x-remote-user", "admin"),
            ("X-Remote-Auth", "basic"),
            ("accept", "application/json"),
            ("content-length", "4"),
        ] {
            h.append(
                HeaderName::from_bytes(n.as_bytes()).unwrap(),
                HeaderValue::from_static(v),
            );
        }
        let out = forward_headers(&h, &route(false));
        let names: Vec<&str> = out.keys().map(HeaderName::as_str).collect();
        assert_eq!(names, ["cookie", "accept", "content-length"], "{:?}", out);
        assert_eq!(out["cookie"], "a=1; b=2");
        let kept = forward_headers(&h, &route(true));
        assert_eq!(kept["authorization"], "Bearer secret");
        assert!(kept["cookie"].to_str().unwrap().contains("iya_pep_session"));
        assert!(kept.get("x-remote-user").is_none());
        let mut only = HeaderMap::new();
        only.insert("cookie", HeaderValue::from_static("iya_pep_session=1"));
        assert!(forward_headers(&only, &route(false))
            .get("cookie")
            .is_none());
    }

    #[test]
    fn response_hop_by_hop_headers_are_stripped() {
        let mut h = HeaderMap::new();
        h.insert("connection", HeaderValue::from_static("x-a"));
        h.insert("x-a", HeaderValue::from_static("1"));
        h.insert("transfer-encoding", HeaderValue::from_static("chunked"));
        h.insert("content-type", HeaderValue::from_static("text/plain"));
        let out = response_headers(&h);
        assert_eq!(out.len(), 1);
        assert!(out.contains_key("content-type"));
    }

    #[test]
    fn cookies_and_browsers() {
        let mut h = HeaderMap::new();
        h.append("cookie", HeaderValue::from_static("a=1"));
        h.append("cookie", HeaderValue::from_static("iya_pep_session=abc"));
        assert_eq!(cookie_value(&h, SESSION_COOKIE).as_deref(), Some("abc"));
        h.insert("accept", HeaderValue::from_static("text/html,*/*"));
        assert!(is_browser("GET", &h));
        assert!(!is_browser("POST", &h));
        h.insert("accept", HeaderValue::from_static("application/json"));
        assert!(!is_browser("GET", &h));
    }
}
