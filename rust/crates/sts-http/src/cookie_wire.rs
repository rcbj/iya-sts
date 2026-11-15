// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! What only the process holding the socket can know (#1438, #1441) — a
//! port of `common/cookie_wire.ts`: `Strict-Transport-Security` on an
//! answer over TLS, and every `sts_*` cookie under the `__Host-` (or, with
//! a `Domain`, `__Secure-`) prefix between the socket and the browser.
//!
//! Inside the service a cookie is still `sts_session`; on the wire it is
//! `__Host-sts_session`. An unprefixed `sts_*` cookie is DROPPED on the
//! way in (a sibling host or a cleartext answer can set one), so is a
//! `__Secure-` form nothing here writes, and the pool pins are spared.
//! Product mode prefixes (`mode.prefixesCookies()`) and sends HSTS
//! (`!mode.omitsStrictTransportSecurity()`); development does neither.
//! Both apply only to a request that arrived over TLS, which the listener
//! says by putting [`OverTls`] in the request's extensions.
//!
//! **WHAT REPLACED WHAT.** Node runs this in the main thread only, since a
//! request worker behind a unix socket cannot see the TLS; this runtime is
//! one process, so the layer runs wherever the request is served.

use axum::http::{header, HeaderMap, HeaderValue};

/// Put in a request's extensions by a listener that terminated TLS.
#[derive(Clone, Copy, Debug)]
pub struct OverTls;

/// The cookies spared the prefix rule: they select a worker.
const SPARED: &[&str] = &["sts_pool", "sts_pool_surfaces"];

/// What the layer is told, per request.
#[derive(Clone, Copy, Debug, Default)]
pub struct WireRules {
    pub over_tls: bool,
    /// `mode.prefixesCookies()`.
    pub prefixes: bool,
    /// `!mode.omitsStrictTransportSecurity()`.
    pub hsts: bool,
    /// `security.hstsIncludeSubDomains`.
    pub include_sub_domains: bool,
    /// `authn.cookieDomain` is set: `__Secure-` is a form written here.
    pub shared_domain: bool,
}

/// `prefixFor()`: `__Host-` for a cookie at `/` with no `Domain`.
// A hot path: every Set-Cookie line; no span.
pub fn prefix_for(attributes: &str) -> &'static str {
    let lower = attributes.to_ascii_lowercase();
    let has_domain = lower
        .split(';')
        .any(|a| a.trim_start().starts_with("domain="));
    let at_root = lower.split(';').any(|a| {
        let a = a.trim();
        a.strip_prefix("path=").is_some_and(|p| p.trim() == "/")
    });
    if !has_domain && at_root {
        "__Host-"
    } else {
        "__Secure-"
    }
}

/// `wrapLine()`: one `Set-Cookie` line in its wire form.
// A hot path: every Set-Cookie line; no span.
pub fn wrap_line(line: &str) -> String {
    let name = line.split('=').next().unwrap_or("").trim();
    if !line.contains('=') || !name.starts_with("sts_") {
        return line.to_string();
    }
    let secure = line
        .to_ascii_lowercase()
        .split(';')
        .any(|a| a.trim() == "secure");
    let line = if secure {
        line.to_string()
    } else {
        format!("{}; Secure", line)
    };
    format!("{}{}", prefix_for(&line), line)
}

/// `unwrapHeader()`: a `Cookie` header in the names the service reads,
/// without what must not be believed.
// A hot path: every request over TLS in product; no span.
pub fn unwrap_header(header: &str, shared_domain: bool) -> String {
    let mut kept: Vec<String> = Vec::new();
    for part in header.split(';') {
        let bit = part.trim();
        let (name, value) = match bit.find('=') {
            Some(at) if at > 0 => (&bit[..at], &bit[at..]),
            _ => (bit, ""),
        };
        let prefixed = name
            .strip_prefix("__Host-")
            .map(|n| ("Host", n))
            .or_else(|| name.strip_prefix("__Secure-").map(|n| ("Secure", n)))
            .filter(|(_, n)| n.starts_with("sts_"));
        if let Some((kind, inside)) = prefixed {
            if kind == "Host"
                || shared_domain
                || inside.starts_with("sts_session_bound")
            {
                kept.push(format!("{}{}", inside, value));
            }
        } else if (!name.starts_with("sts_") || SPARED.contains(&name))
            && !bit.is_empty()
        {
            kept.push(bit.to_string());
        }
    }
    kept.join("; ")
}

/// The request's `Cookie` header, translated in place.
#[tracing::instrument(level = "debug", skip_all)]
pub fn on_request(headers: &mut HeaderMap, rules: WireRules) {
    // OVER HTTP/2 A BROWSER SENDS EACH COOKIE AS A FIELD OF ITS OWN (RFC
    // 9113 section 8.2.3), and node's http2 compatibility layer joins them
    // with "; " before anything reads `req.headers.cookie`. Reading only the
    // first field lost every cookie after it: Chrome orders them by
    // creation, so a session re-set at sign-in moved behind the step cookie
    // and the authorization request saw nobody signed in (#444, phase 5).
    let fields: Vec<String> = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(str::to_string)
        .collect();
    if fields.is_empty() {
        return;
    }
    let header = fields.join("; ");
    let inside = if rules.over_tls && rules.prefixes {
        unwrap_header(&header, rules.shared_domain)
    } else {
        header
    };
    match HeaderValue::from_str(&inside) {
        Ok(v) if !inside.is_empty() => {
            headers.insert(header::COOKIE, v);
        }
        _ => {
            headers.remove(header::COOKIE);
        }
    }
}

/// The answer's HSTS and `Set-Cookie` lines, at the flush.
#[tracing::instrument(level = "debug", skip_all)]
pub fn on_response(headers: &mut HeaderMap, rules: WireRules) {
    if !rules.over_tls {
        return;
    }
    if rules.hsts {
        let value = if rules.include_sub_domains {
            "max-age=31536000; includeSubDomains"
        } else {
            "max-age=31536000"
        };
        headers.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static(value),
        );
    }
    if !rules.prefixes {
        return;
    }
    let lines: Vec<String> = headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(wrap_line)
        .collect();
    headers.remove(header::SET_COOKIE);
    for line in lines {
        if let Ok(v) = HeaderValue::from_str(&line) {
            headers.append(header::SET_COOKIE, v);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cookie_at_the_root_takes_the_host_prefix() {
        assert_eq!(
            wrap_line("sts_session=abc; Path=/; HttpOnly"),
            "__Host-sts_session=abc; Path=/; HttpOnly; Secure"
        );
        assert_eq!(
            wrap_line("sts_x=1; Path=/; Domain=example.com; Secure"),
            "__Secure-sts_x=1; Path=/; Domain=example.com; Secure"
        );
        assert_eq!(wrap_line("other=1; Path=/"), "other=1; Path=/");
    }

    #[test]
    fn an_unprefixed_service_cookie_is_not_believed() {
        assert_eq!(
            unwrap_header(
                "__Host-sts_session=a; sts_session=b; sts_pool=c; x=d",
                false
            ),
            "sts_session=a; sts_pool=c; x=d"
        );
        assert_eq!(unwrap_header("__Secure-sts_x=1", false), "");
        assert_eq!(unwrap_header("__Secure-sts_x=1", true), "sts_x=1");
    }

    #[test]
    fn every_cookie_field_of_an_http2_request_is_read() {
        let mut headers = HeaderMap::new();
        for field in [
            "__Host-sts_signin_step=s",
            "__Host-sts_session=a",
            "__Host-sts_accounts=b",
        ] {
            headers.append(header::COOKIE, HeaderValue::from_static(field));
        }
        let mut plain = headers.clone();
        let rules = WireRules {
            over_tls: true,
            prefixes: true,
            ..WireRules::default()
        };
        on_request(&mut headers, rules);
        assert_eq!(headers.get_all(header::COOKIE).iter().count(), 1);
        assert_eq!(
            headers.get(header::COOKIE).unwrap(),
            "sts_signin_step=s; sts_session=a; sts_accounts=b"
        );
        on_request(
            &mut plain,
            WireRules {
                over_tls: false,
                ..rules
            },
        );
        assert_eq!(
            plain.get(header::COOKIE).unwrap(),
            "__Host-sts_signin_step=s; __Host-sts_session=a; \
             __Host-sts_accounts=b"
        );
    }
}
