// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! HOW THE IDENTITY REACHES THE APPLICATION (#1760, D11), the pure half:
//! the header values a claim renders to, the access tokens the `jwt` mode
//! is handed, and the cookie jar the `saml` mode keeps. `proxy.rs` asks the
//! service (`POST /xacml/pep/identity`) and applies what this file holds.
//!
//! **A header carries no proof**, so a value is refused (403, a PEP
//! failure, `STS-XPEP-0096`) rather than forwarded when it holds CR, LF or NUL, or
//! when a member of a list holds the separator that joins it — a value an
//! application might split differently from how it was meant.
//!
//! **Both caches are bounded and purged at the insert, never on a timer**,
//! and keyed by the proxy session (a `session` route) or by subject and
//! application (a credential presented on each request). A cached token is
//! used only until thirty seconds before it expires; a jar only until its
//! assertion's `NotOnOrAfter`. **A jar's cookies never reach the browser**:
//! they are added to the request to the application and stripped from its
//! answers.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use axum::http::{HeaderMap, HeaderName, HeaderValue};
use serde_json::{Map, Value};

use crate::proxy_config::IdentitySpec;

/// A cached access token is used while it has more than this left.
pub const JWT_MARGIN: Duration = Duration::from_secs(30);

/// The most entries either cache holds.
pub const MAX_ENTRIES: usize = 10_000;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    match m.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

/// One claim's value as header text, or `None` when the subject has none.
pub fn value_of(
    claim: &Value,
    separator: char,
) -> Result<Option<String>, &'static str> {
    let text = match claim {
        Value::Null => return Ok(None),
        Value::String(s) => s.clone(),
        Value::Bool(_) | Value::Number(_) => claim.to_string(),
        Value::Array(list) => {
            let mut members = Vec::new();
            for one in list {
                let member = match one {
                    Value::String(s) => s.clone(),
                    Value::Bool(_) | Value::Number(_) => one.to_string(),
                    _ => return Err("a list claim holds something not text"),
                };
                if member.contains(separator) {
                    return Err("a member of a list claim holds the separator");
                }
                members.push(member);
            }
            members.join(&separator.to_string())
        }
        Value::Object(_) => return Err("a claim is an object"),
    };
    if text.contains(['\r', '\n', '\0']) {
        return Err("a claim value holds CR, LF or NUL");
    }
    // AN EMPTY VALUE IS NO VALUE (2026-11-14): a person in no group sent
    // `X-Iya-Groups:` with nothing after it (found on the 8081 demo), which
    // an application reads as a group list that is present and empty —
    // or, worse, as a header it may trust being there. An empty string or
    // an empty list sends no header, as an absent claim never did.
    if text.is_empty() {
        return Ok(None);
    }
    Ok(Some(text))
}

/// The identity headers of mode `headers`, from `claims` (the subject's,
/// `mechanism` among them). A claim the subject has no value for — absent,
/// null, an empty string or an empty list — sends no header.
pub fn render(
    spec: &IdentitySpec,
    claims: &Map<String, Value>,
) -> Result<Vec<(HeaderName, HeaderValue)>, &'static str> {
    let mut out = Vec::new();
    for (name, claim) in &spec.headers {
        let Some(text) = value_of(
            claims.get(claim).unwrap_or(&Value::Null),
            spec.separator,
        )?
        else {
            continue;
        };
        let value = HeaderValue::from_str(&text)
            .map_err(|_| "a claim value is not a header value")?;
        out.push((name.clone(), value));
    }
    Ok(out)
}

/// The claims mode `headers` asks for that the subject's held claims lack
/// (`mechanism` is never asked: the proxy knows it).
pub fn missing(
    spec: &IdentitySpec,
    claims: &Map<String, Value>,
) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for (_, claim) in &spec.headers {
        let held = claims.get(claim).is_some_and(|v| !v.is_null());
        if claim != "mechanism" && !held && !out.contains(claim) {
            out.push(claim.clone());
        }
    }
    out
}

struct Token {
    value: String,
    expires: Instant,
}

/// Mode `jwt`'s access tokens, keyed by (session or subject, application).
#[derive(Default)]
pub struct Tokens {
    entries: Mutex<HashMap<String, Token>>,
}

impl Tokens {
    /// The token held for `key`, while it has more than [`JWT_MARGIN`] left.
    pub fn get(&self, key: &str) -> Option<String> {
        let entries = lock(&self.entries);
        let token = entries.get(key)?;
        (Instant::now() + JWT_MARGIN < token.expires)
            .then(|| token.value.clone())
    }

    pub fn put(&self, key: &str, value: String, expires_in: Duration) {
        let mut entries = lock(&self.entries);
        let now = Instant::now();
        entries.retain(|_, t| now + JWT_MARGIN < t.expires);
        if entries.len() >= MAX_ENTRIES {
            if let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, t)| t.expires)
                .map(|(k, _)| k.clone())
            {
                entries.remove(&oldest);
            }
        }
        entries.insert(
            key.to_string(),
            Token {
                value,
                expires: now + expires_in,
            },
        );
    }
}

/// One application session, established by an assertion at its ACS.
#[derive(Clone, Debug, PartialEq)]
pub struct Jar {
    /// The cookies the application set, by name.
    pub cookies: Vec<(String, String)>,
    pub not_on_or_after: chrono::DateTime<chrono::Utc>,
    /// The ACS the assertion was posted to, to tell a redirect back there.
    pub acs_url: String,
}

impl Jar {
    pub fn live(&self) -> bool {
        chrono::Utc::now() < self.not_on_or_after
    }

    pub fn names(&self) -> Vec<String> {
        self.cookies.iter().map(|(n, _)| n.clone()).collect()
    }

    /// The application set (or replaced) cookies of the jar's own names on
    /// a later answer.
    pub fn update(&mut self, set: &[(String, String)]) {
        for (name, value) in set {
            if let Some(slot) = self.cookies.iter_mut().find(|(n, _)| n == name)
            {
                slot.1 = value.clone();
            }
        }
    }
}

/// Mode `saml`'s jars, keyed by (session or subject, application).
#[derive(Default)]
pub struct Jars {
    entries: Mutex<HashMap<String, Jar>>,
}

impl Jars {
    pub fn get(&self, key: &str) -> Option<Jar> {
        lock(&self.entries).get(key).filter(|j| j.live()).cloned()
    }

    pub fn put(&self, key: &str, jar: Jar) {
        let mut entries = lock(&self.entries);
        entries.retain(|_, j| j.live());
        if entries.len() >= MAX_ENTRIES {
            if let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, j)| j.not_on_or_after)
                .map(|(k, _)| k.clone())
            {
                entries.remove(&oldest);
            }
        }
        entries.insert(key.to_string(), jar);
    }

    pub fn update(&self, key: &str, set: &[(String, String)]) {
        if let Some(jar) = lock(&self.entries).get_mut(key) {
            jar.update(set);
        }
    }

    pub fn forget(&self, key: &str) {
        lock(&self.entries).remove(key);
    }
}

/// Every `Set-Cookie` of an answer, as (name, value).
pub fn set_cookies(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .filter_map(|text| {
            let pair = text.split(';').next()?.trim();
            let (name, value) = pair.split_once('=')?;
            let name = name.trim();
            (!name.is_empty())
                .then(|| (name.to_string(), value.trim().to_string()))
        })
        .collect()
}

/// The answer's headers without a `Set-Cookie` for any of `names`.
pub fn without_set_cookies(headers: &HeaderMap, names: &[String]) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in headers {
        if name.as_str() == "set-cookie" {
            let named = value
                .to_str()
                .ok()
                .and_then(|t| t.split(';').next())
                .and_then(|p| {
                    p.split_once('=').map(|(n, _)| n.trim().to_string())
                });
            if named.is_some_and(|n| names.contains(&n)) {
                continue;
            }
        }
        out.append(name.clone(), value.clone());
    }
    out
}

/// The `Cookie` header to the application: the client's cookies other than
/// the jar's names (so a client cannot shadow one), then the jar's.
pub fn cookie_header(client: Option<&str>, jar: &Jar) -> String {
    let names = jar.names();
    let mut parts: Vec<String> = client
        .map(|text| {
            text.split(';')
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .filter(|p| {
                    p.split('=')
                        .next()
                        .is_none_or(|n| !names.iter().any(|j| j == n.trim()))
                })
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    for (name, value) in &jar.cookies {
        parts.push(format!("{}={}", name, value));
    }
    parts.join("; ")
}

/// The application's answer says its session ended: a 401, or a redirect
/// back to its ACS or to the identity provider.
pub fn session_ended(
    status: u16,
    location: Option<&str>,
    acs_url: &str,
    issuer: &str,
) -> bool {
    if status == 401 {
        return true;
    }
    if !(300..400).contains(&status) {
        return false;
    }
    let Some(location) = location else {
        return false;
    };
    let origin = |url: &str| {
        reqwest::Url::parse(url)
            .ok()
            .map(|u| u.origin().ascii_serialization())
    };
    let acs_path = reqwest::Url::parse(acs_url)
        .ok()
        .map(|u| u.path().to_string());
    let target = reqwest::Url::parse(location).ok();
    let to_acs = acs_path.is_some_and(|p| {
        location == p || target.as_ref().is_some_and(|t| t.path() == p)
    });
    let to_idp = !issuer.is_empty()
        && origin(location).is_some()
        && origin(location) == origin(issuer);
    to_acs || to_idp
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy_config::IdentityMode;
    use serde_json::json;

    fn spec(sep: char) -> IdentitySpec {
        IdentitySpec {
            mode: IdentityMode::Headers,
            headers: vec![
                (HeaderName::from_static("x-iya-user"), "sub".into()),
                (HeaderName::from_static("x-iya-groups"), "groups".into()),
                (HeaderName::from_static("x-iya-how"), "mechanism".into()),
                (HeaderName::from_static("x-iya-mail"), "email".into()),
            ],
            separator: sep,
        }
    }

    /// An empty list or string sends no header at all (2026-11-14).
    #[test]
    fn an_empty_claim_sends_no_header() {
        let claims = json!({ "sub": "urn:uuid:1", "groups": [],
                             "mechanism": "session", "email": "" });
        let out = render(&spec(','), claims.as_object().unwrap()).unwrap();
        let names: Vec<&str> = out.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["x-iya-user", "x-iya-how"]);
        assert!(value_of(&json!([]), ',').unwrap().is_none());
        assert!(value_of(&json!(""), ',').unwrap().is_none());
        assert_eq!(value_of(&json!(["a"]), ',').unwrap().as_deref(), Some("a"));
    }

    #[test]
    fn claims_render_and_a_dangerous_value_is_refused() {
        let claims = json!({ "sub": "urn:uuid:1", "groups": ["a", "b"],
                             "mechanism": "basic" });
        let map = claims.as_object().unwrap();
        let out = render(&spec(','), map).unwrap();
        assert_eq!(out.len(), 3, "no email, no header");
        assert_eq!(out[1].1, "a,b");
        assert_eq!(missing(&spec(','), map), ["email"]);
        let bad = |v: Value| {
            let mut m = map.clone();
            m.insert("sub".into(), v);
            render(&spec(','), &m).is_err()
        };
        assert!(bad(json!("x\r\nInjected: 1")));
        assert!(bad(json!("x\0")));
        // The rule is this file's own, not the header library's: the
        // value is refused before any header is built.
        for text in ["a\rb", "a\nb", "a\0b"] {
            assert!(value_of(&json!(text), ',').is_err(), "{:?}", text);
            assert!(value_of(&json!([text]), ',').is_err(), "{:?}", text);
        }
        assert!(bad(json!({ "o": 1 })));
        let mut m = map.clone();
        m.insert("groups".into(), json!(["a,b", "c"]));
        assert!(
            render(&spec(','), &m).is_err(),
            "a member holds the separator"
        );
        assert!(render(&spec(';'), &m).is_ok());
    }

    #[test]
    fn a_token_is_not_used_within_thirty_seconds_of_expiry() {
        let tokens = Tokens::default();
        tokens.put("k", "t1".into(), Duration::from_secs(300));
        assert_eq!(tokens.get("k").as_deref(), Some("t1"));
        tokens.put("k", "t2".into(), Duration::from_secs(20));
        assert_eq!(tokens.get("k"), None, "under the margin");
    }

    #[test]
    fn a_jar_is_used_with_the_request_and_stripped_from_answers() {
        let jar = Jar {
            cookies: vec![("app_session".into(), "s1".into())],
            not_on_or_after: chrono::Utc::now() + chrono::Duration::minutes(5),
            acs_url: "http://app/saml/acs".into(),
        };
        assert_eq!(
            cookie_header(Some("app_session=forged; other=1"), &jar),
            "other=1; app_session=s1"
        );
        let mut h = HeaderMap::new();
        h.append(
            "set-cookie",
            HeaderValue::from_static("app_session=s2; Path=/"),
        );
        h.append("set-cookie", HeaderValue::from_static("theme=dark"));
        assert_eq!(set_cookies(&h).len(), 2);
        let kept = without_set_cookies(&h, &jar.names());
        assert_eq!(kept.get_all("set-cookie").iter().count(), 1);
        assert!(session_ended(401, None, &jar.acs_url, "http://sts"));
        assert!(session_ended(
            302,
            Some("/saml/acs"),
            &jar.acs_url,
            "http://sts"
        ));
        assert!(session_ended(
            302,
            Some("http://sts/sso?x"),
            &jar.acs_url,
            "http://sts"
        ));
        assert!(!session_ended(
            302,
            Some("/elsewhere"),
            &jar.acs_url,
            "http://sts"
        ));
        assert!(!session_ended(200, None, &jar.acs_url, "http://sts"));
        let jars = Jars::default();
        let mut gone = jar.clone();
        gone.not_on_or_after =
            chrono::Utc::now() - chrono::Duration::seconds(1);
        jars.put("old", gone);
        assert!(jars.get("old").is_none(), "past NotOnOrAfter");
    }
}
