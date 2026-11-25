// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! EVERY ERROR THE PEP MAKES ITSELF IS A STANDARD ONE, AND EVERY ERROR THE
//! APPLICATION MAKES IS ITS OWN (rcbj, 2026-11-16: "Add tests to validate
//! that every error page returned by the remote pep (or reverse proxy) is
//! a standard error page. If an error comes from the backend, it may
//! return it to the caller.").
//!
//! **STANDARD**, as `xacml-pep/CLAUDE.md` (*What a refused PERSON sees*)
//! and `models/pep/pep_proxy.tsp` define it, on the PROXY listeners:
//!
//! * a caller whose `Accept` names `text/html` gets `proxy_page.rs`'s one
//!   page: status = the refusal's, `text/html; charset=utf-8`, `no-store`,
//!   the page policy (`default-src 'none'`, the style sheet by its hash,
//!   `frame-ancestors 'none'`, `base-uri 'none'`, no `script-src`),
//!   `nosniff`, `no-referrer`; the title and `<h1>` of `wording()`, the
//!   warning box holding the `error`, the start-page link, and the
//!   Diagnostics pane with the time, an incident ID of sixteen hex digits
//!   that exactly ONE log line names beside the code, the `error` and the
//!   `error_description`; and no `STS-` code, no script, no stack trace,
//!   and for a 5xx no address;
//! * any other caller gets the model's `Refusal`, `{error,
//!   error_description}` and nothing else, as `application/json` and
//!   `no-store`, `error` the model's name for the status, no code in it;
//! * the refusal's own headers either way: a 405's `Allow`, a 429's and
//!   `STS-XPEP-0118`'s `Retry-After`, a 401's challenges.
//!
//! The documented exceptions are each held to THEIR shape: `0108` is the
//! page whatever was asked (the callback is a navigation); the API
//! listener (`service.rs`) is JSON-only, whatever the caller accepts, its
//! `POST /notify` a 204 with no body and no type, AuthZEN's refusals its
//! `{error: {status, message}}`; and a request hyper cannot parse never
//! reaches this code at all, so it is hyper's bare status with no body.
//! (The PIP's XML `PIPError` is the SERVICE's `POST /xacml/pip`, not
//! anything this binary answers.)
//!
//! **PASS-THROUGH**: an error the APPLICATION answers is the application's
//! — its status, body bytes, content type and its own headers — with only
//! the hop-by-hop headers gone (`proxy_request.rs`'s `response_headers()`)
//! and NOTHING added, a browser's request included. The PEP's own 502 and
//! 504 (the upstream unreachable, or too slow) are the standard page; the
//! application's 502, 503 and 504 are passed on.
//!
//! **EVERY PEP FAILURE IS A 403** (#2208, rcbj: "Any type of PEP failure
//! should result in a 403 being returned"): a row made by `failed()` is
//! `Refusal::failure()`'s, drawn with the failure wording and a generic
//! description, and the proxy makes no 5xx but the application's two.
//!
//! **THE TABLE IS THE ENUMERATION**: `SOURCES` names every refusal the
//! proxy can construct, where, and how it is reached, and
//! `every_error_source_has_a_row` reads the source and fails when a
//! refusal is added without a row (or a row outlives its refusal).

use std::collections::{BTreeMap, BTreeSet};

use regex::Regex;

use super::*;
use crate::proxy_auth::Refusal;
use crate::proxy_page;

/// How a row is reached.
#[derive(Clone, Copy, Debug)]
enum How {
    /// A request the harness makes: the case in `trigger()`.
    Live(&'static str),
    /// No request the harness can make reaches it: it is held to the same
    /// standard through the one envelope, `refuse()`, and the reason is
    /// the text.
    Envelope(&'static str),
}

/// One error the proxy makes itself.
struct Source {
    status: u16,
    code: &'static str,
    /// A PEP failure (#2208): always a 403, `Refusal::failure()`.
    failure: bool,
    /// The function that constructs it.
    at: &'static str,
    /// When.
    what: &'static str,
    how: How,
}

const fn row(
    status: u16,
    code: &'static str,
    at: &'static str,
    what: &'static str,
    how: How,
) -> Source {
    Source {
        status,
        code,
        failure: false,
        at,
        what,
        how,
    }
}

/// A PEP failure's row (#2208): a 403, whatever it was before.
const fn failed(
    code: &'static str,
    at: &'static str,
    what: &'static str,
    how: How,
) -> Source {
    Source {
        status: 403,
        code,
        failure: true,
        at,
        what,
        how,
    }
}

use How::{Envelope, Live};

/// EVERY ERROR THE PROXY MAKES ITSELF, in the order `answer()` meets it.
/// A code at two statuses, or made in two places, is a row for each.
#[rustfmt::skip]
const SOURCES: &[Source] = &[
    row(400, "STS-XPEP-0064", "proxy.rs answer_noted()",
        "the path does not normalise (an encoded /, a .. segment, //)",
        Live("unnormalised")),
    failed("STS-XPEP-0118", "proxy.rs answer_noted()",
        "no configuration received since the start; Retry-After",
        Live("unconfigured")),
    row(404, "STS-XPEP-0065", "proxy.rs answer_noted()",
        "a configuration received and switched off",
        Live("switched-off")),
    row(404, "STS-XPEP-0065", "proxy.rs answer_noted()",
        "no route matches the path", Live("no-route")),
    row(405, "STS-XPEP-0132", "proxy.rs answer_noted()",
        "the callback asked with a method other than GET or HEAD",
        Live("callback-method")),
    row(405, "STS-XPEP-0133", "proxy.rs answer_noted()",
        "the sign-out asked with a method other than GET or HEAD",
        Live("logout-method")),
    row(404, "STS-XPEP-0134", "proxy.rs answer_noted()",
        "a path under /.iya-pep/ that is none of the proxy's pages",
        Live("reserved")),
    row(405, "STS-XPEP-0066", "proxy.rs answer_noted()",
        "a method the route's non-empty methods does not list",
        Live("route-method")),
    row(403, "STS-XPEP-0093", "proxy.rs answer_noted()",
        "the route's application is not usable (D10)", Live("unusable")),
    row(413, "STS-XPEP-0067", "proxy.rs answer_noted()",
        "a declared Content-Length over maxBodyBytes",
        Live("declared-body")),
    row(413, "STS-XPEP-0067", "proxy.rs forward()",
        "a streamed body that grows over maxBodyBytes",
        Live("streamed-body")),
    row(401, "STS-XPEP-0089", "proxy.rs establish(), proxy_auth.rs",
        "an Authorization header that is not text, carries no credential, \
         is a scheme the route does not take, or is not base64",
        Live("malformed-credential")),
    row(401, "STS-XPEP-0072", "proxy.rs establish()",
        "Authorization: DPoP, which this proxy does not prove",
        Live("dpop-scheme")),
    row(401, "STS-XPEP-0072", "proxy_auth.rs oauth2() via jwt.rs",
        "a token bound to a DPoP key (cnf.jkt)", Live("dpop-bound")),
    row(401, "STS-XPEP-0073", "proxy_auth.rs oauth2() via jwt.rs",
        "a token whose cnf cannot be checked or names another certificate",
        Live("unchecked-cnf")),
    row(401, "STS-XPEP-0071", "proxy_auth.rs oauth2()",
        "a JWT access token refused here (signature, iss, aud, exp)",
        Live("bad-token")),
    row(401, "STS-XPEP-0074", "proxy_auth.rs oauth2()",
        "the service's introspection: not active, another issuer or \
         audience, no subject",
        Live("inactive-token")),
    failed("STS-XPEP-0075", "proxy_auth.rs service_failed() and others",
        "a validation endpoint the service named cannot be asked, or none \
         was named",
        Live("service-unreachable")),
    row(401, "STS-XPEP-0076", "proxy_auth.rs saml2()",
        "an EncryptedAssertion", Live("encrypted-saml")),
    row(401, "STS-XPEP-0078", "proxy_auth.rs saml2()",
        "the service says the SAML assertion is not valid, or it names \
         nobody",
        Live("invalid-saml")),
    row(429, "STS-XPEP-0080", "proxy_auth.rs basic()",
        "the service has locked the account's sign-ins; Retry-After",
        Live("locked-out")),
    row(401, "STS-XPEP-0079", "proxy_auth.rs basic()",
        "the service says the Basic credential is not valid",
        Live("wrong-password")),
    row(401, "STS-XPEP-0070", "proxy.rs establish()",
        "no credential on a route without the session mechanism",
        Live("no-credential")),
    row(401, "STS-XPEP-0081", "proxy.rs no_session()",
        "a session route, no proxy session, and not a browser's GET \
         (a browser's GET is redirected to sign in, not refused)",
        Live("no-session")),
    row(401, "STS-XPEP-0084", "proxy.rs no_session() via session()",
        "a session cookie naming a session this proxy does not hold (made \
         up, expired or ended), not a browser's GET (a browser is sent to \
         sign in, the cookie cleared)",
        Live("stale-cookie")),
    row(401, "STS-XPEP-0084", "proxy.rs no_session()",
        "the sign-on session behind the proxy session has ended, not a \
         browser's GET",
        Live("session-ended")),
    row(401, "STS-XPEP-0084", "proxy.rs session_of_account()",
        "the active account's session has ended, not a browser's GET \
         (a browser goes to the chooser)",
        Live("account-ended")),
    failed("STS-XPEP-0090", "proxy.rs no_session()",
        "the relying party cannot be built (discovery fails)",
        Live("no-relying-party")),
    failed("STS-XPEP-0075", "proxy.rs no_session()",
        "the relying party is built and its authorize() fails",
        Envelope("the mock provider's discovery is what builds the party, \
                  and authorize() then fails only on a PAR the mock does \
                  not publish")),
    row(401, "STS-XPEP-0082", "proxy.rs callback()",
        "a sign-in nobody started, already used or expired, or whose \
         relying party is gone",
        Live("sign-in-unknown")),
    failed("STS-XPEP-0085", "proxy.rs callback()",
        "PEP_PROXY_MAX_SESSIONS live sessions, or no random value",
        Live("sessions-full")),
    row(401, "STS-XPEP-0083", "proxy.rs callback()",
        "the provider's error, or the code or ID Token refused",
        Live("sign-in-refused")),
    row(403, "STS-XPEP-0108", "proxy.rs callback()",
        "the browser's account set is full: ALWAYS the page",
        Live("too-many-accounts")),
    row(403, "STS-XPEP-0109", "proxy.rs accounts()",
        "an account act posted from another site", Live("cross-site")),
    row(404, "STS-XPEP-0110", "proxy.rs accounts()",
        "a return path on no multipleAccounts route, or no such account \
         page or method",
        Live("no-account-page")),
    failed("STS-XPEP-0110", "proxy.rs accounts()",
        "the add page's sign-in established someone instead of starting",
        Envelope("no_session() answers a redirect or a refusal, never an \
                  identity: the arm exists for the type")),
    row(404, "STS-XPEP-0111", "proxy.rs accounts()",
        "the set holds no such account", Live("no-such-account")),
    row(403, "STS-XPEP-0117", "proxy.rs answer_noted()",
        "the route's policy is not held, whatever the bias",
        Live("policy-not-held")),
    row(403, "STS-XPEP-0086", "proxy.rs answer_noted()",
        "the XACML decision refuses (Deny, or NotApplicable or \
         Indeterminate under the bias)",
        Live("policy-denied")),
    row(403, "STS-XPEP-0116", "proxy.rs answer_noted()",
        "a deny-all route (methods empty)", Live("deny-all")),
    row(403, "STS-XPEP-0095", "proxy_auth.rs identity()",
        "the service refused the identity the route sends",
        Live("identity-refused")),
    failed("STS-XPEP-0095", "proxy_auth.rs identity(), proxy.rs deliver()",
        "the identity endpoint did not answer usably, or answered no \
         claims, token or assertion",
        Live("identity-unusable")),
    failed("STS-XPEP-0096", "proxy.rs deliver(), forward()",
        "an identity header, token or cookie that is not a header value",
        Live("header-unsendable")),
    failed("STS-XPEP-0097", "proxy.rs establish_saml()",
        "the ACS the service named is not a URL, or the application's ACS \
         refuses the assertion (4xx) or sets no cookie",
        Live("acs-failed")),
    row(502, "STS-XPEP-0097", "proxy.rs establish_saml()",
        "the application's ACS unreachable, or answering 5xx: the \
         application's failure, a gateway error",
        Live("acs-down")),
    failed("STS-XPEP-0098", "proxy.rs evidence()",
        "the credential gave no evidence the identity endpoint takes",
        Live("no-evidence")),
    failed("STS-XPEP-0091", "proxy.rs forward()",
        "the request would leave the configured upstream",
        Envelope("a normalised path is a path on the upstream: the check \
                  is defence in depth, and no request reaches it")),
    failed("STS-XPEP-0092", "proxy.rs upstream_client()",
        "the upstream client would not build",
        Envelope("reqwest builds a client from any configuration this \
                  binary passes it")),
    row(504, "STS-XPEP-0068", "proxy.rs forward()",
        "the application did not answer within upstreamTimeoutMs",
        Live("upstream-slow")),
    row(502, "STS-XPEP-0069", "proxy.rs forward()",
        "the application cannot be reached", Live("upstream-down")),
];

/// The two dynamic constructions' codes, written as literals beside them:
/// `no_session()`'s `code` is 0084 when the session ended and 0081 when
/// there was none; `jwt.rs`'s `confirmation_problem()` hands
/// `Refusal::token()` its codes (read from that function below).
const DYNAMIC_PAIRS: &[(u16, &str)] =
    &[(401, "STS-XPEP-0081"), (401, "STS-XPEP-0084")];

/// The constructions whose status or code is a variable, by file and
/// argument text, and how many of each: each is argued in `DYNAMIC_PAIRS`
/// or is a closure whose callers' literals the scan reads.
const DYNAMIC_SITES: &[(&str, &str, usize)] = &[
    // `Refusal::token()`'s own body.
    ("proxy_auth.rs", "401, code", 1),
    // `Refusal::failure()`'s own body (#2208).
    ("proxy_auth.rs", "403, code", 1),
    // `confirmation_problem()`'s code, twice (local and introspected).
    ("proxy_auth.rs", "code", 2),
    // `no_session()`, and `callback()`'s `refused` closure.
    ("proxy.rs", "401, code", 2),
    // `accounts()`'s `refuse` closure.
    ("proxy.rs", "status, code", 1),
];

/// The code a refusal of the token itself carries `invalid_token` for.
const TOKEN_CODES: &[&str] = &[
    "STS-XPEP-0071",
    "STS-XPEP-0072",
    "STS-XPEP-0073",
    "STS-XPEP-0074",
];

/// The model's `error` for a status (`pep_proxy.tsp`'s `Refusal`).
fn documented_error(status: u16, code: &str) -> &'static str {
    match status {
        400 => "invalid_request",
        401 if TOKEN_CODES.contains(&code) => "invalid_token",
        401 => "unauthorized",
        403 => "access_denied",
        404 => "not_found",
        405 => "method_not_allowed",
        413 => "payload_too_large",
        429 => "too_many_requests",
        504 => "gateway_timeout",
        _ => "bad_gateway",
    }
}

/// A file's text before its unit tests.
fn production(text: &str) -> &str {
    match text.find("\n#[cfg(test)]\nmod tests") {
        Some(at) => &text[..at],
        None => text,
    }
}

/// The first `n` arguments of the call whose `(` is at `open`, each
/// trimmed: enough for a status and a code, which hold no parenthesis.
fn first_args(text: &str, open: usize, n: usize) -> Vec<String> {
    text[open + 1..]
        .chars()
        .take(240)
        .collect::<String>()
        .split([',', ')'])
        .take(n)
        .map(|a| a.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect()
}

/// What the scan finds in one file: the (status, code) pairs built from
/// literals, the dynamic sites by argument text, and every code that is
/// not inside a `tag(` (a code a log line carries, never an answer).
#[derive(Default)]
struct Scanned {
    pairs: BTreeSet<(u16, String)>,
    dynamic: BTreeMap<(String, String), usize>,
    answered_codes: BTreeSet<String>,
}

fn scan(file: &str, text: &str, into: &mut Scanned) {
    let text = production(text);
    let call = Regex::new(
        r"(Refusal::new|Refusal::token|Refusal::failure|\brefuse|\brefused)\(",
    )
    .unwrap();
    let code = Regex::new(r#"^"(STS-XPEP-\d{4})"$"#).unwrap();
    for found in call.captures_iter(text) {
        let whole = found.get(0).unwrap();
        let open = whole.end() - 1;
        let name = &found[1];
        let token = name == "Refusal::token" || name == "refused";
        let failure = name == "Refusal::failure";
        let args = first_args(text, open, if token || failure { 1 } else { 2 });
        let literal_status = args[0].parse::<u16>().ok();
        match (name, token) {
            // A closure call: only its literal callers are refusals.
            ("refuse", _) if literal_status.is_none() => continue,
            ("refused", _) if !args[0].starts_with('"') => continue,
            _ => {}
        }
        let (status, said) = if token {
            (Some(401), args[0].as_str())
        } else if failure {
            // A PEP failure is always a 403 (#2208).
            (Some(403), args[0].as_str())
        } else {
            (literal_status, args.get(1).map_or("", String::as_str))
        };
        match (status, code.captures(said)) {
            (Some(status), Some(c)) => {
                into.pairs.insert((status, c[1].to_string()));
            }
            _ => {
                *into
                    .dynamic
                    .entry((file.to_string(), args.join(", ")))
                    .or_default() += 1;
            }
        }
    }
    let literal = Regex::new(r#""(STS-XPEP-\d{4})""#).unwrap();
    for found in literal.captures_iter(text) {
        let before = text[..found.get(0).unwrap().start()].trim_end();
        if !before.ends_with("tag(") {
            into.answered_codes.insert(found[1].to_string());
        }
    }
}

/// THE GUARD: every refusal the proxy constructs has a row, and every row
/// a refusal. A new `Refusal::new(…)`, a new code in a comparison or a new
/// dynamic construction fails here until `SOURCES` (and its trigger) says
/// how it is reached and that it is standard.
#[test]
fn every_error_source_has_a_row() {
    let mut scanned = Scanned::default();
    scan("proxy.rs", include_str!("proxy.rs"), &mut scanned);
    scan("proxy_auth.rs", include_str!("proxy_auth.rs"), &mut scanned);
    // `confirmation_problem()`'s codes are `Refusal::token()`'s.
    let jwt = include_str!("jwt.rs");
    let start = jwt.find("pub fn confirmation_problem(").unwrap();
    let end = start + jwt[start..].find("\n}\n").unwrap();
    let literal = Regex::new(r#""(STS-XPEP-\d{4})""#).unwrap();
    let mut source: BTreeSet<(u16, String)> = scanned.pairs.clone();
    for c in literal.captures_iter(&jwt[start..end]) {
        source.insert((401, c[1].to_string()));
    }
    for (status, code) in DYNAMIC_PAIRS {
        source.insert((*status, code.to_string()));
    }
    let table: BTreeSet<(u16, String)> = SOURCES
        .iter()
        .map(|s| (s.status, s.code.to_string()))
        .collect();
    let missing: Vec<_> = source.difference(&table).collect();
    let stale: Vec<_> = table.difference(&source).collect();
    assert!(
        missing.is_empty() && stale.is_empty(),
        "refusals without a row in SOURCES: {:?}; rows no refusal makes: \
         {:?}",
        missing,
        stale
    );
    let expected: BTreeMap<(String, String), usize> = DYNAMIC_SITES
        .iter()
        .map(|(f, a, n)| ((f.to_string(), a.to_string()), *n))
        .collect();
    assert_eq!(
        scanned.dynamic, expected,
        "a refusal whose status or code is a variable: argue it in \
         DYNAMIC_SITES and DYNAMIC_PAIRS"
    );
    // Every code the two files answer with, or compare a refusal to, is a
    // row's: a code only in a `tag(` is a log line's.
    let codes: BTreeSet<String> =
        SOURCES.iter().map(|s| s.code.to_string()).collect();
    let unrowed: Vec<_> = scanned.answered_codes.difference(&codes).collect();
    assert!(unrowed.is_empty(), "codes with no row: {:?}", unrowed);
    // The page's wording by code names only the table's pairs.
    let arm = Regex::new(r#"\((\d{3}),\s*"(STS-XPEP-\d{4})""#).unwrap();
    for c in arm.captures_iter(production(include_str!("proxy_page.rs"))) {
        let pair = (c[1].parse::<u16>().unwrap(), c[2].to_string());
        assert!(table.contains(&pair), "wording() for no row: {:?}", pair);
    }
    // NO OTHER ERROR ANSWER IN proxy.rs: a status constant is a redirect's
    // or `json_answer()`'s fallback, and every JSON or HTML answer is a
    // 200 or the refusal's status.
    let constant = Regex::new(r"StatusCode::([A-Z_]+)").unwrap();
    let proxy = production(include_str!("proxy.rs"));
    let constants: BTreeSet<&str> = constant
        .captures_iter(proxy)
        .map(|c| c.get(1).unwrap().as_str())
        .collect();
    assert_eq!(
        constants,
        BTreeSet::from(["BAD_GATEWAY", "FOUND", "SEE_OTHER"]),
        "a status answered outside the refusal envelope"
    );
    let answer =
        Regex::new(r"\b(json_answer|own_page|html_response)\(").unwrap();
    for c in answer.captures_iter(proxy) {
        let open = c.get(0).unwrap().end() - 1;
        let first = first_args(proxy, open, 1).remove(0);
        assert!(
            // `""` is a mention in prose: `json_answer()`.
            ["", "200", "refusal.status", "status", "status: u16"]
                .contains(&first.as_str()),
            "{}({}…) answers outside the refusal envelope",
            &c[1],
            first
        );
    }
    // The page is drawn by `refuse()`, and by the callback's 0108 alone.
    assert_eq!(proxy.matches("self.error_page(").count(), 2);
    // Each row's status has a model name, and a Live row a trigger.
    for s in SOURCES {
        assert!(
            [400, 401, 403, 404, 405, 413, 429, 502, 504].contains(&s.status),
            "{} {}",
            s.status,
            s.code
        );
        assert!(!s.at.is_empty() && !s.what.is_empty());
        // EVERY PEP FAILURE IS A 403, and the only 5xx are the
        // application's (#2208).
        assert!(!s.failure || s.status == 403, "{}", s.code);
        assert!(
            s.status < 500
                || matches!(
                    s.code,
                    "STS-XPEP-0068" | "STS-XPEP-0069" | "STS-XPEP-0097"
                ),
            "a 5xx that is not the application's: {} {}",
            s.status,
            s.code
        );
    }
}

/// THE API LISTENER'S GUARD: `service.rs` answers an error only as JSON
/// (a 404 by constant, `/protected`'s decision by its variable), and
/// every AuthZEN reply that is not a decision is `Reply::error()`.
#[test]
fn the_api_listener_errors_are_its_two_shapes() {
    let service = production(include_str!("service.rs"));
    let call =
        Regex::new(r"json_response\(\s*([A-Za-z_]+(?:::[A-Z_]+)?)").unwrap();
    let statuses: BTreeSet<&str> = call
        .captures_iter(service)
        .map(|c| c.get(1).unwrap().as_str())
        .collect();
    assert_eq!(
        statuses,
        BTreeSet::from(["StatusCode::NOT_FOUND", "StatusCode::OK", "status"]),
        "an error the API listener answers outside its JSON"
    );
    let authzen = production(include_str!("authzen.rs"));
    // `status: 200`, or the shorthand `status,` of `Reply::error()`.
    // The binding 501 is the second: `reply_of` builds it without
    // `Reply::error`, because `evaluate_one` already logged
    // STS-XPEP-0140 (#1205).
    let literal =
        Regex::new(r"Reply \{\s*status(?::\s*([a-z0-9_]+))?\s*,").unwrap();
    let mut variable = 0;
    for c in literal.captures_iter(authzen) {
        match c.get(1).map(|m| m.as_str()) {
            Some("200") => {}
            None => variable += 1,
            Some(other) => panic!("an AuthZEN reply of status {}", other),
        }
    }
    assert_eq!(
        variable, 2,
        "Reply::error() and the binding 501 alone set a status"
    );
}

// ===== THE STANDARD, CHECKED ==============================================

/// What one answer was: status, headers, body.
struct Answered {
    status: u16,
    headers: reqwest::header::HeaderMap,
    body: Vec<u8>,
}

async fn answered(r: reqwest::Response) -> Answered {
    let status = r.status().as_u16();
    let headers = r.headers().clone();
    let body = r.bytes().await.unwrap_or_default().to_vec();
    Answered {
        status,
        headers,
        body,
    }
}

fn header<'a>(a: &'a Answered, name: &str) -> &'a str {
    a.headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
}

/// Nothing internal on a page or in a JSON body.
fn nothing_internal(
    label: &str,
    text: &str,
    status: u16,
    failure: bool,
    out: &mut Vec<String>,
) {
    for bad in ["STS-", "panicked", "RUST_BACKTRACE", "src/", ".rs:"] {
        if text.contains(bad) {
            out.push(format!("{}: {:?} in the body: {}", label, bad, text));
        }
    }
    let generic = status >= 500 || failure;
    if generic && (text.contains("127.0.0.1") || text.contains("http://")) {
        out.push(format!(
            "{}: an address in a 5xx or failure: {}",
            label, text
        ));
    }
    // A 5xx's and a PEP failure's description is a generic sentence, never
    // the reason logged.
    if generic && !GENERIC_5XX.iter().any(|g| text.contains(g)) {
        out.push(format!("{}: a 5xx's own description: {}", label, text));
    }
}

/// `shown_description()`'s sentences for a 5xx of the proxy's own and for
/// a PEP failure.
const GENERIC_5XX: &[&str] = &[
    "The application could not be reached, or did not answer usably.",
    "This proxy has not yet received its configuration since it started.",
    proxy::FAILURE_DESCRIPTION,
    "The application did not answer in time.",
    "The request could not be completed.",
];

/// THE ERROR PAGE: the one document, its headers, its pane, and the one
/// log line its incident ID names.
fn standard_page(
    label: &str,
    a: &Answered,
    (status, code, failure): (u16, &str, bool),
    out: &mut Vec<String>,
) {
    let mut fail = |why: String| out.push(format!("{}: {}", label, why));
    if a.status != status {
        fail(format!("status {} for {}", a.status, status));
    }
    if header(a, "content-type") != "text/html; charset=utf-8" {
        fail(format!("content-type {:?}", header(a, "content-type")));
    }
    if header(a, "cache-control") != "no-store" {
        fail(format!("cache-control {:?}", header(a, "cache-control")));
    }
    let csp = header(a, "content-security-policy");
    if !csp.starts_with("default-src 'none'; style-src 'sha256-")
        || !csp.contains("frame-ancestors 'none'")
        || !csp.contains("base-uri 'none'")
        || csp.contains("script-src")
        || csp.contains("unsafe")
    {
        fail(format!("the page policy {:?}", csp));
    }
    if header(a, "x-content-type-options") != "nosniff"
        || header(a, "referrer-policy") != "no-referrer"
    {
        fail("no nosniff or no-referrer".into());
    }
    let html = String::from_utf8_lossy(&a.body).to_string();
    let (title, _, _) = proxy_page::wording(status, code, failure);
    let error = documented_error(status, code);
    for want in [
        "<!doctype html>".to_string(),
        format!("<title>{}</title>", title),
        format!("<h1>{}</h1>", title),
        format!(
            "<div class=\"warn\" role=\"alert\"><span class=\"error\">{}\
             </span>",
            error
        ),
        "<a class=\"portal\" href=\"/\">Go to the start page</a>".into(),
        "<section class=\"diagnostics\"".into(),
        "<dt>Time (UTC)</dt>".into(),
        format!("<dt>error</dt><dd><code>{}</code>", error),
        "<dt>error_description</dt><dd><code>".into(),
        "<footer class=\"sts-footer\">".into(),
    ] {
        if !html.contains(&want) {
            fail(format!("no {}", want));
        }
    }
    if html.contains("<script") {
        fail("a script".into());
    }
    nothing_internal(label, &html, status, failure, out);
    let incident = html
        .find("<dt>Incident ID</dt><dd><code>")
        .map(|at| at + 30)
        .and_then(|at| html[at..].split('<').next())
        .unwrap_or("")
        .to_string();
    if incident.len() != 16 || !incident.chars().all(|c| c.is_ascii_hexdigit())
    {
        out.push(format!("{}: incident ID {:?}", label, incident));
        return;
    }
    let lines = proxy::logged::holding(&incident);
    if lines.len() != 1 {
        out.push(format!(
            "{}: {} lines name {}",
            label,
            lines.len(),
            incident
        ));
    } else if !lines[0].contains(&format!("[{}]", code)) {
        out.push(format!("{}: the line is not {}: {}", label, code, lines[0]));
    }
}

/// THE JSON REFUSAL: the model's, closed, and nothing else.
fn standard_json(
    label: &str,
    a: &Answered,
    (status, code, failure): (u16, &str, bool),
    out: &mut Vec<String>,
) {
    use sts_model_pep::pep_proxy::components;
    let mut fail = |why: String| out.push(format!("{}: {}", label, why));
    if a.status != status {
        fail(format!("status {} for {}", a.status, status));
    }
    if header(a, "content-type") != "application/json" {
        fail(format!("content-type {:?}", header(a, "content-type")));
    }
    if header(a, "cache-control") != "no-store" {
        fail(format!("cache-control {:?}", header(a, "cache-control")));
    }
    let text = String::from_utf8_lossy(&a.body).to_string();
    let body: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    let members: Vec<&String> = body
        .as_object()
        .map(|o| o.keys().collect())
        .unwrap_or_default();
    if members != ["error", "error_description"] {
        fail(format!("members {:?}: {}", members, text));
    }
    if serde_json::from_value::<components::Refusal>(body.clone()).is_err() {
        fail(format!("not the model's Refusal: {}", text));
    }
    if body["error"] != documented_error(status, code) {
        fail(format!("error {} for {}", body["error"], status));
    }
    nothing_internal(label, &text, status, failure, out);
}

/// The headers a refusal keeps whichever shape it is drawn in.
fn its_headers(label: &str, a: &Answered, s: &Source, out: &mut Vec<String>) {
    let mut need = |name: &str| {
        if header(a, name).is_empty() {
            out.push(format!("{}: no {}", label, name));
        }
    };
    if s.status == 405 {
        need("allow");
    }
    if s.status == 429 || s.code == "STS-XPEP-0118" {
        need("retry-after");
    }
    if s.status == 401
        && matches!(
            s.code,
            "STS-XPEP-0070"
                | "STS-XPEP-0071"
                | "STS-XPEP-0072"
                | "STS-XPEP-0079"
                | "STS-XPEP-0089"
        )
    {
        need("www-authenticate");
    }
}

/// The standard for one answer to one row.
fn hold(s: &Source, html: bool, a: &Answered, out: &mut Vec<String>) {
    let label = format!(
        "{} {} ({}, {})",
        s.status,
        s.code,
        s.what,
        if html { "browser" } else { "API client" }
    );
    // 0108 is the page whatever was asked: the callback is a navigation.
    if html || s.code == "STS-XPEP-0108" {
        standard_page(&label, a, (s.status, s.code, s.failure), out);
    } else {
        standard_json(&label, a, (s.status, s.code, s.failure), out);
    }
    if s.code != "STS-XPEP-0108" {
        its_headers(&label, a, s, out);
    }
}

// ===== THE TRIGGERS =======================================================

fn accept(r: reqwest::RequestBuilder, html: bool) -> reqwest::RequestBuilder {
    if html {
        as_browser(r)
    } else {
        r.header("accept", "application/json")
    }
}

/// A port nobody listens on: discard, the one `service.rs`'s tests point
/// their PDP at. Not one bound and dropped, which can fail to bind while
/// the whole suite holds its loopback ports.
fn dead_port() -> u16 {
    9
}

impl Harness {
    /// The harness's configuration with `edit`, received as a pull and
    /// reconciled.
    async fn reconfigure(&self, edit: impl FnOnce(&mut Value)) {
        let cert =
            String::from_utf8(self.saml_signer.1.to_pem().unwrap()).unwrap();
        let mut doc =
            configuration(&self.upstream_base, &self.service_base, &cert);
        edit(&mut doc);
        self.sync.receive_proxy(&doc, None);
        self.proxied.reconcile().await;
    }

    /// The callback for the sign-in `location` started, the mock told who
    /// it signs in, asked as a browser or not.
    async fn callback_as(
        &self,
        location: &str,
        who: (&str, &str),
        sid: &str,
        code: &str,
        html: bool,
    ) -> reqwest::Response {
        let q = query_of(location);
        {
            let mut g = self.service.lock().unwrap();
            g.expect = Some((
                member(&q, "code_challenge"),
                member(&q, "nonce"),
                sid.into(),
            ));
            g.who = Some((who.0.into(), who.1.into()));
        }
        let path = format!(
            "/.iya-pep/callback?code={}&state={}",
            code,
            member(&q, "state")
        );
        accept(self.get(&path), html).send().await.unwrap()
    }

    /// A proxy session on `/app` (signals off): its cookie pair.
    async fn signed_in_on_app(&self, sid: &str) -> String {
        let (status, to) = self.location_of("/app/x", "").await;
        assert_eq!(status, 302);
        let r = self.sign_in_as(&to, ("urn:uuid:carol", "carol"), sid, sid);
        cookie_of(&r.await)
    }
}

/// The SAML Authorization header for `xml`.
fn saml_header(xml: &str) -> String {
    format!("SAML {}", openssl::base64::encode_block(xml.as_bytes()))
}

/// Makes the request a row names, on a harness of its own, as a browser
/// (`html`) or an API client.
async fn trigger(case: &str, html: bool) -> (Harness, reqwest::Response) {
    let alice = ("alice", Some("right"));
    if case == "unconfigured" {
        let h = harness_unconfigured(|_| {}).await;
        let r = accept(h.get("/public/page"), html).send().await.unwrap();
        return (h, r);
    }
    if case == "sessions-full" {
        // One live session is the most: the second sign-in has no room.
        let h = harness_with(|o| o.proxy_max_sessions = 1).await;
        h.signed_in_on_app("sid-full-1").await;
        let (_, to) = h.location_of("/app/x", "").await;
        let r = h
            .callback_as(&to, ("urn:uuid:dan", "dan"), "sid-full-2", "f2", html)
            .await;
        return (h, r);
    }
    let h = harness().await;
    let r = match case {
        "unnormalised" => accept(h.get("/public/a%2fb"), html),
        "switched-off" => {
            h.reconfigure(|d| d["proxy"]["enabled"] = json!(false))
                .await;
            accept(h.get("/public/page"), html)
        }
        "no-route" => accept(h.get("/nowhere"), html),
        "callback-method" => accept(
            h.http
                .post(format!("{}/.iya-pep/callback?state=s", h.proxy)),
            html,
        ),
        "logout-method" => {
            accept(h.http.post(format!("{}/.iya-pep/logout", h.proxy)), html)
        }
        "reserved" => accept(h.get("/.iya-pep/nothing"), html),
        "route-method" => {
            accept(h.http.delete(format!("{}/api/x", h.proxy)), html)
        }
        "unusable" => {
            accept(h.get("/gone/x").basic_auth(alice.0, alice.1), html)
        }
        "declared-body" => accept(
            h.http
                .post(format!("{}/api/w", h.proxy))
                .basic_auth(alice.0, alice.1)
                .body(vec![b'x'; 100]),
            html,
        ),
        "streamed-body" => accept(
            h.http
                .post(format!("{}/api/w", h.proxy))
                .basic_auth(alice.0, alice.1)
                .body(reqwest::Body::wrap(Chunks(vec![
                    Bytes::from(vec![b'x'; 40]),
                    Bytes::from(vec![b'y'; 40]),
                ]))),
            html,
        ),
        "malformed-credential" => {
            accept(h.get("/api/x").header("authorization", "Basic"), html)
        }
        "dpop-scheme" => {
            accept(h.get("/api/x").header("authorization", "DPoP abc"), html)
        }
        "dpop-bound" => accept(h.get("/api/x").bearer_auth("opaque-jkt"), html),
        "unchecked-cnf" => {
            let mut claims = h.claims();
            claims["cnf"] = json!("not an object");
            accept(h.get("/api/x").bearer_auth(h.token(claims)), html)
        }
        "bad-token" => {
            let mut claims = h.claims();
            claims["exp"] = json!(chrono::Utc::now().timestamp() - 600);
            accept(h.get("/api/x").bearer_auth(h.token(claims)), html)
        }
        "inactive-token" => {
            accept(h.get("/api/x").bearer_auth("opaque-unknown"), html)
        }
        "service-unreachable" => {
            let dead = format!("http://127.0.0.1:{}/basic", dead_port());
            h.reconfigure(|d| d["validation"]["basic"] = json!(dead))
                .await;
            accept(h.get("/api/x").basic_auth(alice.0, alice.1), html)
        }
        "encrypted-saml" => accept(
            h.get("/saml/x").header(
                "authorization",
                saml_header(
                    "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:\
                     SAML:2.0:protocol\"><saml:EncryptedAssertion \
                     xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"/>\
                     </samlp:Response>",
                ),
            ),
            html,
        ),
        "invalid-saml" => accept(
            h.get("/saml/x")
                .header("authorization", saml_header("<nothing/>")),
            html,
        ),
        "locked-out" => {
            accept(h.get("/api/x").basic_auth("locked", Some("x")), html)
        }
        "wrong-password" => {
            accept(h.get("/api/x").basic_auth("alice", Some("wrong")), html)
        }
        "no-credential" => accept(h.get("/api/x"), html),
        // A POST: not a browser's navigation, so not sent to sign in.
        "no-session" => accept(h.http.post(format!("{}/app/x", h.proxy)), html),
        "stale-cookie" => accept(
            h.http
                .post(format!("{}/app/x", h.proxy))
                .header("cookie", "iya_pep_session=no-such-session"),
            html,
        ),
        "session-ended" => {
            // Signed in, and the service never says the session is live.
            let cookie = h.signed_in_on_app("sid-ended").await;
            accept(
                h.http
                    .post(format!("{}/app/x", h.proxy))
                    .header("cookie", cookie),
                html,
            )
        }
        "account-ended" => {
            // The library no longer holds the active account's session and
            // the service does not say it is live: that account ends.
            let (_, to) = h.location_of("/multi/page", "").await;
            let set = cookie_of(
                &h.sign_in_as(&to, ("urn:uuid:erin", "erin"), "sid-ae", "ae")
                    .await,
            );
            let set_id = set.split_once('=').unwrap().1.to_string();
            for one in h.sync.proxy_sessions.sessions_of_set(&set_id) {
                h.proxied.library_forgets(LIVE_CLIENT, &one.session_id);
            }
            accept(
                h.http
                    .post(format!("{}/multi/page", h.proxy))
                    .header("cookie", set),
                html,
            )
        }
        "no-relying-party" => {
            // The provider's discovery cannot be fetched: no party.
            let dead = format!("http://127.0.0.1:{}", dead_port());
            h.reconfigure(|d| d["realm"]["issuer"] = json!(dead)).await;
            accept(h.get("/.iya-pep/accounts/add?return=%2Fmulti%2Fpage"), html)
        }
        "sign-in-unknown" => {
            accept(h.get("/.iya-pep/callback?code=c&state=nope"), html)
        }
        "sign-in-refused" => {
            let q = h.send_to_sign_in("/app/x", "sid-refused").await;
            accept(
                h.get(&format!(
                    "/.iya-pep/callback?state={}&error=access_denied",
                    member(&q, "state")
                )),
                html,
            )
        }
        "too-many-accounts" => {
            // proxy_max_accounts is 2 in the harness: the third is refused.
            let (_, to) = h.location_of("/multi/page", "").await;
            let set = cookie_of(
                &h.sign_in_as(&to, ("urn:uuid:a1", "a1"), "sid-a1", "a1")
                    .await,
            );
            let add = "/.iya-pep/accounts/add?return=%2Fmulti%2Fpage";
            let (_, to) = h.location_of(add, &set).await;
            h.sign_in_as(&to, ("urn:uuid:a2", "a2"), "sid-a2", "a2")
                .await;
            let (_, to) = h.location_of(add, &set).await;
            let r = h
                .callback_as(&to, ("urn:uuid:a3", "a3"), "sid-a3", "a3", html)
                .await;
            return (h, r);
        }
        "cross-site" => accept(
            h.http
                .post(format!("{}/.iya-pep/accounts/switch", h.proxy))
                .header("origin", "https://elsewhere.example")
                .header("content-type", "application/x-www-form-urlencoded")
                .body("account=x"),
            html,
        ),
        "no-account-page" => accept(h.get("/.iya-pep/accounts/nothing"), html),
        "no-such-account" => accept(
            h.http
                .post(format!("{}/.iya-pep/accounts/switch", h.proxy))
                .header("origin", h.proxy.clone())
                .header("content-type", "application/x-www-form-urlencoded")
                .body("account=nobody"),
            html,
        ),
        "policy-not-held" => {
            accept(h.get("/missing/x").basic_auth(alice.0, alice.1), html)
        }
        "policy-denied" => {
            accept(h.get("/api/x").basic_auth("mallory", Some("right")), html)
        }
        "deny-all" => {
            accept(h.get("/closed/x").basic_auth(alice.0, alice.1), html)
        }
        "identity-refused" => {
            accept(h.get("/hdr/x").basic_auth("denied", Some("right")), html)
        }
        "identity-unusable" => {
            // A route the mock's identity endpoint answers 422 for.
            h.reconfigure(|d| {
                d["proxy"]["routes"].as_array_mut().unwrap().push(json!({
                    "id": "odd", "path": "/odd", "mechanisms": ["basic"],
                    "application": "odd-app", "methods": ALL,
                    "authorization": simple_on("t"),
                    "resolved": resolved_for(false, false, ""),
                    "identity": { "mode": "headers", "headers": [
                        { "name": "X-Iya-Email", "claim": "email" } ] }
                }))
            })
            .await;
            accept(h.get("/odd/x").basic_auth(alice.0, alice.1), html)
        }
        "header-unsendable" => {
            accept(h.get("/hdr/x").basic_auth("evil", Some("right")), html)
        }
        "acs-failed" => {
            // The ACS answers 200 and sets no cookie: no session to forward.
            h.service.lock().unwrap().acs_url =
                format!("{}/no-session-here", h.upstream_base);
            accept(h.get("/sso/x").basic_auth(alice.0, alice.1), html)
        }
        "acs-down" => {
            // Nobody at the application's ACS: the application's failure.
            h.service.lock().unwrap().acs_url =
                format!("http://127.0.0.1:{}/acs", dead_port());
            accept(h.get("/sso/x").basic_auth(alice.0, alice.1), html)
        }
        "no-evidence" => {
            // A Basic answer with no ticket, and a claim to ask for.
            let basic = serve(axum::Router::new().route(
                "/basic",
                post(|| async {
                    Json(json!({ "valid": true, "sub": "urn:uuid:alice",
                                 "username": "alice" }))
                }),
            ))
            .await;
            let at = format!("http://127.0.0.1:{}/basic", basic);
            h.reconfigure(|d| d["validation"]["basic"] = json!(at))
                .await;
            accept(h.get("/hdr/x").basic_auth(alice.0, alice.1), html)
        }
        "upstream-slow" => accept(h.get("/slow"), html),
        "upstream-down" => {
            let dead = format!("http://127.0.0.1:{}/pep-app", dead_port());
            let cert =
                String::from_utf8(h.saml_signer.1.to_pem().unwrap()).unwrap();
            h.sync.receive_proxy(
                &configuration(&dead, &h.service_base, &cert),
                None,
            );
            accept(h.get("/public/page"), html)
        }
        other => panic!("no trigger {}", other),
    };
    let r = r.send().await.unwrap();
    (h, r)
}

/// One row, asked once: by its trigger on a harness of its own, or through
/// `refuse()` for a row no request reaches.
async fn asked(s: &Source, html: bool) -> Answered {
    match s.how {
        Live(case) => answered(trigger(case, html).await.1).await,
        Envelope(why) => {
            assert!(!why.is_empty(), "{}: say why", s.code);
            let h = harness().await;
            let refusal = if s.failure {
                Refusal::failure(s.code, "a reason, logged")
            } else {
                Refusal::new(s.status, s.code, "a reason, logged")
            };
            let response =
                h.proxied.refusal_for_test(&refusal, html, "/somewhere");
            let status = response.status().as_u16();
            // reqwest's header map is http's, as axum's is.
            let headers = response.headers().clone();
            let body = axum::body::to_bytes(response.into_body(), 1 << 20)
                .await
                .unwrap()
                .to_vec();
            Answered {
                status,
                headers,
                body,
            }
        }
    }
}

/// EVERY ROW, AS A BROWSER AND AS AN API CLIENT, IS THE STANDARD ANSWER:
/// the page, or the model's JSON, with the refusal's own headers. A row no
/// request reaches is drawn through `refuse()` itself. Every failure is
/// collected, so one run names them all. **Each ask has a runtime of its
/// own**, dropped after it: a harness's mocks and listeners are tasks on
/// the runtime that started them, and ninety-eight harnesses alive at once
/// run the process out of file descriptors.
#[test]
fn every_error_the_proxy_makes_is_the_standard_one() {
    let mut failures: Vec<String> = Vec::new();
    let mut held = 0;
    for s in SOURCES {
        for html in [true, false] {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let a = runtime.block_on(asked(s, html));
            runtime.shutdown_background();
            hold(s, html, &a, &mut failures);
            held += 1;
        }
    }
    assert_eq!(held, SOURCES.len() * 2);
    assert!(
        failures.is_empty(),
        "{} answer(s) not standard:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

// ===== THE APPLICATION'S OWN ERRORS: PASSED THROUGH =======================

/// The application's error answers, by the last segment of the path: each
/// with a body, a content type and headers of its own, and two hop-by-hop
/// headers that must not cross.
async fn failing_application() -> u16 {
    let answer = |request: Request| async move {
        let path = request.uri().path().to_string();
        let last = path.rsplit('/').next().unwrap_or("").to_string();
        if last == "slow" {
            tokio::time::sleep(Duration::from_millis(2000)).await;
        }
        let builder = axum::response::Response::builder()
            .header("x-app", format!("app {}", last))
            .header("connection", "x-app-hop")
            .header("x-app-hop", "1")
            .header("proxy-app", "1");
        let built = match last.as_str() {
            // error-code: none — the mock app's own error, which the proxy passes on
            "e404" => builder
                .status(404)
                .header("content-type", "text/html; charset=iso-8859-1")
                .header("content-security-policy", "default-src 'self'")
                .header("cache-control", "max-age=60")
                .body(axum::body::Body::from(
                    "<html><body>The application has no such page.\
                     </body></html>",
                )),
            // error-code: none — the mock app's own error, which the proxy passes on
            "e500" => builder
                .status(500)
                .header("content-type", "text/plain")
                .body(axum::body::Body::from("the application broke")),
            // error-code: none — the mock app's own error, which the proxy passes on
            "e502" => builder
                .status(502)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"app":"its own 502"}"#)),
            // error-code: none — the mock app's own error, which the proxy passes on
            "e503" => builder
                .status(503)
                .header("retry-after", "7")
                .header("content-type", "text/html")
                .body(axum::body::Body::from("<p>busy</p>")),
            // error-code: none — the mock app's own error, which the proxy passes on
            "e504" => builder
                .status(504)
                .header("content-type", "text/plain")
                .body(axum::body::Body::from("its own gateway timed out")),
            // error-code: none — the mock app's own error, which the proxy passes on
            "e401" => builder
                .status(401)
                .header("www-authenticate", "Bearer realm=\"app\"")
                .body(axum::body::Body::from("app says sign in")),
            // error-code: none — the mock app's own error, which the proxy passes on
            "e403" => builder
                .status(403)
                .header("content-type", "application/problem+json")
                .body(axum::body::Body::from(r#"{"title":"no"}"#)),
            // Bytes the proxy must not decode or re-encode.
            // error-code: none — the mock app's own error, which the proxy passes on
            "gzip" => builder
                .status(500)
                .header("content-type", "text/plain")
                .header("content-encoding", "gzip")
                .body(axum::body::Body::from(vec![
                    0x1f, 0x8b, 0x08, 0x00, 0xde, 0xad, 0xbe, 0xef,
                ])),
            // error-code: none — the mock app's own error, which the proxy passes on
            "empty" => builder.status(404).body(axum::body::Body::empty()),
            _ => builder.status(200).body(axum::body::Body::from("ok")),
        };
        built.unwrap()
    };
    serve(axum::Router::new().fallback(answer)).await
}

/// The bytes and headers the application answered each error with.
fn application_said(last: &str) -> (u16, Option<&'static str>, Vec<u8>) {
    match last {
        "e404" => (
            404,
            Some("text/html; charset=iso-8859-1"),
            b"<html><body>The application has no such page.</body></html>"
                .to_vec(),
        ),
        "e500" => (500, Some("text/plain"), b"the application broke".to_vec()),
        "e502" => (
            502,
            Some("application/json"),
            br#"{"app":"its own 502"}"#.to_vec(),
        ),
        "e503" => (503, Some("text/html"), b"<p>busy</p>".to_vec()),
        "e504" => (
            504,
            Some("text/plain"),
            b"its own gateway timed out".to_vec(),
        ),
        "e401" => (401, None, b"app says sign in".to_vec()),
        "e403" => (
            403,
            Some("application/problem+json"),
            br#"{"title":"no"}"#.to_vec(),
        ),
        "gzip" => (
            500,
            Some("text/plain"),
            vec![0x1f, 0x8b, 0x08, 0x00, 0xde, 0xad, 0xbe, 0xef],
        ),
        _ => (404, None, Vec::new()),
    }
}

/// AN ERROR FROM THE APPLICATION IS THE APPLICATION'S: status, body bytes,
/// content type and its own headers reach the caller, a browser included;
/// only the hop-by-hop headers go, the proxy adds no policy, no
/// `Cache-Control`, no challenge and no page, logs no refusal, and records
/// the request as forwarded and no fault. The proxy's OWN 502 and 504 on
/// the same paths — the application unreachable, or too slow — are the
/// standard page or JSON.
#[tokio::test]
async fn an_error_the_application_answers_is_passed_through() {
    let h = harness().await;
    let app = failing_application().await;
    let up = format!("http://127.0.0.1:{}/pep-app", app);
    let cert = String::from_utf8(h.saml_signer.1.to_pem().unwrap()).unwrap();
    h.sync
        .receive_proxy(&configuration(&up, &h.service_base, &cert), None);
    let audit = h.proxied.audit();
    let mut failures: Vec<String> = Vec::new();
    let cases = [
        "/public/e404",
        "/public/e500",
        "/public/e502",
        "/public/e503",
        "/public/e504",
        "/public/e401",
        "/public/e403",
        "/public/gzip",
        "/public/empty",
        "/api/e401",
        "/api/e503",
    ];
    for path in cases {
        for html in [true, false] {
            let mut r = accept(h.get(path), html);
            if path.starts_with("/api/") {
                r = r.basic_auth("alice", Some("right"));
            }
            let a = answered(r.send().await.unwrap()).await;
            let last = path.rsplit('/').next().unwrap();
            let (status, content_type, body) = application_said(last);
            let label =
                format!("{} ({})", path, if html { "html" } else { "json" });
            let mut fail =
                |why: String| failures.push(format!("{}: {}", label, why));
            if a.status != status {
                fail(format!(
                    "status {} for the application's {}",
                    a.status, status
                ));
            }
            if a.body != body {
                fail(format!(
                    "the body changed: {:?}",
                    String::from_utf8_lossy(&a.body)
                ));
            }
            if a.headers.get("content-type").and_then(|v| v.to_str().ok())
                != content_type
            {
                fail(format!(
                    "content-type {:?}",
                    a.headers.get("content-type")
                ));
            }
            if header(&a, "x-app") != format!("app {}", last) {
                fail("the application's own header is gone".into());
            }
            for hop in ["connection", "x-app-hop", "proxy-app"] {
                if a.headers.contains_key(hop) {
                    fail(format!("the hop-by-hop {} crossed", hop));
                }
            }
            // Nothing of the proxy's added: the application's policy and
            // caching are its own, and absent where it sent none.
            let csp = header(&a, "content-security-policy");
            let caching = header(&a, "cache-control");
            match last {
                "e404" => {
                    if csp != "default-src 'self'" || caching != "max-age=60" {
                        fail(format!(
                            "its headers were replaced: {} / {}",
                            csp, caching
                        ));
                    }
                }
                _ => {
                    if !csp.is_empty() || !caching.is_empty() {
                        fail(format!("the proxy added {} / {}", csp, caching));
                    }
                }
            }
            if last == "e503" && header(&a, "retry-after") != "7" {
                fail("its Retry-After is gone".into());
            }
            if last == "e401" {
                let challenges: Vec<_> = a
                    .headers
                    .get_all("www-authenticate")
                    .iter()
                    .map(|v| v.to_str().unwrap_or("").to_string())
                    .collect();
                if challenges != ["Bearer realm=\"app\""] {
                    fail(format!("the challenges changed: {:?}", challenges));
                }
            }
            let text = String::from_utf8_lossy(&a.body);
            if text.contains("Diagnostics") || text.contains("Incident ID") {
                fail("the proxy's page".into());
            }
        }
        if !proxy::logged::holding(&format!("{:?}", path)).is_empty() {
            failures.push(format!("{}: a refusal was logged", path));
        }
    }
    // The decision records: forwarded, and never the proxy's fault.
    for record in audit.queued_for_test() {
        if !record.allowed || record.fault {
            failures.push(format!(
                "{:?} {:?}: allowed {} fault {}",
                record.route, record.status, record.allowed, record.fault
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} pass-through failure(s):\n{}",
        failures.len(),
        failures.join("\n")
    );
    // THE PROXY'S OWN 502 AND 504 ARE NOT PASSED THROUGH, THEY ARE MADE:
    // too slow, on the application's own path…
    let slow = SOURCES.iter().find(|s| s.code == "STS-XPEP-0068").unwrap();
    for html in [true, false] {
        let a =
            answered(accept(h.get("/slow"), html).send().await.unwrap()).await;
        hold(slow, html, &a, &mut failures);
    }
    // …and unreachable, on the very path whose 502 was the application's.
    let down = SOURCES.iter().find(|s| s.code == "STS-XPEP-0069").unwrap();
    let dead = format!("http://127.0.0.1:{}/pep-app", dead_port());
    h.sync
        .receive_proxy(&configuration(&dead, &h.service_base, &cert), None);
    for html in [true, false] {
        let a =
            answered(accept(h.get("/public/e502"), html).send().await.unwrap())
                .await;
        hold(down, html, &a, &mut failures);
        if a.body == application_said("e502").2 {
            failures.push("the application's 502 body was answered".into());
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

// ===== THE DOCUMENTED EXCEPTIONS ==========================================

/// THE API LISTENER IS JSON-ONLY: a caller that accepts only HTML still
/// gets JSON there (it has no person in front of it, and no page), each
/// error its documented shape with no code; `POST /notify` is a 204 with no
/// body and no type; AuthZEN's refusal is `{error: {status, message}}`.
#[tokio::test]
async fn the_api_listener_answers_its_documented_shapes_whatever_is_accepted() {
    use crate::listener::Transport;
    let mut options = Options::from_env("0.0.0");
    options.pdp_url = "http://127.0.0.1:9".into();
    options.pip_enabled = false;
    let client = PdpClient::new(&options).unwrap();
    let sync = Arc::new(Sync::new(client.clone(), options.clone()));
    let pep = Arc::new(Pep::new(
        options,
        sts_core::version::load(Path::new(".")),
        sync,
        RemotePip::new(client, false),
        Arc::new(HttpsListener::new("", "", 0, 1000, None)),
    ));
    let ask = |method: &str, path: &str, transport: Transport, body: &str| {
        let pep = pep.clone();
        let request = axum::http::Request::builder()
            .method(method)
            .uri(path)
            .header("accept", "text/html")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body.to_string()));
        async move {
            let mut request = request.unwrap();
            request.extensions_mut().insert(transport);
            let response = pep.handle(request).await;
            let status = response.status().as_u16();
            let headers = response.headers().clone();
            let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
                .await
                .unwrap();
            (status, headers, String::from_utf8_lossy(&bytes).to_string())
        }
    };
    let https = Transport {
        https: true,
        ..Transport::default()
    };
    let crl_only = Transport {
        crl_only: true,
        ..Transport::default()
    };
    let mut failures: Vec<String> = Vec::new();
    for (method, path, transport, status, members) in [
        (
            "GET",
            "/nothing",
            https.clone(),
            404,
            &["error", "error_description"][..],
        ),
        (
            "POST",
            "/notify",
            Transport::default(),
            404,
            &["error", "error_description"],
        ),
        ("GET", "/crl/none.crl", https.clone(), 404, &["error"]),
        ("GET", "/", crl_only, 404, &["error", "error_description"]),
    ] {
        let (got, headers, body) = ask(method, path, transport, "").await;
        let label = format!("{} {}", method, path);
        let parsed: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        let keys: Vec<&String> = parsed
            .as_object()
            .map(|o| o.keys().collect())
            .unwrap_or_default();
        if got != status
            || headers["content-type"] != "application/json"
            || headers["cache-control"] != "no-store"
            || keys != members
            || parsed["error"] != "not_found"
            || body.contains("STS-")
        {
            failures.push(format!("{}: {} {:?} {}", label, got, headers, body));
        }
    }
    // /protected refused: the decision document, still JSON, no code.
    let (got, headers, body) =
        ask("GET", "/protected?subject=alice", https.clone(), "").await;
    if got != 403
        || headers["content-type"] != "application/json"
        || body.contains("STS-")
    {
        failures.push(format!("/protected: {} {:?} {}", got, headers, body));
    }
    // The nudge: 204, no body, no type.
    let (got, headers, body) =
        ask("POST", "/notify", https.clone(), "{}").await;
    if got != 204
        || !body.is_empty()
        || headers.contains_key("content-type")
        || headers["cache-control"] != "no-store"
    {
        failures.push(format!("/notify: {} {:?} {:?}", got, headers, body));
    }
    // AuthZEN's own refusal shape, whatever was accepted.
    let (got, headers, body) =
        ask("POST", "/access/v1/evaluation", https, "not json").await;
    let parsed: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
    if !(400..600).contains(&got)
        || headers["content-type"] != "application/json"
        || parsed["error"]["status"] != json!(got)
        || !parsed["error"]["message"].is_string()
        || parsed.as_object().map(|o| o.len()) != Some(1)
        || body.contains("STS-")
    {
        failures.push(format!("AuthZEN: {} {:?} {}", got, headers, body));
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// A REQUEST HYPER CANNOT PARSE NEVER REACHES THE PROXY: there is no
/// `Accept` to choose a shape by and no refusal to log, so it is hyper's
/// bare status, with no body — nothing internal and no code.
#[tokio::test]
async fn a_request_that_cannot_be_parsed_is_a_bare_status() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let h = harness().await;
    let address = h.proxy.trim_start_matches("http://").to_string();
    for (label, bytes) in [
        (
            "a header line with no colon",
            "GET /public/x HTTP/1.1\r\nHost: x\r\nno colon here\r\n\r\n",
        ),
        ("not HTTP at all", "\x16\x03\x01\x00\x05hello\r\n\r\n"),
    ] {
        let mut stream =
            tokio::net::TcpStream::connect(&address).await.unwrap();
        stream.write_all(bytes.as_bytes()).await.unwrap();
        let mut answer = Vec::new();
        // hyper closes the connection after its 400.
        tokio::time::timeout(
            Duration::from_secs(5),
            stream.read_to_end(&mut answer),
        )
        .await
        .expect("the connection is closed")
        .unwrap();
        let text = String::from_utf8_lossy(&answer).to_string();
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
        // hyper's own: `400 Bad Request`, `content-length: 0`, closed.
        assert!(
            head.starts_with("HTTP/1.1 400 ")
                && head.contains("content-length: 0"),
            "{}: {:?}",
            label,
            text
        );
        assert!(body.is_empty(), "{}: a body {:?}", label, body);
        assert!(!text.contains("STS-"), "{}", label);
    }
    assert_eq!(
        hits(&h),
        0,
        "nothing reached the application, but it saw:\n{}",
        seen(&h)
    );
}
