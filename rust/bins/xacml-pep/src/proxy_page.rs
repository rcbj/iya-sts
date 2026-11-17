// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE REVERSE PROXY'S ONE ERROR PAGE (#1760, rcbj, 2026-11-15): what a
//! PERSON sees when the proxy refuses their browser — the policy said no,
//! the route is closed (deny-all), its policy is not held, the sign-in
//! failed, the application or the service cannot be reached.
//!
//! **IT IS THE SERVICE'S ERROR PAGE, DRAWN HERE** — `common/error_page.ts`
//! (#1326), in the same order and under the same class names, so the two
//! look like one product:
//!
//!   1. the title, and the error in the yellow box: the `error` the API
//!      answer carries, as a value, and a sentence saying what was wrong;
//!   2. what the person can do here — another account through the account
//!      chooser on a `multipleAccounts` route, or a sign-out on a session
//!      route, where the refusal is about WHO is asking;
//!   3. the background, collapsed (a `<details>`: no script);
//!   4. the start-over note, and a link to the start page;
//!   5. **the Diagnostics box**: the time, the INCIDENT ID, then what the
//!      proxy knows about the request — the application, the address, who
//!      is signed in, the `error` and the `error_description` an API client
//!      would have been answered.
//!
//! **THE INCIDENT ID IS WHAT AN OPERATOR SEARCHES FOR.** The service's is
//! the `seq` of the request's audit row; this container has no audit log —
//! its record is a log line (`xacml-pep/CLAUDE.md`) — so its incident ID is
//! a random value drawn for the page and printed in the refusal's log line
//! beside the error code. **The code itself is never on the page** (the
//! rule in the root `CLAUDE.md`, *Every failure has an error code*): what
//! the pane shows is only what an API client of the same request is sent,
//! plus the time, the incident ID and the person's own name.
//!
//! **NO SCRIPT, AND ONE STYLE SHEET ADMITTED BY ITS HASH.** The proxy's own
//! pages run under `default-src 'none'`; this one adds `style-src` with the
//! SHA-256 of its one `<style>` element and nothing else, which is
//! narrower than `'self'` and needs no second request through a proxy whose
//! every other path is the application's. **In English**: the PEP holds no
//! message catalogs (`docs/v1.1.0/remote-pep.md`, *Several accounts*).
//!
//! **THE ACCOUNT CHOOSER USES THIS SHELL** (`document_shell()`), not a second
//! document. It is not an error page — no warning box, no diagnostics, no
//! incident ID — and on 2026-11-15 it was drawn with none of this sheet, so
//! a person who followed *Use a different account* landed on an unstyled
//! page flush to the left. The rules after the copied sheet
//! (`ul.accounts`, `button.portal`, `p.hint`) are the chooser's and match
//! nothing on the error page, so one hash still admits both documents.
//!
//! **THE CSS UP TO THE FOOTER IS A COPY of `common/error_page.ts`'s `CSS`
//! and `FOOTER_CSS` and of the two footer rules of `common/web_footer.ts`
//! it uses**, because this image is built from `rust/` alone and cannot
//! read them. A change there is made here as well. The chooser's rules
//! below that copy are this file's own. The start page's rules at the end
//! (`.front`) are the front door's band and card (`home/home.ts`'s
//! `HOME_CSS`, the sign-in card's border and shadow), scoped so they match
//! nothing on the error page or the chooser.
//!
//! **THE START PAGE** is what *Go to the start page* opens: `GET /` when
//! no route is mounted there (`front_document()`). The same shell, so the
//! footer is the service's, and the product logo (`logo.png` here, a
//! byte-for-byte copy of `docs/logo.png`, served at `LOGO_PATH`). It lists
//! no route. `img-src 'self'` admits that one image; the style sheet stays
//! a hash.

use std::sync::OnceLock;

use axum::body::Body;
use axum::http::{header, HeaderName, HeaderValue, Response, StatusCode};

/// `common/error_page.ts`'s page style, its ending's, and the footer's
/// copyright and version lines (`common/web_footer.ts`).
const CSS: &str = concat!(
    "body{font-family:system-ui,-apple-system,\"Segoe UI\",Roboto,",
    "sans-serif;margin:2rem auto;max-width:46rem;padding:0 1rem;",
    "line-height:1.5;color:#222;background:#fff}",
    "h1{font-size:1.5rem;margin:.4rem 0 1rem}",
    "code{font-family:ui-monospace,Menlo,monospace;font-size:.85rem;",
    "background:#f4f4f8;padding:.1rem .25rem;border-radius:3px;",
    "word-break:break-all}",
    ".warn{background:#fff8e1;border:1px solid #ffe082;padding:.7rem .9rem;",
    "border-radius:4px;margin:1rem 0}",
    ".warn .error{display:block;font-weight:600;margin-bottom:.2rem}",
    "details.prose{margin:1rem 0;color:#444}",
    "details.prose>summary{cursor:pointer;color:#1f4fa3}",
    "details.prose>summary:hover{color:#2c5cc5}",
    "details.prose>div{margin:.5rem 0 0 1rem;font-size:.92rem}",
    ".next{margin:1.2rem 0}",
    ".next a.portal{display:inline-block;margin-top:.5rem;",
    "margin-right:.5rem;padding:.35rem .8rem;border:1px solid #1f4fa3;",
    "border-radius:4px;color:#1f4fa3;text-decoration:none}",
    ".next a.portal:hover{background:#eef3fc}",
    "section.diagnostics{margin:2rem 0 1rem;padding:.6rem .9rem;",
    "border:1px solid #ddd;border-radius:4px;background:#fafafa;",
    "font-size:.82rem;color:#555}",
    "section.diagnostics h2{font-size:.85rem;margin:0 0 .4rem;",
    "text-transform:uppercase;letter-spacing:.04em;color:#666}",
    "section.diagnostics dl{display:grid;",
    "grid-template-columns:max-content 1fr;gap:.15rem .9rem;margin:0}",
    "section.diagnostics dt{color:#666}section.diagnostics dd{margin:0;",
    "min-width:0}section.diagnostics dd code{font-size:.8rem}",
    ".sts-footer{width:100%;box-sizing:border-box;clear:both;",
    "margin:24px 0 0;padding:16px 10px 10px;text-align:center;",
    "border-top:1px solid #ddd;",
    "font-family:system-ui,-apple-system,\"Segoe UI\",Arial,sans-serif;",
    "color:#555;font-size:14px;line-height:1.4}",
    ".sts-footer-copyright{padding:12px 12px 0}",
    ".sts-footer-version{padding:2px 12px 0;font-size:11px;color:#999;",
    "letter-spacing:.02em}",
    // The account chooser's own rules. Nothing on the error page matches
    // them; they live in this sheet so both documents share one hash.
    "ul.accounts{list-style:none;margin:1rem 0;padding:0}",
    "ul.accounts>li{margin:0 0 .9rem;padding:.75rem .9rem;",
    "border:1px solid #ddd;border-radius:4px;background:#fafafa}",
    "ul.accounts .app{color:#555}",
    "ul.accounts .mark{margin-left:.4rem;color:#1b5e20;",
    "font-size:.85rem;font-weight:600}",
    "ul.accounts form,.next form{display:inline}",
    "button.portal{display:inline-block;margin-top:.5rem;",
    "margin-right:.5rem;padding:.35rem .8rem;",
    "border:1px solid #1f4fa3;border-radius:4px;background:#fff;",
    "color:#1f4fa3;font:inherit;line-height:1.5;cursor:pointer}",
    "button.portal:hover{background:#eef3fc}",
    "p.hint{color:#444;margin:.2rem 0 1rem}",
    // The start page. Nothing else carries `.front`. The band is the
    // logo's own ground (`#fbfaf8`); the card is the sign-in card's.
    "body:has(.front){background:#f4f4f7}",
    ".front{background:#fff;border:1px solid #d5d5dd;",
    "border-radius:10px;max-width:44rem;margin:0 auto;",
    "overflow:hidden;box-shadow:0 6px 24px rgba(0,0,0,.08);",
    "padding:0 0 26px}",
    ".front .hero{background:#fbfaf8;padding:22px 24px;",
    "text-align:center;border-bottom:1px solid #ecebe7}",
    ".front .hero img{width:100%;max-width:453px;height:auto;",
    "display:inline-block}",
    ".front .body{padding:22px 28px 0}",
    ".front h1{font-size:1.5em;margin:0 0 2px;color:#12107c;",
    "letter-spacing:.01em}",
    ".front p.sub{color:#666;font-size:.88em;margin:0 0 16px}"
);

/// The product logo's path. The proxy's own, like the account chooser.
pub const LOGO_PATH: &str = "/.iya-pep/logo.png";

/// `docs/logo.png`, byte for byte (906 × 269). `home/assets/logo.png` is
/// the service's copy; this one is embedded because the image is built
/// from `rust/` alone. Copy `docs/logo.png` over it when that file changes.
const LOGO_PNG: &[u8] = include_bytes!("logo.png");

/// The proxy's page policy with the one style sheet admitted by its hash,
/// and `img-src 'self'` for the start page's logo.
fn policy() -> &'static str {
    static POLICY: OnceLock<String> = OnceLock::new();
    POLICY.get_or_init(|| {
        let digest = openssl::sha::sha256(CSS.as_bytes());
        format!(
            "default-src 'none'; style-src 'sha256-{}'; img-src 'self'; \
             form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
            openssl::base64::encode_block(&digest)
        )
    })
}

/// Escapes text for HTML: an element's content or a quoted attribute.
pub fn esc(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// One thing the person can do: a link on this proxy (a GET; the page has
/// no form).
#[derive(Debug, Clone, PartialEq)]
pub struct Action {
    pub href: String,
    pub label: String,
}

/// One row of the Diagnostics box: a label and a value shown as data. An
/// empty value leaves the row out.
#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    pub label: &'static str,
    pub value: String,
}

/// What one page draws. Every member is TEXT, escaped when drawn.
#[derive(Debug, Clone, Default)]
pub struct ErrorPage {
    pub status: u16,
    pub title: String,
    /// The `error` an API client is answered, shown in the box as a value.
    pub error: String,
    /// The sentence in the box.
    pub message: String,
    /// What the person can do, drawn right below the box.
    pub actions: Vec<Action>,
    /// Why the page was shown, collapsed; empty for none.
    pub background: String,
    /// The incident ID; empty when none could be drawn.
    pub incident: String,
    /// The time, as an RFC 3339 instant in UTC.
    pub time: String,
    /// What the proxy knows, below the time and the incident ID.
    pub diagnostics: Vec<Row>,
    /// This PEP's version, for the footer.
    pub version: String,
}

/// A fresh incident ID: 64 random bits as hex, or empty when no random
/// value could be drawn (the page then says none was recorded).
pub fn incident_id() -> String {
    let mut bytes = [0u8; 8];
    match openssl::rand::rand_bytes(&mut bytes) {
        Ok(()) => bytes.iter().map(|b| format!("{:02x}", b)).collect(),
        Err(error) => {
            tracing::debug!(
                "xacml-pep: proxy: no incident ID could be drawn: {}",
                error
            );
            String::new()
        }
    }
}

/// The time an error page prints: `toISOString()`'s shape, as the
/// service's page prints it.
pub fn now_utc() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// The copyright line's years: 2026, or 2026 through this year.
fn copyright_years() -> String {
    let year = chrono::Utc::now().format("%Y").to_string();
    if year.as_str() > "2026" {
        format!("2026–{}", year)
    } else {
        "2026".to_string()
    }
}

/// The footer the service's error page ends with.
fn footer(version: &str) -> String {
    format!(
        "<footer class=\"sts-footer\"><div \
         class=\"sts-footer-copyright\">© {years} Iya CyberSecurity \
         Solutions, LLC. All rights reserved.</div><div \
         class=\"sts-footer-version\">Version {version}</div></footer>",
        years = copyright_years(),
        version = esc(version),
    )
}

/// The proxy's own document: the one style sheet, then `inner` (already
/// escaped by the caller), then the footer. The account chooser and the
/// error page are both this.
pub fn document_shell(title: &str, inner: &str, version: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, \
         initial-scale=1\"><title>{title}</title><style>{css}</style>\
         </head><body>{inner}{footer}</body></html>",
        title = esc(title),
        css = CSS,
        inner = inner,
        footer = footer(version),
    )
}

/// A document from `document_shell` as a response: `text/html`, never
/// cached, and the policy that admits the one style sheet and nothing else.
pub fn html_response(status: u16, html: String) -> Response<Body> {
    let mut response = Response::new(Body::from(html));
    *response.status_mut() = StatusCode::from_u16(status)
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static(policy()),
    );
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    response
}

/// The product logo, as `GET /logo.png` serves it on the service: the
/// bytes cannot change while this process runs, so an hour is enough.
pub fn logo_response() -> Response<Body> {
    let mut response = Response::new(Body::from(LOGO_PNG));
    *response.status_mut() = StatusCode::OK;
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("image/png"));
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=3600"),
    );
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    response
}

/// The start page: the front door's card inside this proxy's shell, so
/// the footer is the service's. It lists no route.
pub fn front_document(version: &str) -> String {
    let inner = format!(
        "<div class=\"front\"><div class=\"hero\"><img src=\"{src}\" \
         width=\"906\" height=\"269\" alt=\"IYA STS — Security Token \
         Service\"></div><div class=\"body\"><h1>IYA STS</h1><p \
         class=\"sub\">A policy enforcement point in front of this \
         realm&#39;s applications.</p></div></div>",
        src = LOGO_PATH,
    );
    document_shell("IYA STS", &inner, version)
}

impl ErrorPage {
    /// The whole document.
    pub fn document(&self) -> String {
        let mut rows = vec![
            Row {
                label: "Time (UTC)",
                value: self.time.clone(),
            },
            Row {
                label: "Incident ID",
                value: if self.incident.is_empty() {
                    "none recorded".to_string()
                } else {
                    self.incident.clone()
                },
            },
        ];
        rows.extend(self.diagnostics.iter().cloned());
        let rows: String = rows
            .iter()
            .filter(|r| !r.value.is_empty())
            .map(|r| {
                format!(
                    "<dt>{}</dt><dd><code>{}</code></dd>",
                    esc(r.label),
                    esc(&r.value)
                )
            })
            .collect();
        let links = |actions: &[Action]| -> String {
            actions
                .iter()
                .map(|a| {
                    format!(
                        "<a class=\"portal\" href=\"{}\">{}</a>",
                        esc(&a.href),
                        esc(&a.label)
                    )
                })
                .collect()
        };
        let after = if self.actions.is_empty() {
            String::new()
        } else {
            format!("<div class=\"next\">{}</div>", links(&self.actions))
        };
        let background = if self.background.is_empty() {
            String::new()
        } else {
            format!(
                "<details class=\"prose\"><summary>Why am I seeing this \
                 page?</summary><div>{}</div></details>",
                esc(&self.background)
            )
        };
        let error = if self.error.is_empty() {
            String::new()
        } else {
            format!("<span class=\"error\">{}</span>", esc(&self.error))
        };
        let start = [Action {
            href: "/".into(),
            label: "Go to the start page".into(),
        }];
        let inner = format!(
            "<h1>{title}</h1><div class=\"warn\" \
             role=\"alert\">{error}{message}</div>{after}{background}\
             <div class=\"next\"><p>Close this tab and start again from the \
             application you were using, or use your browser's Back button. \
             If this happens again, send the diagnostics below to whoever \
             runs that application.</p>{start}</div>\
             <section class=\"diagnostics\" \
             aria-labelledby=\"diagnostics-heading\"><h2 \
             id=\"diagnostics-heading\">Diagnostics</h2><dl>{rows}</dl>\
             </section>",
            title = esc(&self.title),
            error = error,
            message = esc(&self.message),
            after = after,
            background = background,
            start = links(&start),
            rows = rows,
        );
        document_shell(&self.title, &inner, &self.version)
    }

    /// The page as a response: its status, `text/html`, never cached, and
    /// the policy that admits its style sheet and nothing else.
    pub fn response(&self) -> Response<Body> {
        html_response(self.status, self.document())
    }
}

/// The title, the sentence and the background a refusal is drawn with,
/// by its code where the code says more than the status, else by status.
pub fn wording(
    status: u16,
    code: &str,
) -> (&'static str, &'static str, &'static str) {
    const POLICY_BACKGROUND: &str =
        "This application is behind a policy enforcement point. Before \
         every request reaches the application, the enforcement point \
         decides it with the access policy the identity service manages. \
         This request was refused there, so the application never saw it.";
    match (status, code) {
        (403, "STS-XPEP-0086") | (403, "STS-XPEP-0095") => (
            "You do not have access to this page",
            "The access policy for this application does not allow the \
             account you are signed in with to do this.",
            POLICY_BACKGROUND,
        ),
        (403, "STS-XPEP-0116") => (
            "This page is closed",
            "This part of the application has been closed to every request \
             by its administrator.",
            POLICY_BACKGROUND,
        ),
        (403, "STS-XPEP-0117") => (
            "Access cannot be decided now",
            "The access policy this page depends on is not available right \
             now, so the request was refused rather than let through. Try \
             again later.",
            POLICY_BACKGROUND,
        ),
        (403, "STS-XPEP-0093") => (
            "This application cannot be used now",
            "The application this page belongs to is not available for \
             sign-in at the moment.",
            POLICY_BACKGROUND,
        ),
        (403, "STS-XPEP-0108") => (
            "Too many accounts",
            "This browser is already signed in to as many accounts here as \
             this application allows. Sign one of them out first.",
            "",
        ),
        (403, "STS-XPEP-0109") => (
            "This request was refused",
            "An account can only be switched or signed out from this \
             site's own account page.",
            "",
        ),
        (403, _) => (
            "You do not have access to this page",
            "This request was refused.",
            POLICY_BACKGROUND,
        ),
        (401, "STS-XPEP-0082") => (
            "The sign-in could not be completed",
            "The sign-in took too long, was already used, or was started in \
             another browser. Start again from the application.",
            "",
        ),
        (401, "STS-XPEP-0083") => (
            "The sign-in did not succeed",
            "The identity service did not complete the sign-in. Start again \
             from the application.",
            "",
        ),
        (401, _) => (
            "Sign-in required",
            "This page needs you to be signed in, and the request did not \
             carry a sign-in this page accepts.",
            "",
        ),
        (400, _) => (
            "This address cannot be used",
            "The address you asked for is not one this application accepts.",
            "",
        ),
        (404, _) => ("Page not found", "There is no page at this address.", ""),
        (405, _) => (
            "This action is not allowed here",
            "This page does not accept this kind of request.",
            "",
        ),
        (413, _) => (
            "The request is too large",
            "What was sent is larger than this application accepts.",
            "",
        ),
        (429, _) => (
            "Too many attempts",
            "There have been too many attempts. Wait a moment and try again.",
            "",
        ),
        (502, _) => (
            "The application cannot be reached",
            "The application or the identity service could not be reached, \
             or did not answer usably. Try again later.",
            "",
        ),
        (503, "STS-XPEP-0118") => (
            "Try again later",
            "The enforcement point in front of this application has just \
             started and is still receiving its settings from the identity \
             service. Try again in a few seconds.",
            "",
        ),
        (503, _) => (
            "Try again later",
            "This application cannot take the request right now. Try again \
             later.",
            "",
        ),
        (504, _) => (
            "The application did not answer in time",
            "The application took too long to answer. Try again later.",
            "",
        ),
        _ => (
            "Something went wrong",
            "The request could not be completed. Try again later.",
            "",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page() -> ErrorPage {
        ErrorPage {
            status: 403,
            title: "You do not have access to this page".into(),
            error: "access_denied".into(),
            message: "No.".into(),
            actions: vec![Action {
                href: "/.iya-pep/accounts?return=%2Fa".into(),
                label: "Use a different account".into(),
            }],
            background: "Because.".into(),
            incident: "0123456789abcdef".into(),
            time: "2026-11-15T10:00:00.000Z".into(),
            diagnostics: vec![
                Row {
                    label: "Address",
                    value: "/a".into(),
                },
                Row {
                    label: "Signed in as",
                    value: String::new(),
                },
            ],
            version: "1.1.0.1".into(),
        }
    }

    #[test]
    fn the_page_has_the_services_structure_and_the_pane() {
        let html = page().document();
        let order = [
            "<h1>You do not have access to this page</h1>",
            "<div class=\"warn\" role=\"alert\"><span class=\"error\">\
             access_denied</span>No.</div>",
            "<div class=\"next\"><a class=\"portal\" \
             href=\"/.iya-pep/accounts?return=%2Fa\">",
            "<details class=\"prose\"><summary>Why am I seeing this page?",
            "Close this tab and start again",
            "<section class=\"diagnostics\"",
            "<dt>Time (UTC)</dt><dd><code>2026-11-15T10:00:00.000Z</code>",
            "<dt>Incident ID</dt><dd><code>0123456789abcdef</code>",
            "<dt>Address</dt><dd><code>/a</code></dd>",
            "<footer class=\"sts-footer\">",
            "Version 1.1.0.1",
        ];
        let mut at = 0;
        for want in order {
            let found = html[at..].find(want);
            assert!(found.is_some(), "missing or out of order: {}", want);
            at += found.unwrap_or(0) + want.len();
        }
        assert!(!html.contains("Signed in as"), "an empty row is left out");
        assert!(!html.contains("<script"), "no script");
        assert!(!html.contains("STS-"), "no error code");
    }

    #[test]
    fn every_value_is_escaped() {
        let evil = "<script>alert('x')</script>\"&";
        let mut p = page();
        p.title = evil.into();
        p.error = evil.into();
        p.message = evil.into();
        p.background = evil.into();
        p.incident = evil.into();
        p.version = evil.into();
        p.actions = vec![Action {
            href: format!("/x\"onclick=\"{}", evil),
            label: evil.into(),
        }];
        p.diagnostics = vec![Row {
            label: "Address",
            value: evil.into(),
        }];
        let html = p.document();
        assert!(!html.contains("<script"), "{}", html);
        assert!(!html.contains("\"onclick"), "{}", html);
        assert!(html.contains(
            "&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;&quot;&amp;"
        ));
    }

    #[test]
    fn no_incident_says_so() {
        let mut p = page();
        p.incident = String::new();
        assert!(p
            .document()
            .contains("<dt>Incident ID</dt><dd><code>none recorded</code>"));
    }

    #[test]
    fn the_policy_admits_exactly_the_pages_style_sheet() {
        let response = page().response();
        assert_eq!(response.status(), 403);
        let csp = response.headers()["content-security-policy"]
            .to_str()
            .unwrap_or("")
            .to_string();
        let digest = openssl::sha::sha256(CSS.as_bytes());
        let hash = openssl::base64::encode_block(&digest);
        assert!(csp.contains(&format!("style-src 'sha256-{}'", hash)));
        assert!(csp.starts_with("default-src 'none';"));
        assert!(csp.contains("frame-ancestors 'none'"));
        assert!(csp.contains("img-src 'self'"));
        assert!(!csp.contains("script-src"));
        assert!(!csp.contains("unsafe-inline"));
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert!(page()
            .document()
            .contains(&format!("<style>{}</style>", CSS)));
        // The account chooser is the same sheet and the same hash, around
        // its own body.
        let shell = document_shell(
            "Accounts",
            "<h1>Accounts in this browser</h1>",
            "1.1.0.1",
        );
        assert!(shell.contains(&format!("<style>{}</style>", CSS)));
        assert!(
            shell.contains("ul.accounts") && shell.contains("button.portal")
        );
        assert!(shell.contains("Version 1.1.0.1"));
        assert!(shell.contains("<h1>Accounts in this browser</h1>"));
        let shell_csp = html_response(200, shell).headers()
            ["content-security-policy"]
            .to_str()
            .unwrap_or("")
            .to_string();
        assert!(shell_csp.contains(&format!("style-src 'sha256-{}'", hash)));
    }

    #[test]
    fn the_start_page_is_the_front_door() {
        let html = front_document("1.1.0.1");
        assert!(html.contains("<title>IYA STS</title>"));
        assert!(html.contains("class=\"front\""));
        assert!(html.contains(&format!("src=\"{}\"", LOGO_PATH)));
        assert!(html.contains("width=\"906\""));
        assert!(html.contains("height=\"269\""));
        assert!(html.contains("alt=\"IYA STS — Security Token Service\""));
        assert!(html.contains("<h1>IYA STS</h1>"));
        assert!(html.contains("policy enforcement point"));
        assert!(html.contains("class=\"sts-footer\""));
        assert!(html.contains("Iya CyberSecurity Solutions, LLC"));
        assert!(html.contains("Version 1.1.0.1"));
        assert!(!html.contains("<script"), "{}", html);
        assert!(!html.contains("STS-"), "{}", html);
        assert!(LOGO_PNG.starts_with(b"\x89PNG"));
        let logo = logo_response();
        assert_eq!(logo.status(), 200);
        assert_eq!(logo.headers()["content-type"], "image/png");
        assert_eq!(logo.headers()["cache-control"], "public, max-age=3600");
    }

    #[test]
    fn an_incident_id_is_sixteen_hex_digits_and_fresh() {
        let one = incident_id();
        assert_eq!(one.len(), 16);
        assert!(one.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(one, incident_id());
    }
}
