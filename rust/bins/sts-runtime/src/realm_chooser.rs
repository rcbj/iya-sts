// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! THE REALM CHOOSER (`common/realm_chooser.ts`; #444, phase 5, the
//! `apis4` slice): a browser signed in nowhere that opens the plain
//! `/admin`, `/portal` or `/report` of a service with realms is asked which
//! realm it belongs to, rather than signed in to the default one.
//!
//! [`RealmChooser::decide`] is `decide()`: the question is asked only of a
//! GET or HEAD for the surface's root, in the default realm, while any
//! realm is defined, and only of a browser holding no sign-on session
//! (`authn.sessionOf()`, the shells' own test). `?realm=` chooses (an
//! unknown id redraws the page with its sentence, 400, `STS-ADMIN-0790` /
//! `STS-PORTAL-0074`); a choice is remembered in `sts_realm` for a year
//! (HttpOnly, SameSite=Lax, Secure over HTTPS), and the remembered realm
//! is the next bare visit's answer. A choice of another realm is a 303 to
//! its prefix; the default realm draws the shell where it is, with the
//! cookie set ([`RealmChooser::shell_cookie`]).
//!
//! [`RealmChooser::page`] is `page()` and `form()`: the same markup, its
//! words from the `realmChooser` catalog in the page's negotiated language
//! (`PageLocale.forPage()`), the language row (`PageLocale.chooser()`).
//! The catalog's two `{surface, select, …}` messages are chosen here, the
//! runtime's translator filling plain parameters only.

use std::sync::Arc;

use axum::http::{header, HeaderValue, Method, Response, StatusCode};
use sts_core::errors::codes;
use sts_core::realm::{self, RealmRegistry};
use sts_core::settings::Settings;
use sts_http::error_page;
use sts_http::express::escape_html as esc;
use sts_http::Ask;

/// `COOKIE`.
const COOKIE: &str = "sts_realm";

// `encodeURIComponent()`: every byte but `A-Z a-z 0-9 - _ . ! ~ * ' ( )`
// percent-encoded.
fn encode_uri_component(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// A surface the chooser stands in front of (`SURFACES`).
struct Surface {
    root: &'static str,
    application: &'static str,
    which: &'static str,
}

fn surface_of(id: &str) -> Option<Surface> {
    match id {
        "admin" => Some(Surface {
            root: "/admin",
            application: "sts-admin-console",
            which: "admin",
        }),
        "portal" => Some(Surface {
            root: "/portal",
            application: "sts-user-portal",
            which: "portal",
        }),
        "report" => Some(Surface {
            root: "/report",
            application: "sts-report",
            which: "report",
        }),
        _ => None,
    }
}

/// `decide()`'s answer.
enum Decision {
    Page {
        error: String,
        cookie: Option<String>,
    },
    Redirect {
        location: String,
        cookie: String,
    },
    Here {
        cookie: String,
    },
}

/// The chooser, over the realm registry and the session core.
pub struct RealmChooser {
    pub registry: Arc<RealmRegistry>,
    pub settings: Arc<Settings>,
    pub sessions: Arc<sts_authn::Sessions>,
    pub surfaces: Arc<sts_http::shell::Surfaces>,
}

// `{name, select, k {…} … other {…}}` chosen by `value`, every such
// argument in the message (the catalog's markup and words otherwise as
// written).
fn select(message: &str, name: &str, value: &str) -> String {
    let opener = format!("{{{name}, select,");
    let Some(at) = message.find(&opener) else {
        return message.to_string();
    };
    // The argument's end: the brace that balances its opener.
    let bytes = message.as_bytes();
    let mut depth = 0;
    let mut end = None;
    for (i, b) in bytes.iter().enumerate().skip(at) {
        match b {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    end = Some(i);
                    break;
                }
            }
            _ => {}
        }
    }
    let Some(end) = end else {
        return message.to_string();
    };
    let body = &message[at + opener.len()..end];
    // The branches: `key {text}` pairs.
    let mut branches: Vec<(String, String)> = Vec::new();
    let mut rest = body;
    while let Some(open) = rest.find('{') {
        let key = rest[..open].trim().to_string();
        let mut d = 0;
        let mut close = None;
        for (i, b) in rest.as_bytes().iter().enumerate().skip(open) {
            match b {
                b'{' => d += 1,
                b'}' => {
                    d -= 1;
                    if d == 0 {
                        close = Some(i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(close) = close else {
            break;
        };
        branches.push((key, rest[open + 1..close].to_string()));
        rest = &rest[close + 1..];
    }
    let chosen = branches
        .iter()
        .find(|(k, _)| k == value)
        .or_else(|| branches.iter().find(|(k, _)| k == "other"))
        .map(|(_, t)| t.clone())
        .unwrap_or_default();
    let whole = format!("{}{}{}", &message[..at], chosen, &message[end + 1..]);
    select(&whole, name, value)
}

impl RealmChooser {
    fn cookie_state(ask: &Ask<'_>) -> (bool, String) {
        let header = ask
            .headers
            .get(header::COOKIE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let mut present = false;
        let mut value = String::new();
        for part in header.split(';') {
            if let Some(at) = part.find('=').filter(|a| *a > 0) {
                if part[..at].trim() == COOKIE {
                    present = true;
                    value = sts_http::cors::percent_decode_strict(
                        part[at + 1..].trim(),
                    )
                    .unwrap_or_default();
                }
            }
        }
        (present, value)
    }

    fn remembered_id(&self, ask: &Ask<'_>) -> String {
        let raw = Self::cookie_state(ask).1;
        if raw.is_empty() {
            return String::new();
        }
        if raw == realm::DEFAULT_ID {
            return raw;
        }
        match self.registry.get(&raw) {
            Some(r) if r.id != realm::DEFAULT_ID => r.id.clone(),
            _ => String::new(),
        }
    }

    fn cookie_line(&self, id: &str, clear: bool) -> String {
        format!(
            "{COOKIE}={}; Path=/; {}; HttpOnly; SameSite=Lax{}",
            if clear {
                String::new()
            } else {
                encode_uri_component(id)
            },
            if clear {
                "Max-Age=0"
            } else {
                "Max-Age=31536000"
            },
            if self.settings.value_of("global.https").as_bool() {
                "; Secure"
            } else {
                ""
            }
        )
    }

    // `serviceRoot(req)`: the request's base without the realm's prefix
    // (the chooser asks only in the default realm, whose prefix is '').
    fn service_root(&self, ask: &Ask<'_>) -> String {
        sts_authn_api::router::base_of(
            &self.settings,
            ask.headers,
            self.settings.value_of("global.https").as_bool(),
            "",
        )
    }

    fn query_realm(ask: &Ask<'_>) -> Option<String> {
        let query = sts_mgmt_api::request::parse_query(ask.query);
        match query.get("realm")? {
            serde_json::Value::String(s) => Some(s.trim().to_string()),
            serde_json::Value::Array(a) => Some(
                a.first()
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("")
                    .trim()
                    .to_string(),
            ),
            other => Some(other.to_string().trim().to_string()),
        }
    }

    fn chosen(&self, ask: &Ask<'_>, surface: &Surface, id: &str) -> Decision {
        let cookie = self.cookie_line(id, false);
        if id == realm::DEFAULT_ID {
            return Decision::Here { cookie };
        }
        let prefix = self
            .registry
            .get(id)
            .map(|r| self.registry.prefix_of(&r))
            .unwrap_or_default();
        Decision::Redirect {
            location: format!(
                "{}{}{}",
                self.service_root(ask),
                prefix,
                surface.root
            ),
            cookie,
        }
    }

    fn signed_in(&self, ask: &Ask<'_>) -> bool {
        let request = sts_authn::ports::Request {
            cookie: ask
                .headers
                .get(header::COOKIE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string(),
            user_agent: ask
                .headers
                .get(header::USER_AGENT)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string(),
            ..sts_authn::ports::Request::default()
        };
        self.sessions.session_of(&request, false).is_some()
    }

    // `decide(req, surfaceId)`, behind the shells' own test that the
    // browser is signed in nowhere.
    fn decide(&self, surface_id: &str, ask: &Ask<'_>) -> Option<Decision> {
        let surface = surface_of(surface_id)?;
        let get = *ask.method == Method::GET || *ask.method == Method::HEAD;
        let path = ask.path.trim_end_matches('/');
        if !get
            || realm::current_id() != realm::DEFAULT_ID
            || !self.registry.active()
            || path != surface.root
        {
            return None;
        }
        if self.signed_in(ask) {
            return None;
        }
        let Some(asked) = Self::query_realm(ask) else {
            let remembered = self.remembered_id(ask);
            if remembered.is_empty() {
                let stale = Self::cookie_state(ask).0;
                return Some(Decision::Page {
                    error: String::new(),
                    cookie: stale.then(|| self.cookie_line("", true)),
                });
            }
            if self.registry.get(&remembered).is_none() {
                return Some(Decision::Page {
                    error: String::new(),
                    cookie: Some(self.cookie_line("", true)),
                });
            }
            return Some(self.chosen(ask, &surface, &remembered));
        };
        if asked.is_empty() || asked == realm::DEFAULT_ID {
            return Some(self.chosen(ask, &surface, realm::DEFAULT_ID));
        }
        match self.registry.get(&asked) {
            Some(r) if r.id != realm::DEFAULT_ID => {
                Some(self.chosen(ask, &surface, &r.id.clone()))
            }
            _ => Some(Decision::Page {
                error: format!(
                    "There is no realm with the id \"{}\". Check the id and \
                     try again.",
                    asked.chars().take(64).collect::<String>()
                ),
                cookie: None,
            }),
        }
    }

    /// `page(req, surfaceId, error)` with `form()` inside it.
    #[tracing::instrument(level = "debug", skip_all)]
    fn page(&self, surface_id: &str, ask: &Ask<'_>, error: &str) -> String {
        let surface = surface_of(surface_id).unwrap_or(Surface {
            root: "/admin",
            application: "sts-admin-console",
            which: "admin",
        });
        let t = self
            .surfaces
            .translator(ask.headers, surface.application, "");
        let html = |key: &str| {
            select(&error_page::html(&t, key, &[]), "surface", surface.which)
        };
        let remembered = self.remembered_id(ask);
        let options: String = self
            .registry
            .list()
            .iter()
            .map(|r| {
                format!(
                    "<option value=\"{}\"{}>{}{}</option>",
                    esc(&r.id),
                    if r.id == remembered { " selected" } else { "" },
                    esc(&r.name),
                    if r.id == realm::DEFAULT_ID {
                        format!(" {}", html("realmChooser.defaultRealm"))
                    } else {
                        String::new()
                    }
                )
            })
            .collect();
        let control = format!(
            "<select id=\"realmchoice\" name=\"realm\" autofocus>{options}\
             </select>"
        );
        let action = format!("{}{}", self.service_root(ask), surface.root);
        let form = format!(
            "{}<p>{}</p><form method=\"get\" action=\"{}\"><p><label \
             for=\"realmchoice\">{}</label> {} <button type=\"submit\">{}\
             </button></p></form>",
            if error.is_empty() {
                String::new()
            } else {
                format!("<div class=\"err\">{}</div>", esc(error))
            },
            html("realmChooser.explain"),
            esc(&action),
            html("realmChooser.realm"),
            control,
            html("realmChooser.continue")
        );
        let style = concat!(
            ":root{--bg:#f4f4f7;--card:#fff;--ink:#1f2330;--muted:#5b6070;",
            "--line:#d5d5dd;--accent:#4b3fa7;--accent-ink:#fff;--err:#a3242c;",
            "--err-bg:#fbeaea}",
            "@media (prefers-color-scheme:dark){:root{--bg:#15161b;",
            "--card:#1f2129;--ink:#e8e9ee;--muted:#a3a7b5;--line:#3a3d4a;",
            "--accent:#8f84f0;--accent-ink:#15161b;--err:#ff9ca2;",
            "--err-bg:#3a1d20}}",
            "*{box-sizing:border-box}",
            "body{margin:0;min-height:100vh;display:flex;align-items:center;",
            "justify-content:center;background:var(--bg);color:var(--ink);",
            "font-family:system-ui,-apple-system,\"Segoe UI\",Arial,",
            "sans-serif;padding:16px}",
            ".chooser{background:var(--card);border:1px solid var(--line);",
            "border-radius:14px;padding:36px 40px;width:100%;max-width:34rem;",
            "box-shadow:0 8px 32px rgba(0,0,0,.08);text-align:center}",
            ".chooser h1{font-size:1.7rem;margin:0 0 .4em}",
            ".chooser .lead{font-size:1.1rem;margin:0 0 1.4em;",
            "color:var(--muted)}",
            ".chooser form p{display:flex;flex-direction:column;gap:14px;",
            "margin:1.2em 0}",
            ".chooser label{font-weight:600;font-size:1.05rem}",
            ".chooser select,.chooser input{font-size:1.35rem;",
            "padding:.6em .7em;",
            "border:2px solid var(--accent);border-radius:10px;width:100%;",
            "background:var(--card);color:var(--ink)}",
            ".chooser button{font-size:1.25rem;padding:.7em 1em;border:0;",
            "border-radius:10px;background:var(--accent);",
            "color:var(--accent-ink);",
            "cursor:pointer;width:100%}",
            ".chooser button:focus-visible,.chooser select:focus-visible,",
            ".chooser input:focus-visible{outline:3px solid var(--accent);",
            "outline-offset:3px}",
            ".chooser .note,.chooser>p{color:var(--muted);font-size:.95rem}",
            ".chooser .err{background:var(--err-bg);color:var(--err);",
            "border-radius:8px;padding:.7em 1em;margin:0 0 1em;",
            "text-align:left}",
            ".chooser details.language-row{display:inline-block;",
            "font-size:.85rem;color:var(--muted);margin:0 0 1em}",
        );
        let style = format!(
            "{style}{}{}",
            error_page::ROW_CSS,
            concat!(
                ".chooser form.language-chooser select,",
                ".chooser form.language-chooser button{font-size:.85rem;",
                "width:auto;",
                "padding:.2em .5em;border-width:1px;border-radius:6px}",
                ".chooser form.language-chooser button{",
                "background:var(--card);",
                "color:var(--ink);border:1px solid var(--line)}",
            )
        );
        format!(
            "<!DOCTYPE html><html{}><head><meta charset=\"utf-8\"><meta \
             name=\"viewport\" content=\"width=device-width, \
             initial-scale=1\"><title>{}</title><style>{}</style></head>\
             <body><main class=\"chooser\">{}<h1>{}</h1><p class=\"lead\">{}\
             </p>{}</main></body></html>",
            error_page::html_attributes(&t),
            esc(&select(
                &error_page::text(&t, "realmChooser.title", &[]),
                "surface",
                surface.which
            )),
            style,
            error_page::chooser(&t, &self.surfaces.catalogs, surface.root),
            html("realmChooser.heading"),
            html("realmChooser.lead"),
            form
        )
    }
}

fn with_cookie(
    mut response: Response<axum::body::Body>,
    cookie: &str,
) -> Response<axum::body::Body> {
    if let Ok(v) = HeaderValue::from_str(cookie) {
        response.headers_mut().append(header::SET_COOKIE, v);
    }
    response
}

impl sts_http::surfaces::SurfaceGates for RealmChooser {
    fn before_shell(
        &self,
        surface: &str,
        ask: &Ask<'_>,
    ) -> Option<Response<axum::body::Body>> {
        match self.decide(surface, ask)? {
            Decision::Here { .. } => None,
            Decision::Redirect { location, cookie } => {
                let response = Response::builder()
                    .status(StatusCode::SEE_OTHER)
                    .header(header::LOCATION, location)
                    .header(header::CACHE_CONTROL, "no-store")
                    .body(axum::body::Body::empty())
                    .ok()?;
                Some(with_cookie(response, &cookie))
            }
            Decision::Page { error, cookie } => {
                let mut response = Response::builder()
                    .status(if error.is_empty() {
                        StatusCode::OK
                    } else {
                        StatusCode::BAD_REQUEST
                    })
                    .header(header::CACHE_CONTROL, "no-store")
                    .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
                    .body(axum::body::Body::from(
                        self.page(surface, ask, &error),
                    ))
                    .ok()?;
                if !error.is_empty() {
                    response = sts_http::mark(
                        response,
                        if surface == "portal" {
                            codes::STS_PORTAL_0074
                        } else {
                            codes::STS_ADMIN_0790
                        },
                    );
                }
                Some(match cookie {
                    Some(c) => with_cookie(response, &c),
                    None => response,
                })
            }
        }
    }

    fn shell_cookie(&self, surface: &str, ask: &Ask<'_>) -> Option<String> {
        match self.decide(surface, ask)? {
            Decision::Here { cookie } => Some(cookie),
            _ => None,
        }
    }

    fn callback_refused(&self, _: &str, _: &Ask<'_>) -> Option<String> {
        None
    }

    fn elsewhere(&self, _: &str, _: &Ask<'_>) -> (String, String, String) {
        Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_select_chooses_its_branch_and_falls_back_to_other() {
        let m = "Continue to {surface, select, portal {your account} report \
                 {reports} other {the admin console}}";
        assert_eq!(select(m, "surface", "portal"), "Continue to your account");
        assert_eq!(select(m, "surface", "report"), "Continue to reports");
        assert_eq!(
            select(m, "surface", "admin"),
            "Continue to the admin console"
        );
        assert_eq!(select("no argument", "surface", "admin"), "no argument");
    }

    #[test]
    fn encode_uri_component_is_javascripts() {
        assert_eq!(encode_uri_component("a b/c"), "a%20b%2Fc");
        assert_eq!(encode_uri_component("x-y_z.!~*'()"), "x-y_z.!~*'()");
    }
}
