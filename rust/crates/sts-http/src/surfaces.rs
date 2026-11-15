// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

//! The static surfaces' host: every surface of the root `CLAUDE.md`'s
//! *Pages with a script* table — its shell, its bundle, its stylesheet —
//! and `/web` (#446, #568, #570, #571–#580, #584, #956).
//!
//! Two kinds of thing are here, and the split is whose STATE a page needs:
//!
//! * **Answered here** ([`SurfaceHost`], an Express-matched [`Routes`]):
//!   the front door's shell (`/`), the console's (`/admin`, `/admin/*`),
//!   the portal's (`/portal`, `/portal/*`), the reports application's
//!   (`/report`, `/report/*`), every surface's script and stylesheet, the
//!   `/web` files, the realm's theme and logo, the icon, `/healthcheck`.
//!   The console's, the portal's and the reports application's realm
//!   chooser (a question asked only of a browser signed in nowhere, which
//!   needs the sign-on session) and the callback each registers on its
//!   OAuth client are [`SurfaceGates`], filled by the phases that port the
//!   session and `oidc_rp`; empty, they ask nothing and refuse nothing,
//!   which is the answer Node gives on a service with no realm defined.
//! * **Drawn here, routed by the family** ([`Shells`]): a shell whose route
//!   first decides something the family owns — the sign-in screen and its
//!   steps (a pending sign-in), consent (a pending consent), the sign-out
//!   (a session), GNAP's interaction pages (a grant), the federation pages
//!   and the description pages (their views), the SPNEGO exchange (RFC
//!   4559's statuses). The family calls the builder with what it decided.
//!
//! **THE BUNDLES ARE THE TYPESCRIPT BUILD'S OUTPUT**, read from the tree
//! [`files::WebRoot`] names — `/usr/src/sts` in the image, the same files
//! the Node runtime serves, with their `.br` and `.gz`.

use std::sync::{Arc, OnceLock, RwLock};

use axum::body::Bytes;
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::Response;
use serde_json::Value as Json;
use sts_core::errors::{codes, ErrorCode};
use sts_core::realm::RealmRegistry;

use crate::assets::PublicAssets;
use crate::branding::Branding;
use crate::files::{self, BuiltFile, WebRoot};
use crate::shell::{ServeOptions, ShellSpec, Surfaces};
use crate::{Ask, Routes};

/// Express 4's path matching (`path-to-regexp` 0.1): case-insensitive, an
/// optional trailing slash, `:name` one segment (decoded), `*` anything.
/// `Err` is a parameter that does not decode, which Express answers 400.
#[tracing::instrument(level = "trace")]
pub fn express_match(
    pattern: &str,
    path: &str,
) -> Option<Result<Vec<String>, ()>> {
    let lower_path = path.to_ascii_lowercase();
    let path = path
        .strip_suffix('/')
        .filter(|p| !p.is_empty())
        .unwrap_or(path);
    let lower = lower_path
        .strip_suffix('/')
        .filter(|p| !p.is_empty())
        .unwrap_or(&lower_path);
    if let Some(base) = pattern.strip_suffix("/*") {
        let base_l = base.to_ascii_lowercase();
        let full = lower_path.as_str();
        return full
            .strip_prefix(&base_l)
            .filter(|rest| rest.starts_with('/'))
            .map(|_| Ok(Vec::new()));
    }
    if !pattern.contains(':') {
        return (lower == pattern.to_ascii_lowercase()).then(|| Ok(Vec::new()));
    }
    let want: Vec<&str> = pattern.split('/').collect();
    let have: Vec<&str> = path.split('/').collect();
    if want.len() != have.len() {
        return None;
    }
    let mut params = Vec::new();
    for (w, h) in want.iter().zip(have.iter()) {
        if let Some(_name) = w.strip_prefix(':') {
            if h.is_empty() {
                return None;
            }
            params.push(*h);
        } else if !w.eq_ignore_ascii_case(h) {
            return None;
        }
    }
    let mut decoded = Vec::new();
    for p in params {
        match crate::cors::percent_decode_strict(p) {
            Some(d) => decoded.push(d),
            None => return Some(Err(())),
        }
    }
    Some(Ok(decoded))
}

/// What a surface asks the phases that own the session and the OAuth
/// client before it draws its shell.
pub trait SurfaceGates: Send + Sync {
    /// The realm chooser's answer for `surface` (`admin`, `portal`,
    /// `report`) — a redirect or its page — or `None` to draw the shell.
    fn before_shell(&self, surface: &str, ask: &Ask<'_>) -> Option<Response>;
    /// The `Set-Cookie` the shell is drawn with when the chooser answered
    /// "here" (`writeCookie()` of a decision of the default realm), or
    /// `None`.
    fn shell_cookie(&self, surface: &str, ask: &Ask<'_>) -> Option<String> {
        let _ = (surface, ask);
        None
    }
    /// Why the surface's callback cannot be registered here, or `None`.
    fn callback_refused(&self, surface: &str, ask: &Ask<'_>) -> Option<String>;
    /// `(oauth, api, authn)`: the bases of the applications on other
    /// listeners (#472), each '' where this listener answers it.
    fn elsewhere(
        &self,
        surface: &str,
        ask: &Ask<'_>,
    ) -> (String, String, String);
}

/// Nothing to ask: no realm chooser, every callback registered, one
/// listener.
pub struct NoGates;

impl SurfaceGates for NoGates {
    fn before_shell(&self, _: &str, _: &Ask<'_>) -> Option<Response> {
        None
    }
    fn callback_refused(&self, _: &str, _: &Ask<'_>) -> Option<String> {
        None
    }
    fn elsewhere(&self, _: &str, _: &Ask<'_>) -> (String, String, String) {
        Default::default()
    }
}

/// `WebKit.warn()` with a label: a fold.
fn warn_fold(html: &str, label: &str) -> String {
    format!(
        "<details class=\"warn fold\"><summary>{}</summary><div \
         class=\"foldbody\">{}</div></details>",
        crate::escape_html(label),
        html
    )
}

/// The shells' builders, over what every shell is drawn with.
pub struct Shells {
    pub surfaces: Arc<Surfaces>,
    pub registry: Arc<RealmRegistry>,
    /// `mode.hidesStepIds()`.
    pub hides_step_ids: bool,
}

const LOADING: &str = "<p class=\"sub\">Loading&hellip;</p>";

impl Shells {
    fn prefix(&self) -> String {
        self.registry.current_prefix()
    }

    /// The front door's shell (`Home.shellDocument()`).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn home(&self, request: &HeaderMap, authn_at: &str) -> String {
        let mut attributes = vec![
            ("data-sts-prefix".to_string(), self.prefix()),
            ("data-sts-authn".to_string(), authn_at.to_string()),
        ];
        attributes.extend(self.surfaces.locale_attributes(request, "", ""));
        let docs = "https://rcbj.github.io/iya-sts/";
        self.surfaces.document(
            request,
            &ShellSpec {
                title: "IYA STS".into(),
                attributes,
                stylesheets: vec!["/web/card.css".into(), "/home.css".into()],
                script: "/home.js".into(),
                open:
                    "<div class=\"card\"><div class=\"body\"><h1>IYA STS</h1>"
                        .into(),
                close: "</div></div>".into(),
                noscript: format!(
                "<div class=\"warn\">This front page is a script that runs in \
                 your browser and draws itself from <code>/home-api</code>; \
                 with scripts blocked there is nothing it can show. The \
                 documentation is at <a href=\"{0}\">{0}</a>.</div>",
                docs
            ),
                loading: LOADING.into(),
                footer: true,
                ..ShellSpec::default()
            },
        )
    }

    /// The console's shell (`AdminConsole.shellDocument()`).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn console(
        &self,
        request: &HeaderMap,
        refused: Option<&str>,
        elsewhere: &(String, String, String),
    ) -> String {
        let esc_apos =
            |v: &str| crate::escape_html(v).replace("&#39;", "&apos;");
        self.surfaces.document(request, &ShellSpec {
            title: "IYA STS admin".into(),
            attributes: vec![
                ("data-sts-oauth".into(), elsewhere.0.clone()),
                ("data-sts-api".into(), elsewhere.1.clone()),
                ("data-sts-authn".into(), elsewhere.2.clone()),
            ],
            stylesheets: vec!["/admin/console.css".into()],
            script: "/admin/console.js".into(),
            open: "<div class=\"shell\"><div class=\"main\"><div class=\"card\"><h1>IYA STS admin</h1>"
                .into(),
            close: "</div></div></div>".into(),
            refusal: refused.map(|why| {
                let why = if why.is_empty() {
                    "This console cannot sign in at this address."
                } else {
                    why
                };
                warn_fold(&esc_apos(why), "This console cannot sign in here")
            }),
            noscript: warn_fold(
                "This console is a script that runs in your browser and draws \
                 every page from <code>/admin-api</code>; with scripts blocked \
                 there is nothing it can show.",
                "Scripts are blocked",
            ),
            loading: "<p class=\"lede\">Signing in&hellip;</p>".into(),
            apos: true,
            footer: true,
            ..ShellSpec::default()
        })
    }

    /// The portal's shell (`Portal.shellDocument()`).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn portal(
        &self,
        request: &HeaderMap,
        refused: Option<&str>,
        elsewhere: &(String, String, String),
    ) -> String {
        self.surfaces.document(request, &ShellSpec {
            title: "Your account — IYA STS".into(),
            attributes: vec![
                ("data-sts-oauth".into(), elsewhere.0.clone()),
                ("data-sts-api".into(), elsewhere.1.clone()),
                ("data-sts-authn".into(), elsewhere.2.clone()),
            ],
            viewport: Some("width=device-width,initial-scale=1".into()),
            stylesheets: vec!["/portal/portal.css".into()],
            branded: Some(true),
            script: "/portal/portal.js".into(),
            open: "<div class=\"wrap\"><div class=\"card\"><h1>Your account</h1>".into(),
            close: "</div></div>".into(),
            refusal: refused.map(|why| {
                let why = if why.is_empty() {
                    "The portal cannot sign in at this address."
                } else {
                    why
                };
                format!("<div class=\"err\">{}</div>", crate::escape_html(why))
            }),
            noscript: "<div class=\"err\">This portal is a script that runs in \
                       your browser and draws every page from \
                       <code>/account-api</code>; with scripts blocked there is \
                       nothing it can show.</div>"
                .into(),
            loading: LOADING.into(),
            footer: true,
            ..ShellSpec::default()
        })
    }

    /// The reports application's shell (`ReportApp.shellDocument()`).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn report(
        &self,
        request: &HeaderMap,
        refused: Option<&str>,
        elsewhere: &(String, String, String),
    ) -> String {
        self.surfaces.document(
            request,
            &ShellSpec {
                title: "Reports — IYA STS".into(),
                attributes: vec![
                    ("data-sts-oauth".into(), elsewhere.0.clone()),
                    ("data-sts-api".into(), elsewhere.1.clone()),
                    ("data-sts-authn".into(), elsewhere.2.clone()),
                ],
                viewport: Some("width=device-width,initial-scale=1".into()),
                stylesheets: vec!["/report/report.css".into()],
                script: "/report/report.js".into(),
                open: "<div class=\"wrap\"><main class=\"card\" id=\"report\">"
                    .into(),
                close: "</main></div>".into(),
                refusal: refused.map(|why| {
                    let why = if why.is_empty() {
                        "Reports cannot sign in at this address."
                    } else {
                        why
                    };
                    format!("<p class=\"err\">{}</p>", crate::escape_html(why))
                }),
                noscript: "<p class=\"err\">This page needs its script.</p>"
                    .into(),
                loading: LOADING.into(),
                footer: true,
                ..ShellSpec::default()
            },
        )
    }

    /// The sign-in surface's shell (`Authn.signInShell()`): the screen and
    /// every step after it, the wallet's pages. The family sends it with
    /// [`Shells::signin_options`].
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn signin(
        &self,
        request: &HeaderMap,
        application: &str,
        person: &str,
    ) -> String {
        let mut attributes = vec![
            ("data-sts-prefix".to_string(), self.prefix()),
            (
                "data-sts-step-fragment".to_string(),
                if self.hides_step_ids {
                    "1".into()
                } else {
                    String::new()
                },
            ),
        ];
        attributes.extend(self.surfaces.locale_attributes(
            request,
            application,
            person,
        ));
        self.surfaces.document(
            request,
            &ShellSpec {
                title: "Sign in — IYA STS".into(),
                attributes,
                stylesheets: vec!["/web/card.css".into()],
                script: "/authn/signin.js".into(),
                open: "<div class=\"card\">".into(),
                close: "</div>".into(),
                noscript:
                    "<h1>Sign in</h1><div class=\"err\">This sign-in page is a \
                       script that runs in your browser, and with scripts \
                       blocked there is nothing it can show. Allow scripts for \
                       this page to sign in.</div>"
                        .into(),
                loading: LOADING.into(),
                footer: true,
                ..ShellSpec::default()
            },
        )
    }

    /// How the sign-in shell is sent: the client's logo origin in
    /// `img-src` (#1300).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn signin_options(logo_origin: Option<&str>) -> ServeOptions {
        ServeOptions {
            csp: vec![("style-src".into(), Some("'self'".into()))],
            images: logo_origin
                .map(|o| vec![o.to_string()])
                .unwrap_or_default(),
            ..ServeOptions::default()
        }
    }

    /// The consent screen's shell (`ConsentScreen.shell()`).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn consent(
        &self,
        request: &HeaderMap,
        authn_at: &str,
        client_id: &str,
        username: &str,
    ) -> String {
        let mut attributes = vec![
            ("data-sts-prefix".to_string(), self.prefix()),
            ("data-sts-authn".to_string(), authn_at.to_string()),
            (
                "data-sts-step-fragment".to_string(),
                if self.hides_step_ids {
                    "1".into()
                } else {
                    String::new()
                },
            ),
        ];
        attributes.extend(
            self.surfaces
                .locale_attributes(request, client_id, username),
        );
        self.surfaces.document(request, &ShellSpec {
            title: "Allow access? — IYA STS".into(),
            attributes,
            stylesheets: vec!["/web/card.css".into()],
            script: "/oauth2/consent.js".into(),
            open: "<div class=\"card consent\">".into(),
            close: "</div>".into(),
            noscript: "<h1>Allow access?</h1><div class=\"err\">This consent page \
                       is a script that runs in your browser, and with scripts \
                       blocked there is nothing it can show. Allow scripts for \
                       this page to answer it.</div>"
                .into(),
            loading: LOADING.into(),
            footer: true,
            ..ShellSpec::default()
        })
    }

    /// The sign-out's shell (`Logout.shell()`).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn signout(&self, request: &HeaderMap, person: &str) -> String {
        let mut attributes =
            vec![("data-sts-prefix".to_string(), self.prefix())];
        attributes.extend(self.surfaces.locale_attributes(request, "", person));
        self.surfaces.document(request, &ShellSpec {
            title: "Sign out".into(),
            attributes,
            stylesheets: vec!["/logout/signout.css".into()],
            branded: Some(true),
            script: "/logout/signout.js".into(),
            noscript: "<h1>Sign out</h1><div class=\"err\">This sign-out page is a \
                       script that runs in your browser, and with scripts blocked \
                       there is nothing it can show. Allow scripts for this page \
                       to see what you are still signed into and to sign \
                       out.</div>"
                .into(),
            loading: LOADING.into(),
            footer: true,
            ..ShellSpec::default()
        })
    }

    /// A page carrying its view in `data-sts-state`: GNAP's interaction
    /// pages, the federation pages, a description page.
    fn with_state(
        &self,
        request: &HeaderMap,
        authn_at: &str,
        state: &Json,
        application: &str,
        person: &str,
    ) -> Vec<(String, String)> {
        let mut attributes = vec![
            ("data-sts-prefix".to_string(), self.prefix()),
            ("data-sts-authn".to_string(), authn_at.to_string()),
            ("data-sts-state".to_string(), state.to_string()),
        ];
        attributes.extend(self.surfaces.locale_attributes(
            request,
            application,
            person,
        ));
        attributes
    }

    /// GNAP's interaction shell (`GnapInteract.sendShell()`); `state` is
    /// `{ view, preferredLanguage? }`, or `Json::Null` for a page that
    /// fetches its view.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn gnap(
        &self,
        request: &HeaderMap,
        authn_at: &str,
        state: &Json,
        application: &str,
        person: &str,
    ) -> String {
        let mut attributes =
            self.with_state(request, authn_at, state, application, person);
        if state.is_null() {
            attributes[2].1 = String::new();
        }
        self.surfaces.document(request, &ShellSpec {
            title: "GNAP authorization server — IYA STS".into(),
            attributes,
            stylesheets: vec!["/web/card.css".into()],
            script: "/gnap/interaction.js".into(),
            open: "<div class=\"card gnap\">".into(),
            close: "</div>".into(),
            noscript: "<h1>GNAP authorization</h1><div class=\"err\">This page is a \
                       script that runs in your browser, and with scripts blocked \
                       there is nothing it can show. Allow scripts for this page \
                       to answer the application that sent you here.</div>"
                .into(),
            loading: LOADING.into(),
            footer: true,
            ..ShellSpec::default()
        })
    }

    /// The federation pages' shell (`FederationPages.send()`).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn federation(
        &self,
        request: &HeaderMap,
        authn_at: &str,
        state: &Json,
        application: &str,
        person: &str,
    ) -> String {
        self.surfaces.document(request, &ShellSpec {
            title: "Federation — IYA STS".into(),
            attributes: self.with_state(request, authn_at, state, application, person),
            stylesheets: vec!["/web/card.css".into()],
            script: "/federation/pages.js".into(),
            open: "<div class=\"card wide\">".into(),
            close: "</div>".into(),
            noscript: "<h1>Federation</h1><div class=\"err\">This page is a script \
                       that runs in your browser, and with scripts blocked there \
                       is nothing it can show. Allow scripts for this page.</div>"
                .into(),
            loading: LOADING.into(),
            footer: true,
            ..ShellSpec::default()
        })
    }

    /// A protocol family's description page (`DescriptionPages.send()`):
    /// `base` its path (`/saml2`), `title` until the script draws it.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn description(
        &self,
        request: &HeaderMap,
        authn_at: &str,
        base: &str,
        title: &str,
        view: &Json,
    ) -> String {
        let state = serde_json::json!({ "view": view });
        self.surfaces.document(
            request,
            &ShellSpec {
                title: title.into(),
                attributes: self.with_state(request, authn_at, &state, "", ""),
                stylesheets: vec!["/web/card.css".into()],
                script: format!("{}/description.js", base),
                open: "<div class=\"card wide describe\">".into(),
                close: "</div>".into(),
                noscript: format!(
                "<h1>{}</h1><div class=\"err\">This page is a script that runs \
                 in your browser, and with scripts blocked there is nothing it \
                 can show. Allow scripts for this page, or add \
                 <code>?format=json</code> for the same description as \
                 data.</div>",
                crate::escape_html(title).replace("&#39;", "&apos;")
            ),
                loading: LOADING.into(),
                footer: true,
                ..ShellSpec::default()
            },
        )
    }

    /// The SPNEGO exchange's shell (`SpnegoAuthn.sendShell()`): no footer,
    /// since every answer it carries is RFC 4559's.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn spnego(
        &self,
        request: &HeaderMap,
        state: &Json,
        application: &str,
        person: &str,
    ) -> String {
        let mut attributes = vec![
            ("data-sts-prefix".to_string(), self.prefix()),
            ("data-sts-state".to_string(), state.to_string()),
        ];
        attributes.extend(self.surfaces.locale_attributes(
            request,
            application,
            person,
        ));
        self.surfaces.document(request, &ShellSpec {
            title: "Sign in with Kerberos — IYA STS".into(),
            attributes,
            stylesheets: vec!["/web/card.css".into()],
            script: "/authn/signin.js".into(),
            open: "<div class=\"card wide\">".into(),
            close: "</div>".into(),
            noscript: "<h1>Sign in with Kerberos</h1><div class=\"err\">This page is \
                       a script that runs in your browser, and with scripts \
                       blocked there is nothing it can show. Allow scripts for \
                       this page.</div>"
                .into(),
            loading: LOADING.into(),
            footer: false,
            ..ShellSpec::default()
        })
    }

    /// The options every page drawn with its state is sent with:
    /// `style-src 'self'` and the sign-in origin.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn card_options(authn_at: &str) -> ServeOptions {
        ServeOptions {
            connect: crate::shell::origins_of(&[authn_at]),
            csp: vec![("style-src".into(), Some("'self'".into()))],
            ..ServeOptions::default()
        }
    }
}

/// One surface's bundle: its address, its directory and file, and the
/// placeholder a tree that was never built serves.
struct Bundle {
    path: &'static str,
    dir: &'static str,
    file: &'static str,
    placeholder: &'static str,
    cell: OnceLock<BuiltFile>,
}

const fn bundle(
    path: &'static str,
    dir: &'static str,
    file: &'static str,
    placeholder: &'static str,
) -> Bundle {
    Bundle {
        path,
        dir,
        file,
        placeholder,
        cell: OnceLock::new(),
    }
}

/// The families whose description page loads `<family>/description.js`.
// `/xacml/description.js` is not here: everything under `/xacml` is behind
// the XACML family's client-certificate gate, which that family's phase
// ports with the route.
const DESCRIBED: &[&str] = &["saml2", "saml11", "ssf", "scim", "spiffe"];

/// The surfaces' stylesheets, held to Node's bytes by the harness.
const STYLESHEETS: &[(&str, &str)] = &[
    ("/home.css", include_str!("../assets/home.css")),
    (
        "/admin/console.css",
        include_str!("../assets/admin_console.css"),
    ),
    (
        "/portal/portal.css",
        include_str!("../assets/portal_portal.css"),
    ),
    (
        "/report/report.css",
        include_str!("../assets/report_report.css"),
    ),
    (
        "/logout/signout.css",
        include_str!("../assets/logout_signout.css"),
    ),
];

/// The static surfaces' host.
pub struct SurfaceHost {
    shells: Shells,
    assets: PublicAssets,
    branding: Arc<Branding>,
    root: WebRoot,
    bundles: Vec<Bundle>,
    gates: RwLock<Arc<dyn SurfaceGates>>,
}

/// The not-a-form refusal a static application answers a POST with.
fn not_posted(text: &str, code: ErrorCode) -> Response {
    let mut r = crate::text(text);
    *r.status_mut() = StatusCode::NOT_FOUND;
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    crate::mark(r, code)
}

impl SurfaceHost {
    /// The host over the shells, the catalogs, the appearance and the
    /// tree the bundles are read from.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn new(shells: Shells, root: WebRoot) -> Arc<SurfaceHost> {
        let assets = PublicAssets::new(
            shells.surfaces.catalogs.clone(),
            &shells.surfaces.version,
            &root,
        );
        let branding = shells.surfaces.branding.clone();
        let placeholder = |what: &'static str| what;
        Arc::new(SurfaceHost {
            shells,
            assets,
            branding,
            root,
            bundles: vec![
                bundle("/home.js", "home", "home-spa.js", placeholder(
                    "document.body.textContent = \"This service has no front page script (home/home-spa.js): it was not built by build-typescript.sh.\";")),
                bundle("/admin/console.js", "admin-ui", "console.js", placeholder(
                    "document.body.textContent = \"This build of the service has no console script (admin-ui/console.js).\";")),
                bundle("/portal/portal.js", "portal", "portal-spa.js", placeholder(
                    "document.body.textContent = \"This service has no portal script (portal/portal-spa.js): it was not built by build-typescript.sh.\";")),
                bundle("/report/report.js", "report", "report-spa.js", placeholder(
                    "document.body.textContent = \"This service has no report script (report/report-spa.js): it was not built by build-typescript.sh.\";")),
                bundle("/authn/signin.js", "authn", "authn-spa.js", placeholder(
                    "document.body.textContent = \"This service has no sign-in script (authn/authn-spa.js): it was not built by build-typescript.sh.\";")),
                bundle("/oauth2/consent.js", "authn", "authn-spa.js", placeholder(
                    "document.body.textContent = \"This service has no sign-in script (authn/authn-spa.js): it was not built by build-typescript.sh.\";")),
                bundle("/logout/signout.js", "logout", "signout-spa.js", placeholder(
                    "document.body.textContent = \"This service has no sign-out script (logout/signout-spa.js): it was not built by build-typescript.sh.\";")),
                bundle("/gnap/interaction.js", "gnap", "gnap-interaction-spa.js", placeholder(
                    "document.body.textContent = \"This service has no GNAP interaction script (gnap/gnap-interaction-spa.js): it was not built by build-typescript.sh.\";")),
                bundle("/federation/pages.js", "federation", "federation-pages-spa.js", placeholder(
                    "document.body.textContent = \"This service has no federation pages script (federation/federation-pages-spa.js): it was not built by build-typescript.sh.\";")),
                bundle("/description.js", "common", "description-pages-spa.js", placeholder(
                    "document.body.textContent = \"This service has no description pages script (common/description-pages-spa.js): it was not built by build-typescript.sh.\";")),
            ],
            gates: RwLock::new(Arc::new(NoGates)),
        })
    }

    /// The host as the composition root builds it: the catalogs and the
    /// version read from the tree, the appearance over the settings.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn build(
        settings: Arc<sts_core::settings::Settings>,
        mode: Arc<sts_core::mode::Mode>,
        registry: Arc<RealmRegistry>,
        root: WebRoot,
    ) -> Arc<SurfaceHost> {
        let catalogs = Arc::new(crate::i18n::Catalogs::load(
            &crate::i18n::Catalogs::dir_in(&root.0),
        ));
        let version = sts_core::version::load(&root.0);
        let branding = Branding::new(Some(settings.clone()));
        let surfaces = Arc::new(Surfaces {
            settings: Some(settings),
            catalogs,
            version,
            branding,
            locales: Arc::new(crate::shell::EnglishDefault),
        });
        let shells = Shells {
            surfaces,
            registry,
            hides_step_ids: mode.hides_step_ids(),
        };
        SurfaceHost::new(shells, root)
    }

    /// Fills the gates (the realm chooser, the callbacks, the listeners).
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn set_gates(&self, gates: Arc<dyn SurfaceGates>) {
        if let Ok(mut slot) = self.gates.write() {
            *slot = gates;
        }
    }

    /// The shells' builders, for the families that route their own.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn shells(&self) -> &Shells {
        &self.shells
    }

    fn gates(&self) -> Arc<dyn SurfaceGates> {
        self.gates
            .read()
            .map(|g| g.clone())
            .unwrap_or_else(|_| Arc::new(NoGates))
    }

    fn built(&self, b: &Bundle) -> BuiltFile {
        b.cell
            .get_or_init(|| {
                files::read_file(&self.root.join(b.dir), b.file, b.placeholder)
            })
            .clone()
    }

    /// `GET /healthcheck`.
    fn healthcheck() -> Response {
        crate::typed_text("application/json", "{\"message\":\"Success\"}")
    }

    /// One of the console's, the portal's or the reports application's
    /// paths: the refusal for a method that is not GET, the chooser, the
    /// shell.
    fn application_shell(&self, surface: &str, ask: &Ask<'_>) -> Response {
        let get = *ask.method == Method::GET || *ask.method == Method::HEAD;
        if !get {
            return match surface {
                "admin" => not_posted(
                    "The admin console is a static application: what it does is \
                     done through /admin-api, and nothing is posted here.",
                    codes::STS_ADMIN_0843,
                ),
                "portal" => not_posted(
                    "The user portal is a static application: what it does is \
                     done through /account-api, and nothing is posted here.",
                    codes::STS_PORTAL_0246,
                ),
                _ => not_posted(
                    "The report application is a static page. Nothing is posted \
                     here.",
                    codes::STS_REPORT_0033,
                ),
            };
        }
        let gates = self.gates();
        if let Some(answer) = gates.before_shell(surface, ask) {
            return answer;
        }
        let cookie = gates.shell_cookie(surface, ask);
        let refused = gates.callback_refused(surface, ask);
        let elsewhere = gates.elsewhere(surface, ask);
        let (html, options) = match surface {
            "admin" => (
                self.shells.console(
                    ask.headers,
                    refused.as_deref(),
                    &elsewhere,
                ),
                ServeOptions {
                    connect: crate::shell::origins_of(&[
                        &elsewhere.0,
                        &elsewhere.1,
                    ]),
                    compress: true,
                    prefix: self.shells.registry.current_prefix(),
                    isolated: true,
                    ..ServeOptions::default()
                },
            ),
            "portal" => (
                self.shells
                    .portal(ask.headers, refused.as_deref(), &elsewhere),
                ServeOptions {
                    connect: crate::shell::origins_of(&[
                        &elsewhere.0,
                        &elsewhere.1,
                    ]),
                    csp: vec![("img-src".into(), Some("'self' data:".into()))],
                    isolated: true,
                    ..ServeOptions::default()
                },
            ),
            _ => (
                self.shells
                    .report(ask.headers, refused.as_deref(), &elsewhere),
                ServeOptions {
                    connect: crate::shell::origins_of(&[
                        &elsewhere.0,
                        &elsewhere.2,
                    ]),
                    csp: vec![("style-src".into(), Some("'self'".into()))],
                    isolated: true,
                    ..ServeOptions::default()
                },
            ),
        };
        let mut response = crate::shell::serve(ask.headers, html, &options);
        if let Some(v) = cookie.and_then(|c| HeaderValue::from_str(&c).ok()) {
            response.headers_mut().append(header::SET_COOKIE, v);
        }
        response
    }

    /// A surface's stylesheet: `no-cache`; the console's compressed by
    /// the request's Accept-Encoding (`sendConsoleFile()`), the others
    /// sent as they are.
    fn stylesheet(&self, request: &HeaderMap, path: &str) -> Option<Response> {
        let (_, css) = STYLESHEETS.iter().find(|(p, _)| *p == path)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-cache"),
        );
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/css; charset=utf-8"),
        );
        let body = Bytes::from_static(css.as_bytes());
        if path == "/admin/console.css" {
            return Some(files::send_compressed(
                request, headers, body, true, None, None,
            ));
        }
        Some(crate::express::send(StatusCode::OK, headers, body, true))
    }
}

impl Routes for SurfaceHost {
    fn answer(&self, ask: &Ask<'_>) -> Option<Response> {
        let get = *ask.method == Method::GET || *ask.method == Method::HEAD;
        let path = ask.path;
        let m = |pattern: &str| express_match(pattern, path);
        if get {
            if m("/healthcheck").is_some() {
                return Some(SurfaceHost::healthcheck());
            }
            if m("/").is_some() {
                let html = self.shells.home(ask.headers, "");
                return Some(crate::shell::serve(
                    ask.headers,
                    html,
                    &ServeOptions {
                        csp: vec![("style-src".into(), Some("'self'".into()))],
                        ..ServeOptions::default()
                    },
                ));
            }
            if m("/favicon.ico").is_some() {
                return Some(self.assets.favicon());
            }
            if m("/web/card.css").is_some() {
                return Some(self.assets.card(ask.headers, ask.query));
            }
            if m("/web/footer.css").is_some() {
                return Some(self.assets.footer(ask.headers, ask.query));
            }
            if m("/web/theme.css").is_some() {
                return Some(self.branding.theme_css(ask.headers, ask.query));
            }
            if m("/web/branding/logo").is_some() {
                return Some(
                    self.branding.logo_response(ask.headers, ask.query),
                );
            }
            if m("/web/locales/catalogs.json").is_some() {
                return Some(
                    self.assets.index_response(ask.headers, ask.query),
                );
            }
            if let Some(found) = m("/web/locales/:ns/:file") {
                return Some(match found {
                    Ok(p) => self.assets.catalog_response(
                        ask.headers,
                        ask.query,
                        &p[0],
                        &p[1],
                    ),
                    Err(()) => {
                        // Express raises a parameter that does not decode
                        // as the router matches, before the CORS step.
                        let mut r = crate::express::error_page(400);
                        r.extensions_mut().insert(crate::BeforeCors);
                        r
                    }
                });
            }
            for b in &self.bundles {
                if b.path == "/description.js" {
                    continue;
                }
                if m(b.path).is_some() {
                    if b.path == "/admin/console.js" {
                        let file = self.built(b);
                        let mut headers = HeaderMap::new();
                        headers.insert(
                            header::CACHE_CONTROL,
                            HeaderValue::from_static("no-cache"),
                        );
                        headers.insert(
                            header::CONTENT_TYPE,
                            HeaderValue::from_static(
                                "application/javascript; charset=utf-8",
                            ),
                        );
                        return Some(files::send_compressed(
                            ask.headers,
                            headers,
                            file.raw.clone(),
                            true,
                            Some(&file),
                            None,
                        ));
                    }
                    return Some(files::send_file(
                        ask.headers,
                        &self.built(b),
                        "application/javascript",
                    ));
                }
            }
            for family in DESCRIBED {
                if m(&format!("/{}/description.js", family)).is_some() {
                    let b = self
                        .bundles
                        .iter()
                        .find(|b| b.path == "/description.js")?;
                    return Some(files::send_file(
                        ask.headers,
                        &self.built(b),
                        "application/javascript",
                    ));
                }
            }
            for (sheet, _) in STYLESHEETS {
                if m(sheet).is_some() {
                    return self.stylesheet(ask.headers, sheet);
                }
            }
        }
        // The applications' documents, on every method a form could send.
        // What another family registers ABOVE them is not theirs: the
        // console's and the portal's and the reports application's Shared
        // Signals receivers, and the console's API explorer script.
        let ssf = *ask.method == Method::POST
            && [
                "/admin/signals/receive",
                "/portal/signals/receive",
                "/report/signals/receive",
            ]
            .iter()
            .any(|p| m(p).is_some());
        let explorer = *ask.method == Method::GET
            && path == "/admin/api-explorer/explorer.js";
        let methods = [
            Method::GET,
            Method::HEAD,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
        ];
        if ssf || explorer || !methods.contains(ask.method) {
            return None;
        }
        for surface in ["admin", "portal", "report"] {
            let base = format!("/{}", surface);
            if m(&base).is_some() || m(&format!("{}/*", base)).is_some() {
                return Some(self.application_shell(surface, ask));
            }
        }
        None
    }
}
