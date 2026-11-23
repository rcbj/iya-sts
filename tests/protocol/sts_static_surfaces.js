// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_static_surfaces.js
//
// ---------------------------------------------------------------------------
// THE STATIC PUBLIC SURFACES AND WHAT THEY STAND ON, OVER THE WIRE.
//
// D12 (#444): carries over the wire-visible half of, in a development and a
// product realm this job creates and leaves behind,
//
//   * `tests/home_static_surface.js` (#579): `GET /` is the shell — no-store,
//     the card, the home stylesheet and the deferred bundle under the
//     realm's prefix, the `<noscript>`, a policy that runs 'self' and keeps
//     `frame-ancestors` — the bundle served precompressed, and
//     `/home-api` listing its view's operation as the door of `GET /`, the
//     view naming this build's version, the mode's two facts as each realm
//     answers them, the logo and the six links;
//   * `tests/description_pages.js` (#584): `/xacml` and its script refused
//     alike with `xacml.enforceAccess` on and answering with it off; each
//     family's page the shell carrying a view of its kind; `?format=json`
//     and an `Accept` of JSON answering the document, `*/*` and
//     `?format=html` the shell; each `description.js` a script; no mock SP,
//     RP or embedded PEP in either mode; and the specification endpoints
//     beneath (`/saml2/ars`, `/saml11/responder`, the metadata, SCIM
//     discovery, the SSF configuration) unconverted;
//   * `tests/diagnostic_pages.js` (#597, #595): the TLS and SPNEGO
//     diagnostic pages answer as unrouted paths;
//   * `tests/page_footer.js`: every surface's shell carries exactly one
//     footer — the five links, the two icons, this year, the version and
//     its build line — and links `/web/footer.css`; the OP iframe carries
//     none; the error page carries one below its diagnostics, in French for
//     a French browser;
//   * `tests/web_foundation.js` section C: the index, a catalog file and the
//     card served compressed where asked, cached for good only under this
//     build's identifier, a 404 (STS-I18N-0012) for anything that is not
//     one, and the icon kept for a day;
//   * `tests/error_page_auto_redirect.js` (#317): the authorization error
//     page has its link and no timed continue by default; with
//     `oauth2.errorPageAutoRedirectS` set a meta refresh names its target and
//     the seconds and the page says so; the form_post variant never does.
//
// Its realms are left standing, as every job's are, unless
// STS_TEST_REMOVE_REALMS=1 asks for them to be removed at the end: a hand
// run against a private probe would otherwise fill its directory.
//
// OWNED HERE (local: true): this repository's own public pages.
// ---------------------------------------------------------------------------

const assert = require("assert");
const names = require("./random_username.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand run without one still loads.
  appconfigProblem = e;
  appconfig = {};
}
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_static_surfaces",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
function realmId(prefix) {
  log.debug("Entering realmId().");
  log.debug("Leaving realmId().");
  return (prefix + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                       .slice(0, 31);
}
const DEV = realmId("surfd-");
const PROD = realmId("surfp-");
const CLIENT = ("surf-rp-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "");
const REDIRECT = "https://rp.example/cb";
const FOOTER_LINKS = [
  "https://rcbj.github.io/iya-sts/v1.2.0/",
  "https://github.com/rcbj/iya-sts/issues",
  "https://github.com/rcbj/iya-sts",
  "https://www.linkedin.com/company/18811689/",
  "https://github.com/rcbj"
];
const FAMILIES = [
  { base: "/saml2", kind: "saml2", hadJson: false },
  { base: "/saml11", kind: "saml11", hadJson: false },
  { base: "/xacml", kind: "xacml", hadJson: true },
  { base: "/ssf", kind: "ssf", hadJson: true },
  { base: "/scim", kind: "scim", hadJson: true },
  { base: "/spiffe", kind: "spiffe", hadJson: true },
  { base: "/uma", kind: "uma", hadJson: true }
];

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

async function send(url, options) {
  log.debug("Entering send(). url=" + url);
  const r = await fetch(url, Object.assign({ redirect: "manual" },
                                           options || {}));
  const raw = await r.text();
  let body = null;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in send(): " + ((e && e.message) || e));
    // Not JSON — a page or a script; the caller reads `raw`.
    body = null;
  }
  log.debug("Leaving send(). status=" + r.status);
  return { status: r.status, headers: r.headers, body: body, raw: raw };
}

function get(realm, path, headers) {
  log.debug("Entering get().");
  log.debug("Leaving get().");
  return send(base + "/realm/" + realm + path, { headers: headers || {} });
}

async function ok(url, payload, what) {
  log.debug("Entering ok().");
  const r = await send(url, { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {}) });
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "POST " + url + " should have " + what + "; it answered " + r.status +
    " " + String(r.raw).slice(0, 400));
  log.debug("Leaving ok().");
  return r.body;
}

function setting(realm, key, value) {
  log.debug("Entering setting(). " + key);
  log.debug("Leaving setting().");
  return ok(base + "/realm/" + realm + "/admin-api/config/set",
            { key: key, value: value }, "set " + key);
}

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

async function codeCount(realm, code) {
  log.debug("Entering codeCount(). " + code);
  const r = await send(base + "/realm/" + realm + "/admin-api/audit?per=500" +
                       "&code=" + encodeURIComponent(code));
  const rows = (r.body && (r.body.events || r.body.rows)) || [];
  log.debug("Leaving codeCount(). " + rows.length);
  return rows.length;
}

function header(r, name) {
  log.debug("Entering header().");
  log.debug("Leaving header().");
  return String(r.headers.get(name) || "");
}

function unescape(raw) {
  log.debug("Entering unescape().");
  log.debug("Leaving unescape().");
  return String(raw).replace(/&quot;/g, "\"").replace(/&#39;/g, "'")
    .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
}

function stateOf(text) {
  log.debug("Entering stateOf().");
  const m = /<html[^>]* data-sts-state="([^"]*)"/.exec(String(text || ""));
  log.debug("Leaving stateOf().");
  return m ? JSON.parse(unescape(m[1])) : null;
}

function attr(text, name) {
  log.debug("Entering attr(). " + name);
  const m = new RegExp("<html[^>]* " + name + "=\"([^\"]*)\"")
    .exec(String(text || ""));
  log.debug("Leaving attr().");
  return m ? unescape(m[1]) : "";
}

function noStoreShell(r) {
  log.debug("Entering noStoreShell().");
  log.debug("Leaving noStoreShell().");
  return r.status === 200 && /no-store/.test(header(r, "cache-control")) &&
    /^text\/html/.test(header(r, "content-type")) &&
    r.headers.get("location") === null;
}

function scriptPolicy(r) {
  log.debug("Entering scriptPolicy().");
  const csp = header(r, "content-security-policy");
  log.debug("Leaving scriptPolicy().");
  return /frame-ancestors 'none'/.test(csp) &&
    /script-src 'self'(;|$)/.test(csp) && !/unsafe-inline/.test(csp);
}

async function sectionHome() {
  log.debug("Entering sectionHome().");
  log.info("=== 1. the front door is a static surface ===");
  const p = "/realm/" + DEV;
  const r = await get(DEV, "/");
  check("GET / answers the shell: no-store, the card, the home stylesheet " +
        "and the deferred bundle under the realm's prefix, the noscript, " +
        "and not the old server-drawn card", function () {
    assert.ok(noStoreShell(r), r.status + " " + header(r, "cache-control"));
    assert.ok(r.raw.indexOf("<link rel=\"stylesheet\" href=\"" + p +
                            "/web/card.css\">") > 0, "card");
    assert.ok(r.raw.indexOf("<link rel=\"stylesheet\" href=\"" + p +
                            "/home.css\">") > 0, "home.css");
    assert.ok(r.raw.indexOf("<script src=\"" + p + "/home.js\" defer>" +
                            "</script>") > 0, "home.js");
    assert.ok(r.raw.indexOf("<noscript>") > 0, "noscript");
    assert.strictEqual(attr(r.raw, "data-sts-prefix"), p);
    assert.ok(!/<a [^>]*href="\/admin"/.test(r.raw.split("<footer")[0]),
              "a server-drawn link");
  });
  check("its policy runs this service's own script and styles and keeps " +
        "frame-ancestors, with no inline style", function () {
    assert.ok(scriptPolicy(r), header(r, "content-security-policy"));
    assert.ok(/style-src 'self'(;|$)/.test(header(r,
              "content-security-policy")));
  });
  const fr = await get(DEV, "/", { Cookie: "sts_lang=FR" });
  check("the chooser's cookie is read back canonical", function () {
    assert.strictEqual(attr(fr.raw, "data-sts-lang"), "fr");
  });
  const js = await get(DEV, "/home.js", { "Accept-Encoding": "br" });
  const css = await get(DEV, "/home.css");
  check("the bundle is served precompressed, and the stylesheet", function () {
    assert.strictEqual(js.status, 200);
    assert.ok(/javascript/.test(header(js, "content-type")));
    assert.strictEqual(header(js, "content-encoding"), "br");
    assert.ok(js.raw.length > 0);
    assert.strictEqual(css.status, 200);
    assert.ok(/text\/css/.test(header(css, "content-type")));
  });
  const index = await get(DEV, "/home-api");
  check("the API index lists the view's operation as the door of GET /",
        function () {
    const front = (index.body.operations || []).filter(function (o) {
      return o.path === "/home-api/front";
    })[0];
    assert.ok(front && front.method === "GET" && front.mirrors === "GET /" &&
              front.access === "public", JSON.stringify(index.body));
  });
  const dev = await get(DEV, "/home-api/front");
  const prod = await get(PROD, "/home-api/front");
  const version = attr(r.raw, "data-sts-version");
  check("the view names this build's version and build line, the logo and " +
        "the six links by id", function () {
    const v = dev.body.view;
    assert.strictEqual(v.version, version);
    assert.ok(/^Build \d{14} — Built \d{4}-\d\d-\d\dT/.test(v.build),
              v.build);
    assert.deepStrictEqual(v.logo, { src: "/logo.png", width: 906,
                                     height: 269 });
    assert.deepStrictEqual(v.links.map(function (l) {
      return l.id + " " + l.href;
    }), ["repo https://github.com/rcbj/iya-sts",
         "issues https://github.com/rcbj/iya-sts/issues",
         "docs https://rcbj.github.io/iya-sts/v1.2.0/", "console /admin",
         "portal /portal", "report /report"]);
  });
  check("and the mode's two facts as each realm answers them", function () {
    assert.deepStrictEqual(dev.body.view.mode, { verifiesCredentials: false,
                                                 gatesConsole: true });
    assert.deepStrictEqual(prod.body.view.mode, { verifiesCredentials: true,
                                                  gatesConsole: true });
  });
  log.debug("Leaving sectionHome().");
}

async function sectionDescriptions() {
  log.debug("Entering sectionDescriptions().");
  log.info("=== 2. the protocol families' description pages ===");
  await setting(DEV, "xacml.enforceAccess", "true");
  const page = await get(DEV, "/xacml");
  const script = await get(DEV, "/xacml/description.js");
  const asJson = await get(DEV, "/xacml?format=json");
  check("with xacml.enforceAccess on, /xacml, its script and its JSON form " +
        "are all refused to a caller presenting no certificate", function () {
    assert.strictEqual(page.status, 403);
    assert.strictEqual(stateOf(page.raw), null);
    assert.strictEqual(script.status, 403);
    assert.ok(!/javascript/.test(header(script, "content-type")));
    assert.strictEqual(asJson.status, 403);
  });
  await setting(DEV, "xacml.enforceAccess", "false");
  const p = "/realm/" + DEV;
  const views = {};
  for (const f of FAMILIES) {
    const r = await get(DEV, f.base, { Accept: "text/html,*/*;q=0.8" });
    const state = stateOf(r.raw);
    views[f.kind] = state && state.view;
    check("GET " + f.base + ": 200, no-store, the shell loading its own " +
          "script under a policy that runs it, carrying a " + f.kind +
          " view", function () {
      assert.ok(noStoreShell(r), r.status + " " + r.raw.slice(0, 200));
      assert.ok(r.raw.indexOf("<script src=\"" + p + f.base +
                              "/description.js\" defer></script>") > 0);
      assert.ok(r.raw.indexOf("<noscript>") > 0 && !/<table/.test(r.raw));
      assert.ok(scriptPolicy(r), header(r, "content-security-policy"));
      assert.ok(state && state.view && state.view.kind === f.kind,
                JSON.stringify(state).slice(0, 200));
    });
    const byQuery = await get(DEV, f.base + "?format=json");
    const expected = f.hadJson ? state.view.document : state.view;
    check(f.base + "?format=json answers " + (f.hadJson ?
          "the description document the shell carries" :
          "the view the shell carries"), function () {
      assert.strictEqual(byQuery.status, 200);
      assert.ok(/no-store/.test(header(byQuery, "cache-control")));
      assert.ok(/json/.test(header(byQuery, "content-type")));
      assert.deepStrictEqual(Object.keys(byQuery.body).sort(),
                             Object.keys(expected || {}).sort());
    });
    const byAccept = await get(DEV, f.base, { Accept: "application/json" });
    const star = await get(DEV, f.base, { Accept: "*/*" });
    const asked = await get(DEV, f.base + "?format=html",
                            { Accept: "application/json" });
    const js = await get(DEV, f.base + "/description.js");
    check(f.base + ": an Accept of JSON answers the same JSON, */* and " +
          "?format=html the shell, and its script is served", function () {
      assert.ok(byAccept.status === 200 && byAccept.body &&
                stateOf(byAccept.raw) === null);
      assert.deepStrictEqual(Object.keys(byAccept.body).sort(),
                             Object.keys(byQuery.body).sort());
      assert.ok(stateOf(star.raw) && stateOf(asked.raw),
                star.status + " " + asked.status);
      assert.strictEqual(js.status, 200);
      assert.ok(/javascript/.test(header(js, "content-type")) &&
                js.raw.length > 0);
    });
  }
  check("each view carries the facts its page drew beside the document",
        function () {
    assert.strictEqual(typeof views.scim.verifiesCredentials, "boolean");
    assert.strictEqual(views.scim.base, "/scim/v2");
    assert.strictEqual(typeof views.spiffe.authority.ready, "boolean");
    assert.strictEqual(typeof views.spiffe.https, "boolean");
    assert.ok(typeof views.xacml.trustAnchorDoor === "string" &&
              views.xacml.trustAnchorDoor.length > 0);
    assert.ok(views.ssf.deliveryNames &&
              typeof views.ssf.deliveryNames === "object");
  });
  for (const realm of [DEV, PROD]) {
    if (realm === PROD) {
      await setting(PROD, "xacml.enforceAccess", "false");
    }
    const saml2 = (await get(realm, "/saml2?format=json")).body;
    const saml11 = (await get(realm, "/saml11?format=json")).body;
    const xacml = (await get(realm, "/xacml?format=json")).body;
    const shell = stateOf((await get(realm, "/saml2")).raw);
    check((realm === DEV ? "development" : "product") + ": no mock SP or " +
          "RP and no embedded PEP, in the JSON or the shell", function () {
      assert.ok(saml2 && !("sp" in saml2.paths), JSON.stringify(saml2));
      assert.ok(saml11 && !("rp" in saml11.paths), JSON.stringify(saml11));
      assert.ok(xacml && !("pep" in xacml), JSON.stringify(xacml));
      assert.ok(!(xacml.endpoints || []).some(function (row) {
        return row.path === "/xacml/protected";
      }));
      assert.ok(shell && !("sp" in shell.view.paths));
    });
  }
  for (const path of ["/saml2/ars", "/saml11/responder"]) {
    const r = await get(DEV, path);
    check("GET " + path + " is a specification's endpoint, still drawn by " +
          "the server under script-src 'none'", function () {
      assert.strictEqual(r.status, 200);
      assert.strictEqual(stateOf(r.raw), null);
      assert.ok(/<table|<h1>/.test(r.raw));
      assert.ok(/script-src 'none'/.test(header(r,
                "content-security-policy")));
    });
  }
  const metadata = await get(DEV, "/saml2/metadata");
  const ssf = await get(DEV, "/.well-known/ssf-configuration");
  const spc = await get(DEV, "/scim/v2/ServiceProviderConfig");
  check("the SAML metadata, the SSF configuration and SCIM discovery answer " +
        "as they did, with no shell", function () {
    assert.ok(metadata.status === 200 &&
              /xml/.test(header(metadata, "content-type")) &&
              /EntityDescriptor/.test(metadata.raw));
    assert.ok(ssf.body && ssf.body.issuer, ssf.raw.slice(0, 200));
    assert.ok(stateOf(spc.raw) === null && !/description\.js/.test(spc.raw));
  });
  log.debug("Leaving sectionDescriptions().");
}

async function sectionDiagnostics() {
  log.debug("Entering sectionDiagnostics().");
  log.info("=== 3. the diagnostic pages are gone ===");
  const gets = ["/tls", "/tls/forwarded", "/tls/pages.js", "/spnego",
                "/spnego/protected", "/spnego/pages.js", "/krb5/service",
                "/krb5/principals"];
  for (const path of gets) {
    const r = await get(DEV, path);
    check("GET " + path + " answers as an unrouted path", function () {
      assert.strictEqual(r.status, 404);
      assert.ok(r.raw.indexOf("Cannot GET /realm/" + DEV + path) >= 0,
                r.raw.slice(0, 200));
    });
  }
  for (const path of ["/tls/trust", "/tls/trust/clear"]) {
    const r = await send(base + "/realm/" + DEV + path, { method: "POST" });
    check("POST " + path + " answers as an unrouted path", function () {
      assert.strictEqual(r.status, 404);
      assert.ok(r.raw.indexOf("Cannot POST") >= 0, r.raw.slice(0, 200));
    });
  }
  log.debug("Leaving sectionDiagnostics().");
}

function footersIn(text) {
  log.debug("Entering footersIn().");
  log.debug("Leaving footersIn().");
  return String(text || "")
    .match(/<footer class="sts-footer"[\s\S]*?<\/footer>/g) || [];
}

function footerProblems(text, version, build) {
  log.debug("Entering footerProblems().");
  const all = footersIn(text);
  if (all.length !== 1) {
    log.debug("Leaving footerProblems(). count");
    return ["footers: " + all.length];
  }
  const f = all[0];
  const out = [];
  const hrefs = [];
  const re = /<a href="([^"]*)" target="_blank" rel="noopener noreferrer"/g;
  let m = re.exec(f);
  while (m) {
    hrefs.push(unescape(m[1]));
    m = re.exec(f);
  }
  if (JSON.stringify(hrefs) !== JSON.stringify(FOOTER_LINKS)) {
    out.push("hrefs: " + JSON.stringify(hrefs));
  }
  ["LinkedIn", "GitHub"].forEach(function (name) {
    if (f.indexOf("aria-label=\"" + name + "\" title=\"" + name +
                  "\"><svg") < 0) {
      out.push("no " + name + " icon");
    }
  });
  if ((f.match(/<svg /g) || []).length !== 2) {
    out.push("icons are not two inline svgs");
  }
  const year = String(new Date().getUTCFullYear());
  const years = year === "2026" ? "2026" : "2026–" + year;
  if (f.indexOf("© " + years + " Iya CyberSecurity Solutions, LLC.") < 0) {
    out.push("copyright with " + year);
  }
  if (f.indexOf("data-sts-footer-version=\"" + version + "\"") < 0 ||
      unescape(f).indexOf("title=\"" + build + "\"") < 0 ||
      f.indexOf(version + "</div></footer>") < 0) {
    out.push("version " + version + " and its build line");
  }
  log.debug("Leaving footerProblems().");
  return out;
}

async function sectionFooter() {
  log.debug("Entering sectionFooter().");
  log.info("=== 4. the page footer ===");
  const view = (await get(DEV, "/home-api/front")).body.view;
  const shells = ["/", "/admin", "/portal", "/report", "/federation",
                  "/saml2", "/ssf"];
  for (const path of shells) {
    const r = await get(DEV, path, { Accept: "text/html" });
    check(path + "'s shell carries exactly one footer — the five links, " +
          "the two icons, this year and the version — and links " +
          "/web/footer.css", function () {
      assert.strictEqual(r.status, 200);
      assert.deepStrictEqual(footerProblems(r.raw, view.version, view.build),
                             []);
      assert.ok(r.raw.indexOf("<link rel=\"stylesheet\" href=\"/realm/" +
                DEV + "/web/footer.css\">") > 0);
    });
  }
  const css = await get(DEV, "/web/footer.css");
  check("/web/footer.css is served, stacking at 500px", function () {
    assert.strictEqual(css.status, 200);
    assert.ok(/^text\/css/.test(header(css, "content-type")));
    assert.ok(/max-width:500px/.test(css.raw));
  });
  await setting(DEV, "oauth2.sessionManagement", "true");
  const iframe = await get(DEV, "/oauth2/check_session");
  check("a specification's document, the OP iframe, carries no footer",
        function () {
    assert.strictEqual(iframe.status, 200);
    assert.ok(/<html/i.test(iframe.raw));
    assert.strictEqual(footersIn(iframe.raw).length, 0);
    assert.ok(iframe.raw.indexOf("footer.css") < 0);
  });
  log.debug("Leaving sectionFooter().");
}

function authorize(realm, extra, headers) {
  log.debug("Entering authorize().");
  log.debug("Leaving authorize().");
  return get(realm, "/oauth2/authorize?client_id=" + CLIENT +
             "&redirect_uri=" + encodeURIComponent(REDIRECT) +
             "&response_type=token&state=s1&nonce=n1" + (extra || ""),
             Object.assign({ Accept: "text/html" }, headers || {}));
}

async function sectionErrorPage() {
  log.debug("Entering sectionErrorPage().");
  log.info("=== 5. the authorization error page ===");
  const view = (await get(DEV, "/home-api/front")).body.view;
  const plain = await authorize(PROD);
  check("by default the page has its link and no timed continue",
        function () {
    assert.strictEqual(plain.status, 400);
    assert.ok(plain.raw.indexOf("Continue to " + REDIRECT) >= 0);
    assert.ok(plain.raw.indexOf("http-equiv=\"refresh\"") < 0);
    assert.ok(plain.raw.indexOf("automatically in") < 0);
  });
  const box = plain.raw.indexOf("<div class=\"warn\" role=\"alert\">");
  const more = plain.raw.indexOf("<details class=\"prose\">");
  // A NODE DEFECT, FIXED (found by this job, 2026-11-15; fixed
  // 2026-11-14): in a realm the page's portal link carried the realm's
  // prefix TWICE — `/realm/<id>/realm/<id>/portal`, a 404 — because the
  // link was drawn with the prefix and `app.js`'s `send()` added it again.
  // It is the realm's portal, its prefix once.
  const doubled = "/realm/" + PROD + "/realm/" + PROD + "/";
  const portal = plain.raw.indexOf("href=\"/realm/" + PROD + "/portal\"");
  const diag = plain.raw.indexOf("<section class=\"diagnostics\"");
  check("the shared error page: the error, the RFC 9700 background " +
        "collapsed, the portal, the request's values among the diagnostics, " +
        "the chooser, and no script", function () {
    assert.ok(box > 0 && more > box && portal > more && diag > portal,
              [box, more, portal, diag].join(","));
    assert.ok(plain.raw.indexOf(doubled) < 0,
              "a link carries the realm's prefix twice");
    assert.ok(/<form class="language-chooser"/.test(plain.raw));
    assert.ok(/<code>s1<\/code>/.test(plain.raw) &&
              /<code>n1<\/code>/.test(plain.raw) &&
              new RegExp("<code>" + CLIENT + "</code>").test(plain.raw));
    assert.ok(/RFC 9700 section 4\.11\.2/.test(plain.raw.slice(more,
                                                               portal)));
    assert.ok(plain.raw.indexOf("<script") < 0);
  });
  check("it carries one footer, below its diagnostics", function () {
    assert.deepStrictEqual(footerProblems(plain.raw, view.version,
                                          view.build), []);
    assert.ok(plain.raw.indexOf("</section><footer class=\"sts-footer\"") >
              0);
  });
  const fr = await authorize(PROD, "", { "Accept-Language": "fr" });
  check("and in French for a French browser", function () {
    assert.ok(/À propos<\/a>/.test(footersIn(fr.raw)[0] || ""),
              (footersIn(fr.raw)[0] || "").slice(0, 300));
  });
  await setting(PROD, "oauth2.errorPageAutoRedirectS", "5");
  const timed = await authorize(PROD);
  check("set to five seconds, a meta refresh names the link's own target " +
        "and the seconds, and the page says when, with still no script",
        function () {
    assert.ok(/<meta http-equiv="refresh" content="5;url=https:\/\/rp\.example\/cb#error=unsupported_response_type&amp;/
      .test(timed.raw), timed.raw.slice(0, 400));
    assert.ok(timed.raw.indexOf("sent there automatically in 5 seconds") >=
              0);
    assert.ok(timed.raw.indexOf("<script") < 0);
  });
  const posted = await authorize(PROD, "&response_mode=form_post");
  check("the form_post page never continues by itself and keeps its button",
        function () {
    assert.ok(posted.raw.indexOf("http-equiv=\"refresh\"") < 0);
    assert.ok(posted.raw.indexOf("<form method=\"post\" action=\"" +
                                 REDIRECT + "\"") >= 0);
    assert.ok(posted.raw.indexOf("class=\"as-link\"") >= 0);
  });
  log.debug("Leaving sectionErrorPage().");
}

async function sectionWebFiles() {
  log.debug("Entering sectionWebFiles().");
  log.info("=== 6. the shared files under /web ===");
  const shell = await get(DEV, "/");
  const build = attr(shell.raw, "data-sts-build");
  const release = attr(shell.raw, "data-sts-version");
  const idx = await get(DEV, "/web/locales/catalogs.json");
  const idxV = await get(DEV, "/web/locales/catalogs.json?v=" + build);
  const idxOld = await get(DEV, "/web/locales/catalogs.json?v=0.0.1");
  const idxRelease = await get(DEV, "/web/locales/catalogs.json?v=" +
                               encodeURIComponent(release));
  check("the index is the catalogs and the chooser's locales, cached for " +
        "good only under this build's identifier", function () {
    assert.strictEqual(idx.status, 200);
    assert.ok(/json/.test(header(idx, "content-type")));
    assert.ok(Array.isArray(idx.body.catalogs) &&
              idx.body.catalogs.length > 1 &&
              Array.isArray(idx.body.offered), idx.raw.slice(0, 200));
    assert.strictEqual(header(idx, "cache-control"), "no-cache");
    assert.strictEqual(header(idxOld, "cache-control"), "no-cache");
    assert.strictEqual(header(idxRelease, "cache-control"), "no-cache");
    assert.strictEqual(header(idxV, "cache-control"),
                       "public, max-age=31536000, immutable");
  });
  const en = await get(DEV, "/web/locales/authn/en.json?v=" + build,
                       { "Accept-Encoding": "gzip" });
  const card = await get(DEV, "/web/card.css", { "Accept-Encoding": "br" });
  check("a catalog file and the card are compressed where asked",
        function () {
    assert.strictEqual(en.status, 200);
    assert.strictEqual(header(en, "content-encoding"), "gzip");
    assert.ok(en.body && typeof en.body === "object");
    assert.strictEqual(card.status, 200);
    assert.strictEqual(header(card, "content-encoding"), "br");
    assert.ok(/var\(--sts-accent,#12107c\)/.test(card.raw));
  });
  const before = await codeCount(DEV, "STS-I18N-0012");
  const refused = ["/web/locales/nope/en.json", "/web/locales/authn/xx.json",
                   "/web/locales/authn/en.txt",
                   "/web/locales/authn/..%2Fcatalogs.json",
                   "/web/locales/..%2F..%2Fpackage/en.json"];
  const answers = [];
  for (const path of refused) {
    answers.push(await get(DEV, path));
  }
  let after = await codeCount(DEV, "STS-I18N-0012");
  for (let i = 0; i < 20 && after < before + 3; i += 1) {
    await sleep(150);
    after = await codeCount(DEV, "STS-I18N-0012");
  }
  check("a namespace, a catalog or a file name that is not one is a " +
        "no-store 404, recorded STS-I18N-0012, and nothing is read by a " +
        "requested name", function () {
    answers.forEach(function (r, i) {
      assert.strictEqual(r.status, 404, refused[i]);
      assert.strictEqual(header(r, "cache-control"), "no-store", refused[i]);
    });
    assert.ok(after >= before + 3, before + " -> " + after);
  });
  const icon = await send(base + "/realm/" + DEV + "/favicon.ico");
  check("GET /favicon.ico answers an icon kept for a day", function () {
    assert.strictEqual(icon.status, 200);
    assert.ok(/^image\/x-icon/.test(header(icon, "content-type")));
    assert.ok(/max-age=86400/.test(header(icon, "cache-control")));
  });
  log.debug("Leaving sectionWebFiles().");
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. two throwaway realms " + DEV + " and " + PROD + " ===");
  for (const id of [DEV, PROD]) {
    await ok(base + "/admin-api/realms/create", { id: id,
      domain: id + ".example.net", name: "Static surfaces " + STAMP },
      "created the realm " + id);
  }
  await setting(PROD, "global.mode", "product");
  await ok(base + "/realm/" + PROD + "/admin-api/applications/create", {
    identifier: CLIENT, kind: "oauth2-client", name: CLIENT,
    protocols: ["oauth2"], fields: { oauthClientId: [CLIENT],
      oauthRedirectUri: [REDIRECT],
      oauthGrantType: ["authorization_code"],
      oauthResponseType: ["code"] } }, "registered a client");
  await sectionHome();
  await sectionDescriptions();
  await sectionDiagnostics();
  await sectionFooter();
  await sectionErrorPage();
  await sectionWebFiles();
  log.info(checks + " checks passed.");
  log.debug("Leaving test().");
}

// THE REALMS ARE LEFT STANDING, as every job leaves its own (tests/CLAUDE.md,
// "No job removes a realm"), unless STS_TEST_REMOVE_REALMS is "1": a hand
// run against a private probe that hundreds of realms would otherwise fill
// asks for them to be removed, and so for everything made in them.
async function removeRealms() {
  log.debug("Entering removeRealms().");
  if (process.env.STS_TEST_REMOVE_REALMS !== "1") {
    log.debug("Leaving removeRealms(). Left standing.");
    return;
  }
  for (const id of [DEV, PROD]) {
    try {
      const r = await fetch(base + "/admin-api/realms/remove", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: id }) });
      log.info("removed the realm " + id + ": " + r.status);
    } catch (e) {
      log.debug("Caught in removeRealms(): " + ((e && e.message) || e));
      // A removal that fails leaves a realm behind, which is the default.
      log.info("could not remove the realm " + id);
    }
  }
  log.debug("Leaving removeRealms().");
}

async function main() {
  log.debug("Entering main().");
  try {
    try {
      await test();
    } finally {
      await removeRealms();
    }
    log.info("Test completed successfully.");
    log.debug("Leaving main().");
    process.exit(0);
  } catch (e) {
    log.debug("Caught in main(): " + ((e && e.message) || e));
    log.error("Test failed: " + ((e && e.stack) || e));
    log.debug("Leaving main().");
    process.exit(1);
  }
}

main();
