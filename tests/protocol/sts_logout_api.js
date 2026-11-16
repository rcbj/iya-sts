// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_logout_api.js
//
// ---------------------------------------------------------------------------
// THE SIGN-OUT AS A STATIC SURFACE OVER `/authn-api/logout` (#577), OVER THE
// WIRE.
//
// D12 (#444): carries over `tests/logout_api.js`, which drove the whole
// stack in a child process. Here everything is a request to a running
// service, in a throwaway DEVELOPMENT realm (naming somebody, and the
// password the screen does not check, are development's), and each person
// signs in at the screen through `authn_signin.js`:
//
//   1. THE SHELL: `GET /logout` with a session answers the shell (no-store,
//      the bundle, the stylesheet, the <noscript>, no form) under a policy
//      keeping frame-ancestors and allowing script, style and API from
//      'self' only; with no session the browser is sent to sign in;
//      `?username=` answers the shell and mints the arrival cookie; the
//      bundle and the stylesheet are served.
//   2. THE INDEX AND THE OPENAPI DOCUMENT list the view and the act.
//   3. THE VIEW: the inventory as facts with the caller's own session
//      terminable, no credential in a row, `csrf`; a name (naming open) is
//      whom the view is about; with `logout.anyUser` off somebody else's
//      name is refused 403 and one's own honoured; nobody is 401; no code.
//   4. THE ACT'S BINDING: not JSON 415; another Origin, no Origin, no
//      token, another session's token 403; an unknown field or a scope
//      outside the closed set 400; and none of them ended anything.
//   5. NOTHING TO FAN OUT: the result's view, the session ended and its
//      cookie cleared, `Clear-Site-Data: "storage"`.
//   6. A FAN-OUT: a person signed in to a WS-Federation relying party signs
//      out everywhere; the answer is the signed-out document's form and the
//      cookie is cleared; the document is the server-drawn page carrying the
//      relying party's wsignoutcleanup1.0 image and no script, under the
//      fan-out's policy with frame-ancestors kept, its inline rules the
//      static stylesheet to the byte, minting no cookie; refused with no
//      Origin, from another, cross-site with a null Origin, a result this
//      service did not MAC, and none; drawn for a same-origin null Origin.
//   7. THE JSON DOOR at `/logout`: a form posted there ends nothing (303 to
//      the page); GET with JSON answers the inventory; POST with JSON signs
//      out; a bad body is JSON invalid_request.
//   8. THE WHOLE WALK as the page sends it (`authn_signin.signOut()`).
//   9. ENDING ANOTHER SESSION NEEDS A RECENT SIGN-IN (#1521, #1577): with
//      `account.recentAuthMinutes` 1 and a sign-in older than that, ending a
//      second session is refused 403 with a `reauthenticate` view naming
//      where to sign in, nothing ended, and the JSON door the same; signing
//      in again there keeps the session, and then the act ends the other
//      one; signing yourself out everywhere is never asked. The job WAITS
//      the minute out (the clock is not the job's).
//
// NOT carried, and why: 9g, the page DRAWING the reauthenticate view (the
// browser bundle's renderer, class (d)); 6b's byte-for-byte comparison with
// `fanOutOf()`'s output (a library function; the image it draws is asserted
// instead).
//
// OWNED HERE (local: true): this repository's own sign-out surface.
// ---------------------------------------------------------------------------

const assert = require("assert");
const nodeCrypto = require("crypto");
const names = require("./random_username.js");
const registry = require("./sts_applications.js");
const authnSignin = require("./authn_signin");

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
var log = bunyan.createLogger({ name: "sts_logout_api",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp().toLowerCase().replace(/[^a-z0-9]/g, "")
  .slice(-10);
const REALM = "loapi-" + STAMP;
const RB = base + "/realm/" + REALM;
const ORIGIN = new URL(base).origin;
const PASSWORD = "Lo-" + nodeCrypto.randomBytes(9).toString("base64url") +
  "-Aa1!";
const WTREALM = "urn:loapi:rp:" + STAMP;
const WREPLY = "https://rp.loapi.example.test/wsfed";
const FLOOR = 45;

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function codeFree(text) {
  log.debug("Entering codeFree().");
  log.debug("Leaving codeFree().");
  return !/STS-[A-Z0-9]+-\d{4}/.test(String(text || ""));
}

function cookieOf(jar) {
  log.debug("Entering cookieOf().");
  log.debug("Leaving cookieOf().");
  return Object.keys(jar).map(function (k) {
    return k + "=" + jar[k];
  }).join("; ");
}

function keep(jar, headers) {
  log.debug("Entering keep().");
  const set = headers.getSetCookie ? headers.getSetCookie() : [];
  set.forEach(function (one) {
    const pair = String(one).split(";")[0];
    const at = pair.indexOf("=");
    if (at <= 0) {
      return;
    }
    const value = pair.slice(at + 1);
    if (value === "" || /Expires=Thu, 01 Jan 1970/i.test(String(one))) {
      delete jar[pair.slice(0, at)];
    } else {
      jar[pair.slice(0, at)] = value;
    }
  });
  log.debug("Leaving keep().");
}

// One request with a jar: redirects left to the caller, cookies kept.
async function call(jar, method, url, opts) {
  log.debug("Entering call(). " + method + " " + url);
  const o = opts || {};
  const headers = Object.assign({}, o.headers || {});
  if (jar && Object.keys(jar).length && o.cookies !== false) {
    headers.cookie = cookieOf(jar);
  }
  const r = await fetch(/^https?:/.test(url) ? url : RB + url,
    { method: method, redirect: "manual", headers: headers, body: o.body });
  if (jar) {
    keep(jar, r.headers);
  }
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in call(): " + ((e && e.message) || e));
    // Not JSON — a page; the caller reads `text`.
    json = null;
  }
  log.debug("Leaving call(). " + r.status);
  return { status: r.status, text: text, json: json, headers: r.headers,
           location: r.headers.get("location") || "" };
}

async function ok(url, payload, what) {
  log.debug("Entering ok().");
  const r = await call(null, "POST", url, {
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {}) });
  assert.ok(r.status === 200 && r.json && r.json.ok !== false,
            what + ": " + r.status + " " + r.text.slice(0, 400));
  log.debug("Leaving ok().");
  return r.json;
}

function setting(key, value) {
  log.debug("Entering setting(). " + key);
  log.debug("Leaving setting().");
  return ok(base + "/admin-api/realms/set", { id: REALM, key: key,
    value: String(value) }, "set " + key);
}

function sessionIdOf(jar) {
  log.debug("Entering sessionIdOf().");
  log.debug("Leaving sessionIdOf().");
  return String(jar.sts_session || "").split(".")[0];
}

// A person signed in at the screen: `GET /logout` with no session sends the
// browser there, and the screen sends it back.
async function signIn(username, jarIn) {
  log.debug("Entering signIn(). " + username);
  const jar = jarIn || {};
  const first = await call(jar, "GET", "/logout");
  assert.ok(first.status === 302 &&
            /\/authn\/login(?:\?app=[^#]*)?[?#]authn=/.test(first.location),
            "GET /logout with no session: " + first.status + " " +
            first.location);
  const done = await authnSignin.signInWithJar(RB, first.location,
    { action: "login", username: username, password: PASSWORD }, jar);
  assert.ok(jar.sts_session, "no session after signing in " + username +
            ": " + done.status + " " + done.location);
  log.debug("Leaving signIn().");
  return { jar: jar, first: first };
}

function view(jar, query) {
  log.debug("Entering view().");
  log.debug("Leaving view().");
  return call(jar, "GET", "/authn-api/logout" + (query || ""),
              { headers: { accept: "application/json" } });
}

function act(jar, body, o) {
  log.debug("Entering act().");
  const opts = o || {};
  const headers = { accept: "application/json",
    "content-type": opts.contentType || "application/json" };
  if (opts.origin !== null) {
    headers.origin = opts.origin || ORIGIN;
  }
  if (opts.csrf) {
    headers["x-csrf-token"] = opts.csrf;
  }
  log.debug("Leaving act().");
  return call(jar, "POST", "/authn-api/logout", { headers: headers,
    body: typeof body === "string" ? body : JSON.stringify(body) });
}

function sessionRows(v) {
  log.debug("Entering sessionRows().");
  const family = ((v && v.families) || []).filter(function (f) {
    return f.id === "session";
  })[0] || { rows: [] };
  log.debug("Leaving sessionRows().");
  return family.rows;
}

async function alive(jar, sid) {
  log.debug("Entering alive().");
  const r = await view(jar);
  const rows = sessionRows(r.json && r.json.view);
  log.debug("Leaving alive().");
  return rows.some(function (row) {
    return row.id === "session:" + sid;
  });
}

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

async function shellSection() {
  log.debug("Entering shellSection().");
  log.info("=== 1. the shell ===");
  const ann = await signIn("loann-" + STAMP);
  check("1c. a browser with no session is sent to sign in first",
        function () {
    assert.ok(/\/authn\/login/.test(ann.first.location));
  });
  const r = await call(ann.jar, "GET", "/logout");
  const csp = String(r.headers.get("content-security-policy") || "");
  check("1a. a browser's GET /logout answers the shell: no-store, the " +
        "bundle, the stylesheet, the noscript, no form", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.ok(/no-store/.test(String(r.headers.get("cache-control"))));
    assert.ok(r.text.indexOf('<script src="/realm/' + REALM +
              '/logout/signout.js" defer></script>') > 0 ||
              r.text.indexOf('<script src="/logout/signout.js" defer>' +
              '</script>') > 0, r.text.slice(0, 600));
    assert.ok(/<link rel="stylesheet" href="[^"]*\/logout\/signout\.css">/
      .test(r.text), r.text.slice(0, 600));
    assert.ok(/<noscript>/.test(r.text));
    assert.ok(!/<form/.test(r.text));
  });
  check("1b. its policy keeps frame-ancestors and allows script, style and " +
        "API from 'self' only", function () {
    assert.ok(/frame-ancestors 'none'/.test(csp), csp);
    assert.ok(/script-src 'self'(;|$)/.test(csp), csp);
    assert.ok(/connect-src 'self'/.test(csp), csp);
    assert.ok(!/unsafe-inline/.test(csp), csp);
  });
  const named = {};
  const n = await call(named, "GET", "/logout?username=" +
                       encodeURIComponent("lobob-" + STAMP));
  check("1d. ?username= (open in development) answers the shell and mints " +
        "the arrival cookie the act is bound to", function () {
    assert.strictEqual(n.status, 200, n.text.slice(0, 200));
    assert.ok(!!named.sts_session, JSON.stringify(Object.keys(named)));
  });
  const js = await call(null, "GET", "/logout/signout.js");
  check("1e. the bundle is served, built", function () {
    assert.strictEqual(js.status, 200);
    assert.ok(/javascript/.test(js.headers.get("content-type")));
    assert.ok(js.text.length > 1000 && js.text.indexOf("was not built") < 0);
  });
  const css = await call(null, "GET", "/logout/signout.css");
  check("1f. the stylesheet is served, with the account control's rules " +
        "(#561)", function () {
    assert.strictEqual(css.status, 200);
    assert.ok(/text\/css/.test(css.headers.get("content-type")));
    assert.ok(css.text.indexOf("button.global{") >= 0);
    assert.ok(css.text.indexOf("details.sts-accounts{") >= 0);
  });
  log.debug("Leaving shellSection().");
  return { ann: ann, named: named, css: css.text };
}

async function indexSection() {
  log.debug("Entering indexSection().");
  log.info("=== 2. the index and the OpenAPI document ===");
  const r = await call(null, "GET", "/authn-api");
  const ops = (r.json && r.json.operations) || [];
  const one = function (m, action) {
    return ops.filter(function (op) {
      return op.mirrors === m && (!action || op.action === action);
    });
  };
  check("2a. the index lists the view and the act, mirroring GET and POST " +
        "/logout", function () {
    assert.strictEqual(one("GET /logout").length, 1, JSON.stringify(ops)
      .slice(0, 300));
    assert.strictEqual(one("GET /logout")[0].path, "/authn-api/logout");
    assert.strictEqual(one("POST /logout", "logout").length, 1);
    assert.strictEqual(one("POST /logout")[0].method, "POST");
  });
  const d = await call(null, "GET", "/authn-api/openapi.json");
  const doc = (d.json && d.json.paths && d.json.paths["/authn-api/logout"]) ||
    {};
  check("2b. the OpenAPI document has both, the act's body and the view's " +
        "username", function () {
    assert.ok(doc.get && doc.post && doc.post.requestBody,
              JSON.stringify(Object.keys(doc)));
    assert.ok((doc.get.parameters || []).some(function (p) {
      return p.name === "username";
    }));
  });
  log.debug("Leaving indexSection().");
}

async function viewSection(s) {
  log.debug("Entering viewSection().");
  log.info("=== 3. the view ===");
  const annSession = sessionIdOf(s.ann.jar);
  let r = await view(s.ann.jar);
  const v = (r.json && r.json.view) || {};
  check("3a. the inventory as facts: the caller's own session a terminable " +
        "row, its name, naming open, and a csrf token", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.strictEqual(v.state, "inventory");
    assert.strictEqual(v.username, "loann-" + STAMP);
    assert.strictEqual(v.naming, "open");
    assert.ok(sessionRows(v).some(function (row) {
      return row.id === "session:" + annSession && row.terminable;
    }), JSON.stringify(sessionRows(v)).slice(0, 300));
    assert.ok(typeof r.json.csrf === "string" && r.json.csrf.length > 16);
  });
  s.annCsrf = r.json.csrf;
  check("3b. no row carries the credential behind it, and no code",
        function () {
    assert.ok(!/"secret"/.test(r.text));
    assert.ok(codeFree(r.text));
  });
  r = await view(s.named, "?username=" + encodeURIComponent("lobob-" +
                                                            STAMP));
  check("3c. a name, where naming is open, is whom the view is about",
        function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.strictEqual(r.json.view.username, "lobob-" + STAMP);
    assert.strictEqual(r.json.view.named, true);
  });
  await setting("logout.anyUser", false);
  r = await view(s.ann.jar, "?username=" + encodeURIComponent("lobob-" +
                                                              STAMP));
  check("3d. with naming closed, somebody else's name is refused (403), " +
        "saying why and naming no code", function () {
    assert.strictEqual(r.status, 403, r.text.slice(0, 300));
    assert.strictEqual(r.json.ok, false);
    assert.strictEqual(r.json.view.state, "refused");
    assert.ok(/logout\.anyUser is off/.test((r.json.errors || []).join(" ")),
              r.text.slice(0, 300));
    assert.ok(codeFree(r.text));
  });
  r = await view(s.ann.jar, "?username=" + encodeURIComponent("loann-" +
                                                              STAMP));
  check("3e. and the caller's own name is honoured", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.strictEqual(r.json.view.username, "loann-" + STAMP);
  });
  r = await view({});
  check("3f. with no session and no name, nobody (401)", function () {
    assert.strictEqual(r.status, 401, r.text.slice(0, 300));
    assert.strictEqual(r.json.view.state, "nobody");
    assert.ok(codeFree(r.text));
  });
  await setting("logout.anyUser", true);
  log.debug("Leaving viewSection().");
}

async function bindingSection(s) {
  log.debug("Entering bindingSection().");
  log.info("=== 4. the act's binding ===");
  const jar = s.ann.jar;
  const csrf = s.annCsrf;
  const other = await signIn("locy0-" + STAMP);
  const otherCsrf = (await view(other.jar)).json.csrf;
  let r = await act(jar, "scope=global", { csrf: csrf,
    contentType: "application/x-www-form-urlencoded" });
  check("4a. a body that is not JSON is refused (415)", function () {
    assert.strictEqual(r.status, 415, r.text.slice(0, 200));
  });
  r = await act(jar, {}, { csrf: csrf, origin: "https://evil.example" });
  check("4b. another origin is refused (403)", function () {
    assert.strictEqual(r.status, 403);
  });
  r = await act(jar, {}, { csrf: csrf, origin: null });
  check("4c. no Origin is refused (403)", function () {
    assert.strictEqual(r.status, 403);
  });
  r = await act(jar, {}, {});
  check("4d. no token is refused (403)", function () {
    assert.strictEqual(r.status, 403);
  });
  r = await act(jar, {}, { csrf: otherCsrf });
  check("4e. another session's token is refused (403), naming no code",
        function () {
    assert.strictEqual(r.status, 403);
    assert.ok(codeFree(r.text));
  });
  r = await act(jar, { scope: "global", admin: "1" }, { csrf: csrf });
  check("4f. a field the act does not take is refused (400)", function () {
    assert.strictEqual(r.status, 400, r.text.slice(0, 200));
  });
  r = await act(jar, { scope: "Global" }, { csrf: csrf });
  check("4g. a scope outside the closed set is refused (400)", function () {
    assert.strictEqual(r.status, 400, r.text.slice(0, 200));
    assert.ok(codeFree(r.text));
  });
  const still = await alive(jar, sessionIdOf(jar));
  check("4h. and none of them ended anything", function () {
    assert.ok(still);
    assert.ok(!!jar.sts_session);
  });
  log.debug("Leaving bindingSection().");
}

async function resultSection(s) {
  log.debug("Entering resultSection().");
  log.info("=== 5. nothing to fan out ===");
  const jar = s.ann.jar;
  const sid = sessionIdOf(jar);
  const cookieBefore = jar.sts_session;
  const r = await act(jar, { scope: "selected", select: ["session:" + sid] },
                      { csrf: s.annCsrf });
  const answer = r.json || {};
  check("5a. the answer is the result's view, naming the session ended",
        function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.strictEqual(answer.ok, true);
    assert.strictEqual(answer.next, "signed-out");
    assert.ok(!answer.form);
    assert.strictEqual(answer.view.state, "result");
    assert.strictEqual(answer.view.scope, "selected");
    assert.ok(JSON.stringify(answer.view.terminated).indexOf(sid) >= 0,
              JSON.stringify(answer.view.terminated).slice(0, 300));
  });
  // The cookie the browser held before: the session it named is gone.
  const after = await view({ sts_session: cookieBefore });
  check("5b. the browser's own session ended, and its cookie was cleared " +
        "on the answer", function () {
    assert.ok(!jar.sts_session, JSON.stringify(jar));
    assert.strictEqual(after.status, 401, after.text.slice(0, 200));
  });
  check("5c. the answer tells the browser to drop storage, and not cookies " +
        "(#1440)", function () {
    assert.strictEqual(r.headers.get("clear-site-data"), '"storage"');
  });
  log.debug("Leaving resultSection().");
}

async function fanOutSection(css) {
  log.debug("Entering fanOutSection().");
  log.info("=== 6. a sign-out that fans out ===");
  const cy = await signIn("locy-" + STAMP);
  // A WS-Federation sign-in on the same browser: the session now holds a
  // relying party a sign-out cleans up with wsignoutcleanup1.0.
  let r = await call(cy.jar, "GET", "/wsfed?" + new URLSearchParams({
    wa: "wsignin1.0", wtrealm: WTREALM, wreply: WREPLY }).toString());
  check("6.0 (the WS-Federation sign-in answered on the live session)",
        function () {
    assert.strictEqual(r.status, 200, r.status + " " + r.location + " " +
                       r.text.slice(0, 300));
    assert.ok(/wresult/.test(r.text), r.text.slice(0, 300));
  });
  const csrf = (await view(cy.jar)).json.csrf;
  r = await act(cy.jar, { scope: "global" }, { csrf: csrf });
  const fanned = r.json || {};
  check("6a. a sign-out that fans out answers the signed-out document's " +
        "form, and clears the cookie", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.strictEqual(fanned.next, "signed-out");
    assert.ok(!fanned.view);
    assert.strictEqual(fanned.form.method, "POST");
    assert.ok(/\/logout\/signed-out$/.test(fanned.form.action),
              fanned.form.action);
    assert.strictEqual(typeof fanned.form.fields.result, "string");
    assert.ok(!cy.jar.sts_session);
  });
  const postDoc = function (result, o) {
    const opts = o || {};
    const headers = { "content-type": "application/x-www-form-urlencoded" };
    if (opts.origin !== null) {
      headers.origin = opts.origin || ORIGIN;
    }
    if (opts.site) {
      headers["sec-fetch-site"] = opts.site;
    }
    return call(opts.jar || {}, "POST", "/logout/signed-out", {
      headers: headers, body: new URLSearchParams(result === undefined ? {}
        : { result: result }).toString() });
  };
  const docJar = {};
  r = await postDoc(fanned.form.fields.result, { jar: docJar });
  const docCsp = String(r.headers.get("content-security-policy") || "");
  const cleanup = WREPLY + "?wa=wsignoutcleanup1.0";
  check("6b. the signed-out document is the server-drawn page, carrying the " +
        "relying party's wsignoutcleanup1.0 image and no script", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.ok(/^<!doctype html>/i.test(r.text));
    assert.ok(r.text.indexOf('<img src="' + cleanup) > 0,
              r.text.slice(0, 1200));
    assert.ok(r.text.indexOf("<script") < 0);
  });
  check("6c. its policy is the fan-out's, frame-ancestors kept", function () {
    assert.ok(/frame-ancestors 'none'/.test(docCsp), docCsp);
    assert.ok(/img-src 'self' data: \*/.test(docCsp), docCsp);
  });
  check("6d. its inline rules are the static page's stylesheet, to the byte",
        function () {
    assert.ok(r.text.indexOf("<style>" + css + "</style>") > 0);
  });
  check("6e. and it mints no cookie for the browser it signed out",
        function () {
    assert.ok(!docJar.sts_session, JSON.stringify(docJar));
  });
  r = await postDoc(fanned.form.fields.result, { origin: null });
  check("6f. posted with no Origin, it is refused (403), drawing nothing",
        function () {
    assert.strictEqual(r.status, 403);
    assert.ok(codeFree(r.text));
    assert.ok(r.text.indexOf("<img") < 0);
  });
  r = await postDoc(fanned.form.fields.result,
                    { origin: "https://evil.example" });
  check("6g. from another origin, refused (403)", function () {
    assert.strictEqual(r.status, 403);
  });
  r = await postDoc(fanned.form.fields.result,
                    { origin: "null", site: "same-origin" });
  check("6g2. a navigation's null Origin, the browser saying it is " +
        "same-origin, is drawn", function () {
    assert.strictEqual(r.status, 200);
    assert.ok(r.text.indexOf('<img src="' + cleanup) > 0);
  });
  r = await postDoc(fanned.form.fields.result,
                    { origin: "null", site: "cross-site" });
  check("6g3. and refused (403) where it says cross-site", function () {
    assert.strictEqual(r.status, 403);
  });
  const sealed = String(fanned.form.fields.result);
  const forged = sealed.slice(0, sealed.lastIndexOf(".") + 1) +
    "A".repeat(43);
  r = await postDoc(forged);
  check("6h. a result this service did not MAC is refused (400)",
        function () {
    assert.strictEqual(r.status, 400);
    assert.ok(codeFree(r.text));
    assert.ok(r.text.indexOf("<img") < 0);
  });
  r = await postDoc(undefined);
  check("6i. no result at all is refused (400)", function () {
    assert.strictEqual(r.status, 400);
  });
  log.debug("Leaving fanOutSection().");
}

async function jsonDoorSection() {
  log.debug("Entering jsonDoorSection().");
  log.info("=== 7. the JSON door, and a form posted to /logout ===");
  const dee = await signIn("lodee-" + STAMP);
  const sid = sessionIdOf(dee.jar);
  let r = await call(dee.jar, "POST", "/logout", { headers: {
    "content-type": "application/x-www-form-urlencoded" },
    body: "scope=global" });
  const kept = await alive(dee.jar, sid);
  check("7a. a form posted to /logout ends nothing and is sent to the page " +
        "(303)", function () {
    assert.strictEqual(r.status, 303, r.text.slice(0, 200));
    assert.ok(/\/logout$/.test(r.location), r.location);
    assert.ok(kept);
  });
  r = await call(dee.jar, "GET", "/logout", { headers: {
    accept: "application/json" } });
  check("7b. GET /logout asking for JSON answers the inventory as it did",
        function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 200));
    assert.strictEqual(r.json.username, "lodee-" + STAMP);
    assert.ok(Array.isArray(r.json.families));
  });
  r = await call(dee.jar, "POST", "/logout", { headers: {
    "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify({ scope: "global" }) });
  check("7c. POST /logout with JSON signs out as it did", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.strictEqual(r.json.scope, "global");
    assert.strictEqual(r.json.ownSessionEnded, true);
    assert.ok(!dee.jar.sts_session);
  });
  r = await call({}, "POST", "/logout", { headers: {
    "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify({ scope: "nowhere", username: "lo-x" }) });
  check("7d. and its refusal of a body is JSON invalid_request", function () {
    assert.strictEqual(r.status, 400, r.text.slice(0, 200));
    assert.strictEqual(r.json.error, "invalid_request");
  });
  log.debug("Leaving jsonDoorSection().");
}

async function walkSection() {
  log.debug("Entering walkSection().");
  log.info("=== 8. the whole walk, as the page sends it ===");
  const eve = await signIn("loeve-" + STAMP);
  const walked = await authnSignin.signOut(RB, {},
                                           { cookie: cookieOf(eve.jar) });
  check("8a. the page's walk — shell, view, act — signs out everywhere",
        function () {
    assert.strictEqual(walked.status, 200, String(walked.text)
      .slice(0, 200));
    assert.strictEqual(walked.json.view.scope, "global");
  });
  log.debug("Leaving walkSection().");
}

async function reauthSection() {
  log.debug("Entering reauthSection().");
  log.info("=== 9. ending another session needs a recent sign-in ===");
  await setting("account.recentAuthMinutes", 1);
  const name = "lofay-" + STAMP;
  const fay = await signIn(name);
  const fayOther = await signIn(name);
  const gus = await signIn("logus-" + STAMP);
  const faySession = sessionIdOf(fay.jar);
  const otherSession = sessionIdOf(fayOther.jar);
  log.info("waiting 65 s, so that both sign-ins are older than a minute");
  await sleep(65000);
  let r = await act(fay.jar, { scope: "selected",
                               select: ["session:" + otherSession] },
                    { csrf: (await view(fay.jar)).json.csrf });
  const owed = r.json || {};
  check("9a. a stale sign-in ending another session is refused (403) with a " +
        "view naming where to sign in again, and no code", function () {
    assert.strictEqual(r.status, 403, r.text.slice(0, 300));
    assert.strictEqual(owed.ok, false);
    assert.strictEqual(owed.view.state, "reauthenticate");
    assert.ok(/\/authn\/login/.test(String(owed.view.signIn || "")),
              owed.view.signIn);
    assert.strictEqual(owed.errors.length, 1);
    assert.ok(codeFree(r.text));
  });
  const both = await alive(fay.jar, otherSession) &&
               await alive(fay.jar, faySession);
  check("9b. and nothing was ended", function () {
    assert.ok(both);
    assert.ok(!!fay.jar.sts_session);
  });
  r = await call(fay.jar, "POST", "/logout", { headers: {
    "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify({ scope: "selected",
                           select: ["session:" + otherSession] }) });
  check("9c. the JSON door answers the same act the same way", function () {
    assert.strictEqual(r.status, 403, r.text.slice(0, 200));
    assert.strictEqual(r.json.error, "reauthentication_required");
  });
  const signInAt = /^https?:/.test(owed.view.signIn) ? owed.view.signIn
    : ORIGIN + owed.view.signIn;
  const again = await authnSignin.signInWithJar(RB, signInAt,
    { action: "login", username: name, password: PASSWORD }, fay.jar);
  check("9d. signing in again where the view said keeps the same session",
        function () {
    assert.ok(again.status === 302 || again.status === 303 ||
              again.status === 200, again.status + " " + again.location);
    assert.strictEqual(sessionIdOf(fay.jar), faySession);
  });
  r = await act(fay.jar, { scope: "selected",
                           select: ["session:" + otherSession] },
                { csrf: (await view(fay.jar)).json.csrf });
  const otherGone = !(await alive(fay.jar, otherSession));
  const ownKept = await alive(fay.jar, faySession);
  check("9e. and then the same act ends the other session, and only it",
        function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.strictEqual(r.json.ok, true);
    assert.ok(otherGone);
    assert.ok(ownKept);
  });
  r = await act(gus.jar, { scope: "global" },
                { csrf: (await view(gus.jar)).json.csrf });
  check("9f. signing yourself out everywhere is never asked", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.strictEqual(r.json.ok, true);
    assert.ok(!gus.jar.sts_session);
  });
  log.debug("Leaving reauthSection().");
}

async function test() {
  log.debug("Entering test().");
  await ok(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "Sign-out API " + STAMP },
    "created the realm");
  await setting("global.mode", "development");
  // RISK SCORING (#62) is off for sts_admin_client_policies.js's reason.
  await setting("risk.assessSignIns", false);
  for (const who of ["loann", "lobob", "locy0", "locy", "lodee", "loeve",
                     "lofay", "logus"]) {
    await registry.ensurePerson(RB, who + "-" + STAMP, PASSWORD);
  }
  const s = await shellSection();
  await indexSection();
  await viewSection(s);
  await bindingSection(s);
  await resultSection(s);
  await fanOutSection(s.css);
  await jsonDoorSection();
  await walkSection();
  await reauthSection();
  assert.ok(checks >= FLOOR, "only " + checks + " checks ran; the floor is " +
            FLOOR);
  log.info(checks + " check(s) passed.");
  log.debug("Leaving test().");
}

// REMOVAL IS OPT-IN: with STS_TEST_REMOVE_REALMS=1 (a private probe that
// would otherwise fill its directory) the realm this run made is removed at
// the end, pass or fail. A suite run leaves it standing (tests/CLAUDE.md,
// *No job removes a realm*).
async function removeRealms() {
  log.debug("Entering removeRealms().");
  if (process.env.STS_TEST_REMOVE_REALMS !== "1") {
    log.debug("Leaving removeRealms(). Not asked to.");
    return;
  }
  const r = await call(null, "POST", base + "/admin-api/realms/remove", {
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ id: REALM }) });
  log.info("removed the realm " + REALM + " (" + r.status + ")");
  log.debug("Leaving removeRealms().");
}

async function main() {
  log.debug("Entering main().");
  let failure = null;
  try {
    await test();
  } catch (e) {
    log.debug("Caught in main(): " + ((e && e.message) || e));
    // Reported below, after the realm is removed.
    failure = e;
  }
  try {
    await removeRealms();
  } catch (e) {
    log.debug("Caught in main(): " + ((e && e.message) || e));
    // A removal that fails is logged; the job's verdict is the test's.
    log.warn("could not remove the realm: " + ((e && e.message) || e));
  }
  if (failure) {
    log.error("FAILED after " + checks + " check(s): " +
              ((failure && failure.stack) || failure));
    log.debug("Leaving main(). Failed.");
    process.exit(1);
  }
  log.info("Test completed successfully.");
  log.debug("Leaving main().");
  process.exit(0);
}

main();
