// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_rp_initiated_logout_sessions.js
//
// ---------------------------------------------------------------------------
// OPENID CONNECT RP-INITIATED LOGOUT 1.0 AGAINST A LIVE SESSION, OVER THE
// WIRE (#124 with #115, #187, #1301, #1302, #1326, #1331).
//
// D12 (#444): carries over `tests/rp_initiated_logout.js`, which drove real
// sign-ins in a child process. `sts_rp_initiated_logout.js` asks the
// endpoint with no session, so it runs in either mode; this job signs a
// person in at the screen and asks every question a live session changes,
// in a throwaway DEVELOPMENT realm. Whether the session is alive is asked
// as a relying party would — `prompt=none` answering a code or not.
//
//   a. VALIDATE BEFORE ENDING: a malformed request is a 400 page and a POST
//      that is not a form is refused, the session surviving both.
//   b. CONFIRMATION: no hint asks, with a real button and no script; the
//      page says WHY in one sentence per case (no hint, no cookie); no hint
//      and no client is the amber box first ("not valid as sent"), then the
//      question, and once confirmed the partly-refused page with its
//      diagnostics and the way back; an address the named client did not
//      register is the box with its own reason, never naming the registered
//      one; no parameters, or only state and client_id, say no hint; "Stay
//      signed in" keeps the session; a forged confirm_for is asked again; a
//      cross-site POST (no cookie) is asked and no cookie cleared; the
//      page's own form signs out and returns WITH state.
//   c. THE HINT: a verified hint for this session signs out at once, with
//      state; a tampered hint, an alg-none hint (said to be unsigned), a
//      kid-less hint (quoting no empty key) and a client_id it was not
//      issued to are refused, the session surviving; a logout_hint naming
//      somebody else asks and says so; a hint for an EARLIER session asks
//      and says so; POST with the hint signs out.
//   d. THE RETURN: a registered client is held to its own list — an address
//      it did not register, or the registered one with a query added, is
//      not followed, the session ended, and the page says so in a warning
//      box above the "signed out" banner, its heading and title naming the
//      refusal and the registered address nowhere; ui_locales=fr draws the
//      box and the heading in French; no session and a client that
//      registered none is followed straight back in development; a
//      private-use address nobody registered is not; no client named at all
//      is not followed even in development (STS-OAUTH-0785); with nowhere
//      to return, a page.
//   e. THE AUTHORIZATION ENDPOINT'S OWN REFUSALS, on the same realm and
//      client: an unregistered redirect_uri is a 400 never redirected, the
//      JSON and the browser's error page saying the same thing and naming
//      only the address sent; no redirect_uri says the request has none;
//      an empty or malformed one keeps its own sentence; an implicit request
//      with no nonce is told it has none; the error page's shape (the box,
//      the background, the portal, the language chooser, the diagnostics
//      with state, nonce and client, and an incident ID that IS the seq of
//      the request's audit row) and the ring's sequence rising; the page in
//      French; a request with both request and request_uri as a page with
//      its own sentence (STS-OAUTH-0341) and JSON otherwise; a refused
//      sign-out as the same page, in French, the state and the person among
//      the diagnostics.
//   f. THE SECOND SIGN-IN'S REASON in `/authn-api`'s view: none on a first
//      sign-in or prompt=login with no session; `prompt_login` with one;
//      prompt=select_account is the account picker; a max_age the session
//      meets is answered at once, and one it does not is `max_age`.
//
// NOT carried, and why: f's drawn notice and f6 (the screen's bundle draws
// the reason; `WebAuthnLogin.render()` is a browser renderer, class (d)).
//
// OWNED HERE (local: true): this repository's own OpenID Provider.
// ---------------------------------------------------------------------------

const assert = require("assert");
const nodeCrypto = require("crypto");
const names = require("./random_username.js");
const registry = require("./sts_applications.js");
const authnSignin = require("./authn_signin");
const navigation = require("./navigation.js");

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
var log = bunyan.createLogger({ name: "sts_rp_initiated_logout_sessions",
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
const REALM = "rls-" + STAMP;
const RB = base + "/realm/" + REALM;
const ORIGIN = new URL(base).origin;
const PERSON = "rls-alice-" + STAMP;
const PASSWORD = "Rls-" + nodeCrypto.randomBytes(9).toString("base64url") +
  "-Aa1!";
const SECRET = "rls-secret-" + nodeCrypto.randomBytes(16).toString("hex");
const REDIRECT = "https://rp.rl.example/cb";
const BACK = "https://rp.rl.example/signed-out";
const SECTION = " (RP-Initiated Logout 1.0 section 2).";
const NO_HINT = "This sign-out request carried no id_token_hint, so this " +
  "service cannot tell which application sent it";
const BOX_NO_CLIENT = "<strong>This sign-out request is not valid as sent: " +
  "it carries neither an id_token_hint nor a client_id, so this service " +
  "cannot tell which application sent it, and its post_logout_redirect_uri " +
  "is not followed.</strong> The request named <code>{uri}</code> " +
  "(RP-Initiated Logout 1.0 section 2).";
const BOX_NOT_REGISTERED = "<strong>This sign-out request is not valid as " +
  "sent: its post_logout_redirect_uri is not one this client registered, so " +
  "it is not followed.</strong> The request named <code>{uri}</code> " +
  "(RP-Initiated Logout 1.0 section 3).";
const BOX_FR = "<strong>Cette demande de déconnexion n’est pas valide " +
  "telle qu’elle a été envoyée : son post_logout_redirect_uri n’est pas " +
  "l’un de ceux que ce client a enregistrés ; il n’est donc pas " +
  "suivi.</strong> La demande indiquait ";
const FLOOR = 47;

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function form(o) {
  log.debug("Entering form().");
  log.debug("Leaving form().");
  return new URLSearchParams(o).toString();
}

function keep(jar, headers) {
  log.debug("Entering keep().");
  (headers.getSetCookie ? headers.getSetCookie() : []).forEach(function (one) {
    const pair = String(one).split(";")[0];
    const at = pair.indexOf("=");
    if (at <= 0 || !jar) {
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

function cookieOf(jar) {
  log.debug("Entering cookieOf().");
  log.debug("Leaving cookieOf().");
  return Object.keys(jar || {}).map(function (k) {
    return k + "=" + jar[k];
  }).join("; ");
}

async function answer(r, jar) {
  log.debug("Entering answer().");
  keep(jar, r.headers);
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in answer(): " + ((e && e.message) || e));
    // Not JSON — a page; the caller reads `text`.
    json = null;
  }
  log.debug("Leaving answer(). " + r.status);
  return { status: r.status, text: text, json: json,
           type: String(r.headers.get("content-type") || ""),
           setCookie: (r.headers.getSetCookie ? r.headers.getSetCookie()
                                              : []).join("\n"),
           location: r.headers.get("location") || "" };
}

async function call(method, url, opts, jar) {
  log.debug("Entering call(). " + method + " " + url);
  const o = opts || {};
  const headers = Object.assign({}, o.headers || {});
  if (jar && Object.keys(jar).length && o.cookies !== false) {
    headers.cookie = cookieOf(jar);
  }
  const r = await fetch(/^https?:/.test(url) ? url : RB + url,
    { method: method, redirect: "manual", headers: headers, body: o.body });
  log.debug("Leaving call().");
  return answer(r, jar);
}

// A GET as a browser's top-level navigation sends it: `/oauth2/logout`
// asks rather than signs out when a GET is not one (#1443).
async function navigate(url, jar, headers) {
  log.debug("Entering navigate(). " + url);
  const h = Object.assign({}, headers || {});
  if (jar && Object.keys(jar).length) {
    h.cookie = cookieOf(jar);
  }
  const r = await navigation.navigate(/^https?:/.test(url) ? url : RB + url,
                                      h);
  log.debug("Leaving navigate().");
  return answer(r, jar);
}

async function ok(url, payload, what) {
  log.debug("Entering ok().");
  const r = await call("POST", url, { headers: {
    "Content-Type": "application/json" }, body: JSON.stringify(payload) });
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

const S = { jar: {} };

// Sign in through the real screen in a new jar; answers the ID Token.
async function signIn() {
  log.debug("Entering signIn().");
  S.jar = {};
  let r = await call("GET", "/oauth2/authorize?" + form({
    client_id: "rl-rp", response_type: "code", redirect_uri: REDIRECT,
    scope: "openid", state: "st",
    nonce: "n-" + nodeCrypto.randomBytes(4).toString("hex") }), {}, S.jar);
  r = await authnSignin.signInWithJar(RB, r.location,
    { action: "login", username: PERSON, password: PASSWORD }, S.jar);
  for (let hops = 0; hops < 6 && (r.status === 302 || r.status === 303) &&
       String(r.location).indexOf(REDIRECT) !== 0; hops += 1) {
    r = await call("GET", /^https?:/.test(r.location) ? r.location
      : ORIGIN + r.location, {}, S.jar);
  }
  const code = new URL(r.location).searchParams.get("code");
  const t = await call("POST", "/oauth2/token", { headers: {
    "Content-Type": "application/x-www-form-urlencoded" },
    body: form({ grant_type: "authorization_code", code: code,
                 redirect_uri: REDIRECT, client_id: "rl-rp",
                 client_secret: SECRET }) });
  assert.ok(t.json && t.json.id_token, "no ID Token: " + t.text.slice(0,
                                                                     300));
  log.debug("Leaving signIn().");
  return t.json.id_token;
}

// Is the session alive? prompt=none answers a code if so.
async function alive() {
  log.debug("Entering alive().");
  const r = await call("GET", "/oauth2/authorize?" + form({
    client_id: "rl-rp", response_type: "code", redirect_uri: REDIRECT,
    scope: "openid", state: "st", prompt: "none", nonce: "n" }), {}, S.jar);
  log.debug("Leaving alive().");
  return /[?&]code=/.test(r.location);
}

function logout(params, extraHeaders) {
  log.debug("Entering logout().");
  log.debug("Leaving logout().");
  return navigate("/oauth2/logout?" + form(params || {}), S.jar,
                  extraHeaders);
}

function postLogout(fields, cookies) {
  log.debug("Entering postLogout().");
  log.debug("Leaving postLogout().");
  return call("POST", "/oauth2/logout", { cookies: cookies,
    headers: { "Content-Type": "application/x-www-form-urlencoded",
               Origin: ORIGIN },
    body: form(fields) }, S.jar);
}

function hiddenOf(text) {
  log.debug("Entering hiddenOf().");
  const fields = {};
  (String(text).match(/<input type="hidden"[^>]*>/g) || []).forEach(
    function (tag) {
      const name = /name="([^"]+)"/.exec(tag);
      const value = /value="([^"]*)"/.exec(tag);
      if (name) {
        fields[name[1]] = value ? value[1].replace(/&amp;/g, "&") : "";
      }
    });
  log.debug("Leaving hiddenOf().");
  return fields;
}

function whyOf(text) {
  log.debug("Entering whyOf().");
  log.debug("Leaving whyOf().");
  return ((/<\/form><p class="sub">([\s\S]*?)<\/p>/.exec(String(text)) ||
           [])[1] || "");
}

function boxOf(text) {
  log.debug("Entering boxOf().");
  log.debug("Leaving boxOf().");
  return (String(text).match(
    /<div class="warn" role="alert" id="logout-return-refused">[\s\S]*?<\/div>/) ||
    [""])[0];
}

function boxFor(sentence, uri) {
  log.debug("Entering boxFor().");
  log.debug("Leaving boxFor().");
  return '<div class="warn" role="alert" id="logout-return-refused">' +
    sentence.replace("{uri}", uri) + "</div>";
}

function leads(text) {
  log.debug("Entering leads().");
  const body = String(text);
  log.debug("Leaving leads().");
  return boxOf(body) !== "" &&
    body.indexOf(boxOf(body)) < body.indexOf('<form method="post"');
}

function emptyQuoted(text) {
  log.debug("Entering emptyQuoted().");
  log.debug("Leaving emptyQuoted().");
  return /<code>\s*<\/code>|""|\(\s*\)/.test(String(text));
}

async function validateSection() {
  log.debug("Entering validateSection().");
  log.info("=== a. validate before ending ===");
  await signIn();
  const first = await alive();
  check("a0. signed in, the session alive", function () {
    assert.ok(first);
  });
  let r = await logout({ post_logout_redirect_uri: "javascript:alert(1)" });
  let still = await alive();
  check("a1. a malformed sign-out is a 400 PAGE, and the session survives it",
        function () {
    assert.strictEqual(r.status, 400, r.text.slice(0, 200));
    assert.ok(/text\/html/.test(r.type));
    assert.ok(still);
  });
  r = await call("POST", "/oauth2/logout", { headers: {
    "content-type": "application/json", Origin: ORIGIN },
    body: '{"id_token_hint":"x"}' }, S.jar);
  still = await alive();
  check("a2. a POST that is not a form is refused, the session untouched",
        function () {
    assert.strictEqual(r.status, 400, r.text.slice(0, 200));
    assert.ok(still);
  });
  log.debug("Leaving validateSection().");
}

async function confirmSection() {
  log.debug("Entering confirmSection().");
  log.info("=== b. confirmation ===");
  let r = await logout({ client_id: "rl-rp", post_logout_redirect_uri: BACK,
                         state: "st-b" });
  let live = await alive();
  check("b1. no hint: a confirmation page with a real button and no script, " +
        "and the session alive", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 200));
    assert.ok(/name="confirm_for"/.test(r.text));
    assert.ok(/<button type="submit" name="confirm" value="yes"/.test(
      r.text));
    assert.ok(!/<script/i.test(r.text));
    assert.ok(live);
  });
  let why = whyOf(r.text);
  check("b1b. no hint, a client that registered the address: the page says " +
        "the request carried no id_token_hint", function () {
    assert.strictEqual(why, NO_HINT + SECTION);
    assert.ok(!emptyQuoted(why));
  });
  let w = await logout({ post_logout_redirect_uri:
                           "https://rp.rl.example/any", state: "s" });
  live = await alive();
  check("b1c. no hint and no client: the box first — not valid as sent, no " +
        "id_token_hint, the address not followed — then the question, and " +
        "no grey line repeating it", function () {
    assert.strictEqual(w.status, 200);
    assert.ok(!w.location);
    assert.strictEqual(boxOf(w.text), boxFor(BOX_NO_CLIENT,
                                             "https://rp.rl.example/any"));
    assert.ok(leads(w.text));
    assert.strictEqual(whyOf(w.text), "");
    assert.ok(/name="confirm_for"/.test(w.text));
    assert.ok(live);
  });
  const confirmed = await postLogout(Object.assign(hiddenOf(w.text),
                                                   { confirm: "yes" }));
  live = await alive();
  check("b1c-ii. and once confirmed: signed out, the page partly refused, " +
        "the same box, the diagnostics and the way back", function () {
    assert.strictEqual(confirmed.status, 200, confirmed.text.slice(0, 200));
    assert.ok(!confirmed.location);
    assert.strictEqual(boxOf(confirmed.text),
                       boxFor(BOX_NO_CLIENT, "https://rp.rl.example/any"));
    assert.ok(/<h1>Sign-out request partly refused<\/h1>/.test(
      confirmed.text));
    assert.ok(/<section class="diagnostics"/.test(confirmed.text));
    assert.ok(/href="[^"]*\/portal"/.test(confirmed.text));
    assert.ok(!live);
  });
  await signIn();
  w = await logout({ client_id: "rl-rp",
                     post_logout_redirect_uri: "https://evil.example/x" });
  check("b1d. no hint and an address the named client did not register: " +
        "the same box, its own reason, the address sent and never the " +
        "registered one", function () {
    assert.strictEqual(boxOf(w.text), boxFor(BOX_NOT_REGISTERED,
                                             "https://evil.example/x"));
    assert.ok(leads(w.text));
    assert.strictEqual(whyOf(w.text), "");
    assert.ok(w.text.indexOf(BACK) < 0);
  });
  const asked = hiddenOf((await logout({ client_id: "rl-rp",
    post_logout_redirect_uri: BACK, state: "st-b" })).text);
  w = await logout({});
  why = whyOf(w.text);
  live = await alive();
  check("b1e. no parameters at all: the page says the request carried no " +
        "id_token_hint, and names no address", function () {
    assert.strictEqual(w.status, 200);
    assert.strictEqual(why, NO_HINT + SECTION);
    assert.ok(!emptyQuoted(why));
    assert.ok(live);
  });
  w = await logout({ state: "only-state", client_id: "rl-rp" });
  check("b1f. only state and client_id: the same sentence", function () {
    assert.strictEqual(whyOf(w.text), NO_HINT + SECTION);
  });
  let d = await postLogout(Object.assign({}, asked, { confirm: "no" }));
  live = await alive();
  check("b2. \"Stay signed in\" keeps the session", function () {
    assert.strictEqual(d.status, 200);
    assert.ok(/still signed in/i.test(d.text));
    assert.ok(live);
  });
  d = await postLogout(Object.assign({}, asked, { confirm: "yes",
                                                  confirm_for: "forged" }));
  live = await alive();
  check("b3. a forged confirm_for is asked again", function () {
    assert.strictEqual(d.status, 200);
    assert.ok(/name="confirm_for"/.test(d.text));
    assert.ok(live);
  });
  const withCookie = Object.assign({}, S.jar);
  d = await postLogout({ client_id: "rl-rp" }, false);
  S.jar = withCookie;
  check("b4. a cross-site POST (no cookie) is asked, and no cookie is " +
        "cleared", function () {
    assert.strictEqual(d.status, 200);
    assert.ok(/name="confirm_for"/.test(d.text));
    assert.ok(d.setCookie.indexOf("sts_session=;") < 0, d.setCookie);
  });
  check("b4b. and the page says the request came without this browser's " +
        "sign-in cookie", function () {
    assert.strictEqual(whyOf(d.text), "This sign-out request arrived " +
      "without the sign-in cookie of this browser, as a form sent from " +
      "another site does, so this service cannot tell which session it is " +
      "for" + SECTION);
  });
  d = await postLogout(Object.assign({}, asked, { confirm: "yes" }));
  live = await alive();
  check("b5. the page's own form signs out and returns to the registered " +
        "address WITH state", function () {
    assert.strictEqual(d.status, 302, d.text.slice(0, 200));
    assert.ok(d.location.indexOf(BACK) === 0, d.location);
    assert.ok(/[?&]state=st-b(&|$)/.test(d.location));
    assert.ok(!live);
  });
  log.debug("Leaving confirmSection().");
}

async function hintSection() {
  log.debug("Entering hintSection().");
  log.info("=== c. the hint ===");
  let idToken = await signIn();
  let r = await logout({ id_token_hint: idToken,
                         post_logout_redirect_uri: BACK, state: "st-c" });
  let live = await alive();
  check("c1. a verified hint for this session signs out at once, with state",
        function () {
    assert.strictEqual(r.status, 302, r.text.slice(0, 200));
    assert.ok(r.location.indexOf(BACK) === 0);
    assert.ok(/state=st-c/.test(r.location));
    assert.ok(!live);
  });
  idToken = await signIn();
  const tampered = idToken.slice(0, -4) + (idToken.slice(-4) === "AAAA"
    ? "BBBB" : "AAAA");
  r = await logout({ id_token_hint: tampered });
  live = await alive();
  check("c2. a hint that does not verify is refused, the session survives",
        function () {
    assert.strictEqual(r.status, 400);
    assert.ok(live);
  });
  const parts = idToken.split(".");
  const reheaded = function (header) {
    return Buffer.from(JSON.stringify(header)).toString("base64url") + "." +
      parts[1] + ".";
  };
  r = await logout({ id_token_hint: reheaded({ alg: "none" }) });
  live = await alive();
  check("c2b. an alg-none hint is refused as unsigned, naming no empty key",
        function () {
    assert.strictEqual(r.status, 400);
    assert.ok(live);
    assert.ok(/is unsigned \(alg none\)/.test(r.text), r.text.slice(0, 400));
    assert.ok(!/key ""/.test(r.text));
  });
  const head = JSON.parse(Buffer.from(parts[0], "base64url").toString());
  delete head.kid;
  r = await logout({ id_token_hint: reheaded(head) + parts[2] });
  live = await alive();
  check("c2c. a signed hint with no kid is refused, quoting no empty key",
        function () {
    assert.strictEqual(r.status, 400);
    assert.ok(live);
    assert.ok(!/key ""/.test(r.text));
    assert.ok(!/\.\.(\s|<|$)/.test(r.text));
  });
  r = await logout({ id_token_hint: idToken, client_id: "rl-bare" });
  live = await alive();
  check("c3. a client_id the hint was not issued to is refused", function () {
    assert.strictEqual(r.status, 400);
    assert.ok(live);
  });
  r = await logout({ id_token_hint: idToken, logout_hint: "somebody-else" });
  live = await alive();
  check("c4. a logout_hint naming somebody else asks, even with the hint, " +
        "and says so", function () {
    assert.strictEqual(r.status, 200);
    assert.ok(/name="confirm_for"/.test(r.text));
    assert.ok(live);
    assert.strictEqual(whyOf(r.text), "The logout_hint in this sign-out " +
      "request names somebody other than the person signed in to this " +
      "browser" + SECTION);
  });
  const earlier = idToken;
  await signIn();
  r = await logout({ id_token_hint: earlier });
  live = await alive();
  check("c4c. a hint for another session asks, and the page says so",
        function () {
    assert.strictEqual(r.status, 200);
    assert.ok(/name="confirm_for"/.test(r.text));
    assert.strictEqual(whyOf(r.text), "The id_token_hint in this sign-out " +
      "request was issued to another session, not the one signed in to " +
      "this browser" + SECTION);
    assert.ok(live);
  });
  idToken = await signIn();
  r = await postLogout({ id_token_hint: idToken,
                         post_logout_redirect_uri: BACK });
  live = await alive();
  check("c5. POST, section 2's other method, with the hint: signed out",
        function () {
    assert.strictEqual(r.status, 302, r.text.slice(0, 200));
    assert.ok(!live);
  });
  log.debug("Leaving hintSection().");
}

async function returnSection() {
  log.debug("Entering returnSection().");
  log.info("=== d. the return ===");
  let idToken = await signIn();
  let r = await logout({ id_token_hint: idToken,
                         post_logout_redirect_uri: "https://evil.example/x" });
  let live = await alive();
  check("d1. a registered client is held to its own list: an address it did " +
        "not register is not followed, and the page says why", function () {
    assert.strictEqual(r.status, 200);
    assert.ok(!r.location);
    assert.ok(/so it is not followed/.test(r.text));
    assert.ok(!live);
  });
  const okAt = r.text.indexOf('<div class="ok">');
  check("d1b. the warning box sits above the \"signed out\" banner, the " +
        "registered address nowhere on the page, the heading and the title " +
        "naming the refusal (#1302, #1331)", function () {
    assert.strictEqual(boxOf(r.text), boxFor(BOX_NOT_REGISTERED,
                                             "https://evil.example/x"));
    assert.ok(okAt >= 0 && r.text.indexOf(boxOf(r.text)) < okAt);
    assert.ok(!/You were not returned/.test(r.text));
    assert.ok(/\.warn\{background:#fff8e1;border-left:4px solid #b26a00;/
      .test(r.text));
    assert.ok(/<h1>Sign-out request partly refused<\/h1>/.test(r.text));
    assert.ok(/<title>Sign-out request partly refused<\/title>/.test(r.text));
    assert.ok(r.text.indexOf(BACK) < 0);
  });
  idToken = await signIn();
  r = await logout({ id_token_hint: idToken,
                     post_logout_redirect_uri: BACK + "?extra=1" });
  live = await alive();
  check("d1c. a query added to the registered address: not followed, the " +
        "same box, the session ended", function () {
    assert.strictEqual(r.status, 200);
    assert.ok(!r.location);
    assert.ok(!live);
    assert.strictEqual(boxOf(r.text), boxFor(BOX_NOT_REGISTERED,
                                             BACK + "?extra=1"));
  });
  idToken = await signIn();
  r = await logout({ id_token_hint: idToken, ui_locales: "fr",
                     post_logout_redirect_uri: "https://evil.example/x" });
  live = await alive();
  check("d1d. ui_locales=fr: the box and the heading in French, the " +
        "addresses as they are", function () {
    assert.strictEqual(r.status, 200);
    assert.ok(!live);
    assert.ok(boxOf(r.text).indexOf(BOX_FR) > 0, boxOf(r.text));
    assert.ok(boxOf(r.text).indexOf("<code>https://evil.example/x</code>") >
              0);
    assert.ok(r.text.indexOf(BACK) < 0);
    assert.ok(/<h1>Demande de déconnexion refusée en partie<\/h1>/.test(
      r.text));
  });
  S.jar = {};
  r = await logout({ client_id: "rl-bare",
                     post_logout_redirect_uri: "https://rp.rl.example/any",
                     state: "s" });
  check("d2. no session, a client that registered none: development follows " +
        "it straight back, with state", function () {
    assert.strictEqual(r.status, 302, r.text.slice(0, 200));
    assert.strictEqual(r.location, "https://rp.rl.example/any?state=s");
  });
  r = await logout({ post_logout_redirect_uri: "com.example.rl:/out" });
  check("d3. a private-use address nobody registered is not followed",
        function () {
    assert.strictEqual(r.status, 200);
    assert.ok(!r.location);
  });
  r = await logout({ post_logout_redirect_uri: "https://rp.rl.example/any",
                     state: "s" });
  check("d3b. an https address with no client named is not followed in " +
        "development either (STS-OAUTH-0785), and the page says why",
        function () {
    assert.strictEqual(r.status, 200);
    assert.ok(!r.location);
    assert.ok(/neither an id_token_hint nor/.test(r.text));
  });
  r = await logout({});
  check("d4. with nowhere to return, a page — not text/plain \"mock\"",
        function () {
    assert.strictEqual(r.status, 200);
    assert.ok(/text\/html/.test(r.type));
    assert.ok(!/mock/i.test(r.text));
  });
  log.debug("Leaving returnSection().");
}

function authorize(params, accept) {
  log.debug("Entering authorize().");
  const q = Object.assign({ client_id: "rl-rp", response_type: "code",
                            scope: "openid", state: "st", nonce: "n" },
                          params);
  // A member given as null is left out of the request altogether.
  Object.keys(q).forEach(function (k) {
    if (q[k] === null) {
      delete q[k];
    }
  });
  log.debug("Leaving authorize().");
  return call("GET", "/oauth2/authorize?" + form(q),
    { headers: accept ? { accept: accept } : {} }, {});
}

function incidentOf(text) {
  log.debug("Entering incidentOf().");
  const m = /<dt>[^<]*<\/dt><dd><code>(\d+)<\/code><\/dd>/
    .exec(String(text).slice(String(text).indexOf('class="diagnostics"')));
  log.debug("Leaving incidentOf().");
  return m ? Number(m[1]) : 0;
}

function shaped(text) {
  log.debug("Entering shaped().");
  const body = String(text);
  const box = body.indexOf('<div class="warn" role="alert">');
  const more = body.indexOf('<details class="prose">');
  const portal = body.search(/href="[^"]*\/portal"/);
  const diag = body.indexOf('<section class="diagnostics"');
  log.debug("Leaving shaped().");
  return box > 0 && more > box && portal > more && diag > portal &&
    /<form class="language-chooser"/.test(body) && !/<script/i.test(body);
}

async function auditEvents() {
  log.debug("Entering auditEvents().");
  const r = await call("GET", "/admin-api/audit?per=500");
  log.debug("Leaving auditEvents().");
  return (r.json && (r.json.events || r.json.rows)) || [];
}

async function authorizeSection() {
  log.debug("Entering authorizeSection().");
  log.info("=== e. the authorization endpoint's own refusals ===");
  const HTML = "text/html,application/xhtml+xml,*/*;q=0.8";
  const WRONG = "https://rp.rl.example/elsewhere";
  const SENTENCE = "'" + WRONG + "' is not a redirect URI registered for " +
    "this client";
  const plain = await authorize({ redirect_uri: WRONG });
  const page = await authorize({ redirect_uri: WRONG }, HTML);
  const described = String((plain.json || {}).error_description || "");
  check("e1. an unregistered redirect_uri is a 400, never redirected, and " +
        "says it is not a redirect URI registered for this client, with no " +
        "directory detail", function () {
    assert.strictEqual(plain.status, 400);
    assert.ok(!plain.location);
    assert.strictEqual(plain.json.error, "invalid_request");
    assert.ok(described.indexOf(SENTENCE) >= 0, described);
    assert.ok(described.indexOf(REDIRECT) < 0);
    assert.ok(!/the 1 |\(s\)|ou=|oauthRedirectUri|none of/.test(described));
  });
  check("e2. and a browser is shown that refusal on the error page, with " +
        "the same status, error and description", function () {
    assert.strictEqual(page.status, 400);
    assert.ok(!page.location);
    assert.ok(/text\/html/.test(page.type));
    assert.ok(/<h1>This request could not be completed<\/h1>/.test(
      page.text));
    assert.ok(page.text.indexOf("invalid_request") >= 0);
    assert.ok(page.text.replace(/&#39;|&#x27;|&apos;/g, "'")
      .indexOf(SENTENCE) >= 0);
    assert.ok(page.text.indexOf(REDIRECT) < 0);
  });
  const NONE = "This authorization request has no redirect_uri, and one is " +
    "required: without it there is nowhere to send the response.";
  const none = await authorize({}, HTML);
  const noneJson = await authorize({});
  check("e3. no redirect_uri: the error page for a browser, the JSON " +
        "otherwise, both 400 invalid_request, saying the request has none",
        function () {
    assert.strictEqual(none.status, 400);
    assert.ok(!none.location);
    assert.ok(/text\/html/.test(none.type));
    assert.ok(none.text.indexOf(NONE) >= 0);
    assert.strictEqual(noneJson.status, 400);
    assert.strictEqual(noneJson.json.error, "invalid_request");
    assert.strictEqual(noneJson.json.error_description, NONE);
  });
  const empty = await authorize({ redirect_uri: "" });
  const bad = await authorize({ redirect_uri: "not a uri" });
  check("e3b. one that is present and empty keeps \"A valid absolute " +
        "redirect_uri is required.\", and a malformed one keeps its own " +
        "sentence; neither says the request has none", function () {
    assert.strictEqual(empty.status, 400);
    assert.strictEqual(empty.json.error_description,
                       "A valid absolute redirect_uri is required.");
    assert.strictEqual(bad.status, 400);
    assert.strictEqual(bad.json.error, "invalid_request");
    assert.ok(String(bad.json.error_description).indexOf(NONE) < 0);
    assert.ok(String(bad.json.error_description).length > 0);
  });
  const noNonce = await authorize({ response_type: "id_token",
                                    redirect_uri: REDIRECT, nonce: null });
  const noNonceAt = decodeURIComponent(noNonce.location + " " +
                                       noNonce.text).replace(/\+/g, " ");
  check("e4. an implicit request with no nonce is told it has none",
        function () {
    assert.ok(/This request has no nonce, and response_type .id_token. returns an ID Token from the authorization endpoint, for which OIDC Core makes nonce REQUIRED \(section 3\.2\.2\.1, the implicit flow\)/
      .test(noNonceAt), noNonceAt.slice(0, 400));
  });
  const e5 = await authorize({ redirect_uri: WRONG, state: "st-e5",
                               nonce: "n-e5" }, HTML);
  const e5Id = incidentOf(e5.text);
  const events = await auditEvents();
  const e5Row = events.filter(function (row) {
    return row.seq === e5Id;
  })[0];
  check("e5. the refusal page: the box, then the background collapsed, the " +
        "portal, the diagnostics with the state, nonce and client, and an " +
        "incident ID that is the seq of the request's own audit row",
        function () {
    assert.strictEqual(e5.status, 400);
    assert.ok(shaped(e5.text), e5.text.slice(-800));
    assert.ok(e5Id > 0);
    assert.ok(e5Row, "no audit row " + e5Id);
    assert.strictEqual(e5Row.target, "/realm/" + REALM + "/oauth2/authorize");
    assert.ok(!!e5Row.errorCode);
    assert.ok(/<code>st-e5<\/code>/.test(e5.text));
    assert.ok(/<code>n-e5<\/code>/.test(e5.text));
    assert.ok(/<code>rl-rp<\/code>/.test(e5.text));
  });
  const seqs = events.map(function (row) {
    return Number(row.seq);
  });
  check("e5b. and the ring's numbers rise in the order the rows were written " +
        "(newest first here), which the audit export's cursor relies on",
        function () {
    assert.ok(seqs.every(function (n, i) {
      return i === 0 || n < seqs[i - 1];
    }), seqs.slice(0, 8).join(","));
  });
  const e6 = await authorize({ redirect_uri: WRONG, ui_locales: "fr" }, HTML);
  check("e6. ui_locales=fr: the refusal page in French, frame and message",
        function () {
    assert.strictEqual(e6.status, 400);
    assert.ok(/<html lang="fr"/.test(e6.text));
    assert.ok(e6.text.indexOf("Cette demande n’a pas pu aboutir") > 0);
    assert.ok(e6.text.indexOf("Diagnostics") > 0);
    assert.ok(e6.text.indexOf("Accéder à votre compte") > 0);
  });
  const e9Query = { request: "x.y.z",
                    request_uri: "https://rp.rl.example/r" };
  const e9 = await authorize(e9Query, HTML);
  const e9Json = await authorize(e9Query);
  check("e9. both request and request_uri: the page for a browser, saying " +
        "so in its own sentence (STS-OAUTH-0341); the JSON otherwise",
        function () {
    assert.strictEqual(e9.status, 400);
    assert.ok(shaped(e9.text));
    assert.ok(e9.text.indexOf("This request carries both request and " +
      "request_uri. A request object is sent by value or by reference, not " +
      "both (RFC 9101 section 5).") > 0, e9.text.slice(0, 400));
    assert.strictEqual(e9Json.status, 400);
    assert.strictEqual(e9Json.json.error, "invalid_request");
  });
  const idToken = await signIn();
  const tampered = idToken.slice(0, -4) + (idToken.slice(-4) === "AAAA"
    ? "BBBB" : "AAAA");
  const e8 = await logout({ id_token_hint: tampered, ui_locales: "fr",
                            state: "st-e8" });
  const live = await alive();
  check("e8. a refused sign-out: the same page, in French, the state and " +
        "the person signed in among the diagnostics, the session alive",
        function () {
    assert.strictEqual(e8.status, 400);
    assert.ok(live);
    assert.ok(shaped(e8.text), e8.text.slice(-800));
    assert.ok(incidentOf(e8.text) > 0);
    assert.ok(e8.text.indexOf("Cette demande de déconnexion a été " +
                              "refusée") > 0);
    assert.ok(/<code>st-e8<\/code>/.test(e8.text));
    assert.ok(e8.text.indexOf("<code>" + PERSON + "</code>") > 0);
  });
  log.debug("Leaving authorizeSection().");
}

async function screenAfter(extra) {
  log.debug("Entering screenAfter().");
  const asked = await call("GET", "/oauth2/authorize?" + form(Object.assign({
    client_id: "rl-rp", response_type: "code", redirect_uri: REDIRECT,
    scope: "openid", state: "st", nonce: "n-f" }, extra || {})), {}, S.jar);
  if (!/\/authn\/login\?/.test(asked.location)) {
    log.debug("Leaving screenAfter(). No screen.");
    return { at: asked.location, view: null };
  }
  const opened = await authnSignin.screen(RB, asked.location,
                                          { cookie: cookieOf(S.jar) });
  log.debug("Leaving screenAfter().");
  return { at: asked.location, view: opened.view || null };
}

async function reasonSection() {
  log.debug("Entering reasonSection().");
  log.info("=== f. the second sign-in's reason ===");
  S.jar = {};
  let f = await screenAfter({});
  check("f1. a first sign-in: no reason in the view", function () {
    assert.ok(f.view, f.at);
    assert.strictEqual(f.view.reauthentication, "");
  });
  f = await screenAfter({ prompt: "login" });
  check("f1b. prompt=login with no session is a first sign-in too",
        function () {
    assert.ok(f.view, f.at);
    assert.strictEqual(f.view.reauthentication, "");
  });
  await signIn();
  f = await screenAfter({ prompt: "login" });
  check("f2. prompt=login with a session: the view names the application's " +
        "request for a second sign-in", function () {
    assert.ok(f.view, f.at);
    assert.strictEqual(f.view.reauthentication, "prompt_login");
  });
  f = await screenAfter({ prompt: "select_account" });
  check("f3. prompt=select_account: the account picker, as it was",
        function () {
    assert.ok(!f.view);
    assert.ok(/\/authn\/accounts\?/.test(f.at), f.at);
  });
  f = await screenAfter({ max_age: "3600" });
  check("f4. a max_age the session meets: answered at once", function () {
    assert.ok(!f.view);
    assert.ok(/[?&]code=/.test(f.at) && f.at.indexOf(REDIRECT) === 0, f.at);
  });
  await new Promise(function (done) {
    setTimeout(done, 2100);
  });
  f = await screenAfter({ max_age: "1" });
  check("f5. a session older than max_age: the view says so", function () {
    assert.ok(f.view, f.at);
    assert.strictEqual(f.view.reauthentication, "max_age");
  });
  log.debug("Leaving reasonSection().");
}

async function test() {
  log.debug("Entering test().");
  await ok(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "RP logout sessions " + STAMP },
    "created the realm");
  await setting("global.mode", "development");
  // RISK SCORING (#62) is off for sts_admin_client_policies.js's reason.
  await setting("risk.assessSignIns", false);
  await setting("oauth2.consentRequired", false);
  await registry.ensurePerson(RB, PERSON, PASSWORD);
  for (const one of [["rl-rp", { oauthPostLogoutRedirectUri: [BACK] }],
                     ["rl-bare", {}]]) {
    await ok(RB + "/admin-api/applications/create", { identifier: one[0],
      name: one[0], protocols: ["oauth2", "oidc"],
      fields: Object.assign({ oauthClientId: [one[0]],
        oauthClientSecret: SECRET, oauthRedirectUri: [REDIRECT],
        oauthTokenEndpointAuthMethod: "client_secret_post" }, one[1]) },
      "created " + one[0]);
  }
  await validateSection();
  await confirmSection();
  await hintSection();
  await returnSection();
  await authorizeSection();
  await reasonSection();
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
  const r = await call("POST", base + "/admin-api/realms/remove", {
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
