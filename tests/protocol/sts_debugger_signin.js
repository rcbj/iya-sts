// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_debugger_signin.js
//
// ===========================================================================
// THE EMBEDDED DEBUGGER'S SIGN-IN, OVER THE WIRE, AND THE RULE THAT ITS GATE
// NEVER USES THE `Authorization` HEADER (#1717, 2026-11-18).
//
// rcbj: "Add one test to confirm basic login of the embedded debugger by the
// default realm admin. Have it validate that the authorization header is not
// used directly by session management."
//
// Since #1717 the debugger listener (`debugger/debugger_server.ts`) admits
// one credential: its own relying-party session, named by the HttpOnly
// `sts_debugger` cookie, belonging to somebody who is a console administrator
// of the DEFAULT realm at that request. `Authorization` and `DPoP` are the
// debugger's own WORK — a UserInfo Bearer token, introspection's Basic
// credentials — and are passed to the api child untouched. In-process,
// `tests/debugger_server.js` holds that against a stand-in api with sessions
// minted by hand; this job is the half it says it does not drive: the real
// sign-in through the authorization server, the real api child of the image's
// embedded tree, and what each header DOES once it gets there.
//
//   A. THE SIGN-IN. A default-realm console administrator (a person of this
//      job's own, holding Admin Read and Admin Write) opens the debugger with
//      no session: sent to /oauth2/authorize as `sts-debugger-ui` with its
//      callback on the debugger's origin, signs in at the sign-in screen,
//      comes back to `/_sts/callback`, is answered the HttpOnly
//      `sts_debugger` cookie, and then loads the UI, its own account page
//      naming them, and `/api/healthcheck` from the real api child.
//   B. A TOKEN IS NOT A SESSION. With NO cookie, a valid Bearer access token
//      for that administrator and, separately, a valid DPoP-bound one with a
//      good proof, are refused 401 at `/api` with no `WWW-Authenticate`, and
//      a page with a Bearer token is sent to sign in rather than served.
//   C. A HEADER THE GATE DOES NOT READ CANNOT BREAK THE SESSION. With the
//      cookie, `Authorization: Basic <junk>`, `Bearer garbage` and the
//      administrator's own valid Bearer token each still answer 200 as the
//      session's person, and the session is intact afterwards.
//   D. THE HEADER REACHES THE API CHILD UNCHANGED, AND THE CHILD USES IT.
//      `/api/userinfo` forwards the `Authorization` it is given to the
//      UserInfo endpoint it is told to call — this service's own. Through
//      the debugger with the session, the administrator's Bearer token
//      answers that person's claims (the same `sub` a direct call answers),
//      and `Bearer garbage` answers UserInfo's own 401 invalid_token. The
//      claims could only have come from the header arriving intact.
//   E. A DPoP PROOF IS NOT CONSUMED ON THE WAY. A proof made for this
//      service's token endpoint is sent through the debugger first, then
//      presented at the token endpoint, where it is accepted (no replay);
//      presented there a second time it IS a replay — so the endpoint does
//      keep the history, and the debugger did not write to it.
//   F. A ROLE REVOKED IS A SESSION REFUSED, at the next request (403), with
//      the cookie unchanged — the gate asks who the person is now, every
//      time.
//
// ---------------------------------------------------------------------------
// WHO "THE DEFAULT REALM ADMIN" IS HERE, AND WHY IT IS NOT THE SEEDED `admin`.
//
// The person is created in the DEFAULT realm with a password only this
// process holds and is GRANTED Admin Read and Admin Write — a real member of
// both roster groups, which is what `debugger_access.ts` asks (a role held
// only through the empty-roster window is refused, STS-DBG-0024). The seeded
// bootstrap `admin` is not used because signing it in to the default realm
// CLAIMS that realm's console, which closes development's open window for
// every job after this one, and its seeded password is forced to change
// (`sts_admin_bootstrap.js` does its bootstrap work in throwaway realms for
// the same reason). The debugger lives only in the default realm, so a
// throwaway realm is not available here.
//
// ---------------------------------------------------------------------------
// WHERE IT RUNS. `debugger.enabled` is `auto`: on in development, off in
// product (`mode.embedsProtocolDebugger()`, decision 7). So the job asks
// `GET /admin-api/debugger` and DECLINES TO RUN (a skip, with the reason)
// when the debugger is not embedded — every product mode — or when the image
// carries no embedded tree (built with `DEBUGGER_IMAGE=debugger-none`). An
// embedded debugger whose listener did not bind, or whose api child never
// starts, is a FAILURE. The listener is reached on the service's host at the
// port the view reports (`STS_TEST_DEBUGGER_URL` overrides): in the test
// stack that is `https://sts:8444`, on the compose network, unpublished.
//
// WHAT IT LEAVES. Its person loses both roles in F whatever happens after.
// On a pass its client and its person are deleted; on a failure they are
// left standing to be looked at, as the suite leaves a failed job's realms.
//
// WHAT IS NOT OBSERVABLE HERE, said plainly: that `DPoP` reaches the api
// child unchanged. No route of the debugger's api forwards a `DPoP` header
// anywhere a job can see it (UserInfo forwards `Authorization` only), so E
// proves the proof was not CONSUMED, and the passing-through itself is
// `tests/debugger_server.js`'s, against its stand-in api. Nor is
// introspection's Basic credential: a JSON introspection request is not
// authenticated in development (`oauth-oidc/CLAUDE.md` 3ai), so a forwarded
// Basic header and a missing one answer alike.
//
// OWNED HERE (local: true): this repository's debugger listener, its gate,
// its sign-in and its authorization server.
// ===========================================================================

const assert = require("assert");
const nodeCrypto = require("crypto");
const names = require("./random_username.js");
const consoleSignIn = require("./console_signin.js");
const authnSignin = require("./authn_signin.js");
const expectation = require("./expectation.js");

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
var log = bunyan.createLogger({ name: "sts_debugger_signin",
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
const USER = "dbgsignin" + STAMP;
const CLIENT = "dbg-signin-" + STAMP;
const SECRET = "dbg-signin-" + nodeCrypto.randomBytes(16).toString("hex");
// Never fetched: the code is read off the authorization endpoint's Location.
const CLIENT_REDIRECT = "https://dbg-signin.invalid/cb";
// The debugger's own cookie, by its inside name or its wire name (#1441).
const SESSION_COOKIE = /^(?:__Host-|__Secure-)?sts_debugger$/;
const FLOOR = 20;

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function b64u(buffer) {
  log.debug("Entering b64u().");
  log.debug("Leaving b64u().");
  return Buffer.from(buffer).toString("base64url");
}

// One request, answered with its status, headers, text and JSON (or null),
// redirects NOT followed — every hop of a sign-in is a thing asserted.
async function call(method, url, headers, body) {
  log.debug("Entering call(). " + method + " " + url);
  const r = await fetch(url, { method: method, redirect: "manual",
                               headers: headers || {}, body: body });
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in call(): " + ((e && e.message) || e));
    // Not JSON — a page, or nothing; `text` carries it.
    json = null;
  }
  log.debug("Leaving call(). " + r.status);
  return { status: r.status, headers: r.headers, text: text, json: json,
           setCookies: r.headers.getSetCookie ? r.headers.getSetCookie() : [] };
}

// A POST to the management API; the run's token is attached by the runner's
// preload (tests/tools/attach-admin-token.js).
async function adminPost(path, payload) {
  log.debug("Entering adminPost(). " + path);
  const r = await call("POST", base + "/admin-api" + path,
                       { "Content-Type": "application/json" },
                       JSON.stringify(payload));
  log.debug("Leaving adminPost(). " + r.status);
  return r;
}

// A P-256 key and the RFC 9449 proofs it signs, with node's crypto.
function dpopKey() {
  log.debug("Entering dpopKey().");
  const pair = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = pair.publicKey.export({ format: "jwk" });
  log.debug("Leaving dpopKey().");
  return {
    proof: function proof(method, url, accessToken) {
      log.debug("Entering proof().");
      const header = { typ: "dpop+jwt", alg: "ES256",
                       jwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x,
                              y: jwk.y } };
      const claims = { jti: b64u(nodeCrypto.randomBytes(16)), htm: method,
                       htu: String(url).replace(/[?#].*$/, ""),
                       iat: Math.floor(Date.now() / 1000) };
      if (accessToken) {
        claims.ath = b64u(nodeCrypto.createHash("sha256")
          .update(accessToken).digest());
      }
      const input = b64u(JSON.stringify(header)) + "." +
                    b64u(JSON.stringify(claims));
      const signature = nodeCrypto.sign("sha256", Buffer.from(input),
        { key: pair.privateKey, dsaEncoding: "ieee-p1363" });
      log.debug("Leaving proof().");
      return input + "." + b64u(signature);
    }
  };
}

// ---------------------------------------------------------------------------
// WHETHER THIS SERVICE EMBEDS THE DEBUGGER, AND WHERE IT ANSWERS.
// ---------------------------------------------------------------------------
async function debuggerStatus() {
  log.debug("Entering debuggerStatus().");
  const r = await call("GET", base + "/admin-api/debugger",
                       { Accept: "application/json" });
  expectation.mustBeAbleTo(r.status === 200 && r.json,
    "The service at " + base, "answered GET /admin-api/debugger " +
    r.status + " " + r.text.slice(0, 300));
  log.debug("Leaving debuggerStatus().");
  return r.json;
}

// The api child is forked at start and may still be coming up.
async function waitForApi(status) {
  log.debug("Entering waitForApi().");
  let seen = status;
  for (let i = 0; i < 120 && !(seen.api && seen.api.state === "running");
       i++) {
    if (seen.api && seen.api.state === "given-up") {
      break;
    }
    await new Promise(function (resolve) {
      setTimeout(resolve, 500);
    });
    seen = await debuggerStatus();
  }
  log.debug("Leaving waitForApi(). " + (seen.api && seen.api.state));
  return seen;
}

function debuggerBaseFrom(status) {
  log.debug("Entering debuggerBaseFrom().");
  const pinned = String(process.env.STS_TEST_DEBUGGER_URL || "").trim();
  if (pinned) {
    log.debug("Leaving debuggerBaseFrom(). Pinned.");
    return pinned.replace(/\/+$/, "");
  }
  const u = new URL(base);
  log.debug("Leaving debuggerBaseFrom().");
  return (status.scheme || "https") + "://" + u.hostname + ":" + status.port;
}

// ---------------------------------------------------------------------------
// A. THE SIGN-IN, AS A BROWSER MAKES IT.
// ---------------------------------------------------------------------------
async function signInThroughTheDebugger(dbg, password, cookies) {
  log.debug("Entering signInThroughTheDebugger().");
  log.info("=== A. a default-realm console administrator signs in to the " +
           "debugger ===");
  async function hop(url, headers) {
    log.debug("Entering hop(). " + url);
    const r = await call("GET", url, Object.assign(
      { cookie: cookies.header(), Accept: "text/html" }, headers || {}));
    cookies.keep(r);
    log.debug("Leaving hop(). " + r.status);
    return r;
  }

  const first = await hop(dbg + "/");
  const toAuthorize = new URL(String(first.headers.get("location") || ""),
                              dbg + "/");
  check("A. the debugger with no session sends the browser to this " +
        "service's authorization endpoint as sts-debugger-ui, its callback " +
        "on the debugger's own origin", function () {
    assert.ok(first.status === 302 || first.status === 303,
              "GET / answered " + first.status + " " +
              first.text.slice(0, 200));
    assert.strictEqual(toAuthorize.pathname, "/oauth2/authorize",
                       toAuthorize.toString());
    assert.strictEqual(toAuthorize.searchParams.get("client_id"),
                       "sts-debugger-ui");
    assert.strictEqual(toAuthorize.searchParams.get("response_type"),
                       "code");
    assert.strictEqual(toAuthorize.searchParams.get("redirect_uri"),
                       dbg + "/_sts/callback");
  });

  const atAuthorize = await hop(toAuthorize.toString());
  const screen = new URL(String(atAuthorize.headers.get("location") || ""),
                         toAuthorize);
  assert.ok(/[?&#]authn=/.test(screen.toString()),
            "the authorization endpoint should send a browser with no " +
            "sign-on session to the sign-in screen; it answered " +
            atAuthorize.status + " to \"" + screen + "\"");
  const signedIn = await authnSignin.signIn(toAuthorize.origin,
    screen.toString(),
    { action: "login", username: USER, password: password },
    { cookie: cookies.header() });
  cookies.keep(signedIn);
  check("A. the sign-in screen accepts the administrator's password and " +
        "sends the browser back", function () {
    assert.strictEqual(signedIn.next, "redirect",
                       signedIn.status + " " + signedIn.next + " " +
                       JSON.stringify(signedIn.errors));
  });

  // Back through the authorization endpoint, now with a sign-on session,
  // until it answers the debugger's callback. Bounded, so a loop fails as a
  // loop.
  let where = new URL(String(signedIn.location), toAuthorize);
  let last = null;
  for (let i = 0; i < 6 && where.origin + where.pathname !==
       dbg + "/_sts/callback"; i++) {
    if (authnSignin.isConsent(where.toString())) {
      const consented = await authnSignin.consentFor(where.toString(),
                                                     cookies.header());
      cookies.keep(consented);
      where = new URL(String(consented.location || ""), where);
      continue;
    }
    last = await hop(where.toString());
    where = new URL(String(last.headers.get("location") || ""), where);
  }
  check("A. the authorization endpoint answers the debugger's callback " +
        "with a code and the state it was sent", function () {
    assert.strictEqual(where.origin + where.pathname, dbg + "/_sts/callback",
                       (last ? last.status : "") + " " + where.toString());
    assert.ok(where.searchParams.get("code"), where.toString());
    assert.strictEqual(where.searchParams.get("state"),
                       toAuthorize.searchParams.get("state"));
  });

  const back = await hop(where.toString());
  const line = back.setCookies.filter(function (one) {
    return SESSION_COOKIE.test(String(one).split("=")[0]);
  })[0] || "";
  check("A. the callback redeems the code on this side, answers the " +
        "HttpOnly sts_debugger cookie and returns to the page asked for",
        function () {
    assert.ok(back.status === 303 || back.status === 302,
              "the callback answered " + back.status + " " +
              back.text.slice(0, 300));
    assert.strictEqual(new URL(String(back.headers.get("location")),
                               dbg + "/").pathname, "/");
    assert.ok(line, "no sts_debugger cookie among " +
              JSON.stringify(back.setCookies.map(function (one) {
                return String(one).split("=")[0];
              })));
    assert.ok(/;\s*HttpOnly/i.test(line), "not HttpOnly: " +
              line.replace(/=[^;]*/, "=…"));
  });
  log.debug("Leaving signInThroughTheDebugger().");
}

async function theSessionOpensTheDebugger(dbg, cookies) {
  log.debug("Entering theSessionOpensTheDebugger().");
  const page = await call("GET", dbg + "/",
                          { cookie: cookies.header(), Accept: "text/html" });
  check("A. with the session the debugger's UI is served, the placeholder " +
        "for this service's URL substituted", function () {
    assert.strictEqual(page.status, 200, page.text.slice(0, 300));
    assert.ok(/text\/html/.test(String(page.headers.get("content-type"))),
              String(page.headers.get("content-type")));
    assert.ok(page.text.indexOf("__STS_EMBED_STS_URL__") < 0,
              "the placeholder was served as it stands");
  });
  const account = await call("GET", dbg + "/_sts/",
                             { cookie: cookies.header(),
                               Accept: "text/html" });
  check("A. the debugger's own account page names the person the session " +
        "belongs to", function () {
    assert.strictEqual(account.status, 200, account.text.slice(0, 300));
    assert.ok(account.text.indexOf("<code>" + USER + "</code>") >= 0,
              account.text.slice(0, 400));
  });
  const health = await call("GET", dbg + "/api/healthcheck",
                            { cookie: cookies.header() });
  check("A. and /api reaches the real api child", function () {
    assert.strictEqual(health.status, 200, health.text.slice(0, 300));
    assert.strictEqual(health.json && health.json.message, "Success",
                       health.text.slice(0, 300));
  });
  log.debug("Leaving theSessionOpensTheDebugger().");
}

// ---------------------------------------------------------------------------
// THE ADMINISTRATOR'S OWN ACCESS TOKENS, FROM A CLIENT OF THIS JOB'S, ON THE
// SAME SIGN-ON SESSION THE DEBUGGER'S SIGN-IN MADE.
// ---------------------------------------------------------------------------
async function codeFor(cookies) {
  log.debug("Entering codeFor().");
  const verifier = b64u(nodeCrypto.randomBytes(32));
  const state = b64u(nodeCrypto.randomBytes(16));
  let where = new URL(base + "/oauth2/authorize?" + new URLSearchParams({
    response_type: "code", client_id: CLIENT, redirect_uri: CLIENT_REDIRECT,
    scope: "openid profile", state: state,
    nonce: b64u(nodeCrypto.randomBytes(16)),
    code_challenge: b64u(nodeCrypto.createHash("sha256").update(verifier)
      .digest()),
    code_challenge_method: "S256" }).toString());
  let last = null;
  for (let i = 0; i < 6 && where.origin !== new URL(CLIENT_REDIRECT).origin;
       i++) {
    if (authnSignin.isConsent(where.toString())) {
      const consented = await authnSignin.consentFor(where.toString(),
                                                     cookies.header());
      cookies.keep(consented);
      where = new URL(String(consented.location || ""), where);
      continue;
    }
    last = await call("GET", where.toString(),
                      { cookie: cookies.header(), Accept: "text/html" });
    cookies.keep(last);
    where = new URL(String(last.headers.get("location") || ""), where);
  }
  const code = where.searchParams.get("code");
  assert.ok(code && where.searchParams.get("state") === state,
            "the administrator's sign-on session should answer " + CLIENT +
            "'s authorization request with a code; it answered " +
            (last ? last.status : "") + " to \"" + where + "\"");
  log.debug("Leaving codeFor().");
  return { code: code, verifier: verifier };
}

function tokenRequest(fields, proof) {
  log.debug("Entering tokenRequest().");
  const headers = { "Content-Type": "application/x-www-form-urlencoded" };
  if (proof) {
    headers.DPoP = proof;
  }
  log.debug("Leaving tokenRequest().");
  return call("POST", base + "/oauth2/token", headers,
              new URLSearchParams(Object.assign({ client_id: CLIENT,
                client_secret: SECRET }, fields)).toString());
}

async function redeem(issued, proof) {
  log.debug("Entering redeem().");
  log.debug("Leaving redeem().");
  return tokenRequest({ grant_type: "authorization_code", code: issued.code,
                        redirect_uri: CLIENT_REDIRECT,
                        code_verifier: issued.verifier }, proof);
}

// ---------------------------------------------------------------------------
// B. A TOKEN IS NOT A SESSION.
// ---------------------------------------------------------------------------
async function aTokenIsNotASession(dbg, bearer, bound, key) {
  log.debug("Entering aTokenIsNotASession().");
  log.info("=== B. with no session, the administrator's own tokens open " +
           "nothing ===");
  const noChallenge = function (r) {
    log.debug("Entering noChallenge().");
    assert.strictEqual(r.status, 401, r.status + " " + r.text.slice(0, 300));
    assert.strictEqual(r.json && r.json.error, "unauthorized",
                       r.text.slice(0, 300));
    assert.strictEqual(r.headers.get("www-authenticate"), null,
                       "a challenge names a scheme the gate does not take");
    log.debug("Leaving noChallenge().");
  };
  const viaBearer = await call("GET", dbg + "/api/healthcheck",
                               { Authorization: "Bearer " + bearer });
  check("B. a valid Bearer access token for the administrator, with no " +
        "session cookie, is refused 401 with no challenge", function () {
    noChallenge(viaBearer);
  });
  const viaDpop = await call("GET", dbg + "/api/healthcheck",
    { Authorization: "DPoP " + bound,
      DPoP: key.proof("GET", dbg + "/api/healthcheck", bound) });
  check("B. so is a valid DPoP-bound access token for the administrator " +
        "with a good proof", function () {
    noChallenge(viaDpop);
  });
  const page = await call("GET", dbg + "/",
                          { Authorization: "Bearer " + bearer,
                            Accept: "text/html" });
  check("B. and a page asked for with a Bearer token and no session is " +
        "sent to sign in, not served", function () {
    assert.ok(page.status === 302 || page.status === 303,
              page.status + " " + page.text.slice(0, 200));
    assert.strictEqual(new URL(String(page.headers.get("location")),
                               dbg + "/").pathname, "/oauth2/authorize");
  });
  log.debug("Leaving aTokenIsNotASession().");
}

// ---------------------------------------------------------------------------
// C. WITH THE SESSION, NO Authorization HEADER IS READ AS A CREDENTIAL.
// ---------------------------------------------------------------------------
async function aHeaderCannotBreakTheSession(dbg, cookies, bearer) {
  log.debug("Entering aHeaderCannotBreakTheSession().");
  log.info("=== C. with the session, Authorization is not the gate's ===");
  const cases = [
    ["Basic " + Buffer.from("not-a-client:not-a-secret").toString("base64"),
     "a Basic header naming no client"],
    ["Bearer garbage", "a Bearer token that is not one"],
    ["Bearer " + bearer, "the administrator's own valid Bearer token"]
  ];
  for (const one of cases) {
    const r = await call("GET", dbg + "/api/healthcheck",
                         { cookie: cookies.header(), Authorization: one[0] });
    check("C. the session with " + one[1] + " still reaches the api",
          function () {
      assert.strictEqual(r.status, 200, r.text.slice(0, 300));
      assert.strictEqual(r.json && r.json.message, "Success");
    });
  }
  const account = await call("GET", dbg + "/_sts/",
    { cookie: cookies.header(), Accept: "text/html",
      Authorization: "Bearer garbage" });
  check("C. and is still the session's person, whatever the header says",
        function () {
    assert.strictEqual(account.status, 200, account.text.slice(0, 300));
    assert.ok(account.text.indexOf("<code>" + USER + "</code>") >= 0,
              account.text.slice(0, 400));
  });
  const after = await call("GET", dbg + "/api/healthcheck",
                           { cookie: cookies.header() });
  check("C. the session is intact afterwards, with no header at all",
        function () {
    assert.strictEqual(after.status, 200, after.text.slice(0, 300));
  });
  log.debug("Leaving aHeaderCannotBreakTheSession().");
}

// ---------------------------------------------------------------------------
// D. THE HEADER ARRIVES AT THE API CHILD, AND THE CHILD USES IT.
// ---------------------------------------------------------------------------
async function theHeaderReachesTheApi(dbg, cookies, bearer) {
  log.debug("Entering theHeaderReachesTheApi().");
  log.info("=== D. /api/userinfo forwards the Authorization it was sent ===");
  const endpoint = base + "/oauth2/userinfo";
  const direct = await call("GET", endpoint,
                            { Authorization: "Bearer " + bearer });
  check("D. the administrator's Bearer token answers UserInfo directly",
        function () {
    assert.strictEqual(direct.status, 200, direct.text.slice(0, 300));
    assert.ok(direct.json && direct.json.sub, direct.text.slice(0, 300));
  });
  const through = dbg + "/api/userinfo?userinfo_endpoint=" +
    encodeURIComponent(Buffer.from(endpoint, "utf8").toString("base64"));
  const relayed = await call("GET", through,
    { cookie: cookies.header(), Authorization: "Bearer " + bearer });
  check("D. through the debugger, with the session, the same token answers " +
        "the same person's claims — the header arrived intact", function () {
    assert.strictEqual(relayed.status, 200, relayed.text.slice(0, 300));
    assert.strictEqual(relayed.json && relayed.json.sub, direct.json.sub,
                       relayed.text.slice(0, 300));
  });
  const junk = await call("GET", through,
    { cookie: cookies.header(), Authorization: "Bearer garbage" });
  check("D. and a token that is not one answers UserInfo's own 401 " +
        "invalid_token, relayed — the answer depends on the header the " +
        "browser sent, not on the session", function () {
    assert.strictEqual(junk.status, 401, junk.text.slice(0, 300));
    assert.strictEqual(junk.json && junk.json.error, "invalid_token",
                       junk.text.slice(0, 300));
  });
  log.debug("Leaving theHeaderReachesTheApi().");
}

// ---------------------------------------------------------------------------
// E. A DPoP PROOF PASSES THROUGH WITHOUT BEING SPENT.
// ---------------------------------------------------------------------------
async function aProofIsNotConsumed(dbg, cookies) {
  log.debug("Entering aProofIsNotConsumed().");
  log.info("=== E. a DPoP proof sent through the debugger is still fresh " +
           "at its real target ===");
  const key = dpopKey();
  const proof = key.proof("POST", base + "/oauth2/token");
  const issued = await codeFor(cookies);
  const passed = await call("GET", dbg + "/api/healthcheck",
                            { cookie: cookies.header(), DPoP: proof });
  check("E. the proof rides a gated call through the debugger, which is " +
        "admitted on the session", function () {
    assert.strictEqual(passed.status, 200, passed.text.slice(0, 300));
  });
  const first = await redeem(issued, proof);
  check("E. at this service's token endpoint the same proof is accepted, " +
        "not a replay: the debugger did not reserve its jti", function () {
    assert.strictEqual(first.status, 200, first.text.slice(0, 300));
    assert.strictEqual(String(first.json.token_type).toLowerCase(), "dpop",
                       first.text.slice(0, 300));
  });
  const again = await tokenRequest({ grant_type: "client_credentials" },
                                   proof);
  check("E. while presenting it there a second time IS refused as a " +
        "replay — so the endpoint keeps the history the debugger would " +
        "have written to", function () {
    assert.strictEqual(again.status, 400, again.text.slice(0, 300));
    assert.strictEqual(again.json && again.json.error, "invalid_dpop_proof",
                       again.text.slice(0, 300));
  });
  log.debug("Leaving aProofIsNotConsumed().");
}

// ---------------------------------------------------------------------------
// F. THE ROLE, ASKED AGAIN AT THE NEXT REQUEST.
// ---------------------------------------------------------------------------
async function aRevokedRoleIsRefused(dbg, cookies) {
  log.debug("Entering aRevokedRoleIsRefused().");
  log.info("=== F. the roles revoked, the same session is refused ===");
  for (const role of ["write", "read"]) {
    const r = await adminPost("/rbac/revoke", { username: USER, role: role });
    assert.strictEqual(r.status, 200, "revoking Admin " + role + " from " +
                       USER + " answered " + r.status + " " +
                       r.text.slice(0, 200));
  }
  let r = null;
  for (let i = 0; i < 20; i++) {
    r = await call("GET", dbg + "/api/healthcheck",
                   { cookie: cookies.header() });
    if (r.status !== 200) {
      break;
    }
    await new Promise(function (resolve) {
      setTimeout(resolve, 250);
    });
  }
  check("F. the next call on the same cookie is refused 403 access_denied",
        function () {
    assert.strictEqual(r.status, 403, r.status + " " + r.text.slice(0, 300));
    assert.strictEqual(r.json && r.json.error, "access_denied",
                       r.text.slice(0, 300));
  });
  log.debug("Leaving aRevokedRoleIsRefused().");
}

async function test() {
  log.debug("Entering test().");
  log.info("[debugger sign-in] the service: " + base);
  let status = await debuggerStatus();
  if (!status.embedded) {
    expectation.declineToRun(log, "this service does not embed the " +
      "protocol debugger here (debugger.enabled=" + status.setting +
      ", global.mode=" + status.mode + "): it is on in development and off " +
      "in product unless turned on (debugger/CLAUDE.md, decision 7).");
    log.debug("Leaving test(). Skipped.");
    return false;
  }
  if (status.api && status.api.state === "not-installed") {
    expectation.declineToRun(log, "the debugger is enabled but this image " +
      "carries no embedded debugger tree (STS-DBG-0015; built with " +
      "DEBUGGER_IMAGE=debugger-none?), so there is nothing to sign in to.");
    log.debug("Leaving test(). Skipped.");
    return false;
  }
  expectation.mustBeAbleTo(status.listening, "The embedded debugger",
    "is enabled and did not bind its listener: " +
    JSON.stringify(status.listenError || status.startProblem));
  status = await waitForApi(status);
  expectation.mustBeAbleTo(status.api && status.api.state === "running",
    "The embedded debugger's api child", "is not running: " +
    JSON.stringify(status.api).slice(0, 400));
  const dbg = debuggerBaseFrom(status);
  log.info("[debugger sign-in] the debugger: " + dbg);

  // The person, a real member of both console roles of the default realm.
  const password = await consoleSignIn.ensureConsoleAccount(base, USER,
    function (line) {
      log.info(line);
    });
  for (const role of ["read", "write"]) {
    const g = await adminPost("/rbac/grant", { username: USER, role: role });
    assert.strictEqual(g.status, 200, "granting Admin " + role + " to " +
                       USER + " answered " + g.status + " " +
                       g.text.slice(0, 200));
  }
  // The job's client, for the administrator's own access tokens.
  const made = await adminPost("/applications/create", {
    identifier: CLIENT, name: CLIENT, protocols: ["oauth2", "oidc"],
    fields: { oauthClientId: [CLIENT], oauthClientSecret: SECRET,
              oauthTokenEndpointAuthMethod: "client_secret_post",
              oauthRedirectUri: [CLIENT_REDIRECT],
              oauthGrantType: ["authorization_code", "client_credentials"] }
  });
  assert.ok(made.status === 200 || /already in this registry/i
    .test(made.text), "creating " + CLIENT + " answered " + made.status +
    " " + made.text.slice(0, 300));

  const cookies = consoleSignIn.jar();
  await signInThroughTheDebugger(dbg, password, cookies);
  await theSessionOpensTheDebugger(dbg, cookies);

  // The administrator's tokens, on the sign-on session the debugger's
  // sign-in made: a Bearer one, and a DPoP-bound one.
  const plain = await redeem(await codeFor(cookies), null);
  assert.ok(plain.status === 200 && plain.json && plain.json.access_token &&
            /^bearer$/i.test(String(plain.json.token_type)),
            "a Bearer token for the administrator: " + plain.status + " " +
            plain.text.slice(0, 300));
  const key = dpopKey();
  const boundAnswer = await redeem(await codeFor(cookies),
                                   key.proof("POST", base + "/oauth2/token"));
  assert.ok(boundAnswer.status === 200 && boundAnswer.json &&
            /^dpop$/i.test(String(boundAnswer.json.token_type)),
            "a DPoP-bound token for the administrator: " +
            boundAnswer.status + " " + boundAnswer.text.slice(0, 300));

  await aTokenIsNotASession(dbg, plain.json.access_token,
                            boundAnswer.json.access_token, key);
  await aHeaderCannotBreakTheSession(dbg, cookies, plain.json.access_token);
  await theHeaderReachesTheApi(dbg, cookies, plain.json.access_token);
  await aProofIsNotConsumed(dbg, cookies);
  await aRevokedRoleIsRefused(dbg, cookies);
  assert.ok(checks >= FLOOR, "only " + checks + " checks ran");
  log.debug("Leaving test().");
  return true;
}

// ON A PASS ONLY: the client and the person. A failure leaves them to be
// looked at (the person no longer holds a role once F has run).
async function cleanUp() {
  log.debug("Entering cleanUp().");
  const app = await adminPost("/applications/forget", { application: CLIENT });
  log.info("deleted the client " + CLIENT + " (" + app.status + ")");
  const person = await adminPost("/users/delete", { user: USER });
  log.info("deleted the person " + USER + " (" + person.status + ")");
  log.debug("Leaving cleanUp().");
}

async function main() {
  log.debug("Entering main().");
  let ran = false;
  try {
    ran = await test();
  } catch (e) {
    log.debug("Caught in main(): " + ((e && e.message) || e));
    log.error("FAILED after " + checks + " check(s): " +
              ((e && e.stack) || e));
    log.debug("Leaving main(). Failed.");
    process.exit(1);
  }
  if (ran) {
    try {
      await cleanUp();
    } catch (e) {
      log.debug("Caught in main(): " + ((e && e.message) || e));
      // The verdict is the test's; a removal that fails is said and left.
      log.warn("could not clean up: " + ((e && e.message) || e));
    }
    log.info(checks + " checks passed.");
    log.info("Test completed successfully.");
  }
  log.debug("Leaving main().");
  // A self-skip has set process.exitCode (expectation.js); keep it.
  process.exit(process.exitCode || 0);
}

main();
