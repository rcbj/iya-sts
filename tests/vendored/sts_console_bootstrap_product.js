// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// ===========================================================================
// sts_console_bootstrap_product.js — THE CONSOLE BEFORE ITS BOOTSTRAP
// ADMINISTRATOR ARRIVES, OVER HTTP, IN BOTH MODES (2026-09-22, #103).
//
// Until that day every realm's console was OPEN to anybody who signed in, by
// any method, until the realm's bootstrap `admin` first signed in to it — in
// product mode as well. A federation partner's assertion, a certificate a
// trusted CA issued, a wallet or a Kerberos ticket made its holder an
// administrator of the whole service for as long as the operator took to
// arrive; and any of them could sign in AS `admin` and claim the console.
// `admin-ui/CLAUDE.md` 8a is the design; `tests/console_bootstrap_product.js`
// holds the half no request can choose the state for. This is the half that
// is only true of a running service:
//
//   1. THE ROSTER VIEW SAYS WHICH MODE IT IS IN. A realm this run creates has
//      an unclaimed window; `/admin-api/rbac` reports it open to anyone in
//      development, and in product reports it closed with the bootstrap
//      administrator's password required.
//   2. A PERSON HOLDING NO ROLE, signed in to that realm's console with a
//      password, is let in by development's window and refused by product.
//   3. A NON-PASSWORD SIGN-IN — a client certificate, through
//      `GET /tls/sign-in` in the default realm — holds no role in product.
//      In product, the same certificate naming the default realm's `admin`
//      is refused `bootstrap_password_required` and claims nothing. (Not in
//      development, where it WOULD claim the default realm's console, as
//      development always has — and every later job in the run would then
//      meet a closed console.)
//   4. THE REALM'S BOOTSTRAP ADMINISTRATOR, signing in with its password —
//      the generated one `POST /admin-api/realms/create` hands back once in
//      product — changes it, is let in with both roles and claims the
//      console, after which the person holding no role is refused in both
//      modes.
//
// **IT IS `local: true`** on the first of `tests/CLAUDE.md`'s questions: it is
// about this service's own `/admin` and `/admin-api`.
//
// **ITS REALM IS LEFT STANDING**, by `tests/CLAUDE.md`'s rule. The default
// realm is touched only by a certificate sign-in, which grants nothing and —
// in product, the one mode the `admin` half runs in — claims nothing. The
// certificate's anchor is added to the default realm's truststore, as
// `sts_global_logout.js` adds its own.
// ===========================================================================

"use strict";

const assert = require("assert");
const https = require("https");
const { Command, Option } = require("commander");
const { usernameFor, runStamp } = require("./random_username.js");
const consoleSignIn = require("./console_signin.js");
const facts = require("./service_facts.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, for the reason tests/vendored/wait_for.js gives.
  appconfigProblem = e;
  appconfig = {};
}

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_console_bootstrap_product",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug('CONFIG_FILE could not be read, so the configuration is empty: ' +
            appconfigProblem.message);
}
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");

const STAMP = runStamp();
const REALM = "cbw-" + STAMP;
const R = "/realm/" + REALM;
const VISITOR = usernameFor("cb-visitor");
const HOLDER = usernameFor("cb-holder");
// A password the default policy accepts: twelve characters or more, an
// uppercase letter, a digit and a symbol.
const NEW_ADMIN_PASSWORD = "Claimed-Console-" + STAMP + "-9!";

var checks = 0;
let product = false;

function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  ✓ " + what);
  log.debug("Leaving check().");
}

// One request, with no redirect followed and the body read both ways.
async function call(method, url, options) {
  log.debug("Entering call(). " + method + " " + url);
  const opts = Object.assign({ method: method, redirect: "manual" },
                             options || {});
  const r = await fetch(url, opts);
  const text = await r.text();
  let body = null;
  try {
    body = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in call(): " + ((e && e.message) || e));
    // Not JSON — a page, a redirect or an empty body. The text is kept.
    body = null;
  }
  log.debug("Leaving call(). status=" + r.status);
  return { status: r.status, body: body, text: text, headers: r.headers,
           location: r.headers.get("location") || "" };
}

// The management API with the run's token, which the preload attaches.
async function api(method, path, payload) {
  log.debug("Entering api(). " + method + " " + path);
  const options = payload === undefined ? {}
    : { headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload) };
  const reply = await call(method, base + path, options);
  log.debug("Leaving api().");
  return reply;
}

// ---------------------------------------------------------------------------
// THE CONSOLE OVER A SIGN-ON SESSION THIS JOB STARTED ITSELF (#446).
//
// Since the cutover the console is a static page that signs in in the
// browser as the public client `sts-admin-console` — the code flow with PKCE
// S256, `resource` the realm's `/admin-api`, a DPoP-bound token — and draws
// every page from `/admin-api`. `console_signin.js` does that walk for a
// password typed at the screen; the two sign-ins here are not that one (a
// forced password change, a client certificate), so this file starts the
// sign-on session its own way and then does the CONSOLE's half on top of it:
// the authorization request with the session's cookie, the code off the
// callback's address, and the token. Answers a small client of the realm's
// `/admin-api`, or the refusal when no console token is issued — which is
// one of the two shapes product's refusal of a person holding no role can
// take (the other is a 403 from the API), and the checks below accept both.
// ---------------------------------------------------------------------------
function b64u(buffer) {
  log.debug("Entering b64u().");
  log.debug("Leaving b64u().");
  return Buffer.from(buffer).toString("base64")
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// The console's authorization request in `realmBase`, for a PKCE pair.
function consoleAuthorizeUrl(realmBase, pkce) {
  log.debug("Entering consoleAuthorizeUrl().");
  log.debug("Leaving consoleAuthorizeUrl().");
  return base + realmBase + "/oauth2/authorize?" + new URLSearchParams({
    response_type: "code", client_id: "sts-admin-console",
    redirect_uri: base + realmBase + "/admin/callback",
    scope: "openid admin:read admin:write", state: pkce.state,
    code_challenge: pkce.challenge, code_challenge_method: "S256",
    resource: base + realmBase + "/admin-api" }).toString();
}

function newPkce() {
  log.debug("Entering newPkce().");
  const crypto = require("crypto");
  const verifier = b64u(crypto.randomBytes(32));
  log.debug("Leaving newPkce().");
  return { verifier: verifier, state: b64u(crypto.randomBytes(16)),
           challenge: b64u(crypto.createHash("sha256").update(verifier)
             .digest()) };
}

async function consoleOverSession(realmBase, cookieHeader) {
  log.debug("Entering consoleOverSession(). " + realmBase);
  const crypto = require("crypto");
  // The console's document first, as a browser opening it loads it: it is
  // what registers the realm's console callback.
  await call("GET", base + realmBase + "/admin");
  const pkce = newPkce();
  let at = await call("GET", consoleAuthorizeUrl(realmBase, pkce),
                      { headers: { Cookie: cookieHeader } });
  for (let i = 0; i < 5 && (at.status === 302 || at.status === 303) &&
       !/\/admin\/callback\?/.test(at.location); i++) {
    at = await call("GET", new URL(at.location, base).toString(),
                    { headers: { Cookie: cookieHeader } });
  }
  const back = new URL(at.location || base, base);
  const code = back.searchParams.get("code");
  assert.ok(code && back.searchParams.get("state") === pkce.state,
    "the console's authorization request over the session should come back " +
    "to its callback with a code; it answered " + at.status + " -> " +
    at.location + " " + at.text.slice(0, 200));
  const pair = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = pair.publicKey.export({ format: "jwk" });
  let nonce = "";
  const proof = function (method, url, token) {
    const claims = { jti: b64u(crypto.randomBytes(16)), htm: method,
                     htu: String(url).replace(/[?#].*$/, ""),
                     iat: Math.floor(Date.now() / 1000) };
    if (token) {
      claims.ath = b64u(crypto.createHash("sha256").update(token).digest());
    }
    if (nonce) {
      claims.nonce = nonce;
    }
    const input = b64u(JSON.stringify({ typ: "dpop+jwt", alg: "ES256",
      jwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y } })) + "." +
      b64u(JSON.stringify(claims));
    return input + "." + b64u(crypto.sign("sha256", Buffer.from(input),
      { key: pair.privateKey, dsaEncoding: "ieee-p1363" }));
  };
  const tokenUrl = base + realmBase + "/oauth2/token";
  let minted = null;
  for (let attempt = 0; attempt < 2; attempt++) {
    minted = await call("POST", tokenUrl, {
      headers: { "Content-Type": "application/x-www-form-urlencoded",
                 DPoP: proof("POST", tokenUrl, "") },
      body: new URLSearchParams({ grant_type: "authorization_code",
        code: code, redirect_uri: base + realmBase + "/admin/callback",
        client_id: "sts-admin-console", code_verifier: pkce.verifier,
        resource: base + realmBase + "/admin-api" }).toString() });
    nonce = minted.headers.get("dpop-nonce") || nonce;
    if (!(minted.status === 400 && minted.body &&
          minted.body.error === "use_dpop_nonce")) {
      break;
    }
  }
  const token = minted.body && minted.body.access_token;
  log.debug("Leaving consoleOverSession(). " +
            (token ? "A token." : "No token: " + minted.status));
  return {
    refused: token ? null : minted,
    // One `/admin-api` read in the console's realm, with its token.
    api: async function (method, path) {
      const url = base + realmBase + path;
      let reply = null;
      for (let attempt = 0; attempt < 2; attempt++) {
        reply = await call(method, url, { headers: {
          Authorization: "DPoP " + token, DPoP: proof(method, url, token),
          Accept: "application/json" } });
        nonce = reply.headers.get("dpop-nonce") || nonce;
        if (!(reply.status === 401 && /use_dpop_nonce/.test(
          reply.headers.get("www-authenticate") || ""))) {
          break;
        }
      }
      return reply;
    }
  };
}

// A CONSOLE READ: the operation `path`'s page is drawn from, asked with the
// console's token — or the token request's refusal, when none was issued.
async function consolePage(consoleClient, path) {
  log.debug("Entering consolePage(). " + path);
  const reply = consoleClient.refused ? consoleClient.refused
    : await consoleClient.api("GET", path);
  log.debug("Leaving consolePage().");
  return reply;
}

// Whether a console read was REFUSED to a person: a 403 from the API, or —
// where the authorization server narrowed the console's scopes away — no
// console token at all. Which one product answers is recorded in the check.
function refusedAccess(reply) {
  log.debug("Entering refusedAccess().");
  log.debug("Leaving refusedAccess().");
  return reply.status === 403 ||
         (reply.status === 400 && reply.body &&
          /invalid_scope|access_denied/.test(String(reply.body.error)));
}

// ---------------------------------------------------------------------------
// A SIGN-IN THAT ANSWERS THE PASSWORD-CHANGE STEP. `console_signin.js` types a
// name and a password and nothing else; the bootstrap administrator's first
// sign-in is asked for a new password before any session exists
// (`authn/CLAUDE.md`), so this walk answers that step when it is drawn, and
// then does the console's half over the session (`consoleOverSession()`).
// `jar` keeps every cookie by name, as that helper's does.
// ---------------------------------------------------------------------------
async function signInWithPassword(realmBase, user, password, newPassword) {
  log.debug("Entering signInWithPassword(). " + user);
  const cookies = consoleSignIn.jar();
  const hop = async function (url, options) {
    const opts = Object.assign({ redirect: "manual" }, options || {});
    opts.headers = Object.assign({ cookie: cookies.header() },
                                 opts.headers || {});
    const r = await fetch(new URL(url, base).toString(), opts);
    cookies.keep(r);
    return r;
  };
  // The sign-in screen, reached as the console reaches it: its own
  // authorization request with no session yet.
  await hop(base + realmBase + "/admin");
  const toScreen = await hop(consoleAuthorizeUrl(realmBase, newPkce()));
  const where = toScreen.headers.get("location") || "";
  const authnId = (where.match(/[?&]authn=([^&]+)/) || [])[1] || "";
  assert.ok(authnId, "the console's authorization request should send the " +
            "browser to the sign-in screen; it answered " + toScreen.status +
            " -> " + where);
  const screen = await hop(where);
  const screenHtml = await screen.text();
  const csrf = (screenHtml.match(/name="csrf_token" value="([^"]+)"/) ||
                [])[1] || "";
  let answered = await hop(base + realmBase + "/authn/login", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ authn_id: decodeURIComponent(authnId),
                                username: user, password: password,
                                action: "login", csrf_token: csrf })
      .toString()
  });
  // Up to two steps before a session: the forced password change, and —
  // since #246 — the second factor OFFERED to an administrator, which this
  // job ignores (rcbj: "update tests to just click ignore for the time
  // being"). Either may come first; each is answered once.
  for (let step = 0; step < 2 && answered.status === 200; step++) {
    const page = await answered.text();
    const changeId = (page.match(/name="change_id" value="([^"]+)"/) ||
                      [])[1] || "";
    const setupId = /id="mfa-setup-ignore"/.test(page)
      ? (page.match(/name="mfa_id" value="([^"]+)"/) || [])[1] || "" : "";
    assert.ok(changeId || setupId, "the sign-in screen answered 200 with " +
              "neither a session, the password-change step nor the offer " +
              "of a second factor: " + page.slice(0, 300));
    if (setupId) {
      answered = await hop(base + realmBase + "/authn/mfa-setup", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ mfa_id: setupId, action: "ignore" })
          .toString()
      });
      continue;
    }
    const changeCsrf = (page.match(/name="csrf_token" value="([^"]+)"/) ||
                        [])[1] || "";
    answered = await hop(base + realmBase + "/authn/password-change", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ change_id: changeId,
                                  new_password: newPassword,
                                  confirm_password: newPassword,
                                  csrf_token: changeCsrf }).toString()
    });
  }
  assert.ok(cookies.get("sts_session"),
    "signing in as " + user + " should start a sign-on session; the last " +
    "answer was " + answered.status);
  const consoleClient = await consoleOverSession(realmBase, cookies.header());
  log.debug("Leaving signInWithPassword().");
  return consoleClient;
}

// ---------------------------------------------------------------------------
// A CLIENT CERTIFICATE SIGN-IN, then the console's half on top of the
// sign-on session it started (`consoleOverSession()`). The anchor is this
// job's own CA, added through `POST /admin-api/tls/trust/add` — the gated
// door both modes open, persisted so every node of a cluster applies it —
// and the session lands in the
// DEFAULT realm, the realm of an anchor installed there (`tls/CLAUDE.md`).
// ---------------------------------------------------------------------------
async function makeCertificate(commonName) {
  log.debug("Entering makeCertificate(). " + commonName);
  const forge = require("node-forge");
  const list = await require("./test_crl_host.js").reserve("ca");
  const caKeys = forge.pki.rsa.generateKeyPair(2048);
  const ca = forge.pki.createCertificate();
  ca.publicKey = caKeys.publicKey;
  ca.serialNumber = "0a" + require("crypto").randomBytes(7).toString("hex");
  ca.validity.notBefore = new Date(Date.now() - 60000);
  ca.validity.notAfter = new Date(Date.now() + 3600 * 1000);
  // A name of its own per CA, for `sts_global_logout.js`'s reason: two keys
  // under one subject DN in one truststore verify against whichever is found
  // first.
  const caName = [{ name: "commonName",
                    value: "console bootstrap test CA " + STAMP + " " +
                           commonName }];
  ca.setSubject(caName);
  ca.setIssuer(caName);
  ca.setExtensions([{ name: "basicConstraints", cA: true }]);
  ca.sign(caKeys.privateKey, forge.md.sha256.create());
  const leafKeys = forge.pki.rsa.generateKeyPair(2048);
  const leaf = forge.pki.createCertificate();
  leaf.publicKey = leafKeys.publicKey;
  leaf.serialNumber = "0b" + require("crypto").randomBytes(7).toString("hex");
  leaf.validity.notBefore = new Date(Date.now() - 60000);
  leaf.validity.notAfter = new Date(Date.now() + 3600 * 1000);
  leaf.setSubject([{ name: "commonName", value: commonName }]);
  leaf.setIssuer(caName);
  // THE CA'S OWN LIST (#174): this job runs in product mode, which refuses
  // under hard-fail a certificate from an authority it does not hold that
  // names no CRL and no responder. Served from this process
  // (`test_crl_host.js`) while the certificate is presented.
  leaf.setExtensions([{ name: "basicConstraints", cA: false },
                      { name: "extKeyUsage", clientAuth: true },
                      { name: "cRLDistributionPoints",
                        altNames: [{ type: 6, value: list.url }] }]);
  leaf.sign(caKeys.privateKey, forge.md.sha256.create());
  const caPem = forge.pki.certificateToPem(ca);
  await list.publish({ pem: caPem,
                       privateKeyPem: forge.pki.privateKeyToPem(
                           caKeys.privateKey) });
  log.debug("Leaving makeCertificate().");
  return { caPem: caPem,
           certPem: forge.pki.certificateToPem(leaf),
           keyPem: forge.pki.privateKeyToPem(leafKeys.privateKey) };
}

function certificateRequest(pki, path, cookie) {
  log.debug("Entering certificateRequest(). " + path);
  const url = new URL(base);
  log.debug("Leaving certificateRequest().");
  return new Promise(function (resolve, reject) {
    const req = https.request({
      host: url.hostname, port: Number(url.port || 443), path: path,
      method: "GET", cert: pki.certPem, key: pki.keyPem,
      headers: cookie ? { Cookie: cookie } : {},
      // What is under test is the CLIENT certificate; the server's is not
      // verified here, as in `sts_global_logout.js`.
      rejectUnauthorized: false
    }, function (res) {
      let body = "";
      res.on("data", function (d) { body += d; });
      res.on("end", function () {
        resolve({ status: res.statusCode, body: body,
                  location: res.headers.location || "",
                  cookies: res.headers["set-cookie"] || [] });
      });
    });
    req.on("error", reject);
    req.end();
  });
}

async function signInWithCertificate(commonName) {
  log.debug("Entering signInWithCertificate(). " + commonName);
  const pki = await makeCertificate(commonName);
  const added = await api("POST", "/admin-api/tls/trust/add",
                          { certificates: pki.caPem });
  assert.strictEqual(added.status, 200,
    "adding this job's CA through POST /admin-api/tls/trust/add answered " +
    added.status + " " + added.text.slice(0, 200));
  // THE ANCHOR IS APPLIED WITH `setSecureContext()` AND THE NEXT HANDSHAKE IS
  // JUDGED AGAINST IT, so a sign-in in the same tick can meet the old
  // context — retried, as `sts_global_logout.js` retries it, on a sign-in that
  // did not happen rather than only on a thrown connection. IN `cluster` THE
  // ANCHOR REACHES THE OTHER NODE THROUGH THE CHANGE LOG, and under the
  // in-process lanes' load that took longer than the eight tries at 400 ms
  // this loop used to allow (2026-10-04: presented, not verified, for all
  // eight) — so it is a deadline, not a count.
  let session = "";
  let last = null;
  const deadline = Date.now() + 20000;
  while (!session && Date.now() < deadline) {
    try {
      last = await certificateRequest(pki, "/tls/sign-in", "");
      const found = last.cookies.map(function (one) {
        return String(one).split(";")[0];
      }).filter(function (one) { return /^sts_session=./.test(one); })[0];
      session = found || "";
    } catch (e) {
      log.debug("Caught in signInWithCertificate(): " +
                ((e && e.message) || e));
      // A handshake refused while the anchor is landing; tried again below.
      last = { status: 0, body: String(e && e.message) };
    }
    if (!session) {
      await new Promise(function (r) { setTimeout(r, 400); });
    }
  }
  assert.ok(session, "GET /tls/sign-in with a certificate for " + commonName +
            " under an installed anchor should start a session; it answered " +
            (last && last.status) + " " + String(last && last.body)
              .slice(0, 300));
  // The console's half over that sign-on session (#446): no screen, a code
  // and the console's token — or no token, which is one shape of a refusal.
  const consoleClient = await consoleOverSession("", session);
  log.debug("Leaving signInWithCertificate().");
  return consoleClient;
}

// ---------------------------------------------------------------------------
// 1. THE ROSTER VIEW.
// ---------------------------------------------------------------------------
async function theRosterViewSaysWhichModeItIsIn() {
  log.debug("Entering theRosterViewSaysWhichModeItIsIn().");
  log.info("=== 1. a new realm's roster view, in " +
           (product ? "product" : "development") + " mode ===");
  const roster = await api("GET", R + "/admin-api/rbac");
  check("the realm's bootstrap administrator is seeded and has not claimed " +
        "its console", function () {
    assert.strictEqual(roster.status, 200, "it answered " + roster.status);
    assert.ok(roster.body.bootstrap && roster.body.bootstrap.seeded &&
              !roster.body.bootstrap.claimedAt,
              JSON.stringify(roster.body.bootstrap));
  });
  if (product) {
    check("PRODUCT: the window does not open, whatever admin.openWhenEmpty " +
          "says, and the bootstrap administrator's password is required",
      function () {
        assert.strictEqual(roster.body.openToAnyone, false,
                           JSON.stringify(roster.body.openToAnyone));
        assert.strictEqual(roster.body.windowOpens, false);
        assert.strictEqual(roster.body.bootstrapPasswordRequired, true);
      });
  } else {
    check("DEVELOPMENT: the window is open to anyone who signs in",
      function () {
        assert.strictEqual(roster.body.openToAnyone, true,
                           JSON.stringify(roster.body.openToAnyone));
        assert.strictEqual(roster.body.windowOpens, true);
        assert.strictEqual(roster.body.bootstrapPasswordRequired, false);
      });
  }
  log.debug("Leaving theRosterViewSaysWhichModeItIsIn().");
}

// ---------------------------------------------------------------------------
// 2. A PERSON HOLDING NO ROLE.
// ---------------------------------------------------------------------------
async function aPersonHoldingNoRole() {
  log.debug("Entering aPersonHoldingNoRole().");
  log.info("=== 2. a person holding no role, signed in with a password ===");
  // Through this file's own walk rather than `console_signin.js`'s, which
  // asserts a console token: product's refusal may be NO token (#446).
  const password = await consoleSignIn.ensureConsoleAccount(base + R, VISITOR,
    function (line) {
      log.info(line);
    });
  const consoleClient = await signInWithPassword(R, VISITOR, password,
                                                 password);
  const reply = await consolePage(consoleClient, "/admin-api/tokens?per=1");
  if (product) {
    check("PRODUCT: refused — the window never opens", function () {
      assert.ok(refusedAccess(reply), "it answered " + reply.status + " " +
                reply.text.slice(0, 200));
      log.info("  (refused as " + reply.status + " " +
               JSON.stringify(reply.body && reply.body.error) + ")");
    });
  } else {
    check("DEVELOPMENT: let in by the open window", function () {
      assert.strictEqual(reply.status, 200,
                         "it answered " + reply.status + " " +
                         reply.text.slice(0, 200));
    });
  }
  const roster = await api("GET", R + "/admin-api/rbac");
  check("and nothing was claimed by it", function () {
    assert.ok(!roster.body.bootstrap.claimedAt,
              JSON.stringify(roster.body.bootstrap));
  });
  log.debug("Leaving aPersonHoldingNoRole().");
  return consoleClient;
}

// ---------------------------------------------------------------------------
// 3. A NON-PASSWORD SIGN-IN, IN THE DEFAULT REALM.
// ---------------------------------------------------------------------------
async function aCertificateSignIn() {
  log.debug("Entering aCertificateSignIn().");
  log.info("=== 3. a client-certificate sign-in reaches the console ===");
  const made = await api("POST", "/admin-api/users/create", {
    username: HOLDER, invent: false,
    attributes: { cn: "Certificate " + HOLDER, givenName: "Certificate",
                  sn: HOLDER, displayName: "Certificate " + HOLDER,
                  mail: HOLDER + "@console-bootstrap.test" } });
  assert.ok(made.status === 200 || (made.body && made.body.existing),
            "creating " + HOLDER + " answered " + made.status + " " +
            made.text.slice(0, 200));
  const service = await api("GET", "/admin-api/rbac");
  const consoleClient = await signInWithCertificate(HOLDER);
  const reply = await consolePage(consoleClient, "/admin-api/tokens?per=1");
  if (product) {
    check("PRODUCT: a certificate holder holding no role is refused",
      function () {
        assert.ok(refusedAccess(reply), "it answered " + reply.status + " " +
                  reply.text.slice(0, 200));
      });
  } else {
    check("DEVELOPMENT: a certificate holder holding no role is let in " +
          "exactly while the default realm's window is open", function () {
      assert.strictEqual(reply.status,
                         service.body.openToAnyone ? 200 : 403,
                         "it answered " + reply.status + " with " +
                         "openToAnyone " + service.body.openToAnyone);
    });
  }

  if (!product) {
    log.info("Development: the certificate naming `admin` is not tried — " +
             "it would claim the default realm's console, as development " +
             "always has, and close it for every later job.");
    log.debug("Leaving aCertificateSignIn(). Development.");
    return;
  }
  if (!service.body.bootstrapPasswordRequired) {
    log.info("The default realm's console is already claimed, so a " +
             "certificate naming `admin` is an ordinary member's sign-in " +
             "and there is no pending claim to test against.");
    log.debug("Leaving aCertificateSignIn(). Already claimed.");
    return;
  }
  const bootName = service.body.bootstrap.username;
  const asAdmin = await signInWithCertificate(bootName);
  const refused = await consolePage(asAdmin, "/admin-api/tokens?per=1");
  check("PRODUCT: a certificate naming the bootstrap administrator is " +
        "refused — its password is required", function () {
    assert.ok(refusedAccess(refused), "it answered " + refused.status + " " +
              refused.text.slice(0, 200));
    log.info("  (refused as " + refused.status + " " +
             JSON.stringify(refused.body && refused.body.error) + ")");
  });
  const write = await consolePage(asAdmin, "/admin-api/rbac");
  check("and so is the roster it would claim", function () {
    assert.ok(refusedAccess(write), "it answered " + write.status);
  });
  const after = await api("GET", "/admin-api/rbac");
  check("and claims nothing: the default realm's console is still unclaimed",
    function () {
      assert.ok(!after.body.bootstrap.claimedAt,
                JSON.stringify(after.body.bootstrap));
      assert.strictEqual(after.body.bootstrapPasswordRequired, true);
    });
  log.debug("Leaving aCertificateSignIn().");
}

// ---------------------------------------------------------------------------
// 4. THE BOOTSTRAP ADMINISTRATOR'S PASSWORD CLAIMS THE REALM'S CONSOLE.
// ---------------------------------------------------------------------------
async function thePasswordClaimsIt(created, visitorClient) {
  log.debug("Entering thePasswordClaimsIt().");
  log.info("=== 4. the realm's bootstrap administrator signs in with its " +
           "password ===");
  const bootName = (created.body && (created.body.username ||
                    (created.body.bootstrap &&
                     created.body.bootstrap.username))) || "admin";
  const generated = created.body && created.body.password;
  if (product) {
    check("PRODUCT: the realm's create handed back its generated password " +
          "once", function () {
      assert.ok(generated, JSON.stringify(created.body).slice(0, 300));
    });
  }
  // Development checks no password, so any string reaches the change step.
  const consoleClient = await signInWithPassword(R, bootName,
    generated || "anything-at-all", NEW_ADMIN_PASSWORD);
  const reply = await consolePage(consoleClient, "/admin-api/rbac");
  check("the bootstrap administrator is let in holding both roles",
    function () {
      assert.strictEqual(reply.status, 200, "it answered " + reply.status +
                         " " + reply.text.slice(0, 200));
      // The console's two roles; the API's `you` also names the computed
      // built-in roles every person holds, which are not console roles.
      assert.deepStrictEqual((reply.body.you.roles || []).filter(
        function (role) {
          return role === "read" || role === "write";
        }).sort(), ["read", "write"]);
      assert.strictEqual(reply.body.you.viaEmptyRoster, false);
    });
  const roster = await api("GET", R + "/admin-api/rbac");
  check("and its arrival claimed the realm's console", function () {
    assert.ok(roster.body.bootstrap.claimedAt,
              JSON.stringify(roster.body.bootstrap));
    assert.strictEqual(roster.body.openToAnyone, false);
    assert.strictEqual(roster.body.bootstrapPasswordRequired, false);
  });
  // The visitor's token was issued while the window was open: what it may
  // do is asked again at every call (held ∩ carried, rule 3bq), so the
  // claim shuts it out without a new sign-in.
  const visitor = await consolePage(visitorClient, "/admin-api/tokens?per=1");
  check("after which the person holding no role is refused, in both modes",
    function () {
      assert.ok(refusedAccess(visitor), "it answered " + visitor.status);
    });
  log.debug("Leaving thePasswordClaimsIt().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving the console's bootstrap window at " + base + ".");
  product = await facts.isProduct(base + "/admin-api");
  const created = await api("POST", "/admin-api/realms/create",
                            { id: REALM, domain: REALM + ".example.net",
                              name: "Console bootstrap " + STAMP });
  assert.strictEqual(created.status, 200, "creating the realm " + REALM +
                     " answered " + created.status + " " +
                     created.text.slice(0, 300));

  await theRosterViewSaysWhichModeItIsIn();
  const visitorClient = await aPersonHoldingNoRole();
  await aCertificateSignIn();
  await thePasswordClaimsIt(created, visitorClient);

  // A FLOOR ON THE COUNT, for the reason sts_roles.js gives: a section that
  // stops being called takes its assertions with it and the run still says
  // "passed".
  const floor = product ? 9 : 8;
  assert.ok(checks >= floor,
    "only " + checks + " checks ran where at least " + floor + " should " +
    "have, so a SECTION STOPPED BEING CALLED.");
  log.info(checks + " checks passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_console_bootstrap_product")
  .description("Drive the admin console before its bootstrap administrator " +
      "arrives: development's open window, product's closed one, a " +
      "certificate sign-in as a person and as `admin`, and the password " +
      "sign-in that claims a realm's console.")
  .addOption(new Option("-u, --url <url>", "base url of the STS under test")
      .default(base))
  .parse(process.argv);
base = String(program.opts().url || base).replace(/\/+$/, "");

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
