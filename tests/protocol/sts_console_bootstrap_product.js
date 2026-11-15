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
// D12 (#444) ADDS TWO SECTIONS, one per kind of process:
//
//   5. (DEVELOPMENT PROCESS) tests/console_bootstrap_product.js 2 and 3: A
//      REALM IN PRODUCT MODE IS PRODUCT WHERE THE PROCESS IS NOT. A realm
//      created with `overrides: { "global.mode": "product" }` reports its
//      window closed and no longer open to anyone, while this job's
//      development realm reports it open; a person holding no role who
//      signs in to its console is refused, and claims nothing.
//   6. (PRODUCT PROCESS) tests/console_claim_at_issuance.js: THE CLAIM IS
//      MADE AT ISSUANCE TO THE CONSOLE'S OWN CLIENT. In a second realm of
//      its own the bootstrap administrator signs in with its password
//      through ANOTHER client first: that client is issued no admin scope
//      and the console stays unclaimed; then the console's client over the
//      same sign-on session claims it and is issued both admin scopes; and
//      the default realm's own window is exactly as it was.
//
// Its two realms are removed at the end only when STS_TEST_REMOVE_REALMS is
// "1" (a shared private probe would fill otherwise); the suite leaves them.
//
// What stays in process (each file's D12 note): the federated, Kerberos,
// security-key and application-subject cases of the claim, the debugger's
// two refusals (no test stack binds the debugger's listener), the startup
// line STS-ADMIN-0798, and what a password sign-in IS (amr and authority as
// a module answers them).
//
// **IT IS `local: true`** on the first of `tests/CLAUDE.md`'s questions: it is
// about this service's own `/admin` and `/admin-api`.
//
// **ITS REALM IS LEFT STANDING**, by `tests/CLAUDE.md`'s rule. The default
// realm is touched only by a certificate sign-in, which grants nothing and —
// in product, the one mode the `admin` half runs in — claims nothing. The
// certificate's anchor is added to the service-wide truststore and removed
// when the job finishes (#335), as `sts_global_logout.js` does with its own.
// ===========================================================================

"use strict";

// The sign-in screen over `/authn-api` (#571).
const authnSignin = require("./authn_signin");
const assert = require("assert");
const https = require("https");
const { Command, Option } = require("commander");
const { usernameFor, runStamp } = require("./random_username.js");
const consoleSignIn = require("./console_signin.js");
const facts = require("./service_facts.js");
const credentials = require("../tools/pep-credential.js");
// CAs this job posts. Removed when it finishes, pass or fail (#335). The
// truststore is service-wide and holds 32. tests/CLAUDE.md.
const addedAnchors = [];
// Certificates this job stored on default-realm entries (#1061), taken off
// when it finishes: the default realm outlives the job.
const storedHere = [];

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
// D12's two realms: born in product in a development process (5), and the
// claim-at-issuance realm in a product process (6).
const PRODUCT_REALM = ("cbq-" + STAMP).toLowerCase().slice(0, 31);
const CLAIM_REALM = ("cbc-" + STAMP).toLowerCase().slice(0, 31);
const OTHER_CLIENT = "cb-other-client";
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
  const authnId = (where.match(/[?&#]authn=([^&]+)/) || [])[1] || "";
  assert.ok(authnId, "the console's authorization request should send the " +
            "browser to the sign-in screen; it answered " + toScreen.status +
            " -> " + where);
  // THE SCREEN OVER `/authn-api` (#571), through the one helper. Up to two
  // steps before a session: the forced password change, and — since #246 —
  // the second factor OFFERED to an administrator, which this job ignores
  // (rcbj: "update tests to just click ignore for the time being"). Either
  // may come first; each is answered once.
  let answered = await authnSignin.signIn(base + realmBase,
    new URL(where, base).toString(),
    { action: "login", username: user, password: password },
    { cookie: cookies.header() });
  cookies.keep(answered);
  for (let step = 0; step < 2 && answered.next === "password-change";
       step++) {
    answered = await authnSignin.changePassword(base + realmBase,
      answered.location, { new_password: newPassword,
                           confirm_password: newPassword },
      { cookie: cookies.header() });
    cookies.keep(answered);
    answered = await authnSignin.ignoreOffer(base + realmBase, answered);
    cookies.keep(answered);
  }
  assert.strictEqual(answered.next, "redirect",
    "the sign-in as " + user + " answered neither a session, the " +
    "password-change step nor the offer of a second factor: " +
    answered.status + " " + JSON.stringify(answered.json));
  assert.ok((cookies.get("sts_session") || cookies.get("__Host-sts_session")),
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
      rejectUnauthorized: false,
      // A full handshake every time, never a resumed session (2026-10-07).
      // The global agent caches TLS sessions, and since #406 a session
      // resumes on any node with the verdict of its first handshake. A first
      // try made before the anchor reached the node left an UNVERIFIED
      // session, every retry resumed it, and the sign-in stayed "presented,
      // not verified" for the whole 20 s (the cluster mode, 2026-10-07).
      agent: false
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
  // Recorded before it is posted (#1307): an add applied but answered late
  // is still removed when the job finishes.
  credentials.recordAnchor(addedAnchors, pki.caPem);
  const added = await api("POST", "/admin-api/tls/trust/add",
                          { certificates: pki.caPem });
  assert.strictEqual(added.status, 200,
    "adding this job's CA through POST /admin-api/tls/trust/add answered " +
    added.status + " " + added.text.slice(0, 200));
  // Its add answered 2xx, so a later "not held" is a node behind (#1307).
  credentials.confirmAnchor(pki.caPem);
  // STORED ON THE ENTRY IT SIGNS IN AS (#1061, rcbj 2026-10-27). The leaf is
  // an outside authority's, and such a certificate names nobody by its CN any
  // more: it is the one entry of the realm storing it in `userCertificate`.
  // Stored on `commonName`'s default-realm entry, which is the person this
  // section means; an unstored one starts no session (STS-TLS-0054).
  storedHere.push(await credentials.storeOnEntry({
    get: function (url) {
      return call("GET", url);
    },
    post: function (url, payload) {
      return call("POST", url, {
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload) });
    } }, base, "", commonName, pki.certPem));
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
      }).filter(function (one) { return /^(?:__Host-)?sts_session=./.test(one); })[0];
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
  // READ AGAIN FOR A MOMENT (cluster, 2026-10-27): the claim is written on
  // the node the sign-in landed on and reaches the others through the
  // change log, so a roster read through the balancer may be a pull
  // behind. A bounded wait, never an unbounded one.
  let roster = await api("GET", R + "/admin-api/rbac");
  for (let attempt = 0; attempt < 40; attempt++) {
    if (roster.body && roster.body.bootstrap &&
        roster.body.bootstrap.claimedAt) {
      break;
    }
    await new Promise(function (r) { setTimeout(r, 500); });
    roster = await api("GET", R + "/admin-api/rbac");
  }
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

// ---------------------------------------------------------------------------
// 5. A PRODUCT REALM IN A DEVELOPMENT PROCESS (D12).
// ---------------------------------------------------------------------------
async function aProductRealmInADevelopmentProcess() {
  log.debug("Entering aProductRealmInADevelopmentProcess().");
  log.info("=== 5. a realm born in product, in a development process ===");
  const made = await api("POST", "/admin-api/realms/create", {
    id: PRODUCT_REALM, domain: PRODUCT_REALM + ".example.net",
    name: "Product realm " + STAMP,
    // ITS OWN global.publicBaseUrl (run #300): a product realm accepts only
    // the console's REGISTERED redirect URI, made from that setting, and a
    // memory-mode process has none (run-tests.sh sets STS_PUBLIC_BASE_URL
    // for the product modes alone), so the realm is given the address this
    // job reaches it at — the same value where the process has one.
    overrides: { "global.mode": "product",
                 "global.publicBaseUrl": base,
                 "authn.allowOptionalSecondFactor": "true" } });
  assert.strictEqual(made.status, 200, "creating " + PRODUCT_REALM +
                     " answered " + made.status + " " +
                     made.text.slice(0, 300));
  const QR = "/realm/" + PRODUCT_REALM;
  const roster = await api("GET", QR + "/admin-api/rbac");
  const dev = await api("GET", R + "/admin-api/rbac");
  check("5. the mode is asked in the roster's realm: the product realm's " +
        "window is closed while the development realm's opens",
        function () {
    assert.strictEqual(roster.status, 200, roster.text.slice(0, 200));
    assert.strictEqual(roster.body.openToAnyone, false,
                       JSON.stringify(roster.body.openToAnyone));
    assert.strictEqual(roster.body.windowOpens, false);
    assert.strictEqual(dev.body.windowOpens, true);
  });
  const password = await consoleSignIn.ensureConsoleAccount(base + QR,
    usernameFor("cb-q-visitor"), function (line) {
      log.info(line);
    });
  const visitor = await signInWithPassword(QR, usernameFor("cb-q-visitor"),
                                           password, password);
  const reply = await consolePage(visitor, "/admin-api/tokens?per=1");
  check("5. a person holding no role is refused its console", function () {
    assert.ok(refusedAccess(reply), "it answered " + reply.status + " " +
              reply.text.slice(0, 200));
  });
  const after = await api("GET", QR + "/admin-api/rbac");
  check("5. and claims nothing", function () {
    assert.ok(!after.body.bootstrap.claimedAt,
              JSON.stringify(after.body.bootstrap));
  });
  // A NODE DEFECT, FIXED (2026-11-14, #444's D12): the realm was seeded
  // with the CREATE's realm's name (`admin`, development) while its roster
  // asks for the product name (`admin-<hmac>`), so nobody could ever claim
  // this console. The name is now asked in the realm, and so is whether a
  // generated password is handed back.
  const keepsDefault = String(await facts.setting(base + QR + "/admin-api",
    "admin.allowDefaultUsername")) === "true";
  const bootName = String((made.body && made.body.bootstrap &&
                           made.body.bootstrap.username) || "");
  const generated = String((made.body && made.body.password) || "");
  check("5. the realm is seeded under the name its roster asks for, and " +
        "its create hands back that account's generated password",
        function () {
    assert.ok(roster.body.bootstrap && roster.body.bootstrap.seeded === true,
              JSON.stringify(roster.body.bootstrap));
    assert.strictEqual(bootName, roster.body.bootstrap.username,
                       JSON.stringify(made.body.bootstrap));
    // The generated name unless admin.allowDefaultUsername keeps the
    // configured one, as the suite's stack sets it (run #300).
    assert.ok(keepsDefault ? bootName === "admin"
                           : /^admin-[0-9a-f]{16}$/.test(bootName), bootName);
    assert.ok(generated && made.body.username === bootName,
              JSON.stringify(made.body).slice(0, 300));
  });
  await signInWithPassword(QR, bootName, generated, NEW_ADMIN_PASSWORD);
  // THE CLAIM, READ FROM THE ROSTER through the service's own API client.
  // (The claimer's own first read is not asserted here: in a product realm
  // it intermittently answers 401 STS-API-0122 although the claim was made,
  // reported to #444 separately.)
  let claimed = await api("GET", QR + "/admin-api/rbac");
  for (let attempt = 0; attempt < 40; attempt++) {
    if (claimed.body && claimed.body.bootstrap &&
        claimed.body.bootstrap.claimedAt) {
      break;
    }
    await new Promise(function (r) { setTimeout(r, 500); });
    claimed = await api("GET", QR + "/admin-api/rbac");
  }
  check("5. so its bootstrap administrator signs in with that password and " +
        "claims the console", function () {
    assert.ok(claimed.body.bootstrap.claimedAt,
              JSON.stringify(claimed.body.bootstrap));
    assert.strictEqual(claimed.body.bootstrap.username, bootName);
    assert.strictEqual(claimed.body.openToAnyone, false);
    assert.strictEqual(claimed.body.bootstrapPasswordRequired, false);
  });
  log.debug("Leaving aProductRealmInADevelopmentProcess().");
}

// A sign-in through `clientId`'s own authorization request in `realmBase`,
// answering the forced password change; answers the jar holding the
// sign-on session and the scope the code bought.
async function signInThroughAnotherClient(realmBase, user, password,
                                          newPassword) {
  log.debug("Entering signInThroughAnotherClient(). " + user);
  const cookies = consoleSignIn.jar();
  const hop = async function (url, options) {
    const opts = Object.assign({ redirect: "manual" }, options || {});
    opts.headers = Object.assign({ cookie: cookies.header() },
                                 opts.headers || {});
    const r = await fetch(new URL(url, base).toString(), opts);
    cookies.keep(r);
    return r;
  };
  const pkce = newPkce();
  const callback = "https://" + OTHER_CLIENT + ".example/cb";
  const authorize = base + realmBase + "/oauth2/authorize?" +
    new URLSearchParams({ response_type: "code", client_id: OTHER_CLIENT,
      redirect_uri: callback, scope: "openid admin:read admin:write",
      state: pkce.state, code_challenge: pkce.challenge,
      code_challenge_method: "S256",
      resource: base + realmBase + "/admin-api" }).toString();
  const toScreen = await hop(authorize);
  const where = toScreen.headers.get("location") || "";
  let answered = await authnSignin.signIn(base + realmBase,
    new URL(where, base).toString(),
    { action: "login", username: user, password: password },
    { cookie: cookies.header() });
  cookies.keep(answered);
  for (let step = 0; step < 2 && answered.next === "password-change";
       step++) {
    answered = await authnSignin.changePassword(base + realmBase,
      answered.location, { new_password: newPassword,
                           confirm_password: newPassword },
      { cookie: cookies.header() });
    cookies.keep(answered);
    answered = await authnSignin.ignoreOffer(base + realmBase, answered);
    cookies.keep(answered);
  }
  // THE CONSENT SCREEN, which product draws for a client that is not one of
  // this service's own (`/oauth2/consent`, #576): Allow, as a person would.
  let at = await hop(answered.location || authorize);
  for (let i = 0; i < 6 && (at.status === 302 || at.status === 303) &&
       String(at.headers.get("location") || "").indexOf(callback) !== 0;
       i++) {
    const next = new URL(at.headers.get("location"), base).toString();
    if (authnSignin.isConsent(next)) {
      const allowed = await authnSignin.consentFor(next, cookies.header());
      cookies.keep(allowed);
      at = await hop(allowed.location || authorize);
    } else {
      at = await hop(next);
    }
  }
  const back = new URL(at.headers.get("location") || base, base);
  const code = back.searchParams.get("code") || "";
  const minted = await call("POST", base + realmBase + "/oauth2/token", {
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "authorization_code",
      code: code, redirect_uri: callback, client_id: OTHER_CLIENT,
      code_verifier: pkce.verifier,
      resource: base + realmBase + "/admin-api" }).toString() });
  log.debug("Leaving signInThroughAnotherClient(). " + minted.status);
  return { cookies: cookies, minted: minted, code: code,
           where: answered.next + " " + at.status + " " +
                  (at.headers.get("location") || "") };
}

// ---------------------------------------------------------------------------
// 6. THE CLAIM AT ISSUANCE (D12, tests/console_claim_at_issuance.js).
// ---------------------------------------------------------------------------
async function theClaimAtIssuance() {
  log.debug("Entering theClaimAtIssuance().");
  log.info("=== 6. the bootstrap administrator claims at issuance ===");
  const defaultBefore = await api("GET", "/admin-api/rbac");
  const made = await api("POST", "/admin-api/realms/create", {
    id: CLAIM_REALM, domain: CLAIM_REALM + ".example.net",
    name: "Claim at issuance " + STAMP });
  assert.strictEqual(made.status, 200, "creating " + CLAIM_REALM +
                     " answered " + made.status + " " +
                     made.text.slice(0, 300));
  const CR = "/realm/" + CLAIM_REALM;
  const admin = made.body.username || made.body.bootstrap.username;
  const generated = made.body.password;
  const created = await api("POST", CR + "/admin-api/applications/create", {
    identifier: OTHER_CLIENT, kind: "oauth2-client", name: OTHER_CLIENT,
    protocols: ["oauth2", "oidc"],
    fields: { oauthClientId: [OTHER_CLIENT],
              oauthTokenEndpointAuthMethod: "none",
              oauthGrantType: ["authorization_code"],
              oauthAllowedScope: ["openid"],
              oauthDelegatedPermission: ["urn:sts:admin-api:admin:read",
                                         "urn:sts:admin-api:admin:write"],
              oauthRedirectUri: ["https://" + OTHER_CLIENT +
                                 ".example/cb"] } });
  assert.strictEqual(created.status, 200, "creating the other client " +
                     "answered " + created.status + " " +
                     created.text.slice(0, 300));
  const pending = await api("GET", CR + "/admin-api/rbac");
  check("6.1 before the claim the bootstrap administrator is seeded and " +
        "pending, its password required", function () {
    assert.ok(pending.body.bootstrap.seeded &&
              !pending.body.bootstrap.claimedAt,
              JSON.stringify(pending.body.bootstrap));
    assert.strictEqual(pending.body.bootstrapPasswordRequired, true);
  });
  const other = await signInThroughAnotherClient(CR, admin, generated,
                                                 NEW_ADMIN_PASSWORD);
  const otherScope = String((other.minted.body &&
                             other.minted.body.scope) || "");
  const afterOther = await api("GET", CR + "/admin-api/rbac");
  check("6.2 another client, on a password sign-in as the bootstrap " +
        "administrator, is issued no admin scope and claims nothing",
        function () {
    assert.ok(other.code, "the other client's request got no code: " +
              other.where);
    assert.strictEqual(other.minted.status, 200,
                       other.minted.text.slice(0, 300));
    assert.ok(!/admin:(read|write)/.test(otherScope), otherScope);
    assert.ok(!afterOther.body.bootstrap.claimedAt,
              JSON.stringify(afterOther.body.bootstrap));
  });
  const consoleClient = await consoleOverSession(CR,
                                                 other.cookies.header());
  const me = await consolePage(consoleClient, "/admin-api/me");
  let roster = await api("GET", CR + "/admin-api/rbac");
  for (let attempt = 0; attempt < 40 && !roster.body.bootstrap.claimedAt;
       attempt++) {
    await new Promise(function (r) { setTimeout(r, 500); });
    roster = await api("GET", CR + "/admin-api/rbac");
  }
  check("6.3 the console's client over the same session claims the " +
        "console, recorded on the account", function () {
    assert.ok(roster.body.bootstrap.claimedAt,
              JSON.stringify(roster.body.bootstrap));
    assert.strictEqual(roster.body.bootstrapPasswordRequired, false);
  });
  check("6.4 and is issued both admin scopes", function () {
    assert.strictEqual(me.status, 200, me.text.slice(0, 300));
    assert.ok((me.body.scopes || []).indexOf("admin:read") >= 0 &&
              (me.body.scopes || []).indexOf("admin:write") >= 0,
              JSON.stringify(me.body.scopes));
    assert.strictEqual(me.body.write, true);
  });
  const defaultAfter = await api("GET", "/admin-api/rbac");
  check("6.5 the default realm's own window is exactly as it was",
        function () {
    assert.strictEqual(JSON.stringify(defaultAfter.body.bootstrap),
                       JSON.stringify(defaultBefore.body.bootstrap));
    assert.strictEqual(defaultAfter.body.windowOpens,
                       defaultBefore.body.windowOpens);
  });
  log.debug("Leaving theClaimAtIssuance().");
}

async function testBody() {
  log.debug("Entering testBody().");
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
  if (product) {
    await theClaimAtIssuance();
  } else {
    await aProductRealmInADevelopmentProcess();
  }

  // A FLOOR ON THE COUNT, for the reason sts_roles.js gives: a section that
  // stops being called takes its assertions with it and the run still says
  // "passed".
  const floor = product ? 14 : 13;
  assert.ok(checks >= floor,
    "only " + checks + " checks ran where at least " + floor + " should " +
    "have, so a SECTION STOPPED BEING CALLED.");
  log.info(checks + " checks passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving testBody().");
}

// D12'S TWO REALMS ARE REMOVED ONLY WHEN STS_TEST_REMOVE_REALMS IS "1": a
// private probe many jobs share fills its directory otherwise, while the
// suite's own rule (tests/CLAUDE.md, *No job removes a realm*) leaves them.
async function test() {
  log.debug("Entering test().");
  try {
    await testBody();
  } finally {
    if (process.env.STS_TEST_REMOVE_REALMS === "1") {
      for (const id of [PRODUCT_REALM, CLAIM_REALM]) {
        const r = await api("POST", "/admin-api/realms/remove", { id: id });
        log.info("Removed the realm " + id + ": " + r.status);
      }
    }
  }
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

// The stored certificates come off first (#1061); `forgetStored()` never
// throws, so the verdict below is the test's.
function forgetTheStored() {
  log.debug("Entering forgetTheStored().");
  log.debug("Leaving forgetTheStored().");
  return credentials.forgetStored({
    get: function (url) {
      return call("GET", url);
    },
    post: function (url, payload) {
      return call("POST", url, {
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload) });
    } }, base, storedHere);
}

test().then(function () {
  return forgetTheStored().then(function () {
    return credentials.settleAnchors(base, addedAnchors, null);
  });
}, function (e) {
  // Cleanup still runs, and the original failure is passed through
  // settleAnchors(), which rethrows it.
  log.debug("Caught in test(): " + ((e && e.message) || e));
  return forgetTheStored().then(function () {
    return credentials.settleAnchors(base, addedAnchors, e);
  });
}).catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
