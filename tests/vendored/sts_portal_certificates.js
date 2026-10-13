// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: sts_portal_certificates.js
//
// ===========================================================================
// /portal/certificates (2026-09-13): A PERSON'S OWN ENROLLMENT CREDENTIALS AND
// CERTIFICATES, OVER HTTP, WITH TWO REAL SIGNED-IN PEOPLE.
//
// `tests/cert_enrollment.js` holds the core in process and the three protocol
// jobs hold ACME, EST and SCEP. What is here is the PAGE, and most of it is the
// portal's one rule — the identity is the session's — asserted the only way
// that catches a handler reading a name from the request: by doing something
// to the OTHER person's credential and then reading the other person's own
// page back.
//
// **SINCE #568 THE PAGE IS DRAWN IN THE BROWSER** from `/account-api`, and
// each person signs in as the static portal does (`portal_signin.js`: PKCE,
// a DPoP-bound token): the view is `GET /account-api/certificates`, the form
// is `POST /account-api/certificates`, and the page's markup is the portal's
// own renderer drawing that answer. A secret made is the answer's
// `view.fresh`, shown once. The identity is the TOKEN's now, and section 4 —
// a post with no CSRF token until #568 — asks the same question of the
// token: a post with none is refused and makes nothing.
//
//   0. two people, with passwords, in the default realm;
//   1. the page is drawn, `no-store`, with the three protocol cards;
//   2. an ACME account binding key is made, shown ONCE, named for the owner
//      whatever the body says, and never shown again;
//   3. a SCEP challenge is made for a chosen profile, a refused profile is
//      refused, and the admin view lists it as the owner's;
//   4. no token: refused, nothing made;
//   5. the OTHER person's key cannot be deleted by the owner — answered as not
//      found — and is still on the other person's page;
//   6. a certificate enrolled over EST for each: the owner cannot revoke the
//      other's (not found, and still valid on the other's page), and revokes
//      their own;
//   7. ACME turned off in the realm: the card goes and the door refuses.
// ===========================================================================

const assert = require("assert");
const nodeCrypto = require("crypto");
const path = require("path");
const { Command, Option } = require("commander");
const { usernameFor } = require("./random_username.js");
const est = require("./est_client.js");
const portal = require("./portal_signin.js");

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
var log = bunyan.createLogger({ name: "sts_portal_certificates",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug('CONFIG_FILE could not be read, so the configuration is empty: ' +
            appconfigProblem.message);
}

const REPO = process.env.MOCK_STS_DIR || path.join(__dirname, "..", "..");
// The parent project's own PKI code, for building CSRs — the arrangement
// `sts_user_credentials.js` already uses. Nothing from the enrollment core.
const x509 = require(path.join(REPO, "common", "vendored", "x509.js"));
const keys = require(path.join(REPO, "common", "vendored", "key_material.js"));

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");
var api = base + "/admin-api";

var OWNER = usernameFor("pcert-owner");
var OTHER = usernameFor("pcert-other");
var PASSWORD = "portal-certificates-Passw0rd!-" +
  String(Date.now()).slice(-6);

var checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

async function apiPost(where, body) {
  log.debug("Entering apiPost().");
  const r = await fetch(api + where, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}) });
  const raw = await r.text();
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in apiPost(): " + ((e && e.message) || e));
    // Not JSON — the raw text says more than a parse failure.
    parsed = raw;
  }
  log.debug("Leaving apiPost().");
  return { status: r.status, body: parsed };
}

async function apiGet(where) {
  log.debug("Entering apiGet().");
  const r = await fetch(api + where);
  const raw = await r.text();
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in apiGet(): " + ((e && e.message) || e));
    // Not JSON — the raw text says more than a parse failure.
    parsed = raw;
  }
  log.debug("Leaving apiGet().");
  return { status: r.status, body: parsed, raw: raw };
}

// SIGNED IN AS THE STATIC PORTAL SIGNS IN (#568): the code flow with PKCE as
// `sts-user-portal`, a DPoP-bound token for `/account-api`.
async function signIn(who) {
  log.debug("Entering signIn(). who=" + who);
  const c = await portal.signInToThePortal(base, who, null,
                                           { password: PASSWORD });
  assert.ok(c.token, "signing in as the portal should issue a token.");
  log.debug("Leaving signIn().");
  return c;
}

// THE PAGE AS THE PORTAL DRAWS IT, from a view — the GET's, or the one a
// form's answer carries (a secret shown once): the portal's own renderer,
// in the person's language.
async function drawn(c, view) {
  log.debug("Entering drawn().");
  const table = portal.portalBundle();
  if (c.meJson === undefined) {
    c.meJson = (await c.api("GET", "/account-api/me")).json;
  }
  const me = c.meJson || {};
  const t = table.messages.WebTranslator.fromData(me.locale);
  const html = view ? table.render("/portal/certificates", view,
    { t: t, query: {}, prefix: "", origin: base, me: me,
      locale: me.locale, version: me.version,
      here: "/portal/certificates" }) : "";
  log.debug("Leaving drawn().");
  return html;
}

// The page: its view, and the markup drawn from it.
async function page(c) {
  log.debug("Entering page().");
  const r = await c.page("/portal/certificates");
  const html = await drawn(c, r.status === 200 ? r.json : null);
  log.debug("Leaving page().");
  return { status: r.status, json: r.json, headers: r.headers, text: html };
}

// The form, sent to the operation that mirrors it; `text` is the page drawn
// from the view the answer carries, where it carries one.
async function post(c, fields) {
  log.debug("Entering post().");
  const r = await c.act("/portal/certificates", fields);
  const view = r.json && r.json.view;
  const html = await drawn(c, view || null);
  log.debug("Leaving post().");
  return { status: r.status, json: r.json, headers: r.headers, text: html };
}

function kidsOn(text) {
  log.debug("Entering kidsOn().");
  log.debug("Leaving kidsOn().");
  return (String(text).match(/eab-p-[A-Za-z0-9_-]+-[0-9a-f]{16}/g) || [])
    .filter(function (one, i, all) {
      return all.indexOf(one) === i;
    });
}

async function enrollOverEst(who) {
  log.debug("Entering enrollOverEst(). who=" + who);
  const pair = await keys.generateKeyPair("ec-p256");
  const csr = await x509.certificationRequest({
    subject: "CN=" + who, publicKeyPem: pair.publicPem,
    privateKeyPem: pair.privatePem });
  const r = await est.send({
    method: "POST",
    url: base + "/.well-known/est/tls-client/simpleenroll",
    headers: { "Content-Type": "application/pkcs10",
               "Content-Transfer-Encoding": "base64" },
    body: est.requestBody(csr.der),
    basic: [who, PASSWORD] });
  log.debug("Leaving enrollOverEst(). status=" + r.status);
  return r;
}

function serialsOn(text) {
  log.debug("Entering serialsOn().");
  log.debug("Leaving serialsOn().");
  return (String(text).match(/name="serial" value="([0-9a-f]+)"/g) || [])
    .map(function (one) {
      return one.replace(/.*value="/, "").replace(/"$/, "");
    });
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving " + base + ".");

  log.info("=== 0. two people ===");
  for (const who of [OWNER, OTHER]) {
    const made = await apiPost("/users/create", {
      username: who, invent: false, credential: "password",
      password: PASSWORD,
      attributes: { cn: "Portal Certificates " + who, sn: who,
                    mail: who + "@portal-certificates.test" } });
    check(who + " is created with a password", function () {
      assert.strictEqual(made.status, 200,
                         JSON.stringify(made.body).slice(0, 300));
    });
  }

  log.info("=== 1. the page ===");
  const owner = await signIn(OWNER);
  const first = await page(owner);
  check("the page is drawn for the signed-in person, not cached", function () {
    assert.strictEqual(first.status, 200, "answered " + first.status);
    assert.ok(/no-store/.test(first.headers.get("cache-control") || ""),
              "no Cache-Control: no-store");
    assert.ok(/Your enrolled certificates/.test(first.text) &&
              /<h2>ACME<\/h2>/.test(first.text) &&
              /<h2>EST<\/h2>/.test(first.text) &&
              /<h2>SCEP<\/h2>/.test(first.text),
              "the three protocol cards are not all drawn");
    assert.ok(first.text.indexOf('name="username"') < 0,
              "a form on this page names a person");
  });

  log.info("=== 2. an ACME account binding key, shown once ===");
  // A01 (#568, and /account-api's strict bodies since 87142740): a body
  // naming somebody else is REFUSED — `username` is no field of this
  // operation — and makes nothing. The key is then made with a `kid` the
  // operation ignores, and is named for the OWNER.
  const named = await post(owner, { action: "create-eab", username: OTHER });
  check("a body naming somebody else is refused, not honoured", function () {
    assert.strictEqual(named.status, 400, "answered " + named.status);
    assert.ok(!(named.json && named.json.view && named.json.view.fresh),
              "a key was made for a body naming somebody else");
  });
  const made = await post(owner, { action: "create-eab", kid: "ignored" });
  const expectedPrefix = "eab-p-" + Buffer.from(OWNER).toString("base64url");
  const fresh = (made.json && made.json.view && made.json.view.fresh) || {};
  const kid = String(fresh.kid || "");
  const hmac = String(fresh.hmacKey || "");
  check("it is made, named for the OWNER whatever `kid` the body named, " +
        "and its HMAC key is on the page", function () {
    assert.strictEqual(made.status, 200, "answered " + made.status);
    assert.ok(kid.indexOf(expectedPrefix + "-") === 0,
              "the key id " + kid + " does not name " + OWNER);
    assert.ok(made.text.indexOf(hmac) >= 0 && made.text.indexOf(kid) >= 0,
              "the page drawn from the answer does not show the key");
    assert.strictEqual(Buffer.from(hmac, "base64url").length, 32,
                       "the HMAC key is not 32 bytes");
    assert.ok(/no-store/.test(made.headers.get("cache-control") || ""),
              "the page carrying the secret is cacheable");
    assert.ok(new RegExp("--server " + base.replace(/[.*+?^${}()|[\]\\]/g,
      "\\$&") + "/enroll/acme/directory").test(made.text),
              "no certbot line naming this service's ACME directory");
  });
  const again = await page(owner);
  check("and never again: the key id is listed, the HMAC key is not",
        function () {
    assert.ok(again.text.indexOf(kid) >= 0, "the key is not listed");
    assert.ok(again.text.indexOf(hmac) < 0 &&
              JSON.stringify(again.json).indexOf(hmac) < 0,
              "the HMAC key is shown again");
  });

  log.info("=== 3. a SCEP challenge for a profile ===");
  const challenge = await post(owner, { action: "create-challenge",
                                        profile: "email" });
  const secret = String((challenge.json && challenge.json.view &&
                         challenge.json.view.fresh &&
                         challenge.json.view.fresh.challenge) || "");
  check("it is made for the chosen profile and shown once", function () {
    assert.strictEqual(challenge.status, 200, "answered " + challenge.status);
    assert.ok(/^scep-p-[A-Za-z0-9_-]+-[0-9a-f]{16}\.[A-Za-z0-9_-]+$/
      .test(secret), "no challenge on the page: " + secret);
    assert.ok(secret.indexOf("scep-p-" +
      Buffer.from(OWNER).toString("base64url") + "-") === 0,
              "the challenge does not name the owner");
    assert.ok(/<code>email<\/code>/.test(challenge.text) &&
              challenge.text.indexOf(secret) >= 0,
              "the challenge and its profile are not shown");
  });
  const refusedProfile = await post(owner, { action: "create-challenge",
                                             profile: "kdc" });
  check("a refused profile is refused at the form's shape", function () {
    assert.strictEqual(refusedProfile.status, 400,
                       "answered " + refusedProfile.status);
  });
  const scepView = await apiGet("/scep");
  check("the SCEP console's view lists the challenge as the owner's, " +
        "without its secret", function () {
    assert.strictEqual(scepView.status, 200, "answered " + scepView.status);
    const id = secret.split(".")[0];
    assert.ok(scepView.raw.indexOf(id) >= 0, "the challenge id is not listed");
    assert.ok(scepView.raw.indexOf(secret.split(".")[1]) < 0,
              "the challenge secret is in the admin view");
  });

  // A CSRF TOKEN UNTIL #568, A DPoP-BOUND TOKEN SINCE: the same question
  // asked of the credential that replaced it — a post that carries none is
  // refused before anything is made.
  log.info("=== 4. no token ===");
  const before = kidsOn((await page(owner)).text);
  const noToken = await fetch(base + "/account-api/certificates", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action: "create-eab" }) });
  const after = kidsOn((await page(owner)).text);
  check("a post with no token is refused and makes nothing", function () {
    assert.strictEqual(noToken.status, 401, "answered " + noToken.status);
    assert.strictEqual(after.length, before.length,
                       "a key was made anyway");
  });

  log.info("=== 5. the other person's key ===");
  const other = await signIn(OTHER);
  const theirs = await post(other, { action: "create-eab" });
  const theirKid = String((theirs.json && theirs.json.view &&
                           theirs.json.view.fresh &&
                           theirs.json.view.fresh.kid) || "");
  check("the other person makes a key of their own", function () {
    assert.ok(theirKid.indexOf("eab-p-" +
      Buffer.from(OTHER).toString("base64url")) === 0, "no key: " + theirKid);
  });
  const stolen = await post(owner, { action: "delete-eab", kid: theirKid });
  const stillThere = await page(other);
  check("the owner cannot delete it — answered as not found — and it is " +
        "still on the other person's own page", function () {
    assert.strictEqual(stolen.status, 404, "answered " + stolen.status);
    assert.ok(stillThere.text.indexOf(theirKid) >= 0,
              "the other person's key is gone");
  });
  const mineGone = await post(owner, { action: "delete-eab", kid: kid });
  check("and deletes their own", function () {
    assert.strictEqual(mineGone.status, 200, "answered " + mineGone.status);
    assert.ok(mineGone.json && mineGone.json.ok && mineGone.json.message,
              "the answer says what was done");
  });

  log.info("=== 6. certificates enrolled over EST ===");
  const ownEst = await enrollOverEst(OWNER);
  const theirEst = await enrollOverEst(OTHER);
  check("each person enrolls a certificate over EST with their password",
        function () {
          assert.strictEqual(ownEst.status, 200, "owner: " + ownEst.status +
                             " " + ownEst.body.toString().slice(0, 200));
          assert.strictEqual(theirEst.status, 200, "other: " +
                             theirEst.status);
        });
  const otherPage = await page(other);
  const theirSerial = serialsOn(otherPage.text)[0] || "";
  const ownerPage = await page(owner);
  const ownSerial = serialsOn(ownerPage.text)[0] || "";
  check("each sees their own certificate and not the other's", function () {
    assert.ok(theirSerial && ownSerial && theirSerial !== ownSerial,
              "serials: " + theirSerial + " " + ownSerial);
    assert.ok(ownerPage.text.indexOf(theirSerial) < 0,
              "the owner's page lists the other person's certificate");
  });
  const wrongRevoke = await post(owner, { action: "revoke",
                                          serial: theirSerial,
                                          reason: "keyCompromise" });
  const otherAfter = await page(other);
  check("the owner cannot revoke the other's — not found — and it is still " +
        "valid and revocable on the other's page", function () {
    assert.strictEqual(wrongRevoke.status, 404,
                       "answered " + wrongRevoke.status);
    assert.ok(serialsOn(otherAfter.text).indexOf(theirSerial) >= 0,
              "the other person's certificate lost its Revoke control");
  });
  const rightRevoke = await post(owner, { action: "revoke",
                                          serial: ownSerial,
                                          reason: "cessationOfOperation" });
  const ownerAfter = await page(owner);
  check("the owner revokes their own", function () {
    assert.strictEqual(rightRevoke.status, 200,
                       "answered " + rightRevoke.status);
    assert.ok(serialsOn(ownerAfter.text).indexOf(ownSerial) < 0 &&
              /revoked/.test(ownerAfter.text),
              "the certificate is not shown revoked");
  });

  log.info("=== 7. ACME turned off ===");
  const off = await apiPost("/config/set", { key: "acme.enabled",
                                             value: "false" });
  try {
    check("ACME is turned off", function () {
      assert.strictEqual(off.status, 200, JSON.stringify(off.body));
    });
    const hidden = await page(owner);
    const door = await post(owner, { action: "create-eab" });
    check("the ACME card is gone and the door refuses", function () {
      assert.ok(!/<h2>ACME<\/h2>/.test(hidden.text), "the card is still drawn");
      assert.ok(!hidden.json.acme, "the view still carries the ACME card");
      assert.strictEqual(door.status, 403, "answered " + door.status);
    });
  } finally {
    await apiPost("/config/reset", { key: "acme.enabled" });
  }

  assert.ok(checks >= 17,
    "only " + checks + " checks ran; a section has stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_portal_certificates")
  .description("/portal/certificates: a person makes their own ACME account " +
      "binding key and SCEP challenge, each shown once and named for them " +
      "whatever the body says; cannot delete another person's key or revoke " +
      "another person's certificate; revokes their own; and a protocol " +
      "turned off is refused at the door.")
  .addOption(new Option("-u, --url <url>", "base url (unused)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
