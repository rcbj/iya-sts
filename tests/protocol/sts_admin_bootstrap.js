// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_admin_bootstrap.js
//
// ===========================================================================
// THE BOOTSTRAP ADMINISTRATOR, WHAT AN ADMINISTRATOR DOES TO SOMEBODY'S
// CREDENTIALS, AND THE SECOND FACTOR AN ADMINISTRATOR IS OFFERED, OVER HTTP
// (D12, #444).
//
// Every realm is seeded with its own `admin` (`admin.bootstrapUsername`)
// when it is created, so a throwaway realm is the bootstrap's known state:
//
//   A. THE BOOTSTRAP. The create answers the seeded account; it holds
//      pwdReset and both console roles; until it signs in to the console a
//      person holding no role is OPEN (`/admin-api/me`); a sign-in of
//      another realm's `admin` does not close it; the sign-in screen draws
//      the change step with no session, refuses a mismatch and the reserved
//      `invalid`, and a new password resumes the sign-in (the offered
//      second factor ignored), starts the session and clears the flag, the
//      step then spent (STS-AUTHN-0144); once `admin` has signed in to the
//      console, the person holding no role is refused; over LDAP an
//      ordinary person is deleted and a SEEDED `admin`, a realm's or the
//      default realm's, is not (53, STS-LDAP-0077); nor is it by `POST
//      /admin-api/users/delete` (400, or 403 for want of the Security
//      Administrator's role).
//   B. PRODUCT. A password reset by an administrator (shown once,
//      `forcedChange`) is refused at a door that cannot ask for a new one
//      (an LDAPS bind) and taken by the sign-in screen, which asks; a wrong
//      password never reaches the change step; the realm's password policy
//      decides the new one.
//   C. CREDENTIAL CONTROLS. `reset-password` once, and `issue-password-
//      reset`'s absolute link on the realm's base, which removes the
//      password; `/account-api/reset-password` answering the form for a
//      good link, one sentence for a bad one, refusing a mismatch, setting
//      the password and spending the link; `disable-primary-keys` and
//      `disable-mfa` refused for somebody holding nothing to disable;
//      `require-mfa` and `stop-requiring-mfa`; a sign-in of somebody of whom
//      a second factor is required and who holds none is the REQUIRED
//      set-up step, a wrong code keeps it, the right one enrols the app and
//      signs them in; `disable-mfa` then removes it and ends the session it
//      signed in; the realm's requirement reaches somebody with no flag, and
//      with both mechanisms off that sign-in is refused.
//   D. A SECOND FACTOR FOR ADMINISTRATORS, AS POLICY (#246): the field's
//      values and default; `always` refused with no second-factor mechanism;
//      an administrator OFFERED the set-up step with an Ignore, which signs
//      them in on their password; under `always` no Ignore, and an Ignore
//      posted anyway refused; somebody holding no console role never
//      offered one.
//   E. AN ENROLMENT FOR A NAME NO PERSON CAN HAVE: begin and finish of an
//      administrator's passkey enrolment for a name holding U+0000, a line
//      break, a lone surrogate or a bell, each 400, recorded STS-AUTHN-0556,
//      quoting nothing.
//
// D12 (#444): carries over tests/admin_bootstrap.js (1-3 and 5-7; 4 seeds
// against a roster at start-up, 8 is a restart-only setting, and 5c's
// `admin` made in a realm nobody seeded cannot be made over the wire: a
// realm the API creates is always seeded, and its `admin` is protected),
// tests/admin_credential_controls.js (1-7 but the Shared Signals, which
// `sts_credential_signals.js` and `sts_caep_credential_changes.js` hold, and
// 4-5's sessions a passkey signed in, which no scripted client can make),
// tests/admin_second_factor.js (A-E; F needs a risk dataset) and
// tests/admin_enrolment_unstorable_name.js (A; B and C are the persistence
// store's journal), so they stay covered when Rust replaces Node.
//
// Its realms are removed at the end only when STS_TEST_REMOVE_REALMS=1
// (see removeRealms()).
//
// OWNED HERE (local: true): this repository's own console, its sign-in
// screen and its management API.
// ===========================================================================

const assert = require("assert");
const crypto = require("crypto");
const ldap = require("ldapjs");
const names = require("./random_username.js");
const consoleSignIn = require("./console_signin.js");
const authnSignin = require("./authn_signin.js");

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
var log = bunyan.createLogger({ name: "sts_admin_bootstrap",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const LDAPS_PORT = Number(process.env.STS_LDAPS_PORT || 636);
const LDAP_PORT = Number(process.env.STS_LDAP_PORT || 389);
const STAMP = names.runStamp().toLowerCase().replace(/[^a-z0-9]/g, "");

function realmId(prefix) {
  log.debug("Entering realmId().");
  log.debug("Leaving realmId().");
  return (prefix + STAMP).slice(0, 31);
}

const BOOT = realmId("bsa");
const OTHER = realmId("bsb");
const PROD = realmId("bsp");
const CTL = realmId("bsc");
const SECOND = realmId("bsf");

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

// A call; the preload attaches the harness's token to /admin-api.
async function call(method, url, payload, headers) {
  log.debug("Entering call(). " + method + " " + url);
  const sent = Object.assign({ accept: "application/json" }, headers || {});
  const init = { method: method, headers: sent, redirect: "manual" };
  if (payload !== undefined) {
    sent["content-type"] = "application/json";
    init.body = JSON.stringify(payload);
  }
  const r = await fetch(url, init);
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in call(): " + ((e && e.message) || e));
    // Not JSON: the caller reads the text.
    json = null;
  }
  log.debug("Leaving call(). " + r.status);
  return { status: r.status, text: text, json: json, headers: r.headers };
}

function errorsOf(reply) {
  log.debug("Entering errorsOf().");
  log.debug("Leaving errorsOf().");
  return [].concat((reply && ((reply.json && reply.json.errors) ||
                              reply.errors)) || []).join(" ");
}

async function ok(url, payload, what) {
  log.debug("Entering ok().");
  const r = await call("POST", url, payload);
  assert.ok(r.status === 200 && r.json && r.json.ok !== false,
    "POST " + url + " should have " + what + "; it answered " + r.status +
    " " + r.text.slice(0, 400));
  log.debug("Leaving ok().");
  return r.json;
}

async function codeRows(realmBase, code, pathPart) {
  log.debug("Entering codeRows(). " + code);
  let found = [];
  for (let i = 0; i < 20; i += 1) {
    const r = await call("GET", realmBase + "/admin-api/audit?per=500&code=" +
                         encodeURIComponent(code));
    found = ((r.json && r.json.events) || []).filter(function (row) {
      return !pathPart || String(row.target).indexOf(pathPart) >= 0;
    });
    if (found.length) {
      break;
    }
    await sleep(150);
  }
  log.debug("Leaving codeRows(). " + found.length);
  return found;
}

// The person's directory entry, as the person page reads it.
async function entryOf(realmBase, user) {
  log.debug("Entering entryOf().");
  const r = await call("GET", realmBase + "/admin-api/users?user=" +
                       encodeURIComponent(user));
  assert.strictEqual(r.status, 200, r.text.slice(0, 200));
  log.debug("Leaving entryOf().");
  return ((r.json.ldap || {}).entry || {}).attributes || {};
}

// A pending sign-in at the realm's screen: the console's authorization
// request from a browser with no session.
async function pendingSignIn(realmBase) {
  log.debug("Entering pendingSignIn().");
  await fetch(realmBase + "/admin", { redirect: "manual" });
  const verifier = crypto.randomBytes(32).toString("base64url");
  const r = await fetch(realmBase + "/oauth2/authorize?" +
    new URLSearchParams({ response_type: "code",
      client_id: "sts-admin-console",
      redirect_uri: realmBase + "/admin/callback",
      scope: "openid admin:read", state: "s" + STAMP.slice(0, 8),
      code_challenge: crypto.createHash("sha256").update(verifier)
        .digest("base64url"),
      code_challenge_method: "S256",
      resource: realmBase + "/admin-api" }).toString(),
    { redirect: "manual" });
  const where = r.headers.get("location") || "";
  assert.ok(/[?&#]authn=/.test(where), "the authorization request should " +
            "send the browser to the sign-in screen; it answered " +
            r.status + " " + where);
  log.debug("Leaving pendingSignIn().");
  return new URL(where, realmBase).toString();
}

function sessionCookieIn(setCookies) {
  log.debug("Entering sessionCookieIn().");
  log.debug("Leaving sessionCookieIn().");
  return (setCookies || []).some(function (one) {
    return /^(__Host-)?sts_session=[^;]+/.test(String(one));
  });
}

// RFC 6238 with HMAC-SHA-1, six digits, thirty seconds: the parameters the
// set-up step's own answer names.
function totp(secret, offset) {
  log.debug("Entering totp().");
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = String(secret).replace(/[\s=]/g, "").toUpperCase();
  let bits = "";
  for (const ch of clean) {
    bits += alphabet.indexOf(ch).toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  const counter = Math.floor(Date.now() / 30000) + (offset || 0);
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const mac = crypto.createHmac("sha1", Buffer.from(bytes)).update(message)
    .digest();
  const at = mac[mac.length - 1] & 0xf;
  const value = ((mac[at] & 0x7f) << 24) | (mac[at + 1] << 16) |
    (mac[at + 2] << 8) | mac[at + 3];
  log.debug("Leaving totp().");
  return String(value % 1000000).padStart(6, "0");
}

// A simple bind as `bindDn` over plain LDAP, then a delete of `dn`:
// `{ ok, code, message }`. Development checks no password.
function ldapDelete(bindDn, dn) {
  log.debug("Entering ldapDelete().");
  return new Promise(function (resolve) {
    const client = ldap.createClient({
      url: "ldap://localhost:" + LDAP_PORT, timeout: 10000,
      connectTimeout: 10000 });
    client.on("error", function (e) {
      log.debug("Caught in ldapDelete(): " + ((e && e.message) || e));
      // A socket error is the answer: the delete did not happen.
      resolve({ ok: false, code: -1, message: String(e && e.message) });
    });
    client.bind(bindDn, "dev", function (bindErr) {
      if (bindErr) {
        client.unbind(function () {
          log.debug("Leaving ldapDelete(). The bind failed.");
          resolve({ ok: false, code: bindErr.code,
                    message: String(bindErr.message) });
        });
        return;
      }
      client.del(dn, function (err) {
        const out = err ? { ok: false, code: err.code,
                            message: String(err.message) }
                        : { ok: true, code: 0, message: "" };
        client.unbind(function () {
          log.debug("Leaving ldapDelete(). " + out.code);
          resolve(out);
        });
      });
    });
  });
}

// A simple bind over LDAPS: `{ ok, code, message }`.
function ldapsBind(dn, password) {
  log.debug("Entering ldapsBind().");
  return new Promise(function (resolve) {
    const client = ldap.createClient({
      url: "ldaps://localhost:" + LDAPS_PORT,
      tlsOptions: { rejectUnauthorized: false }, timeout: 10000,
      connectTimeout: 10000 });
    client.on("error", function (e) {
      log.debug("Caught in ldapsBind(): " + ((e && e.message) || e));
      // A socket error is the answer: the bind did not happen.
      resolve({ ok: false, code: -1, message: String(e && e.message) });
    });
    client.bind(dn, password, function (err) {
      const out = err ? { ok: false, code: err.code,
                          message: String(err.lde_message || err.message) }
                      : { ok: true, code: 0, message: "" };
      client.unbind(function () {
        log.debug("Leaving ldapsBind(). " + out.code);
        resolve(out);
      });
    });
  });
}

// ---------------------------------------------------------------------------

async function sectionA(ctx) {
  log.debug("Entering sectionA().");
  log.info("=== A. the bootstrap administrator ===");
  const rb = ctx.bootBase;
  check("A1. the realm's create answers its seeded administrator, made " +
        "now and forced to change its password", function () {
    const seeded = ctx.created[BOOT].bootstrap;
    assert.strictEqual(seeded.username, "admin");
    assert.strictEqual(seeded.created, true);
    assert.strictEqual(seeded.passwordResetRequired, true);
  });
  const before = await entryOf(rb, "admin");
  // A group is asked for by DN; the realm's tree is rooted at its domain.
  const suffix = ",ou=groups,dc=" + BOOT + ",dc=example,dc=net";
  const readers = await call("GET", rb + "/admin-api/groups?group=" +
                             encodeURIComponent("cn=admin-read" + suffix));
  const writers = await call("GET", rb + "/admin-api/groups?group=" +
                             encodeURIComponent("cn=admin-write" + suffix));
  check("A1. the entry holds pwdReset, and both console groups name it",
        function () {
    assert.deepStrictEqual(before.pwdReset, ["TRUE"], JSON.stringify(before));
    assert.ok(/uid=admin,ou=users/.test(readers.text),
              readers.text.slice(0, 300));
    assert.ok(/uid=admin,ou=users/.test(writers.text),
              writers.text.slice(0, 300));
  });
  const nobody = await consoleSignIn.signInToTheConsole(rb,
    ("bn" + STAMP).slice(0, 30), log);
  const open = await nobody.api("GET", "/admin-api/me");
  check("A2. until the bootstrap administrator signs in to the console, a " +
        "person holding no role is OPEN: reads and writes", function () {
    assert.strictEqual(open.status, 200, open.text.slice(0, 300));
    assert.strictEqual(open.json.console.open, true);
    assert.strictEqual(open.json.console.bootstrap.claimedAt, "");
    assert.strictEqual(open.json.read, true);
    assert.strictEqual(open.json.write, true);
  });

  // ANOTHER REALM'S `admin` signs in to ITS console first.
  const otherWhere = await pendingSignIn(ctx.otherBase);
  const otherLogin = await authnSignin.submit(ctx.otherBase, otherWhere,
    { action: "login", username: "admin", password: "first-Pass-1!" }, {});
  const otherPassword = "Other-Realm-" + crypto.randomBytes(6)
    .toString("base64url") + "-9!";
  await authnSignin.changePassword(ctx.otherBase, otherLogin.location,
    { new_password: otherPassword, confirm_password: otherPassword },
    { cookie: otherLogin.cookie });
  await consoleSignIn.signInToTheConsole(ctx.otherBase, "admin", log,
                                         { password: otherPassword });
  const stillOpen = await nobody.api("GET", "/admin-api/me");
  check("A3. another realm's bootstrap administrator signing in does not " +
        "close this realm's window", function () {
    assert.strictEqual(stillOpen.status, 200, stillOpen.text.slice(0, 300));
    assert.strictEqual(stillOpen.json.console.open, true);
  });

  const where = await pendingSignIn(rb);
  const login = await authnSignin.submit(rb, where, { action: "login",
    username: "admin", password: "anything-at-all" }, {});
  check("A4. the sign-in screen answers the change step (next: " +
        "password-change) and starts no session", function () {
    assert.strictEqual(login.status, 200, JSON.stringify(login.json));
    assert.strictEqual(login.next, "password-change");
    assert.ok(/\/authn\/password-change[?#]change=/.test(login.location),
              login.location);
  });
  const mismatch = await authnSignin.changePassword(rb, login.location,
    { new_password: "one-Pass-1!", confirm_password: "two-Pass-1!" },
    { cookie: login.cookie });
  check("A5. two different passwords are refused and the step kept",
        function () {
    assert.strictEqual(mismatch.status, 400, JSON.stringify(mismatch.json));
    assert.ok(/not the same/.test(errorsOf(mismatch)), errorsOf(mismatch));
  });
  const reserved = await authnSignin.changePassword(rb, login.location,
    { new_password: "invalid", confirm_password: "invalid" },
    { cookie: login.cookie });
  check("A6. the reserved refusal password `invalid` is refused",
        function () {
    assert.strictEqual(reserved.status, 400, JSON.stringify(reserved.json));
    assert.ok(/reserved/.test(errorsOf(reserved)), errorsOf(reserved));
  });
  const chosen = "Chosen-Boot-" + crypto.randomBytes(6).toString("base64url") +
                 "-42!";
  const changed = await authnSignin.changePassword(rb, login.location,
    { new_password: chosen, confirm_password: chosen },
    { cookie: login.cookie });
  const resumed = await authnSignin.ignoreOffer(rb, changed);
  const after = await entryOf(rb, "admin");
  check("A7. a new password resumes the sign-in (the offered second factor " +
        "ignored), starts the session and clears pwdReset", function () {
    assert.strictEqual(changed.next, "mfa", JSON.stringify(changed.json));
    assert.strictEqual(resumed.ignored, true);
    assert.strictEqual(resumed.next, "redirect", JSON.stringify(resumed.json));
    assert.ok(/\/oauth2\/authorize/.test(resumed.location), resumed.location);
    assert.ok(sessionCookieIn(resumed.setCookies),
              JSON.stringify(resumed.setCookies));
    assert.ok(!after.pwdReset, JSON.stringify(after.pwdReset));
  });
  const spent = await authnSignin.screen(rb, login.location,
    { page: "password-change" }).catch(function (e) {
      log.debug("Caught in sectionA(): " + ((e && e.message) || e));
      // The spent step's view refuses, which the helper may throw on.
      return { status: 400, view: null };
    });
  const spentRows = await codeRows(rb, "STS-AUTHN-0144");
  check("A8. the change step is spent: no view, recorded STS-AUTHN-0144",
        function () {
    assert.ok(!spent.view, JSON.stringify(spent.view));
    assert.ok(spentRows.length > 0, "no STS-AUTHN-0144 row");
  });

  await consoleSignIn.signInToTheConsole(rb, "admin", log,
                                         { password: chosen });
  const closed = await nobody.api("GET", "/admin-api/me");
  const refusedWrite = await nobody.api("POST", "/admin-api/groups/create",
    { group: "bs-closed-" + STAMP.slice(0, 12) });
  check("A9. once the bootstrap administrator has signed in to the " +
        "console, the person holding no role is refused", function () {
    assert.ok(closed.status === 403 ||
              (closed.status === 200 && closed.json.console.open === false &&
               closed.json.write === false),
              closed.status + " " + closed.text.slice(0, 300));
    assert.strictEqual(refusedWrite.status, 403,
                       refusedWrite.text.slice(0, 300));
  });

  // DELETED OVER LDAP: the directory's socket, where a client deletes an
  // entry. The management API's person delete (2026-11-16) is the same
  // function, and is asked below (A11c).
  const otherDn = ",ou=users,dc=" + OTHER + ",dc=example,dc=net";
  await ok(ctx.otherBase + "/admin-api/users/create", { username: "plain",
    invent: false, attributes: { cn: "Plain Person", sn: "Person" } },
    "created an ordinary person in " + OTHER);
  const plain = await ldapDelete("uid=tester" + otherDn, "uid=plain" +
                                 otherDn);
  const realmAdmin = await ldapDelete("uid=tester" + otherDn, "uid=admin" +
                                      otherDn);
  const defaultAdmin = await ldapDelete("uid=tester" + otherDn,
    "uid=admin," + ctx.defaultUsersDn);
  const protectedRows = await codeRows(ctx.otherBase, "STS-LDAP-0077",
                                       "uid=admin" + otherDn);
  const defaultRows = await codeRows(base, "STS-LDAP-0077",
                                     "uid=admin," + ctx.defaultUsersDn);
  check("A10. an ordinary person in a trust realm is deleted over LDAP",
        function () {
    assert.ok(plain.ok, JSON.stringify(plain));
  });
  check("A11. a realm's SEEDED administrator, and the default realm's, are " +
        "not: 53 unwillingToPerform, recorded STS-LDAP-0077", function () {
    assert.strictEqual(realmAdmin.code, 53, JSON.stringify(realmAdmin));
    assert.strictEqual(defaultAdmin.code, 53, JSON.stringify(defaultAdmin));
    assert.ok(protectedRows.length > 0, "no STS-LDAP-0077 row in " + OTHER);
    assert.ok(defaultRows.length > 0, "no STS-LDAP-0077 row in the default " +
              "realm");
  });
  // A NODE DEFECT, FIXED (2026-11-14, #444's D12): the trust realm's refusal
  // called its account "the default realm's bootstrap administrator".
  check("A11b. each refusal names the realm whose bootstrap administrator " +
        "it is", function () {
    const said = function (rows) {
      return rows.map(function (row) {
        return String(row.summary || "");
      }).join(" | ");
    };
    assert.ok(protectedRows.some(function (row) {
      return String(row.summary || "").indexOf("the \"" + OTHER +
        "\" realm's bootstrap administrator") >= 0;
    }), said(protectedRows));
    assert.ok(!/default realm's/.test(said(protectedRows)),
              said(protectedRows));
    assert.ok(defaultRows.some(function (row) {
      return /the default realm's bootstrap administrator/
        .test(String(row.summary || ""));
    }), said(defaultRows));
  });
  // THE MANAGEMENT API'S DOOR (2026-11-16): `POST /admin-api/users/delete`
  // reaches the directory's one person delete, so the seeded administrator
  // is refused there too, and stays. The seeded account holds the Security
  // Administrator's role, so a caller without it is turned away at the gate
  // (403) before the directory's refusal (400) is reached; either is a
  // refusal, and the entry stays.
  const viaApi = await call("POST", ctx.otherBase + "/admin-api/users/delete",
                            { user: "admin" });
  const stillThere = await call("GET", ctx.otherBase +
                                "/admin-api/users?user=admin");
  check("A11c. the management API refuses to delete the realm's seeded " +
        "administrator, and the entry stays", function () {
    assert.ok((viaApi.status === 400 &&
               /bootstrap administrator/.test(errorsOf(viaApi))) ||
              (viaApi.status === 403 &&
               /Security Administrator/.test(errorsOf(viaApi))),
              viaApi.status + " " + viaApi.text.slice(0, 300));
    assert.ok(((stillThere.json || {}).ldap || {}).dn,
              stillThere.text.slice(0, 300));
  });
  log.debug("Leaving sectionA().");
}

async function sectionB(ctx) {
  log.debug("Entering sectionB().");
  log.info("=== B. product: a reset password at the doors ===");
  const rb = ctx.prodBase;
  const reset = await ok(rb + "/admin-api/users/reset-password",
                         { user: "admin" }, "reset admin's password");
  check("B1. reset-password answers a generated password once, and forces " +
        "the change", function () {
    assert.ok(typeof reset.password === "string" &&
              reset.password.length >= 12, JSON.stringify(reset));
    assert.strictEqual(reset.forcedChange, true);
    assert.ok(/SHOWN ONCE/.test(reset.message), reset.message);
  });
  const entry = await entryOf(rb, "admin");
  const dn = "uid=admin,ou=users," + PROD.split("").length &&
    String(((await call("GET", rb + "/admin-api/users?user=admin")).json
      .ldap || {}).dn || "");
  const bind = await ldapsBind(dn, reset.password);
  const wrongBind = await ldapsBind(dn, "not-" + reset.password);
  check("B2. product: the right password flagged pwdReset is refused at a " +
        "door that cannot ask for a new one (an LDAPS bind)", function () {
    assert.deepStrictEqual(entry.pwdReset, ["TRUE"], JSON.stringify(entry));
    assert.ok(/^uid=admin,ou=users,/.test(dn), dn);
    assert.strictEqual(bind.ok, false, JSON.stringify(bind));
    assert.strictEqual(wrongBind.ok, false, JSON.stringify(wrongBind));
  });
  const wrong = await authnSignin.submit(rb, await pendingSignIn(rb),
    { action: "login", username: "admin", password: "wrong-one" }, {});
  check("B3. product: a wrong password never reaches the change step",
        function () {
    assert.strictEqual(wrong.next, "refused", JSON.stringify(wrong.json));
  });
  const right = await authnSignin.submit(rb, await pendingSignIn(rb),
    { action: "login", username: "admin", password: reset.password }, {});
  check("B4. and the right one is taken by the sign-in screen, which asks " +
        "for a new one", function () {
    assert.strictEqual(right.next, "password-change",
                       JSON.stringify(right.json));
  });
  const weak = await authnSignin.changePassword(rb, right.location,
    { new_password: "short", confirm_password: "short" },
    { cookie: right.cookie });
  const strong = "Product-Boot-" + crypto.randomBytes(8)
    .toString("base64url") + "-7!";
  const accepted = await authnSignin.changePassword(rb, right.location,
    { new_password: strong, confirm_password: strong },
    { cookie: right.cookie });
  check("B5. product: the realm's password policy refuses a weak new " +
        "password and takes a strong one", function () {
    assert.strictEqual(weak.status, 400, JSON.stringify(weak.json));
    assert.strictEqual(weak.next, "refused");
    assert.ok(accepted.next === "mfa" || accepted.next === "redirect",
              JSON.stringify(accepted.json));
  });
  log.debug("Leaving sectionB().");
}

async function setupSignIn(rb, user, password) {
  log.debug("Entering setupSignIn().");
  const login = await authnSignin.submit(rb, await pendingSignIn(rb),
    { action: "login", username: user, password: password }, {});
  let opened = null;
  if (login.next === "mfa") {
    opened = await authnSignin.step(login.location, { cookie: login.cookie });
  }
  log.debug("Leaving setupSignIn(). " + login.next);
  return { login: login, opened: opened };
}

async function sectionC(ctx) {
  log.debug("Entering sectionC().");
  log.info("=== C. what an administrator does to somebody's credentials ===");
  const rb = ctx.ctlBase;
  const alice = ("ca" + STAMP).slice(0, 30);
  const bob = ("cb" + STAMP).slice(0, 30);
  const carol = ("cc" + STAMP).slice(0, 30);
  const pw = "Ctl-Start-" + crypto.randomBytes(6).toString("base64url") +
             "-1!";
  for (const who of [alice, bob, carol]) {
    await ok(rb + "/admin-api/users/create", { username: who, invent: false,
      attributes: { cn: "Ctl " + who, sn: who }, credential: "password",
      password: pw }, "created " + who);
  }
  const reset = await ok(rb + "/admin-api/users/reset-password",
                         { user: alice }, "reset alice's password");
  const flagged = await entryOf(rb, alice);
  check("C1. reset-password returns a generated password ONCE and sets " +
        "pwdReset", function () {
    assert.ok(reset.password && reset.forcedChange === true,
              JSON.stringify(reset));
    assert.deepStrictEqual(flagged.pwdReset, ["TRUE"]);
  });
  const issued = await ok(rb + "/admin-api/users/issue-password-reset",
                          { user: alice }, "issued a reset link");
  const link = new URL(issued.resetUrl);
  const linkToken = new URLSearchParams(link.hash.slice(1)).get("token");
  check("C2. issue-password-reset answers an absolute link on the realm's " +
        "base and removes the password", function () {
    assert.strictEqual(link.origin + link.pathname,
                       rb + "/portal/reset-password");
    assert.strictEqual(link.searchParams.get("user"), alice);
    assert.ok(linkToken && linkToken.length > 20, issued.resetUrl);
    assert.strictEqual(issued.passwordRevoked, true);
  });
  const resetApi = rb + "/account-api/reset-password";
  const good = await call("GET", resetApi + "?user=" +
    encodeURIComponent(alice), undefined, { "x-link-token": linkToken });
  const bad = await call("GET", resetApi + "?user=" +
    encodeURIComponent(alice), undefined,
    { "x-link-token": linkToken.slice(0, -2) + "zz" });
  check("C3. /account-api/reset-password answers the form's view for a " +
        "good link and one sentence for a bad one", function () {
    assert.strictEqual(good.status, 200, good.text.slice(0, 300));
    assert.ok(!good.json.refused && good.json.username === alice,
              good.text.slice(0, 300));
    assert.strictEqual(bad.status, 400, bad.text.slice(0, 300));
    assert.ok(/not valid/.test(bad.text), bad.text.slice(0, 300));
  });
  const newPw = "Ctl-New-" + crypto.randomBytes(6).toString("base64url") +
                "-456!";
  const differ = await call("POST", resetApi, { user: alice,
    token: linkToken, password: newPw, confirm: newPw + "x" });
  const set = await call("POST", resetApi, { user: alice, token: linkToken,
    password: newPw, confirm: newPw });
  const again = await call("POST", resetApi, { user: alice,
    token: linkToken, password: newPw + "y", confirm: newPw + "y" });
  check("C4. two different passwords are refused; a good one is set; the " +
        "spent link is refused", function () {
    assert.strictEqual(differ.status, 400, differ.text.slice(0, 300));
    assert.ok(/do not match/.test(differ.text), differ.text.slice(0, 300));
    assert.strictEqual(set.status, 200, set.text.slice(0, 300));
    assert.ok(set.json.ok === true && set.json.view.done === true,
              set.text.slice(0, 300));
    assert.strictEqual(again.status, 400, again.text.slice(0, 300));
  });

  const noKeys = await call("POST", rb + "/admin-api/users/" +
                            "disable-primary-keys", { user: bob });
  const noMfa = await call("POST", rb + "/admin-api/users/disable-mfa",
                           { user: bob });
  check("C5. disable-primary-keys and disable-mfa are refused for somebody " +
        "holding nothing to disable", function () {
    assert.strictEqual(noKeys.status, 400, noKeys.text.slice(0, 300));
    assert.ok(/holds no passkey/.test(errorsOf(noKeys)), errorsOf(noKeys));
    assert.strictEqual(noMfa.status, 400, noMfa.text.slice(0, 300));
    assert.ok(/holds no second factor/.test(errorsOf(noMfa)),
              errorsOf(noMfa));
  });

  const required = await ok(rb + "/admin-api/users/require-mfa",
                            { user: bob }, "required a second factor");
  check("C6. require-mfa writes the per-account requirement", function () {
    assert.strictEqual(required.required, true);
    assert.strictEqual(required.requirement.byUser, true);
    assert.strictEqual(required.requirement.byRealm, false);
  });
  const atSetup = await setupSignIn(rb, bob, pw);
  check("C7. a sign-in of somebody of whom a second factor is required and " +
        "who holds none is the REQUIRED set-up step, no Ignore",
        function () {
    assert.strictEqual(atSetup.login.next, "mfa",
                       JSON.stringify(atSetup.login.json));
    assert.strictEqual(atSetup.login.step, "enrol");
    assert.strictEqual(atSetup.opened.view.page, "setup");
    assert.strictEqual(atSetup.opened.view.setup.optional, false);
    assert.ok(atSetup.opened.view.setup.offered.totp === true,
              JSON.stringify(atSetup.opened.view.setup));
  });
  const ignored = await authnSignin.stepAct(atSetup.opened, "skip", {});
  check("C8. an Ignore posted at the required step anyway is refused",
        function () {
    assert.ok(ignored.status >= 400 && ignored.next !== "redirect",
              JSON.stringify(ignored.json));
  });
  const begun = await authnSignin.stepAct(atSetup.opened, "setup/totp", {});
  const shown = await authnSignin.step(begun.location || atSetup.login.location,
                                       { cookie: atSetup.login.cookie });
  const secret = ((shown.view.setup || {}).totp || {}).secret || "";
  const wrongCode = await authnSignin.stepAct(shown, "setup/confirm",
    { code: totp(secret, 0) === "000000" ? "111111" : "000000" });
  const rightCode = await authnSignin.stepAct(shown, "setup/confirm",
    { code: totp(secret, 0) });
  check("C9. the app's secret is shown; a wrong code keeps the step; the " +
        "right one enrols the app and signs them in", function () {
    assert.ok(secret.length >= 16, JSON.stringify(shown.view.setup));
    assert.strictEqual(wrongCode.status, 400, JSON.stringify(wrongCode.json));
    assert.strictEqual(rightCode.next, "redirect",
                       JSON.stringify(rightCode.json));
    assert.ok(sessionCookieIn(rightCode.setCookies),
              JSON.stringify(rightCode.setCookies));
  });
  const totpRow = await call("GET", rb + "/admin-api/mfa");
  const bobSessions = async function () {
    const s = await call("GET", rb + "/admin-api/sessions?per=500");
    return (s.json.sessions || []).filter(function (row) {
      return row.user === bob || row.username === bob;
    }).length;
  };
  const liveBefore = await bobSessions();
  const disabled = await call("POST", rb + "/admin-api/users/disable-mfa",
                              { user: bob });
  const liveAfter = await bobSessions();
  check("C10. disable-mfa then removes the authenticator app and ends the " +
        "session it signed in", function () {
    assert.strictEqual(totpRow.status, 200);
    assert.ok(disabled.status === 200 && disabled.json.ok === true,
              disabled.text.slice(0, 300));
    assert.ok(liveBefore >= 1, String(liveBefore));
    assert.strictEqual(liveAfter, 0, String(liveAfter));
  });
  const stopped = await ok(rb + "/admin-api/users/stop-requiring-mfa",
                           { user: bob }, "stopped requiring");
  check("C11. stop-requiring-mfa takes the requirement away", function () {
    assert.strictEqual(stopped.required, false, JSON.stringify(stopped));
  });

  const policies = await call("GET", rb + "/admin-api/policies");
  const fields = authnFields(policies.json.authn.profile);
  await ok(rb + "/admin-api/policies/save-authn-policy",
           Object.assign({}, fields, { requireSecondFactor: "always" }),
           "required a second factor of the realm");
  const byRealm = await setupSignIn(rb, carol, pw);
  check("C12. the realm's requirement reaches somebody with no flag",
        function () {
    assert.strictEqual(byRealm.login.next, "mfa",
                       JSON.stringify(byRealm.login.json));
    assert.strictEqual(byRealm.opened.view.setup.optional, false);
  });
  await ok(rb + "/admin-api/policies/save-authn-policy",
           Object.assign({}, fields, { requireSecondFactor: "always",
             totpSecondFactor: false, securityKeySecondFactor: false }),
           "turned both set-up mechanisms off");
  const none = await authnSignin.submit(rb, await pendingSignIn(rb),
    { action: "login", username: carol, password: pw }, {});
  check("C13. with both mechanisms off, that sign-in is refused",
        function () {
    assert.ok(none.next === "refused" ||
              (none.next === "mfa" && none.status >= 400),
              JSON.stringify(none.json));
  });
  await ok(rb + "/admin-api/policies/reset-authn-policy", {},
           "reset the realm's authentication policy");
  log.debug("Leaving sectionC().");
}

// The authentication policy's whole profile, as a save wants it.
function authnFields(profile) {
  log.debug("Entering authnFields().");
  const out = {};
  Object.keys(profile.sources || {}).forEach(function (name) {
    out[name] = profile[name];
  });
  log.debug("Leaving authnFields().");
  return out;
}

async function sectionD(ctx) {
  log.debug("Entering sectionD().");
  log.info("=== D. a second factor for administrators, as policy ===");
  const rb = ctx.secondBase;
  const policies = await call("GET", rb + "/admin-api/policies");
  const profile = policies.json.authn.profile;
  check("D1. the field's default is `offer`", function () {
    assert.strictEqual(profile.requireSecondFactorForAdministrators, "offer");
  });
  const fields = authnFields(profile);
  // EVERY second-factor mechanism off (each `…SecondFactor` field but the
  // two requirements), which leaves an administrator nothing to set up.
  const secondOff = {};
  Object.keys(fields).forEach(function (key) {
    if (/SecondFactor$/.test(key) && key.indexOf("require") !== 0) {
      secondOff[key] = false;
    }
  });
  const noMechanism = await call("POST", rb + "/admin-api/policies/" +
    "save-authn-policy", Object.assign({}, fields, secondOff, {
      requireSecondFactorForAdministrators: "always" }));
  const unknown = await call("POST", rb + "/admin-api/policies/" +
    "save-authn-policy", Object.assign({}, fields, {
      requireSecondFactorForAdministrators: "sometimes" }));
  check("D2. `always` with no second-factor mechanism is refused, in words " +
        "naming administrators, and so is a value outside if-held, offer " +
        "and always", function () {
    assert.strictEqual(noMechanism.status, 400, noMechanism.text.slice(0, 300));
    assert.ok(/administrators/.test(errorsOf(noMechanism)),
              errorsOf(noMechanism));
    assert.strictEqual(unknown.status, 400, unknown.text.slice(0, 300));
  });
  const admin = ("da" + STAMP).slice(0, 30);
  const realmOnly = ("dr" + STAMP).slice(0, 30);
  const plain = ("dp" + STAMP).slice(0, 30);
  const pw = "Second-" + crypto.randomBytes(6).toString("base64url") + "-1!";
  for (const who of [admin, realmOnly, plain]) {
    await ok(rb + "/admin-api/users/create", { username: who, invent: false,
      attributes: { cn: "Second " + who, sn: who }, credential: "password",
      password: pw }, "created " + who);
  }
  for (const who of [admin, realmOnly]) {
    await ok(rb + "/admin-api/rbac/grant", { username: who, role: "write" },
             "made " + who + " an administrator of " + SECOND);
  }
  // NODE DEFECT, PINNED (D12): the #246 test of "holds a console role"
  // (`credentials.consoleRolesOf()` -> `adminRbac.rolesOf()`) reads the
  // DEFAULT realm's roster, not the realm the sign-in is in. So a trust
  // realm's own administrator is never offered (nor, under `always`,
  // required) a second factor, and a person of the same name who
  // administers the DEFAULT realm is. The person `admin` is therefore made
  // an administrator of the default realm too (revoked at the end), and
  // `realmOnly` pins what Node does today.
  await ok(base + "/admin-api/users/create", { username: admin,
    invent: false, attributes: { cn: "Second " + admin, sn: admin } },
    "created " + admin + " in the default realm");
  await ok(base + "/admin-api/rbac/grant", { username: admin, role: "write" },
           "made " + admin + " an administrator of the default realm");
  ctx.defaultGrant = admin;
  const notOffered = await authnSignin.submit(rb, await pendingSignIn(rb),
    { action: "login", username: realmOnly, password: pw }, {});
  check("D3a. (Node defect, pinned) an administrator of this realm alone is " +
        "NOT offered one: the roster read is the default realm's",
        function () {
    assert.strictEqual(notOffered.next, "redirect",
                       JSON.stringify(notOffered.json));
  });
  const offered = await setupSignIn(rb, admin, pw);
  check("D3. an administrator is OFFERED the set-up step, with an Ignore",
        function () {
    assert.strictEqual(offered.login.next, "mfa",
                       JSON.stringify(offered.login.json));
    assert.strictEqual(offered.login.step, "enrol");
    assert.strictEqual(offered.opened.view.setup.optional, true);
  });
  const ignored = await authnSignin.stepAct(offered.opened, "skip", {});
  check("D4. Ignore signs them in on their password", function () {
    assert.strictEqual(ignored.next, "redirect", JSON.stringify(ignored.json));
    assert.ok(sessionCookieIn(ignored.setCookies),
              JSON.stringify(ignored.setCookies));
  });
  const ordinary = await authnSignin.submit(rb, await pendingSignIn(rb),
    { action: "login", username: plain, password: pw }, {});
  check("D5. somebody holding no console role is never offered one",
        function () {
    assert.strictEqual(ordinary.next, "redirect",
                       JSON.stringify(ordinary.json));
  });
  await ok(rb + "/admin-api/policies/save-authn-policy",
           Object.assign({}, fields, {
             requireSecondFactorForAdministrators: "always" }),
           "required a second factor of administrators");
  const always = await setupSignIn(rb, admin, pw);
  const forced = always.opened
    ? await authnSignin.stepAct(always.opened, "skip", {}) : null;
  check("D6. under `always` there is no Ignore, and one posted anyway is " +
        "refused", function () {
    assert.strictEqual(always.login.next, "mfa",
                       JSON.stringify(always.login.json));
    assert.strictEqual(always.opened.view.setup.optional, false);
    assert.ok(forced && forced.status >= 400 && forced.next !== "redirect",
              JSON.stringify(forced && forced.json));
  });
  const stillPlain = await authnSignin.submit(rb, await pendingSignIn(rb),
    { action: "login", username: plain, password: pw }, {});
  check("D7. and still nobody who is not an administrator is asked",
        function () {
    assert.strictEqual(stillPlain.next, "redirect",
                       JSON.stringify(stillPlain.json));
  });
  await ok(rb + "/admin-api/policies/reset-authn-policy", {},
           "reset the realm's authentication policy");
  log.debug("Leaving sectionD().");
}

async function sectionE(ctx) {
  log.debug("Entering sectionE().");
  log.info("=== E. an enrolment for a name no person can have ===");
  const rb = ctx.ctlBase;
  const unstorable = { nul: "a\u0000b", newline: "tester\nalice",
                       lone: "a\ud800b", bell: "a\u0007b" };
  const wrong = [];
  for (const kind of Object.keys(unstorable)) {
    for (const action of ["begin-passkey-enrolment",
                          "finish-passkey-enrolment"]) {
      const r = await call("POST", rb + "/admin-api/users/" + action,
                           { user: unstorable[kind] });
      if (r.status !== 400 || r.json.ok !== false ||
          !/cannot be stored/.test(errorsOf(r)) ||
          errorsOf(r).indexOf(unstorable[kind]) >= 0) {
        wrong.push(kind + " " + action + " " + r.status + " " +
                   r.text.slice(0, 160));
      }
    }
  }
  const coded = await codeRows(rb, "STS-AUTHN-0556",
                               "/admin-api/users/finish-passkey-enrolment");
  const begunRows = await codeRows(rb, "STS-AUTHN-0556",
                                   "/admin-api/users/begin-passkey-enrolment");
  check("E1. both doors refuse a NUL, a line break, a lone surrogate and a " +
        "bell in the name, 400, quoting nothing", function () {
    assert.strictEqual(wrong.length, 0, wrong.join("; "));
  });
  check("E2. each refusal is recorded STS-AUTHN-0556", function () {
    assert.ok(coded.length >= 4, String(coded.length));
    assert.ok(begunRows.length >= 4, String(begunRows.length));
  });
  log.debug("Leaving sectionE().");
}

// THE REALMS THIS JOB MADE ARE REMOVED ONLY WHEN ASKED
// (`STS_TEST_REMOVE_REALMS=1`, which a by-hand run against a long-lived
// probe sets so its directory does not fill). The suite leaves them
// standing: tests/CLAUDE.md's *No job removes a realm* is the rule for a
// shared run, where a realm left behind is what an operator reads.
async function removeRealms(ids) {
  log.debug("Entering removeRealms().");
  if (process.env.STS_TEST_REMOVE_REALMS !== "1") {
    log.debug("Leaving removeRealms(). Not asked.");
    return;
  }
  for (const id of ids) {
    try {
      const r = await fetch(base + "/admin-api/realms/remove", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ id: id }) });
      log.info("removed the realm " + id + ": " + r.status);
    } catch (e) {
      log.debug("Caught in removeRealms(): " + ((e && e.message) || e));
      // A realm left behind is litter, not a failure of what was tested.
      log.info("could not remove the realm " + id);
    }
  }
  log.debug("Leaving removeRealms().");
}

async function test() {
  log.debug("Entering test().");
  const ids = [BOOT, OTHER, PROD, CTL, SECOND];
  log.info("=== 0. throwaway realms " + ids.join(", ") + " ===");
  const created = {};
  for (const id of ids) {
    created[id] = await ok(base + "/admin-api/realms/create", { id: id,
      domain: id + ".example.net", name: "Bootstrap " + STAMP },
      "created the realm " + id);
  }
  await ok(base + "/realm/" + PROD + "/admin-api/config/set",
           { key: "global.mode", value: "product" },
           "switched " + PROD + " to product");
  // Product requires a second factor of everybody unless a realm allows an
  // optional one; this realm's sign-ins are about the password step.
  await ok(base + "/realm/" + PROD + "/admin-api/config/set",
           { key: "authn.allowOptionalSecondFactor", value: "true" },
           "allowed an optional second factor in " + PROD);
  const ctx = { created: created, bootBase: base + "/realm/" + BOOT,
                otherBase: base + "/realm/" + OTHER,
                prodBase: base + "/realm/" + PROD,
                ctlBase: base + "/realm/" + CTL,
                secondBase: base + "/realm/" + SECOND };
  const service = await call("GET", base + "/admin-api/ldap/service");
  ctx.defaultUsersDn = service.json.usersDn;
  await sectionA(ctx);
  await sectionB(ctx);
  await sectionC(ctx);
  try {
    await sectionD(ctx);
  } finally {
    if (ctx.defaultGrant) {
      await call("POST", base + "/admin-api/rbac/revoke",
                 { username: ctx.defaultGrant, role: "write" });
    }
  }
  await sectionE(ctx);
  assert.ok(checks >= 35, "only " + checks + " checks ran");
  log.info(checks + " checks passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

let failure = null;
test().catch(function (e) {
  failure = e;
}).then(function () {
  return removeRealms([BOOT, OTHER, PROD, CTL, SECOND]);
}).then(function () {
  if (failure) {
    log.error(failure.stack || failure.message);
    process.exit(1);
  }
});
