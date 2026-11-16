// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_service_accounts.js
//
// ---------------------------------------------------------------------------
// SERVICE ACCOUNTS OVER THE WIRE (#221 P1, P2, P4, 2026-10-06).
//
// In a throwaway realm it leaves behind, through /admin-api alone:
//
//   a. a create naming a service account with an owner who is nobody is
//      REFUSED, and nobody is left behind as an ordinary person;
//   b. a create naming a real owner makes one, and /admin-api/users tags it
//      and filters it with ?kind=service and ?kind=person;
//   c. its person page describes it — its owners, and the policy's
//      defaults: no browser sign-in, no exemption, no rotation; and (#600)
//      it may name two owners, and an empty list is refused once it names
//      one;
//   d. the service-account policy is the third kind on /admin-api/policies,
//      and a save of it is read back, inherited by nothing else;
//   e. Rotate now is REFUSED for an account that names no destination, and
//      for a person;
//   f. GET /admin-api/service-accounts lists it with the realm's rotation
//      settings;
//   g. set-service-account false is refused: a service account is never
//      made an ordinary person again (rcbj, 2026-11-15).
//
// D12 (#444) carries over what `tests/service_accounts.js` holds that a
// client sees, in two more throwaway realms — one development, one born in
// product (`overrides: { "global.mode": "product" }`):
//
//   h. the refusals of `set-service-account` by their codes on the realm's
//      audit: nobody (STS-SVCACCT-0021), no owner while one is required
//      (0023), an owner who is nobody (0024), the account as its own owner
//      (0025), half a destination (0026), `serviceAccount` false on a
//      service account (0060); a create with a bad owner is
//      0024; Rotate now refuses a person (0040) and an account naming no
//      destination (0041);
//   i. the policy: a save leaving a field out is refused by name; rotation
//      with no push destination is refused (STS-SVCACCT-0002); with
//      `requireOwner` off an account may have no owner;
//   j. the doors in development: the OAuth 2.0 password grant takes the
//      account, the sign-in screen refuses it (STS-SVCACCT-0010) while an
//      ordinary person signs in; the grant's door closed refuses its right
//      password as a wrong one is (invalid_grant, STS-OAUTH-0220) and
//      `allowBrowserSignIn` lets the screen take it;
//   k. the doors in product, over LDAPS: the account's RIGHT password
//      binds; with `allowLdapBind` off it is refused as a wrong one is
//      (invalidCredentials, STS-SVCACCT-0011); with a second factor
//      required of it its password alone is refused (STS-AUTHN-0213) until
//      the realm exempts service accounts; the screen refuses it there too;
//   l. an LDAP modify making a person a service account with no owner is
//      refused while one is required, and with an owner is accepted with
//      the auxiliary class beside the flag;
//   m. over LDAP, a modify deleting the flag (STS-SVCACCT-0064) or the last
//      owner (0065) is refused, an owner bound as themselves cannot take
//      themselves off (0066), and another owner may take them off while an
//      owner remains (rcbj, 2026-11-15).
//
// What stays in process (its D12 note): the rotation's push, commit,
// overlap and alarm against a fake destination, the KDC's question, the
// keyed session funnel, and inheriting the DEFAULT realm's profile (a write
// to the default realm this job may not make on a shared service).
//
// Its realms are removed at the end only when STS_TEST_REMOVE_REALMS is
// "1" (a shared private probe would fill otherwise); the suite leaves them.
//
// `local: true` in MANIFEST.js: this repository's own /admin-api.
// ---------------------------------------------------------------------------

const assert = require("assert");
const crypto = require("crypto");
const ldapjs = require("ldapjs");
const names = require("./random_username.js");
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
var log = bunyan.createLogger({ name: "sts_service_accounts",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const REALM = ("svc221-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                               .slice(0, 31);
const realmApi = base + "/realm/" + REALM + "/admin-api";
const OWNER = "svc221-owner-" + STAMP.toLowerCase();
const OWNER_TWO = "svc221-owner2-" + STAMP.toLowerCase();
const ACCOUNT = "svc221-acct-" + STAMP.toLowerCase();
const REFUSED = "svc221-refused-" + STAMP.toLowerCase();
const DEV = ("svcd-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
  .slice(0, 31);
const PROD = ("svcp-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
  .slice(0, 31);
const PASSWORD = "Sv1c-Acc0unt-Pa55word!x";
const WEB = "svc-web";
const CONFIDENTIAL = "svc-grant";
const CONFIDENTIAL_SECRET = "svc-grant-secret-" + STAMP.toLowerCase();

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
    // Not JSON — an empty answer or a page; the caller reads `raw`.
    body = null;
  }
  log.debug("Leaving send(). status=" + r.status);
  return { status: r.status, body: body, raw: raw };
}

function postJson(url, payload) {
  log.debug("Entering postJson().");
  log.debug("Leaving postJson().");
  return send(url, { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {}) });
}

async function ok(url, payload, what) {
  log.debug("Entering ok().");
  const r = await postJson(url, payload);
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "POST " + url + " should have " + what + "; it answered " + r.status +
    " " + String(r.raw).slice(0, 400));
  log.debug("Leaving ok().");
  return r.body;
}

function ownerAttributes(who) {
  log.debug("Entering ownerAttributes().");
  log.debug("Leaving ownerAttributes().");
  return { givenName: "Owner", sn: who,
           mail: who + "@" + REALM + ".example.net" };
}

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

// The audit rows of one code in the realm whose API this is: a code is
// recorded, never sent.
async function codeCount(api, code) {
  log.debug("Entering codeCount(). " + code);
  const r = await send(api + "/audit?per=1&code=" + encodeURIComponent(code));
  assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
  log.debug("Leaving codeCount().");
  return Number(r.body.matched || 0);
}

// Runs `act` and answers it with how far the code's count grew.
async function coded(api, code, act) {
  log.debug("Entering coded(). " + code);
  const before = await codeCount(api, code);
  const answer = await act();
  let now = before;
  for (let i = 0; i < 20 && now <= before; i += 1) {
    now = await codeCount(api, code);
    if (now <= before) {
      await sleep(150);
    }
  }
  log.debug("Leaving coded(). " + before + " -> " + now);
  return { answer: answer, grew: now - before };
}

function refusedWith(got, code, what) {
  log.debug("Entering refusedWith(). " + code);
  check(what + ", recorded as " + code, function () {
    assert.ok(got.answer.status >= 400 && got.answer.status < 500,
              got.answer.status + " " + got.answer.raw.slice(0, 300));
    assert.strictEqual(got.grew, 1, code + " rows grew by " + got.grew);
    assert.ok(got.answer.raw.indexOf(code) < 0, "the code was sent");
  });
  log.debug("Leaving refusedWith().");
}

// The whole service-account profile, `default` as the realm reads it, with
// `changes` on top: a save replaces the whole profile.
async function fullPolicy(api, changes) {
  log.debug("Entering fullPolicy().");
  const r = await send(api + "/policies");
  const out = Object.assign({}, r.body.serviceAccount.defaults, changes || {});
  log.debug("Leaving fullPolicy().");
  return out;
}

// A person's stored attributes, as the users view answers them.
function attributesOf(view) {
  log.debug("Entering attributesOf().");
  const ldap = (view && view.ldap) || {};
  log.debug("Leaving attributesOf().");
  return (ldap.entry && ldap.entry.attributes) || {};
}

function person(api, who, extra) {
  log.debug("Entering person(). " + who);
  log.debug("Leaving person().");
  return ok(api + "/users/create", Object.assign({ username: who,
    invent: false, credential: "password", password: PASSWORD,
    attributes: { cn: "Person " + who, givenName: "Person", sn: who,
                  mail: who + "@svc.example.net" } }, extra || {}),
    "created " + who);
}

function ldapUrl() {
  log.debug("Entering ldapUrl().");
  const host = new URL(base).hostname;
  log.debug("Leaving ldapUrl().");
  return process.env.STS_LDAPS_URL ||
    ("ldaps://" + host + ":" + (process.env.STS_LDAPS_PORT || 636));
}

// One LDAPS connection: bound as `dn` with `password`, then `then(client)`.
// Answers the bind's result code (0 for success) and what `then` answered.
function overLdap(dn, password, then) {
  log.debug("Entering overLdap(). dn=" + dn);
  log.debug("Leaving overLdap().");
  return new Promise(function (resolve) {
    const client = ldapjs.createClient({ url: ldapUrl(), reconnect: false,
      timeout: 20000, connectTimeout: 15000,
      tlsOptions: { rejectUnauthorized:
                      process.env.NODE_TLS_REJECT_UNAUTHORIZED !== "0" } });
    client.on("error", function (e) {
      // The operation in flight reports it; an unhandled 'error' would throw.
      log.debug("The LDAP client emitted an error: " + e.message);
    });
    client.bind(dn, password, function (e) {
      const code = e ? e.code : 0;
      if (e || !then) {
        client.unbind();
        resolve({ code: code, then: null });
        return;
      }
      then(client).then(function (out) {
        client.unbind();
        resolve({ code: 0, then: out });
      }, function (err) {
        log.debug("Caught in overLdap(): " + ((err && err.message) || err));
        client.unbind();
        resolve({ code: 0, then: { code: (err && err.code) || -1 } });
      });
    });
  });
}

function modify(client, dn, changes) {
  log.debug("Entering modify(). dn=" + dn);
  log.debug("Leaving modify().");
  return new Promise(function (resolve) {
    client.modify(dn, changes.map(function (one) {
      return new ldapjs.Change({ operation: one[0],
        modification: new ldapjs.Attribute({ type: one[1],
                                             values: one[2] }) });
    }), function (e) {
      // The refusal's text is the result's diagnosticMessage (#261): the
      // client error's own `message` is the result code's name ("Constraint
      // Violation"), which is what section m read in run #300.
      resolve({ code: e ? e.code : 0, message: e ? String(
        e.diagnosticMessage || e.lde_message || e.message || "") : "" });
    });
  });
}

function dnOf(realm, who) {
  log.debug("Entering dnOf().");
  log.debug("Leaving dnOf().");
  return "uid=" + who + ",ou=users,dc=" + realm.split(".").join(",dc=") +
         ",dc=example,dc=net";
}

// The sign-in screen for `who`, reached through an authorization request of
// the realm's public client `WEB`, as a browser reaches it.
async function screenSignIn(realmBase, who, password) {
  log.debug("Entering screenSignIn(). " + who);
  const verifier = crypto.randomBytes(32).toString("base64url");
  const at = await fetch(realmBase + "/oauth2/authorize?" +
    new URLSearchParams({ response_type: "code", client_id: WEB,
      redirect_uri: "https://svc-web.example.net/cb", scope: "openid",
      state: "s-" + STAMP, code_challenge_method: "S256",
      code_challenge: crypto.createHash("sha256").update(verifier)
        .digest("base64url") }).toString(), { redirect: "manual" });
  const where = new URL(at.headers.get("location") || "", realmBase)
    .toString();
  assert.ok(/\/authn\/login/.test(where), "the authorization request went " +
            at.status + " -> " + where);
  const answer = await authnSignin.signIn(realmBase, where,
    { action: "login", username: who, password: password }, {});
  log.debug("Leaving screenSignIn(). " + answer.next);
  return answer;
}

function passwordGrant(realmBase, who) {
  log.debug("Entering passwordGrant(). " + who);
  log.debug("Leaving passwordGrant().");
  return send(realmBase + "/oauth2/token", { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "password", username: who,
      password: PASSWORD, client_id: CONFIDENTIAL,
      client_secret: CONFIDENTIAL_SECRET, scope: "openid" }).toString() });
}

async function aRealmWithClients(id, overrides) {
  log.debug("Entering aRealmWithClients(). " + id);
  await ok(base + "/admin-api/realms/create", Object.assign({ id: id,
    domain: id + ".example.net", name: "Service account doors " + STAMP },
    overrides ? { overrides: overrides } : {}), "created the realm " + id);
  const api = base + "/realm/" + id + "/admin-api";
  await ok(api + "/applications/create", { identifier: WEB,
    kind: "oauth2-client", name: WEB, protocols: ["oauth2", "oidc"],
    fields: { oauthClientId: [WEB], oauthTokenEndpointAuthMethod: "none",
              oauthGrantType: ["authorization_code"],
              oauthRedirectUri: ["https://svc-web.example.net/cb"] } },
    "created the realm's sign-in client");
  await ok(api + "/applications/create", { identifier: CONFIDENTIAL,
    kind: "oauth2-client", name: CONFIDENTIAL, protocols: ["oauth2"],
    fields: { oauthClientId: [CONFIDENTIAL],
              oauthClientSecret: CONFIDENTIAL_SECRET,
              oauthTokenEndpointAuthMethod: "client_secret_post",
              oauthGrantType: ["password"],
              oauthRedirectUri: ["https://svc-grant.example.net/cb"] } },
    "created the realm's password-grant client");
  log.debug("Leaving aRealmWithClients().");
  return api;
}

async function theRefusalsByCode() {
  log.debug("Entering theRefusalsByCode().");
  log.info("=== h. the refusals, by their codes ===");
  const api = base + "/realm/" + DEV + "/admin-api";
  await person(api, "svc-h");
  await person(api, "svc-h-owner");
  const setTo = function (body) {
    return function () {
      return postJson(api + "/users/set-service-account", body);
    };
  };
  refusedWith(await coded(api, "STS-SVCACCT-0021", setTo({
    user: "svc-h-nobody", owners: ["svc-h-owner"] })),
    "STS-SVCACCT-0021", "nobody by that name is refused");
  refusedWith(await coded(api, "STS-SVCACCT-0023", setTo({
    user: "svc-h" })),
    "STS-SVCACCT-0023", "no owner is refused while one is required");
  refusedWith(await coded(api, "STS-SVCACCT-0024", setTo({
    user: "svc-h", owners: ["nobody-here"] })),
    "STS-SVCACCT-0024", "an owner who is neither a person nor a group is " +
    "refused");
  refusedWith(await coded(api, "STS-SVCACCT-0025", setTo({
    user: "svc-h", owners: ["svc-h"] })),
    "STS-SVCACCT-0025", "an account cannot own itself");
  refusedWith(await coded(api, "STS-SVCACCT-0026", setTo({
    user: "svc-h", owners: ["svc-h-owner"], secretName: "x" })),
    "STS-SVCACCT-0026", "a secret name without a destination is refused");
  refusedWith(await coded(api, "STS-SVCACCT-0024", function () {
    return postJson(api + "/users/create", { username: "svc-h-refused",
      invent: false, credential: "none", serviceAccount: true,
      owners: ["nobody-at-all"] });
  }), "STS-SVCACCT-0024", "a create with a bad owner is refused before " +
      "anybody exists");
  await ok(api + "/users/set-service-account", { user: "svc-h",
    owners: ["svc-h-owner"] }, "made svc-h a service account");
  const page = await send(api + "/users?user=svc-h");
  check("a person owns it, and its entry carries the auxiliary class",
        function () {
    const sa = page.body.serviceAccount;
    assert.ok(sa && sa.owners.length === 1 && sa.owners[0].kind === "person",
              JSON.stringify(sa));
    const classes = attributesOf(page.body).objectClass || [];
    assert.ok(classes.indexOf("stsServiceAccount") >= 0,
              JSON.stringify(classes));
  });
  refusedWith(await coded(api, "STS-SVCACCT-0040", function () {
    return postJson(api + "/users/rotate-password", { user: "svc-h-owner" });
  }), "STS-SVCACCT-0040", "Rotate now refuses a person");
  refusedWith(await coded(api, "STS-SVCACCT-0041", function () {
    return postJson(api + "/users/rotate-password", { user: "svc-h" });
  }), "STS-SVCACCT-0041", "and an account naming no destination");
  // ONCE A SERVICE ACCOUNT, ALWAYS ONE (rcbj, 2026-11-15).
  refusedWith(await coded(api, "STS-SVCACCT-0060", setTo({
    user: "svc-h", serviceAccount: false })),
    "STS-SVCACCT-0060", "a service account is not made a person again");
  const cleared = await send(api + "/users?user=svc-h");
  check("and the class and the owner stay on the entry", function () {
    const attrs = attributesOf(cleared.body);
    const keys = Object.keys(attrs).map(function (k) {
      return k.toLowerCase();
    });
    assert.ok(keys.indexOf("stsserviceaccountowner") >= 0, keys.join(","));
    assert.ok((attrs.objectClass || attrs.objectclass || [])
      .indexOf("stsServiceAccount") >= 0);
  });
  log.debug("Leaving theRefusalsByCode().");
}

async function thePolicy() {
  log.debug("Entering thePolicy().");
  log.info("=== i. the policy's own rules ===");
  const api = base + "/realm/" + DEV + "/admin-api";
  const partial = await postJson(api + "/policies/save-serviceAccount-policy",
                                 { allowBrowserSignIn: true });
  check("a save that leaves a field out is refused by name", function () {
    assert.strictEqual(partial.status, 400, partial.raw.slice(0, 300));
    assert.ok((partial.body.errors || []).some(function (one) {
      return /`requireOwner`.*required/.test(one);
    }), partial.raw.slice(0, 400));
  });
  refusedWith(await coded(api, "STS-SVCACCT-0002", async function () {
    return postJson(api + "/policies/save-serviceAccount-policy",
                    await fullPolicy(api, { rotationEnabled: true }));
  }), "STS-SVCACCT-0002", "rotation is refused in a realm with no push " +
      "destination");
  await ok(api + "/policies/save-serviceAccount-policy",
           await fullPolicy(api, { requireOwner: false }),
           "turned requireOwner off");
  await person(api, "svc-unowned");
  const unowned = await postJson(api + "/users/set-service-account",
                                 { user: "svc-unowned" });
  check("with requireOwner off a service account may have none",
        function () {
    assert.strictEqual(unowned.status, 200, unowned.raw.slice(0, 300));
    assert.strictEqual(unowned.body.serviceAccount, true);
  });
  await ok(api + "/policies/reset-serviceAccount-policy", {},
           "reset the realm's policy");
  log.debug("Leaving thePolicy().");
}

async function theDoorsInDevelopment() {
  log.debug("Entering theDoorsInDevelopment().");
  log.info("=== j. the doors, in development ===");
  const api = base + "/realm/" + DEV + "/admin-api";
  const realmBase = base + "/realm/" + DEV;
  await person(api, "svc-d");
  await person(api, "svc-d-owner");
  await ok(api + "/users/set-service-account", { user: "svc-d",
    owners: ["svc-d-owner"] }, "made svc-d a service account");
  const grant = await passwordGrant(realmBase, "svc-d");
  check("the password grant's door is open, and takes the account",
        function () {
    assert.strictEqual(grant.status, 200, grant.raw.slice(0, 300));
    assert.ok(grant.body.access_token);
  });
  const screen = await coded(api, "STS-SVCACCT-0010", function () {
    return screenSignIn(realmBase, "svc-d", PASSWORD);
  });
  check("the sign-in screen refuses it by default, recorded as " +
        "STS-SVCACCT-0010", function () {
    assert.strictEqual(screen.answer.next, "refused",
                       JSON.stringify(screen.answer.json));
    // The credential check and the screen's refusal each record it.
    assert.ok(screen.grew >= 1, "STS-SVCACCT-0010 rows grew by " +
              screen.grew);
  });
  const owner = await screenSignIn(realmBase, "svc-d-owner", PASSWORD);
  check("an ordinary person is asked nothing new", function () {
    assert.strictEqual(owner.next, "redirect", JSON.stringify(owner.json));
  });
  await ok(api + "/policies/save-serviceAccount-policy",
           await fullPolicy(api, { allowPasswordGrant: false,
                                   allowBrowserSignIn: true }),
           "closed the password grant's door and opened the browser");
  // OBSERVED: the token endpoint records the closed door as it records a
  // wrong password, STS-OAUTH-0220 ("did not verify"), not the credential
  // check's STS-SVCACCT-0011 — the refusal reads as a wrong password's.
  const closed = await coded(api, "STS-OAUTH-0220", function () {
    return passwordGrant(realmBase, "svc-d");
  });
  check("a closed door refuses the account's right password as a wrong " +
        "one is, recorded as STS-OAUTH-0220", function () {
    assert.strictEqual(closed.answer.status, 400,
                       closed.answer.raw.slice(0, 300));
    assert.strictEqual(closed.answer.body.error, "invalid_grant");
    assert.strictEqual(closed.grew, 1);
  });
  const opened = await screenSignIn(realmBase, "svc-d", PASSWORD);
  check("allowBrowserSignIn lets the screen take it", function () {
    assert.strictEqual(opened.next, "redirect", JSON.stringify(opened.json));
  });
  await ok(api + "/policies/reset-serviceAccount-policy", {},
           "reset the realm's policy");
  log.debug("Leaving theDoorsInDevelopment().");
}

async function theDoorsInProduct() {
  log.debug("Entering theDoorsInProduct().");
  log.info("=== k. the doors, in product, over LDAPS ===");
  const api = await aRealmWithClients(PROD, { "global.mode": "product" });
  const realmBase = base + "/realm/" + PROD;
  await person(api, "svc-p");
  await person(api, "svc-p-owner");
  await ok(api + "/users/set-service-account", { user: "svc-p",
    owners: ["svc-p-owner"] }, "made svc-p a service account");
  const dn = dnOf(PROD, "svc-p");
  const open = await overLdap(dn, PASSWORD);
  check("PRODUCT: the account's right password binds at the open door",
        function () {
    assert.strictEqual(open.code, 0);
  });
  const wrong = await overLdap(dn, PASSWORD + "-wrong");
  check("PRODUCT: a wrong one does not", function () {
    assert.strictEqual(wrong.code, 49);
  });
  const screen = await coded(api, "STS-SVCACCT-0010", function () {
    return screenSignIn(realmBase, "svc-p", PASSWORD);
  });
  check("PRODUCT: the sign-in screen refuses it, recorded as " +
        "STS-SVCACCT-0010", function () {
    assert.strictEqual(screen.answer.next, "refused",
                       JSON.stringify(screen.answer.json));
    // The credential check and the screen's refusal each record it.
    assert.ok(screen.grew >= 1, "STS-SVCACCT-0010 rows grew by " +
              screen.grew);
  });
  await ok(api + "/policies/save-serviceAccount-policy",
           await fullPolicy(api, { allowLdapBind: false }),
           "closed the LDAP door");
  const closed = await coded(api, "STS-SVCACCT-0011", function () {
    return overLdap(dn, PASSWORD);
  });
  check("PRODUCT: the closed door refuses its RIGHT password as a wrong " +
        "one is, recorded as STS-SVCACCT-0011", function () {
    assert.strictEqual(closed.answer.code, 49);
    assert.strictEqual(closed.grew, 1);
  });
  await ok(api + "/policies/reset-serviceAccount-policy", {},
           "reset the realm's policy");
  await ok(api + "/users/require-mfa", { user: "svc-p" },
           "required a second factor of the account");
  const alone = await coded(api, "STS-AUTHN-0213", function () {
    return overLdap(dn, PASSWORD);
  });
  check("PRODUCT: with a second factor required its password alone is " +
        "refused at the password-only door, recorded as STS-AUTHN-0213",
        function () {
    assert.notStrictEqual(alone.answer.code, 0);
    assert.strictEqual(alone.grew, 1);
  });
  await ok(api + "/policies/save-serviceAccount-policy",
           await fullPolicy(api, { exemptFromSecondFactor: true }),
           "exempted service accounts from the second factor");
  const exempt = await overLdap(dn, PASSWORD);
  check("PRODUCT: an exempting realm asks it for none, and the door takes " +
        "its password", function () {
    assert.strictEqual(exempt.code, 0);
  });
  await ok(api + "/policies/reset-serviceAccount-policy", {},
           "reset the realm's policy");
  log.debug("Leaving theDoorsInProduct().");
}

async function anLdapModify() {
  log.debug("Entering anLdapModify().");
  log.info("=== l. an LDAP modify meets the same rules ===");
  const api = base + "/realm/" + DEV + "/admin-api";
  await person(api, "svc-l");
  await person(api, "svc-l-owner");
  const dn = dnOf(DEV, "svc-l");
  const noOwner = await overLdap(dn, PASSWORD, function (client) {
    return modify(client, dn, [["replace", "stsServiceAccount", ["TRUE"]]]);
  });
  const still = await send(api + "/users?user=svc-l");
  check("an LDAP modify making a service account with no owner is refused " +
        "while one is required", function () {
    assert.strictEqual(noOwner.code, 0, "the bind failed");
    assert.notStrictEqual(noOwner.then.code, 0, JSON.stringify(noOwner));
    assert.strictEqual(still.body.serviceAccount, null);
  });
  const owned = await overLdap(dn, PASSWORD, function (client) {
    return modify(client, dn, [
      ["replace", "stsServiceAccount", ["TRUE"]],
      ["replace", "stsServiceAccountOwner", [dnOf(DEV, "svc-l-owner")]]]);
  });
  const after = await send(api + "/users?user=svc-l");
  check("with an owner it is accepted, and the auxiliary class is kept " +
        "beside the flag", function () {
    assert.strictEqual(owned.then.code, 0, JSON.stringify(owned));
    assert.ok(after.body.serviceAccount &&
              after.body.serviceAccount.owners.length === 1,
              JSON.stringify(after.body.serviceAccount));
    const attrs = attributesOf(after.body);
    assert.ok((attrs.objectClass || attrs.objectclass || [])
      .indexOf("stsServiceAccount") >= 0, JSON.stringify(attrs.objectClass));
  });

  // m. FOR GOOD, OVER LDAP (rcbj, 2026-11-15): the flag is never taken
  // away, the last owner never goes, and the bound DN does not take itself
  // off. Each is constraintViolation (19).
  await person(api, "svc-l-two");
  const ownerDn = dnOf(DEV, "svc-l-owner");
  const twoDn = dnOf(DEV, "svc-l-two");
  // The sentence is what a client is sent; the code is recorded, never
  // sent, so it is held by the in-process twin
  // (`tests/service_account_irreversible.js`).
  const refusedOverLdap = function (got, said, what) {
    log.debug("Entering refusedOverLdap().");
    check(what, function () {
      assert.strictEqual(got.code, 0, "the bind failed");
      assert.strictEqual(got.then.code, 19, JSON.stringify(got));
      assert.ok(said.test(got.then.message), got.then.message);
    });
    log.debug("Leaving refusedOverLdap().");
  };
  refusedOverLdap(await overLdap(dn, PASSWORD, function (client) {
    return modify(client, dn, [["delete", "stsServiceAccount", []]]);
  }), /cannot be made an ordinary person again/,
  "an LDAP modify deleting the flag is refused");
  const flagged = await send(api + "/users?user=svc-l");
  check("and it is still a service account", function () {
    assert.ok(flagged.body.serviceAccount,
              JSON.stringify(flagged.body.serviceAccount));
  });
  refusedOverLdap(await overLdap(dn, PASSWORD, function (client) {
    return modify(client, dn, [["delete", "stsServiceAccountOwner",
                                [ownerDn]]]);
  }), /at least one owner/, "an LDAP modify deleting the last owner is " +
     "refused");
  const added = await overLdap(dn, PASSWORD, function (client) {
    return modify(client, dn, [["add", "stsServiceAccountOwner", [twoDn]]]);
  });
  check("a second owner is added over LDAP", function () {
    assert.strictEqual(added.then.code, 0, JSON.stringify(added));
  });
  refusedOverLdap(await overLdap(ownerDn, PASSWORD, function (client) {
    return modify(client, dn, [["delete", "stsServiceAccountOwner",
                                [ownerDn]]]);
  }), /cannot remove themselves/, "an owner bound as themselves cannot " +
     "take themselves off");
  const byAnother = await overLdap(twoDn, PASSWORD, function (client) {
    return modify(client, dn, [["delete", "stsServiceAccountOwner",
                                [ownerDn]]]);
  });
  const left = await send(api + "/users?user=svc-l");
  check("another owner may take them off while an owner remains",
        function () {
    assert.strictEqual(byAnother.then.code, 0, JSON.stringify(byAnother));
    assert.strictEqual(left.body.serviceAccount.owners.length, 1,
                       JSON.stringify(left.body.serviceAccount));
  });
  log.debug("Leaving anLdapModify().");
}

async function testBody() {
  log.debug("Entering testBody().");
  log.info("=== 0. a throwaway realm " + REALM + " ===");
  await ok(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "Service accounts " + STAMP },
    "created the realm");
  // The realm's attribute policy (#396) requires givenName, sn and mail of
  // every person in product mode; a service account is exempt.
  await ok(realmApi + "/users/create", { username: OWNER, invent: false,
    credential: "none", attributes: ownerAttributes(OWNER) },
    "created the owner");

  log.info("=== a. a refused owner creates nobody ===");
  const refused = await postJson(realmApi + "/users/create", {
    username: REFUSED, invent: false, credential: "none",
    serviceAccount: true, owners: ["nobody-" + STAMP.toLowerCase()] });
  check("a service account whose owner is nobody is refused", function () {
    assert.ok(refused.status >= 400 && refused.status < 500,
              refused.status + " " + refused.raw.slice(0, 400));
  });
  const ghost = await send(realmApi + "/users?q=" +
                           encodeURIComponent(REFUSED));
  check("and nobody was left behind as an ordinary person", function () {
    assert.strictEqual(ghost.status, 200, ghost.raw.slice(0, 300));
    assert.ok(!(ghost.body.users || []).some(function (row) {
      return row.key === REFUSED;
    }), JSON.stringify(ghost.body.users));
  });

  log.info("=== b. a service account, tagged and filtered ===");
  const made = await ok(realmApi + "/users/create", { username: ACCOUNT,
    invent: false, credential: "none", serviceAccount: true,
    owners: [OWNER] },
    "created the service account");
  check("the create says it made a service account", function () {
    assert.strictEqual(made.serviceAccount, true, JSON.stringify(made));
  });
  const services = await send(realmApi + "/users?kind=service");
  check("?kind=service lists it, tagged, and only service accounts",
        function () {
    const rows = services.body.users || [];
    assert.ok(rows.some(function (row) {
      return row.key === ACCOUNT && row.serviceAccount === true;
    }), JSON.stringify(rows));
    assert.ok(rows.every(function (row) {
      return row.serviceAccount === true;
    }), JSON.stringify(rows));
    assert.ok(services.body.serviceAccounts >= 1);
  });
  const people = await send(realmApi + "/users?kind=person");
  check("?kind=person leaves it out", function () {
    assert.ok(!(people.body.users || []).some(function (row) {
      return row.key === ACCOUNT;
    }));
  });

  log.info("=== c. its page ===");
  const page = await send(realmApi + "/users?user=" +
                          encodeURIComponent(ACCOUNT));
  check("its page describes it, with the policy's secure defaults",
        function () {
    const sa = page.body && page.body.serviceAccount;
    assert.ok(sa && Array.isArray(sa.owners) && sa.owners.length === 1 &&
              /svc221-owner-/.test(sa.owners[0].dn) &&
              sa.owners[0].kind === "person", JSON.stringify(sa));
    assert.strictEqual(sa.policy.allowBrowserSignIn, false);
    assert.strictEqual(sa.policy.exemptFromSecondFactor, false);
    assert.strictEqual(sa.rotation.enabled, false);
  });

  log.info("=== c2. more than one owner (#600) ===");
  await ok(realmApi + "/users/create", { username: OWNER_TWO, invent: false,
    credential: "none", attributes: ownerAttributes(OWNER_TWO) },
    "created a second owner");
  await ok(realmApi + "/users/set-service-account", { user: ACCOUNT,
    owners: [OWNER, OWNER_TWO] }, "named two owners");
  const two = await send(realmApi + "/users?user=" +
                         encodeURIComponent(ACCOUNT));
  check("its page lists both owners", function () {
    const sa = two.body && two.body.serviceAccount;
    assert.ok(sa && sa.owners.length === 2 &&
              sa.owners.every(function (one) {
                return one.kind === "person";
              }), JSON.stringify(sa));
  });
  const emptied = await postJson(realmApi + "/users/set-service-account", {
    user: ACCOUNT, owners: [] });
  check("an empty list is refused: an account that names owners keeps one",
        function () {
    assert.ok(emptied.status === 400, emptied.status + " " +
              emptied.raw.slice(0, 300));
  });
  await ok(realmApi + "/users/set-service-account", { user: ACCOUNT,
    owners: [OWNER] }, "named one owner again");

  log.info("=== d. the third kind of policy ===");
  const policies = await send(realmApi + "/policies");
  check("/admin-api/policies holds the service-account policy", function () {
    assert.ok((policies.body.kinds || []).some(function (kind) {
      return kind.id === "serviceAccount";
    }), JSON.stringify(policies.body.kinds));
    assert.ok(policies.body.actions.indexOf(
      "save-serviceAccount-policy") >= 0);
  });
  const profile = Object.assign({}, policies.body.serviceAccount.profile);
  const fields = {};
  Object.keys(profile).forEach(function (key) {
    if (typeof profile[key] === "boolean" ||
        typeof profile[key] === "number") {
      fields[key] = profile[key];
    }
  });
  delete fields.stored;
  delete fields.inherited;
  delete fields.enforced;
  // The default profile's precedence is 0, a sentinel. The save schema
  // accepts a named profile's precedence only, from 1 to 1000, and the
  // default profile does not store one.
  delete fields.precedence;
  fields.allowWsTrust = false;
  await ok(realmApi + "/policies/save-serviceAccount-policy", fields,
           "saved the realm's service-account policy");
  const after = await send(realmApi + "/policies");
  check("the save is read back, stored in this realm", function () {
    const p = after.body.serviceAccount.profile;
    assert.strictEqual(p.allowWsTrust, false, JSON.stringify(p));
    assert.strictEqual(p.stored, true);
  });

  log.info("=== e. Rotate now, refused where it cannot push ===");
  const noDest = await postJson(realmApi + "/users/rotate-password",
                                { user: ACCOUNT });
  check("an account naming no destination is refused", function () {
    assert.ok(noDest.status >= 400 && noDest.status < 500,
              noDest.status + " " + noDest.raw.slice(0, 300));
  });
  const person = await postJson(realmApi + "/users/rotate-password",
                                { user: OWNER });
  check("and so is a person", function () {
    assert.ok(person.status >= 400 && person.status < 500,
              person.status + " " + person.raw.slice(0, 300));
  });

  log.info("=== f. Monitoring → Service accounts ===");
  const monitor = await send(realmApi + "/service-accounts");
  check("GET /admin-api/service-accounts lists it, with the rotation's " +
        "settings", function () {
    assert.strictEqual(monitor.status, 200, monitor.raw.slice(0, 300));
    assert.ok((monitor.body.accounts || []).some(function (row) {
      return row.username === ACCOUNT;
    }), JSON.stringify(monitor.body.accounts));
    assert.strictEqual(monitor.body.policy.rotationEnabled, false);
    assert.ok(monitor.body.paging, JSON.stringify(monitor.body));
  });

  log.info("=== g. never an ordinary person again ===");
  const cleared = await postJson(realmApi + "/users/set-service-account",
                                 { user: ACCOUNT, serviceAccount: false });
  const still = await send(realmApi + "/users?user=" +
                           encodeURIComponent(ACCOUNT));
  check("set-service-account false is refused, and their page still " +
        "describes a service account", function () {
    assert.strictEqual(cleared.status, 400, cleared.raw.slice(0, 300));
    assert.ok(still.body.serviceAccount,
              JSON.stringify(still.body.serviceAccount));
  });

  // THE DEVELOPMENT REALM SAYS SO (run #300): section j asserts the
  // development doors — the password grant among them, which product
  // refuses as unsupported_grant_type — so in a product process its realm
  // is put in development mode, as section k puts its own in product.
  await aRealmWithClients(DEV, { "global.mode": "development" });
  await theRefusalsByCode();
  await thePolicy();
  await theDoorsInDevelopment();
  await theDoorsInProduct();
  await anLdapModify();

  log.info("Test completed successfully. " + checks + " check(s) passed.");
  log.debug("Leaving testBody().");
}

// THE REALMS ARE REMOVED ONLY WHEN STS_TEST_REMOVE_REALMS IS "1": a private
// probe many jobs share fills its directory otherwise, while the suite's own
// rule (tests/CLAUDE.md, *No job removes a realm*) leaves them standing.
async function removeRealms() {
  log.debug("Entering removeRealms().");
  if (process.env.STS_TEST_REMOVE_REALMS === "1") {
    for (const id of [REALM, DEV, PROD]) {
      const r = await fetch(base + "/admin-api/realms/remove", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: id }) });
      log.info("Removed the realm " + id + ": " + r.status);
    }
  }
  log.debug("Leaving removeRealms().");
}

async function test() {
  log.debug("Entering test().");
  try {
    await testBody();
  } finally {
    await removeRealms();
  }
  log.debug("Leaving test().");
}

test().catch(function (e) {
  log.error("sts_service_accounts FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
