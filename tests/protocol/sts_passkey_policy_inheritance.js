// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: sts_passkey_policy_inheritance.js
//
// ===========================================================================
// A REALM'S PASSKEY POLICY FOLLOWS THE DEFAULT REALM'S UNTIL IT HAS ITS OWN
// (#527), OVER THE WIRE.
//
// D12 (#444): carries over `tests/passkey_policy.js` P3. **EXCLUSIVE**,
// because it saves the DEFAULT realm's passkey profile, which every realm
// with no profile of its own follows meanwhile — every other job's passkeys
// included. It is put back with `reset-passkey-policy` in a `finally`
// (tests/CLAUDE.md, *Restore a setting with reset*), pass or fail.
//
//   1. the default realm saves its own profile (usernameless sign-in off, a
//      security key `preferred`) and `GET /admin-api/policies` says it is
//      the realm's;
//   2. a realm with no entry of its own follows it (`from` default-realm,
//      the two rows its values) — and so does what that realm's portal
//      asks a security key for;
//   3. its own entry wins;
//   4. its reset goes back to inheriting;
//   5. the default realm's reset puts the built-in profile back, for it and
//      for the realm.
//
// OWNED HERE (local: true): the passkey policy is this repository's own.
// ===========================================================================

"use strict";

const assert = require("assert");
const wire = require("./passkey_wire_kit.js");
const portalSignin = require("./portal_signin.js");

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
var log = bunyan.createLogger({ name: "sts_passkey_policy_inheritance",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const K = wire.kit("sts_passkey_policy_inheritance", { log: log });
const check = K.check;
const PASSWORD = "Pk-inherit-" + K.STAMP + "-Aa1!";
const DEFAULT = { id: "default", base: K.root, api: K.root + "/admin-api" };

async function profileOf(realm) {
  log.debug("Entering profileOf(). " + realm.id);
  const page = await K.call(realm, "GET", "/policies");
  assert.strictEqual(page.status, 200, page.raw.slice(0, 300));
  log.debug("Leaving profileOf().");
  return page.body.passkey.profile;
}

async function securityKeyAsked(client) {
  log.debug("Entering securityKeyAsked().");
  const e = await K.enrol(client, null, { kind: "security-key" });
  assert.ok(e.pending && e.pending.options, JSON.stringify(e.begun.json));
  log.debug("Leaving securityKeyAsked().");
  return e.pending.options.authenticatorSelection.residentKey;
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving the passkey policy's inheritance at " + K.root);
  const realm = await K.realm("pkinh", "development");
  const name = ("pki-" + K.STAMP).slice(0, 40);
  await K.person(realm, name, PASSWORD);
  const client = await portalSignin.signInToThePortal(realm.base, name, null,
    { password: PASSWORD });
  const before = await profileOf(DEFAULT);
  assert.strictEqual(before.from, "built-in",
    "the default realm already holds a passkey profile of its own, so " +
    "this job cannot assert inheritance from a known state: " +
    JSON.stringify(before).slice(0, 300));
  try {
    const saved = await K.savePolicy(DEFAULT, { allowUsernameless: false,
      securityKeyResidentKey: "preferred" });
    const own = await profileOf(DEFAULT);
    check("1. the default realm saves its own profile", function () {
      assert.strictEqual(saved.status, 200, saved.raw.slice(0, 300));
      assert.strictEqual(own.from, "realm", JSON.stringify(own));
    });
    const inherited = await profileOf(realm);
    const asked = await securityKeyAsked(client);
    check("2. a realm with no entry of its own follows the default realm's, " +
          "and its portal asks a security key what that profile says",
          function () {
      assert.strictEqual(inherited.from, "default-realm",
                         JSON.stringify(inherited));
      assert.strictEqual(inherited.allowUsernameless, false);
      assert.strictEqual(inherited.securityKeyResidentKey, "preferred");
      assert.strictEqual(inherited.inherited, true);
      // Usernameless OFF asks a security key `required` (rcbj's answer 1):
      // the inherited row is what decided it.
      assert.strictEqual(asked, "required");
    });
    const mine = await K.savePolicy(realm, { securityKeyResidentKey:
                                               "discouraged" });
    const ownRealm = await profileOf(realm);
    const askedOwn = await securityKeyAsked(client);
    check("3. its own entry wins", function () {
      assert.strictEqual(mine.status, 200, mine.raw.slice(0, 300));
      assert.strictEqual(ownRealm.from, "realm", JSON.stringify(ownRealm));
      assert.strictEqual(ownRealm.allowUsernameless, true);
      assert.strictEqual(askedOwn, "discouraged");
    });
    const reset = await K.call(realm, "POST", "/policies/reset-passkey-policy",
                               { profile: "default" });
    const again = await profileOf(realm);
    check("4. a reset goes back to inheriting", function () {
      assert.strictEqual(reset.status, 200, reset.raw.slice(0, 300));
      assert.strictEqual(again.from, "default-realm", JSON.stringify(again));
    });
  } finally {
    const put = await K.call(DEFAULT, "POST", "/policies/reset-passkey-policy",
                             { profile: "default" });
    log.info("the default realm's passkey profile reset: " + put.status);
  }
  const back = await profileOf(DEFAULT);
  const realmBack = await profileOf(realm);
  check("5. the default realm's reset puts the built-in profile back, for " +
        "it and for the realm", function () {
    assert.strictEqual(back.from, "built-in", JSON.stringify(back));
    assert.strictEqual(realmBack.from, "built-in", JSON.stringify(realmBack));
    assert.strictEqual(realmBack.allowUsernameless, true);
  });
  log.debug("Leaving test().");
}

K.main(test);
