// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: sts_passkey_xacml.js
//
// ===========================================================================
// THE PASSKEY REFUSALS ARE RULES OF THE ISSUANCE POLICY, AND A REALM'S OWN
// DOCUMENT IS HONOURED (#536), OVER THE WIRE.
//
// D12 (#444): carries over what a client can see of `tests/passkey_xacml.js`
// section D, in two throwaway realms, with real ceremonies from the kit's
// software authenticator. Each realm's passkey profile takes only
// device-bound passkeys (`backupEligibility: disallow`), and a person's
// synced passkey was registered before that was saved:
//
//   1. with the built-in document deciding, the synced passkey is refused
//      at sign-in (STS-AUTHN-0313);
//   2. an operator's `role-issuance` document written from the built-in
//      template (`POST /admin-api/xacml/create-from-template`) decides the
//      same until its `passkey-use-backup-eligible` rule is removed through
//      the editor (`/admin-api/xacml/remove`): then the synced passkey signs
//      in, although the passkey policy takes only device-bound ones — the
//      realm's policy decided, not the built-in rule;
//   3. its registration rule is untouched, so a synced passkey is still
//      refused at registration (STS-AUTHN-0312);
//   4. the other realm, with no document of its own, still refuses the
//      same kind of key (STS-AUTHN-0313);
//   5. a document written with `decidePasskeys: no` carries no passkey
//      rule, so the built-in rule decides again: the synced passkey is
//      refused at sign-in (STS-AUTHN-0313) and at registration
//      (STS-AUTHN-0312).
//
// NOT CARRIED: A, B and E's truth tables (the built-in rules and the strict
// reading asked of the gate with no request, class (d)); C's `refusalFor()`
// is what every ceremony asks, and its codes are asserted at real
// ceremonies by `sts_passkey_policy_profile.js` (0301, 0309, 0312-0315,
// 0333), `sts_passkey_attestation_rules.js` (0316, 0317, 0320, 0321) and
// `sts_passkey_post_quantum_*.js` (0355-0357); D4 (a realm rule refusing
// with a reason of its own and no code, STS-AUTHN-0322) needs a new rule
// with its own obligation built through the policy editor's add-rule walk —
// owed, on `sts_xacml_editor.js`'s ground.
//
// OWNED HERE (local: true): the issuance policy is this repository's own.
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
var log = bunyan.createLogger({ name: "sts_passkey_xacml",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const K = wire.kit("sts_passkey_xacml", { log: log });
const check = K.check;
const PASSWORD = "Pk-xacml-" + K.STAMP + "-Aa1!";
const POLICY = "role-issuance";

// A realm whose profile takes only device-bound passkeys, a person holding
// a synced one registered before that, and their portal.
async function realmWithASyncedKey(prefix) {
  log.debug("Entering realmWithASyncedKey(). " + prefix);
  const realm = await K.realm(prefix, "development");
  await K.client(realm);
  const name = ("pkx-" + prefix + "-" + K.STAMP).slice(0, 40);
  await K.person(realm, name, PASSWORD);
  const portal = await portalSignin.signInToThePortal(realm.base, name, null,
    { password: PASSWORD });
  const key = K.authenticator({ synced: true });
  const e = await K.enrol(portal, key);
  assert.strictEqual(e.done && e.done.status, 200,
                     JSON.stringify(e.done && e.done.json).slice(0, 300));
  await K.mustSavePolicy(realm, { backupEligibility: "disallow" });
  log.debug("Leaving realmWithASyncedKey().");
  return { realm: realm, name: name, portal: portal, key: key };
}

// A usernameless sign-in with the synced key: `{ r, recorded }`, `recorded`
// the new STS-AUTHN-0313 rows.
async function signIn(held) {
  log.debug("Entering signIn().");
  const before = await K.codeCount(held.realm, "STS-AUTHN-0313");
  const r = await K.usernameless(held.realm, function (challenge) {
    return held.key.assert(challenge);
  });
  const recorded = await K.newCodes(held.realm, "STS-AUTHN-0313", before);
  log.debug("Leaving signIn(). " + r.next);
  return { r: r, recorded: recorded };
}

// A second synced passkey's registration: `{ done, recorded }`, `recorded`
// the new STS-AUTHN-0312 rows.
async function register(held) {
  log.debug("Entering register().");
  const before = await K.codeCount(held.realm, "STS-AUTHN-0312");
  const e = await K.enrol(held.portal, K.authenticator({ synced: true }));
  if (e.pending && !(e.done && e.done.status === 200)) {
    await held.portal.api("POST", "/account-api/keys", { action: "cancel" });
  }
  const recorded = await K.newCodes(held.realm, "STS-AUTHN-0312", before);
  log.debug("Leaving register().");
  return { done: e.done, recorded: recorded };
}

async function removeRule(realm, suffix) {
  log.debug("Entering removeRule(). " + suffix);
  const view = await K.call(realm, "GET", "/xacml/editor?policy=" + POLICY);
  const row = ((view.body && view.body.tree) || []).filter(function (one) {
    return one.kind === "rule" && one.edit && one.edit.node &&
      String(one.edit.node.id).endsWith(":rule:" + suffix);
  })[0];
  assert.ok(row, "no rule " + suffix + " in " + view.raw.slice(0, 300));
  const r = await K.call(realm, "POST", "/xacml/remove",
                         { policy: POLICY, path: row.path });
  assert.strictEqual(r.status, 200, "remove " + suffix + ": " +
                     r.raw.slice(0, 300));
  log.debug("Leaving removeRule().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving the passkey rules of the issuance policy at " + K.root);
  const mine = await realmWithASyncedKey("pkx-own");
  const other = await realmWithASyncedKey("pkx-other");

  const builtIn = await signIn(mine);
  check("1. with the built-in document deciding, a synced passkey is " +
        "refused at sign-in where the profile takes only device-bound ones " +
        "(STS-AUTHN-0313)", function () {
    assert.notStrictEqual(builtIn.r.next, "redirect", K.said(builtIn.r)
      .slice(0, 300));
    assert.ok(/device-bound/.test(K.said(builtIn.r)), K.said(builtIn.r)
      .slice(0, 300));
    assert.ok(builtIn.recorded > 0, "no STS-AUTHN-0313 row");
  });

  const made = await K.call(mine.realm, "POST", "/xacml/create-from-template",
                            { name: POLICY, template: POLICY });
  const fromTemplate = await signIn(mine);
  check("2. an operator's role-issuance document from the built-in " +
        "template decides the same", function () {
    assert.strictEqual(made.status, 200, made.raw.slice(0, 300));
    assert.notStrictEqual(fromTemplate.r.next, "redirect",
                          K.said(fromTemplate.r).slice(0, 300));
    assert.ok(fromTemplate.recorded > 0, "no STS-AUTHN-0313 row");
  });
  await removeRule(mine.realm, "passkey-use-backup-eligible");
  const allowed = await signIn(mine);
  check("2. without its passkey-use-backup-eligible rule the synced " +
        "passkey signs in, although the passkey policy takes only " +
        "device-bound ones: the realm's policy decided", function () {
    assert.ok(K.redirected(allowed.r), K.said(allowed.r).slice(0, 300));
    assert.strictEqual(allowed.recorded, 0);
  });
  const stillRegistering = await register(mine);
  check("3. its registration rule is untouched: a synced passkey is still " +
        "refused at registration (STS-AUTHN-0312)", function () {
    assert.ok(stillRegistering.done && stillRegistering.done.status >= 400,
              JSON.stringify(stillRegistering.done &&
                             stillRegistering.done.json).slice(0, 300));
    assert.ok(stillRegistering.recorded > 0, "no STS-AUTHN-0312 row");
  });
  const elsewhere = await signIn(other);
  check("4. the other realm, with no document of its own, still refuses " +
        "its synced passkey (STS-AUTHN-0313)", function () {
    assert.notStrictEqual(elsewhere.r.next, "redirect",
                          K.said(elsewhere.r).slice(0, 300));
    assert.ok(elsewhere.recorded > 0, "no STS-AUTHN-0313 row");
  });

  const deleted = await K.call(mine.realm, "POST", "/xacml/delete",
                               { name: POLICY });
  const quiet = await K.call(mine.realm, "POST",
    "/xacml/create-from-template",
    { name: POLICY, template: POLICY, p_decidePasskeys: "no" });
  const fallsBack = await signIn(mine);
  const fallsBackRegistering = await register(mine);
  check("5. a document that decides no passkey leaves the built-in rule " +
        "deciding: refused at sign-in (STS-AUTHN-0313) and at registration " +
        "(STS-AUTHN-0312)", function () {
    assert.strictEqual(deleted.status, 200, deleted.raw.slice(0, 300));
    assert.strictEqual(quiet.status, 200, quiet.raw.slice(0, 300));
    assert.notStrictEqual(fallsBack.r.next, "redirect",
                          K.said(fallsBack.r).slice(0, 300));
    assert.ok(fallsBack.recorded > 0, "no STS-AUTHN-0313 row");
    assert.ok(fallsBackRegistering.done &&
              fallsBackRegistering.done.status >= 400,
              JSON.stringify(fallsBackRegistering.done &&
                             fallsBackRegistering.done.json).slice(0, 300));
    assert.ok(fallsBackRegistering.recorded > 0, "no STS-AUTHN-0312 row");
  });
  log.debug("Leaving test().");
}

K.main(test);
