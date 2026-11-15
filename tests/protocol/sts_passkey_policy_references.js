// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: sts_passkey_policy_references.js
//
// ===========================================================================
// AN APPLICATION AND A GROUP NAME THEIR PASSKEY POLICY, OVER THE WIRE (#609,
// reshaped by #1235).
//
// D12 (#444): carries over what a client can see of
// `tests/passkey_policy_on_application.js`, in a throwaway realm of its
// own, through `/admin-api` and the sign-in screen an authorization request
// reaches. The application `pkr-app` has the client_id `pkr-client`, so the
// two names a sign-in may carry are different:
//
//   A1. `appPasskeyPolicy` takes a named profile of the realm and refuses
//       one it does not hold (STS-REG-0203), naming the choices;
//   A3. a group names a profile through the group page's `set-policy`; a
//       name the realm does not hold (STS-LDAP-0195) and an attribute no
//       policy kind declared (STS-LDAP-0194) are refused;
//   A4/A7. a sign-in naming the application by its client_id gets the
//       profile it names — the first-use registration step offers that
//       profile's ordered classical-only list — and another application's
//       sign-in the default, which offers ML-DSA;
//   A5. the profile a member's group names wins on a lower precedence, for
//       the application and for another one; for anybody else the
//       application's applies;
//   B1. the application read's `page.passkeyPolicies`: the profile named,
//       what applies, its precedence, the profiles a group names, the link;
//   D1. a profile an application or a group names is not deleted
//       (STS-AUTHN-0538), the refusal naming its holder; named by nothing
//       it is.
//
// NOT CARRIED (class (d)): A2 (`applicationFields()`'s choices row, a
// library table; A1's refusal names the same choices), A6 (a reference
// whose profile the directory stopped answering is made only by a delete
// by hand under the reference — owed, with an LDAP client, as
// STS-AUTHN-0537), B2-B3, C and E (the console's card, sub-tabs, picker and
// the New policy form's redraw are the browser bundle's markup).
//
// OWNED HERE (local: true): the passkey policy is this repository's own.
// ===========================================================================

"use strict";

const assert = require("assert");
const wire = require("./passkey_wire_kit.js");
const fixtures = require("./oauth_fixtures.js");
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
var log = bunyan.createLogger({ name: "sts_passkey_policy_references",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const K = wire.kit("sts_passkey_policy_references", { log: log });
const check = K.check;
const APP = "pkr-app";
const CLIENT = "pkr-client";
const OTHER = "pkr-other";

function who(name) {
  log.debug("Entering who(). " + name);
  log.debug("Leaving who().");
  return ("pkr-" + name + "-" + K.STAMP).slice(0, 40);
}

async function refusedWith(realm, code, act) {
  log.debug("Entering refusedWith(). " + code);
  const before = await K.codeCount(realm, code);
  const r = await act();
  const recorded = await K.newCodes(realm, code, before);
  if (!recorded) {
    const last = await K.call(realm, "GET", "/audit?per=3&outcome=refused");
    log.info("no " + code + " row; the newest refusals: " +
             JSON.stringify(((last.body && last.body.events) || [])
               .map(function (row) {
                 return row.errorCode;
               })));
  }
  log.debug("Leaving refusedWith(). " + r.status + " " + recorded);
  return { r: r, recorded: recorded };
}

// The algorithms the first-use registration step offers `name` signing in
// to `clientId` with no password (a person with no passkey in development
// is asked to create one).
async function offered(realm, name, clientId) {
  log.debug("Entering offered(). " + name + " " + clientId);
  const s = await K.screen(realm, K.BROWSER, clientId);
  const answer = await authnSignin.submit(realm.base, s.opened.id,
    { action: "login", username: name, password: "", webauthn_only: "1" },
    { screen: s.opened, cookie: s.opened.cookie, headers: K.BROWSER });
  assert.ok(answer.next === "mfa" && answer.location,
            name + " reached no passkey step: " + K.said(answer)
              .slice(0, 300));
  const step = await authnSignin.step(answer.location,
    { cookie: answer.cookie, headers: K.BROWSER });
  const view = (step.json && step.json.view && step.json.view.webauthn) ||
               {};
  log.debug("Leaving offered().");
  return JSON.stringify(view.algorithms || null);
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving the passkey policy's references at " + K.root);
  const realm = await K.realm("pkref", "development");
  const strict = "strict-" + K.STAMP.slice(-6);
  const byGroup = "bygroup-" + K.STAMP.slice(-6);
  const group = who("group");
  const member = who("member");
  const outsider = who("outsider");
  await K.person(realm, member, null);
  await K.person(realm, outsider, null);
  const made = await K.call(realm, "POST", "/groups/create",
                            { group: group, members: [member] });
  assert.strictEqual(made.status, 200, made.raw.slice(0, 300));
  await fixtures.publicClient(realm.api, APP, [K.REDIRECT],
                              { oauthClientId: CLIENT });
  await fixtures.publicClient(realm.api, OTHER, [K.REDIRECT]);
  await K.mustSavePolicy(realm, { registrationMode: "classical-only",
    registrationAlgorithms: "ES256,RS256" }, strict, { precedence: 50 });
  await K.mustSavePolicy(realm, { registrationMode: "classical-only",
    registrationAlgorithms: "RS256" }, byGroup, { precedence: 10 });

  log.info("=== A. the references ===");
  const good = await K.call(realm, "POST", "/applications/set",
    { application: APP, attribute: "appPasskeyPolicy", value: strict });
  const ghost = await refusedWith(realm, "STS-REG-0203", function () {
    return K.call(realm, "POST", "/applications/set",
      { application: OTHER, attribute: "appPasskeyPolicy",
        value: "ghost-" + K.STAMP.slice(-6) });
  });
  const read = await K.call(realm, "GET", "/applications?application=" +
                            APP);
  check("A1. appPasskeyPolicy takes a named profile of the realm and " +
        "refuses one it does not hold (STS-REG-0203), naming default and " +
        "the realm's named profiles", function () {
    assert.strictEqual(good.status, 200, good.raw.slice(0, 300));
    assert.strictEqual([].concat(read.body.fields.appPasskeyPolicy).join(),
                       strict);
    assert.strictEqual(ghost.r.status, 400, ghost.r.raw.slice(0, 300));
    assert.ok(ghost.recorded > 0, "no STS-REG-0203 row");
    const said = JSON.stringify(ghost.r.body.errors);
    assert.ok(said.indexOf("default") >= 0 && said.indexOf(strict) >= 0 &&
              said.indexOf(byGroup) >= 0, said);
  });

  const grouped = await K.call(realm, "POST", "/groups/set-policy",
    { group: group, attribute: "stsPasskeyPolicy", policy: byGroup });
  const badValue = await refusedWith(realm, "STS-LDAP-0195", function () {
    return K.call(realm, "POST", "/groups/set-policy",
      { group: group, attribute: "stsPasskeyPolicy",
        policy: "ghost-" + K.STAMP.slice(-6) });
  });
  const badAttribute = await refusedWith(realm, "STS-LDAP-0194", function () {
    return K.call(realm, "POST", "/groups/set-policy",
      { group: group, attribute: "stsNoSuchPolicy", policy: byGroup });
  });
  check("A3. a group names a profile in stsPasskeyPolicy; a name the realm " +
        "does not hold (STS-LDAP-0195) and an undeclared attribute " +
        "(STS-LDAP-0194) are refused", function () {
    assert.strictEqual(grouped.status, 200, grouped.raw.slice(0, 300));
    assert.strictEqual(badValue.r.status, 400, badValue.r.raw.slice(0, 300));
    assert.ok(badValue.recorded > 0, "no STS-LDAP-0195 row");
    assert.strictEqual(badAttribute.r.status, 400,
                       badAttribute.r.raw.slice(0, 300));
    assert.ok(badAttribute.recorded > 0, "no STS-LDAP-0194 row");
  });

  const outsiderApp = await offered(realm, outsider, CLIENT);
  const outsiderOther = await offered(realm, outsider, OTHER);
  check("A4/A7. a sign-in naming the application by its client_id gets the " +
        "profile it names — its ordered classical-only list — and another " +
        "application's the default, which offers ML-DSA", function () {
    assert.strictEqual(outsiderApp, '["ES256","RS256"]');
    assert.ok(/ML-DSA/.test(outsiderOther), outsiderOther);
  });
  const memberApp = await offered(realm, member, CLIENT);
  const memberOther = await offered(realm, member, OTHER);
  check("A5. the profile a member's group names wins on a lower " +
        "precedence, for the application and for another one", function () {
    assert.strictEqual(memberApp, '["RS256"]');
    assert.strictEqual(memberOther, '["RS256"]');
  });

  log.info("=== B. the application read ===");
  const pk = (read.body.page || {}).passkeyPolicies;
  const reread = await K.call(realm, "GET", "/applications?application=" +
                              APP);
  const pk2 = (reread.body.page || {}).passkeyPolicies || {};
  check("B1. the read says the profile named, what applies, its " +
        "precedence, the profiles a group names, and links to it",
        function () {
    assert.ok(pk, JSON.stringify(read.body.page || {}).slice(0, 300));
    assert.strictEqual(pk2.named, strict, JSON.stringify(pk2));
    assert.strictEqual(pk2.applies, strict);
    assert.strictEqual(pk2.precedence, 50);
    assert.strictEqual(pk2.missing, false);
    assert.strictEqual(pk2.groupPolicies, 1);
    assert.strictEqual(pk2.link, "/admin/policies#passkey-profile-" + strict);
  });

  log.info("=== D. the delete ===");
  const byApp = await refusedWith(realm, "STS-AUTHN-0538", function () {
    return K.call(realm, "POST", "/policies/reset-passkey-policy",
                  { profile: strict });
  });
  const byGrp = await refusedWith(realm, "STS-AUTHN-0538", function () {
    return K.call(realm, "POST", "/policies/reset-passkey-policy",
                  { profile: byGroup });
  });
  check("D1. a profile an application or a group names is not deleted " +
        "(STS-AUTHN-0538), each refusal naming what holds it", function () {
    assert.strictEqual(byApp.r.status, 400, byApp.r.raw.slice(0, 300));
    assert.ok(byApp.r.raw.indexOf(APP) >= 0, byApp.r.raw.slice(0, 300));
    assert.strictEqual(byGrp.r.status, 400, byGrp.r.raw.slice(0, 300));
    assert.ok(byGrp.r.raw.indexOf(group) >= 0, byGrp.r.raw.slice(0, 300));
    assert.ok(byApp.recorded > 0 && byGrp.recorded > 0,
              "no STS-AUTHN-0538 rows: " + byApp.recorded + " " +
              byGrp.recorded);
  });
  await K.call(realm, "POST", "/applications/set",
    { application: APP, attribute: "appPasskeyPolicy", value: "default" });
  await K.call(realm, "POST", "/groups/set-policy",
    { group: group, attribute: "stsPasskeyPolicy", policy: "" });
  const gone = await K.call(realm, "POST", "/policies/reset-passkey-policy",
                            { profile: strict });
  const gone2 = await K.call(realm, "POST", "/policies/reset-passkey-policy",
                             { profile: byGroup });
  const after = await K.call(realm, "GET", "/policies");
  const left = ((after.body.passkey || {}).named || []).map(function (one) {
    return one.name;
  });
  const back = await offered(realm, member, CLIENT);
  check("D2. named by nothing, both are deleted, and the default applies " +
        "again", function () {
    assert.strictEqual(gone.status, 200, gone.raw.slice(0, 300));
    assert.strictEqual(gone2.status, 200, gone2.raw.slice(0, 300));
    assert.ok(left.indexOf(strict) < 0 && left.indexOf(byGroup) < 0,
              JSON.stringify(left));
    assert.ok(/ML-DSA/.test(back), back);
  });
  log.debug("Leaving test().");
}

K.main(test);
