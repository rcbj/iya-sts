// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: sts_passkey_policy_rules.js
//
// ===========================================================================
// WHAT THE PASSKEY POLICY'S ROWS DO TO A CEREMONY, OVER THE WIRE (#533,
// #535, #1112, #1235).
//
// D12 (#444): carries over the part a client can see of three in-process
// files deleted at the cutover:
//
//   A. `passkey_named_policies.js` — a named profile saved with its
//      precedence, refused with a bad name or a precedence out of 1..1000
//      (by the request schema, STS-API-0009); a group naming a profile that
//      refuses synced passkeys refusing its member's registration while the
//      default takes another person's; an application naming a profile
//      that allows no usernameless sign-in deciding what the sign-in screen
//      offers for that client and not for another; the realm's named
//      profiles not seen in another realm; a profile a group still names
//      not deleted (STS-AUTHN-0538), and once nothing names it, deleted,
//      the default selected in its place;
//   B. `passkey_names.js` — `userDisplayName` read off a real enrolment's
//      `display`: empty, the door's own name; a gap skipped and a group
//      joined; a group with a gap skipped whole; the first with a value;
//      whitespace collapsed and a value cut at 64 characters; none with a
//      value, the door's name; `rpNameExtras` appending the realm's name,
//      the organisation and both to `webauthn.rpName`; `credentialLabel`
//      labelling a new key with {kind}, the owner's rename staying; and a
//      save refusing seven groups, a bad attribute, a group of four and a
//      label with a control character (STS-AUTHN-0309);
//   C. `passkey_client_rules.js` — the `clientRules` row read to one
//      canonical text and an unreadable one refused (STS-AUTHN-0309); a
//      registration from a matching client (this suite's portal is Chrome
//      126 on Linux) offered no ML-DSA, the ceremony row's `offered` naming
//      the rule, a client outside the rule's range or family offered ML-DSA;
//      the rule not applied where a classical passkey is not allowed
//      (`webauthn.pqcOnly`, `registrationMode` pq-only, `postQuantumRequired`
//      registration-and-sign-in), and under `postQuantumRequired` sign-in the
//      portal narrowed and the sign-in screen's first-use step not; learning
//      off by default, on counting a NotSupportedError once per person, not
//      a NotAllowedError, not an offer with no ML-DSA, learning at the
//      threshold with one audit row, the learned client offered no ML-DSA,
//      switched off kept and not applied; the register paged by
//      `clientsPage`/`clientsPer`, one cleared, an unlisted one refused
//      (STS-AUTHN-0477), all cleared; and the sweep a scheduler job.
//
// NOT CARRIED (class (d)): `displaySafe()`'s control and bidirectional
// characters — the directory refuses such a value at the entry, so no
// stored attribute ever carries one to the ceremony (the whitespace and the
// length are asserted); the selection functions and the ambient selection
// as module calls (each is asserted by the ceremony it changes); `*`
// matching an unreadable client and a client with no User-Agent (the
// portal's agent is fixed, so one client is all a job here can be); a
// registration that asked for ML-DSA from a LEARNED client succeeding,
// which removes the entry — while learning is on the learned client is
// never offered ML-DSA over the wire; the sweep's ageing (a clock).
//
// EVERY REALM IS THE JOB'S OWN: each section rewrites the realm's passkey
// policy. `local: true`: written here, never vendored.
// ===========================================================================

const assert = require("assert");
const { Command, Option } = require("commander");
const portalSignin = require("./portal_signin.js");
const wire = require("./passkey_wire_kit.js");

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
var log = bunyan.createLogger({ name: "sts_passkey_policy_rules",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const k = wire.kit("sts_passkey_policy_rules", { log: log });
const check = k.check;
const PASSWORD = "Pk-Policy-" + k.STAMP + "-correct-9!";
const MLDSA = [-48, -49, -50];

function who(name) {
  log.debug("Entering who().");
  log.debug("Leaving who().");
  return name + "-" + k.STAMP;
}

function asksMlDsa(algorithms) {
  log.debug("Entering asksMlDsa().");
  log.debug("Leaving asksMlDsa().");
  return (algorithms || []).some(function (a) {
    return MLDSA.indexOf(a) >= 0;
  });
}

async function portalOf(realm, name, attributes) {
  log.debug("Entering portalOf(). " + name);
  await k.person(realm, name, PASSWORD, attributes);
  const client = await portalSignin.signInToThePortal(realm.base, name, null,
    { password: PASSWORD });
  log.debug("Leaving portalOf().");
  return client;
}

async function refusedWith(realm, code, fn) {
  log.debug("Entering refusedWith(). " + code);
  const before = await k.codeCount(realm, code);
  const r = await fn();
  const n = await k.newCodes(realm, code, before);
  log.debug("Leaving refusedWith(). " + r.status + " " + n);
  return { r: r, recorded: n };
}

// ---------------------------------------------------------------------------
// A. NAMED PASSKEY POLICIES (#535, #1235).
// ---------------------------------------------------------------------------
async function namedPolicies() {
  log.debug("Entering namedPolicies().");
  log.info("=== A. named passkey policies ===");
  const realm = await k.realm("pkpr-a", "development");
  await k.client(realm);
  const other = await k.client(realm, "pk-wire-other");
  const strict = "strict-" + k.STAMP;
  const noUser = "nouser-" + k.STAMP;
  const group = "pkn-admins-" + k.STAMP;

  const saved = await k.savePolicy(realm, { backupEligibility: "disallow" },
                                   strict, { precedence: 20 });
  // THE REQUEST SCHEMA REFUSES BOTH FIRST (STS-API-0009): `profile`'s
  // pattern and `precedence`'s range are in `/admin-api`'s closed model, so
  // the policy's own codes (STS-AUTHN-0308, and 0309 for the rank) are
  // never reached through this door.
  const badName = await refusedWith(realm, "STS-API-0009", function () {
    return k.savePolicy(realm, {}, "Bad Name!", { precedence: 20 });
  });
  const badRank = await refusedWith(realm, "STS-API-0009", function () {
    return k.savePolicy(realm, {}, "ranked-" + k.STAMP, { precedence: 0 });
  });
  check("A1. a named profile is saved with its precedence; a bad name and a " +
        "precedence out of 1..1000 are refused, by the request schema " +
        "(STS-API-0009)", function () {
    assert.strictEqual(saved.status, 200, saved.raw.slice(0, 300));
    assert.strictEqual(saved.body.profile.precedence, 20);
    assert.strictEqual(badName.r.status, 400, badName.r.raw.slice(0, 300));
    assert.ok(badName.recorded > 0, "no STS-API-0009 row");
    assert.strictEqual(badRank.r.status, 400, badRank.r.raw.slice(0, 300));
    assert.ok(badRank.recorded > 0, "no STS-API-0009 row");
  });

  const made = await k.call(realm, "POST", "/groups/create", { group: group });
  assert.strictEqual(made.status, 200, made.raw.slice(0, 300));
  const alice = who("alice");
  const bob = who("bob");
  await k.person(realm, alice, PASSWORD);
  await k.person(realm, bob, PASSWORD);
  const joined = await k.call(realm, "POST", "/groups/add-member",
                              { group: group, member: alice });
  assert.strictEqual(joined.status, 200, joined.raw.slice(0, 300));
  const named = await k.call(realm, "POST", "/groups/set-policy",
    { group: group, attribute: "stsPasskeyPolicy", policy: strict });
  assert.strictEqual(named.status, 200, named.raw.slice(0, 300));
  const aliceTry = await firstUse(realm, alice,
                                  k.authenticator({ synced: true }));
  const bobTry = await firstUse(realm, bob, k.authenticator({ synced: true }));
  check("A2. BY GROUP: the profile the group names refuses its member's " +
        "synced passkey, and the default takes the other person's",
        function () {
    assert.notStrictEqual(aliceTry.next, "redirect",
                          k.said(aliceTry).slice(0, 300));
    assert.ok(/device-bound passkeys/.test(k.said(aliceTry)),
              k.said(aliceTry).slice(0, 300));
    assert.strictEqual(bobTry.next, "redirect", k.said(bobTry).slice(0, 300));
  });

  await k.mustSavePolicy(realm, { allowUsernameless: false }, noUser,
                         { precedence: 5 });
  const pointed = await k.call(realm, "POST", "/applications/set",
    { application: k.CLIENT, attribute: "appPasskeyPolicy", value: noUser });
  assert.strictEqual(pointed.status, 200, pointed.raw.slice(0, 300));
  const forApp = await k.screen(realm, null, k.CLIENT);
  const forOther = await k.screen(realm, null, other);
  check("A3. BY APPLICATION: the profile the application names decides what " +
        "its sign-in screen offers — no passkey without a username — and " +
        "another client's screen, under the default, still offers it",
        function () {
    assert.strictEqual(forApp.view.passkey, false);
    assert.strictEqual(forOther.view.passkey, true);
  });

  const elsewhere = await k.realm("pkpr-a2", "development");
  const theirs = await k.call(elsewhere, "GET", "/policies");
  const names = ((theirs.body && theirs.body.passkey &&
                  theirs.body.passkey.named) || []).map(function (one) {
    return one.name;
  });
  check("A4. a realm's named profiles are its own: another realm lists none " +
        "of them", function () {
    assert.ok(names.indexOf(strict) < 0 && names.indexOf(noUser) < 0,
              JSON.stringify(names));
  });

  const held = await refusedWith(realm, "STS-AUTHN-0538", function () {
    return k.call(realm, "POST", "/policies/reset-passkey-policy",
                  { profile: strict });
  });
  await k.call(realm, "POST", "/groups/set-policy",
    { group: group, attribute: "stsPasskeyPolicy", policy: "" });
  const gone = await k.call(realm, "POST", "/policies/reset-passkey-policy",
                            { profile: strict });
  const after = await k.call(realm, "GET", "/policies");
  const left = ((after.body.passkey || {}).named || []).map(function (one) {
    return one.name;
  });
  const aliceAgain = await firstUse(realm, alice,
                                    k.authenticator({ synced: true }));
  check("A5. a profile a group still names is not deleted (STS-AUTHN-0538); " +
        "named by nothing it is, and its member's synced passkey is taken " +
        "under the default", function () {
    assert.strictEqual(held.r.status, 400, held.r.raw.slice(0, 300));
    assert.ok(held.recorded > 0, "no STS-AUTHN-0538 row");
    assert.strictEqual(gone.status, 200, gone.raw.slice(0, 300));
    assert.ok(left.indexOf(strict) < 0, JSON.stringify(left));
    assert.strictEqual(aliceAgain.next, "redirect",
                       k.said(aliceAgain).slice(0, 300));
  });
  log.debug("Leaving namedPolicies().");
}

// A first use at the sign-in screen (development): its answer.
async function firstUse(realm, name, auth) {
  log.debug("Entering firstUse(). " + name);
  const t = await k.typed(realm, name, {});
  assert.ok(t.step, name + " reached no step: " +
            k.said(t.answer).slice(0, 300));
  const done = await k.ceremony(t.step, function (c) {
    return auth.register(c.challenge, c.user && c.user.id, c.rpId);
  });
  done.step = t.step;
  log.debug("Leaving firstUse(). " + done.next);
  return done;
}

// ---------------------------------------------------------------------------
// B. THE NAMES A PASSKEY PROMPT SHOWS (#533).
// ---------------------------------------------------------------------------
async function promptNames() {
  log.debug("Entering promptNames().");
  log.info("=== B. the names a passkey prompt shows ===");
  const realm = await k.realm("pkpr-b", "development");
  const grace = who("grace");
  const portal = await portalOf(realm, grace, {
    givenName: "Grace", sn: "Hopper", cn: "G. Hopper",
    mail: "grace-" + k.STAMP + "@example.test",
    title: "  spaced    out   title  ", description: "x".repeat(80) });
  const display = async function (order) {
    log.debug("Entering display(). " + order);
    await k.mustSavePolicy(realm, { userDisplayName: order });
    const begun = await k.enrol(portal, null, {});
    log.debug("Leaving display().");
    return (begun.pending || {}).display;
  };
  const door = await display("");
  const gap = await display("displayName, givenName sn, cn");
  const partial = await display("displayName, givenName displayName, cn");
  const firstValue = await display("displayName, mail");
  const spaced = await display("title");
  const long = await display("description");
  const none = await display("displayName");
  check("B1. userDisplayName: empty is the door's own name; a gap is " +
        "skipped and a group joins its values; a group with one attribute " +
        "missing is skipped whole; the first with a value wins; whitespace " +
        "is collapsed and a value cut at 64 characters; none with a value " +
        "is the door's name", function () {
    assert.ok(door && door.indexOf(grace) === 0, String(door));
    assert.strictEqual(gap, "Grace Hopper");
    assert.strictEqual(partial, "G. Hopper");
    assert.strictEqual(firstValue, "grace-" + k.STAMP + "@example.test");
    assert.strictEqual(spaced, "spaced out title");
    assert.strictEqual(long, "x".repeat(64));
    assert.strictEqual(none, door);
  });

  await k.mustSet(realm, "webauthn.rpName", "Example Login");
  await k.mustSet(realm, "saml.organizationName", "Acme Corp");
  const rpName = async function (extras) {
    log.debug("Entering rpName(). " + extras);
    await k.mustSavePolicy(realm, { rpNameExtras: extras });
    const begun = await k.enrol(portal, null, {});
    log.debug("Leaving rpName().");
    return (((begun.pending || {}).options || {}).rp || {}).name;
  };
  const plain = await rpName("none");
  const withRealm = await rpName("realm");
  const withOrg = await rpName("organisation");
  const both = await rpName("realm-and-organisation");
  check("B2. rpNameExtras: rp.name alone, then with the realm's name, the " +
        "organisation and both", function () {
    assert.strictEqual(plain, "Example Login");
    assert.strictEqual(withRealm, "Example Login — " + realm.name);
    assert.strictEqual(withOrg, "Example Login — Acme Corp");
    assert.strictEqual(both, "Example Login — " + realm.name +
                       " — Acme Corp");
  });
  await k.reset(realm, "webauthn.rpName");
  await k.reset(realm, "saml.organizationName");

  await k.mustSavePolicy(realm, {});
  const first = k.authenticator({});
  const done = await k.enrol(portal, first, {});
  await k.mustSavePolicy(realm, { credentialLabel: "Work {kind}" });
  const second = k.authenticator({});
  const done2 = await k.enrol(portal, second, {});
  const keys = await k.keysOf(realm, grace);
  const labelOf = function (id) {
    log.debug("Entering labelOf().");
    log.debug("Leaving labelOf().");
    return (keys.filter(function (one) {
      return one.credentialId === id;
    })[0] || {}).label;
  };
  const renamed = await portal.api("POST", "/account-api/keys/rename",
    { credentialId: second.credentialId, label: "My laptop" });
  const afterRename = await k.keysOf(realm, grace);
  check("B3. credentialLabel: empty gives the default name; set, a new key " +
        "is labelled from it with {kind} filled in; the owner's rename " +
        "stays", function () {
    assert.strictEqual(done.done.status, 200);
    assert.strictEqual(done2.done.status, 200);
    assert.ok(labelOf(first.credentialId) &&
              labelOf(first.credentialId) !== "Work Passkey",
              String(labelOf(first.credentialId)));
    assert.strictEqual(labelOf(second.credentialId), "Work Passkey");
    assert.strictEqual(renamed.status, 200, String(renamed.text)
      .slice(0, 300));
    assert.strictEqual((afterRename.filter(function (one) {
      return one.credentialId === second.credentialId;
    })[0] || {}).label, "My laptop");
  });

  const refusals = [];
  for (const fields of [{ userDisplayName: "a, b, c, d, e, f, g" },
                        { userDisplayName: "displayName, 9lives" },
                        { userDisplayName: "a b c d" },
                        { credentialLabel: "Key\u0007" }]) {
    refusals.push(await refusedWith(realm, "STS-AUTHN-0309", function () {
      return k.savePolicy(realm, fields);
    }));
  }
  check("B4. a save refuses seven groups, a bad attribute name, a group of " +
        "four and a label with a control character (STS-AUTHN-0309)",
        function () {
    refusals.forEach(function (one) {
      assert.strictEqual(one.r.status, 400, one.r.raw.slice(0, 300));
      assert.ok(one.recorded > 0, "no STS-AUTHN-0309 row for " +
                one.r.raw.slice(0, 200));
    });
  });
  log.debug("Leaving promptNames().");
}

// ---------------------------------------------------------------------------
// C. THE CLIENTS OFFERED NO ML-DSA (#1112).
// ---------------------------------------------------------------------------
async function clientRules() {
  log.debug("Entering clientRules().");
  log.info("=== C. client rules ===");
  const realm = await k.realm("pkpr-c", "development");
  await k.client(realm);
  const readBack = async function () {
    log.debug("Entering readBack().");
    const page = await k.call(realm, "GET", "/policies");
    log.debug("Leaving readBack().");
    return page.body.passkey.profile.clientRules;
  };
  await k.mustSavePolicy(realm, { clientRules: "chrome 120- on  Linux;  * " +
    "on Android 13 ;Chrome 130-141 on macOS; Safari -18 on *" });
  const canonical = await readBack();
  const bad = [];
  for (const rule of ["Firefox", "Chrome 141-130 on macOS", "<b> on Linux",
                      "Chrome on", new Array(22).join("Chrome on Linux;")]) {
    bad.push(await refusedWith(realm, "STS-AUTHN-0309", function () {
      return k.savePolicy(realm, { clientRules: rule });
    }));
  }
  check("C1. client rules are read to one canonical text; a rule that is " +
        "not `<browser> on <system>`, an empty range, markup and more than " +
        "twenty rules are refused at the save (STS-AUTHN-0309)", function () {
    assert.strictEqual(canonical, "chrome 120- on Linux; * on Android 13; " +
                       "Chrome 130-141 on macOS; Safari -18 on *");
    bad.forEach(function (one) {
      assert.strictEqual(one.r.status, 400, one.r.raw.slice(0, 300));
      assert.ok(one.recorded > 0, "no STS-AUTHN-0309 row");
    });
  });

  const person = who("cr");
  const portal = await portalOf(realm, person);
  const offerUnder = async function (rule, extra) {
    log.debug("Entering offerUnder(). " + rule);
    await k.mustSavePolicy(realm, Object.assign({ clientRules: rule },
                                                extra || {}));
    const begun = await k.enrol(portal, null, {});
    log.debug("Leaving offerUnder().");
    return ((begun.pending || {}).options || {}).algorithms || [];
  };
  const matching = await offerUnder("Chrome 120- on linux");
  // The refused ceremony's row says what was offered, then the rule.
  const begun = await k.enrol(portal, null, {});
  await portal.api("POST", "/account-api/keys", { action: "finish",
    enrolment_id: begun.pending.id,
    credential: JSON.stringify({ error: "NotAllowedError" }) });
  const rows = await k.call(realm, "GET",
                            "/audit?per=50&action=webauthn.ceremony");
  const offered = String((((rows.body.rows || rows.body.events || [])[0] ||
                           {}).detail || {}).offered || "");
  const outOfRange = await offerUnder("Chrome 127- on Linux");
  const otherFamily = await offerUnder("Firefox on Linux");
  const anyBrowser = await offerUnder("* on Linux");
  check("C2. a registration from a matching client (Chrome 126 on Linux) " +
        "offers no ML-DSA, and the ceremony row's `offered` says what was " +
        "offered, then the rule; a range the version is outside, another " +
        "family, offer ML-DSA as before; `*` is any browser", function () {
    assert.ok(matching.length > 0 && !asksMlDsa(matching),
              JSON.stringify(matching));
    assert.ok(/^[^|]+\|configured: Chrome 120- on linux$/.test(offered) &&
              offered.indexOf("ML-DSA") < 0, offered);
    assert.ok(asksMlDsa(outOfRange), JSON.stringify(outOfRange));
    assert.ok(asksMlDsa(otherFamily), JSON.stringify(otherFamily));
    assert.ok(!asksMlDsa(anyBrowser), JSON.stringify(anyBrowser));
  });

  await k.mustSet(realm, "webauthn.pqcOnly", true);
  let pqcOnly;
  try {
    pqcOnly = await offerUnder("Chrome on Linux");
  } finally {
    await k.reset(realm, "webauthn.pqcOnly");
  }
  const pqMode = await offerUnder("Chrome on Linux",
                                  { registrationMode: "pq-only" });
  const required = await offerUnder("Chrome on Linux",
    { postQuantumRequired: "registration-and-sign-in" });
  check("C3. where a classical passkey is not allowed — webauthn.pqcOnly, " +
        "registrationMode pq-only, postQuantumRequired " +
        "registration-and-sign-in — the rule is not applied: ML-DSA is " +
        "offered", function () {
    assert.ok(asksMlDsa(pqcOnly), JSON.stringify(pqcOnly));
    assert.ok(asksMlDsa(pqMode), JSON.stringify(pqMode));
    assert.ok(asksMlDsa(required), JSON.stringify(required));
  });
  const atPortal = await offerUnder("Chrome on Linux",
                                    { postQuantumRequired: "sign-in" });
  const t = await k.typed(realm, who("step"), {});
  const armed = t.step ? await k.ceremony(t.step, function () {
    return { error: "NotAllowedError" };
  }) : null;
  const atStep = (((armed || {}).armed || {}).json || {}).options || {};
  check("C4. under postQuantumRequired sign-in the portal is narrowed and " +
        "the sign-in screen's first-use step is not (its key would not sign " +
        "the person in)", function () {
    assert.ok(!asksMlDsa(atPortal), JSON.stringify(atPortal));
    assert.ok(t.step, k.said(t.answer).slice(0, 300));
    assert.ok(asksMlDsa(atStep.algorithms), JSON.stringify(atStep));
  });

  await k.mustSavePolicy(realm, {});
  const register = async function () {
    log.debug("Entering register().");
    const page = await k.call(realm, "GET", "/policies?clientsPer=200");
    log.debug("Leaving register().");
    return page.body.passkey.clients;
  };
  const fail = async function (client, error) {
    log.debug("Entering fail(). " + error);
    const b = await k.enrol(client, null, {});
    const r = await client.api("POST", "/account-api/keys", {
      action: "finish", enrolment_id: b.pending.id,
      credential: JSON.stringify({ error: error }) });
    log.debug("Leaving fail(). " + r.status);
    return b;
  };
  await fail(portal, "NotSupportedError");
  const offByDefault = await register();
  await k.mustSet(realm, "webauthn.clientLearning", true);
  await k.mustSet(realm, "webauthn.clientLearningFailures", 2);
  await fail(portal, "NotSupportedError");
  await fail(portal, "NotSupportedError");
  const second = await portalOf(realm, who("cr2"));
  await fail(second, "NotAllowedError");
  await k.mustSavePolicy(realm, { registrationMode: "classical-only" });
  const third = await portalOf(realm, who("cr3"));
  await fail(third, "NotSupportedError");
  await k.mustSavePolicy(realm, {});
  const counting = await register();
  check("C5. learning is off by default — a failure is not counted; on, one " +
        "person counts once, and a NotAllowedError and an offer with no " +
        "ML-DSA count nothing", function () {
    assert.strictEqual(offByDefault.learning, false);
    assert.strictEqual(offByDefault.rows.length, 0,
                       JSON.stringify(offByDefault.rows));
    assert.strictEqual(counting.rows.length, 1, JSON.stringify(counting));
    assert.strictEqual(counting.rows[0].client, "Chrome 126 on Linux");
    assert.strictEqual(counting.rows[0].failures, 1);
    assert.ok(!counting.rows[0].learned);
  });
  const fourth = await portalOf(realm, who("cr4"));
  await fail(fourth, "NotSupportedError");
  const learnt = await register();
  const learntRows = await k.call(realm, "GET", "/audit?per=50&action=" +
                                  "webauthn.client.learned");
  const next = await k.enrol(fourth, null, {});
  check("C6. a second person's failure learns the client, with one audit " +
        "row, and its next registration offers no ML-DSA", function () {
    assert.strictEqual(learnt.rows.length, 1, JSON.stringify(learnt));
    assert.strictEqual(learnt.rows[0].learned, true);
    assert.strictEqual(learnt.rows[0].learnedFailures, 2);
    assert.strictEqual(Number(learntRows.body.matched), 1,
                       learntRows.raw.slice(0, 300));
    assert.ok(!asksMlDsa(next.pending.options.algorithms),
              JSON.stringify(next.pending.options.algorithms));
  });
  await k.mustSet(realm, "webauthn.clientLearning", false);
  const off = await k.enrol(fourth, null, {});
  const kept = await register();
  check("C7. learning switched off, the entry is kept and not applied",
        function () {
    assert.ok(asksMlDsa(off.pending.options.algorithms),
              JSON.stringify(off.pending.options.algorithms));
    assert.strictEqual(kept.rows.length, 1, JSON.stringify(kept));
  });

  const paged = await k.call(realm, "GET",
                             "/policies?clientsPage=1&clientsPer=10");
  const unlisted = await refusedWith(realm, "STS-AUTHN-0477", function () {
    return k.call(realm, "POST", "/policies/clear-passkey-client",
                  { client: "Nobody 1 on Nothing 2" });
  });
  const cleared = await k.call(realm, "POST", "/policies/clear-passkey-client",
                               { client: "Chrome 126 on Linux" });
  await k.mustSet(realm, "webauthn.clientLearning", true);
  await k.mustSet(realm, "webauthn.clientLearningFailures", 1);
  await fail(fourth, "NotSupportedError");
  const all = await k.call(realm, "POST", "/policies/clear-passkey-clients",
                           {});
  const empty = await register();
  const scheduler = await k.call(realm, "GET", "/scheduler");
  check("C8. the register on the policies view is paged by clientsPage and " +
        "clientsPer; one learned client is cleared, an unlisted one is " +
        "refused (STS-AUTHN-0477), every one is cleared at once; the sweep " +
        "is a scheduler job", function () {
    const clients = paged.body.passkey.clients;
    assert.strictEqual(clients.paging.per, 10, JSON.stringify(clients.paging));
    assert.strictEqual(clients.paging.page, 1);
    assert.strictEqual(clients.paging.total, 1);
    assert.strictEqual(unlisted.r.status, 400, unlisted.r.raw.slice(0, 300));
    assert.ok(unlisted.recorded > 0, "no STS-AUTHN-0477 row");
    assert.strictEqual(cleared.status, 200, cleared.raw.slice(0, 300));
    assert.strictEqual(cleared.body.removed, 1, cleared.raw.slice(0, 300));
    assert.strictEqual(all.status, 200, all.raw.slice(0, 300));
    assert.ok(all.body.removed >= 1, all.raw.slice(0, 300));
    assert.strictEqual(empty.paging.total, 0, JSON.stringify(empty.paging));
    assert.ok(scheduler.raw.indexOf("passkeys.client-learning-sweep") >= 0,
              "the sweep is not a scheduler job");
  });
  await k.reset(realm, "webauthn.clientLearning");
  await k.reset(realm, "webauthn.clientLearningFailures");
  log.debug("Leaving clientRules().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving the passkey policy's rows at " + k.root);
  await namedPolicies();
  await promptNames();
  await clientRules();
  assert.ok(k.checks() >= 17, "only " + k.checks() + " checks ran; a " +
            "section has stopped being called.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_passkey_policy_rules")
  .description("What the passkey policy's rows do to a ceremony over the " +
      "wire: named profiles by group and application, the names a prompt " +
      "shows, and the clients offered no ML-DSA (D12, #444).")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

k.main(test);
