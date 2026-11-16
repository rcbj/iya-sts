// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: sts_passkey_signin_rules.js
//
// ===========================================================================
// WHAT A PASSKEY SIGN-IN ASKS AND REFUSES, OVER THE WIRE (#474, #528, #534,
// #1135, and product's first-use rule of 2026-09-21).
//
// D12 (#444): carries over the part a client can see of five in-process
// files, each of which drove the stack from a child process and is deleted
// at the cutover:
//
//   A. `passkey_discoverable.js` — off, the screen offers no passkey and
//      the door refuses (STS-AUTHN-0301); a first-use key is created under a
//      minted 64-byte handle, recorded on the row, discoverable, with no
//      role; on, a usernameless sign-in, a replay on another screen
//      refused, no user verification refused and the autofill not armed
//      again, a handle nobody holds (STS-AUTHN-0302, the credential named
//      for signalUnknownCredential), somebody else's handle, a wrong handle
//      at the typed step (STS-AUTHN-0303, section 7.2 step 6), the realm's
//      `webauthn.primaryAllowed` switched off after the ceremony was armed
//      (0301) and on again, no ceremony at all (needs JavaScript,
//      STS-AUTHN-0022), the portal's enrolment carrying the person's handle
//      and `residentKey: required`, and primaryAllowed off taking the
//      usernameless sign-in away;
//   B. `passkey_backup_eligible.js` — synced keys (BE and BS) allowed by
//      default and recorded; under `backupEligibility: disallow` a new one
//      refused at the screen (STS-AUTHN-0312) with nothing written, a
//      device-bound one taken, the synced one refused passwordless, after a
//      password and with no username (STS-AUTHN-0313), the device-bound one
//      still in both ways, and back at `allow` the synced one in again;
//   C. `passkey_first_use_product.js` — development enrols on first use;
//      in a PRODUCT realm a keyless person who exists is refused before any
//      ceremony (STS-AUTHN-0206) with no key written, a name that does not
//      exist gets the same sentence, a key holder still gets the assertion,
//      a step minted in development is refused at the registration, and the
//      screen says it checks credentials;
//   D. `passkey_aggregate_devices.js` — `aggregateDevices` on, one ceremony
//      listing every key; off, one key one ceremony, two and five a choice
//      by name with no ceremony until chosen, a chosen key the ceremony
//      naming only it, another person's key not a choice, and the
//      second-factor step following the same rule;
//   E. `passkey_no_role.js` — an enrolment asked for a `role` stores none,
//      one key answers both steps, `webauthn.primaryAllowed` off refuses it
//      passwordless (STS-AUTHN-0045) and keeps it as a second factor,
//      `webauthn.mfaAllowed` off the reverse (STS-AUTHN-0046), both off a
//      new enrolment refused (STS-AUTHN-0531); in a product realm the
//      holder's bare password refused at a password-only door (SCIM Basic,
//      STS-AUTHN-0213) and admitted with mfaAllowed off; and the last key of
//      a person with no password not removed (STS-AUTHN-0070) while a key
//      may sign in on its own, removed once it may not.
//
// NOT CARRIED, and why (class (d)): a key registered BEFORE #474 (no handle
// on its row) and one whose BE was never read — only `credentials.addKey()`
// called in process writes either, and no door does; `addKey()` refusing
// BE=1 "whatever door calls it" is the writer's claim, and every door is
// asserted here instead; `keyForAssertion()`, `mechanismsFor()` and
// `secondFactorDemand()` are module questions, asserted here by the doors
// that ask them; `credentials.isUserHandle()`/`userHandleOf()` are read
// here off the ceremony and the key row.
//
// EVERY REALM IS THE JOB'S OWN, because each section writes the realm's
// passkey policy or a `webauthn.*` setting that changes what every sign-in
// there offers. `local: true`: written here, never vendored.
// ===========================================================================

const assert = require("assert");
const nodeCrypto = require("crypto");
const { Command, Option } = require("commander");
const portalSignin = require("./portal_signin.js");
const authnSignin = require("./authn_signin");
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
var log = bunyan.createLogger({ name: "sts_passkey_signin_rules",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const k = wire.kit("sts_passkey_signin_rules", { log: log });
const check = k.check;
// Development checks no password (root CLAUDE.md), so any will do there;
// the product sections create their people with this one.
const PASSWORD = "Pk-Signin-" + k.STAMP + "-correct-9!";
const HANDLE = /^[A-Za-z0-9_-]{86}$/;
// What a product realm asks an administrator who clears a factor to record.
const EVIDENCE = "Identity verified in person against a photo ID (D12 job).";

function who(name) {
  log.debug("Entering who().");
  log.debug("Leaving who().");
  return name + "-" + k.STAMP;
}

// A passwordless first use at the screen (development's enrolment): the
// step's ceremony armed, `auth` registering under the handle it was given.
async function firstUse(realm, name, auth) {
  log.debug("Entering firstUse(). " + name);
  const t = await k.typed(realm, name, {});
  assert.ok(t.step, "the passwordless sign-in for " + name + " reached no " +
    "step: " + k.said(t.answer).slice(0, 300));
  let given = "";
  const done = await k.ceremony(t.step, function (c) {
    given = c.user && c.user.id;
    return auth.register(c.challenge, given, c.rpId);
  });
  log.debug("Leaving firstUse(). " + done.next);
  return { done: done, armed: done.armed, handle: given, step: t.step };
}

// A typed passkey sign-in (`o.password` before it), the step's ceremony
// answered by `auth.assert()` with `ao`. The answer; where the session was
// refused at the end, the screen it was sent back to (`screenView`).
async function signIn(realm, name, auth, o, ao) {
  log.debug("Entering signIn(). " + name);
  const t = await k.typed(realm, name, o || {});
  if (!t.step) {
    log.debug("Leaving signIn(). No step: " + t.answer.next);
    return t.answer;
  }
  const done = await k.ceremony(t.step, function (c) {
    return auth.assert(c.challenge, ao);
  });
  if (done.next === "refused" && done.location &&
      /\/authn\/login/.test(done.location)) {
    const back = await authnSignin.screen(realm.base, done.location,
                                          { cookie: done.cookie });
    done.screenView = back.view || null;
  }
  log.debug("Leaving signIn(). " + done.next);
  return done;
}

// Where an answer ended: signed in, or the sentence that refused it (the
// act's own, or the screen's it was sent back to).
function refusedSaying(answer, pattern) {
  log.debug("Entering refusedSaying().");
  const text = ((answer.errors || []).join(" ") + " " +
                String((answer.screenView && answer.screenView.error) || "") +
                " " + JSON.stringify(answer.json || {}));
  log.debug("Leaving refusedSaying().");
  return answer.next !== "redirect" && pattern.test(text);
}

// ---------------------------------------------------------------------------
// A. DISCOVERABLE CREDENTIALS (#474).
// ---------------------------------------------------------------------------
async function discoverable() {
  log.debug("Entering discoverable().");
  log.info("=== A. passkeys as discoverable credentials ===");
  const realm = await k.realm("pksi-a", "development");
  await k.client(realm);
  const alice = who("alice");

  await k.mustSavePolicy(realm, { allowUsernameless: false });
  let before = await k.codeCount(realm, "STS-AUTHN-0301");
  let s = await k.screen(realm);
  let r = await k.usernameless(realm, null, s);
  const offRows = await k.newCodes(realm, "STS-AUTHN-0301", before);
  check("A1. OFF: the screen's view offers no passkey, and the usernameless " +
        "door refuses with STS-AUTHN-0301", function () {
    assert.strictEqual(s.view.passkey, false, JSON.stringify(s.view.passkey));
    assert.strictEqual(r.next, "refused", k.said(r).slice(0, 300));
    assert.ok(offRows > 0, "no STS-AUTHN-0301 row");
  });
  await k.mustSavePolicy(realm, {});

  const a = k.authenticator({});
  const used = await firstUse(realm, alice, a);
  const key = (await k.keysOf(realm, alice))[0] || {};
  check("A2. A FIRST-USE KEY IS CREATED UNDER A MINTED 64-BYTE HANDLE, not " +
        "the username's bytes; the row is discoverable, signs in with no " +
        "username, and carries no role (#1135)", function () {
    assert.strictEqual(used.armed.json.mode, "create",
      JSON.stringify(used.armed.json).slice(0, 300));
    assert.ok(HANDLE.test(used.handle), used.handle);
    assert.notStrictEqual(used.handle,
                          Buffer.from(alice).toString("base64url"));
    assert.strictEqual(used.done.next, "redirect",
      k.said(used.done).slice(0, 300));
    assert.strictEqual(key.credentialId, a.credentialId);
    assert.strictEqual(key.discoverable, true, JSON.stringify(key));
    assert.ok(key.withoutUsername && key.withoutUsername.ready === true);
    assert.ok(!Object.prototype.hasOwnProperty.call(key, "role"),
      "the key row carries a role: " + key.role);
  });

  s = await k.screen(realm);
  r = await k.usernameless(realm, function (challenge) {
    return a.assert(challenge);
  }, s);
  check("A3. ON (the default): a usernameless assertion signs its owner in, " +
        "the armed ceremony requiring user verification", function () {
    assert.strictEqual(s.view.passkey, true);
    assert.strictEqual(((r.armed.json || {}).options || {}).userVerification,
                       "required");
    assert.strictEqual(r.next, "redirect", k.said(r).slice(0, 300));
  });

  s = await k.screen(realm);
  const armed = await authnSignin.passkeyOptions(realm.base, s.opened);
  const once = a.assert(armed.json.challenge);
  const first = await authnSignin.act(realm.base, "/authn-api/pending/" +
    encodeURIComponent(s.opened.id) + "/passkey",
    { credential: JSON.stringify(once) },
    { cookie: armed.cookie, csrf: s.opened.csrf });
  const again = await k.usernameless(realm, function () {
    return once;
  });
  check("A4. the same assertion on another screen is refused: its challenge " +
        "is not that screen's", function () {
    assert.strictEqual(first.next, "redirect", k.said(first).slice(0, 300));
    assert.strictEqual(again.next, "refused", k.said(again).slice(0, 300));
  });

  r = await k.usernameless(realm, function (challenge) {
    return a.assert(challenge, { uv: false });
  });
  const fresh = await k.screen(realm);
  check("A5. an assertion WITHOUT user verification is refused, the answer " +
        "tells the page not to arm the autofill again, and a fresh screen " +
        "still offers the passkey", function () {
    assert.strictEqual(r.next, "refused", k.said(r).slice(0, 300));
    assert.ok(/could not sign you in/.test(k.said(r)), k.said(r));
    assert.ok(r.json.passkey && r.json.passkey.autofill === false,
      JSON.stringify(r.json).slice(0, 300));
    assert.strictEqual(fresh.view.passkey, true);
  });

  before = await k.codeCount(realm, "STS-AUTHN-0302");
  r = await k.usernameless(realm, function (challenge) {
    return a.assert(challenge,
      { handle: nodeCrypto.randomBytes(64).toString("base64url") });
  });
  const stranger = await k.newCodes(realm, "STS-AUTHN-0302", before);
  // THE CREDENTIAL IS NAMED FOR signalUnknownCredential ONLY WHERE ONE
  // REALM AND ONE CELL EXIST (STS-AUTHN-0302's own row): a service holding
  // this job's realm holds two, so the browser is asked to forget nothing —
  // the credential may be another realm's. The in-process file asserted the
  // one-realm case.
  check("A6. a handle nobody holds is STS-AUTHN-0302; with more than one " +
        "realm the answer names no credential to forget", function () {
    assert.strictEqual(r.next, "refused", k.said(r).slice(0, 300));
    assert.ok(stranger > 0, "no STS-AUTHN-0302 row");
    assert.strictEqual((r.json.passkey || {}).unknownCredential, "",
                       JSON.stringify(r.json).slice(0, 300));
  });

  // Bob holds a password too, and is signed in to the portal (A11) before
  // he holds a key — after it, a password alone no longer signs him in.
  const bob = who("bob");
  await k.person(realm, bob, PASSWORD);
  const portal = await portalSignin.signInToThePortal(realm.base, bob, null,
    { password: PASSWORD });
  const b = k.authenticator({});
  const bobUse = await firstUse(realm, bob, b);
  r = await k.usernameless(realm, function (challenge) {
    return a.assert(challenge, { handle: bobUse.handle });
  });
  check("A7. alice's credential presented under bob's handle is refused",
        function () {
    assert.ok(HANDLE.test(bobUse.handle) && bobUse.handle !== used.handle);
    assert.strictEqual(r.next, "refused", k.said(r).slice(0, 300));
  });

  before = await k.codeCount(realm, "STS-AUTHN-0303");
  r = await signIn(realm, alice, a, {},
                   { handle: nodeCrypto.randomBytes(64)
                     .toString("base64url") });
  const wrong = await k.newCodes(realm, "STS-AUTHN-0303", before);
  const typedOk = await signIn(realm, alice, a, {});
  check("A8. at the typed passkey step the key still signs in, and a handle " +
        "that is not the key's is refused there, STS-AUTHN-0303 (section " +
        "7.2 step 6)", function () {
    assert.strictEqual(typedOk.next, "redirect",
                       k.said(typedOk).slice(0, 300));
    assert.notStrictEqual(r.next, "redirect", k.said(r).slice(0, 300));
    assert.ok(wrong > 0, "no STS-AUTHN-0303 row");
  });

  before = await k.codeCount(realm, "STS-AUTHN-0301");
  s = await k.screen(realm);
  const armedOff = await authnSignin.passkeyOptions(realm.base, s.opened);
  await k.mustSet(realm, "webauthn.primaryAllowed", false);
  let off;
  try {
    off = await authnSignin.act(realm.base, "/authn-api/pending/" +
      encodeURIComponent(s.opened.id) + "/passkey",
      { credential: JSON.stringify(a.assert(armedOff.json.challenge)) },
      { cookie: armedOff.cookie, csrf: s.opened.csrf });
  } finally {
    await k.reset(realm, "webauthn.primaryAllowed");
  }
  const offCodes = await k.newCodes(realm, "STS-AUTHN-0301", before);
  r = await k.usernameless(realm, function (challenge) {
    return a.assert(challenge);
  });
  check("A9. THE REALM DECIDES, NOT THE KEY (#1135): webauthn.primaryAllowed " +
        "switched off after the ceremony was armed refuses it " +
        "(STS-AUTHN-0301), and on again the same key signs in", function () {
    assert.strictEqual(off.next, "refused", k.said(off).slice(0, 300));
    assert.ok(offCodes > 0, "no STS-AUTHN-0301 row");
    assert.strictEqual(r.next, "redirect", k.said(r).slice(0, 300));
  });

  before = await k.codeCount(realm, "STS-AUTHN-0022");
  r = await k.usernameless(realm, null);
  const none = await k.newCodes(realm, "STS-AUTHN-0022", before);
  check("A10. a passkey act carrying no ceremony is told the ceremony needs " +
        "JavaScript (STS-AUTHN-0022)", function () {
    assert.strictEqual(r.next, "refused", k.said(r).slice(0, 300));
    assert.ok(/needs JavaScript/.test(k.said(r)), k.said(r));
    assert.ok(none > 0, "no STS-AUTHN-0022 row");
  });

  const begun = await k.enrol(portal, null, {});
  const selection = ((begun.pending || {}).options || {})
    .authenticatorSelection || {};
  check("A11. the portal's enrolment carries the person's own handle, and a " +
        "passkey is asked for with residentKey: required", function () {
    assert.strictEqual(begun.pending.userHandle, bobUse.handle,
      JSON.stringify(begun.pending).slice(0, 300));
    assert.strictEqual(selection.residentKey, "required");
    assert.strictEqual(selection.requireResidentKey, true);
  });

  await k.mustSet(realm, "webauthn.primaryAllowed", false);
  try {
    s = await k.screen(realm);
  } finally {
    await k.reset(realm, "webauthn.primaryAllowed");
  }
  check("A12. webauthn.primaryAllowed off takes the usernameless sign-in " +
        "away", function () {
    assert.strictEqual(s.view.passkey, false);
  });
  log.debug("Leaving discoverable().");
}

// ---------------------------------------------------------------------------
// B. SYNCED PASSKEYS (#528).
// ---------------------------------------------------------------------------
async function backupEligible() {
  log.debug("Entering backupEligible().");
  log.info("=== B. synced passkeys and backupEligibility ===");
  const realm = await k.realm("pksi-b", "development");
  await k.client(realm);
  const alice = who("alice");
  const a = k.authenticator({ synced: true });
  const used = await firstUse(realm, alice, a);
  const aliceKey = (await k.keysOf(realm, alice))[0] || {};
  let r = await signIn(realm, alice, a, {});
  check("B1. ALLOWED BY DEFAULT: a synced passkey (BE and BS set) registers, " +
        "the row records both flags, and it signs in", function () {
    assert.strictEqual(used.done.next, "redirect",
                       k.said(used.done).slice(0, 300));
    assert.strictEqual(aliceKey.backupEligible, true);
    assert.strictEqual(aliceKey.backupState, true);
    assert.strictEqual(r.next, "redirect", k.said(r).slice(0, 300));
  });
  // Dave signs in with a password, his synced key the step after it.
  const dave = who("dave");
  await k.person(realm, dave, PASSWORD);
  const davePortal = await portalSignin.signInToThePortal(realm.base, dave,
    null, { password: PASSWORD });
  const d = k.authenticator({ eligible: true });
  const daveKey = await k.enrol(davePortal, d, {});
  assert.strictEqual(daveKey.done.status, 200,
    "dave's synced key: " + JSON.stringify(daveKey.done.json).slice(0, 300));

  await k.mustSavePolicy(realm, { backupEligibility: "disallow" });
  const bob = who("bob");
  let before = await k.codeCount(realm, "STS-AUTHN-0312");
  const bobUse = await firstUse(realm, bob, k.authenticator({
    eligible: true }));
  const bobRefused = await k.newCodes(realm, "STS-AUTHN-0312", before);
  const bobKeys = await k.keysOf(realm, bob);
  check("B2a. under disallow a backup-eligible key is NOT registered at the " +
        "sign-in screen (STS-AUTHN-0312): the answer says why and nothing " +
        "is written", function () {
    assert.strictEqual(bobUse.done.next, "refused",
                       k.said(bobUse.done).slice(0, 300));
    assert.ok(/device-bound passkeys/.test(k.said(bobUse.done)),
              k.said(bobUse.done).slice(0, 300));
    assert.ok(bobRefused > 0, "no STS-AUTHN-0312 row");
    assert.strictEqual(bobKeys.length, 0, JSON.stringify(bobKeys));
  });
  const carol = who("carol");
  const c = k.authenticator({});
  const carolUse = await firstUse(realm, carol, c);
  const carolKey = (await k.keysOf(realm, carol))[0] || {};
  check("B2b. a device-bound key is registered", function () {
    assert.strictEqual(carolUse.done.next, "redirect",
                       k.said(carolUse.done).slice(0, 300));
    assert.strictEqual(carolKey.backupEligible, false);
  });

  before = await k.codeCount(realm, "STS-AUTHN-0313");
  r = await signIn(realm, alice, a, {});
  const passwordless = await k.newCodes(realm, "STS-AUTHN-0313", before);
  before = await k.codeCount(realm, "STS-AUTHN-0313");
  const afterPassword = await signIn(realm, dave, d, { password: PASSWORD });
  const secondStep = await k.newCodes(realm, "STS-AUTHN-0313", before);
  const noName = await k.usernameless(realm, function (challenge) {
    return a.assert(challenge);
  });
  check("B3. a synced key registered before the realm said no does not sign " +
        "in — passwordless (STS-AUTHN-0313, the screen saying why), as the " +
        "step after a password (0313), nor with no username", function () {
    assert.ok(refusedSaying(r, /device-bound passkeys/),
              k.said(r).slice(0, 400));
    assert.ok(passwordless > 0, "no STS-AUTHN-0313 row (passwordless)");
    assert.notStrictEqual(afterPassword.next, "redirect",
                          k.said(afterPassword).slice(0, 300));
    assert.ok(secondStep > 0, "no STS-AUTHN-0313 row (second step)");
    assert.ok(refusedSaying(noName, /device-bound passkeys/),
              k.said(noName).slice(0, 300));
  });

  r = await signIn(realm, carol, c, {});
  const carolNoName = await k.usernameless(realm, function (challenge) {
    return c.assert(challenge);
  });
  check("B4. a device-bound key still signs in, typed and with no username",
        function () {
    assert.strictEqual(r.next, "redirect", k.said(r).slice(0, 300));
    assert.strictEqual(carolNoName.next, "redirect",
                       k.said(carolNoName).slice(0, 300));
  });

  await k.mustSavePolicy(realm, {});
  r = await signIn(realm, alice, a, {});
  check("B6. back to allow, the synced key signs in again: BE is a fact " +
        "about the key, the rule the realm's", function () {
    assert.strictEqual(r.next, "redirect", k.said(r).slice(0, 300));
  });
  log.debug("Leaving backupEligible().");
}

// ---------------------------------------------------------------------------
// C. PRODUCT ENROLS NO KEY AT THE SIGN-IN SCREEN.
// ---------------------------------------------------------------------------
const NO_KEY = /There is no passkey registered for signing in to this account/;

async function firstUseProduct() {
  log.debug("Entering firstUseProduct().");
  log.info("=== C. product enrols no key at the sign-in screen ===");
  const realm = await k.realm("pksi-c", "development");
  await k.client(realm);
  const dev = await firstUse(realm, who("devp"), k.authenticator({}));
  const holder = who("holder");
  const h = k.authenticator({});
  await k.person(realm, holder, PASSWORD);
  const holderPortal = await portalSignin.signInToThePortal(realm.base,
    holder, null, { password: PASSWORD });
  await k.enrol(holderPortal, h, {});
  const victim = who("victim");
  await k.person(realm, victim, PASSWORD);
  // The step minted while still in development, completed after the switch.
  const late = await k.typed(realm, who("late"), {});
  check("C1. DEVELOPMENT, the control: a passwordless sign-in for a keyless " +
        "person is the enrol ceremony, and a real registration signs them " +
        "in", function () {
    assert.strictEqual(dev.armed.json.mode, "create");
    assert.strictEqual(dev.done.next, "redirect",
                       k.said(dev.done).slice(0, 300));
    assert.ok(late.step && late.step.view.webauthn.mode === "create",
              JSON.stringify(late.step && late.step.view).slice(0, 200));
  });

  const set = await k.send("POST", k.root + "/admin-api/realms/set",
    { id: realm.id, key: "global.mode", value: "product" });
  assert.strictEqual(set.status, 200, set.raw.slice(0, 300));
  await k.mustSet(realm, "authn.allowOptionalSecondFactor", true);

  const before = await k.codeCount(realm, "STS-AUTHN-0206");
  const attack = await k.typed(realm, victim, {});
  const refusals = await k.newCodes(realm, "STS-AUTHN-0206", before);
  const victimKeys = await k.keysOf(realm, victim);
  check("C2. PRODUCT: a passwordless sign-in for somebody who exists and " +
        "holds no key is refused BEFORE any ceremony (STS-AUTHN-0206), and " +
        "no key is on the entry", function () {
    assert.strictEqual(attack.answer.next, "refused",
                       k.said(attack.answer).slice(0, 300));
    assert.strictEqual(attack.answer.status, 400);
    assert.ok(NO_KEY.test(k.said(attack.answer)),
              k.said(attack.answer).slice(0, 300));
    assert.strictEqual(attack.step, null);
    assert.ok(refusals > 0, "no STS-AUTHN-0206 row");
    assert.strictEqual(victimKeys.length, 0);
  });
  const nobody = await k.typed(realm, who("nobody"), {});
  check("C3. PRODUCT: a name that does not exist gets the SAME sentence",
        function () {
    assert.strictEqual(nobody.answer.next, "refused");
    assert.ok(NO_KEY.test(k.said(nobody.answer)),
              k.said(nobody.answer).slice(0, 300));
  });
  const held = await k.typed(realm, holder, {});
  check("C4. PRODUCT: a person who HOLDS a passkey still gets the ceremony, " +
        "as an assertion", function () {
    assert.ok(held.step, k.said(held.answer).slice(0, 300));
    assert.strictEqual(held.step.view.webauthn.mode, "get");
  });
  const lateDone = await k.ceremony(late.step, function (c) {
    return k.authenticator({}).register(c.challenge, c.user && c.user.id,
                                        c.rpId);
  });
  const lateKeys = await k.keysOf(realm, who("late"));
  // OVER THE WIRE THE REALM'S SWITCH TO PRODUCT ALSO RENAMES ITS COOKIES
  // (`__Host-` in product), so the browser that began the step in
  // development holds no session the product realm reads, and the step is
  // refused for that before the registration's own rule ("never at the
  // sign-in screen", which the in-process file reached by switching the
  // process) is asked. Either refusal keeps the key off the entry, which is
  // the claim.
  check("C5. PRODUCT: a step minted in development is refused at the " +
        "registration, and no key is written", function () {
    assert.notStrictEqual(lateDone.next, "redirect",
                          k.said(lateDone).slice(0, 300));
    assert.ok(/never at the sign-in screen|holds no session/.test(
      k.said(lateDone) + " " +
      JSON.stringify((lateDone.armed || {}).json || {})),
      k.said(lateDone).slice(0, 300));
    assert.strictEqual(lateKeys.length, 0);
  });
  check("C6. PRODUCT: the sign-in screen says it checks credentials (no " +
        "longer that no password is checked)", function () {
    assert.strictEqual(held.screen.view.verifiesCredentials, true,
      JSON.stringify(held.screen.view.verifiesCredentials));
  });
  log.debug("Leaving firstUseProduct().");
}

// ---------------------------------------------------------------------------
// D. ONE CHOICE OR ONE PER PASSKEY (#534).
// ---------------------------------------------------------------------------
async function aggregateDevices() {
  log.debug("Entering aggregateDevices().");
  log.info("=== D. aggregateDevices ===");
  const realm = await k.realm("pksi-d", "development");
  await k.client(realm);
  const people = {};
  for (const one of [["one", 1], ["two", 2], ["five", 5], ["dave", 2]]) {
    const name = who("pkg-" + one[0]);
    await k.person(realm, name, PASSWORD);
    const portal = await portalSignin.signInToThePortal(realm.base, name,
      null, { password: PASSWORD });
    for (let i = 0; i < one[1]; i += 1) {
      const e = await k.enrol(portal, k.authenticator({}), {});
      assert.strictEqual(e.done.status, 200,
        name + "'s key " + i + ": " + JSON.stringify(e.done.json)
          .slice(0, 300));
    }
    const keys = await k.keysOf(realm, name);
    people[one[0]] = { name: name, ids: keys.map(function (key) {
      return key.credentialId;
    }), labels: keys.map(function (key) {
      return key.label || key.name;
    }) };
  }
  const allowOf = async function (step, key) {
    log.debug("Entering allowOf().");
    const armed = await authnSignin.stepAct(step, "webauthn/options",
                                            key ? { key: key } : {});
    log.debug("Leaving allowOf().");
    if (!(armed.status === 200 && armed.json && armed.json.ok !== false)) {
      return null;
    }
    return (armed.json.allow || []).map(function (one) {
      return typeof one === "string" ? one : one.id;
    });
  };
  const choicesOf = function (step) {
    log.debug("Entering choicesOf().");
    log.debug("Leaving choicesOf().");
    return ((step.view && step.view.webauthn &&
             step.view.webauthn.choices) || []);
  };
  const same = function (a, b) {
    log.debug("Entering same().");
    log.debug("Leaving same().");
    return !!a && JSON.stringify(a.slice().sort()) ===
           JSON.stringify(b.slice().sort());
  };
  const stepOf = async function (p, password) {
    log.debug("Entering stepOf().");
    const t = await k.typed(realm, p.name,
                            password ? { password: PASSWORD } : {});
    assert.ok(t.step, p.name + " reached no step: " +
              k.said(t.answer).slice(0, 300));
    log.debug("Leaving stepOf().");
    return t.step;
  };

  let s1 = await stepOf(people.one);
  let s2 = await stepOf(people.two);
  let s5 = await stepOf(people.five);
  const a1 = await allowOf(s1);
  const a2 = await allowOf(s2);
  const a5 = await allowOf(s5);
  check("D1. ON (the default): one ceremony listing every key, for one, two " +
        "and five", function () {
    assert.ok(same(a1, people.one.ids), JSON.stringify(a1));
    assert.ok(same(a2, people.two.ids), JSON.stringify(a2));
    assert.ok(same(a5, people.five.ids), JSON.stringify(a5));
    assert.strictEqual(choicesOf(s2).length, 0);
    assert.strictEqual(choicesOf(s5).length, 0);
  });

  await k.mustSavePolicy(realm, { aggregateDevices: false });
  s1 = await stepOf(people.one);
  s2 = await stepOf(people.two);
  s5 = await stepOf(people.five);
  const off1 = await allowOf(s1);
  const off5 = await allowOf(s5);
  check("D2. OFF: one key is still one ceremony; two and five are a choice, " +
        "one per key by its name, and no ceremony until one is chosen",
        function () {
    assert.ok(same(off1, people.one.ids), JSON.stringify(off1));
    assert.strictEqual(choicesOf(s1).length, 0);
    assert.strictEqual(choicesOf(s2).length, 2);
    assert.strictEqual(choicesOf(s5).length, 5);
    assert.strictEqual(off5, null, JSON.stringify(off5));
    const offered = choicesOf(s5).map(function (one) {
      return one.name;
    }).sort();
    assert.deepStrictEqual(offered, people.five.labels.slice().sort());
  });

  const pickId = people.five.ids[3];
  const at = s5.base + "/authn/webauthn?mfa=" + encodeURIComponent(s5.id) +
             "&key=" + encodeURIComponent(pickId);
  const pick = await authnSignin.step(at, { cookie: s5.cookie });
  const pickAllow = await allowOf(pick, pickId);
  const stray = await authnSignin.step(s5.base + "/authn/webauthn?mfa=" +
    encodeURIComponent(s5.id) + "&key=" +
    encodeURIComponent(people.two.ids[0]), { cookie: s5.cookie });
  const strayAllow = await allowOf(stray, people.two.ids[0]);
  check("D3. a chosen key draws the ceremony naming only it; a key that is " +
        "not this person's is not a choice — the list again, no ceremony",
        function () {
    assert.strictEqual(pick.status, 200, String(pick.text).slice(0, 300));
    assert.ok(same(pickAllow, [pickId]), JSON.stringify(pickAllow));
    assert.ok(pick.view.webauthn.chosen, JSON.stringify(pick.view.webauthn)
      .slice(0, 300));
    assert.strictEqual(choicesOf(pick).length, 0);
    assert.strictEqual(stray.status, 200);
    assert.strictEqual(choicesOf(stray).length, 5);
    assert.strictEqual(strayAllow, null, JSON.stringify(strayAllow));
  });

  const sd = await stepOf(people.dave, true);
  const dId = people.dave.ids[1];
  const dpick = await authnSignin.step(sd.base + "/authn/webauthn?mfa=" +
    encodeURIComponent(sd.id) + "&key=" + encodeURIComponent(dId),
    { cookie: sd.cookie });
  const dAllow = await allowOf(dpick, dId);
  check("D4. the second-factor step after a password follows the same rule",
        function () {
    assert.strictEqual(choicesOf(sd).length, 2);
    assert.ok(same(dAllow, [dId]), JSON.stringify(dAllow));
  });
  log.debug("Leaving aggregateDevices().");
}

// ---------------------------------------------------------------------------
// E. A PASSKEY CARRIES NO ROLE (#1135).
// ---------------------------------------------------------------------------
function basic(user, password) {
  log.debug("Entering basic().");
  log.debug("Leaving basic().");
  return "Basic " + Buffer.from(user + ":" + password).toString("base64");
}

// SCIM Basic, one of the password-only doors: refused is a 401.
async function scimBasic(realm, user, password) {
  log.debug("Entering scimBasic(). " + user);
  const r = await fetch(realm.base + "/scim/v2/Users?count=1", { headers: {
    Authorization: basic(user, password), Accept: "application/scim+json" } });
  await r.text();
  log.debug("Leaving scimBasic(). " + r.status);
  return r.status;
}

async function noRole() {
  log.debug("Entering noRole().");
  log.info("=== E. a passkey carries no role ===");
  const realm = await k.realm("pksi-e", "development");
  await k.client(realm);
  const pat = who("pat");
  await k.person(realm, pat, PASSWORD);
  const portal = await portalSignin.signInToThePortal(realm.base, pat, null,
    { password: PASSWORD });
  const p = k.authenticator({});
  const begun = await portal.api("POST", "/account-api/keys",
    { action: "begin", kind: "passkey", role: "mfa" });
  const page = await portal.api("GET", "/account-api/keys");
  const pending = (page.json && page.json.enrol &&
                   page.json.enrol.pending) || {};
  const finished = await portal.api("POST", "/account-api/keys",
    { action: "finish", enrolment_id: pending.id,
      credential: JSON.stringify(p.register(pending.challenge,
                                            pending.userHandle)) });
  const row = (await k.keysOf(realm, pat))[0] || {};
  check("E1. an enrolment begun with the old `role` asks none and stores " +
        "none", function () {
    assert.ok(begun.status === 200 || begun.status === 400,
              String(begun.text).slice(0, 300));
    assert.strictEqual(finished.status, 200,
                       String(finished.text).slice(0, 300));
    assert.ok(!Object.prototype.hasOwnProperty.call(pending, "role"),
              JSON.stringify(pending).slice(0, 300));
    assert.strictEqual(row.credentialId, p.credentialId);
    assert.ok(!Object.prototype.hasOwnProperty.call(row, "role"),
              "the row carries a role: " + row.role);
  });

  let first = await signIn(realm, pat, p, {});
  let second = await signIn(realm, pat, p, { password: PASSWORD });
  check("E2. one key answers both steps: passwordless and after a password",
        function () {
    assert.strictEqual(first.next, "redirect", k.said(first).slice(0, 300));
    assert.strictEqual(second.next, "redirect",
                       k.said(second).slice(0, 300));
  });

  await k.mustSet(realm, "webauthn.primaryAllowed", false);
  let before = await k.codeCount(realm, "STS-AUTHN-0045");
  try {
    first = await signIn(realm, pat, p, {});
    second = await signIn(realm, pat, p, { password: PASSWORD });
  } finally {
    await k.reset(realm, "webauthn.primaryAllowed");
  }
  const primaryCodes = await k.newCodes(realm, "STS-AUTHN-0045", before);
  check("E3. webauthn.primaryAllowed off: the key is refused as a first " +
        "factor (STS-AUTHN-0045) and still accepted as a second",
        function () {
    assert.notStrictEqual(first.next, "redirect", k.said(first).slice(0, 300));
    assert.ok(primaryCodes > 0, "no STS-AUTHN-0045 row");
    assert.strictEqual(second.next, "redirect",
                       k.said(second).slice(0, 300));
  });

  await k.mustSet(realm, "webauthn.mfaAllowed", false);
  before = await k.codeCount(realm, "STS-AUTHN-0046");
  try {
    second = await signIn(realm, pat, p, { password: PASSWORD });
    first = await signIn(realm, pat, p, {});
  } finally {
    await k.reset(realm, "webauthn.mfaAllowed");
  }
  const mfaCodes = await k.newCodes(realm, "STS-AUTHN-0046", before);
  check("E4. webauthn.mfaAllowed off: the reverse — refused as a second " +
        "factor (STS-AUTHN-0046), accepted passwordless", function () {
    assert.notStrictEqual(second.next, "redirect",
                          k.said(second).slice(0, 300));
    assert.ok(mfaCodes > 0, "no STS-AUTHN-0046 row");
    assert.strictEqual(first.next, "redirect", k.said(first).slice(0, 300));
  });

  await k.mustSet(realm, "webauthn.primaryAllowed", false);
  await k.mustSet(realm, "webauthn.mfaAllowed", false);
  before = await k.codeCount(realm, "STS-AUTHN-0531");
  let refused;
  try {
    refused = await portal.api("POST", "/account-api/keys",
                               { action: "begin", kind: "passkey" });
  } finally {
    await k.reset(realm, "webauthn.primaryAllowed");
    await k.reset(realm, "webauthn.mfaAllowed");
  }
  const enrolCodes = await k.newCodes(realm, "STS-AUTHN-0531", before);
  check("E5. both off: a new enrolment is refused (STS-AUTHN-0531)",
        function () {
    assert.strictEqual(refused.status, 400, String(refused.text)
      .slice(0, 300));
    assert.ok(enrolCodes > 0, "no STS-AUTHN-0531 row");
  });

  // The last way in: a person with no password and one key.
  const lone = who("lone");
  const l = k.authenticator({});
  const loneUse = await firstUse(realm, lone, l);
  assert.strictEqual(loneUse.done.next, "redirect",
                     k.said(loneUse.done).slice(0, 300));
  before = await k.codeCount(realm, "STS-AUTHN-0070");
  const kept = await k.call(realm, "POST", "/users/clear-key",
                            { user: lone, credentialId: l.credentialId,
                              evidence: EVIDENCE });
  const lastCodes = await k.newCodes(realm, "STS-AUTHN-0070", before);
  const stillThere = await k.keysOf(realm, lone);
  await k.mustSet(realm, "webauthn.primaryAllowed", false);
  let gone;
  try {
    gone = await k.call(realm, "POST", "/users/clear-key",
                        { user: lone, credentialId: l.credentialId,
                              evidence: EVIDENCE });
  } finally {
    await k.reset(realm, "webauthn.primaryAllowed");
  }
  const afterKeys = await k.keysOf(realm, lone);
  check("E7. THE LAST WAY IN: the only key of a person with no password is " +
        "not removed (STS-AUTHN-0070) while a key may sign in on its own, " +
        "and is removed while it may not — there is no way in to lose",
        function () {
    assert.notStrictEqual(kept.status, 200, kept.raw.slice(0, 300));
    assert.ok(lastCodes > 0, "no STS-AUTHN-0070 row");
    assert.strictEqual(stillThere.length, 1);
    assert.strictEqual(gone.status, 200, gone.raw.slice(0, 300));
    assert.strictEqual(afterKeys.length, 0);
  });

  // D, in a product realm: the password-only door.
  const prod = await k.realm("pksi-f", "development");
  const holder = who("holder");
  await k.person(prod, holder, PASSWORD);
  const holderPortal = await portalSignin.signInToThePortal(prod.base, holder,
    null, { password: PASSWORD });
  await k.enrol(holderPortal, k.authenticator({}), {});
  const plain = who("plain");
  await k.person(prod, plain, PASSWORD);
  const set = await k.send("POST", k.root + "/admin-api/realms/set",
    { id: prod.id, key: "global.mode", value: "product" });
  assert.strictEqual(set.status, 200, set.raw.slice(0, 300));
  await k.mustSet(prod, "authn.allowOptionalSecondFactor", true);
  before = await k.codeCount(prod, "STS-AUTHN-0213");
  const holderDoor = await scimBasic(prod, holder, PASSWORD);
  const doorCodes = await k.newCodes(prod, "STS-AUTHN-0213", before);
  const plainDoor = await scimBasic(prod, plain, PASSWORD);
  await k.mustSet(prod, "webauthn.mfaAllowed", false);
  let admitted;
  try {
    admitted = await scimBasic(prod, holder, PASSWORD);
  } finally {
    await k.reset(prod, "webauthn.mfaAllowed");
  }
  check("E6. PRODUCT: holding a key is holding a second factor, so the " +
        "holder's own right password is refused at a password-only door " +
        "(SCIM Basic, STS-AUTHN-0213) while a password-only person's is " +
        "not; with webauthn.mfaAllowed off the key is no second factor and " +
        "the door admits it", function () {
    assert.strictEqual(holderDoor, 401, String(holderDoor));
    assert.ok(doorCodes > 0, "no STS-AUTHN-0213 row");
    assert.notStrictEqual(plainDoor, 401, String(plainDoor));
    assert.notStrictEqual(admitted, 401, String(admitted));
  });
  log.debug("Leaving noRole().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving passkey sign-in rules at " + k.root);
  await discoverable();
  await backupEligible();
  await firstUseProduct();
  await aggregateDevices();
  await noRole();
  assert.ok(k.checks() >= 35, "only " + k.checks() + " checks ran; a " +
            "section has stopped being called.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_passkey_signin_rules")
  .description("What a passkey sign-in asks and refuses over the wire: " +
      "discoverable credentials, synced passkeys, product's first-use " +
      "refusal, one choice or one per passkey, and a key carrying no role " +
      "(D12, #444).")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

k.main(test);
