// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_webauthn_rules.js
//
// ===========================================================================
// WHAT A WEBAUTHN CEREMONY IS HELD TO, AND WHAT IT RECORDS, OVER THE WIRE
// (2026-09-10, 2026-09-12, #943, #1108, #1114, #1135).
//
// D12 (#444): carries over the part a client can see of five in-process
// files, each deleted at the cutover. Every ceremony is a real one — the
// sign-in screen's passkey step over `/authn-api`, or the portal's
// `/account-api/keys` — answered by `passkey_wire_kit.js`'s software
// authenticator over the challenge and RP ID the service armed, in realms
// this job makes; every code is read off `/admin-api/audit`:
//
//   A. `webauthn_addresses.js` — the origin a clientDataJSON must carry is
//      the service's own while `webauthn.allowedOrigins` is empty, and an
//      origin nobody listed is refused; set, the list is the whole answer:
//      a listed origin is taken (a trailing slash in the setting is not
//      part of it) and the service's own origin is refused. A configured
//      `webauthn.rpId` that does not fit the host falls back to the host in
//      development (the armed ceremony names the host and no problem), and
//      in PRODUCT the ceremony says what is wrong and refuses — a value that
//      ends in the host's name as a STRING but not at a label boundary as
//      well; the host itself is no problem in either mode.
//   B. `webauthn_policy.js` — what the ceremony OFFERS, read off the armed
//      options: every algorithm the verifier checks and nothing else, a
//      write naming an unknown one refused, RS1 only behind
//      `webauthn.insecureAlgorithms` (last) in development and that flag
//      refused in product, `webauthn.pqcOnly` narrowing to ML-DSA; the
//      attachment ABSENT where the setting is `any` (a security key asking
//      cross-platform), a setting naming one winning; a passkey's resident
//      key required with `requireResidentKey` beside it; `credProps`; user
//      verification REQUESTED at preferred and ENFORCED at required. Then
//      the policy half: a key refused as a first factor
//      (`webauthn.primaryAllowed`, STS-AUTHN-0045) is still a second
//      factor, the mirror image (`webauthn.mfaAllowed`, 0046), both off
//      refusing a new key (0531), the mechanism off refusing one (0044),
//      and `webauthn.maxKeysPerPerson` an ENROLMENT limit that names
//      the count held and stops nobody signing in; a credential the person
//      never enrolled refused; `GET /admin-api/webauthn` marking the algorithms
//      offered and saying user verification is enforced.
//   C. `webauthn_session.js` — a security key as the only credential: a
//      passwordless first use in development creates the person's entry
//      and the key on it, its session says one factor, and a different
//      authenticator presenting that credential's id is refused.
//   D. `webauthn_ceremony_log.js` — the audit rows a ceremony writes
//      (`webauthn.ceremony`): a registration the browser declined at the
//      portal (STS-AUTHN-0022, the error NAME and never its message, what
//      was offered, a duration), a completed one naming its algorithm, the
//      client as family and major version only; and the algorithm mismatch
//      (`webauthn.algorithm-mismatch`) for a person holding an ML-DSA
//      passkey who signs in with an ES256 one, and for nobody else.
//   E. `webauthn_enterprise_attestation.js` — `webauthn.attestation`
//      `enterprise` refused while no RP ID is listed (STS-AUTHN-0500) and
//      the list emptied under it refused too; the pair taken together in
//      one section Save (`config/set-many`); a registration ASKING for
//      `enterprise` at a listed RP ID and for `direct` elsewhere.
//
// NOT CARRIED (class (d)): the JOSE-name table derived from the verifier's
// (a module fact), `clientOf()` and `clientErrorName()` over strings (their
// effect is asserted on the row), `unfold()` (a library), the row's
// twelve-field cap, the RP ID suffix rule's other hosts (the probe has one
// host, `localhost`), the per-person key count by use (`mechanismsFor()`),
// the device link's rows (H: `sts_devices`' family) and the source reads of
// `webauthn_addresses.js` section 3 (both doors are exercised here instead).
//
// OWNED HERE (local: true): this repository's own `/authn-api`,
// `/account-api` and `/admin-api`.
// ===========================================================================

const assert = require("assert");
const nodeCrypto = require("crypto");
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
var log = bunyan.createLogger({ name: "sts_webauthn_rules",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const k = wire.kit("sts_webauthn_rules", { log: log });
const check = k.check;
const PASSWORD = "Wa-Rules-Passw0rd!-" + String(Date.now()).slice(-6);

function who(name) {
  log.debug("Entering who(). " + name);
  log.debug("Leaving who().");
  return (name + "-" + k.STAMP).slice(0, 30);
}

function sha256(data) {
  log.debug("Entering sha256().");
  log.debug("Leaving sha256().");
  return nodeCrypto.createHash("sha256").update(data).digest();
}

// A passwordless first use at the screen (development's enrolment): the
// step armed, registered by `auth`. `{ done, armed, step }`.
async function firstUse(realm, name, auth) {
  log.debug("Entering firstUse(). " + name);
  const t = await k.typed(realm, name, {});
  assert.ok(t.step, "the passwordless sign-in for " + name + " reached no " +
    "step: " + k.said(t.answer).slice(0, 300));
  const done = await k.ceremony(t.step, function (c) {
    return auth.register(c.challenge, c.user && c.user.id, c.rpId);
  });
  log.debug("Leaving firstUse(). " + done.next);
  return { done: done, armed: done.armed, step: t.step };
}

// A typed sign-in (`o.password` first) whose passkey step `auth` answers
// with `ao`; the answer, `armed` beside it.
async function signIn(realm, name, auth, o, ao) {
  log.debug("Entering signIn(). " + name);
  const t = await k.typed(realm, name, o || {});
  if (!t.step) {
    log.debug("Leaving signIn(). No step: " + t.answer.next);
    return t.answer;
  }
  const done = await k.ceremony(t.step, function (c) {
    return auth.assert(c.challenge, Object.assign({ rpId: c.rpId },
                                                  ao || {}));
  });
  log.debug("Leaving signIn(). " + done.next);
  return done;
}

// The options a portal enrolment arms (`kind`), cancelled again.
async function portalOptions(portal, kind) {
  log.debug("Entering portalOptions(). " + kind);
  await portal.api("POST", "/account-api/keys", { action: "cancel" });
  const begun = await portal.api("POST", "/account-api/keys",
    kind ? { action: "begin", kind: kind } : { action: "begin" });
  const page = await portal.api("GET", "/account-api/keys");
  await portal.api("POST", "/account-api/keys", { action: "cancel" });
  const enrol = (page.json && page.json.enrol) || {};
  log.debug("Leaving portalOptions(). " + begun.status);
  return { begun: begun, pending: enrol.pending || null, enrol: enrol };
}

function refusedWith(r) {
  log.debug("Entering refusedWith().");
  log.debug("Leaving refusedWith().");
  return r.status >= 400 || (r.body && r.body.ok === false) ||
         (r.json && r.json.ok === false);
}

async function addresses() {
  log.debug("Entering addresses().");
  log.info("=== A. the origin and the RP ID a ceremony is held to ===");
  const realm = await k.realm("wa-addr", "development");
  await k.client(realm);
  const own = await firstUse(realm, who("own"), k.authenticator({}));
  const evil = await firstUse(realm, who("evil"),
    k.authenticator({ origin: "https://evil.example" }));
  check("A1. unset, the origin is the service's own: a ceremony carrying " +
        "it registers, one carrying an origin nobody listed is refused",
    function () {
      assert.strictEqual(own.done.next, "redirect", k.said(own.done));
      assert.notStrictEqual(evil.done.next, "redirect", k.said(evil.done));
    });
  await k.mustSet(realm, "webauthn.allowedOrigins",
                  "https://login.example.test, https://sso.example.test/");
  const listed = await firstUse(realm, who("sso"),
    k.authenticator({ origin: "https://sso.example.test" }));
  const ownNow = await firstUse(realm, who("own2"), k.authenticator({}));
  const evilNow = await firstUse(realm, who("evil2"),
    k.authenticator({ origin: "https://evil.example" }));
  check("A2. set, an origin ON THE LIST is taken — the setting's trailing " +
        "slash is not part of an origin", function () {
    assert.strictEqual(listed.done.next, "redirect", k.said(listed.done));
  });
  check("A3. and the origin the request arrived at is refused, as is one " +
        "nobody listed: the list is the whole answer", function () {
    assert.notStrictEqual(ownNow.done.next, "redirect", k.said(ownNow.done));
    assert.notStrictEqual(evilNow.done.next, "redirect",
                          k.said(evilNow.done));
  });
  await k.reset(realm, "webauthn.allowedOrigins");

  // THE RP ID. A person with a password and a key, whose second step is
  // the ceremony asked about.
  const holder = who("holder");
  await k.person(realm, holder, PASSWORD);
  const key = k.authenticator({});
  const portal = await portalSignin.signInToThePortal(realm.base, holder,
    null, { password: PASSWORD });
  const enrolled = await k.enrol(portal, key, {});
  assert.strictEqual(enrolled.done && enrolled.done.status, 200,
    "enrolling the holder's key answered " +
    JSON.stringify(enrolled.done && enrolled.done.json).slice(0, 300));
  await k.mustSet(realm, "webauthn.rpId", "attacker.example");
  const fallback = await signIn(realm, holder, key, { password: PASSWORD });
  check("A4. DEVELOPMENT: an RP ID that does not fit the host falls back to " +
        "the host — the ceremony names it and no problem, and the key " +
        "answers", function () {
    const armed = fallback.armed && fallback.armed.json;
    assert.ok(armed, k.said(fallback));
    assert.strictEqual(armed.rpId, k.RP_ID, JSON.stringify(armed));
    assert.strictEqual(String(armed.problem || ""), "");
    assert.strictEqual(fallback.next, "redirect", k.said(fallback));
  });
  const set = await k.send("POST", k.root + "/admin-api/realms/set",
    { id: realm.id, key: "global.mode", value: "product" });
  assert.strictEqual(set.status, 200, set.raw.slice(0, 300));
  await k.mustSet(realm, "authn.allowOptionalSecondFactor", true);
  const refused = await signIn(realm, holder, key, { password: PASSWORD });
  const refusedArmed = (refused.armed && refused.armed.json) || {};
  check("A5. PRODUCT: the same RP ID is refused, the ceremony naming the " +
        "setting and the fix", function () {
    assert.notStrictEqual(refused.next, "redirect", k.said(refused));
    const said = String(refusedArmed.problem || "") + " " + k.said(refused);
    assert.ok(/webauthn\.rpId/.test(said) &&
              /global\.publicBaseUrl/.test(said), said.slice(0, 500));
  });
  await k.mustSet(realm, "webauthn.rpId", k.RP_ID.slice(1));
  const suffix = await signIn(realm, holder, key, { password: PASSWORD });
  check("A6. and a value the host ends in as a STRING but not at a label " +
        "boundary is refused too — endsWith() alone is the mistake",
    function () {
      assert.notStrictEqual(suffix.next, "redirect", k.said(suffix));
      assert.ok(/webauthn\.rpId/.test(String(((suffix.armed || {}).json ||
                                              {}).problem || "") + " " +
                                       k.said(suffix)), k.said(suffix));
    });
  await k.mustSet(realm, "webauthn.rpId", k.RP_ID);
  const exact = await signIn(realm, holder, key, { password: PASSWORD });
  check("A7. while the host itself is no problem in product either",
    function () {
      assert.strictEqual(exact.next, "redirect", k.said(exact));
      assert.strictEqual(String(((exact.armed || {}).json || {}).problem ||
                                ""), "");
    });
  await k.reset(realm, "webauthn.rpId");
  log.debug("Leaving addresses().");
}

async function offer() {
  log.debug("Entering offer().");
  log.info("=== B. what the ceremony offers, and the policy over a key ===");
  const realm = await k.realm("wa-pol", "development");
  await k.client(realm);
  const name = who("offer");
  await k.person(realm, name, PASSWORD);
  const portal = await portalSignin.signInToThePortal(realm.base, name, null,
    { password: PASSWORD });
  const algsOf = async function (kind) {
    log.debug("Entering algsOf().");
    const o = await portalOptions(portal, kind || "security-key");
    log.debug("Leaving algsOf().");
    return ((o.pending && o.pending.options &&
             o.pending.options.algorithms) || []).map(Number);
  };

  const report = await k.call(realm, "GET", "/webauthn");
  const dflt = await algsOf();
  check("B1. by default the offer is every algorithm the verifier checks, " +
        "strongest first — ML-DSA-87, -65, -44, EdDSA, ES256, RS256",
    function () {
      assert.deepStrictEqual(dflt, [-50, -49, -48, -8, -7, -257]);
    });
  check("B2. and GET /admin-api/webauthn lists every algorithm the verifier " +
        "knows, the offered ones marked", function () {
    assert.strictEqual(report.status, 200, report.raw.slice(0, 300));
    const rows = ((report.body || {}).status || {}).algorithms || [];
    const offered = rows.filter(function (one) {
      return one.offered;
    }).map(function (one) {
      return one.coseAlg;
    });
    assert.deepStrictEqual(offered, dflt, JSON.stringify(rows));
    ["ES384", "PS256", "Ed448", "ES256K", "RS1"].forEach(function (alg) {
      assert.ok(rows.some(function (one) {
        return one.name === alg && one.offered === false;
      }), alg + " is not on the report as not offered");
    });
    assert.ok(rows.some(function (one) {
      return one.name === "RS1" && one.notOfferedBecause === "insecure-off";
    }), JSON.stringify(rows));
  });
  const unknown = await k.setting(realm, "webauthn.algorithms",
                                  "ES256,NOSUCHALG");
  check("B3. a write naming an algorithm the verifier does not know is " +
        "refused, naming it", function () {
    assert.ok(refusedWith(unknown), unknown.status + " " +
              unknown.raw.slice(0, 300));
    assert.ok(/NOSUCHALG/.test(unknown.raw), unknown.raw.slice(0, 300));
  });
  await k.mustSet(realm, "webauthn.algorithms", "ES256,RS1");
  const rs1Off = await algsOf();
  await k.mustSet(realm, "webauthn.insecureAlgorithms", true);
  const rs1On = await algsOf();
  check("B4. RS1 is not requested even where webauthn.algorithms names it, " +
        "until webauthn.insecureAlgorithms — and then LAST", function () {
    assert.deepStrictEqual(rs1Off, [-7], JSON.stringify(rs1Off));
    assert.deepStrictEqual(rs1On, [-7, -65535], JSON.stringify(rs1On));
  });
  await k.mustSet(realm, "webauthn.pqcOnly", true);
  const pqOnly = await algsOf();
  await k.mustSet(realm, "webauthn.algorithms", "ES256,ML-DSA-87,RS256");
  const pqNamed = await algsOf();
  check("B5. webauthn.pqcOnly narrows the offer to ML-DSA and beats the " +
        "insecure flag; with a list naming one it keeps that one",
    function () {
      assert.ok(pqOnly.length > 0 && pqOnly.every(function (a) {
        return [-48, -49, -50].indexOf(a) >= 0;
      }), JSON.stringify(pqOnly));
      assert.deepStrictEqual(pqNamed, [-50], JSON.stringify(pqNamed));
    });
  await k.reset(realm, "webauthn.pqcOnly");
  await k.reset(realm, "webauthn.insecureAlgorithms");
  await k.reset(realm, "webauthn.algorithms");

  const asPasskey = await portalOptions(portal, "passkey");
  const asKey = await portalOptions(portal, "security-key");
  check("B6. with no preference the attachment member is ABSENT, not the " +
        "string any; a security key asks cross-platform", function () {
    const sel = asPasskey.pending.options.authenticatorSelection;
    assert.ok(!Object.prototype.hasOwnProperty.call(sel,
      "authenticatorAttachment"), JSON.stringify(sel));
    assert.strictEqual(asKey.pending.options.authenticatorSelection
      .authenticatorAttachment, "cross-platform");
  });
  check("B7. a passkey REQUIRES a discoverable credential and sets the " +
        "Level 1 requireResidentKey with it", function () {
    const sel = asPasskey.pending.options.authenticatorSelection;
    assert.strictEqual(sel.residentKey, "required");
    assert.strictEqual(sel.requireResidentKey, true);
  });
  await k.mustSet(realm, "webauthn.authenticatorAttachment",
                  "cross-platform");
  const forced = await portalOptions(portal, "passkey");
  check("B8. a setting that names an attachment wins over the person's " +
        "choice, and only that button is offered", function () {
    assert.strictEqual(forced.pending.options.authenticatorSelection
      .authenticatorAttachment, "cross-platform");
    assert.deepStrictEqual(forced.enrol.kinds, ["security-key"],
                           JSON.stringify(forced.enrol).slice(0, 400));
  });
  await k.reset(realm, "webauthn.authenticatorAttachment");
  await k.mustSet(realm, "webauthn.credProps", false);
  const noProps = await portalOptions(portal, "security-key");
  check("B9. credProps off is carried through to the options", function () {
    assert.strictEqual(noProps.pending.options.credProps, false);
  });
  await k.reset(realm, "webauthn.credProps");

  // USER VERIFICATION: requested at preferred, enforced at required.
  const key = k.authenticator({});
  const enrolled = await k.enrol(portal, key, {});
  assert.strictEqual(enrolled.done.status, 200,
    JSON.stringify(enrolled.done.json).slice(0, 300));
  await k.mustSet(realm, "webauthn.userVerification", "preferred");
  const presence = await signIn(realm, name, key, { password: PASSWORD },
                                { uv: false });
  await k.mustSet(realm, "webauthn.userVerification", "required");
  const strict = await signIn(realm, name, key, { password: PASSWORD },
                              { uv: false });
  const strictOk = await signIn(realm, name, key, { password: PASSWORD });
  const uvReport = await k.call(realm, "GET", "/webauthn");
  check("B10. preferred is REQUESTED and not enforced: an assertion without " +
        "the UV flag is taken", function () {
    assert.strictEqual(presence.next, "redirect", k.said(presence));
  });
  check("B11. required IS enforced — the flag is inside the signed bytes — " +
        "and the report says so", function () {
    assert.notStrictEqual(strict.next, "redirect", k.said(strict));
    assert.strictEqual(strictOk.next, "redirect", k.said(strictOk));
    assert.strictEqual(((uvReport.body || {}).status || {})
      .userVerificationEnforced, true, uvReport.raw.slice(0, 300));
  });
  await k.reset(realm, "webauthn.userVerification");

  // THE POLICY HALF: two uses of one key, and the enrolment limit.
  const pw = who("pw");
  await k.person(realm, pw, PASSWORD);
  const pwPortal = await portalSignin.signInToThePortal(realm.base, pw, null,
    { password: PASSWORD });
  const pwKey = k.authenticator({});
  await k.enrol(pwPortal, pwKey, {});
  await k.mustSet(realm, "webauthn.primaryAllowed", false);
  const b45 = await k.codeCount(realm, "STS-AUTHN-0045");
  const noPrimary = await signIn(realm, pw, pwKey, {});
  const n45 = await k.newCodes(realm, "STS-AUTHN-0045", b45);
  const asSecond = await signIn(realm, pw, pwKey, { password: PASSWORD });
  check("B12. with webauthn.primaryAllowed off the passwordless USE is " +
        "refused (STS-AUTHN-0045), naming the setting, and the same key is " +
        "still a second factor", function () {
    assert.notStrictEqual(noPrimary.next, "redirect", k.said(noPrimary));
    assert.ok(n45 >= 1, "STS-AUTHN-0045 rows: " + n45);
    assert.strictEqual(asSecond.next, "redirect", k.said(asSecond));
  });
  await k.reset(realm, "webauthn.primaryAllowed");
  await k.mustSet(realm, "webauthn.mfaAllowed", false);
  const b46 = await k.codeCount(realm, "STS-AUTHN-0046");
  const noSecond = await signIn(realm, pw, pwKey, { password: PASSWORD,
                                                    headers: k.BROWSER });
  const n46 = await k.newCodes(realm, "STS-AUTHN-0046", b46);
  const asFirst = await signIn(realm, pw, pwKey, {});
  check("B13. the mirror image: webauthn.mfaAllowed off refuses the " +
        "second-factor use (STS-AUTHN-0046) and the key still signs in on " +
        "its own", function () {
    assert.ok(noSecond.next !== "redirect" || n46 >= 1, k.said(noSecond));
    assert.ok(n46 >= 1, "STS-AUTHN-0046 rows: " + n46 + " " +
              k.said(noSecond).slice(0, 200));
    assert.strictEqual(asFirst.next, "redirect", k.said(asFirst));
  });
  await k.mustSet(realm, "webauthn.primaryAllowed", false);
  const b531 = await k.codeCount(realm, "STS-AUTHN-0531");
  const neither = await k.enrol(pwPortal, k.authenticator({}), {});
  const n531 = await k.newCodes(realm, "STS-AUTHN-0531", b531);
  check("B14. with both uses refused a new key is refused " +
        "(STS-AUTHN-0531): it could never answer anything", function () {
    assert.ok(n531 >= 1, "STS-AUTHN-0531 rows: " + n531 + " " +
              JSON.stringify(neither.begun.json).slice(0, 300));
  });
  await k.reset(realm, "webauthn.primaryAllowed");
  await k.reset(realm, "webauthn.mfaAllowed");
  await k.mustSet(realm, "webauthn.enabled", false);
  const b44 = await k.codeCount(realm, "STS-AUTHN-0044");
  const off = await k.enrol(pwPortal, k.authenticator({}), {});
  const n44 = await k.newCodes(realm, "STS-AUTHN-0044", b44);
  check("B15. with the mechanism off no key may be enrolled " +
        "(STS-AUTHN-0044)", function () {
    assert.ok(!off.done || off.done.status !== 200,
              JSON.stringify(off.begun.json).slice(0, 300));
    assert.ok(n44 >= 1, "STS-AUTHN-0044 rows: " + n44);
  });
  await k.reset(realm, "webauthn.enabled");
  await k.mustSet(realm, "webauthn.maxKeysPerPerson", 1);
  const capped = await k.enrol(pwPortal, k.authenticator({}), {});
  const stillIn = await signIn(realm, pw, pwKey, { password: PASSWORD });
  check("B16. webauthn.maxKeysPerPerson refuses the next enrolment, saying " +
        "how many are held — and is an ENROLMENT limit: the person still " +
        "signs in",
    function () {
      const said = JSON.stringify(capped.begun.json) +
                   JSON.stringify(capped.done && capped.done.json);
      assert.ok(!capped.done || capped.done.status !== 200, said);
      // The portal's sentence names the count, not the setting (the
      // in-process claim was the library's errors, which named it).
      assert.ok(/already hold 1 security key/.test(said), said.slice(0, 400));
      assert.strictEqual(stillIn.next, "redirect", k.said(stillIn));
    });
  await k.reset(realm, "webauthn.maxKeysPerPerson");
  const stranger = k.authenticator({});
  const notHers = await signIn(realm, pw, stranger, { password: PASSWORD });
  check("B17. a credential this person never enrolled is refused",
    function () {
      assert.notStrictEqual(notHers.next, "redirect", k.said(notHers));
    });
  log.debug("Leaving offer().");
}

async function session() {
  log.debug("Entering session().");
  log.info("=== C. a security key as the only credential ===");
  const realm = await k.realm("wa-only", "development");
  await k.client(realm);
  const name = who("only");
  const key = k.authenticator({});
  const used = await firstUse(realm, name, key);
  const entry = await k.call(realm, "GET", "/users?user=" +
                             encodeURIComponent(name));
  check("C1. a passwordless first use in development creates the person's " +
        "entry, the key on it, and signs them in", function () {
    assert.strictEqual(used.done.next, "redirect", k.said(used.done));
    assert.strictEqual(entry.status, 200, entry.raw.slice(0, 300));
    const keys = (entry.body.factors && entry.body.factors.keys) || [];
    assert.ok(keys.some(function (one) {
      return one.credentialId === key.credentialId;
    }), JSON.stringify(keys).slice(0, 400));
  });
  const again = await signIn(realm, name, key, {});
  check("C2. the key it enrolled then ASSERTS", function () {
    assert.strictEqual(again.next, "redirect", k.said(again));
  });
  // A DIFFERENT authenticator presenting the enrolled credential's id: the
  // signature is checked against the enrolled key and fails.
  const forger = k.authenticator({});
  const t = await k.typed(realm, name, {});
  const forged = await k.ceremony(t.step, function (c) {
    const made = forger.assert(c.challenge, { rpId: c.rpId,
                                              handle: key.handle() });
    made.id = key.credentialId;
    made.rawId = key.credentialId;
    return made;
  });
  check("C3. a DIFFERENT authenticator presenting that credential's id is " +
        "refused — without this the two above would pass against a " +
        "verifier that checked nothing", function () {
    assert.notStrictEqual(forged.next, "redirect", k.said(forged));
  });
  log.debug("Leaving session().");
}

async function rowsOf(realm, action, actor) {
  log.debug("Entering rowsOf(). " + action);
  const r = await k.call(realm, "GET", "/audit?per=500&action=" +
                         encodeURIComponent(action));
  const rows = ((r.body && (r.body.rows || r.body.events)) || []).filter(
    function (one) {
      return one.action === action && (!actor || one.actor === actor);
    });
  log.debug("Leaving rowsOf(). " + rows.length);
  return rows;
}

async function ceremonyLog() {
  log.debug("Entering ceremonyLog().");
  log.info("=== D. what a ceremony records ===");
  const realm = await k.realm("wa-log", "development");
  await k.client(realm);
  const name = who("log");
  await k.person(realm, name, PASSWORD);
  const portal = await portalSignin.signInToThePortal(realm.base, name, null,
    { password: PASSWORD });
  await portal.api("POST", "/account-api/keys", { action: "cancel" });
  await portal.api("POST", "/account-api/keys",
                   { action: "begin", kind: "passkey" });
  const page = await portal.api("GET", "/account-api/keys");
  const pending = (page.json && page.json.enrol &&
                   page.json.enrol.pending) || {};
  const b22 = await k.codeCount(realm, "STS-AUTHN-0022");
  const declined = await portal.api("POST", "/account-api/keys",
    { action: "finish", enrolment_id: pending.id,
      credential: JSON.stringify({ error: "NotAllowedError",
        message: "The operation timed out. SECRET FREE TEXT" }) });
  const n22 = await k.newCodes(realm, "STS-AUTHN-0022", b22);
  const rows = await rowsOf(realm, "webauthn.ceremony", name);
  const refused = rows.filter(function (one) {
    return one.errorCode === "STS-AUTHN-0022";
  })[0] || { detail: {} };
  check("D1. a registration the browser declined at the portal leaves one " +
        "row: STS-AUTHN-0022, the error NAME, what was offered, a duration " +
        "— and never the message", function () {
    assert.ok(declined.status >= 400 || (declined.json &&
              declined.json.ok === false), JSON.stringify(declined.json));
    assert.ok(n22 >= 1, "STS-AUTHN-0022 rows: " + n22);
    const d = refused.detail || {};
    assert.ok(d.ceremony === "registration" && d.door === "portal" &&
              d.clientError === "NotAllowedError" &&
              String(d.offered || "").length > 0 &&
              typeof d.durationMs === "number",
              JSON.stringify(refused).slice(0, 800));
    assert.ok(JSON.stringify(rows).indexOf("SECRET FREE TEXT") < 0);
  });
  // Two keys, ML-DSA-65 and ES256: the classical sign-in is the mismatch.
  const pq = k.authenticator({ alg: -49 });
  const ec = k.authenticator({});
  const pqDone = await k.enrol(portal, pq, {});
  const ecDone = await k.enrol(portal, ec, {});
  assert.strictEqual(pqDone.done && pqDone.done.status, 200,
    JSON.stringify(pqDone.begun.json).slice(0, 300) +
    JSON.stringify(pqDone.done && pqDone.done.json).slice(0, 300));
  assert.strictEqual(ecDone.done && ecDone.done.status, 200,
    JSON.stringify(ecDone.done && ecDone.done.json).slice(0, 300));
  const done = (await rowsOf(realm, "webauthn.ceremony", name)).filter(
    function (one) {
      return one.outcome === "success" &&
             (one.detail || {}).ceremony === "registration";
    });
  check("D2. a completed registration's row names its algorithm, whether " +
        "it is post-quantum, and the client as family and major version " +
        "only", function () {
    const algs = done.map(function (one) {
      return (one.detail || {}).algorithm;
    });
    assert.ok(algs.indexOf("ML-DSA-65") >= 0 && algs.indexOf("ES256") >= 0,
              JSON.stringify(done).slice(0, 800));
    done.forEach(function (one) {
      const client = String((one.detail || {}).client || "");
      assert.ok(/^[A-Za-z]+ \d+ on [A-Za-z]+/.test(client) &&
                !/\d+\.\d+/.test(client.split("|")[0]),
                JSON.stringify(one.detail));
      assert.ok(!one.errorCode, JSON.stringify(one));
    });
  });
  const ecIn = await signIn(realm, name, ec, { password: PASSWORD });
  const pqIn = await signIn(realm, name, pq, { password: PASSWORD });
  const mismatch = await rowsOf(realm, "webauthn.algorithm-mismatch", name);
  check("D3. a classical sign-in by a person holding an ML-DSA passkey is " +
        "an event of its own, naming what was used and what is held; the " +
        "post-quantum sign-in is not", function () {
    assert.strictEqual(ecIn.next, "redirect", k.said(ecIn));
    assert.strictEqual(pqIn.next, "redirect", k.said(pqIn));
    assert.strictEqual(mismatch.length, 1, JSON.stringify(mismatch));
    assert.ok(mismatch[0].detail.used === "ES256" &&
              /ML-DSA-65/.test(String(mismatch[0].detail.held)) &&
              !mismatch[0].errorCode, JSON.stringify(mismatch[0]));
  });
  const classical = who("classical");
  await k.person(realm, classical, PASSWORD);
  const cPortal = await portalSignin.signInToThePortal(realm.base, classical,
    null, { password: PASSWORD });
  const only = k.authenticator({});
  await k.enrol(cPortal, only, {});
  await signIn(realm, classical, only, { password: PASSWORD });
  const none = await rowsOf(realm, "webauthn.algorithm-mismatch", classical);
  check("D4. and a person with no post-quantum key has no such event",
    function () {
      assert.strictEqual(none.length, 0, JSON.stringify(none));
    });
  log.debug("Leaving ceremonyLog().");
}

async function enterprise() {
  log.debug("Entering enterprise().");
  log.info("=== E. enterprise attestation, asked for only by RP ID ===");
  const realm = await k.realm("wa-ent", "development");
  const name = who("ent");
  await k.person(realm, name, PASSWORD);
  const portal = await portalSignin.signInToThePortal(realm.base, name, null,
    { password: PASSWORD });
  const b500 = await k.codeCount(realm, "STS-AUTHN-0500");
  const alone = await k.setting(realm, "webauthn.attestation", "enterprise");
  const n500 = await k.newCodes(realm, "STS-AUTHN-0500", b500);
  check("E1. enterprise with no RP ID listed is refused at the write " +
        "(STS-AUTHN-0500)", function () {
    assert.ok(refusedWith(alone), alone.status + " " + alone.raw);
    assert.ok(n500 >= 1, "STS-AUTHN-0500 rows: " + n500);
  });
  const together = await k.call(realm, "POST", "/config/set-many",
    { "webauthn.attestation": "enterprise",
      "webauthn.attestationEnterpriseRpIds": k.RP_ID.toUpperCase() });
  check("E2. a section's Save takes both in one post — the pair judged by " +
        "both new values", function () {
    assert.ok(together.status === 200 && together.body.ok !== false,
              together.status + " " + together.raw.slice(0, 300));
  });
  const listed = await portalOptions(portal, "security-key");
  check("E3. a registration at a listed RP ID (case aside) asks for " +
        "enterprise", function () {
    assert.strictEqual(listed.pending.options.attestation, "enterprise",
                       JSON.stringify(listed.pending.options));
  });
  const b500b = await k.codeCount(realm, "STS-AUTHN-0500");
  const emptied = await k.setting(realm,
    "webauthn.attestationEnterpriseRpIds", "");
  const n500b = await k.newCodes(realm, "STS-AUTHN-0500", b500b);
  check("E4. emptying the list while enterprise is chosen is refused too",
    function () {
      assert.ok(refusedWith(emptied), emptied.status + " " + emptied.raw);
      assert.ok(n500b >= 1, "STS-AUTHN-0500 rows: " + n500b);
    });
  await k.mustSet(realm, "webauthn.attestationEnterpriseRpIds",
                  "other.example.test");
  const elsewhere = await portalOptions(portal, "security-key");
  check("E5. at an RP ID the list does not name it asks for direct",
    function () {
      assert.strictEqual(elsewhere.pending.options.attestation, "direct",
                         JSON.stringify(elsewhere.pending.options));
    });
  const back = await k.call(realm, "POST", "/config/set-many",
    { "webauthn.attestation": "direct",
      "webauthn.attestationEnterpriseRpIds": "" });
  const lone = await k.call(realm, "POST", "/config/set-many",
    { "webauthn.attestation": "enterprise" });
  check("E6. the way back to direct with the list emptied is one Save, " +
        "and a Save of enterprise alone is refused", function () {
    assert.ok(back.status === 200 && back.body.ok !== false,
              back.status + " " + back.raw.slice(0, 300));
    assert.ok(refusedWith(lone), lone.status + " " + lone.raw);
  });
  await k.reset(realm, "webauthn.attestation");
  await k.reset(realm, "webauthn.attestationEnterpriseRpIds");
  log.debug("Leaving enterprise().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving " + k.root + "; realms carry " + k.STAMP);
  await addresses();
  await offer();
  await session();
  await ceremonyLog();
  await enterprise();
  assert.ok(k.checks() >= 37, "only " + k.checks() + " checks ran; a " +
            "section has stopped being called.");
  log.debug("Leaving test().");
}

k.main(test);
