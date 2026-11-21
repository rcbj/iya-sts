// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: sts_passkey_policy_profile.js
//
// ===========================================================================
// THE PASSKEY POLICY'S PROFILE, ITS PIN LENGTH AND A SIGN-IN WITH NO
// USERNAME REQUIRED, OVER THE WIRE (#527, #528, #529, #531, #608).
//
// D12 (#444): carries over what a client can see of three in-process files
// deleted at the cutover, each section in a throwaway realm of its own, the
// profile written through `POST /admin-api/policies/save-passkey-policy`,
// every passkey made by a software authenticator of the job (no key
// material is kept anywhere), and every code read off the realm's
// `/admin-api/audit`:
//
//   A. `passkey_policy.js` P1, P7b: the built-in profile as
//      `GET /admin-api/policies` answers it (usernameless sign-in ON, a
//      security key asked `required`, in force in development and in
//      product), its twenty-eight rows with their types, and both enrolment
//      kinds of `/account-api/keys` asking for a discoverable credential;
//   B. P2: a save naming one row is refused (STS-AUTHN-0309), a resident
//      key outside WebAuthn's three is refused naming them, a profile name
//      that is not one is refused (STS-AUTHN-0308), and a named profile
//      with no holder is kept until its reset;
//   C. P4: with usernameless sign-in OFF the security key is asked
//      `required` whatever `securityKeyResidentKey` says; ON, the row, while
//      "Create a passkey" stays `required`;
//   D. P5: the usernameless door refused while the row is off
//      (STS-AUTHN-0301), offered while it is on;
//   E. P8: synced passkeys allowed by default; under `disallow` a
//      backup-eligible key refused at registration (STS-AUTHN-0312) and a
//      synced key registered before refused at sign-in (STS-AUTHN-0313); a
//      value that is neither refused;
//   F. `passkey_pin_length.js` and P9: no minimum asked by default and a key
//      reporting 4 registers; enforced at 6 the options ask for
//      `minPinLength`, a key reporting 8 registers, one reporting 4 or
//      nothing is refused (STS-AUTHN-0314) saying why; with
//      `pinLengthOnlyIfSupported` the silent key registers; at sign-in the
//      minimum raised to 10 refuses the key that reported 8
//      (STS-AUTHN-0315), the silent key only while the row is off, the key
//      that reported exactly the minimum signs in; reset, every key signs in
//      and nothing is asked; the minimum held to 4..63;
//   G. P10: each ceremony's hints as they were before #531, a list reaching
//      its ceremony in its order, `none` sending none, and the
//      contradictions, a hint twice and an unknown hint refused;
//   H. `passkey_require_usernameless.js` 1-3: `requireUsernameless` without
//      `allowUsernameless` refused; on, a passkey-only application's screen
//      asks for no username and a sign-in naming a person is refused
//      (STS-AUTHN-0333), while an application allowing a password too
//      keeps its username field.
//
// NOT CARRIED (class (d)): P2d (the console form's unticked checkbox is the
// browser bundle's reading), P3 (inheritance from the default realm writes
// the DEFAULT realm's profile, process-wide state:
// `sts_passkey_policy_inheritance.js`, exclusive), P4c (`describe()`'s
// sentences are a library answer), P6 (retired settings refused at start),
// P7a/P7c (the policy-kind table and the action dispatcher), P10e/P10f
// (`webauthn.authenticatorAttachment` is a restart-only process setting no
// realm may carry), require_usernameless 4 (the hosted surfaces —
// `usernamelessRequired()` asked of a pending record the console's own
// sign-in builds; owed: a console sign-in in a realm whose console names a
// webauthn-only policy) and 5 (the renderer's markup).
//
// OWNED HERE (local: true): the passkey policy is this repository's own.
// ===========================================================================

"use strict";

const assert = require("assert");
const nodeCrypto = require("crypto");
const wire = require("./passkey_wire_kit.js");
const portalSignin = require("./portal_signin.js");
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
var log = bunyan.createLogger({ name: "sts_passkey_policy_profile",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const K = wire.kit("sts_passkey_policy_profile", { log: log });
const check = K.check;
const PASSWORD = "Pk-profile-" + K.STAMP + "-Aa1!";

function who(name) {
  log.debug("Entering who(). " + name);
  log.debug("Leaving who().");
  return ("pkp-" + name + "-" + K.STAMP).slice(0, 40);
}

// The code's audit rows since `before`, as `{ r, recorded }` beside the
// answer `act()` gave.
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

function errorsOf(r) {
  log.debug("Entering errorsOf().");
  log.debug("Leaving errorsOf().");
  return JSON.stringify((r.body && (r.body.errors || r.body.error)) ||
                        r.raw || "");
}

// A person signed in to the realm's portal, with a password.
async function portalFor(realm, name) {
  log.debug("Entering portalFor(). " + name);
  await K.person(realm, name, PASSWORD);
  const client = await portalSignin.signInToThePortal(realm.base, name, null,
    { password: PASSWORD });
  log.debug("Leaving portalFor().");
  return client;
}

// The armed options of an enrolment of `kind`, read back and left pending.
async function optionsOf(client, kind) {
  log.debug("Entering optionsOf(). " + kind);
  const e = await K.enrol(client, null, { kind: kind });
  assert.ok(e.pending && e.pending.options,
    "no pending " + kind + " enrolment: " + e.begun.status + " " +
    JSON.stringify(e.begun.json || {}).slice(0, 300));
  log.debug("Leaving optionsOf().");
  return e.pending.options;
}

// ONE ES256 AUTHENTICATOR THAT MAY REPORT CTAP 2.1 section 12.4's
// `minPinLength` in its authenticator extension outputs (`pin` a whole
// number: the ED flag set and a one-entry map appended to the attested
// data; anything else: no extensions). The kit's authenticator carries no
// extension, which is the whole of what this one varies.
function pinAuthenticator(pin) {
  log.debug("Entering pinAuthenticator(). " + pin);
  const reports = typeof pin === "number";
  const pair = nodeCrypto.generateKeyPairSync("ec",
                                              { namedCurve: "prime256v1" });
  const jwk = pair.publicKey.export({ format: "jwk" });
  const credentialId = nodeCrypto.randomBytes(32);
  const id = credentialId.toString("base64url");
  const cose = new Map([[1, 2], [3, -7], [-1, 1],
                        [-2, Buffer.from(jwk.x, "base64url")],
                        [-3, Buffer.from(jwk.y, "base64url")]]);
  let signCount = 0;
  let userHandle = "";
  const clientData = function (type, challenge) {
    return Buffer.from(JSON.stringify({ type: type, challenge: challenge,
      origin: K.ORIGIN, crossOrigin: false }), "utf8");
  };
  log.debug("Leaving pinAuthenticator().");
  return {
    credentialId: id,
    register: function (challenge, handle, rpId) {
      userHandle = handle || "";
      const idLen = Buffer.alloc(2);
      idLen.writeUInt16BE(credentialId.length, 0);
      const parts = [K.sha256(Buffer.from(rpId || K.RP_ID, "utf8")),
        Buffer.from([0x45 | (reports ? 0x80 : 0)]), Buffer.alloc(4),
        Buffer.alloc(16), idLen, credentialId, K.cbor(cose)];
      if (reports) {
        parts.push(K.cbor(new Map([["minPinLength", pin]])));
      }
      const authData = Buffer.concat(parts);
      const cdj = clientData("webauthn.create", challenge);
      return {
        id: id, rawId: id, type: "public-key",
        authenticatorAttachment: "cross-platform",
        clientExtensionResults: { credProps: { rk: true } },
        response: {
          attestationObject: K.cbor(new Map([["fmt", "none"],
            ["attStmt", new Map()], ["authData", authData]]))
            .toString("base64url"),
          clientDataJSON: cdj.toString("base64url"),
          transports: ["usb"] } };
    },
    assert: function (challenge) {
      signCount += 1;
      const count = Buffer.alloc(4);
      count.writeUInt32BE(signCount, 0);
      const authData = Buffer.concat([
        K.sha256(Buffer.from(K.RP_ID, "utf8")), Buffer.from([0x05]),
        count]);
      const cdj = clientData("webauthn.get", challenge);
      const signature = nodeCrypto.sign("sha256",
        Buffer.concat([authData, K.sha256(cdj)]), pair.privateKey);
      return {
        id: id, rawId: id, type: "public-key",
        authenticatorAttachment: "cross-platform",
        response: {
          authenticatorData: authData.toString("base64url"),
          clientDataJSON: cdj.toString("base64url"),
          signature: Buffer.from(signature).toString("base64url"),
          userHandle: userHandle || null } };
    }
  };
}

// A usernameless sign-in with `auth`'s key: true where it reached the
// application.
async function signsIn(realm, auth) {
  log.debug("Entering signsIn().");
  const answer = await K.usernameless(realm, function (challenge) {
    return auth.assert(challenge);
  });
  log.debug("Leaving signsIn(). " + answer.next);
  return answer;
}

// The key row the console reads for `name`'s credential `id`.
async function rowOf(realm, name, id) {
  log.debug("Entering rowOf().");
  const keys = await K.keysOf(realm, name);
  log.debug("Leaving rowOf().");
  return keys.filter(function (one) {
    return one.credentialId === id;
  })[0] || null;
}

async function builtIn() {
  log.debug("Entering builtIn().");
  log.info("=== A. the built-in profile ===");
  const dev = await K.realm("pkpf-a", "development");
  const prod = await K.realm("pkpf-ap", "product");
  const page = await K.call(dev, "GET", "/policies");
  const prodPage = await K.call(prod, "GET", "/policies");
  const p = page.body.passkey.profile;
  check("A1. built in: usernameless sign-in ON, a security key asked " +
        "`required`, in force — in development and in product", function () {
    assert.strictEqual(p.from, "built-in", JSON.stringify(p).slice(0, 300));
    assert.strictEqual(p.allowUsernameless, true);
    assert.strictEqual(p.securityKeyResidentKey, "required");
    assert.strictEqual(p.enforced, true);
    assert.strictEqual(prodPage.body.passkey.profile.enforced, true);
    assert.strictEqual(prodPage.body.passkey.profile.from, "built-in");
  });
  const fields = page.body.passkey.fields;
  const typeOf = function (key) {
    const f = fields.filter(function (one) {
      return one.key === key;
    })[0];
    return f ? f.type + ":" + (f.values || []).length : "absent";
  };
  // Twenty-eight since #1955 P7's credProtect and enforceCredProtect.
  check("A2. the policy page draws twenty-eight rows from its fields, " +
        "with their types", function () {
    assert.strictEqual(fields.length, 28, fields.map(function (f) {
      return f.key;
    }).join(","));
    assert.strictEqual(typeOf("securityKeyResidentKey"), "enum:3");
    assert.strictEqual(typeOf("lanes"), "enum:3");
    assert.ok(/^list:/.test(typeOf("registrationAlgorithms")),
              typeOf("registrationAlgorithms"));
    assert.ok(/^clientRules:/.test(typeOf("clientRules")),
              typeOf("clientRules"));
    assert.notStrictEqual(typeOf("adminEnrolment"), "absent");
    const mode = fields.filter(function (one) {
      return one.key === "registrationMode";
    })[0];
    assert.ok(mode && mode.values.indexOf("classical-only") >= 0,
              JSON.stringify(mode));
  });
  const client = await portalFor(dev, who("a"));
  const passkey = await optionsOf(client, "passkey");
  const securityKey = await optionsOf(client, "security-key");
  check("A3. so both of the portal's enrolments ask for a discoverable " +
        "credential", function () {
    assert.strictEqual(passkey.authenticatorSelection.residentKey,
                       "required", JSON.stringify(passkey));
    assert.strictEqual(securityKey.authenticatorSelection.residentKey,
                       "required", JSON.stringify(securityKey));
  });
  log.debug("Leaving builtIn().");
}

async function saves() {
  log.debug("Entering saves().");
  log.info("=== B. a save replaces the whole profile ===");
  const realm = await K.realm("pkpf-b", "development");
  const missing = await refusedWith(realm, "STS-AUTHN-0309", function () {
    return K.call(realm, "POST", "/policies/save-passkey-policy",
                  { profile: "default", allowUsernameless: true });
  });
  check("B1. a save naming one row is refused, naming a row it left out " +
        "(STS-AUTHN-0309)", function () {
    assert.strictEqual(missing.r.status, 400, missing.r.raw.slice(0, 300));
    assert.ok(/securityKeyResidentKey/.test(errorsOf(missing.r)),
              errorsOf(missing.r));
    assert.ok(missing.recorded > 0, "no STS-AUTHN-0309 row");
  });
  // THE WIRE DIFFERS: the enum is the request schema's, so the refusal is
  // recorded STS-API-0009 before the policy's own STS-AUTHN-0309.
  const bad = await refusedWith(realm, "STS-API-0009", function () {
    return K.savePolicy(realm, { securityKeyResidentKey: "sometimes" });
  });
  check("B2. a resident key that is not one of WebAuthn's three is " +
        "refused at the request schema, naming them (STS-API-0009)",
        function () {
    assert.strictEqual(bad.r.status, 400, bad.r.raw.slice(0, 300));
    assert.ok(/discouraged\W+preferred\W+required/.test(errorsOf(bad.r)),
              errorsOf(bad.r));
    assert.ok(bad.recorded > 0, "no STS-API-0009 row");
  });
  // The name's shape is the request schema's too (STS-API-0009).
  const other = await refusedWith(realm, "STS-API-0009", function () {
    return K.savePolicy(realm, {}, "Not A Name");
  });
  const named = await K.savePolicy(realm, {}, "admins");
  const listed = await K.call(realm, "GET", "/policies");
  const namedList = ((listed.body.passkey || {}).named || []).map(
    function (one) {
      return one.name;
    });
  check("B3. a profile name that is not one is refused (STS-API-0009), " +
        "and a named profile with no holder is kept (#1235)", function () {
    assert.strictEqual(other.r.status, 400, other.r.raw.slice(0, 300));
    assert.ok(other.recorded > 0, "no STS-API-0009 row");
    assert.strictEqual(named.status, 200, named.raw.slice(0, 300));
    assert.ok(namedList.indexOf("admins") >= 0, JSON.stringify(namedList));
  });
  const cleared = await K.call(realm, "POST", "/policies/reset-passkey-policy",
                               { profile: "admins" });
  const after = await K.call(realm, "GET", "/policies");
  const left = ((after.body.passkey || {}).named || []).map(function (one) {
    return one.name;
  });
  check("B4. the profile nothing names is removed again by its reset",
        function () {
    assert.strictEqual(cleared.status, 200, cleared.raw.slice(0, 300));
    assert.ok(left.indexOf("admins") < 0, JSON.stringify(left));
  });
  log.debug("Leaving saves().");
}

async function answers() {
  log.debug("Entering answers().");
  log.info("=== C. what a security key is asked ===");
  const realm = await K.realm("pkpf-c", "development");
  const client = await portalFor(realm, who("c"));
  await K.mustSavePolicy(realm, { allowUsernameless: false,
                                  securityKeyResidentKey: "discouraged" });
  const offPasskey = await optionsOf(client, "passkey");
  const offKey = await optionsOf(client, "security-key");
  check("C1. usernameless OFF: the security key is asked REQUIRED whatever " +
        "securityKeyResidentKey says (rcbj's answer 1)", function () {
    assert.strictEqual(offKey.authenticatorSelection.residentKey,
                       "required", JSON.stringify(offKey));
    assert.strictEqual(offPasskey.authenticatorSelection.residentKey,
                       "required", JSON.stringify(offPasskey));
  });
  for (const value of ["discouraged", "preferred", "required"]) {
    await K.mustSavePolicy(realm, { allowUsernameless: true,
                                    securityKeyResidentKey: value });
    const passkey = await optionsOf(client, "passkey");
    const key = await optionsOf(client, "security-key");
    check("C2. usernameless ON: the security key is asked the row (" + value +
          "); Create a passkey stays required", function () {
      assert.strictEqual(key.authenticatorSelection.residentKey, value,
                         JSON.stringify(key));
      assert.strictEqual(passkey.authenticatorSelection.residentKey,
                         "required", JSON.stringify(passkey));
    });
  }
  log.debug("Leaving answers().");
}

async function door() {
  log.debug("Entering door().");
  log.info("=== D. the usernameless door ===");
  const realm = await K.realm("pkpf-d", "development");
  await K.client(realm);
  await K.mustSavePolicy(realm, { allowUsernameless: false });
  const before = await K.codeCount(realm, "STS-AUTHN-0301");
  const screenOff = await K.screen(realm);
  const armedOff = await authnSignin.passkeyOptions(realm.base,
                                                    screenOff.opened);
  const recorded = await K.newCodes(realm, "STS-AUTHN-0301", before);
  check("D1. usernameless OFF: the screen offers no usernameless passkey " +
        "and the door refuses, naming the row (STS-AUTHN-0301)",
        function () {
    assert.strictEqual(screenOff.view.usernameless === true, false,
                       JSON.stringify(screenOff.view).slice(0, 300));
    assert.ok(armedOff.status >= 400, armedOff.status + " " +
              JSON.stringify(armedOff.json || {}).slice(0, 300));
    assert.ok(/allowUsernameless/.test(JSON.stringify(armedOff.json || {})),
              JSON.stringify(armedOff.json || {}).slice(0, 300));
    assert.ok(recorded > 0, "no STS-AUTHN-0301 row");
  });
  await K.mustSavePolicy(realm, { allowUsernameless: true });
  const screenOn = await K.screen(realm);
  const armedOn = await authnSignin.passkeyOptions(realm.base,
                                                   screenOn.opened);
  check("D2. usernameless ON: offered — the door arms a ceremony",
        function () {
    assert.strictEqual(armedOn.status, 200, armedOn.status + " " +
                       JSON.stringify(armedOn.json || {}).slice(0, 300));
    assert.ok(armedOn.json && armedOn.json.challenge,
              JSON.stringify(armedOn.json || {}).slice(0, 300));
  });
  log.debug("Leaving door().");
}

async function synced() {
  log.debug("Entering synced().");
  log.info("=== E. synced (backup-eligible) passkeys ===");
  const realm = await K.realm("pkpf-e", "development");
  await K.client(realm);
  const client = await portalFor(realm, who("e"));
  const early = K.authenticator({ synced: true });
  const first = await K.enrol(client, early);
  check("E1. #528: allowed by default — a synced passkey registers",
        function () {
    assert.strictEqual(first.done.status, 200, first.done.status + " " +
                       JSON.stringify(first.done.json).slice(0, 300));
  });
  await K.mustSavePolicy(realm, { backupEligibility: "disallow" });
  const at = await refusedWith(realm, "STS-AUTHN-0312", function () {
    return K.enrol(client, K.authenticator({ synced: true }))
      .then(function (e) {
        return { status: e.done.status, raw: JSON.stringify(e.done.json) };
      });
  });
  const later = await refusedWith(realm, "STS-AUTHN-0313", function () {
    return signsIn(realm, early).then(function (a) {
      return { status: a.status, raw: K.said(a), next: a.next };
    });
  });
  const bound = await K.enrol(client, K.authenticator({}));
  check("E2. disallow: a backup-eligible key is refused at registration " +
        "(STS-AUTHN-0312) and the synced key registered before at sign-in " +
        "(STS-AUTHN-0313), each saying why; a device-bound key registers",
        function () {
    assert.ok(at.r.status >= 400, at.r.raw.slice(0, 300));
    assert.ok(/device-bound/.test(at.r.raw), at.r.raw.slice(0, 300));
    assert.ok(at.recorded > 0, "no STS-AUTHN-0312 row");
    assert.notStrictEqual(later.r.next, "redirect", later.r.raw);
    assert.ok(/device-bound/.test(later.r.raw), later.r.raw.slice(0, 300));
    assert.ok(later.recorded > 0, "no STS-AUTHN-0313 row");
    assert.strictEqual(bound.done.status, 200,
                       JSON.stringify(bound.done.json).slice(0, 300));
  });
  const bad = await refusedWith(realm, "STS-API-0009", function () {
    return K.savePolicy(realm, { backupEligibility: "sometimes" });
  });
  check("E3. a value that is neither allow nor disallow is refused, by the " +
        "request schema (STS-API-0009)", function () {
    assert.strictEqual(bad.r.status, 400, bad.r.raw.slice(0, 300));
    assert.ok(bad.recorded > 0, "no STS-API-0009 row");
  });
  log.debug("Leaving synced().");
}

async function pinLength() {
  log.debug("Entering pinLength().");
  log.info("=== F. a minimum security-key PIN length ===");
  const realm = await K.realm("pkpf-f", "development");
  await K.client(realm);
  const on = function (fields) {
    return K.mustSavePolicy(realm, Object.assign({ enforcePinLength: true,
      minPinLength: 6, pinLengthOnlyIfSupported: false }, fields || {}));
  };
  const enrolAs = async function (name, auth) {
    const client = await portalFor(realm, name);
    const e = await K.enrol(client, auth, { kind: "security-key" });
    return e;
  };

  const alice = pinAuthenticator(4);
  const aliceName = who("fa");
  const off = await enrolAs(aliceName, alice);
  const aliceRow = await rowOf(realm, aliceName, alice.credentialId);
  check("F1. OFF BY DEFAULT: the options ask for no minPinLength, and a key " +
        "reporting a minimum PIN of 4 registers", function () {
    assert.strictEqual(off.pending.options.minPinLength, undefined,
                       JSON.stringify(off.pending.options));
    assert.strictEqual(off.done.status, 200,
                       JSON.stringify(off.done.json).slice(0, 300));
    assert.ok(aliceRow, "no row for the key");
  });

  await on();
  const bob = pinAuthenticator(8);
  const bobName = who("fb");
  const bobDone = await enrolAs(bobName, bob);
  const bobRow = await rowOf(realm, bobName, bob.credentialId);
  check("F2. ON (minimum 6): the options ask for minPinLength, and a key " +
        "reporting 8 registers", function () {
    assert.strictEqual(bobDone.pending.options.minPinLength, true,
                       JSON.stringify(bobDone.pending.options));
    assert.strictEqual(bobDone.done.status, 200,
                       JSON.stringify(bobDone.done.json).slice(0, 300));
    assert.ok(bobRow, "no row for the key");
  });
  const carolName = who("fc");
  const carol = await refusedWith(realm, "STS-AUTHN-0314", function () {
    return enrolAs(carolName, pinAuthenticator(4)).then(function (e) {
      return { status: e.done.status, raw: JSON.stringify(e.done.json) };
    });
  });
  const carolKeys = await K.keysOf(realm, carolName);
  check("F3. one reporting 4 is refused (STS-AUTHN-0314), saying why, and " +
        "nothing is written", function () {
    assert.ok(carol.r.status >= 400, carol.r.raw.slice(0, 300));
    assert.ok(/requires at least 6/.test(carol.r.raw), carol.r.raw);
    assert.ok(carol.recorded > 0, "no STS-AUTHN-0314 row");
    assert.strictEqual(carolKeys.length, 0, JSON.stringify(carolKeys));
  });
  const daveName = who("fd");
  const dave = await enrolAs(daveName, pinAuthenticator(null));
  const daveKeys = await K.keysOf(realm, daveName);
  check("F4. and one that reports nothing is refused too", function () {
    assert.ok(dave.done.status >= 400,
              JSON.stringify(dave.done.json).slice(0, 300));
    assert.ok(/did not report its minimum PIN length/.test(
      JSON.stringify(dave.done.json)), JSON.stringify(dave.done.json));
    assert.strictEqual(daveKeys.length, 0, JSON.stringify(daveKeys));
  });

  await on({ pinLengthOnlyIfSupported: true });
  const erin = pinAuthenticator(null);
  const erinName = who("fe");
  const erinDone = await enrolAs(erinName, erin);
  check("F5. pinLengthOnlyIfSupported on: a key that reports nothing " +
        "registers", function () {
    assert.strictEqual(erinDone.done.status, 200,
                       JSON.stringify(erinDone.done.json).slice(0, 300));
  });

  await on({ minPinLength: 10, pinLengthOnlyIfSupported: false });
  const bobTen = await refusedWith(realm, "STS-AUTHN-0315", function () {
    return signsIn(realm, bob).then(function (a) {
      return { status: a.status, raw: K.said(a), next: a.next };
    });
  });
  const erinOff = await signsIn(realm, erin);
  check("F6. AT SIGN-IN, the minimum raised to 10: the key that reported 8 " +
        "does not sign in (STS-AUTHN-0315), saying why; nor does the key " +
        "that reported nothing while pinLengthOnlyIfSupported is off",
        function () {
    assert.notStrictEqual(bobTen.r.next, "redirect", bobTen.r.raw);
    assert.ok(/requires at least 10/.test(bobTen.r.raw),
              bobTen.r.raw.slice(0, 300));
    assert.ok(bobTen.recorded > 0, "no STS-AUTHN-0315 row");
    assert.notStrictEqual(erinOff.next, "redirect", K.said(erinOff));
  });
  await on({ minPinLength: 10, pinLengthOnlyIfSupported: true });
  const erinOn = await signsIn(realm, erin);
  await on({ minPinLength: 8 });
  const bobEight = await signsIn(realm, bob);
  check("F7. the silent key signs in while pinLengthOnlyIfSupported is on, " +
        "and a key that reported exactly the minimum signs in", function () {
    assert.ok(K.redirected(erinOn), K.said(erinOn).slice(0, 300));
    assert.ok(K.redirected(bobEight), K.said(bobEight).slice(0, 300));
  });

  const reset = await K.call(realm, "POST", "/policies/reset-passkey-policy",
                             { profile: "default" });
  const aliceBack = await signsIn(realm, alice);
  const asked = await optionsOf(await portalFor(realm, who("ff")),
                                "security-key");
  check("F8. off again (reset): every key signs in and nothing is asked",
        function () {
    assert.strictEqual(reset.status, 200, reset.raw.slice(0, 300));
    assert.ok(K.redirected(aliceBack), K.said(aliceBack).slice(0, 300));
    assert.strictEqual(asked.minPinLength, undefined, JSON.stringify(asked));
  });
  const low = await K.savePolicy(realm, { enforcePinLength: true,
                                          minPinLength: 3 });
  const high = await K.savePolicy(realm, { enforcePinLength: true,
                                           minPinLength: 64 });
  const edge = await K.savePolicy(realm, { enforcePinLength: true,
                                           minPinLength: 63 });
  check("F9. the minimum is held to 4..63", function () {
    assert.strictEqual(low.status, 400, low.raw.slice(0, 300));
    assert.strictEqual(high.status, 400, high.raw.slice(0, 300));
    assert.strictEqual(edge.status, 200, edge.raw.slice(0, 300));
  });
  log.debug("Leaving pinLength().");
}

async function hints() {
  log.debug("Entering hints().");
  log.info("=== G. the hints each ceremony sends ===");
  const realm = await K.realm("pkpf-g", "development");
  await K.client(realm);
  const client = await portalFor(realm, who("g"));
  const signInHints = async function () {
    const s = await K.screen(realm);
    const armed = await authnSignin.passkeyOptions(realm.base, s.opened);
    const o = (armed.json && (armed.json.options || armed.json)) || {};
    return JSON.stringify(o.hints === undefined ? null : o.hints);
  };
  const passkey = await optionsOf(client, "passkey");
  const key = await optionsOf(client, "security-key");
  const signIn = await signInHints();
  check("G1. #531: the defaults are what each ceremony sent before",
        function () {
    assert.strictEqual(JSON.stringify(passkey.hints),
                       '["client-device","hybrid"]');
    assert.strictEqual(JSON.stringify(key.hints), '["security-key"]');
    assert.ok(signIn === "null" || signIn === "[]", signIn);
  });
  await K.mustSavePolicy(realm, { passkeyHints: "hybrid, client-device",
    securityKeyHints: "none", signInHints: "security-key,hybrid" });
  const passkey2 = await optionsOf(client, "passkey");
  const key2 = await optionsOf(client, "security-key");
  const signIn2 = await signInHints();
  check("G2. a list reaches its ceremony in its order; none sends none",
        function () {
    assert.strictEqual(JSON.stringify(passkey2.hints),
                       '["hybrid","client-device"]');
    assert.ok(!key2.hints || key2.hints.length === 0,
              JSON.stringify(key2.hints));
    assert.strictEqual(signIn2, '["security-key","hybrid"]');
  });
  const contra = await refusedWith(realm, "STS-AUTHN-0309", function () {
    return K.savePolicy(realm,
                        { securityKeyHints: "security-key,client-device" });
  });
  const twice = await K.savePolicy(realm, { passkeyHints: "hybrid,hybrid" });
  const unknown = await K.savePolicy(realm, { signInHints: "usb" });
  check("G3. client-device on \"Use a security key\" (cross-platform) is " +
        "refused with the reason (STS-AUTHN-0309); a hint twice, or one " +
        "that is not a hint, is refused", function () {
    assert.strictEqual(contra.r.status, 400, contra.r.raw.slice(0, 300));
    assert.ok(/client-device contradicts.*cross-platform/.test(
      errorsOf(contra.r)), errorsOf(contra.r));
    assert.ok(contra.recorded > 0, "no STS-AUTHN-0309 row");
    assert.strictEqual(twice.status, 400, twice.raw.slice(0, 300));
    assert.strictEqual(unknown.status, 400, unknown.raw.slice(0, 300));
  });
  log.debug("Leaving hints().");
}

// The mechanisms are a named authentication policy's (#1148), one per
// client.
async function passkeyOnlyClient(realm, id, mechanisms) {
  log.debug("Entering passkeyOnlyClient(). " + id);
  const saved = await K.call(realm, "POST",
    "/policies/save-named-authn-policy",
    { name: "p-" + id, description: "sts_passkey_policy_profile",
      mechanisms: mechanisms,
      secondFactors: ["password", "securityKey", "totp", "recoveryCode"],
      precedence: 50 + mechanisms.length });
  assert.strictEqual(saved.status, 200, saved.raw.slice(0, 300));
  await fixtures.publicClient(realm.api, id, [K.REDIRECT]);
  const pointed = await K.call(realm, "POST", "/applications/set",
    { application: id, attribute: "appAuthnPolicy", value: "p-" + id });
  assert.strictEqual(pointed.status, 200, pointed.raw.slice(0, 300));
  log.debug("Leaving passkeyOnlyClient().");
}

async function requireUsernameless() {
  log.debug("Entering requireUsernameless().");
  log.info("=== H. a sign-in with no username, required ===");
  const realm = await K.realm("pkpf-h", "development");
  await passkeyOnlyClient(realm, "pru-passkey", ["webauthn"]);
  await passkeyOnlyClient(realm, "pru-mixed", ["webauthn", "password"]);
  const first = await K.screen(realm, null, "pru-passkey");
  check("H1. off by default: the passkey-only application's screen asks " +
        "for a username as before", function () {
    assert.strictEqual(first.view.passkey, true, JSON.stringify(first.view)
      .slice(0, 300));
    assert.strictEqual(first.view.usernameless, false);
  });
  const bad = await K.savePolicy(realm, { allowUsernameless: false,
                                          requireUsernameless: true });
  check("H2. a save requiring a usernameless sign-in that does not allow " +
        "one is refused", function () {
    assert.strictEqual(bad.status, 400, bad.raw.slice(0, 300));
    assert.ok(/requireUsernameless/.test(errorsOf(bad)), errorsOf(bad));
  });
  await K.mustSavePolicy(realm, { allowUsernameless: true,
                                  requireUsernameless: true });
  const s = await K.screen(realm, null, "pru-passkey");
  check("H3. on: an application signing in with a passkey alone gets a " +
        "view asking for no username", function () {
    assert.strictEqual(s.view.usernameless, true,
                       JSON.stringify(s.view).slice(0, 300));
    assert.strictEqual(s.view.passkey, true);
  });
  const posted = await refusedWith(realm, "STS-AUTHN-0333", function () {
    return authnSignin.act(realm.base, "/authn-api/pending/" +
      encodeURIComponent(s.opened.id) + "/password",
      { username: who("hsomebody"), webauthn_only: "1" },
      { cookie: s.opened.cookie, csrf: s.opened.csrf, headers: K.BROWSER })
      .then(function (a) {
        return { status: a.status, raw: a.text, next: a.next };
      });
  });
  const mixed = await K.screen(realm, null, "pru-mixed");
  check("H4. a sign-in naming a person is refused (STS-AUTHN-0333), and an " +
        "application allowing a password too keeps its username field",
        function () {
    assert.strictEqual(posted.r.status, 400, posted.r.raw.slice(0, 300));
    assert.strictEqual(posted.r.next, "refused", posted.r.raw.slice(0, 300));
    assert.ok(posted.recorded > 0, "no STS-AUTHN-0333 row");
    assert.strictEqual(mixed.view.usernameless, false,
                       JSON.stringify(mixed.view).slice(0, 300));
  });
  log.debug("Leaving requireUsernameless().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving the passkey policy's profile at " + K.root);
  await builtIn();
  await saves();
  await answers();
  await door();
  await synced();
  await pinLength();
  await hints();
  await requireUsernameless();
  log.debug("Leaving test().");
}

K.main(test);
