// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: sts_webauthn_u2f_import.js
//
// ===========================================================================
// LEGACY U2F CREDENTIALS AND credProtect, OVER THE WIRE (#1955 P7).
//
//   A. OFF BY DEFAULT: an import is refused while webauthn.u2fAppIds is
//      empty (STS-AUTHN-0561), and an AppID that is not https is refused at
//      the setting's write (STS-AUTHN-0566).
//   B. THE IMPORT: listed, a U2F key (made here: a P-256 pair, a key handle)
//      is imported through POST /admin-api/users/import-u2f-key and listed
//      on the person with its AppID.
//   C. THE SECOND FACTOR: a password sign-in's passkey step names the key,
//      asks the `appid` extension and `preferred` user verification; a
//      U2F-style assertion over SHA-256 of the AppID signs in when the
//      client says `appid: true`, and is refused (STS-AUTHN-0031) when it
//      does not.
//   D. NOT A WAY IN ON ITS OWN: a passwordless step offers a registration
//      instead, which asks `appidExclude` with the imported key handle in
//      its exclude list.
//   E. credProtect: a profile asking level 3 and enforcing it sends the
//      client extension inputs, and refuses a key that reports none
//      (STS-AUTHN-0559).
//
// Every key is made when the job runs; nothing here is key material.
// ===========================================================================

const assert = require("assert");
const nodeCrypto = require("crypto");
const { Command, Option } = require("commander");
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
var log = bunyan.createLogger({ name: "sts_webauthn_u2f_import",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const k = wire.kit("sts_webauthn_u2f_import", { log: log });
const check = k.check;
const PASSWORD = "U2f-Import-" + k.STAMP + "-correct-9!";
const APP_ID = "https://" + k.RP_ID + "/u2f/app-id.json";

/**
 * A U2F key: a P-256 pair, a 64-byte key handle, and the public key as the
 * uncompressed point a U2F relying party kept.
 *
 * @returns {object} the key
 */
function u2fKey() {
  log.debug("Entering u2fKey().");
  const pair = nodeCrypto.generateKeyPairSync("ec",
                                              { namedCurve: "prime256v1" });
  const jwk = pair.publicKey.export({ format: "jwk" });
  const point = Buffer.concat([Buffer.from([0x04]),
                               Buffer.from(jwk.x, "base64url"),
                               Buffer.from(jwk.y, "base64url")]);
  log.debug("Leaving u2fKey().");
  return { pair: pair, counter: 41,
           handle: nodeCrypto.randomBytes(64).toString("base64url"),
           point: point.toString("base64url") };
}

/**
 * The assertion a browser running a U2F key under the appid extension
 * posts: the authenticator data over SHA-256 of the AppID, UP alone, the
 * counter, an ES256 signature, and the extension outputs `results`.
 *
 * @param {object} key - from `u2fKey()`
 * @param {string} challenge - the step's challenge
 * @param {object} results - the client extension results
 * @returns {object} the credential's JSON form
 */
function u2fAssertion(key, challenge, results) {
  log.debug("Entering u2fAssertion().");
  key.counter += 1;
  const count = Buffer.alloc(4);
  count.writeUInt32BE(key.counter, 0);
  const authData = Buffer.concat([k.sha256(Buffer.from(APP_ID, "utf8")),
                                  Buffer.from([0x01]), count]);
  const cdj = Buffer.from(JSON.stringify({ type: "webauthn.get",
    challenge: challenge, origin: k.ORIGIN, crossOrigin: false }));
  const signature = nodeCrypto.sign("sha256",
    Buffer.concat([authData, k.sha256(cdj)]), key.pair.privateKey);
  log.debug("Leaving u2fAssertion().");
  return { id: key.handle, rawId: key.handle, type: "public-key",
           authenticatorAttachment: "cross-platform",
           clientExtensionResults: results,
           response: { authenticatorData: authData.toString("base64url"),
                       clientDataJSON: cdj.toString("base64url"),
                       signature: signature.toString("base64url"),
                       userHandle: null } };
}

async function u2f() {
  log.debug("Entering u2f().");
  log.info("=== A-D. a legacy U2F key, imported and used ===");
  const realm = await k.realm("u2f", "development");
  await k.client(realm);
  const name = "u2f-person-" + k.STAMP;
  await k.person(realm, name, PASSWORD);
  const key = u2fKey();
  const body = { user: name, appId: APP_ID, keyHandle: key.handle,
                 publicKey: key.point, counter: key.counter,
                 label: "Old office key" };

  let before = await k.codeCount(realm, "STS-AUTHN-0561");
  const off = await k.call(realm, "POST", "/users/import-u2f-key", body);
  const offRows = await k.newCodes(realm, "STS-AUTHN-0561", before);
  before = await k.codeCount(realm, "STS-AUTHN-0566");
  const plainHttp = await k.setting(realm, "webauthn.u2fAppIds",
                                    "http://" + k.RP_ID + "/app-id.json");
  const httpRows = await k.newCodes(realm, "STS-AUTHN-0566", before);
  check("A. off by default: the import is refused (STS-AUTHN-0561), and an " +
        "AppID that is not https is refused at the write (STS-AUTHN-0566)",
        function () {
    assert.strictEqual(off.status, 400, off.raw.slice(0, 300));
    assert.ok(offRows > 0, "no STS-AUTHN-0561 row");
    assert.ok(plainHttp.status >= 400, plainHttp.raw.slice(0, 300));
    assert.ok(httpRows > 0, "no STS-AUTHN-0566 row");
  });

  await k.mustSet(realm, "webauthn.u2fAppIds", APP_ID);
  const imported = await k.call(realm, "POST", "/users/import-u2f-key", body);
  const listed = (await k.keysOf(realm, name)).filter(function (one) {
    return one.credentialId === key.handle;
  })[0] || {};
  check("B. listed, the key is imported and listed with its AppID",
        function () {
    assert.strictEqual(imported.status, 200, imported.raw.slice(0, 300));
    assert.strictEqual(listed.appid, APP_ID, JSON.stringify(listed));
  });

  let armedOptions = null;
  let allowed = [];
  const t = await k.typed(realm, name, { password: PASSWORD });
  assert.ok(t.step, "the password sign-in reached no passkey step: " +
    k.said(t.answer).slice(0, 300));
  const done = await k.ceremony(t.step, function (c) {
    armedOptions = c.options || {};
    allowed = c.allow || [];
    return u2fAssertion(key, c.challenge, { appid: true });
  });
  check("C1. the second-factor step names the key, asks the appid " +
        "extension and preferred user verification; an assertion over the " +
        "AppID's hash with appid true signs in", function () {
    assert.strictEqual(armedOptions.appid, APP_ID,
                       JSON.stringify(armedOptions));
    assert.strictEqual(armedOptions.userVerification, "preferred",
                       JSON.stringify(armedOptions));
    assert.ok(allowed.indexOf(key.handle) >= 0, JSON.stringify(allowed));
    assert.strictEqual(done.next, "redirect", k.said(done).slice(0, 400));
  });

  before = await k.codeCount(realm, "STS-AUTHN-0031");
  const t2 = await k.typed(realm, name, { password: PASSWORD });
  const notSaid = await k.ceremony(t2.step, function (c) {
    return u2fAssertion(key, c.challenge, {});
  });
  const hashRows = await k.newCodes(realm, "STS-AUTHN-0031", before);
  check("C2. the same assertion without appid true is held to the RP ID's " +
        "hash and refused (STS-AUTHN-0031)", function () {
    assert.notStrictEqual(notSaid.next, "redirect",
                          k.said(notSaid).slice(0, 300));
    assert.ok(hashRows > 0, "no STS-AUTHN-0031 row");
  });

  let created = null;
  const t3 = await k.typed(realm, name, {});
  if (t3.step) {
    await k.ceremony(t3.step, function (c) {
      created = c;
      return { error: "NotAllowedError" };
    });
  }
  check("D. a passwordless step never offers the U2F key: it offers a " +
        "registration, which asks appidExclude and excludes the key handle",
        function () {
    assert.ok(created, "no ceremony was armed: " +
              k.said(t3.answer).slice(0, 300));
    assert.strictEqual(created.mode, "create", JSON.stringify(created));
    assert.strictEqual((created.options || {}).appidExclude, APP_ID,
                       JSON.stringify(created.options));
    assert.ok((created.exclude || []).indexOf(key.handle) >= 0,
              JSON.stringify(created.exclude));
  });
  log.debug("Leaving u2f().");
}

async function credProtect() {
  log.debug("Entering credProtect().");
  log.info("=== E. credProtect asked and enforced ===");
  const realm = await k.realm("credprot", "development");
  await k.client(realm);
  await k.mustSavePolicy(realm, { credProtect: "userVerificationRequired",
                                  enforceCredProtect: true });
  const name = "cp-person-" + k.STAMP;
  await k.person(realm, name, PASSWORD);
  const auth = k.authenticator({});
  let options = null;
  const before = await k.codeCount(realm, "STS-AUTHN-0559");
  const t = await k.typed(realm, name, {});
  assert.ok(t.step, "the passwordless sign-in reached no step: " +
    k.said(t.answer).slice(0, 300));
  const done = await k.ceremony(t.step, function (c) {
    options = c.options || {};
    return auth.register(c.challenge, c.user && c.user.id, c.rpId);
  });
  const rows = await k.newCodes(realm, "STS-AUTHN-0559", before);
  check("E. the registration asks credProtect level 3, enforced, and a key " +
        "that reports none is refused (STS-AUTHN-0559)", function () {
    assert.deepStrictEqual(options.credProtect,
      { credentialProtectionPolicy: "userVerificationRequired",
        enforceCredentialProtectionPolicy: true },
      JSON.stringify(options));
    assert.notStrictEqual(done.next, "redirect", k.said(done).slice(0, 300));
    assert.ok(rows > 0, "no STS-AUTHN-0559 row");
  });
  log.debug("Leaving credProtect().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving legacy U2F credentials and credProtect at " + k.root);
  await u2f();
  await credProtect();
  assert.ok(k.checks() >= 6, "only " + k.checks() + " checks ran; a " +
            "section has stopped being called.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_webauthn_u2f_import")
  .description("Legacy U2F credentials imported and used with the appid " +
      "extension, appidExclude, and credProtect enforced (#1955 P7).")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

k.main(test);
