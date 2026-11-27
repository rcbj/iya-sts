// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: sts_oath_oathtool.js
//
// ---------------------------------------------------------------------------
// IMPORTED OATH TOKENS WITH oathtool (#2062, umbrella #2055). rcbj's
// "realistic tests": every code a person types comes from `oathtool`
// (OATH Toolkit), in the client lab (tests/CLAUDE.md, *THE CLIENT LAB*),
// from the seed the vendor's file carries, as a hardware token computes it.
// sts_oath_tokens.js imports and assigns with codes made in node; here the
// person CLAIMS the token and SIGNS IN with it.
//
//   a. the administrator imports a PSKC file (RFC 6030) made in the run: an
//      HOTP and a TOTP token in one container, the seeds sealed under a
//      pre-shared key (AES-128-CBC, HMAC-SHA1, section 6.1), as a vendor
//      ships them;
//   b. each person claims one on the portal's operation, as
//      /portal/tokens-and-keys does (POST /account-api/tokens, `claim`,
//      the serial printed on it and a code it shows now, from oathtool);
//      a wrong code is refused; the token is on the person's entry
//      (stsOathToken), read with ldapsearch over LDAPS, with no seed;
//   c. HOTP at /authn: the password, then oathtool's next code signs in;
//      the same code again is refused; a code two presses ahead (inside
//      the look-ahead) signs in and moves the counter, and the code it
//      skipped is then refused;
//   d. TOTP at /authn: the code the claim spent is refused at sign-in; at
//      the next time step oathtool's code signs in, and is refused again;
//   e. reported lost, by the person on the portal (HOTP) and by the
//      administrator through /admin-api (TOTP), each by the key the PSKC
//      import answered (#2095): the next code the token would show signs
//      nobody in.
//
// The realm runs in the stack's mode, with the hotp row of its
// authentication policy on. Every seed and key is drawn in the run.
// `local: true`, `clientLab: true`: SKIPPED by the runner where there is
// no CLIENT_LAB_URL.
// ---------------------------------------------------------------------------

"use strict";

const assert = require("assert");
const nodeCrypto = require("crypto");
const fs = require("fs");
const lab = require("./client_lab.js");
const names = require("./random_username.js");
const portal = require("./portal_signin.js");
const authnSignin = require("./authn_signin.js");
const ownPassword = require("./own_password");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand run without one still
  // loads.
  appconfigProblem = e;
  appconfig = {};
}
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_oath_oathtool",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const LAB_BASE = String(process.env.CLIENT_LAB_STS_URL || base)
  .replace(/\/+$/, "");
const STAMP = names.runStamp().toLowerCase().replace(/[^a-z0-9]/g, "")
  .slice(-10);
const REALM = "oath" + STAMP;
const DOMAIN = REALM + ".example.net";
const HOLDER_H = ("oh" + STAMP).slice(0, 24);
const HOLDER_T = ("ot" + STAMP).slice(0, 24);
const ADMIN = ("oa" + STAMP).slice(0, 24);
const PASSWORD = "Oath-Tool-Key9!xQ";
const DIR = "oath-" + STAMP;
const STEP = 30;
const ENC = "http://www.w3.org/2001/04/xmlenc#aes128-cbc";

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function pause(ms) {
  log.debug("Entering pause().");
  log.debug("Leaving pause().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

async function send(url, options) {
  log.debug("Entering send().");
  const response = await fetch(url, Object.assign({ redirect: "manual" },
                                                   options || {}));
  const raw = await response.text();
  let body = null;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in send(): " + ((e && e.message) || e));
    // Not JSON. The caller reads raw.
    body = null;
  }
  log.debug("Leaving send(). " + response.status);
  return { status: response.status, body: body, raw: raw };
}

function postJson(url, payload) {
  log.debug("Entering postJson().");
  log.debug("Leaving postJson().");
  return send(url, { method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload || {}) });
}

async function ok(url, payload, what) {
  log.debug("Entering ok().");
  const response = await postJson(url, payload);
  assert.ok(response.status >= 200 && response.status < 300 &&
            response.body && response.body.ok !== false,
            "POST " + url + " should have " + what + "; it answered " +
            response.status + " " + String(response.raw).slice(0, 300));
  log.debug("Leaving ok().");
  return response.body;
}

// ---------------------------------------------------------------------------
// THE VENDOR'S FILE: RFC 6030, the seeds and the MAC key encrypted under a
// pre-shared key, each encrypted value MACed (section 6.1).
// ---------------------------------------------------------------------------
function cbc(key, plain) {
  log.debug("Entering cbc().");
  const iv = nodeCrypto.randomBytes(16);
  const c = nodeCrypto.createCipheriv("aes-128-cbc", key, iv);
  const out = Buffer.concat([iv, c.update(plain), c.final()]);
  log.debug("Leaving cbc().");
  return out;
}

function keyPackage(token, preShared, macKey, id) {
  log.debug("Entering keyPackage(). " + token.kind);
  const sealed = cbc(preShared, token.seed);
  const mac = nodeCrypto.createHmac("sha1", macKey).update(sealed)
    .digest("base64");
  const moving = token.kind === "hotp"
    ? "<Counter><PlainValue>0</PlainValue></Counter>"
    : "<Time><PlainValue>0</PlainValue></Time><TimeInterval><PlainValue>" +
      STEP + "</PlainValue></TimeInterval>";
  log.debug("Leaving keyPackage().");
  return "<KeyPackage><DeviceInfo><Manufacturer>Lab Tokens</Manufacturer>" +
    "<SerialNo>" + token.serial + "</SerialNo><Model>" +
    token.kind.toUpperCase() + " fob</Model></DeviceInfo>\n" +
    "<Key Id=\"" + id + "\" Algorithm=\"urn:ietf:params:xml:ns:keyprov:" +
    "pskc:" + token.kind + "\">" +
    "<AlgorithmParameters><ResponseFormat Length=\"6\" " +
    "Encoding=\"DECIMAL\"/></AlgorithmParameters>" +
    "<Data><Secret><EncryptedValue><xenc:EncryptionMethod Algorithm=\"" +
    ENC + "\"/><xenc:CipherData><xenc:CipherValue>" +
    sealed.toString("base64") + "</xenc:CipherValue></xenc:CipherData>" +
    "</EncryptedValue><ValueMAC>" + mac + "</ValueMAC></Secret>" + moving +
    "</Data></Key></KeyPackage>";
}

function pskcFile(tokens, preShared) {
  log.debug("Entering pskcFile().");
  const macKey = nodeCrypto.randomBytes(20);
  const sealedMac = cbc(preShared, macKey);
  const xml = [
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
    "<KeyContainer Version=\"1.0\" " +
      "xmlns=\"urn:ietf:params:xml:ns:keyprov:pskc\" " +
      "xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" " +
      "xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\">",
    "<EncryptionKey><ds:KeyName>lab-transport-key</ds:KeyName>" +
      "</EncryptionKey>",
    "<MACMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#hmac-sha1\">" +
      "<MACKey><xenc:EncryptionMethod Algorithm=\"" + ENC + "\"/>" +
      "<xenc:CipherData><xenc:CipherValue>" + sealedMac.toString("base64") +
      "</xenc:CipherValue></xenc:CipherData></MACKey></MACMethod>"
  ].concat(tokens.map(function (t, i) {
    return keyPackage(t, preShared, macKey, i + 1);
  })).concat(["</KeyContainer>"]).join("\n");
  log.debug("Leaving pskcFile().");
  return xml;
}

// ---------------------------------------------------------------------------
// THE TOKEN: oathtool, from the seed, as the fob computes the code it shows.
// ---------------------------------------------------------------------------
async function hotpCode(token, counter) {
  log.debug("Entering hotpCode(). " + counter);
  const r = await lab.must("oathtool", ["--hotp", "--digits=6",
    "--counter=" + counter, token.seed.toString("hex")]);
  log.debug("Leaving hotpCode().");
  return String(r.stdout).trim();
}

async function totpCode(token, at) {
  log.debug("Entering totpCode(). " + at);
  const r = await lab.must("oathtool", ["--totp", "--digits=6",
    "--time-step-size=" + STEP + "s", "--now=@" + Math.floor(at),
    token.seed.toString("hex")]);
  log.debug("Leaving totpCode().");
  return String(r.stdout).trim();
}

// The start of the time step `at` (seconds) is in, and of the one after.
function stepOf(at) {
  log.debug("Entering stepOf().");
  log.debug("Leaving stepOf().");
  return Math.floor(at / STEP) * STEP;
}

// WAIT FOR A FRESH STEP so a code is not computed in one step and checked
// in the next: the sign-in takes a few seconds, and in product totp.window
// is 0.
async function earlyInAStep() {
  log.debug("Entering earlyInAStep().");
  const now = Date.now() / 1000;
  if (now - stepOf(now) > STEP - 12) {
    await pause((stepOf(now) + STEP - now + 1) * 1000);
  }
  log.debug("Leaving earlyInAStep().");
  return Date.now() / 1000;
}

// ---------------------------------------------------------------------------
// THE SIGN-IN, as a browser walks it: the portal's authorization request to
// /authn's screen, the password, and the one-time code step.
// ---------------------------------------------------------------------------
function b64url(buf) {
  log.debug("Entering b64url().");
  log.debug("Leaving b64url().");
  return Buffer.from(buf).toString("base64url");
}

async function signInWithCode(rb, username, code) {
  log.debug("Entering signInWithCode(). " + username);
  const shell = await fetch(rb + "/portal", { redirect: "manual" });
  await shell.text();
  const verifier = b64url(nodeCrypto.randomBytes(32));
  const authorize = rb + "/oauth2/authorize?" + new URLSearchParams({
    response_type: "code", client_id: "sts-user-portal",
    redirect_uri: rb + "/portal/callback", scope: "openid account:manage",
    state: b64url(nodeCrypto.randomBytes(16)),
    code_challenge: b64url(nodeCrypto.createHash("sha256").update(verifier)
      .digest()),
    code_challenge_method: "S256", resource: rb + "/account-api" })
    .toString();
  const r = await fetch(authorize, { redirect: "manual" });
  await r.text();
  const login = new URL(String(r.headers.get("location") || ""), rb)
    .toString();
  assert.ok(/\/authn\/login/.test(login), "the authorization request did " +
            "not reach the sign-in screen: " + r.status + " " + login);
  const answer = await authnSignin.signIn(rb, login,
    { action: "login", username: username, password: PASSWORD }, {});
  if (answer.next !== "mfa") {
    log.debug("Leaving signInWithCode(). No code step: " + answer.next);
    return { codeStep: false, next: answer.next, answer: answer };
  }
  const opened = await authnSignin.step(answer.location,
                                        { cookie: answer.cookie });
  const done = await authnSignin.stepAct(opened, "totp", { code: code });
  log.debug("Leaving signInWithCode(). " + done.next);
  return { codeStep: true, next: done.next, answer: done };
}

function signedIn(attempt) {
  log.debug("Entering signedIn().");
  const yes = attempt.codeStep && attempt.next === "redirect";
  log.debug("Leaving signedIn(). " + yes);
  return yes;
}

function ldapsUrl() {
  log.debug("Entering ldapsUrl().");
  log.debug("Leaving ldapsUrl().");
  return process.env.CLIENT_LAB_LDAPS_URL ||
    ("ldaps://" + new URL(LAB_BASE).hostname + ":" +
     (process.env.STS_LDAPS_PORT || 636));
}

async function entryTokens(adminDn, dn) {
  log.debug("Entering entryTokens().");
  const answer = await lab.must("ldapsearch", ["-LLL", "-o", "ldif-wrap=no",
    "-H", ldapsUrl(), "-D", adminDn, "-w", PASSWORD, "-b", dn, "-s", "base",
    "(objectClass=*)", "stsOathToken"],
    { env: { LDAPTLS_CACERT: lab.work(DIR + "/anchor.pem"),
             LDAPTLS_REQCERT: "demand" } });
  const values = [];
  String(answer.stdout).split("\n").forEach(function (line) {
    const plain = /^stsOathToken: (.*)$/i.exec(line);
    const coded = /^stsOathToken:: (.*)$/i.exec(line);
    if (plain) {
      values.push(plain[1]);
    } else if (coded) {
      values.push(Buffer.from(coded[1], "base64").toString("utf8"));
    }
  });
  log.debug("Leaving entryTokens(). " + values.length);
  return values;
}

async function setUp() {
  log.debug("Entering setUp().");
  await ok(base + "/admin-api/realms/create", { id: REALM, domain: DOMAIN,
    name: "OATH tokens with oathtool " + STAMP, overrides: {
      // A product realm requires a second factor of everybody, and the
      // people here sign in to the portal with a password before the token
      // they claim is theirs; the administrator binds over LDAP.
      "authn.allowOptionalSecondFactor": "true",
      "risk.assessSignIns": "false" } },
    "created the realm " + REALM);
  const rb = base + "/realm/" + REALM;
  const dns = {};
  for (const who of [HOLDER_H, HOLDER_T, ADMIN]) {
    dns[who] = String((await ok(rb + "/admin-api/users/create", {
      username: who, invent: false, credential: "password",
      password: ownPassword.temporaryFor(PASSWORD),
      attributes: { cn: "Oath " + who, sn: who, givenName: "Oath",
                    mail: who + "@" + DOMAIN } }, "created " + who)).dn);
    // Temporary, then the person's own (#2160, `own_password.js`): the
    // holders sign in and the administrator binds with PASSWORD.
    await ownPassword.ownPassword(rb, who, PASSWORD, function (one, value) {
      return postJson(rb + "/admin-api/users/set-password",
                      { user: one, password: value });
    });
  }
  await ok(rb + "/admin-api/rbac/grant", { username: ADMIN, role: "read" },
           "granted " + ADMIN + " Admin Read on the realm's roster");
  // The hotp row is off by default; an imported HOTP token is claimed
  // only where it is on.
  const policies = await send(rb + "/admin-api/policies");
  assert.strictEqual(policies.status, 200, policies.raw.slice(0, 300));
  await ok(rb + "/admin-api/policies/save-authn-policy",
           Object.assign({ profile: "default" }, policies.body.authn.defaults,
                         { hotpSecondFactor: true }),
           "turned the hotp row on");
  log.debug("Leaving setUp().");
  return { rb: rb, dns: dns };
}

async function test() {
  log.debug("Entering test().");
  log.info("OATH tokens with oathtool, realm " + REALM);
  await lab.ready(180000);
  const anchorFile = process.env.NODE_EXTRA_CA_CERTS || "";
  assert.ok(anchorFile && fs.existsSync(anchorFile), "the job needs the " +
            "service's TLS anchor in NODE_EXTRA_CA_CERTS");
  await lab.put(DIR + "/anchor.pem", fs.readFileSync(anchorFile));
  const s = await setUp();
  const rb = s.rb;
  // On the portal before the tokens are theirs: once claimed, the sign-in
  // asks for a code, which portal_signin.js's password walk does not give.
  const holderH = await portal.signInToThePortal(rb, HOLDER_H, log,
                                                 { password: PASSWORD });
  const holderT = await portal.signInToThePortal(rb, HOLDER_T, log,
                                                 { password: PASSWORD });

  log.info("=== a. the vendor's PSKC file, imported ===");
  const hotp = { kind: "hotp", serial: "LH" + STAMP.toUpperCase(),
                 seed: nodeCrypto.randomBytes(20) };
  const totp = { kind: "totp", serial: "LT" + STAMP.toUpperCase(),
                 seed: nodeCrypto.randomBytes(20) };
  const preShared = nodeCrypto.randomBytes(16);
  const imported = await ok(rb + "/admin-api/hardware-tokens/import-pskc",
    { pskc: pskcFile([hotp, totp], preShared),
      preSharedKey: preShared.toString("hex") },
    "imported the PSKC file");
  const keyOf = {};
  (imported.imported || []).forEach(function (one) {
    keyOf[String(one.serial)] = one.key;
  });
  check("the administrator imports one PSKC file holding an HOTP and a " +
        "TOTP token, and no answer carries a seed", function () {
    assert.ok(keyOf[hotp.serial] && keyOf[totp.serial],
              JSON.stringify(imported).slice(0, 400));
    const text = JSON.stringify(imported);
    assert.ok(text.indexOf(hotp.seed.toString("hex")) < 0 &&
              text.indexOf(totp.seed.toString("base64")) < 0);
  });

  log.info("=== b. each person claims theirs on the portal ===");
  const wrong = await holderH.api("POST", "/account-api/tokens",
    { action: "claim", serial: hotp.serial,
      code: String((Number(await hotpCode(hotp, 0)) + 1) % 1000000)
        .padStart(6, "0") });
  const claimH = await holderH.api("POST", "/account-api/tokens",
    { action: "claim", serial: hotp.serial, code: await hotpCode(hotp, 0) });
  const claimedAt = await earlyInAStep();
  const claimT = await holderT.api("POST", "/account-api/tokens",
    { action: "claim", serial: totp.serial,
      code: await totpCode(totp, claimedAt) });
  const onH = await entryTokens(s.dns[ADMIN], s.dns[HOLDER_H]);
  const onT = await entryTokens(s.dns[ADMIN], s.dns[HOLDER_T]);
  check("a wrong code is refused; with oathtool's code each person claims " +
        "the token by its serial, and it is on their entry in " +
        "stsOathToken, with no seed", function () {
    assert.notStrictEqual(wrong.status, 200, String(wrong.text)
      .slice(0, 300));
    assert.strictEqual(claimH.status, 200, String(claimH.text)
      .slice(0, 300));
    assert.strictEqual(claimT.status, 200, String(claimT.text)
      .slice(0, 300));
    for (const pair of [[onH, hotp], [onT, totp]]) {
      assert.strictEqual(pair[0].length, 1, JSON.stringify(pair[0]));
      const value = JSON.parse(pair[0][0]);
      assert.strictEqual(String(value.serial), pair[1].serial, pair[0][0]);
      assert.strictEqual(value.kind, pair[1].kind, pair[0][0]);
      assert.ok(pair[0][0].indexOf(pair[1].seed.toString("hex")) < 0 &&
                pair[0][0].indexOf(pair[1].seed.toString("base64")) < 0);
    }
  });

  // AND THE ADMINISTRATOR REQUIRES A SECOND FACTOR OF BOTH, as they would
  // of somebody they handed a token: so once the token is lost, no
  // password alone signs either of them in, and what (e) asks is whether
  // the token's code still can.
  for (const who of [HOLDER_H, HOLDER_T]) {
    await ok(rb + "/admin-api/users/require-mfa", { username: who },
             "required a second factor of " + who);
  }

  log.info("=== c. HOTP at /authn ===");
  const c1 = await hotpCode(hotp, 1);
  const h1 = await signInWithCode(rb, HOLDER_H, c1);
  const h1again = await signInWithCode(rb, HOLDER_H, c1);
  const h3 = await signInWithCode(rb, HOLDER_H, await hotpCode(hotp, 3));
  const h2 = await signInWithCode(rb, HOLDER_H, await hotpCode(hotp, 2));
  check("the password and oathtool's next code sign in; the same code " +
        "again is refused; a code two presses ahead signs in, and the one " +
        "it skipped is then refused", function () {
    assert.ok(signedIn(h1), JSON.stringify(h1).slice(0, 400));
    assert.ok(h1again.codeStep && !signedIn(h1again),
              JSON.stringify(h1again).slice(0, 400));
    assert.ok(signedIn(h3), JSON.stringify(h3).slice(0, 400));
    assert.ok(h2.codeStep && !signedIn(h2), JSON.stringify(h2).slice(0, 400));
  });

  log.info("=== d. TOTP at /authn ===");
  const spent = await signInWithCode(rb, HOLDER_T,
                                     await totpCode(totp, claimedAt));
  const nextStep = stepOf(claimedAt) + STEP;
  const wait = nextStep + 1 - Date.now() / 1000;
  if (wait > 0) {
    log.info("  waiting " + Math.ceil(wait) + " s for the next time step");
    await pause(wait * 1000);
  }
  const fresh = await totpCode(totp, Date.now() / 1000);
  const t1 = await signInWithCode(rb, HOLDER_T, fresh);
  const t1again = await signInWithCode(rb, HOLDER_T, fresh);
  check("the code the claim spent is refused at sign-in; at the next step " +
        "oathtool's code signs in, and is refused the second time",
        function () {
    assert.ok(spent.codeStep && !signedIn(spent),
              JSON.stringify(spent).slice(0, 400));
    assert.ok(signedIn(t1), JSON.stringify(t1).slice(0, 400));
    assert.ok(t1again.codeStep && !signedIn(t1again),
              JSON.stringify(t1again).slice(0, 400));
  });

  log.info("=== e. reported lost ===");
  // THE KEY THE IMPORT ANSWERED (#2095), `<vendor>/<serial>/<key id>`,
  // and nothing else: the lost act takes it as well as the register's
  // `<vendor>/<serial>`, so a caller holding only the import's answer can
  // report the token lost, on the portal and through /admin-api alike.
  const lostH = await holderH.api("POST", "/account-api/tokens",
    { action: "lost", key: keyOf[hotp.serial] });
  const lostT = await postJson(rb + "/admin-api/hardware-tokens/lost",
                               { key: keyOf[totp.serial] });
  const afterH = await signInWithCode(rb, HOLDER_H, await hotpCode(hotp, 4));
  await earlyInAStep();
  const afterT = await signInWithCode(rb, HOLDER_T,
                                      await totpCode(totp, Date.now() / 1000));
  const retiredH = await entryTokens(s.dns[ADMIN], s.dns[HOLDER_H]);
  check("reported lost on the portal and through /admin-api, the next " +
        "code each token would show signs nobody in, and the HOTP " +
        "holder's entry records the token retired", function () {
    assert.strictEqual(lostH.status, 200, String(lostH.text).slice(0, 300));
    assert.strictEqual(lostT.status, 200, lostT.raw.slice(0, 300));
    for (const after of [afterH, afterT]) {
      assert.ok(!signedIn(after) && after.next !== "redirect",
                JSON.stringify(after).slice(0, 400));
    }
    assert.strictEqual(retiredH.length, 1, JSON.stringify(retiredH));
    assert.strictEqual(JSON.parse(retiredH[0]).status, "retired",
                       retiredH[0]);
    log.info("    after the loss, the HOTP holder's sign-in " +
             (afterH.codeStep ? "asked for a code and refused it"
                              : "asked for no code: " + afterH.next) +
             "; the TOTP holder's " +
             (afterT.codeStep ? "asked for a code and refused it"
                              : "asked for no code: " + afterT.next));
  });
  log.debug("Leaving test().");
}

async function main() {
  log.debug("Entering main().");
  if (!lab.available()) {
    log.info("SKIPPED: no CLIENT_LAB_URL, so there is no client lab " +
             "(an AWS target, or ./run-coverage.sh).");
    log.debug("Leaving main(). No lab.");
    return;
  }
  let failure = null;
  try {
    await test();
  } catch (e) {
    log.debug("Caught in main(): " + ((e && e.message) || e));
    // Reported below, after the realm is removed.
    failure = e;
  }
  if (process.env.STS_TEST_REMOVE_REALMS === "1") {
    try {
      await postJson(base + "/admin-api/realms/remove", { id: REALM });
    } catch (e) {
      log.debug("Caught in main() removing the realm: " +
                ((e && e.message) || e));
      // A removal that fails does not hide the test's own verdict.
      log.info("could not remove the realm " + REALM);
    }
  }
  if (failure) {
    log.error("FAILED after " + checks + " check(s): " +
              (failure.stack || failure));
    log.debug("Leaving main(). Failed.");
    process.exit(1);
  }
  log.info(checks + " check(s) passed.");
  log.debug("Leaving main().");
}

main();
