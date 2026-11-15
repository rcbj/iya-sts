// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_second_factor_codes.js
//
// ---------------------------------------------------------------------------
// THE FIVE PASSWORD-ONLY DOORS BY CODE, AND EVERY WAY A SECOND FACTOR GETS
// THERE, OVER THE WIRE.
//
// D12 (#444): carries over `tests/second_factor_doors.js` and
// `tests/totp_password_only_doors.js`. `sts_second_factor_doors.js` drives
// the five doors in whichever mode the stack runs, for ONE way a second
// factor is demanded (an entry's stsMfaRequired); the in-process files held
// the rest by reading the code a refusal carries, which a client never sees.
// Here those codes come off `/admin-api/audit`, in realms of this job's own
// whose mode it chooses:
//
//   A. IN A PRODUCT REALM, at each of the five doors (an LDAPS simple bind,
//      a WS-Security UsernameToken, SCIM Basic, SSF Basic, EST Basic), the
//      RIGHT password of a person who holds a second factor or of whom one
//      is required is refused with exactly the answer a WRONG password gets,
//      and the two are told apart only in the record: STS-AUTHN-0213 for
//      the right one, STS-AUTHN-0054 for the wrong one, at LDAP and SCIM;
//      WS-Trust, SSF and EST record only their own refusal for both
//      (STS-WSTRUST-0003, STS-SSF-0009, STS-ENROLL-0014). Four people, one for
//      each way: stsMfaRequired on the entry, an authenticator app enrolled
//      as `/portal/mfa` enrols it (totp_password_only_doors.js, #417), a
//      passkey enrolled at `/account-api/keys` (a key has no role since
//      #1135), and everybody required by the realm's authentication policy
//      (`requireSecondFactor: always`, in a second product realm). A person
//      with none is admitted at each door;
//   B. IN A DEVELOPMENT REALM the TOTP-enrolled person is admitted at all
//      five doors — the control that each door is reached;
//   C. `authn.passwordAloneDoors` takes only the five door names, and
//      listing `ldap` admits the password alone at LDAP and nowhere else;
//   D. APP PASSWORDS BY CODE: made and refused at
//      `/admin-api/users/create-app-password` — an over-long name and a
//      name already held (STS-AUTHN-0215), no door (STS-AUTHN-0216, or the
//      request schema's STS-API-0009 for a door outside the five), somebody
//      who does not exist (STS-AUTHN-0061), past
//      `appPasswords.maxPerPerson` (STS-AUTHN-0217), with
//      `appPasswords.enabled` off (STS-AUTHN-0218), an application's name
//      (STS-AUTHN-0061: an application is not an account); a
//      revoke of an id nobody holds (STS-AUTHN-0219); an app password
//      presented at a door outside its scope (SSF's own STS-SSF-0009) and
//      at the sign-in screen (STS-AUTHN-0214), on a disabled account
//      (STS-AUTHN-0200), and a wrong one (STS-AUTHN-0054). The app
//      password survives a reset of the person's password; one made while
//      app passwords are on goes on working once they are turned off.
//
// THE PRODUCT REALMS turn `risk.assessSignIns` off: a sign-in from this
// job's client is scored `automated-client` and refused STS-RISK-0016,
// which is risk's subject and not this job's, and
// `authn.allowOptionalSecondFactor` on, so a person who holds nothing is
// signed in with a password (sts_ldap_read_authorization.js's reason).
//
// NOT carried, and why (class (d)): the verifier's two declared exemptions
// (`asked-next`, `session-held`) and `verifyAsync()`'s parity with
// `verify()` are arguments of a library call no door passes from outside;
// a refused LDAP bind counting against the bind rate limit — the limiter is
// keyed by the caller's address and shared by every concurrent job, as
// `sts_rate_limits.js` says of the address bucket; the stored form of an app
// password (a scrypt hash on the entry, which no answer carries — that the
// API never answers it is asserted here); the console's renderer of the
// list; `DOOR_IDS` as a table. `authn.passwordAloneDoors` with an unknown
// name in a layer nobody checks on write (the appconfig file) is (d) too:
// over the wire the write is refused.
//
// OWNED HERE (local: true): this repository's own doors and API.
// ---------------------------------------------------------------------------

const assert = require("assert");
const nodeCrypto = require("crypto");
const ldapjs = require("ldapjs");
const names = require("./random_username.js");
const authnSignin = require("./authn_signin");
const portal = require("./portal_signin.js");
const passkeys = require("./passkey_wire_kit.js");

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
var log = bunyan.createLogger({ name: "sts_second_factor_codes",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp().toLowerCase().replace(/[^a-z0-9]/g, "")
  .slice(-10);
const PASSWORD = "Sfc-" + STAMP + "-Correct.Horse.42";
const WRONG = PASSWORD + "-wrong";
const DOORS = ["ldap", "wstrust", "scim", "ssf", "est"];
const AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";

const PROD = { id: "sfc-p-" + STAMP };
const EVERY = { id: "sfc-e-" + STAMP };
const DEV = { id: "sfc-d-" + STAMP };
[PROD, EVERY, DEV].forEach(function (r) {
  r.domain = r.id + ".example.net";
  r.base = base + "/realm/" + r.id;
  r.api = r.base + "/admin-api";
  r.appliesTo = "https://wstrust." + r.id + ".example.test/rp";
});

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

async function send(url, options) {
  log.debug("Entering send(). url=" + url);
  const sent = Object.assign({ redirect: "manual" }, options || {});
  sent.headers = Object.assign({ "User-Agent": AGENT }, sent.headers || {});
  const r = await fetch(url, sent);
  const raw = await r.text();
  let body = null;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in send(): " + ((e && e.message) || e));
    // Not JSON — an empty answer, a page or a SOAP envelope; `raw` holds it.
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

function setting(realm, key, value) {
  log.debug("Entering setting(). " + key + "=" + value);
  log.debug("Leaving setting().");
  return postJson(base + "/admin-api/realms/set",
                  { id: realm.id, key: key, value: String(value) });
}

async function codeCount(realm, code) {
  log.debug("Entering codeCount(). " + code);
  const r = await send(realm.api + "/audit?per=1&code=" +
                       encodeURIComponent(code));
  log.debug("Leaving codeCount().");
  return Number((r.body && r.body.matched) || 0);
}

// The rows a code has gained since `before`, waited for: the audit row of a
// refusal is written as the refusal is answered, and read here a moment on.
async function gained(realm, code, before, atLeast) {
  log.debug("Entering gained(). " + code);
  const want = atLeast === undefined ? 1 : atLeast;
  let n = (await codeCount(realm, code)) - before;
  for (let i = 0; i < 20 && n < want; i += 1) {
    await sleep(150);
    n = (await codeCount(realm, code)) - before;
  }
  log.debug("Leaving gained(). " + n);
  return n;
}

// ---------------------------------------------------------------------------
// THE FIVE DOORS (sts_second_factor_doors.js's, per realm). Each answers
// `{ accepted, answer }`, `answer` with the moving parts taken out, so "the
// same answer as a wrong password" is a string comparison.
// ---------------------------------------------------------------------------
function basic(user, password) {
  log.debug("Entering basic().");
  log.debug("Leaving basic().");
  return "Basic " + Buffer.from(user + ":" + password).toString("base64");
}

function personDn(realm, who) {
  log.debug("Entering personDn().");
  log.debug("Leaving personDn().");
  return "uid=" + who + ",ou=users," + realm.domain.split(".").map(
    function (one) {
      return "dc=" + one;
    }).join(",");
}

function ldapBind(realm, who, password) {
  log.debug("Entering ldapBind(). " + who);
  return new Promise(function (resolve) {
    const url = process.env.STS_LDAPS_URL ||
      ("ldaps://" + new URL(base).hostname + ":" +
       (process.env.STS_LDAPS_PORT || 636));
    const client = ldapjs.createClient({
      url: url, reconnect: false, timeout: 20000, connectTimeout: 15000,
      tlsOptions: { servername: new URL(url).hostname,
                    rejectUnauthorized:
                      process.env.NODE_TLS_REJECT_UNAUTHORIZED !== "0" }
    });
    client.on("error", function (e) {
      // ldapjs also emits on the client; the bind's callback reports it.
      log.debug("The LDAP client emitted an error: " + e.message);
    });
    client.bind(personDn(realm, who), password, function (e) {
      const out = e ? { accepted: false, answer: "ldap " + e.code + " " +
                        String(e.name) }
                    : { accepted: true, answer: "ldap 0" };
      try {
        client.unbind(function () {
          client.destroy();
        });
      } catch (x) {
        // An unbind on a connection the server already closed.
        log.debug("Caught in ldapBind(): " + ((x && x.message) || x));
      }
      log.debug("Leaving ldapBind(). " + out.answer);
      resolve(out);
    });
  });
}

async function wsTrust(realm, who, password) {
  log.debug("Entering wsTrust(). " + who);
  const rst = '<?xml version="1.0" encoding="UTF-8"?>' +
    '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">' +
    '<soap:Header><wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/' +
    '2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">' +
    '<wsse:UsernameToken><wsse:Username>' + who + '</wsse:Username>' +
    '<wsse:Password>' + password +
    '</wsse:Password></wsse:UsernameToken></wsse:Security></soap:Header>' +
    '<soap:Body><wst:RequestSecurityToken ' +
    'xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">' +
    '<wst:RequestType>' +
    'http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType>' +
    '<wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy">' +
    '<wsa:EndpointReference ' +
    'xmlns:wsa="http://www.w3.org/2005/08/addressing"><wsa:Address>' +
    realm.appliesTo + '</wsa:Address></wsa:EndpointReference></wsp:AppliesTo>' +
    '</wst:RequestSecurityToken></soap:Body></soap:Envelope>';
  const r = await send(realm.base + "/sts", { method: "POST",
    headers: { "Content-Type": "application/soap+xml" }, body: rst });
  const accepted = r.status === 200 && /Assertion/.test(r.raw);
  log.debug("Leaving wsTrust(). " + r.status);
  return { accepted: accepted,
           answer: r.status + " " + String(r.raw)
             .replace(/(uuid|urn:uuid):[0-9a-f-]+/gi, "ID")
             .replace(/_[0-9a-f]{16,}/gi, "ID")
             .replace(/\d{4}-\d\d-\d\dT[\d:.]+Z/g, "TIME") };
}

async function scim(realm, who, password) {
  log.debug("Entering scim(). " + who);
  const r = await send(realm.base + "/scim/v2/Users?count=1",
    { headers: { Authorization: basic(who, password),
                 Accept: "application/scim+json" } });
  log.debug("Leaving scim(). " + r.status);
  return { accepted: r.status !== 401, answer: r.status + " " + r.raw };
}

async function ssf(realm, who, password) {
  log.debug("Entering ssf(). " + who);
  const r = await send(realm.base + "/ssf/stream",
    { headers: { Authorization: basic(who, password) } });
  log.debug("Leaving ssf(). " + r.status);
  return { accepted: r.status !== 401, answer: r.status + " " + r.raw };
}

// A body that is not a certificate request: an authenticated caller is
// answered 400 about the body, an unauthenticated one 401 before it is read.
async function est(realm, who, password) {
  log.debug("Entering est(). " + who);
  const r = await send(realm.base + "/.well-known/est/simpleenroll", {
    method: "POST", headers: { Authorization: basic(who, password),
                               "Content-Type": "application/pkcs10" },
    body: "not-a-certificate-request" });
  log.debug("Leaving est(). " + r.status);
  return { accepted: r.status !== 401, answer: r.status + " " + r.raw };
}

const DOOR = { ldap: ldapBind, wstrust: wsTrust, scim: scim, ssf: ssf,
               est: est };

// ---------------------------------------------------------------------------
// RFC 6238 (SHA-1, six digits, thirty seconds), from the secret the portal's
// set-up view shows grouped in fours.
// ---------------------------------------------------------------------------
function base32ToBytes(text) {
  log.debug("Entering base32ToBytes().");
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = String(text).toUpperCase().replace(/[^A-Z2-7]/g, "");
  let bits = "";
  for (const ch of clean) {
    bits += alphabet.indexOf(ch).toString(2).padStart(5, "0");
  }
  const out = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    out.push(parseInt(bits.slice(i, i + 8), 2));
  }
  log.debug("Leaving base32ToBytes().");
  return Buffer.from(out);
}

function totpCode(secret, offsetSteps) {
  log.debug("Entering totpCode().");
  const step = Math.floor(Date.now() / 30000) + (offsetSteps || 0);
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const mac = nodeCrypto.createHmac("sha1", base32ToBytes(secret))
    .update(counter).digest();
  const at = mac[mac.length - 1] & 0x0f;
  const n = ((mac[at] & 0x7f) << 24) | (mac[at + 1] << 16) |
            (mac[at + 2] << 8) | mac[at + 3];
  log.debug("Leaving totpCode().");
  return String(n % 1000000).padStart(6, "0");
}

// ---------------------------------------------------------------------------
// THE REALMS AND THE PEOPLE.
// ---------------------------------------------------------------------------
async function makeRealm(realm, mode) {
  log.debug("Entering makeRealm(). " + realm.id);
  // Every realm is made in DEVELOPMENT and the product ones switched once
  // their fixtures are in: a product realm on a service with no
  // key-encryption key cannot store a TOTP secret ("could not be
  // encrypted"), and enrolment is not what this job asserts.
  const overrides = { "global.mode": "development",
                      "risk.assessSignIns": "false",
                      "est.attemptsPerAddress": "100000" };
  if (mode === "product") {
    overrides["authn.allowOptionalSecondFactor"] = "true";
  }
  realm.mode = mode;
  await ok(base + "/admin-api/realms/create", { id: realm.id,
    domain: realm.domain, name: "Second-factor codes " + realm.id,
    overrides: overrides }, "created the realm " + realm.id);
  await ok(realm.api + "/applications/create", { identifier: realm.appliesTo,
    name: "sfc relying party", protocols: ["wstrust"],
    fields: { wstrustAppliesTo: [realm.appliesTo] } },
    "registered the WS-Trust relying party in " + realm.id);
  log.debug("Leaving makeRealm().");
}

async function person(realm, who) {
  log.debug("Entering person(). " + who);
  await ok(realm.api + "/users/create", { username: who, invent: false,
    credential: "password", password: PASSWORD,
    attributes: { cn: "SFC " + who, givenName: "SFC", sn: who,
                  mail: who + "@" + realm.domain } },
    "created " + who + " in " + realm.id);
  log.debug("Leaving person().");
}

// An authenticator app enrolled as /portal/mfa enrols one: start, the
// secret read off the set-up view, a code computed here to confirm it.
async function enrolTotp(realm, who) {
  log.debug("Entering enrolTotp(). " + who);
  const s = await portal.signInToThePortal(realm.base, who, null,
                                           { password: PASSWORD });
  const started = await s.act("/portal/mfa", { action: "start" });
  assert.ok(started.status === 200, "start: " + started.status + " " +
            String(started.text).slice(0, 300));
  const view = await s.page("/portal/mfa");
  const secret = (view.json && view.json.setup &&
                  view.json.setup.grouped) || "";
  assert.ok(secret.length > 20, "no secret on the set-up view: " +
            JSON.stringify(view.json).slice(0, 300));
  const confirmed = await s.act("/portal/mfa", { action: "confirm",
                                                 code: totpCode(secret) });
  assert.ok(confirmed.status === 200 && confirmed.json &&
            confirmed.json.ok !== false, "confirm: " + confirmed.status +
            " " + String(confirmed.text).slice(0, 300));
  log.debug("Leaving enrolTotp().");
}

// A passkey enrolled at /account-api/keys, as the portal's page makes one.
async function enrolPasskey(realm, who) {
  log.debug("Entering enrolPasskey(). " + who);
  const k = passkeys.kit("sts_second_factor_codes", { log: log });
  const s = await portal.signInToThePortal(realm.base, who, null,
                                           { password: PASSWORD });
  const e = await k.enrol(s, k.authenticator({}), {});
  assert.ok(e.done && e.done.status === 200 && e.done.json &&
            e.done.json.ok !== false, "the passkey enrolment: " +
            JSON.stringify(e.done && e.done.json).slice(0, 300) + " " +
            JSON.stringify(e.begun && e.begun.json).slice(0, 300));
  log.debug("Leaving enrolPasskey().");
}

async function factorsOf(realm, who) {
  log.debug("Entering factorsOf(). " + who);
  const r = await send(realm.api + "/users/app-passwords?user=" +
                       encodeURIComponent(who));
  log.debug("Leaving factorsOf().");
  return r;
}

// ---------------------------------------------------------------------------
// THE ASSERTION ABOUT ONE DOOR AND ONE PERSON, BY CODE.
// ---------------------------------------------------------------------------
// WHAT EACH DOOR RECORDS. LDAP and SCIM record the verifier's own code —
// STS-AUTHN-0213 for the right password, STS-AUTHN-0054 for a wrong one.
// WS-Trust, SSF and EST record only their own door's refusal for both
// (STS-WSTRUST-0003, STS-SSF-0009, STS-ENROLL-0014): the verifier's reason
// does not reach the audit log there. That is an observed difference from
// the in-process claim, which read the verifier's answer, and it is pinned.
const RECORDED = {
  ldap: ["STS-AUTHN-0213", "STS-AUTHN-0054"],
  wstrust: ["STS-WSTRUST-0003", "STS-WSTRUST-0003"],
  scim: ["STS-AUTHN-0213", "STS-AUTHN-0054"],
  ssf: ["STS-SSF-0009", "STS-SSF-0009"],
  est: ["STS-ENROLL-0014", "STS-ENROLL-0014"]
};

async function refusedByCode(realm, door, who, why) {
  log.debug("Entering refusedByCode(). " + door + " " + who);
  const rightCode = RECORDED[door][0];
  const wrongCode = RECORDED[door][1];
  const before13 = await codeCount(realm, rightCode);
  const beforeOwn = await codeCount(realm, "STS-AUTHN-0213");
  const right = await DOOR[door](realm, who, PASSWORD);
  const gotRight = await gained(realm, rightCode, before13);
  const gotOwn = (await codeCount(realm, "STS-AUTHN-0213")) - beforeOwn;
  const before54 = await codeCount(realm, wrongCode);
  const wrong = await DOOR[door](realm, who, WRONG);
  const gotWrong = await gained(realm, wrongCode, before54);
  check("A. " + door + " (" + why + "): the RIGHT password is refused with " +
        "exactly a wrong password's answer, recorded " + rightCode +
        " where the wrong one is " + wrongCode, function () {
    assert.ok(!right.accepted, "accepted: " + right.answer.slice(0, 300));
    assert.ok(!wrong.accepted, "a wrong password was accepted: " +
              wrong.answer.slice(0, 300));
    assert.strictEqual(right.answer, wrong.answer,
      "the refusal is distinguishable from a wrong password");
    assert.ok(gotRight >= 1, rightCode + " rows gained: " + gotRight);
    assert.ok(gotWrong >= 1, wrongCode + " rows gained: " + gotWrong);
    if (rightCode !== "STS-AUTHN-0213") {
      assert.strictEqual(gotOwn, 0, door + " recorded STS-AUTHN-0213 now");
    }
    assert.ok(!/STS-[A-Z]+-\d{4}/.test(right.answer + wrong.answer),
              "a code was sent");
  });
  log.debug("Leaving refusedByCode().");
}

async function admitted(realm, door, who, password, what) {
  log.debug("Entering admitted(). " + door + " " + who);
  const r = await DOOR[door](realm, who, password);
  check(door + ": " + what, function () {
    assert.ok(r.accepted, r.answer.slice(0, 400));
  });
  log.debug("Leaving admitted().");
  return r;
}

async function refusedAt(realm, door, who, password, code, what) {
  log.debug("Entering refusedAt(). " + door + " " + who);
  const before = await codeCount(realm, code);
  const r = await DOOR[door](realm, who, password);
  const got = await gained(realm, code, before);
  check(door + ": " + what + " (" + code + ")", function () {
    assert.ok(!r.accepted, "accepted: " + r.answer.slice(0, 400));
    assert.ok(got >= 1, code + " rows gained: " + got);
  });
  log.debug("Leaving refusedAt().");
  return r;
}

// One make at create-app-password expected refused, with its code.
async function makeRefused(realm, body, code, what) {
  log.debug("Entering makeRefused(). " + code);
  const before = await codeCount(realm, code);
  const r = await postJson(realm.api + "/users/create-app-password", body);
  const got = await gained(realm, code, before);
  check("D. " + what + " is refused (" + code + ")", function () {
    assert.ok(r.status >= 400 && r.status < 500,
              r.status + " " + r.raw.slice(0, 300));
    assert.ok(!(r.body && r.body.appPassword), "an app password was made");
    assert.ok(got >= 1, code + " rows gained: " + got);
    assert.ok(!/STS-[A-Z]+-\d{4}/.test(r.raw), "a code was sent");
  });
  log.debug("Leaving makeRefused().");
  return r;
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving " + base + " in realms of this job's own (" + STAMP +
           ").");

  // -------------------------------------------------------------------------
  log.info("=== setup: two product realms, a development realm, people ===");
  await makeRealm(PROD, "product");
  await makeRealm(EVERY, "product");
  await makeRealm(DEV, "development");
  const PLAIN = names.usernameFor("sfc-plain");
  const FLAGGED = names.usernameFor("sfc-flagged");
  const TOTP = names.usernameFor("sfc-totp");
  const KEYED = names.usernameFor("sfc-keyed");
  const APPU = names.usernameFor("sfc-app");
  const ALL = names.usernameFor("sfc-all");
  for (const who of [PLAIN, FLAGGED, TOTP, KEYED, APPU]) {
    await person(PROD, who);
  }
  await person(EVERY, ALL);
  await person(EVERY, PLAIN);
  await person(DEV, TOTP);
  await ok(PROD.api + "/users/require-mfa", { user: FLAGGED },
           "required a second factor of " + FLAGGED);
  await enrolTotp(PROD, TOTP);
  await enrolTotp(DEV, TOTP);
  await enrolPasskey(PROD, KEYED);
  const view = await send(EVERY.api + "/policies");
  assert.ok(view.status === 200 && view.body && view.body.authn,
            "GET /admin-api/policies: " + view.raw.slice(0, 300));
  const profile = {};
  view.body.authn.fields.forEach(function (f) {
    profile[f.key] = f.value;
  });
  profile.requireSecondFactor = "always";
  await ok(EVERY.api + "/policies/save-authn-policy", profile,
           "required a second factor of everybody in " + EVERY.id);
  for (const realm of [PROD, EVERY]) {
    await ok(base + "/admin-api/realms/set", { id: realm.id,
      key: "global.mode", value: "product" }, "switched " + realm.id +
      " to product");
  }

  const doorsOf = {};
  for (const who of [PLAIN, FLAGGED, TOTP, KEYED]) {
    doorsOf[who] = await factorsOf(PROD, who);
  }
  doorsOf[ALL] = await factorsOf(EVERY, ALL);
  check("setup: the API says the four people's password is refused at all " +
        "five doors and the plain person's at none", function () {
    [FLAGGED, TOTP, KEYED].forEach(function (who) {
      assert.deepStrictEqual(doorsOf[who].body.passwordOnlyDoors.refused,
                             DOORS, who + ": " +
                             doorsOf[who].raw.slice(0, 300));
    });
    assert.deepStrictEqual(doorsOf[ALL].body.passwordOnlyDoors.refused,
                           DOORS, doorsOf[ALL].raw.slice(0, 300));
    assert.deepStrictEqual(doorsOf[PLAIN].body.passwordOnlyDoors.refused,
                           [], doorsOf[PLAIN].raw.slice(0, 300));
  });

  // -------------------------------------------------------------------------
  log.info("=== A. product: each door, each way a second factor arrives ===");
  for (const door of DOORS) {
    await refusedByCode(PROD, door, FLAGGED, "stsMfaRequired");
    await refusedByCode(PROD, door, TOTP, "an authenticator app");
    await refusedByCode(PROD, door, KEYED, "a passkey");
    await refusedByCode(EVERY, door, ALL, "the realm requires one");
    await admitted(PROD, door, PLAIN, PASSWORD, "a person with no second " +
                   "factor is admitted with their password");
  }

  // -------------------------------------------------------------------------
  log.info("=== B. development: the same TOTP person at every door ===");
  for (const door of DOORS) {
    await admitted(DEV, door, TOTP, PASSWORD, "B. DEVELOPMENT admits the " +
                   "TOTP-enrolled person's password (each door is reached)");
  }

  // -------------------------------------------------------------------------
  log.info("=== C. authn.passwordAloneDoors ===");
  const bogus = await setting(PROD, "authn.passwordAloneDoors", "ldap,bogus");
  check("C. a door name outside the five is refused at the write",
        function () {
    assert.ok(bogus.status === 400, bogus.status + " " +
              bogus.raw.slice(0, 300));
  });
  await ok(base + "/admin-api/realms/set", { id: PROD.id,
    key: "authn.passwordAloneDoors", value: "ldap" }, "listed ldap");
  try {
    await admitted(PROD, "ldap", FLAGGED, PASSWORD, "C. a listed door " +
                   "admits the password alone");
    await refusedByCode(PROD, "scim", FLAGGED, "C. a door not listed");
  } finally {
    await postJson(base + "/admin-api/realms/unset",
                   { id: PROD.id, key: "authn.passwordAloneDoors" });
  }

  // -------------------------------------------------------------------------
  log.info("=== D. app passwords, by code ===");
  await ok(PROD.api + "/users/require-mfa", { user: APPU },
           "required a second factor of " + APPU);
  const made = await ok(PROD.api + "/users/create-app-password",
    { user: APPU, name: "mail client", doors: ["ldap", "scim"] },
    "made an app password");
  check("D. an app password is answered once, printed in groups of four, " +
        "scoped to the doors asked", function () {
    assert.ok(/^[A-Z2-7]{4}(-[A-Z2-7]{4}){5}$/.test(made.appPassword),
              JSON.stringify(made));
    assert.deepStrictEqual(made.doors, ["ldap", "scim"]);
  });
  await admitted(PROD, "scim", APPU, made.appPassword, "D. it is accepted " +
                 "at a door it names");
  await admitted(PROD, "ldap", APPU, made.appPassword.toLowerCase()
    .replace(/-/g, " "), "D. in lower case with spaces for its dashes too");
  // SSF records its own refusal only (RECORDED, above), so the door outside
  // the scope is read by SSF's code; STS-AUTHN-0214 is read at the screen.
  await refusedAt(PROD, "ssf", APPU, made.appPassword, "STS-SSF-0009",
                  "D. it is refused at a door it does not name");
  await refusedAt(PROD, "scim", APPU, made.appPassword + "X",
                  "STS-AUTHN-0054", "D. a wrong app password is a wrong " +
                  "password");
  await refusedByCode(PROD, "scim", APPU, "D. its owner's own password " +
                      "still");
  const listed = await factorsOf(PROD, APPU);
  check("D. the list records its last use and carries neither the password " +
        "nor a hash", function () {
    assert.ok(listed.body.passwords[0].lastUsedAt > 0,
              listed.raw.slice(0, 300));
    assert.ok(!!listed.body.passwords[0].lastUsedDoor,
              listed.raw.slice(0, 300));
    assert.ok(listed.raw.indexOf(made.appPassword) < 0 &&
              listed.raw.indexOf("$scrypt$") < 0, listed.raw.slice(0, 300));
  });

  // At the sign-in screen, as an app password never is.
  const k = passkeys.kit("sts_second_factor_codes", { log: log });
  const client = await k.client(PROD);
  const screen = await k.screen(PROD);
  const before14 = await codeCount(PROD, "STS-AUTHN-0214");
  const signIn = await authnSignin.submit(PROD.base, screen.location,
    { action: "login", username: APPU, password: made.appPassword },
    { cookie: screen.cookie, screen: screen.opened,
      headers: { "User-Agent": AGENT } });
  const got14 = await gained(PROD, "STS-AUTHN-0214", before14);
  check("D. at the sign-in screen it is refused, recorded STS-AUTHN-0214",
        function () {
    assert.ok(client, "no client");
    assert.strictEqual(signIn.next, "refused", signIn.next + " " +
                       JSON.stringify(signIn.json).slice(0, 300));
    assert.ok(got14 >= 1, "STS-AUTHN-0214 rows gained: " + got14);
  });

  const reset = await ok(PROD.api + "/users/reset-password", { user: APPU },
                         "reset " + APPU + "'s password");
  check("(the reset answered a new password)", function () {
    assert.ok(reset.password);
  });
  await admitted(PROD, "scim", APPU, made.appPassword, "D. a reset of the " +
                 "person's password leaves the app password working");

  await makeRefused(PROD, { user: APPU, name: "x".repeat(65),
    doors: ["ldap"] }, "STS-AUTHN-0215", "a name over sixty-four " +
    "characters");
  await makeRefused(PROD, { user: APPU, name: "mail client",
    doors: ["ldap"] }, "STS-AUTHN-0215", "a name the person already " +
    "holds");
  await makeRefused(PROD, { user: APPU, name: "no door", doors: [] },
                    "STS-AUTHN-0216", "a make naming no door");
  const kerberos = await postJson(PROD.api + "/users/create-app-password",
    { user: APPU, name: "kdc", doors: ["ldap", "kerberos"] });
  check("D. a door outside the five is refused by the request schema",
        function () {
    assert.strictEqual(kerberos.status, 400, kerberos.raw.slice(0, 300));
    assert.ok(!(kerberos.body && kerberos.body.appPassword));
  });
  await makeRefused(PROD, { user: "nobody-" + STAMP, name: "ghost",
    doors: ["ldap"] }, "STS-AUTHN-0061", "a make for somebody who does " +
    "not exist");
  await ok(base + "/admin-api/realms/set", { id: PROD.id,
    key: "appPasswords.maxPerPerson", value: "1" }, "capped at one");
  try {
    await makeRefused(PROD, { user: APPU, name: "second", doors: ["ldap"] },
                      "STS-AUTHN-0217", "a make past " +
                      "appPasswords.maxPerPerson");
  } finally {
    await postJson(base + "/admin-api/realms/unset",
                   { id: PROD.id, key: "appPasswords.maxPerPerson" });
  }
  await ok(base + "/admin-api/realms/set", { id: PROD.id,
    key: "appPasswords.enabled", value: "false" }, "turned them off");
  try {
    await makeRefused(PROD, { user: APPU, name: "off", doors: ["ldap"] },
                      "STS-AUTHN-0218", "a make with " +
                      "appPasswords.enabled off");
    await admitted(PROD, "scim", APPU, made.appPassword, "D. one made " +
                   "before they were turned off goes on working");
  } finally {
    await postJson(base + "/admin-api/realms/unset",
                   { id: PROD.id, key: "appPasswords.enabled" });
  }
  const before19 = await codeCount(PROD, "STS-AUTHN-0219");
  const revokeNone = await postJson(PROD.api + "/users/revoke-app-password",
    { user: APPU, id: "ZZZZ" });
  const got19 = await gained(PROD, "STS-AUTHN-0219", before19);
  check("D. revoking an id the person does not hold is refused " +
        "(STS-AUTHN-0219)", function () {
    assert.ok(revokeNone.status >= 400 && revokeNone.status < 500,
              revokeNone.status + " " + revokeNone.raw.slice(0, 300));
    assert.ok(got19 >= 1, "STS-AUTHN-0219 rows gained: " + got19);
  });
  await ok(PROD.api + "/users/disable", { user: APPU }, "disabled " + APPU);
  try {
    await refusedAt(PROD, "scim", APPU, made.appPassword, "STS-AUTHN-0200",
                    "D. a disabled account is refused its app password");
  } finally {
    await ok(PROD.api + "/users/enable", { user: APPU }, "enabled " + APPU);
  }
  await ok(PROD.api + "/users/revoke-app-password",
           { user: APPU, id: made.id }, "revoked it");
  const again = await postJson(PROD.api + "/users/revoke-app-password",
                               { user: APPU, id: made.id });
  check("D. revoking it a second time is refused", function () {
    assert.ok(again.status >= 400 && again.status < 500,
              again.status + " " + again.raw.slice(0, 300));
  });
  await refusedAt(PROD, "scim", APPU, made.appPassword, "STS-AUTHN-0054",
                  "D. a revoked app password is a wrong password");

  // An application's secret is not a person's account (G).
  const APP = "sfc-app-" + STAMP;
  await ok(PROD.api + "/applications/create", { identifier: APP, name: APP,
    protocols: ["oauth2"], fields: { oauthClientId: [APP],
      oauthGrantType: ["client_credentials"] } }, "made an application");
  const before21 = await codeCount(PROD, "STS-AUTHN-0221");
  const before61 = await codeCount(PROD, "STS-AUTHN-0061");
  const appMade = await postJson(PROD.api + "/users/create-app-password",
    { user: APP, name: "for an app", doors: ["ldap"] });
  const got21 = await gained(PROD, "STS-AUTHN-0221", before21, 0);
  const got61 = await gained(PROD, "STS-AUTHN-0061", before61, 0);
  log.info("an application's make recorded STS-AUTHN-0221 x" + got21 +
           ", STS-AUTHN-0061 x" + got61);
  // The in-process file allowed either code; over the wire an application
  // named by its identifier is no entry under people, so it is 0061.
  check("D. an application is not given an app password: its name is no " +
        "person in the realm (STS-AUTHN-0061)", function () {
    assert.ok(appMade.status >= 400 && appMade.status < 500,
              appMade.status + " " + appMade.raw.slice(0, 300));
    assert.ok(got61 >= 1, "0221: " + got21 + ", 0061: " + got61);
  });

  log.info(checks + " check(s) passed.");
  log.debug("Leaving test().");
}

// REMOVAL IS OPT-IN: with STS_TEST_REMOVE_REALMS=1 (a private probe that
// would otherwise fill its directory) every realm this run made — each id
// carries the run's STAMP — is removed at the end, pass or fail. A suite run
// leaves them standing (tests/CLAUDE.md, *No job removes a realm*).
async function removeRealms() {
  log.debug("Entering removeRealms().");
  if (process.env.STS_TEST_REMOVE_REALMS !== "1") {
    log.debug("Leaving removeRealms(). Not asked to.");
    return;
  }
  for (const realm of [PROD, EVERY, DEV]) {
    const r = await postJson(base + "/admin-api/realms/remove",
                             { id: realm.id });
    log.info("removed the realm " + realm.id + " (" + r.status + ")");
  }
  log.debug("Leaving removeRealms().");
}

async function main() {
  log.debug("Entering main().");
  let failure = null;
  try {
    await test();
  } catch (e) {
    log.debug("Caught in main(): " + ((e && e.message) || e));
    // Reported below, after the realms are removed.
    failure = e;
  }
  try {
    await removeRealms();
  } catch (e) {
    log.debug("Caught in main(): " + ((e && e.message) || e));
    log.warn("could not remove the realms: " + ((e && e.message) || e));
  }
  if (failure) {
    log.error("sts_second_factor_codes FAILED: " +
              ((failure && failure.stack) || failure));
    log.debug("Leaving main(). Failed.");
    process.exit(1);
  }
  log.info("Test completed successfully.");
  log.debug("Leaving main().");
}

main();
