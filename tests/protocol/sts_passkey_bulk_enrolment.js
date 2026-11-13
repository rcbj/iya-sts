// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

// ===========================================================================
// sts_passkey_bulk_enrolment.js — MANY PEOPLE, AND ONE PASSKEY EACH, THROUGH
// THE MANAGEMENT API (#957).
//
// An administrator cannot import a registration made somewhere else. rcbj's
// decision on #945, recorded on the two acts: begin mints a challenge, the
// authenticator runs in the administrator's browser, finish posts what that
// ceremony produced. This job is that loop, over HTTP, for many people.
//
//   1. POST /admin-api/users/create, invent:false, one person at a time.
//   2. adminEnrolment is off, and begin says so.
//   3. The passkey policy turns it on. The service's own token is still
//      refused: the subject has to be a person (STS-AUTHN-0445).
//   4. A console administrator begins every enrolment, then finishes every
//      one. One pending record per person, so they can all be in flight.
//   5. Each finish is an ES256 `none` ceremony from a software authenticator
//      written in this file. Development does not skip that verification.
//   6. GET /admin-api/users?user= lists the credential id, and the finish
//      names who enrolled it.
//   7. One of those keys signs the person in, which is the half `none`
//      attestation cannot show: registration carries the public key, and
//      the assertion is what the private key signs.
//   8. Somebody else's registration posted at a new begin is refused, and
//      that enrolment is spent, so the real ceremony cannot finish it.
//   9. A credential that is not a ceremony is refused the same way.
//  10. With webauthn.maxKeysPerPerson at 1, another begin is refused.
//
// ALL OF IT IN A THROWAWAY REALM. adminEnrolment changes every passkey
// enrolment in the realm it is saved in, and the directory bulk jobs leave
// their people in the default realm on purpose. This job must not join
// them, and it must not read BULK_USERS: that variable moves all three
// timings together.
//
// THE COUNT IS 50 UNLESS PASSKEY_BULK_USERS SAYS OTHERWISE, and it will not
// go past 80. The runner's watchdog is 300s. The five-thousand-person
// timings are sts_directory_bulk_load_api.js and its two siblings; this
// file is the ceremony, not that measurement.
//
// `local: true`: this repository's own /admin-api. The authenticator is
// written here, on sts_dpop.js's rule.
// ===========================================================================

"use strict";

const assert = require("assert");
const nodeCrypto = require("crypto");
const { Command, Option } = require("commander");
const { usernameFor } = require("./random_username.js");
const fixtures = require("./oauth_fixtures.js");
const authnSignin = require("./authn_signin");
const consoleSignin = require("./console_signin.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, for the reason tests/vendored/wait_for.js gives.
  appconfigProblem = e;
  appconfig = {};
}

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_passkey_bulk_enrolment",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");
var REALM = usernameFor("pkbulk").replace(/[^a-z0-9-]/g, "").slice(0, 30);
var DOMAIN = REALM + ".example.net";
var serviceApi = base + "/admin-api";
base = base + "/realm/" + REALM;
var api = base + "/admin-api";

// Compared byte for byte with the ceremony, sts_webauthn_second_factor.js's
// reason: a written-down origin passes on one stack and fails on the next.
var ORIGIN = new URL(base).origin;
var RP_ID = new URL(base).hostname;

var ADMIN = usernameFor("pkbulk-admin");
var PASSWORD = "Bulk-load " + nodeCrypto.randomBytes(12).toString("hex") +
               " Aa!9";
var CLIENT = "pk-bulk-probe";
var REDIRECT = "http://localhost:9999/cb";
var COUNT = countOf();

var checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  ✓ " + what);
  log.debug("Leaving check().");
}

// 50 fits the main lane. 80 is the most a hand-set PASSKEY_BULK_USERS may
// ask for before this job would need the bulk lane's watchdog.
function countOf() {
  log.debug("Entering countOf().");
  const raw = process.env.PASSKEY_BULK_USERS;
  const n = raw === undefined || String(raw).trim() === "" ? 50
                                                            : Number(raw);
  if (!Number.isInteger(n) || n < 2 || n > 80) {
    log.debug("Leaving countOf(). Refused.");
    throw new Error("PASSKEY_BULK_USERS must be an integer from 2 to 80. " +
      "It is " + JSON.stringify(raw) + ". The five-thousand-person timings " +
      "are sts_directory_bulk_load_*.js, and they do not share this " +
      "variable.");
  }
  log.debug("Leaving countOf().");
  return n;
}

function snippet(answer) {
  log.debug("Entering snippet().");
  const raw = answer && (answer.raw || answer.text);
  const text = raw !== undefined && raw !== null ? String(raw)
    : JSON.stringify((answer && (answer.body || answer.json)) || "");
  log.debug("Leaving snippet().");
  return text.slice(0, 300);
}

// ---------------------------------------------------------------------------
// CBOR, encode only, and an ES256 authenticator. The same shape as
// sts_passkey_dual_lane.js's classical half, written again here.
// ---------------------------------------------------------------------------
function cborHead(major, n) {
  log.debug("Entering cborHead().");
  let out;
  if (n < 24) {
    out = Buffer.from([(major << 5) | n]);
  } else if (n < 256) {
    out = Buffer.from([(major << 5) | 24, n]);
  } else if (n < 65536) {
    out = Buffer.alloc(3);
    out[0] = (major << 5) | 25;
    out.writeUInt16BE(n, 1);
  } else {
    out = Buffer.alloc(5);
    out[0] = (major << 5) | 26;
    out.writeUInt32BE(n, 1);
  }
  log.debug("Leaving cborHead().");
  return out;
}

function cbor(value) {
  log.debug("Entering cbor().");
  let out;
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    const b = Buffer.from(value);
    out = Buffer.concat([cborHead(2, b.length), b]);
  } else if (typeof value === "string") {
    const b = Buffer.from(value, "utf8");
    out = Buffer.concat([cborHead(3, b.length), b]);
  } else if (typeof value === "number") {
    out = value >= 0 ? cborHead(0, value) : cborHead(1, -1 - value);
  } else {
    const entries = Array.from(value.entries());
    out = Buffer.concat([cborHead(5, entries.length)].concat(
      entries.map(function (kv) {
        return Buffer.concat([cbor(kv[0]), cbor(kv[1])]);
      })));
  }
  log.debug("Leaving cbor().");
  return out;
}

function sha256(buf) {
  log.debug("Entering sha256().");
  log.debug("Leaving sha256().");
  return nodeCrypto.createHash("sha256").update(buf).digest();
}

function clientData(type, challenge) {
  log.debug("Entering clientData().");
  log.debug("Leaving clientData().");
  return Buffer.from(JSON.stringify({
    type: type, challenge: challenge, origin: ORIGIN, crossOrigin: false
  }), "utf8");
}

function makeAuthenticator() {
  log.debug("Entering makeAuthenticator().");
  const credentialId = nodeCrypto.randomBytes(32);
  const pair = nodeCrypto.generateKeyPairSync("ec",
                                              { namedCurve: "prime256v1" });
  const jwk = pair.publicKey.export({ format: "jwk" });
  const cose = new Map([[1, 2], [3, -7], [-1, 1],
                         [-2, Buffer.from(jwk.x, "base64url")],
                         [-3, Buffer.from(jwk.y, "base64url")]]);
  let signCount = 0;
  let userHandle = "";
  const id = credentialId.toString("base64url");
  log.debug("Leaving makeAuthenticator().");
  return {
    credentialId: id,
    register: function (challenge, handle) {
      log.debug("Entering register().");
      userHandle = handle;
      const idLen = Buffer.alloc(2);
      idLen.writeUInt16BE(credentialId.length, 0);
      // UP, UV and AT. BE stays clear: a synced passkey is a different case.
      const authData = Buffer.concat([sha256(Buffer.from(RP_ID, "utf8")),
        Buffer.from([0x45]), Buffer.alloc(4), Buffer.alloc(16), idLen,
        credentialId, cbor(cose)]);
      const attestationObject = cbor(new Map([["fmt", "none"],
        ["attStmt", new Map()], ["authData", authData]]));
      log.debug("Leaving register().");
      return {
        id: id, rawId: id, type: "public-key",
        authenticatorAttachment: "platform",
        clientExtensionResults: { credProps: { rk: true } },
        response: {
          attestationObject: attestationObject.toString("base64url"),
          clientDataJSON: clientData("webauthn.create", challenge)
            .toString("base64url"),
          transports: ["internal"] } };
    },
    assert: function (challenge) {
      log.debug("Entering assert().");
      signCount += 1;
      const count = Buffer.alloc(4);
      count.writeUInt32BE(signCount, 0);
      // UP and UV.
      const authData = Buffer.concat([sha256(Buffer.from(RP_ID, "utf8")),
                                      Buffer.from([0x05]), count]);
      const cdj = clientData("webauthn.get", challenge);
      const signature = nodeCrypto.sign("sha256",
        Buffer.concat([authData, sha256(cdj)]), pair.privateKey);
      log.debug("Leaving assert().");
      return {
        id: id, rawId: id, type: "public-key",
        authenticatorAttachment: "platform",
        response: {
          authenticatorData: authData.toString("base64url"),
          clientDataJSON: cdj.toString("base64url"),
          signature: Buffer.from(signature).toString("base64url"),
          userHandle: userHandle } };
    }
  };
}

// ---------------------------------------------------------------------------
// THE VERBS. call() sends no Authorization of its own: the launcher's
// preload attaches the service token, and a person-bound call goes through
// console_signin instead.
// ---------------------------------------------------------------------------
async function call(method, path, payload, root) {
  log.debug("Entering call().");
  const r = await fetch((root || api) + path, method === "GET" ? {} : {
    method: method, headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {}) });
  const raw = await r.text();
  let body;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in call(): " + ((e && e.message) || e));
    // An HTML error page from a door that answers JSON is worth quoting.
    body = raw;
  }
  log.debug("Leaving call().");
  return { status: r.status, body: body, raw: raw };
}

async function setting(key, value) {
  log.debug("Entering setting(). " + key + "=" + value);
  const r = await call("POST", "/config/set", { key: key,
                                                value: String(value) });
  log.debug("Leaving setting(). " + r.status);
  return r;
}

function form(o) {
  log.debug("Entering form().");
  log.debug("Leaving form().");
  return new URLSearchParams(o).toString();
}

async function theSignInScreen() {
  log.debug("Entering theSignInScreen().");
  const challenge = fixtures.pkce();
  const started = await fetch(base + "/oauth2/authorize?" + form({
    client_id: CLIENT, redirect_uri: REDIRECT, response_type: "code",
    scope: "openid", code_challenge: challenge.challenge,
    code_challenge_method: challenge.method }), { redirect: "manual" });
  const location = started.headers.get("location") || "";
  assert.ok(/\/authn\/login(?:\?app=[^#]*)?[?#]authn=/.test(location),
    "the authorization endpoint did not send us to the sign-in screen: " +
    started.status + " " + location);
  const set = started.headers.getSetCookie ? started.headers.getSetCookie()
                                           : [];
  const opened = await authnSignin.screen(base, location, {
    cookie: set.map(function (one) {
      return String(one).split(";")[0];
    }).join("; ") });
  let armed = null;
  if (opened.view && opened.view.passkey) {
    const options = await authnSignin.passkeyOptions(base, opened);
    armed = options.json && options.json.ok ? options.json : null;
  }
  log.debug("Leaving theSignInScreen().");
  return { opened: opened, challenge: armed ? armed.challenge : "" };
}

async function withoutAUsername(make) {
  log.debug("Entering withoutAUsername().");
  const s = await theSignInScreen();
  assert.ok(s.challenge, "the screen armed no passkey ceremony.");
  const answer = await authnSignin.act(base, "/authn-api/pending/" +
    encodeURIComponent(s.opened.id) + "/passkey",
    { credential: JSON.stringify(make(s.challenge)) },
    { cookie: s.opened.cookie, csrf: s.opened.csrf });
  log.debug("Leaving withoutAUsername(). " + answer.next);
  return answer;
}

async function createPeople(people) {
  log.debug("Entering createPeople().");
  const started = Date.now();
  for (let i = 0; i < people.length; i++) {
    const person = people[i];
    const created = await call("POST", "/users/create", {
      username: person.username, invent: false, credential: "password",
      password: PASSWORD,
      attributes: { cn: "Bulk " + person.username, givenName: "Bulk",
                    sn: "Load",
                    mail: person.username + "@passkey-bulk.test" } });
    assert.ok(created.status === 200 && created.body && created.body.ok,
      "creating " + person.username + " answered " + created.status + " " +
      snippet(created));
  }
  log.info("created " + people.length + " people in " +
           (Date.now() - started) + "ms.");
  log.debug("Leaving createPeople().");
}

async function beginFor(admin, username) {
  log.debug("Entering beginFor().");
  const begun = await admin.api("POST",
    "/admin-api/users/begin-passkey-enrolment", {
      user: username, lane: "classical", kind: "passkey" });
  log.debug("Leaving beginFor(). " + begun.status);
  return begun;
}

async function finishFor(admin, username, enrolmentId, credential) {
  log.debug("Entering finishFor().");
  const posted = typeof credential === "string" ? credential
                                                 : JSON.stringify(credential);
  const done = await admin.api("POST",
    "/admin-api/users/finish-passkey-enrolment", {
      user: username, enrolmentId: enrolmentId, credential: posted });
  log.debug("Leaving finishFor(). " + done.status);
  return done;
}

// Every begin first, then every finish. A second begin for one person would
// replace that person's challenge; a begin for somebody else must not.
async function enrolAll(admin, people) {
  log.debug("Entering enrolAll().");
  const started = Date.now();
  const armed = [];
  for (let i = 0; i < people.length; i++) {
    const person = people[i];
    const authenticator = makeAuthenticator();
    const begun = await beginFor(admin, person.username);
    assert.strictEqual(begun.status, 200,
      person.username + " begin " + snippet(begun));
    const ceremony = begun.json && begun.json.ceremony;
    assert.ok(ceremony && ceremony.challenge && ceremony.user &&
      ceremony.user.id, person.username + " ceremony " + snippet(begun));
    armed.push({ person: person, begun: begun, ceremony: ceremony,
                 authenticator: authenticator });
  }
  const finished = [];
  for (let i = 0; i < armed.length; i++) {
    const one = armed[i];
    const credential = one.authenticator.register(one.ceremony.challenge,
                                                   one.ceremony.user.id);
    const done = await finishFor(admin, one.person.username,
      one.begun.json.enrolmentId, credential);
    assert.strictEqual(done.status, 200,
      one.person.username + " finish " + snippet(done));
    finished.push({ person: one.person, begun: one.begun,
                    authenticator: one.authenticator,
                    credential: credential, done: done });
    log.info("enrolled " + (i + 1) + "/" + armed.length + " " +
             one.person.username + ".");
  }
  log.info("enrolled " + finished.length + " passkeys in " +
           (Date.now() - started) + "ms.");
  log.debug("Leaving enrolAll().");
  return finished;
}

async function test() {
  log.debug("Entering test().");
  log.info("=== " + COUNT + " people, one passkey each, realm " + REALM +
           " ===");
  const made = await call("POST", "/realms/create",
    { id: REALM, domain: DOMAIN, name: "passkey bulk (#957)" }, serviceApi);
  assert.strictEqual(made.status, 200, "creating the realm " + REALM +
    " answered " + made.status + " " + snippet(made));
  await fixtures.publicClient(api, CLIENT, [REDIRECT]);

  const people = [];
  for (let i = 0; i < COUNT; i++) {
    people.push({ username: usernameFor("pkbulk-" + i) });
  }
  await createPeople(people);
  check(COUNT + " PEOPLE CREATED THROUGH POST /admin-api/users/create, " +
        "invent:false, ONE AT A TIME", function () {
    assert.strictEqual(people.length, COUNT);
    const names = {};
    people.forEach(function (person) {
      names[person.username] = true;
    });
    assert.strictEqual(Object.keys(names).length, COUNT,
      "two of the generated usernames collided.");
  });

  log.info("=== adminEnrolment off, then on ===");
  const switchedOff = await call("POST", "/users/begin-passkey-enrolment", {
    user: people[0].username, lane: "classical", kind: "passkey" });
  check("WHILE adminEnrolment IS OFF, BEGIN IS REFUSED AND NAMES THE SWITCH",
        function () {
    assert.strictEqual(switchedOff.status, 400, snippet(switchedOff));
    assert.ok(snippet(switchedOff).indexOf("adminEnrolment") >= 0,
      snippet(switchedOff));
  });

  const policyPage = await call("GET", "/policies");
  assert.ok(policyPage.status === 200 && policyPage.body &&
    policyPage.body.passkey &&
    Array.isArray(policyPage.body.passkey.fields),
    "GET /policies answered " + snippet(policyPage));
  const policyDefaults = {};
  policyPage.body.passkey.fields.forEach(function (field) {
    policyDefaults[field.key] = field.default;
  });
  const enabled = await call("POST", "/policies/save-passkey-policy",
    Object.assign({ profile: "default" }, policyDefaults,
                   { adminEnrolment: "on" }));
  const serviceToken = await call("POST", "/users/begin-passkey-enrolment", {
    user: people[0].username, lane: "classical", kind: "passkey" });
  check("THE POLICY TURNS adminEnrolment ON, AND THE SERVICE TOKEN IS STILL " +
        "REFUSED: ITS SUBJECT IS NOT A PERSON", function () {
    assert.ok(enabled.status === 200 && enabled.body &&
              enabled.body.ok !== false, snippet(enabled));
    assert.strictEqual(serviceToken.status, 400, snippet(serviceToken));
    assert.ok(snippet(serviceToken).indexOf("subject is a person") >= 0,
      snippet(serviceToken));
  });

  const admin = await consoleSignin.signInToTheConsole(base, ADMIN, log,
                                                       { grant: "write" });
  const missingName = usernameFor("pkbulk-missing");
  const missing = await beginFor(admin, missingName);
  check("A NAME NOBODY HOLDS IS REFUSED, AND NOTHING IS STARTED", function () {
    assert.strictEqual(missing.status, 400, snippet(missing));
    assert.ok(/nobody called/.test(snippet(missing)), snippet(missing));
  });

  log.info("=== one ceremony per person ===");
  const finished = await enrolAll(admin, people);
  const reads = [];
  for (let i = 0; i < finished.length; i++) {
    const one = finished[i];
    const got = await admin.api("GET", "/admin-api/users?user=" +
      encodeURIComponent(one.person.username));
    reads.push(got);
  }
  check("EACH FINISH STORES A DISTINCT CREDENTIAL, enrolledBy NAMES THE " +
        "ADMINISTRATOR, AND GET /admin-api/users LISTS THE ID", function () {
    const ids = {};
    const handles = {};
    finished.forEach(function (one, index) {
      const body = one.done.json || {};
      assert.strictEqual(body.ok, true, snippet(one.done));
      assert.strictEqual(body.credentialId, one.authenticator.credentialId);
      assert.strictEqual(body.lane, "classical", snippet(one.done));
      assert.strictEqual(body.held, 1, snippet(one.done));
      assert.ok(body.enrolledBy && body.enrolledBy.username === ADMIN &&
        body.enrolledBy.at > 0 && body.enrolledBy.sub,
        snippet(one.done));
      assert.ok(ids[body.credentialId] === undefined, body.credentialId);
      ids[body.credentialId] = true;
      const handle = one.begun.json.ceremony.user.id;
      assert.ok(handles[handle] === undefined, handle);
      handles[handle] = true;
      assert.ok(one.begun.json.ceremony.options.algorithms.indexOf(-7) >= 0,
        JSON.stringify(one.begun.json.ceremony.options.algorithms));
      const got = reads[index];
      const keys = (got.json && got.json.factors && got.json.factors.keys) ||
                   [];
      assert.strictEqual(got.status, 200, snippet(got));
      assert.ok(keys.some(function (key) {
        return key.credentialId === body.credentialId;
      }), one.person.username + " " + JSON.stringify(keys).slice(0, 300));
    });
    assert.strictEqual(Object.keys(ids).length, COUNT);
  });

  log.info("=== one of the keys signs its person in ===");
  const signedIn = await withoutAUsername(function (challenge) {
    return finished[0].authenticator.assert(challenge);
  });
  check("A USERNAMELESS SIGN-IN WITH THE FIRST KEY SIGNS THAT PERSON IN",
        function () {
    assert.strictEqual(signedIn.next, "redirect",
      JSON.stringify(signedIn.json).slice(0, 300));
  });

  log.info("=== a registration cannot be copied, and a finish is single " +
           "use ===");
  const source = finished[0];
  const target = finished[1];
  const copiedBegin = await beginFor(admin, target.person.username);
  assert.strictEqual(copiedBegin.status, 200, snippet(copiedBegin));
  const copied = await finishFor(admin, target.person.username,
    copiedBegin.json.enrolmentId, source.credential);
  const copiedAgain = await finishFor(admin, target.person.username,
    copiedBegin.json.enrolmentId, makeAuthenticator().register(
      copiedBegin.json.ceremony.challenge,
      copiedBegin.json.ceremony.user.id));
  check("ANOTHER PERSON'S REGISTRATION IS REFUSED, AND THE ENROLMENT IS " +
        "SPENT, SO THE REAL CEREMONY CANNOT FINISH IT EITHER", function () {
    assert.strictEqual(copied.status, 400, snippet(copied));
    assert.strictEqual(copiedAgain.status, 400, snippet(copiedAgain));
    assert.ok(/no enrolment|already|cancelled|Start again/i
      .test(snippet(copiedAgain)), snippet(copiedAgain));
  });

  const garbageBegin = await beginFor(admin, source.person.username);
  assert.strictEqual(garbageBegin.status, 200, snippet(garbageBegin));
  const garbage = await finishFor(admin, source.person.username,
    garbageBegin.json.enrolmentId, JSON.stringify({
      id: "not-a-credential", type: "public-key", response: {} }));
  const garbageAgain = await finishFor(admin, source.person.username,
    garbageBegin.json.enrolmentId, makeAuthenticator().register(
      garbageBegin.json.ceremony.challenge,
      garbageBegin.json.ceremony.user.id));
  check("A CREDENTIAL THAT IS NOT A CEREMONY IS REFUSED, AND THAT " +
        "ENROLMENT IS SPENT TOO", function () {
    assert.strictEqual(garbage.status, 400, snippet(garbage));
    assert.strictEqual(garbageAgain.status, 400, snippet(garbageAgain));
    assert.ok(/no enrolment|already|cancelled|Start again/i
      .test(snippet(garbageAgain)), snippet(garbageAgain));
  });

  log.info("=== the key cap ===");
  const capped = await setting("webauthn.maxKeysPerPerson", 1);
  const over = await beginFor(admin, source.person.username);
  check("WITH webauthn.maxKeysPerPerson AT 1, A PERSON WHO ALREADY HOLDS A " +
        "KEY CANNOT BEGIN ANOTHER", function () {
    assert.ok(capped.status === 200 && capped.body && capped.body.ok !== false,
      snippet(capped));
    assert.strictEqual(over.status, 400, snippet(over));
    assert.ok(snippet(over).indexOf("maxKeysPerPerson") >= 0, snippet(over));
  });

  assert.ok(checks >= 9, "only " + checks + " checks ran; a section has " +
            "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_passkey_bulk_enrolment")
  .description("Many people created through POST /admin-api/users/create, " +
      "and one ES256 passkey enrolled for each through begin-passkey-" +
      "enrolment and finish-passkey-enrolment (#957).")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
