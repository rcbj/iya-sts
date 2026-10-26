// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

// ===========================================================================
// sts_passkey_dual_lane.js — A CLASSICAL PASSKEY AND A POST-QUANTUM ONE SIDE
// BY SIDE (#643), over HTTP, in every mode the suite runs.
//
// `tests/passkey_dual_lane.js` holds the same design in process; this is the
// protocol half, so the product mode, the cluster and an AWS target see it
// too (tests/CLAUDE.md, *where a new test goes*). It is `local: true`:
// written here, never vendored from the parent.
//
// **ALL OF IT IN A THROWAWAY REALM OF ITS OWN**, because the switch,
// `webauthn.pqcAlongsideClassical`, is per realm and changes what every
// passkey enrolment there offers; turned on in the default realm it would be
// on for every job enrolling a passkey meanwhile. The realm is left behind
// afterwards, as every job's is.
//
// The person signs in to the realm's portal with a password and enrols both
// passkeys through `/account-api/keys`, the portal's only door, with two
// software authenticators of this file's own — one ES256, one ML-DSA-65
// (`./pqc.js`'s noble primitives) — each keeping the user handle it was
// created under and handing it back on every assertion, as a discoverable
// credential does:
//
//   A. the switch cannot be on beside `webauthn.pqcOnly` (refused at the
//      write), and on, the page offers both lanes;
//   B. each lane's ceremony carries its own user handle, its own algorithms
//      (ML-DSA alone in the post-quantum lane, none in the classical one) and
//      its own name — `<username>+ml-dsa` / `(ML-DSA)` for the post-quantum
//      lane at creation;
//   C. both keys are registered, each row saying its lane, and the Signal
//      API's data is one entry per lane, the post-quantum one named for its
//      algorithm, `<username>+ml-dsa-65`;
//   D. a usernameless sign-in with EITHER key signs the person in;
//   E. the post-quantum key returning the classical handle signs nobody in;
//   F. a typed `<username>+ml-dsa-65` is refused at the screen
//      (STS-AUTHN-0354);
//   G. switched off, a new post-quantum enrolment is refused and the
//      post-quantum key still signs in.
// ===========================================================================

// The sign-in screen over `/authn-api` (#571).
const authnSignin = require("./authn_signin");
const assert = require("assert");
const nodeCrypto = require("crypto");
const { Command, Option } = require("commander");
const { usernameFor } = require("./random_username.js");
const fixtures = require("./oauth_fixtures.js");
const portalSignin = require("./portal_signin.js");
const consoleSignin = require("./console_signin.js");
const pqc = require("./pqc.js");

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
var log = bunyan.createLogger({ name: "sts_passkey_dual_lane",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug('CONFIG_FILE could not be read, so the configuration is empty: ' +
            appconfigProblem.message);
}
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");
// THE REALM (see the header): every request below goes to it.
var REALM = usernameFor("pkdual").replace(/[^a-z0-9-]/g, "").slice(0, 30);
var DOMAIN = REALM + ".example.net";
var serviceApi = base + "/admin-api";
base = base + "/realm/" + REALM;
var api = base + "/admin-api";

// The origin and RP ID from the service's own base, for
// `sts_webauthn_second_factor.js`'s reason: both are compared byte for byte.
var ORIGIN = new URL(base).origin;
var RP_ID = new URL(base).hostname;

var PERSON = usernameFor("passkey-dual");
var ADMIN = usernameFor("passkey-upgrade-admin");
var PASSWORD = "Dual-lane " + nodeCrypto.randomBytes(12).toString("hex") +
               " !9";
var CLIENT = "pk-dual-probe";
var REDIRECT = "http://localhost:9999/cb";
var SWITCH = "webauthn.pqcAlongsideClassical";

var checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  ✓ " + what);
  log.debug("Leaving check().");
}

// ---------------------------------------------------------------------------
// CBOR, encode only: the attestation object and the COSE keys. An ML-DSA-65
// public key is 1952 bytes, so lengths go past one byte.
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

// ---------------------------------------------------------------------------
// THE AUTHENTICATOR: ES256 (`-7`) or ML-DSA-65 (`-49`), holding the user
// handle it was created under. Written here, on `sts_dpop.js`'s rule: two
// ends of one exchange from one implementation would let a shared
// misunderstanding pass.
// ---------------------------------------------------------------------------
function makeAuthenticator(alg) {
  log.debug("Entering makeAuthenticator(). alg=" + alg);
  const credentialId = nodeCrypto.randomBytes(32);
  let cose;
  let sign;
  if (alg === -49) {
    const pair = pqc.generateAkpKeyPair("ML-DSA-65");
    cose = new Map([[1, 7], [3, -49], [-1, Buffer.from(pair.pub)]]);
    sign = function (data) {
      log.debug("Entering sign() (ML-DSA-65).");
      log.debug("Leaving sign() (ML-DSA-65).");
      return Buffer.from(pqc.signWithPriv("ML-DSA-65", new Uint8Array(data),
                                          pair.priv));
    };
  } else {
    const pair = nodeCrypto.generateKeyPairSync("ec",
                                                { namedCurve: "prime256v1" });
    const jwk = pair.publicKey.export({ format: "jwk" });
    cose = new Map([[1, 2], [3, -7], [-1, 1],
                    [-2, Buffer.from(jwk.x, "base64url")],
                    [-3, Buffer.from(jwk.y, "base64url")]]);
    sign = function (data) {
      log.debug("Entering sign() (ES256).");
      log.debug("Leaving sign() (ES256).");
      return nodeCrypto.sign("sha256", data, pair.privateKey);
    };
  }
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
      // UP, UV and AT.
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
    assert: function (challenge, opts) {
      log.debug("Entering assert().");
      const o = opts || {};
      signCount += 1;
      const count = Buffer.alloc(4);
      count.writeUInt32BE(signCount, 0);
      // UP and UV.
      const authData = Buffer.concat([sha256(Buffer.from(RP_ID, "utf8")),
                                      Buffer.from([0x05]), count]);
      const cdj = clientData("webauthn.get", challenge);
      const signature = sign(Buffer.concat([authData, sha256(cdj)]));
      log.debug("Leaving assert().");
      return {
        id: id, rawId: id, type: "public-key",
        authenticatorAttachment: "platform",
        response: {
          authenticatorData: authData.toString("base64url"),
          clientDataJSON: cdj.toString("base64url"),
          signature: Buffer.from(signature).toString("base64url"),
          userHandle: o.handle === undefined ? userHandle : o.handle } };
    }
  };
}

// ---------------------------------------------------------------------------
// THE VERBS.
// ---------------------------------------------------------------------------
function form(o) {
  log.debug("Entering form().");
  log.debug("Leaving form().");
  return new URLSearchParams(o).toString();
}

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
    // An HTML error page from a door that answers JSON is worth quoting whole.
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

async function codeCount(code) {
  log.debug("Entering codeCount().");
  const r = await call("GET", "/audit?per=500&code=" +
                       encodeURIComponent(code));
  const body = r.body && typeof r.body === "object" ? r.body : {};
  log.debug("Leaving codeCount().");
  return Number(body.matched || (body.rows || body.events || []).length || 0);
}

// The sign-in screen of an authorization request, its passkey ceremony
// armed (a pending record exists only there).
async function theSignInScreen() {
  log.debug("Entering theSignInScreen().");
  const challenge = fixtures.pkce();
  const started = await fetch(base + "/oauth2/authorize?" + form({
    client_id: CLIENT, redirect_uri: REDIRECT, response_type: "code",
    scope: "openid", code_challenge: challenge.challenge,
    code_challenge_method: challenge.method }), { redirect: "manual" });
  const location = started.headers.get("location") || "";
  assert.ok(/\/authn\/login\?authn=/.test(location),
    "the authorization endpoint did not send us to the sign-in screen: " +
    started.status + " " + location);
  // The cookie the authorization endpoint set, which the screen is bound
  // to, as a browser would carry it.
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

// A usernameless sign-in with an assertion `make(challenge)` produces.
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

// An enrolment at `/account-api/keys`: begun in a lane, the armed ceremony
// read back, answered by `authenticator`.
async function enrol(client, authenticator, lane) {
  log.debug("Entering enrol(). lane=" + lane);
  const begun = await client.api("POST", "/account-api/keys",
    { action: "begin", role: "primary", kind: "passkey", lane: lane });
  if (!(begun.status === 200 && begun.json && begun.json.ok)) {
    log.debug("Leaving enrol(). Not begun.");
    return { begun: begun, pending: null, done: null };
  }
  const page = await client.api("GET", "/account-api/keys");
  const pending = (page.json && page.json.enrol &&
                   page.json.enrol.pending) || {};
  const done = await client.api("POST", "/account-api/keys",
    { action: "finish", enrolment_id: pending.id,
      credential: JSON.stringify(authenticator.register(pending.challenge,
                                                        pending.userHandle)) });
  log.debug("Leaving enrol().");
  return { begun: begun, pending: pending, done: done };
}

async function test() {
  log.debug("Entering test().");
  const made = await call("POST", "/realms/create",
    { id: REALM, domain: DOMAIN, name: "passkey lanes (#643)" }, serviceApi);
  assert.strictEqual(made.status, 200, "creating the realm " + REALM +
    " answered " + made.status + " " + String(made.raw).slice(0, 300));
  await fixtures.publicClient(api, CLIENT, [REDIRECT]);
  const created = await call("POST", "/users/create", {
    username: PERSON, invent: false, credential: "password",
    password: PASSWORD,
    attributes: { cn: "Dual Lane " + PERSON, givenName: "Dual", sn: PERSON,
                  mail: PERSON + "@passkey-dual.test" } });
  assert.ok(created.status === 200 && created.body && created.body.ok,
    "creating " + PERSON + " answered " + created.status + " " +
    String(created.raw).slice(0, 300));

  // A. The switch, and pqcOnly beside it.
  log.info("=== the switch ===");
  const on = await setting(SWITCH, true);
  const both = await setting("webauthn.pqcOnly", true);
  check("THE SWITCH IS ON IN THE REALM, AND webauthn.pqcOnly BESIDE IT IS " +
        "REFUSED AT THE WRITE", function () {
    assert.ok(on.status === 200 && on.body && on.body.ok !== false,
      "turning the switch on answered " + on.status + " " +
      String(on.raw).slice(0, 300));
    assert.ok(both.status !== 200 || (both.body && both.body.ok === false),
      "pqcOnly beside the switch was accepted: " + both.status + " " +
      String(both.raw).slice(0, 300));
  });

  const client = await portalSignin.signInToThePortal(base, PERSON, null,
                                                      { password: PASSWORD });
  let page = await client.api("GET", "/account-api/keys");
  check("THE PASSKEY PAGE OFFERS BOTH LANES", function () {
    assert.strictEqual(page.status, 200, String(page.text).slice(0, 300));
    assert.deepStrictEqual(page.json.enrol.lanes, ["classical", "pqc"]);
  });

  // B and C. Both lanes, one person.
  log.info("=== a classical passkey and a post-quantum one ===");
  const classical = makeAuthenticator(-7);
  const postQuantum = makeAuthenticator(-49);
  const c = await enrol(client, classical, "classical");
  const p = await enrol(client, postQuantum, "pqc");
  check("EACH LANE'S CEREMONY HAS ITS OWN HANDLE, ITS OWN ALGORITHMS AND ITS " +
        "OWN NAME: <username>+ml-dsa and (ML-DSA) for the post-quantum lane " +
        "at creation", function () {
    assert.ok(c.pending && p.pending, "an enrolment was not begun: " +
      JSON.stringify([c.begun.json, p.begun.json]).slice(0, 400));
    assert.ok(/^[A-Za-z0-9_-]{86}$/.test(c.pending.userHandle) &&
              /^[A-Za-z0-9_-]{86}$/.test(p.pending.userHandle));
    assert.notStrictEqual(c.pending.userHandle, p.pending.userHandle);
    assert.deepStrictEqual(p.pending.options.algorithms, [-48, -49, -50]);
    assert.ok(c.pending.options.algorithms.every(function (a) {
      return [-48, -49, -50].indexOf(a) < 0;
    }), "the classical lane offers ML-DSA: " +
        JSON.stringify(c.pending.options.algorithms));
    assert.strictEqual(c.pending.user, PERSON);
    assert.strictEqual(p.pending.user, PERSON + "+ml-dsa");
    assert.ok(/ \(ML-DSA\)$/.test(p.pending.display), p.pending.display);
    assert.deepStrictEqual(p.pending.exclude, [],
      "the post-quantum lane excluded the classical key.");
  });
  page = await client.api("GET", "/account-api/keys");
  const keys = (page.json && page.json.keys) || [];
  const signals = (page.json && page.json.signals) || [];
  const signalOf = function (lane) {
    return signals.filter(function (one) {
      return one.lane === lane;
    })[0] || {};
  };
  check("BOTH ARE REGISTERED, EACH ROW SAYING ITS LANE, AND THE SIGNAL API'S " +
        "DATA IS ONE ENTRY PER LANE — the post-quantum one named " +
        "<username>+ml-dsa-65", function () {
    assert.ok(c.done.status === 200 && p.done.status === 200,
      "a registration answered " + c.done.status + " / " + p.done.status +
      " " + JSON.stringify([c.done.json, p.done.json]).slice(0, 400));
    assert.deepStrictEqual(keys.map(function (one) {
      return one.lane;
    }).sort(), ["classical", "pqc"]);
    assert.strictEqual(signals.length, 2, JSON.stringify(signals));
    assert.strictEqual(signalOf("classical").userId, c.pending.userHandle);
    assert.strictEqual(signalOf("pqc").userId, p.pending.userHandle);
    assert.deepStrictEqual(signalOf("classical").accepted,
                           [classical.credentialId]);
    assert.deepStrictEqual(signalOf("pqc").accepted,
                           [postQuantum.credentialId]);
    assert.strictEqual(signalOf("classical").name, PERSON);
    assert.strictEqual(signalOf("pqc").name, PERSON + "+ml-dsa-65");
  });

  // #939: the same proof-first upgrade, through the administrator's own
  // person-bound console token, with two authenticator ceremonies.
  const administrator = await consoleSignin.signInToTheConsole(base, ADMIN,
    log, { grant: "write" });
  const upgradeBegin = await administrator.api("POST",
    "/admin-api/users/begin-passkey-upgrade", {
      user: PERSON, credentialId: classical.credentialId });
  const upgradeCeremony = upgradeBegin.json && upgradeBegin.json.ceremony;
  const upgradeProof = upgradeCeremony
    ? await administrator.api("POST",
        "/admin-api/users/prove-passkey-upgrade", {
          user: PERSON, upgradeId: upgradeBegin.json.upgradeId,
          credential: JSON.stringify(classical.assert(
            upgradeCeremony.challenge)) }) : { status: 0, json: null };
  const registrationCeremony = upgradeProof.json &&
                               upgradeProof.json.ceremony;
  const adminUpgraded = makeAuthenticator(-49);
  const upgradeFinish = registrationCeremony
    ? await administrator.api("POST",
        "/admin-api/users/finish-passkey-upgrade", {
          user: PERSON, upgradeId: upgradeBegin.json.upgradeId,
          credential: JSON.stringify(adminUpgraded.register(
            registrationCeremony.challenge,
            registrationCeremony.user.id)) })
    : { status: 0, json: null };
  const afterAdminUpgrade = await administrator.api("GET",
    "/admin-api/users?user=" + encodeURIComponent(PERSON));
  const adminKeys = afterAdminUpgrade.json &&
    afterAdminUpgrade.json.factors && afterAdminUpgrade.json.factors.keys || [];
  check("AN ADMINISTRATOR PROVES THE CLASSICAL KEY, THEN REGISTERS ML-DSA " +
        "THROUGH THEIR PERSON-BOUND CONSOLE TOKEN", function () {
    assert.strictEqual(upgradeBegin.status, 200,
      JSON.stringify(upgradeBegin.json).slice(0, 300));
    assert.deepStrictEqual(registrationCeremony.options.algorithms,
                           [-48, -49, -50]);
    assert.ok(upgradeProof.status === 200 &&
              registrationCeremony.user.id !== c.pending.userHandle,
      JSON.stringify(upgradeProof.json).slice(0, 300));
    assert.strictEqual(upgradeFinish.status, 200,
      JSON.stringify(upgradeFinish.json).slice(0, 300));
    assert.strictEqual(upgradeFinish.json.mode, "alongside");
    assert.ok(adminKeys.some(function (one) {
      return one.credentialId === adminUpgraded.credentialId;
    }), JSON.stringify(adminKeys).slice(0, 500));
    assert.ok(adminKeys.some(function (one) {
      return one.credentialId === classical.credentialId;
    }), "the previous classical passkey disappeared");
  });

  // #945: the admin-only policy is off by default; once enabled, an
  // administrator person token runs the ceremony in their own console.
  const firstAdminAttempt = await call("POST",
    "/users/begin-passkey-enrolment", { user: PERSON, lane: "pqc",
      role: "mfa", kind: "passkey" });
  const policyPage = await call("GET", "/policies");
  const policyDefaults = {};
  (policyPage.body.passkey.fields || []).forEach(function (field) {
    policyDefaults[field.key] = field.default;
  });
  const enabledAdminEnrolment = await call("POST",
    "/policies/save-passkey-policy", Object.assign({ profile: "default" },
      policyDefaults, { adminEnrolment: "on" }));
  const appCallerAfterEnable = await call("POST",
    "/users/begin-passkey-enrolment", { user: PERSON, lane: "pqc",
      role: "mfa", kind: "passkey" });
  const personAdmin = await consoleSignin.signInToTheConsole(base, ADMIN,
    log, { grant: "write" });
  // The console is a static application: page() is the API answer the
  // page is drawn from, and the enrolment control is markup
  // (`data-admin-passkey-enrolment`), so the assertion reads draw().
  const adminPage = await personAdmin.draw("/admin/users", { user: PERSON });
  const adminBegin = await personAdmin.api("POST",
    "/admin-api/users/begin-passkey-enrolment", { user: PERSON,
      lane: "pqc", role: "mfa", kind: "passkey" });
  const adminCeremony = adminBegin.json && adminBegin.json.ceremony;
  const adminAuthenticator = makeAuthenticator(-49);
  const adminFinish = adminCeremony
    ? await personAdmin.api("POST",
        "/admin-api/users/finish-passkey-enrolment", { user: PERSON,
          enrolmentId: adminBegin.json.enrolmentId,
          credential: JSON.stringify(adminAuthenticator.register(
            adminCeremony.challenge, adminCeremony.user.id)) })
    : { status: 0, json: null };
  check("ADMIN PASSKEY ENROLMENT IS OFF BY DEFAULT, THEN AVAILABLE IN THE " +
        "CONSOLE ONLY TO A PERSON TOKEN, AND RECORDS WHO ENROLLED IT",
        function () {
    assert.ok(firstAdminAttempt.status === 400 &&
              JSON.stringify(firstAdminAttempt.body).indexOf("adminEnrolment")
                >= 0,
      JSON.stringify(firstAdminAttempt.body).slice(0, 300));
    assert.ok(enabledAdminEnrolment.status === 200 &&
              enabledAdminEnrolment.body.ok !== false,
      JSON.stringify(enabledAdminEnrolment.body).slice(0, 300));
    assert.strictEqual(appCallerAfterEnable.status, 400,
      JSON.stringify(appCallerAfterEnable.body).slice(0, 300));
    assert.ok(/data-admin-passkey-enrolment/.test(adminPage.html || ""),
      "the person's admin detail page did not draw the enrollment control");
    assert.strictEqual(adminBegin.status, 200,
      JSON.stringify(adminBegin.json).slice(0, 300));
    assert.deepStrictEqual(adminCeremony.options.algorithms, [-48, -49, -50]);
    assert.strictEqual(adminFinish.status, 200,
      JSON.stringify(adminFinish.json).slice(0, 300));
     assert.strictEqual(adminFinish.json.enrolledBy.username, ADMIN);
    assert.ok(adminFinish.json.enrolledBy.at > 0);
    assert.strictEqual(adminFinish.json.lane, "pqc");
  });

  // D. Either key, one person.
  log.info("=== signing in with either, and no username ===");
  let r = await withoutAUsername(function (challenge) {
    return classical.assert(challenge);
  });
  const viaClassical = r.next;
  r = await withoutAUsername(function (challenge) {
    return postQuantum.assert(challenge);
  });
  check("A USERNAMELESS SIGN-IN WITH EITHER KEY SIGNS THE PERSON IN — each " +
        "handle names the same account", function () {
    assert.strictEqual(viaClassical, "redirect");
    assert.strictEqual(r.next, "redirect", JSON.stringify(r.json)
      .slice(0, 300));
  });

  // E. The wrong handle.
  r = await withoutAUsername(function (challenge) {
    return postQuantum.assert(challenge, { handle: c.pending.userHandle });
  });
  check("THE POST-QUANTUM KEY RETURNING THE CLASSICAL HANDLE SIGNS NOBODY IN " +
        "(section 7.2 step 6)", function () {
    assert.strictEqual(r.next, "refused", JSON.stringify(r.json)
      .slice(0, 300));
  });

  // F. The lane's name typed.
  const before = await codeCount("STS-AUTHN-0354");
  const s = await theSignInScreen();
  r = await authnSignin.submit(base, s.opened.id,
    { action: "login", username: PERSON + "+ml-dsa-65", password: PASSWORD },
    { screen: s.opened, cookie: s.opened.cookie });
  const after = await codeCount("STS-AUTHN-0354");
  check("THE POST-QUANTUM PASSKEY'S NAME TYPED AT THE SCREEN IS REFUSED " +
        "(STS-AUTHN-0354)", function () {
    assert.strictEqual(r.next, "refused", JSON.stringify(r.json)
      .slice(0, 300));
    assert.ok(after > before, "no new STS-AUTHN-0354 row (" + before +
              " then " + after + ").");
  });

  // G. Off again.
  log.info("=== the switch off ===");
  const off = await setting(SWITCH, false);
  const refused = await client.api("POST", "/account-api/keys",
    { action: "begin", role: "primary", kind: "passkey", lane: "pqc" });
  r = await withoutAUsername(function (challenge) {
    return postQuantum.assert(challenge);
  });
  check("SWITCHED OFF, A NEW POST-QUANTUM ENROLMENT IS REFUSED AND THE " +
        "POST-QUANTUM KEY STILL SIGNS IN", function () {
    assert.ok(off.status === 200, String(off.raw).slice(0, 300));
    assert.strictEqual(refused.status, 400, String(refused.text)
      .slice(0, 300));
    assert.strictEqual(r.next, "redirect", JSON.stringify(r.json)
      .slice(0, 300));
  });

  assert.ok(checks >= 9, "only " + checks + " checks ran; a section has " +
            "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_passkey_dual_lane")
  .description("A classical and a post-quantum passkey side by side for one " +
      "person (#643): each lane's handle, algorithms and name, both " +
      "registered at /account-api/keys, the Signal API's data per lane, a " +
      "usernameless sign-in with either, the wrong handle refused, the " +
      "lane's name refused at the screen, and the switch turned off.")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
