// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

// ===========================================================================
// sts_passkey_post_quantum_required.js — A POST-QUANTUM PASSKEY REQUIRED BY
// THE PASSKEY POLICY (#718), over HTTP, in every mode the suite runs.
//
// `tests/passkey_post_quantum_required.js` holds the same design in
// process; this is the protocol half, so the product mode, the cluster and
// an AWS target see it too (tests/CLAUDE.md, *where a new test goes*). It
// is `local: true`: written here, never vendored from the parent.
//
// **ALL OF IT IN A THROWAWAY REALM OF ITS OWN**, because the row it sets,
// `postQuantumRequired`, is on the realm's `default` passkey policy and
// would hold every job's passkeys meanwhile. The realm is left behind
// afterwards, as every job's is.
//
// The person signs in to the realm's portal with a password and enrols two
// passkeys through `/account-api/keys` with #643's switch OFF — so neither
// row records a lane — from two software authenticators of this file's
// own, one ES256 and one ML-DSA-65 (`./pqc.js`'s noble primitives). Then
// the row is set through `POST /admin-api/policies/save-passkey-policy`,
// the one door, and each kind of key signs in:
//
//   A. a save requiring it is refused while the realm offers no ML-DSA
//      (`webauthn.algorithms` naming none), and accepted once it does;
//   B. `sign-in`: a usernameless sign-in with the ES256 key is refused
//      (STS-AUTHN-0356 on an audit row), and the ML-DSA-65 key — whose row
//      records no lane — signs the person in: the ALGORITHM decides;
//   C. `/account-api/keys` marks the ES256 key and not the ML-DSA one, and
//      the console's `GET /admin-api/users?user=` carries the refusal
//      beside the ES256 key only;
//   D. `registration-and-sign-in`: an enrolment offers only ML-DSA, and an
//      ES256 registration is refused;
//   E. `off` again: the ES256 key signs in.
// ===========================================================================

// The sign-in screen over `/authn-api` (#571).
const authnSignin = require("./authn_signin");
const assert = require("assert");
const nodeCrypto = require("crypto");
const { Command, Option } = require("commander");
const { usernameFor } = require("./random_username.js");
const fixtures = require("./oauth_fixtures.js");
const portalSignin = require("./portal_signin.js");
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
var log = bunyan.createLogger({ name: "sts_passkey_post_quantum_required",
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
var REALM = usernameFor("pkpq").replace(/[^a-z0-9-]/g, "").slice(0, 30);
var DOMAIN = REALM + ".example.net";
var serviceApi = base + "/admin-api";
base = base + "/realm/" + REALM;
var api = base + "/admin-api";

// The origin and RP ID from the service's own base, for
// `sts_webauthn_second_factor.js`'s reason: both are compared byte for byte.
var ORIGIN = new URL(base).origin;
var RP_ID = new URL(base).hostname;

var PERSON = usernameFor("passkey-pq");
var PASSWORD = "Post-quantum " + nodeCrypto.randomBytes(12).toString("hex") +
               " !9";
var CLIENT = "pk-pq-probe";
var REDIRECT = "http://localhost:9999/cb";

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
    lane ? { action: "begin", role: "primary", kind: "passkey", lane: lane }
         : { action: "begin", role: "primary", kind: "passkey" });
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

// The passkey policy's built-in rows, read off `GET /admin-api/policies`, so
// a save sends every field as the door requires.
async function defaultRows() {
  log.debug("Entering defaultRows().");
  const policies = await call("GET", "/policies");
  assert.ok(policies.status === 200 && policies.body.passkey &&
            Array.isArray(policies.body.passkey.fields),
            "GET /policies answered " + policies.status + " " +
            String(policies.raw).slice(0, 300));
  const out = {};
  policies.body.passkey.fields.forEach(function (field) {
    out[field.key] = field.default;
  });
  log.debug("Leaving defaultRows().");
  return out;
}

// The realm's `default` profile saved with `postQuantumRequired` set.
async function requirement(defaults, value) {
  log.debug("Entering requirement(). " + value);
  const r = await call("POST", "/policies/save-passkey-policy",
    Object.assign({}, defaults, { allowUsernameless: true,
                                  postQuantumRequired: value }));
  log.debug("Leaving requirement(). " + r.status);
  return r;
}

// One key row of the person's, off a list of rows.
function rowOf(rows, credentialId) {
  log.debug("Entering rowOf().");
  log.debug("Leaving rowOf().");
  return (rows || []).filter(function (one) {
    return one.credentialId === credentialId;
  })[0] || null;
}

async function test() {
  log.debug("Entering test().");
  const made = await call("POST", "/realms/create",
    { id: REALM, domain: DOMAIN, name: "post-quantum passkeys (#718)" },
    serviceApi);
  assert.strictEqual(made.status, 200, "creating the realm " + REALM +
    " answered " + made.status + " " + String(made.raw).slice(0, 300));
  await fixtures.publicClient(api, CLIENT, [REDIRECT]);
  const created = await call("POST", "/users/create", {
    username: PERSON, invent: false, credential: "password",
    password: PASSWORD,
    attributes: { cn: "Post Quantum " + PERSON, givenName: "Post",
                  sn: PERSON, mail: PERSON + "@passkey-pq.test" } });
  assert.ok(created.status === 200 && created.body && created.body.ok,
    "creating " + PERSON + " answered " + created.status + " " +
    String(created.raw).slice(0, 300));

  // The two keys, with the lanes off.
  const client = await portalSignin.signInToThePortal(base, PERSON, null,
                                                      { password: PASSWORD });
  const classical = makeAuthenticator(-7);
  const postQuantum = makeAuthenticator(-49);
  const c = await enrol(client, classical, "");
  const p = await enrol(client, postQuantum, "");
  let page = await client.api("GET", "/account-api/keys");
  check("(AN ES256 KEY AND AN ML-DSA-65 KEY ARE REGISTERED WITH THE LANES " +
        "OFF: one lane, every row classical by the lane)", function () {
    assert.ok(c.done && p.done && c.done.status === 200 &&
              p.done.status === 200,
      "a registration answered " + JSON.stringify([c.begun.json,
        c.done && c.done.json, p.begun.json, p.done && p.done.json])
        .slice(0, 500));
    assert.deepStrictEqual(page.json.enrol.lanes, ["classical"]);
    assert.deepStrictEqual((page.json.keys || []).map(function (one) {
      return one.lane;
    }), ["classical", "classical"]);
  });

  // A. The save.
  log.info("=== the save ===");
  const defaults = await defaultRows();
  const narrowed = await setting("webauthn.algorithms", "ES256,RS256");
  const refused = await requirement(defaults, "sign-in");
  const widened = await setting("webauthn.algorithms", "ML-DSA-65,ES256");
  const accepted = await requirement(defaults, "sign-in");
  check("A. REQUIRING A POST-QUANTUM PASSKEY WHILE THE REALM OFFERS NO " +
        "ML-DSA IS REFUSED AT THE SAVE, AND ACCEPTED ONCE IT DOES",
        function () {
    assert.ok(narrowed.status === 200 && widened.status === 200,
      "a setting write answered " + narrowed.status + " / " + widened.status);
    assert.strictEqual(refused.status, 400, String(refused.raw)
      .slice(0, 300));
    assert.ok(/offers no ML-DSA/.test(String(refused.raw)),
      String(refused.raw).slice(0, 300));
    assert.ok(accepted.status === 200 && accepted.body &&
              accepted.body.ok !== false, String(accepted.raw)
      .slice(0, 300));
  });

  // B. Each kind of key, at sign-in.
  log.info("=== sign-in ===");
  const before = await codeCount("STS-AUTHN-0356");
  let r = await withoutAUsername(function (challenge) {
    return classical.assert(challenge);
  });
  const after = await codeCount("STS-AUTHN-0356");
  check("B1. sign-in: THE ES256 KEY IS REFUSED, AND SAYS WHY " +
        "(STS-AUTHN-0356 on an audit row)", function () {
    assert.strictEqual(r.next, "refused", JSON.stringify(r.json)
      .slice(0, 300));
    assert.ok(/requires a post-quantum passkey/.test(JSON.stringify(r.json)),
      JSON.stringify(r.json).slice(0, 300));
    assert.ok(after > before, "no new STS-AUTHN-0356 row (" + before +
              " then " + after + ").");
  });
  r = await withoutAUsername(function (challenge) {
    return postQuantum.assert(challenge);
  });
  check("B2. THE ML-DSA-65 KEY, WHOSE ROW RECORDS NO LANE, SIGNS THE PERSON " +
        "IN: the algorithm decides", function () {
    assert.strictEqual(r.next, "redirect", JSON.stringify(r.json)
      .slice(0, 300));
  });

  // C. The warnings.
  page = await client.api("GET", "/account-api/keys");
  const person = await call("GET", "/users?user=" +
                            encodeURIComponent(PERSON));
  const consoleKeys = (person.body && person.body.factors &&
                       person.body.factors.keys) || [];
  check("C. /account-api/keys MARKS THE ES256 KEY AND NOT THE ML-DSA ONE, " +
        "AND THE CONSOLE CARRIES THE REFUSAL BESIDE THE ES256 KEY ONLY",
        function () {
    const portalC = rowOf(page.json.keys, classical.credentialId) || {};
    const portalP = rowOf(page.json.keys, postQuantum.credentialId) || {};
    assert.strictEqual(portalC.postQuantumRefused, true,
                       JSON.stringify(portalC).slice(0, 300));
    assert.strictEqual(portalP.postQuantumRefused, false);
    const consoleC = rowOf(consoleKeys, classical.credentialId) || {};
    const consoleP = rowOf(consoleKeys, postQuantum.credentialId) || {};
    assert.ok(/requires a post-quantum passkey/.test(
      String(consoleC.postQuantumRefused)), person.status + " " +
      JSON.stringify(consoleC).slice(0, 300));
    assert.strictEqual(consoleP.postQuantumRefused, "");
  });

  // D. Registration too.
  log.info("=== registration ===");
  const both = await requirement(defaults, "registration-and-sign-in");
  const late = makeAuthenticator(-7);
  const d = await enrol(client, late, "");
  if (d.pending && d.pending.id && !(d.done && d.done.status === 200)) {
    await client.api("POST", "/account-api/keys", { action: "cancel" });
  }
  check("D. registration-and-sign-in: AN ENROLMENT OFFERS ONLY ML-DSA, AND " +
        "AN ES256 REGISTRATION IS REFUSED", function () {
    assert.ok(both.status === 200, String(both.raw).slice(0, 300));
    assert.ok(d.pending, "no enrolment was begun: " +
              JSON.stringify(d.begun.json).slice(0, 300));
    assert.deepStrictEqual(d.pending.options.algorithms, [-49]);
    assert.ok(d.done && d.done.status === 400, "the ES256 registration " +
      "answered " + (d.done && d.done.status) + " " +
      JSON.stringify(d.done && d.done.json).slice(0, 300));
  });

  // E. Off again.
  const off = await requirement(defaults, "off");
  r = await withoutAUsername(function (challenge) {
    return classical.assert(challenge);
  });
  check("E. off AGAIN: THE ES256 KEY SIGNS IN", function () {
    assert.ok(off.status === 200, String(off.raw).slice(0, 300));
    assert.strictEqual(r.next, "redirect", JSON.stringify(r.json)
      .slice(0, 300));
  });

  assert.ok(checks >= 7, "only " + checks + " checks ran; a section has " +
            "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_passkey_post_quantum_required")
  .description("A post-quantum passkey required by the passkey policy " +
      "(#718): the save refused where no ML-DSA is offered, an ES256 key " +
      "refused and an ML-DSA-65 key with no lane signing in, the portal's " +
      "and the console's warnings, enrolment narrowed to ML-DSA, and off " +
      "again.")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
