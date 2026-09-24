"use strict";
//
// File: sts_webauthn_attestation.js
//
// ===========================================================================
// A SECURITY KEY'S ATTESTATION, VERIFIED OVER HTTP (#105).
//
// A person enrols keys at `/portal/keys` in a throwaway trust realm this job
// creates (and leaves behind, tests/CLAUDE.md), each with an attestation
// statement this job's own authenticator makes: a `packed` statement whose
// certificate chains to a root minted here at run time and handed to the
// realm as `webauthn.attestationTrustAnchors`. No key material is in the
// repository; every key and certificate below is made when the job runs.
//
//   1. require-trusted: the anchored statement is accepted, a self
//      attestation is refused, and so is the anchored statement when the
//      realm's AAGUID allow-list names another model;
//   2. verify-if-present: a statement whose signature does not verify is
//      refused, and `none` is accepted as untrusted;
//   3. THE REPORTING: what each statement proved is on the key's row on
//      `/portal/keys`, on `GET /admin-api/users`, and on the console's
//      `/admin/users` row; `/admin/webauthn` and `GET /admin-api/webauthn`
//      report the policy in force — `by-mode` is verify-if-present in
//      product and off in development, which is the one assertion here that
//      differs by mode.
//
// `local: true`: the portal, the API and the console are this repository's.
// It carries its own AUTHENTICATOR (the CBOR, the authenticator data, the
// signatures) for `sts_dpop.js`'s reason; the certificates are minted with the
// vendored X.509 engine, which verifies nothing here.
// ===========================================================================

const assert = require("assert");
const nodeCrypto = require("crypto");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const facts = require("./service_facts.js");
const consoleSignIn = require("./console_signin.js");
const x509 = require("../../common/vendored/x509");
const keyMaterial = require("../../common/vendored/key_material");

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
var log = bunyan.createLogger({ name: "sts_webauthn_attestation",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}
var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");

const STAMP = names.runStamp();
const REALM = ("wa105-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                              .slice(0, 31);
const DOMAIN = REALM + ".example.net";
const R = "/realm/" + REALM;
const realmBase = base + R;
const realmApi = realmBase + "/admin-api";
const ORIGIN = new URL(base).origin;
const RP_ID = new URL(base).hostname;
const PASSWORD = "Wa-105-Passw0rd!-" + String(Date.now()).slice(-6);
const PERSON = names.usernameFor("wa105");
const CONSOLE_USER = names.usernameFor("wa105-console");

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function form(o) {
  log.debug("Entering form().");
  log.debug("Leaving form().");
  return new URLSearchParams(o).toString();
}

async function send(url, options) {
  log.debug("Entering send(). url=" + url);
  const r = await fetch(url, Object.assign({ redirect: "manual" },
                                           options || {}));
  const raw = await r.text();
  let body = null;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in send(): " + ((e && e.message) || e));
    // A page rather than JSON; the caller reads `raw`.
    body = null;
  }
  log.debug("Leaving send(). status=" + r.status);
  return { status: r.status, body: body, raw: raw };
}

async function ok(url, payload, what) {
  log.debug("Entering ok().");
  const r = await send(url, { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {}) });
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "POST " + url + " should have " + what + "; it answered " + r.status +
    " " + String(r.raw).slice(0, 400));
  log.debug("Leaving ok().");
  return r.body;
}

async function setting(key, value) {
  log.debug("Entering setting(). " + key);
  await ok(realmApi + "/config/set", { key: key, value: value },
           "set " + key);
  log.debug("Leaving setting().");
}

async function reset(key) {
  log.debug("Entering reset(). " + key);
  await ok(realmApi + "/config/reset", { key: key }, "reset " + key);
  log.debug("Leaving reset().");
}

// ---------------------------------------------------------------------------
// THE AUTHENTICATOR: CBOR, authenticator data, and the attestation.
// ---------------------------------------------------------------------------
function cborHead(major, n) {
  log.debug("Entering cborHead().");
  let out;
  if (n < 24) {
    out = Buffer.from([(major << 5) | n]);
  } else if (n < 256) {
    out = Buffer.from([(major << 5) | 24, n]);
  } else {
    out = Buffer.alloc(3);
    out[0] = (major << 5) | 25;
    out.writeUInt16BE(n, 1);
  }
  log.debug("Leaving cborHead().");
  return out;
}

function cbor(v) {
  log.debug("Entering cbor().");
  let out;
  if (Buffer.isBuffer(v)) {
    out = Buffer.concat([cborHead(2, v.length), v]);
  } else if (typeof v === "string") {
    const b = Buffer.from(v, "utf8");
    out = Buffer.concat([cborHead(3, b.length), b]);
  } else if (typeof v === "number") {
    out = v >= 0 ? cborHead(0, v) : cborHead(1, -1 - v);
  } else if (Array.isArray(v)) {
    out = Buffer.concat([cborHead(4, v.length)].concat(v.map(cbor)));
  } else {
    const entries = v instanceof Map ? Array.from(v.entries())
      : Object.keys(v).map(function (k) { return [k, v[k]]; });
    out = Buffer.concat([cborHead(5, entries.length)].concat(
      entries.map(function (kv) {
        return Buffer.concat([cbor(kv[0]), cbor(kv[1])]);
      })));
  }
  log.debug("Leaving cbor().");
  return out;
}

function sha256(b) {
  log.debug("Entering sha256().");
  log.debug("Leaving sha256().");
  return nodeCrypto.createHash("sha256").update(b).digest();
}

function derOf(pem) {
  log.debug("Entering derOf().");
  log.debug("Leaving derOf().");
  return Buffer.from(String(pem).replace(/-----[^-]+-----/g, "")
    .replace(/\s+/g, ""), "base64");
}

// A root, and a packed attestation certificate under it for `aaguid`, with
// the fields WebAuthn Level 3 section 8.2.1 requires.
async function vendor(name) {
  log.debug("Entering vendor(). " + name);
  const rootPair = await keyMaterial.generateKeyPair("ec-p256");
  const root = await x509.issueCertificate({
    subject: [{ name: "CN", value: name + " Root" }],
    subjectPublicKey: rootPair.publicPem, signatureAlg: "sha256-ecdsa",
    profile: "root-ca",
    issuer: { privateKeyPem: rootPair.privatePem, keyAlg: "ec-p256" },
    extensions: {
      basicConstraints: { present: true, critical: true, ca: true,
                          pathLen: null },
      keyUsage: { present: true, critical: true,
                  usages: ["keyCertSign", "cRLSign"] } } });
  log.debug("Leaving vendor().");
  return {
    rootPem: root.pem,
    attestationCertificate: async function (aaguid) {
      log.debug("Entering attestationCertificate().");
      const pair = await keyMaterial.generateKeyPair("ec-p256");
      const cert = await x509.issueCertificate({
        subject: [{ name: "C", value: "US" },
                  { name: "O", value: name },
                  { name: "OU", value: "Authenticator Attestation" },
                  { name: "CN", value: name + " Attestation" }],
        subjectPublicKey: pair.publicPem, signatureAlg: "sha256-ecdsa",
        profile: "digital-signature",
        issuer: { certificatePem: root.pem, privateKeyPem: rootPair.privatePem,
                  keyAlg: "ec-p256" },
        extensions: {
          basicConstraints: { present: true, critical: true, ca: false },
          keyUsage: { present: true, critical: true,
                      usages: ["digitalSignature"] },
          custom: [{ oid: "1.3.6.1.4.1.45724.1.1.4", critical: false,
                     value: Buffer.concat([Buffer.from([0x04, 0x10]),
                                           aaguid]).toString("base64") }] } });
      log.debug("Leaving attestationCertificate().");
      return { der: derOf(cert.pem), privatePem: pair.privatePem };
    }
  };
}

// One authenticator of one model: `register(challenge, how)` answers the
// credential `/portal/keys` takes, attested `how`: "packed" (the x5c
// statement), "self", "forged" (packed, signature over something else) or
// "none".
async function authenticator(model, aaguid) {
  log.debug("Entering authenticator().");
  const pair = nodeCrypto.generateKeyPairSync("ec",
                                              { namedCurve: "prime256v1" });
  const jwk = pair.publicKey.export({ format: "jwk" });
  const cose = new Map([[1, 2], [3, -7], [-1, 1],
                        [-2, Buffer.from(jwk.x, "base64url")],
                        [-3, Buffer.from(jwk.y, "base64url")]]);
  const attCert = await model.attestationCertificate(aaguid);
  log.debug("Leaving authenticator().");
  return {
    register: function (challenge, how) {
      log.debug("Entering register(). " + how);
      const id = nodeCrypto.randomBytes(32);
      const idLength = Buffer.alloc(2);
      idLength.writeUInt16BE(id.length, 0);
      const authData = Buffer.concat([sha256(Buffer.from(RP_ID, "utf8")),
        Buffer.from([0x45]), Buffer.alloc(4), aaguid, idLength, id,
        cbor(cose)]);
      const clientDataJSON = Buffer.from(JSON.stringify({
        type: "webauthn.create", challenge: challenge, origin: ORIGIN,
        crossOrigin: false }));
      const signed = Buffer.concat([authData, sha256(clientDataJSON)]);
      let fmt = "packed";
      let attStmt;
      if (how === "none") {
        fmt = "none";
        attStmt = {};
      } else if (how === "self") {
        attStmt = { alg: -7,
                    sig: nodeCrypto.sign("sha256", signed, pair.privateKey) };
      } else {
        attStmt = { alg: -7, x5c: [attCert.der],
          sig: nodeCrypto.sign("sha256", how === "forged"
            ? Buffer.from("something else entirely") : signed,
            attCert.privatePem) };
      }
      log.debug("Leaving register().");
      return {
        id: id.toString("base64url"), rawId: id.toString("base64url"),
        type: "public-key", authenticatorAttachment: "cross-platform",
        clientExtensionResults: {},
        response: {
          attestationObject: cbor(new Map([["fmt", fmt],
            ["attStmt", attStmt], ["authData", authData]]))
            .toString("base64url"),
          clientDataJSON: clientDataJSON.toString("base64url") } };
    }
  };
}

// ---------------------------------------------------------------------------
// THE BROWSER, THE SIGN-IN AND THE ENROLMENT.
// ---------------------------------------------------------------------------
function browser() {
  log.debug("Entering browser().");
  const jar = {};
  const self = {
    async go(method, path, body) {
      log.debug("Entering go(). " + method + " " + path);
      const headers = {};
      const cookie = Object.keys(jar).map(function (k) {
        return k + "=" + jar[k];
      }).join("; ");
      if (cookie) {
        headers.cookie = cookie;
      }
      if (body !== undefined) {
        headers["Content-Type"] = "application/x-www-form-urlencoded";
      }
      const url = /^https?:\/\//i.test(path) ? path : base + path;
      const r = await fetch(url, { method: method, redirect: "manual",
                                   headers: headers, body: body });
      (r.headers.getSetCookie ? r.headers.getSetCookie() : [])
        .forEach(function (one) {
          const pair = String(one).split(";")[0];
          const at = pair.indexOf("=");
          if (at <= 0) {
            return;
          }
          const value = pair.slice(at + 1);
          if (value === "") {
            delete jar[pair.slice(0, at)];
          } else {
            jar[pair.slice(0, at)] = value;
          }
        });
      const text = await r.text();
      log.debug("Leaving go(). status=" + r.status);
      return { status: r.status, location: r.headers.get("location") || "",
               text: text };
    }
  };
  log.debug("Leaving browser().");
  return self;
}

function hiddenFields(html) {
  log.debug("Entering hiddenFields().");
  const out = {};
  (String(html).match(/<input type="hidden"[^>]*>/g) || [])
    .forEach(function (tag) {
      const name = /name="([^"]+)"/.exec(tag);
      const value = /value="([^"]*)"/.exec(tag);
      if (name) {
        out[name[1]] = value ? value[1].replace(/&amp;/g, "&") : "";
      }
    });
  log.debug("Leaving hiddenFields().");
  return out;
}

function attr(html, name) {
  log.debug("Entering attr().");
  const m = String(html).match(new RegExp(name + '="([^"]*)"'));
  log.debug("Leaving attr().");
  return m ? m[1] : "";
}

function csrfOf(text) {
  log.debug("Entering csrfOf().");
  log.debug("Leaving csrfOf().");
  return (String(text).match(/name="csrf_token" value="([^"]+)"/) ||
          [])[1] || "";
}

async function portalSignIn(who, path) {
  log.debug("Entering portalSignIn(). " + who);
  const b = browser();
  let r = await b.go("GET", path);
  for (let hop = 0; hop < 12 && r.status !== 200; hop++) {
    assert.ok(r.status === 302 || r.status === 303,
      "signing in to " + path + " stopped at " + r.status + " " +
      r.text.slice(0, 300));
    r = await b.go("GET", r.location);
    if (r.status === 200 && /name="authn_id"/.test(r.text)) {
      const fields = hiddenFields(r.text);
      fields.username = who;
      fields.password = PASSWORD;
      fields.action = "login";
      r = await b.go("POST", R + "/authn/login", form(fields));
    }
  }
  assert.strictEqual(r.status, 200, "the signed-in page: " + r.status);
  log.debug("Leaving portalSignIn().");
  return b;
}

// `/portal/keys`'s two steps, with one attestation. Answers the finish.
async function enrol(b, key, how, label) {
  log.debug("Entering enrol(). " + how);
  let page = await b.go("GET", R + "/portal/keys");
  const begun = await b.go("POST", R + "/portal/keys",
    form({ action: "begin", role: "mfa", label: label,
           csrf_token: csrfOf(page.text) }));
  assert.strictEqual(begun.status, 303, "beginning the enrolment answered " +
    begun.status + " " + begun.text.slice(0, 300));
  page = await b.go("GET", R + "/portal/keys");
  const challenge = attr(page.text, "data-challenge");
  assert.ok(challenge, "the armed page carries no challenge");
  const done = await b.go("POST", R + "/portal/keys",
    form({ action: "finish", enrolment_id: hiddenFields(page.text)
             .enrolment_id || "",
           credential: JSON.stringify(key.register(challenge, how)),
           csrf_token: csrfOf(page.text) }));
  if (done.status !== 303) {
    // A refused enrolment keeps the ceremony armed; cancel it so the next
    // one starts clean.
    const again = await b.go("GET", R + "/portal/keys");
    await b.go("POST", R + "/portal/keys",
               form({ action: "cancel", csrf_token: csrfOf(again.text) }));
  }
  log.debug("Leaving enrol(). " + done.status);
  return done;
}

async function keysOf(who) {
  log.debug("Entering keysOf().");
  const r = await send(realmApi + "/users?user=" + encodeURIComponent(who));
  assert.strictEqual(r.status, 200, "GET /admin-api/users answered " +
                     r.status);
  log.debug("Leaving keysOf().");
  return (r.body.factors && r.body.factors.keys) || [];
}

async function test() {
  log.debug("Entering test().");
  const product = await facts.isProduct(base + "/admin-api");
  log.info("Driving " + base + " (" + (product ? "product" : "development") +
           " mode) in the trust realm \"" + REALM + "\".");

  log.info("=== setup: the realm, the person, the vendor's root ===");
  await ok(base + "/admin-api/realms/create", { id: REALM, domain: DOMAIN,
    name: "WebAuthn attestation " + STAMP }, "created the realm");
  await ok(realmApi + "/users/create", { username: PERSON, invent: false,
    credential: "password", password: PASSWORD,
    attributes: { cn: "WA " + PERSON, givenName: "WA", sn: PERSON,
                  mail: PERSON + "@wa105.test" } }, "created " + PERSON);
  const model = await vendor("Synthetic Vendor " + STAMP);
  const AAGUID = nodeCrypto.randomBytes(16);
  const OTHER = nodeCrypto.randomBytes(16).toString("hex");
  await setting("webauthn.attestationTrustAnchors", model.rootPem);
  await setting("webauthn.maxKeysPerPerson", 20);

  const b = await portalSignIn(PERSON, R + "/portal/keys");

  // -------------------------------------------------------------------------
  log.info("=== 1. require-trusted ===");
  await setting("webauthn.attestationPolicy", "require-trusted");
  const trusted = await authenticator(model, AAGUID);
  const accepted = await enrol(b, trusted, "packed", "anchored key");
  check("an x5c statement chaining to the realm's anchor is accepted",
    function () {
      assert.strictEqual(accepted.status, 303, accepted.text.slice(0, 500));
    });
  const self = await enrol(b, await authenticator(model, AAGUID), "self",
                           "self key");
  check("a SELF attestation is refused: it proves nothing about what made " +
        "the key", function () {
    assert.strictEqual(self.status, 400, self.text.slice(0, 300));
    assert.ok(/self attestation/i.test(self.text), self.text.slice(0, 600));
  });
  await setting("webauthn.attestationAllowedAaguids", OTHER);
  const notAllowed = await enrol(b, await authenticator(model, AAGUID),
                                 "packed", "other model");
  check("an anchored key from a model the allow-list does not name is " +
        "refused", function () {
    assert.strictEqual(notAllowed.status, 400, notAllowed.text.slice(0, 300));
    assert.ok(/not one this realm allows/i.test(notAllowed.text),
              notAllowed.text.slice(0, 600));
  });
  await reset("webauthn.attestationAllowedAaguids");

  // -------------------------------------------------------------------------
  log.info("=== 2. verify-if-present ===");
  await setting("webauthn.attestationPolicy", "verify-if-present");
  const forged = await enrol(b, await authenticator(model, AAGUID), "forged",
                             "forged key");
  check("a statement whose signature does not verify is refused", function () {
    assert.strictEqual(forged.status, 400, forged.text.slice(0, 300));
    assert.ok(/does not verify/i.test(forged.text), forged.text.slice(0, 600));
  });
  const none = await enrol(b, await authenticator(model, AAGUID), "none",
                           "passkey");
  check("`none` is accepted — what a synced passkey sends", function () {
    assert.strictEqual(none.status, 303, none.text.slice(0, 500));
  });

  // -------------------------------------------------------------------------
  log.info("=== 3. what each key's statement proved is reported ===");
  const keys = await keysOf(PERSON);
  const byLabel = {};
  keys.forEach(function (k) { byLabel[k.label] = k; });
  check("GET /admin-api/users: the anchored key is verified, trusted, " +
        "packed, through the configured anchor", function () {
    const a = (byLabel["anchored key"] || {}).attestation || {};
    assert.ok(a.verified === true && a.trusted === true &&
              a.format === "packed" && a.type === "basic" &&
              a.anchor === "configured", JSON.stringify(keys));
  });
  check("and the passkey is recorded as `none`, untrusted", function () {
    const a = (byLabel.passkey || {}).attestation || {};
    assert.ok(a.verified === true && a.trusted === false &&
              a.type === "none", JSON.stringify(keys));
  });
  check("and none of the three refused keys was stored", function () {
    assert.strictEqual(keys.length, 2, JSON.stringify(keys));
  });
  const portal = await b.go("GET", R + "/portal/keys");
  check("/portal/keys shows the person what each key's statement proved",
    function () {
      assert.ok(/verified and trusted/.test(portal.text),
                portal.text.slice(0, 800));
      assert.ok(/no attestation sent/.test(portal.text),
                portal.text.slice(0, 800));
    });
  const cookie = await consoleSignIn.signInToTheConsole(realmBase,
    CONSOLE_USER, log, { grant: "read" });
  const consoleGet = async function (path) {
    log.debug("Entering consoleGet(). " + path);
    const r = await fetch(base + path,
                          { redirect: "manual",
                            headers: cookie ? { cookie: cookie } : {} });
    const text = await r.text();
    log.debug("Leaving consoleGet().");
    return { status: r.status, text: text };
  };
  const row = await consoleGet(R + "/admin/users?user=" +
                               encodeURIComponent(PERSON));
  check("the console's /admin/users row draws an Attestation column: " +
        "verified and trusted for one key, untrusted for the other",
    function () {
      assert.strictEqual(row.status, 200, row.text.slice(0, 300));
      assert.ok(/<th>Attestation<\/th>/.test(row.text),
                "no Attestation column");
      assert.ok(/verified, trusted/.test(row.text), "no trusted key");
      assert.ok(/verified, untrusted/.test(row.text), "no untrusted key");
    });
  await reset("webauthn.attestationPolicy");
  const page = await consoleGet(R + "/admin/webauthn");
  const api = await send(realmApi + "/webauthn");
  const status = (api.body && api.body.status) || {};
  check("/admin/webauthn and GET /admin-api/webauthn report the policy in " +
        "force: by-mode is " + (product ? "verify-if-present in product"
                                        : "off in development"),
    function () {
      assert.strictEqual(page.status, 200, page.text.slice(0, 300));
      assert.ok(/The attestation statement/.test(page.text),
                "the page has no attestation section");
      assert.strictEqual(status.attestationPolicy,
                         product ? "verify-if-present" : "off",
                         JSON.stringify(status).slice(0, 600));
      assert.strictEqual((status.attestationFormats || []).length, 8,
                         JSON.stringify(status.attestationFormats));
    });

  assert.ok(checks >= 11,
    "only " + checks + " checks ran; a section has stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_webauthn_attestation")
  .description("Enrol security keys at /portal/keys with attestation " +
      "statements this job makes — an x5c packed statement under a root " +
      "minted at run time, a self attestation, a forged one, none — under " +
      "require-trusted, an AAGUID allow-list and verify-if-present, and read " +
      "what each proved back from /portal/keys, /admin-api/users, the " +
      "console's /admin/users and /admin/webauthn.")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
