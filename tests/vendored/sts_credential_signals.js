"use strict";
//
// File: sts_credential_signals.js
//
// ---------------------------------------------------------------------------
// CREDENTIAL SIGNALS FROM THE DOORS #231, #236 AND #237 CLOSED, OVER THE WIRE
// (2026-09-26).
//
// In a throwaway PRODUCT-mode realm it leaves behind — a realm's
// `global.mode` is its own, so the same questions are asked whichever mode
// the stack runs in — with a poll stream that takes CAEP credential-change
// and RISC credential-compromise and account-credential-change-required and
// covers everybody:
//
//   a. #236: an ACME External Account Binding key made and deleted on
//      /admin-api sends credential-change
//      `urn:iya:sts:credential-type:acme-eab-key` create, then delete; a SCEP
//      challenge password the registered `password` with a friendly_name
//      naming it; a SIOP self-issued subject enrolled and removed
//      `urn:iya:sts:credential-type:self-issued-key` create, then delete.
//   b. #231: a person's signing key pair issued on /admin-api/pki and
//      revoked there for `keyCompromise` sends RISC credential-compromise
//      `x509` beside the CAEP revoke.
//   c. #237, over LDAPS, bound as the realm's own administrator: a modify of
//      `stsTotpCredential` and an add carrying `stsWebauthnCredential` are
//      refused unwillingToPerform (53) — administrator or not — with a
//      diagnosticMessage naming the door that writes each (#261); deleting the
//      person's `userPassword` sends credential-change password revoke,
//      initiated by admin; setting `pwdReset` sends RISC
//      account-credential-change-required.
//
// What cannot be driven over the wire — the breached password at sign-in
// (the Pwned Passwords API stubbed), a cloned key's counter, the emailed
// factor's failure limit, a replayed one-time code, the CIBA user code, a
// HOBA key, Kerberos keys — is `tests/credential_signals.js` and
// `tests/kerberos_person_keytab.js`, in process.
//
// OWNED HERE (local: true): this repository's own transmitter and directory.
// It needs LDAPS reachable — STS_LDAPS_URL where the launcher sets it,
// otherwise the service's host on 636.
// ---------------------------------------------------------------------------

const assert = require("assert");
const nodeCrypto = require("crypto");
const ldapjs = require("ldapjs");
const names = require("./random_username.js");

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
var log = bunyan.createLogger({ name: "sts_credential_signals",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const REALM = ("cs231-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                              .slice(0, 31);
const realmBase = base + "/realm/" + REALM;
const realmApi = realmBase + "/admin-api";
const CAEP = "https://schemas.openid.net/secevent/caep/event-type/";
const RISC = "https://schemas.openid.net/secevent/risc/event-type/";
const POLL = "urn:ietf:rfc:8936";
const SECRET = "cs-231-" + nodeCrypto.randomBytes(12).toString("hex");
const RECEIVER = "cs231-rx-" + STAMP.toLowerCase();
const PASSWORD = "Cs-231-" + nodeCrypto.randomBytes(9).toString("base64url") +
                 "-Aa1!";
const ALICE = names.usernameFor("c231-alice");
const ADMIN = names.usernameFor("c231-admin");
const EAB = "urn:iya:sts:credential-type:acme-eab-key";
const SELF = "urn:iya:sts:credential-type:self-issued-key";

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

function hostOf(url) {
  log.debug("Entering hostOf().");
  log.debug("Leaving hostOf().");
  return new URL(url).hostname;
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
    // Not JSON — a page; the caller reads `raw`.
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

async function tokenFor(scope) {
  log.debug("Entering tokenFor().");
  const r = await send(realmBase + "/oauth2/token", { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form({ grant_type: "client_credentials", client_id: RECEIVER,
                 client_secret: SECRET, scope: scope }) });
  assert.ok(r.body && r.body.access_token,
            "a token for " + scope + ": " + r.raw.slice(0, 300));
  log.debug("Leaving tokenFor().");
  return r.body.access_token;
}

function decode(token) {
  log.debug("Entering decode().");
  const parts = String(token).split(".");
  log.debug("Leaving decode().");
  return JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
}

// Every SET waiting on the stream, decoded, and acknowledged.
async function drain(token, streamId) {
  log.debug("Entering drain().");
  const auth = { "Content-Type": "application/json",
                 Authorization: "Bearer " + token };
  const r = await send(realmBase + "/ssf/poll", { method: "POST",
    headers: auth, body: JSON.stringify({ stream_id: streamId,
      returnImmediately: true, maxEvents: 100 }) });
  assert.strictEqual(r.status, 200, "poll: " + r.raw.slice(0, 300));
  const sets = r.body.sets || {};
  const jtis = Object.keys(sets);
  if (jtis.length) {
    await send(realmBase + "/ssf/poll", { method: "POST", headers: auth,
      body: JSON.stringify({ stream_id: streamId, ack: jtis,
                             returnImmediately: true, maxEvents: 0 }) });
  }
  log.debug("Leaving drain(). " + jtis.length + " SET(s).");
  return jtis.map(function (jti) {
    return decode(sets[jti]);
  });
}

// What the stream has handed over and no check has claimed yet.
const POOL = [];

// Waits for a SET the predicate accepts and takes it out of the pool.
// Delivery is on a promise after the write answers, so a first poll may be
// early.
async function waitFor(token, streamId, what, predicate) {
  log.debug("Entering waitFor(). " + what);
  for (let i = 0; i < 24; i++) {
    (await drain(token, streamId)).forEach(function (one) {
      POOL.push(one);
    });
    const at = POOL.findIndex(predicate);
    if (at >= 0) {
      const hit = POOL.splice(at, 1)[0];
      log.debug("Leaving waitFor(). Found.");
      return { hit: hit, seen: POOL.slice() };
    }
    await new Promise(function (r) { setTimeout(r, 250); });
  }
  log.debug("Leaving waitFor(). Not found.");
  return { hit: null, seen: POOL.slice() };
}

function caep(set) {
  log.debug("Entering caep().");
  log.debug("Leaving caep().");
  return ((set && set.events) || {})[CAEP + "credential-change"] || null;
}

function risc(set, type) {
  log.debug("Entering risc().");
  log.debug("Leaving risc().");
  return ((set && set.events) || {})[RISC + type] || null;
}

function change(type, how) {
  log.debug("Entering change().");
  log.debug("Leaving change().");
  return function (set) {
    const ev = caep(set);
    return !!ev && ev.credential_type === type && ev.change_type === how;
  };
}

// ---------------------------------------------------------------------------
// LDAPS, as a directory client does.
// ---------------------------------------------------------------------------
function ldapsUrl() {
  log.debug("Entering ldapsUrl().");
  log.debug("Leaving ldapsUrl().");
  return process.env.STS_LDAPS_URL ||
    ("ldaps://" + hostOf(base) + ":" + (process.env.STS_LDAPS_PORT || 636));
}

function connect() {
  log.debug("Entering connect().");
  const url = ldapsUrl();
  const client = ldapjs.createClient({
    url: url, reconnect: false, timeout: 20000, connectTimeout: 15000,
    tlsOptions: { rejectUnauthorized: true, servername: hostOf(url) }
  });
  client.on("error", function (e) {
    // ldapjs emits on the client as well as calling back, and an unhandled
    // 'error' is a process-level throw. The operation in flight reports it.
    log.debug("The LDAP client emitted an error: " + e.message);
  });
  log.debug("Leaving connect().");
  return client;
}

function settle(fn) {
  log.debug("Entering settle().");
  log.debug("Leaving settle().");
  return new Promise(function (resolve) {
    fn(function (e) {
      // `message` is the result code's name; what the server said is the
      // error's `diagnosticMessage` (RFC 4511 section 4.1.9, #261).
      resolve({ code: e ? e.code : 0,
                message: e ? String(e.lde_message || e.message || "") : "",
                diagnostic: e ? String(e.diagnosticMessage || "") : "" });
    });
  });
}

function modify(client, dn, operation, type, values) {
  log.debug("Entering modify(). " + operation + " " + type);
  log.debug("Leaving modify().");
  return settle(function (done) {
    client.modify(dn, new ldapjs.Change({ operation: operation,
      modification: new ldapjs.Attribute({ type: type, values: values }) }),
    done);
  });
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. a throwaway product realm " + REALM + ", a stream ===");
  await ok(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "Credential signals " + STAMP,
    overrides: { "global.mode": "product" } }, "created the realm");
  await ok(realmApi + "/applications/create", { identifier: RECEIVER,
    kind: "oauth2-client", name: RECEIVER, protocols: ["oauth2", "ssf"],
    // The Shared Signals scopes are issued only to a client that declares
    // them (#110).
    fields: { oauthClientId: [RECEIVER], oauthClientSecret: SECRET,
              oauthTokenEndpointAuthMethod: "client_secret_post",
              oauthAllowedScope: ["ssf:read", "ssf:write"],
              oauthGrantType: ["client_credentials"] } },
    "created the receiver's application");
  const token = await tokenFor("ssf:read ssf:write");
  const created = await send(realmBase + "/ssf/stream", { method: "POST",
    headers: { "Content-Type": "application/json",
               Authorization: "Bearer " + token },
    body: JSON.stringify({ delivery: { method: POLL },
      events_requested: [CAEP + "credential-change",
                         RISC + "credential-compromise",
                         RISC + "account-credential-change-required"] }) });
  check("a poll stream takes credential-change, credential-compromise and " +
        "account-credential-change-required", function () {
    assert.strictEqual(created.status, 201, created.raw.slice(0, 400));
    const delivered = created.body.events_delivered || [];
    assert.ok(delivered.indexOf(CAEP + "credential-change") >= 0 &&
              delivered.indexOf(RISC + "credential-compromise") >= 0,
              JSON.stringify(delivered));
  });
  const streamId = created.body.stream_id;
  const dns = {};
  for (const who of [ALICE, ADMIN]) {
    const made = await ok(realmApi + "/users/create", { username: who,
      invent: false, credential: "password", password: PASSWORD,
      attributes: { cn: "CS " + who, sn: who, mail: who + "@cs231.test" } },
      "created " + who);
    dns[who] = String(made.dn);
  }
  await ok(realmApi + "/rbac/grant", { username: ADMIN, role: "write" },
           "granted " + ADMIN + " Admin Write on the realm's own roster");
  await drain(token, streamId);

  log.info("=== a. #236: EAB, SCEP challenge, self-issued subject ===");
  const eab = await ok(realmApi + "/acme/create-eab",
                       { kind: "person", identifier: ALICE },
                       "made an EAB key for alice");
  let found = await waitFor(token, streamId, "eab create",
                            change(EAB, "create"));
  check("an EAB key made is credential-change " + EAB + " create",
    function () {
      assert.ok(found.hit, JSON.stringify(found.seen).slice(0, 1200));
    });
  await ok(realmApi + "/acme/delete-eab", { kid: eab.kid },
           "deleted the EAB key");
  found = await waitFor(token, streamId, "eab delete",
                        change(EAB, "delete"));
  check("and deleting it is delete", function () {
    assert.ok(found.hit, JSON.stringify(found.seen).slice(0, 1200));
  });
  const challenge = await ok(realmApi + "/scep/create-challenge",
                             { kind: "person", identifier: ALICE },
                             "made a SCEP challenge for alice");
  found = await waitFor(token, streamId, "scep create",
                        change("password", "create"));
  check("a SCEP challenge is the registered `password`, create, with a " +
        "friendly_name naming it", function () {
    assert.ok(found.hit, JSON.stringify(found.seen).slice(0, 1200));
    assert.ok(/^SCEP challenge password /.test(
      String(caep(found.hit).friendly_name)), JSON.stringify(caep(found.hit)));
  });
  await ok(realmApi + "/scep/delete-challenge", { id: challenge.id },
           "deleted the challenge");
  found = await waitFor(token, streamId, "scep delete",
                        change("password", "delete"));
  check("and deleting it is delete", function () {
    assert.ok(found.hit, JSON.stringify(found.seen).slice(0, 1200));
  });
  const jwk = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" })
    .publicKey.export({ format: "jwk" });
  const subject = JSON.stringify({ kty: jwk.kty, crv: jwk.crv, x: jwk.x,
                                   y: jwk.y });
  await ok(realmApi + "/users/enrol-self-issued-subject",
           { user: ALICE, subject: subject, label: "wallet" },
           "enrolled a self-issued subject");
  found = await waitFor(token, streamId, "siop create",
                        change(SELF, "create"));
  check("a self-issued subject enrolled is " + SELF + " create, by admin",
    function () {
      assert.ok(found.hit, JSON.stringify(found.seen).slice(0, 1200));
      assert.strictEqual(caep(found.hit).initiating_entity, "admin");
    });
  await ok(realmApi + "/users/remove-self-issued-subject",
           { user: ALICE, subject: subject }, "removed it");
  found = await waitFor(token, streamId, "siop delete",
                        change(SELF, "delete"));
  check("and removing it is delete", function () {
    assert.ok(found.hit, JSON.stringify(found.seen).slice(0, 1200));
  });

  log.info("=== b. #231: a key pair revoked for keyCompromise ===");
  await ok(realmApi + "/pki/build", { organisation: "Credential signals" },
           "built the realm's certificate authority");
  const issued = await ok(realmApi + "/pki/issue",
                          { target: "person", identifier: ALICE },
                          "issued alice a signing key pair");
  const serial = new nodeCrypto.X509Certificate(issued.certificatePem)
    .serialNumber.toLowerCase();
  await drain(token, streamId);
  POOL.length = 0;
  await ok(realmApi + "/pki/revoke-certificate", { ca: "assertions",
    serialHex: serial, reason: "keyCompromise" },
    "revoked it for keyCompromise");
  found = await waitFor(token, streamId, "credential-compromise x509",
    function (set) {
      const ev = risc(set, "credential-compromise");
      return !!ev && ev.credential_type === "x509";
    });
  check("a certificate revoked for keyCompromise sends RISC " +
        "credential-compromise x509", function () {
    assert.ok(found.hit, JSON.stringify(found.seen).slice(0, 1200));
  });
  found = await waitFor(token, streamId, "x509 revoke",
                        change("x509", "revoke"));
  check("beside the CAEP credential-change x509 revoke", function () {
    assert.ok(found.hit, JSON.stringify(found.seen).slice(0, 1200));
  });

  log.info("=== c. #237: the LDAPS socket, bound as an administrator ===");
  const client = connect();
  const bound = await settle(function (done) {
    client.bind(dns[ADMIN], PASSWORD, done);
  });
  check("the realm's administrator binds", function () {
    assert.strictEqual(bound.code, 0, bound.message);
  });
  const totp = await modify(client, dns[ALICE], "replace",
                            "stsTotpCredential", ["{}"]);
  check("a modify of stsTotpCredential is refused unwillingToPerform (53), " +
        "administrator or not", function () {
    assert.strictEqual(totp.code, 53, JSON.stringify(totp));
  });
  // The refusal's text arrives as the diagnosticMessage since #261, and it
  // names the door that writes the attribute.
  check("and its diagnostic message names the door, /portal/mfa",
    function () {
      assert.ok(totp.diagnostic.indexOf("stsTotpCredential") >= 0 &&
                totp.diagnostic.indexOf("/portal/mfa") >= 0,
                JSON.stringify(totp));
    });
  const usersDn = dns[ALICE].split(",").slice(1).join(",");
  const addDn = "uid=c231-new-" + STAMP.toLowerCase() + "," + usersDn;
  const added = await settle(function (done) {
    client.add(addDn, { objectClass: ["inetOrgPerson"],
      uid: ["c231-new-" + STAMP.toLowerCase()], cn: ["x"], sn: ["x"],
      stsWebauthnCredential: ["{}"] }, done);
  });
  check("an add carrying stsWebauthnCredential is refused the same way, " +
        "naming /portal/keys", function () {
    assert.strictEqual(added.code, 53, JSON.stringify(added));
    assert.ok(added.diagnostic.indexOf("/portal/keys") >= 0,
              JSON.stringify(added));
  });
  const removed = await modify(client, dns[ALICE], "delete", "userPassword",
                               []);
  check("the administrator deletes alice's userPassword", function () {
    assert.strictEqual(removed.code, 0, removed.message);
  });
  found = await waitFor(token, streamId, "password revoke",
                        change("password", "revoke"));
  check("which is credential-change password revoke, initiated by admin",
    function () {
      assert.ok(found.hit, JSON.stringify(found.seen).slice(0, 1200));
      assert.strictEqual(caep(found.hit).initiating_entity, "admin");
    });
  const reset = await modify(client, dns[ALICE], "replace", "pwdReset",
                             ["TRUE"]);
  check("the administrator sets pwdReset", function () {
    assert.strictEqual(reset.code, 0, reset.message);
  });
  found = await waitFor(token, streamId, "change required", function (set) {
    return !!risc(set, "account-credential-change-required");
  });
  check("which is RISC account-credential-change-required", function () {
    assert.ok(found.hit, JSON.stringify(found.seen).slice(0, 1200));
  });
  await settle(function (done) {
    client.unbind(done);
  });

  log.info("Test completed successfully. " + checks + " check(s) passed.");
  log.debug("Leaving test().");
}

test().catch(function (e) {
  log.error("sts_credential_signals FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
