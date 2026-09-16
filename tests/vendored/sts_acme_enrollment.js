"use strict";
//
// File: sts_acme_enrollment.js
//
// ===========================================================================
// THE ACME SERVER (RFC 8555, RFC 9773) OVER HTTPS, DRIVEN BY AN INDEPENDENT
// CLIENT, EVERY PROFILE AND EVERY REFUSAL (2026-09-13).
//
// `acme_client.js` beside this file is a second reading of the RFCs with
// nothing from acme/ in it; this job drives the running service with it, in
// three throwaway trust realms it builds and leaves standing — the one under
// test, a second for the cross-realm refusals and a product-mode one
// (`tests/CLAUDE.md`, *No job removes a realm*). What it asserts:
//
//   * EACH OF THE NINE PROFILES ISSUED OVER ACME — five over a
//     permanent-identifier order with an RSA key, the two server profiles over
//     a registered dns name, S/MIME over the person's own mail, and smartcard
//     logon with the UPN the core adds (the person's mail, since a person is
//     created with no userPrincipalName) — each chained by OPENSSL (node's
//     X509Certificate) to this realm's Intermediate and the service Root, with
//     the extended key usage the profile defines and the urn:sts: name of the
//     entry it was issued for.
//   * AN APPLICATION ISSUED FOR ITSELF, and refused a person's identifiers.
//   * THE ADMINISTRATOR'S PATH, which in ACME is an EAB key an administrator
//     created on `/admin-api` for somebody else's entry. Every account here is
//     bound through that door; the portal door (a person creating their own) is
//     not this job's (`sts_portal_certificates.js` drives it). No person is
//     put in the DEFAULT realm's Admin Write group: that roster is shared by
//     every job after this one, and nothing in ACME reads it. (The reason
//     given here first — a member closing the console's empty-roster door — no
//     longer applies to a stack started through server.js, whose roster holds
//     the seeded bootstrap administrator: `admin-ui/admin_rbac.ts`,
//     `rolesOf()`.)
//   * THE RECORD: the certificate listed by `GET /admin-api/acme` against its
//     entry; OCSP `good` from the ACME Issuing CA's responder before
//     revocation and `revoked` after; the serial on `/pki/crl/{realm}/acme.crl`
//     after an ACME revokeCert and after the console action; the monitor's
//     counts moving.
//   * THE REFUSALS: another person's identifiers, an application's order for a
//     person, no binding, a wrong MAC, a binding reused, the five refused
//     profiles, a profile disabled by acme.allowedProfiles, an unregistered dns
//     name, somebody else's mail, a CSR whose signature does not verify, a KEM
//     key, a CSR naming what the order does not, a body over the limit, the
//     wrong media type, malformed JSON, base64 and ASN.1, a credential and a
//     certificate from another realm, a reused and an expired nonce, an expired
//     EAB key, the family turned off, and the throttle after repeated refusals.
//   * PRODUCT MODE, where it changes something reachable over TLS: a realm
//     carrying `global.mode: product` still answers over this HTTPS port and
//     still verifies the binding. Its plain-HTTP refusal needs a plain
//     listener, which this stack does not have — `tests/acme_protocol.js`
//     asserts it in process — and the job says so rather than passing silently.
// ===========================================================================

const assert = require("assert");
const nodeCrypto = require("crypto");
const { Command, Option } = require("commander");
const { usernameFor } = require("./random_username.js");
const C = require("./acme_client.js");

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
var log = bunyan.createLogger({ name: "sts_acme_enrollment",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const asn1js = require("asn1js");
const pkijs = require("pkijs");

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");
var api = base + "/admin-api";

const STAMP = usernameFor("acme").replace(/[^a-z0-9-]/g, "").slice(0, 24);
const REALM = ("acme-" + STAMP).slice(0, 30);
const REALM_B = ("acmeb-" + STAMP).slice(0, 30);
const REALM_P = ("acmep-" + STAMP).slice(0, 30);
const realmApi = function (realm) {
  return base + "/realm/" + realm + "/admin-api";
};
const ALICE = "alice-" + STAMP;
const BOB = "bob-" + STAMP;
const APP = "acmeapp-" + STAMP;
const P = "urn:ietf:params:acme:error:";
const EKU = { serverAuth: "1.3.6.1.5.5.7.3.1", clientAuth: "1.3.6.1.5.5.7.3.2",
              codeSigning: "1.3.6.1.5.5.7.3.3", email: "1.3.6.1.5.5.7.3.4",
              timeStamping: "1.3.6.1.5.5.7.3.8",
              smartcard: "1.3.6.1.4.1.311.20.2.2" };

var checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  ✓ " + what);
  log.debug("Leaving check().");
}

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) { setTimeout(resolve, ms); });
}

async function send(url, options) {
  log.debug("Entering send().");
  const r = await fetch(url, options);
  const raw = await r.text();
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in send(): " + ((e && e.message) || e));
    // Not JSON — the raw text says more than a parse failure.
    parsed = raw;
  }
  log.debug("Leaving send().");
  return { status: r.status, body: parsed, raw: raw, headers: r.headers };
}

async function post(url, body) {
  log.debug("Entering post().");
  const r = await send(url, { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}) });
  log.debug("Leaving post().");
  return r;
}

async function ok(url, body, what) {
  log.debug("Entering ok().");
  const r = await post(url, body);
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "POST " + url + " should have " + what + "; it answered " + r.status +
    " " + JSON.stringify((r.body && (r.body.errors || r.body.why)) || r.body)
      .slice(0, 500));
  log.debug("Leaving ok().");
  return r.body;
}

async function setting(realm, key, value) {
  log.debug("Entering setting(). key=" + key);
  await ok(realmApi(realm) + "/config/set", { key: key, value: value },
           "set " + key);
  log.debug("Leaving setting().");
}

async function reset(realm, key) {
  log.debug("Entering reset(). key=" + key);
  const r = await post(realmApi(realm) + "/config/reset", { key: key });
  log.debug("Leaving reset(). status=" + r.status);
}

function problem(r, type, what) {
  log.debug("Entering problem(). type=" + type);
  assert.ok(r.body && r.body.type === P + type,
    what + ": expected " + type + ", got " + r.status + " " +
    String(r.text || r.raw || "").slice(0, 400));
  assert.ok(/problem\+json/.test(r.type || ""),
    what + ": the refusal is not application/problem+json: " + r.type);
  log.debug("Leaving problem().");
}

// ---------------------------------------------------------------------------
// CERTIFICATES, OCSP AND CRLs, READ HERE.
// ---------------------------------------------------------------------------
function x509Of(pemOrDer) {
  log.debug("Entering x509Of().");
  log.debug("Leaving x509Of().");
  return new nodeCrypto.X509Certificate(pemOrDer);
}

async function rootCertificate() {
  log.debug("Entering rootCertificate().");
  const r = await fetch(base + "/pki/ca/service/root.cer");
  const bytes = Buffer.from(await r.arrayBuffer());
  assert.strictEqual(r.status, 200, "the service Root is published");
  log.debug("Leaving rootCertificate().");
  return x509Of(bytes);
}

async function realmIntermediate(realm) {
  log.debug("Entering realmIntermediate().");
  const r = await fetch(base + "/pki/ca/" + realm + "/intermediate.cer");
  const bytes = Buffer.from(await r.arrayBuffer());
  assert.strictEqual(r.status, 200, "the realm Intermediate is published");
  log.debug("Leaving realmIntermediate().");
  return x509Of(bytes);
}

function pkijsCert(der) {
  log.debug("Entering pkijsCert().");
  const buf = Buffer.from(der);
  log.debug("Leaving pkijsCert().");
  return new pkijs.Certificate({ schema: asn1js.fromBER(buf.buffer.slice(
    buf.byteOffset, buf.byteOffset + buf.byteLength)).result });
}

// An OCSPRequest for one certificate, built here in DER (RFC 6960 section
// 4.1.1) with a SHA-1 CertID, because that is what every responder takes.
function ocspRequestFor(leafDer, issuerDer) {
  log.debug("Entering ocspRequestFor().");
  const leaf = pkijsCert(leafDer);
  const issuer = pkijsCert(issuerDer);
  const sha1 = function (bytes) {
    return nodeCrypto.createHash("sha1").update(Buffer.from(bytes)).digest();
  };
  const ab = function (buf) {
    return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
  };
  const nameHash = sha1(issuer.subject.toSchema().toBER(false));
  const keyHash = sha1(issuer.subjectPublicKeyInfo.subjectPublicKey.valueBlock
                       .valueHexView);
  const certId = new asn1js.Sequence({ value: [
    new asn1js.Sequence({ value: [
      new asn1js.ObjectIdentifier({ value: "1.3.14.3.2.26" }),
      new asn1js.Null() ] }),
    new asn1js.OctetString({ valueHex: ab(nameHash) }),
    new asn1js.OctetString({ valueHex: ab(keyHash) }),
    new asn1js.Integer({ valueHex: ab(Buffer.from(leaf.serialNumber.valueBlock
                                                  .valueHexView)) })
  ] });
  const der = new asn1js.Sequence({ value: [
    new asn1js.Sequence({ value: [
      new asn1js.Sequence({ value: [
        new asn1js.Sequence({ value: [certId] }) ] }) ] }) ] }).toBER(false);
  log.debug("Leaving ocspRequestFor().");
  return Buffer.from(der);
}

async function ocspStatus(realm, leafDer, issuerDer) {
  log.debug("Entering ocspStatus().");
  const r = await fetch(base + "/pki/ocsp/" + realm + "/acme", {
    method: "POST", headers: { "Content-Type": "application/ocsp-request" },
    body: ocspRequestFor(leafDer, issuerDer) });
  const bytes = Buffer.from(await r.arrayBuffer());
  assert.strictEqual(r.status, 200, "the OCSP responder answered");
  const response = new pkijs.OCSPResponse({ schema: asn1js.fromBER(
    bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength))
    .result });
  assert.strictEqual(response.responseStatus.valueBlock.valueDec, 0,
                     "the OCSP response is successful");
  const inner = response.responseBytes.response.valueBlock.valueHexView;
  const basic = new pkijs.BasicOCSPResponse({ schema: asn1js.fromBER(
    inner.buffer.slice(inner.byteOffset, inner.byteOffset + inner.byteLength))
    .result });
  const tag = basic.tbsResponseData.responses[0].certStatus.idBlock.tagNumber;
  log.debug("Leaving ocspStatus(). tag=" + tag);
  return ["good", "revoked", "unknown"][tag];
}

async function crlSerials(realm) {
  log.debug("Entering crlSerials().");
  const r = await fetch(base + "/pki/crl/" + realm + "/acme.crl");
  const bytes = Buffer.from(await r.arrayBuffer());
  assert.strictEqual(r.status, 200, "the ACME CRL is published");
  const crl = new pkijs.CertificateRevocationList({ schema: asn1js.fromBER(
    bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength))
    .result });
  log.debug("Leaving crlSerials().");
  return (crl.revokedCertificates || []).map(function (entry) {
    return Buffer.from(entry.userCertificate.valueBlock.valueHexView)
      .toString("hex").replace(/^(00)+/, "");
  });
}

function serialOf(x) {
  log.debug("Entering serialOf().");
  log.debug("Leaving serialOf().");
  return String(x.serialNumber).toLowerCase().replace(/^(00)+/, "");
}

// ---------------------------------------------------------------------------
// ONE ISSUANCE, END TO END: order, finalize, download, and the chain checked.
// ---------------------------------------------------------------------------
async function issue(client, key, kid, identifiers, profile, csrSpec) {
  log.debug("Entering issue(). profile=" + profile);
  const order = await client.newOrder(key, kid, identifiers,
                                      { profile: profile });
  assert.strictEqual(order.status, 201, profile + " order: " + order.text);
  assert.strictEqual(order.body.status, "ready");
  assert.strictEqual(order.body.profile, profile);
  const csr = await C.buildCsr(csrSpec);
  const done = await client.finalize(key, kid, order.body.finalize, csr.der);
  assert.strictEqual(done.status, 200, profile + " finalize: " + done.text);
  assert.strictEqual(done.body.status, "valid");
  const cert = await client.postAsGet(done.body.certificate, key, kid);
  assert.strictEqual(cert.status, 200, profile + " download: " + cert.text);
  const chain = C.splitPemChain(cert.text);
  log.debug("Leaving issue().");
  return { order: order, done: done, csr: csr, chain: chain,
           leaf: x509Of(chain[0]), type: cert.type,
           cacheControl: cert.headers.get("cache-control") };
}

function assertChain(result, root, intermediate, entryUri, ekus) {
  log.debug("Entering assertChain().");
  const x = result.chain.map(x509Of);
  assert.strictEqual(x.length, 3, "certificate, Issuing CA, Intermediate");
  assert.ok(x[0].checkIssued(x[1]) && x[0].verify(x[1].publicKey),
            "the leaf is signed by the ACME Issuing CA");
  assert.ok(x[1].checkIssued(x[2]) && x[1].verify(x[2].publicKey),
            "the Issuing CA is signed by the Intermediate");
  assert.ok(Buffer.from(x[2].raw).equals(Buffer.from(intermediate.raw)),
            "the Intermediate is this realm's own");
  assert.ok(x[2].checkIssued(root) && x[2].verify(root.publicKey),
            "the Intermediate is signed by the service Root");
  assert.ok(x.every(function (one) { return one.subject !== one.issuer; }),
            "no self-signed certificate travels in the chain");
  assert.ok(String(x[0].subjectAltName).indexOf("URI:" + entryUri) >= 0,
            "the subjectAltName names " + entryUri + ": " +
            x[0].subjectAltName);
  const has = x[0].keyUsage || [];
  (ekus || []).forEach(function (oid) {
    assert.ok(has.indexOf(oid) >= 0, "EKU " + oid + " in " + has.join(","));
  });
  assert.strictEqual(result.type, "application/pem-certificate-chain");
  assert.ok(/no-store/.test(result.cacheControl || ""), "no-store");
  log.debug("Leaving assertChain().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving " + base + " in the trust realm \"" + REALM + "\".");

  // -------------------------------------------------------------------------
  log.info("=== 0. three realms, their CAs, people and an application ===");
  for (const realm of [REALM, REALM_B]) {
    await ok(api + "/realms/create", { id: realm, name: "ACME " + realm },
             "created the trust realm " + realm);
    await ok(realmApi(realm) + "/pki/build", { organisation: "ACME Job" },
             "built a certificate authority in " + realm);
    for (const who of [ALICE, BOB]) {
      await ok(realmApi(realm) + "/users/create",
               { username: who, invent: false, credential: "none",
                 attributes: { cn: who, sn: who,
                               mail: who + "@example.test" } },
               "created " + who);
    }
    await setting(realm, "acme.attemptsPerAddress", 100000);
  }
  await ok(realmApi(REALM) + "/applications/create",
           { identifier: APP, protocols: ["oauth2"],
             fields: { oauthClientId: APP } }, "created an application");
  await ok(realmApi(REALM) + "/acme/add-host-name",
           { kind: "person", identifier: ALICE,
             hostName: "www." + ALICE + ".test" }, "registered a host name");
  const expiring = await ok(realmApi(REALM) + "/acme/create-eab",
    { kind: "person", identifier: BOB, lifetimeS: 60 },
    "created a sixty-second EAB key, to present once it has expired");
  const root = await rootCertificate();
  const intermediate = await realmIntermediate(REALM);

  // -------------------------------------------------------------------------
  log.info("=== 1. the directory ===");
  const client = new C.AcmeClient(base + "/realm/" + REALM +
                                  "/enroll/acme/directory");
  const dir = await client.directory();
  check("the directory is absolute in the realm, requires EAB and lists nine " +
        "profiles", function () {
    assert.strictEqual(dir.status, 200);
    assert.strictEqual(dir.body.newOrder, base + "/realm/" + REALM +
                                          "/enroll/acme/new-order");
    assert.strictEqual(dir.body.meta.externalAccountRequired, true);
    assert.strictEqual(Object.keys(dir.body.meta.profiles).length, 9);
    assert.ok(dir.body.renewalInfo && dir.body.keyChange);
    assert.ok(dir.headers.get("replay-nonce"));
    assert.ok(/no-store/.test(dir.headers.get("cache-control")));
  });

  // -------------------------------------------------------------------------
  log.info("=== 2. accounts bound by External Account Binding ===");
  const aliceEab = await ok(realmApi(REALM) + "/acme/create-eab",
    { kind: "person", identifier: ALICE }, "created alice's EAB key");
  check("the EAB key is answered once, with a certbot line", function () {
    assert.ok(/^eab-p-/.test(aliceEab.kid) && aliceEab.hmacKey);
    assert.ok(aliceEab.certbot.indexOf(dir.body.newNonce.replace(/new-nonce$/,
      "directory")) >= 0);
  });
  const aliceKey = C.generateAccountKey("ES256");
  const noEab = await client.newAccount(aliceKey, null);
  check("a newAccount without a binding is externalAccountRequired",
        function () { problem(noEab, "externalAccountRequired", "no EAB"); });
  const badMac = await client.newAccount(aliceKey, { kid: aliceEab.kid,
    hmacKey: nodeCrypto.randomBytes(32).toString("base64url") });
  check("a binding MACed with the wrong key is unauthorized", function () {
    problem(badMac, "unauthorized", "wrong MAC");
  });
  const aliceAccount = await client.newAccount(aliceKey,
    { kid: aliceEab.kid, hmacKey: aliceEab.hmacKey });
  const aliceKid = aliceAccount.location;
  check("alice's account is created and bound (201)", function () {
    assert.strictEqual(aliceAccount.status, 201, aliceAccount.text);
    assert.strictEqual(aliceAccount.body.status, "valid");
  });
  const reused = await client.newAccount(C.generateAccountKey("RS256"),
    { kid: aliceEab.kid, hmacKey: aliceEab.hmacKey });
  check("the same EAB key presented for a second account key is refused",
        function () { problem(reused, "unauthorized", "EAB reuse"); });

  const clientB = new C.AcmeClient(base + "/realm/" + REALM_B +
                                   "/enroll/acme/directory");
  await clientB.directory();
  const crossEab = await clientB.newAccount(C.generateAccountKey("ES256"),
    { kid: aliceEab.kid, hmacKey: aliceEab.hmacKey });
  check("an EAB key from realm A presented at realm B is unauthorized",
        function () { problem(crossEab, "unauthorized", "cross-realm EAB"); });
  const crossKid = await clientB.newOrder(aliceKey, aliceKid,
    [{ type: "permanent-identifier", value: ALICE }]);
  check("an account of realm A used at realm B is accountDoesNotExist",
        function () {
    problem(crossKid, "accountDoesNotExist", "cross-realm");
  });

  const appEab = await ok(realmApi(REALM) + "/acme/create-eab",
    { kind: "application", identifier: APP }, "created the application's key");
  const appKey = C.generateAccountKey("RS256");
  const appAccount = await client.newAccount(appKey,
    { kid: appEab.kid, hmacKey: appEab.hmacKey });
  const appKid = appAccount.location;
  const bobEab = await ok(realmApi(REALM) + "/acme/create-eab",
    { kind: "person", identifier: BOB }, "created bob's key");
  const bobKey = C.generateAccountKey("EdDSA");
  const bobAccount = await client.newAccount(bobKey,
    { kid: bobEab.kid, hmacKey: bobEab.hmacKey });
  const bobKid = bobAccount.location;
  check("an application (RS256) and a second person (EdDSA) register too",
        function () {
    assert.strictEqual(appAccount.status, 201, appAccount.text);
    assert.strictEqual(bobAccount.status, 201, bobAccount.text);
  });

  // -------------------------------------------------------------------------
  log.info("=== 3. the nine profiles ===");
  const aliceUri = "urn:sts:person:" + ALICE;
  const perm = [{ type: "permanent-identifier", value: ALICE }];
  const permCsr = function (keyAlg) {
    return { keyAlg: keyAlg, cn: ALICE, sans: [{ kind: "uri",
                                                 value: aliceUri }] };
  };
  const issued = {};
  const plan = [
    ["tls-client", perm, permCsr("rsa-2048"), [EKU.clientAuth]],
    ["digital-signature", perm, permCsr("rsa-2048"), []],
    ["code-signing", perm, permCsr("rsa-2048"), [EKU.codeSigning]],
    ["timestamping", perm, permCsr("rsa-2048"), [EKU.timeStamping]],
    ["key-encipherment", perm, permCsr("rsa-2048"), []],
    ["tls-server", [{ type: "dns", value: "www." + ALICE + ".test" }],
     { keyAlg: "ec-p256", cn: "www." + ALICE + ".test",
       sans: [{ kind: "dns", value: "www." + ALICE + ".test" }] },
     [EKU.serverAuth]],
    ["tls-server-client", perm.concat([{ type: "dns",
                                         value: "www." + ALICE + ".test" }]),
     { keyAlg: "ec-p256", cn: ALICE, sans: [
       { kind: "dns", value: "www." + ALICE + ".test" },
       { kind: "uri", value: aliceUri }] },
     [EKU.serverAuth, EKU.clientAuth]],
    ["email", [{ type: "email", value: ALICE + "@example.test" }],
     { keyAlg: "ec-p256", cn: ALICE + "@example.test",
       sans: [{ kind: "email", value: ALICE + "@example.test" }] },
     [EKU.email]],
    ["smartcard-logon", perm, permCsr("rsa-2048"),
     [EKU.smartcard, EKU.clientAuth]]
  ];
  for (const row of plan) {
    issued[row[0]] = await issue(client, aliceKey, aliceKid, row[1], row[0],
                                 row[2]);
    check(row[0] + " is issued over ACME, chains to the realm Intermediate " +
          "and the Root, names the entry and carries its key usage",
          function () {
      assertChain(issued[row[0]], root, intermediate, aliceUri, row[3]);
    });
  }
  check("the tls-server certificate names the registered host", function () {
    assert.ok(/DNS:www\./.test(issued["tls-server"].leaf.subjectAltName));
  });
  check("the email certificate names the person's own mail", function () {
    assert.ok(issued.email.leaf.subjectAltName.indexOf("email:" + ALICE +
      "@example.test") >= 0, issued.email.leaf.subjectAltName);
  });
  check("the smartcard-logon certificate's UPN is the person's mail",
        function () {
    assert.strictEqual(C.upnOf(issued["smartcard-logon"].chain[0]),
                       ALICE + "@example.test");
  });
  check("the key-encipherment certificate was issued over an RSA key",
        function () {
    assert.strictEqual(issued["key-encipherment"].leaf.publicKey
                         .asymmetricKeyType, "rsa");
  });

  const appCert = await issue(client, appKey, appKid,
    [{ type: "permanent-identifier", value: APP }], "tls-client",
    { keyAlg: "ec-p256", cn: APP,
      sans: [{ kind: "uri", value: "urn:sts:application:" + APP }] });
  check("an application is issued a certificate for its own entry",
        function () {
    assertChain(appCert, root, intermediate, "urn:sts:application:" + APP,
                [EKU.clientAuth]);
  });

  const view = await send(realmApi(REALM) + "/acme?per=100");
  check("GET /admin-api/acme lists the certificates against their entries " +
        "and carries no private key or HMAC key", function () {
    assert.strictEqual(view.status, 200);
    const rows = view.body.certificates.rows;
    const serial = serialOf(issued["tls-client"].leaf);
    assert.ok(rows.some(function (row) {
      return String(row.serialHex).replace(/^0+/, "") ===
             serial.replace(/^0+/, "") && row.entryUri === aliceUri &&
             row.profile === "tls-client";
    }), JSON.stringify(rows).slice(0, 400));
    assert.ok(view.raw.indexOf("PRIVATE KEY") < 0);
    assert.ok(view.raw.indexOf(aliceEab.hmacKey) < 0);
    assert.ok(view.body.eabKeys.rows.some(function (row) {
      return row.kid === aliceEab.kid && row.status === "bound" &&
             row.createdBy === "admin-api";
    }), "the key an administrator created is listed bound");
  });

  // -------------------------------------------------------------------------
  log.info("=== 4. identity refusals ===");
  const forBob = await client.newOrder(aliceKey, aliceKid,
    [{ type: "permanent-identifier", value: BOB }]);
  check("a person ordering another person's identifier is rejectedIdentifier",
        function () {
    problem(forBob, "rejectedIdentifier", "another person");
    assert.strictEqual(forBob.body.subproblems[0].identifier.value, BOB);
  });
  const appForPerson = await client.newOrder(appKey, appKid,
    [{ type: "permanent-identifier", value: ALICE }]);
  const appForMail = await client.newOrder(appKey, appKid,
    [{ type: "email", value: ALICE + "@example.test" }], { profile: "email" });
  check("an application ordering a person's identifier or mail is " +
        "rejectedIdentifier", function () {
    problem(appForPerson, "rejectedIdentifier", "application for a person");
    problem(appForMail, "rejectedIdentifier", "application for a mail");
  });
  const unregistered = await client.newOrder(aliceKey, aliceKid,
    [{ type: "dns", value: "nope." + ALICE + ".test" }],
    { profile: "tls-server" });
  const notMine = await client.newOrder(aliceKey, aliceKid,
    [{ type: "email", value: BOB + "@example.test" }], { profile: "email" });
  check("an unregistered dns name and somebody else's mail are " +
        "rejectedIdentifier", function () {
    problem(unregistered, "rejectedIdentifier", "unregistered dns");
    problem(notMine, "rejectedIdentifier", "another mail");
  });
  for (const refused of ["root-ca", "intermediate-ca", "issuing-ca",
                         "ocsp-responder", "kdc"]) {
    const r = await client.newOrder(aliceKey, aliceKid, perm,
                                    { profile: refused });
    check("the " + refused + " profile is invalidProfile, saying why",
          function () {
      problem(r, "invalidProfile", refused);
      assert.ok(/never issued/.test(r.body.detail), r.body.detail);
    });
  }
  await setting(REALM, "acme.allowedProfiles", "tls-client");
  const narrowed = await client.newOrder(aliceKey, aliceKid, perm,
                                         { profile: "code-signing" });
  const narrowDir = await client.directory();
  await reset(REALM, "acme.allowedProfiles");
  check("a profile acme.allowedProfiles leaves out is invalidProfile and " +
        "gone from the directory", function () {
    problem(narrowed, "invalidProfile", "disabled profile");
    assert.deepStrictEqual(Object.keys(narrowDir.body.meta.profiles),
                           ["tls-client"]);
  });

  // -------------------------------------------------------------------------
  log.info("=== 5. CSR refusals ===");
  const csrOrder = await client.newOrder(aliceKey, aliceKid, perm,
                                         { profile: "tls-client" });
  const goodCsr = await C.buildCsr(permCsr("ec-p256"));
  const corrupt = await client.finalize(aliceKey, aliceKid,
    csrOrder.body.finalize, C.corruptSignature(goodCsr.der));
  const kem = await C.csrWithKemKey(permCsr("ec-p256"));
  const kemRefused = await client.finalize(aliceKey, aliceKid,
    csrOrder.body.finalize, kem.der);
  const extra = await C.buildCsr({ keyAlg: "ec-p256", cn: ALICE, sans: [
    { kind: "uri", value: aliceUri },
    { kind: "dns", value: "www." + ALICE + ".test" }] });
  const extraRefused = await client.finalize(aliceKey, aliceKid,
    csrOrder.body.finalize, extra.der);
  const garbage = await client.finalize(aliceKey, aliceKid,
    csrOrder.body.finalize, nodeCrypto.randomBytes(64));
  const notB64 = await client.post(csrOrder.body.finalize, { csr: "a+b/c=" },
                                   { key: aliceKey, kid: aliceKid });
  check("a CSR whose signature does not verify is badCSR", function () {
    problem(corrupt, "badCSR", "signature");
  });
  check("a CSR carrying an ML-KEM key is badPublicKey", function () {
    problem(kemRefused, "badPublicKey", "KEM");
  });
  check("a CSR naming what the order does not is badCSR", function () {
    problem(extraRefused, "badCSR", "names");
  });
  check("bytes that are not ASN.1 and a csr that is not base64url are badCSR",
        function () {
    problem(garbage, "badCSR", "ASN.1");
    problem(notB64, "badCSR", "base64url");
  });
  const finalized = await client.finalize(aliceKey, aliceKid,
    csrOrder.body.finalize, goodCsr.der);
  const again = await client.finalize(aliceKey, aliceKid,
    csrOrder.body.finalize, goodCsr.der);
  check("after all that the order still finalizes, and a second finalize " +
        "is orderNotReady", function () {
    assert.strictEqual(finalized.status, 200, finalized.text);
    problem(again, "orderNotReady", "finalize twice");
  });

  // -------------------------------------------------------------------------
  log.info("=== 6. the envelope ===");
  const big = await client.post(dir.body.newOrder, null,
    { key: aliceKey, kid: aliceKid, body: "{\"x\":\"" + "a".repeat(70000) +
      "\"}" });
  const wrongType = await client.post(dir.body.newOrder, { identifiers: perm },
    { key: aliceKey, kid: aliceKid, contentType: "application/json" });
  const badJson = await client.post(dir.body.newOrder, null,
    { key: aliceKey, kid: aliceKid, body: "{not json" });
  const badB64 = await client.post(dir.body.newOrder, { identifiers: perm },
    { key: aliceKey, kid: aliceKid, mutate: function (flat) {
      return Object.assign({}, flat, { payload: flat.payload + "==" });
    } });
  check("a body over acme.maxRequestBytes is 413 and the wrong media type 415",
        function () {
    assert.strictEqual(big.status, 413, big.text);
    assert.strictEqual(wrongType.status, 415, wrongType.text);
  });
  check("malformed JSON and malformed base64url are malformed", function () {
    problem(badJson, "malformed", "JSON");
    problem(badB64, "malformed", "base64url");
  });
  const nonce = await client.takeNonce();
  await client.postAsGet(aliceKid, aliceKey, aliceKid, { nonce: nonce });
  const replayed = await client.postAsGet(aliceKid, aliceKey, aliceKid,
                                          { nonce: nonce });
  check("a nonce presented twice is badNonce with a fresh one attached",
        function () {
    problem(replayed, "badNonce", "replay");
    assert.ok(replayed.headers.get("replay-nonce"));
  });
  const lying = await client.postAsGet(aliceKid, aliceKey, aliceKid,
                                       { url: dir.body.newOrder });
  const both = await client.post(dir.body.newOrder, { identifiers: perm },
    { key: aliceKey, kid: aliceKid, jwk: true });
  check("a url header that lies is unauthorized and jwk with kid malformed",
        function () {
    problem(lying, "unauthorized", "url");
    problem(both, "malformed", "jwk+kid");
  });
  await setting(REALM, "acme.nonceLifetimeS", 5);
  const shortNonce = await client.freshNonce();
  client.nonce = null;
  await sleep(6500);
  const stale = await client.postAsGet(aliceKid, aliceKey, aliceKid,
                                       { nonce: shortNonce });
  await reset(REALM, "acme.nonceLifetimeS");
  check("a nonce presented after acme.nonceLifetimeS is badNonce (expired)",
        function () {
    problem(stale, "badNonce", "expired nonce");
    assert.ok(/expired/.test(stale.body.detail), stale.body.detail);
  });

  // -------------------------------------------------------------------------
  log.info("=== 7. OCSP, revocation and the CRL ===");
  const target = issued["tls-client"];
  const leafDer = C.pemToDer(target.chain[0]);
  const issuerDer = C.pemToDer(target.chain[1]);
  const before = await ocspStatus(REALM, leafDer, issuerDer);
  check("the ACME Issuing CA's OCSP responder says good", function () {
    assert.strictEqual(before, "good");
  });
  const byBob = await client.revoke(bobKey, bobKid, leafDer, 1);
  check("an unrelated account revoking it is unauthorized", function () {
    problem(byBob, "unauthorized", "unrelated revoke");
  });
  const atB = await clientB.revoke(C.accountKeyFromPem("RS256",
    target.csr.privatePem), null, leafDer, 1);
  check("the certificate presented at realm B is not one issued there",
        function () {
    assert.strictEqual(atB.status, 404, atB.text);
  });
  const reason = await client.revoke(aliceKey, aliceKid, leafDer, 7);
  check("reason code 7 is badRevocationReason", function () {
    problem(reason, "badRevocationReason", "reason 7");
  });
  const revoked = await client.revoke(aliceKey, aliceKid, leafDer, 1);
  const already = await client.revoke(aliceKey, aliceKid, leafDer, 1);
  const after = await ocspStatus(REALM, leafDer, issuerDer);
  const serials = await crlSerials(REALM);
  check("revokeCert by the account revokes it: OCSP revoked, on the CRL, " +
        "and a second revokeCert is alreadyRevoked", function () {
    assert.strictEqual(revoked.status, 200, revoked.text);
    assert.strictEqual(after, "revoked");
    assert.ok(serials.indexOf(serialOf(target.leaf)) >= 0, serials.join(","));
    problem(already, "alreadyRevoked", "twice");
  });
  const byKey = await client.revoke(C.accountKeyFromPem("RS256",
    issued["code-signing"].csr.privatePem), null,
    C.pemToDer(issued["code-signing"].chain[0]), 4);
  check("the certificate's own key revokes it (jwk)", function () {
    assert.strictEqual(byKey.status, 200, byKey.text);
  });
  const consoleTarget = issued["digital-signature"];
  await ok(realmApi(REALM) + "/acme/revoke-certificate",
           { serial: serialOf(consoleTarget.leaf), reason: "superseded" },
           "revoked a certificate through the console action");
  const serialsAfter = await crlSerials(REALM);
  check("the console action's revocation is on the CRL too", function () {
    assert.ok(serialsAfter.indexOf(serialOf(consoleTarget.leaf)) >= 0);
  });
  const ari = await send(dir.body.renewalInfo + "/" +
                         C.certIdOf(issued.email.chain[0]));
  check("renewalInfo answers a suggested window for a certificate",
        function () {
    assert.strictEqual(ari.status, 200, ari.raw);
    assert.ok(ari.body.suggestedWindow.start < ari.body.suggestedWindow.end);
    assert.ok(ari.headers.get("retry-after"));
  });

  // -------------------------------------------------------------------------
  log.info("=== 8. key change ===");
  const clash = await client.keyChange(aliceKey, aliceKid, bobKey);
  check("a key change to another account's key is 409", function () {
    assert.strictEqual(clash.status, 409, clash.text);
    assert.strictEqual(clash.location, bobKid);
  });
  const newKey = C.generateAccountKey("ES384");
  const rolled = await client.keyChange(aliceKey, aliceKid, newKey);
  const oldUse = await client.postAsGet(aliceKid, aliceKey, aliceKid);
  const newUse = await client.postAsGet(aliceKid, newKey, aliceKid);
  check("a key change rolls the account over: the old key no longer signs " +
        "for it and the new one does", function () {
    assert.strictEqual(rolled.status, 200, rolled.text);
    assert.strictEqual(oldUse.status, 400, oldUse.text);
    assert.strictEqual(newUse.status, 200, newUse.text);
  });

  // -------------------------------------------------------------------------
  log.info("=== 9. the switch, the throttle and the expired key ===");
  await setting(REALM, "acme.enabled", false);
  const off = await send(dir.body.newNonce);
  await reset(REALM, "acme.enabled");
  const on = await send(dir.body.newNonce);
  check("acme.enabled off answers 503, and on again answers", function () {
    assert.strictEqual(off.status, 503);
    assert.strictEqual(on.status, 204);
  });
  await setting(REALM, "acme.attemptsPerIdentity", 3);
  const statuses = [];
  for (let i = 0; i < 5; i++) {
    const r = await client.newOrder(bobKey, bobKid,
      [{ type: "permanent-identifier", value: ALICE }]);
    statuses.push(r.status + (r.headers.get("retry-after") ? "+ra" : ""));
  }
  await reset(REALM, "acme.attemptsPerIdentity");
  check("after acme.attemptsPerIdentity refusals an account is rateLimited " +
        "with Retry-After", function () {
    assert.ok(statuses.indexOf("429+ra") >= 0, statuses.join(","));
    assert.strictEqual(statuses[0], "400");
  });

  const monitor = await send(realmApi(REALM) + "/acme/monitor");
  check("the monitor counted issuance, revocation and refusals", function () {
    assert.ok(monitor.body.totals.issued >= 11, JSON.stringify(
      monitor.body.totals));
    assert.ok(monitor.body.totals.revoked >= 3);
    assert.ok(monitor.body.totals.refused >= 20);
    assert.ok(monitor.body.errorCodes.length >= 5);
  });

  const waitFor = Date.parse(expiring.expiresAt) + 2000 - Date.now();
  if (waitFor > 0) {
    log.info("Waiting " + Math.ceil(waitFor / 1000) + "s for the " +
             "sixty-second " +
             "EAB key to expire.");
    await sleep(waitFor);
  }
  const expired = await client.newAccount(C.generateAccountKey("ES256"),
    { kid: expiring.kid, hmacKey: expiring.hmacKey });
  check("an EAB key presented after its lifetime is unauthorized (expired)",
        function () {
    problem(expired, "unauthorized", "expired EAB");
    assert.ok(/expired/.test(expired.body.detail), expired.body.detail);
  });

  // -------------------------------------------------------------------------
  log.info("=== 10. product mode ===");
  await ok(api + "/realms/create", { id: REALM_P, name: "ACME product",
                                     overrides: { "global.mode": "product" } },
           "created a product-mode realm");
  const clientP = new C.AcmeClient(base + "/realm/" + REALM_P +
                                   "/enroll/acme/directory");
  const dirP = await clientP.directory();
  check("a product-mode realm answers ACME over this TLS port", function () {
    assert.strictEqual(dirP.status, 200, JSON.stringify(dirP.body));
  });
  if (/^https:/.test(base)) {
    log.info("  (skipped) the product-mode refusal of plain HTTP needs a " +
             "plain listener serving ACME, and this stack's main port is " +
             "TLS; tests/acme_protocol.js asserts it in process.");
  }
  const productNoEab = await clientP.newAccount(C.generateAccountKey("ES256"),
    { kid: aliceEab.kid, hmacKey: aliceEab.hmacKey });
  check("and a product-mode realm still refuses a key that is not its own",
        function () { problem(productNoEab, "unauthorized", "product EAB"); });

  assert.ok(checks >= 45,
    "only " + checks + " checks ran; a section has stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_acme_enrollment")
  .description("The ACME server over HTTPS with an independent client: every " +
      "one of the nine profiles issued and chained to the Root, an " +
      "application issued for itself, OCSP, revocation and the CRL, key " +
      "change, renewal information, and every refusal — identity, profile, " +
      "CSR, envelope, realm, replay, expiry, switch and throttle.")
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

pkijs.setEngine("node", new pkijs.CryptoEngine({
  name: "node", crypto: nodeCrypto.webcrypto }));

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
