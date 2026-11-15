// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_enrollment_codes.js
//
// ---------------------------------------------------------------------------
// THE REST OF THE ENROLLMENT CODES A CLIENT CAN MEET, OVER THE WIRE.
//
// D12 (#444): what `sts_enrollment_rules.js` left owed of
// `tests/cert_enrollment.js`, `tests/est_handlers.js` and
// `tests/application_enrollment.js`, each refusal's code read off the
// realm's audit log:
//
//   A. EST'S DOOR: a label naming the realm the prefix already named
//      (STS-EST-0022); `/nonce` POSTed with another media type (0035), a
//      `len` outside 8..64 (0034), a `reqTypeInfo` type with no answer
//      (0036); an `/admin-api/est` body that fails validation (0031, or the
//      request schema's STS-API-0009 first);
//   B. EST WITH A CLIENT CERTIFICATE: a re-enrollment whose subject differs
//      from the certificate being renewed (STS-EST-0016); a certificate
//      that does not certify clientAuth presented to authenticate
//      (STS-ENROLL-0019); an ML-KEM template at a profile that is not
//      key-encipherment (STS-EST-0017);
//   C. THE CORE: a CA profile named as an EST label (STS-ENROLL-0002);
//      a development realm refuses an RSA-1024 key (STS-ENROLL-0031,
//      #35; it was certified, which this job pinned);
//   D. AN APPLICATION IN A PRODUCT REALM: a wrong client secret
//      (STS-ENROLL-0016), Basic authentication its own
//      `estBasicAuthentication` turns off (STS-ENROLL-0096);
//   E. ACME: a newOrder naming a CA profile (refused `invalidProfile`
//      with the core's sentence; ACME records its own code), and one
//      `replaces` a certificate never issued, refused `malformed` (its
//      code is ACME's own, not STS-ENROLL-0092).
//
// NOT carried, and why: /serverkeygen's DecryptKeyIdentifier (STS-EST-0018)
// needs a template attribute the suite's CSR builder does not write; an ACME
// revocation of another account's certificate (STS-ENROLL-0071) needs a
// whole ACME issuance per account, which `sts_acme_enrollment.js` makes and
// refuses by problem type.
//
// OWNED HERE (local: true): this repository's own enrollment protocols.
// ---------------------------------------------------------------------------

const assert = require("assert");
const path = require("path");
const nodeCrypto = require("crypto");
const est = require("./est_client.js");
const C = require("./acme_client.js");
const K = require("./oauth_wire_kit.js").kit("sts_enrollment_codes");
const log = K.log;

const REPO = process.env.MOCK_STS_DIR || path.join(__dirname, "..", "..");
const x509 = require(path.join(REPO, "common", "crypto_impl", "x509.js"));
const keys = require(path.join(REPO, "common", "crypto_impl",
                               "key_material.js"));

const FLOOR = 14;

function check(what, fn) {
  log.debug("Entering check().");
  K.check(what, fn);
  log.debug("Leaving check().");
}

async function csr(commonName, names, alg) {
  log.debug("Entering csr().");
  const pair = await keys.generateKeyPair(alg || "ec-p256");
  const built = await x509.certificationRequest({ subject: "CN=" + commonName,
    publicKeyPem: pair.publicPem, privateKeyPem: pair.privatePem,
    subjectAltName: names || [] });
  log.debug("Leaving csr().");
  return { der: Buffer.from(built.der), pair: pair };
}

function send(url, body, extra) {
  log.debug("Entering send(). " + url);
  const more = extra || {};
  log.debug("Leaving send().");
  return est.send({ method: more.method || "POST", url: url,
    body: body === null ? undefined
      : (Buffer.isBuffer(body) ? est.requestBody(body) : body),
    headers: Object.assign({ "Content-Type": "application/pkcs10" },
                           more.headers || {}),
    basic: more.basic, key: more.key, cert: more.cert });
}

function certOf(r) {
  log.debug("Entering certOf().");
  assert.strictEqual(r.status, 200, "issued: " + r.status + " " +
                     String(r.body).slice(0, 200));
  const parsed = est.parseCertsOnly(est.base64Body(r.body));
  log.debug("Leaving certOf().");
  return parsed.certificates[0];
}

async function refusedBy(realm, code, act) {
  log.debug("Entering refusedBy(). " + code);
  const out = await K.coded(realm, code, act);
  log.debug("Leaving refusedBy(). " + out.rose);
  return { status: out.answer.status, rose: out.rose,
           text: String(out.answer.body !== undefined ? out.answer.body
                                                      : out.answer.text) };
}

function refusal(what, r, code) {
  log.debug("Entering refusal(). " + code);
  check(what + " (" + code + ")", function () {
    assert.ok(r.status >= 400, r.status + " " + r.text.slice(0, 200));
    assert.ok(r.rose >= 1, code + " rows: " + r.rose + " (" + r.status +
              " " + r.text.slice(0, 200) + ")");
    assert.ok(!/STS-[A-Z]+-\d{4}/.test(r.text), "a code was sent");
  });
  log.debug("Leaving refusal().");
}

async function person(realm, name) {
  log.debug("Entering person(). " + name);
  const password = "Enc-" + nodeCrypto.randomBytes(15).toString("base64url");
  await K.ok(K.rb(realm) + "/admin-api/users/create", { username: name,
    invent: false, credential: "password", password: password,
    attributes: { cn: name, givenName: name, sn: name,
                  mail: name + "@enc.example.test" } }, "created " + name);
  log.debug("Leaving person().");
  return [name, password];
}

async function door(realm, E, alice) {
  log.debug("Entering door().");
  log.info("=== A. EST's door ===");
  const good = await csr(alice[0]);
  refusal("A1. a label naming the realm the prefix already named",
    await refusedBy(realm, "STS-EST-0022", function () {
      return send(E + "/" + realm + "/simpleenroll", good.der,
                  { basic: alice });
    }), "STS-EST-0022");
  const NONCE = "application/est-attestation-freshness+json";
  refusal("A2. /nonce POSTed as application/json",
    await refusedBy(realm, "STS-EST-0035", function () {
      return send(E + "/nonce", JSON.stringify({ len: 16 }),
        { basic: alice, headers: { "Content-Type": "application/json" } });
    }), "STS-EST-0035");
  refusal("A3. /nonce with a len outside 8..64",
    await refusedBy(realm, "STS-EST-0034", function () {
      return send(E + "/nonce", JSON.stringify({ len: 3 }),
        { basic: alice, headers: { "Content-Type": NONCE } });
    }), "STS-EST-0034");
  refusal("A4. /nonce naming a reqTypeInfo type with no answer",
    await refusedBy(realm, "STS-EST-0036", function () {
      return send(E + "/nonce", JSON.stringify({ len: 16,
        reqTypeInfo: { type: "1.2.3.4.5.6.7" } }),
        { basic: alice, headers: { "Content-Type": NONCE } });
    }), "STS-EST-0036");
  const bad = await K.coded(realm, "STS-EST-0031", function () {
    return K.send(K.rb(realm) + "/admin-api/est/add-host-name",
                  { json: { kind: "person" } });
  });
  const api9 = await K.codeCount(realm, "STS-API-0009");
  check("A5. an /admin-api/est body that fails validation is refused 400 " +
        "(STS-EST-0031, or the request schema's STS-API-0009 first)",
        function () {
    assert.strictEqual(bad.answer.status, 400, K.shown(bad.answer));
    assert.ok(bad.rose >= 1 || api9 >= 1, "0031 rows " + bad.rose +
              ", API-0009 rows " + api9);
  });
  log.debug("Leaving door().");
}

async function withCertificate(realm, E, alice) {
  log.debug("Entering withCertificate().");
  log.info("=== B. EST with a client certificate ===");
  const first = await csr(alice[0]);
  const client = certOf(await send(E + "/tls-client/simpleenroll", first.der,
                                   { basic: alice }));
  const other = await csr("someone-else-" + K.STAMP);
  refusal("B1. a re-enrollment whose subject differs from the certificate " +
          "being renewed",
    await refusedBy(realm, "STS-EST-0016", function () {
      return send(E + "/simplereenroll", other.der,
                  { key: first.pair.privatePem, cert: client });
    }), "STS-EST-0016");
  await K.ok(K.rb(realm) + "/admin-api/est/add-host-name", { kind: "person",
    identifier: alice[0], hostName: alice[0] + ".host.example.test" },
    "registered a host name");
  const srv = await csr(alice[0], [{ kind: "dns",
                                     value: alice[0] + ".host.example.test" }]);
  const serverOnly = certOf(await send(E + "/tls-server/simpleenroll",
                                       srv.der, { basic: alice }));
  refusal("B2. a certificate that does not certify clientAuth is no " +
          "enrollment credential",
    await refusedBy(realm, "STS-ENROLL-0019", async function () {
      return send(E + "/tls-client/simpleenroll", (await csr(alice[0])).der,
                  { key: srv.pair.privatePem, cert: serverOnly });
    }), "STS-ENROLL-0019");
  const kem = await keys.generateKeyPair("ml-kem-768");
  refusal("B3. an ML-KEM template at a profile that is not " +
          "key-encipherment is refused",
    await refusedBy(realm, "STS-EST-0017", function () {
      return send(E + "/tls-client/serverkeygen",
                  est.kemTemplateCsr(kem.publicPem, alice[0]),
                  { basic: alice });
    }), "STS-EST-0017");
  log.debug("Leaving withCertificate().");
}

async function core(realm, E, alice) {
  log.debug("Entering core().");
  log.info("=== C. the core ===");
  const weak = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 1024 });
  const built = await x509.certificationRequest({ subject: "CN=" + alice[0],
    publicKeyPem: weak.publicKey.export({ type: "spki", format: "pem" }),
    privateKeyPem: weak.privateKey.export({ type: "pkcs8", format: "pem" }),
    subjectAltName: [] });
  // REFUSED IN EVERY MODE (#35, 2026-11-15): an RSA key under 2048 bits is
  // a key this authority cannot certify, STS-ENROLL-0031. Until #35 a
  // development realm certified it, which this job pinned.
  refusal("C1. a development realm refuses an RSA-1024 key",
    await refusedBy(realm, "STS-ENROLL-0031", function () {
      return send(E + "/tls-client/simpleenroll", Buffer.from(built.der),
                  { basic: alice });
    }), "STS-ENROLL-0031");
  refusal("C2. a CA profile named as an EST label is refused by design",
    await refusedBy(realm, "STS-ENROLL-0002", async function () {
      return send(E + "/issuing-ca/simpleenroll", (await csr(alice[0])).der,
                  { basic: alice });
    }), "STS-ENROLL-0002");
  log.debug("Leaving core().");
}

async function applications() {
  log.debug("Entering applications().");
  log.info("=== D. an application in a product realm ===");
  const realm = await K.realm("encapp");
  await K.ok(K.rb(realm) + "/admin-api/pki/build", { organisation: "Enc" },
             "built the CA");
  await K.set(realm, "est.attemptsPerAddress", 100000);
  const secret = "Enc-" + nodeCrypto.randomBytes(15).toString("base64url");
  const app = "encapp-" + K.STAMP;
  const noBasic = "encnob-" + K.STAMP;
  for (const one of [[app, {}], [noBasic, { estBasicAuthentication: false }]]) {
    await K.ok(K.rb(realm) + "/admin-api/applications/create", {
      identifier: one[0], protocols: ["oauth2", "est"],
      fields: Object.assign({ oauthClientId: one[0],
                              oauthClientSecret: secret }, one[1]) },
      "created " + one[0]);
  }
  await K.set(realm, "global.mode", "product");
  const E = K.rb(realm) + "/.well-known/est";
  refusal("D1. in product a wrong client secret is refused",
    await refusedBy(realm, "STS-ENROLL-0016", async function () {
      return send(E + "/tls-client/simpleenroll", (await csr(app)).der,
                  { basic: [app, "wrong-" + secret] });
    }), "STS-ENROLL-0016");
  refusal("D2. Basic authentication its own estBasicAuthentication turns " +
          "off is refused",
    await refusedBy(realm, "STS-ENROLL-0096", async function () {
      return send(E + "/tls-client/simpleenroll", (await csr(noBasic)).der,
                  { basic: [noBasic, secret] });
    }), "STS-ENROLL-0096");
  log.debug("Leaving applications().");
}

async function acme(realm, alice) {
  log.debug("Entering acme().");
  log.info("=== E. ACME ===");
  await K.set(realm, "acme.attemptsPerAddress", 100000);
  const client = new C.AcmeClient(K.rb(realm) + "/enroll/acme/directory");
  await client.directory();
  const eab = await K.ok(K.rb(realm) + "/admin-api/acme/create-eab",
    { kind: "person", identifier: alice[0] }, "created an EAB key");
  const key = C.generateAccountKey("ES256");
  const made = await client.newAccount(key, { kid: eab.kid,
    hmacKey: eab.hmacKey });
  assert.strictEqual(made.status, 201, made.text);
  const ids = [{ type: "permanent-identifier",
                 value: "urn:sts:person:" + alice[0] }];
  const ca = await client.newOrder(key, made.location, ids,
                                   { profile: "issuing-ca" });
  check("E1. a newOrder naming a CA profile is refused invalidProfile, " +
        "saying it is never issued over an enrollment protocol", function () {
    assert.strictEqual(ca.status, 400, ca.text);
    assert.strictEqual(ca.body.type,
                       "urn:ietf:params:acme:error:invalidProfile");
    assert.ok(/never issued over an enrollment protocol/.test(
      ca.body.detail), ca.text);
  });
  const replaces = await client.newOrder(key, made.location, ids,
    { replaces: "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE" });
  check("E2. a newOrder replacing a certificate never issued is refused " +
        "malformed, naming RFC 9773's rule", function () {
    assert.strictEqual(replaces.status, 400, replaces.text);
    assert.ok(/replaces/.test(replaces.body.detail), replaces.text);
  });
  log.debug("Leaving acme().");
}

async function test() {
  log.debug("Entering test().");
  const realm = await K.realm("enccodes");
  await K.ok(K.rb(realm) + "/admin-api/pki/build", { organisation: "Enc" },
             "built the CA");
  await K.set(realm, "est.attemptsPerAddress", 100000);
  const alice = await person(realm, "enca-" + K.STAMP);
  const E = K.rb(realm) + "/.well-known/est";
  await door(realm, E, alice);
  await withCertificate(realm, E, alice);
  await core(realm, E, alice);
  await acme(realm, alice);
  await applications();
  log.debug("Leaving test().");
}

K.main(test, FLOOR);
