// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_enrollment_accounts.js
//
// ---------------------------------------------------------------------------
// A REVOCATION BY ANOTHER ACME ACCOUNT, AND A KEY THE CA CANNOT CERTIFY, BY
// THEIR CODES, OVER THE WIRE.
//
// D12 (#444): the last two of `tests/cert_enrollment.js`'s codes a client
// can meet, each read off the realm's audit log:
//
//   A. a certificate issued over ACME to one person's account is revoked
//      by ANOTHER person's account: refused `unauthorized`, recorded under
//      ACME's own STS-ACME-0063 (the core's STS-ENROLL-0071, the
//      certificate not the asking entry's, does not reach the audit log);
//      its own account then revokes it;
//   B. an EST request carrying a public key this CA cannot certify — an
//      X25519 key-agreement key in a template signed by an unrelated key —
//      is refused (STS-ENROLL-0031).
//
// OWNED HERE (local: true): this repository's own enrollment protocols.
// ---------------------------------------------------------------------------

const assert = require("assert");
const nodeCrypto = require("crypto");
const C = require("./acme_client.js");
const est = require("./est_client.js");
const K = require("./oauth_wire_kit.js").kit("sts_enrollment_accounts");
const log = K.log;

const FLOOR = 3;
const PW = "Ena-" + nodeCrypto.randomBytes(15).toString("base64url");

function check(what, fn) {
  log.debug("Entering check().");
  K.check(what, fn);
  log.debug("Leaving check().");
}

async function person(realm, who) {
  log.debug("Entering person(). " + who);
  log.debug("Leaving person().");
  return K.ok(K.rb(realm) + "/admin-api/users/create", { username: who,
    invent: false, credential: "password", password: PW,
    attributes: { cn: who, givenName: who, sn: who,
                  mail: who + "@ena.example.test" } }, "created " + who);
}

async function account(realm, client, who) {
  log.debug("Entering account(). " + who);
  const eab = await K.ok(K.rb(realm) + "/admin-api/acme/create-eab",
    { kind: "person", identifier: who }, "created " + who + "'s EAB key");
  const key = C.generateAccountKey("ES256");
  const made = await client.newAccount(key, { kid: eab.kid,
    hmacKey: eab.hmacKey });
  assert.strictEqual(made.status, 201, made.text);
  log.debug("Leaving account().");
  return { key: key, kid: made.location };
}

async function test() {
  log.debug("Entering test().");
  const realm = await K.realm("enracct");
  await K.ok(K.rb(realm) + "/admin-api/pki/build", { organisation: "Acct" },
             "built the CA");
  await K.set(realm, "acme.attemptsPerAddress", 100000);
  await K.set(realm, "est.attemptsPerAddress", 100000);
  const alice = "enaa-" + K.STAMP;
  const bob = "enab-" + K.STAMP;
  await person(realm, alice);
  await person(realm, bob);

  log.info("=== A. another account's revocation ===");
  const client = new C.AcmeClient(K.rb(realm) + "/enroll/acme/directory");
  await client.directory();
  const a = await account(realm, client, alice);
  const b = await account(realm, client, bob);
  const order = await client.newOrder(a.key, a.kid,
    [{ type: "permanent-identifier", value: alice }],
    { profile: "tls-client" });
  assert.strictEqual(order.status, 201, order.text);
  const csr = await C.buildCsr({ keyAlg: "ec-p256", cn: alice, sans: [
    { kind: "uri", value: "urn:sts:person:" + alice }] });
  const done = await client.finalize(a.key, a.kid, order.body.finalize,
                                     csr.der);
  assert.strictEqual(done.status, 200, done.text);
  const got = await client.postAsGet(done.body.certificate, a.key, a.kid);
  const leafDer = C.pemToDer(C.splitPemChain(got.text)[0]);
  const byBob = await K.coded(realm, "STS-ACME-0063", function () {
    return client.revoke(b.key, b.kid, leafDer, 1);
  });
  const audit = await K.send(K.rb(realm) + "/admin-api/audit?per=60");
  const seen = (JSON.stringify((audit.json || {}).events || [])
    .match(/STS-[A-Z]+-\d{4}/) || ["none"])[0];
  check("A1. another person's account revoking it is refused " +
        "unauthorized, recorded STS-ACME-0063 (ACME's own code; the core's " +
        "STS-ENROLL-0071 is not what reaches the audit log)", function () {
    assert.strictEqual(byBob.answer.status, 403, byBob.answer.text);
    assert.strictEqual(byBob.answer.body.type,
                       "urn:ietf:params:acme:error:unauthorized");
    assert.ok(byBob.rose >= 1, "rows: " + byBob.rose + "; newest " + seen);
    assert.ok(!/STS-[A-Z]+-\d{4}/.test(byBob.answer.text));
  });
  const byAlice = await client.revoke(a.key, a.kid, leafDer, 1);
  check("A2. its own account then revokes it", function () {
    assert.strictEqual(byAlice.status, 200, byAlice.text);
  });

  log.info("=== B. a key this CA cannot certify ===");
  const x = nodeCrypto.generateKeyPairSync("x25519");
  const template = est.kemTemplateCsr(x.publicKey.export({ type: "spki",
                                                           format: "pem" }),
                                      alice);
  const r = await K.coded(realm, "STS-ENROLL-0031", function () {
    return est.send({ method: "POST",
      url: K.rb(realm) + "/.well-known/est/tls-client/simpleenroll",
      headers: { "Content-Type": "application/pkcs10" },
      body: est.requestBody(template), basic: [alice, PW] });
  });
  check("B. an X25519 key in a request is refused (STS-ENROLL-0031)",
        function () {
    assert.ok(r.answer.status >= 400, r.answer.status + " " +
              String(r.answer.body).slice(0, 200));
    assert.ok(r.rose >= 1, "rows: " + r.rose + " (" + r.answer.status +
              " " + String(r.answer.body).slice(0, 200) + ")");
  });
  log.debug("Leaving test().");
}

K.main(test, FLOOR);
