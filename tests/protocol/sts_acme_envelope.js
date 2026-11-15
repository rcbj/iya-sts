// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_acme_envelope.js
//
// ---------------------------------------------------------------------------
// THE ACME ENVELOPE, READ STRICTLY, OVER THE WIRE, BY ITS CODES.
//
// D12 (#444): carries over the part of `tests/acme_jws.js` and
// `tests/acme_protocol.js` a client can see. `sts_acme_enrollment.js` drives
// the whole protocol and its refusals by their ACME problem types; this job
// sends the envelopes those two files read as a library — each refusal
// answered `malformed` (or `badNonce`) 400 and recorded under its own code
// on the realm's `/admin-api/audit`, never in the answer:
//
//   A. a body that is not exactly `protected`, `payload`, `signature`
//      (STS-ACME-0012), a member that is not strict base64url (0013), a
//      protected header carrying `crit`, `jku`, `x5u` or `b64` (0014);
//   B. a signature that does not verify with the account key, and an ES256
//      signature sent under the name RS256 (0024);
//   C. a POST-as-GET carrying a payload, a newOrder with none, and a payload
//      that is not JSON (0025);
//   D. an external account binding whose header carries an extra member,
//      names another url, or whose payload is another key (0032);
//   E. a Replay-Nonce spent twice (0018), answered `badNonce` with a fresh
//      Replay-Nonce, and a nonce another realm issued refused the same way;
//   F. the account key's thumbprint: the account URL is per key, so a second
//      newAccount with the same key and `onlyReturnExisting` finds it.
//
// NOT carried, and why: the parsers' tables (the media-type spellings, the
// RFC 7638 and RFC 9773 vectors, the mailto rules as a function), the nonce
// MAC's construction and secret, and the seven stores per realm are class
// (d): library facts and module state. The product realm's plain-HTTP
// refusal needs the plain listener in product mode, which no stack offers
// (phases 3-4 recorded the same).
//
// OWNED HERE (local: true): this repository's own ACME server.
// ---------------------------------------------------------------------------

const assert = require("assert");
const C = require("./acme_client.js");
const K = require("./oauth_wire_kit.js").kit("sts_acme_envelope");
const log = K.log;

const FLOOR = 18;
const P = "urn:ietf:params:acme:error:";

function check(what, fn) {
  log.debug("Entering check().");
  K.check(what, fn);
  log.debug("Leaving check().");
}

// A refusal that is an ACME problem of `type`, 400, with no code in it.
function problem(r, type, what) {
  log.debug("Entering problem(). " + what);
  assert.strictEqual(r.status, 400, what + ": " + r.status + " " +
                     String(r.text).slice(0, 300));
  assert.strictEqual(r.body && r.body.type, P + type,
                     what + ": " + String(r.text).slice(0, 300));
  assert.ok(/application\/problem\+json/.test(r.type), r.type);
  assert.ok(!/STS-[A-Z]+-\d{4}/.test(r.text), "a code was sent: " + r.text);
  log.debug("Leaving problem().");
}

// Sends one request and reads how many rows of `code` it added.
async function coded(realm, code, act) {
  log.debug("Entering coded(). " + code);
  const out = await K.coded(realm, code, act);
  log.debug("Leaving coded(). " + out.rose);
  return out;
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. a realm, its CA, a person and an account ===");
  const realm = await K.realm("acmeenv");
  const other = await K.realm("acmeenv2");
  for (const id of [realm, other]) {
    await K.ok(K.rb(id) + "/admin-api/pki/build", { organisation: "ACME" },
               "built " + id + "'s certificate authority");
    await K.set(id, "acme.attemptsPerAddress", 100000);
  }
  const who = "envp-" + K.STAMP;
  await K.ok(K.rb(realm) + "/admin-api/users/create", { username: who,
    invent: false, credential: "none", attributes: { cn: who,
      givenName: who, sn: who, mail: who + "@example.test" } },
    "created " + who);
  const client = new C.AcmeClient(K.rb(realm) + "/enroll/acme/directory");
  await client.directory();
  const eab = await K.ok(K.rb(realm) + "/admin-api/acme/create-eab",
    { kind: "person", identifier: who }, "created the EAB key");
  const key = C.generateAccountKey("ES256");
  const made = await client.newAccount(key, { kid: eab.kid,
    hmacKey: eab.hmacKey });
  assert.strictEqual(made.status, 201, made.text);
  const kid = made.location;
  const order = client.dir.newOrder;
  const ids = { identifiers: [{ type: "permanent-identifier",
    value: "urn:sts:person:" + who }] };

  log.info("=== A. the flattened JWS and its protected header ===");
  const extra = await coded(realm, "STS-ACME-0012", function () {
    return client.post(order, ids, { key: key, kid: kid,
      mutate: function (jws) {
        return Object.assign({}, jws, { header: { kid: kid } });
      } });
  });
  check("A1. a fourth member beside protected, payload and signature is " +
        "malformed, recorded STS-ACME-0012", function () {
    problem(extra.answer, "malformed", "an unprotected header");
    assert.ok(extra.rose >= 1, "STS-ACME-0012 rows: " + extra.rose);
  });
  const notJws = await coded(realm, "STS-ACME-0012", function () {
    return client.post(order, ids, { key: key, kid: kid,
      body: JSON.stringify(["not", "an", "object"]) });
  });
  check("A2. a body that is not a JWS object is malformed (STS-ACME-0012)",
        function () {
    problem(notJws.answer, "malformed", "an array");
    assert.ok(notJws.rose >= 1, "STS-ACME-0012 rows: " + notJws.rose);
  });
  const padded = await coded(realm, "STS-ACME-0013", function () {
    return client.post(order, ids, { key: key, kid: kid,
      mutate: function (jws) {
        return Object.assign({}, jws, { payload: jws.payload + "==" });
      } });
  });
  check("A3. a payload with base64 padding is not strict base64url, " +
        "recorded STS-ACME-0013", function () {
    problem(padded.answer, "malformed", "padding");
    assert.ok(padded.rose >= 1, "STS-ACME-0013 rows: " + padded.rose);
  });
  for (const member of [{ crit: ["exp"] }, { jku: "https://a.example/k" },
                        { x5u: "https://a.example/c" }, { b64: false }]) {
    const name = Object.keys(member)[0];
    const r = await coded(realm, "STS-ACME-0014", function () {
      return client.post(order, ids, { key: key, kid: kid, header: member });
    });
    check("A4. a protected header carrying " + name + " is malformed, " +
          "recorded STS-ACME-0014", function () {
      problem(r.answer, "malformed", name);
      assert.ok(r.rose >= 1, "STS-ACME-0014 rows: " + r.rose);
    });
  }

  log.info("=== B. the signature ===");
  const flipped = await coded(realm, "STS-ACME-0024", function () {
    return client.post(order, ids, { key: key, kid: kid,
      mutate: function (jws) {
        const sig = Buffer.from(jws.signature, "base64url");
        sig[sig.length - 1] ^= 1;
        return Object.assign({}, jws, { signature: sig.toString("base64url") });
      } });
  });
  check("B1. a signature that does not verify with the account key is " +
        "refused, recorded STS-ACME-0024", function () {
    assert.strictEqual(flipped.answer.status, 400, flipped.answer.text);
    assert.ok(!/STS-[A-Z]+-\d{4}/.test(flipped.answer.text));
    assert.ok(flipped.rose >= 1, "STS-ACME-0024 rows: " + flipped.rose);
  });
  const misnamed = await client.post(order, ids, { key: key, kid: kid,
    header: { alg: "RS256" } });
  check("B2. an ES256 signature sent under the name RS256 is refused, and " +
        "nothing is ordered", function () {
    assert.strictEqual(misnamed.status, 400, misnamed.text);
    assert.ok(/badSignatureAlgorithm|malformed/.test(misnamed.body.type),
              misnamed.text);
    assert.ok(!misnamed.location, misnamed.text);
  });

  log.info("=== C. the payload ===");
  const placed = await client.newOrder(key, kid, ids.identifiers);
  assert.strictEqual(placed.status, 201, placed.text);
  const asGet = await client.postAsGet(placed.location, key, kid);
  const withBody = await coded(realm, "STS-ACME-0025", function () {
    return client.post(placed.location, {}, { key: key, kid: kid });
  });
  check("C1. an order read as POST-as-GET is answered; with a payload " +
        "where POST-as-GET is required it is malformed (STS-ACME-0025)",
        function () {
    assert.strictEqual(asGet.status, 200, asGet.text);
    problem(withBody.answer, "malformed", "a payload on POST-as-GET");
    assert.ok(withBody.rose >= 1, "STS-ACME-0025 rows: " + withBody.rose);
  });
  // Both signed properly, so the refusal is the payload's own.
  const none = await coded(realm, "STS-ACME-0025", function () {
    return client.post(order, null, { key: key, kid: kid });
  });
  check("C2. a newOrder with no payload is malformed, recorded " +
        "STS-ACME-0025", function () {
    problem(none.answer, "malformed", "no payload");
    assert.ok(none.rose >= 1, "STS-ACME-0025 rows: " + none.rose);
  });
  const notJson = await client.post(order, { raw: Buffer.from("{not json")
    .toString("base64url") }, { key: key, kid: kid });
  check("C3. a signed payload that is not JSON is malformed, and nothing " +
        "is ordered", function () {
    problem(notJson, "malformed", "not JSON");
    assert.ok(!notJson.location, notJson.text);
  });

  log.info("=== D. the external account binding ===");
  const eab2 = await K.ok(K.rb(realm) + "/admin-api/acme/create-eab",
    { kind: "person", identifier: who }, "created a second EAB key");
  const cases = [
    ["an extra header member", { extraHeader: { nonce: "x" } }],
    ["another url", { url: K.rb(realm) + "/enroll/acme/new-order" }],
    ["another key as the payload",
     { jwk: C.generateAccountKey("ES256").jwk }]
  ];
  for (const one of cases) {
    const r = await coded(realm, "STS-ACME-0032", function () {
      return client.newAccount(C.generateAccountKey("ES256"),
        Object.assign({ kid: eab2.kid, hmacKey: eab2.hmacKey }, one[1]));
    });
    check("D. a binding with " + one[0] + " is refused, recorded " +
          "STS-ACME-0032", function () {
      assert.strictEqual(r.answer.status, 400, r.answer.text);
      assert.ok(/malformed|badSignatureAlgorithm/.test(r.answer.body.type),
                r.answer.text);
      assert.ok(r.rose >= 1, "STS-ACME-0032 rows: " + r.rose);
    });
  }

  log.info("=== E. the Replay-Nonce ===");
  const nonce = await client.freshNonce();
  const first = await client.post(order, ids, { key: key, kid: kid,
    nonce: nonce });
  const again = await coded(realm, "STS-ACME-0018", function () {
    return client.post(order, ids, { key: key, kid: kid, nonce: nonce });
  });
  check("E1. a nonce is spent once: the second use is badNonce, with a " +
        "fresh Replay-Nonce, recorded STS-ACME-0018", function () {
    assert.strictEqual(first.status, 201, first.text);
    problem(again.answer, "badNonce", "a reused nonce");
    const fresh = again.answer.headers.get("replay-nonce");
    assert.ok(fresh && fresh !== nonce, String(fresh));
    assert.ok(again.rose >= 1, "STS-ACME-0018 rows: " + again.rose);
  });
  const elsewhere = new C.AcmeClient(K.rb(other) + "/enroll/acme/directory");
  await elsewhere.directory();
  const foreign = await elsewhere.freshNonce();
  const crossed = await client.post(order, ids, { key: key, kid: kid,
    nonce: foreign });
  check("E2. a nonce another realm issued is badNonce here", function () {
    problem(crossed, "badNonce", "a foreign nonce");
  });

  log.info("=== F. one account per key ===");
  const existing = await client.post(client.dir.newAccount,
    { onlyReturnExisting: true }, { key: key, jwk: true });
  check("F. newAccount with onlyReturnExisting and the same key finds the " +
        "same account URL (RFC 7638 thumbprint)", function () {
    assert.strictEqual(existing.status, 200, existing.text);
    assert.strictEqual(existing.location, kid);
  });
  log.debug("Leaving test().");
}

K.main(test, FLOOR);
