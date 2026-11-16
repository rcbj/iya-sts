// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_scep_rules.js
//
// ---------------------------------------------------------------------------
// SCEP'S CMS RULES, BY THEIR CODES, OVER THE WIRE.
//
// D12 (#444): carries over what a client can see of `tests/scep_enrollment.js`
// (SCEP's CMS codec and handlers, in process). `sts_scep_enrollment.js`
// drives the nine profiles and most refusals; this job sends the messages
// that file built by hand to the codec, through the running service's
// /enroll/scep, and reads each refusal's code off the realm's SCEP monitor
// and audit log — never off the answer:
//
//   A. a pkiMessage whose transactionID is empty (STS-SCEP-0012);
//   B. a messageDigest that is not the digest of the content: one byte of
//      the encapsulated envelope changed after signing (STS-SCEP-0022);
//   C. a pkcsPKIEnvelope for another certificate (STS-SCEP-0027), and one
//      that names the RA but is encrypted to another key: the unwrap fails
//      and is answered as any failed unwrap is, a FAILURE CertRep that does
//      not tell a wrong key from bad padding (STS-SCEP-0030);
//   D. the management API: a body that fails validation (STS-SCEP-0061) and
//      an action that does not exist (STS-SCEP-0062).
//
// NOT carried, and why: the transaction store per realm and the zod schema
// against the OpenAPI body are class (d) (module state, a document
// comparison); a public key this CA cannot certify (STS-ENROLL-0031) needs
// a key type the job's CMS builder cannot carry (forge signs RSA only), so
// it is owed; a CA profile is `sts_scep_enrollment.js`'s refused-profile
// row by its answer.
//
// OWNED HERE (local: true): this repository's own SCEP server.
// ---------------------------------------------------------------------------

const assert = require("assert");
const nodeCrypto = require("crypto");
const forge = require("node-forge");
const client = require("./scep_client.js");
const K = require("./oauth_wire_kit.js").kit("sts_scep_rules");
const log = K.log;

const FLOOR = 7;

function check(what, fn) {
  log.debug("Entering check().");
  K.check(what, fn);
  log.debug("Leaving check().");
}

// A certificate naming the RA's issuer and serial over ANOTHER key: an
// envelope made for it names the RA as its recipient, so the server tries
// its RA key, and the unwrap fails (a wrong key, as bad padding would).
function posingAsRa(raPem, key) {
  log.debug("Entering posingAsRa().");
  const real = forge.pki.certificateFromPem(raPem);
  const cert = forge.pki.createCertificate();
  cert.publicKey = forge.pki.publicKeyFromPem(key.publicKeyPem);
  cert.serialNumber = real.serialNumber;
  cert.validity.notBefore = new Date(Date.now() - 60000);
  cert.validity.notAfter = new Date(Date.now() + 86400000);
  cert.setSubject(real.subject.attributes);
  cert.setIssuer(real.issuer.attributes);
  cert.sign(forge.pki.privateKeyFromPem(key.privateKeyPem),
            forge.md.sha256.create());
  log.debug("Leaving posingAsRa().");
  return forge.pki.certificateToPem(cert);
}

function device(commonName) {
  log.debug("Entering device().");
  const key = client.rsaKey(2048);
  log.debug("Leaving device().");
  return { key: key, certPem: client.selfSigned(key, commonName) };
}

// One PKIOperation; `mutate` changes the signed message before it is sent.
async function operate(url, spec) {
  log.debug("Entering operate().");
  const nonce = nodeCrypto.randomBytes(16);
  const txid = spec.txid !== undefined ? spec.txid
    : "tx-" + nodeCrypto.randomBytes(8).toString("hex");
  const env = client.envelope(spec.inner, spec.recipient);
  let msg = client.signedMessage({ content: env,
    signerCertPem: spec.dev.certPem, signerKeyPem: spec.dev.key.privateKeyPem,
    messageType: "19", transactionID: txid, senderNonce: nonce });
  if (spec.mutate) {
    msg = spec.mutate(msg, env);
  }
  const r = await client.pkiOperation(url, msg, {});
  let rep = null;
  if (r.status === 200 && /x-pki-message/.test(r.type)) {
    rep = client.readCertRep(r.body, spec.ra);
  }
  log.debug("Leaving operate(). " + r.status);
  return { r: r, rep: rep };
}

async function monitorCode(realm) {
  log.debug("Entering monitorCode().");
  const r = await K.send(K.rb(realm) + "/admin-api/scep/monitor?per=5");
  const row = ((r.json && r.json.recent) || [])[0] || {};
  log.debug("Leaving monitorCode().");
  return row.errorCode || null;
}

// A refused PKIOperation: no certificate, the code recorded on the audit
// log (and, where the monitor keeps the row, there too), none sent.
async function refused(realm, url, what, code, spec) {
  log.debug("Entering refused(). " + code);
  const out = await K.coded(realm, code, function () {
    return operate(url, spec);
  });
  const seen = await monitorCode(realm);
  check(what + " (" + code + ")", function () {
    const done = out.answer;
    if (done.rep) {
      assert.strictEqual(done.rep.pkiStatus, "2", "pkiStatus " +
                         done.rep.pkiStatus + "; monitor " + seen);
      assert.strictEqual(done.rep.content, null);
    } else {
      assert.ok(done.r.status >= 400, done.r.status + " " +
                done.r.body.toString("utf8").slice(0, 200));
    }
    assert.ok(out.rose >= 1 || seen === code, code + " rows: " + out.rose +
              "; the monitor's newest code is " + seen);
    assert.ok(done.r.body.toString("binary").indexOf("STS-") < 0,
              "a code was sent");
  });
  log.debug("Leaving refused().");
}

async function test() {
  log.debug("Entering test().");
  const realm = await K.realm("sceprules");
  await K.ok(K.rb(realm) + "/admin-api/pki/build", { organisation: "SCEP" },
             "built the CA");
  await K.set(realm, "scep.attemptsPerAddress", 100000);
  const who = "scepr-" + K.STAMP;
  await K.ok(K.rb(realm) + "/admin-api/users/create", { username: who,
    invent: false, credential: "none", attributes: { cn: who,
      givenName: who, sn: who, mail: who + "@scep.example.test" } },
    "created " + who);
  const url = K.rb(realm) + "/enroll/scep";
  const chain = await client.getCaCert(url);
  assert.ok(chain.ra, "GetCACert named no RA certificate");
  const ra = chain.ra;
  async function inner(dev) {
    const made = await K.ok(K.rb(realm) + "/admin-api/scep/create-challenge",
      { kind: "person", identifier: who, profile: "tls-client" },
      "created a challenge");
    return client.csr(dev.key, { commonName: who,
                                 challenge: made.challenge });
  }

  log.info("=== A. an empty transactionID ===");
  const a = device(who);
  await refused(realm, url, "A. a pkiMessage with an empty transactionID " +
                "is refused", "STS-SCEP-0012",
                { dev: a, ra: ra, recipient: ra, txid: "",
                  inner: await inner(a) });

  log.info("=== B. a messageDigest that is not the content's ===");
  const b = device(who);
  await refused(realm, url, "B. one byte of the envelope changed after " +
                "signing: the messageDigest is not the content's",
                "STS-SCEP-0022", { dev: b, ra: ra, recipient: ra,
                  inner: await inner(b),
                  mutate: function (msg, env) {
                    const at = msg.indexOf(env);
                    assert.ok(at >= 0, "the envelope is not in the message");
                    const copy = Buffer.from(msg);
                    copy[at + env.length - 3] ^= 1;
                    return copy;
                  } });

  log.info("=== C. an envelope for another key ===");
  const c = device(who);
  const stranger = device("not the RA");
  await refused(realm, url, "C1. an envelope for another certificate is " +
                "refused as not encrypted to the realm's RA",
                "STS-SCEP-0027", { dev: c, ra: ra,
                  recipient: stranger.certPem, inner: await inner(c) });
  const d = device(who);
  await refused(realm, url, "C2. an envelope naming the RA but encrypted to " +
                "another key is a FAILURE that does not tell a wrong key " +
                "from bad padding", "STS-SCEP-0030", { dev: d, ra: ra,
                  recipient: posingAsRa(ra, client.rsaKey(2048)),
                  inner: await inner(d) });

  log.info("=== D. the management API ===");
  const api = K.rb(realm) + "/admin-api/scep";
  const badBody = await K.coded(realm, "STS-SCEP-0061", function () {
    return K.send(api + "/create-challenge", { json: { kind: "person",
      identifier: who, profile: "tls-client", lifetimeS: "never" } });
  });
  check("D1. a body that fails validation is refused (STS-SCEP-0061, or " +
        "the request schema's STS-API-0009 first)", function () {
    assert.strictEqual(badBody.answer.status, 400, K.shown(badBody.answer));
  });
  const api9 = await K.codeCount(realm, "STS-API-0009");
  check("D1. and a code is recorded for it", function () {
    assert.ok(badBody.rose >= 1 || api9 >= 1, "SCEP-0061 rows " +
              badBody.rose + ", API-0009 rows " + api9);
  });
  const unknown = await K.coded(realm, "STS-SCEP-0062", function () {
    return K.send(api + "/no-such-action", { json: {} });
  });
  check("D2. an action that does not exist is refused (STS-SCEP-0062)",
        function () {
    assert.ok(unknown.answer.status === 400 || unknown.answer.status === 404,
              K.shown(unknown.answer));
    assert.ok(unknown.rose >= 1, "rows: " + unknown.rose);
  });
  log.debug("Leaving test().");
}

K.main(test, FLOOR);
