// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_revocation_hard_fail.js
//
// ---------------------------------------------------------------------------
// REVOCATION CONSULTED FOR A PRESENTED CLIENT CERTIFICATE, UNDER HARD-FAIL,
// OVER REAL HANDSHAKES.
//
// D12 (#444): carries over the door half of `tests/revocation_status.js`.
// Outside chains are minted here (`tools/pep-credential.js`, and node-forge
// for the RFC 9608 leaf), their Roots put in the client truststore through
// the gated door (recorded first, removed at the end), each leaf stored on a
// person's entry so it is that person, and presented at `GET /tls/sign-in`
// on the main port of a realm with `pki.revocationCheck` hard-fail:
//
//   A. a leaf whose CRL is served (by `test_crl_host.js`, which the service
//      dials at OUTBOUND_TEST_HOST) and does not list it signs its holder
//      in — the control;
//   B. a leaf whose CRL distribution point nothing answers is refused, its
//      status unknown (STS-PKI-0119's reason, `refusedOnRevocation`);
//   C. a leaf asserting RFC 9608 noRevAvail beside a cRLDistributionPoints
//      extension, which section 3 forbids, is refused (STS-PKI-0189's
//      reason). Each code is on an audit row of the realm (#34,
//      2026-11-15; until then neither was on any, which this job pinned).
//
// NOT carried, and why: a foreign CRL that is badly signed, stale, slow or
// a redirect, the cache and the failure memory (claims about requests NOT
// made, which only the CRL server sees), the worker's view of a socket, and
// delta and indirect CRLs as parsed lists are class (d); a certificate
// REGISTERED on an application entry or a federation relationship and
// revoked (STS-PKI-0129) is the RFC 7523/7522 and federation families'
// door, owed with phase 7.
//
// OWNED HERE (local: true): this repository's own certificate sign-in.
// ---------------------------------------------------------------------------

const assert = require("assert");
const https = require("https");
const nodeCrypto = require("crypto");
const forge = require("node-forge");
const anchors = require("../tools/pep-credential.js");
const K = require("./oauth_wire_kit.js").kit("sts_revocation_hard_fail");
const log = K.log;

const FLOOR = 4;
const added = [];

function check(what, fn) {
  log.debug("Entering check().");
  K.check(what, fn);
  log.debug("Leaving check().");
}

function signIn(realm, tls) {
  log.debug("Entering signIn().");
  const u = new URL(K.rb(realm) + "/tls/sign-in");
  return new Promise(function (resolve, reject) {
    const req = https.request({ host: u.hostname, port: u.port,
      path: u.pathname, method: "GET", agent: false,
      headers: { accept: "application/json" },
      cert: tls.cert, key: tls.key }, function (res) {
      let text = "";
      res.setEncoding("utf8");
      res.on("data", function (c) {
        text += c;
      });
      res.on("end", function () {
        let json = null;
        try {
          json = JSON.parse(text);
        } catch (e) {
          log.debug("Caught in signIn(): " + ((e && e.message) || e));
          // Not JSON: the caller reads the text.
          json = null;
        }
        log.debug("Leaving signIn(). " + res.statusCode);
        resolve({ status: res.statusCode, json: json, text: text });
      });
    });
    req.on("error", reject);
    req.end();
  });
}

// Retried while the truststore is being applied (tests/CLAUDE.md, #335).
async function settledSignIn(realm, tls) {
  log.debug("Entering settledSignIn().");
  let last = null;
  for (let i = 0; i < 10; i += 1) {
    try {
      const r = await signIn(realm, tls);
      log.debug("Leaving settledSignIn().");
      return r;
    } catch (e) {
      log.debug("Caught in settledSignIn(): " + ((e && e.message) || e));
      // A handshake refused while the anchor is being applied; again.
      last = e;
      await K.sleep(300);
    }
  }
  throw last;
}

// A code counted in the realm's audit log and the default realm's together:
// the handshake's revocation verdict is made before a request names a
// realm, so its row may be the process's.
// The code's rows in the realm the request named (#34, #38: the door's
// refusal is written there) and in the default realm, before and after.
async function bothRealms(realm, code, act) {
  log.debug("Entering bothRealms(). " + code);
  const realmBefore = await K.codeCount(realm, code);
  const defaultBefore = await K.codeCount(null, code);
  const answer = await act();
  let inRealm = realmBefore;
  for (let i = 0; i < 20 && inRealm <= realmBefore; i += 1) {
    await K.sleep(150);
    inRealm = await K.codeCount(realm, code);
  }
  const inDefault = await K.codeCount(null, code);
  const rose = inRealm - realmBefore + inDefault - defaultBefore;
  log.debug("Leaving bothRealms(). " + rose);
  return { answer: answer, rose: rose, realmRose: inRealm - realmBefore };
}

async function personWith(realm, name, leafPem) {
  log.debug("Entering personWith(). " + name);
  await K.ok(K.rb(realm) + "/admin-api/users/create", { username: name,
    invent: false, credential: "none", attributes: { cn: name,
      givenName: name, sn: name, mail: name + "@rhf.example.test" } },
    "created " + name);
  await K.ok(K.rb(realm) + "/admin-api/users/add-certificate", { user: name,
    certificate: leafPem }, "stored the leaf on " + name);
  log.debug("Leaving personWith().");
}

// A Root and, under it, a leaf asserting noRevAvail (2.5.29.56) beside a
// cRLDistributionPoints extension (RFC 9608 section 3 forbids the pair).
function noRevAvailChain() {
  log.debug("Entering noRevAvailChain().");
  const rootKeys = forge.pki.rsa.generateKeyPair(2048);
  const root = forge.pki.createCertificate();
  root.publicKey = rootKeys.publicKey;
  root.serialNumber = "01" + nodeCrypto.randomBytes(8).toString("hex");
  root.validity.notBefore = new Date(Date.now() - 60000);
  root.validity.notAfter = new Date(Date.now() + 365 * 86400000);
  const rootName = [{ name: "commonName", value: "noRevAvail Root " +
                                                 K.STAMP }];
  root.setSubject(rootName);
  root.setIssuer(rootName);
  root.setExtensions([{ name: "basicConstraints", cA: true, critical: true },
    { name: "keyUsage", keyCertSign: true, cRLSign: true, critical: true },
    { name: "subjectKeyIdentifier" }]);
  root.sign(rootKeys.privateKey, forge.md.sha256.create());
  const leafKeys = forge.pki.rsa.generateKeyPair(2048);
  const leaf = forge.pki.createCertificate();
  leaf.publicKey = leafKeys.publicKey;
  leaf.serialNumber = "02" + nodeCrypto.randomBytes(8).toString("hex");
  leaf.validity.notBefore = new Date(Date.now() - 60000);
  leaf.validity.notAfter = new Date(Date.now() + 30 * 86400000);
  leaf.setSubject([{ name: "commonName", value: "norev-" + K.STAMP }]);
  leaf.setIssuer(rootName);
  leaf.setExtensions([{ name: "basicConstraints", cA: false },
    { name: "keyUsage", digitalSignature: true, critical: true },
    { name: "extKeyUsage", clientAuth: true },
    { name: "cRLDistributionPoints", altNames: [{ type: 6,
      value: "http://127.0.0.1:9/norev.crl" }] },
    { id: "2.5.29.56", critical: false,
      value: forge.asn1.toDer(forge.asn1.create(forge.asn1.Class.UNIVERSAL,
        forge.asn1.Type.NULL, false, "")).getBytes() }]);
  leaf.sign(rootKeys.privateKey, forge.md.sha256.create());
  log.debug("Leaving noRevAvailChain().");
  return { anchorPem: forge.pki.certificateToPem(root),
           leafPem: forge.pki.certificateToPem(leaf),
           keyPem: forge.pki.privateKeyToPem(leafKeys.privateKey) };
}

async function test() {
  log.debug("Entering test().");
  const realm = await K.realm("revhard");
  await K.set(realm, "pki.revocationCheck", "hard-fail");

  log.info("=== A. a served CRL that does not list it: the control ===");
  const good = await anchors.mint({ subject: "CN=rhg-" + K.STAMP +
                                    ",O=outside" });
  assert.ok((await anchors.trustRecorded(K.base, good.anchorPem, added)).ok);
  await personWith(realm, "rhg-" + K.STAMP, good.leaf.pem);
  const control = await settledSignIn(realm, { cert: good.certPem,
                                               key: good.keyPem });
  check("A. under hard-fail a leaf whose CRL is served and does not list " +
        "it signs its holder in", function () {
    assert.strictEqual(control.json && control.json.signedIn, true,
                       control.text.slice(0, 300));
  });

  log.info("=== B. a CRL nobody answers ===");
  const dark = await anchors.mint({ subject: "CN=rhd-" + K.STAMP +
                                    ",O=outside",
                                    rootSubject: "CN=dark Root " + K.STAMP,
                                    crlBase: "http://127.0.0.1:9" });
  assert.ok((await anchors.trustRecorded(K.base, dark.anchorPem, added)).ok);
  await personWith(realm, "rhd-" + K.STAMP, dark.leaf.pem);
  const unknown = await bothRealms(realm, "STS-PKI-0119", function () {
    return settledSignIn(realm, { cert: dark.certPem, key: dark.keyPem });
  });
  check("B. a leaf whose CRL nothing answers is refused under hard-fail " +
        "(STS-PKI-0119: refusedOnRevocation, the status not established)",
        function () {
    assert.notStrictEqual(unknown.answer.json &&
                          unknown.answer.json.signedIn, true,
                          unknown.answer.text.slice(0, 300));
    const session = (unknown.answer.json || {}).session || {};
    assert.strictEqual(session.refusedOnRevocation, true,
                       unknown.answer.text.slice(0, 300));
    assert.ok(/could not be established/.test(session.why || ""),
              unknown.answer.text.slice(0, 300));
    assert.ok(!/STS-[A-Z]+-\d{4}/.test(unknown.answer.text));
  });
  // #34 (2026-11-15): the refusal is on the realm's audit log; until then
  // the code was in the reason's log line only, which this job pinned.
  check("B. and STS-PKI-0119 is on an audit row of the realm (#34)",
        function () {
    assert.ok(unknown.realmRose >= 1, JSON.stringify(unknown.rose));
  });

  log.info("=== C. noRevAvail beside a CRL distribution point ===");
  const nr = noRevAvailChain();
  assert.ok((await anchors.trustRecorded(K.base, nr.anchorPem, added)).ok);
  await personWith(realm, "norev-" + K.STAMP, nr.leafPem);
  const forbidden = await bothRealms(realm, "STS-PKI-0189", function () {
    return settledSignIn(realm, { cert: nr.leafPem, key: nr.keyPem });
  });
  check("C. a leaf asserting noRevAvail beside cRLDistributionPoints is " +
        "refused (STS-PKI-0189: refusedOnRevocation, the certificate invalid)",
        function () {
    assert.notStrictEqual(forbidden.answer.json &&
                          forbidden.answer.json.signedIn, true,
                          forbidden.answer.text.slice(0, 300));
    const session = (forbidden.answer.json || {}).session || {};
    assert.strictEqual(session.refusedOnRevocation, true,
                       forbidden.answer.text.slice(0, 300));
    assert.ok(/noRevAvail beside cRLDistributionPoints/.test(
      session.why || ""), forbidden.answer.text.slice(0, 300));
  });
  check("C. and STS-PKI-0189 is on an audit row of the realm (#34)",
        function () {
    assert.ok(forbidden.realmRose >= 1, JSON.stringify(forbidden.rose));
  });
  check("C. and no code is sent", function () {
    assert.ok(!/STS-[A-Z]+-\d{4}/.test(forbidden.answer.text));
  });
  log.debug("Leaving test().");
}

async function guarded() {
  log.debug("Entering guarded().");
  let failure = null;
  try {
    await test();
  } catch (e) {
    log.debug("Caught in guarded(): " + ((e && e.message) || e));
    // Rethrown after the anchors are removed.
    failure = e;
  }
  await anchors.settleAnchors(K.base, added, failure);
  log.debug("Leaving guarded().");
}

K.main(guarded, FLOOR);
