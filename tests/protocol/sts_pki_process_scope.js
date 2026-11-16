// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_pki_process_scope.js
//
// ---------------------------------------------------------------------------
// THE SERVICE ROOT AND THE PROCESS BRANCH REFUSE A KEY THE LISTENERS COULD
// NOT USE, OVER THE WIRE, AND CHANGE NOTHING.
//
// D12 (#444): carries over the process-scope half of `tests/pki_hybrid.js`
// and `tests/pki_rebuild_recertifies.js`. Every listener presents the
// service Root and the process branch, so a key OpenSSL cannot read, or a
// chain larger than a stock TLS client accepts, is refused before anything
// is built:
//
//   1. `build-root` asked for a composite ML-DSA key is refused
//      (STS-PKI-0272), and the Root `/pki/ca/service/root.cer` serves is the
//      one before;
//   2. `build-scope` of the process branch asked for the same is refused
//      (0272);
//   3. and the main port still presents the same Root.
//
// NOT carried: STS-PKI-0270 (an alternative key that would make the
// listener chain larger than 102400 bytes). The largest alternative key a
// build takes, SLH-DSA SHA2-256s, was ACCEPTED on the probe and rebuilt the
// process branch, so no single choice through this door reaches the
// refusal, and trying one risks a rebuild of every job's branch.
//
// EXCLUSIVE: the Root and the process branch are every job's; only refused
// requests are sent, but a regression that ACCEPTED one would rebuild them
// under every concurrent job, so this runs alone.
//
// OWNED HERE (local: true): this repository's own certificate authority.
// ---------------------------------------------------------------------------

const assert = require("assert");
const tls = require("tls");
const K = require("./oauth_wire_kit.js").kit("sts_pki_process_scope");
const log = K.log;

const FLOOR = 3;

function check(what, fn) {
  log.debug("Entering check().");
  K.check(what, fn);
  log.debug("Leaving check().");
}

async function rootDer() {
  log.debug("Entering rootDer().");
  const r = await fetch(K.base + "/pki/ca/service/root.cer");
  log.debug("Leaving rootDer().");
  return Buffer.from(await r.arrayBuffer());
}

function presentedRoot() {
  log.debug("Entering presentedRoot().");
  const url = new URL(K.base);
  return new Promise(function (resolve, reject) {
    const socket = tls.connect({ host: url.hostname, port: Number(url.port),
      servername: url.hostname, rejectUnauthorized: false }, function () {
      let one = socket.getPeerCertificate(true);
      const seen = {};
      let last = null;
      while (one && one.raw && !seen[one.fingerprint256]) {
        seen[one.fingerprint256] = true;
        last = one.raw;
        one = one.issuerCertificate;
      }
      socket.end();
      log.debug("Leaving presentedRoot().");
      resolve(last);
    });
    socket.on("error", reject);
  });
}

function refused(what, out, code) {
  log.debug("Entering refused(). " + code);
  check(what + " (" + code + ")", function () {
    assert.ok(out.answer.status >= 400, K.shown(out.answer));
    assert.ok(out.rose >= 1, code + " rows: " + out.rose + "; " +
              K.shown(out.answer));
  });
  log.debug("Leaving refused().");
}

async function test() {
  log.debug("Entering test().");
  const before = await rootDer();
  const api = K.base + "/admin-api/pki";
  refused("1. build-root asked for a composite ML-DSA key is refused",
    await K.coded(null, "STS-PKI-0272", function () {
      return K.send(api + "/build-root", { json: {
        keyAlg: "mldsa44-rsa2048-pss-sha256" } });
    }), "STS-PKI-0272");
  refused("2. build-scope of the process branch asked for it is refused",
    await K.coded(null, "STS-PKI-0272", function () {
      return K.send(api + "/build-scope", { json: { scope: "*process",
        keyAlg: "mldsa44-rsa2048-pss-sha256" } });
    }), "STS-PKI-0272");
  const after = await rootDer();
  const shown = await presentedRoot();
  check("3. nothing changed: the Root served and the Root the main port " +
        "presents are the one before", function () {
    assert.ok(after.equals(before), "the served Root changed");
    assert.ok(Buffer.from(shown).equals(before) ||
              Buffer.from(shown).toString("base64") ===
              before.toString("latin1").replace(/-----[^-]+-----/g, "")
                .replace(/\s+/g, ""), "the presented Root changed");
  });
  log.debug("Leaving test().");
}

K.main(test, FLOOR);
