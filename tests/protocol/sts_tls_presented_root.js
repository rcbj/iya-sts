// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_tls_presented_root.js
//
// ---------------------------------------------------------------------------
// THE SERVICE ROOT GOES WITH EVERY CHAIN THE MAIN PORT PRESENTS (#1064),
// OVER A REAL HANDSHAKE.
//
// D12 (#444): carries over half A of `tests/tls_presented_root.js`. Every
// install builds its own Root under the same name, so a client never handed
// the current Root matched an older one by NAME. Since #1064 every chain the
// service reports ends with the Root. Asked of the running service:
//
//   1. a TLS handshake on the main port presents a chain whose last
//      certificate is self-signed;
//   2. that certificate is the one `/pki/ca/service/root.cer` serves, byte
//      for byte — not merely one with the Root's name;
//   3. each certificate of the chain is signed by the next one.
//
// NOT carried, and why: half B (each reported chain built through
// `chainThroughRoot()` as a function, the console's and the API's views of
// it as a model) is class (d).
//
// OWNED HERE (local: true): this repository's own TLS listener.
// ---------------------------------------------------------------------------

const assert = require("assert");
const tls = require("tls");
const nodeCrypto = require("crypto");
const K = require("./oauth_wire_kit.js").kit("sts_tls_presented_root");
const serviceTrust = require("../tools/service_trust.js");
const log = K.log;

const FLOOR = 3;

function check(what, fn) {
  log.debug("Entering check().");
  K.check(what, fn);
  log.debug("Leaving check().");
}

// The chain the main port presents, leaf first, as DER buffers.
function presented() {
  log.debug("Entering presented().");
  const url = new URL(K.base);
  return new Promise(function (resolve, reject) {
    const socket = tls.connect({ host: url.hostname,
      port: Number(url.port || 443), servername: url.hostname,
      ca: serviceTrust.trustedCa() }, function () {
      const chain = [];
      let one = socket.getPeerCertificate(true);
      const seen = {};
      while (one && one.raw && !seen[one.fingerprint256]) {
        seen[one.fingerprint256] = true;
        chain.push(one.raw);
        one = one.issuerCertificate;
      }
      socket.end();
      log.debug("Leaving presented(). " + chain.length);
      resolve(chain);
    });
    socket.on("error", reject);
  });
}

async function test() {
  log.debug("Entering test().");
  const chain = await presented();
  const rootAnswer = await fetch(K.base + "/pki/ca/service/root.cer");
  const raw = Buffer.from(await rootAnswer.arrayBuffer());
  const text = raw.toString("latin1");
  const root = /-----BEGIN/.test(text)
    ? Buffer.from(text.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""),
                  "base64") : raw;
  const xs = chain.map(function (der) {
    return new nodeCrypto.X509Certificate(der);
  });
  const last = xs[xs.length - 1];
  check("1. the main port's chain ends with a self-signed certificate",
        function () {
    assert.ok(xs.length >= 2, "a chain of " + xs.length);
    assert.strictEqual(last.subject, last.issuer);
    assert.ok(last.verify(last.publicKey), "it does not sign itself");
  });
  check("2. and it is the service Root /pki/ca/service/root.cer serves, " +
        "byte for byte", function () {
    assert.strictEqual(rootAnswer.status, 200);
    assert.ok(chain[chain.length - 1].equals(root),
              "the presented Root is not the one served");
  });
  check("3. each certificate is signed by the next", function () {
    for (let i = 0; i + 1 < xs.length; i += 1) {
      assert.ok(xs[i].verify(xs[i + 1].publicKey), "link " + i);
    }
  });
  log.debug("Leaving test().");
}

K.main(test, FLOOR);
