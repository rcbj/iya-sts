// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_tls_connection.js
//
// ---------------------------------------------------------------------------
// MONITORING → TLS CONNECTION OVER HTTP (#597, 2026-10-12; rcbj's decision 3
// on #591).
//
// `GET /tls` and `GET /tls/forwarded` were development pages anybody could
// load; they are now one console page, `/admin/tls-connection`, drawn from
// `GET /admin-api/tls-connection` — Admin Read, in every mode. Against the
// running service:
//
//   a. the open pages are gone: `/tls`, `/tls/forwarded` and `/tls/pages.js`
//      answer as unrouted paths, and so do `POST /tls/trust` and
//      `/tls/trust/clear`;
//   b. the console page answers its shell, and the operation refuses a
//      caller with no token;
//   c. with no client certificate, the operation describes this request:
//      over TLS, its version and cipher, nothing presented — and every
//      forwarding header it carried, by value, with the client-certificate
//      headers listed and read by nothing;
//   d. with a client certificate whose Root was added through
//      `POST /admin-api/tls/trust/add`, the same operation reports it
//      presented and VERIFIED, with its subject and fingerprint — and starts
//      no session. The anchor is removed again by fingerprint.
//
// It runs in every mode: the operation is the management API's, the
// certificate's Root is added through the gated door product mode allows,
// and its CRLs are served by `test_crl_host.js` for the product modes'
// revocation check. A load balancer in front (the `cluster` mode's) is L4,
// so the certificate reaches a node.
//
// OWNED HERE (local: true): this repository's own console and management API
// (tests/CLAUDE.md, *where a new test goes*, rule 1).
// ---------------------------------------------------------------------------

const assert = require("assert");
const crypto = require("crypto");
const https = require("https");
const { Command, Option } = require("commander");
const credentials = require("../tools/pep-credential.js");

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
var log = bunyan.createLogger({ name: "sts_tls_connection",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const OPERATION = "/admin-api/tls-connection";

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

// One request over node's own https, so a client certificate can be
// presented; `agent: false` gives it a connection of its own, which is the
// connection the answer describes. The management API's token is attached
// by the launcher's preload (`tests/tools/attach-admin-token.js`) unless
// `bare` sends `Authorization: none`.
function send(method, path, options) {
  log.debug("Entering send(). " + method + " " + path);
  const o = options || {};
  const target = new URL(base + path);
  const headers = Object.assign({ accept: "application/json" },
                                o.headers || {});
  const body = o.json === undefined ? "" : JSON.stringify(o.json);
  if (body) {
    headers["content-type"] = "application/json";
    headers["content-length"] = Buffer.byteLength(body);
  }
  if (o.bare) {
    // `tests/tools/attach-admin-token.js` leaves this alone, and the service
    // reads it as a malformed credential: a caller with no token.
    headers.authorization = "none";
  }
  log.debug("Leaving send().");
  return new Promise(function (resolve, reject) {
    const transport = target.protocol === "http:" ? require("http") : https;
    const req = transport.request({
      method: method, hostname: target.hostname, port: target.port,
      path: target.pathname + target.search, headers: headers,
      agent: false, cert: o.cert, key: o.key
    }, function (res) {
      const chunks = [];
      res.on("data", function (c) {
        chunks.push(c);
      });
      res.on("end", function () {
        const raw = Buffer.concat(chunks).toString("utf8");
        let json = null;
        try {
          json = JSON.parse(raw);
        } catch (e) {
          log.debug("Caught in send(): " + ((e && e.message) || e));
          // Not JSON: a page or Express's own 404; the caller reads `raw`.
          json = null;
        }
        resolve({ status: res.statusCode, headers: res.headers, raw: raw,
                  json: json });
      });
    });
    req.on("error", reject);
    req.end(body);
  });
}

async function test() {
  log.debug("Entering test().");
  log.info("Monitoring → TLS connection at " + base);

  log.info("=== a. the open pages are gone ===");
  for (const asked of [["GET", "/tls"], ["GET", "/tls/forwarded"],
                       ["GET", "/tls/pages.js"], ["POST", "/tls/trust"],
                       ["POST", "/tls/trust/clear"]]) {
    const r = await send(asked[0], asked[1], { json: {} });
    check(asked.join(" ") + " answers as an unrouted path", function () {
      assert.strictEqual(r.status, 404, r.raw.slice(0, 200));
      assert.ok(r.raw.indexOf("Cannot " + asked[0] + " " + asked[1]) >= 0,
                r.raw.slice(0, 200));
    });
  }

  log.info("=== b. the page and its gate ===");
  const shell = await send("GET", "/admin/tls-connection",
                           { headers: { accept: "text/html" } });
  const anonymous = await send("GET", OPERATION, { bare: true });
  check("the console page answers its shell, and the operation refuses a " +
        "caller with no token", function () {
    assert.strictEqual(shell.status, 200, shell.raw.slice(0, 200));
    assert.ok(/<html/i.test(shell.raw), shell.raw.slice(0, 200));
    assert.strictEqual(anonymous.status, 401, anonymous.raw.slice(0, 200));
  });

  log.info("=== c. no client certificate; forwarding headers sent ===");
  const STAMP = String(Date.now());
  const plain = await send("GET", OPERATION, { headers: {
    "x-forwarded-host": "forged-" + STAMP + ".example",
    "x-client-cert": "-----BEGIN CERTIFICATE----- forged " + STAMP } });
  const view = plain.json || {};
  check("the operation answers the request it was asked by", function () {
    assert.strictEqual(plain.status, 200, plain.raw.slice(0, 300));
    assert.ok(view.connection && view.clientCertificate && view.forwarded,
              plain.raw.slice(0, 300));
    assert.strictEqual(view.clientCertificate.presented, false,
                       JSON.stringify(view.clientCertificate));
    assert.strictEqual(view.clientCertificate.verified, false);
  });
  if (base.indexOf("https:") === 0) {
    check("over TLS, with its version and cipher", function () {
      assert.strictEqual(view.connection.encrypted, true,
                         JSON.stringify(view.connection));
      assert.ok(/^TLSv1\.[23]$/.test(String(view.connection.protocol)),
                JSON.stringify(view.connection));
      assert.ok(view.connection.cipher, JSON.stringify(view.connection));
    });
  }
  const forwarded = (view.forwarded && view.forwarded.forwarding) || [];
  const hostRow = forwarded.filter(function (row) {
    return row.header === "x-forwarded-host";
  })[0];
  const certHeaders = (view.forwarded &&
                       view.forwarded.clientCertificateHeaders) || {};
  check("every forwarding header is listed with this request's value, and " +
        "the certificate header is seen and read by nothing", function () {
    assert.ok(hostRow && hostRow.present === true &&
              hostRow.value === "forged-" + STAMP + ".example",
              JSON.stringify(forwarded));
    assert.strictEqual(certHeaders.readByThisService, false);
    assert.ok((certHeaders.seen || []).indexOf("x-client-cert") >= 0,
              JSON.stringify(certHeaders.seen));
    assert.strictEqual(typeof view.forwarded.trustProxy, "boolean");
    assert.strictEqual(typeof view.forwarded.believed, "boolean");
    assert.ok(/^https?:\/\//.test(String(view.forwarded.effectiveBaseUrl)),
              String(view.forwarded.effectiveBaseUrl));
  });

  if (base.indexOf("https:") !== 0) {
    log.info("The service is plain HTTP, so no client certificate can be " +
             "presented; section d needs global.https.");
  } else {
    log.info("=== d. a client certificate, trusted through the gated door " +
             "===");
    const cred = await credentials.mint({
      subject: "CN=tls-connection-" + STAMP + ",O=iya-sts tests" });
    const fingerprint = new crypto.X509Certificate(cred.anchorPem)
      .fingerprint256;
    const added = await credentials.trustAnchor(base, cred.anchorPem);
    assert.ok(added.ok, "POST /admin-api/tls/trust/add should accept the " +
              "Root this job minted; it answered " + added.status + " " +
              String(added.body || added.why || "").slice(0, 300));
    try {
      const withCert = await send("GET", OPERATION,
                                  { cert: cred.certPem, key: cred.keyPem });
      const cc = (withCert.json && withCert.json.clientCertificate) || {};
      const leaf = new crypto.X509Certificate(cred.certPem);
      check("the certificate the connection presented is reported " +
            "presented and VERIFIED, with its subject and fingerprint",
            function () {
        assert.strictEqual(withCert.status, 200, withCert.raw.slice(0, 300));
        assert.strictEqual(cc.presented, true, JSON.stringify(cc));
        assert.strictEqual(cc.verified, true, JSON.stringify(cc));
        assert.ok(/tls-connection-/.test(String(cc.certificate &&
                                                cc.certificate.subject)),
                  JSON.stringify(cc.certificate));
        assert.strictEqual(String(cc.certificate.fingerprint256)
                             .toUpperCase(),
                           leaf.fingerprint256.toUpperCase());
        assert.ok(cc.thumbprint, JSON.stringify(cc));
      });
      check("and it started no session: no cookie came back", function () {
        assert.ok(!(withCert.headers["set-cookie"] || []).some(function (c) {
          return /^sts_session=/.test(c);
        }), JSON.stringify(withCert.headers["set-cookie"]));
      });
    } finally {
      const removed = await send("POST", "/admin-api/tls/trust/remove",
                                 { json: { fingerprint: fingerprint } });
      log.info("Removed this job's anchor again: " + removed.status);
    }
  }

  assert.ok(checks >= 8, "only " + checks + " checks ran; a section has " +
                                           "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_tls_connection")
  .description("Monitoring → TLS connection over HTTP (#597).")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().then(function () {
  // The CRL host `mint()` started is unref()ed; exit plainly regardless.
  process.exit(0);
}, function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
