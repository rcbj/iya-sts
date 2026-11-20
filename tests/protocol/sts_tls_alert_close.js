// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_tls_alert_close.js
//
// ---------------------------------------------------------------------------
// A CONNECTION THAT FAILS AT THE TLS LAYER IS CLOSED LATER, SO ITS ALERT IS
// READ — ON THE RUNNING SERVICE'S MAIN PORT (2026-11-13, tls/alert_close.ts).
//
// D12 (#444): carries over tests/tls_alert_close.js's claims that a peer can
// see. A client completes a handshake, sends an application-data record
// whose tag cannot verify, and keeps sending; what it observes on its own
// TCP socket (kept half open, so the server's FIN does not close it) is:
//
//   1. the server's fatal `bad_record_mac` alert, read by the client's TLS
//      engine;
//   2. the server's FIN straight behind it — the sending side is ended at
//      once (the first version held the FIN too, and stalled tlsfuzzer);
//   3. and the descriptor HELD: the client's further writes are accepted
//      for most of a second and more, and only then refused (EPIPE or a
//      reset), where node used to close within a tick and reset the
//      connection with the alert unread.
//
// The same on every way in a client can choose: TLS 1.3 over HTTP/1.1,
// TLS 1.3 over HTTP/2, and TLS 1.2 over HTTP/1.1 (TLS 1.2 is turned on for
// that probe and reset after); a handshake refused before it began — a
// ClientHello cut short — sends its alert and its FIN at once while the
// descriptor is held; and a good request on a connection of its own is
// answered as ever.
//
// What stays in process (class (d)): the bound (MAX_HELD, 256 per
// listener, STS-TLS-0061, which is logged and never audited, and needs 257
// connections failing inside two seconds); a peer's OWN alert not held
// (node's TLS client sends no fatal alert a job can choose); TLS 1.3 behind
// the Finished (a bad record coalesced with the client's Finished, which
// node's client does not write); the parser refusal writing nothing into a
// failed connection; and the source.
//
// OWNED HERE (local: true): this repository's own main port.
// ---------------------------------------------------------------------------

const assert = require("assert");
const crypto = require("crypto");
const net = require("net");
const tls = require("tls");
const serviceTrust = require("../tools/service_trust.js");
const { Duplex } = require("stream");

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
var log = bunyan.createLogger({ name: "sts_tls_alert_close",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const TARGET = new URL(base);
const HOST = TARGET.hostname;
const PORT = Number(TARGET.port || 443);
// The hold is two seconds (CLOSE_DELAY_MS); a close sooner than this is the
// old behaviour. Wide of a loaded node's scheduling, well short of two.
const HELD_AT_LEAST_MS = 1200;
// The alert and the FIN are written in the same turn as the failure.
const PROMPT_MS = 1000;

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function badRecord() {
  log.debug("Entering badRecord().");
  log.debug("Leaving badRecord().");
  return Buffer.concat([Buffer.from([0x17, 0x03, 0x03, 0x00, 0x20]),
                        crypto.randomBytes(32)]);
}

// A HANDSHAKE, THEN A RECORD THAT CANNOT VERIFY, AND MORE OF THEM EVERY
// 50 ms. The TLS engine runs over a pass-through stream, so its own error
// never closes the TCP socket underneath; that socket is half open, so the
// server's FIN leaves it writable. Resolves the timeline, relative to the
// first bad record.
function failAfterHandshake(alpn, version) {
  log.debug("Entering failAfterHandshake(). " + alpn + " " + version);
  log.debug("Leaving failAfterHandshake().");
  return new Promise(function (resolve) {
    const raw = net.connect({ host: HOST, port: PORT, allowHalfOpen: true });
    const out = { alpn: null, protocol: null, alert: false, fin: -1,
                  refused: -1, error: null };
    let t0 = 0;
    let timer = null;
    const since = function () {
      return t0 ? Date.now() - t0 : -1;
    };
    const pipe = new Duplex({
      read: function () {},
      write: function (chunk, encoding, done) {
        if (!raw.destroyed && raw.writable) {
          raw.write(chunk);
        }
        done();
      }
    });
    raw.on("data", function (c) {
      pipe.push(c);
    });
    raw.on("connect", function () {
      const s = tls.connect({ socket: pipe, servername: HOST,
                              ca: serviceTrust.trustedCa(),
                              ALPNProtocols: [alpn],
                              minVersion: version, maxVersion: version },
      function () {
        out.alpn = s.alpnProtocol;
        out.protocol = s.getProtocol();
        raw.write(badRecord());
        t0 = Date.now();
        timer = setInterval(function () {
          if (!raw.destroyed && raw.writable) {
            raw.write(badRecord());
          }
        }, 50);
      });
      s.on("error", function (e) {
        if (/bad record mac/i.test(String(e && e.message))) {
          out.alert = true;
        } else {
          out.error = String((e && e.message) || e);
        }
      });
    });
    raw.on("end", function () {
      out.fin = since();
      // Nothing more will be read; the client gives up after ten seconds.
      setTimeout(function () {
        raw.destroy();
      }, 10000);
    });
    raw.on("error", function (e) {
      if (out.refused < 0) {
        out.refused = since();
        out.refusedBy = e && e.code;
      }
    });
    raw.on("close", function () {
      clearInterval(timer);
      if (out.refused < 0) {
        out.refused = since();
      }
      resolve(out);
    });
  });
}

// A CLIENTHELLO CUT SHORT: a handshake record whose message claims more
// bytes than it carries, followed by a record that cannot be one. Resolves
// the alert's bytes and the timeline from the first write.
function truncatedHello() {
  log.debug("Entering truncatedHello().");
  log.debug("Leaving truncatedHello().");
  return new Promise(function (resolve) {
    const raw = net.connect({ host: HOST, port: PORT, allowHalfOpen: true });
    const out = { alertAt: -1, alert: null, fin: -1, refused: -1 };
    let t0 = 0;
    let timer = null;
    const since = function () {
      return Date.now() - t0;
    };
    raw.on("connect", function () {
      const body = Buffer.from([0x01, 0x00, 0x00, 0xff, 0x03, 0x03]);
      raw.write(Buffer.concat([Buffer.from([0x16, 0x03, 0x01, 0x00,
                                            body.length]), body]));
      raw.write(Buffer.from([0x16, 0x03, 0x01, 0x00, 0x04,
                             0x99, 0x00, 0x00, 0x00]));
      t0 = Date.now();
      timer = setInterval(function () {
        if (!raw.destroyed && raw.writable) {
          raw.write(Buffer.from([0x17, 0x03, 0x03, 0x00, 0x01, 0x00]));
        }
      }, 50);
    });
    raw.on("data", function (c) {
      if (out.alertAt < 0) {
        out.alertAt = since();
        out.alert = c.slice(0, 7);
      }
    });
    raw.on("end", function () {
      out.fin = since();
      setTimeout(function () {
        raw.destroy();
      }, 10000);
    });
    raw.on("error", function (e) {
      if (out.refused < 0) {
        out.refused = since();
        out.refusedBy = e && e.code;
      }
    });
    raw.on("close", function () {
      clearInterval(timer);
      if (out.refused < 0) {
        out.refused = since();
      }
      resolve(out);
    });
  });
}

async function api(method, path, payload) {
  log.debug("Entering api(). " + method + " " + path);
  const r = await fetch(base + path, {
    method: method,
    headers: { "Content-Type": "application/json",
               Accept: "application/json" },
    body: payload === undefined ? undefined : JSON.stringify(payload) });
  const raw = await r.text();
  log.debug("Leaving api(). " + r.status);
  return { status: r.status, raw: raw };
}

function held(r, what) {
  log.debug("Entering held().");
  assert.ok(r.alert, what + ": the client read no bad_record_mac alert " +
            JSON.stringify(r));
  assert.ok(r.fin >= 0 && r.fin < PROMPT_MS, what + ": the FIN did not " +
            "follow the alert at once " + JSON.stringify(r));
  assert.ok(r.refused >= HELD_AT_LEAST_MS, what + ": the descriptor was " +
            "closed after " + r.refused + " ms, not held " +
            JSON.stringify(r));
  log.debug("Leaving held().");
}

async function test() {
  log.debug("Entering test().");
  assert.ok(base.indexOf("https:") === 0,
            "the main port is HTTPS in every appconfig; " + base + " is not");

  log.info("=== 1-3. a bad record after the handshake ===");
  const h1 = await failAfterHandshake("http/1.1", "TLSv1.3");
  check("TLS 1.3 over HTTP/1.1: the alert is read, the FIN follows at " +
        "once, and the descriptor is held (closed +" + h1.refused + " ms)",
        function () {
    assert.strictEqual(h1.alpn, "http/1.1", JSON.stringify(h1));
    held(h1, "TLS 1.3 over HTTP/1.1");
  });
  const h2 = await failAfterHandshake("h2", "TLSv1.3");
  check("TLS 1.3 over HTTP/2: the same (closed +" + h2.refused + " ms)",
        function () {
    assert.strictEqual(h2.alpn, "h2", JSON.stringify(h2));
    held(h2, "TLS 1.3 over HTTP/2");
  });
  const set = await api("POST", "/admin-api/config/set",
                        { key: "tls.disableTls12", value: false });
  assert.strictEqual(set.status, 200, set.raw.slice(0, 300));
  let t12;
  try {
    await new Promise(function (resolve) {
      setTimeout(resolve, 200);
    });
    t12 = await failAfterHandshake("http/1.1", "TLSv1.2");
  } finally {
    const reset = await api("POST", "/admin-api/config/reset",
                            { key: "tls.disableTls12" });
    if (reset.status !== 200) {
      log.warn("tls.disableTls12 was not reset: " + reset.raw.slice(0, 200));
    }
  }
  check("TLS 1.2 over HTTP/1.1: the same (closed +" + t12.refused + " ms)",
        function () {
    assert.strictEqual(t12.protocol, "TLSv1.2", JSON.stringify(t12));
    held(t12, "TLS 1.2 over HTTP/1.1");
  });

  log.info("=== a handshake refused before it began ===");
  const cut = await truncatedHello();
  check("a ClientHello cut short is answered with a fatal alert and a FIN " +
        "at once, and the descriptor is held (closed +" + cut.refused +
        " ms)", function () {
    assert.ok(cut.alert && cut.alert[0] === 0x15 && cut.alert[5] === 0x02,
              "no fatal alert record: " + JSON.stringify(cut));
    assert.ok(cut.alertAt >= 0 && cut.alertAt < PROMPT_MS,
              JSON.stringify(cut));
    assert.ok(cut.fin >= 0 && cut.fin < PROMPT_MS, JSON.stringify(cut));
    assert.ok(cut.refused >= HELD_AT_LEAST_MS, JSON.stringify(cut));
  });

  log.info("=== a good request ===");
  const good = await api("GET", "/.well-known/openid-configuration");
  check("a good request on a connection of its own is answered 200",
        function () {
    assert.strictEqual(good.status, 200, good.raw.slice(0, 200));
  });
  log.info("sts_tls_alert_close: " + checks + " checks passed.");
  log.debug("Leaving test().");
}

test().then(function () {
  log.info("Test completed successfully.");
}).catch(function (e) {
  log.error("sts_tls_alert_close FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
