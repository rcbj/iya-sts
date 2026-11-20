// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_http_transport.js
//
// ---------------------------------------------------------------------------
// WHAT THE MAIN PORT'S TRANSPORT OWES A CLIENT, OVER REAL SOCKETS.
//
// D12 (#444): carries over the wire-visible half of
//
//   * `tests/parser_refusal.js` (#1500): a request the HTTP parser refuses
//     keeps its answer — an oversized request line, written in pieces so
//     that most of it is still arriving when the parser gives up, is
//     answered 431 every time with no reset, malformed HTTP is a 400 and a
//     good request is untouched; on the main port over TLS (HTTP/1.1 by
//     ALPN) and on the plain-HTTP revocation listener;
//   * `tests/http2_large_body.js` (#1725): over ONE HTTP/2 session, as a
//     browser holds one, `GET /admin-api/openapi.json` (several MB) parses
//     whole, and four of it at once with readers that pause, beside three
//     hundred small requests, all finish, none is refused and the session
//     never fails;
//   * `tests/lingering_close.js`: a risk dataset upload refused on its
//     query while 24 MB is still being sent is answered in full — status
//     and the whole JSON body — with no reset of a client still writing.
//
// What those files hold besides — the request pool's pipe and a worker's
// early answer, the paced methods' contract on an adapted app, and
// `arm()`'s socket handling — is the in-process half of a split pair with
// no client-visible difference in a single front process, and stays there.
//
// The revocation listener is `PKI_DISTRIBUTION_BASE_URL` (the launcher's
// `http://sts:8082`), or port 8082 of the service's host.
//
// Its realms are left standing, as every job's are, unless
// STS_TEST_REMOVE_REALMS=1 asks for them to be removed at the end: a hand
// run against a private probe would otherwise fill its directory.
//
// OWNED HERE (local: true): this repository's own listeners.
// ---------------------------------------------------------------------------

const assert = require("assert");
const net = require("net");
const tls = require("tls");
const http2 = require("http2");
const names = require("./random_username.js");

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
var log = bunyan.createLogger({ name: "sts_http_transport",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const MAIN = new URL(base);
const PLAIN = new URL(String(process.env.PKI_DISTRIBUTION_BASE_URL ||
                             "http://" + MAIN.hostname + ":8082"));
const STAMP = names.runStamp();
const REALM = ("wire-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
  .slice(0, 31);
const ATTEMPTS = 25;
const PARALLEL = 4;
const SMALL = 300;

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function token() {
  log.debug("Entering token().");
  const t = String(process.env.STS_ADMIN_API_TOKEN || "");
  assert.ok(t, "STS_ADMIN_API_TOKEN is not set: the launcher mints it");
  log.debug("Leaving token().");
  return t;
}

function mainPort() {
  log.debug("Entering mainPort().");
  log.debug("Leaving mainPort().");
  return Number(MAIN.port || 443);
}

// One connection: TLS with ALPN http/1.1 to the main port, or plain TCP to
// the revocation listener. The client never half-closes — a browser does
// not — and reads until the server closes or the bound passes.
function connect(kind, onConnect) {
  log.debug("Entering connect(). " + kind);
  log.debug("Leaving connect().");
  if (kind === "tls") {
    return tls.connect({ host: MAIN.hostname, port: mainPort(),
      servername: MAIN.hostname, ALPNProtocols: ["http/1.1"],
      rejectUnauthorized: false }, onConnect);
  }
  return net.connect(Number(PLAIN.port || 80), PLAIN.hostname, onConnect);
}

function sendRaw(kind, text) {
  log.debug("Entering sendRaw(). " + kind);
  log.debug("Leaving sendRaw().");
  return new Promise(function (resolve) {
    let got = "";
    let error = "";
    const socket = connect(kind, function () {
      socket.write(text.slice(0, 32000));
      setImmediate(function () {
        socket.write(text.slice(32000));
      });
    });
    const bound = setTimeout(function () {
      socket.destroy();
    }, 8000);
    socket.on("data", function (d) {
      got += d;
    });
    socket.on("error", function (e) {
      error = e.code || String(e);
    });
    socket.on("close", function () {
      clearTimeout(bound);
      resolve({ line: got.split("\r\n")[0], error: error });
    });
  });
}

async function sectionParser() {
  log.debug("Entering sectionParser().");
  log.info("=== 1. a request the parser refuses keeps its answer ===");
  const big = "GET /x?a=" + "a".repeat(200000) +
              " HTTP/1.1\r\nHost: h\r\n\r\n";
  for (const kind of ["tls", "plain"]) {
    const seen = {};
    for (let i = 0; i < ATTEMPTS; i += 1) {
      const one = await sendRaw(kind, big);
      const key = one.line + "|" + one.error;
      seen[key] = (seen[key] || 0) + 1;
    }
    check(kind + ": an oversized request is answered 431 every time, with " +
          "no reset", function () {
      assert.strictEqual(seen["HTTP/1.1 431 Request Header Fields Too " +
                              "Large|"], ATTEMPTS, JSON.stringify(seen));
    });
    const bad = await sendRaw(kind, "NOT HTTP AT ALL\r\n\r\n" +
                              "x".repeat(40000));
    check(kind + ": malformed HTTP is a 400", function () {
      assert.strictEqual(bad.line, "HTTP/1.1 400 Bad Request",
                         JSON.stringify(bad));
    });
    const good = await sendRaw(kind, "GET /healthcheck HTTP/1.1\r\n" +
                               "Host: h\r\nConnection: close\r\n\r\n");
    check(kind + ": and a good request is untouched", function () {
      assert.strictEqual(good.line, "HTTP/1.1 200 OK", JSON.stringify(good));
    });
  }
  log.debug("Leaving sectionParser().");
}

// One stream on the session; `pauseAt` bytes in, the reader stops for
// `pauseMs`, as a slow tab does.
function stream(session, path, pauseAt, pauseMs) {
  log.debug("Entering stream(). " + path);
  log.debug("Leaving stream().");
  return new Promise(function (resolve) {
    const req = session.request({ ":path": path,
                                  authorization: "Bearer " + token() });
    const chunks = [];
    let size = 0;
    let status = 0;
    let paused = false;
    req.on("response", function (headers) {
      status = headers[":status"];
    });
    req.on("data", function (c) {
      chunks.push(c);
      size += c.length;
      if (pauseAt && !paused && size >= pauseAt) {
        paused = true;
        req.pause();
        setTimeout(function () {
          req.resume();
        }, pauseMs);
      }
    });
    req.on("end", function () {
      resolve({ status: status, body: Buffer.concat(chunks), error: "" });
    });
    req.on("error", function (e) {
      resolve({ status: status, body: Buffer.concat(chunks),
                error: e.code || String(e) });
    });
    req.end();
  });
}

function parses(buffer) {
  log.debug("Entering parses().");
  try {
    JSON.parse(buffer.toString("utf8"));
    log.debug("Leaving parses(). true");
    return true;
  } catch (e) {
    log.debug("Caught in parses(): " + ((e && e.message) || e));
    log.debug("Leaving parses(). false");
    return false;
  }
}

async function sectionHttp2() {
  log.debug("Entering sectionHttp2().");
  log.info("=== 2. a large body over HTTP/2 always finishes ===");
  const session = http2.connect(base, { rejectUnauthorized: false });
  let sessionError = "";
  session.on("error", function (e) {
    sessionError = e.code || String(e);
  });
  try {
    const one = await stream(session, "/admin-api/openapi.json", 0, 0);
    check("one fetch of the document is a 200 whose body parses, over 4 MB",
          function () {
      assert.strictEqual(one.status, 200, one.error);
      assert.ok(one.body.length > 4 * 1024 * 1024, String(one.body.length));
      assert.ok(parses(one.body), "the body did not parse");
    });
    const started = Date.now();
    const large = [];
    for (let i = 0; i < PARALLEL; i += 1) {
      large.push(stream(session, "/admin-api/openapi.json", 1024 * 1024,
                        2000));
    }
    const small = [];
    for (let i = 0; i < SMALL; i += 1) {
      small.push(stream(session, "/healthcheck", 0, 0));
    }
    const bound = new Promise(function (resolve) {
      setTimeout(function () {
        resolve("timeout");
      }, 90000);
    });
    const done = await Promise.race([
      Promise.all([Promise.all(large), Promise.all(small)]), bound]);
    check("under load every large body ends and parses within the bound",
          function () {
      assert.notStrictEqual(done, "timeout", "a stream never ended in 90s");
      done[0].forEach(function (r) {
        assert.strictEqual(r.status, 200, r.error);
        assert.strictEqual(r.error, "");
        assert.ok(parses(r.body), "a body of " + r.body.length +
                  " bytes did not parse");
      });
    });
    check("no small request on the same session was refused", function () {
      const bad = done[1].filter(function (r) {
        return r.status !== 200 || r.error;
      });
      assert.strictEqual(bad.length, 0, JSON.stringify(bad.slice(0, 3)
        .map(function (r) {
          return { status: r.status, error: r.error };
        })));
    });
    check("and the session never failed (" + (Date.now() - started) +
          " ms)", function () {
      assert.strictEqual(sessionError, "");
      assert.ok(!session.destroyed && !session.closed);
    });
  } finally {
    session.close();
  }
  log.debug("Leaving sectionHttp2().");
}

// A 24 MB upload whose query the door refuses: the answer arrives while
// the client is still writing, and is read whole.
function earlyRefusal(path) {
  log.debug("Entering earlyRefusal().");
  log.debug("Leaving earlyRefusal().");
  return new Promise(function (resolve) {
    let got = "";
    let error = "";
    const total = 24 * 1024 * 1024;
    const socket = connect("tls", function () {
      socket.write("POST " + path + " HTTP/1.1\r\nHost: " + MAIN.host +
                   "\r\nAuthorization: Bearer " + token() +
                   "\r\nContent-Type: application/octet-stream" +
                   "\r\nContent-Length: " + total + "\r\n\r\n");
      let sent = 0;
      const chunk = Buffer.alloc(65536, 120);
      const pump = function () {
        while (sent < total && !socket.destroyed) {
          sent += chunk.length;
          if (!socket.write(chunk)) {
            socket.once("drain", pump);
            return;
          }
        }
      };
      pump();
    });
    const bound = setTimeout(function () {
      socket.destroy();
    }, 15000);
    socket.on("data", function (d) {
      got += d;
    });
    socket.on("error", function (e) {
      error = e.code || String(e);
    });
    socket.on("close", function () {
      clearTimeout(bound);
      const at = got.indexOf("\r\n\r\n");
      resolve({ line: got.split("\r\n")[0],
                head: at >= 0 ? got.slice(0, at) : got,
                body: at >= 0 ? got.slice(at + 4) : "", error: error });
    });
  });
}

async function sectionLingering() {
  log.debug("Entering sectionLingering().");
  log.info("=== 3. an early answer to a large upload reaches the client ===");
  const api = "/realm/" + REALM + "/admin-api/risk/upload";
  const cases = [
    [api + "?format=ip-list",
     "An upload names its dataset and its format. Nothing was stored."],
    [api + "?dataset=nope&format=ip-list",
     "\"dataset\" is \"nope\", which is not one of the 9 values it accepts"]
  ];
  for (const one of cases) {
    for (let i = 0; i < 3; i += 1) {
      const r = await earlyRefusal(one[0]);
      let body = null;
      try {
        body = JSON.parse(r.body);
      } catch (e) {
        log.debug("Caught in sectionLingering(): " + ((e && e.message) || e));
        // Asserted below: a body cut short by a reset does not parse.
        body = null;
      }
      check("refused while 24 MB is still arriving (" +
            one[0].split("?")[1] + ", #" + (i + 1) + "), the whole answer " +
            "is read and nothing is reset", function () {
        assert.strictEqual(r.line, "HTTP/1.1 400 Bad Request",
                           JSON.stringify(r).slice(0, 300));
        assert.strictEqual(r.error, "", r.error);
        assert.ok(body && body.ok === false &&
                  String(body.errors[0]).indexOf(one[1]) === 0,
                  r.body.slice(0, 300));
      });
    }
  }
  log.debug("Leaving sectionLingering().");
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. a throwaway realm " + REALM + " ===");
  const made = await fetch(base + "/admin-api/realms/create", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ id: REALM, domain: REALM + ".example.net",
                           name: "HTTP transport " + STAMP }) });
  assert.strictEqual(made.status, 200, await made.text());
  await sectionParser();
  await sectionHttp2();
  await sectionLingering();
  log.info(checks + " checks passed.");
  log.debug("Leaving test().");
}

// THE REALMS ARE LEFT STANDING, as every job leaves its own (tests/CLAUDE.md,
// "No job removes a realm"), unless STS_TEST_REMOVE_REALMS is "1": a hand
// run against a private probe that hundreds of realms would otherwise fill
// asks for them to be removed, and so for everything made in them.
async function removeRealms() {
  log.debug("Entering removeRealms().");
  if (process.env.STS_TEST_REMOVE_REALMS !== "1") {
    log.debug("Leaving removeRealms(). Left standing.");
    return;
  }
  for (const id of [REALM]) {
    try {
      const r = await fetch(base + "/admin-api/realms/remove", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: id }) });
      log.info("removed the realm " + id + ": " + r.status);
    } catch (e) {
      log.debug("Caught in removeRealms(): " + ((e && e.message) || e));
      // A removal that fails leaves a realm behind, which is the default.
      log.info("could not remove the realm " + id);
    }
  }
  log.debug("Leaving removeRealms().");
}

async function main() {
  log.debug("Entering main().");
  try {
    try {
      await test();
    } finally {
      await removeRealms();
    }
    log.info("Test completed successfully.");
    log.debug("Leaving main().");
    process.exit(0);
  } catch (e) {
    log.debug("Caught in main(): " + ((e && e.message) || e));
    log.error("Test failed: " + ((e && e.stack) || e));
    log.debug("Leaving main().");
    process.exit(1);
  }
}

main();
