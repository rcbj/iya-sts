// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_main_port_http2.js
//
// ---------------------------------------------------------------------------
// THE MAIN PORT ANSWERS HTTP/2 AND HTTP/1.1 ALIKE, OVER THE WIRE (#407,
// #1304).
//
// D12 (#444): carries over tests/main_port_http2.js's claims that a client
// can see, against the running service's main port:
//
//   1. the same answer over each protocol — the discovery document, a token
//      request with a form body and no content-length (1a: and one with
//      one), an unknown realm and an unrouted path: status, body, the
//      `frame-ancestors` clause, and no `X-Powered-By`;
//   2. a client certificate at the handshake still binds the token (RFC
//      8705's `cnf.x5t#S256`), over HTTP/2 as over HTTP/1.1;
//   3. ten requests multiplexed on one HTTP/2 session, each answered;
//   6. `http.http2` off: the next handshake negotiates `http/1.1` while an
//      open HTTP/2 session keeps answering; reset, `h2` again;
//   8. the HTTP/2 bounds: `http.http2MaxConcurrentStreams` is what a
//      session is told in its SETTINGS; a session that has carried
//      `http.maxRequestsPerSocket` requests is sent a GOAWAY; an idle
//      session is closed after `http.keepAliveTimeoutS`;
//   9. `:authority` and `host` naming different hosts refused 400 with
//      its sentence, and the same host in another case or spelled with its
//      port again is not a difference;
//  13. CONNECT answered 501, no-store and `frame-ancestors` kept, over
//      HTTP/2 and HTTP/1.1.
//
// STS-HTTP-0024 AND STS-HTTP-0025 ARE NOT ASSERTED: both refusals are made
// before the call log's middleware, so neither reaches the audit — the code
// is in the service's log line only, which no job reads. The status and the
// sentence are what a client sees;
//  14. `OPTIONS *` over HTTP/2 answered 204;
//  15. `GET /admin-api/listeners` carries `http2MaxConcurrentStreams`.
//
// What stays in process (class (d)): the express module left untouched
// (10), the request pool's forwarding (7) and the lingering close's arming
// (4), which are the shape of one process; the debugger's own API proxy
// (12), which no test stack binds; and section 5, the source.
//
// The settings in 6 and 8 are process-wide, so each is put back with
// `reset` in a `finally`, pass or fail. The token requests run in a
// throwaway realm in development mode, where an unknown client is made the
// first time it is named.
//
// Its realms are removed at the end only under STS_TEST_REMOVE_REALMS=1
// (a hand run on a shared probe); the suite leaves them standing.
//
// OWNED HERE (local: true): this repository's own main port and management
// API.
// ---------------------------------------------------------------------------

const assert = require("assert");
const crypto = require("crypto");
const http2 = require("http2");
const https = require("https");
const tls = require("tls");
const forge = require("node-forge");
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
var log = bunyan.createLogger({ name: "sts_main_port_http2",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const TARGET = new URL(base);
const STAMP = names.runStamp();
const REALM = ("h2-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
  .slice(0, 31);
const TOKEN = process.env.STS_ADMIN_API_TOKEN || "";

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

// A self-signed client certificate, so RFC 8705's binding has something to
// bind to. It is bound by thumbprint; nothing needs to trust it.
function clientCertificate() {
  log.debug("Entering clientCertificate().");
  const pair = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = pair.publicKey;
  cert.serialNumber = "0" + crypto.randomBytes(8).toString("hex");
  cert.validity.notBefore = new Date(Date.now() - 60000);
  cert.validity.notAfter = new Date(Date.now() + 3600000);
  const subject = [{ name: "commonName", value: "h2-client-" + STAMP }];
  cert.setSubject(subject);
  cert.setIssuer(subject);
  cert.setExtensions([{ name: "extKeyUsage", clientAuth: true }]);
  cert.sign(pair.privateKey, forge.md.sha256.create());
  const certPem = forge.pki.certificateToPem(cert);
  log.debug("Leaving clientCertificate().");
  return { cert: certPem, key: forge.pki.privateKeyToPem(pair.privateKey),
           thumbprint: crypto.createHash("sha256")
             .update(new crypto.X509Certificate(certPem).raw)
             .digest("base64url") };
}

// One HTTP/1.1 request on a connection of its own.
function h1(method, path, options) {
  log.debug("Entering h1(). " + method + " " + path);
  const o = options || {};
  log.debug("Leaving h1().");
  return new Promise(function (resolve, reject) {
    const headers = Object.assign({}, o.headers || {});
    const req = https.request({
      method: method, hostname: TARGET.hostname, port: TARGET.port,
      path: path, headers: headers, agent: false,
      rejectUnauthorized: false, cert: o.cert, key: o.key,
      ALPNProtocols: ["http/1.1"]
    }, function (res) {
      const chunks = [];
      res.on("data", function (c) {
        chunks.push(c);
      });
      res.on("end", function () {
        resolve({ status: res.statusCode, headers: res.headers,
                  raw: Buffer.concat(chunks).toString("utf8"),
                  alpn: res.socket && res.socket.alpnProtocol });
      });
    });
    req.on("error", reject);
    req.end(o.body || undefined);
  });
}

// An HTTP/2 session; `connect()` resolves once its SETTINGS have arrived.
function session(options) {
  log.debug("Entering session().");
  const o = options || {};
  log.debug("Leaving session().");
  return new Promise(function (resolve, reject) {
    const s = http2.connect(base, { rejectUnauthorized: false,
                                    cert: o.cert, key: o.key });
    const state = { goaway: false, closed: false };
    s.on("goaway", function () {
      state.goaway = true;
    });
    s.on("close", function () {
      state.closed = true;
    });
    s.on("error", function (e) {
      log.debug("HTTP/2 session error: " + ((e && e.message) || e));
      state.error = e;
    });
    s.once("remoteSettings", function (settings) {
      resolve({ session: s, settings: settings, state: state });
    });
    s.once("error", reject);
  });
}

// One request on an HTTP/2 session.
function h2(s, headers, body) {
  log.debug("Entering h2().");
  log.debug("Leaving h2().");
  return new Promise(function (resolve) {
    let st;
    try {
      st = s.request(headers);
    } catch (e) {
      log.debug("Caught in h2(): " + ((e && e.message) || e));
      // A session that has gone away refuses a new stream at once.
      resolve({ error: e });
      return;
    }
    const chunks = [];
    let head = {};
    st.on("response", function (h) {
      head = h;
    });
    st.on("data", function (c) {
      chunks.push(c);
    });
    st.on("end", function () {
      resolve({ status: head[":status"], headers: head,
                raw: Buffer.concat(chunks).toString("utf8") });
    });
    st.on("error", function (e) {
      log.debug("HTTP/2 stream error: " + ((e && e.message) || e));
      resolve({ error: e });
    });
    st.end(body || undefined);
  });
}

async function api(method, path, payload) {
  log.debug("Entering api(). " + method + " " + path);
  const ask = function () {
    return fetch(base + path, {
      method: method,
      headers: { "Content-Type": "application/json",
                 Accept: "application/json" },
      body: payload === undefined ? undefined : JSON.stringify(payload) });
  };
  let r;
  try {
    r = await ask();
  } catch (e) {
    log.debug("Caught in api(): " + ((e && e.message) || e));
    // A kept-alive connection the service closed under a short
    // http.keepAliveTimeoutS (section 8): ask once more on a new one.
    await sleep(200);
    r = await ask();
  }
  const raw = await r.text();
  let body = null;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in api(): " + ((e && e.message) || e));
    // Not JSON; the caller reads `raw`.
    body = null;
  }
  log.debug("Leaving api(). " + r.status);
  return { status: r.status, body: body, raw: raw };
}

async function setSetting(key, value) {
  log.debug("Entering setSetting(). " + key);
  const r = await api("POST", "/admin-api/config/set",
                      { key: key, value: value });
  assert.strictEqual(r.status, 200, "config/set " + key + ": " +
                     r.raw.slice(0, 300));
  log.debug("Leaving setSetting().");
}

async function resetSetting(key) {
  log.debug("Entering resetSetting(). " + key);
  const r = await api("POST", "/admin-api/config/reset", { key: key });
  if (r.status !== 200 && !/no runtime override/.test(r.raw)) {
    log.warn("config/reset " + key + " answered " + r.status + " " +
             r.raw.slice(0, 200));
  }
  log.debug("Leaving resetSetting().");
}

function form(fields) {
  log.debug("Entering form().");
  log.debug("Leaving form().");
  return new URLSearchParams(fields).toString();
}

function claimsOf(jwt) {
  log.debug("Entering claimsOf().");
  log.debug("Leaving claimsOf().");
  return JSON.parse(Buffer.from(String(jwt).split(".")[1], "base64url")
    .toString("utf8"));
}

function sameAnswer(a, b, what) {
  log.debug("Entering sameAnswer().");
  assert.strictEqual(a.status, b.status, what + ": HTTP/1.1 " + a.status +
                     ", HTTP/2 " + b.status);
  const csp1 = String(a.headers["content-security-policy"]);
  const csp2 = String(b.headers["content-security-policy"]);
  assert.ok(/frame-ancestors/.test(csp1),
            what + " over HTTP/1.1 carries no frame-ancestors");
  assert.ok(/frame-ancestors/.test(csp2),
            what + " over HTTP/2 carries no frame-ancestors");
  assert.strictEqual(a.headers["x-powered-by"], undefined, what);
  assert.strictEqual(b.headers["x-powered-by"], undefined, what);
  log.debug("Leaving sameAnswer().");
}

// CONNECT over HTTP/1.1, written by hand: node's client would open a tunnel.
function connectOverH1() {
  log.debug("Entering connectOverH1().");
  log.debug("Leaving connectOverH1().");
  return new Promise(function (resolve, reject) {
    const socket = tls.connect({ host: TARGET.hostname,
      port: Number(TARGET.port), rejectUnauthorized: false,
      servername: TARGET.hostname, ALPNProtocols: ["http/1.1"] },
    function () {
      socket.write("CONNECT example.com:443 HTTP/1.1\r\nHost: " +
                   "example.com:443\r\n\r\n");
    });
    let text = "";
    socket.setTimeout(10000, function () {
      socket.destroy();
    });
    socket.on("data", function (c) {
      text += c.toString("latin1");
      if (/\r\n\r\n[\s\S]*\n$/.test(text) || /Content-Length: 0/i.test(text)) {
        socket.end();
      }
    });
    socket.on("close", function () {
      resolve(text);
    });
    socket.on("error", reject);
  });
}

async function test() {
  log.debug("Entering test().");
  assert.ok(base.indexOf("https:") === 0,
            "the main port is HTTPS in every appconfig; " + base + " is not");
  log.info("=== 0. a throwaway realm " + REALM + " ===");
  const made = await api("POST", "/admin-api/realms/create",
    { id: REALM, domain: REALM + ".example.net",
      name: "HTTP/2 " + STAMP });
  assert.strictEqual(made.status, 200, made.raw.slice(0, 300));
  const realmBase = "/realm/" + REALM;

  log.info("=== 1. the same answer over each protocol ===");
  const one = await session();
  const s = one.session;
  const pairs = [
    ["the discovery document", "/.well-known/openid-configuration"],
    ["an unknown realm", "/realm/no-such-" + STAMP.toLowerCase() +
     "/.well-known/openid-configuration"],
    ["an unrouted path", "/no-such-path-" + STAMP]
  ];
  for (const pair of pairs) {
    const a = await h1("GET", pair[1]);
    const b = await h2(s, { ":path": pair[1] });
    check(pair[0] + ": status, body, frame-ancestors and no X-Powered-By " +
          "agree", function () {
      sameAnswer(a, b, pair[0]);
      assert.strictEqual(a.raw, b.raw, pair[0] + " bodies differ");
    });
  }
  const tokenPath = realmBase + "/oauth2/token";
  const client = "h2-client-" + STAMP.toLowerCase();
  const tokenBody = form({ grant_type: "client_credentials",
                           client_id: client });
  const viaH1 = await h1("POST", tokenPath, { body: tokenBody,
    headers: { "content-type": "application/x-www-form-urlencoded",
               "content-length": Buffer.byteLength(tokenBody) } });
  const viaH2 = await h2(s, { ":method": "POST", ":path": tokenPath,
    "content-type": "application/x-www-form-urlencoded" }, tokenBody);
  const viaH2Length = await h2(s, { ":method": "POST", ":path": tokenPath,
    "content-type": "application/x-www-form-urlencoded",
    "content-length": String(Buffer.byteLength(tokenBody)) }, tokenBody);
  check("1a. a token request with a form body answers 200 over HTTP/1.1, " +
        "over HTTP/2 with no content-length, and with one", function () {
    for (const r of [viaH1, viaH2, viaH2Length]) {
      assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
      assert.ok(JSON.parse(r.raw).access_token, r.raw.slice(0, 300));
    }
    sameAnswer(viaH1, viaH2, "the token request");
  });

  log.info("=== 2. a client certificate still binds the token ===");
  const cc = clientCertificate();
  const bound1 = await h1("POST", tokenPath, { body: tokenBody,
    cert: cc.cert, key: cc.key,
    headers: { "content-type": "application/x-www-form-urlencoded" } });
  const certSession = await session({ cert: cc.cert, key: cc.key });
  const bound2 = await h2(certSession.session, { ":method": "POST",
    ":path": tokenPath,
    "content-type": "application/x-www-form-urlencoded" }, tokenBody);
  certSession.session.close();
  check("2. the token's cnf carries the presented certificate's " +
        "thumbprint over HTTP/1.1 and HTTP/2", function () {
    for (const r of [bound1, bound2]) {
      assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
      const cnf = claimsOf(JSON.parse(r.raw).access_token).cnf || {};
      assert.strictEqual(cnf["x5t#S256"], cc.thumbprint, JSON.stringify(cnf));
    }
  });

  log.info("=== 3. ten requests multiplexed on one session ===");
  const ten = await Promise.all(Array.from({ length: 10 }, function (_, i) {
    return h2(s, { ":path": "/.well-known/openid-configuration?n=" + i });
  }));
  check("3. ten requests in flight together on one HTTP/2 session are " +
        "each answered 200", function () {
    assert.strictEqual(ten.filter(function (r) {
      return r.status === 200;
    }).length, 10, JSON.stringify(ten.map(function (r) {
      return r.status || String(r.error);
    })));
  });

  log.info("=== 9. :authority and host ===");
  const authority = TARGET.host;
  const differs = await h2(s, { ":path": "/.well-known/openid-configuration",
                                ":authority": authority,
                                host: "evil.example" });
  const sameCase = await h2(s, { ":path": "/.well-known/openid-configuration",
                                 ":authority": authority,
                                 host: authority.toUpperCase() });
  check("9. :authority and host naming different hosts is refused 400, " +
        "and the same host in another case is not a difference",
        function () {
    assert.strictEqual(differs.status, 400, differs.raw.slice(0, 200));
    assert.strictEqual(sameCase.status, 200, sameCase.raw.slice(0, 200));
  });
  check("9. the refusal says why in a plain, no-store body", function () {
    assert.ok(/:authority and Host name different hosts/.test(differs.raw) &&
              /RFC 9113 section 8\.3\.1/.test(differs.raw), differs.raw);
    assert.strictEqual(differs.headers["cache-control"], "no-store");
  });
  if (TARGET.port === "443" || TARGET.port === "") {
    log.info("The service is on the default port, so the default-port " +
             "spelling is the authority itself.");
  } else {
    const plain = await h2(s, { ":path": "/.well-known/openid-configuration",
                                ":authority": authority,
                                host: TARGET.hostname + ":" + TARGET.port });
    check("9. the same host and port spelled again is not a difference",
          function () {
      assert.strictEqual(plain.status, 200, plain.raw.slice(0, 200));
    });
  }

  log.info("=== 13. CONNECT ===");
  const connect2 = await h2(s, { ":method": "CONNECT",
                                 ":authority": "example.com:443" });
  const connect1 = await connectOverH1();
  check("13. CONNECT over HTTP/2 answers 501, no-store, frame-ancestors " +
        "kept", function () {
    assert.strictEqual(connect2.status, 501, connect2.raw.slice(0, 200));
    assert.strictEqual(connect2.headers["cache-control"], "no-store");
    assert.ok(/frame-ancestors 'none'/
      .test(connect2.headers["content-security-policy"]),
      String(connect2.headers["content-security-policy"]));
    assert.ok(/origin server, not a proxy/.test(connect2.raw), connect2.raw);
  });
  check("13. CONNECT over HTTP/1.1 answers the same 501", function () {
    assert.ok(/^HTTP\/1\.1 501 /.test(connect1), connect1.slice(0, 300));
    assert.ok(/cache-control: no-store/i.test(connect1), connect1);
    assert.ok(/frame-ancestors 'none'/i.test(connect1), connect1);
  });

  log.info("=== 14. OPTIONS * ===");
  const star = await h2(s, { ":method": "OPTIONS", ":path": "*" });
  check("14. OPTIONS * over HTTP/2 is answered 204", function () {
    assert.strictEqual(star.status, 204, String(star.error || star.raw));
  });

  log.info("=== 8 and 15. the HTTP/2 bounds and the Listeners view ===");
  const view = await api("GET", "/admin-api/listeners");
  const main = ((view.body && view.body.listeners) || []).filter(function (l) {
    return l.id === "main";
  })[0] || {};
  check("15. the Listeners view carries the main port's stream cap, and a " +
        "session is told exactly that", function () {
    assert.strictEqual(view.status, 200, view.raw.slice(0, 200));
    const cap = main.http && main.http.http2MaxConcurrentStreams;
    assert.ok(Number.isInteger(cap) && cap > 0, JSON.stringify(main.http));
    assert.strictEqual(one.settings.maxConcurrentStreams, cap,
                       JSON.stringify(one.settings));
    assert.strictEqual(main.http.http2, true, JSON.stringify(main.http));
  });
  s.close();

  const touched = ["http.http2MaxConcurrentStreams",
                   "http.maxRequestsPerSocket", "http.keepAliveTimeoutS",
                   "http.http2"];
  try {
    await setSetting("http.http2MaxConcurrentStreams", 3);
    await sleep(300);
    const capped = await session();
    check("8. a lowered stream cap is what the next session is told",
          function () {
      assert.strictEqual(capped.settings.maxConcurrentStreams, 3,
                         JSON.stringify(capped.settings));
    });
    const six = await Promise.all(Array.from({ length: 6 }, function (_, i) {
      return h2(capped.session, { ":path": "/.well-known/openid-" +
                                  "configuration?c=" + i });
    }));
    check("8. more streams than the cap still complete, queued by the " +
          "client within it", function () {
      assert.strictEqual(six.filter(function (r) {
        return r.status === 200;
      }).length, 6, JSON.stringify(six.map(function (r) {
        return r.status || String(r.error);
      })));
    });
    capped.session.close();

    await setSetting("http.maxRequestsPerSocket", 3);
    await sleep(300);
    const counted = await session();
    const answered = [];
    for (let i = 0; i < 5; i += 1) {
      answered.push(await h2(counted.session,
        { ":path": "/.well-known/openid-configuration?m=" + i }));
      if (counted.state.goaway) {
        break;
      }
    }
    await sleep(300);
    check("8. a session that has carried http.maxRequestsPerSocket " +
          "requests is sent a GOAWAY", function () {
      assert.ok(counted.state.goaway || counted.state.closed,
                JSON.stringify(counted.state) + " after " +
                JSON.stringify(answered.map(function (r) {
                  return r.status || String(r.error);
                })));
      assert.ok(answered.filter(function (r) {
        return r.status === 200;
      }).length >= 3, "the first three were not all answered");
    });
    counted.session.close();
    await resetSetting("http.maxRequestsPerSocket");

    await setSetting("http.keepAliveTimeoutS", 2);
    await sleep(300);
    const idle = await session();
    await h2(idle.session, { ":path": "/.well-known/openid-configuration" });
    const waitUntil = Date.now() + 15000;
    while (!idle.state.closed && !idle.state.goaway &&
           Date.now() < waitUntil) {
      await sleep(250);
    }
    check("8. an idle HTTP/2 session is closed after http.keepAliveTimeoutS",
          function () {
      assert.ok(idle.state.closed || idle.state.goaway,
                "the idle session was still open after 15s");
    });
    idle.session.destroy();
    await resetSetting("http.keepAliveTimeoutS");

    log.info("=== 6. http.http2 off and back ===");
    const kept = await session();
    await setSetting("http.http2", false);
    await sleep(300);
    const offered = await h1("GET", "/.well-known/openid-configuration");
    const alpnOff = await new Promise(function (resolve, reject) {
      const sock = tls.connect({ host: TARGET.hostname,
        port: Number(TARGET.port), rejectUnauthorized: false,
        servername: TARGET.hostname, ALPNProtocols: ["h2", "http/1.1"] },
      function () {
        resolve(sock.alpnProtocol);
        sock.end();
      });
      sock.on("error", reject);
    });
    const still = await h2(kept.session,
                           { ":path": "/.well-known/openid-configuration" });
    check("6. with http.http2 off the next handshake negotiates http/1.1, " +
          "and an open HTTP/2 session keeps answering", function () {
      assert.strictEqual(alpnOff, "http/1.1");
      assert.strictEqual(offered.status, 200, offered.raw.slice(0, 200));
      assert.strictEqual(still.status, 200, String(still.error || still.raw));
    });
    kept.session.close();
    await resetSetting("http.http2");
    await sleep(300);
    const alpnOn = await new Promise(function (resolve, reject) {
      const sock = tls.connect({ host: TARGET.hostname,
        port: Number(TARGET.port), rejectUnauthorized: false,
        servername: TARGET.hostname, ALPNProtocols: ["h2", "http/1.1"] },
      function () {
        resolve(sock.alpnProtocol);
        sock.end();
      });
      sock.on("error", reject);
    });
    check("6. reset, the next handshake negotiates h2 again", function () {
      assert.strictEqual(alpnOn, "h2");
    });
  } finally {
    for (const key of touched) {
      await resetSetting(key);
    }
  }
  log.info("sts_main_port_http2: " + checks + " checks passed.");
  log.debug("Leaving test().");
}

if (!TOKEN) {
  log.warn("STS_ADMIN_API_TOKEN is not set; the launcher's preload is " +
           "what presents it.");
}
// THE REALMS THIS JOB MADE, REMOVED AT ITS END ONLY WHEN ASKED
// (STS_TEST_REMOVE_REALMS=1, a hand run against a probe that many jobs
// share and whose directory would otherwise fill). The suite does not ask:
// no job removes a realm on a shared run (tests/CLAUDE.md).
async function removeRealms() {
  log.debug("Entering removeRealms().");
  if (process.env.STS_TEST_REMOVE_REALMS !== "1") {
    log.debug("Leaving removeRealms(). Not asked.");
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
      // A realm left behind is litter, not a failure of what was tested.
      log.warn("could not remove the realm " + id);
    }
  }
  log.debug("Leaving removeRealms().");
}

test().finally(removeRealms).then(function () {
  log.info("Test completed successfully.");
}).catch(function (e) {
  log.error("sts_main_port_http2 FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
