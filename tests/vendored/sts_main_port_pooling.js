// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: sts_main_port_pooling.js
//
// ===========================================================================
// THE MAIN PORT KEEPS CONNECTIONS AND SESSIONS, AND A SESSION RESUMES ON ANY
// NODE (#406, 2026-10-02).
//
// The main port asks every FULL TLS handshake for a client certificate, and a
// browser holding one under a CA it names asks its user whether to send it —
// on every full handshake, because a resumed session carries no
// CertificateRequest. With node's five-second keep-alive and a session-ticket
// key per node, a person clicking through the console or the portal behind a
// balancer was asked on nearly every click. Four things fixed it, and this job
// asserts each where it can be seen — on the wire:
//
//   1. an idle HTTP/1.1 connection is kept `http.keepAliveTimeoutS`
//      (the `Keep-Alive: timeout=` header node answers with);
//   2. requests PIPELINED on one connection are answered, in order;
//   3. a TLS session may be resumed for `tls.sessionTimeoutS` (the
//      timeout of the session OpenSSL's own client records);
//   4. a session made with a client certificate RESUMES on the next
//      connection — on whichever node the balancer picks, in the `cluster`
//      mode — and the certificate still signs its holder in. That is the
//      half the shared ticket key needed the replicated chain for: a resumed
//      session hands the server the leaf alone, the certificate here has an
//      intermediate the service does not hold, and product mode's hard-fail
//      refuses a leaf whose issuer it cannot find.
//
// Its connections are raw TLS sockets, so `tools/fresh-connections.js` (the
// cluster mode's preload) changes nothing here: every connection is new, and
// each one offers the session the one before it was given.
// ===========================================================================

const assert = require("assert");
const https = require("https");
const tls = require("tls");
const net = require("net");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFileSync } = require("child_process");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, for the reason wait_for.js (beside this file) gives.
  appconfigProblem = e;
  appconfig = {};
}

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_main_port_pooling",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");
var url = new URL(base);
var HOST = url.hostname;
var PORT = Number(url.port || 443);
var EXPECTED_NODES = Number(process.env.STS_TEST_CLUSTER_NODES || 1);
var RESUMPTIONS = Number(process.env.STS_POOLING_RESUMPTIONS || 10);
var STAMP = Date.now().toString(36);

var checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function token() {
  log.debug("Entering token().");
  log.debug("Leaving token().");
  return process.env.STS_ADMIN_API_TOKEN || "";
}

// One request through node's own client, for the headers it answers with.
function get(pathname, headers) {
  log.debug("Entering get(). " + pathname);
  log.debug("Leaving get().");
  return new Promise(function (resolve, reject) {
    const req = https.request({
      host: HOST, port: PORT, path: pathname, method: "GET",
      headers: Object.assign({ Connection: "keep-alive" }, headers || {}),
      agent: new https.Agent({ keepAlive: true })
    }, function (res) {
      let body = "";
      res.on("data", function (d) { body += d; });
      res.on("end", function () {
        let json = null;
        try {
          json = JSON.parse(body);
        } catch (e) {
          log.debug("Caught in get(): " + e.message);
        }
        resolve({ status: res.statusCode, headers: res.headers,
                  body: body, json: json });
      });
    });
    req.on("error", reject);
    req.end();
  });
}

// One POST to the management API, JSON both ways.
function post(pathname, body) {
  log.debug("Entering post(). " + pathname);
  log.debug("Leaving post().");
  return new Promise(function (resolve, reject) {
    const text = JSON.stringify(body);
    const req = https.request({
      host: HOST, port: PORT, path: pathname, method: "POST",
      headers: { "Content-Type": "application/json",
                 "Content-Length": Buffer.byteLength(text),
                 Authorization: "Bearer " + token() }
    }, function (res) {
      let answer = "";
      res.on("data", function (d) { answer += d; });
      res.on("end", function () {
        resolve({ status: res.statusCode, text: answer });
      });
    });
    req.on("error", reject);
    req.end(text);
  });
}

// What a setting is on this service, as the management API reports it.
async function settingValue(key) {
  log.debug("Entering settingValue(). " + key);
  const answer = await get("/admin-api/config",
                           { Authorization: "Bearer " + token() });
  assert.strictEqual(answer.status, 200,
    "GET /admin-api/config answered " + answer.status + " " +
    answer.body.slice(0, 200));
  const json = answer.json || {};
  // The rows are the groups' `settings`, as admin_api.js reads them. A
  // top-level `settings` is the page's own settings BLOCK since #446 (an
  // object), not a list of rows; it is read only when it is an array.
  const row = (json.groups || []).reduce(function (all, g) {
    return all.concat(g.settings || []);
  }, Array.isArray(json.settings) ? json.settings : []).filter(function (one) {
    return one.key === key;
  })[0];
  assert.ok(row, "GET /admin-api/config lists no " + key);
  log.debug("Leaving settingValue(). " + row.value);
  return row.value;
}

// ---------------------------------------------------------------------------
// RAW HTTP/1.1 OVER ONE TLS CONNECTION. Requests are written back to back
// (pipelined), the last one asking to close, and the answers are read off
// the stream in order — by Content-Length, or chunk by chunk.
// ---------------------------------------------------------------------------
function parseResponses(buf) {
  log.debug("Entering parseResponses(). " + buf.length + " bytes");
  const out = [];
  let at = 0;
  while (at < buf.length) {
    const end = buf.indexOf("\r\n\r\n", at);
    if (end < 0) {
      break;
    }
    const head = buf.slice(at, end).toString("latin1").split("\r\n");
    const status = Number((head[0].match(/^HTTP\/1\.1 (\d{3})/) || [])[1]);
    const headers = {};
    head.slice(1).forEach(function (line) {
      const i = line.indexOf(":");
      if (i > 0) {
        headers[line.slice(0, i).trim().toLowerCase()] =
          line.slice(i + 1).trim();
      }
    });
    let bodyAt = end + 4;
    let body = Buffer.alloc(0);
    if (/chunked/i.test(headers["transfer-encoding"] || "")) {
      const parts = [];
      for (;;) {
        const lineEnd = buf.indexOf("\r\n", bodyAt);
        const size = parseInt(buf.slice(bodyAt, lineEnd).toString(), 16);
        bodyAt = lineEnd + 2;
        if (!size) {
          bodyAt += 2;
          break;
        }
        parts.push(buf.slice(bodyAt, bodyAt + size));
        bodyAt += size + 2;
      }
      body = Buffer.concat(parts);
    } else {
      const n = Number(headers["content-length"] || 0);
      body = buf.slice(bodyAt, bodyAt + n);
      bodyAt += n;
    }
    let json = null;
    try {
      json = JSON.parse(body.toString("utf8"));
    } catch (e) {
      log.debug("Caught in parseResponses(): " + e.message);
    }
    out.push({ status: status, headers: headers,
               body: body.toString("utf8"), json: json });
    at = bodyAt;
  }
  log.debug("Leaving parseResponses(). " + out.length);
  return out;
}

function pipelined(requests, options) {
  log.debug("Entering pipelined(). " + requests.length + " request(s)");
  const opts = options || {};
  log.debug("Leaving pipelined().");
  return new Promise(function (resolve, reject) {
    const chunks = [];
    let issued = null;
    // Read at the handshake: by `close` the socket's handle is gone and
    // isSessionReused() answers null, which read as a full handshake on
    // every connection.
    let reused = null;
    const socket = tls.connect({
      host: HOST, port: PORT, servername: net.isIP(HOST) ? undefined : HOST,
      cert: opts.certPem, key: opts.keyPem, session: opts.session,
      // What is asserted is the session and the client certificate; the
      // server's certificate is not verified here, as in
      // `sts_global_logout.js`.
      rejectUnauthorized: false
    }, function () {
      reused = socket.isSessionReused();
      const text = requests.map(function (one, i) {
        const last = i === requests.length - 1;
        return "GET " + one.path + " HTTP/1.1\r\nHost: " + url.host + "\r\n" +
          Object.keys(one.headers || {}).map(function (k) {
            return k + ": " + one.headers[k] + "\r\n";
          }).join("") +
          "Connection: " + (last ? "close" : "keep-alive") + "\r\n\r\n";
      }).join("");
      socket.write(text);
    });
    socket.on("session", function (s) {
      issued = s;
    });
    socket.on("data", function (d) {
      chunks.push(d);
    });
    socket.on("error", reject);
    socket.on("close", function () {
      resolve({ reused: reused, session: issued,
                responses: parseResponses(Buffer.concat(chunks)) });
    });
    socket.setTimeout(30000, function () {
      socket.destroy(new Error("no answer within 30 s"));
    });
  });
}

// ---------------------------------------------------------------------------
// 1. KEEP-ALIVE.
// ---------------------------------------------------------------------------
async function keepAlive() {
  log.debug("Entering keepAlive().");
  log.info("== 1. An idle HTTP/1.1 connection is kept");
  // The main port's own value where it sets one (#429), else the service's.
  const own = Number(await settingValue("listenerMain.keepAliveTimeoutS"));
  const want = own >= 0 ? own
    : Number(await settingValue("http.keepAliveTimeoutS"));
  const answer = await get("/.well-known/openid-configuration");
  check("the main port answers a kept-alive request with Keep-Alive: " +
        "timeout=" + want, function () {
    assert.strictEqual(answer.status, 200);
    const header = String(answer.headers["keep-alive"] || "");
    const seen = Number((header.match(/timeout=(\d+)/) || [])[1]);
    assert.strictEqual(seen, want,
      "Keep-Alive was \"" + header + "\"; http.keepAliveTimeoutS is " +
      want + " (node's own default, which this replaced, is 5)");
  });
  log.debug("Leaving keepAlive().");
}

// ---------------------------------------------------------------------------
// 2. PIPELINING.
// ---------------------------------------------------------------------------
async function pipelining() {
  log.debug("Entering pipelining().");
  log.info("== 2. Pipelined requests are answered in order");
  const got = await pipelined([
    { path: "/.well-known/openid-configuration" },
    { path: "/oauth2/jwks" },
    { path: "/.well-known/oauth-authorization-server" }
  ]);
  check("three requests written back to back on one connection get three " +
        "answers, in the order asked", function () {
    assert.strictEqual(got.responses.length, 3,
      "answers read: " + got.responses.length);
    got.responses.forEach(function (r) {
      assert.strictEqual(r.status, 200, "an answer was " + r.status);
    });
    assert.ok(got.responses[0].json && got.responses[0].json.issuer &&
              got.responses[0].json.userinfo_endpoint,
      "the first answer is not the OpenID configuration");
    assert.ok(got.responses[1].json &&
              Array.isArray(got.responses[1].json.keys),
      "the second answer is not the JWKS");
    assert.ok(got.responses[2].json && got.responses[2].json.issuer &&
              !got.responses[2].json.userinfo_endpoint,
      "the third answer is not the OAuth server metadata");
  });
  log.debug("Leaving pipelining().");
}

// ---------------------------------------------------------------------------
// 3. THE SESSION'S LIFETIME, AS OPENSSL'S CLIENT RECORDS IT.
// ---------------------------------------------------------------------------
async function sessionLifetime() {
  log.debug("Entering sessionLifetime().");
  log.info("== 3. A TLS session may be resumed for tls.sessionTimeoutS");
  const ownS = Number(await settingValue("listenerMain.sessionTimeoutS"));
  const want = ownS >= 0 ? ownS
    : Number(await settingValue("tls.sessionTimeoutS"));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sts-pooling-"));
  const sess = path.join(dir, "session.pem");
  try {
    // A request is sent so that the TLS 1.3 tickets, which arrive after the
    // handshake, are in before OpenSSL writes the session out.
    execFileSync("openssl", ["s_client", "-connect", HOST + ":" + PORT,
                             "-servername", HOST, "-ign_eof", "-quiet",
                             "-sess_out", sess],
                 { input: "GET /.well-known/openid-configuration HTTP/1.1\r\n" +
                          "Host: " + url.host + "\r\nConnection: close\r\n\r\n",
                   stdio: ["pipe", "ignore", "ignore"], timeout: 30000 });
    const text = execFileSync("openssl", ["sess_id", "-in", sess, "-text",
                                          "-noout"],
                              { encoding: "utf8", timeout: 10000 });
    const hint = Number((text.match(/lifetime hint:\s*(\d+)/) || [])[1]);
    check("the session ticket's lifetime hint is " + want + " seconds",
          function () {
      assert.strictEqual(hint, want, "lifetime hint was " + hint + "\n" +
                         text.slice(0, 600));
    });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  log.debug("Leaving sessionLifetime().");
}

// ---------------------------------------------------------------------------
// 4. A CLIENT-CERTIFICATE SESSION RESUMES, ON ANY NODE, AND STILL SIGNS IN.
// ---------------------------------------------------------------------------
async function resumption() {
  log.debug("Entering resumption().");
  log.info("== 4. A session made with a client certificate resumes, on any " +
           "node, and the certificate still signs its holder in");
  const pki = await require("../tools/pep-credential.js").mint({
    rootSubject: "CN=pooling test Root " + STAMP + ",O=iya-sts tests",
    issuingSubject: "CN=pooling test Issuing CA " + STAMP + ",O=iya-sts tests",
    subject: "CN=pooling-" + STAMP + ",O=iya-sts tests"
  });
  // THE CERTIFICATE'S PERSON, made first: product mode signs nobody in whom
  // nobody provisioned.
  const made = await post("/admin-api/users/create",
                          { username: "pooling-" + STAMP, invent: false,
                            credential: "generate" });
  assert.strictEqual(made.status, 200,
    "POST /admin-api/users/create answered " + made.status + " " +
    made.text.slice(0, 200));
  const added = await post("/admin-api/tls/trust/add",
                           { certificates: pki.anchorPem });
  assert.strictEqual(added.status, 200,
    "adding the test Root through POST /admin-api/tls/trust/add answered " +
    added.status + " " + added.text.slice(0, 200));

  const ask = [
    { path: "/admin-api/cluster",
      headers: { Authorization: "Bearer " + token() } },
    { path: "/tls/sign-in" }
  ];
  const nodeOf = function (r) {
    const s = r && r.json && r.json.status && r.json.status.self;
    return s ? String(s.name || s.nodeId || "") : "";
  };
  // THE ANCHOR IS APPLIED BY `setSecureContext()` ON EVERY NODE, which the
  // other node does when the store's change reaches it — so the first full
  // handshake is retried until a sign-in happens.
  let first = null;
  for (let i = 0; i < 20; i += 1) {
    first = await pipelined(ask, pki);
    const signed = first.responses[1] && first.responses[1].json &&
      first.responses[1].json.signedIn === true;
    if (signed && first.session) {
      break;
    }
    await new Promise(function (r) { setTimeout(r, 500); });
  }
  check("a full handshake with the certificate (leaf and intermediate, the " +
        "Root trusted) signs its holder in", function () {
    assert.ok(first.responses[1] && first.responses[1].json &&
              first.responses[1].json.signedIn === true,
      "GET /tls/sign-in: " +
      String(first.responses[1] && first.responses[1].body).slice(0, 400));
    assert.ok(first.session, "the server issued no session ticket");
  });

  const rows = [{ reused: first.reused, node: nodeOf(first.responses[0]),
                  signedIn: true }];
  let session = first.session;
  for (let i = 0; i < RESUMPTIONS; i += 1) {
    const got = await pipelined(ask, Object.assign({ session: session }, pki));
    const signIn = got.responses[1] || {};
    rows.push({ reused: got.reused, node: nodeOf(got.responses[0]),
                signedIn: !!(signIn.json && signIn.json.signedIn === true),
                why: signIn.json ? JSON.stringify(signIn.json.revocation ||
                                                  signIn.json.session || {})
                                 : String(signIn.body || "").slice(0, 200) });
    session = got.session || session;
  }
  log.info("  connections: " + rows.map(function (r) {
    return (r.node || "?") + (r.reused ? "/resumed" : "/full") +
           (r.signedIn ? "" : "/REFUSED");
  }).join(" "));
  const later = rows.slice(1);
  check("every later connection resumed the session (" + later.length + ")",
        function () {
    const full = later.filter(function (r) { return !r.reused; });
    assert.strictEqual(full.length, 0,
      full.length + " of " + later.length + " connections made a full " +
      "handshake (a browser holding a matching certificate asks its user on " +
      "each): " + full.map(function (r) { return r.node; }).join(", "));
  });
  check("the certificate signed its holder in on every resumed connection",
        function () {
    const refused = later.filter(function (r) { return !r.signedIn; });
    assert.strictEqual(refused.length, 0,
      refused.length + " resumed connection(s) did not sign in: " +
      refused.map(function (r) { return r.node + " " + r.why; }).join("; "));
  });
  if (EXPECTED_NODES > 1) {
    check("sessions resumed on " + EXPECTED_NODES + " nodes", function () {
      const nodes = new Set(later.filter(function (r) {
        return r.reused && r.node;
      }).map(function (r) { return r.node; }));
      assert.ok(nodes.size >= Math.min(EXPECTED_NODES, 2),
        "resumed connections reached " + Array.from(nodes).join(", ") +
        " only; the balancer picks a node per connection, so a session made " +
        "on one node was never resumed on another");
    });
  }
  log.debug("Leaving resumption().");
}

async function main() {
  log.debug("Entering main().");
  await keepAlive();
  await pipelining();
  await sessionLifetime();
  await resumption();
  log.info("sts_main_port_pooling passed: " + checks + " checks.");
  log.debug("Leaving main().");
}

main().then(function () {
  process.exit(0);
}, function (e) {
  log.error("sts_main_port_pooling FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
