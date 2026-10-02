// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: sts_realm_listener.js
//
// ===========================================================================
// A TRUST REALM ON A LISTENER OF ITS OWN, OVER THE WIRE (#99, 2026-10-02).
//
// A realm given `listener.port` and `listener.publicBaseUrl` through
// `/admin-api/realms/set` is served on that port by every node, with every URL
// it builds on that base and its `/realm/<id>` prefix kept. This job, in every
// local mode:
//
//   1. frees the port from any realm an earlier run on this stack left on it
//      (no job removes a realm), creates a realm, and gives it the port and a
//      base on the host this job reaches the service by;
//   2. waits for the listener (each node binds it when the realm's change
//      reaches it), then reads the realm's discovery document THERE: its
//      issuer is the realm's base and prefix, and the certificate the listener
//      presents — issued by the realm's own CA — verifies against the
//      service's Root for that host name;
//   3. the default realm's path and another realm's are refused there (404,
//      STS-TLS-0041);
//   4. the realm read on the MAIN port names the same issuer, on its own
//      base, so its URLs are the same whichever listener answered;
//   5. `GET /admin-api/realms` reports the listener;
//   6. in the cluster mode, both nodes answer on the realm's port (the stack's
//      HAProxy balances 8099 like the main port).
//
// The port is `STS_TEST_REALM_LISTENER_PORT` (8099). The realm is left
// standing, as every realm a job makes is.
// ===========================================================================

const assert = require("assert");
const https = require("https");

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
var log = bunyan.createLogger({ name: "sts_realm_listener",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");
var HOST = new URL(base).hostname;
var PORT = Number(process.env.STS_TEST_REALM_LISTENER_PORT || 8099);
var EXPECTED_NODES = Number(process.env.STS_TEST_CLUSTER_NODES || 1);
var STAMP = Date.now().toString(36);
var REALM = "rlis-" + STAMP;
var OWN_BASE = "https://" + HOST + ":" + PORT;

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

// One request on a NEW connection, so a balancer picks a node for each.
function request(method, url, body, opts) {
  log.debug("Entering request(). " + method + " " + url);
  const o = opts || {};
  log.debug("Leaving request().");
  return new Promise(function (resolve) {
    const u = new URL(url);
    const text = body === undefined ? null : JSON.stringify(body);
    const headers = { Connection: "close" };
    if (text) {
      headers["Content-Type"] = "application/json";
      headers["Content-Length"] = Buffer.byteLength(text);
    }
    if (/\/admin-api(\/|$)/.test(u.pathname)) {
      headers.Authorization = "Bearer " + token();
    }
    const req = https.request({
      host: u.hostname, port: Number(u.port || 443),
      path: u.pathname + u.search, method: method, headers: headers,
      agent: false, servername: u.hostname,
      rejectUnauthorized: o.verify !== false
    }, function (res) {
      let answer = "";
      res.on("data", function (d) { answer += d; });
      res.on("end", function () {
        let json = null;
        try {
          json = JSON.parse(answer);
        } catch (e) {
          log.debug("Caught in request(): " + e.message);
        }
        resolve({ status: res.statusCode, text: answer, json: json,
                  error: "" });
      });
    });
    req.on("error", function (e) {
      resolve({ status: 0, text: "", json: null,
                error: (e && (e.code || e.message)) || String(e) });
    });
    if (text) {
      req.write(text);
    }
    req.end();
  });
}

async function ok(method, url, body, what) {
  log.debug("Entering ok(). " + what);
  const r = await request(method, url, body);
  assert.strictEqual(r.status, 200, what + ": " + method + " " + url +
                     " answered " + (r.status || r.error) + " " +
                     r.text.slice(0, 300));
  log.debug("Leaving ok().");
  return r;
}

function realmRows(json) {
  log.debug("Entering realmRows().");
  log.debug("Leaving realmRows().");
  return (json && json.realms) || [];
}

async function main() {
  log.debug("Entering main().");
  log.info("== 1. A realm given its own port and base");
  const listed = await ok("GET", base + "/admin-api/realms", undefined,
                          "listing the realms");
  for (const row of realmRows(listed.json)) {
    if (row.listener && Number(row.listener.port) === PORT &&
        row.id !== REALM) {
      await ok("POST", base + "/admin-api/realms/unset",
               { id: row.id, key: "listener.port" },
               "freeing port " + PORT + " from realm " + row.id);
    }
  }
  await ok("POST", base + "/admin-api/realms/create",
           { id: REALM, name: "Realm listener " + STAMP }, "made the realm");
  await ok("POST", base + "/admin-api/realms/set",
           { id: REALM, key: "listener.publicBaseUrl", value: OWN_BASE },
           "gave it its own base");
  const refused = await request("POST", base + "/admin-api/realms/set",
                                { id: REALM, key: "listener.port",
                                  value: String(new URL(base).port || 443) });
  check("the main port is refused as the realm's port", function () {
    assert.notStrictEqual(refused.status, 200, refused.text.slice(0, 200));
  });
  await ok("POST", base + "/admin-api/realms/set",
           { id: REALM, key: "listener.port", value: String(PORT) },
           "gave it port " + PORT);

  log.info("== 2. The realm on its own port");
  const discovery = OWN_BASE + "/realm/" + REALM +
                    "/.well-known/openid-configuration";
  let got = null;
  for (let i = 0; i < 60; i += 1) {
    got = await request("GET", discovery);
    if (got.status === 200) {
      break;
    }
    await new Promise(function (r) { setTimeout(r, 1000); });
  }
  check("the realm's discovery document on its own port, over a " +
        "certificate that verifies for " + HOST + ", names its own base " +
        "and prefix", function () {
    assert.strictEqual(got.status, 200, discovery + " answered " +
                       (got.status || got.error) + " " +
                       got.text.slice(0, 200));
    assert.strictEqual(got.json.issuer, OWN_BASE + "/realm/" + REALM);
  });

  log.info("== 3. Only that realm there");
  const dflt = await request("GET", OWN_BASE +
                             "/.well-known/openid-configuration");
  check("the default realm's path is 404 on the realm's port", function () {
    assert.strictEqual(dflt.status, 404, dflt.status + " " +
                       dflt.text.slice(0, 200));
    assert.ok(/serves realm/.test(dflt.text), dflt.text.slice(0, 200));
  });

  log.info("== 4. The same issuer through the main port");
  const main1 = await request("GET", base + "/realm/" + REALM +
                              "/.well-known/openid-configuration");
  check("read through the main port, the realm names the same issuer, on " +
        "its own base", function () {
    assert.strictEqual(main1.status, 200, main1.text.slice(0, 200));
    assert.strictEqual(main1.json.issuer, OWN_BASE + "/realm/" + REALM);
  });

  log.info("== 5. GET /admin-api/realms");
  const after = await ok("GET", base + "/admin-api/realms", undefined,
                         "listing the realms again");
  const mine = realmRows(after.json).filter(function (row) {
    return row.id === REALM;
  })[0];
  check("the realm reports its listener and its base", function () {
    assert.ok(mine && mine.listener, JSON.stringify(mine).slice(0, 300));
    assert.strictEqual(mine.listener.configured, true);
    assert.strictEqual(mine.listener.port, PORT);
    assert.strictEqual(mine.baseUrl, OWN_BASE + "/realm/" + REALM);
  });

  if (EXPECTED_NODES > 1) {
    log.info("== 6. Both nodes answer on the realm's port");
    const nodes = new Set();
    for (let i = 0; i < 16 && nodes.size < 2; i += 1) {
      const r = await request("GET", OWN_BASE + "/realm/" + REALM +
                              "/admin-api/cluster");
      const self = r.json && r.json.status && r.json.status.self;
      if (self) {
        nodes.add(String(self.name || self.nodeId));
      }
      await new Promise(function (res) { setTimeout(res, 20); });
    }
    check("both nodes answer on the realm's own port", function () {
      assert.ok(nodes.size >= 2, "answered by " +
                Array.from(nodes).join(", "));
    });
  }
  log.info("sts_realm_listener passed: " + checks + " checks.");
  log.debug("Leaving main().");
}

main().then(function () {
  process.exit(0);
}, function (e) {
  log.error("sts_realm_listener FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
