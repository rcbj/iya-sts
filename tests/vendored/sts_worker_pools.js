// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: sts_worker_pools.js
//
// ===========================================================================
// MONITORING → WORKER POOLS OVER HTTP, IN EVERY MODE (#327, 2026-09-28).
//
// `tests/worker_pools_page.js` holds the pools' counters and the page's
// states in process. This job holds the RUNNING service to them through the
// two surfaces an operator uses — `/admin/worker-pools` and
// `GET /admin-api/worker-pools` — in `memory` (both request pools off),
// `single-node` (request workers on) and `cluster`:
//
//   1. THE API answers two pools — request and surface — each with the
//      seven figures #327 asked for, and a figure set that adds up: busy
//      and free are the ready workers, no pool holds more than its maximum,
//      and a pool that is off says so in a sentence. There is no third,
//      post-quantum pool since #363: post-quantum signing and scrypt run on
//      libuv's thread pool inside each process;
//   2. IT IS THE FRONT PROCESS THAT ANSWERS: the report was drawn on the
//      front process's MAIN thread (`mainThread`), and every worker it lists
//      is a thread named by its threadId (#364) — a worker answering would
//      have reported every request pool off. It compared the answering pid
//      with the workers' until #364, which every thread now shares;
//   3. THE PAGE draws the same two pools, and its `?format=json` agrees
//      with the API on each pool's state and maximum;
//   4. A REALM'S OWN TOKEN is refused it (403): the pools are the process's.
//
// `local: true` (tests/vendored/MANIFEST.js): it drives this repository's own
// `/admin` and `/admin-api`, which is tests/CLAUDE.md's first question.
// ===========================================================================

const assert = require("assert");

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

const bunyan = require("bunyan");
const log = bunyan.createLogger({ name: "sts_worker_pools",
                                  level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}
const signin = require("./console_signin");

const stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
const base = String(process.env.OID4VCI_ISSUER_URL ||
                    stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const EXPECTED_NODES = Number(process.env.STS_TEST_CLUSTER_NODES || 1);
const STAMP = Date.now().toString(36);
const REALM = "pools-" + STAMP;
const POOL_IDS = ["request", "surface"];
const FIGURES = ["currentWorkers", "busyWorkers", "freeWorkers",
                 "maxWorkers", "initialWorkers"];

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  ✓ " + what);
  log.debug("Leaving check().");
}

// One request, no redirect followed, the body read both ways.
async function call(method, url, options) {
  log.debug("Entering call(). " + method + " " + url);
  const opts = Object.assign({ method: method, redirect: "manual" },
                             options || {});
  const r = await fetch(url, opts);
  const text = await r.text();
  let body = null;
  try {
    body = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in call(): " + ((e && e.message) || e));
    // Not JSON — a page or an empty body. The text is kept.
    body = null;
  }
  log.debug("Leaving call(). status=" + r.status);
  return { status: r.status, body: body, text: text };
}

// The management API with the run's token, which the preload attaches.
async function api(method, path, payload) {
  log.debug("Entering api(). " + method + " " + path);
  const options = payload === undefined ? {}
    : { headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload) };
  const reply = await call(method, base + path, options);
  log.debug("Leaving api().");
  return reply;
}

function poolOf(body, id) {
  log.debug("Entering poolOf().");
  log.debug("Leaving poolOf().");
  return ((body && body.pools) || []).filter(function (one) {
    return one.id === id;
  })[0];
}

async function theApiAnswersTwoPools() {
  log.debug("Entering theApiAnswersTwoPools().");
  log.info("=== 1. GET /admin-api/worker-pools: two pools, seven " +
           "figures ===");
  const r = await api("GET", "/admin-api/worker-pools");
  check("it answers 200", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
  });
  const body = r.body;
  check("scoped to the node, naming the process and the node", function () {
    assert.strictEqual(body.scope, "node");
    assert.ok(Number(body.pid) > 0 && body.node && !("host" in body),
              JSON.stringify(body).slice(0, 300));
  });
  check("and there are exactly the two pools, none post-quantum (#363)",
        function () {
          assert.deepStrictEqual((body.pools || []).map(function (one) {
            return one.id;
          }), POOL_IDS);
        });
  POOL_IDS.forEach(function (id) {
    const p = poolOf(body, id);
    check("the " + id + " pool carries the figures", function () {
      assert.ok(p, "no " + id + " pool: " + r.text.slice(0, 300));
      FIGURES.forEach(function (name) {
        assert.ok(typeof p[name] === "number" && p[name] >= 0,
                  name + " is " + JSON.stringify(p[name]));
      });
      assert.ok(p.restarts && typeof p.restarts.crashed === "number" &&
                typeof p.restarts.failedStarts === "number",
                JSON.stringify(p.restarts));
      assert.ok(p.responseTime && ("averageMs" in p.responseTime),
                JSON.stringify(p.responseTime));
      assert.ok(typeof p.state === "string" && p.stateText,
                JSON.stringify(p));
    });
    check("and they add up for the " + id + " pool (" + p.state + ")",
          function () {
            if (p.state === "off") {
              assert.ok(/^Off:/.test(p.stateText), p.stateText);
              return;
            }
            assert.ok(p.currentWorkers <= p.maxWorkers, JSON.stringify(p));
            assert.strictEqual(p.busyWorkers + p.freeWorkers,
                               p.readyWorkers, JSON.stringify(p));
          });
  });
  log.debug("Leaving theApiAnswersTwoPools().");
  return body;
}

function theFrontProcessAnswered(body) {
  log.debug("Entering theFrontProcessAnswered().");
  log.info("=== 2. the front process drew it ===");
  const workers = [];
  ["request", "surface"].forEach(function (id) {
    (poolOf(body, id).workers || []).forEach(function (w) {
      workers.push(w);
    });
  });
  check("it was drawn on the front process's main thread (pid " + body.pid +
        ")", function () {
    assert.strictEqual(body.mainThread, true,
                       JSON.stringify(body).slice(0, 300));
  });
  check("and each of the " + workers.length + " worker(s) it lists is a " +
        "thread, by its threadId", function () {
    workers.forEach(function (w) {
      assert.ok(Number(w.threadId) > 0 && !("pid" in w), JSON.stringify(w));
    });
  });
  log.debug("Leaving theFrontProcessAnswered().");
}

async function thePageAgrees(cookie, body) {
  log.debug("Entering thePageAgrees().");
  log.info("=== 3. /admin/worker-pools draws the same pools ===");
  const page = await call("GET", base + "/admin/worker-pools",
                          { headers: { Cookie: cookie } });
  check("the page answers 200 and draws each pool", function () {
    assert.strictEqual(page.status, 200, page.text.slice(0, 300));
    ["pool-request", "pool-surface"].forEach(function (anchor) {
      assert.ok(page.text.indexOf('id="' + anchor + '"') >= 0, anchor);
    });
    assert.ok(page.text.indexOf('id="pool-post-quantum"') < 0,
              "a post-quantum pool is still drawn");
  });
  const json = await call("GET", base + "/admin/worker-pools?format=json",
                          { headers: { Cookie: cookie } });
  check("its ?format=json agrees with the API on each pool's state and " +
        "maximum", function () {
    assert.strictEqual(json.status, 200, json.text.slice(0, 300));
    POOL_IDS.forEach(function (id) {
      const a = poolOf(body, id);
      const b = poolOf(json.body, id);
      assert.ok(b, "no " + id + " pool on the page");
      assert.strictEqual(b.maxWorkers, a.maxWorkers, id);
      if (EXPECTED_NODES < 2) {
        // One node: the same front process answered both, and a request
        // pool's state does not move between two reads.
        assert.strictEqual(b.state, a.state, id);
      }
    });
  });
  log.debug("Leaving thePageAgrees().");
}

async function aRealmTokenIsRefused() {
  log.debug("Entering aRealmTokenIsRefused().");
  log.info("=== 4. a realm's own token is refused ===");
  const made = await api("POST", "/admin-api/realms/create",
                         { id: REALM, domain: REALM + ".example.net",
                           name: "Worker pools test " + STAMP });
  assert.ok(made.status === 200, "precondition: creating " + REALM +
            " answered " + made.status + " " + made.text.slice(0, 300));
  const R = "/realm/" + REALM;
  const regenerated = await api("POST", R +
    "/admin-api/applications/regenerate-secret",
    { application: "sts-management-api" });
  const secret = regenerated.body && regenerated.body.clientSecret;
  assert.ok(secret, "precondition: regenerating the realm's " +
    "sts-management-api secret answered " + regenerated.status);
  const minted = await call("POST", base + R + "/oauth2/token", {
    headers: { "Content-Type": "application/x-www-form-urlencoded",
               Authorization: "Basic " +
                 Buffer.from("sts-management-api:" + secret)
                   .toString("base64") },
    body: new URLSearchParams({ grant_type: "client_credentials",
                                scope: "admin:read admin:write",
                                resource: base + R + "/admin-api" })
      .toString()
  });
  const token = minted.body && minted.body.access_token;
  assert.ok(token, "precondition: the realm's token endpoint answered " +
            minted.status + " " + minted.text.slice(0, 200));
  const refused = await call("GET", base + R + "/admin-api/worker-pools",
                             { headers: { Authorization: "Bearer " +
                                                         token } });
  check("GET /admin-api/worker-pools with the realm's token is 403",
        function () {
          assert.strictEqual(refused.status, 403, refused.text.slice(0, 300));
        });
  log.debug("Leaving aRealmTokenIsRefused().");
}

// ---------------------------------------------------------------------------
// EVERY NODE, BY NAME (#332): in memory mode one section and a sentence
// saying there is no cluster; in the cluster mode a section per node, each
// live once its snapshot has been written (within 15 s of its start, so this
// waits up to a minute), and ?node= answering each one. Never an address.
// ---------------------------------------------------------------------------
const IPV4 = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;

async function everyNodeByName() {
  log.debug("Entering everyNodeByName().");
  log.info("=== 5. every node, by name (#332) ===");
  let r = await api("GET", "/admin-api/worker-pools");
  const until = Date.now() + 60000;
  while (EXPECTED_NODES > 1 && Date.now() < until &&
         (r.body.nodes || []).filter(function (n) {
           return n.state === "live" && n.view;
         }).length < EXPECTED_NODES) {
    await new Promise(function (resolve) {
      setTimeout(resolve, 3000);
    });
    r = await api("GET", "/admin-api/worker-pools");
  }
  const body = r.body;
  const nodes = body.nodes || [];
  check("the answer names its nodes and carries no address (" +
        nodes.map(function (n) {
          return n.name + ":" + n.state;
        }).join(", ") + ")", function () {
    assert.ok(nodes.length >= 1 && nodes[0].self && nodes[0].state === "live",
              JSON.stringify(nodes).slice(0, 300));
    assert.ok(!IPV4.test(r.text) && !/"host"/.test(r.text),
              "an address or a host in the answer");
    assert.ok(body.answeredBy && body.answeredBy.node === body.node,
              JSON.stringify(body.answeredBy));
    assert.ok(body.totals && body.cluster, JSON.stringify(body.cluster));
  });
  if (EXPECTED_NODES < 2) {
    check("one node, and the page says there is no cluster", function () {
      assert.strictEqual(nodes.length, 1);
      assert.strictEqual(body.cluster.clustered, false);
      assert.ok(/no cluster/.test(body.cluster.text), body.cluster.text);
    });
  } else {
    check("every one of the " + EXPECTED_NODES + " nodes is live, with its " +
          "own view", function () {
      assert.strictEqual(body.cluster.clustered, true,
                         JSON.stringify(body.cluster));
      assert.ok(nodes.filter(function (n) {
        return n.state === "live" && n.view;
      }).length >= EXPECTED_NODES, JSON.stringify(nodes.map(function (n) {
        return [n.name, n.state, n.ageSeconds];
      })));
      assert.strictEqual(body.totals.nodesCounted, nodes.filter(function (n) {
        return n.state !== "gone" && n.view;
      }).length);
    });
  }
  for (const n of nodes) {
    const one = await api("GET", "/admin-api/worker-pools?node=" +
                                        encodeURIComponent(n.name));
    check("?node=" + n.name + " answers that node alone", function () {
      assert.strictEqual(one.status, 200, one.text.slice(0, 200));
      assert.strictEqual(one.body.node, n.name);
      assert.strictEqual(one.body.nodes.length, 1);
    });
  }
  const none = await api("GET", "/admin-api/worker-pools?node=no-such-node-" +
                         STAMP);
  check("an unknown node is 404, with the names there are", function () {
    assert.strictEqual(none.status, 404, none.text.slice(0, 200));
    assert.ok(Array.isArray(none.body.nodes), none.text.slice(0, 200));
  });
  log.debug("Leaving everyNodeByName().");
}

async function main() {
  log.debug("Entering main().");
  const admin = "pools-admin-" + STAMP;
  const cookie = await signin.signInToTheConsole(base, admin, log,
                                                 { grant: "read" });
  const body = await theApiAnswersTwoPools();
  theFrontProcessAnswered(body);
  await thePageAgrees(cookie || "", body);
  await everyNodeByName();
  await aRealmTokenIsRefused();
  log.info("sts_worker_pools: " + checks + " check(s) passed.");
  log.debug("Leaving main().");
}

main().catch(function (e) {
  log.error("sts_worker_pools FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
