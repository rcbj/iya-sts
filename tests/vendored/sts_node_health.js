// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: sts_node_health.js
//
// ===========================================================================
// MONITORING → NODE HEALTH OVER HTTP, IN EVERY MODE (#329, 2026-09-28).
//
// `tests/node_health_page.js` holds the arithmetic and the unavailable
// sources on a cgroup it writes itself. This job holds the RUNNING service —
// a real container with a real cgroup — to the two surfaces an operator uses,
// `/admin/node-health` and `GET /admin-api/node-health`, in `memory`,
// `single-node` (request workers on) and `cluster`:
//
//   1. THE API answers the container's CPU and memory — each either read,
//      with its figures in range, or unavailable with a sentence and no
//      figure — and a row per process with `process.memoryUsage()`'s five
//      figures for every Node.js process that reports one, the front process
//      first; a row per request or hosted-surface worker THREAD (#364) with
//      its own heap and no resident size or CPU time, which are the
//      process's; and totals that are the sum of the rows, the resident one
//      over processes alone; the debugger's api child, where it runs, with
//      its own figures (answering through its preload) or the reason it has
//      none (#329; the post-quantum children went with their pool in #363);
//   2. IT IS THE FRONT PROCESS THAT ANSWERS, AND IT LISTS THE WORKERS: every
//      worker thread `/admin-api/worker-pools` lists, by its threadId, is a
//      row or is listed as unanswered — on one node, where both reads reach
//      the same front process;
//   3. THE PAGE draws the sections, and its `?format=json` names the same
//      front process (on one node);
//   4. A REALM'S OWN TOKEN is refused it (403): the container is the
//      process's.
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
const log = bunyan.createLogger({ name: "sts_node_health",
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
const REALM = "health-" + STAMP;
const MEMORY_FIGURES = ["rssBytes", "heapUsedBytes", "heapTotalBytes",
                        "externalBytes", "arrayBuffersBytes"];

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

function isCount(n) {
  log.debug("Entering isCount().");
  log.debug("Leaving isCount().");
  return typeof n === "number" && isFinite(n) && n >= 0;
}

async function theApiAnswers() {
  log.debug("Entering theApiAnswers().");
  log.info("=== 1. GET /admin-api/node-health: the container and its " +
           "processes ===");
  const r = await api("GET", "/admin-api/node-health");
  check("it answers 200", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
  });
  const body = r.body;
  check("scoped to the node, naming the process and the node", function () {
    assert.strictEqual(body.scope, "node");
    assert.ok(Number(body.pid) > 0 && body.node && !("host" in body) &&
              body.scopeText,
              JSON.stringify(body).slice(0, 300));
  });
  check("the CPU is read or said to be unavailable (" +
        (body.cpu.available ? body.cpu.utilisationPercent + " %"
                            : "unavailable") + ")", function () {
    const cpu = body.cpu;
    if (!cpu.available) {
      assert.ok(cpu.unavailableText && !("utilisationPercent" in cpu),
                JSON.stringify(cpu));
      return;
    }
    assert.ok(isCount(cpu.utilisationPercent) && isCount(cpu.coresUsed) &&
              cpu.percentOfVcpus > 0 && cpu.windowSeconds > 0 &&
              cpu.limitText, JSON.stringify(cpu));
    assert.ok(cpu.limitVcpus === null || cpu.limitVcpus > 0,
              JSON.stringify(cpu));
  });
  check("the memory is read or said to be unavailable (" +
        (body.memory.available ? body.memory.currentBytes + " bytes"
                               : "unavailable") + ")", function () {
    const m = body.memory;
    if (!m.available) {
      assert.ok(m.unavailableText && !("currentBytes" in m),
                JSON.stringify(m));
      return;
    }
    assert.ok(m.currentBytes > 0 && m.limitText, JSON.stringify(m));
    if (m.limitBytes !== null) {
      assert.ok(m.limitBytes > 0 && isCount(m.utilisationPercent),
                JSON.stringify(m));
    } else {
      assert.strictEqual(m.utilisationPercent, null, JSON.stringify(m));
    }
  });
  const p = body.processes;
  check("a row per process, the front process first, each Node.js process " +
        "with its five figures, each worker thread with its heap", function () {
    assert.ok(p.rows.length >= 1, JSON.stringify(p));
    assert.strictEqual(p.rows[0].role, "front process");
    assert.strictEqual(p.rows[0].pid, body.pid);
    p.rows.forEach(function (row) {
      if (row.kind === "thread") {
        // A worker THREAD of the front process (#364): its resident size
        // and CPU time are the process's, on the front row, and not here.
        assert.ok(row.pid === body.pid && isCount(row.threadId) &&
                  row.rssBytes === null && row.cpuUserSeconds === null &&
                  row.heapUsedBytes > 0 &&
                  /worker thread \d+$/.test(row.role), JSON.stringify(row));
        return;
      }
      if (row.source === "process.memoryUsage()") {
        MEMORY_FIGURES.forEach(function (name) {
          assert.ok(isCount(row[name]), row.pid + " " + name + " is " +
                    JSON.stringify(row[name]));
        });
        assert.ok(row.rssBytes > 0 && row.heapUsedBytes > 0,
                  JSON.stringify(row));
      } else {
        assert.ok(/^\/proc\//.test(row.source) &&
                  row.heapUsedBytes === null &&
                  (isCount(row.rssBytes) || row.unreadable),
                  JSON.stringify(row));
      }
    });
  });
  const children = p.rows.filter(function (row) {
    return /^protocol debugger api$/.test(row.role);
  });
  check("each of the " + children.length + " child process(es) reports its " +
        "own memory, or says why it did not", function () {
    children.forEach(function (row) {
      assert.ok(row.source === "process.memoryUsage()" || row.notReported,
                JSON.stringify(row));
    });
  });
  const dbg = children.filter(function (row) {
    return row.role === "protocol debugger api";
  })[0];
  if (dbg) {
    check("the debugger's api child answers through its preload (" +
          dbg.pid + ")", function () {
      assert.strictEqual(dbg.source, "process.memoryUsage()",
                         JSON.stringify(dbg));
      assert.ok(dbg.heapUsedBytes > 0, JSON.stringify(dbg));
    });
  } else {
    log.info("  (no debugger api child on this node, so its row is not " +
             "checked)");
  }
  check("the totals are the sum of the rows", function () {
    const rss = p.rows.reduce(function (n, row) {
      return n + (typeof row.rssBytes === "number" ? row.rssBytes : 0);
    }, 0);
    const heap = p.rows.reduce(function (n, row) {
      return n + (typeof row.heapUsedBytes === "number" ? row.heapUsedBytes
                                                         : 0);
    }, 0);
    const threads = p.rows.filter(function (row) {
      return row.kind === "thread";
    }).length;
    assert.strictEqual(p.totals.rows, p.rows.length);
    assert.strictEqual(p.totals.workerThreads, threads);
    assert.strictEqual(p.totals.processes, p.rows.length - threads);
    assert.strictEqual(p.totals.rssBytes, rss);
    assert.strictEqual(p.totals.heapUsedBytes, heap);
  });
  check("the ECS endpoint is cross-checked or said to be absent", function () {
    assert.ok(body.ecs.available === true || body.ecs.unavailableText,
              JSON.stringify(body.ecs));
  });
  check("the machine's figures are labelled as not the container's",
        function () {
          assert.ok(/NOT the container/.test(body.machine.text),
                    JSON.stringify(body.machine));
        });
  log.debug("Leaving theApiAnswers().");
  return body;
}

async function everyWorkerIsListed(body) {
  log.debug("Entering everyWorkerIsListed().");
  log.info("=== 2. the front process drew it, and lists every worker ===");
  if (EXPECTED_NODES > 1) {
    log.info("  (a cluster: two reads may reach two front processes, so " +
             "the workers are not compared)");
    log.debug("Leaving everyWorkerIsListed(). A cluster.");
    return;
  }
  const pools = await api("GET", "/admin-api/worker-pools");
  assert.strictEqual(pools.status, 200, pools.text.slice(0, 300));
  check("the same front process answers both", function () {
    assert.strictEqual(pools.body.pid, body.pid);
  });
  // BY threadId (#364): every worker thread shares the front's pid.
  const listed = body.processes.rows.filter(function (row) {
    return row.kind === "thread";
  }).map(function (row) {
    return row.threadId;
  }).concat(body.processes.unanswered.map(function (u) {
    return u.threadId;
  }));
  const workers = [];
  (pools.body.pools || []).forEach(function (pool) {
    (pool.workers || []).forEach(function (w) {
      if (w.ready) {
        workers.push(w.threadId);
      }
    });
  });
  check("each of the " + workers.length + " ready worker thread(s) is a " +
        "row or unanswered", function () {
    workers.forEach(function (threadId) {
      assert.ok(listed.indexOf(threadId) >= 0, threadId + " not in " +
                JSON.stringify(listed));
    });
  });
  log.debug("Leaving everyWorkerIsListed().");
}

async function thePageAgrees(cookie, body) {
  log.debug("Entering thePageAgrees().");
  log.info("=== 3. /admin/node-health draws the same node ===");
  const page = await call("GET", base + "/admin/node-health",
                          { headers: { Cookie: cookie } });
  check("the page answers 200 and draws each section", function () {
    assert.strictEqual(page.status, 200, page.text.slice(0, 300));
    ["cpu", "memory", "processes", "ecs", "machine"].forEach(
      function (anchor) {
        assert.ok(page.text.indexOf('id="' + anchor + '"') >= 0, anchor);
      });
  });
  const json = await call("GET", base + "/admin/node-health?format=json",
                          { headers: { Cookie: cookie } });
  check("its ?format=json answers the same view", function () {
    assert.strictEqual(json.status, 200, json.text.slice(0, 300));
    assert.strictEqual(json.body.scope, "node");
    assert.ok(json.body.processes && json.body.cpu && json.body.memory,
              json.text.slice(0, 300));
    if (EXPECTED_NODES < 2) {
      assert.strictEqual(json.body.pid, body.pid);
      assert.strictEqual(json.body.cgroup, body.cgroup);
    }
  });
  log.debug("Leaving thePageAgrees().");
}

async function aRealmTokenIsRefused() {
  log.debug("Entering aRealmTokenIsRefused().");
  log.info("=== 4. a realm's own token is refused ===");
  const made = await api("POST", "/admin-api/realms/create",
                         { id: REALM, domain: REALM + ".example.net",
                           name: "Node health test " + STAMP });
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
  const refused = await call("GET", base + R + "/admin-api/node-health",
                             { headers: { Authorization: "Bearer " +
                                                         token } });
  check("GET /admin-api/node-health with the realm's token is 403",
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
  let r = await api("GET", "/admin-api/node-health");
  const until = Date.now() + 60000;
  while (EXPECTED_NODES > 1 && Date.now() < until &&
         (r.body.nodes || []).filter(function (n) {
           return n.state === "live" && n.view;
         }).length < EXPECTED_NODES) {
    await new Promise(function (resolve) {
      setTimeout(resolve, 3000);
    });
    r = await api("GET", "/admin-api/node-health");
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
    const one = await api("GET", "/admin-api/node-health?node=" +
                                        encodeURIComponent(n.name));
    check("?node=" + n.name + " answers that node alone", function () {
      assert.strictEqual(one.status, 200, one.text.slice(0, 200));
      assert.strictEqual(one.body.node, n.name);
      assert.strictEqual(one.body.nodes.length, 1);
    });
  }
  const none = await api("GET", "/admin-api/node-health?node=no-such-node-" +
                         STAMP);
  check("an unknown node is 404, with the names there are", function () {
    assert.strictEqual(none.status, 404, none.text.slice(0, 200));
    assert.ok(Array.isArray(none.body.nodes), none.text.slice(0, 200));
  });
  log.debug("Leaving everyNodeByName().");
}

async function main() {
  log.debug("Entering main().");
  const admin = "health-admin-" + STAMP;
  const cookie = await signin.signInToTheConsole(base, admin, log,
                                                 { grant: "read" });
  const body = await theApiAnswers();
  await everyWorkerIsListed(body);
  await thePageAgrees(cookie || "", body);
  await everyNodeByName();
  await aRealmTokenIsRefused();
  log.info("sts_node_health: " + checks + " check(s) passed.");
  log.debug("Leaving main().");
}

main().catch(function (e) {
  log.error("sts_node_health FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
