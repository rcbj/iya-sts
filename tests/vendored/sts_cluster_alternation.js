// File: sts_cluster_alternation.js
//
// ===========================================================================
// EVERY JOB IN THE `cluster` MODE REALLY TALKS TO BOTH NODES (2026-09-14,
// issue #46).
//
// The `cluster` mode (tests/tools/modes.sh) puts two nodes of this service
// behind an L4 load balancer that picks a node per CONNECTION, and preloads
// tests/tools/fresh-connections.js into every job so that each request opens
// one. **If either half silently stopped working the whole mode would still be
// green** — a balancer pinned to one node, a node that never joined, or a
// client that went back to keeping its connection alive all produce a suite
// that passes against ONE node while the report says two. This job is the one
// place that would go red.
//
// So it asks `GET /admin-api/cluster` — whose `status.self` is the answering
// node's own identity — many times in a row, through the SAME two kinds of
// client the other jobs use (`fetch()` and `https.request()` on the global
// agent), and asserts:
//
//   * in the `cluster` mode (`STS_TEST_CLUSTER_NODES=2`): every answer is
//     active-active, BOTH nodes answered through EACH client, neither took
//     fewer than a quarter of the requests, and the membership table lists both
//     nodes as live;
//   * in every other mode: ONE identity answered every request and the mode is
//     not active-active — so the job asserts what the launcher claims about the
//     stack in all four modes, rather than skipping in three.
//
// A QUARTER RATHER THAN STRICT ALTERNATION, because the suite is not the
// balancer's only client: the remote XACML PEP container polls through it
// every few seconds, and each of its connections takes a turn in the round
// robin. A pinned client gives every request to one node, so the bound still
// separates the two cases by a wide margin.
//
// ---------------------------------------------------------------------------
// WHY IT IS HERE, WHICH IS `tests/CLAUDE.md`'s FIRST QUESTION.
//
// `local: true`: it drives this repository's own `/admin-api`, and the thing
// it guards — the test stack's topology — exists only in this repository's
// launchers. It is FIRST in MANIFEST.js so that a mode which is not what it
// says is reported before an hour of jobs that would each be right about the
// wrong stack.
// ===========================================================================

const assert = require("assert");
const https = require("https");
const http = require("http");
const { Command, Option } = require("commander");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, for the reason tests/wait_for.js gives.
  appconfigProblem = e;
  appconfig = {};
}

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_cluster_alternation",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug('CONFIG_FILE could not be read, so the configuration is empty: ' +
            appconfigProblem.message);
}
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");
var api = base + "/admin-api";

// How many requests through each client. Twenty-four is enough that a quarter
// is six, and cheap: each is one read of a status snapshot.
var PER_CLIENT = Number(process.env.STS_CLUSTER_ALTERNATION_REQUESTS || 24);
var EXPECTED = Number(process.env.STS_TEST_CLUSTER_NODES || 1);
var PAUSE_MS = 20;

var checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function authorization() {
  log.debug("Entering authorization().");
  const token = process.env.STS_ADMIN_API_TOKEN || "";
  log.debug("Leaving authorization().");
  return token ? { authorization: "Bearer " + token } : {};
}

// The answering node, as it describes itself.
function identityOf(code, body, raw) {
  log.debug("Entering identityOf().");
  assert.strictEqual(code, 200,
    "GET /admin-api/cluster answered " + code + " " +
    String(raw).slice(0, 200));
  const report = (body && body.status) || {};
  assert.ok(report.self, "GET /admin-api/cluster answered 200 with no " +
    "status.self: " + String(raw).slice(0, 200));
  const self = report.self;
  log.debug("Leaving identityOf().");
  return { nodeId: String(self.nodeId || ""), name: String(self.name || ""),
           mode: String(self.mode || ""), nodes: report.nodes,
           now: Number(report.databaseNow) || 0 };
}

async function viaFetch() {
  log.debug("Entering viaFetch().");
  const r = await fetch(api + "/cluster", { headers: authorization() });
  const raw = await r.text();
  let body = null;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in viaFetch(): " + ((e && e.message) || e));
    body = null;
  }
  log.debug("Leaving viaFetch().");
  return identityOf(r.status, body, raw);
}

// `https.request` and NOT `https.get`: node's `get` calls the module's own
// `request` function directly, so a client patched on `module.exports` — which
// is what both preloads do — is only exercised through `request`.
function viaRequest() {
  log.debug("Entering viaRequest().");
  const target = new URL(api + "/cluster");
  const mod = target.protocol === "https:" ? https : http;
  log.debug("Leaving viaRequest().");
  return new Promise(function (resolve, reject) {
    const req = mod.request({
      host: target.hostname, port: target.port, path: target.pathname,
      method: "GET", headers: authorization(), timeout: 30000
    }, function (res) {
      let raw = "";
      res.setEncoding("utf8");
      res.on("data", function (chunk) {
        raw += chunk;
      });
      res.on("end", function () {
        let body = null;
        try {
          body = JSON.parse(raw);
        } catch (e) {
          log.debug("Caught in a callback in viaRequest(): " +
                    ((e && e.message) || e));
          body = null;
        }
        try {
          resolve(identityOf(res.statusCode, body, raw));
        } catch (e) {
          log.debug("Caught in a callback in viaRequest(): " +
                    ((e && e.message) || e));
          reject(e);
        }
      });
    });
    req.on("timeout", function () {
      req.destroy(new Error("GET /admin-api/cluster timed out"));
    });
    req.on("error", reject);
    req.end();
  });
}

async function sample(label, once) {
  log.debug("Entering sample().");
  const answers = [];
  for (let i = 0; i < PER_CLIENT; i += 1) {
    answers.push(await once());
    // A PAUSE, WHICH IS WHAT MAKES THIS DISCRIMINATE. Back to back, undici's
    // pool sometimes opens a second connection before the first is returned
    // idle, and two pooled connections on two nodes alternate exactly like
    // fresh ones — the first mutation run of this job passed its fetch()
    // half with keep-alive back on for that reason. Twenty milliseconds lets
    // a connection go idle, so a keeping-alive client reuses it and pins.
    await new Promise(function (resolve) {
      setTimeout(resolve, PAUSE_MS);
    });
  }
  const counts = {};
  answers.forEach(function (a) {
    const key = a.name ? a.name + " (" + a.nodeId + ")" : a.nodeId || "(none)";
    counts[key] = (counts[key] || 0) + 1;
  });
  log.info(label + ": " + PER_CLIENT + " requests answered by " +
           JSON.stringify(counts) + "; sequence " +
           answers.map(function (a) {
             return a.name || a.nodeId.slice(0, 8) || "-";
           }).join(","));
  log.debug("Leaving sample().");
  return { answers: answers, counts: counts };
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving " + base + "; this stack is expected to have " + EXPECTED +
           " node(s).");

  const clients = [
    { label: "fetch()", once: viaFetch },
    { label: "https.request() on the global agent", once: viaRequest }
  ];
  let last = null;
  for (const client of clients) {
    const s = await sample(client.label, client.once);
    last = s;
    const ids = {};
    s.answers.forEach(function (a) {
      ids[a.nodeId] = (ids[a.nodeId] || 0) + 1;
    });
    const distinct = Object.keys(ids);
    if (EXPECTED >= 2) {
      check(client.label + ": every answer is from an active-active node",
            function () {
              const modes = s.answers.map(function (a) {
                return a.mode;
              }).filter(function (m, i, all) {
                return all.indexOf(m) === i;
              });
              assert.deepStrictEqual(modes, ["active-active"],
                "the modes answered were " + JSON.stringify(modes));
            });
      check(client.label + ": " + EXPECTED + " different nodes answered — " +
            "the balancer spreads connections AND this client opens a new " +
            "one per request", function () {
              assert.strictEqual(distinct.length, EXPECTED,
                distinct.length + " node(s) answered " + PER_CLIENT +
                " requests: " + JSON.stringify(s.counts) + ". ONE means " +
                "every request rode one connection (keep-alive is back: see " +
                "tests/tools/fresh-connections.js) or the balancer has one " +
                "server up (see the sts-lb log).");
              assert.ok(distinct.indexOf("") < 0,
                "a node answered with no node id: it has not joined");
            });
      check(client.label + ": and no node took fewer than a quarter of them",
            function () {
              distinct.forEach(function (id) {
                assert.ok(ids[id] >= Math.floor(PER_CLIENT / 4),
                  "node " + id + " answered " + ids[id] + " of " +
                  PER_CLIENT + ": " + JSON.stringify(s.counts));
              });
            });
    } else {
      check(client.label + ": one identity answered every request, and it " +
            "is not an active-active node", function () {
              assert.strictEqual(distinct.length, 1,
                "this stack is not a cluster and yet " + distinct.length +
                " node identities answered: " + JSON.stringify(s.counts));
              s.answers.forEach(function (a) {
                assert.notStrictEqual(a.mode, "active-active",
                  "an active-active node answered in a mode that is not " +
                  "the cluster mode");
              });
            });
    }
  }

  if (EXPECTED >= 2) {
    check("and the membership table lists every node that answered as live " +
          "by the database's clock", function () {
            const answer = last.answers[last.answers.length - 1];
            // Live is the membership rule itself (cluster/CLAUDE.md): a row
            // whose lifetime has not passed by the DATABASE's clock and that
            // has not left.
            const live = (answer.nodes || []).filter(function (n) {
              return n && !n.leftAt && n.expiresAt > answer.now;
            }).map(function (n) {
              return n.nodeId;
            });
            const answered = last.answers.map(function (a) {
              return a.nodeId;
            }).filter(function (id, i, all) {
              return all.indexOf(id) === i;
            });
            answered.forEach(function (id) {
              assert.ok(live.indexOf(id) >= 0,
                "node " + id + " answered and is not a live member: " +
                JSON.stringify(answer.nodes).slice(0, 400));
            });
            assert.ok(live.length >= EXPECTED,
              live.length + " live member(s), " + EXPECTED + " expected");
          });
  }

  const floor = EXPECTED >= 2 ? 7 : 2;
  assert.ok(checks >= floor,
    "only " + checks + " checks ran (" + floor + " expected); a section has " +
    "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_cluster_alternation")
  .description("in the cluster mode every job's requests reach both nodes " +
      "behind the load balancer, through fetch() and through " +
      "https.request(); " +
      "in every other mode one node answers them all.")
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
