// File: sts_scheduler.js
//
// ===========================================================================
// THE SCHEDULER OVER HTTP, IN EVERY MODE (#49, 2026-09-22) — the plan's T5.
//
// `tests/scheduler.js` and `tests/scheduler_cluster.js` hold the scheduler
// to its promises in process. This job holds the RUNNING service to them,
// through the two surfaces an operator uses — Monitoring → Scheduler
// (`/admin/scheduler`) and `GET /admin-api/scheduler` — in `memory`,
// `single-node` and `cluster`:
//
//   1. THE PAGE AND THE API AGREE: every job the API lists is a row on the
//      page, by id, the two P1 jobs and the scheduler's own history job among
//      them, and each job's `nextRunAt` is the same to the second;
//   2. A LEADER IS NAMED and it ticks;
//   3. RUN NOW, through the API and through the console's form: the run is
//      queued, then succeeded, on a named node — and an unknown job is 404;
//   4. ADMIN READ RUNS NOTHING: a console session holding only Admin Read is
//      refused the form;
//   5. A REALM'S OWN TOKEN is confined: its view names the realm and shows the
//      service jobs read-only, and Run now on a service job is refused 403;
//   6. IN THE `cluster` MODE (`STS_TEST_CLUSTER_NODES=2`): asked through the
//      balancer, BOTH nodes answer and name the same leader and the same
//      `nextRunAt`; a STEP-DOWN hands the scheduler to the other node; and
//      every slot of the session-expiry job is one run however many nodes
//      could have run it. In every other mode a step-down is refused
//      (STS-SCHED-0010): there is nobody to hand to.
//
// No sleep waits for a job: each wait is a bounded poll on the condition, at
// the tick the service runs at (`scheduler.tickS`).
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
const log = bunyan.createLogger({ name: "sts_scheduler",
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
const REALM = "sched-" + STAMP;

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
  return { status: r.status, body: body, text: text,
           location: r.headers.get("location") || "" };
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

// The management API with a token this file chose.
async function apiAs(token, method, path, payload) {
  log.debug("Entering apiAs(). " + method + " " + path);
  const headers = { Authorization: "Bearer " + token };
  const options = { headers: headers };
  if (payload !== undefined) {
    headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(payload);
  }
  const reply = await call(method, base + path, options);
  log.debug("Leaving apiAs().");
  return reply;
}

// EVERY PAGE OF JOBS (2026-09-23). The job list is paged on `jobsPage`, and
// a REALM job has a row per realm — so once the suite has made enough realms
// the 200 rows of page one no longer hold `scheduler.history`, and jobOf()
// answered null for a job the service was running (cluster mode, job 334).
// A claim about what the list CONTAINS is a claim about the whole list.
async function report(prefix) {
  log.debug("Entering report().");
  const path = (prefix || "") + "/admin-api/scheduler?per=200";
  const r = await api("GET", path);
  assert.strictEqual(r.status, 200, "GET /admin-api/scheduler answered " +
                     r.status + " " + r.text.slice(0, 300));
  const body = r.body;
  const pages = Number((body.jobsPaging || {}).pages) || 1;
  for (let page = 2; page <= pages; page++) {
    const more = await api("GET", path + "&jobsPage=" + page);
    assert.strictEqual(more.status, 200, "GET /admin-api/scheduler page " +
                       page + " answered " + more.status);
    body.jobs = (body.jobs || []).concat(more.body.jobs || []);
  }
  log.debug("Leaving report().");
  return body;
}

// Polls `fn` until it answers something truthy, at the service's own tick,
// for at most `limitMs`. The condition, not the clock, ends the wait.
async function until(what, fn, limitMs) {
  log.debug("Entering until(). " + what);
  const deadline = Date.now() + (limitMs || 90000);
  for (;;) {
    const got = await fn();
    if (got) {
      log.debug("Leaving until(). Met.");
      return got;
    }
    if (Date.now() > deadline) {
      log.debug("Leaving until(). Timed out.");
      assert.fail("timed out waiting for " + what);
    }
    await new Promise(function (resolve) { setTimeout(resolve, 500); });
  }
}

function jobOf(json, id, realm) {
  log.debug("Entering jobOf().");
  log.debug("Leaving jobOf().");
  return (json.jobs || []).filter(function (j) {
    return j.id === id && (!realm || j.realm === realm);
  })[0] || null;
}

// A console form post, with the CSRF token taken off the page it posts to.
async function consolePost(cookie, path, form) {
  log.debug("Entering consolePost(). " + path);
  const drawn = await call("GET", base + path, { headers: { Cookie: cookie } });
  const csrf = (drawn.text.match(/name="csrf_token" value="([^"]+)"/) ||
                [])[1] || "";
  assert.ok(csrf, "precondition: " + path + " drawn for this session should " +
                  "carry a CSRF token; it answered " + drawn.status);
  const reply = await call("POST", base + path, {
    headers: { Cookie: cookie,
               "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(Object.assign({ csrf_token: csrf }, form))
      .toString()
  });
  log.debug("Leaving consolePost().");
  return reply;
}

// ---------------------------------------------------------------------------
async function thePageAndTheApiAgree(cookie) {
  log.debug("Entering thePageAndTheApiAgree().");
  log.info("=== 1. the page and the API list the same jobs ===");
  const json = await report();
  const pageJson = await call("GET", base + "/admin/scheduler?format=json" +
                              "&per=200", { headers: { Cookie: cookie } });
  // **`per=200` HERE TOO, AND IT IS THE POINT RATHER THAN A CONVENIENCE**
  // (2026-09-22). The jobs table is PAGED now — `admin-ui/CLAUDE.md`, *every
  // list that can grow without a bound is paged*; a REALM job has a row per
  // realm, so a service with fifty realms has fifty rows of each. The check
  // below asks for a row per job the API lists, so it has to ask for a page
  // big enough to hold them: without this it failed on `signing.rotate`,
  // which sorts onto the second page, about a page that was drawing exactly
  // what it should. The JSON fetch above already asks the same way.
  const html = await call("GET", base + "/admin/scheduler?per=200",
                          { headers: { Cookie: cookie } });
  const ids = json.jobs.map(function (j) { return j.id + "@" + j.realm; })
    .sort();
  check("the API lists the two jobs P1 moved and the scheduler's own",
        function () {
          ["authn.session-expiry", "pki.crl-directory-refresh",
           "scheduler.history"].forEach(function (id) {
            assert.ok(jobOf(json, id), id + " is not in " + ids.join(", "));
          });
        });
  check("the page's JSON lists exactly the same jobs", function () {
    assert.strictEqual(pageJson.status, 200, "it answered " + pageJson.status);
    const pageIds = pageJson.body.jobs.map(function (j) {
      return j.id + "@" + j.realm;
    }).sort();
    assert.deepStrictEqual(pageIds, ids);
  });
  check("and every job is a row of the drawn page, by id", function () {
    assert.strictEqual(html.status, 200, "it answered " + html.status);
    json.jobs.forEach(function (j) {
      assert.ok(html.text.indexOf('id="job-' + j.id + "-" + j.realm + '"') >= 0,
                j.id + " has no row on /admin/scheduler");
    });
  });
  check("each job's nextRunAt is the same on both, to the second",
        function () {
          json.jobs.forEach(function (j) {
            const other = jobOf(pageJson.body, j.id, j.realm);
            if (j.nextRunAt === null || other.nextRunAt === null) {
              assert.strictEqual(j.nextRunAt, other.nextRunAt, j.id);
              return;
            }
            const delta = Math.abs(Date.parse(j.nextRunAt) -
                                   Date.parse(other.nextRunAt));
            assert.ok(delta < 1000, j.id + ": " + j.nextRunAt + " and " +
                      other.nextRunAt);
          });
        });
  log.debug("Leaving thePageAndTheApiAgree().");
}

async function aLeaderTicks() {
  log.debug("Entering aLeaderTicks().");
  log.info("=== 2. a leader is named and ticks ===");
  const json = await until("a live leader", async function () {
    const r = await report();
    return r.leader && r.leader.known && r.leader.live ? r : null;
  });
  check("the scheduler has a live leader: " + json.leader.nodeName +
        " pid " + json.leader.pid, function () {
    assert.ok(json.leader.pid, JSON.stringify(json.leader));
  });
  check("the session-expiry job has run on its own schedule", function () {
    const job = jobOf(json, "authn.session-expiry");
    assert.ok(job.state === "off" || job.lastRun || job.running,
              JSON.stringify(job));
  });
  log.debug("Leaving aLeaderTicks().");
  return json;
}

async function runNow(cookie) {
  log.debug("Entering runNow().");
  log.info("=== 3. Run now, through the API and the console ===");
  const before = await report();
  const target = ["pki.crl-directory-refresh", "scheduler.history"]
    .filter(function (id) {
      const j = jobOf(before, id);
      return j && j.state === "enabled" && j.manual;
    })[0];
  assert.ok(target, "precondition: neither the CRL refresh nor the history " +
            "job can be run now: " + JSON.stringify(before.jobs));
  const queued = await api("POST", "/admin-api/scheduler/run", { job: target });
  check("POST /admin-api/scheduler/run queues a run of " + target + " (202)",
        function () {
          assert.strictEqual(queued.status, 202, queued.text.slice(0, 300));
          assert.ok(queued.body.runId, queued.text.slice(0, 300));
        });
  const done = await until("the queued run to finish", async function () {
    const r = await api("GET", "/admin-api/scheduler?run=" +
                        encodeURIComponent(queued.body.runId));
    const d = r.body && r.body.detail;
    return d && (d.state === "succeeded" || d.state === "failed") ? d : null;
  });
  check("the leader runs it: succeeded, manual, on a named node",
        function () {
          assert.strictEqual(done.state, "succeeded", JSON.stringify(done));
          assert.strictEqual(done.trigger, "manual");
          assert.ok(done.nodeName || done.host, JSON.stringify(done));
        });
  const viaConsole = await consolePost(cookie, "/admin/scheduler",
                                       { action: "run", job: target });
  // A form is answered as a form is: 303, to the run's own page.
  const consoleRunId = decodeURIComponent(
    (viaConsole.location.match(/[?&]run=([^&]+)/) || [])[1] || "");
  check("the console's Run now form queues one too, and lands on its run",
        function () {
          assert.strictEqual(viaConsole.status, 303,
                             viaConsole.text.slice(0, 300));
          assert.ok(consoleRunId, "the redirect was " + viaConsole.location);
        });
  await until("the console's run to finish", async function () {
    const r = await api("GET", "/admin-api/scheduler?run=" +
                        encodeURIComponent(consoleRunId));
    const d = r.body && r.body.detail;
    return d && d.state === "succeeded" ? d : null;
  });
  const unknown = await api("POST", "/admin-api/scheduler/run",
                            { job: "no.such-job" });
  check("an unknown job is refused 404", function () {
    assert.strictEqual(unknown.status, 404, unknown.text.slice(0, 300));
  });
  log.debug("Leaving runNow().");
}

async function adminReadRunsNothing() {
  log.debug("Entering adminReadRunsNothing().");
  log.info("=== 4. Admin Read runs nothing ===");
  const reader = "sched-read-" + STAMP;
  const cookie = await signin.signInToTheConsole(base, reader, log,
                                                 { grant: "read" });
  if (cookie === null) {
    log.info("  (the console gate is off in this stack; nothing to refuse)");
    log.debug("Leaving adminReadRunsNothing(). Gate off.");
    return;
  }
  const page = await call("GET", base + "/admin/scheduler",
                          { headers: { Cookie: cookie } });
  check("an Admin Read session reads the page", function () {
    assert.strictEqual(page.status, 200, "it answered " + page.status);
  });
  check("and is drawn no Run now button", function () {
    assert.ok(page.text.indexOf(">Run now</button>") < 0,
              "a Run now button is drawn for Admin Read");
  });
  const refused = await consolePost(cookie, "/admin/scheduler",
                                    { action: "run",
                                      job: "scheduler.history" });
  check("and its form post is refused", function () {
    assert.ok(refused.status === 403 ||
              (refused.status === 303 && /[?&]error=/.test(refused.location)),
              "it answered " + refused.status + " " + refused.location + " " +
              refused.text.slice(0, 200));
  });
  log.debug("Leaving adminReadRunsNothing().");
}

async function aRealmTokenIsConfined() {
  log.debug("Entering aRealmTokenIsConfined().");
  log.info("=== 5. a realm's own token is confined ===");
  const made = await api("POST", "/admin-api/realms/create",
                         { id: REALM, domain: REALM + ".example.net",
                           name: "Scheduler test " + STAMP });
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
  const view = await apiAs(token, "GET", R + "/admin-api/scheduler");
  check("the realm's token reads the scheduler, confined to its realm",
        function () {
          assert.strictEqual(view.status, 200, view.text.slice(0, 300));
          assert.strictEqual(view.body.confinedToRealm, REALM);
        });
  check("and sees the service jobs read-only", function () {
    const job = jobOf(view.body, "authn.session-expiry");
    assert.ok(job && job.readOnly, JSON.stringify(job));
  });
  const refused = await apiAs(token, "POST", R + "/admin-api/scheduler/run",
                              { job: "authn.session-expiry" });
  check("Run now on a service job is refused 403", function () {
    assert.strictEqual(refused.status, 403, refused.text.slice(0, 300));
  });
  const stepDown = await apiAs(token, "POST",
                               R + "/admin-api/scheduler/step-down", {});
  check("and so is a step-down", function () {
    assert.strictEqual(stepDown.status, 403, stepDown.text.slice(0, 300));
  });
  log.debug("Leaving aRealmTokenIsConfined().");
}

async function theClusterAgrees() {
  log.debug("Entering theClusterAgrees().");
  if (EXPECTED_NODES < 2) {
    log.info("=== 6. one node: a step-down has nobody to hand to ===");
    const refused = await api("POST", "/admin-api/scheduler/step-down", {});
    check("a step-down is refused, STS-SCHED-0010's answer", function () {
      assert.strictEqual(refused.status, 400, refused.text.slice(0, 300));
      assert.ok(/not clustered/.test(refused.text), refused.text);
    });
    log.debug("Leaving theClusterAgrees(). One node.");
    return;
  }
  log.info("=== 6. two nodes agree, and hand over ===");
  const seen = {};
  const answers = [];
  for (let i = 0; i < 16; i++) {
    const r = await report();
    seen[r.answeredBy.node] = true;
    answers.push(r);
  }
  check("both nodes answered through the balancer", function () {
    assert.strictEqual(Object.keys(seen).length, 2,
                       JSON.stringify(Object.keys(seen)));
  });
  check("and every answer names the same leader", function () {
    const leaders = answers.map(function (r) { return r.leader.node; })
      .filter(function (v, i, a) { return a.indexOf(v) === i; });
    assert.strictEqual(leaders.length, 1, JSON.stringify(leaders));
  });
  check("and the same next run of the history job, to the second",
        function () {
          const times = answers.map(function (r) {
            return Date.parse(jobOf(r, "scheduler.history").nextRunAt);
          });
          assert.ok(Math.max.apply(null, times) - Math.min.apply(null, times) <
                    1000, JSON.stringify(times));
        });
  const was = answers[0].leader.node;
  const asked = await api("POST", "/admin-api/scheduler/step-down", {});
  check("a step-down is accepted (202)", function () {
    assert.strictEqual(asked.status, 202, asked.text.slice(0, 300));
  });
  const after = await until("another node to lead", async function () {
    const r = await report();
    return r.leader.known && r.leader.node !== was && r.leader.live ? r : null;
  });
  check("the other node leads: " + after.leader.nodeName, function () {
    assert.notStrictEqual(after.leader.node, was);
  });
  const runs = await api("GET", "/admin-api/scheduler?job=" +
                         "authn.session-expiry&outcome=succeeded&per=500");
  check("every slot of the session-expiry job is one succeeded run",
        function () {
          const bySlot = {};
          runs.body.runs.forEach(function (r) {
            bySlot[r.dueAt] = (bySlot[r.dueAt] || 0) + 1;
          });
          const doubles = Object.keys(bySlot).filter(function (k) {
            return bySlot[k] > 1;
          });
          assert.strictEqual(doubles.length, 0, JSON.stringify(doubles));
        });
  log.debug("Leaving theClusterAgrees().");
}

async function main() {
  log.debug("Entering main().");
  const admin = "sched-admin-" + STAMP;
  const cookie = await signin.signInToTheConsole(base, admin, log,
                                                 { grant: "write" });
  const jar = cookie || "";
  await aLeaderTicks();
  await thePageAndTheApiAgree(jar);
  await runNow(jar);
  await adminReadRunsNothing();
  await aRealmTokenIsConfined();
  await theClusterAgrees();
  log.info("sts_scheduler: " + checks + " check(s) passed.");
  log.debug("Leaving main().");
}

main().catch(function (e) {
  log.error("sts_scheduler FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
