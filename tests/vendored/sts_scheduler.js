// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
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

// THE TWO JOB LISTS, WITH A REALM CREATED MID-WALK ALLOWED FOR (2026-09-28).
// `ids` and `pageIds` are sorted `id@realm` lists. A row on one side only is
// set aside when its realm has rows on both sides and its job has rows for
// some other realm on both sides — the signature of a row inserted behind a
// paged walk's cursor. Anything else is a real difference: `agree` is false
// and the lists are handed back unchanged.
function settleRealmWalk(ids, pageIds) {
  log.debug("Entering settleRealmWalk().");
  const split = function (row) {
    const at = row.lastIndexOf("@");
    return { job: row.slice(0, at), realm: row.slice(at + 1) };
  };
  const index = function (list) {
    const realms = {};
    const jobRealms = {};
    list.forEach(function (row) {
      const p = split(row);
      realms[p.realm] = true;
      (jobRealms[p.job] = jobRealms[p.job] || {})[p.realm] = true;
    });
    return { realms: realms, jobRealms: jobRealms };
  };
  const a = index(ids);
  const b = index(pageIds);
  const inA = {};
  ids.forEach(function (row) {
    inA[row] = true;
  });
  const inB = {};
  pageIds.forEach(function (row) {
    inB[row] = true;
  });
  const onlyOne = ids.filter(function (row) {
    return !inB[row];
  }).concat(pageIds.filter(function (row) {
    return !inA[row];
  }));
  const explained = function (row) {
    const p = split(row);
    if (p.realm === "default" || !a.realms[p.realm] || !b.realms[p.realm]) {
      return false;
    }
    const elsewhere = function (x) {
      return Object.keys(x.jobRealms[p.job] || {}).some(function (r) {
        return r !== p.realm;
      });
    };
    return elsewhere(a) && elsewhere(b);
  };
  if (!onlyOne.length || !onlyOne.every(explained)) {
    log.debug("Leaving settleRealmWalk(). " +
              (onlyOne.length ? "A real difference." : "No difference."));
    return { agree: !onlyOne.length, setAside: [], ids: ids,
             pageIds: pageIds };
  }
  const drop = {};
  onlyOne.forEach(function (row) {
    drop[row] = true;
  });
  log.debug("Leaving settleRealmWalk(). Set aside " + onlyOne.length + ".");
  return { agree: true, setAside: onlyOne,
           ids: ids.filter(function (row) {
             return !drop[row];
           }),
           pageIds: pageIds.filter(function (row) {
             return !drop[row];
           }) };
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
  // THE TWO READINGS ARE TAKEN AGAIN UNTIL THEY AGREE (2026-09-27), at most
  // five times. Under the parallel scheduler other lanes create realms all
  // the time, a realm brings jobs of its own, and a paged walk made while
  // rows are inserted can repeat a row at a page boundary — so the API's
  // list and the page's, read a moment apart, differ for a reason that is
  // not this page. On a list that is not moving they are the same, which is
  // the claim; the rows are de-duplicated and the pair is read again.
  const unique = function (list) {
    log.debug("Entering unique().");
    const seen = {};
    const out = list.filter(function (x) {
      if (seen[x]) {
        return false;
      }
      seen[x] = true;
      return true;
    }).sort();
    log.debug("Leaving unique().");
    return out;
  };
  let json = null;
  let pageJson = null;
  let html = null;
  let ids = [];
  let pageIds = [];
  // How far apart the two reads the nextRunAt check compares were made, for
  // that check's allowance (below).
  let readGapMs = 0;
  let readEndedMs = 0;
  // The `id@realm` rows set aside as a realm created mid-walk (below).
  let walkSetAside = [];
  for (let attempt = 1; attempt <= 5; attempt++) {
    const readStarted = Date.now();
    json = await report();
    pageJson = await call("GET", base + "/admin/scheduler?format=json" +
                                "&per=200", { headers: { Cookie: cookie } });
    readEndedMs = Date.now();
    readGapMs = readEndedMs - readStarted;
    // EVERY PAGE, as report() reads the API's (2026-09-23): a comparison of
    // all the API's jobs with one page of the console's would fail on a
    // service with more than 200 job rows, about pages drawing exactly what
    // they should.
    const pagesOf = Number(((pageJson.body || {}).jobsPaging || {}).pages) ||
                    1;
    for (let page = 2; page <= pagesOf; page++) {
      const more = await call("GET", base + "/admin/scheduler?format=json" +
                              "&per=200&jobsPage=" + page,
                              { headers: { Cookie: cookie } });
      pageJson.body.jobs = pageJson.body.jobs.concat((more.body || {}).jobs ||
                                                     []);
    }
    // **`per=200` HERE TOO, AND IT IS THE POINT RATHER THAN A CONVENIENCE**
    // (2026-09-22). The jobs table is PAGED now — `admin-ui/CLAUDE.md`, *every
    // list that can grow without a bound is paged*; a REALM job has a row per
    // realm, so a service with fifty realms has fifty rows of each. The check
    // below asks for a row per job the API lists, so it has to ask for a page
    // big enough to hold them: without this it failed on `signing.rotate`,
    // which sorts onto the second page, about a page that was drawing exactly
    // what it should. The JSON fetch above already asks the same way.
    html = await call("GET", base + "/admin/scheduler?per=200",
                            { headers: { Cookie: cookie } });
    for (let page = 2; page <= pagesOf; page++) {
      const more = await call("GET", base + "/admin/scheduler?per=200" +
                              "&jobsPage=" + page,
                              { headers: { Cookie: cookie } });
      html.text += more.text;
    }
    ids = json.jobs.map(function (j) { return j.id + "@" + j.realm; })
      .sort();
    ids = unique(ids);
    pageIds = unique((pageJson.body.jobs || []).map(function (j) {
      return j.id + "@" + j.realm;
    }));
    if (JSON.stringify(ids) === JSON.stringify(pageIds)) {
      break;
    }
    // A REALM CREATED DURING THE WALK LOSES THE ROWS THAT LAND BEHIND IT
    // (2026-09-28, CI run 36380417724, cluster). Each read walks the job
    // table a page at a time while other lanes create realms, and a row
    // inserted into a page a walk has already read is seen by that walk
    // never — while the same realm's other rows, landing ahead of the cursor,
    // are. So one side can lack `signing.retire@<realm>` while holding that
    // realm's other jobs, and with realms made all the time in cluster mode
    // five readings need not find a quiet moment. Such a row is set aside
    // ONLY where its realm is on both sides and its job is listed for some
    // other realm on both sides: a job a process never registered is missing
    // for every realm or is a service-wide row, and still fails below.
    const settled = settleRealmWalk(ids, pageIds);
    if (settled.agree) {
      log.info("the API and the page agree but for " + settled.setAside.length +
               " row(s) of realms created during the walk, set aside: " +
               settled.setAside.join(", "));
      walkSetAside = settled.setAside;
      ids = settled.ids;
      pageIds = settled.pageIds;
      break;
    }
    log.info("the API and the page were read while the job list moved " +
             "(attempt " + attempt + "); reading both again");
    await new Promise(function (resolve) { setTimeout(resolve, 2000); });
  }
  check("the API lists the two jobs P1 moved and the scheduler's own",
        function () {
          ["authn.session-expiry", "pki.crl-directory-refresh",
           "scheduler.history"].forEach(function (id) {
            assert.ok(jobOf(json, id), id + " is not in " + ids.join(", "));
          });
        });
  check("the page's JSON lists exactly the same jobs", function () {
    assert.strictEqual(pageJson.status, 200, "it answered " + pageJson.status);
    assert.deepStrictEqual(pageIds, ids);
  });
  check("and every job is a row of the drawn page, by id", function () {
    assert.strictEqual(html.status, 200, "it answered " + html.status);
    json.jobs.filter(function (j) {
      return walkSetAside.indexOf(j.id + "@" + j.realm) < 0;
    }).forEach(function (j) {
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
            // WHOLE SLOTS APART IS AGREEMENT (2026-09-27): the two reads
            // are made one after the other, and for a job whose interval is
            // a few seconds (persistence.change-log-pull, 5 s) slot
            // boundaries can fall between them — the cluster run in CI saw
            // 5 s exactly, and the single-node run 10 s, with the API's
            // paged read taking more than five. Both then name the right
            // next run for the instant they were asked, so the difference
            // may be any whole number of slots that fits in the time the
            // reads took; a disagreement is anything else.
            const every = Number(j.schedule && j.schedule.everyMs) || 0;
            const slots = every > 0 ? Math.round(delta / every) : 0;
            const wholeSlots = every > 0 && every <= 60000 && slots >= 1 &&
              Math.abs(delta - slots * every) < 1000 &&
              delta <= readGapMs + every;
            // A SLOT DUE BETWEEN THE READS (2026-09-28): a job whose slot
            // had come due but not yet run answers that slot as its next
            // run, and the other read, made after it ran, answers the one
            // after. So one whole interval apart, the earlier of the two
            // already past when the reads ended, is agreement at any
            // interval (a 5-minute job met it at 17:50:00 in memory mode).
            const earlier = Math.min(Date.parse(j.nextRunAt),
                                     Date.parse(other.nextRunAt));
            const ranBetween = every > 0 &&
              Math.abs(delta - every) < 1000 && earlier <= readEndedMs;
            assert.ok(delta < 1000 || wholeSlots || ranBetween,
                      j.id + ": " + j.nextRunAt + " and " +
                      other.nextRunAt + " (the reads took " + readGapMs +
                      " ms)");
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
  // EVERY node, not two (#311): the AWS environments run three, and
  // STS_TEST_CLUSTER_NODES says how many; the local cluster mode sets 2.
  log.info("=== 6. " + EXPECTED_NODES + " nodes agree, and hand over ===");
  const seen = {};
  const answers = [];
  for (let i = 0; i < 8 * EXPECTED_NODES; i++) {
    const r = await report();
    seen[r.answeredBy.node] = true;
    answers.push(r);
  }
  check("every node answered through the balancer", function () {
    assert.strictEqual(Object.keys(seen).length, EXPECTED_NODES,
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
