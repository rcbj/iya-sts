// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_post_login_activities.js
//
// ---------------------------------------------------------------------------
// DIRECTORY → POST-LOGIN ACTIVITIES OVER HTTP (#1111, 2026-10-28; #1123).
//
// A started post-login activity's controls, as
// `/admin-api/post-login-activities` answers them and
// `/admin/post-login-activities` draws them. Against the running service, in
// every mode:
//
//   a. the console page answers its shell, the five operations are in the
//      OpenAPI document, and the view refuses a caller with no token;
//   b. the view answers the activities, the bounds, the job, the started
//      activities, and its group chooser: a search for the two groups made
//      here finds both, and with one chosen (`groups`, `;`-separated) it
//      is resolved and left out of the results;
//   c. a start with a value out of its bounds, an unknown activity, a group
//      this realm does not have (STS-AUTHN-0530, by name), and an unknown
//      action are refused 400;
//   d. a post-login activity narrowed to the two groups starts, is listed
//      running with both DNs, a second for the same groups in the other
//      order is refused, and it pauses, resumes and ends; an ended one does
//      not pause.;
//   e. in a realm of its own (D12, #444), the acts' codes and the job's
//      body run now — see section e's own header below.
//
// It is narrowed to groups made here, which hold nobody, so the job — which
// runs every few minutes on the stack this job shares — mails nobody for
// it, and it is ended before the job finishes. What the job mails
// and what the reports application reads back is
// `tests/post_login_activities.js`'s, in process, through the real channel.
//
// OWNED HERE (local: true): this repository's own console and management API
// (tests/CLAUDE.md, *where a new test goes*, rule 1).
// ---------------------------------------------------------------------------

const assert = require("assert");
const https = require("https");
const { Command, Option } = require("commander");

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
var log = bunyan.createLogger({ name: "sts_post_login_activities",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const OPERATION = "/admin-api/post-login-activities";
const STAMP = Date.now().toString(36);

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

// One request over node's own https. The management API's token is attached
// by the launcher's preload (`tests/tools/attach-admin-token.js`) unless
// `bare` sends `Authorization: none`.
function send(method, path, options) {
  log.debug("Entering send(). " + method + " " + path);
  const o = options || {};
  const target = new URL(base + path);
  const headers = Object.assign({ accept: "application/json" },
                                o.headers || {});
  const body = o.json === undefined ? "" : JSON.stringify(o.json);
  if (body) {
    headers["content-type"] = "application/json";
    headers["content-length"] = Buffer.byteLength(body);
  }
  if (o.bare) {
    // `tests/tools/attach-admin-token.js` leaves this alone, and the service
    // reads it as a malformed credential: a caller with no token.
    headers.authorization = "none";
  }
  log.debug("Leaving send().");
  return new Promise(function (resolve, reject) {
    const transport = target.protocol === "http:" ? require("http") : https;
    const req = transport.request({
      method: method, hostname: target.hostname, port: target.port,
      path: target.pathname + target.search, headers: headers
    }, function (res) {
      const chunks = [];
      res.on("data", function (c) {
        chunks.push(c);
      });
      res.on("end", function () {
        const raw = Buffer.concat(chunks).toString("utf8");
        let json = null;
        try {
          json = JSON.parse(raw);
        } catch (e) {
          log.debug("Caught in send(): " + ((e && e.message) || e));
          // Not JSON: a page, a CSV, or Express's own 404; the caller reads
          // `raw`.
          json = null;
        }
        resolve({ status: res.statusCode, headers: res.headers, raw: raw,
                  json: json });
      });
    });
    req.on("error", reject);
    req.end(body);
  });
}

async function test() {
  log.debug("Entering test().");
  log.info("Directory → Post-login activities at " + base);

  log.info("=== a. the page, the document and the gate ===");
  const shell = await send("GET", "/admin/post-login-activities",
                           { headers: { accept: "text/html" } });
  const doc = await send("GET", "/admin-api/openapi.json");
  const anonymous = await send("GET", OPERATION, { bare: true });
  check("the console page answers its shell, the operations are " +
        "published, and the view refuses a caller with no token",
        function () {
    assert.strictEqual(shell.status, 200, shell.raw.slice(0, 200));
    assert.ok(/<html/i.test(shell.raw), shell.raw.slice(0, 200));
    const paths = Object.keys((doc.json && doc.json.paths) || {});
    [OPERATION, OPERATION + "/start", OPERATION + "/pause",
     OPERATION + "/resume", OPERATION + "/end"].forEach(function (p) {
      assert.ok(paths.indexOf(p) >= 0, p + " is not in the document");
    });
    assert.strictEqual(anonymous.status, 401, anonymous.raw.slice(0, 200));
  });

  log.info("=== b. the view and its group chooser ===");
  const group = "pla-group-" + STAMP;
  const other = "pla-other-" + STAMP;
  const madeGroup = await send("POST", "/admin-api/groups/create",
                               { json: { group: group } });
  const madeOther = await send("POST", "/admin-api/groups/create",
                               { json: { group: other } });
  const view = await send("GET", OPERATION + "?groupq=" +
                          encodeURIComponent(STAMP));
  const narrowed = await send("GET", OPERATION + "?groupq=" +
                              encodeURIComponent(STAMP) + "&groups=" +
                              encodeURIComponent(group + ";nope-" +
                                                 STAMP));
  check("the view answers the activities, the bounds, the job, the " +
        "started activities and its group chooser", function () {
    assert.ok(madeGroup.status === 200 || madeGroup.status === 201,
              madeGroup.raw.slice(0, 300));
    assert.ok(madeOther.status === 200 || madeOther.status === 201,
              madeOther.raw.slice(0, 300));
    assert.strictEqual(view.status, 200, view.raw.slice(0, 300));
    const v = view.json || {};
    assert.ok(Array.isArray(v.started), view.raw.slice(0, 300));
    const pane = (v.groupChooser || {}).pane || {};
    assert.strictEqual(pane.matched, 2, JSON.stringify(v.groupChooser));
    assert.strictEqual(pane.from, 0);
    const n = (narrowed.json || {}).groupChooser || {};
    assert.strictEqual((n.pane || {}).matched, 1, JSON.stringify(n));
    assert.strictEqual(n.pane.shown[0].cn, other, JSON.stringify(n));
    assert.deepStrictEqual((n.chosen || []).map(function (g) {
      return g.found;
    }), [true, false], JSON.stringify(n.chosen));
    assert.ok(v.activities.indexOf("pqc-passkey-migration") >= 0,
              JSON.stringify(v.activities));
    assert.strictEqual(v.job, "post-login.activity-mail");
    assert.ok(v.limits && v.limits.maxMails && v.limits.intervalDays &&
              v.limits.perRun, JSON.stringify(v.limits));
    assert.strictEqual(typeof v.mailAvailable, "boolean");
  });

  log.info("=== c. refusals ===");
  const badNumber = await send("POST", OPERATION + "/start",
                               { json: { groups: [group], maxMails: 99 } });
  const badActivity = await send("POST", OPERATION + "/start",
                                 { json: { activity: "nonsense" } });
  const badGroup = await send("POST", OPERATION + "/start",
                              { json: { groups: [group,
                                                 "pla-nobody-" + STAMP] } });
  const badAction = await send("POST", OPERATION + "/nonsense",
                               { json: { id: "x" } });
  check("a value out of bounds, an unknown activity, an unknown group and " +
        "an unknown action are refused", function () {
    assert.strictEqual(badNumber.status, 400, badNumber.raw.slice(0, 300));
    assert.strictEqual(badActivity.status, 400,
                       badActivity.raw.slice(0, 300));
    assert.strictEqual(badGroup.status, 400, badGroup.raw.slice(0, 300));
    assert.ok(!("errorCode" in badGroup.json), badGroup.raw.slice(0, 300));
    assert.ok(/pla-nobody-/.test(JSON.stringify(badGroup.json.errors)),
              badGroup.raw.slice(0, 300));
    assert.strictEqual(badAction.status, 400, badAction.raw.slice(0, 300));
  });

  // WHERE THE CODE IS RECORDED (#1355): the audit row, written as the
  // response finishes, so the read after it may need a moment.
  let recorded = 0;
  for (let i = 0; i < 20 && !recorded; i += 1) {
    await new Promise(function (done) {
      setTimeout(done, 150);
    });
    const rows = await send("GET",
                            "/admin-api/audit?per=50&code=STS-AUTHN-0530");
    recorded = ((rows.json && (rows.json.rows || rows.json.events)) ||
                []).length;
  }
  check("the unknown group's refusal is recorded under its code", function () {
    assert.ok(recorded > 0, "no audit row carries STS-AUTHN-0530");
  });

  log.info("=== d. start, pause, resume, end ===");
  const started = await send("POST", OPERATION + "/start",
                             { json: { activity: "pqc-passkey-migration",
                                       groups: [group, other],
                                       intervalDays: 7, maxMails: 2,
                                       perRun: 100 } });
  const id = started.json && started.json.started &&
             started.json.started.id;
  try {
    const listed = await send("GET", OPERATION);
    const again = await send("POST", OPERATION + "/start",
                             { json: { groups: [other, group] } });
    check("a post-login activity narrowed to two groups starts and is " +
          "listed running, and a second for the same groups is refused",
          function () {
      assert.strictEqual(started.status, 200, started.raw.slice(0, 300));
      assert.ok(id, started.raw.slice(0, 300));
      assert.strictEqual(started.json.started.groups.length, 2,
                         started.raw.slice(0, 300));
      assert.ok(started.json.started.groups.every(function (dn) {
        return /^cn=/i.test(dn);
      }), started.raw.slice(0, 300));
      const row = (listed.json.started || []).filter(function (one) {
        return one.id === id;
      })[0];
      assert.ok(row && row.state === "running", listed.raw.slice(0, 300));
      assert.strictEqual(again.status, 400, again.raw.slice(0, 300));
    });
    const paused = await send("POST", OPERATION + "/pause",
                              { json: { id: id } });
    const resumed = await send("POST", OPERATION + "/resume",
                               { json: { id: id } });
    check("it pauses and resumes", function () {
      assert.strictEqual(paused.status, 200, paused.raw.slice(0, 300));
      assert.strictEqual(paused.json.started.state, "paused");
      assert.strictEqual(resumed.status, 200, resumed.raw.slice(0, 300));
      assert.strictEqual(resumed.json.started.state, "running");
    });
  } finally {
    if (id) {
      const ended = await send("POST", OPERATION + "/end",
                               { json: { id: id } });
      const afterEnd = await send("POST", OPERATION + "/pause",
                                  { json: { id: id } });
      check("it ends, and an ended one does not pause", function () {
        assert.strictEqual(ended.status, 200, ended.raw.slice(0, 300));
        assert.strictEqual(ended.json.started.state, "ended");
        assert.strictEqual(afterEnd.status, 400,
                           afterEnd.raw.slice(0, 300));
      });
    }
  }

  const own = await jobBody();
  try {
    await own.removeRealms();
  } catch (e) {
    log.debug("Caught in test(): " + ((e && e.message) || e));
    // A realm left behind is not a failed assertion.
    log.warn("removing this run's realm failed: " + e.message);
  }
  assert.ok(checks >= 12, "only " + checks + " checks ran; a section has " +
                                            "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

// ---------------------------------------------------------------------------
// e. THE ACTS' CODES AND THE JOB'S BODY, IN A REALM OF ITS OWN (D12, #444:
// the wire half of `tests/post_login_activities.js`, deleted at the
// cutover).
//
// Sections a-d above work in the default realm; this one makes its own,
// so the job's run reads people this section made and nobody else:
//
//   e1. the codes of the refusals, off `/admin-api/audit`: a number out of
//       its bounds and an unknown activity (the request schema's,
//       STS-API-0009: every bound STS-AUTHN-0490 names is in the schema), a
//       second for the same groups in the other order (0492), an act whose
//       state does not move and an unknown id (0491);
//   e2-e4. the job's body, run now through `/admin-api/scheduler/run`:
//       a started activity over two groups mails the people its groups
//       reach who are due — three people holding a classical passkey, one
//       in both groups, one in neither — the shared member ONCE and the
//       outsider not, each to the address on the entry, through the
//       development capture; the captured message's one link is the
//       portal's path with no query, and it carries no credential;
//   e5. with the realm's mail transport off, a run mails nobody
//       (STS-AUTHN-0495 on the scheduler's run row).
//
// OWED: a member with no address refused by the channel and counted
// (STS-AUTHN-0494) — a development realm invents an address for a person
// created with none, and a product realm captures no mail to read back.
//
// NOT CARRIED (class (d)): the slice after the key cursor, the cursor
// starting over, the interval and the maximum holding a person back
// across runs on a moved clock, one audit row per started activity per
// run, the chooser's paging over twenty-five groups (section b holds the
// chooser), and `/report-api`'s `postLoginProgress` source (the reports
// family's job).
// ---------------------------------------------------------------------------
const wire = require("./passkey_wire_kit.js");
const portalSignin = require("./portal_signin.js");

async function jobBody() {
  log.debug("Entering jobBody().");
  const k = wire.kit("sts_post_login_activities", { log: log });
  const realm = await k.realm("pla-job", "development");
  const PASSWORD = "Pla-Job-Passw0rd!-" + String(Date.now()).slice(-6);
  const name = function (n) {
    log.debug("Entering name(). " + n);
    log.debug("Leaving name().");
    return (n + "-" + k.STAMP).slice(0, 30);
  };
  const g1 = name("plj-one").toLowerCase();
  const g2 = name("plj-two").toLowerCase();
  for (const g of [g1, g2]) {
    const made = await k.call(realm, "POST", "/groups/create", { group: g });
    assert.strictEqual(made.status, 200, made.raw.slice(0, 300));
  }
  // A in the first group, B in both, C in neither — each holding a
  // classical passkey, so each is due.
  const people = {};
  for (const p of [["a", [g1]], ["b", [g1, g2]], ["c", []]]) {
    const n = name("plj-" + p[0]);
    await k.person(realm, n, PASSWORD);
    const portal = await portalSignin.signInToThePortal(realm.base, n, null,
      { password: PASSWORD });
    const key = k.authenticator({});
    const done = await k.enrol(portal, key, {});
    assert.ok(done.done && done.done.status === 200,
      "registering " + n + "'s passkey answered " +
      JSON.stringify((done.done || done.begun).json).slice(0, 300));
    for (const g of p[1]) {
      const added = await k.call(realm, "POST", "/groups/add-member",
                                 { group: g, member: n });
      assert.strictEqual(added.status, 200, added.raw.slice(0, 300));
    }
    people[p[0]] = n;
  }

  log.info("=== e1. the acts' codes ===");
  const refused = async function (code, path, body) {
    log.debug("Entering refused(). " + code);
    const before = await k.codeCount(realm, code);
    const r = await k.call(realm, "POST", "/post-login-activities" + path,
                           body);
    const n = await k.newCodes(realm, code, before);
    log.debug("Leaving refused(). " + r.status + " " + n);
    return { r: r, n: n };
  };
  // THE REQUEST SCHEMA HOLDS EVERY BOUND STS-AUTHN-0490 NAMES — the
  // numbers' ranges and types, the activity's one value, fifty groups — so
  // over /admin-api those refusals are the schema's (STS-API-0009).
  const bounds = await refused("STS-API-0009", "/start",
                               { groups: [g1], maxMails: 99 });
  const activity = await refused("STS-API-0009", "/start",
                                 { activity: "nonsense", groups: [g1] });
  const started = await k.call(realm, "POST", "/post-login-activities/start",
    { activity: "pqc-passkey-migration", groups: [g1, g2], intervalDays: 1,
      maxMails: 3, perRun: 100 });
  const id = started.body && started.body.started && started.body.started.id;
  const twice = await refused("STS-AUTHN-0492", "/start",
                              { groups: [g2, g1] });
  const resume = await refused("STS-AUTHN-0491", "/resume", { id: id });
  const nobody = await refused("STS-AUTHN-0491", "/pause",
                               { id: "pla-nobody-" + k.STAMP });
  check("e1. a number out of bounds and an unknown activity are refused " +
        "by the request schema (STS-API-0009, before STS-AUTHN-0490), a " +
        "second for the same groups in the other order STS-AUTHN-0492, and " +
        "an act whose state does not move or an unknown id 0491",
        function () {
    [bounds, activity, twice, resume, nobody].forEach(function (one) {
      assert.strictEqual(one.r.status, 400, one.r.raw.slice(0, 300));
      assert.ok(one.n >= 1, one.r.raw.slice(0, 300));
      assert.ok(!/STS-[A-Z]+-\d{4}/.test(one.r.raw), one.r.raw);
    });
    assert.ok(started.status === 200 && id, started.raw.slice(0, 300));
  });

  log.info("=== e2. the job's body, run now ===");
  const runJob = async function () {
    log.debug("Entering runJob().");
    const queued = await k.send("POST", k.root + "/admin-api/scheduler/run",
      { job: "post-login.activity-mail", realm: realm.id });
    assert.ok(queued.status === 202 || queued.status === 200,
      "queueing the job answered " + queued.status + " " +
      queued.raw.slice(0, 300));
    const runId = queued.body && queued.body.runId;
    let detail = null;
    for (let i = 0; i < 120; i += 1) {
      const r = await k.send("GET", k.root + "/admin-api/scheduler?run=" +
                             encodeURIComponent(runId));
      detail = r.body && r.body.detail;
      if (detail && /^(succeeded|failed|ok|done|error|completed)/.test(
            String(detail.state || ""))) {
        break;
      }
      await k.sleep(500);
    }
    log.debug("Leaving runJob(). " + JSON.stringify(detail).slice(0, 200));
    return detail;
  };
  const reminders = async function () {
    log.debug("Entering reminders().");
    const r = await k.call(realm, "GET", "/mail/outbox?per=300&q=" +
                           encodeURIComponent("post-login-reminder"));
    log.debug("Leaving reminders().");
    return ((r.body && r.body.rows) || []).filter(function (one) {
      return one.template === "post-login-reminder";
    });
  };
  const run = await runJob();
  const mails = await reminders();
  const count = function (who) {
    log.debug("Entering count().");
    log.debug("Leaving count().");
    return mails.filter(function (one) {
      return one.username === who;
    }).length;
  };
  check("e2. a run of the job mails the union of the two groups — the " +
        "member of both ONCE, the person in neither not", function () {
    assert.ok(run, "the run did not finish");
    assert.strictEqual(count(people.a), 1, JSON.stringify(mails));
    assert.strictEqual(count(people.b), 1, JSON.stringify(mails));
    assert.strictEqual(count(people.c), 0, JSON.stringify(mails));
  });
  const toA = mails.filter(function (one) {
    return one.username === people.a;
  })[0] || {};
  check("e3. to the address on the entry", function () {
    assert.strictEqual(toA.to, people.a + "@passkey-wire.test",
                       JSON.stringify(toA));
  });
  let body = null;
  for (let i = 0; i < 40; i += 1) {
    const r = await k.call(realm, "GET", "/mail/outbox?message=" +
                           encodeURIComponent(toA.id));
    body = r.body && r.body.message;
    if (body && body.state === "captured") {
      break;
    }
    await k.sleep(150);
  }
  const links = String((body && body.text) || "").match(
    /https?:\/\/[^\s]+/g) || [];
  check("e4. the captured message's one link is the portal's path, with no " +
        "query, and it carries no credential", function () {
    assert.strictEqual(links.length, 1, JSON.stringify(links));
    assert.ok(/\/portal$/.test(links[0]), links[0]);
    assert.ok(!/token|code=|secret/i.test(String(body.html || "") +
                                          String(body.text || "")));
  });
  const ended = await k.call(realm, "POST", "/post-login-activities/end",
                             { id: id });
  assert.strictEqual(ended.status, 200, ended.raw.slice(0, 300));

  log.info("=== e5. no transport, nobody mailed ===");
  await k.mustSet(realm, "mail.transport", "off");
  const again = await k.call(realm, "POST", "/post-login-activities/start",
    { activity: "pqc-passkey-migration", intervalDays: 1 });
  const againId = again.body && again.body.started && again.body.started.id;
  const before = (await reminders()).length;
  const b495 = await k.codeCount(realm, "STS-AUTHN-0495");
  const dry = await runJob();
  const n495 = await k.newCodes(realm, "STS-AUTHN-0495", b495);
  const afterRows = (await reminders()).length;
  check("e5. with the realm's mail transport off a run mails nobody and " +
        "says why (STS-AUTHN-0495)", function () {
    assert.ok(again.status === 200 && againId, again.raw.slice(0, 300));
    assert.strictEqual(afterRows, before);
    // On the scheduler's run row, not the audit log (the code's own row
    // in common/error_codes.js says "logged; the scheduler run row").
    assert.ok(/STS-AUTHN-0495/.test(JSON.stringify(dry)),
              JSON.stringify(dry) + " audit rows: " + n495);
  });
  await k.call(realm, "POST", "/post-login-activities/end", { id: againId });
  await k.reset(realm, "mail.transport");
  log.debug("Leaving jobBody().");
  return k;
}

const program = new Command();
program
  .name("sts_post_login_activities")
  .description("Directory → Post-login activities over HTTP (#1111, " +
               "#1123).")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().then(function () {
  process.exit(0);
}, function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
