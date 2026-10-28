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
//      here finds both, and with one chosen (`groups`, one name a line) it
//      is resolved and left out of the results;
//   c. a start with a value out of its bounds, an unknown activity, a group
//      this realm does not have (STS-AUTHN-0530, by name), and an unknown
//      action are refused 400;
//   d. a post-login activity narrowed to the two groups starts, is listed
//      running with both DNs, a second for the same groups in the other
//      order is refused, and it pauses, resumes and ends; an ended one does
//      not pause.
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
                              encodeURIComponent(group + "\nnope-" +
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
    assert.strictEqual(badGroup.json.errorCode, "STS-AUTHN-0530",
                       badGroup.raw.slice(0, 300));
    assert.ok(/pla-nobody-/.test(JSON.stringify(badGroup.json.errors)),
              badGroup.raw.slice(0, 300));
    assert.strictEqual(badAction.status, 400, badAction.raw.slice(0, 300));
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

  assert.ok(checks >= 6, "only " + checks + " checks ran; a section has " +
                                           "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
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
