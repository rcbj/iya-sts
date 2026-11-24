// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_post_login_started_kinds.js
//
// ---------------------------------------------------------------------------
// EVERY POST-LOGIN ACTIVITY CAN BE STARTED, OVER /admin-api (#2009 P4).
//
// Until #2009's P4 an administrator could start the passkey migration
// alone; the mail-encryption migration (`pqc-mail-encryption`, P2) and the
// PIV re-issue (`piv-reissue`, P3) were asked at a sign-in and nowhere else.
// In a realm of its own, against the running service:
//
//   a. the view offers all three activities, and answers
//      `enabledActivities` (none: the realm saved no policy);
//   b. for each of the two new activities, a start narrowed to a group made
//      here answers 200 naming that activity, is listed running, a second
//      for the same activity and group is refused (400, STS-AUTHN-0492 on
//      the audit log, no code in the body), and it pauses, resumes and
//      ends; an ended one does not pause;
//   c. the passkey migration started for the SAME group while the other two
//      run is not refused — the duplicate rule is per activity — and a start
//      naming no activity is still the passkey migration (a client written
//      before P4 is answered as it was);
//   d. an activity outside the three is still refused by the request schema.
//
// The group holds nobody, so the scheduler job (every few minutes on the
// stack this job shares) mails nobody for it; every activity is ended
// before the job finishes. What the reminder SAYS per activity, the job's
// run and the report's filter are `tests/post_login_started_kinds.js`'s,
// in process.
//
// OWNED HERE (local: true): this repository's own management API
// (tests/CLAUDE.md, *where a new test goes*, rule 1).
// ---------------------------------------------------------------------------

const assert = require("assert");
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
var log = bunyan.createLogger({ name: "sts_post_login_started_kinds",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const wire = require("./passkey_wire_kit.js");

const NEW_ACTIVITIES = ["pqc-mail-encryption", "piv-reissue"];
const PASSKEY = "pqc-passkey-migration";

async function test() {
  log.debug("Entering test().");
  const k = wire.kit("sts_post_login_started_kinds", { log: log });
  const realm = await k.realm("plk", "development");
  const group = ("plk-group-" + k.STAMP).slice(0, 30).toLowerCase();
  const made = await k.call(realm, "POST", "/groups/create",
                            { group: group });
  assert.strictEqual(made.status, 200, made.raw.slice(0, 300));
  const ids = [];

  log.info("=== a. the view offers every activity ===");
  const view = await k.call(realm, "GET", "/post-login-activities");
  k.check("a. the view offers the three activities and answers " +
          "enabledActivities", function () {
    assert.strictEqual(view.status, 200, view.raw.slice(0, 300));
    assert.deepStrictEqual(view.body.activities,
      [PASSKEY].concat(NEW_ACTIVITIES), view.raw.slice(0, 300));
    assert.ok(Array.isArray(view.body.enabledActivities),
              view.raw.slice(0, 300));
    assert.strictEqual(view.body.enabledActivities.length, 0,
                       view.raw.slice(0, 300));
  });

  try {
    for (const activity of NEW_ACTIVITIES) {
      log.info("=== b. " + activity + ": start, pause, resume, end ===");
      const started = await k.call(realm, "POST",
        "/post-login-activities/start",
        { activity: activity, groups: [group], intervalDays: 7,
          maxMails: 2, perRun: 100 });
      const id = started.body && started.body.started &&
                 started.body.started.id;
      if (id) {
        ids.push(id);
      }
      const before = await k.codeCount(realm, "STS-AUTHN-0492");
      const twice = await k.call(realm, "POST",
        "/post-login-activities/start",
        { activity: activity, groups: [group] });
      const n492 = await k.newCodes(realm, "STS-AUTHN-0492", before);
      const listed = await k.call(realm, "GET", "/post-login-activities");
      k.check("b. " + activity + " starts for the group, is listed " +
              "running under its own id, and a second for the same " +
              "people is refused (STS-AUTHN-0492)", function () {
        assert.strictEqual(started.status, 200, started.raw.slice(0, 300));
        assert.ok(id, started.raw.slice(0, 300));
        assert.strictEqual(started.body.started.activity, activity);
        assert.strictEqual(started.body.started.groups.length, 1);
        const row = (listed.body.started || []).filter(function (one) {
          return one.id === id;
        })[0];
        assert.ok(row && row.state === "running" &&
                  row.activity === activity, listed.raw.slice(0, 300));
        assert.strictEqual(twice.status, 400, twice.raw.slice(0, 300));
        assert.ok(n492 >= 1, "no audit row carries STS-AUTHN-0492");
        assert.ok(!/STS-[A-Z]+-\d{4}/.test(twice.raw), twice.raw);
      });
      const paused = await k.call(realm, "POST",
        "/post-login-activities/pause", { id: id });
      const resumed = await k.call(realm, "POST",
        "/post-login-activities/resume", { id: id });
      const ended = await k.call(realm, "POST",
        "/post-login-activities/end", { id: id });
      const after = await k.call(realm, "POST",
        "/post-login-activities/pause", { id: id });
      k.check("b. " + activity + " pauses, resumes and ends, and an " +
              "ended one does not pause", function () {
        assert.strictEqual(paused.status, 200, paused.raw.slice(0, 300));
        assert.strictEqual(paused.body.started.state, "paused");
        assert.strictEqual(resumed.status, 200, resumed.raw.slice(0, 300));
        assert.strictEqual(resumed.body.started.state, "running");
        assert.strictEqual(ended.status, 200, ended.raw.slice(0, 300));
        assert.strictEqual(ended.body.started.state, "ended");
        assert.strictEqual(after.status, 400, after.raw.slice(0, 300));
      });
    }

    log.info("=== c. one group, several activities ===");
    const mail = await k.call(realm, "POST", "/post-login-activities/start",
      { activity: "pqc-mail-encryption", groups: [group] });
    const mailId = mail.body && mail.body.started && mail.body.started.id;
    if (mailId) {
      ids.push(mailId);
    }
    const passkey = await k.call(realm, "POST",
      "/post-login-activities/start", { groups: [group] });
    const passkeyId = passkey.body && passkey.body.started &&
                      passkey.body.started.id;
    if (passkeyId) {
      ids.push(passkeyId);
    }
    k.check("c. the passkey migration starts for a group another " +
            "activity is running for, and a start naming no activity is " +
            "the passkey migration", function () {
      assert.strictEqual(mail.status, 200, mail.raw.slice(0, 300));
      assert.strictEqual(passkey.status, 200, passkey.raw.slice(0, 300));
      assert.strictEqual(passkey.body.started.activity, PASSKEY);
    });

    log.info("=== d. an activity outside the three ===");
    const before = await k.codeCount(realm, "STS-API-0009");
    const nonsense = await k.call(realm, "POST",
      "/post-login-activities/start",
      { activity: "pqc-ssh-migration", groups: [group] });
    const n009 = await k.newCodes(realm, "STS-API-0009", before);
    k.check("d. an activity outside the three is refused by the request " +
            "schema (STS-API-0009)", function () {
      assert.strictEqual(nonsense.status, 400, nonsense.raw.slice(0, 300));
      assert.ok(n009 >= 1, "no audit row carries STS-API-0009");
    });
  } finally {
    for (const id of ids) {
      const ended = await k.call(realm, "POST", "/post-login-activities/end",
                                 { id: id });
      log.debug("ending " + id + " answered " + ended.status);
    }
  }
  await k.removeRealms();
  assert.ok(k.checks() >= 6, "only " + k.checks() + " checks ran; a " +
                             "section has stopped being called.");
  log.info(k.checks() + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_post_login_started_kinds")
  .description("Every post-login activity started over /admin-api " +
               "(#2009 P4).")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().then(function () {
  process.exit(0);
}, function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
