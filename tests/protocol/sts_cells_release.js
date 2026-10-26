// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: sts_cells_release.js
//
// ===========================================================================
// ANOTHER CELL'S RESIDENTS, UNDER ITS RELEASE POLICY (#98 D11, 2026-09-28).
//
// A directory-wide read answers the SERVING cell's residents; the console
// and `/admin-api` name another cell explicitly (`?cell=`), and the request
// is relayed there and answered under that cell's jurisdiction's release
// policy — asked where the people are, before anything is read. In a realm
// of the job's own, with a person homed at cell B (`ca`), from cell A (`us`):
//
//   1. UNDER THE STRICT DEFAULT, `GET /admin-api/cells/people?cell=<B>` at
//      cell A is refused: nothing personal leaves its jurisdiction, and a
//      list of names is personal.
//   2. The realm LISTS `ca>us` (`cells.permittedTransfers`, the one list the
//      hold and release rules both read). The same call at cell A is then
//      answered with cell B's residents — the person among them, as a login
//      name, an entryUUID and a display name and nothing else.
//   3. Cell A's own directory still does not hold them: the listing was
//      cell B's answer, not a copy.
//
// `local: true`: this repository's own `/admin-api`, against a stack only
// this repository's launcher builds. It declines to run in every mode but
// `cells`.
// ===========================================================================
"use strict";

const assert = require("assert");
const { Command, Option } = require("commander");
const expectation = require("./expectation.js");
const kit = require("./cells_kit.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, for the reason wait_for.js gives.
  appconfigProblem = e;
  appconfig = {};
}

const log = require("bunyan").createLogger({ name: "sts_cells_release",
  level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const STAMP = Date.now().toString(36);
const REALM = "cellsrl" + STAMP;
const PERSON = "cells-rel-" + STAMP;
const PASSWORD = "Cells-release-" + STAMP + "-Aa1!";

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

// Whether an answer to the people call is a refusal: the edge's 403, or a
// 200 carrying `refused`.
function refusal(got) {
  log.debug("Entering refusal().");
  const refused = got.status === 403 ||
    (got.status === 200 && got.body && !!got.body.refused);
  log.debug("Leaving refusal(). " + refused);
  return refused;
}

async function test() {
  log.debug("Entering test().");
  const cells = kit.cellsFromEnv();
  if (!cells) {
    expectation.declineToRun(log, "STS_TEST_CELL_B_URL is not set: this is " +
      "not the `cells` mode (./run-tests.sh --modes=cells), so there is no " +
      "other cell's residents to ask for.");
    log.debug("Leaving test(). Skipped.");
    return;
  }
  const realm = await kit.throwawayRealm(cells, REALM);
  const made = await kit.createPerson(realm.b, PERSON, PASSWORD, "");
  check("a person is created at cell B", function () {
    assert.strictEqual(made.status, 200, made.raw.slice(0, 300));
  });
  await kit.homed(realm.a, REALM, cells.ids.b, 1);
  const ask = "/cells/people?cell=" + encodeURIComponent(cells.ids.b);

  log.info("=== 1. the strict default ===");
  const strict = await kit.api(realm.a, "GET", ask);
  check("GET /admin-api/cells/people?cell=" + cells.ids.b + " at cell A is " +
        "refused, and names nobody", function () {
          assert.ok(refusal(strict), strict.status + " " +
            strict.raw.slice(0, 300));
          assert.ok(strict.raw.indexOf(PERSON) < 0, strict.raw.slice(0, 300));
        });

  log.info("=== 2. the realm lists ca>us ===");
  await kit.setSetting(realm.a, "cells.permittedTransfers",
                       cells.jurisdictions.b + ">" + cells.jurisdictions.a);
  const listed = await kit.until("cell B releases its residents to cell A",
    60000, async function () {
      const got = await kit.api(realm.a, "GET", ask);
      return got.status === 200 && got.body && Array.isArray(got.body.people)
        ? got : null;
    });
  const people = listed.body.people;
  const one = people.filter(function (p) {
    return p.name === PERSON;
  })[0];
  check("the same call is answered with cell B's residents, the person " +
        "among them", function () {
          assert.ok(one, "the person is not listed: " +
            JSON.stringify(people).slice(0, 300));
          assert.strictEqual(listed.body.cell, cells.ids.b);
        });
  check("as a login name, an entryUUID and a display name and nothing else",
        function () {
          assert.deepStrictEqual(Object.keys(one).sort(),
                                 ["displayName", "name", "uuid"]);
          assert.ok(/^[0-9a-f-]{36}$/i.test(one.uuid), one.uuid);
        });

  log.info("=== 3. it was cell B's answer, not a copy ===");
  const atA = await kit.api(realm.a, "GET", "/users?user=" +
                            encodeURIComponent(PERSON));
  check("cell A's own directory still does not hold the person", function () {
    assert.strictEqual(atA.status, 200, atA.raw.slice(0, 300));
    assert.ok(!(atA.body && atA.body.known === true &&
                (atA.body.ldap || atA.body.entry || atA.body.directory)),
      "cell A holds " + PERSON + ": " + atA.raw.slice(0, 300));
  });

  assert.ok(checks >= 5, "only " + checks + " checks ran; a section has " +
    "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_cells_release")
  .description("another cell's residents are refused under the strict " +
      "default and listed once the realm permits the transfer.")
  .addOption(new Option("-u, --url <url>",
      "base url (unused: the cells come from STS_TEST_CELL_*_URL)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
