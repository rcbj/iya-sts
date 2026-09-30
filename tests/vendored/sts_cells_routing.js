// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: sts_cells_routing.js
//
// ===========================================================================
// A PERSON IS HOMED IN ONE CELL, AND A LOGIN NAME IS UNIQUE ACROSS ALL OF
// THEM (#98 D1, section 4, 2026-09-28).
//
// The global routing index maps a keyed digest of a realm's login name to the
// cell the person is homed in. It is the one global write a creation makes,
// and it is what keeps a name unique across cells. Over HTTP, in a realm of
// its own, at the `cells` mode's two cells:
//
//   1. A person created at cell B is homed there: the routing index counts
//      one more person in cell B and none more in cell A — the count every
//      cell reads off the global tier, asked at cell A.
//   2. The SAME NAME created at cell A is refused 409 before anything is
//      made: the name is claimed by cell B.
//   3. A person created at cell A naming `homeCell: <cell B>` is created AT
//      CELL B — the creation is relayed whole — so cell B knows them, cell A
//      holds no entry for them, and the index counts them in cell B.
//   4. A `homeCell` naming no cell of this service is refused 400.
//
// `local: true`: it drives this repository's own `/admin-api`, against a
// stack only this repository's launcher builds. It declines to run in every
// mode but `cells`.
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

const log = require("bunyan").createLogger({ name: "sts_cells_routing",
  level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const STAMP = Date.now().toString(36);
const REALM = "cellsrt" + STAMP;
const PASSWORD = "Cells-routing-" + STAMP + "-Aa1!";

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

// Whether a cell's directory holds a person, by the management API's
// one-person view: `known` and an entry.
async function holds(realmBase, username) {
  log.debug("Entering holds(). " + username);
  const got = await kit.api(realmBase, "GET", "/users?user=" +
                            encodeURIComponent(username));
  assert.strictEqual(got.status, 200, got.raw.slice(0, 300));
  const body = got.body || {};
  const yes = body.known === true && JSON.stringify(body)
    .indexOf(username) >= 0 && !!(body.ldap || body.entry || body.directory);
  log.debug("Leaving holds(). " + yes);
  return { yes: yes, body: body };
}

async function test() {
  log.debug("Entering test().");
  const cells = kit.cellsFromEnv();
  if (!cells) {
    expectation.declineToRun(log, "STS_TEST_CELL_B_URL is not set: this is " +
      "not the `cells` mode (./run-tests.sh --modes=cells), so there is no " +
      "second cell to route to.");
    log.debug("Leaving test(). Skipped.");
    return;
  }
  const realm = await kit.throwawayRealm(cells, REALM);
  const before = await kit.peopleIn(realm.a, REALM);

  log.info("=== 1. a person created at cell B is homed there ===");
  const bee = "cells-b-" + STAMP;
  const atB = await kit.createPerson(realm.b, bee, PASSWORD, "");
  check("POST /admin-api/users/create at cell B answers 200", function () {
    assert.strictEqual(atB.status, 200, atB.raw.slice(0, 300));
  });
  // The entryUUID half of the index — what `peoplePerCell` counts — is
  // written when cell B's store is flushed (persistence/CLAUDE.md, *Tiers*),
  // a moment after the name claimed at the creation itself.
  const afterB = await kit.until("the index counts the person", 30000,
    async function () {
      const now = await kit.peopleIn(realm.a, REALM);
      return (now[cells.ids.b] || 0) > (before[cells.ids.b] || 0) ? now
                                                                  : null;
    });
  check("and the routing index, read at cell A, counts one more person in " +
        cells.ids.b + " and none more in " + cells.ids.a, function () {
          assert.strictEqual((afterB[cells.ids.b] || 0),
                             (before[cells.ids.b] || 0) + 1,
                             JSON.stringify({ before: before, after: afterB }));
          assert.strictEqual((afterB[cells.ids.a] || 0),
                             (before[cells.ids.a] || 0),
                             JSON.stringify({ before: before, after: afterB }));
        });

  log.info("=== 2. the same name is refused at cell A ===");
  const again = await kit.createPerson(realm.a, bee, PASSWORD, "");
  check("POST /admin-api/users/create of the same name at cell A answers " +
        "409: the name is claimed by another cell", function () {
          assert.strictEqual(again.status, 409, again.raw.slice(0, 300));
          assert.strictEqual(again.body && again.body.error, "conflict",
                             again.raw.slice(0, 300));
        });
  // A flush's worth of waiting, so a person made in spite of the refusal
  // would be counted by now.
  await new Promise(function (resolve) {
    setTimeout(resolve, 4000);
  });
  const stillB = await kit.peopleIn(realm.a, REALM);
  check("and nothing was made: the index still counts the same people",
        function () {
          assert.deepStrictEqual(stillB, afterB);
        });

  log.info("=== 3. a creation at cell A naming cell B as home ===");
  const relayed = "cells-a2b-" + STAMP;
  const named = await kit.createPerson(realm.a, relayed, PASSWORD,
                                       cells.ids.b);
  check("POST /admin-api/users/create at cell A with homeCell " +
        cells.ids.b + " answers 200", function () {
          assert.strictEqual(named.status, 200, named.raw.slice(0, 300));
        });
  // AT ONCE, with no wait for a flush: the home cell claimed the name before
  // it answered, so the index already names cell B.
  const atOnce = await kit.createPerson(realm.a, relayed, PASSWORD, "");
  check("and at once, with no wait, the same name at cell A answers 409: " +
        "the relayed creation claimed it before answering", function () {
          assert.strictEqual(atOnce.status, 409, atOnce.raw.slice(0, 300));
        });
  const afterRelay = await kit.until("the index counts the relayed person",
    30000, async function () {
      const now = await kit.peopleIn(realm.a, REALM);
      return (now[cells.ids.b] || 0) > (afterB[cells.ids.b] || 0) ? now
                                                                  : null;
    });
  check("and the index counts them in " + cells.ids.b + ", not " +
        cells.ids.a, function () {
          assert.strictEqual((afterRelay[cells.ids.b] || 0),
                             (afterB[cells.ids.b] || 0) + 1,
                             JSON.stringify(afterRelay));
          assert.strictEqual((afterRelay[cells.ids.a] || 0),
                             (afterB[cells.ids.a] || 0),
                             JSON.stringify(afterRelay));
        });
  const heldAtB = await holds(realm.b, relayed);
  const heldAtA = await holds(realm.a, relayed);
  check("cell B's directory holds the person; cell A's does not (a " +
        "directory read answers the serving cell's residents, D11)",
        function () {
          assert.ok(heldAtB.yes, "cell B does not hold " + relayed + ": " +
            JSON.stringify(heldAtB.body).slice(0, 300));
          assert.ok(!heldAtA.yes, "cell A holds " + relayed + ", homed in " +
            "cell B: " + JSON.stringify(heldAtA.body).slice(0, 300));
        });
  const refusedAgain = await kit.createPerson(realm.a, relayed, PASSWORD, "");
  check("and its name is claimed too: created again at cell A, 409",
        function () {
          assert.strictEqual(refusedAgain.status, 409,
                             refusedAgain.raw.slice(0, 300));
        });

  log.info("=== 4. a home that is no cell of this service ===");
  const nowhere = await kit.createPerson(realm.a, "cells-nowhere-" + STAMP,
                                         PASSWORD, "nosuchcell");
  check("homeCell naming no cell answers 400 invalid_request", function () {
    assert.strictEqual(nowhere.status, 400, nowhere.raw.slice(0, 300));
    assert.strictEqual(nowhere.body && nowhere.body.error,
                       "invalid_request", nowhere.raw.slice(0, 300));
  });

  assert.ok(checks >= 9, "only " + checks + " checks ran; a section has " +
    "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_cells_routing")
  .description("a login name is unique across cells, and a creation naming " +
      "another cell as home is made there.")
  .addOption(new Option("-u, --url <url>",
      "base url (unused: the cells come from STS_TEST_CELL_*_URL)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
