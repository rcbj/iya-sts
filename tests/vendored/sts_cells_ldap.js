// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: sts_cells_ldap.js
//
// ===========================================================================
// A DIRECTORY BIND AT A CELL THAT DOES NOT HOLD THE PERSON (#98 D2,
// 2026-09-28).
//
// A person's `userPassword` exists only in their home cell. A simple bind
// at another cell's directory socket names them by DN, finds no entry there,
// and sends the password home over the inter-cell channel; only the verdict
// comes back (ldap/ldap_server.js, `verifyInHomeCell()`). In a realm of the
// job's own, for a person homed at cell A, over LDAPS at cell B's port 636:
//
//   1. cell B's directory does not hold them;
//   2. the right password binds (resultCode 0) — verified at home;
//   3. a wrong one is refused invalidCredentials (49), not unavailable: home
//      answered, and said no.
//
// What a bind does when home CANNOT be asked (STS-CELL-0147, `unavailable`)
// is sts_cells_unreachable.js's, which is the job that can cut a link.
//
// `local: true`: a stack only this repository's launcher builds. It declines
// to run in every mode but `cells`. The realm is left behind like every
// throwaway realm.
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

const log = require("bunyan").createLogger({ name: "sts_cells_ldap",
  level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const STAMP = Date.now().toString(36);
const REALM = "cellsld" + STAMP;
const PERSON = "cells-ldap-" + STAMP;
const PASSWORD = "Cells-ldap-" + STAMP + "-Aa1!";
// LDAP resultCodes (RFC 4511 section 4.1.9).
const LDAP_INVALID_CREDENTIALS = 49;

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

async function test() {
  log.debug("Entering test().");
  const cells = kit.cellsFromEnv();
  if (!cells) {
    expectation.declineToRun(log, "STS_TEST_CELL_B_URL is not set: this is " +
      "not the `cells` mode (./run-tests.sh --modes=cells), so there is no " +
      "second cell's directory to bind at.");
    log.debug("Leaving test(). Skipped.");
    return;
  }
  const realm = await kit.throwawayRealm(cells, REALM);
  const made = await kit.createPerson(realm.a, PERSON, PASSWORD, "");
  check("the person is created at cell A, homed there", function () {
    assert.strictEqual(made.status, 200, made.raw.slice(0, 300));
    assert.ok(made.body && made.body.dn, "no dn: " + made.raw.slice(0, 300));
  });
  const dn = String(made.body.dn);
  await kit.homed(realm.b, REALM, cells.ids.a, 1);

  const atB = await kit.api(realm.b, "GET", "/users?user=" +
                            encodeURIComponent(PERSON));
  check("cell B's directory does not hold them", function () {
    assert.strictEqual(atB.status, 200, atB.raw.slice(0, 300));
    // `ldap` is absent for a name the cell has never seen at all.
    assert.ok(!(atB.body && atB.body.ldap && atB.body.ldap.found),
              atB.raw.slice(0, 300));
  });

  const good = await kit.ldapBind(cells.b, dn, PASSWORD);
  check("a simple bind as " + dn + " at cell B's LDAPS, with the right " +
        "password, succeeds: verified at home", function () {
          assert.strictEqual(good.code, 0, JSON.stringify(good));
        });
  const bad = await kit.ldapBind(cells.b, dn, PASSWORD + "-wrong");
  check("and with a wrong one is refused invalidCredentials (49) — home " +
        "answered, and said no", function () {
          assert.strictEqual(bad.code, LDAP_INVALID_CREDENTIALS,
                             JSON.stringify(bad));
        });

  assert.ok(checks >= 4, "only " + checks + " checks ran; a section has " +
    "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_cells_ldap")
  .description("a simple bind at cell B's directory for a person homed at " +
      "cell A is verified at home.")
  .addOption(new Option("-u, --url <url>",
      "base url (unused: the cells come from STS_TEST_CELL_*_URL)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
