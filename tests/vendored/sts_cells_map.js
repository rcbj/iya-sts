// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: sts_cells_map.js
//
// ===========================================================================
// THE CELL MAP, AS EACH CELL REPORTS IT (#98, 2026-09-28).
//
// `GET /admin-api/cells` at each of the `cells` mode's two cells:
//
//   * two cells, this one and one peer, each in the jurisdiction the stack
//     gave it (STS_TEST_CELLS) and each naming the other;
//   * the peer REACHABLE — asked `cell-ping` over the inter-cell channel,
//     mutual TLS on 8446, with a leaf from the `cell` Issuing CA — and
//     reporting the jurisdiction this cell has it in;
//   * the store TIERED: the global tier's database and the cell's own;
//   * the channel listening, with the ping among its operations;
//   * and the PEER'S ADDRESS NOWHERE IN WHAT THE MAP REPORTS. A cell is
//     never published (#98 section 2): the map names cells, never where
//     they are. (The answer's `settings` block is the Cells settings group
//     the page's form edits, and `cells.peers` there is the configured
//     value — that block is left out of the check, and only it.)
//
// `local: true`: it drives this repository's own `/admin-api`, and the stack
// it asserts about exists only in this repository's launcher. It declines to
// run in every mode but `cells`, naming the variable it looked for.
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

const log = require("bunyan").createLogger({ name: "sts_cells_map",
  level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

// One cell's report, asserted against what the stack says it is.
async function assertCell(label, url, self, peer, peerAddress) {
  log.debug("Entering assertCell(). " + label);
  const got = await kit.api(url, "GET", "/cells");
  check(label + ": GET /admin-api/cells answers 200", function () {
    assert.strictEqual(got.status, 200, got.raw.slice(0, 300));
  });
  const view = got.body || {};
  check(label + ": it is cell " + self.id + " in jurisdiction " +
        self.jurisdiction + ", deployed as cells", function () {
          assert.strictEqual(view.multi, true, "multi is " + view.multi);
          assert.strictEqual(view.cell, self.id);
          assert.strictEqual(view.jurisdiction, self.jurisdiction);
        });
  check(label + ": its one peer is " + peer.id + " in " + peer.jurisdiction,
        function () {
          assert.ok(Array.isArray(view.peers), "no peers list");
          assert.strictEqual(view.peers.length, 1,
            JSON.stringify(view.peers));
          assert.strictEqual(view.peers[0].id, peer.id);
          assert.strictEqual(view.peers[0].jurisdiction, peer.jurisdiction);
        });
  check(label + ": the peer is reachable over the channel and reports the " +
        "same jurisdiction", function () {
          const p = view.peers[0];
          assert.strictEqual(p.reachable, true,
            "the peer is not reachable: " + (p.error || JSON.stringify(p)));
          assert.strictEqual(p.reportedJurisdiction, peer.jurisdiction);
        });
  check(label + ": the store is tiered", function () {
    assert.strictEqual(view.store && view.store.tiered, true,
      JSON.stringify(view.store || {}).slice(0, 300));
  });
  check(label + ": the channel listens and answers the ping", function () {
    const ch = view.channel || {};
    assert.strictEqual(ch.listening, true,
      "the inter-cell listener is not up: " + (ch.listenError || ""));
    assert.ok((ch.operations || []).indexOf("cell-ping") >= 0,
      "cell-ping is not among " + JSON.stringify(ch.operations));
  });
  // THE SETTINGS BLOCK IS LEFT OUT, and only it: it is the Cells settings
  // group as the page's form draws it, `cells.peers` among them — the
  // configured value an administrator edits, where the address has to be.
  // Everything the map REPORTS is asserted to carry none.
  const reported = Object.assign({}, view);
  delete reported.settings;
  check(label + ": and the peer's address is nowhere in what the map " +
        "reports", function () {
          assert.ok(JSON.stringify(reported).indexOf(peerAddress) < 0,
            "the answer names " + peerAddress);
          view.peers.forEach(function (p) {
            assert.ok(!("url" in p) && !("address" in p),
              "a peer carries an address member: " + JSON.stringify(p));
          });
        });
  log.debug("Leaving assertCell().");
}

async function test() {
  log.debug("Entering test().");
  const cells = kit.cellsFromEnv();
  if (!cells) {
    expectation.declineToRun(log, "STS_TEST_CELL_B_URL is not set: this is " +
      "not the `cells` mode (./run-tests.sh --modes=cells), so there is no " +
      "second cell to report.");
    log.debug("Leaving test(). Skipped.");
    return;
  }
  const a = { id: cells.ids.a, jurisdiction: cells.jurisdictions.a };
  const b = { id: cells.ids.b, jurisdiction: cells.jurisdictions.b };
  // The peers' private names, as the layer gives them: the host each cell's
  // channel is dialled at.
  await assertCell("cell A", cells.a, a, b,
                   new URL(cells.b).hostname + ":8446");
  await assertCell("cell B", cells.b, b, a,
                   new URL(cells.a).hostname + ":8446");
  assert.ok(checks >= 14, "only " + checks + " checks ran; a section has " +
    "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_cells_map")
  .description("each of two cells reports both cells, the peer reachable " +
      "over the channel, a tiered store, and no cell's address.")
  .addOption(new Option("-u, --url <url>",
      "base url (unused: the cells come from STS_TEST_CELL_*_URL)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
