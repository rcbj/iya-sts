// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: sts_cells_rehome.js
//
// ===========================================================================
// MOVING A PERSON'S HOME TO ANOTHER CELL (#98 section 8.8, 2026-09-28).
//
// Re-homing is an administrator's act, made at the cell that holds the
// person (`POST /admin-api/cells/rehome`, common/cell_rehome.ts). In a realm
// of the job's own, for a person homed in cell B who is signed in there and
// holds a refresh token:
//
//   1. THE MOVE, made at cell B, answers `{ ok: true, target: <A> }`.
//   2. WHAT THEY HELD IS ENDED: the refresh token they held before the move
//      is refused (`invalid_grant`).
//   3. THEY ARE ONE PERSON THROUGHOUT: cell A's directory holds them and
//      cell B's does not, their entryUUID is the one they had, and the
//      routing index — read at either cell — counts them in cell A and
//      nobody in cell B.
//   4. THEY SIGN IN AGAIN, NOW SERVED AT A: a flow at cell A signs them in
//      with the password they had (sealed again under cell A's key if it was
//      sealed), with no restart elsewhere — nothing of the flow
//      relayed — and the ID Token names the same `sub`.
//   5. A MOVE THE REALM DOES NOT ALLOW IS REFUSED: once the realm lists only
//      cell A's jurisdiction in `cells.jurisdictions`, a move back to cell B
//      answers 400 naming the jurisdiction, and they stay at cell A. And a
//      move asked of a cell that does not hold them is refused as well.
//
// `local: true`: this repository's own `/admin-api`, against a stack only
// this repository's launcher builds. It declines to run in every mode but
// `cells`. The realm is left behind like every throwaway realm
// (tests/CLAUDE.md, *No job removes a realm*).
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

const log = require("bunyan").createLogger({ name: "sts_cells_rehome",
  level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const STAMP = Date.now().toString(36);
const REALM = "cellsrh" + STAMP;
const CLIENT = "cells-rehome-" + STAMP;
const REDIRECT = "https://client.cells.example.test/cb";
const PERSON = "cells-rehome-" + STAMP;
const PASSWORD = "Cells-rehome-" + STAMP + "-Aa1!";

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

// Whether a cell's directory holds the person, by the management API's
// one-person view — `ldap.found`, the directory's own answer: `known` is
// the activity history, which a cell the person signed in at keeps after
// they have moved — and the entryUUID it shows.
async function holds(realmBase, username) {
  log.debug("Entering holds(). " + username);
  const got = await kit.api(realmBase, "GET", "/users?user=" +
                            encodeURIComponent(username));
  assert.strictEqual(got.status, 200, got.raw.slice(0, 300));
  const body = got.body || {};
  const yes = !!(body.ldap && body.ldap.found === true);
  log.debug("Leaving holds(). " + yes);
  return { yes: yes, uuid: yes ? kit.entryUuidIn(body) : "", body: body };
}

// How many requests a cell has relayed to another.
async function relayedAt(realmBase) {
  log.debug("Entering relayedAt().");
  const view = await kit.api(realmBase, "GET", "/cells");
  assert.strictEqual(view.status, 200, view.raw.slice(0, 300));
  log.debug("Leaving relayedAt().");
  return Number((view.body && view.body.placement &&
                 view.body.placement.relayed) || 0);
}

// The index conflicts a cell has counted (`store.routing.conflicts`).
async function conflictsAt(realmBase) {
  log.debug("Entering conflictsAt().");
  const view = await kit.api(realmBase, "GET", "/cells");
  assert.strictEqual(view.status, 200, view.raw.slice(0, 300));
  log.debug("Leaving conflictsAt().");
  return Number((view.body && view.body.store && view.body.store.routing &&
                 view.body.store.routing.conflicts) || 0);
}

// A whole sign-in at one cell, for a person that cell serves, and the
// tokens the code redeems for there.
async function signInAt(realmBase, state) {
  log.debug("Entering signInAt(). " + realmBase);
  const jar = new kit.Jar();
  const pair = kit.pkce();
  const start = kit.authorizeUrl(realmBase, CLIENT, REDIRECT, pair, state);
  const signed = await kit.signInScreen(jar, start, PERSON, PASSWORD);
  assert.ok(signed.posted.status >= 300 && signed.posted.status < 400 &&
            signed.posted.location,
    "the login POST at " + realmBase + " answered " + signed.posted.status +
    " " + kit.said(signed.posted.text));
  const flow = await kit.drive(jar, signed.posted.location, REDIRECT);
  assert.ok(flow.code, "no code at " + realmBase + "; the flow stopped at " +
    JSON.stringify(flow.hops.slice(-2)) + " " +
    (flow.stopped ? flow.stopped.status + " " + kit.said(flow.stopped.text)
                  : flow.error));
  const tokens = await kit.tokenCall(realmBase, {
    grant_type: "authorization_code", code: flow.code,
    redirect_uri: REDIRECT, client_id: CLIENT,
    code_verifier: pair.verifier });
  assert.strictEqual(tokens.status, 200, "the code did not redeem at " +
    realmBase + ": " + tokens.raw.slice(0, 300));
  log.debug("Leaving signInAt().");
  return { jar: jar, hops: flow.hops, tokens: tokens.body };
}

async function setUp(cells) {
  log.debug("Entering setUp().");
  const realm = await kit.throwawayRealm(cells, REALM);
  await kit.publicClient(realm.a, CLIENT, REDIRECT);
  await kit.until("cell B knows the client " + CLIENT, 60000,
                  async function () {
                    const got = await kit.api(realm.b, "GET",
                      "/applications?application=" +
                      encodeURIComponent(CLIENT));
                    return got.status === 200 && got.body && got.body.found;
                  });
  const made = await kit.createPerson(realm.b, PERSON, PASSWORD, "");
  check("the person is created at cell B, homed there", function () {
    assert.strictEqual(made.status, 200, made.raw.slice(0, 300));
  });
  await kit.homed(realm.a, REALM, cells.ids.b, 1);
  log.debug("Leaving setUp().");
  return realm;
}

async function test() {
  log.debug("Entering test().");
  const cells = kit.cellsFromEnv();
  if (!cells) {
    expectation.declineToRun(log, "STS_TEST_CELL_B_URL is not set: this is " +
      "not the `cells` mode (./run-tests.sh --modes=cells), so there is no " +
      "second cell to move a person to.");
    log.debug("Leaving test(). Skipped.");
    return;
  }
  const realm = await setUp(cells);
  const atBBefore = await holds(realm.b, PERSON);
  check("cell B holds them, with an entryUUID", function () {
    assert.ok(atBBefore.yes, JSON.stringify(atBBefore.body).slice(0, 300));
    assert.ok(atBBefore.uuid, "no entryUUID in " +
      JSON.stringify(atBBefore.body).slice(0, 400));
  });

  log.info("=== signed in at home, holding a refresh token ===");
  const before = await signInAt(realm.b, "rh1-" + STAMP);
  const subBefore = kit.claimsOf(before.tokens.id_token).sub;
  kit.verifyJwt(before.tokens.id_token, await kit.jwksAt(realm.b));
  check("signed in at cell B: an ID Token that verifies, and a refresh " +
        "token", function () {
          assert.ok(subBefore, "the ID Token names no sub");
          assert.ok(before.tokens.refresh_token,
            "no refresh token: " + JSON.stringify(before.tokens));
        });

  log.info("=== 1. the move, made at cell B ===");
  const conflictsBefore = await conflictsAt(realm.a);
  const indexBefore = await kit.peopleIn(realm.a, REALM);
  const moved = await kit.api(realm.b, "POST", "/cells/rehome",
                              { username: PERSON, target: cells.ids.a });
  check("POST /admin-api/cells/rehome at cell B answers 200 naming " +
        cells.ids.a, function () {
          assert.strictEqual(moved.status, 200, moved.raw.slice(0, 300));
          assert.ok(moved.body && moved.body.ok === true, moved.raw);
          assert.strictEqual(moved.body.target, cells.ids.a, moved.raw);
        });

  log.info("=== 2. what they held is ended ===");
  const refreshed = await kit.tokenCall(realm.b, {
    grant_type: "refresh_token", refresh_token: before.tokens.refresh_token,
    client_id: CLIENT });
  check("the refresh token held before the move is refused invalid_grant",
        function () {
          assert.strictEqual(refreshed.status, 400,
                             refreshed.raw.slice(0, 300));
          assert.strictEqual(refreshed.body && refreshed.body.error,
                             "invalid_grant", refreshed.raw.slice(0, 300));
        });
  const refreshedAtA = await kit.tokenCall(realm.a, {
    grant_type: "refresh_token", refresh_token: before.tokens.refresh_token,
    client_id: CLIENT });
  check("and presented at cell A, where they are homed now, too",
        function () {
          assert.strictEqual(refreshedAtA.status, 400,
                             refreshedAtA.raw.slice(0, 300));
          assert.strictEqual(refreshedAtA.body && refreshedAtA.body.error,
                             "invalid_grant", refreshedAtA.raw.slice(0, 300));
        });

  log.info("=== 3. one person throughout ===");
  const atA = await holds(realm.a, PERSON);
  const atB = await holds(realm.b, PERSON);
  check("cell A's directory holds them and cell B's does not", function () {
    assert.ok(atA.yes, "cell A does not hold " + PERSON + ": " +
      JSON.stringify(atA.body).slice(0, 300));
    assert.ok(!atB.yes, "cell B still holds " + PERSON + ": " +
      JSON.stringify(atB.body).slice(0, 300));
  });
  check("with the entryUUID they had at cell B", function () {
    assert.strictEqual(atA.uuid, atBBefore.uuid,
                       JSON.stringify(atA.body).slice(0, 400));
  });
  // By difference: the realm's seeded `admin` is homed in cell A, where the
  // realm was created, and is counted there too.
  const wantA = (indexBefore[cells.ids.a] || 0) + 1;
  const wantB = (indexBefore[cells.ids.b] || 0) - 1;
  for (const [label, base] of [["cell A", realm.a], ["cell B", realm.b]]) {
    const counted = await kit.until("the routing index read at " + label +
      " counts them in " + cells.ids.a, 30000, async function () {
        const now = await kit.peopleIn(base, REALM);
        return (now[cells.ids.a] || 0) === wantA &&
               (now[cells.ids.b] || 0) === wantB ? now : null;
      });
    check("the routing index read at " + label + " counts one person more " +
          "in " + cells.ids.a + " and one fewer in " + cells.ids.b,
          function () {
            assert.strictEqual(counted[cells.ids.a] || 0, wantA,
                               JSON.stringify(counted));
          });
  }

  const conflictsAfter = await conflictsAt(realm.a);
  check("and cell A counted no index conflict taking them in", function () {
    assert.strictEqual(conflictsAfter, conflictsBefore,
                       "conflicts " + conflictsBefore + " -> " +
                       conflictsAfter);
  });

  log.info("=== 4. signed in again, now served at cell A ===");
  const quiet = await relayedAt(realm.a);
  const after = await signInAt(realm.a, "rh2-" + STAMP);
  const still = await relayedAt(realm.a);
  check("the login at cell A signs them in there, and nothing of the flow " +
        "was relayed from cell A", function () {
    assert.strictEqual(still, quiet, "cell A relayed " + (still - quiet) +
                       " request(s)");
  });
  kit.verifyJwt(after.tokens.id_token, await kit.jwksAt(realm.a));
  check("the ID Token verifies and names the same sub as before the move",
        function () {
          assert.strictEqual(kit.claimsOf(after.tokens.id_token).sub,
                             subBefore);
        });

  log.info("=== 5. moves that are refused ===");
  const notHere = await kit.api(realm.b, "POST", "/cells/rehome",
                                { username: PERSON, target: cells.ids.a });
  check("a move asked of cell B, which no longer holds them, is refused",
        function () {
          assert.strictEqual(notHere.status, 400, notHere.raw.slice(0, 300));
          assert.ok(/not homed in this cell/i.test(notHere.raw),
                    notHere.raw.slice(0, 300));
        });
  await kit.setSetting(realm.a, "cells.jurisdictions",
                       cells.jurisdictions.a);
  await kit.until("cell A reads the realm's jurisdictions", 30000,
                  async function () {
                    const v = await kit.settingAt(realm.a,
                                                  "cells.jurisdictions");
                    return JSON.stringify(v || "")
                      .indexOf(cells.jurisdictions.a) >= 0;
                  });
  const refused = await kit.api(realm.a, "POST", "/cells/rehome",
                                { username: PERSON, target: cells.ids.b });
  check("with the realm pinned to " + cells.jurisdictions.a + ", a move " +
        "to " + cells.ids.b + " (" + cells.jurisdictions.b + ") is refused " +
        "naming the jurisdiction", function () {
          assert.strictEqual(refused.status, 400, refused.raw.slice(0, 300));
          assert.ok(refused.body && refused.body.ok === false, refused.raw);
          assert.strictEqual(refused.body.code, "STS-CELL-0045",
                             refused.raw.slice(0, 300));
          assert.ok(new RegExp("jurisdiction \"" + cells.jurisdictions.b +
                               "\"").test(String(refused.body.why ||
                                                  (refused.body.errors ||
                                                   []).join(" "))),
                    refused.raw.slice(0, 300));
        });
  const stays = await holds(realm.a, PERSON);
  const notMoved = await holds(realm.b, PERSON);
  check("and they stay at cell A", function () {
    assert.ok(stays.yes && !notMoved.yes,
              JSON.stringify({ a: stays.yes, b: notMoved.yes }));
  });

  assert.ok(checks >= 16, "only " + checks + " checks ran; a section has " +
    "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_cells_rehome")
  .description("a person homed at cell B is moved to cell A: what they held " +
      "is ended, their entryUUID and sub kept, and they sign in at A; a " +
      "move the realm's jurisdictions forbid is refused.")
  .addOption(new Option("-u, --url <url>",
      "base url (unused: the cells come from STS_TEST_CELL_*_URL)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
