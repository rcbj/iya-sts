// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: sts_cells_unreachable.js
//
// ===========================================================================
// WHEN A PERSON'S HOME CELL CANNOT BE REACHED (#98 D6, 2026-09-28).
//
// `cells.homeUnreachable` decides: `fail-closed`, the default, refuses a
// sign-in, a refresh and a directory bind for a person homed in a cell this
// one cannot reach; `fail-open` lets a session HELD here be refreshed on
// home's last confirmation for up to `cells.failOpenGraceS`, and opens
// nothing else.
//
// HOW HOME IS MADE UNREACHABLE: cell A dials cell B through a link the
// `cells` mode's layer puts between them (tests/tools/cell_link.js), and the
// job cuts it with a POST to the link's control port — cell B stays up,
// and still reaches cell A. It is restored, with the setting, however the
// job ends; a job after this one that found the link down would fail for a
// reason of this one's.
//
// In a realm of the job's own that lists `ca>us` — so a session of a person
// homed in cell B can be HELD at cell A (sts_cells_transfer.js) — for such a
// person, signed in through cell A with the session exported there and a
// refresh token minted at A:
//
//   1. WHILE HOME ANSWERS: a refresh at cell A is confirmed at home and
//      answered, and a bind at cell A's directory is verified at home.
//   2. FAIL-CLOSED (the default), the link cut: the refresh is refused
//      `invalid_grant` naming the unreachable home (STS-CELL-0056); a new
//      sign-in at cell A restarts at home and is answered 503 with a
//      Retry-After (STS-CELL-0030); a bind at cell A's directory is refused
//      `unavailable` (STS-CELL-0147).
//   3. FAIL-OPEN, still cut: the same refresh token — which the refusal did
//      not spend — is answered on home's last confirmation; a new sign-in is
//      still 503, because fail-open covers a session held here and nothing
//      that needs home's credentials.
//   4. RESTORED: the setting reset and the link up, a refresh is confirmed
//      at home again.
//
// `local: true`: this repository's own `/admin-api`, against a stack only
// this repository's launcher builds. It declines to run in every mode but
// `cells`. **WARNING, AS THE SETTINGS SAY**: `ca>us` and `fail-open` are
// both loosenings a real realm has to decide on; this realm is a test's, and
// is left behind like every throwaway realm.
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

const log = require("bunyan").createLogger({ name: "sts_cells_unreachable",
  level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const STAMP = Date.now().toString(36);
const REALM = "cellsur" + STAMP;
const CLIENT = "cells-unreach-" + STAMP;
const REDIRECT = "https://client.cells.example.test/cb";
const PERSON = "cells-unreach-" + STAMP;
const PASSWORD = "Cells-unreach-" + STAMP + "-Aa1!";
// LDAP resultCodes (RFC 4511 section 4.1.9).
const LDAP_UNAVAILABLE = 52;

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

async function projectionsAt(realmBase) {
  log.debug("Entering projectionsAt().");
  const view = await kit.api(realmBase, "GET", "/cells");
  assert.strictEqual(view.status, 200, view.raw.slice(0, 300));
  log.debug("Leaving projectionsAt().");
  return Number((view.body && view.body.sessions &&
                 view.body.sessions.projections) || 0);
}

async function setUp(cells) {
  log.debug("Entering setUp().");
  const realm = await kit.throwawayRealm(cells, REALM);
  await kit.setSetting(realm.a, "cells.permittedTransfers",
                       cells.jurisdictions.b + ">" + cells.jurisdictions.a);
  await kit.until("cell B reads the realm's permitted transfer", 60000,
                  async function () {
                    const v = await kit.settingAt(realm.b,
                                                  "cells.permittedTransfers");
                    return JSON.stringify(v || "").indexOf(
                      cells.jurisdictions.b + ">" +
                      cells.jurisdictions.a) >= 0;
                  });
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
    assert.ok(made.body && made.body.dn, "no dn: " + made.raw.slice(0, 300));
  });
  await kit.homed(realm.a, REALM, cells.ids.b, 1);
  log.debug("Leaving setUp().");
  return { realm: realm, dn: String(made.body.dn) };
}

// Signs the person in through cell A the D9 way — the login at A restarts
// at home, and the pinned flow signs in there — and then asks cell A again
// once the session is exported, for a code minted AT A. Answers that code's
// tokens.
async function heldAtA(realm) {
  log.debug("Entering heldAtA().");
  const before = await projectionsAt(realm.a);
  const jar = new kit.Jar();
  const pair = kit.pkce();
  const start = kit.authorizeUrl(realm.a, CLIENT, REDIRECT, pair,
                                 "ur-" + STAMP);
  const atA = await kit.signInScreen(jar, start, PERSON, PASSWORD);
  assert.strictEqual(atA.posted.status, 303, atA.posted.status + " " +
    kit.said(atA.posted.text));
  const atHome = await kit.signInScreen(jar, start, PERSON, PASSWORD);
  assert.ok(atHome.posted.status >= 300 && atHome.posted.status < 400,
    atHome.posted.status + " " + kit.said(atHome.posted.text));
  const flow = await kit.drive(jar, atHome.posted.location, REDIRECT);
  assert.ok(flow.code, "no code; the flow stopped at " +
    JSON.stringify(flow.hops.slice(-2)));
  await kit.until("cell A holds the exported session", 30000,
                  async function () {
                    return (await projectionsAt(realm.a)) > before;
                  });
  const again = kit.pkce();
  const second = await kit.drive(jar, kit.authorizeUrl(realm.a, CLIENT,
                                 REDIRECT, again, "ur2-" + STAMP), REDIRECT);
  assert.ok(second.code, "no code at cell A for the held session; stopped " +
    "at " + JSON.stringify(second.hops.slice(-2)));
  const tokens = await kit.tokenCall(realm.a, {
    grant_type: "authorization_code", code: second.code,
    redirect_uri: REDIRECT, client_id: CLIENT,
    code_verifier: again.verifier });
  assert.strictEqual(tokens.status, 200, tokens.raw.slice(0, 300));
  log.debug("Leaving heldAtA().");
  return tokens.body;
}

// A new sign-in at cell A, in a new browser: the login restarts at home,
// and the request pinned there is what cell A has to relay.
async function newSignInAtA(realm, state) {
  log.debug("Entering newSignInAtA().");
  const jar = new kit.Jar();
  const start = kit.authorizeUrl(realm.a, CLIENT, REDIRECT, kit.pkce(),
                                 state);
  const signed = await kit.signInScreen(jar, start, PERSON, PASSWORD);
  assert.strictEqual(signed.posted.status, 303, signed.posted.status + " " +
    kit.said(signed.posted.text));
  const relayed = await kit.browse(jar, signed.posted.location ||
                                   start);
  log.debug("Leaving newSignInAtA(). " + relayed.status);
  return { pinned: !!jar.get("sts_cell"), answer: relayed };
}

function refresh(realm, token) {
  log.debug("Entering refresh().");
  log.debug("Leaving refresh().");
  return kit.tokenCall(realm.a, { grant_type: "refresh_token",
                                  refresh_token: token, client_id: CLIENT });
}

async function restore(realm) {
  log.debug("Entering restore().");
  let problem = null;
  try {
    const reset = await kit.api(realm.a, "POST", "/config/reset",
                                { key: "cells.homeUnreachable" });
    // A 400 is "there was no override", which is what restored means.
    log.info("  (cells.homeUnreachable reset: " + reset.status + ")");
  } catch (e) {
    log.debug("Caught in restore(): " + ((e && e.message) || e));
    problem = e;
  }
  const state = await kit.link("POST", "up");
  log.info("  (the link is " + (state.up ? "up" : "DOWN") + " again)");
  if (problem) {
    log.debug("Leaving restore(). With a problem.");
    throw problem;
  }
  log.debug("Leaving restore().");
}

async function whileCut(cells, realm, dn, held) {
  log.debug("Entering whileCut().");
  log.info("=== 2. fail-closed, home unreachable ===");
  const mode = await kit.settingAt(realm.a, "cells.homeUnreachable");
  check("cells.homeUnreachable is fail-closed, the default", function () {
    assert.strictEqual(mode, "fail-closed");
  });
  const cut = await kit.link("POST", "down");
  check("the link is cut: cell A cannot reach cell B", function () {
    assert.strictEqual(cut.up, false, JSON.stringify(cut));
  });
  const closed = await refresh(realm, held);
  check("a refresh at cell A is refused invalid_grant, naming the " +
        "unreachable home", function () {
          assert.strictEqual(closed.status, 400, closed.raw.slice(0, 300));
          assert.strictEqual(closed.body && closed.body.error,
                             "invalid_grant", closed.raw.slice(0, 300));
          assert.ok(/cannot be reached/.test(String(
            closed.body.error_description || "")), closed.raw.slice(0, 300));
        });
  const signIn = await newSignInAtA(realm, "ur3-" + STAMP);
  check("a new sign-in at cell A restarts at home and is answered 503 " +
        "with a Retry-After", function () {
          assert.ok(signIn.pinned, "the login did not pin the browser home");
          assert.strictEqual(signIn.answer.status, 503,
            signIn.answer.status + " " + kit.said(signIn.answer.text));
          assert.ok(/cannot reach the region/.test(signIn.answer.text),
                    kit.said(signIn.answer.text));
        });
  const bind = await kit.ldapBind(cells.a, dn, PASSWORD);
  check("a bind at cell A's directory is refused unavailable (52), not " +
        "invalidCredentials", function () {
          assert.strictEqual(bind.code, LDAP_UNAVAILABLE,
                             JSON.stringify(bind));
        });

  log.info("=== 3. fail-open, still unreachable ===");
  await kit.setSetting(realm.a, "cells.homeUnreachable", "fail-open");
  const grace = Number(await kit.settingAt(realm.a, "cells.failOpenGraceS"));
  check("cells.homeUnreachable is fail-open at cell A, with a grace of " +
        grace + " s", function () {
          assert.ok(grace > 0, "no grace: " + grace);
        });
  const open = await refresh(realm, held);
  check("the same refresh token, not spent by the refusal, is answered on " +
        "home's last confirmation", function () {
          assert.strictEqual(open.status, 200, open.raw.slice(0, 300));
          assert.ok(open.body && open.body.refresh_token, open.raw);
        });
  const stillRefused = await newSignInAtA(realm, "ur4-" + STAMP);
  check("a new sign-in is still 503: fail-open covers a session held here " +
        "and nothing that needs home", function () {
          assert.strictEqual(stillRefused.answer.status, 503,
            stillRefused.answer.status + " " +
            kit.said(stillRefused.answer.text));
        });
  log.debug("Leaving whileCut().");
  return open.body.refresh_token;
}

async function test() {
  log.debug("Entering test().");
  const cells = kit.cellsFromEnv();
  if (!cells) {
    expectation.declineToRun(log, "STS_TEST_CELL_B_URL is not set: this is " +
      "not the `cells` mode (./run-tests.sh --modes=cells), so there is no " +
      "second cell to lose.");
    log.debug("Leaving test(). Skipped.");
    return;
  }
  const linkState = await kit.link("GET", "state");
  check("the link between the cells is up", function () {
    assert.strictEqual(linkState.up, true, JSON.stringify(linkState));
  });
  const made = await setUp(cells);
  const realm = made.realm;

  log.info("=== 1. while home answers ===");
  const tokens = await heldAtA(realm);
  const first = await refresh(realm, tokens.refresh_token);
  check("a refresh at cell A of a session held there is confirmed at home " +
        "and answered", function () {
          assert.strictEqual(first.status, 200, first.raw.slice(0, 300));
          assert.ok(first.body && first.body.refresh_token, first.raw);
        });
  const bound = await kit.ldapBind(cells.a, made.dn, PASSWORD);
  check("a bind at cell A's directory is verified at home", function () {
    assert.strictEqual(bound.code, 0, JSON.stringify(bound));
  });

  let latest = first.body.refresh_token;
  try {
    latest = await whileCut(cells, realm, made.dn, latest);
  } finally {
    log.info("=== 4. restored ===");
    await restore(realm);
  }
  const mode = await kit.settingAt(realm.a, "cells.homeUnreachable");
  const back = await refresh(realm, latest);
  check("restored — fail-closed again, the link up — a refresh is " +
        "confirmed at home and answered", function () {
          assert.strictEqual(mode, "fail-closed");
          assert.strictEqual(back.status, 200, back.raw.slice(0, 300));
        });

  assert.ok(checks >= 13, "only " + checks + " checks ran; a section has " +
    "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_cells_unreachable")
  .description("with cell B cut off from cell A, fail-closed refuses a " +
      "refresh, a sign-in and a bind for a person homed at B; fail-open " +
      "refreshes a session held at A on home's last confirmation.")
  .addOption(new Option("-u, --url <url>",
      "base url (unused: the cells come from STS_TEST_CELL_*_URL)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
