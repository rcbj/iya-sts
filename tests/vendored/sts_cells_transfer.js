// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: sts_cells_transfer.js
//
// ===========================================================================
// A SESSION HELD AWAY FROM HOME WHERE THE REALM PERMITS IT, AND HOME'S
// AUTHORITY OVER IT (#98 D4, D6, D9, 2026-09-28).
//
// The strict default relays a traveller's every request home. A realm that
// LISTS a transfer — `cells.permittedTransfers` = `ca>us`: a session of a
// person homed in `ca` may be held in a `us` cell — loosens it, and the
// issuance policy decides on that fact (`hold-session`). In a realm of the
// job's own, with that one entry, the job is a browser at cell A for a
// person homed at cell B:
//
//   1. The flow restarts at home and the person signs in there (D9), exactly
//      as sts_cells_traveller.js shows under the strict default.
//   2. THE EXPORT: the next request cell A relays home carries the session,
//      and home COPIES it to cell A with a credential-free projection of the
//      person, moving the browser's pin to cell A on that response. Cell A
//      then reports a projection held, and cell B an export made.
//   3. SERVED AT CELL A: a second authorization request with the browser's
//      cookies is answered with a code and no sign-in, and neither it nor
//      the code's redemption is relayed — cell A's relay counter does not
//      move — and the tokens verify against the realm's one key set.
//   4. HOME IS AUTHORITATIVE (D6): the person is DISABLED at cell B. Home
//      pushes the revocation to every cell holding an export, and within a
//      bound cell A holds the projection no longer, a refresh at cell A is
//      refused, and the browser's next authorization request at cell A is
//      not answered with a code.
//
// **WARNING, AS THE SETTING SAYS**: each entry of `cells.permittedTransfers`
// is a decision that personal data may be processed in the serving
// jurisdiction. This realm is a test's, and is left behind like every
// throwaway realm (tests/CLAUDE.md, *No job removes a realm*).
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

const log = require("bunyan").createLogger({ name: "sts_cells_transfer",
  level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const STAMP = Date.now().toString(36);
const REALM = "cellsxf" + STAMP;
const CLIENT = "cells-transfer-" + STAMP;
const REDIRECT = "https://client.cells.example.test/cb";
const PERSON = "cells-xfer-" + STAMP;
const PASSWORD = "Cells-transfer-" + STAMP + "-Aa1!";
// How long home's revocation may take to reach cell A: a durable delivery
// sent at once and retried (cells.deliveryBackoffMs), and — should the push
// be lost — cell A's own check against home (cells.subjectCheckS, 60 s).
const REVOCATION_BOUND_MS = 90000;

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function authorizeUrl(realmBase, pair, state) {
  log.debug("Entering authorizeUrl().");
  log.debug("Leaving authorizeUrl().");
  return realmBase + "/oauth2/authorize?" + new URLSearchParams({
    response_type: "code", client_id: CLIENT, redirect_uri: REDIRECT,
    scope: "openid profile", state: state, code_challenge: pair.challenge,
    code_challenge_method: "S256" }).toString();
}

// A cell's own report: relayed requests, projections held, exports made.
async function reportAt(realmBase) {
  log.debug("Entering reportAt().");
  const view = await kit.api(realmBase, "GET", "/cells");
  assert.strictEqual(view.status, 200, view.raw.slice(0, 300));
  const body = view.body || {};
  log.debug("Leaving reportAt().");
  return {
    relayed: Number((body.placement && body.placement.relayed) || 0),
    projections: Number((body.sessions && body.sessions.projections) || 0),
    exports: Number((body.sessions && body.sessions.exports) || 0)
  };
}

async function tokenCall(realmBase, form) {
  log.debug("Entering tokenCall().");
  const r = await fetch(realmBase + "/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded",
               Accept: "application/json" },
    body: new URLSearchParams(form).toString()
  });
  const raw = await r.text();
  let body = null;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    // Asserted on with the raw text.
    log.debug("Caught in tokenCall(): " + ((e && e.message) || e));
    body = null;
  }
  log.debug("Leaving tokenCall(). " + r.status);
  return { status: r.status, body: body, raw: raw };
}

async function setUp(cells) {
  log.debug("Entering setUp().");
  const realm = await kit.throwawayRealm(cells, REALM);
  await kit.setSetting(realm.a, "cells.permittedTransfers", "ca>us");
  await kit.until("cell B reads the realm's permitted transfer", 60000,
                  async function () {
                    const v = await kit.settingAt(realm.b,
                                                  "cells.permittedTransfers");
                    return JSON.stringify(v || "").indexOf("ca>us") >= 0;
                  });
  check("the realm lists ca>us, read at both cells", function () {
    assert.ok(true);
  });
  await kit.publicClient(realm.a, CLIENT, REDIRECT);
  await kit.until("cell B knows the client " + CLIENT, 60000,
                  async function () {
                    const got = await kit.api(realm.b, "GET",
                      "/applications?application=" +
                      encodeURIComponent(CLIENT));
                    return got.status === 200 && got.body && got.body.found;
                  });
  const made = await kit.createPerson(realm.a, PERSON, PASSWORD,
                                      cells.ids.b);
  check("the traveller is created, homed in " + cells.ids.b, function () {
    assert.strictEqual(made.status, 200, made.raw.slice(0, 300));
  });
  await kit.homed(realm.a, REALM, cells.ids.b, 1);
  log.debug("Leaving setUp().");
  return realm;
}

// Signs the traveller in through cell A, the D9 way, and follows the flow
// to the client. Answers the jar, the code, the verifier and the pins seen.
async function signInThroughA(realm) {
  log.debug("Entering signInThroughA().");
  const jar = new kit.Jar();
  const pair = kit.pkce();
  const start = authorizeUrl(realm.a, pair, "xf-" + STAMP);
  const first = await kit.browse(jar, start);
  const screen = await kit.browse(jar, first.location);
  const fields = kit.signInFields(screen.text);
  const at = new URL(first.location);
  const posted = await kit.browse(jar, at.origin + at.pathname,
    { form: { authn_id: fields.authnId, username: PERSON, password: PASSWORD,
              action: "login", csrf_token: fields.csrf } });
  const homePin = jar.get("sts_cell");
  check("the login at cell A restarts the flow at home, pinned", function () {
    assert.strictEqual(posted.status, 303, posted.status + " " +
      kit.said(posted.text));
    assert.ok(homePin, "no pin: " + JSON.stringify(posted.set));
  });
  const again = await kit.browse(jar, start);
  const homeScreen = await kit.browse(jar, again.location);
  const homeFields = kit.signInFields(homeScreen.text);
  const homeAt = new URL(again.location);
  const signedIn = await kit.browse(jar, homeAt.origin + homeAt.pathname,
    { form: { authn_id: homeFields.authnId, username: PERSON,
              password: PASSWORD, action: "login",
              csrf_token: homeFields.csrf } });
  check("and the person signs in at home through cell A", function () {
    assert.ok(signedIn.status >= 300 && signedIn.status < 400,
      signedIn.status + " " + kit.said(signedIn.text));
  });
  const flow = await kit.drive(jar, signedIn.location, REDIRECT);
  check("the flow ends at the client with a code", function () {
    assert.ok(flow.code, "no code; the flow stopped at " +
      JSON.stringify(flow.hops.slice(-2)) + " " +
      (flow.stopped ? flow.stopped.status + " " +
                      kit.said(flow.stopped.text) : flow.error));
  });
  log.debug("Leaving signInThroughA().");
  return { jar: jar, code: flow.code, verifier: pair.verifier,
           homePin: homePin, hops: flow.hops };
}

async function test() {
  log.debug("Entering test().");
  const cells = kit.cellsFromEnv();
  if (!cells) {
    expectation.declineToRun(log, "STS_TEST_CELL_B_URL is not set: this is " +
      "not the `cells` mode (./run-tests.sh --modes=cells), so there is no " +
      "second cell to hold a session in.");
    log.debug("Leaving test(). Skipped.");
    return;
  }
  const realm = await setUp(cells);
  const beforeA = await reportAt(realm.a);
  const beforeB = await reportAt(realm.b);

  log.info("=== 1 and 2. signed in at home, and the session exported ===");
  const signed = await signInThroughA(realm);
  check("the pin moved: a response relayed home re-pinned the browser to " +
        "another cell", function () {
          const pin = signed.jar.get("sts_cell");
          assert.ok(pin && pin !== signed.homePin,
            "the pin is still home's: " + pin + " (hops " +
            JSON.stringify(signed.hops.map(function (h) {
              return h.status + " " + h.set.join(",");
            })) + ")");
        });
  const exported = await kit.until("cell A reports the projection held", 30000,
    async function () {
      const now = await reportAt(realm.a);
      return now.projections > beforeA.projections ? now : null;
    });
  const home = await reportAt(realm.b);
  check("cell A holds one more projection, and cell B reports the export",
        function () {
          assert.ok(exported.projections > beforeA.projections);
          assert.ok(home.exports > beforeB.exports,
            "exports at cell B " + beforeB.exports + " -> " + home.exports);
        });

  log.info("=== 3. served at cell A ===");
  const firstTokens = await tokenCall(realm.a, {
    grant_type: "authorization_code", code: signed.code,
    redirect_uri: REDIRECT, client_id: CLIENT,
    code_verifier: signed.verifier });
  check("the code of the flow redeems at cell A", function () {
    assert.strictEqual(firstTokens.status, 200,
                       firstTokens.raw.slice(0, 300));
  });
  const pair = kit.pkce();
  const quiet = await reportAt(realm.a);
  const second = await kit.drive(signed.jar, authorizeUrl(realm.a, pair,
                                 "xf2-" + STAMP), REDIRECT);
  check("a second authorization request with the browser's cookies is " +
        "answered with a code and no sign-in", function () {
          assert.ok(second.code, "no code; stopped at " +
            JSON.stringify(second.hops.slice(-2)) + " " +
            (second.stopped ? second.stopped.status + " " +
                              kit.said(second.stopped.text) : second.error));
        });
  const tokens = await tokenCall(realm.a, {
    grant_type: "authorization_code", code: second.code,
    redirect_uri: REDIRECT, client_id: CLIENT, code_verifier: pair.verifier });
  const still = await reportAt(realm.a);
  check("and its code redeems at cell A", function () {
    assert.strictEqual(tokens.status, 200, tokens.raw.slice(0, 300));
  });
  check("with nothing relayed: the session is served where it is held",
        function () {
          assert.strictEqual(still.relayed, quiet.relayed,
            "cell A relayed " + (still.relayed - quiet.relayed) +
            " request(s)");
        });
  const jwks = await kit.jwksAt(realm.a);
  kit.verifyJwt(tokens.body.id_token, jwks);
  check("and its ID Token verifies against the realm's one key set",
        function () {
          assert.ok(true);
        });

  log.info("=== 4. disabled at home, ended at cell A (D6) ===");
  const disabled = await kit.api(realm.b, "POST", "/users/disable",
                                 { user: PERSON });
  check("the person is disabled at cell B", function () {
    assert.strictEqual(disabled.status, 200, disabled.raw.slice(0, 300));
  });
  const ended = await kit.until("cell A drops the projection",
    REVOCATION_BOUND_MS, async function () {
      const now = await reportAt(realm.a);
      return now.projections < exported.projections ? now : null;
    });
  check("within " + (REVOCATION_BOUND_MS / 1000) + " s cell A holds the " +
        "projection no longer", function () {
          assert.ok(ended.projections < exported.projections);
        });
  const refreshToken = (tokens.body && tokens.body.refresh_token) ||
    (firstTokens.body && firstTokens.body.refresh_token) || "";
  if (refreshToken) {
    const refreshed = await tokenCall(realm.a, {
      grant_type: "refresh_token", refresh_token: refreshToken,
      client_id: CLIENT });
    check("a refresh at cell A is refused", function () {
      assert.strictEqual(refreshed.status, 400, refreshed.raw.slice(0, 300));
      assert.strictEqual(refreshed.body && refreshed.body.error,
                         "invalid_grant", refreshed.raw.slice(0, 300));
    });
  }
  const pair3 = kit.pkce();
  const after = await kit.drive(signed.jar, authorizeUrl(realm.a, pair3,
                                "xf3-" + STAMP), REDIRECT);
  check("and the browser's next authorization request at cell A is not " +
        "answered with a code", function () {
          assert.ok(!after.code, "a code was issued after the disable");
        });

  assert.ok(checks >= 14, "only " + checks + " checks ran; a section has " +
    "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_cells_transfer")
  .description("a realm listing ca>us holds a traveller's session at cell A " +
      "with a projection; a disable at home ends it there.")
  .addOption(new Option("-u, --url <url>",
      "base url (unused: the cells come from STS_TEST_CELL_*_URL)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
