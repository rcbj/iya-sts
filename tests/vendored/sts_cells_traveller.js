// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: sts_cells_traveller.js
//
// ===========================================================================
// THE TRAVELLER: A FLOW STARTED AT ONE CELL FOR A PERSON HOMED AT THE OTHER
// (#98 D8, D9, D10, 2026-09-28).
//
// Every cell answers on the service's one name, so a browser reaches the cell
// DNS chose. This job IS that browser, and every request it makes goes to
// cell A — the traveller never addresses cell B. The person is homed in cell
// B, under the STRICT default (nothing personal leaves its jurisdiction), in
// a realm of the job's own:
//
//   1. THE RESTART (D9). The authorization request starts at cell A, and the
//      sign-in screen is cell A's. The login name names a person homed in
//      cell B, so the login POST answers 303 back to the ORIGINAL
//      authorization request — nothing verified, counted or spent at A — and
//      pins the browser to cell B with the `sts_cell` cookie.
//   2. FOLLOWED WITH THE PIN, cell A relays every request to cell B: the
//      authorization request starts again there, and the sign-in screen it
//      sends the browser to is cell B's — the same URL at cell A without
//      the pin is a sign-in cell A does not hold.
//   3. THE PASSWORD POST at cell A is relayed to cell B and signs the person
//      in there, and the flow ends at the client with a code minted AT CELL
//      B. Redeemed at cell A, it is relayed by its sealed locator (D10) —
//      cell A's relay counter moves — and answers tokens.
//   4. ONE SET OF REALM KEYS (D8): the ID Token and the access token verify
//      against cell A's key set, and cell B publishes the same keys.
//   5. A PUSHED REQUEST (D10): a PAR pushed at cell B, and the authorization
//      request that names its request_uri started at cell A with no pin,
//      reaches cell B — cell A holds no such request and could only refuse
//      it — and the flow continues there to a code.
//
// `local: true`: this repository's own `/admin-api` sets it up, against a
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

const log = require("bunyan").createLogger({ name: "sts_cells_traveller",
  level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const STAMP = Date.now().toString(36);
const REALM = "cellstv" + STAMP;
const CLIENT = "cells-traveller-" + STAMP;
const REDIRECT = "https://client.cells.example.test/cb";
const PERSON = "cells-trav-" + STAMP;
const PASSWORD = "Cells-traveller-" + STAMP + "-Aa1!";

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

// The authorization request, as the client builds it.
function authorizeUrl(realmBase, pair, state) {
  log.debug("Entering authorizeUrl().");
  log.debug("Leaving authorizeUrl().");
  return realmBase + "/oauth2/authorize?" + new URLSearchParams({
    response_type: "code", client_id: CLIENT, redirect_uri: REDIRECT,
    scope: "openid profile", state: state, code_challenge: pair.challenge,
    code_challenge_method: "S256" }).toString();
}

// How many requests cell A has relayed, from its own report.
async function relayedAt(realmBase) {
  log.debug("Entering relayedAt().");
  const view = await kit.api(realmBase, "GET", "/cells");
  assert.strictEqual(view.status, 200, view.raw.slice(0, 300));
  log.debug("Leaving relayedAt().");
  return Number((view.body.placement && view.body.placement.relayed) || 0);
}

// The token endpoint, as a public client calls it.
async function redeem(realmBase, code, verifier) {
  log.debug("Entering redeem().");
  const r = await fetch(realmBase + "/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded",
               Accept: "application/json" },
    body: new URLSearchParams({ grant_type: "authorization_code", code: code,
                                redirect_uri: REDIRECT, client_id: CLIENT,
                                code_verifier: verifier }).toString()
  });
  const raw = await r.text();
  let body = null;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    // The status and the raw text are asserted on instead.
    log.debug("Caught in redeem(): " + ((e && e.message) || e));
    body = null;
  }
  log.debug("Leaving redeem(). " + r.status);
  return { status: r.status, body: body, raw: raw };
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
  const made = await kit.createPerson(realm.a, PERSON, PASSWORD,
                                      cells.ids.b);
  check("the traveller is created at cell A, homed in " + cells.ids.b,
        function () {
          assert.strictEqual(made.status, 200, made.raw.slice(0, 300));
        });
  // NO WAIT FOR THE INDEX HERE, deliberately. A relayed creation claims its
  // login name at the home cell before it answers, so the sign-in below may
  // start at once; until 2026-09-28 it waited for the home cell's flush,
  // and a sign-in in that half second was answered at the wrong cell.
  log.debug("Leaving setUp().");
  return realm;
}

async function theRestart(cells, realm) {
  log.debug("Entering theRestart().");
  const jar = new kit.Jar();
  const pair = kit.pkce();
  const state = "tv-" + STAMP;
  const start = authorizeUrl(realm.a, pair, state);

  log.info("=== 1. the restart at home (D9) ===");
  const first = await kit.browse(jar, start);
  check("the authorization request at cell A sends the browser to cell A's " +
        "sign-in screen", function () {
          assert.ok(first.status >= 300 && first.status < 400,
            first.status + " " + kit.said(first.text));
          assert.ok(/\/authn\/login\?authn=/.test(first.location),
            first.location);
        });
  const screen = await kit.browse(jar, first.location);
  const fields = kit.signInFields(screen.text);
  check("which is a sign-in screen", function () {
    assert.ok(fields.authnId, screen.status + " " + kit.said(screen.text));
  });
  const screenUrl = new URL(first.location);
  const posted = await kit.browse(jar, screenUrl.origin + screenUrl.pathname,
    { form: { authn_id: fields.authnId, username: PERSON, password: PASSWORD,
              action: "login", csrf_token: fields.csrf } });
  check("the login POST names a person homed in " + cells.ids.b + ": 303 " +
        "back to the original authorization request", function () {
          assert.strictEqual(posted.status, 303,
            posted.status + " " + kit.said(posted.text));
          assert.strictEqual(posted.location, start, posted.location);
        });
  const pin = jar.get("sts_cell");
  check("and the browser is pinned with an sts_cell cookie that names no " +
        "cell in the clear", function () {
          assert.ok(pin, "no sts_cell cookie was set: " +
            JSON.stringify(posted.set));
          assert.ok(pin.indexOf(cells.ids.b) < 0 &&
                    pin.indexOf(cells.ids.a) < 0, pin);
        });
  check("and no session was started at cell A", function () {
    assert.deepStrictEqual(posted.set, ["sts_cell"],
      "the restart set " + JSON.stringify(posted.set));
  });

  log.info("=== 2. followed with the pin, cell A relays to cell B ===");
  const again = await kit.browse(jar, start);
  check("the same authorization request with the pin sends the browser to " +
        "a sign-in screen again", function () {
          assert.ok(again.status >= 300 && again.status < 400,
            again.status + " " + kit.said(again.text));
          assert.ok(/\/authn\/login\?authn=/.test(again.location),
            again.location);
        });
  const homeScreen = await kit.browse(jar, again.location);
  const homeFields = kit.signInFields(homeScreen.text);
  check("the pinned sign-in screen is a sign-in", function () {
    assert.ok(homeFields.authnId, homeScreen.status + " " +
      kit.said(homeScreen.text));
  });
  const unpinned = await kit.browse(jar.without("sts_cell"), again.location);
  check("and it is cell B's: the same URL at cell A without the pin is not " +
        "a sign-in cell A holds", function () {
          assert.ok(unpinned.text.indexOf(homeFields.authnId) < 0 ||
                    unpinned.status >= 400,
            "cell A drew the pinned sign-in itself: " + unpinned.status);
          assert.notStrictEqual(kit.signInFields(unpinned.text).authnId,
                                homeFields.authnId);
        });

  log.info("=== 3. the password at home, the code from home ===");
  const homeUrl = new URL(again.location);
  const signedIn = await kit.browse(jar, homeUrl.origin + homeUrl.pathname,
    { form: { authn_id: homeFields.authnId, username: PERSON,
              password: PASSWORD, action: "login",
              csrf_token: homeFields.csrf } });
  check("the password POST at cell A is relayed home and signs the person " +
        "in: a redirect and a session cookie", function () {
          assert.ok(signedIn.status >= 300 && signedIn.status < 400,
            signedIn.status + " " + kit.said(signedIn.text));
          assert.ok(signedIn.set.filter(function (n) {
            return n !== "sts_cell";
          }).length > 0, "no session cookie: " +
            JSON.stringify(signedIn.set));
        });
  const flow = await kit.drive(jar, signedIn.location, REDIRECT);
  check("the flow ends at the client with a code and the state it sent",
        function () {
          assert.ok(flow.code, "no code; the flow stopped at " +
            JSON.stringify(flow.hops.slice(-2)) + " " +
            (flow.stopped ? flow.stopped.status + " " +
                            kit.said(flow.stopped.text) : flow.error));
          assert.strictEqual(flow.state, state);
        });
  check("the strict default holds the session at home: the pin still " +
        "names the cell it named", function () {
          assert.strictEqual(jar.get("sts_cell"), pin);
        });
  const before = await relayedAt(realm.a);
  const tokens = await redeem(realm.a, flow.code, pair.verifier);
  const after = await relayedAt(realm.a);
  check("the code redeemed at cell A answers tokens", function () {
    assert.strictEqual(tokens.status, 200, tokens.raw.slice(0, 300));
    assert.ok(tokens.body.id_token && tokens.body.access_token,
      tokens.raw.slice(0, 300));
  });
  check("because cell A relayed it to the cell that minted it (D10): its " +
        "relay counter moved", function () {
          assert.ok(after > before, "relayed " + before + " -> " + after);
        });

  log.info("=== 4. one set of realm keys (D8) ===");
  const jwksA = await kit.jwksAt(realm.a);
  const jwksB = await kit.jwksAt(realm.b);
  const claims = kit.verifyJwt(tokens.body.id_token, jwksA);
  check("the ID Token minted at cell B verifies against cell A's key set",
        function () {
          assert.strictEqual(claims.aud === CLIENT ||
                             (Array.isArray(claims.aud) &&
                              claims.aud.indexOf(CLIENT) >= 0), true,
                             JSON.stringify(claims.aud));
        });
  if (String(tokens.body.access_token).split(".").length === 3) {
    kit.verifyJwt(tokens.body.access_token, jwksA);
    check("and so does the access token", function () {
      assert.ok(true);
    });
  }
  check("and cell B publishes the same keys", function () {
    const kids = function (set) {
      return (set.keys || []).map(function (k) {
        return k.kid;
      }).sort();
    };
    assert.deepStrictEqual(kids(jwksB), kids(jwksA));
  });
  log.debug("Leaving theRestart().");
}

async function thePushedRequest(cells, realm) {
  log.debug("Entering thePushedRequest().");
  log.info("=== 5. a pushed request made at cell B, started at cell A ===");
  const pair = kit.pkce();
  const state = "par-" + STAMP;
  const pushed = await fetch(realm.b + "/oauth2/par", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded",
               Accept: "application/json" },
    body: new URLSearchParams({ response_type: "code", client_id: CLIENT,
      redirect_uri: REDIRECT, scope: "openid", state: state,
      code_challenge: pair.challenge, code_challenge_method: "S256"
    }).toString()
  });
  const raw = await pushed.text();
  let body = {};
  try {
    body = JSON.parse(raw);
  } catch (e) {
    // Asserted below with the raw text.
    log.debug("Caught in thePushedRequest(): " + ((e && e.message) || e));
    body = {};
  }
  check("the PAR at cell B answers 201 with a request_uri", function () {
    assert.strictEqual(pushed.status, 201, raw.slice(0, 300));
    assert.ok(/^urn:ietf:params:oauth:request_uri:/.test(body.request_uri),
      raw.slice(0, 300));
  });
  const jar = new kit.Jar();
  const started = await kit.browse(jar, realm.a + "/oauth2/authorize?" +
    new URLSearchParams({ client_id: CLIENT,
                          request_uri: body.request_uri }).toString());
  check("the authorization request naming it at cell A, with no pin, is " +
        "answered with a sign-in — cell A holds no such request and could " +
        "only have refused it", function () {
          assert.ok(started.status >= 300 && started.status < 400,
            started.status + " " + kit.said(started.text));
          assert.ok(/\/authn\/login\?authn=/.test(started.location),
            started.location);
        });
  const atHome = await kit.browse(new kit.Jar(),
    started.location.replace(new URL(realm.a).origin,
                             new URL(realm.b).origin));
  check("and that sign-in is cell B's: cell B draws it", function () {
    assert.ok(kit.signInFields(atHome.text).authnId,
      atHome.status + " " + kit.said(atHome.text));
  });
  const screen = await kit.browse(jar, started.location);
  const fields = kit.signInFields(screen.text);
  check("the browser that made the request reaches it through cell A",
        function () {
          assert.ok(fields.authnId, screen.status + " " +
            kit.said(screen.text));
        });
  const screenUrl = new URL(started.location);
  const signedIn = await kit.browse(jar, screenUrl.origin +
                                    screenUrl.pathname,
    { form: { authn_id: fields.authnId, username: PERSON, password: PASSWORD,
              action: "login", csrf_token: fields.csrf } });
  const flow = await kit.drive(jar, signedIn.location || "", REDIRECT);
  check("and the person signs in there and the flow ends at the client " +
        "with a code and the pushed state", function () {
          assert.ok(signedIn.status >= 300 && signedIn.status < 400,
            signedIn.status + " " + kit.said(signedIn.text));
          assert.ok(flow.code, "no code; the flow stopped at " +
            JSON.stringify(flow.hops.slice(-2)) + " " +
            (flow.stopped ? flow.stopped.status + " " +
                            kit.said(flow.stopped.text) : flow.error));
          assert.strictEqual(flow.state, state);
        });
  const tokens = await redeem(realm.a, flow.code, pair.verifier);
  check("and the code redeemed at cell A answers tokens", function () {
    assert.strictEqual(tokens.status, 200, tokens.raw.slice(0, 300));
  });
  log.debug("Leaving thePushedRequest().");
}

async function test() {
  log.debug("Entering test().");
  const cells = kit.cellsFromEnv();
  if (!cells) {
    expectation.declineToRun(log, "STS_TEST_CELL_B_URL is not set: this is " +
      "not the `cells` mode (./run-tests.sh --modes=cells), so there is no " +
      "home cell to travel from.");
    log.debug("Leaving test(). Skipped.");
    return;
  }
  const realm = await setUp(cells);
  await theRestart(cells, realm);
  await thePushedRequest(cells, realm);
  assert.ok(checks >= 22, "only " + checks + " checks ran; a section has " +
    "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_cells_traveller")
  .description("a flow started at cell A for a person homed at cell B " +
      "restarts at home and is served there through cell A; one key set; " +
      "a pushed request made at cell B is found from cell A.")
  .addOption(new Option("-u, --url <url>",
      "base url (unused: the cells come from STS_TEST_CELL_*_URL)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
