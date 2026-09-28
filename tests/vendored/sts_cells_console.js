// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// File: sts_cells_console.js
//
// ===========================================================================
// THE ADMIN CONSOLE AT CELL B (#98, 2026-09-28).
//
// The console is an OpenID Connect relying party of this service's own
// authorization server (common/oidc_rp.ts, console_signin.js), and every
// address it builds is the service's ONE public name — cell A's, here. A
// browser the network sends to cell B instead reaches cell B under that
// name; the job is that browser, by answering every hop the public name
// names AT CELL B (the test-only resolver override, #98 section 9). For an
// administrator homed at cell B:
//
//   1. `GET /admin/cells` at cell B with no session starts the console's
//      authorization request, the administrator signs in at cell B — the
//      offered second factor ignored, as console_signin.js does (#246) — and
//      the callback establishes the console's own session: its back-channel
//      token request goes to the public name, which is cell A, and the code
//      minted at cell B is relayed home by its locator.
//   2. `/admin/cells`, drawn by cell B, names cell B as this cell and cell A
//      in its jurisdiction, reachable.
//
// `local: true`: this repository's own console, against a stack only this
// repository's launcher builds. It declines to run in every mode but
// `cells`. The administrator is left in the default realm, holding Admin
// Read, with a password only this process knew.
// ===========================================================================
"use strict";

const assert = require("assert");
const nodeCrypto = require("crypto");
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

const log = require("bunyan").createLogger({ name: "sts_cells_console",
  level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const STAMP = Date.now().toString(36);
const ADMIN = "cells-console-" + STAMP;
const PASSWORD = "Cells-console-" +
  nodeCrypto.randomBytes(9).toString("base64url") + "-Aa1!";

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

// An address the service built, on its public name, answered at cell B.
function atB(cells, url) {
  log.debug("Entering atB().");
  const publicOrigin = new URL(cells.a).origin;
  const u = new URL(url);
  const out = u.origin === publicOrigin
    ? new URL(cells.b).origin + u.pathname + u.search : url;
  log.debug("Leaving atB().");
  return out;
}

// The console's sign-in, walked at cell B. Answers every hop and the jar.
async function signInAtB(cells) {
  log.debug("Entering signInAtB().");
  const jar = new kit.Jar();
  const hops = [];
  let at = cells.b + "/admin/cells";
  let signedIn = false;
  for (let i = 0; i < 16; i++) {
    const r = await kit.browse(jar, at);
    hops.push({ url: at, status: r.status, location: r.location,
                set: r.set });
    if (r.status >= 300 && r.status < 400 && r.location) {
      at = atB(cells, r.location);
      continue;
    }
    const fields = kit.signInFields(r.text);
    if (r.status === 200 && fields.authnId && !signedIn) {
      signedIn = true;
      const screen = new URL(at);
      const posted = await kit.browse(jar, screen.origin + screen.pathname,
        { form: { authn_id: fields.authnId, username: ADMIN,
                  password: PASSWORD, action: "login",
                  csrf_token: fields.csrf } });
      hops.push({ url: screen.origin + screen.pathname,
                  status: posted.status, location: posted.location,
                  set: posted.set });
      let next = posted;
      // THE OFFERED SECOND FACTOR (#246): an administrator with none is
      // shown the set-up step, and Ignore finishes the sign-in.
      const setupId = next.status === 200 &&
        /id="mfa-setup-ignore"/.test(next.text)
        ? (next.text.match(/name="mfa_id" value="([^"]+)"/) || [])[1] || ""
        : "";
      if (setupId) {
        next = await kit.browse(jar, screen.origin + "/authn/mfa-setup",
          { form: { mfa_id: setupId, action: "ignore" } });
        hops.push({ url: screen.origin + "/authn/mfa-setup",
                    status: next.status, location: next.location,
                    set: next.set });
      }
      assert.ok(next.status >= 300 && next.status < 400 && next.location,
        "signing in at cell B answered " + next.status + " " +
        kit.said(next.text));
      at = atB(cells, next.location);
      continue;
    }
    log.debug("Leaving signInAtB(). Stopped on " + r.status + ".");
    return { jar: jar, hops: hops, last: r, at: at };
  }
  log.debug("Leaving signInAtB(). Too many hops.");
  return { jar: jar, hops: hops, last: { status: 0, text: "too many hops" },
           at: at };
}

async function test() {
  log.debug("Entering test().");
  const cells = kit.cellsFromEnv();
  if (!cells) {
    expectation.declineToRun(log, "STS_TEST_CELL_B_URL is not set: this is " +
      "not the `cells` mode (./run-tests.sh --modes=cells), so there is no " +
      "cell B to draw the console at.");
    log.debug("Leaving test(). Skipped.");
    return;
  }

  const made = await kit.createPerson(cells.b, ADMIN, PASSWORD, "");
  check("the administrator is created at cell B, homed there", function () {
    assert.strictEqual(made.status, 200, made.raw.slice(0, 300));
  });
  const granted = await kit.api(cells.b, "POST", "/rbac/grant",
                                { username: ADMIN, role: "read" });
  check("and given Admin Read at cell B", function () {
    assert.strictEqual(granted.status, 200, granted.raw.slice(0, 300));
  });

  log.info("=== 1. the console's sign-in, at cell B ===");
  const walked = await signInAtB(cells);
  const trail = JSON.stringify(walked.hops.map(function (h) {
    return h.status + " " + new URL(h.url).host + new URL(h.url).pathname;
  }));
  check("the walk went through the console's authorization request and " +
        "callback, every hop at cell B", function () {
          assert.ok(walked.hops.some(function (h) {
            return /\/oauth2\/authorize$/.test(new URL(h.url).pathname);
          }), trail);
          assert.ok(walked.hops.some(function (h) {
            return /\/admin\/callback$/.test(new URL(h.url).pathname);
          }), trail);
          const bHost = new URL(cells.b).host;
          assert.ok(walked.hops.every(function (h) {
            return new URL(h.url).host === bHost;
          }), trail);
        });
  check("the console's own session is established", function () {
    assert.ok(walked.jar.get("sts_admin"), "no sts_admin cookie; " + trail +
      " " + walked.last.status + " " + kit.said(walked.last.text));
  });

  log.info("=== 2. /admin/cells, drawn at cell B ===");
  const page = walked.last;
  check("GET /admin/cells at cell B answers the page", function () {
    assert.strictEqual(page.status, 200, page.status + " at " + walked.at +
      " " + kit.said(page.text));
    assert.ok(/\/admin\/cells$/.test(new URL(walked.at).pathname),
              walked.at);
    assert.ok(/<h2>The cells<\/h2>/.test(page.text), kit.said(page.text));
  });
  check("it names " + cells.ids.b + " as this cell, in " +
        cells.jurisdictions.b, function () {
          assert.ok(new RegExp("<th>" + cells.ids.b +
                               " <small>\\(this cell\\)</small></th><td>" +
                               cells.jurisdictions.b + "</td>")
            .test(page.text), kit.said(page.text));
        });
  check("and " + cells.ids.a + ", in " + cells.jurisdictions.a +
        ", reachable", function () {
          assert.ok(new RegExp("<th>" + cells.ids.a + "</th><td>" +
                               cells.jurisdictions.a + "</td><td>yes, ")
            .test(page.text), kit.said(page.text));
        });

  assert.ok(checks >= 7, "only " + checks + " checks ran; a section has " +
    "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_cells_console")
  .description("an administrator homed at cell B signs in to /admin " +
      "through cell B, and /admin/cells draws both cells.")
  .addOption(new Option("-u, --url <url>",
      "base url (unused: the cells come from STS_TEST_CELL_*_URL)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
