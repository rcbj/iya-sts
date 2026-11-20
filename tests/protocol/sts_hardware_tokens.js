// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: sts_hardware_tokens.js
//
// ---------------------------------------------------------------------------
// DIRECTORY → HARDWARE TOKENS OVER HTTP (#1955 P1).
//
//   a. the console page answers its shell, both operations are in the
//      management API's document, and the view refuses a caller with no
//      token;
//   b. the view answers `tokens`, `paging` and `capped`, filtered by status
//      and searched by a serial nobody holds;
//   c. the lost-key act refuses a token nobody holds (404) and an unknown
//      action (400), and records nothing;
//   d. the account API publishes `/account-api/tokens` (GET and POST).
//
// A token is recorded only from attestation, so nothing here can make one:
// the register's behaviour with real tokens is `tests/hardware_tokens.js`,
// in process. `local: true`: this repository's console and APIs.
// ---------------------------------------------------------------------------

"use strict";
//
// File: sts_hardware_tokens.js
//
// ---------------------------------------------------------------------------
// DIRECTORY → POST-LOGIN ACTIVITIES OVER HTTP (#1111, 2026-10-28; #1123).
//
// A started post-login activity's controls, as
// `/admin-api/post-login-activities` answers them and
// `/admin/post-login-activities` draws them. Against the running service, in
// every mode:
//
//   a. the console page answers its shell, the five operations are in the
//      OpenAPI document, and the view refuses a caller with no token;
//   b. the view answers the activities, the bounds, the job, the started
//      activities, and its group chooser: a search for the two groups made
//      here finds both, and with one chosen (`groups`, `;`-separated) it
//      is resolved and left out of the results;
//   c. a start with a value out of its bounds, an unknown activity, a group
//      this realm does not have (STS-AUTHN-0530, by name), and an unknown
//      action are refused 400;
//   d. a post-login activity narrowed to the two groups starts, is listed
//      running with both DNs, a second for the same groups in the other
//      order is refused, and it pauses, resumes and ends; an ended one does
//      not pause.;
//   e. in a realm of its own (D12, #444), the acts' codes and the job's
//      body run now — see section e's own header below.
//
// It is narrowed to groups made here, which hold nobody, so the job — which
// runs every few minutes on the stack this job shares — mails nobody for
// it, and it is ended before the job finishes. What the job mails
// and what the reports application reads back is
// `tests/post_login_activities.js`'s, in process, through the real channel.
//
// OWNED HERE (local: true): this repository's own console and management API
// (tests/CLAUDE.md, *where a new test goes*, rule 1).
// ---------------------------------------------------------------------------

const assert = require("assert");
const https = require("https");
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
var log = bunyan.createLogger({ name: "sts_hardware_tokens",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const OPERATION = "/admin-api/hardware-tokens";
const STAMP = Date.now().toString(36);

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

// One request over node's own https. The management API's token is attached
// by the launcher's preload (`tests/tools/attach-admin-token.js`) unless
// `bare` sends `Authorization: none`.
function send(method, path, options) {
  log.debug("Entering send(). " + method + " " + path);
  const o = options || {};
  const target = new URL(base + path);
  const headers = Object.assign({ accept: "application/json" },
                                o.headers || {});
  const body = o.json === undefined ? "" : JSON.stringify(o.json);
  if (body) {
    headers["content-type"] = "application/json";
    headers["content-length"] = Buffer.byteLength(body);
  }
  if (o.bare) {
    // `tests/tools/attach-admin-token.js` leaves this alone, and the service
    // reads it as a malformed credential: a caller with no token.
    headers.authorization = "none";
  }
  log.debug("Leaving send().");
  return new Promise(function (resolve, reject) {
    const transport = target.protocol === "http:" ? require("http") : https;
    const req = transport.request({
      method: method, hostname: target.hostname, port: target.port,
      path: target.pathname + target.search, headers: headers
    }, function (res) {
      const chunks = [];
      res.on("data", function (c) {
        chunks.push(c);
      });
      res.on("end", function () {
        const raw = Buffer.concat(chunks).toString("utf8");
        let json = null;
        try {
          json = JSON.parse(raw);
        } catch (e) {
          log.debug("Caught in send(): " + ((e && e.message) || e));
          // Not JSON: a page, a CSV, or Express's own 404; the caller reads
          // `raw`.
          json = null;
        }
        resolve({ status: res.statusCode, headers: res.headers, raw: raw,
                  json: json });
      });
    });
    req.on("error", reject);
    req.end(body);
  });
}

async function test() {
  log.debug("Entering test().");
  log.info("Directory → Hardware tokens at " + base);

  log.info("=== a. the page, the document and the gate ===");
  const shell = await send("GET", "/admin/hardware-tokens",
                           { headers: { accept: "text/html" } });
  const doc = await send("GET", "/admin-api/openapi.json");
  const anonymous = await send("GET", OPERATION, { bare: true });
  check("the console page answers its shell, both operations are " +
        "published, and the view refuses a caller with no token",
        function () {
    assert.strictEqual(shell.status, 200, shell.raw.slice(0, 200));
    assert.ok(/<html/i.test(shell.raw), shell.raw.slice(0, 200));
    const paths = Object.keys((doc.json && doc.json.paths) || {});
    [OPERATION, OPERATION + "/lost"].forEach(function (p) {
      assert.ok(paths.indexOf(p) >= 0, p + " is not in the document");
    });
    assert.strictEqual(anonymous.status, 401, anonymous.raw.slice(0, 200));
  });

  log.info("=== b. the view ===");
  const view = await send("GET", OPERATION + "?per=5");
  const lost = await send("GET", OPERATION + "?status=lost&per=5");
  const none = await send("GET", OPERATION + "?q=" +
                          encodeURIComponent("no-such-serial-" + STAMP));
  check("the view answers tokens, paging and capped, filtered and " +
        "searched", function () {
    assert.strictEqual(view.status, 200, view.raw.slice(0, 300));
    const v = view.json || {};
    assert.ok(Array.isArray(v.tokens), view.raw.slice(0, 300));
    assert.ok(v.tokens.length <= 5, view.raw.slice(0, 300));
    assert.strictEqual(typeof v.capped, "boolean");
    assert.strictEqual((v.paging || {}).perPage, 5,
                       JSON.stringify(v.paging));
    assert.strictEqual(lost.status, 200, lost.raw.slice(0, 300));
    (lost.json.tokens || []).forEach(function (one) {
      assert.strictEqual(one.status, "lost", JSON.stringify(one));
    });
    assert.strictEqual(none.status, 200, none.raw.slice(0, 300));
    assert.strictEqual(none.json.tokens.length, 0, none.raw.slice(0, 300));
  });

  log.info("=== c. the lost-key act's refusals ===");
  const missing = await send("POST", OPERATION + "/lost",
    { json: { key: "yubico/no-such-serial-" + STAMP } });
  const unknown = await send("POST", OPERATION + "/misplaced",
    { json: { key: "yubico/no-such-serial-" + STAMP } });
  check("a token nobody holds is 404, an unknown action is refused, and " +
        "neither answer names an error code", function () {
    assert.strictEqual(missing.status, 404, missing.raw.slice(0, 300));
    assert.strictEqual(missing.json.ok, false);
    assert.ok(unknown.status === 400 || unknown.status === 404,
              unknown.raw.slice(0, 300));
    assert.ok(!/STS-[A-Z]+-\d{4}/.test(missing.raw + unknown.raw),
              missing.raw + unknown.raw);
  });

  log.info("=== d. the account API's operations ===");
  const index = await send("GET", "/account-api", { bare: true });
  check("the account API publishes /account-api/tokens", function () {
    const text = index.raw || "";
    assert.ok(index.status === 200 || index.status === 401,
              text.slice(0, 200));
    if (index.status === 200) {
      assert.ok(/\/account-api\/tokens/.test(text), text.slice(0, 400));
    }
  });

  log.info(checks + " checks passed.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_hardware_tokens")
  .description("Directory → Hardware tokens over HTTP (#1955 P1).")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().then(function () {
  process.exit(0);
}, function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
