// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: sts_broadcast_announcement.js
//
// ===========================================================================
// AN ANNOUNCEMENT TO EVERYBODY SIGNED IN, OVER HTTP (#1086).
//
// The whole path in a running service, in every mode: the page's view, the
// send, this service's own `announcement` SET on the console's receiver
// stream, the ssf.internal-poll job collecting it over /ssf/poll, the
// receiver keeping it, and an open console tab's ask finding it — through
// the balancer in `cluster`, so the node that answers the tab need not be
// the node that sent or collected it. A refusal, and a first ask that
// answers nothing. `local: true`: this repository's own /admin-api.
// `tests/ssf_announcements.js` holds the rest in process.
// ===========================================================================

const assert = require("assert");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, for the reason wait_for.js (beside this file) gives.
  appconfigProblem = e;
  appconfig = {};
}

const bunyan = require("bunyan");
const log = bunyan.createLogger({ name: "sts_broadcast_announcement",
                                  level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}
const crypto = require("crypto");

const stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
const base = String(process.env.OID4VCI_ISSUER_URL ||
                    stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = Date.now().toString(36) + crypto.randomBytes(3).toString("hex");

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  ✓ " + what);
  log.debug("Leaving check().");
}

async function api(method, path, payload) {
  log.debug("Entering api(). " + method + " " + path);
  const options = { method: method, redirect: "manual" };
  if (payload !== undefined) {
    options.headers = { "Content-Type": "application/json" };
    options.body = JSON.stringify(payload);
  }
  const r = await fetch(base + path, options);
  const text = await r.text();
  let body = null;
  try {
    body = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in api(): " + ((e && e.message) || e));
    // Not JSON: kept as text for the assertion's message.
    body = null;
  }
  log.debug("Leaving api(). status=" + r.status);
  return { status: r.status, body: body, text: text };
}

async function main() {
  log.debug("Entering main().");
  const view = await api("GET", "/admin-api/broadcast");
  check("GET /admin-api/broadcast names the three applications", function () {
    assert.strictEqual(view.status, 200, view.text.slice(0, 300));
    const ids = (view.body.surfaces || []).map(function (s) {
      return s.id;
    }).sort().join(",");
    assert.strictEqual(ids, "admin-console,report,user-portal");
  });
  if (!view.body.ready) {
    log.info("sts_broadcast_announcement: nothing can be delivered here (" +
             view.body.why + "); the send is not driven. " + checks +
             " check(s) passed.");
    log.debug("Leaving main(). Not ready.");
    return;
  }

  const refused = await api("POST", "/admin-api/broadcast/send",
                            { message: "", surfaces: ["admin-console"] });
  check("an empty message is refused with 400", function () {
    assert.strictEqual(refused.status, 400, refused.text.slice(0, 300));
    assert.ok(/needs a message/.test((refused.body.errors || []).join(" ")),
              refused.text.slice(0, 300));
  });

  const first = await api("GET", "/admin-api/announcements");
  check("a tab's first ask answers `now` and no announcement", function () {
    assert.strictEqual(first.status, 200, first.text.slice(0, 300));
    assert.ok(Number(first.body.now) > 0, first.text);
    assert.strictEqual((first.body.announcements || []).length, 0);
  });

  const message = "sts_broadcast_announcement " + STAMP;
  const sent = await api("POST", "/admin-api/broadcast/send",
    { message: message,
      surfaces: ["admin-console", "user-portal", "report"] });
  check("the send reaches the three receiver streams", function () {
    assert.strictEqual(sent.status, 200, sent.text.slice(0, 400));
    assert.ok(sent.body.ok && sent.body.sent === 3 &&
              sent.body.streams === 3, sent.text.slice(0, 400));
  });

  const deadline = Date.now() + 30000;
  let found = null;
  while (!found && Date.now() < deadline) {
    const asked = await api("GET", "/admin-api/announcements?since=" +
                            encodeURIComponent(String(first.body.now)));
    found = ((asked.body && asked.body.announcements) || [])
      .filter(function (one) {
        return one.message === message;
      })[0] || null;
    if (!found) {
      await new Promise(function (resolve) {
        setTimeout(resolve, 500);
      });
    }
  }
  check("an open console tab finds it within 30 s, as sent", function () {
    assert.ok(found, "the announcement never reached the console's tab");
    assert.ok(found.id && found.at, JSON.stringify(found));
  });
  log.info("sts_broadcast_announcement: " + checks + " check(s) passed.");
  log.debug("Leaving main().");
}

main().catch(function (e) {
  log.error("sts_broadcast_announcement FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
