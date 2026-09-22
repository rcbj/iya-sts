'use strict';
//
// File: sts_key_rotation.js
//
// ===========================================================================
// SIGNING KEY ROTATION OVER HTTP, IN EVERY MODE (#42/#48, 2026-09-22).
//
// `tests/key_generations.js` and `tests/signing_rotation.js` hold the
// generations and the rotation module to their promises in process. This job
// holds the RUNNING service to them through the two surfaces an operator uses
// — `/admin/keys`' Rotation forms and `POST /admin-api/keys/:action` — and the
// documents a relying party reads, in a THROWAWAY REALM so that its emergency
// signs nobody else out:
//
//   1. THE REFUSALS: an unknown action names the three, an unknown unit is
//      400, and an emergency without `confirm: "compromised"` is 400;
//   2. A ROTATION: 202 with a run id, the run succeeds on the scheduler, the
//      JWKS and `/crypto/metadata` carry the new current key AND the retired
//      one — and an access token signed before it is still accepted;
//   3. THE CONSOLE: the Rotate form queues the same run and lands on the
//      run's page;
//   4. AN EMERGENCY: the old keys leave the JWKS and the document, and the
//      token signed before it is refused.
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
const log = bunyan.createLogger({ name: "sts_key_rotation",
                                  level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}
const signin = require("./console_signin");

const stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
const base = String(process.env.OID4VCI_ISSUER_URL ||
                    stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = Date.now().toString(36);
const REALM = "keys-" + STAMP;
const R = "/realm/" + REALM;

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  ✓ " + what);
  log.debug("Leaving check().");
}

async function call(method, url, options) {
  log.debug("Entering call(). " + method + " " + url);
  const opts = Object.assign({ method: method, redirect: "manual" },
                             options || {});
  const r = await fetch(url, opts);
  const text = await r.text();
  let body = null;
  try {
    body = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in call(): " + ((e && e.message) || e));
    // Not JSON — a page or an empty body. The text is kept.
    body = null;
  }
  log.debug("Leaving call(). status=" + r.status);
  return { status: r.status, body: body, text: text,
           location: r.headers.get("location") || "" };
}

async function api(method, path, payload) {
  log.debug("Entering api(). " + method + " " + path);
  const options = payload === undefined ? {}
    : { headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload) };
  const reply = await call(method, base + path, options);
  log.debug("Leaving api().");
  return reply;
}

async function apiAs(token, method, path) {
  log.debug("Entering apiAs(). " + method + " " + path);
  const reply = await call(method, base + path,
                           { headers: { Authorization: "Bearer " + token } });
  log.debug("Leaving apiAs().");
  return reply;
}

async function until(what, fn, limitMs) {
  log.debug("Entering until(). " + what);
  const deadline = Date.now() + (limitMs || 120000);
  for (;;) {
    const got = await fn();
    if (got) {
      log.debug("Leaving until(). Met.");
      return got;
    }
    if (Date.now() > deadline) {
      log.debug("Leaving until(). Timed out.");
      assert.fail("timed out waiting for " + what);
    }
    await new Promise(function (resolve) { setTimeout(resolve, 500); });
  }
}

// The run a rotation queued, once it has finished.
async function finished(prefix, runId) {
  log.debug("Entering finished(). " + runId);
  const detail = await until("run " + runId + " to finish", async function () {
    const r = await api("GET", prefix + "/admin-api/scheduler?run=" +
                               encodeURIComponent(runId));
    const d = r.body && r.body.detail;
    return d && (d.state === "succeeded" || d.state === "failed") ? d : null;
  });
  log.debug("Leaving finished(). " + detail.state);
  return detail;
}

async function jwksKids(prefix) {
  log.debug("Entering jwksKids().");
  const r = await api("GET", prefix + "/oauth2/jwks");
  assert.strictEqual(r.status, 200, "GET " + prefix + "/oauth2/jwks answered " +
                     r.status);
  log.debug("Leaving jwksKids().");
  return (r.body.keys || []).map(function (k) { return k.kid; });
}

async function joseUnit(prefix) {
  log.debug("Entering joseUnit().");
  const r = await api("GET", prefix + "/crypto/metadata.json");
  assert.strictEqual(r.status, 200, "GET " + prefix + "/crypto/metadata.json " +
                     "answered " + r.status);
  const unit = (r.body.units || []).filter(function (u) {
    return u.unit === "jose:RS256";
  })[0];
  assert.ok(unit, "the crypto metadata lists jose:RS256");
  log.debug("Leaving joseUnit().");
  return unit;
}

function stateOf(unit, kid) {
  log.debug("Entering stateOf().");
  const k = unit.keys.filter(function (one) { return one.kid === kid; })[0];
  log.debug("Leaving stateOf().");
  return k ? k.state : "";
}

// A console form post, with the CSRF token taken off the page it posts to.
async function consolePost(cookie, page, path, form) {
  log.debug("Entering consolePost(). " + path);
  const drawn = await call("GET", base + page, { headers: { Cookie: cookie } });
  const csrf = (drawn.text.match(/name="csrf_token" value="([^"]+)"/) ||
                [])[1] || "";
  assert.ok(csrf, "precondition: " + page + " drawn for this session should " +
                  "carry a CSRF token; it answered " + drawn.status);
  const reply = await call("POST", base + path, {
    headers: { Cookie: cookie,
               "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(Object.assign({ csrf_token: csrf }, form))
      .toString()
  });
  log.debug("Leaving consolePost().");
  return { reply: reply, page: drawn };
}

async function realmToken() {
  log.debug("Entering realmToken().");
  const regenerated = await api("POST", R +
    "/admin-api/applications/regenerate-secret",
    { application: "sts-management-api" });
  const secret = regenerated.body && regenerated.body.clientSecret;
  assert.ok(secret, "precondition: regenerating the realm's " +
    "sts-management-api secret answered " + regenerated.status);
  const minted = await call("POST", base + R + "/oauth2/token", {
    headers: { "Content-Type": "application/x-www-form-urlencoded",
               Authorization: "Basic " +
                 Buffer.from("sts-management-api:" + secret)
                   .toString("base64") },
    body: new URLSearchParams({ grant_type: "client_credentials",
                                scope: "admin:read",
                                resource: base + R + "/admin-api" })
      .toString()
  });
  const token = minted.body && minted.body.access_token;
  assert.ok(token, "precondition: the realm's token endpoint answered " +
            minted.status + " " + minted.text.slice(0, 200));
  log.debug("Leaving realmToken().");
  return token;
}

async function main() {
  log.debug("Entering main().");
  const made = await api("POST", "/admin-api/realms/create",
                         { id: REALM, domain: REALM + ".example.net",
                           name: "Key rotation test " + STAMP });
  assert.ok(made.status === 200, "precondition: creating " + REALM +
            " answered " + made.status + " " + made.text.slice(0, 300));

  // --- 1. the refusals -------------------------------------------------------
  log.info("=== 1. the refusals ===");
  const unknownAction = await api("POST", R + "/admin-api/keys/twirl", {});
  check("an unknown action is 400 and names export, rotate and emergency",
        function () {
          assert.strictEqual(unknownAction.status, 400);
          assert.ok(/export, rotate, emergency/.test(unknownAction.text),
                    unknownAction.text.slice(0, 300));
        });
  const unknownUnit = await api("POST", R + "/admin-api/keys/rotate",
                                { units: ["jose:nope"] });
  check("an unknown unit is 400", function () {
    assert.strictEqual(unknownUnit.status, 400, unknownUnit.text);
    assert.ok(/jose:nope/.test(unknownUnit.text), unknownUnit.text);
  });
  const unconfirmed = await api("POST", R + "/admin-api/keys/emergency", {});
  check("an emergency without confirm: \"compromised\" is 400", function () {
    assert.strictEqual(unconfirmed.status, 400, unconfirmed.text);
    assert.ok(/compromised/.test(unconfirmed.text), unconfirmed.text);
  });

  // --- 2. a rotation -----------------------------------------------------------
  log.info("=== 2. a rotation ===");
  const token = await realmToken();
  const before = await joseUnit(R);
  const k0 = before.keys.filter(function (k) {
    return k.state === "current";
  })[0].kid;
  const accepted = await apiAs(token, "GET", R + "/admin-api/keys");
  assert.strictEqual(accepted.status, 200, "precondition: the realm token " +
                     "reads /admin-api/keys: " + accepted.text.slice(0, 200));
  const rotated = await api("POST", R + "/admin-api/keys/rotate",
                            { units: ["jose:RS256"] });
  check("a rotation answers 202 with the run it queued", function () {
    assert.strictEqual(rotated.status, 202, rotated.text.slice(0, 300));
    assert.ok(/^m-/.test(rotated.body.runId || ""), rotated.text);
  });
  const run = await finished(R, rotated.body.runId);
  check("and the run succeeds on the scheduler", function () {
    assert.strictEqual(run.state, "succeeded", JSON.stringify(run));
  });
  const after = await joseUnit(R);
  const k1 = after.keys.filter(function (k) {
    return k.state === "current";
  })[0].kid;
  const kids1 = await jwksKids(R);
  check("the JWKS carries the new current key and the retired one",
        function () {
          assert.notStrictEqual(k1, k0);
          assert.ok(kids1.indexOf(k1) >= 0 && kids1.indexOf(k0) >= 0,
                    JSON.stringify(kids1));
        });
  check("and /crypto/metadata says which is which", function () {
    assert.strictEqual(stateOf(after, k0), "retired");
    assert.strictEqual(stateOf(after, k1), "current");
  });
  const stillAccepted = await apiAs(token, "GET", R + "/admin-api/keys");
  check("an access token signed BEFORE the rotation is still accepted",
        function () {
          assert.strictEqual(stillAccepted.status, 200,
                             stillAccepted.text.slice(0, 300));
        });
  check("GET /admin-api/keys reports the rotation state", function () {
    const rot = stillAccepted.body && stillAccepted.body.rotation;
    assert.ok(rot && rot.units.some(function (u) {
      return u.unit === "jose:RS256" && u.current === k1;
    }), JSON.stringify(rot && rot.units && rot.units[0]));
  });

  // --- 3. the console ------------------------------------------------------------
  log.info("=== 3. the console ===");
  const admin = "keys-admin-" + STAMP;
  const cookie = await signin.signInToTheConsole(base, admin, log,
                                                 { grant: "write" });
  const posted = await consolePost(cookie || "", "/admin/keys",
    "/admin/keys/rotate", { action: "rotate", units: "xml:RS256" });
  check("/admin/keys draws the Rotation section and its two forms",
        function () {
          assert.ok(/id="keys-rotate-selected"/.test(posted.page.text) &&
                    /id="keys-emergency"/.test(posted.page.text),
                    posted.page.text.slice(0, 200));
        });
  check("and its Rotate form queues a run and lands on its page",
        function () {
          assert.strictEqual(posted.reply.status, 303,
                             posted.reply.text.slice(0, 300));
          assert.ok(/\/admin\/scheduler\?run=m-/.test(posted.reply.location),
                    posted.reply.location);
        });
  const consoleRun = decodeURIComponent(
    (posted.reply.location.match(/run=([^&]+)/) || [])[1] || "");
  const consoleDone = await finished("", consoleRun);
  check("and that run succeeds", function () {
    assert.strictEqual(consoleDone.state, "succeeded",
                       JSON.stringify(consoleDone));
  });

  // --- 4. an emergency --------------------------------------------------------------
  log.info("=== 4. an emergency ===");
  const em = await api("POST", R + "/admin-api/keys/emergency",
                       { confirm: "compromised" });
  check("an emergency answers 202", function () {
    assert.strictEqual(em.status, 202, em.text.slice(0, 300));
    assert.strictEqual(em.body.emergency, true);
  });
  const emRun = await finished(R, em.body.runId);
  check("and its run succeeds", function () {
    assert.strictEqual(emRun.state, "succeeded", JSON.stringify(emRun));
  });
  const kids2 = await jwksKids(R);
  const afterEm = await joseUnit(R);
  check("neither old key is in the JWKS or the document any more",
        function () {
          assert.ok(kids2.indexOf(k0) < 0 && kids2.indexOf(k1) < 0,
                    JSON.stringify(kids2));
          assert.strictEqual(stateOf(afterEm, k0), "");
          assert.strictEqual(stateOf(afterEm, k1), "");
        });
  const refused = await apiAs(token, "GET", R + "/admin-api/keys");
  check("and the token signed before is refused", function () {
    assert.strictEqual(refused.status, 401, refused.text.slice(0, 300));
  });

  log.info("sts_key_rotation: " + checks + " check(s) passed.");
  log.debug("Leaving main().");
}

main().catch(function (e) {
  log.error("sts_key_rotation FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
