// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: sts_data_keys.js
//
// ===========================================================================
// DATA ENCRYPTION KEY ROTATION OVER HTTP, IN EVERY MODE (#391 P2).
//
// `tests/data_key_rotation.js` holds the keystore's lifecycle and the jobs to
// their promises in process. This job holds the RUNNING service to them
// through the surface an operator uses — `POST /admin-api/encryption/:action`
// and the report at `GET /admin-api/encryption` — and asserts in whichever
// mode it runs:
//
//   * WHERE DATA KEYS ARE DERIVED PER RUN (development, or nothing durable):
//     the report says so, and both acts answer 400 STS-KEYS-0100 naming why;
//   * EVERYWHERE: the key-encryption key is named and never shown, and its
//     rotation from here is refused where it is read into the process (every
//     stack here) and queued where it is in a key management service (#391
//     P5);
//   * WHERE THEY ARE STORED (product): a rotation of one realm's one class
//     answers 202, its run succeeds, and the report then holds a SECOND key
//     for that slot, waiting to be used while the first stays current; a
//     re-encryption pass answers 202 and succeeds, destroying nothing that
//     is still current; a rotation naming a realm no key serves is 400; and
//     a count (#391 P5) answers 202, succeeds, and leaves every current key
//     with a count and the time it was taken — or is refused where the store
//     cannot count.
//
// It never prints a key: the report carries none, and it is asserted to.
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
const log = bunyan.createLogger({ name: "sts_data_keys",
                                  level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
const base = String(process.env.OID4VCI_ISSUER_URL ||
                    stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");

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
    // Not JSON; the text is kept for the failure message.
    body = null;
  }
  log.debug("Leaving api(). status=" + r.status);
  return { status: r.status, body: body, text: text };
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

async function finished(runId) {
  log.debug("Entering finished(). " + runId);
  const detail = await until("run " + runId + " to finish", async function () {
    const r = await api("GET", "/admin-api/scheduler?run=" +
                               encodeURIComponent(runId));
    const d = r.body && r.body.detail;
    return d && (d.state === "succeeded" || d.state === "failed") ? d : null;
  });
  log.debug("Leaving finished(). " + detail.state);
  return detail;
}

async function report() {
  log.debug("Entering report().");
  const r = await api("GET", "/admin-api/encryption?per=500");
  assert.strictEqual(r.status, 200, "GET /admin-api/encryption answered " +
                     r.status + ": " + r.text.slice(0, 300));
  log.debug("Leaving report().");
  return r.body;
}

async function main() {
  log.debug("Entering main().");
  log.info("=== 1. the report ===");
  const first = await report();
  const dk = first.dataKeys;
  check("the report carries the data keys and their lifecycle", function () {
    assert.ok(dk && Array.isArray(dk.keys) && dk.counts && dk.paging,
              JSON.stringify(dk).slice(0, 300));
    assert.ok(dk.lifecycle && typeof dk.lifecycle.on === "boolean",
              JSON.stringify(dk.lifecycle));
  });
  check("and no key material", function () {
    dk.keys.forEach(function (k) {
      assert.deepStrictEqual(Object.keys(k).sort(),
        ["activateAt", "ageDays", "alg", "cls", "countedAt", "createdAt",
         "id", "realm", "scope", "state", "values"],
        JSON.stringify(k));
    });
  });
  const unknown = await api("POST", "/admin-api/encryption/nonsense", {});
  check("an unknown action is 400 naming both", function () {
    assert.strictEqual(unknown.status, 400, unknown.text.slice(0, 300));
    assert.ok(/rotate-data-keys/.test(unknown.text) &&
              /reencrypt-data-keys/.test(unknown.text) &&
              /count-data-keys/.test(unknown.text) &&
              /rotate-kek/.test(unknown.text), unknown.text);
  });
  check("the key-encryption key is named, never shown", function () {
    assert.ok(first.key && typeof first.key.inKms === "boolean",
              JSON.stringify(first.key));
    assert.ok(!/BEGIN|"kek"\s*:\s*"[A-Za-z0-9+/=]{40,}"/
      .test(JSON.stringify(first.key)), JSON.stringify(first.key));
  });
  // A KEY READ INTO THE PROCESS (every stack here) is rotated by deploying
  // its successor, so the act is refused; one in a KMS is queued.
  const kek = await api("POST", "/admin-api/encryption/rotate-kek", {});
  if (dk.lifecycle.kekRotation) {
    check("a key-encryption key in a KMS: its rotation is queued", function () {
      assert.strictEqual(kek.status, 202, kek.text.slice(0, 300));
    });
    const kekRun = await finished(kek.body.runId);
    check("and the rotation run succeeds", function () {
      assert.strictEqual(kekRun.state, "succeeded", JSON.stringify(kekRun));
    });
  } else {
    check("a key-encryption key read into the process is not rotated from " +
          "here, and the refusal says how", function () {
      assert.strictEqual(kek.status, 400, kek.text.slice(0, 300));
      assert.ok(/previousKek|derived per run/.test(kek.text), kek.text);
    });
  }

  if (!dk.lifecycle.on) {
    log.info("=== 2. data keys derived per run here ===");
    const rot = await api("POST", "/admin-api/encryption/rotate-data-keys", {});
    const re = await api("POST", "/admin-api/encryption/reencrypt-data-keys",
                         {});
    check("a rotation is refused 400, saying why", function () {
      assert.strictEqual(rot.status, 400, rot.text.slice(0, 300));
      assert.ok(/derived per run/.test(rot.text), rot.text);
    });
    check("and so is a re-encryption pass", function () {
      assert.strictEqual(re.status, 400, re.text.slice(0, 300));
    });
    const cnt = await api("POST", "/admin-api/encryption/count-data-keys", {});
    check("and so is a count", function () {
      assert.strictEqual(cnt.status, 400, cnt.text.slice(0, 300));
    });
    log.info("sts_data_keys: " + checks + " check(s) passed (data keys are " +
             "derived here: " + dk.lifecycle.offReason + ").");
    log.debug("Leaving main().");
    return;
  }

  log.info("=== 2. a rotation of one realm's one class ===");
  const current = dk.keys.filter(function (k) {
    return k.state === "current" && k.realm === "default";
  });
  assert.ok(current.length, "the default realm holds no current data key: " +
            JSON.stringify(dk.counts));
  const slot = current[0];
  const nobody = await api("POST", "/admin-api/encryption/rotate-data-keys",
                           { realm: "no-such-realm-" + Date.now() });
  check("a realm no key serves is 400", function () {
    assert.strictEqual(nobody.status, 400, nobody.text.slice(0, 300));
  });
  const rot = await api("POST", "/admin-api/encryption/rotate-data-keys",
                        { realm: slot.realm, cls: slot.cls });
  check("a rotation answers 202 with a run", function () {
    assert.strictEqual(rot.status, 202, rot.text.slice(0, 300));
    assert.ok(rot.body.runId, rot.text);
  });
  const run = await finished(rot.body.runId);
  check("and its run succeeds", function () {
    assert.strictEqual(run.state, "succeeded", JSON.stringify(run));
  });
  const after = (await report()).dataKeys;
  const ofSlot = after.keys.filter(function (k) {
    return k.realm === slot.realm && k.cls === slot.cls &&
           k.scope === slot.scope;
  });
  check("the slot now holds a successor beside the key it had", function () {
    assert.ok(ofSlot.length >= 2, JSON.stringify(ofSlot));
    assert.ok(ofSlot.some(function (k) {
      return k.id !== slot.id && (k.state === "pending" ||
                                  k.state === "current");
    }), JSON.stringify(ofSlot));
  });
  check("and the key it had is still there, not destroyed", function () {
    const had = ofSlot.filter(function (k) { return k.id === slot.id; })[0];
    assert.ok(had && had.state !== "destroyed", JSON.stringify(ofSlot));
  });

  log.info("=== 3. a re-encryption pass ===");
  const re = await api("POST", "/admin-api/encryption/reencrypt-data-keys", {});
  check("a re-encryption pass answers 202", function () {
    assert.strictEqual(re.status, 202, re.text.slice(0, 300));
  });
  const reRun = await finished(re.body.runId);
  check("and its run succeeds", function () {
    assert.strictEqual(reRun.state, "succeeded", JSON.stringify(reRun));
  });
  const last = (await report()).dataKeys;
  check("no current key was destroyed", function () {
    last.keys.forEach(function (k) {
      if (k.id === slot.id || k.state === "current") {
        assert.notStrictEqual(k.state, "destroyed", JSON.stringify(k));
      }
    });
  });

  log.info("=== 4. a count of what is sealed under each key ===");
  // The keys that exist BEFORE the count; one made after it has no count yet.
  const before = (await report()).dataKeys.keys.filter(function (k) {
    return k.state === "current";
  }).map(function (k) {
    return k.id;
  });
  const cnt = await api("POST", "/admin-api/encryption/count-data-keys", {});
  if (!dk.lifecycle.counting) {
    check("where the store cannot count, a count is refused 400", function () {
      assert.strictEqual(cnt.status, 400, cnt.text.slice(0, 300));
    });
  } else {
    check("a count answers 202", function () {
      assert.strictEqual(cnt.status, 202, cnt.text.slice(0, 300));
    });
    const cntRun = await finished(cnt.body.runId);
    check("and its run succeeds", function () {
      assert.strictEqual(cntRun.state, "succeeded", JSON.stringify(cntRun));
    });
    // On a cluster the report may come from a node that has not yet adopted
    // the leader's counts through the change log, so it is asked again.
    const counted = await until("every current key to carry a count",
                                async function () {
      const got = (await report()).dataKeys;
      const current = got.keys.filter(function (k) {
        return before.indexOf(k.id) >= 0;
      });
      return current.length && current.every(function (k) {
        return typeof k.values === "number";
      }) ? got : null;
    }, 60000);
    check("every current key then carries a count and when it was taken",
          function () {
      const current = counted.keys.filter(function (k) {
        return before.indexOf(k.id) >= 0;
      });
      assert.ok(current.length, JSON.stringify(counted.counts));
      current.forEach(function (k) {
        assert.ok(typeof k.values === "number" && k.values >= 0 &&
                  k.countedAt, JSON.stringify(k));
      });
      assert.ok(counted.lastCounted, JSON.stringify(counted.lastCounted));
    });
    check("and something is sealed under the default realm's keys",
          function () {
      assert.ok(counted.keys.some(function (k) {
        return k.realm === "default" && k.values > 0;
      }), JSON.stringify(counted.keys.slice(0, 5)));
    });
  }

  log.info("sts_data_keys: " + checks + " check(s) passed.");
  log.debug("Leaving main().");
}

main().catch(function (e) {
  log.error("sts_data_keys FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
