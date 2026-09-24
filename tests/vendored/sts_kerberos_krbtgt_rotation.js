"use strict";
//
// File: sts_kerberos_krbtgt_rotation.js
//
// ---------------------------------------------------------------------------
// THE KRBTGT KEY IS ROTATED, AND A TGT OUTLIVES A ROTATION BUT NOT AN
// INVALIDATION — OVER MS-KKDCP, AGAINST THE SERVICE (#169, 2026-09-23).
//
// Each trust realm's krbtgt key — the key every ticket-granting ticket is
// sealed under — is a RANDOM key in product mode, sealed on the directory
// entry `krbtgt/<REALM>@<REALM>`, and derived from the published
// `krb5.krbtgtPassword` in development. Both rotate: on the scheduler in
// product (`krb5.krbtgt-rotate`), and by hand in both modes through
// `POST /admin-api/kerberos/principals/rotate-krbtgt` and
// `rotate-krbtgt-invalidate`, which QUEUE a run of `krb5.krbtgt-rotate-now`.
// This job is a Kerberos client of a THROWAWAY trust realm's KDC — its own
// Kerberos realm, reached at `/realm/<id>/KdcProxy` — because an
// invalidation ends every TGT in the realm it runs in, and the default
// realm's belong to every other job. In order:
//
//   1. a realm with Kerberos on, a person and a service principal in it; the
//      krbtgt block of `GET /admin-api/kerberos/principals` (stored in
//      product, the password's in development) and of
//      `GET /admin-api/kerberos` agree;
//   2. a TGT, and a service ticket bought with it;
//   3. `rotate-krbtgt`: queued, and once the scheduler has run it the kvno
//      is one higher and the old one is kept — the OLD TGT still buys a
//      service ticket, and a new AS-REP's TGT is at the new kvno;
//   4. `rotate-krbtgt-invalidate` without `confirm` is refused (400); with
//      it, once run, the kvno moves again, nothing is kept, and BOTH earlier
//      TGTs are refused KRB_AP_ERR_BADKEYVER (44); a fresh AS exchange works;
//   5. the scheduler lists both jobs for the realm, and the scheduled one is
//      off in development and on in product;
//   6. the DEFAULT realm's console page (`/admin/kerberos/principals` as
//      JSON) and the API report the same krbtgt kvno.
//
// No key is in any answer: the krbtgt block is checked for one.
//
// THE CLIENT is `krb5_wire.js` beside this file. In product the krbtgt key is
// random and nothing outside the service can derive it, so everything is
// asserted from what the KDC answers, never by opening a ticket.
//
// WHAT IT CHANGES: one trust realm, created here and left standing
// (`leave-test-created-realms`), with a person and a service principal in it.
// The default realm's krbtgt is not touched.
//
// OWNED HERE (local: true): this repository's KDC, scheduler and API.
// ---------------------------------------------------------------------------

const assert = require("assert");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const facts = require("./service_facts.js");
const signin = require("./console_signin");
const wire = require("./krb5_wire.js");

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
var log = bunyan.createLogger({ name: "sts_kerberos_krbtgt_rotation",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const api = base + "/admin-api";

const STAMP = names.runStamp();
const RID = ("krbtgt-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                               .slice(0, 31);
const DOMAIN = RID + ".example.net";
const KREALM = DOMAIN.toUpperCase();
const USER = names.usernameFor("krbtgt-rot");
const PASSWORD = "Krbtgt-Rotation-Passw0rd!-" + String(Date.now()).slice(-6);
const SPN = "HTTP/app." + DOMAIN;

// How long a queued run may take to happen: the scheduler's leader picks it
// up at its next tick (`scheduler.tickS`), and in a cluster the next tick of
// whichever node leads.
const RUN_WAIT_MS = 120000;
// How long a product person's keys, and a product realm's first krbtgt key
// behind a shared store, may take to arrive (sts_kerberos_spnego.js's
// number).
const KEYS_WAIT_MS = 30000;

const K = { product: false, password: "" };

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function pause(ms) {
  log.debug("Entering pause().");
  log.debug("Leaving pause().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

async function call(method, url, body, headers) {
  log.debug("Entering call(). " + method + " " + url);
  const r = await fetch(url, { method: method, redirect: "manual",
    headers: Object.assign({ "Content-Type": "application/json" },
                           headers || {}),
    body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in call(): " + ((e && e.message) || e));
    // Not JSON; `text` carries it into the message.
    json = null;
  }
  log.debug("Leaving call(). HTTP " + r.status);
  return { status: r.status, json: json, text: text };
}

async function ok(url, body, what) {
  log.debug("Entering ok().");
  const r = await call("POST", url, body);
  assert.ok(r.status === 200 && r.json && r.json.ok !== false,
            what + ": " + r.status + " " + r.text.slice(0, 400));
  log.debug("Leaving ok().");
  return r.json;
}

const realmApi = base + "/realm/" + RID + "/admin-api";

// The realm's krbtgt block, as `GET /admin-api/kerberos/principals` draws it.
async function krbtgtOf(apiBase) {
  log.debug("Entering krbtgtOf().");
  const r = await call("GET", apiBase + "/kerberos/principals");
  assert.strictEqual(r.status, 200, r.text.slice(0, 300));
  log.debug("Leaving krbtgtOf().");
  return (r.json && r.json.krbtgt) || null;
}

// Until the realm's krbtgt kvno is `kvno` — the queued run has happened.
async function waitForKvno(kvno) {
  log.debug("Entering waitForKvno(). " + kvno);
  const started = Date.now();
  let seen = null;
  while (Date.now() - started < RUN_WAIT_MS) {
    seen = await krbtgtOf(realmApi);
    if (seen && seen.kvno === kvno) {
      log.debug("Leaving waitForKvno().");
      return seen;
    }
    await pause(1000);
  }
  log.debug("Leaving waitForKvno(). Timed out.");
  return seen;
}

function refusal(result) {
  log.debug("Entering refusal().");
  log.debug("Leaving refusal().");
  return (result.second && result.second.error) ||
         (result.first && result.first.error) || null;
}

// An AS exchange in the throwaway realm, retried only while the refusal is
// one of product mode's windows: the person's keys, or the realm's first
// krbtgt key made under a claim, not there yet.
async function signIn(transport) {
  log.debug("Entering signIn().");
  const started = Date.now();
  for (;;) {
    const r = await wire.asExchange(transport, KREALM, USER,
                                    { password: K.password });
    const e = refusal(r);
    if (!(K.product && !r.tgt && e &&
          /no Kerberos keys yet|sign in once|nobody by that name|krbtgt/i
            .test(e.eText) && Date.now() - started < KEYS_WAIT_MS)) {
      log.debug("Leaving signIn().");
      return r;
    }
    await pause(500);
  }
}

function service() {
  log.debug("Entering service().");
  log.debug("Leaving service().");
  return { type: 3, name: SPN.split("/") };
}

function codeOf(result) {
  log.debug("Entering codeOf().");
  log.debug("Leaving codeOf().");
  return result && !result.ok && result.error ? result.error.code : null;
}

// No key material in a krbtgt block: no member named for one, and no long
// base64 run anywhere in it.
function holdsNoKey(block) {
  log.debug("Entering holdsNoKey().");
  const text = JSON.stringify(block || {});
  log.debug("Leaving holdsNoKey().");
  return !/"keys?"\s*:/.test(text) && !/[A-Za-z0-9+/]{40,}={0,2}/.test(text);
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving a krbtgt rotation in the throwaway realm " + RID +
           " at " + base);
  K.product = await facts.isProduct(api);

  log.info("=== 1. the realm, the person and the service principal ===");
  await ok(api + "/realms/create",
           { id: RID, domain: DOMAIN, name: "#169 krbtgt rotation",
             overrides: { "krb5.enabled": true, "krb5.realm": KREALM } },
           "created the realm " + RID + " with Kerberos on");
  K.password = K.product ? PASSWORD
    : String(await facts.setting(realmApi, "krb5.userPassword") ||
             "password!");
  await ok(realmApi + "/users/create",
           { username: USER, invent: false, credential: "password",
             password: PASSWORD,
             attributes: { cn: "krbtgt " + USER, givenName: "krbtgt",
                           sn: USER, displayName: "krbtgt " + USER,
                           mail: USER + "@" + DOMAIN } },
           "created " + USER + " in " + RID);
  const made = await ok(realmApi + "/kerberos/principals/create-service",
                        { spn: SPN }, "created " + SPN);
  check("the service principal " + SPN + " holds a key, and its keytab is " +
        "the only key in any answer here", function () {
    assert.ok(made.keytab && made.kvno, JSON.stringify(made).slice(0, 200));
  });
  const kdc = wire.proxyTransport(base + "/realm/" + RID);

  log.info("=== 2. a TGT ===");
  const first = await signIn(kdc);
  check("AS exchange at /realm/" + RID + "/KdcProxy: a TGT for " + USER,
        function () {
    assert.ok(first.tgt, "no TGT: " + JSON.stringify(refusal(first)));
  });
  const tgt1 = first.tgt;
  const k0 = tgt1.ticket.encPart.kvno;
  const before = await krbtgtOf(realmApi);
  const status = await call("GET", realmApi + "/kerberos");
  check((K.product ? "PRODUCT: the krbtgt key is a stored random one"
                   : "DEVELOPMENT: the krbtgt key is the password's") +
        ", at the kvno the TGT names, and the settings page's status says " +
        "the same", function () {
    assert.ok(before, "no krbtgt block");
    assert.strictEqual(before.source, K.product ? "stored" : "password",
                       JSON.stringify(before));
    assert.strictEqual(before.kvno, k0, JSON.stringify(before));
    const st = status.json && status.json.status && status.json.status.krbtgt;
    assert.ok(st && st.kvno === k0, JSON.stringify(st));
    assert.ok(holdsNoKey(before) && holdsNoKey(st),
              "a key-shaped value is in a krbtgt block");
  });
  const t1 = await wire.tgsExchange(kdc, tgt1, service(), KREALM);
  check("the TGT buys a ticket for " + SPN, function () {
    assert.ok(t1.ok, t1.error && t1.error.toString());
  });

  log.info("=== 3. rotate-krbtgt ===");
  const queued = await ok(realmApi + "/kerberos/principals/rotate-krbtgt",
                          {}, "queued a krbtgt rotation");
  check("rotate-krbtgt QUEUES a run and returns no key", function () {
    assert.ok(queued.queued && queued.runId, JSON.stringify(queued));
    assert.ok(holdsNoKey(queued), JSON.stringify(queued));
  });
  const rotated = await waitForKvno(k0 + 1);
  check("once the scheduler has run it the kvno is " + (k0 + 1) + " and " +
        "kvno " + k0 + " is kept, with the rotation's time reported",
        function () {
    assert.ok(rotated && rotated.kvno === k0 + 1,
              "the kvno did not move within " + RUN_WAIT_MS + " ms: " +
              JSON.stringify(rotated));
    assert.strictEqual(rotated.source, "stored");
    assert.ok((rotated.retained || []).some(function (one) {
      return one.kvno === k0;
    }), JSON.stringify(rotated.retained));
    assert.ok(rotated.lastRotatedAt, JSON.stringify(rotated));
  });
  const old = await wire.tgsExchange(kdc, tgt1, service(), KREALM);
  check("THE OLD TGT STILL BUYS A SERVICE TICKET, through the kept kvno",
        function () {
    assert.ok(old.ok, old.error && old.error.toString());
  });
  const second = await signIn(kdc);
  check("a new TGT is sealed under kvno " + (k0 + 1), function () {
    assert.ok(second.tgt, "no TGT: " + JSON.stringify(refusal(second)));
    assert.strictEqual(second.tgt.ticket.encPart.kvno, k0 + 1);
  });
  const tgt2 = second.tgt;

  log.info("=== 4. rotate-krbtgt-invalidate ===");
  const unconfirmed = await call("POST", realmApi +
    "/kerberos/principals/rotate-krbtgt-invalidate", {});
  check("without confirm: \"invalidate\" it is refused (400) and nothing " +
        "is queued", function () {
    assert.strictEqual(unconfirmed.status, 400, unconfirmed.text.slice(0,
                                                                       300));
  });
  await ok(realmApi + "/kerberos/principals/rotate-krbtgt-invalidate",
           { confirm: "invalidate" }, "queued an invalidation");
  const invalidated = await waitForKvno(k0 + 2);
  check("once run, the kvno is " + (k0 + 2) + " and NOTHING is kept",
        function () {
    assert.ok(invalidated && invalidated.kvno === k0 + 2,
              JSON.stringify(invalidated));
    assert.strictEqual((invalidated.retained || []).length, 0,
                       JSON.stringify(invalidated.retained));
    assert.ok(invalidated.invalidatedAt, JSON.stringify(invalidated));
  });
  const dead1 = await wire.tgsExchange(kdc, tgt1, service(), KREALM);
  const dead2 = await wire.tgsExchange(kdc, tgt2, service(), KREALM);
  check("BOTH earlier TGTs are refused KRB_AP_ERR_BADKEYVER (44)",
        function () {
    assert.strictEqual(codeOf(dead1), 44,
                       dead1.ok ? "accepted" : dead1.error.toString());
    assert.strictEqual(codeOf(dead2), 44,
                       dead2.ok ? "accepted" : dead2.error.toString());
  });
  const third = await signIn(kdc);
  const t3 = third.tgt
    ? await wire.tgsExchange(kdc, third.tgt, service(), KREALM) : null;
  check("a fresh AS exchange gets a TGT at kvno " + (k0 + 2) + " that works",
        function () {
    assert.ok(third.tgt, "no TGT: " + JSON.stringify(refusal(third)));
    assert.strictEqual(third.tgt.ticket.encPart.kvno, k0 + 2);
    assert.ok(t3 && t3.ok, t3 && t3.error && t3.error.toString());
  });

  log.info("=== 5. the scheduler ===");
  const jobs = await call("GET", realmApi + "/scheduler?per=200");
  check("the scheduler lists krb5.krbtgt-rotate (" +
        (K.product ? "on" : "off in development") + ") and " +
        "krb5.krbtgt-rotate-now", function () {
    assert.strictEqual(jobs.status, 200, jobs.text.slice(0, 300));
    const text = jobs.text;
    assert.ok(text.indexOf("krb5.krbtgt-rotate-now") >= 0,
              "krb5.krbtgt-rotate-now is not listed");
    assert.ok(text.indexOf("\"krb5.krbtgt-rotate\"") >= 0,
              "krb5.krbtgt-rotate is not listed");
  });
  const view = await krbtgtOf(realmApi);
  check("the krbtgt block says whether the schedule is on, and why not",
        function () {
    assert.strictEqual(view.scheduled, K.product, JSON.stringify(view));
    if (K.product) {
      assert.ok(view.nextDueAt, JSON.stringify(view));
    } else {
      assert.ok(/development/.test(view.offReason), view.offReason);
    }
  });

  log.info("=== 6. the console and the API ===");
  const reader = "krbtgt-reader-" + STAMP;
  const cookie = await signin.signInToTheConsole(base, reader, log,
                                                 { grant: "read" });
  const page = await call("GET", base + "/admin/kerberos/principals" +
                          "?format=json", undefined,
                          cookie ? { Cookie: cookie } : {});
  const apiView = await krbtgtOf(api);
  check("the default realm's console page and the API report the same " +
        "krbtgt kvno", function () {
    assert.strictEqual(page.status, 200, page.text.slice(0, 300));
    const drawn = page.json && page.json.krbtgt;
    assert.ok(drawn && apiView, JSON.stringify([drawn, apiView]));
    assert.strictEqual(drawn.kvno, apiView.kvno);
    assert.strictEqual(drawn.source, apiView.source);
    assert.ok(holdsNoKey(drawn), "a key-shaped value is on the page");
  });

  const floor = 14;
  assert.ok(checks >= floor, "only " + checks + " checks ran (floor " +
            floor + "); a section has stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_kerberos_krbtgt_rotation")
  .description("A realm's krbtgt key rotates by hand, queued on the " +
    "scheduler: a TGT outlives a rotation through the kept kvno and is " +
    "refused KRB_AP_ERR_BADKEYVER after rotate-and-invalidate (#169).")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
