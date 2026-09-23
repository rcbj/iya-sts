"use strict";
//
// File: sts_kerberos_signout.js
//
// ---------------------------------------------------------------------------
// A KERBEROS SIGN-OUT OUTLIVES THE NEXT AS EXCHANGE — OVER TCP 88, AGAINST
// THE SERVICE (#111, 2026-09-23).
//
// A global sign-out stamps a sign-out instant on the person's principal, and
// the KDC refuses a TGS-REQ presenting a ticket authenticated before it with
// KDC_ERR_TGT_REVOKED (20). Until #111 the person's next successful AS
// exchange CLEARED the instant, so every ticket-granting ticket from before
// the sign-out — a renewal of one included — was accepted again. This job is a
// Kerberos client at the service's published address and asserts, in order:
//
//   1. sign in: a renewable TGT, which buys a service ticket;
//   2. sign out (`POST /admin-api/logout/global`): the TGT is refused 20;
//   3. a NEW AS exchange, straight away, succeeds — signing out is not being
//      locked out — with an authtime at or after the sign-out's whole second,
//      and its TGT buys a service ticket;
//   4. the OLD TGT is STILL refused 20 — the issue's case;
//   5. a RENEWAL of the old TGT is refused 20 (a renewal keeps authtime), and
//      a renewal of the new one is accepted with its authtime kept;
//   6. `restore-kerberos`, the console's undo: refused in product mode
//      (HTTP 400) with the old TGT still refused; in development it clears
//      the instant and the old TGT is accepted again.
//
// THE CLIENT is `krb5_wire.js` beside this file: the vendored codec for RFC
// 4120's encodings, the exchanges assembled there apart from the KDC.
//
// WHAT IT CHANGES: one person, created here and signed out here. Nothing is
// loosened; no setting is changed.
//
// WHERE IT DIALS: the KDC at the service URL's host and `krb5.kdcPort`, or
// STS_KDC_HOST / STS_KDC_PORT (sts_kerberos_spnego.js's convention).
//
// OWNED HERE (local: true): this repository's KDC and API.
// ---------------------------------------------------------------------------

const assert = require("assert");
const { Command, Option } = require("commander");
const { usernameFor } = require("./random_username.js");
const facts = require("./service_facts.js");
const wire = require("./krb5_wire.js");
const { declineToRun } = require("./expectation.js");

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
var log = bunyan.createLogger({ name: "sts_kerberos_signout",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const apiBase = base + "/admin-api";

const P = usernameFor("krb5-signout");
const PASSWORD = "Krb5-Sign-Out-Passw0rd!-" + String(Date.now()).slice(-6);

const K = { product: false, realm: "", kdcHost: "", kdcPort: 88,
            servicePrincipal: "", password: "" };

// How long a product person's keys may take to appear after the password is
// set (sts_kerberos_spnego.js argues the number).
const KEYS_WAIT_MS = 20000;

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

async function apiCall(method, pathName, body) {
  log.debug("Entering apiCall(). " + method + " " + pathName);
  const init = { method: method, headers: {} };
  if (body !== undefined) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(body);
  }
  const r = await fetch(apiBase + pathName, init);
  const raw = await r.text();
  let parsed = null;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in apiCall(): " + ((e && e.message) || e));
    parsed = raw;
  }
  log.debug("Leaving apiCall(). " + r.status);
  return { status: r.status, body: parsed, raw: raw };
}

async function learnTheService() {
  log.debug("Entering learnTheService().");
  K.product = await facts.isProduct(apiBase);
  K.realm = String(process.env.KRB5_REALM ||
                   await facts.setting(apiBase, "krb5.realm") || "");
  K.kdcHost = process.env.STS_KDC_HOST || new URL(base).hostname;
  K.kdcPort = Number(process.env.STS_KDC_PORT ||
                     await facts.setting(apiBase, "krb5.kdcPort") || 88);
  K.servicePrincipal = String(
    await facts.setting(apiBase, "krb5.servicePrincipal") || "");
  // Product keys a person from their own password; development keys every
  // user account from one shared password (kerberos/CLAUDE.md).
  K.password = K.product ? PASSWORD
    : String(await facts.setting(apiBase, "krb5.userPassword") ||
             "password!");
  const signOutOn = await facts.setting(apiBase, "logout.kerberosSignOut");
  assert.ok(signOutOn !== false && String(signOutOn) !== "false",
            "logout.kerberosSignOut is off on this service; the job asserts " +
            "the default");
  assert.ok(K.realm && K.servicePrincipal,
            "the service reports no krb5.realm or krb5.servicePrincipal");
  log.info("mode " + (K.product ? "product" : "development") + ", realm " +
           K.realm + ", KDC " + K.kdcHost + ":" + K.kdcPort);
  log.debug("Leaving learnTheService().");
}

async function ensurePerson() {
  log.debug("Entering ensurePerson(). " + P);
  const r = await apiCall("POST", "/users/create", {
    username: P, invent: false, credential: "password", password: PASSWORD,
    attributes: { cn: "Sign-out " + P, givenName: "Sign-out", sn: P,
                  displayName: "Sign-out " + P, mail: P + "@signout.test" } });
  assert.ok(r.status === 200 && r.body && r.body.ok,
            "POST /admin-api/users/create " + P + ": " + r.status + " " +
            String(r.raw).slice(0, 300));
  log.debug("Leaving ensurePerson().");
}

// The AS exchange for P, waiting out product mode's derivation window (only
// the refusals that window produces are retried).
async function signIn(tcp) {
  log.debug("Entering signIn().");
  const started = Date.now();
  for (;;) {
    const r = await wire.asExchange(tcp, K.realm, P,
                                    { password: K.password });
    const e = (r.second && r.second.error) || (r.first && r.first.error);
    if (!(K.product && !r.tgt && e &&
          /no Kerberos keys yet|sign in once|nobody by that name/i
            .test(e.eText) && Date.now() - started < KEYS_WAIT_MS)) {
      log.debug("Leaving signIn().");
      return r;
    }
    await pause(500);
  }
}

function codeOf(result) {
  log.debug("Entering codeOf().");
  log.debug("Leaving codeOf().");
  return result && !result.ok && result.error ? result.error.code : null;
}

function service() {
  log.debug("Entering service().");
  log.debug("Leaving service().");
  return { type: 3, name: K.servicePrincipal.split("/") };
}

function krbtgt() {
  log.debug("Entering krbtgt().");
  log.debug("Leaving krbtgt().");
  return { type: 2, name: ["krbtgt", K.realm] };
}

// The sign-out instant the service reports for P: the Kerberos row's
// `startedAt` on the sign-out view IS it (0 when there is none).
async function stampOf() {
  log.debug("Entering stampOf().");
  const r = await apiCall("GET", "/logout?user=" + encodeURIComponent(P));
  const row = ((r.body && r.body.rows) || []).filter(function (one) {
    return one.family === "krb5";
  })[0];
  log.debug("Leaving stampOf().");
  return row ? Number(row.startedAt || 0) : 0;
}

async function test() {
  log.debug("Entering test().");
  if (String(process.env.STS_TEST_UNPUBLISHED || "").split(",")
        .indexOf("kerberos") >= 0) {
    declineToRun(log, "this environment does not publish the KDC's TCP 88 " +
                      "(STS_TEST_UNPUBLISHED names kerberos).");
    log.debug("Leaving test(). Skipped.");
    return;
  }
  log.info("Driving a Kerberos sign-out across a new AS exchange at " + base);
  await learnTheService();
  const tcp = wire.tcpTransport(K.kdcHost, K.kdcPort);
  await ensurePerson();

  log.info("=== 1. sign in ===");
  const first = await signIn(tcp);
  check("AS exchange: a renewable TGT for " + P, function () {
    assert.ok(first.tgt, "no TGT: " +
              JSON.stringify(first.second || first.first).slice(0, 300));
    assert.ok(first.tgt.flagNames.indexOf("renewable") !== -1,
              "not renewable: " + first.tgt.flagNames.join(","));
  });
  const old = first.tgt;
  const before = await wire.tgsExchange(tcp, old, service());
  check("the TGT buys a ticket for " + K.servicePrincipal, function () {
    assert.ok(before.ok, before.error && before.error.toString());
  });

  log.info("=== 2. sign out ===");
  const out = await apiCall("POST", "/logout/global", { user: P });
  check("POST /admin-api/logout/global signs " + P + " out", function () {
    assert.ok(out.status === 200 && out.body && out.body.ok,
              out.status + " " + String(out.raw).slice(0, 300));
  });
  const refused = await wire.tgsExchange(tcp, old, service());
  check("the TGT from before the sign-out is refused KDC_ERR_TGT_REVOKED " +
        "(20)", function () {
          assert.strictEqual(codeOf(refused), 20,
                             refused.ok ? "it was ACCEPTED"
                                        : refused.error.toString());
        });

  log.info("=== 3. a new AS exchange, straight away ===");
  const second = await signIn(tcp);
  check("a NEW AS exchange succeeds — signing out is not being locked out",
        function () {
          assert.ok(second.tgt, "no TGT: " +
                    JSON.stringify(second.second || second.first)
                      .slice(0, 300));
        });
  const fresh = second.tgt;
  const stamp = await stampOf();
  check("the sign-out instant still stands after it, and the new TGT's " +
        "authtime is at or after its whole second", function () {
          assert.ok(stamp > 0, "no sign-out instant is reported for " + P +
                    " after the AS exchange — was it cleared?");
          assert.ok(fresh.authtime.getTime() >=
                    Math.ceil(stamp / 1000) * 1000,
                    "authtime " + fresh.authtime.toISOString() +
                    " is before the sign-out " +
                    new Date(stamp).toISOString());
        });
  const newTicket = await wire.tgsExchange(tcp, fresh, service());
  check("the NEW TGT buys a service ticket", function () {
    assert.ok(newTicket.ok, newTicket.error && newTicket.error.toString());
  });

  log.info("=== 4. the old TGT, after the new AS exchange ===");
  const stillRefused = await wire.tgsExchange(tcp, old, service());
  check("THE OLD TGT IS STILL REFUSED KDC_ERR_TGT_REVOKED (20) after a new " +
        "AS exchange (#111)", function () {
          assert.strictEqual(codeOf(stillRefused), 20,
                             stillRefused.ok ? "it was ACCEPTED again"
                                             : stillRefused.error.toString());
        });

  log.info("=== 5. renewals ===");
  const renewedOld = await wire.tgsExchange(tcp, old, krbtgt(), K.realm,
                                            { renew: true });
  check("a RENEWAL of the old TGT is refused 20 — it keeps authtime",
        function () {
          assert.strictEqual(codeOf(renewedOld), 20,
                             renewedOld.ok ? "it was RENEWED"
                                           : renewedOld.error.toString());
        });
  const renewedNew = await wire.tgsExchange(tcp, fresh, krbtgt(), K.realm,
                                            { renew: true });
  check("a renewal of the NEW TGT is accepted and keeps its authtime",
        function () {
          assert.ok(renewedNew.ok,
                    renewedNew.error && renewedNew.error.toString());
          assert.strictEqual(renewedNew.authtime.toISOString(),
                             fresh.authtime.toISOString());
        });

  log.info("=== 6. restore-kerberos ===");
  const restore = await apiCall("POST", "/logout/restore-kerberos",
                                { user: P });
  if (K.product) {
    check("PRODUCT: restore-kerberos is refused (HTTP 400) — a development " +
          "test control", function () {
            assert.strictEqual(restore.status, 400,
                               String(restore.raw).slice(0, 300));
            assert.ok(restore.body && restore.body.ok === false &&
                      /development-only/.test(JSON.stringify(restore.body)),
                      String(restore.raw).slice(0, 300));
          });
    const afterRefusal = await wire.tgsExchange(tcp, old, service());
    check("and the old TGT is still refused 20", function () {
      assert.strictEqual(codeOf(afterRefusal), 20,
                         afterRefusal.ok ? "it was ACCEPTED"
                                         : afterRefusal.error.toString());
    });
  } else {
    check("DEVELOPMENT: restore-kerberos clears the instant", function () {
      assert.ok(restore.status === 200 && restore.body && restore.body.ok,
                restore.status + " " + String(restore.raw).slice(0, 300));
    });
    const restored = await wire.tgsExchange(tcp, old, service());
    check("and the old TGT buys a service ticket again", function () {
      assert.ok(restored.ok, restored.error && restored.error.toString());
    });
  }

  const floor = 12;
  assert.ok(checks >= floor, "only " + checks + " checks ran (floor " +
            floor + "); a section has stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_kerberos_signout")
  .description("A Kerberos sign-out instant survives the next AS exchange: " +
    "a ticket-granting ticket from before it, and a renewal of one, stay " +
    "refused KDC_ERR_TGT_REVOKED while a new one is accepted (#111).")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
