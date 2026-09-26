"use strict";
//
// File: sts_ssf_oidf_conformance.js
//
// ---------------------------------------------------------------------------
// THE OPENID FOUNDATION'S CONFORMANCE SUITE: SHARED SIGNALS (#187,
// 2026-09-24). `openid-ssf-transmitter-test-plan` and
// `openid-ssf-transmitter-caep-test-plan` (the CAEP Interop Profile), each by
// push and by poll, against this service as the TRANSMITTER, on the three
// containers `sts_fapi_conformance.js` (#176) brought into the stack. Not to
// be confused with `sts_ssf_conformance.js`, this repository's own SSF 1.0
// checks (#144), which this job does not replace.
//
//   1. Per plan a throwaway realm, a receiver registered as an OAuth client
//      (client_secret_post, `client_credentials`) with `ssf:read` and
//      `ssf:write` declared by an administrator (#110) — the plans' dynamic
//      auth mode, in which the suite gets its own access token — and the
//      suite's certificate as the realm's `ssf.pushCaFile`, so a push reaches
//      the suite with verification on (#171).
//   2. The suite finds the transmitter the way SSF 1.0 section 6.2.1 says:
//      the issuer `https://…:8081` and the path suffix `/realm/<id>`, whose
//      configuration is at `/.well-known/ssf-configuration/realm/<id>`.
//   3. The CAEP interop module waits for events "triggered on the
//      transmitter". This job is that operator: once the module says it is
//      waiting, it signs the realm's person in (a real session, through the
//      browser flow `sts_applications.authorizationCode()` drives) and emits
//      each CAEP event the stream delivers through `/admin-api/caep/emit`,
//      the door `/admin/caep` shares.
//   4. The ledger is `conformance_suite.js`'s: a FAILED module, or a WARNING
//      from a condition KNOWN_WARNINGS does not name, fails the job.
//
// The receiver plans are #153's (this service as a receiver of somebody
// else's transmitter), and are not run here.
//
// OWNED HERE (local: true): this repository's SSF transmitter.
// ---------------------------------------------------------------------------

const assert = require("assert");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const registry = require("./sts_applications.js");
const oidf = require("./conformance_suite.js");

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
var log = bunyan.createLogger({ name: "sts_ssf_oidf_conformance",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var root = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const TAG = STAMP.toLowerCase().replace(/[^a-z0-9]/g, "").slice(0, 10);
const PASSWORD = "Conf-Passw0rd!-" + String(Date.now()).slice(-6);

const COMMON = { server_metadata: "discovery",
                 client_registration: "static_client",
                 client_auth_type: "client_secret_post",
                 ssf_auth_mode: "dynamic", ssf_server_metadata: "discovery" };

const PLANS = [
  { key: "ssf-push", name: "openid-ssf-transmitter-test-plan",
    variant: Object.assign({ ssf_delivery_mode: "push",
                             ssf_profile: "default" }, COMMON) },
  { key: "ssf-poll", name: "openid-ssf-transmitter-test-plan",
    variant: Object.assign({ ssf_delivery_mode: "poll",
                             ssf_profile: "default" }, COMMON) },
  { key: "caep-push", name: "openid-ssf-transmitter-caep-test-plan",
    variant: Object.assign({ ssf_delivery_mode: "push" }, COMMON) },
  { key: "caep-poll", name: "openid-ssf-transmitter-caep-test-plan",
    variant: Object.assign({ ssf_delivery_mode: "poll" }, COMMON) }
];

const EXPECTED = {};
// Conditions whose WARNING this service keeps, and why — the same sentences
// as `oauth-oidc/CLAUDE.md` 3bl.
const KNOWN_WARNINGS = {
  WarnOnUnusableJwksKeys: "the realm's JWKS carries post-quantum keys " +
    "(kty AKP, ML-DSA and SLH-DSA) the suite cannot parse; rcbj " +
    "(2026-09-24): PQC support matters more than a clean run (3bg)",
  OIDSSFCheckSupportedEventsForStream: "events_supported names this " +
    "service's own two event types (urn:iya:sts:secevent:event-type:" +
    "signing-key-rotated and :kerberos-tickets-invalidated); SSF 1.0's " +
    "events_supported is an open list of event type URIs",
  OIDSSFWarnCaepInteropEventUsesComplexSubject: "a CAEP event about a " +
    "session names the session AND its user, which only a complex subject " +
    "can (CAEP 1.0 section 3); the suite accepts it and says the interop " +
    "profile is expected to permit it (openid/sharedsignals#351)"
};

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

async function prepare(plan) {
  log.debug("Entering prepare(). " + plan.key);
  const id = ("ssf-" + plan.key + "-" + TAG).slice(0, 31).replace(/-+$/, "");
  const realm = await oidf.makeRealm(root, id, "Conformance " + plan.name, [
    ["oauth2.openRegistration", true],
    ["ssf.pushCaFile", oidf.suiteCaFile()]]);
  const person = names.usernameFor("conf-" + plan.key);
  await oidf.makePerson(realm.api, person, PASSWORD);
  const registered = await oidf.send(realm.base + "/oauth2/register", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_name: "conformance SSF receiver " + plan.key,
      grant_types: ["client_credentials", "authorization_code"],
      response_types: ["code"],
      redirect_uris: ["https://receiver.invalid/callback"],
      token_endpoint_auth_method: "client_secret_post" }) });
  assert.strictEqual(registered.status, 201, plan.key + " receiver: " +
                     registered.raw.slice(0, 400));
  // ssf:read and ssf:write are this service's protected scopes (#110): a
  // registration may not grant them to itself, and an administrator
  // declares them.
  for (const scope of ["ssf:read", "ssf:write"]) {
    await oidf.ok(realm.api + "/applications/add", {
      application: registered.body.client_id,
      attribute: "oauthAllowedScope", value: scope },
      "declared " + scope);
  }
  const configuration = {
    alias: "iya-" + plan.key + "-" + TAG,
    description: "iya-sts " + plan.name + " " + STAMP,
    server: { discoveryUrl: realm.base + "/.well-known/openid-configuration",
              allow_unexpected_metadata_fields: oidf.EXTENSION_METADATA },
    client: { client_id: registered.body.client_id,
              client_secret: registered.body.client_secret,
              scope: "ssf:read ssf:write" },
    ssf: { transmitter: { issuer: root,
                          metadata_suffix: "/realm/" + id } }
  };
  log.debug("Leaving prepare().");
  return { realm: realm, person: person,
           clientId: registered.body.client_id,
           configuration: configuration };
}

// ---------------------------------------------------------------------------
// THE OPERATOR THE CAEP INTEROP MODULE WAITS FOR (see the header).
// ---------------------------------------------------------------------------
async function sessionOf(prepared) {
  log.debug("Entering sessionOf().");
  await registry.authorizationCode(prepared.realm.base, {
    clientId: prepared.clientId,
    redirectUri: "https://receiver.invalid/callback",
    username: prepared.person, password: PASSWORD, scope: "openid" });
  const listed = await oidf.send(prepared.realm.api + "/caep/sessions");
  const rows = [].concat((listed.body && (listed.body.sessions ||
                                          listed.body)) || []);
  const mine = rows.filter(function (row) {
    return row && String(row.username || "") === prepared.person;
  });
  assert.ok(mine.length, "no CAEP session row for " + prepared.person +
            ": " + listed.raw.slice(0, 300));
  log.debug("Leaving sessionOf().");
  return String(mine[mine.length - 1].sessionId || mine[mine.length - 1].id);
}

async function triggerCaep(prepared, instanceId) {
  log.debug("Entering triggerCaep(). " + instanceId);
  const deadline = Date.now() + 240000;
  let expected = null;
  while (Date.now() < deadline && !expected) {
    const logs = (await oidf.suite("GET", "api/log/" + instanceId)).body ||
                 [];
    const waiting = logs.filter(function (entry) {
      return /Please trigger these events/.test(String(entry.msg || ""));
    })[0];
    if (waiting) {
      expected = [].concat(waiting.expected_caep_event_types || []);
      break;
    }
    const info = (await oidf.suite("GET", "api/info/" + instanceId)).body ||
                 {};
    if (info.status === "FINISHED" || info.status === "INTERRUPTED") {
      log.debug("Leaving triggerCaep(). The module ended first.");
      return;
    }
    await oidf.waitMs(1500);
  }
  if (!expected) {
    log.debug("Leaving triggerCaep(). Never asked.");
    return;
  }
  const session = await sessionOf(prepared);
  // The session revocation LAST: the others are about a live session.
  expected.sort(function (a, b) {
    return (/session-revoked/.test(a) ? 1 : 0) -
           (/session-revoked/.test(b) ? 1 : 0);
  });
  for (const type of expected) {
    await oidf.ok(prepared.realm.api + "/caep/emit", {
      session_id: session, type: type, initiating_entity: "admin" },
      "emitted " + type);
    log.info("  emitted " + type + " on session " + session);
  }
  log.debug("Leaving triggerCaep().");
}

async function runPlan(plan, prepared) {
  log.debug("Entering runPlan(). " + plan.key);
  const created = await oidf.suite("POST", "api/plan?planName=" +
    encodeURIComponent(plan.name) + "&variant=" +
    encodeURIComponent(JSON.stringify(plan.variant)),
    prepared.configuration);
  assert.ok(created.status === 201 || created.status === 200,
            "creating " + plan.name + ": " + created.raw.slice(0, 400));
  const results = [];
  const modules = created.body.modules || [];
  for (let i = 0; i < modules.length; i++) {
    let got = null;
    if (/caep-interop/.test(modules[i].testModule)) {
      // The module and the operator side by side: runModule() creates the
      // instance, so the trigger finds it through the plan.
      const running = oidf.runModule(created.body.id, modules[i]);
      const trigger = (async function () {
        for (let n = 0; n < 40; n++) {
          const now = (await oidf.suite("GET", "api/plan/" +
                                        created.body.id)).body || {};
          const row = (now.modules || [])[i] || {};
          const instances = row.instances || [];
          if (instances.length) {
            return triggerCaep(prepared, instances[instances.length - 1]);
          }
          await oidf.waitMs(500);
        }
        return null;
      })();
      got = await running;
      await trigger.catch(function (e) {
        log.warn("The CAEP trigger failed: " + ((e && e.message) || e));
      });
    } else {
      got = await oidf.runModule(created.body.id, modules[i]);
    }
    log.info("  " + plan.key + " " + got.module + ": " +
             (got.result || got.status) +
             (got.failures.length ? " — " + got.failures[0].src + ": " +
                                    got.failures[0].msg : ""));
    results.push(got);
  }
  log.debug("Leaving runPlan().");
  return { planId: created.body.id, results: results };
}

async function test() {
  log.debug("Entering test().");
  await registry.isProduct(root);
  await oidf.waitForSuite();
  const unexpected = [];
  for (const plan of PLANS) {
    if (!oidf.selected(plan.key)) {
      continue;
    }
    log.info("=== " + plan.name + " " + JSON.stringify(plan.variant) +
             " (" + plan.key + ") ===");
    let ran = null;
    try {
      ran = await runPlan(plan, await prepare(plan));
    } catch (e) {
      log.error("Caught in test(): " + plan.key + ": " +
                ((e && e.message) || e));
      unexpected.push(plan.key + " could not run: " +
                      ((e && e.message) || e));
      continue;
    }
    const judged = oidf.judge(plan.key, ran, EXPECTED, KNOWN_WARNINGS);
    log.info("  " + plan.key + ": " + JSON.stringify(judged.counts) +
             ", plan " + oidf.SUITE + "plan-detail.html?plan=" + ran.planId);
    judged.unexplained.forEach(function (line) {
      unexpected.push(line);
    });
  }
  if (unexpected.length) {
    log.error("Unexplained:\n  " + unexpected.join("\n  "));
  }
  check("every module passed or is argued, and every warning is known",
        function () {
          assert.strictEqual(unexpected.length, 0, unexpected.join("\n"));
        });
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

new Command()
  .description("The OpenID Foundation conformance suite's Shared Signals " +
    "transmitter plans (#187), push and poll, against this service.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
