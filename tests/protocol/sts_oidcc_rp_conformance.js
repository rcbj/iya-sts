// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_oidcc_rp_conformance.js
//
// ---------------------------------------------------------------------------
// THE OPENID FOUNDATION'S CONFORMANCE SUITE: OPENID CONNECT RELYING PARTY
// (#930, 2026-11-02). The suite plays the OpenID Provider and this service
// is its relying party, through what makes this service one: an inbound
// OpenID Connect federation relationship (`federation/federation_sp.ts`) — a
// person signs in at the partner, and the partner's ID Token starts a
// session here. `sts_oidcc_conformance.js` runs the OpenID Provider plans;
// this runs the relying-party ones, on the same containers.
//
//   1. For each plan below, a throwaway trust realm (left behind) whose one
//      service-provider-side OpenID Connect relationship has the suite's
//      issuer for this plan's alias as its fedPeer, the suite's endpoints
//      (or, for the configuration plan, its discovery document), and a
//      client id and secret made here at run time, which the plan's static
//      client configuration names too — with this relationship's assertion
//      consumer service as its redirect_uri, and its sign-out and
//      login-initiation addresses where the plan asks for them, each read
//      off the relationship's own view rather than composed here.
//   2. The plan is created and its modules run one at a time. Before each,
//      the relationship's response type is set to the module's (the
//      implicit and hybrid plans run three and two of them), as an
//      administrator configuring the relationship would. When a module
//      waits, the PERSON starts where an application would send them —
//      this service's /federation/login/{id} — in the one headless Chrome
//      (`conformance_browser.js`), and the browser carries them to the
//      suite and back. A module of the logout plan that wants an
//      RP-Initiated Logout then signs out HERE, and follows the partner's
//      link the signed-out page offers. The third-party-initiated module
//      sends the person to this relationship's initiate_login_uri itself,
//      as an address it lists, which the person visits.
//   3. A FAILED module fails the job unless EXPECTED names it with its
//      reason; a FAILURE from a condition KNOWN_FAILURES names is argued
//      only when it is the module's only kind of failure; a WARNING from a
//      condition KNOWN_WARNINGS does not name fails it too
//      (`conformance_suite.js`'s judge(), #187's rule). A module EXPECTED
//      to wait out its time — a relying-party feature this service does not
//      have, by a decision recorded in `federation/CLAUDE.md` — is given a
//      minute (ARGUED_SECONDS) rather than five, and is not run again.
//   4. NO CLASSICAL TWIN, as the FAPI job has none, and for its reason: no
//      post-quantum key or algorithm is in front of the suite here. The
//      relying party signs nothing and publishes nothing the suite reads —
//      the ID Tokens, keys and UserInfo answers are all the suite's — so no
//      ledger entry is about a post-quantum key, and this run already is the
//      classical proof (`tests/CLAUDE.md`, *THE OPENID CONNECT RELYING PARTY
//      PLANS*).
//
// OWNED HERE (local: true): this repository's federation relying party.
// ---------------------------------------------------------------------------

const assert = require("assert");
const nodeCrypto = require("crypto");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const registry = require("./sts_applications.js");
const oidf = require("./conformance_suite.js");
const conformanceBrowser = require("./conformance_browser.js");

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
var log = bunyan.createLogger({ name: "sts_oidcc_rp_conformance",
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

// What every plan leaves to its runner: a static client (the relationship is
// configured, not registered), and plain authorization requests.
const STATIC = { client_registration: "static_client",
                 request_type: "plain_http_request" };
// And for a plan that fixes no variant at all.
const WHOLE = Object.assign({ response_type: "code",
                              response_mode: "default",
                              client_auth_type: "client_secret_basic" },
                            STATIC);

// ---------------------------------------------------------------------------
// THE PLANS. `key` is what CONFORMANCE_PLANS names (a trailing `*` is a
// prefix); `variant` is what the plan leaves open; `responseMode` is the
// relationship's fedResponseMode — `fragment` where the plan's response mode
// is the specification's default (what the suite sends whatever is asked),
// `form_post` for the three formpost plans; `discovery` reads the partner's
// endpoints from its discovery document at each sign-in; `logout` and
// `initiate` register the sign-out and login-initiation addresses.
// ---------------------------------------------------------------------------
const PLANS = [
  { key: "basic", name: "oidcc-client-basic-certification-test-plan",
    variant: STATIC, responseMode: "fragment" },
  { key: "implicit", name: "oidcc-client-implicit-certification-test-plan",
    variant: STATIC, responseMode: "fragment" },
  { key: "hybrid", name: "oidcc-client-hybrid-certification-test-plan",
    variant: STATIC, responseMode: "fragment" },
  { key: "config", name: "oidcc-client-config-certification-test-plan",
    variant: Object.assign({ response_mode: "default",
                             client_auth_type: "client_secret_basic" },
                           STATIC),
    responseMode: "fragment", discovery: true },
  { key: "dynamic", name: "oidcc-client-dynamic-certification-test-plan",
    variant: { response_mode: "default",
               client_auth_type: "client_secret_basic" },
    responseMode: "fragment", discovery: true, dynamic: true },
  { key: "formpost-basic",
    name: "oidcc-client-formpost-basic-certification-test-plan",
    variant: STATIC, responseMode: "form_post" },
  { key: "formpost-implicit",
    name: "oidcc-client-formpost-implicit-certification-test-plan",
    variant: STATIC, responseMode: "form_post" },
  { key: "formpost-hybrid",
    name: "oidcc-client-formpost-hybrid-certification-test-plan",
    variant: STATIC, responseMode: "form_post" },
  { key: "3rdparty", name: "oidcc-client-test-3rd-party-init-login-test-plan",
    variant: WHOLE, responseMode: "fragment", initiate: true },
  { key: "logout", name: "oidcc-client-logout-test-plan",
    variant: WHOLE, responseMode: "fragment", logout: true },
  { key: "refresh", name: "oidcc-client-refreshtoken-test-plan",
    variant: WHOLE, responseMode: "fragment" }
];

// ---------------------------------------------------------------------------
// KNOWN AND ARGUED DIFFERENCES. `<plan key>/<module>` (or `*/<module>`) ->
// why a module that FAILED or waited out its time is not a defect here — the
// same sentences as `federation/CLAUDE.md`'s *THE OPENID CONNECT RELYING
// PARTY PLANS*.
// ---------------------------------------------------------------------------
const SESSION_MANAGEMENT = "this relying party does not poll the " +
  "partner's check_session_iframe: rcbj's decision 3 on #167 " +
  "(federation/CLAUDE.md), because the script it needs is admitted only " +
  "where a page cannot work without one and Back-Channel Logout tells " +
  "this relying party what it would find out";
const NO_REFRESH = "this relying party holds no partner's refresh token: " +
  "the partner's tokens learn who the person is and are discarded, and " +
  "its sign-out and Shared Signals end the session (federation/CLAUDE.md, " +
  "*Things this half deliberately does not do*, kept by #930)";
const NO_DYNAMIC = "this relying party is configured by an administrator: " +
  "it does not register itself at a partner (RFC 7591), discover a partner " +
  "by WebFinger from an identifier somebody types, or send request " +
  "objects by reference (federation/CLAUDE.md, #930)";
const EXPECTED = {
  "logout/oidcc-client-test-session-management": SESSION_MANAGEMENT,
  "refresh/oidcc-client-test-refresh-token": NO_REFRESH,
  "refresh/oidcc-client-test-refresh-token-invalid-issuer": NO_REFRESH,
  "refresh/oidcc-client-test-refresh-token-invalid-sub": NO_REFRESH
};
// Every module of the dynamic plan.
const EXPECTED_PLANS = { dynamic: NO_DYNAMIC };

// How long a module EXPECTED to wait out its time is given.
const ARGUED_SECONDS = 30;

// FAILURE conditions this service keeps, keyed by the suite's condition.
const KNOWN_FAILURES = {};

// Conditions whose WARNING this service keeps, and why.
const KNOWN_WARNINGS = {};

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

// The module names whose person signs out here after signing in: the
// RP-Initiated Logout modules, alone and beside the back- and front-channel
// ones the partner sends when it is told.
function signsOut(moduleName) {
  log.debug("Entering signsOut(). " + moduleName);
  log.debug("Leaving signsOut().");
  return /rp-init-logout|rpinitlogout|session-management/.test(
    String(moduleName || ""));
}

// The response type a module tests: its own variant, the plan's, or code.
function responseTypeOf(plan, module) {
  log.debug("Entering responseTypeOf().");
  const own = (module && module.variant) || {};
  log.debug("Leaving responseTypeOf().");
  return String(own.response_type || (plan.variant || {}).response_type ||
                "code");
}

function expectedFor(plan, moduleName) {
  log.debug("Entering expectedFor(). " + moduleName);
  log.debug("Leaving expectedFor().");
  return EXPECTED_PLANS[plan.key] ||
         EXPECTED[plan.key + "/" + moduleName] ||
         EXPECTED["*/" + moduleName] || "";
}

// ---------------------------------------------------------------------------
// THE REALM AND ITS RELATIONSHIP (step 1 of the header).
// ---------------------------------------------------------------------------
async function relationshipView(api, id) {
  log.debug("Entering relationshipView(). " + id);
  const r = await oidf.send(api + "/federation?relationship=" +
                            encodeURIComponent(id));
  assert.ok(r.status === 200 && r.body, "the relationship " + id +
            " answered " + r.status + " " + String(r.raw).slice(0, 300));
  log.debug("Leaving relationshipView().");
  return r.body;
}

async function setField(api, id, field, value) {
  log.debug("Entering setField(). " + field);
  await oidf.ok(api + "/federation/set",
                { id: id, field: field, value: String(value) },
                "set " + field + " on " + id);
  log.debug("Leaving setField().");
}

async function prepare(plan) {
  log.debug("Entering prepare(). " + plan.key);
  const realm = ("oidcc-rp-" + plan.key + "-" + TAG).slice(0, 31)
    .replace(/-+$/, "");
  const alias = "iya-rp-" + plan.key + "-" + TAG;
  const issuer = oidf.SUITE + "test/a/" + alias + "/";
  const made = await oidf.makeRealm(root, realm, "Conformance " + plan.name,
    // What the service fetches from the suite — its token, UserInfo and
    // JWKS endpoints and its discovery document — and what it sends there
    // goes through the federation outbound policy, verified against the
    // suite's own certificate (#171).
    [["federation.outboundCaFile", oidf.suiteCaFile()]]);
  const id = "suite-" + plan.key;
  const clientId = "iya-rp-" + plan.key + "-" + TAG;
  const secret = nodeCrypto.randomBytes(32).toString("base64url");
  await oidf.ok(made.api + "/federation/create",
                { id: id, role: "service-provider", protocol: "oidc",
                  peer: issuer },
                "created the relationship " + id);
  const fields = {
    fedName: "The conformance suite (" + plan.key + ")",
    // The suite's one subject is a person this realm has never seen, and a
    // relationship created in product mode does not create entries.
    fedAutocreateUsers: "TRUE",
    fedClientId: clientId, fedClientSecret: secret,
    fedTokenAuth: "client_secret_basic",
    fedScope: "openid profile email",
    fedResponseType: "code",
    fedResponseMode: plan.responseMode || ""
  };
  if (plan.discovery) {
    fields.fedDiscovery = "TRUE";
  } else {
    fields.fedSsoUrl = issuer + "authorize";
    fields.fedTokenUrl = issuer + "token";
    fields.fedUserinfoUrl = issuer + "userinfo";
    fields.fedJwksUri = issuer + "jwks";
  }
  if (plan.logout) {
    fields.fedEndSessionUrl = issuer + "end_session_endpoint";
  }
  if (plan.initiate) {
    fields.fedInitiateLogin = "TRUE";
  }
  // PRODUCT MODE requires a partner to encrypt an ID Token that crosses the
  // browser, to the relationship's key. The suite could only be told to
  // through its static client configuration, and its encryption is not
  // what these plans test, so a product run accepts plaintext as the
  // relationship's own switch allows (`mode.js`); the memory mode, where
  // the plans run, is development and never asks.
  if (await registry.isProduct(root)) {
    fields.fedAllowUnencrypted = "TRUE";
  }
  const keys = Object.keys(fields);
  for (let i = 0; i < keys.length; i++) {
    await setField(made.api, id, keys[i], fields[keys[i]]);
  }
  await oidf.ok(made.api + "/federation/enable", { id: id },
                "enabled " + id);
  const view = await relationshipView(made.api, id);
  const endpoints = view.endpoints || {};
  assert.ok(endpoints.assertionConsumerService, "the relationship " + id +
            " reports no assertion consumer service");
  const client = { client_id: clientId, client_secret: secret,
                   redirect_uri: endpoints.assertionConsumerService };
  if (plan.logout) {
    client.post_logout_redirect_uri = endpoints.postLogoutRedirect;
    client.backchannel_logout_uri = endpoints.backchannelLogout;
    client.frontchannel_logout_uri = endpoints.frontchannelLogout;
  }
  if (plan.initiate) {
    client.initiate_login_uri = endpoints.initiateLogin;
  }
  log.debug("Leaving prepare().");
  return {
    realm: made, id: id, issuer: issuer,
    login: made.base + "/federation/login/" + encodeURIComponent(id),
    configuration: {
      alias: alias,
      description: "iya-sts " + plan.name + " " + STAMP,
      client: client,
      // How long a negative module waits for this relying party to call
      // something it should not before it passes: the suite's default.
      waitTimeoutSeconds: 5
    }
  };
}

// ---------------------------------------------------------------------------
// THE PERSON, and what they do for each module (step 2 of the header).
// ---------------------------------------------------------------------------
function operatorFor(plan, prepared, person) {
  log.debug("Entering operatorFor(). " + plan.key);
  const started = {};
  log.debug("Leaving operatorFor().");
  return async function (id, info) {
    log.debug("Entering the relying party's person. " + id);
    if (!info || info.status !== "WAITING") {
      log.debug("Leaving the relying party's person. Not waiting.");
      return;
    }
    const name = String(info.testName || "");
    // The third-party-initiated module lists the address it sends the
    // person to; so may the OP-initiated front-channel logout module, once
    // the person is signed in. Whatever a module lists is visited.
    if (!started[id] && !/3rd-party-init-login/.test(name)) {
      started[id] = true;
      await person.start(id, info, prepared.login);
      if (signsOut(name)) {
        await person.signOut(id, info, prepared.realm.base);
      }
    }
    await person.visit(id, info);
    log.debug("Leaving the relying party's person.");
  };
}

// ONE PLAN, prepared, run module by module and judged; answers the lines
// that are not explained.
async function runOnePlan(plan) {
  log.debug("Entering runOnePlan(). " + plan.key);
  const lines = [];
  log.info("=== " + plan.name + " " + JSON.stringify(plan.variant) +
           " (" + plan.key + ") ===");
  const results = [];
  let planId = "";
  try {
    const prepared = await prepare(plan);
    const created = await oidf.suite("POST", "api/plan?planName=" +
      encodeURIComponent(plan.name) + "&variant=" +
      encodeURIComponent(JSON.stringify(plan.variant)),
      prepared.configuration);
    assert.ok(created.status === 201 || created.status === 200,
              "creating " + plan.name + ": " +
              String(created.raw).slice(0, 400));
    planId = created.body.id;
    const person = conformanceBrowser.person({
      suite: oidf.suite, suiteBase: oidf.SUITE,
      serviceBase: prepared.realm.base, username: "", password: "",
      markFirst: true, actions: {} });
    const operator = operatorFor(plan, prepared, person);
    const modules = created.body.modules || [];
    for (let i = 0; i < modules.length; i++) {
      const module = modules[i];
      // THE MODULE'S RESPONSE TYPE, set on the relationship before it runs:
      // what an administrator configuring this partner for that flow does.
      await setField(prepared.realm.api, prepared.id, "fedResponseType",
                     responseTypeOf(plan, module));
      const argued = expectedFor(plan, module.testModule);
      let got = await oidf.runModule(planId, module, argued ? null : operator,
                                     argued ? ARGUED_SECONDS : undefined);
      // ONE MORE RUN FOR A MODULE THAT TIMED OUT, as runPlan() gives one —
      // unless it is argued to wait out its time.
      if (got.status === "TIMED OUT" && !argued) {
        log.info("  " + plan.key + " " + got.module + ": TIMED OUT; " +
                 "running it once more.");
        got = await oidf.runModule(planId, module, operator);
      }
      log.info("  " + plan.key + " " + got.module + ": " +
               (got.result || got.status) +
               (got.failures.length ? " — " + got.failures[0].src + ": " +
                                      got.failures[0].msg : "") +
               (argued ? " (argued: " + argued + ")" : ""));
      results.push(got);
    }
  } catch (e) {
    // One plan that cannot be set up or created is reported with the rest
    // rather than ending the run.
    log.error("Caught in runOnePlan(): " + plan.key + ": " +
              ((e && e.message) || e));
    lines.push(plan.key + " could not run: " + ((e && e.message) || e));
    log.debug("Leaving runOnePlan(). It could not run.");
    return lines;
  }
  // A module argued in EXPECTED is argued whatever it ended as, a plan
  // argued whole for every module; both are handed to judge() by module.
  const expected = Object.assign({}, EXPECTED);
  if (EXPECTED_PLANS[plan.key]) {
    results.forEach(function (r) {
      expected[plan.key + "/" + r.module] = EXPECTED_PLANS[plan.key];
    });
  }
  const judged = oidf.judge(plan.key, { planId: planId, results: results },
                            expected, KNOWN_WARNINGS, KNOWN_FAILURES);
  log.info("  " + plan.key + ": " + JSON.stringify(judged.counts) +
           ", plan " + oidf.SUITE + "plan-detail.html?plan=" + planId);
  judged.unexplained.forEach(function (line) {
    lines.push(line);
  });
  log.debug("Leaving runOnePlan(). " + lines.length + " unexplained.");
  return lines;
}

async function test() {
  log.debug("Entering test().");
  await oidf.waitForSuite();
  const unexpected = [];
  // THE PLANS RUN SEVERAL AT A TIME, as sts_oidcc_conformance.js's do: each
  // is a realm and an alias of its own, and the one Chrome serialises the
  // person's visits. CONFORMANCE_PLAN_CONCURRENCY=1 runs them one by one.
  const wanted = PLANS.filter(function (plan) {
    return oidf.selected(plan.key);
  });
  const width = Math.max(1, Math.min(8,
    Number(process.env.CONFORMANCE_PLAN_CONCURRENCY) || 3));
  const outcomes = new Array(wanted.length);
  let next = 0;
  const worker = async function () {
    log.debug("Entering worker().");
    while (next < wanted.length) {
      const index = next++;
      outcomes[index] = await runOnePlan(wanted[index]);
    }
    log.debug("Leaving worker().");
  };
  const workers = [];
  for (let w = 0; w < width; w++) {
    workers.push(worker());
  }
  await Promise.all(workers);
  await conformanceBrowser.quit();
  outcomes.forEach(function (lines) {
    lines.forEach(function (line) {
      unexpected.push(line);
    });
  });
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
  .description("The OpenID Foundation conformance suite's OpenID Connect " +
    "relying-party plans (#930), against an inbound OpenID Connect " +
    "federation relationship of this service.")
  .addOption(new Option("-u, --url <url>", "base url (unused: the " +
                                           "service's is the realm's)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
