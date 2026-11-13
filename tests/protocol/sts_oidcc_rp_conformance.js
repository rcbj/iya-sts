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
//   4. ONE CLASSICAL TWIN, THE DYNAMIC PLAN'S (rcbj, #930): the plan in
//      which this relying party registers itself and signs its Request
//      Objects runs again as `dynamic-cl`, keys.postQuantumSigning off
//      (`conformance_suite.js`, THE CLASSICAL TWINS). PQ_ONLY is empty: the
//      registration hands the suite one classical key, so neither run
//      should need a post-quantum exemption. The other plans sign and
//      publish nothing the suite reads, so their run already is the
//      classical proof (the FAPI job's position).
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
const DYNAMIC_PLAN = { key: "dynamic",
  name: "oidcc-client-dynamic-certification-test-plan",
  variant: { response_mode: "default",
             client_auth_type: "client_secret_basic" },
  responseMode: "fragment", discovery: true, register: true,
  webfinger: true, requestUri: true };
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
  // THE DYNAMIC PLAN TWICE (rcbj, #930): as it is, and as its classical
  // twin `dynamic-cl`, keys.postQuantumSigning off — the plan in which this
  // relying party signs (its Request Objects) and registers a key.
].concat(oidf.withClassicalTwins([DYNAMIC_PLAN])).concat([
  { key: "formpost-basic",
    name: "oidcc-client-formpost-basic-certification-test-plan",
    variant: STATIC, responseMode: "form_post" },
  { key: "formpost-implicit",
    name: "oidcc-client-formpost-implicit-certification-test-plan",
    variant: STATIC, responseMode: "form_post" },
  { key: "formpost-hybrid",
    name: "oidcc-client-formpost-hybrid-certification-test-plan",
    variant: STATIC, responseMode: "form_post" },
  // DYNAMICALLY REGISTERED: with a static client the suite's module starts
  // its background step while it is still CREATED and fails itself
  // ("Illegal test state change: CREATED -> RUNNING", the first full run);
  // with a registration it starts it during the registration.
  { key: "3rdparty", name: "oidcc-client-test-3rd-party-init-login-test-plan",
    variant: Object.assign({}, WHOLE,
                           { client_registration: "dynamic_client" }),
    responseMode: "fragment", initiate: true, discovery: true,
    register: true },
  { key: "logout", name: "oidcc-client-logout-test-plan",
    variant: WHOLE, responseMode: "fragment", logout: true },
  { key: "refresh", name: "oidcc-client-refreshtoken-test-plan",
    variant: WHOLE, responseMode: "fragment", refresh: true }
]);

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
const EXPECTED = {
  "logout/oidcc-client-test-session-management": SESSION_MANAGEMENT
};
// A plan argued whole: none since rcbj's decision built the dynamic plan.
const EXPECTED_PLANS = {};
// The ledger entries about post-quantum keys, which a classical twin is
// judged without: none, since the registration hands the partner only the
// one classical key that signs Request Objects (`jwks` by value).
const PQ_ONLY = [];
// The modules that finish when the relying party registers, which the
// person does not sign in for: a sign-in would reach a FINISHED module.
const REGISTER_ONLY = ["oidcc-client-test-dynamic-registration"];
// The modules whose person types an identifier for WebFinger, and how.
const WEBFINGER = {
  "oidcc-client-test-discovery-webfinger-acct": "acct",
  "oidcc-client-test-discovery-webfinger-url": "url"
};

// The modules that finish when the partner's configuration is read, which
// the person does not sign in for (see operatorFor()).
const CHECK_ONLY = ["oidcc-client-test-discovery-openid-config",
                    "oidcc-client-test-discovery-jwks-uri-keys"];
// The module that wants two sign-ins, the second after a key rotation.
const TWO_SIGN_INS = ["oidcc-client-test-signing-key-rotation"];

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
    // suite's own certificate (#171). A classical twin's own setting
    // (withClassicalTwins()) comes after it.
    [["federation.outboundCaFile", oidf.suiteCaFile()]]
      .concat(plan.settings || []));
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
    fedResponseMode: plan.responseMode || "",
    // What the static client registers as id_token_signed_response_alg
    // below, so a Logout Token or an ID Token under any other algorithm is
    // refused (the back-channel logout's wrong-alg module).
    fedIdTokenSignedResponseAlg: "RS256"
  };
  if (plan.discovery) {
    fields.fedDiscovery = "TRUE";
    // SELF-REGISTRATION (#930): no client written here; the relationship
    // registers itself at the suite's registration endpoint.
    if (plan.register) {
      fields.fedRegister = "TRUE";
      delete fields.fedClientId;
      delete fields.fedClientSecret;
    }
    if (plan.webfinger) {
      fields.fedWebFinger = "TRUE";
    }
    if (plan.requestUri) {
      fields.fedRequestObject = "request_uri";
      fields.fedRequestObjectSigningAlg = "RS256";
    }
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
  // THE REFRESH-TOKEN PLAN (#930): the partner's refresh token kept for the
  // session and used every five seconds, so the federation.partner-refresh
  // job (every fifteen) refreshes well inside a module's five minutes.
  if (plan.refresh) {
    fields.fedRefreshTokens = "TRUE";
    fields.fedRefreshEverySeconds = "5";
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
  // A REGISTERED CLIENT is named only by its name: the suite takes the
  // rest from the registration.
  const client = plan.register
    ? { client_name: "iya-sts " + plan.key }
    : { client_id: clientId, client_secret: secret,
        redirect_uri: endpoints.assertionConsumerService,
        id_token_signed_response_alg: "RS256" };
  if (plan.logout) {
    client.post_logout_redirect_uri = endpoints.postLogoutRedirect;
    client.backchannel_logout_uri = endpoints.backchannelLogout;
    client.frontchannel_logout_uri = endpoints.frontchannelLogout;
  }
  if (plan.initiate && !plan.register) {
    client.initiate_login_uri = endpoints.initiateLogin;
  }
  log.debug("Leaving prepare().");
  return {
    realm: made, id: id, issuer: issuer, alias: alias,
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
  const nudged = {};
  log.debug("Leaving operatorFor().");
  return async function (id, info) {
    log.debug("Entering the relying party's person. " + id);
    if (!info || info.status !== "WAITING") {
      log.debug("Leaving the relying party's person. Not waiting.");
      return;
    }
    const name = String(info.testName || "");
    // THE MODULES THAT END THE MOMENT THE DISCOVERY DOCUMENT (AND THE KEY
    // SET) IS READ: a sign-in would go on to the authorization endpoint of
    // a module already FINISHED, which the suite records as "Illegal test
    // state change: FINISHED -> RUNNING" (the first full run, 2026-11-03).
    // The administrator's check reads exactly those two and nothing else.
    if (REGISTER_ONLY.indexOf(name) >= 0 ||
        (plan.register && /3rd-party-init-login/.test(name))) {
      // THE REGISTRATION MODULE ends when the relying party registers; the
      // third-party-initiated one sends the person on from the
      // registration, and they are visited below.
      if (!started[id]) {
        started[id] = 1;
        await oidf.ok(prepared.realm.api + "/federation/register-partner",
                      { id: prepared.id }, "registered at the partner");
      }
      await person.visit(id, info);
      log.debug("Leaving the relying party's person. Registered.");
      return;
    }
    if (WEBFINGER[name]) {
      // THE PERSON TYPES AN IDENTIFIER (#930), in the suite's two shapes
      // (its TestDispatcher reads the alias and the module from it); the
      // module ends when the discovery document is read, so the page that
      // names the issuer is where the person stops.
      if (!started[id]) {
        started[id] = 1;
        const host = new URL(oidf.SUITE).host;
        const resource = WEBFINGER[name] === "acct"
          ? "acct:" + prepared.alias + "." + name + "@" + host
          : oidf.SUITE + prepared.alias + "/" + name;
        await person.start(id, info, prepared.realm.base +
          "/federation/webfinger/" + encodeURIComponent(prepared.id) +
          "?resource=" + encodeURIComponent(resource));
      }
      log.debug("Leaving the relying party's person. Looked up.");
      return;
    }
    if (CHECK_ONLY.indexOf(name) >= 0) {
      if (!started[id]) {
        started[id] = 1;
        await oidf.ok(prepared.realm.api + "/federation/check-partner",
                      { id: prepared.id }, "checked the partner");
      }
      log.debug("Leaving the relying party's person. Checked.");
      return;
    }
    // The third-party-initiated module lists the address it sends the
    // person to; so may the OP-initiated front-channel logout module, once
    // the person is signed in. Whatever a module lists is visited.
    if (!started[id] && !/3rd-party-init-login/.test(name)) {
      started[id] = 1;
      await person.start(id, info, prepared.login);
      if (signsOut(name)) {
        await person.signOut(id, info, prepared.realm.base);
      }
    } else if (started[id] === 1 && TWO_SIGN_INS.indexOf(name) >= 0) {
      // The key rotation module asks for a SECOND sign-in once the first
      // is done, and rotates its keys before signing that one's ID Token.
      started[id] = 2;
      await person.start(id, info, prepared.login);
    }
    if (plan.refresh && started[id]) {
      await nudgeRefresh(prepared, id, nudged);
    }
    await person.visit(id, info);
    log.debug("Leaving the relying party's person.");
  };
}

// THE REFRESH PLAN'S JOB, ASKED FOR RATHER THAN WAITED ON (run 22,
// 2026-11-13). federation.partner-refresh runs every fifteen seconds, but
// at the end of a full run its scheduled run queues behind every realm's
// other jobs: the refresh module's refresh came 3.5 minutes after its
// sign-in, and the invalid-issuer module's never came in its five minutes,
// so it timed out. A Run now is first in the scheduler's line, so while a
// signed-in refresh module waits the operator queues one, at most every
// NUDGE_MS. The job still refreshes only a token that is due
// (fedRefreshEverySeconds), so what the module is sent is unchanged.
const NUDGE_MS = 10000;
async function nudgeRefresh(prepared, id, nudged) {
  log.debug("Entering nudgeRefresh(). " + id);
  const now = Date.now();
  if (nudged[id] && now - nudged[id] < NUDGE_MS) {
    log.debug("Leaving nudgeRefresh(). Asked lately.");
    return;
  }
  nudged[id] = now;
  const r = await oidf.send(prepared.realm.api + "/scheduler/run", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ job: "federation.partner-refresh",
                           realm: prepared.realm.id }) });
  if (!((r.status === 200 || r.status === 202) && r.body &&
        r.body.ok !== false)) {
    // Not fatal: the scheduled run still comes, only later.
    log.warn("Queueing federation.partner-refresh in " + prepared.realm.id +
             " answered " + r.status + " " + String(r.raw).slice(0, 200));
  }
  log.debug("Leaving nudgeRefresh().");
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
      // A REGISTERING RELATIONSHIP FORGETS ITS CLIENT before each module,
      // as an administrator clearing it would: the suite keeps a client
      // for one module only, so each registers again.
      if (plan.register) {
        await setField(prepared.realm.api, prepared.id, "fedClientId", "");
        await setField(prepared.realm.api, prepared.id,
                       "fedRegisteredIssuer", "");
      }
      // The unsigned Request Object module registers, and is sent, `none`.
      if (plan.requestUri) {
        await setField(prepared.realm.api, prepared.id,
                       "fedRequestObjectSigningAlg",
                       /request-uri-signed-none/.test(module.testModule)
                         ? "none" : "RS256");
      }
      const argued = expectedFor(plan, module.testModule);
      let got = await oidf.runModule(planId, module, argued ? null : operator,
                                     argued ? ARGUED_SECONDS : undefined);
      // ONE MORE RUN FOR A MODULE THAT TIMED OUT, as runPlan() gives one —
      // unless it is argued to wait out its time.
      if (got.status === "TIMED OUT" && !argued) {
        log.info("  " + plan.key + " " + got.module + ": TIMED OUT; " +
                 "running it once more.");
        // AND THE STOPPED RUN'S SESSION ENDS FIRST (run 22, 2026-11-13), for
        // the reason given below: the invalid-issuer module timed out signed
        // in, its rerun signed in again on the same alias, and the next
        // partner-refresh run presented BOTH sessions' tokens — the stopped
        // instance's first, which the rerun's ValidateRefreshToken refused
        // ("Invalid refresh_token parameter"), then the rerun's own, to a
        // module already INTERRUPTED ("Illegal test state change:
        // INTERRUPTED -> RUNNING"). Two sessions holding a token each is
        // right for this relying party; a module that knows only one token
        // is why the first session has to go.
        if (plan.refresh && got.id) {
          await person.signOut(got.id, { testName: got.module },
                               prepared.realm.base, { localOnly: true });
        }
        got = await oidf.runModule(planId, module, operator);
      }
      log.info("  " + plan.key + " " + got.module + ": " +
               (got.result || got.status) +
               (got.failures.length ? " — " + got.failures[0].src + ": " +
                                      got.failures[0].msg : "") +
               (argued ? " (argued: " + argued + ")" : ""));
      results.push(got);
      // THE REFRESH PLAN'S SESSIONS END WITH THEIR MODULE (2026-11-03).
      // Each module signs in with a jar of its own, so the one before it
      // stayed signed in, and the federation.partner-refresh job went on
      // presenting that module's refresh token to the suite while the next
      // module ran: its ValidateRefreshToken failed it ("Invalid
      // refresh_token parameter"). Signed out here, its held token is
      // dropped before it is dialled again (`refreshOne()`).
      if (plan.refresh && got.id) {
        await person.signOut(got.id, { testName: got.module },
                             prepared.realm.base, { localOnly: true });
      }
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
                            oidf.ledgerFor(plan, expected, PQ_ONLY),
                            oidf.ledgerFor(plan, KNOWN_WARNINGS, PQ_ONLY),
                            oidf.ledgerFor(plan, KNOWN_FAILURES, PQ_ONLY));
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
