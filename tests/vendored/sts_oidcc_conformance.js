"use strict";
//
// File: sts_oidcc_conformance.js
//
// ---------------------------------------------------------------------------
// THE OPENID FOUNDATION'S CONFORMANCE SUITE: OPENID CONNECT (#187,
// 2026-09-24). The OpenID Provider certification plans, `oidcc-test-plan`
// across its client-authentication methods and response modes, and the four
// logout plans (RP-Initiated, Front-Channel, Back-Channel, Session
// Management) — the plans #176's `sts_fapi_conformance.js` did not run, on
// the same three containers (`tests/CLAUDE.md`, *The OpenID conformance
// suite*) — and Identity Assurance's `ekyc-test-plan-oidccore`, which is an
// OpenID Provider plan of the same shape.
//
//   1. For each plan below, a throwaway trust realm (left behind) with open
//      registration and whatever the plan tests switched on, and a person the
//      suite signs in as. Most plans register their OWN clients through
//      `/oauth2/register` (`client_registration: dynamic_client`), which is
//      how the suite's own CI runs these plans against a provider and is the
//      one way to give the suite the redirect, logout and front- and
//      back-channel URIs it builds per module. The static variants register
//      two clients here and hand the suite their credentials; the mutual TLS
//      one gets certificates from the realm's CA.
//   2. The plan is created with the discovery URL, the clients and the
//      `browser` commands, and every module runs, one at a time. One browser
//      list serves every module because every task in it is optional: sign
//      in, consent, an error page photographed into the module's
//      placeholder, the callback; and on the end-session endpoint the page
//      photographed, the confirmation pressed, and the return followed.
//   3. A FAILED module fails the job unless EXPECTED names it with its
//      reason; a WARNING from a condition KNOWN_WARNINGS does not name fails
//      it too (#187: every warning is fixed or recorded with its reason, and
//      `oauth-oidc/CLAUDE.md` 3bg carries the same sentences).
//
// OWNED HERE (local: true): this repository's OpenID Provider.
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
var log = bunyan.createLogger({ name: "sts_oidcc_conformance",
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

const DYNAMIC = { server_metadata: "discovery",
                  client_registration: "dynamic_client" };

// ---------------------------------------------------------------------------
// THE PLANS. `key` is what CONFORMANCE_PLANS names (a trailing `*` is a
// prefix). `settings` are realm settings the plan needs; `static` registers
// the clients here with that authentication method.
// ---------------------------------------------------------------------------
const PLANS = [
  // --- OpenID Provider certification profiles ---------------------------
  { key: "basic", name: "oidcc-basic-certification-test-plan",
    variant: DYNAMIC },
  { key: "basic-static", name: "oidcc-basic-certification-test-plan",
    variant: { server_metadata: "discovery",
               client_registration: "static_client" },
    static: "client_secret_basic", responseTypes: ["code"] },
  { key: "implicit", name: "oidcc-implicit-certification-test-plan",
    variant: DYNAMIC },
  { key: "hybrid", name: "oidcc-hybrid-certification-test-plan",
    variant: DYNAMIC },
  { key: "config", name: "oidcc-config-certification-test-plan",
    variant: null },
  { key: "dynamic", name: "oidcc-dynamic-certification-test-plan",
    variant: { response_type: "code id_token" } },
  { key: "formpost-basic", name: "oidcc-formpost-basic-certification-test-plan",
    variant: DYNAMIC },
  { key: "formpost-implicit",
    name: "oidcc-formpost-implicit-certification-test-plan",
    variant: DYNAMIC },
  { key: "formpost-hybrid",
    name: "oidcc-formpost-hybrid-certification-test-plan",
    variant: DYNAMIC },
  { key: "3rdparty", name: "oidcc-3rdparty-init-login-certification-test-plan",
    variant: { response_type: "code" } },
  // --- oidcc-test-plan: every client authentication, every response mode.
  // Query (`code`), fragment (the hybrid and implicit types) and form_post
  // are each exercised, and each method in its own plan.
  { key: "t-basic", name: "oidcc-test-plan",
    variant: { client_auth_type: "client_secret_basic", response_type: "code",
               response_mode: "default",
               client_registration: "dynamic_client" } },
  { key: "t-post", name: "oidcc-test-plan",
    variant: { client_auth_type: "client_secret_post",
               response_type: "code id_token", response_mode: "default",
               client_registration: "dynamic_client" } },
  { key: "t-jwt", name: "oidcc-test-plan",
    variant: { client_auth_type: "client_secret_jwt",
               response_type: "code token", response_mode: "form_post",
               client_registration: "dynamic_client" } },
  { key: "t-pkjwt", name: "oidcc-test-plan",
    variant: { client_auth_type: "private_key_jwt", response_type: "code",
               response_mode: "form_post",
               client_registration: "dynamic_client" } },
  { key: "t-mtls", name: "oidcc-test-plan",
    variant: { client_auth_type: "mtls",
               response_type: "code id_token token", response_mode: "default",
               client_registration: "static_client" },
    static: "tls_client_auth",
    responseTypes: ["code id_token token"] },
  // --- Logout --------------------------------------------------------------
  { key: "logout-rp", name: "oidcc-rp-initiated-logout-certification-test-plan",
    variant: { response_type: "code",
               client_registration: "dynamic_client" } },
  { key: "logout-front",
    name: "oidcc-frontchannel-rp-initiated-logout-certification-test-plan",
    variant: { response_type: "code",
               client_registration: "dynamic_client" },
    frontchannel: true },
  { key: "logout-back",
    name: "oidcc-backchannel-rp-initiated-logout-certification-test-plan",
    variant: { response_type: "code",
               client_registration: "dynamic_client" },
    backchannel: true },
  { key: "session", name: "oidcc-session-management-certification-test-plan",
    variant: { response_type: "code",
               client_registration: "dynamic_client" },
    settings: [["oauth2.sessionManagement", true]] },
  // --- OpenID Connect for Identity Assurance 1.0 (#127) ----------------------
  // The plan the suite's own CI runs against a provider: a dynamic
  // private_key_jwt client, the code flow, verified claims asked for in the
  // ID Token and at UserInfo.
  { key: "ekyc", name: "ekyc-test-plan-oidccore",
    variant: { client_auth_type: "private_key_jwt",
               server_metadata: "discovery", response_type: "code",
               client_registration: "dynamic_client",
               response_mode: "default", security_profile: "none",
               auth_request_method: "http_query",
               auth_request_non_repudiation_method: "unsigned",
               sender_constrain: "none", fapi_response_mode: "plain_response",
               ekyc_profile: "plain_ekyc",
               ekyc_verified_claims_response_support: "id_token_userinfo" },
    // The plan registers `token_endpoint_auth_signing_alg` RS256 whatever
    // key it is given, and this OP holds a client to the algorithm it
    // registered (OIDC Core section 9), so its clients' keys are RSA.
    keyAlg: "RS256",
    settings: [["oauth2.idaTrustFrameworks", "eidas"]],
    // A verification RECORDED on the person, as an administrator would
    // (#127), rather than development's invented `urn:sts:demo` one — so
    // the plan reads what product would release. `name` because the plan
    // asks for the first of claims_in_verified_claims_supported.
    verification: {
      verification: { trust_framework: "eidas", assurance_level: "high",
        evidence: [{ type: "document",
          check_details: [{ check_method: "vpip" }],
          document_details: { type: "passport",
                              document_number: "C01X00T47" } }] },
      claims: ["name", "given_name", "family_name", "email"] },
    // ekyc-server-testuserprovidedrequest sends each request the operator
    // lists: here, the recorded claims, in the ID Token and at UserInfo.
    ekyc: { verified_claims_request_list: [
      { id_token: { verified_claims: {
          verification: { trust_framework: null },
          claims: { given_name: null, family_name: null } } },
        userinfo: { verified_claims: {
          verification: { trust_framework: { value: "eidas" } },
          claims: { given_name: null, family_name: null, email: null } } }
      }] } }
];

// ---------------------------------------------------------------------------
// KNOWN AND ARGUED DIFFERENCES. `<plan key>/<module>` (or `*/<module>`) ->
// why a FAILED module is not a defect here.
// ---------------------------------------------------------------------------
const EXPECTED = {
  // The suite's browser cannot load the OP iframe at all. HtmlUnit 4.17's
  // WebClient passes Policy.allowsFrameAncestor() the FRAMED document's own
  // origin where the framing page's belongs, so `frame-ancestors` is met
  // only by listing the OP's own origin — which this OP reaches here as
  // `https://sts:8081` and could list only by taking an origin from the
  // request. Shown 2026-09-26 by driving HtmlUnit itself: the same page
  // framed from the suite's origin is refused, and with the OP's origin
  // added it loads, runs check_session.js and answers. The module never
  // gets its `session_result`; the iframe's answers are checked in
  // tests/session_management.js and tests/vendored/sts_session_management.js.
  "session/oidcc-session-management-rp-initiated-logout": "HtmlUnit " +
    "checks frame-ancestors against the framed document's own origin, so " +
    "the suite's browser never loads the OP iframe (3bp)"
};

// FAILURE conditions this service keeps, keyed by the suite's condition (a
// module still fails if anything ELSE in it fails) — the same sentences as
// `oauth-oidc/CLAUDE.md` 3bp.
const KNOWN_FAILURES = {
  // The suite's own contradiction: this module requires verified_claims to
  // be ABSENT from the ID Token (EnsureIdTokenDoesNotContainVerifiedClaims,
  // which passes) and then validates the verified_claims of the UserInfo
  // response against the schema, which fails when the same section 5.7.4
  // omission leaves UserInfo without one. The claim IS omitted from both.
  ["ekyc/ekyc-server-one-claim-with-random-value-omitted/" +
   "ValidateVerifiedClaimsResponseAgainstSchema"]: "the suite validates " +
    "a UserInfo verified_claims its own module needs omitted (5.7.4)",
  // oidcc-server-rotate-keys: the condition hands every key in the rotated
  // JWKS to nimbus's JWK.parse(), which throws on kty AKP (the post-quantum
  // ML-DSA and SLH-DSA keys), so the module fails on a key it cannot read
  // before comparing the ones it can. Seen 2026-09-26 in every plan that
  // runs the module; the rotation itself succeeds.
  VerifyNewJwksHasNewSigningKey: "nimbus cannot parse the realm's " +
    "post-quantum keys (kty AKP); rcbj (2026-09-24): PQC support matters " +
    "more than a clean run (3bg)"
};

// Conditions whose WARNING this service keeps, and why — the same sentences
// as `oauth-oidc/CLAUDE.md` 3bp.
const KNOWN_WARNINGS = {
  WarnOnUnusableJwksKeys: "the realm's JWKS carries post-quantum keys " +
    "(kty AKP, ML-DSA and SLH-DSA) the suite cannot parse; rcbj " +
    "(2026-09-24): PQC support matters more than a clean run (3bg)",
  // The `profile` scope's claims no directory attribute answers —
  // middle_name, profile, picture, gender, zoneinfo — are absent from
  // UserInfo, which Core 5.4 allows ("claims ... when available"). 3bg's
  // open item: map them or stop listing them in claims_supported.
  VerifyScopesReturnedInUserInfoClaims: "five profile-scope claims have " +
    "no directory attribute; rcbj's call (3bg) whether to map them",
  // The same five, in an ID Token the implicit flow returns without an
  // access token (Core 5.4 puts the scope claims there then).
  VerifyScopesReturnedInAuthorizationEndpointIdToken: "the same five " +
    "profile-scope claims, absent from an implicit-flow ID Token",
  // OpenID Connect Enterprise Extensions 1.0 (#148): `session_expiry` and
  // `tenant` MAY be in an ID Token, and rcbj's answer on #148 puts them in
  // every one. Only those two are argued: any other unrequested claim is a
  // finding.
  EnsureIdTokenDoesNotContainNonRequestedClaims: { why: "session_expiry " +
    "and tenant, in every ID Token by rcbj's answer on #148",
    msg: /non-requested claim '(session_expiry|tenant)'|contains non-requested claims\. This may indicate/ }
};

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

// ---------------------------------------------------------------------------
// THE SCRIPTED BROWSER (see the header).
// ---------------------------------------------------------------------------
function browserFor(base, person, frontchannel) {
  log.debug("Entering browserFor().");
  const logoutTasks = [
    // The confirmation page, or a refusal — photographed either way, then
    // the confirmation pressed where there is one.
    { task: "End-session page", optional: true,
      match: base + "/oauth2/logout*",
      commands: [
        ["wait", "xpath", "//body", 10, ".*",
         "update-image-placeholder-optional"],
        ["click", "xpath", "//button[@value='yes']", "optional"]] }
  ];
  // Front-channel only: the notification page returns by a refresh, so the
  // browser waits for it. Nowhere else — the suite's `wait` has no optional
  // form, and the RP-Initiated modules whose right answer is NOT to return
  // (no id_token_hint, a bad or absent post_logout_redirect_uri, no
  // parameters) would time out on it with the page they wanted on screen.
  if (frontchannel) {
    logoutTasks.push({ task: "Return to the client", optional: true,
                       match: base + "/oauth2/logout*",
                       commands: [["wait", "contains",
                                   "/post_logout_redirect", 20]] });
  }
  logoutTasks.push({ task: "Verify complete", optional: true,
                     match: oidf.SUITE + "test/*/post_logout_redirect*" });
  log.debug("Leaving browserFor().");
  return [{
    match: base + "/oauth2/authorize*",
    tasks: [
      // No photograph here: a module whose placeholder is an ERROR page
      // (an invalid redirect_uri the server may equally honour) would have
      // it filled by the sign-in page and finish before its callback came.
      // The modules that want the sign-in page photographed say so in
      // overridesFor().
      { task: "Sign in", optional: true, match: base + "/authn/login*",
        commands: signInCommands(person) },
      { task: "Consent", optional: true, match: base + "/oauth2/consent*",
        commands: [["click", "id", "consent-allow"]] },
      // A refused authorization request shows this service's error page
      // (an unregistered redirect_uri must not be redirected to): photographed
      // into the placeholder, a REVIEW outcome.
      { task: "Error page", optional: true,
        match: base + "/oauth2/authorize*",
        commands: [["wait", "xpath", "//body", 10, ".*",
                    "update-image-placeholder-optional"]] },
      { task: "Verify complete", optional: true,
        match: oidf.SUITE + "test/*/callback*",
        commands: [["wait", "id", "submission_complete", 10]] }
    ]
  }, {
    match: base + "/oauth2/logout*",
    tasks: logoutTasks
  }, {
    // Session Management (#121): the suite sends the browser to a page of
    // its own that frames this realm's OP iframe beside an RP iframe, whose
    // script asks the OP iframe and then moves the page to the suite's
    // result URL. Without an entry here the suite has no browser for that
    // URL and the module waits out its bound; the wait is what gives the
    // page's script time to run.
    match: oidf.SUITE + "test/*/*session_verify*",
    tasks: [
      { task: "Session check", match: oidf.SUITE + "test/*/*session_verify*",
        commands: [["wait", "contains", "session_result", 20]] }
    ]
  }];
}

function signInCommands(person) {
  log.debug("Entering signInCommands().");
  log.debug("Leaving signInCommands().");
  return [["text", "id", "username", person, "optional"],
          ["text", "id", "password", PASSWORD, "optional"],
          ["click", "id", "kc-login"]];
}

// The modules that ask for the sign-in page itself as their evidence: a
// second sign-in forced by prompt=login or max_age, and the three
// registration modules that expect the client's logo, policy or terms to be
// shown there. The suite merges `override[<module>]` over the configuration.
function overridesFor(base, person) {
  log.debug("Entering overridesFor().");
  const photographed = {
    match: base + "/oauth2/authorize*",
    tasks: [
      { task: "Sign in, photographed", optional: true,
        match: base + "/authn/login*",
        commands: [["wait", "id", "username", 10, ".*",
                    "update-image-placeholder-optional"]]
          .concat(signInCommands(person)) },
      { task: "Consent", optional: true, match: base + "/oauth2/consent*",
        commands: [["click", "id", "consent-allow"]] },
      { task: "Verify complete", optional: true,
        match: oidf.SUITE + "test/*/callback*",
        commands: [["wait", "id", "submission_complete", 10]] }
    ]
  };
  const onlyPhotographed = {
    match: base + "/oauth2/authorize*",
    tasks: [
      { task: "The sign-in page, photographed",
        match: base + "/authn/login*",
        commands: [["wait", "id", "username", 10, ".*",
                    "update-image-placeholder"]] }
    ]
  };
  const out = {};
  ["oidcc-prompt-login", "oidcc-max-age-1"].forEach(function (name) {
    out[name] = { browser: [photographed] };
  });
  ["oidcc-registration-logo-uri", "oidcc-registration-policy-uri",
   "oidcc-registration-tos-uri"].forEach(function (name) {
    out[name] = { browser: [onlyPhotographed] };
  });
  log.debug("Leaving overridesFor().");
  return out;
}

// Two clients registered here, for the static variants.
async function staticClients(plan, base, api, alias) {
  log.debug("Entering staticClients(). " + plan.key);
  const redirect = oidf.SUITE + "test/a/" + alias + "/callback";
  const clients = [];
  // The certification plans run one module with client_secret_post, from a
  // third client the configuration names `client_secret_post`.
  const methods = [plan.static, plan.static].concat(
    plan.static === "client_secret_basic" ? ["client_secret_post"] : []);
  for (let n = 1; n <= methods.length; n++) {
    const metadata = {
      redirect_uris: [redirect],
      token_endpoint_auth_method: methods[n - 1],
      // RFC 7591 section 2.1: implicit only beside a response type that
      // uses it.
      grant_types: ["authorization_code", "refresh_token"].concat(
        plan.responseTypes.some(function (t) {
          return /token/.test(t);
        }) ? ["implicit"] : []),
      response_types: plan.responseTypes,
      scope: "openid profile email address phone offline_access",
      client_name: "conformance " + plan.key + " " + n
    };
    const registered = await oidf.send(base + "/oauth2/register", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(metadata) });
    assert.strictEqual(registered.status, 201, plan.key + " client " + n +
                       ": " + registered.raw.slice(0, 400));
    const client = { client_id: registered.body.client_id };
    if (registered.body.client_secret) {
      client.client_secret = registered.body.client_secret;
    }
    if (plan.static === "tls_client_auth") {
      client.mtls = await oidf.clientCertificate(api,
                                                 registered.body.client_id);
    }
    clients.push(client);
  }
  log.debug("Leaving staticClients().");
  return clients;
}

async function prepare(plan) {
  log.debug("Entering prepare(). " + plan.key);
  const realm = ("oidcc-" + plan.key + "-" + TAG).slice(0, 31)
    .replace(/-+$/, "");
  const base = root + "/realm/" + realm;
  const api = base + "/admin-api";
  const alias = "iya-" + plan.key + "-" + TAG;
  const person = names.usernameFor("conf-" + plan.key);
  await oidf.ok(root + "/admin-api/realms/create", { id: realm,
    domain: realm + ".example.net", name: "Conformance " + plan.name },
    "created the realm");
  // The OpenID plans test the default: the test stack's appconfig turns the
  // code-replay courtesy on for a parent job (env/docker-tests.js), so each
  // realm here turns it back off.
  // And the request_uri modules send a fragment hashed from random bytes
  // (the suite's content is not known when it makes the URI), which this
  // OP checks by default: OpenID Connect Core 6.2 asks no OP to, so these
  // realms do not (`oauth2.requestUriFragmentCheck`, #187).
  const settings = [["oauth2.openRegistration", true],
                    ["oauth2.codeReplayIdempotent", false],
                    ["oauth2.requestUriFragmentCheck", false]]
    .concat(plan.settings || []);
  // What the service fetches from the suite (a registered request_uri, a
  // client's jwks_uri, a sector_identifier_uri) and what it sends there (a
  // Logout Token) goes through the federation outbound policy, verified
  // against the suite's own certificate (#171).
  settings.push(["federation.outboundCaFile",
                 oidf.suiteCaFile()]);
  for (let i = 0; i < settings.length; i++) {
    await oidf.ok(api + "/config/set", { key: settings[i][0],
                                         value: settings[i][1] },
                  "set " + settings[i][0]);
  }
  await oidf.ok(api + "/users/create", { username: person, invent: false,
    credential: "password", password: PASSWORD,
    attributes: { cn: "Conformance " + person, givenName: "Conformance",
                  sn: person, mail: person + "@conformance.test" } },
    "created " + person);
  const configuration = {
    alias: alias,
    description: "iya-sts " + plan.name + " " + STAMP,
    // Not the suite's: taken off again before the plan is created, for the
    // operator above.
    realmApi: api,
    server: { discoveryUrl: base + "/.well-known/openid-configuration",
              allow_unexpected_metadata_fields: oidf.EXTENSION_METADATA },
    browser: browserFor(base, person, !!plan.frontchannel),
    override: overridesFor(base, person)
  };
  let recorded = null;
  if (plan.verification) {
    recorded = await oidf.ok(api + "/users/record-verification",
                             Object.assign({ user: person },
                                           plan.verification),
                             "recorded a verification for " + person);
  }
  if (plan.ekyc) {
    configuration.ekyc = Object.assign({}, plan.ekyc);
    // `ekyc.userinfo`: what the operator knows this person's verified
    // claims to be — the record just made, as UserInfo would carry it. The
    // two modules that read it (the defaults and the not-advertised check)
    // are skipped without it.
    if (recorded && recorded.verification) {
      configuration.ekyc.userinfo = { verified_claims: {
        verification: recorded.verification.verification,
        claims: recorded.verification.claims } };
    }
  }
  const keys1 = oidf.keyPair("conf-" + plan.key + "-1", plan.keyAlg);
  const keys2 = oidf.keyPair("conf-" + plan.key + "-2", plan.keyAlg);
  if (plan.static) {
    const clients = await staticClients(plan, base, api, alias);
    configuration.client = { client_id: clients[0].client_id,
                             client_secret: clients[0].client_secret,
                             scope: "openid profile email" };
    configuration.client2 = { client_id: clients[1].client_id,
                              client_secret: clients[1].client_secret,
                              scope: "openid profile email" };
    if (clients[2]) {
      configuration.client_secret_post = {
        client_id: clients[2].client_id,
        client_secret: clients[2].client_secret,
        scope: "openid profile email" };
    }
    if (clients[0].mtls) {
      configuration.mtls = clients[0].mtls;
      configuration.mtls2 = clients[1].mtls;
    }
  } else {
    configuration.client = { client_name: "conformance " + plan.key + " 1",
                             jwks: keys1.privateJwks };
    configuration.client2 = { client_name: "conformance " + plan.key + " 2",
                              jwks: keys2.privateJwks };
  }
  log.debug("Leaving prepare().");
  return configuration;
}

// ---------------------------------------------------------------------------
// THE OP'S OPERATOR. oidcc-server-rotate-keys is not started by the suite: it
// reads the JWKS, asks the operator to rotate the OP's signing keys, and
// compares once it is started. So this job rotates the realm's keys
// (`/admin-api/keys/rotate`, the console's Rotate), waits for the scheduler
// run it queues, and starts the module.
// ---------------------------------------------------------------------------
function operatorFor(api) {
  log.debug("Entering operatorFor().");
  const started = {};
  log.debug("Leaving operatorFor().");
  return async function (id, info) {
    log.debug("Entering the OP operator. " + id);
    if (started[id] || !info || info.status !== "CONFIGURED" ||
        info.testName !== "oidcc-server-rotate-keys") {
      log.debug("Leaving the OP operator. Nothing to do.");
      return;
    }
    started[id] = true;
    const rotated = await oidf.send(api + "/keys/rotate", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: "{}" });
    assert.strictEqual(rotated.status, 202, "the key rotation: " +
                       rotated.raw.slice(0, 300));
    for (let i = 0; i < 30; i++) {
      const run = await oidf.send(api + "/scheduler?run=" +
                                  encodeURIComponent(rotated.body.runId));
      const state = JSON.stringify(run.body || {});
      if (/"(succeeded|done|finished|completed|failed)"/i.test(state)) {
        break;
      }
      await oidf.waitMs(1000);
    }
    const r = await oidf.suite("POST", "api/runner/" + id);
    log.info("  rotated the realm's signing keys and started the module: " +
             r.status);
    log.debug("Leaving the OP operator.");
  };
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
      const configuration = await prepare(plan);
      const realmApi = configuration.realmApi;
      delete configuration.realmApi;
      ran = await oidf.runPlan(plan.name, plan.variant, configuration,
                               plan.key, operatorFor(realmApi));
    } catch (e) {
      // One plan that cannot be set up or created is reported with the rest
      // rather than ending the run.
      log.error("Caught in test(): " + plan.key + ": " +
                ((e && e.message) || e));
      unexpected.push(plan.key + " could not run: " +
                      ((e && e.message) || e));
      continue;
    }
    const judged = oidf.judge(plan.key, ran, EXPECTED, KNOWN_WARNINGS,
                              KNOWN_FAILURES);
    log.info("  " + plan.key + ": " + JSON.stringify(judged.counts) +
             ", plan " + oidf.SUITE + "plan-detail.html?plan=" + ran.planId);
    judged.unexplained.forEach(function (line) {
      unexpected.push(line);
    });
  }
  // Every plan runs before the verdict, so one run reports all of them.
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
    "plans (#187): the OP certification profiles, oidcc-test-plan's " +
    "variants, and the four logout plans, against this service.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
