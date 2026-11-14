// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_fapi_client_conformance.js
//
// ---------------------------------------------------------------------------
// THE OPENID FOUNDATION'S CONFORMANCE SUITE: THE FAPI CLIENT PLANS (#931,
// 2026-11-13). The suite plays a FAPI authorization server and this service
// is its client, through what makes this service one: an inbound OpenID
// Connect federation relationship held to a FAPI profile (`fedFapi`,
// `federation/fapi_client.ts`) — a person starts here, signs in at the
// partner, and the partner's answer starts a session here.
// `sts_fapi_conformance.js` runs the FAPI authorization-server plans and
// `sts_oidcc_rp_conformance.js` the OpenID Connect relying-party ones; this
// is their shape, on the same containers.
//
//   1. For each plan below, a throwaway trust realm (left behind) whose one
//      service-provider-side OpenID Connect relationship has the suite's
//      issuer for this plan's alias as its fedPeer and reads its endpoints
//      from the suite's discovery document (`fedDiscovery`) — which for
//      FAPI 1.0 Advanced names `mtls_endpoint_aliases`, the addresses a
//      client presenting a certificate dials (RFC 8705 section 5). The
//      client is STATIC: a client id made here at run time, written onto
//      the relationship, and the plan's client configuration names it,
//      this relationship's assertion consumer service as its redirect_uri,
//      the realm's RSA signing keys as its `jwks` (each with `alg: PS256`,
//      which is what private_key_jwt and the request object are signed
//      with), and — for FAPI 1.0 Advanced — the relationship's TLS client
//      certificate as its `certificate`, read off the relationship's own
//      view (`clientCertificate`, issued when fedFapi became 1-advanced:
//      rcbj's decision of 2026-11-13 on #931). The suite holds every token
//      request and UserInfo call to that certificate. FAPI 1.0 Advanced
//      also takes the key the suite signs with as `server.jwks` (one PS256
//      RSA key made here; the 2.x plans make their own) and a `client2`
//      for its two encrypted-ID-Token modules: a second relationship to the
//      same issuer, its RSA-OAEP-256 encryption key in that client's `jwks`.
//   2. The plan is created and its modules run one at a time. When a
//      module waits, the PERSON starts where an application would send
//      them — this service's /federation/login/{id} — in the one headless
//      Chrome (`conformance_browser.js`), and the browser carries them to
//      the suite and back. A negative module (an ID Token, JARM response
//      or token answer the client must refuse) passes when this service
//      refuses it and dials nothing more. A positive module waits for a
//      resource call this relying party never makes, so it is stopped once
//      the suite has answered its UserInfo and judged REACHED RESOURCE
//      (operatorFor() argues it).
//   3. A FAILED module fails the job unless EXPECTED names it with its
//      reason; a FAILURE from a condition KNOWN_FAILURES names is argued
//      only when it is the module's only kind of failure; a WARNING from a
//      condition KNOWN_WARNINGS does not name fails it too
//      (`conformance_suite.js`'s judge(), #187's rule). EXPECTED starts
//      empty: an argument is added only for a module `federation/CLAUDE.md`
//      has already called a decision.
//   4. EVERY PLAN ALSO RUNS AS ITS CLASSICAL TWIN (`<key>-cl`,
//      `withClassicalTwins()`, keys.postQuantumSigning off). PQ_ONLY is
//      empty: the relationship signs with the realm's classical RSA key and
//      the client configuration hands the suite only those keys, so neither
//      run should need a post-quantum exemption.
//
// NOT THESE: `fapi-ciba-id1-client-test-plan` (this service has no CIBA
// client role; `POST /oauth2/bc-authorize` is the authorization server's,
// `sts_fapi_conformance.js`), FAPI 1.0 Advanced's `pushed` and
// `by_reference` request methods and its JARM response mode (1-advanced
// sends its request object by value on a plain hybrid response), and the
// 2.x plans' mutual-TLS sender constraint (2.x binds with DPoP).
//
// HOW TO RUN IT: it is `conformance: true`, so `./run-tests.sh` brings the
// suite up and runs it in the modes STS_TEST_CONFORMANCE_MODES names
// (`memory` by default), in a lane of its own. By hand:
// `./run-tests.sh --modes=memory --only=sts_fapi_client_conformance`, and
// CONFORMANCE_PLANS selects plans by key (`fapi1adv,fapi1adv-mtls`, or a
// prefix ending `*`: `fapi2*`).
//
// OWNED HERE (local: true): this repository's federation FAPI client.
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
var log = bunyan.createLogger({ name: "sts_fapi_client_conformance",
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

// ---------------------------------------------------------------------------
// THE PLANS. `key` is what CONFORMANCE_PLANS names; `variant` is what the
// plan leaves open, with the client role's variant keys (the suite's
// `FAPI1AdvancedFinalClientTestPlan`, `FAPI2SPFinalClientTestPlan` and
// `FAPI2MessageSigningFinalClientTestPlan`); `fapi` is the relationship's
// fedFapi and `tokenAuth` its fedTokenAuth where it is not private_key_jwt.
// A createPlan that rejects a key is a fix to that JSON.
// ---------------------------------------------------------------------------
const BASE_PLANS = [
  { key: "fapi1adv", name: "fapi1-advanced-final-client-test-plan",
    fapi: "1-advanced", mtls: true,
    variant: { fapi_profile: "plain_fapi", fapi_client_type: "oidc",
               client_auth_type: "private_key_jwt",
               fapi_auth_request_method: "by_value",
               fapi_response_mode: "plain_response" } },
  // RFC 8705 section 2.1's tls_client_auth: the certificate authenticates
  // the client as well as binding its tokens.
  { key: "fapi1adv-mtls", name: "fapi1-advanced-final-client-test-plan",
    fapi: "1-advanced", mtls: true, tokenAuth: "tls_client_auth",
    variant: { fapi_profile: "plain_fapi", fapi_client_type: "oidc",
               client_auth_type: "mtls",
               fapi_auth_request_method: "by_value",
               fapi_response_mode: "plain_response" } },
  { key: "fapi2sp", name: "fapi2-security-profile-final-client-test-plan",
    fapi: "2-security",
    variant: { fapi_profile: "plain_fapi", fapi_client_type: "oidc",
               client_auth_type: "private_key_jwt",
               sender_constrain: "dpop" } },
  { key: "fapi2ms", name: "fapi2-message-signing-final-client-test-plan",
    fapi: "2-message-signing",
    variant: { fapi_profile: "plain_fapi", fapi_client_type: "oidc",
               client_auth_type: "private_key_jwt",
               sender_constrain: "dpop",
               fapi_request_method: "signed_non_repudiation",
               fapi_response_mode: "jarm",
               authorization_request_type: "simple" } }
];
const PLANS = oidf.withClassicalTwins(BASE_PLANS);

// ---------------------------------------------------------------------------
// KNOWN AND ARGUED DIFFERENCES. `<plan key>/<module>` (or `*/<module>`) ->
// why a module that FAILED or waited out its time is not a defect here.
// None yet: a sentence belongs here only once `federation/CLAUDE.md`
// records the decision it cites.
// ---------------------------------------------------------------------------
const EXPECTED = {};
// The ledger entries about post-quantum keys a classical twin is judged
// without: none, since the suite is handed only the realm's RSA keys.
const PQ_ONLY = [];
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

function expectedFor(plan, moduleName) {
  log.debug("Entering expectedFor(). " + moduleName);
  log.debug("Leaving expectedFor().");
  return EXPECTED[plan.key + "/" + moduleName] ||
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

// The realm's RSA signing keys as the client's JWKS: what private_key_jwt
// and the PS256 request object verify against. Public halves only, each
// marked PS256 (the JWKS publishes the same RSA key for RS256 as well).
async function clientJwks(realmBase) {
  log.debug("Entering clientJwks().");
  const r = await oidf.send(realmBase + "/oauth2/jwks");
  assert.ok(r.status === 200 && r.body && Array.isArray(r.body.keys),
            "the realm's JWKS answered " + r.status);
  const keys = r.body.keys.filter(function (one) {
    return one && one.kty === "RSA" && (!one.use || one.use === "sig") &&
           !one.d;
  }).map(function (one) {
    const key = { kty: "RSA", n: one.n, e: one.e, kid: one.kid,
                  use: "sig", alg: "PS256" };
    if (Array.isArray(one.x5c)) {
      key.x5c = one.x5c;
    }
    return key;
  });
  assert.ok(keys.length > 0, "the realm publishes no RSA signing key");
  log.debug("Leaving clientJwks(). " + keys.length);
  return { keys: keys };
}

// THE KEY THE SUITE SIGNS WITH AS FAPI 1.0 ADVANCED'S AUTHORIZATION SERVER
// (#931's first run, 2026-11-13). The FAPI 2 client plans generate their
// own (FAPI2GenerateServerJWKs) when the configuration names none; the
// FAPI 1.0 Advanced plan only loads one (LoadServerJWKs: "Couldn't find a
// JWK set in configuration" failed all 92 of its modules), from
// `server.jwks`, and it must be ONE key with an `alg`
// (ExtractServerSigningAlg) of at least 2048 bits
// (FAPIEnsureMinimumServerKeyLength). PS256, because that is what the
// relationship's fedIdTokenSignedResponseAlg expects. Made per plan here
// and handed to nobody but the suite; this service reads only its public
// half, from the suite's jwks_uri.
function serverJwks(plan) {
  log.debug("Entering serverJwks(). " + plan.key);
  const pair = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = pair.privateKey.export({ format: "jwk" });
  jwk.kid = "suite-as-" + plan.key + "-" + TAG;
  jwk.use = "sig";
  jwk.alg = "PS256";
  log.debug("Leaving serverJwks().");
  return { keys: [jwk] };
}

// THE RELATIONSHIP'S OWN ENCRYPTION KEY, public half, as the client's
// `jwks` member for ID Token encryption (OpenID Connect Registration
// section 2): what /federation/jwks/{id} publishes.
async function encryptionJwks(realmBase, id) {
  log.debug("Entering encryptionJwks(). " + id);
  const r = await oidf.send(realmBase + "/federation/jwks/" +
                            encodeURIComponent(id));
  assert.ok(r.status === 200 && r.body && Array.isArray(r.body.keys),
            "the relationship " + id + "'s key set answered " + r.status);
  const keys = r.body.keys.filter(function (one) {
    return one && one.use === "enc" && !one.d;
  });
  assert.ok(keys.length === 1, "the relationship " + id + " publishes " +
            keys.length + " encryption keys: " + JSON.stringify(r.body));
  log.debug("Leaving encryptionJwks(). " + keys[0].kid);
  return keys;
}

// ONE INBOUND RELATIONSHIP TO THE SUITE: created, configured, enabled and
// read back. `extra` is written before fedFapi (which, set to 1-advanced,
// issues the client certificate).
async function relationship(plan, made, issuer, id, clientId, extra) {
  log.debug("Entering relationship(). " + id);
  await oidf.ok(made.api + "/federation/create",
                { id: id, role: "service-provider", protocol: "oidc",
                  peer: issuer },
                "created the relationship " + id);
  const fields = {
    fedName: "The conformance suite (" + plan.key + ")",
    // The suite's one subject is a person this realm has never seen, and a
    // relationship created in product mode does not create entries.
    fedAutocreateUsers: "TRUE",
    fedClientId: clientId,
    fedScope: "openid profile email",
    fedDiscovery: "TRUE",
    // FAPI's signing algorithms are PS256 and ES256; the suite's server
    // keys sign PS256.
    fedIdTokenSignedResponseAlg: "PS256",
    // A hybrid response with an ID Token comes back in the fragment
    // whatever is asked (the RP job's position); 2.x answers on the query.
    fedResponseMode: plan.fapi === "1-advanced" ? "fragment" : "",
    // Set last: setting it to 1-advanced issues the client certificate.
    fedFapi: plan.fapi
  };
  if (plan.tokenAuth) {
    fields.fedTokenAuth = plan.tokenAuth;
  }
  // PRODUCT MODE requires a partner to encrypt an ID Token that crosses the
  // browser; the suite could only be told to through its client
  // configuration, and encryption is not what these plans test — except
  // for the second client, which `extra` makes encrypt.
  if (await registry.isProduct(root) && !extra) {
    fields.fedAllowUnencrypted = "TRUE";
  }
  const fapi = fields.fedFapi;
  delete fields.fedFapi;
  Object.assign(fields, extra || {}, { fedFapi: fapi });
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
  const client = {
    client_id: clientId,
    scope: "openid profile email",
    redirect_uri: endpoints.assertionConsumerService,
    jwks: await clientJwks(made.base)
  };
  if (plan.mtls) {
    // THE CERTIFICATE THE SUITE HOLDS EVERY CALL TO, read off the
    // relationship's own view: what an administrator registers at a
    // FAPI 1.0 Advanced partner.
    const cert = view.clientCertificate || {};
    assert.ok(cert.held && cert.certificatePem, "the relationship " + id +
              " holds no client certificate: " + JSON.stringify(cert));
    client.certificate = cert.certificatePem;
  }
  log.debug("Leaving relationship().");
  return { id: id, client: client,
           login: made.base + "/federation/login/" + encodeURIComponent(id) };
}

async function prepare(plan) {
  log.debug("Entering prepare(). " + plan.key);
  const realm = ("fapi-rp-" + plan.key + "-" + TAG).slice(0, 31)
    .replace(/-+$/, "");
  const alias = "iya-fapi-rp-" + plan.key + "-" + TAG;
  const issuer = oidf.SUITE + "test/a/" + alias + "/";
  const made = await oidf.makeRealm(root, realm, "Conformance " + plan.name,
    // What the service fetches from the suite — its discovery document,
    // token, UserInfo, PAR and JWKS endpoints — goes through the federation
    // outbound policy, verified against the suite's own certificate (#171).
    // A classical twin's own setting (withClassicalTwins()) comes after it.
    [["federation.outboundCaFile", oidf.suiteCaFile()]]
      .concat(plan.settings || []));
  const first = await relationship(plan, made, issuer, "suite-" + plan.key,
    "iya-fapi-rp-" + plan.key + "-" + TAG, null);
  const configuration = {
    alias: alias,
    description: "iya-sts " + plan.name + " " + STAMP,
    client: first.client,
    // How long a negative module waits for this client to call something
    // it should not before it passes: the suite's default.
    waitTimeoutSeconds: 5
  };
  const logins = { client: first.login };
  if (plan.fapi === "1-advanced") {
    configuration.server = { jwks: serverJwks(plan) };
    // THE SECOND CLIENT (#931's first run): FAPI 1.0 Advanced's two
    // encrypted-ID-Token modules run as `client2`, whose ID Tokens the
    // suite encrypts to a key in its `jwks` (FAPI 1.0 Advanced 5.2.2.1
    // clause 6: an OP shall support signed and encrypted ID Tokens). It is
    // a second relationship to the same suite issuer, RSA-OAEP-256 and
    // A256GCM, so the RSA1_5 module runs too (the suite skips it for an
    // EC key) and this client must refuse that ID Token (STS-FED-0139).
    const second = await relationship(plan, made, issuer,
      "suite-" + plan.key + "-enc",
      "iya-fapi-rp-" + plan.key + "-enc-" + TAG,
      { fedEncryptionKeyType: "rsa-3072",
        fedKeyManagementAlgorithm: "RSA-OAEP-256",
        fedContentEncryptionAlgorithm: "A256GCM" });
    second.client.jwks = { keys: second.client.jwks.keys.concat(
      await encryptionJwks(made.base, second.id)) };
    second.client.id_token_encrypted_response_alg = "RSA-OAEP-256";
    second.client.id_token_encrypted_response_enc = "A256GCM";
    configuration.client2 = second.client;
    logins.client2 = second.login;
  }
  log.debug("Leaving prepare().");
  return {
    realm: made, id: first.id, issuer: issuer, alias: alias,
    login: first.login, logins: logins, configuration: configuration
  };
}

// ---------------------------------------------------------------------------
// THE PERSON (step 2 of the header): each module that waits is started once
// at the login endpoint — the second relationship's for a module that runs
// as `client2` — and whatever the module lists is visited.
//
// AND WHERE THIS CLIENT'S EXCHANGE ENDS (#931's first run, 2026-11-13).
// Every positive module of these plans finishes only when the client calls
// the suite's resource endpoint (`accounts_endpoint`,
// `open-banking/v1.1/accounts`): its UserInfo answer leaves the module
// WAITING, and a client that makes no further call is TIMED OUT. This
// client is a relying party: it authenticates the person by the ID Token
// and UserInfo (OpenID Connect Core 3.1.3, 5.3), and the partner's tokens
// are used once and never handed on (`federation/CLAUDE.md`, *THIS SERVICE
// AS A FAPI CLIENT*), so there is no resource for it to call. The suite
// itself ends a module at UserInfo where UserInfo is the profile's
// resource (`userInfoIsResourceEndpoint()`, ConnectID and CBUAE). So once
// the suite's log shows UserInfo answered 200 — every check of the token
// request and the UserInfo request having run — the module is stopped
// here and judged REACHED RESOURCE: passed if the suite logged no FAILURE,
// FAILED otherwise, its warnings judged as any module's.
// ---------------------------------------------------------------------------
async function userinfoAnswered(id) {
  log.debug("Entering userinfoAnswered(). " + id);
  const logs = (await oidf.suite("GET", "api/log/" + id)).body || [];
  const answered = Array.isArray(logs) && logs.some(function (entry) {
    // `userinfo` on 8443 and on FAPI 1.0 Advanced's mutual-TLS alias
    // (8444, `test-mtls/a/<alias>/userinfo`) alike; matched at the end so
    // a prefix the suite logs on either listener does not hide it.
    return entry && entry.http === "outgoing" &&
           /(^|\/)userinfo$/.test(String(entry.outgoing_path || "")) &&
           Number(entry.outgoing_status_code) === 200;
  });
  log.debug("Leaving userinfoAnswered(). " + answered);
  return answered;
}

function operatorFor(plan, prepared, person) {
  log.debug("Entering operatorFor(). " + plan.key);
  const started = {};
  const reached = {};
  log.debug("Leaving operatorFor().");
  const operator = async function (id, info) {
    log.debug("Entering the FAPI client's person. " + id);
    if (!info || info.status !== "WAITING" || reached[id]) {
      log.debug("Leaving the FAPI client's person. Not waiting.");
      return;
    }
    if (!started[id]) {
      started[id] = 1;
      const second = /encrypted-idtoken/.test(String(info.testName || ""));
      await person.start(id, info, second && prepared.logins.client2
        ? prepared.logins.client2 : prepared.login);
    }
    await person.visit(id, info);
    if (await userinfoAnswered(id)) {
      reached[id] = 1;
      log.info("  " + plan.key + " " + (info.testName || id) + ": UserInfo " +
               "answered; stopping it at the resource call this client " +
               "does not make.");
      await oidf.suite("DELETE", "api/runner/" + id);
    }
    log.debug("Leaving the FAPI client's person.");
  };
  operator.reached = reached;
  return operator;
}

// What a module the operator stopped at the resource call is reported as.
function judgedAtResource(got, operator) {
  log.debug("Entering judgedAtResource(). " + got.module);
  if (!operator || !operator.reached[got.id] ||
      got.status !== "INTERRUPTED") {
    log.debug("Leaving judgedAtResource(). Not stopped there.");
    return got;
  }
  log.debug("Leaving judgedAtResource().");
  return Object.assign({}, got, { status: "FINISHED",
    result: got.failures.length ? "FAILED" : "REACHED RESOURCE" });
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
      const argued = expectedFor(plan, module.testModule);
      let got = judgedAtResource(await oidf.runModule(planId, module,
        argued ? null : operator, argued ? ARGUED_SECONDS : undefined),
        operator);
      // ONE MORE RUN FOR A MODULE THAT TIMED OUT, as runPlan() gives one —
      // unless it is argued to wait out its time.
      if (got.status === "TIMED OUT" && !argued) {
        log.info("  " + plan.key + " " + got.module + ": TIMED OUT; " +
                 "running it once more.");
        got = judgedAtResource(await oidf.runModule(planId, module,
                                                    operator), operator);
      }
      log.info("  " + plan.key + " " + got.module + ": " +
               (got.result || got.status) +
               (got.failures.length ? " — " + got.failures[0].src + ": " +
                                      got.failures[0].msg : "") +
               (argued ? " (argued: " + argued + ")" : ""));
      results.push(got);
      // Each module signs in with a jar of its own; signing it out here
      // keeps a refresh-token module's held token from being presented
      // while the next module runs (the RP job's lesson, 2026-11-03).
      if (got.id) {
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
  const judged = oidf.judge(plan.key, { planId: planId, results: results },
                            oidf.ledgerFor(plan, EXPECTED, PQ_ONLY),
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
  // THE PLANS RUN SEVERAL AT A TIME, as the RP job's do: each is a realm and
  // an alias of its own, and the one Chrome serialises the person's visits.
  // CONFORMANCE_PLAN_CONCURRENCY=1 runs them one by one.
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
  .description("The OpenID Foundation conformance suite's FAPI client " +
    "plans (#931), against an inbound OpenID Connect federation " +
    "relationship of this service held to a FAPI profile.")
  .addOption(new Option("-u, --url <url>", "base url (unused: the " +
                                           "service's is the realm's)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
