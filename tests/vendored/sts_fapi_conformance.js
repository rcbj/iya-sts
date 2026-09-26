"use strict";
//
// File: sts_fapi_conformance.js
//
// ---------------------------------------------------------------------------
// THE OPENID FOUNDATION'S CONFORMANCE SUITE AGAINST THIS SERVICE (#176,
// 2026-09-24). rcbj's decision (on #142): a job in ./run-tests.sh that fails
// when a module fails.
//
// The suite (`registry.gitlab.com/openid/conformance-suite`, pinned by tag in
// the compose file, with its nginx and a MongoDB) runs beside the service in
// the test stack. This job is its DRIVER — the part of the suite's own
// `scripts/run-test-plan.py` this repository needs, in node, so the tests
// container needs no python:
//
//   1. For each plan below, a throwaway trust realm (left behind) under the
//      profile the plan tests, a person the suite signs in as, and two
//      clients registered dynamically with keys made here, at run time — no
//      key material in git. A plan that tests mutual TLS gets client
//      certificates made here too.
//   2. The plan is created through the suite's API with its configuration —
//      the discovery URL, the clients, the resource, and the `browser`
//      commands that sign the person in on `/authn/login` and allow the
//      consent screen — and every module of it is run, one at a time.
//   3. A module ends PASSED, WARNING, REVIEW (a screenshot a person would
//      check), SKIPPED or FAILED. **A FAILED module fails the job** unless it
//      is listed in EXPECTED below WITH ITS REASON — a known and argued
//      difference, never a way to make the job green.
//   4. FAPI-CIBA needs the person to approve on another device. The suite's
//      `automated_ciba_approval_url` names an address it POSTs to with the
//      request and allow or deny; this job serves that address itself and
//      answers through `/admin-api/users/answer-ciba-request`, the test
//      control development mode opens and product closes — so the CIBA plan
//      runs in development only.
//
// #187 (2026-09-24) added the VARIANT MATRIX to PLANS — mutual TLS as client
// authentication and as the sender constraint, Message Signing with Grant
// Management, PAR with JARM under 1.0 Advanced, CIBA ping — and nothing
// about how the first four run. The other families' plans are their own
// jobs, sharing `conformance_suite.js` (tests/CLAUDE.md, *The other plans*).
//
// OWNED HERE (local: true): this repository's authorization server.
// ---------------------------------------------------------------------------

const assert = require("assert");
const http = require("http");
const https = require("https");
const nodeCrypto = require("crypto");
const os = require("os");
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
var log = bunyan.createLogger({ name: "sts_fapi_conformance",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var root = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
// Where the suite answers, as this job reaches it — and the base the suite
// believes it has, which its redirect URIs are built on.
const SUITE = String(process.env.CONFORMANCE_SUITE_URL ||
                     "https://localhost.emobix.co.uk:8443/")
  .replace(/\/?$/, "/");
// Where the suite reaches THIS job, for the CIBA approval address.
const SELF_HOST = process.env.CONFORMANCE_CALLBACK_HOST || os.hostname();
const STAMP = names.runStamp();
const TAG = STAMP.toLowerCase().replace(/[^a-z0-9]/g, "").slice(0, 12);
const PASSWORD = "Conf-Passw0rd!-" + String(Date.now()).slice(-6);
// How long one module may run. The slowest module on 2026-09-24 took well
// under a minute; the refresh and expiry modules wait on purpose, for less.
const MODULE_SECONDS = Number(process.env.CONFORMANCE_MODULE_SECONDS) || 300;

// ---------------------------------------------------------------------------
// THE PLANS, one representative variant each, then #187's matrix: a whole
// plan is 67 to 90 modules, and every variant is another run of them.
// ---------------------------------------------------------------------------
const PLANS = [
  { key: "fapi2sp", name: "fapi2-security-profile-final-test-plan",
    fapi: "2-security",
    variant: { fapi_profile: "plain_fapi", authorization_request_type:
               "simple", client_auth_type: "private_key_jwt",
               grant_management: "enabled", openid: "openid_connect",
               sender_constrain: "dpop" } },
  { key: "fapi2ms", name: "fapi2-message-signing-final-test-plan",
    fapi: "2-message-signing",
    variant: { fapi_profile: "plain_fapi", authorization_request_type:
               "simple", client_auth_type: "private_key_jwt",
               fapi_request_method: "signed_non_repudiation",
               fapi_response_mode: "jarm", grant_management: "disabled",
               openid: "openid_connect", sender_constrain: "dpop" } },
  { key: "fapi1adv", name: "fapi1-advanced-final-test-plan",
    fapi: "1-advanced", mtls: true,
    variant: { fapi_profile: "plain_fapi", client_auth_type:
               "private_key_jwt", fapi_auth_request_method: "by_value",
               fapi_response_mode: "plain_response" } },
  { key: "fapiciba", name: "fapi-ciba-id1-test-plan",
    fapi: "1-advanced", mtls: true, ciba: true, developmentOnly: true,
    variant: { client_registration: "static_client", ciba_mode: "poll",
               client_auth_type: "private_key_jwt",
               fapi_ciba_profile: "plain_fapi" } },
  // -------------------------------------------------------------------------
  // THE VARIANT MATRIX (#187): each profile once more with the axes the four
  // above do not take — mutual TLS as client authentication and as the
  // sender constraint, JARM where FAPI 1.0 Advanced took a plain response,
  // a pushed request, Grant Management under Message Signing, and CIBA's
  // ping mode. The
  // suite (release-v5.3.1) publishes no push-mode FAPI-CIBA plan: its own CI
  // has `fapi-ciba-id1-push-with-mtls-test-plan` commented out, and the
  // plan's `ciba_mode` offers poll and ping only.
  // -------------------------------------------------------------------------
  { key: "fapi2sp-mtls", name: "fapi2-security-profile-final-test-plan",
    fapi: "2-security", mtls: true,
    variant: { fapi_profile: "plain_fapi", authorization_request_type:
               "simple", client_auth_type: "mtls",
               grant_management: "disabled", openid: "openid_connect",
               sender_constrain: "mtls" } },
  // Message Signing keeps JARM: FAPI 2.0 Message Signing section 5.4.1 says
  // an authorization server implementing response signing "shall support,
  // require use of" JARM, and this one implements it — so the plan's
  // `plain_response` variant, which tests one that does not, is refused at
  // PAR by design (#187, oauth-oidc/CLAUDE.md 3bl).
  { key: "fapi2ms-mtls", name: "fapi2-message-signing-final-test-plan",
    fapi: "2-message-signing", mtls: true,
    variant: { fapi_profile: "plain_fapi", authorization_request_type:
               "simple", client_auth_type: "mtls",
               fapi_request_method: "signed_non_repudiation",
               fapi_response_mode: "jarm",
               grant_management: "enabled", openid: "openid_connect",
               sender_constrain: "mtls" } },
  { key: "fapi1adv-par-jarm", name: "fapi1-advanced-final-test-plan",
    fapi: "1-advanced", mtls: true,
    variant: { fapi_profile: "plain_fapi", client_auth_type: "mtls",
               fapi_auth_request_method: "pushed",
               fapi_response_mode: "jarm" } },
  { key: "fapiciba-ping", name: "fapi-ciba-id1-test-plan",
    fapi: "1-advanced", mtls: true, ciba: true, developmentOnly: true,
    variant: { client_registration: "static_client", ciba_mode: "ping",
               client_auth_type: "mtls",
               fapi_ciba_profile: "plain_fapi" } }
];

// ---------------------------------------------------------------------------
// KNOWN AND ARGUED DIFFERENCES: `<plan key>/<module>` -> why. Empty until a
// run shows one, and every entry is a sentence a reviewer can check.
// ---------------------------------------------------------------------------
const EXPECTED = {};

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

async function send(url, options) {
  log.debug("Entering send(). " + url);
  const r = await fetch(url, Object.assign({ redirect: "manual" },
                                           options || {}));
  const raw = await r.text();
  let body = null;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in send(): " + ((e && e.message) || e));
    // Not JSON; the caller reads `raw`.
    body = null;
  }
  log.debug("Leaving send(). " + r.status);
  return { status: r.status, body: body, raw: raw };
}

async function ok(url, payload, what) {
  log.debug("Entering ok().");
  const r = await send(url, { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {}) });
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "POST " + url + " should have " + what + "; it answered " + r.status +
    " " + String(r.raw).slice(0, 400));
  log.debug("Leaving ok().");
  return r.body;
}

function waitMs(ms) {
  log.debug("Entering waitMs().");
  log.debug("Leaving waitMs().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

// An EC P-256 key pair as the suite wants it: a JWK Set with the PRIVATE
// key (the suite signs with it) and the public one this service registers.
function keyPair(kid) {
  log.debug("Entering keyPair().");
  const pair = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const pub = pair.publicKey.export({ format: "jwk" });
  const priv = pair.privateKey.export({ format: "jwk" });
  [pub, priv].forEach(function (jwk) {
    jwk.kid = kid;
    jwk.use = "sig";
    jwk.alg = "ES256";
  });
  log.debug("Leaving keyPair().");
  return { publicJwks: { keys: [pub] }, privateJwks: { keys: [priv] } };
}

// A TLS client certificate for a registered client, from the realm's own CA
// (`issue-tls-client-certificate`, the application's credentials section),
// as the PEMs the suite wants: the key comes back encrypted under a password
// chosen here, and is opened here.
async function clientCertificate(api, clientId) {
  log.debug("Entering clientCertificate(). " + clientId);
  const password = nodeCrypto.randomBytes(18).toString("base64url");
  const r = await ok(api + "/applications/issue-tls-client-certificate",
                     { application: clientId, password: password,
                       keyAlg: "ec-p256", label: "conformance" },
                     "issued a client certificate");
  const key = nodeCrypto.createPrivateKey({ key: r.files.key.text,
                                           format: "pem",
                                           passphrase: password })
    .export({ format: "pem", type: "pkcs8" });
  log.debug("Leaving clientCertificate().");
  return { cert: r.certificate.certificatePem, key: String(key),
           ca: (r.certificate.chainPem || []).join("\n") };
}

// ---------------------------------------------------------------------------
// THE SCRIPTED BROWSER. The suite drives an HtmlUnit browser through a list
// of TASKS, each run only while the page's address matches it, and a task
// that is not `optional` failing to match fails the module. One list serves
// every module, because every task in it is optional:
//
//   * Sign in — only on the first authorization of a module; a second one in
//     the same browser (merge, replace) finds the session and skips it.
//   * Consent — only where this realm asks.
//   * The error page — a refused authorization request stays on
//     /oauth2/authorize and shows this service's error page, which the suite
//     photographs into the module's placeholder. That is a REVIEW outcome,
//     never a failure: the suite cannot read a page it did not write.
//   * The callback.
//
// Two modules need a path of their own, in `override` (the suite merges
// `override[<module name>]` over the configuration for that module).
// ---------------------------------------------------------------------------
const CLIENT2_QUERY = "?dummy1=lorem&dummy2=ipsum";
const MODULE_PREFIXES = ["fapi2-security-profile-final-",
                         "fapi2-message-signing-final-",
                         "fapi1-advanced-final-", "fapi-ciba-id1-"];

function signInCommands(person) {
  log.debug("Entering signInCommands().");
  log.debug("Leaving signInCommands().");
  return [["text", "id", "username", person],
          ["text", "id", "password", PASSWORD],
          ["click", "id", "kc-login"]];
}

function browserFor(base, alias, person) {
  log.debug("Entering browserFor().");
  log.debug("Leaving browserFor().");
  return [{
    match: base + "/oauth2/authorize*",
    tasks: [
      { task: "Sign in", optional: true, match: base + "/authn/login*",
        commands: signInCommands(person) },
      { task: "Consent", optional: true, match: base + "/oauth2/consent*",
        commands: [["click", "id", "consent-allow"]] },
      { task: "Error page", optional: true,
        match: base + "/oauth2/authorize*",
        commands: [["wait", "xpath", "//body", 10, ".*",
                    "update-image-placeholder-optional"]] },
      { task: "Verify complete", optional: true,
        match: SUITE + "test/a/" + alias + "/callback*",
        commands: [["wait", "id", "submission_complete", 10]] }
    ]
  }];
}

function overridesFor(plan, base, alias, person) {
  log.debug("Entering overridesFor(). " + plan.key);
  const out = {};
  // A plan runs modules named for more than itself — the message-signing
  // plan's are mostly the security profile's — so the two are keyed under
  // every family's prefix; a key naming no module in the plan is ignored.
  MODULE_PREFIXES.forEach(function (prefix) {
    // The person presses Cancel on the sign-in page, which answers
    // access_denied to the client.
    out[prefix + "user-rejects-authentication"] = { browser: [{
      match: base + "/oauth2/authorize*",
      tasks: [
        { task: "Cancel", match: base + "/authn/login*",
          commands: [["click", "id", "kc-cancel"]] },
        { task: "Verify complete",
          match: SUITE + "test/a/" + alias + "/callback*",
          commands: [["wait", "id", "submission_complete", 10]] }
      ]
    }] };
    // The first visit only LOADS the sign-in page — the module then visits
    // the same request_uri again, and signs in on that one.
    out[prefix + "par-ensure-reused-request-uri-prior-to-auth-completion-" +
        "succeeds"] = { browser: [{
      match: base + "/oauth2/authorize*",
      "match-limit": 1,
      tasks: [
        { task: "Load the sign-in page", match: base + "/authn/login*",
          commands: [["wait", "id", "username", 10]] }
      ]
    }].concat(browserFor(base, alias, person)) };
  });
  log.debug("Leaving overridesFor().");
  return out;
}

// ---------------------------------------------------------------------------
// ONE PLAN'S REALM, PERSON AND CLIENTS, and the suite's configuration.
// ---------------------------------------------------------------------------
async function prepare(plan) {
  log.debug("Entering prepare(). " + plan.key);
  const realm = ("conf-" + plan.key + "-" + TAG).slice(0, 31);
  const base = root + "/realm/" + realm;
  const api = base + "/admin-api";
  const alias = "iya-" + plan.key + "-" + TAG;
  const person = names.usernameFor("conf-" + plan.key);
  await ok(root + "/admin-api/realms/create", { id: realm,
    domain: realm + ".example.net", name: "Conformance " + plan.name },
    "created the realm");
  const settings = [["oauth2.fapi", plan.fapi],
                    ["oauth2.openRegistration", true]];
  if (plan.ciba) {
    settings.push(["oauth2.ciba", true]);
  }
  if (plan.variant.ciba_mode === "ping") {
    // The ping is a request this service makes to the suite, through the
    // federation outbound policy, verified against the certificate
    // conformance-tls minted (#187).
    settings.push(["federation.outboundCaFile", oidf.suiteCaFile()]);
  }
  for (let i = 0; i < settings.length; i++) {
    await ok(api + "/config/set", { key: settings[i][0],
                                    value: settings[i][1] },
             "set " + settings[i][0]);
  }
  await ok(api + "/users/create", { username: person, invent: false,
    credential: "password", password: PASSWORD,
    attributes: { cn: "Conformance " + person, givenName: "Conformance",
                  sn: person, mail: person + "@conformance.test" } },
    "created " + person);
  const discovery = (await send(base + "/.well-known/openid-configuration"))
    .body;
  const redirect = SUITE + "test/a/" + alias + "/callback";
  const clients = [];
  for (let n = 1; n <= 2; n++) {
    const keys = keyPair("conf-" + plan.key + "-" + n);
    const metadata = {
      // The suite sends the SECOND client's authorization requests to its
      // callback with a query of its own, to see that the query survives
      // (RFC 6749 section 3.1.2), and exact matching means it is registered
      // that way.
      redirect_uris: [n === 1 ? redirect : redirect + CLIENT2_QUERY],
      jwks: keys.publicJwks,
      grant_types: plan.ciba
        ? ["urn:openid:params:grant-type:ciba", "refresh_token"]
        : ["authorization_code", "refresh_token"],
      // FAPI 1.0 Advanced's plain response is the hybrid `code id_token`
      // (section 5.2.2 item 2), and a client is held to the response types
      // it registered (#120).
      response_types: plan.ciba ? []
        : (plan.variant.fapi_response_mode === "plain_response" &&
           plan.fapi === "1-advanced")
          ? ["code id_token"] : ["code"],
      scope: "openid profile email",
      id_token_signed_response_alg: "PS256"
    };
    // RFC 8705 section 2.1's tls_client_auth for the matrix's mutual TLS
    // variants (the certificate issued below is the client's by the implicit
    // mapping, 3an); private_key_jwt, with the key above, otherwise.
    if (plan.variant.client_auth_type === "mtls") {
      metadata.token_endpoint_auth_method = "tls_client_auth";
    } else {
      metadata.token_endpoint_auth_method = "private_key_jwt";
      metadata.token_endpoint_auth_signing_alg = "ES256";
    }
    if (plan.ciba) {
      metadata.backchannel_token_delivery_mode =
        plan.variant.ciba_mode || "poll";
      if (plan.variant.ciba_mode === "ping") {
        metadata.backchannel_client_notification_endpoint = SUITE +
          "test/a/" + alias + "/ciba-notification-endpoint";
      }
      // The algorithm of the keys made above: FAPI allows PS256 and ES256.
      metadata.backchannel_authentication_request_signing_alg = "ES256";
    }
    if (plan.variant.fapi_response_mode === "jarm") {
      metadata.authorization_signed_response_alg = "PS256";
    }
    const registered = await send(base + "/oauth2/register", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(metadata) });
    assert.strictEqual(registered.status, 201, plan.key + " client " + n +
                       ": " + registered.raw.slice(0, 400));
    // Grant Management's two scopes are this service's protected scopes
    // (#110): a registration may not grant them to itself, and an
    // administrator declares them.
    for (const scope of ["grant_management_query",
                         "grant_management_revoke"]) {
      await ok(api + "/applications/add", {
        application: registered.body.client_id,
        attribute: "oauthAllowedScope", value: scope },
        "declared " + scope);
    }
    const client = { client_id: registered.body.client_id,
                     jwks: keys.privateJwks, scope: "openid profile",
                     dpop_signing_alg: "ES256" };
    if (plan.ciba) {
      client.hint_type = "login_hint";
      client.hint_value = person;
      // The FAPI-CIBA plan sends acr_values, and wants one the realm
      // publishes: level 1 (a password) where there is one, which the test
      // control that answers for the person satisfies.
      const acrs = discovery.acr_values_supported || [];
      client.acr_value = acrs.indexOf("1") >= 0 ? "1" : String(acrs[0] || "");
    }
    clients.push(client);
  }
  const configuration = {
    alias: alias,
    description: "iya-sts " + plan.name + " " + STAMP,
    server: { discoveryUrl: base + "/.well-known/openid-configuration",
              // Members the suite's RFC 8414 schema does not know, named as
              // the warning asks: `verified_claims_supported` (Identity
              // Assurance) and `native_sso_supported` (Native SSO) are from
              // specifications the schema has not caught up with;
              // `crypto_metadata_uri` (#42) and the five RFC 7521/7522
              // assertion members are this service's own extensions.
              allow_unexpected_metadata_fields: [
                "crypto_metadata_uri", "verified_claims_supported",
                "native_sso_supported",
                "urn:ietf:params:oauth:client-assertion-type:" +
                  "jwt-bearer_supported",
                "urn:ietf:params:oauth:client-assertion-type:" +
                  "saml2-bearer_supported",
                "assertion_signing_alg_values_supported",
                "assertion_encryption_alg_values_supported",
                "assertion_encryption_enc_values_supported"] },
    client: clients[0],
    client2: clients[1],
    resource: { resourceUrl: discovery.userinfo_endpoint },
    browser: browserFor(base, alias, person),
    override: overridesFor(plan, base, alias, person)
  };
  if (plan.mtls) {
    configuration.mtls = await clientCertificate(api, clients[0].client_id);
    configuration.mtls2 = await clientCertificate(api, clients[1].client_id);
  }
  if (plan.ciba) {
    configuration.automated_ciba_approval_url = "http://" + SELF_HOST +
      ":" + cibaPort + "/approve?realm=" + encodeURIComponent(realm) +
      "&user=" + encodeURIComponent(person) +
      "&acr=" + encodeURIComponent(clients[0].acr_value || "") +
      "&token={auth_req_id}&type={action}";
  }
  log.debug("Leaving prepare().");
  return { realm: realm, configuration: configuration };
}

// ---------------------------------------------------------------------------
// THE CIBA APPROVAL ADDRESS the suite calls (see the header).
// ---------------------------------------------------------------------------
let cibaPort = 0;
function startCibaApprover() {
  log.debug("Entering startCibaApprover().");
  const server = http.createServer(function (req, res) {
    log.debug("Entering the CIBA approver.");
    const url = new URL(req.url, "http://approver.invalid");
    const realm = url.searchParams.get("realm") || "";
    ok(root + "/realm/" + realm + "/admin-api/users/answer-ciba-request", {
      user: url.searchParams.get("user") || "",
      id: url.searchParams.get("token") || "",
      approve: url.searchParams.get("type") === "allow",
      // What the person proved at approval, as /portal/ciba records it — the
      // level the request asked for, which the ID Token then carries.
      acr: url.searchParams.get("acr") || undefined
    }, "answered the CIBA request").then(function () {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end("{}");
      log.debug("Leaving the CIBA approver.");
    }, function (e) {
      log.warn("The CIBA approver could not answer: " + e.message);
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end("{}");
      log.debug("Leaving the CIBA approver. Failed.");
    });
  });
  log.debug("Leaving startCibaApprover().");
  return new Promise(function (resolve) {
    server.listen(0, "0.0.0.0", function () {
      cibaPort = server.address().port;
      resolve(server);
    });
  });
}

// ---------------------------------------------------------------------------
// THE SUITE'S API.
// ---------------------------------------------------------------------------
// THE SUITE'S CERTIFICATE IS NOT VERIFIED, AND ONLY THE SUITE'S. Its nginx
// serves a self-signed certificate made when its image was built, for a name
// that is an alias on this network; there is nothing to anchor it to. So the
// suite's API is called through `https` with verification off for that one
// agent, and every call to THIS service still goes through `fetch`, verified
// against the stack's trust as in every other job.
const SUITE_AGENT = new https.Agent({ rejectUnauthorized: false,
                                      keepAlive: true });

function suite(method, path, body) {
  log.debug("Entering suite(). " + method + " " + path);
  const payload = body ? JSON.stringify(body) : "";
  return new Promise(function (resolve, reject) {
    const req = https.request(new URL(SUITE + path), {
      method: method, agent: SUITE_AGENT,
      headers: body ? { "Content-Type": "application/json",
                        "Content-Length": Buffer.byteLength(payload) } : {}
    }, function (res) {
      let raw = "";
      res.setEncoding("utf8");
      res.on("data", function (chunk) {
        raw += chunk;
      });
      res.on("end", function () {
        let parsed = null;
        try {
          parsed = JSON.parse(raw);
        } catch (e) {
          log.debug("Caught in suite(): " + ((e && e.message) || e));
          // Not JSON; the caller reads `raw`.
          parsed = null;
        }
        log.debug("Leaving suite(). " + res.statusCode);
        resolve({ status: res.statusCode, body: parsed, raw: raw });
      });
    });
    req.on("error", function (e) {
      log.debug("Leaving suite(). " + ((e && e.message) || e));
      reject(e);
    });
    req.end(payload);
  });
}

async function waitForSuite() {
  log.debug("Entering waitForSuite().");
  for (let i = 0; i < 120; i++) {
    try {
      const r = await suite("GET", "api/plan?length=1");
      if (r.status === 200) {
        log.debug("Leaving waitForSuite(). Up.");
        return;
      }
    } catch (e) {
      log.debug("Caught in waitForSuite(): " + ((e && e.message) || e));
    }
    await waitMs(5000);
  }
  log.debug("Leaving waitForSuite(). Never up.");
  throw new Error("the conformance suite at " + SUITE + " never answered");
}

// One module: created in the plan, then waited on until it finishes.
async function runModule(planId, module) {
  log.debug("Entering runModule(). " + module.testModule);
  const q = "test=" + encodeURIComponent(module.testModule) + "&plan=" +
            encodeURIComponent(planId) +
            (module.variant ? "&variant=" +
             encodeURIComponent(JSON.stringify(module.variant)) : "");
  const created = await suite("POST", "api/runner?" + q);
  assert.ok(created.status === 201 || created.status === 200,
            "creating " + module.testModule + ": " + created.raw.slice(0, 300));
  const id = created.body.id;
  let info = null;
  // A module waits on nothing longer than MODULE_SECONDS: one left WAITING
  // (a browser task that never matched, a callback that never came) is
  // stopped through the suite's API and counted as the failure it is,
  // rather than holding the plan until the job's watchdog kills it.
  const deadline = Date.now() + MODULE_SECONDS * 1000;
  while (true) {
    info = (await suite("GET", "api/info/" + id)).body || {};
    if (info.status === "FINISHED" || info.status === "INTERRUPTED") {
      break;
    }
    if (Date.now() > deadline) {
      await suite("DELETE", "api/runner/" + id);
      info = Object.assign({}, info, { status: "TIMED OUT" });
      break;
    }
    await waitMs(2000);
  }
  let failures = [];
  if (info.result === "FAILED" || info.status !== "FINISHED") {
    const logs = (await suite("GET", "api/log/" + id)).body || [];
    failures = logs.filter(function (entry) {
      return entry.result === "FAILURE";
    }).map(function (entry) {
      return String(entry.src || "") + ": " + String(entry.msg || "");
    }).slice(0, 5);
  }
  log.debug("Leaving runModule(). " + info.result);
  return { module: module.testModule, id: id, status: info.status,
           result: info.result || "", failures: failures };
}

async function runPlan(plan) {
  log.debug("Entering runPlan(). " + plan.key);
  const prepared = await prepare(plan);
  const created = await suite("POST", "api/plan?planName=" +
    encodeURIComponent(plan.name) + "&variant=" +
    encodeURIComponent(JSON.stringify(plan.variant)),
    prepared.configuration);
  assert.ok(created.status === 201 || created.status === 200,
            "creating " + plan.name + ": " + created.raw.slice(0, 400));
  const results = [];
  const modules = created.body.modules || [];
  for (let i = 0; i < modules.length; i++) {
    const got = await runModule(created.body.id, modules[i]);
    log.info("  " + plan.key + " " + got.module + ": " +
             (got.result || got.status) +
             (got.failures.length ? " — " + got.failures[0] : ""));
    results.push(got);
  }
  log.debug("Leaving runPlan(). " + results.length);
  return { plan: plan, planId: created.body.id, results: results };
}

async function test() {
  log.debug("Entering test().");
  const product = await registry.isProduct(root);
  const only = String(process.env.CONFORMANCE_PLANS || "").split(",")
    .map(function (s) {
      return s.trim();
    }).filter(Boolean);
  await waitForSuite();
  const approver = await startCibaApprover();
  const unexpected = [];
  try {
    for (const plan of PLANS) {
      if (only.length && only.indexOf(plan.key) < 0) {
        continue;
      }
      if (plan.developmentOnly && product) {
        log.info("=== " + plan.name + ": skipped in product mode, where the " +
                 "CIBA test control is closed ===");
        continue;
      }
      log.info("=== " + plan.name + " " + JSON.stringify(plan.variant) +
               " ===");
      const ran = await runPlan(plan);
      const failed = ran.results.filter(function (r) {
        return (r.result === "FAILED" || r.status !== "FINISHED") &&
               !EXPECTED[plan.key + "/" + r.module];
      });
      const counts = {};
      ran.results.forEach(function (r) {
        const k = r.result || r.status;
        counts[k] = (counts[k] || 0) + 1;
      });
      log.info("  " + plan.key + ": " + JSON.stringify(counts) + ", plan " +
               SUITE + "plan-detail.html?plan=" + ran.planId);
      failed.forEach(function (r) {
        unexpected.push(plan.key + "/" + r.module + " (" +
                        (r.result || r.status) + "): " +
                        r.failures.join(" | "));
      });
      check(plan.name + ": every module passed, or failed as EXPECTED says " +
            "and why", function () {
        assert.strictEqual(failed.length, 0, failed.map(function (r) {
          return r.module;
        }).join(", "));
      });
    }
  } finally {
    approver.close();
  }
  if (unexpected.length) {
    log.error("Unexpected failures:\n  " + unexpected.join("\n  "));
  }
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

new Command()
  .description("The OpenID Foundation conformance suite's FAPI plans " +
    "(#176): FAPI 2.0 Security Profile and Message Signing, FAPI 1.0 " +
    "Advanced and FAPI-CIBA, against this service.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
