// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: sts_fga.js
//
// ---------------------------------------------------------------------------
// APPLICATION-SCOPED FINE-GRAINED AUTHORIZATION, DRIVEN OVER HTTP (#564 P6).
//
// `tests/fga_policies.js`, `tests/fga_issuance.js`, `tests/fga_authzen.js`
// and `tests/fga_console.js` hold the lifecycle, the gate, the PEP, the
// AuthZEN branch and the console in process. This job asks the same
// questions of a RUNNING service, in a throwaway trust realm, through the
// doors a deployment has: `/admin-api` for every write, the OAuth endpoints
// for issuance, the AuthZEN endpoint for access time, and the remote PEP's
// pull. Nothing here reaches into the process. The sections:
//
//   1. THE SETUP: the realm, a person, a REMOTE_PEPS identity and an
//      AUTHZEN_PEPS identity (certificates minted here, their Roots in the
//      truststore, each stored on its own entry), the AuthZEN caller's scope,
//      and a realm ROOT written in ALFA that permits every AuthZEN question
//      — so a `false` below can only be the application's own policy.
//   2. THE DEFAULT POLICY: a new application gets one, its own, enabled; it
//      is never the root (listed so, and `set-root` refuses it); and the
//      remote PEP's pull withholds it by name.
//   3. THE TYPE AND THE SWITCH: `document_access` declared with xacml rows
//      and one member left uncovered; FGA off, issuance and AuthZEN are
//      unchanged; enabling is refused naming the member, then accepted once
//      it is listed in notForPolicy.
//   4. THE DEFAULT POLICY DECIDES: client_credentials with the detail is
//      issued; the token response, the access token and introspection (by
//      the resource application, the type's owner) carry the details.
//   5. A CUSTOM POLICY, IN ALFA, DENYING `delete`: the token endpoint
//      refuses delete (invalid_authorization_details) and grants read; the
//      authorization endpoint redirects access_denied for delete, before any
//      consent screen, and issues a code for read.
//   6. THE TOKEN EXCHANGE'S BOUND: a detail the subject_token carries is
//      granted, a broader one refused.
//   7. AUTHZEN: the application's policy answers false for delete and true
//      for read though the root permits both; an application without FGA is
//      still decided by the root.
//   8. A REFRESH AFTER THE POLICY CHANGES is refused.
//   9. A DISABLED POLICY: AuthZEN answers 500, never false; the token
//      endpoint answers server_error.
//  10. FGA OFF AGAIN: issuance and AuthZEN are back to the old behaviour.
//  11. DELETING THE APPLICATION: its policy stays, disabled and orphaned,
//      and an administrator removes it through `/admin-api`.
//
// **WHAT IS NOT HERE, AND WHERE IT IS.** The audit rows and their codes
// (STS-FGA-0018 on the refused enable, the digests on `fga.decision`) are
// asserted in process — over HTTP a code is never sent, so this file
// asserts the refusal and the member it names. PAR, `prompt=none`, limits
// lowered at consent and a MISSING policy are `tests/fga_issuance.js`'s
// alone: each is one more request of the same shape, against branches that
// file reaches with nothing but the endpoints.
//
// THE REALM IS LEFT IN PLACE (tests/CLAUDE.md, *No job removes a realm*);
// what this file stored on entries and the anchors it added are taken off
// at the end, as `sts_authzen.js` does.
//
// WHY `local: true`: the policies, the switch, the API and the AuthZEN
// branch are this repository's.
// ---------------------------------------------------------------------------

const assert = require("assert");
const crypto = require("crypto");
const https = require("https");
const { URL } = require("url");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const authnSignin = require("./authn_signin");
const consentScreen = require("./consent_screen.js");
const credentials = require("../tools/pep-credential.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, for the reason tests/vendored/wait_for.js gives.
  appconfigProblem = e;
  appconfig = {};
}

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_fga",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug('CONFIG_FILE could not be read, so the configuration is empty: ' +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");

const STAMP = names.runStamp().toLowerCase().replace(/[^a-z0-9-]/g, "");
const REALM = ("fga-" + STAMP).slice(0, 40);
const PREFIX = "/realm/" + REALM;
// THE RESOURCE APPLICATION that declares the type and owns the policy, the
// CLIENT that asks for details, and an application with no FGA at all, for
// the AuthZEN regression.
const DOCS = "fga-docs-" + STAMP;
const CLIENT = "fga-client-" + STAMP;
const OTHER = "fga-other-" + STAMP;
const PERSON = "fga-alice";
const AUTHZEN_CALLER = "fga-authzen-" + STAMP;
const REMOTE_PEP = "fga-pep-" + STAMP;
const REDIRECT = "https://" + CLIENT + ".example.com/callback";
const LOCATION = "https://docs." + REALM + ".example/";
const SECRETS = {};

// A browser's User-Agent on the sign-in walk, for token_exchange_chain_kit's
// reason: a product service scores a sign-in from `node` as automated. This
// realm is in development mode, so it is belt and braces there.
const DESKTOP_USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) " +
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";

// THE ISSUE'S EXAMPLE TYPE (docs/fga.md): a closed schema, `classification`
// mapped, `note` deliberately NOT listed yet, so the first enable has a
// member to name.
const DOCUMENT_ACCESS = {
  application: DOCS,
  type: "document_access",
  description: "Access to documents",
  locations: [LOCATION],
  actions: ["read", "update", "delete"],
  schema: { type: "object", additionalProperties: false,
            properties: {
              type: { const: "document_access" },
              locations: { type: "array", items: { type: "string" } },
              actions: { type: "array", items: { type: "string" } },
              identifier: { type: "string" },
              classification: { type: "string" },
              note: { type: "string" } } },
  xacml: [{ path: "classification",
            attributeId: "urn:example:classification" }]
};

// THE REALM'S ROOT: every AuthZEN question permitted, so the application's
// own policy is the only thing that can answer false.
const ROOT_POLICY = [
  'namespace fgaroot {',
  '    attribute protocol { category = environmentCat',
  '        id = "urn:sts:xacml:protocol" type = string }',
  '    policy everythingAtAuthzen {',
  '        id = "urn:test:fga-root"',
  '        apply firstApplicable',
  '        target clause protocol == "authzen"',
  '        rule permitAll { permit }',
  '    }',
  '}'
].join('\n');

const ALFA_HEAD = [
  'namespace fgadocs {',
  '    attribute act { category = actionCat',
  '        id = "urn:oasis:names:tc:xacml:1.0:action:action-id"',
  '        type = string }',
  '    attribute detailAction { category = actionCat',
  '        id = "urn:sts:xacml:fga:detail:action" type = string }',
  '    attribute stage { category = environmentCat',
  '        id = "urn:sts:xacml:fga:stage" type = string }',
  '    policy documents {',
  '        id = "urn:test:fga-docs"',
  '        apply firstApplicable'];

// NO DELETES, at issuance and at access time: docs/fga.md's two examples in
// one document, the stage telling them apart.
const NO_DELETE = ALFA_HEAD.concat([
  '        rule noDeleteDetail {',
  '            deny',
  '            target clause act == "grant-authorization-detail"',
  '            target clause detailAction == "delete"',
  '        }',
  '        rule noDeleteNow {',
  '            deny',
  '            target clause stage == "access"',
  '            target clause act == "delete"',
  '        }',
  '        rule everythingElse { permit }',
  '    }',
  '}']).join('\n');

// AND NO READS EITHER, for the refresh: the grant was for `read`.
const NO_READ = ALFA_HEAD.concat([
  '        rule noReadDetail {',
  '            deny',
  '            target clause act == "grant-authorization-detail"',
  '            target clause detailAction == "read"',
  '        }',
  '        rule everythingElse { permit }',
  '    }',
  '}']).join('\n');

var checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.debug("check passed: " + what);
  log.debug("Leaving check().");
}

function api(path) {
  log.debug("Entering api().");
  log.debug("Leaving api().");
  return base + PREFIX + "/admin-api" + path;
}

async function fetchJson(url, options) {
  log.debug("Entering fetchJson(). url=" + url);
  const r = await fetch(url, Object.assign({ redirect: "manual" },
                                           options || {}));
  const text = await r.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in fetchJson(): " + ((e && e.message) || e));
    // Not JSON; the caller reports the status and the text.
    body = null;
  }
  log.debug("Leaving fetchJson(). status=" + r.status);
  return { status: r.status, body: body, text: text, headers: r.headers };
}

function get(url) {
  log.debug("Entering get().");
  log.debug("Leaving get().");
  return fetchJson(url);
}

function postJson(url, payload) {
  log.debug("Entering postJson().");
  log.debug("Leaving postJson().");
  return fetchJson(url, { method: "POST",
                          headers: { "Content-Type": "application/json" },
                          body: JSON.stringify(payload || {}) });
}

// An /admin-api call that must have worked, its refusal quoted whole.
async function must(path, payload, what) {
  log.debug("Entering must(). " + path);
  const r = await postJson(api(path), payload);
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "POST " + PREFIX + "/admin-api" + path + " should have " + what +
    "; it answered " + r.status + " " + String(r.text).slice(0, 400));
  log.debug("Leaving must().");
  return r.body;
}

async function mustRead(path, what) {
  log.debug("Entering mustRead(). " + path);
  const r = await get(api(path));
  assert.ok(r.status === 200 && r.body,
    "GET " + PREFIX + "/admin-api" + path + " (" + what + ") answered " +
    r.status + " " + String(r.text).slice(0, 300));
  log.debug("Leaving mustRead().");
  return r.body;
}

// One request with a client certificate. `fetch` in node cannot present
// one, so this is `https.request`, as `sts_authzen.js` has it.
function withCertificate(method, path, identity, payload) {
  log.debug("Entering withCertificate(). " + method + " " + path);
  log.debug("Leaving withCertificate().");
  return new Promise(function (resolve, reject) {
    const target = new URL(path.indexOf("http") === 0 ? path : base + path);
    const data = payload === undefined ? null : JSON.stringify(payload);
    const request = https.request({
      host: target.hostname, port: target.port || 443,
      path: target.pathname + target.search, method: method,
      rejectUnauthorized: false,
      cert: identity ? identity.certPem : undefined,
      key: identity ? identity.keyPem : undefined,
      headers: data ? { "Content-Type": "application/json",
                        "Content-Length": Buffer.byteLength(data) } : {}
    }, function (response) {
      let text = "";
      response.on("data", function (chunk) { text += chunk; });
      response.on("end", function () {
        let body;
        try {
          body = JSON.parse(text);
        } catch (e) {
          log.debug("Caught in a callback in withCertificate(): " +
                    ((e && e.message) || e));
          body = null;
        }
        resolve({ status: response.statusCode, body: body, text: text });
      });
    });
    request.on("error", reject);
    if (data) {
      request.write(data);
    }
    request.end();
  });
}

// An AuthZEN question about `application`: who, which action, which
// document.
function evaluate(action, application) {
  log.debug("Entering evaluate(). " + action + " " + application);
  log.debug("Leaving evaluate().");
  return withCertificate("POST", PREFIX + "/access/v1/evaluation",
    authzenCaller, {
      subject: { type: "user", id: PERSON },
      action: { name: action },
      resource: { type: "document", id: "doc-1" },
      context: { application: application } });
}

function basicAuth(identifier) {
  log.debug("Entering basicAuth().");
  log.debug("Leaving basicAuth().");
  return "Basic " + Buffer.from(encodeURIComponent(identifier) + ":" +
    encodeURIComponent(SECRETS[identifier])).toString("base64");
}

async function token(form, as) {
  log.debug("Entering token(). " + form.grant_type);
  const r = await fetchJson(base + PREFIX + "/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded",
               Authorization: basicAuth(as || CLIENT) },
    body: new URLSearchParams(form).toString() });
  log.debug("Leaving token(). " + r.status);
  return r;
}

// A detail of the type, asking for `actions`.
function detail(actions) {
  log.debug("Entering detail().");
  log.debug("Leaving detail().");
  return { type: "document_access", locations: [LOCATION],
           actions: actions, identifier: "doc-1",
           classification: "internal", note: "not for the policy" };
}

function clientCredentials(actions) {
  log.debug("Entering clientCredentials().");
  log.debug("Leaving clientCredentials().");
  return token({ grant_type: "client_credentials",
                 authorization_details: JSON.stringify([detail(actions)]) });
}

function claimsOf(jwt) {
  log.debug("Entering claimsOf().");
  const parts = String(jwt || "").split(".");
  assert.strictEqual(parts.length, 3, "not a compact JWS: " +
                     String(jwt).slice(0, 60));
  log.debug("Leaving claimsOf().");
  return JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
}

function refusedAsInvalidDetails(r) {
  log.debug("Entering refusedAsInvalidDetails().");
  log.debug("Leaving refusedAsInvalidDetails().");
  return r.status === 400 && r.body &&
         r.body.error === "invalid_authorization_details";
}

// THE AUTHORIZATION REQUEST, AS A BROWSER MAKES IT, without a browser:
// `token_exchange_chain_kit.authorizationCode()`'s walk — the request, the
// sign-in screen over `/authn-api` (development mode: the password is not
// checked), the hop back, and any consent screen answered Allow — stopping
// at the first Location that leaves the service. A refusal before consent
// is that Location, with `error` on it and no screen answered.
async function authorize(actions) {
  log.debug("Entering authorize(). " + actions.join(","));
  const agent = { "User-Agent": DESKTOP_USER_AGENT };
  const verifier = crypto.randomBytes(32).toString("base64url");
  const challenge = crypto.createHash("sha256").update(verifier)
    .digest("base64url");
  const url = base + PREFIX + "/oauth2/authorize?" + new URLSearchParams({
    response_type: "code", client_id: CLIENT, redirect_uri: REDIRECT,
    scope: "openid", state: "s-" + crypto.randomBytes(6).toString("hex"),
    code_challenge: challenge, code_challenge_method: "S256",
    authorization_details: JSON.stringify([detail(actions)]) }).toString();
  const first = await fetch(url, { redirect: "manual", headers: agent });
  const screenAt = first.headers.get("location") || "";
  assert.ok(/\/authn\/login\?authn=/.test(screenAt), "the authorization " +
    "request should reach the sign-in screen; it answered " + first.status +
    " " + screenAt + " " + String(await first.text()).slice(0, 300));
  const screenUrl = new URL(screenAt, base);
  const signedIn = await authnSignin.submit(screenUrl.origin +
    screenUrl.pathname.replace(/\/authn\/login$/, ""), screenUrl.toString(),
    { action: "login", username: PERSON, password: "Fga-" + STAMP + "-9a!" },
    { headers: agent });
  if (signedIn.next !== "redirect" || !signedIn.cookie ||
      !signedIn.location) {
    assert.fail("signing " + PERSON + " in should redirect with a session; " +
      "the screen answered " + signedIn.status + " " + signedIn.next + ": " +
      JSON.stringify(signedIn.errors));
  }
  const back = await fetch(new URL(signedIn.location, base).toString(),
    { redirect: "manual",
      headers: Object.assign({ Cookie: signedIn.cookie }, agent) });
  const after = back.headers.get("location") || "";
  const settled = await consentScreen.settleAuthorization({
    base: base, location: after, cookie: signedIn.cookie, headers: agent });
  const location = settled.location || after;
  const query = location.indexOf("?") >= 0
    ? new URLSearchParams(location.split("?")[1].split("#")[0])
    : new URLSearchParams();
  log.debug("Leaving authorize(). " + location.slice(0, 120));
  return { location: location, query: query, screens: settled.screens,
           verifier: verifier };
}

// The application's read, `page.fga` (docs/fga.md, *The console and the
// API*).
async function fgaOf(identifier) {
  log.debug("Entering fgaOf().");
  const body = await mustRead("/applications?application=" +
                              encodeURIComponent(identifier),
                              "the application's read");
  // `page` is what the console's tabs are drawn from (#446); the entry's
  // own attributes are spread beside it.
  log.debug("Leaving fgaOf().");
  return (body.page && body.page.fga) || {};
}

async function repository() {
  log.debug("Entering repository().");
  const out = await mustRead("/xacml/policies", "the repository");
  log.debug("Leaving repository().");
  return out;
}

const addedAnchors = [];
const storedHere = [];
var authzenCaller = null;
var remotePep = null;
var policyName = "";

// ===========================================================================
// 1. THE SETUP.
// ===========================================================================
async function setUp() {
  log.debug("Entering setUp().");
  log.info("=== 1. the setup ===");
  const made = await postJson(base + "/admin-api/realms/create", {
    id: REALM, domain: REALM + ".example.net",
    name: "FGA test realm",
    description: "Created by tests/protocol/sts_fga.js; LEFT IN PLACE on " +
                 "purpose, so that a failed run can be read afterwards.",
    overrides: { "global.mode": "development" } });
  assert.ok(made.status === 200 && made.body && made.body.ok !== false,
    "creating the throwaway realm " + REALM + " answered " + made.status +
    " " + String(made.text).slice(0, 300));
  await must("/users/create", { username: PERSON, invent: false,
    attributes: { cn: PERSON, sn: PERSON, givenName: "Alice",
                  mail: PERSON + "@" + REALM + ".example.net" } },
    "created " + PERSON);
  authzenCaller = await credentials.mint({
    subject: "CN=" + AUTHZEN_CALLER + ",OU=authzen,O=iya-sts tests" });
  remotePep = await credentials.mint({
    subject: "CN=" + REMOTE_PEP + ",OU=remote-peps,O=iya-sts tests" });
  for (const one of [authzenCaller, remotePep]) {
    const posted = await credentials.trustAnchor(base, one.anchorPem);
    assert.ok(posted.ok, "POST /admin-api/tls/trust/add should accept the " +
      "Root CA this file built; it answered " + posted.status);
    addedAnchors.push(one.anchorPem);
  }
  storedHere.push(await credentials.storeOnEntry({ get: get, post: postJson },
    base, PREFIX, AUTHZEN_CALLER, authzenCaller.leaf.pem));
  storedHere.push(await credentials.storeOnEntry({ get: get, post: postJson },
    base, PREFIX, REMOTE_PEP, remotePep.leaf.pem));
  await must("/groups/add-member",
             { group: "authzen-peps", member: AUTHZEN_CALLER },
             "put the AuthZEN caller in authzen-peps");
  await must("/groups/add-member",
             { group: "remote-peps", member: REMOTE_PEP },
             "put the remote PEP in remote-peps");
  await must("/xacml/authzen/set-scope",
             { caller: AUTHZEN_CALLER, applications: [DOCS, OTHER] },
             "scoped the AuthZEN caller to both applications");
  await must("/xacml/import-alfa", { name: "fga-root", alfa: ROOT_POLICY },
             "imported the root");
  await must("/xacml/set-root", { name: "fga-root" },
             "made it the root");
  log.debug("Leaving setUp().");
}

// ===========================================================================
// 2. THE DEFAULT POLICY.
// ===========================================================================
async function theDefaultPolicy() {
  log.debug("Entering theDefaultPolicy().");
  log.info("=== 2. a new application gets its default policy ===");
  for (const one of [DOCS, CLIENT, OTHER]) {
    const fields = { oauthClientId: one };
    if (one === CLIENT) {
      fields.oauthRedirectUri = [REDIRECT];
      fields.oauthTokenEndpointAuthMethod = ["client_secret_basic"];
    }
    await must("/applications/create",
               { identifier: one, protocols: ["oauth2", "oidc"],
                 fields: fields }, "created " + one);
    if (one !== OTHER) {
      SECRETS[one] = crypto.randomBytes(48).toString("base64url");
      await must("/applications/set", { application: one,
        attribute: "oauthClientSecret", value: SECRETS[one] },
        "set " + one + "'s client secret");
    }
  }
  const fga = await fgaOf(DOCS);
  const policy = fga.policy || {};
  policyName = String(policy.name || "");
  check("the new application has its own enabled policy, not enforced",
        function () {
    assert.ok(/^fga-/.test(policyName) && policy.own === true &&
              policy.enabled === true && fga.enforced === false &&
              /^urn:sts:xacml:fga:/.test(String(policy.policyId)),
      "page.fga is " + JSON.stringify(fga).slice(0, 500));
  });
  const repo = await repository();
  const row = (repo.policies || []).filter(function (one) {
    return one.name === policyName;
  })[0] || {};
  check("the repository lists it with its owner, and the root is not it",
        function () {
    assert.ok(row.application === DOCS && !row.isRoot &&
              repo.root === "fga-root",
      "root " + repo.root + "; row " + JSON.stringify(row));
  });
  const rooted = await postJson(api("/xacml/set-root"), { name: policyName });
  check("an application's policy cannot be made the root", function () {
    assert.ok(rooted.status !== 200 || (rooted.body &&
                                        rooted.body.ok === false),
      "set-root answered " + rooted.status + " " + rooted.text);
  });
  const pulled = await withCertificate("GET", PREFIX + "/xacml/pep/policies",
                                       remotePep);
  check("the remote PEP's pull withholds it by name", function () {
    assert.ok(pulled.status === 200 && pulled.body &&
              (pulled.body.withheld || []).indexOf(policyName) >= 0 &&
              !(pulled.body.policies || []).some(function (one) {
                return one.name === policyName;
              }),
      "the pull answered " + pulled.status + " " +
      String(pulled.text).slice(0, 400));
  });
  log.debug("Leaving theDefaultPolicy().");
}

// ===========================================================================
// 3. THE TYPE AND THE SWITCH.
// ===========================================================================
async function theTypeAndTheSwitch() {
  log.debug("Entering theTypeAndTheSwitch().");
  log.info("=== 3. the type, FGA off, and the switch ===");
  await must("/applications/set-access-type", DOCUMENT_ACCESS,
             "declared document_access with its xacml row");
  let r = await clientCredentials(["read", "delete"]);
  check("FGA off: a detail asking to delete is issued as before",
        function () {
    assert.ok(r.status === 200 && r.body &&
              Array.isArray(r.body.authorization_details),
      "answered " + r.status + " " + String(r.text).slice(0, 300));
  });
  r = await evaluate("delete", DOCS);
  check("FGA off: AuthZEN about the application is the root's (true)",
        function () {
    assert.ok(r.status === 200 && r.body && r.body.decision === true,
      "answered " + r.status + " " + r.text);
  });
  r = await postJson(api("/applications/fga-enable"), { application: DOCS });
  check("enabling is refused while `note` is uncovered, and names it",
        function () {
    assert.ok((r.status !== 200 || (r.body && r.body.ok === false)) &&
              /\bnote\b/.test(r.text),
      "fga-enable answered " + r.status + " " + String(r.text).slice(0, 400));
  });
  const stillOff = (await fgaOf(DOCS)).enforced;
  check("and the refused switch is still off", function () {
    assert.strictEqual(stillOff, false, "a refused enable switched FGA on");
  });
  await must("/applications/set-not-for-policy",
             { application: DOCS, type: "document_access",
               notForPolicy: ["note"] }, "listed note as not for the policy");
  const on = await must("/applications/fga-enable", { application: DOCS },
                        "enabled FGA once every member is covered");
  check("enabling is accepted once covered", function () {
    assert.ok(on.enforced === true, JSON.stringify(on));
  });
  log.debug("Leaving theTypeAndTheSwitch().");
}

// ===========================================================================
// 4. THE DEFAULT POLICY DECIDES.
// ===========================================================================
async function theDefaultPolicyDecides() {
  log.debug("Entering theDefaultPolicyDecides().");
  log.info("=== 4. the default policy permits ===");
  const r = await clientCredentials(["read", "delete"]);
  check("the default policy permits: client_credentials is issued",
        function () {
    assert.ok(r.status === 200 && r.body && r.body.access_token,
      "answered " + r.status + " " + String(r.text).slice(0, 300));
  });
  const granted = (r.body.authorization_details || [])[0] || {};
  check("the token response carries the detail", function () {
    assert.ok(granted.type === "document_access" &&
              (granted.actions || []).indexOf("delete") >= 0,
      JSON.stringify(r.body.authorization_details));
  });
  const claims = claimsOf(r.body.access_token);
  check("the access token carries it", function () {
    assert.ok(Array.isArray(claims.authorization_details) &&
              claims.authorization_details[0].type === "document_access",
      JSON.stringify(claims).slice(0, 400));
  });
  const seen = await fetchJson(base + PREFIX + "/oauth2/introspect", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded",
               Authorization: basicAuth(DOCS) },
    body: "token=" + encodeURIComponent(r.body.access_token) +
          "&token_type_hint=access_token" });
  check("introspection by the type's owner carries it", function () {
    assert.ok(seen.status === 200 && seen.body && seen.body.active === true &&
              Array.isArray(seen.body.authorization_details) &&
              seen.body.authorization_details[0].type === "document_access",
      "answered " + seen.status + " " + String(seen.text).slice(0, 400));
  });
  log.debug("Leaving theDefaultPolicyDecides().");
}

// ===========================================================================
// 5. A CUSTOM POLICY DENYING DELETE, WRITTEN IN ALFA THROUGH /admin-api.
//
// `import-alfa` under the policy's own entry name REPLACES its document;
// the store keeps the owner (`xacmlApplication`) and it is not made the
// root, because the realm has one.
// ===========================================================================
async function aPolicyDenyingDelete() {
  log.debug("Entering aPolicyDenyingDelete().");
  log.info("=== 5. a custom policy denying delete ===");
  await must("/xacml/import-alfa", { name: policyName, alfa: NO_DELETE },
             "replaced the application's policy with one denying delete");
  const still = (await fgaOf(DOCS)).policy || {};
  check("the rewritten policy is still the application's own", function () {
    assert.ok(still.name === policyName && still.own === true &&
              still.enabled === true, JSON.stringify(still));
  });
  let r = await clientCredentials(["delete"]);
  check("the token endpoint refuses delete invalid_authorization_details",
        function () {
    assert.ok(refusedAsInvalidDetails(r),
      "answered " + r.status + " " + String(r.text).slice(0, 300));
  });
  r = await clientCredentials(["read"]);
  check("and grants read", function () {
    assert.ok(r.status === 200 && r.body && r.body.access_token,
      "answered " + r.status + " " + String(r.text).slice(0, 300));
  });
  const refused = await authorize(["read", "delete"]);
  check("the authorization endpoint redirects access_denied, before consent",
        function () {
    assert.ok(refused.location.indexOf(REDIRECT) === 0 &&
              refused.query.get("error") === "access_denied" &&
              !refused.query.get("code") && refused.screens === 0,
      "the flow ended at " + refused.location + " after " + refused.screens +
      " consent screen(s)");
  });
  log.debug("Leaving aPolicyDenyingDelete().");
}

// ===========================================================================
// 6. A CODE FOR READ, AND THE EXCHANGE'S BOUND.
// ===========================================================================
async function aCodeAndTheExchange() {
  log.debug("Entering aCodeAndTheExchange().");
  log.info("=== 6. a code for read, and the token exchange's bound ===");
  const flow = await authorize(["read"]);
  check("the authorization endpoint issues a code for read", function () {
    assert.ok(flow.location.indexOf(REDIRECT) === 0 &&
              !!flow.query.get("code"),
      "the flow ended at " + flow.location);
  });
  const r = await token({ grant_type: "authorization_code",
                          code: flow.query.get("code"),
                          redirect_uri: REDIRECT,
                          code_verifier: flow.verifier });
  check("the code is redeemed with a refresh token", function () {
    assert.ok(r.status === 200 && r.body && r.body.access_token &&
              r.body.refresh_token,
      "answered " + r.status + " " + String(r.text).slice(0, 300));
  });
  const exchange = function (actions) {
    log.debug("Entering exchange().");
    log.debug("Leaving exchange().");
    return token({
      grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
      subject_token: r.body.access_token,
      subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
      authorization_details: JSON.stringify([detail(actions)]) });
  };
  let x = await exchange(["read"]);
  check("an exchange for a detail the subject_token carries is granted",
        function () {
    assert.ok(x.status === 200 && x.body && x.body.access_token,
      "answered " + x.status + " " + String(x.text).slice(0, 300));
  });
  x = await exchange(["read", "update"]);
  check("one asking for more than the subject_token carries is refused",
        function () {
    assert.ok(refusedAsInvalidDetails(x),
      "answered " + x.status + " " + String(x.text).slice(0, 300));
  });
  log.debug("Leaving aCodeAndTheExchange().");
  return r.body.refresh_token;
}

// ===========================================================================
// 7. AUTHZEN.
// ===========================================================================
async function atAccessTime() {
  log.debug("Entering atAccessTime().");
  log.info("=== 7. AuthZEN decides against the application's policy ===");
  let r = await evaluate("delete", DOCS);
  check("delete is false, though the root permits it", function () {
    assert.ok(r.status === 200 && r.body && r.body.decision === false,
      "answered " + r.status + " " + r.text);
  });
  r = await evaluate("read", DOCS);
  check("read is true", function () {
    assert.ok(r.status === 200 && r.body && r.body.decision === true,
      "answered " + r.status + " " + r.text);
  });
  r = await evaluate("delete", OTHER);
  check("an application without FGA is still decided by the root (true)",
        function () {
    assert.ok(r.status === 200 && r.body && r.body.decision === true,
      "answered " + r.status + " " + r.text);
  });
  log.debug("Leaving atAccessTime().");
}

// ===========================================================================
// 8. A REFRESH AFTER THE POLICY CHANGES.
// ===========================================================================
async function aRefreshAfterTheChange(refreshToken) {
  log.debug("Entering aRefreshAfterTheChange().");
  log.info("=== 8. a refresh after the policy changes ===");
  await must("/xacml/import-alfa", { name: policyName, alfa: NO_READ },
             "replaced the policy with one denying read");
  const r = await token({ grant_type: "refresh_token",
                          refresh_token: refreshToken });
  check("the refresh is decided against the current policy, and refused",
        function () {
    assert.ok(refusedAsInvalidDetails(r),
      "answered " + r.status + " " + String(r.text).slice(0, 300));
  });
  await must("/xacml/import-alfa", { name: policyName, alfa: NO_DELETE },
             "put the policy denying delete back");
  log.debug("Leaving aRefreshAfterTheChange().");
}

// ===========================================================================
// 9. A DISABLED POLICY.
// ===========================================================================
async function aDisabledPolicy() {
  log.debug("Entering aDisabledPolicy().");
  log.info("=== 9. a disabled policy is an error, never a decision ===");
  await must("/xacml/disable", { name: policyName },
             "disabled the application's policy");
  let r = await evaluate("read", DOCS);
  check("AuthZEN answers 500, never false and never the root's", function () {
    assert.ok(r.status === 500 && !(r.body && r.body.decision !== undefined),
      "answered " + r.status + " " + r.text);
  });
  r = await clientCredentials(["read"]);
  check("the token endpoint answers server_error", function () {
    assert.ok(r.status === 500 && r.body && r.body.error === "server_error",
      "answered " + r.status + " " + String(r.text).slice(0, 300));
  });
  await must("/xacml/enable", { name: policyName },
             "enabled the application's policy again");
  log.debug("Leaving aDisabledPolicy().");
}

// ===========================================================================
// 10. FGA OFF AGAIN.
// ===========================================================================
async function offAgain() {
  log.debug("Entering offAgain().");
  log.info("=== 10. disabling FGA restores the old behaviour ===");
  const off = await must("/applications/fga-disable", { application: DOCS },
                         "stopped enforcing");
  check("the switch is off and the policy is kept", function () {
    assert.ok(off.enforced === false, JSON.stringify(off));
  });
  let r = await clientCredentials(["delete"]);
  check("delete is issued again", function () {
    assert.ok(r.status === 200 && r.body && r.body.access_token,
      "answered " + r.status + " " + String(r.text).slice(0, 300));
  });
  r = await evaluate("delete", DOCS);
  check("and AuthZEN about the application is the root's again", function () {
    assert.ok(r.status === 200 && r.body && r.body.decision === true,
      "answered " + r.status + " " + r.text);
  });
  log.debug("Leaving offAgain().");
}

// ===========================================================================
// 11. DELETING THE APPLICATION.
// ===========================================================================
async function theOrphan() {
  log.debug("Entering theOrphan().");
  log.info("=== 11. deleting the application leaves an orphan ===");
  let r = await postJson(api("/xacml/delete"), { name: policyName });
  check("the policy an application names is not deleted", function () {
    assert.ok(r.status !== 200 || (r.body && r.body.ok === false),
      "answered " + r.status + " " + r.text);
  });
  await must("/applications/forget", { application: DOCS },
             "deleted the resource application");
  const repo = await repository();
  const group = (repo.applicationPolicies || []).filter(function (one) {
    return one.application === DOCS;
  })[0] || { policies: [] };
  const orphan = group.policies[0] || {};
  check("its policy is kept, disabled and orphaned", function () {
    assert.ok(group.policies.length === 1 && orphan.name === policyName &&
              orphan.enabled === false && !!orphan.orphanedAt &&
              orphan.referenced === false,
      JSON.stringify(repo.applicationPolicies));
  });
  await must("/xacml/delete", { name: policyName }, "removed the orphan");
  const after = await repository();
  check("and an administrator removes it", function () {
    assert.ok(!(after.policies || []).some(function (one) {
      return one.name === policyName;
    }), JSON.stringify((after.policies || []).map(function (one) {
      return one.name;
    })));
  });
  log.debug("Leaving theOrphan().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving IYA STS's fine-grained authorization at " + base +
           PREFIX);
  const status = await fetchJson(base + "/admin-api/status");
  assert.strictEqual(status.status, 200,
    "GET /admin-api/status answered " + status.status + " at " + base);
  await setUp();
  await theDefaultPolicy();
  await theTypeAndTheSwitch();
  await theDefaultPolicyDecides();
  await aPolicyDenyingDelete();
  const refreshToken = await aCodeAndTheExchange();
  await atAccessTime();
  await aRefreshAfterTheChange(refreshToken);
  await aDisabledPolicy();
  await offAgain();
  await theOrphan();
  assert.ok(checks >= 33,
    "only " + checks + " checks ran; a section stopped being called.");
  log.info(checks + " checks passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_fga")
  .description("Drive IYA STS's application-scoped fine-grained " +
      "authorization over HTTP in a throwaway trust realm: the default " +
      "policy, the switch, issuance at the token and authorization " +
      "endpoints, the exchange bound, refresh, AuthZEN, and the orphan.")
  .addOption(new Option("-u, --url <url>", "base url of the STS under test")
      .default(base))
  .parse(process.argv);
base = String(program.opts().url || base).replace(/\/+$/, "");

function forgetTheStored() {
  log.debug("Entering forgetTheStored().");
  log.debug("Leaving forgetTheStored().");
  return credentials.forgetStored({ get: get, post: postJson }, base,
                                  storedHere);
}

test().then(function () {
  return forgetTheStored().then(function () {
    return credentials.settleAnchors(base, addedAnchors, null);
  });
}, function (e) {
  log.debug("Caught in test(): " + ((e && e.message) || e));
  return forgetTheStored().then(function () {
    return credentials.settleAnchors(base, addedAnchors, e);
  });
}).catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
