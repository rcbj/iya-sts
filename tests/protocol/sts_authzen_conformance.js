// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_authzen_conformance.js
//
// ---------------------------------------------------------------------------
// THE OPENID FOUNDATION'S CONFORMANCE SUITE: AUTHZEN PDP (#936). The six
// certification plans, the discovery plan when release-v5.3.1 contains it,
// one static-metadata evaluation, and one api_key evaluation. The suite is
// the PEP. This service is the PDP, in a throwaway realm whose catalogue
// and root policy this file wrote. No browser.
//
//   eval, evals, evals-comp, search-subject, search-resource, search-action
//     pdp_auth_type=mtls, pdp_server_metadata=discovery,
//     authzen_support=properties, on the mutual-TLS realm.
//   discovery
//     authzen-pdp-discovery-test-plan, no variant. The same realm. A 404,
//     or any other status whose body says the plan is unknown and does not
//     reject a variant key, skips this plan only. Any other body fails the
//     job. The image is not bumped.
//   eval-static
//     the evaluation plan with pdp_server_metadata=static.
//   eval-apikey
//     the evaluation plan with pdp_auth_type=api_key, on a second realm
//     whose door is bearer. The token is minted immediately before that
//     plan, and only when the plan is selected.
//
// The mutual-TLS caller is a person, az-pep, holding a certificate from
// tests/tools/pep-credential.js, stored on the entry and placed in
// authzen-peps, scoped to the one application "records". The bearer caller
// is the registered application itself: its group member is the entry DN,
// and its only application name is its own client id. alice and bob are
// the subject ids the policy names.
//
// NO CLASSICAL TWIN IN THIS FILE. signed_metadata stays on (RS256).
// pdp.jwks is the one public JWK whose kid matches that JWT, with no alg
// filter, so the realm's post-quantum keys are not what the suite is
// given. oauth2.signedMetadataCertificateHeader stays x5u until a result
// names x5u or /pki/chain; this file then sets it to none on the throwaway
// realm and runs the selected plans once more. Twins are added only after
// that re-run still names AKP, OKP, an unknown key type, or
// WarnOnUnusableJwksKeys. This file does not call withClassicalTwins.
//
// THE LEDGERS START EMPTY. Resource search of type record
// (RESOURCE_TYPES) and a closed request that refuses an unknown member
// (STS-AUTHZEN-0009) are permanent differences, ledgered from the printed
// module id after a run. They are not written here in advance, and a line
// for either is not a certification claim. A wrong fixture decision, a
// missing alice or bob, a missing read or write, a batch-order failure,
// an authentication failure, and a Content-Type the suite will not accept
// as a ledger line are fixed, not ledgered.
//
// release-v5.3.1's mtls variant never reaches the PDP, and current
// master has the same order. setupMtls() installs
// SupportMTLSEndpointAliases. AbstractAuthzenPDPTest.configure calls
// that sequence, then env.mapKey("server", "pdp"). The sequence's one
// condition, AddMTLSEndpointAliasesToEnvironment, is
// @PreEnvironment(required = "server") and throws before evaluate.
// GetPDPDynamicServerConfiguration stores the fetched metadata as
// "pdp". configure() stores the published JSON as "config" and does
// not copy a top-level "server" member into the environment, so this
// file cannot satisfy the check by adding one. Later conditions read
// the endpoint from the "pdp" object, so the alias step is not what
// places the URL. It only aborts configuration. That failure is not a
// ledger line. The manifest row stays out until a suite that maps
// "server" onto "pdp" before the sequence can be run. This file does
// not bump the image.
//
// OWNED HERE (local: true). sts_authzen.js stays the Todo job.
// ---------------------------------------------------------------------------

const assert = require("assert");
const crypto = require("crypto");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const credentials = require("../tools/pep-credential.js");
const oidf = require("./conformance_suite.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE. A hand run without one still
  // loads, and the line below says the configuration is empty.
  appconfigProblem = e;
  appconfig = {};
}
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_authzen_conformance",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var root = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const TAG = names.runStamp().toLowerCase().replace(/[^a-z0-9]/g, "")
  .slice(-10);
const DISCOVERY_NAME = "authzen-pdp-discovery-test-plan";
const PEP = "az-pep";
const APPLICATION = "records";
const POLICY_NAME = "authzen-certification";

const MTLS_VARIANT = {
  pdp_auth_type: "mtls",
  pdp_server_metadata: "discovery",
  authzen_support: "properties"
};
const PLANS = [
  { key: "eval", name: "authzen-pdp-evaluation-test-plan",
    door: "mtls", variant: MTLS_VARIANT },
  { key: "evals", name: "authzen-pdp-evaluations-test-plan",
    door: "mtls", variant: MTLS_VARIANT },
  { key: "evals-comp",
    name: "authzen-pdp-evaluations-comprehensive-test-plan",
    door: "mtls", variant: MTLS_VARIANT },
  { key: "search-subject", name: "authzen-pdp-subject-search-test-plan",
    door: "mtls", variant: MTLS_VARIANT },
  { key: "search-resource", name: "authzen-pdp-resource-search-test-plan",
    door: "mtls", variant: MTLS_VARIANT },
  { key: "search-action", name: "authzen-pdp-action-search-test-plan",
    door: "mtls", variant: MTLS_VARIANT },
  { key: "discovery", name: DISCOVERY_NAME, door: "mtls",
    discovery: true, variant: null },
  { key: "eval-static", name: "authzen-pdp-evaluation-test-plan",
    door: "mtls", staticMetadata: true,
    variant: { pdp_auth_type: "mtls", pdp_server_metadata: "static",
               authzen_support: "properties" } },
  { key: "eval-apikey", name: "authzen-pdp-evaluation-test-plan",
    door: "bearer", apiKey: true,
    variant: { pdp_auth_type: "api_key", pdp_server_metadata: "discovery",
               authzen_support: "properties" } }
];

// The variant keys a discovery rejection is about. A value counts only
// when the body is also rejecting something, and not when the value is
// only the plan's own name.
const VARIANT_KEYS = ["pdp_auth_type", "pdp_server_metadata",
                      "authzen_support"];
const VARIANT_VALUES = ["none", "client_secret_basic", "api_key", "mtls",
                        "discovery", "static", "core", "properties"];
const REJECTION = /reject|invalid|unrecognized|unrecognised|unexpected|not a valid|not supported|unknown variant|not allowed/i;

const STATIC_ENDPOINTS = ["access_evaluation_endpoint",
                          "access_evaluations_endpoint",
                          "search_subject_endpoint",
                          "search_resource_endpoint",
                          "search_action_endpoint"];
const PRIVATE_JWK = { d: true, p: true, q: true, dp: true, dq: true,
                      qi: true, k: true };

// Nine rows. The policy reads role, status, and soft. The other six are
// what the scenario sends and must not change a decision. foo and
// futureField are not rows: they are unknown request members.
const CATALOGUE = [
  { object: "subject", property: "role",
    attributeId: "urn:example:authzen:cert:role" },
  { object: "resource", property: "status",
    attributeId: "urn:example:authzen:cert:status" },
  { object: "action", property: "soft", dataType: "boolean",
    attributeId: "urn:example:authzen:cert:soft" },
  { object: "context", property: "time",
    attributeId: "urn:example:authzen:cert:time" },
  { object: "context", property: "ip",
    attributeId: "urn:example:authzen:cert:ip" },
  { object: "context", property: "source",
    attributeId: "urn:example:authzen:cert:source" },
  { object: "subject", property: "department",
    attributeId: "urn:example:authzen:cert:department" },
  { object: "action", property: "method",
    attributeId: "urn:example:authzen:cert:method" },
  { object: "resource", property: "owner",
    attributeId: "urn:example:authzen:cert:owner" }
];

// targetClause() does not group. A parenthesised `or` is an expression,
// and a match term compares one attribute with one literal. Two clauses
// are ANDed, which is (read of record-1) AND (alice OR bob). Writing the
// `or` in the same clause as the `and`s would permit bob for every
// request, because `and` binds tighter than `or`.
const CERT_POLICY = [
  "namespace cert {",
  "  attribute act { category = actionCat",
  "    id = \"urn:oasis:names:tc:xacml:1.0:action:action-id\"",
  "    type = string }",
  "  attribute protocol { category = environmentCat",
  "    id = \"urn:sts:xacml:protocol\" type = string }",
  "  attribute subjectId { category = subjectCat",
  "    id = \"urn:oasis:names:tc:xacml:1.0:subject:subject-id\"",
  "    type = string }",
  "  attribute resourceId { category = resourceCat",
  "    id = \"urn:oasis:names:tc:xacml:1.0:resource:resource-id\"",
  "    type = string }",
  "  attribute role { category = subjectCat",
  "    id = \"urn:example:authzen:cert:role\" type = string }",
  "  attribute status { category = resourceCat",
  "    id = \"urn:example:authzen:cert:status\" type = string }",
  "  attribute soft { category = actionCat",
  "    id = \"urn:example:authzen:cert:soft\" type = boolean }",
  "  policy certRoot {",
  "    id = \"urn:test:authzen-certification\"",
  "    apply firstApplicable",
  "    target clause protocol == \"authzen\"",
  "    rule readRecord1 {",
  "      permit",
  "      target clause act == \"read\" and resourceId == \"record-1\"",
  "      target clause subjectId == \"alice\" or subjectId == \"bob\"",
  "    }",
  "    rule aliceWriteRecord1 {",
  "      permit",
  "      target clause act == \"write\" and resourceId == \"record-1\" and",
  "        subjectId == \"alice\"",
  "    }",
  "    rule bobAdminWriteArchived {",
  "      permit",
  "      target clause act == \"write\" and resourceId == \"record-2\" and",
  "        subjectId == \"bob\" and role == \"admin\" and",
  "        status == \"archived\"",
  "    }",
  "    rule aliceSoftDelete {",
  "      permit",
  "      target clause act == \"delete\" and resourceId == \"record-1\" and",
  "        subjectId == \"alice\" and soft == true",
  "    }",
  "  }",
  "}"
].join("\n");

// A module the suite judged FAILED, argued (none yet: filled from a run).
const EXPECTED = {};
// Conditions whose WARNING is kept, and why (none yet).
const KNOWN_WARNINGS = {};
// Conditions whose FAILURE is argued (none yet).
const KNOWN_FAILURES = {};

const addedAnchors = [];
let checks = 0;
let headerCleared = false;

function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function freshPassword() {
  log.debug("Entering freshPassword().");
  const out = crypto.randomBytes(18).toString("base64url");
  log.debug("Leaving freshPassword().");
  return out;
}

function redact(text) {
  log.debug("Entering redact().");
  let out = String(text || "");
  out = out.replace(
    /-----BEGIN [A-Z0-9 ]+-----[\s\S]*?-----END [A-Z0-9 ]+-----/g,
    "[redacted pem]");
  out = out.replace(
    /-----BEGIN [A-Z0-9 ]+-----(?:\\n|\\r\\n)[\s\S]*?-----END [A-Z0-9 ]+-----/g,
    "[redacted pem]");
  out = out.replace(/"(client_secret|access_token)"\s*:\s*"[^"]*"/g,
                    '"$1":"[redacted]"');
  out = out.replace(/("(?:key|cert|ca|api_key)"\s*:\s*")[^"]{40,}/g,
                    '$1[redacted]');
  log.debug("Leaving redact().");
  return out;
}

function saysUnknownPlan(body) {
  log.debug("Entering saysUnknownPlan().");
  const text = String(body || "").toLowerCase();
  const unknown = /unknown[\s\S]{0,80}plan/.test(text) ||
    /plan[\s\S]{0,40}unknown/.test(text) ||
    /does not exist/.test(text) ||
    /no such plan/.test(text) ||
    /there is no plan/.test(text) ||
    /no plan (with|named|called)/.test(text) ||
    /plan[\s\S]{0,40}not found/.test(text);
  log.debug("Leaving saysUnknownPlan(). " + unknown);
  return unknown;
}

function rejectsVariant(body) {
  log.debug("Entering rejectsVariant().");
  let text = String(body || "");
  text = text.split(DISCOVERY_NAME).join(" ");
  text = text.replace(/mtls\.(cert|key|ca)/gi, " ");
  text = text.replace(/configuration\.mtls/gi, " ");
  text = text.replace(/client\.api_key/gi, " ");
  const lower = text.toLowerCase();
  let hit = false;
  if (REJECTION.test(lower)) {
    hit = VARIANT_KEYS.some(function (key) {
      return lower.indexOf(key) >= 0;
    });
    if (!hit) {
      hit = VARIANT_VALUES.some(function (value) {
        return new RegExp("\\b" + value + "\\b").test(lower);
      });
    }
  }
  log.debug("Leaving rejectsVariant(). " + hit);
  return hit;
}

function planIsMissing(status, raw) {
  log.debug("Entering planIsMissing().");
  if (status === 404) {
    log.debug("Leaving planIsMissing(). A 404.");
    return true;
  }
  const missing = saysUnknownPlan(raw) && !rejectsVariant(raw);
  log.debug("Leaving planIsMissing(). " + missing);
  return missing;
}

function sawCertificateFetch(lines) {
  log.debug("Entering sawCertificateFetch().");
  const saw = (lines || []).some(function (line) {
    return /x5u|\/pki\/chain/.test(String(line));
  });
  log.debug("Leaving sawCertificateFetch(). " + saw);
  return saw;
}

function wants(door) {
  log.debug("Entering wants(). " + door);
  const yes = PLANS.some(function (plan) {
    return plan.door === door && oidf.selected(plan.key);
  });
  log.debug("Leaving wants(). " + yes);
  return yes;
}

function realmId(kind) {
  log.debug("Entering realmId().");
  const id = ("az-" + kind + "-" + TAG).slice(0, 39).replace(/-+$/, "");
  log.debug("Leaving realmId(). " + id);
  return id;
}

function adminVerbs() {
  log.debug("Entering adminVerbs().");
  async function get(url) {
    log.debug("Entering get().");
    const r = await oidf.send(url);
    log.debug("Leaving get(). " + r.status);
    return { status: r.status, body: r.body, text: r.raw };
  }

  async function post(url, payload) {
    log.debug("Entering post().");
    const r = await oidf.send(url, { method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload || {}) });
    log.debug("Leaving post(). " + r.status);
    return { status: r.status, body: r.body, text: r.raw };
  }

  log.debug("Leaving adminVerbs().");
  return { get: get, post: post };
}

async function installCatalogue(api) {
  log.debug("Entering installCatalogue().");
  for (let i = 0; i < CATALOGUE.length; i++) {
    const row = CATALOGUE[i];
    await oidf.ok(api + "/xacml/authzen/set-attribute", row,
      "declared " + row.object + "." + row.property);
  }
  log.debug("Leaving installCatalogue().");
}

async function installPolicy(api) {
  log.debug("Entering installPolicy().");
  await oidf.ok(api + "/xacml/import-alfa",
    { name: POLICY_NAME, alfa: CERT_POLICY },
    "imported the certification policy");
  await oidf.ok(api + "/xacml/set-root", { name: POLICY_NAME },
    "made the certification policy the root");
  log.debug("Leaving installPolicy().");
}

async function addPeople(api, usernames) {
  log.debug("Entering addPeople().");
  for (let i = 0; i < usernames.length; i++) {
    const name = usernames[i];
    // Development seeds alice, bob, carol and sensitive into every realm
    // (ldap/ldap_server.js seed()). Those entries are the subject ids the
    // policy names. Creating them again is a 400, and the suite never
    // signs in as them, so the seeded entry is the one that stays.
    const r = await oidf.send(api + "/users/create", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: name, invent: false, credential: "password",
        password: freshPassword(),
        attributes: {
          cn: "Conformance " + name, givenName: "Conformance",
          sn: name, mail: name + "@conformance.test" } }) });
    const already = r.status === 400 &&
      /already a user called/.test(String(r.raw || ""));
    if (already) {
      log.info(name + " is already in this realm, so the seeded entry " +
               "stays.");
      continue;
    }
    if (r.status !== 200 || !r.body || r.body.ok === false) {
      log.debug("Leaving addPeople(). " + name + " " + r.status);
      throw new Error("creating " + name + " answered " + r.status + " " +
                      redact(String(r.raw || "")).slice(0, 400));
    }
  }
  log.debug("Leaving addPeople().");
}

async function prepareMtls() {
  log.debug("Entering prepareMtls().");
  const realm = await oidf.makeRealm(root, realmId("mtls"),
    "AuthZEN conformance mutual TLS", [
      ["authzen.callerAuthentication", "mtls"],
      ["authzen.accessRequests", false],
      ["authzen.obligationsProfile", false]]);
  await addPeople(realm.api, [PEP, "alice", "bob"]);
  const minted = await credentials.mint({
    subject: "CN=" + PEP + ",OU=authzen,O=iya-sts tests" });
  const posted = await credentials.trustRecorded(root, minted.anchorPem,
                                                 addedAnchors);
  assert.ok(posted.ok, "the PEP anchor was not trusted (" +
            (posted.status || "no status") + ")");
  await credentials.storeOnEntry(adminVerbs(), root, "/realm/" + realm.id,
                                PEP, minted.leaf.pem);
  await oidf.ok(realm.api + "/groups/add-member",
    { group: "authzen-peps", member: PEP },
    "put " + PEP + " in authzen-peps");
  await oidf.ok(realm.api + "/xacml/authzen/set-scope",
    { caller: PEP, applications: [APPLICATION] },
    "scoped " + PEP + " to " + APPLICATION);
  await installCatalogue(realm.api);
  await installPolicy(realm.api);
  log.info("Prepared " + realm.id + " for mutual TLS.");
  log.debug("Leaving prepareMtls().");
  return { realm: realm, certPem: minted.certPem, keyPem: minted.keyPem,
           anchorPem: minted.anchorPem };
}

async function prepareBearer() {
  log.debug("Entering prepareBearer().");
  const realm = await oidf.makeRealm(root, realmId("bearer"),
    "AuthZEN conformance bearer", [
      ["authzen.callerAuthentication", "bearer"],
      ["authzen.accessRequests", false],
      ["authzen.obligationsProfile", false],
      ["oauth2.accessTokenTtlS", 7200]]);
  await addPeople(realm.api, ["alice", "bob"]);
  await installCatalogue(realm.api);
  await installPolicy(realm.api);
  log.info("Prepared " + realm.id + " for a bearer api_key.");
  log.debug("Leaving prepareBearer().");
  return { realm: realm };
}

async function mintToken(realm) {
  log.debug("Entering mintToken(). " + realm.id);
  const registered = await oidf.send(realm.base + "/oauth2/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      grant_types: ["client_credentials"],
      token_endpoint_auth_method: "client_secret_basic",
      client_name: "AuthZEN conformance PEP" }) });
  assert.strictEqual(registered.status, 201,
    "registration answered " + registered.status);
  const clientId = registered.body && registered.body.client_id;
  const secret = registered.body && registered.body.client_secret;
  assert.ok(clientId && secret, "registration returned no client");
  await oidf.ok(realm.api + "/applications/add", {
    application: clientId, attribute: "oauthAllowedScope",
    value: "authzen:evaluate" }, "declared authzen:evaluate");
  const viewed = await oidf.send(realm.api + "/applications?application=" +
                                 encodeURIComponent(clientId));
  const body = viewed.body || {};
  const dn = body.dn || (body.application && body.application.dn);
  if (viewed.status !== 200 || !dn) {
    log.debug("Leaving mintToken(). No dn.");
    throw new Error("application " + clientId + " answered " +
                    viewed.status + " with no dn");
  }
  await oidf.ok(realm.api + "/groups/add-member",
    { group: "authzen-peps", member: dn },
    "put the application in authzen-peps");
  const basic = Buffer.from(clientId + ":" + secret).toString("base64");
  const token = await oidf.send(realm.base + "/oauth2/token", {
    method: "POST",
    headers: { Authorization: "Basic " + basic,
               "Content-Type": "application/x-www-form-urlencoded" },
    body: "grant_type=client_credentials&scope=" +
          encodeURIComponent("authzen:evaluate") + "&resource=" +
          encodeURIComponent(realm.base + "/access/v1") });
  assert.strictEqual(token.status, 200,
    "the access token answered " + token.status);
  const access = token.body && token.body.access_token;
  if (!access) {
    log.debug("Leaving mintToken(). No access token.");
    throw new Error("the token response has no access_token");
  }
  log.info("Minted an authzen:evaluate token for " + realm.id + ".");
  log.debug("Leaving mintToken().");
  return access;
}

async function readMetadata(realm) {
  log.debug("Entering readMetadata(). " + realm.id);
  const url = root + "/.well-known/authzen-configuration/realm/" + realm.id;
  const r = await oidf.send(url);
  if (r.status !== 200 || !r.body || !r.body.policy_decision_point) {
    log.debug("Leaving readMetadata(). " + r.status);
    throw new Error("AuthZEN metadata for " + realm.id + " answered " +
                    r.status);
  }
  if (!r.body.signed_metadata) {
    log.debug("Leaving readMetadata(). No signed_metadata.");
    throw new Error("signed_metadata was omitted for " + realm.id);
  }
  log.debug("Leaving readMetadata().");
  return r.body;
}

function jwtKid(token) {
  log.debug("Entering jwtKid().");
  const part = String(token || "").split(".")[0];
  let header = {};
  try {
    header = JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
  } catch (e) {
    log.debug("Caught in jwtKid(): " + ((e && e.message) || e));
    log.debug("Leaving jwtKid(). Not a JWT.");
    throw new Error("signed_metadata is not a JWT");
  }
  log.debug("Leaving jwtKid().");
  return header.kid ? String(header.kid) : "";
}

function publicJwk(jwk) {
  log.debug("Entering publicJwk().");
  const out = {};
  Object.keys(jwk || {}).forEach(function (name) {
    if (!PRIVATE_JWK[name]) {
      out[name] = jwk[name];
    }
  });
  log.debug("Leaving publicJwk().");
  return out;
}

async function matchingJwks(realm, signed) {
  log.debug("Entering matchingJwks(). " + realm.id);
  const kid = jwtKid(signed);
  if (!kid) {
    log.debug("Leaving matchingJwks(). No kid.");
    throw new Error("signed_metadata has no kid in " + realm.id);
  }
  const r = await oidf.send(realm.base + "/oauth2/jwks");
  const keys = (r.body && r.body.keys) || [];
  const found = keys.filter(function (key) {
    return key && key.kid === kid;
  })[0];
  if (!found) {
    log.debug("Leaving matchingJwks(). No match.");
    throw new Error("no public JWK with kid " + kid + " in " + realm.id);
  }
  log.debug("Leaving matchingJwks().");
  return publicJwk(found);
}

function configurationFor(plan, prepared, doc, jwk, token) {
  log.debug("Entering configurationFor(). " + plan.key);
  const pdp = {
    policy_decision_point: doc.policy_decision_point,
    jwks: { keys: [jwk] }
  };
  if (plan.staticMetadata) {
    STATIC_ENDPOINTS.forEach(function (key) {
      if (doc[key]) {
        pdp[key] = doc[key];
      }
    });
  }
  const out = {
    alias: "iya-az-" + plan.key + "-" + TAG,
    description: "AuthZEN certification " + plan.key,
    pdp: pdp
  };
  if (prepared.certPem) {
    out.mtls = { cert: prepared.certPem, key: prepared.keyPem,
                 ca: prepared.anchorPem };
  }
  if (token) {
    out.client = { api_key: token };
  }
  log.debug("Leaving configurationFor().");
  return out;
}

async function clearCertificateHeader(realm) {
  log.debug("Entering clearCertificateHeader(). " + realm.id);
  await oidf.ok(realm.api + "/config/set", {
    key: "oauth2.signedMetadataCertificateHeader", value: "none" },
    "cleared the signed-metadata certificate header in " + realm.id);
  log.info("Set oauth2.signedMetadataCertificateHeader to none in " +
           realm.id + ".");
  log.debug("Leaving clearCertificateHeader().");
}

async function createDiscovery(configuration) {
  log.debug("Entering createDiscovery().");
  const path = "api/plan?planName=" + encodeURIComponent(DISCOVERY_NAME);
  const created = await oidf.suite("POST", path, configuration);
  if (created.status === 201 || created.status === 200) {
    log.debug("Leaving createDiscovery(). " + created.status);
    return created;
  }
  if (planIsMissing(created.status, created.raw)) {
    log.info("release-v5.3.1 has no " + DISCOVERY_NAME +
             " (HTTP " + created.status + "); skipping discovery.");
    log.debug("Leaving createDiscovery(). Skipped.");
    return { skipped: true, status: created.status };
  }
  log.debug("Leaving createDiscovery(). " + created.status);
  throw new Error("creating " + DISCOVERY_NAME + ": " + created.status +
                  " " + redact(created.raw).slice(0, 400));
}

async function runOne(planId, module) {
  log.debug("Entering runOne(). " + module.testModule);
  const got = await oidf.runModule(planId, module);
  log.debug("Leaving runOne(). " + (got.result || got.status));
  return got;
}

async function runCreated(plan, created) {
  log.debug("Entering runCreated(). " + plan.key);
  const results = [];
  const modules = (created.body && created.body.modules) || [];
  for (let i = 0; i < modules.length; i++) {
    let got = await runOne(created.body.id, modules[i]);
    if (got.status === "TIMED OUT") {
      log.info("  " + plan.key + " " + got.module +
               ": TIMED OUT; running it once more.");
      got = await runOne(created.body.id, modules[i]);
    }
    const note = got.failures.length
      ? " — " + got.failures[0].src + ": " + redact(got.failures[0].msg)
      : "";
    log.info("  " + plan.key + " " + got.module + ": " +
             (got.result || got.status) + note);
    results.push(got);
  }
  log.debug("Leaving runCreated().");
  return { planId: created.body.id, results: results };
}

async function runAll(mtls, bearer) {
  log.debug("Entering runAll().");
  const unexpected = [];
  for (let i = 0; i < PLANS.length; i++) {
    const plan = PLANS[i];
    if (!oidf.selected(plan.key)) {
      continue;
    }
    const prepared = plan.door === "bearer" ? bearer : mtls;
    log.info("=== " + plan.name + " " +
             JSON.stringify(plan.variant) + " (" + plan.key + ") ===");
    let ran = null;
    try {
      const doc = await readMetadata(prepared.realm);
      const jwk = await matchingJwks(prepared.realm, doc.signed_metadata);
      const token = plan.apiKey ? await mintToken(prepared.realm) : null;
      const configuration = configurationFor(plan, prepared, doc, jwk,
                                             token);
      if (plan.discovery) {
        const created = await createDiscovery(configuration);
        if (created.skipped) {
          continue;
        }
        ran = await runCreated(plan, created);
      } else {
        ran = await oidf.runPlan(plan.name, plan.variant, configuration,
                                 plan.key);
      }
    } catch (e) {
      const message = redact((e && e.message) || e);
      log.error("Caught in runAll(): " + plan.key + ": " + message);
      unexpected.push(plan.key + " could not run: " + message);
      continue;
    }
    const judged = oidf.judge(plan.key, ran, EXPECTED, KNOWN_WARNINGS,
                              KNOWN_FAILURES);
    log.info("  " + plan.key + ": " + JSON.stringify(judged.counts) +
             ", plan " + oidf.SUITE + "plan-detail.html?plan=" +
             ran.planId);
    judged.unexplained.forEach(function (line) {
      unexpected.push(redact(line));
    });
  }
  log.debug("Leaving runAll(). " + unexpected.length);
  return unexpected;
}

async function test() {
  log.debug("Entering test().");
  await oidf.waitForSuite();
  const mtls = wants("mtls") ? await prepareMtls() : null;
  const bearer = wants("bearer") ? await prepareBearer() : null;
  let unexpected = await runAll(mtls, bearer);
  if (!headerCleared && sawCertificateFetch(unexpected)) {
    log.info("A result named x5u or /pki/chain. Clearing the " +
             "signed-metadata certificate header and running once more.");
    if (mtls) {
      await clearCertificateHeader(mtls.realm);
    }
    if (bearer) {
      await clearCertificateHeader(bearer.realm);
    }
    headerCleared = true;
    unexpected = await runAll(mtls, bearer);
  }
  if (unexpected.length) {
    log.error("Unexplained:\n  " + unexpected.join("\n  "));
  }
  check("every module passed or is argued, and every warning is known",
        function () {
          assert.strictEqual(unexpected.length, 0,
                             redact(unexpected.join("\n")));
        });
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

new Command()
  .description("The OpenID Foundation conformance suite's AuthZEN PDP " +
    "plans (#936) against this service.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(redact((e && e.stack) || (e && e.message) || e));
  process.exit(1);
});
