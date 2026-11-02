// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

// ===========================================================================
// sts_passkey_policy_application.js — THE PASSKEY POLICY AN APPLICATION
// AND A GROUP NAME, READ THROUGH /admin-api (#609, reshaped by #1235), over
// HTTP, in every mode the suite runs.
//
// `tests/passkey_policy_on_application.js` holds the same design in process
// with the renderers; this is the protocol half (tests/CLAUDE.md, *where a
// new test goes*: it is about this service's own /admin-api, so it is
// `local: true`, written here and never vendored from the parent).
//
// rcbj's decisions on #1234 (2026-10-30): what a named policy covers NAMES
// it — the application in `appPasskeyPolicy`, the group in
// `stsPasskeyPolicy` — and the policy keeps only its rows and its
// precedence. The application read the console draws its page from carries
// what that comes to as `page.passkeyPolicies`.
//
// **IN A THROWAWAY REALM OF ITS OWN**, because named passkey policies change
// what a sign-in gets and the suite runs jobs side by side; a realm's named
// policies are its own and not inherited. The realm is left behind, as every
// job's is.
//
//   A. two named policies, one at precedence 50 and one at 10; the
//      application names the first through `POST /applications/set`, and a
//      group the second through `POST /groups/set-policy`; a name the realm
//      does not hold is refused at both doors;
//   B. the application read says the policy it names, what applies, its
//      precedence and how many policies a group names; one naming none
//      reads `default`;
//   C. the policies read lists, per named policy, the applications and
//      groups naming it, and the kind's references;
//   D. a policy something names is not deleted; #940's registration rows
//      read back, and classical-only beside post-quantum-required is
//      refused.
// ===========================================================================

const assert = require("assert");
const { Command, Option } = require("commander");
const { usernameFor } = require("./random_username.js");

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
var log = bunyan.createLogger({ name: "sts_passkey_policy_application",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug('CONFIG_FILE could not be read, so the configuration is empty: ' +
            appconfigProblem.message);
}
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");
var REALM = usernameFor("pkapp").replace(/[^a-z0-9-]/g, "").slice(0, 30);
var DOMAIN = REALM + ".example.net";
var serviceApi = base + "/admin-api";
var api = base + "/realm/" + REALM + "/admin-api";

var TAG = REALM.slice(-8);
var APP = "pkapp-" + TAG + "-app";
var CLIENT = "pkapp-" + TAG + "-Client";
var OTHER = "pkapp-" + TAG + "-other";
var LONE = "pkapp-" + TAG + "-lone";
var STRICT = "strict-" + TAG;
var BYGROUP = "bygroup-" + TAG;
var GROUP = "pkgroup-" + TAG;

var checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  ✓ " + what);
  log.debug("Leaving check().");
}

async function call(method, path, payload) {
  log.debug("Entering call().");
  const r = await fetch(api + path, method === "GET" ? {} : {
    method: method, headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {}) });
  const raw = await r.text();
  let body;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in call(): " + ((e && e.message) || e));
    // An HTML error page from a door that answers JSON is worth quoting whole.
    body = raw;
  }
  log.debug("Leaving call().");
  return { status: r.status, body: body, raw: raw };
}

async function created(identifier, fields, protocols) {
  log.debug("Entering created(). " + identifier);
  const r = await call("POST", "/applications/create", {
    identifier: identifier, name: identifier, protocols: protocols || [],
    fields: fields || {} });
  assert.strictEqual(r.status, 200, "creating " + identifier + " answered " +
                     r.status + " " + String(r.raw).slice(0, 300));
  log.debug("Leaving created().");
}

// A WHOLE PROFILE (a save replaces it): the passkey policy's built-in
// defaults, read off `GET /admin-api/policies`, with the selectors.
async function saveNamed(defaults, name, selectors) {
  log.debug("Entering saveNamed(). " + name);
  const r = await call("POST", "/policies/save-passkey-policy",
                       Object.assign({ profile: name }, defaults, selectors));
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
            "saving the named passkey policy " + name + " answered " +
            r.status + " " + String(r.raw).slice(0, 400));
  log.debug("Leaving saveNamed().");
}

async function pageOf(identifier) {
  log.debug("Entering pageOf(). " + identifier);
  const r = await call("GET", "/applications?application=" +
                       encodeURIComponent(identifier));
  assert.strictEqual(r.status, 200, "reading " + identifier + " answered " +
                     r.status + " " + String(r.raw).slice(0, 300));
  log.debug("Leaving pageOf().");
  return r.body;
}

async function test() {
  log.debug("Entering test().");
  const made = await fetch(serviceApi + "/realms/create", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ id: REALM, domain: DOMAIN,
                           name: "passkey policy on applications (#609)" })
  });
  assert.strictEqual(made.status, 200, "creating the realm " + REALM +
    " answered " + made.status + " " + (await made.text()).slice(0, 300));
  await created(APP, { oauthClientId: CLIENT }, ["oauth2"]);
  await created(OTHER);
  await created(LONE);
  const group = await call("POST", "/groups/create", { group: GROUP });
  assert.strictEqual(group.status, 200, "creating the group answered " +
                     group.status + " " + String(group.raw).slice(0, 300));

  const policies = await call("GET", "/policies");
  assert.ok(policies.status === 200 && policies.body.passkey &&
            Array.isArray(policies.body.passkey.fields),
            "GET /policies answered " + policies.status + " " +
            String(policies.raw).slice(0, 300));
  check("THE PASSKEY POLICY API EXPOSES POPULATION REGISTRATION ALGORITHMS " +
        "AND MODE", function () {
    const fields = policies.body.passkey.fields;
    const algorithms = fields.filter(function (field) {
      return field.key === "registrationAlgorithms";
    })[0];
    const mode = fields.filter(function (field) {
      return field.key === "registrationMode";
    })[0];
    assert.ok(algorithms && algorithms.type === "list" &&
              algorithms.values.indexOf("ML-DSA-65") >= 0,
      JSON.stringify(algorithms));
    assert.ok(mode && mode.type === "enum" &&
              mode.values.indexOf("classical-only") >= 0,
      JSON.stringify(mode));
  });
  const defaults = {};
  policies.body.passkey.fields.forEach(function (field) {
    defaults[field.key] = field.default;
  });
  await saveNamed(defaults, STRICT, { precedence: 50,
    registrationAlgorithms: "ES256,RS256",
    registrationMode: "classical-only" });
  await saveNamed(defaults, BYGROUP, { precedence: 10 });
  const pointed = await call("POST", "/applications/set", {
    application: APP, attribute: "appPasskeyPolicy", value: STRICT });
  const ghost = await call("POST", "/applications/set", {
    application: OTHER, attribute: "appPasskeyPolicy",
    value: "ghost-" + TAG });
  const grouped = await call("POST", "/groups/set-policy", {
    group: GROUP, attribute: "stsPasskeyPolicy", policy: BYGROUP });
  const groupGhost = await call("POST", "/groups/set-policy", {
    group: GROUP, attribute: "stsPasskeyPolicy", policy: "ghost-" + TAG });
  check("A. AN APPLICATION AND A GROUP NAME A POLICY THE REALM HOLDS, AND " +
        "ONLY ONE IT HOLDS", function () {
    assert.strictEqual(pointed.status, 200, String(pointed.raw).slice(0, 300));
    assert.strictEqual(ghost.status, 400, String(ghost.raw).slice(0, 300));
    assert.strictEqual(grouped.status, 200, String(grouped.raw).slice(0, 300));
    assert.strictEqual(groupGhost.status, 400,
                       String(groupGhost.raw).slice(0, 300));
  });

  const read = await pageOf(APP);
  const pk = read.page && read.page.passkeyPolicies;
  check("B. THE APPLICATION READ SAYS THE POLICY IT NAMES, what applies, its " +
        "precedence and the policies groups name", function () {
    assert.ok(pk && pk.named === STRICT && pk.applies === STRICT &&
              pk.missing === false && pk.precedence === 50 &&
              pk.groupPolicies === 1 &&
              pk.link === "/admin/policies#passkey-profile-" + STRICT,
              JSON.stringify(pk));
  });
  const lone = (await pageOf(LONE)).page.passkeyPolicies;
  check("B2. AN APPLICATION NAMING NONE READS default", function () {
    assert.ok(lone && lone.applies === "default" && lone.missing === false,
              JSON.stringify(lone));
  });

  const body = (await call("GET", "/policies")).body.passkey;
  check("C. THE POLICIES READ LISTS WHAT NAMES EACH POLICY", function () {
    assert.deepStrictEqual(body.references, {
      application: "appPasskeyPolicy", group: "stsPasskeyPolicy" });
    assert.deepStrictEqual(body.selectors, ["precedence"]);
    const strict = body.named.filter(function (one) {
      return one.name === STRICT;
    })[0];
    const byGroup = body.named.filter(function (one) {
      return one.name === BYGROUP;
    })[0];
    assert.ok(strict && byGroup, JSON.stringify(body.named));
    assert.deepStrictEqual(strict.namedBy.applications, [APP]);
    assert.deepStrictEqual(byGroup.namedBy.groups, [GROUP]);
    assert.deepStrictEqual(strict.registrationAlgorithms, ["ES256", "RS256"]);
    assert.strictEqual(strict.registrationMode, "classical-only");
  });

  const held = await call("POST", "/policies/reset-passkey-policy",
                          { profile: BYGROUP });
  check("D. A POLICY A GROUP NAMES IS NOT DELETED", function () {
    assert.strictEqual(held.status, 400, String(held.raw).slice(0, 300));
    assert.ok(String(held.raw).indexOf(GROUP) >= 0,
              String(held.raw).slice(0, 300));
  });
  const conflict = await call("POST", "/policies/save-passkey-policy",
    Object.assign({ profile: "conflict-" + TAG }, defaults, {
      registrationAlgorithms: "ES256", registrationMode: "classical-only",
      postQuantumRequired: "registration-and-sign-in" }));
  check("CLASSICAL-ONLY CANNOT BE SAVED BESIDE A POST-QUANTUM REQUIRED " +
        "POLICY", function () {
    assert.strictEqual(conflict.status, 400, String(conflict.raw).slice(0, 300));
    assert.ok(JSON.stringify(conflict.body).indexOf("registrationMode") >= 0,
      JSON.stringify(conflict.body).slice(0, 400));
  });
  assert.ok(checks >= 7, "only " + checks + " checks ran; a section has " +
            "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_passkey_policy_application")
  .description("The passkey policy an application and a group name " +
      "(appPasskeyPolicy, stsPasskeyPolicy, #1235), read through " +
      "/admin-api (page.passkeyPolicies, #609), plus population " +
      "registration algorithms, modes and the classical-only / PQ-required " +
      "conflict (#940).")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
