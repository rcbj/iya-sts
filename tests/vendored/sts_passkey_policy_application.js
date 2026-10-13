// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

// ===========================================================================
// sts_passkey_policy_application.js — AN APPLICATION'S PASSKEY POLICY, READ
// THROUGH /admin-api, AND THE POLICY PAGE'S APPLICATION SEARCH (#609), over
// HTTP, in every mode the suite runs.
//
// `tests/passkey_policy_on_application.js` holds the same design in process
// with the renderers; this is the protocol half (tests/CLAUDE.md, *where a
// new test goes*: it is about this service's own /admin-api, so it is
// `local: true`, written here and never vendored from the parent).
//
// rcbj's decisions on #609: nothing is stored on the application — the
// relation is a named passkey policy's `stsPasskeySelectApplication` — and
// the application read the console draws its page from carries it as
// `page.passkeyPolicies`; the Passkey policy tab's applications box searches
// the realm's applications through `GET /admin-api/applications` and stores
// what it adds by IDENTIFIER, written by the profile's Save as before.
//
// **IN A THROWAWAY REALM OF ITS OWN**, because named passkey policies change
// what a sign-in gets and the suite runs jobs side by side; a realm's named
// policies are its own and not inherited. The realm is left behind, as every
// job's is.
//
//   A. three named policies — one naming the application by identifier at
//      precedence 5, one by its client_id in another case (and a group) at
//      40, one naming another application at 1 — and the read lists the
//      first two in precedence order, the first marked as applying, each
//      with the value that named it and its link; the third is not listed;
//   B. an application no policy names reads `default`;
//   C. the search's data: the Applications list, five a page, leaving out
//      what the box already names, rows by identifier;
//   D. an Add's identifier saved with the profile's applications is read
//      back on that application's page as the policy that applies.
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
var BYCLIENT = "byclient-" + TAG;
var ELSEWHERE = "elsewhere-" + TAG;

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

  const policies = await call("GET", "/policies");
  assert.ok(policies.status === 200 && policies.body.passkey &&
            Array.isArray(policies.body.passkey.fields),
            "GET /policies answered " + policies.status + " " +
            String(policies.raw).slice(0, 300));
  const defaults = {};
  policies.body.passkey.fields.forEach(function (field) {
    defaults[field.key] = field.default;
  });
  await saveNamed(defaults, STRICT, { selectApplications: APP,
                                      precedence: 5 });
  await saveNamed(defaults, BYCLIENT, {
    selectApplications: CLIENT.toUpperCase(), selectGroups: "staff-" + TAG,
    precedence: 40 });
  await saveNamed(defaults, ELSEWHERE, { selectApplications: OTHER,
                                         precedence: 1 });

  const read = await pageOf(APP);
  const pk = read.page && read.page.passkeyPolicies;
  check("A. THE APPLICATION READ CARRIES THE POLICIES NAMING IT, lowest " +
        "precedence first and marked, each with what named it and its link",
        function () {
    assert.ok(pk && Array.isArray(pk.policies), JSON.stringify(read.page &&
      Object.keys(read.page)));
    assert.deepStrictEqual(pk.policies.map(function (one) {
      return one.name;
    }), [STRICT, BYCLIENT], JSON.stringify(pk.policies));
    assert.strictEqual(pk.applies, STRICT);
    assert.strictEqual(pk.policies[0].applies, true);
    assert.strictEqual(pk.policies[1].applies, false);
    assert.deepStrictEqual(pk.policies[0].matched, [APP]);
    assert.deepStrictEqual(pk.policies[1].matched, [CLIENT.toUpperCase()]);
    assert.strictEqual(pk.policies[1].precedence, 40);
    assert.strictEqual(pk.policies[0].link,
                       "/admin/policies#passkey-profile-" + STRICT);
    assert.ok(pk.groupPolicies >= 1, JSON.stringify(pk));
    // An OAuth sign-in names the client_id, and gets the policy naming it.
    assert.strictEqual(pk.appliesBy[APP], STRICT, JSON.stringify(pk));
    assert.strictEqual(pk.appliesBy[CLIENT], BYCLIENT, JSON.stringify(pk));
  });

  const lone = (await pageOf(LONE)).page.passkeyPolicies;
  check("B. AN APPLICATION NO POLICY NAMES READS default", function () {
    assert.ok(lone && lone.policies.length === 0 &&
              lone.applies === "default", JSON.stringify(lone));
  });

  const listed = await call("GET", "/applications?q=" +
    encodeURIComponent("pkapp-" + TAG) + "&per=5&page=1&exclude=" +
    encodeURIComponent(APP) + "&exclude=" + encodeURIComponent(OTHER));
  check("C. THE SEARCH'S DATA: five a page, by identifier, leaving out what " +
        "the box names", function () {
    assert.strictEqual(listed.status, 200, String(listed.raw).slice(0, 300));
    const ids = (listed.body.applications || []).map(function (one) {
      return one.identifier;
    });
    assert.deepStrictEqual(ids, [LONE], JSON.stringify(ids));
  });

  // What an Add makes of the box, saved as the profile's Save sends it.
  await saveNamed(defaults, STRICT, { selectApplications: APP + ", " + LONE,
                                      precedence: 5 });
  const after = (await pageOf(LONE)).page.passkeyPolicies;
  check("D. AN ADDED IDENTIFIER, SAVED, IS READ BACK on that application",
        function () {
    assert.strictEqual(after.applies, STRICT, JSON.stringify(after));
    assert.deepStrictEqual(after.policies[0].matched, [LONE]);
  });
  const named = (await call("GET", "/policies")).body.passkey.named;
  check("D2. AND THE POLICY'S OWN READ HOLDS BOTH, by identifier",
        function () {
    const strict = named.filter(function (one) {
      return one.name === STRICT;
    })[0];
    assert.ok(strict, JSON.stringify(named));
    assert.deepStrictEqual(strict.selectApplications, [APP, LONE]);
  });
  assert.ok(checks >= 5, "only " + checks + " checks ran; a section has " +
            "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_passkey_policy_application")
  .description("An application's passkey policies read through /admin-api " +
      "(page.passkeyPolicies), and the policy page's application search " +
      "and its Add saved by identifier (#609).")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
