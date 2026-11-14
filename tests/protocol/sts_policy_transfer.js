// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

// ===========================================================================
// sts_policy_transfer.js — POLICY EXPORT AND IMPORT THROUGH /admin-api
// (#1713), over HTTP, in every mode the suite runs.
//
// `tests/policy_transfer.js` holds the module in process; this is the
// protocol half (tests/CLAUDE.md, *where a new test goes*: it is about this
// service's own /admin-api, so it is `local: true`, written here).
//
// **IN TWO THROWAWAY REALMS OF ITS OWN**, an exporter and an importer,
// because an import writes the importer's policies and its signer
// truststore, and the suite runs jobs side by side. They are left behind, as
// every job's are.
//
//   A. the exporter saves a password profile and exports: a flattened JWS,
//      typ policy-export+json, the whole chain in x5c;
//   B. the exporter inspects its own export: `own`, trusted, the chain held
//      to the full checks (forced in development too, while
//      pki.paranoidPolicySigner is on);
//   C. an altered export is refused before anything is asked;
//   D. the importer is asked first (400, needsTrust); a yes naming another
//      Issuing CA is refused; the yes naming the one shown imports, adds the
//      chain to the signer truststore for policy-signer, and the profile
//      reads back; the next import is `trusted` without a question.
//   E. a selection: the view lists what may be selected; an export of one
//      policy carries it alone and records the selection; a name the realm
//      does not store is refused; inspect lists every profile and marks the
//      one it would replace; an import of a selection writes only that one
//      and leaves the importer's other policy as it was; a name the export
//      does not carry is refused.
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
var log = bunyan.createLogger({ name: "sts_policy_transfer",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug('CONFIG_FILE could not be read, so the configuration is empty: ' +
            appconfigProblem.message);
}
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");
var EXPORTER = usernameFor("ptxe").replace(/[^a-z0-9-]/g, "").slice(0, 30);
var IMPORTER = usernameFor("ptxi").replace(/[^a-z0-9-]/g, "").slice(0, 30);
var serviceApi = base + "/admin-api";

var checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  ✓ " + what);
  log.debug("Leaving check().");
}

async function call(realm, method, path, payload) {
  log.debug("Entering call(). " + realm + " " + path);
  const r = await fetch(base + "/realm/" + realm + "/admin-api" + path,
    method === "GET" ? {} : {
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

async function realm(id) {
  log.debug("Entering realm(). " + id);
  const made = await fetch(serviceApi + "/realms/create", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ id: id, domain: id + ".example.net",
                           name: "policy export and import (#1713)" }) });
  assert.strictEqual(made.status, 200, "creating the realm " + id +
    " answered " + made.status + " " + (await made.text()).slice(0, 300));
  log.debug("Leaving realm().");
}

// A WHOLE PASSWORD PROFILE (a save replaces it): every field's built-in
// default from `GET /policies`, with the minimum length given.
async function passwordProfile(id, minLength) {
  log.debug("Entering passwordProfile().");
  const policies = await call(id, "GET", "/policies");
  assert.ok(policies.status === 200 && policies.body.password &&
            Array.isArray(policies.body.password.fields),
            "GET /policies answered " + policies.status + " " +
            String(policies.raw).slice(0, 300));
  const body = {};
  policies.body.password.fields.forEach(function (field) {
    body[field.key] = field.default;
  });
  body.minLength = minLength;
  log.debug("Leaving passwordProfile().");
  return body;
}

async function minLengthIn(id) {
  log.debug("Entering minLengthIn(). " + id);
  const policies = await call(id, "GET", "/policies");
  const profile = policies.body.password.profile || {};
  log.debug("Leaving minLengthIn().");
  return profile.minLength;
}

// E. A SELECTION, OVER HTTP (rcbj, 2026-11-14: "import / export individual
// policies"). Runs after D, so IMPORTER already trusts EXPORTER's signer and
// stores its default password profile.
async function selections() {
  log.debug("Entering selections().");
  const named = Object.assign(await passwordProfile(EXPORTER, 18),
                              { profile: "ptx-strict", precedence: 40 });
  const saved = await call(EXPORTER, "POST",
                           "/policies/save-password-policy", named);
  assert.strictEqual(saved.status, 200, "saving a named password policy " +
                     "answered " + saved.status + " " +
                     String(saved.raw).slice(0, 400));
  const view = await call(EXPORTER, "GET", "/policies/transfer");
  check("E. THE VIEW LISTS WHAT AN EXPORT MAY SELECT", function () {
    assert.strictEqual(view.status, 200, String(view.raw).slice(0, 300));
    const names = (view.body.policies || []).map(function (one) {
      return one.kind + "/" + one.name;
    });
    assert.ok(names.indexOf("password/default") >= 0 &&
              names.indexOf("password/ptx-strict") >= 0,
              JSON.stringify(view.body.policies));
  });

  const one = await call(EXPORTER, "POST", "/policies/transfer/export",
    { policies: [{ kind: "password", name: "ptx-strict" }] });
  check("E. AN EXPORT OF ONE POLICY CARRIES THAT ONE AND SAYS SO",
        function () {
    assert.strictEqual(one.status, 200, String(one.raw).slice(0, 400));
    const payload = JSON.parse(Buffer.from(one.body.document.payload,
                                           "base64url").toString("utf8"));
    assert.strictEqual(payload.kinds.length, 1, JSON.stringify(payload.kinds));
    assert.deepStrictEqual(payload.kinds[0].profiles.map(function (p) {
      return p.name;
    }), ["ptx-strict"]);
    assert.deepStrictEqual(payload.selection,
                           [{ kind: "password", name: "ptx-strict" }]);
    assert.ok(/^policy-/.test(one.body.filename), one.body.filename);
  });

  const unknown = await call(EXPORTER, "POST", "/policies/transfer/export",
    { policies: [{ kind: "password", name: "ptx-no-such-policy" }] });
  check("E. AN EXPORT NAMING A POLICY THE REALM DOES NOT STORE IS REFUSED, " +
        "AND NOTHING IS EXPORTED", function () {
    assert.strictEqual(unknown.status, 400, String(unknown.raw).slice(0, 300));
    assert.ok(!unknown.body.document && Array.isArray(unknown.body.missing),
              String(unknown.raw).slice(0, 300));
  });

  const whole = await call(EXPORTER, "POST", "/policies/transfer/export", {});
  const seen = await call(IMPORTER, "POST", "/policies/transfer/inspect",
                          { document: whole.body.document });
  check("E. INSPECT LISTS EVERY PROFILE, MARKING ONE IT WOULD REPLACE",
        function () {
    assert.strictEqual(seen.status, 200, String(seen.raw).slice(0, 300));
    const byName = {};
    (seen.body.profiles || []).forEach(function (one) {
      byName[one.kind + "/" + one.name] = one;
    });
    assert.strictEqual(byName["password/default"].replaces, true,
                       JSON.stringify(seen.body.profiles));
    assert.strictEqual(byName["password/ptx-strict"].replaces, false,
                       JSON.stringify(seen.body.profiles));
  });

  const lowered = await call(IMPORTER, "POST",
                             "/policies/save-password-policy",
                             await passwordProfile(IMPORTER, 11));
  assert.strictEqual(lowered.status, 200, String(lowered.raw).slice(0, 300));
  const picked = await call(IMPORTER, "POST", "/policies/transfer/import",
    { document: whole.body.document,
      policies: [{ kind: "password", name: "ptx-strict" }] });
  const after = await call(IMPORTER, "GET", "/policies/transfer");
  const length = await minLengthIn(IMPORTER);
  check("E. AN IMPORT OF A SELECTION WRITES ONLY WHAT IT NAMES", function () {
    assert.strictEqual(picked.status, 200, String(picked.raw).slice(0, 400));
    assert.deepStrictEqual(picked.body.imported,
                           [{ kind: "password", names: ["ptx-strict"] }]);
    assert.ok((after.body.policies || []).some(function (one) {
      return one.kind === "password" && one.name === "ptx-strict";
    }), JSON.stringify(after.body.policies));
    assert.strictEqual(length, 11, "the importer's default was rewritten " +
                       "to " + length);
  });

  const missing = await call(IMPORTER, "POST", "/policies/transfer/import",
    { document: one.body.document,
      policies: [{ kind: "password", name: "default" }] });
  check("E. AN IMPORT NAMING A PROFILE THE EXPORT DOES NOT CARRY IS REFUSED",
        function () {
    assert.strictEqual(missing.status, 400, String(missing.raw).slice(0, 300));
    assert.ok(Array.isArray(missing.body.missing) && !missing.body.needsTrust,
              String(missing.raw).slice(0, 300));
  });
  log.debug("Leaving selections().");
}

async function test() {
  log.debug("Entering test().");
  await realm(EXPORTER);
  await realm(IMPORTER);
  const saved = await call(EXPORTER, "POST", "/policies/save-password-policy",
                           await passwordProfile(EXPORTER, 15));
  assert.strictEqual(saved.status, 200, "saving the exporter's password " +
                     "profile answered " + saved.status + " " +
                     String(saved.raw).slice(0, 400));

  const exported = await call(EXPORTER, "POST",
                              "/policies/transfer/export", {});
  const doc = exported.body && exported.body.document;
  check("A. AN EXPORT IS A FLATTENED JWS CARRYING ITS WHOLE CHAIN",
        function () {
    assert.strictEqual(exported.status, 200, String(exported.raw)
      .slice(0, 400));
    assert.ok(doc && doc.protected && doc.payload && doc.signature,
              JSON.stringify(doc).slice(0, 300));
    const header = JSON.parse(Buffer.from(doc.protected, "base64url")
      .toString("utf8"));
    assert.strictEqual(header.typ, "policy-export+json");
    assert.strictEqual(header.x5c.length, 4, JSON.stringify(header.x5c
      .length));
    assert.ok(Array.isArray(exported.body.files) &&
              exported.body.files[0].mime === "application/json",
              JSON.stringify(exported.body.files).slice(0, 200));
  });

  const own = await call(EXPORTER, "POST", "/policies/transfer/inspect",
                         { document: doc });
  check("B. ITS OWN REALM TRUSTS IT, AFTER THE FULL CHECKS", function () {
    assert.strictEqual(own.status, 200, String(own.raw).slice(0, 400));
    assert.strictEqual(own.body.origin, "own");
    assert.strictEqual(own.body.trusted, true);
    assert.strictEqual(own.body.verdict.inForce, true,
                       JSON.stringify(own.body.verdict));
  });

  const altered = Object.assign({}, doc, {
    payload: Buffer.from(JSON.stringify({ format: "iya-sts.policy-export",
      version: 1, realm: EXPORTER, kinds: [] })).toString("base64url") });
  const refused = await call(IMPORTER, "POST", "/policies/transfer/import",
                             { document: altered, trustSigner: true });
  check("C. AN ALTERED EXPORT IS REFUSED, AND NOTHING IS ASKED", function () {
    assert.strictEqual(refused.status, 400, String(refused.raw).slice(0, 300));
    assert.ok(!refused.body.needsTrust, JSON.stringify(refused.body)
      .slice(0, 300));
  });

  const asked = await call(IMPORTER, "POST", "/policies/transfer/import",
                           { document: JSON.stringify(doc) });
  const shown = asked.body && asked.body.inspection;
  const wrong = await call(IMPORTER, "POST", "/policies/transfer/import",
    { document: doc, trustSigner: true,
      issuerFingerprint: "AB".repeat(32) });
  check("D. ANOTHER REALM IS ASKED FIRST, AND A YES IS ABOUT ONE CHAIN",
        function () {
    assert.strictEqual(asked.status, 400, String(asked.raw).slice(0, 300));
    assert.strictEqual(asked.body.needsTrust, true);
    assert.ok(shown && shown.origin === "foreign" &&
              shown.realm === EXPORTER && shown.issuerFingerprint,
              JSON.stringify(shown).slice(0, 300));
    assert.strictEqual(wrong.status, 400, String(wrong.raw).slice(0, 300));
  });

  const yes = await call(IMPORTER, "POST", "/policies/transfer/import",
    { document: doc, trustSigner: true,
      issuerFingerprint: shown.issuerFingerprint });
  const trust = await call(IMPORTER, "GET", "/pki/trust");
  const length = await minLengthIn(IMPORTER);
  const again = await call(IMPORTER, "POST", "/policies/transfer/import",
                           { document: doc });
  check("D. THE YES IMPORTS, TRUSTS THAT CHAIN FOR POLICY IMPORTS, AND THE " +
        "NEXT IMPORT ASKS NOTHING", function () {
    assert.strictEqual(yes.status, 200, String(yes.raw).slice(0, 400));
    assert.strictEqual(yes.body.trustAdded.length, 3,
                       JSON.stringify(yes.body.trustAdded).slice(0, 300));
    assert.ok(String(trust.raw).indexOf(shown.issuerFingerprint) >= 0 &&
              String(trust.raw).indexOf("policy-signer") >= 0,
              String(trust.raw).slice(0, 300));
    assert.strictEqual(length, 15, "the importer's minimum length is " +
                       length);
    assert.strictEqual(again.status, 200, String(again.raw).slice(0, 300));
    assert.strictEqual(again.body.origin, "trusted");
  });
  await selections();
  assert.ok(checks >= 10, "only " + checks + " checks ran; a section has " +
            "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_policy_transfer")
  .description("Policy export and import through /admin-api (#1713): a " +
      "signed JSON export with its whole chain, its own realm trusted, " +
      "another realm asked first and pinned by its Issuing CA.")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
