// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: schemathesis_plan.js
//
// ===========================================================================
// THE SCHEMATHESIS PLAN, ASSERTED WITHOUT A STACK (#1299).
//
// tests/protocol/schemathesis_kit.js holds the PLAN — the surfaces, their
// auth, the checks and the run-sabotage exclusions. A Schemathesis run needs
// the tests image and a dedicated product stack, and the choices can be
// asserted without either: that the three realm profiles are product baseline,
// RFC 9700 and OAuth 2.1; that each surface names a known auth kind and
// enables the no-uncaught-5xx check; that the synthesized protocol surface
// runs exactly the four invariant checks; that the four custom checks are this
// service's own invariants; and that every exclusion carries a reason (an op
// excluded with
// no reason is indistinguishable from one dropped by accident). This is the
// tlsfuzzer_plan.js split: the data is the kit's, the assertions are here, and
// the fuzzer itself is not run here.
// ===========================================================================

const childProcess = require("child_process");
const fs = require("fs");
const path = require("path");
const kit = require("./protocol/schemathesis_kit");

// The four custom checks the plan must name, each this service's own
// cross-cutting invariant. no_uncaught_server_error is the no-uncaught-5xx
// invariant as a custom check (501-tolerant), in place of the built-in
// not_a_server_error, which mis-flags this service's deliberate 501s.
const INVARIANT_CHECKS = ["no_uncaught_server_error", "no_error_code_leak",
  "frame_ancestors_present", "no_outbound_fetch"];

// The expected auth kind of each surface, so a silent change to one is caught.
const EXPECTED_AUTH = {
  "account-api": "dpop-portal",
  "authn-api": "authn",
  "admin-api": "dpop-console",
  "report-api": "dpop-report",
  "protocol": "per-op"
};

// What tests/schemathesis/code_members.py says of each case, by plain python3:
// the file imports no schemathesis, so this needs no fuzzing virtual
// environment.
function leakedBy(cases) {
  const log = require("bunyan").createLogger({
    name: "schemathesis_plan", level: process.env.STS_LOG_LEVEL || "info" });
  log.debug("Entering leakedBy().");
  const answer = childProcess.spawnSync("python3", [path.join(__dirname,
    "schemathesis", "code_members.py")], { input: cases.map(function (one) {
    return JSON.stringify(one);
  }).join("\n") + "\n", encoding: "utf8" });
  if (answer.status !== 0) {
    log.debug("Leaving leakedBy(). It failed.");
    throw new Error("code_members.py failed: " + answer.stderr);
  }
  log.debug("Leaving leakedBy().");
  return answer.stdout.trim().split("\n").map(function (line) {
    return JSON.parse(line).length;
  });
}

// What tests/schemathesis/egress_routes.py says of each case, by plain python3
// (it imports no schemathesis): the reason string when the route may show a
// blocked outbound dial, or null.
function dialAllowed(cases) {
  const log = require("bunyan").createLogger({
    name: "schemathesis_plan", level: process.env.STS_LOG_LEVEL || "info" });
  log.debug("Entering dialAllowed().");
  const answer = childProcess.spawnSync("python3", [path.join(__dirname,
    "schemathesis", "egress_routes.py")], { input: cases.map(function (one) {
    return JSON.stringify(one);
  }).join("\n") + "\n", encoding: "utf8" });
  if (answer.status !== 0) {
    log.debug("Leaving dialAllowed(). It failed.");
    throw new Error("egress_routes.py failed: " + answer.stderr);
  }
  log.debug("Leaving dialAllowed().");
  return answer.stdout.trim().split("\n").map(function (line) {
    return JSON.parse(line);
  });
}

// (#1358) no_outbound_fetch allows a blocked dial ONLY at the exact routes
// that dial an administrator-configured address by design. Each refused case
// is an allowed one with a single thing changed, and the marker still fails on
// every other route (the no-egress network is the guarantee; this only stops
// the false positive).
function egressRouteSection(t) {
  t.log.debug("Entering egressRouteSection().");
  const cases = [
    ["a claims provider's registration dial", true,
     { method: "POST", path: "/admin-api/claim-providers/{action}",
       action: "add-provider" }],
    ["an outbound SCIM client's reconcile dial", true,
     { method: "POST", path: "/admin-api/scim/clients/{action}",
       action: "reconcile" }],
    ["an outbound SCIM client's connection test", true,
     { method: "POST", path: "/admin-api/scim/clients/{action}",
       action: "test-connection" }],
    ["an OpenID Federation resolve", true,
     { method: "POST", path: "/admin-api/oidfed/{action}",
       action: "resolve" }],
    ["adding a trust anchor", true,
     { method: "POST", path: "/admin-api/oidfed/{action}",
       action: "add-trust-anchor" }],
    ["adding a subordinate", true,
     { method: "POST", path: "/admin-api/oidfed/{action}",
       action: "add-subordinate" }],
    ["a resolve whose path was filled rather than templated", true,
     { method: "POST", path: "/admin-api/oidfed/resolve",
       action: "resolve" }],
    ["the SCIM outbound report read (dials nothing, echoes stored error)",
     true, { method: "GET", path: "/admin-api/scim", action: "scim" }],
    ["the SCIM outbound clients report read", true,
     { method: "GET", path: "/admin-api/scim/clients", action: "clients" }],
    ["a secret destination's test push", true,
     { method: "POST", path: "/admin-api/secret-destinations/{action}",
       action: "test-push" }],
    ["a filled secret-destination test-push path", true,
     { method: "POST", path: "/admin-api/secret-destinations/test-push",
       action: "test-push" }],
    ["another action on the secret-destinations route", false,
     { method: "POST", path: "/admin-api/secret-destinations/{action}",
       action: "add-destination" }],
    ["the audit history read (dials nothing, echoes stored event text)",
     true, { method: "GET", path: "/admin-api/audit", action: "audit" }],
    ["the audit read with no derived action still resolves whole", true,
     { method: "GET", path: "/admin-api/audit", action: "" }],
    ["a POST to the audit route is still a finding", false,
     { method: "POST", path: "/admin-api/audit", action: "audit" }],
    ["the SCIM read with no derived action still resolves whole", true,
     { method: "GET", path: "/admin-api/scim", action: "" }],
    ["another GET read is still a finding (the \"\" key is route-exact)",
     false, { method: "GET", path: "/admin-api/ldap", action: "ldap" }],
    ["another action on the claim-providers route", false,
     { method: "POST", path: "/admin-api/claim-providers/{action}",
       action: "remove-provider" }],
    ["another action on the SCIM clients route", false,
     { method: "POST", path: "/admin-api/scim/clients/{action}",
       action: "remove" }],
    ["another action on the oidfed route", false,
     { method: "POST", path: "/admin-api/oidfed/{action}",
       action: "enable" }],
    ["the right action under the wrong method", false,
     { method: "GET", path: "/admin-api/claim-providers/{action}",
       action: "add-provider" }],
    ["an unrelated route", false,
     { method: "POST", path: "/admin-api/users/{action}",
       action: "create" }],
    ["a dialing action's NAME on another route", false,
     { method: "POST", path: "/admin-api/users/{action}",
       action: "reconcile" }]
  ];
  const answers = dialAllowed(cases.map(function (one) {
    return one[2];
  }));
  cases.forEach(function (one, at) {
    const allowed = answers[at] !== null;
    t.check(allowed === one[1],
      (one[1] ? "allowed: " : "still a finding: ") + one[0],
      String(answers[at]));
  });

  // The routes egress_routes.py lists are exactly the designed dials the
  // #1358 review named, the connection test of that same SCIM client
  // (#1405), a secret destination's test push (#1430, the seventeenth
  // exception), and the three stored-error reads (#1299's two SCIM
  // reports and the audit history read, #1420), so a row added or
  // removed in the table fails here.
  const listed = childProcess.spawnSync("python3", [path.join(__dirname,
    "schemathesis", "egress_routes.py"), "--routes"], { encoding: "utf8" });
  t.equal(JSON.parse(listed.stdout).join(","),
    ["GET /admin-api/audit",
     "GET /admin-api/scim",
     "GET /admin-api/scim/clients",
     "POST /admin-api/claim-providers/{action} add-provider",
     "POST /admin-api/oidfed/{action} add-subordinate",
     "POST /admin-api/oidfed/{action} add-trust-anchor",
     "POST /admin-api/oidfed/{action} resolve",
     "POST /admin-api/scim/clients/{action} reconcile",
     "POST /admin-api/scim/clients/{action} test-connection",
     "POST /admin-api/secret-destinations/{action} test-push"].join(","),
    "egress_routes lists the designed dials and two stored-error reads");
  t.log.debug("Leaving egressRouteSection().");
}

// (#1357) Where an answer may name an error code. Each case that must fail
// is the allowed one with a single thing changed.
function codeMemberSection(t) {
  t.log.debug("Entering codeMemberSection().");
  const CODE = "refused (STS-PKI-0188)";
  const settings = JSON.stringify({ settings: { groups: [{ settings: [{
    description: CODE }] }] } });
  const cases = [
    ["help text in the settings block, on any /admin-api read", 0,
     { method: "GET", path: "/admin-api/saml2", status: 200, body: settings }],
    ["and in an act's answer", 0,
     { method: "POST", path: "/admin-api/saml-assertions/defaults",
       status: 200, body: settings }],
    ["a route's own help text", 0,
     { method: "GET", path: "/admin-api/oauth2", status: 200,
       body: JSON.stringify({ notes: [CODE] }) }],
    ["a recorded failure on a read that draws them", 0,
     { method: "GET", path: "/admin-api/audit", status: 200,
       body: JSON.stringify({ rows: [{ errorCode: "STS-HTTP-0011" }] }) }],
    ["the account API's document as the console holds it", 0,
     { method: "GET", path: "/admin-api/account-api", status: 200,
       body: JSON.stringify({ document: { paths: { "/account-api/a": {
         get: { description: CODE } } } } }) }],
    ["a cache's declared bound", 0,
     { method: "GET", path: "/admin-api/caches", status: 200,
       body: JSON.stringify({ caches: [{ bound: CODE }] }) }],
    ["a secret's fixed sentence", 0,
     { method: "GET", path: "/admin-api/secrets", status: 200,
       body: JSON.stringify({ notes: { "previous-kek": {
         without: CODE } } }) }],
    ["a seeded policy document in the editor", 0,
     { method: "GET", path: "/admin-api/xacml/editor", status: 200,
       body: JSON.stringify({ document: CODE, alfa: CODE,
         tree: [{ label: CODE, detail: CODE }] }) }],
    ["but a cache's name is not help text", 1,
     { method: "GET", path: "/admin-api/caches", status: 200,
       body: JSON.stringify({ caches: [{ name: CODE }] }) }],
    ["an answer naming no code", 0,
     { method: "GET", path: "/admin-api/oauth2", status: 200, body: "{}" }],
    ["a seeded policy document on the policies read", 0,
     { method: "GET", path: "/admin-api/ldap/policies", status: 200,
       body: JSON.stringify({ policies: [{ attributes: {
         xacmlPolicyDocument: [CODE] } }] }) }],
    ["the same document on another route", 1,
     { method: "GET", path: "/admin-api/ldap/roles", status: 200,
       body: JSON.stringify({ policies: [{ attributes: {
         xacmlPolicyDocument: [CODE] } }] }) }],
    ["the same document on the directory read", 0,
     { method: "GET", path: "/admin-api/ldap/directory", status: 200,
       body: JSON.stringify({ entries: [{ attributes: {
         xacmlPolicyDocument: [CODE] } }] }) }],
    ["a directory entry's description, which is stored text", 1,
     { method: "GET", path: "/admin-api/ldap/directory", status: 200,
       body: JSON.stringify({ entries: [{ attributes: {
         description: [CODE] } }] }) }],
    ["a named service-account field's sentence", 0,
     { method: "GET", path: "/admin-api/policies", status: 200,
       body: JSON.stringify({ serviceAccount: { named: [{ fields: [{
         what: CODE }] }] } }) }],
    ["a role description, which is stored text", 1,
     { method: "GET", path: "/admin-api/roles", status: 200,
       body: JSON.stringify({ roles: [{ description: CODE }],
                              shownRoles: [{ description: CODE }] }) }],
    ["the same text in a refusal", 1,
     { method: "GET", path: "/admin-api/saml2", status: 400, body: settings }],
    ["the same text on another API", 1,
     { method: "GET", path: "/account-api/x", status: 200, body: settings }],
    ["a route's help text on a route it does not belong to", 1,
     { method: "GET", path: "/admin-api/saml2", status: 200,
       body: JSON.stringify({ notes: [CODE] }) }],
    ["a code in a member nobody listed", 1,
     { method: "GET", path: "/admin-api/saml2", status: 200,
       body: JSON.stringify({ errorCode: "STS-HTTP-0011" }) }],
    ["a description outside the listed members", 1,
     { method: "GET", path: "/admin-api/saml2", status: 200,
       body: JSON.stringify({ reason: { description: CODE } }) }],
    ["a code after help text naming one, which reading the first would miss",
     1,
     { method: "GET", path: "/admin-api/saml2", status: 200,
       body: JSON.stringify({ settings: { groups: [{ settings: [{
         description: CODE }] }] }, errorCode: "STS-HTTP-0011" }) }],
    ["a code in a member's name", 1,
     { method: "GET", path: "/admin-api/saml2", status: 200,
       body: JSON.stringify({ "STS-HTTP-0011": 1 }) }],
    ["an act on a read that draws recorded failures", 1,
     { method: "POST", path: "/admin-api/audit", status: 200,
       body: JSON.stringify({ errorCode: "STS-HTTP-0011" }) }],
    // Fuzz run 14: the caller's own text, stored and answered back whole.
    ["a description this request sent, answered back whole", 0,
     { method: "POST", path: "/admin-api/authorization-servers/create",
       status: 200, echoed: ["tenant1", CODE],
       body: JSON.stringify({ ok: true, profile: { id: "tenant1",
         description: CODE } }) }],
    ["but a code beside the text this request sent", 1,
     { method: "POST", path: "/admin-api/authorization-servers/create",
       status: 200, echoed: ["note"],
       body: JSON.stringify({ ok: true, profile: {
         description: "note (" + CODE + ")" } }) }],
    ["and the same answer when the request sent something else", 1,
     { method: "POST", path: "/admin-api/authorization-servers/create",
       status: 200, echoed: ["tenant1"],
       body: JSON.stringify({ ok: true, profile: { id: "tenant1",
         description: CODE } }) }],
    ["and an echo in a refusal still fails", 1,
     { method: "POST", path: "/admin-api/authorization-servers/create",
       status: 400, echoed: [CODE],
       body: JSON.stringify({ ok: false, errors: [CODE] }) }],
    ["an answer that is not JSON", 1,
     { method: "GET", path: "/admin-api/saml2", status: 200,
       body: "<p>" + CODE + "</p>" }]
  ];
  const answers = leakedBy(cases.map(function (one) {
    return one[2];
  }));
  cases.forEach(function (one, at) {
    t.check((answers[at] > 0) === (one[1] > 0),
      (one[1] ? "refused: " : "allowed: ") + one[0], String(answers[at]));
  });

  // The diagnostic reads are the ones the response-model test names: a row
  // of either table with no route here fails a fuzz run, and a route with no
  // row is an exception nothing else knows about.
  const source = fs.readFileSync(path.join(__dirname,
    "openapi_response_models.js"), "utf8");
  const table = function (name) {
    const at = source.indexOf("const " + name + " = {");
    return source.slice(at, source.indexOf("\n};", at));
  };
  const named = new Set();
  (table("DRAWN_CODE_OPERATIONS").match(/^ {2}(get[A-Za-z]+):/gm) || [])
    .forEach(function (one) {
      named.add(one.trim().replace(":", ""));
    });
  (table("DRAWN_PLAIN_CODES").match(/^ {2}'(get[A-Za-z]+) /gm) || [])
    .forEach(function (one) {
      named.add(one.trim().replace("'", ""));
    });
  const listed = childProcess.spawnSync("python3", [path.join(__dirname,
    "schemathesis", "code_members.py"), "--diagnostic-operations"],
  { encoding: "utf8" });
  t.equal(JSON.parse(listed.stdout).join(","), Array.from(named).sort()
    .join(","), "the diagnostic reads are the response-model test's rows");
  t.log.debug("Leaving codeMemberSection().");
}

// A wedged store is answered 503 with Retry-After, which the checks allow, so
// the kit reads the store's own status at the end of a cell (#1463).
function storeProblemSection(t) {
  t.log.debug("Entering storeProblemSection().");
  t.equal(kit.storeProblemOf({ status: 200, json: { healthy: false,
    lastError: "unsupported Unicode escape sequence" } }),
          "unsupported Unicode escape sequence",
          "a store reporting a failed write is a finding, by its error");
  t.check(kit.storeProblemOf({ status: 200, json: { healthy: false } }) !== "",
          "and one reporting no error is still a finding");
  t.equal(kit.storeProblemOf({ status: 200, json: { healthy: true } }), "",
          "a healthy store is not");
  t.equal(kit.storeProblemOf({ status: 200, json: { healthy: null } }), "",
          "nor one with nothing to persist");
  t.equal(kit.storeProblemOf({ status: 403, json: { healthy: false } }), "",
          "and an answer that could not be read says nothing");
  t.log.debug("Leaving storeProblemSection().");
}

// EVERY REQUEST BODY TYPE THE MODELS DECLARE CAN BE SENT (fuzz run 14). A
// media type Schemathesis 4.33 has no serializer for is rejected at every
// draw that picks it: the type is never fuzzed, and an operation offering it
// beside one that can be sent fails filter_too_much now and then
// (`POST /admin-api/risk/upload`, application/gzip and application/zip). The
// built-in serializers are JSON, text, form, multipart, YAML, XML, the
// octet-stream bytes and the four image types; anything else is aliased in
// sts_checks.py, and this reads that file's alias call.
const BUILT_IN_BODY_TYPES = ["application/json", "application/octet-stream",
  "image/gif", "image/jpeg", "image/png", "image/webp"];

function bodyTypeSection(t) {
  t.log.debug("Entering bodyTypeSection().");
  const dir = path.join(__dirname, "..", "models", "api");
  const declared = new Set();
  fs.readdirSync(dir).filter(function (name) {
    return /\.tsp$/.test(name);
  }).forEach(function (name) {
    const text = fs.readFileSync(path.join(dir, name), "utf8");
    (text.match(/requestBody\/content\/[a-z0-9.+-]+~1[a-z0-9.+-]+/g) || [])
      .forEach(function (one) {
        declared.add(one.replace("requestBody/content/", "")
          .replace("~1", "/"));
      });
  });
  const hooks = fs.readFileSync(path.join(__dirname, "schemathesis",
    "sts_checks.py"), "utf8");
  const call = /schemathesis\.serializer\.alias\(\[([^\]]*)\],\s*"([^"]+)"\)/
    .exec(hooks);
  const aliased = call ? (call[1].match(/"[^"]+"/g) || [])
    .map(function (one) {
      return one.slice(1, -1);
    }) : [];
  t.check(!!call && BUILT_IN_BODY_TYPES.indexOf(call[2]) >= 0,
    "sts_checks.py aliases its archive types to a built-in serializer",
    call ? call[2] : "no alias call");
  const unsendable = Array.from(declared).filter(function (one) {
    return BUILT_IN_BODY_TYPES.indexOf(one) < 0 && aliased.indexOf(one) < 0;
  });
  t.check(declared.has("application/gzip") && declared.has("application/zip"),
    "the models still declare the two archive types the alias is for",
    Array.from(declared).join(", "));
  t.equal(unsendable.length, 0,
    "every request body type in models/api/*.tsp can be sent by the fuzzer (" +
    unsendable.join(", ") + ")");
  t.log.debug("Leaving bodyTypeSection().");
}

function run(t) {
  t.log.debug("Entering run().");
  codeMemberSection(t);
  bodyTypeSection(t);
  egressRouteSection(t);
  storeProblemSection(t);

  // The plan is internally well-formed.
  const problems = kit.validate();
  t.equal(problems.length, 0,
    "the plan validates (" + problems.join("; ") + ")");

  // The three realm profiles are product baseline, RFC 9700 and OAuth 2.1,
  // each on a realm of its own.
  const profileKeys = kit.PROFILES.map(function (one) {
    return one.key;
  });
  t.check(profileKeys.indexOf("base") >= 0 &&
    profileKeys.indexOf("rfc9700") >= 0 &&
    profileKeys.indexOf("oauth21") >= 0,
    "the three profiles are base, rfc9700 and oauth21",
    profileKeys.join(","));
  const realms = kit.PROFILES.map(function (one) {
    return one.realm;
  });
  t.equal(new Set(realms).size, kit.PROFILES.length,
    "each profile uses a distinct realm");
  const rfc9700 = kit.PROFILES.find(function (one) {
    return one.key === "rfc9700";
  });
  t.check(rfc9700 && rfc9700.settings["oauth2.rfc9700"] === true,
    "the rfc9700 profile turns oauth2.rfc9700 on");
  const oauth21 = kit.PROFILES.find(function (one) {
    return one.key === "oauth21";
  });
  t.check(oauth21 && oauth21.settings["oauth2.oauth21"] === true,
    "the oauth21 profile turns oauth2.oauth21 on");
  const base = kit.PROFILES.find(function (one) {
    return one.key === "base";
  });
  // The baseline profile turns NO mode switch on (that is what makes it the
  // baseline); the only overrides it carries are the DPoP replay-cache
  // headroom every fuzz realm needs (#1299 — see FUZZ_DPOP), so that the
  // fuzzer's proof volume does not fill the realm's history and get every
  // later proof refused (STS-OAUTH-0554).
  t.check(base && base.settings["oauth2.rfc9700"] === undefined &&
    base.settings["oauth2.oauth21"] === undefined,
    "the baseline profile turns no mode switch on");
  kit.PROFILES.forEach(function (one) {
    t.check(Number(one.settings["oauth2.accessTokenTtlS"]) >= 21600,
            one.key + ": a cell's token outlives the mode's six-hour bound",
            String(one.settings["oauth2.accessTokenTtlS"]));
    t.check(Number(one.settings["oauth2.dpopReplayCacheSize"]) > 10000 &&
      Number(one.settings["oauth2.dpopIatSkewS"]) < 300,
      "the " + one.key + " profile raises the DPoP replay-cache headroom " +
      "and shortens the proof window, so fuzz-volume proofs are not refused");
  });

  // Five surfaces: the four OpenAPI'd APIs plus the synthesized protocol doc.
  t.equal(kit.SURFACES.length, 5, "there are five surfaces");
  ["account-api", "authn-api", "admin-api", "report-api", "protocol"]
    .forEach(function (key) {
      t.check(!!kit.surfaceNamed(key), "the " + key + " surface is present");
    });

  // The checks a surface actually enables: its own (none today) plus the four
  // custom invariants, exactly as runSurface() builds the --checks argument.
  const enabledFor = function (surface) {
    return surface.checks.concat(kit.CUSTOM_CHECKS);
  };

  // Each surface names the auth kind it must, names NO built-in check (the
  // no-server-error invariant is the custom no_uncaught_server_error), and so
  // enables the no-uncaught-5xx check.
  kit.SURFACES.forEach(function (surface) {
    t.equal(surface.auth, EXPECTED_AUTH[surface.key],
      "the " + surface.key + " surface uses the expected auth kind");
    t.equal(surface.checks.length, 0,
      "the " + surface.key + " surface names no built-in check");
    t.check(enabledFor(surface).indexOf("no_uncaught_server_error") >= 0,
      "the " + surface.key + " surface checks for no uncaught server error");
  });

  // The synthesized protocol surface is built from the router walk and runs
  // exactly the four custom invariants (it has no response schemas, so no
  // conformance check applies).
  const protocol = kit.surfaceNamed("protocol");
  t.equal(protocol.kind, "synthesized",
    "the protocol surface is synthesized");
  t.equal(protocol.schemaPath, "/admin-api/sts-metadata",
    "the protocol surface is built from the router walk");
  t.equal(enabledFor(protocol).length, INVARIANT_CHECKS.length,
    "the protocol surface runs exactly the four invariant checks");

  // The openapi'd surfaces publish or gate their schema document as expected.
  t.equal(kit.surfaceNamed("account-api").schemaAuth, "none",
    "the account-api schema is anonymous");
  t.equal(kit.surfaceNamed("authn-api").schemaAuth, "none",
    "the authn-api schema is anonymous");
  t.equal(kit.surfaceNamed("admin-api").schemaAuth, "dpop-console",
    "the admin-api schema is read with the console token");
  t.equal(kit.surfaceNamed("report-api").schemaAuth, "dpop-report",
    "the report-api schema is read with the report token");

  // The custom checks are exactly this service's four invariants.
  t.equal(kit.CUSTOM_CHECKS.length, INVARIANT_CHECKS.length,
    "there are four custom checks");
  INVARIANT_CHECKS.forEach(function (check) {
    t.check(kit.CUSTOM_CHECKS.indexOf(check) >= 0,
      "the custom checks include " + check);
  });

  // One request may take 300 seconds. The CLI default is 10, and a legal
  // realm certificate-authority rebuild whose alternative key is
  // SLH-DSA-SHAKE-256s took 21 to 33 seconds (one POST /admin-api/pki
  // handler 77 seconds) on iya-sts-fuzz-1432. The client recorded that as
  // a network error and banned the later phases (#1435). 120 was outrun in
  // fuzz run 16 (2026-11-11) by a POST /admin-api/pki/build under load.
  t.equal(kit.REQUEST_TIMEOUT_SECONDS, 300,
    "one Schemathesis request may take 300 seconds");
  t.equal(kit.requestTimeoutArgs().join(" "), "--request-timeout 300",
    "the run passes that timeout, so a legal realm CA build is observed");

  // Every exclusion is scoped to a known surface and carries a reason. An
  // op excluded with no reason is indistinguishable from one dropped by
  // accident, so this is the assertion the exclusion list exists for.
  const surfaceKeys = kit.SURFACES.map(function (one) {
    return one.key;
  });
  kit.EXCLUSIONS.forEach(function (one) {
    t.check(surfaceKeys.indexOf(one.surface) >= 0,
      "exclusion " + one.match + " names a known surface", one.surface);
    t.check(!!one.reason && one.reason.trim().length > 0,
      "exclusion " + one.match + " carries a reason");
  });

  // The default-realm service cell (#1299): it drives the admin-api document
  // with the console token, inherits the admin-api surface's exclusions, and
  // adds exactly the six service operations that would stop the service or
  // take its store, keys or TLS away — each with a reason, like every
  // exclusion, so a service op excluded by accident is caught.
  const cell = kit.SERVICE_CELL;
  t.equal(cell.auth, "dpop-console",
    "the service cell signs in with the console token");
  t.equal(cell.schemaPath, "/admin-api/openapi.json",
    "the service cell fuzzes the admin-api document");
  t.check(surfaceKeys.indexOf(cell.exclusionsKey) >= 0,
    "the service cell inherits a known surface's exclusions",
    cell.exclusionsKey);
  t.check(cell.checks.concat(kit.CUSTOM_CHECKS)
    .indexOf("no_uncaught_server_error") >= 0,
    "the service cell checks for no uncaught server error");
  const serviceMatches = kit.SERVICE_EXCLUSIONS.map(function (one) {
    return one.match;
  }).sort();
  t.equal(serviceMatches.join(","),
    ["reencryptDataKeys", "rotateDataKeys", "rotateKek", "setListenerApplications",
     "setListeners", "stepDownScheduler"].join(","),
    "the service cell excludes exactly the six store/keys/TLS/service ops");
  kit.SERVICE_EXCLUSIONS.forEach(function (one) {
    t.check(!!one.match && !!one.reason && one.reason.trim().length > 0,
      "service exclusion " + one.match + " carries a reason");
  });

  // The infrastructure-name guard (#1299): the proxy refuses to forward an
  // admin-api request that names, as an exact value, one of these identities
  // or the fuzz person — because the admin-api cell can delete, forget or
  // disable the applications the run stands on (the 2026-11-06 run deleted
  // sts-admin-console, its own sign-in client). Each entry is a non-empty name
  // and carries a reason, exactly as the exclusions do; the list must include
  // the four surface/management clients iya-sts-60 named, so a dropped one is
  // caught here rather than as a mid-run token storm.
  t.check(Array.isArray(kit.PROTECTED_CLIENTS) &&
    kit.PROTECTED_CLIENTS.length > 0,
    "the guard protects a non-empty set of infrastructure names");
  kit.PROTECTED_CLIENTS.forEach(function (one) {
    t.check(!!one.name && typeof one.name === "string" &&
      one.name.trim().length > 0 && !!one.reason &&
      one.reason.trim().length > 0,
      "protected client " + (one && one.name) + " is a name with a reason");
  });
  const protectedNames = kit.PROTECTED_CLIENTS.map(function (one) {
    return one.name;
  });
  ["sts-admin-console", "sts-api-client", "sts-user-portal", "sts-report"]
    .forEach(function (name) {
      t.check(protectedNames.indexOf(name) >= 0,
        "the guard protects the infrastructure client " + name);
    });

  strictRequestSection(t);
  t.log.debug("Leaving run().");
}

// #1476: what the gate sends to every /admin-api GET, and what each answer
// means. The probes themselves need a stack; the decisions do not.
function strictRequestSection(t) {
  t.log.debug("Entering strictRequestSection().");
  const probes = kit.strictRequestProbes({ paths: {
    "/admin-api/bare": { get: { operationId: "bare" } },
    "/admin-api/paged/{id}": { get: { operationId: "paged", parameters: [
      { name: "page", in: "query", schema: { type: "integer" } },
      { name: "skip", in: "query", schema: { type: "integer",
                                             "x-refused-by-handler": true } }
    ] } },
    "/admin-api/held": { post: { operationId: "held" } }
  } });
  const of = function (id, kind) {
    return probes.filter(function (one) {
      return one.operationId === id && one.kind === kind;
    });
  };
  t.check(of("held", "unknown-parameter").length === 0,
    "only a GET is probed");
  t.check(of("bare", "unknown-parameter").length === 1 &&
    of("bare", "garbage-header").length === 1 &&
    of("bare", "standard-header").length === 1,
    "a GET with no parameters gets the unknown parameter and both headers");
  t.check(of("bare", "wrong-type").length === 0,
    "and no wrong-typed value, having nothing to type");
  t.check(of("paged", "wrong-type").length === 1 &&
    /\?page=abc$/.test(of("paged", "wrong-type")[0].url),
    "a declared integer is sent a word");
  t.check(of("paged", "unknown-parameter")[0].url.indexOf("{") < 0,
    "a path parameter is given a harmless value");
  t.equal(of("bare", "garbage-header")[0].headers["X-Sts-Garbage"],
    "%%%{{<garbage>}}~", "the garbage header is sent as the issue says");
  t.check(of("paged", "unknown-parameter")[0].named === "sts_garbage" &&
    of("paged", "wrong-type")[0].named === "page" &&
    of("bare", "garbage-header")[0].named === "x-sts-garbage",
    "every refusing probe names what the refusal has to name");
  const zodPaged = kit.strictRequestProbes({ paths: {
    "/account-api/paged": { get: { operationId: "zod", parameters: [
      { name: "page", in: "query", schema: { anyOf: [
        { type: "string", const: "" }, { type: "integer", minimum: 1 }] } }
    ] } }
  } }).filter(function (one) {
    return one.kind === "wrong-type";
  });
  t.check(zodPaged.length === 1 && /\?page=abc$/.test(zodPaged[0].url),
    "a zod integer (`anyOf` a string and an integer) is sent a word too " +
    "(#1483)");
  [ ["unknown-parameter", 400, "", null],
    ["unknown-parameter", 200, "", "unknown-parameter answered 200, not 400"],
    ["wrong-type", 400, "", null],
    ["wrong-type", 200, "", "wrong-type answered 200, not 400"],
    ["garbage-header", 400, "", null],
    ["garbage-header", 200, "", "garbage-header answered 200, not 400"],
    ["garbage-header", 400, '{"errors":["STS-API-0144"]}',
      "a refusal carried an error code"],
    ["standard-header", 200, "", null],
    ["standard-header", 400, "", null],
    ["standard-header", 500, "", "a standard header answered 500"],
    ["unknown-parameter", 401, "", "gate"],
    ["garbage-header", 403, "", "gate"]
  ].forEach(function (one) {
    t.equal(kit.strictRequestVerdict(one[0], one[1], one[2]), one[3],
      one[0] + " answered " + one[1] + " is " + one[3]);
  });
  // A 400 that names something else is not the refusal (#1483): a pending
  // id that does not exist answers 400 with or without the garbage.
  t.equal(kit.strictRequestVerdict("unknown-parameter", 400,
    '{"errors":["There is no sign-in waiting"]}', { named: "sts_garbage" }),
    "unknown-parameter answered 400 and did not name sts_garbage",
    "a 400 for the wrong reason is a miss");
  t.equal(kit.strictRequestVerdict("unknown-parameter", 400,
    '{"errors":["The query parameter \\"sts_garbage\\" is not one"]}',
    { named: "sts_garbage" }), null, "a 400 naming the parameter passes");
  t.equal(kit.strictRequestVerdict("garbage-header", 400,
    '{"errors":["The request header \\"x-sts-garbage\\" is not one"]}',
    { named: "x-sts-garbage" }), null, "a 400 naming the header passes");
  // What the protocol surface is held to (#1483): no 5xx, no leaked code.
  [ ["unknown-parameter", 200, "ignored", null],
    ["garbage-header", 200, "ignored", null],
    ["standard-header", 302, "", null],
    ["unknown-parameter", 401, "", null],
    ["unknown-parameter", 400, "bad", null],
    ["unknown-parameter", 404, "Cannot GET", null],
    ["unknown-parameter", 501, "Not Implemented", null],
    ["unknown-parameter", 500, "x", "unknown-parameter answered 500"],
    ["garbage-header", 503, "x", "garbage-header answered 503"],
    ["garbage-header", 0, "no answer", "garbage-header answered 0"],
    ["unknown-parameter", 400, '{"error":"STS-OAUTH-0171"}',
      "a refusal carried an error code"]
  ].forEach(function (one) {
    t.equal(kit.strictRequestVerdict(one[0], one[1], one[2],
      { tolerates: true }), one[3],
      "protocol: " + one[0] + " answered " + one[1] + " is " + one[3]);
  });
  // Every surface says what its probes hold, and only the protocol one is
  // tolerant; the service cell refuses like the realm's admin-api.
  kit.SURFACES.forEach(function (surface) {
    t.equal(surface.strict,
      surface.key === "protocol" ? "tolerates" : "refuses",
      surface.key + " is probed as " + surface.strict);
  });
  t.equal(kit.SERVICE_CELL.strict, "refuses",
    "the service cell is probed as refuses");
  // Sign-outs are not probed, and every exclusion carries its reason.
  t.check(kit.PROTOCOL_PROBE_EXCLUSIONS.length >= 5 &&
    kit.PROTOCOL_PROBE_EXCLUSIONS.every(function (one) {
      return one.template && one.template.charAt(0) === "/" &&
        one.reason && one.reason.length > 20;
    }), "every protocol probe exclusion names a template and a reason");
  const toleratedDoc = { paths: {
    "/oauth2/logout": { get: { operationId: "out" } },
    "/oauth2/token": { get: { operationId: "token" } }
  } };
  const tolerated = kit.strictRequestProbes(toleratedDoc, { tolerates: true });
  t.check(tolerated.every(function (one) {
    return one.path !== "/oauth2/logout";
  }) && tolerated.some(function (one) {
    return one.path === "/oauth2/token";
  }), "the sign-out is held back from the probes and the rest are not");
  t.check(kit.strictRequestProbes(toleratedDoc).some(function (one) {
    return one.path === "/oauth2/logout";
  }), "the exclusion is the protocol surface's alone");
  // The fuzz proxy strips what Schemathesis stamps on every request, and a
  // GET does not get a CSRF header its operation does not declare (#1483).
  const proxy = fs.readFileSync(path.join(__dirname, "schemathesis",
    "auth_proxy.js"), "utf8");
  t.check(/if \(low\.indexOf\("x-schemathesis-"\) === 0\) \{/.test(proxy),
    "the fuzz proxy does not forward X-Schemathesis-TestCaseId");
  t.check(new RegExp("if \\(session\\.csrf && req\\.method !== \"GET\" && " +
    "req\\.method !== \"HEAD\"\\)")
    .test(proxy), "the proxy adds X-CSRF-Token to a POST and not to a GET");
  // The sign-in policy guard (rcbj, 2026-11-10): what the proxy refuses to
  // forward that names nobody and still reaches the run's own sign-in.
  // The proxy reads its service base at load; a placeholder is enough for
  // its two predicates, which dial nothing.
  if (!process.env.STS_SCHEMA_SERVICE_BASE) {
    process.env.STS_SCHEMA_SERVICE_BASE = "https://sts:8081";
  }
  const guard = require("./schemathesis/auth_proxy.js");
  const base = "https://sts:8081/realm/fuzz-base/admin-api/";
  const body = function (o) {
    return Buffer.from(JSON.stringify(o), "utf8");
  };
  const refused = [
    [base + "policies/save-authn-policy", body({ firstFactors: ["x"] })],
    [base + "policies/save-authn-policy", body({ profile: "default",
      name: "anything" })],
    [base + "policies/reset-passkey-policy", body({ profile: " Default " })],
    [base + "xacml/edit-match", body({ policy: "role-issuance" })],
    [base + "xacml/create-from-template", body({ template: "x",
      name: "access-control" })],
    [base + "xacml/delete?name=role-issuance", null],
    [base + "config/set", body({ key: "xacml.issuancePolicy", value: "x" })],
    [base + "config/set-many", body({ values: { "roles.enforceIssuance":
      "false" } })]
  ];
  const forwarded = [
    [base + "policies/save-authn-policy", body({ profile: "fuzz-named" })],
    [base + "policies/delete-authn-policy", body({ name: "fuzz-named" })],
    [base + "policies/clear-passkey-client", body({})],
    [base + "xacml/edit-match", body({ policy: "seeded-rbac" })],
    [base + "config/set", body({ key: "saml.clockSkewS", value: "30" })],
    [base + "users/clear-totp", body({ user: "alice" })]
  ];
  t.check(refused.every(function (one) {
    return !!guard.touchesSignInPolicy(one[0], one[1], "POST");
  }), "the proxy refuses a write to a default policy profile, an edit of " +
    "either built-in XACML policy and a change to the settings that point " +
    "at them", JSON.stringify(refused.map(function (one) {
      return guard.touchesSignInPolicy(one[0], one[1]);
    })));
  t.check(forwarded.every(function (one) {
    return guard.touchesSignInPolicy(one[0], one[1], "POST") === null;
  }) &&
    guard.touchesSignInPolicy(base + "policies?x=1", null, "GET") === null &&
    guard.touchesSignInPolicy(base + "xacml/policies?name=role-issuance", null,
      "GET") === null,
  "and forwards a named profile, an act that is not a save, another " +
    "policy, another setting, another door and every read (the strict " +
    "probes are reads)", JSON.stringify(forwarded.map(function (one) {
      return guard.touchesSignInPolicy(one[0], one[1]);
    })));
  t.log.debug("Leaving strictRequestSection().");
}

module.exports = {
  name: "schemathesis_plan",
  describe: "the Schemathesis fuzzing plan is well-formed (no stack needed)",
  run: run
};
