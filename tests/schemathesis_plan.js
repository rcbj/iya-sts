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
// RFC 9700 and OAuth 2.1; that each surface names a known auth kind and at
// least the no-server-error check; that the synthesized protocol surface runs
// only that check; that the three custom checks are this service's own
// invariants; and that every exclusion carries a reason (an op excluded with
// no reason is indistinguishable from one dropped by accident). This is the
// tlsfuzzer_plan.js split: the data is the kit's, the assertions are here, and
// the fuzzer itself is not run here.
// ===========================================================================

const kit = require("./protocol/schemathesis_kit");

// The three custom checks the plan must name, each this service's own
// cross-cutting invariant.
const INVARIANT_CHECKS = ["no_error_code_leak", "frame_ancestors_present",
  "no_outbound_fetch"];

// The expected auth kind of each surface, so a silent change to one is caught.
const EXPECTED_AUTH = {
  "account-api": "dpop-portal",
  "authn-api": "authn",
  "admin-api": "dpop-console",
  "report-api": "dpop-report",
  "protocol": "per-op"
};

function run(t) {
  t.log.debug("Entering run().");

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
  t.equal(base && Object.keys(base.settings).length, 0,
    "the baseline profile overrides no setting");

  // Five surfaces: the four OpenAPI'd APIs plus the synthesized protocol doc.
  t.equal(kit.SURFACES.length, 5, "there are five surfaces");
  ["account-api", "authn-api", "admin-api", "report-api", "protocol"]
    .forEach(function (key) {
      t.check(!!kit.surfaceNamed(key), "the " + key + " surface is present");
    });

  // Each surface names the auth kind it must, and every surface runs the
  // no-server-error check (the floor for the synthesized doc, included in the
  // built-ins for the others).
  kit.SURFACES.forEach(function (surface) {
    t.equal(surface.auth, EXPECTED_AUTH[surface.key],
      "the " + surface.key + " surface uses the expected auth kind");
    t.check(surface.checks.indexOf("not_a_server_error") >= 0,
      "the " + surface.key + " surface checks for no server error");
  });

  // The synthesized protocol surface is built from the router walk and runs
  // only the no-server-error check (it has no response schemas).
  const protocol = kit.surfaceNamed("protocol");
  t.equal(protocol.kind, "synthesized",
    "the protocol surface is synthesized");
  t.equal(protocol.schemaPath, "/admin-api/sts-metadata",
    "the protocol surface is built from the router walk");
  t.equal(protocol.checks.length, 1,
    "the protocol surface runs exactly the no-server-error check");

  // The openapi'd surfaces publish or gate their schema document as expected.
  t.equal(kit.surfaceNamed("account-api").schemaAuth, "none",
    "the account-api schema is anonymous");
  t.equal(kit.surfaceNamed("authn-api").schemaAuth, "none",
    "the authn-api schema is anonymous");
  t.equal(kit.surfaceNamed("admin-api").schemaAuth, "dpop-console",
    "the admin-api schema is read with the console token");
  t.equal(kit.surfaceNamed("report-api").schemaAuth, "dpop-report",
    "the report-api schema is read with the report token");

  // The custom checks are exactly this service's three invariants.
  t.equal(kit.CUSTOM_CHECKS.length, INVARIANT_CHECKS.length,
    "there are three custom checks");
  INVARIANT_CHECKS.forEach(function (check) {
    t.check(kit.CUSTOM_CHECKS.indexOf(check) >= 0,
      "the custom checks include " + check);
  });

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

  t.log.debug("Leaving run().");
}

module.exports = {
  name: "schemathesis_plan",
  describe: "the Schemathesis fuzzing plan is well-formed (no stack needed)",
  run: run
};
