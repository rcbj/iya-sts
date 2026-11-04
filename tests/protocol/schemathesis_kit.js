// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: schemathesis_kit.js
//
// ===========================================================================
// SCHEMATHESIS AGAINST THIS SERVICE'S FOUR APIS AND ITS PROTOCOL SURFACE
// (#1299).
//
// This is the kit, on the pattern of tlsfuzzer_kit.js: it holds THE PLAN —
// which surfaces are fuzzed, how each one is authenticated, which checks run,
// and the handful of operations excluded so a fuzz run cannot sabotage its own
// infrastructure — and (added with the auth proxy) the code that runs the
// unmodified Schemathesis CLI against each (realm x surface) through that
// proxy. `tests/schemathesis_plan.js` is the in-process test that asserts the
// PLAN below WITHOUT a stack, exactly as tlsfuzzer_plan.js asserts
// tlsfuzzer_kit.js's PLAN.
//
// WHY A FORWARD PROXY RATHER THAN SCHEMATHESIS AUTH HOOKS. In product mode
// every gated API fully validates the access token (issuer, audience, scope,
// cnf.jkt binding, a real subject) AND a per-request DPoP proof (htm/htu/jti,
// the use_dpop_nonce retry). Reimplementing that in a Python auth hook would
// be a second DPoP implementation to keep right; instead Schemathesis points
// at a node forward proxy (tests/schemathesis/auth_proxy.js) that reuses this
// repository's own client machinery — dpop.js, portal_signin.js,
// console_signin.js — to attach the right surface's token and a fresh proof to
// every request, and forwards to the service. The proxy knows the real
// forwarded URL, so the proof's htu matches what the service checks.
//
// WHY A DEDICATED, NETWORK-ISOLATED PRODUCT STACK (the `fuzz` mode). Fuzzing
// uses any method and any input, so it runs against a throwaway product stack
// brought up per run and torn down after — never the shared suite instance.
// That stack's docker network is `internal: true` (no egress): even a
// URL-shaped fuzz input cannot make the service dial out. Everything stays on
// the device. The no_outbound_fetch check is a secondary, best-effort signal;
// the network is the guarantee.
// ===========================================================================

const bunyan = require("bunyan");
const log = bunyan.createLogger({ name: "schemathesis_kit",
  level: process.env.LOG_LEVEL || "info" });

// ---------------------------------------------------------------------------
// THE THREE REALM PROFILES. Each is a realm the job creates on the dedicated
// product stack and configures through `/admin-api` before fuzzing it. OAuth
// 2.1 implies RFC 9700, so `fuzz-21` is the strictest. The settings are
// per-realm runtime rows (common/mode.js, common/config.js), set with
// `admin:write`.
// ---------------------------------------------------------------------------
const PROFILES = [
  { key: "base", realm: "fuzz-base", label: "product baseline",
    settings: {} },
  { key: "rfc9700", realm: "fuzz-9700", label: "RFC 9700",
    settings: { "oauth2.rfc9700": true } },
  { key: "oauth21", realm: "fuzz-21", label: "OAuth 2.1",
    settings: { "oauth2.oauth21": true } }
];

// ---------------------------------------------------------------------------
// THE AUTH KINDS. How the proxy authenticates each surface's operations.
//
//   none       nothing presented (an anonymous surface, or the operations the
//              synthesized protocol doc lists that take no credential).
//   authn      no access token; authn-api POSTs are bound, so the proxy adds
//              the sts_session cookie, a matching X-CSRF-Token and an allowed
//              Origin (the operations themselves are unauthenticated).
//   dpop-portal   a DPoP-bound `account:manage` token for `sts-user-portal`,
//                 the fuzz person the subject (portal_signin.js).
//   dpop-console  a DPoP-bound `admin:read`/`admin:write` token for
//                 `sts-admin-console`, the fuzz admin the subject
//                 (console_signin.js).
//   dpop-report   a DPoP-bound `report:use report:admin` token for
//                 `sts-report`; no packaged helper exists, so the proxy builds
//                 the PKCE+DPoP code flow from dpop.js (portal helper's shape).
// ---------------------------------------------------------------------------
const AUTH_KINDS = ["none", "authn", "dpop-portal", "dpop-console",
  "dpop-report"];

// ---------------------------------------------------------------------------
// THE CHECKS. Built-in Schemathesis checks run against the schema'd APIs;
// against the synthesized protocol doc only `not_a_server_error` is meaningful
// (there are no response schemas). The custom checks live in
// tests/schemathesis/sts_checks.py and encode this service's own invariants;
// they run on every surface.
// ---------------------------------------------------------------------------
const BUILTIN_CHECKS = [
  "not_a_server_error",
  "status_code_conformance",
  "content_type_conformance",
  "response_schema_conformance",
  "response_headers_conformance"
];

const CUSTOM_CHECKS = [
  // Every refusal records an operator error code and NEVER sends it; a code in
  // a response body is a leak (root CLAUDE.md, Every failure has an error
  // code).
  "no_error_code_leak",
  // frame-ancestors is the one CSP clause a page may not drop (RFC 9700 4.14);
  // every HTML response must still carry it.
  "frame_ancestors_present",
  // Best-effort signal that the service attempted an outbound fetch; the
  // internal network is the real guarantee.
  "no_outbound_fetch"
];

// ---------------------------------------------------------------------------
// THE SURFACES. Five per realm. `schemaPath` is relative to the realm base
// (helpers.baseUrlOf carries the realm prefix); `schemaAuth` is what READING
// the openapi.json itself needs (account-api and authn-api publish it
// anonymously; admin-api gates it behind admin:read; report-api behind its
// DPoP token; the synthesized protocol doc is built from `/admin-api/
// sts-metadata`, admin:read). `auth` is how the OPERATIONS are authenticated.
// ---------------------------------------------------------------------------
const SURFACES = [
  { key: "account-api", title: "Account API (portal/user)",
    kind: "openapi", schemaPath: "/account-api/openapi.json",
    schemaAuth: "none", auth: "dpop-portal", checks: BUILTIN_CHECKS },
  { key: "authn-api", title: "Sign-in API",
    kind: "openapi", schemaPath: "/authn-api/openapi.json",
    schemaAuth: "none", auth: "authn", checks: BUILTIN_CHECKS },
  { key: "admin-api", title: "Management API",
    kind: "openapi", schemaPath: "/admin-api/openapi.json",
    schemaAuth: "dpop-console", auth: "dpop-console", checks: BUILTIN_CHECKS },
  { key: "report-api", title: "Reporting API",
    kind: "openapi", schemaPath: "/report-api/openapi.json",
    schemaAuth: "dpop-report", auth: "dpop-report", checks: BUILTIN_CHECKS },
  { key: "protocol", title: "Protocol endpoints (synthesized)",
    kind: "synthesized", schemaPath: "/admin-api/sts-metadata",
    schemaAuth: "dpop-console", auth: "per-op",
    checks: ["not_a_server_error"] }
];

// ---------------------------------------------------------------------------
// EXCLUSIONS. The user's instruction is to fuzz any operation with any input;
// the stack absorbs the damage. These few exclusions are NOT about safety —
// they are operations that would sabotage the RUN'S OWN INFRASTRUCTURE, so
// excluding them is what lets the run continue (the tlsfuzzer `-e` analogue).
// Each carries its reason, and `tests/schemathesis_plan.js` fails on an
// exclusion with no reason. `match` is a substring of the operationId or path;
// `surface` is the surface it applies to. A new exclusion needs its own
// sentence, not a reference to these.
// ---------------------------------------------------------------------------
const EXCLUSIONS = [
  { surface: "admin-api", match: "deleteRealm",
    reason: "a realm delete can remove the fuzz run's own realm (or the " +
      "default realm), ending the run before it finishes" },
  { surface: "admin-api", match: "buildRoot",
    reason: "rebuilds the Root CA and reissues the listener leaf, " +
      "invalidating the adapter's pinned trust anchor mid-run (the reason " +
      "sts_admin_api_operations is exclusive)" },
  { surface: "admin-api", match: "rotateSigningKey",
    reason: "rotates the signing key the adapter's own access tokens are " +
      "verified against, so every later request fails to authenticate" },
  { surface: "admin-api", match: "revokeAll",
    reason: "revokes every token, the run's own admin:read/write token " +
      "among them, so the adapter cannot drive the next operation" }
];

// ---------------------------------------------------------------------------
// Accessors the plan test reads. Pure; no stack, no I/O.
// ---------------------------------------------------------------------------

// The surface entry for a key, or undefined.
function surfaceNamed(key) {
  log.debug("Entering surfaceNamed().");
  const hit = SURFACES.find(function (one) {
    return one.key === key;
  });
  log.debug("Leaving surfaceNamed().");
  return hit;
}

// The exclusions declared for one surface.
function exclusionsFor(surfaceKey) {
  log.debug("Entering exclusionsFor().");
  const list = EXCLUSIONS.filter(function (one) {
    return one.surface === surfaceKey;
  });
  log.debug("Leaving exclusionsFor().");
  return list;
}

// Every check name the plan may name, built-in or custom.
function knownChecks() {
  log.debug("Entering knownChecks().");
  log.debug("Leaving knownChecks().");
  return BUILTIN_CHECKS.concat(CUSTOM_CHECKS);
}

// The list of problems with the PLAN, empty when it is well-formed. The plan
// test asserts this is empty AND asserts the specific facts below, so a change
// that makes the whole thing vacuously pass is still caught.
function validate() {
  log.debug("Entering validate().");
  const problems = [];
  const surfaceKeys = SURFACES.map(function (one) {
    return one.key;
  });
  PROFILES.forEach(function (profile) {
    if (!profile.realm) {
      problems.push("profile " + profile.key + " names no realm");
    }
    if (!profile.settings || typeof profile.settings !== "object") {
      problems.push("profile " + profile.key + " has no settings object");
    }
  });
  SURFACES.forEach(function (surface) {
    if (surface.kind !== "openapi" && surface.kind !== "synthesized") {
      problems.push("surface " + surface.key + " has an unknown kind");
    }
    if (surface.auth !== "per-op" && AUTH_KINDS.indexOf(surface.auth) < 0) {
      problems.push("surface " + surface.key + " has an unknown auth kind");
    }
    if (!Array.isArray(surface.checks) || surface.checks.length === 0) {
      problems.push("surface " + surface.key + " runs no check");
    }
    (surface.checks || []).forEach(function (check) {
      if (BUILTIN_CHECKS.indexOf(check) < 0) {
        problems.push("surface " + surface.key + " names unknown built-in " +
          "check " + check);
      }
    });
  });
  EXCLUSIONS.forEach(function (one) {
    if (surfaceKeys.indexOf(one.surface) < 0) {
      problems.push("exclusion for unknown surface " + one.surface);
    }
    if (!one.match) {
      problems.push("exclusion on " + one.surface + " matches nothing");
    }
    if (!one.reason || one.reason.trim().length === 0) {
      problems.push("exclusion " + one.match + " on " + one.surface +
        " carries no reason");
    }
  });
  log.debug("Leaving validate(). " + problems.length + " problem(s)");
  return problems;
}

module.exports = {
  PROFILES: PROFILES,
  SURFACES: SURFACES,
  AUTH_KINDS: AUTH_KINDS,
  BUILTIN_CHECKS: BUILTIN_CHECKS,
  CUSTOM_CHECKS: CUSTOM_CHECKS,
  EXCLUSIONS: EXCLUSIONS,
  surfaceNamed: surfaceNamed,
  exclusionsFor: exclusionsFor,
  knownChecks: knownChecks,
  validate: validate
};
