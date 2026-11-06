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
const childProcess = require("child_process");
const fs = require("fs");
const net = require("net");
const os = require("os");
const path = require("path");
const log = bunyan.createLogger({ name: "schemathesis_kit",
  level: process.env.LOG_LEVEL || "info" });

// ---------------------------------------------------------------------------
// THE THREE REALM PROFILES. Each is a realm the job creates on the dedicated
// product stack and configures through `/admin-api` before fuzzing it. OAuth
// 2.1 implies RFC 9700, so `fuzz-21` is the strictest. The settings are
// per-realm runtime rows (common/mode.js, common/config.js), set with
// `admin:write`.
// ---------------------------------------------------------------------------
// Every fuzz realm needs headroom on the DPoP replay cache. The fuzzer signs
// DPoP proofs far faster than the default 600s window (2 x oauth2.dpopIatSkewS)
// lets them expire, and a full history REFUSES the next proof (STS-OAUTH-0554)
// rather than forgetting a live one — which left admin-api @ fuzz-21 at ~41k
// 401s (the handlers barely fuzzed) and the synthesized protocol-doc fetch,
// which runs on the last surface after the cache is full, empty (#1299). The
// SHORT window is the real fix: on the dedicated stack the proxy signs a fresh
// proof per request and delivers it over loopback with synced clocks, so 30s
// is ample and the live count stays tiny (rate x 60s). The large ceiling is
// then headroom the run never fills, not resident memory it holds.
const FUZZ_DPOP = Object.freeze({
  "oauth2.dpopIatSkewS": 30,
  "oauth2.dpopReplayCacheSize": 200000
});

const PROFILES = [
  { key: "base", realm: "fuzz-base", label: "product baseline",
    settings: Object.assign({}, FUZZ_DPOP) },
  { key: "rfc9700", realm: "fuzz-9700", label: "RFC 9700",
    settings: Object.assign({ "oauth2.rfc9700": true }, FUZZ_DPOP) },
  { key: "oauth21", realm: "fuzz-21", label: "OAuth 2.1",
    settings: Object.assign({ "oauth2.oauth21": true }, FUZZ_DPOP) }
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
// THE CHECKS. The gate asserts THIS SERVICE'S FOUR INVARIANTS and nothing else
// (rcbj, 2026-11-04), and ALL FOUR are CUSTOM checks loaded from the hooks
// file (no uncaught 5xx, no leaked error code, frame-ancestors kept, no
// outbound fetch). It does NOT assert strict OpenAPI conformance — this is a
// mock identity service, so "schema-valid request rejected" is overwhelmingly
// product-mode gating doing its job, and a 400 for an undeclared method or an
// accepted schema-violating body is not a robustness defect we are hunting. So
// every surface runs exactly the four checks (the run enables them BY NAME
// rather than `--checks all`, which turns on the conformance checks too).
//
// The no-uncaught-5xx invariant is the CUSTOM `no_uncaught_server_error`
// rather than the built-in `not_a_server_error`, because the invariant is "no
// UNCAUGHT 5xx — the fault boundary holds": this service deliberately answers
// 501 Not Implemented for a feature it does not implement or a realm turned
// off (the VC API, UMA, EST /fullcmc), each a handled refusal with a marked
// operator error code, which the built-in would mis-flag as a server error.
// The custom check allows 501 alone and fails every other 5xx (a 502 included
// — in this harness that can only be the auth proxy failing to forward, since
// the service gateways nothing). `BUILTIN_CHECKS` is the catalogue a surface
// MAY name; today no surface names any built-in.
// ---------------------------------------------------------------------------
const BUILTIN_CHECKS = [
  "not_a_server_error",
  "status_code_conformance",
  "content_type_conformance",
  "response_schema_conformance",
  "response_headers_conformance"
];

// The built-in checks every surface enables: NONE. The no-server-error
// invariant is the custom `no_uncaught_server_error` below, because the
// built-in `not_a_server_error` mis-flags this service's deliberate 501s. The
// catalogue above is left for a surface that ever needs a conformance check;
// naming one would reintroduce the noise this gate excludes.
const INVARIANT_BUILTIN = [];

const CUSTOM_CHECKS = [
  // No UNCAUGHT 5xx: the fault boundary holds. A deliberate 501 Not Implemented
  // is a handled refusal and is allowed; every other 5xx fails. Custom rather
  // than the built-in not_a_server_error, which cannot tell the two apart.
  "no_uncaught_server_error",
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
    schemaAuth: "none", auth: "dpop-portal", checks: INVARIANT_BUILTIN },
  { key: "authn-api", title: "Sign-in API",
    kind: "openapi", schemaPath: "/authn-api/openapi.json",
    schemaAuth: "none", auth: "authn", checks: INVARIANT_BUILTIN },
  { key: "admin-api", title: "Management API",
    kind: "openapi", schemaPath: "/admin-api/openapi.json",
    schemaAuth: "dpop-console", auth: "dpop-console", checks: INVARIANT_BUILTIN },
  { key: "report-api", title: "Reporting API",
    kind: "openapi", schemaPath: "/report-api/openapi.json",
    schemaAuth: "dpop-report", auth: "dpop-report", checks: INVARIANT_BUILTIN },
  { key: "protocol", title: "Protocol endpoints (synthesized)",
    kind: "synthesized", schemaPath: "/admin-api/sts-metadata",
    schemaAuth: "dpop-console", auth: "per-op",
    checks: INVARIANT_BUILTIN }
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
  { surface: "admin-api", match: "removeRealm",
    reason: "a realm delete can remove the fuzz run's own realm (or the " +
      "default realm), ending the run before it finishes" },
  { surface: "admin-api", match: "buildPkiRoot",
    reason: "rebuilds the Root CA and reissues the listener leaf, " +
      "invalidating the run's pinned trust anchor mid-run (the reason " +
      "sts_admin_api_operations is exclusive)" },
  { surface: "admin-api", match: "rotateSigningKeys",
    reason: "rotates the signing key the run's own access tokens are " +
      "verified against, so every later request fails to authenticate" },
  { surface: "admin-api", match: "rotateSigningKeysEmergency",
    reason: "an immediate signing-key rotation, invalidating the run's own " +
      "tokens at once" },
  { surface: "admin-api", match: "revokeAllTokens",
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
    // The checks actually enabled are the surface's own (a built-in catalogue
    // name, none today) plus the four custom invariants — exactly what
    // runSurface() passes to --checks. The set must be non-empty and must
    // carry the no-uncaught-5xx invariant.
    const enabled = (surface.checks || []).concat(CUSTOM_CHECKS);
    if (!Array.isArray(surface.checks) || enabled.length === 0) {
      problems.push("surface " + surface.key + " runs no check");
    }
    if (enabled.indexOf("no_uncaught_server_error") < 0) {
      problems.push("surface " + surface.key + " omits the no-uncaught-5xx " +
        "invariant");
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

// ---------------------------------------------------------------------------
// THE RUN. Provision the three realms + a fuzz person through `/admin-api`,
// then for each (realm x surface) start the auth proxy and run the unmodified
// Schemathesis CLI against it. Schemathesis loads each API's schema THROUGH
// the proxy (so report-api's gated openapi.json gets its DPoP for free); only
// the synthesized protocol document is built here, from the router walk. None
// of this runs without a stack — `tests/schemathesis_plan.js` asserts the PLAN
// above without one.
// ---------------------------------------------------------------------------

const FUZZ_USER = "fuzzer";
// Meets a typical product password policy: upper, lower, digit, symbol, long.
const FUZZ_PASSWORD = "Fuzz-Runner-Passw0rd!2026";
// The two console roles are granted on the roster (`/admin-api/rbac/grant`,
// `rbacAction`), by their SHORT roster ids — `read` and `write`, not the
// permission names (`admin-ui/admin_rbac.ts` ROLES; an unknown id is 400,
// STS-ADMIN-0582). `write` implies `read`, but both are granted for clarity.
// The report roles are CONFIGURED roles granted on the role register by NAME
// (`/admin-api/roles/add-member`, `rolesAction`).
const FUZZ_CONSOLE_ROLES = ["read", "write"];
const FUZZ_CONFIGURED_ROLES = ["REPORT_USE", "REPORT_ADMIN"];
// The person-create attributes a realm's attribute policy requires every
// person to hold (#396): cn, sn, givenName, mail (uid is the `username`).
// Product mode does not INVENT claim values (`mode.inventsClaimValues()` is
// false), so they are given explicitly rather than left to `invent`. The mail
// value is a non-routable `.invalid` address — it is only stored (mail sending
// is off by default), so nothing is dialed and nothing leaves the device.
const FUZZ_ATTRIBUTES = { cn: "Fuzz Runner", sn: "Runner",
  givenName: "Fuzz", mail: "fuzzer@fuzz.invalid" };
// The four APIs are fuzzed from their real schemas, so the synthesized
// protocol document leaves their paths out.
const API_BASES = ["/account-api", "/admin-api", "/authn-api", "/report-api"];
const PROXY_SCRIPT = path.join(__dirname, "..", "schemathesis",
  "auth_proxy.js");
const HOOKS_FILE = path.join(__dirname, "..", "schemathesis", "sts_checks.py");
const MAX_EXAMPLES = parseInt(
  process.env.STS_SCHEMATHESIS_MAX_EXAMPLES || "50", 10);
// The venv the tests image builds, or the PATH. STS_SCHEMATHESIS_DIR is the
// venv ROOT (the Dockerfile's `python3 -m venv /opt/schemathesis`), so the
// executable is `<dir>/bin/schemathesis` — no `venv` segment.
const SCHEMATHESIS_BIN = process.env.STS_SCHEMATHESIS_BIN ||
  (process.env.STS_SCHEMATHESIS_DIR
    ? path.join(process.env.STS_SCHEMATHESIS_DIR, "bin", "schemathesis")
    : "schemathesis");

// The management API's bearer token. The preload (attach-admin-token.js) holds
// the live one — a job may have minted itself a fresh token and handed it there
// — so prefer that; `process.env.STS_ADMIN_API_TOKEN` is the launcher's and the
// fallback for an in-process run with no preload.
function adminToken() {
  log.debug("Entering adminToken().");
  if (globalThis.stsAdminApiToken &&
      typeof globalThis.stsAdminApiToken.get === "function") {
    const held = globalThis.stsAdminApiToken.get();
    if (held) {
      log.debug("Leaving adminToken(). from the preload");
      return held;
    }
  }
  log.debug("Leaving adminToken(). from the environment");
  return process.env.STS_ADMIN_API_TOKEN || "";
}

// The client secret this run was handed. The tests container is given
// `ADMIN_API_CLIENT_SECRET` (docker-compose-run-tests.yml), and a launcher that
// minted the token itself exports `STS_ADMIN_API_CLIENT_SECRET`; either is the
// seeded `sts-api-client`'s secret.
function adminClientSecret() {
  log.debug("Entering adminClientSecret().");
  log.debug("Leaving adminClientSecret().");
  return process.env.STS_ADMIN_API_CLIENT_SECRET ||
    process.env.ADMIN_API_CLIENT_SECRET || "";
}

// One warning when no secret is available to re-mint with, so the fallback to
// the launcher's one-shot token is visible rather than silent.
let adminMintWarned = false;

// Mints a FRESH `/admin-api` token and installs it everywhere this run reads
// one, so a long run never provisions or fuzzes with an EXPIRED token (#1299:
// the launcher's token is minted once at start and the access-token lifetime is
// an hour, so cells and provisioning 63 minutes in answered 401 invalid_token).
// Called per provisioning and per cell. It mints DIRECTLY with the secret the
// kit can read rather than through the preload's refresh(), whose secretFor()
// reads only `STS_ADMIN_API_CLIENT_SECRET` and so mints nothing in the tests
// container. Updates the preload's live token (what console_signin's unheadered
// /admin-api calls carry) AND `process.env.STS_ADMIN_API_TOKEN` (what adminCall
// reads here and what a proxy child inherits at spawn). On no secret, or a mint
// that throws, it keeps the token in place: the caller's own 401 says so, and a
// mint failure must not be reported as whatever was being fuzzed.
async function freshAdminToken(serviceBase, say) {
  log.debug("Entering freshAdminToken().");
  const secret = adminClientSecret();
  if (!secret) {
    if (!adminMintWarned) {
      adminMintWarned = true;
      (say || function () {})("[schemathesis] WARNING: no client secret " +
        "(STS_ADMIN_API_CLIENT_SECRET / ADMIN_API_CLIENT_SECRET) to re-mint " +
        "the /admin-api token; using the launcher's one-shot token, which " +
        "expires mid-run.");
    }
    log.debug("Leaving freshAdminToken(). no secret");
    return adminToken();
  }
  try {
    const minter = require("../tools/admin-api-token.js");
    const fresh = await minter.mint(serviceBase, secret);
    if (fresh) {
      process.env.STS_ADMIN_API_TOKEN = fresh;
      if (globalThis.stsAdminApiToken &&
          typeof globalThis.stsAdminApiToken.set === "function") {
        globalThis.stsAdminApiToken.set(fresh);
      }
    }
    log.debug("Leaving freshAdminToken(). minted");
    return adminToken();
  } catch (e) {
    log.warn("freshAdminToken() could not mint (keeping the current token): " +
      ((e && e.message) || e));
    log.debug("Leaving freshAdminToken(). threw");
    return adminToken();
  }
}

// One `/admin-api` call with the run's admin token; { status, json }.
async function adminCall(serviceBase, realmPrefix, method, apiPath, body) {
  log.debug("Entering adminCall(). " + method + " " + apiPath);
  const url = serviceBase + realmPrefix + apiPath;
  const init = { method: method, headers: {
    authorization: "Bearer " + adminToken(),
    "content-type": "application/json" } };
  if (body) {
    init.body = JSON.stringify(body);
  }
  // Retry a CONNECTION-LEVEL failure once (#1299). `TypeError: fetch failed`
  // carries the real reason on e.cause -- a socket hang up / ECONNRESET, e.g.
  // a keep-alive socket in node's fetch agent gone stale over a long idle gap
  // (a realm's surfaces fuzz for ~25 min while nothing calls /admin-api, which
  // is where the 2026-11-06 run died, just before provisioning fuzz-21). Log
  // the message, the cause and the URL both times; the retry picks up a fresh
  // connection. A final failure answers status 0 so the caller's own status
  // check refuses it with a clear message rather than this throwing.
  let response = null;
  let lastError = null;
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      response = await fetch(url, init);
      lastError = null;
      break;
    } catch (e) {
      lastError = e;
      const cause = e && e.cause;
      log.warn("adminCall " + method + " " + url + " failed (attempt " +
        (attempt + 1) + " of 2): " + ((e && e.message) || e) + "; cause: " +
        ((cause && (cause.code || cause.message)) || "none"));
      if (attempt === 0) {
        await new Promise(function (resolve) { setTimeout(resolve, 300); });
      }
    }
  }
  if (!response) {
    log.debug("Leaving adminCall(). fetch failed after a retry");
    return { status: 0, json: { fetchError:
      (lastError && lastError.message) || "fetch failed",
      cause: (lastError && lastError.cause &&
        (lastError.cause.code || lastError.cause.message)) || "none" } };
  }
  const text = await response.text();
  let json = {};
  try {
    json = text ? JSON.parse(text) : {};
  } catch (e) {
    log.debug("Caught in adminCall() parsing: " + ((e && e.message) || e));
    json = { raw: text.slice(0, 400) };
  }
  log.debug("Leaving adminCall(). " + response.status);
  return { status: response.status, json: json };
}

// The protocol endpoints from `/admin-api/sts-metadata`, read with a
// DPoP-BOUND CONSOLE TOKEN rather than the plain-Bearer launcher token
// adminCall() carries (#1299). An OAuth-2.1 realm requires a sender-
// constrained token at /admin-api, so the plain Bearer is refused there and
// the synthesized doc came back empty ("schema defines no API operations");
// the openapi surfaces already read their schema THROUGH the proxy, which
// attaches dpop-console, and this gives the synthesized surface the same.
// console_signin's wrapper signs a fresh proof per request and retries a
// use_dpop_nonce challenge, as the proxy does — and with the fuzz realms'
// raised DPoP replay-cache headroom (FUZZ_DPOP) the proof is not refused as a
// cache-full STS-OAUTH-0554 the way it was once the admin-api surface before
// it had filled the realm's history. The fuzz person already exists with the
// console roles (provision() granted them). Resolves { ok, json, why }.
async function metadataAnswer(serviceBase, provisioned, say) {
  log.debug("Entering metadataAnswer(). " + provisioned.realmPrefix);
  let answer = null;
  try {
    const wrapper = await require("./console_signin").signInToTheConsole(
      serviceBase + provisioned.realmPrefix, provisioned.user, say,
      { password: provisioned.password });
    answer = await wrapper.api("GET", "/admin-api/sts-metadata");
  } catch (e) {
    log.debug("Caught in metadataAnswer(): " + ((e && e.message) || e));
    return { ok: false, json: null,
      why: "the console sign-in or the sts-metadata fetch threw: " +
        ((e && e.message) || e) };
  }
  if (!answer || answer.status !== 200 || !answer.json) {
    log.debug("Leaving metadataAnswer(). " +
      (answer ? answer.status : "no answer"));
    return { ok: false, json: null,
      why: "GET /admin-api/sts-metadata answered " +
        (answer ? answer.status + " " +
          String(answer.text || "").slice(0, 200) : "nothing") };
  }
  log.debug("Leaving metadataAnswer(). ok");
  return { ok: true, json: answer.json, why: "" };
}

// Creates the profile's realm (with its mode overrides), a fuzz person, their
// password and the four roles the gated surfaces need. Cross-realm admin-token
// behaviour is confirmed at the end-to-end run. Resolves the sign-in facts.
async function provision(serviceBase, profile, say) {
  log.debug("Entering provision(). " + profile.realm);
  // A fresh token before provisioning: the launcher's one expires an hour in,
  // and a late realm's provisioning would otherwise answer 401 (#1299).
  await freshAdminToken(serviceBase, say);
  const realmPrefix = "/realm/" + profile.realm;
  const made = await adminCall(serviceBase, "", "POST",
    "/admin-api/realms/create",
    { id: profile.realm, overrides: profile.settings });
  if ([200, 201, 409].indexOf(made.status) < 0) {
    throw new Error("could not create realm " + profile.realm + ": " +
      made.status + " " + JSON.stringify(made.json).slice(0, 300));
  }
  const person = await adminCall(serviceBase, realmPrefix, "POST",
    "/admin-api/users/create",
    { username: FUZZ_USER, attributes: FUZZ_ATTRIBUTES, credential: "none" });
  if ([200, 201, 409].indexOf(person.status) < 0) {
    throw new Error("could not create the fuzz person in " + profile.realm +
      ": " + person.status + " " + JSON.stringify(person.json).slice(0, 300));
  }
  const password = await adminCall(serviceBase, realmPrefix, "POST",
    "/admin-api/users/set-password",
    { user: FUZZ_USER, password: FUZZ_PASSWORD });
  if (password.status !== 200) {
    throw new Error("could not set the fuzz person's password in " +
      profile.realm + ": " + password.status + " " +
      JSON.stringify(password.json).slice(0, 300));
  }
  for (let i = 0; i < FUZZ_CONSOLE_ROLES.length; i++) {
    const granted = await adminCall(serviceBase, realmPrefix, "POST",
      "/admin-api/rbac/grant",
      { username: FUZZ_USER, role: FUZZ_CONSOLE_ROLES[i] });
    if (granted.status !== 200) {
      // A missing role is not fatal: the surface that needs it will fail its
      // own sign-in, which the run reports.
      say("[schemathesis] WARNING: granting " + FUZZ_CONSOLE_ROLES[i] + " in " +
        profile.realm + " answered " + granted.status);
    }
  }
  for (let i = 0; i < FUZZ_CONFIGURED_ROLES.length; i++) {
    const granted = await adminCall(serviceBase, realmPrefix, "POST",
      "/admin-api/roles/add-member",
      { role: FUZZ_CONFIGURED_ROLES[i], kind: "user", member: FUZZ_USER });
    if (granted.status !== 200) {
      say("[schemathesis] WARNING: granting " + FUZZ_CONFIGURED_ROLES[i] +
        " in " + profile.realm + " answered " + granted.status);
    }
  }
  say("[schemathesis] provisioned realm " + profile.realm + " (" +
    profile.label + ")");
  log.debug("Leaving provision().");
  return { realmPrefix: realmPrefix, user: FUZZ_USER,
    password: FUZZ_PASSWORD, label: profile.label };
}

// A free loopback TCP port.
function freePort() {
  log.debug("Entering freePort().");
  return new Promise(function (resolve, reject) {
    const server = net.createServer();
    server.on("error", reject);
    server.listen(0, "127.0.0.1", function () {
      const chosen = server.address().port;
      server.close(function () {
        log.debug("Leaving freePort(). " + chosen);
        resolve(chosen);
      });
    });
  });
}

// Resolves true once a connection to the port succeeds, or false on timeout.
function waitForPort(port, timeoutMs) {
  log.debug("Entering waitForPort(). " + port);
  const deadline = Date.now() + timeoutMs;
  return new Promise(function (resolve) {
    function attempt() {
      const socket = net.connect(port, "127.0.0.1");
      socket.on("connect", function () {
        socket.destroy();
        log.debug("Leaving waitForPort(). up");
        resolve(true);
      });
      socket.on("error", function () {
        socket.destroy();
        if (Date.now() > deadline) {
          log.debug("Leaving waitForPort(). timed out");
          resolve(false);
        } else {
          setTimeout(attempt, 200);
        }
      });
    }
    attempt();
  });
}

// An Express path as an OpenAPI path: `:id` becomes `{id}`.
function openApiPathOf(expressPath) {
  log.debug("Entering openApiPathOf().");
  log.debug("Leaving openApiPathOf().");
  return String(expressPath).replace(/:([A-Za-z0-9_]+)/g, "{$1}");
}

// The endpoint rows out of a `/admin-api/sts-metadata` answer, defensively:
// any object carrying a string `path` and an array `methods`, wherever the
// document nests them (confirmed against the real shape at the run).
function extractRows(json) {
  log.debug("Entering extractRows().");
  const rows = [];
  const seen = new Set();
  function walk(node) {
    if (!node || typeof node !== "object") {
      return;
    }
    if (typeof node.path === "string" && Array.isArray(node.methods)) {
      const key = node.path;
      if (!seen.has(key)) {
        seen.add(key);
        rows.push({ path: node.path, methods: node.methods });
      }
    }
    if (Array.isArray(node)) {
      node.forEach(walk);
    } else {
      Object.keys(node).forEach(function (name) {
        walk(node[name]);
      });
    }
  }
  walk(json);
  log.debug("Leaving extractRows(). " + rows.length + " row(s)");
  return rows;
}

// An OpenAPI 3.1 document of the protocol endpoints (the router rows that are
// not one of the four APIs), with loose schemas: the no-server-error check and
// the custom invariant checks are what these are fuzzed for.
function synthesizeProtocolDoc(rows) {
  log.debug("Entering synthesizeProtocolDoc().");
  const paths = {};
  const verbs = ["get", "post", "put", "delete", "patch"];
  rows.forEach(function (row) {
    const inApi = API_BASES.some(function (base) {
      return row.path === base || row.path.indexOf(base + "/") === 0;
    });
    if (inApi) {
      return;
    }
    const key = openApiPathOf(row.path);
    paths[key] = paths[key] || {};
    // A path template parameter ({id}) MUST be declared with in:path,
    // required:true and a schema, or OpenAPI 3.1 is invalid and Schemathesis
    // reports a per-operation "Schema Error" and never fuzzes it. Declare them
    // once on the path item (inherited by every verb). A loose string lets a
    // fuzzed value be anything.
    const names = (key.match(/\{([^}]+)\}/g) || []).map(function (token) {
      return token.slice(1, -1);
    });
    if (names.length > 0) {
      paths[key].parameters = names.map(function (name) {
        return { name: name, in: "path", required: true,
          schema: { type: "string" } };
      });
    }
    (row.methods || []).forEach(function (method) {
      const verb = String(method).toLowerCase();
      if (verbs.indexOf(verb) < 0) {
        return;
      }
      paths[key][verb] = { responses: { default: {
        description: "synthesized from the running router" } } };
    });
  });
  log.debug("Leaving synthesizeProtocolDoc(). " +
    Object.keys(paths).length + " path(s)");
  return { openapi: "3.1.0",
    info: { title: "iya-sts protocol endpoints", version: "1" },
    paths: paths };
}

// Runs the Schemathesis CLI and ECHOES its output live to our own stdout --
// the persisted per-job log -- so a failing case appears there as it happens
// and SURVIVES A CRASH of a LATER cell (#1299: the 2026-11-06 run died 57 min
// in and spawnSync's buffer, returned only when the whole job ended, took
// every finding with it). It still accumulates stdout/stderr for the result's
// tail. Resolves { status, stdout, stderr, error } in spawnSync's shape, so
// runSurface reads it unchanged.
function runSchemathesis(bin, args, env, cwd) {
  log.debug("Entering runSchemathesis().");
  return new Promise(function (resolve) {
    let out = "";
    let err = "";
    let child = null;
    try {
      child = childProcess.spawn(bin, args,
        { env: env, cwd: cwd, stdio: ["ignore", "pipe", "pipe"] });
    } catch (e) {
      log.debug("Caught spawning schemathesis: " + ((e && e.message) || e));
      resolve({ status: null, stdout: "", stderr: "", error: e });
      return;
    }
    child.stdout.on("data", function (chunk) {
      out += chunk;
      process.stdout.write(chunk);
    });
    child.stderr.on("data", function (chunk) {
      err += chunk;
      process.stderr.write(chunk);
    });
    child.on("error", function (e) {
      log.debug("Caught a schemathesis child error: " + ((e && e.message) || e));
      resolve({ status: null, stdout: out, stderr: err, error: e });
    });
    child.on("close", function (code) {
      log.debug("Leaving runSchemathesis(). close " + code);
      resolve({ status: code, stdout: out, stderr: err, error: null });
    });
  });
}

// Runs Schemathesis against one surface of one realm, through a proxy of its
// own. Resolves { surface, realm, code, status, output }.
async function runSurface(serviceBase, provisioned, surface, workDir, say) {
  log.debug("Entering runSurface(). " + surface.key);
  // A fresh token before every cell, and BEFORE the proxy is spawned so the
  // child inherits it in `process.env`: a cell is ~25 min and the token lasts
  // an hour, so a realm's third cell otherwise fuzzes with an expired token
  // and console_signin's /admin-api account-ensure answers 401 (#1299).
  await freshAdminToken(serviceBase, say);
  const port = await freePort();
  const proxyEnv = Object.assign({}, process.env, {
    STS_SCHEMA_PROXY_PORT: String(port),
    STS_SCHEMA_SERVICE_BASE: serviceBase,
    STS_SCHEMA_REALM_PREFIX: provisioned.realmPrefix,
    STS_SCHEMA_SURFACE: surface.key,
    STS_SCHEMA_AUTH: surface.auth,
    STS_SCHEMA_USER: provisioned.user,
    STS_SCHEMA_PASSWORD: provisioned.password });
  const proxy = childProcess.spawn(process.execPath, [PROXY_SCRIPT],
    { env: proxyEnv, stdio: ["ignore", "pipe", "pipe"] });
  let proxyOut = "";
  proxy.stdout.on("data", function (chunk) {
    proxyOut += chunk;
  });
  proxy.stderr.on("data", function (chunk) {
    proxyOut += chunk;
  });
  try {
    const up = await waitForPort(port, 60000);
    if (!up) {
      log.debug("Leaving runSurface(). proxy did not listen");
      return { surface: surface.key, realm: provisioned.realmPrefix,
        code: null, status: "error", findings: [],
        output: "the auth proxy did not listen: " + proxyOut.slice(-600) };
    }
    let schemaLocation;
    if (surface.kind === "synthesized") {
      const meta = await metadataAnswer(serviceBase, provisioned, say);
      if (!meta.ok) {
        log.debug("Leaving runSurface(). sts-metadata unreadable");
        return { surface: surface.key, realm: provisioned.realmPrefix,
          code: null, status: "error", findings: [],
          output: "could not read /admin-api/sts-metadata with a DPoP-bound " +
            "console token (the synthesized protocol doc needs it): " +
            meta.why };
      }
      const doc = synthesizeProtocolDoc(extractRows(meta.json));
      schemaLocation = path.join(workDir, "protocol" +
        provisioned.realmPrefix.replace(/[^A-Za-z0-9]+/g, "_") + ".json");
      fs.writeFileSync(schemaLocation, JSON.stringify(doc));
    } else {
      schemaLocation = "http://127.0.0.1:" + port + surface.schemaPath;
    }
    const base = "http://127.0.0.1:" + port;
    // Enable EXACTLY the four invariant checks by name — all four are custom
    // checks from the hooks file (no_uncaught_server_error, no_error_code_leak,
    // frame_ancestors_present, no_outbound_fetch); no surface names a built-in.
    // `--checks all` would also turn on the strict OpenAPI-conformance checks
    // (undeclared-method, schema-valid-rejected, schema-violating-accepted),
    // which this gate does not assert (rcbj, 2026-11-04); naming the checks is
    // how the scope stays the four invariants.
    const enabledChecks = surface.checks.concat(CUSTOM_CHECKS);
    const args = ["run", schemaLocation, "--url", base,
      "--checks", enabledChecks.join(","), "-n", String(MAX_EXAMPLES)];
    exclusionsFor(surface.key).forEach(function (one) {
      args.push("--exclude-operation-id", one.match);
    });
    // Each custom check appends its finding (route, status, code, body
    // snippet) as a JSON line here, so the run emits the authoritative
    // route->code list the per-cell summary omits — the 40000-char output tail
    // below drops the per-failure detail on a large cell (#1347's leak-sink
    // work reads this). A per-(surface, realm) file so cells never collide.
    const realmSlug = provisioned.realmPrefix.replace(/[^A-Za-z0-9]+/g, "_");
    const findingsPath = path.join(workDir,
      "findings-" + surface.key + realmSlug + ".jsonl");
    try {
      fs.rmSync(findingsPath, { force: true });
    } catch (e) {
      log.debug("Caught removing a stale findings file: " +
                ((e && e.message) || e));
    }
    const runEnv = Object.assign({}, process.env,
      { SCHEMATHESIS_HOOKS: HOOKS_FILE,
        STS_SCHEMATHESIS_FINDINGS: findingsPath,
        STS_SCHEMA_REALM_PREFIX: provisioned.realmPrefix,
        STS_SCHEMA_SURFACE: surface.key });
    say("[schemathesis] " + surface.key + " @ " + provisioned.realmPrefix +
      ": " + SCHEMATHESIS_BIN + " " + args.join(" "));
    const run = await runSchemathesis(SCHEMATHESIS_BIN, args, runEnv, workDir);
    const code = run.status;
    const status = code === 0 ? "pass" : (code === 1 ? "fail" : "error");
    // A null status means the binary could not be spawned (ENOENT, EACCES) or
    // was killed by a signal; `run.error` names which, so carry it.
    const spawnError = run.error
      ? ("\nspawn error: " + ((run.error && run.error.message) || run.error))
      : "";
    log.debug("Leaving runSurface(). " + status + " (" + code + ")");
    // The structured findings the checks recorded this cell (one JSON line
    // each), so route->code survives whatever the output slice drops.
    let findings = [];
    try {
      const raw = fs.readFileSync(findingsPath, "utf8");
      findings = raw.split("\n").filter(function (line) {
        return line.trim().length > 0;
      }).map(function (line) {
        return JSON.parse(line);
      });
    } catch (e) {
      log.debug("Caught reading the findings file (none is normal on a " +
                "clean cell): " + ((e && e.message) || e));
    }
    // The scope is the four invariants, so a failing run prints only the real
    // findings (a 5xx, a leaked error code, a dropped frame-ancestors clause).
    // Keep a generous slice so each finding's endpoint and the custom check's
    // message — which names the leaked code — survive into the host log.
    return { surface: surface.key, realm: provisioned.realmPrefix,
      code: code, status: status, findings: findings,
      output: (((run.stdout || "") + (run.stderr || "")).slice(-40000)) +
        spawnError };
  } finally {
    proxy.kill();
  }
}

// The whole matrix: every surface of every realm profile. Resolves the list
// of per-(realm, surface) results.
async function run(serviceBase, options) {
  log.debug("Entering run().");
  const opts = options || {};
  const say = typeof opts.say === "function" ? opts.say : function () {};
  if (!adminToken() && !adminClientSecret()) {
    throw new Error("STS_ADMIN_API_TOKEN or a client secret " +
      "(STS_ADMIN_API_CLIENT_SECRET / ADMIN_API_CLIENT_SECRET) is required; " +
      "the launcher provides one and the kit re-mints per cell from the " +
      "secret");
  }
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "sts-schemathesis-"));
  const onResult = typeof opts.onResult === "function"
    ? opts.onResult : function () {};
  const results = [];
  function record(result) {
    results.push(result);
    // Emit each cell the moment it ends, so a crash of a LATER cell keeps
    // what the finished ones found (#1299: the 2026-11-06 run buffered every
    // result and printed at the end, so a fetch failure before fuzz-21 lost
    // all of fuzz-base's and fuzz-9700's). Returning them is now only for the
    // final assert.
    try {
      onResult(result);
    } catch (e) {
      log.debug("Caught in onResult(): " + ((e && e.message) || e));
    }
  }
  for (let p = 0; p < PROFILES.length; p++) {
    const profile = PROFILES[p];
    let provisioned = null;
    try {
      provisioned = await provision(serviceBase, profile, say);
    } catch (e) {
      // A failed provisioning step must not end the job (#1299): record it as
      // this realm's error and carry on to the next realm, so the realms that
      // DID run are not lost with it.
      log.warn("provisioning " + profile.realm + " failed: " +
        ((e && e.message) || e));
      record({ surface: "(provision)", realm: "/realm/" + profile.realm,
        code: null, status: "error", findings: [],
        output: "provisioning " + profile.realm + " failed: " +
          ((e && e.message) || e) });
      continue;
    }
    for (let s = 0; s < SURFACES.length; s++) {
      let result;
      try {
        result = await runSurface(serviceBase, provisioned, SURFACES[s],
          workDir, say);
      } catch (e) {
        // runSurface returns its own error results; this is the backstop for
        // an unexpected throw, so one surface never ends the matrix.
        log.warn("the surface " + SURFACES[s].key + " @ " +
          provisioned.realmPrefix + " threw: " + ((e && e.message) || e));
        result = { surface: SURFACES[s].key, realm: provisioned.realmPrefix,
          code: null, status: "error", findings: [],
          output: "the surface threw: " + ((e && e.message) || e) };
      }
      record(result);
    }
  }
  log.debug("Leaving run(). " + results.length + " result(s)");
  return results;
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
  validate: validate,
  openApiPathOf: openApiPathOf,
  extractRows: extractRows,
  synthesizeProtocolDoc: synthesizeProtocolDoc,
  provision: provision,
  runSurface: runSurface,
  run: run
};
