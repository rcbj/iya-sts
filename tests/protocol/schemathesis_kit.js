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
const crypto = require("crypto");
const fs = require("fs");
const http = require("http");
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

// SIGN-IN RISK SCORING OFF IN THE FUZZ REALMS (#1299, the cb74ce0f8 run). The
// fuzz person signs in rapidly with no stable device or TLS client, which the
// risk engine scored HIGH once ("device and TLS client changed") during the
// authn-api cell; the product risk-response policy then ran risk-end-sessions
// (a global logout for fuzzer) and risk-credential-compromise. That is real
// self-sabotage worth preventing — but, on closer reading of the log, it was
// NOT the cause of the admin-api STS-API-0122 flood: that was the examples
// phase calling revoke-kind (every access_token, now excluded) plus the
// admin-api cell having rewritten its own policies so the proxy's re-sign hit
// MFA. This setting stops only the risk-driven logout. The fuzz person is not a
// real user and its risk is test noise; risk.assessSignIns=false short-circuits
// the scoring before any response can fire (risk/risk_engine.ts:1733), and the
// risk ADMIN endpoints are still fuzzed. A change of who is asking (a test
// realm's config), not of the service.
const FUZZ_RISK = Object.freeze({ "risk.assessSignIns": false });

// What every fuzz realm carries beside its mode flag: the DPoP headroom and the
// sign-in-risk opt-out.
// A TOKEN THAT OUTLIVES ITS CELL (#1502). The admin-api cells take over an hour
// once the realms overlap, past the hour a token lasts by default, and by then
// the cell's own fuzzing has usually changed who may sign in to the console, so
// the proxy cannot get another: 230 of 272 re-sign-ins failed, and the rest of
// the cell "passed" against a 401. Eight hours, the mode's own bound being six.
//
// AND A SIGN-IN THAT STAYS RECENT (#1538). Product mode asks for a sign-in within
// 15 minutes before a credential-changing operation, and answers 401
// insufficient_user_authentication after that. The proxy re-signs only on
// invalid_token, so those operations would go untested for most of a cell while
// the cell passed. 1440 is the row's maximum.
const FUZZ_TOKEN = Object.freeze({ "oauth2.accessTokenTtlS": 28800,
                                   "account.recentAuthMinutes": 1440 });

const FUZZ_REALM = Object.freeze(Object.assign({}, FUZZ_DPOP, FUZZ_RISK,
  FUZZ_TOKEN));

const PROFILES = [
  { key: "base", realm: "fuzz-base", label: "product baseline",
    settings: Object.assign({}, FUZZ_REALM) },
  { key: "rfc9700", realm: "fuzz-9700", label: "RFC 9700",
    settings: Object.assign({ "oauth2.rfc9700": true }, FUZZ_REALM) },
  { key: "oauth21", realm: "fuzz-21", label: "OAuth 2.1",
    settings: Object.assign({ "oauth2.oauth21": true }, FUZZ_REALM) }
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
// ADMIN-API RUNS LAST IN EACH REALM (#1299, iya-sts-60's directive). Holding
// SECURITY_ADMIN, the admin-api cell can rewrite the realm's policies (authn,
// passkey, post-login), and a fuzzed save turned sign-in into an MFA / held
// "pqc-passkey-migration" step that broke the LATER cells' sign-ins
// (report-api and protocol errored after it on the cb74ce0f8 run). Run it after
// account-api, authn-api, report-api and protocol, and it can only affect
// itself; the per-cell re-assert then has only the earlier cells' doing to fix.
// A realm's admin-api cannot reach the next realm (each realm is its own tree,
// keys and policies); if a way is found, it is a finding.
// `strict` (#1476, #1483) is what the cell's probes hold a GET to: `refuses`
// (a published API: an undeclared query name, a wrong-typed value and an
// unknown custom header are 400s) or `tolerates` (a protocol endpoint: an
// outside specification defines it and several say to ignore what they do
// not know, so a garbage request only has to answer no 5xx and no leaked
// code).
const SURFACES = [
  { key: "account-api", title: "Account API (portal/user)",
    kind: "openapi", schemaPath: "/account-api/openapi.json",
    schemaAuth: "none", auth: "dpop-portal", checks: INVARIANT_BUILTIN,
    strict: "refuses" },
  { key: "authn-api", title: "Sign-in API",
    kind: "openapi", schemaPath: "/authn-api/openapi.json",
    schemaAuth: "none", auth: "authn", checks: INVARIANT_BUILTIN,
    strict: "refuses" },
  { key: "report-api", title: "Reporting API",
    kind: "openapi", schemaPath: "/report-api/openapi.json",
    schemaAuth: "dpop-report", auth: "dpop-report", checks: INVARIANT_BUILTIN,
    strict: "refuses" },
  { key: "protocol", title: "Protocol endpoints (synthesized)",
    kind: "synthesized", schemaPath: "/admin-api/sts-metadata",
    schemaAuth: "dpop-console", auth: "per-op",
    checks: INVARIANT_BUILTIN, strict: "tolerates" },
  { key: "admin-api", title: "Management API",
    kind: "openapi", schemaPath: "/admin-api/openapi.json",
    schemaAuth: "dpop-console", auth: "dpop-console",
    checks: INVARIANT_BUILTIN, strict: "refuses" }
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
      "among them, so the adapter cannot drive the next operation" },
  { surface: "admin-api", match: "revokeTokensByKind",
    reason: "revokes every token of a kind (e.g. access_token), which " +
      "includes the run's own admin-api token — no username or subject the " +
      "fuzz person could avoid naming makes it miss, unlike revoke-subject / " +
      "revoke-user (kept, since the fuzz cannot name the random fuzz person). " +
      "It revoked the run's token ~2s into the 2026-11-06 admin-api cell and " +
      "the STS-API-0122 flood followed (#1299)" },
  { surface: "admin-api", match: "resetAllSettings",
    reason: "config/reset-all clears every setting override in the realm — " +
      "the DPoP headroom, the mode flag and (before the process floor) the " +
      "risk opt-out — mid-cell, which the between-cells re-assert cannot undo; " +
      "it cleared 31 settings 4.5 min into the 211fecc74 admin-api cell and " +
      "risk scoring came back on. A single config/reset or config/set is kept " +
      "(the risk and DPoP process floors hold whatever one override does)" }
];

// ---------------------------------------------------------------------------
// THE DEFAULT-REALM SERVICE CELL (#1299). The three realm profiles are
// non-default realms, so each one's admin-api token is a REALM token and the
// gate refuses every SERVICE-level operation (STS-API-0112) — the ones
// mirroring admin_scope.ts's SERVICE_PAGES (persistence, cluster, database,
// encryption, secrets, caches, worker-pools, node-health, debugger, tls,
// ldap/service, api-explorer) and the service-setting writes, ~86 routes on
// the 2026-11-06 run, refused in EVERY realm cell. To fuzz those, this one
// cell runs the admin-api surface against the DEFAULT realm (empty prefix)
// with a SERVICE admin token (the fuzz person on the default realm's roster,
// read/write/security). It runs LAST, after every realm cell, so a service op
// that disrupts the process cannot wedge a realm's cell (rcbj via iya-sts-60).
//
// Its exclusions are the admin-api surface's (inherited through exclusionsKey)
// PLUS these — the service operations that would STOP THE SERVICE or take its
// STORE, KEYS or TLS away from it. Everything else on those pages is what we
// want fuzzed, so the list is deliberately short and each entry names what it
// would take away.
const SERVICE_EXCLUSIONS = [
  { match: "rotateKek",
    reason: "rotates the key-encryption key every sealed secret is wrapped " +
      "under; re-wrapping the whole store mid-run can leave the service " +
      "unable to read its own keys" },
  { match: "reencryptDataKeys",
    reason: "runs the data re-encryption pass over the whole sealed store — a " +
      "long operation that races the run's own writes and rewrites the key " +
      "material everything is read through" },
  { match: "rotateDataKeys",
    reason: "rotates the data encryption keys, rewriting the sealed material " +
      "the store is read through" },
  { match: "stepDownScheduler",
    reason: "steps the scheduler leader down; the single-node fuzz stack is " +
      "the one node leasing the run's own jobs, so losing and reacquiring " +
      "leadership mid-cell can wedge store coordination" },
  { match: "setListeners",
    reason: "reconfigures the listeners; it can rebind or stop the port and " +
      "TLS the run is talking to" },
  { match: "setListenerApplications",
    reason: "moves which application answers on a listener; it can move the " +
      "console and /admin-api off the main port (tests/CLAUDE.md records the " +
      "same move breaking a realm-switcher test)" }
];

// The service cell's surface: the admin-api openapi document, driven against
// the default realm. `exclusionsKey` inherits the admin-api surface's five
// run-sabotage exclusions; `serviceExclusions` adds the six above.
const SERVICE_CELL = Object.freeze({
  key: "admin-api-service",
  title: "Management API (service, default realm)",
  kind: "openapi", schemaPath: "/admin-api/openapi.json",
  schemaAuth: "dpop-console", auth: "dpop-console",
  checks: INVARIANT_BUILTIN, strict: "refuses", exclusionsKey: "admin-api",
  serviceExclusions: SERVICE_EXCLUSIONS
});

// ---------------------------------------------------------------------------
// THE INFRASTRUCTURE IDENTITIES THE PROXY WILL NOT LET A CELL NAME (#1299,
// iya-sts-60, 2026-11-06). An admin-api cell holds admin:write and (with
// SECURITY_ADMIN) admin:security, so a fuzzed body can delete, forget or
// disable the very applications the run stands on — and the admin-api document
// surfaces their identifiers, so the fuzzer finds them. On the 2026-11-06 run
// the admin-api cell posted applications/forget naming sts-admin-console, the
// console client the proxy signs in as; with it gone every later token failed
// to verify (STS-API-0123 -> 0003 -> STS-API-0002, 29,079 times) and the proxy
// re-signed 402 times, 370 failing — 365 of 661 operations saw only 401/403.
// The service was RIGHT to let an administrator delete a client; the RUN cannot
// survive deleting its own feet. So auth_proxy.js refuses to FORWARD (a
// synthetic 4xx, counted and logged, never a finding — a 4xx trips no invariant
// check) any admin-api request (the per-realm cells AND the service cell) whose
// JSON body or query names, as an exact value, one of these identities or the
// fuzz person (added at the proxy from STS_SCHEMA_USER, since its name is
// random per run and so cannot be a constant here). The four clients are
// iya-sts-60's; the four resource/surface identities are the other names the
// admin-api document reaches that a cell needs — sts-management-api is the
// audience the cell's OWN /admin-api token is bound to, so forgetting it breaks
// the cell as surely as deleting its sign-in client did.
// `tests/schemathesis_plan.js` asserts each carries a reason.
const PROTECTED_CLIENTS = Object.freeze([
  { name: "sts-admin-console",
    reason: "the public console client the admin-api proxy signs in as; " +
      "deleting it (applications/forget, as the 2026-11-06 run did) leaves " +
      "every later token unverifiable and the proxy unable to re-sign" },
  { name: "sts-api-client",
    reason: "the bootstrap/management client the kit mints the run's " +
      "admin-api token with (pinned by adminApi.clientSecret); deleting it " +
      "stops the run minting or renewing that token" },
  { name: "sts-user-portal",
    reason: "the public portal client the account-api cell signs in as; " +
      "deleting it breaks that cell's sign-in" },
  { name: "sts-report",
    reason: "the public reports client the report-api cell signs in as; " +
      "deleting it breaks that cell's sign-in" },
  { name: "sts-management-api",
    reason: "the resource server for /admin-api; the admin-api cell's own " +
      "token is audienced to it, so forgetting it breaks the cell's " +
      "authentication as surely as deleting its sign-in client" },
  { name: "sts-account-api",
    reason: "the resource server for /account-api, the audience the " +
      "account-api cell's token is bound to" },
  { name: "sts-report-api",
    reason: "the resource server for /report-api, the audience the " +
      "report-api cell's token is bound to" },
  { name: "sts-debugger-ui",
    reason: "the debugger console's public client, a seeded hosted-surface " +
      "client the admin-api document names; deleting a hosted-surface client " +
      "removes infrastructure the service seeds" }
]);

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

// ---------------------------------------------------------------------------
// WHAT A GET DOES WITH A NAME IT DOES NOT TAKE (#1476 for `/admin-api`, #1483
// for the other three published APIs and the protocol endpoints, rcbj
// 2026-11-09). Schemathesis sends what the document declares, so a parameter
// or header nothing declares is the one request it never makes. These probes
// make it, on every GET in the document, while the cell's proxy is up:
//
//   unknown-parameter   one query parameter nothing declares        400
//   wrong-type          a declared integer holding a word            400
//   garbage-header      a custom header no specification defines     400
//   standard-header     a garbage value in a standard header         no 5xx
//
// A refusal carries no error code. A gate's 401 or 403 means the request
// never reached the check, and is counted rather than called a miss: a realm's
// administrator is refused the process-wide operations, and that is correct.
//
// THE PROTOCOL SURFACE IS THE OTHER CASE (`strict: "tolerates"`): a protocol
// endpoint is its specification's, and several say to ignore an unknown
// parameter. The same garbage goes to its GETs and the answer is held only to
// no 5xx (501, a deliberate Not Implemented, excepted) and no leaked code: a
// 200 passes. Nothing about those endpoints changes for this.
// ---------------------------------------------------------------------------
const STRICT_UNKNOWN_PARAMETER = "sts_garbage";
const STRICT_GARBAGE_VALUE = "%%%{{<garbage>}}~";
const STRICT_FINDING = "strict_request_miss";
const LEAKED_CODE = /STS-[A-Z0-9]+-\d{4}/;

// THE PROTOCOL GETS THAT ARE NOT PROBED (#1483), exact templates of the
// synthesized document. `{as}` is an embedded authorization server's prefix.
// A probe carries no credential and no cookie (auth "per-op"), so none of
// these can end a session on one; they are held back because each is
// specified to end a browser's sign-on, and a cell that exists to prove it did
// no damage does not ask a sign-out endpoint for its opinion of a garbage
// parameter. Everything else in the document is probed.
const PROTOCOL_PROBE_EXCLUSIONS = [
  { template: "/oauth2/logout",
    reason: "RP-Initiated Logout: a GET ends the browser's sign-on session" },
  { template: "/{as}/oauth2/logout",
    reason: "RP-Initiated Logout at an embedded authorization server: a GET " +
      "ends the browser's sign-on session" },
  { template: "/saml2/slo",
    reason: "SAML 2.0 Single Logout's GET binding, which ends a session it " +
      "names" },
  { template: "/saml2/slo/{sp}",
    reason: "SAML 2.0 Single Logout's GET binding for one service provider, " +
      "which ends a session it names" },
  { template: "/federation/slo/{id}",
    reason: "a federation partner's Single Logout entry, which ends the " +
      "session the partner names" },
  { template: "/federation/frontchannel-logout/{id}",
    reason: "OpenID Connect Front-Channel Logout's GET at a partner, which " +
      "ends the session it names" }
];

function protocolProbeExcluded(template) {
  log.debug("Entering protocolProbeExcluded().");
  const excluded = PROTOCOL_PROBE_EXCLUSIONS.some(function (one) {
    return one.template === template;
  });
  log.debug("Leaving protocolProbeExcluded(). " + excluded);
  return excluded;
}

// The requests one GET of the document is probed with. Pure, so that
// tests/schemathesis_plan.js can hold the plan without a stack.
function strictRequestProbes(document, options) {
  log.debug("Entering strictRequestProbes().");
  const out = [];
  const opts = options || {};
  const paths = (document && document.paths) || {};
  Object.keys(paths).sort().forEach(function (template) {
    const get = paths[template] && paths[template].get;
    if (!get) {
      return;
    }
    if (opts.tolerates && protocolProbeExcluded(template)) {
      return;
    }
    // A harmless value for a path parameter: the check runs before the
    // handler, so the route only has to match.
    const url = template.replace(/\{[^}]+\}/g, "fuzz-probe");
    const id = get.operationId || url;
    const parameters = get.parameters || [];
    out.push({ kind: "unknown-parameter", operationId: id, path: template,
      url: url + "?" + STRICT_UNKNOWN_PARAMETER + "=1", headers: {},
      named: STRICT_UNKNOWN_PARAMETER });
    // `integer` or zod's `anyOf` of an empty string and an integer, which is
    // how `/account-api` documents `vt.opt(vt.integer())` (#1483).
    const integer = parameters.filter(function (p) {
      const schema = (p && p.schema) || {};
      return p && p.in === "query" && (schema.type === "integer" ||
        (Array.isArray(schema.anyOf) && schema.anyOf.some(function (one) {
          return one && one.type === "integer";
        }))) && schema["x-refused-by-handler"] !== true;
    })[0];
    if (integer) {
      out.push({ kind: "wrong-type", operationId: id, path: template,
        url: url + "?" + encodeURIComponent(integer.name) + "=abc",
        headers: {}, named: integer.name });
    }
    out.push({ kind: "garbage-header", operationId: id, path: template,
      url: url, headers: { "X-Sts-Garbage": STRICT_GARBAGE_VALUE },
      named: "x-sts-garbage" });
    out.push({ kind: "standard-header", operationId: id, path: template,
      url: url, headers: { "Accept-Language": STRICT_GARBAGE_VALUE } });
  });
  log.debug("Leaving strictRequestProbes(). " + out.length + ".");
  return out;
}

// What one probe's answer means: null for an answer that is right, `gate`
// for a request a gate stopped, otherwise the finding's detail. Pure.
function strictRequestVerdict(kind, status, body, options) {
  log.debug("Entering strictRequestVerdict(). " + kind + " " + status);
  const opts = options || {};
  let verdict = null;
  const text = String(body || "");
  if (opts.tolerates) {
    // A protocol endpoint (#1483): no 5xx and no leaked code, and that is all.
    if (status === 0 || (status >= 500 && status !== 501)) {
      verdict = kind + " answered " + status;
    } else if (status >= 400 && LEAKED_CODE.test(text)) {
      verdict = "a refusal carried an error code";
    }
  } else if (status === 401 || status === 403) {
    verdict = "gate";
  } else if (status >= 400 && LEAKED_CODE.test(text)) {
    verdict = "a refusal carried an error code";
  } else if (kind === "standard-header") {
    verdict = status >= 500 ? "a standard header answered " + status : null;
  } else if (status !== 400) {
    verdict = kind + " answered " + status + ", not 400";
  } else if (opts.named && text.indexOf(opts.named) < 0) {
    // A 400 NAMING SOMETHING ELSE IS NOT THE REFUSAL (#1483): a GET of
    // `/authn-api/pending/fuzz-probe` answers 400 for the id that does not
    // exist, with or without the garbage, and passing it would be a gate
    // that checked nothing.
    verdict = kind + " answered 400 and did not name " + opts.named;
  }
  log.debug("Leaving strictRequestVerdict().");
  return verdict;
}

// One request to the cell's proxy; the proxy signs it.
function strictRequest(port, url, headers) {
  log.debug("Entering strictRequest().");
  return new Promise(function (resolve) {
    const req = http.request({ host: "127.0.0.1", port: port, path: url,
      method: "GET", headers: Object.assign({ accept: "application/json" },
        headers), timeout: 60000 }, function (res) {
      let text = "";
      res.setEncoding("utf8");
      res.on("data", function (chunk) {
        text += chunk;
      });
      res.on("end", function () {
        log.debug("Leaving strictRequest(). " + res.statusCode);
        resolve({ status: res.statusCode || 0, text: text });
      });
    });
    req.on("timeout", function () {
      req.destroy(new Error("timed out"));
    });
    req.on("error", function (e) {
      log.debug("Caught in strictRequest(): " + ((e && e.message) || e));
      log.debug("Leaving strictRequest(). No answer.");
      resolve({ status: 0, text: String((e && e.message) || e) });
    });
    req.end();
  });
}

// Every GET in the cell's document, probed through the cell's proxy. Answers
// the findings; a document that cannot be read, or one where every probe was
// stopped by a gate, is itself a finding, because a gate that checked nothing
// must not read as a gate that passed.
async function probeStrictRequests(port, surface, say, synthesized) {
  log.debug("Entering probeStrictRequests(). " + surface.key);
  const tolerates = surface.strict === "tolerates";
  // The synthesized document exists only in this process, and the proxy's
  // `/admin-api/sts-metadata` is not it.
  const documentAnswer = synthesized
    ? { status: 200, text: JSON.stringify(synthesized) }
    : await strictRequest(port, surface.schemaPath, {});
  let document = null;
  try {
    document = JSON.parse(documentAnswer.text);
  } catch (e) {
    log.debug("Caught parsing the cell's document: " +
              ((e && e.message) || e));
  }
  const probes = strictRequestProbes(document, { tolerates: tolerates });
  if (documentAnswer.status !== 200 || !probes.length) {
    log.debug("Leaving probeStrictRequests(). No document.");
    return [{ kind: STRICT_FINDING, status: documentAnswer.status,
      route: surface.schemaPath, detail: "the document could not be read" }];
  }
  const findings = [];
  let gated = 0;
  for (let i = 0; i < probes.length; i++) {
    const probe = probes[i];
    const answer = await strictRequest(port, probe.url, probe.headers);
    const verdict = strictRequestVerdict(probe.kind, answer.status,
      answer.text, { tolerates: tolerates, named: probe.named });
    if (verdict === "gate") {
      gated = gated + 1;
    } else if (verdict) {
      findings.push({ kind: STRICT_FINDING, status: answer.status,
        method: "GET", route: probe.path, operationId: probe.operationId,
        probe: probe.kind, detail: verdict,
        body: answer.text.slice(0, 200) });
    }
  }
  if (!tolerates && gated === probes.length) {
    findings.push({ kind: STRICT_FINDING, status: 403,
      route: surface.schemaPath,
      detail: "every probe was stopped by a gate, so nothing was checked" });
  }
  say("[schemathesis] " + surface.key + ": " + probes.length +
      " strict-request probe(s), " + gated + " stopped by a gate, " +
      findings.length + " finding(s) (#1476)");
  log.debug("Leaving probeStrictRequests(). " + findings.length + ".");
  return findings;
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
  // The service cell: a known auth kind and the no-5xx invariant like every
  // surface, an exclusionsKey that names a real surface (so it inherits that
  // surface's exclusions), and every serviceExclusion carrying a reason — the
  // same rule the EXCLUSIONS carry, since a service op excluded with no reason
  // is indistinguishable from one dropped by accident (#1299).
  if (AUTH_KINDS.indexOf(SERVICE_CELL.auth) < 0) {
    problems.push("the service cell has an unknown auth kind");
  }
  if (SERVICE_CELL.checks.concat(CUSTOM_CHECKS)
    .indexOf("no_uncaught_server_error") < 0) {
    problems.push("the service cell omits the no-uncaught-5xx invariant");
  }
  if (surfaceKeys.indexOf(SERVICE_CELL.exclusionsKey) < 0) {
    problems.push("the service cell's exclusionsKey names no surface");
  }
  if (!Array.isArray(SERVICE_CELL.serviceExclusions) ||
      SERVICE_CELL.serviceExclusions.length === 0) {
    problems.push("the service cell declares no service exclusions");
  }
  (SERVICE_CELL.serviceExclusions || []).forEach(function (one) {
    if (!one.match) {
      problems.push("a service exclusion matches nothing");
    }
    if (!one.reason || one.reason.trim().length === 0) {
      problems.push("service exclusion " + one.match + " carries no reason");
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

// A RANDOM username, so the fuzzer cannot NAME the fuzz person (#1299). The
// token-revoking actions revoke-subject and revoke-user match `sub` OR
// `username` EXACTLY, and a fixed "fuzzer" is a short string the fuzzer can
// generate — which would revoke the run's own tokens. The uuid subject is
// already random; this makes the username un-nameable too, so those two
// actions stay fuzzable (iya-sts-60: fuzz them with another subject). The
// probe on 2026-11-06 confirmed a named revoke-subject/revoke-user revokes the
// token and the proxy then recovers; revoke-KIND is excluded below instead,
// because it revokes every access_token and no username makes it miss.
const FUZZ_USER = "fuzzer-" + crypto.randomBytes(4).toString("hex");
// Meets a typical product password policy: upper, lower, digit, symbol, long.
const FUZZ_PASSWORD = "Fuzz-Runner-Passw0rd!2026";
// The console roles are granted on the roster (`/admin-api/rbac/grant`,
// `rbacAction`), by their SHORT roster ids — `read`, `write`, `security`, not
// the permission names (`admin-ui/admin_rbac.ts` ROLES; an unknown id is 400,
// STS-ADMIN-0582). `write` and `security` each imply `read`, but all are
// granted for clarity.
//
// `security` is SECURITY_ADMIN (#645, #1299): without it the gate refuses every
// SECURITY CHANGE on /admin-api with STS-API-0138 — a Directory → Policies save
// or reset, a policy reference that changes, a grant of the role, an act on a
// holder's account — and console_signin ALREADY requests `admin:security`
// (narrowed off a subject that does not hold the role), so holding the role is
// the whole of what lets the cell's token carry the scope and reach those
// operations. It is a change of WHO IS ASKING, not of the service. The one
// account-ending power this adds over admin:write (which already disables and
// deletes) bites only a request that names the fuzz person, which the fuzzer's
// random usernames almost never do; the per-cell re-assert recovers the rest.
//
// The report roles are CONFIGURED roles granted on the role register by NAME
// (`/admin-api/roles/add-member`, `rolesAction`).
const FUZZ_CONSOLE_ROLES = ["read", "write", "security"];
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
// How long one Schemathesis request may take, in seconds. The CLI default
// is 10. A realm certificate-authority rebuild whose alternative key is
// SLH-DSA-SHAKE-256s finished in 21 to 33 seconds on iya-sts-fuzz-1432
// (four builds, 2026-11-09T06:33:05Z through 06:34:44Z), and one
// POST /admin-api/pki handler in that window ran 77 seconds (phase total
// 81 seconds). The client recorded each as "Read timed out after 10
// seconds" and banned the later phases. 120 covers that 81 seconds with
// margin. A true hang waits 120 seconds; coverage is one case per
// constraint, so the cost is bounded. Not an environment variable: a run
// that forgot it would fail the same way again. The algorithm stays legal
// on a realm branch (#1432 refuses it only on the process branch, #1435).
// 300 SINCE 2026-11-11: fuzz run 16's admin-api cell in fuzz-21 failed on
// one POST /admin-api/pki/build still running at 120 seconds. A rebuild
// makes about fifty signatures (three tiers, every Issuing CA, and the
// realm's signing keys re-certified), one SLH-DSA-SHAKE-256s signature
// takes 1,087 ms in the service image on an idle machine, and the fuzz
// stage's other cells hold every core. The handler was working, not hung.
const REQUEST_TIMEOUT_SECONDS = 300;
// The venv the tests image builds, or the PATH. STS_SCHEMATHESIS_DIR is the
// venv ROOT (the Dockerfile's `python3 -m venv /opt/schemathesis`), so the
// executable is `<dir>/bin/schemathesis` — no `venv` segment.
const SCHEMATHESIS_BIN = process.env.STS_SCHEMATHESIS_BIN ||
  (process.env.STS_SCHEMATHESIS_DIR
    ? path.join(process.env.STS_SCHEMATHESIS_DIR, "bin", "schemathesis")
    : "schemathesis");

function requestTimeoutArgs() {
  log.debug("Entering requestTimeoutArgs().");
  const args = ["--request-timeout", String(REQUEST_TIMEOUT_SECONDS)];
  log.debug("Leaving requestTimeoutArgs().");
  return args;
}

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
  // `settings` is the profile's FULL set — the mode flag (oauth2.rfc9700 /
  // oauth2.oauth21) AND the DPoP headroom — so reassertRealm() can put ALL of
  // it back before each cell, not just the DPoP rows (#1299). A cell that flips
  // oauth2.rfc9700 or oauth2.oauth21 off through config/set would otherwise make
  // the rest of that run a different profile while still reporting under its
  // name; those two are realmRuntime, so the same realm-scoped config door the
  // fuzzer reaches them through is the one that restores them.
  return { realmPrefix: realmPrefix, user: FUZZ_USER,
    password: FUZZ_PASSWORD, label: profile.label,
    settings: profile.settings };
}

// Creates the fuzz person on the DEFAULT realm's roster — a SERVICE admin — for
// the service cell (#1299). The default realm is the service itself, so there
// is no realm to create; the per-cell re-assert sets the password, grants
// read/write/security and the report roles, and enables the account, exactly as
// for a realm profile, through the empty prefix. `settings` is DPoP headroom
// only (no mode flag): the default realm is the product baseline. `realmLabel`
// is what the result shows, since the prefix is empty.
async function provisionServiceAdmin(serviceBase, say) {
  log.debug("Entering provisionServiceAdmin().");
  await freshAdminToken(serviceBase, say);
  const person = await adminCall(serviceBase, "", "POST",
    "/admin-api/users/create",
    { username: FUZZ_USER, attributes: FUZZ_ATTRIBUTES, credential: "none" });
  if ([200, 201, 409].indexOf(person.status) < 0) {
    throw new Error("could not create the default-realm service admin: " +
      person.status + " " + JSON.stringify(person.json).slice(0, 300));
  }
  say("[schemathesis] provisioned the default realm's service admin");
  log.debug("Leaving provisionServiceAdmin().");
  return { realmPrefix: "", realmLabel: "(default realm, service admin)",
    user: FUZZ_USER, password: FUZZ_PASSWORD,
    label: "default realm (service admin)",
    settings: Object.assign({}, FUZZ_REALM) };
}

// Re-assert the realm's known state before every cell (#1299, "start from a
// known state"): a cell's own fuzzing changes the realm, and the next cell
// starts from whatever it left. The 2026-11-06 run showed two: the admin-api
// cell changed the fuzz person's password, so report-api's sign-in answered
// STS-AUTHN-0054 (a password that does not match); and the DPoP replay cap was
// back at its 10000 default (STS-CORE-0097 / STS-OAUTH-0554), filling under the
// proof volume and refusing every proof. So before each cell, with a fresh
// token already in hand, this re-asserts the profile's WHOLE settings object
// (the mode flag oauth2.rfc9700 / oauth2.oauth21 AND the DPoP replay headroom
// and window), the fuzz person's password, and the console and configured
// roles, through the runtime doors — idempotent, and the process-env default on
// the fuzz stack's `sts` service is the fallback for a reset WITHIN a cell. The
// mode flag is widened in (#1299): a cell that flipped it off would otherwise
// run the rest of this profile as the baseline while still reporting under the
// stricter name.
// Resolves { ok, why }; the caller FAILS THE CELL LOUDLY when it is not ok.
// A random, policy-compliant password: a fixed stem guarantees an upper, a
// lower, a digit and a symbol, and the random middle keeps it out of the
// realm's password history (#1299). Never a constant — see reassertRealm().
function freshFuzzPassword() {
  log.debug("Entering freshFuzzPassword().");
  log.debug("Leaving freshFuzzPassword().");
  return "Fuzz-" + crypto.randomBytes(12).toString("base64url") + "-Aa1!";
}

async function reassertRealm(serviceBase, provisioned, say) {
  log.debug("Entering reassertRealm(). " + provisioned.realmPrefix);
  const prefix = provisioned.realmPrefix;
  // The profile's WHOLE settings object, not just the DPoP rows (#1299): the
  // mode flag (oauth2.rfc9700 / oauth2.oauth21) too, so a cell that flipped it
  // off through config/set cannot leave the rest of the run a different profile
  // under this profile's name. Both mode flags are realmRuntime, so the same
  // realm-scoped config/set-many door the fuzzer reaches them through accepts
  // them here (config.setOverride passes the ambient-realm argument;
  // common/config.js, `realmRuntime`). Falls back to FUZZ_DPOP for an in-process
  // caller that provisioned before `settings` was carried.
  const settings = provisioned.settings || FUZZ_DPOP;
  const applied = await adminCall(serviceBase, prefix, "POST",
    "/admin-api/config/set-many", settings);
  if (applied.status !== 200) {
    log.debug("Leaving reassertRealm(). set-many " + applied.status);
    return { ok: false, why: "config/set-many in " + prefix + " answered " +
      applied.status + " " + JSON.stringify(applied.json).slice(0, 200) };
  }
  // Re-ENABLE the fuzz person (#1299): a cell's own fuzzing can disable the
  // account (STS-API-0122, "the person's account disabled") — the fuzz person
  // now holds SECURITY_ADMIN, and an admin:write token always could — and a
  // disabled account refuses the next cell's sign-in before anything is fuzzed.
  // Idempotent (accountState.setDisabled(who, false) on an enabled account is
  // ok), so it runs every cell. Any WITHIN-cell disable the proxy's re-mint
  // cannot undo (it holds no admin token) is undone here at the next cell.
  const enabled = await adminCall(serviceBase, prefix, "POST",
    "/admin-api/users/enable", { user: FUZZ_USER });
  if (enabled.status !== 200) {
    log.debug("Leaving reassertRealm(). enable " + enabled.status);
    return { ok: false, why: "users/enable in " + prefix + " answered " +
      enabled.status + " " + JSON.stringify(enabled.json).slice(0, 200) };
  }
  // A FRESH password every re-assert, never a constant: the realm's password
  // policy refuses the current password and the five before it
  // (password-history), so re-setting FUZZ_PASSWORD failed every cell after the
  // first. The new one is set, then becomes provisioned.password, which the
  // proxy child (STS_SCHEMA_PASSWORD) and console_signin / portal_signin /
  // report_signin all sign in with — so the account's one password and every
  // sign-in's agree, and nothing holds a stale constant. The realm's policy is
  // NOT weakened: product baseline is what is under test, and this is a
  // random policy-compliant value.
  const nextPassword = freshFuzzPassword();
  const password = await adminCall(serviceBase, prefix, "POST",
    "/admin-api/users/set-password",
    { user: FUZZ_USER, password: nextPassword });
  if (password.status !== 200) {
    log.debug("Leaving reassertRealm(). set-password " + password.status);
    return { ok: false, why: "users/set-password in " + prefix +
      " answered " + password.status + " " +
      JSON.stringify(password.json).slice(0, 200) };
  }
  provisioned.password = nextPassword;
  for (let i = 0; i < FUZZ_CONSOLE_ROLES.length; i++) {
    const granted = await adminCall(serviceBase, prefix, "POST",
      "/admin-api/rbac/grant",
      { username: FUZZ_USER, role: FUZZ_CONSOLE_ROLES[i] });
    if (granted.status !== 200) {
      log.debug("Leaving reassertRealm(). grant " + granted.status);
      return { ok: false, why: "granting " + FUZZ_CONSOLE_ROLES[i] + " in " +
        prefix + " answered " + granted.status + " " +
        JSON.stringify(granted.json).slice(0, 200) };
    }
  }
  for (let i = 0; i < FUZZ_CONFIGURED_ROLES.length; i++) {
    const member = await adminCall(serviceBase, prefix, "POST",
      "/admin-api/roles/add-member",
      { role: FUZZ_CONFIGURED_ROLES[i], kind: "user", member: FUZZ_USER });
    // Already holding it is the state this asks for, and this door refuses
    // the second add (400 "already holds"), where rbac/grant answers 200.
    const holds = member.status === 400 &&
      /already holds/.test(JSON.stringify(member.json));
    if (member.status !== 200 && !holds) {
      log.debug("Leaving reassertRealm(). add-member " + member.status);
      return { ok: false, why: "adding " + FUZZ_USER + " to " +
        FUZZ_CONFIGURED_ROLES[i] + " in " + prefix + " answered " +
        member.status + " " + JSON.stringify(member.json).slice(0, 200) };
    }
  }
  say("[schemathesis] re-asserted " + prefix + ": DPoP headroom, the fuzz " +
    "person's password and its roles");
  log.debug("Leaving reassertRealm(). ok");
  return { ok: true, why: "" };
}

// The two DPoP settings' values in force in a realm, walked out of a
// `GET /admin-api/config` answer (groups[].settings[] with key and value),
// wherever the document nests them. Null for a key the answer did not carry.
function dpopSettingsOf(json) {
  log.debug("Entering dpopSettingsOf().");
  const found = { "oauth2.dpopReplayCacheSize": null,
    "oauth2.dpopIatSkewS": null };
  function walk(node) {
    if (!node || typeof node !== "object") {
      return;
    }
    if (typeof node.key === "string" &&
        Object.prototype.hasOwnProperty.call(found, node.key) &&
        found[node.key] === null) {
      found[node.key] = node.value;
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
  log.debug("Leaving dpopSettingsOf().");
  return found;
}

// Reads the two DPoP settings back at a cell's end and logs them (#1299). A
// value other than FUZZ_DPOP's means the cell's own fuzzing reset the setting
// mid-cell. Best-effort: a read that fails is logged and nothing else.
async function logDpopSettings(serviceBase, provisioned, surfaceKey, say) {
  log.debug("Entering logDpopSettings().");
  try {
    const after = await adminCall(serviceBase, provisioned.realmPrefix, "GET",
      "/admin-api/config");
    if (after.status !== 200) {
      say("[schemathesis] " + surfaceKey + " @ " + provisioned.realmPrefix +
        " ended; could not read the DPoP settings back (" + after.status + ")");
      log.debug("Leaving logDpopSettings(). " + after.status);
      return;
    }
    const seen = dpopSettingsOf(after.json);
    say("[schemathesis] " + surfaceKey + " @ " + provisioned.realmPrefix +
      " ended; DPoP settings in force: oauth2.dpopReplayCacheSize=" +
      seen["oauth2.dpopReplayCacheSize"] + " (wanted " +
      FUZZ_DPOP["oauth2.dpopReplayCacheSize"] + "), oauth2.dpopIatSkewS=" +
      seen["oauth2.dpopIatSkewS"] + " (wanted " +
      FUZZ_DPOP["oauth2.dpopIatSkewS"] + ")");
  } catch (e) {
    log.debug("Caught in logDpopSettings(): " + ((e && e.message) || e));
  }
  log.debug("Leaving logDpopSettings().");
}

// What a read of `/admin-api/persistence` says is wrong with the store, or
// '' when nothing is. Only `healthy: false` is a finding: an answer that could
// not be read says nothing about the store.
function storeProblemOf(answer) {
  log.debug("Entering storeProblemOf().");
  const body = answer && answer.status === 200 ? answer.json : null;
  if (!body || body.healthy !== false) {
    log.debug("Leaving storeProblemOf(). Nothing to report.");
    return "";
  }
  log.debug("Leaving storeProblemOf(). Failing.");
  return String(body.lastError || "the store reports itself unhealthy");
}

// IS THE STORE STILL WRITING WHEN THE CELL ENDS (#1463). A failed commit is
// answered 503 with Retry-After, which no_uncaught_server_error allows, so a
// value that stopped every write in the process passed as a clean cell. One
// failed flush clears itself, so a failure is asked about three times, five
// seconds apart, and only one that outlasts them is a finding. The token is
// the service's, in the default realm: a realm's own may not read this page.
async function storeFailing(serviceBase, surfaceKey, realmShown, say) {
  log.debug("Entering storeFailing().");
  let problem = "";
  for (let attempt = 0; attempt < 3; attempt++) {
    if (attempt) {
      await new Promise(function (resolve) {
        setTimeout(resolve, 5000);
      });
    }
    try {
      problem = storeProblemOf(await adminCall(serviceBase, "", "GET",
        "/admin-api/persistence"));
    } catch (e) {
      log.debug("Caught in storeFailing(): " + ((e && e.message) || e));
      problem = "";
    }
    if (!problem) {
      log.debug("Leaving storeFailing(). Writing.");
      return "";
    }
  }
  say("[schemathesis] " + surfaceKey + " @ " + realmShown +
    ": THE STORE IS NOT WRITING at the end of this cell: " + problem);
  log.debug("Leaving storeFailing(). Failing.");
  return problem;
}

// How many realms' cells run at once: STS_SCHEMATHESIS_REALMS, every realm
// by default, and 1 for the order this mode always had (#1502).
function realmConcurrency() {
  log.debug("Entering realmConcurrency().");
  const asked = parseInt(process.env.STS_SCHEMATHESIS_REALMS || "", 10);
  log.debug("Leaving realmConcurrency().");
  return asked > 0 ? asked : PROFILES.length;
}

// Runs `task` over `items`, at most `width` at once. A task that rejects
// rejects the whole, after the ones already running have settled.
async function boundedMap(items, width, task) {
  log.debug("Entering boundedMap(). " + width);
  let next = 0;
  async function lane() {
    while (next < items.length) {
      const item = items[next];
      next += 1;
      await task(item);
    }
  }
  const lanes = [];
  for (let i = 0; i < Math.min(width, items.length); i++) {
    lanes.push(lane());
  }
  await Promise.all(lanes);
  log.debug("Leaving boundedMap().");
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
  // What a result and the log show for the realm: the default-realm service
  // cell has an empty prefix, so it carries a readable label instead (#1299).
  const realmShown = provisioned.realmLabel || provisioned.realmPrefix;
  // A fresh token before every cell, and BEFORE the proxy is spawned so the
  // child inherits it in `process.env`: a cell is ~25 min and the token lasts
  // an hour, so a realm's third cell otherwise fuzzes with an expired token
  // and console_signin's /admin-api account-ensure answers 401 (#1299).
  await freshAdminToken(serviceBase, say);
  // Re-assert the realm's known state before the cell, and FAIL THE CELL
  // LOUDLY if it cannot be done (#1299): a previous cell's fuzzing can change
  // the fuzz person's password or the realm's DPoP settings, and the next cell
  // starts from whatever it left.
  const reasserted = await reassertRealm(serviceBase, provisioned, say);
  if (!reasserted.ok) {
    log.debug("Leaving runSurface(). re-assert failed");
    return { surface: surface.key, realm: provisioned.realmPrefix,
      code: null, status: "error", findings: [],
      output: "could not re-assert the realm's known state before the " +
        surface.key + " cell (#1299, start from a known state): " +
        reasserted.why };
  }
  const port = await freePort();
  const proxyEnv = Object.assign({}, process.env, {
    STS_SCHEMA_PROXY_PORT: String(port),
    STS_SCHEMA_SERVICE_BASE: serviceBase,
    STS_SCHEMA_REALM_PREFIX: provisioned.realmPrefix,
    STS_SCHEMA_SURFACE: surface.key,
    STS_SCHEMA_AUTH: surface.auth,
    STS_SCHEMA_USER: provisioned.user,
    STS_SCHEMA_PASSWORD: provisioned.password,
    // The infrastructure identities the proxy refuses to forward a naming of
    // (#1299); the fuzz person is added at the proxy from STS_SCHEMA_USER.
    STS_SCHEMA_PROTECTED: PROTECTED_CLIENTS.map(function (one) {
      return one.name;
    }).join(",") });
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
    // The synthesized protocol document, kept for the probes after the run.
    let synthesizedDoc = null;
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
      synthesizedDoc = doc;
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
      "--checks", enabledChecks.join(","), "-n", String(MAX_EXAMPLES)]
      .concat(requestTimeoutArgs());
    // The surface's own run-sabotage exclusions (the service cell inherits the
    // admin-api surface's through exclusionsKey) plus any serviceExclusions it
    // carries (#1299, the default-realm service cell).
    exclusionsFor(surface.exclusionsKey || surface.key)
      .concat(surface.serviceExclusions || []).forEach(function (one) {
        args.push("--exclude-operation-id", one.match);
      });
    // Each custom check appends its finding (route, status, code, body
    // snippet) as a JSON line here, so the run emits the authoritative
    // route->code list the per-cell summary omits — the 40000-char output tail
    // below drops the per-failure detail on a large cell (#1347's leak-sink
    // work reads this). A per-(surface, realm) file so cells never collide.
    const realmSlug = (realmShown || "default").replace(/[^A-Za-z0-9]+/g, "_");
    const findingsPath = path.join(workDir,
      "findings-" + surface.key + "_" + realmSlug + ".jsonl");
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
    say("[schemathesis] " + surface.key + " @ " + realmShown +
      ": " + SCHEMATHESIS_BIN + " " + args.join(" "));
    const run = await runSchemathesis(SCHEMATHESIS_BIN, args, runEnv, workDir);
    // Read the two DPoP settings back now the cell has run, and log them: the
    // re-assert set them at the cell's START, so a value here that is not
    // FUZZ_DPOP's is the cell's own fuzzing having reset them mid-cell (#1299),
    // which is the remaining explanation for a replay cache that filled. A
    // diagnostic only; it changes nothing and never fails the cell.
    await logDpopSettings(serviceBase, provisioned, surface.key, say);
    const storeProblem = await storeFailing(serviceBase, surface.key,
      realmShown, say);
    const code = run.status;
    let status = storeProblem ? "fail"
      : (code === 0 ? "pass" : (code === 1 ? "fail" : "error"));
    // WHAT THE DOCUMENT DOES NOT SAY (#1476): the probes Schemathesis cannot
    // make, while this cell's proxy is up. A miss fails the cell.
    let strictFindings = [];
    if (surface.strict) {
      strictFindings = await probeStrictRequests(port, surface, say,
        surface.kind === "synthesized" ? synthesizedDoc : null);
      if (strictFindings.length && status === "pass") {
        status = "fail";
      }
    }
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
    if (storeProblem) {
      findings.push({ kind: "store_not_writing", realm: realmShown,
        surface: surface.key, route: "(the persistence store)", status: 503,
        detail: storeProblem, body: "" });
    }
    // The scope is the four invariants, so a failing run prints only the real
    // findings (a 5xx, a leaked error code, a dropped frame-ancestors clause).
    // Keep a generous slice so each finding's endpoint and the custom check's
    // message — which names the leaked code — survive into the host log.
    return { surface: surface.key, realm: realmShown,
      code: code, status: status, findings: findings.concat(strictFindings),
      output: (((run.stdout || "") + (run.stderr || "")).slice(-40000)) +
        spawnError };
  } finally {
    // Surface the proxy's recovery behaviour into the run log (#1299,
    // iya-sts-60): its stdio is piped to proxyOut and was otherwise shown only
    // when it failed to listen, so a re-sign storm or a re-sign that kept
    // throwing was invisible. Report how many times it re-signed in and how
    // many of those failed — a large count is the admin-api cell breaking its
    // own sign-in (a policy it rewrote now demands MFA).
    try {
      const lines = proxyOut.split("\n");
      const resigns = lines.filter(function (l) {
        return /re-signing in/.test(l);
      }).length;
      const failed = lines.filter(function (l) {
        return /re-sign-in failed|sign-in threw/.test(l);
      }).length;
      if (resigns || failed) {
        say("[schemathesis] " + surface.key + " @ " + realmShown +
          ": proxy re-signed in " + resigns + " time(s), " + failed +
          " failed" + (failed ? " (sign-in blocked — see proxy tail): " +
            lines.filter(function (l) {
              return /re-sign-in failed|sign-in threw/.test(l);
            }).slice(-3).join(" | ").slice(-400) : ""));
      }
      // The infrastructure-name guard (#1299): how many requests the proxy
      // refused to forward because they named a protected identity, broken
      // down by the name. A non-zero count is the cell having TRIED to delete
      // or disable what the run stands on — not a finding, but worth seeing.
      const guarded = lines.filter(function (l) {
        return /guard: not forwarding/.test(l);
      });
      if (guarded.length) {
        const names = {};
        guarded.forEach(function (l) {
          const m = /names ([^)]+)\)/.exec(l);
          if (m) {
            names[m[1]] = (names[m[1]] || 0) + 1;
          }
        });
        say("[schemathesis] " + surface.key + " @ " + realmShown +
          ": guard refused " + guarded.length + " request(s) naming " +
          "protected infrastructure: " + Object.keys(names).map(function (n) {
            return n + " x" + names[n];
          }).join(", "));
      }
    } catch (e) {
      log.debug("Caught surfacing the proxy log: " + ((e && e.message) || e));
    }
    proxy.kill();
  }
}

// The cells a caller named, or null for the whole matrix. Keys match a
// surface or the service cell exactly: `admin-api` does not select
// `admin-api-service`. Empty and unset are the whole matrix (#1416).
function selectedSurfaces() {
  log.debug("Entering selectedSurfaces().");
  const raw = String(process.env.STS_SCHEMATHESIS_SURFACES || "").trim();
  if (!raw) {
    log.debug("Leaving selectedSurfaces(). Every surface.");
    return null;
  }
  const wanted = {};
  raw.split(",").forEach(function (one) {
    const key = one.trim();
    if (key) {
      wanted[key] = true;
    }
  });
  log.debug("Leaving selectedSurfaces(). " + Object.keys(wanted).join(","));
  return wanted;
}

// The whole matrix: every surface of every realm profile. Resolves the list
// of per-(realm, surface) results. `STS_SCHEMATHESIS_SURFACES` narrows it
// to the named cells; the realms are still provisioned.
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
  const only = selectedSurfaces();
  if (only) {
    const known = {};
    SURFACES.forEach(function (one) {
      known[one.key] = true;
    });
    known[SERVICE_CELL.key] = true;
    const unknown = Object.keys(only).filter(function (key) {
      return !known[key];
    });
    if (unknown.length) {
      throw new Error("STS_SCHEMATHESIS_SURFACES names " +
        unknown.join(", ") + ", which is not a surface. The surfaces are " +
        Object.keys(known).join(", ") + ".");
    }
    say("[schemathesis] running only " + Object.keys(only).join(", ") + ".");
  }
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
  // THE REALMS OVERLAP (#1502): they are isolated from each other, so one
  // realm's cells cannot disturb another's, and `admin-api`'s three cells are
  // nearly all of this mode's time. A realm's OWN surfaces stay in order: the
  // ordering above is what stops one surface breaking the next.
  async function runRealm(profile) {
    log.debug("Entering runRealm(). " + profile.realm);
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
      return;
    }
    for (let s = 0; s < SURFACES.length; s++) {
      if (only && !only[SURFACES[s].key]) {
        continue;
      }
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
    log.debug("Leaving runRealm(). " + profile.realm);
  }
  await boundedMap(PROFILES, realmConcurrency(), runRealm);
  // THE DEFAULT-REALM SERVICE CELL, LAST (#1299): the admin-api surface against
  // the default realm with a SERVICE admin token, so the ~86 service-level
  // operations every realm cell's realm token is refused (STS-API-0112) are
  // fuzzed. Run after every realm cell so a service op that disrupts the
  // process cannot wedge a realm's cell; a failure here is this cell's error
  // and ends nothing (the realm cells have all run). Skipped only when a
  // surface filter is set and does not name this cell exactly.
  if (!only || only[SERVICE_CELL.key]) {
  try {
    const serviceAdmin = await provisionServiceAdmin(serviceBase, say);
    let result;
    try {
      result = await runSurface(serviceBase, serviceAdmin, SERVICE_CELL,
        workDir, say);
    } catch (e) {
      log.warn("the service cell threw: " + ((e && e.message) || e));
      result = { surface: SERVICE_CELL.key,
        realm: "(default realm, service admin)", code: null, status: "error",
        findings: [], output: "the service cell threw: " +
          ((e && e.message) || e) };
    }
    record(result);
  } catch (e) {
    log.warn("provisioning the service admin failed: " + ((e && e.message) ||
      e));
    record({ surface: SERVICE_CELL.key,
      realm: "(default realm, service admin)", code: null, status: "error",
      findings: [], output: "provisioning the default-realm service admin " +
        "failed: " + ((e && e.message) || e) });
  }
  }
  log.debug("Leaving run(). " + results.length + " result(s)");
  return results;
}

module.exports = {
  storeProblemOf: storeProblemOf,
  boundedMap: boundedMap,
  realmConcurrency: realmConcurrency,
  PROFILES: PROFILES,
  SURFACES: SURFACES,
  SERVICE_CELL: SERVICE_CELL,
  SERVICE_EXCLUSIONS: SERVICE_EXCLUSIONS,
  PROTECTED_CLIENTS: PROTECTED_CLIENTS,
  AUTH_KINDS: AUTH_KINDS,
  BUILTIN_CHECKS: BUILTIN_CHECKS,
  CUSTOM_CHECKS: CUSTOM_CHECKS,
  REQUEST_TIMEOUT_SECONDS: REQUEST_TIMEOUT_SECONDS,
  requestTimeoutArgs: requestTimeoutArgs,
  EXCLUSIONS: EXCLUSIONS,
  surfaceNamed: surfaceNamed,
  exclusionsFor: exclusionsFor,
  knownChecks: knownChecks,
  validate: validate,
  openApiPathOf: openApiPathOf,
  extractRows: extractRows,
  synthesizeProtocolDoc: synthesizeProtocolDoc,
  provision: provision,
  provisionServiceAdmin: provisionServiceAdmin,
  STRICT_FINDING: STRICT_FINDING,
  PROTOCOL_PROBE_EXCLUSIONS: PROTOCOL_PROBE_EXCLUSIONS,
  protocolProbeExcluded: protocolProbeExcluded,
  strictRequestProbes: strictRequestProbes,
  strictRequestVerdict: strictRequestVerdict,
  runSurface: runSurface,
  run: run
};
