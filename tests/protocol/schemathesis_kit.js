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
const FUZZ_ROLES = ["ADMIN_READ", "ADMIN_WRITE", "REPORT_USE", "REPORT_ADMIN"];
// The four APIs are fuzzed from their real schemas, so the synthesized
// protocol document leaves their paths out.
const API_BASES = ["/account-api", "/admin-api", "/authn-api", "/report-api"];
const PROXY_SCRIPT = path.join(__dirname, "..", "schemathesis",
  "auth_proxy.js");
const HOOKS_FILE = path.join(__dirname, "..", "schemathesis", "sts_checks.py");
const MAX_EXAMPLES = parseInt(
  process.env.STS_SCHEMATHESIS_MAX_EXAMPLES || "50", 10);
// The venv the tests image builds (build-schemathesis.sh), or the PATH.
const SCHEMATHESIS_BIN = process.env.STS_SCHEMATHESIS_BIN ||
  (process.env.STS_SCHEMATHESIS_DIR
    ? path.join(process.env.STS_SCHEMATHESIS_DIR, "venv", "bin",
                "schemathesis")
    : "schemathesis");

// The management API's bearer token the launcher minted for this run.
function adminToken() {
  log.debug("Entering adminToken().");
  log.debug("Leaving adminToken().");
  return process.env.STS_ADMIN_API_TOKEN || "";
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
  const response = await fetch(url, init);
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

// Creates the profile's realm (with its mode overrides), a fuzz person, their
// password and the four roles the gated surfaces need. Cross-realm admin-token
// behaviour is confirmed at the end-to-end run. Resolves the sign-in facts.
async function provision(serviceBase, profile, say) {
  log.debug("Entering provision(). " + profile.realm);
  const realmPrefix = "/realm/" + profile.realm;
  const made = await adminCall(serviceBase, "", "POST",
    "/admin-api/realms/create",
    { id: profile.realm, overrides: profile.settings });
  if ([200, 201, 409].indexOf(made.status) < 0) {
    throw new Error("could not create realm " + profile.realm + ": " +
      made.status + " " + JSON.stringify(made.json).slice(0, 300));
  }
  const person = await adminCall(serviceBase, realmPrefix, "POST",
    "/admin-api/users/create", { username: FUZZ_USER, invent: true });
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
  for (let i = 0; i < FUZZ_ROLES.length; i++) {
    const granted = await adminCall(serviceBase, realmPrefix, "POST",
      "/admin-api/roles/add-member",
      { role: FUZZ_ROLES[i], kind: "user", member: FUZZ_USER });
    if (granted.status !== 200) {
      // A missing role is not fatal: the surface that needs it will fail its
      // own sign-in, which the run reports.
      say("[schemathesis] WARNING: granting " + FUZZ_ROLES[i] + " in " +
        profile.realm + " answered " + granted.status);
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

// Runs Schemathesis against one surface of one realm, through a proxy of its
// own. Resolves { surface, realm, code, status, output }.
async function runSurface(serviceBase, provisioned, surface, workDir, say) {
  log.debug("Entering runSurface(). " + surface.key);
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
        code: null, status: "error",
        output: "the auth proxy did not listen: " + proxyOut.slice(-600) };
    }
    let schemaLocation;
    if (surface.kind === "synthesized") {
      const metadata = await adminCall(serviceBase, provisioned.realmPrefix,
        "GET", surface.schemaPath, null);
      const doc = synthesizeProtocolDoc(extractRows(metadata.json));
      schemaLocation = path.join(workDir, "protocol" +
        provisioned.realmPrefix.replace(/[^A-Za-z0-9]+/g, "_") + ".json");
      fs.writeFileSync(schemaLocation, JSON.stringify(doc));
    } else {
      schemaLocation = "http://127.0.0.1:" + port + surface.schemaPath;
    }
    const base = "http://127.0.0.1:" + port;
    const args = ["run", schemaLocation, "--url", base, "--checks", "all",
      "-n", String(MAX_EXAMPLES)];
    const excludeChecks = BUILTIN_CHECKS.filter(function (check) {
      return surface.checks.indexOf(check) < 0;
    });
    if (excludeChecks.length) {
      args.push("--exclude-checks", excludeChecks.join(","));
    }
    exclusionsFor(surface.key).forEach(function (one) {
      args.push("--exclude-operation-id", one.match);
    });
    const runEnv = Object.assign({}, process.env,
      { SCHEMATHESIS_HOOKS: HOOKS_FILE });
    say("[schemathesis] " + surface.key + " @ " + provisioned.realmPrefix +
      ": " + SCHEMATHESIS_BIN + " " + args.join(" "));
    const run = childProcess.spawnSync(SCHEMATHESIS_BIN, args,
      { env: runEnv, encoding: "utf8", cwd: workDir,
        maxBuffer: 64 * 1024 * 1024 });
    const code = run.status;
    const status = code === 0 ? "pass" : (code === 1 ? "fail" : "error");
    log.debug("Leaving runSurface(). " + status + " (" + code + ")");
    return { surface: surface.key, realm: provisioned.realmPrefix,
      code: code, status: status,
      output: ((run.stdout || "") + (run.stderr || "")).slice(-4000) };
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
  if (!adminToken()) {
    throw new Error("STS_ADMIN_API_TOKEN is required; the launcher mints it");
  }
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "sts-schemathesis-"));
  const results = [];
  for (let p = 0; p < PROFILES.length; p++) {
    const provisioned = await provision(serviceBase, PROFILES[p], say);
    for (let s = 0; s < SURFACES.length; s++) {
      results.push(await runSurface(serviceBase, provisioned, SURFACES[s],
        workDir, say));
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
