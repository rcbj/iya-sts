// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: schemathesis_pep.js
//
// ===========================================================================
// THE REMOTE XACML PEP'S HALF OF THE SCHEMATHESIS PLAN (rcbj, 2026-11-16:
// "Build a fuzzing test for all documented endpoints (within the model) for
// the Remote XACML PEP", and "model it after the iya-sts data fuzzing test").
//
// The four documents `models/pep/` generates (#1830) are fuzzed by the SAME
// job, the same kit and the same verdict as the service's APIs
// (sts_schemathesis.js, schemathesis_kit.js). This file holds what is the
// PEP's: its surfaces, how each is authenticated, the checks each runs, what
// is not fuzzed and why, and the provisioning a PEP surface needs before it
// can answer anything but a refusal. The kit requires this file and runs its
// cells; this file requires nothing of the kit, so the two cannot cycle, and
// `tests/schemathesis_plan.js` asserts this PLAN without a stack.
//
// WHY ONE JOB AND NOT `sts_schemathesis_pep.js`. The PEP container is not
// optional in the fuzz stack: the `fuzz` mode layers its overlay over
// docker-compose-run-tests.yml, which starts `xacml-pep` (and `companion`,
// the application its proxy fronts) in EVERY local mode, and run-tests.sh
// generates its assertion key in every mode (mintThePepCredential()). What is
// optional is only that nothing in the fuzz mode REGISTERED it — the job that
// does, sts_xacml_remote_pep.js, is not in the fuzz mode's filter — so this
// file does that registration itself (`provisionPepLane()`). A separate job
// would need its own provisioning of the same realms, its own token minting
// and its own verdict line, and the fuzz mode's filter (stsModeJobFilter():
// `schemathesis`) would have to grow; one job keeps one verdict, which is
// what rcbj asked of the data fuzzing test.
//
// THE TWO KINDS OF CELL.
//
//   * PER REALM (`PEP_REALM_SURFACES`): the CONTROL PLANE, which the SERVICE
//     serves to PEPs (`/xacml/pep/*`, `POST /xacml/pip`). It is per realm, so
//     it runs in each of the three realm profiles (product baseline, RFC 9700,
//     OAuth 2.1), in that realm's lane, before the realm's admin-api cell
//     (which can only break itself, the kit's ordering rule).
//   * ONE PEP LANE (`PEP_CELLS`): the PEP CONTAINER's own three documents —
//     its API, its AuthZEN edge PDP and its reverse proxy's `/.iya-pep/*`
//     paths — against the one container the stack runs, in its realm
//     (XACML_PEP_REALM, `pep-e2e`). The lane overlaps the realm lanes: it
//     touches only that realm and that container, and each fuzz realm is a
//     tree of its own.
//
// THE CONTROL PLANE IS FUZZED AS A SECOND PEP, NOT AS THE CONTAINER. A
// registration is named by the caller's credential and its body is stored on
// that PEP's row: fuzzed as the container, `POST /xacml/pep/register` would
// rewrite the container's notify URL, bias and resource and stop its nudges
// — run sabotage. Excluding `postRegister` would leave the operation
// unfuzzed; fuzzing it as a PEP of its own (an entry in `remote-peps` whose
// RFC 7523 key is certified by `issue-pep-credential`, exactly as a PEP is
// provisioned) fuzzes every operation and can harm only that row. So the
// control plane needs NO exclusion, and `PEP_EXCLUSIONS` is empty for that
// reason rather than by omission; the plan test holds that the identity is
// not the container's.
// ===========================================================================

const bunyan = require("bunyan");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const serviceTrust = require("../tools/service_trust.js");
const log = bunyan.createLogger({ name: "schemathesis_pep",
  level: process.env.LOG_LEVEL || "info" });

const REPO_ROOT = path.join(__dirname, "..", "..");
const OPENAPI_DIR = path.join(REPO_ROOT, "xacml-pep", "openapi");

// ---------------------------------------------------------------------------
// THE AUTH KINDS THE PEP SURFACES ADD to the kit's (auth_proxy.js):
//
//   dpop-pep   the control plane as a PEP: an RFC 7523 self-assertion signed
//              with the fuzz PEP's key, presented through `sts-remote-pep`
//              for a DPoP-bound `xacml:pep` token audienced to the realm's
//              `/xacml/pep`, and a fresh proof by the same key on every
//              request (htm, htu, ath, and the DPoP-Nonce retry) — what
//              rust/bins/xacml-pep/src/credential.rs does, through
//              tests/tools/pep-credential.js's minter.
//   mtls       the AuthZEN edge PDP's door: a client certificate the SERVICE
//              admits (an entry in `authzen-peps` storing it), which the PEP
//              finds on the caller list it pulls.
//   none       nothing presented: the PEP's own API and its proxy's paths take
//              no credential by design, and every `-anonymous` cell.
// ---------------------------------------------------------------------------
const PEP_AUTH_KINDS = ["dpop-pep", "mtls", "none"];

// ---------------------------------------------------------------------------
// THE CHECKS. Every PEP surface runs the kit's four invariants (no uncaught
// 5xx, no leaked error code, frame-ancestors on HTML, no outbound fetch) and,
// UNLIKE the service's surfaces, Schemathesis's three conformance checks:
// these documents are a MODEL (#1830) that the binary's and the service's
// answers are held to in their own tests (the three `the_*_model_s` tests,
// authzen_evaluation.js X, tests/model_pep.js), so an answer outside its
// documented status, content type or schema is a finding here and not the
// product-mode gating noise that kept the service's gate to the four.
// ---------------------------------------------------------------------------
// The "no hang" check, `max_response_time`, is not named here: it is not a
// --checks choice, and the kit's --max-response-time (pepBudgetArgs()) is
// what turns it on for every PEP cell.
const PEP_CONFORMANCE = Object.freeze(["status_code_conformance",
  "content_type_conformance", "response_schema_conformance"]);

// The PEP's own invariants, beside the kit's four (sts_checks.py):
//   no_internal_detail        no stack trace, panic, source path or
//                             backtrace in a body: a Rust panic is contained
//                             (STS-XPEP-0033) and a node one is caught by the
//                             fault boundary, and either leaking its text is
//                             an internal detail sent to a caller.
//   refused_unauthenticated   ONLY in an `-anonymous` cell: every operation
//                             the document gates answers one of the cell's
//                             `refusedWith` statuses, and none is answered.
const PEP_EXTRA_CHECKS = Object.freeze(["no_internal_detail"]);
const ANONYMOUS_CHECK = "refused_unauthenticated";

// THE REFUSALS THAT COME BEFORE THE GATE, which an unauthenticated call may
// meet instead of the gate's own: it is still refused, and whether the
// status is DOCUMENTED for the operation is status_code_conformance's
// question, not this one's. Each is the answer of something that runs ahead
// of every endpoint's credential check, by design.
const REFUSED_BEFORE_THE_GATE = Object.freeze([
  Object.freeze({ status: 400, reason: "the service refuses a control " +
    "character in a query value before any endpoint sees it (app.js), and " +
    "a body that does not parse in the parser" }),
  Object.freeze({ status: 413, reason: "a body over the parser's limit, " +
    "refused before any endpoint sees it (STS-HTTP-0004)" }),
  Object.freeze({ status: 415, reason: "a body in a charset or encoding " +
    "the parser does not read (STS-HTTP-0012)" }),
  Object.freeze({ status: 429, reason: "the validation doors' and the PIP's " +
    "limiters count by address BEFORE the gate (xacml.pipMaxPerWindow, " +
    "STS-XACML-0215, documented on each), and the service's per-address " +
    "ceiling (STS-CORE-0172) where it is on" })
]);

// ---------------------------------------------------------------------------
// THE SURFACES. `schemaFile` is the committed document; `target` is where
// the cell's proxy forwards:
//   service    the service, under the realm's prefix (the control plane)
//   pep-http   XACML_PEP_URL, the PEP's plain API listener (PEP_HTTP=true)
//   pep-https  XACML_PEP_HTTPS_URL, its HTTPS listener (the AuthZEN door
//              answers only there)
//   pep-proxy  XACML_PEP_PROXY_URL, the reverse proxy's plain listener
//
// `strict` decides what the kit's strictRequestProbes() hold a GET to
// (#1476, #1483), and is argued per surface in `strictReason`.
// `anonymous` names the second, unauthenticated pass: a cell of its own
// (`refusedWith` the documented refusal), or the reason none is run.
// ---------------------------------------------------------------------------
const PEP_REALM_SURFACES = Object.freeze([
  Object.freeze({ key: "pep-control-plane",
    title: "Remote PEP control plane (served by the service)",
    kind: "openapi", schemaFile: "pep-control-plane.json",
    target: "service", auth: "dpop-pep", checks: PEP_CONFORMANCE,
    strict: "tolerates",
    strictReason: "the control plane is the XACML family's PEP contract, " +
      "not one of the published APIs #1476/#1483 made refuse an undeclared " +
      "name: an older or newer PEP sends what its version knows (`?since=`, " +
      "`?pep=`), and the service ignores a name it does not read, so a " +
      "garbage GET is held to no 5xx and no leaked code" }),
  Object.freeze({ key: "pep-control-plane-anonymous",
    title: "Remote PEP control plane, no credential",
    kind: "openapi", schemaFile: "pep-control-plane.json",
    target: "service", auth: "none", checks: PEP_CONFORMANCE,
    anonymous: true, refusedWith: Object.freeze([401]),
    beforeTheGate: true,
    strict: "tolerates",
    strictReason: "the pep-control-plane cell's reason; anonymously every " +
      "probe meets the gate, which answers 401 with a DPoP challenge" })
]);

const PEP_CELLS = Object.freeze([
  // THE PEP'S API ON BOTH ITS LISTENERS, because they do not serve the same
  // operations: the nudge is answered on HTTPS only (the notify listener is
  // always HTTPS since 2026-11-14) and a CRL on the plain listener only
  // (PEP_HTTP / PEP_CRL_HTTP), each 404 on the other — documented, and an
  // operation fuzzed on one listener alone would be one that only ever met
  // its 404.
  Object.freeze({ key: "pep-service", title: "Remote PEP API (HTTPS)",
    kind: "openapi", schemaFile: "pep-service.json",
    target: "pep-https", auth: "none", checks: PEP_CONFORMANCE,
    strict: "tolerates",
    strictReason: "`GET /protected` asserts every query parameter it does " +
      "not name as a subject attribute (models/pep/pep_service.tsp), so an " +
      "unknown name is an input by design; the other GETs read none",
    anonymousReason: "every operation of the PEP's own API takes no " +
      "credential by design (`/protected` decides on what the query says; " +
      "`/notify` is the service's unauthenticated nudge), so this cell is " +
      "already the unauthenticated pass" }),
  Object.freeze({ key: "pep-service-plain", title: "Remote PEP API (plain)",
    kind: "openapi", schemaFile: "pep-service.json",
    target: "pep-http", auth: "none", checks: PEP_CONFORMANCE,
    strict: "tolerates",
    strictReason: "the pep-service cell's reason: the same document on the " +
      "plain listener, where `/crl/{name}` is served and the nudge is not",
    anonymousReason: "the pep-service cell's reason: no operation of the " +
      "PEP's own API takes a credential" }),
  Object.freeze({ key: "pep-authzen", title: "Remote PEP AuthZEN edge PDP",
    kind: "openapi", schemaFile: "pep-authzen.json",
    target: "pep-https", auth: "mtls", checks: PEP_CONFORMANCE,
    strict: "tolerates",
    strictReason: "the one GET is the AuthZEN metadata document, a " +
      "specification's endpoint (AuthZEN 1.0 section 9), which a client " +
      "may ask with whatever it likes" }),
  Object.freeze({ key: "pep-authzen-anonymous",
    title: "Remote PEP AuthZEN edge PDP, no client certificate",
    kind: "openapi", schemaFile: "pep-authzen.json",
    target: "pep-https", auth: "none", checks: PEP_CONFORMANCE,
    anonymous: true, refusedWith: Object.freeze([401]),
    strict: "tolerates",
    strictReason: "the pep-authzen cell's reason" }),
  Object.freeze({ key: "pep-proxy", title: "Remote PEP reverse proxy paths",
    kind: "openapi", schemaFile: "pep-proxy.json",
    target: "pep-proxy", auth: "none", checks: PEP_CONFORMANCE,
    strict: "tolerates",
    strictReason: "the proxy's own paths are a relying party's callback " +
      "and sign-out (OpenID Connect Core 3.1.2.5, RP-Initiated Logout), " +
      "whose specifications pass parameters they do not define through",
    anonymousReason: "the proxy's paths take no credential: a session " +
      "cookie is what the proxy ISSUES after a browser sign-in through the " +
      "realm, which this kit does not drive. So this cell is the " +
      "unauthenticated pass, and the session-bearing answers of " +
      "`/.iya-pep/accounts*` are covered by sts_xacml_remote_pep.js's " +
      "theProxyHoldsASession(), not here" })
]);

// ---------------------------------------------------------------------------
// EXCLUSIONS. Empty, and the header says why: the control plane is fuzzed as
// a PEP of its own, so no operation can deregister, silence or re-key the
// container; and the container's own operations are each safe to send
// anything — `/notify` pulls from the PEP's OWN configured PDP and honours
// `full` at most once a poll interval (STS-XPEP-0120), `/crl/{name}` reads
// only `<word>.crl` from its own directory, `/protected` and the AuthZEN
// endpoints decide, and the proxy's paths act on a session the cell does not
// hold. A new one needs `surface`, `match` (an operationId) and its own
// `reason`, as the kit's do, and the plan test fails on one without.
// ---------------------------------------------------------------------------
const PEP_EXCLUSIONS = Object.freeze([]);

// ---------------------------------------------------------------------------
// WHAT IS CONTAINED, AND HOW (the egress_routes.py question for the PEP).
// None of the PEP's endpoints dials a URL a caller names: a nudge pulls from
// PEP_PDP_URL; `/protected` and the AuthZEN door ask the service's PIP; a
// forwarded fine-grained evaluation goes to PEP_PDP_URL's `/access/v1`; the
// proxy forwards to its CONFIGURED upstream. The one caller-named address on
// these surfaces is the control plane's `register` `notifyUrl`, which the
// SERVICE nudges on the next policy change — and the fuzz PEP's row is the
// only one a fuzzed register reaches. On the internal, no-egress network
// that nudge fails at the network layer (the guarantee); the
// `no_outbound_fetch` check also reads the Rust resolver's words on a PEP
// surface (sts_checks.py), and no row of egress_routes.py names a PEP route,
// so a marker on one is a finding.
// ---------------------------------------------------------------------------

// The HTTPS listener's anchors for the AuthZEN caller, written beside the
// listener pair (the container mounts XACML_PEP_SERVER_CERT_DIR's parent at
// /certs) and named to the PEP through its environment listener's tuning.
const AUTHZEN_ANCHORS_FILE = "authzen-fuzz-anchors.pem";
const PEP_CERT_MOUNT = process.env.STS_SCHEMA_PEP_CERT_MOUNT ||
  "/certs/server";

// The fuzz PEP of a realm and the AuthZEN caller of the PEP's realm. Random,
// so the admin-api cell that follows cannot NAME them (FUZZ_USER's reason).
const RUN_STAMP = crypto.randomBytes(4).toString("hex");
const FUZZ_PEP_NAME = "pep-fuzzer-" + RUN_STAMP;
const AUTHZEN_CALLER = "authzen-fuzzer-" + RUN_STAMP;

// ---------------------------------------------------------------------------
// Accessors the kit and the plan test read. Pure.
// ---------------------------------------------------------------------------

function allPepSurfaces() {
  log.debug("Entering allPepSurfaces().");
  log.debug("Leaving allPepSurfaces().");
  return PEP_REALM_SURFACES.concat(PEP_CELLS);
}

// The committed document of a PEP surface, parsed.
function documentOf(surface) {
  log.debug("Entering documentOf(). " + surface.key);
  const text = fs.readFileSync(path.join(OPENAPI_DIR, surface.schemaFile),
                               "utf8");
  log.debug("Leaving documentOf().");
  return JSON.parse(text);
}

function schemaPathOf(surface) {
  log.debug("Entering schemaPathOf().");
  log.debug("Leaving schemaPathOf().");
  return path.join(OPENAPI_DIR, surface.schemaFile);
}

// "METHOD /path" of every operation that takes no credential: its own
// `security` empty, or none and the document's empty. What
// refused_unauthenticated leaves alone. Pure.
function publicOperations(document) {
  log.debug("Entering publicOperations().");
  const out = [];
  const docSecurity = (document && document.security) || [];
  const paths = (document && document.paths) || {};
  Object.keys(paths).sort().forEach(function (template) {
    ["get", "put", "post", "delete", "patch", "head", "options"]
      .forEach(function (method) {
        const op = paths[template][method];
        if (!op) {
          return;
        }
        const security = Array.isArray(op.security) ? op.security
          : docSecurity;
        const gated = security.some(function (one) {
          return one && Object.keys(one).length > 0;
        });
        if (!gated) {
          out.push(method.toUpperCase() + " " + template);
        }
      });
  });
  log.debug("Leaving publicOperations(). " + out.length);
  return out;
}

// The statuses an unauthenticated cell's gated operation may answer: the
// gate's own refusal, and, where the cell's target is the service, the
// refusals that run ahead of the gate. Pure.
function refusalStatuses(surface) {
  log.debug("Entering refusalStatuses(). " + surface.key);
  let out = (surface.refusedWith || []).slice();
  if (surface.beforeTheGate) {
    out = out.concat(REFUSED_BEFORE_THE_GATE.map(function (one) {
      return one.status;
    }));
  }
  log.debug("Leaving refusalStatuses().");
  return out;
}

// The checks a PEP cell enables, given the kit's custom four. Pure.
function checksFor(surface, kitCustomChecks) {
  log.debug("Entering checksFor(). " + surface.key);
  let out = (surface.checks || []).concat(kitCustomChecks || [])
    .concat(PEP_EXTRA_CHECKS);
  if (surface.anonymous) {
    out = out.concat([ANONYMOUS_CHECK]);
  }
  log.debug("Leaving checksFor().");
  return out;
}

// The problems with a PEP plan, empty when it is well-formed. It takes the
// plan as an argument so that the plan test can hand it a mutated copy (an
// exclusion with its reason removed, a cell with no checks) and see it go
// red, which is how "every exclusion carries a reason" is known to be
// checked rather than assumed. `builtins` and `custom` are the kit's lists.
function validatePep(plan, builtins, custom) {
  log.debug("Entering validatePep().");
  const problems = [];
  const surfaces = (plan.realmSurfaces || []).concat(plan.cells || []);
  const keys = surfaces.map(function (one) {
    return one.key;
  });
  if (new Set(keys).size !== keys.length) {
    problems.push("two PEP surfaces share a key");
  }
  surfaces.forEach(function (surface) {
    if (PEP_AUTH_KINDS.indexOf(surface.auth) < 0) {
      problems.push("PEP surface " + surface.key + " has an unknown auth " +
        "kind " + surface.auth);
    }
    if (["service", "pep-http", "pep-https", "pep-proxy"]
        .indexOf(surface.target) < 0) {
      problems.push("PEP surface " + surface.key + " has an unknown target");
    }
    if (!surface.schemaFile ||
        !fs.existsSync(path.join(OPENAPI_DIR, surface.schemaFile))) {
      problems.push("PEP surface " + surface.key + " names no committed " +
        "document");
    }
    const enabled = checksFor(surface, custom);
    if (enabled.indexOf("no_uncaught_server_error") < 0) {
      problems.push("PEP surface " + surface.key + " omits the " +
        "no-uncaught-5xx invariant");
    }
    (surface.checks || []).forEach(function (check) {
      if ((builtins || []).indexOf(check) < 0) {
        problems.push("PEP surface " + surface.key + " names unknown " +
          "built-in check " + check);
      }
    });
    if (surface.strict !== "refuses" && surface.strict !== "tolerates") {
      problems.push("PEP surface " + surface.key + " says nothing of an " +
        "undeclared name (strict)");
    }
    if (!surface.strictReason || !String(surface.strictReason).trim()) {
      problems.push("PEP surface " + surface.key + " gives no reason for " +
        "its strictness");
    }
    if (surface.anonymous) {
      if (!Array.isArray(surface.refusedWith) ||
          surface.refusedWith.length === 0 || surface.auth !== "none") {
        problems.push("anonymous PEP surface " + surface.key + " presents " +
          "a credential or names no refusal");
      }
    } else if (surface.auth !== "none") {
      const pass = surfaces.filter(function (one) {
        return one.anonymous && one.schemaFile === surface.schemaFile &&
          one.target === surface.target;
      });
      if (!pass.length) {
        problems.push("PEP surface " + surface.key + " has no " +
          "unauthenticated pass");
      }
    } else if (!surface.anonymousReason ||
               !String(surface.anonymousReason).trim()) {
      problems.push("PEP surface " + surface.key + " takes no credential " +
        "and does not say why it is its own unauthenticated pass");
    }
  });
  (plan.exclusions || []).forEach(function (one) {
    if (keys.indexOf(one.surface) < 0) {
      problems.push("PEP exclusion for unknown surface " + one.surface);
    }
    if (!one.match) {
      problems.push("PEP exclusion on " + one.surface + " matches nothing");
    }
    if (!one.reason || String(one.reason).trim().length === 0) {
      problems.push("PEP exclusion " + one.match + " on " + one.surface +
        " carries no reason");
    }
  });
  if (plan.fuzzPepName && plan.containerName &&
      plan.fuzzPepName === plan.containerName) {
    problems.push("the control plane is fuzzed as the container's own " +
      "identity, whose row a fuzzed register would rewrite");
  }
  log.debug("Leaving validatePep(). " + problems.length + " problem(s)");
  return problems;
}

function plan() {
  log.debug("Entering plan().");
  log.debug("Leaving plan().");
  return { realmSurfaces: PEP_REALM_SURFACES, cells: PEP_CELLS,
    exclusions: PEP_EXCLUSIONS, fuzzPepName: FUZZ_PEP_NAME,
    containerName: pepEnvironment().name };
}

// Where the stack's PEP is, from the launcher's variables (run-tests.sh's
// COMPOSE_ENV, docker-compose-run-tests.yml's `tests` service).
function pepEnvironment() {
  log.debug("Entering pepEnvironment().");
  const strip = function (v) {
    log.debug("Entering strip().");
    log.debug("Leaving strip().");
    return String(v || "").replace(/\/+$/, "");
  };
  const env = {
    url: strip(process.env.XACML_PEP_URL),
    httpsUrl: strip(process.env.XACML_PEP_HTTPS_URL),
    proxyUrl: strip(process.env.XACML_PEP_PROXY_URL),
    proxyHttpsUrl: strip(process.env.XACML_PEP_PROXY_HTTPS_URL),
    upstreamUrl: strip(process.env.XACML_PEP_UPSTREAM_URL),
    name: String(process.env.XACML_PEP_NAME || ""),
    realm: String(process.env.XACML_PEP_REALM || ""),
    serverCertDir: String(process.env.XACML_PEP_SERVER_CERT_DIR || "")
  };
  log.debug("Leaving pepEnvironment().");
  return env;
}

// Why the PEP lane cannot run here, or "" when it can.
function pepLaneMissing(env) {
  log.debug("Entering pepLaneMissing().");
  const missing = ["url", "httpsUrl", "proxyUrl", "name", "realm",
    "serverCertDir"].filter(function (one) {
      return !env[one];
    });
  log.debug("Leaving pepLaneMissing(). " + missing.join(","));
  return missing.length ? "the launcher did not say where the PEP is (" +
    missing.map(function (one) {
      return { url: "XACML_PEP_URL", httpsUrl: "XACML_PEP_HTTPS_URL",
        proxyUrl: "XACML_PEP_PROXY_URL", name: "XACML_PEP_NAME",
        realm: "XACML_PEP_REALM",
        serverCertDir: "XACML_PEP_SERVER_CERT_DIR" }[one];
    }).join(", ") + " unset)" : "";
}

// The base a PEP cell's proxy forwards to.
function targetBase(surface, serviceBase, env) {
  log.debug("Entering targetBase(). " + surface.target);
  const out = { service: serviceBase, "pep-http": env.url,
    "pep-https": env.httpsUrl, "pep-proxy": env.proxyUrl }[surface.target];
  log.debug("Leaving targetBase().");
  return out || "";
}

// ---------------------------------------------------------------------------
// THE PROVISIONING. Nothing here is fuzzed; it is what a PEP surface needs
// before it can answer anything but a refusal. `deps` carries the kit's
// verbs: { serviceBase, adminCall(base, prefix, method, path, body), say }.
// ---------------------------------------------------------------------------

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

async function mustAct(deps, prefix, apiPath, body, what, accept) {
  log.debug("Entering mustAct(). " + apiPath);
  const r = await deps.adminCall(deps.serviceBase, prefix, "POST", apiPath,
                                 body);
  const fine = (accept || [200]).indexOf(r.status) >= 0 &&
    !(r.json && r.json.ok === false && r.status === 200);
  if (!fine) {
    log.debug("Leaving mustAct(). Refused.");
    throw new Error("POST " + prefix + apiPath + " (" + what + ") answered " +
      r.status + " " + JSON.stringify(r.json).slice(0, 400));
  }
  log.debug("Leaving mustAct().");
  return r.json;
}

// A remote PEP's identity in one realm: the entry, `remote-peps`, and its
// assertion key certified by issue-pep-credential from a request made here
// (the service never holds the key). Answers { name, keyFile }.
async function provisionPepIdentity(deps, prefix, name, workDir, csrPem) {
  log.debug("Entering provisionPepIdentity(). " + prefix + " " + name);
  const credentials = require("../tools/pep-credential.js");
  await mustAct(deps, prefix, "/admin-api/users/create", {
    username: name, invent: false,
    attributes: { cn: name, givenName: "Remote", sn: "Fuzz PEP",
                  mail: name + "@pep-fuzz.invalid", displayName: name }
  }, "make the PEP's entry", [200, 201, 409]);
  await mustAct(deps, prefix, "/admin-api/groups/add-member",
                { group: "remote-peps", member: name },
                "put the PEP in remote-peps", [200, 400]);
  let keyFile = "";
  let request = csrPem || "";
  if (!request) {
    const made = await credentials.assertionRequest({ keyAlg: "ec-p256",
                                                      name: name });
    // One file per realm: the name is the same in every fuzz realm, and
    // each realm certifies a key of its own.
    keyFile = path.join(workDir, name + "-" +
      String(prefix || "default").replace(/[^A-Za-z0-9]+/g, "_") +
      "-assertion.key");
    fs.writeFileSync(keyFile, made.privateKeyPem, { mode: 0o600 });
    request = made.csrPem;
  }
  const api = { post: async function (url, payload) {
    log.debug("Entering post(). " + url);
    const r = await deps.adminCall(url, "", "POST", "", payload);
    log.debug("Leaving post(). " + r.status);
    return { status: r.status, body: r.json, text: JSON.stringify(r.json) };
  } };
  try {
    await credentials.issueAssertionCredential(api, deps.serviceBase, prefix,
                                               name, request);
  } catch (e) {
    // A REALM WITH NO CERTIFICATE AUTHORITY YET cannot certify the key
    // (`issue-pep-credential` says so and names `pki/build`); a realm the
    // fuzz mode made has none until something builds it. Built once, here,
    // and asked again; any other refusal is the error it was.
    log.debug("Caught in provisionPepIdentity(): " + ((e && e.message) || e));
    await mustAct(deps, prefix, "/admin-api/pki/build",
                  { organisation: "iya-sts fuzz", country: "US" },
                  "build the realm's certificate authority");
    await credentials.issueAssertionCredential(api, deps.serviceBase, prefix,
                                               name, request);
  }
  log.debug("Leaving provisionPepIdentity().");
  return { name: name, keyFile: keyFile };
}

// The control plane's fuzz PEP in one fuzz realm, once per realm: an
// identity, a first registration with a valid body (so its row exists and
// the five pulls answer a row's documents), and that registration checked
// with a token, so a cell that fails to authenticate fails here, loudly,
// rather than as a cell of 401s. Answers { name, keyFile }.
async function provisionFuzzPep(deps, prefix, workDir) {
  log.debug("Entering provisionFuzzPep(). " + prefix);
  const credentials = require("../tools/pep-credential.js");
  const made = await provisionPepIdentity(deps, prefix, FUZZ_PEP_NAME,
                                          workDir, "");
  // THE VALIDATION DOORS' LIMITER AT ITS CEILING in the fuzz realm: at its
  // 600 a minute the authenticated cell's four doors and the PIP answered
  // mostly 429 (the 2026-11-16 throwaway run, "Rate limited: 6 operations"),
  // so the fuzz met the limiter and not the doors. The limiter still counts
  // every request first; its 429 is documented on each door, and the
  // unauthenticated cell accepts it as a refusal (REFUSED_BEFORE_THE_GATE).
  await mustAct(deps, prefix, "/admin-api/config/set",
                { key: "xacml.pipMaxPerWindow", value: 100000 },
                "raise the validation doors' limiter for the fuzz");
  const realmBase = deps.serviceBase + prefix;
  const key = fs.readFileSync(made.keyFile, "utf8");
  const got = await credentials.pepAccessToken(realmBase, made.name, key,
                                               "xacml:pep", "/xacml/pep");
  if (!got.token) {
    log.debug("Leaving provisionFuzzPep(). No token.");
    throw new Error("the fuzz PEP " + made.name + " was refused a token in " +
      prefix + ": " + got.status + " " + String(got.text).slice(0, 300));
  }
  const url = realmBase + "/xacml/pep/register";
  const register = async function (nonce) {
    log.debug("Entering register().");
    const headers = credentials.dpopHeaders(key, "POST", url, got.token);
    if (nonce) {
      headers.DPoP = credentials.dpopProof(key, "POST", url, got.token,
                                           nonce);
    }
    headers["Content-Type"] = "application/json";
    log.debug("Leaving register().");
    return fetch(url, { method: "POST", headers: headers,
      body: JSON.stringify({ name: made.name, bias: "deny-biased",
        resource: "https://pep-fuzz.invalid/protected",
        version: "fuzz", description: "the control plane's fuzz PEP" }) });
  };
  let answer = await register("");
  if (answer.status === 401 && answer.headers.get("dpop-nonce")) {
    answer = await register(answer.headers.get("dpop-nonce"));
  }
  if (answer.status !== 200 && answer.status !== 201) {
    const text = await answer.text();
    log.debug("Leaving provisionFuzzPep(). Not registered.");
    throw new Error("the fuzz PEP's first registration in " + prefix +
      " answered " + answer.status + " " + text.slice(0, 300));
  }
  deps.say("[schemathesis] the control plane's fuzz PEP " + made.name +
    " is registered in " + prefix + " on its own key");
  log.debug("Leaving provisionFuzzPep().");
  return made;
}

async function pepGetJson(url, options) {
  log.debug("Entering pepGetJson(). " + url);
  let status = 0;
  let json = null;
  let text = "";
  try {
    const https = require("https");
    const http = require("http");
    const target = new URL(url);
    const answer = await new Promise(function (resolve, reject) {
      const lib = target.protocol === "https:" ? https : http;
      // An https PEP presents the certificate the realm issued it
      // (`issue-pep-certificate`, below), under the service Root, so it
      // verifies against the service's chain like the service does.
      const verify = target.protocol === "https:"
        ? { ca: serviceTrust.trustedCa() } : {};
      const req = lib.request(target, Object.assign({ method: "GET",
        timeout: 15000, agent: false }, verify,
        options || {}), function (res) {
          let body = "";
          res.setEncoding("utf8");
          res.on("data", function (chunk) {
            body += chunk;
          });
          res.on("end", function () {
            resolve({ status: res.statusCode, text: body });
          });
        });
      req.on("timeout", function () {
        req.destroy(new Error("timed out"));
      });
      req.on("error", reject);
      req.end();
    });
    status = answer.status;
    text = answer.text;
    try {
      json = JSON.parse(text);
    } catch (e) {
      log.debug("Caught parsing in pepGetJson(): " + ((e && e.message) || e));
      json = null;
    }
  } catch (e) {
    log.debug("Caught in pepGetJson(): " + ((e && e.message) || e));
    text = String((e && e.message) || e);
  }
  log.debug("Leaving pepGetJson(). " + status);
  return { status: status, json: json, text: text };
}

async function until(what, probe, budgetMs) {
  log.debug("Entering until(). " + what);
  const deadline = Date.now() + (budgetMs || 120000);
  let last = { ok: false, note: "never asked" };
  while (Date.now() < deadline) {
    last = await probe();
    if (last.ok) {
      log.debug("Leaving until(). ok");
      return last;
    }
    await sleep(1000);
  }
  log.debug("Leaving until(). Timed out.");
  throw new Error("timed out waiting for " + what + ": " + last.note);
}

// The PEP lane's provisioning, in the PEP's realm, as sts_xacml_remote_pep.js
// does it for the same container: the realm, the container's identity on the
// key the launcher generated, a policy to hold, its HTTPS listener's pair,
// a proxy configuration, and an AuthZEN caller the service admits with the
// anchors the PEP's listener verifies it by. Answers what the cells need:
// { caller: { certFile, keyFile }, anchors, stored }.
async function provisionPepLane(deps, workDir) {
  log.debug("Entering provisionPepLane().");
  const env = pepEnvironment();
  const credentials = require("../tools/pep-credential.js");
  const prefix = "/realm/" + env.realm;
  const made = await deps.adminCall(deps.serviceBase, "", "POST",
    "/admin-api/realms/create",
    { id: env.realm, domain: env.realm + ".example.net",
      name: "Remote PEP fuzz realm",
      description: "Created by tests/protocol/schemathesis_pep.js for the " +
        "fuzz mode's PEP lane; the stack is thrown away after the run." });
  if ([200, 201, 409].indexOf(made.status) < 0) {
    throw new Error("could not create the PEP's realm " + env.realm + ": " +
      made.status + " " + JSON.stringify(made.json).slice(0, 300));
  }
  const csrFile = path.join(path.dirname(env.serverCertDir),
                            "pep-assertion.csr");
  const csr = fs.existsSync(csrFile) ? fs.readFileSync(csrFile, "utf8") : "";
  if (csr.indexOf("CERTIFICATE REQUEST") < 0) {
    throw new Error("the launcher wrote no pep-assertion.csr at " + csrFile +
      ", so the container has no key the realm could certify");
  }
  await provisionPepIdentity(deps, prefix, env.name, workDir, csr);
  await mustAct(deps, prefix, "/admin-api/xacml/create-from-template", {
    template: "rbac", name: "pep-fuzz-baseline",
    p_roleAttribute: "employeeType", p_adminRoles: "admin",
    p_readerRoles: "staff", p_readerActions: "GET, HEAD"
  }, "deploy a policy for the PEP to hold");
  await until("the PEP to register in " + env.realm, async function () {
    const seen = await pepGetJson(env.url + "/");
    const reg = (seen.json && seen.json.registration) || {};
    return { ok: reg.registered === true, note: String(reg.why ||
      seen.status) };
  }, 180000);
  const host = new URL(env.httpsUrl).hostname;
  const issued = await mustAct(deps, prefix,
    "/admin-api/xacml/issue-pep-certificate",
    { name: env.name, dnsNames: [host], ipAddresses: [] },
    "issue the PEP's HTTPS listener pair");
  fs.writeFileSync(path.join(env.serverCertDir, "pep-server.crt"),
                   issued.fullChainPem, { mode: 0o644 });
  fs.writeFileSync(path.join(env.serverCertDir, "pep-server.key"),
                   issued.privateKeyPem, { mode: 0o644 });
  await until("the PEP's HTTPS listener", async function () {
    const seen = await pepGetJson(env.url + "/");
    const h = (seen.json && seen.json.https) || {};
    return { ok: h.listening === true, note: String(h.problem || "") };
  }, 120000);
  // The proxy's public base is https in product (its session cookie is
  // Secure): its HTTPS listener, though the cell fuzzes the plain one.
  const publicBase = env.proxyHttpsUrl ||
    ("https://" + new URL(env.proxyUrl).hostname + ":9543");
  // THE PROXY: one public route under a path no document names, so the
  // proxy's own paths answer as a configured proxy's do (every path is 503
  // before a configuration, STS-XPEP-0118) and the start page is the
  // proxy's own rather than the upstream's.
  await mustAct(deps, prefix, "/admin-api/xacml/set-pep-proxy", {
    name: env.name, proxy: { enabled: true,
      upstream: env.upstreamUrl || "http://companion:9700",
      publicBaseUrl: publicBase, upstreamTimeoutMs: 3000,
      maxBodyBytes: 4096,
      routes: [{ id: "public", path: "/pep-fuzz/public", match: "prefix",
                 methods: ["GET", "HEAD"],
                 authorization: { kind: "public" } }] }
  }, "configure the PEP's reverse proxy");
  // THE AUTHZEN CALLER: an outside chain, its Root trusted by the service
  // (whose door stores and lists the leaf), the leaf stored on an entry in
  // authzen-peps; the PEP admits it by the SHA-256 the caller pull lists and
  // verifies the handshake against anchors named in its HTTPS listener's
  // tuning (the listener asks for a certificate only when it can verify
  // one, rust/bins/xacml-pep/src/listener.rs).
  const caller = await credentials.mint({
    subject: "CN=" + AUTHZEN_CALLER + ",OU=authzen,O=iya-sts fuzz" });
  const anchors = [];
  const posted = await credentials.trustRecorded(deps.serviceBase,
                                                 caller.anchorPem, anchors);
  if (!posted.ok) {
    throw new Error("the service refused the AuthZEN caller's Root: " +
      (posted.why || posted.status));
  }
  const verbs = {
    get: async function (url) {
      log.debug("Entering get(). " + url);
      const r = await deps.adminCall(url, "", "GET", "", null);
      log.debug("Leaving get(). " + r.status);
      return { status: r.status, body: r.json, text: JSON.stringify(r.json) };
    },
    post: async function (url, payload) {
      log.debug("Entering post(). " + url);
      const r = await deps.adminCall(url, "", "POST", "", payload);
      log.debug("Leaving post(). " + r.status);
      return { status: r.status, body: r.json, text: JSON.stringify(r.json) };
    }
  };
  const stored = await credentials.storeOnEntry(verbs, deps.serviceBase,
    prefix, AUTHZEN_CALLER, caller.leaf.pem);
  await mustAct(deps, prefix, "/admin-api/groups/add-member",
                { group: "authzen-peps", member: AUTHZEN_CALLER },
                "put the AuthZEN caller in authzen-peps", [200, 400]);
  // SCOPED TO ONE APPLICATION, which need not exist: an unscoped caller is
  // refused every evaluation (403, "scoped to no application"), and a caller
  // with exactly one is asked about it when a request names none, so the
  // fuzzed evaluations reach the decision rather than the scope check.
  await mustAct(deps, prefix, "/admin-api/xacml/authzen/set-scope",
                { caller: AUTHZEN_CALLER, applications: ["pep-fuzz-app"] },
                "scope the AuthZEN caller to one application");
  fs.writeFileSync(path.join(env.serverCertDir, AUTHZEN_ANCHORS_FILE),
                   caller.anchorPem + caller.issuing.pem, { mode: 0o644 });
  await mustAct(deps, prefix, "/admin-api/xacml/set-pep-environment-tuning", {
    name: env.name, listener: "api-https",
    tuning: { askClientCertificate: true,
              trustAnchorsFile: PEP_CERT_MOUNT + "/" + AUTHZEN_ANCHORS_FILE }
  }, "make the PEP's HTTPS listener ask for and verify a caller");
  await until("the PEP to admit the AuthZEN caller", async function () {
    const seen = await pepGetJson(env.url + "/");
    const json = seen.json || {};
    const asks = !!(json.https && json.https.asksForClientCertificates);
    const authzen = json.authzen || {};
    const pulled = authzen.pulledCallers || {};
    const count = Number(pulled.callers || 0);
    return { ok: asks && count > 0 && authzen.enabled === true,
      note: "asks=" + asks + ", enabled=" + authzen.enabled + ", callers=" +
        JSON.stringify(pulled).slice(0, 200) };
  }, 120000);
  const certFile = path.join(workDir, "authzen-caller.crt");
  const keyFile = path.join(workDir, "authzen-caller.key");
  fs.writeFileSync(certFile, caller.certPem, { mode: 0o600 });
  fs.writeFileSync(keyFile, caller.keyPem, { mode: 0o600 });
  deps.say("[schemathesis] the PEP lane is provisioned in " + env.realm +
    ": registered, HTTPS listening, proxy configured, AuthZEN caller " +
    AUTHZEN_CALLER + " admitted");
  log.debug("Leaving provisionPepLane().");
  return { caller: { certFile: certFile, keyFile: keyFile },
           anchors: anchors, stored: [stored], env: env };
}

// THE PEP STAYS UP AND REGISTERED AFTER THE RUN: its healthcheck answers,
// GET / says it is registered, and its credential still holds the control
// plane's token with no refusal. Answers "" or what is wrong.
async function pepStillServing(env) {
  log.debug("Entering pepStillServing().");
  const health = await pepGetJson(env.url + "/healthcheck");
  if (health.status !== 200) {
    log.debug("Leaving pepStillServing(). Unhealthy.");
    return "GET /healthcheck answered " + health.status + " " +
      String(health.text).slice(0, 200);
  }
  const seen = await pepGetJson(env.url + "/");
  const json = seen.json || {};
  const problems = [];
  if (!json.registration || json.registration.registered !== true) {
    problems.push("it is not registered (" + JSON.stringify(
      json.registration || null).slice(0, 200) + ")");
  }
  const tokens = (json.credential && json.credential.tokens) || {};
  const control = tokens["xacml-pep"] || {};
  if (control.held !== true) {
    problems.push("its credential holds no control-plane token (" +
      JSON.stringify(control).slice(0, 200) + ")");
  }
  if (!json.holding || json.holding.loaded !== true) {
    problems.push("it holds no policy (" + JSON.stringify(
      json.holding || null).slice(0, 200) + ")");
  }
  log.debug("Leaving pepStillServing(). " + problems.length);
  return problems.join("; ");
}

module.exports = {
  PEP_AUTH_KINDS: PEP_AUTH_KINDS,
  PEP_CONFORMANCE: PEP_CONFORMANCE,
  PEP_EXTRA_CHECKS: PEP_EXTRA_CHECKS,
  ANONYMOUS_CHECK: ANONYMOUS_CHECK,
  REFUSED_BEFORE_THE_GATE: REFUSED_BEFORE_THE_GATE,
  refusalStatuses: refusalStatuses,
  PEP_REALM_SURFACES: PEP_REALM_SURFACES,
  PEP_CELLS: PEP_CELLS,
  PEP_EXCLUSIONS: PEP_EXCLUSIONS,
  FUZZ_PEP_NAME: FUZZ_PEP_NAME,
  AUTHZEN_CALLER: AUTHZEN_CALLER,
  allPepSurfaces: allPepSurfaces,
  documentOf: documentOf,
  schemaPathOf: schemaPathOf,
  publicOperations: publicOperations,
  checksFor: checksFor,
  validatePep: validatePep,
  plan: plan,
  pepEnvironment: pepEnvironment,
  pepLaneMissing: pepLaneMissing,
  targetBase: targetBase,
  provisionFuzzPep: provisionFuzzPep,
  provisionPepLane: provisionPepLane,
  pepStillServing: pepStillServing
};
