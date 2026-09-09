"use strict";
//
// File: sts_route_inputs.js
//
// ===========================================================================
// EVERY ROUTE THIS SERVICE REGISTERS, ASKED A MALFORMED QUESTION.
//
// One property, over the whole router: **a request this service cannot make
// sense of must be REFUSED, never survived.** A 400, a 403, a 404 or a redirect
// are all fine answers — they mean a handler looked at the input and decided.
// **A 5xx is not an answer, it is an uncaught throw**, and a timeout is worse
// still because on this service it means the event loop stopped.
//
// It found five of those the day it was written, none of which any other job in
// either suite could see:
//
//   500 POST /sts            a malformed SOAP envelope, AND AN EMPTY BODY
//   500 GET  /saml2/sso      a malformed SAMLRequest
//   500 POST /saml2/sso      the same, through the POST binding
//   500 GET  /saml2/sso/:sp  and again, per service provider
//   500 POST /saml2/slo      a malformed LogoutRequest
//
// **None was carelessness.** `@xmldom/xmldom` used to report a malformed
// document by CALLING A HANDLER whose default wrote to the console and carried
// on, so a bare parse returned a partial tree and the code limped along. In
// 0.9.10 that default THROWS. Ten parse sites in this service were wrapped in a
// try/catch and three were not — and those three became 500s on a library bump,
// with nothing in this repository changed. That is the shape of defect this job
// exists for: nobody edits anything and a working endpoint stops working.
//
// ---------------------------------------------------------------------------
// WHY IT IS THIS REPOSITORY'S OWN (`local: true`).
//
// `tests/CLAUDE.md` asks first whether the thing under test is this service's
// `/admin` console or its `/admin-api`, and second whether it can be asserted by
// driving the running service over HTTP. This job is the whole router rather
// than the console, and it plainly can be driven over HTTP — so by those two
// questions it would belong in the parent project's suite.
//
// **It is here on a third argument, and the argument is the ROUTE LIST.** This
// job does not carry a list of endpoints; it DISCOVERS them by reading this
// repository's own source, so what it probes is exactly what this working tree
// registers. That coupling is the point: the tree that ADDS a route is the tree
// that should go red when that route answers 500 to a malformed request. A copy
// over there would read the pinned `sts/` gitlink and could probe a route list
// that is not the one running.
//
// It is the same ownership argument the console jobs make, applied one level
// out — and like them it is edited HERE and only here.
//
// ---------------------------------------------------------------------------
// TWO THINGS THAT MADE AN EARLIER VERSION OF THIS PROVE NOTHING.
//
// Both are the mistake `tests/CLAUDE.md` keeps naming — a fixture that cannot
// fail rather than an assertion that is wrong — and both are guarded below.
//
// 1. **EXTRACTING ONLY LITERAL PATHS MISSED FIFTY-NINE ROUTES.** `app.get('/x')`
//    was found and `app.get(SSO_PATH, …)` was not, so every route registered
//    through a constant was invisible — `/saml2/sso` among them, which is where
//    four of the five defects were. The extractor resolves simple constants now,
//    and `MINIMUM_ROUTES` below is the alarm on it ever silently narrowing
//    again.
//
// 2. **AND I BLAMED THE PAYLOAD FOR IT, WHICH IS THE MORE USEFUL HALF.** When
//    the probe missed `/saml2/sso`, the payload was `base64("not xml")` and the
//    route list was the narrow one. Both were changed at about the same time,
//    the miss went away, and I recorded that the payload had been too weak —
//    *"it parses to a document with no root element"*. **That was invented
//    rather than measured, and it is false**: `@xmldom/xmldom` 0.9.10 throws a
//    ParseError for `not xml` exactly as it does for `<a><b></a>`, so either
//    payload would have found the defect once the route was in the list. The
//    cause was always (1).
//
//    The tag mismatch is kept anyway, because it is unambiguously a document
//    that IS XML and is WRONG — it exercises the parser rather than the base64
//    decode in front of it — but nothing here rests on the other one being
//    inert, and a comment claiming it was would be a false statement in the
//    header of a security test. Mutating this constant to `not xml` leaves the
//    job still catching all six routes; that is the check, and it is why this
//    paragraph says so instead of the opposite.
//
// ===========================================================================

const assert = require("assert");
const fs = require("fs");
const path = require("path");
const http = require("http");
const https = require("https");
const { Command, Option } = require("commander");

var appconfig = require(process.env.CONFIG_FILE);
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_route_inputs",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

// run-report.js decides a job needs the mock by looking for these names, so the
// read is what enlists this file rather than an entry in a list somewhere.
var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = (process.env.OID4VCI_ISSUER_URL ||
            stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");

// The repository root, from this file. `tests/vendored/` -> `../..`.
const ROOT = path.resolve(__dirname, "..", "..");

// ---------------------------------------------------------------------------
// FLOORS.
//
// `sts_roles.js`'s convention, and the reason is the one failure a suite cannot
// report about itself: a section that stops running takes its assertions with
// it and the run still says "passed". If the extractor below ever breaks — a
// refactor to a router table, a move to `app.route()`, a constant it cannot
// resolve — it does not find zero routes and fail loudly, it finds SOME and
// quietly probes a fraction of the service.
//
// The numbers are deliberately well under what is there (236 routes, ~3300
// probes when this was written) so that ordinary growth never trips them, and
// far above what a broken extractor would return.
// ---------------------------------------------------------------------------
const MINIMUM_ROUTES = 180;
const MINIMUM_PROBES = 2000;

// A document with a FATAL well-formedness error. Not "not xml" — see the header.
const MALFORMED_XML = "<a><b></a>";
const MALFORMED_XML_B64 = Buffer.from(MALFORMED_XML, "utf8").toString("base64");
const LONG = "a".repeat(9000);

// ---------------------------------------------------------------------------
// The hostile inputs. Each is a class this service has actually been wrong
// about, rather than a general-purpose fuzz corpus:
//
//   * a REPEATED parameter        — the parameter-pollution shape
//   * a NESTED parameter          — `?x[y]=1`, which express turns into an object
//   * an OVER-LONG value          — the unbounded-field shape
//   * an EMPTY value              — `?x=`, which an untouched form control sends
//   * an EXECUTABLE URI scheme    — `javascript:` in something rendered as a link
//   * a MALFORMED JSON body       — the parse that throws
//   * a `__proto__` JSON body     — the prototype-pollution shape
//   * a MALFORMED XML body        — the three 500s above
//   * an EMPTY body               — which is what took `POST /sts` down
//   * PROTOCOL-SHAPED payloads    — the generic cases above would have caught
//                                   `/sts` and NOT `/saml2/sso`, which needed a
//                                   real parameter name
// ---------------------------------------------------------------------------
const CASES = [
  ["repeated parameter", "x=1&x=2&client_id=a&client_id=b&user=a&user=b", null],
  ["nested parameter", "client_id[evil]=1&user[evil]=1&id[a]=b", null],
  ["over-long value", "client_id=" + LONG + "&q=" + LONG + "&user=" + LONG, null],
  ["empty values", "client_id=&redirect_uri=&user=&id=&sp=&rp=&format=", null],
  ["executable scheme",
   "redirect_uri=javascript%3Aalert(1)&to=data%3Atext%2Fhtml%2C1&wallet=javascript%3A1",
   null],

  ["malformed JSON body", null, { type: "application/json", data: '{"a":' }],
  ["__proto__ JSON body", null,
   { type: "application/json", data: '{"__proto__":{"polluted":true}}' }],
  ["malformed XML body", null, { type: "text/xml", data: MALFORMED_XML }],
  ["empty body", null, { type: "text/xml", data: "" }],

  ["malformed SAMLRequest",
   "SAMLRequest=" + encodeURIComponent(MALFORMED_XML_B64), null],
  ["malformed SAMLResponse",
   "SAMLResponse=" + encodeURIComponent(MALFORMED_XML_B64), null],
  ["malformed SAMLart", "SAMLart=" + encodeURIComponent("%%%not-base64%%%"), null],
  ["malformed wresult",
   "wa=wsignin1.0&wresult=" + encodeURIComponent(MALFORMED_XML), null],
  ["malformed wreq", "wa=wsignin1.0&wreq=" + encodeURIComponent(MALFORMED_XML), null],
  ["unreadable credential", "access_token=..&id_token_hint=..&token=..&code=..", null],
  ["control characters", "state=%00%01&code=%0d%0a&q=%00", null],

  ["SAML in a form body", null,
   { type: "application/x-www-form-urlencoded",
     data: "SAMLRequest=" + encodeURIComponent(MALFORMED_XML_B64) +
           "&SAMLResponse=" + encodeURIComponent(MALFORMED_XML_B64) }],
  ["WS-Federation in a form body", null,
   { type: "application/x-www-form-urlencoded",
     data: "wa=wsignin1.0&wresult=" + encodeURIComponent(MALFORMED_XML) }]
];

// ---------------------------------------------------------------------------
// THE ROUTE LIST, READ OFF THIS TREE'S SOURCE.
//
// Not off the running service: `/admin/sts-metadata` knows the answer but is
// behind the console's gate and renders HTML, and asking the service to list
// what to probe would mean trusting the thing under test to describe itself.
//
// Constants are resolved one level (`const X = '/lit'`, and `const Y = X +
// '/more'`), which is what the seven route modules here actually use. Anything
// it cannot resolve is COUNTED AND REPORTED rather than skipped silently —
// `unresolved` is printed, so a new registration idiom shows up as a number
// going up instead of as coverage quietly shrinking.
// ---------------------------------------------------------------------------
function routesFrom(root) {
  log.debug("Entering routesFrom().");
  const found = new Map();
  let unresolved = 0;
  const dirs = fs.readdirSync(root, { withFileTypes: true })
    .filter(function (e) {
      return e.isDirectory() && ["node_modules", "tests", "node-ldapjs",
                                 "xacml-pep", "docs", ".git", "coverage"]
        .indexOf(e.name) < 0;
    })
    .map(function (e) { return path.join(root, e.name); });
  dirs.push(root);

  dirs.forEach(function (dir) {
    let entries = [];
    try {
      entries = fs.readdirSync(dir).filter(function (f) { return /\.js$/.test(f); });
    } catch (e) {
      // A directory that is not readable is not a route module; nothing here
      // depends on it and the floors below catch a systematic loss.
      return;
    }
    entries.forEach(function (file) {
      const full = path.join(dir, file);
      let text = "";
      try {
        text = fs.readFileSync(full, "utf8");
      } catch (e) {
        return;
      }
      const consts = {};
      let m;
      const litRe = /^const ([A-Z_][A-Z0-9_]*)\s*=\s*'(\/[^']*)'/gm;
      while ((m = litRe.exec(text))) { consts[m[1]] = m[2]; }
      const catRe = /^const ([A-Z_][A-Z0-9_]*)\s*=\s*([A-Z_][A-Z0-9_]*)\s*\+\s*'([^']*)'/gm;
      while ((m = catRe.exec(text))) {
        if (consts[m[2]] !== undefined) { consts[m[1]] = consts[m[2]] + m[3]; }
      }
      const routeRe = /app\.(get|post)\(\s*([^,]+?)\s*,/g;
      while ((m = routeRe.exec(text))) {
        const verb = m[1];
        const arg = m[2].trim();
        let p = null;
        const lit = /^'(\/[^']*)'$/.exec(arg);
        const named = /^([A-Z_][A-Z0-9_]*)$/.exec(arg);
        const cat = /^([A-Z_][A-Z0-9_]*)\s*\+\s*'([^']*)'$/.exec(arg);
        if (lit) { p = lit[1]; }
        else if (named && consts[named[1]] !== undefined) { p = consts[named[1]]; }
        else if (cat && consts[cat[1]] !== undefined) { p = consts[cat[1]] + cat[2]; }
        else { unresolved = unresolved + 1; continue; }
        if (p.indexOf("*") >= 0) { continue; }
        // ------------------------------------------------------------------
        // ONE ROUTE IS LEFT OUT BY NAME, AND IT IS THE SECOND JOB TO NEED
        // THIS (2026-09-08). `tests/CLAUDE.md` records the first:
        // `sts_metadata.js` calls every method of every endpoint and had to
        // stop calling `POST /tls/trust/clear`, because that endpoint needs
        // no credential, succeeds, and EMPTIES THE CLIENT TRUSTSTORE the
        // launcher filled before the run started.
        //
        // This job reaches it for the same reason — it drives every route it
        // can find — and the consequence is identical and just as hard to
        // read: `sts_xacml_remote_pep` runs eleven jobs later and its
        // container, whose pull, heartbeat and PIP queries all resolve a
        // VERIFIED client certificate, authenticates as nobody for the rest
        // of the run. It reports `403 ... they hold ALL_UNAUTHENTICATED_USERS`
        // about a certificate that is perfectly good. **The symptom names a
        // certificate and the cause is another job.**
        //
        // The test for adding a second entry here is the one that file
        // states, and this meets it exactly: the endpoint needs no credential
        // AND it destroys state another job depends on. It is a LIST rather
        // than a rule because there is no rule — every other POST in this
        // walk changes something too, and being refused is what most of them
        // are for.
        // ------------------------------------------------------------------
        if (p === "/tls/trust/clear") { continue; }
        found.set(verb + " " + p, { method: verb.toUpperCase(), path: p });
      }
    });
  });
  const list = Array.from(found.values());
  log.debug("Leaving routesFrom(). " + list.length + " route(s), " +
            unresolved + " unresolved.");
  return { routes: list, unresolved: unresolved };
}

// A path parameter filled with something harmless: what is under test is the
// INPUT handling, not whether `probe` happens to name a real object.
function fill(p) {
  return p.replace(/:([A-Za-z_]+)\??/g, "probe");
}

function request(method, target, body, type) {
  return new Promise(function (resolve) {
    let url;
    try {
      url = new URL(base + target);
    } catch (e) {
      resolve({ status: 0, why: "the probe built an unusable URL" });
      return;
    }
    const lib = url.protocol === "https:" ? https : http;
    const opts = {
      method: method,
      hostname: url.hostname,
      port: url.port,
      path: url.pathname + url.search,
      headers: {},
      // The suite hands every job an anchor through NODE_EXTRA_CA_CERTS, so
      // verification stays ON — a probe that turned it off would be the one
      // job in this suite unable to notice a certificate problem.
      rejectUnauthorized: true
    };
    if (body !== null && body !== undefined) {
      opts.headers["Content-Type"] = type;
      opts.headers["Content-Length"] = Buffer.byteLength(body);
    }
    const req = lib.request(opts, function (res) {
      res.resume();
      res.on("end", function () { resolve({ status: res.statusCode }); });
    });
    req.on("error", function (e) {
      // A connection-level failure is not a 5xx and is not this job's finding —
      // it is the stack being torn down under it, which is what a late
      // ECONNREFUSED in this suite has always meant.
      resolve({ status: 0, why: e.code || e.message });
    });
    req.setTimeout(8000, function () {
      req.destroy();
      resolve({ status: -1, why: "timed out" });
    });
    if (body !== null && body !== undefined) { req.write(body); }
    req.end();
  });
}

async function test() {
  log.info("Probing every registered route with malformed input against " + base);

  // -----------------------------------------------------------------------
  // 1. THE ROUTE LIST, AND THE FLOOR UNDER IT.
  // -----------------------------------------------------------------------
  const discovered = routesFrom(ROOT);
  const routes = discovered.routes;
  log.info("=== the router, read off this working tree ===");
  log.info("[routes] " + routes.length + " route(s) found, " +
           discovered.unresolved + " registration(s) this extractor could not " +
           "resolve.");

  assert.ok(routes.length >= MINIMUM_ROUTES,
    "the extractor found only " + routes.length + " routes and this service " +
    "registers far more. It is not a service that shrank, it is an extractor " +
    "that broke — a new registration idiom, a move to a router table, a " +
    "constant it cannot follow. An earlier version of this job matched only " +
    "LITERAL paths and missed fifty-nine routes, /saml2/sso among them, which " +
    "is where four of the five defects this job was written for actually were. " +
    "The floor is " + MINIMUM_ROUTES + ".");

  const families = {};
  routes.forEach(function (r) {
    const seg = r.path.split("/")[1] || "(root)";
    families[seg] = (families[seg] || 0) + 1;
  });
  log.info("[routes] OK — " + routes.length + " routes across " +
           Object.keys(families).length + " path families.");

  // -----------------------------------------------------------------------
  // 2. THE PROBE.
  // -----------------------------------------------------------------------
  log.info("=== a malformed question at every one of them ===");
  const failures = [];
  let probes = 0;

  for (const route of routes) {
    const target = fill(route.path);
    for (const entry of CASES) {
      const label = entry[0];
      const query = entry[1];
      const body = entry[2];
      if (route.method === "GET" && body) { continue; }
      if (route.method === "POST" && !body && !query) { continue; }
      const url = query
        ? target + (target.indexOf("?") >= 0 ? "&" : "?") + query
        : target;
      const answer = await request(route.method, url,
                                   body ? body.data : null,
                                   body ? body.type : null);
      probes = probes + 1;
      if (answer.status >= 500 || answer.status === -1) {
        failures.push(route.method + " " + route.path + " <- " + label +
                      " => " + (answer.status === -1 ? "TIMED OUT"
                                                     : answer.status));
      }
    }
  }

  assert.ok(probes >= MINIMUM_PROBES,
    "only " + probes + " probes ran, and the floor is " + MINIMUM_PROBES +
    ". A section that stops running takes its assertions with it and the run " +
    "still says passed, which is the one failure a suite cannot report about " +
    "itself.");

  // -----------------------------------------------------------------------
  // 3. THE ONE ASSERTION.
  // -----------------------------------------------------------------------
  assert.deepStrictEqual(failures, [],
    "these answered 5xx or timed out. A 400, a 403, a 404 or a redirect are " +
    "all fine — they mean a handler looked at the input and decided. A 5xx is " +
    "an uncaught throw, and a timeout on this service means the event loop " +
    "stopped, which takes the KDC, the directory and every TLS and SPIFFE " +
    "socket with it:\n  " + failures.join("\n  "));

  log.info("[inputs] OK — " + probes + " probes over " + routes.length +
           " routes; every one answered rather than threw.");
  log.info(probes + " checks passed.");
  log.info("Test completed successfully.");
}

const program = new Command();
program
  .name("sts_route_inputs")
  .description("Send malformed input to every route this service registers " +
      "and require that each one REFUSES rather than throws.")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
