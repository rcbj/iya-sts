// ===========================================================================
// sts_admin_api_auth.js — THE MANAGEMENT API'S OWN GATE.
//
// `/admin-api` required no credential at all until 2026-09-09. It requires an
// OAuth 2.0 access token now — issued by this service, audienced to this API,
// carrying `admin:read` for a read and `admin:write` for anything that changes
// state — and this job is the whole of that contract asserted from outside.
//
// **IT IS `local: true` FOR THE OWNERSHIP REASON AND NOT THE CAPABILITY ONE.**
// Everything here could be driven from the parent project's suite; the tree
// that GATED this surface is the tree that should go red when the gate stops
// refusing, and that tree is this one.
//
// ---------------------------------------------------------------------------
// WHY IT EXISTS AT ALL, WHICH IS THE PART WORTH READING.
//
// Every refusal below was verified BY HAND with curl on the day the gate was
// written, and a hand-run verification is a claim about one afternoon. The
// three that matter are the ones a plausible "simplification" would remove
// while every other job in this suite went on passing:
//
//   * THE AUDIENCE CHECK. Drop it and every job here still passes, because
//     they all present a token minted for this API. What breaks is the
//     property that makes a bearer token safe to hand out at all: a token
//     minted for some other resource server would be replayable here.
//   * THE READ/WRITE SPLIT. Grant ADMIN_READ for both and nothing goes red —
//     the run's own token carries both scopes. What is lost is the whole point
//     of having two.
//   * THE DEFAULT-REALM KEY. `STS` is a proxy over the AMBIENT realm's keys,
//     so verifying the SERVICE credential with it under
//     `/realm/<id>/admin-api` would mean a realm's own signing key could mint
//     a service administrator's token — anybody who can create a realm
//     reaching everything. The job asserts the token minted at the default
//     realm works inside a realm, which is the observable half of that
//     decision. Since 2026-09-14 (#32) a realm's own key does sign a token of
//     its own — believed under that realm's prefix only and refused every
//     service-wide operation (mgmt-api/admin_api.ts's gate) — and that half is
//     `sts_realm_administrators.js`'s.
//
// ---------------------------------------------------------------------------
// WHAT IS DELIBERATELY NOT HERE, so that nobody reads this file as complete:
//
//   * **A SIGNED-IN BROWSER reaching `/admin-api`.** A console session is not
//     an API credential and must never become one, and the case is uncovered:
//     obtaining a real console session means driving the OIDC code flow in a
//     browser, which is `sts_admin_console.js`'s equipment rather than this
//     job's. That file asserts the half a browser can reach — a browser with
//     NO session is refused 401 rather than redirected to a sign-in screen.
//   * **`adminApi.authRequired=false`.** Turning the gate off is the
//     documented way back in, and asserting it would mean turning it off on
//     the service every other job in this run is sharing. A setting that
//     reaches the whole process is not something one job may borrow.
//
// ---------------------------------------------------------------------------
// THE SHIM, AND WHY `Authorization: none` APPEARS BELOW.
//
// `tests/tools/attach-admin-token.js` is preloaded into every job and attaches
// the run's token to `/admin-api` calls that carry no Authorization header —
// which is exactly what a job asserting the UNAUTHENTICATED refusal must not
// get. It leaves a header a job set itself alone, so `Authorization: none` is
// how this file says "send nothing the service will accept". That is a
// malformed credential rather than an absent one, and the service answers both
// the same way: 401, because `bearerOf()` reads anything that is not
// `Bearer <token>` as no token.
// ===========================================================================

"use strict";

const assert = require("assert");
const { Command, Option } = require("commander");
const tokens = require("../tools/admin-api-token.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, for the reason wait_for.js (beside this file) gives.
  appconfigProblem = e;
  appconfig = {};
}

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_admin_api_auth",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug('CONFIG_FILE could not be read, so the configuration is empty: ' +
            appconfigProblem.message);
}
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");

// THE RUN'S OWN TOKEN, which the launcher minted and every job is given. This
// file needs it in its own hand rather than through the shim, because half of
// what it does is send something else.
const RUN_TOKEN = process.env.STS_ADMIN_API_TOKEN || "";

var checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.debug("check passed: " + what);
  log.debug("Leaving check().");
}

async function fetchJson(url, options) {
  log.debug("Entering fetchJson(). url=" + url);
  const r = await fetch(url, options || {});
  const text = await r.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in fetchJson(): " + ((e && e.message) || e));
    // Not JSON — an HTML refusal or an empty body. The status and the raw text
    // say more than a parse error would.
    body = null;
  }
  log.debug("Leaving fetchJson(). status=" + r.status);
  return { status: r.status, body: body, text: text,
           authenticate: r.headers.get("www-authenticate") || "" };
}

// A read and a write, each reachable with one token and refused with the
// other. `/admin-api/status` is the cheapest GET; `/admin-api/config/set` is a
// write that changes something harmless and is the shape every other write has.
function readUrl(prefix) {
  log.debug("Entering readUrl().");
  log.debug("Leaving readUrl().");
  return (prefix || base) + "/admin-api/status";
}

function writeUrl(prefix) {
  log.debug("Entering writeUrl().");
  log.debug("Leaving writeUrl().");
  return (prefix || base) + "/admin-api/config/set";
}

// The body a write takes. `groups.claim` is a boolean this service reads on
// every issuance, so setting it to what it already is changes nothing while
// being a real write through the real handler — which is what the gate is
// being asked about. The refusals below never reach the handler at all.
function writeBody() {
  log.debug("Entering writeBody().");
  log.debug("Leaving writeBody().");
  return JSON.stringify({ key: "groups.claim", value: "true" });
}

async function readWith(authorization, prefix) {
  log.debug("Entering readWith().");
  log.debug("Leaving readWith().");
  return fetchJson(readUrl(prefix),
                   { headers: { authorization: authorization } });
}

async function writeWith(authorization, prefix) {
  log.debug("Entering writeWith().");
  log.debug("Leaving writeWith().");
  return fetchJson(writeUrl(prefix), {
    method: "POST",
    headers: { authorization: authorization,
               "content-type": "application/json" },
    body: writeBody()
  });
}

// ---------------------------------------------------------------------------
// 1. NO CREDENTIAL. The status and the header a client is built to read.
// ---------------------------------------------------------------------------
async function withNoToken() {
  log.debug("Entering withNoToken().");
  log.info("=== A call with no access token ===");
  const read = await readWith("none");
  check("an unauthenticated read is 401", function () {
    assert.strictEqual(read.status, 401,
      "GET /admin-api/status with no token must be 401. It answered " +
      read.status + ": " + read.text.slice(0, 300));
  });
  // WWW-Authenticate IS THE POINT OF A 401 rather than a decoration on it.
  // RFC 9110 requires the header on a 401 and an OAuth client reads the scope
  // out of it to know what to ask for; a 401 without it tells a program that
  // something went wrong and nothing about what to do next.
  check("and it names the scheme and the scope", function () {
    assert.ok(/bearer/i.test(read.authenticate),
      "a 401 from this API must carry a WWW-Authenticate header naming " +
      "Bearer. It carried " + JSON.stringify(read.authenticate));
    assert.ok(/admin:read/.test(read.authenticate),
      "and the scope a caller should ask for. It carried " +
      JSON.stringify(read.authenticate));
  });
  check("the refusal says how to get a token", function () {
    assert.ok(/client_credentials/.test(read.text) &&
              /adminApi\.authRequired/.test(read.text),
      "the body of the refusal must name the grant that produces a token AND " +
      "the setting that turns the requirement off — the second is the way " +
      "back in for somebody who cannot mint one, and a refusal that hid it " +
      "would make this API unrecoverable. It said: " + read.text.slice(0, 400));
  });
  const write = await writeWith("none");
  check("an unauthenticated write is 401 too", function () {
    assert.strictEqual(write.status, 401,
      "POST /admin-api/config/set with no token must be 401. It answered " +
      write.status + ": " + write.text.slice(0, 300));
  });
  log.debug("Leaving withNoToken().");
}

// ---------------------------------------------------------------------------
// 2. A TOKEN THIS SERVICE DID NOT SIGN. 401 and not 403: the difference is
//    whether the credential is READABLE, and a client that cannot tell them
//    apart retries forever with the same broken token.
// ---------------------------------------------------------------------------
async function withAGarbageToken() {
  log.debug("Entering withAGarbageToken().");
  log.info("=== A token this service did not sign ===");
  const read = await readWith("Bearer not.a.jwt");
  check("a token that is not a JWS at all is 401", function () {
    assert.strictEqual(read.status, 401,
      "an unreadable credential is 401 (invalid_token), not 403. It " +
      "answered " + read.status + ": " + read.text.slice(0, 300));
  });
  // A WELL-FORMED JWS SIGNED BY SOMEBODY ELSE. The header and payload are
  // real JSON and the signature is nonsense, which is the shape of the attack
  // this check is about — a caller that can build a token but cannot sign one.
  const forged = Buffer.from('{"alg":"RS256","typ":"JWT"}')
                       .toString("base64url") +
    "." + Buffer.from(JSON.stringify({
      sub: "sts-management-api", client_id: "sts-management-api",
      scope: "admin:read admin:write",
      aud: base + "/admin-api",
      exp: Math.floor(Date.now() / 1000) + 3600
    })).toString("base64url") + ".AAAA";
  const forgedRead = await readWith("Bearer " + forged);
  check("a forged token with perfect claims is still 401", function () {
    assert.strictEqual(forgedRead.status, 401,
      "a token carrying exactly the right audience, scopes and expiry is " +
      "worth nothing without a signature this service made — that is the " +
      "whole of what verification buys. It answered " + forgedRead.status +
      ": " + forgedRead.text.slice(0, 300));
  });
  log.debug("Leaving withAGarbageToken().");
}

// ---------------------------------------------------------------------------
// 3. A REAL TOKEN FOR SOMEBODY ELSE. 403 rather than 401, because the
//    credential is perfectly readable and simply not for this API.
// ---------------------------------------------------------------------------
async function withTheWrongAudience() {
  log.debug("Entering withTheWrongAudience().");
  log.info("=== A real token minted for another resource ===");
  const elsewhere = await tokens.tokenFor(base, {
    audience: "https://example.test/some-other-api"
  });
  const read = await readWith("Bearer " + elsewhere);
  check("a token for another audience is refused", function () {
    assert.strictEqual(read.status, 403,
      "an access token is a BEARER credential: one minted for another " +
      "resource server must not be replayable here, which is the whole " +
      "purpose of `aud`. This token was signed by this service, is unexpired " +
      "and carries both scopes — and names somebody else. It answered " +
      read.status + ": " + read.text.slice(0, 300));
  });
  check("and the refusal names both audiences", function () {
    assert.ok(/example\.test/.test(read.text),
      "the refusal must quote what the token actually carries, or a caller " +
      "with two tokens cannot tell which one it sent: " +
      read.text.slice(0, 400));
    assert.ok(read.text.indexOf("/admin-api") >= 0,
      "and what this API answers to: " + read.text.slice(0, 400));
  });
  log.debug("Leaving withTheWrongAudience().");
}

// ---------------------------------------------------------------------------
// 4. THE READ/WRITE SPLIT, which is the reason there are two scopes.
// ---------------------------------------------------------------------------
async function theTwoScopes() {
  log.debug("Entering theTwoScopes().");
  log.info("=== admin:read reads and does not write ===");
  const readOnly = await tokens.tokenFor(base, { scope: "admin:read" });
  const read = await readWith("Bearer " + readOnly);
  check("a read-only token reads", function () {
    assert.strictEqual(read.status, 200,
      "GET /admin-api/status with `admin:read` must succeed. It answered " +
      read.status + ": " + read.text.slice(0, 300));
  });
  const write = await writeWith("Bearer " + readOnly);
  check("and cannot write", function () {
    assert.strictEqual(write.status, 403,
      "POST with `admin:read` alone must be refused 403 — 403 and not 401, " +
      "because the credential is valid and the PERMISSION is missing. It " +
      "answered " + write.status + ": " + write.text.slice(0, 300));
  });
  // THE REFUSAL HAS TO SAY WHICH OF THE TWO IS MISSING. "Forbidden" on a
  // surface with two scopes is a message that costs its reader a bisect.
  check("and says which scope a write needs", function () {
    assert.ok(/admin:write/.test(write.text) &&
              /ADMIN_WRITE/.test(write.text),
      "the refusal must name the scope AND the role it becomes — the scope " +
      "is what a client asks the token endpoint for, the role is what the " +
      "policy document names, and the two are edited in different places. " +
      "It said: " + write.text.slice(0, 400));
  });

  log.info("=== admin:write writes ===");
  const writeOnly = await tokens.tokenFor(base, { scope: "admin:write" });
  const wrote = await writeWith("Bearer " + writeOnly);
  check("a write-scoped token writes", function () {
    assert.strictEqual(wrote.status, 200,
      "POST /admin-api/config/set with `admin:write` must succeed. It " +
      "answered " + wrote.status + ": " + wrote.text.slice(0, 300));
  });
  // AND THE SPLIT IS REAL IN BOTH DIRECTIONS. Without this the gate could be
  // "any admin scope allows anything" and every assertion above would pass.
  const refusedRead = await readWith("Bearer " + writeOnly);
  check("and a write-only token cannot read", function () {
    assert.strictEqual(refusedRead.status, 403,
      "`admin:write` alone must not read: a split that only refuses in one " +
      "direction is one scope wearing two names. It answered " +
      refusedRead.status + ": " + refusedRead.text.slice(0, 300));
  });
  log.debug("Leaving theTwoScopes().");
}

// ---------------------------------------------------------------------------
// 5. THE CREDENTIAL IS SERVICE-WIDE, WHICH IS A REALM DECISION.
// ---------------------------------------------------------------------------
async function insideARealm() {
  log.debug("Entering insideARealm().");
  log.info("=== The same token inside a trust realm ===");
  // The DEFAULT realm always exists, and `/realm/<id>` for it is not a path
  // this service serves — so the realm asked about here is one the run has
  // already created, and without one the section says so and asserts nothing.
  // What is being asserted does not need a realm of this job's own: it needs a
  // PREFIXED path, and `GET /realms` names one that exists.
  const realms = await fetchJson(base + "/realms");
  const list = (realms.body && realms.body.realms) || [];
  const other = list.filter(function (one) {
    return one && one.id && one.id !== "default" && !one.isDefault;
  })[0];
  if (!other) {
    // NOT A SKIP AND NOT A PASS. There is nothing to assert without a second
    // realm, and this job does not create one: realms this suite creates are
    // deliberately left behind for somebody to read, and a job that made one
    // per run to check a path prefix would leave a realm per run forever.
    log.warn("No non-default realm exists on this service, so the " +
             "realm-scoped half of the gate was not exercised. It runs " +
             "whenever another job has created one, which in a whole-suite " +
             "run is always.");
    log.debug("Leaving insideARealm().");
    return;
  }
  const prefix = base + "/realm/" + other.id;
  const read = await readWith("Bearer " + RUN_TOKEN, prefix);
  check("a token minted at the default realm works inside a realm",
        function () {
    assert.strictEqual(read.status, 200,
      "GET " + prefix + "/admin-api/status must accept the service-wide " +
      "token. This is the observable half of a deliberate decision: the " +
      "token is verified against the DEFAULT realm's signing key wherever " +
      "this API is reached, because a per-realm key would let anybody who " +
      "can create a realm mint that realm's own administrator credential. " +
      "It answered " + read.status + ": " + read.text.slice(0, 300));
  });
  const refused = await readWith("none", prefix);
  check("and the realm's own /admin-api is gated too", function () {
    assert.strictEqual(refused.status, 401,
      "the gate is one middleware on the base path, so a realm prefix must " +
      "not walk around it. " + prefix + "/admin-api/status answered " +
      refused.status);
  });
  log.debug("Leaving insideARealm().");
}

// ---------------------------------------------------------------------------
// 6. THE RUN'S OWN TOKEN WORKS, which is what every other job depends on.
// ---------------------------------------------------------------------------
async function theRunsOwnToken() {
  log.debug("Entering theRunsOwnToken().");
  log.info("=== The token this run was given ===");
  check("the launcher handed this job a token", function () {
    assert.ok(RUN_TOKEN,
      "STS_ADMIN_API_TOKEN is empty. Both launchers mint one before any job " +
      "runs and hand it over; without it every job that drives /admin-api " +
      "reports a 401 and the run names twenty problems instead of one.");
  });
  // CHECKED HERE RATHER THAN WHERE IT IS SPENT, and the first version of this
  // file did the second: `tokenFor()` is called for the first time three
  // sections down, so a missing secret arrived as a thrown Error in the middle
  // of the audience section and read like a failure of the thing under test.
  // This job is the only one in the suite that mints default-realm tokens of
  // its own with the run's pinned client secret (sts_realm_administrators.js
  // mints a realm's, with a secret it reads itself), so it is the only one
  // that needs that secret — and the fastest way to be told is at the top.
  check("and the secret those tokens are minted with", function () {
    assert.ok(process.env.STS_ADMIN_API_CLIENT_SECRET,
      "STS_ADMIN_API_CLIENT_SECRET is empty. This job asks the token " +
      "endpoint for tokens the run was NOT given — one scope at a time, and " +
      "one audienced elsewhere — which needs the seeded client's secret. " +
      "run-report.js passes it through from the launcher, which pins it per " +
      "run as adminApi.clientSecret.");
  });
  const read = await readWith("Bearer " + RUN_TOKEN);
  check("and it reads", function () {
    assert.strictEqual(read.status, 200,
      "the run's own token must read /admin-api/status. It answered " +
      read.status + ": " + read.text.slice(0, 300));
  });
  const write = await writeWith("Bearer " + RUN_TOKEN);
  check("and it writes", function () {
    assert.strictEqual(write.status, 200,
      "the run's own token carries both scopes, so it must write too. It " +
      "answered " + write.status + ": " + write.text.slice(0, 300));
  });
  log.debug("Leaving theRunsOwnToken().");
}

// ===========================================================================
// THE DOCUMENT THIS API PUBLISHES DESCRIBES THE GATE THE SECTIONS ABOVE DRIVE.
//
// Every section of this file asks the SERVICE what it does about a credential.
// This one asks what it SAYS, because until 2026-09-10 the two were opposite
// and only a person reading both would ever have known: `/admin-api` had
// required a token since 2026-09-09, and its own OpenAPI document carried
// `security: []` — which is not silence, it is OpenAPI for "no credential is
// needed" — no `securitySchemes` at all, and an opening paragraph beginning
// "Nothing here is protected". A generated client read that, sent nothing, and
// was refused on all 238 operations.
//
// `tests/admin_api_document_security.js` holds the BUILDER to this in process,
// in both states of the switch. What is left for here is the one thing that
// file cannot see: that the document a RUNNING, GATED service actually serves
// is that document — same claim, other end of the wire, and a rendering step,
// a cache or a second call site between them.
//
// It reads the document with the run's own token, which is the only way to
// read it: the document is behind the gate it describes. That is not a
// contradiction and it is worth being clear about — the reader who needs it
// before they have a token gets it from the console's API explorer at
// `/admin/api-explorer/openapi.json`, on a session instead, and the 401 body
// this API returns names the grant, the scopes and the `resource` in the
// meantime.
// ===========================================================================
async function theDocumentDescribesTheGate() {
  log.debug("Entering theDocumentDescribesTheGate().");
  log.info("=== what the published document says about the gate ===");

  const doc = await fetchJson(base + "/admin-api/openapi.json",
                              { headers: { Authorization: "Bearer " +
                                  RUN_TOKEN } });
  check("the OpenAPI document is served to a token holder", function () {
    assert.strictEqual(doc.status, 200,
      "GET /admin-api/openapi.json answered " + doc.status + " to the run's " +
      "own token: " + doc.text.slice(0, 200));
  });
  const document = doc.body || {};

  check("and it states that a credential is required", function () {
    assert.ok(Array.isArray(document.security) && document.security.length > 0,
      "the document's top-level `security` is " +
      JSON.stringify(document.security) + ". An EMPTY array is OpenAPI for " +
      "\"no credential is needed\" and this API refuses every call without " +
      "one — that combination is what a client generated from this document " +
      "cannot recover from, because it will not send a header the document " +
      "never mentioned.");
  });

  check("and offers a scheme for presenting one", function () {
    const schemes = (document.components || {}).securitySchemes || {};
    assert.ok(schemes.oauth2 && schemes.bearerAuth,
      "components.securitySchemes holds " +
      (Object.keys(schemes).join(", ") || "nothing") + ". A `security` " +
      "requirement naming a scheme the document does not define is a " +
      "document no tool can act on.");
  });

  check("the token endpoint it names is this service's", function () {
    const flow = (((document.components || {}).securitySchemes || {}).oauth2 ||
                  {}).flows || {};
    const url = (flow.clientCredentials || {}).tokenUrl || "";
    assert.ok(url.indexOf(base) === 0,
      "the document sends a client to " + url + " for a token and this " +
      "service is at " + base + ". `servers[0].url` is built from the " +
      "request, and this must be too, or a document fetched through a proxy " +
      "or a published port names an address the reader cannot reach.");
  });

  // THE SCOPE PER OPERATION, AGAINST THE GATE'S OWN RULE — asserted here as
  // well as in process because this is the copy a client actually reads.
  check("every operation names the scope its method needs", function () {
    const wrong = [];
    Object.keys(document.paths || {}).forEach(function (path) {
      Object.keys(document.paths[path]).forEach(function (method) {
        const wanted = method.toUpperCase() === "GET" ? "admin:read"
                                                      : "admin:write";
        const security = document.paths[path][method].security || [];
        const named = (security[0] || {}).oauth2 || [];
        if (named.length !== 1 || named[0] !== wanted) {
          wrong.push(method.toUpperCase() + " " + path + " -> " +
                     JSON.stringify(security));
        }
      });
    });
    assert.deepStrictEqual(wrong.slice(0, 5), [],
      wrong.length + " operation(s) declare a scope the gate would not ask " +
      "for. A GET needs admin:read and everything else needs admin:write, " +
      "which is one line in the middleware this file drives:\n  " +
      wrong.slice(0, 5).join("\n  "));
  });

  const index = await fetchJson(base + "/admin-api",
                                { headers: { Authorization: "Bearer " +
                                    RUN_TOKEN } });
  check("and the index says it is protected", function () {
    assert.strictEqual((index.body || {}).protected, true,
      "GET /admin-api reports `protected: " +
      JSON.stringify((index.body || {}).protected) + "` on a service that " +
      "just refused every one of the sections above. It was the literal " +
      "`false` until 2026-09-10 — a field a caller could only read by " +
      "presenting the credential it denied needing.");
  });

  log.debug("Leaving theDocumentDescribesTheGate().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving the management API's gate at " + base + ".");

  await theRunsOwnToken();
  await withNoToken();
  await withAGarbageToken();
  await withTheWrongAudience();
  await theTwoScopes();
  await insideARealm();
  await theDocumentDescribesTheGate();

  // A FLOOR ON THE COUNT, for the reason sts_roles.js gives: a section that
  // stops being called takes its assertions with it and the run still says
  // "passed", which is the one failure mode a suite cannot report about
  // itself. Sixteen rather than the full count because the realm section is
  // conditional on another job having created one.
  assert.ok(checks >= 16,
    "only " + checks + " checks ran. This file makes at least sixteen " +
    "against a healthy service, so a count this low means a SECTION STOPPED " +
    "BEING CALLED rather than that the gate got simpler.");
  log.info(checks + " checks passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_admin_api_auth")
  .description("Drive the management API's OAuth 2.0 gate: the 401 with no " +
      "token, the 401 for one this service did not sign, the 403 for a token " +
      "audienced elsewhere, the admin:read/admin:write split in both " +
      "directions, and the service-wide credential inside a trust realm.")
  .addOption(new Option("-u, --url <url>", "base url of the STS under test")
      .default(base))
  .parse(process.argv);
base = String(program.opts().url || base).replace(/\/+$/, "");

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
