// File: admin_api.js
//
// The mock STS's MANAGEMENT API at /admin-api — the /admin console's whole
// surface over JSON — and the OpenAPI document that describes it.
//
// The API is built so that most of it cannot go wrong on its own: every
// operation calls the same function the console's form posts to, and the
// document is generated from the table that registers the routes, so an
// operation cannot be undocumented and a documented one cannot be missing.
// This test exists for the three things that arrangement CANNOT check itself,
// and each of them is a way the API would rot silently:
//
//   * **A control added to the console with no operation here.** That is the
//     failure the whole feature is written against — an API that covers eight
//     of nine controls is worse than one that covers none, because the ninth
//     is discovered by somebody who has already written the code that assumed
//     it. Nothing in the mock can see a form appear on a page, so the parity
//     is asserted from OUTSIDE, and from the service's own answers rather than
//     from a list typed into this file: the console's page list comes back in
//     `pages`, and each action handler, asked to perform an action that does
//     not exist, replies with the names of the ones that do. Add an action to
//     the console's switch and that sentence grows; this test then fails until
//     the API has an operation for it.
//   * **A schema that describes a reply the service does not send.** A wrong
//     property name is invisible to a generator and fatal to whatever it
//     generated, so every documented property is checked against a LIVE reply.
//     It has already caught two: `expiresAt` for what is really `expiresAtMs`,
//     and a group drill-down documented with its members at the top level when
//     they are inside `group`.
//   * **That the revocation reached is the REAL one.** The API's whole claim to
//     usefulness is that it is not a second implementation, and the way to
//     prove it is not to read the code but to revoke a token here and watch
//     RFC 7662 introspection call it inactive.
//
// It also checks the one thing the explorer costs: /admin/api-explorer is the only
// page in this service with a script on it, so it is the only one served under
// a relaxed Content-Security-Policy. That relaxation must stay scoped — the
// console next door must still be `script-src 'none'` — and it must stay
// minimal, which means `'self'` and never `'unsafe-inline'`.
//
// **This test restores what it changes.** The mock's admin state survives
// between jobs, so a test that leaves a custom claim behind changes what every
// later job's tokens contain. Everything mutated here is read first and put
// back at the end, including the tokens revoked by the bulk operations — which
// are restored one jti at a time, because `revoke-all` has no opposite.
//
// Needs the STS mock and nothing else — no browser, no Keycloak.
const assert = require("assert");
const { Command, Option } = require("commander");
const consoleSignIn = require("./console_signin.js");
const common = require("./jwt_vc_json_common.js");
var appconfig = require(process.env.CONFIG_FILE);

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "admin_api",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
var api = base + "/admin-api";

// The name this file signs into the console AS. It is a name and not a
// credential: the mock checks no password anywhere. It is distinctive so that
// a row in /admin/audit or a directory entry seeded by the sign-in says which
// test made it.
const CONSOLE_USER = "admin-api-test";

// The console pages that are not this API's to mirror. /admin/sts-metadata is
// on the console's nav because a reader wants it there — it has been a page of
// the console proper since 2026-08-24, and was at /sts-metadata before that —
// but it is the whole service's index rather than one of the console's own
// pages, and it is already asserted by tests/sts_metadata.js.
const NOT_MIRRORED = ["/admin/sts-metadata"];

// Properties a schema documents that a healthy reply may legitimately omit,
// each with the reason. Without this list the check below would have to be
// weakened to "no property is misspelt", which is most of its value gone.
const CONDITIONAL = {
  // Present, and false, only in a process with no LDAP directory loaded. A run
  // with one — which is every run of this suite — must not carry it.
  "GroupList.directory": true,
  // THE COMMIT THE BUILD CAME FROM, and its absence is the ORDINARY case for a
  // container rather than an edge one. `.dockerignore` excludes `.git`, so
  // there is no history in the build context for `git rev-parse` to read — an
  // image knows its commit only when `GIT_COMMIT` was passed in as a build
  // argument, which the compose files offer and neither launcher sets. A
  // checkout run in place DOES have one, so this property is present for a
  // host run and absent for the containerized one, and a check that demanded
  // it would fail in exactly the stack CI uses.
  //
  // It is reported as ABSENT rather than as an empty string on purpose: "this
  // build does not know which commit it came from" and "it came from a commit
  // named nothing" are different claims, and the second one is not true.
  "ApiIndex.commit": true,
};

// ---------------------------------------------------------------------------
// A browser sign-on session for the CONSOLE, which this file needs in exactly
// two places and could not have needed before 2026-08-24.
//
// The API takes an OAuth 2.0 access token since 2026-09-09 — it was unprotected
// before that, and mgmt-api/CLAUDE.md keeps the three reasons it was, because
// they are the argument for `adminApi.authRequired`, the off switch. This test
// being able to drive it is the first of the three. The CONSOLE next door takes
// a DIFFERENT credential: its gate is unconditional, so every /admin page needs
// a session from /authn/login and a console role, and a caller that asks for
// `?format=json` is refused 401 `login_required` rather than redirected,
// because a redirect to an HTML sign-in screen is not an answer a program can
// read. That refusal is what failed theReadsAgreeWithTheConsole() below.
//
// The comparison is the point of that check — one list read through two doors —
// so the answer is to walk through the door rather than to stop reading the
// console. The dance is the one a browser does, in three steps:
//
//   1. GET a console page WITHOUT ?format=json and without following the
//      redirect. A GET with no session is sent to the sign-in screen, and the
//      `authn` id in that Location is what the screen is signing in FOR.
//   2. POST that id with a username and a password to /authn/login. This
//      service checks no password anywhere, so any pair is accepted; the reply
//      sets the session cookie.
//   3. Send the cookie on the console reads.
//
// The role comes from `admin.openWhenEmpty`, which is on by default: while
// neither role group has a member, whoever signs in holds both. If some earlier
// job has granted a role to somebody else the roster is enforced and this user
// holds nothing — so the caller checks the read it makes rather than assuming,
// and says which of the two states it met.
//
// A gate that has been turned OFF is a legitimate state too (the setting is
// switchable on purpose), and it is reported rather than silently treated as a
// pass: no redirect means no session is needed, and the reads below then work
// exactly as they did before any of this existed.
// ---------------------------------------------------------------------------
// **THE WALK ITSELF IS IN `console_signin.js` SINCE 2026-09-06**, because the
// console became a relying party of this service's own authorization server on
// that date and the three-fetch sign-in this function used to hold became a
// five-hop flow with two cookies — which `sts_metadata.js` also needs. Two
// copies of it would agree on the day they were written and diverge the first
// time the flow gained a hop. That file argues every hop; this one keeps the
// two things that are THIS job's: which user, and what a missing role means.
async function signInToTheConsole() {
  log.debug("Entering signInToTheConsole().");
  const cookie = await consoleSignIn.signInToTheConsole(base, CONSOLE_USER, log);
  log.debug("Leaving signInToTheConsole(). " +
            (cookie ? "Holding a session." : "The gate is off."));
  return cookie;
}

// One console read, carrying the session when there is one.
async function consoleJson(path, session) {
  log.debug("Entering consoleJson(). path=" + path);
  const r = await common.httpJson(base + path,
      session ? { headers: { Cookie: session } } : undefined);
  log.debug("Leaving consoleJson(). status=" + r.status);
  return r;
}

async function get(path) {
  log.debug("Entering get(). path=" + path);
  const r = await common.httpJson(api + path);
  assert.ok(r.ok, "GET " + api + path + " should answer 200; got " + r.status +
            " " + String(r.raw).slice(0, 200));
  log.debug("Leaving get().");
  return r.body;
}

async function post(path, body) {
  log.debug("Entering post(). path=" + path);
  const r = await common.httpJson(api + path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  log.debug("Leaving post(). status=" + r.status);
  return r;
}

// ---------------------------------------------------------------------------
// The document itself.
// ---------------------------------------------------------------------------
async function theDocumentIsServedAndWellFormed() {
  log.debug("Entering theDocumentIsServedAndWellFormed().");
  log.info("=== The OpenAPI document ===");
  const doc = await get("/openapi.json");
  assert.strictEqual(doc.openapi, "3.1.0",
    "the document should declare OpenAPI 3.1.0. It uses JSON Schema " +
    "`examples` and union types, which 3.0 spells differently or not at all, " +
    "so a document that says 3.0 would fail in a generator's schemas rather " +
    "than at the top of the file; got " + doc.openapi);
  assert.ok(doc.info && doc.info.title && doc.info.version,
    "it should name and version itself.");
  // -------------------------------------------------------------------
  // **THE DESCRIPTION MUST AGREE WITH THE GATE, AND THIS ASSERTION USED TO
  // REQUIRE THE OPPOSITE (2026-09-10).**
  //
  // It read: the description "must say the API is unprotected" — correct, and
  // load-bearing, for as long as it was. `/admin-api` began requiring an
  // access token on 2026-09-09 and this check went on demanding the sentence
  // that denied it, so the suite was holding the document to a claim the
  // service had stopped making. That is the shape of a test outliving its
  // subject: it did not go red when the behaviour changed, it went red when
  // the DOCUMENT was corrected.
  //
  // So it is asked against the state rather than against a remembered answer.
  // `protected` on the index is that state, and the two artifacts must not
  // disagree — which is the same rule this file already applies to the
  // console and the API.
  // -------------------------------------------------------------------
  const indexForProtection = await get("");
  if (indexForProtection.protected === true) {
    assert.ok(/requires an OAuth 2\.0 access token/i.test(doc.info.description),
      "GET /admin-api reports `protected: true`, so the document's own " +
      "description must say a token is required. It opens: " +
      String(doc.info.description).split("\n\n")[1].slice(0, 160));
    assert.ok(Array.isArray(doc.security) && doc.security.length > 0,
      "and `security` must not be the empty array, which is OpenAPI for " +
      "\"no credential is needed\" — the one statement a client generated " +
      "from this document cannot recover from, because it will not send a " +
      "header the document never mentioned. It is " +
      JSON.stringify(doc.security) + ".");
  } else {
    assert.ok(/(nothing here is|not) protected/i.test(doc.info.description),
      "GET /admin-api reports `protected: false` (adminApi.authRequired is " +
      "off), so the description must say the API is unprotected. Every other " +
      "page of this console says so where a reader will see it, and a " +
      "machine-readable document that omitted it would be the one artifact a " +
      "person could act on without being told.");
  }
  assert.ok(Array.isArray(doc.servers) && doc.servers.length === 1 &&
            doc.servers[0].url === base,
    "servers[0].url should be this service as the request reached it (" +
    base + "), so a document fetched through a published port names an " +
    "address the caller can use; got " +
    JSON.stringify(doc.servers));
  // -------------------------------------------------------------------
  // AND THE SAME QUESTION IN THE SCHEMA RATHER THAN THE PROSE. Both branches
  // are the original assertion, one of them inverted: the point it was making
  // — that `security` is a STATEMENT and must be present either way — is what
  // survives the gate arriving.
  // -------------------------------------------------------------------
  if (indexForProtection.protected === true) {
    const schemes = (doc.components || {}).securitySchemes || {};
    assert.ok(schemes.oauth2 && schemes.bearerAuth,
      "a `security` requirement naming a scheme the document does not define " +
      "is a document no tool can act on. components.securitySchemes holds " +
      (Object.keys(schemes).join(", ") || "nothing") + ".");
  } else {
    assert.ok(Array.isArray(doc.security) && doc.security.length === 0,
      "security should be an EMPTY ARRAY rather than absent: that is how " +
      "OpenAPI states 'this needs no credential', which is what " +
      "adminApi.authRequired=false means and is worth stating rather than " +
      "leaving to be inferred from a missing member.");
    assert.ok(!doc.components.securitySchemes,
      "and there should be no securityScheme at all, since nothing here " +
      "checks one.");
  }

  const paths = Object.keys(doc.paths);
  assert.ok(paths.length > 25,
    "the console has four action resources and eight pages, so a document " +
    "with fewer than about thirty operations has lost some; got " +
    paths.length);
  paths.forEach(function (path) {
    assert.ok(path.indexOf(":") < 0,
      "a documented path must be a URL a caller can use. Express serves the " +
      "actions from one `:action` pattern each, and the document has to " +
      "list the concrete URLs behind it; " + path + " is a route pattern.");
    Object.keys(doc.paths[path]).forEach(function (method) {
      const operation = doc.paths[path][method];
      assert.ok(operation.operationId,
        method + " " + path + " needs an operationId; a generator names its " +
        "function after it.");
      assert.ok(operation.summary && operation.description,
        method + " " + path + " needs a summary and a description.");
      assert.ok(operation.responses && operation.responses["200"],
        method + " " + path + " should document its 200.");
      if (method === "post") {
        assert.ok(operation.responses["400"],
          "POST " + path + " should document its 400 — a refusal is the " +
          "reply half of these operations that a caller has to handle, and " +
          "it carries `errors` rather than a status alone.");
      }
    });
  });
  const ids = paths.reduce(function (out, path) {
    Object.keys(doc.paths[path]).forEach(function (method) {
      out.push(doc.paths[path][method].operationId);
    });
    return out;
  }, []);
  assert.strictEqual(new Set(ids).size, ids.length,
    "operationIds must be unique, or a generated client has two methods of " +
    "one name.");
  log.info("[document] OK — OpenAPI " + doc.openapi + ", " + paths.length +
           " paths, " + ids.length + " operations, " +
           (Array.isArray(doc.security) && doc.security.length
             ? Object.keys((doc.components || {}).securitySchemes || {}).length +
               " security scheme(s)."
             : "no security scheme."));
  log.debug("Leaving theDocumentIsServedAndWellFormed().");
  return doc;
}

// The index has to agree with the document. It is a second listing of the same
// table, and a second listing is exactly the thing that goes stale.
async function theIndexAgreesWithTheDocument(doc) {
  log.debug("Entering theIndexAgreesWithTheDocument().");
  log.info("=== The index ===");
  const index = await get("");
  // **THE FIELD MUST AGREE WITH THE DOCUMENT, RATHER THAN BE A REMEMBERED
  // VALUE (2026-09-10).** This read `strictEqual(index.protected, false)` —
  // written when nothing here checked a credential, and left demanding it
  // after `/admin-api` grew a token gate. What the assertion is FOR is that
  // the index says so in a field as well as in prose, and that survives the
  // switch being thrown either way; the constant did not.
  const documentIsGuarded = Array.isArray(doc.security) && doc.security.length > 0;
  assert.strictEqual(index.protected, documentIsGuarded,
    "the index must say in a field what the OpenAPI document says in its " +
    "`security`, and they disagree: the index reports `protected: " +
    JSON.stringify(index.protected) + "` while the document's security is " +
    JSON.stringify(doc.security) + ". These are the two machine-readable " +
    "answers to \"does this API need a credential\" and a client may read " +
    "either one.");
  const documented = [];
  Object.keys(doc.paths).forEach(function (path) {
    Object.keys(doc.paths[path]).forEach(function (method) {
      documented.push(method.toUpperCase() + " " + path);
    });
  });
  const listed = index.operations.map(function (o) {
    return o.method + " " + o.path;
  });
  assert.deepStrictEqual(listed.slice().sort(), documented.slice().sort(),
    "the index and the document should list the same operations; the index " +
    "has " + listed.length + " and the document " + documented.length);
  index.operations.forEach(function (operation) {
    assert.ok(operation.mirrors,
      operation.method + " " + operation.path + " should name the console " +
      "control it mirrors. That line is what makes the parity below " +
      "checkable at all.");
  });
  log.info("[index] OK — " + listed.length +
           " operations, each naming what it mirrors.");
  log.debug("Leaving theIndexAgreesWithTheDocument().");
  return index;
}

// ---------------------------------------------------------------------------
// EVERY SURFACE REPORTS THE SAME BUILD.
//
// The version is M.N.O — a release from the repo-root VERSION file plus a build
// number fixed when the image was built (see CLAUDE.md, *Versioning*). Six
// surfaces draw it, and `tests/version.js` asserts in process that each of them
// reads the same MODULE. What only a running service can be asked is whether
// they then report the same STRING, which is the check here.
//
// **It is worth an over-HTTP check because the failure it guards is the state
// this feature replaced.** Two of those surfaces used to read
// `require('../package.json').version` — M.N.0, whose patch is a placeholder —
// so the front page and this API agreed with each other perfectly while both
// being wrong about every build ever made. Two surfaces reading two sources
// agree right up until they stop, and nothing goes red when they do: a wrong
// version still renders and still answers 200.
//
// The console page is read through the session, for the reason
// theReadsAgreeWithTheConsole() gives: `?format=json` at a gated page is a 401
// rather than a redirect, because a sign-in screen is not an answer a program
// can read.
// ---------------------------------------------------------------------------
async function everySurfaceReportsTheSameBuild(index, session) {
  log.debug("Entering everySurfaceReportsTheSameBuild().");
  log.info("=== The version ===");

  assert.ok(/^\d+\.\d+\.[A-Za-z0-9._-]+$/.test(index.version),
    "the index's version should be M.N.O — a release and a build number. It " +
    "is " + JSON.stringify(index.version) + ". A version ending in `.0` is " +
    "the shape package.json carries, which is a release with a placeholder " +
    "where the build number goes.");
  assert.strictEqual(index.version,
    index.version.split(".").slice(0, 2).join(".") + "." + index.build,
    "the index's `version` should be its `major.minor` and its `build` " +
    "joined, so a client can use either without parsing the other.");
  assert.strictEqual(typeof index.stamped, "boolean",
    "the index should say whether this version came off a build stamp or was " +
    "computed at startup. Without it a build number is unreadable: two " +
    "instances reporting different ones mean nothing if neither was built.");
  assert.ok(index.builtAt && !isNaN(Date.parse(index.builtAt)),
    "`builtAt` should be a timestamp. It is " + JSON.stringify(index.builtAt));

  // THE SERVICE METADATA PAGE, which is the one page whose subject is what
  // this service IS — so it names the build in its lead paragraph and in its
  // JSON, and that JSON must be the same string this API just gave.
  const read = await consoleJson("/admin/sts-metadata?format=json", session);
  assert.ok(read.ok,
    "the service metadata page's JSON view should answer 200, and it " +
    "answered " + read.status + ": " + String(read.raw).slice(0, 300) +
    ". A 401 or a 403 here is the console's own gate rather than a broken " +
    "read — see signInToTheConsole().");
  const metadata = read.body;
  assert.strictEqual(metadata.version, index.version,
    "/admin/sts-metadata and /admin-api should report the SAME version. " +
    "They say " + JSON.stringify(metadata.version) + " and " +
    JSON.stringify(index.version) + ", which means one of them is reading a " +
    "different source — the exact defect this check exists for.");
  assert.strictEqual(metadata.build.number, index.build,
    "and the same build number.");
  assert.strictEqual(metadata.build.stamped, index.stamped,
    "and agree about whether it was stamped.");

  // THE FRONT PAGE. Not JSON and not gated: it is HTML, so the assertion is
  // that the string is ON it. This is the surface that carried the wrong
  // number for the whole life of the service before this feature existed,
  // which is why it is checked here rather than assumed from the two above.
  const home = await fetch(base + "/", { redirect: "manual" });
  const html = await home.text();
  assert.ok(html.indexOf(index.version) >= 0,
    "the front page should carry the version this API reports (" +
    index.version + "). It is the surface that reported package.json's " +
    "placeholder patch for every build ever made, so it is checked against " +
    "the string rather than trusted.");

  log.info("[version] OK — " + index.version + " (build " + index.build +
           ", " + (index.stamped ? "stamped at build time" :
                   "computed at startup: this is a checkout, not an artifact") +
           ") on the API, the metadata page and the front page.");
  log.debug("Leaving everySurfaceReportsTheSameBuild().");
}

// ---------------------------------------------------------------------------
// PARITY. The reason this file exists.
// ---------------------------------------------------------------------------
function everyConsolePageIsMirrored(status, index) {
  log.debug("Entering everyConsolePageIsMirrored().");
  log.info("=== Parity: the console's pages ===");
  const mirrored = new Set(index.operations.map(function (o) {
    return o.mirrors.replace(/^(GET|POST)\s+/, "");
  }));
  assert.ok(Array.isArray(status.pages) && status.pages.length > 5,
    "the status reply should carry the console's own page list; got " +
    JSON.stringify(status.pages));
  const missing = status.pages.filter(function (page) {
    return NOT_MIRRORED.indexOf(page) < 0 && !mirrored.has(page);
  });
  assert.deepStrictEqual(missing, [],
    "every page of the /admin console must have an operation on /admin-api " +
    "that mirrors it. These have none: " + missing.join(", ") + ". That is " +
    "the rule this API is written under — a control added to the console " +
    "gets an operation in the same commit — and this is the check that " +
    "notices when it did not.");
  log.info("[parity/pages] OK — all " +
           (status.pages.length - NOT_MIRRORED.length) +
           " console pages are mirrored.");
  log.debug("Leaving everyConsolePageIsMirrored().");
}

// The action names, read off the service rather than written down here. Each
// action handler answers an unknown action with the list of the ones it knows,
// so this is the console's own switch statement, quoted back.
async function everyConsoleActionIsMirrored(index) {
  log.debug("Entering everyConsoleActionIsMirrored().");
  log.info("=== Parity: the console's actions ===");
  // The probe bodies matter. /claims validates its `set` BEFORE it looks at
  // the action, so a probe with an empty body comes back naming the four claim
  // SETS — a sentence of exactly the same shape, which this check would then
  // have read as four actions that do not exist. Each probe therefore carries
  // whatever that resource needs in order to reach its action switch.
  const resources = [
    { path: "/tokens", probe: {} },
    { path: "/claims", probe: { set: "id_token" } },
    { path: "/credential-claims", probe: {} },
    { path: "/verifier-request", probe: {} },
    // The configuration resource. Its probe is empty for the same reason
    // /tokens' is: it reaches its action switch before it looks at anything
    // else, so an unknown action comes back naming the four that exist rather
    // than complaining about a field.
    { path: "/config", probe: {} },
    // The delegated permission actions, whose console form is the CONFIGURED
    // half of /admin/delegation. Its probe is empty for /tokens' reason: the
    // handler reaches its action switch before it asks which application, so
    // an unknown action comes back naming the five that exist rather than
    // complaining about a missing `resource`.
    { path: "/permissions", probe: {} },
  ];
  const paths = new Set(index.operations.map(function (o) { return o.path; }));
  let checked = 0;
  for (const resource of resources) {
    const refused = await post(resource.path + "/no-such-action-exists",
                               resource.probe);
    assert.strictEqual(refused.status, 400,
      "POST " + resource.path + "/no-such-action-exists should be refused " +
      "with 400, not accepted and not routed away; got " + refused.status);
    const message = (refused.body.errors || []).join(" ");
    assert.ok(/unknown action/i.test(message),
      "and the refusal must be about the ACTION rather than about something " +
      "the probe body was missing — otherwise the list parsed below is a " +
      "list of something else. Got: " + message);
    // The sentence is 'Unknown action "x". The four are: add, remove, clear,
    // replace.' — so the names are what follows the colon. Parsed rather than
    // listed here on purpose; a list here would be a third copy of the same
    // facts and the first one to go stale.
    const tail = message.split(":").pop() || "";
    const actions = tail.replace(/\.$/, "").split(",").map(function (name) {
      return name.trim();
    }).filter(function (name) {
      return /^[a-z][a-z-]*$/.test(name);
    });
    assert.ok(actions.length >= 4,
      "the refusal for " + resource.path + " should name the actions that DO " +
      "exist — that sentence is what this parity check reads. Got: " +
      message);
    actions.forEach(function (action) {
      const wanted = "/admin-api" + resource.path + "/" + action;
      assert.ok(paths.has(wanted),
        "the console accepts the action '" + action + "' on " +
        resource.path + " and the management API has no operation for it. " +
        "Expected " + wanted + " to be one of its documented paths. Adding " +
        "an action to the console's switch means adding a row to " +
        "admin_api.js's table in the same commit.");
      checked += 1;
    });
  }
  log.info("[parity/actions] OK — all " + checked +
           " console actions across " + resources.length +
           " resources have an operation.");
  log.debug("Leaving everyConsoleActionIsMirrored().");
}

// ---------------------------------------------------------------------------
// The schemas describe the replies that are really sent.
// ---------------------------------------------------------------------------
async function theSchemasMatchTheReplies(doc) {
  log.debug("Entering theSchemasMatchTheReplies().");
  log.info("=== The schemas against live replies ===");
  const schemas = doc.components.schemas;
  const groups = await get("/groups");
  assert.ok(groups.groups && groups.groups.length,
    "this check needs the embedded directory, which every run of this suite " +
    "has: the mock seeds two groups at startup. None came back, so the " +
    "group half of these schemas would have been checked against nothing.");
  const dn = encodeURIComponent(groups.groups[0].dn);

  const cases = [
    { name: "ApiIndex", body: await get("") },
    { name: "Status", body: await get("/status") },
    { name: "Metrics", body: await get("/metrics") },
    { name: "UserList", body: await get("/users") },
    { name: "GroupList", body: groups },
    { name: "IssuedList", body: await get("/tokens") },
    { name: "ClaimSets", body: await get("/claims") },
    { name: "CredentialClaims", body: await get("/credential-claims") },
    { name: "VerifierRequest", body: await get("/verifier-request") },
    { name: "Config", body: await get("/config") },
    { name: "GroupDetail", body: await get("/groups?group=" + dn) },
  ];
  const detail = cases[cases.length - 1].body;
  cases.push({ name: "GroupDetail.group",
               schema: schemas.GroupDetail.properties.group,
               body: detail.group });

  // The schemas reached only through an `items`, which is where the two
  // property names this check has already caught both lived. A schema is not
  // checked by checking the list that carries it: IssuedList named `issued`
  // correctly for as long as IssuedRecord called `expiresAtMs` `expiresAt`.
  const issuedList = cases.filter(function (item) {
    return item.name === "IssuedList";
  })[0].body;
  const issued = issuedList.issued;
  assert.ok(issued.length,
    "this check needs at least one issued artifact, and the revocation " +
    "check above has just minted three — an empty list here means " +
    "IssuedRecord would be checked against nothing at all, which is this " +
    "suite's classic way of passing while testing nothing.");
  cases.push({ name: "IssuedRecord", schema: schemas.IssuedRecord,
               body: issued[0] });

  // The SET shape, which is what that resource actually lists since
  // 2026-09-05. Reached only through an `items` like IssuedRecord above, and
  // for the same reason: IssuedList named `sets` correctly for as long as the
  // entries in it were whatever they were.
  assert.ok((issuedList.sets || []).length,
    "IssuedList should carry `sets` — that resource lists one entry per " +
    "ISSUANCE now, and `issued` is the flatten of it. An empty array here " +
    "means IssuedSet is checked against nothing.");
  cases.push({ name: "IssuedSet", schema: schemas.IssuedSet,
               body: issuedList.sets[0] });
  // And the drill-down, which is the only place IssuedSetDetail appears.
  cases.push({ name: "IssuedSetDetail",
               body: await get("/tokens/set?id=" +
                               encodeURIComponent(issuedList.sets[0].setKey)) });

  const sets = cases.filter(function (item) {
    return item.name === "ClaimSets";
  })[0].body.sets;
  const populated = sets.filter(function (set) { return set.claims.length; });
  if (populated.length) {
    cases.push({ name: "ClaimEntry", schema: schemas.ClaimEntry,
                 body: populated[0].claims[0] });
  } else {
    // Not a skip that hides: the four sets are empty on a fresh service, which
    // is the normal state, and the claim-set check below adds one and reads it
    // back. Said out loud so a reader is not left wondering which schemas were
    // covered.
    log.info("[schemas] no custom claim is configured, so ClaimEntry is " +
             "covered by the claim-set check below rather than here.");
  }

  let checked = 0;
  cases.forEach(function (item) {
    const schema = item.schema || schemas[item.name];
    assert.ok(schema && schema.properties,
      item.name + " should be a documented schema with properties.");
    const absent = Object.keys(schema.properties).filter(function (name) {
      return !CONDITIONAL[item.name + "." + name] &&
             !(name in item.body);
    });
    assert.deepStrictEqual(absent, [],
      "the " + item.name + " schema documents " + absent.join(", ") +
      ", which the live reply does not carry. A property name that is wrong " +
      "is invisible to a reader and fatal to a generated client.");
    checked += Object.keys(schema.properties).length;
  });
  log.info("[schemas] OK — " + checked + " documented properties across " +
           cases.length + " schemas are all present in live replies.");
  log.debug("Leaving theSchemasMatchTheReplies().");
}

// ---------------------------------------------------------------------------
// The reads answer, are paged, and agree with the console.
// ---------------------------------------------------------------------------
async function theReadsAgreeWithTheConsole(session) {
  log.debug("Entering theReadsAgreeWithTheConsole().");
  log.info("=== The API and the console see one service ===");
  const apiTokens = await get("/tokens?per=5");
  assert.ok(apiTokens.held > 0,
    "the revocation check above has just minted three artifacts, so an " +
    "empty list here means this comparison would be 0 against 0 — which " +
    "passes and proves nothing.");
  const consoleTokens = await consoleJson("/admin/tokens?per=5&format=json",
                                          session);
  assert.ok(consoleTokens.ok,
    "the console's JSON view should answer 200, and it answered " +
    consoleTokens.status + ": " + String(consoleTokens.raw).slice(0, 300) +
    ". A 401 or a 403 here is the console's own gate " +
    "rather than a broken read — see signInToTheConsole(); a 403 means the " +
    "session is real and the role is not, which happens once some other job " +
    "has granted a role and turned the empty roster into an enforced one.");
  assert.strictEqual(apiTokens.held, consoleTokens.body.held,
    "the API and the console must report the same number of held artifacts " +
    "— they are one list read through two doors. API " + apiTokens.held +
    ", console " + consoleTokens.body.held);
  assert.strictEqual(apiTokens.perPage, 5,
    "?per= should be honoured; got " + apiTokens.perPage);
  assert.ok(apiTokens.page >= 1 && apiTokens.pages >= 1,
    "and the reply should say which page of how many it is.");

  const clamped = await get("/tokens?page=99999");
  assert.strictEqual(clamped.page, clamped.pages,
    "a page past the end should be CLAMPED to the last page and say so, " +
    "rather than answering an empty page numbered 99999 — a caller walking " +
    "the list has no other way to know it has finished. Got page " +
    clamped.page + " of " + clamped.pages);

  const contradiction = await get("/tokens?family=kerberos&kind=id_token");
  assert.strictEqual(contradiction.matched, 0,
    "family and kind are ANDed, so a kind from another family should match " +
    "nothing; got " + contradiction.matched);

  const nobody = await get("/users?user=" + encodeURIComponent(
    "nobody-has-ever-signed-in-as-this"));
  assert.strictEqual(nobody.known, false,
    "an identity this service has never seen is an ANSWER and not a 404: " +
    "the call must return 200 with known:false, or a caller goes looking " +
    "for a routing problem.");
  log.info("[reads] OK — paging clamps, filters AND, and the API and the " +
           "console report the same " + apiTokens.held + " artifacts.");
  log.debug("Leaving theReadsAgreeWithTheConsole().");
}

// ---------------------------------------------------------------------------
// The revocation is the real one.
// ---------------------------------------------------------------------------
async function revokingHereReachesIntrospection() {
  log.debug("Entering revokingHereReachesIntrospection().");
  log.info("=== A revocation through the API reaches RFC 7662 ===");
  // THE PERSON AND THE CLIENT ARE REAL (2026-09-12). The person is the console
  // account `console_signin.js` created with a password before the first
  // sign-in of this run, and that password is what the grant presents; the
  // client is REGISTERED here, with a secret the request presents, rather than
  // created on sight because a token request named it. Product mode does
  // neither on anybody's behalf, and a job leaning on development's doing both
  // would be testing that. A second run against a kept stack finds the client
  // already registered, which is the same state and is accepted.
  const clientSecret = "admin-api-test-client-secret";
  const registered = await post("/applications/create", {
    identifier: CONSOLE_USER, name: "Management API test client",
    protocols: ["oauth2", "oidc"],
    fields: { oauthClientId: [CONSOLE_USER], oauthClientSecret: clientSecret,
              oauthTokenEndpointAuthMethod: "client_secret_post" }
  });
  assert.ok((registered.status === 200 && registered.body &&
             registered.body.ok) ||
            /already/i.test(JSON.stringify(registered.body || {})),
    "registering the client " + CONSOLE_USER + " answered " +
    registered.status + " " + String(registered.raw).slice(0, 300));
  const minted = await common.httpJson(base + "/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "grant_type=password&username=" + encodeURIComponent(CONSOLE_USER) +
          "&password=" +
          encodeURIComponent(consoleSignIn.consolePasswordFor(CONSOLE_USER)) +
          "&client_id=" + encodeURIComponent(CONSOLE_USER) +
          "&client_secret=" + encodeURIComponent(clientSecret) +
          "&scope=openid",
  });
  assert.ok(minted.ok && minted.body.access_token,
    "the password grant should mint a token to revoke; got " + minted.status);
  const token = minted.body.access_token;

  const before = await common.httpJson(base + "/oauth2/introspect", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "token=" + encodeURIComponent(token),
  });
  assert.strictEqual(before.body.active, true,
    "the freshly minted token must introspect as ACTIVE first, or the " +
    "assertion below would pass against a token that was never valid — " +
    "which is this suite's classic way of testing nothing at all.");

  // The whole token rather than its jti, because that is what somebody holding
  // a token actually has, and because it is the path that reads the jti out of
  // an unverified JWT.
  const revoked = await post("/tokens/revoke", { target: token });
  assert.strictEqual(revoked.status, 200,
    "the revocation should be applied; got " + revoked.status + " " +
    JSON.stringify(revoked.body));
  assert.strictEqual(revoked.body.ok, true, "and report ok.");

  const after = await common.httpJson(base + "/oauth2/introspect", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "token=" + encodeURIComponent(token),
  });
  assert.strictEqual(after.body.active, false,
    "a token revoked through /admin-api/tokens/revoke must introspect as " +
    "INACTIVE. If it does not, the API is writing to a second set of revoked " +
    "jtis — which would look correct from either side and never be seen from " +
    "both.");

  const userinfo = await common.httpJson(base + "/oauth2/userinfo", {
    headers: { Authorization: "Bearer " + token },
  });
  assert.strictEqual(userinfo.status, 401,
    "and UserInfo must refuse it; got " + userinfo.status);
  log.info("[revocation] OK — revoked through the API, dead at " +
           "/oauth2/introspect and /oauth2/userinfo.");
  log.debug("Leaving revokingHereReachesIntrospection().");
  return revoked.body.jti;
}

// ---------------------------------------------------------------------------
// The writes, each restored afterwards.
// ---------------------------------------------------------------------------
async function customClaimsCanBeChangedAndPutBack() {
  log.debug("Entering customClaimsCanBeChangedAndPutBack().");
  log.info("=== Custom claims ===");
  const before = await get("/claims");
  const idTokenSet = before.sets.filter(function (s) {
    return s.id === "id_token";
  })[0];
  assert.ok(idTokenSet, "there should be an id_token claim set.");
  const original = idTokenSet.claims;

  const added = await post("/claims/add", {
    set: "id_token", name: "admin_api_test", value: "${username}",
  });
  assert.strictEqual(added.status, 200,
    "adding a claim should be applied; got " + JSON.stringify(added.body));
  const withIt = await get("/claims");
  const names = withIt.sets.filter(function (s) {
    return s.id === "id_token";
  })[0].claims.map(function (c) { return c.name; });
  assert.ok(names.indexOf("admin_api_test") >= 0,
    "and the claim must actually be in the set afterwards, not merely " +
    "reported as added; the set holds " + names.join(", "));

  const reserved = await post("/claims/add", {
    set: "id_token", name: "exp", value: "9",
  });
  assert.strictEqual(reserved.status, 400,
    "a claim this service sets itself must be REFUSED with 400, not " +
    "accepted and not silently ignored. A settable exp would produce tokens " +
    "that fail to verify with nothing pointing back at the call.");
  assert.ok((reserved.body.errors || []).join(" ").indexOf("exp") >= 0,
    "and the refusal should name it.");

  const unknownSet = await post("/claims/add", {
    set: "not-a-set", name: "x", value: "y",
  });
  assert.strictEqual(unknownSet.status, 400,
    "an unknown claim set should be refused; got " + unknownSet.status);

  // Put it back exactly, through `replace` rather than `remove`, so that a set
  // this test found in an unexpected state is restored to that state.
  const restored = await post("/claims/replace", {
    set: "id_token", claims: original,
  });
  assert.strictEqual(restored.status, 200, "the set should be restorable.");
  const after = await get("/claims");
  assert.deepStrictEqual(
    after.sets.filter(function (s) { return s.id === "id_token"; })[0].claims,
    original,
    "and this test must leave the claim set exactly as it found it. The " +
    "mock's admin state survives between jobs, so a claim left behind here " +
    "changes what every later job's ID Tokens contain.");
  log.info("[claims] OK — added, refused a reserved name, refused an " +
           "unknown set, and restored " + original.length + " claim(s).");
  log.debug("Leaving customClaimsCanBeChangedAndPutBack().");
}

async function credentialClaimsCanBeChangedAndPutBack() {
  log.debug("Entering credentialClaimsCanBeChangedAndPutBack().");
  log.info("=== Credential claims ===");
  const before = await get("/credential-claims");
  const original = before.selected;
  assert.ok(original.length,
    "the issuer should start with a claim set selected; got none, which " +
    "would make the restore below a no-op and this whole check vacuous.");

  const narrowed = await post("/credential-claims/select", {
    attributes: ["givenName", "sn"],
  });
  assert.strictEqual(narrowed.status, 200,
    "narrowing the selection should be applied; got " +
    JSON.stringify(narrowed.body));
  assert.ok(narrowed.body.sweep,
    "and the reply must report what the DIRECTORY SWEEP did. Changing the " +
    "selection writes to the embedded directory, and a reply that did not " +
    "say so would hide the half of this operation that has an effect " +
    "outside the issuer.");
  const now = await get("/credential-claims");
  assert.deepStrictEqual(now.selected, ["givenName", "sn"],
    "the selection must actually have changed; it is " +
    now.selected.join(", "));
  assert.ok(now.preview && now.preview.claims,
    "and the preview should say what a credential would now carry.");

  const bogus = await post("/credential-claims/add", {
    attribute: "givenName",
  });
  assert.strictEqual(bogus.status, 400,
    "adding an attribute already selected should be refused rather than " +
    "treated as done; got " + bogus.status);

  const restored = await post("/credential-claims/select", {
    attributes: original,
  });
  assert.strictEqual(restored.status, 200, "the selection should restore.");
  const after = await get("/credential-claims");
  assert.deepStrictEqual(after.selected, original,
    "and this test must leave the credential claim set as it found it — it " +
    "decides what every later job's credentials carry AND what the issuer " +
    "metadata advertises.");
  log.info("[credential claims] OK — narrowed to 2, swept the directory, " +
           "refused a duplicate, restored " + original.length + ".");
  log.debug("Leaving credentialClaimsCanBeChangedAndPutBack().");
}

async function theVerifierRequestCanBeChangedAndPutBack() {
  log.debug("Entering theVerifierRequestCanBeChangedAndPutBack().");
  log.info("=== The verifier request ===");
  const before = await get("/verifier-request");
  const originalClaims = before.requested;
  const originalFormat = before.format;

  const asked = await post("/verifier-request/add", {
    claim: "no_credential_here_carries_this",
  });
  assert.strictEqual(asked.status, 200,
    "asking for a claim NOT in the catalogue must be ACCEPTED — it is the " +
    "only way to exercise what a wallet does with a request it cannot " +
    "satisfy, and refusing it would remove the negative this setting exists " +
    "for; got " + asked.status);
  const withIt = await get("/verifier-request");
  assert.ok(withIt.requested.indexOf("no_credential_here_carries_this") >= 0,
    "and it should be in the request.");
  assert.ok(JSON.stringify(withIt.dcqlQuery)
            .indexOf("no_credential_here_carries_this") >= 0,
    "and it must reach the dcql_query, which is what the wallet is actually " +
    "sent. A setting that changed a page and not the query would be the " +
    "worst possible outcome here.");

  const noFormat = await post("/verifier-request/format", { format: "nope" });
  assert.strictEqual(noFormat.status, 400,
    "an unknown credential format should be refused; got " + noFormat.status);

  const empty = await post("/verifier-request/select", { claims: [] });
  assert.strictEqual(empty.status, 200,
    "requesting NOTHING is a legitimate setting rather than an empty form: " +
    "DCQL reads an absent claims member as the whole credential.");
  const emptied = await get("/verifier-request");
  assert.strictEqual(emptied.requested.length, 0,
    "and nothing should be requested.");

  const restored = await post("/verifier-request/select",
                              { claims: originalClaims });
  assert.strictEqual(restored.status, 200, "the request should restore.");
  const formatBack = await post("/verifier-request/format",
                                { format: originalFormat });
  assert.strictEqual(formatBack.status, 200, "and so should the format.");
  const after = await get("/verifier-request");
  assert.deepStrictEqual(after.requested, originalClaims,
    "this test must leave the verifier request as it found it — it decides " +
    "what every later OID4VP job is asked for.");
  assert.strictEqual(after.format, originalFormat,
    "and in the format it found.");
  log.info("[verifier request] OK — asked for an unissued claim, refused a " +
           "bad format, emptied and restored " + originalClaims.length +
           " claim(s) in " + originalFormat + ".");
  log.debug("Leaving theVerifierRequestCanBeChangedAndPutBack().");
}

// The bulk revocations, and the restore that undoes them. `revoke-all` has no
// opposite, so what is put back is every jti that was NOT already revoked when
// this started — which is why the set is read first.
async function theBulkRevocationsWorkAndAreUndone() {
  log.debug("Entering theBulkRevocationsWorkAndAreUndone().");
  log.info("=== The bulk revocations ===");
  const before = await get("/tokens?state=revoked&per=300");
  const alreadyRevoked = new Set(before.issued.map(function (r) {
    return r.jti;
  }));
  const held = await get("/tokens?per=300");
  assert.ok(held.held > 0,
    "this check needs something to revoke, and the revocation test above " +
    "has just minted a token — so a run reaching here with an empty list " +
    "would be asserting against nothing.");

  const badKind = await post("/tokens/revoke-kind", { kind: "saml2" });
  assert.strictEqual(badKind.status, 400,
    "a kind that cannot be revoked must be refused rather than silently " +
    "revoking nothing: nothing consults this service about a SAML " +
    "assertion, so a success would be a lie about what happened.");

  const all = await post("/tokens/revoke-all", {});
  assert.strictEqual(all.status, 200, "revoke-all should be applied.");
  assert.ok(typeof all.body.revoked === "number",
    "and report how many it revoked; got " + JSON.stringify(all.body));
  const nowRevoked = await get("/tokens?state=revoked&per=300");
  assert.ok(nowRevoked.matched >= before.matched,
    "and the revoked list should not have shrunk.");

  let restored = 0;
  for (const record of nowRevoked.issued) {
    if (alreadyRevoked.has(record.jti) || !record.revocable) {
      continue;
    }
    const put = await post("/tokens/restore", { jti: record.jti });
    assert.strictEqual(put.status, 200,
      "restoring " + record.jti + " should be applied; got " + put.status);
    restored += 1;
  }
  const after = await get("/tokens?state=revoked&per=300");
  const leftBehind = after.issued.filter(function (record) {
    return !alreadyRevoked.has(record.jti);
  }).map(function (record) { return record.jti; });
  assert.deepStrictEqual(leftBehind, [],
    "this test must leave nothing revoked that it found valid: a later job " +
    "using a token minted before this one ran would fail with " +
    "invalid_grant and nothing to point at. Still revoked: " +
    leftBehind.join(", "));
  log.info("[bulk] OK — refused an unrevocable kind, revoked " +
           all.body.revoked + ", restored " + restored + ".");
  log.debug("Leaving theBulkRevocationsWorkAndAreUndone().");
}

// ---------------------------------------------------------------------------
// The explorer, and the one clause it costs.
// ---------------------------------------------------------------------------
async function theExplorerIsServedUnderAScopedPolicy(session) {
  log.debug("Entering theExplorerIsServedUnderAScopedPolicy().");
  log.info("=== The explorer and its Content-Security-Policy ===");
  // ---------------------------------------------------------------------
  // THE EXPLORER IS A CONSOLE PAGE SINCE 2026-09-09, and this section reads
  // it there. It was `GET /admin-api/docs`, fetched here with no credential
  // at all, which is what that API was — until it began requiring an access
  // token, at which point the one page in this service written to be opened
  // in a browser became the one page a browser could not open.
  //
  // **THE SESSION IS NOW LOAD-BEARING FOR THE FIRST FETCH AS WELL.** Without
  // one this is a 303 to the sign-in screen, `fetch` follows it, and the
  // policy read back is that screen's — which is the same failure the
  // console check at the bottom of this function already carries a paragraph
  // about, now applying twice.
  // ---------------------------------------------------------------------
  const explorerUrl = base + "/admin/api-explorer";
  const withSession = session ? { headers: { Cookie: session } } : undefined;
  const page = await fetch(explorerUrl, withSession);
  assert.ok(page.ok, "GET /admin/api-explorer should answer 200 to a session " +
            "that holds a role; got " + page.status);
  assert.ok(/text\/html/.test(page.headers.get("content-type") || ""),
    "and be served as HTML, or a browser shows the source.");
  const policy = page.headers.get("content-security-policy") || "";
  assert.ok(/script-src 'self'/.test(policy),
    "the explorer needs script-src 'self'; its policy is: " + policy);
  assert.ok(!/unsafe-inline/.test(policy.replace(/style-src[^;]*/, "")),
    "and it must NOT relax anything else to 'unsafe-inline'. The script is " +
    "a separate resource precisely so that 'self' suffices — " +
    "'unsafe-inline' is the clause that would make this relaxation matter. " +
    "The policy is: " + policy);
  assert.ok(/connect-src 'self'/.test(policy),
    "and connect-src 'self', which is what lets the page call the API it " +
    "documents and nothing else.");
  assert.ok(/default-src 'none'/.test(policy),
    "everything else stays as the service sets it.");
  const html = await page.text();
  assert.ok(html.indexOf("<script") >= 0 &&
            html.indexOf("/admin/api-explorer/explorer.js") >= 0,
    "the page should load its script from its own URL rather than inline.");
  // THE BANNER IT USED TO CARRY IS GONE AND ITS ABSENCE IS ASSERTED. It read
  // "Nothing here is protected", which was true of this API for as long as
  // the page hung off it and is now false twice over: the API takes a token
  // and this page takes a session. A page still claiming it would be the
  // most misleading sentence in the service, on the one page an operator
  // reads before pressing things.
  assert.ok(!/nothing here is protected/i.test(html),
    "the explorer must not still say it is unprotected: it is a console " +
    "page behind a session and two roles, calling an API that requires an " +
    "access token.");
  // AND IT SAYS WHAT THE READER MAY ACTUALLY DO, which is what replaced the
  // banner: the scopes the token it was handed carries.
  assert.ok(/admin:read/.test(html),
    "the page should say which scopes its calls will carry, so that a " +
    "reader knows before pressing Try it whether a write would be refused. " +
    "It is the token the console minted for THEM, with their own roles' " +
    "scopes and no others.");
  // THE DOCUMENT COMES FROM THE CONSOLE'S OWN PATH rather than from
  // /admin-api/openapi.json, and that is not cosmetic: the API path needs a
  // token, and a page whose first act is a fetch that 401s would fail to
  // render rather than rendering and saying so.
  assert.ok(html.indexOf("/admin/api-explorer/openapi.json") >= 0,
    "the page should read its document from the console's own path, which " +
    "arrives on the session it was drawn with.");

  const script = await fetch(base + "/admin/api-explorer/explorer.js",
                             withSession);
  assert.ok(script.ok, "the script should be served; got " + script.status);
  const source = await script.text();
  assert.ok(source.length > 2000,
    "and it should be the whole explorer; got " + source.length + " bytes.");
  // The lesson coverage_beacon.js taught in the client tree, applied here: a
  // file that reaches a browser as raw script has no module system, and a
  // require() at its top level throws before anything on the page runs.
  assert.ok(!/\brequire\s*\(/.test(source),
    "the explorer runs in a browser with no module system, so a require() " +
    "in it would throw at load and the page would never render.");
  assert.ok(!/\bprocess\.\w/.test(source),
    "and there is no `process` there either.");
  assert.ok(!/\.innerHTML\s*=/.test(source),
    "and it must build nodes rather than ASSIGN innerHTML — it renders " +
    "response bodies, which are not always this service's own. (The word " +
    "itself appears in a comment there saying exactly that, which is why " +
    "this looks for the assignment rather than the name.)");

  // The relaxation must be scoped. The console next door is the page that
  // would be most costly to have quietly loosened, since it renders values a
  // caller supplied.
  // WITH the session, and that is not a detail: without one this GET is a 302
  // to the sign-in screen, fetch follows it, and the policy read back is that
  // screen's rather than the console's. It happens to be the same policy
  // today, so the check would have gone on passing while measuring a
  // different page — which is the shape of a check that is silenced rather
  // than broken.
  const consolePage = await fetch(base + "/admin",
      session ? { headers: { Cookie: session } } : undefined);
  assert.strictEqual(consolePage.status, 200,
    "the console's own page should answer 200 to a session that holds a " +
    "role, so that the policy below is the console's; got " +
    consolePage.status + ".");
  const consolePolicy =
    consolePage.headers.get("content-security-policy") || "";
  assert.ok(/script-src 'none'/.test(consolePolicy),
    "the /admin console must still be script-src 'none'. The explorer's " +
    "relaxation is scoped to its own two routes, and a middleware change " +
    "that widened it would show up here first. The console's policy is: " +
    consolePolicy);
  log.info("[explorer] OK — script-src 'self' on the two docs routes, " +
           "script-src 'none' next door, and no require/process/innerHTML " +
           "in " + source.length + " bytes of browser script.");
  log.debug("Leaving theExplorerIsServedUnderAScopedPolicy().");
}

// ---------------------------------------------------------------------------
// The configuration resource, and the one thing about it that cannot be checked
// by reading it: that a setting changed here reaches the WIRE.
//
// Everything else on this resource is self-describing and could be right about
// a service that ignored it — the value comes back, the source says "override",
// and nothing has actually moved. So this sets a setting whose effect is
// visible in a document the service publishes, reads that document, and puts it
// back. The batch size was chosen because it is an integer in the OID4VCI
// issuer metadata: an assertion about a number is not satisfiable by accident
// the way one about a string that was echoed back would be.
//
// It also checks the honesty of the restart-only half. Those rows exist to say
// "this cannot be changed and here is why", and a row that claimed it while
// quietly accepting a change would be worse than not having the row.
//
// RESTORES WHAT IT CHANGES, like everything else here — through reset-all,
// which is the operation that exists for exactly this.
// ---------------------------------------------------------------------------
async function configurationCanBeChangedAndPutBack(doc) {
  log.debug("Entering configurationCanBeChangedAndPutBack().");
  log.info("=== The configuration resource ===");

  const before = await get("/config");
  assert.ok(before.settingCount > 20 && before.groups.length > 5,
    "the configuration resource should carry this service's whole settings " +
    "table, grouped by protocol. Got " + before.settingCount + " setting(s) " +
    "in " + before.groups.length + " group(s), which is too few for this " +
    "check to mean anything.");
  assert.deepStrictEqual(before.overridden, [],
    "no runtime override should be in force before this check runs. The " +
    "mock's admin state survives between jobs, so a leftover here would " +
    "change what every later job's tokens and assertions contain. Found: " +
    JSON.stringify(before.overridden));

  const rows = before.groups.reduce(function (all, group) {
    return all.concat(group.settings);
  }, []);

  // Every property the row schema documents must appear on at least ONE row.
  // Per-row rather than per-property, because three of them are legitimately
  // conditional — only enums carry enumValues, only restart-only rows carry
  // restartReason, and only the three issuers carved out of STS_ISSUER carry
  // legacyEnv — and a misspelt name would still appear on none of them.
  const rowSchema = doc.components.schemas.Config
    .properties.groups.items.properties.settings.items;
  const never = Object.keys(rowSchema.properties).filter(function (name) {
    return !rows.some(function (row) { return row[name] !== undefined; });
  });
  assert.deepStrictEqual(never, [],
    "every property the setting schema documents should appear on at least " +
    "one of the " + rows.length + " settings. These appear on none, which is " +
    "what a misspelt property name looks like: " + never.join(", "));

  // The restart-only half says why, and means it.
  const fixed = rows.filter(function (row) { return !row.editable; });
  assert.ok(fixed.length,
    "some settings must be restart-only — the bound ports at least — or the " +
    "refusal below is checking nothing.");
  fixed.forEach(function (row) {
    assert.ok(row.restartReason,
      row.key + " is not editable and must say why: that sentence is the " +
      "whole difference between a setting that cannot be changed and one " +
      "that looks broken.");
  });
  const refused = await post("/config/set",
                             { key: fixed[0].key, value: "1234" });
  assert.strictEqual(refused.status, 400,
    "setting " + fixed[0].key + " should be REFUSED rather than accepted " +
    "and ignored: an accepted change that does nothing reads as having " +
    "worked. Got " + refused.status);
  assert.ok(/cannot be changed while this service is running/
              .test((refused.body.errors || []).join(" ")),
    "and the refusal must say so and give the reason. Got: " +
    JSON.stringify(refused.body.errors));

  // Now the half that does move, checked on the wire.
  const metadataUrl = base + "/.well-known/openid-credential-issuer";
  const original = await common.httpJson(metadataUrl);
  assert.ok(original.ok, "the issuer metadata should be served; got " +
    original.status);
  const was = original.body.batch_credential_issuance.batch_size;
  const wanted = was + 3;

  const set = await post("/config/set",
                         { key: "oid4vci.batchSize", value: wanted });
  assert.ok(set.ok, "setting oid4vci.batchSize should be accepted; got " +
    set.status + " " + JSON.stringify(set.body.errors || []));
  assert.strictEqual(set.body.setting.source, "override",
    "and the setting should then report its source as the runtime override.");

  const after = await common.httpJson(metadataUrl);
  assert.strictEqual(after.body.batch_credential_issuance.batch_size, wanted,
    "the issuer metadata must carry the new batch size. It does not, which " +
    "means this resource reported a change it did not make — the one way " +
    "this whole page could be wrong while looking right. Expected " + wanted +
    ", got " + after.body.batch_credential_issuance.batch_size);
  log.info("[config] the batch size reached the issuer metadata: " + was +
           " -> " + wanted + ".");

  // set-many is all-or-nothing, which is the property a section's Save rests
  // on: a body with one bad field must change NOTHING.
  const partly = await post("/config/set-many",
    { "oid4vci.offerUsername": "someone.else", "oid4vp.kbMaxAgeS": "not-a-number" });
  assert.strictEqual(partly.status, 400,
    "a set-many with one unusable value should be refused; got " +
    partly.status);
  const midway = await get("/config");
  assert.ok(midway.overridden.indexOf("oid4vci.offerUsername") < 0,
    "and it must have applied NONE of them. oid4vci.offerUsername was the " +
    "good field in that body and it has been written, so the section was " +
    "applied halfway — which is the state the console's Save must never be " +
    "able to leave this service in.");

  const cleared = await post("/config/reset-all", {});
  assert.ok(cleared.ok, "reset-all should succeed; got " + cleared.status);
  const restored = await common.httpJson(metadataUrl);
  assert.strictEqual(restored.body.batch_credential_issuance.batch_size, was,
    "and it must put the service back where it started: the batch size is " +
    "still " + restored.body.batch_credential_issuance.batch_size +
    " rather than " + was + ", so this test has changed what every later " +
    "job sees.");
  const end = await get("/config");
  assert.deepStrictEqual(end.overridden, [],
    "and no override should remain. Left behind: " +
    JSON.stringify(end.overridden));

  log.info("[config] OK — " + before.settingCount + " settings, " +
           fixed.length + " of them restart-only and refused, one change " +
           "seen on the wire and undone.");
  log.debug("Leaving configurationCanBeChangedAndPutBack().");
}

// ---------------------------------------------------------------------------
// A SUCCESSFUL LIVENESS PROBE IS NOT AN EVENT.
//
// `/healthcheck` is asked every few seconds for the whole life of the service —
// by the compose healthcheck in every launcher here, and by CI's wait loop —
// and it always answers the same 200. Recorded, it is by a wide margin the most
// common row in the audit log and it pushes everything a person opened that
// page to read off the end of a capped list.
//
// THE ABSENCE IS ASSERTED WITH TWO CONTROLS BESIDE IT, because "no rows came
// back" is the easiest passing check in this suite to write and the easiest to
// be wrong:
//
//   * `audit.protocolCalls` must be ON. That setting turns off the whole
//     category a `/healthcheck` row would belong to, and with it off the
//     absence below proves nothing whatever.
//   * A `POST /healthcheck`, which Express answers 404, MUST be recorded. Same
//     path, same page, same query — so a row that is missing for any reason
//     other than the rule under test takes this control with it. It is also
//     the second half of the rule stated: the quiet one is a SUCCESSFUL probe,
//     because a healthcheck answering anything else is exactly the event
//     somebody hunting a start-up failure came looking for.
//
// And the counters are checked to have counted the probes anyway: this is a
// rule about the event log, where one act is one line, and not about how much
// the service was asked to do.
// ---------------------------------------------------------------------------
const PROBES = 3;

async function successfulHealthchecksAreNotInTheAuditLog() {
  log.debug("Entering successfulHealthchecksAreNotInTheAuditLog().");
  log.info("=== The audit log ignores a successful liveness probe ===");
  const before = await get("/metrics");
  const countedBefore = healthcheckCalls(before);
  for (let i = 0; i < PROBES; i++) {
    const probe = await common.httpJson(base + "/healthcheck");
    assert.strictEqual(probe.status, 200,
        "GET /healthcheck answered " + probe.status + ". This test is about " +
        "what that call does NOT write; if the call itself is broken, " +
        "everything below would pass for the wrong reason.");
  }
  const refused = await common.httpJson(base + "/healthcheck",
      { method: "POST" });
  assert.ok(refused.status >= 400,
      "POST /healthcheck answered " + refused.status + ", so the control " +
      "this section leans on is not a refusal any more and the absence " +
      "below would have nothing standing beside it.");

  const view = await get("/audit?q=healthcheck&per=200");
  assert.strictEqual(view.protocolCalls, true,
      "audit.protocolCalls is off, so protocol endpoint calls get no row at " +
      "all and the absence this section asserts is vacuous. Something " +
      "earlier in the run turned it off and did not put it back.");
  // `events`, and NOT `rows`: that is what the reply calls the page of the
  // list, and reading a member that does not exist is an empty array and a
  // green check.
  const rows = view.events || [];
  assert.ok(Array.isArray(view.events),
      "The audit reply has no `events` array, so every assertion below is " +
      "reading undefined and passing. Members: " +
      Object.keys(view || {}).join(", ") + ".");
  const onThePath = rows.filter(function (row) {
    return String(row.target || "") === "/healthcheck";
  });
  const succeeded = onThePath.filter(function (row) {
    return row.outcome === "success";
  });
  assert.deepStrictEqual(succeeded.map(function (row) {
    return row.summary;
  }), [],
      "These successful /healthcheck rows are in the audit log. The probe " +
      "runs every few seconds for the life of the service, so one row here " +
      "means the log fills with nothing else and the page stops being " +
      "readable — which is what recordHttp()'s QUIET_WHEN_OK exists to " +
      "prevent.");
  assert.ok(onThePath.length > 0,
      "NO /healthcheck row of any kind came back, not even the POST that was " +
      "just refused — so this section proved nothing: the query, the " +
      "recording or the path could each be broken and it would still pass.");

  // -------------------------------------------------------------------------
  // POLLED, BECAUSE A PER-PROCESS TALLY CONVERGES RATHER THAN SYNCHRONISING
  // (2026-09-08).
  //
  // `admin_stats.calls` is declared `merge: 'own'`: each process keeps its own
  // tally, because `count++` is an INCREMENT and a last-writer-wins row would
  // report one process's traffic while looking perfectly plausible. The
  // console sums them when somebody asks — and those sums are exactly the rows
  // the read barrier deliberately does NOT wait for, since a target that moves
  // with every request is one no reader ever reaches (224 barrier timeouts in
  // one run, every one a stale answer).
  //
  // So with request workers these three probes land on three workers and the
  // sum reaches the reader shortly afterwards rather than instantly. Measured:
  // reading straight back gave 6, 5, 5, 6 for an expected 7, depending on
  // which worker answered — never wrong for long, and never exact at once.
  //
  // THE ASSERTION IS UNCHANGED — the probes must still all be counted. Only
  // the reading is retried, and a run where the number never arrives still
  // fails with the same sentence.
  //
  // **THE BUDGET WENT FROM 20s TO 45s ON 2026-09-09 AND THE REASON IS NOT
  // "IT WAS FLAKY".** It went because this read stopped being able to use the
  // fast path, and the change that did it was somewhere else entirely: on that
  // day `/admin-api` began requiring an access token, so every call this job
  // makes now carries an Authorization header — and `request_pool.js` keys a
  // fanout request on its CREDENTIAL. Every poll below therefore lands on ONE
  // worker, where before they spread across three.
  //
  // That matters because of WHICH mechanism does the catching up.
  // `syncNow()`'s unconditional pass — the one written for exactly these
  // excluded counter rows — runs when the pool decides a reader is behind, and
  // the pool decides that from a generation the WRITES move. These probes are
  // GETs of `/healthcheck`, so nothing bumps it, no barrier fires, and the
  // pinned worker catches up on `persistence.pollInterval` alone.
  //
  // Measured against a three-worker stack under a full suite's load: three
  // probes were visible to every worker in 12s, in two or three poll cycles,
  // and 20s had already failed a run at 1 of 3. 45s is several times the
  // measurement rather than several times the poll interval, which is what the
  // sentence here used to claim.
  // -------------------------------------------------------------------------
  let after = await get("/metrics");
  const deadline = Date.now() + 45000;
  while (healthcheckCalls(after) < countedBefore + PROBES &&
         Date.now() < deadline) {
    await new Promise(function (r) { setTimeout(r, 250); });
    after = await get("/metrics");
  }
  assert.ok(healthcheckCalls(after) >= countedBefore + PROBES,
      "The metrics page counted " + healthcheckCalls(after) + " calls to " +
      "/healthcheck against " + countedBefore + " before " + PROBES + " were " +
      "made. The audit rule is about the event LOG — a counter is one row " +
      "however often it goes up, so the probes must still be counted.");
  log.info("[audit] OK — " + PROBES + " successful probes wrote no row, the " +
           "refused one wrote " + onThePath.length + ", and all of them were " +
           "counted.");
  log.debug("Leaving successfulHealthchecksAreNotInTheAuditLog().");
}

// Every call the metrics table has counted against /healthcheck, whatever the
// method — the row is keyed on the route pattern AND the method, so a GET row
// and a POST row are two of them.
function healthcheckCalls(metrics) {
  log.debug("Entering healthcheckCalls().");
  const rows = (metrics && metrics.calls && metrics.calls.rows) || [];
  let total = 0;
  rows.forEach(function (row) {
    if (String(row.path || "") === "/healthcheck") {
      total += Number(row.count || 0);
    }
  });
  log.debug("Leaving healthcheckCalls(). " + total);
  return total;
}

// ---------------------------------------------------------------------------
// THE CRYPTO REPORT, CHECKED AGAINST WHAT THIS SERVICE ADVERTISES ELSEWHERE.
//
// /admin/crypto-metadata claims that every algorithm list on it is READ FROM
// THE MODULE THAT PERFORMS THE ALGORITHM rather than written down. That claim
// is the whole reason the page is worth having, and it is exactly the kind of
// claim that is true on the day it is made and quietly false a month later —
// somebody adds a curve to `JWS_ALGS`, the discovery document gains it, and a
// list typed into a console page does not.
//
// So this compares the report against the SERVICE'S OWN DISCOVERY DOCUMENT,
// which is a different door onto the same tables. It is the only check that
// can see the two disagree: reading the report on its own says nothing about
// whether it was derived, because a hand-written list is well-formed too.
//
// It also asserts the page's DRIFT REPORT is clean, in both directions. That
// one is about the FILE rather than the service — a protocol family this mock
// advertises with no crypto profile, or a profile naming a family that does
// not exist, which is what a rename produces. The page says so on itself; this
// is what makes it fail rather than merely be said.
// ---------------------------------------------------------------------------
async function theCryptoReportAgreesWithTheServiceItDescribes() {
  log.debug("Entering theCryptoReportAgreesWithTheServiceItDescribes().");
  log.info("=== The crypto report ===");
  const report = await get("/crypto");

  // --- the drift report, both directions --------------------------------
  assert.ok(report.drift && report.drift.checked === true,
    "the crypto page checks its family list against /admin/sts-metadata's, " +
    "and `checked` false means sts_metadata.js never handed that list over — " +
    "so the page is drawing its own word for what this service advertises. " +
    "That is a wiring failure (setProtocolFamilies) and not a disagreement; " +
    "got " + JSON.stringify(report.drift));
  assert.deepStrictEqual(report.drift.undescribed, [],
    "every protocol family this mock advertises must have a crypto profile " +
    "on /admin/crypto-metadata. These have none: " +
    report.drift.undescribed.join(", ") + ". A family added to " +
    "sts_metadata.js's PROTOCOLS needs a row in crypto_metadata.js's " +
    "FAMILIES in the same commit.");
  assert.deepStrictEqual(report.drift.stale, [],
    "and every crypto profile must name a family that is advertised. These " +
    "name one that is not: " + report.drift.stale.join(", ") + " — which is " +
    "what a rename on one side and not the other produces.");
  assert.deepStrictEqual(report.drift.envelopes, [],
    "and every envelope a family cites must have a row in the standards " +
    "table, or the page renders a dead cross-reference. Missing: " +
    report.drift.envelopes.join(", "));

  // --- the coverage notes -----------------------------------------------
  report.standards.forEach(function (row) {
    assert.ok(/^(full|partial|mock)\b/.test(row.coverage),
      "every coverage note must start `full`, `partial` or `mock` and say " +
      "what is missing — the rule /admin/sts-metadata's specification list " +
      "follows, and worth more on a page about cryptography, which somebody " +
      "may be using to learn these specifications. `" + row.key +
      "` starts: " + JSON.stringify(String(row.coverage).slice(0, 60)));
  });

  // --- against the discovery document -----------------------------------
  const oidc = await common.httpJson(base + "/.well-known/openid-configuration");
  assert.ok(oidc.ok, "the OpenID Provider metadata should answer 200; got " +
            oidc.status);
  const oauthFamily = report.families.filter(function (row) {
    return row.name === "OAuth2 / OIDC";
  })[0];
  assert.ok(oauthFamily, "the report should carry the OAuth2 / OIDC family.");
  const listNamed = function (what) {
    const group = oauthFamily.algorithms.filter(function (row) {
      return row.what === what;
    })[0];
    assert.ok(group, "the OAuth2 / OIDC family should carry a `" + what +
              "` algorithm list; it carries " +
              JSON.stringify(oauthFamily.algorithms.map(function (row) {
                return row.what;
              })));
    return group.values;
  };
  assert.deepStrictEqual(listNamed("ID Token, when a client registers one"),
    oidc.body.id_token_signing_alg_values_supported,
    "the crypto page's ID Token signing list must BE the one the discovery " +
    "document advertises, because both are meant to be the same table read " +
    "twice. A difference means one of them is a copy.");
  assert.deepStrictEqual(listNamed("UserInfo response"),
    oidc.body.userinfo_signing_alg_values_supported,
    "and so must the UserInfo signing list. It is deliberately NOT the same " +
    "list as the ID Token's — it adds the HMAC family and `none` — which is " +
    "why it is checked separately rather than assumed to follow.");
  assert.deepStrictEqual(listNamed("JWE key management (out)"),
    oidc.body.userinfo_encryption_alg_values_supported,
    "and so must the JWE key management list.");
  assert.deepStrictEqual(listNamed("JWE content encryption"),
    oidc.body.userinfo_encryption_enc_values_supported,
    "and the content encryption list.");
  const as = await common.httpJson(base +
      "/.well-known/oauth-authorization-server");
  assert.ok(as.ok, "the RFC 8414 metadata should answer 200; got " + as.status);
  assert.deepStrictEqual(listNamed("DPoP proof"),
    as.body.dpop_signing_alg_values_supported,
    "and the DPoP list must be the one RFC 8414 advertises. It is a FILTER " +
    "over the shared JWS table — asymmetric, and not post-quantum, because " +
    "RFC 7638 registers no thumbprint for `AKP` — so a report that listed " +
    "the whole table here would be describing a proof this service refuses.");

  // --- the post-quantum split -------------------------------------------
  const pq = report.postQuantum;
  assert.ok(pq && pq.algorithms.mlDsa.length && pq.algorithms.slhDsa.length &&
            pq.algorithms.composite.length,
    "the post-quantum section should name the ML-DSA, SLH-DSA and composite " +
    "algorithms this service holds; got " + JSON.stringify(pq &&
    pq.algorithms));
  pq.algorithms.mlDsa.concat(pq.algorithms.slhDsa)
    .concat(pq.algorithms.composite.map(function (row) { return row.alg; }))
    .forEach(function (alg) {
      assert.ok(oidc.body.id_token_signing_alg_values_supported
                    .indexOf(alg) >= 0,
        "every post-quantum algorithm the report names must be one this " +
        "service will really sign an ID Token with — a post-quantum section " +
        "listing an algorithm no endpoint accepts is the one thing on that " +
        "page that would be worse than not having it. `" + alg + "` is not " +
        "in id_token_signing_alg_values_supported.");
    });
  assert.strictEqual(pq.keyEstablishment.state, "classical",
    "and the key establishment half must still report itself as classical. " +
    "There is no ML-KEM in this process — not in JWE, not in XML Encryption " +
    "and not on any TLS socket — and the page's whole argument is that the " +
    "two halves are in different positions. If this ever changes, it is the " +
    "sentence to change first.");

  log.info("[crypto] OK — " + report.families.length +
           " identity services profiled with no drift, " +
           report.standards.length +
           " standards each with a coverage note, and 5 algorithm list(s) " +
           "identical to what this service advertises in its own metadata.");
  log.debug("Leaving theCryptoReportAgreesWithTheServiceItDescribes().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Running the management API checks against " + api);
  // Before anything reads the console: the API needs no credential and the
  // console now does.
  const session = await signInToTheConsole();
  const doc = await theDocumentIsServedAndWellFormed();
  const index = await theIndexAgreesWithTheDocument(doc);
  await everySurfaceReportsTheSameBuild(index, session);
  const status = await get("/status");
  everyConsolePageIsMirrored(status, index);
  await everyConsoleActionIsMirrored(index);
  // First of the three that need artifacts to exist, because it is the one
  // that mints them: a schema checked against an empty list, and a comparison
  // of 0 against 0, both pass and prove nothing.
  await revokingHereReachesIntrospection();
  await theSchemasMatchTheReplies(doc);
  await theReadsAgreeWithTheConsole(session);
  await customClaimsCanBeChangedAndPutBack();
  await credentialClaimsCanBeChangedAndPutBack();
  await theVerifierRequestCanBeChangedAndPutBack();
  await configurationCanBeChangedAndPutBack(doc);
  await theBulkRevocationsWorkAndAreUndone();
  await theExplorerIsServedUnderAScopedPolicy(session);
  await successfulHealthchecksAreNotInTheAuditLog();
  await theCryptoReportAgreesWithTheServiceItDescribes();
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("admin_api")
  .description("Verify the mock STS management API at /admin-api: its " +
      "OpenAPI document, its parity with the /admin console, and that its " +
      "revocation is the same one /oauth2/revoke performs.")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
