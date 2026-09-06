"use strict";
//
// File: sts_portal_sessions.js
//
// ===========================================================================
// SIGNING IN CREATES A SESSION, SIGNING OUT INVALIDATES IT, AND ONE PERSON
// CANNOT REACH ANOTHER'S ACCOUNT — ALL OF IT OVER HTTP.
//
// Three claims, driven through the real doors and checked through the
// management API, which is what makes them assertions about the SERVICE rather
// than about a function:
//
//   1. a sign-in at `/admin` and a sign-in at `/portal` each create a session
//      that `GET /admin-api/sessions` lists, named by the surface it came
//      through;
//   2. a signed-in person reaching for SOMEBODY ELSE'S account in the portal
//      gets their own — every parameter a future author might read, with
//      another person's name in it;
//   3. signing out INVALIDATES the session: it leaves that list AND the cookie
//      stops working.
//
// ---------------------------------------------------------------------------
// WHY IT IS HERE, WHICH IS THE FIRST QUESTION tests/CLAUDE.md ASKS.
//
// `local: true`. It drives this service's own `/admin` console and reads
// `/admin-api`, which is an OWNERSHIP argument rather than a capability one:
// the tree that adds a control to that console is the tree that should go red
// when the control loses its operation.
//
// ---------------------------------------------------------------------------
// WHAT THIS ADDS THAT THE IN-PROCESS TESTS DO NOT, because two files already
// assert something adjacent and neither covers this.
//
// `tests/portal_access.js` asserts the CREDENTIAL layer — that
// `credentials.removeKey()` looks an id up among the caller's own keys — and
// `tests/access_policy.js` asserts the POLICY layer, that the XACML document
// denies a subject who is not the owner. **Neither sends a request.** Nothing
// checked that the ROUTES behave, with real sessions, over the wire — which is
// where broken access control actually happens: a handler that reads a
// username from the body instead of the session is invisible to both of those
// files and fails this one.
//
// **THE DECISIVE ASSERTION IS THE AUDIT ROW.** A page that renders the
// caller's own name proves the page; it does not prove the WRITE. So the
// password change is posted with somebody else's name in the body and the
// audit log is read back: the actor must be the person whose session it was.
// That is the one place this service records who a write was attributed to,
// and it is the difference between "the response looked right" and "the right
// account changed".
// ===========================================================================

const assert = require("assert");
const { Command, Option } = require("commander");
const { usernameFor } = require("./random_username.js");

var appconfig;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, for the reason tests/wait_for.js gives.
  appconfig = {};
}

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_portal_sessions",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");
var api = base + "/admin-api";

// Two people, both suffixed per run. The directory is append-only in practice,
// so two runs against one long-lived mock must not see each other's people.
var OPERATOR = usernameFor("portal-operator");
var OWNER = usernameFor("portal-owner");
var INTRUDER = usernameFor("portal-intruder");

var checks = 0;
function check(what, fn) {
  fn();
  checks += 1;
  log.info("  [ok] " + what);
}

// ---------------------------------------------------------------------------
// ONE BROWSER. Manual redirects and a cookie jar of our own, because every
// assertion here is about WHICH redirect and about WHOSE session — a fetch
// that followed them would answer the question by hiding it.
// ---------------------------------------------------------------------------
function form(o) {
  return new URLSearchParams(o).toString();
}

function absolute(location) {
  return /^https?:\/\//i.test(String(location || ""))
    ? String(location) : base + String(location || "");
}

function browser(name) {
  const self = {
    name: name,
    cookie: "",
    async go(method, path, body) {
      const headers = {};
      if (self.cookie) headers.cookie = self.cookie;
      if (body !== undefined) {
        headers["Content-Type"] = "application/x-www-form-urlencoded";
      }
      const r = await fetch(absolute(path), { method: method, redirect: "manual",
                                              headers: headers, body: body });
      const set = r.headers.getSetCookie ? r.headers.getSetCookie() : [];
      set.forEach(function (one) { self.cookie = String(one).split(";")[0]; });
      return { status: r.status, location: r.headers.get("location") || "",
               text: await r.text() };
    }
  };
  return self;
}

async function get(path) {
  const r = await fetch(api + path);
  const raw = await r.text();
  let body;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    // An HTML error page from a door that answers JSON is worth quoting whole
    // rather than reporting as a parse failure.
    body = raw;
  }
  return { status: r.status, body: body, raw: raw };
}

// The session id out of the cookie, so an assertion can name the row it means
// rather than "the only one there" — this suite runs against a service other
// jobs are also signing in to.
function sessionIdOf(b) {
  return String(b.cookie || "").split("=")[1] || "";
}

async function liveSessions() {
  const r = await get("/sessions?per=200");
  assert.ok(r.status === 200 && r.body && Array.isArray(r.body.sessions),
    "GET /admin-api/sessions should list sessions; it answered " + r.status +
    " " + String(r.raw).slice(0, 200));
  return r.body.sessions;
}

async function rowFor(id) {
  const rows = await liveSessions();
  return rows.filter(function (row) { return row.sessionId === id; })[0] || null;
}

// ---------------------------------------------------------------------------
// SIGN IN AT A DOOR. Both doors send an unauthenticated browser to the same
// screen — that is `authn.js` owning the session and every family reaching it
// through `beginAuthentication()` — so one function drives both, and WHICH
// door it started at is what the session's `protocol` should then say.
// ---------------------------------------------------------------------------
async function signInAt(door, who) {
  log.debug("Entering signInAt(). door=" + door);
  const b = browser(who);
  let r = await b.go("GET", door);
  assert.ok(/\/authn\/login\?authn=/.test(r.location),
    door + " should send an unauthenticated browser to the sign-in screen; " +
    "it answered " + r.status + " -> " + r.location);
  r = await b.go("GET", r.location);
  const authnId = (r.text.match(/name="authn_id" value="([^"]+)"/) || [])[1];
  assert.ok(authnId, "the sign-in screen carries no authn_id to post back.");
  r = await b.go("POST", "/authn/login",
                 form({ authn_id: authnId, username: who,
                        password: "any-password", action: "login" }));
  assert.ok(r.status === 303 || r.status === 302,
    "the sign-in form should redirect, got " + r.status + " " +
    String(r.text).slice(0, 200));
  assert.ok(b.cookie, "signing in should establish a session cookie.");
  log.debug("Leaving signInAt(). " + sessionIdOf(b));
  return b;
}

function csrfOf(text) {
  return (String(text).match(/name="csrf_token" value="([^"]+)"/) || [])[1] || "";
}

// ---------------------------------------------------------------------------
// 1. THE ADMIN CONSOLE.
// ---------------------------------------------------------------------------
async function theConsoleSignInCreatesASession() {
  log.info("=== the admin console: sign in, and the session is listed ===");
  const before = (await liveSessions()).length;
  const b = await signInAt("/admin/sessions", OPERATOR);
  const id = sessionIdOf(b);

  const row = await rowFor(id);
  check("signing in at /admin creates a session the management API lists",
    function () {
      assert.ok(row, "no row for session " + id + " in GET /admin-api/sessions");
    });
  check("it names the person who signed in", function () {
    assert.strictEqual(row.username, OPERATOR);
  });
  check("and the SURFACE they came through, which is what makes the row " +
        "worth reading — every browser family shares one session, so the " +
        "protocol is where it STARTED and not the only thing using it",
    function () {
      assert.strictEqual(row.protocol, "Admin console");
    });
  check("it is a browser sign-on session and not one of the other three " +
        "kinds", function () {
      assert.strictEqual(row.kind, "Browser sign-on session");
    });
  check("and somebody actually authenticated for it — the field that tells " +
        "it from a Continue-without-signing-in session", function () {
      assert.strictEqual(row.authenticated, true);
    });

  const after = await liveSessions();
  check("the count went up by exactly one", function () {
    assert.strictEqual(after.length, before + 1);
  });

  // The console is REACHABLE now, which is the half a list cannot show: a row
  // in a register and a working credential are different claims.
  const page = await b.go("GET", "/admin/sessions");
  check("and the console it was signed in to now answers 200 rather than " +
        "redirecting", function () {
      assert.strictEqual(page.status, 200);
    });
  return b;
}

// ---------------------------------------------------------------------------
// 2. THE USER PORTAL.
// ---------------------------------------------------------------------------
async function thePortalSignInCreatesASession() {
  log.info("=== the user portal: sign in, and the session is listed ===");
  const b = await signInAt("/portal", OWNER);
  const id = sessionIdOf(b);
  const row = await rowFor(id);

  check("signing in at /portal creates a session the management API lists",
    function () {
      assert.ok(row, "no row for session " + id);
    });
  check("named for the person and for the PORTAL, so the two doors are told " +
        "apart in the register even though they share one session store",
    function () {
      assert.strictEqual(row.username, OWNER);
      assert.strictEqual(row.protocol, "User Portal");
    });

  const page = await b.go("GET", "/portal");
  check("and the portal answers 200 for them", function () {
    assert.strictEqual(page.status, 200);
  });
  check("showing THEIR name", function () {
    assert.ok(page.text.indexOf(OWNER) >= 0,
      "the portal page does not name " + OWNER);
  });
  return b;
}

// ---------------------------------------------------------------------------
// 3. OWASP A01: ONE PERSON CANNOT REACH ANOTHER'S ACCOUNT.
//
// The intruder is SIGNED IN. That is the whole point: this is not an
// unauthenticated caller being turned away, it is a real session reaching for
// somebody else's data, which is the shape broken access control actually
// takes.
// ---------------------------------------------------------------------------
async function oneUserCannotReachAnother(owner) {
  log.info("=== a signed-in person cannot reach another's portal account ===");
  const b = await signInAt("/portal", INTRUDER);

  // EVERY PARAMETER A FUTURE AUTHOR MIGHT PLAUSIBLY READ, with the owner's
  // name in it. A handler that grew `req.query.user` would fail here on the
  // day it was written rather than on the day somebody noticed.
  const q = form({ user: OWNER, username: OWNER, id: OWNER, uid: OWNER,
                   sub: OWNER, dn: "uid=" + OWNER + ",ou=users,dc=example,dc=com",
                   account: OWNER, as: OWNER });
  const page = await b.go("GET", "/portal?" + q);
  check("the portal answers the intruder's own page, not a refusal — the " +
        "parameters are IGNORED rather than obeyed or rejected, which is " +
        "what reading the identity from the session means", function () {
      assert.strictEqual(page.status, 200);
    });
  check("IT NAMES THE INTRUDER", function () {
    assert.ok(page.text.indexOf(INTRUDER) >= 0,
      "the page does not name " + INTRUDER);
  });
  check("AND IT DOES NOT NAME THE OWNER ANYWHERE, which is the assertion " +
        "that fails the moment a handler starts reading a name off the request",
    function () {
      assert.ok(page.text.indexOf(OWNER) < 0,
        "the intruder's portal page contains " + OWNER + " — somewhere in " +
        "this page somebody else's account is being shown");
    });

  // THE WRITE, WHICH IS THE HALF A RENDERED PAGE CANNOT PROVE. The audit log
  // is the one place this service records who a change was attributed to.
  const csrf = csrfOf((await b.go("GET", "/portal")).text);
  assert.ok(csrf, "the portal draws no csrf_token to post back.");
  const wrote = await b.go("POST", "/portal/password",
    form({ csrf_token: csrf, username: OWNER, user: OWNER,
           current: "any-password", next: "IntruderChosen123!",
           confirm: "IntruderChosen123!" }));
  check("a password change naming somebody else is accepted or refused, but " +
        "either way it answers — it is not a crash", function () {
      assert.ok(wrote.status === 303 || wrote.status === 302 ||
                wrote.status === 200 || wrote.status === 403,
        "unexpected " + wrote.status);
    });

  const audit = await get("/audit?per=200");
  assert.ok(audit.status === 200 && audit.body && Array.isArray(audit.body.events),
    "GET /admin-api/audit should list events; it answered " + audit.status);
  const changes = audit.body.events.filter(function (e) {
    return String(e.action || "").indexOf("portal.password") === 0;
  });
  check("the password change was recorded", function () {
    assert.ok(changes.length > 0,
      "no portal.password* row in the audit log at all");
  });
  check("AND THE ACTOR IS THE INTRUDER, NEVER THE OWNER. This is the " +
        "decisive assertion in this file: a page that renders the caller's " +
        "own name proves the PAGE, and only this proves the WRITE went to " +
        "the caller's account and not to the one they named",
    function () {
      const wrong = changes.filter(function (e) {
        return String(e.actor || "") === OWNER;
      });
      assert.strictEqual(wrong.length, 0,
        "a portal password change was attributed to " + OWNER +
        ", who did not make it: " + JSON.stringify(wrong[0]));
    });

  // And the owner's own session is untouched by any of it.
  const ownerRow = await rowFor(sessionIdOf(owner));
  check("the owner's session is still live — the intruder reached nothing " +
        "and broke nothing", function () {
      assert.ok(ownerRow, "the owner's session disappeared");
      assert.strictEqual(ownerRow.username, OWNER);
    });
  return b;
}

// ---------------------------------------------------------------------------
// 4. SIGNING OUT INVALIDATES THE SESSION.
//
// **TWO ASSERTIONS AND NOT ONE.** Leaving the register is what an operator
// SEES; the cookie no longer working is what actually matters, and a bug that
// removed the row and left the session usable would pass the first alone.
// ---------------------------------------------------------------------------
async function signingOutInvalidatesIt(b, who, door) {
  log.info("=== " + who + " signs out ===");
  const id = sessionIdOf(b);
  assert.ok(await rowFor(id), "precondition: " + who + " should be signed in");

  const out = await b.go("POST", "/logout", form({}));
  check(who + "'s sign-out answers", function () {
    assert.ok(out.status === 200 || out.status === 303 || out.status === 302,
      "POST /logout answered " + out.status);
  });

  const gone = await rowFor(id);
  check("THE SESSION IS GONE FROM GET /admin-api/sessions, which is what an " +
        "operator looking at /admin/sessions sees", function () {
      assert.strictEqual(gone, null,
        "session " + id + " is still listed after a sign-out");
    });

  // THE HALF THE LIST CANNOT SHOW. The cookie is deliberately re-presented:
  // this is the assertion that fails for a sign-out that forgot the row and
  // left the credential working.
  const again = await b.go("GET", door);
  check("AND THE COOKIE NO LONGER WORKS — presenting it at " + door +
        " sends the browser back to the sign-in screen rather than to the " +
        "page. A row removed from a register and a credential that stops " +
        "being accepted are different claims, and only the second is a " +
        "sign-out", function () {
      assert.ok(again.status === 302 || again.status === 303,
        door + " answered " + again.status + " to a signed-out cookie; it " +
        "should have redirected to the sign-in screen");
      assert.ok(/\/authn\/login/.test(again.location),
        "it redirected to " + again.location + " rather than to the sign-in " +
        "screen");
    });

  const audit = await get("/audit?per=200");
  const ended = audit.body.events.filter(function (e) {
    return String(e.action || "") === "session.end" &&
           String(e.target || "") === id;
  });
  check("and the sign-out is in the audit log naming that session — the row " +
        "an operator asked 'when did this end' would read", function () {
      assert.ok(ended.length > 0,
        "no session.end row naming " + id);
    });
}

async function test() {
  log.info("Driving the admin console and the User Portal at " + base);

  const operator = await theConsoleSignInCreatesASession();
  const owner = await thePortalSignInCreatesASession();

  check("both sessions are live at once and are DIFFERENT sessions — one " +
        "store does not mean one session", function () {
      assert.notStrictEqual(sessionIdOf(operator), sessionIdOf(owner));
    });

  const intruder = await oneUserCannotReachAnother(owner);

  await signingOutInvalidatesIt(intruder, INTRUDER, "/portal");
  await signingOutInvalidatesIt(owner, OWNER, "/portal");
  await signingOutInvalidatesIt(operator, OPERATOR, "/admin/sessions");

  // A FLOOR ON THE COUNT, for sts_admin_console.js's reason: a section that
  // stops being called takes its assertions with it and the run still says
  // "passed", which is the one failure mode a suite cannot report about
  // itself.
  assert.ok(checks >= 24,
    "only " + checks + " assertions ran; a section has stopped being called.");
  log.info(checks + " assertion(s).");
  log.info("Test completed successfully.");
}

const program = new Command();
program
  .name("sts_portal_sessions")
  .description("Sign in at /admin and at /portal, check the session through " +
      "the management API, prove a signed-in person cannot reach another's " +
      "portal account, then sign out and prove the session is invalid — gone " +
      "from the register AND no longer accepted.")
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
