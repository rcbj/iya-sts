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
const { usernameFor, runStamp } = require("./random_username.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, for the reason tests/wait_for.js gives.
  appconfigProblem = e;
  appconfig = {};
}

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_portal_sessions",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug('CONFIG_FILE could not be read, so the configuration is empty: ' +
            appconfigProblem.message);
}
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
// The fourth person exists only to be ACTIVATED: they are created through the
// management API with no credential at all, which is the one way into this
// service that starts before anybody can sign in.
var NEWCOMER = usernameFor("portal-newcomer");

// ---------------------------------------------------------------------------
// EVERY PERSON THIS JOB SIGNS IN IS CREATED FIRST, WITH A PASSWORD AND THE
// ATTRIBUTES A REAL ACCOUNT CARRIES (2026-09-12).
//
// In product mode this service invents no persona for a name that signs in,
// creates nobody because a sign-in named them, and verifies the password
// against the person's own entry. The suite runs in development, where none of
// that is enforced — which is exactly why a job that leaned on it would go on
// passing while testing the invention. So `ensurePerson()` makes each account
// through `/admin-api/users/create` with `invent: false`, its own `cn`, `sn`,
// `givenName`, `displayName` and `mail`, and a password of at least twelve
// characters, and that password is what the sign-in screen is sent.
// ---------------------------------------------------------------------------
var PASSWORD = "portal-sessions-Passw0rd!-" + String(Date.now()).slice(-6);
var MAIL_DOMAIN = "portal-sessions.test";

function personAttributes(who) {
  log.debug("Entering personAttributes().");
  log.debug("Leaving personAttributes().");
  return { cn: "Portal Person " + who, givenName: "Portal", sn: who,
           displayName: "Portal Person " + who, mail: who + "@" + MAIL_DOMAIN };
}

var checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

// ---------------------------------------------------------------------------
// ONE BROWSER. Manual redirects and a cookie jar of our own, because every
// assertion here is about WHICH redirect and about WHOSE session — a fetch
// that followed them would answer the question by hiding it.
// ---------------------------------------------------------------------------
function form(o) {
  log.debug("Entering form().");
  log.debug("Leaving form().");
  return new URLSearchParams(o).toString();
}

function absolute(location) {
  log.debug("Entering absolute().");
  log.debug("Leaving absolute().");
  return /^https?:\/\//i.test(String(location || ""))
    ? String(location) : base + String(location || "");
}

function browser(name) {
  log.debug("Entering browser().");
  const self = {
    name: name,
    cookie: "",
    jar: {},
    cookieHeader: function () {
      log.debug("Entering cookieHeader().");
      log.debug("Leaving cookieHeader().");
      return Object.keys(self.jar).map(function (k) {
        return k + "=" + self.jar[k];
      }).join("; ");
    },
    async go(method, path, body) {
      log.debug("Entering go().");
      const headers = {};
      if (self.cookie) headers.cookie = self.cookie;
      if (body !== undefined) {
        headers["Content-Type"] = "application/x-www-form-urlencoded";
      }
      const r = await fetch(absolute(path),
                            { method: method, redirect: "manual",
                                              headers: headers, body: body });
      // A JAR KEYED BY NAME, and it has to be since 2026-09-06: a browser
      // signing in to a hosted surface ends up holding TWO cookies — the
      // sign-on session (`sts_session`, the identity provider's) and the
      // surface's own, established from the ID Token. Keeping only the last
      // one seen dropped whichever arrived first, which made the second half
      // of every flow behave as though nobody had signed in.
      const set = r.headers.getSetCookie ? r.headers.getSetCookie() : [];
      set.forEach(function (one) {
        const pair = String(one).split(";")[0];
        const name = pair.split("=")[0];
        const value = pair.slice(name.length + 1);
        // An empty value is a cookie being CLEARED — which is what a sign-out
        // sends — and it has to remove the entry rather than store an empty
        // one, or the jar goes on presenting a name with nothing after it.
        if (value === "" || /Expires=Thu, 01 Jan 1970/i.test(String(one))) {
          delete self.jar[name];
        } else {
          self.jar[name] = value;
        }
        self.cookie = self.cookieHeader();
      });
      log.debug("Leaving go().");
      return { status: r.status, location: r.headers.get("location") || "",
               text: await r.text() };
    }
  };
  log.debug("Leaving browser().");
  return self;
}

async function get(path) {
  log.debug("Entering get().");
  const r = await fetch(api + path);
  const raw = await r.text();
  let body;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in get(): " + ((e && e.message) || e));
    // An HTML error page from a door that answers JSON is worth quoting whole
    // rather than reporting as a parse failure.
    body = raw;
  }
  log.debug("Leaving get().");
  return { status: r.status, body: body, raw: raw };
}

// The management API taking JSON, for the one thing this job needs that no
// browser door offers: creating a person who has no credential yet. It is
// ungated like everything under /admin-api, which is what a test drives.
async function post(path, body) {
  log.debug("Entering post().");
  const r = await fetch(api + path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
  const raw = await r.text();
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in post(): " + ((e && e.message) || e));
    // An HTML error page from a door that answers JSON is worth quoting whole
    // rather than reporting as a parse failure.
    parsed = raw;
  }
  log.debug("Leaving post().");
  return { status: r.status, body: parsed, raw: raw };
}

// Create `who` with a password and real attributes, once. A name this job has
// already created (a second sign-in by the same person) is left as it is.
var createdPeople = {};
async function ensurePerson(who) {
  log.debug("Entering ensurePerson(). who=" + who);
  if (createdPeople[who]) {
    log.debug("Leaving ensurePerson(). Already created by this run.");
    return;
  }
  const r = await post("/users/create", {
    username: who, invent: false, attributes: personAttributes(who),
    credential: "password", password: PASSWORD
  });
  assert.ok(r.status === 200 && r.body && r.body.ok && r.body.passwordSet,
    "POST /admin-api/users/create should create " + who + " with a password " +
    "before they sign in; it answered " + r.status + " " +
    String(r.raw).slice(0, 300));
  createdPeople[who] = true;
  log.debug("Leaving ensurePerson(). Created " + who + ".");
}

// The session id out of the cookie, so an assertion can name the row it means
// rather than "the only one there" — this suite runs against a service other
// jobs are also signing in to.
//
// **IT IS THE SURFACE'S OWN SESSION SINCE 2026-09-06 AND NOT THE SIGN-ON
// SESSION.** Signing in at `/admin` now produces two rows: the sign-on session
// the identity provider holds, and the RELYING PARTY session the console holds,
// derived from it. The one a door CREATED is the second, so that is the one
// these assertions are about — and `signOnIdOf()` beside it is how a test
// reaches the other when it means the other.
const SURFACE_COOKIES = { admin: "sts_admin", portal: "sts_portal" };
const SIGN_ON_COOKIE = "sts_session";

function sessionIdOf(b) {
  log.debug("Entering sessionIdOf().");
  log.debug("Leaving sessionIdOf().");
  return b.jar[SURFACE_COOKIES.admin] || b.jar[SURFACE_COOKIES.portal] || "";
}

function signOnIdOf(b) {
  log.debug("Entering signOnIdOf().");
  log.debug("Leaving signOnIdOf().");
  return b.jar[SIGN_ON_COOKIE] || "";
}

async function liveSessions() {
  log.debug("Entering liveSessions().");
  const r = await get("/sessions?per=200");
  assert.ok(r.status === 200 && r.body && Array.isArray(r.body.sessions),
    "GET /admin-api/sessions should list sessions; it answered " + r.status +
    " " + String(r.raw).slice(0, 200));
  log.debug("Leaving liveSessions().");
  return r.body.sessions;
}

async function rowFor(id) {
  log.debug("Entering rowFor().");
  const rows = await liveSessions();
  log.debug("Leaving rowFor().");
  return rows.filter(function (row) { return row.sessionId === id; })[0] ||
         null;
}

// ---------------------------------------------------------------------------
// SIGN IN AT A DOOR. Both doors send an unauthenticated browser to the same
// screen — that is `authn.js` owning the session and every family reaching it
// through `beginAuthentication()` — so one function drives both, and WHICH
// door it started at is what the session's `protocol` should then say.
// ---------------------------------------------------------------------------
// **IT IS AN AUTHORIZATION CODE FLOW SINCE 2026-09-06 AND WAS A REDIRECT TO THE
// SIGN-IN SCREEN BEFORE IT.** `/admin` and `/portal` are RELYING PARTIES of
// this service's own authorization server now — `sts-admin-console` and
// `sts-user-portal`, both ordinary entries under `ou=applications` — so an
// unauthenticated request is answered with a redirect to `/oauth2/authorize`
// and the sign-in screen is reached because the AUTHORIZATION ENDPOINT decides
// it needs one.
//
// **THE HOPS ARE ASSERTED RATHER THAN FOLLOWED BLINDLY**, which is the whole
// reason this helper does not just turn redirect-following on: what is worth
// checking is that the FIRST hop goes to the authorization endpoint as the
// right client, and that the LAST one comes back to that surface's registered
// redirect URI with a code. A `redirect: "follow"` fetch would assert that
// signing in works and nothing at all about which protocol did it.
//
// The browser ends up holding TWO cookies and that is the design: the sign-on
// session (`sts_session`, the identity provider's) and the surface's own
// (`sts_admin` or `sts_portal`, established from the ID Token). The
// jar keeps whichever it was last sent, so `cookies` below holds both by name.
async function signInAt(door, who) {
  log.debug("Entering signInAt(). door=" + door);
  await ensurePerson(who);
  const b = browser(who);
  let r = await b.go("GET", door);
  assert.ok(/\/oauth2\/authorize\?/.test(r.location),
    door + " should send an unauthenticated browser to the AUTHORIZATION " +
    "ENDPOINT; it answered " + r.status + " -> " + r.location);
  assert.ok(/client_id=sts-(admin-console|user-portal)/.test(r.location),
    "the authorization request should name one of this service's own two " +
    "seeded clients; it was " + r.location);
  assert.ok(/code_challenge=/.test(r.location) &&
            /code_challenge_method=S256/.test(r.location),
    "PKCE is always sent and there is no setting to turn it off; the " +
    "authorization request was " + r.location);

  // The authorization endpoint, which finds no sign-on session and sends the
  // browser to the screen.
  r = await b.go("GET", r.location);
  assert.ok(/\/authn\/login\?authn=/.test(r.location),
    "the authorization endpoint should send a browser with no sign-on " +
    "session to the sign-in screen; it " +
    "answered " + r.status + " -> " + r.location);

  r = await b.go("GET", r.location);
  const authnId = (r.text.match(/name="authn_id" value="([^"]+)"/) || [])[1];
  assert.ok(authnId, "the sign-in screen carries no authn_id to post back.");
  r = await b.go("POST", "/authn/login",
                 form({ authn_id: authnId, username: who,
                        password: PASSWORD, action: "login",
                        csrf_token: csrfOf(r.text) }));
  assert.ok(r.status === 303 || r.status === 302,
    "the sign-in form should redirect, got " + r.status + " " +
    String(r.text).slice(0, 200));

  // Back to the authorization endpoint, which now has a sign-on session and
  // answers with a code at the surface's registered redirect URI.
  r = await b.go("GET", r.location);
  assert.ok(/\/(admin|portal)\/callback\?/.test(r.location) &&
            /[?&]code=/.test(r.location),
    "the authorization endpoint should come back to the surface's registered " +
    "redirect URI with a code; it answered " + r.status + " -> " + r.location);

  // And the callback, which redeems the code and establishes the surface's own
  // session. THIS is the hop that sets the cookie the surface then reads.
  r = await b.go("GET", r.location);
  assert.ok(r.status === 303 || r.status === 302,
    "the callback should redirect to the page that was asked for; it answered " +
    r.status + " " + String(r.text).slice(0, 300));
  assert.ok(b.cookie, "completing the flow should establish a session cookie.");
  log.debug("Leaving signInAt(). " + sessionIdOf(b));
  return b;
}

function csrfOf(text) {
  log.debug("Entering csrfOf().");
  log.debug("Leaving csrfOf().");
  return (String(text).match(/name="csrf_token" value="([^"]+)"/) ||
          [])[1] || "";
}

// Follow redirects to wherever they end, bounded. Used where the assertion is
// about the DESTINATION rather than the journey — `signInAt()` asserts every
// hop by hand precisely because there the journey is the subject.
async function follow(b, r, hops) {
  log.debug("Entering follow().");
  let at = r;
  for (let i = 0; i < (hops || 6) &&
                  (at.status === 302 || at.status === 303); i++) {
    at = await b.go("GET", at.location);
  }
  log.debug("Leaving follow().");
  return at;
}

// ---------------------------------------------------------------------------
// 1. THE ADMIN CONSOLE.
// ---------------------------------------------------------------------------
async function theConsoleSignInCreatesASession() {
  log.debug("Entering theConsoleSignInCreatesASession().");
  log.info("=== the admin console: sign in, and the session is listed ===");
  const before = (await liveSessions()).length;
  const b = await signInAt("/admin/sessions", OPERATOR);
  const id = sessionIdOf(b);

  const row = await rowFor(id);
  check("signing in at /admin creates a session the management API lists",
    function () {
      assert.ok(row,
                "no row for session " + id + " in GET /admin-api/sessions");
    });
  check("it names the person who signed in", function () {
    assert.strictEqual(row.username, OPERATOR);
  });
  check("IT IS THE CONSOLE'S OWN SESSION AND NOT THE SIGN-ON SESSION, which " +
        "is what moving this surface onto the authorization code flow " +
        "bought: the console is a relying party and holds a session of its " +
        "own, derived from the one the identity provider holds", function () {
      assert.strictEqual(row.kind, "Admin console session");
    });
  check("it names the client that holds it — an ordinary entry in the " +
        "registry, which is what the console signs in AS", function () {
      assert.strictEqual(row.rpClientId, "sts-admin-console");
    });
  check("AND THE SIGN-ON SESSION IT WAS DERIVED FROM, which is the join that " +
        "makes a sign-out reach both", function () {
      assert.strictEqual(row.derivedFrom, signOnIdOf(b));
    });

  const signOn = await rowFor(signOnIdOf(b));
  check("that sign-on session is listed too, as a SECOND row of a different " +
        "kind — one store, two kinds of thing, told apart by a field rather " +
        "than by a register of their own", function () {
      assert.ok(signOn, "no row for sign-on session " + signOnIdOf(b));
      assert.strictEqual(signOn.kind, "Browser sign-on session");
    });
  check("and somebody actually authenticated for it — the field that tells " +
        "it from a Continue-without-signing-in session", function () {
      assert.strictEqual(row.authenticated, true);
    });

  const after = await liveSessions();
  check("THE COUNT WENT UP BY EXACTLY TWO, which is the whole shape of this " +
        "change in one number: an identity provider session and an " +
        "application session, where before there was one row doing both jobs",
    function () {
      assert.strictEqual(after.length, before + 2);
    });

  // The console is REACHABLE now, which is the half a list cannot show: a row
  // in a register and a working credential are different claims.
  const page = await b.go("GET", "/admin/sessions");
  check("and the console it was signed in to now answers 200 rather than " +
        "redirecting", function () {
      assert.strictEqual(page.status, 200);
    });
  log.debug("Leaving theConsoleSignInCreatesASession().");
  return b;
}

// ---------------------------------------------------------------------------
// 2. THE USER PORTAL.
// ---------------------------------------------------------------------------
async function thePortalSignInCreatesASession() {
  log.debug("Entering thePortalSignInCreatesASession().");
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
      assert.strictEqual(row.protocol, "User portal");
    });

  const page = await b.go("GET", "/portal");
  check("and the portal answers 200 for them", function () {
    assert.strictEqual(page.status, 200);
  });
  check("showing THEIR name", function () {
    assert.ok(page.text.indexOf(OWNER) >= 0,
      "the portal page does not name " + OWNER);
  });
  log.debug("Leaving thePortalSignInCreatesASession().");
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
  log.debug("Entering oneUserCannotReachAnother().");
  log.info("=== a signed-in person cannot reach another's portal account ===");
  const b = await signInAt("/portal", INTRUDER);

  // EVERY PARAMETER A FUTURE AUTHOR MIGHT PLAUSIBLY READ, with the owner's
  // name in it. A handler that grew `req.query.user` would fail here on the
  // day it was written rather than on the day somebody noticed.
  const q = form({ user: OWNER, username: OWNER, id: OWNER, uid: OWNER,
                   sub: OWNER,
                   dn: "uid=" + OWNER + ",ou=users,dc=example,dc=com",
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
           current: PASSWORD, next: "IntruderChosen123!",
           confirm: "IntruderChosen123!" }));
  check("a password change naming somebody else is accepted or refused, but " +
        "either way it answers — it is not a crash", function () {
      assert.ok(wrote.status === 303 || wrote.status === 302 ||
                wrote.status === 200 || wrote.status === 403,
        "unexpected " + wrote.status);
    });

  const audit = await get("/audit?per=200");
  assert.ok(audit.status === 200 && audit.body &&
            Array.isArray(audit.body.events),
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
  log.debug("Leaving oneUserCannotReachAnother().");
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
  log.debug("Entering signingOutInvalidatesIt().");
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
        "should have started a new sign-in");
      // **IT IS THE AUTHORIZATION ENDPOINT AND NOT THE SIGN-IN SCREEN SINCE
      // 2026-09-06**, and that is the same assertion rather than a weaker one:
      // these two surfaces are relying parties now, so a request they do not
      // recognise starts a new authorization request — which is what reaches
      // the screen. What is being checked is unchanged: the presented cookie
      // bought nothing.
      assert.ok(/\/oauth2\/authorize\?/.test(again.location),
        "it redirected to " + again.location + " rather than starting a new " +
        "authorization request");
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
  log.debug("Leaving signingOutInvalidatesIt().");
}

// ---------------------------------------------------------------------------
// 4. THE ACTIVATION LINK ENDS AT A SIGN-IN THAT WORKS.
//
// **THIS SECTION EXISTS BECAUSE THE LAST STEP OF IT WAS AN ERROR PAGE**, and
// the shape of that defect is the reason it is asserted over HTTP rather than
// anywhere cheaper. Setting a password at `/portal/activate` worked, the
// account was real, the audit row was written — and the button offered at the
// end, labelled *Sign in*, pointed at a bare `/authn/login`. That endpoint
// draws a form for a PENDING AUTHENTICATION RECORD and answers 400
// `There is no sign-in waiting under that id` to a request naming none, so the
// whole activation flow finished on an OAuth error page. Every function
// involved was correct; the only thing wrong was one `href`, which is exactly
// what no in-process test can see.
//
// So the assertion is on the LINK and then on FOLLOWING it. Checking only that
// the page renders would have passed on the broken version, and checking only
// that `/portal` redirects to the screen would have missed that this page does
// not send anybody there.
// ---------------------------------------------------------------------------
async function anActivationLinkEndsAtAUsableSignIn() {
  log.debug("Entering anActivationLinkEndsAtAUsableSignIn().");
  log.info("=== an activation link ends at a sign-in that works ===");
  // Created with the attributes a real account carries and NO credential —
  // the activation link below is how the credential arrives.
  const created = await post("/users/create",
    { username: NEWCOMER, invent: false, attributes: personAttributes(NEWCOMER),
      credential: "activation" });
  assert.ok(created.status === 200 && created.body && created.body.ok,
    "POST /admin-api/users/create should create " + NEWCOMER +
    "; it answered " +
    created.status + " " + String(created.raw).slice(0, 300));
  const link = String((created.body || {}).activationUrl || "");
  check("creating a user with credential=activation hands back a link, once",
    function () {
      assert.ok(/^\/portal\/activate\?user=/.test(link),
        "no activation URL came back: " +
        JSON.stringify(created.body).slice(0, 300));
    });

  // **THE WHOLE OF THIS SECTION IS DRIVEN WITH NO SESSION, WHICH IS THE
  // PREMISE RATHER THAN A CONVENIENCE.** A password-set link is followed by
  // somebody who cannot sign in yet — that is what it is FOR — so every
  // assertion here is about an unauthenticated browser, and the cookie jar is
  // checked at each step rather than assumed empty. A step that quietly
  // started working only because a session existed would be a step that fails
  // for the one person this flow is written for.
  const b = browser(NEWCOMER);
  let r = await b.go("GET", link);
  check("the activation link opens the setup form for a browser holding no " +
        "sign-in — nobody following a password-set link can have one",
    function () {
      assert.strictEqual(r.status, 200);
    });
  // **HOW "HOLDING NO SESSION" IS ASKED CHANGED ON 2026-09-07**, and the
  // paragraph above still means every word of what it says. It used to be
  // `b.cookie === ""`, which stopped being the same question when `authn.js`
  // began minting an ARRIVAL SESSION for every cookie-less request at a
  // protocol front door — so this browser is handed one by the very request
  // that opens the link, before it has typed anything.
  //
  // That session names the `anonymous` principal, carries
  // `authenticated: false` and `chosen: false`, and `sessionOf()` refuses to
  // hand one to anybody: the browser holds a COOKIE and holds no SIGN-IN, and
  // those were the same sentence until they were not. What this section is
  // about is somebody who CANNOT sign in yet, so the assertion is that they
  // still cannot — asked of `/portal`, which sends an unauthenticated browser
  // to the authorization endpoint (see signInAt()). A step that had quietly
  // started working because a session existed is exactly what this catches,
  // and it catches it where the old line could not: a real sign-on session
  // would send them to their account instead.
  const notSignedIn = await b.go("GET", "/portal");
  check("and that browser is signed in to NOBODY — the cookie it now holds " +
        "names an anonymous arrival session and not a person",
    function () {
      assert.ok(/\/oauth2\/authorize\?/.test(notSignedIn.location),
        "/portal should still send this browser to the authorization " +
        "endpoint; it answered " + notSignedIn.status + " -> " +
        notSignedIn.location + ". The jar holds " + b.cookie);
    });
  const token = (r.text.match(/name="token" value="([^"]+)"/) || [])[1];
  assert.ok(token, "the activation form carries no token to post back.");

  const password = "Activated-Pw1!-" + Date.now();
  r = await b.go("POST", "/portal/activate",
                 form({ user: NEWCOMER, token: token, password: password,
                        confirm: password, key_role: "none",
                        csrf_token: csrfOf(r.text) }));
  check("setting a password spends the link and answers the account-ready page",
    function () {
      assert.strictEqual(r.status, 200);
      assert.ok(/ready/i.test(r.text),
        "the activation POST did not answer the account-ready page: " +
        String(r.text).slice(0, 300));
    });

  // AND IT SIGNS NOBODY IN, which is `portal/CLAUDE.md`'s rule and the whole
  // difference between a SETUP link and a MAGIC link: spending it proves
  // possession of a link, which is not the credential just configured. A
  // session minted here would be a standing bypass of the mechanism the person
  // is in the middle of choosing, and the page that follows has to offer a way
  // to sign in precisely BECAUSE of that.
  //
  // **ASKED OF `/portal` AND NOT OF THE COOKIE JAR, AND HERE THAT IS THE ONLY
  // THING THAT CAN WORK.** The jar has held an anonymous arrival session since
  // the link was opened, so "is it empty" stopped being this question.
  // Comparing the VALUE would not have rescued it either: `startSession()`
  // upgrades an arrival row IN PLACE and keeps its id, precisely so the cookie
  // the browser already has goes on naming the session — so a real sign-in
  // here would leave the jar holding the same string it held a moment ago.
  // Only asking a gated page whether this browser is anybody tells them apart.
  const stillNobody = await b.go("GET", "/portal");
  check("and it establishes NO session — the last step of setup is to go and " +
        "use the credential, not to be let in by the link that set it",
    function () {
      assert.ok(/\/oauth2\/authorize\?/.test(stillNobody.location),
        "spending the activation link signed this browser in: /portal " +
        "answered " + stillNobody.status + " -> " + stillNobody.location +
        " instead of sending it to the authorization endpoint. The jar holds " +
        b.cookie);
    });

  // THE ASSERTION THE DEFECT WOULD HAVE FAILED. A bare `/authn/login` is a
  // page nobody can be sent to, so the link out of this page must carry a
  // pending id or go somewhere that mints one.
  const signIn = (r.text.match(/<a href="([^"]*)"[^>]*>\s*Sign in\s*<\/a>/) ||
                  [])[1];
  check("the account-ready page offers a way to sign in, and it is NOT a " +
        "bare /authn/login — that endpoint answers 400 to a request naming " +
        "no pending record, so this button used to end the whole flow on an " +
        "error page", function () {
      assert.ok(signIn, "no Sign in link on the account-ready page.");
      assert.ok(!/^\/authn\/login$/.test(signIn),
        "the account-ready page links to a bare " + signIn + ", which " +
        "answers 400: there is no sign-in waiting under that id");
    });

  // AND FOLLOWING IT, because a link that is merely different is not a link
  // that works.
  // FOLLOWED TO THE SCREEN, however many hops that is. It was two before
  // 2026-09-06 and is three now that `/portal` is a relying party — the page
  // goes to `/oauth2/authorize`, which goes to the sign-in screen — and the
  // assertion is about where it LANDS rather than about the shape of the
  // journey, which the flow assertions in `signInAt()` cover. Bounded, so a
  // redirect loop fails here as a loop rather than as a hang.
  r = await b.go("GET", signIn);
  for (let hop = 0; hop < 5 && (r.status === 302 || r.status === 303); hop++) {
    r = await b.go("GET", r.location);
  }
  check("following it reaches a sign-in screen with a pending record behind " +
        "it rather than an error", function () {
      assert.strictEqual(r.status, 200,
        "following " + signIn + " answered " + r.status + " " +
        String(r.text).slice(0, 300));
      assert.ok(/name="authn_id" value="/.test(r.text),
        "the page reached from the account-ready link carries no authn_id, " +
        "so it is not the sign-in screen: " + String(r.text).slice(0, 300));
    });

  const authnId = (r.text.match(/name="authn_id" value="([^"]+)"/) || [])[1];
  r = await b.go("POST", "/authn/login",
                 form({ authn_id: authnId, username: NEWCOMER,
                        password: password, action: "login",
                        csrf_token: csrfOf(r.text) }));
  check("and the credential just set up signs them in", function () {
    assert.ok(r.status === 303 || r.status === 302,
      "the sign-in form answered " + r.status + " " +
      String(r.text).slice(0, 300));
    assert.ok(b.cookie, "signing in established no session cookie.");
  });

  // The rest of the code flow: back to the authorization endpoint, which now
  // has a sign-on session, then to `/portal/callback` with a code, then to the
  // page. Followed rather than asserted hop by hop — `signInAt()` is where the
  // hops themselves are the subject.
  const landed = await follow(b, r);
  check("landing on their OWN account page, which is the only destination an " +
        "activation link can name: it belongs to no application and there is " +
        "no flow in progress to resume", function () {
      assert.strictEqual(landed.status, 200);
      assert.ok(landed.text.indexOf(NEWCOMER) >= 0,
        "the portal page does not name " + NEWCOMER);
    });
  log.debug("Leaving anActivationLinkEndsAtAUsableSignIn().");
  return b;
}

// ---------------------------------------------------------------------------
// 5. NO PAGE THIS SERVICE RENDERS LINKS TO A BARE `/authn/login`.
//
// The section above fixes one page; this is the RULE it is an instance of, and
// it is here because the same mistake was in three files on the day it was
// found — the portal's account-ready page, the federation index and the admin
// console's 401 for a form posted with an expired session. Each was written
// separately, each looked obviously right, and each was a dead end.
//
// It checks the pages a person can actually reach without a session, which is
// where the mistake lives: a page drawn for somebody who is NOT signed in is
// exactly the page that wants to offer a sign-in link.
// ---------------------------------------------------------------------------
async function noPageLinksToABareSignInScreen() {
  log.debug("Entering noPageLinksToABareSignInScreen().");
  log.info("=== no page links to a bare /authn/login ===");
  const b = browser("anonymous");
  const pages = ["/", "/federation", "/logout"];
  for (const path of pages) {
    const r = await b.go("GET", path);
    if (r.status !== 200) {
      // A page that redirects or is not registered in this configuration is not
      // evidence of anything; the ones that DRAW are what this section is
      // about.
      continue;
    }
    check(path + " draws no link to a bare /authn/login", function () {
      assert.ok(!/href="\/authn\/login"/.test(r.text),
        path + " links to a bare /authn/login, which answers 400 to a reader " +
        "who clicks it: there is no sign-in waiting under that id");
    });
  }

  // THE CONSOLE'S 401, which is the one of the three that is not a GET: a form
  // posted after the session expired. Its link has to be an ABSOLUTE URL in the
  // DEFAULT realm as well, which is asserted here rather than assumed because
  // app.js rewrites root-relative hrefs into whatever realm is being read.
  const refused = await b.go("POST", "/admin/tokens",
                             form({ action: "revoke-kind" }));
  if (refused.status === 401) {
    check("the console's refusal for a form posted with an expired session " +
          "offers a REAL way back — an absolute URL that mints a pending " +
          "record, not the screen itself", function () {
        assert.ok(!/href="\/authn\/login"/.test(refused.text),
          "the console's 401 links to a bare /authn/login");
        assert.ok(/<a href="https?:\/\/[^"]+\/admin"/.test(refused.text),
          "the console's 401 carries no absolute link back to the default " +
          "realm's console: " + String(refused.text).slice(0, 400));
      });
  }
  log.debug("Leaving noPageLinksToABareSignInScreen().");
}

// ---------------------------------------------------------------------------
// 6. THE SIGN OUT BUTTON ON EACH SURFACE, AND THE SESSION BEHIND IT
//    (2026-09-06).
//
// `/admin` and `/portal` each draw a Sign out button of their own now, and the
// claim worth asserting is NOT that the surface session ends — a button that
// deleted only its own row would pass every check a person could make on the
// page it lands on. It is that **the SIGN-ON session behind it ends too**.
//
// That is what makes the button work at all. These two surfaces are relying
// parties: a request with no surface session starts an authorization request,
// and if the sign-on session is still live the authorization endpoint answers
// with a code, the callback mints a new surface session, and the person is back
// where they started having pressed Sign out. The defect is invisible on the
// page that says "you are signed out" and shows up on the NEXT CLICK.
//
// So this drives both surfaces, and asserts three things per surface: the
// surface session is gone from the register, the sign-on session is gone from
// it too, and the browser — still holding both cookies — ends at the SIGN-IN
// SCREEN when it asks for the door again rather than back inside it.
// ---------------------------------------------------------------------------
async function theSignOutButtonEndsBothSessions(door, surface, who) {
  log.debug("Entering theSignOutButtonEndsBothSessions().");
  log.info("=== " + who + " presses Sign out on " + door + " ===");
  const b = await signInAt(door, who);
  const surfaceId = sessionIdOf(b);
  const signOnId = signOnIdOf(b);
  assert.ok(surfaceId && signOnId,
    "precondition: signing in at " + door + " should leave the browser " +
    "holding both cookies; it holds " + JSON.stringify(Object.keys(b.jar)));
  assert.ok(await rowFor(surfaceId),
    "precondition: the surface session should be listed");
  assert.ok(await rowFor(signOnId),
    "precondition: the sign-on session should be listed");

  // THE TOKEN IS TAKEN OFF THE PAGE THAT DRAWS THE BUTTON, which is the point
  // of asking for the page first: a token this test computed would prove the
  // handler accepts a token, and what is wanted is that the CONTROL works.
  const page = await b.go("GET", door);
  const shown = new RegExp('<form[^>]+action="[^"]*' + surface +
                           '/signout"[^>]*>([\\s\\S]*?)</form>').exec(
                               page.text);
  check(door + " draws the Sign out form", function () {
    assert.ok(shown,
      door + " should draw a form posting to " + surface + "/signout. What " +
      "it drew begins: " + String(page.text).slice(0, 300));
  });
  const csrf = (shown[1].match(/name="csrf_token" value="([^"]+)"/) ||
                [])[1] || "";
  check("and it carries this session's CSRF token", function () {
    assert.ok(csrf,
      "the sign-out form carries no csrf_token, and the handler requires one " +
      "— so the button as drawn would be refused. The form is: " +
      shown[1].slice(0, 200));
  });

  const refused = await b.go("POST", surface + "/signout", form({}));
  check("a sign-out with no token is REFUSED, which is not a nicety: a " +
        "sign-out fired from another site is the classic harmless CSRF that " +
        "is not", function () {
      assert.strictEqual(refused.status, 403,
        surface + "/signout answered " + refused.status + " to a form with " +
        "no csrf_token");
    });
  assert.ok(await rowFor(surfaceId),
    "and the refused sign-out must have ended nothing");

  const out = await b.go("POST", surface + "/signout",
                         form({ csrf_token: csrf }));
  check("pressing it answers a page saying so rather than a redirect — a 303 " +
        "back to the door would be indistinguishable from the button doing " +
        "nothing until the next click", function () {
      assert.strictEqual(out.status, 200,
        surface + "/signout answered " + out.status);
      assert.ok(/signed out/i.test(out.text),
        "and the page should say so: " + String(out.text).slice(0, 300));
    });

  const surfaceGone = await rowFor(surfaceId);
  const signOnGone = await rowFor(signOnId);
  check("BOTH sessions are gone from GET /admin-api/sessions — the " +
        "surface's own AND the sign-on session it was derived from",
    function () {
      assert.strictEqual(surfaceGone, null,
        "the " + surface + " session " + surfaceId + " is still listed");
      assert.strictEqual(signOnGone, null,
        "THE SIGN-ON SESSION " + signOnId + " SURVIVED THE SIGN-OUT. That is " +
        "the defect this section exists for: the surface session is gone, " +
        "the page says signed out, and the next request runs the " +
        "authorization code flow, meets this session, and comes straight " +
        "back in with nothing typed.");
    });

  // AND THE COOKIES BUY NOTHING. Both are re-presented deliberately — the jar
  // drops what the sign-out cleared, so this is the state a real browser is in.
  const again = await b.go("GET", door);
  check("asking for " + door + " again starts a new authorization request",
    function () {
      assert.ok(again.status === 302 || again.status === 303,
        door + " answered " + again.status + " after the sign-out");
      assert.ok(/\/oauth2\/authorize\?/.test(again.location),
        "it went to " + again.location);
    });
  const authorize = await b.go("GET", again.location);
  check("and that request ends at the SIGN-IN SCREEN, which is the whole " +
        "claim: the authorization endpoint has no session to answer with",
    function () {
      assert.ok(/\/authn\/login\?authn=/.test(authorize.location),
        "the authorization endpoint answered " + authorize.status + " to " +
        authorize.location + " rather than sending the browser to the " +
        "sign-in screen. If that is a callback carrying a code, the sign-on " +
        "session is still live and this surface's Sign out button is signing " +
        "nobody out.");
    });
  log.debug("Leaving theSignOutButtonEndsBothSessions().");
}

// ---------------------------------------------------------------------------
// 7. THE APPLICATIONS PAGE, AND THE FOUR PAGES THE PORTAL BECAME (2026-09-06).
//
// The portal was one page with four cards; it is four pages behind a
// navigation column, and `/portal/applications` is the new one. This section
// is here rather than in the parent project's suite for the ownership reason
// the manifest gives: the tree that adds a control to a hosted surface is the
// tree that should go red when the control loses its meaning.
//
// **THE DECISIVE ASSERTION IS A TRANSITION AND NOT A VALUE.** A page that
// listed every application would pass "the permitted one is listed" perfectly,
// so what is asserted is that granting a role CHANGES the list: an application
// narrowed to a role is absent, the role is granted through /admin-api, and it
// appears. `xacml/CLAUDE.md` records the sixteenth defect being exactly this —
// a guard that was never true, invisible to every assertion about a value.
//
// **AND THE SECOND ONE IS ABOUT WHAT IS *NOT* RECORDED.** Drawing this page
// asks the issuance gate once per application, and none of those is an
// issuance: nothing may reach the audit log as `xacml.issuance.refused` and
// nothing may move `/admin/xacml/monitor`'s counters. That is checked by
// reading both BEFORE and AFTER a page load, because a page that quietly wrote
// a refusal row per application would push real events out of a 5,000-event
// ring and nothing on the page itself would look wrong.
// ---------------------------------------------------------------------------

// The issuance PEP's row on the monitor, which is where a dry run would show
// up if it were being counted.
async function issuanceCounters() {
  log.debug("Entering issuanceCounters().");
  const r = await get("/xacml/monitor");
  assert.ok(r.status === 200 && r.body,
    "GET /admin-api/xacml/monitor answered " + r.status);
  const rows = r.body.enforcement || r.body.points || r.body.rows || [];
  const row = rows.filter(function (one) { return one.id === "issuance"; })[0];
  assert.ok(row, "the monitor has no row for the issuance PEP; it listed " +
    rows.map(function (one) { return one.id; }).join(", "));
  log.debug("Leaving issuanceCounters().");
  return { decisions: row.decisions, allowed: row.allowed,
           refused: row.refused };
}

async function issuanceAuditRows() {
  log.debug("Entering issuanceAuditRows().");
  const r = await get("/audit?per=500");
  assert.ok(r.status === 200 && r.body,
            "GET /admin-api/audit answered " + r.status);
  log.debug("Leaving issuanceAuditRows().");
  return (r.body.events || r.body.audit || []).filter(function (e) {
    return String(e.action || "").indexOf("xacml.issuance") === 0;
  }).length;
}

// Which application names the page is showing, read out of the table's own
// `<strong>` cells rather than by searching the whole document: the prose on
// that page names applications too — "sts-user-portal" appears in the sign-in
// explanation — and a substring match against the whole page would report a
// row that is not there.
// The `<a>` in the middle is why this is an exec loop rather than the
// match-and-strip it was until 2026-09-10: an application whose entry carries
// `appHomePageUrl` has its name drawn as a link to that page, and one that does
// not has it drawn in a `<span class="unlinked">`. A pattern anchored on
// `<td><strong>NAME</strong>` matched neither of those and reported every row
// missing.
function listedApplications(text) {
  log.debug("Entering listedApplications().");
  const names = [];
  const pattern = /<td><strong>(?:<(?:a|span)\b[^>]*>)?([^<]*)/g;
  let found = pattern.exec(String(text));
  while (found) {
    names.push(found[1]);
    found = pattern.exec(String(text));
  }
  log.debug("Leaving listedApplications().");
  return names;
}

// The href a named application's row links to, or "" when its name is drawn
// greyed out instead. Read out of the row rather than off the page, because
// several rows carry links and "this page contains that URL" would pass for a
// link on somebody else's row.
function homePageLinkFor(text, name) {
  log.debug("Entering homePageLinkFor().");
  const rows = String(text).split("<tr>");
  const mine = rows.filter(function (row) {
    return row.indexOf(">" + name + "<") >= 0;
  })[0];
  if (!mine) {
    log.debug("Leaving homePageLinkFor().");
    return null;
  }
  const link =
      mine.match(/<strong><a class="home" rel="noopener" href="([^"]*)"/);
  if (link) {
    log.debug("Leaving homePageLinkFor().");
    return link[1];
  }
  log.debug("Leaving homePageLinkFor().");
  return mine.indexOf('<strong><span class="unlinked"') >= 0 ? "" : null;
}

// How many pages that list runs to, off the pager's own "Page 1 of 3" marker.
// One page draws no pager at all, which is not a missing element: it is the
// page saying there is nothing to page through.
function pageCountOf(text) {
  log.debug("Entering pageCountOf().");
  const m = String(text).match(/<span class="here">Page \d+ of (\d+)<\/span>/);
  log.debug("Leaving pageCountOf().");
  return m ? Number(m[1]) : 1;
}

// EVERY application this person may reach, and not the first twenty of them.
//
// This walked one page until 2026-09-06, and it passed for as long as this
// file was the only thing that had ever created an application. In a whole
// suite run it is not: by the time this section runs, the jobs ahead of it
// have registered more than PER_PAGE entries in the default realm, the list is
// alphabetical, and a probe named "Portal Probe ..." sorts onto page two —
// so the assertion that the open application is listed failed against a page
// that was drawing exactly what it should. What is under test here is the
// ISSUANCE POLICY deciding the list, which is a claim about the whole list;
// asserting it against one page was asserting it about the alphabet.
async function everyListedApplication(b) {
  log.debug("Entering everyListedApplication().");
  const first = await b.go("GET", "/portal/applications");
  assert.strictEqual(first.status, 200,
    "the applications page answered " + first.status + " " +
    String(first.text).slice(0, 200));
  const pages = pageCountOf(first.text);
  let names = listedApplications(first.text);
  let text = first.text;
  for (let at = 2; at <= pages; at += 1) {
    const next = await b.go("GET", "/portal/applications?page=" + at);
    assert.strictEqual(next.status, 200,
      "page " + at + " of the applications list answered " + next.status);
    names = names.concat(listedApplications(next.text));
    text += next.text;
  }
  log.debug("Leaving everyListedApplication().");
  // The two counts at the foot are TOTALS rather than per-page tallies, so
  // page one's are the whole list's; `text` is every page concatenated,
  // because "this name appears nowhere outside the table" is a claim about
  // all of them.
  return { listed: names, text: text, first: first.text, pages: pages };
}

// The two counts at the foot of the page: refused, and not-a-sign-in-door.
function notListedCounts(text) {
  log.debug("Entering notListedCounts().");
  const refused = (String(text)
    .match(/Not permitted to you<\/th><td>(\d+) application/) || [])[1];
  const other = (String(text)
    .match(/Not sign-in destinations<\/th><td>(\d+) entr/) || [])[1];
  log.debug("Leaving notListedCounts().");
  return { refused: refused === undefined ? null : Number(refused),
           notSignIn: other === undefined ? null : Number(other) };
}

async function theApplicationsPageIsDecidedByThePolicy() {
  log.debug("Entering theApplicationsPageIsDecidedByThePolicy().");
  log.info("=== the applications page: what the ISSUANCE POLICY permits ===");
  const who = usernameFor("portal-apps");
  const stamp = runStamp();
  const openName = "Portal Probe Open " + stamp;
  const narrowedName = "Portal Probe Narrowed " + stamp;
  const role = "portal-probe-role-" + stamp;
  // The two halves of the link on this page (2026-09-10): an application that
  // has told this registry where it lives, and one that has not. Both are
  // LISTED — the issuance policy permits them equally — and the difference is
  // whether the name is a way in.
  const openHome = "https://portal-probe-" + stamp + ".example.com/expenses";
  const nowhereName = "Portal Probe Nowhere " + stamp;

  // Three entries: one anybody may reach, one narrowed to a role nobody holds
  // yet, and one that is not a sign-in destination at all.
  let r = await post("/applications/create",
    { identifier: "portal-probe-open-" + stamp, name: openName,
      protocols: ["oauth2", "oidc"],
      fields: { appHomePageUrl: openHome } });
  assert.ok(r.status === 200 && r.body && r.body.ok,
    "creating the open application answered " + r.status + " " +
    String(r.raw).slice(0, 300));
  r = await post("/applications/create",
    { identifier: "portal-probe-narrowed-" + stamp, name: narrowedName,
      protocols: ["saml2"], fields: { appRequiredRole: [role] } });
  assert.ok(r.status === 200 && r.body && r.body.ok,
    "creating the narrowed application answered " + r.status + " " +
    String(r.raw).slice(0, 300));
  r = await post("/applications/create",
    { identifier: "portal-probe-nowhere-" + stamp, name: nowhereName,
      protocols: ["oauth2"] });
  assert.ok(r.status === 200 && r.body && r.body.ok,
    "creating the application with no home page answered " + r.status + " " +
    String(r.raw).slice(0, 300));
  r = await post("/applications/create",
    { identifier: "portal-probe-ssf-" + stamp,
      name: "Portal Probe Receiver " + stamp, protocols: ["ssf"] });
  assert.ok(r.status === 200 && r.body && r.body.ok,
    "creating the Shared Signals receiver answered " + r.status + " " +
    String(r.raw).slice(0, 300));

  const b = await signInAt("/portal", who);

  // ------------------------------------------------------------------
  // THE FOUR PAGES, and the column that joins them.
  // ------------------------------------------------------------------
  const pages = [["/portal", "Overview"],
                 ["/portal/applications", "Applications"],
                 ["/portal/password", "Password"], ["/portal/keys",
                                                    "Security " +
                     "keys"]];
  for (const [path, label] of pages) {
    const page = await b.go("GET", path);
    check(path + " answers 200 for the person signed in", function () {
      assert.strictEqual(page.status, 200,
        path + " answered " + page.status + " " +
        String(page.text).slice(0, 200));
    });
    check("and its navigation marks \"" + label + "\" as the page being " +
          "drawn — the column is one table, so a page missing from it is a " +
          "page with no way in", function () {
        assert.ok(page.text.indexOf('<span class="here" aria-current="page">' +
                                    label + "</span>") >= 0,
          path + " does not mark " + label + " as current. It drew: " +
          (page.text.match(/aria-current="page">[^<]*/g) || []).join(", "));
        assert.ok(/href="\/portal\/applications"/.test(page.text) ||
                  label === "Applications",
          path + " draws no link to the applications page.");
      });
  }

  // ------------------------------------------------------------------
  // WHAT IS LISTED, BEFORE ANYBODY HOLDS THE ROLE.
  // ------------------------------------------------------------------
  let apps = await everyListedApplication(b);
  let listed = apps.listed;
  let counts = notListedCounts(apps.first);
  check("the open application is listed", function () {
    assert.ok(listed.indexOf(openName) >= 0,
      openName + " is not on the page. It listed: " + listed.join(", "));
  });
  check("THE NARROWED ONE IS NOT — the issuance policy refuses it, and this " +
        "page shows what the policy permits rather than what the registry " +
        "holds", function () {
      assert.ok(listed.indexOf(narrowedName) < 0,
        narrowedName + " is on the page and nobody holds " + role + " yet.");
    });
  check("and it is COUNTED rather than named, which is the whole of what " +
        "this page tells somebody about applications they cannot reach",
    function () {
      assert.ok(counts.refused !== null && counts.refused >= 1,
        "the page reports " + counts.refused + " refused applications.");
      assert.ok(apps.text.indexOf(narrowedName) < 0,
        "the page names " + narrowedName + " somewhere outside the table, " +
        "which is the disclosure the count exists to avoid.");
    });
  // ------------------------------------------------------------------
  // THE LINK ON EACH ROW (2026-09-10), and the greyed-out name beside it.
  //
  // This page listed the applications a person may sign in to and gave them no
  // way to reach any of them. The link is the entry's DECLARED
  // `appHomePageUrl` and is never computed from the redirect URIs on the entry
  // — `common/applications.js`'s row for that attribute argues why — so the
  // assertion here is a pair rather than a value: the application that stated a
  // home page links to exactly it, and the one that did not is listed with no
  // link at all rather than with a guess.
  // ------------------------------------------------------------------
  check("the application that declared a home page is LINKED to it, exactly " +
        "as declared", function () {
      const href = homePageLinkFor(apps.text, openName);
      assert.strictEqual(href, openHome,
        openName + " links to " + JSON.stringify(href) + " rather than to " +
        openHome + ". A home page is what the entry says it is; nothing " +
        "derives one.");
    });
  check("AND THE ONE THAT DECLARED NONE IS LISTED WITH NO LINK — greyed out " +
        "rather than pointed at a guessed address, which is the whole reason " +
        "the attribute is declared", function () {
      assert.ok(listed.indexOf(nowhereName) >= 0,
        nowhereName + " is not listed at all. Having no home page must not " +
        "keep an application off this page: it is the ordinary shape of an " +
        "entry a protocol endpoint created. It listed: " + listed.join(", "));
      assert.strictEqual(homePageLinkFor(apps.text, nowhereName), "",
        nowhereName +
        " is drawn with a link and its entry names no home page.");
    });

  // A HOME PAGE BECOMES AN `href` ON THIS PAGE, so the write door refuses a
  // value that is not http or https. The scheme list is an ALLOWLIST rather
  // than a blocklist and `javascript:` is why: this registry accepts an entry
  // from a dynamic client registration, so a scheme of somebody's choosing
  // must not be able to reach an attribute a signed-in person's page renders
  // as a link. Checked at the door AND again when the page reads it — an
  // `ldapmodify` on TCP 389 goes through neither.
  const refused = await post("/applications/set",
    { application: "portal-probe-nowhere-" + stamp,
      attribute: "appHomePageUrl", value: "javascript:alert(1)" });
  check("a home page that is not http or https is REFUSED where it is written",
    function () {
      assert.strictEqual(refused.status, 400,
        "setting a javascript: home page answered " + refused.status +
        " rather than refusing it. " + String(refused.raw).slice(0, 300));
      assert.ok(/http/.test(String(refused.raw)),
        "the refusal does not say what a home page must be: " +
        String(refused.raw).slice(0, 300));
    });

  check("the Shared Signals receiver is on neither list — it is not a " +
        "sign-in destination, and is counted as one of those instead",
    function () {
      assert.ok(listed.indexOf("Portal Probe Receiver " + stamp) < 0,
        "a Shared Signals receiver is listed as somewhere to sign in.");
      assert.ok(counts.notSignIn !== null && counts.notSignIn >= 1,
        "the page reports " + counts.notSignIn + " entries that are not " +
        "sign-in destinations, and one was just created.");
    });

  // ------------------------------------------------------------------
  // THE DRY RUN RECORDS NOTHING. Read on both sides of one page load.
  // ------------------------------------------------------------------
  const countersBefore = await issuanceCounters();
  const auditBefore = await issuanceAuditRows();
  const again = await b.go("GET", "/portal/applications");
  assert.strictEqual(again.status, 200,
    "the applications page answered " + again.status + " on a second load.");
  const countersAfter = await issuanceCounters();
  const auditAfter = await issuanceAuditRows();
  check("DRAWING THE PAGE MOVES NO COUNTER ON /admin/xacml/monitor — it asks " +
        "the gate once per application and every one of those is a dry run, " +
        "not a decision this service acted on", function () {
      assert.deepStrictEqual(countersAfter, countersBefore,
        "the issuance PEP's counters moved from " +
        JSON.stringify(countersBefore) + " to " +
        JSON.stringify(countersAfter) +
        " because somebody opened a page.");
    });
  check("AND WRITES NO xacml.issuance.* ROW TO THE AUDIT LOG — a refusal row " +
        "per refused application per page load would push real events out of " +
        "a 5,000-event ring", function () {
      assert.strictEqual(auditAfter, auditBefore,
        "the audit log gained " + (auditAfter - auditBefore) +
        " xacml.issuance.* row(s) from a page being drawn.");
    });

  // ------------------------------------------------------------------
  // THE TRANSITION. Grant the role and the list changes.
  // ------------------------------------------------------------------
  r = await post("/roles/create-role",
    { role: role, description: "created by sts_portal_sessions.js" });
  assert.ok(r.status === 200 && r.body && r.body.ok,
    "creating the role answered " + r.status + " " +
    String(r.raw).slice(0, 300));
  r = await post("/roles/add-member",
                 { role: role, kind: "user", member: who });
  assert.ok(r.status === 200 && r.body && r.body.ok,
    "granting the role answered " + r.status + " " +
    String(r.raw).slice(0, 300));

  apps = await everyListedApplication(b);
  listed = apps.listed;
  const after = notListedCounts(apps.first);
  check("GRANTING THE ROLE PUTS THE APPLICATION ON THE PAGE. This is the " +
        "assertion that means anything: a page listing everything would have " +
        "passed every check above, and only a CHANGE proves the issuance " +
        "policy is what decides the list", function () {
      assert.ok(listed.indexOf(narrowedName) >= 0,
        narrowedName + " is still missing after " + who + " was given " +
        role + ". The page listed: " + listed.join(", "));
    });
  check("and the refused count came down with it", function () {
    assert.ok(after.refused < counts.refused,
      "the refused count stayed at " + after.refused +
      " while an application moved onto the list.");
  });

  // ------------------------------------------------------------------
  // PAGINATION, AND THE SHAPE OF `page`.
  // ------------------------------------------------------------------
  const clamped = await b.go("GET", "/portal/applications?page=9999");
  check("a page number past the end is CLAMPED to the last real page rather " +
        "than answering an empty table — a bookmark to page 40 of a list " +
        "that has shrunk to three is not an error", function () {
      assert.strictEqual(clamped.status, 200,
        "?page=9999 answered " + clamped.status);
      assert.ok(listedApplications(clamped.text).length > 0,
        "?page=9999 drew an empty table.");
    });
  const badPage = await b.go("GET", "/portal/applications?page=not-a-number");
  check("and a `page` that is not a number is refused as a BAD SHAPE by the " +
        "validator rather than being parsed by the handler", function () {
      assert.strictEqual(badPage.status, 400,
        "?page=not-a-number answered " + badPage.status);
    });

  // ------------------------------------------------------------------
  // A01, ON THE NEW PAGE. Section 3 asserts it on /portal; a page added
  // later is a page the rule has to be checked on again, which is the whole
  // reason that rule is written down.
  // ------------------------------------------------------------------
  const nominated = await b.go("GET", "/portal/applications?user=" + OWNER +
                               "&username=" + OWNER + "&subject=" + OWNER);
  check("naming somebody else in every parameter this page could plausibly " +
        "have read changes nothing: it is drawn for the session's own person",
    function () {
      assert.ok(nominated.status === 200 || nominated.status === 400,
        "it answered " + nominated.status);
      if (nominated.status === 200) {
        assert.ok(nominated.text.indexOf(who) >= 0,
          "the page was not drawn for " + who + ".");
        assert.ok(nominated.text.indexOf(OWNER) < 0,
          "the page names " + OWNER + ", who was named in a parameter.");
      }
    });

  log.debug("Leaving theApplicationsPageIsDecidedByThePolicy().");
  return b;
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving the admin console and the User Portal at " + base);

  const operator = await theConsoleSignInCreatesASession();
  const owner = await thePortalSignInCreatesASession();

  check("both sessions are live at once and are DIFFERENT sessions — one " +
        "store does not mean one session", function () {
      assert.notStrictEqual(sessionIdOf(operator), sessionIdOf(owner));
    });

  const intruder = await oneUserCannotReachAnother(owner);

  const newcomer = await anActivationLinkEndsAtAUsableSignIn();
  await noPageLinksToABareSignInScreen();

  // THE TWO SURFACES' OWN SIGN OUT BUTTONS, each in a browser of its own so
  // that nothing above is signed out from underneath it.
  await theSignOutButtonEndsBothSessions("/portal", "/portal",
                                         usernameFor("portal-signout"));
  await theSignOutButtonEndsBothSessions("/admin", "/admin",
                                         usernameFor("console-signout"));
  await signingOutInvalidatesIt(newcomer, NEWCOMER, "/portal");

  // SECTION 7 RUNS BEFORE THE SIGN-OUTS, in a browser of its own, so that
  // nothing it signs in is signed out from underneath the sections above.
  const appsBrowser = await theApplicationsPageIsDecidedByThePolicy();

  await signingOutInvalidatesIt(intruder, INTRUDER, "/portal");
  await signingOutInvalidatesIt(owner, OWNER, "/portal");
  await signingOutInvalidatesIt(operator, OPERATOR, "/admin/sessions");

  // A FLOOR ON THE COUNT, for sts_admin_console.js's reason: a section that
  // stops being called takes its assertions with it and the run still says
  // "passed", which is the one failure mode a suite cannot report about
  // itself.
  // RAISED FROM 33 TO 50 ON 2026-09-06, when section 6 added eighteen, AND TO
  // 68 the same day when section 7 added eighteen more. A floor
  // that stays where it was as sections are added stops being a floor: it goes
  // on passing with the newest section gone, which is the one it was written to
  // catch.
  assert.ok(checks >= 68,
    "only " + checks + " assertions ran; a section has stopped being called.");
  log.info(checks + " assertion(s).");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
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
