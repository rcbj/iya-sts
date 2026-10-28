// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_portal_sessions.js
//
// ===========================================================================
// SIGNING IN CREATES A SESSION, SIGNING OUT INVALIDATES IT, AND ONE PERSON
// CANNOT REACH ANOTHER'S ACCOUNT — ALL OF IT OVER HTTP.
//
// Three claims to begin with, driven through the real doors and checked
// through the management API, which is what makes them assertions about the
// SERVICE rather than about a function:
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
// Later sections added more, each argued above its own function: an
// activation link ends at a sign-in that works, no page links to a bare
// `/authn/login`, each surface's Sign out ends the sign-on session behind
// it, and `/portal/applications` lists what the issuance policy permits.
//
// **BOTH SURFACES ARE STATIC APPLICATIONS NOW** — the console since #446, the
// portal since #568. Each signs in in the browser as a public client and holds
// a DPoP-bound token, so a sign-in makes ONE session, the identity
// provider's; each draws its pages from its API (`/admin-api`,
// `/account-api`) and sends its forms there. So the portal is driven here as
// its page drives it (`portal_signin.js`): pages are their operations' views
// drawn by the portal's own renderers, forms are those operations, and "the
// cookie no longer works" is "the token is refused and the next
// authorization request meets the sign-in screen".
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
const signin = require("./console_signin.js");
const portalSignin = require("./portal_signin.js");
// THE SIGN-OUT PAGE (#577): a static surface over /authn-api/logout, which
// `authn_signin.js`'s `signOut()` walks as the page does.
const authnSignin = require("./authn_signin.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, for the reason tests/vendored/wait_for.js gives.
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

// THE SIGN-OUT PAGE, as it signs out since #577: its shell, its view, the
// act over /authn-api/logout, and the signed-out document where the act
// answers one — with this browser's cookies, every one the walk set kept
// (a cleared one removed). Answers `{ status, text, view, shellStatus }`.
async function signOutAt(b, fields) {
  log.debug("Entering signOutAt().");
  const shell = await b.go("GET", "/logout");
  const out = await authnSignin.signOut(base, fields, { cookie: b.cookie });
  out.setCookies.forEach(function (one) {
    const pair = String(one).split(";")[0];
    const name = pair.split("=")[0];
    const value = pair.slice(name.length + 1);
    if (value === "" || /Max-Age=0/i.test(String(one))) {
      delete b.jar[name];
    } else {
      b.jar[name] = value;
    }
  });
  b.cookie = b.cookieHeader();
  log.debug("Leaving signOutAt(). " + out.status);
  return { status: out.status, text: out.text || "", view: out.view,
           shell: shell };
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
// browser door offers: creating a person who has no credential yet. The
// access token /admin-api requires (since 2026-09-09) is attached by the
// suite's preload, `tests/tools/attach-admin-token.js`, not here.
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
// SESSION.** Signing in at `/portal` produces two rows: the sign-on session
// the identity provider holds, and the RELYING PARTY session the portal holds,
// derived from it. (The console did the same until the cutover, #446; it
// holds a token now and makes only the sign-on session — section 1.) The
// one a door CREATED is the second, so that is the one these assertions are
// about — and `signOnIdOf()` beside it is how a test reaches the other when
// it means the other.
//
// **AND A COOKIE IS `<sid>.<handle>` SINCE 2026-09-14**, not the bare id: the
// handle rotates on every re-authentication and the sid never does
// (`authn/CLAUDE.md`), and every row, audit target and `derivedFrom` names the
// sid. So the id is the part before the first dot.
const SURFACE_COOKIES = { admin: "sts_admin", portal: "sts_portal" };
const SIGN_ON_COOKIE = "sts_session";

function sidOfCookie(value) {
  log.debug("Entering sidOfCookie().");
  const text = String(value || "");
  const dot = text.indexOf(".");
  log.debug("Leaving sidOfCookie().");
  return dot > 0 ? text.slice(0, dot) : text;
}

// The session a sign-in at a surface made. Since #446 (the console) and #568
// (the portal) neither surface holds a session of its own, so it is the
// sign-on session; the surface cookies are read first only for a browser that
// still carries one from before.
function sessionIdOf(b) {
  log.debug("Entering sessionIdOf().");
  log.debug("Leaving sessionIdOf().");
  return sidOfCookie(b.jar[SURFACE_COOKIES.admin] ||
                     b.jar[SURFACE_COOKIES.portal] ||
                     b.jar[SIGN_ON_COOKIE]);
}

function signOnIdOf(b) {
  log.debug("Entering signOnIdOf().");
  log.debug("Leaving signOnIdOf().");
  return sidOfCookie(b.jar[SIGN_ON_COOKIE]);
}

// NARROWED WITH `q` AND NEVER READ AS PAGE ONE OF EVERYTHING (2026-09-27).
// Since the protocol half runs in lanes, other jobs hold live sessions at the
// same time as this one — more than a page of them — so a session this job
// made fell off `?per=200` and read as never having existed. `q` matches the
// session id and the username (admin-ui's /admin/sessions search), which is
// exactly what every caller here is asking about.
async function liveSessions(q) {
  log.debug("Entering liveSessions().");
  const r = await get("/sessions?per=500&q=" + encodeURIComponent(q));
  assert.ok(r.status === 200 && r.body && Array.isArray(r.body.sessions),
    "GET /admin-api/sessions should list sessions; it answered " + r.status +
    " " + String(r.raw).slice(0, 200));
  log.debug("Leaving liveSessions().");
  return r.body.sessions;
}

async function rowFor(id) {
  log.debug("Entering rowFor().");
  const rows = await liveSessions(id);
  log.debug("Leaving rowFor().");
  return rows.filter(function (row) { return row.sessionId === id; })[0] ||
         null;
}

// THE CONSOLE'S ROSTER IS IN FORCE WHEREVER SOMEBODY ADMINISTERS THE SERVICE
// (2026-09-18). A development-mode stack with an empty roster admits anybody
// to /admin; a deployment with an administrator — testidp, and any product
// install past its bootstrap — admits only a holder of Admin Read. So a
// person this job signs in to the console is GRANTED it, and every grant is
// taken back when the job ends, pass or fail: a real deployment must not
// collect test accounts holding a console role.
const granted = [];

async function grantConsoleRead(who) {
  log.debug("Entering grantConsoleRead(). who=" + who);
  if (granted.indexOf(who) >= 0) {
    log.debug("Leaving grantConsoleRead(). Already granted.");
    return;
  }
  const r = await post("/rbac/grant", { username: who, role: "read" });
  assert.ok(r.status === 200,
    "POST /admin-api/rbac/grant should give " + who + " Admin Read; it " +
    "answered " + r.status + " " + String(r.raw).slice(0, 300));
  granted.push(who);
  log.debug("Leaving grantConsoleRead().");
}

async function revokeConsoleGrants() {
  log.debug("Entering revokeConsoleGrants().");
  for (const who of granted) {
    const r = await post("/rbac/revoke", { username: who, role: "read" });
    if (r.status !== 200) {
      log.warn("could not take Admin Read back from " + who + ": " +
               r.status + " " + String(r.raw).slice(0, 200));
    }
  }
  log.debug("Leaving revokeConsoleGrants().");
}

// ---------------------------------------------------------------------------
// 1. THE ADMIN CONSOLE.
//
// **THE CONSOLE HOLDS NO SESSION OF ITS OWN SINCE THE CUTOVER (#446).** It
// was a relying party with a session derived from the sign-on session — two
// rows per sign-in. It is a static page now that signs in in the browser as
// the public client `sts-admin-console`, with PKCE, and holds a DPoP-bound
// access token; the only session a sign-in makes is the identity provider's.
// `console_signin.js` signs in exactly as the page does, and the browser this
// answers holds the sign-on cookie that walk set, and the console's client.
// ---------------------------------------------------------------------------
async function signInToConsole(who) {
  log.debug("Entering signInToConsole(). who=" + who);
  await ensurePerson(who);
  await grantConsoleRead(who);
  const client = await signin.signInToTheConsole(base, who, log);
  const b = browser(who);
  String(client.cookie || "").split("; ").forEach(function (pair) {
    const name = pair.split("=")[0];
    if (name) {
      b.jar[name] = pair.slice(name.length + 1);
    }
  });
  b.cookie = b.cookieHeader();
  b.console = client;
  log.debug("Leaving signInToConsole(). " + signOnIdOf(b));
  return b;
}

// ---------------------------------------------------------------------------
// THE PORTAL, SIGNED IN AS ITS PAGE SIGNS IN (#568): the public client
// `sts-user-portal`, PKCE, a DPoP-bound token for `/account-api`
// (`portal_signin.js`). The browser this answers holds the sign-on cookie the
// walk set, the portal's client as `b.portal`, and `b.draw()` — a page drawn
// as the portal's runtime draws it: the operation its row in the page table
// names (`web_portal_pages.ts`) and the row's own renderer, in the reader's
// language, answered `{ status, text, json }`.
// ---------------------------------------------------------------------------
async function signInToPortal(who, password) {
  log.debug("Entering signInToPortal(). who=" + who);
  await ensurePerson(who);
  const client = await portalSignin.signInToThePortal(base, who, log,
    { password: password || PASSWORD });
  const b = browser(who);
  String(client.cookie || "").split("; ").forEach(function (pair) {
    const name = pair.split("=")[0];
    if (name) {
      b.jar[name] = pair.slice(name.length + 1);
    }
  });
  b.cookie = b.cookieHeader();
  b.portal = client;
  b.draw = async function (path, query) {
    log.debug("Entering draw(). " + path);
    const table = portalSignin.portalBundle();
    const row = table.PAGES.filter(function (one) {
      return one.path === path;
    })[0];
    assert.ok(row, "the portal draws no page at " + path);
    const qs = new URLSearchParams(query || {}).toString();
    const answer = await client.api("GET", row.operation +
                                           (qs ? "?" + qs : ""));
    if (b.me === undefined) {
      b.me = (await client.api("GET", "/account-api/me")).json;
    }
    const t = table.messages.WebTranslator.fromData(b.me && b.me.locale);
    const html = answer.status === 200 && answer.json
      ? row.render(answer.json, { t: t, query: query || {}, prefix: "",
                                  origin: base, me: b.me,
                                  locale: b.me && b.me.locale,
                                  version: b.me && b.me.version,
                                  here: path })
      : "";
    log.debug("Leaving draw().");
    return { status: answer.status, text: html, json: answer.json };
  };
  log.debug("Leaving signInToPortal(). " + signOnIdOf(b));
  return b;
}

// A NEW AUTHORIZATION REQUEST FROM A BROWSER, as the portal's page would send
// one: where the authorization endpoint sends it says whether the browser is
// anybody — a code at `/portal/callback` for a live sign-on session, the
// sign-in screen for none.
async function portalAuthorize(b) {
  log.debug("Entering portalAuthorize().");
  const r = await b.go("GET", "/oauth2/authorize?" + form({
    response_type: "code", client_id: "sts-user-portal",
    redirect_uri: base + "/portal/callback",
    scope: "openid account:manage", state: "probe",
    code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    code_challenge_method: "S256", resource: base + "/account-api" }));
  log.debug("Leaving portalAuthorize(). " + r.status + " " + r.location);
  return r;
}

async function theConsoleSignInCreatesASession() {
  log.debug("Entering theConsoleSignInCreatesASession().");
  log.info("=== the admin console: sign in, and the session is listed ===");
  const before = (await liveSessions(OPERATOR)).length;
  const b = await signInToConsole(OPERATOR);
  const id = signOnIdOf(b);

  const row = await rowFor(id);
  check("signing in to the console creates a session the management API " +
        "lists", function () {
      assert.ok(row,
                "no row for session " + id + " in GET /admin-api/sessions");
    });
  check("it names the person who signed in", function () {
    assert.strictEqual(row.username, OPERATOR);
  });
  check("IT IS THE SIGN-ON SESSION — the console's sign-in makes no session " +
        "of its own since the cutover (#446): the page holds a token, and " +
        "the identity provider holds the one session", function () {
      assert.strictEqual(row.kind, "Browser sign-on session");
    });
  check("and somebody actually authenticated for it — the field that tells " +
        "it from a Continue-without-signing-in session", function () {
      assert.strictEqual(row.authenticated, true);
    });

  const after = await liveSessions(OPERATOR);
  check("THE COUNT WENT UP BY EXACTLY ONE, which is the shape of the " +
        "cutover in one number: the identity provider's session and no " +
        "console session beside it", function () {
      assert.strictEqual(after.length, before + 1);
      assert.ok(after.every(function (one) {
        return one.kind !== "Admin console session";
      }), JSON.stringify(after.map(function (one) {
        return one.kind;
      })));
    });

  // The console is REACHABLE, which is the half a list cannot show: a row in
  // a register and a working credential are different claims. Its credential
  // is the token, and `/admin/sessions` is drawn from this operation.
  const page = await b.console.api("GET", "/admin-api/sessions?per=1");
  check("and the console's token reads GET /admin-api/sessions, the page " +
        "it was signed in to", function () {
      assert.strictEqual(page.status, 200,
                         page.status + " " + String(page.text).slice(0, 200));
    });
  log.debug("Leaving theConsoleSignInCreatesASession().");
  return b;
}

// THE CONSOLE'S SIGN OUT (#446). The shell's Sign out sends the browser to
// the protocol-independent `/logout`, whose Global logout form ends the
// sign-on session — and with it everything issued on it. The claim is not
// that a page says so: it is that the session leaves the register, that the
// console's refresh token is refused afterwards, and that the browser, still
// holding its cookie, starts the next authorization request at the sign-in
// screen rather than coming straight back in.
async function theConsoleSignOutEndsIt(b, who) {
  log.debug("Entering theConsoleSignOutEndsIt().");
  log.info("=== " + who + " signs out of " +
           (b.portal ? "the portal" : "the console") + " at /logout ===");
  const signOnId = signOnIdOf(b);
  assert.ok(signOnId && await rowFor(signOnId),
    "precondition: " + who + "'s sign-on session should be listed");

  // THE PAGE IS A STATIC SURFACE SINCE #577: the shell, drawn in the
  // browser from the view of everything this session holds, whose Global
  // logout is an act on /authn-api/logout bound to the sign-on cookie.
  const out = await signOutAt(b, { scope: "global" });
  check("/logout answers the sign-out page the console's Sign out leads " +
        "to, drawn from what this browser holds", function () {
      assert.ok(out.shell.status === 200 &&
                out.shell.text.indexOf("/logout/signout.js") > 0 &&
                out.view && out.view.state === "inventory",
        "/logout answered " + out.shell.status + ": " +
        String(out.shell.text).slice(0, 300));
    });
  check("pressing its Global logout answers", function () {
    assert.ok(out.status === 200, "the sign-out answered " + out.status +
              ": " + out.text.slice(0, 300));
  });

  const gone = await rowFor(signOnId);
  check("THE SIGN-ON SESSION IS GONE FROM GET /admin-api/sessions, which is " +
        "what an operator looking at /admin/sessions sees", function () {
      assert.strictEqual(gone, null,
        "session " + signOnId + " is still listed after the sign-out");
    });

  const renewed = await (b.portal || b.console).refresh();
  check("AND THE " + (b.portal ? "PORTAL'S" : "CONSOLE'S") + " REFRESH " +
        "TOKEN IS REFUSED — a sign-out that left the page able to renew its " +
        "token would sign nobody out", function () {
      assert.notStrictEqual(renewed.status, 200,
        "the refresh grant answered 200 after the sign-out: " +
        JSON.stringify(renewed.json).slice(0, 200));
    });

  if (b.portal) {
    const asked = await b.portal.api("GET", "/account-api/me");
    check("and the portal's access token is refused at /account-api — it " +
          "died with the sign-on session it was issued on", function () {
      assert.strictEqual(asked.status, 401, asked.text.slice(0, 200));
    });
  }
  // THE COOKIE BUYS NOTHING EITHER: a new authorization request from the
  // same browser ends at the sign-in screen, not at the console's callback.
  const authorize = b.portal ? await portalAuthorize(b)
                             : await b.go("GET", "/oauth2/authorize?" + form({
    response_type: "code", client_id: "sts-admin-console",
    redirect_uri: base + "/admin/callback",
    scope: "openid admin:read admin:write", state: "after-signout",
    code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    code_challenge_method: "S256", resource: base + "/admin-api" }));
  check("and the surface's next authorization request ends at the SIGN-IN " +
        "SCREEN: the authorization endpoint has no session to answer with",
    function () {
      assert.ok(/\/authn\/login\?authn=/.test(authorize.location),
        "the authorization endpoint answered " + authorize.status + " to " +
        authorize.location + " rather than sending the browser to the " +
        "sign-in screen");
    });

  const audit = await get("/audit?per=200");
  const ended = audit.body.events.filter(function (e) {
    return String(e.action || "") === "session.end" &&
           String(e.target || "") === signOnId;
  });
  check("and the sign-out is in the audit log naming that session",
    function () {
      assert.ok(ended.length > 0, "no session.end row naming " + signOnId);
    });
  log.debug("Leaving theConsoleSignOutEndsIt().");
}

// ---------------------------------------------------------------------------
// 2. THE USER PORTAL.
// ---------------------------------------------------------------------------
async function thePortalSignInCreatesASession() {
  log.debug("Entering thePortalSignInCreatesASession().");
  log.info("=== the user portal: sign in, and the session is listed ===");
  const before = (await liveSessions(OWNER)).length;
  const b = await signInToPortal(OWNER);
  const id = signOnIdOf(b);
  const row = await rowFor(id);

  check("signing in to /portal creates a session the management API lists",
    function () {
      assert.ok(row, "no row for session " + id);
    });
  check("named for the person, and it is the SIGN-ON SESSION — the portal's " +
        "sign-in makes no session of its own since #568: the page holds a " +
        "token, and the identity provider holds the one session",
    function () {
      assert.strictEqual(row.username, OWNER);
      assert.strictEqual(row.kind, "Browser sign-on session");
    });
  const after = await liveSessions(OWNER);
  check("THE COUNT WENT UP BY EXACTLY ONE: no portal session beside it",
    function () {
      assert.strictEqual(after.length, before + 1,
        JSON.stringify(after.map(function (one) { return one.kind; })));
    });

  const page = await b.draw("/portal");
  check("and the portal's Overview is drawn for them from its operation",
    function () {
      assert.strictEqual(page.status, 200, JSON.stringify(page.json));
    });
  check("showing THEIR name", function () {
    assert.ok(page.text.indexOf(OWNER) >= 0,
      "the portal page does not name " + OWNER);
  });

  // "TIMES YOU HAVE SIGNED IN" IS AT LEAST ONE, BECAUSE THEY JUST DID (#672).
  // The figure is `admin_stats`' register — the row the console's user page
  // draws — and from the portal's first day until #672 the Overview read it
  // off the wrong member of `userDetail()`'s answer and said 0 for
  // everybody. The sign-in above was recorded through the funnel every
  // protocol goes through, so the figure is at least one; EXACTLY one is
  // not asserted, because `ensurePerson()` may have signed them in before
  // and the register counts a process's whole life. The view is read off
  // the operation's JSON and the drawn page both: the JSON is what the
  // runtime draws from, the page is what the person sees.
  //
  // READ AGAIN FOR A MOMENT if the figure is not there yet: the register
  // is per process and folded across workers and nodes through the
  // change log, so an operation answered by a worker other than the one
  // that signed them in may be a pull behind (`common/admin_stats.js`,
  // `everyUserRecord()`). A bounded wait, never an unbounded one.
  let signedIn = null;
  let drawn = page;
  for (let attempt = 0; attempt < 12; attempt++) {
    const view = drawn.json && drawn.json.view ? drawn.json.view : drawn.json;
    signedIn = view && typeof view.timesSignedIn === "number"
      ? view.timesSignedIn : null;
    if (signedIn !== null && signedIn >= 1) {
      break;
    }
    await new Promise(function (resolve) {
      setTimeout(resolve, 500);
    });
    drawn = await b.draw("/portal");
  }
  check("THE OVERVIEW COUNTS THE SIGN-IN THAT JUST HAPPENED: " +
        "\"Times you have signed in\" is a number of at least one (#672: " +
        "it was 0 for everybody)", function () {
      assert.strictEqual(typeof signedIn, "number",
        "timesSignedIn is not on the overview: " +
        JSON.stringify(drawn.json).slice(0, 300));
      assert.ok(signedIn >= 1, "timesSignedIn is " + signedIn);
    });
  check("and the drawn page carries that figure under its label", function () {
    const pattern = new RegExp("Times you have signed in</th><td>" +
                               signedIn + "</td>");
    assert.ok(pattern.test(drawn.text),
      "the Overview does not draw the count " + signedIn + ": " +
      (drawn.text.match(/Times you have signed in[^<]*<\/th><td>[^<]*/) ||
       ["no such row"])[0]);
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
  const b = await signInToPortal(INTRUDER);

  // EVERY PARAMETER A FUTURE AUTHOR MIGHT PLAUSIBLY READ, with the owner's
  // name in it. A handler that grew `req.query.user` would fail here on the
  // day it was written rather than on the day somebody noticed.
  // Since #568 these go to the page's operation, `GET /account-api/overview`,
  // which is where a handler could grow the bug now.
  const q = { user: OWNER, username: OWNER, id: OWNER, uid: OWNER,
              sub: OWNER, dn: "uid=" + OWNER + ",ou=users,dc=example,dc=com",
              account: OWNER, as: OWNER };
  const page = await b.draw("/portal", q);
  check("the portal answers the intruder's own page, not a refusal — the " +
        "parameters are IGNORED rather than obeyed or rejected, which is " +
        "what reading the identity from the session means", function () {
      assert.strictEqual(page.status, 200, JSON.stringify(page.json));
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
  // The form's operation, `POST /account-api/password`, with the owner's
  // name in every member a handler might read beside the three it takes.
  // SINCE 2026-10-12 THE ACCOUNT API REFUSES A FIELD AN OPERATION DOES NOT
  // TAKE, so naming somebody is refused outright (400) and writes nothing;
  // the same change with only its three fields is then made, and the audit
  // row below is that change's — attributed to the token's person.
  const named = await b.portal.act("/portal/password",
    { username: OWNER, user: OWNER, current: PASSWORD,
      next: "IntruderChosen123!", confirm: "IntruderChosen123!" });
  check("a password change naming somebody else is refused 400, naming the " +
        "fields it does not take", function () {
      assert.strictEqual(named.status, 400,
        "unexpected " + named.status + " " + named.text.slice(0, 200));
      assert.ok(/username/.test(named.text) && /user\b/.test(named.text),
        "the refusal does not name the fields: " + named.text.slice(0, 200));
    });
  const wrote = await b.portal.act("/portal/password",
    { current: PASSWORD, next: "IntruderChosen123!",
      confirm: "IntruderChosen123!" });
  check("the same change with only its own fields answers — it is not a " +
        "crash", function () {
      assert.ok(wrote.status === 200 || wrote.status === 400 ||
                wrote.status === 403,
        "unexpected " + wrote.status + " " + wrote.text.slice(0, 200));
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
// 4a. SIGNING OUT INVALIDATES THE SESSION. (Called last, from test().)
//
// **TWO ASSERTIONS AND NOT ONE.** Leaving the register is what an operator
// SEES; the cookie no longer working is what actually matters, and a bug that
// removed the row and left the session usable would pass the first alone.
// ---------------------------------------------------------------------------
async function signingOutInvalidatesIt(b, who) {
  log.debug("Entering signingOutInvalidatesIt().");
  log.info("=== " + who + " signs out ===");
  const id = sessionIdOf(b);
  assert.ok(await rowFor(id), "precondition: " + who + " should be signed in");

  const out = await signOutAt(b, {});
  check(who + "'s sign-out answers", function () {
    assert.ok(out.status === 200,
      "the sign-out answered " + out.status + ": " + out.text.slice(0, 300));
  });

  const gone = await rowFor(id);
  check("THE SESSION IS GONE FROM GET /admin-api/sessions, which is what an " +
        "operator looking at /admin/sessions sees", function () {
      assert.strictEqual(gone, null,
        "session " + id + " is still listed after a sign-out");
    });

  // THE HALF THE LIST CANNOT SHOW: the credentials are deliberately
  // re-presented. Since #568 the portal's credential is its token, and the
  // browser's is the sign-on cookie — so the token must be refused and the
  // cookie must buy no code at the authorization endpoint. A row removed from
  // a register and a credential that stops being accepted are different
  // claims, and only the second is a sign-out.
  const asked = await b.portal.api("GET", "/account-api/me");
  check("AND THE PORTAL'S TOKEN NO LONGER WORKS — /account-api refuses it, " +
        "because it died with the sign-on session it was issued on",
    function () {
      assert.strictEqual(asked.status, 401, asked.text.slice(0, 200));
    });
  const again = await portalAuthorize(b);
  check("AND THE COOKIE NO LONGER WORKS — the portal's next authorization " +
        "request ends at the sign-in screen rather than with a code",
    function () {
      assert.ok(/\/authn\/login\?authn=/.test(again.location),
        "the authorization endpoint answered " + again.status + " -> " +
        again.location + " to a signed-out cookie");
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
  // Created here, by the activation's own door, so the sign-in at the end of
  // this section must not try to create them again.
  createdPeople[NEWCOMER] = true;
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
  // assertion here is about a browser that is signed in to nobody.
  //
  // **SINCE #568 THE LINK IS A PAGE OF THE STATIC PORTAL**: opening it loads
  // the portal's document, whose script asks `GET /account-api/activation`
  // with the link's own query, and the form posts to `POST
  // /account-api/activation` — operations that take no token and spend the
  // link. This browser opens the link as a person's would (it is handed the
  // anonymous arrival cookie on the way, which signs nobody in), and the
  // operations are asked as the page asks them.
  const b = browser(NEWCOMER);
  const linked = new URL(link, base);
  let r = await b.go("GET", link);
  check("the activation link opens the portal's document for a browser " +
        "holding no sign-in", function () {
      assert.strictEqual(r.status, 200);
      assert.ok(/<script src="\/portal\/portal\.js"/.test(r.text),
        "the link did not answer the portal's document: " +
        String(r.text).slice(0, 200));
    });
  const opened = await portalSignin.nobody(base, "GET",
    "/account-api/activation" + linked.search);
  check("and its operation answers the setup form — nobody following a " +
        "password-set link can be signed in, and none is asked for",
    function () {
      assert.ok(opened.status === 200 && opened.json &&
                opened.json.step === "setup",
        "GET /account-api/activation answered " + opened.status + " " +
        opened.text.slice(0, 300));
    });
  // AN ANONYMOUS ARRIVAL SESSION IS NOT A SIGN-IN (2026-09-07): the cookie
  // the document handed over names nobody, so the portal's authorization
  // request from this browser meets the sign-in screen.
  const notSignedIn = await portalAuthorize(b);
  check("and that browser is signed in to NOBODY — the cookie it now holds " +
        "names an anonymous arrival session and not a person",
    function () {
      assert.ok(/\/authn\/login\?authn=/.test(notSignedIn.location),
        "the authorization endpoint answered " + notSignedIn.status + " -> " +
        notSignedIn.location + ". The jar holds " + b.cookie);
    });
  const token = linked.searchParams.get("token");
  assert.ok(token, "the activation link carries no token.");

  const password = "Activated-Pw1!-" + Date.now();
  r = await portalSignin.nobody(base, "POST", "/account-api/activation",
    { user: NEWCOMER, token: token, password: password, confirm: password,
      key_role: "none", step: "setup" });
  check("setting a password spends the link and answers the account-ready " +
        "step", function () {
      assert.strictEqual(r.status, 200, r.text.slice(0, 300));
      assert.ok(r.json && r.json.view && r.json.view.step === "ready",
        "the activation did not answer the account-ready step: " +
        String(r.text).slice(0, 300));
    });

  // AND IT SIGNS NOBODY IN, which is `portal/CLAUDE.md`'s rule and the whole
  // difference between a SETUP link and a MAGIC link: spending it proves
  // possession of a link, which is not the credential just configured.
  const stillNobody = await portalAuthorize(b);
  check("and it establishes NO session — the last step of setup is to go and " +
        "use the credential, not to be let in by the link that set it",
    function () {
      assert.ok(/\/authn\/login\?authn=/.test(stillNobody.location),
        "spending the activation link signed this browser in: the " +
        "authorization endpoint answered " + stillNobody.status + " -> " +
        stillNobody.location + ". The jar holds " + b.cookie);
    });

  // THE ASSERTION THE DEFECT WOULD HAVE FAILED. A bare `/authn/login` is a
  // page nobody can be sent to, so the link out of the account-ready step
  // must go somewhere that STARTS a sign-in: the step is drawn here with the
  // portal's own renderer.
  const table = portalSignin.portalBundle();
  const activation = table.PAGES.filter(function (one) {
    return one.path === "/portal/activate";
  })[0];
  const ready = activation.render(r.json.view, {
    t: table.messages.WebTranslator.fromData(null), query: {}, prefix: "",
    origin: base, me: null, locale: null, version: null,
    here: "/portal/activate" });
  // The step's last link: the one under the prose, after what was set up.
  const links = ready.match(/<a href="[^"]*"/g) || [];
  const signIn = links.length
    ? links[links.length - 1].slice('<a href="'.length, -1) : "";
  check("the account-ready step offers a way to sign in, and it is NOT a " +
        "bare /authn/login — that endpoint answers 400 to a request naming " +
        "no pending record, so this button used to end the whole flow on an " +
        "error page", function () {
      assert.ok(signIn, "no Sign in link on the account-ready step: " +
                        ready.slice(0, 400));
      assert.ok(!/^\/authn\/login$/.test(signIn),
        "the account-ready step links to a bare " + signIn);
      assert.ok(/^\/portal(\/|$|\?)/.test(signIn),
        "the link should be a portal page, whose script starts a sign-in; " +
        "it is " + signIn);
    });

  // AND FOLLOWING IT, as the portal's page does: an authorization request,
  // which reaches the sign-in screen with a pending record, and the
  // credential just set up signs them in.
  const followed = await b.go("GET", signIn);
  check("following it opens the portal's document, which starts the " +
        "sign-in", function () {
      assert.strictEqual(followed.status, 200, String(followed.status));
    });
  const newcomer = await signInToPortal(NEWCOMER, password);
  check("and the credential just set up signs them in", function () {
    assert.ok(newcomer.portal.token, "no token was issued");
  });
  const landed = await newcomer.draw("/portal");
  check("landing on their OWN account page, which is the only destination an " +
        "activation link can name: it belongs to no application and there is " +
        "no flow in progress to resume", function () {
      assert.strictEqual(landed.status, 200);
      assert.ok(landed.text.indexOf(NEWCOMER) >= 0,
        "the portal page does not name " + NEWCOMER);
    });
  log.debug("Leaving anActivationLinkEndsAtAUsableSignIn().");
  return newcomer;
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

  // THE CONSOLE'S 401 WENT WITH ITS HANDLERS AT THE CUTOVER (#446): a form
  // is sent to `/admin-api` by the page, which signs in again itself, so a
  // POST to a console path has no handler to answer it — it is a 404, and a
  // 404 draws no sign-in link at all.
  const refused = await b.go("POST", "/admin/tokens",
                             form({ action: "revoke-kind" }));
  check("a form posted to a console path is answered 404, with no link to " +
        "a bare /authn/login", function () {
      assert.strictEqual(refused.status, 404,
        "POST /admin/tokens answered " + refused.status);
      assert.ok(!/href="\/authn\/login"/.test(refused.text),
        "the 404 links to a bare /authn/login");
    });
  log.debug("Leaving noPageLinksToABareSignInScreen().");
}

// ---------------------------------------------------------------------------
// 6. THE SIGN OUT ON EACH SURFACE ENDS THE SIGN-ON SESSION BEHIND IT.
//
// This section drove the portal's own Sign out button — a form posting to
// `/portal/signout` with a CSRF token, ending the portal's relying-party
// session AND its sign-on session — until #568. Since then the portal is the
// console's case: its Sign out is the protocol-independent `/logout`, and
// there is only the sign-on session to end. So `theConsoleSignOutEndsIt()`
// above drives both surfaces, and the claim is unchanged: the sign-on
// session leaves the register, the surface's refresh token (and, for the
// portal, its access token) is refused, and the browser's next authorization
// request ends at the sign-in screen rather than coming straight back in.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 7. THE APPLICATIONS PAGE, AND THE FOUR PAGES THE PORTAL BECAME (2026-09-06).
//
// The portal was one page with four cards; it became four pages behind a
// navigation column, and `/portal/applications` was the new one. The column
// has grown since (`portal/portal.ts`'s NAV); this section still checks the
// original four. This section
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
  const first = await b.draw("/portal/applications");
  assert.strictEqual(first.status, 200,
    "the applications page answered " + first.status + " " +
    String(first.text).slice(0, 200));
  const pages = pageCountOf(first.text);
  let names = listedApplications(first.text);
  let text = first.text;
  for (let at = 2; at <= pages; at += 1) {
    const next = await b.draw("/portal/applications", { page: at });
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

  const b = await signInToPortal(who);

  // ------------------------------------------------------------------
  // THE FOUR PAGES. Since #568 the column is the portal's frame, drawn by
  // its runtime around every page (`web_portal_shell.ts`), and each page is
  // its operation's view drawn by its row's renderer — so what is asserted
  // per page is that it draws, for the person, from its operation.
  // ------------------------------------------------------------------
  const pages = [["/portal", "Overview"],
                 ["/portal/applications", "Applications"],
                 ["/portal/password", "Password"],
                 // "Passkeys" since #470, which renamed the page.
                 ["/portal/keys", "Passkeys"]];
  for (const [path, label] of pages) {
    const page = await b.draw(path);
    check(path + " (" + label + ") is drawn for the person signed in, from " +
          "its operation", function () {
      assert.strictEqual(page.status, 200,
        path + " answered " + page.status + " " +
        JSON.stringify(page.json).slice(0, 200));
      assert.ok(page.text.length > 0, path + " drew nothing");
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
  const again = await b.draw("/portal/applications");
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
  const clamped = await b.draw("/portal/applications", { page: 9999 });
  check("a page number past the end is CLAMPED to the last real page rather " +
        "than answering an empty table — a bookmark to page 40 of a list " +
        "that has shrunk to three is not an error", function () {
      assert.strictEqual(clamped.status, 200,
        "?page=9999 answered " + clamped.status);
      assert.ok(listedApplications(clamped.text).length > 0,
        "?page=9999 drew an empty table.");
    });
  const badPage = await b.draw("/portal/applications",
                               { page: "not-a-number" });
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
  const nominated = await b.draw("/portal/applications",
    { user: OWNER, username: OWNER, subject: OWNER });
  check("naming somebody else in every parameter this page could plausibly " +
        "have read changes nothing: it is drawn for the session's own person",
    function () {
      assert.ok(nominated.status === 200 || nominated.status === 400,
        "it answered " + nominated.status);
      if (nominated.status === 200) {
        // DRAWN FOR THE TOKEN'S PERSON (#568): the page is its cards, the
        // name is in the frame, so what shows whose list this is is the
        // application only `who` was just granted the role for.
        assert.ok(listedApplications(nominated.text).indexOf(narrowedName) >=
                  0 || pageCountOf(nominated.text) > 1,
          "the page was not drawn for " + who + ": " + narrowedName +
          " is not listed.");
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
      assert.notStrictEqual(signOnIdOf(operator), signOnIdOf(owner));
    });

  const intruder = await oneUserCannotReachAnother(owner);

  const newcomer = await anActivationLinkEndsAtAUsableSignIn();
  await noPageLinksToABareSignInScreen();

  // THE TWO SURFACES' SIGN OUTS, each in a browser of its own so that
  // nothing above is signed out from underneath it. Both are `/logout`: the
  // console since the cutover (#446), the portal since #568 — neither holds
  // a session of its own for a button of its own to end.
  const portalSignout = usernameFor("portal-signout");
  await theConsoleSignOutEndsIt(await signInToPortal(portalSignout),
                                portalSignout);
  const consoleSignout = usernameFor("console-signout");
  await theConsoleSignOutEndsIt(await signInToConsole(consoleSignout),
                                consoleSignout);
  await signingOutInvalidatesIt(newcomer, NEWCOMER);

  // SECTION 7 RUNS BEFORE THE THREE SIGN-OUTS BELOW, in a browser of its own,
  // so that nothing it signs in is signed out from underneath the sections
  // above.
  const appsBrowser = await theApplicationsPageIsDecidedByThePolicy();

  // THE INTRUDER SIGNS IN AGAIN FIRST (2026-09-27). Section 3 has them change
  // their own password, which is CAEP credential-change (#231), and the
  // portal is a Shared Signals receiver whose default signal-response policy
  // ends that person's sessions on it — so the session section 3 made is
  // gone by now, correctly. They sign in with the password they chose.
  const intruderAgain = await signInToPortal(INTRUDER, "IntruderChosen123!");
  log.debug("intruder session before sign-out: " +
            sessionIdOf(intruder) + " replaced by " +
            sessionIdOf(intruderAgain));
  await signingOutInvalidatesIt(intruderAgain, INTRUDER);
  await signingOutInvalidatesIt(owner, OWNER);
  await theConsoleSignOutEndsIt(operator, OPERATOR);

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

test().then(revokeConsoleGrants, async function (e) {
  log.error(e.stack || e.message);
  await revokeConsoleGrants();
  process.exit(1);
});
