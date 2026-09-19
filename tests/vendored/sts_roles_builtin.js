// ===========================================================================
// THE SIX COMPUTED BUILT-IN ROLES, ONE SECTION EACH, IN A THROWAWAY TRUST
// REALM.
//
// `sts_roles.js` beside this file drives the role REGISTER — a role somebody
// was put in, a group that carries one, an application narrowed to one. Every
// role it uses is CONFIGURED. This file drives the six that are not
// configurable at all: they are computed from what the party IS, they were the
// only roles an unedited service had when this file was written, and until
// 2026-09-05 three of them could not be held or failed by anything arriving at
// an endpoint. The four built-in roles added since — REMOTE_PEPS and
// XACML_USER, held through a group, and ADMIN_READ and ADMIN_WRITE, held
// through an access token's scope — are not driven here (`common/roles.js`
// argues each).
//
// ---------------------------------------------------------------------------
// WHY THIS IS A SECOND FILE AND NOT SIX MORE SECTIONS IN THE FIRST.
//
// The two need different WORLDS, and that is the whole of it. `sts_roles.js`
// needs people in a register; this one needs an unauthenticated session, a
// confidential client with a secret on it and a public client with none — and
// it has to be able to say that a token was refused for the client's OWN
// nature rather than for anything anybody configured. Folding them together
// would mean one setup that satisfied both and neither assertion being about
// the world it names.
//
// ---------------------------------------------------------------------------
// POSITIVE AND NEGATIVE FOR FIVE OF THE SIX, AND EVERYBODY IS THE EXCEPTION.
//
// There is no negative case for EVERYBODY and that is a property of the role
// rather than a gap in this file. `holds()` for it is `return true` — every
// party of every kind holds it, authenticated or not, person or application —
// so an application requiring it can refuse nobody. It is the DEFAULT
// requirement, which is what makes this whole feature off-by-default without
// being absent: an application that names no role requires EVERYBODY, and the
// service behaves exactly as it did before roles existed. So the two
// assertions here are that it admits the two parties that are furthest apart
// — somebody who signed in, and somebody who explicitly declined to — and
// section 1 says so rather than leaving a reader to notice that the negative
// is missing.
//
// The other five are asserted in BOTH directions, and the negative is the one
// that carries the weight, for `sts_dpop.js`'s reason: a service that
// issues a token to a party holding the role is what an unmodified service
// does for everybody, so the positive alone would pass against a gate that was
// never consulted. Every negative here is paired with a positive taken in the
// SAME realm against the SAME application a moment earlier or later, so a
// refusal cannot be the service being broken for everybody.
//
// ---------------------------------------------------------------------------
// THE THREE THINGS THIS FILE NEEDED BUILT BEFORE IT COULD BE WRITTEN.
//
// It is worth knowing that the feature moved to meet the test rather than the
// other way round, because it explains why the assertions are shaped as they
// are:
//
//   1. **AN UNAUTHENTICATED SESSION.** There was no such thing. Every session
//      this service held was one somebody had signed into, so
//      ALL_UNAUTHENTICATED_USERS was a name a policy could match and nothing
//      could ever hold. `authn.unauthenticatedSessions` and the sign-in
//      screen's third button are what this file turns on in section 2.
//   2. **A CLIENT'S AUTHENTICATION, OBSERVED WITHOUT BEING ENFORCED.** The
//      token endpoint knew whether RFC 9700 mode REQUIRED a client to
//      authenticate; it did not record whether one had. Both application roles
//      are about exactly that, so `oauth2_bcp.observeClientAuthentication()`
//      exists and is deliberately not mode-gated — see its header. This file
//      runs with `oauth2.rfc9700` OFF, which is the default and the
//      configuration almost everything here runs in, precisely so that the
//      observation is shown to work without the mode.
//   3. **A BUG IN THE SIGN-IN GATE.** The SESSION door asked the role gate
//      with `authenticated: false`, on the reasoning that the session did not
//      exist yet — so an application requiring ALL_AUTHENTICATED_USERS refused
//      EVERY sign-in and could never be used by anybody. It survived because
//      `sts_roles.js` narrows an application to a CONFIGURED role, which the
//      register answers the same either way; only a built-in role can see it.
//      Section 3's positive case is what caught it and is what keeps it
//      caught.
//
// ---------------------------------------------------------------------------
// IT RUNS IN A TRUST REALM OF ITS OWN, for `sts_roles.js`'s reason and one
// more of its own.
//
// That file's reason: this feature REFUSES people, and a job that narrowed an
// application in the default realm and died before clearing it would leave
// every later job in the run signing in to a service that turned them away,
// naming the wrong file.
//
// The one of its own: `authn.unauthenticatedSessions` puts a THIRD BUTTON on
// the sign-in screen, and `sts_admin_console.js` walks every page of the
// console and every control on it. Turning that on process-wide would change a
// screen another job is asserting about. In a realm it changes that realm's
// screen and nothing else.
//
// ---------------------------------------------------------------------------
// IT WAS MUTATION-TESTED BEFORE IT WAS COMMITTED, which tests/CLAUDE.md makes
// non-optional. Each was applied to a copy of the tree, driven, reverted:
//
//   1. `issuanceSubjectOf()` back to the constant `authenticated: true` for
//      the user branch — caught by section 3's negative and section 4's
//      positive, which are the two halves of that constant being wrong;
//   2. the same for the application branch (`clientAuthenticated` ignored,
//      always true) — caught by section 6's negative;
//   3. `observeClientAuthentication()` answering `authenticated: true` for a
//      PUBLIC client — caught by section 5's negative and section 6's
//      positive. This is the mutant worth having: a public client that reads
//      as authenticated is the permissive failure, and it is invisible to
//      every assertion that only checks a token came back;
//   4. the authorization code no longer carrying `session_authenticated` —
//      caught by section 3's negative, which redeems the code rather than
//      stopping at the redirect for exactly this reason;
//   5. the sign-in gate restored to `authenticated: false` (the bug above) —
//      caught by section 3's positive;
//   6. `authn.unauthenticatedSessions` ignored at the endpoint and honoured
//      only on the page — caught by section 2's last check, which posts the
//      form by hand with the setting off;
//   7. `liveSessions()` reporting every session as authenticated — caught by
//      section 2, and it is the mutant that shows why that section exists at
//      all. Every ROLE assertion in this file would still pass with the
//      console blind: the gate reads the session object and the page reads it
//      separately, so a page that lost the distinction would go on drawing a
//      service that was enforcing it correctly.
//
// All seven were killed. None survived a first round.
// ===========================================================================

"use strict";

const assert = require("assert");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const fixtures = require("./oauth_fixtures.js");
const facts = require("./service_facts.js");
// PRODUCT mode implies RFC 9700 mode, which ENFORCES client authentication
// where development only observes it, and allows a public client no
// client_credentials grant. Two sections read it (set in test()).
let PRODUCT = false;

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
var log = bunyan.createLogger({ name: "sts_roles_builtin",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug('CONFIG_FILE could not be read, so the configuration is empty: ' +
            appconfigProblem.message);
}
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");

const REALM = ("builtin-" + names.runStamp()).toLowerCase()
    .replace(/[^a-z0-9-]/g, "").slice(0, 40);

// THE PARTIES, fixed rather than random because every refusal sentence below
// quotes them and a name that changed per run would make a failing log
// unreadable.
//
// **THE PERSON IS CREATED BY THIS JOB AND NOT SEEDED (2026-09-12).** It was
// `alice`, whom every realm's directory is seeded with in development and in
// product nobody. So it is made in `createTheRealm()` through the realm's own
// `/admin-api/users/create`, with the attributes a real account carries and a
// password of at least twelve characters, which is what the sign-in screen is
// sent. The six applications are registered with the redirect URI the
// authorization requests name, because product mode answers only a registered
// one.
//
// **WHAT IS DELIBERATELY NOT SUPPLIED**: a client secret on the six
// applications and on PUBLIC_CLIENT. Three of the six sections are ABOUT
// whether a client authenticated — ALL_UNAUTHENTICATED_APPLICATIONS needs a
// client with no credential to have a positive case at all — so this job
// exercises a development-mode behaviour on purpose. Product mode ALLOWS a
// public client since 2026-09-17, but only one REGISTERED
// `token_endpoint_auth_method=none`, and it holds that client to RFC 9700
// (PKCE, an exactly registered redirect URI) — which these six applications,
// registered with no method and so confidential under RFC 7591 section 2,
// are not set up for. The suite runs every mode in development, so none of
// that is reached here; it is stated so a reader does not assume the old
// "product mode has no public clients" still holds.
const PERSON = "builtin-person";
const PASSWORD = "roles-builtin-Passw0rd!-" + names.runStamp();
const ANON = "anonymous";        // authn.js's ANONYMOUS_USERNAME

// SIX APPLICATIONS, ONE PER ROLE, and that is deliberate rather than tidy: an
// application carries its requirement in `appRequiredRole`, so reusing one
// across sections would mean clearing and re-adding the attribute between
// them, and a section that failed to clear would make the NEXT section's
// result a lie about a requirement it never set.
const APP_EVERYBODY   = "builtin-everybody";
const APP_AUTH_USERS  = "builtin-auth-users";
const APP_UNAUTH_USER = "builtin-unauth-users";
const APP_ALL_APPS    = "builtin-all-apps";
const APP_AUTH_APPS   = "builtin-auth-apps";
const APP_UNAUTH_APPS = "builtin-unauth-apps";

// THE TWO CLIENTS THE APPLICATION SECTIONS ARE ABOUT. They are the SUBJECT of
// those decisions rather than the resource, which is the thing most likely to
// be misread here: under client_credentials the client IS the party being
// asked about, so these two are what holds or does not hold the role.
const CONFIDENTIAL = "builtin-confidential-client";
const PUBLIC_CLIENT = "builtin-public-client";
const CLIENT_SECRET = "builtin-secret-not-a-real-one";

var checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.debug("check passed: " + what);
  log.debug("Leaving check().");
}

function realmUrl(path) {
  log.debug("Entering realmUrl().");
  log.debug("Leaving realmUrl().");
  return base + "/realm/" + REALM + path;
}

function api(path) {
  log.debug("Entering api().");
  log.debug("Leaving api().");
  return realmUrl("/admin-api" + path);
}

// ---------------------------------------------------------------------------
// THE VERBS. Copied in shape from sts_roles.js, which is the file this one
// sits beside; the two differ in what they drive and not in how.
// ---------------------------------------------------------------------------
async function fetchJson(url, options) {
  log.debug("Entering fetchJson(). url=" + url);
  const r = await fetch(url, options || {});
  const text = await r.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in fetchJson(): " + ((e && e.message) || e));
    // Not JSON — an HTML page or a redirect with no body. The caller reports
    // the status and the raw text, which says more than a parse error would.
    body = null;
  }
  log.debug("Leaving fetchJson(). status=" + r.status);
  return { status: r.status, body: body, text: text,
           location: r.headers.get("location") || "" };
}

function get(url) {
  log.debug("Entering get().");
  log.debug("Leaving get().");
  return fetchJson(url);
}

function postJson(url, payload) {
  log.debug("Entering postJson().");
  log.debug("Leaving postJson().");
  return fetchJson(url, { method: "POST",
                          headers: { "Content-Type": "application/json" },
                          body: JSON.stringify(payload || {}) });
}

async function act(resource, action, payload, what) {
  log.debug("Entering act().");
  const r = await postJson(api("/" + resource + "/" + action), payload || {});
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "POST /admin-api/" + resource + "/" + action + " should have " + what +
    "; it answered " + r.status + " " +
    JSON.stringify((r.body && (r.body.errors || r.body.why)) ||
                   r.body || r.text).slice(0, 400));
  log.debug("Leaving act().");
  return r.body;
}

async function setSetting(key, value) {
  log.debug("Entering setSetting().");
  const r = await postJson(api("/config/set"), { key: key, value: value });
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "setting " + key + " in the realm should have worked; it answered " +
    r.status + " " + String(r.text).slice(0, 300));
  log.debug("Leaving setSetting().");
}

function claimsOf(jwt) {
  log.debug("Entering claimsOf().");
  const part = String(jwt).split(".")[1] || "";
  log.debug("Leaving claimsOf().");
  return JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
}

// ---------------------------------------------------------------------------
// A BROWSER, because four of the six sections need a SESSION and a session is
// a cookie. Manual redirects, for `sts_consent.js`'s reason: every assertion
// about a refusal here is about WHICH redirect came back, and a fetch that
// followed them would answer the question by hiding it.
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

function browser() {
  log.debug("Entering browser().");
  const self = {
    cookie: "",
    async go(method, path, body) {
      log.debug("Entering go(). " + method + " " + path);
      const headers = {};
      if (self.cookie) { headers.cookie = self.cookie; }
      if (body !== undefined) {
        headers["Content-Type"] = "application/x-www-form-urlencoded";
      }
      const r = await fetch(absolute(path), { method: method,
                                              redirect: "manual",
                                              headers: headers, body: body });
      const set = r.headers.getSetCookie ? r.headers.getSetCookie() : [];
      set.forEach(function (one) { self.cookie = String(one).split(";")[0]; });
      const text = await r.text();
      log.debug("Leaving go(). status=" + r.status);
      return { status: r.status, location: r.headers.get("location") || "",
               text: text };
    }
  };
  log.debug("Leaving browser().");
  return self;
}

const REDIRECT_URI = "https://example.test/builtin-callback";

// PKCE ON EVERY REQUEST (2026-09-18). The clients below are public — they
// hold no secret — and a product-mode service holds a public client to PKCE
// with S256 and a challenge it has not seen before, so each authorization
// request carries a fresh pair and the code it produces is redeemed with the
// verifier of the MOST RECENT request for that client, which is the order this
// file always asks in.
const latestVerifier = {};

function authorizeUrl(clientId, state) {
  log.debug("Entering authorizeUrl().");
  const pair = fixtures.pkce();
  latestVerifier[clientId] = pair.verifier;
  log.debug("Leaving authorizeUrl().");
  return "/realm/" + REALM + "/oauth2/authorize?" + form({
    response_type: "code", client_id: clientId, redirect_uri: REDIRECT_URI,
    scope: "openid", state: state || ("builtin-" + REALM),
    code_challenge: pair.challenge, code_challenge_method: pair.method
  });
}

// The `authn_id` the sign-in form carries. Read out of the markup rather than
// guessed, because it is minted per request and is the only thing tying the
// POST back to the flow that started it.
function authnIdIn(html) {
  log.debug("Entering authnIdIn().");
  const m = /name="authn_id"\s+value="([^"]+)"/.exec(String(html));
  log.debug("Leaving authnIdIn().");
  return m ? m[1] : "";
}

// SIGN SOMEBODY IN, OR DECLINE TO. One function for both, because the two
// paths differ in exactly one form field and writing them separately would
// hide that — which is the whole point of this file.
//
// It returns the browser, so a caller can then present the session it holds to
// whichever endpoint the section is about.
async function arriveAt(clientId, how, state) {
  log.debug("Entering arriveAt(). client=" + clientId + ", how=" + how);
  const b = browser();
  const first = await b.go("GET", authorizeUrl(clientId, state));
  assert.strictEqual(first.status, 302,
    "an authorization request with no session should redirect to the " +
    "sign-in screen; it answered " + first.status);
  const screen = await b.go("GET", first.location);
  const id = authnIdIn(screen.text);
  assert.ok(id, "the sign-in screen should carry an authn_id; it did not. " +
    String(screen.text).slice(0, 300));
  const fields = how === "anonymous"
    ? { authn_id: id, action: "anonymous" }
    : { authn_id: id, action: "login", username: PERSON, password: PASSWORD };
  const posted = await b.go("POST", "/realm/" + REALM + "/authn/login",
                            form(fields));
  log.debug("Leaving arriveAt(). status=" + posted.status);
  return { browser: b, posted: posted, screen: screen };
}

// A SESSION OBTAINED SOMEWHERE PERMISSIVE, TO BE PRESENTED SOMEWHERE STRICT.
//
// **THERE ARE TWO DOORS AND THIS FILE HAS TO REACH BOTH.** A required role is
// asked about at the SESSION door — the sign-in screen, before a session
// exists — and again at the AUTHORIZATION door for a session that already
// does. They are different code, they refuse differently, and a test that only
// ever arrived at the strict application would never see the second: the
// sign-in screen would turn the party away and no session would ever be
// carried to the authorization endpoint at all.
//
// So this signs in at the EVERYBODY application, which refuses nobody, and
// hands back a browser holding the session. Presenting that session to a
// strict application is what exercises the second door — and it is also what a
// real single sign-on looks like, where the session was made for one
// application and offered to the next.
async function sessionVia(how, state) {
  log.debug("Entering sessionVia(). how=" + how);
  const arrived = await arriveAt(APP_EVERYBODY, how, state);
  assert.strictEqual(arrived.posted.status, 303,
    "the EVERYBODY application must admit " + how + " — every other section " +
    "builds its session here. It answered " + arrived.posted.status + " " +
    String(arrived.posted.text).slice(0, 300));
  // Complete the flow it interrupted, so the session is settled before it is
  // carried anywhere else.
  await arrived.browser.go("GET", authorizeUrl(APP_EVERYBODY, state));
  log.debug("Leaving sessionVia().");
  return arrived.browser;
}

// WAS THIS THE SIGN-IN SCREEN REFUSING, and did it say why?
//
// The screen's refusal is the PAGE AGAIN with the reason on it, rather than a
// redirect carrying an error, and that is deliberate in `authn.js`: the only
// place to send somebody is back into the authorization endpoint that would
// refuse them a second time, which is a loop. So a refusal here is a 200 that
// is still the form, and the assertion has to be about the sentence.
function refusedAtTheScreen(posted, requiredRole) {
  log.debug("Entering refusedAtTheScreen().");
  log.debug("Leaving refusedAtTheScreen().");
  return posted.status === 200 &&
         /name="authn_id"/.test(String(posted.text)) &&
         String(posted.text).indexOf(requiredRole) >= 0;
}

// WHAT THE AUTHORIZATION ENDPOINT ANSWERED, split into the two shapes that
// matter. A code in the redirect is a Permit; `error=access_denied` in it is
// the refusal this feature makes. Anything else — a sign-in screen, a 500 — is
// neither, and saying which is what makes a failure readable.
function verdictOf(r) {
  log.debug("Entering verdictOf().");
  const loc = String(r.location || "");
  if (/[?&]code=/.test(loc)) {
    log.debug("Leaving verdictOf().");
    return { permitted: true, code: /[?&]code=([^&]+)/.exec(loc)[1],
             where: loc };
  }
  if (/[?&]error=/.test(loc)) {
    const code = /[?&]error=([^&]+)/.exec(loc)[1];
    const why = /[?&]error_description=([^&]*)/.exec(loc);
    log.debug("Leaving verdictOf().");
    return { permitted: false, error: decodeURIComponent(code),
             why: why ? decodeURIComponent(why[1].replace(/\+/g, " ")) : "",
             where: loc };
  }
  log.debug("Leaving verdictOf().");
  return { permitted: false, error: "", why: "", where: loc ||
           ("status " + r.status) };
}

// REDEEM THE CODE. Section 3 and section 4 do this rather than stopping at the
// redirect, and the reason is mutant 4: the authorization endpoint and the
// TOKEN endpoint ask the gate separately, so a code that was correctly issued
// can still be redeemed by a token endpoint that lost track of who the session
// belonged to. Only redeeming it covers both.
function redeem(code, clientId) {
  log.debug("Entering redeem().");
  log.debug("Leaving redeem().");
  return fetchJson(realmUrl("/oauth2/token"), {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form({ grant_type: "authorization_code", code: code,
                 redirect_uri: REDIRECT_URI, client_id: clientId,
                 code_verifier: latestVerifier[clientId] || "" })
  });
}

// A client_credentials request, with or without the secret. The one grant in
// which the CLIENT is the party the gate is asked about, which is what makes
// the two application roles reachable at all.
function clientCredentials(clientId, secret, resourceApp) {
  log.debug("Entering clientCredentials().");
  const headers = { "Content-Type": "application/x-www-form-urlencoded" };
  if (secret) {
    headers.authorization = "Basic " +
      Buffer.from(clientId + ":" + secret).toString("base64");
  }
  log.debug("Leaving clientCredentials().");
  // `client_id` in the body EVEN WHEN the secret is in the header, because
  // this service reads the identifier from the body and the credential from
  // wherever it arrived. A request that named the client only in the header
  // would be testing the parser rather than the role.
  return fetchJson(realmUrl("/oauth2/token"), {
    method: "POST", headers: headers,
    body: form({ grant_type: "client_credentials", client_id: clientId,
                 scope: "openid" })
  });
}

// ---------------------------------------------------------------------------
// SETUP AND TEARDOWN.
// ---------------------------------------------------------------------------
async function createTheRealm() {
  log.debug("Entering createTheRealm().");
  log.info("=== A throwaway trust realm ===");
  const r = await postJson(base + "/admin-api/realms/create",
                           { id: REALM,
                             name: "the built-in roles under test" });
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "creating the realm " + REALM + " should have worked; it answered " +
    r.status + " " + String(r.text).slice(0, 300));
  log.info("Created the throwaway realm " + REALM + ".");
  log.debug("Leaving createTheRealm().");
}

// THE REALM IS LEFT STANDING, DELIBERATELY (2026-09-06). It used to be removed
// here; what changed is an operator requirement rather than anything about the
// feature — **a realm a test run created stays, because it is what a person
// reads when the run went red.** Its six applications, its two clients and its
// settings are the record of what this job actually built, and a teardown
// that removed it threw that away at the moment it was worth something. The id
// carries `names.runStamp()` and every write is inside the realm, so leaving it
// meets neither a later run of this job nor anything else in the suite.
async function theRealmIsLeftBehind() {
  log.debug("Entering theRealmIsLeftBehind().");
  log.info("The throwaway realm " + REALM + " is LEFT IN PLACE on purpose — " +
           "it holds the six applications, the two clients and the settings " +
           "this job built, and it is where somebody debugging this run " +
           "should look. Read it at " + base + "/realm/" + REALM + "/admin, " +
           "or remove it by hand when you are done with it.");
  log.debug("Leaving theRealmIsLeftBehind().");
}

// THE WORLD. Six applications, two clients, the one setting this feature
// needs and the one it must turn off — all of it in the realm, none of it
// anywhere else.
async function buildTheWorld() {
  log.debug("Entering buildTheWorld().");
  log.info("=== Building the world ===");

  // THE CONSENT SCREEN IS TURNED OFF, and that needs saying rather than doing
  // quietly. `oauth2.consentRequired` is ON by default — one of the few
  // policies here that is — and it sits between the authorization endpoint
  // and its redirect, so every `verdictOf()` below would see a consent screen
  // instead of the decision this file is about. `sts_consent.js` is what
  // covers that screen; this file is about what happens after it, and the two
  // must not each be half-testing the other's subject.
  await setSetting("oauth2.consentRequired", false);

  // AND THE THIRD BUTTON IS TURNED ON. Off by default, because it changes a
  // screen; on here, because three of the six sections need a party that
  // declined to authenticate and there is no other way to become one.
  await setSetting("authn.unauthenticatedSessions", true);

  const apps = [
    [APP_EVERYBODY,   "EVERYBODY"],
    [APP_AUTH_USERS,  "ALL_AUTHENTICATED_USERS"],
    [APP_UNAUTH_USER, "ALL_UNAUTHENTICATED_USERS"],
    [APP_ALL_APPS,    "ALL_APPLICATIONS"],
    [APP_AUTH_APPS,   "ALL_AUTHENTICATED_APPLICATIONS"],
    [APP_UNAUTH_APPS, "ALL_UNAUTHENTICATED_APPLICATIONS"]
  ];
  await act("users", "create", {
    username: PERSON, invent: false,
    attributes: { cn: "Builtin Person", givenName: "Builtin", sn: "Person",
                  displayName: "Builtin Person",
                  mail: PERSON + "@roles-builtin.test" },
    credential: "password", password: PASSWORD
  }, "created " + PERSON + " in the realm, with a password");

  for (const [identifier, role] of apps) {
    await act("applications", "create",
              { identifier: identifier, kind: "oauth2-client", name: identifier,
                protocols: ["oauth2", "oidc"],
                fields: { oauthClientId: [identifier],
                          oauthRedirectUri: [REDIRECT_URI] } },
              "created " + identifier);
    // EVERY ONE OF THEM NAMES ITS ROLE EXPLICITLY, including the EVERYBODY
    // one, which would behave identically with the attribute absent. That is
    // the point: section 1 asserts that naming the default requirement
    // explicitly is the same as naming nothing, which is what makes EVERYBODY
    // a real answer rather than a way of spelling "unconfigured".
    await act("applications", "add",
              { application: identifier, attribute: "appRequiredRole",
                value: role },
              "required " + role + " of " + identifier);
  }

  // THE CONFIDENTIAL CLIENT. A secret AND the method that says to check it —
  // both, because `observeClientAuthentication()` treats a client declaring a
  // method with nothing on file to check as NOT authenticated, which is a
  // third state and one this file does not want to be accidentally in.
  await act("applications", "create",
            { identifier: CONFIDENTIAL, kind: "oauth2-client",
              name: "a confidential client" },
            "created the confidential client");
  await act("applications", "set",
            { application: CONFIDENTIAL, attribute: "oauthClientSecret",
              value: CLIENT_SECRET }, "gave it a secret");
  await act("applications", "set",
            { application: CONFIDENTIAL,
              attribute: "oauthTokenEndpointAuthMethod",
              value: "client_secret_basic" }, "made it confidential");

  // THE PUBLIC CLIENT. `none` stated OUTRIGHT rather than left absent, so that
  // this client is public because somebody said so and not because a field was
  // forgotten — the two are the same to the code and very different to a
  // reader working out why a section failed.
  await act("applications", "create",
            { identifier: PUBLIC_CLIENT, kind: "oauth2-client",
              name: "a public client" }, "created the public client");
  await act("applications", "set",
            { application: PUBLIC_CLIENT,
              attribute: "oauthTokenEndpointAuthMethod",
              value: "none" }, "made it public");

  log.info("Six applications, two clients, two settings.");
  log.debug("Leaving buildTheWorld().");
}

// ---------------------------------------------------------------------------
// 1. EVERYBODY — TWO POSITIVES AND NO NEGATIVE, AND THE ABSENCE IS THE POINT.
// ---------------------------------------------------------------------------
async function everybody() {
  log.debug("Entering everybody().");
  log.info("=== 1. EVERYBODY ===");

  const signedIn = await arriveAt(APP_EVERYBODY, "login", "e1");
  const one = verdictOf(await signedIn.browser.go("GET",
                          authorizeUrl(APP_EVERYBODY, "e1")));
  check("EVERYBODY admits somebody who signed in", function () {
    assert.ok(one.permitted,
      "an application requiring EVERYBODY should issue a code to a person " +
      "who authenticated; it answered " + one.where);
  });

  const declined = await arriveAt(APP_EVERYBODY, "anonymous", "e2");
  const two = verdictOf(await declined.browser.go("GET",
                          authorizeUrl(APP_EVERYBODY, "e2")));
  check("EVERYBODY admits somebody who declined to sign in", function () {
    assert.ok(two.permitted,
      "an application requiring EVERYBODY should issue a code to an " +
      "UNAUTHENTICATED session too — that is the whole difference between it " +
      "and ALL_AUTHENTICATED_USERS; it answered " + two.where);
  });

  // THE TOKEN, not just the code. The authorization endpoint and the token
  // endpoint ask the gate separately.
  const token = await redeem(two.code, APP_EVERYBODY);
  check("and the code redeems for a token", function () {
    assert.strictEqual(token.status, 200,
      "redeeming a code issued to an unauthenticated session under " +
      "EVERYBODY should work; it answered " + token.status + " " +
      String(token.text).slice(0, 300));
  });
  check("whose subject is the anonymous principal", function () {
    const c = claimsOf(token.body.access_token);
    assert.ok(String(c.username || c.sub || "").indexOf(ANON) >= 0,
      "the token should be about the anonymous principal; its username was " +
      JSON.stringify(c.username) + " and its sub " + JSON.stringify(c.sub));
  });

  // AND THE NEGATIVE THAT DOES NOT EXIST, stated as an assertion about the
  // CATALOGUE rather than left as a missing section. If somebody ever gives
  // EVERYBODY a `holds()` that can answer false, this is what fails.
  const cat = await get(api("/roles"));
  check("EVERYBODY is documented as the default requirement", function () {
    const all = (cat.body && cat.body.builtIn) || [];
    const it = all.filter(function (r) { return r.name === "EVERYBODY"; })[0];
    assert.ok(it, "the built-in catalogue should list EVERYBODY; it listed " +
      JSON.stringify(all.map(function (r) { return r.name; })));
    assert.ok(/default/i.test(String(it.what)),
      "EVERYBODY's description should say it is the DEFAULT requirement, " +
      "which is why this section has no negative case: it refuses nobody. " +
      "It said: " + JSON.stringify(it.what).slice(0, 200));
  });
  log.debug("Leaving everybody().");
}

// ---------------------------------------------------------------------------
// 2. THE UNAUTHENTICATED SESSION ITSELF, before any role is asked about it.
// ---------------------------------------------------------------------------
async function theUnauthenticatedSession() {
  log.debug("Entering theUnauthenticatedSession().");
  log.info("=== 2. The unauthenticated session ===");

  const declined = await arriveAt(APP_EVERYBODY, "anonymous", "u1");
  check("declining returns to the caller rather than ending the flow",
        function () {
    assert.strictEqual(declined.posted.status, 303,
      "\"Continue without signing in\" should send the browser back to the " +
      "flow it interrupted; it answered " + declined.posted.status);
    assert.ok(/\/oauth2\/authorize/.test(declined.posted.location),
      "and back to the authorization endpoint; it went to " +
      declined.posted.location);
  });
  check("and it is NOT the access_denied that Cancel answers", function () {
    assert.ok(declined.posted.location.indexOf("error=access_denied") < 0,
      "Cancel answers access_denied and creates nothing; this button is the " +
      "opposite act and must not. It went to " + declined.posted.location);
  });

  const live = await get(api("/sessions"));
  check("the session is live and counted as unauthenticated", function () {
    assert.ok(live.body.unauthenticatedHeld >= 1,
      "at least one unauthenticated session should be live; " +
      "/admin-api/sessions reported " +
      JSON.stringify(live.body.unauthenticatedHeld));
  });
  check("and it is the anonymous principal, on a real session id", function () {
    const rows = live.body.unauthenticatedSessions || [];
    assert.ok(rows.length >= 1, "there should be rows to go with the count; " +
      "there were " + rows.length);
    assert.strictEqual(rows[0].username, ANON,
      "an unauthenticated session belongs to the anonymous principal; this " +
      "one said " + JSON.stringify(rows[0].username));
    assert.ok(rows[0].sessionId,
      "it is a REAL session and must carry the id a token records; it had " +
      JSON.stringify(rows[0].sessionId));
  });

  // THE SIGNED-IN SESSION IS NOT IN THAT LIST, which is the half that stops
  // the section passing against a service that simply put every session in it.
  const signedIn = await arriveAt(APP_EVERYBODY, "login", "u2");
  await signedIn.browser.go("GET", authorizeUrl(APP_EVERYBODY, "u2"));
  const after = await get(api("/sessions"));
  check("a session somebody signed into is NOT in that list", function () {
    const names = (after.body.unauthenticatedSessions || [])
      .map(function (r) { return r.username; });
    assert.ok(names.indexOf(PERSON) < 0,
      PERSON + " authenticated, so that session must not be listed as " +
      "unauthenticated. The list held " + JSON.stringify(names));
    assert.ok(after.body.held > after.body.unauthenticatedHeld,
      "there should be more live sessions than unauthenticated ones by now: " +
      after.body.held + " live, " + after.body.unauthenticatedHeld +
      " unauthenticated.");
  });

  // THE SETTING IS THE DOOR AND NOT ONLY THE BUTTON — mutant 6. The form is
  // posted BY HAND with the setting off, which is what somebody who had seen
  // the button once would do.
  await setSetting("authn.unauthenticatedSessions", false);
  const b = browser();
  const first = await b.go("GET", authorizeUrl(APP_EVERYBODY, "u3"));
  const screen = await b.go("GET", first.location);
  check("with the setting off the button is not drawn", function () {
    assert.ok(String(screen.text).indexOf("kc-anonymous") < 0,
      "the sign-in screen should not offer the third button while " +
      "authn.unauthenticatedSessions is off.");
  });
  const byHand = await b.go("POST", "/realm/" + REALM + "/authn/login",
                            form({ authn_id: authnIdIn(screen.text),
                                   action: "anonymous" }));
  check("and posting the form by hand does NOT mint a session", function () {
    assert.ok(byHand.status !== 303 ||
              /\/authn\/login/.test(String(byHand.location)),
      "with the setting off, action=anonymous must not start a session — the " +
      "button being absent is a fact about one rendering and the refusal has " +
      "to be a fact about the endpoint. It answered " + byHand.status + " -> " +
      byHand.location);
  });
  await setSetting("authn.unauthenticatedSessions", true);
  log.debug("Leaving theUnauthenticatedSession().");
}

// ---------------------------------------------------------------------------
// 3. ALL_AUTHENTICATED_USERS — positive and negative, AT BOTH DOORS.
// ---------------------------------------------------------------------------
async function allAuthenticatedUsers() {
  log.debug("Entering allAuthenticatedUsers().");
  log.info("=== 3. ALL_AUTHENTICATED_USERS ===");

  // THE POSITIVE IS THE ONE THAT FOUND THE BUG. The sign-in gate asked with
  // `authenticated: false`, so this application refused EVERY sign-in and
  // could never be used by anybody.
  const signedIn = await arriveAt(APP_AUTH_USERS, "login", "a1");
  check("somebody can actually SIGN IN to such an application", function () {
    assert.strictEqual(signedIn.posted.status, 303,
      "the sign-in screen's own role gate must not refuse a person who is " +
      "authenticating at it — that gate runs after the credential has been " +
      "accepted and before the session exists, and reading it as " +
      "\"nobody has authenticated\" made ALL_AUTHENTICATED_USERS refuse " +
      "everybody. It answered " + signedIn.posted.status + " " +
      String(signedIn.posted.text).slice(0, 300));
  });

  const yes = verdictOf(await signedIn.browser.go("GET",
                          authorizeUrl(APP_AUTH_USERS, "a1")));
  check("and the authorization endpoint issues them a code", function () {
    assert.ok(yes.permitted,
      "a person who authenticated holds ALL_AUTHENTICATED_USERS; it " +
      "answered " + yes.where);
  });
  const token = await redeem(yes.code, APP_AUTH_USERS);
  check("which redeems for a token", function () {
    assert.strictEqual(token.status, 200,
      "the token endpoint asks the gate separately and must reach the same " +
      "answer; it answered " + token.status + " " +
      String(token.text).slice(0, 300));
  });

  // NEGATIVE, DOOR ONE — THE SIGN-IN SCREEN. Declining AT this application is
  // refused before a session exists, which is the better place to refuse it:
  // there is still a screen to say so on.
  const declinedHere = await arriveAt(APP_AUTH_USERS, "anonymous", "a2");
  check("declining AT such an application is refused at the sign-in screen",
        function () {
    assert.ok(refusedAtTheScreen(declinedHere.posted,
                                 "ALL_AUTHENTICATED_USERS"),
      "the SESSION door should refuse this before minting anything, and say " +
      "which role it wanted. It answered " + declinedHere.posted.status +
      " -> " + declinedHere.posted.location + " " +
      String(declinedHere.posted.text).slice(0, 300));
  });
  check("and mints no session at all", function () {
    assert.notStrictEqual(declinedHere.posted.status, 303,
      "a refusal at this door must not also start the session it refused; " +
      "it answered " + declinedHere.posted.status);
  });

  // NEGATIVE, DOOR TWO — THE AUTHORIZATION ENDPOINT. The session is made at
  // the EVERYBODY application, which admits it, and then offered here. That is
  // single sign-on, and it is the only way to reach this door with a session
  // the strict application would never have created.
  const carried = await sessionVia("anonymous", "a3");
  const no = verdictOf(await carried.go("GET",
                         authorizeUrl(APP_AUTH_USERS, "a3")));
  check("an unauthenticated session carried here is REFUSED", function () {
    assert.ok(!no.permitted,
      "an application requiring ALL_AUTHENTICATED_USERS must refuse a " +
      "session nobody authenticated for, however that session got here; it " +
      "issued " + no.where);
  });
  check("in OAuth's own words, and as the error CODE", function () {
    assert.strictEqual(no.error, "access_denied",
      "read as the error CODE and not merely as a redirect: a working gate " +
      "and a broken handler both fail to issue a code, and only the code " +
      "tells them apart. It answered error=" + JSON.stringify(no.error));
  });
  check("naming the role required and the roles held", function () {
    assert.ok(/ALL_AUTHENTICATED_USERS/.test(no.why),
      "the refusal should name the role that was required; it said " +
      JSON.stringify(no.why));
    assert.ok(/ALL_UNAUTHENTICATED_USERS/.test(no.why),
      "and the roles the party actually holds, which is what makes it " +
      "actionable; it said " + JSON.stringify(no.why));
  });
  log.debug("Leaving allAuthenticatedUsers().");
}

// ---------------------------------------------------------------------------
// 4. ALL_UNAUTHENTICATED_USERS — positive and negative, the mirror of 3.
// ---------------------------------------------------------------------------
async function allUnauthenticatedUsers() {
  log.debug("Entering allUnauthenticatedUsers().");
  log.info("=== 4. ALL_UNAUTHENTICATED_USERS ===");

  const declined = await arriveAt(APP_UNAUTH_USER, "anonymous", "n1");
  check("declining is admitted by an application that wants exactly that",
        function () {
    assert.strictEqual(declined.posted.status, 303,
      "the party that declined to authenticate is who this role is about, so " +
      "the SESSION door must admit them; it answered " +
      declined.posted.status + " " +
      String(declined.posted.text).slice(0, 300));
  });
  const yes = verdictOf(await declined.browser.go("GET",
                          authorizeUrl(APP_UNAUTH_USER, "n1")));
  check("and the authorization endpoint issues a code", function () {
    assert.ok(yes.permitted,
      "an unauthenticated session HOLDS ALL_UNAUTHENTICATED_USERS; it " +
      "answered " + yes.where);
  });
  const token = await redeem(yes.code, APP_UNAUTH_USER);
  check("and the token endpoint agrees", function () {
    assert.strictEqual(token.status, 200,
      "the code carries what was true of the session when it was minted, so " +
      "the token endpoint must reach the same answer over a back channel " +
      "with no cookie on it. It answered " + token.status + " " +
      String(token.text).slice(0, 300));
  });

  // THE NEGATIVE, AT BOTH DOORS AGAIN — and this is the pair that shows the
  // two roles are not each other's negation as far as a target is concerned.
  // The same person section 3 admitted is refused here.
  const signedInHere = await arriveAt(APP_UNAUTH_USER, "login", "n2");
  check("somebody signing IN is refused at the screen", function () {
    assert.ok(refusedAtTheScreen(signedInHere.posted,
                                 "ALL_UNAUTHENTICATED_USERS"),
      "a person who authenticates does not hold ALL_UNAUTHENTICATED_USERS, " +
      "and the SESSION door is where that is noticed. It answered " +
      signedInHere.posted.status + " " +
      String(signedInHere.posted.text).slice(0, 300));
  });

  const carried = await sessionVia("login", "n3");
  const no = verdictOf(await carried.go("GET",
                         authorizeUrl(APP_UNAUTH_USER, "n3")));
  check("and an authenticated session carried here is refused too",
        function () {
    assert.ok(!no.permitted,
      "the same person section 3 admitted must be refused by this " +
      "application; it issued " + no.where);
  });
  check("with access_denied naming both sides", function () {
    assert.strictEqual(no.error, "access_denied",
      "it answered error=" + JSON.stringify(no.error));
    assert.ok(/ALL_UNAUTHENTICATED_USERS/.test(no.why) &&
              /ALL_AUTHENTICATED_USERS/.test(no.why),
      "the sentence should name the role required and the role held, which " +
      "here are the two that differ by one word — so a reader can see which " +
      "way round it went. It said " + JSON.stringify(no.why));
  });
  log.debug("Leaving allUnauthenticatedUsers().");
}

// ---------------------------------------------------------------------------
// 5. ALL_APPLICATIONS — two positives, and the negative that is a PERSON.
// ---------------------------------------------------------------------------
async function allApplications() {
  log.debug("Entering allApplications().");
  log.info("=== 5. ALL_APPLICATIONS ===");

  // BOTH CLIENTS, because the role is about being an application at all and
  // says nothing about how it turned up. A gate that quietly meant
  // "authenticated application" would pass the first of these and fail the
  // second.
  await act("applications", "add",
            { application: CONFIDENTIAL, attribute: "appRequiredRole",
              value: "ALL_APPLICATIONS" }, "narrowed the confidential client");
  await act("applications", "add",
            { application: PUBLIC_CLIENT, attribute: "appRequiredRole",
              value: "ALL_APPLICATIONS" }, "narrowed the public client");

  const conf = await clientCredentials(CONFIDENTIAL, CLIENT_SECRET);
  check("a CONFIDENTIAL client holds ALL_APPLICATIONS", function () {
    assert.strictEqual(conf.status, 200,
      "client_credentials for a confidential client against an application " +
      "requiring ALL_APPLICATIONS should be issued; it answered " +
      conf.status + " " + String(conf.text).slice(0, 300));
  });

  const pub = await clientCredentials(PUBLIC_CLIENT, null);
  if (PRODUCT) {
    // No grant lets a public client act AS ITSELF in product mode, so this
    // positive is unreachable there; what is asserted is the rule that makes
    // it so, which is decided before any role is asked.
    check("in PRODUCT mode a PUBLIC client is refused client_credentials " +
          "before any role is asked", function () {
      assert.strictEqual(pub.body && pub.body.error, "unauthorized_client",
        "it answered " + pub.status + " " + String(pub.text).slice(0, 300));
    });
  } else check("and so does a PUBLIC one", function () {
    assert.strictEqual(pub.status, 200,
      "ALL_APPLICATIONS is about being an application, not about having " +
      "proved anything — a public client holds it too. It answered " +
      pub.status + " " + String(pub.text).slice(0, 300));
  });

  // THE NEGATIVE IS A PERSON, and it is the only negative this role has.
  // ALL_APPLICATIONS cannot refuse an application, so what it refuses is a
  // party of the other KIND — which is what makes it a real requirement rather
  // than a synonym for EVERYBODY. Carried from the EVERYBODY application,
  // because the sign-in screen would otherwise refuse first and this would be
  // section 3's assertion over again rather than this one.
  const carried = await sessionVia("login", "p1");
  const no = verdictOf(await carried.go("GET",
                         authorizeUrl(APP_ALL_APPS, "p1")));
  check("a PERSON is refused by ALL_APPLICATIONS", function () {
    assert.ok(!no.permitted,
      "an authorization-code flow is about a person, and a person is not an " +
      "application however well they authenticated. It issued " + no.where);
  });
  check("with access_denied naming the role required", function () {
    assert.strictEqual(no.error, "access_denied",
      "it answered error=" + JSON.stringify(no.error));
    assert.ok(/ALL_APPLICATIONS/.test(no.why),
      "it should name the role required; it said " + JSON.stringify(no.why));
  });
  check("and the person is NOT reported as holding an application role",
        function () {
    const held = /holds\s+([^.]*)/.exec(String(no.why));
    assert.ok(held, "the sentence should say what the party holds; it said " +
      JSON.stringify(no.why));
    assert.ok(held[1].indexOf("ALL_APPLICATIONS") < 0,
      "a person holds no application role, and reporting one would mean the " +
      "gate had lost track of the KIND of party it was asked about. It said " +
      JSON.stringify(held[1]));
  });
  log.debug("Leaving allApplications().");
}

// ---------------------------------------------------------------------------
// 6. THE TWO APPLICATION ROLES THAT SPLIT ON CLIENT AUTHENTICATION.
//
// This is the section the observation was built for, and it runs with
// `oauth2.rfc9700` OFF — the default. A service that only noticed client
// authentication in BCP mode would pass every other section in this file and
// fail both halves of this one.
// ---------------------------------------------------------------------------
async function theApplicationAuthenticationSplit() {
  log.debug("Entering theApplicationAuthenticationSplit().");
  log.info("=== 6. ALL_AUTHENTICATED_APPLICATIONS / " +
           "ALL_UNAUTHENTICATED_APPLICATIONS ===");

  const mode = await get(realmUrl("/oauth2/rfc9700"));
  if (PRODUCT) check("RFC 9700 mode is ON, as product mode implies — so " +
                     "client authentication is ENFORCED here", function () {
    assert.ok(mode.body && mode.body.enabled === true,
      "/oauth2/rfc9700 said " + JSON.stringify(mode.body && mode.body.enabled));
  });
  else check("RFC 9700 mode is OFF, which is what makes this section worth having",
        function () {
    assert.ok(mode.body && mode.body.enabled === false,
      "this section asserts that client authentication is OBSERVED without " +
      "being ENFORCED, so the mode must be off for the assertion to mean " +
      "that. /oauth2/rfc9700 said " +
      JSON.stringify(mode.body && mode.body.enabled));
  });

  // Each client now requires the role that is about ITS OWN nature.
  await act("applications", "remove",
            { application: CONFIDENTIAL, attribute: "appRequiredRole",
              value: "ALL_APPLICATIONS" }, "cleared the confidential client");
  await act("applications", "remove",
            { application: PUBLIC_CLIENT, attribute: "appRequiredRole",
              value: "ALL_APPLICATIONS" }, "cleared the public client");
  await act("applications", "add",
            { application: CONFIDENTIAL, attribute: "appRequiredRole",
              value: "ALL_AUTHENTICATED_APPLICATIONS" },
            "required authentication of the confidential client");
  await act("applications", "add",
            { application: PUBLIC_CLIENT, attribute: "appRequiredRole",
              value: "ALL_UNAUTHENTICATED_APPLICATIONS" },
            "required non-authentication of the public client");

  // POSITIVE: the confidential client, presenting its secret.
  const withSecret = await clientCredentials(CONFIDENTIAL, CLIENT_SECRET);
  check("a confidential client that PRESENTS its secret is authenticated",
        function () {
    assert.strictEqual(withSecret.status, 200,
      "it holds ALL_AUTHENTICATED_APPLICATIONS and should be issued a " +
      "token; it answered " + withSecret.status + " " +
      String(withSecret.text).slice(0, 300));
  });

  // NEGATIVE: the same client, same entry, same requirement — and no secret.
  // Nothing about the CONFIGURATION differs between these two requests, which
  // is what makes this the strongest assertion in the file: the only variable
  // is whether the client authenticated on this call.
  const withoutSecret = await clientCredentials(CONFIDENTIAL, null);
  check("and the SAME client without it is refused", function () {
    assert.ok(withoutSecret.status >= 400,
      "the only difference between this request and the one above is the " +
      "credential, so a token here would mean the gate is not reading the " +
      "client's authentication at all. It answered " + withoutSecret.status +
      " " + String(withoutSecret.text).slice(0, 300));
  });
  if (PRODUCT) {
    check("in PRODUCT mode it is refused as a CLIENT, before any role",
          function () {
      assert.strictEqual(withoutSecret.body && withoutSecret.body.error,
        "invalid_client", "it answered error=" +
        JSON.stringify(withoutSecret.body && withoutSecret.body.error));
    });
  } else {
  check("with access_denied rather than a client-authentication error",
        function () {
    assert.strictEqual(withoutSecret.body && withoutSecret.body.error,
      "access_denied",
      "RFC 9700 mode is off, so nothing REQUIRED this client to " +
      "authenticate — it was refused for the ROLE it therefore does not " +
      "hold, and invalid_client here would mean the mode had been turned on " +
      "underneath this test. It answered " +
      JSON.stringify(withoutSecret.body && withoutSecret.body.error));
    assert.ok(/ALL_AUTHENTICATED_APPLICATIONS/
                .test(String(withoutSecret.body.error_description)),
      "and should name the role; it said " +
      JSON.stringify(withoutSecret.body.error_description));
  });
  check("and the sentence says it holds the UNAUTHENTICATED one instead",
        function () {
    assert.ok(/ALL_UNAUTHENTICATED_APPLICATIONS/
                .test(String(withoutSecret.body.error_description)),
      "a confidential client that did not present its secret is, on this " +
      "request, an unauthenticated application — which is the fact the two " +
      "roles split on. It said " +
      JSON.stringify(withoutSecret.body.error_description));
  });
  }

  // A WRONG SECRET IS NOT AN AUTHENTICATED CLIENT. The permissive failure this
  // guards against is an observation that reports "a credential was sent"
  // rather than "a credential verified".
  const wrongSecret = await clientCredentials(CONFIDENTIAL, "not-the-secret");
  check("a WRONG secret does not make it authenticated either", function () {
    assert.ok(wrongSecret.status >= 400,
      "presenting a credential is not the same as proving one. It answered " +
      wrongSecret.status + " " + String(wrongSecret.text).slice(0, 300));
  });

  // POSITIVE: the public client, which holds the unauthenticated role.
  const publicClient = await clientCredentials(PUBLIC_CLIENT, null);
  if (PRODUCT) {
    check("in PRODUCT mode a PUBLIC client is refused client_credentials, so " +
          "ALL_UNAUTHENTICATED_APPLICATIONS is never reached", function () {
      assert.strictEqual(publicClient.body && publicClient.body.error,
        "unauthorized_client", "it answered " + publicClient.status + " " +
        String(publicClient.text).slice(0, 300));
    });
  } else check("a PUBLIC client holds ALL_UNAUTHENTICATED_APPLICATIONS", function () {
    assert.strictEqual(publicClient.status, 200,
      "a public client proves nothing and that is correct rather than a " +
      "failure, so it holds this role; it answered " + publicClient.status +
      " " + String(publicClient.text).slice(0, 300));
  });

  // NEGATIVE: the confidential client, authenticated, against the application
  // that wants an UNauthenticated one.
  await act("applications", "remove",
            { application: CONFIDENTIAL, attribute: "appRequiredRole",
              value: "ALL_AUTHENTICATED_APPLICATIONS" },
            "cleared the confidential client again");
  await act("applications", "add",
            { application: CONFIDENTIAL, attribute: "appRequiredRole",
              value: "ALL_UNAUTHENTICATED_APPLICATIONS" },
            "required non-authentication of the confidential client");
  const confidentialRefused = await clientCredentials(CONFIDENTIAL,
                                                      CLIENT_SECRET);
  check("and an AUTHENTICATED client is refused by the unauthenticated role",
        function () {
    assert.ok(confidentialRefused.status >= 400,
      "the mirror of the case above: a client that proved who it is does " +
      "NOT hold ALL_UNAUTHENTICATED_APPLICATIONS. It answered " +
      confidentialRefused.status + " " +
      String(confidentialRefused.text).slice(0, 300));
    assert.strictEqual(confidentialRefused.body &&
                       confidentialRefused.body.error, "access_denied",
      "it answered error=" +
      JSON.stringify(confidentialRefused.body &&
                     confidentialRefused.body.error));
  });
  log.debug("Leaving theApplicationAuthenticationSplit().");
}

// ---------------------------------------------------------------------------
// 7. THE OFF SWITCH, which is the way back if any of the above locks something
//    out — and the assertion that this feature is a MODE and not a rewrite.
// ---------------------------------------------------------------------------
async function turningItOff() {
  log.debug("Entering turningItOff().");
  log.info("=== 7. roles.enforceIssuance off ===");

  // The confidential client is still narrowed to a role it does not hold from
  // section 6, so it is refused right now. That is the state this section
  // needs and it is asserted rather than assumed.
  const before = await clientCredentials(CONFIDENTIAL, CLIENT_SECRET);
  check("it is refused while enforcement is on", function () {
    assert.ok(before.status >= 400,
      "section 6 left this client narrowed to a role it does not hold, so " +
      "it should still be refused; it answered " + before.status);
  });

  await setSetting("roles.enforceIssuance", false);
  const after = await clientCredentials(CONFIDENTIAL, CLIENT_SECRET);
  check("and issued the moment enforcement is turned off", function () {
    assert.strictEqual(after.status, 200,
      "turning roles.enforceIssuance off stops the question being asked at " +
      "all, which is the way back when a requirement locks something out. " +
      "It answered " + after.status + " " + String(after.text).slice(0, 300));
  });

  // AND THE PERSON TOO, at a different door, because the setting is one switch
  // over nine issuance sites and a section that only proved it at the token
  // endpoint would not have shown that.
  const declined = await arriveAt(APP_AUTH_USERS, "anonymous", "o1");
  const nowAllowed = verdictOf(await declined.browser.go("GET",
                                 authorizeUrl(APP_AUTH_USERS, "o1")));
  check("and so is the unauthenticated session section 3 refused", function () {
    assert.ok(nowAllowed.permitted,
      "the same request section 3 saw refused should now be permitted, at a " +
      "different door from the one above — one switch, nine sites. It " +
      "answered " + nowAllowed.where);
  });

  await setSetting("roles.enforceIssuance", true);
  const again = await clientCredentials(CONFIDENTIAL, CLIENT_SECRET);
  check("and refused again when it is turned back on", function () {
    assert.ok(again.status >= 400,
      "the switch has to work both ways or the section above proved only " +
      "that something changed; it answered " + again.status);
  });
  log.debug("Leaving turningItOff().");
}

// ---------------------------------------------------------------------------
// THE RUN.
// ---------------------------------------------------------------------------
async function test() {
  log.debug("Entering test().");
  log.info("Driving the six built-in roles at " + base);

  // A SERVICE THAT IS NOT THERE IS A FAILURE AND NOT A SKIP.
  const status = await fetchJson(base + "/admin-api/status");
  assert.strictEqual(status.status, 200,
    "GET /admin-api/status answered " + status.status + " at " + base +
    ". This job needs the mock and nothing else.");

  PRODUCT = await facts.isProduct(base + "/admin-api");
  log.info("The service is in " + (PRODUCT ? "PRODUCT" : "development") +
           " mode.");
  await createTheRealm();
  try {
    await buildTheWorld();
    await everybody();
    await theUnauthenticatedSession();
    await allAuthenticatedUsers();
    await allUnauthenticatedUsers();
    await allApplications();
    await theApplicationAuthenticationSplit();
    await turningItOff();
  } finally {
    await theRealmIsLeftBehind();
  }

  // A FLOOR ON THE COUNT, for the reason sts_admin_console.js gives: a section
  // that stops being called takes its assertions with it and the run still
  // says "passed".
  assert.ok(checks >= 28,
    "only " + checks + " checks ran. This file makes about thirty against a " +
    "healthy service, so a count this low means a SECTION STOPPED BEING " +
    "CALLED rather than that the feature got simpler.");
  log.info(checks + " checks passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_roles_builtin")
  .description("Drive the six BUILT-IN roles of the mock STS, in a throwaway " +
      "trust realm: EVERYBODY admitting both a signed-in and an " +
      "unauthenticated session, the two user roles splitting on whether " +
      "anybody authenticated, ALL_APPLICATIONS refusing a person, and the " +
      "two application roles splitting on whether the client proved who it " +
      "is — with RFC 9700 mode off.")
  .addOption(new Option("-u, --url <url>", "base url of the STS under test")
      .default(base))
  .parse(process.argv);
base = String(program.opts().url || base).replace(/\/+$/, "");

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
