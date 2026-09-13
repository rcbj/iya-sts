"use strict";
//
// File: console_signin.js
//
// ===========================================================================
// SIGNING IN TO THE ADMIN CONSOLE OVER HTTP, THROUGH THE AUTHORIZATION CODE
// FLOW (2026-09-06).
//
// **THIS IS A HELPER AND NOT A JOB.** It has no assertions of its own beyond
// the ones that say the flow did not happen, and nothing in `MANIFEST.js` runs
// it — `random_username.js` and `module_paths.js` are here on the same terms.
//
// ---------------------------------------------------------------------------
// WHY IT EXISTS: THREE JOBS WERE ABOUT TO HOLD THE SAME WALK.
//
// The console used to be reached in three fetches — a gated GET answered 302 to
// `/authn/login?authn=…`, a POST of a username, and a cookie — and two jobs had
// that written out. On 2026-09-06 `/admin` became a RELYING PARTY of this
// service's own authorization server (`common/oidc_rp.js`), so the walk is now
// five hops and two cookies, and a third job would have been a third copy.
//
// Copying it would have been the mistake this repository keeps writing down in
// other words: the copies agree on the day they are made, and the first time
// the flow gains a hop the one nobody edited becomes a job that reports a
// broken console instead of an out-of-date test.
//
// ---------------------------------------------------------------------------
// WHAT THE WALK IS, AND WHY EACH HOP IS ASSERTED RATHER THAN FOLLOWED.
//
//   GET  /admin/<anything>          -> 302/303 /oauth2/authorize?client_id=…
//   GET  /oauth2/authorize          -> 302 /authn/login?authn=…
//   POST /authn/login               -> 303 back to /oauth2/authorize
//   GET  /oauth2/authorize          -> 302 /admin/callback?code=…&state=…
//   GET  /admin/callback            -> 303 wherever the reader was going
//                                      + the console's own session cookie
//
// A `redirect: "follow"` fetch would do all of that silently and would then
// assert that signing in works and NOTHING about which protocol did it. The
// hops are named here so that a job using this helper fails with the hop that
// broke rather than with a 401 five steps later.
//
// **IT KEEPS EVERY COOKIE, BY NAME.** There are two by the end — the sign-on
// session (`sts_session`, the identity provider's) and the console's own
// (`sts_admin`, established from the ID Token) — and the console reads the
// second. A jar that kept only the last `Set-Cookie` seen would work by luck
// and break the day the order changed.
//
// **A GATE THAT IS OFF IS A LEGITIMATE STATE** and is reported rather than
// treated as a pass: no redirect means no session is needed, and the reads a
// job then makes work exactly as they did before any of this existed. That is
// why this answers `null` rather than throwing.
// ===========================================================================

const assert = require("assert");

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'console_signin',
  level: process.env.LOG_LEVEL || 'info' });

// The jar, and the two things a caller does with it.
function jar() {
  log.debug("Entering jar().");
  const held = {};
  log.debug("Leaving jar().");
  return {
    keep: function (response) {
      log.debug("Entering keep().");
      const set = response.headers.getSetCookie
        ? response.headers.getSetCookie() : [];
      set.forEach(function (one) {
        const pair = String(one).split(";")[0];
        const name = pair.split("=")[0];
        const value = pair.slice(name.length + 1);
        // An empty value is a cookie being CLEARED — what a sign-out sends —
        // and it has to remove the entry rather than store an empty one, or
        // the jar goes on presenting a name with nothing after it.
        if (value === "") {
          delete held[name];
        } else {
          held[name] = value;
        }
      });
      log.debug("Leaving keep().");
    },
    header: function () {
      log.debug("Entering header().");
      log.debug("Leaving header().");
      return Object.keys(held).map(function (k) {
        return k + "=" + held[k];
      }).join("; ");
    },
    names: function () {
      log.debug("Entering names().");
      log.debug("Leaving names().");
      return Object.keys(held);
    },
    get: function (name) {
      log.debug("Entering get().");
      log.debug("Leaving get().");
      return held[name] || "";
    }
  };
}

// ---------------------------------------------------------------------------
// THE PERSON WHO SIGNS IN IS CREATED FIRST, WITH A PASSWORD AND THE ATTRIBUTES
// A REAL ACCOUNT CARRIES (2026-09-12).
//
// This walk used to type a name nobody had created and a password equal to it,
// and it worked because development mode checks no password and creates a
// person — with an INVENTED persona on the entry — for any name that signs in.
// Product mode does neither: it verifies the password against the person's own
// entry and invents no `sn`, `mail` or `displayName`. So the account is made
// through `POST /admin-api/users/create` with `invent: false`, its own
// attributes and a password of at least twelve characters, and that is the
// password typed. A name already taken (a second job, or a second run against a
// kept stack) gets the same password SET rather than a second entry, because
// one entry per person is the directory's rule and the sign-in below has to
// present a password that entry holds.
//
// The management API is reached with whatever credential the run's preload
// attaches (`tests/tools/attach-admin-token.js`); nothing here mints one.
// ---------------------------------------------------------------------------
function consolePasswordFor(user) {
  log.debug("Entering consolePasswordFor().");
  log.debug("Leaving consolePasswordFor().");
  return "Console-signin-" + String(user) + "-Passw0rd!";
}

async function ensureConsoleAccount(base, user, say) {
  log.debug("Entering ensureConsoleAccount().");
  const password = consolePasswordFor(user);
  const domain = "console-signin.test";
  async function apiPost(path, payload) {
    log.debug("Entering apiPost().");
    const r = await fetch(base + "/admin-api" + path, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    const raw = await r.text();
    let body = {};
    try {
      body = JSON.parse(raw);
    } catch (e) {
      log.debug("Caught in apiPost(): " + ((e && e.message) || e));
      // Not JSON — an HTML error page. Kept as the raw text for the message.
      body = { raw: raw };
    }
    log.debug("Leaving apiPost().");
    return { status: r.status, body: body };
  }
  const created = await apiPost("/users/create", {
    username: user, invent: false,
    attributes: { cn: "Console " + user, givenName: "Console", sn: String(user),
                  displayName: "Console " + user,
                  mail: String(user) + "@" + domain },
    credential: "password", password: password
  });
  if (created.status === 200 && created.body && created.body.ok) {
    say("[console] created " + user + " with a password and its attributes " +
        "before signing in.");
    log.debug("Leaving ensureConsoleAccount().");
    return password;
  }
  if (created.body && created.body.existing) {
    const set = await apiPost("/users/set-password",
                              { user: user, password: password });
    if (!(set.status === 200 && set.body && set.body.ok)) {
      // NOT A FAILURE. The password this helper derives for a name never
      // changes, so an account an earlier job or run created already holds it
      // — and a password policy with a HISTORY refuses setting the same one
      // again. The sign-in below says soon enough if the password is wrong.
      say("[console] " + user + " already exists and setting its password " +
          "again answered " + set.status + " " +
          JSON.stringify(set.body).slice(0, 200) + "; signing in with the " +
          "password this helper always gives it.");
    }
    log.debug("Leaving ensureConsoleAccount().");
    return password;
  }
  assert.fail("creating the console account " + user + " through POST " +
    "/admin-api/users/create answered " + created.status + " " +
    JSON.stringify(created.body).slice(0, 300));
  log.debug("Leaving ensureConsoleAccount().");
}

// `base` is the service's base URL; `user` is the name to type. `log` is
// optional and is used only to say which of the two states the gate was in.
// Answers the Cookie header to send on console reads, or null when the gate is
// off.
async function signInToTheConsole(base, user, log) {
  const say = (log && log.info) ? log.info.bind(log) : function () {};
  const cookies = jar();

  function absolute(where) {
    return /^https?:\/\//i.test(String(where || ""))
      ? String(where) : base + String(where || "");
  }

  async function hop(where, options) {
    const opts = Object.assign({ redirect: "manual" }, options || {});
    opts.headers = Object.assign({ cookie: cookies.header() },
                                 opts.headers || {});
    const r = await fetch(absolute(where), opts);
    cookies.keep(r);
    return r;
  }

  const gated = await hop("/admin/tokens");
  if (gated.status !== 302 && gated.status !== 303) {
    say("[console] the gate is off (GET /admin/tokens answered " +
        gated.status + " with no redirect), so the reads below need no " +
        "session.");
    return null;
  }

  const toAuthorize = gated.headers.get("location") || "";
  assert.ok(/\/oauth2\/authorize\?/.test(toAuthorize),
    "a console GET with no session should start an AUTHORIZATION REQUEST, " +
    "and it went to " +
    "\"" + toAuthorize + "\". The console signs in as the seeded " +
    "client sts-admin-console; if that entry has been deleted the gate " +
    "answers 503 with the reason rather than redirecting.");
  assert.ok(/client_id=sts-admin-console/.test(toAuthorize),
    "the console's authorization request should name sts-admin-console; it " +
    "was " + toAuthorize);

  const toScreen = await hop(toAuthorize);
  const where = toScreen.headers.get("location") || "";
  const authn = (where.match(/[?&]authn=([^&]+)/) || [])[1];
  assert.ok(authn,
    "the authorization endpoint should send a browser with no sign-on " +
    "session to the sign-in screen carrying the id of the request waiting " +
    "there, and it went to " +
    "\"" + where + "\". Without that id the screen has nothing to " +
    "sign in FOR and refuses the POST.");

  const password = await ensureConsoleAccount(base, user, say);
  const screen = await hop(where);
  const screenHtml = await screen.text();
  const csrf =
    (screenHtml.match(/name="csrf_token" value="([^"]+)"/) || [])[1] || "";

  const signedIn = await hop("/authn/login", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "authn_id=" + encodeURIComponent(authn) +
          "&username=" + encodeURIComponent(user) +
          "&password=" + encodeURIComponent(password) +
          "&action=login" +
          (csrf ? "&csrf_token=" + encodeURIComponent(csrf) : "")
  });
  assert.ok(cookies.get("sts_session"),
    "signing in at /authn/login should set the sign-on session cookie; the " +
    "reply was " + signedIn.status + ". This service checks no password, so " +
    "a refusal here is about the request rather than the credential.");

  // Back through the authorization endpoint — which now has a session — and
  // then the callback, which redeems the code and establishes the console's
  // own session. Bounded, so a redirect loop fails as a loop.
  let at = await hop(signedIn.headers.get("location") || "");
  for (let i = 0; i < 4 && (at.status === 302 || at.status === 303); i++) {
    at = await hop(at.headers.get("location") || "");
  }

  assert.ok(cookies.get("sts_admin"),
    "completing the authorization code flow should establish the CONSOLE's " +
    "own session cookie, and the jar holds [" + cookies.names().join(", ") +
    "]. That cookie is what the console reads: since 2026-09-06 the sign-on " +
    "session alone does not open it, which is the point of the console being " +
    "a relying party rather than a reader of the identity provider's store.");

  say("[console] signed in as " + user + " through the authorization code " +
      "flow; holding " + cookies.names().length + " cookie(s).");
  return cookies.header();
}

module.exports = { signInToTheConsole: signInToTheConsole, jar: jar,
                   ensureConsoleAccount: ensureConsoleAccount,
                   consolePasswordFor: consolePasswordFor };
