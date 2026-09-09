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
// session (`sts_mock_session`, the identity provider's) and the console's own
// (`sts_mock_admin`, established from the ID Token) — and the console reads the
// second. A jar that kept only the last `Set-Cookie` seen would work by luck and
// break the day the order changed.
//
// **A GATE THAT IS OFF IS A LEGITIMATE STATE** and is reported rather than
// treated as a pass: no redirect means no session is needed, and the reads a
// job then makes work exactly as they did before any of this existed. That is
// why this answers `null` rather than throwing.
// ===========================================================================

const assert = require("assert");

// The jar, and the two things a caller does with it.
function jar() {
  const held = {};
  return {
    keep: function (response) {
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
    },
    header: function () {
      return Object.keys(held).map(function (k) {
        return k + "=" + held[k];
      }).join("; ");
    },
    names: function () { return Object.keys(held); },
    get: function (name) { return held[name] || ""; }
  };
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
    "a console GET with no session should start an AUTHORIZATION REQUEST, and " +
    "it went to \"" + toAuthorize + "\". The console signs in as the seeded " +
    "client sts-admin-console; if that entry has been deleted the gate " +
    "answers 503 with the reason rather than redirecting.");
  assert.ok(/client_id=sts-admin-console/.test(toAuthorize),
    "the console's authorization request should name sts-admin-console; it " +
    "was " + toAuthorize);

  const toScreen = await hop(toAuthorize);
  const where = toScreen.headers.get("location") || "";
  const authn = (where.match(/[?&]authn=([^&]+)/) || [])[1];
  assert.ok(authn,
    "the authorization endpoint should send a browser with no sign-on session " +
    "to the sign-in screen carrying the id of the request waiting there, and " +
    "it went to \"" + where + "\". Without that id the screen has nothing to " +
    "sign in FOR and refuses the POST.");

  const screen = await hop(where);
  const screenHtml = await screen.text();
  const csrf =
    (screenHtml.match(/name="csrf_token" value="([^"]+)"/) || [])[1] || "";

  const signedIn = await hop("/authn/login", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "authn_id=" + encodeURIComponent(authn) +
          "&username=" + encodeURIComponent(user) +
          "&password=" + encodeURIComponent(user) +
          "&action=login" +
          (csrf ? "&csrf_token=" + encodeURIComponent(csrf) : "")
  });
  assert.ok(cookies.get("sts_mock_session"),
    "signing in at /authn/login should set the sign-on session cookie; the " +
    "reply was " + signedIn.status + ". This service checks no password, so a " +
    "refusal here is about the request rather than the credential.");

  // Back through the authorization endpoint — which now has a session — and
  // then the callback, which redeems the code and establishes the console's
  // own session. Bounded, so a redirect loop fails as a loop.
  let at = await hop(signedIn.headers.get("location") || "");
  for (let i = 0; i < 4 && (at.status === 302 || at.status === 303); i++) {
    at = await hop(at.headers.get("location") || "");
  }

  assert.ok(cookies.get("sts_mock_admin"),
    "completing the authorization code flow should establish the CONSOLE's " +
    "own session cookie, and the jar holds [" + cookies.names().join(", ") +
    "]. That cookie is what the console reads: since 2026-09-06 the sign-on " +
    "session alone does not open it, which is the point of the console being " +
    "a relying party rather than a reader of the identity provider's store.");

  say("[console] signed in as " + user + " through the authorization code " +
      "flow; holding " + cookies.names().length + " cookie(s).");
  return cookies.header();
}

module.exports = { signInToTheConsole: signInToTheConsole, jar: jar };
