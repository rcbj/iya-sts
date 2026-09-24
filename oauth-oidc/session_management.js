// @ts-check
'use strict';
//
// File: session_management.js
//
// ===========================================================================
// OPENID CONNECT SESSION MANAGEMENT 1.0 (#121, 2026-09-23).
//
// A relying party loads this provider's OP iframe in a hidden iframe, and
// asks it through `postMessage` whether the person's session here is still
// the one it signed them in with — comparing the `session_state` it was given
// on the authentication response with one the iframe computes from the OP
// BROWSER STATE, a value readable by script in this origin. rcbj's answers:
//
// | Asked | Chosen |
// |---|---|
// | Who may frame the iframe | The registered relying parties: every http(s) origin of a redirect URI in the realm — `frame-ancestors` NARROWED, never dropped (`app.framedContentSecurityPolicy()`) |
// | On by default | NO: `oauth2.sessionManagement`, per realm, off. Off means no cookie, no iframe, no `session_state`, no discovery member |
// | The iframe's script | The ninth `script-src 'self'` page, with no button: no markup answers a `postMessage` |
// | Tests | The served script in a node vm with a fake window |
//
// THE BROWSER STATE is a random value on the SESSION ROW (`browserState`),
// minted with every session handle by `authn.ts` — so it changes at sign-in
// and at every re-authentication — and written to the browser as the cookie
// `sts_op_browser_state`, which is NOT HttpOnly (the iframe's script must read
// it) and is `SameSite=None; Secure` (it has to reach an iframe on another
// site's page). It is not a credential: it names nothing and opens nothing.
// A browser with no authenticated session has the EMPTY state, so a
// `prompt=none` answer with no session carries a `session_state` that turns
// `changed` when somebody signs in.
//
// WHERE IT IS WRITTEN: beside every authorization response that carries a
// `session_state` (`oauth2.ts`'s `redirectBack()`), so the two can never be
// out of step; and CLEARED wherever the session cookie is cleared
// (`authn.clearSessionCookie()`), which is every sign-out door.
//
// **WHAT IT CANNOT SEE, SAID ON THE CARD**: a session that EXPIRES, or that an
// administrator ends, leaves the cookie in place, so the iframe answers
// `unchanged` until the relying party next asks the authorization endpoint —
// Back-Channel Logout (#36) is what tells a relying party that. And a browser
// that blocks third-party cookies never sends the cookie to the iframe, so the
// iframe computes with the empty state; that is the specification's own
// limitation in current browsers.
//
// A LEAF (rule 3): `helpers`, `config` and `common/crypto.js`; `applications`
// is required lazily, for `assertion_grant.js`'s reason in #120.
// ===========================================================================

const { log } = require('../common/helpers');
const config = require('../common/config');
const stsCrypto = require('../common/crypto');

const COOKIE = 'sts_op_browser_state';
const IFRAME_PATH = '/oauth2/check_session';
const SCRIPT_PATH = '/oauth2/check_session.js';

// Whether Session Management is on in the ambient realm.
function enabled() {
  log.debug("Entering enabled().");
  log.debug("Leaving enabled().");
  return config.value('oauth2.sessionManagement') === true;
}

// The OP browser state of a session: its `browserState` when somebody is
// signed in to it, and '' otherwise (no session, an arrival session, a
// session minted before this existed).
function browserStateOf(session) {
  log.debug("Entering browserStateOf().");
  const state = session && session.authenticated !== false &&
                session.browserState ? String(session.browserState) : '';
  log.debug("Leaving browserStateOf().");
  return state;
}

// The cookie line that puts `state` in the browser, or clears it for ''.
// `SameSite=None` needs `Secure`, and a plain-HTTP port cannot set one, so
// there it is `Lax` — which no third-party iframe will ever be sent, and the
// card says so. `secure` defaults to the port's own scheme (`global.https`,
// restart-only); a test names it.
function cookieLine(state, secure) {
  log.debug("Entering cookieLine().");
  const onTls = secure === undefined
    ? config.value('global.https') === true : !!secure;
  const tail = onTls ? '; SameSite=None; Secure' : '; SameSite=Lax';
  log.debug("Leaving cookieLine().");
  return state
    ? COOKIE + '=' + state + '; Path=/' + tail
    : COOKIE + '=; Path=/; Max-Age=0' + tail;
}

// Appends the browser-state cookie to a response, beside whatever else it
// sets. Appending, `clearSessionCookie()`'s reason: `res.set()` would throw
// away the session cookie the same response may carry.
function writeCookie(res, state) {
  log.debug("Entering writeCookie().");
  if (res && typeof res.append === 'function') {
    res.append('Set-Cookie', cookieLine(state));
  } else if (res && typeof res.setHeader === 'function') {
    res.setHeader('Set-Cookie', cookieLine(state));
  }
  log.debug("Leaving writeCookie().");
}

// The origin section 3 hashes: the redirect URI's. A private-use scheme or an
// unparseable URI has no web origin, and so no `session_state` — a native
// application has no iframe to ask.
function originOf(redirectUri) {
  log.debug("Entering originOf().");
  let origin = '';
  try {
    const parsed = new URL(String(redirectUri));
    origin = /^https?:$/.test(parsed.protocol) ? parsed.origin : '';
  } catch (e) {
    log.debug("Caught in originOf(): " + ((e && e.message) || e));
    // No origin: no session_state.
    origin = '';
  }
  log.debug("Leaving originOf().");
  return origin;
}

// The `session_state` for one authentication response, or '' where none is
// owed: the feature off, no client, not an OpenID Connect request, or a
// redirect URI with no web origin.
function sessionStateFor(clientId, redirectUri, scope, session) {
  log.debug("Entering sessionStateFor().");
  const origin = originOf(redirectUri);
  const openid = String(scope || '').split(/\s+/).indexOf('openid') >= 0;
  if (!enabled() || !clientId || !origin || !openid) {
    log.debug("Leaving sessionStateFor(). None owed.");
    return '';
  }
  log.debug("Leaving sessionStateFor().");
  return stsCrypto.sessionStateHash(String(clientId), origin,
                                    browserStateOf(session));
}

// Who may frame the iframe: the realm's registered relying parties.
function frameAncestors() {
  log.debug("Entering frameAncestors().");
  const applications = require('../common/applications');
  log.debug("Leaving frameAncestors().");
  return applications.redirectOriginsOfRealm();
}

// The OP iframe itself. The script is a sibling resource, named relatively so
// a realm's prefix carries over; the page carries no inline script.
function iframePage() {
  log.debug("Entering iframePage().");
  log.debug("Leaving iframePage().");
  return '<!doctype html><html lang="en"><head><meta charset="utf-8">' +
    '<title>OP iframe</title></head><body>' +
    '<script src="check_session.js"></script></body></html>';
}

// ---------------------------------------------------------------------------
// THE IFRAME'S SCRIPT, section 3.2. Data served to a browser, so it is
// written as the browser runs it and not in this file's style (the root
// CLAUDE.md: JavaScript inside a string is data).
//
// A message is `client_id + " " + session_state`; the client_id is everything
// before the LAST space, so one with a space still parses. The origin hashed
// is the MESSAGE's origin, which is what binds the answer to the relying
// party that asked. The answer is `changed`, `unchanged` or `error`, posted
// back to that origin only.
// ---------------------------------------------------------------------------
const IFRAME_SCRIPT = [
  '(function () {',
  '  "use strict";',
  '  var NAME = ' + JSON.stringify(COOKIE) + ';',
  '  function browserState() {',
  '    var all = String(document.cookie || "").split(";");',
  '    for (var i = 0; i < all.length; i++) {',
  '      var pair = all[i].replace(/^\\s+/, "");',
  '      if (pair.indexOf(NAME + "=") === 0) {',
  '        return pair.slice(NAME.length + 1);',
  '      }',
  '    }',
  '    return "";',
  '  }',
  '  function b64url(buffer) {',
  '    var bytes = new Uint8Array(buffer), text = "";',
  '    for (var i = 0; i < bytes.length; i++) {',
  '      text += String.fromCharCode(bytes[i]);',
  '    }',
  '    return btoa(text).replace(/\\+/g, "-").replace(/\\//g, "_")',
  '      .replace(/=+$/, "");',
  '  }',
  '  window.addEventListener("message", function (e) {',
  '    var answer = function (text) {',
  '      if (e.source && typeof e.source.postMessage === "function") {',
  '        e.source.postMessage(text, e.origin);',
  '      }',
  '    };',
  '    if (typeof e.data !== "string") { answer("error"); return; }',
  '    var at = e.data.lastIndexOf(" ");',
  '    var clientId = at > 0 ? e.data.slice(0, at) : "";',
  '    var sessionState = at > 0 ? e.data.slice(at + 1) : "";',
  '    var dot = sessionState.lastIndexOf(".");',
  '    if (!clientId || dot <= 0 || dot === sessionState.length - 1) {',
  '      answer("error");',
  '      return;',
  '    }',
  '    if (!window.crypto || !window.crypto.subtle) {',
  '      answer("error");',
  '      return;',
  '    }',
  '    var salt = sessionState.slice(dot + 1);',
  '    var input = clientId + " " + e.origin + " " + browserState() + " " +',
  '                salt;',
  '    window.crypto.subtle.digest("SHA-256",',
  '                                new TextEncoder().encode(input))',
  '      .then(function (digest) {',
  '        answer(b64url(digest) + "." + salt === sessionState ?',
  '               "unchanged" : "changed");',
  '      }, function () { answer("error"); });',
  '  });',
  '})();',
  ''
].join('\n');

module.exports = {
  COOKIE: COOKIE,
  IFRAME_PATH: IFRAME_PATH,
  SCRIPT_PATH: SCRIPT_PATH,
  IFRAME_SCRIPT: IFRAME_SCRIPT,
  enabled: enabled,
  browserStateOf: browserStateOf,
  cookieLine: cookieLine,
  writeCookie: writeCookie,
  originOf: originOf,
  sessionStateFor: sessionStateFor,
  frameAncestors: frameAncestors,
  iframePage: iframePage
};
