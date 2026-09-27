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
//
// THE DIGEST IS WEB CRYPTO'S WHERE IT WORKS AND A PLAIN SHA-256 WHERE IT
// DOES NOT (#187). The OpenID conformance suite's browser (HtmlUnit 4.17)
// has a `crypto.subtle` whose `digest` rejects as not implemented, and a
// browser in an insecure context has none at all; the iframe answered
// `error` to both, so a relying party could never learn `unchanged`. The
// hand-written SHA-256 is FIPS 180-4 over the UTF-8 bytes, checked against
// node's in `tests/session_management.js`; the value hashed is not a
// secret the page did not already hold.
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
  '  function utf8(text) {',
  '    var s = unescape(encodeURIComponent(text)), out = [];',
  '    for (var i = 0; i < s.length; i++) { out.push(s.charCodeAt(i)); }',
  '    return out;',
  '  }',
  '  var K = [',
  '    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,',
  '    0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,',
  '    0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,',
  '    0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,',
  '    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,',
  '    0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,',
  '    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,',
  '    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,',
  '    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,',
  '    0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,',
  '    0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,',
  '    0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,',
  '    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];',
  '  function sha256(bytes) {',
  '    var h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,',
  '             0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];',
  '    var m = bytes.slice(), bits = bytes.length * 8, w = [], i, j;',
  '    m.push(0x80);',
  '    while (m.length % 64 !== 56) { m.push(0); }',
  '    for (i = 7; i >= 0; i--) {',
  '      m.push(i > 3 ? 0 : (bits >>> (i * 8)) & 0xff);',
  '    }',
  '    function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }',
  '    for (j = 0; j < m.length; j += 64) {',
  '      for (i = 0; i < 64; i++) {',
  '        if (i < 16) {',
  '          w[i] = (m[j + i * 4] << 24) | (m[j + i * 4 + 1] << 16) |',
  '                 (m[j + i * 4 + 2] << 8) | m[j + i * 4 + 3];',
  '        } else {',
  '          var s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^',
  '                   (w[i - 15] >>> 3);',
  '          var s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^',
  '                   (w[i - 2] >>> 10);',
  '          w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;',
  '        }',
  '      }',
  '      var a = h[0], b = h[1], c = h[2], d = h[3],',
  '          f = h[4], g = h[5], k = h[6], l = h[7];',
  '      for (i = 0; i < 64; i++) {',
  '        var t1 = (l + (rotr(f, 6) ^ rotr(f, 11) ^ rotr(f, 25)) +',
  '                  ((f & g) ^ (~f & k)) + K[i] + w[i]) | 0;',
  '        var t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) +',
  '                  ((a & b) ^ (a & c) ^ (b & c))) | 0;',
  '        l = k; k = g; g = f; f = (d + t1) | 0;',
  '        d = c; c = b; b = a; a = (t1 + t2) | 0;',
  '      }',
  '      h[0] = (h[0] + a) | 0; h[1] = (h[1] + b) | 0;',
  '      h[2] = (h[2] + c) | 0; h[3] = (h[3] + d) | 0;',
  '      h[4] = (h[4] + f) | 0; h[5] = (h[5] + g) | 0;',
  '      h[6] = (h[6] + k) | 0; h[7] = (h[7] + l) | 0;',
  '    }',
  '    var out = [];',
  '    for (i = 0; i < 8; i++) {',
  '      out.push((h[i] >>> 24) & 0xff, (h[i] >>> 16) & 0xff,',
  '               (h[i] >>> 8) & 0xff, h[i] & 0xff);',
  '    }',
  '    return out;',
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
  '    var salt = sessionState.slice(dot + 1);',
  '    var input = clientId + " " + e.origin + " " + browserState() + " " +',
  '                salt;',
  '    var decide = function (digest) {',
  '      answer(b64url(digest) + "." + salt === sessionState ?',
  '             "unchanged" : "changed");',
  '    };',
  '    var byHand = function () { decide(sha256(utf8(input))); };',
  '    var subtle = window.crypto && window.crypto.subtle;',
  '    var pending = null;',
  '    try {',
  '      pending = subtle && typeof TextEncoder === "function" ?',
  '        subtle.digest("SHA-256", new TextEncoder().encode(input)) : null;',
  '    } catch (err) {',
  '      pending = null;',
  '    }',
  '    if (pending && typeof pending.then === "function") {',
  '      pending.then(decide, byHand);',
  '    } else {',
  '      byHand();',
  '    }',
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
