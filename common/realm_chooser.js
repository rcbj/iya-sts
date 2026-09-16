// @ts-check
'use strict';
//
// File: realm_chooser.js
//
// ---------------------------------------------------------------------------
// WHICH REALM TO SIGN IN THROUGH (2026-09-14, ticket #32).
//
// Since #32 a trust realm has administrators of its own, and the admin console
// and the user portal sign a person in through the realm they are reached in —
// `/realm/acme/admin` authenticates against acme's directory and asks acme's
// roster. A person who opens the plain `/admin` or `/portal` of a service with
// realms defined therefore has a question to answer before a sign-in screen
// means anything: WHICH realm are they? This module asks it, for both
// surfaces, so the two cannot come to ask it differently.
//
// **WHEN IT ASKS**, and every condition is what keeps something else working:
//
//   * a GET or HEAD of the surface's ROOT — exactly `/admin` or `/portal` — in
//     the DEFAULT realm, because a deep link already says where the reader was
//     going and a path under a realm prefix has already chosen;
//   * with no session for that surface, which the caller has already decided;
//   * with realms defined (`realms.active()`), because a service with none has
//     only one realm to choose and the page would be a click that does nothing;
//   * and with no `?realm=` — the choice itself, which is what the page's own
//     form submits and what a script or a test names to skip the page.
//
// **HOW IT ASKS** is a `common/mode.js` question: a list of every realm in
// development, a text box for the realm's id in product
// (`mode.listsRealmsBeforeSignIn()`).
//
// **A CHOICE IS A REDIRECT AND NEVER AN ECHO.** The id is looked up in the
// registry and the target is BUILT from the realm's own prefix, the surface's
// fixed root and the service's base — nothing from the request reaches the
// `Location` header, which is `/admin/realm-switch`'s rule for the same shape.
// The default realm's choice is not a redirect at all: the caller goes on to
// sign in right where it is.
//
// A LIBRARY (rule 3): no route. Each surface calls `decide()` from its own gate
// and draws `form()` in its own shell.
// ---------------------------------------------------------------------------

const { log, baseUrlOf } = require('./helpers');
const realms = require('./realms');
const mode = require('./mode');

const SURFACES = {
  admin: { root: '/admin', label: 'the admin console' },
  portal: { root: '/portal', label: 'your account' }
};

function esc(value) {
  // Called per option while one page is drawn, so no Entering/Leaving pair.
  return String(value == null ? '' : value)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// The service's own base with no realm prefix, whichever realm is ambient.
function serviceRoot(req) {
  log.debug("Entering serviceRoot().");
  const withRealm = baseUrlOf(req);
  const prefix = realms.currentPrefix();
  log.debug("Leaving serviceRoot().");
  return prefix && withRealm.slice(-prefix.length) === prefix
    ? withRealm.slice(0, withRealm.length - prefix.length) : withRealm;
}

function queryRealm(req) {
  log.debug("Entering queryRealm().");
  const raw = req && req.query ? req.query.realm : undefined;
  const value = Array.isArray(raw) ? raw[0] : raw;
  log.debug("Leaving queryRealm().");
  return value === undefined || value === null ? null : String(value).trim();
}

// ---------------------------------------------------------------------------
// THE DECISION. `surfaceId` is 'admin' or 'portal'; the caller has already
// found no session. Answers:
//
//   null                              sign in here, as before
//   { kind: 'page', error }           draw the chooser (with a sentence when
//                                     the id asked for is not a realm)
//   { kind: 'redirect', location }    the realm chosen, under its own prefix
// ---------------------------------------------------------------------------
function decide(req, surfaceId) {
  log.debug("Entering decide(). surface=" + surfaceId);
  const surface = SURFACES[surfaceId];
  const method = String((req && req.method) || 'GET').toUpperCase();
  const path = String((req && req.originalUrl) || '').split('?')[0]
    .replace(/\/+$/, '');
  if (!surface || (method !== 'GET' && method !== 'HEAD') ||
      realms.currentId() !== realms.DEFAULT_ID || !realms.active() ||
      path !== surface.root) {
    log.debug("Leaving decide(). Not the chooser's question.");
    return null;
  }
  const asked = queryRealm(req);
  if (asked === null) {
    log.debug("Leaving decide(). Draw the chooser.");
    return { kind: 'page', error: '' };
  }
  if (!asked || asked === realms.DEFAULT_ID) {
    log.debug("Leaving decide(). The default realm; sign in here.");
    return null;
  }
  const realm = realms.get(asked);
  if (!realm || realm.id === realms.DEFAULT_ID) {
    log.debug("Leaving decide(). No such realm.");
    return { kind: 'page',
             error: 'There is no realm with the id "' + asked.slice(0, 64) +
                    '". Check the id and try again.' };
  }
  const location = serviceRoot(req) + realms.prefixOf(realm) + surface.root;
  log.debug("Leaving decide(). To " + location + ".");
  return { kind: 'redirect', location: location };
}

// The form, as a fragment for the surface's own page. No script: a list or a
// text box and a real submit button, posting nothing — a GET of the surface's
// root carrying `realm`, which `decide()` answers.
function form(req, surfaceId, error) {
  log.debug("Entering form(). surface=" + surfaceId);
  const surface = SURFACES[surfaceId] || SURFACES.admin;
  const action = serviceRoot(req) + surface.root;
  const listed = mode.listsRealmsBeforeSignIn();
  const control = listed
    ? '<select id="realmchoice" name="realm">' +
      realms.list().map(function (realm) {
        return '<option value="' + esc(realm.id) + '">' + esc(realm.name) +
          (realm.id === realms.DEFAULT_ID ? ' (the default realm)' : '') +
          '</option>';
      }).join('') + '</select>'
    : '<input type="text" id="realmchoice" name="realm" size="28" ' +
      'autocomplete="organization" placeholder="' +
      esc(realms.DEFAULT_ID) + '" required>';
  log.debug("Leaving form(). " + (listed ? "A list." : "A text box."));
  return (error ? '<div class="err">' + esc(error) + '</div>' : '') +
    '<p>This service hosts more than one trust realm, and each has its own ' +
    'people and its own administrators. Choose the realm you belong to, and ' +
    'you will be asked to sign in there.</p>' +
    '<form method="get" action="' + esc(action) + '">' +
    '<p><label for="realmchoice">Realm</label> ' + control + ' ' +
    '<button type="submit">Continue to ' + esc(surface.label) + '</button>' +
    '</p></form>' +
    (listed ? ''
      : '<p class="note">Your administrator can tell you the id of your ' +
        'realm. The default realm\'s id is <code>' + esc(realms.DEFAULT_ID) +
        '</code>.</p>');
}

module.exports = {
  SURFACES: SURFACES,
  decide: decide,
  form: form
};
