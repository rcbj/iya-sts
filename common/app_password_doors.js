// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: app_password_doors.js
//
// ---------------------------------------------------------------------------
// THE FIVE DOORS AN APP PASSWORD MAY BE SCOPED TO, AS DATA AND NOTHING ELSE
// (#1579).
//
// Each is a place a person's password is taken with no way to ask for more;
// the ids are what a door passes to `credentials.verify()` as `door`, what
// `authn.passwordAloneDoors` lists and what a record's scope names. The table
// was `common/app_passwords.ts`'s, which still decides with it. It is a leaf of
// its own because the model reads it too: `models/lib/api_lib.mjs` writes the
// Account API's `changeAppPasswords` body a `door_<id>` member per row
// (`$membersFrom`), during the image build, where the TypeScript is not yet
// compiled. So a door is added here and nowhere else.
//
// **IT REQUIRES NOTHING**, so that build step can read it; it is data only,
// with no function to log the entry of.
// ---------------------------------------------------------------------------

/**
 * One password-only door.
 *
 * @typedef {Object} AppPasswordDoor
 * @property {string} id - what the door passes as `door`
 * @property {string} label - its name on the page
 * @property {string} what - the credential it takes, in a phrase
 */

/**
 * The five password-only doors an app password may be scoped to: LDAP bind,
 * WS-Trust, SCIM, Shared Signals and EST.
 *
 * @type {AppPasswordDoor[]}
 */
const DOORS = [
  { id: 'ldap', label: 'LDAP bind',
    what: 'an LDAP simple bind on 389 or 636 (RFC 4513)' },
  { id: 'wstrust', label: 'WS-Trust',
    what: 'a WS-Security UsernameToken sent to the security token service' },
  { id: 'scim', label: 'SCIM',
    what: 'HTTP Basic at /scim/v2 (RFC 7617)' },
  { id: 'ssf', label: 'Shared Signals',
    what: 'HTTP Basic at the /ssf endpoints (RFC 7617)' },
  { id: 'est', label: 'EST',
    what: 'HTTP Basic at /.well-known/est (RFC 7030 section 3.2.3)' }
];

/**
 * The ids of the doors, in the table's order.
 *
 * @type {string[]}
 */
const DOOR_IDS = DOORS.map(function (one) {
  return one.id;
});

module.exports = {
  DOORS: DOORS,
  DOOR_IDS: DOOR_IDS
};
