// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: directory_secrets.ts
//
// ---------------------------------------------------------------------------
// AN ENTRY'S ROW WITH ITS CREDENTIALS MASKED, FOR EVERY DOOR THAT ANSWERS ONE.
//
// `SECRET_ATTRIBUTES` is written in `models/directory/names.tsp` (#1390) and
// read through `ModelTables.names()`. This is the one function that masks
// those attributes in an answer: every value of one is replaced by one
// sentence, in `attributes`, in `fields` and in an `entry`'s attributes. It
// was `withoutSecrets()` inside `ldap/ldap_server.js` (#446), which every
// `GET /admin-api/ldap/*` answer and the directory reader slot already used.
//
// IT MOVED HERE ON 2026-11-14, because `POST /admin-api/users/create`
// answered the entry it had just created as the directory holds it, AFTER
// the credential step had written to it: the new person's `userPassword`
// scrypt hash, and with `credential: activation` the activation token's
// hash. #444's Rust port found it. `admin-core/admin_actions.ts` cannot
// require `ldap_server.js` — a JavaScript route module, whose routes the
// require would drag forward (root `CLAUDE.md`, rule 1) — so the masking
// lives in a library both can require, and there is still one list and
// one mask.
//
// A LEAF. It requires nothing of this service but `model_tables`, which is
// a leaf too, so it can be required from anywhere without moving a route
// or closing a cycle. It masks in every mode: no answer carries a stored
// credential, development included. What `mode.withholdsDirectorySecrets()`
// governs is the LDAP socket, and that stays in `ldap_server.js`.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
import ModelTables = require('../common/model_tables');

const log = bunyan.createLogger({
  name: 'sts-directory-secrets',
  level: process.env.LOG_LEVEL || process.env.STS_LOG_LEVEL || 'info'
});

// The list is written in models/directory/names.tsp (#1390), lower-cased.
const SECRET_ATTRIBUTES: string[] = ModelTables.names().secret;

// What a masked value reads as. `GET /admin-api/ldap/*` has answered it
// since #446, and the console draws it.
const MASK = '(set — not returned)';

/**
 * The directory's secret attributes, and the mask every answer applies.
 */
class DirectorySecrets {
  static readonly SECRET_ATTRIBUTES = SECRET_ATTRIBUTES;

  static readonly MASK = MASK;

  /**
   * Tells whether an attribute is one the directory never hands out.
   *
   * @param name - the attribute name, in any case
   * @returns true for a name `SECRET_ATTRIBUTES` lists
   */
  static isSecret(name: unknown): boolean {
    // A hot path: a search asks it of every attribute of every entry it
    // answers, so there is no Entering/Leaving pair here, which would
    // drown the log.
    return SECRET_ATTRIBUTES.indexOf(String(name || '').toLowerCase()) !== -1;
  }

  /**
   * A copy of an attribute bag with every secret value masked.
   *
   * @param bag - `{ name: value | values }`
   * @returns the copy
   */
  static masked(bag: Record<string, any>): Record<string, any> {
    log.debug("Entering DirectorySecrets.masked().");
    const copy = Object.assign({}, bag);
    Object.keys(copy).forEach(function (name) {
      if (DirectorySecrets.isSecret(name)) {
        const value = copy[name];
        copy[name] = Array.isArray(value)
          ? value.map(function () {
            return MASK;
          })
          : (value === undefined || value === null || value === ''
            ? value : MASK);
      }
    });
    log.debug("Leaving DirectorySecrets.masked().");
    return copy;
  }

  /**
   * A row with its credentials masked: `attributes`, `fields` and an
   * `entry`'s attributes. The row is not changed; the bags are copies.
   *
   * @param row - an entry's row, or anything carrying one
   * @returns the masked copy
   */
  static withoutSecrets(row: any): any {
    log.debug("Entering DirectorySecrets.withoutSecrets().");
    const out = Object.assign({}, row);
    if (row && row.attributes) {
      out.attributes = DirectorySecrets.masked(row.attributes);
    }
    if (row && row.fields) {
      out.fields = DirectorySecrets.masked(row.fields);
    }
    if (row && row.entry && row.entry.attributes) {
      out.entry = Object.assign({}, row.entry,
        { attributes: DirectorySecrets.masked(row.entry.attributes) });
    }
    log.debug("Leaving DirectorySecrets.withoutSecrets().");
    return out;
  }
}

export = DirectorySecrets;
