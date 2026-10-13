// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: cell_routing.ts
//
// ---------------------------------------------------------------------------
// WHERE A PERSON IS HOMED (#98 D1, 2026-09-28).
//
// A person is homed in one cell and their entry exists only there. The GLOBAL
// routing index (`sts_cell_routing`, kept at the directory flush by
// `persistence/persistence_tiered.js`) is how every other cell finds that
// cell from what a request carries: a login name typed into a form, an LDAP
// bind DN, a Kerberos principal, a SCIM id or a token's subject.
//
// **THE INDEX HOLDS KEYED DIGESTS, NEVER A NAME.** The digest is
// `keystore.keyedDigest('cell-routing', realm \n kind \n value)` under the
// service key every cell holds, so each cell computes the same one and the
// global database — which every cell's region reads — holds nothing a person
// could be recognised by. The same function is the one the flush uses; there
// is one definition of it, `digest()` below, handed to the driver by
// `persistence.js`.
//
// **A PERSON THIS CELL HOLDS IS ANSWERED WITHOUT ASKING THE INDEX**: the
// directory is in memory here, and a question about somebody resident is the
// common case at every door. The index is asked only for a name the local
// directory does not have.
//
// **CREATION ASKS FIRST** (`claimName()`): a console, API or SCIM creation
// claims the login name in the index BEFORE the entry is made, so a name
// homed in another cell is refused with a sentence rather than created twice.
// The flush claims again (it is the one place every person passes) and counts
// the race this check cannot close.
//
// A LIBRARY: no route. Everything it reaches is required lazily.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
import cells = require('./cells');
import errorCodes = require('./error_codes');

const log = bunyan.createLogger({ name: 'sts-cell-routing' });

/**
 * Where people are homed: the digests of the routing index and the questions
 * asked of it.
 */
class CellRouting {
  /**
   * Builds the router. It holds nothing.
   */
  constructor() {
    log.debug("Entering CellRouting.constructor().");
    log.debug("Leaving CellRouting.constructor().");
  }

  /**
   * The keyed digest a routing index row is keyed by.
   *
   * @param realmId - the realm
   * @param kind - 'name' or 'uuid'
   * @param value - the login name (lower-cased here) or the entryUUID
   * @returns the digest, or null without a key-encryption key
   */
  static digest(realmId: string, kind: string, value: string): string | null {
    log.debug("Entering CellRouting.digest().");
    const keystore = require('./keystore');
    log.debug("Leaving CellRouting.digest().");
    return keystore.keyedDigest('cell-routing', String(realmId || '') + '\n' +
                                String(kind) + '\n' +
                                String(value || '').trim().toLowerCase());
  }

  // The tiered driver, or null where the store is not tiered (single-cell
  // mode, which never asks).
  private driver(): any {
    log.debug("Entering CellRouting.driver().");
    const persistence = require('../persistence/persistence');
    const d = typeof persistence.currentDriver === 'function'
      ? persistence.currentDriver() : null;
    log.debug("Leaving CellRouting.driver().");
    return d && d.tiered ? d : null;
  }

  // Is a login name, or an entryUUID, in this cell's own directory? The
  // directory reader is the one the portal and the console use, reached
  // lazily for rule 3e's reason.
  private residentHere(realmId: string, kind: string, value: string): boolean {
    log.debug("Entering CellRouting.residentHere().");
    // A PROJECTION IS NOT A RESIDENT (#98 D4): a person whose session was
    // exported here is in the directory and is homed elsewhere, and a
    // sign-in or a step-up for them still restarts at home.
    if (require('./cell_sessions').isProjected(realmId, kind, value)) {
      log.debug("Leaving CellRouting.residentHere(). A projection.");
      return false;
    }
    let found = false;
    try {
      const helpers = require('./helpers');
      const realms = require('./realms');
      const realm = realms.get(realmId) || realms.get(realms.DEFAULT_ID);
      const run = (fn: () => void) => realm ? realms.run(realm, fn) : fn();
      run(function () {
        // The subject resolver `ldap_server.js` fills: a name answers a
        // subject, and a subject a name, only for an entry held here.
        found = kind === 'uuid'
          ? !!helpers.nameForSubject('urn:uuid:' + value)
          : !!helpers.subjectForName(value);
      });
    } catch (e) {
      log.debug("Caught in CellRouting.residentHere(): " +
                ((e && e.message) || e));
      found = false;
    }
    log.debug("Leaving CellRouting.residentHere(). " + found);
    return found;
  }

  /**
   * Finds the cell a person is homed in.
   *
   * @param realmId - the realm
   * @param kind - 'name' (a login name) or 'uuid' (an entryUUID)
   * @param value - the name or the UUID
   * @returns a promise of the cell id: this cell's when the person is
   *   resident here, another's from the index, or '' when nobody knows them
   */
  homeOf(realmId: string, kind: string, value: string): Promise<string> {
    log.debug("Entering CellRouting.homeOf().");
    if (!cells.isMulti()) {
      log.debug("Leaving CellRouting.homeOf(). Single-cell.");
      return Promise.resolve('');
    }
    if (!value) {
      log.debug("Leaving CellRouting.homeOf(). Nothing to look up.");
      return Promise.resolve('');
    }
    if (this.residentHere(realmId, kind, value)) {
      log.debug("Leaving CellRouting.homeOf(). Resident here.");
      return Promise.resolve(cells.id());
    }
    const d = this.driver();
    const digest = CellRouting.digest(realmId, kind, value);
    if (!d || !digest) {
      log.debug("Leaving CellRouting.homeOf(). No index to ask.");
      return Promise.resolve('');
    }
    log.debug("Leaving CellRouting.homeOf(). Asking the index.");
    return d.routeLookup(realmId, kind, digest).then(function (cell: string) {
      return String(cell || '');
    }, function (err: any) {
      log.warn(errorCodes.tag('STS-CELL-0040') + 'cells: the routing index ' +
               'could not be read (' + ((err && err.message) || err) + '); ' +
               'the request is served here as if the person were unknown.');
      return '';
    });
  }

  /**
   * Claims a login name for a person about to be created in a cell.
   *
   * @param realmId - the realm
   * @param name - the login name
   * @param cellId - the cell the person will be homed in
   * @returns a promise of `{ ok: true }`, or `{ ok: false, cell }` when the
   *   name is already homed in another cell
   */
  claimName(realmId: string, name: string,
            cellId: string): Promise<{ ok: boolean; cell?: string }> {
    log.debug("Entering CellRouting.claimName().");
    const d = this.driver();
    const digest = CellRouting.digest(realmId, 'name', name);
    if (!cells.isMulti() || !d || !digest) {
      log.debug("Leaving CellRouting.claimName(). Nothing to claim.");
      return Promise.resolve({ ok: true });
    }
    log.debug("Leaving CellRouting.claimName().");
    return d.routeClaim(realmId, 'name', digest, cellId).then(function (
        answer: { cell: string; claimed: boolean }) {
      if (answer && answer.cell && answer.cell !== cellId) {
        return { ok: false, cell: answer.cell };
      }
      return { ok: true };
    });
  }

  /**
   * How many people each cell holds, per realm, for `/admin/cells`.
   *
   * @returns a promise of `[{ realm, cell, people }]`, empty where there is
   *   no index
   */
  counts(): Promise<Array<{ realm: string; cell: string; people: number }>> {
    log.debug("Entering CellRouting.counts().");
    const d = this.driver();
    log.debug("Leaving CellRouting.counts().");
    return d ? d.routeCounts() : Promise.resolve([]);
  }
}

const routing = new CellRouting();

/**
 * Where people are homed (#98 D1): the routing index's digests, the lookup
 * of a person's home cell, and the claim a creation makes first. A library:
 * no route.
 * @namespace
 */
export = {
  CellRouting: CellRouting,
  digest: CellRouting.digest,
  homeOf: (realmId: string, kind: string, value: string): Promise<string> =>
    routing.homeOf(realmId, kind, value),
  claimName: (realmId: string, name: string, cellId: string) =>
    routing.claimName(realmId, name, cellId),
  counts: () => routing.counts()
};
