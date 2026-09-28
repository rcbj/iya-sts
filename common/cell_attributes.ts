// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: cell_attributes.ts
//
// ---------------------------------------------------------------------------
// A PERSON'S ATTRIBUTES, ASKED OF THEIR HOME (#98 section 5's
// `fetch-attributes`, 2026-09-28).
//
// Some tokens are ABOUT a person who is not the one presenting a credential:
// a WS-Trust OnBehalfOf or ActAs is served at the REQUESTER's home cell
// (`ws-trust/wstrust.ts`), and the person it names may be homed in another.
// That cell's directory does not hold them, so the token about them — its
// subject, its configured attributes, the delegation policy's two flags on
// their entry, the issuance policy's roles — would be made from nothing.
// This operation is how the serving cell gets what the token needs, and
// nothing more:
//
//   * **HOME DECIDES, AND DECIDES BY POLICY.** The home cell answers only
//     when the transfer policy releases the person's attributes to the asking
//     cell (`cell_transfer.ts`'s `releaseDecision()`, purpose `attributes`).
//     No decision available — the module absent, or throwing — is a refusal.
//   * **WHAT LEAVES IS CREDENTIAL-FREE**: `cell_sessions.ts`'s projection of
//     the entry (`projectionOf()` — `credentialFree()` and the groups home
//     says they are in). No password hash, second-factor secret or key.
//   * **IT IS HELD FOR ONE SYNCHRONOUS CALL AND NEVER STORED**
//     (`withPerson()`): the projection is put into this process's directory, the caller's
//     function runs, and it is taken out again before anything else in this
//     process can run — so no other request here ever reads the person as a
//     resident, and no row, store or cache keeps them. A person already held
//     here as a projection (a session exported here) is read as they are and
//     left alone.
//   * **FAIL-CLOSED (D6).** Home refusing, or not reachable, is the caller's
//     refusal: `fetch()` answers `{ ok: false, code, why }` and never throws.
//
// A LIBRARY with no route. Its operation is registered at load, which binds
// and dials nothing (`cell_channel.ts` keeps a map).
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
import realms = require('./realms');
import cells = require('./cells');
import errorCodes = require('./error_codes');

const log = bunyan.createLogger({ name: 'sts-cell-attributes' });

// The inter-cell operation.
const FETCH_OP = 'fetch-attributes';

/**
 * What `fetch()` answers: the projection, or why there is none.
 */
interface Fetched {
  ok: boolean;
  projection?: any;
  code?: string;
  why?: string;
}

/**
 * A person's credential-free attributes, asked of their home cell and held
 * for one call.
 */
class CellAttributes {
  /**
   * Answers another cell's `fetch-attributes`, at the person's home.
   *
   * @param body - `{ realm, name }`
   * @param peer - the asking cell
   * @returns `{ released: true, projection }` or `{ released: false, why }`
   * @throws an Error for an unknown realm
   */
  static answer(body: any, peer: string): any {
    log.debug("Entering CellAttributes.answer(). from " + peer);
    const realmId = String((body && body.realm) || '');
    const realm = realmId ? realms.get(realmId)
                          : realms.get(realms.DEFAULT_ID);
    if (!realm) {
      log.debug("Leaving CellAttributes.answer(). No realm.");
      throw new Error('no such realm');
    }
    let decision = { allowed: false, why: 'no release decision is available' };
    try {
      const answer = require('./cell_transfer').releaseDecision({
        realm: realmId, homeCell: cells.id(), servingCell: String(peer || ''),
        purpose: 'attributes' });
      decision = { allowed: !!(answer && answer.allowed),
                   why: String((answer && answer.why) || '') };
    } catch (e) {
      log.debug("Caught in CellAttributes.answer(): " +
                ((e && e.message) || e));
      // No transfer policy in this build, or one that failed: a refusal.
    }
    if (!decision.allowed) {
      log.info('cells: the attributes of a person homed here were NOT ' +
               'released to cell "' + peer + '": ' + (decision.why ||
               'the release policy refused') + '.');
      log.debug("Leaving CellAttributes.answer(). Not released.");
      return { released: false, why: decision.why ||
               'the release policy refused' };
    }
    let projection = null;
    realms.run(realm, function () {
      projection = require('./cell_sessions').projectionOf(
        String(body.name || ''));
    });
    if (!projection) {
      log.debug("Leaving CellAttributes.answer(). Not homed here.");
      return { released: false, why: 'the person is not homed here' };
    }
    log.info('cells: the credential-free attributes of a person homed here ' +
             'were released to cell "' + peer + '" (' + decision.why + ').');
    log.debug("Leaving CellAttributes.answer(). Released.");
    return { released: true, projection: projection };
  }

  /**
   * Asks a person's home cell for their credential-free attributes.
   *
   * @param realmId - the realm
   * @param name - the person's login name
   * @param home - their home cell
   * @returns a promise of `{ ok: true, projection }`, or `{ ok: false,
   *   code, why }` when home refused or could not be reached; never rejects
   */
  static fetch(realmId: string, name: string, home: string): Promise<Fetched> {
    log.debug("Entering CellAttributes.fetch(). home=" + home);
    const channel = require('./cell_channel');
    log.debug("Leaving CellAttributes.fetch().");
    return channel.call(home, FETCH_OP, { realm: realmId, name: name })
      .then(function (answer: any): Fetched {
        if (!answer || !answer.released || !answer.projection ||
            String(answer.projection.home || '') !== home) {
          log.warn(errorCodes.tag('STS-CELL-0124') + 'cells: cell "' + home +
                   '" did not release the attributes of a person homed ' +
                   'there: ' + String((answer && answer.why) ||
                                      'no projection') + '.');
          return { ok: false, code: 'STS-CELL-0124',
                   why: String((answer && answer.why) ||
                               'the home cell released nothing') };
        }
        const cellSessions = require('./cell_sessions');
        const projection = Object.assign({}, answer.projection, {
          attributes: cellSessions.credentialFree(
            answer.projection.attributes || {}) });
        return { ok: true, projection: projection };
      }, function (err: any): Fetched {
        log.warn(errorCodes.tag('STS-CELL-0125') + 'cells: cell "' + home +
                 '" could not be asked for the attributes of a person ' +
                 'homed there (' + ((err && err.message) || err) + ').');
        return { ok: false, code: 'STS-CELL-0125',
                 why: 'the person\'s home could not be reached' };
      });
  }

  /**
   * Runs a SYNCHRONOUS function with a fetched projection in this process's
   * directory, and takes it out again before returning — thrown or not.
   *
   * @param realmId - the realm
   * @param projection - what `fetch()` answered
   * @param fn - the function; it must not return before it is done
   * @returns what `fn` returns
   */
  static withPerson<T>(realmId: string, projection: any, fn: () => T): T {
    log.debug("Entering CellAttributes.withPerson().");
    const cellSessions = require('./cell_sessions');
    cellSessions.CellSessions.materialize(realmId, projection);
    try {
      const out = fn();
      log.debug("Leaving CellAttributes.withPerson().");
      return out;
    } finally {
      cellSessions.CellSessions.dematerialize(realmId, projection);
    }
  }
}

require('./cell_channel').registerOp(FETCH_OP,
  function (body: any, ctx: any) {
    return CellAttributes.answer(body, String((ctx && ctx.peer) || ''));
  });

/**
 * A person's credential-free attributes asked of their home cell (#98
 * section 5): the `fetch-attributes` operation and the one-call hold. A
 * library: no route.
 * @namespace
 */
export = {
  CellAttributes: CellAttributes,
  FETCH_OP: FETCH_OP,
  answer: CellAttributes.answer,
  fetch: CellAttributes.fetch,
  withPerson: CellAttributes.withPerson
};
