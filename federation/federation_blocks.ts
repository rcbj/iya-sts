// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: federation_blocks.ts
//
// ===========================================================================
// A PARTNER'S STOP ON ONE PERSON, THROUGH ONE RELATIONSHIP (#373, 2026-10-01).
//
// A partner identity provider that tells this realm, over Shared Signals,
// that a person's account is DISABLED at its end has said something about
// the sign-ins IT vouches for, and nothing about the rest. rcbj's decision
// on #373: the answer is to refuse that person's sign-ins THROUGH THAT
// RELATIONSHIP — their local password, their security key and every other
// partner keep working — and to end the sessions that partner started. The
// partner's `account-enabled` lifts it; an administrator can lift it on the
// relationship's page. Locking the whole account (`pwdAccountLockedTime`)
// would have let any partner switch a person off everywhere, which is more
// than its own statement covers.
//
// So this is a store of (relationship, person) pairs, per realm, persisted
// in the cell tier (it names a person), and the ONE place the pair is kept:
// `ssf/ssf_transmitters.ts` writes it when the `signal-response` policy
// permits `signal-block-relationship`, and `federation_sp.ts`'s
// `subjectDecision()` reads it before any rule (STS-FED-0156).
//
// A LEAF: it requires only the realms and the logger, so the sign-in path
// and the receiver can both require it without either requiring the other.
// ===========================================================================

import helpers = require('../common/helpers');
import realms = require('../common/realms');

type Json = any;

// `<relationship>|<username, lower-cased>` → { relationship, username, at,
// event, jti, by }.
const blocks = realms.map({ persist: 'federation.signalBlocks' });

/**
 * A partner's block on one person's sign-ins through one federation
 * relationship, set by a verified Shared Signals event. A static utility
 * class over one per-realm persisted store.
 */
export = class FederationBlocks {
  // The key of a pair: the username compared as a username is, without case.
  private static keyOf(fedId: string, username: string): string {
    helpers.log.debug("Entering FederationBlocks.keyOf().");
    helpers.log.debug("Leaving FederationBlocks.keyOf().");
    return String(fedId || '') + '|' + String(username || '').toLowerCase();
  }

  /**
   * Blocks a person's sign-ins through a relationship.
   *
   * @param fedId - the relationship
   * @param username - the person
   * @param detail - `event`, `jti` and `by`, for the console
   * @returns whether it was newly blocked
   */
  static block(fedId: string, username: string, detail?: Json): boolean {
    const { log } = helpers;
    log.debug("Entering FederationBlocks.block(). " + fedId);
    const key = FederationBlocks.keyOf(fedId, username);
    const fresh = !blocks.get(key);
    const d = detail || {};
    blocks.set(key, { relationship: String(fedId), username:
                      String(username), at: Date.now(),
                      event: String(d.event || ''), jti: String(d.jti || ''),
                      by: String(d.by || '') });
    log.debug("Leaving FederationBlocks.block(). " + (fresh ? 'New.' :
                                                             'Again.'));
    return fresh;
  }

  /**
   * Lifts a person's block through a relationship.
   *
   * @param fedId - the relationship
   * @param username - the person
   * @returns whether there was one to lift
   */
  static unblock(fedId: string, username: string): boolean {
    const { log } = helpers;
    log.debug("Entering FederationBlocks.unblock(). " + fedId);
    const key = FederationBlocks.keyOf(fedId, username);
    const had = !!blocks.get(key);
    if (had) {
      blocks.delete(key);
    }
    log.debug("Leaving FederationBlocks.unblock(). " + had);
    return had;
  }

  /**
   * Returns a person's block through a relationship.
   *
   * @param fedId - the relationship
   * @param username - the person
   * @returns the row, or null when there is none
   */
  static blockOf(fedId: string, username: string): Json {
    const { log } = helpers;
    log.debug("Entering FederationBlocks.blockOf(). " + fedId);
    const held = blocks.get(FederationBlocks.keyOf(fedId, username));
    log.debug("Leaving FederationBlocks.blockOf(). " + !!held);
    return held ? Object.assign({}, held) : null;
  }

  /**
   * Returns every block in the ambient realm, newest first, narrowed to one
   * relationship when one is named.
   *
   * @param fedId - the relationship, or empty for all
   * @returns the rows, `at` as an ISO time
   */
  static list(fedId?: string): Json[] {
    const { log } = helpers;
    log.debug("Entering FederationBlocks.list().");
    const out: Json[] = [];
    blocks.forEach(function (row: Json): void {
      if (row && (!fedId || row.relationship === fedId)) {
        out.push(Object.assign({}, row, {
          at: new Date(Number(row.at) || 0).toISOString() }));
      }
    });
    out.sort(function (a: Json, b: Json): number {
      return String(b.at).localeCompare(String(a.at));
    });
    log.debug("Leaving FederationBlocks.list(). " + out.length);
    return out;
  }

  /**
   * Lifts every block through a relationship, as deleting it does.
   *
   * @param fedId - the relationship
   * @returns how many were lifted
   */
  static clearRelationship(fedId: string): number {
    const { log } = helpers;
    log.debug("Entering FederationBlocks.clearRelationship(). " + fedId);
    const gone: string[] = [];
    blocks.forEach(function (row: Json, key: string): void {
      if (row && row.relationship === fedId) {
        gone.push(key);
      }
    });
    gone.forEach(function (key: string): void {
      blocks.delete(key);
    });
    log.debug("Leaving FederationBlocks.clearRelationship(). " +
              gone.length);
    return gone.length;
  }
};
