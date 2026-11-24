// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: post_login_kinds.ts
//
// ---------------------------------------------------------------------------
// THE POST-LOGIN ACTIVITIES THERE ARE, AND WHAT EACH ONE MUST ANSWER (#2009
// P1, design X1).
//
// Until #2009 there was one post-login activity, `pqc-passkey-migration`
// (#1096), and its id was written in three places: the policy's `activity`
// row, the started activities' list (#1111) and the report's filter
// (#1110). #2009 adds activities for the other credentials a person's
// token carries (#1955): the mail-encryption key (OpenPGP, S/MIME) and the
// PIV certificates. So this file is the ONE list, and what an activity must
// answer to be asked at a sign-in.
//
// **A CLOSED TABLE, NOT A HOOK.** Each row names its activity, its exposure
// (the order a sign-in asks in, below) and the module that answers for it.
// The passkey activity's answers are `common/post_login.ts`'s own (it was
// the whole of that module until #2009), so its row names no module; a
// later activity's row names a module that `post_login.ts` requires LAZILY
// the first time it asks, so this leaf closes no cycle and nobody has to
// remember to register anything — rule 3e's test, failed both ways round:
// `post_login.ts` requiring each activity's module at load would load
// `openpgp_keys`, `piv_enrolment` and `cert_enrollment` at its own place in
// the require order, and each of them requiring `post_login.ts` to register
// would close a cycle through the credential store. A row in a table that
// is read lazily has neither cost, and an activity missing from it is
// missing everywhere at once rather than from one caller.
//
// **EXPOSURE ORDERS THE ASKING** (design X3). When several activities are
// due at one sign-in, the required ones come first, then by how the
// credential is exposed to a quantum adversary:
//
//   decrypt-later  An ENCRYPTION key: what is encrypted to it today is
//                  readable once it falls (harvest now, decrypt later), so
//                  the damage is done before the adversary exists.
//   forgery        A signature or authentication key, or a CA's signature
//                  over a certificate: forgeable only once the adversary
//                  exists, so its migration must be finished before then.
//   other          An activity that is not a post-quantum migration.
//
// and then by this table's order.
//
// A LIBRARY (rule 3) AND A LEAF: it requires `helpers` only.
// ---------------------------------------------------------------------------

import helpers = require('./helpers');

const { log } = helpers;

/**
 * How an activity's credential is exposed: the order a sign-in asks in.
 */
type Exposure = 'decrypt-later' | 'forgery' | 'other';

/**
 * One row of the table.
 */
interface KindRow {
  // The activity's id: on the progress row's key, a started activity, the
  // audit rows' `activity`, the report's filter.
  id: string;
  exposure: Exposure;
  // The module that answers for it, relative to this directory, required
  // lazily by `post_login.ts`; '' where `post_login.ts` answers itself.
  module: string;
  // Whether an administrator may START it (#1111): mail its people. Only
  // the passkey migration until #2009's P4 gives the started activities,
  // their mail and their report the other activities' words.
  startable: boolean;
}

/**
 * What a post-login activity answers, for `post_login.ts` to ask it at a
 * sign-in. The module a row names exports one, as `kind`; `post_login.ts`
 * declares the same shape for what it asks, since this module exports its
 * class alone.
 */
interface PostLoginKind {
  id: string;
  exposure: Exposure;
  /**
   * Whether the selected profile's rows turn this activity on.
   */
  enabledIn(profile: Record<string, any>): boolean;
  /**
   * The profile's rows with this activity turned on: what a running
   * started activity asks under (it overrides only the switch).
   */
  turnedOn(profile: Record<string, any>): Record<string, any>;
  /**
   * Skip's length and the allotted time, from this activity's rows.
   */
  timing(rules: Record<string, any>): { snoozeDays: number;
                                        graceDays: number };
  /**
   * Why this person is due it under these rules, or null where they are
   * not — computed from their credentials, never from the progress row,
   * and null where the realm cannot make what it asks for.
   */
  due(username: string, rules: Record<string, any>,
      application: string): { reason: string; enforceable: boolean;
                              method: string; fallback: string;
                              [fact: string]: any } | null;
}

/**
 * The passkey migration's id (#1096).
 */
const PQC_PASSKEY_MIGRATION = 'pqc-passkey-migration';

/**
 * The mail-encryption migration's id (#2009 P2): OpenPGP and S/MIME, one
 * activity (rcbj's D1).
 */
const PQC_MAIL_ENCRYPTION = 'pqc-mail-encryption';

/**
 * Every post-login activity, in the order a sign-in asks those of one
 * exposure.
 */
const KINDS: readonly KindRow[] = Object.freeze([
  Object.freeze({ id: PQC_PASSKEY_MIGRATION, exposure: 'forgery' as Exposure,
                  module: '', startable: true }),
  // #2009 P2: `common/post_login_mail.ts` answers for it.
  Object.freeze({ id: PQC_MAIL_ENCRYPTION,
                  exposure: 'decrypt-later' as Exposure,
                  module: './post_login_mail', startable: false })
]);

/**
 * The exposures, in the order a sign-in asks them.
 */
const EXPOSURE_ORDER: readonly Exposure[] =
  Object.freeze(['decrypt-later', 'forgery', 'other'] as Exposure[]);

/**
 * The post-login activities there are (#2009): one list.
 */
class PostLoginKinds {
  /**
   * The passkey migration's id.
   */
  static readonly PQC_PASSKEY_MIGRATION = PQC_PASSKEY_MIGRATION;
  /**
   * The mail-encryption migration's id (#2009 P2).
   */
  static readonly PQC_MAIL_ENCRYPTION = PQC_MAIL_ENCRYPTION;
  /**
   * The table.
   */
  static readonly KINDS = KINDS;
  /**
   * The exposures, in asking order.
   */
  static readonly EXPOSURE_ORDER = EXPOSURE_ORDER;

  /**
   * Every activity's id, in the table's order.
   *
   * @returns the ids
   */
  static ids(): string[] {
    log.debug("Entering PostLoginKinds.ids().");
    const out = KINDS.map(function (row) {
      return row.id;
    });
    log.debug("Leaving PostLoginKinds.ids(). " + out.length);
    return out;
  }

  /**
   * The activities an administrator may start (#1111), in the table's
   * order: the passkey migration until #2009's P4.
   *
   * @returns the ids
   */
  static startableIds(): string[] {
    log.debug("Entering PostLoginKinds.startableIds().");
    const out = KINDS.filter(function (row) {
      return row.startable === true;
    }).map(function (row) {
      return row.id;
    });
    log.debug("Leaving PostLoginKinds.startableIds(). " + out.length);
    return out;
  }

  /**
   * One activity's row.
   *
   * @param id - the activity
   * @returns its row, or null where there is no such activity
   */
  static rowOf(id: string): KindRow | null {
    log.debug("Entering PostLoginKinds.rowOf().");
    const out = KINDS.filter(function (row) {
      return row.id === String(id || '');
    })[0] || null;
    log.debug("Leaving PostLoginKinds.rowOf(). " + (out ? out.id : 'None.'));
    return out;
  }

  /**
   * Where an exposure falls in the asking order; last for one not listed.
   *
   * @param exposure - an activity's exposure
   * @returns its rank, from 0
   */
  static exposureRank(exposure: string): number {
    log.debug("Entering PostLoginKinds.exposureRank().");
    const at = EXPOSURE_ORDER.indexOf(exposure as Exposure);
    log.debug("Leaving PostLoginKinds.exposureRank().");
    return at < 0 ? EXPOSURE_ORDER.length : at;
  }

  /**
   * Checks that a module's answer is a whole activity for its row: every
   * method a function, and its id and exposure the row's. A half-made one
   * would be asked and answer nothing, so it is refused whole.
   *
   * @param row - the table's row
   * @param kind - what the row's module exported as `kind`
   * @returns the problem, or '' where it is whole
   */
  static problemWith(row: KindRow, kind: any): string {
    log.debug("Entering PostLoginKinds.problemWith().");
    let out = '';
    if (!kind || typeof kind !== 'object') {
      out = 'exports no kind';
    } else if (kind.id !== row.id) {
      out = 'answers for "' + String(kind.id) + '", not "' + row.id + '"';
    } else if (kind.exposure !== row.exposure) {
      out = 'gives its exposure as "' + String(kind.exposure) +
            '", not "' + row.exposure + '"';
    } else {
      const missing = ['enabledIn', 'turnedOn', 'timing', 'due']
        .filter(function (name) {
          return typeof kind[name] !== 'function';
        });
      out = missing.length ? 'has no ' + missing.join(', ') : '';
    }
    log.debug("Leaving PostLoginKinds.problemWith(). " + (out || 'Whole.'));
    return out;
  }
}

export = PostLoginKinds;
