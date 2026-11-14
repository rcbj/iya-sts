// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: passkey_history.ts
//
// ---------------------------------------------------------------------------
// THE `passkeyHistory` SOURCE'S ROWS (#1109).
//
// The passkey report (`common/passkey_report.ts`, #942) is a snapshot, and
// since #1109 its daily recount also writes one row of
// `passkey_report.history` per realm per UTC day: people by kind, passkeys
// by algorithm, by lane and by attestation algorithm, and each named
// passkey profile's population. This file turns those stored rows into the
// catalog's rows (`catalog.ts`, `passkeyHistorySource()`).
//
// ONE STORED DAY IS SEVERAL REPORT ROWS, told apart by `scope`, because the
// query document has one aggregate (`count`) and no pivot: a trend is read
// by filtering on one scope and ordering by `day`.
//
//   realm        one a day: the realm's people by kind and its passkeys;
//   profile      one per named passkey profile: the same numbers over the
//                profile's population, or `counted` false where the row
//                did not count it (past the profiles a row counts, or a
//                population that could not be read);
//   algorithm    one per algorithm and lane: `count` passkeys;
//   lane         one per lane: `count` passkeys;
//   attestation  one per attestation certificate algorithm: `count`
//                passkeys whose attestation that algorithm signed.
//
// THE READ IS THE STORE ALREADY IN MEMORY: at most
// `webauthn.passkeyHistoryDays` rows per realm, each a few dozen numbers,
// so the source is bounded by the retention and never reads the
// directory. `postQuantum` is read off the stored row, which the recount
// derived with the passkey report's own rule (an ML-DSA algorithm), so the
// source and Monitoring → Passkeys cannot disagree.
//
// A LIBRARY (rule 3): it registers nothing, and it reaches
// `common/passkey_report` LAZILY, at the first read, so requiring it moves
// no load-time effect forward. In a file of its own so a source added
// beside it merges cleanly.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');

const { log } = helpers;

/**
 * The scopes one stored day is projected into, in the order they are
 * emitted.
 */
const SCOPES = Object.freeze(['realm', 'profile', 'algorithm', 'lane',
  'attestation']);

// The people columns of a realm or profile row, null on the others.
const PEOPLE = ['people', 'holding', 'postQuantumOnly', 'classicalOnly',
  'both', 'none', 'withPostQuantum'];

/**
 * Projects the passkey history rows into the catalog's rows.
 */
class PasskeyHistoryRows {
  /**
   * The scopes a row may have.
   */
  static readonly SCOPES = SCOPES;

  // A number, or null for anything that is not a finite one.
  private static num(value: unknown): number | null {
    log.debug("Entering PasskeyHistoryRows.num().");
    const n = value === null || value === undefined || value === ''
      ? NaN : Number(value);
    log.debug("Leaving PasskeyHistoryRows.num().");
    return Number.isFinite(n) ? n : null;
  }

  // A row with every field of the source present, null where the scope has
  // no value for it, so a column is never missing from a CSV.
  private static blank(stored: any, scope: string): any {
    log.debug("Entering PasskeyHistoryRows.blank().");
    const out: any = {
      day: String(stored.day || ''),
      countedAt: stored.countedAt ? String(stored.countedAt) : null,
      scope: scope, name: '', coseAlg: null, lane: '', postQuantum: null,
      count: null, postQuantumKeys: null, postQuantumShare: null,
      postQuantumRequired: '', members: null, complete: null,
      counted: true
    };
    PEOPLE.forEach(function (key: string): void {
      out[key] = null;
    });
    log.debug("Leaving PasskeyHistoryRows.blank().");
    return out;
  }

  // The people and key columns of a realm or profile row.
  private static fill(out: any, people: any, keys: any): void {
    log.debug("Entering PasskeyHistoryRows.fill().");
    const p = people || {};
    PEOPLE.forEach(function (key: string): void {
      const from = key === 'people' ? p.total : p[key];
      out[key] = PasskeyHistoryRows.num(from);
    });
    const k = keys || {};
    out.count = PasskeyHistoryRows.num(k.total);
    out.postQuantumKeys = PasskeyHistoryRows.num(k.postQuantum);
    // The share of the people HOLDING a passkey who hold an ML-DSA one,
    // in percent to one decimal: the adoption figure. Null where nobody
    // holds one, rather than a 0 that would read as "nobody migrated".
    out.postQuantumShare = out.holding > 0 && out.withPostQuantum !== null
      ? Math.round(out.withPostQuantum * 1000 / out.holding) / 10 : null;
    log.debug("Leaving PasskeyHistoryRows.fill().");
  }

  /**
   * The catalog rows of the stored history rows, day by day in the order
   * given and, within a day, in `SCOPES` order.
   *
   * @param stored - `passkey_report.historyRows()`'s rows
   * @returns catalog rows
   */
  static rowsOf(stored: any[]): any[] {
    log.debug("Entering PasskeyHistoryRows.rowsOf().");
    const out: any[] = [];
    (Array.isArray(stored) ? stored : []).forEach(function (row: any): void {
      if (!row || typeof row !== 'object' || !row.day) {
        return;
      }
      const realm = PasskeyHistoryRows.blank(row, 'realm');
      PasskeyHistoryRows.fill(realm, row.people, row.keys);
      out.push(realm);
      (Array.isArray(row.profiles) ? row.profiles : [])
        .forEach(function (p: any): void {
          const one = PasskeyHistoryRows.blank(row, 'profile');
          one.name = String((p && p.name) || '');
          one.postQuantumRequired = String((p && p.postQuantumRequired) ||
                                           '');
          one.counted = !!(p && p.counted);
          if (one.counted) {
            PasskeyHistoryRows.fill(one, p.people, p.keys);
            one.members = PasskeyHistoryRows.num(p.members);
            one.complete = p.complete !== false;
          }
          out.push(one);
        });
      const keys = row.keys || {};
      (Array.isArray(keys.byAlgorithm) ? keys.byAlgorithm : [])
        .forEach(function (a: any): void {
          const one = PasskeyHistoryRows.blank(row, 'algorithm');
          one.name = String((a && a.algorithm) || '');
          one.coseAlg = PasskeyHistoryRows.num(a && a.coseAlg);
          one.lane = String((a && a.lane) || '');
          one.postQuantum = !!(a && a.postQuantum);
          one.count = PasskeyHistoryRows.num(a && a.count);
          out.push(one);
        });
      const lanes = keys.byLane && typeof keys.byLane === 'object'
        ? keys.byLane : {};
      Object.keys(lanes).sort().forEach(function (lane: string): void {
        const one = PasskeyHistoryRows.blank(row, 'lane');
        one.name = lane;
        one.lane = lane;
        one.count = PasskeyHistoryRows.num(lanes[lane]);
        out.push(one);
      });
      (Array.isArray(row.attestation) ? row.attestation : [])
        .forEach(function (a: any): void {
          const one = PasskeyHistoryRows.blank(row, 'attestation');
          one.name = String((a && a.algorithm) || '');
          one.coseAlg = PasskeyHistoryRows.num(a && a.coseAlg);
          one.postQuantum = !!(a && a.postQuantum);
          one.count = PasskeyHistoryRows.num(a && a.count);
          out.push(one);
        });
    });
    log.debug("Leaving PasskeyHistoryRows.rowsOf(). " + out.length);
    return out;
  }

  /**
   * The ambient realm's stored history rows, oldest day first, from the
   * passkey report (reached here, lazily).
   *
   * @returns the stored rows
   */
  static stored(): any[] {
    log.debug("Entering PasskeyHistoryRows.stored().");
    // Lazily (see the header): the first read, not the require.
    const report = require('../common/passkey_report');
    const rows = report.historyRows() || [];
    log.debug("Leaving PasskeyHistoryRows.stored(). " + rows.length);
    return rows;
  }
}

export = PasskeyHistoryRows;
