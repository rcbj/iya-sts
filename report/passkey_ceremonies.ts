// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: passkey_ceremonies.ts
//
// ---------------------------------------------------------------------------
// THE `passkeyCeremonies` SOURCE'S ROWS (#1107).
//
// Every WebAuthn ceremony writes one `webauthn.ceremony` audit row and a
// classical sign-in by a person who holds an ML-DSA passkey writes
// `webauthn.algorithm-mismatch` (`authn/webauthn_ceremonies.ts`, #943; the
// row's application, duration and fold since #1108). Until #1107 nothing
// read them back. This file turns them into the catalog's rows
// (`catalog.ts`, `passkeyCeremonySource()`); `sources.ts` reads the audit
// ring the way it reads it for `authActivity` — `reportAuditEvents()`,
// which waits for the other processes' rows (`audit.fresh()`, #820) and
// caps the list at `audit.maxEvents` — and offers each row here to the
// bounded row collector. So the read costs what `authActivity`'s costs:
// one pass over a list already in memory, never the store.
//
// WHAT A ROW CARRIES is the catalog's field list and nothing else. The
// folded `authenticator` field is read back through
// `webauthn_ceremonies.unfold()`, which also reads a row written before
// #1108 (separate `attachment`, `transports`, `attestation`), so the source
// answers the same over a ring that holds both shapes. `postQuantum` and
// `postQuantumOffered` are derived from the algorithm names with
// `passkey_policy.isPostQuantum()`, the one test of what is post-quantum.
// An address, a summary sentence and a session are not copied.
//
// A LIBRARY (rule 3): it registers nothing, and it reaches
// `authn/webauthn_ceremonies` and `common/passkey_policy` LAZILY, at the
// first projection, so requiring it moves no load-time effect forward.
// In a file of its own so a source added beside it merges cleanly.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');

const { log } = helpers;

/**
 * The audit actions this source reads, and the `kind` each becomes.
 */
const KINDS: Record<string, string> = Object.freeze({
  'webauthn.ceremony': 'ceremony',
  'webauthn.algorithm-mismatch': 'algorithm-mismatch'
});

/**
 * Projects passkey ceremony audit rows into the catalog's rows.
 */
class PasskeyCeremonyRows {
  /**
   * The audit actions read, and the `kind` each becomes.
   */
  static readonly KINDS = KINDS;

  // An audit time (ms) as ISO text, or '' for none.
  private static iso(at: unknown): string {
    log.debug("Entering PasskeyCeremonyRows.iso().");
    const ms = Number(at);
    const out = Number.isFinite(ms) && ms > 0 ? new Date(ms).toISOString()
                                              : '';
    log.debug("Leaving PasskeyCeremonyRows.iso().");
    return out;
  }

  /**
   * The catalog rows of the passkey ceremony audit rows among `events`, in
   * the order given (the ring's: newest first). Any other row is skipped.
   *
   * @param events - `audit.list()`'s rows
   * @returns catalog rows
   */
  static rowsOf(events: any[]): any[] {
    log.debug("Entering PasskeyCeremonyRows.rowsOf().");
    // Lazily (see the header): the first projection, not the require.
    const ceremonies = require('../authn/webauthn_ceremonies');
    const passkeyPolicy = require('../common/passkey_policy');
    const pq = function (name: string): boolean {
      return passkeyPolicy.isPostQuantum(String(name || '').trim());
    };
    const out: any[] = [];
    const list = Array.isArray(events) ? events : [];
    for (let i = 0; i < list.length; i++) {
      const event = list[i] || {};
      const kind = KINDS[String(event.action || '')];
      if (!kind) {
        continue;
      }
      const d = event.detail && typeof event.detail === 'object'
        ? event.detail : {};
      const when = PasskeyCeremonyRows.iso(event.at);
      const mismatch = kind === 'algorithm-mismatch';
      // A mismatch row names the algorithm that signed `used`, and the
      // person's post-quantum ones `held`; a ceremony row `algorithm`.
      const algorithm = String((mismatch ? d.used : d.algorithm) || '');
      // `offered` may carry, after its first `|`, the client rule that
      // narrowed the offer or would have (#1112: `configured: <rule>`,
      // `learned: <client>`, `not applied (<why>): ...`); the names are
      // before it.
      const raw = mismatch ? '' : String(d.offered || '');
      const bar = raw.indexOf('|');
      const offered = (bar >= 0 ? raw.slice(0, bar) : raw).trim();
      const offerRule = bar >= 0 ? raw.slice(bar + 1).trim() : '';
      const names = offered ? offered.split(',').map(function (n: string) {
        return n.trim();
      }).filter(Boolean) : [];
      const unfolded = mismatch
        ? { attachment: '', transports: '', attestation: '' }
        : ceremonies.unfold(d);
      const duration = Number(d.durationMs);
      out.push({
        timestamp: when,
        day: when.slice(0, 10),
        kind: kind,
        ceremony: mismatch ? '' : String(d.ceremony || ''),
        door: String(d.door || ''),
        outcome: String(event.outcome || ''),
        errorCode: String(event.errorCode || ''),
        actor: String(event.actor || ''),
        application: String(d.application || ''),
        role: String(d.role || ''),
        lane: String(d.lane || ''),
        offered: offered,
        offerRule: offerRule,
        offeredFirst: names.length ? String(names[0]) : '',
        postQuantumOffered: names.some(pq),
        algorithm: algorithm,
        postQuantum: pq(algorithm),
        held: mismatch ? String(d.held || '') : '',
        client: String(d.client || ''),
        clientError: String(d.clientError || ''),
        capabilities: String(d.capabilities || ''),
        attachment: String(unfolded.attachment || ''),
        transports: String(unfolded.transports || ''),
        attestation: String(unfolded.attestation || ''),
        durationMs: d.durationMs !== undefined && d.durationMs !== '' &&
          Number.isFinite(duration) ? duration : null
      });
    }
    log.debug("Leaving PasskeyCeremonyRows.rowsOf(). " + out.length);
    return out;
  }
}

export = PasskeyCeremonyRows;
