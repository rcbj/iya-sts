// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: revoking_writes.ts
//
// ---------------------------------------------------------------------------
// A WRITE THAT ENDS WHAT A REFRESH TOKEN RESTS ON, SAID ON ITS ANSWER
// (2026-11-13, the review of #879).
//
// #879 keyed the refresh grant's read-your-write wait by the presented token
// (`request_pool.js`, THE REFRESH GRANT, KEYED BY ITS TOKEN), so a refresh
// stopped waiting for every browser's writes. One kind of browser write is
// exactly what a refresh must not answer ahead of: one that ENDS the session,
// the token, the family, the grant or the account the refresh token rests
// on. In product, a refresh sent a moment after a sign-out and routed to a
// request worker that had not yet applied it was issued new tokens from a
// session that had just ended. The global wait before #879 had prevented
// that.
//
// The front process cannot see which request revoked something: a sign-out
// path it can name, but a sign-in that replaces another session in the same
// browser, a disabled account through the console, a refresh replay that
// revokes its family — those are decided inside the handler. So the
// handler says so. The funnels call `note()`:
//
//   * `admin_stats.revoke()` — the one revocation set — except for a token
//     SUPERSEDED by its successor (a refresh token rotated on use), which
//     ends nothing and is every refresh's own write;
//   * `oauth2_bcp.revokeFamily()` — a refresh family revoked by id;
//   * `authn.dropSession()` — the one place a session stops existing;
//   * `account_state.setDisabled()` — an account disabled;
//   * `grant_management.revoke()` — a Grant Management grant revoked.
//
// In a request worker the marker `request_worker.ts` installs puts
// `HEADER` on the answer in flight, and the front process files that
// answer's ticket under the key every refresh grant waits for, BEFORE the
// client is sent a byte. In the front process, and in any process with no
// marker, `note()` does nothing: the front process's own writes are
// everybody's already (`frontGeneration`), and a process with no pool has no
// barrier to tell.
//
// A LEAF over `helpers` (for the logger), with no state but the marker; it
// requires nothing that could require it back.
// ---------------------------------------------------------------------------

import helpers = require('./helpers');

const log = helpers.log;

// The answer header a worker sets, and `request_pool.js` reads and strips.
// Spelled in both files; `tests/revoking_writes.js` compares them.
const HEADER = 'x-sts-pool-revoking';

type Marker = (what: string) => void;

let marker: Marker | null = null;

/**
 * Where a write that ends what a refresh token rests on is said.
 */
class RevokingWrites {
  /** The answer header a request worker sets. */
  static readonly HEADER = HEADER;

  /**
   * Installs the marker a request worker answers with. Null removes it.
   *
   * @param fn - called with what was ended, inside the request's context
   */
  static install(fn: Marker | null): void {
    log.debug("Entering RevokingWrites.install().");
    marker = typeof fn === 'function' ? fn : null;
    log.debug("Leaving RevokingWrites.install(). " +
              (marker ? 'Installed.' : 'Removed.'));
  }

  /**
   * Whether a marker is installed.
   *
   * @returns true in a request worker
   */
  static installed(): boolean {
    log.debug("Entering RevokingWrites.installed().");
    log.debug("Leaving RevokingWrites.installed().");
    return !!marker;
  }

  /**
   * Says that the request being answered ended a session, a token, a family,
   * a grant or an account. Never throws: the revocation is the real work and
   * this is what tells the barrier about it.
   *
   * @param what - what was ended, for the log
   */
  static note(what: string): void {
    log.debug("Entering RevokingWrites.note(). " + what);
    if (!marker) {
      log.debug("Leaving RevokingWrites.note(). No marker here.");
      return;
    }
    try {
      marker(String(what || ''));
    } catch (e: any) {
      // The marker logs its own refusal under its code; a throw past it is
      // a bug in the marker, and the revocation it describes still stands.
      log.debug("Caught in RevokingWrites.note(): " +
                ((e && e.message) || e));
    }
    log.debug("Leaving RevokingWrites.note().");
  }
}

export = RevokingWrites;
