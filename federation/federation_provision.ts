// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: federation_provision.ts
//
// ===========================================================================
// THE IDLE SWEEP OF A FEDERATED PERSON (#358).
//
// A relationship's `fedProvisionIdleMinutes` — empty or 0 — leaves everybody
// alone. Past it, an entry whose every `federationLink` is that
// relationship's, and which holds no local `userPassword`, is disabled
// through `common/account_state.ts`. The entry and the link stay, so the
// next assertion from that partner finds the same person and the account
// state refuses them. A partner's own account-disabled signal stays
// `STS-FED-0156` and blocks only that partner's sign-ins.
//
// A passkey or a WebAuthn credential is another local path this sweep does
// not see. The minimum it holds is the password and the other links.
//
// A CLUSTER job, realm scope, every five minutes, off while
// `federation.enabled` is off. Registering starts nothing: the scheduler's
// leader runs it. The directory is asked for the holders of
// `federationLink`, never for every person. One disable that fails is
// logged `STS-FED-0159` and the run continues.
// ===========================================================================

import helpers = require('../common/helpers');
import config = require('../common/config');
import federation = require('./federation');
import errorCodes = require('../common/error_codes');
import scheduler = require('../cluster/scheduler');

type Json = any;

const log = helpers.log;
const IDLE_JOB = 'federation.provision-idle';

/**
 * Disables people a federation relationship has not seen within its idle
 * time, and registers the scheduler job that does it.
 */
class FederationProvision {
  /**
   * Reads a directory generalized time as milliseconds, or NaN.
   *
   * @param text - `YYYYMMDDHHmmss`, an optional trailing `Z` ignored
   * @returns the instant, or NaN when it cannot be read
   */
  static lastSeenMs(text: unknown): number {
    log.debug("Entering FederationProvision.lastSeenMs().");
    const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/.exec(
      String(text || ''));
    const ms = m ? Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5],
                            +m[6]) : NaN;
    log.debug("Leaving FederationProvision.lastSeenMs().");
    return ms;
  }

  /**
   * Disables, in the current realm, every person a relationship's idle
   * time has passed for. The scheduler job's body.
   *
   * @param nowMs - the time to check against; now by default
   * @returns `{ disabled }`, how many accounts this run disabled
   */
  static sweepIdle(nowMs?: number): Json {
    log.debug("Entering FederationProvision.sweepIdle().");
    const given = Number(nowMs);
    const now = Number.isFinite(given) ? given : Date.now();
    // Lazy: this module loads with `federation_sp`, before a require of
    // `account_state` from a federation module would be a cycle.
    const account = require('../common/account_state');
    let disabled = 0;
    federation.inRole('service-provider').forEach(function (record): void {
      if (!federation.signsIn(record)) {
        return;
      }
      const minutes = federation.provisionIdleMinutesOf(record);
      if (!(minutes > 0)) {
        return;
      }
      const limit = now - minutes * 60000;
      const rows = federation.idleCandidates(record.fedId) || [];
      rows.forEach(function (row): void {
        const seen = FederationProvision.lastSeenMs(row && row.lastSeen);
        const username = String((row && row.username) || '');
        if (!username || !Number.isFinite(seen) || seen >= limit) {
          return;
        }
        let act: Json = null;
        try {
          act = account.setDisabled(username, true, {
            actor: 'federation:' + record.fedId,
            door: IDLE_JOB,
            by: 'the idle sweep of federation relationship ' +
                record.fedId,
            reason: record.fedId + ' disables a person whose only ' +
                    'sign-in path is that relationship once ' +
                    'federationLastSeen is older than ' + minutes +
                    ' minutes'
          });
        } catch (e) {
          log.debug("Caught in FederationProvision.sweepIdle(): " +
                    ((e && e.message) || e));
          log.error(errorCodes.tag('STS-FED-0159') + 'federation: ' +
                    record.fedId + ' could not disable ' + username +
                    ' for being idle: ' + ((e && e.message) || e));
          return;
        }
        if (!act || !act.ok) {
          const why = act && act.errors
            ? [].concat(act.errors).join(' ') : '';
          log.error(errorCodes.tag('STS-FED-0159') + 'federation: ' +
                    record.fedId + ' could not disable ' + username +
                    ' for being idle' + (why ? ': ' + why : '') + '.');
          return;
        }
        if (act.changed) {
          disabled += 1;
        }
      });
    });
    log.debug("Leaving FederationProvision.sweepIdle(). " + disabled);
    return { disabled: disabled };
  }

  /**
   * Registers the idle sweep, once. It runs per realm every five minutes
   * while `federation.enabled` is on.
   */
  static registerIdleJob(): void {
    log.debug("Entering FederationProvision.registerIdleJob().");
    if (scheduler.job(IDLE_JOB)) {
      log.debug("Leaving FederationProvision.registerIdleJob(). " +
                "Registered.");
      return;
    }
    scheduler.register({
      id: IDLE_JOB,
      title: 'Federated provisioning idle sweep',
      describe: 'Disables a person whose only sign-in path is one ' +
                'federation relationship, once federationLastSeen is ' +
                'older than that relationship\'s ' +
                'fedProvisionIdleMinutes. Empty or 0 leaves everybody. ' +
                'The entry and the link are kept. A local password, or ' +
                'a link through another relationship, is left alone.',
      owner: 'federation/federation_provision.ts',
      scope: 'realm',
      everyMs: function (): number {
        return 300000;
      },
      off: function (): string {
        return config.value('federation.enabled') ? ''
          : 'federation.enabled is off';
      },
      run: function (ctx: Json): Json {
        return FederationProvision.sweepIdle(ctx.nowMs());
      }
    });
    log.debug("Leaving FederationProvision.registerIdleJob().");
  }
}

// Registered at load, as `federation_encryption.ts` registers its
// retirement. A registration arms no timer.
FederationProvision.registerIdleJob();

export = FederationProvision;
