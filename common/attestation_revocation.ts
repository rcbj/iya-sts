// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: attestation_revocation.ts
//
// ===========================================================================
// GOOGLE'S ANDROID KEY ATTESTATION STATUS LIST, CONSULTED (#256, 2026-10-06).
//
// An Android Key Attestation chain verifies up to Google's hardware
// attestation roots (`device_attestation.ts`, and WebAuthn's `android-key`
// statement in `authn/webauthn_attestation.ts`), and a chain that verifies
// can still be one Google has REVOKED — a leaked batch key, a compromised
// intermediate. Google publishes which, by certificate serial, at
// https://android.googleapis.com/attestation/status. This module asks that
// list about every certificate of a chain, and rechecks the chains already
// stored when a newer list arrives.
//
// rcbj's four decisions (2026-10-06, on #256):
//
//   1. **No current list** — never downloaded, the download failing, or
//      stale (`devices.androidStatusStaleHours`) — leaves the chain
//      attested, its revocation `unchecked` with the reason. In product
//      with `devices.androidRevocationRequired` on
//      (`mode.refusesUncheckedAttestationRevocation()`), an unchecked chain
//      is treated as unattested instead.
//   2. **A stored key whose chain a newer list revokes or suspends** is
//      downgraded to self-asserted with the reason, its device's level
//      recomputed, audited, and CAEP credential-change (`update`) sent
//      (`devices.downgradeKeyAttestation()`); a WebAuthn credential's
//      statement becomes untrusted the same way
//      (`credentials.untrustKeyAttestation()`). The device's status is not
//      touched.
//   3. **Both verifiers ask**: device registration and WebAuthn.
//   4. **On by default**: `devices.androidStatusUrl` is Google's address.
//
// WHAT IS KEPT. Each key's attestation record gains the chain's serials
// (`chainSerials`) and what the list said (`revocation`: status `good`,
// `revoked`, `suspended` or `unchecked`, the reason, the serial listed, the
// list's version and when it was asked). A key registered before this
// change has no serials and cannot be rechecked: it is reported as
// registered before the check, and its level is left as it was.
//
// THE LIST ITSELF is a risk dataset (`android.attestation-status`, in
// `risk/risk_datasets.ts`), for the versions, the verify-before-active, the
// staleness, the upload door and the console's dataset table it already
// gives: downloaded by `devices.android-status-refresh` (#49: periodic work
// is a scheduler job), the address the operator's, dialled through
// `federation_http.fetchPublished()`. Its activation asks for
// `devices.android-status-recheck`, which also runs daily so a recheck a
// failed node never made is made the next day.
//
// A LIBRARY (rule 3): it registers two jobs and no route. Everything it
// reaches it reaches lazily — the risk datasets, the device register and the
// credentials are built in other places in the composition root — and every
// certificate question is `pki.js`'s (rcbj's rule).
// ===========================================================================

import helpers = require('./helpers');
import errorCodes = require('./error_codes');
import InstanceSlot = require('./instance_slot');

const { log } = helpers;

type Json = any;

/**
 * The download job's id.
 */
const REFRESH_JOB = 'devices.android-status-refresh';

/**
 * The recheck job's id.
 */
const RECHECK_JOB = 'devices.android-status-recheck';

const DAY_MS = 24 * 60 * 60 * 1000;

// The most certificates of one chain asked about: an Android chain is a
// leaf, one or two intermediates and the root.
const MAX_CHAIN = 10;

interface RevocationDeps {
  log: typeof helpers.log;
  errorCodes: typeof errorCodes;
  now(): number;
  pki(): Json;
  datasets(): Json;
  mode(): Json;
  realms(): Json;
  devices(): Json;
  credentials(): Json;
  scheduler(): Json;
  accountSignals(): Json | null;
  audit(): Json;
}

/**
 * Google's Android key attestation status list, consulted for every
 * certificate of an Android chain at registration, and the recheck of the
 * chains already stored when a newer list is active.
 */
class AttestationRevocation {
  /**
   * The download job's id.
   */
  static readonly REFRESH_JOB = REFRESH_JOB;
  /**
   * The recheck job's id.
   */
  static readonly RECHECK_JOB = RECHECK_JOB;

  /**
   * Builds the consultation over its collaborators.
   *
   * @param deps - the logger, error codes, a clock and lazy reaches of the
   *   modules it asks
   */
  constructor(private readonly deps: RevocationDeps) {
    deps.log.debug("Entering AttestationRevocation.constructor().");
    deps.log.debug("Leaving AttestationRevocation.constructor().");
  }

  /**
   * Returns the dependencies the default instance is built from, every module
   * reached lazily.
   *
   * @returns the dependencies
   */
  static defaultDeps(): RevocationDeps {
    log.debug("Entering AttestationRevocation.defaultDeps().");
    log.debug("Leaving AttestationRevocation.defaultDeps().");
    return {
      log: log,
      errorCodes: errorCodes,
      now: function (): number {
        return Date.now();
      },
      pki: function (): Json {
        return require('./pki');
      },
      datasets: function (): Json {
        return require('../risk/risk_datasets');
      },
      mode: function (): Json {
        return require('./mode');
      },
      realms: function (): Json {
        return require('./realms');
      },
      devices: function (): Json {
        return require('./devices');
      },
      credentials: function (): Json {
        return require('./credentials');
      },
      scheduler: function (): Json {
        return require('../cluster/scheduler');
      },
      accountSignals: function (): Json | null {
        log.debug("Entering AttestationRevocation accountSignals().");
        try {
          const signals = require('../ssf/account_signals');
          log.debug("Leaving AttestationRevocation accountSignals().");
          return signals;
        } catch (e) {
          log.debug("Caught in AttestationRevocation accountSignals(): " +
                    ((e && e.message) || e));
          log.debug("Leaving AttestationRevocation accountSignals(). None.");
          return null;
        }
      },
      audit: function (): Json {
        return require('./audit');
      }
    };
  }

  /**
   * Returns the serial numbers of a chain's certificates, as the status list
   * keys them.
   *
   * @param chain - the certificates, DER bytes, base64 DER or PEM, leaf first
   * @returns the serials, '' for one that could not be read dropped
   */
  serialsOf(chain: unknown[]): string[] {
    const { log } = this.deps;
    log.debug("Entering AttestationRevocation.serialsOf().");
    const pki = this.deps.pki();
    const out = (Array.isArray(chain) ? chain : []).slice(0, MAX_CHAIN)
      .map(function (one: unknown): string {
        const der = Buffer.isBuffer(one) ? one
          : (typeof one === 'string' && !/-----BEGIN/.test(one)
            ? Buffer.from(one, 'base64') : one);
        return pki.certificateSerialHex(der);
      }).filter(Boolean);
    log.debug("Leaving AttestationRevocation.serialsOf(). " + out.length);
    return out;
  }

  // What the active list says about a set of serials, as one record.
  private async verdictOf(serials: string[]): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering AttestationRevocation.verdictOf().");
    const checkedAt = new Date(this.deps.now()).toISOString();
    let lookup: Json = null;
    try {
      lookup = await this.deps.datasets().lookupAttestationSerials(serials);
    } catch (e) {
      log.debug("Caught in AttestationRevocation.verdictOf(): " +
                ((e && e.message) || e));
      lookup = { checked: false, version: '', hits: [],
                 why: 'the Android attestation status list could not be ' +
                      'read: ' + String((e && e.message) || e) };
    }
    if (!lookup || !lookup.checked) {
      log.debug("Leaving AttestationRevocation.verdictOf(). Unchecked.");
      return { status: 'unchecked', reason: '', serial: '',
               listVersion: String((lookup && lookup.version) || ''),
               checkedAt: checkedAt, chainSerials: serials,
               why: String((lookup && lookup.why) || 'no list') };
    }
    const hits = lookup.hits || [];
    const revoked = hits.filter(function (h: Json): boolean {
      return h.status === 'REVOKED';
    })[0];
    const suspended = hits.filter(function (h: Json): boolean {
      return h.status === 'SUSPENDED';
    })[0];
    const hit = revoked || suspended;
    log.debug("Leaving AttestationRevocation.verdictOf(). " +
              (hit ? hit.status : 'good'));
    return { status: hit ? String(hit.status).toLowerCase() : 'good',
             reason: hit ? String(hit.reason || '') : '',
             serial: hit ? String(hit.serial) : '',
             listVersion: String(lookup.version || ''),
             checkedAt: checkedAt, chainSerials: serials, why: '' };
  }

  /**
   * Asks Google's status list about every certificate of an Android chain.
   *
   * @param chain - the chain, leaf first: DER, base64 DER or PEM
   * @returns `{ status, reason, serial, listVersion, checkedAt,
   *   chainSerials, why }` — status `good`, `revoked`, `suspended` or
   *   `unchecked`
   */
  async consult(chain: unknown[]): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering AttestationRevocation.consult().");
    const out = await this.verdictOf(this.serialsOf(chain));
    log.debug("Leaving AttestationRevocation.consult(). " + out.status);
    return out;
  }

  /**
   * Says whether a verdict makes an Android chain count as unattested: a
   * revoked or suspended certificate always, an unchecked one where
   * `mode.refusesUncheckedAttestationRevocation()` says so.
   *
   * @param verdict - `consult()`'s answer
   * @returns true when the chain must not be trusted
   */
  untrusts(verdict: Json): boolean {
    const { log } = this.deps;
    log.debug("Entering AttestationRevocation.untrusts().");
    const status = String((verdict && verdict.status) || 'unchecked');
    const out = status === 'revoked' || status === 'suspended' ||
      (status === 'unchecked' &&
       !!this.deps.mode().refusesUncheckedAttestationRevocation());
    log.debug("Leaving AttestationRevocation.untrusts(). " + out);
    return out;
  }

  /**
   * Describes a verdict in a sentence, for an attestation's summary.
   *
   * @param verdict - `consult()`'s answer
   * @returns the sentence
   */
  describe(verdict: Json): string {
    const { log } = this.deps;
    log.debug("Entering AttestationRevocation.describe().");
    const v = verdict || {};
    const list = 'Google\'s Android attestation status list' +
      (v.listVersion ? ' ' + v.listVersion : '');
    const out = v.status === 'good'
      ? 'no certificate of the chain is revoked (' + list + ')'
      : (v.status === 'revoked' || v.status === 'suspended'
        ? 'certificate ' + v.serial + ' of the chain is ' +
          String(v.status).toUpperCase() + (v.reason ? ' (' + v.reason + ')'
                                                     : '') + ' in ' + list
        : 'its revocation is UNCHECKED: ' + String(v.why || 'no list'));
    log.debug("Leaving AttestationRevocation.describe().");
    return out;
  }

  // -------------------------------------------------------------------------
  // THE RECHECK (decision 2): every stored chain asked again, in every realm.
  // -------------------------------------------------------------------------
  /**
   * Rechecks every stored Android chain — device keys and WebAuthn
   * credentials, in every realm — and downgrades the ones the active list
   * revokes or suspends.
   *
   * @param ctx - the scheduler's run context; `stillOwner()` is asked
   *   between realms
   * @returns counts: `checked`, `downgraded`, `unchecked`, `failed`
   */
  async recheckAll(ctx?: Json): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering AttestationRevocation.recheckAll().");
    const c = ctx || {};
    const out = { realms: 0, checked: 0, downgraded: 0, unchecked: 0,
                  failed: 0 };
    const realms = this.deps.realms();
    const list = [realms.DEFAULT_REALM].concat((realms.list() || [])
      .filter(function (one: Json): boolean {
        return one && one.id && one.id !== realms.DEFAULT_ID;
      }));
    for (const realm of list) {
      if (c.stillOwner && !c.stillOwner()) {
        break;
      }
      out.realms += 1;
      await realms.run(realm, async () => {
        await this.recheckRealm(out);
      });
    }
    log.info('devices: the Android attestation recheck asked about ' +
             out.checked + ' stored chain(s) in ' + out.realms + ' realm(s): ' +
             out.downgraded + ' downgraded, ' + out.unchecked + ' unchecked.');
    log.debug("Leaving AttestationRevocation.recheckAll().");
    return out;
  }

  // One realm's device keys and WebAuthn credentials.
  private async recheckRealm(out: Json): Promise<void> {
    const { log } = this.deps;
    log.debug("Entering AttestationRevocation.recheckRealm().");
    const devices = this.deps.devices();
    const credentials = this.deps.credentials();
    for (const one of devices.androidAttestedKeys()) {
      out.checked += 1;
      const verdict = await this.verdictOf(one.chainSerials);
      if (verdict.status === 'unchecked') {
        out.unchecked += 1;
        continue;
      }
      if (verdict.status === 'good') {
        continue;
      }
      const done = devices.downgradeKeyAttestation(one.deviceId, one.keyId,
                                                   verdict);
      if (done && done.ok && done.changed) {
        out.downgraded += 1;
      } else if (!done || !done.ok) {
        out.failed += 1;
      }
    }
    for (const one of credentials.androidAttestedCredentials()) {
      out.checked += 1;
      const verdict = await this.verdictOf(one.chainSerials);
      if (verdict.status === 'unchecked') {
        out.unchecked += 1;
        continue;
      }
      if (verdict.status === 'good') {
        continue;
      }
      if (credentials.untrustKeyAttestation(one.username, one.credentialId,
                                            verdict)) {
        out.downgraded += 1;
        this.credentialDowngraded(one.username, one.credentialId, verdict);
      } else {
        out.failed += 1;
      }
    }
    log.debug("Leaving AttestationRevocation.recheckRealm().");
  }

  // A WebAuthn credential's statement made untrusted: the log, the audit row
  // and CAEP credential-change about the key, as a device key's is.
  private credentialDowngraded(username: string, credentialId: string,
                               verdict: Json): void {
    const { log, errorCodes } = this.deps;
    log.debug("Entering AttestationRevocation.credentialDowngraded().");
    const why = this.describe(verdict);
    log.warn(errorCodes.tag('STS-AUTHN-0297') + 'webauthn: the attestation ' +
             'of a security key of ' + username + ' is no longer trusted: ' +
             why + '.');
    try {
      this.deps.audit().record({
        category: 'authentication', action: 'webauthn.attestation-revoked',
        actor: 'system', target: username, outcome: 'success',
        errorCode: 'STS-AUTHN-0297',
        summary: 'the attestation of a security key of ' + username +
                 ' is no longer trusted: ' + why,
        detail: { credentialId: credentialId, serial: verdict.serial,
                  status: verdict.status, reason: verdict.reason,
                  listVersion: verdict.listVersion } });
    } catch (e) {
      log.debug("Caught in AttestationRevocation.credentialDowngraded(): " +
                ((e && e.message) || e));
      // The record was rewritten; an audit ring that refused does not undo
      // it, and the log line above says what happened.
    }
    const signals = this.deps.accountSignals();
    if (signals && typeof signals.credentialChanged === 'function') {
      signals.credentialChanged({ username: username,
        credentialType: signals.keyCredentialType
          ? signals.keyCredentialType({}) : 'fido2-roaming',
        changeType: 'update', initiatingEntity: 'system',
        friendlyName: 'security key ' + credentialId.slice(0, 16),
        via: 'the Android attestation status list',
        reasonAdmin: 'The attestation of a security key of ' + username +
                     ' is no longer trusted: ' + why + '.',
        reasonUser: 'The attestation of one of your security keys is no ' +
                    'longer trusted; the key still signs you in.' });
    }
    log.debug("Leaving AttestationRevocation.credentialDowngraded().");
  }

  /**
   * Queues a recheck of every stored chain on the scheduler's leader — what a
   * newly activated list asks for.
   *
   * @param why - why, for the run's record
   * @returns the scheduler's answer
   */
  requestRecheck(why: string): Json {
    const { log } = this.deps;
    log.debug("Entering AttestationRevocation.requestRecheck().");
    const answer = this.deps.scheduler().requestRun(RECHECK_JOB, {
      requestedBy: 'system', via: String(why || ''), channel: 'internal' });
    log.debug("Leaving AttestationRevocation.requestRecheck(). " +
              !!(answer && answer.ok));
    return answer;
  }

  /**
   * Registers the download and the recheck jobs with the scheduler, once per
   * process.
   *
   * @returns true when registered, false when they already were
   */
  registerJobs(): boolean {
    const { log } = this.deps;
    log.debug("Entering AttestationRevocation.registerJobs().");
    const s = this.deps.scheduler();
    if (s.job(REFRESH_JOB)) {
      log.debug("Leaving AttestationRevocation.registerJobs(). Already " +
                "there.");
      return false;
    }
    const self = this;
    const config = require('./config');
    s.register({
      id: REFRESH_JOB,
      title: 'Android attestation status list download',
      describe: 'Downloads Google\'s Android key attestation status list ' +
                'from devices.androidStatusUrl and loads it as the risk ' +
                'dataset android.attestation-status: which attestation ' +
                'certificates are revoked or suspended. Daily ' +
                '(devices.androidStatusRefreshS); a list identical to the ' +
                'active one loads nothing.',
      owner: 'common/attestation_revocation.ts',
      kind: 'cluster',
      everyMs: function (): number {
        return Number(config.value('devices.androidStatusRefreshS')) * 1000;
      },
      manual: true,
      off: function (): string {
        return String(config.value('devices.androidStatusUrl') || '')
          ? '' : 'devices.androidStatusUrl is empty';
      },
      run: function (): Promise<Json> {
        return self.deps.datasets().refreshAndroidStatus();
      }
    });
    s.register({
      id: RECHECK_JOB,
      title: 'Android attestation recheck',
      describe: 'Asks the active Android attestation status list about every ' +
                'stored Android chain — device keys and WebAuthn ' +
                'credentials, in every realm — and downgrades the ones it ' +
                'revokes or suspends: self-asserted, audited, CAEP ' +
                'credential-change. Run when a list is activated, and daily.',
      owner: 'common/attestation_revocation.ts',
      kind: 'cluster',
      everyMs: function (): number {
        return DAY_MS;
      },
      manual: true,
      run: function (ctx: Json): Promise<Json> {
        return self.recheckAll(ctx);
      }
    });
    log.debug("Leaving AttestationRevocation.registerJobs().");
    return true;
  }
}

const slot = new InstanceSlot<AttestationRevocation>(
  'common/attestation_revocation',
  () => new AttestationRevocation(AttestationRevocation.defaultDeps()),
  function (instance: AttestationRevocation): void {
    instance.registerJobs();
  },
  log);

slot.buildNowUnlessDeferred();

/**
 * Google's Android key attestation status list, consulted (#256). The exports
 * forward to the instance the composition root installs.
 *
 * @namespace
 */
export = {
  AttestationRevocation: AttestationRevocation,
  /**
   * Installs the instance the module-level functions forward to.
   */
  installInstance: (instance: AttestationRevocation): void =>
    slot.install(instance),
  /**
   * Says where the installed instance came from.
   */
  instanceOrigin: (): string => slot.origin(),
  REFRESH_JOB: AttestationRevocation.REFRESH_JOB,
  RECHECK_JOB: AttestationRevocation.RECHECK_JOB,
  serialsOf: slot.forward('serialsOf'),
  consult: slot.forward('consult'),
  untrusts: slot.forward('untrusts'),
  describe: slot.forward('describe'),
  recheckAll: slot.forward('recheckAll'),
  requestRecheck: slot.forward('requestRecheck'),
  registerJobs: slot.forward('registerJobs')
};
