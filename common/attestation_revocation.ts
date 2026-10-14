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
//
// THE RECHECK READS ONLY THE HOLDERS, WITHOUT BLOCKING, AND ONLY WHEN
// SOMETHING CHANGED (#615, 2026-10-13). It used to ask
// `credentials.androidAttestedCredentials()`, which is `persons()` and a
// `keysOf()` per person — on 8081, about 191,000 synchronous store reads on
// the serving front process at 17:00, every listener stopped for minutes, to
// find one person holding a security key. rcbj's decision on #615 was all
// five of:
//
//   1. **THE HOLDERS ONLY.** A key the recheck asks about is MARKED on its
//      entry — `stsAndroidAttestedCredential` on a person, naming the
//      credential ids; `stsDeviceAndroidKey` on a device, naming the key ids
//      — derived from the keys on every write of them, by the rule that
//      decides what a recheckable key is (`credentials.ts`'s and
//      `devices.ts`'s `isAndroidRecheckable()`). The recheck asks the
//      directory's `holdersAsync()` for the entries holding the marker,
//      which in a windowed process is `withAttribute()` against the store's
//      `attr_names` index; the keys are still interpreted by those two
//      files, so the marker decides who is READ, never what is rechecked.
//   2. **ASYNCHRONOUS AND YIELDING.** The holders are asked on the driver's
//      read pool, a page at a time, and the chains are asked about in
//      batches of `RECHECK_BATCH` with the event loop given back and
//      `ctx.stillOwner()` asked between them.
//   3. **SKIPPED WHEN NOTHING MOVED.** Every key was asked about the list
//      active when it was registered, so a recheck can only change
//      something when a different list is active, or a key was registered
//      since the last recheck. What the last complete recheck of a realm
//      covered — the list's version and the registration mark — is kept in
//      `devices.androidRecheck`, a persisted store every node restores (the
//      job is a cluster job: the next run may be on another node), and a
//      scheduled run that finds neither moved does nothing and says so. A
//      run asked for — Run now, or a list's activation (`requestRecheck()`)
//      — always runs. No list, or a stale one, rechecks nothing: every
//      verdict would be `unchecked`, which downgrades nothing.
//   4. **THE MARKER BACKFILLED** on the first run in each realm
//      (`MARKER_BACKFILL`), from the holders of the keys themselves —
//      everybody with a security key, every device with a key — never from
//      everybody.
//   5. **AND THE AUDIT OF EVERY OTHER JOB**, held by
//      `tests/no_full_directory_walk_in_jobs.js`.
//
// Where the directory offers no `holdersAsync()` (a test's stub, an older
// `ldap_server.js`) the two lists are the old walks, which is the old cost
// and the same answer.
// ===========================================================================

import helpers = require('./helpers');
import errorCodes = require('./error_codes');
import InstanceSlot = require('./instance_slot');
import realmStores = require('./realms');

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

// How many stored chains are asked about between two turns of the event
// loop (and two `stillOwner()` questions).
const RECHECK_BATCH = 50;

// The marker's backfill, by version: a realm whose last recheck recorded an
// older one (or none) is backfilled before it is rechecked. Raised if what
// the marker means ever changes.
const MARKER_BACKFILL = 1;

// WHAT THE LAST RECHECK OF EACH REALM COVERED, AND THE LATEST REGISTRATION
// (#615). Per realm, persisted: `covered` is `{ listVersion, mark, backfill,
// at }` of the last complete recheck, `registered` is `{ mark, at }` of the
// last Android-attested registration. Two keys rather than one row, so a
// registration on one node and a recheck's record on another never write the
// same key: each is last-writer-wins on its own. Cell tier
// (`persistence/tiers.js`): it describes this cell's people.
const recheckState = realmStores.map({ persist: 'devices.androidRecheck' });

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
  // The ambient realm's recheck state (#615): `get(key)` and `set(key, v)`.
  state(): Json;
  // A fresh, unguessable registration mark.
  newMark(): string;
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
      },
      state: function (): Json {
        return recheckState;
      },
      newMark: function (): string {
        return require('./crypto').randomToken(128);
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
  // THE RECHECK (decision 2): every stored chain asked again, in every realm
  // — the holders only, in batches, and only when something moved (#615).
  // -------------------------------------------------------------------------
  /**
   * Rechecks every stored Android chain — device keys and WebAuthn
   * credentials, in every realm — and downgrades the ones the active list
   * revokes or suspends; a realm where neither the list nor the
   * registrations moved since its last complete recheck is skipped, unless
   * the run was asked for.
   *
   * @param ctx - the scheduler's run context; `stillOwner()` is asked
   *   between realms and between batches, and a `manual` trigger (or
   *   `force`) rechecks whatever moved
   * @returns counts: `realms`, `checked`, `downgraded`, `unchecked`,
   *   `failed`, `skipped`, `backfilled`, `holders`, and `summary`
   */
  async recheckAll(ctx?: Json): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering AttestationRevocation.recheckAll().");
    const c = ctx || {};
    const forced = c.trigger === 'manual' || c.force === true;
    const out: Json = { realms: 0, checked: 0, downgraded: 0, unchecked: 0,
                        failed: 0, skipped: 0, backfilled: 0, holders: 0,
                        walked: 0, stopped: false, why: [] };
    const realms = this.deps.realms();
    const list = [realms.DEFAULT_REALM].concat((realms.list() || [])
      .filter(function (one: Json): boolean {
        return one && one.id && one.id !== realms.DEFAULT_ID;
      }));
    for (const realm of list) {
      if (c.stillOwner && !c.stillOwner()) {
        out.stopped = true;
        break;
      }
      out.realms += 1;
      await realms.run(realm, async () => {
        await this.recheckRealm(out, c, forced);
      });
      if (out.stopped) {
        break;
      }
    }
    out.summary = 'asked about ' + out.checked + ' stored chain(s) of ' +
      out.holders + ' holder(s) in ' + out.realms + ' realm(s): ' +
      out.downgraded + ' downgraded, ' + out.unchecked + ' unchecked, ' +
      out.failed + ' failed; ' + out.skipped + ' realm(s) skipped (' +
      (out.why.length ? Array.from(new Set(out.why)).join('; ')
                      : 'none') + ')' +
      (out.backfilled ? '; ' + out.backfilled + ' marker(s) backfilled' : '') +
      (out.walked ? '; ' + out.walked + ' realm(s) WALKED, the directory ' +
                    'offering no holder query' : '') +
      (out.stopped ? '; stopped, this node no longer owns the run' : '');
    delete out.why;
    log.info('devices: the Android attestation recheck ' + out.summary + '.');
    log.debug("Leaving AttestationRevocation.recheckAll().");
    return out;
  }

  // One realm: the backfill if it is owed, the skip if nothing moved, then
  // the device keys and the WebAuthn credentials of the marked holders.
  private async recheckRealm(out: Json, ctx: Json, forced: boolean):
      Promise<void> {
    const { log } = this.deps;
    log.debug("Entering AttestationRevocation.recheckRealm().");
    const devices = this.deps.devices();
    const credentials = this.deps.credentials();
    const state = this.deps.state();
    const stillOwner = function (): boolean {
      return !ctx.stillOwner || !!ctx.stillOwner();
    };
    const covered = state.get('covered') || {};
    // The mark as it was BEFORE anything was read: a key registered while
    // this recheck runs moves it past what is recorded, and the next run
    // reads that key.
    const mark = String((state.get('registered') || {}).mark || '');
    let backfill = Number(covered.backfill) || 0;
    if (backfill !== MARKER_BACKFILL) {
      const people = typeof credentials.backfillAndroidMarkers === 'function'
        ? await credentials.backfillAndroidMarkers(stillOwner)
        : { written: 0, stopped: false };
      const kit = typeof devices.backfillAndroidMarkers === 'function'
        ? await devices.backfillAndroidMarkers(stillOwner)
        : { written: 0, stopped: false };
      out.backfilled += Number(people.written || 0) + Number(kit.written || 0);
      if (people.stopped || kit.stopped) {
        out.stopped = true;
        log.debug("Leaving AttestationRevocation.recheckRealm(). Stopped " +
                  "in the backfill.");
        return;
      }
      backfill = MARKER_BACKFILL;
    }
    let snapshot: Json = null;
    try {
      snapshot = await this.deps.datasets().androidStatusSnapshot();
    } catch (e) {
      log.debug("Caught in AttestationRevocation.recheckRealm(): " +
                ((e && e.message) || e));
      // Asked as no list: nothing can be downgraded against a list that
      // cannot be read, and the next run asks again.
      snapshot = null;
    }
    const listVersion = String((snapshot && snapshot.active) || '');
    if (!listVersion || (snapshot && snapshot.stale)) {
      // No verdict could be `revoked` or `suspended`, so nothing is read.
      // The backfill is recorded; a list version is NOT — and one recorded
      // before is forgotten — so the first current list rechecks everything,
      // the keys registered while their revocation was `unchecked` with it.
      out.skipped += 1;
      out.why.push(listVersion ? 'the list ' + listVersion + ' is stale'
                               : 'no list is active');
      state.set('covered', { listVersion: '', mark: '', backfill: backfill,
                             at: this.deps.now() });
      log.debug("Leaving AttestationRevocation.recheckRealm(). No list.");
      return;
    }
    if (!forced && covered.listVersion === listVersion &&
        String(covered.mark || '') === mark &&
        Number(covered.backfill) === MARKER_BACKFILL) {
      out.skipped += 1;
      out.why.push('the list ' + listVersion + ' and the registrations are ' +
                   'as the last recheck found them');
      log.debug("Leaving AttestationRevocation.recheckRealm(). Unchanged.");
      return;
    }
    const keys = typeof devices.androidAttestedKeysAsync === 'function'
      ? await devices.androidAttestedKeysAsync()
      : { rows: devices.androidAttestedKeys(), holders: null,
          viaHolders: false };
    const creds = typeof credentials.androidAttestedCredentialsAsync ===
        'function'
      ? await credentials.androidAttestedCredentialsAsync()
      : { rows: credentials.androidAttestedCredentials(), holders: null,
          viaHolders: false };
    out.holders += Number(keys.holders || 0) + Number(creds.holders || 0);
    if (!keys.viaHolders || !creds.viaHolders) {
      out.walked += 1;
    }
    const work: Json[] = (keys.rows || []).map(function (one: Json): Json {
      return { kind: 'device', one: one };
    }).concat((creds.rows || []).map(function (one: Json): Json {
      return { kind: 'credential', one: one };
    }));
    for (let i = 0; i < work.length; i += 1) {
      if (i > 0 && i % RECHECK_BATCH === 0) {
        if (!stillOwner()) {
          out.stopped = true;
          log.debug("Leaving AttestationRevocation.recheckRealm(). Stopped.");
          return;
        }
        await new Promise<void>(function (resolve) {
          setImmediate(resolve);
        });
      }
      await this.recheckOne(out, work[i].kind, work[i].one, devices,
                            credentials);
    }
    // COMPLETE: what it covered is recorded, so the next scheduled run can
    // skip. A run stopped above records nothing and the next one repeats it.
    state.set('covered', { listVersion: listVersion, mark: mark,
                           backfill: backfill, at: this.deps.now() });
    log.debug("Leaving AttestationRevocation.recheckRealm().");
  }

  // One stored chain asked about again, and downgraded where the list now
  // revokes or suspends it.
  private async recheckOne(out: Json, kind: string, one: Json, devices: Json,
                           credentials: Json): Promise<void> {
    const { log } = this.deps;
    log.debug("Entering AttestationRevocation.recheckOne(). " + kind);
    out.checked += 1;
    const verdict = await this.verdictOf(one.chainSerials);
    if (verdict.status === 'unchecked') {
      out.unchecked += 1;
      log.debug("Leaving AttestationRevocation.recheckOne(). Unchecked.");
      return;
    }
    if (verdict.status === 'good') {
      log.debug("Leaving AttestationRevocation.recheckOne(). Good.");
      return;
    }
    if (kind === 'device') {
      const done = devices.downgradeKeyAttestation(one.deviceId, one.keyId,
                                                   verdict);
      if (done && done.ok && done.changed) {
        out.downgraded += 1;
      } else if (!done || !done.ok) {
        out.failed += 1;
      }
    } else if (credentials.untrustKeyAttestation(one.username,
                                                 one.credentialId, verdict)) {
      out.downgraded += 1;
      this.credentialDowngraded(one.username, one.credentialId, verdict);
    } else {
      out.failed += 1;
    }
    log.debug("Leaving AttestationRevocation.recheckOne(). " +
              verdict.status);
  }

  /**
   * Moves the ambient realm's registration mark: an Android-attested key was
   * registered, so the next recheck must not skip as "nothing changed"
   * (#615). Called by `credentials.ts` and `devices.ts` after the write.
   *
   * @param what - what was registered, for the log
   */
  noteRegistration(what: string): void {
    const { log } = this.deps;
    log.debug("Entering AttestationRevocation.noteRegistration().");
    this.deps.state().set('registered', { mark: this.deps.newMark(),
                                          at: this.deps.now() });
    log.debug("Leaving AttestationRevocation.noteRegistration(). " +
              String(what || ''));
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
                'credential-change. Reads only the people and devices ' +
                'marked as holding one, a page at a time, and skips a realm ' +
                'where neither the list nor the registrations moved since ' +
                'its last recheck. Run when a list is activated, and daily.',
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
  noteRegistration: slot.forward('noteRegistration'),
  requestRecheck: slot.forward('requestRecheck'),
  registerJobs: slot.forward('registerJobs')
};
