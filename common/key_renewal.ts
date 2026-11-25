// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: key_renewal.ts
//
// ===========================================================================
// THREE RENEWALS NOTHING DID ON ITS OWN, ON THE SCHEDULER (#2220, ASVS 5.0.0
// Level 3; the Known gaps of docs/v1.2.0/key-management.md).
//
// This module decides WHEN; what each renewal IS belongs to the module that
// owns the key, as `common/signing_rotation.ts` decides when a signing key
// moves on and `helpers.js` moves it:
//
//   `pki.ca-renew`                    cluster, service; daily. Renews the
//                                     Root, then each Intermediate, then each
//                                     Issuing CA that is inside its lead
//                                     (`pki.rootRenewalLeadDays`,
//                                     `pki.caRenewalLeadDays`) over the SAME
//                                     key and subject — `common/pki.js`'s
//                                     `renewCaCertificate()`, whose header
//                                     argues the trust-anchor overlap, the
//                                     pins and paranoid PKI mode. In both
//                                     modes. No Run now: a deliberate change
//                                     of a CA key is Replace the Root or
//                                     Reissue this CA, which are on-demand
//                                     acts in the two-person table
//                                     (`admin-core/dual_control.ts`).
//   `keys.credential-signer-rotate`   cluster, realm; hourly. Moves each
//                                     dedicated credential signer's key
//                                     family on to its next generation once
//                                     its key is as old as its setting asks
//                                     (keys.credentialSignerRotationInterval
//                                     Days), through `credential_signer.js`'s
//                                     `rotateFamilyAsync()`; the one it
//                                     replaces stays published and accepted.
//   `keys.encryption-key-rotate`      cluster, realm; hourly. Replaces the
//                                     request object encryption keys, the
//                                     OpenID4VCI request-encryption key and
//                                     the KEM decryption keys once they are
//                                     `keys.encryptionKeyRotationIntervalDays`
//                                     old (`helpers.rotateEncryptionKeys()`),
//                                     the new one published first and the old
//                                     one still decrypting for
//                                     `keys.encryptionKeyOverlapDays`.
//
// **THE AGE OF A KEY IS COUNTED FROM WHEN IT WAS FIRST SEEN HERE**, in a
// small per-realm store of this module's (`keys.renewalClock`, a kid to an
// instant), because neither a credential signer's row nor a request key
// records when it was made, and a row is never changed once written. A key
// a rotation made is entered at the rotation. So AN UPGRADE ROTATES NOTHING
// ON ITS FIRST START: every key held then is entered at its first run and
// rotates a whole interval later, and a realm created later counts from its
// own keys' first sight. The two key schedules are off in development mode
// (`mode.rotatesSigningKeys()`), whose keys are made anew at every start.
//
// A LIBRARY (rule 3): it registers three jobs and no route, built by
// `common/protocol_stack.ts` beside `common/signing_rotation` (23b-ii-c).
// Everything it drives is reached lazily.
// ===========================================================================

import helpers = require('./helpers');
import config = require('./config');
import realms = require('./realms');
import errorCodes = require('./error_codes');
import InstanceSlot = require('./instance_slot');

type Json = any;

/** The CA renewal job. */
const CA_JOB = 'pki.ca-renew';
/** The credential signer rotation job. */
const CREDENTIAL_JOB = 'keys.credential-signer-rotate';
/** The request-decryption key rotation job. */
const ENCRYPTION_JOB = 'keys.encryption-key-rotate';
const HOUR_MS = 3600000;
const DAY_MS = 86400000;

// ---------------------------------------------------------------------------
// THE CLOCK: when each key was first seen, per realm, persisted (so a
// restart does not reset an age) and global, for the reason the key sets
// are (`persistence/tiers.js`). One small row per key; a row whose key is
// no longer held is dropped by the run that notices.
// ---------------------------------------------------------------------------
// A hot path (every row a flush writes): no Entering/Leaving pair.
const clock = realms.map({
  persist: 'keys.renewalClock'
});

interface ClockStore {
  get(key: string): any;
  set(key: string, value: any): unknown;
  delete(key: string): boolean;
  forEach(fn: (value: any, key: string) => void): void;
}

interface KeyRenewalDeps {
  log: typeof helpers.log;
  config: typeof config;
  realms: typeof realms;
  errorCodes: typeof errorCodes;
  clock: ClockStore;
  // Lazily, each.
  scheduler: () => Json;
  mode: () => Json;
  pki: () => Json;
  keys: () => Json;
  credentialSigner: () => Json;
  audit: () => Json;
  now: () => number;
}

/**
 * When the CA certificates, the credential signers and the request-
 * decryption keys are renewed, on the scheduler.
 */
class KeyRenewal {
  /** The CA renewal job. */
  static readonly CA_JOB = CA_JOB;
  /** The credential signer rotation job. */
  static readonly CREDENTIAL_JOB = CREDENTIAL_JOB;
  /** The request-decryption key rotation job. */
  static readonly ENCRYPTION_JOB = ENCRYPTION_JOB;

  /**
   * Builds the instance over its dependencies.
   *
   * @param deps - the modules it uses, most of them reached lazily, a clock
   *   store and a clock
   */
  constructor(private readonly deps: KeyRenewalDeps) {
    deps.log.debug("Entering KeyRenewal.constructor().");
    deps.log.debug("Leaving KeyRenewal.constructor().");
  }

  /**
   * Returns the dependencies the composition root builds the instance with.
   *
   * @returns the real modules, the store and `Date.now`
   */
  static defaultDeps(): KeyRenewalDeps {
    helpers.log.debug("Entering KeyRenewal.defaultDeps().");
    helpers.log.debug("Leaving KeyRenewal.defaultDeps().");
    return {
      log: helpers.log,
      config: config,
      realms: realms,
      errorCodes: errorCodes,
      clock: clock,
      scheduler: function (): Json {
        return require('../cluster/scheduler');
      },
      mode: function (): Json {
        return require('./mode');
      },
      pki: function (): Json {
        return require('./pki');
      },
      keys: function (): Json {
        return require('./helpers');
      },
      credentialSigner: function (): Json {
        return require('./credential_signer');
      },
      audit: function (): Json {
        return require('./audit');
      },
      now: function (): number {
        return Date.now();
      }
    };
  }

  // `fn` inside the trust realm `realmId`: the clock is per realm.
  private inRealm(realmId: string, fn: () => Json): Json {
    const { log, realms } = this.deps;
    log.debug("Entering KeyRenewal.inRealm(). realm=" + realmId);
    const realm = realms.get(String(realmId || realms.DEFAULT_ID));
    log.debug("Leaving KeyRenewal.inRealm().");
    return realm ? realms.run(realm, fn) : fn();
  }

  // -------------------------------------------------------------------------
  // THE CLOCK, in the ambient realm.
  // -------------------------------------------------------------------------
  /**
   * When the key `id` was first seen in the ambient realm; entered now when
   * it never was.
   *
   * @param id - `<kind>:<kid>`
   * @param nowMs - the time
   * @returns the epoch milliseconds
   */
  firstSeen(id: string, nowMs: number): number {
    const { log, clock } = this.deps;
    log.debug("Entering KeyRenewal.firstSeen(). " + id);
    const held = Number(clock.get(id));
    if (held > 0) {
      log.debug("Leaving KeyRenewal.firstSeen(). Known.");
      return held;
    }
    clock.set(id, nowMs);
    log.debug("Leaving KeyRenewal.firstSeen(). Entered now.");
    return nowMs;
  }

  // Drops the clock rows of `prefix` whose key is not among `keep`.
  private forgetOthers(prefix: string, keep: string[]): void {
    const { log, clock } = this.deps;
    log.debug("Entering KeyRenewal.forgetOthers(). " + prefix);
    const gone: string[] = [];
    clock.forEach(function (_value: Json, key: string): void {
      if (key.indexOf(prefix) === 0 && keep.indexOf(key) < 0) {
        gone.push(key);
      }
    });
    gone.forEach(function (key: string): void {
      clock.delete(key);
    });
    log.debug("Leaving KeyRenewal.forgetOthers(). " + gone.length + ".");
  }

  // -------------------------------------------------------------------------
  // THE CA CERTIFICATES.
  // -------------------------------------------------------------------------
  /**
   * Why the CA renewal is off, or ''.
   *
   * @returns the reason
   */
  caOffReason(): string {
    const { log, config, pki } = this.deps;
    log.debug("Entering KeyRenewal.caOffReason().");
    let why = '';
    if (config.value('pki.caRenewal') === false) {
      why = 'pki.caRenewal is off';
    } else if (config.value('pki.autoBuild') === false && !pki().hasRoot()) {
      why = 'there is no certificate authority (pki.autoBuild is off)';
    }
    log.debug("Leaving KeyRenewal.caOffReason(). " + (why || 'on'));
    return why;
  }

  /**
   * The scheduled CA renewal: every tier inside its lead, top down, each
   * one audited. A tier that could not be renewed fails the run (with its
   * code) after the others have been tried.
   *
   * @param ctx - the scheduler's run context
   * @returns a promise of `{ summary, renewed, waiting }`
   */
  async renewCasDue(ctx?: Json): Promise<Json> {
    const { log, pki, audit, errorCodes } = this.deps;
    log.debug("Entering KeyRenewal.renewCasDue().");
    const nowMs = ctx && ctx.nowMs ? ctx.nowMs() : this.deps.now();
    const renewed: Json[] = [];
    const failed: Json[] = [];
    // TOP DOWN, re-planned after each renewal: a renewed parent is what lets
    // a child inside its lead gain anything.
    const tiers = ['root', 'intermediate', 'issuing'];
    for (let t = 0; t < tiers.length; t++) {
      const due = pki().caRenewalPlan(nowMs).filter(function (one: Json) {
        return one.tier === tiers[t] && one.due;
      });
      for (let i = 0; i < due.length; i++) {
        if (ctx && typeof ctx.stillOwner === 'function' &&
            !ctx.stillOwner()) {
          log.debug("Leaving KeyRenewal.renewCasDue(). No longer the " +
                    "owner.");
          return { summary: renewed.length + ' renewed; stopped, this ' +
                            'node no longer owns the run',
                   renewed: renewed };
        }
        const one = due[i];
        const done = await pki().renewCaCertificate(one.scope, one.tier,
                                                    one.useCase, nowMs);
        const named = one.tier + (one.useCase ? ' ' + one.useCase : '') +
                      ' of ' + (one.tier === 'root' ? 'the service'
                                : '"' + (one.scope || 'default') + '"');
        if (done && done.ok && done.renewed) {
          renewed.push({ scope: one.scope, tier: one.tier,
                         useCase: one.useCase, from: done.from,
                         to: done.to });
          audit().record({
            action: 'pki.ca.renew', protocol: 'PKI', channel: 'scheduler',
            outcome: 'success',
            summary: 'The ' + named + ' CA certificate was renewed over ' +
                     'the same key' + (one.tier === 'root'
                       ? '; the Root it replaced stays published until it ' +
                         'expires' : ''),
            detail: { scope: one.scope, tier: one.tier,
                      useCase: one.useCase, from: done.from, to: done.to }
          });
        } else if (!done || !done.ok) {
          const why = ((done && done.errors) || []).join(' ');
          failed.push({ scope: one.scope, tier: one.tier,
                        useCase: one.useCase, why: why });
          audit().record({
            action: 'pki.ca.renew', protocol: 'PKI', channel: 'scheduler',
            outcome: 'failure',
            errorCode: errorCodes.codeOf(done) || 'STS-PKI-0310',
            summary: 'The ' + named + ' CA certificate could not be renewed',
            detail: { scope: one.scope, tier: one.tier,
                      useCase: one.useCase, why: why }
          });
        }
      }
    }
    if (failed.length) {
      log.debug("Leaving KeyRenewal.renewCasDue(). " + failed.length +
                " failed.");
      throw errorCodes.mark(new Error(failed.length + ' CA certificate(s) ' +
        'could not be renewed: ' + failed.map(function (one: Json) {
          return one.tier + ' ' + (one.useCase || '') + ' of "' +
                 (one.scope || 'default') + '" (' + one.why + ')';
        }).join('; ')), 'STS-PKI-0310');
    }
    const waiting = pki().caRenewalPlan(nowMs).filter(function (one: Json) {
      return !one.due && /parent expires first/.test(String(one.why));
    }).length;
    log.debug("Leaving KeyRenewal.renewCasDue(). " + renewed.length +
              " renewed.");
    return { summary: renewed.length + ' renewed' +
                      (waiting ? ', ' + waiting + ' waiting for a parent'
                               : ''),
             renewed: renewed };
  }

  // -------------------------------------------------------------------------
  // THE CREDENTIAL SIGNERS.
  // -------------------------------------------------------------------------
  /**
   * The interval of the credential signers' schedule, in milliseconds; 0 is
   * off.
   *
   * @returns the interval
   */
  credentialIntervalMs(): number {
    const { log, config } = this.deps;
    log.debug("Entering KeyRenewal.credentialIntervalMs().");
    const days = Number(config.value(
      'keys.credentialSignerRotationIntervalDays'));
    log.debug("Leaving KeyRenewal.credentialIntervalMs().");
    return days > 0 ? days * DAY_MS : 0;
  }

  /**
   * Why the credential signers' schedule is off in a realm, or ''.
   *
   * @param realmId - the trust realm
   * @returns the reason
   */
  credentialOffReason(realmId?: string): string {
    const self = this;
    const { log, mode, config } = this.deps;
    log.debug("Entering KeyRenewal.credentialOffReason().");
    const why = this.inRealm(String(realmId || ''), function (): string {
      if (!mode().rotatesSigningKeys()) {
        return 'development mode, whose keys are made anew at every start';
      }
      if (String(config.value('keys.credentialSigner') || 'dedicated') !==
          'dedicated') {
        return 'keys.credentialSigner is realm-key: credentials are signed ' +
               'with the realm signing key, on signing.rotate\'s schedule';
      }
      if (!(self.credentialIntervalMs() > 0)) {
        return 'keys.credentialSignerRotationIntervalDays is 0';
      }
      return '';
    });
    log.debug("Leaving KeyRenewal.credentialOffReason(). " + (why || 'on'));
    return why;
  }

  /**
   * The scheduled run for one realm: each credential signer family whose
   * key is a whole interval old moves on to its next generation.
   *
   * @param realmId - the trust realm
   * @param ctx - the scheduler's run context
   * @returns a promise of `{ summary, rotated }`
   */
  async rotateCredentialSignersDue(realmId: string, ctx?: Json):
      Promise<Json> {
    const self = this;
    const { log, keys, credentialSigner, audit, errorCodes } = this.deps;
    log.debug("Entering KeyRenewal.rotateCredentialSignersDue(). realm=" +
              realmId);
    const nowMs = ctx && ctx.nowMs ? ctx.nowMs() : this.deps.now();
    const interval = this.credentialIntervalMs();
    const set = keys().stsKeysFor.of(String(realmId ||
                                            this.deps.realms.DEFAULT_ID));
    const families = credentialSigner().credentialFamilies(set);
    const kept: string[] = [];
    const due: Json[] = [];
    this.inRealm(realmId, function (): void {
      families.forEach(function (one: Json): void {
        const id = 'vc:' + one.current.publicJwk.kid;
        kept.push(id);
        if (nowMs - self.firstSeen(id, nowMs) >= interval) {
          due.push(one);
        }
      });
      self.forgetOthers('vc:', kept);
    });
    const rotated: Json[] = [];
    for (let i = 0; i < due.length; i++) {
      if (ctx && typeof ctx.stillOwner === 'function' && !ctx.stillOwner()) {
        break;
      }
      let done = null;
      try {
        done = await this.inRealm(realmId, function (): Json {
          return credentialSigner().rotateFamilyAsync(set,
            due[i].familySlot, keys().CURVE_KEY_SPECS);
        });
      } catch (e) {
        log.error(errorCodes.tag(errorCodes.codeOf(e) || 'STS-PKI-0312') +
                  'key renewal: the "' + (realmId || 'default') + '" ' +
                  'realm\'s ' + due[i].familySlot + ' credential signer ' +
                  'could not be rotated: ' + ((e && e.message) || e) +
                  '. It goes on signing.');
        audit().record({
          action: 'keys.credential-signer.rotate', protocol: 'Keys',
          channel: 'scheduler', outcome: 'failure', realm: realmId,
          errorCode: errorCodes.codeOf(e) || 'STS-PKI-0312',
          summary: 'The ' + due[i].familySlot + ' credential signer could ' +
                   'not be rotated',
          detail: { family: due[i].familySlot,
                    why: String((e && e.message) || e) }
        });
        log.debug("Leaving KeyRenewal.rotateCredentialSignersDue(). " +
                  "Failed.");
        throw errorCodes.mark(new Error('the ' + due[i].familySlot +
          ' credential signer could not be rotated: ' +
          ((e && e.message) || e)), errorCodes.codeOf(e) || 'STS-PKI-0312');
      }
      this.inRealm(realmId, function (): void {
        self.firstSeen('vc:' + done.to, nowMs);
      });
      rotated.push({ family: due[i].familySlot, from: done.from,
                     to: done.to });
      audit().record({
        action: 'keys.credential-signer.rotate', protocol: 'Keys',
        channel: 'scheduler', outcome: 'success', realm: realmId,
        summary: 'The ' + due[i].familySlot + ' credential signer moved on ' +
                 'to ' + done.to + '; ' + done.from + ' is retired and ' +
                 'stays published',
        detail: { family: due[i].familySlot, from: done.from, to: done.to,
                  slot: done.slot }
      });
    }
    log.debug("Leaving KeyRenewal.rotateCredentialSignersDue(). " +
              rotated.length + ".");
    return { summary: rotated.length + ' rotated of ' + families.length +
                      ' famil' + (families.length === 1 ? 'y' : 'ies'),
             rotated: rotated };
  }

  // -------------------------------------------------------------------------
  // THE REQUEST-DECRYPTION KEYS.
  // -------------------------------------------------------------------------
  /**
   * The interval of the request-decryption keys' schedule, in milliseconds;
   * 0 is off.
   *
   * @returns the interval
   */
  encryptionIntervalMs(): number {
    const { log, config } = this.deps;
    log.debug("Entering KeyRenewal.encryptionIntervalMs().");
    const days = Number(config.value('keys.encryptionKeyRotationIntervalDays'));
    log.debug("Leaving KeyRenewal.encryptionIntervalMs().");
    return days > 0 ? days * DAY_MS : 0;
  }

  /**
   * How long a replaced request-decryption key still decrypts, in
   * milliseconds.
   *
   * @returns the overlap
   */
  encryptionOverlapMs(): number {
    const { log, config } = this.deps;
    log.debug("Entering KeyRenewal.encryptionOverlapMs().");
    const days = Number(config.value('keys.encryptionKeyOverlapDays'));
    log.debug("Leaving KeyRenewal.encryptionOverlapMs().");
    return days > 0 ? days * DAY_MS : 0;
  }

  /**
   * Why the request-decryption keys' schedule is off in a realm, or ''.
   *
   * @param realmId - the trust realm
   * @returns the reason
   */
  encryptionOffReason(realmId?: string): string {
    const self = this;
    const { log, mode } = this.deps;
    log.debug("Entering KeyRenewal.encryptionOffReason().");
    const why = this.inRealm(String(realmId || ''), function (): string {
      if (!mode().rotatesSigningKeys()) {
        return 'development mode, whose keys are made anew at every start';
      }
      if (!(self.encryptionIntervalMs() > 0)) {
        return 'keys.encryptionKeyRotationIntervalDays is 0';
      }
      return '';
    });
    log.debug("Leaving KeyRenewal.encryptionOffReason(). " + (why || 'on'));
    return why;
  }

  /**
   * The scheduled run for one realm: every kind of request-decryption key
   * whose key is a whole interval old is replaced, the replaced one still
   * decrypting for the overlap.
   *
   * @param realmId - the trust realm
   * @param ctx - the scheduler's run context
   * @returns a promise of `{ summary, rotated }`
   */
  async rotateEncryptionKeysDue(realmId: string, ctx?: Json): Promise<Json> {
    const self = this;
    const { log, keys, audit, errorCodes } = this.deps;
    log.debug("Entering KeyRenewal.rotateEncryptionKeysDue(). realm=" +
              realmId);
    const nowMs = ctx && ctx.nowMs ? ctx.nowMs() : this.deps.now();
    const interval = this.encryptionIntervalMs();
    const held = keys().encryptionKeysHeld(
      keys().stsKeysFor.of(String(realmId || realms.DEFAULT_ID)));
    const kinds: string[] = [];
    this.inRealm(realmId, function (): void {
      const kept: string[] = [];
      held.forEach(function (one: Json): void {
        const id = 'enc:' + one.kind + ':' + one.kid;
        kept.push(id);
        if (nowMs - self.firstSeen(id, nowMs) >= interval &&
            kinds.indexOf(one.kind) < 0) {
          kinds.push(one.kind);
        }
      });
      self.forgetOthers('enc:', kept);
    });
    if (!kinds.length) {
      log.debug("Leaving KeyRenewal.rotateEncryptionKeysDue(). Not due.");
      return { summary: '0 rotated of ' + held.length + ' key(s)',
               rotated: [] };
    }
    if (ctx && typeof ctx.stillOwner === 'function' && !ctx.stillOwner()) {
      log.debug("Leaving KeyRenewal.rotateEncryptionKeysDue(). No longer " +
                "the owner.");
      return { summary: 'not rotated: this node no longer owns the run',
               rotated: [] };
    }
    const done = await keys().rotateEncryptionKeys(realmId, kinds,
      this.encryptionOverlapMs(), 'a scheduled rotation of the ' +
      'request-decryption keys (' + kinds.join(', ') + ')');
    if (!done || !done.ok) {
      const why = String((done && done.why) || 'refused');
      log.error(errorCodes.tag('STS-KEYS-0214') + 'key renewal: the "' +
                (realmId || 'default') + '" realm\'s request-decryption ' +
                'keys (' + kinds.join(', ') + ') could not be rotated: ' +
                why + '. They go on as they are; the next run tries again.');
      audit().record({
        action: 'keys.encryption.rotate', protocol: 'Keys',
        channel: 'scheduler', outcome: 'failure', realm: realmId,
        errorCode: 'STS-KEYS-0214',
        summary: 'The request-decryption keys could not be rotated',
        detail: { kinds: kinds, why: why }
      });
      log.debug("Leaving KeyRenewal.rotateEncryptionKeysDue(). Refused.");
      throw errorCodes.mark(new Error('the request-decryption keys could ' +
        'not be rotated: ' + why), 'STS-KEYS-0214');
    }
    this.inRealm(realmId, function (): void {
      done.rotated.forEach(function (one: Json): void {
        self.firstSeen('enc:' + one.kind + ':' + one.to, nowMs);
      });
    });
    audit().record({
      action: 'keys.encryption.rotate', protocol: 'Keys',
      channel: 'scheduler', outcome: 'success', realm: realmId,
      summary: done.rotated.length + ' request-decryption key(s) of the "' +
               (realmId || 'default') + '" realm replaced; each replaced ' +
               'key still decrypts for ' +
               Math.round(this.encryptionOverlapMs() / DAY_MS) + ' day(s)',
      detail: { rotated: done.rotated, generation: done.generation }
    });
    log.debug("Leaving KeyRenewal.rotateEncryptionKeysDue(). " +
              done.rotated.length + ".");
    return { summary: done.rotated.length + ' rotated',
             rotated: done.rotated };
  }

  // The three jobs, registered once per process.
  /**
   * Registers the three jobs, once per process.
   *
   * @returns whether they were registered now
   */
  registerJobs(): boolean {
    const { log, scheduler } = this.deps;
    log.debug("Entering KeyRenewal.registerJobs().");
    const s = scheduler();
    if (s.job(CA_JOB)) {
      log.debug("Leaving KeyRenewal.registerJobs(). Already there.");
      return false;
    }
    const self = this;
    s.register({
      id: CA_JOB,
      title: 'CA certificate renewal',
      describe: 'Renews the Root, then each Intermediate, then each Issuing ' +
                'CA inside its lead (pki.rootRenewalLeadDays, ' +
                'pki.caRenewalLeadDays) over the same key and subject, so ' +
                'everything it signed still verifies. A renewed Root is ' +
                'published beside the one it replaces until that expires. ' +
                'An imported CA is the operator\'s to renew.',
      owner: 'common/key_renewal.ts',
      kind: 'cluster', scope: 'service',
      everyMs: function (): number {
        return DAY_MS;
      },
      off: function (): string {
        return self.caOffReason();
      },
      manual: false,
      run: function (ctx: Json): Promise<Json> {
        return self.renewCasDue(ctx);
      }
    });
    s.register({
      id: CREDENTIAL_JOB,
      title: 'Credential signer rotation',
      describe: 'Moves each dedicated credential signer\'s key family on to ' +
                'a new key once its key is ' +
                'keys.credentialSignerRotationIntervalDays old. The key it ' +
                'replaces signs nothing more and stays published, so every ' +
                'credential it signed goes on verifying.',
      owner: 'common/key_renewal.ts',
      kind: 'cluster', scope: 'realm',
      everyMs: function (): number {
        return HOUR_MS;
      },
      off: function (realmId: string): string {
        return self.credentialOffReason(realmId);
      },
      manual: true,
      run: function (ctx: Json): Promise<Json> {
        return self.rotateCredentialSignersDue(ctx.realm, ctx);
      }
    });
    s.register({
      id: ENCRYPTION_JOB,
      title: 'Request decryption key rotation',
      describe: 'Replaces the request object encryption keys, the ' +
                'OpenID4VCI request-encryption key and the KEM decryption ' +
                'keys once they are keys.encryptionKeyRotationIntervalDays ' +
                'old. The new key is published at once; the one it replaces ' +
                'still decrypts for keys.encryptionKeyOverlapDays.',
      owner: 'common/key_renewal.ts',
      kind: 'cluster', scope: 'realm',
      everyMs: function (): number {
        return HOUR_MS;
      },
      off: function (realmId: string): string {
        return self.encryptionOffReason(realmId);
      },
      manual: true,
      run: function (ctx: Json): Promise<Json> {
        return self.rotateEncryptionKeysDue(ctx.realm, ctx);
      }
    });
    log.debug("Leaving KeyRenewal.registerJobs().");
    return true;
  }
}

const slot = new InstanceSlot<KeyRenewal>(
  'common/key_renewal',
  () => new KeyRenewal(KeyRenewal.defaultDeps()),
  function (instance: KeyRenewal): void {
    instance.registerJobs();
  },
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The scheduled renewal of the CA certificates, the credential signers and
 * the request-decryption keys (#2220).
 *
 * A library: it registers three scheduler jobs and no route.
 *
 * @namespace
 */
export = {
  KeyRenewal: KeyRenewal,
  /**
   * Installs the instance the composition root built.
   *
   * @param instance - the instance to install
   */
  installInstance: (instance: KeyRenewal): void => slot.install(instance),
  /**
   * Says whether the installed instance came from the root or the default.
   *
   * @returns `root`, `default` or `none`
   */
  instanceOrigin: (): string => slot.origin(),
  CA_JOB: CA_JOB,
  CREDENTIAL_JOB: CREDENTIAL_JOB,
  ENCRYPTION_JOB: ENCRYPTION_JOB,
  /** Forwards to `KeyRenewal.renewCasDue()` on the installed instance. */
  renewCasDue: slot.forward('renewCasDue'),
  /**
   * Forwards to `KeyRenewal.rotateCredentialSignersDue()` on the installed
   * instance.
   */
  rotateCredentialSignersDue: slot.forward('rotateCredentialSignersDue'),
  /**
   * Forwards to `KeyRenewal.rotateEncryptionKeysDue()` on the installed
   * instance.
   */
  rotateEncryptionKeysDue: slot.forward('rotateEncryptionKeysDue'),
  /** Forwards to `KeyRenewal.caOffReason()` on the installed instance. */
  caOffReason: slot.forward('caOffReason'),
  /**
   * Forwards to `KeyRenewal.credentialOffReason()` on the installed instance.
   */
  credentialOffReason: slot.forward('credentialOffReason'),
  /**
   * Forwards to `KeyRenewal.encryptionOffReason()` on the installed instance.
   */
  encryptionOffReason: slot.forward('encryptionOffReason'),
  /** Forwards to `KeyRenewal.firstSeen()` on the installed instance. */
  firstSeen: slot.forward('firstSeen')
};
