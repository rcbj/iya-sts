// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: data_key_rotation.ts
//
// ===========================================================================
// DATA ENCRYPTION KEY ROTATION AND RE-ENCRYPTION, ON THE SCHEDULER (#391 P2).
//
// Every sealed value is sealed under a data encryption key (DEK) — one per
// realm and data class, wrapped by the key-encryption key — and the DEKs are
// `common/keystore.js`'s: it makes them, rotates them, re-seals a value under
// the current one and destroys one. This module decides WHEN, and does
// nothing to a key itself (`common/signing_rotation.ts`'s arrangement for the
// signing keys).
//
// rcbj's decision on #391: a yearly scheduled rotation of every DEK, a job
// that re-encrypts what the old DEK sealed, and a rotation by hand from the
// console and the API.
//
// THREE JOBS, ALL CLUSTER JOBS FOR THE WHOLE SERVICE (run once, on the
// leader; a DEK names its realm, so one run reaches every realm):
//
//   `keys.data-key-rotate`        daily. A slot whose current DEK has been
//                                 current for `keys.dataKeyRotationDays` (365;
//                                 0 is off) is given a new one, published
//                                 `keys.dataKeyActivationLeadSeconds` before
//                                 anything is sealed under it.
//   `keys.data-key-rotate-now`    manual only: the rotation an administrator
//                                 asks for, of every DEK or of one realm or
//                                 one class (`/admin/encryption`,
//                                 `POST /admin-api/encryption/rotate-data-keys`).
//   `keys.data-key-reencrypt`     hourly. Re-seals this process's own key and
//                                 certificate-authority rows, then every
//                                 value in the store still sealed under a
//                                 SUPERSEDED DEK, then DESTROYS each
//                                 superseded DEK nothing is sealed under any
//                                 longer and that has been superseded for
//                                 `keys.dataKeyRetireAfterDays`.
//
// WHERE NOTHING IS STORED THERE IS NOTHING TO DO. In development mode, and
// anywhere the key-encryption key does not outlive the process, a DEK is
// DERIVED from the key per run and never written, so the jobs are off and
// say why. Where the store cannot count what is sealed (the `ldif` and
// `memory` stores) the re-encryption job still re-seals this process's own
// rows and destroys NOTHING: a key is destroyed only on a count of zero, and
// a store that cannot count never says zero.
//
// A LIBRARY THAT REGISTERS JOBS AND NO ROUTE, built by
// `common/protocol_stack.ts` beside `common/signing_rotation` (23b-ii).
// ===========================================================================

import helpers = require('./helpers');
import config = require('./config');
import errorCodes = require('./error_codes');
import InstanceSlot = require('./instance_slot');

type Json = any;

/**
 * The daily scheduled rotation job's id.
 */
const ROTATE_JOB = 'keys.data-key-rotate';
/**
 * The id of the manual rotation job the console and the API queue.
 */
const ROTATE_NOW_JOB = 'keys.data-key-rotate-now';
/**
 * The hourly re-encryption and destruction job's id.
 */
const REENCRYPT_JOB = 'keys.data-key-reencrypt';
const HOUR_MS = 3600000;
const DAY_MS = 86400000;
// How many rows of each table one pass re-seals per DEK. A pass that leaves
// rows behind is followed by the next, an hour later; the bound keeps one
// pass from holding a database connection for minutes.
const RESEAL_BATCH = 500;

interface DataKeyRotationDeps {
  log: typeof helpers.log;
  config: typeof config;
  errorCodes: typeof errorCodes;
  // Lazily, each: the keystore is loaded long before this module and needs
  // nothing from it, the scheduler requires `helpers`, and the audit log is
  // a leaf this module reaches only when it writes a row.
  keystore: () => Json;
  scheduler: () => Json;
  audit: () => Json;
  now: () => number;
}

/**
 * Decides when the data encryption keys rotate, re-seals what a superseded
 * key sealed, and destroys a superseded key nothing is sealed under.
 *
 * It changes no key itself: every change goes through `common/keystore.js`.
 */
class DataKeyRotation {
  /**
   * The module's `ROTATE_JOB`.
   */
  static readonly ROTATE_JOB = ROTATE_JOB;
  /**
   * The module's `ROTATE_NOW_JOB`.
   */
  static readonly ROTATE_NOW_JOB = ROTATE_NOW_JOB;
  /**
   * The module's `REENCRYPT_JOB`.
   */
  static readonly REENCRYPT_JOB = REENCRYPT_JOB;

  /**
   * Builds the instance over its dependencies.
   *
   * @param deps - the modules it uses, most of them reached lazily, and a clock
   */
  constructor(private readonly deps: DataKeyRotationDeps) {
    deps.log.debug("Entering DataKeyRotation.constructor().");
    deps.log.debug("Leaving DataKeyRotation.constructor().");
  }

  /**
   * Returns the dependencies the composition root builds the instance with.
   *
   * @returns the real modules and `Date.now`
   */
  static defaultDeps(): DataKeyRotationDeps {
    helpers.log.debug("Entering DataKeyRotation.defaultDeps().");
    helpers.log.debug("Leaving DataKeyRotation.defaultDeps().");
    return {
      log: helpers.log,
      config: config,
      errorCodes: errorCodes,
      keystore: function (): Json {
        return require('./keystore');
      },
      scheduler: function (): Json {
        return require('../cluster/scheduler');
      },
      audit: function (): Json {
        return require('./audit');
      },
      now: function (): number {
        return Date.now();
      }
    };
  }

  /**
   * Why the jobs are off now, or '' when they are on.
   *
   * @returns the reason, in a sentence's middle
   */
  offReason(): string {
    const { log, keystore } = this.deps;
    log.debug("Entering DataKeyRotation.offReason().");
    if (!keystore().deksStored()) {
      log.debug("Leaving DataKeyRotation.offReason(). Derived.");
      return 'data encryption keys are derived per run here and never ' +
             'stored, so there is nothing to rotate';
    }
    log.debug("Leaving DataKeyRotation.offReason(). On.");
    return '';
  }

  /**
   * Why the SCHEDULED rotation is off now, or '' when it is on.
   *
   * @returns the reason
   */
  scheduleOffReason(): string {
    const { log, config } = this.deps;
    log.debug("Entering DataKeyRotation.scheduleOffReason().");
    const off = this.offReason();
    if (off) {
      log.debug("Leaving DataKeyRotation.scheduleOffReason(). Off.");
      return off;
    }
    if (!(Number(config.value('keys.dataKeyRotationDays')) > 0)) {
      log.debug("Leaving DataKeyRotation.scheduleOffReason(). Interval 0.");
      return 'keys.dataKeyRotationDays is 0';
    }
    log.debug("Leaving DataKeyRotation.scheduleOffReason(). On.");
    return '';
  }

  /**
   * Rotates the DEKs that are due: each slot whose current DEK has been
   * current for `keys.dataKeyRotationDays`.
   *
   * @param ctx - the scheduler's run context
   * @returns `{ rotated }`, the number of new DEKs
   */
  rotateDue(ctx: Json): Json {
    const { log, config, keystore } = this.deps;
    log.debug("Entering DataKeyRotation.rotateDue().");
    const due = keystore().rotationDue(
      Number(config.value('keys.dataKeyRotationDays')));
    let rotated: Json[] = [];
    for (const one of due) {
      const done = keystore().rotateDeks({ scope: one.scope, realm: one.realm,
                                           cls: one.cls,
                                           reason: 'scheduled' });
      if (done.ok) {
        rotated = rotated.concat(done.rotated);
      }
    }
    if (rotated.length) {
      this.recordRotation(rotated, 'scheduled', '', ctx);
    }
    log.debug("Leaving DataKeyRotation.rotateDue(). " + rotated.length + ".");
    return { rotated: rotated.length,
             summary: rotated.length + ' data encryption key(s) rotated' };
  }

  /**
   * Rotates the DEKs an administrator asked for: every one, or one realm's,
   * or one class's.
   *
   * @param params - `{ realm, cls }`, each optional
   * @param ctx - the scheduler's run context
   * @returns `{ rotated }`
   */
  rotateNow(params: Json, ctx: Json): Json {
    const { log, keystore, errorCodes } = this.deps;
    log.debug("Entering DataKeyRotation.rotateNow().");
    const p = params || {};
    const done = keystore().rotateDeks({
      realm: p.realm === undefined || p.realm === null ? undefined
        : String(p.realm),
      cls: p.cls ? String(p.cls) : undefined,
      reason: 'requested' });
    if (!done.ok) {
      log.debug("Leaving DataKeyRotation.rotateNow(). Refused.");
      throw errorCodes.mark(new Error(done.why), 'STS-KEYS-0100');
    }
    this.recordRotation(done.rotated, 'requested',
                        String((ctx && ctx.requestedBy) || ''), ctx);
    log.debug("Leaving DataKeyRotation.rotateNow(). " + done.rotated.length +
              ".");
    return { rotated: done.rotated.length,
             summary: done.rotated.length + ' data encryption key(s) ' +
                      'rotated by hand' };
  }

  // One audit row per act, however many keys it moved; the ids and slots are
  // in the detail and never a key.
  private recordRotation(rotated: Json[], reason: string, by: string,
                         ctx: Json): void {
    const { log, audit } = this.deps;
    log.debug("Entering DataKeyRotation.recordRotation().");
    audit().record({
      action: 'keys.data-key-rotate', protocol: 'Keys',
      channel: 'scheduler', outcome: 'success', realm: '',
      actor: by,
      summary: rotated.length + ' data encryption key(s) rotated (' + reason +
               '); each is used once it has been published',
      detail: { reason: reason, trigger: String((ctx && ctx.trigger) || ''),
                rotated: rotated.map(function (r: Json): Json {
                  return { id: r.id, realm: r.realm, cls: r.cls,
                           scope: r.scope, activateAt: r.activateAt };
                }) }
    });
    log.debug("Leaving DataKeyRotation.recordRotation().");
  }

  /**
   * One pass of the re-encryption job: re-seals this process's own rows,
   * then what the store holds under a superseded DEK, then destroys each
   * superseded DEK nothing is sealed under any longer and that has been
   * superseded long enough.
   *
   * @param ctx - the scheduler's run context
   * @returns `{ superseded, ownRows, resealed, destroyed, remaining }`
   */
  async reencrypt(ctx: Json): Promise<Json> {
    const { log, config, keystore, errorCodes, now } = this.deps;
    log.debug("Entering DataKeyRotation.reencrypt().");
    const ks = keystore();
    // The DEKs a re-seal seals under must be in the store before a single
    // row names them: a process that read the row and not the key could not
    // open it.
    await ks.settleDeks();
    const ownRows = ks.resealOwnRows();
    await ks.settleAll();
    const superseded: Json[] = ks.supersededDeks();
    if (!superseded.length) {
      log.debug("Leaving DataKeyRotation.reencrypt(). Nothing superseded.");
      return { superseded: 0, ownRows: ownRows, resealed: 0, destroyed: 0,
               remaining: 0, summary: 'no superseded data encryption key' +
               (ownRows ? '; ' + ownRows + ' own row(s) re-sealed' : '') };
    }
    const store = ks.sealedStore();
    if (!store) {
      log.debug("Leaving DataKeyRotation.reencrypt(). No counting store.");
      return { superseded: superseded.length, ownRows: ownRows, resealed: 0,
               destroyed: 0, remaining: null,
               summary: superseded.length + ' superseded data encryption ' +
                        'key(s) kept: this store cannot count what is sealed ' +
                        'under them, so none is destroyed' };
    }
    const ids = superseded.map(function (d: Json): string {
      return d.id;
    });
    let tally: Json;
    let counts: Json;
    try {
      tally = await store.reseal(ids, function (cipher: string): Json {
        return ks.reseal(cipher);
      }, { limit: RESEAL_BATCH });
      counts = await store.count(ids);
    } catch (e) {
      const why = (e && (e as Error).message) || String(e);
      log.error(errorCodes.tag('STS-KEYS-0099') + 'data keys: the ' +
                're-encryption pass failed and nothing was destroyed: ' + why);
      log.debug("Leaving DataKeyRotation.reencrypt(). Failed.");
      throw errorCodes.mark(new Error('the re-encryption pass failed: ' + why),
                            'STS-KEYS-0099');
    }
    const resealed = (Number(tally.minted) || 0) +
                     (Number(tally.entries) || 0) +
                     (Number(tally.secrets) || 0);
    const retireMs = Math.max(1, Number(config.value(
      'keys.dataKeyRetireAfterDays')) || 1) * DAY_MS;
    const at = now();
    const doomed = superseded.filter(function (d: Json): boolean {
      return Number(counts[d.id]) === 0 && at - d.supersededAt >= retireMs;
    }).map(function (d: Json): string {
      return d.id;
    });
    const remaining = ids.reduce(function (sum: number, id: string): number {
      return sum + (Number(counts[id]) || 0);
    }, 0);
    const destroyed = doomed.length ? ks.destroyDeks(doomed) : 0;
    if (destroyed) {
      await ks.settleDeks();
    }
    if (resealed) {
      this.deps.audit().record({
        action: 'keys.data-key-reencrypt', protocol: 'Keys',
        channel: 'scheduler', outcome: 'success', realm: '',
        summary: resealed + ' value(s) re-sealed under the current data ' +
                 'encryption keys; ' + remaining + ' still under a ' +
                 'superseded one',
        detail: { minted: tally.minted, entries: tally.entries,
                  secrets: tally.secrets, skipped: tally.skipped,
                  ownRows: ownRows, remaining: remaining,
                  trigger: String((ctx && ctx.trigger) || '') }
      });
    }
    if (destroyed) {
      this.deps.audit().record({
        action: 'keys.data-key-destroy', protocol: 'Keys',
        channel: 'scheduler', outcome: 'success', realm: '',
        summary: destroyed + ' superseded data encryption key(s) destroyed: ' +
                 'nothing in the store was sealed under them',
        detail: { destroyed: doomed }
      });
    }
    log.info('data keys: ' + superseded.length + ' superseded, ' + resealed +
             ' value(s) re-sealed, ' + remaining + ' still under a ' +
             'superseded key, ' + destroyed + ' key(s) destroyed.');
    log.debug("Leaving DataKeyRotation.reencrypt().");
    return { superseded: superseded.length, ownRows: ownRows,
             resealed: resealed, destroyed: destroyed, remaining: remaining,
             summary: resealed + ' re-sealed, ' + remaining + ' remaining, ' +
                      destroyed + ' destroyed' };
  }

  /**
   * Queues a rotation by hand, for the console and the API.
   *
   * @param options - `{ realm, cls, requestedBy, via, channel }`
   * @returns `{ ok, runId, alreadyQueued }` or `{ ok: false, errorCode,
   * status, why }`
   */
  requestRotation(options: Json): Json {
    const { log, scheduler } = this.deps;
    const o = options || {};
    log.debug("Entering DataKeyRotation.requestRotation().");
    const off = this.offReason();
    if (off) {
      log.debug("Leaving DataKeyRotation.requestRotation(). Off.");
      return { ok: false, errorCode: 'STS-KEYS-0100', status: 400,
               why: 'Nothing to rotate: ' + off + '.' };
    }
    const realm = o.realm === undefined || o.realm === null ? undefined
      : String(o.realm);
    const cls = o.cls ? String(o.cls) : undefined;
    const held: Json[] = this.deps.keystore().dataKeys();
    const matches = held.filter(function (d: Json): boolean {
      return !d.derived && d.status !== 'destroyed' &&
        (realm === undefined || d.realm === (realm || 'default')) &&
        (!cls || d.cls === cls.toLowerCase());
    });
    if (!matches.length) {
      log.debug("Leaving DataKeyRotation.requestRotation(). No match.");
      return { ok: false, errorCode: 'STS-KEYS-0100', status: 400,
               why: 'No stored data encryption key serves ' +
                    (realm !== undefined ? 'the realm "' + realm + '"' :
                     'this service') +
                    (cls ? ' for the class "' + cls + '"' : '') + '.' };
    }
    const answer = scheduler().requestRun(ROTATE_NOW_JOB, {
      params: { realm: realm, cls: cls },
      requestedBy: String(o.requestedBy || ''), via: String(o.via || ''),
      channel: String(o.channel || 'console') });
    log.debug("Leaving DataKeyRotation.requestRotation(). " +
              (answer.ok ? answer.runId : answer.why));
    return answer.ok
      ? { ok: true, runId: answer.runId, alreadyQueued: !!answer.alreadyQueued }
      : { ok: false, errorCode: answer.errorCode, status: answer.status || 400,
          why: answer.why };
  }

  /**
   * Queues a pass of the re-encryption job by hand.
   *
   * @param options - `{ requestedBy, via, channel }`
   * @returns the scheduler's answer
   */
  requestReencryption(options: Json): Json {
    const { log, scheduler } = this.deps;
    const o = options || {};
    log.debug("Entering DataKeyRotation.requestReencryption().");
    const off = this.offReason();
    if (off) {
      log.debug("Leaving DataKeyRotation.requestReencryption(). Off.");
      return { ok: false, errorCode: 'STS-KEYS-0100', status: 400,
               why: 'Nothing to re-encrypt: ' + off + '.' };
    }
    const answer = scheduler().requestRun(REENCRYPT_JOB, {
      requestedBy: String(o.requestedBy || ''), via: String(o.via || ''),
      channel: String(o.channel || 'console') });
    log.debug("Leaving DataKeyRotation.requestReencryption().");
    return answer.ok
      ? { ok: true, runId: answer.runId, alreadyQueued: !!answer.alreadyQueued }
      : { ok: false, errorCode: answer.errorCode, status: answer.status || 400,
          why: answer.why };
  }

  /**
   * What `/admin/encryption` and `GET /admin-api/encryption` draw of the
   * lifecycle: whether the jobs run and on what settings.
   *
   * @returns the lifecycle view
   */
  lifecycleView(): Json {
    const { log, config } = this.deps;
    log.debug("Entering DataKeyRotation.lifecycleView().");
    const view = {
      on: this.offReason() === '',
      offReason: this.offReason(),
      scheduled: this.scheduleOffReason() === '',
      scheduleOffReason: this.scheduleOffReason(),
      rotationDays: Number(config.value('keys.dataKeyRotationDays')),
      activationLeadSeconds: Number(config.value(
        'keys.dataKeyActivationLeadSeconds')),
      retireAfterDays: Number(config.value('keys.dataKeyRetireAfterDays')),
      directoryCipher: String(config.value('keys.directoryCipher')),
      jobs: [ROTATE_JOB, ROTATE_NOW_JOB, REENCRYPT_JOB]
    };
    log.debug("Leaving DataKeyRotation.lifecycleView().");
    return view;
  }

  /**
   * Registers the three jobs with the scheduler, once per process.
   *
   * @returns true when registered, false when they already were
   */
  registerJobs(): boolean {
    const { log, scheduler } = this.deps;
    log.debug("Entering DataKeyRotation.registerJobs().");
    const s = scheduler();
    if (s.job(ROTATE_JOB)) {
      log.debug("Leaving DataKeyRotation.registerJobs(). Already there.");
      return false;
    }
    const self = this;
    s.register({
      id: ROTATE_JOB,
      title: 'Data encryption key rotation',
      describe: 'Gives every data encryption key that has sealed new values ' +
                'for keys.dataKeyRotationDays a successor, published ' +
                'keys.dataKeyActivationLeadSeconds before anything is sealed ' +
                'under it; the re-encryption job then re-seals what the old ' +
                'key sealed.',
      owner: 'common/data_key_rotation.ts',
      kind: 'cluster', scope: 'service',
      everyMs: function (): number {
        return DAY_MS;
      },
      off: function (): string {
        return self.scheduleOffReason();
      },
      manual: true,
      run: function (ctx: Json): Json {
        return self.rotateDue(ctx);
      }
    });
    // A job of its own rather than a manual run of the one above, because
    // that one is OFF where the interval is 0 and a rotation by hand must
    // not be; `params` names a realm, a class, both or neither.
    s.register({
      id: ROTATE_NOW_JOB,
      title: 'Data encryption key rotation, by hand',
      describe: 'Rotates every stored data encryption key now — or one ' +
                'realm\'s, or one class\'s; the keys they replace go on ' +
                'opening what they sealed until it is re-sealed.',
      owner: 'common/data_key_rotation.ts',
      kind: 'cluster', scope: 'service', manualOnly: true, manual: true,
      off: function (): string {
        return self.offReason();
      },
      run: function (ctx: Json): Json {
        return self.rotateNow(ctx.params || {}, ctx);
      }
    });
    s.register({
      id: REENCRYPT_JOB,
      title: 'Data re-encryption and key destruction',
      describe: 'Re-seals every value still sealed under a superseded data ' +
                'encryption key under the current one, and destroys a ' +
                'superseded key once nothing is sealed under it and it has ' +
                'been superseded for keys.dataKeyRetireAfterDays.',
      owner: 'common/data_key_rotation.ts',
      kind: 'cluster', scope: 'service',
      everyMs: function (): number {
        return HOUR_MS;
      },
      off: function (): string {
        return self.offReason();
      },
      manual: true,
      timeoutS: 1800,
      run: function (ctx: Json): Promise<Json> {
        return self.reencrypt(ctx);
      }
    });
    log.debug("Leaving DataKeyRotation.registerJobs().");
    return true;
  }
}

const slot = new InstanceSlot<DataKeyRotation>(
  'common/data_key_rotation',
  () => new DataKeyRotation(DataKeyRotation.defaultDeps()),
  function (instance: DataKeyRotation): void {
    instance.registerJobs();
  },
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * Data encryption key rotation, re-encryption and destruction on the
 * scheduler (#391 P2).
 *
 * A library that registers jobs and no route. The method names below forward
 * to the instance the composition root installs.
 * @namespace
 */
export = {
  DataKeyRotation: DataKeyRotation,
  /**
   * Installs the instance the composition root built.
   */
  installInstance: (instance: DataKeyRotation): void => slot.install(instance),
  /**
   * Names where the installed instance came from.
   */
  instanceOrigin: (): string => slot.origin(),
  ROTATE_JOB: ROTATE_JOB,
  ROTATE_NOW_JOB: ROTATE_NOW_JOB,
  REENCRYPT_JOB: REENCRYPT_JOB,
  offReason: slot.forward('offReason'),
  scheduleOffReason: slot.forward('scheduleOffReason'),
  rotateDue: slot.forward('rotateDue'),
  rotateNow: slot.forward('rotateNow'),
  reencrypt: slot.forward('reencrypt'),
  requestRotation: slot.forward('requestRotation'),
  requestReencryption: slot.forward('requestReencryption'),
  lifecycleView: slot.forward('lifecycleView')
};
