// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: service_account_rotation.ts
//
// ---------------------------------------------------------------------------
// A SERVICE ACCOUNT'S PASSWORD, ROTATED AND PUSHED (#221 P4, 2026-10-06).
//
// rcbj's decisions 3 and 5: "Automatic password rotation, plus a push of each
// new password to any of the supported secrets managers", and "The new
// password is pushed first and its hash committed only after that. The
// previous password stays valid for a configurable grace period. If the push
// fails, nothing changes."
//
// **THE ORDER, AND WHY EACH STEP IS WHERE IT IS:**
//
//   1. A per-account CLAIM (`cluster_claims`, scope
//      `service-accounts.rotate`, the account and its last rotation as the
//      value). The job runs on one node already (#49); the claim is what
//      keeps a Rotate now by hand and the job from rotating one account
//      twice at once, each pushing a password the other then overwrites.
//   2. A password from the PASSWORD POLICY's generator, at the
//      service-account policy's length — so it meets the policy that
//      `credentials.preparePassword()` asks at every door (3ac).
//   3. The PUSH, to the account's destination, as a new version
//      (`common/secret_destinations.ts`). A failure here ENDS the rotation
//      with nothing changed: the old password is the one at the destination
//      and the one this service accepts, so every consumer still works. The
//      failure is counted on the entry and retried at the job's next run;
//      at the policy's `rotationAlarmFailures` it is an alarm
//      (STS-SVCACCT-0042).
//   4. Only then the COMMIT, through `credentials.setPassword()` with
//      `rotation` — which keeps the hash it replaces as the previous
//      password until the overlap ends, records the rotation's time, and
//      tells the KDC (whose keys are derived from the new password) to hold
//      the retired key version at least as long.
//   5. CAEP `credential-change` (`update`, `password`, initiated by the
//      `system`) and an audit row.
//
// **A COMMIT THAT FAILS AFTER A PUSH THAT SUCCEEDED** is the one state that
// is not "nothing changed": the destination holds a password this service
// does not accept. It is counted and alarmed at once (STS-SVCACCT-0045)
// rather than at the threshold, and the next run pushes and commits another.
// It cannot be undone here, because the push never deletes a version — the
// destination's own history is what an operator restores from.
//
// **THE PLAINTEXT IS NEVER LOGGED, DRAWN OR KEPT** beyond the push and the
// commit: it is a local of `rotateOne()`.
//
// ---------------------------------------------------------------------------
// THE JOBS (#49: anything periodic is a scheduler job), all three cluster
// jobs scoped per realm:
//
//   service-accounts.rotate            every hour: every service account
//                                      whose interval has passed, where the
//                                      realm's policy turns rotation on.
//   service-accounts.rotate-now        manual only: one account, now —
//                                      what Rotate now and POST
//                                      /admin-api/users/rotate-password
//                                      queue.
//   service-accounts.previous-cleanup  every hour: clears a previous
//                                      password whose overlap has ended.
//                                      Housekeeping only — the overlap is
//                                      CHECKED where the password is read
//                                      (`service_accounts.previousPassword()`),
//                                      so a run that is late changes nothing
//                                      anybody can observe.
//
// IT IS A LIBRARY (rule 3): it registers jobs and no route. Everything it
// reaches is reached lazily, because it is built with the scheduler's other
// job owners (18-row) and its collaborators — the destinations, Shared
// Signals — are built at other places in the composition root.
// ---------------------------------------------------------------------------

import helpers = require('./helpers');
import errorCodes = require('./error_codes');
import InstanceSlot = require('./instance_slot');

const { log } = helpers;

type Json = any;

/**
 * The hourly rotation job's id.
 */
const ROTATE_JOB = 'service-accounts.rotate';

/**
 * The by-hand rotation job's id.
 */
const ROTATE_NOW_JOB = 'service-accounts.rotate-now';

/**
 * The previous-password clean-up job's id.
 */
const CLEANUP_JOB = 'service-accounts.previous-cleanup';

/**
 * The claim scope that keeps one account from rotating twice at once.
 */
const CLAIM_SCOPE = 'service-accounts.rotate';

const HOUR_MS = 60 * 60 * 1000;

// How long one rotation's claim is held: long enough for a push to a slow
// secrets manager, short enough that a node that died mid-rotation does not
// hold an account for long.
const CLAIM_TTL_MS = 5 * 60 * 1000;

interface RotationDeps {
  log: typeof helpers.log;
  errorCodes: typeof errorCodes;
  now(): number;
  realms(): Json;
  serviceAccounts(): Json;
  policy(): Json;
  passwordPolicy(): Json;
  credentials(): Json;
  destinations(): Json | null;
  claims(): Json;
  scheduler(): Json;
  accountSignals(): Json | null;
  audit(): Json;
}

/**
 * Service-account password rotation (#221): generate, push to the account's
 * destination, and only then commit — with the previous password kept for the
 * policy's overlap. Three scheduler jobs; a library that registers no route.
 */
class ServiceAccountRotation {
  /**
   * The hourly rotation job's id.
   */
  static readonly ROTATE_JOB = ROTATE_JOB;
  /**
   * The by-hand rotation job's id.
   */
  static readonly ROTATE_NOW_JOB = ROTATE_NOW_JOB;
  /**
   * The previous-password clean-up job's id.
   */
  static readonly CLEANUP_JOB = CLEANUP_JOB;

  /**
   * Builds the rotation over its collaborators.
   *
   * @param deps - the logger, error codes, a clock, and lazy reaches of every
   *   module it uses
   */
  constructor(private readonly deps: RotationDeps) {
    deps.log.debug("Entering ServiceAccountRotation.constructor().");
    deps.log.debug("Leaving ServiceAccountRotation.constructor().");
  }

  /**
   * Returns the dependencies the default instance is built from, every module
   * reached lazily.
   *
   * @returns the dependencies
   */
  static defaultDeps(): RotationDeps {
    log.debug("Entering ServiceAccountRotation.defaultDeps().");
    const optional = function (path: string): Json | null {
      log.debug("Entering ServiceAccountRotation optional(). " + path);
      try {
        const mod = require(path);
        log.debug("Leaving ServiceAccountRotation optional().");
        return mod;
      } catch (e) {
        log.debug("Caught in ServiceAccountRotation optional(): " +
                  ((e && e.message) || e));
        log.debug("Leaving ServiceAccountRotation optional(). Absent.");
        return null;
      }
    };
    log.debug("Leaving ServiceAccountRotation.defaultDeps().");
    return {
      log: log,
      errorCodes: errorCodes,
      now: function (): number {
        return Date.now();
      },
      realms: function (): Json {
        return require('./realms');
      },
      serviceAccounts: function (): Json {
        return require('./service_accounts');
      },
      policy: function (): Json {
        return require('./service_account_policy');
      },
      passwordPolicy: function (): Json {
        return require('./password_policy');
      },
      credentials: function (): Json {
        return require('./credentials');
      },
      destinations: function (): Json | null {
        return optional('./secret_destinations');
      },
      claims: function (): Json {
        return require('../cluster/cluster_claims');
      },
      scheduler: function (): Json {
        return require('../cluster/scheduler');
      },
      accountSignals: function (): Json | null {
        return optional('../ssf/account_signals');
      },
      audit: function (): Json {
        return require('./audit');
      }
    };
  }

  // The realm `id` names, entered for `fn`.
  private inRealm<T>(realmId: string, fn: () => T): T {
    const { log } = this.deps;
    log.debug("Entering ServiceAccountRotation.inRealm(). " + realmId);
    const realms = this.deps.realms();
    const realm = realmId ? realms.get(realmId) : null;
    log.debug("Leaving ServiceAccountRotation.inRealm().");
    return realm ? realms.run(realm, fn) : fn();
  }

  private record(action: string, target: string, outcome: string,
                 summary: string, detail: Json, code?: string): void {
    const { log } = this.deps;
    log.debug("Entering ServiceAccountRotation.record(). " + action);
    try {
      this.deps.audit().record({
        category: 'authentication', action: action, actor: 'system',
        target: target, outcome: outcome, summary: summary,
        errorCode: code || undefined, detail: detail
      });
    } catch (e) {
      log.debug("Caught in ServiceAccountRotation.record(): " +
                ((e && e.message) || e));
      // An audit ring that refused is not a reason a rotation fails; the log
      // line beside every row here still says what happened.
    }
    log.debug("Leaving ServiceAccountRotation.record().");
  }

  // A failure counted on the entry, and the alarm where it is due.
  private failed(username: string, code: string, why: string,
                 alarmNow: boolean): Json {
    const { log, errorCodes } = this.deps;
    log.debug("Entering ServiceAccountRotation.failed(). " + code);
    const failures = this.deps.serviceAccounts().recordFailure(username, code);
    const threshold = this.deps.policy().rotation().alarmFailures;
    const alarm = alarmNow || failures >= threshold;
    if (alarm) {
      log.error(errorCodes.tag(alarmNow ? 'STS-SVCACCT-0045'
                                        : 'STS-SVCACCT-0042') +
                'service-accounts: the password of ' + username + ' has ' +
                (alarmNow ? 'been PUSHED and NOT COMMITTED: the destination ' +
                  'holds a password this service does not accept'
                  : 'failed to rotate ' + failures + ' time(s) in a row') +
                ' (' + code + ': ' + why + ').');
    } else {
      log.warn(errorCodes.tag(code) + 'service-accounts: the password of ' +
               username + ' did not rotate (' + why + '); nothing changed, ' +
               'and the next run tries again.');
    }
    this.record('service-account.rotation-failed', username, 'failure',
                'the password of ' + username + ' did not rotate: ' + why,
                { failures: failures, alarm: alarm }, code);
    log.debug("Leaving ServiceAccountRotation.failed().");
    return errorCodes.mark({ ok: false, username: username, code: code,
                             error: why, failures: failures, alarm: alarm },
                           code);
  }

  /**
   * Rotates one service account's password in the AMBIENT realm: a claim,
   * a generated password, the push, and only then the commit with the
   * previous password kept for the overlap.
   *
   * Never throws.
   *
   * @param username - the account
   * @param ctx - `trigger` (`schedule` or `manual`), `requestedBy`, and the
   *   scheduler's `stillOwner()` where a job asked
   * @returns `{ ok, username, version, rotatedAt }`, or `{ ok: false, code,
   *   error, failures, alarm }`
   */
  async rotateOne(username: string, ctx?: Json): Promise<Json> {
    const { log, errorCodes } = this.deps;
    log.debug("Entering ServiceAccountRotation.rotateOne(). " + username);
    const c = ctx || {};
    const accounts = this.deps.serviceAccounts();
    const facts = accounts.of(username);
    if (!facts) {
      log.debug("Leaving ServiceAccountRotation.rotateOne(). Not one.");
      return errorCodes.mark({ ok: false, username: username,
                               code: 'STS-SVCACCT-0040',
                               error: username + ' is not a service ' +
                                      'account in this realm.' },
                             'STS-SVCACCT-0040');
    }
    if (!facts.destination || !facts.secretName) {
      log.debug("Leaving ServiceAccountRotation.rotateOne(). No " +
                "destination.");
      return errorCodes.mark({ ok: false, username: facts.username,
                               code: 'STS-SVCACCT-0041',
                               error: facts.username + ' names no push ' +
                                      'destination, so a rotated password ' +
                                      'would reach nobody.' },
                             'STS-SVCACCT-0041');
    }
    const destinations = this.deps.destinations();
    if (!destinations || typeof destinations.push !== 'function') {
      log.debug("Leaving ServiceAccountRotation.rotateOne(). No register.");
      return this.failed(facts.username, 'STS-SVCACCT-0044',
                         'the push destination register is not loaded in ' +
                         'this process', false);
    }
    const realms = this.deps.realms();
    const realmId = String(realms.currentId());
    const claims = this.deps.claims();
    const claimed = await claims.claim({
      scope: CLAIM_SCOPE,
      value: realmId + ':' + facts.username + ':' + (facts.rotatedAt || '-'),
      ttlMs: CLAIM_TTL_MS,
      realm: realmId
    });
    if (!claimed || !claimed.ok) {
      log.debug("Leaving ServiceAccountRotation.rotateOne(). Claimed " +
                "elsewhere.");
      return errorCodes.mark({ ok: false, username: facts.username,
                               code: 'STS-SVCACCT-0043',
                               error: 'another rotation of ' +
                                      facts.username + ' holds it (' +
                                      ((claimed && claimed.reason) ||
                                       'refused') + ')' },
                             'STS-SVCACCT-0043');
    }
    try {
      const rotation = this.deps.policy().rotation();
      const passwordPolicy = this.deps.passwordPolicy();
      const profile = Object.assign({}, passwordPolicy.read(),
                                    { generatedLength:
                                        rotation.generatedLength });
      let password = '';
      try {
        password = passwordPolicy.generate(profile);
      } catch (e) {
        log.debug("Caught in ServiceAccountRotation.rotateOne(): " +
                  ((e && e.message) || e));
        return this.failed(facts.username, 'STS-SVCACCT-0046',
                           'no password of ' + rotation.generatedLength +
                           ' characters satisfied the password policy',
                           false);
      }
      const rotatedAt = new Date(this.deps.now()).toISOString();
      // THE PUSH, FIRST.
      const pushed = await destinations.push(facts.destination,
        facts.secretName, { username: facts.username, password: password,
                            realm: realmId, rotatedAt: rotatedAt });
      if (!pushed || !pushed.ok) {
        log.debug("Leaving ServiceAccountRotation.rotateOne(). The push " +
                  "failed.");
        return this.failed(facts.username,
                           (pushed && pushed.code) || 'STS-SVCACCT-0044',
                           'the push to ' + facts.destination + ' failed: ' +
                           String((pushed && pushed.error) || 'no answer'),
                           false);
      }
      // THE COMMIT, ONLY NOW.
      const set = this.deps.credentials().setPassword(facts.username,
        password, { generated: true, via: 'service-account rotation',
                    rotation: { overlapMs: rotation.overlapMs } });
      password = '';
      if (!set || !set.ok) {
        log.debug("Leaving ServiceAccountRotation.rotateOne(). The commit " +
                  "failed after the push.");
        return this.failed(facts.username, 'STS-SVCACCT-0045',
                           'the password was pushed (version ' +
                           String(pushed.version || '?') + ') and could not ' +
                           'be committed: ' +
                           ((set && set.errors) || []).join(' '), true);
      }
      const signals = this.deps.accountSignals();
      if (signals && typeof signals.credentialChanged === 'function') {
        signals.credentialChanged({ username: facts.username,
          credentialType: 'password', changeType: 'update',
          initiatingEntity: 'system', via: 'service-account rotation',
          reasonAdmin: 'The password of the service account ' +
                       facts.username + ' was rotated and pushed to ' +
                       facts.destination + '.',
          reasonUser: 'Your service account\'s password was rotated.' });
      }
      this.record('service-account.rotated', facts.username, 'success',
                  'the password of ' + facts.username + ' was rotated and ' +
                  'pushed to ' + facts.destination,
                  { destination: facts.destination,
                    secretName: facts.secretName,
                    version: pushed.version || null,
                    overlapMs: rotation.overlapMs,
                    trigger: c.trigger || 'manual',
                    requestedBy: c.requestedBy || null });
      log.info('service-accounts: the password of ' + facts.username +
               ' was rotated (' + (c.trigger || 'manual') + ') and pushed ' +
               'to ' + facts.destination + '; the previous one is accepted ' +
               'for ' + Math.round(rotation.overlapMs / 60000) +
               ' more minute(s).');
      log.debug("Leaving ServiceAccountRotation.rotateOne(). Rotated.");
      return { ok: true, username: facts.username,
               version: pushed.version || null, rotatedAt: rotatedAt };
    } finally {
      claims.release(claimed.handle);
    }
  }

  /**
   * Says why the hourly rotation is off in a realm, or ''.
   *
   * @param realmId - the realm
   * @returns the reason, or '' when it is on
   */
  offReason(realmId: string): string {
    const { log } = this.deps;
    log.debug("Entering ServiceAccountRotation.offReason().");
    const on = this.inRealm(realmId, () => {
      return this.deps.policy().rotation().enabled;
    });
    log.debug("Leaving ServiceAccountRotation.offReason(). " + on);
    return on ? '' : 'the realm\'s service-account policy does not rotate ' +
                     'passwords (rotationEnabled)';
  }

  /**
   * Rotates every service account in a realm whose interval has passed.
   *
   * @param realmId - the realm
   * @param ctx - the scheduler's run context
   * @returns `{ rotated, failed, skipped }`, counts
   */
  async rotateDue(realmId: string, ctx?: Json): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering ServiceAccountRotation.rotateDue(). " + realmId);
    const c = ctx || {};
    const out = { rotated: 0, failed: 0, skipped: 0, accounts: 0 };
    const due = this.inRealm(realmId, () => {
      const rotation = this.deps.policy().rotation();
      if (!rotation.enabled) {
        return [];
      }
      const now = c.nowMs ? c.nowMs() : this.deps.now();
      return this.deps.serviceAccounts().list().filter((one: Json) => {
        out.accounts += 1;
        if (!one.destination) {
          out.skipped += 1;
          return false;
        }
        const last = this.rotatedMs(one.rotatedAt);
        return !last || last + rotation.intervalMs <= now;
      }).map(function (one: Json): string {
        return one.username;
      });
    });
    for (const name of due) {
      // A STEP THAT CANNOT BE TAKEN BACK: a run that no longer owns its
      // slot leaves the rest to whoever does.
      if (c.stillOwner && !c.stillOwner()) {
        break;
      }
      const answer = await this.inRealm(realmId, () => {
        return this.rotateOne(name, { trigger: c.trigger || 'schedule' });
      });
      if (answer.ok) {
        out.rotated += 1;
      } else {
        out.failed += 1;
      }
    }
    log.debug("Leaving ServiceAccountRotation.rotateDue(). " +
              JSON.stringify(out));
    return out;
  }

  // `stsPasswordRotatedAt` (GeneralizedTime) as epoch ms, or 0.
  private rotatedMs(value: string): number {
    const { log } = this.deps;
    log.debug("Entering ServiceAccountRotation.rotatedMs().");
    const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/
      .exec(String(value || ''));
    const out = m ? Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]),
                             Number(m[4]), Number(m[5]), Number(m[6])) : 0;
    log.debug("Leaving ServiceAccountRotation.rotatedMs().");
    return out;
  }

  /**
   * Clears every previous password in a realm whose overlap has ended.
   *
   * @param realmId - the realm
   * @param ctx - the scheduler's run context
   * @returns `{ cleared }`
   */
  cleanup(realmId: string, ctx?: Json): Json {
    const { log } = this.deps;
    log.debug("Entering ServiceAccountRotation.cleanup(). " + realmId);
    const now = ctx && ctx.nowMs ? ctx.nowMs() : this.deps.now();
    const cleared = this.inRealm(realmId, () => {
      const accounts = this.deps.serviceAccounts();
      return accounts.names().filter(function (name: string): boolean {
        return accounts.clearExpiredPrevious(name, now);
      }).length;
    });
    log.debug("Leaving ServiceAccountRotation.cleanup(). " + cleared);
    return { cleared: cleared };
  }

  /**
   * Queues a rotation of one account now, on the scheduler's leader — what
   * Rotate now and `POST /admin-api/users/rotate-password` ask.
   *
   * @param realmId - the realm
   * @param username - the account
   * @param options - `requestedBy`, `via`, `channel`
   * @returns `{ ok: true, runId, alreadyQueued }`, or a refusal with
   *   `errorCode`, `status` and `why`
   */
  requestRotation(realmId: string, username: string, options?: Json): Json {
    const { log } = this.deps;
    log.debug("Entering ServiceAccountRotation.requestRotation().");
    const o = options || {};
    const facts = this.inRealm(realmId, () => {
      return this.deps.serviceAccounts().of(username);
    });
    if (!facts) {
      log.debug("Leaving ServiceAccountRotation.requestRotation(). Not one.");
      return { ok: false, errorCode: 'STS-SVCACCT-0040', status: 400,
               why: '"' + String(username || '').slice(0, 64) + '" is not a ' +
                    'service account in this realm.' };
    }
    if (!facts.destination) {
      log.debug("Leaving ServiceAccountRotation.requestRotation(). No " +
                "destination.");
      return { ok: false, errorCode: 'STS-SVCACCT-0041', status: 400,
               why: facts.username + ' names no push destination, so a ' +
                    'rotated password would reach nobody. Name one first.' };
    }
    const answer = this.deps.scheduler().requestRun(ROTATE_NOW_JOB, {
      realm: realmId, params: { user: facts.username },
      requestedBy: String(o.requestedBy || ''), via: String(o.via || ''),
      channel: String(o.channel || 'console') });
    log.debug("Leaving ServiceAccountRotation.requestRotation(). " +
              (answer.ok ? answer.runId : answer.why));
    return answer.ok
      ? { ok: true, runId: answer.runId, alreadyQueued: !!answer.alreadyQueued,
          username: facts.username }
      : { ok: false, errorCode: answer.errorCode, status: answer.status || 400,
          why: answer.why };
  }

  /**
   * Registers the three jobs with the scheduler, once per process.
   *
   * @returns true when registered, false when they already were
   */
  registerJobs(): boolean {
    const { log } = this.deps;
    log.debug("Entering ServiceAccountRotation.registerJobs().");
    const s = this.deps.scheduler();
    if (s.job(ROTATE_JOB)) {
      log.debug("Leaving ServiceAccountRotation.registerJobs(). Already " +
                "there.");
      return false;
    }
    const self = this;
    s.register({
      id: ROTATE_JOB,
      title: 'Service-account password rotation',
      describe: 'Gives every service account that names a push destination ' +
                'a new password once its interval has passed ' +
                '(the service-account policy): pushed to the destination ' +
                'first, committed only after the push succeeded, the ' +
                'previous password accepted for the overlap. A failed push ' +
                'changes nothing.',
      owner: 'common/service_account_rotation.ts',
      kind: 'cluster', scope: 'realm',
      everyMs: function (): number {
        return HOUR_MS;
      },
      off: function (realmId: string): string {
        return self.offReason(realmId);
      },
      manual: true,
      run: function (ctx: Json): Promise<Json> {
        return self.rotateDue(ctx.realm, ctx);
      }
    });
    s.register({
      id: ROTATE_NOW_JOB,
      title: 'Service-account password rotation, by hand',
      describe: 'Rotates one service account\'s password now, as the hourly ' +
                'job would: push first, then commit.',
      owner: 'common/service_account_rotation.ts',
      kind: 'cluster', scope: 'realm', manualOnly: true, manual: true,
      run: function (ctx: Json): Promise<Json> {
        const p = ctx.params || {};
        return self.inRealm(ctx.realm, function (): Promise<Json> {
          return self.rotateOne(String(p.user || ''),
                                { trigger: 'manual',
                                  requestedBy: ctx.requestedBy || '' });
        });
      }
    });
    s.register({
      id: CLEANUP_JOB,
      title: 'Service-account previous password clean-up',
      describe: 'Clears a rotated service account\'s previous password once ' +
                'its overlap has ended. The overlap is checked where the ' +
                'password is read, so this is housekeeping.',
      owner: 'common/service_account_rotation.ts',
      kind: 'cluster', scope: 'realm',
      everyMs: function (): number {
        return HOUR_MS;
      },
      manual: true,
      run: function (ctx: Json): Json {
        return self.cleanup(ctx.realm, ctx);
      }
    });
    log.debug("Leaving ServiceAccountRotation.registerJobs().");
    return true;
  }
}

const slot = new InstanceSlot<ServiceAccountRotation>(
  'common/service_account_rotation',
  () => new ServiceAccountRotation(ServiceAccountRotation.defaultDeps()),
  function (instance: ServiceAccountRotation): void {
    instance.registerJobs();
  },
  log);

slot.buildNowUnlessDeferred();

/**
 * Service-account password rotation (#221 P4) on the scheduler. The exports
 * forward to the instance the composition root installs.
 *
 * @namespace
 */
export = {
  ServiceAccountRotation: ServiceAccountRotation,
  /**
   * Installs the instance the module-level functions forward to.
   */
  installInstance: (instance: ServiceAccountRotation): void =>
    slot.install(instance),
  /**
   * Says where the installed instance came from.
   */
  instanceOrigin: (): string => slot.origin(),
  ROTATE_JOB: ServiceAccountRotation.ROTATE_JOB,
  ROTATE_NOW_JOB: ServiceAccountRotation.ROTATE_NOW_JOB,
  CLEANUP_JOB: ServiceAccountRotation.CLEANUP_JOB,
  rotateOne: slot.forward('rotateOne'),
  rotateDue: slot.forward('rotateDue'),
  cleanup: slot.forward('cleanup'),
  offReason: slot.forward('offReason'),
  requestRotation: slot.forward('requestRotation'),
  registerJobs: slot.forward('registerJobs')
};
