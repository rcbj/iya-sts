'use strict';
//
// File: krb5_krbtgt_rotation.ts
//
// ===========================================================================
// THE KRBTGT KEY'S ROTATION, ON THE SCHEDULER AND BY HAND (2026-09-23, #169).
//
// Each trust realm's krbtgt key seals every ticket-granting ticket its KDC
// issues. It was derived once from `krb5.krbtgtPassword`, at a fixed kvno,
// and never rotated — so one leaked krbtgt key let whoever held it forge TGTs
// for that realm (a "golden ticket") for as long as the service ran. The key
// is now a STORED random key with previous versions, and this module decides
// WHEN it moves on. What a rotation IS — the random key, the seal, the kept
// version, the entry `krbtgt/<REALM>@<REALM>` — is
// `krb5_person_keys.ts`'s THE KRBTGT KEY; this file does nothing to a key
// itself, exactly as `common/signing_rotation.ts` does nothing to a signing
// key.
//
// TWO JOBS, BOTH PER REALM, BOTH CLUSTER JOBS (run once, on the leader):
//
//   `krb5.krbtgt-rotate`      every hour, deciding per realm from the key's
//                             OWN age (the scheduler's rule: a job that must
//                             not fire at a fresh start decides from its
//                             state, not from being called). A realm whose
//                             current key is at least
//                             `krb5.krbtgtRotationIntervalDays` old is
//                             rotated — **unless the version the last
//                             rotation kept is still inside its window**, so
//                             the schedule can never make Active Directory's
//                             "two resets inside one TGT lifetime" and strand
//                             a live TGT. A product realm that has no key yet
//                             is given its first here too.
//   `krb5.krbtgt-rotate-now`  manual only, in EVERY mode: what
//                             `/admin/kerberos/principals` and
//                             `POST /admin-api/kerberos/principals/
//                             {rotate-krbtgt,rotate-krbtgt-invalidate}`
//                             queue. `params.invalidate` is AD's double
//                             reset in one act: nothing is kept, and every TGT
//                             in the realm is refused KRB_AP_ERR_BADKEYVER.
//
// **THE SCHEDULE IS OFF IN DEVELOPMENT MODE** (`mode.rotatesKerberosKeys()`):
// its krbtgt is derived from the published password so a reader can decrypt
// a TGT, and rotating that away on a timer would pull the fixtures out from
// under them. A rotation by hand works there. It is also off while
// `krb5.retainedKeyVersions` is 0: a rotation that keeps nothing is an
// unannounced sign-out of every Kerberos user in the realm, which is what the
// invalidate form is for, said out loud.
//
// **AN INVALIDATION IS ANNOUNCED** with a Shared Signals event of this
// service's own vocabulary (`ssf.kerberosTicketsInvalidated()`, rcbj's
// decision 4 on #169, following `signingKeyRotated()`), because every
// person's Kerberos session in the realm has just ended. An ordinary
// rotation is not: every TGT goes on working.
//
// A LIBRARY THAT REGISTERS JOBS AND NO ROUTE, built by
// `common/protocol_stack.ts` after `ldap/ldap_server` (21) — the register it
// drives writes through the directory slot that module fills — and beside
// `common/signing_rotation` (23b-iii). It requires nothing of the three locked
// Kerberos files' closure: the register, the principal database, the
// scheduler, the mode, the audit log and Shared Signals are all reached
// LAZILY, so the parent project's COPY set is unchanged.
// ===========================================================================

import helpers = require('../common/helpers');
import config = require('../common/config');
import realms = require('../common/realms');
import errorCodes = require('../common/error_codes');
import InstanceSlot = require('../common/instance_slot');

type Json = any;

const ROTATE_JOB = 'krb5.krbtgt-rotate';
const ROTATE_NOW_JOB = 'krb5.krbtgt-rotate-now';
const CHECK_EVERY_MS = 3600000;
const DAY_MS = 86400000;
// The word a person types to confirm "rotate and invalidate".
const CONFIRM_WORD = 'invalidate';

interface KrbtgtRotationDeps {
  log: typeof helpers.log;
  config: typeof config;
  realms: typeof realms;
  errorCodes: typeof errorCodes;
  // Lazily, each: the register and the principal database load before this
  // module and after the scheduler, and Shared Signals after both.
  scheduler: () => Json;
  mode: () => Json;
  keys: () => Json;
  principals: () => Json;
  ssf: () => Json;
  now: () => number;
}

class KrbtgtRotation {
  static readonly ROTATE_JOB = ROTATE_JOB;
  static readonly ROTATE_NOW_JOB = ROTATE_NOW_JOB;
  static readonly CONFIRM_WORD = CONFIRM_WORD;

  constructor(private readonly deps: KrbtgtRotationDeps) {
    deps.log.debug("Entering KrbtgtRotation.constructor().");
    deps.log.debug("Leaving KrbtgtRotation.constructor().");
  }

  static defaultDeps(): KrbtgtRotationDeps {
    helpers.log.debug("Entering KrbtgtRotation.defaultDeps().");
    helpers.log.debug("Leaving KrbtgtRotation.defaultDeps().");
    return {
      log: helpers.log,
      config: config,
      realms: realms,
      errorCodes: errorCodes,
      scheduler: function (): Json {
        return require('../cluster/scheduler');
      },
      mode: function (): Json {
        return require('../common/mode');
      },
      keys: function (): Json {
        return require('./krb5_person_keys');
      },
      principals: function (): Json {
        return require('./krb5_principals');
      },
      ssf: function (): Json {
        return require('../ssf/ssf');
      },
      now: function (): number {
        return Date.now();
      }
    };
  }

  // `fn` inside the trust realm `realmId` — the scheduler asks `off()`
  // outside any realm, and every answer here is a realm's.
  private inRealm(realmId: string, fn: () => Json): Json {
    const { log, realms } = this.deps;
    log.debug("Entering KrbtgtRotation.inRealm(). realm=" + realmId);
    const realm = realms.get(String(realmId || realms.DEFAULT_ID));
    log.debug("Leaving KrbtgtRotation.inRealm().");
    return realm ? realms.run(realm, fn) : fn();
  }

  // The interval, in milliseconds, for the AMBIENT realm; 0 is off.
  intervalMs(): number {
    const { log, config } = this.deps;
    log.debug("Entering KrbtgtRotation.intervalMs().");
    const days = Number(config.value('krb5.krbtgtRotationIntervalDays'));
    log.debug("Leaving KrbtgtRotation.intervalMs().");
    return days > 0 ? days * DAY_MS : 0;
  }

  // WHY THE SCHEDULE IS OFF IN A REALM, or ''. Four reasons, in the order a
  // person would look for them.
  offReason(realmId?: string): string {
    const self = this;
    const { log, config, mode, principals, realms } = this.deps;
    log.debug("Entering KrbtgtRotation.offReason(). realm=" + realmId);
    const answer = this.inRealm(String(realmId || realms.DEFAULT_ID),
        function (): string {
      if (!mode().rotatesKerberosKeys()) {
        return 'development mode, whose krbtgt is derived from the ' +
               'published krb5.krbtgtPassword so a reader can decrypt a TGT ' +
               '(a rotation by hand still works)';
      }
      const kerberos = principals().kerberosRealmOf();
      if (!kerberos.enabled || !kerberos.active) {
        return 'this trust realm has no KDC (' +
               (kerberos.reason || 'krb5.enabled is off') + ')';
      }
      if (!(self.intervalMs() > 0)) {
        return 'krb5.krbtgtRotationIntervalDays is 0';
      }
      if (!(Number(config.value('krb5.retainedKeyVersions')) > 0)) {
        return 'krb5.retainedKeyVersions is 0, so a rotation would keep no ' +
               'previous version and sign every Kerberos user in the realm ' +
               'out unannounced — use "Rotate and invalidate" for that';
      }
      return '';
    });
    log.debug("Leaving KrbtgtRotation.offReason(). " + (answer || 'on'));
    return answer;
  }

  // -------------------------------------------------------------------------
  // THE DECISION, from a realm's `krbtgtState()` and the time: `{ due, dueAt,
  // lastMs, openUntilMs, why }`. Pure, so the timing can be held to the
  // clock a test moves.
  //
  //   * the key's age runs from its LAST rotation, or its creation;
  //   * `dueAt` is that plus the interval, or the end of the kept version's
  //     window if that is later — the window is never cut short by the
  //     schedule;
  //   * no stored key yet (product) is due at once: it is the first key.
  // -------------------------------------------------------------------------
  decide(state: Json, nowMs: number, intervalMs: number): Json {
    const { log } = this.deps;
    log.debug("Entering KrbtgtRotation.decide().");
    const s = state || {};
    if (s.source === 'none') {
      log.debug("Leaving KrbtgtRotation.decide(). No key yet.");
      return { due: true, first: true, dueAt: nowMs, lastMs: 0,
               openUntilMs: 0, why: 'no krbtgt key is stored yet' };
    }
    if (s.source !== 'stored') {
      log.debug("Leaving KrbtgtRotation.decide(). Not a stored key.");
      return { due: false, dueAt: 0, lastMs: 0, openUntilMs: 0,
               why: s.source === 'unreadable'
                 ? 'the stored krbtgt record cannot be opened (' +
                   (s.why || 'unreadable') + '); only "rotate and ' +
                   'invalidate" replaces it'
                 : 'the krbtgt is derived from a password here' };
    }
    const last = Date.parse(String(s.rotatedAt || s.keyCreatedAt ||
                                   s.createdAt || ''));
    const lastMs = Number.isFinite(last) ? last : 0;
    const opened = Date.parse(String(s.windowOpenUntil || ''));
    const openUntilMs = Number.isFinite(opened) ? opened : 0;
    const dueAt = Math.max(lastMs + intervalMs, openUntilMs);
    const open = openUntilMs > nowMs;
    const due = intervalMs > 0 && nowMs >= lastMs + intervalMs && !open;
    log.debug("Leaving KrbtgtRotation.decide(). due=" + due);
    return { due: due, dueAt: dueAt, lastMs: lastMs,
             openUntilMs: openUntilMs,
             why: due ? 'the key is ' +
                        Math.floor((nowMs - lastMs) / DAY_MS) + ' day(s) ' +
                        'old'
               : open ? 'the version the last rotation kept is still ' +
                        'inside its window until ' +
                        new Date(openUntilMs).toISOString()
               : 'not due until ' + new Date(dueAt).toISOString() };
  }

  // -------------------------------------------------------------------------
  // THE SCHEDULED RUN of one realm (ambient: the scheduler entered it).
  // -------------------------------------------------------------------------
  async rotateDue(realmId: string, ctx?: Json): Promise<Json> {
    const { log, keys } = this.deps;
    log.debug("Entering KrbtgtRotation.rotateDue(). realm=" + realmId);
    const nowMs = ctx && ctx.nowMs ? ctx.nowMs() : this.deps.now();
    const state = keys().krbtgtState();
    const decision = this.decide(state, nowMs, this.intervalMs());
    if (decision.first) {
      const made = await keys().ensureKrbtgtKey(realmId);
      const after = keys().krbtgtState();
      log.debug("Leaving KrbtgtRotation.rotateDue(). First key.");
      return { created: !!(made && made.ok && !made.existing),
               kvno: after.kvno, rotated: false,
               nextDueAt: this.nextDueIso(after, nowMs) };
    }
    if (!decision.due) {
      log.debug("Leaving KrbtgtRotation.rotateDue(). Not due.");
      return { kvno: state.kvno, rotated: false, why: decision.why,
               lastRotatedAt: state.rotatedAt || null,
               nextDueAt: decision.dueAt
                 ? new Date(decision.dueAt).toISOString() : null };
    }
    if (ctx && typeof ctx.stillOwner === 'function' && !ctx.stillOwner()) {
      log.debug("Leaving KrbtgtRotation.rotateDue(). No longer the owner.");
      return { kvno: state.kvno, rotated: false,
               why: 'this node no longer owns the run' };
    }
    const done = await this.rotate(realmId, { reason: 'scheduled',
                                              via: 'scheduler' });
    log.debug("Leaving KrbtgtRotation.rotateDue(). ok=" + done.ok);
    return done.ok
      ? { kvno: done.kvno, rotated: true, previousKvno: done.previousKvno,
          lastRotatedAt: new Date(nowMs).toISOString(),
          nextDueAt: this.nextDueIso(keys().krbtgtState(), nowMs) }
      : { kvno: state.kvno, rotated: false,
          why: (done.errors || []).join(' ') };
  }

  // When the schedule would next rotate a realm with this state, or null.
  private nextDueIso(state: Json, nowMs: number): string | null {
    const { log } = this.deps;
    log.debug("Entering KrbtgtRotation.nextDueIso().");
    const interval = this.intervalMs();
    const decision = this.decide(state, nowMs, interval);
    log.debug("Leaving KrbtgtRotation.nextDueIso().");
    return interval > 0 && decision.dueAt
      ? new Date(decision.dueAt).toISOString() : null;
  }

  // -------------------------------------------------------------------------
  // ONE ROTATION — the scheduler's, or the one an administrator queued.
  // Announced when it invalidated.
  // -------------------------------------------------------------------------
  async rotate(realmId: string, options?: Json): Promise<Json> {
    const { log, keys } = this.deps;
    const o = options || {};
    log.debug("Entering KrbtgtRotation.rotate(). realm=" + realmId +
              " invalidate=" + !!o.invalidate);
    const done = await keys().rotateKrbtgt({
      invalidate: !!o.invalidate, reason: String(o.reason || 'requested'),
      context: { actor: String(o.actor || ''),
                 via: String(o.via || 'scheduler') } });
    if (done && done.ok && done.invalidated) {
      this.announce(realmId, done, String(o.reason || 'requested'));
    }
    log.debug("Leaving KrbtgtRotation.rotate(). ok=" + !!(done && done.ok));
    return done;
  }

  // The Shared Signals event (#169's decision 4). Never lets a failure reach
  // the rotation, which has already happened.
  private announce(realmId: string, done: Json, reason: string): void {
    const { log, ssf, principals } = this.deps;
    log.debug("Entering KrbtgtRotation.announce().");
    try {
      Promise.resolve(ssf().kerberosTicketsInvalidated({
        realm: realmId, kerberos_realm: principals().REALM,
        kvno: done.kvno, reason: reason
      })).catch(function (e: Json): void {
        log.debug("Caught in a callback in KrbtgtRotation.announce(): " +
                  ((e && e.message) || e));
      });
    } catch (e) {
      // No Shared Signals in this process: the rotation stands, and the audit
      // row is its record.
      log.debug("Caught in KrbtgtRotation.announce(): " +
                ((e && e.message) || e));
    }
    log.debug("Leaving KrbtgtRotation.announce().");
  }

  // -------------------------------------------------------------------------
  // WHAT THE CONSOLE AND THE API ASK FOR: a run of `krb5.krbtgt-rotate-now`
  // queued, never a rotation in the request — so it runs once, on the
  // scheduler's leader, wherever it was asked. The invalidate form needs
  // `confirm` to be the word `invalidate`, because it ends every TGT in the
  // realm and cannot be undone.
  // -------------------------------------------------------------------------
  requestRotation(realmId: string, options?: Json): Json {
    const { log, scheduler, principals, realms } = this.deps;
    const o = options || {};
    const invalidate = !!o.invalidate;
    log.debug("Entering KrbtgtRotation.requestRotation(). realm=" + realmId +
              " invalidate=" + invalidate);
    const id = String(realmId || realms.DEFAULT_ID);
    const kerberos = principals().kerberosRealmOf(id);
    if (!kerberos.enabled || !kerberos.active) {
      log.debug("Leaving KrbtgtRotation.requestRotation(). No KDC.");
      return errorCodes.mark({ ok: false, errors: ['Trust realm "' + id +
        '" has no KDC, so it has no krbtgt key to rotate: ' +
        (kerberos.reason || 'krb5.enabled is off for it') + '.'] },
        'STS-KRB-0128');
    }
    if (invalidate && String(o.confirm || '').trim() !== CONFIRM_WORD) {
      log.debug("Leaving KrbtgtRotation.requestRotation(). Unconfirmed.");
      return errorCodes.mark({ ok: false, errors: ['"Rotate and invalidate" ' +
        'ends EVERY ticket-granting ticket in the realm at once — everybody ' +
        'signs in to Kerberos again — and cannot be undone. Confirm it by ' +
        'sending confirm: "' + CONFIRM_WORD + '".'] }, 'STS-ADMIN-0610');
    }
    const answer = scheduler().requestRun(ROTATE_NOW_JOB, {
      realm: id,
      params: { invalidate: invalidate, actor: String(o.requestedBy || ''),
                via: String(o.via || 'console') },
      requestedBy: String(o.requestedBy || ''), via: String(o.via || ''),
      channel: String(o.channel || 'console') });
    if (!answer.ok) {
      log.debug("Leaving KrbtgtRotation.requestRotation(). Not queued.");
      return errorCodes.mark({ ok: false, errors: ['The krbtgt rotation ' +
        'could not be queued: ' + String(answer.why || 'the scheduler ' +
        'refused it')] }, 'STS-ADMIN-0611');
    }
    log.debug("Leaving KrbtgtRotation.requestRotation(). Queued " +
              answer.runId + ".");
    return {
      ok: true, queued: true, runId: answer.runId,
      alreadyQueued: !!answer.alreadyQueued, invalidate: invalidate,
      trustRealm: id,
      message: (invalidate
        ? 'A rotation of the krbtgt key that keeps NOTHING was queued'
        : 'A rotation of the krbtgt key was queued') + ' (run ' +
        answer.runId + '). It runs on the scheduler\'s leader at its next ' +
        'tick; the kvno on this page moves when it has.' +
        (invalidate ? ' Every TGT issued before it is then refused.' : '')
    };
  }

  // -------------------------------------------------------------------------
  // THE STATE OF A REALM'S KRBTGT, for `/admin/kerberos`,
  // `/admin/kerberos/principals` and their `/admin-api` twins: the register's
  // public state, and the schedule — whether it is on, the interval, the
  // last rotation and when the next is due.
  // -------------------------------------------------------------------------
  rotationView(realmId?: string): Json {
    const self = this;
    const { log, keys, realms } = this.deps;
    const id = String(realmId === undefined ? realms.currentId() : realmId);
    log.debug("Entering KrbtgtRotation.rotationView(). realm=" + id);
    const view = this.inRealm(id, function (): Json {
      const state = keys().krbtgtState();
      const off = self.offReason(id);
      const interval = self.intervalMs();
      const decision = self.decide(state, self.deps.now(), interval);
      return Object.assign({}, state, {
        trustRealm: id,
        scheduled: off === '', offReason: off,
        intervalDays: interval / DAY_MS,
        lastRotatedAt: state.rotatedAt || null,
        nextDueAt: off === '' && decision.dueAt
          ? new Date(decision.dueAt).toISOString() : null,
        jobs: { scheduled: ROTATE_JOB, byHand: ROTATE_NOW_JOB },
        confirmWord: CONFIRM_WORD
      });
    });
    log.debug("Leaving KrbtgtRotation.rotationView(). " + view.source);
    return view;
  }

  // -------------------------------------------------------------------------
  // EVERY PRODUCT REALM'S FIRST KEY, AT STARTUP — `server.js` awaits this
  // after the store is restored and before the request workers fork or the
  // listener binds, so a KDC has its key before its first request. One realm
  // at a time, each under the register's claim. Never rejects.
  // -------------------------------------------------------------------------
  async ensureAll(): Promise<Json[]> {
    const { log, keys, principals, realms } = this.deps;
    log.debug("Entering KrbtgtRotation.ensureAll().");
    const out: Json[] = [];
    const list = realms.list();
    for (let i = 0; i < list.length; i++) {
      const realm = list[i];
      const wanted = realms.run(realm, function (): boolean {
        return principals().enabledIn(realm.id) &&
               !principals().krbtgtFromPassword;
      });
      if (!wanted) {
        continue;
      }
      try {
        out.push(Object.assign({ realm: realm.id },
                               await keys().ensureKrbtgtKey(realm.id)));
      } catch (e) {
        // ensureKrbtgtKey() never rejects; a throw here is a missing module,
        // and the KDC says why it has no krbtgt on its own.
        log.debug("Caught in KrbtgtRotation.ensureAll(): " +
                  ((e && e.message) || e));
        out.push({ realm: realm.id, ok: false,
                   why: String((e && e.message) || e) });
      }
    }
    log.debug("Leaving KrbtgtRotation.ensureAll(). " + out.length +
              " realm(s).");
    return out;
  }

  // The two jobs, registered once per process.
  registerJobs(): boolean {
    const { log, scheduler } = this.deps;
    log.debug("Entering KrbtgtRotation.registerJobs().");
    const s = scheduler();
    if (s.job(ROTATE_JOB)) {
      log.debug("Leaving KrbtgtRotation.registerJobs(). Already there.");
      return false;
    }
    const self = this;
    s.register({
      id: ROTATE_JOB,
      title: 'krbtgt key rotation',
      describe: 'Replaces each realm\'s krbtgt key — the key every TGT is ' +
                'sealed under — with a new random one at the next kvno once ' +
                'it is krb5.krbtgtRotationIntervalDays old, keeping the one ' +
                'it replaces for the longest a TGT under it can live, and ' +
                'never while the version the last rotation kept is still in ' +
                'its window. Gives a product realm with none its first key. ' +
                'Each run\'s result names the kvno, the last rotation and ' +
                'when the next is due.',
      owner: 'kerberos/krb5_krbtgt_rotation.ts',
      kind: 'cluster', scope: 'realm',
      everyMs: function (): number {
        return CHECK_EVERY_MS;
      },
      off: function (realmId: string): string {
        return self.offReason(realmId);
      },
      manual: true,
      run: function (ctx: Json): Promise<Json> {
        return self.rotateDue(ctx.realm, ctx);
      }
    });
    // BY HAND — what the console and the API queue. A job of its own rather
    // than a manual run of the one above, because that one is OFF in
    // development mode and this must not be. `params.invalidate` keeps
    // nothing.
    s.register({
      id: ROTATE_NOW_JOB,
      title: 'krbtgt key rotation, by hand',
      describe: 'Rotates the realm\'s krbtgt key now. With invalidate, keeps ' +
                'no previous version: every TGT issued before it is refused ' +
                'and a Shared Signals event says so.',
      owner: 'kerberos/krb5_krbtgt_rotation.ts',
      kind: 'cluster', scope: 'realm', manualOnly: true, manual: true,
      run: function (ctx: Json): Promise<Json> {
        const p = ctx.params || {};
        return self.rotate(ctx.realm, {
          invalidate: !!p.invalidate,
          reason: p.invalidate ? 'invalidated' : 'requested',
          actor: String(p.actor || ''), via: String(p.via || 'console')
        }).then(function (done: Json): Json {
          if (!done || !done.ok) {
            throw new Error('the krbtgt rotation was refused: ' +
                            ((done && done.errors) || []).join(' '));
          }
          return { kvno: done.kvno, previousKvno: done.previousKvno,
                   invalidated: !!done.invalidated,
                   retained: (done.retained || []).map(function (one: Json) {
                     return one.kvno;
                   }) };
        });
      }
    });
    log.debug("Leaving KrbtgtRotation.registerJobs().");
    return true;
  }
}

const slot = new InstanceSlot<KrbtgtRotation>(
  'kerberos/krb5_krbtgt_rotation',
  () => new KrbtgtRotation(KrbtgtRotation.defaultDeps()),
  function (instance: KrbtgtRotation): void {
    instance.registerJobs();
  },
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  KrbtgtRotation: KrbtgtRotation,
  installInstance: (instance: KrbtgtRotation): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  ROTATE_JOB: ROTATE_JOB,
  ROTATE_NOW_JOB: ROTATE_NOW_JOB,
  CONFIRM_WORD: CONFIRM_WORD,
  offReason: slot.forward('offReason'),
  intervalMs: slot.forward('intervalMs'),
  decide: slot.forward('decide'),
  rotateDue: slot.forward('rotateDue'),
  rotate: slot.forward('rotate'),
  requestRotation: slot.forward('requestRotation'),
  rotationView: slot.forward('rotationView'),
  ensureAll: slot.forward('ensureAll')
};
