// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: gnap_spend.ts
//
// ===========================================================================
// THE RUNNING TOTALS OF A RIGHT'S LIMITS, KEPT BY THE RESOURCE SERVER (#432
// phase 5, 2026-10-03).
//
// rcbj's decision 2 on #432: the authorization server validates a right's
// limits, shows them, lets the person lower them, and states them in the
// token and at introspection; the RESOURCE SERVER keeps the running totals,
// per grant id. There is no standard spend call from a resource server to
// an authorization server, and inventing one would make every resource
// server depend on this one being up for every operation. So this module is
// what a resource server does, written once as the reference — the
// demonstration resource server's `POST /gnap/rs/spend` (`gnap.ts`) is its
// one caller, and `docs/gnap.md` points an RS author at it.
//
// **WHAT ONE OPERATION IS CHECKED AGAINST**, in this order, each a coded
// refusal (`spendRefusal()`):
//
//   * the WINDOW: now inside notBefore / notAfter (STS-GNAP-0871);
//   * the INTERVAL: now at or after its start and before the end of its last
//     repetition (0871) — and which period, so the totals reset at each
//     boundary;
//   * the RECEIVER: an operation for somebody the limit does not name (0872);
//   * the CURRENCY: an operation in another currency, or none where the
//     limit counts an amount (0873);
//   * the TOTALS, atomically: this period's amount and count plus this
//     operation's, within the limits (0870, HTTP 403 `insufficient_scope`).
//
// **KEYED BY GRANT, TYPE AND IDENTIFIER.** The grant is the token's own
// (`grant`, the one a rotation keeps and a derivation inherits), so neither
// a rotated token nor a derived one is a fresh budget; type and identifier
// separate two rights of one grant. A right whose limits a later
// modification LOWERED is counted against what was already spent.
//
// **ATOMIC ACROSS THE CLUSTER.** Where the store is shared (postgres) the
// spend is `cluster/cluster_counters.js`'s `spendBudget()`, one conditional
// upsert every node agrees on; where it is not, there is one process, and
// this module's own persisted per-realm ledger, checked and written with no
// await between, is exactly as atomic. A shared store that cannot be asked
// REFUSES the operation (STS-GNAP-0875): a spend that cannot be proved within
// the limit is not allowed.
//
// **A REFUND** (`refund()`) takes back an operation that failed after its
// spend was counted — from the period it was counted in only, never below
// zero. The demonstration operation fails when asked to (`simulateFailure`),
// which is how the refund is exercised.
//
// **A ROW OUTLIVES NO GRANT.** Each carries the grant's end; the scheduler
// job `gnap.spend-purge` (cluster, realm, hourly) deletes the rows past it —
// in the shared table and in the ledger — because after it no token of that
// grant can be presented.
//
// A LIBRARY (rule 3): no route. Capability `gnap.limits`.
// ===========================================================================

import helpers = require('../common/helpers');
import config = require('../common/config');
import errorCodes = require('../common/error_codes');
import realms = require('../common/realms');
import InstanceSlot = require('../common/instance_slot');
import AccessLimits = require('../common/access_limits');
import counters = require('../cluster/cluster_counters');
import capabilities = require('../cluster/cluster_capabilities');

type Json = any;

// The scope the shared table keys this module's rows under.
const SCOPE = 'gnap.spend';
// The scheduler job that deletes the rows of ended grants.
const PURGE_JOB = 'gnap.spend-purge';
const PURGE_EVERY_MS = 3600000;
// A grant with no recorded end is held this long past its last spend.
const DEFAULT_HOLD_S = 86400;

// key -> { period, amount (millionths, a decimal string), count, expiresAt }
// THE LEDGER where no store is shared: persisted, so a restart of the one
// process is not a fresh budget for every grant.
const ledger = realms.map({ persist: 'gnap.spend' });

interface GnapSpendDeps {
  log: typeof helpers.log;
  config: { value(key: string): any };
  errorCodes: typeof errorCodes;
  nowSec(): number;
  counters: Json;
  scheduler(): Json;
}

/**
 * The resource server's running totals of a GNAP right's limits (#432 phase
 * 5): checked, spent atomically, reset per interval, refunded.
 */
class GnapSpend {
  /** The scope of this module's rows in the shared budget table. */
  static readonly SCOPE = SCOPE;
  /** The scheduler job that purges the rows of ended grants. */
  static readonly PURGE_JOB = PURGE_JOB;

  /**
   * Builds the module from its dependencies.
   *
   * @param deps - the modules it reads
   */
  constructor(private readonly deps: GnapSpendDeps) {
    deps.log.debug("Entering GnapSpend.constructor().");
    deps.log.debug("Leaving GnapSpend.constructor().");
  }

  /**
   * Returns the dependencies built from this module's own imports.
   *
   * @returns the default dependency set
   */
  static defaultDeps(): GnapSpendDeps {
    helpers.log.debug("Entering GnapSpend.defaultDeps().");
    helpers.log.debug("Leaving GnapSpend.defaultDeps().");
    return {
      log: helpers.log, config: config, errorCodes: errorCodes,
      nowSec: helpers.nowSec, counters: counters,
      scheduler: function scheduler(): Json {
        helpers.log.debug("Entering scheduler().");
        helpers.log.debug("Leaving scheduler().");
        return require('../cluster/scheduler');
      }
    };
  }

  // A refusal: `{ ok: false, code, why, status, error }`, marked.
  private spendRefusal(code: string, why: string, status: number,
                       error: string): Json {
    const { log, errorCodes } = this.deps;
    log.debug("Entering GnapSpend.spendRefusal(). " + code);
    log.debug("Leaving GnapSpend.spendRefusal().");
    return errorCodes.mark({ ok: false, code: code, why: why, status: status,
                             error: error }, code);
  }

  /**
   * The ledger key of one right of one grant.
   *
   * @param grant - the grant the token spends against
   * @param right - the access right
   * @returns the key
   */
  static keyOf(grant: string, right: Json): string {
    helpers.log.debug("Entering GnapSpend.keyOf().");
    helpers.log.debug("Leaving GnapSpend.keyOf().");
    return String(grant) + '\n' + String((right && right.type) || '') + '\n' +
      String((right && right.identifier) || '');
  }

  // -------------------------------------------------------------------------
  // The checks that need no totals: the window, the interval (and its
  // period), the receiver, the currency. `{ ok: true, period, units }` or a
  // refusal.
  // -------------------------------------------------------------------------
  /**
   * Checks one operation against a right's limits, everything but the
   * totals.
   *
   * @param limits - the right's limits
   * @param operation - `{ amount?, currency?, receiver? }`
   * @param now - seconds since the epoch
   * @returns `{ ok: true, period, units }`, or a refusal
   */
  check(limits: Json, operation: Json, now: number): Json {
    const { log } = this.deps;
    log.debug("Entering GnapSpend.check().");
    const op = operation || {};
    const window = limits.window || null;
    if (window) {
      const nb = AccessLimits.timeOf(window.notBefore);
      const na = AccessLimits.timeOf(window.notAfter);
      if ((nb !== null && now < nb) || (na !== null && now >= na)) {
        log.debug("Leaving GnapSpend.check(). Outside the window.");
        return this.spendRefusal('STS-GNAP-0871', 'the operation is outside ' +
          'the window the token\'s limits allow (' +
          JSON.stringify(window) + ').', 403, 'insufficient_scope');
      }
    }
    let period: Json = { index: 0, start: null, end: null };
    if (typeof limits.interval === 'string') {
      period = AccessLimits.periodAt(limits.interval, now);
      if (period.outside) {
        log.debug("Leaving GnapSpend.check(). Outside the interval.");
        return this.spendRefusal('STS-GNAP-0871', 'the operation is ' +
          (period.outside === 'before' ? 'before the start' : 'after the ' +
           'last repetition') + ' of the interval the token\'s limits ' +
          'allow (' + limits.interval + ').', 403, 'insufficient_scope');
      }
    }
    const receivers = AccessLimits.receiversOf(limits);
    if (receivers && (typeof op.receiver !== 'string' ||
                      receivers.indexOf(op.receiver) < 0)) {
      log.debug("Leaving GnapSpend.check(). The receiver.");
      return this.spendRefusal('STS-GNAP-0872', 'the token\'s limits allow ' +
        'operations for ' + receivers.join(', ') + ' only, and this one is ' +
        'for ' + (typeof op.receiver === 'string' ? '"' + op.receiver + '"'
                                                   : 'nobody named') + '.',
        403, 'insufficient_scope');
    }
    let units = BigInt(0);
    if (op.amount !== undefined) {
      const parsed = AccessLimits.units(op.amount);
      if (parsed === null) {
        log.debug("Leaving GnapSpend.check(). The amount is unreadable.");
        return this.spendRefusal('STS-GNAP-0874', 'the operation\'s amount ' +
          'is not a non-negative decimal.', 400, 'invalid_request');
      }
      units = parsed;
    }
    if (limits.amount !== undefined) {
      if (op.amount === undefined || op.currency !== limits.currency) {
        log.debug("Leaving GnapSpend.check(). The currency.");
        return this.spendRefusal('STS-GNAP-0873', 'the token\'s limits count ' +
          'amounts in ' + limits.currency + ', and this operation ' +
          (op.amount !== undefined ? 'is in ' + String(op.currency || 'no ' +
            'currency') : 'states no amount') + '.', 403,
          'insufficient_scope');
      }
    }
    log.debug("Leaving GnapSpend.check(). Within.");
    return { ok: true, period: period, units: units };
  }

  // -------------------------------------------------------------------------
  // spend({ grant, right, operation, expiresAt }): every check, then the
  // totals, atomically. Answers `{ ok: true, spent, totals, limits, period }`
  // — `spent` is what `refund()` takes back — or a refusal.
  // -------------------------------------------------------------------------
  /**
   * Spends one operation against a right's limits.
   *
   * @param args - `{ grant, right, operation, expiresAt }`
   * @returns a promise of the totals this operation made, or a refusal
   */
  async spend(args: Json): Promise<Json> {
    const { log, nowSec, counters } = this.deps;
    log.debug("Entering GnapSpend.spend().");
    const right = args.right || {};
    const limits = right.limits || {};
    const now = nowSec();
    const checked = this.check(limits, args.operation, now);
    if (!checked.ok) {
      log.debug("Leaving GnapSpend.spend(). " + checked.code);
      return checked;
    }
    const key = GnapSpend.keyOf(args.grant, right);
    const limitAmount = limits.amount !== undefined
      ? AccessLimits.units(limits.amount) : null;
    const limitCount = typeof limits.count === 'number' ? limits.count : null;
    const expiresAt = Number(args.expiresAt) > now ? Number(args.expiresAt)
                                                   : now + DEFAULT_HOLD_S;
    const spent = { key: key, period: checked.period.index,
                    amount: limitAmount !== null ? checked.units
                                                 : BigInt(0),
                    count: 1 };
    let totals: Json;
    if (counters.sharesBudgets()) {
      const answer = await counters.spendBudget({
        scope: SCOPE, key: key, period: spent.period, amount: spent.amount,
        count: spent.count, limitAmount: limitAmount, limitCount: limitCount,
        expiresAtMs: expiresAt * 1000 });
      if (!answer.ok && answer.reason === 'store') {
        log.debug("Leaving GnapSpend.spend(). The store.");
        return this.spendRefusal('STS-GNAP-0875', 'the running totals ' +
          'could not be read, so the operation is refused.', 503,
          'temporarily_unavailable');
      }
      totals = answer.ok ? { amount: answer.amount, count: answer.count }
                         : null;
    } else {
      // ONE PROCESS: read, decide and write with no await between.
      const held = ledger.get(key);
      const same = held && Number(held.period) === spent.period;
      if (held && Number(held.period) > spent.period) {
        totals = null;
      } else {
        const amount = (same ? BigInt(held.amount) : BigInt(0)) +
          spent.amount;
        const count = (same ? Number(held.count) : 0) + spent.count;
        totals = (limitAmount !== null && amount > limitAmount) ||
                 (limitCount !== null && count > limitCount)
          ? null : { amount: amount, count: count };
        if (totals) {
          ledger.set(key, { period: spent.period, amount: amount.toString(),
                            count: count,
                            expiresAt: Math.max(expiresAt,
                              Number((held && held.expiresAt) || 0)) });
        }
      }
    }
    if (!totals) {
      log.debug("Leaving GnapSpend.spend(). Over the limit.");
      return this.spendRefusal('STS-GNAP-0870', 'the operation would pass ' +
        'the token\'s limits' + (checked.period.end
          ? ' for the period ending ' +
            new Date(checked.period.end * 1000).toISOString() : '') + '.',
        403, 'insufficient_scope');
    }
    log.debug("Leaving GnapSpend.spend(). Spent.");
    return {
      ok: true, spent: spent,
      totals: { amount: limitAmount !== null
                  ? AccessLimits.decimal(totals.amount) : undefined,
                currency: limitAmount !== null ? limits.currency : undefined,
                count: totals.count },
      remaining: {
        amount: limitAmount !== null
          ? AccessLimits.decimal(limitAmount - totals.amount) : undefined,
        count: limitCount !== null ? limitCount - totals.count : undefined
      },
      period: checked.period.end ? { start: new Date(checked.period.start *
                                                      1000).toISOString(),
                                     end: new Date(checked.period.end *
                                                   1000).toISOString() }
                                 : undefined
    };
  }

  /**
   * Takes back what a spend counted, from the period it was counted in.
   *
   * @param spent - the `spent` a successful `spend()` answered
   * @returns a promise of true when it was taken back
   */
  async refund(spent: Json): Promise<boolean> {
    const { log, counters, errorCodes } = this.deps;
    log.debug("Entering GnapSpend.refund().");
    if (!spent || !spent.key) {
      log.debug("Leaving GnapSpend.refund(). Nothing spent.");
      return false;
    }
    if (counters.sharesBudgets()) {
      const answer = await counters.refundBudget({
        scope: SCOPE, key: spent.key, period: spent.period,
        amount: spent.amount, count: spent.count });
      if (!answer.refunded) {
        log.warn(errorCodes.tag('STS-GNAP-0877') + 'gnap: a demonstration ' +
                 'spend could not be refunded (a new period began, or the ' +
                 'store could not be asked).');
      }
      log.debug("Leaving GnapSpend.refund(). Shared.");
      return !!answer.refunded;
    }
    const held = ledger.get(spent.key);
    if (!held || Number(held.period) !== Number(spent.period) ||
        BigInt(held.amount) < BigInt(spent.amount) ||
        Number(held.count) < Number(spent.count)) {
      log.warn(errorCodes.tag('STS-GNAP-0877') + 'gnap: a demonstration ' +
               'spend could not be refunded (a new period began).');
      log.debug("Leaving GnapSpend.refund(). Nothing to take from.");
      return false;
    }
    ledger.set(spent.key, Object.assign({}, held, {
      amount: (BigInt(held.amount) - BigInt(spent.amount)).toString(),
      count: Number(held.count) - Number(spent.count) }));
    log.debug("Leaving GnapSpend.refund(). Refunded.");
    return true;
  }

  /**
   * Deletes the ledger rows, here and in the shared table, of grants that
   * have ended.
   *
   * @returns a promise of how many rows were deleted
   */
  async purge(): Promise<number> {
    const { log, nowSec, counters } = this.deps;
    log.debug("Entering GnapSpend.purge().");
    const now = nowSec();
    const stale: string[] = [];
    ledger.forEach(function (held: Json, key: string): void {
      if (!(Number(held && held.expiresAt) > now)) {
        stale.push(key);
      }
    });
    stale.forEach(function (key: string): void {
      ledger.delete(key);
    });
    const shared = await counters.purgeBudgets(SCOPE, realms.currentId());
    log.debug("Leaving GnapSpend.purge(). " + (stale.length + shared));
    return stale.length + Number(shared || 0);
  }

  /**
   * Registers the `gnap.spend-purge` scheduler job, once.
   */
  scheduleJobs(): void {
    const { log, scheduler } = this.deps;
    const self = this;
    log.debug("Entering GnapSpend.scheduleJobs().");
    const s = scheduler();
    if (!s || typeof s.register !== 'function' || s.job(PURGE_JOB)) {
      log.debug("Leaving GnapSpend.scheduleJobs(). Nothing to do.");
      return;
    }
    s.register({
      id: PURGE_JOB,
      title: 'GNAP: limits of ended grants',
      describe: 'Deletes the running totals the demonstration resource ' +
                'server keeps for each GNAP grant\'s limits once the grant ' +
                'has ended, when no token of it can be presented (#432).',
      owner: 'gnap/gnap_spend.ts',
      kind: 'cluster', scope: 'realm', everyMs: function (): number {
        return PURGE_EVERY_MS;
      },
      manual: true,
      run: function (): any {
        return self.purge();
      }
    });
    log.debug("Leaving GnapSpend.scheduleJobs(). On the scheduler.");
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2): see
// `common/instance_slot.ts`. The wire step registers the purge job.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<GnapSpend>(
  'gnap/gnap_spend',
  () => new GnapSpend(GnapSpend.defaultDeps()),
  function (instance: GnapSpend): void {
    instance.scheduleJobs();
  },
  helpers.log);

slot.buildNowUnlessDeferred();

// ACTIVE-ACTIVE MAY COUNT ON IT (#46): every node spends one budget, through
// the shared table, and a store that cannot be asked refuses.
capabilities.provide('gnap.limits');

/**
 * The resource server's running totals of a GNAP right's limits (#432 phase
 * 5). A library that registers no route.
 *
 * @namespace
 */
export = {
  GnapSpend: GnapSpend,
  installInstance: (instance: GnapSpend): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  SCOPE: SCOPE,
  PURGE_JOB: PURGE_JOB,
  keyOf: GnapSpend.keyOf,
  check: slot.forward('check'),
  spend: slot.forward('spend'),
  refund: slot.forward('refund'),
  purge: slot.forward('purge'),
  // The ledger, for a test that must start from nothing.
  forget: function (): void {
    helpers.log.debug("Entering forget().");
    ledger.clear();
    helpers.log.debug("Leaving forget().");
  }
};
