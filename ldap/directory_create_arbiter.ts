// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: ldap/directory_create_arbiter.ts
//
// ===========================================================================
// ONE NODE'S CREATE CLAIMS, DECIDED BY ITS FRONT PROCESS IN MEMORY (#628,
// 2026-10-14).
//
// `directory_create_claims.ts` makes a create claim its DN and username
// before its door asks the directory, so that two processes writing one
// store cannot both create a name. Where those processes are the front
// process of ONE node and its request worker threads, nothing outside the
// node can be racing, and a claim in `sts_cluster_claims` — a statement to
// take it and one to give it back, under every add of a bulk load — was
// paying the database to decide something the front process can decide
// alone. So on one node the FRONT PROCESS arbitrates, here, in memory: a
// worker asks over the worker channel (`{ createClaim, op: 'claim' }`) and is
// answered; it gives the claim back with `{ createClaim, op: 'release' }`.
// The front process asks itself directly. `directory_create_claims.ts` says
// when this is used and when the store still is (several NODES share it).
//
// **IT KEEPS THE STORE CLAIM'S SEMANTICS, AND THAT IS ITS WHOLE
// SPECIFICATION.** Two enforcement paths for one rule is the cost rcbj
// accepted on #628; a difference between them is a duplicate entry on one
// of them. So:
//
// * **All or none.** A claim of several keys takes every one or none. It is
//   decided synchronously, between two yields, which is what makes it atomic.
// * **A held key refuses**, whoever holds it — the same holder included,
//   since two requests in one process are two creates.
// * **Waiting and retrying** are the caller's, unchanged: a refused claim
//   asks again every `CLAIM_RETRY_MS` until `CLAIM_WAIT_MS`.
// * **Given back** at once on a refusal, and after the create's flush has
//   committed on a success; a flush that fails keeps it until it expires, as
//   a rolled-back release does in the store.
// * **A lifetime**: `ttlMs` (the caller's `CLAIM_TTL_MS`), after which an
//   abandoned claim is taken over. **And a worker that dies gives back
//   everything it held at once** (`workerExited()`, from the pool's
//   `reap()`), which is better than a row that waits out its lifetime.
// * **The winner catches up before its door looks**, but only when it has to
//   (`catchUp` on the answer). The store claim makes every winner pull the
//   change log, because a deleted row cannot say who held it. Here the front
//   remembers, per key, which holder last gave it back after a COMMITTED
//   create, and in what order (`settled`): a winner whose last FINISHED
//   catch-up began before that, and who is not that holder, pulls; anybody
//   else asks the directory it already has. A holder counts as caught up only
//   once it says its pull has finished (`caughtUp()`, `op: 'caughtUp'`), not
//   when the front tells it to pull — a second create in the same worker,
//   granted while the first one's pull is still running, would otherwise look
//   at a directory that pull has not filled yet (the first version did, and
//   `tests/directory_create_cluster_claims.js` D1 found it: 23 duplicates of
//   24). A worker's own write is in its own
//   memory; the FRONT never counts as having its own, because an LDAP add it
//   claims runs in whichever worker the pool picks.
// * **Bounded.** `MAX_LIVE` live claims — a ceiling far above what a node
//   has in flight, reached only by a leak, and answered as a store that
//   cannot be asked (`STS-LDAP-0144`, fail closed). `MAX_SETTLED` keys
//   remembered for the catch-up, oldest forgotten first; forgetting one
//   moves `forgottenThrough`, and any holder whose last catch-up is older
//   than that pulls once — so a forgotten key costs a pull, never a missed
//   one.
//
// A worker's question that is not answered within `ANSWER_MS` is refused as
// a store that cannot be asked (`STS-LDAP-0145`), and an answer that arrives
// after that is given straight back.
//
// A LIBRARY (rule 3): it registers no route, holds no timer of its own
// beyond a question's bound, and requires the logger, the error codes and
// the worker channel.
// ===========================================================================

import bunyan = require('bunyan');
import config = require('../common/config');
import errorCodes = require('../common/error_codes');
import WorkerChannel = require('../common/worker_channel');

const log = bunyan.createLogger({ name: 'sts-directory-create-arbiter' });
config.registerLogger(log);

/** What a claim is answered. */
interface ArbiterAnswer {
  ok: boolean;
  // On a grant.
  reservation?: string;
  catchUp?: boolean;
  // With `catchUp`: the release order its catch-up will cover, which the
  // winner reports back once the catch-up has finished (`caughtUp()`).
  through?: number;
  // On a refusal: 'used', or 'store' for one that could not be decided.
  reason?: string;
  index?: number;
  code?: string;
  why?: string;
}

// A live claim on one key.
interface Live {
  holder: string;
  reservation: string;
  expiresAt: number;
}

// The last committed create of one key: who gave it back, and when, in the
// order of every such release.
interface Settled {
  seq: number;
  holder: string;
}

// A pool's table entry, as much of it as this module reads.
interface WorkerEntry {
  pid: number | string;
  child: { send(message: any): any };
}

interface ArbiterDeps {
  log: {
    debug(message: string): void;
    warn(message: string): void;
  };
  errorCodes: { tag(code: string): string };
  channel: {
    inWorkerThread(): boolean;
    send(message: any): boolean;
    onKind(key: string, listener: (message: any) => void): unknown;
  };
  now(): number;
}

/**
 * The front process's arbitration of directory create claims between itself
 * and its own request workers, in memory; and, in a worker, the client that
 * asks it over the worker channel.
 */
class DirectoryCreateArbiter {
  /** The most claims held at once before a claim is refused (a leak). */
  static readonly MAX_LIVE = 16384;
  /** The most keys whose last committed create is remembered. */
  static readonly MAX_SETTLED = 8192;
  /** The most keys one claim may carry. */
  static readonly MAX_KEYS = 64;
  /** How long a worker waits for the front process's answer. */
  static readonly ANSWER_MS = 10000;
  /** The holder name of the front process itself. */
  static readonly FRONT = 'front';

  // key -> the claim on it.
  private readonly live = new Map<string, Live>();
  // key -> its last committed create; insertion order is age.
  private readonly settled = new Map<string, Settled>();
  // holder -> the `seq` at its last catch-up.
  private readonly pulledThrough = new Map<string, number>();
  private seq = 0;
  private forgottenThrough = 0;
  private nextReservation = 0;
  private full = false;
  // In a worker: question id -> its waiter.
  private readonly asking = new Map<number, {
    resolve: (answer: ArbiterAnswer) => void;
    timer: NodeJS.Timeout;
  }>();
  private nextQuestion = 1;
  private listening = false;

  /**
   * Builds the arbiter from its dependencies.
   *
   * @param deps - the logger, the error codes, the worker channel and a clock
   */
  constructor(private readonly deps: ArbiterDeps) {
    deps.log.debug("Entering DirectoryCreateArbiter.constructor().");
    deps.log.debug("Leaving DirectoryCreateArbiter.constructor().");
  }

  /**
   * Returns the real dependencies.
   *
   * @returns the dependencies
   */
  static defaultDeps(): ArbiterDeps {
    log.debug("Entering DirectoryCreateArbiter.defaultDeps().");
    log.debug("Leaving DirectoryCreateArbiter.defaultDeps().");
    return {
      log: log,
      errorCodes: errorCodes,
      channel: WorkerChannel,
      now: function () {
        return Date.now();
      }
    };
  }

  /**
   * The holder name of a worker, from the pool's table entry — the front
   * process's own view of who is asking, never one the worker supplies.
   *
   * @param entry - the worker's table entry
   * @returns the holder name
   */
  static holderOf(entry: WorkerEntry): string {
    log.debug("Entering DirectoryCreateArbiter.holderOf().");
    log.debug("Leaving DirectoryCreateArbiter.holderOf().");
    return 'worker:' + String(entry && entry.pid);
  }

  // =========================================================================
  // THE FRONT PROCESS'S SIDE.
  // =========================================================================

  /**
   * Decides a claim of every key in `keys` for `holder`, all or none,
   * synchronously.
   *
   * @param holder - who asks
   * @param keys - the keys, each naming a realm, a scope and a value
   * @param ttlMs - the claim's lifetime
   * @returns the grant, with `reservation` and `catchUp`, or the refusal
   */
  decide(holder: string, keys: string[], ttlMs: number): ArbiterAnswer {
    const { log, errorCodes, now } = this.deps;
    log.debug("Entering DirectoryCreateArbiter.decide(). holder=" + holder +
              " keys=" + keys.length);
    const at = now();
    if (this.live.size + keys.length > DirectoryCreateArbiter.MAX_LIVE) {
      this.sweep(at);
    }
    if (this.live.size + keys.length > DirectoryCreateArbiter.MAX_LIVE) {
      if (!this.full) {
        this.full = true;
        log.warn(errorCodes.tag('STS-LDAP-0144') + 'ldap: this node\'s ' +
                 'front process holds ' + this.live.size + ' create ' +
                 'claims, its ceiling, so creates are refused until some ' +
                 'are given back or expire. That many creates are not in ' +
                 'flight at once; something is not giving its claims back.');
      }
      log.debug("Leaving DirectoryCreateArbiter.decide(). Full.");
      return { ok: false, reason: 'store', code: 'STS-LDAP-0144',
               why: 'the front process holds as many create claims as it ' +
                    'may' };
    }
    this.full = false;
    for (let i = 0; i < keys.length; i += 1) {
      const held = this.live.get(keys[i]);
      if (held && held.expiresAt > at) {
        log.debug("Leaving DirectoryCreateArbiter.decide(). Key " + i +
                  " is held.");
        return { ok: false, reason: 'used', index: i };
      }
    }
    // NOTHING ABOVE YIELDED, so every key is still free: take them all.
    this.nextReservation += 1;
    const reservation = String(this.nextReservation);
    const expiresAt = at + Math.max(1000, Number(ttlMs) || 0);
    keys.forEach((key) => {
      this.live.set(key, { holder: holder, reservation: reservation,
                           expiresAt: expiresAt });
    });
    const catchUp = this.mustCatchUp(holder, keys);
    log.debug("Leaving DirectoryCreateArbiter.decide(). Granted" +
              (catchUp ? ', with a catch-up.' : '.'));
    // Its catch-up starts after this moment, so it will see every create
    // committed before it — every release numbered up to `seq` — which it
    // reports when the catch-up has finished.
    return catchUp
      ? { ok: true, reservation: reservation, catchUp: true,
          through: this.seq }
      : { ok: true, reservation: reservation, catchUp: false };
  }

  /**
   * Records that `holder` has FINISHED a catch-up that began after release
   * number `through`, so a create given back up to then needs no other pull.
   *
   * @param holder - who caught up
   * @param through - the `through` its grant carried
   */
  caughtUpTo(holder: string, through: number): void {
    const { log } = this.deps;
    log.debug("Entering DirectoryCreateArbiter.caughtUpTo(). holder=" +
              holder + " through=" + through);
    const at = Math.min(this.seq, Math.max(0, Math.floor(Number(through) ||
                                                         0)));
    if (at > (this.pulledThrough.get(holder) || 0)) {
      this.pulledThrough.set(holder, at);
    }
    log.debug("Leaving DirectoryCreateArbiter.caughtUpTo().");
  }

  // Whether `holder` must pull the store before its door looks: a key's last
  // committed create was given back by somebody else after its last catch-up,
  // or a remembered create it may not have seen has been forgotten.
  private mustCatchUp(holder: string, keys: string[]): boolean {
    const { log } = this.deps;
    log.debug("Entering DirectoryCreateArbiter.mustCatchUp().");
    const since = this.pulledThrough.get(holder) || 0;
    if (this.forgottenThrough > since) {
      log.debug("Leaving DirectoryCreateArbiter.mustCatchUp(). Forgotten.");
      return true;
    }
    const must = keys.some((key) => {
      const last = this.settled.get(key);
      return !!last && last.seq > since &&
        (holder === DirectoryCreateArbiter.FRONT || last.holder !== holder);
    });
    log.debug("Leaving DirectoryCreateArbiter.mustCatchUp().");
    return must;
  }

  /**
   * Gives a claim back. `committed` says the create it guarded has
   * committed, which is remembered for the next winner's catch-up.
   *
   * @param holder - who held it
   * @param reservation - the reservation it was granted under
   * @param keys - its keys
   * @param committed - true when its create committed
   * @returns how many keys were given back
   */
  settle(holder: string, reservation: string, keys: string[],
         committed: boolean): number {
    const { log } = this.deps;
    log.debug("Entering DirectoryCreateArbiter.settle(). holder=" + holder +
              " committed=" + committed);
    let released = 0;
    keys.forEach((key) => {
      const held = this.live.get(key);
      if (!held || held.holder !== holder ||
          held.reservation !== String(reservation)) {
        return;
      }
      this.live.delete(key);
      released += 1;
      if (committed) {
        this.seq += 1;
        // Deleted first, so a key given back again is the YOUNGEST.
        this.settled.delete(key);
        this.settled.set(key, { seq: this.seq, holder: holder });
      }
    });
    while (this.settled.size > DirectoryCreateArbiter.MAX_SETTLED) {
      const oldest = this.settled.keys().next().value as string;
      const was = this.settled.get(oldest);
      this.forgottenThrough = Math.max(this.forgottenThrough,
                                       was ? was.seq : 0);
      this.settled.delete(oldest);
    }
    log.debug("Leaving DirectoryCreateArbiter.settle(). " + released +
              " released.");
    return released;
  }

  /**
   * Gives back every claim a holder held, and forgets its catch-up: for a
   * worker that has exited, which will never give them back itself.
   *
   * @param holder - the holder
   * @returns how many keys were given back
   */
  dropHolder(holder: string): number {
    const { log } = this.deps;
    log.debug("Entering DirectoryCreateArbiter.dropHolder(). " + holder);
    let dropped = 0;
    this.live.forEach((held, key) => {
      if (held.holder === holder) {
        this.live.delete(key);
        dropped += 1;
      }
    });
    this.pulledThrough.delete(holder);
    log.debug("Leaving DirectoryCreateArbiter.dropHolder(). " + dropped +
              " given back.");
    return dropped;
  }

  /**
   * The pool's `reap()` calls this for a worker that has exited.
   *
   * @param entry - the worker's table entry
   * @returns how many keys were given back
   */
  workerExited(entry: WorkerEntry): number {
    const { log } = this.deps;
    log.debug("Entering DirectoryCreateArbiter.workerExited().");
    log.debug("Leaving DirectoryCreateArbiter.workerExited().");
    return this.dropHolder(DirectoryCreateArbiter.holderOf(entry));
  }

  /**
   * The pool's message handler calls this with a worker's `{ createClaim }`
   * message: a claim, answered on the worker's channel, or a release.
   *
   * @param entry - the worker's table entry
   * @param message - the message
   */
  receive(entry: WorkerEntry, message: any): void {
    const { log } = this.deps;
    log.debug("Entering DirectoryCreateArbiter.receive(). op=" +
              (message && message.op));
    const holder = DirectoryCreateArbiter.holderOf(entry);
    const keys = DirectoryCreateArbiter.keysOf(message && message.keys);
    if (message && message.op === 'caughtUp') {
      this.caughtUpTo(holder, Number(message.through) || 0);
      log.debug("Leaving DirectoryCreateArbiter.receive(). Caught up.");
      return;
    }
    if (message && message.op === 'release') {
      if (keys) {
        this.settle(holder, String(message.reservation || ''), keys,
                    message.committed === true);
      }
      log.debug("Leaving DirectoryCreateArbiter.receive(). Released.");
      return;
    }
    if (!message || message.op !== 'claim') {
      log.debug("Leaving DirectoryCreateArbiter.receive(). Not a claim.");
      return;
    }
    const answer: ArbiterAnswer = keys
      ? this.decide(holder, keys, Number(message.ttlMs) || 0)
      : { ok: false, reason: 'store', code: 'STS-LDAP-0093',
          why: 'the claim named no keys this arbiter can hold' };
    try {
      // A grant names its keys, so a worker that gave up waiting for it can
      // give it straight back.
      entry.child.send(Object.assign({ createClaim: true, answer: true,
                                       id: message.id,
                                       keys: answer.ok ? keys : [] },
                                     answer));
    } catch (e) {
      log.debug("Caught in DirectoryCreateArbiter.receive(): " +
                ((e && e.message) || e));
      // The worker has gone between asking and being answered: what it was
      // granted goes back now rather than waiting for `reap()`.
      if (answer.ok && keys) {
        this.settle(holder, String(answer.reservation), keys, false);
      }
    }
    log.debug("Leaving DirectoryCreateArbiter.receive().");
  }

  // The keys a message names, or null for anything that is not a short list
  // of strings.
  private static keysOf(value: any): string[] | null {
    log.debug("Entering DirectoryCreateArbiter.keysOf().");
    const ok = Array.isArray(value) && value.length > 0 &&
      value.length <= DirectoryCreateArbiter.MAX_KEYS &&
      value.every(function (one) {
        return typeof one === 'string' && one.length > 0 &&
          one.length <= 4096;
      });
    log.debug("Leaving DirectoryCreateArbiter.keysOf().");
    return ok ? value.slice(0) : null;
  }

  // Lets go of every claim whose lifetime has passed.
  private sweep(at: number): void {
    const { log } = this.deps;
    log.debug("Entering DirectoryCreateArbiter.sweep().");
    this.live.forEach((held, key) => {
      if (held.expiresAt <= at) {
        this.live.delete(key);
      }
    });
    log.debug("Leaving DirectoryCreateArbiter.sweep().");
  }

  // =========================================================================
  // EVERY PROCESS'S SIDE: what `directory_create_claims.ts` calls.
  // =========================================================================

  /**
   * Asks for a claim of every key: of this process's own arbitration in the
   * front process, and of the front process over the worker channel in a
   * worker.
   *
   * @param keys - the keys
   * @param ttlMs - the claim's lifetime
   * @returns a promise of the answer; it never rejects
   */
  ask(keys: string[], ttlMs: number): Promise<ArbiterAnswer> {
    const { log, errorCodes, channel } = this.deps;
    log.debug("Entering DirectoryCreateArbiter.ask().");
    if (!channel.inWorkerThread()) {
      log.debug("Leaving DirectoryCreateArbiter.ask(). The front decides.");
      return Promise.resolve(this.decide(DirectoryCreateArbiter.FRONT, keys,
                                         ttlMs));
    }
    this.listen();
    const id = this.nextQuestion;
    this.nextQuestion += 1;
    log.debug("Leaving DirectoryCreateArbiter.ask(). Asking the front.");
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        if (!this.asking.delete(id)) {
          return;
        }
        log.warn(errorCodes.tag('STS-LDAP-0145') + 'ldap: the front ' +
                 'process did not answer this worker\'s create claim within ' +
                 DirectoryCreateArbiter.ANSWER_MS + 'ms; the create is ' +
                 'refused rather than made unclaimed.');
        resolve({ ok: false, reason: 'store', code: 'STS-LDAP-0145',
                  why: 'the front process did not answer' });
      }, DirectoryCreateArbiter.ANSWER_MS);
      if (timer.unref) {
        timer.unref();
      }
      this.asking.set(id, { resolve: resolve, timer: timer });
      const sent = channel.send({ createClaim: true, op: 'claim', id: id,
                                  keys: keys, ttlMs: ttlMs });
      if (!sent) {
        clearTimeout(timer);
        this.asking.delete(id);
        resolve({ ok: false, reason: 'store', code: 'STS-LDAP-0145',
                  why: 'the front process could not be asked' });
      }
    });
  }

  /**
   * Gives a claim back: to this process's own arbitration in the front
   * process, over the worker channel in a worker.
   *
   * @param reservation - the reservation it was granted under
   * @param keys - its keys
   * @param committed - true when its create committed
   */
  give(reservation: string, keys: string[], committed: boolean): void {
    const { log, channel } = this.deps;
    log.debug("Entering DirectoryCreateArbiter.give(). committed=" +
              committed);
    if (!channel.inWorkerThread()) {
      this.settle(DirectoryCreateArbiter.FRONT, reservation, keys, committed);
      log.debug("Leaving DirectoryCreateArbiter.give(). Given back here.");
      return;
    }
    channel.send({ createClaim: true, op: 'release',
                   reservation: reservation, keys: keys,
                   committed: committed });
    log.debug("Leaving DirectoryCreateArbiter.give(). Sent to the front.");
  }

  /**
   * Says a catch-up has finished: to this process's own arbitration in the
   * front process, over the worker channel in a worker.
   *
   * @param through - the `through` the grant carried
   */
  caughtUp(through: number): void {
    const { log, channel } = this.deps;
    log.debug("Entering DirectoryCreateArbiter.caughtUp().");
    if (!channel.inWorkerThread()) {
      this.caughtUpTo(DirectoryCreateArbiter.FRONT, through);
      log.debug("Leaving DirectoryCreateArbiter.caughtUp(). Here.");
      return;
    }
    channel.send({ createClaim: true, op: 'caughtUp', through: through });
    log.debug("Leaving DirectoryCreateArbiter.caughtUp(). Sent to the front.");
  }

  // In a worker, the front's answers, from the one listener this installs.
  private listen(): void {
    const { log, channel } = this.deps;
    log.debug("Entering DirectoryCreateArbiter.listen().");
    if (!this.listening) {
      this.listening = true;
      channel.onKind('createClaim', (message: any) => {
        this.answered(message);
      });
    }
    log.debug("Leaving DirectoryCreateArbiter.listen().");
  }

  /**
   * In a worker: delivers the front process's answer to the question it
   * answers. An answer nobody is waiting for any more is a grant given
   * straight back.
   *
   * @param message - the `{ createClaim, answer }` message
   */
  answered(message: any): void {
    const { log, channel } = this.deps;
    log.debug("Entering DirectoryCreateArbiter.answered().");
    if (!message || message.answer !== true) {
      log.debug("Leaving DirectoryCreateArbiter.answered(). Not an answer.");
      return;
    }
    const waiting = this.asking.get(Number(message.id));
    if (!waiting) {
      if (message.ok && message.reservation) {
        log.debug("DirectoryCreateArbiter.answered(): a grant arrived after " +
                  "its question was given up on; it is given back.");
        channel.send({ createClaim: true, op: 'release',
                       reservation: String(message.reservation),
                       keys: Array.isArray(message.keys) ? message.keys : [],
                       committed: false });
      }
      log.debug("Leaving DirectoryCreateArbiter.answered(). Nobody waits.");
      return;
    }
    this.asking.delete(Number(message.id));
    clearTimeout(waiting.timer);
    waiting.resolve({ ok: message.ok === true,
                      reservation: message.reservation,
                      catchUp: message.catchUp === true,
                      through: Number(message.through) || 0,
                      reason: message.reason, index: message.index,
                      code: message.code, why: message.why });
    log.debug("Leaving DirectoryCreateArbiter.answered().");
  }

  /**
   * What is held and remembered, for a test or a status line.
   *
   * @returns the counts
   */
  stats(): { live: number; settled: number; seq: number;
             forgottenThrough: number; holders: number } {
    const { log } = this.deps;
    log.debug("Entering DirectoryCreateArbiter.stats().");
    log.debug("Leaving DirectoryCreateArbiter.stats().");
    return { live: this.live.size, settled: this.settled.size,
             seq: this.seq, forgottenThrough: this.forgottenThrough,
             holders: this.pulledThrough.size };
  }

  /**
   * Forgets everything. For tests.
   */
  reset(): void {
    const { log } = this.deps;
    log.debug("Entering DirectoryCreateArbiter.reset().");
    this.live.clear();
    this.settled.clear();
    this.pulledThrough.clear();
    this.seq = 0;
    this.forgottenThrough = 0;
    this.full = false;
    log.debug("Leaving DirectoryCreateArbiter.reset().");
  }
}

// THE ONE INSTANCE A PROCESS HAS: the front process's arbitration is state
// every caller in it must share, and a worker's questions share one channel
// listener.
const instance = new DirectoryCreateArbiter(
  DirectoryCreateArbiter.defaultDeps());

/**
 * One node's directory create claims, decided by its front process in
 * memory: the class, and this process's instance.
 *
 * @namespace
 */
export = {
  DirectoryCreateArbiter: DirectoryCreateArbiter,
  /** This process's arbiter. */
  arbiter: instance,
  /** The holder name of a worker's table entry. */
  holderOf: DirectoryCreateArbiter.holderOf
};
