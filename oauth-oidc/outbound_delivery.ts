'use strict';
//
// File: outbound_delivery.ts
//
// ===========================================================================
// ONE DURABLE, COORDINATED OUTBOUND DELIVERY QUEUE, FOR EVERY KIND OF THING
// THIS SERVICE POSTS TO A RELYING PARTY'S REGISTERED ADDRESS (#151,
// 2026-09-26).
//
// Three things are sent server to server to an address a client registered:
// a Back-Channel Logout Token (`backchannel_logout.ts`, #36), a CIBA ping or
// push (`ciba.ts`, #131), and an OpenID Provider Command Token
// (`provider_commands.ts`, #151). The first was built durable and
// coordinated; the second was a thinner copy of the same idea without the
// fence, the merge, retention, a summary line, an audit row or a retry by
// hand; the third would have been a third copy. rcbj's answer on #151 was
// ONE library, and this is it — the machinery `backchannel_logout.ts`
// argued in its header, lifted out without changing a rule:
//
// **1. A DELIVERY IS A ROW, AND THE ROW IS THE RETRY.** Each kind declares
// its own per-realm store (`realms.map`, persisted, TOMBSTONED, merged by
// `mergeRow` below) at its own declaration — the store rule is the realm
// rule, and this file declares none — and hands it in. State, attempt
// count, when it is next due and whatever the kind needs to resend are on
// the row, so a restarted process or another node picks it up.
//
// **2. EXACTLY ONE PROCESS SENDS EACH ATTEMPT: A CLAIM WITH A LEASE, AND THE
// CLAIM'S TIME IS THE FENCE.** `cluster_claims.claim()` on (delivery,
// generation, attempt number); the winner writes the attempt in flight,
// sends, and records the outcome only while its fence still stands. A row's
// copies are ordered by (generation, attempt, fence, final over pending,
// last update) — `compareRows()` — so a process that paused past its lease
// loses to the one that took over.
//
// **3. IT GOES OUT THROUGH THE OUTBOUND POLICY.** `federation_http`'s
// `deliverForm()` / `deliverJson()` — the kill switch, https with the
// certificate verified, no redirect, the internal-address refusal with the
// connection pinned, the cap.
//
// **4. ONLY WHAT IS WORTH REPEATING IS RETRIED**: a timeout, a connection
// failure, 5xx, 408, 429 — with a doubling backoff, a retry of this
// process's own at the due time, and the kind's sweep job as the net. A final
// failure is a DEAD LETTER with its code, sent again only when an operator
// asks (`retry()`), which starts a new GENERATION. A row pending past the
// retention is dead-lettered, so nothing is pending for ever.
//
// **5. LOGGING IS A SUMMARY**: the kind writes one audit row when a delivery
// finishes (`onFinish`), and this file writes at most one line per kind per
// realm per summary interval.
//
// WHAT A KIND SUPPLIES (`DeliveryKind`): its store, its claim scope, the
// address attribute the outbound policy reads, whether the body is a form or
// JSON, its settings' keys, its error codes, `prepare()` (the body, signing
// a token if it must), optionally `judge()` (a success that is not simply
// 2xx — a Provider Command's answer is read), `onFinish()`, `onRetry()`,
// and its sweep job.
//
// It is a LIBRARY (rule 3): it registers no route, and each kind registers
// its own sweep job through `scheduleSweep()`.
// ===========================================================================

import os = require('os');
import helpers = require('../common/helpers');

type Json = any;

// The states a delivery passes through.
const STATES = ['pending', 'sent', 'dead'];

// This process's name on a row it is sending, for the console.
const HOLDER = os.hostname() + ':' + process.pid;

// The configuration keys a kind's numbers are read from.
interface DeliverySettings {
  attempts: string;
  timeoutMs: string;
  backoffMs: string;
  leaseMs?: string;
  retentionS: string;
  maxRows: string;
  concurrency: string;
  summaryS: string;
}

// A kind's error codes, by what happened.
interface DeliveryCodes {
  outboundOff: string;
  url: string;
  internal: string;
  unresolved: string;
  redirect: string;
  build: string;
  timeout: string;
  network: string;
  status400: string;
  status: string;
  deferred: string;
  stale: string;
  summary: string;
  sweepFailed: string;
  retry: string;
}

// What `prepare()` answers: the body (a form or a JSON value), any headers,
// and fields to write back on the row (a signed token, say) before sending.
interface Prepared {
  body: Json;
  headers?: Record<string, string>;
  patch?: Json;
}

// What `judge()` answers about a result: success or not, the code and a
// sentence, whether a failure is worth another attempt, and fields to write.
interface Judgement {
  ok: boolean;
  code?: string;
  why?: string;
  retry?: boolean;
  patch?: Json;
}

interface DeliveryKind {
  // For log lines: "back-channel logout", "CIBA notification", ...
  label: string;
  // The per-realm store the kind declared.
  store: Json;
  attemptScope: string;
  attribute: string;
  body: 'form' | 'json';
  keepBody?: boolean;
  settings: DeliverySettings;
  codes: DeliveryCodes;
  // Where dead letters are listed, for the summary line.
  deadLetterHint: string;
  prepare(row: Json): Promise<Prepared>;
  judge?(result: Json, row: Json): Judgement | null;
  onFinish?(row: Json, state: string, code: string, why: string): void;
  // Before an operator's retry: a refusal, or fields to refresh.
  onRetry?(row: Json): { problem?: string; patch?: Json };
  viewExtra?(row: Json): Json;
  searchText?(row: Json): string;
  sweepJob: { id: string; title: string; describe: string; owner: string;
              everySetting: string };
  // Extra per-realm work the kind's sweep does (CIBA's request expiry).
  onSweepRealm?(realmId: string): Promise<Json> | Json;
}

interface DeliveryDeps {
  log: typeof helpers.log;
  config: Json;
  realms: Json;
  errorCodes: Json;
  fedHttp: Json;
  claims: Json;
  now: () => number;
  later: (fn: () => void, ms: number) => void;
}

interface ListOptions {
  state?: string;
  since?: number;
  q?: string;
  where?: (row: Json) => boolean;
}

// ---------------------------------------------------------------------------
// WHICH OF TWO COPIES OF A ROW IS NEWER — the stores' `mergeRow`, and the
// comparison every write here makes. A total order, so the merge is pure and
// converges; ties keep the STORED copy.
// ---------------------------------------------------------------------------
function rankOf(row: Json): number[] {
  helpers.log.debug("Entering rankOf().");
  const r = row || {};
  const at = Math.max(Number(r.attempts) || 0, Number(r.inFlight) || 0);
  helpers.log.debug("Leaving rankOf().");
  return [Number(r.generation) || 0, at, Number(r.fenceAt) || 0,
          r.state === 'pending' ? 0 : 1, Number(r.updatedAt) || 0];
}

function compareRows(a: Json, b: Json): number {
  helpers.log.debug("Entering compareRows().");
  const x = rankOf(a);
  const y = rankOf(b);
  for (let i = 0; i < x.length; i++) {
    if (x[i] !== y[i]) {
      helpers.log.debug("Leaving compareRows().");
      return x[i] < y[i] ? -1 : 1;
    }
  }
  helpers.log.debug("Leaving compareRows(). Equal.");
  return 0;
}

// For a kind's store declaration: `realms.map({ ..., mergeRow })`.
function mergeRow(mine: Json, theirs: Json): Json {
  helpers.log.debug("Entering mergeRow().");
  helpers.log.debug("Leaving mergeRow().");
  return compareRows(mine, theirs) > 0 ? mine : theirs;
}

// The fields every delivery row carries, fresh.
function freshFields(at: number): Json {
  helpers.log.debug("Entering freshFields().");
  helpers.log.debug("Leaving freshFields().");
  return { state: 'pending', generation: 1, attempts: 0, inFlight: 0,
           fenceAt: 0, holder: '', status: 0, errorCode: '', why: '',
           queuedAt: at, nextAttemptAt: at, lastAttemptAt: 0, finishedAt: 0,
           updatedAt: at };
}

class OutboundDelivery {
  static readonly STATES = STATES;
  // Per realm, what this process did since its last summary line.
  private readonly tallies = new Map<string, Json>();
  private readonly lastSummaryAt = new Map<string, number>();
  // Attempts in flight in this process for this kind.
  private inFlightHere = 0;

  constructor(private readonly kind: DeliveryKind,
              private readonly deps: DeliveryDeps) {
    deps.log.debug("Entering OutboundDelivery.constructor(). " + kind.label);
    deps.log.debug("Leaving OutboundDelivery.constructor().");
  }

  // The real modules, less the kind's own.
  static defaultDeps(): DeliveryDeps {
    helpers.log.debug("Entering OutboundDelivery.defaultDeps().");
    helpers.log.debug("Leaving OutboundDelivery.defaultDeps().");
    return {
      log: helpers.log,
      config: require('../common/config'),
      realms: require('../common/realms'),
      errorCodes: require('../common/error_codes'),
      fedHttp: require('../federation/federation_http'),
      claims: require('../cluster/cluster_claims'),
      now: function (): number {
        return Date.now();
      },
      later: OutboundDelivery.later
    };
  }

  // A retry of this process's own at a row's due time: a delay inside one
  // operation, which root CLAUDE.md's scheduler rule leaves where it is.
  static later(fn: () => void, ms: number): void {
    helpers.log.debug("Entering OutboundDelivery.later().");
    const timer = setTimeout(fn, Math.max(0, ms));
    // Never the reason a process that is shutting down stays up.
    if (timer && typeof timer.unref === 'function') {
      timer.unref();
    }
    helpers.log.debug("Leaving OutboundDelivery.later().");
  }

  private setting(key: string): number {
    const { log, config } = this.deps;
    log.debug("Entering OutboundDelivery.setting(). " + key);
    log.debug("Leaving OutboundDelivery.setting().");
    return Number(config.value(key));
  }

  // How long an attempt's claim lasts: the setting where the kind has one,
  // and never less than one request's timeout and a second.
  leaseMs(): number {
    const { log } = this.deps;
    log.debug("Entering OutboundDelivery.leaseMs().");
    const timeout = this.setting(this.kind.settings.timeoutMs);
    const lease = Math.max(this.kind.settings.leaseMs
      ? this.setting(this.kind.settings.leaseMs) : 2 * timeout,
      timeout + 1000);
    log.debug("Leaving OutboundDelivery.leaseMs(). " + lease);
    return lease;
  }

  // A row as the store holds it NOW, in its own realm.
  liveRow(realmId: string, id: string): Json | null {
    const { log } = this.deps;
    log.debug("Entering OutboundDelivery.liveRow().");
    const held = this.kind.store.realmMap(realmId).get(id);
    log.debug("Leaving OutboundDelivery.liveRow(). " +
              (held ? 'held' : 'gone'));
    return held ? Object.assign({}, held) : null;
  }

  // WRITE A ROW, unless the store holds a newer copy; answers the copy that
  // stands.
  writeRow(row: Json): Json {
    const { log, now } = this.deps;
    log.debug("Entering OutboundDelivery.writeRow(). " + row.id + " " +
              row.state);
    const store = this.kind.store.realmMap(row.realm);
    const held = store.get(row.id);
    row.updatedAt = Math.max(now(), (held && Number(held.updatedAt) + 1) || 0);
    if (held && compareRows(row, held) < 0) {
      log.debug("Leaving OutboundDelivery.writeRow(). A newer copy stands.");
      return Object.assign({}, held);
    }
    store.set(row.id, Object.assign({}, row));
    log.debug("Leaving OutboundDelivery.writeRow().");
    return row;
  }

  // A NEW DELIVERY: the kind's fields over the generic ones, pending and due
  // now, written in the ambient realm. An id already in the store is LEFT
  // ALONE and answered as it stands (`existing: true`).
  queue(fields: Json): Json {
    const { log, realms, now } = this.deps;
    log.debug("Entering OutboundDelivery.queue(). " + this.kind.label);
    const realmId = String(fields.realm || realms.currentId());
    const held = fields.id ? this.liveRow(realmId, String(fields.id)) : null;
    if (held) {
      log.debug("Leaving OutboundDelivery.queue(). Already queued.");
      return { row: held, existing: true };
    }
    const row = Object.assign(freshFields(now()), fields, {
      id: String(fields.id || helpers.randomId(16)), realm: realmId });
    const written = this.writeRow(row);
    log.debug("Leaving OutboundDelivery.queue().");
    return { row: written, existing: false };
  }

  private tally(realmId: string, what: string, code?: string): void {
    const { log } = this.deps;
    log.debug("Entering OutboundDelivery.tally(). " + what);
    let t = this.tallies.get(realmId);
    if (!t) {
      t = { sent: 0, retried: 0, takenOver: 0, deferred: 0, dead: 0,
            byCode: {} };
      this.tallies.set(realmId, t);
    }
    t[what] = (t[what] || 0) + 1;
    if (code) {
      t.byCode[code] = (t.byCode[code] || 0) + 1;
    }
    log.debug("Leaving OutboundDelivery.tally().");
  }

  // A delivery reaches its final state: the row changes and the kind's
  // `onFinish` writes its one audit row. Answers the row as written.
  finish(row: Json, state: string, code: string, why: string): Json {
    const { log, now } = this.deps;
    log.debug("Entering OutboundDelivery.finish(). " + row.id + " -> " +
              state);
    row.state = state;
    row.errorCode = code || '';
    row.why = why || '';
    row.finishedAt = now();
    row.inFlight = 0;
    row.nextAttemptAt = 0;
    const written = this.writeRow(row);
    if (written.state !== state || written.updatedAt !== row.updatedAt) {
      log.debug("Leaving OutboundDelivery.finish(). A newer copy stood; " +
                "its writer reports it.");
      return written;
    }
    this.tally(row.realm, state === 'sent' ? 'sent' : 'dead', code);
    if (this.kind.onFinish) {
      try {
        this.kind.onFinish(written, state, code, why);
      } catch (e) {
        log.debug("Caught in OutboundDelivery.finish(): " +
                  ((e && e.message) || e));
      }
    }
    log.debug("Leaving OutboundDelivery.finish().");
    return written;
  }

  // How a failed attempt is coded, and whether it is worth another.
  classify(result: Json): Json {
    const { log } = this.deps;
    const c = this.kind.codes;
    log.debug("Entering OutboundDelivery.classify(). kind=" + result.kind);
    const status = Number(result.status) || 0;
    const table = {
      'outbound-off': [c.outboundOff, false],
      'url': [c.url, false],
      'attribute': [c.url, false],
      'ca-file': [c.url, false],
      'internal': [c.internal, false],
      'unresolved': [c.unresolved, false],
      'redirect': [c.redirect, false],
      'build': [c.build, false],
      'timeout': [c.timeout, true],
      'network': [c.network, true]
    };
    let answer = null;
    if (result.kind === 'status') {
      answer = status === 400
        ? { code: c.status400, retry: false }
        : { code: c.status,
            retry: status >= 500 || status === 408 || status === 429 };
    } else {
      const row = table[result.kind] || [c.network, true];
      answer = { code: row[0], retry: row[1] };
    }
    log.debug("Leaving OutboundDelivery.classify(). " + answer.code +
              ", retry=" + answer.retry);
    return answer;
  }

  private scheduleRetry(realmId: string, id: string, atMs: number): void {
    const { log, realms, now, later } = this.deps;
    const self = this;
    log.debug("Entering OutboundDelivery.scheduleRetry(). " + id);
    const realm = realms.get(realmId);
    later(function () {
      realms.run(realm, function () {
        return self.attempt(realmId, id).catch(function (e) {
          log.debug("Caught in OutboundDelivery.scheduleRetry(): " +
                    ((e && e.message) || e));
        });
      });
    }, atMs - now());
    log.debug("Leaving OutboundDelivery.scheduleRetry().");
  }

  // -------------------------------------------------------------------------
  // ONE ATTEMPT of one delivery, claimed. Resolves `sent`, `retry`, `dead`,
  // or why nothing was done (`not-due`, `claimed-elsewhere`, `deferred`,
  // `gone`). Never rejects.
  // -------------------------------------------------------------------------
  async attempt(realmId: string, id: string): Promise<string> {
    const { log, claims, fedHttp, now, errorCodes } = this.deps;
    const kind = this.kind;
    log.debug("Entering OutboundDelivery.attempt(). " + id);
    const before = this.liveRow(realmId, id);
    if (!before || before.state !== 'pending') {
      log.debug("Leaving OutboundDelivery.attempt(). Not pending.");
      return 'gone';
    }
    if (Number(before.nextAttemptAt) > now()) {
      log.debug("Leaving OutboundDelivery.attempt(). Not due.");
      return 'not-due';
    }
    const n = Number(before.inFlight) || (Number(before.attempts) + 1);
    const lease = this.leaseMs();
    const answer: Json = await claims.claim({
      scope: kind.attemptScope,
      value: id + ':' + before.generation + ':' + n,
      ttlMs: lease,
      realm: realmId
    });
    if (!answer.ok) {
      if (answer.reason === 'store') {
        this.tally(realmId, 'deferred', kind.codes.deferred);
      }
      log.debug("Leaving OutboundDelivery.attempt(). Not claimed (" +
                answer.reason + ").");
      return answer.reason === 'store' ? 'deferred' : 'claimed-elsewhere';
    }
    // Re-read under the claim.
    let row = this.liveRow(realmId, id);
    if (!row || row.state !== 'pending' ||
        row.generation !== before.generation) {
      log.debug("Leaving OutboundDelivery.attempt(). It changed under the " +
                "claim.");
      return 'gone';
    }
    if (Number(row.inFlight) === n && Number(row.fenceAt) > 0) {
      // A lapsed lease: the claim just won proves the earlier one expired.
      this.tally(realmId, 'takenOver');
      log.debug("OutboundDelivery.attempt(): taking over attempt " + n +
                " of " + id + " from " + (row.holder || 'an unnamed holder') +
                ".");
    }
    const startedAt = now();
    const claimedFence = Number(answer.claimedAt) || startedAt;
    row.inFlight = n;
    row.fenceAt = claimedFence;
    row.holder = HOLDER;
    row.lastAttemptAt = startedAt;
    row.nextAttemptAt = startedAt + lease;
    row = this.writeRow(row);
    if (row.fenceAt !== claimedFence || row.inFlight !== n) {
      log.debug("Leaving OutboundDelivery.attempt(). Fenced out before " +
                "sending.");
      return 'claimed-elsewhere';
    }
    const fence = row.fenceAt;
    let prepared: Prepared;
    try {
      prepared = await kind.prepare(row);
      if (prepared && prepared.patch) {
        row = this.writeRow(Object.assign(row, prepared.patch));
      }
    } catch (e) {
      log.debug("Caught in OutboundDelivery.attempt(): " +
                ((e && e.message) || e));
      const current = this.liveRow(realmId, id) || row;
      if (current.fenceAt === fence) {
        current.attempts = n;
        this.finish(current, 'dead',
                    errorCodes.codeOf(e) || kind.codes.build,
                    String((e && e.message) || e));
      }
      log.debug("Leaving OutboundDelivery.attempt(). Not prepared.");
      return 'dead';
    }
    const record = { id: row.clientId };
    record[kind.attribute] = row.uri;
    const options = { timeoutMs: this.setting(kind.settings.timeoutMs),
                      keepBody: !!kind.keepBody };
    let result: Json = null;
    try {
      result = kind.body === 'json'
        ? await fedHttp.deliverJson(record, kind.attribute, prepared.body,
                                    prepared.headers || {}, options)
        : await fedHttp.deliverForm(record, kind.attribute, prepared.body,
                                    options);
    } catch (e) {
      log.debug("Caught in OutboundDelivery.attempt(): " +
                ((e && e.message) || e));
      result = { ok: false, kind: 'build', status: 0,
                 why: String((e && e.message) || e) };
    }
    // The outcome, written only while this process still holds the attempt.
    const current = this.liveRow(realmId, id);
    if (!current || current.fenceAt !== fence ||
        current.generation !== row.generation) {
      log.debug("Leaving OutboundDelivery.attempt(). Fenced out after " +
                "sending; the process that took over records it.");
      return 'claimed-elsewhere';
    }
    current.attempts = n;
    current.inFlight = 0;
    current.status = Number(result.status) || 0;
    let judged: Json = kind.judge ? kind.judge(result, current) : null;
    if (!judged) {
      judged = result.ok ? { ok: true } :
        Object.assign({ why: String(result.why || 'it failed') },
                      this.classify(result));
    }
    if (judged.patch) {
      Object.assign(current, judged.patch);
    }
    if (judged.ok) {
      this.finish(current, 'sent', '', '');
      log.debug("Leaving OutboundDelivery.attempt(). Sent.");
      return 'sent';
    }
    const attempts = Math.max(1, this.setting(kind.settings.attempts));
    const why = String(judged.why || result.why || 'it failed');
    if (!judged.retry || n >= attempts) {
      this.finish(current, 'dead', judged.code || kind.codes.status,
                  why + (n > 1 ? ' (after ' + n + ' attempts)' : ''));
      log.debug("Leaving OutboundDelivery.attempt(). Dead.");
      return 'dead';
    }
    const backoff = Math.max(0, this.setting(kind.settings.backoffMs)) *
      Math.pow(2, n - 1);
    current.errorCode = judged.code || '';
    current.why = why + ' (attempt ' + n + '; trying again)';
    current.nextAttemptAt = now() + backoff;
    const written = this.writeRow(current);
    this.tally(realmId, 'retried');
    this.scheduleRetry(realmId, id, written.nextAttemptAt);
    log.debug("Leaving OutboundDelivery.attempt(). Retry in " + backoff +
              "ms.");
    return 'retry';
  }

  // Attempt every given row still pending, now. Settles when each has been
  // attempted once; never rejects.
  dispatch(rows: Json[] | null | undefined): Promise<void> {
    const { log, realms } = this.deps;
    const self = this;
    log.debug("Entering OutboundDelivery.dispatch().");
    const pending = (rows || []).filter(function (row) {
      return row && row.state === 'pending';
    });
    if (!pending.length) {
      log.debug("Leaving OutboundDelivery.dispatch(). Nothing to send.");
      return Promise.resolve();
    }
    const realmId = realms.currentId();
    log.debug("Leaving OutboundDelivery.dispatch(). " + pending.length +
              " to send.");
    return Promise.all(pending.map(function (row) {
      return self.attempt(row.realm || realmId, row.id)
        .catch(function (e) {
          log.debug("Caught in OutboundDelivery.dispatch(): " +
                    ((e && e.message) || e));
          return 'error';
        });
    })).then(function () {
      return undefined;
    });
  }

  // -------------------------------------------------------------------------
  // AN OPERATOR'S RETRY OF A DEAD LETTER: a new generation and a fresh
  // attempt budget, after the kind's `onRetry` has refreshed what it must
  // (the client's current address, above all) or refused. `{ ok, message,
  // row }`, a refusal carrying the kind's retry code. `reset` names the
  // kind's fields cleared for the new generation (a signed token).
  // -------------------------------------------------------------------------
  retry(id: string, actor: string, noun: string, reset?: Json): Json {
    const { log, realms, errorCodes, now } = this.deps;
    log.debug("Entering OutboundDelivery.retry(). " + id);
    const code = this.kind.codes.retry;
    const row = this.liveRow(realms.currentId(), String(id || ''));
    if (!row) {
      log.debug("Leaving OutboundDelivery.retry(). Unknown.");
      return errorCodes.mark({ ok: false, message: 'There is no ' + noun +
        ' delivery "' + String(id || '') + '" in this realm; it may have ' +
        'been removed by retention.' }, code);
    }
    if (row.state !== 'dead') {
      log.debug("Leaving OutboundDelivery.retry(). Not dead.");
      return errorCodes.mark({ ok: false, message: 'The delivery to ' +
        row.clientId + ' is ' + row.state + ', not a dead letter; only a ' +
        'dead letter is retried by hand.' }, code);
    }
    const refreshed = this.kind.onRetry ? this.kind.onRetry(row) || {} : {};
    if (refreshed.problem) {
      log.debug("Leaving OutboundDelivery.retry(). Refused by the kind.");
      return errorCodes.mark({ ok: false, message: refreshed.problem }, code);
    }
    const fresh = Object.assign(row, refreshed.patch || {}, reset || {}, {
      state: 'pending', generation: row.generation + 1, attempts: 0,
      inFlight: 0, fenceAt: 0, holder: '', status: 0, errorCode: '',
      why: 'retried by ' + (actor || 'an administrator'),
      nextAttemptAt: now(), finishedAt: 0
    });
    const written = this.writeRow(fresh);
    this.dispatch([written]);
    log.debug("Leaving OutboundDelivery.retry(). Generation " +
              written.generation + ".");
    return { ok: true, row: written };
  }

  // -------------------------------------------------------------------------
  // THE SWEEP: every realm, the rows that are due, bounded by the kind's
  // concurrency in this process; retention; the kind's own per-realm work;
  // the summary line. Resolves the totals; never rejects.
  // -------------------------------------------------------------------------
  sweep(): Promise<Json> {
    const { log, realms, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering OutboundDelivery.sweep(). " + this.kind.label);
    const total: Json = { attempted: 0, removed: 0, dead: 0 };
    let chain: Promise<unknown> = Promise.resolve();
    realms.list().forEach(function (realm) {
      chain = chain.then(function () {
        return realms.run(realm, function () {
          return self.sweepRealm(realm.id).then(function (one: Json) {
            Object.keys(one).forEach(function (k) {
              total[k] = (Number(total[k]) || 0) + (Number(one[k]) || 0);
            });
          });
        });
      }).catch(function (e) {
        log.debug("Caught in OutboundDelivery.sweep(): " +
                  ((e && e.message) || e));
        // error-code: none — the kind's own sweep code, tagged here.
        log.error(errorCodes.tag(self.kind.codes.sweepFailed) +
                  self.kind.label + ': the delivery sweep failed in the "' +
                  realm.id + '" realm: ' + ((e && e.message) || e));
      });
    });
    log.debug("Leaving OutboundDelivery.sweep().");
    return chain.then(function () {
      return total;
    });
  }

  private async sweepRealm(realmId: string): Promise<Json> {
    const { log, now } = this.deps;
    const self = this;
    const kind = this.kind;
    log.debug("Entering OutboundDelivery.sweepRealm(). " + realmId);
    const at = now();
    const keepMs = Math.max(1, this.setting(kind.settings.retentionS)) * 1000;
    const cap = Math.max(1, this.setting(kind.settings.maxRows));
    const store = kind.store.realmMap(realmId);
    const due: string[] = [];
    const finished: Json[] = [];
    const stale: Json[] = [];
    let dead = 0;
    store.forEach(function (row: Json, id: string) {
      if (!row) {
        return;
      }
      if (row.state === 'pending') {
        if (at - Number(row.queuedAt) > keepMs) {
          stale.push(Object.assign({}, row));
        } else if (!(Number(row.nextAttemptAt) > at)) {
          due.push(id);
        }
        return;
      }
      finished.push(row);
    });
    stale.forEach(function (row) {
      self.finish(row, 'dead', kind.codes.stale,
                  'still unsent ' + Math.round(keepMs / 1000) + ' seconds ' +
                  'after it was queued (' + kind.settings.retentionS + ')');
      dead++;
    });
    let removed = 0;
    finished.sort(function (a, b) {
      return Number(a.queuedAt) - Number(b.queuedAt);
    });
    const over = Math.max(0, store.size - cap);
    finished.forEach(function (row, i) {
      if (at - Number(row.queuedAt) > keepMs || i < over) {
        store.delete(row.id);
        removed++;
      }
    });
    const limit = Math.max(1, this.setting(kind.settings.concurrency));
    let attempted = 0;
    const next = function (): Promise<void> {
      log.debug("Entering next().");
      const id = due.shift();
      if (id === undefined || self.inFlightHere >= limit) {
        log.debug("Leaving next(). Nothing more this sweep.");
        return Promise.resolve();
      }
      self.inFlightHere++;
      attempted++;
      log.debug("Leaving next().");
      return self.attempt(realmId, id).catch(function (e) {
        log.debug("Caught in next(): " + ((e && e.message) || e));
        return 'error';
      }).then(function () {
        self.inFlightHere--;
        return next();
      });
    };
    const lanes = [];
    for (let i = 0; i < limit; i++) {
      lanes.push(next());
    }
    await Promise.all(lanes);
    let extra: Json = {};
    if (kind.onSweepRealm) {
      extra = (await kind.onSweepRealm(realmId)) || {};
    }
    this.summarise(realmId);
    log.debug("Leaving OutboundDelivery.sweepRealm(). " + attempted +
              " attempted, " + removed + " removed.");
    return Object.assign({ attempted: attempted, removed: removed,
                           dead: dead }, extra);
  }

  // At most one line per realm per summary interval, when something happened.
  summarise(realmId: string, force?: boolean): string {
    const { log, errorCodes, now } = this.deps;
    log.debug("Entering OutboundDelivery.summarise(). " + realmId);
    const t = this.tallies.get(realmId);
    const at = now();
    const every = Math.max(1, this.setting(this.kind.settings.summaryS)) *
      1000;
    if (!t || (!force &&
               at - (this.lastSummaryAt.get(realmId) || 0) < every)) {
      log.debug("Leaving OutboundDelivery.summarise(). Not due.");
      return '';
    }
    this.tallies.delete(realmId);
    this.lastSummaryAt.set(realmId, at);
    const codes = Object.keys(t.byCode).sort().map(function (code) {
      return code + ' ' + t.byCode[code];
    }).join(', ');
    const line = this.kind.label + ' in the "' + realmId + '" realm since ' +
      'the last summary: ' + t.sent + ' sent, ' + t.retried + ' retried, ' +
      t.takenOver + ' taken over from a lapsed lease, ' + t.deferred +
      ' deferred (claim store unavailable), ' + t.dead + ' dead-lettered' +
      (codes ? ' (' + codes + ')' : '') + '.';
    if (t.dead || t.deferred) {
      log.warn(errorCodes.tag(this.kind.codes.summary) + line + ' ' +
               this.kind.deadLetterHint);
    } else {
      log.info(line);
    }
    log.debug("Leaving OutboundDelivery.summarise().");
    return line;
  }

  // The kind's sweep, as a CLUSTER scheduler job (#49): once, on the leader.
  scheduleSweep(): void {
    const { log } = this.deps;
    const self = this;
    const job = this.kind.sweepJob;
    log.debug("Entering OutboundDelivery.scheduleSweep(). " + job.id);
    const scheduler = require('../cluster/scheduler');
    if (scheduler.job(job.id)) {
      log.debug("Leaving OutboundDelivery.scheduleSweep(). Registered.");
      return;
    }
    scheduler.register({
      id: job.id, title: job.title, describe: job.describe, owner: job.owner,
      everySetting: job.everySetting, everySettingUnit: 's',
      run: function (): Promise<Json> {
        return self.sweep();
      }
    });
    log.debug("Leaving OutboundDelivery.scheduleSweep(). On the scheduler.");
  }

  // A row as a caller sees it: the generic fields, and what the kind adds.
  // Never a token or a body, unless the kind puts it there.
  view(row: Json): Json {
    const { log } = this.deps;
    log.debug("Entering OutboundDelivery.view().");
    const iso = function (ms: unknown): string {
      log.debug("Entering iso().");
      log.debug("Leaving iso().");
      return Number(ms) ? new Date(Number(ms)).toISOString() : '';
    };
    const out = {
      id: row.id, realm: row.realm, clientId: row.clientId, uri: row.uri,
      state: row.state, generation: row.generation, attempts: row.attempts,
      inFlight: !!row.inFlight, holder: row.holder || '',
      status: row.status, errorCode: row.errorCode, why: row.why,
      queuedAt: iso(row.queuedAt), nextAttemptAt: iso(row.nextAttemptAt),
      lastAttemptAt: iso(row.lastAttemptAt), finishedAt: iso(row.finishedAt)
    };
    log.debug("Leaving OutboundDelivery.view().");
    return Object.assign(out, this.kind.viewExtra ?
                               this.kind.viewExtra(row) : {});
  }

  // The rows of the ambient realm, newest first, as stored (the caller
  // views them). `state`, `since`, `q` (a substring of the kind's search
  // text) and `where` narrow.
  rows(options?: ListOptions): Json[] {
    const { log, realms } = this.deps;
    const self = this;
    log.debug("Entering OutboundDelivery.rows().");
    const o = options || {};
    const since = Number(o.since) || 0;
    const q = String(o.q || '').toLowerCase();
    const out: Json[] = [];
    this.kind.store.realmMap(realms.currentId()).forEach(function (row: Json) {
      if (!row || (o.state && row.state !== o.state) ||
          (since && Number(row.queuedAt) < since) ||
          (o.where && !o.where(row))) {
        return;
      }
      if (q) {
        const text = [row.clientId, row.uri, row.errorCode, row.id,
          self.kind.searchText ? self.kind.searchText(row) : '']
          .join(' ').toLowerCase();
        if (text.indexOf(q) < 0) {
          return;
        }
      }
      out.push(row);
    });
    out.sort(function (a, b) {
      return (Number(b.queuedAt) - Number(a.queuedAt)) ||
             String(a.id).localeCompare(String(b.id));
    });
    log.debug("Leaving OutboundDelivery.rows(). " + out.length + " row(s).");
    return out;
  }

  // How many rows are in each state, in the ambient realm.
  counts(): Json {
    const { log, realms } = this.deps;
    log.debug("Entering OutboundDelivery.counts().");
    const out = { pending: 0, sent: 0, dead: 0 };
    this.kind.store.realmMap(realms.currentId()).forEach(function (row: Json) {
      if (row && out[row.state] !== undefined) {
        out[row.state]++;
      }
    });
    log.debug("Leaving OutboundDelivery.counts().");
    return out;
  }
}

// ---------------------------------------------------------------------------
// EVERY KIND, FOR `/admin/deliveries` AND `GET /admin-api/deliveries`: each
// kind's counts and rows, newest first, and a retry of a dead letter by kind.
// The modules are reached lazily — each requires this file — and a kind whose
// module is not loaded is left out.
// ---------------------------------------------------------------------------
const KINDS = [
  { id: 'backchannel-logout', title: 'Back-Channel Logout Tokens',
    module: './backchannel_logout', page: '/admin/logout',
    rows: function (m: Json, o: Json): Json[] {
      return m.list(o);
    },
    counts: function (m: Json): Json {
      return m.counts();
    },
    retry: function (m: Json, id: string, actor: string): Json {
      return m.retry(id, actor);
    } },
  { id: 'ciba', title: 'CIBA pings and pushes', module: './ciba',
    page: '/admin/deliveries',
    rows: function (m: Json, o: Json): Json[] {
      return m.deliveryRows(o);
    },
    counts: function (m: Json): Json {
      return m.deliveryCounts();
    },
    retry: function (m: Json, id: string, actor: string): Json {
      return m.retryDelivery(id, actor);
    } },
  { id: 'provider-commands', title: 'OpenID Provider Commands',
    module: './provider_commands', page: '/admin/commands',
    rows: function (m: Json, o: Json): Json[] {
      return m.deliveryRows(o);
    },
    counts: function (m: Json): Json {
      return m.deliveryCounts();
    },
    retry: function (m: Json, id: string, actor: string): Json {
      return m.retryDelivery(id, actor);
    } }
];

function kindReport(options?: Json): Json {
  helpers.log.debug("Entering kindReport().");
  const o = options || {};
  const limit = Number(o.limit) > 0 ? Number(o.limit) : 200;
  const out = KINDS.filter(function (k) {
    return !o.kind || k.id === String(o.kind);
  }).map(function (k) {
    const m = require(k.module);
    return { id: k.id, title: k.title, page: k.page, counts: k.counts(m),
             rows: k.rows(m, { state: o.state || undefined,
                               q: o.q || undefined }).slice(0, limit) };
  });
  helpers.log.debug("Leaving kindReport(). " + out.length + " kind(s).");
  return { kinds: out, states: STATES.slice(0) };
}

function kindRetry(kind: string, id: string, actor: string): Json {
  helpers.log.debug("Entering kindRetry(). " + kind);
  const found = KINDS.filter(function (k) {
    return k.id === String(kind || '');
  })[0];
  if (!found) {
    helpers.log.debug("Leaving kindRetry(). Unknown kind.");
    return require('../common/error_codes').mark({ ok: false,
      errors: ['Unknown kind "' + String(kind || '') + '". The ' +
               KINDS.length + ' are: ' + KINDS.slice(0, -1).map(function (k) {
                 return k.id;
               }).join(', ') + ' and ' + KINDS[KINDS.length - 1].id + '.'] },
      'STS-OAUTH-0774');
  }
  const result = found.retry(require(found.module), String(id || ''),
                             String(actor || ''));
  if (!result.ok && !result.errors) {
    result.errors = [String(result.message || 'refused')];
  }
  helpers.log.debug("Leaving kindRetry(). " + result.ok);
  return result;
}

export = {
  OutboundDelivery: OutboundDelivery,
  STATES: STATES,
  HOLDER: HOLDER,
  compareRows: compareRows,
  mergeRow: mergeRow,
  freshFields: freshFields,
  KINDS: KINDS.map(function (k) {
    return k.id;
  }),
  kindReport: kindReport,
  kindRetry: kindRetry
};
