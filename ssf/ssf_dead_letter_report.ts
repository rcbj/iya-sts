'use strict';
//
// File: ssf_dead_letter_report.ts
//
// ---------------------------------------------------------------------------
// WHAT THE DEAD-LETTER QUEUES HOLD, COUNTED — Monitoring → Shared Signals →
// Dead letters, and `GET /admin-api/ssf/dead-letters` (2026-09-14).
//
// `/admin/ssf` draws each stream's dead letters inside that stream's card, the
// first twenty-five of each, which answers "what could this stream not be
// sent". It cannot answer the questions somebody arrives with DURING an
// incident: how many, since when, WHY — a receiver refusing, the push backlog
// full, a stream declared dead — which streams, which event types, and whether
// it is still happening. Those are counts over every stream at once, and this
// module is the one place they are computed, so the page and the management
// API cannot come to disagree about them (rule 7).
//
// **PER REALM, BECAUSE THE QUEUE IS.** `ssf_streams.deadLetters` is a
// `realms.map()`: one Map per realm, not one queue with a realm on each row.
// Everything counted here is the AMBIENT realm's, read inside it, and that is
// what the page says at the top.
//
// **THREE THINGS HERE ARE PER PROCESS AND ARE LABELLED SO**, because a reader
// comparing two refreshes answered by two workers would otherwise see numbers
// jump for no reason:
//
//   * THE PUSH CAP (`ssf_http.ts`'s `pushGateState()`). One gate per process,
//     SHARED BY EVERY REALM — the one Shared Signals limit that is not per
//     realm, so a storm in one realm can dead-letter another realm's SETs with
//     STS-SSF-0092. In a dispatched service the console is answered by a
//     SURFACE worker, whose gate is not the one the protocol workers push
//     through; the reply names the process so nobody reads it as the
//     service's.
//   * THE SWEEP HISTORY. Every process sweeps (`ssf.ts`'s THE SWEEP), and what
//     a sweep counts as NEW is that process's own pushes. What it counts as
//     HELD, EXPIRED and ORPHANED is the shared store, so those agree across
//     processes and the new-letter counts do not.
//   * THE SINCE-START TOTALS, for the same reason.
//
// **NO TOKEN LEAVES THIS MODULE.** A dead letter keeps the signed SET so a
// probe can push it; a SET is a signed statement about somebody, and neither a
// console page nor a management API reply is where it goes — `/admin/ssf`'s
// report drops it for the same reason. Each row says whether it WAS signed.
//
// **NOTHING HERE WRITES.** It has no store: the history is a note of what this
// process's sweeps returned, kept in memory like the push gate it sits beside,
// and forgotten on restart. A reset control would make every number on the
// page one somebody might have zeroed, which is `/admin/xacml/monitor`'s
// argument for having none.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `DeadLetterReport` takes the logger, `config`, the error-code table,
// `realms`, the SET describer, the stream store and the push transport through
// its constructor. The sweep notes stay a module-level `realms.keyed()` store,
// declared at load as before. The module still exports its old names as
// FACADES forwarding to the instance the composition root builds (#50, R2),
// for `ssf/ssf.ts`, `admin-core/admin_views.ts` and the tests. A process that
// loads this module without the root builds a default instance when the module
// loads.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
import errorCodes = require('../common/error_codes');
import realms = require('../common/realms');
import events = require('./ssf_events');
import streams = require('./ssf_streams');
import transport = require('./ssf_http');

interface Cause {
  id: string;
  label: string;
  code?: string;
  what: string;
}

// A dead letter as the stream store holds it; only what is read here.
interface Letter {
  stream_id?: string;
  jti?: string;
  errorCode?: string;
  deadAtMs?: number;
  deadAt?: string;
  queuedAt?: string;
  reason?: string;
  status?: number;
  signed?: boolean;
  claims?: unknown;
  [member: string]: unknown;
}

interface DeadLetterReportDeps {
  log: { debug(m: string): void };
  config: { value(key: string): any };
  errorCodes: { describe(code: string): { summary?: string } | null };
  realms: {
    currentId(): string;
  };
  events: { describeSet(claims: any): any };
  streams: {
    DELIVERY_PUSH: string;
    isDead(record: any): boolean;
    deadTimeoutMs(): number;
    listStreams(): any[];
    allDeadLetters(): any[];
  };
  transport: { pushGateState(): unknown };
}

// ---------------------------------------------------------------------------
// WHY A SET WAS DEAD-LETTERED, IN FOUR CAUSES AND NOT ONE PER CODE.
//
// A failed push carries whatever code the push classified it as — a refusal,
// a timeout, a TLS failure, an unclassified one — and there are more than a
// dozen of those. Three codes are not about the push at all: they say this
// service decided not to push. Those are what an operator acts on differently
// (raise `ssf.pushBacklog`; find out why a receiver died), so they are causes
// of their own and every other code is "the push failed". The codes stay on
// every row and in `byCode` — the cause is a grouping, never a replacement.
//
// ORDER IS THE CHART'S STACKING ORDER, bottom up, and the page's legend.
// ---------------------------------------------------------------------------
const CAUSES: Cause[] = [
  { id: 'push-failed', label: 'Push failed',
    what: 'A push was made and did not deliver after ssf.pushRetries: the ' +
          'receiver refused it, answered an error, timed out or could not be ' +
          'reached. The code says which.' },
  { id: 'backlog-full', label: 'Backlog full', code: 'STS-SSF-0092',
    what: 'No push was made: ssf.pushBacklog pushes were already waiting for ' +
          'one of ssf.pushConcurrency slots in the process that sent it. A ' +
          'burst, not a receiver fault.' },
  { id: 'declared-dead', label: 'Waiting when declared dead',
    code: 'STS-SSF-0093',
    what: 'The SET was queued when its stream was declared dead, and was ' +
          'moved off the live queue.' },
  { id: 'dead-stream', label: 'Sent to a dead stream', code: 'STS-SSF-0096',
    what: 'The stream was already dead, so the SET was dead-lettered ' +
          'unsigned instead of being pushed.' }
];

const CAUSE_BY_CODE: Record<string, string> = {};
CAUSES.forEach(function (cause) {
  if (cause.code) {
    CAUSE_BY_CODE[cause.code] = cause.id;
  }
});

// ---------------------------------------------------------------------------
// THE TIMELINE'S BUCKET, from a short list of round sizes, the smallest that
// keeps the whole retention window within SIXTY bars. Sixty because the
// default window is an hour and a minute is the unit somebody watching a
// storm thinks in; the longest window, thirty days, gets sixty half-day bars
// rather than forty-three thousand one-minute ones. Buckets are aligned to the
// epoch, so a refresh a few seconds later moves the bars by whole buckets
// rather than re-cutting every one.
// ---------------------------------------------------------------------------
const BUCKET_STEPS_S = [60, 120, 300, 600, 900, 1800, 3600, 7200, 10800, 21600,
                        43200, 86400];
const MAX_BUCKETS = 60;

// ---------------------------------------------------------------------------
// THE SWEEPS THIS PROCESS HAS RUN, per realm. `ssf.ts` hands over what
// `sweepDeadLetters()` returned plus the two facts only it knows (how many
// streams were dead and how many were probed). The most recent twenty are
// kept, and running totals since the process started.
// ---------------------------------------------------------------------------
const SWEEPS_KEPT = 20;

const sweepNotes = realms.keyed(function () {
  return { recent: [], since: { sweeps: 0, letters: 0, expired: 0,
    orphaned: 0, trimmed: 0, probes: 0 }, firstAt: '' };
});

class DeadLetterReport {
  static readonly CAUSES = CAUSES;

  constructor(private readonly deps: DeadLetterReportDeps) {
    deps.log.debug("Entering DeadLetterReport.constructor().");
    deps.log.debug("Leaving DeadLetterReport.constructor().");
  }

  // Called once per letter per report, so no Entering/Leaving pair: a realm
  // holding a few thousand letters would put a few thousand pairs in the log
  // for one page load.
  causeOf(letter?: Letter | null): string {
    return CAUSE_BY_CODE[String((letter && letter.errorCode) || '')] ||
           'push-failed';
  }

  bucketSecondsFor(windowS: number): number {
    const { log } = this.deps;
    log.debug("Entering DeadLetterReport.bucketSecondsFor(). " + windowS);
    const fits = BUCKET_STEPS_S.filter(function (step) {
      return Math.ceil(windowS / step) <= MAX_BUCKETS;
    });
    const out = fits.length ? fits[0]
                            : BUCKET_STEPS_S[BUCKET_STEPS_S.length - 1];
    log.debug("Leaving DeadLetterReport.bucketSecondsFor(). " + out);
    return out;
  }

  private emptyCounts(): Record<string, number> {
    const { log } = this.deps;
    log.debug("Entering DeadLetterReport.emptyCounts().");
    const out = {};
    CAUSES.forEach(function (cause) {
      out[cause.id] = 0;
    });
    log.debug("Leaving DeadLetterReport.emptyCounts().");
    return out;
  }

  // The held letters by when they were dead-lettered, over the retention
  // window ending now. A letter OLDER than the window is one the next sweep
  // will delete (retention was shortened, or no sweep has run yet) and is
  // counted beside the buckets rather than folded into the first bar, which
  // would draw a spike that never happened. One from a few seconds in the
  // FUTURE — another process's clock — goes in the last bucket.
  private timelineOf(letters: Letter[], nowMs: number,
                     windowS: number): Record<string, unknown> {
    const { log } = this.deps;
    log.debug("Entering DeadLetterReport.timelineOf(). " + letters.length +
              ' letter(s).');
    const bucketS = this.bucketSecondsFor(windowS);
    const bucketMs = bucketS * 1000;
    const endMs = Math.ceil(nowMs / bucketMs) * bucketMs;
    const count = Math.max(1, Math.ceil(windowS / bucketS));
    const startMs = endMs - count * bucketMs;
    const buckets = [];
    for (let i = 0; i < count; i += 1) {
      const from = startMs + i * bucketMs;
      buckets.push({ start: new Date(from).toISOString(), startMs: from,
                     total: 0, counts: this.emptyCounts() });
    }
    let older = 0;
    letters.forEach((letter) => {
      const at = Number(letter.deadAtMs) || 0;
      if (at < startMs) {
        older += 1;
        return;
      }
      const index = Math.min(count - 1,
                             Math.floor((at - startMs) / bucketMs));
      const bucket = buckets[index];
      bucket.total += 1;
      bucket.counts[this.causeOf(letter)] += 1;
    });
    const peak = buckets.reduce(function (n, bucket) {
      return Math.max(n, bucket.total);
    }, 0);
    log.debug("Leaving DeadLetterReport.timelineOf(). " + count +
              ' bucket(s) of ' + bucketS + 's, peak ' + peak + '.');
    return { bucketS: bucketS, windowS: windowS,
             from: new Date(startMs).toISOString(),
             to: new Date(endMs).toISOString(),
             buckets: buckets, peak: peak, olderThanWindow: older };
  }

  // A count per key, as rows sorted biggest first and then by key, so two
  // reports of one store list their rows in one order.
  private countedRows(map: Map<unknown, number>, keyName: string): any[] {
    const { log } = this.deps;
    log.debug("Entering DeadLetterReport.countedRows(). " + keyName);
    const rows = Array.from(map.entries()).map(function (pair) {
      const row: Record<string, any> = {};
      row[keyName] = pair[0];
      row.count = pair[1];
      return row;
    });
    rows.sort(function (a, b) {
      if (b.count !== a.count) {
        return b.count - a.count;
      }
      return String(a[keyName]).localeCompare(String(b[keyName]));
    });
    log.debug("Leaving DeadLetterReport.countedRows(). " + rows.length +
              ' row(s).');
    return rows;
  }

  private bump(map: Map<unknown, number>, key: unknown): void {
    const { log } = this.deps;
    log.debug("Entering DeadLetterReport.bump().");
    map.set(key, (map.get(key) || 0) + 1);
    log.debug("Leaving DeadLetterReport.bump().");
  }

  // -------------------------------------------------------------------------
  // A STREAM'S DELIVERY STATE, in the four words the page uses.
  //
  // `dead` is `streams.isDead()`. `half-open` is a push stream failing for at
  // least `ssf.deadStreamTimeoutS` without being dead — what `halfOpen()`
  // leaves when a dead stream has nothing left to probe with, and equally a
  // stream whose failures began that long ago and has not been pushed to
  // since: in both, ONE more failure declares it dead. `failing` is younger
  // than that. A poll stream is never pushed to and has none of these states.
  // -------------------------------------------------------------------------
  deliveryStateOf(record: any, nowMs: number, timeoutMs: number): string {
    const { log, streams } = this.deps;
    log.debug("Entering DeadLetterReport.deliveryStateOf(). " +
              record.stream_id);
    if (!record.delivery ||
        record.delivery.method !== streams.DELIVERY_PUSH) {
      log.debug("Leaving DeadLetterReport.deliveryStateOf(). Poll.");
      return 'poll';
    }
    if (streams.isDead(record)) {
      log.debug("Leaving DeadLetterReport.deliveryStateOf(). Dead.");
      return 'dead';
    }
    const failingSince = Number(record.failingSinceMs) || 0;
    if (failingSince > 0) {
      const state = timeoutMs && nowMs - failingSince >= timeoutMs
        ? 'half-open' : 'failing';
      log.debug("Leaving DeadLetterReport.deliveryStateOf(). " + state +
                '.');
      return state;
    }
    log.debug("Leaving DeadLetterReport.deliveryStateOf(). Healthy.");
    return 'healthy';
  }

  private isoOrEmpty(ms: unknown): string {
    const { log } = this.deps;
    log.debug("Entering DeadLetterReport.isoOrEmpty().");
    const n = Number(ms) || 0;
    log.debug("Leaving DeadLetterReport.isoOrEmpty().");
    return n > 0 ? new Date(n).toISOString() : '';
  }

  noteSweep(summary?: any, extra?: any): Record<string, any> {
    const { log, realms } = this.deps;
    log.debug("Entering DeadLetterReport.noteSweep(). " + realms.currentId());
    const s = summary || {};
    const x = extra || {};
    const notes = sweepNotes();
    const row = {
      at: new Date(Number(x.nowMs) || Date.now()).toISOString(),
      held: Number(s.held) || 0,
      letters: Number(s.letters) || 0,
      expired: Number(s.expired) || 0,
      orphaned: Number(s.orphaned) || 0,
      trimmed: Number(s.trimmed) || 0,
      deadStreams: Number(x.deadStreams) || 0,
      probes: Number(x.probes) || 0,
      byCode: (s.byCode || []).map(function (pair) {
        return { errorCode: pair[0], count: pair[1] };
      })
    };
    notes.recent.unshift(row);
    if (notes.recent.length > SWEEPS_KEPT) {
      notes.recent.length = SWEEPS_KEPT;
    }
    notes.since.sweeps += 1;
    notes.since.letters += row.letters;
    notes.since.expired += row.expired;
    notes.since.orphaned += row.orphaned;
    notes.since.trimmed += row.trimmed;
    notes.since.probes += row.probes;
    if (!notes.firstAt) {
      notes.firstAt = row.at;
    }
    log.debug("Leaving DeadLetterReport.noteSweep(). " + notes.since.sweeps +
              ' sweep(s).');
    return row;
  }

  private processRole(): string {
    const { log } = this.deps;
    log.debug("Entering DeadLetterReport.processRole().");
    let role = 'the front process, or the only one';
    if (process.env.STS_REQUEST_WORKER) {
      role = process.env.STS_REQUEST_WORKER_POOL === 'surfaces'
        ? 'a surface worker (the console and portal pool)'
        : 'a request worker';
    }
    log.debug("Leaving DeadLetterReport.processRole(). " + role);
    return role;
  }

  private settingOf(key: string): any {
    const { log, config } = this.deps;
    log.debug("Entering DeadLetterReport.settingOf(). " + key);
    let value = null;
    try {
      value = config.value(key);
    } catch (e) {
      // A setting this build does not have is reported as absent rather than
      // failing the page: every other number on it is still true.
      log.debug("Caught in DeadLetterReport.settingOf(): " +
                ((e && e.message) || e));
    }
    log.debug("Leaving DeadLetterReport.settingOf().");
    return value;
  }

  // -------------------------------------------------------------------------
  // THE REPORT. Everything is counted over ONE scan of the realm's letters
  // and ONE list of its streams, so no two numbers in a reply were read at
  // different moments.
  //
  // `letters` is every held letter, newest first, without its token; the
  // caller filters and pages it (`admin-core/admin_views.ts`).
  // `options.nowMs` is for tests.
  // -------------------------------------------------------------------------
  report(options?: { nowMs?: number } | null): any {
    const { log, realms, streams, events, errorCodes, transport } = this.deps;
    log.debug("Entering DeadLetterReport.report(). " + realms.currentId());
    const opts = options || {};
    const now = Number(opts.nowMs) || Date.now();
    const windowS = Number(this.settingOf('ssf.deadLetterRetentionS')) ||
      3600;
    const timeoutMs = streams.deadTimeoutMs();
    const records = streams.listStreams();
    const byStream = new Map();
    records.forEach(function (record) {
      byStream.set(record.stream_id, record);
    });

    const held = streams.allDeadLetters();
    held.sort(function (a, b) {
      const left = Number(a.deadAtMs) || 0;
      const right = Number(b.deadAtMs) || 0;
      if (left !== right) {
        return right - left;
      }
      return String(a.jti).localeCompare(String(b.jti));
    });

    const causeCounts = new Map();
    const codeCounts = new Map();
    const statusCounts = new Map();
    const typeCounts = new Map();
    const typeNames = new Map();
    const perStream = new Map();
    let signed = 0;

    const letters = held.map((letter) => {
      const cause = this.causeOf(letter);
      this.bump(causeCounts, cause);
      this.bump(codeCounts, letter.errorCode || '');
      this.bump(statusCounts, Number(letter.status) || 0);
      if (letter.signed) {
        signed += 1;
      }
      const summary = letter.claims ? events.describeSet(letter.claims)
                                    : null;
      const type = summary && summary.types.length ? summary.types[0] : '';
      this.bump(typeCounts, type);
      if (!typeNames.has(type)) {
        typeNames.set(type, summary ? summary.name : '(unreadable)');
      }
      const at = Number(letter.deadAtMs) || 0;
      const mine = perStream.get(letter.stream_id) ||
        { held: 0, oldestMs: 0, newestMs: 0, causes: this.emptyCounts() };
      mine.held += 1;
      mine.causes[cause] += 1;
      mine.oldestMs = mine.oldestMs ? Math.min(mine.oldestMs, at) : at;
      mine.newestMs = Math.max(mine.newestMs, at);
      perStream.set(letter.stream_id, mine);
      return {
        stream_id: letter.stream_id,
        jti: letter.jti,
        queuedAt: letter.queuedAt || '',
        deadAt: letter.deadAt || this.isoOrEmpty(at),
        ageS: at ? Math.max(0, Math.round((now - at) / 1000)) : null,
        cause: cause,
        reason: letter.reason || '',
        errorCode: letter.errorCode || '',
        status: Number(letter.status) || 0,
        signed: !!letter.signed,
        streamKnown: byStream.has(letter.stream_id),
        event: summary
          ? { name: summary.name, types: summary.types,
              subject: summary.subject }
          : null
      };
    });

    const states = { dead: 0, 'half-open': 0, failing: 0 };
    const streamRows = [];
    records.forEach((record) => {
      const state = this.deliveryStateOf(record, now, timeoutMs);
      const mine = perStream.get(record.stream_id);
      if (states[state] !== undefined) {
        states[state] += 1;
      }
      if (!mine && (state === 'healthy' || state === 'poll')) {
        return;
      }
      streamRows.push({
        stream_id: record.stream_id,
        aud: record.aud,
        endpoint_url: (record.delivery && record.delivery.endpoint_url) ||
          '',
        status: record.status,
        state: state,
        held: mine ? mine.held : 0,
        causes: mine ? mine.causes : this.emptyCounts(),
        oldestAt: mine ? this.isoOrEmpty(mine.oldestMs) : '',
        newestAt: mine ? this.isoOrEmpty(mine.newestMs) : '',
        deadLetteredEver: Number(record.counters &&
                                 record.counters.deadLettered) || 0,
        deadSince: this.isoOrEmpty(record.deadSinceMs),
        failingSince: this.isoOrEmpty(record.failingSinceMs),
        nextProbeAt: this.isoOrEmpty(record.nextProbeAtMs),
        deadReason: record.deadReason || '',
        lastPushError: record.lastPushError || '',
        lastPushAt: record.lastPushAt || ''
      });
    });
    // Letters whose stream this process does not hold — deleted, or
    // replicated ahead of its stream. The sweep removes the first kind; both
    // are counted here so the per-stream rows add up to the total.
    perStream.forEach((mine, streamId) => {
      if (byStream.has(streamId)) {
        return;
      }
      streamRows.push({ stream_id: streamId, aud: '', endpoint_url: '',
        status: '', state: 'unknown', held: mine.held, causes: mine.causes,
        oldestAt: this.isoOrEmpty(mine.oldestMs),
        newestAt: this.isoOrEmpty(mine.newestMs),
        deadLetteredEver: 0, deadSince: '', failingSince: '', nextProbeAt: '',
        deadReason: '', lastPushError: '', lastPushAt: '' });
    });
    const order = { dead: 0, 'half-open': 1, failing: 2, unknown: 3,
      healthy: 4, poll: 5 };
    streamRows.sort(function (a, b) {
      if (order[a.state] !== order[b.state]) {
        return order[a.state] - order[b.state];
      }
      if (b.held !== a.held) {
        return b.held - a.held;
      }
      return String(a.stream_id).localeCompare(String(b.stream_id));
    });

    const oldestMs = held.length
      ? Number(held[held.length - 1].deadAtMs) || 0 : 0;
    const newestMs = held.length ? Number(held[0].deadAtMs) || 0 : 0;
    const notes = sweepNotes();

    const out = {
      realm: realms.currentId(),
      generatedAt: new Date(now).toISOString(),
      enabled: !!this.settingOf('ssf.enabled'),
      pushDelivery: !!this.settingOf('ssf.pushDelivery'),
      causes: CAUSES.map(function (cause) {
        return { id: cause.id, label: cause.label, code: cause.code || '',
                 what: cause.what, count: causeCounts.get(cause.id) || 0 };
      }),
      totals: {
        held: held.length,
        streamsHolding: perStream.size,
        signed: signed,
        unsigned: held.length - signed,
        deadStreams: states.dead,
        halfOpenStreams: states['half-open'],
        failingStreams: states.failing,
        pushStreams: records.filter(function (record) {
          return record.delivery &&
                 record.delivery.method === streams.DELIVERY_PUSH;
        }).length,
        oldestAt: this.isoOrEmpty(oldestMs),
        newestAt: this.isoOrEmpty(newestMs),
        oldestAgeS: oldestMs ? Math.round((now - oldestMs) / 1000) : null,
        newestAgeS: newestMs ? Math.round((now - newestMs) / 1000) : null,
        deadLetteredEver: records.reduce(function (n, record) {
          return n + (Number(record.counters &&
                             record.counters.deadLettered) || 0);
        }, 0)
      },
      timeline: this.timelineOf(held, now, windowS),
      byCode: this.countedRows(codeCounts, 'errorCode').map(function (row) {
        const known = row.errorCode ? errorCodes.describe(row.errorCode)
                                    : null;
        return { errorCode: row.errorCode, count: row.count,
                 cause: CAUSE_BY_CODE[row.errorCode] || 'push-failed',
                 summary: known ? known.summary : '' };
      }),
      byStatus: this.countedRows(statusCounts, 'status'),
      byEventType: this.countedRows(typeCounts, 'type').map(function (row) {
        return { type: row.type, name: typeNames.get(row.type) || '',
                 count: row.count };
      }),
      streams: streamRows,
      letters: letters,
      settings: {
        retentionS: this.settingOf('ssf.deadLetterRetentionS'),
        maxPerStream: this.settingOf('ssf.deadLetterMaxPerStream'),
        deadStreamTimeoutS: this.settingOf('ssf.deadStreamTimeoutS'),
        sweepS: this.settingOf('ssf.deadLetterSweepS'),
        pushConcurrency: this.settingOf('ssf.pushConcurrency'),
        pushBacklog: this.settingOf('ssf.pushBacklog'),
        pushRetries: this.settingOf('ssf.pushRetries')
      },
      process: {
        pid: process.pid,
        role: this.processRole(),
        pushes: transport.pushGateState(),
        sweeps: notes.recent.slice(),
        sinceStart: Object.assign({ firstSweepAt: notes.firstAt },
                                  notes.since)
      }
    };
    log.debug("Leaving DeadLetterReport.report(). " + held.length +
              ' letter(s), ' + streamRows.length + ' stream row(s).');
    return out;
  }

  // What the composition root passes (#50, R2): the real modules, as the
  // module built its own instance from before.
  static defaultDeps(): DeadLetterReportDeps {
    helpers.log.debug("Entering DeadLetterReport.defaultDeps().");
    helpers.log.debug("Leaving DeadLetterReport.defaultDeps().");
    return {
      log: helpers.log,
      config: config,
      errorCodes: errorCodes,
      realms: realms,
      events: events,
      streams: streams,
      transport: transport
    };
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds
// no instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` (see `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<DeadLetterReport>(
  'ssf/ssf_dead_letter_report',
  () => new DeadLetterReport(DeadLetterReport.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  DeadLetterReport: DeadLetterReport,
  installInstance: (instance: DeadLetterReport): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  CAUSES: DeadLetterReport.CAUSES,
  causeOf: slot.forward('causeOf'),
  bucketSecondsFor: slot.forward('bucketSecondsFor'),
  deliveryStateOf: slot.forward('deliveryStateOf'),
  noteSweep: slot.forward('noteSweep'),
  report: slot.forward('report')
};
