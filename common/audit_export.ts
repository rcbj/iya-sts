// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: audit_export.ts
//
// ===========================================================================
// AUDIT EXPORT (#641).
//
// One process delivers its OWN audit rows to the destinations an
// administrator configured for the realm. The ring in `common/audit.js` is
// the record. Copying each row into a second outbox at record time would
// double the cluster's write of a log that is already the expensive one
// (#46), so the job keeps a cursor over `audit.localEvents()` instead.
//
// THE CURSOR IS PER PROCESS (`merge: 'own'`). A leader delivering every
// process's rows would need `merged()` and would double-deliver or miss.
// A per-process job is also what "no single centralized logging process"
// asks for, and a file destination writes on the node that recorded the
// row. Sequence numbers are leased in blocks and are NOT contiguous in one
// process, so a gap is a bookmark (`nextSeq`, the first undelivered row's
// seq) that is gone on the next tick, not arithmetic on `seq`.
//
// AT LEAST ONCE. The cursor is written once, at the end of the tick, after
// the sends. A crash between the send and that write sends the row again.
// The event id is `(origin || 'local') + ':' + seq`, which is what a
// receiver deduplicates on. This is not exactly-once.
//
// A destination that has been failing for `auditExport.retryMaxPeriodMs`
// still attempts ONE event each run, so it can recover. The event that
// attempt fails, and up to one batch behind it, are counted permanently
// failed in a single row. Before that period, a failure holds the cursor
// and backs off. HTTP 400 advances that one event and does not start an
// episode. A redirect is not followed.
//
// Syslog (and LogRhythm, which is the same adapter) speaks RFC 5424. The
// default transport is TCP: an audit log does not default to
// fire-and-forget UDP, which remains available. The structured-data id
// `iyaAudit` is a local name, not an IANA-registered SD-ID and not a
// private-enterprise number. UDP is transmitted when `dgram.send` accepts
// it. TCP and TLS use RFC 6587 octet counting, one socket for the tick.
//
// A filesystem destination appends one JSON line with one `write` on an
// `O_APPEND` handle. Two processes appending to the same path can
// interleave a line longer than PIPE_BUF (4096). The path is absolute,
// has no `..`, and stays under `auditExport.fileRoots` when that is set.
//
// Webhook and Splunk HEC are the twenty-first outbound URL an operator
// configures (`federation/CLAUDE.md`). Plain http is development-only.
// Cloud metadata addresses are refused even when private addresses are
// allowed. DNS is resolved and checked before the connect; a later answer
// can still change, and the code says so rather than claiming otherwise.
// Secrets are sealed when the keystore persists, and no view, log line or
// audit row carries one.
//
// A LIBRARY (rule 3da). It registers no route. The job is registered when
// the instance is wired. The console's API is `mgmt-api/audit_export_api.ts`.
// ===========================================================================

import bunyan = require('bunyan');
import dgram = require('dgram');
import dns = require('dns');
import fs = require('fs');
import http = require('http');
import https = require('https');
import net = require('net');
import os = require('os');
import path = require('path');
// Every random value is crypto.js's (`tests/crypto_centralised.js`).
import stsCrypto = require('./crypto');
// The audit row as the model says it means (#1579): `canonical()` reads it
// through the `AuditEvent` concept.
import DomainClasses = require('./domain_classes');
import tls = require('tls');
import audit = require('./audit');
import config = require('./config');
import errorCodes = require('./error_codes');
import InstanceSlot = require('./instance_slot');
import keystore = require('./keystore');
import mode = require('./mode');
import OutboundTls = require('./outbound_tls');
import realms = require('./realms');
import version = require('./version');

const log = bunyan.createLogger({ name: 'sts-audit-export' });
config.registerLogger(log);

type Json = any;

// What one attempt decided. `ack-wait` accepted the event and is waiting
// for Splunk to acknowledge it; the cursor stays on that event.
interface SendResult {
  ok: boolean;
  kind: 'ok' | 'ack-wait' | 'transient' | 'pause' | 'permanent';
  disposition: string;
  code: string;
  why: string;
  retryAfterMs: number;
  ackId: number | string | null;
}

interface Cursor {
  seq: number;
  origin: string;
  primed: boolean;
  pausedUntil: number;
  retryMs: number;
  failingSince: number;
  lastSuccessAt: number;
  lastFailureAt: number;
  lastFailure: string;
  lastDisposition: string;
  delivered: number;
  failedPermanent: number;
  droppedGap: number;
  retries: number;
  latencyMs: number;
  samples: number;
  ackId: number | string | null;
  ackChannel: string;
  inFlightId: string;
  inFlightSeq: number;
  nextSeq: number | null;
}

const JOB_ID = 'audit.export';
const ID_RE = /^[a-z0-9][a-z0-9-]{0,62}$/;
const TYPES = ['syslog', 'file', 'webhook', 'splunk', 'logrhythm'];
const SECRET_LABEL = 'audit-export-secret';
const BODY_CAP = 65536;
const NIL = '-';

// The family's three outbound settings. `STS-AUDIT-0012` is what product
// mode logs when skip-TLS is on and ignored. Plain http uses 0005.
const FAMILY = {
  what: 'an audit export',
  allowHttpKey: 'auditExport.allowHttp',
  skipTlsKey: 'auditExport.skipTlsVerification',
  caFileKey: 'auditExport.caFile',
  loopbackHttpInProduct: false,
  httpRefusedCode: 'STS-AUDIT-0005',
  skipIgnoredCode: 'STS-AUDIT-0012'
};

// Names removed from every exported event even when the setting is cleared.
const ALWAYS_REDACT = ['password', 'secret', 'token', 'authorization',
  'client_secret', 'assertion', 'access_token', 'refresh_token', 'id_token'];

const VERBS: Json = {
  'admin.audit-export.add': 'added',
  'admin.audit-export.update': 'updated',
  'admin.audit-export.remove': 'removed',
  'admin.audit-export.enable': 'enabled',
  'admin.audit-export.disable': 'disabled',
  'admin.audit-export.test': 'tested'
};

/**
 * Delivers one process's audit rows to the realm's destinations.
 *
 * The composition root builds one instance. The facades forward to it.
 */
class AuditExport {
  // The realms already warned about having no destination.
  private readonly warnedNoDestination = new Set<string>();

  // Open file handles, keyed by realm and destination. A socket is not a
  // row, so it lives on the process (`CLAUDE.md`, *One front process*).
  private readonly files = new Map<string, Json>();

  /**
   * @param deps - log, stores, and the clients a test can replace
   */
  constructor(private readonly deps: Json) {
    deps.log.debug("Entering AuditExport.constructor().");
    deps.log.debug("Leaving AuditExport.constructor().");
  }

  /**
   * The dependencies the composition root builds the instance with.
   *
   * The two maps are declared here, once. A second declaration of the same
   * persist name is not persisted.
   *
   * @returns the dependency object
   */
  static defaultDeps(): Json {
    log.debug("Entering AuditExport.defaultDeps().");
    const deps = {
      log: log,
      config: config,
      mode: mode,
      realms: realms,
      audit: audit,
      errorCodes: errorCodes,
      keystore: keystore,
      outbound: OutboundTls,
      version: version,
      scheduler: function (): Json {
        return require('../cluster/scheduler');
      },
      destinations: realms.map({
        persist: 'audit.export.destinations'
      }),
      cursors: realms.map({
        persist: 'audit.export.cursors', merge: 'own'
      }),
      fs: fs.promises,
      http: http,
      https: https,
      dgram: dgram,
      dns: dns.promises,
      net: net,
      tls: tls,
      path: path,
      os: os,
      crypto: stsCrypto
    };
    log.debug("Leaving AuditExport.defaultDeps().");
    return deps;
  }

  /**
   * Registers `audit.export` with the scheduler.
   *
   * A per-process realm job. Quiet, because a row per run per process
   * would be a write every few seconds. `requestRun` still refuses a
   * per-process job; `manual` is set so the registration matches the
   * other quiet jobs.
   *
   * @returns true when it was registered
   */
  registerJobs(): boolean {
    const { log: logger, scheduler } = this.deps;
    logger.debug("Entering AuditExport.registerJobs().");
    const s = scheduler();
    if (!s || typeof s.register !== 'function' || s.job(JOB_ID)) {
      logger.debug("Leaving AuditExport.registerJobs(). Nothing to do.");
      return false;
    }
    const self = this;
    s.register({
      id: JOB_ID,
      title: 'Audit export',
      describe: 'In every process, for each realm: delivers this ' +
        'process\'s own new audit events to that realm\'s enabled ' +
        'destinations. One destination\'s failure does not hold the ' +
        'others. Delivery is at least once.',
      owner: 'common/audit_export.ts',
      kind: 'per-process',
      scope: 'realm',
      quiet: true,
      everySetting: 'auditExport.intervalS',
      everySettingUnit: 's',
      manual: true,
      timeoutS: 120,
      off: function (realmId: string): string {
        return self.offIn(realmId);
      },
      run: function (ctx: Json): Promise<Json> {
        return self.runAsync(ctx);
      }
    });
    logger.debug("Leaving AuditExport.registerJobs().");
    return true;
  }

  /**
   * Why the job is off in a realm, or '' when it should run.
   *
   * Called outside the realm. An interval of 0 is the scheduler's own
   * off reason and is not repeated here.
   *
   * @param realmId - the realm the tick is considering
   * @returns the sentence, or ''
   */
  offIn(realmId: string): string {
    const { log: logger, realms: realmBook } = this.deps;
    logger.debug("Entering AuditExport.offIn(). " + realmId);
    const self = this;
    const realm = realmBook.get(realmId) ||
      realmBook.get(realmBook.DEFAULT_ID);
    const why = realmBook.run(realm, function (): string {
      return self.offHere();
    });
    // A COPY OF THE LOG LEAVES THIS SERVICE ONLY IF SOMEBODY SAYS WHERE TO (ASVS
    // 5.0.0 16.4.3). Said once per realm per process, as the state it is.
    if (why && !self.warnedNoDestination.has(realmId) &&
        require('./mode').warnsWithoutAuditDestination()) {
      self.warnedNoDestination.add(realmId);
      logger.warn(require('./error_codes').tag('STS-AUDIT-0017') + 'audit ' +
        'export: realm "' + realmId + '" sends its audit log nowhere (' + why +
        ') A compromise of this service could alter it. Add a destination ' +
        'under Audit export.');
    }
    logger.debug("Leaving AuditExport.offIn(). " + (why || 'on'));
    return why;
  }

  /**
   * The off reason in the ambient realm.
   *
   * @returns the sentence, or ''
   */
  offHere(): string {
    const { log: logger, config: cfg } = this.deps;
    logger.debug("Entering AuditExport.offHere().");
    if (!cfg.value('auditExport.enabled')) {
      logger.debug("Leaving AuditExport.offHere(). Off.");
      return 'Audit export is off.';
    }
    let enabled = false;
    this.deps.destinations.forEach(function (dest: Json): void {
      if (dest && dest.enabled) {
        enabled = true;
      }
    });
    if (!enabled) {
      logger.debug("Leaving AuditExport.offHere(). No destination.");
      return 'No audit export destination is enabled.';
    }
    logger.debug("Leaving AuditExport.offHere(). On.");
    return '';
  }

  /**
   * Runs one tick for the ambient realm.
   *
   * Destinations run together. One destination is walked in order, so a
   * slow one cannot reorder its own events or hold another destination.
   *
   * @param ctx - the scheduler's run context
   * @returns a small summary
   */
  async runAsync(ctx: Json): Promise<Json> {
    const { log: logger } = this.deps;
    logger.debug("Entering AuditExport.runAsync().");
    const ids: string[] = [];
    this.deps.destinations.forEach(function (dest: Json, id: string): void {
      if (dest && dest.enabled) {
        ids.push(String(id));
      }
    });
    const self = this;
    await Promise.all(ids.map(function (id: string): Promise<void> {
      return self.deliverDestination(id, ctx);
    }));
    logger.debug("Leaving AuditExport.runAsync(). " + ids.length);
    return { destinations: ids.length };
  }

  /**
   * Delivers one destination. A throw becomes a held cursor, not a
   * failed job: the audited operation already finished.
   *
   * @param id - the destination id
   * @param ctx - the run context
   */
  async deliverDestination(id: string, ctx: Json): Promise<void> {
    const { log: logger } = this.deps;
    logger.debug("Entering AuditExport.deliverDestination(). " + id);
    try {
      await this.walkDestination(id, ctx);
    } catch (e) {
      // The tick must not fail the job. The cursor stays where the last
      // successful save put it, which resends at least the unsent row.
      logger.debug("Caught in AuditExport.deliverDestination(): " +
        ((e && e.message) || e));
    }
    logger.debug("Leaving AuditExport.deliverDestination().");
  }

  /**
   * Walks one destination's cursor across this process's ring.
   *
   * @param id - the destination id
   * @param ctx - the run context
   */
  async walkDestination(id: string, ctx: Json): Promise<void> {
    const { log: logger, audit: auditLog, config: cfg } = this.deps;
    logger.debug("Entering AuditExport.walkDestination(). " + id);
    const dest = this.readDest(id);
    if (!dest || !dest.enabled) {
      logger.debug("Leaving AuditExport.walkDestination(). Disabled.");
      return;
    }
    const cursor = this.readCursor(id);
    const rows = this.localRows();
    const pipe: Json = { socket: null };
    const now = Date.now();
    try {
      if (cursor.ackId != null && cursor.ackId !== '') {
        const polled = await this.pollAck(dest, cursor);
        if (polled.kind === 'pending') {
          cursor.nextSeq = cursor.inFlightSeq || cursor.nextSeq;
          this.putCursor(id, cursor);
          logger.debug("Leaving AuditExport.walkDestination(). Ack " +
            "pending.");
          return;
        }
        if (polled.kind === 'failed') {
          this.hold(cursor, id, polled.code, polled.why, polled.retryAfterMs);
          cursor.nextSeq = cursor.inFlightSeq || null;
          this.putCursor(id, cursor);
          logger.debug("Leaving AuditExport.walkDestination(). Ack poll " +
            "failed.");
          return;
        }
        if (polled.kind === 'acked') {
          cursor.seq = cursor.inFlightSeq || cursor.seq;
          cursor.delivered += 1;
          cursor.lastDisposition = 'acknowledged';
          cursor.lastSuccessAt = now;
          cursor.ackId = null;
          cursor.inFlightId = '';
          cursor.inFlightSeq = 0;
          this.recover(cursor, id);
        } else {
          // The collector no longer knows the id. Send the event again.
          cursor.ackId = null;
          cursor.inFlightId = '';
        }
      }
      if (!cursor.primed) {
        const oldest = rows.length ? rows[0] : null;
        cursor.seq = oldest ? Number(oldest.seq) - 1 : 0;
        cursor.primed = true;
        cursor.origin = this.originId();
      } else if (cursor.nextSeq != null &&
                 !this.hasSeq(rows, cursor.nextSeq) &&
                 cursor.seq < Number(cursor.nextSeq)) {
        cursor.droppedGap += 1;
        const oldest = rows.length ? rows[0] : null;
        this.noteDelivery('STS-AUDIT-0009',
          'Audit events were trimmed before destination ' + id +
          ' delivered them.',
          { destinationId: id, bookmark: cursor.nextSeq });
        cursor.seq = oldest ? Number(oldest.seq) - 1 : cursor.seq;
      }
      if (cursor.pausedUntil > now) {
        this.noteBookmark(cursor, rows);
        this.putCursor(id, cursor);
        logger.debug("Leaving AuditExport.walkDestination(). Paused.");
        return;
      }
      const batch = Number(cfg.value('auditExport.batch'));
      const budget = Number(cfg.value('auditExport.budgetMs'));
      const maxPeriod = Number(cfg.value('auditExport.retryMaxPeriodMs'));
      const started = Date.now();
      const dropped: string[] = [];
      let offered = 0;
      // The first event of an expired episode is still sent, so a
      // destination that has recovered is noticed. Only a failed probe
      // of that episode, and the rows blocked behind it, are given up.
      // A permanent rejection (HTTP 400) advances that one event and
      // does not start the silent drop.
      let givingUp = false;
      const owner = ctx && ctx.stillOwner ? ctx.stillOwner : function () {
        return true;
      };
      for (let i = 0; i < rows.length; i++) {
        const row = rows[i];
        if (Number(row.seq) <= cursor.seq) {
          continue;
        }
        if (!owner()) {
          break;
        }
        if (offered >= batch || Date.now() - started >= budget) {
          break;
        }
        if (AuditExport.skipped(row)) {
          cursor.seq = Number(row.seq);
          continue;
        }
        const expired = cursor.failingSince > 0 &&
          now - cursor.failingSince >= maxPeriod;
        if (expired && givingUp && dropped.length < batch) {
          dropped.push(this.eventId(row));
          cursor.failedPermanent += 1;
          cursor.seq = Number(row.seq);
          cursor.lastDisposition = 'failed';
          offered += 1;
          continue;
        }
        const event = this.buildEvent(row, dest);
        const began = Date.now();
        const result = await this.offerEvent(dest, event, pipe);
        if (result.kind === 'ack-wait') {
          cursor.ackId = result.ackId;
          cursor.ackChannel = cursor.ackChannel ||
            this.deps.crypto.randomUuid();
          cursor.inFlightId = event.id;
          cursor.inFlightSeq = Number(row.seq);
          cursor.lastDisposition = 'accepted';
          cursor.nextSeq = Number(row.seq);
          break;
        }
        if (result.ok) {
          cursor.seq = Number(row.seq);
          cursor.delivered += 1;
          cursor.lastSuccessAt = Date.now();
          cursor.lastDisposition = result.disposition || 'accepted';
          this.noteLatency(cursor, Date.now() - began);
          this.recover(cursor, id);
          offered += 1;
          continue;
        }
        if (result.kind === 'permanent') {
          cursor.seq = Number(row.seq);
          cursor.failedPermanent += 1;
          cursor.lastDisposition = 'failed';
          this.noteDelivery(result.code || 'STS-AUDIT-0015',
            'Destination ' + id + ' rejected event ' + event.id + '.',
            { destinationId: id, eventId: event.id });
          offered += 1;
          continue;
        }
        if (expired) {
          givingUp = true;
          dropped.push(event.id);
          cursor.failedPermanent += 1;
          cursor.seq = Number(row.seq);
          cursor.lastDisposition = 'failed';
          cursor.lastFailure = AuditExport.safeWhy(result.why);
          cursor.lastFailureAt = Date.now();
          cursor.retries += 1;
          offered += 1;
          continue;
        }
        this.hold(cursor, id, result.code, result.why, result.retryAfterMs);
        break;
      }
      if (dropped.length) {
        this.noteDelivery('STS-AUDIT-0011',
          'Destination ' + id + ' dropped ' + dropped.length +
          ' event(s) after auditExport.retryMaxPeriodMs.',
          { destinationId: id, count: dropped.length,
            firstId: dropped[0], lastId: dropped[dropped.length - 1] });
        cursor.pausedUntil = Date.now() +
          Number(cfg.value('auditExport.retryInitialMs'));
      }
      this.noteBookmark(cursor, rows);
      this.putCursor(id, cursor);
    } finally {
      this.closePipe(pipe);
    }
    logger.debug("Leaving AuditExport.walkDestination().");
  }

  /**
   * Records the first undelivered seq, which the next tick uses as the
   * trim bookmark. An acknowledgement in flight names that event.
   *
   * @param cursor - the cursor being saved
   * @param rows - this process's ring, oldest first
   */
  noteBookmark(cursor: Cursor, rows: Json[]): void {
    const { log: logger } = this.deps;
    logger.debug("Entering AuditExport.noteBookmark().");
    if (cursor.ackId != null && cursor.ackId !== '') {
      cursor.nextSeq = cursor.inFlightSeq || cursor.nextSeq;
      logger.debug("Leaving AuditExport.noteBookmark(). In flight.");
      return;
    }
    let next: number | null = null;
    for (let i = 0; i < rows.length; i++) {
      if (Number(rows[i].seq) > cursor.seq &&
          !AuditExport.skipped(rows[i])) {
        next = Number(rows[i].seq);
        break;
      }
    }
    cursor.nextSeq = next;
    logger.debug("Leaving AuditExport.noteBookmark().");
  }

  /**
   * Tells whether the ring still holds `seq`.
   *
   * @param rows - the ring
   * @param seq - the bookmark
   * @returns true when a row has that seq
   */
  hasSeq(rows: Json[], seq: number): boolean {
    const { log: logger } = this.deps;
    logger.debug("Entering AuditExport.hasSeq().");
    for (let i = 0; i < rows.length; i++) {
      if (Number(rows[i].seq) === Number(seq)) {
        logger.debug("Leaving AuditExport.hasSeq(). Yes.");
        return true;
      }
    }
    logger.debug("Leaving AuditExport.hasSeq(). No.");
    return false;
  }

  /**
   * Starts or continues a failure episode without advancing the cursor.
   *
   * The first failure of an episode is the one audit row. Later failures
   * wait longer, up to the maximum retry delay.
   *
   * @param cursor - the destination's cursor
   * @param id - the destination id
   * @param code - the error code
   * @param why - a sentence with no secret
   * @param retryAfterMs - a peer's Retry-After, or 0
   */
  hold(cursor: Cursor, id: string, code: string, why: string,
       retryAfterMs: number): void {
    const { log: logger, config: cfg } = this.deps;
    logger.debug("Entering AuditExport.hold(). " + id);
    const initial = Number(cfg.value('auditExport.retryInitialMs'));
    const max = Number(cfg.value('auditExport.retryMaxMs'));
    if (!cursor.failingSince) {
      cursor.failingSince = Date.now();
      this.noteDelivery(code || 'STS-AUDIT-0007',
        'Audit export destination ' + id + ' is failing.',
        { destinationId: id });
    }
    cursor.retries += 1;
    const wait = retryAfterMs > 0 ? retryAfterMs
      : (cursor.retryMs || initial);
    cursor.pausedUntil = Date.now() + wait;
    const grown = (cursor.retryMs || initial) * 2;
    cursor.retryMs = grown > max ? max : grown;
    cursor.lastFailureAt = Date.now();
    cursor.lastFailure = AuditExport.safeWhy(why);
    cursor.lastDisposition = 'failed';
    logger.debug("Leaving AuditExport.hold().");
  }

  /**
   * Ends a failure episode the first time a send succeeds.
   *
   * @param cursor - the destination's cursor
   * @param id - the destination id
   */
  recover(cursor: Cursor, id: string): void {
    const { log: logger, audit: auditLog, config: cfg } = this.deps;
    logger.debug("Entering AuditExport.recover(). " + id);
    if (cursor.failingSince) {
      auditLog.audit({
        action: 'service.failure',
        outcome: 'success',
        summarised: true,
        target: id,
        summary: 'Audit export destination ' + id + ' is delivering again.',
        detail: { exportSkip: true }
      });
    }
    cursor.failingSince = 0;
    cursor.retryMs = Number(cfg.value('auditExport.retryInitialMs'));
    cursor.pausedUntil = 0;
    cursor.lastFailure = '';
    logger.debug("Leaving AuditExport.recover().");
  }

  /**
   * Writes one delivery-failure audit row.
   *
   * Every delivery code is named here, beside the outcome, so a new one
   * cannot be recorded without a code. The row carries `exportSkip` and
   * is not itself exported.
   *
   * @param code - the error code
   * @param summary - the sentence
   * @param detail - extra detail; `exportSkip` is added
   */
  noteDelivery(code: string, summary: string, detail: Json): void {
    const { log: logger, audit: auditLog } = this.deps;
    logger.debug("Entering AuditExport.noteDelivery().");
    const known = code === 'STS-AUDIT-0004' ||
      code === 'STS-AUDIT-0005' || code === 'STS-AUDIT-0006' ||
      code === 'STS-AUDIT-0007' || code === 'STS-AUDIT-0008' ||
      code === 'STS-AUDIT-0009' || code === 'STS-AUDIT-0011' ||
      code === 'STS-AUDIT-0014' || code === 'STS-AUDIT-0015' ||
      code === 'STS-CORE-0104';
    auditLog.failure(known ? code : 'STS-AUDIT-0007', {
      action: 'service.failure',
      outcome: 'error',
      summarised: true,
      summary: summary,
      target: detail && detail.destinationId,
      detail: Object.assign({ exportSkip: true }, detail || {})
    });
    logger.debug("Leaving AuditExport.noteDelivery().");
  }

  /**
   * Folds one sample into the destination's mean latency.
   *
   * @param cursor - the cursor
   * @param ms - the sample
   */
  noteLatency(cursor: Cursor, ms: number): void {
    const { log: logger } = this.deps;
    logger.debug("Entering AuditExport.noteLatency().");
    const n = cursor.samples || 0;
    cursor.latencyMs = n === 0 ? ms
      : Math.round(((cursor.latencyMs * n) + ms) / (n + 1));
    cursor.samples = n + 1;
    logger.debug("Leaving AuditExport.noteLatency().");
  }

  /**
   * Sends one event to one destination.
   *
   * @param dest - the destination
   * @param event - the canonical event
   * @param pipe - the tick's syslog socket, if any
   * @returns what the destination did
   */
  async offerEvent(dest: Json, event: Json, pipe: Json): Promise<SendResult> {
    const { log: logger } = this.deps;
    logger.debug("Entering AuditExport.offerEvent(). " + dest.id);
    let result: SendResult;
    try {
      if (dest.type === 'file') {
        result = await this.sendFile(dest, event);
      } else if (dest.type === 'syslog' || dest.type === 'logrhythm') {
        result = await this.sendSyslog(dest, event, pipe);
      } else if (dest.type === 'webhook' || dest.type === 'splunk') {
        result = await this.sendHttp(dest, event);
      } else {
        result = this.failed('pause', 'STS-AUDIT-0001',
          'The destination type is not usable.');
      }
    } catch (e) {
      logger.debug("Caught in AuditExport.offerEvent(): " +
        ((e && e.message) || e));
      const code = dest.type === 'file' ? 'STS-AUDIT-0008'
        : (dest.type === 'syslog' || dest.type === 'logrhythm'
          ? 'STS-AUDIT-0006' : 'STS-AUDIT-0007');
      result = this.failed('transient', code,
        (e && e.message) || 'the send failed');
    }
    logger.debug("Leaving AuditExport.offerEvent(). " + result.kind);
    return result;
  }

  /**
   * Builds a SendResult for a refusal or a failure.
   *
   * @param kind - transient, pause or permanent
   * @param code - the error code
   * @param why - the sentence
   * @returns the result
   */
  failed(kind: 'transient' | 'pause' | 'permanent', code: string,
         why: string): SendResult {
    const { log: logger } = this.deps;
    logger.debug("Entering AuditExport.failed().");
    logger.debug("Leaving AuditExport.failed().");
    return {
      ok: false, kind: kind, disposition: 'failed', code: code,
      why: why, retryAfterMs: 0, ackId: null
    };
  }

  /**
   * Appends one JSON line. Success is acceptance: the file is this
   * process's.
   *
   * @param dest - the file destination
   * @param event - the canonical event
   * @returns the result
   */
  async sendFile(dest: Json, event: Json): Promise<SendResult> {
    const { log: logger, fs: files } = this.deps;
    logger.debug("Entering AuditExport.sendFile(). " + dest.id);
    const checked = this.checkPath(dest.path);
    if (!checked.ok) {
      logger.debug("Leaving AuditExport.sendFile(). Path refused.");
      return this.failed('pause', 'STS-AUDIT-0004', checked.why);
    }
    const key = this.fileKey(dest.id);
    let held = this.files.get(key);
    if (held && held.path !== checked.path) {
      await this.closeHeld(held);
      this.files.delete(key);
      held = null;
    }
    const modeBits = AuditExport.parseMode(dest.mode);
    if (!held) {
      const fh = await files.open(checked.path, 'a', modeBits);
      held = { path: checked.path, fh: fh };
      this.files.set(key, held);
    }
    const rotate = Number(dest.rotateBytes) || 0;
    if (rotate > 0) {
      const st = await held.fh.stat();
      if (st.size >= rotate) {
        await held.fh.close();
        const stamp = new Date().toISOString().replace(/[:.]/g, '-');
        let rotated = checked.path + '.' + stamp;
        rotated = await this.freeName(rotated);
        await files.rename(checked.path, rotated);
        held.fh = await files.open(checked.path, 'a', modeBits);
      }
    }
    const line = JSON.stringify(event) + '\n';
    await held.fh.write(Buffer.from(line, 'utf8'));
    logger.debug("Leaving AuditExport.sendFile(). Accepted.");
    return {
      ok: true, kind: 'ok', disposition: 'accepted', code: '',
      why: '', retryAfterMs: 0, ackId: null
    };
  }

  /**
   * A rotation name `stat` does not already find. The timestamp is tried
   * first, then the same name with this process's pid, because two
   * processes can rotate one path in the same millisecond.
   *
   * @param base - the path plus the timestamp
   * @returns a free name
   */
  async freeName(base: string): Promise<string> {
    const { log: logger, fs: files } = this.deps;
    logger.debug("Entering AuditExport.freeName().");
    const candidates = [base, base + '-' + process.pid];
    for (let i = 0; i < candidates.length; i++) {
      try {
        await files.stat(candidates[i]);
      } catch (e) {
        // The name is free when stat cannot see it. A permission error
        // fails the same way, and the rename then holds the destination.
        logger.debug("Caught in AuditExport.freeName(): " +
          ((e && e.message) || e));
        logger.debug("Leaving AuditExport.freeName(). Free.");
        return candidates[i];
      }
    }
    logger.debug("Leaving AuditExport.freeName(). Stamped.");
    return base + '-' + process.pid + '-' + Date.now();
  }

  /**
   * Sends one RFC 5424 message.
   *
   * @param dest - the syslog destination
   * @param event - the canonical event
   * @param pipe - the tick's socket
   * @returns the result
   */
  async sendSyslog(dest: Json, event: Json,
                   pipe: Json): Promise<SendResult> {
    const { log: logger } = this.deps;
    logger.debug("Entering AuditExport.sendSyslog(). " + dest.id);
    const screened = await this.screenHost(String(dest.host || ''), true);
    if (!screened.ok) {
      logger.debug("Leaving AuditExport.sendSyslog(). Host refused.");
      return this.failed('pause', 'STS-AUDIT-0005', screened.why);
    }
    const transport = AuditExport.transportOf(dest);
    const port = AuditExport.portOf(dest);
    const message = AuditExport.syslogLine(event, dest);
    const ip = screened.addresses[0];
    try {
      if (transport === 'udp') {
        await this.sendUdp(message, ip, port);
        logger.debug("Leaving AuditExport.sendSyslog(). Transmitted.");
        return {
          ok: true, kind: 'ok', disposition: 'transmitted', code: '',
          why: '', retryAfterMs: 0, ackId: null
        };
      }
      await this.sendFramed(dest, message, ip, port, transport, pipe);
    } catch (e) {
      logger.debug("Caught in AuditExport.sendSyslog(): " +
        ((e && e.message) || e));
      this.closePipe(pipe);
      logger.debug("Leaving AuditExport.sendSyslog(). Failed.");
      const code = (e && e.codeName) || 'STS-AUDIT-0006';
      const kind = code === 'STS-AUDIT-0006' ? 'transient' : 'pause';
      return this.failed(kind, code,
        (e && e.message) || 'the syslog send failed');
    }
    logger.debug("Leaving AuditExport.sendSyslog(). Transmitted.");
    return {
      ok: true, kind: 'ok', disposition: 'transmitted', code: '',
      why: '', retryAfterMs: 0, ackId: null
    };
  }

  /**
   * Sends one UDP datagram. The callback accepting it is transmission.
   *
   * @param message - the RFC 5424 line
   * @param ip - the resolved address
   * @param port - the port
   */
  sendUdp(message: string, ip: string, port: number): Promise<void> {
    const { log: logger, dgram: udp, config: cfg } = this.deps;
    logger.debug("Entering AuditExport.sendUdp().");
    const family = ip.indexOf(':') >= 0 ? 'udp6' : 'udp4';
    const timeout = Number(cfg.value('auditExport.timeoutMs'));
    logger.debug("Leaving AuditExport.sendUdp(). Sending.");
    return new Promise(function (resolve, reject) {
      const sock = udp.createSocket(family);
      let settled = false;
      const finish = function (err: Error | null): void {
        if (settled) {
          return;
        }
        settled = true;
        try {
          sock.close();
        } catch (e) {
          logger.debug("Caught in AuditExport.sendUdp(): " +
            ((e && e.message) || e));
        }
        if (err) {
          reject(err);
          return;
        }
        resolve();
      };
      sock.setTimeout(timeout, function (): void {
        finish(new Error('the syslog send timed out'));
      });
      sock.once('error', function (err: Error): void {
        finish(err);
      });
      sock.send(Buffer.from(message, 'utf8'), port, ip,
                function (err: Error | null): void {
        finish(err);
      });
    });
  }

  /**
   * Writes one RFC 6587 frame on the tick's socket, opening it if needed.
   *
   * TCP and TLS connect to the address that was checked, and TLS keeps
   * the configured name as the server name. The length counts the
   * message octets and the frame has no extra newline.
   *
   * @param dest - the destination
   * @param message - the RFC 5424 line
   * @param ip - the resolved address
   * @param port - the port
   * @param transport - `tcp` or `tls`
   * @param pipe - the tick's socket
   */
  async sendFramed(dest: Json, message: string, ip: string, port: number,
                   transport: string, pipe: Json): Promise<void> {
    const { log: logger, config: cfg } = this.deps;
    logger.debug("Entering AuditExport.sendFramed(). " + dest.id);
    if (!pipe.socket || pipe.socket.destroyed ||
        pipe.key !== transport + ':' + ip + ':' + port) {
      this.closePipe(pipe);
      pipe.socket = await this.openSyslog(dest, ip, port, transport);
      pipe.key = transport + ':' + ip + ':' + port;
    }
    const body = Buffer.from(message, 'utf8');
    const frame = Buffer.concat([
      Buffer.from(String(body.length) + ' ', 'ascii'), body
    ]);
    const sock = pipe.socket;
    const timeout = Number(cfg.value('auditExport.timeoutMs'));
    await new Promise(function (resolve, reject) {
      let settled = false;
      const finish = function (err: Error | null): void {
        if (settled) {
          return;
        }
        settled = true;
        sock.setTimeout(0);
        if (err) {
          reject(err);
          return;
        }
        resolve(null);
      };
      sock.setTimeout(timeout, function (): void {
        finish(new Error('the syslog write timed out'));
      });
      sock.once('error', finish);
      const flushed = sock.write(frame, function (err: Error | null): void {
        if (err) {
          finish(err);
        }
      });
      if (flushed) {
        finish(null);
        return;
      }
      sock.once('drain', function (): void {
        finish(null);
      });
    });
    logger.debug("Leaving AuditExport.sendFramed().");
  }

  /**
   * Opens one syslog TCP or TLS socket to an address already checked.
   *
   * @param dest - the destination
   * @param ip - the resolved address
   * @param port - the port
   * @param transport - `tcp` or `tls`
   * @returns the socket
   */
  openSyslog(dest: Json, ip: string, port: number,
             transport: string): Promise<Json> {
    const { log: logger, net: netMod, tls: tlsMod, config: cfg,
            outbound } = this.deps;
    logger.debug("Entering AuditExport.openSyslog().");
    const timeout = Number(cfg.value('auditExport.timeoutMs'));
    const host = AuditExport.bareHost(dest.host);
    if (transport !== 'tls') {
      logger.debug("Leaving AuditExport.openSyslog(). TCP.");
      return new Promise(function (resolve, reject) {
        const sock = netMod.connect({ host: ip, port: port });
        const fail = function (err: Error): void {
          sock.destroy();
          reject(err);
        };
        sock.setTimeout(timeout, function (): void {
          fail(new Error('the syslog connect timed out'));
        });
        sock.once('error', fail);
        sock.once('connect', function (): void {
          sock.setTimeout(0);
          resolve(sock);
        });
      });
    }
    const policy = outbound.tlsVerdict(FAMILY, host + ':' + port);
    if (!policy.ok) {
      logger.debug("Leaving AuditExport.openSyslog(). TLS refused.");
      const refused: Json = new Error(policy.why || 'TLS was refused');
      refused.codeName = policy.errorCode || 'STS-AUDIT-0006';
      return Promise.reject(refused);
    }
    logger.debug("Leaving AuditExport.openSyslog(). TLS.");
    return new Promise(function (resolve, reject) {
      const options: Json = {
        host: ip, port: port,
        servername: AuditExport.isIp(host) ? undefined : host,
        rejectUnauthorized: policy.rejectUnauthorized
      };
      if (policy.ca) {
        options.ca = policy.ca;
      }
      if (policy.checkServerIdentity) {
        options.checkServerIdentity = policy.checkServerIdentity;
      }
      const sock = tlsMod.connect(options);
      const fail = function (err: Error): void {
        sock.destroy();
        reject(err);
      };
      sock.setTimeout(timeout, function (): void {
        fail(new Error('the syslog connect timed out'));
      });
      sock.once('error', fail);
      sock.once('secureConnect', function (): void {
        sock.setTimeout(0);
        resolve(sock);
      });
    });
  }

  /**
   * Posts one event to a webhook or to Splunk HEC.
   *
   * @param dest - the destination
   * @param event - the canonical event
   * @returns the result
   */
  async sendHttp(dest: Json, event: Json): Promise<SendResult> {
    const { log: logger } = this.deps;
    logger.debug("Entering AuditExport.sendHttp(). " + dest.id);
    const target = String(dest.url || '');
    const screened = await this.screenUrl(target, true);
    if (!screened.ok) {
      logger.debug("Leaving AuditExport.sendHttp(). URL refused.");
      return this.failed('pause', screened.code || 'STS-AUDIT-0005',
        screened.why);
    }
    let body: string;
    let contentType: string;
    const headers: Json = {};
    if (dest.type === 'splunk') {
      const token = this.openBox(dest.token);
      if (!token) {
        logger.debug("Leaving AuditExport.sendHttp(). No token.");
        return this.failed('pause', 'STS-AUDIT-0007',
          'the collector token is not held');
      }
      headers.Authorization = 'Splunk ' + token;
      const payload: Json = {
        time: Number(event.at) / 1000,
        host: AuditExport.hostToken(this.deps.os),
        source: dest.source || 'iya-sts',
        sourcetype: dest.sourcetype || 'iya:audit',
        event: event
      };
      if (dest.index) {
        payload.index = dest.index;
      }
      body = JSON.stringify(payload);
      contentType = 'application/json';
    } else {
      const template = String(dest.template || '');
      if (template) {
        body = AuditExport.fillTemplate(template, event);
        contentType = dest.contentType || 'text/plain; charset=utf-8';
      } else {
        body = JSON.stringify(event);
        contentType = dest.contentType || 'application/json';
      }
      AuditExport.copyHeaders(headers, dest.headers);
      this.copySecrets(headers, dest.secretHeaders);
    }
    headers['Content-Type'] = contentType;
    const posted = await this.postHttp(screened.url, headers, body,
      screened.addresses);
    if (!posted.ok && posted.status === 0 &&
        posted.code === 'STS-CORE-0104') {
      logger.debug("Leaving AuditExport.sendHttp(). CA file.");
      return this.failed('pause', 'STS-CORE-0104', posted.why);
    }
    const result = AuditExport.classifyHttp(posted, !!dest.ack &&
      dest.type === 'splunk');
    logger.debug("Leaving AuditExport.sendHttp(). " + result.kind);
    return result;
  }

  /**
   * Polls a Splunk acknowledgement.
   *
   * True advances. False holds without a new failure. An id the
   * collector has forgotten is sent again.
   *
   * @param dest - the Splunk destination
   * @param cursor - the cursor holding the ack id
   * @returns `acked`, `pending`, `missing` or `failed`
   */
  async pollAck(dest: Json, cursor: Cursor): Promise<Json> {
    const { log: logger } = this.deps;
    logger.debug("Entering AuditExport.pollAck(). " + dest.id);
    const token = this.openBox(dest.token);
    if (!token) {
      logger.debug("Leaving AuditExport.pollAck(). No token.");
      return { kind: 'failed', code: 'STS-AUDIT-0007',
               why: 'the collector token is not held', retryAfterMs: 0 };
    }
    let ackTo = '';
    try {
      ackTo = AuditExport.ackUrl(String(dest.url || ''));
    } catch (e) {
      logger.debug("Caught in AuditExport.pollAck(): " +
        ((e && e.message) || e));
      logger.debug("Leaving AuditExport.pollAck(). Bad URL.");
      return { kind: 'failed', code: 'STS-AUDIT-0005',
               why: 'the acknowledgement URL is not usable',
               retryAfterMs: 0 };
    }
    const screened = await this.screenUrl(ackTo, true);
    if (!screened.ok) {
      logger.debug("Leaving AuditExport.pollAck(). Refused.");
      return { kind: 'failed', code: screened.code || 'STS-AUDIT-0005',
               why: screened.why, retryAfterMs: 0 };
    }
    if (!cursor.ackChannel) {
      cursor.ackChannel = this.deps.crypto.randomUuid();
    }
    const headers: Json = {
      Authorization: 'Splunk ' + token,
      'Content-Type': 'application/json',
      'X-Splunk-Request-Channel': cursor.ackChannel
    };
    const posted = await this.postHttp(screened.url, headers,
      JSON.stringify({ acks: [cursor.ackId] }), screened.addresses);
    if (!posted.ok && posted.status === 0) {
      logger.debug("Leaving AuditExport.pollAck(). Failed.");
      return { kind: 'failed', code: posted.code || 'STS-AUDIT-0007',
               why: posted.why, retryAfterMs: posted.retryAfterMs || 0 };
    }
    const classified = AuditExport.classifyHttp(posted, false);
    if (!classified.ok) {
      logger.debug("Leaving AuditExport.pollAck(). Status.");
      return { kind: 'failed', code: classified.code, why: classified.why,
               retryAfterMs: classified.retryAfterMs };
    }
    const acks = posted.json && posted.json.acks;
    const key = String(cursor.ackId);
    if (!acks || !Object.prototype.hasOwnProperty.call(acks, key)) {
      logger.debug("Leaving AuditExport.pollAck(). Missing.");
      return { kind: 'missing' };
    }
    if (acks[key] === true) {
      logger.debug("Leaving AuditExport.pollAck(). Acknowledged.");
      return { kind: 'acked' };
    }
    logger.debug("Leaving AuditExport.pollAck(). Pending.");
    return { kind: 'pending' };
  }

  /**
   * Posts a body to a URL whose addresses were already checked.
   *
   * The request names the original host and pins DNS to the first
   * checked address, which closes the window between the check and the
   * connect as far as one lookup can. It does not follow a redirect.
   * The body is capped and is not put on a log line.
   *
   * @param target - the parsed URL
   * @param headers - request headers; Authorization is not logged
   * @param body - the body
   * @param addresses - the checked addresses
   * @returns status, a short why, and parsed JSON when the body was JSON
   */
  postHttp(target: URL, headers: Json, body: string,
           addresses: string[]): Promise<Json> {
    const { log: logger, http: httpMod, https: httpsMod, config: cfg,
            outbound, version: versions } = this.deps;
    logger.debug("Entering AuditExport.postHttp().");
    const secure = target.protocol === 'https:';
    if (!secure) {
      const verdict = outbound.httpVerdict(FAMILY, target.hostname);
      if (!verdict.ok) {
        logger.debug("Leaving AuditExport.postHttp(). HTTP refused.");
        return Promise.resolve({
          ok: false, status: 0,
          code: verdict.errorCode || 'STS-AUDIT-0005',
          why: verdict.why || 'plain http is refused',
          retryAfterMs: 0, json: null
        });
      }
    }
    let policy: Json = null;
    if (secure) {
      policy = outbound.tlsVerdict(FAMILY, target.hostname);
      if (!policy.ok) {
        logger.debug("Leaving AuditExport.postHttp(). TLS refused.");
        return Promise.resolve({
          ok: false, status: 0,
          code: policy.errorCode || 'STS-AUDIT-0007',
          why: policy.why || 'TLS was refused',
          retryAfterMs: 0, json: null
        });
      }
    }
    const buf = Buffer.from(body, 'utf8');
    const sent: Json = Object.assign({}, headers, {
      'Content-Length': buf.length,
      'User-Agent': versions.userAgent('audit-export')
    });
    const pinned = addresses && addresses.length ? addresses[0] : '';
    const family = pinned.indexOf(':') >= 0 ? 6 : 4;
    const timeout = Number(cfg.value('auditExport.timeoutMs'));
    const options: Json = {
      protocol: target.protocol,
      hostname: target.hostname,
      port: target.port || (secure ? 443 : 80),
      path: target.pathname + target.search,
      method: 'POST',
      headers: sent
    };
    if (pinned) {
      options.lookup = function (_hostname: string, opts: Json,
                                 cb?: Json): void {
        const done = typeof opts === 'function' ? opts : cb;
        done(null, pinned, family);
      };
    }
    if (secure && policy) {
      options.rejectUnauthorized = policy.rejectUnauthorized;
      if (policy.ca) {
        options.ca = policy.ca;
      }
      if (policy.checkServerIdentity) {
        options.checkServerIdentity = policy.checkServerIdentity;
      }
    }
    logger.debug("Leaving AuditExport.postHttp(). Dialling.");
    return new Promise(function (resolve) {
      let request: Json = null;
      const done = function (result: Json): void {
        resolve(result);
      };
      try {
        request = (secure ? httpsMod : httpMod).request(options,
                                                         function (response) {
          const status = response.statusCode || 0;
          if (status >= 300 && status < 400) {
            response.destroy();
            done({
              ok: false, status: status, code: 'STS-AUDIT-0014',
              why: 'it answered ' + status + ', and a redirect is not ' +
                'followed',
              retryAfterMs: AuditExport.retryAfter(response),
              json: null
            });
            return;
          }
          const chunks: Buffer[] = [];
          let bytes = 0;
          let overflow = false;
          response.on('data', function (chunk: Buffer): void {
            if (overflow) {
              return;
            }
            bytes += chunk.length;
            if (bytes > BODY_CAP) {
              overflow = true;
              response.destroy();
              return;
            }
            chunks.push(chunk);
          });
          response.on('end', function (): void {
            const text = Buffer.concat(chunks).toString('utf8');
            let parsed = null;
            if (text) {
              try {
                parsed = JSON.parse(text);
              } catch (e) {
                logger.debug("Caught in AuditExport.postHttp(): " +
                  ((e && e.message) || e));
                parsed = null;
              }
            }
            done({
              ok: status >= 200 && status < 300,
              status: status,
              code: '',
              why: overflow ? 'the response was longer than ' + BODY_CAP +
                ' bytes' : '',
              retryAfterMs: AuditExport.retryAfter(response),
              json: parsed
            });
          });
          response.on('error', function (err: Error): void {
            done({
              ok: false, status: status, code: 'STS-AUDIT-0007',
              why: err && err.message, retryAfterMs: 0, json: null
            });
          });
        });
      } catch (e) {
        logger.debug("Caught in AuditExport.postHttp(): " +
          ((e && e.message) || e));
        done({
          ok: false, status: 0, code: 'STS-AUDIT-0007',
          why: (e && e.message) || 'the request could not be built',
          retryAfterMs: 0, json: null
        });
        return;
      }
      request.setTimeout(timeout, function (): void {
        request.destroy();
        done({
          ok: false, status: 0, code: 'STS-AUDIT-0007',
          why: 'the request timed out', retryAfterMs: 0, json: null
        });
      });
      request.on('error', function (err: Error): void {
        done({
          ok: false, status: 0, code: 'STS-AUDIT-0007',
          why: err && err.message, retryAfterMs: 0, json: null
        });
      });
      request.write(buf);
      request.end();
    });
  }

  /**
   * Classifies an HTTP result.
   *
   * 2xx is acceptance unless Splunk's code is non-zero. 400 is permanent
   * for that event. A redirect, 401 and 403 pause. 408, 429, 5xx and a
   * missing status retry.
   *
   * @param posted - `postHttp`'s answer
   * @param wantAck - whether a Splunk ack id should be kept
   * @returns the send result
   */
  static classifyHttp(posted: Json, wantAck: boolean): SendResult {
    log.debug("Entering AuditExport.classifyHttp().");
    const status = posted.status || 0;
    const retryAfterMs = posted.retryAfterMs || 0;
    if (posted.code === 'STS-AUDIT-0014' ||
        (status >= 300 && status < 400)) {
      log.debug("Leaving AuditExport.classifyHttp(). Redirect.");
      return {
        ok: false, kind: 'pause', disposition: 'failed',
        code: 'STS-AUDIT-0014',
        why: posted.why || 'a redirect is not followed',
        retryAfterMs: retryAfterMs, ackId: null
      };
    }
    if (posted.code === 'STS-CORE-0104') {
      log.debug("Leaving AuditExport.classifyHttp(). CA file.");
      return {
        ok: false, kind: 'pause', disposition: 'failed',
        code: 'STS-CORE-0104', why: posted.why || 'the CA file is unusable',
        retryAfterMs: 0, ackId: null
      };
    }
    if (status >= 200 && status < 300) {
      const collector = posted.json && posted.json.code;
      if (collector) {
        log.debug("Leaving AuditExport.classifyHttp(). Collector code.");
        return {
          ok: false, kind: 'pause', disposition: 'failed',
          code: 'STS-AUDIT-0007',
          why: 'the collector answered code ' + collector,
          retryAfterMs: 0, ackId: null
        };
      }
      if (wantAck && posted.json && posted.json.ackId != null) {
        log.debug("Leaving AuditExport.classifyHttp(). Ack.");
        return {
          ok: true, kind: 'ack-wait', disposition: 'accepted', code: '',
          why: '', retryAfterMs: 0, ackId: posted.json.ackId
        };
      }
      log.debug("Leaving AuditExport.classifyHttp(). Accepted.");
      return {
        ok: true, kind: 'ok', disposition: 'accepted', code: '',
        why: '', retryAfterMs: 0, ackId: null
      };
    }
    if (status === 400) {
      log.debug("Leaving AuditExport.classifyHttp(). Rejected.");
      return {
        ok: false, kind: 'permanent', disposition: 'failed',
        code: 'STS-AUDIT-0015',
        why: 'the destination rejected the event',
        retryAfterMs: 0, ackId: null
      };
    }
    if (status === 401 || status === 403) {
      log.debug("Leaving AuditExport.classifyHttp(). Credentials.");
      return {
        ok: false, kind: 'pause', disposition: 'failed',
        code: 'STS-AUDIT-0007',
        why: 'the destination answered ' + status,
        retryAfterMs: 0, ackId: null
      };
    }
    if (status === 429 || status === 408 || status >= 500 || status === 0) {
      log.debug("Leaving AuditExport.classifyHttp(). Transient.");
      return {
        ok: false, kind: 'transient', disposition: 'failed',
        code: posted.code || 'STS-AUDIT-0007',
        why: posted.why || ('the destination answered ' + status),
        retryAfterMs: retryAfterMs, ackId: null
      };
    }
    log.debug("Leaving AuditExport.classifyHttp(). Pause.");
    return {
      ok: false, kind: 'pause', disposition: 'failed',
      code: posted.code || 'STS-AUDIT-0007',
      why: posted.why || ('the destination answered ' + status),
      retryAfterMs: 0, ackId: null
    };
  }

  /**
   * Reads Retry-After as milliseconds, or 0 when it is absent or not a
   * delay this process should wait.
   *
   * @param response - the HTTP response
   * @returns the delay
   */
  static retryAfter(response: Json): number {
    log.debug("Entering AuditExport.retryAfter().");
    const raw = response && response.headers
      ? response.headers['retry-after'] : '';
    const text = Array.isArray(raw) ? raw[0] : raw;
    if (!text) {
      log.debug("Leaving AuditExport.retryAfter(). None.");
      return 0;
    }
    if (/^\d+$/.test(String(text).trim())) {
      const ms = Number(text) * 1000;
      log.debug("Leaving AuditExport.retryAfter(). " + ms);
      return ms > 3600000 ? 3600000 : ms;
    }
    const when = Date.parse(String(text));
    if (!isFinite(when)) {
      log.debug("Leaving AuditExport.retryAfter(). Unreadable.");
      return 0;
    }
    const ms = when - Date.now();
    log.debug("Leaving AuditExport.retryAfter().");
    return ms > 0 ? (ms > 3600000 ? 3600000 : ms) : 0;
  }

  /**
   * The acknowledgement URL beside a HEC event URL.
   *
   * A path ending in `/event` swaps that segment for `/ack`. A path
   * ending in `/collector` appends `/ack`. Anything else appends `/ack`.
   * The query is dropped: a token belongs in the header, and a query
   * must not be written down.
   *
   * @param eventUrl - the collector event URL
   * @returns the acknowledgement URL
   */
  static ackUrl(eventUrl: string): string {
    log.debug("Entering AuditExport.ackUrl().");
    const url = new URL(eventUrl);
    let pathname = url.pathname || '/';
    if (pathname.endsWith('/event')) {
      pathname = pathname.slice(0, -'/event'.length) + '/ack';
    } else if (pathname.endsWith('/collector')) {
      pathname = pathname + '/ack';
    } else {
      pathname = pathname.replace(/\/$/, '') + '/ack';
    }
    url.pathname = pathname;
    url.search = '';
    url.hash = '';
    log.debug("Leaving AuditExport.ackUrl().");
    return url.toString();
  }

  /**
   * Builds the canonical event for one audit row.
   *
   * @param row - the audit row
   * @param dest - the destination, for its extra redaction
   * @returns the event
   */
  buildEvent(row: Json, dest: Json): Json {
    const { log: logger } = this.deps;
    logger.debug("Entering AuditExport.buildEvent().");
    const names = this.redactNames(dest && dest.excludeAttributes);
    const event = AuditExport.canonical(row, {
      realm: String(this.deps.realms.currentId()),
      origin: this.originId(),
      source: this.deps.version.userAgent('audit-export'),
      names: names
    });
    logger.debug("Leaving AuditExport.buildEvent().");
    return event;
  }

  /**
   * The canonical event. Built at delivery, not stored beside the row.
   *
   * @param row - the audit row
   * @param opts - realm, origin, source, and the redaction names
   * @returns the event
   */
  static canonical(row: Json, opts: Json): Json {
    log.debug("Entering AuditExport.canonical().");
    // THE ROW IS READ THROUGH THE `AuditEvent` CONCEPT (#1579), so the
    // model is the one statement of what an audit row holds. The wire
    // format below is the export's own and does not change with it.
    const one = DomainClasses.AuditEvent.fromRecord(row || {});
    const detail: Json = one.detail || {};
    const origin = opts.origin || one.origin || '';
    const at = Number(one.at) || Date.now();
    const outcome = String(one.outcome || '');
    log.debug("Leaving AuditExport.canonical().");
    return {
      id: (origin || 'local') + ':' + one.sequence,
      seq: one.sequence,
      origin: origin || '',
      timestamp: new Date(at).toISOString(),
      at: at,
      severity: AuditExport.severityName(outcome),
      category: one.category || '',
      action: one.action || '',
      outcome: outcome,
      errorCode: one.errorCode || '',
      source: opts.source || '',
      realm: opts.realm || '',
      subject: one.actor || '',
      subjectForm: one.actorForm || '',
      client: detail.client_id || detail.application || '',
      address: one.address || '',
      target: one.target || '',
      protocol: one.protocol || '',
      channel: one.channel || '',
      message: one.summary || '',
      attributes: AuditExport.redact(detail, opts.names)
    };
  }

  /**
   * Replaces one template's placeholders in a single pass.
   *
   * An unknown placeholder is left as written. A value that itself
   * contains `{message}` is not expanded again.
   *
   * @param template - the destination's template
   * @param event - the canonical event
   * @returns the body
   */
  static fillTemplate(template: string, event: Json): string {
    log.debug("Entering AuditExport.fillTemplate().");
    const map: Json = {
      timestamp: event.timestamp || '',
      severity: event.severity || '',
      event_type: event.action || '',
      subject: event.subject || '',
      message: event.message || '',
      id: event.id || '',
      realm: event.realm || '',
      outcome: event.outcome || '',
      category: event.category || '',
      target: event.target || '',
      address: event.address || '',
      origin: event.origin || '',
      protocol: event.protocol || '',
      channel: event.channel || ''
    };
    const out = String(template).replace(/\{([a-z_]+)\}/g,
                                          function (whole, key) {
      if (Object.prototype.hasOwnProperty.call(map, key)) {
        return String(map[key]);
      }
      return whole;
    });
    log.debug("Leaving AuditExport.fillTemplate().");
    return out;
  }

  /**
   * Formats one RFC 5424 line. No trailing newline.
   *
   * @param event - the canonical event
   * @param dest - the syslog destination
   * @returns the line
   */
  static syslogLine(event: Json, dest: Json): string {
    log.debug("Entering AuditExport.syslogLine().");
    const facility = AuditExport.clamp(dest && dest.facility, 0, 23, 16);
    const severity = AuditExport.severityNumber(event && event.outcome);
    const pri = facility * 8 + severity;
    const at = event && event.at ? Number(event.at) : Date.now();
    const host = AuditExport.token(AuditExport.hostToken(os), 255);
    const app = AuditExport.token(
      (dest && dest.appName) || 'iya-sts', 48);
    const msgid = AuditExport.token(
      String((event && event.action) || '').replace(/ /g, '_'), 32);
    const sd = AuditExport.structuredData(event);
    let msg = String((event && event.message) || '')
      .replace(/[\u0000\r\n]/g, ' ');
    if (/[^\u0000-\u007f]/.test(msg)) {
      msg = '\uFEFF' + msg;
    }
    const line = '<' + pri + '>1 ' + new Date(at).toISOString() + ' ' +
      host + ' ' + app + ' ' + String(process.pid) + ' ' + msgid + ' ' +
      sd + (msg ? ' ' + msg : '');
    log.debug("Leaving AuditExport.syslogLine().");
    return line;
  }

  /**
   * The `iyaAudit` structured-data element. The id is not registered
   * with IANA.
   *
   * @param event - the canonical event
   * @returns the element, or NILVALUE when there is nothing to say
   */
  static structuredData(event: Json): string {
    log.debug("Entering AuditExport.structuredData().");
    const one = event || {};
    const params: string[][] = [
      ['id', one.id], ['realm', one.realm], ['origin', one.origin],
      ['seq', one.seq], ['category', one.category],
      ['outcome', one.outcome]
    ];
    const parts = params.map(function (pair) {
      return pair[0] + '="' + AuditExport.sdEscape(pair[1]) + '"';
    });
    log.debug("Leaving AuditExport.structuredData().");
    return '[iyaAudit ' + parts.join(' ') + ']';
  }

  /**
   * Escapes one structured-data value per RFC 5424.
   *
   * @param value - the value
   * @returns the escaped value
   */
  static sdEscape(value: unknown): string {
    log.debug("Entering AuditExport.sdEscape().");
    const out = String(value == null ? '' : value)
      .replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\]/g, '\\]');
    log.debug("Leaving AuditExport.sdEscape().");
    return out;
  }

  /**
   * A syslog token: no spaces, cut to `max`, NILVALUE when empty.
   *
   * @param value - the token
   * @param max - the maximum length
   * @returns the token
   */
  static token(value: unknown, max: number): string {
    log.debug("Entering AuditExport.token().");
    const clean = String(value == null ? '' : value)
      .replace(/[\s\u0000-\u001f]/g, '').slice(0, max);
    log.debug("Leaving AuditExport.token().");
    return clean || NIL;
  }

  /**
   * The process hostname, with spaces removed.
   *
   * @param osMod - the `os` module
   * @returns the hostname, or ''
   */
  static hostToken(osMod: Json): string {
    log.debug("Entering AuditExport.hostToken().");
    let name = '';
    try {
      name = osMod.hostname();
    } catch (e) {
      log.debug("Caught in AuditExport.hostToken(): " +
        ((e && e.message) || e));
      name = '';
    }
    log.debug("Leaving AuditExport.hostToken().");
    return String(name || '').replace(/[\s\u0000-\u001f]/g, '').slice(0, 255);
  }

  /**
   * The notice/warning/error name for an outcome.
   *
   * @param outcome - success, refused or error
   * @returns the name
   */
  static severityName(outcome: string): string {
    log.debug("Entering AuditExport.severityName().");
    const name = outcome === 'success' ? 'notice'
      : (outcome === 'refused' ? 'warning' : 'error');
    log.debug("Leaving AuditExport.severityName().");
    return name;
  }

  /**
   * The RFC 5424 severity for an outcome.
   *
   * @param outcome - success, refused or error
   * @returns 5, 4 or 3
   */
  static severityNumber(outcome: string): number {
    log.debug("Entering AuditExport.severityNumber().");
    const n = outcome === 'success' ? 5 : (outcome === 'refused' ? 4 : 3);
    log.debug("Leaving AuditExport.severityNumber().");
    return n;
  }

  /**
   * Clamps a number, using `fallback` when it is not finite.
   *
   * @param value - the candidate
   * @param min - the minimum
   * @param max - the maximum
   * @param fallback - the value when it is missing
   * @returns the clamped number
   */
  static clamp(value: unknown, min: number, max: number,
               fallback: number): number {
    log.debug("Entering AuditExport.clamp().");
    const n = Number(value);
    const used = isFinite(n) ? n : fallback;
    const out = used < min ? min : (used > max ? max : used);
    log.debug("Leaving AuditExport.clamp().");
    return out;
  }

  /**
   * Walks a value and replaces redacted keys.
   *
   * @param value - the value
   * @param names - lower-case key names
   * @returns the copy
   */
  static redact(value: Json, names: Json): Json {
    log.debug("Entering AuditExport.redact().");
    const out = AuditExport.redactValue(value, names || new Set());
    log.debug("Leaving AuditExport.redact().");
    return out;
  }

  // No Entering/Leaving pair. This walks every attribute of every
  // exported event, and a line per value would drown the log.
  /**
   * The recursive half of `redact`.
   *
   * @param value - the value
   * @param names - the names
   * @returns the copy
   */
  static redactValue(value: Json, names: Json): Json {
    if (Array.isArray(value)) {
      return value.map(function (one) {
        return AuditExport.redactValue(one, names);
      });
    }
    if (!value || typeof value !== 'object') {
      return value;
    }
    const out: Json = {};
    Object.keys(value).forEach(function (key) {
      if (names.has(String(key).toLowerCase())) {
        out[key] = '[redacted]';
        return;
      }
      out[key] = AuditExport.redactValue(value[key], names);
    });
    return out;
  }

  /**
   * The redaction set: the fixed names, the setting, and the destination's
   * own list.
   *
   * @param extra - the destination's comma-separated names
   * @returns the set
   */
  redactNames(extra: unknown): Set<string> {
    const { log: logger, config: cfg } = this.deps;
    logger.debug("Entering AuditExport.redactNames().");
    const set = new Set<string>();
    const configured = String(cfg.value('auditExport.redactKeys') || '');
    (ALWAYS_REDACT.join(',') + ',' + configured + ',' +
      String(extra || '')).split(',').forEach(function (part) {
      const name = part.trim().toLowerCase();
      if (name) {
        set.add(name);
      }
    });
    logger.debug("Leaving AuditExport.redactNames(). " + set.size);
    return set;
  }

  /**
   * Tells whether a row must not be exported. The cursor still advances.
   *
   * @param row - the audit row
   * @returns true when `detail.exportSkip` is set
   */
  static skipped(row: Json): boolean {
    log.debug("Entering AuditExport.skipped().");
    const skip = !!(row && row.detail && row.detail.exportSkip);
    log.debug("Leaving AuditExport.skipped(). " + skip);
    return skip;
  }

  /**
   * The event id a receiver can deduplicate on.
   *
   * @param row - the audit row
   * @returns `origin:seq`
   */
  eventId(row: Json): string {
    const { log: logger } = this.deps;
    logger.debug("Entering AuditExport.eventId().");
    const origin = (row && row.origin) || this.originId() || 'local';
    logger.debug("Leaving AuditExport.eventId().");
    return origin + ':' + (row && row.seq);
  }

  /**
   * This process's origin, read lazily so loading this module does not
   * load the store.
   *
   * @returns the origin id, or ''
   */
  originId(): string {
    const { log: logger } = this.deps;
    logger.debug("Entering AuditExport.originId().");
    try {
      const persistence = require('../persistence/persistence');
      const id = persistence.originId && persistence.originId();
      logger.debug("Leaving AuditExport.originId().");
      return id ? String(id) : '';
    } catch (e) {
      logger.debug("Caught in AuditExport.originId(): " +
        ((e && e.message) || e));
      logger.debug("Leaving AuditExport.originId(). None.");
      return '';
    }
  }

  /**
   * This process's ring, oldest first.
   *
   * @returns the rows
   */
  localRows(): Json[] {
    const { log: logger, audit: auditLog } = this.deps;
    logger.debug("Entering AuditExport.localRows().");
    const rows = auditLog.localEvents().slice(0);
    rows.sort(function (a: Json, b: Json) {
      return Number(a.seq) - Number(b.seq);
    });
    logger.debug("Leaving AuditExport.localRows(). " + rows.length);
    return rows;
  }

  /**
   * A cursor with nothing delivered.
   *
   * @returns the cursor
   */
  static emptyCursor(): Cursor {
    log.debug("Entering AuditExport.emptyCursor().");
    log.debug("Leaving AuditExport.emptyCursor().");
    return {
      seq: 0, origin: '', primed: false, pausedUntil: 0, retryMs: 0,
      failingSince: 0, lastSuccessAt: 0, lastFailureAt: 0, lastFailure: '',
      lastDisposition: '', delivered: 0, failedPermanent: 0, droppedGap: 0,
      retries: 0, latencyMs: 0, samples: 0, ackId: null, ackChannel: '',
      inFlightId: '', inFlightSeq: 0, nextSeq: null
    };
  }

  /**
   * Copies a stored cursor onto an empty one, so a missing field is the
   * empty value rather than a mutation of the stored object.
   *
   * @param stored - the stored cursor, or null
   * @returns the copy
   */
  static copyCursor(stored: Json): Cursor {
    log.debug("Entering AuditExport.copyCursor().");
    const cursor = Object.assign(AuditExport.emptyCursor(), stored || {});
    if (cursor.nextSeq === undefined) {
      cursor.nextSeq = null;
    }
    if (cursor.ackId === undefined) {
      cursor.ackId = null;
    }
    log.debug("Leaving AuditExport.copyCursor().");
    return cursor;
  }

  /**
   * Reads one destination from the ambient realm.
   *
   * @param id - the destination id
   * @returns the destination, or null
   */
  readDest(id: string): Json {
    const { log: logger, destinations } = this.deps;
    logger.debug("Entering AuditExport.readDest().");
    const dest = destinations.get(id) || null;
    logger.debug("Leaving AuditExport.readDest().");
    return dest;
  }

  /**
   * Reads one cursor.
   *
   * @param id - the destination id
   * @returns the cursor
   */
  readCursor(id: string): Cursor {
    const { log: logger, cursors } = this.deps;
    logger.debug("Entering AuditExport.readCursor().");
    const cursor = AuditExport.copyCursor(cursors.get(id));
    logger.debug("Leaving AuditExport.readCursor().");
    return cursor;
  }

  /**
   * Stores a cursor as a new object. An in-place change is not journaled.
   *
   * @param id - the destination id
   * @param cursor - the cursor
   */
  putCursor(id: string, cursor: Cursor): void {
    const { log: logger, cursors } = this.deps;
    logger.debug("Entering AuditExport.putCursor().");
    cursors.set(id, Object.assign(AuditExport.emptyCursor(), cursor));
    logger.debug("Leaving AuditExport.putCursor().");
  }

  /**
   * Stores a destination as a new object.
   *
   * @param dest - the destination
   */
  putDest(dest: Json): void {
    const { log: logger, destinations } = this.deps;
    logger.debug("Entering AuditExport.putDest().");
    destinations.set(dest.id, Object.assign({}, dest));
    logger.debug("Leaving AuditExport.putDest().");
  }

  /**
   * Performs one console or API act.
   *
   * @param body - the act, including `action`
   * @returns `{ ok: true, destination }` or a marked refusal
   */
  async act(body: Json): Promise<Json> {
    const { log: logger } = this.deps;
    const asked = body || {};
    const action = String(asked.action || '');
    logger.debug("Entering AuditExport.act(). " + action);
    let result: Json;
    if (action === 'add') {
      result = await this.addDest(asked);
    } else if (action === 'update') {
      result = await this.updateDest(asked);
    } else if (action === 'remove') {
      result = this.removeDest(asked);
    } else if (action === 'enable' || action === 'disable') {
      result = this.setEnabled(asked, action === 'enable');
    } else if (action === 'test') {
      result = await this.testDestination(asked);
    } else {
      // THE SENTENCE NAMES THE ACTIONS, in the "Unknown action" shape every
      // other resource writes: `sts_admin_api_operations` compares it with
      // the OpenAPI document, and `tests/admin_api.js`'s parity check reads
      // it. "The action is not known." turned both checks off for this
      // resource (2026-11-02).
      result = this.refusal('STS-AUDIT-0001',
        'Unknown action "' + action + '". The six are: add, update, ' +
        'remove, enable, disable, test.');
    }
    logger.debug("Leaving AuditExport.act(). ok=" + result.ok);
    return result;
  }

  /**
   * Adds a destination.
   *
   * @param body - the fields
   * @returns the act result
   */
  async addDest(body: Json): Promise<Json> {
    const { log: logger } = this.deps;
    logger.debug("Entering AuditExport.addDest().");
    const built = await this.prepare(body, null);
    if (!built.ok) {
      logger.debug("Leaving AuditExport.addDest(). Refused.");
      return built;
    }
    if (this.readDest(built.dest.id)) {
      logger.debug("Leaving AuditExport.addDest(). Duplicate.");
      return this.refusal('STS-AUDIT-0001',
        'A destination already has that id.');
    }
    this.putDest(built.dest);
    this.changed('admin.audit-export.add', built.dest);
    logger.debug("Leaving AuditExport.addDest().");
    return { ok: true, destination: this.publicDest(built.dest) };
  }

  /**
   * Updates a destination. An empty secret keeps the stored one. The id
   * does not change.
   *
   * @param body - the fields
   * @returns the act result
   */
  async updateDest(body: Json): Promise<Json> {
    const { log: logger } = this.deps;
    logger.debug("Entering AuditExport.updateDest().");
    const id = String((body && body.id) || '');
    const existing = this.readDest(id);
    if (!existing) {
      logger.debug("Leaving AuditExport.updateDest(). Unknown.");
      return this.refusal('STS-AUDIT-0002',
        'No destination has that id.');
    }
    const built = await this.prepare(body, existing);
    if (!built.ok) {
      logger.debug("Leaving AuditExport.updateDest(). Refused.");
      return built;
    }
    if (existing.type === 'file' && existing.path !== built.dest.path) {
      this.closeFile(id);
    }
    this.putDest(built.dest);
    this.changed('admin.audit-export.update', built.dest);
    logger.debug("Leaving AuditExport.updateDest().");
    return { ok: true, destination: this.publicDest(built.dest) };
  }

  /**
   * Removes a destination and its cursor.
   *
   * @param body - `{ id }`
   * @returns the act result
   */
  removeDest(body: Json): Json {
    const { log: logger, destinations, cursors } = this.deps;
    logger.debug("Entering AuditExport.removeDest().");
    const id = String((body && body.id) || '');
    const existing = this.readDest(id);
    if (!existing) {
      logger.debug("Leaving AuditExport.removeDest(). Unknown.");
      return this.refusal('STS-AUDIT-0002',
        'No destination has that id.');
    }
    this.closeFile(id);
    destinations.delete(id);
    cursors.delete(id);
    this.changed('admin.audit-export.remove', existing);
    logger.debug("Leaving AuditExport.removeDest().");
    return { ok: true, destination: this.publicDest(existing) };
  }

  /**
   * Enables or disables a destination. The cursor stays, so a disable
   * does not backfill again when the destination is enabled later.
   * The first enable of a destination that was never enabled does
   * backfill, because its cursor is still unprimed.
   *
   * @param body - `{ id }`
   * @param enabled - the new state
   * @returns the act result
   */
  setEnabled(body: Json, enabled: boolean): Json {
    const { log: logger } = this.deps;
    logger.debug("Entering AuditExport.setEnabled(). " + enabled);
    const id = String((body && body.id) || '');
    const existing = this.readDest(id);
    if (!existing) {
      logger.debug("Leaving AuditExport.setEnabled(). Unknown.");
      return this.refusal('STS-AUDIT-0002',
        'No destination has that id.');
    }
    const next = Object.assign({}, existing, { enabled: enabled });
    this.putDest(next);
    this.changed(enabled ? 'admin.audit-export.enable'
                         : 'admin.audit-export.disable', next);
    logger.debug("Leaving AuditExport.setEnabled().");
    return { ok: true, destination: this.publicDest(next) };
  }

  /**
   * Sends a synthetic event straight to one destination.
   *
   * The synthetic event is not an audit row. The act is: an operator
   * tested a destination, and that fact is recorded without the
   * destination's address or its secret.
   *
   * @param body - `{ id }`
   * @returns the act result, with a short diagnostic
   */
  async testDestination(body: Json): Promise<Json> {
    const { log: logger, audit: auditLog } = this.deps;
    logger.debug("Entering AuditExport.testDestination().");
    const id = String((body && body.id) || '');
    const dest = this.readDest(id);
    if (!dest) {
      logger.debug("Leaving AuditExport.testDestination(). Unknown.");
      return this.refusal('STS-AUDIT-0002',
        'No destination has that id.');
    }
    const event = this.testEvent(dest);
    const sent = await this.offerEvent(dest, event, { socket: null });
    if (!sent.ok) {
      auditLog.audit({
        action: 'admin.audit-export.test',
        target: id,
        outcome: 'error',
        errorCode: 'STS-AUDIT-0010',
        summarised: true,
        summary: 'Audit export destination ' + id + ' was tested.',
        detail: { type: dest.type }
      });
      logger.debug("Leaving AuditExport.testDestination(). Failed.");
      return this.refusal('STS-AUDIT-0010',
        sent.why || 'The test event was not delivered.');
    }
    auditLog.audit({
      action: 'admin.audit-export.test',
      target: id,
      outcome: 'success',
      summary: 'Audit export destination ' + id + ' was tested.',
      detail: { type: dest.type, enabled: !!dest.enabled }
    });
    logger.debug("Leaving AuditExport.testDestination().");
    return {
      ok: true,
      destination: this.publicDest(dest),
      diagnostic: {
        disposition: sent.disposition,
        test: true
      }
    };
  }

  /**
   * The synthetic event. `test: true` is an attribute, not an audit row.
   *
   * @param dest - the destination
   * @returns the event
   */
  testEvent(dest: Json): Json {
    const { log: logger } = this.deps;
    logger.debug("Entering AuditExport.testEvent().");
    const at = Date.now();
    logger.debug("Leaving AuditExport.testEvent().");
    return {
      id: 'test:' + dest.id + ':' + at,
      seq: 0,
      origin: this.originId(),
      timestamp: new Date(at).toISOString(),
      at: at,
      severity: 'notice',
      category: 'service',
      action: 'audit.export.test',
      outcome: 'success',
      errorCode: '',
      source: this.deps.version.userAgent('audit-export'),
      realm: String(this.deps.realms.currentId()),
      subject: 'audit-export',
      subjectForm: '',
      client: '',
      address: '',
      target: dest.id,
      protocol: '',
      channel: 'audit-export',
      message: 'IYA-STS audit export test',
      attributes: { test: true }
    };
  }

  /**
   * Checks and normalizes a destination. `existing` is null for an add.
   *
   * @param body - the submitted fields
   * @param existing - the stored destination, or null
   * @returns `{ ok, dest }` or a refusal
   */
  async prepare(body: Json, existing: Json | null): Promise<Json> {
    const { log: logger } = this.deps;
    logger.debug("Entering AuditExport.prepare().");
    const id = existing ? existing.id : String((body && body.id) || '');
    if (!ID_RE.test(id)) {
      logger.debug("Leaving AuditExport.prepare(). Bad id.");
      return this.refusal('STS-AUDIT-0001',
        'The id must start with a letter or a digit and use only ' +
        'lower-case letters, digits and hyphens.');
    }
    const type = String((body && body.type) ||
                        (existing && existing.type) || '');
    if (TYPES.indexOf(type) < 0) {
      logger.debug("Leaving AuditExport.prepare(). Bad type.");
      return this.refusal('STS-AUDIT-0001',
        'The type must be syslog, file, webhook, splunk or logrhythm.');
    }
    const name = AuditExport.picked(body, existing, 'name', id);
    if (!String(name).trim() || String(name).length > 128) {
      logger.debug("Leaving AuditExport.prepare(). Bad name.");
      return this.refusal('STS-AUDIT-0001',
        'The destination needs a name of at most 128 characters.');
    }
    let enabled = true;
    if (body && body.enabled !== undefined) {
      enabled = !!body.enabled;
    } else if (existing) {
      enabled = !!existing.enabled;
    }
    const excluded = String(AuditExport.picked(body, existing,
      'excludeAttributes', ''));
    if (excluded.length > 1000) {
      logger.debug("Leaving AuditExport.prepare(). Long exclusions.");
      return this.refusal('STS-AUDIT-0001',
        'The excluded attributes are too long.');
    }
    const dest: Json = {
      id: id, name: String(name).trim(), type: type, enabled: enabled,
      excludeAttributes: excluded
    };
    const typed = await this.fillTyped(dest, body, existing);
    if (!typed.ok) {
      logger.debug("Leaving AuditExport.prepare(). Refused.");
      return typed;
    }
    logger.debug("Leaving AuditExport.prepare().");
    return { ok: true, dest: dest };
  }

  /**
   * Fills the type-specific fields.
   *
   * @param dest - the destination being built
   * @param body - the submitted fields
   * @param existing - the stored destination, or null
   * @returns `{ ok: true }` or a refusal
   */
  async fillTyped(dest: Json, body: Json,
                  existing: Json | null): Promise<Json> {
    const { log: logger } = this.deps;
    logger.debug("Entering AuditExport.fillTyped(). " + dest.type);
    if (dest.type === 'syslog' || dest.type === 'logrhythm') {
      dest.host = AuditExport.picked(body, existing, 'host', '');
      dest.port = AuditExport.picked(body, existing, 'port', 0);
      dest.transport = AuditExport.picked(body, existing, 'transport',
                                           'tcp');
      dest.facility = AuditExport.picked(body, existing, 'facility', 16);
      dest.appName = AuditExport.picked(body, existing, 'appName',
                                         'iya-sts');
      if (!dest.host || String(dest.host).length > 255) {
        logger.debug("Leaving AuditExport.fillTyped(). No host.");
        return this.refusal('STS-AUDIT-0001',
          'A syslog destination needs a host.');
      }
      if (String(dest.appName).length > 48) {
        logger.debug("Leaving AuditExport.fillTyped(). Long app name.");
        return this.refusal('STS-AUDIT-0001',
          'The application name is too long.');
      }
      if (['udp', 'tcp', 'tls'].indexOf(dest.transport) < 0) {
        logger.debug("Leaving AuditExport.fillTyped(). Bad transport.");
        return this.refusal('STS-AUDIT-0001',
          'The transport must be udp, tcp or tls.');
      }
      // ASVS 5.0.0 12.3.1: the audit log leaves encrypted in product (#1527).
      if (dest.transport !== 'tls' &&
          require('./mode').refusesPlainSyslog()) {
        logger.debug("Leaving AuditExport.fillTyped(). Plain syslog.");
        return this.refusal('STS-AUDIT-0016', 'Product mode sends syslog ' +
          'over tls only, unless audit.allowPlainSyslog is on.');
      }
      const facility = Number(dest.facility);
      if (!isFinite(facility) || facility < 0 || facility > 23) {
        logger.debug("Leaving AuditExport.fillTyped(). Bad facility.");
        return this.refusal('STS-AUDIT-0001',
          'The facility must be from 0 to 23.');
      }
      dest.facility = facility;
      const port = Number(dest.port) || 0;
      if (port !== 0 && (port < 1 || port > 65535)) {
        logger.debug("Leaving AuditExport.fillTyped(). Bad port.");
        return this.refusal('STS-AUDIT-0001',
          'The port must be from 1 to 65535.');
      }
      dest.port = port;
      const screened = await this.screenHost(String(dest.host), false);
      if (!screened.ok) {
        logger.debug("Leaving AuditExport.fillTyped(). Host refused.");
        return this.refusal(screened.code || 'STS-AUDIT-0005',
          screened.why);
      }
    } else if (dest.type === 'file') {
      dest.path = AuditExport.picked(body, existing, 'path', '');
      if (String(dest.path).length > 1024) {
        logger.debug("Leaving AuditExport.fillTyped(). Long path.");
        return this.refusal('STS-AUDIT-0001',
          'The path is too long.');
      }
      dest.mode = AuditExport.picked(body, existing, 'mode', '');
      dest.rotateBytes = Number(AuditExport.picked(body, existing,
        'rotateBytes', 0)) || 0;
      if (AuditExport.parseMode(dest.mode) < 0) {
        logger.debug("Leaving AuditExport.fillTyped(). Bad mode.");
        return this.refusal('STS-AUDIT-0001',
          'The mode must be three octal digits, such as 640.');
      }
      if (dest.rotateBytes < 0) {
        logger.debug("Leaving AuditExport.fillTyped(). Bad rotation.");
        return this.refusal('STS-AUDIT-0001',
          'The rotation size cannot be negative.');
      }
      const checked = this.checkPath(dest.path);
      if (!checked.ok) {
        logger.debug("Leaving AuditExport.fillTyped(). Path refused.");
        return this.refusal('STS-AUDIT-0004', checked.why);
      }
      dest.path = checked.path;
    } else if (dest.type === 'webhook') {
      dest.url = AuditExport.picked(body, existing, 'url', '');
      dest.template = AuditExport.picked(body, existing, 'template', '');
      dest.contentType = AuditExport.picked(body, existing, 'contentType',
                                            '');
      if (String(dest.url).length > 2048 ||
          String(dest.template).length > 4000 ||
          String(dest.contentType).length > 200) {
        logger.debug("Leaving AuditExport.fillTyped(). Too long.");
        return this.refusal('STS-AUDIT-0001',
          'A webhook field is too long.');
      }
      const headers = await this.takeHeaders(body, existing, false);
      if (!headers.ok) {
        logger.debug("Leaving AuditExport.fillTyped(). Headers.");
        return headers;
      }
      dest.headers = headers.headers;
      const secrets = await this.takeHeaders(body, existing, true);
      if (!secrets.ok) {
        logger.debug("Leaving AuditExport.fillTyped(). Secret headers.");
        return secrets;
      }
      dest.secretHeaders = secrets.headers;
      const moved = await this.sealSensitive(dest);
      if (!moved.ok) {
        logger.debug("Leaving AuditExport.fillTyped(). Sensitive.");
        return moved;
      }
      const screened = await this.screenUrl(String(dest.url), false);
      if (!screened.ok) {
        logger.debug("Leaving AuditExport.fillTyped(). URL refused.");
        return this.refusal(screened.code || 'STS-AUDIT-0005',
          screened.why);
      }
    } else if (dest.type === 'splunk') {
      dest.url = AuditExport.picked(body, existing, 'url', '');
      if (String(dest.url).length > 2048) {
        logger.debug("Leaving AuditExport.fillTyped(). Long URL.");
        return this.refusal('STS-AUDIT-0001',
          'The collector URL is too long.');
      }
      dest.index = AuditExport.picked(body, existing, 'index', '');
      dest.sourcetype = AuditExport.picked(body, existing, 'sourcetype',
                                           'iya:audit');
      dest.source = AuditExport.picked(body, existing, 'source', 'iya-sts');
      dest.ack = body && body.ack !== undefined ? !!body.ack
        : !!(existing && existing.ack);
      const token = await this.takeSecret(body, existing, 'token');
      if (!token.ok) {
        logger.debug("Leaving AuditExport.fillTyped(). Token.");
        return token;
      }
      dest.token = token.box;
      if (!dest.token) {
        logger.debug("Leaving AuditExport.fillTyped(). No token.");
        return this.refusal('STS-AUDIT-0001',
          'A Splunk destination needs a token.');
      }
      const screened = await this.screenUrl(String(dest.url), false);
      if (!screened.ok) {
        logger.debug("Leaving AuditExport.fillTyped(). URL refused.");
        return this.refusal(screened.code || 'STS-AUDIT-0005',
          screened.why);
      }
    }
    logger.debug("Leaving AuditExport.fillTyped().");
    return { ok: true };
  }

  /**
   * A field from the body, or the stored value, or the fallback.
   *
   * An omitted field is `undefined`. An empty string is a value, except
   * where the caller treats it as "keep" itself.
   *
   * @param body - the submitted fields
   * @param existing - the stored destination, or null
   * @param key - the field
   * @param fallback - the value when neither has it
   * @returns the value
   */
  static picked(body: Json, existing: Json | null, key: string,
                fallback: Json): Json {
    log.debug("Entering AuditExport.picked().");
    if (body && body[key] !== undefined && body[key] !== null) {
      log.debug("Leaving AuditExport.picked(). Submitted.");
      return body[key];
    }
    if (existing && existing[key] !== undefined) {
      log.debug("Leaving AuditExport.picked(). Stored.");
      return existing[key];
    }
    log.debug("Leaving AuditExport.picked(). Fallback.");
    return fallback;
  }

  /**
   * Takes a write-only secret. Empty on update keeps the stored box.
   *
   * @param body - the submitted fields
   * @param existing - the stored destination, or null
   * @param key - `token`
   * @returns `{ ok, box }`
   */
  async takeSecret(body: Json, existing: Json | null,
                   key: string): Promise<Json> {
    const { log: logger } = this.deps;
    logger.debug("Entering AuditExport.takeSecret().");
    const submitted = body && body[key] !== undefined ? body[key] : undefined;
    if (submitted === undefined || submitted === '') {
      logger.debug("Leaving AuditExport.takeSecret(). Kept.");
      return { ok: true, box: existing ? existing[key] : null };
    }
    if (String(submitted).length > 4096) {
      logger.debug("Leaving AuditExport.takeSecret(). Too long.");
      return this.refusal('STS-AUDIT-0001', 'The secret is too long.');
    }
    const box = this.sealBox(String(submitted));
    if (!box) {
      logger.debug("Leaving AuditExport.takeSecret(). Unsealed.");
      return this.refusal('STS-AUDIT-0003',
        'The secret could not be sealed.');
    }
    logger.debug("Leaving AuditExport.takeSecret().");
    return { ok: true, box: box };
  }

  /**
   * Takes header lines. Plain headers replace wholesale when the field
   * is present, including empty. Secret headers merge: a blank value
   * keeps that one key, and a field that names no key keeps them all.
   *
   * @param body - the submitted fields
   * @param existing - the stored destination, or null
   * @param secret - whether these are the secret headers
   * @returns `{ ok, headers }`
   */
  async takeHeaders(body: Json, existing: Json | null,
                    secret: boolean): Promise<Json> {
    const { log: logger } = this.deps;
    logger.debug("Entering AuditExport.takeHeaders(). secret=" + secret);
    const key = secret ? 'secretHeaders' : 'headers';
    const submitted = body ? body[key] : undefined;
    const prior = (existing && existing[key]) || {};
    if (submitted === undefined) {
      logger.debug("Leaving AuditExport.takeHeaders(). Kept.");
      return { ok: true, headers: prior };
    }
    const text = typeof submitted === 'string' ? submitted
      : AuditExport.headerText(submitted);
    if (secret && !String(text).trim()) {
      logger.debug("Leaving AuditExport.takeHeaders(). No keys.");
      return { ok: true, headers: prior };
    }
    if (String(text).length > 8000) {
      logger.debug("Leaving AuditExport.takeHeaders(). Too long.");
      return this.refusal('STS-AUDIT-0001', 'The headers are too long.');
    }
    const parsed = AuditExport.parseHeaderLines(text);
    if (!parsed.ok) {
      logger.debug("Leaving AuditExport.takeHeaders(). Bad line.");
      return this.refusal('STS-AUDIT-0001', parsed.why);
    }
    if (!secret) {
      logger.debug("Leaving AuditExport.takeHeaders(). Replaced.");
      return { ok: true, headers: parsed.headers };
    }
    const merged: Json = Object.assign({}, prior);
    const names = Object.keys(parsed.headers);
    for (let i = 0; i < names.length; i++) {
      const name = names[i];
      const value = parsed.headers[name];
      if (!value) {
        continue;
      }
      const box = this.sealBox(value);
      if (!box) {
        logger.debug("Leaving AuditExport.takeHeaders(). Unsealed.");
        return this.refusal('STS-AUDIT-0003',
          'The secret could not be sealed.');
      }
      merged[name] = box;
    }
    logger.debug("Leaving AuditExport.takeHeaders().");
    return { ok: true, headers: merged };
  }

  /**
   * Moves a plain header whose name looks like a credential into the
   * sealed set. A name already sealed on this save is left there, and
   * the plain copy is dropped so a view cannot show the value.
   *
   * @param dest - the webhook destination
   * @returns `{ ok: true }` or a refusal
   */
  async sealSensitive(dest: Json): Promise<Json> {
    const { log: logger } = this.deps;
    logger.debug("Entering AuditExport.sealSensitive().");
    const sensitive = /authorization|token|api-key|secret/i;
    const names = Object.keys(dest.headers || {});
    for (let i = 0; i < names.length; i++) {
      const name = names[i];
      if (!sensitive.test(name)) {
        continue;
      }
      const value = dest.headers[name];
      delete dest.headers[name];
      if (!value || dest.secretHeaders[name]) {
        continue;
      }
      const box = this.sealBox(String(value));
      if (!box) {
        logger.debug("Leaving AuditExport.sealSensitive(). Unsealed.");
        return this.refusal('STS-AUDIT-0003',
          'The secret could not be sealed.');
      }
      dest.secretHeaders[name] = box;
    }
    logger.debug("Leaving AuditExport.sealSensitive().");
    return { ok: true };
  }

  /**
   * Parses `Name: value` lines.
   *
   * @param text - the textarea
   * @returns `{ ok, headers }` or `{ ok: false, why }`
   */
  static parseHeaderLines(text: unknown): Json {
    log.debug("Entering AuditExport.parseHeaderLines().");
    const headers: Json = {};
    const lines = String(text == null ? '' : text).split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line) {
        continue;
      }
      const cut = line.indexOf(':');
      if (cut <= 0) {
        log.debug("Leaving AuditExport.parseHeaderLines(). Bad line.");
        return { ok: false, why: 'A header must be "Name: value".' };
      }
      const name = line.slice(0, cut).trim();
      if (!/^[A-Za-z0-9-]{1,64}$/.test(name)) {
        log.debug("Leaving AuditExport.parseHeaderLines(). Bad name.");
        return { ok: false, why: 'A header name is not usable.' };
      }
      headers[name] = line.slice(cut + 1).trim();
    }
    log.debug("Leaving AuditExport.parseHeaderLines().");
    return { ok: true, headers: headers };
  }

  /**
   * Renders stored plain headers as lines, for a form that must send them
   * back.
   *
   * @param headers - the stored headers
   * @returns the lines
   */
  static headerText(headers: Json): string {
    log.debug("Entering AuditExport.headerText().");
    if (!headers || typeof headers !== 'object') {
      log.debug("Leaving AuditExport.headerText(). None.");
      return '';
    }
    const lines = Object.keys(headers).map(function (name) {
      return name + ': ' + headers[name];
    });
    log.debug("Leaving AuditExport.headerText().");
    return lines.join('\n');
  }

  /**
   * Copies plain headers onto a request, skipping the ones this service
   * sets itself.
   *
   * @param target - the request headers
   * @param headers - the stored headers
   */
  static copyHeaders(target: Json, headers: Json): void {
    log.debug("Entering AuditExport.copyHeaders().");
    const skip = { host: true, 'content-length': true,
                   'transfer-encoding': true, 'content-type': true,
                   'user-agent': true };
    Object.keys(headers || {}).forEach(function (name) {
      if (skip[name.toLowerCase()]) {
        return;
      }
      target[name] = String(headers[name]);
    });
    log.debug("Leaving AuditExport.copyHeaders().");
  }

  /**
   * Opens secret headers onto a request.
   *
   * @param target - the request headers
   * @param headers - the stored boxes
   */
  copySecrets(target: Json, headers: Json): void {
    const { log: logger } = this.deps;
    logger.debug("Entering AuditExport.copySecrets().");
    const self = this;
    Object.keys(headers || {}).forEach(function (name) {
      const value = self.openBox(headers[name]);
      if (value) {
        target[name] = value;
      }
    });
    logger.debug("Leaving AuditExport.copySecrets().");
  }

  /**
   * Seals a secret when the keystore persists. Development's in-memory
   * keystore stores the box unsealed; a view still does not return it.
   *
   * @param plain - the secret
   * @returns the box, or null when sealing was required and failed
   */
  sealBox(plain: string): Json | null {
    const { log: logger, keystore: keys } = this.deps;
    logger.debug("Entering AuditExport.sealBox().");
    if (keys.persists()) {
      const sealed = keys.seal(String(plain), SECRET_LABEL);
      if (!sealed) {
        logger.debug("Leaving AuditExport.sealBox(). Refused.");
        return null;
      }
      logger.debug("Leaving AuditExport.sealBox(). Sealed.");
      return { sealed: true, value: sealed };
    }
    logger.debug("Leaving AuditExport.sealBox(). In memory.");
    return { sealed: false, value: String(plain) };
  }

  /**
   * Opens a secret box. A failure is an empty string, not a throw, and
   * the ciphertext is not logged.
   *
   * @param box - the stored box
   * @returns the plaintext, or ''
   */
  openBox(box: Json): string {
    const { log: logger, keystore: keys } = this.deps;
    logger.debug("Entering AuditExport.openBox().");
    if (!box) {
      logger.debug("Leaving AuditExport.openBox(). None.");
      return '';
    }
    if (box.sealed) {
      const opened = keys.open(box.value, SECRET_LABEL);
      logger.debug("Leaving AuditExport.openBox(). " +
        (opened == null ? 'Unopened.' : 'Opened.'));
      return opened == null ? '' : String(opened);
    }
    logger.debug("Leaving AuditExport.openBox(). In memory.");
    return String(box.value || '');
  }

  /**
   * The destination as a page may show it. No secret value.
   *
   * @param dest - the stored destination
   * @returns the public copy
   */
  publicDest(dest: Json): Json {
    const { log: logger } = this.deps;
    logger.debug("Entering AuditExport.publicDest().");
    const copy = Object.assign({}, dest);
    copy.tokenSet = !!(dest.token && (dest.token.sealed ||
      dest.token.value));
    delete copy.token;
    const secretNames = Object.keys(dest.secretHeaders || {});
    copy.secretHeaderSet = secretNames;
    delete copy.secretHeaders;
    if (typeof copy.headers !== 'string') {
      copy.headerText = AuditExport.headerText(copy.headers);
    }
    logger.debug("Leaving AuditExport.publicDest().");
    return copy;
  }

  /**
   * The page's model: destinations, this process's counters, and the
   * queue each cursor still has. Figures are this process only.
   *
   * @returns the model
   */
  view(): Json {
    const { log: logger, config: cfg } = this.deps;
    logger.debug("Entering AuditExport.view().");
    const rows = this.localRows();
    const now = Date.now();
    const self = this;
    const destinations: Json[] = [];
    this.deps.destinations.forEach(function (dest: Json, id: string): void {
      const cursor = self.readCursor(String(id));
      const depth = AuditExport.queueDepth(cursor, rows);
      const status = !dest.enabled ? 'disabled'
        : (cursor.pausedUntil > now ? 'paused'
          : (cursor.failingSince ? 'failing' : 'healthy'));
      destinations.push(Object.assign(self.publicDest(dest), {
        status: status,
        queueDepth: depth,
        delivered: cursor.delivered,
        failedPermanent: cursor.failedPermanent,
        droppedGap: cursor.droppedGap,
        retries: cursor.retries,
        lastSuccessAt: cursor.lastSuccessAt,
        lastFailureAt: cursor.lastFailureAt,
        lastFailure: cursor.lastFailure,
        lastDisposition: cursor.lastDisposition,
        pausedUntil: cursor.pausedUntil,
        failingSince: cursor.failingSince,
        latencyMs: cursor.latencyMs,
        cursorSeq: cursor.seq,
        primed: cursor.primed
      }));
    });
    destinations.sort(function (a: Json, b: Json) {
      return String(a.id).localeCompare(String(b.id));
    });
    let delivered = 0;
    let awaiting = 0;
    let retrying = 0;
    let permanentlyFailed = 0;
    let dropped = 0;
    let latencyTotal = 0;
    let latencyCount = 0;
    let enabled = 0;
    let healthy = 0;
    destinations.forEach(function (row: Json): void {
      delivered += row.delivered;
      awaiting += row.queueDepth;
      permanentlyFailed += row.failedPermanent;
      dropped += row.droppedGap;
      if (row.latencyMs) {
        latencyTotal += row.latencyMs;
        latencyCount += 1;
      }
      if (row.enabled) {
        enabled += 1;
        if (!row.failingSince) {
          healthy += 1;
        }
        if (row.pausedUntil > now || row.failingSince) {
          retrying += 1;
        }
      }
    });
    logger.debug("Leaving AuditExport.view().");
    return {
      thisProcess: true,
      enabled: !!cfg.value('auditExport.enabled'),
      job: { id: JOB_ID, kind: 'per-process', scope: 'realm' },
      destinations: destinations,
      stats: {
        delivered: delivered,
        awaiting: awaiting,
        retrying: retrying,
        permanentlyFailed: permanentlyFailed,
        dropped: dropped,
        latencyMs: latencyCount
          ? Math.round(latencyTotal / latencyCount) : 0,
        availability: enabled ? healthy / enabled : 1,
        generated: delivered + awaiting + dropped + permanentlyFailed
      }
    };
  }

  /**
   * How many of this process's rows are still ahead of the cursor.
   * An unprimed cursor counts the whole ring, which is what the first
   * enable will backfill.
   *
   * @param cursor - the cursor
   * @param rows - the ring
   * @returns the depth
   */
  static queueDepth(cursor: Cursor, rows: Json[]): number {
    log.debug("Entering AuditExport.queueDepth().");
    let floor = cursor.seq;
    if (!cursor.primed) {
      floor = rows.length ? Number(rows[0].seq) - 1 : 0;
    }
    let depth = 0;
    for (let i = 0; i < rows.length; i++) {
      if (Number(rows[i].seq) > floor && !AuditExport.skipped(rows[i])) {
        depth += 1;
      }
    }
    log.debug("Leaving AuditExport.queueDepth(). " + depth);
    return depth;
  }

  /**
   * Records a configuration change. The detail is the type and whether
   * it is enabled. The address is not a detail: a URL can carry a token.
   *
   * @param action - the audit action
   * @param dest - the destination
   */
  changed(action: string, dest: Json): void {
    const { log: logger, audit: auditLog } = this.deps;
    logger.debug("Entering AuditExport.changed(). " + action);
    auditLog.audit({
      action: action,
      target: dest.id,
      outcome: 'success',
      summary: 'Audit export destination ' + dest.id + ' ' +
        (VERBS[action] || 'changed') + '.',
      detail: { type: dest.type, enabled: !!dest.enabled }
    });
    logger.debug("Leaving AuditExport.changed().");
  }

  /**
   * A marked refusal. The code is on the result, and the API marks the
   * response from it.
   *
   * @param code - the error code
   * @param why - the sentence a person can read
   * @returns `{ ok: false, errors }`
   */
  refusal(code: string, why: string): Json {
    const { log: logger, errorCodes: codes } = this.deps;
    logger.debug("Entering AuditExport.refusal().");
    logger.debug("Leaving AuditExport.refusal().");
    return codes.mark({ ok: false, errors: [why] }, code);
  }

  /**
   * Checks a filesystem path: absolute, no `..`, and under the configured
   * roots when there are any.
   *
   * @param raw - the submitted path
   * @returns `{ ok, path }` or `{ ok: false, why }`
   */
  checkPath(raw: unknown): Json {
    const { log: logger, path: paths, config: cfg } = this.deps;
    logger.debug("Entering AuditExport.checkPath().");
    const text = String(raw == null ? '' : raw);
    if (!text || text.indexOf('\0') >= 0 || !paths.isAbsolute(text)) {
      logger.debug("Leaving AuditExport.checkPath(). Not absolute.");
      return { ok: false,
               why: 'The path must be absolute.' };
    }
    if (text.split(/[\\/]/).indexOf('..') >= 0) {
      logger.debug("Leaving AuditExport.checkPath(). Climbs.");
      return { ok: false,
               why: 'The path climbs out of its directory.' };
    }
    const resolved = paths.resolve(text);
    const roots = String(cfg.value('auditExport.fileRoots') || '')
      .split(',').map(function (one: string) {
        return one.trim();
      }).filter(function (one: string) {
        return !!one;
      });
    if (roots.length) {
      const under = roots.some(function (root: string) {
        const base = paths.resolve(root);
        return resolved === base ||
          resolved.startsWith(base + paths.sep);
      });
      if (!under) {
        logger.debug("Leaving AuditExport.checkPath(). Outside roots.");
        return { ok: false,
                 why: 'The path is outside the allowed filesystem roots.' };
      }
    }
    logger.debug("Leaving AuditExport.checkPath().");
    return { ok: true, path: resolved };
  }

  /**
   * Checks a syslog host. At save time a DNS failure is not a refusal.
   * At send time it is, and every answer is checked again.
   *
   * @param host - the host
   * @param atSend - whether this is a delivery
   * @returns `{ ok, addresses }` or a refusal
   */
  async screenHost(host: string, atSend: boolean): Promise<Json> {
    const { log: logger } = this.deps;
    logger.debug("Entering AuditExport.screenHost().");
    const bare = AuditExport.bareHost(host);
    if (!bare || bare.length > 255 || /[\s@/\\]/.test(bare)) {
      logger.debug("Leaving AuditExport.screenHost(). Unusable.");
      return { ok: false, code: 'STS-AUDIT-0001',
               why: 'The host is not usable.', addresses: [] };
    }
    if (AuditExport.isMetadata(bare)) {
      logger.debug("Leaving AuditExport.screenHost(). Metadata.");
      return { ok: false, code: 'STS-AUDIT-0005',
               why: 'Cloud metadata addresses are refused.', addresses: [] };
    }
    let addresses: string[] = [];
    let looked = false;
    try {
      const answers = await this.deps.dns.lookup(bare, {
        all: true, verbatim: true
      });
      looked = true;
      addresses = (answers || []).map(function (one: Json) {
        return String(one.address || '');
      });
    } catch (e) {
      logger.debug("Caught in AuditExport.screenHost(): " +
        ((e && e.message) || e));
      if (atSend) {
        logger.debug("Leaving AuditExport.screenHost(). Unresolved.");
        return { ok: false, code: 'STS-AUDIT-0005',
                 why: 'The host could not be resolved.', addresses: [] };
      }
      addresses = [];
    }
    if (atSend && addresses.length === 0) {
      logger.debug("Leaving AuditExport.screenHost(). No address.");
      return { ok: false, code: 'STS-AUDIT-0005',
               why: 'The host could not be resolved.', addresses: [] };
    }
    const denied = this.addressDenied(bare, looked ? addresses : null,
                                       atSend);
    if (denied) {
      logger.debug("Leaving AuditExport.screenHost(). Denied.");
      return { ok: false, code: 'STS-AUDIT-0005', why: denied,
               addresses: [] };
    }
    logger.debug("Leaving AuditExport.screenHost().");
    return { ok: true, addresses: addresses.length ? addresses : [bare] };
  }

  /**
   * Checks a webhook or collector URL.
   *
   * @param raw - the URL
   * @param atSend - whether this is a delivery
   * @returns `{ ok, url, addresses }` or a refusal
   */
  async screenUrl(raw: string, atSend: boolean): Promise<Json> {
    const { log: logger, outbound, mode: modeMod } = this.deps;
    logger.debug("Entering AuditExport.screenUrl().");
    let url: URL;
    try {
      url = new URL(String(raw || ''));
    } catch (e) {
      logger.debug("Caught in AuditExport.screenUrl(): " +
        ((e && e.message) || e));
      logger.debug("Leaving AuditExport.screenUrl(). Unusable.");
      return { ok: false, code: 'STS-AUDIT-0001',
               why: 'The URL is not usable.' };
    }
    if (url.username || url.password) {
      logger.debug("Leaving AuditExport.screenUrl(). Userinfo.");
      return { ok: false, code: 'STS-AUDIT-0005',
               why: 'The URL must not carry user information.' };
    }
    if (url.protocol !== 'https:' && url.protocol !== 'http:') {
      logger.debug("Leaving AuditExport.screenUrl(). Scheme.");
      return { ok: false, code: 'STS-AUDIT-0005',
               why: 'The URL must be http or https.' };
    }
    if (url.protocol === 'http:') {
      const verdict = outbound.httpVerdict(FAMILY, url.hostname);
      if (!verdict.ok) {
        logger.debug("Leaving AuditExport.screenUrl(). HTTP.");
        return { ok: false, code: verdict.errorCode || 'STS-AUDIT-0005',
                 why: 'Plain http is not allowed for this destination.' };
      }
      // The verdict allows development. Say so at the call, once per
      // save, without quoting the URL.
      if (modeMod.dialsPlainHttpOutbound()) {
        logger.debug("Audit export will use plain http in development.");
      }
    }
    const host = await this.screenHost(url.hostname, atSend);
    if (!host.ok) {
      logger.debug("Leaving AuditExport.screenUrl(). Host.");
      return host;
    }
    logger.debug("Leaving AuditExport.screenUrl().");
    return { ok: true, url: url, addresses: host.addresses };
  }

  /**
   * Why a host or its answers are refused, or ''.
   *
   * Metadata is always refused. Other private addresses need
   * `auditExport.allowPrivateDestinations`, except development's
   * loopback, which a test listener uses.
   *
   * @param host - the bare host
   * @param addresses - the resolved addresses, or null when DNS failed
   *   at save time
   * @param atSend - whether this is a delivery
   * @returns the sentence, or ''
   */
  addressDenied(host: string, addresses: string[] | null,
                atSend: boolean): string {
    const { log: logger, config: cfg, mode: modeMod, outbound } = this.deps;
    logger.debug("Entering AuditExport.addressDenied().");
    if (AuditExport.isMetadata(host) ||
        (addresses || []).some(function (one) {
          return AuditExport.isMetadata(one);
        })) {
      logger.debug("Leaving AuditExport.addressDenied(). Metadata.");
      return 'Cloud metadata addresses are refused.';
    }
    const literalPrivate = outbound.isLoopbackHost(host) ||
      AuditExport.isPrivate(host);
    const answerPrivate = (addresses || []).some(function (one) {
      return outbound.isLoopbackHost(one) || AuditExport.isPrivate(one);
    });
    if (!literalPrivate && !answerPrivate) {
      logger.debug("Leaving AuditExport.addressDenied(). Public.");
      return '';
    }
    if (cfg.value('auditExport.allowPrivateDestinations')) {
      logger.debug("Leaving AuditExport.addressDenied(). Allowed.");
      return '';
    }
    const answers = addresses || [];
    const allLoop = answers.length > 0 && answers.every(function (one) {
      return outbound.isLoopbackHost(one);
    });
    if (modeMod.dialsPlainHttpOutbound() && outbound.isLoopbackHost(host) &&
        (!atSend || allLoop)) {
      logger.debug("Leaving AuditExport.addressDenied(). Loopback.");
      return '';
    }
    logger.debug("Leaving AuditExport.addressDenied(). Private.");
    return 'Private and loopback addresses are refused.';
  }

  /**
   * A host with brackets, a trailing dot and a zone id removed.
   *
   * @param host - the host
   * @returns the bare host
   */
  static bareHost(host: unknown): string {
    log.debug("Entering AuditExport.bareHost().");
    const bare = String(host || '').trim().replace(/^\[|\]$/g, '')
      .replace(/%.*$/, '').replace(/\.$/, '').toLowerCase();
    log.debug("Leaving AuditExport.bareHost().");
    return bare;
  }

  /**
   * Tells whether a host is a cloud metadata name or the metadata address.
   *
   * @param host - the bare host or address
   * @returns true for metadata
   */
  static isMetadata(host: string): boolean {
    log.debug("Entering AuditExport.isMetadata().");
    const name = AuditExport.bareHost(host);
    const names = ['metadata.google.internal', 'metadata.azure.com',
      'instance-data', 'instance-data.ec2.internal'];
    for (let i = 0; i < names.length; i++) {
      if (name === names[i] || name.endsWith('.' + names[i])) {
        log.debug("Leaving AuditExport.isMetadata(). Yes.");
        return true;
      }
    }
    const v4 = AuditExport.ipv4Of(name);
    if (v4 && v4[0] === 169 && v4[1] === 254 && v4[2] === 169 &&
        v4[3] === 254) {
      log.debug("Leaving AuditExport.isMetadata(). Address.");
      return true;
    }
    log.debug("Leaving AuditExport.isMetadata(). No.");
    return false;
  }

  /**
   * Tells whether an address is loopback, link-local, private, or
   * unspecified. Names that are not addresses are false; the caller
   * checks those through DNS and `isLoopbackHost`.
   *
   * @param host - the address
   * @returns true for a private address
   */
  static isPrivate(host: string): boolean {
    log.debug("Entering AuditExport.isPrivate().");
    const name = AuditExport.bareHost(host);
    const v4 = AuditExport.ipv4Of(name);
    if (v4) {
      const a = v4[0];
      const b = v4[1];
      const priv = a === 0 || a === 10 || a === 127 ||
        (a === 169 && b === 254) ||
        (a === 172 && b >= 16 && b <= 31) ||
        (a === 192 && b === 168) ||
        // RFC 6598 carrier-grade NAT, treated as private.
        (a === 100 && b >= 64 && b <= 127);
      log.debug("Leaving AuditExport.isPrivate(). " + priv);
      return priv;
    }
    if (name.indexOf(':') < 0) {
      log.debug("Leaving AuditExport.isPrivate(). Not an address.");
      return false;
    }
    const bytes = AuditExport.ipv6Bytes(name);
    if (!bytes) {
      log.debug("Leaving AuditExport.isPrivate(). Unparsed.");
      return false;
    }
    const mapped = AuditExport.mappedV4(bytes);
    if (mapped) {
      log.debug("Leaving AuditExport.isPrivate(). Mapped.");
      return AuditExport.isPrivate(mapped);
    }
    const allZero = bytes.every(function (one) {
      return one === 0;
    });
    const loop = allZero === false && bytes[15] === 1 &&
      bytes.slice(0, 15).every(function (one) {
        return one === 0;
      });
    // fc00::/7 and fe80::/10.
    const ula = (bytes[0] & 0xfe) === 0xfc;
    const link = bytes[0] === 0xfe && (bytes[1] & 0xc0) === 0x80;
    log.debug("Leaving AuditExport.isPrivate().");
    return allZero || loop || ula || link;
  }

  /**
   * Parses an IPv4 address, including an IPv4-mapped IPv6 literal.
   *
   * @param host - the bare host
   * @returns four octets, or null
   */
  static ipv4Of(host: string): number[] | null {
    log.debug("Entering AuditExport.ipv4Of().");
    const mapped = host.startsWith('::ffff:') ? host.slice(7) : host;
    const parts = mapped.split('.');
    if (parts.length !== 4) {
      log.debug("Leaving AuditExport.ipv4Of(). No.");
      return null;
    }
    const nums = parts.map(function (part) {
      if (!/^\d{1,3}$/.test(part)) {
        return -1;
      }
      return Number(part);
    });
    if (nums.some(function (n) {
      return n < 0 || n > 255;
    })) {
      log.debug("Leaving AuditExport.ipv4Of(). Range.");
      return null;
    }
    log.debug("Leaving AuditExport.ipv4Of(). Yes.");
    return nums;
  }

  /**
   * Tells whether a host is an IP address.
   *
   * @param host - the bare host
   * @returns true for an address
   */
  static isIp(host: string): boolean {
    log.debug("Entering AuditExport.isIp().");
    const ip = !!AuditExport.ipv4Of(host) || host.indexOf(':') >= 0;
    log.debug("Leaving AuditExport.isIp(). " + ip);
    return ip;
  }

  /**
   * Expands an IPv6 address to 16 bytes.
   *
   * @param host - the bare address
   * @returns the bytes, or null
   */
  static ipv6Bytes(host: string): number[] | null {
    log.debug("Entering AuditExport.ipv6Bytes().");
    const text = host.split('%')[0];
    if (text.indexOf(':') < 0) {
      log.debug("Leaving AuditExport.ipv6Bytes(). No.");
      return null;
    }
    const halves = text.split('::');
    if (halves.length > 2) {
      log.debug("Leaving AuditExport.ipv6Bytes(). Two gaps.");
      return null;
    }
    const parse = function (side: string): number[] | null {
      if (!side) {
        return [];
      }
      const groups = side.split(':');
      const out: number[] = [];
      for (let i = 0; i < groups.length; i++) {
        if (groups[i].indexOf('.') >= 0) {
          const v4 = AuditExport.ipv4Of(groups[i]);
          if (!v4) {
            return null;
          }
          out.push((v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]);
          continue;
        }
        if (!/^[0-9a-f]{1,4}$/i.test(groups[i])) {
          return null;
        }
        out.push(parseInt(groups[i], 16));
      }
      return out;
    };
    const left = parse(halves[0]);
    const right = halves.length === 2 ? parse(halves[1]) : [];
    if (!left || !right) {
      log.debug("Leaving AuditExport.ipv6Bytes(). Unparsed.");
      return null;
    }
    const missing = 8 - left.length - right.length;
    if (halves.length === 1 && missing !== 0) {
      log.debug("Leaving AuditExport.ipv6Bytes(). Short.");
      return null;
    }
    if (halves.length === 2 && missing < 0) {
      log.debug("Leaving AuditExport.ipv6Bytes(). Long.");
      return null;
    }
    const groups = left.concat(new Array(missing < 0 ? 0 : missing)
      .fill(0), right);
    if (groups.length !== 8) {
      log.debug("Leaving AuditExport.ipv6Bytes(). Length.");
      return null;
    }
    const bytes: number[] = [];
    groups.forEach(function (group) {
      bytes.push((group >> 8) & 0xff, group & 0xff);
    });
    log.debug("Leaving AuditExport.ipv6Bytes().");
    return bytes;
  }

  /**
   * The IPv4 address inside an IPv4-mapped IPv6 address, or ''.
   *
   * @param bytes - 16 bytes
   * @returns the dotted address, or ''
   */
  static mappedV4(bytes: number[]): string {
    log.debug("Entering AuditExport.mappedV4().");
    const prefix = bytes.slice(0, 10).every(function (one) {
      return one === 0;
    }) && bytes[10] === 0xff && bytes[11] === 0xff;
    if (!prefix) {
      log.debug("Leaving AuditExport.mappedV4(). No.");
      return '';
    }
    log.debug("Leaving AuditExport.mappedV4(). Yes.");
    return bytes.slice(12).join('.');
  }

  /**
   * The transport, defaulting to TCP. An unknown value is UDP only when
   * the stored field itself says udp; a missing field is TCP.
   *
   * @param dest - the destination
   * @returns udp, tcp or tls
   */
  static transportOf(dest: Json): string {
    log.debug("Entering AuditExport.transportOf().");
    const transport = String((dest && dest.transport) || 'tcp');
    log.debug("Leaving AuditExport.transportOf().");
    if (transport === 'udp' || transport === 'tls') {
      return transport;
    }
    return 'tcp';
  }

  /**
   * The port, or 6514 for TLS and 514 otherwise.
   *
   * @param dest - the destination
   * @returns the port
   */
  static portOf(dest: Json): number {
    log.debug("Entering AuditExport.portOf().");
    const given = Number(dest && dest.port) || 0;
    if (given > 0) {
      log.debug("Leaving AuditExport.portOf(). Given.");
      return given;
    }
    const port = AuditExport.transportOf(dest) === 'tls' ? 6514 : 514;
    log.debug("Leaving AuditExport.portOf(). Default.");
    return port;
  }

  /**
   * Parses a file mode. `640` and `"640"` are octal digits. Empty is
   * `0o640`.
   *
   * @param value - the submitted mode
   * @returns the mode, or -1 when it is not usable
   */
  static parseMode(value: unknown): number {
    log.debug("Entering AuditExport.parseMode().");
    if (value === undefined || value === null || value === '' ||
        value === 0) {
      log.debug("Leaving AuditExport.parseMode(). Default.");
      return 0o640;
    }
    const text = String(value).trim();
    if (!text || text === '0') {
      log.debug("Leaving AuditExport.parseMode(). Default.");
      return 0o640;
    }
    if (!/^0?[0-7]{3}$/.test(text)) {
      log.debug("Leaving AuditExport.parseMode(). Refused.");
      return -1;
    }
    log.debug("Leaving AuditExport.parseMode().");
    return parseInt(text, 8);
  }

  /**
   * A sentence safe to store: no URL, no newline, cut at 300 characters.
   *
   * @param text - the raw sentence
   * @returns the stored sentence
   */
  static safeWhy(text: unknown): string {
    log.debug("Entering AuditExport.safeWhy().");
    const cleaned = String(text || '')
      .replace(/https?:\/\/\S+/gi, '[url]')
      .replace(/[\r\n\t]+/g, ' ').trim();
    const out = cleaned.length > 300
      ? cleaned.slice(0, 297) + '...' : cleaned;
    log.debug("Leaving AuditExport.safeWhy().");
    return out;
  }

  /**
   * The key of this process's file handle for a destination.
   *
   * @param id - the destination id
   * @returns the key
   */
  fileKey(id: string): string {
    const { log: logger, realms: realmBook } = this.deps;
    logger.debug("Entering AuditExport.fileKey().");
    logger.debug("Leaving AuditExport.fileKey().");
    return String(realmBook.currentId()) + '\0' + id;
  }

  /**
   * Closes one destination's file handle.
   *
   * @param id - the destination id
   */
  closeFile(id: string): void {
    const { log: logger } = this.deps;
    logger.debug("Entering AuditExport.closeFile().");
    const key = this.fileKey(id);
    const held = this.files.get(key);
    this.files.delete(key);
    if (held) {
      this.closeHeld(held);
    }
    logger.debug("Leaving AuditExport.closeFile().");
  }

  /**
   * Closes a held file. A failure is logged and swallowed: the handle is
   * already forgotten.
   *
   * @param held - `{ fh }`
   */
  async closeHeld(held: Json): Promise<void> {
    const { log: logger } = this.deps;
    logger.debug("Entering AuditExport.closeHeld().");
    try {
      if (held && held.fh) {
        await held.fh.close();
      }
    } catch (e) {
      logger.debug("Caught in AuditExport.closeHeld(): " +
        ((e && e.message) || e));
    }
    logger.debug("Leaving AuditExport.closeHeld().");
  }

  /**
   * Closes the tick's syslog socket.
   *
   * @param pipe - `{ socket }`
   */
  closePipe(pipe: Json): void {
    const { log: logger } = this.deps;
    logger.debug("Entering AuditExport.closePipe().");
    if (pipe && pipe.socket) {
      try {
        pipe.socket.end();
        pipe.socket.destroy();
      } catch (e) {
        logger.debug("Caught in AuditExport.closePipe(): " +
          ((e && e.message) || e));
      }
      pipe.socket = null;
    }
    logger.debug("Leaving AuditExport.closePipe().");
  }

  /**
   * Forgets every destination, cursor and file handle. Tests use it.
   * The job registration stays.
   *
   * @returns a promise that settles when the handles are closed
   */
  async resetForTests(): Promise<void> {
    const { log: logger, realms: realmBook, destinations, cursors } =
      this.deps;
    logger.debug("Entering AuditExport.resetForTests().");
    const ids = realmBook.list().map(function (one: Json) {
      return one.id;
    });
    if (ids.indexOf(realmBook.DEFAULT_ID) < 0) {
      ids.push(realmBook.DEFAULT_ID);
    }
    ids.forEach(function (id: string): void {
      AuditExport.clearMap(destinations.realmMap(id));
      AuditExport.clearMap(cursors.realmMap(id));
    });
    const closing: Promise<void>[] = [];
    const self = this;
    this.files.forEach(function (held: Json): void {
      closing.push(self.closeHeld(held));
    });
    this.files.clear();
    await Promise.all(closing);
    logger.debug("Leaving AuditExport.resetForTests().");
  }

  /**
   * Deletes every key of a map.
   *
   * @param map - the realm's map
   */
  static clearMap(map: Json): void {
    log.debug("Entering AuditExport.clearMap().");
    const keys: string[] = [];
    map.forEach(function (_value: Json, key: string): void {
      keys.push(key);
    });
    keys.forEach(function (key) {
      map.delete(key);
    });
    log.debug("Leaving AuditExport.clearMap().");
  }
}

const slot = new InstanceSlot<AuditExport>(
  'common/audit_export',
  function (): AuditExport {
    return new AuditExport(AuditExport.defaultDeps());
  },
  function (instance: AuditExport): void {
    instance.registerJobs();
  },
  log);

slot.buildNowUnlessDeferred();

/**
 * Audit export (#641).
 *
 * The functions forward to the instance the composition root installs.
 * @namespace
 */
export = {
  AuditExport: AuditExport,
  JOB_ID: JOB_ID,
  /**
   * Installs the instance the composition root built.
   *
   * Installing twice, or after a default was built, is refused.
   * @param instance - the instance
   */
  installInstance: function (instance: AuditExport): void {
    slot.install(instance);
  },
  /**
   * Says where the instance came from.
   *
   * @returns `root`, `default` or `none`
   */
  instanceOrigin: function (): string {
    return slot.origin();
  },
  registerJobs: slot.forward('registerJobs'),
  runAsync: slot.forward('runAsync'),
  act: slot.forward('act'),
  view: slot.forward('view'),
  resetForTests: slot.forward('resetForTests')
};
