// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: cell_deliveries.ts
//
// ---------------------------------------------------------------------------
// WHAT ONE CELL MUST TELL ANOTHER AND MAY NOT LOSE (#98 D6, 2026-09-28).
//
// A revocation pushed from a person's home to the cells holding their
// exported session, a projection that changed there: a direct call over the
// inter-cell channel is lost when the other cell is down at that moment, and
// "it finds out at its next check" is a bound (`cells.subjectCheckS`), not a
// delivery. So each of these is a ROW of the service's one durable outbound
// queue (`oauth-oidc/outbound_delivery.ts`) — persisted, sent once for the
// cluster by a claimed attempt, retried with a doubling backoff by any node
// across restarts, dead-lettered after `cells.deliveryAttempts`, and retried
// by hand from /admin/deliveries — whose TRANSPORT is the channel
// (`send()`) rather than the public outbound policy: a peer cell is a
// private address the policy's internal-address refusal exists to refuse.
//
// The row names a cell, an operation and a body — never an address; the
// channel resolves the cell (`cells.peers`). What it carries is what the
// operation needs: a realm, an entryUUID, a reason, or a credential-free
// projection. Sealed at rest under this cell's key like every cell-tier row
// (`cells.deliveries`).
//
// A LIBRARY: no route. Its sweep job is registered when the store is first
// used (`scheduleSweep()`).
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
import realms = require('./realms');
import errorCodes = require('./error_codes');
import outbound = require('../oauth-oidc/outbound_delivery');

const log = bunyan.createLogger({ name: 'sts-cell-deliveries' });

// Per realm, persisted, tombstoned and merged the queue's way.
const deliveries = realms.map({ persist: 'cells.deliveries',
                                tombstone: true,
                                mergeRow: outbound.mergeRow });

// The claim scope of an attempt.
const ATTEMPT_SCOPE = 'cells.delivery-attempt';

/**
 * The durable deliveries of inter-cell operations.
 */
class CellDeliveries {
  private readonly outbox: any;
  private swept = false;

  /**
   * Builds the kind over the shared outbound queue.
   */
  constructor() {
    log.debug("Entering CellDeliveries.constructor().");
    this.outbox = new outbound.OutboundDelivery({
      label: 'inter-cell delivery',
      store: deliveries,
      attemptScope: ATTEMPT_SCOPE,
      attribute: 'cell',
      body: 'json',
      settings: {
        attempts: 'cells.deliveryAttempts',
        timeoutMs: 'cells.relayTimeoutMs',
        backoffMs: 'cells.deliveryBackoffMs',
        retentionS: 'cells.deliveryRetentionS',
        maxRows: 'cells.deliveryMaxRows',
        concurrency: 'cells.deliveryConcurrency',
        summaryS: 'cells.deliverySummaryS'
      },
      codes: {
        outboundOff: 'STS-CELL-0060', url: 'STS-CELL-0061',
        internal: 'STS-CELL-0061', unresolved: 'STS-CELL-0061',
        redirect: 'STS-CELL-0061', build: 'STS-CELL-0062',
        timeout: 'STS-CELL-0063', network: 'STS-CELL-0063',
        status400: 'STS-CELL-0064', status: 'STS-CELL-0064',
        deferred: 'STS-CELL-0065', stale: 'STS-CELL-0066',
        summary: 'STS-CELL-0067', sweepFailed: 'STS-CELL-0068',
        retry: 'STS-CELL-0069'
      },
      deadLetterHint: 'Dead letters are listed on /admin/deliveries and ' +
        'retried from there.',
      prepare: function (row: any): Promise<any> {
        return Promise.resolve({ body: row.body || {} });
      },
      // THE TRANSPORT: the channel's call, with its answer translated into
      // what the queue's classification reads — an unreachable cell and a
      // timeout are worth another attempt, an operation the other cell
      // refused is final.
      send: function (row: any): Promise<any> {
        log.debug("Entering the inter-cell delivery's send().");
        return require('./cell_channel').call(String(row.cell),
                                              String(row.op), row.body || {})
          .then(function () {
            log.debug("Leaving the inter-cell delivery's send(). Sent.");
            return { ok: true, status: 200 };
          }, function (err: any) {
            const why = String((err && err.message) || err);
            log.debug("Leaving the inter-cell delivery's send(). " + why);
            const refused = /answered (4\d\d)/.exec(why);
            return refused
              ? { ok: false, kind: 'status', status: Number(refused[1]),
                  why: why }
              : { ok: false, kind: /timed out/.test(why) ? 'timeout'
                                                          : 'network',
                  status: 0, why: why };
          });
      },
      onFinish: function (row: any, state: string, code: string,
                          why: string): void {
        if (state === 'dead') {
          log.warn(errorCodes.tag(code || 'STS-CELL-0064') + 'cells: "' +
                   row.op + '" to cell "' + row.cell + '" was given up: ' +
                   why + '. /admin/deliveries retries it.');
        }
      },
      viewExtra: function (row: any): any {
        return { cell: row.cell, op: row.op };
      },
      searchText: function (row: any): string {
        return String(row.cell || '') + ' ' + String(row.op || '');
      },
      sweepJob: {
        id: 'cells.delivery-sweep',
        title: 'Inter-cell delivery sweep',
        describe: 'Attempts every inter-cell delivery that is due — a ' +
                  'revocation or a changed projection a person\'s home ' +
                  'owes the cells holding their session — dead-letters one ' +
                  'still pending past cells.deliveryRetentionS, and drops ' +
                  'what finished more than an hour ago.',
        owner: 'common/cell_deliveries.ts',
        everySetting: 'cells.deliverySweepS'
      }
    }, outbound.OutboundDelivery.defaultDeps());
    log.debug("Leaving CellDeliveries.constructor().");
  }

  /**
   * Queues an operation for another cell, durably, and tries it now.
   *
   * @param cellId - the cell
   * @param op - the operation name
   * @param body - its body (JSON)
   * @returns the queued row
   */
  deliver(cellId: string, op: string, body: any): any {
    log.debug("Entering CellDeliveries.deliver(). " + op + " -> " + cellId);
    if (!this.swept) {
      this.swept = true;
      this.outbox.scheduleSweep();
    }
    const queued = this.outbox.queue({
      cell: String(cellId), op: String(op), body: body || {},
      clientId: 'cell:' + String(cellId), uri: 'cell:' + String(cellId)
    });
    this.outbox.dispatch([queued.row]).catch(function (e: any) {
      log.debug("Caught in CellDeliveries.deliver(): " +
                ((e && e.message) || e));
    });
    log.debug("Leaving CellDeliveries.deliver().");
    return queued.row;
  }

  /**
   * The rows, for /admin/deliveries.
   *
   * @param options - the queue's list options
   * @returns the rows, newest first
   */
  rows(options: any): any[] {
    log.debug("Entering CellDeliveries.rows().");
    log.debug("Leaving CellDeliveries.rows().");
    return this.outbox.rows(options);
  }

  /**
   * The counts by state, for /admin/deliveries.
   *
   * @returns the counts
   */
  counts(): any {
    log.debug("Entering CellDeliveries.counts().");
    log.debug("Leaving CellDeliveries.counts().");
    return this.outbox.counts();
  }

  /**
   * Retries a dead letter, for /admin/deliveries.
   *
   * @param id - the delivery id
   * @param actor - who asked
   * @returns the queue's answer
   */
  retry(id: string, actor: string): any {
    log.debug("Entering CellDeliveries.retry().");
    log.debug("Leaving CellDeliveries.retry().");
    return this.outbox.retry(id, actor, 'inter-cell delivery');
  }
}

const cellDeliveries = new CellDeliveries();

/**
 * Durable inter-cell operations over the shared outbound queue (#98). A
 * library: no route.
 * @namespace
 */
export = {
  CellDeliveries: CellDeliveries,
  deliver: (cellId: string, op: string, body: any): any =>
    cellDeliveries.deliver(cellId, op, body),
  rows: (options: any): any[] => cellDeliveries.rows(options),
  counts: (): any => cellDeliveries.counts(),
  retry: (id: string, actor: string): any => cellDeliveries.retry(id, actor)
};
