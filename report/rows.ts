// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: rows.ts
//
// ---------------------------------------------------------------------------
// WHAT A QUERY KEEPS (#956).
//
// A bounded source can honour a limit without holding the population. With
// no order and no count, matching stops at the limit. With an order, a heap
// of that size keeps the rows that sort first and drops the rest as they
// are seen. A count keeps one number per group and drops the row. Nothing
// here returns a partial body: the caller refuses when the clock or the
// byte cap says the result will not fit.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'sts-report-rows' });

interface Plan {
  source: string;
  select: string[];
  where: any;
  orderBy: Array<{ field: string; dir: string }>;
  limit: number;
  aggregate: string | null;
  groupBy: string[];
  fields: string[];
}

type Row = Record<string, unknown>;

function stamp(value: unknown): number | null {
  log.debug("Entering stamp().");
  if (typeof value === 'number' && Number.isFinite(value)) {
    log.debug("Leaving stamp(). Number.");
    return value;
  }
  if (typeof value === 'string' && Number.isFinite(Date.parse(value))) {
    log.debug("Leaving stamp(). String.");
    return Date.parse(value);
  }
  log.debug("Leaving stamp(). None.");
  return null;
}

function same(type: string, left: unknown, right: unknown): boolean {
  log.debug("Entering same().");
  if (type === 'timestamp') {
    const a = stamp(left);
    const b = stamp(right);
    log.debug("Leaving same(). Timestamp.");
    return a != null && b != null && a === b;
  }
  log.debug("Leaving same().");
  return left === right;
}

function before(type: string, left: unknown, right: unknown): boolean {
  log.debug("Entering before().");
  if (type === 'timestamp') {
    const a = stamp(left);
    const b = stamp(right);
    log.debug("Leaving before(). Timestamp.");
    return a != null && b != null && a < b;
  }
  if (typeof left === 'number' && typeof right === 'number') {
    log.debug("Leaving before(). Number.");
    return left < right;
  }
  log.debug("Leaving before().");
  return false;
}

/**
 * The rows a plan keeps while a source is paged.
 */
class Rows {
  plan: Plan;
  types: Record<string, string>;
  kept: Row[];
  groups: Map<string, { row: Row; count: number }>;
  stopped: boolean;

  /**
   * @param plan - a plan `Query.validate` accepted
   * @param types - field id to catalog type, for comparisons
   */
  constructor(plan: Plan, types: Record<string, string>) {
    log.debug("Entering Rows().");
    this.plan = plan;
    this.types = types || {};
    this.kept = [];
    this.groups = new Map();
    this.stopped = false;
    log.debug("Leaving Rows().");
  }

  /**
   * Offers one source row. False means the limit is already met and the
   * caller can stop paging. A count and an ordered read always say true,
   * because a later row can still change the answer; they do not keep it.
   *
   * @param row - one source row, keyed by catalog field id
   * @returns whether the caller should keep paging
   */
  take(row: Row): boolean {
    log.debug("Entering Rows.take().");
    if (this.stopped) {
      log.debug("Leaving Rows.take(). Stopped.");
      return false;
    }
    if (!this.matches(this.plan.where, row)) {
      log.debug("Leaving Rows.take(). Filtered.");
      return true;
    }
    if (this.plan.aggregate === 'count') {
      this.count(row);
      log.debug("Leaving Rows.take(). Counted.");
      return true;
    }
    const projected = this.project(row);
    if (!this.plan.orderBy.length) {
      this.kept.push(projected);
      if (this.kept.length >= this.plan.limit) {
        this.stopped = true;
      }
      log.debug("Leaving Rows.take(). Kept.");
      return !this.stopped;
    }
    this.heap(projected);
    log.debug("Leaving Rows.take(). Heaped.");
    return true;
  }

  /**
   * The rows the plan asked for, in order, at most `limit` of them.
   *
   * @returns the output rows
   */
  finish(): Row[] {
    log.debug("Entering Rows.finish().");
    let rows: Row[];
    if (this.plan.aggregate === 'count') {
      rows = this.finishCount();
    } else if (this.plan.orderBy.length) {
      rows = this.kept.slice().sort((a, b) => this.order(a, b));
    } else {
      rows = this.kept.slice(0, this.plan.limit);
    }
    log.debug("Leaving Rows.finish().");
    return rows;
  }

  private count(row: Row): void {
    log.debug("Entering Rows.count().");
    const keyParts: unknown[] = [];
    const projected: Row = {};
    const ids = this.plan.groupBy;
    for (let i = 0; i < ids.length; i++) {
      projected[ids[i]] = row[ids[i]] == null ? null : row[ids[i]];
      keyParts.push(projected[ids[i]]);
    }
    const key = JSON.stringify(keyParts);
    const held = this.groups.get(key);
    if (held) {
      held.count += 1;
    } else {
      this.groups.set(key, { row: projected, count: 1 });
    }
    log.debug("Leaving Rows.count().");
  }

  private finishCount(): Row[] {
    log.debug("Entering Rows.finishCount().");
    const show = this.plan.select.length ? this.plan.select :
      this.plan.groupBy;
    const rows: Row[] = [];
    this.groups.forEach(function (held) {
      const out: Row = {};
      for (let i = 0; i < show.length; i++) {
        out[show[i]] = held.row[show[i]] == null ? null : held.row[show[i]];
      }
      out.count = held.count;
      rows.push(out);
    });
    if (!this.groups.size && !this.plan.groupBy.length) {
      const out: Row = { count: 0 };
      rows.push(out);
    }
    rows.sort((a, b) => this.order(a, b));
    const limited = rows.slice(0, this.plan.limit);
    log.debug("Leaving Rows.finishCount().");
    return limited;
  }

  private project(row: Row): Row {
    log.debug("Entering Rows.project().");
    const out: Row = {};
    const ids = this.plan.select;
    for (let i = 0; i < ids.length; i++) {
      out[ids[i]] = row[ids[i]] == null ? null : row[ids[i]];
    }
    log.debug("Leaving Rows.project().");
    return out;
  }

  /**
   * Keeps at most `limit` rows, the ones that sort first. The heap's root
   * is the worst of those, so a better row replaces it and the population
   * is never stored.
   *
   * @param row - a matching projected row
   */
  private heap(row: Row): void {
    log.debug("Entering Rows.heap().");
    if (this.kept.length < this.plan.limit) {
      this.kept.push(row);
      this.bubbleUp(this.kept.length - 1);
      log.debug("Leaving Rows.heap(). Pushed.");
      return;
    }
    if (this.order(row, this.kept[0]) < 0) {
      this.kept[0] = row;
      this.bubbleDown(0);
    }
    log.debug("Leaving Rows.heap().");
  }

  private bubbleUp(index: number): void {
    log.debug("Entering Rows.bubbleUp().");
    let at = index;
    while (at > 0) {
      const parent = Math.floor((at - 1) / 2);
      if (this.worse(this.kept[at], this.kept[parent])) {
        const swap = this.kept[at];
        this.kept[at] = this.kept[parent];
        this.kept[parent] = swap;
        at = parent;
      } else {
        break;
      }
    }
    log.debug("Leaving Rows.bubbleUp().");
  }

  private bubbleDown(index: number): void {
    log.debug("Entering Rows.bubbleDown().");
    let at = index;
    const n = this.kept.length;
    while (true) {
      const left = at * 2 + 1;
      const right = left + 1;
      let worst = at;
      if (left < n && this.worse(this.kept[left], this.kept[worst])) {
        worst = left;
      }
      if (right < n && this.worse(this.kept[right], this.kept[worst])) {
        worst = right;
      }
      if (worst === at) {
        break;
      }
      const swap = this.kept[at];
      this.kept[at] = this.kept[worst];
      this.kept[worst] = swap;
      at = worst;
    }
    log.debug("Leaving Rows.bubbleDown().");
  }

  /** @returns true when `a` sorts after `b` and is the worse one to keep */
  private worse(a: Row, b: Row): boolean {
    log.debug("Entering Rows.worse().");
    const after = this.order(a, b) > 0;
    log.debug("Leaving Rows.worse().");
    return after;
  }

  private order(a: Row, b: Row): number {
    log.debug("Entering Rows.order().");
    const keys = this.plan.orderBy;
    for (let i = 0; i < keys.length; i++) {
      const id = keys[i].field;
      const dir = keys[i].dir === 'desc' ? -1 : 1;
      const cmp = this.compare(id, a[id], b[id]);
      if (cmp !== 0) {
        log.debug("Leaving Rows.order().");
        return cmp * dir;
      }
    }
    log.debug("Leaving Rows.order().");
    return 0;
  }

  private compare(field: string, left: unknown, right: unknown): number {
    log.debug("Entering Rows.compare().");
    if (left == null && right == null) {
      log.debug("Leaving Rows.compare(). Both empty.");
      return 0;
    }
    if (left == null) {
      log.debug("Leaving Rows.compare(). Left empty.");
      return -1;
    }
    if (right == null) {
      log.debug("Leaving Rows.compare(). Right empty.");
      return 1;
    }
    const type = this.types[field] || '';
    if (type === 'timestamp' || type === 'number') {
      const a = type === 'timestamp' ? stamp(left) : Number(left);
      const b = type === 'timestamp' ? stamp(right) : Number(right);
      const cmp = (a == null ? 0 : a) - (b == null ? 0 : b);
      log.debug("Leaving Rows.compare(). Number.");
      return cmp < 0 ? -1 : (cmp > 0 ? 1 : 0);
    }
    const as = String(left);
    const bs = String(right);
    if (as < bs) {
      log.debug("Leaving Rows.compare(). Before.");
      return -1;
    }
    if (as > bs) {
      log.debug("Leaving Rows.compare(). After.");
      return 1;
    }
    log.debug("Leaving Rows.compare().");
    return 0;
  }

  private matches(node: any, row: Row): boolean {
    log.debug("Entering Rows.matches().");
    if (node == null) {
      log.debug("Leaving Rows.matches(). No filter.");
      return true;
    }
    if (node.op === 'and') {
      const args = node.args || [];
      for (let i = 0; i < args.length; i++) {
        if (!this.matches(args[i], row)) {
          log.debug("Leaving Rows.matches(). And.");
          return false;
        }
      }
      log.debug("Leaving Rows.matches(). And holds.");
      return true;
    }
    if (node.op === 'or') {
      const args = node.args || [];
      for (let i = 0; i < args.length; i++) {
        if (this.matches(args[i], row)) {
          log.debug("Leaving Rows.matches(). Or.");
          return true;
        }
      }
      log.debug("Leaving Rows.matches(). Or fails.");
      return false;
    }
    if (node.op === 'not') {
      const negated = !this.matches(node.arg, row);
      log.debug("Leaving Rows.matches(). Not.");
      return negated;
    }
    const held = this.leaf(node, row);
    log.debug("Leaving Rows.matches().");
    return held;
  }

  private leaf(node: any, row: Row): boolean {
    log.debug("Entering Rows.leaf().");
    const value = row[node.field];
    const type = this.types[node.field] || 'string';
    const empty = value == null || value === '';
    if (node.op === 'isNull') {
      log.debug("Leaving Rows.leaf(). isNull.");
      return empty;
    }
    if (node.op === 'in') {
      const list = Array.isArray(node.value) ? node.value : [];
      for (let i = 0; i < list.length; i++) {
        if (same(type, value, list[i])) {
          log.debug("Leaving Rows.leaf(). In.");
          return true;
        }
      }
      log.debug("Leaving Rows.leaf(). Not in.");
      return false;
    }
    if (node.op === 'eq') {
      log.debug("Leaving Rows.leaf(). eq.");
      return same(type, value, node.value);
    }
    if (node.op === 'ne') {
      log.debug("Leaving Rows.leaf(). ne.");
      return !same(type, value, node.value);
    }
    if (node.op === 'contains') {
      const held = typeof value === 'string' &&
        typeof node.value === 'string' &&
        value.indexOf(node.value) >= 0;
      log.debug("Leaving Rows.leaf(). contains.");
      return held;
    }
    if (node.op === 'startsWith') {
      const held = typeof value === 'string' &&
        typeof node.value === 'string' &&
        value.indexOf(node.value) === 0;
      log.debug("Leaving Rows.leaf(). startsWith.");
      return held;
    }
    if (node.op === 'lt') {
      log.debug("Leaving Rows.leaf(). lt.");
      return before(type, value, node.value);
    }
    if (node.op === 'le') {
      log.debug("Leaving Rows.leaf(). le.");
      return before(type, value, node.value) || same(type, value, node.value);
    }
    if (node.op === 'gt') {
      log.debug("Leaving Rows.leaf(). gt.");
      return before(type, node.value, value);
    }
    if (node.op === 'ge') {
      log.debug("Leaving Rows.leaf(). ge.");
      return before(type, node.value, value) || same(type, value, node.value);
    }
    log.debug("Leaving Rows.leaf(). Unknown operator.");
    return false;
  }
}

export = Rows;
