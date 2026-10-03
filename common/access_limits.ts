// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: access_limits.ts
//
// ===========================================================================
// THE LIMITS VOCABULARY OF AN ACCESS RIGHT (#432 phase 5, 2026-10-03).
//
// An access-type catalogue entry (`oauthAuthorizationDetailsType`, shared by
// RFC 9396 and GNAP — `common/applications.js`) may declare a `limits`
// schema, and a right of that type may then carry a `limits` member: how
// much, how many times, to whom, how often, and when. The schema is the
// resource server's statement of SHAPE. This module is the statement of
// MEANING, which a schema cannot carry and three parties need: the
// authorization server shows a limit to the person and lets them LOWER it,
// the token states it, and the resource server keeps the running totals
// (rcbj's decision 2 on #432) — so "lower" and "spent" must mean one thing
// to all three.
//
// THE FIVE MEMBERS WITH A MEANING:
//
//   amount    { value, currency }   a decimal string (or number) of at most
//                                   18 integer and 6 fraction digits, and an
//                                   ISO 4217 code — the most that may be
//                                   spent (per interval, where one is given)
//   count     integer >= 0          the most operations (per interval)
//   receiver  string or [strings]   who an operation may be FOR; an
//                                   operation naming anybody else is refused
//   interval  "R[n]/start/duration" an ISO 8601 repeating interval: the
//                                   totals RESET at each boundary, and an
//                                   operation before `start` or after the
//                                   n-th repetition is outside the limits
//   window    { notBefore, notAfter } RFC 3339 times, at least one: an
//                                   operation outside is refused
//
// ANY OTHER MEMBER is the API's own: the type's schema says what it may be,
// it is carried and shown as it is, and — because this module cannot say
// what lowering it would mean — the person may not change it.
//
// "LOWER", PER MEMBER, AND NOTHING ELSE IS:
//
//   amount    the same currency and a value no greater
//   count     no greater
//   receiver  a subset of the receivers (a single string is a set of one)
//   interval  the same start, a duration no SHORTER (a longer period resets
//             the budget less often), and no more repetitions — a shorter
//             period with the same budget is MORE spend, which is why the
//             comparison runs that way round. A duration is compared
//             component-wise (calendar months, then fixed seconds), because
//             P1M against P30D has no answer.
//   window    a notBefore no earlier and a notAfter no later
//
// A member the original carried may not be REMOVED (no limit is the most of
// all). A member it did not carry may be ADDED — except `interval`: with a
// budget present, adding a reset is a raise, and without one it adds
// nothing a window does not say better.
//
// AMOUNTS ARE COUNTED IN MILLIONTHS, AS BigInt. A currency amount summed in
// binary floating point is a different amount after enough additions, and
// the totals are the resource server's ledger. Six fraction digits cover
// every ISO 4217 minor unit with room to spare.
//
// A STATIC UTILITY CLASS (the code style's rule for a helper with no
// dependency but the logger): no route, no store, no require of anything in
// a protocol directory, so `oauth-oidc/authorization_details.ts`, `gnap/`
// and the demonstration resource server all read the one copy.
// ===========================================================================

import helpers = require('./helpers');

type Json = any;

// The members with a meaning, in the order a page draws them.
const MEMBERS = ['amount', 'count', 'receiver', 'interval', 'window'];

// Millionths: see the header.
const FRACTION_DIGITS = 6;
const UNIT = BigInt(1000000);
const DECIMAL_RE = /^(\d{1,18})(?:\.(\d{1,6}))?$/;
const CURRENCY_RE = /^[A-Z]{3}$/;
const RFC3339_RE =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;
const DURATION_RE = new RegExp('^P(?:(\\d{1,7})Y)?(?:(\\d{1,7})M)?' +
  '(?:(\\d{1,7})W)?(?:(\\d{1,7})D)?(?:T(?:(\\d{1,7})H)?(?:(\\d{1,7})M)?' +
  '(?:(\\d{1,9})S)?)?$');
const INTERVAL_RE = /^R(\d{0,7})\/([^/]{1,64})\/(P[^/]{1,64})$/;
const CONTROL_RE = /[\x00-\x1f\x7f]/;
// The most receivers a limit may name, and the longest one.
const MAX_RECEIVERS = 64;
const MAX_RECEIVER_LENGTH = 512;
// A month, for ESTIMATING which period a time falls in before the exact
// calendar arithmetic corrects it (the Gregorian average, in seconds).
const AVERAGE_MONTH_S = 2629746;

interface Duration {
  months: number;
  seconds: number;
}

interface Interval {
  repetitions: number | null;
  start: number;
  duration: Duration;
  text: string;
}

/**
 * The limits vocabulary of an access right (#432 phase 5): what each member
 * means, whether a limit is well formed, whether one limit is LOWER than
 * another, and which period of a repeating interval a time falls in.
 */
class AccessLimits {
  /** The members with a meaning, in display order. */
  static readonly MEMBERS = MEMBERS;
  /** The fraction digits an amount may carry. */
  static readonly FRACTION_DIGITS = FRACTION_DIGITS;

  // A value as canonical JSON (sorted keys), for comparing a member this
  // module does not interpret.
  private static canonical(value: Json): string {
    helpers.log.debug("Entering AccessLimits.canonical().");
    let out: string;
    if (Array.isArray(value)) {
      out = '[' + value.map(function (one: Json): string {
        return AccessLimits.canonical(one);
      }).join(',') + ']';
    } else if (value && typeof value === 'object') {
      out = '{' + Object.keys(value).sort().map(function (k: string): string {
        return JSON.stringify(k) + ':' + AccessLimits.canonical(value[k]);
      }).join(',') + '}';
    } else {
      out = JSON.stringify(value);
    }
    helpers.log.debug("Leaving AccessLimits.canonical().");
    return out;
  }

  /**
   * Reads a decimal amount as millionths.
   *
   * @param value - a decimal string, or a non-negative finite number
   * @returns the amount in millionths, or null when it is not one
   */
  static units(value: Json): bigint | null {
    helpers.log.debug("Entering AccessLimits.units().");
    let text = '';
    if (typeof value === 'string') {
      text = value;
    } else if (typeof value === 'number' && Number.isFinite(value) &&
               value >= 0) {
      // A number is read through its shortest decimal spelling; one that
      // needs an exponent (1e21) is not an amount here.
      text = String(value);
    }
    const match = DECIMAL_RE.exec(text);
    if (!match) {
      helpers.log.debug("Leaving AccessLimits.units(). Not a decimal.");
      return null;
    }
    const fraction = (match[2] || '').padEnd(FRACTION_DIGITS, '0');
    helpers.log.debug("Leaving AccessLimits.units().");
    return BigInt(match[1]) * UNIT + BigInt(fraction);
  }

  /**
   * Writes millionths back as the shortest decimal string.
   *
   * @param units - the amount in millionths
   * @returns the decimal string
   */
  static decimal(units: bigint): string {
    helpers.log.debug("Entering AccessLimits.decimal().");
    const negative = units < BigInt(0);
    const abs = negative ? -units : units;
    const whole = (abs / UNIT).toString();
    const fraction = (abs % UNIT).toString().padStart(FRACTION_DIGITS, '0')
      .replace(/0+$/, '');
    helpers.log.debug("Leaving AccessLimits.decimal().");
    return (negative ? '-' : '') + whole + (fraction ? '.' + fraction : '');
  }

  /**
   * Reads an RFC 3339 date-time with its offset, in seconds.
   *
   * @param text - the date-time
   * @returns seconds since the epoch, or null
   */
  static timeOf(text: Json): number | null {
    helpers.log.debug("Entering AccessLimits.timeOf().");
    if (typeof text !== 'string' || !RFC3339_RE.test(text)) {
      helpers.log.debug("Leaving AccessLimits.timeOf(). Not RFC 3339.");
      return null;
    }
    const ms = Date.parse(text);
    helpers.log.debug("Leaving AccessLimits.timeOf().");
    return Number.isFinite(ms) ? Math.floor(ms / 1000) : null;
  }

  /**
   * Reads an ISO 8601 duration of whole units into calendar months and fixed
   * seconds.
   *
   * @param text - the duration, such as `P1M` or `PT12H`
   * @returns `{ months, seconds }`, or null when it is not a positive one
   */
  static durationOf(text: Json): Duration | null {
    helpers.log.debug("Entering AccessLimits.durationOf().");
    const match = typeof text === 'string' ? DURATION_RE.exec(text) : null;
    if (!match || /T$/.test(text)) {
      helpers.log.debug("Leaving AccessLimits.durationOf(). Not a duration.");
      return null;
    }
    const n = function (i: number): number {
      helpers.log.debug("Entering n().");
      helpers.log.debug("Leaving n().");
      return match[i] ? Number(match[i]) : 0;
    };
    const months = n(1) * 12 + n(2);
    const seconds = n(3) * 604800 + n(4) * 86400 + n(5) * 3600 + n(6) * 60 +
      n(7);
    if (months + seconds <= 0) {
      helpers.log.debug("Leaving AccessLimits.durationOf(). Zero.");
      return null;
    }
    helpers.log.debug("Leaving AccessLimits.durationOf().");
    return { months: months, seconds: seconds };
  }

  /**
   * Reads an ISO 8601 repeating interval in its `R[n]/start/duration` form.
   *
   * @param text - the interval
   * @returns the repetitions (null: unbounded), the start in seconds and the
   *   duration, or null when it is not one
   */
  static intervalOf(text: Json): Interval | null {
    helpers.log.debug("Entering AccessLimits.intervalOf().");
    const match = typeof text === 'string' ? INTERVAL_RE.exec(text) : null;
    if (!match) {
      helpers.log.debug("Leaving AccessLimits.intervalOf(). Not R/start/P.");
      return null;
    }
    const repetitions = match[1] === '' ? null : Number(match[1]);
    const start = AccessLimits.timeOf(match[2]);
    const duration = AccessLimits.durationOf(match[3]);
    if (repetitions === 0 || start === null || !duration) {
      helpers.log.debug("Leaving AccessLimits.intervalOf(). A part is bad.");
      return null;
    }
    helpers.log.debug("Leaving AccessLimits.intervalOf().");
    return { repetitions: repetitions, start: start, duration: duration,
             text: text };
  }

  /**
   * The instant `k` durations after `start`, calendar months first.
   *
   * @param start - seconds since the epoch
   * @param duration - the duration
   * @param k - how many durations
   * @returns seconds since the epoch
   */
  static after(start: number, duration: Duration, k: number): number {
    helpers.log.debug("Entering AccessLimits.after().");
    const at = new Date(start * 1000);
    if (duration.months) {
      at.setUTCMonth(at.getUTCMonth() + duration.months * k);
    }
    helpers.log.debug("Leaving AccessLimits.after().");
    return Math.floor(at.getTime() / 1000) + duration.seconds * k;
  }

  /**
   * Finds the period of a repeating interval a time falls in.
   *
   * @param interval - the interval, as `intervalOf()` reads it (or its text)
   * @param now - seconds since the epoch
   * @returns `{ index, start, end }`, or `{ outside: 'before' | 'after' }`
   */
  static periodAt(interval: Json, now: number): Json {
    helpers.log.debug("Entering AccessLimits.periodAt().");
    const read: Interval | null = typeof interval === 'string'
      ? AccessLimits.intervalOf(interval) : interval;
    if (!read) {
      helpers.log.debug("Leaving AccessLimits.periodAt(). No interval.");
      return { outside: 'malformed' };
    }
    if (now < read.start) {
      helpers.log.debug("Leaving AccessLimits.periodAt(). Before.");
      return { outside: 'before' };
    }
    const span = read.duration.months * AVERAGE_MONTH_S +
      read.duration.seconds;
    let index = Math.floor((now - read.start) / span);
    // The estimate is exact for fixed durations and within a period or two
    // for calendar ones; corrected in both directions, a bounded number of
    // steps.
    for (let i = 0; i < 8 &&
         AccessLimits.after(read.start, read.duration, index) > now; i++) {
      index--;
    }
    for (let i = 0; i < 8 &&
         AccessLimits.after(read.start, read.duration, index + 1) <= now;
         i++) {
      index++;
    }
    if (index < 0) {
      index = 0;
    }
    if (read.repetitions !== null && index >= read.repetitions) {
      helpers.log.debug("Leaving AccessLimits.periodAt(). After.");
      return { outside: 'after' };
    }
    helpers.log.debug("Leaving AccessLimits.periodAt(). " + index);
    return { index: index,
             start: AccessLimits.after(read.start, read.duration, index),
             end: AccessLimits.after(read.start, read.duration, index + 1) };
  }

  /**
   * The receivers a limit names, as a list, or null when it names none.
   *
   * @param limits - the limits member
   * @returns the receivers, or null
   */
  static receiversOf(limits: Json): string[] | null {
    helpers.log.debug("Entering AccessLimits.receiversOf().");
    const value = limits ? limits.receiver : undefined;
    helpers.log.debug("Leaving AccessLimits.receiversOf().");
    if (value === undefined) {
      return null;
    }
    return (Array.isArray(value) ? value : [value]).map(String);
  }

  // -------------------------------------------------------------------------
  // WELL-FORMEDNESS: the members with a meaning, read as the header says.
  // A sentence naming the first problem, or ''.
  // -------------------------------------------------------------------------
  /**
   * Checks the members of a `limits` object that carry a meaning.
   *
   * @param limits - the limits member
   * @returns the problem as a sentence, or ''
   */
  static problem(limits: Json): string {
    helpers.log.debug("Entering AccessLimits.problem().");
    if (!limits || typeof limits !== 'object' || Array.isArray(limits)) {
      helpers.log.debug("Leaving AccessLimits.problem(). Not an object.");
      return 'limits is not a JSON object';
    }
    if (limits.amount !== undefined) {
      const a = limits.amount;
      if (!a || typeof a !== 'object' || Array.isArray(a) ||
          Object.keys(a).sort().join(',') !== 'currency,value') {
        helpers.log.debug("Leaving AccessLimits.problem(). amount shape.");
        return 'limits.amount must be an object of exactly "value" and ' +
          '"currency"';
      }
      if (AccessLimits.units(a.value) === null) {
        helpers.log.debug("Leaving AccessLimits.problem(). amount value.");
        return 'limits.amount.value must be a non-negative decimal of at ' +
          'most 18 integer and ' + FRACTION_DIGITS + ' fraction digits';
      }
      if (typeof a.currency !== 'string' || !CURRENCY_RE.test(a.currency)) {
        helpers.log.debug("Leaving AccessLimits.problem(). currency.");
        return 'limits.amount.currency must be an ISO 4217 code of three ' +
          'capital letters';
      }
    }
    if (limits.count !== undefined &&
        !(Number.isSafeInteger(limits.count) && limits.count >= 0)) {
      helpers.log.debug("Leaving AccessLimits.problem(). count.");
      return 'limits.count must be a non-negative integer';
    }
    if (limits.receiver !== undefined) {
      const list = Array.isArray(limits.receiver) ? limits.receiver
        : [limits.receiver];
      const bad = !list.length || list.length > MAX_RECEIVERS ||
        list.some(function (one: Json): boolean {
          return typeof one !== 'string' || !one ||
            one.length > MAX_RECEIVER_LENGTH || CONTROL_RE.test(one);
        });
      if (bad) {
        helpers.log.debug("Leaving AccessLimits.problem(). receiver.");
        return 'limits.receiver must be a non-empty string, or an array of ' +
          '1 to ' + MAX_RECEIVERS + ' of them, with no control character';
      }
    }
    if (limits.interval !== undefined &&
        !AccessLimits.intervalOf(limits.interval)) {
      helpers.log.debug("Leaving AccessLimits.problem(). interval.");
      return 'limits.interval must be an ISO 8601 repeating interval ' +
        '"R[n]/<RFC 3339 start>/<duration>" of whole units, n at least 1 ' +
        'where given';
    }
    if (limits.window !== undefined) {
      const w = limits.window;
      const keys = w && typeof w === 'object' && !Array.isArray(w)
        ? Object.keys(w) : null;
      const nb = keys ? AccessLimits.timeOf(w.notBefore) : null;
      const na = keys ? AccessLimits.timeOf(w.notAfter) : null;
      if (!keys || !keys.length || keys.some(function (k: string): boolean {
        return k !== 'notBefore' && k !== 'notAfter';
      }) || (w.notBefore !== undefined && nb === null) ||
          (w.notAfter !== undefined && na === null) ||
          (nb !== null && na !== null && nb >= na)) {
        helpers.log.debug("Leaving AccessLimits.problem(). window.");
        return 'limits.window must be an object of "notBefore" and/or ' +
          '"notAfter", each an RFC 3339 date-time, the first earlier';
      }
    }
    helpers.log.debug("Leaving AccessLimits.problem().");
    return '';
  }

  // -------------------------------------------------------------------------
  // IS `proposed` NO MORE THAN `original`? '' when it is (equal included), or
  // the sentence naming the first member it raises — see the header for what
  // lower means, member by member.
  // -------------------------------------------------------------------------
  /**
   * Says whether one set of limits is no more than another.
   *
   * @param original - the limits as requested or as granted (or undefined)
   * @param proposed - the limits asked for in their place (or undefined)
   * @returns '' when `proposed` is equal or lower, or the sentence naming
   *   the member it raises
   */
  static raised(original: Json, proposed: Json): string {
    helpers.log.debug("Entering AccessLimits.raised().");
    if (original === undefined || original === null) {
      helpers.log.debug("Leaving AccessLimits.raised(). Nothing to raise.");
      return '';
    }
    if (proposed === undefined || proposed === null) {
      helpers.log.debug("Leaving AccessLimits.raised(). Removed.");
      return 'the limits were removed, and no limit is the most of all';
    }
    const shape = AccessLimits.problem(proposed);
    if (shape) {
      helpers.log.debug("Leaving AccessLimits.raised(). Malformed.");
      return shape;
    }
    const keys = Object.keys(original);
    for (let i = 0; i < keys.length; i++) {
      if (proposed[keys[i]] === undefined) {
        helpers.log.debug("Leaving AccessLimits.raised(). " + keys[i] +
                          " removed.");
        return 'limits.' + keys[i] + ' was removed';
      }
    }
    const added = Object.keys(proposed).filter(function (k: string): boolean {
      return original[k] === undefined;
    });
    for (let i = 0; i < added.length; i++) {
      if (MEMBERS.indexOf(added[i]) < 0 || added[i] === 'interval') {
        helpers.log.debug("Leaving AccessLimits.raised(). " + added[i] +
                          " added.");
        return 'limits.' + added[i] + ' cannot be added: ' +
          (added[i] === 'interval' ? 'a reset is more to spend, not less'
            : 'this service does not know what it would mean');
      }
    }
    for (let i = 0; i < keys.length; i++) {
      const k = keys[i];
      const was = original[k];
      const now = proposed[k];
      let why = '';
      if (k === 'amount') {
        const a = AccessLimits.units(was && was.value);
        const b = AccessLimits.units(now.value);
        if (!was || now.currency !== was.currency) {
          why = 'limits.amount must stay in ' + (was && was.currency);
        } else if (a === null || b === null || b > a) {
          why = 'limits.amount.value is more than ' + String(was.value);
        }
      } else if (k === 'count') {
        if (!(now <= was)) {
          why = 'limits.count is more than ' + String(was);
        }
      } else if (k === 'receiver') {
        const from = AccessLimits.receiversOf(original) || [];
        const to = AccessLimits.receiversOf(proposed) || [];
        if (to.some(function (one: string): boolean {
          return from.indexOf(one) < 0;
        })) {
          why = 'limits.receiver names somebody the original does not';
        }
      } else if (k === 'interval') {
        const a = AccessLimits.intervalOf(was);
        const b = AccessLimits.intervalOf(now);
        if (!a || !b || a.start !== b.start) {
          why = 'limits.interval must keep its start';
        } else if (b.duration.months < a.duration.months ||
                   b.duration.seconds < a.duration.seconds) {
          why = 'limits.interval\'s period is shorter, and a shorter ' +
            'period resets the budget more often';
        } else if (a.repetitions !== null &&
                   (b.repetitions === null ||
                    b.repetitions > a.repetitions)) {
          why = 'limits.interval repeats more often than ' + a.repetitions +
            ' times';
        }
      } else if (k === 'window') {
        const nbWas = AccessLimits.timeOf(was && was.notBefore);
        const naWas = AccessLimits.timeOf(was && was.notAfter);
        const nbNow = AccessLimits.timeOf(now.notBefore);
        const naNow = AccessLimits.timeOf(now.notAfter);
        if ((nbWas !== null && (nbNow === null || nbNow < nbWas)) ||
            (naWas !== null && (naNow === null || naNow > naWas))) {
          why = 'limits.window is wider than the original';
        }
      } else if (AccessLimits.canonical(was) !==
                 AccessLimits.canonical(now)) {
        why = 'limits.' + k + ' is the API\'s own member, and this ' +
          'service cannot say what lowering it would mean';
      }
      if (why) {
        helpers.log.debug("Leaving AccessLimits.raised(). " + k);
        return why;
      }
    }
    helpers.log.debug("Leaving AccessLimits.raised(). Not raised.");
    return '';
  }

  /**
   * Describes limits for a person, one row per member.
   *
   * @param limits - the limits member
   * @returns `[{ member, label, value }]`
   */
  static rows(limits: Json): Json[] {
    helpers.log.debug("Entering AccessLimits.rows().");
    const out: Json[] = [];
    if (!limits || typeof limits !== 'object') {
      helpers.log.debug("Leaving AccessLimits.rows(). None.");
      return out;
    }
    Object.keys(limits).sort(function (a: string, b: string): number {
      const ia = MEMBERS.indexOf(a) < 0 ? 99 : MEMBERS.indexOf(a);
      const ib = MEMBERS.indexOf(b) < 0 ? 99 : MEMBERS.indexOf(b);
      return ia - ib || (a < b ? -1 : 1);
    }).forEach(function (k: string): void {
      const v = limits[k];
      let label = k;
      let text = '';
      if (k === 'amount' && v && typeof v === 'object') {
        label = 'At most';
        text = String(v.value) + ' ' + String(v.currency);
      } else if (k === 'count') {
        label = 'At most';
        text = String(v) + ' operation' + (v === 1 ? '' : 's');
      } else if (k === 'receiver') {
        label = 'Only to';
        text = (AccessLimits.receiversOf(limits) || []).join(', ');
      } else if (k === 'interval') {
        label = 'Resetting every';
        text = String(v);
      } else if (k === 'window' && v && typeof v === 'object') {
        label = 'Only';
        text = (v.notBefore ? 'from ' + v.notBefore : '') +
          (v.notBefore && v.notAfter ? ' ' : '') +
          (v.notAfter ? 'until ' + v.notAfter : '');
      } else {
        text = JSON.stringify(v);
      }
      out.push({ member: k, label: label, value: text });
    });
    helpers.log.debug("Leaving AccessLimits.rows().");
    return out;
  }
}

/**
 * The limits vocabulary of an access right (#432 phase 5). A static utility
 * class: no route, no store.
 */
export = AccessLimits;
