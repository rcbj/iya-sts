// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: request_phases.js
//
// ---------------------------------------------------------------------------
// WHERE A DISPATCHED REQUEST'S TIME GOES (2026-10-22, #820).
//
// On 8081, refreshes stopped at about 160 a second with 4 workers and with
// 8, the workers at 75-85% CPU and postgres at 1.5-3 cores: something every
// request waits on, and nothing said what. A dispatched request can wait in
// six places (`common/CLAUDE.md` has the pool's design):
//
//   ticket   the front, for every request answered before it on another
//            worker to be reported committed (`awaitCommitConfirmations()`);
//   barrier  the front, for the chosen worker to catch up with the change
//            log when it is behind (`barrier()`, read-your-write);
//   queue    between the front sending it and the worker's answer, less
//            what the worker itself reports: the socket, and the worker's
//            event loop busy with other requests;
//   handler  the worker, from the request reaching the commit barrier's
//            middleware to the handler ending its response;
//   commit   the worker, holding that response until its writes committed
//            (`cluster/cluster_barrier.js`'s rule 2);
//   bridge   of the worker's time, how long its event loop was BLOCKED in
//            synchronous store reads (`common/sync_query.ts`) — every
//            request on that worker waited through those, not this one only.
//
// The front times the first three; the worker reports the rest in
// `PHASES_HEADER` on its answer, which the front takes off before the answer
// goes out, and only when the front asked for it with `ASK_HEADER` (which it
// takes off what a client sent first).
//
// **NO TIMER, NO LINE PER REQUEST** (the scheduler rule, and *No per-event
// failure logs*): each finished request adds its numbers to the current
// window, and the first one after the window ends logs ONE summary line per
// route — the busiest `REPORTED_ROUTES` — and keeps it for `stats()`. A
// window with no requests logs nothing.
//
// A LEAF: it requires nothing of this service, so `sync_query.ts`,
// `cluster_barrier.js` and `request_pool.js` can all require it.
// ---------------------------------------------------------------------------

const bunyan = require('bunyan');

const log = bunyan.createLogger({
  name: 'sts-request-phases',
  level: process.env.STS_LOG_LEVEL || 'info'
});

// What the front asks with, and what a worker answers in. Both are taken off
// at the front, in each direction.
const ASK_HEADER = 'x-sts-pool-phases-wanted';
const PHASES_HEADER = 'x-sts-pool-phases';

// How long one window is, and how many samples a route keeps in it (beyond
// that, a sample replaces the oldest: the latest ones are kept).
const WINDOW_MS = 60 * 1000;
const SAMPLES_PER_ROUTE = 4000;
// How many routes a window holds, and how many it reports. A path past the
// first is kept under 'other', so a client inventing paths cannot grow it.
const MAX_ROUTES = 64;
const REPORTED_ROUTES = 12;
// `prepare`, `db` and `rows` are a flush's (2026-10-22, #820): the minted
// flush is recorded under its own route, `FLUSH minted`, in the process
// that flushes — a request worker's own window and lines.
// `directory`, `minted` and `keys` are a response's commit wait, by the part
// it waited on (#820): `COMMIT through`, beside `FLUSH directory`.
const PHASES = ['ticket', 'barrier', 'queue', 'handler', 'commit', 'bridge',
                'prepare', 'db', 'rows', 'directory', 'minted', 'keys',
                'total'];

// Milliseconds the event loop spent blocked in synchronous store reads since
// the process started (`noteBlocked()`).
let blockedMs = 0;
// route -> { n, samples: { phase: number[] } }
let windowRoutes = new Map();
let windowStartedAt = Date.now();
let lastReport = null;

/**
 * Counts time the event loop spent blocked in a synchronous store read.
 * Called by `common/sync_query.ts` after each question.
 *
 * @param ms - how long that question blocked
 */
// Hot path: every synchronous store read. No Entering/Leaving pair.
function noteBlocked(ms) {
  blockedMs += Number(ms) || 0;
}

/**
 * The milliseconds blocked in synchronous store reads since the start.
 *
 * @returns the running total
 */
// Hot path: twice per dispatched request. No Entering/Leaving pair.
function blockedTotal() {
  return blockedMs;
}

/**
 * The worker's half, as the header value: handler, commit and bridge ms.
 *
 * @param handlerMs - arrival to the handler ending its response
 * @param commitMs - the hold until the response's writes committed
 * @param bridgeMs - blocked in synchronous store reads meanwhile
 * @returns the value of `PHASES_HEADER`
 */
// Hot path: every dispatched response. No Entering/Leaving pair.
function encode(handlerMs, commitMs, bridgeMs) {
  return 'h=' + Math.max(0, Math.round(handlerMs)) +
    ';c=' + Math.max(0, Math.round(commitMs)) +
    ';b=' + Math.max(0, Math.round(bridgeMs));
}

/**
 * Reads a worker's `PHASES_HEADER`.
 *
 * @param value - the header's value
 * @returns `{ handler, commit, bridge }`, or null when it is not one
 */
// Hot path: every dispatched response. No Entering/Leaving pair.
function decode(value) {
  const match = /^h=(\d+);c=(\d+);b=(\d+)$/.exec(String(value || ''));
  return match ? { handler: Number(match[1]), commit: Number(match[2]),
                   bridge: Number(match[3]) } : null;
}

/**
 * The route a request is counted under: its method and the first two
 * segments of its path, with a realm prefix taken off.
 *
 * @param method - the request's method
 * @param url - its path, as the client sent it
 * @returns the route
 */
// Hot path: every dispatched request. No Entering/Leaving pair.
function routeOf(method, url) {
  const segments = String(url || '').split('?')[0].split('/')
    .filter(Boolean);
  const rest = segments[0] === 'realm' ? segments.slice(2) : segments;
  return String(method || '').toUpperCase() + ' /' +
    rest.slice(0, 2).join('/');
}

// Each phase's p50, p95 and mean, over one route's samples.
function summaryOf(entry) {
  log.debug("Entering summaryOf().");
  const out = { n: entry.n };
  PHASES.forEach(function (phase) {
    // A phase a request did not report leaves its slot empty.
    const sorted = entry.samples[phase].filter(function (value) {
      return typeof value === 'number';
    }).sort(function (a, b) {
      return a - b;
    });
    if (!sorted.length) {
      return;
    }
    const at = function (q) {
      return sorted[Math.min(sorted.length - 1,
                             Math.floor(q * sorted.length))];
    };
    const sum = sorted.reduce(function (a, b) {
      return a + b;
    }, 0);
    out[phase] = { p50: at(0.5), p95: at(0.95),
                   mean: Math.round(sum / sorted.length) };
  });
  log.debug("Leaving summaryOf().");
  return out;
}

// Closes the window: logs the busiest routes and keeps them for stats().
function report(now) {
  log.debug("Entering report().");
  const routes = Array.from(windowRoutes.entries())
    .sort(function (a, b) {
      return b[1].n - a[1].n;
    })
    .slice(0, REPORTED_ROUTES);
  const seconds = Math.max(1, (now - windowStartedAt) / 1000);
  const summary = { at: new Date(now).toISOString(),
                    seconds: Math.round(seconds), routes: {} };
  routes.forEach(function (pair) {
    const one = summaryOf(pair[1]);
    summary.routes[pair[0]] = one;
    const parts = PHASES.filter(function (phase) {
      return one[phase];
    }).map(function (phase) {
      return phase + ' ' + one[phase].p50 + '/' + one[phase].p95;
    });
    log.info('request phases, last ' + Math.round(seconds) + ' s: ' +
             pair[0] + ' ' + (one.n / seconds).toFixed(1) + '/s — ' +
             'p50/p95 ms: ' + parts.join(', '));
  });
  lastReport = summary;
  windowRoutes = new Map();
  windowStartedAt = now;
  log.debug("Leaving report().");
}

/**
 * Adds one finished request's phases to the window, and closes the window
 * when it has run out.
 *
 * @param route - `routeOf()`'s answer
 * @param phases - any of `ticket`, `barrier`, `queue`, `handler`, `commit`,
 *   `bridge` and `total`, in ms
 * @param now - the instant, for the tests; defaults to now
 */
// Hot path: every dispatched request. No Entering/Leaving pair.
function record(route, phases, now) {
  const at = typeof now === 'number' ? now : Date.now();
  if (at - windowStartedAt >= WINDOW_MS) {
    if (windowRoutes.size) {
      report(at);
    } else {
      windowStartedAt = at;
    }
  }
  let key = String(route);
  if (!windowRoutes.has(key) && windowRoutes.size >= MAX_ROUTES) {
    key = 'other';
  }
  let entry = windowRoutes.get(key);
  if (!entry) {
    entry = { n: 0, samples: {} };
    PHASES.forEach(function (phase) {
      entry.samples[phase] = [];
    });
    windowRoutes.set(key, entry);
  }
  entry.n += 1;
  // A RING, NOT A RANDOM RESERVOIR (2026-10-22): past SAMPLES_PER_ROUTE a
  // sample replaces the oldest, so a busy route's percentiles are its
  // latest SAMPLES_PER_ROUTE requests of the window. A random slot needed a
  // generator, and this leaf may use neither Math.random()
  // (tests/random_values.js) nor node's crypto, which only common/crypto.js
  // requires (tests/crypto_centralised.js) — and requiring that would end
  // this file being a leaf.
  const slot = (entry.n - 1) % SAMPLES_PER_ROUTE;
  PHASES.forEach(function (phase) {
    const value = phases[phase];
    if (typeof value === 'number' && isFinite(value)) {
      entry.samples[phase][slot] = Math.max(0, value);
    }
  });
}

/**
 * The last closed window's summary, per route, or null before the first.
 *
 * @returns `{ at, seconds, routes: { route: { n, phase: { p50, p95,
 *   mean } } } }`
 */
function stats() {
  log.debug("Entering stats().");
  log.debug("Leaving stats().");
  return lastReport;
}

/**
 * Forgets every window, for the tests.
 */
function reset() {
  log.debug("Entering reset().");
  windowRoutes = new Map();
  windowStartedAt = Date.now();
  lastReport = null;
  blockedMs = 0;
  log.debug("Leaving reset().");
}

module.exports = {
  ASK_HEADER: ASK_HEADER,
  PHASES_HEADER: PHASES_HEADER,
  WINDOW_MS: WINDOW_MS,
  noteBlocked: noteBlocked,
  blockedTotal: blockedTotal,
  encode: encode,
  decode: decode,
  routeOf: routeOf,
  record: record,
  stats: stats,
  reset: reset
};
