'use strict';
// ===========================================================================
// tests/tools/fresh-connections.js — A NEW CONNECTION FOR EVERY REQUEST A JOB
// MAKES, IN THE `cluster` MODE ONLY (2026-09-14, issue #46).
//
// PRELOADED, never required: `run-report.js` puts `--require <this file>` on a
// protocol job's NODE_OPTIONS when `STS_TEST_FRESH_CONNECTIONS=1`, which the
// launchers set for the `cluster` mode and for nothing else.
//
// **WHY IT EXISTS.** The `cluster` mode puts two nodes behind an L4 load
// balancer that chooses a node per CONNECTION (tests/cluster/haproxy.cfg), and
// node's HTTP clients keep connections alive: `fetch()` pools them in its
// global dispatcher and, since node 19, so does `http.globalAgent`. A job then
// makes every request on the connection its first request opened — ONE node —
// and the mode reports two nodes of which each job saw one. Nothing would fail;
// the cross-node axis would simply not be under test, which is the worst kind
// of green. With a connection per request, consecutive requests of one job
// alternate between the nodes, which is what a client behind a real load
// balancer, or several clients, do to a cluster.
//
// **A PRELOAD, BECAUSE MOST OF THE CLIENTS ARE IN VENDORED FILES.** The jobs
// under tests/vendored/ are copies of the parent project's and may not be
// edited here (tests/CLAUDE.md), and they call `fetch()` and `https.request()`
// directly rather than through one helper. `attach-admin-token.js` is the
// precedent for changing what every job's client does without touching a job.
//
// WHAT IT CHANGES, and all of it is the transport:
//
//   * `fetch()`: every request is dispatched with undici's `reset: true`, which
//     is exactly what a `Connection: close` request header does inside undici
//     — the connection is closed after the response instead of returned to the
//     pool. It is done on the DISPATCHER rather than as a header so that a job
//     passing a `Request` object or a `Headers` instance is covered the same
//     way, and so nothing a job reads back about its own request changes.
//   * `http.globalAgent` / `https.globalAgent`: replaced by agents with
//     `keepAlive: false`. A request that names its own agent keeps it — three
//     jobs do, and all three already ask for no keep-alive or `agent: false`.
//
// WHAT IT CANNOT CHANGE, and says so in tests/CLAUDE.md: Chrome's connections
// (the browser jobs are balanced per connection Chrome opens), and a long-lived
// socket that is one connection by definition (an LDAP session, a WebSocket).
//
// **THE DISPATCHER IS FOUND BY THE SYMBOL UNDICI PUBLISHES IT UNDER**, and it
// does not exist until the first `fetch()` has loaded undici — so the first
// call primes it with a `data:` fetch (no socket) and wraps what appeared.
// Where the symbol is absent after that (a node whose bundled undici names it
// differently), this says so at `warn` and falls back to adding
// `connection: close` to the headers of a plain-object request, which undici
// reads the same way; `tests/vendored/sts_cluster_alternation.js` is what
// notices if neither took.
// ===========================================================================

const http = require('http');
const https = require('https');

const log = require('bunyan').createLogger({ name: 'fresh-connections',
  level: process.env.LOG_LEVEL || 'info' });

const DISPATCHER = Symbol.for('undici.globalDispatcher.1');
const MARK = Symbol.for('sts.tests.freshConnections');

function wrapTheDispatcher() {
  log.debug("Entering wrapTheDispatcher().");
  const base = globalThis[DISPATCHER];
  if (!base) {
    log.debug("Leaving wrapTheDispatcher(). No dispatcher.");
    return false;
  }
  if (base[MARK]) {
    log.debug("Leaving wrapTheDispatcher(). Already wrapped.");
    return true;
  }
  // A PROXY rather than an object copying methods, because undici's Agent
  // keeps its state in private fields and symbol-keyed properties: every
  // member other than `dispatch` is the real one, bound to the real agent.
  const wrapped = new Proxy(base, {
    get: function (target, prop) {
      if (prop === MARK) {
        return true;
      }
      if (prop === 'dispatch') {
        return function (options, handler) {
          return target.dispatch(Object.assign({}, options, { reset: true }),
                                 handler);
        };
      }
      const value = target[prop];
      return typeof value === 'function' ? value.bind(target) : value;
    }
  });
  globalThis[DISPATCHER] = wrapped;
  log.debug("Leaving wrapTheDispatcher(). Wrapped.");
  return true;
}

// The fallback, for a plain-object `init` only: a `Headers` or a `Request`
// is left alone rather than rebuilt, because rebuilding either is a change to
// what the job sends and not only to how.
function withConnectionClose(init) {
  log.debug("Entering withConnectionClose().");
  const options = Object.assign({}, init || {});
  const headers = options.headers;
  if (headers && (typeof headers.get === 'function' ||
                  Array.isArray(headers))) {
    log.debug("Leaving withConnectionClose(). Headers left as they were.");
    return init;
  }
  options.headers = Object.assign({}, headers || {}, { connection: 'close' });
  log.debug("Leaving withConnectionClose().");
  return options;
}

if (process.env.STS_TEST_FRESH_CONNECTIONS === '1') {
  http.globalAgent = new http.Agent({ keepAlive: false });
  https.globalAgent = new https.Agent({ keepAlive: false });

  if (typeof globalThis.fetch === 'function') {
    const realFetch = globalThis.fetch;
    let primed = null;
    let wrapped = false;

    const prime = function () {
      log.debug("Entering prime().");
      if (!primed) {
        primed = realFetch('data:,').then(function (r) {
          return r.text();
        }, function (e) {
          log.debug("Caught in prime(): " + ((e && e.message) || e));
          return '';
        }).then(function () {
          wrapped = wrapTheDispatcher();
          if (!wrapped) {
            log.warn('fresh-connections: fetch() exposes no global ' +
                     'dispatcher under ' + String(DISPATCHER) + ', so ' +
                     'connections are closed by a `connection: close` ' +
                     'header on plain-object requests only.');
          }
        });
      }
      log.debug("Leaving prime().");
      return primed;
    };

    globalThis.fetch = function (input, init) {
      log.debug("Entering fetch().");
      const self = this;
      log.debug("Leaving fetch().");
      return prime().then(function () {
        // Re-wrapped on every call, because a job that installs its own
        // global dispatcher after the first request would otherwise be back
        // on a pooled one without anything saying so.
        wrapped = wrapTheDispatcher();
        return realFetch.call(self, input,
                              wrapped ? init : withConnectionClose(init));
      });
    };
  }
  log.debug('fresh-connections: every request this job makes opens a new ' +
            'connection (STS_TEST_FRESH_CONNECTIONS=1).');
}

module.exports = {
  wrapTheDispatcher: wrapTheDispatcher,
  withConnectionClose: withConnectionClose
};
