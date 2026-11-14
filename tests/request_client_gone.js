// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: request_client_gone.js
//
// ===========================================================================
// A DISPATCHED REQUEST WHOSE CLIENT LEFT, AND THE HEALTH PROBE THAT MADE IT
// LEAVE (#624, 2026-10-14).
//
// Under the 1M → 10M LDAP bulk load on 8081 `common/request_pool.js` dropped
// two tickets with STS-WORKER-0008, both the same request:
//
//   ticket 1218283 GET /healthcheck on protocol worker 4, answered 30.7s ago
//   (dispatched 128.4s ago); that worker has announced 2579 commit(s) since
//   without naming it (last 0.1s ago): LOST.
//
// The log around each says what happened, and this file reproduces it in
// process:
//
//   * the probe was DISPATCHED and held at the front by the read barrier —
//     worker 4 missed one (STS-WORKER-0027) at the moment each was finally
//     sent, five seconds after its ticket — so the compose healthcheck's 5 s
//     timeout had already closed its connection;
//   * proxy() hangs its "the client went away" handlers only when it is
//     called, so it never heard that, and a destroyed request never emits
//     `end`, so `upstream.end()` never ran and the worker was handed a
//     connection with no request on it;
//   * the worker's HTTP PARSER answered that connection 408 when its
//     `headersTimeout` (70 s, checked every 30 s) ran out — 93 and 96 s after
//     each was sent — and the front process took the 408 as an answer and
//     armed the ticket; no handler ran, so the worker never named it, however
//     many commits it announced.
//
// What is asserted:
//
//   1. a request whose client left while it waited is not sent to the worker,
//      and its ticket is released at once — under a continuous stream of
//      writes the same worker announces, which is what "announced 2579
//      commits since" was; the stand-in worker answers an empty connection
//      408 after 400 ms as the real one does after 70 s, so the defect shows
//      as a ticket the reaper calls LOST;
//   2. a response whose `end()` ran and whose peer then left is announced in
//      the same tick, however long the flush takes; one closed before its
//      `end()` still waits for the flush, because its handler may yet write;
//   3. `GET /healthcheck` is answered by the front process within a probe's
//      timeout while the only worker is blocked and a ticket is armed — and a
//      dispatched path, the control, is not.
// ===========================================================================

const http = require('http');
const os = require('os');
const fs = require('fs');
const path = require('path');
const EventEmitter = require('events');
const express = require('express');
const pool = require('../common/request_pool');
const CommitAnnouncer = require('../common/commit_announcer');

const log = require('bunyan').createLogger({ name: 'request_client_gone',
  level: process.env.LOG_LEVEL || 'info' });

// How long a probe may take here: well inside the compose healthcheck's 5 s,
// and far short of the 2,000 ms ticket wait the probe used to pay first.
const PROBE_BOUND_MS = 1000;

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

// Sets environment variables for the body, and puts them back after it
// AWAITS — tests/request_barrier.js' withReadYourWrite() says what not
// awaiting cost.
async function withEnv(vars, fn) {
  log.debug("Entering withEnv().");
  const had = {};
  Object.keys(vars).forEach(function (name) {
    had[name] = process.env[name];
    process.env[name] = vars[name];
  });
  try {
    log.debug("Leaving withEnv().");
    return await fn();
  } finally {
    Object.keys(had).forEach(function (name) {
      if (had[name] === undefined) {
        delete process.env[name];
      } else {
        process.env[name] = had[name];
      }
    });
  }
}

// A store whose flush never settles — a flush that keeps running under a
// continuous write load, or a worker whose event loop is blocked — and whose
// answers are held for their commit, as postgres's are.
function stuckStore() {
  log.debug("Entering stuckStore().");
  const s = {
    rows: 0,
    flushes: 0,
    flush: function () {
      log.debug("Entering stuckStore flush().");
      s.flushes += 1;
      log.debug("Leaving stuckStore flush().");
      return new Promise(function () {});
    },
    flushMinted: function () {
      log.debug("Entering stuckStore flushMinted().");
      log.debug("Leaving stuckStore flushMinted().");
      return Promise.resolve({ written: false });
    },
    changeRowsWritten: function () {
      log.debug("Entering stuckStore changeRowsWritten().");
      log.debug("Leaving stuckStore changeRowsWritten().");
      return s.rows;
    },
    answersAfterCommit: function () {
      log.debug("Entering stuckStore answersAfterCommit().");
      log.debug("Leaving stuckStore answersAfterCommit().");
      return true;
    }
  };
  log.debug("Leaving stuckStore().");
  return s;
}

// The announcer a worker builds, its channel replaced by the pool's own
// receiving end for `entry` — which is all the channel does.
function announcerFor(entry, persistence) {
  log.debug("Entering announcerFor().");
  log.debug("Leaving announcerFor().");
  return new CommitAnnouncer({
    log: log,
    config: { value: function (key) {
      return key === 'workers.readYourWrite' ? true : undefined;
    } },
    errorCodes: { tag: function (code) {
      return '[' + code + '] ';
    } },
    persistence: persistence,
    send: function (message) {
      pool.receiveCommitted(entry, message.committed);
    }
  });
}

// A CONTINUOUS STREAM OF WRITES on `entry`, every few milliseconds, each
// answered after its commit and announced by `announcer` — the LDAP adds
// worker 4 was answering. Returns a function that stops it and says how many.
function writeStream(entry, announcer, persistence) {
  log.debug("Entering writeStream().");
  let count = 0;
  const timer = setInterval(function () {
    const ticket = pool.dispatchTicket(entry, 'operation ldap.add');
    persistence.rows += 1;
    announcer.noteOperationFinished(ticket, true);
    pool.ticketFinished(entry, ticket);
    count += 1;
  }, 10);
  log.debug("Leaving writeStream().");
  return function () {
    clearInterval(timer);
    return count;
  };
}

// ---------------------------------------------------------------------------
// 1. A REQUEST WHOSE CLIENT LEFT WHILE IT WAITED.
// ---------------------------------------------------------------------------

// The stand-in worker: counts connections and requests, answers a request
// 200, and — as node's server does with `headersTimeout` — answers a
// connection that never sent a request 408, here after 400 ms rather than
// 70 s.
async function silentConnectionWorker() {
  log.debug("Entering silentConnectionWorker().");
  const socketPath = path.join(os.tmpdir(), 'sts-client-gone-' + process.pid +
                               '-' + Date.now() + '.sock');
  const seen = { connections: 0, requests: 0 };
  const server = http.createServer({ connectionsCheckingInterval: 100 },
                                   function (req, res) {
    seen.requests += 1;
    res.end('ok');
  });
  server.headersTimeout = 400;
  server.requestTimeout = 0;
  server.on('connection', function () {
    seen.connections += 1;
  });
  await new Promise(function (resolve) {
    server.listen(socketPath, resolve);
  });
  log.debug("Leaving silentConnectionWorker().");
  return { socketPath: socketPath, seen: seen, server: server };
}

async function checkAGoneClientIsNotSent(t) {
  log.debug("Entering checkAGoneClientIsNotSent().");
  t.log.info('=== a request whose client left while it waited is not sent ' +
             '===');
  pool.reset();
  const worker = await silentConnectionWorker();
  const entry = { pid: 624, pool: pool.PROTOCOL_POOL,
                  socket: worker.socketPath, tickets: new Set(),
                  agent: new http.Agent({ keepAlive: false, maxSockets: 4 }),
                  inFlight: 0, served: 0, generation: 0 };
  await withEnv({ STS_WORKERS_READ_YOUR_WRITE: 'true' }, async function () {
    const persistence = stuckStore();
    const announcer = announcerFor(entry, persistence);
    const stop = writeStream(entry, announcer, persistence);
    let probeTicket = 0;
    // THE FRONT PROCESS, with the barrier's wait made explicit: the ticket
    // is taken as the middleware takes it, and proxy() is called only once
    // the client has gone — which is where the 5 s barrier left the probe.
    const app = express();
    app.use(function (req, res) {
      probeTicket = pool.dispatchTicket(entry, 'GET /healthcheck');
      res.on('close', function () {
        setTimeout(function () {
          pool.proxy(entry, req, res, 0, probeTicket);
        }, 50);
      });
    });
    const front = http.createServer(app);
    await new Promise(function (resolve) {
      front.listen(0, '127.0.0.1', resolve);
    });
    try {
      // THE PROBE, which gives up first, as the compose healthcheck did.
      const probe = http.get({ host: '127.0.0.1',
                               port: front.address().port,
                               path: '/healthcheck', agent: false });
      probe.on('error', function (e) {
        log.debug("Caught in checkAGoneClientIsNotSent(): " +
                  ((e && e.message) || e));
      });
      setTimeout(function () {
        probe.destroy();
      }, 100);
      // Long enough for the stand-in's 408 to have come and gone.
      await sleep(1200);
      const writes = stop();
      t.check(writes > 20,
              'the worker announced a continuous stream of writes meanwhile',
              String(writes));
      t.equal(worker.seen.connections, 0,
              'NOTHING was sent to the worker for a client that had gone',
              'before #624 the worker was handed an empty connection and ' +
              'its parser answered it 408 (' + worker.seen.connections +
              ' connection(s), ' + worker.seen.requests + ' request(s))');
      t.equal(entry.inFlight, 0,
              'so it holds no place in the worker\'s queue',
              'before #624 it held one for the 70 to 100 s the 408 took');
      const said = pool.describeTicket(probeTicket, Date.now() + 31000);
      pool.reapStuckTickets(Infinity, Date.now() + 31000);
      t.equal(pool.stats().tickets.reaped, 0,
              'and its ticket was released at once rather than dropped as ' +
              'LOST thirty seconds later',
              'STS-WORKER-0008 would say: ' + said);
      t.equal(pool.stats().tickets.outstanding, 0,
              'nothing is left outstanding once the stream stops',
              JSON.stringify(pool.stats().tickets));
    } finally {
      stop();
      await new Promise(function (resolve) {
        front.close(resolve);
      });
      entry.agent.destroy();
      await new Promise(function (resolve) {
        worker.server.close(resolve);
      });
      try {
        fs.unlinkSync(worker.socketPath);
      } catch (e) {
        log.debug("Caught in checkAGoneClientIsNotSent(): " +
                  ((e && e.message) || e));
      }
    }
  });
  pool.reset();
  log.debug("Leaving checkAGoneClientIsNotSent().");
}

// ---------------------------------------------------------------------------
// 2. A RESPONSE WHOSE PEER LEFT, IN THE WORKER.
//
// A response as node ends one: `writableEnded` once the real `end()` has run
// (which, on a store that holds answers, is after the commit), then `close`
// with no `finish` when the peer has gone before the bytes were flushed.
// ---------------------------------------------------------------------------
function response(ended) {
  log.debug("Entering response().");
  const res = new EventEmitter();
  res.writableEnded = ended;
  log.debug("Leaving response().");
  return res;
}

async function checkAClosedResponseIsAnnounced(t) {
  log.debug("Entering checkAClosedResponseIsAnnounced().");
  t.log.info('=== a response whose peer left is announced by what it had ' +
             'done ===');
  pool.reset();
  const a = { pid: 6241, pool: pool.PROTOCOL_POOL, tickets: new Set(),
              inFlight: 0 };
  await withEnv({ STS_WORKERS_READ_YOUR_WRITE: 'true' }, async function () {
    const persistence = stuckStore();
    const announcer = announcerFor(a, persistence);
    const stop = writeStream(a, announcer, persistence);
    try {
      await sleep(50);

      // ENDED, THEN CLOSED: its hold released it, so it is in the store.
      const ended = pool.dispatchTicket(a, 'GET /oauth2/authorize');
      const one = response(true);
      announcer.watchResponse({ stsPoolTicket: ended }, one);
      pool.ticketFinished(a, ended);
      one.emit('close');
      t.check(pool.describeTicket(ended).indexOf('not recorded') >= 0,
              'a response whose end() ran and whose peer then left is ' +
              'announced in the same tick, with the flush stuck',
              'before #624 it waited for that flush: ' +
              pool.describeTicket(ended));

      // CLOSED BEFORE ITS end(): the handler may still write.
      const cut = pool.dispatchTicket(a, 'POST /scim/v2/Users');
      const two = response(false);
      announcer.watchResponse({ stsPoolTicket: cut }, two);
      pool.ticketFinished(a, cut);
      two.emit('close');
      await sleep(30);
      t.check(pool.describeTicket(cut).indexOf('not recorded') < 0,
              'one closed before its end() still waits for the flush, ' +
              'because its handler may yet write',
              pool.describeTicket(cut));

      // FINISHED: as #620 made it.
      const done = pool.dispatchTicket(a, 'GET /scim/v2/Users');
      const three = response(true);
      announcer.watchResponse({ stsPoolTicket: done }, three);
      three.emit('finish');
      three.emit('close');
      pool.ticketFinished(a, done);
      t.check(pool.describeTicket(done).indexOf('not recorded') >= 0,
              'a finished response is announced at once, as before',
              pool.describeTicket(done));
    } finally {
      stop();
    }
  });
  pool.reset();
  log.debug("Leaving checkAClosedResponseIsAnnounced().");
}

// ---------------------------------------------------------------------------
// 3. THE HEALTH PROBE, WITH THE ONLY WORKER BLOCKED.
//
// A real pool of one worker THREAD running a stub that accepts and never
// answers — a worker whose event loop is blocked, from outside — with a
// ticket armed on it, so a dispatched read waits the 2,000 ms bound before
// it even reaches the worker. The stub speaks the channel the real one does
// (`begin` in, `ready` out), as tests/request_worker_replacement.js' does.
// ---------------------------------------------------------------------------
const BLOCKED_STUB = [
  "'use strict';",
  "const http = require('http');",
  "const wt = require('worker_threads');",
  "wt.parentPort.on('message', function (m) {",
  "  if (m && m.stop) { process.exit(0); }",
  "  if (!m || !m.begin) { return; }",
  "  const server = http.createServer(function () {});",
  "  server.listen(m.socket, function () {",
  "    wt.parentPort.postMessage({ ready: true });",
  "  });",
  "});",
  ""
].join('\n');

// One GET, answered or not within `ms`.
function getWithin(port, urlPath, ms) {
  log.debug("Entering getWithin().");
  log.debug("Leaving getWithin().");
  return new Promise(function (resolve) {
    const began = Date.now();
    const req = http.get({ host: '127.0.0.1', port: port, path: urlPath,
                           agent: false }, function (answer) {
      let text = '';
      answer.on('data', function (chunk) {
        text += chunk;
      });
      answer.on('end', function () {
        resolve({ status: answer.statusCode, text: text,
                  ms: Date.now() - began });
      });
    });
    req.on('error', function (e) {
      log.debug("Caught in getWithin(): " + ((e && e.message) || e));
    });
    req.setTimeout(ms, function () {
      req.destroy();
      resolve({ status: 0, text: 'timed out', ms: Date.now() - began });
    });
  });
}

async function checkTheProbeIsAnsweredHere(t) {
  log.debug("Entering checkTheProbeIsAnsweredHere().");
  t.log.info('=== the health probe is answered within its timeout while the ' +
             'worker is blocked ===');
  t.check(pool.dispatched('/healthcheck') === false &&
          pool.dispatched('/realm/acme/healthcheck') === false,
          '/healthcheck is never dispatched, in a realm or out of one',
          'it was, with `workers.dispatch` at its default of *');
  const stubPath = path.join(os.tmpdir(), 'sts-blocked-stub-' + process.pid +
                             '.js');
  fs.writeFileSync(stubPath, BLOCKED_STUB);
  await withEnv({ STS_WORKERS_REQUEST_COUNT: '1',
                  STS_WORKERS_DISPATCH: '*',
                  STS_WORKERS_READ_YOUR_WRITE: 'true' }, async function () {
    pool.reset();
    pool.useWorkerModule(stubPath);
    let front = null;
    try {
      const entry = await pool.queueFork(pool.PROTOCOL_POOL, 0);
      t.check(entry && entry.ready, 'the blocked worker is up', '');
      t.check(pool.dispatched('/oauth2/userinfo'),
              'and dispatching is on — the control below depends on it', '');
      // A WRITE IT ANSWERED AND NEVER ANNOUNCED, which a reader served by any
      // other worker — or by this process — waits for.
      const armed = pool.dispatchTicket(entry, 'operation ldap.add');
      pool.ticketFinished(entry, armed);

      const app = express();
      app.use(pool.middleware());
      app.get('/healthcheck', function (req, res) {
        res.status(200).json({ message: 'Success' });
      });
      front = http.createServer(app);
      await new Promise(function (resolve) {
        front.listen(0, '127.0.0.1', resolve);
      });
      const port = front.address().port;

      const probe = await getWithin(port, '/healthcheck', PROBE_BOUND_MS);
      t.equal(probe.status, 200,
              'GET /healthcheck is answered 200 within ' + PROBE_BOUND_MS +
              'ms', 'before #624 it waited for the ticket and the blocked ' +
              'worker: ' + JSON.stringify(probe));
      t.check(/Success/.test(probe.text),
              'by this process\'s own route', probe.text);

      const control = await getWithin(port, '/oauth2/userinfo',
                                      PROBE_BOUND_MS);
      t.equal(control.status, 0,
              'THE CONTROL: a dispatched path in the same state is not ' +
              'answered within the bound',
              JSON.stringify(control));
    } finally {
      if (front) {
        front.closeAllConnections();
        await new Promise(function (resolve) {
          front.close(resolve);
        });
      }
      await pool.stop(3000);
      pool.reset();
      try {
        fs.unlinkSync(stubPath);
      } catch (e) {
        log.debug("Caught in checkTheProbeIsAnsweredHere(): " +
                  ((e && e.message) || e));
      }
    }
  });
  log.debug("Leaving checkTheProbeIsAnsweredHere().");
}

async function run(t) {
  log.debug("Entering run().");
  await checkAGoneClientIsNotSent(t);
  await checkAClosedResponseIsAnnounced(t);
  await checkTheProbeIsAnsweredHere(t);
  // The pool is process-wide module state; nothing armed here may outlive it.
  pool.reset();
  log.debug("Leaving run().");
}

module.exports = {
  name: 'request_client_gone',
  describe: 'that a dispatched request whose client left while it waited is ' +
            'not sent to a worker and releases its ticket, that a response ' +
            'whose peer left after its end() is announced at once, and that ' +
            '/healthcheck is answered by the front process within a ' +
            'probe\'s timeout while a worker is blocked (#624)',
  run: run
};
