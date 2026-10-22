// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: request_ryw_session.js
//
// ===========================================================================
// SESSION READ-YOUR-WRITE IN THE REQUEST POOL (2026-10-22, #820).
//
// `workers.readYourWrite` is a mode: `session` (the default) holds a request
// to the writes of earlier requests that carried the same client keys, and
// `global` to everybody's. `common/request_pool.js`'s SESSION READ-YOUR-WRITE
// block argues it. A real pool of two stub worker THREADS (the pool's own
// `begin`/`ready` channel, and an answer to every sync round) and tickets
// armed by hand, as tests/request_client_gone.js arms one:
//
//   R1. the mode reader: true is session, false off, the words themselves;
//       and the client keys a request carries (every session cookie, the
//       pin, every flow, once each);
//   R2. session: a request from client A is NOT held by a finished,
//       unannounced write ticket of client B on another worker;
//   R3. session: a request with no client key still waits for every ticket
//       (global), and is answered once they are announced;
//   R4. session: client A IS held by its own ticket on another worker, is
//       answered once it is announced, and its worker is then synced to that
//       write's generation; B's write moving the generation syncs nothing for
//       A;
//   R5. global: A is held by B's tickets, and B's write makes A's worker sync;
//   R6. a session cookie an answer hands out files the ticket under it, so the
//       client's next request (carrying it) waits for that write;
//   R7. a pool pin naming a worker that is not the one chosen is no key: the
//       request waits globally;
//   R8. bounded: a key evicted with a ticket outstanding spills it to every
//       keyed request, until that ticket is announced.
// ===========================================================================

const http = require('http');
const os = require('os');
const fs = require('fs');
const path = require('path');
const express = require('express');
const pool = require('../common/request_pool');

const log = require('bunyan').createLogger({
  name: 'request_ryw_session',
  level: process.env.LOG_LEVEL || 'info' });

// How long a held request is watched before it is released by hand: far
// inside the 2,000 ms ticket bound, so "still waiting" means held.
const HELD_MS = 400;

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

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

// A worker THREAD that answers every request at once with its threadId and
// how many sync rounds it has answered, answers every sync round `ok`, and
// hands out a session cookie on /login.
const STUB = [
  "'use strict';",
  "const http = require('http');",
  "const wt = require('worker_threads');",
  "let syncs = 0;",
  "wt.parentPort.on('message', function (m) {",
  "  if (m && m.stop) { process.exit(0); }",
  "  if (m && m.sync) {",
  "    syncs += 1;",
  "    wt.parentPort.postMessage({ sync: true, id: m.id, ok: true });",
  "    return;",
  "  }",
  "  if (!m || !m.begin) { return; }",
  "  const server = http.createServer(function (req, res) {",
  "    res.setHeader('x-worker', String(wt.threadId));",
  "    res.setHeader('x-syncs', String(syncs));",
  "    if (req.url.indexOf('/login') === 0) {",
  "      res.setHeader('set-cookie', 'sts_session=ccc.h; Path=/');",
  "    }",
  "    res.end('ok');",
  "  });",
  "  server.listen(m.socket, function () {",
  "    wt.parentPort.postMessage({ ready: true });",
  "  });",
  "});",
  ""
].join('\n');

// One GET, as a promise that remembers whether it has settled yet.
function start(port, urlPath, cookie) {
  log.debug("Entering start().");
  const call = { done: false, answer: null };
  call.promise = new Promise(function (resolve) {
    const headers = cookie ? { cookie: cookie } : {};
    const req = http.get({ host: '127.0.0.1', port: port, path: urlPath,
                           agent: false, headers: headers },
                         function (answer) {
      answer.resume();
      answer.on('end', function () {
        call.done = true;
        call.answer = { status: answer.statusCode, headers: answer.headers };
        resolve(call.answer);
      });
    });
    req.on('error', function (e) {
      log.debug("Caught in start(): " + ((e && e.message) || e));
      call.done = true;
      call.answer = { status: 0, headers: {} };
      resolve(call.answer);
    });
  });
  log.debug("Leaving start().");
  return call;
}

// A finished, unannounced ticket on `entry`, filed under `keys`.
function arm(entry, keys) {
  log.debug("Entering arm().");
  const ticket = pool.dispatchTicket(entry, 'GET /armed', keys);
  pool.ticketFinished(entry, ticket);
  log.debug("Leaving arm().");
  return ticket;
}

function checkTheReaders(t) {
  log.debug("Entering checkTheReaders().");
  const of = pool.readYourWriteModeOf;
  t.check(of(true) === 'session' && of('true') === 'session' &&
          of('session') === 'session' && of(false) === 'off' &&
          of('false') === 'off' && of('off') === 'off' &&
          of('global') === 'global' && of(undefined) === 'off',
          'R1. true is session, false off, and the words are themselves',
          [of(true), of('true'), of(false), of('global')].join(','));
  const keys = pool.clientKeysOf({
    headers: { cookie: 'sts_session=abc.h1; sts_pool=7; other=x; ' +
                       'sts_session=abc.h2' },
    originalUrl: '/authn/login?authn=p1&consent=c2' }, pool.PROTOCOL_POOL);
  t.equal(keys.join(' '), 's:abc p:7 authn:p1 consent:c2',
          'R1. every session cookie (once), the pin and every flow');
  t.equal(pool.clientKeysOf({ headers: {}, originalUrl: '/oauth2/token' },
                            pool.PROTOCOL_POOL).length, 0,
          'R1. a back-channel request carries no key');
  log.debug("Leaving checkTheReaders().");
}

async function checkThePool(t) {
  log.debug("Entering checkThePool().");
  const stubPath = path.join(os.tmpdir(), 'sts-ryw-stub-' + process.pid +
                             '.js');
  fs.writeFileSync(stubPath, STUB);
  await withEnv({ STS_WORKERS_REQUEST_COUNT: '2',
                  STS_WORKERS_DISPATCH: '*',
                  STS_WORKERS_READ_YOUR_WRITE: 'session' },
                async function () {
    pool.reset();
    pool.useWorkerModule(stubPath);
    let front = null;
    try {
      const one = await pool.queueFork(pool.PROTOCOL_POOL, 0);
      const two = await pool.queueFork(pool.PROTOCOL_POOL, 1);
      t.check(one && one.ready && two && two.ready,
              'two stub workers are up', '');
      const app = express();
      app.use(pool.middleware());
      front = http.createServer(app);
      await new Promise(function (resolve) {
        front.listen(0, '127.0.0.1', resolve);
      });
      const port = front.address().port;
      const A = 'sts_session=aaa.h';

      // Where client A is held: its first request binds it to a worker.
      const first = await start(port, '/oauth2/authorize', A).promise;
      const table = pool.workerTable();
      const X = table.filter(function (w) {
        return String(w.pid) === first.headers['x-worker'];
      })[0];
      const Y = table.filter(function (w) {
        return w !== X && w.pool === X.pool;
      })[0];
      t.check(X && Y, 'client A is bound to one of the two workers',
              JSON.stringify(first.headers));

      const syncsOf = function (answer) {
        return Number(answer.headers['x-syncs']);
      };

      // R2: B's writes on BOTH workers hold nobody keyed as A.
      const b1 = arm(X, ['s:bbb']);
      const b2 = arm(Y, ['s:bbb']);
      const t0 = Date.now();
      const a2 = await start(port, '/oauth2/authorize', A).promise;
      t.check(a2.status === 200 && (Date.now() - t0) < 1000 &&
              a2.headers['x-worker'] === String(X.pid),
              'R2. A is not held by B\'s unannounced tickets',
              (Date.now() - t0) + 'ms ' + JSON.stringify(a2.headers));

      // R3: a request with no key waits for B's tickets (whichever worker
      // serves it, the other's ticket holds it), then is answered.
      const anon = start(port, '/oauth2/token');
      await sleep(HELD_MS);
      t.check(!anon.done, 'R3. a request with no client key is held by ' +
              'every finished ticket (global)', JSON.stringify(anon.answer));
      // B's writes are announced, and move the generation.
      pool.receiveCommitted(X, { wrote: true, tickets: [b1] });
      pool.receiveCommitted(Y, { wrote: true, tickets: [b2] });
      const anonAnswer = await anon.promise;
      t.equal(anonAnswer.status, 200,
              'R3. and is answered once they are announced');

      // R4: B's writes moved the generation; A's next request asks X for
      // no sync, because none of the writes was A's.
      const before = syncsOf(await start(port, '/oauth2/authorize',
                                         A).promise);
      const after = syncsOf(await start(port, '/oauth2/authorize',
                                        A).promise);
      t.equal(after, before,
              'R4. another client\'s write makes A\'s worker sync nothing');

      // A's own write, answered on Y and not yet announced, holds A on X.
      const own = arm(Y, ['s:aaa']);
      const held = start(port, '/oauth2/authorize', A);
      await sleep(HELD_MS);
      t.check(!held.done, 'R4. A IS held by its own unannounced ticket on ' +
              'another worker', JSON.stringify(held.answer));
      pool.receiveCommitted(Y, { wrote: true, tickets: [own] });
      const heldAnswer = await held.promise;
      t.check(heldAnswer.status === 200 &&
              syncsOf(heldAnswer) === after + 1,
              'R4. and once it is announced, A\'s worker is synced to that ' +
              'write before answering',
              after + ' -> ' + JSON.stringify(heldAnswer.headers));

      // R7: a pin naming a worker that does not exist is no key: global.
      const p1 = arm(X, ['s:bbb']);
      const p2 = arm(Y, ['s:bbb']);
      const pinned = start(port, '/oauth2/authorize', 'sts_pool=99999');
      await sleep(HELD_MS);
      t.check(!pinned.done, 'R7. a pin the route did not honour is no key ' +
              '(global)', JSON.stringify(pinned.answer));
      pool.receiveCommitted(X, { wrote: false, tickets: [p1] });
      pool.receiveCommitted(Y, { wrote: false, tickets: [p2] });
      await pinned.promise;

      // R6: the session cookie /login hands out files its ticket under it.
      const login = await start(port, '/login').promise;
      const writer = pool.workerTable().filter(function (w) {
        return String(w.pid) === login.headers['x-worker'];
      })[0];
      const other = pool.workerTable().filter(function (w) {
        return w !== writer && w.pool === writer.pool;
      })[0];
      // The ticket is finished as the answer is piped out; a moment for it.
      await sleep(50);
      let released = false;
      const waiting = pool.awaitCommitConfirmations(other, ['s:ccc'])
        .then(function () {
          released = true;
        });
      await sleep(HELD_MS);
      t.check(!released, 'R6. the next request carrying the cookie the ' +
              'answer handed out waits for that answer\'s write', '');
      const range = [];
      for (let i = 1; i <= 200; i++) {
        range.push(i);
      }
      pool.receiveCommitted(writer, { wrote: false, tickets: range });
      await waiting;
      t.check(released, 'R6. and is released once it is announced', '');

      // R5: global mode restores the old behaviour.
      await withEnv({ STS_WORKERS_READ_YOUR_WRITE: 'global' },
                    async function () {
        const g1 = arm(X, ['s:bbb']);
        const g2 = arm(Y, ['s:bbb']);
        const globalHeld = start(port, '/oauth2/authorize', A);
        await sleep(HELD_MS);
        t.check(!globalHeld.done, 'R5. global: A is held by B\'s tickets',
                JSON.stringify(globalHeld.answer));
        const gBefore = syncsOf(await (async function () {
          pool.receiveCommitted(Y, { wrote: true, tickets: [g2] });
          pool.receiveCommitted(X, { wrote: false, tickets: [g1] });
          return globalHeld.promise;
        })());
        // Y's write moved the generation past X: A's next request syncs.
        const g3 = arm(Y, ['s:bbb']);
        pool.receiveCommitted(Y, { wrote: true, tickets: [g3] });
        const gAfter = syncsOf(await start(port, '/oauth2/authorize',
                                           A).promise);
        t.equal(gAfter, gBefore + 1,
                'R5. global: another client\'s write makes A\'s worker ' +
                'sync');
        t.equal(pool.stats().sessionBarrier.mode, 'global',
                'R5. stats() names the mode');
      });
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
        log.debug("Caught in checkThePool(): " + ((e && e.message) || e));
      }
    }
  });
  log.debug("Leaving checkThePool().");
}

// R8, with table entries the pool never forked: the bound and the prune.
async function checkTheBounds(t) {
  log.debug("Entering checkTheBounds().");
  await withEnv({ STS_WORKERS_READ_YOUR_WRITE: 'session' },
                async function () {
    pool.reset();
    const X = { pid: 901, pool: pool.PROTOCOL_POOL, generation: 0 };
    const Y = { pid: 902, pool: pool.PROTOCOL_POOL, generation: 0 };
    const kept = arm(Y, ['s:first']);
    for (let i = 0; i < 20000; i++) {
      pool.dispatchTicket(X, 'GET /many', ['s:k' + i]);
    }
    const rw = pool.stats().sessionBarrier;
    t.check(rw.keys === 20000 && rw.evicted === 1 && rw.spilled === 1,
            'R8. the table is bounded, and the key evicted with a ticket ' +
            'outstanding spills it', JSON.stringify(rw));
    let released = false;
    const waiting = pool.awaitCommitConfirmations(X, ['s:another'])
      .then(function () {
        released = true;
      });
    await sleep(HELD_MS);
    t.check(!released, 'R8. a spilled ticket holds every keyed request', '');
    pool.receiveCommitted(Y, { wrote: false, tickets: [kept] });
    await waiting;
    t.check(released && pool.stats().sessionBarrier.spilled === 0,
            'R8. and is released, and forgotten, once announced', '');
  });
  pool.reset();
  log.debug("Leaving checkTheBounds().");
}

async function run(t) {
  log.debug("Entering run().");
  checkTheReaders(t);
  await checkThePool(t);
  await checkTheBounds(t);
  pool.reset();
  log.debug("Leaving run().");
}

module.exports = {
  name: 'request_ryw_session',
  describe: 'session read-your-write: a request waits for its own client\'s ' +
            'writes only, a request with no client key for everybody\'s, ' +
            'and `global` restores the old barrier (#820)',
  run: run
};
