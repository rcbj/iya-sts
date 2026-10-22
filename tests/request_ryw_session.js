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
//   R9. THE CODE EXCHANGE (2026-10-22, #820): an authorization code redirect
//       (a `Location` carrying `code=`) files its ticket under the code, with
//       the session's own outstanding ticket; a `POST /oauth2/token` naming
//       that code then waits for those two and not for another client's,
//       and its worker is synced to their write; its body reaches the
//       worker byte for byte;
//  R10. an unknown code is the global wait, never "wait for nothing";
//  R11. a refresh grant is the global wait;
//  R12. a body over 16 KiB, and a chunked one, are the global wait, and each
//       reaches the worker whole;
//  R13. over HTTP/2: with a `content-length` keyed by its code, without one
//       global, the body whole either way.
// ===========================================================================

const http = require('http');
const http2 = require('http2');
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
  "    const parts = [];",
  "    req.on('data', function (d) { parts.push(d); });",
  "    req.on('end', function () {",
  "      const body = Buffer.concat(parts);",
  "      res.setHeader('x-worker', String(wt.threadId));",
  "      res.setHeader('x-syncs', String(syncs));",
  "      if (req.url.indexOf('/login') === 0) {",
  "        res.setHeader('set-cookie', 'sts_session=ccc.h; Path=/');",
  "      }",
  "      const code = /^\\/authorize-code\\?code=([^&]+)/.exec(req.url);",
  "      if (code) {",
  "        res.statusCode = 302;",
  "        res.setHeader('location', 'https://rp.example/cb?code=' +",
  "                      code[1] + '&state=s');",
  "      }",
  "      res.end(body.length ? body : 'ok');",
  "    });",
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

// One POST, as a promise that remembers whether it has settled yet, with the
// answer's body. `chunked` sends no content-length and writes the body in
// pieces, so node frames it with Transfer-Encoding: chunked.
function post(port, urlPath, body, chunked) {
  log.debug("Entering post().");
  const call = { done: false, answer: null };
  call.promise = new Promise(function (resolve) {
    const headers = { 'content-type': 'application/x-www-form-urlencoded' };
    if (!chunked) {
      headers['content-length'] = String(Buffer.byteLength(body));
    }
    const req = http.request({ host: '127.0.0.1', port: port,
                               path: urlPath, method: 'POST', agent: false,
                               headers: headers },
                             function (answer) {
      const parts = [];
      answer.on('data', function (d) {
        parts.push(d);
      });
      answer.on('end', function () {
        call.done = true;
        call.answer = { status: answer.statusCode, headers: answer.headers,
                        body: Buffer.concat(parts) };
        resolve(call.answer);
      });
    });
    req.on('error', function (e) {
      log.debug("Caught in post(): " + ((e && e.message) || e));
      call.done = true;
      call.answer = { status: 0, headers: {}, body: Buffer.alloc(0) };
      resolve(call.answer);
    });
    if (chunked) {
      const data = Buffer.from(body);
      const step = Math.ceil(data.length / 3);
      for (let i = 0; i < data.length; i += step) {
        req.write(data.subarray(i, i + step));
      }
      req.end();
    } else {
      req.end(body);
    }
  });
  log.debug("Leaving post().");
  return call;
}

// The same over an HTTP/2 session, with or without a content-length.
function postH2(session, urlPath, body, withLength) {
  log.debug("Entering postH2().");
  const call = { done: false, answer: null };
  call.promise = new Promise(function (resolve) {
    const headers = { ':method': 'POST', ':path': urlPath,
                      'content-type': 'application/x-www-form-urlencoded' };
    if (withLength) {
      headers['content-length'] = String(Buffer.byteLength(body));
    }
    const stream = session.request(headers);
    const parts = [];
    let answerHeaders = {};
    stream.on('response', function (h) {
      answerHeaders = h;
    });
    stream.on('data', function (d) {
      parts.push(d);
    });
    stream.on('end', function () {
      call.done = true;
      call.answer = { status: answerHeaders[':status'],
                      headers: answerHeaders, body: Buffer.concat(parts) };
      resolve(call.answer);
    });
    stream.on('error', function (e) {
      log.debug("Caught in postH2(): " + ((e && e.message) || e));
      call.done = true;
      call.answer = { status: 0, headers: {}, body: Buffer.alloc(0) };
      resolve(call.answer);
    });
    stream.end(body);
  });
  log.debug("Leaving postH2().");
  return call;
}

// Every ticket either worker may still hold, announced: the stubs announce
// nothing themselves, so every request this file dispatched left one.
function announceAll(entries) {
  log.debug("Entering announceAll().");
  const range = [];
  for (let i = 1; i <= 2000; i++) {
    range.push(i);
  }
  entries.forEach(function (one) {
    pool.receiveCommitted(one, { wrote: false, tickets: range });
  });
  log.debug("Leaving announceAll().");
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
  // Which requests are read before the barrier (#820).
  const form = 'application/x-www-form-urlencoded';
  const ask = function (method, url, headers) {
    return pool.codeExchangeCandidate({ method: method, originalUrl: url,
                                        headers: headers });
  };
  t.check(ask('POST', '/oauth2/token',
              { 'content-type': form, 'content-length': '40' }) &&
          ask('POST', '/realm/r1/oauth2/token?x=1',
              { 'content-type': form + '; charset=UTF-8',
                'content-length': '16384' }) &&
          ask('POST', '/as1/oauth2/token',
              { 'content-type': form, 'content-length': '0' }),
          'R9. a small form POST to a token endpoint, a realm\'s or a named ' +
          'authorization server\'s, is read first', '');
  t.check(!ask('GET', '/oauth2/token',
               { 'content-type': form, 'content-length': '40' }) &&
          !ask('POST', '/oauth2/authorize',
               { 'content-type': form, 'content-length': '40' }) &&
          !ask('POST', '/oauth2/token',
               { 'content-type': 'application/json',
                 'content-length': '40' }) &&
          !ask('POST', '/oauth2/token', { 'content-type': form }) &&
          !ask('POST', '/oauth2/token',
               { 'content-type': form, 'content-length': '16385' }) &&
          !ask('POST', '/oauth2/token',
               { 'content-type': form, 'content-length': '40',
                 'transfer-encoding': 'chunked' }) &&
          !ask('POST', '/oauth2/token',
               { 'content-type': form, 'content-length': '40',
                 'content-encoding': 'gzip' }) &&
          !ask('POST', '/oauth2/token',
               { 'content-type': form, 'content-length': '4e1' }),
          'R12. anything else is not: another method, path or type, no ' +
          'length, over 16 KiB, a transfer or content encoding', '');
  log.debug("Leaving checkTheReaders().");
}

// R9 to R13: the code exchange, keyed by its code (#820), over HTTP/1.1 on
// `port` and HTTP/2 on `port2`, both fronting the same two stub workers.
async function checkTheCodeExchange(t, port, port2) {
  log.debug("Entering checkTheCodeExchange().");
  const workers = pool.workerTable().filter(function (w) {
    return w.pool === pool.PROTOCOL_POOL;
  });
  announceAll(workers);
  // The browser C, bound to a worker W by its first request.
  const C = 'sts_session=ddd.h';
  const first = await start(port, '/oauth2/authorize', C).promise;
  const W = workers.filter(function (w) {
    return String(w.pid) === first.headers['x-worker'];
  })[0];
  const O = workers.filter(function (w) {
    return w !== W;
  })[0];
  // Every request with no key is sent to the OTHER worker, O: least loaded
  // reads `served`. So the code exchange is never answered by the worker
  // that holds the code in memory, which is the case the wait is for.
  const served = W.served;
  W.served = 1e9;
  const session = http2.connect('http://127.0.0.1:' + port2);
  session.on('error', function (e) {
    log.debug("Caught in checkTheCodeExchange(): " + ((e && e.message) || e));
  });
  try {
    await sleep(50);
    announceAll(workers);
    // How many sync rounds O has answered, once it is current.
    const s0 = Number((await start(port, '/oauth2/token').promise)
      .headers['x-syncs']);
    await sleep(50);
    announceAll(workers);
    const before = pool.stats().sessionBarrier;

    // R9. Another client's write on W, and this browser's own sign-in.
    const other = arm(W, ['s:eee']);
    const sign = arm(W, ['s:ddd']);
    const redirect = await start(port, '/authorize-code?code=C9', C).promise;
    t.check(redirect.status === 302 &&
            /\?code=C9&/.test(String(redirect.headers.location)) &&
            redirect.headers['x-worker'] === String(W.pid),
            'R9. the authorization code redirect is answered by the ' +
            'browser\'s worker', JSON.stringify(redirect.headers));
    // The redirect's ticket is the next one after `sign`. It is finished as
    // the answer is piped out; a moment for it.
    const minted = sign + 1;
    await sleep(50);
    const sent = 'grant_type=authorization_code&code=C9&redirect_uri=' +
                 encodeURIComponent('https://rp.example/cb') +
                 '&code_verifier=' + 'v'.repeat(43);
    const exchange = post(port, '/oauth2/token', sent, false);
    await sleep(HELD_MS);
    t.check(!exchange.done, 'R9. the code exchange is held by its code\'s ' +
            'and its session\'s writes on another worker',
            JSON.stringify(exchange.answer));
    pool.receiveCommitted(W, { wrote: true, tickets: [sign, minted] });
    const t0 = Date.now();
    const answered = await exchange.promise;
    t.check(answered.status === 200 &&
            answered.headers['x-worker'] === String(O.pid) &&
            (Date.now() - t0) < 1000,
            'R9. and is answered on O once those two are announced, while ' +
            'another client\'s write is not', (Date.now() - t0) + 'ms ' +
            JSON.stringify(answered.headers));
    t.equal(Number(answered.headers['x-syncs']), s0 + 1,
            'R9. after O is synced to that write');
    t.check(answered.body.equals(Buffer.from(sent)),
            'R9. the body reaches the worker byte for byte',
            answered.body.toString('utf8').slice(0, 120));
    let now = pool.stats().sessionBarrier;
    t.check(now.codeKeyed === before.codeKeyed + 1 &&
            now.codesLearnt >= before.codesLearnt + 1,
            'R9. stats() counts the learnt code and the keyed exchange',
            JSON.stringify(now));

    // R10 to R12, all held together by the other client's write on W.
    const big = 'grant_type=authorization_code&code=C9&pad=' +
                'x'.repeat(20000);
    const unknown = post(port, '/oauth2/token',
                         'grant_type=authorization_code&code=NEVER-SEEN',
                         false);
    const refresh = post(port, '/oauth2/token',
                         'grant_type=refresh_token&refresh_token=C9', false);
    const oversized = post(port, '/oauth2/token', big, false);
    const chunkedBody = 'grant_type=authorization_code&code=C9&x=' +
                        'y'.repeat(300);
    const chunked = post(port, '/oauth2/token', chunkedBody, true);
    await sleep(HELD_MS);
    t.check(!unknown.done, 'R10. an unknown code waits globally: held by ' +
            'another client\'s write', JSON.stringify(unknown.answer));
    t.check(!refresh.done, 'R11. a refresh grant waits globally',
            JSON.stringify(refresh.answer));
    t.check(!oversized.done && !chunked.done,
            'R12. a body over 16 KiB, and a chunked one, wait globally',
            JSON.stringify([oversized.done, chunked.done]));
    pool.receiveCommitted(W, { wrote: false, tickets: [other] });
    const held = await Promise.all([unknown.promise, refresh.promise,
                                    oversized.promise, chunked.promise]);
    t.check(held.every(function (a) {
      return a.status === 200;
    }), 'R10-R12. and each is answered once it is announced',
            held.map(function (a) {
              return a.status;
            }).join(','));
    t.check(held[2].body.equals(Buffer.from(big)) &&
            held[3].body.equals(Buffer.from(chunkedBody)),
            'R12. both bodies reach the worker whole',
            held[2].body.length + ' ' + held[3].body.length);
    const after = pool.stats().sessionBarrier;
    t.check(after.codeKeyed === now.codeKeyed &&
            after.global >= now.global + 4,
            'R10-R12. counted as global dispatches, none keyed by a code',
            JSON.stringify(after));

    // R13. Over HTTP/2. A code learnt and its writes announced; another
    // client's write still outstanding on W.
    await start(port, '/authorize-code?code=C13', C).promise;
    await sleep(50);
    announceAll(workers);
    now = pool.stats().sessionBarrier;
    const other2 = arm(W, ['s:eee']);
    const h2Body = 'grant_type=authorization_code&code=C13&n=' +
                   'z'.repeat(200);
    const t1 = Date.now();
    const keyed = await postH2(session, '/realm/r1/oauth2/token', h2Body,
                               true).promise;
    t.check(keyed.status === 200 && (Date.now() - t1) < 1000 &&
            keyed.headers['x-worker'] === String(O.pid) &&
            keyed.body.equals(Buffer.from(h2Body)),
            'R13. an HTTP/2 code exchange with a content-length, under a ' +
            'realm, is keyed by its code: not held, its body whole',
            (Date.now() - t1) + 'ms ' + keyed.body.length);
    t.equal(pool.stats().sessionBarrier.codeKeyed, now.codeKeyed + 1,
            'R13. and counted as keyed by its code');
    const unframed = postH2(session, '/oauth2/token', h2Body, false);
    await sleep(HELD_MS);
    t.check(!unframed.done, 'R13. without a content-length it waits ' +
            'globally', JSON.stringify(unframed.answer));
    pool.receiveCommitted(W, { wrote: false, tickets: [other2] });
    const late = await unframed.promise;
    t.check(late.status === 200 && late.body.equals(Buffer.from(h2Body)),
            'R13. and is answered once it is announced, its body whole',
            late.status + ' ' + late.body.length);
  } finally {
    W.served = served;
    session.close();
    announceAll(workers);
  }
  log.debug("Leaving checkTheCodeExchange().");
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
    let front2 = null;
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
      // AND THE SAME POOL BEHIND AN HTTP/2 FRONT (#407), cleartext: the
      // main port's adapter, which is what lets express serve HTTP/2.
      const h2app = require('../common/http2_express').adapt(express());
      h2app.use(pool.middleware());
      front2 = http2.createServer({}, h2app);
      await new Promise(function (resolve) {
        front2.listen(0, '127.0.0.1', resolve);
      });
      const port2 = front2.address().port;
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

      await checkTheCodeExchange(t, port, port2);

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
      if (front2) {
        await new Promise(function (resolve) {
          front2.close(resolve);
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
