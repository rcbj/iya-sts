'use strict';
//
// File: request_proxy_replay.js
//
// ===========================================================================
// A DISPATCHED REQUEST NONE OF WHOSE BYTES REACHED ITS WORKER IS SENT AGAIN,
// AND EVERY DISPATCHED REQUEST HAS A CONNECTION OF ITS OWN (#77, 2026-09-26).
//
// `common/request_pool.js`'s proxy() answered `502 … write EPIPE` for a
// `POST /oauth2/register` in a dispatch-mode CI run while the worker it named
// went on serving: the worker's end of the connection was closed before this
// process wrote. Two things came out of it.
//
// * **THE AGENT'S `keepAlive: false` DID NOT MEAN WHAT IT SAID.** Node sends
//   `Connection: keep-alive` from any agent with a finite `maxSockets` and
//   hands a freed socket to the next queued request, and proxy() forwarded the
//   client's own hop-by-hop headers besides. proxy() now sends
//   `Connection: close`, strips the client's, and a connection carries one
//   request.
// * **A REQUEST NO BYTE OF WHICH WAS DELIVERED IS SENT AGAIN, ONCE, ON A NEW
//   CONNECTION TO THE SAME WORKER.** A write the kernel refused delivers
//   nothing, so a worker that was never handed a byte ran no handler, and
//   sending it again cannot do anything twice. A request some byte of which
//   WAS delivered is never repeated — the worker may be running it — and is
//   the 502 it always was.
//
// Real sockets and no mock of http, on `tests/request_barrier.js` section 8's
// arrangement: an express app in front calling proxy(), a unix socket behind
// it whose server misbehaves on purpose.
// ===========================================================================

const http = require('http');
const os = require('os');
const path = require('path');
const fs = require('fs');
const express = require('express');
const pool = require('../common/request_pool');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for.
const log = require('bunyan').createLogger({ name: 'request_proxy_replay',
  level: process.env.LOG_LEVEL || 'info' });

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) { setTimeout(resolve, ms); });
}

// A worker socket whose server does whatever `behave` says with each
// connection and each request. Records what it was handed.
async function workerSocket(tag, behave) {
  log.debug("Entering workerSocket(). " + tag);
  const socketPath = path.join(os.tmpdir(), 'sts-replay-' + tag + '-' +
                               process.pid + '-' + Date.now() + '.sock');
  const seen = { connections: 0, requests: [] };
  const server = http.createServer(function (req, res) {
    const chunks = [];
    req.on('data', function (chunk) {
      chunks.push(chunk);
    });
    req.on('end', function () {
      const one = { url: req.url, headers: req.headers,
                    body: Buffer.concat(chunks).toString('utf8'),
                    socket: req.socket };
      seen.requests.push(one);
      behave.request(one, res);
    });
  });
  server.on('connection', function (socket) {
    seen.connections++;
    if (behave.connection) {
      behave.connection(seen.connections, socket);
    }
  });
  await new Promise(function (resolve) {
    server.listen(socketPath, resolve);
  });
  log.debug("Leaving workerSocket().");
  return { socketPath: socketPath, seen: seen, server: server };
}

async function closeWorker(worker, entry) {
  log.debug("Entering closeWorker().");
  entry.agent.destroy();
  await new Promise(function (resolve) { worker.server.close(resolve); });
  try {
    fs.unlinkSync(worker.socketPath);
  } catch (e) {
    log.debug("Caught in closeWorker(): " + ((e && e.message) || e));
  }
  log.debug("Leaving closeWorker().");
}

function entryFor(pid, worker, maxSockets) {
  log.debug("Entering entryFor().");
  log.debug("Leaving entryFor().");
  return { pid: pid, socket: worker.socketPath, tickets: new Set(),
           agent: new http.Agent({ keepAlive: false,
                                   maxSockets: maxSockets || 64 }),
           inFlight: 0, served: 0, generation: 0 };
}

// The front process: every request proxied to `entry`, with no ticket.
async function front(entry) {
  log.debug("Entering front().");
  const app = express();
  app.use(function (req, res) {
    pool.proxy(entry, req, res, 0, 0);
  });
  const server = http.createServer(app);
  await new Promise(function (resolve) {
    server.listen(0, '127.0.0.1', resolve);
  });
  log.debug("Leaving front().");
  return server;
}

// One POST to the front process. With `pauseMs` the headers go first and the
// body that long after, which is what lets a worker drop the connection
// before a byte of the request reaches it.
function post(port, body, opts) {
  log.debug("Entering post().");
  const options = opts || {};
  const headers = Object.assign({ 'Content-Type': 'application/json',
                                  'Content-Length': Buffer.byteLength(body) },
                                options.headers || {});
  log.debug("Leaving post().");
  return new Promise(function (resolve) {
    const req = http.request({ host: '127.0.0.1', port: port, path: '/p',
                               method: 'POST', headers: headers,
                               agent: false },
      function (answer) {
        let text = '';
        answer.on('data', function (chunk) {
          text += chunk;
        });
        answer.on('end', function () {
          resolve({ status: answer.statusCode, body: text });
        });
      });
    req.on('error', function (e) {
      log.debug("Caught in post(): " + ((e && e.message) || e));
      resolve({ status: 0, body: e.message });
    });
    if (options.pauseMs) {
      req.flushHeaders();
      setTimeout(function () {
        req.end(body);
      }, options.pauseMs);
    } else {
      req.end(body);
    }
  });
}

// ---------------------------------------------------------------------------
// 1. THE CI FAILURE'S SHAPE: THE WORKER'S END IS GONE BEFORE ANYTHING IS
//    WRITTEN. The first connection is closed the moment it is accepted; the
//    request must still be answered, by the worker, exactly once.
// ---------------------------------------------------------------------------
async function checkAnUndeliveredRequestIsSentAgain(t) {
  log.debug("Entering checkAnUndeliveredRequestIsSentAgain().");
  t.log.info('=== a request no byte of which reached the worker is sent ' +
             'again ===');
  pool.reset();
  const worker = await workerSocket('undelivered', {
    connection: function (n, socket) {
      if (n === 1) {
        socket.destroy();
      }
    },
    request: function (one, res) {
      res.setHeader('Content-Type', 'text/plain');
      res.end('registered ' + one.body);
    }
  });
  const entry = entryFor(911, worker);
  const server = await front(entry);
  const before = pool.stats().replayed;

  const answer = await post(server.address().port, '{"n":1}',
                            { pauseMs: 150 });
  t.equal(answer.status, 200, 'the request is answered by the worker',
          answer.body);
  t.equal(answer.body, 'registered {"n":1}',
          'with the whole body the client sent');
  t.equal(worker.seen.requests.length, 1,
          'and the worker handled it exactly once');
  t.equal(worker.seen.connections, 2,
          'on the second connection, the first having been dropped');
  t.equal(pool.stats().replayed - before, 1,
          'and the pool counts one request sent again');
  t.equal(entry.inFlight, 0, 'nothing is left in flight');

  await new Promise(function (resolve) { server.close(resolve); });
  await closeWorker(worker, entry);
  log.debug("Leaving checkAnUndeliveredRequestIsSentAgain().");
}

// ---------------------------------------------------------------------------
// 2. A REQUEST THE WORKER WAS HANDED IS NEVER SENT AGAIN. The worker reads
//    it whole and drops the connection without answering: it may have acted
//    on it, so the client gets the 502 and the handler has run once.
// ---------------------------------------------------------------------------
async function checkADeliveredRequestIsNotRepeated(t) {
  log.debug("Entering checkADeliveredRequestIsNotRepeated().");
  t.log.info('=== a request the worker received is never repeated ===');
  pool.reset();
  const worker = await workerSocket('delivered', {
    request: function (one) {
      one.socket.destroy();
    }
  });
  const entry = entryFor(912, worker);
  const server = await front(entry);
  const before = pool.stats().replayed;

  const answer = await post(server.address().port, '{"n":2}');
  t.equal(answer.status, 502, 'the client is told the worker went away',
          answer.body);
  t.equal(worker.seen.requests.length, 1,
          'and the worker was handed the request once, not twice');
  t.equal(pool.stats().replayed - before, 0, 'nothing was sent again');

  await new Promise(function (resolve) { server.close(resolve); });
  await closeWorker(worker, entry);
  log.debug("Leaving checkADeliveredRequestIsNotRepeated().");
}

// ---------------------------------------------------------------------------
// 3. A BODY OVER THE COPY'S BOUND IS NOT KEPT, SO IT IS NOT SENT AGAIN. The
//    same dropped first connection as section 1, with a body the pool does
//    not keep a copy of.
// ---------------------------------------------------------------------------
async function checkALargeBodyIsNotRepeated(t) {
  log.debug("Entering checkALargeBodyIsNotRepeated().");
  t.log.info('=== a body over the copy bound is not sent again ===');
  pool.reset();
  const worker = await workerSocket('large', {
    connection: function (n, socket) {
      if (n === 1) {
        socket.destroy();
      }
    },
    request: function (one, res) {
      res.end('ok');
    }
  });
  const entry = entryFor(913, worker);
  const server = await front(entry);

  const body = JSON.stringify({ big: 'x'.repeat(1100 * 1024) });
  const answer = await post(server.address().port, body, { pauseMs: 150 });
  t.equal(answer.status, 502,
          'a body over 1 MiB is answered 502 rather than kept and repeated',
          answer.status + ' ' + answer.body.slice(0, 80));
  t.equal(worker.seen.requests.length, 0, 'and no worker ran it');

  await new Promise(function (resolve) { server.close(resolve); });
  await closeWorker(worker, entry);
  log.debug("Leaving checkALargeBodyIsNotRepeated().");
}

// ---------------------------------------------------------------------------
// 4. THE CLIENT'S HOP-BY-HOP HEADERS STAY ON THE CLIENT'S HOP, AND EVERY
//    DISPATCHED REQUEST HAS A CONNECTION OF ITS OWN — with the agent at one
//    connection, so every request after the first is QUEUED, which is the
//    case node reused a socket in.
// ---------------------------------------------------------------------------
async function checkOneConnectionPerRequest(t) {
  log.debug("Entering checkOneConnectionPerRequest().");
  t.log.info('=== one connection per dispatched request, hop-by-hop ' +
             'headers stripped ===');
  pool.reset();
  const worker = await workerSocket('close', {
    request: function (one, res) {
      setTimeout(function () {
        res.end('ok');
      }, 20);
    }
  });
  const entry = entryFor(914, worker, 1);
  const server = await front(entry);
  const port = server.address().port;

  const answers = await Promise.all([1, 2, 3, 4, 5].map(function (n) {
    return post(port, '{"n":' + n + '}', {
      headers: { 'Connection': 'keep-alive, x-hop',
                 'Keep-Alive': 'timeout=5', 'X-Hop': 'secret' }
    });
  }));
  t.check(answers.every(function (one) { return one.status === 200; }),
          'all five are answered',
          JSON.stringify(answers.map(function (one) { return one.status; })));
  t.equal(worker.seen.requests.length, 5, 'the worker saw five requests');
  t.equal(worker.seen.connections, 5,
          'on five connections — none reused, though four were queued ' +
          'behind a one-connection agent');
  const headers = worker.seen.requests.map(function (one) {
    return one.headers;
  });
  t.check(headers.every(function (h) { return h.connection === 'close'; }),
          'every request reached the worker saying Connection: close',
          JSON.stringify(headers.map(function (h) { return h.connection; })));
  t.check(headers.every(function (h) {
    return h['x-hop'] === undefined && h['keep-alive'] === undefined;
  }), 'and neither Keep-Alive nor a header the client\'s Connection named ' +
      'was forwarded', '');
  t.check(headers.every(function (h) {
    return h['content-length'] !== undefined;
  }), 'while the body\'s framing was kept', '');

  await new Promise(function (resolve) { server.close(resolve); });
  await closeWorker(worker, entry);
  log.debug("Leaving checkOneConnectionPerRequest().");
}

async function run(t) {
  log.debug("Entering run().");
  await checkAnUndeliveredRequestIsSentAgain(t);
  await checkADeliveredRequestIsNotRepeated(t);
  await checkALargeBodyIsNotRepeated(t);
  await checkOneConnectionPerRequest(t);
  pool.reset();
  log.debug("Leaving run().");
}

module.exports = {
  name: 'request_proxy_replay',
  describe: 'that a dispatched request none of whose bytes reached its ' +
            'worker is sent again on a new connection, one that was ' +
            'delivered never is, and every dispatched request has a ' +
            'connection of its own (#77)',
  run: run
};
