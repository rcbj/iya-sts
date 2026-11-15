// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: request_proxy_last_write.js
//
// ===========================================================================
// NOTHING IS WRITTEN TO A WORKER AFTER THE LAST BYTE OF A REQUEST'S BODY
// (2026-11-15).
//
// `tests/request_ryw_session.js` failed in three of five unit-pool runs on
// GitHub Actions (run 43672106260 among them) with a 502,
// `[STS-WORKER-0030] … could not answer POST /oauth2/token?issue=RT1:
// write EPIPE`, for requests the worker had read whole and answered. The
// cause was in `common/request_pool.js`'s proxy(): it wrote a body chunk and
// then called `ClientRequest.end()`, and while the agent's socket is still
// connecting — as it is when the body arrives a tick after the request was
// opened — node's end() makes a SEPARATE, empty write after the one carrying
// the last byte. The worker answers on that byte and, the hop being
// `Connection: close`, closes; a unix socket whose peer has closed refuses
// even an empty write with EPIPE. It took this thread being preempted
// between the two writes for the worker's thread to get there first.
//
// This file makes that preemption certain instead of rare: the agent's
// sockets delay every write after their first by DELAY_MS, which is far
// longer than the worker's thread takes to answer and close, and the delay
// STOPS this thread rather than setting a timer, which is what a
// preemption is: nothing here reads the answer meanwhile. Before the fix
// the first section is the CI failure exactly — a 502 naming `write
// EPIPE` for a request the worker handled once; after it, the last chunk
// and the end go in one write and there is nothing to delay.
//
//   L1. a body in one chunk is answered by the worker, whole, once, and
//       the connection carries ONE write after it connects;
//   L2. a body in three chunks, spaced so the front reads each separately,
//       is answered whole and once (the earlier chunks may be written
//       ahead; the worker cannot answer before the last one);
//   L3. a request with no body (a GET) is answered as it always was.
//
// Real sockets and no mock of http, `tests/request_proxy_replay.js`'s
// arrangement: an express front calling proxy(), a unix-socket worker.
// ===========================================================================

const http = require('http');
const net = require('net');
const { Worker } = require('worker_threads');
const os = require('os');
const path = require('path');
const fs = require('fs');
const express = require('express');
const pool = require('../common/request_pool');

const log = require('bunyan').createLogger({
  name: 'request_proxy_last_write',
  level: process.env.LOG_LEVEL || 'info' });

// How long a write after a socket's first is held back: the "preemption".
// The worker answers and closes in a few milliseconds.
const DELAY_MS = 150;

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

// Every write a marked socket makes once it is connected is counted, and
// before each after the first this THREAD stops for DELAY_MS — not a timer:
// a preemption, so this thread reads nothing in the meantime, while the
// worker's thread runs on. Only sockets the test's agent made are marked,
// so the front's own listener is untouched.
const original = net.Socket.prototype._writeGeneric;
const pause = new Int32Array(new SharedArrayBuffer(4));
function installDelay() {
  log.debug("Entering installDelay().");
  net.Socket.prototype._writeGeneric = function (writev, data, enc, cb) {
    if (this.__lastWrite && !this.connecting) {
      this.__lastWrite.writes += 1;
      if (this.__lastWrite.writes > 1) {
        Atomics.wait(pause, 0, 0, DELAY_MS);
      }
    }
    return original.call(this, writev, data, enc, cb);
  };
  log.debug("Leaving installDelay().");
}

function removeDelay() {
  log.debug("Entering removeDelay().");
  net.Socket.prototype._writeGeneric = original;
  log.debug("Leaving removeDelay().");
}

// The worker, in a THREAD of its own as a request worker is: answers once
// the whole body is in, with what it read, and (the request saying
// `Connection: close`) closes. It counts the requests it handled.
const WORKER = [
  "'use strict';",
  "const http = require('http');",
  "const wt = require('worker_threads');",
  "let handled = 0;",
  "const server = http.createServer(function (req, res) {",
  "  const chunks = [];",
  "  req.on('data', function (chunk) { chunks.push(chunk); });",
  "  req.on('end', function () {",
  "    handled += 1;",
  "    wt.parentPort.postMessage({ handled: handled });",
  "    res.setHeader('Content-Type', 'text/plain');",
  "    res.end('got ' + req.method + ' ' +",
  "            Buffer.concat(chunks).toString('utf8'));",
  "  });",
  "});",
  "wt.parentPort.on('message', function (m) {",
  "  if (m && m.stop) { server.close(function () { process.exit(0); }); }",
  "});",
  "server.listen(wt.workerData, function () {",
  "  wt.parentPort.postMessage({ ready: true });",
  "});",
  ""
].join('\n');

async function workerSocket() {
  log.debug("Entering workerSocket().");
  const socketPath = path.join(os.tmpdir(), 'sts-last-write-' +
                               process.pid + '-' + Date.now() + '.sock');
  const seen = { handled: 0 };
  const thread = new Worker(WORKER, { eval: true, workerData: socketPath });
  await new Promise(function (resolve, reject) {
    thread.on('message', function (m) {
      if (m && m.ready) {
        resolve();
      }
      if (m && m.handled) {
        seen.handled = m.handled;
      }
    });
    thread.once('error', reject);
  });
  log.debug("Leaving workerSocket().");
  return { socketPath: socketPath, seen: seen, thread: thread };
}

// The pool's entry for that worker, with an agent whose sockets are marked.
function entryFor(worker, marks) {
  log.debug("Entering entryFor().");
  const agent = new http.Agent({ keepAlive: false, maxSockets: 64 });
  const make = agent.createConnection;
  agent.createConnection = function (options, cb) {
    const socket = make.call(agent, options, cb);
    socket.__lastWrite = { writes: 0 };
    marks.push(socket.__lastWrite);
    return socket;
  };
  log.debug("Leaving entryFor().");
  return { pid: 931, socket: worker.socketPath, tickets: new Set(),
           agent: agent, inFlight: 0, served: 0, generation: 0 };
}

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

// One request to the front. `pieces` writes the body in that many parts,
// `gapMs` apart, so the front reads each as its own `data` event.
function send(port, method, body, pieces, gapMs) {
  log.debug("Entering send().");
  const headers = {};
  if (body !== null) {
    headers['Content-Type'] = 'application/x-www-form-urlencoded';
    headers['Content-Length'] = String(Buffer.byteLength(body));
  }
  log.debug("Leaving send().");
  return new Promise(function (resolve) {
    const req = http.request({ host: '127.0.0.1', port: port, path: '/p',
                               method: method, headers: headers,
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
      log.debug("Caught in send(): " + ((e && e.message) || e));
      resolve({ status: 0, body: e.message });
    });
    if (body === null) {
      req.end();
      return;
    }
    if (!pieces || pieces < 2) {
      req.end(body);
      return;
    }
    const data = Buffer.from(body);
    const step = Math.ceil(data.length / pieces);
    let at = 0;
    const next = function () {
      const piece = data.subarray(at, at + step);
      at += step;
      if (at >= data.length) {
        req.end(piece);
        return;
      }
      req.write(piece);
      setTimeout(next, gapMs);
    };
    req.flushHeaders();
    setTimeout(next, gapMs);
  });
}

async function run(t) {
  log.debug("Entering run().");
  pool.reset();
  const worker = await workerSocket();
  const marks = [];
  const entry = entryFor(worker, marks);
  const server = await front(entry);
  const port = server.address().port;
  installDelay();
  try {
    // L1. One chunk: the CI failure's shape.
    const one = await send(port, 'POST', 'n=1', 1, 0);
    t.check(one.status === 200 && one.body === 'got POST n=1',
            'L1. a one-chunk body is answered by the worker, not a 502 ' +
            '(write EPIPE)', one.status + ' ' + one.body);
    await sleep(20);
    t.equal(worker.seen.handled, 1, 'L1. and the worker handled it once');
    t.equal(marks.length === 1 ? marks[0].writes : -1, 1,
            'L1. the last byte and the end went to the worker in ONE write');

    // L2. Three chunks, read separately by the front.
    const body = 'grant_type=refresh_token&refresh_token=' + 'r'.repeat(60);
    const three = await send(port, 'POST', body, 3, 30);
    t.check(three.status === 200 && three.body === 'got POST ' + body,
            'L2. a body in three chunks is answered whole',
            three.status + ' ' + three.body.slice(0, 80));
    await sleep(20);
    t.equal(worker.seen.handled, 2, 'L2. and the worker handled it once');

    // L3. No body at all.
    const get = await send(port, 'GET', null, 0, 0);
    t.check(get.status === 200 && get.body === 'got GET ',
            'L3. a request with no body is answered as before',
            get.status + ' ' + get.body);
    await sleep(DELAY_MS + 50);
    t.equal(entry.inFlight, 0, 'nothing is left in flight');
  } finally {
    removeDelay();
    await new Promise(function (resolve) {
      server.close(resolve);
    });
    entry.agent.destroy();
    worker.thread.postMessage({ stop: true });
    await new Promise(function (resolve) {
      worker.thread.once('exit', resolve);
    });
    try {
      fs.unlinkSync(worker.socketPath);
    } catch (e) {
      log.debug("Caught in run(): " + ((e && e.message) || e));
    }
    pool.reset();
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'request_proxy_last_write',
  describe: 'that nothing is written to a request worker after the last ' +
            'byte of a body, so a worker that answers and closes on that ' +
            'byte is not reported as a 502 write EPIPE',
  run: run
};
