'use strict';
//
// File: lingering_close.js
//
// ===========================================================================
// AN ANSWER SENT BEFORE AN UPLOAD HAS ALL ARRIVED REACHES THE CLIENT
// (2026-09-26).
//
// A risk dataset upload refused on its fields — a realm not named, a
// dataset that is not one — is answered while the file is still arriving,
// with `Connection: close`. Node then closed the socket at once, and a
// socket closed with unread data sends a TCP RESET, which makes the peer
// discard the answer it had not read yet. On the 8081 stack that was
// `STS-WORKER-0030 … read ECONNRESET` in the front process and a
// connection error in the browser, in place of the console's refusal.
// `common/lingering_close.js` half-closes and discards the rest instead.
//
//   1. DIRECTLY: a server that answers on the headers, a client sending a
//      large body — every answer is read in full.
//   2. THROUGH THE REQUEST POOL: the same early answer from a worker, proxied
//      by `request_pool.proxy()` — the client gets the worker's status and
//      body, and nothing is left in flight.
//   3. A REQUEST WHOSE BODY HAS ARRIVED is closed the ordinary way:
//      `arm()` does not touch its socket.
//
// Whether a reset beats the answer to the client's kernel is a race, and on
// loopback the answer usually wins; what a reset does DETERMINISTICALLY is
// fail the writes of a client that is still sending, which is what a browser
// mid-upload is. So every client keeps sending after its answer, and section
// 1 runs a plain `Connection: close` beside the lingering one as the control
// that shows the check can fail.
// ===========================================================================

const http = require('http');
const os = require('os');
const path = require('path');
const fs = require('fs');
const express = require('express');
const lingeringClose = require('../common/lingering_close');
const pool = require('../common/request_pool');

const log = require('bunyan').createLogger({ name: 'lingering_close',
  level: process.env.LOG_LEVEL || 'info' });

// How much each client tries to send, and in what pieces. Large enough that
// most of it is still unsent when the answer comes.
const BODY_BYTES = 24 * 1024 * 1024;
const CHUNK = Buffer.alloc(64 * 1024, 0x61);
const ROUNDS = 8;

// A handler that refuses on the headers, the upload route's shape.
function refuseEarly(armed) {
  log.debug("Entering refuseEarly().");
  log.debug("Leaving refuseEarly().");
  return function (req, res) {
    if (armed) {
      lingeringClose.arm(req, res);
    } else {
      res.setHeader('Connection', 'close');
    }
    res.statusCode = 303;
    res.setHeader('Location', '/admin/risk/upload?error=refused');
    res.setHeader('Content-Type', 'text/plain');
    res.end('refused before the body arrived');
  };
}

// POST a large body, writing until the answer arrives — and then, as a
// browser does, KEEPING ON writing for `KEEP_SENDING_MS` before ending, and
// recording whether the connection failed under it. A socket closed with
// unread data answers those writes with a reset; a lingering one reads and
// discards them. Resolves the answer, or `{ status: 0, error }` for a
// connection that failed before the answer.
const KEEP_SENDING_MS = 300;
const UPLOAD_DEADLINE_MS = 15000;

function upload(target) {
  log.debug("Entering upload().");
  log.debug("Leaving upload().");
  return new Promise(function (resolve) {
    let settled = false;
    let answered = false;
    const settle = function (value) {
      if (!settled) {
        settled = true;
        clearTimeout(deadline);
        resolve(value);
      }
    };
    const req = http.request(Object.assign({ method: 'POST', path: '/up',
      headers: { 'Content-Type': 'application/octet-stream',
                 'Content-Length': BODY_BYTES },
      agent: false }, target), function (answer) {
      answered = true;
      let text = '';
      answer.on('data', function (chunk) {
        text += chunk;
      });
      answer.on('end', function () {
        const result = { status: answer.statusCode, body: text,
                         connection: answer.headers.connection,
                         writeError: '' };
        req.on('error', function (e) {
          log.debug("Caught in upload(): " + ((e && e.message) || e));
          result.writeError = result.writeError || e.message;
        });
        // Paced by a timer rather than by write callbacks: a write on a
        // socket the peer has reset may never call back, and that is the
        // very case this loop is here to observe.
        const until = Date.now() + KEEP_SENDING_MS;
        const more = function () {
          if (result.writeError || Date.now() >= until || req.destroyed) {
            req.destroy();
            settle(result);
            return;
          }
          req.write(CHUNK, function (e) {
            if (e) {
              result.writeError = result.writeError || e.message;
            }
          });
          setTimeout(more, 5);
        };
        more();
      });
      answer.on('error', function (e) {
        log.debug("Caught in upload(): " + ((e && e.message) || e));
        settle({ status: 0, error: 'answer: ' + e.message });
      });
    });
    req.on('error', function (e) {
      log.debug("Caught in upload(): " + ((e && e.message) || e));
      if (!answered) {
        settle({ status: 0, error: e.message });
      }
    });
    // A bound on the whole upload, so no reset or stall can hang the file.
    const deadline = setTimeout(function () {
      req.destroy();
      settle({ status: 0, error: 'no answer within ' + UPLOAD_DEADLINE_MS +
                                 ' ms' });
    }, UPLOAD_DEADLINE_MS);
    deadline.unref();
    let sent = 0;
    const pump = function () {
      while (!answered && sent < BODY_BYTES) {
        const piece = CHUNK.subarray(0, Math.min(CHUNK.length,
                                                 BODY_BYTES - sent));
        sent += piece.length;
        if (!req.write(piece)) {
          req.once('drain', pump);
          return;
        }
      }
      if (!answered) {
        req.end();
      }
    };
    pump();
  });
}

async function listen(server, where) {
  log.debug("Entering listen().");
  await new Promise(function (resolve) {
    if (where) {
      server.listen(where, resolve);
    } else {
      server.listen(0, '127.0.0.1', resolve);
    }
  });
  log.debug("Leaving listen().");
  return server;
}

async function close(server) {
  log.debug("Entering close().");
  if (typeof server.closeAllConnections === 'function') {
    server.closeAllConnections();
  }
  await new Promise(function (resolve) { server.close(resolve); });
  log.debug("Leaving close().");
}

// ---------------------------------------------------------------------------
// 1. DIRECTLY.
// ---------------------------------------------------------------------------
async function checkDirect(t) {
  log.debug("Entering checkDirect().");
  t.log.info('=== an early answer to a large upload reaches the client ===');
  const armed = await listen(http.createServer(refuseEarly(true)));
  const control = await listen(http.createServer(refuseEarly(false)));
  const got = [];
  const lost = [];
  for (let i = 0; i < ROUNDS; i++) {
    got.push(await upload({ host: '127.0.0.1',
                            port: armed.address().port }));
    lost.push(await upload({ host: '127.0.0.1',
                             port: control.address().port }));
  }
  const whole = got.filter(function (one) {
    return one.status === 303 &&
           one.body === 'refused before the body arrived';
  });
  t.equal(whole.length, ROUNDS, 'every answer from the lingering close is ' +
          'read whole', JSON.stringify(got.filter(function (one) {
            return one.status !== 303;
          })));
  t.check(got.every(function (one) {
    return one.status !== 303 || one.connection === 'close';
  }), 'and says Connection: close', '');
  t.check(got.every(function (one) {
    return one.status !== 303 || !one.writeError;
  }), 'and a client still sending after it is not reset', JSON.stringify(
    got.map(function (one) { return one.writeError; })));
  const reset = lost.filter(function (one) {
    return one.status !== 303 || one.writeError;
  });
  t.check(reset.length > 0, 'while a plain Connection: close resets it ' +
          '(the control — without it this section proves nothing)',
          reset.length + ' of ' + ROUNDS + ': ' +
          JSON.stringify(reset.map(function (one) {
            return one.error || one.writeError;
          })));
  await close(armed);
  await close(control);
  log.debug("Leaving checkDirect().");
}

// ---------------------------------------------------------------------------
// 2. THROUGH THE REQUEST POOL.
// ---------------------------------------------------------------------------
async function checkThroughThePool(t) {
  log.debug("Entering checkThroughThePool().");
  t.log.info('=== an early answer from a request worker reaches the client ' +
             '===');
  pool.reset();
  const socketPath = path.join(os.tmpdir(), 'sts-linger-' + process.pid +
                               '-' + Date.now() + '.sock');
  const worker = await listen(http.createServer(refuseEarly(true)),
                              socketPath);
  const entry = { pid: 913, socket: socketPath, tickets: new Set(),
                  agent: new http.Agent({ keepAlive: false, maxSockets: 64 }),
                  inFlight: 0, served: 0, generation: 0 };
  const app = express();
  app.use(function (req, res) {
    pool.proxy(entry, req, res, 0, 0);
  });
  const front = await listen(http.createServer(app));
  const answers = [];
  for (let i = 0; i < ROUNDS; i++) {
    answers.push(await upload({ host: '127.0.0.1',
                                port: front.address().port }));
  }
  const whole = answers.filter(function (one) {
    return one.status === 303 &&
           one.body === 'refused before the body arrived';
  });
  t.equal(whole.length, ROUNDS, 'every worker\'s early answer reaches the ' +
          'client whole, not a 502 or a reset',
          JSON.stringify(answers.filter(function (one) {
            return one.status !== 303;
          })));
  t.check(answers.every(function (one) {
    return one.status !== 303 || one.connection === 'close';
  }), 'and the client is told Connection: close', '');
  t.check(answers.every(function (one) {
    return one.status !== 303 || !one.writeError;
  }), 'and a client still sending after it is not reset', JSON.stringify(
    answers.map(function (one) { return one.writeError; })));
  t.equal(entry.inFlight, 0, 'nothing is left in flight');
  await close(front);
  entry.agent.destroy();
  await close(worker);
  try {
    fs.unlinkSync(socketPath);
  } catch (e) {
    log.debug("Caught in checkThroughThePool(): " + ((e && e.message) || e));
  }
  log.debug("Leaving checkThroughThePool().");
}

// ---------------------------------------------------------------------------
// 3. A BODY THAT HAS ARRIVED.
// ---------------------------------------------------------------------------
async function checkACompleteRequestIsUntouched(t) {
  log.debug("Entering checkACompleteRequestIsUntouched().");
  t.log.info('=== a request whose body has arrived is closed as before ===');
  let sawDestroySoon = null;
  const server = await listen(http.createServer(function (req, res) {
    req.resume();
    req.on('end', function () {
      const before = req.socket.destroySoon;
      lingeringClose.arm(req, res);
      sawDestroySoon = req.socket.destroySoon === before;
      res.end('ok');
    });
  }));
  const answer = await new Promise(function (resolve) {
    const req = http.request({ host: '127.0.0.1',
                               port: server.address().port, method: 'POST',
                               path: '/', agent: false,
                               headers: { 'Content-Length': 2 } },
      function (res) {
        let text = '';
        res.on('data', function (chunk) {
          text += chunk;
        });
        res.on('end', function () {
          resolve({ status: res.statusCode, body: text,
                    connection: res.headers.connection });
        });
      });
    req.on('error', function (e) {
      log.debug("Caught in checkACompleteRequestIsUntouched(): " +
                ((e && e.message) || e));
      resolve({ status: 0 });
    });
    req.end('hi');
  });
  t.check(answer.status === 200 && answer.body === 'ok' &&
          answer.connection === 'close',
          'it is answered, saying Connection: close', JSON.stringify(answer));
  t.equal(sawDestroySoon, true, 'and its socket\'s close was not replaced');
  await close(server);
  log.debug("Leaving checkACompleteRequestIsUntouched().");
}

async function run(t) {
  log.debug("Entering run().");
  await checkDirect(t);
  await checkThroughThePool(t);
  await checkACompleteRequestIsUntouched(t);
  pool.reset();
  log.debug("Leaving run().");
}

module.exports = {
  name: 'lingering_close',
  describe: 'that an answer sent before a large upload has all arrived — ' +
            'a risk dataset upload refused on its fields — reaches the ' +
            'client whole, directly and through the request pool, instead ' +
            'of being lost to a TCP reset',
  run: run
};
