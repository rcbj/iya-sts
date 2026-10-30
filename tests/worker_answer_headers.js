// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: worker_answer_headers.js
//
// ===========================================================================
// A WORKER'S ANSWER WITH LARGE HEADERS REACHES THE CLIENT (#1225).
//
// `common/request_pool.js`'s proxy() forwards a dispatched request to its
// worker over the worker's unix socket and reads the answer back with node's
// HTTP parser, whose default refuses a header block past 16 KiB. On 8081 a
// SAML 2.0 Response on the Redirect binding, signed and with its assertion
// encrypted, was 19,633 characters in its `Location`, and the front process
// answered 502 STS-WORKER-0030 — "the request worker went away" — for an
// answer the worker had produced correctly.
//
// Driven the way lingering_close.js drives it: a stub worker, an HTTP server
// on a unix socket, and an express front whose one handler is pool.proxy().
//
//   1. a 303 whose Location is 40 KiB (twice the size seen on 8081) arrives
//      whole, with its status, and nothing is left in flight;
//   2. so does a Set-Cookie of 64 KiB beside it — the hop's limit is on the
//      whole block, not on one header;
//   3. an answer past WORKER_ANSWER_MAX_HEADER_BYTES is still the 502: the
//      bound exists, and is the constant's.
// ===========================================================================

const http = require('http');
const os = require('os');
const path = require('path');
const fs = require('fs');
const express = require('express');
const pool = require('../common/request_pool');

const log = require('bunyan').createLogger({ name: 'worker_answer_headers',
  level: process.env.LOG_LEVEL || 'info' });

// The client's own parser has the same 16 KiB default; it is raised so that
// the test sees what the front process sent rather than its own refusal.
const CLIENT_MAX_HEADER = 4 * 1024 * 1024;

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

// The stub worker: GET /redirect?bytes=N answers a 303 whose Location carries
// N bytes of query; GET /cookie?bytes=N adds a Set-Cookie of N bytes as well.
function stubWorker(req, res) {
  log.debug("Entering stubWorker().");
  const url = new URL(req.url, 'http://worker.invalid');
  const bytes = Number(url.searchParams.get('bytes') || 0);
  const headers = {
    location: 'https://sp.example.com/acs?SAMLResponse=' + 'A'.repeat(bytes)
  };
  if (url.pathname === '/cookie') {
    headers['set-cookie'] = 'big=' + 'b'.repeat(bytes);
  }
  res.writeHead(303, headers);
  res.end('see other');
  log.debug("Leaving stubWorker().");
}

function get(port, pathAndQuery) {
  log.debug("Entering get().");
  return new Promise(function (resolve, reject) {
    const req = http.get({ host: '127.0.0.1', port: port, path: pathAndQuery,
                           maxHeaderSize: CLIENT_MAX_HEADER },
    function (res) {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', function (chunk) { body += chunk; });
      res.on('end', function () {
        resolve({ status: res.statusCode, headers: res.headers, body: body });
      });
    });
    req.on('error', reject);
    log.debug("Leaving get().");
  });
}

async function run(t) {
  log.debug("Entering run().");
  pool.reset();
  const socketPath = path.join(os.tmpdir(), 'sts-answer-headers-' +
                               process.pid + '-' + Date.now() + '.sock');
  const worker = await listen(http.createServer(stubWorker), socketPath);
  const entry = { pid: 1225, socket: socketPath, tickets: new Set(),
                  agent: new http.Agent({ keepAlive: false, maxSockets: 8 }),
                  inFlight: 0, served: 0, generation: 0 };
  const app = express();
  app.use(function (req, res) {
    pool.proxy(entry, req, res, 0, 0);
  });
  const front = await listen(http.createServer(app));
  const port = front.address().port;

  t.log.info('=== a 40 KiB Location reaches the client ===');
  const big = 40 * 1024;
  const one = await get(port, '/redirect?bytes=' + big);
  t.equal(one.status, 303, 'the worker\'s 303 is the client\'s, not a 502',
          one.status + ' ' + one.body.slice(0, 200));
  t.equal((one.headers.location || '').length,
          'https://sp.example.com/acs?SAMLResponse='.length + big,
          'and its Location arrives whole', '');

  t.log.info('=== a 64 KiB Set-Cookie beside it ===');
  const two = await get(port, '/cookie?bytes=' + 64 * 1024);
  t.equal(two.status, 303, 'an answer whose header block is over 128 KiB ' +
          'is delivered', two.status + ' ' + two.body.slice(0, 200));
  t.equal(String((two.headers['set-cookie'] || [])[0] || '').length,
          'big='.length + 64 * 1024, 'and the cookie is whole', '');

  t.log.info('=== past the hop\'s own bound it is still refused ===');
  t.equal(pool.WORKER_ANSWER_MAX_HEADER_BYTES, 1024 * 1024,
          'the bound is a mebibyte',
          String(pool.WORKER_ANSWER_MAX_HEADER_BYTES));
  const three = await get(port, '/redirect?bytes=' +
                          (pool.WORKER_ANSWER_MAX_HEADER_BYTES + 1024));
  t.equal(three.status, 502, 'an answer past it is the 502 it always was',
          String(three.status));
  t.check(/Header overflow/.test(three.body), 'naming the overflow',
          three.body.slice(0, 200));
  t.equal(entry.inFlight, 0, 'nothing is left in flight', '');

  await close(front);
  entry.agent.destroy();
  await close(worker);
  try {
    fs.unlinkSync(socketPath);
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  pool.reset();
  log.debug("Leaving run().");
}

module.exports = {
  name: 'worker_answer_headers',
  describe: 'that a request worker\'s answer whose headers are past node\'s ' +
            '16 KiB default — a Redirect-binding SAML Response, a large ' +
            'cookie — reaches the client through the request pool instead ' +
            'of a 502 (#1225)',
  run: run
};
