// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: proxy_early_headers.js
//
// ===========================================================================
// A DISPATCHED ANSWER'S SECURITY HEADERS ARE THE WORKER'S, PRESENT OR ABSENT
// (2026-11-10).
//
// `common/app.js`'s enterRealm() writes `X-Content-Type-Options`,
// `X-Frame-Options: DENY` and an early `Content-Security-Policy` on every
// response before anything else runs — in the front process too, before
// `request_pool.js` dispatches the request. proxy() copied the worker's
// headers over the front's, so a header the worker's route had REMOVED was
// simply not in the answer and the front's early value went out. The OP
// iframe (`/oauth2/check_session`, OpenID Connect Session Management) removes
// `X-Frame-Options` so that its narrower `frame-ancestors` decides who may
// frame it, and in every mode that dispatches (product's single-node run
// among them) it answered `X-Frame-Options: DENY`: sts_session_management
// failed there and passed in `memory`, which has no workers.
//
// Real sockets, `tests/request_proxy_replay.js`'s arrangement: an express app
// in front that writes the early headers as enterRealm() does and calls
// proxy(), and a unix socket behind it answering as a worker would.
// ===========================================================================

const http = require('http');
const os = require('os');
const path = require('path');
const fs = require('fs');
const express = require('express');
const pool = require('../common/request_pool');

const log = require('bunyan').createLogger({ name: 'proxy_early_headers',
  level: process.env.LOG_LEVEL || 'info' });

const EARLY_POLICY = "default-src 'none'; frame-ancestors 'none'; " +
                     "base-uri 'none'; object-src 'none'";
const FRAMED_POLICY = "default-src 'none'; frame-ancestors " +
                      "https://rp.example; base-uri 'none'";

// A worker: `/framed` answers as the OP iframe does (no X-Frame-Options, a
// policy naming who may frame it); anything else answers as every other
// route does (DENY and the base policy).
async function workerSocket() {
  log.debug("Entering workerSocket().");
  const socketPath = path.join(os.tmpdir(), 'sts-early-headers-' +
                               process.pid + '-' + Date.now() + '.sock');
  const server = http.createServer(function (req, res) {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    if (req.url === '/framed') {
      res.setHeader('Content-Security-Policy', FRAMED_POLICY);
    } else {
      res.setHeader('X-Frame-Options', 'DENY');
      res.setHeader('Content-Security-Policy', EARLY_POLICY);
    }
    res.setHeader('Content-Type', 'text/plain');
    res.end('answered ' + req.url);
  });
  await new Promise(function (resolve) {
    server.listen(socketPath, resolve);
  });
  log.debug("Leaving workerSocket().");
  return { socketPath: socketPath, server: server };
}

// The front process: the early headers, as enterRealm() writes them, then
// every request proxied to `entry`.
async function front(entry) {
  log.debug("Entering front().");
  const app = express();
  app.use(function (req, res) {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Content-Security-Policy', EARLY_POLICY);
    pool.proxy(entry, req, res, 0, 0);
  });
  const server = http.createServer(app);
  await new Promise(function (resolve) {
    server.listen(0, '127.0.0.1', resolve);
  });
  log.debug("Leaving front().");
  return server;
}

function get(port, where) {
  log.debug("Entering get(). " + where);
  log.debug("Leaving get().");
  return new Promise(function (resolve) {
    const req = http.request({ host: '127.0.0.1', port: port, path: where,
                               method: 'GET', agent: false },
      function (answer) {
        let text = '';
        answer.on('data', function (chunk) {
          text += chunk;
        });
        answer.on('end', function () {
          resolve({ status: answer.statusCode, headers: answer.headers,
                    body: text });
        });
      });
    req.on('error', function (e) {
      log.debug("Caught in get(): " + ((e && e.message) || e));
      resolve({ status: 0, headers: {}, body: e.message });
    });
    req.end();
  });
}

// The names enterRealm() writes, read out of `common/app.js`'s source: the
// list proxy() clears must name every one, or a header added there later
// would come back as the front's on every dispatched answer.
function earlyHeaderNames() {
  log.debug("Entering earlyHeaderNames().");
  const source = fs.readFileSync(path.join(__dirname, '..', 'common',
                                           'app.js'), 'utf8');
  const start = source.indexOf('function enterRealm(');
  const end = source.indexOf('const pathname', start);
  const body = start >= 0 && end > start ? source.slice(start, end) : '';
  const names = [];
  const re = /res\.setHeader\(\s*'([^']+)'/g;
  for (let m = re.exec(body); m; m = re.exec(body)) {
    names.push(m[1].toLowerCase());
  }
  log.debug("Leaving earlyHeaderNames(). " + names.length);
  return names;
}

async function run(t) {
  log.debug("Entering run().");
  t.log.info('=== a dispatched answer carries the worker\'s security ' +
             'headers, and no header the worker removed ===');
  pool.reset();
  const worker = await workerSocket();
  const entry = { pid: 921, socket: worker.socketPath, tickets: new Set(),
                  agent: new http.Agent({ keepAlive: false, maxSockets: 8 }),
                  inFlight: 0, served: 0, generation: 0 };
  const server = await front(entry);
  try {
    const port = server.address().port;
    const framed = await get(port, '/framed');
    t.equal(framed.status, 200, 'the framed page is answered', framed.body);
    t.equal(framed.headers['x-frame-options'], undefined,
            'a page whose worker removed X-Frame-Options goes out without ' +
            'it, not with the front process\'s early DENY');
    t.equal(framed.headers['content-security-policy'], FRAMED_POLICY,
            'and with the policy the worker chose, once');
    t.equal(framed.headers['x-content-type-options'], 'nosniff',
            'nosniff is the worker\'s and is still there');

    const plain = await get(port, '/plain');
    t.equal(plain.status, 200, 'an ordinary page is answered', plain.body);
    t.equal(plain.headers['x-frame-options'], 'DENY',
            'an ordinary page keeps X-Frame-Options: DENY');
    t.equal(plain.headers['content-security-policy'], EARLY_POLICY,
            'and its policy');

    const early = earlyHeaderNames();
    t.check(early.length >= 3, 'enterRealm() was read out of app.js',
            JSON.stringify(early));
    const missing = early.filter(function (name) {
      return pool.WORKER_DECIDES.indexOf(name) < 0;
    });
    t.equal(missing.length, 0, 'every header enterRealm() writes is one ' +
            'proxy() lets the worker decide', JSON.stringify(missing));
  } finally {
    await new Promise(function (resolve) { server.close(resolve); });
    entry.agent.destroy();
    await new Promise(function (resolve) { worker.server.close(resolve); });
    try {
      fs.unlinkSync(worker.socketPath);
    } catch (e) {
      log.debug("Caught in run(): " + ((e && e.message) || e));
    }
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'proxy_early_headers',
  describe: 'that a dispatched answer carries the worker\'s security ' +
            'headers and not the front process\'s early ones, so the OP ' +
            'iframe is sent without X-Frame-Options in every mode',
  run: run
};
