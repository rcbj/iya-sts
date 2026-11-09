// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: parser_refusal.js
//
// ===========================================================================
// A REQUEST THE PARSER REFUSES KEEPS ITS ANSWER (#1500).
//
// Node destroyed the socket after writing its 431, so a client still sending
// an oversized request line got a reset in place of the answer. Over a real
// socket, with the request written in pieces so that plenty is still to come
// when the parser gives up: the 431 arrives every time, and nothing is reset.
// ===========================================================================

delete process.env.CONFIG_FILE;

const http = require('http');
const net = require('net');
const ParserRefusal = require('../common/parser_refusal');

const log = require('bunyan').createLogger({ name: 'parser_refusal',
  level: process.env.LOG_LEVEL || 'info' });

const ATTEMPTS = 25;

function send(port, text) {
  log.debug("Entering send().");
  log.debug("Leaving send().");
  return new Promise(function (resolve) {
    let got = '';
    let error = '';
    const socket = net.connect(port, '127.0.0.1', function () {
      socket.write(text.slice(0, 32000));
      setImmediate(function () {
        socket.write(text.slice(32000), function () {
          socket.end();
        });
      });
    });
    socket.on('data', function (d) {
      got += d;
    });
    socket.on('error', function (e) {
      error = e.code;
    });
    socket.on('close', function () {
      resolve({ line: got.split('\r\n')[0], error: error });
    });
  });
}

async function run(t) {
  log.debug("Entering run().");
  const server = http.createServer(function (req, res) {
    res.end('ok');
  });
  ParserRefusal.install(server, 'the test listener');
  await new Promise(function (resolve) {
    server.listen(0, '127.0.0.1', resolve);
  });
  const port = server.address().port;
  try {
    const big = 'GET /x?a=' + 'a'.repeat(200000) +
                ' HTTP/1.1\r\nHost: h\r\n\r\n';
    const seen = {};
    for (let i = 0; i < ATTEMPTS; i++) {
      const one = await send(port, big);
      const key = one.line + '|' + one.error;
      seen[key] = (seen[key] || 0) + 1;
    }
    t.check(seen['HTTP/1.1 431 Request Header Fields Too Large|'] === ATTEMPTS,
            'an oversized request is answered 431 every time, with no reset',
            JSON.stringify(seen));
    const bad = await send(port, 'NOT HTTP AT ALL\r\n\r\n' + 'x'.repeat(40000));
    t.equal(bad.line, 'HTTP/1.1 400 Bad Request', 'malformed HTTP is a 400');
    const good = await send(port, 'GET / HTTP/1.1\r\nHost: h\r\n' +
                            'Connection: close\r\n\r\n');
    t.equal(good.line, 'HTTP/1.1 200 OK', 'and a good request is untouched');
  } finally {
    server.close();
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'parser_refusal',
  describe: 'a request the HTTP parser refuses still gets its answer',
  run: run
};
