// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: ldap_error_close_delay.js
//
// ===========================================================================
// A CONNECTION THAT FAILS IS CLOSED LATER, SO ITS TLS ALERT IS READ (run 21).
//
// node-ldapjs destroyed a connection in the same tick as its 'error'. After a
// TLS failure the peer is usually still sending the record the alert is
// about, so the socket closed with data unread, the kernel answered with a
// TCP reset, and a reset that reached the peer first discarded the alert.
// tlsfuzzer's record-layer test against LDAPS saw "Unexpected closure from
// peer" about once in sixty probes under a full run's load. The fix is the
// `errorCloseDelay` server option in the `rcbj/node-ldapjs` fork, and this
// file holds it:
//
//   1. THE CONTROL: a node-ldapjs server without the option closes a
//      connection that errors at once — the library's default.
//   2. WITH THE OPTION, it closes that connection only after the delay —
//      which is also the check that the node-ldapjs installed here is the
//      fork that has the option.
//   3. AS SOURCE, `ldap_server.js` creates both of its servers with the
//      option and asks each one afterwards whether it took.
//
// The alert itself is `tests/protocol/sts_tlsfuzzer.js`'s, against the
// service; it is lost only under load, so it is not reproduced here.
// ===========================================================================
const fs = require('fs');
const net = require('net');
const path = require('path');

const ROOT = path.join(__dirname, '..');

// This file's own logger, for the Entering/Leaving lines the code style asks
// for; its level is LOG_LEVEL, which the harness's logger reads too.
const log = require('bunyan').createLogger({ name: 'ldap_error_close_delay',
  level: process.env.LOG_LEVEL || 'info' });

// How long after an 'error' on its server-side socket a client sees the
// connection close, against a node-ldapjs server built with `options`.
function closeDelayAfterError(ldapjs, options) {
  log.debug("Entering closeDelayAfterError().");
  const server = ldapjs.createServer(Object.assign({ log: log }, options));
  server.on('clientError', function () {
    // The error this file raises; nothing to report about it.
  });
  server.server.on('connection', function (sock) {
    setImmediate(function () {
      sock.emit('error', new Error('a fatal TLS alert was sent'));
    });
  });
  log.debug("Leaving closeDelayAfterError().");
  return new Promise(function (resolve) {
    server.listen(0, '127.0.0.1', function () {
      const started = Date.now();
      const client = net.connect(server.address().port, '127.0.0.1');
      client.on('error', function (e) {
        // A reset is a close too; the time is what is measured.
        log.debug("Caught in closeDelayAfterError(): " +
                  ((e && e.message) || e));
      });
      client.on('close', function () {
        const waited = Date.now() - started;
        server.close();
        resolve({ waited: waited, took: server._errorCloseDelay });
      });
    });
  });
}

module.exports = {
  name: 'ldap_error_close_delay',
  describe: 'a node-ldapjs connection that errors is closed after ' +
            'errorCloseDelay, not at once, so a TLS alert is not lost to ' +
            'the TCP reset, and ldap_server.js asks for it on both servers',
  run: async function (t) {
    log.debug("Entering run().");
    const ldapjs = require(path.join(ROOT, 'node_modules', 'ldapjs'));

    const plain = await closeDelayAfterError(ldapjs, {});
    t.check(plain.waited < 300,
            '1. without errorCloseDelay a connection that errors is closed ' +
            'at once', plain.waited + ' ms');

    const delayed = await closeDelayAfterError(ldapjs,
                                               { errorCloseDelay: 600 });
    t.equal(delayed.took, 600,
            '2a. the installed node-ldapjs takes errorCloseDelay');
    t.check(delayed.waited >= 550,
            '2b. and closes a connection that errors only after it',
            delayed.waited + ' ms');

    const source = fs.readFileSync(path.join(ROOT, 'ldap', 'ldap_server.js'),
                                   'utf8');
    t.check((source.match(/errorCloseDelay: ERROR_CLOSE_MS/g) || []).length ===
            2,
            '3a. ldap_server.js creates both of its servers with ' +
            'errorCloseDelay');
    t.check(/servers\.forEach\(errorCloseDelayed\)/.test(source),
            '3b. and asks each one afterwards whether the option took');
    log.debug("Leaving run().");
  }
};
