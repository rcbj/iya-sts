// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tls_alert_close.js
//
// ===========================================================================
// A TLS CONNECTION THAT FAILED IS CLOSED LATER, SO ITS ALERT IS READ
// (2026-11-13, tls/alert_close.ts).
//
// Node closed a connection on the main port in the tick of its TLS failure,
// with the peer's record unread, so the kernel's TCP reset could discard the
// alert already written: tlsfuzzer's record-layer probe ("too big ciphertext
// … fuzzed tag") saw "Unexpected closure from peer" about once in seventy
// under load. LDAPS had the same failure (`ldap_error_close_delay.js`).
//
// Over a real listener built as the main port is — node's HTTP/2 secure
// server offering HTTP/1.1, with the parser refusal and the alert close
// installed — clients complete a handshake and then send a record whose tag
// does not verify, followed by more data they keep sending:
//
//   1. THE CONTROL: without the alert close, the server closes every such
//      connection within a moment of the record, in each of the ways below.
//   2. WITH IT, each client reads the bad_record_mac alert, and the server
//      closes the connection only after the delay, having read what the
//      client went on sending — on all four ways in:
//        a. TLS 1.3, the record behind the client's Finished: node's own
//           failure before the handshake is counted done (`tlsClientError`);
//        b. TLS 1.3 after the handshake, over HTTP/1.1 (`clientError`);
//        c. TLS 1.2 after the handshake, over HTTP/1.1;
//        d. TLS 1.3 after the handshake, over HTTP/2 (the session).
//      Both kinds of (a) and (b) are asserted to have happened, or the test
//      would not be testing what it says.
//   3. THE BOUND: a listener holding its bound closes the next failure at
//      once, and every held socket is released.
//   4. AN ALERT THE PEER SENT is not held, a good request is untouched,
//      and the parser refusal writes no plaintext answer into a connection
//      whose TLS failed.
//   5. AS SOURCE, server.js installs it on the main port and on every
//      custom listener, and the debugger's listener has it too.
//
// The alert lost under load is `tests/protocol/sts_tlsfuzzer.js`'s against
// the service; it is not reproduced here.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const http2 = require('http2');
const https = require('https');
const net = require('net');
const path = require('path');
const tls = require('tls');

const AlertClose = require('../tls/alert_close');
const ParserRefusal = require('../common/parser_refusal');
const pepCredential = require('./tools/pep-credential');

const ROOT = path.join(__dirname, '..');

const log = require('bunyan').createLogger({ name: 'tls_alert_close',
  level: process.env.LOG_LEVEL || 'info' });

// The test's own delay, shorter than the service's two seconds.
const DELAY_MS = 600;
// What counts as "at once": the close in the failure's tick, plus a loaded
// machine's scheduling.
const AT_ONCE_MS = 300;
// Probes of each kind, all at once.
const EACH = 6;

// A TLS application-data record of 100 bytes that no key encrypted: its tag
// cannot verify, so the server's TLS engine fails with bad_record_mac.
function badRecord() {
  log.debug("Entering badRecord().");
  const record = Buffer.alloc(5 + 100, 0x5a);
  record[0] = 23;
  record[1] = 3;
  record[2] = 3;
  record.writeUInt16BE(100, 3);
  log.debug("Leaving badRecord().");
  return record;
}

// A listener built as the main port is (server.js), with what the server
// saw of each connection, keyed by the client's port.
function listener(pki, alertOptions) {
  log.debug("Entering listener().");
  const server = http2.createSecureServer({
    allowHTTP1: true, key: pki.keyPem, cert: pki.certPem,
    minVersion: 'TLSv1.2'
  }, function (req, res) {
    res.end('ok');
  });
  ParserRefusal.install(server, 'the test listener');
  if (alertOptions) {
    AlertClose.install(server, 'the test listener', alertOptions);
  }
  const seen = new Map();
  server.on('connection', function (raw) {
    const one = { secured: false, tlsClientError: false, errorCode: '',
                  closedAt: 0 };
    seen.set(raw.remotePort, one);
    raw.once('close', function () {
      one.closedAt = Date.now();
    });
  });
  server.on('secureConnection', function (socket) {
    const one = seen.get(socket.remotePort);
    if (one) {
      one.secured = true;
    }
  });
  server.on('tlsClientError', function (err, socket) {
    const one = seen.get(socket.remotePort);
    if (one) {
      one.tlsClientError = true;
      one.errorCode = String((err && err.code) || '');
    }
  });
  log.debug("Leaving listener().");
  return new Promise(function (resolve) {
    server.listen(0, '127.0.0.1', function () {
      resolve({ server: server, port: server.address().port, seen: seen });
    });
  });
}

// One client: a handshake, then (after `waitMs`, or at once) the bad record
// and more data, until its connection is gone. Resolves with what it read
// and when the server closed its end.
function probe(where, options) {
  log.debug("Entering probe().");
  log.debug("Leaving probe().");
  return new Promise(function (resolve) {
    const result = { alert: '', error: '', sentAt: 0, port: 0 };
    let pump = null;
    let finished = false;
    const finish = function () {
      if (finished) {
        return;
      }
      finished = true;
      clearInterval(pump);
      // The server's end closes on its own clock; wait for it.
      const until = Date.now() + DELAY_MS + 3000;
      const look = function () {
        const one = where.seen.get(result.port);
        if ((one && one.closedAt) || Date.now() > until) {
          resolve(Object.assign(result, {
            secured: !!(one && one.secured),
            tlsClientError: !!(one && one.tlsClientError),
            serverError: one ? one.errorCode : '',
            serverClosedAfter: one && one.closedAt ?
              one.closedAt - result.sentAt : null
          }));
          return;
        }
        setTimeout(look, 20);
      };
      look();
    };
    const raw = net.connect(where.port, '127.0.0.1', function () {
      result.port = raw.localPort;
      const client = tls.connect({
        socket: raw, rejectUnauthorized: false,
        minVersion: options.version, maxVersion: options.version,
        ALPNProtocols: options.alpn ? [options.alpn] : undefined
      }, function () {
        const go = function () {
          result.sentAt = Date.now();
          raw.write(Buffer.concat([badRecord(), Buffer.alloc(100000, 1)]));
          pump = setInterval(function () {
            if (!raw.destroyed && raw.writable) {
              raw.write(Buffer.alloc(16384, 1));
            }
          }, 10);
        };
        if (options.waitMs) {
          setTimeout(go, options.waitMs);
        } else {
          go();
        }
      });
      client.on('error', function (e) {
        if (!result.sentAt) {
          result.sentAt = Date.now();
        }
        if (/ALERT/.test(String(e.code))) {
          result.alert = result.alert || e.code;
        } else {
          result.error = result.error || String(e.code || e.message);
        }
      });
      client.on('close', finish);
    });
    raw.on('error', function (e) {
      result.error = result.error || String(e.code || e.message);
      finish();
    });
    raw.on('close', finish);
  });
}

// A TLS 1.2 ClientHello as node writes one, caught by a listener that
// answers nothing.
function clientHello() {
  log.debug("Entering clientHello().");
  log.debug("Leaving clientHello().");
  return new Promise(function (resolve) {
    const catcher = net.createServer(function (sock) {
      sock.once('data', function (d) {
        resolve(d);
        sock.destroy();
        catcher.close();
      });
    });
    catcher.listen(0, '127.0.0.1', function () {
      const c = tls.connect({ port: catcher.address().port,
                              host: '127.0.0.1', maxVersion: 'TLSv1.2',
                              rejectUnauthorized: false });
      c.on('error', function (e) {
        log.debug("Caught in clientHello(): " + ((e && e.message) || e));
      });
    });
  });
}

// A client that sends its ClientHello, reads the server's first flight and
// answers it with a fatal handshake_failure alert, keeping its end open:
// the PEER's alert, which owes nothing back.
function peerAlert(where, hello) {
  log.debug("Entering peerAlert().");
  log.debug("Leaving peerAlert().");
  return new Promise(function (resolve) {
    let port = 0;
    let sentAt = 0;
    const raw = net.connect(where.port, '127.0.0.1', function () {
      port = raw.localPort;
      raw.write(hello);
    });
    raw.once('data', function () {
      sentAt = Date.now();
      raw.write(Buffer.from([21, 3, 3, 0, 2, 2, 40]));
    });
    raw.on('error', function (e) {
      log.debug("Caught in peerAlert(): " + ((e && e.message) || e));
    });
    raw.on('close', function () {
      const until = Date.now() + DELAY_MS + 3000;
      const look = function () {
        const one = where.seen.get(port);
        if ((one && one.closedAt) || Date.now() > until) {
          resolve({ serverError: one ? one.errorCode : '',
                    serverClosedAfter: one && one.closedAt ?
                      one.closedAt - sentAt : null });
          return;
        }
        setTimeout(look, 20);
      };
      look();
    });
    // The server's close is what is measured; this end closes only after
    // it, or after the delay and some.
    setTimeout(function () {
      raw.destroy();
    }, DELAY_MS + 500);
  });
}

// The four ways in, EACH probes of each, all at once.
const KINDS = {
  a: { version: 'TLSv1.3', waitMs: 0 },
  b: { version: 'TLSv1.3', waitMs: 150 },
  c: { version: 'TLSv1.2', waitMs: 150 },
  d: { version: 'TLSv1.3', waitMs: 150, alpn: 'h2' }
};

async function allKinds(where) {
  log.debug("Entering allKinds().");
  const names = Object.keys(KINDS);
  const runs = [];
  names.forEach(function (name) {
    for (let i = 0; i < EACH; i++) {
      runs.push(probe(where, KINDS[name]).then(function (r) {
        return Object.assign(r, { kind: name });
      }));
    }
  });
  const results = await Promise.all(runs);
  const byKind = {};
  names.forEach(function (name) {
    byKind[name] = results.filter(function (r) {
      return r.kind === name;
    });
  });
  log.debug("Leaving allKinds().");
  return byKind;
}

function summary(list) {
  log.debug("Entering summary().");
  log.debug("Leaving summary().");
  return JSON.stringify(list.map(function (r) {
    return { alert: r.alert, error: r.error, secured: r.secured,
             tlsClientError: r.tlsClientError,
             closedAfter: r.serverClosedAfter };
  }));
}

function closedAtOnce(r) {
  log.debug("Entering closedAtOnce().");
  log.debug("Leaving closedAtOnce().");
  return r.serverClosedAfter !== null && r.serverClosedAfter < AT_ONCE_MS;
}

function held(r) {
  log.debug("Entering held().");
  log.debug("Leaving held().");
  return r.serverClosedAfter !== null &&
         r.serverClosedAfter >= DELAY_MS - 50 &&
         r.serverClosedAfter < DELAY_MS + 2000;
}

async function run(t) {
  log.debug("Entering run().");
  const pki = await pepCredential.mint({ subject: 'CN=127.0.0.1,O=tests',
                                         crlBase: false });

  // 1. The control.
  const plain = await listener(pki, null);
  try {
    const byKind = await allKinds(plain);
    Object.keys(byKind).forEach(function (name) {
      t.check(byKind[name].every(closedAtOnce),
              '1' + name + '. without the alert close a connection that ' +
              'failed is closed at once', summary(byKind[name]));
    });
  } finally {
    plain.server.close();
  }

  // 2. The alert close.
  const delayed = await listener(pki, { delayMs: DELAY_MS });
  try {
    const byKind = await allKinds(delayed);
    Object.keys(byKind).forEach(function (name) {
      const list = byKind[name];
      t.check(list.every(function (r) {
        return /BAD_RECORD_MAC/.test(r.alert);
      }), '2' + name + '. every client reads the bad_record_mac alert',
              summary(list));
      t.check(list.every(held),
              '2' + name + '. and the server closes only after the delay',
              summary(list));
    });
    t.check(byKind.a.some(function (r) {
      return r.tlsClientError && !r.secured;
    }), '2a. a failure before the handshake was counted done happened',
            summary(byKind.a));
    t.check(byKind.b.concat(byKind.c, byKind.d).every(function (r) {
      return r.secured && !r.tlsClientError;
    }), '2b-d. and the others failed after it', '');
    t.equal(AlertClose.heldOn(delayed.server), 0,
            '2e. every held connection was released');
  } finally {
    delayed.server.close();
  }

  // 3. The bound.
  const bounded = await listener(pki, { delayMs: DELAY_MS, maxHeld: 2 });
  try {
    const runs = [];
    for (let i = 0; i < 6; i++) {
      runs.push(probe(bounded, KINDS.b));
    }
    const results = await Promise.all(runs);
    t.equal(results.filter(held).length, 2,
            '3a. a listener holds no more than its bound', summary(results));
    t.equal(results.filter(closedAtOnce).length, 4,
            '3b. and closes the failures beyond it at once',
            summary(results));
    t.equal(AlertClose.heldOn(bounded.server), 0,
            '3c. and releases every one it held');
  } finally {
    bounded.server.close();
  }

  // 4. A peer's alert is not held; a good request is untouched.
  const quiet = await listener(pki, { delayMs: DELAY_MS });
  try {
    const refused = await peerAlert(quiet, await clientHello());
    t.check(/_ALERT_/.test(refused.serverError),
            '4a. a client answering the server\'s first flight with a fatal ' +
            'alert reaches the server as the client\'s alert',
            JSON.stringify(refused));
    t.check(refused.serverClosedAfter !== null &&
            refused.serverClosedAfter < AT_ONCE_MS,
            '4b. and the server closes on it at once, holding nothing',
            String(refused.serverClosedAfter));
    const body = await new Promise(function (resolve, reject) {
      https.get({ host: '127.0.0.1', port: quiet.port, path: '/',
                  rejectUnauthorized: false, agent: false }, function (res) {
        let text = '';
        res.on('data', function (d) {
          text += d;
        });
        res.on('end', function () {
          resolve(text);
        });
      }).on('error', reject);
    });
    t.equal(body, 'ok', '4c. a good request is answered');
    t.equal(AlertClose.heldOn(quiet.server), 0, '4d. and nothing is held');
  } finally {
    quiet.server.close();
  }

  // 4e. The parser refusal answers a TLS failure with nothing: no plaintext
  // 400 into a connection whose TLS engine has sent its fatal alert.
  const writes = [];
  let destroyed = 0;
  const fake = {
    writable: true,
    write: function (d) {
      writes.push(String(d));
    },
    destroy: function () {
      destroyed += 1;
    },
    destroySoon: function () {
      destroyed += 1;
    },
    on: function () {
      return fake;
    },
    once: function () {
      return fake;
    },
    removeAllListeners: function () {
      return fake;
    },
    setTimeout: function () {
      return fake;
    },
    resume: function () {
      return fake;
    },
    end: function () {
      return fake;
    }
  };
  ParserRefusal.answer({ code: 'ERR_SSL_DECRYPTION_FAILED_OR_BAD_RECORD_MAC',
                         library: 'SSL routines' }, fake, 'the test');
  t.check(writes.length === 0 && destroyed === 1,
          '4e. the parser refusal writes nothing on a TLS failure and ' +
          'closes it',
          JSON.stringify({ writes: writes, destroyed: destroyed }));

  // 5. Where it is installed.
  const server = fs.readFileSync(path.join(ROOT, 'server.js'), 'utf8');
  t.check(/require\('\.\/tls\/alert_close'\)\.install\(mainServer,/
            .test(server),
          '5a. server.js installs it on the main port');
  t.check(/require\('\.\/tls\/alert_close'\)\.install\(server, label\)/
            .test(server),
          '5b. and on every custom listener');
  const debuggerServer = fs.readFileSync(
    path.join(ROOT, 'debugger', 'debugger_server.ts'), 'utf8');
  t.check(/AlertClose\.install\(server,/.test(debuggerServer),
          '5c. and the debugger\'s listener has it');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'tls_alert_close',
  describe: 'a connection that fails at the TLS layer is closed after a ' +
            'delay, its reads drained, so the peer reads the alert before ' +
            'the close; bounded per listener; installed on the main port, ' +
            'the custom listeners and the debugger',
  run: run
};
