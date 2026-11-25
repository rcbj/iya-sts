// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: ldap_message_guard.js
//
// ===========================================================================
// AN LDAP MESSAGE IS REFUSED FROM ITS HEADER, BEFORE IT IS BUFFERED (#2220).
//
// node-ldapjs's parser holds a connection's bytes until the length a
// message's BER header declares has arrived. `ldap/ldap_message_guard.ts`
// reads the header first and closes the connection when the declared length
// is over `ldap.maxMessageBytesBeforeBind` (before a bind) or
// `ldap.maxMessageBytes` (after one). This file holds:
//
//   A. THE GUARD ALONE: a header split over chunks, the short and long
//      forms, several messages in one chunk, the indefinite length, a first
//      octet that is not a SEQUENCE (stepped aside), and the two limits.
//   B. THE SERVICE: `ldap/ldap_server.js` started as `server.js` starts it,
//      in a child process, with `ldap.maxMessageBytes` at 1 MiB:
//        1. a bind and a search are answered (the control);
//        2. a header declaring 256 MiB, followed by 1 KiB, closes the
//           connection AT ONCE — had anything waited for the rest it would
//           time out, which is how "without buffering it" is observed;
//        3. a header declaring 300 KiB closes it before a bind;
//        4. a modify carrying a 300 KiB value after a bind is answered;
//        5. a header declaring 2 MiB after a raw bind on the same
//           connection closes it;
//        6. the indefinite length closes it;
//        7. on LDAPS (636) the 256 MiB header closes it too;
//        8. afterwards the bind and the search are still answered.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const tls = require('tls');

const ROOT = path.join(__dirname, '..');
const CHILD_FLAG = 'STS_LDAP_MESSAGE_GUARD_CHILD';
const CHILD_TIMEOUT_MS = 120000;
const ANSWER_MS = 5000;

const log = require('bunyan').createLogger({
  name: 'ldap_message_guard',
  level: process.env.LOG_LEVEL || 'info' });

function recorder() {
  log.debug("Entering recorder().");
  const rows = [];
  log.debug("Leaving recorder().");
  return {
    rows: rows,
    check: function (ok, what, detail) {
      log.debug("Entering check().");
      rows.push({ ok: !!ok, what: what,
                  detail: detail === undefined ? ''
                    : String(detail).slice(0, 2000) });
      log.debug("Leaving check().");
      return !!ok;
    }
  };
}

// A BER TLV: the tag, the definite length in its shortest form, the content.
function tlv(tag, content) {
  log.debug("Entering tlv().");
  const length = content.length;
  let head = null;
  if (length < 0x80) {
    head = Buffer.from([tag, length]);
  } else {
    const octets = [];
    let n = length;
    while (n > 0) {
      octets.unshift(n & 0xff);
      n = Math.floor(n / 256);
    }
    head = Buffer.from([tag, 0x80 | octets.length].concat(octets));
  }
  log.debug("Leaving tlv().");
  return Buffer.concat([head, content]);
}

// An LDAPMessage header only: a SEQUENCE declaring `length` content octets,
// in the four-octet long form.
function headerDeclaring(length) {
  log.debug("Entering headerDeclaring().");
  log.debug("Leaving headerDeclaring().");
  return Buffer.from([0x30, 0x84, (length >>> 24) & 0xff,
                      (length >>> 16) & 0xff, (length >>> 8) & 0xff,
                      length & 0xff]);
}

// A simple BindRequest, message id 1, LDAP version 3.
function bindRequest(dn, password) {
  log.debug("Entering bindRequest().");
  const body = Buffer.concat([
    tlv(0x02, Buffer.from([0x03])),
    tlv(0x04, Buffer.from(dn, 'utf8')),
    tlv(0x80, Buffer.from(password, 'utf8'))]);
  log.debug("Leaving bindRequest().");
  return tlv(0x30, Buffer.concat([tlv(0x02, Buffer.from([0x01])),
                                  tlv(0x60, body)]));
}

// ---------------------------------------------------------------------------
// A. THE GUARD ALONE.
// ---------------------------------------------------------------------------
function unitChecks(t) {
  log.debug("Entering unitChecks().");
  const Guard = require('../ldap/ldap_message_guard');
  const limits = function () {
    return { bound: 1000, unbound: 100 };
  };
  let g = new Guard(limits);
  t.check(g.feed(Buffer.from([0x30, 0x05, 1, 2, 3, 4, 5]), false) === null,
          'A: a short-form message under the limit passes');
  g = new Guard(limits);
  t.check(g.feed(Buffer.from([0x30, 0x03, 1, 2, 3, 0x30, 0x02, 1, 2]),
                 false) === null,
          'A: two messages in one chunk pass');
  g = new Guard(limits);
  t.check(g.feed(Buffer.from([0x30]), false) === null &&
          g.feed(Buffer.from([0x82, 0x00]), false) === null,
          'A: a header split over chunks is waited for');
  const split = g.feed(Buffer.from([0x80]), false);
  t.check(split && split.reason === 'too-long' &&
          split.declared === 4 + 128 && split.limit === 100,
          'A: ... and refused once its length is known (128 content ' +
          'octets plus a 4-octet header, over 100 before a bind)',
          JSON.stringify(split));
  g = new Guard(limits);
  const bound = g.feed(Buffer.from([0x30, 0x82, 0x00, 0x80]), true);
  t.check(bound === null, 'A: the same message passes once bound (limit ' +
          '1000)', JSON.stringify(bound));
  g = new Guard(limits);
  const over = g.feed(Buffer.from([0x30, 0x82, 0x04, 0x00]), true);
  t.check(over && over.declared === 1028 && over.bound === true,
          'A: a bound message over 1000 is refused', JSON.stringify(over));
  g = new Guard(limits);
  const huge = g.feed(headerDeclaring(0x7fffffff), true);
  t.check(huge && huge.reason === 'too-long',
          'A: a header declaring 2 GiB is refused from six octets',
          JSON.stringify(huge));
  g = new Guard(limits);
  const indefinite = g.feed(Buffer.from([0x30, 0x80, 0x02]), true);
  t.check(indefinite && indefinite.reason === 'indefinite',
          'A: the indefinite length is refused', JSON.stringify(indefinite));
  g = new Guard(limits);
  t.check(g.feed(Buffer.from([0x04, 0x84, 0xff, 0xff, 0xff, 0xff]),
                 false) === null &&
          g.feed(Buffer.alloc(500), false) === null,
          'A: a stream that is not LDAP is left to ldapjs to refuse');
  g = new Guard(limits);
  t.check(g.feed(Buffer.from([0x30, 0x05, 1, 2]), false) === null &&
          g.feed(Buffer.from([3, 4, 5, 0x30, 0x10]), false) === null,
          'A: a message\'s content split over chunks is skipped, and the ' +
          'next header read');
  const both = new Guard(function () {
    return { bound: 50, unbound: 100 };
  }).feed(Buffer.from([0x30, 0x40]), false);
  t.check(both && both.limit === 50,
          'A: before a bind the limit is never more than ldap.maxMessageBytes',
          JSON.stringify(both));
  log.debug("Leaving unitChecks().");
}

// Writes `bytes` on a fresh connection (or `socket`). Answers `closed` when
// the server closes it, `answered` when bytes come back, and `timeout` when
// neither happens within ANSWER_MS.
function sendRaw(connect, bytes) {
  log.debug("Entering sendRaw().");
  log.debug("Leaving sendRaw().");
  return new Promise(function (resolve) {
    const socket = connect();
    let done = false;
    const finish = function (outcome) {
      log.debug("Entering finish(). " + outcome);
      if (done) {
        log.debug("Leaving finish(). Already finished.");
        return;
      }
      done = true;
      clearTimeout(timer);
      socket.destroy();
      resolve(outcome);
      log.debug("Leaving finish().");
    };
    const timer = setTimeout(function () {
      finish('timeout');
    }, ANSWER_MS);
    socket.on('data', function () {
      finish('answered');
    });
    socket.on('close', function () {
      finish('closed');
    });
    socket.on('error', function (e) {
      log.debug("Caught in sendRaw(): " + ((e && e.message) || e));
      finish('closed');
    });
    socket.write(bytes);
  });
}

// A raw bind on one connection, then `after` on the same one once the bind
// is answered: `{ bind, outcome }`, the bind's result code and what `after`
// got.
function bindThenSend(port, dn, after) {
  log.debug("Entering bindThenSend().");
  log.debug("Leaving bindThenSend().");
  return new Promise(function (resolve) {
    const socket = net.connect(port, '127.0.0.1');
    const result = { bind: null, outcome: null };
    let phase = 'bind';
    const finish = function (outcome) {
      log.debug("Entering finish(). " + outcome);
      if (result.outcome) {
        log.debug("Leaving finish(). Already finished.");
        return;
      }
      result.outcome = outcome;
      clearTimeout(timer);
      socket.destroy();
      resolve(result);
      log.debug("Leaving finish().");
    };
    const timer = setTimeout(function () {
      finish(phase === 'bind' ? 'bind-timeout' : 'timeout');
    }, ANSWER_MS * 2);
    socket.on('data', function (chunk) {
      if (phase === 'bind') {
        const at = chunk.indexOf(Buffer.from([0x61]));
        const code = at >= 0 ? chunk.indexOf(Buffer.from([0x0a, 0x01]), at)
          : -1;
        result.bind = code >= 0 ? chunk[code + 2] : -1;
        phase = 'after';
        socket.write(after);
        return;
      }
      finish('answered');
    });
    socket.on('close', function () {
      finish(phase === 'bind' ? 'closed-before-bind' : 'closed');
    });
    socket.on('error', function (e) {
      log.debug("Caught in bindThenSend(): " + ((e && e.message) || e));
      finish('closed');
    });
    socket.write(bindRequest(dn, 'secret'));
  });
}

// node-ldapjs's own client: a bind, then either a base search of `base`
// or (with `modify`) a replace of `description` on it.
function client(port, bindDn, base, modify) {
  log.debug("Entering client(). " + bindDn);
  const ldapjs = require('ldapjs');
  log.debug("Leaving client().");
  return new Promise(function (resolve) {
    const result = { bind: null, entries: [], search: null, modify: null };
    const c = ldapjs.createClient({
      url: 'ldap://127.0.0.1:' + port, reconnect: false,
      timeout: ANSWER_MS * 2, connectTimeout: ANSWER_MS });
    let done = false;
    const finish = function () {
      log.debug("Entering finish().");
      if (done) {
        log.debug("Leaving finish(). Already finished.");
        return;
      }
      done = true;
      clearTimeout(timer);
      c.destroy();
      resolve(result);
      log.debug("Leaving finish().");
    };
    const timer = setTimeout(function () {
      result.timeout = true;
      finish();
    }, ANSWER_MS * 3);
    c.on('error', function (e) {
      log.debug("Caught in client(): " + ((e && e.message) || e));
      result.error = (e && e.message) || String(e);
      finish();
    });
    c.bind(bindDn, 'secret', function (e) {
      result.bind = e ? e.code : 0;
      if (e) {
        finish();
        return;
      }
      if (modify) {
        c.modify(base, [new ldapjs.Change({ operation: 'replace',
          modification: new ldapjs.Attribute({ type: 'description',
                                               values: [modify] }) })],
        function (err) {
          result.modify = err ? err.code : 0;
          result.message = err ? String(err.message || '') : '';
          finish();
        });
        return;
      }
      c.search(base, { scope: 'base', attributes: ['uid'] },
        function (err, res) {
          if (err) {
            result.search = err.code;
            finish();
            return;
          }
          res.on('searchEntry', function (entry) {
            result.entries.push(String(entry.objectName));
          });
          res.on('error', function (e2) {
            result.search = e2.code;
            finish();
          });
          res.on('end', function (r) {
            result.search = r ? r.status : null;
            finish();
          });
        });
    });
  });
}

// ---------------------------------------------------------------------------
// B. THE SERVICE, IN A CHILD.
// ---------------------------------------------------------------------------
async function childBody() {
  log.debug("Entering childBody().");
  const t = recorder();
  require(ROOT + '/common/protocol_stack');
  const keystore = require(ROOT + '/common/keystore');
  const ldap = require(ROOT + '/ldap/ldap_server');
  await keystore.start();
  ldap.createUser('lmgalice', { invent: false });
  const aliceDn = ldap.existingUserEntry('lmgalice').dn;
  const ready = await ldap.listen().whenReady;
  const port = ready.port;
  if (!t.check(!!port, 'B: precondition: 389 is listening',
               JSON.stringify(ready))) {
    log.debug("Leaving childBody(). Not listening.");
    return t.rows;
  }
  const plain = function () {
    return net.connect(port, '127.0.0.1');
  };
  const ordinary = async function (label) {
    log.debug("Entering ordinary(). " + label);
    const got = await client(port, aliceDn, aliceDn, null);
    t.check(got.bind === 0 && got.search === 0 &&
            got.entries.length === 1,
            label + ': a bind and a base search are answered',
            JSON.stringify(got));
    log.debug("Leaving ordinary().");
  };

  await ordinary('B1');

  const started = Date.now();
  const huge = await sendRaw(plain, Buffer.concat([
    headerDeclaring(256 * 1024 * 1024), Buffer.alloc(1024, 0x41)]));
  t.check(huge === 'closed' && Date.now() - started < ANSWER_MS,
          'B2: a header declaring 256 MiB, then 1 KiB, closes the ' +
          'connection at once rather than waiting for the rest',
          huge + ' after ' + (Date.now() - started) + ' ms');

  const before = await sendRaw(plain, Buffer.concat([
    headerDeclaring(300 * 1024), Buffer.alloc(1024, 0x41)]));
  t.check(before === 'closed',
          'B3: a 300 KiB message before a bind is over ' +
          'ldap.maxMessageBytesBeforeBind and closes the connection', before);

  const big = 'x'.repeat(300 * 1024);
  const modified = await client(port, aliceDn, aliceDn, big);
  t.check(modified.bind === 0 && modified.modify === 0 && !modified.error,
          'B4: after a bind, a modify carrying a 300 KiB value is answered ' +
          'and succeeds', JSON.stringify(Object.assign({}, modified,
                                                       { entries: [] })));

  const after = await bindThenSend(port, aliceDn, Buffer.concat([
    headerDeclaring(2 * 1024 * 1024), Buffer.alloc(1024, 0x41)]));
  t.check(after.bind === 0 && after.outcome === 'closed',
          'B5: after a bind on the same connection, a 2 MiB message is ' +
          'over ldap.maxMessageBytes (1 MiB here) and closes it',
          JSON.stringify(after));

  const indefinite = await sendRaw(plain, Buffer.from([0x30, 0x80, 0x02,
                                                       0x01, 0x01]));
  t.check(indefinite === 'closed',
          'B6: the indefinite length closes the connection', indefinite);

  if (ready.ldapsPort) {
    const secure = function () {
      return tls.connect({ port: ready.ldapsPort, host: '127.0.0.1',
                           rejectUnauthorized: false });
    };
    const overTls = await sendRaw(secure, Buffer.concat([
      headerDeclaring(256 * 1024 * 1024), Buffer.alloc(1024, 0x41)]));
    t.check(overTls === 'closed',
            'B7: on LDAPS a header declaring 256 MiB closes the connection',
            overTls);
  } else {
    t.check(false, 'B7: precondition: LDAPS is listening',
            JSON.stringify(ready));
  }

  await ordinary('B8');
  log.debug("Leaving childBody().");
  return t.rows;
}

function spawnChild() {
  log.debug("Entering spawnChild().");
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(KRB5_|STS_|LDAP_|LDAPS_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const stamp = process.pid + '-' + Date.now();
  const out = path.join(os.tmpdir(), 'lmg-' + stamp + '.json');
  Object.assign(clean, { LMG_OUT: out,
                         LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal',
                         STS_HOST: '127.0.0.1',
                         LDAP_PORT: '0', LDAPS_PORT: '0',
                         LDAP_MAX_MESSAGE_BYTES: '1048576' });
  clean[CHILD_FLAG] = '1';
  const result = childProcess.spawnSync(process.execPath, [__filename], {
    cwd: ROOT, env: clean, encoding: 'utf8', timeout: CHILD_TIMEOUT_MS,
    killSignal: 'SIGKILL', maxBuffer: 64 * 1024 * 1024
  });
  let rows = null;
  try {
    rows = JSON.parse(fs.readFileSync(out, 'utf8'));
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in spawnChild(): " + ((e && e.message) || e));
    rows = null;
  }
  if (!rows) {
    log.debug("Leaving spawnChild(). No result.");
    return { error: 'the child produced no result (exit ' + result.status +
                    ', signal ' + result.signal + '): ' +
                    String(result.stderr || '').slice(-1500) };
  }
  log.debug("Leaving spawnChild().");
  return { rows: rows };
}

function run(t) {
  log.debug("Entering run().");
  unitChecks(t);
  const got = spawnChild();
  if (!t.check(!got.error, 'B: the child ran to the end', got.error)) {
    log.debug("Leaving run(). The child failed.");
    return;
  }
  got.rows.forEach(function (row) {
    t.check(row.ok, row.what, row.detail);
  });
  log.debug("Leaving run().");
}

if (process.env[CHILD_FLAG] === '1' && require.main === module) {
  childBody().then(function (rows) {
    fs.writeFileSync(process.env.LMG_OUT, JSON.stringify(rows));
    process.exit(0);
  }, function (e) {
    process.stderr.write('child failed: ' + String((e && e.stack) || e) +
                         '\n');
    process.exit(1);
  });
}

module.exports = {
  name: 'ldap_message_guard',
  describe: 'LDAP: a message whose BER header declares more than ' +
            'ldap.maxMessageBytesBeforeBind or ldap.maxMessageBytes closes ' +
            'its connection before it is buffered, on 389 and 636, and ' +
            'ordinary traffic and a large modify still work (#2220)',
  run: run
};
