// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/tls_pq_listeners.js
// ===========================================================================
// LDAPS SERVES EVERY LISTENER CERTIFICATE, AND EVERY LISTENER COUNTS THE KEY
// EXCHANGE IT NEGOTIATED (#2220).
//
//   A. `tls/key_exchange.ts` reads the group off a session OpenSSL encoded:
//      a hand-made SSL_SESSION DER, a session with no [19], and garbage;
//   B. a TLS server with it installed, in this process: a client offering
//      only X25519MLKEM768, only SecP256r1MLKEM768 and only X25519 is each
//      counted under its group, the two hybrids as post-quantum; the
//      per-listener bound folds the rest into `other`;
//   C. LDAPS on 636 as `ldap.listen()` starts it, in a child, with
//      `tls.certificateAlgorithms` `rsa,ml-dsa-65`: a client that offers
//      only ML-DSA signature algorithms is served the ML-DSA certificate,
//      and one that offers only RSA the RSA one — the main port's
//      behaviour, which LDAPS lacked — and its handshakes are counted under
//      `ldaps`.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const tls = require('tls');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'tls_pq_listeners',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// One handshake: the peer certificate's key type, and the group the client
// saw. Resolves on close; never rejects.
function handshake(port, opts) {
  log.debug("Entering handshake(). " + port);
  log.debug("Leaving handshake().");
  return new Promise(function (resolve) {
    let out = { ok: false };
    const socket = tls.connect(Object.assign({ host: '127.0.0.1',
      port: port, rejectUnauthorized: false, servername: 'localhost' },
    opts), function () {
      let keyType = '';
      try {
        const peer = socket.getPeerX509Certificate();
        keyType = peer ? String(peer.publicKey.asymmetricKeyType) : '';
      } catch (e) {
        log.debug("Caught in handshake(): " + ((e && e.message) || e));
      }
      out = { ok: true, keyType: keyType,
              group: (socket.getEphemeralKeyInfo() || {}).name || '' };
      socket.end();
    });
    socket.on('data', function () {});
    socket.on('error', function (e) {
      out = { ok: false, error: String((e && e.message) || e) };
    });
    socket.on('close', function () {
      resolve(out);
    });
    socket.setTimeout(15000, function () {
      socket.destroy();
    });
  });
}

function checkParser(t) {
  log.debug("Entering checkParser().");
  const KeyExchange = require('../tls/key_exchange');
  // SEQUENCE { INTEGER 1, [1] { INTEGER }, [19] { INTEGER 0x11ec } }
  const der = Buffer.from('30' + '0e' + '020101' + 'a1' + '03' + '020101' +
                          'b3' + '04' + '020211ec', 'hex');
  t.equal(KeyExchange.groupCodeOfSession(der), 0x11ec,
          'A1. kex_group [19] is read from an SSL_SESSION DER');
  t.equal(KeyExchange.describeCode(0x11ec).group, 'X25519MLKEM768',
          'A2. 0x11ec is X25519MLKEM768');
  t.equal(KeyExchange.describeCode(0x11ec).postQuantum, true,
          'A3. and it is post-quantum, a hybrid');
  t.equal(KeyExchange.describeCode(0x001d).postQuantum, false,
          'A4. X25519 is classical');
  t.equal(KeyExchange.groupCodeOfSession(Buffer.from('3003020101', 'hex')),
          null, 'A5. a session with no [19] has no group');
  t.equal(KeyExchange.groupCodeOfSession(Buffer.from('ff00', 'hex')), null,
          'A6. garbage is no group, and does not throw');
  t.equal(KeyExchange.describeCode(0x9999).group, '0x9999',
          'A7. an unregistered code point is named by its number');
  log.debug("Leaving checkParser().");
}

async function checkCounting(t) {
  log.debug("Entering checkCounting().");
  const KeyExchange = require('../tls/key_exchange');
  const made = require('../common/crypto').selfSignedRsaCertificate({
    commonName: 'localhost' });
  KeyExchange.reset();
  const server = tls.createServer({ key: made.privateKeyPem,
    cert: made.certPem,
    ecdhCurve: 'X25519MLKEM768:SecP256r1MLKEM768:X25519:P-256' },
  function (socket) {
    socket.end();
  });
  KeyExchange.install(server, 'test', 'the test listener');
  await new Promise(function (r) {
    server.listen(0, '127.0.0.1', r);
  });
  const port = server.address().port;
  try {
    for (const group of ['X25519MLKEM768', 'SecP256r1MLKEM768', 'X25519']) {
      const seen = await handshake(port, { ecdhCurve: group });
      t.check(seen.ok && seen.group === group,
              'B1. a client offering only ' + group + ' negotiated it',
              JSON.stringify(seen));
    }
    // The server's 'secureConnection' runs before the client closes; give
    // the last one a turn of the loop.
    await new Promise(function (r) {
      setImmediate(r);
    });
    const report = KeyExchange.report();
    const row = report.listeners.filter(function (one) {
      return one.listener === 'test';
    })[0] || { groups: [] };
    const by = {};
    row.groups.forEach(function (g) {
      by[g.group] = g;
    });
    t.check(by.X25519MLKEM768 && by.X25519MLKEM768.connections === 1 &&
            by.X25519MLKEM768.postQuantum && by.X25519MLKEM768.hybrid,
            'B2. the X25519MLKEM768 handshake was counted, post-quantum',
            JSON.stringify(row.groups));
    t.check(by.SecP256r1MLKEM768 && by.SecP256r1MLKEM768.postQuantum,
            'B3. so was SecP256r1MLKEM768');
    t.check(by.x25519 && by.x25519.postQuantum === false,
            'B4. X25519 was counted as classical');
    t.equal(report.connections, 3, 'B5. three connections in all');
    t.equal(report.postQuantum, 2, 'B6. two of them post-quantum');
    for (let i = 0; i < KeyExchange.MAX_GROUPS + 3; i++) {
      KeyExchange.record('bound', 'the bound', KeyExchange.describeCode(
        0x7000 + i));
    }
    const bound = KeyExchange.report().listeners.filter(function (one) {
      return one.listener === 'bound';
    })[0];
    t.check(bound && bound.groups.length === KeyExchange.MAX_GROUPS + 1 &&
            bound.groups.some(function (g) {
              return g.group === 'other' && g.connections === 3;
            }), 'B7. past the bound, a listener\'s groups are counted as ' +
            '`other`', String(bound && bound.groups.length));
  } finally {
    server.close();
    KeyExchange.reset();
  }
  log.debug("Leaving checkCounting().");
}

// In a child: LDAPS as `server.js` starts it, with two listener
// certificates, asked by a client of each kind.
async function inChild() {
  log.debug("Entering inChild().");
  const out = process.env.TPQ_OUT;
  const report = { versions: {} };
  try {
    require(path.join(ROOT, 'common/protocol_stack'));
    const config = require(path.join(ROOT, 'common/config'));
    const ldap = require(path.join(ROOT, 'ldap/ldap_server'));
    report.algorithms = config.value('tls.certificateAlgorithms');
    const ready = await ldap.listen().whenReady;
    report.port = ready.ldapsPort;
    report.mldsa = await handshake(ready.ldapsPort, {
      sigalgs: 'mldsa65:mldsa44:mldsa87', ecdhCurve: 'X25519MLKEM768' });
    report.rsa = await handshake(ready.ldapsPort, {
      sigalgs: 'rsa_pss_rsae_sha256:rsa_pkcs1_sha256', ecdhCurve: 'X25519' });
    await new Promise(function (r) {
      setTimeout(r, 200);
    });
    report.kx = require(path.join(ROOT, 'tls/key_exchange')).report();
  } catch (e) {
    log.debug("Caught in inChild(): " + ((e && e.message) || e));
    report.error = String((e && e.stack) || e);
  }
  fs.writeFileSync(out, JSON.stringify(report));
  log.debug("Leaving inChild().");
  process.exit(0);
}

function child() {
  log.debug("Entering child().");
  const out = path.join(os.tmpdir(), 'tpq-' + process.pid + '-' +
                        Date.now() + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(KRB5_|STS_|LDAP_|LDAPS_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath, ['-e',
    'require(' + JSON.stringify(__filename) + ').inChild()'], {
    env: Object.assign(clean, { LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal',
                                STS_MODE: 'development',
                                STS_HOST: '127.0.0.1',
                                STS_TLS_CERT_ALGS: 'rsa,ml-dsa-65',
                                LDAP_PORT: '0', LDAPS_PORT: '0',
                                TPQ_OUT: out }),
    encoding: 'utf8', timeout: 180000, cwd: ROOT
  });
  let report = null;
  try {
    report = JSON.parse(fs.readFileSync(out, 'utf8'));
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in child(): " + ((e && e.message) || e));
    report = { error: 'no report: exit ' + result.status + ' ' +
                      String(result.stderr || '').slice(-600) };
  }
  log.debug("Leaving child().");
  return report;
}

function checkLdaps(t) {
  log.debug("Entering checkLdaps().");
  const report = child();
  if (!t.check(!report.error && report.port,
               'C1. LDAPS started with rsa,ml-dsa-65',
               report.error || JSON.stringify(report.algorithms))) {
    log.debug("Leaving checkLdaps(). No listener.");
    return;
  }
  t.check(report.mldsa.ok && /^ml-dsa/.test(report.mldsa.keyType),
          'C2. a client offering only ML-DSA is served the ML-DSA ' +
          'certificate on 636', JSON.stringify(report.mldsa));
  t.check(report.rsa.ok && report.rsa.keyType === 'rsa',
          'C3. a client offering only RSA is served the RSA certificate',
          JSON.stringify(report.rsa));
  const ldaps = ((report.kx && report.kx.listeners) || []).filter(
    function (one) {
      return one.listener === 'ldaps';
    })[0];
  t.check(ldaps && ldaps.connections >= 2 && ldaps.postQuantum >= 1,
          'C4. LDAPS counted its handshakes, the X25519MLKEM768 one as ' +
          'post-quantum', JSON.stringify(ldaps));
  log.debug("Leaving checkLdaps().");
}

async function run(t) {
  log.debug("Entering run().");
  checkParser(t);
  await checkCounting(t);
  checkLdaps(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'tls_pq_listeners',
  describe: 'LDAPS serves every listener certificate (RSA and ML-DSA), and ' +
            'every listener counts the key exchange it negotiated (#2220)',
  run: run,
  inChild: inChild
};
