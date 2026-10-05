// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/ldaps_no_certificate_request.js
// ===========================================================================
// LDAPS 636 ASKS FOR NO CLIENT CERTIFICATE (#418, 2026-10-02).
//
// The main port asks every handshake for a client certificate (RFC 8705,
// certificate sign-in, the remote PEP) and requires none; LDAPS does not ask
// at all — a bind is how a directory client says who it is. Nothing held that
// (#113 item 14): `tests/vendored/tlsfuzzer_kit.js` only skips its
// CertificateRequest probes for LDAPS. A listener that started asking would
// put a certificate prompt in front of every LDAP client holding one, and a
// strict client could refuse to bind.
//
// OpenSSL's own client prints every handshake message (`s_client -msg`), so
// the absence is read off the wire rather than off this service's options:
//
//   A. the CONTROL — a TLS server that does ask (`requestCert: true`) is seen
//      to send a CertificateRequest, in TLS 1.2 and 1.3, so the detector can
//      see one;
//   B. the directory's own LDAPS listener, started as the service starts it
//      (`ldap.listen()`), sends none, in TLS 1.2 and 1.3 — in development and
//      in product, a child process each (the mode is read at start).
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'ldaps_no_certificate_request',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// The handshake messages OpenSSL's client saw from `port`, in one version.
// ASYNCHRONOUS, AND THAT IS THE POINT: the server under test is in this same
// process, and a spawnSync() would block the very event loop that has to
// answer the handshake — OpenSSL then waits for a ServerHello that never
// comes, and is killed at the timeout.
function handshakeOf(port, version) {
  log.debug("Entering handshakeOf(). " + port + " " + version);
  log.debug("Leaving handshakeOf().");
  return new Promise(function (resolve) {
    const proc = childProcess.spawn('openssl', ['s_client', '-connect',
      '127.0.0.1:' + port, version === 'TLSv1.3' ? '-tls1_3' : '-tls1_2',
      '-msg']);
    let text = '';
    proc.stdout.on('data', function (d) { text += d; });
    proc.stderr.on('data', function (d) { text += d; });
    const timer = setTimeout(function () {
      proc.kill('SIGKILL');
    }, 20000);
    proc.on('close', function () {
      clearTimeout(timer);
      resolve({
        text: text,
        finished: /Handshake \[length [0-9a-f]+\], Finished/.test(text),
        certificateRequest: /, CertificateRequest/.test(text)
      });
    });
    // No input: s_client sends nothing after the handshake and, its stdin
    // closed, ends the connection.
    proc.stdin.end();
  });
}

// In a child: the directory's LDAPS listener, as `server.js` starts it, and
// what OpenSSL saw of it.
async function inChild() {
  log.debug("Entering inChild().");
  const out = process.env.LNCR_OUT;
  const report = { mode: '', versions: {} };
  try {
    require(path.join(ROOT, 'common/protocol_stack'));
    const config = require(path.join(ROOT, 'common/config'));
    const ldap = require(path.join(ROOT, 'ldap/ldap_server'));
    report.mode = String(config.value('global.mode'));
    const ready = await ldap.listen().whenReady;
    report.port = ready.ldapsPort;
    for (const v of ['TLSv1.2', 'TLSv1.3']) {
      const seen = await handshakeOf(ready.ldapsPort, v);
      report.versions[v] = { finished: seen.finished,
                             certificateRequest: seen.certificateRequest,
                             tail: seen.text.slice(-400) };
    }
  } catch (e) {
    log.debug("Caught in inChild(): " + ((e && e.message) || e));
    report.error = String((e && e.stack) || e);
  }
  fs.writeFileSync(out, JSON.stringify(report));
  log.debug("Leaving inChild().");
  process.exit(0);
}

function child(mode) {
  log.debug("Entering child(). " + mode);
  const out = path.join(os.tmpdir(), 'lncr-' + process.pid + '-' + mode +
                        '-' + Date.now() + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(KRB5_|STS_|LDAP_|LDAPS_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath, ['-e',
    'require(' + JSON.stringify(__filename) + ').inChild()'], {
    env: Object.assign(clean, { LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal',
                                STS_MODE: mode, STS_HOST: '127.0.0.1',
                                // TLS 1.2 on, so both versions are asked:
                                // every listener is TLS 1.3 only by default
                                // since #429.
                                STS_TLS_DISABLE_TLS12: 'false',
                                LDAP_PORT: '0', LDAPS_PORT: '0',
                                LNCR_OUT: out }),
    encoding: 'utf8', timeout: 120000, cwd: ROOT
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

async function run(t) {
  log.debug("Entering run().");

  t.log.info('=== A. the control: a server that asks is seen to ===');
  const tls = require('tls');
  const made = require('../common/crypto').selfSignedRsaCertificate({
    commonName: 'localhost' });
  const asking = tls.createServer({ key: made.privateKeyPem,
                                    cert: made.certPem, requestCert: true,
                                    rejectUnauthorized: false },
                                  function (socket) { socket.end(); });
  await new Promise(function (r) { asking.listen(0, '127.0.0.1', r); });
  try {
    for (const v of ['TLSv1.2', 'TLSv1.3']) {
      const seen = await handshakeOf(asking.address().port, v);
      t.check(seen.finished && seen.certificateRequest,
              'A. ' + v + ': OpenSSL sees the CertificateRequest a ' +
              'requestCert server sends', seen.text.slice(-300));
    }
  } finally {
    asking.close();
  }

  for (const mode of ['development', 'product']) {
    t.log.info('=== B. LDAPS in ' + mode + ' ===');
    const report = child(mode);
    if (!t.check(!report.error && report.mode === mode,
                 'B. ' + mode + ': the directory\'s LDAPS listener started',
                 report.error || report.mode)) {
      continue;
    }
    ['TLSv1.2', 'TLSv1.3'].forEach(function (v) {
      const seen = report.versions[v] || {};
      t.check(seen.finished && !seen.certificateRequest,
              'B. ' + mode + ', ' + v + ': LDAPS completes the handshake ' +
              'and sends no CertificateRequest', seen.tail);
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'ldaps_no_certificate_request',
  describe: 'LDAPS 636 asks for no client certificate, in TLS 1.2 and 1.3, ' +
            'in both modes (#418)',
  run: run,
  inChild: inChild
};
