'use strict';
//
// File: tlsfuzzer_debugger.js
//
// ===========================================================================
// TLSFUZZER AGAINST THE EMBEDDED DEBUGGER'S LISTENER (#212, 2026-09-26).
//
// `tests/vendored/sts_tlsfuzzer.js` runs tlsfuzzer against the main port and
// LDAPS 636 of a running stack. The third TLS listener this process owns is
// the embedded debugger's (`debugger.port`), and no test stack binds it: a
// stack is built from this tree with no debugger tree embedded
// (debugger/CLAUDE.md), so `listen()` records "not installed" and binds
// nothing. So it is bound HERE, by `debugger_server.ts`'s own `listen()` —
// over TLS (`global.https`), from `tls_server.js`'s
// `clientTruststoreOptions()`, registered with `trustClientCertificatesOn()`
// exactly as the service does it — with a stand-in site directory and the
// api child's start stubbed, because the handshake is the whole of what is
// under test and the api is reached only after it.
//
// The PLAN is the stack job's, from tests/vendored/tlsfuzzer_kit.js, run for
// the listener `debugger`: every script that applies, every exception with
// its reason. The client certificates the certificate scripts present are
// made here with `openssl` and self-signed — the listener asks for one and
// requires none, so a certificate that chains to nothing still completes the
// handshake a CertificateVerify probe needs.
//
// Needs the tests image: tlsfuzzer is fetched there
// (tests/tlsfuzzer/build-tlsfuzzer.sh, STS_TLSFUZZER_DIR). Run anywhere
// else, this file FAILS naming that variable, as x509_limbo.js does: a
// conformance run that quietly ran nothing is the failure to prevent.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');

const log = require('bunyan').createLogger({ name: 'tlsfuzzer_debugger',
  level: process.env.LOG_LEVEL || 'info' });

// A port nobody holds, for `debugger.port` (a `port` setting takes no 0).
function freePort() {
  log.debug("Entering freePort().");
  log.debug("Leaving freePort().");
  return new Promise(function (resolve, reject) {
    const probe = net.createServer();
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', function () {
      const port = probe.address().port;
      probe.close(function () {
        resolve(port);
      });
    });
  });
}

// A self-signed client certificate of each kind the plan names.
function certificates(dir) {
  log.debug("Entering certificates().");
  const kinds = {
    rsa: ['-newkey', 'rsa:2048'],
    ec: ['-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256'],
    ed25519: ['-newkey', 'ed25519'],
    rsapss: ['-newkey', 'rsa-pss', '-pkeyopt', 'rsa_keygen_bits:2048'],
    mldsa: ['-newkey', 'ml-dsa-65'],
    // A curve outside the NIST set, for the guard's refusal (#212).
    nonNist: ['-newkey', 'ec', '-pkeyopt',
              'ec_paramgen_curve:brainpoolP256r1']
  };
  const made = {};
  Object.keys(kinds).forEach(function (kind) {
    const pair = { key: path.join(dir, kind + '.key'),
                   cert: path.join(dir, kind + '.crt') };
    const r = childProcess.spawnSync('openssl', ['req', '-x509', '-nodes',
      '-days', '1', '-subj', '/CN=tlsfuzzer-debugger-' + kind,
      '-keyout', pair.key, '-out', pair.cert].concat(kinds[kind]),
      { encoding: 'utf8', timeout: 120000 });
    if (r.status !== 0) {
      throw new Error('openssl could not make the ' + kind + ' client ' +
                      'certificate: ' + (r.stderr || r.error || ''));
    }
    made[kind] = pair;
  });
  // tlslite reads a non-NIST EC key only in the traditional SEC 1 form: its
  // PKCS #8 parser knows the NIST curves alone ("Unknown curve").
  const sec1 = childProcess.spawnSync('openssl', ['ec', '-in',
    made.nonNist.key, '-out', made.nonNist.key],
  { encoding: 'utf8', timeout: 60000 });
  if (sec1.status !== 0) {
    throw new Error('openssl could not rewrite the non-NIST key: ' +
                    (sec1.stderr || sec1.error || ''));
  }
  log.debug("Leaving certificates().");
  return made;
}

async function run(t) {
  log.debug("Entering run().");
  const dir = process.env.STS_TLSFUZZER_DIR || '';
  if (!dir || !fs.existsSync(path.join(dir, 'tlsfuzzer', 'COMMIT'))) {
    t.bad('tlsfuzzer is where STS_TLSFUZZER_DIR says',
          'STS_TLSFUZZER_DIR is ' + (dir ? 'not a tlsfuzzer tree: ' + dir
                                         : 'not set') +
          '. It is fetched into the tests image when it is built ' +
          '(tests/tlsfuzzer/build-tlsfuzzer.sh); run this file there, with ' +
          './docker-npm-test.sh.');
    log.debug("Leaving run(). No tlsfuzzer.");
    return;
  }
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-tlsf-dbg-'));
  const uiDir = path.join(scratch, 'ui');
  fs.mkdirSync(uiDir);
  fs.writeFileSync(path.join(uiDir, 'index.html'),
                   '<html><body>tlsfuzzer</body></html>');
  const port = await freePort();
  process.env.STS_HTTPS = 'true';
  process.env.STS_DEBUGGER_ENABLED = 'on';
  process.env.STS_DEBUGGER_PORT = String(port);
  process.env.STS_DEBUGGER_UI_DIRECTORY = uiDir;

  const apiProcess = require('../debugger/debugger_api_process');
  const debuggerServer = require('../debugger/debugger_server');
  const fuzzer = require('./vendored/tlsfuzzer_kit');
  // The api child is not what is under test: it is reached only through the
  // handshake, and a real one needs the debugger project's built tree.
  const stubbed = { start: apiProcess.start,
                    installedProblem: apiProcess.installedProblem };
  apiProcess.start = function () {
    return Promise.resolve();
  };
  apiProcess.installedProblem = function () {
    return '';
  };
  let bound = null;
  try {
    const started = debuggerServer.listen();
    const ready = await started.whenReady;
    bound = ready && ready.port;
    t.check(!!bound, 'the debugger listener is bound over TLS for the run',
            JSON.stringify(ready));
    if (!bound) {
      log.debug("Leaving run(). Not bound.");
      return;
    }
    t.log.info('tlsfuzzer ' + fs.readFileSync(path.join(dir, 'tlsfuzzer',
      'COMMIT'), 'utf8').trim() + ' against the debugger listener on ' +
      bound);
    fuzzer.notApplicable('debugger').forEach(function (entry) {
      t.log.info('  [not applicable] ' + entry.script + ': ' + entry.reason);
    });
    const results = await fuzzer.runPlan(
      { host: '127.0.0.1', port: bound,
        certificates: certificates(scratch) }, 'debugger',
      { concurrency: Number(process.env.STS_TLSFUZZER_CONCURRENCY || 6),
        onResult: function (r) {
          t.log.info('  ' + fuzzer.line(r));
        } });
    t.check(results.length > 0, 'the plan ran on the debugger listener');
    results.forEach(function (r) {
      t.check(r.ok, 'tlsfuzzer ' + r.script + ' on the debugger listener',
              r.ok ? '' : fuzzer.line(r) + '\n    reproduce: ' + r.command +
                          '\n' + r.output.split('\n').slice(-40).join('\n'));
    });
  } finally {
    await debuggerServer.close().catch(function (e) {
      log.debug("Caught in run(): " + ((e && e.message) || e));
      // A listener that will not close is not this file's finding.
    });
    apiProcess.start = stubbed.start;
    apiProcess.installedProblem = stubbed.installedProblem;
    delete process.env.STS_HTTPS;
    delete process.env.STS_DEBUGGER_ENABLED;
    delete process.env.STS_DEBUGGER_PORT;
    delete process.env.STS_DEBUGGER_UI_DIRECTORY;
    fs.rmSync(scratch, { recursive: true, force: true });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'tlsfuzzer_debugger',
  describe: 'tlsfuzzer (#212) against the embedded debugger\'s TLS listener, ' +
            'bound in process: every applicable script of the plan the ' +
            'stack job runs against the main port and LDAPS',
  run: run
};
