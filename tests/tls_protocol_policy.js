'use strict';
//
// File: tls_protocol_policy.js
//
// ===========================================================================
// WHAT tlsfuzzer FOUND IN THE TLS POLICY, HELD IN PROCESS (#212, 2026-09-26).
//
// tests/vendored/sts_tlsfuzzer.js runs tlsfuzzer against the listeners of a
// running stack and would see each of these again; this file holds them
// where a failure names the function that regressed:
//
//   A. `protocolOptions()` — what the main port, LDAPS and the debugger's
//      listener are built from — carries the post-quantum-first group list
//      with no finite-field group, the signature list with no DSA, no SHA-224
//      and brainpool omitted by policy, and SSL_OP_NO_RENEGOTIATION; and
//      `secureContextOptions()`, which every truststore change re-applies,
//      carries all of it (a listener must not lose the policy at its first
//      re-application);
//   B. a REAL handshake against a server built from it: a client offering
//      only SecP384r1MLKEM1024 is served, one offering only ffdhe2048 is
//      refused, and a TLS 1.2 renegotiation is refused;
//   C. THE NIST-CURVE GUARD: certificates whose EC key is on a curve other
//      than P-256/P-384/P-521 are refused before any certificate object is
//      built (a third-party runtime defect found by #212; details are held
//      privately by the maintainer). A child runs a server whose handshake
//      lets any curve through, with `refuseNonNistCurveCertificatesOn()`
//      installed: such a client certificate is closed — as the leaf and as
//      the issuer — and the server keeps serving, while a P-256 one, and a
//      P-256 chain, are read whole;
//   D. the SPIFFE listeners' own signature list omits brainpool by policy.
//
// In process because each is a function or a loopback socket; the guarded
// server is a CHILD process, so a regression stops a child and not the
// suite.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const tls = require('tls');

const log = require('bunyan').createLogger({ name: 'tls_protocol_policy',
  level: process.env.LOG_LEVEL || 'info' });

// The curve the guard's refusal is exercised with: any EC curve outside the
// NIST set the guard accepts would do.
const NON_NIST_CURVE = 'brainpoolP256r1';

// A self-signed certificate with `openssl req`, key and certificate PEMs.
function selfSigned(dir, name, keyArgs) {
  log.debug("Entering selfSigned(). " + name);
  const key = path.join(dir, name + '.key');
  const cert = path.join(dir, name + '.crt');
  const r = childProcess.spawnSync('openssl', ['req', '-x509', '-nodes',
    '-days', '1', '-subj', '/CN=' + name, '-keyout', key, '-out', cert,
    '-addext', 'basicConstraints=critical,CA:true']
    .concat(keyArgs), { encoding: 'utf8', timeout: 60000 });
  if (r.status !== 0) {
    throw new Error('openssl req for ' + name + ': ' + (r.stderr || r.error));
  }
  log.debug("Leaving selfSigned().");
  return { key: fs.readFileSync(key, 'utf8'), cert: fs.readFileSync(cert,
    'utf8'), keyFile: key, certFile: cert };
}

// A certificate issued by `ca` (a selfSigned() result) with `openssl x509
// -req`; the certificate PEM is followed by the CA's, as a client sends it.
function issuedBy(dir, name, keyArgs, ca) {
  log.debug("Entering issuedBy(). " + name);
  const key = path.join(dir, name + '.key');
  const csr = path.join(dir, name + '.csr');
  const cert = path.join(dir, name + '.crt');
  const steps = [
    ['req', '-new', '-nodes', '-subj', '/CN=' + name, '-keyout', key,
     '-out', csr].concat(keyArgs),
    ['x509', '-req', '-in', csr, '-CA', ca.certFile, '-CAkey', ca.keyFile,
     '-set_serial', '0x' + crypto.randomBytes(8).toString('hex'),
     '-days', '1', '-out', cert]
  ];
  steps.forEach(function (args) {
    const r = childProcess.spawnSync('openssl', args,
                                     { encoding: 'utf8', timeout: 60000 });
    if (r.status !== 0) {
      throw new Error('openssl ' + args[0] + ' for ' + name + ': ' +
                      (r.stderr || r.error));
    }
  });
  log.debug("Leaving issuedBy().");
  return { key: fs.readFileSync(key, 'utf8'),
           cert: fs.readFileSync(cert, 'utf8') + ca.cert };
}

// A handshake from a node client with the options given; resolves with
// what happened rather than rejecting.
function handshake(port, options) {
  log.debug("Entering handshake().");
  log.debug("Leaving handshake().");
  return new Promise(function (resolve) {
    const socket = tls.connect(Object.assign({ host: '127.0.0.1', port: port,
      rejectUnauthorized: false }, options), function () {
      resolve({ ok: true, protocol: socket.getProtocol(), socket: socket });
    });
    socket.on('error', function (e) {
      log.debug("Caught in handshake(): " + ((e && e.message) || e));
      resolve({ ok: false, error: e.message });
    });
  });
}

async function run(t) {
  log.debug("Entering run().");
  const tlsServer = require('../tls/tls_server');
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-tls-policy-'));
  try {
    t.log.info('=== A. the policy every TLS listener is built from ===');
    const opts = tlsServer.protocolOptions();
    t.check(/^X25519MLKEM768:SecP256r1MLKEM768:SecP384r1MLKEM1024 \//
              .test(String(opts.ecdhCurve || '')) &&
            !/ffdhe/i.test(String(opts.ecdhCurve)),
            'the groups are the three post-quantum hybrids first, and no ' +
            'finite-field group', String(opts.ecdhCurve));
    t.check(!!opts.sigalgs && !/dsa_sha|sha224|brainpool/i.test(
              opts.sigalgs.replace(/mldsa\d+/g, '')),
            'the signature list has no DSA and no SHA-224 scheme, and ' +
            'omits brainpool by policy', String(opts.sigalgs));
    t.check((opts.secureOptions & crypto.constants.SSL_OP_NO_RENEGOTIATION)
              !== 0, 'renegotiation is refused (SSL_OP_NO_RENEGOTIATION)');
    const context = tlsServer.clientTruststoreOptions();
    t.check(context.ecdhCurve === opts.ecdhCurve &&
            context.sigalgs === opts.sigalgs &&
            context.secureOptions === opts.secureOptions &&
            context.ciphers === opts.ciphers &&
            context.minVersion === opts.minVersion,
            'and the secure context re-applied on every truststore change ' +
            'carries all of it');

    t.log.info('=== B. real handshakes against that policy ===');
    const rsa = selfSigned(scratch, 'server', ['-newkey', 'rsa:2048']);
    const server = tls.createServer(Object.assign({ key: rsa.key,
      cert: rsa.cert }, opts), function (socket) {
      socket.on('error', function (e) {
        log.debug("Caught on a policy test socket: " +
                  ((e && e.message) || e));
      });
      socket.end('ok\n');
    });
    await new Promise(function (resolve) {
      server.listen(0, '127.0.0.1', resolve);
    });
    const port = server.address().port;
    const hybrid = await handshake(port, { ecdhCurve: 'SecP384r1MLKEM1024',
                                           minVersion: 'TLSv1.3' });
    t.check(hybrid.ok, 'a client offering only SecP384r1MLKEM1024 is ' +
            'served (node\'s own default offered only X25519MLKEM768)',
            hybrid.error || '');
    if (hybrid.socket) {
      hybrid.socket.destroy();
    }
    const ffdhe = await handshake(port, { ecdhCurve: 'ffdhe2048',
                                          minVersion: 'TLSv1.3' });
    t.check(!ffdhe.ok, 'a client offering only ffdhe2048 is refused',
            ffdhe.ok ? 'it was served' : '');
    const twelve = await handshake(port, { maxVersion: 'TLSv1.2' });
    t.check(twelve.ok, 'a TLS 1.2 handshake completes', twelve.error || '');
    if (twelve.ok) {
      // Refused: an error, or no second handshake within five seconds (the
      // server's no_renegotiation is a WARNING, and node's client may sit
      // on it). Renegotiated: the callback without an error.
      const renegotiated = await new Promise(function (resolve) {
        const timer = setTimeout(function () {
          resolve('no second handshake within five seconds');
        }, 5000);
        const done = twelve.socket.renegotiate({}, function (e) {
          clearTimeout(timer);
          resolve(e ? e.message : '');
        });
        if (done === false) {
          clearTimeout(timer);
          resolve('renegotiate() refused locally');
        }
        twelve.socket.on('error', function (e) {
          clearTimeout(timer);
          resolve(e.message);
        });
      });
      t.check(!!renegotiated, 'and its renegotiation is refused',
              renegotiated || 'it renegotiated');
      twelve.socket.destroy();
    }
    await new Promise(function (resolve) {
      server.close(resolve);
    });

    t.log.info('=== C. a client certificate on a non-NIST curve ===');
    const nonNist = selfSigned(scratch, 'non-nist', ['-newkey', 'ec',
      '-pkeyopt', 'ec_paramgen_curve:' + NON_NIST_CURVE]);
    const p256 = selfSigned(scratch, 'p256', ['-newkey', 'ec', '-pkeyopt',
      'ec_paramgen_curve:P-256']);
    // The server in a child: the handshake lets any curve through (OpenSSL's
    // default signature list), and the only thing between the certificate
    // and getPeerCertificate() is the guard.
    const program = "const tls=require('tls'),fs=require('fs');" +
      "const g=require('./tls/tls_server');" +
      "const s=tls.createServer({key:fs.readFileSync(process.argv[1])," +
      "cert:fs.readFileSync(process.argv[2]),requestCert:true," +
      "rejectUnauthorized:false},function(c){" +
      "const p=c.getPeerCertificate(true);" +
      "console.log('READ '+(p&&p.subject?p.subject.CN:'none')+' '+" +
      "(p&&p.issuerCertificate&&p.issuerCertificate.subject?" +
      "p.issuerCertificate.subject.CN:'no-issuer'));" +
      "c.on('error',function(){});c.end('ok\\n');});" +
      "g.refuseNonNistCurveCertificatesOn(s,'the policy test');" +
      "s.listen(0,'127.0.0.1',function(){console.log('PORT '+" +
      "s.address().port)});";
    const serverChild = childProcess.spawn(process.execPath, ['-e', program,
      rsa.keyFile, rsa.certFile], { cwd: path.join(__dirname, '..'),
      env: Object.assign({}, process.env, { LOG_LEVEL: 'fatal' }),
      stdio: ['ignore', 'pipe', 'pipe'] });
    let childOut = '';
    let childExit = null;
    serverChild.stdout.on('data', function (d) {
      childOut += d;
    });
    serverChild.stderr.on('data', function (d) {
      childOut += d;
    });
    serverChild.on('close', function (code, signal) {
      childExit = { code: code, signal: signal };
    });
    const guardedPort = await new Promise(function (resolve) {
      const started = Date.now();
      (function wait() {
        log.debug("Entering wait().");
        log.debug("Leaving wait().");
        const m = /PORT (\d+)/.exec(childOut);
        if (m || childExit || Date.now() - started > 60000) {
          resolve(m ? Number(m[1]) : 0);
          return;
        }
        setTimeout(wait, 100);
      })();
    });
    t.check(guardedPort > 0, 'the guarded server started in a child',
            childOut.slice(-400));
    if (guardedPort) {
      const refused = await handshake(guardedPort, {
        key: nonNist.key, cert: nonNist.cert, minVersion: 'TLSv1.3' });
      if (refused.socket) {
        await new Promise(function (resolve) {
          refused.socket.on('close', resolve);
          refused.socket.on('data', function () {});
          setTimeout(resolve, 3000);
        });
      }
      await new Promise(function (resolve) {
        setTimeout(resolve, 500);
      });
      t.check(childExit === null, 'a client certificate on a non-NIST ' +
              'curve is closed and the server keeps serving',
              JSON.stringify(childExit) + ' ' + childOut.slice(-400));
      t.check(childOut.indexOf('READ tlsfuzzer') < 0 &&
              childOut.indexOf('READ non-nist') < 0,
              'and nothing read it', childOut.slice(-400));
      const settle = async function (attempt) {
        log.debug("Entering settle().");
        log.debug("Leaving settle().");
        if (attempt.socket) {
          await new Promise(function (resolve) {
            attempt.socket.on('data', function () {});
            attempt.socket.on('close', resolve);
            setTimeout(resolve, 3000);
          });
        }
      };
      // A P-256 leaf whose ISSUER is on a non-NIST curve: the rule covers
      // the whole chain, and no signature list can refuse it in the
      // handshake.
      const otherCa = selfSigned(scratch, 'non-nist-ca', ['-newkey', 'ec',
        '-pkeyopt', 'ec_paramgen_curve:' + NON_NIST_CURVE]);
      const underOther = issuedBy(scratch, 'under-non-nist', ['-newkey',
        'ec', '-pkeyopt', 'ec_paramgen_curve:P-256'], otherCa);
      await settle(await handshake(guardedPort, {
        key: underOther.key, cert: underOther.cert,
        minVersion: 'TLSv1.3' }));
      t.check(childExit === null &&
              childOut.indexOf('READ under-non-nist') < 0,
              'a P-256 leaf presented with a non-NIST issuer is closed ' +
              'too, and the server keeps serving',
              JSON.stringify(childExit) + ' ' + childOut.slice(-400));
      await settle(await handshake(guardedPort, {
        key: p256.key, cert: p256.cert, minVersion: 'TLSv1.3' }));
      t.check(/READ p256/.test(childOut), 'a P-256 client certificate is ' +
              'read as before', childOut.slice(-400));
      // AND THE CHAIN SURVIVES THE GUARD: the guard serves every reader
      // from its one reading of the chain — here, a leaf and the P-256 CA
      // it came with.
      const pCa = selfSigned(scratch, 'p256-ca', ['-newkey', 'ec', '-pkeyopt',
        'ec_paramgen_curve:P-256']);
      const underP = issuedBy(scratch, 'under-p256', ['-newkey', 'ec',
        '-pkeyopt', 'ec_paramgen_curve:P-256'], pCa);
      await settle(await handshake(guardedPort, {
        key: underP.key, cert: underP.cert, minVersion: 'TLSv1.3' }));
      t.check(/READ under-p256 p256-ca/.test(childOut), 'and a chain is ' +
              'still read whole: getPeerCertificate(true) links the leaf ' +
              'to the issuer it was sent with', childOut.slice(-400));
    }
    serverChild.kill('SIGKILL');

    t.log.info('=== D. the SPIFFE listeners\' signature list ===');
    const spiffeGrpc = require('../spiffe/spiffe_grpc');
    const policy = (spiffeGrpc.SpiffeGrpc || {}).POLICY_SIGALGS || '';
    t.check(!!policy && !/brainpool/i.test(policy),
            'the SPIFFE TLS listeners omit brainpool by policy', policy);
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'tls_protocol_policy',
  describe: 'What tlsfuzzer found in the TLS policy (#212): post-quantum ' +
            'groups first and no finite-field group, no DSA/SHA-224 ' +
            'signatures, no renegotiation, and a client certificate on a ' +
            'curve other than P-256/P-384/P-521 closed by the guard',
  run: run
};
