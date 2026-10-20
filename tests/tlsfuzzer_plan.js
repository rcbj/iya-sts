// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tlsfuzzer_plan.js
//
// ===========================================================================
// THE TLSFUZZER PLAN FOLLOWS THE LISTENER'S CERTIFICATE (#321).
//
// sts_tlsfuzzer.js reads the key a listener presents and hands it to
// tests/vendored/tlsfuzzer_kit.js. This file holds that choice. A tlsfuzzer
// run needs the tests image and a service, and the choice can be asserted
// without either: which scripts run for RSA and for ECDSA, that an omitted
// key is RSA, that a curve exception excuses only the curves it names, that
// a real handshake names the key and the curve, that any other key is
// declined, and that the adapter retargets TLS 1.2 to the matching ECDHE
// suite. The map is tests/tlsfuzzer/sts_adapter_map.py, which this file
// runs; the assertions stay here. It does not run tlsfuzzer.
// ===========================================================================

const childProcess = require('child_process');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const tls = require('tls');

const log = require('bunyan').createLogger({ name: 'tlsfuzzer_plan',
  level: process.env.LOG_LEVEL || 'info' });
const kit = require('./vendored/tlsfuzzer_kit');

const EC_SERVER = 'needs an ECDSA server certificate; this listener ' +
  'presents RSA';
const RSA_SERVER = 'needs an RSA server certificate; this listener ' +
  'presents ECDSA';

function skipped(listener, serverKey) {
  log.debug('Entering skipped().');
  log.debug('Leaving skipped().');
  return kit.notApplicable(listener, serverKey).map(function (entry) {
    return entry.script;
  });
}

function why(listener, serverKey, script) {
  log.debug('Entering why().');
  const hit = kit.notApplicable(listener, serverKey).find(function (entry) {
    return entry.script === script;
  });
  log.debug('Leaving why().');
  return hit ? hit.reason : '';
}

function entryNamed(script) {
  log.debug('Entering entryNamed().');
  log.debug('Leaving entryNamed().');
  return kit.PLAN.find(function (entry) {
    return entry.script === script;
  });
}

// The TLS 1.3 scheme probes a curve exception would excuse on this curve.
function curveProbes(curve) {
  log.debug('Entering curveProbes().');
  const probes = kit.exceptionsFor(entryNamed('test-tls13-ecdsa-support.py'),
                                   'main', curve).filter(function (one) {
    return one.alert === 'handshake_failure' &&
      typeof one.probe === 'string' &&
      one.probe.indexOf('Test with ecdsa_secp') === 0;
  }).map(function (one) {
    return one.probe;
  });
  log.debug('Leaving curveProbes().');
  return probes;
}

function hasBrainpool(curve) {
  log.debug('Entering hasBrainpool().');
  const found = kit.exceptionsFor(entryNamed('test-tls13-ecdsa-support.py'),
                                  'main', curve).some(function (one) {
    return one.probe instanceof RegExp &&
      one.probe.source === 'brainpool' &&
      one.alert === 'handshake_failure';
  });
  log.debug('Leaving hasBrainpool(). ' + found);
  return found;
}

// The first plan entry that does not follow its serverKey, or "".
function planGap() {
  log.debug('Entering planGap().');
  const gap = kit.PLAN.find(function (entry) {
    const listener = (entry.on && entry.on[0]) || 'main';
    const onRsa = kit.appliesTo(entry, listener, 'rsa');
    const onEc = kit.appliesTo(entry, listener, 'ec');
    if (entry.serverKey === 'rsa') {
      return !(onRsa && !onEc &&
        why(listener, 'ec', entry.script) === RSA_SERVER);
    }
    if (entry.serverKey === 'ec') {
      return !(!onRsa && onEc &&
        why(listener, 'rsa', entry.script) === EC_SERVER);
    }
    if (entry.skip) {
      return onRsa || onEc;
    }
    return onRsa !== onEc;
  });
  log.debug('Leaving planGap(). ' + (gap ? gap.script : 'none'));
  return gap ? gap.script : '';
}

function selfSigned(dir, name, args) {
  log.debug('Entering selfSigned(). ' + name);
  const key = path.join(dir, name + '.key');
  const cert = path.join(dir, name + '.crt');
  const made = childProcess.spawnSync('openssl', ['req', '-x509', '-newkey']
    .concat(args).concat(['-keyout', key, '-out', cert, '-days', '1',
                          '-nodes', '-subj', '/CN=' + name]),
    { encoding: 'utf8' });
  if (made.status !== 0) {
    log.debug('Leaving selfSigned(). openssl ' + made.status);
    throw new Error('openssl ' + name + ': ' +
                    (made.stderr || (made.error && made.error.message) ||
                     made.status));
  }
  log.debug('Leaving selfSigned().');
  return { key: fs.readFileSync(key), cert: fs.readFileSync(cert) };
}

function unusedPort() {
  log.debug('Entering unusedPort().');
  return new Promise(function (resolve, reject) {
    const probe = net.createServer();
    probe.once('error', function (e) {
      log.debug('Caught in unusedPort(): ' + ((e && e.message) || e));
      log.debug('Leaving unusedPort().');
      reject(e);
    });
    probe.listen(0, '127.0.0.1', function () {
      const port = probe.address().port;
      probe.close(function () {
        log.debug('Leaving unusedPort(). ' + port);
        resolve(port);
      });
    });
  });
}

function serve(pair) {
  log.debug('Entering serve().');
  return new Promise(function (resolve, reject) {
    const server = tls.createServer({ key: pair.key, cert: pair.cert },
      function (socket) {
        socket.end();
      });
    server.once('error', function (e) {
      log.debug('Caught in serve(): ' + ((e && e.message) || e));
      log.debug('Leaving serve().');
      reject(e);
    });
    server.listen(0, '127.0.0.1', function () {
      log.debug('Leaving serve(). ' + server.address().port);
      resolve({
        port: server.address().port,
        close: function () {
          log.debug('Entering close().');
          return new Promise(function (done) {
            server.close(function () {
              log.debug('Leaving close().');
              done();
            });
          });
        }
      });
    });
  });
}

async function presented(t, dir) {
  log.debug('Entering presented().');
  const servers = [];
  try {
    const rsa = await serve(selfSigned(dir, 'rsa', ['rsa:2048']));
    servers.push(rsa);
    const p256 = await serve(selfSigned(dir, 'p256',
      ['ec', '-pkeyopt', 'ec_paramgen_curve:P-256']));
    servers.push(p256);
    const p384 = await serve(selfSigned(dir, 'p384',
      ['ec', '-pkeyopt', 'ec_paramgen_curve:P-384']));
    servers.push(p384);
    const ed = await serve(selfSigned(dir, 'ed25519', ['ed25519']));
    servers.push(ed);
    const rsaCert = await kit.presentedCertificate('127.0.0.1', rsa.port);
    const p256Cert = await kit.presentedCertificate('127.0.0.1', p256.port);
    const p384Cert = await kit.presentedCertificate('127.0.0.1', p384.port);
    const edCert = await kit.presentedCertificate('127.0.0.1', ed.port);
    const closedPort = await unusedPort();
    const closed = await kit.presentedCertificate('127.0.0.1', closedPort);
    t.equal(rsaCert.type, 'rsa', 'an RSA listener is read as RSA');
    t.equal(rsaCert.curve, '', 'an RSA listener has no curve');
    t.equal(p256Cert.type, 'ec', 'a P-256 listener is read as ECDSA');
    t.equal(p256Cert.curve, 'P-256', 'a P-256 listener names P-256');
    t.equal(p384Cert.type, 'ec', 'a P-384 listener is read as ECDSA');
    t.equal(p384Cert.curve, 'P-384', 'a P-384 listener names P-384');
    t.equal(edCert.type, 'ed25519',
            'an Ed25519 listener is read as Ed25519');
    t.equal(closed.type, '', 'a closed port names no key');
    t.equal(closed.curve, '', 'a closed port names no curve');
    t.equal(kit.declineReason({ main: edCert, ldaps: rsaCert }),
            'the main listener presents a ed25519 certificate, and the ' +
            'plan has a variant for RSA and for ECDSA only',
            'an Ed25519 listener declines the job');
    t.equal(kit.declineReason({ main: rsaCert, ldaps: p256Cert }), '',
            'RSA beside ECDSA is not declined');
    t.equal(kit.declineReason({ main: closed, ldaps: closed }), '',
            'two unread handshakes are not declined');
    const borrowed = kit.planFor(closed, p256Cert);
    t.equal(borrowed.type, 'ec',
            'a listener that named nothing takes the other\'s ECDSA key');
    t.equal(borrowed.curve, 'P-256',
            'the borrowed key keeps the curve that was read');
    const unread = kit.planFor(closed, { type: '', curve: '' });
    t.equal(unread.type, 'rsa',
            'two unread handshakes keep the RSA plan');
    t.equal(unread.curve, '', 'two unread handshakes keep no curve');
    const foreign = kit.planFor(closed, edCert);
    t.equal(foreign.type, 'rsa',
            'an unread handshake does not borrow a key the plan declines');
  } finally {
    await Promise.all(servers.map(function (one) {
      return one.close();
    }));
  }
  log.debug('Leaving presented().');
}

// The suite map is a program of its own, as the other jobs run Python
// they own. It prints the map; the assertions stay in this file. The
// adapter's checked-in bytecode is the #212 cache, so loading the source
// must not rewrite it.
function adapterSuites(t) {
  log.debug('Entering adapterSuites().');
  const dir = path.join(__dirname, 'tlsfuzzer');
  const env = Object.assign({}, process.env,
    { PYTHONDONTWRITEBYTECODE: '1' });
  const ran = childProcess.spawnSync('python3',
    [path.join(dir, 'sts_adapter_map.py')],
    { encoding: 'utf8', env: env });
  if (ran.status !== 0) {
    log.debug('Leaving adapterSuites(). python ' + ran.status);
    throw new Error('adapter map: ' + (ran.stderr || ran.stdout ||
                                        ran.status));
  }
  const got = JSON.parse(ran.stdout);
  t.equal(got.ec_rsa_gcm, 'ECDHE_ECDSA_128',
          'an ECDSA listener retargets an ECDHE-RSA GCM suite');
  t.equal(got.ec_rsa_cbc, 'ECDHE_ECDSA_256',
          'an ECDSA listener retargets an RSA CBC suite to AES-256-GCM');
  t.equal(got.rsa_ecdsa_gcm, 'ECDHE_RSA_128',
          'an RSA listener retargets an ECDHE-ECDSA GCM suite');
  t.equal(got.rsa_rsa_gcm, 'ECDHE_RSA_128',
          'an RSA listener retargets an RSA GCM suite to ECDHE-RSA');
  t.equal(got.schemes.join(','),
          'ecdsa_secp256r1_sha256,ecdsa_secp384r1_sha384,' +
          'ecdsa_secp521r1_sha512',
          'an ECDSA listener is offered the three NIST schemes');
  const refused = childProcess.spawnSync('python3',
    [path.join(dir, 'sts_adapter.py'), '--server-key', 'ed25519'],
    { encoding: 'utf8', env: env });
  t.equal(refused.status, 2, 'a key other than rsa or ec is refused');
  t.check((refused.stderr || '').indexOf('needs rsa or ec') >= 0,
          'the refusal names the keys the adapter accepts',
          refused.stderr);
  log.debug('Leaving adapterSuites().');
}

async function run(t) {
  log.debug('Entering run().');
  const rsa = skipped(null, 'rsa');
  const ec = skipped(null, 'ec');
  const omitted = skipped();
  t.check(rsa.length === omitted.length && rsa.every(function (script, i) {
    return script === omitted[i];
  }), 'an omitted server key is the RSA plan',
          'rsa ' + rsa.length + ', omitted ' + omitted.length);

  ['test-ecdsa-sig-flexibility.py', 'test-tls13-ecdsa-support.py']
    .forEach(function (script) {
      t.check(rsa.indexOf(script) >= 0,
              script + ' is not applicable to an RSA listener');
      t.equal(why(null, 'rsa', script), EC_SERVER,
              script + ' says why it does not run against RSA');
      t.check(ec.indexOf(script) < 0,
              script + ' runs against an ECDSA listener');
    });

  ['test-sig-algs.py', 'test-tls13-rsa-signatures.py',
   'test-clienthello-md5.py'].forEach(function (script) {
    t.check(rsa.indexOf(script) < 0,
            script + ' runs against an RSA listener');
    t.check(ec.indexOf(script) >= 0,
            script + ' is not applicable to an ECDSA listener');
    t.equal(why(null, 'ec', script), RSA_SERVER,
            script + ' says why it does not run against ECDSA');
  });

  const rsaMain = skipped('main', 'rsa');
  const ecMain = skipped('main', 'ec');
  t.check(rsaMain.indexOf('test-certificate-verify.py') < 0,
          'the RSA CertificateVerify script runs on an RSA main port');
  t.check(ecMain.indexOf('test-certificate-verify.py') >= 0,
          'the RSA CertificateVerify script does not run on an ECDSA ' +
          'main port');
  t.equal(why('main', 'ec', 'test-certificate-verify.py'), RSA_SERVER,
          'the RSA CertificateVerify script is skipped for the server key');

  ['test-aes-gcm-nonces.py', 'test-ecdhe-rsa-key-exchange.py',
   'test-invalid-client-hello-w-record-overflow.py'].forEach(
    function (script) {
      t.check(rsa.indexOf(script) < 0 && ec.indexOf(script) < 0,
              script + ' runs for both server keys');
    });

  ['test-tls13-minerva.py', 'test-dsa-sig-flexibility.py',
   'test-tls13-eddsa.py', 'test-tls13-rsapss-signatures.py'].forEach(
    function (script) {
      t.check(rsa.indexOf(script) >= 0 && ec.indexOf(script) >= 0,
              script + ' is not applicable whichever key is presented');
    });

  const p256 = curveProbes('P-256');
  t.check(p256.indexOf('Test with ecdsa_secp256r1_sha256') < 0,
          'a P-256 certificate is not excused the P-256 scheme',
          p256.join(', '));
  t.check(p256.indexOf('Test with ecdsa_secp384r1_sha384') >= 0 &&
          p256.indexOf('Test with ecdsa_secp521r1_sha512') >= 0,
          'a P-256 certificate is excused the P-384 and P-521 schemes',
          p256.join(', '));
  const p384 = curveProbes('P-384');
  t.check(p384.indexOf('Test with ecdsa_secp256r1_sha256') >= 0 &&
          p384.indexOf('Test with ecdsa_secp384r1_sha384') < 0,
          'a P-384 certificate is excused the P-256 scheme and not its own',
          p384.join(', '));
  t.check(curveProbes('').length === 0 && curveProbes('P-999').length === 0,
          'an empty curve, and an unknown curve, excuse no scheme');
  t.check(hasBrainpool('P-256') && hasBrainpool(''),
          'a brainpool scheme is refused on every curve, including none');

  const flex = kit.exceptionsFor(
    entryNamed('test-ecdsa-sig-flexibility.py'), 'main', 'P-256');
  t.check(flex.some(function (one) {
    return one.probe === 'connect with sha1+ecdsa only' &&
      one.alert === 'handshake_failure';
  }) && flex.some(function (one) {
    return one.probe === 'connect with sha224+ecdsa only';
  }), 'ECDSA flexibility expects SHA-1 and SHA-224 to be refused');

  const target = { host: '127.0.0.1', port: 443, certificates: {} };
  const ecArgv = kit.argsFor(entryNamed('test-tls13-ecdsa-support.py'),
                              'main', Object.assign({ serverKey: 'ec' },
                                                    target));
  const at = ecArgv.indexOf('--server-key');
  t.equal(at < 0 ? '' : ecArgv[at + 1], 'ec',
          'an ECDSA listener is passed --server-key ec');
  t.check(ecArgv.indexOf('--tls12-aead') > at,
          'the AEAD swap stays on the ECDSA command line');
  const rsaArgv = kit.argsFor(entryNamed('test-sig-algs.py'), 'main',
                               Object.assign({ serverKey: 'rsa' }, target));
  t.check(rsaArgv.indexOf('--server-key') < 0,
          'an RSA listener command line does not carry --server-key');
  t.check(kit.argsFor(entryNamed('test-sig-algs.py'), 'main', target)
            .indexOf('--server-key') < 0,
          'an omitted server key keeps the RSA command line');

  const rsaMarked = kit.PLAN.filter(function (entry) {
    return entry.serverKey === 'rsa';
  }).length;
  const ecMarked = kit.PLAN.filter(function (entry) {
    return entry.serverKey === 'ec';
  }).length;
  t.equal(rsaMarked, 54, 'fifty-four scripts need an RSA server certificate');
  t.equal(ecMarked, 2, 'two scripts need an ECDSA server certificate');
  t.equal(planGap(), '', 'every plan entry follows its server key');
  t.equal(kit.curveName('prime256v1'), 'P-256',
          'prime256v1 is the plan\'s P-256');
  t.equal(kit.curveName('secp521r1'), 'P-521',
          'secp521r1 is the plan\'s P-521');
  t.equal(kit.curveName('secp256k1'), 'secp256k1',
          'a curve outside the three NIST names is kept');
  t.equal(kit.curveName(''), '', 'no curve stays empty');

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tlsfuzzer-plan-'));
  try {
    await presented(t, dir);
    adapterSuites(t);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  log.debug('Leaving run().');
}

module.exports = {
  name: 'tlsfuzzer_plan',
  describe: 'The tlsfuzzer plan follows the certificate the listener ' +
            'presents (#321): the key read from a handshake, RSA by ' +
            'default, the ECDSA-server scripts when the certificate is ' +
            'ECDSA, a curve exception only for the curves it names, and ' +
            'the adapter suite that matches the key',
  run: run
};
