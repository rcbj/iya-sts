// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tls_ocsp_stapling.js
//
// ===========================================================================
// OCSP STAPLING ON THIS SERVICE'S OWN LISTENERS (#2254, ASVS 5.0.0 12.1.4).
//
//   A. The main port, as `server.js` builds it: a client sending
//      `status_request` gets a staple, in TLS 1.3 and in TLS 1.2, that
//      OpenSSL verifies against the CA chain and that says `good`; it
//      carries a SingleResponse for every leaf the port presents.
//   B. The debugger listener's context: the same staple.
//   C. A custom listener with a `realm-tls` leaf: a staple from the realm's
//      own CA.
//   D. LDAPS 636, as `ldap/ldap_server.js` starts it (in a child).
//   E. A revoked listener certificate staples `revoked` after a refresh, and
//      `good` again once the hold is released.
//   F. `tls.ocspStapling` off: no staple, and the handshake succeeds;
//      `auto` is the mode's answer.
//   G. The per-process job: registered, its interval a fraction of the
//      responses' lifetime, and a refresh re-makes the staple before its
//      nextUpdate; off in a request worker.
//   H. A staple that cannot be made — a responder that throws, one that
//      never answers — never fails the handshake.
//   I. A certificate from an outside authority is not stapled.
//   J. Every listener kind's construction site installs it.
//
// The staple is verified by `openssl ocsp`, an implementation this service
// does not share (tests/pki_revocation.js's reason); without the binary the
// verification is pkijs's parse alone, and the file says so.
// ===========================================================================

delete process.env.CONFIG_FILE;

const tls = require('tls');
const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const nodeCrypto = require('crypto');

const ROOT = path.join(__dirname, '..');

const log = require('bunyan').createLogger({ name: 'tls_ocsp_stapling',
  level: process.env.LOG_LEVEL || 'info' });

let scratch = '';
let openSsl = null;

function haveOpenSsl() {
  log.debug("Entering haveOpenSsl().");
  if (openSsl === null) {
    try {
      childProcess.execFileSync('openssl', ['version'], { stdio: 'pipe' });
      openSsl = true;
    } catch (e) {
      log.debug("Caught in haveOpenSsl(): " + ((e && e.message) || e));
      openSsl = false;
    }
  }
  log.debug("Leaving haveOpenSsl(). " + openSsl);
  return openSsl;
}

// One handshake asking for the certificate status. `staple` is what the
// server stapled (null for none).
function handshake(port, options) {
  log.debug("Entering handshake().");
  return new Promise(function (resolve) {
    const out = { ok: false, staple: null, leafPem: '', protocol: '',
                  error: '' };
    const socket = tls.connect(Object.assign({
      host: '127.0.0.1', port: port, servername: 'localhost',
      requestOCSP: true, rejectUnauthorized: false
    }, options || {}), function () {
      out.ok = true;
      out.protocol = socket.getProtocol();
      const peer = socket.getPeerX509Certificate();
      out.leafPem = peer ? peer.toString() : '';
      socket.end();
    });
    socket.on('OCSPResponse', function (response) {
      out.staple = response || null;
    });
    socket.on('error', function (e) {
      out.error = String((e && e.message) || e);
      resolve(out);
    });
    socket.on('close', function () {
      resolve(out);
    });
    socket.setTimeout(20000, function () {
      out.error = 'timed out';
      socket.destroy();
    });
  });
}

function listen(server) {
  log.debug("Entering listen().");
  return new Promise(function (resolve) {
    server.listen(0, '127.0.0.1', function () {
      log.debug("Leaving listen().");
      resolve(server.address().port);
    });
  });
}

// The SingleResponses of a staple, by serial: pkijs's reading.
function singles(der) {
  log.debug("Entering singles().");
  const pkijs = require('pkijs');
  const plain = function (buf) {
    log.debug("Entering plain().");
    log.debug("Leaving plain().");
    return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
  };
  const response = pkijs.OCSPResponse.fromBER(plain(der));
  const basic = pkijs.BasicOCSPResponse.fromBER(plain(Buffer.from(
    response.responseBytes.response.valueBlock.valueHexView)));
  const out = {};
  basic.tbsResponseData.responses.forEach(function (one) {
    const serial = Buffer.from(one.certID.serialNumber.valueBlock
      .valueHexView).toString('hex').replace(/^0+/, '');
    const tag = one.certStatus.idBlock.tagNumber;
    out[serial] = tag === 0 ? 'good' : tag === 1 ? 'revoked' : 'unknown';
  });
  log.debug("Leaving singles().");
  return { status: response.responseStatus.valueBlock.valueDec,
           byStatus: out,
           nextUpdate: basic.tbsResponseData.responses[0].nextUpdate };
}

// OpenSSL's verdict on a staple: the signature against the CA chain, and the
// status of `leafPem` under `issuerPem`.
function opensslVerdict(der, leafPem, issuerPem, chainPems) {
  log.debug("Entering opensslVerdict().");
  if (!haveOpenSsl()) {
    log.debug("Leaving opensslVerdict(). No openssl.");
    return { verified: null, status: '' };
  }
  const dir = fs.mkdtempSync(path.join(scratch, 'v-'));
  fs.writeFileSync(path.join(dir, 'staple.der'), der);
  fs.writeFileSync(path.join(dir, 'leaf.pem'), leafPem);
  fs.writeFileSync(path.join(dir, 'issuer.pem'), issuerPem);
  fs.writeFileSync(path.join(dir, 'ca.pem'), chainPems.join('\n'));
  const r = childProcess.spawnSync('openssl', ['ocsp', '-respin',
    path.join(dir, 'staple.der'), '-issuer', path.join(dir, 'issuer.pem'),
    '-cert', path.join(dir, 'leaf.pem'), '-CAfile', path.join(dir, 'ca.pem'),
    '-no_nonce'], { encoding: 'utf8' });
  const text = String(r.stdout || '') + String(r.stderr || '');
  const m = /leaf\.pem: (good|revoked|unknown)/.exec(text);
  log.debug("Leaving opensslVerdict().");
  return { verified: /Response verify OK/.test(text),
           status: m ? m[1] : '', text: text };
}

function serialOf(pem) {
  log.debug("Entering serialOf().");
  log.debug("Leaving serialOf().");
  return new nodeCrypto.X509Certificate(pem).serialNumber.toLowerCase()
    .replace(/^0+/, '');
}

// The Root and every CA the listener's chain carries: what a client holding
// the anchor verifies against.
function caChainOf(serverCert, pki) {
  log.debug("Entering caChainOf().");
  log.debug("Leaving caChainOf().");
  return [pki.serviceRoot().certificatePem].concat(serverCert.chainPem || []);
}

function assertStaple(t, label, seen, issuerPem, chain, want) {
  log.debug("Entering assertStaple(). " + label);
  t.check(seen.ok, label + ': the handshake succeeded', seen.error);
  if (!t.check(!!seen.staple, label + ': a staple was sent')) {
    log.debug("Leaving assertStaple(). None.");
    return null;
  }
  const read = singles(seen.staple);
  t.equal(read.status, 0, label + ': the OCSP response is `successful`');
  t.equal(read.byStatus[serialOf(seen.leafPem)], want,
          label + ': it says `' + want + '` for the certificate presented',
          JSON.stringify(read.byStatus));
  const verdict = opensslVerdict(seen.staple, seen.leafPem, issuerPem, chain);
  if (verdict.verified === null) {
    t.log.warn('openssl is not here: ' + label + '\'s signature is not ' +
               'verified by an independent implementation.');
  } else {
    t.check(verdict.verified, label + ': OpenSSL verifies its signature ' +
            'against the CA chain', verdict.text);
    t.equal(verdict.status, want, label + ': and reads `' + want + '`',
            verdict.text);
  }
  log.debug("Leaving assertStaple().");
  return read;
}

// --- D, in a child: LDAPS as server.js starts it ---------------------------

async function inChild() {
  log.debug("Entering inChild().");
  const out = process.env.TOS_OUT;
  const report = {};
  try {
    require(path.join(ROOT, 'common/protocol_stack'));
    const pki = require(path.join(ROOT, 'common/pki'));
    await pki.start();
    await pki.certifyRegistered();
    const tlsServer = require(path.join(ROOT, 'tls/tls_server'));
    const ldap = require(path.join(ROOT, 'ldap/ldap_server'));
    const ready = await ldap.listen().whenReady;
    report.port = ready.ldapsPort;
    report.seen = await handshake(ready.ldapsPort, {
      sigalgs: 'rsa_pss_rsae_sha256:rsa_pkcs1_sha256' });
    // The ML-DSA leaf beside it (tls.certificateAlgorithms): the one staple
    // must answer for it too.
    const mldsa = await handshake(ready.ldapsPort, {
      sigalgs: 'mldsa65:mldsa44:mldsa87' });
    report.mldsa = { ok: mldsa.ok, error: mldsa.error,
                     leafPem: mldsa.leafPem,
                     staple: mldsa.staple ? mldsa.staple.toString('base64')
                       : '' };
    report.staple = report.seen.staple
      ? report.seen.staple.toString('base64') : '';
    delete report.seen.staple;
    report.chain = [pki.serviceRoot().certificatePem]
      .concat(tlsServer.serverCertificate().chainPem || []);
    report.issuer = (tlsServer.serverCertificate().chainPem || [])[0] || '';
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
  const out = path.join(os.tmpdir(), 'tos-' + process.pid + '-' +
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
                                STS_TLS_OCSP_STAPLING: 'on',
                                STS_TLS_CERT_ALGS: 'rsa,ml-dsa-65',
                                LDAP_PORT: '0', LDAPS_PORT: '0',
                                TOS_OUT: out }),
    encoding: 'utf8', timeout: 240000, cwd: ROOT
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
  if (!t.check(!report.error && report.port, 'D0. LDAPS started',
               report.error)) {
    log.debug("Leaving checkLdaps(). No listener.");
    return;
  }
  report.seen.staple = report.staple ? Buffer.from(report.staple, 'base64')
    : null;
  assertStaple(t, 'D1. LDAPS 636', report.seen, report.issuer, report.chain,
               'good');
  const mldsa = report.mldsa || {};
  const keyType = mldsa.leafPem ? new nodeCrypto.X509Certificate(
    mldsa.leafPem).publicKey.asymmetricKeyType : '';
  t.check(mldsa.ok && /^ml-dsa/.test(keyType),
          'D2. a client offering only ML-DSA is served the ML-DSA leaf',
          mldsa.error || keyType);
  if (mldsa.staple && mldsa.leafPem) {
    const read = singles(Buffer.from(mldsa.staple, 'base64'));
    t.equal(read.byStatus[serialOf(mldsa.leafPem)], 'good',
            'D3. and the staple answers `good` for THAT leaf: one ' +
            'SingleResponse per leaf, whichever OpenSSL selects',
            JSON.stringify(read.byStatus));
  } else {
    t.check(false, 'D3. the ML-DSA handshake carried a staple');
  }
  log.debug("Leaving checkLdaps().");
}

// --- I: an outside authority's certificate, made by openssl ----------------

function outsideCertificate() {
  log.debug("Entering outsideCertificate().");
  const dir = fs.mkdtempSync(path.join(scratch, 'out-'));
  const run = function (args) {
    log.debug("Entering run(). openssl " + args[0]);
    childProcess.execFileSync('openssl', args, { stdio: 'pipe', cwd: dir });
    log.debug("Leaving run().");
  };
  run(['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key',
       '-out', 'ca.pem', '-subj', '/CN=An outside CA', '-days', '2']);
  run(['req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'leaf.key',
       '-out', 'leaf.csr', '-subj', '/CN=localhost']);
  run(['x509', '-req', '-in', 'leaf.csr', '-CA', 'ca.pem', '-CAkey',
       'ca.key', '-out', 'leaf.pem', '-days', '1']);
  log.debug("Leaving outsideCertificate().");
  return { key: fs.readFileSync(path.join(dir, 'leaf.key'), 'utf8'),
           cert: fs.readFileSync(path.join(dir, 'leaf.pem'), 'utf8') +
                 fs.readFileSync(path.join(dir, 'ca.pem'), 'utf8') };
}

// ---------------------------------------------------------------------------

async function run(t) {
  log.debug("Entering run().");
  scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-ocsp-staple-'));
  const config = require('../common/config');
  const pki = require('../common/pki');
  const revocation = require('../common/pki_revocation');
  const tlsServer = require('../tls/tls_server');
  const Stapling = require('../tls/ocsp_stapling');
  await pki.start();
  await pki.certifyRegistered();
  Stapling.forget();
  config.setOverride('tls.ocspStapling', 'on');
  const servers = [];
  const realStapleFor = revocation.stapleFor;
  try {
    // --- A. the main port --------------------------------------------------
    t.log.info('=== A. the main port ===');
    const serverCert = tlsServer.serverCertificate();
    t.check(serverCert.chainPem.length > 0,
            'A0. the listener certificate is issued by this service\'s CA');
    const issuerPem = serverCert.chainPem[0];
    const chain = caChainOf(serverCert, pki);
    const main = tls.createServer({
      cert: tlsServer.presentedBundlePem(serverCert),
      key: serverCert.privateKeyPem }, function (socket) {
      socket.end();
    });
    servers.push(main);
    t.check(Stapling.install(main, 'main', 'the main port'),
            'A1. installed on the main port');
    const mainPort = await listen(main);
    const v13 = await handshake(mainPort, { maxVersion: 'TLSv1.3',
                                            minVersion: 'TLSv1.3' });
    t.equal(v13.protocol, 'TLSv1.3', 'A2. a TLS 1.3 handshake');
    const read = assertStaple(t, 'A3. the main port in TLS 1.3', v13,
                              issuerPem, chain, 'good');
    const v12 = await handshake(mainPort, { maxVersion: 'TLSv1.2' });
    t.equal(v12.protocol, 'TLSv1.2', 'A4. a TLS 1.2 handshake');
    assertStaple(t, 'A5. the main port in TLS 1.2', v12, issuerPem, chain,
                 'good');
    const presented = tlsServer.presentedCertificatePems();
    t.check(read && presented.every(function (pem) {
      return read.byStatus[serialOf(pem)] === 'good';
    }), 'A6. ONE SINGLERESPONSE PER LEAF the port presents (' +
            presented.length + '), whichever OpenSSL selects',
    JSON.stringify(read && read.byStatus));
    const mainRow = Stapling.report().filter(function (one) {
      return one.listeners.indexOf('main') >= 0;
    })[0] || {};
    t.check(mainRow.state === 'current' && mainRow.status === 'good' &&
            mainRow.made === 1, 'A7. one staple made and kept, current, ' +
            'good — the second handshake was served from it',
    JSON.stringify(mainRow));

    // --- B. the debugger's context -----------------------------------------
    t.log.info('=== B. the debugger listener ===');
    const dbg = tls.createServer(Object.assign({},
      tlsServer.clientTruststoreOptions(tlsServer.policyFor('debugger')),
      { requestCert: false }), function (socket) {
      socket.end();
    });
    servers.push(dbg);
    Stapling.install(dbg, 'debugger', 'the protocol debugger');
    const dbgSeen = await handshake(await listen(dbg), {});
    assertStaple(t, 'B1. the debugger listener', dbgSeen, issuerPem, chain,
                 'good');
    const shared = Stapling.report().filter(function (one) {
      return one.listeners.indexOf('debugger') >= 0;
    })[0] || {};
    t.check(shared.listeners && shared.listeners.indexOf('main') >= 0 &&
            shared.made === 1, 'B2. the same certificates share one staple',
    JSON.stringify(shared));

    // --- C. a custom listener ----------------------------------------------
    t.log.info('=== C. a custom listener ===');
    const issued = await pki.issueTlsServerKeyPair('', 'realm-tls', {
      slot: 'listener:ocsp-test:' + os.hostname(), label: 'listener ocsp-test',
      commonName: 'localhost', dnsNames: ['localhost'], ipAddresses: [] });
    if (t.check(issued && issued.ok, 'C0. a realm-tls leaf is issued',
                JSON.stringify((issued && issued.errors) || ''))) {
      const custom = tls.createServer({
        cert: tlsServer.presentedBundlePem({
          certPem: issued.issued.certificatePem,
          chainPem: issued.issued.chainPem || [] }),
        key: issued.issued.privateKeyPem }, function (socket) {
        socket.end();
      });
      servers.push(custom);
      Stapling.install(custom, 'custom:ocsp-test', 'listener ocsp-test');
      const customSeen = await handshake(await listen(custom), {});
      assertStaple(t, 'C1. a custom listener', customSeen,
                   (issued.issued.chainPem || [])[0],
                   [pki.serviceRoot().certificatePem]
                     .concat(issued.issued.chainPem || []), 'good');
      const customRow = Stapling.report().filter(function (one) {
        return one.listeners.indexOf('custom:ocsp-test') >= 0;
      })[0] || {};
      t.check(customRow.ca && customRow.ca !== mainRow.ca,
              'C2. answered by the realm\'s own CA, not the process\'s',
              customRow.ca + ' vs ' + mainRow.ca);
    }

    // --- E. revoked after a refresh ----------------------------------------
    t.log.info('=== E. a revoked listener certificate ===');
    const leafSerial = serialOf(serverCert.certPem);
    const held = revocation.revoke(mainRow.scope, mainRow.ca, {
      serialHex: leafSerial, reason: 'certificateHold',
      note: 'tests/tls_ocsp_stapling.js' });
    t.check(held.ok, 'E0. the listener certificate is put on hold',
            JSON.stringify(held.errors || ''));
    await Stapling.refresh();
    assertStaple(t, 'E1. after a refresh', await handshake(mainPort, {}),
                 issuerPem, chain, 'revoked');
    const released = revocation.release(mainRow.scope, mainRow.ca,
                                        leafSerial);
    t.check(released.ok, 'E2. the hold is released');
    await Stapling.refresh();
    assertStaple(t, 'E3. and good again after the next refresh',
                 await handshake(mainPort, {}), issuerPem, chain, 'good');

    // --- F. the setting ----------------------------------------------------
    t.log.info('=== F. tls.ocspStapling ===');
    config.setOverride('tls.ocspStapling', 'off');
    const off = await handshake(mainPort, {});
    t.check(off.ok && !off.staple,
            'F1. off: the handshake succeeds and nothing is stapled',
            off.error);
    config.setOverride('tls.ocspStapling', 'auto');
    t.equal(Stapling.enabled(), !!require('../common/mode').staplesOcsp(),
            'F2. auto is mode.staplesOcsp()');
    t.equal(require('../common/mode').staplesOcsp(),
            require('../common/mode').isProduct(),
            'F3. which is on in product and off in development');
    config.setOverride('tls.ocspStapling', 'on');

    // --- G. the job --------------------------------------------------------
    t.log.info('=== G. tls.ocsp-staple-refresh ===');
    const job = require('../cluster/scheduler').job(Stapling.JOB);
    t.check(job && job.kind === 'per-process',
            'G1. a per-process scheduler job, never a timer');
    [1, 60, 10080].forEach(function (minutes) {
      config.setOverride('pki.crlLifetimeMinutes', String(minutes));
      const every = job.everyMs();
      t.check(every > 0 && every < minutes * 60000,
              'G2. with responses fresh for ' + minutes + ' min it runs ' +
              'every ' + every + ' ms, inside that window');
    });
    config.clearOverride('pki.crlLifetimeMinutes');
    t.equal(job.off(), '', 'G3. on in a front process that staples');
    process.env.STS_REQUEST_WORKER = '1';
    t.check(/request worker/.test(job.off()),
            'G4. off in a request worker, which holds no socket');
    delete process.env.STS_REQUEST_WORKER;
    const before = Stapling.report().filter(function (one) {
      return one.listeners.indexOf('main') >= 0;
    })[0];
    await new Promise(function (r) {
      setTimeout(r, 1100);
    });
    const ranAt = Date.now();
    await job.run({});
    const after = Stapling.report().filter(function (one) {
      return one.listeners.indexOf('main') >= 0;
    })[0];
    t.check(ranAt < Date.parse(before.nextUpdate),
            'G5. the run came before the old staple\'s nextUpdate');
    t.check(after.made === before.made + 1 &&
            Date.parse(after.thisUpdate) > Date.parse(before.thisUpdate) &&
            Date.parse(after.nextUpdate) > Date.parse(before.nextUpdate),
            'G6. and re-made it: a later thisUpdate and nextUpdate',
            JSON.stringify([before, after]));

    // --- H. a staple that cannot be made -----------------------------------
    t.log.info('=== H. failures never fail a handshake ===');
    Stapling.forget();
    revocation.stapleFor = function () {
      return Promise.reject(new Error('a signer that fails (the test)'));
    };
    const failed = await handshake(mainPort, {});
    t.check(failed.ok && !failed.staple,
            'H1. the responder throws: the handshake succeeds, unstapled',
            failed.error);
    const failing = Stapling.report()[0] || {};
    t.check(failing.state === 'failing' && /signer that fails/.test(
      failing.why), 'H2. the staple is recorded as failing, with why',
    JSON.stringify(failing));
    Stapling.forget();
    revocation.stapleFor = function () {
      return new Promise(function () {
        // Never settles.
      });
    };
    const started = Date.now();
    const slow = await handshake(mainPort, {});
    t.check(slow.ok && !slow.staple && Date.now() - started <
            Stapling.HANDSHAKE_WAIT_MS + 5000,
            'H3. a responder that never answers: the handshake waits at ' +
            'most HANDSHAKE_WAIT_MS and goes on unstapled', slow.error);
    revocation.stapleFor = realStapleFor;
    Stapling.forget();
    assertStaple(t, 'H4. and staples again once it answers',
                 await handshake(mainPort, {}), issuerPem, chain, 'good');

    // --- I. an outside authority -------------------------------------------
    t.log.info('=== I. a certificate from an outside authority ===');
    if (!haveOpenSsl()) {
      t.log.warn('openssl is not here, so section I is not run.');
    } else {
      const outside = tls.createServer(outsideCertificate(),
        function (socket) {
          socket.end();
        });
      servers.push(outside);
      Stapling.install(outside, 'custom:outside', 'an outside listener');
      const seen = await handshake(await listen(outside), {});
      t.check(seen.ok && !seen.staple,
              'I1. not stapled, and the handshake succeeds', seen.error);
      const row = Stapling.report().filter(function (one) {
        return one.listeners.indexOf('custom:outside') >= 0;
      })[0] || {};
      t.equal(row.state, 'outside', 'I2. recorded as an outside issuer');
    }

    // --- J. the construction sites -----------------------------------------
    t.log.info('=== J. every listener kind installs it ===');
    const src = function (file) {
      log.debug("Entering src(). " + file);
      log.debug("Leaving src().");
      return fs.readFileSync(path.join(ROOT, file), 'utf8');
    };
    t.equal((src('server.js').match(
      /require\('\.\/tls\/ocsp_stapling'\)\.install\(/g) || []).length, 2,
    'J1. server.js installs it on the main port and in customListener()');
    t.check(/require\('\.\.\/tls\/ocsp_stapling'\)\.install\(secureServer/
      .test(src('ldap/ldap_server.js')), 'J2. LDAPS installs it');
    t.check(/OcspStapling\.install\(server, 'debugger'/
      .test(src('debugger/debugger_server.ts')),
    'J3. the debugger listener installs it');
  } finally {
    revocation.stapleFor = realStapleFor;
    servers.forEach(function (one) {
      one.close();
    });
    config.clearOverride('tls.ocspStapling');
    config.clearOverride('pki.crlLifetimeMinutes');
    Stapling.forget();
  }

  // --- D. LDAPS, in a child ------------------------------------------------
  t.log.info('=== D. LDAPS 636 ===');
  checkLdaps(t);
  fs.rmSync(scratch, { recursive: true, force: true });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'tls_ocsp_stapling',
  describe: 'OCSP stapling on the main port, LDAPS, the debugger and custom ' +
            'listeners (#2254): verified and good, revoked after a refresh, ' +
            'off by the setting, refreshed by a per-process job before ' +
            'nextUpdate, and never a failed handshake',
  run: run,
  inChild: inChild
};
