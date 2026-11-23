// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tls_same_subject_anchors.js
//
// ===========================================================================
// TWO RUNTIME ANCHORS, ONE SUBJECT (#1242).
//
// OpenSSL looks an issuer up by subject name. With no authority key
// identifier on the certificate being verified, the first anchor of that
// subject is the only candidate, and a signature that does not match it is
// DEPTH_ZERO_SELF_SIGNED_CERT — OpenSSL does not try the next certificate.
// Two self-signed certificates whose CN defaulted to the same host were both
// reported installed, and only the first verified.
//
// What this holds, against a listener registered the way the main port is
// (`trustClientCertificatesOn` and `observeConnectionsOn`, so the path rules
// run after the fingerprint recognition):
//
//   * both certificates verify when presented as themselves;
//   * the later row's `shadowedBy` is the earlier fingerprint, and the add
//     warns under STS-TLS-0064;
//   * a certificate the later anchor ISSUED stays unverified while the
//     earlier one is installed, and verifies once that one is removed — so
//     the recognition matched the anchor itself and not anything it signed;
//   * two anchors whose authority key identifiers name different subject key
//     identifiers are a rollover: no warning, no `shadowedBy`, both verify;
//   * INVALID_PURPOSE is not promoted.
//
// In process, like tests/truststore_admin.js: the verdict is the listener's
// `socket.authorized`, which a request over HTTP against a running service
// would only see once a protocol had decided to refuse. Every anchor this
// file adds is removed before it returns. The shared subject is unique per
// run, so an anchor another file left behind cannot be the one `shadowedBy`
// names.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const https = require('https');
const os = require('os');
const path = require('path');

const log = require('bunyan').createLogger({
  name: 'tls_same_subject_anchors',
  level: process.env.LOG_LEVEL || 'info' });

// The listener certificate, filled before the listener is registered. Its
// subject is not one of the anchors', so issuer lookup is not contaminated
// by the certificate the socket presents.
const SERVER = { key: '', cert: '' };

function certificateOf() {
  log.debug("Entering certificateOf().");
  log.debug("Leaving certificateOf().");
  return { key: SERVER.key, cert: SERVER.cert };
}

function fingerprintOf(pem) {
  log.debug("Entering fingerprintOf().");
  log.debug("Leaving fingerprintOf().");
  return new crypto.X509Certificate(pem).fingerprint256;
}

function rowOf(tlsServer, pem) {
  log.debug("Entering rowOf().");
  const want = fingerprintOf(pem);
  const row = tlsServer.truststore.list().anchors.filter(function (one) {
    return one.fingerprint256 === want;
  })[0] || null;
  log.debug("Leaving rowOf().");
  return row;
}

// A self-signed end entity whose subject and authority key identifiers
// differ from another minted the same way. OpenSSL 3 adds a subject key
// identifier by default even to a request that did not ask, so the
// identifiers are requested in a private config rather than by `-addext`.
function opensslPair(dir, name, commonName) {
  log.debug("Entering opensslPair(). " + name);
  const key = path.join(dir, name + '.key');
  const cert = path.join(dir, name + '.crt');
  const cfg = path.join(dir, name + '.cnf');
  fs.writeFileSync(cfg, [
    '[req]',
    'distinguished_name = dn',
    'prompt = no',
    'x509_extensions = ext',
    '[dn]',
    'CN = ' + commonName,
    '[ext]',
    'basicConstraints = CA:FALSE',
    'keyUsage = digitalSignature',
    'subjectKeyIdentifier = hash',
    'authorityKeyIdentifier = keyid:always',
    ''
  ].join('\n'));
  const made = childProcess.spawnSync('openssl', [
    'req', '-x509', '-nodes', '-newkey', 'rsa:2048', '-days', '1',
    '-config', cfg, '-extensions', 'ext', '-keyout', key, '-out', cert
  ], { encoding: 'utf8', timeout: 60000 });
  if (made.status !== 0) {
    log.debug("Leaving opensslPair(). openssl failed.");
    throw new Error('openssl req for ' + name + ': ' +
                    (made.stderr || made.error));
  }
  const text = childProcess.spawnSync('openssl',
    ['x509', '-noout', '-text', '-in', cert],
    { encoding: 'utf8', timeout: 30000 });
  log.debug("Leaving opensslPair().");
  return { key: fs.readFileSync(key, 'utf8'),
           cert: fs.readFileSync(cert, 'utf8'),
           text: text.stdout || '' };
}

// A leaf the second anchor signed. No authority key identifier, so OpenSSL's
// lookup is by the issuer name alone. A different subject from the anchor,
// so the leaf is not itself an anchor.
function issuedLeaf(caPem, caKeyPem, commonName) {
  log.debug("Entering issuedLeaf(). " + commonName);
  const forge = require('node-forge');
  const ca = forge.pki.certificateFromPem(caPem);
  const key = forge.pki.privateKeyFromPem(caKeyPem);
  const pair = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = pair.publicKey;
  cert.serialNumber = '01' + crypto.randomBytes(8).toString('hex');
  cert.validity.notBefore = new Date(Date.now() - 60 * 1000);
  cert.validity.notAfter = new Date(Date.now() + 86400 * 1000);
  cert.setSubject([{ name: 'commonName', value: commonName }]);
  cert.setIssuer(ca.subject.attributes);
  cert.setExtensions([
    { name: 'basicConstraints', cA: false },
    { name: 'keyUsage', digitalSignature: true, critical: true }
  ]);
  cert.sign(key, forge.md.sha256.create());
  log.debug("Leaving issuedLeaf().");
  return { cert: forge.pki.certificateToPem(cert),
           key: forge.pki.privateKeyToPem(pair.privateKey) };
}

// The server's verdict, first line `verified` or `unverified`. `unverified`
// contains the letters of `verified`, so the line is compared whole.
function presented(server, material) {
  log.debug("Entering presented().");
  log.debug("Leaving presented().");
  return new Promise(function (resolve) {
    const req = https.request({
      host: '127.0.0.1', port: server.address().port, path: '/',
      method: 'GET', cert: material.cert, key: material.key,
      rejectUnauthorized: false, agent: false
    }, function (res) {
      let text = '';
      res.on('data', function (chunk) {
        text += chunk;
      });
      res.on('end', function () {
        const lines = text.split('\n');
        resolve({ line: lines[0], error: lines[1] || '', body: text });
      });
    });
    req.setTimeout(15000, function () {
      req.destroy();
      resolve({ line: 'error', error: 'timeout', body: '' });
    });
    req.on('error', function (e) {
      resolve({ line: 'error', error: e.message, body: '' });
    });
    req.end();
  });
}

function stopListener(server) {
  log.debug("Entering stopListener().");
  if (typeof server.closeAllConnections === 'function') {
    server.closeAllConnections();
  }
  log.debug("Leaving stopListener().");
  return new Promise(function (resolve) {
    server.close(function () {
      resolve();
    });
  });
}

async function run(t) {
  log.debug("Entering run().");
  const tlsServer = require('../tls/tls_server');
  const stsCrypto = require('../common/crypto');
  const stamp = String(process.pid) + '-' + Date.now();
  const shared = 'issue-1242-' + stamp;
  // No extensions at all: the shape the ticket minted, which carries neither
  // key identifier. `selfSignedRsaCertificate` adds extensions only when it
  // is given some, and OpenSSL 3 would add a subject key identifier to one
  // minted with `openssl req -x509`.
  const first = stsCrypto.selfSignedRsaCertificate({ commonName: shared });
  const second = stsCrypto.selfSignedRsaCertificate({ commonName: shared });
  const other = stsCrypto.selfSignedRsaCertificate({
    commonName: 'issue-1242-other-' + stamp });
  const serverCert = stsCrypto.selfSignedRsaCertificate({
    commonName: 'issue-1242-server-' + stamp,
    extensions: [
      { name: 'basicConstraints', cA: false, critical: true },
      { name: 'keyUsage', digitalSignature: true, keyEncipherment: true,
        critical: true },
      { name: 'extKeyUsage', serverAuth: true },
      { name: 'subjectAltName',
        altNames: [{ type: 7, ip: '127.0.0.1' }] }
    ]
  });
  SERVER.key = serverCert.privateKeyPem;
  SERVER.cert = serverCert.certPem;
  // A CA whose only use is signing. Presented as a client certificate,
  // OpenSSL answers INVALID_PURPOSE, which recognition must not override.
  const purposeOnly = stsCrypto.selfSignedRsaCertificate({
    commonName: 'issue-1242-purpose-' + stamp,
    extensions: [
      { name: 'basicConstraints', cA: true, critical: true },
      { name: 'keyUsage', keyCertSign: true, cRLSign: true, critical: true }
    ]
  });
  const caName = 'issue-1242-ca-' + stamp;
  const caExtensions = [
    { name: 'basicConstraints', cA: true, critical: true },
    { name: 'keyUsage', keyCertSign: true, cRLSign: true, critical: true }
  ];
  const caFirst = stsCrypto.selfSignedRsaCertificate({
    commonName: caName, extensions: caExtensions });
  const caSecond = stsCrypto.selfSignedRsaCertificate({
    commonName: caName, extensions: caExtensions });
  const leaf = issuedLeaf(caSecond.certPem, caSecond.privateKeyPem,
                          'issue-1242-leaf-' + stamp);
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(),
                                           'sts-1242-'));
  let listener = null;
  let before = null;
  try {
    const skiName = 'issue-1242-ski-' + stamp;
    const skiFirst = opensslPair(scratch, 'ski-a', skiName);
    const skiSecond = opensslPair(scratch, 'ski-b', skiName);
    t.check(/Subject Key Identifier/.test(skiFirst.text) &&
            /Authority Key Identifier/.test(skiFirst.text) &&
            /Subject Key Identifier/.test(skiSecond.text) &&
            /Authority Key Identifier/.test(skiSecond.text),
            'the rollover pair carries both key identifiers',
            skiFirst.text.slice(0, 500));

    listener = https.createServer(
      Object.assign(tlsServer.clientAuthOptions('optional'),
                    tlsServer.clientTruststoreOptions(),
                    { key: SERVER.key, cert: SERVER.cert }),
      function (req, res) {
        const raw = req.socket.authorizationError;
        const error = String((raw && raw.code) || raw || '');
        res.end((req.socket.authorized ? 'verified' : 'unverified') +
                '\n' + error);
      });
    await new Promise(function (ok) {
      listener.listen(0, '127.0.0.1', ok);
    });
    tlsServer.trustClientCertificatesOn(listener, 'issue-1242',
                                        certificateOf);
    tlsServer.observeConnectionsOn(listener, 'issue-1242');
    before = new Set(tlsServer.truststore.list().anchors.map(
      function (one) {
        return one.fingerprint256;
      }));

    t.log.info('=== same subject, no authority key identifier ===');
    const added = tlsServer.truststore.add(first.certPem + second.certPem,
                                           { strict: true });
    t.equal(added.added, 2, 'both anchors are kept');
    t.equal(added.duplicates || 0, 0, 'neither was already held');
    const rowFirst = rowOf(tlsServer, first.certPem);
    const rowSecond = rowOf(tlsServer, second.certPem);
    t.check(!!added.warning &&
            added.warning.indexOf('STS-TLS-0064') >= 0 &&
            added.warning.indexOf(rowFirst.fingerprint256) >= 0 &&
            added.warning.indexOf(rowSecond.fingerprint256) >= 0,
            'the add warns, naming the code and both fingerprints',
            added.warning);
    t.equal(added.warning.split('The subject of ').length, 2,
            'the warning is the later anchor only');
    t.equal(rowFirst.shadowedBy, undefined,
            'the earlier anchor is the one the lookup finds');
    t.equal(rowSecond.shadowedBy, rowFirst.fingerprint256,
            'the later row names the earlier fingerprint');

    const addedOther = tlsServer.truststore.add(other.certPem,
                                                { strict: true });
    t.equal(addedOther.warning, undefined,
            'a different subject is not a collision');
    t.equal(rowOf(tlsServer, other.certPem).shadowedBy, undefined,
            'and its row carries no shadowedBy');

    const seenFirst = await presented(listener, {
      cert: first.certPem, key: first.privateKeyPem });
    t.equal(seenFirst.line, 'verified',
            'the earlier anchor verifies (' + seenFirst.error + ')');
    const seenSecond = await presented(listener, {
      cert: second.certPem, key: second.privateKeyPem });
    t.equal(seenSecond.line, 'verified',
            'the later anchor verifies by its fingerprint (' +
            seenSecond.error + ')');
    const seenOther = await presented(listener, {
      cert: other.certPem, key: other.privateKeyPem });
    t.equal(seenOther.line, 'verified',
            'a distinct subject still verifies (' + seenOther.error + ')');

    t.log.info('=== a certificate the later anchor issued ===');
    const addedCas = tlsServer.truststore.add(
      caFirst.certPem + caSecond.certPem, { strict: true });
    t.equal(addedCas.added, 2, 'both CAs are kept');
    t.check(!!addedCas.warning &&
            addedCas.warning.indexOf('STS-TLS-0064') >= 0,
            'no authority key identifier on the later CA is a collision',
            addedCas.warning || '');
    const blocked = await presented(listener, leaf);
    t.equal(blocked.line, 'unverified',
            'the issued leaf stays unverified while the earlier CA is ' +
            'installed (' + blocked.error + ')');
    t.check(blocked.error.indexOf('CERT_SIGNATURE_FAILURE') >= 0 ||
            blocked.error.indexOf('UNABLE_TO_VERIFY_LEAF_SIGNATURE') >= 0,
            'the refusal is the signature, not a promoted anchor',
            blocked.error);
    tlsServer.truststore.remove(rowOf(tlsServer,
                                      caFirst.certPem).fingerprint256);
    const opened = await presented(listener, leaf);
    t.equal(opened.line, 'verified',
            'the same leaf verifies once its issuer is the anchor OpenSSL ' +
            'finds (' + opened.error + ')');
    t.equal(rowOf(tlsServer, caSecond.certPem).shadowedBy, undefined,
            'removing the earlier CA clears shadowedBy');

    tlsServer.truststore.remove(rowFirst.fingerprint256);
    t.equal(rowOf(tlsServer, second.certPem).shadowedBy, undefined,
            'removing the earlier end entity clears shadowedBy');
    const still = await presented(listener, {
      cert: second.certPem, key: second.privateKeyPem });
    t.equal(still.line, 'verified',
            'that certificate still verifies (' + still.error + ')');

    t.log.info('=== distinct key identifiers are a rollover ===');
    const addedSki = tlsServer.truststore.add(
      skiFirst.cert + skiSecond.cert, { strict: true });
    t.equal(addedSki.added, 2, 'both rollover anchors are kept');
    t.equal(addedSki.warning, undefined,
            'an authority key identifier that names a different subject ' +
            'key identifier is not a collision');
    t.equal(rowOf(tlsServer, skiFirst.cert).shadowedBy, undefined,
            'the earlier rollover row is not shadowed');
    t.equal(rowOf(tlsServer, skiSecond.cert).shadowedBy, undefined,
            'the later rollover row is not shadowed');
    const seenSkiFirst = await presented(listener, skiFirst);
    t.equal(seenSkiFirst.line, 'verified',
            'the earlier rollover anchor verifies (' +
            seenSkiFirst.error + ')');
    const seenSkiSecond = await presented(listener, skiSecond);
    t.equal(seenSkiSecond.line, 'verified',
            'the later rollover anchor verifies without recognition (' +
            seenSkiSecond.error + ')');

    t.log.info('=== a purpose OpenSSL refused is not promoted ===');
    const addedPurpose = tlsServer.truststore.add(purposeOnly.certPem,
                                                  { strict: true });
    t.equal(addedPurpose.added, 1, 'the keyCertSign-only CA is kept');
    const seenPurpose = await presented(listener, {
      cert: purposeOnly.certPem, key: purposeOnly.privateKeyPem });
    t.equal(seenPurpose.line, 'unverified',
            'INVALID_PURPOSE stays unverified (' + seenPurpose.error + ')');
    t.check(seenPurpose.error.indexOf('INVALID_PURPOSE') >= 0,
            'OpenSSL refused the purpose', seenPurpose.error);
  } finally {
    if (before) {
      tlsServer.truststore.list().anchors.forEach(function (one) {
        if (!before.has(one.fingerprint256)) {
          tlsServer.truststore.remove(one.fingerprint256);
        }
      });
    }
    if (listener) {
      tlsServer.forgetListener(listener);
      await stopListener(listener);
    }
    fs.rmSync(scratch, { recursive: true, force: true });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'tls_same_subject_anchors',
  describe: 'two client-truststore anchors with one subject: the later ' +
            'certificate verifies by its fingerprint, one it issued does ' +
            'not, and a key-id rollover is not a collision (#1242)',
  run: run
};
