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
//   * BOTH rows' `shadowedBy` names the other (which one OpenSSL finds first
//     is not promised), and the add warns — naming both fingerprints and no
//     error code, which goes on the log line alone;
//   * a certificate the later anchor ISSUED stays unverified while the
//     earlier one is installed, and verifies once that one is removed — so
//     the recognition matched the anchor itself and not anything it signed;
//   * two anchors whose authority key identifiers name different subject key
//     identifiers are a rollover: no warning, no `shadowedBy`, both verify;
//   * INVALID_PURPOSE is not promoted, and neither is a same-subject anchor
//     whose own extendedKeyUsage refuses client authentication, where
//     OpenSSL's LAST error is the signature failure and hides the purpose;
//   * an anchor that is not self-issued — an Intermediate installed alone,
//     an outside authority's end entity installed alone — is NOT an
//     identity when its holder presents it (UNABLE_TO_VERIFY_LEAF_SIGNATURE
//     is not promoted);
//   * an end entity installed beside its issuer verifies the ordinary way,
//     and the chain the listener reports names that issuer above it, not
//     the end entity as its own issuer.
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
function issuedLeaf(caPem, caKeyPem, commonName, extensions) {
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
  cert.setExtensions(extensions || [
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
        resolve({ line: lines[0], error: lines[1] || '',
                  issuer: lines[2] || '', body: text });
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
  // Three anchors of one subject, two for server authentication only, all
  // with keyUsage digitalSignature and no keyCertSign — the usual shape of
  // a self-signed client certificate, which node's checkIssued(self) calls
  // not self-issued and this service's recognition must still take. The
  // review of #1994 expected OpenSSL to report the later signature failure
  // and hide the purpose; the OpenSSL in this image reports
  // INVALID_PURPOSE for every arrangement tried (insertion order either
  // way, keyUsage or none), so the handshakes below hold that a wrong
  // purpose is not promoted, and the socket-shaped calls after them hold
  // the re-check for the error OpenSSL could report.
  const wrongName = 'issue-1242-wrong-' + stamp;
  const serverOnly = [
    { name: 'basicConstraints', cA: false },
    { name: 'keyUsage', digitalSignature: true, critical: true },
    { name: 'extKeyUsage', serverAuth: true }
  ];
  const wrongFirst = stsCrypto.selfSignedRsaCertificate({
    commonName: wrongName,
    extensions: [
      { name: 'basicConstraints', cA: false },
      { name: 'keyUsage', digitalSignature: true, critical: true }
    ]
  });
  const wrongSecond = stsCrypto.selfSignedRsaCertificate({
    commonName: wrongName, extensions: serverOnly });
  const wrongThird = stsCrypto.selfSignedRsaCertificate({
    commonName: wrongName, extensions: serverOnly });
  // An outside Root that is NEVER installed, an Intermediate it issued and
  // an end entity it issued: each installed alone, neither self-issued.
  const outsideRoot = stsCrypto.selfSignedRsaCertificate({
    commonName: 'issue-1242-outside-root-' + stamp,
    extensions: caExtensions });
  const intermediate = issuedLeaf(outsideRoot.certPem,
                                  outsideRoot.privateKeyPem,
                                  'issue-1242-intermediate-' + stamp, [
      { name: 'basicConstraints', cA: true, critical: true },
      { name: 'keyUsage', digitalSignature: true, keyCertSign: true,
        cRLSign: true, critical: true }
    ]);
  const outsideLeaf = issuedLeaf(outsideRoot.certPem,
                                 outsideRoot.privateKeyPem,
                                 'issue-1242-outside-leaf-' + stamp);
  // A CA and an end entity it issued, both installed.
  const pairCa = stsCrypto.selfSignedRsaCertificate({
    commonName: 'issue-1242-pair-ca-' + stamp, extensions: caExtensions });
  const pairLeaf = issuedLeaf(pairCa.certPem, pairCa.privateKeyPem,
                              'issue-1242-pair-leaf-' + stamp);
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
        // The issuer the listener reports above the leaf: what the path
        // rules, revocation and the identity gate read.
        const peer = /** @type {any} */ (req.socket).getPeerCertificate(true);
        const above = peer && peer.issuerCertificate;
        res.end((req.socket.authorized ? 'verified' : 'unverified') +
                '\n' + error + '\n' +
                ((above && above.fingerprint256) || ''));
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
            added.warning.indexOf(rowFirst.fingerprint256) >= 0 &&
            added.warning.indexOf(rowSecond.fingerprint256) >= 0,
            'the add warns, naming both fingerprints', added.warning);
    t.check(!/STS-[A-Z0-9]+-\d{4}/.test(added.warning),
            'the warning carries no error code: it names the caller\'s ' +
            'subject, so it is not fixed help text', added.warning);
    t.equal(added.warning.split('The subject of ').length, 2,
            'the warning is said once, for the anchor that made the pair');
    t.equal(rowFirst.shadowedBy, rowSecond.fingerprint256,
            'the first row names the second: no order is promised');
    t.equal(rowSecond.shadowedBy, rowFirst.fingerprint256,
            'the second row names the first');

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
            addedCas.warning.indexOf('is shared by') >= 0,
            'no subject key identifier on either CA is a collision',
            addedCas.warning || '');
    const blocked = await presented(listener, leaf);
    t.equal(blocked.line, 'unverified',
            'the issued leaf stays unverified while the earlier CA is ' +
            'installed (' + blocked.error + ')');
    t.equal(blocked.error, 'CERT_SIGNATURE_FAILURE',
            'the refusal is the signature checked against the other CA, ' +
            'which is what STS-TLS-0064\'s summary names');
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
            'removing the other end entity clears shadowedBy');
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

    t.log.info('=== a same-subject anchor with the wrong purpose ===');
    // Two carry extendedKeyUsage serverAuth alone. Whatever error OpenSSL
    // reports for them, neither may come out verified.
    const added2 = tlsServer.truststore.add(
      wrongFirst.certPem + wrongSecond.certPem + wrongThird.certPem,
      { strict: true });
    t.equal(added2.added, 3, 'all three same-subject anchors are kept');
    t.check(/extendedKeyUsage does not name/.test(
      stsCrypto.presentedAnchorProblem(wrongSecond.certPem, {
        keyUsage: ['digitalSignature', 'keyAgreement'],
        eku: stsCrypto.EKU.clientAuth })),
            'the purpose check refuses the serverAuth-only certificate');
    t.equal(stsCrypto.presentedAnchorProblem(first.certPem, {
      keyUsage: ['digitalSignature', 'keyAgreement'],
      eku: stsCrypto.EKU.clientAuth }), '',
            'and passes the certificate with no extensions');
    t.check(stsCrypto.certificateSelfSigned(wrongFirst.certPem) &&
            !new crypto.X509Certificate(wrongFirst.certPem)
              .checkIssued(new crypto.X509Certificate(wrongFirst.certPem)),
            'a self-signed end entity without keyCertSign is self-signed ' +
            'here, where node\'s checkIssued(self) says it is not');
    const hidden = [];
    for (const wrong of [wrongSecond, wrongThird]) {
      const seenWrong = await presented(listener, {
        cert: wrong.certPem, key: wrong.privateKeyPem });
      t.equal(seenWrong.line, 'unverified',
              'a same-subject anchor whose own purpose refuses client ' +
              'authentication is not promoted (' + seenWrong.error + ')');
      hidden.push(seenWrong.error);
    }
    t.log.info('the wrong-purpose anchors were refused with ' +
               hidden.join(', '));
    const seenRight = await presented(listener, {
      cert: wrongFirst.certPem, key: wrongFirst.privateKeyPem });
    t.equal(seenRight.line, 'verified',
            'their same-subject partner with no purpose restriction still ' +
            'verifies, natively or by its fingerprint (' + seenRight.error +
            ')');

    // This OpenSSL reports the purpose rather than the later signature
    // failure for every shape this file can mint, so the handshakes above
    // cannot show the re-check by themselves. A socket shaped as node
    // leaves one, refused with the error a same-subject lookup produces,
    // can: only the certificate whose own purpose allows a client is
    // promoted.
    const pems = tlsServer.clientTruststoreOptions().ca;
    const asRefused = function (pem, code) {
      return {
        authorized: false, authorizationError: { code: code },
        getPeerX509Certificate: function () {
          return new crypto.X509Certificate(pem);
        }
      };
    };
    const hiddenPurpose = asRefused(wrongSecond.certPem,
                                    'CERT_SIGNATURE_FAILURE');
    tlsServer.recogniseInstalledAnchor(hiddenPurpose, pems, 'issue-1242');
    t.equal(hiddenPurpose.authorized, false,
            'a purpose hidden behind CERT_SIGNATURE_FAILURE is asked again ' +
            'and refuses the promotion');
    const rightPurpose = asRefused(wrongFirst.certPem,
                                   'CERT_SIGNATURE_FAILURE');
    tlsServer.recogniseInstalledAnchor(rightPurpose, pems, 'issue-1242');
    t.equal(rightPurpose.authorized, true,
            'the same error on the anchor whose purpose allows it is ' +
            'promoted');
    const noIssuer = asRefused(wrongFirst.certPem,
                               'UNABLE_TO_VERIFY_LEAF_SIGNATURE');
    tlsServer.recogniseInstalledAnchor(noIssuer, pems, 'issue-1242');
    t.equal(noIssuer.authorized, false,
            'UNABLE_TO_VERIFY_LEAF_SIGNATURE is never promoted');

    t.log.info('=== an anchor that is not self-issued is not an ' +
               'identity ===');
    const addedLone = tlsServer.truststore.add(
      intermediate.cert + outsideLeaf.cert, { strict: true });
    t.equal(addedLone.added, 2,
            'the Intermediate and the outside end entity are kept alone');
    const seenIntermediate = await presented(listener, intermediate);
    t.equal(seenIntermediate.line, 'unverified',
            'an Intermediate installed without its Root is not verified ' +
            'when its holder presents it (' + seenIntermediate.error + ')');
    const seenOutside = await presented(listener, outsideLeaf);
    t.equal(seenOutside.line, 'unverified',
            'an outside authority\'s end entity installed alone is not ' +
            'verified (' + seenOutside.error + ')');
    t.check(!stsCrypto.certificateSelfSigned(intermediate.cert) &&
            !stsCrypto.certificateSelfSigned(outsideLeaf.cert),
            'neither is self-signed');
    const loneIntermediate = asRefused(intermediate.cert,
                                       'CERT_SIGNATURE_FAILURE');
    tlsServer.recogniseInstalledAnchor(loneIntermediate,
                                       tlsServer.clientTruststoreOptions().ca,
                                       'issue-1242');
    t.equal(loneIntermediate.authorized, false,
            'an anchor that is not self-signed is not promoted even on an ' +
            'error a collision produces');

    t.log.info('=== an end entity installed beside its issuer ===');
    const addedPair = tlsServer.truststore.add(
      pairCa.certPem + pairLeaf.cert, { strict: true });
    t.equal(addedPair.added, 2, 'the CA and its end entity are kept');
    const seenPair = await presented(listener, pairLeaf);
    t.equal(seenPair.line, 'verified',
            'the end entity verifies the ordinary way (' +
            seenPair.error + ')');
    t.equal(seenPair.issuer, fingerprintOf(pairCa.certPem),
            'and the chain the listener reports has its CA above it, not ' +
            'itself as its own issuer');
    const seenSelf = await presented(listener, {
      cert: second.certPem, key: second.privateKeyPem });
    t.equal(seenSelf.issuer, fingerprintOf(second.certPem),
            'a self-signed anchor is still reported as its own issuer');
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
  describe: 'two client-truststore anchors with one subject: each ' +
            'certificate verifies by its fingerprint, one it issued does ' +
            'not, a key-id rollover is not a collision, and neither a ' +
            'wrong purpose nor an anchor that is not self-issued is ' +
            'promoted (#1242)',
  run: run
};
