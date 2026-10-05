// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: pep_listener_certificate.js
//
// ===========================================================================
// A REMOTE XACML PEP'S HTTPS LISTENER CERTIFICATE (2026-09-13).
//
// The realm a PEP registered to certifies its HTTPS listener from a per-realm
// Issuing CA (`pep-tls`), hands the private key over once, and the container
// picks the pair up from two files. `tests/vendored/sts_xacml_remote_pep.js`
// drives that end to end against a real container; what is here is what no
// request can choose:
//
//   A. THE TOP-UP. A branch built before the use case existed — which is every
//      branch in a product-mode store the day this ships — gets the one
//      missing Issuing CA under its EXISTING Intermediate, and nothing already
//      issued is replaced or revoked. A rebuild would pass every other section
//      and revoke the realm's published signing chain on a restart.
//   B. THE CERTIFICATE, AND A REAL HANDSHAKE. serverAuth, not a CA, the names
//      asked for, the private key the certificate's, and a node TLS client
//      holding only the service Root completing a handshake against it by the
//      name in its subjectAltName — through this realm's own Intermediate.
//   C. THE REFUSALS: no slot, no name, a name that is not one, a key algorithm
//      a TLS stack does not serve.
//   D. A REISSUE SUPERSEDES, and the register keeps no private key.
//   E. THE NAMES A REGISTRATION IMPLIES (`xacml/xacml_pep_tls.ts`).
//
// THE CONTAINER'S RELOAD RULES were section F, in a child requiring the
// Node PEP. The PEP is a Rust binary since #444, and the same rules — a
// missing pair waits, halves that disagree are refused, a good pair starts
// the listener, the same bytes are no change, a bad pair never replaces a
// good one — are `rust/bins/xacml-pep/src/listener.rs`'s own test.
// ===========================================================================

// Deleted rather than set, for the reason `config_realm_layer.js` gives.
delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const tls = require('tls');

const REALM = 'peptls-a';

const log = require('bunyan').createLogger({ name: 'pep_listener_certificate',
  level: process.env.LOG_LEVEL || 'info' });

// One TLS handshake against `port`, trusting only `anchorPem`, asking for
// `servername`, and sending a GET for `/healthcheck`. Answers what the client
// saw: whether it was authorized, why not, the serial it was served, and the
// HTTP status line.
function handshake(port, anchorPem, servername) {
  log.debug("Entering handshake().");
  log.debug("Leaving handshake().");
  return new Promise(function (resolve) {
    const socket = tls.connect({ host: '127.0.0.1', port: port,
                                 servername: servername, ca: [anchorPem],
                                 rejectUnauthorized: false }, function () {
      const peer = socket.getPeerCertificate(true);
      const issuer = peer && peer.issuerCertificate
        ? peer.issuerCertificate : null;
      const seen = {
        authorized: socket.authorized,
        error: socket.authorizationError
          ? String(socket.authorizationError) : '',
        serialHex: String((peer && peer.serialNumber) || '').toLowerCase(),
        issuerCn: issuer && issuer.subject ? issuer.subject.CN : '',
        intermediateCn: issuer && issuer.issuerCertificate &&
                        issuer.issuerCertificate.subject
          ? issuer.issuerCertificate.subject.CN : '',
        identity: tls.checkServerIdentity(servername, peer) ? 'mismatch' : 'ok',
        status: ''
      };
      socket.write('GET /healthcheck HTTP/1.1\r\nHost: ' + servername +
                   '\r\nConnection: close\r\n\r\n');
      let text = '';
      socket.on('data', function (chunk) {
        text += chunk.toString('utf8');
      });
      socket.on('end', function () {
        seen.status = text.split('\r\n')[0] || '';
        resolve(seen);
      });
    });
    socket.on('error', function (e) {
      resolve({ authorized: false, error: e.message, serialHex: '' });
    });
  });
}

async function inProcess(t) {
  log.debug("Entering inProcess().");
  const keystore = require('../common/keystore');
  const pki = require('../common/pki');
  const helpers = require('../common/helpers');
  const realms = require('../common/realms');
  const revocation = require('../common/pki_revocation');
  const errorCodes = require('../common/error_codes');
  const pepTls = require('../xacml/xacml_pep_tls');

  await keystore.start();
  if (!realms.get(REALM)) {
    realms.create({ id: REALM, name: REALM });
  }
  await pki.start({ realmIds: ['', REALM],
    keySetFor: function (id) {
      log.debug("Entering keySetFor().");
      log.debug("Leaving keySetFor().");
      return helpers.stsKeysFor.of(id);
    },
    keySetHeldFor: function () {
      log.debug("Entering keySetHeldFor().");
      log.debug("Leaving keySetHeldFor().");
      return false;
    } });
  await pki.ensureScope(REALM);

  // -------------------------------------------------------------------------
  t.log.info('=== A. a branch built before the use case gets it added ===');
  // -------------------------------------------------------------------------
  t.check(pki.useCasesFor('realm').some(function (one) {
    return one.id === 'pep-tls';
  }), 'pep-tls is a REALM use case');
  const before = pki.rawRowFor(REALM);
  t.check(!!(before && before.issuing && before.issuing['pep-tls']),
          'a branch built now carries a pep-tls Issuing CA');
  // An OLDER branch, as a product-mode store holds it: the same row with the
  // use case missing.
  const older = Object.assign({}, before, {
    issuing: Object.assign({}, before.issuing)
  });
  delete older.issuing['pep-tls'];
  pki.saveRow(REALM, older);
  const intermediateSerial = before.intermediate.serialHex;
  const joseSerial = before.issuing.jose.serialHex;
  const revokedBefore = revocation.listFor(REALM, 'intermediate').length;
  const toppedUp = await pki.ensureScope(REALM);
  const after = pki.rawRowFor(REALM);
  t.check(toppedUp.ok && (toppedUp.toppedUp || []).indexOf('pep-tls') >= 0,
          'ensureScope() tops up a branch missing only a new use case',
          JSON.stringify({ ok: toppedUp.ok, toppedUp: toppedUp.toppedUp,
                           errors: toppedUp.errors }));
  t.equal(after.intermediate.serialHex, intermediateSerial,
          'the Intermediate is the one the branch already had — a rebuild ' +
          'would have replaced it and revoked every chain under it');
  t.equal(after.issuing.jose.serialHex, joseSerial,
          'and the JOSE Issuing CA beside it is untouched');
  t.check(!!after.issuing['pep-tls'] &&
          after.issuing['pep-tls'].serialHex !== intermediateSerial,
          'the missing Issuing CA is there now');
  t.equal(revocation.listFor(REALM, 'intermediate').length, revokedBefore,
          'and nothing was superseded to add it');
  t.check(/\(peptls-a\)/.test(after.issuing['pep-tls'].subject),
          'the added CA names its realm, as a built one does');
  const signed = new nodeCrypto.X509Certificate(
    after.issuing['pep-tls'].certificatePem)
    .verify(new nodeCrypto.X509Certificate(after.intermediate.certificatePem)
      .publicKey);
  t.check(signed, 'and it is signed by that realm\'s existing Intermediate');

  // -------------------------------------------------------------------------
  t.log.info('=== B. the certificate, and a real handshake against it ===');
  // -------------------------------------------------------------------------
  const first = await realms.run(realms.get(REALM), function () {
    log.debug("Entering the first issue.");
    log.debug("Leaving the first issue.");
    return pki.issueTlsServerKeyPair('', 'pep-tls', {
      slot: 'pep-one', dnsNames: ['pep-one.test'], ipAddresses: ['127.0.0.1']
    });
  });
  t.check(first.ok, 'a listener certificate is issued',
          JSON.stringify(first.errors || ''));
  const leaf = new nodeCrypto.X509Certificate(first.issued.certificatePem);
  t.check(!leaf.ca, 'it is not a certificate authority');
  t.check(/DNS:pep-one\.test/.test(leaf.subjectAltName) &&
          /IP Address:127\.0\.0\.1/.test(leaf.subjectAltName),
          'it names the DNS name and the IP address asked for',
          leaf.subjectAltName);
  t.equal((leaf.keyUsage || []).join(','), '1.3.6.1.5.5.7.3.1',
          'its extended key usage is serverAuth and nothing else');
  t.check(leaf.checkPrivateKey(nodeCrypto.createPrivateKey(
    first.issued.privateKeyPem)),
          'the private key handed back is the one it certifies');
  t.equal(first.issued.scope, REALM, 'it was issued in the ambient realm');
  t.equal(first.issued.anchorPem, pki.serviceRoot().certificatePem,
          'the anchor handed back is the service Root');

  const server = require('https').createServer({
    cert: [first.issued.certificatePem].concat(first.issued.chainPem)
      .join('\n'),
    key: first.issued.privateKeyPem
  }, function (req, res) {
    res.writeHead(200);
    res.end('ok');
  });
  await new Promise(function (resolve) {
    server.listen(0, '127.0.0.1', resolve);
  });
  try {
    const port = server.address().port;
    const good = await handshake(port, first.issued.anchorPem, 'pep-one.test');
    t.check(good.authorized, 'a client holding only the service Root ' +
            'completes a verified handshake', good.error);
    t.equal(good.identity, 'ok', 'and the name it dialled matches');
    t.check(/\(peptls-a\)/.test(good.intermediateCn || ''),
            'the path runs through THIS realm\'s Intermediate',
            good.intermediateCn);
    t.check(/Remote PEP TLS Issuing CA/.test(good.issuerCn || ''),
            'from the Remote PEP listeners Issuing CA', good.issuerCn);
    const wrong = await handshake(port, first.issued.anchorPem,
                                  'somebody-else.test');
    t.equal(wrong.identity, 'mismatch',
            'a name the certificate does not carry does not match');
    // The same handshake trusting the realm's INTERMEDIATE alone must not
    // verify: the chain is meant to end at the Root, and a pair that only
    // verified against the Intermediate would be a chain that stops short.
    const intermediateOnly = await handshake(
      port, before.intermediate.certificatePem, 'pep-one.test');
    t.check(!intermediateOnly.authorized,
            'trusting only the Intermediate does not verify — the path ends ' +
            'at the Root', intermediateOnly.error);
  } finally {
    server.close();
  }

  // -------------------------------------------------------------------------
  t.log.info('=== C. the refusals ===');
  // -------------------------------------------------------------------------
  const refusals = [
    [{ dnsNames: ['a.test'] }, 'STS-PKI-0165', 'no slot'],
    [{ slot: 'x' }, 'STS-PKI-0166', 'no name at all'],
    [{ slot: 'x', dnsNames: ['under_score.test'] }, 'STS-PKI-0166',
     'a name that is not a DNS name'],
    [{ slot: 'x', ipAddresses: ['300.1.1.1'] }, 'STS-PKI-0166',
     'an address that is not one'],
    [{ slot: 'x', dnsNames: ['a.test'], keyAlg: 'ed25519' }, 'STS-PKI-0167',
     'a key algorithm TLS listeners are not issued with']
  ];
  for (let i = 0; i < refusals.length; i++) {
    const r = await realms.run(realms.get(REALM), function () {
      log.debug("Entering a refusal.");
      log.debug("Leaving a refusal.");
      return pki.issueTlsServerKeyPair('', 'pep-tls', refusals[i][0]);
    });
    t.check(!r.ok && errorCodes.codeOf(r) === refusals[i][1],
            'refused: ' + refusals[i][2],
            JSON.stringify({ ok: r.ok, code: errorCodes.codeOf(r) }));
  }
  const wildcard = await realms.run(realms.get(REALM), function () {
    log.debug("Entering the wildcard issue.");
    log.debug("Leaving the wildcard issue.");
    return pki.issueTlsServerKeyPair('', 'pep-tls', {
      slot: 'pep-wild', dnsNames: ['*.peps.test'], keyAlg: 'rsa-2048' });
  });
  t.check(wildcard.ok, 'a leading wildcard and an RSA key are accepted',
          JSON.stringify(wildcard.errors || ''));

  // -------------------------------------------------------------------------
  t.log.info('=== D. a reissue supersedes, and no key is kept ===');
  // -------------------------------------------------------------------------
  const second = await realms.run(realms.get(REALM), function () {
    log.debug("Entering the second issue.");
    log.debug("Leaving the second issue.");
    return pki.issueTlsServerKeyPair('', 'pep-tls', {
      slot: 'pep-one', dnsNames: ['pep-one.test'] });
  });
  t.check(second.ok && second.issued.replacedSerialHex ===
          first.issued.serialHex,
          'the reissue names the certificate it replaces');
  const listed = revocation.isRevoked(REALM, 'pep-tls',
                                      first.issued.serialHex);
  t.check(!!listed && listed.reason === 'superseded',
          'and that certificate is on the issuer\'s list as superseded',
          JSON.stringify(listed));
  const held = pki.certificateFor(REALM, 'pep-tls', 'pep-one');
  t.equal(held.serialHex, second.issued.serialHex,
          'the register holds the new certificate under the slot');
  t.check(!held.privateKeyPem && JSON.stringify(pki.rawRowFor(REALM))
          .indexOf(second.issued.privateKeyPem.split('\n')[1]) < 0,
          'and no copy of the private key anywhere in the realm\'s row');

  // -------------------------------------------------------------------------
  t.log.info('=== E. the names a registration implies ===');
  // -------------------------------------------------------------------------
  const byName = pepTls.derivedNames({ name: 'remote-pep-1',
    notifyUrl: 'http://xacml-pep:9090/notify' });
  t.equal(byName.dnsNames.join(','), 'remote-pep-1,xacml-pep',
          'the registered name and the notify host are DNS names');
  const byIp = pepTls.derivedNames({ name: 'CN-odd_name',
    notifyUrl: 'http://[::1]:9090/notify' });
  t.equal(byIp.dnsNames.length + ':' + byIp.ipAddresses.join(','), '0:::1',
          'an IPv6 notify host is an IP name, and a non-DNS PEP name is ' +
          'left out');
  t.equal(pepTls.derivedNames({ name: 'p', notifyUrl: 'not a url' })
            .dnsNames.join(','), 'p',
          'a notify URL that will not parse names no host');
  t.equal(pepTls.listFrom('a.test, b.test\nc.test').join('|'),
          'a.test|b.test|c.test', 'a typed list splits on commas and lines');

  log.debug("Leaving inProcess().");
  return { first: first.issued, second: second.issued };
}

// ---------------------------------------------------------------------------
// THE CERTIFICATE AUTHORITY THIS FILE FINDS IS THE ONE IT LEAVES, for
// `tests/application_credentials.js`'s reason: `run.js` runs every file in ONE
// process, and a service Root built here is the Root `tests/pki.js` meets when
// it asks for one with an organisation of its own — which it then does not
// carry. Measured: that assertion failed with this file before it and passed
// without. What was absent on the way in is removed on the way out.
// ---------------------------------------------------------------------------
function heldAuthority() {
  log.debug("Entering heldAuthority().");
  const keystore = require('../common/keystore');
  const pki = require('../common/pki');
  log.debug("Leaving heldAuthority().");
  return { root: !!keystore.pkiFor(pki.SERVICE_SCOPE),
           process: !!keystore.pkiFor(pki.PROCESS_SCOPE),
           chain: pki.hasChain() };
}

function restoreAuthority(before) {
  log.debug("Entering restoreAuthority().");
  const keystore = require('../common/keystore');
  const pki = require('../common/pki');
  if (!before.chain && pki.hasChain()) {
    pki.clearChain(undefined);
  }
  if (!before.process && keystore.pkiFor(pki.PROCESS_SCOPE)) {
    keystore.attachPki(pki.PROCESS_SCOPE, null);
  }
  if (!before.root && keystore.pkiFor(pki.SERVICE_SCOPE)) {
    keystore.attachPki(pki.SERVICE_SCOPE, null);
  }
  log.debug("Leaving restoreAuthority().");
}

async function run(t) {
  log.debug("Entering run().");
  const before = heldAuthority();
  try {
    await inProcess(t);
  } finally {
    // `realm_isolation.js` asserts only the default realm is left.
    const realms = require('../common/realms');
    if (realms.get(REALM)) {
      realms.remove(REALM);
    }
    restoreAuthority(before);
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'pep_listener_certificate',
  describe: 'A remote PEP\'s HTTPS listener certificate: a branch topped up ' +
            'rather than rebuilt, a serverAuth leaf a Root-only client ' +
            'verifies through its realm\'s Intermediate, the refusals, a ' +
            'reissue superseding',
  run: run
};
