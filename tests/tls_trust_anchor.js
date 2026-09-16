'use strict';
//
// File: tls_trust_anchor.js
//
// ===========================================================================
// WHAT A CALLER PINS THIS SERVICE AGAINST, AND WHY IT STOPPED BEING THE
// CERTIFICATE (2026-09-11).
//
// On the day every key pair this service generates became a LEAF of its own
// Root, three callers in this repository broke at once and none of them said
// so in words that named the change:
//
//   * `common/oidc_rp.js`'s back channel, which is how `/admin` and `/portal`
//     redeem an authorization code. The console reported it as **Signing in
//     did not complete**, and underneath it was `unable to get local issuer
//     certificate`.
//   * `ssf/ssf_http.ts`'s loopback push to this service's own two receivers.
//   * `tests/tools/trust.js`, which fetches `/tls/server-certificate` and
//     hands it to every node-driven job as `NODE_EXTRA_CA_CERTS` — so the
//     protocol half of the suite could not open a connection at all.
//
// All three pinned `serverCertificate().certPem`, and all three were RIGHT to
// while that certificate was self-signed: OpenSSL takes a self-signed leaf
// found in a truststore as an anchor. It will not take a CERTIFIED one — the
// path walks up to the Intermediate, finds no Root, and fails at depth 2 about
// a certificate the caller was never given.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS, WHICH IS THE QUESTION tests/CLAUDE.md ASKS FIRST.
//
// Because the claim is about the BEFORE and the AFTER of `pki.start()`, and
// choosing how the process was started is this directory's rule. A running
// service has already certified its listener; nothing it serves can be asked
// what the pin looked like an instant earlier, and the whole defect lives in
// that transition.
//
// And because the assertion that matters is a HANDSHAKE rather than a field.
// Every version of this that compares subjects and issuers passes on a
// truststore OpenSSL would refuse — which is exactly the state this service
// was in for the hours the console could not be signed into. So the two
// sections below build a real TLS connection on an ephemeral port and let
// OpenSSL answer.
// ===========================================================================

// Deleted rather than set, for the reason config_realm_layer.js gives: this
// file must not inherit a CONFIG_FILE from whatever launched the run.
delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const fs = require('fs');
const nodeCrypto = require('crypto');
const os = require('os');
const path = require('path');
const tls = require('tls');

const keystore = require('../common/keystore');
const pki = require('../common/pki');
const tlsServer = require('../tls/tls_server');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'tls_trust_anchor',
  level: process.env.LOG_LEVEL || 'info' });

// ---------------------------------------------------------------------------
// ONE HANDSHAKE, ANSWERED BY OpenSSL.
//
// The server presents what `secureContextOptions()` builds — the leaf and the
// chain it travels with — and the client trusts exactly the one PEM it is
// handed, with the hostname check off, which is the shape of both loopback
// pins in this repository. It resolves to `''` on success and to the error
// CODE on failure, because the code is the thing worth asserting: an assertion
// on a message would pass on the wrong failure.
// ---------------------------------------------------------------------------
function handshake(certPem, keyPem, anchorPem) {
  log.debug("Entering handshake().");
  log.debug("Leaving handshake().");
  return new Promise(function (resolve) {
    const server = tls.createServer({ cert: certPem, key: keyPem },
      function (socket) {
        socket.end();
      });
    server.listen(0, '127.0.0.1', function () {
      const socket = tls.connect({
        host: '127.0.0.1',
        port: server.address().port,
        ca: [anchorPem],
        checkServerIdentity: function () {
          log.debug("Entering checkServerIdentity().");
          log.debug("Leaving checkServerIdentity().");
          return undefined;
        }
      }, function () {
        socket.destroy();
        server.close(function () { resolve(''); });
      });
      socket.on('error', function (e) {
        socket.destroy();
        server.close(function () { resolve(e.code || e.message); });
      });
    });
  });
}

// The whole bundle a listener presents: leaf first, then what it travels with.
function presented(record) {
  log.debug("Entering presented().");
  log.debug("Leaving presented().");
  return (record.chainPem && record.chainPem.length)
    ? [record.certPem].concat(record.chainPem).join('')
    : record.certPem;
}

// SUBJECT, ISSUER AND THE SIGNATURE — not `checkIssued()`, which answers NO
// for the self-signed listener certificate: node asks whether the supposed
// issuer is a CA, and this one carries `basicConstraints CA:FALSE`. That is the
// same quirk tests/tools/trust.js has a paragraph about, and the reason the
// leaf worked as an anchor at all is that OpenSSL's truststore lookup does not
// ask.
function isSelfSigned(pem) {
  log.debug("Entering isSelfSigned().");
  const cert = new nodeCrypto.X509Certificate(pem);
  log.debug("Leaving isSelfSigned().");
  return cert.subject === cert.issuer && cert.verify(cert.publicKey);
}

// ---------------------------------------------------------------------------
// WHAT A PROCESS THAT HAS NOT BUILT A HIERARCHY HOLDS.
//
// The child writes its answer to a FILE rather than to stdout, because this
// service logs to stdout from the moment `common/config.js` loads and the
// result would arrive interleaved with a startup banner.
// ---------------------------------------------------------------------------
function freshProcessCertificate() {
  log.debug("Entering freshProcessCertificate().");
  const out = path.join(os.tmpdir(),
                        'sts-trust-anchor-' + process.pid + '.json');
  const script =
    'delete process.env.CONFIG_FILE;' +
    'const one = require(' + JSON.stringify(path.join(__dirname, '..', 'tls',
                                                      'tls_server')) + ')' +
    '.serverCertificate();' +
    'require("fs").writeFileSync(' + JSON.stringify(out) + ', ' +
    'JSON.stringify({ certPem: one.certPem, privateKeyPem: one.privateKeyPem,' +
    ' chainLength: one.chainPem.length,' +
    ' anchorIsCertificate: one.trustAnchorPem === one.certPem }));';
  try {
    childProcess.execFileSync(process.execPath, ['-e', script],
                              { stdio: 'ignore', timeout: 60000 });
    log.debug("Leaving freshProcessCertificate().");
    return JSON.parse(fs.readFileSync(out, 'utf8'));
  } finally {
    try {
      fs.unlinkSync(out);
    } catch (e) {
      // The temporary file is gone or was never written; the read above has
      // already decided whether this section can run.
      log.debug("Caught in freshProcessCertificate(): " +
                ((e && e.message) || e));
    }
  }
}

async function run(t) {
  log.debug("Entering run().");
  // -----------------------------------------------------------------------
  // 1. BEFORE `pki.start()`: the certificate IS the anchor, and that is the
  //    state every process that never builds a hierarchy stays in — `npm
  //    test`, and any service running on a supplied `tls.certificateFile`.
  //    The pin must keep working there, which is why the anchor is asked for
  //    rather than switched to the Root unconditionally.
  //
  //    **IN A CHILD PROCESS, AND THAT IS NOT FASTIDIOUSNESS.** `tests/run.js`
  //    runs every file in ONE process, and `tests/pki_hierarchy.js` builds the
  //    hierarchy — so by the time this file runs under `npm test` the listener
  //    certificate has already been certified and the "before" state is gone.
  //    Read in this process it passed alone and failed in the suite, which is
  //    the shape of flake that gets a test deleted rather than fixed. A child
  //    is the only way to ask what a fresh process holds.
  // -----------------------------------------------------------------------
  t.log.info('=== before pki.start(): a self-signed leaf is its own anchor ' +
             '===');
  const before = freshProcessCertificate();
  t.check(isSelfSigned(before.certPem),
          'the certificate a fresh process builds at require time is ' +
          'self-signed');
  t.equal(before.chainLength, 0,
          'so it travels with no chain');
  t.check(before.anchorIsCertificate,
          'and the anchor a caller pins IS that certificate — which is why ' +
          'pinning the certificate was right for as long as it was');
  t.equal(await handshake(before.certPem, before.privateKeyPem,
                          before.certPem), '',
          'a connection pinned to it verifies');

  // -----------------------------------------------------------------------
  // 2. AFTER IT: the certificate is a leaf and the anchor is the Root.
  // -----------------------------------------------------------------------
  t.log.info('=== after pki.start(): the leaf is NOT the anchor ===');
  await keystore.start();
  const started = await pki.start({ realmIds: [] });
  t.check(started.ok, 'pki.start() builds the hierarchy',
          JSON.stringify(started));

  const after = tlsServer.serverCertificate();
  t.check(!isSelfSigned(after.certPem),
          'the listener certificate is now issued by this service\'s own TLS ' +
          'Issuing CA — which is what changed underneath all three callers');
  t.check(after.chainPem.length > 0,
          'and it travels with the chain between it and the Root',
          after.chainPem.length + ' certificate(s)');
  t.check(isSelfSigned(after.trustAnchorPem),
          'THE ANCHOR IS SELF-SIGNED. This is the invariant the three pins ' +
          'were relying on without saying so, and it is the one that has to ' +
          'hold in both states rather than the anchor being any particular ' +
          'certificate');
  t.check(nodeCrypto.createHash('sha256')
            .update(new nodeCrypto.X509Certificate(after.trustAnchorPem).raw)
            .digest('hex') ===
          nodeCrypto.createHash('sha256')
            .update(new nodeCrypto.X509Certificate(
              pki.trustAnchorsFor(null)[0] ||
              pki.serviceRoot().certificatePem).raw)
            .digest('hex'),
          'and it is the service Root rather than a second copy of anything');

  // -----------------------------------------------------------------------
  // 3. THE DEFECT ITSELF, asserted as the failure it actually produced.
  //    Pinning the certificate is not merely weaker now — it refuses every
  //    connection, which is worse than no pin because it looks like one.
  // -----------------------------------------------------------------------
  t.log.info('=== pinning the CERTIFICATE refuses every connection ===');
  t.equal(await handshake(presented(after), after.privateKeyPem,
                          after.certPem),
          'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
          'a caller pinning the leaf gets exactly the error the admin ' +
          'console reported as "Signing in did not complete"');
  t.equal(await handshake(presented(after), after.privateKeyPem,
                          after.trustAnchorPem), '',
          'and a caller pinning the ANCHOR verifies — the chain the ' +
          'certificate travels with is what makes the path terminate');

  // -----------------------------------------------------------------------
  // 4. AND THE THREE CALL SITES ASK FOR THE ANCHOR.
  //
  //    A source check rather than a behavioural one, for `tests/version.js`'s
  //    reason: what went wrong was not a wrong value but the wrong FIELD being
  //    read, and a test that drove the flow would pass on a fourth caller
  //    added tomorrow that reads `certPem` again.
  // -----------------------------------------------------------------------
  t.log.info('=== the loopback pins read trustAnchorPem ===');
  const fs = require('fs');
  const path = require('path');
  [['common/oidc_rp.js',
    'the back channel /admin and /portal redeem a code on'],
   ['ssf/ssf_http.ts', 'the loopback push to this service\'s own receivers']
  ].forEach(function (pair) {
    const src = fs.readFileSync(path.join(__dirname, '..', pair[0]), 'utf8');
    // The comments in both files name `certPem` while explaining why they
    // stopped reading it, so the check is on the CALL and not on the word.
    t.check(src.indexOf('serverCertificate().certPem') < 0,
            pair[0] + ' does not pin the certificate — ' + pair[1]);
    t.check(src.indexOf('serverCertificate().trustAnchorPem') > 0,
            pair[0] + ' pins the anchor');
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'tls trust anchor',
  describe: 'what a loopback caller pins this service against, before and ' +
            'after its certificate acquires an issuer',
  run: run
};
