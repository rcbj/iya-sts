'use strict';
//
// File: tls_handshake_alerts.js
//
// ===========================================================================
// WHICH SIDE BROKE A HANDSHAKE (2026-09-26, #225).
//
// rcbj's Chrome refused this service's certificate and the log said "this is
// the handshake itself rather than a certificate being refused" — the wrong
// way round. `tls/tls_server.js`'s handshakeFailureOf() now reads the alert
// the CLIENT sent. This file holds it to:
//
//   A. the exact error #225 logged (certificate_unknown, 46, received) — a
//      client refusing the certificate — and node's code form of unknown_ca;
//   B. errors that are NOT a refused certificate — an alert the client sent
//      about something else, and a handshake with no alert at all;
//   C. a REAL handshake: a client that does not trust a server's certificate
//      refuses it, and the error node hands the server's `tlsClientError` is
//      classified as the peer refusing the certificate — the reading of
//      OpenSSL's text is checked against OpenSSL, not against a string
//      written here.
//
// In process because the classification is a pure function and the real
// handshake needs a listener this file owns, on a loopback port.
// ===========================================================================

delete process.env.CONFIG_FILE;

const tls = require('tls');
const log = require('bunyan').createLogger({ name: 'tls_handshake_alerts',
  level: process.env.LOG_LEVEL || 'info' });

async function run(t) {
  log.debug("Entering run().");
  const tlsServer = require('../tls/tls_server');
  const stsCrypto = require('../common/crypto');
  const classify = tlsServer.handshakeFailureOf;

  t.log.info('=== A. a client refusing the certificate ===');
  // The line #225 carried, verbatim.
  const fromIssue = new Error('40FEFBC6557F0000:error:0A000416:SSL ' +
    'routines:ssl3_read_bytes:ssl/tls alert certificate unknown:' +
    '../deps/openssl/openssl/ssl/record/rec_layer_s3.c:918:SSL alert ' +
    'number 46\n');
  const issue = classify(fromIssue);
  t.check(issue.kind === 'peer-refused-certificate' && issue.alert === 46 &&
          issue.alertName === 'certificate_unknown',
          'the error #225 logged is the CLIENT refusing the certificate ' +
          '(certificate_unknown, 46)', JSON.stringify(issue));
  const unknownCa = Object.assign(new Error('tlsv1 alert unknown ca'),
                                  { code: 'ERR_SSL_TLSV1_ALERT_UNKNOWN_CA' });
  t.equal(classify(unknownCa).alertName, 'unknown_ca',
          'and node\'s code form of unknown_ca (48) is read too');

  t.log.info('=== B. failures that are not a refused certificate ===');
  const otherAlert = new Error('0A000410:SSL routines:ssl3_read_bytes:' +
    'sslv3 alert handshake failure:rec_layer_s3.c:918:SSL alert number 40');
  t.equal(classify(otherAlert).kind, 'handshake',
          'an alert about something else (handshake_failure, 40) is a ' +
          'handshake failure, not a refused certificate');
  const noAlert = new Error('0A00010B:SSL routines:ssl3_get_record:' +
                            'wrong version number');
  t.equal(classify(noAlert).kind, 'handshake',
          'and so is a client not speaking TLS, which sends no alert');
  t.equal(classify(null).kind, 'handshake', 'and nothing at all');

  t.log.info('=== C. a real client refusing a real certificate ===');
  const made = stsCrypto.selfSignedRsaCertificate({ bits: 2048,
                                                    commonName: 'localhost' });
  const server = tls.createServer({ key: made.privateKeyPem,
                                    cert: made.certPem });
  const seen = new Promise(function (resolve) {
    server.on('tlsClientError', function (error) {
      resolve(error);
    });
  });
  await new Promise(function (resolve) {
    server.listen(0, '127.0.0.1', resolve);
  });
  const port = server.address().port;
  // AN OPENSSL CLIENT, not node's. node's TLS client verifies the peer AFTER
  // the handshake and drops the socket without an alert, which reaches the
  // server as "socket hang up" — the first version of this section found
  // that. A browser (BoringSSL) and OpenSSL's own client refuse DURING the
  // handshake and send the alert, which is what #225 saw. `-CAfile` names an
  // UNRELATED certificate: OpenSSL refuses an empty CA file before it
  // connects at all, which the second version of this section found.
  const emptyStore = require('path').join(require('os').tmpdir(),
    'tls-handshake-alerts-' + process.pid + '.pem');
  require('fs').writeFileSync(emptyStore, stsCrypto.selfSignedRsaCertificate(
    { bits: 2048, commonName: 'unrelated' }).certPem);
  const client = require('child_process').spawn('openssl',
    ['s_client', '-connect', '127.0.0.1:' + port, '-servername', 'localhost',
     '-verify_return_error', '-CAfile', emptyStore],
    { stdio: ['pipe', 'ignore', 'ignore'] });
  client.on('error', function (e) {
    log.debug("Caught in the probe client: " + ((e && e.message) || e));
    // Reported below as "no tlsClientError".
  });
  client.stdin.end();
  const serverError = await Promise.race([seen, new Promise(
    function (resolve) { setTimeout(resolve, 15000); })]);
  client.kill();
  require('fs').rmSync(emptyStore, { force: true });
  await new Promise(function (resolve) { server.close(resolve); });
  const real = classify(serverError);
  t.check(!!serverError && real.kind === 'peer-refused-certificate',
          'the error node gives the SERVER when a client refuses its ' +
          'certificate is classified as exactly that (' +
          (real.alertName || 'none') + ')',
          serverError ? String(serverError.message) : 'no tlsClientError');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'tls_handshake_alerts',
  describe: 'Which side broke a TLS handshake (#225): the error #225 logged ' +
            'is the client refusing this service\'s certificate; other ' +
            'alerts and no alert are handshake failures; and a real client ' +
            'refusing a real certificate is classified as that',
  run: run
};
