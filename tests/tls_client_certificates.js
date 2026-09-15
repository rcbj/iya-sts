'use strict';
//
// File: tls_client_certificates.js
//
// ===========================================================================
// A PERSON'S TLS CLIENT CERTIFICATE, AND THE GATE THAT MAKES TRUSTING THE
// SERVICE ROOT SAFE (2026-09-13).
//
// `/portal/signing-key` issues a TLS client certificate from the realm's
// `tls-client` Issuing CA, and the TLS listeners trust the service Root so that
// it verifies. `common/tls_client_certificates.js` is what stops that Root
// from turning EVERY key pair this service issued into a sign-in. What is here
// is what no request to the portal can show on its own:
//
//   A. THE CERTIFICATE: clientAuth, the person's CN and urn:sts:person: name,
//      the rfc822Name, issued by THIS realm's TLS Client Issuing CA, the key
//      the certificate's, and the refusals (key algorithm, label, the cap).
//   B. THE FILES: a PKCS#12 OpenSSL opens with the password and whose leaf is
//      the certificate, and an encrypted PEM key that opens with the same
//      password and holds the certificate's key.
//   C. THE GATE, in process: a TLS client leaf is an identity in its realm; an
//      RFC 7523 person key pair — same Root, same realm, same person — is not;
//      an unverified chain is not this module's business; another realm's
//      certificate is refused at a main-port door; `mtls.peerVerified()` says
//      the same thing.
//   D. THE LISTENERS, over a real handshake: the Root is in the client
//      truststore; 9443 signs the TLS client certificate's holder in, IN ITS
//      REALM; the assertion key pair gets a 403 and no session on 9443 and no
//      session on 8443; a revocation by somebody else is refused and one by the
//      holder makes 9443 refuse the certificate.
//
// ALL OF IT RUNS IN ONE CHILD PROCESS, for `tests/revocation_status.js`'s
// reason: the listeners read their ports at require time, and the certificate
// authority, the realm and the revocation register are process state another
// file in `run.js`'s single process would otherwise inherit.
//
// MUTATION-TESTED, and the first round is why section C has three fixtures
// that each break ONE rule. Nine mutants: the use-case check, the clientAuth
// check, the CN-equals-SAN check, the realm comparison at a main-port door,
// the Root in the truststore, the realm the listener runs in, and the strict
// listener's 403 all go red — but the use-case, clientAuth and CN checks
// SURVIVED at first, because the only refused fixture was an assertion key
// pair failing two rules at once, so deleting either left the other refusing
// it.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const fs = require('fs');
const https = require('https');
const nodeCrypto = require('crypto');
const os = require('os');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const CHILD_FLAG = 'STS_TLS_CLIENT_CERT_CHILD';
const REALM = 'tlsclient-a';
const PERSON = 'tlsalice';
const PASSWORD = 'correct horse battery';

const log = require('bunyan').createLogger({ name: 'tls_client_certificates',
  level: process.env.LOG_LEVEL || 'info' });

// A recording harness: the child cannot reach the parent's `t`, so it keeps
// every assertion and hands the list back.
function recorder() {
  log.debug("Entering recorder().");
  const rows = [];
  log.debug("Leaving recorder().");
  return {
    rows: rows,
    check: function (ok, what, detail) {
      log.debug("Entering check().");
      rows.push({ ok: !!ok, what: what,
                  detail: detail === undefined ? '' : String(detail) });
      log.debug("Leaving check().");
    }
  };
}

function ask(port, cert, key) {
  log.debug("Entering ask().");
  log.debug("Leaving ask().");
  return new Promise(function (resolve) {
    const req = https.request({ host: '127.0.0.1', port: port,
      path: '/tls/whoami', method: 'GET', cert: cert, key: key,
      rejectUnauthorized: false, agent: false }, function (res) {
      let text = '';
      res.on('data', function (c) { text += c; });
      res.on('end', function () {
        let body = {};
        try {
          body = JSON.parse(text);
        } catch (e) {
          log.debug("Caught in a callback in ask(): " +
                    ((e && e.message) || e));
          body = { raw: text.slice(0, 300) };
        }
        resolve({ status: res.statusCode, body: body });
      });
    });
    req.on('error', function (e) {
      resolve({ status: 0, body: { error: e.message } });
    });
    req.end();
  });
}

function hasOpenssl() {
  log.debug("Entering hasOpenssl().");
  try {
    childProcess.execFileSync('openssl', ['version'], { stdio: 'pipe' });
    log.debug("Leaving hasOpenssl(). Yes.");
    return true;
  } catch (e) {
    log.debug("Caught in hasOpenssl(): " + ((e && e.message) || e));
    log.debug("Leaving hasOpenssl(). No.");
    return false;
  }
}

// A socket-shaped object for the doors that read one: what
// `revocation_status.fromSocket()` needs, and nothing else.
function fakeSocket(certPem, chainPems, authorized) {
  log.debug("Entering fakeSocket().");
  const der = new nodeCrypto.X509Certificate(certPem).raw;
  log.debug("Leaving fakeSocket().");
  return {
    authorized: authorized,
    getPeerCertificate: function () {
      return { raw: der, subject: { CN: PERSON },
               issuerChain: (chainPems || []).map(function (pem) {
                 return new nodeCrypto.X509Certificate(pem).raw
                   .toString('base64');
               }) };
    }
  };
}

async function childBody() {
  log.debug("Entering childBody().");
  const t = recorder();
  const keystore = require('../common/keystore');
  const pki = require('../common/pki');
  const helpers = require('../common/helpers');
  const realms = require('../common/realms');
  const config = require('../common/config');
  const errorCodes = require('../common/error_codes');
  const tlsClient = require('../common/tls_client_certificates');

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
  const inRealm = function (fn) {
    log.debug("Entering inRealm().");
    log.debug("Leaving inRealm().");
    return realms.run(realms.get(REALM), fn);
  };

  // -------------------------------------------------------------------------
  // A. THE CERTIFICATE
  // -------------------------------------------------------------------------
  t.check(pki.useCasesFor('realm').some(function (one) {
    return one.id === 'tls-client';
  }), 'A: tls-client is a REALM use case');
  const made = await inRealm(function () {
    return tlsClient.issue(undefined, { username: PERSON, label: 'laptop',
                                        keyAlg: 'ec-p256',
                                        email: 'alice@example.com' });
  });
  t.check(made.ok, 'A: a TLS client certificate is issued',
          JSON.stringify(made.errors || ''));
  const issued = made.issued;
  const leaf = new nodeCrypto.X509Certificate(issued.certificatePem);
  t.check((leaf.keyUsage || []).indexOf('1.3.6.1.5.5.7.3.2') >= 0,
          'A: it carries clientAuth', JSON.stringify(leaf.keyUsage));
  t.check((leaf.keyUsage || []).indexOf('1.3.6.1.5.5.7.3.1') < 0,
          'A: and not serverAuth');
  t.check(/(^|\n)CN=tlsalice(\n|$)/.test(leaf.subject),
          'A: its CN is the person', leaf.subject);
  t.check(String(leaf.subjectAltName).indexOf('URI:urn:sts:person:tlsalice') >=
          0 && String(leaf.subjectAltName).indexOf('alice@example.com') >= 0,
          'A: its subjectAltName names the person and their mail',
          leaf.subjectAltName);
  t.check(!leaf.ca, 'A: it is not a certificate authority');
  const issuing = pki.rawRowFor(REALM).issuing['tls-client'];
  t.check(leaf.verify(new nodeCrypto.X509Certificate(issuing.certificatePem)
    .publicKey), 'A: it was signed by THIS realm\'s TLS Client Issuing CA');
  t.check(issued.chainPem.length === 2 &&
          issued.chainPem[0] === issuing.certificatePem,
          'A: the chain is the Issuing CA then the Intermediate, no Root');
  t.check(nodeCrypto.createPublicKey(issued.privateKeyPem)
            .export({ type: 'spki', format: 'der' })
            .equals(leaf.publicKey.export({ type: 'spki', format: 'der' })),
          'A: the private key handed back is the certificate\'s');
  const stored = pki.certificatesFor(REALM, 'tls-client');
  t.check(stored.length === 1 && !stored[0].privateKeyPem,
          'A: the register holds the certificate and no private key');
  const listed = tlsClient.listFor(REALM, PERSON);
  t.check(listed.length === 1 && listed[0].state === 'valid',
          'A: the person\'s list holds it, valid', JSON.stringify(listed));
  t.check(tlsClient.listFor(REALM, 'bob').length === 0,
          'A: nobody else\'s list does');
  const badAlg = await inRealm(function () {
    return tlsClient.issue(undefined, { username: PERSON, keyAlg: 'ed25519' });
  });
  t.check(!badAlg.ok && errorCodes.codeOf(badAlg) === 'STS-PKI-0169',
          'A: a key algorithm a browser does not present is refused');
  const badLabel = await inRealm(function () {
    return tlsClient.issue(undefined, { username: PERSON,
                                        label: '<script>' });
  });
  t.check(!badLabel.ok && errorCodes.codeOf(badLabel) === 'STS-PKI-0169',
          'A: a label that is not a short name is refused');
  config.setOverride('pki.personTlsClientCertificateMax', '1');
  const capped = await inRealm(function () {
    return tlsClient.issue(undefined, { username: PERSON });
  });
  t.check(!capped.ok && errorCodes.codeOf(capped) === 'STS-PKI-0170',
          'A: the cap refuses a second valid certificate',
          JSON.stringify(capped.errors));
  config.clearOverride('pki.personTlsClientCertificateMax');

  // -------------------------------------------------------------------------
  // B. THE FILES
  // -------------------------------------------------------------------------
  const files = await tlsClient.bundle(issued, PASSWORD);
  t.check(/\.p12$/.test(files.pkcs12.name) && files.pkcs12.base64.length > 100,
          'B: a PKCS#12 is built', files.pkcs12.name);
  const opened = nodeCrypto.createPrivateKey({ key: files.key.text,
                                               format: 'pem',
                                               passphrase: PASSWORD });
  t.check(/ENCRYPTED PRIVATE KEY/.test(files.key.text) &&
          nodeCrypto.createPublicKey(opened).export({ type: 'spki',
                                                      format: 'der' })
            .equals(leaf.publicKey.export({ type: 'spki', format: 'der' })),
          'B: the PEM key is encrypted and opens with the file password');
  t.check(files.chain.text.split('BEGIN CERTIFICATE').length - 1 === 3,
          'B: the chain file holds the leaf and its two issuers');
  t.check(tlsClient.pkcs12PasswordProblem('short') !== '' &&
          tlsClient.pkcs12PasswordProblem(PASSWORD, 'other') !== '' &&
          tlsClient.pkcs12PasswordProblem(PASSWORD, PASSWORD) === '',
          'B: a short or mismatched file password is refused');
  if (hasOpenssl()) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tls-client-p12-'));
    const p12Path = path.join(dir, 'client.p12');
    fs.writeFileSync(p12Path, Buffer.from(files.pkcs12.base64, 'base64'));
    let text = '';
    try {
      text = childProcess.execFileSync('openssl', ['pkcs12', '-in', p12Path,
        '-passin', 'pass:' + PASSWORD, '-nokeys', '-clcerts'],
        { stdio: 'pipe', encoding: 'utf8' });
    } catch (e) {
      text = 'openssl refused: ' + String(e.stderr || e.message);
    }
    fs.rmSync(dir, { recursive: true, force: true });
    const inside = (/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/
      .exec(text) || [''])[0];
    t.check(inside && new nodeCrypto.X509Certificate(inside).fingerprint256 ===
            leaf.fingerprint256,
            'B: OpenSSL opens the PKCS#12 with the password and its client ' +
            'certificate is the one issued', text.slice(0, 200));
  }

  // -------------------------------------------------------------------------
  // C. THE GATE
  // -------------------------------------------------------------------------
  const asInput = function (pem, chain, verified) {
    log.debug("Entering asInput().");
    log.debug("Leaving asInput().");
    return { leaf: new nodeCrypto.X509Certificate(pem).raw,
             chain: (chain || []).map(function (one) {
               return new nodeCrypto.X509Certificate(one).raw;
             }),
             verified: verified };
  };
  const accepted = tlsClient.identityOf(asInput(issued.certificatePem,
                                                issued.chainPem, true));
  t.check(accepted.issuedHere && accepted.accepted &&
          accepted.realm === REALM && accepted.username === PERSON &&
          accepted.kind === 'person',
          'C: the TLS client certificate is an identity, in its realm',
          JSON.stringify(accepted));
  const leafOnly = tlsClient.identityOf(asInput(issued.certificatePem, [],
                                                true));
  t.check(leafOnly.accepted,
          'C: and so is the leaf presented without its chain, which is what ' +
          'a browser commonly sends');
  const assertion = await pki.issueSigningKeyPair(REALM, {
    identifier: PERSON, purpose: 'jwt', subjectKind: 'person',
    commonName: PERSON });
  t.check(assertion.ok, 'C: an RFC 7523 key pair is issued to the same person');
  const refused = tlsClient.identityOf(asInput(
    assertion.issued.certificatePem, assertion.issued.chainPem, true));
  t.check(refused.issuedHere && !refused.accepted &&
          refused.error === 'NOT_A_TLS_CLIENT_CERTIFICATE',
          'C: that key pair — same Root, same realm, same person — is NOT an ' +
          'identity', JSON.stringify(refused));
  // TWO LEAVES THAT FAIL ONE RULE EACH. The assertion key pair above fails two
  // at once — wrong authority AND no clientAuth — so with either check deleted
  // it is still refused by the other, and the first mutation run of this file
  // showed exactly that: both mutants survived. So: a clientAuth leaf naming
  // the person from the WRONG authority, and a leaf from the RIGHT authority
  // with no clientAuth.
  const makeLeaf = async function (useCaseId, usages, sanName) {
    log.debug("Entering makeLeaf().");
    const pair = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const publicKeyPem = pair.publicKey.export({ type: 'spki', format: 'pem' });
    const extensions = { subjectAltName: { present: true, critical: false,
      names: [{ kind: 'uri',
                value: 'urn:sts:person:' + (sanName || PERSON) }] } };
    if (usages) {
      extensions.extKeyUsage = { present: true, critical: false,
                                 usages: usages };
    }
    const one = await pki.certify(REALM, useCaseId, {
      slot: 'fixture:' + useCaseId + ':' + (usages ? 'eku' : 'none') + ':' +
            (sanName || PERSON),
      commonName: PERSON, keyAlg: 'ec-p256', publicKeyPem: publicKeyPem,
      keyUsage: ['digitalSignature'], extensions: extensions });
    log.debug("Leaving makeLeaf().");
    return one.record;
  };
  const wrongAuthority = await makeLeaf('assertions', ['clientAuth']);
  const wrongGot = tlsClient.identityOf(asInput(wrongAuthority.certificatePem,
                                                wrongAuthority.chainPem, true));
  t.check(wrongGot.issuedHere && !wrongGot.accepted,
          'C: a clientAuth leaf naming the person from ANOTHER authority is ' +
          'not an identity', JSON.stringify(wrongGot));
  const noEku = await makeLeaf('tls-client', null);
  const noEkuGot = tlsClient.identityOf(asInput(noEku.certificatePem,
                                                noEku.chainPem, true));
  t.check(noEkuGot.issuedHere && !noEkuGot.accepted,
          'C: a leaf from the TLS client authority with no clientAuth is not ' +
          'an identity', JSON.stringify(noEkuGot));
  const otherName = await makeLeaf('tls-client', ['clientAuth'], 'bob');
  const otherNameGot = tlsClient.identityOf(asInput(otherName.certificatePem,
                                                    otherName.chainPem, true));
  t.check(otherNameGot.issuedHere && !otherNameGot.accepted,
          'C: a TLS client leaf whose CN and urn:sts:person: name disagree ' +
          'is ' +
          'not an identity', JSON.stringify(otherNameGot));
  const unverified = tlsClient.identityOf(asInput(issued.certificatePem,
                                                  issued.chainPem, false));
  t.check(!unverified.issuedHere && !unverified.accepted,
          'C: an unverified chain is not the gate\'s business');
  const sock = fakeSocket(issued.certificatePem, issued.chainPem, true);
  const elsewhere = tlsClient.checkSocket(sock);
  t.check(!elsewhere.ok && elsewhere.error === 'OTHER_REALM',
          'C: at a main-port door in another realm it is refused',
          JSON.stringify(elsewhere));
  const home = inRealm(function () { return tlsClient.checkSocket(sock); });
  t.check(home.ok, 'C: in its own realm it is accepted');
  const mtls = require('../oauth-oidc/mtls');
  const verdictHome = inRealm(function () {
    return mtls.peerVerified({ socket: sock });
  });
  t.check(verdictHome.verified === true,
          'C: mtls.peerVerified() verifies it in its realm',
          JSON.stringify(verdictHome));
  const assertionSock = fakeSocket(assertion.issued.certificatePem,
                                   assertion.issued.chainPem, true);
  const verdictAssertion = inRealm(function () {
    return mtls.peerVerified({ socket: assertionSock });
  });
  t.check(verdictAssertion.verified === false &&
          verdictAssertion.error === 'NOT_A_TLS_CLIENT_CERTIFICATE',
          'C: and refuses the assertion key pair that OpenSSL verified',
          JSON.stringify(verdictAssertion));

  // -------------------------------------------------------------------------
  // D. THE LISTENERS
  // -------------------------------------------------------------------------
  const tls = require('../tls/tls_server');
  await tls.listen().whenReady;
  const root = pki.serviceRoot();
  t.check(tls.clientTruststoreOptions().ca.some(function (pem) {
    return String(pem).trim() === String(root.certificatePem).trim();
  }), 'D: the service Root is in the client truststore');
  const ports = tls.ports();
  const clientCert = issued.certificatePem + issued.chainPem.join('');
  const strict = await ask(ports.mtls, clientCert, issued.privateKeyPem);
  const session = strict.body.session || {};
  t.check(strict.status === 200 && session.started === true &&
          session.username === PERSON && session.realm === REALM,
          'D: 9443 signs the holder in, in the certificate\'s realm',
          JSON.stringify({ status: strict.status, session: session,
                           raw: strict.body.raw, error: strict.body.error }));
  const assertionCert = assertion.issued.certificatePem +
                        assertion.issued.chainPem.join('');
  const strictRefused = await ask(ports.mtls, assertionCert,
                                  assertion.issued.privateKeyPem);
  t.check(strictRefused.status === 403 &&
          !(strictRefused.body.session || {}).started &&
          (strictRefused.body.authentication || {}).refusedAsIdentity === true,
          'D: 9443 answers the assertion key pair 403 and starts no session',
          JSON.stringify({ status: strictRefused.status,
                           session: strictRefused.body.session }));
  const optionalRefused = await ask(ports.tls, assertionCert,
                                    assertion.issued.privateKeyPem);
  t.check(optionalRefused.status === 200 &&
          !(optionalRefused.body.session || {}).started &&
          (optionalRefused.body.authentication || {}).authenticated === false,
          'D: 8443 reports it and starts no session',
          JSON.stringify({ status: optionalRefused.status,
                           session: optionalRefused.body.session }));
  const notTheirs = tlsClient.revoke(REALM, 'bob', issued.serialHex,
                                     'keyCompromise');
  t.check(!notTheirs.ok && errorCodes.codeOf(notTheirs) === 'STS-PKI-0171',
          'D: somebody else cannot revoke it');
  const revoked = tlsClient.revoke(REALM, PERSON, issued.serialHex,
                                   'keyCompromise');
  t.check(revoked.ok && tlsClient.listFor(REALM, PERSON)[0].state === 'revoked',
          'D: the holder revokes it', JSON.stringify(revoked.errors || ''));
  const afterRevoke = await ask(ports.mtls, clientCert, issued.privateKeyPem);
  t.check(afterRevoke.status === 403 &&
          !(afterRevoke.body.session || {}).started,
          'D: and 9443 refuses it from then on',
          JSON.stringify({ status: afterRevoke.status,
                           session: afterRevoke.body.session }));
  tls.close();
  log.debug("Leaving childBody().");
  return t.rows;
}

function spawnChild() {
  log.debug("Entering spawnChild().");
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(KRB5_|STS_|LDAP_|LDAPS_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  clean[CHILD_FLAG] = '1';
  clean.STS_TLS_PORT = '0';
  clean.STS_MTLS_PORT = '0';
  clean.LOG_LEVEL = 'fatal';
  const result = childProcess.spawnSync(process.execPath, [__filename], {
    cwd: ROOT, env: clean, encoding: 'utf8', timeout: 240000,
    maxBuffer: 64 * 1024 * 1024
  });
  const line = String(result.stdout || '').split('\n').filter(function (one) {
    return one.indexOf('TLS-CLIENT-CHILD ') === 0;
  })[0];
  if (!line) {
    log.debug("Leaving spawnChild(). No result.");
    return { error: 'the child produced no result (exit ' + result.status +
                    '): ' + String(result.stderr || '').slice(-1500) };
  }
  log.debug("Leaving spawnChild().");
  return { rows: JSON.parse(line.slice('TLS-CLIENT-CHILD '.length)) };
}

function run(t) {
  log.debug("Entering run().");
  t.log.info('=== a person\'s TLS client certificate, its files, the ' +
             'identity gate and the listeners ===');
  const got = spawnChild();
  if (got.error) {
    t.bad('the child did not run', got.error);
    log.debug("Leaving run(). No child.");
    return;
  }
  got.rows.forEach(function (row) {
    t.check(row.ok, row.what, row.detail);
  });
  log.debug("Leaving run().");
}

if (require.main === module && process.env[CHILD_FLAG]) {
  childBody().then(function (rows) {
    process.stdout.write('\nTLS-CLIENT-CHILD ' + JSON.stringify(rows) + '\n');
    process.exit(0);
  }, function (e) {
    process.stderr.write('child failed: ' + String((e && e.stack) || e) +
                         '\n');
    process.exit(1);
  });
}

module.exports = {
  name: 'tls_client_certificates',
  describe: 'A person\'s TLS client certificate: clientAuth from the ' +
            'realm\'s ' +
            'TLS Client Issuing CA, a PKCS#12 OpenSSL opens, the gate that ' +
            'refuses every other key pair under the same Root, and 9443 ' +
            'signing the holder in to their realm until they revoke it',
  run: run
};
