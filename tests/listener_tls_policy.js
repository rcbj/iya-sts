// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/listener_tls_policy.js
// ===========================================================================
// THE LISTENERS' TLS POLICY AND CLIENT AUTHENTICATION (#423, 2026-10-02).
//
// rcbj asked for a "Disable TLS v1.2" flag on every TLS listener (and on a
// realm's own), the TLS 1.3 cipher suites chosen one by one with the
// post-quantum safe ones among them, a post-quantum-only toggle, and per
// listener a toggle that stops it asking for a client certificate and one
// that requires one. Every claim here is read off a REAL HANDSHAKE made by
// OpenSSL's own client (`s_client`, spawned ASYNCHRONOUSLY — the listeners
// are in this process, and a spawnSync() would block the loop that answers),
// against listeners built the way `server.js` builds the main port and a
// realm's listener: `tls_server.js`'s `protocolOptions(policyFor(kind))` and
// `clientAuthOptions()`, registered with `trustClientCertificatesOn()`. A
// probe is ACCEPTED when an HTTP request sent over it is answered 200.
//
// Each setting is CHANGED AT RUNTIME through `config.setOverride()` — the
// door the console and the API write through — and the next handshake is
// expected to follow it, which is the re-application the settings rest on.
//
//   A. the defaults: TLS 1.2 and 1.3, the three default suites, CCM refused,
//      a CertificateRequest sent and a client with no certificate admitted;
//   B. tls.disableTls12: TLS 1.2 refused, TLS 1.3 accepted, and back;
//   C. tls.tls13CipherSuites: a suite not chosen refused, a chosen one —
//      CCM included — accepted;
//   D. tls.pqcOnly: TLS 1.2, AES-128 and a classical group refused, AES-256
//      with an ML-KEM group accepted; and the write rules (STS-TLS-0043);
//   E. the main port's two toggles: no CertificateRequest, and a certificate
//      required — refused without one and with a stranger's, accepted with
//      one chaining to the truststore;
//   F. a realm's own listener: listener.disableTls12, listener.pqcOnly and
//      its client authentication decide for it alone, and inherit otherwise;
//   G. the real LDAPS listener: no CertificateRequest by default, one once
//      ldap.ldapsDisableOptionalClientCertificate is off — re-applied to the
//      socket ldap.listen() bound;
//   H. an applier (SPIFFE's and the cells' kind) is handed each new policy;
//   I. a TLS 1.3 name in tls.ciphers stops the service (STS-TLS-0042), and a
//      listener's own unreadable anchors file (STS-TLS-0045);
//   J. EVERY SETTING PER LISTENER (#429): one listener's own TLS 1.2 switch,
//      TLS 1.3 suites and post-quantum toggle decide for it alone, inherit
//      returns it to the service's, its write rule, its restart-only rows;
//   K. a listener's own client truststore (its anchors file).
// And TLS 1.3 by default (#429): A1 asserts TLS 1.2 refused untouched.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'listener_tls_policy',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.LT_ROOT;
  const OUT = process.env.LT_OUT;
  const https = require('https');
  const spawn = require('child_process').spawn;
  const spawnSync = require('child_process').spawnSync;
  const fsx = require('fs');
  const osx = require('os');
  const pathx = require('path');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  // One handshake by OpenSSL's client, an HTTP request over it, and what it
  // saw. `opts`: version ('1.2' or '1.3'), suites (TLS 1.3), cipher (TLS 1.2),
  // groups, cert and key.
  function probe(port, opts) {
    const o = opts || {};
    const args = ['s_client', '-connect', '127.0.0.1:' + port,
                  '-servername', 'localhost', '-msg', '-ign_eof'];
    if (o.version === '1.2') {
      args.push('-tls1_2');
    }
    if (o.version === '1.3') {
      args.push('-tls1_3');
    }
    if (o.suites) {
      args.push('-ciphersuites', o.suites);
    }
    if (o.cipher) {
      args.push('-cipher', o.cipher);
    }
    if (o.groups) {
      args.push('-groups', o.groups);
    }
    if (o.cert) {
      args.push('-cert', o.cert, '-key', o.key);
    }
    return new Promise(function (resolve) {
      const proc = spawn('openssl', args);
      let text = '';
      proc.stdout.on('data', function (d) { text += d; });
      proc.stderr.on('data', function (d) { text += d; });
      const timer = setTimeout(function () { proc.kill('SIGKILL'); }, 20000);
      proc.on('close', function () {
        clearTimeout(timer);
        resolve({ text: text,
                  accepted: /HTTP\/1\.1 200/.test(text),
                  certificateRequest: /, CertificateRequest/.test(text) });
      });
      proc.stdin.write('GET / HTTP/1.0\r\nHost: localhost\r\n\r\n');
      proc.stdin.end();
    });
  }
  const tail = function (r) {
    return r.text.replace(/\s+/g, ' ').slice(-300);
  };
  // Lets the re-application land: it is synchronous, but a setting written
  // in one tick and a probe in the same tick prove nothing about order.
  const settle = function () {
    return new Promise(function (r) { setTimeout(r, 50); });
  };

  (async function () {
    // A certificate authority and two client certificates, made here by
    // OpenSSL: one the truststore will hold the CA of, one self-signed.
    const dir = fsx.mkdtempSync(pathx.join(osx.tmpdir(), 'lt-'));
    const ossl = function (args) {
      return spawnSync('openssl', args, { cwd: dir, encoding: 'utf8' });
    };
    ossl(['req', '-x509', '-newkey', 'ec', '-pkeyopt',
          'ec_paramgen_curve:P-256', '-nodes', '-keyout', 'ca.key', '-out',
          'ca.crt', '-days', '2', '-subj', '/CN=lt test ca',
          '-addext', 'basicConstraints=critical,CA:TRUE',
          '-addext', 'keyUsage=critical,keyCertSign,cRLSign']);
    ossl(['req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
          '-nodes', '-keyout', 'client.key', '-out', 'client.csr', '-subj',
          '/CN=lt client']);
    fsx.writeFileSync(pathx.join(dir, 'ext.cnf'),
      'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\n' +
      'extendedKeyUsage=clientAuth\n');
    ossl(['x509', '-req', '-in', 'client.csr', '-CA', 'ca.crt', '-CAkey',
          'ca.key', '-CAcreateserial', '-out', 'client.crt', '-days', '2',
          '-extfile', 'ext.cnf']);
    ossl(['req', '-x509', '-newkey', 'ec', '-pkeyopt',
          'ec_paramgen_curve:P-256', '-nodes', '-keyout', 'stranger.key',
          '-out', 'stranger.crt', '-days', '2', '-subj', '/CN=lt stranger']);
    // A SECOND authority, held only in the debugger listener's OWN anchors
    // file (#429, listenerDebugger.trustAnchorsFile — restart-only, so it is
    // in the environment before the stack loads).
    ossl(['req', '-x509', '-newkey', 'ec', '-pkeyopt',
          'ec_paramgen_curve:P-256', '-nodes', '-keyout', 'ca2.key', '-out',
          'ca2.crt', '-days', '2', '-subj', '/CN=lt debugger-only ca',
          '-addext', 'basicConstraints=critical,CA:TRUE',
          '-addext', 'keyUsage=critical,keyCertSign,cRLSign']);
    ossl(['req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
          '-nodes', '-keyout', 'client2.key', '-out', 'client2.csr', '-subj',
          '/CN=lt client2']);
    ossl(['x509', '-req', '-in', 'client2.csr', '-CA', 'ca2.crt', '-CAkey',
          'ca2.key', '-CAcreateserial', '-out', 'client2.crt', '-days', '2',
          '-extfile', 'ext.cnf']);
    // AND A THIRD, in the SERVICE-WIDE anchors file (tls.trustAnchorsFile):
    // a listener's own file REPLACES the service's file anchors for it.
    ossl(['req', '-x509', '-newkey', 'ec', '-pkeyopt',
          'ec_paramgen_curve:P-256', '-nodes', '-keyout', 'ca3.key', '-out',
          'ca3.crt', '-days', '2', '-subj', '/CN=lt service-file ca',
          '-addext', 'basicConstraints=critical,CA:TRUE',
          '-addext', 'keyUsage=critical,keyCertSign,cRLSign']);
    ossl(['req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
          '-nodes', '-keyout', 'client3.key', '-out', 'client3.csr', '-subj',
          '/CN=lt client3']);
    ossl(['x509', '-req', '-in', 'client3.csr', '-CA', 'ca3.crt', '-CAkey',
          'ca3.key', '-CAcreateserial', '-out', 'client3.crt', '-days', '2',
          '-extfile', 'ext.cnf']);
    const file = function (name) { return pathx.join(dir, name); };
    process.env.STS_LISTENER_DEBUGGER_TRUST_ANCHORS_FILE = file('ca2.crt');
    process.env.STS_TLS_TRUST_ANCHORS_FILE = file('ca3.crt');
    note(fsx.existsSync(file('client.crt')) &&
         fsx.existsSync(file('stranger.crt')),
         'precondition: OpenSSL made the test CA and client certificates',
         fsx.readdirSync(dir).join(','));
    // The whole stack next: the composition root installs each module's
    // instance, and a module required before it would have built its own.
    require(ROOT_DIR + '/common/protocol_stack');
    const config = require(ROOT_DIR + '/common/config');
    const realms = require(ROOT_DIR + '/common/realms');
    const stsCrypto = require(ROOT_DIR + '/common/crypto');
    const tlsServer = require(ROOT_DIR + '/tls/tls_server');

    const added = tlsServer.addAnchors(fsx.readFileSync(file('ca.crt'),
                                                        'utf8'),
                                       { source: 'runtime' });
    note(added && added.added === 1, 'precondition: the test CA is a ' +
         'truststore anchor', JSON.stringify(added));

    const made = stsCrypto.selfSignedRsaCertificate({
      commonName: 'localhost' });
    const own = { key: made.privateKeyPem, cert: made.certPem };
    const listen = async function (kind, realmId) {
      const policy = tlsServer.policyFor(kind, realmId);
      const server = https.createServer(Object.assign({
        key: own.key, cert: own.cert,
        ca: tlsServer.clientTruststoreOptions(policy).ca
      }, tlsServer.clientAuthOptions(policy.clientAuth),
      tlsServer.protocolOptions(policy)), function (req, res) {
        res.end('ok');
      });
      tlsServer.trustClientCertificatesOn(server, 'test ' + kind,
        function () { return own; }, { kind: kind, realm: realmId });
      await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
      return server;
    };

    // --- A. the defaults --------------------------------------------------
    const main = await listen('main');
    const mainPort = main.address().port;
    let r = await probe(mainPort, { version: '1.2' });
    const row12 = config.SETTINGS.filter(function (one) {
      return one.key === 'tls.disableTls12';
    })[0];
    note(!r.accepted && config.value('tls.disableTls12') === true &&
         row12 && row12.dflt === true,
         'A1. default: TLS 1.2 is REFUSED — every listener is TLS 1.3 by ' +
         'default (#429)', tail(r));
    // TLS 1.2 on, service-wide, for the sections that need it.
    config.setOverride('tls.disableTls12', false);
    await settle();
    r = await probe(mainPort, { version: '1.2' });
    note(r.accepted, 'A1b. tls.disableTls12 off: TLS 1.2 is accepted',
         tail(r));
    r = await probe(mainPort, { version: '1.3' });
    note(r.accepted && r.certificateRequest, 'A2. default: TLS 1.3 is ' +
         'accepted, a CertificateRequest is sent and a client with no ' +
         'certificate is admitted', tail(r));
    for (const suite of ['TLS_AES_256_GCM_SHA384', 'TLS_AES_128_GCM_SHA256',
                         'TLS_CHACHA20_POLY1305_SHA256']) {
      r = await probe(mainPort, { version: '1.3', suites: suite });
      note(r.accepted, 'A3. default: ' + suite + ' is accepted', tail(r));
    }
    r = await probe(mainPort, { version: '1.3',
                                suites: 'TLS_AES_128_CCM_SHA256' });
    note(!r.accepted, 'A4. default: TLS_AES_128_CCM_SHA256 is refused',
         tail(r));

    // --- B. tls.disableTls12 ----------------------------------------------
    let w = config.setOverride('tls.disableTls12', true);
    await settle();
    r = await probe(mainPort, { version: '1.2' });
    note(w.ok && !r.accepted, 'B1. tls.disableTls12 on: TLS 1.2 is refused ' +
         'at the next handshake', JSON.stringify(w.errors) + ' ' + tail(r));
    r = await probe(mainPort, { version: '1.3' });
    note(r.accepted, 'B2. tls.disableTls12 on: TLS 1.3 is accepted',
         tail(r));
    // THE FLOOR ITSELF, beside the handshake. With TLS 1.2 off the cipher
    // string also carries no TLS 1.2 suite, so B1 is refused by EITHER guard
    // and a floor left at TLS 1.2 passed it (the mutant survived): the
    // options the listener is keyed from are asked directly.
    const floor = tlsServer.protocolOptions(tlsServer.policyFor('main'));
    note(floor.minVersion === 'TLSv1.3', 'B2b. tls.disableTls12 on: the ' +
         'listener\'s floor is TLSv1.3, not only its cipher list',
         floor.minVersion);
    config.setOverride('tls.disableTls12', false);
    await settle();
    r = await probe(mainPort, { version: '1.2' });
    note(r.accepted, 'B3. tls.disableTls12 off again: TLS 1.2 is accepted ' +
         'again', tail(r));

    // --- C. tls.tls13CipherSuites -----------------------------------------
    w = config.setOverride('tls.tls13CipherSuites',
                           'TLS_CHACHA20_POLY1305_SHA256');
    await settle();
    r = await probe(mainPort, { version: '1.3',
                                suites: 'TLS_AES_256_GCM_SHA384' });
    note(w.ok && !r.accepted, 'C1. only ChaCha20 chosen: a client offering ' +
         'AES-256-GCM alone is refused', tail(r));
    r = await probe(mainPort, { version: '1.3',
                                suites: 'TLS_CHACHA20_POLY1305_SHA256' });
    note(r.accepted, 'C2. only ChaCha20 chosen: ChaCha20 is accepted',
         tail(r));
    w = config.setOverride('tls.tls13CipherSuites',
                           'TLS_AES_128_CCM_SHA256,TLS_AES_256_GCM_SHA384');
    await settle();
    r = await probe(mainPort, { version: '1.3',
                                suites: 'TLS_AES_128_CCM_SHA256' });
    note(w.ok && r.accepted, 'C3. CCM chosen: TLS_AES_128_CCM_SHA256 is ' +
         'accepted', tail(r));
    w = config.setOverride('tls.tls13CipherSuites', '');
    note(!w.ok, 'C4. an empty suite list is refused',
         JSON.stringify(w));
    note(config.checkOverrideCode('tls.tls13CipherSuites', '') ===
         'STS-TLS-0043', 'C5. ... under STS-TLS-0043',
         config.checkOverrideCode('tls.tls13CipherSuites', ''));
    config.clearOverride('tls.tls13CipherSuites');
    await settle();

    // --- D. tls.pqcOnly ---------------------------------------------------
    w = config.setOverride('tls.tls13CipherSuites', 'TLS_AES_128_GCM_SHA256');
    note(w.ok, 'precondition: AES-128 alone may be chosen', JSON.stringify(w));
    note(config.checkOverrideCode('tls.pqcOnly', 'true') === 'STS-TLS-0043',
         'D1. post-quantum only is refused (STS-TLS-0043) while the suites ' +
         'hold no 256-bit suite',
         config.checkOverrideCode('tls.pqcOnly', 'true'));
    config.clearOverride('tls.tls13CipherSuites');
    w = config.setOverride('tls.pqcOnly', true);
    await settle();
    note(w.ok, 'precondition: post-quantum only is turned on',
         JSON.stringify(w));
    note(config.checkOverrideCode('tls.tls13CipherSuites',
                                  'TLS_AES_128_GCM_SHA256') === 'STS-TLS-0043',
         'D2. while it is on, a suite list with no 256-bit suite is refused',
         config.checkOverrideCode('tls.tls13CipherSuites',
                                  'TLS_AES_128_GCM_SHA256'));
    r = await probe(mainPort, { version: '1.2' });
    note(!r.accepted, 'D3. post-quantum only: TLS 1.2 is refused', tail(r));
    r = await probe(mainPort, { version: '1.3',
                                suites: 'TLS_AES_128_GCM_SHA256' });
    note(!r.accepted, 'D4. post-quantum only: AES-128-GCM is refused',
         tail(r));
    r = await probe(mainPort, { version: '1.3', groups: 'X25519:P-256' });
    note(!r.accepted, 'D5. post-quantum only: a classical group is refused',
         tail(r));
    r = await probe(mainPort, { version: '1.3',
                                suites: 'TLS_AES_256_GCM_SHA384',
                                groups: 'X25519MLKEM768' });
    note(r.accepted, 'D6. post-quantum only: AES-256-GCM with ' +
         'X25519MLKEM768 is accepted', tail(r));
    config.clearOverride('tls.pqcOnly');
    await settle();
    r = await probe(mainPort, { version: '1.2' });
    note(r.accepted, 'D7. post-quantum only reset: TLS 1.2 is accepted ' +
         'again', tail(r));

    // --- E. the main port's client authentication -------------------------
    w = config.setOverride('tls.mainPortDisableOptionalClientCertificate',
                           true);
    await settle();
    r = await probe(mainPort, { version: '1.3' });
    note(w.ok && r.accepted && !r.certificateRequest, 'E1. "do not ask" on: ' +
         'no CertificateRequest, and the client is admitted', tail(r));
    w = config.setOverride('tls.mainPortRequireClientCertificate', true);
    await settle();
    r = await probe(mainPort, { version: '1.3' });
    note(w.ok && r.certificateRequest && !r.accepted, 'E2. "require" on ' +
         '(and winning over "do not ask"): a CertificateRequest, and a ' +
         'client with no certificate is refused', tail(r));
    r = await probe(mainPort, { version: '1.3', cert: file('stranger.crt'),
                                key: file('stranger.key') });
    note(!r.accepted, 'E3. "require" on: a certificate chaining to nothing ' +
         'held is refused', tail(r));
    r = await probe(mainPort, { version: '1.3', cert: file('client.crt'),
                                key: file('client.key') });
    note(r.accepted, 'E4. "require" on: a certificate chaining to the ' +
         'truststore is admitted', tail(r));
    r = await probe(mainPort, { version: '1.2', cert: file('client.crt'),
                                key: file('client.key') });
    note(r.accepted, 'E5. "require" on: the same over TLS 1.2', tail(r));
    config.clearOverride('tls.mainPortRequireClientCertificate');
    config.clearOverride('tls.mainPortDisableOptionalClientCertificate');
    await settle();
    r = await probe(mainPort, { version: '1.3' });
    note(r.accepted && r.certificateRequest, 'E6. both reset: asked for ' +
         'and not required again', tail(r));

    // --- F. a realm's own listener ----------------------------------------
    const realmId = 'lt-' + process.pid;
    const created = realms.create({ id: realmId });
    note(created && created.ok !== false, 'precondition: a realm is made',
         JSON.stringify(created && created.errors));
    w = realms.setOverride(realmId, 'listener.disableTls12', 'on');
    note(w && w.ok !== false, 'precondition: listener.disableTls12 is set ' +
         'on the realm', JSON.stringify(w));
    const realmServer = await listen('realm', realmId);
    const realmPort = realmServer.address().port;
    r = await probe(realmPort, { version: '1.2' });
    const r2 = await probe(mainPort, { version: '1.2' });
    note(!r.accepted && r2.accepted, 'F1. listener.disableTls12 on: the ' +
         'realm\'s listener refuses TLS 1.2 while the main port accepts it',
         tail(r) + ' | ' + tail(r2));
    realms.setOverride(realmId, 'listener.disableTls12', 'inherit');
    await settle();
    r = await probe(realmPort, { version: '1.2' });
    note(r.accepted, 'F2. inherit: the realm\'s listener follows the ' +
         'process again (TLS 1.2 accepted), re-applied on the realm change',
         tail(r));
    realms.setOverride(realmId, 'listener.pqcOnly', 'on');
    await settle();
    r = await probe(realmPort, { version: '1.3',
                                 suites: 'TLS_AES_128_GCM_SHA256' });
    note(!r.accepted, 'F3. listener.pqcOnly on: the realm\'s listener ' +
         'refuses AES-128-GCM', tail(r));
    w = realms.setOverride(realmId, 'listener.tls13CipherSuites',
                           'TLS_AES_128_GCM_SHA256');
    note(w && w.ok === false, 'F4. a realm suite list with no 256-bit ' +
         'suite is refused while its listener.pqcOnly is on',
         JSON.stringify(w));
    realms.setOverride(realmId, 'listener.pqcOnly', 'inherit');
    realms.setOverride(realmId, 'listener.requireClientCertificate', 'true');
    await settle();
    r = await probe(realmPort, { version: '1.3' });
    const r3 = await probe(mainPort, { version: '1.3' });
    note(!r.accepted && r3.accepted, 'F5. listener.requireClientCertificate: ' +
         'the realm\'s listener refuses a client without a certificate; ' +
         'the main port does not', tail(r) + ' | ' + tail(r3));
    r = await probe(realmPort, { version: '1.3', cert: file('client.crt'),
                                 key: file('client.key') });
    note(r.accepted, 'F6. ... and admits one chaining to the truststore',
         tail(r));
    w = realms.setOverride(realms.DEFAULT_ID, 'listener.disableTls12', 'on');
    note(w && w.ok === false, 'F7. the default realm may not carry a ' +
         'listener row', JSON.stringify(w));

    // --- G. the real LDAPS listener ---------------------------------------
    const ldap = require(ROOT_DIR + '/ldap/ldap_server');
    const ready = await ldap.listen().whenReady;
    const ldapsPort = ready.ldapsPort;
    r = await probe(ldapsPort, { version: '1.3' });
    note(/Finished/.test(r.text) && !r.certificateRequest, 'G1. LDAPS by ' +
         'default sends no CertificateRequest', tail(r));
    w = config.setOverride('ldap.ldapsDisableOptionalClientCertificate',
                           false);
    await settle();
    r = await probe(ldapsPort, { version: '1.3' });
    note(w.ok && r.certificateRequest, 'G2. "do not ask" off: LDAPS sends a ' +
         'CertificateRequest at the next handshake', tail(r));
    w = config.setOverride('tls.disableTls12', true);
    await settle();
    r = await probe(ldapsPort, { version: '1.2' });
    note(w.ok && !/Finished/.test(r.text), 'G3. tls.disableTls12 reaches ' +
         'LDAPS: TLS 1.2 is refused there', tail(r));
    config.clearOverride('tls.disableTls12');
    config.clearOverride('ldap.ldapsDisableOptionalClientCertificate');

    // --- H. an applier is handed each new policy --------------------------
    const handed = [];
    const unregister = tlsServer.registerPolicyApplier('test applier',
      'spiffeServer', function (policy) { handed.push(policy); });
    tlsServer.reapplyPolicy();
    config.setOverride('tls.tls13CipherSuites', 'TLS_AES_256_GCM_SHA384');
    const after = handed[handed.length - 1] || {};
    note(handed.length >= 1 && after.kind === 'spiffeServer' &&
         JSON.stringify(after.tls13Suites) === '["TLS_AES_256_GCM_SHA384"]' &&
         after.clientAuth === null,
         'H1. a registered applier (the SPIFFE and cell kind) is handed the ' +
         'new policy when a setting moves, with no client authentication ' +
         'of its own', JSON.stringify(handed));
    const count = handed.length;
    config.setOverride('oauth2.parRequestUriLifetimeS', '60');
    note(handed.length === count, 'H2. a setting that moves no policy ' +
         'hands nothing', String(handed.length - count));
    config.clearOverride('oauth2.parRequestUriLifetimeS');
    unregister();
    config.clearOverride('tls.tls13CipherSuites');
    note(handed.length === count, 'H3. an unregistered applier is handed ' +
         'nothing', String(handed.length - count));

    // --- J. every setting per listener (#429) ------------------------------
    // The service-wide default is back (TLS 1.3 only). A second listener of
    // another kind beside the main port shows a value deciding for ONE.
    const dbg = await listen('debugger');
    const dbgPort = dbg.address().port;
    w = config.setOverride('listenerMain.disableTls12', 'off');
    await settle();
    r = await probe(mainPort, { version: '1.2' });
    let r4 = await probe(dbgPort, { version: '1.2' });
    note(w.ok && r.accepted && !r4.accepted, 'J1. listenerMain.disableTls12 ' +
         'off: the main port accepts TLS 1.2 while the debugger listener, ' +
         'inheriting TLS 1.3 only, refuses it', tail(r) + ' | ' + tail(r4));
    config.setOverride('listenerMain.disableTls12', 'inherit');
    await settle();
    r = await probe(mainPort, { version: '1.2' });
    note(!r.accepted, 'J2. inherit: the main port follows the service ' +
         'again and refuses TLS 1.2', tail(r));
    w = config.setOverride('listenerDebugger.tls13CipherSuites',
                           'TLS_CHACHA20_POLY1305_SHA256');
    await settle();
    r = await probe(dbgPort, { version: '1.3',
                               suites: 'TLS_AES_256_GCM_SHA384' });
    r4 = await probe(mainPort, { version: '1.3',
                                 suites: 'TLS_AES_256_GCM_SHA384' });
    note(w.ok && !r.accepted && r4.accepted, 'J3. the debugger\'s own TLS ' +
         '1.3 suites: AES-256-GCM refused there and accepted on the main ' +
         'port', tail(r) + ' | ' + tail(r4));
    config.setOverride('listenerDebugger.tls13CipherSuites', '');
    w = config.setOverride('listenerMain.pqcOnly', 'on');
    await settle();
    r = await probe(mainPort, { version: '1.3', groups: 'X25519:P-256' });
    r4 = await probe(dbgPort, { version: '1.3', groups: 'X25519:P-256' });
    note(w.ok && !r.accepted && r4.accepted, 'J4. listenerMain.pqcOnly on: ' +
         'a classical group refused on the main port alone', tail(r) +
         ' | ' + tail(r4));
    note(config.checkOverrideCode('listenerMain.tls13CipherSuites',
                                  'TLS_AES_128_GCM_SHA256') === 'STS-TLS-0043',
         'J5. while the main port is post-quantum only, its own suite list ' +
         'with no 256-bit suite is refused (STS-TLS-0043)',
         config.checkOverrideCode('listenerMain.tls13CipherSuites',
                                  'TLS_AES_128_GCM_SHA256'));
    config.setOverride('listenerMain.pqcOnly', 'inherit');
    w = config.setOverride('listenerMain.minVersion', 'TLSv1.3');
    note(!w.ok, 'J6. a listener\'s minVersion is restart-only, as the ' +
         'service\'s tls.minVersion is', JSON.stringify(w));
    w = config.setOverride('listenerMain.trustAnchorsFile', '/x');
    note(!w.ok, 'J7. a listener\'s own anchors file is restart-only, as the ' +
         'service\'s is', JSON.stringify(w));

    // --- K. a listener's own client truststore ------------------------------
    // listenerDebugger.trustAnchorsFile holds an authority the service does
    // not trust; both listeners require a client certificate.
    config.setOverride('tls.mainPortRequireClientCertificate', true);
    config.setOverride('debugger.requireClientCertificate', true);
    await settle();
    r = await probe(dbgPort, { version: '1.3', cert: file('client2.crt'),
                               key: file('client2.key') });
    r4 = await probe(mainPort, { version: '1.3', cert: file('client2.crt'),
                                 key: file('client2.key') });
    note(r.accepted && !r4.accepted, 'K1. a certificate from the debugger\'s ' +
         'own anchors file is admitted there and refused on the main port',
         tail(r) + ' | ' + tail(r4));
    r = await probe(dbgPort, { version: '1.3', cert: file('client.crt'),
                               key: file('client.key') });
    note(r.accepted, 'K2. and a runtime anchor (/tls/trust) still reaches ' +
         'the debugger: its own file replaces the service\'s FILE anchors, ' +
         'not the runtime ones', tail(r));
    r = await probe(mainPort, { version: '1.3', cert: file('client3.crt'),
                                key: file('client3.key') });
    r4 = await probe(dbgPort, { version: '1.3', cert: file('client3.crt'),
                                key: file('client3.key') });
    note(r.accepted && !r4.accepted, 'K3. a certificate from the SERVICE\'s ' +
         'anchors file is admitted on the main port and refused on the ' +
         'debugger, whose own file replaces the service\'s for it',
         tail(r) + ' | ' + tail(r4));
    config.clearOverride('tls.mainPortRequireClientCertificate');
    config.clearOverride('debugger.requireClientCertificate');
    dbg.close();

    main.close();
    realmServer.close();
    tlsServer.clearAnchors();
    fsx.rmSync(dir, { recursive: true, force: true });
    fsx.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    note(false, 'the child process ran to the end', e && e.stack);
    fsx.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function cleanEnv() {
  log.debug("Entering cleanEnv().");
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|LDAP_|LDAPS_|KRB5_|CONFIG_FILE$|OAUTH2_)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  log.debug("Leaving cleanEnv().");
  return clean;
}

async function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'lt-' + process.pid + '-' + Date.now() +
                        '.json');
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(cleanEnv(), {
        LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal', STS_HOST: '127.0.0.1',
        LDAP_PORT: '0', LDAPS_PORT: '0', LT_ROOT: ROOT, LT_OUT: out }),
      encoding: 'utf8', timeout: 600000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    findings = null;
  }
  if (t.check(Array.isArray(findings),
              'the child process reported its findings',
              'exit ' + result.status + ' ' +
              String(result.stderr || '').slice(-800))) {
    findings.forEach(function (one) {
      t.check(one.ok, one.what, one.detail);
    });
  }

  // --- I. a TLS 1.3 name in tls.ciphers stops the service ---------------
  t.log.info('=== I. the startup refusal ===');
  const refused = childProcess.spawnSync(process.execPath, ['-e',
    'require(' + JSON.stringify(path.join(ROOT, 'tls/tls_server')) + ')'], {
    env: Object.assign(cleanEnv(), {
      STS_TLS_CIPHERS: 'TLS_AES_256_GCM_SHA384:ECDHE-RSA-AES128-GCM-SHA256',
      LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal' }),
    encoding: 'utf8', timeout: 120000, cwd: ROOT
  });
  t.check(refused.status === 1 &&
          /STS-TLS-0042/.test(String(refused.stdout) + refused.stderr),
          'I1. a TLS 1.3 suite in tls.ciphers stops the service, naming ' +
          'STS-TLS-0042',
          'exit ' + refused.status + ' ' +
          String(refused.stdout + refused.stderr).slice(-400));
  // --- I2. a listener's own anchors file that cannot be read --------------
  const unreadable = childProcess.spawnSync(process.execPath, ['-e',
    'require(' + JSON.stringify(path.join(ROOT, 'tls/tls_server')) + ')'], {
    env: Object.assign(cleanEnv(), {
      STS_LISTENER_LDAPS_TRUST_ANCHORS_FILE: '/nonexistent/anchors.pem',
      LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal' }),
    encoding: 'utf8', timeout: 120000, cwd: ROOT
  });
  t.check(unreadable.status === 1 &&
          /STS-TLS-0045/.test(String(unreadable.stdout) + unreadable.stderr),
          'I2. a listener\'s own anchors file that cannot be read stops the ' +
          'service, naming STS-TLS-0045',
          'exit ' + unreadable.status + ' ' +
          String(unreadable.stdout + unreadable.stderr).slice(-400));
  log.debug("Leaving run().");
}

module.exports = {
  name: 'listener_tls_policy',
  describe: 'TLS 1.2 off, the TLS 1.3 suites chosen, post-quantum only and ' +
            'client authentication, per listener and per realm listener, ' +
            'over real handshakes (#423)',
  run: run
};
