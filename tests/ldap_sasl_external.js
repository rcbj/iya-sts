// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: ldap_sasl_external.js
//
// ===========================================================================
// SASL EXTERNAL OVER LDAPS: A PERSON BOUND BY THE CERTIFICATE THIS SERVICE
// ISSUED THEM (#1047, from #520).
//
// A SASL EXTERNAL bind (RFC 4513 section 5.2.1.2) binds the connection as
// the existing person entry named by the `urn:sts:person:` subjectAltName of
// a TLS client certificate this realm issued, and it is available exactly
// when 636 asks for a certificate (#423's pair). Real handshakes, real BER:
// the directory's own listeners, started as `server.js` starts them, and a
// client that writes the SASL bind by hand (ldapjs's client sends only simple
// binds) and reads every answer with node-ldapjs's own parser.
//
//   A. OPTIONAL mode (`ldap.ldapsDisableOptionalClientCertificate` off):
//      A1 alice's certificate binds her, with an empty name, with her own
//         `dn:` and `u:` authzId; the connection is bound as her entry
//         (`boundConnections()`), and in product a search of her entry,
//         refused unbound, succeeds bound;
//      A2 refusals, each with its result code and its STS-LDAP code: an
//         authzId naming bob (50, 0189) or in neither form (50, 0189), a
//         bind name naming bob (49, 0190), no certificate (48, 0179), a
//         mechanism other than EXTERNAL (7, 0178), EXTERNAL on 389 (48,
//         0180), an application's certificate (49, 0185), a certificate
//         from an OUTSIDE authority trusted through the truststore that is
//         stored on no entry, even when it names alice (49, 0192; it was
//         0182 until #1061), another realm's certificate held
//         against this realm's DN (49, 0184), a person with no entry (49,
//         0187), a disabled person (49, 0188), a revoked certificate (49,
//         0181);
//      A2b an outside authority's certificate STORED in userCertificate on
//         frank's entry binds as frank (#1061), with his u: authzId and not
//         alice's (50, 0189); a renewed certificate with the same subject is
//         refused until stored (49, 0192), and one stored on two entries is
//         refused (49, 0193);
//      A3 the bind as a request worker runs it: the operation's shape
//         carries the certificate, `performOperation()` binds, and the
//         outcome names the DN `applyOperationResult()` hands node-ldapjs.
//   B. REQUIRED mode: a handshake without a certificate is refused, and one
//      with alice's binds her with SASL EXTERNAL.
//   C. THE DEFAULTS: 636 asks for nothing, so the certificate the client
//      holds is never sent, and EXTERNAL is refused as having none (48,
//      0179) — #418's posture, unchanged.
//
// A child process per mode, for `wstrust_client_certificate.js`'s reason:
// the stack, the certificate authority and the listeners are process state.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const tls = require('tls');

const ROOT = path.join(__dirname, '..');
const CHILD_FLAG = 'STS_LDAP_SASL_EXTERNAL_CHILD';

const log = require('bunyan').createLogger({
  name: 'ldap_sasl_external',
  level: process.env.LOG_LEVEL || 'info' });

function recorder() {
  log.debug("Entering recorder().");
  const rows = [];
  log.debug("Leaving recorder().");
  return {
    rows: rows,
    check: function (ok, what, detail) {
      log.debug("Entering check().");
      rows.push({ ok: !!ok, what: what,
                  detail: detail === undefined ? ''
                    : String(detail).slice(0, 2000) });
      log.debug("Leaving check().");
      return !!ok;
    }
  };
}

// ---------------------------------------------------------------------------
// THE CLIENT: one connection, requests written as BER, answers read with
// node-ldapjs's own Parser and matched by message id.
// ---------------------------------------------------------------------------
function connection(socket) {
  log.debug("Entering connection().");
  const { Parser } = require(ROOT + '/node_modules/ldapjs/lib/messages');
  const parser = new Parser({ log: log });
  const waiting = {};
  const entries = {};
  let closed = null;
  parser.on('message', function (message) {
    const id = message.messageId;
    if (message.type === 'SearchResultEntry') {
      (entries[id] = entries[id] || []).push(String(message.objectName));
      return;
    }
    const done = waiting[id];
    delete waiting[id];
    if (done) {
      done({ status: message.status,
             diagnosticMessage: String(message.diagnosticMessage || ''),
             entries: entries[id] || [] });
    }
  });
  parser.on('error', function (e) {
    log.debug("Caught in the client parser: " + ((e && e.message) || e));
  });
  socket.on('data', function (data) {
    parser.write(data);
  });
  const fail = function (why) {
    log.debug("Entering fail(). " + why);
    closed = closed || why;
    Object.keys(waiting).forEach(function (id) {
      const done = waiting[id];
      delete waiting[id];
      done({ closed: closed });
    });
    log.debug("Leaving fail().");
  };
  socket.on('error', function (e) {
    fail('error: ' + ((e && e.message) || e));
  });
  socket.on('close', function () {
    fail('closed');
  });
  let next = 1;
  log.debug("Leaving connection().");
  return {
    send: function (build) {
      log.debug("Entering send().");
      const id = next++;
      log.debug("Leaving send().");
      return new Promise(function (resolve) {
        if (closed) {
          resolve({ closed: closed });
          return;
        }
        waiting[id] = resolve;
        const timer = setTimeout(function () {
          if (waiting[id]) {
            delete waiting[id];
            resolve({ closed: 'timeout' });
          }
        }, 15000);
        timer.unref();
        socket.write(build(id));
      });
    },
    end: function () {
      log.debug("Entering end().");
      socket.destroy();
      log.debug("Leaving end().");
    }
  };
}

function saslBind(mechanism, credentials, name) {
  log.debug("Entering saslBind(). " + mechanism);
  const { BerWriter } = require(ROOT + '/node_modules/@ldapjs/asn1');
  log.debug("Leaving saslBind().");
  return function (id) {
    const ber = new BerWriter();
    ber.startSequence();
    ber.writeInt(id);
    ber.startSequence(0x60);
    ber.writeInt(3);
    ber.writeString(name || '');
    ber.startSequence(0xa3);
    ber.writeString(mechanism);
    if (credentials !== undefined) {
      ber.writeBuffer(Buffer.from(credentials, 'utf8'), 0x04);
    }
    ber.endSequence();
    ber.endSequence();
    ber.endSequence();
    return ber.buffer;
  };
}

function baseSearch(dn) {
  log.debug("Entering baseSearch().");
  const messages = require(ROOT + '/node_modules/@ldapjs/messages');
  const filters = require(ROOT + '/node_modules/@ldapjs/filter');
  log.debug("Leaving baseSearch().");
  return function (id) {
    return new messages.SearchRequest({
      messageId: id, baseObject: dn, scope: 'base',
      filter: new filters.PresenceFilter({ attribute: 'objectClass' }),
      attributes: ['uid']
    }).toBer().buffer;
  };
}

function ldaps(port, credential) {
  log.debug("Entering ldaps(). " + port);
  const socket = tls.connect(Object.assign({
    host: '127.0.0.1', port: port, rejectUnauthorized: false
  }, credential ? { cert: credential.cert, key: credential.key } : {}));
  log.debug("Leaving ldaps().");
  return new Promise(function (resolve) {
    const conn = connection(socket);
    socket.once('secureConnect', function () { resolve(conn); });
    socket.once('error', function () { resolve(conn); });
  });
}

function plain(port) {
  log.debug("Entering plain(). " + port);
  const socket = net.connect(port, '127.0.0.1');
  log.debug("Leaving plain().");
  return new Promise(function (resolve) {
    const conn = connection(socket);
    socket.once('connect', function () { resolve(conn); });
    socket.once('error', function () { resolve(conn); });
  });
}

// One SASL bind on a fresh LDAPS connection: its answer, and the connection
// for whatever follows.
async function bindOnce(port, credential, mechanism, authzId, name) {
  log.debug("Entering bindOnce().");
  const conn = await ldaps(port, credential);
  const answer = await conn.send(saslBind(mechanism, authzId, name));
  log.debug("Leaving bindOnce().");
  return { conn: conn, answer: answer };
}

// An outside certificate authority and a leaf it issued, with clientAuth
// and a urn:sts:person: name — everything this service's own would carry
// except the issuer.
function outsideCertificate(dir, person) {
  log.debug("Entering outsideCertificate().");
  const run = function (args, input) {
    const r = childProcess.spawnSync('openssl', args, { cwd: dir,
      encoding: 'utf8', input: input });
    if (r.status !== 0) {
      throw new Error('openssl ' + args[0] + ': ' + r.stderr);
    }
  };
  fs.writeFileSync(path.join(dir, 'ext.cnf'),
    '[ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=keyCertSign,cRLSign\n' +
    '[leaf]\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\n' +
    'extendedKeyUsage=clientAuth\nsubjectAltName=URI:urn:sts:person:' +
    person + '\n');
  run(['ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out',
       'ca.key']);
  run(['req', '-new', '-x509', '-key', 'ca.key', '-subj',
       '/CN=Outside Test CA', '-days', '2', '-out', 'ca.pem', '-extensions',
       'ca', '-config', 'ext.cnf']);
  run(['ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out',
       'leaf.key']);
  run(['req', '-new', '-key', 'leaf.key', '-subj', '/CN=' + person, '-out',
       'leaf.csr', '-config', 'ext.cnf']);
  run(['x509', '-req', '-in', 'leaf.csr', '-CA', 'ca.pem', '-CAkey',
       'ca.key', '-CAcreateserial', '-days', '1', '-out', 'leaf.pem',
       '-extfile', 'ext.cnf', '-extensions', 'leaf']);
  log.debug("Leaving outsideCertificate().");
  return {
    caPem: fs.readFileSync(path.join(dir, 'ca.pem'), 'utf8'),
    cert: fs.readFileSync(path.join(dir, 'leaf.pem'), 'utf8'),
    key: fs.readFileSync(path.join(dir, 'leaf.key'), 'utf8')
  };
}

// ---------------------------------------------------------------------------
// THE CHILD: the stack, a certificate authority, people and certificates,
// the listeners, and the assertions for its mode.
// ---------------------------------------------------------------------------
async function childBody() {
  log.debug("Entering childBody().");
  const t = recorder();
  const which = String(process.env.LSE_MODE || '');
  require(ROOT + '/common/protocol_stack');
  const keystore = require(ROOT + '/common/keystore');
  const pki = require(ROOT + '/common/pki');
  const helpers = require(ROOT + '/common/helpers');
  const config = require(ROOT + '/common/config');
  const realms = require(ROOT + '/common/realms');
  const audit = require(ROOT + '/common/audit');
  const ldap = require(ROOT + '/ldap/ldap_server');
  const applications = require(ROOT + '/common/applications');
  const accountState = require(ROOT + '/common/account_state');
  const tlsClient = require(ROOT + '/common/tls_client_certificates');
  const tlsServer = require(ROOT + '/tls/tls_server');

  await keystore.start();
  const otherId = 'lseother';
  const made = realms.create({ id: otherId, name: otherId,
                               description: 'Created by ' + __filename });
  t.check(made.ok, 'precondition: a second realm exists',
          JSON.stringify(made.errors || ''));
  await pki.start({ realmIds: ['', otherId],
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
  await pki.ensureScope(realms.currentId());
  await pki.ensureScope(otherId);

  ldap.createUser('lsealice', { invent: false });
  ldap.createUser('lsebob', { invent: false });
  ldap.createUser('lsecarol', { invent: false });
  ldap.createUser('lsedave', { invent: false });
  ldap.createUser('lseerin', { invent: false });
  // frank holds no certificate this service issued: an outside one is
  // stored on his entry (#1061).
  ldap.createUser('lsefrank', { invent: false });
  const svc = applications.createApplication({ identifier: 'lsesvc',
    protocols: ['wstrust'], fields: { oauthClientId: 'lsesvc' } });
  t.check(svc && svc.ok, 'precondition: an application exists',
          JSON.stringify(svc));

  const issued = {};
  const issueFor = async function (key, spec, realmId) {
    log.debug("Entering issueFor(). " + key);
    const r = await tlsClient.issue(realmId,
      Object.assign({ label: key, keyAlg: 'ec-p256' }, spec));
    t.check(r.ok, 'precondition: a TLS client certificate for ' + key,
            JSON.stringify(r.errors || ''));
    issued[key] = r.ok ? {
      cert: r.issued.certificatePem + r.issued.chainPem.join(''),
      key: r.issued.privateKeyPem, serialHex: r.issued.serialHex
    } : null;
    log.debug("Leaving issueFor().");
  };
  await issueFor('alice', { username: 'lsealice' });
  await issueFor('alice2', { username: 'lsealice' });
  await issueFor('carol', { username: 'lsecarol' });
  await issueFor('dave', { username: 'lsedave' });
  await issueFor('svc', { kind: 'application', application: 'lsesvc' });
  await realms.run(realms.get(otherId), async function () {
    ldap.createUser('lsealice', { invent: false });
    await issueFor('other', { username: 'lsealice' }, otherId);
  });
  // dave's entry goes, his certificate stays on the register.
  const daveDn = ldap.existingUserEntry('lsedave').dn;

  const aliceDn = ldap.existingUserEntry('lsealice').dn;
  const bobDn = ldap.existingUserEntry('lsebob').dn;

  const ready = await ldap.listen().whenReady;
  tlsServer.reapplyTruststore();
  const port = ready.ldapsPort;
  t.check(!!port, 'precondition: LDAPS is listening', JSON.stringify(ready));

  // RULE 7: the service page (and its /admin-api mirror, the same view)
  // says which mode 636 is in and whether a certificate bind is available.
  const view = ldap.ldapServiceView({ get: function () {
    return 'localhost';
  } }).json.tls;
  const expectedMode = which === 'defaults' ? 'none' : which;
  t.check(view.clientCertificateMode === expectedMode &&
          view.saslExternal.available === (expectedMode !== 'none') &&
          view.saslExternal.outsideCertificateAuthorities === true &&
          /SASL EXTERNAL/.test(view.clientCertificates) &&
          /outside/.test(view.saslExternal.rule),
          'the service page says 636 is in "' + expectedMode + '" mode and ' +
          'that SASL EXTERNAL is ' +
          (expectedMode === 'none' ? 'not available' : 'available'),
          JSON.stringify(view));

  // The code an LDAP refusal was recorded with, newest first, in any realm.
  const coded = function (code) {
    log.debug("Entering coded(). " + code);
    const seen = ['', otherId].some(function (id) {
      return realms.run(realms.get(id) || realms.DEFAULT_REALM, function () {
        return audit.list().some(function (row) {
          return row && row.errorCode === code;
        });
      });
    });
    log.debug("Leaving coded().");
    return seen;
  };
  const brief = function (answer) {
    log.debug("Entering brief().");
    log.debug("Leaving brief().");
    return JSON.stringify(answer);
  };
  const refused = async function (label, credential, status, code, opts) {
    log.debug("Entering refused(). " + label);
    const o = opts || {};
    const got = await bindOnce(port, credential, o.mechanism || 'EXTERNAL',
                               o.authzId, o.name);
    got.conn.end();
    t.check(got.answer.status === status && coded(code),
            label + ' is refused with ' + status + ', ' + code,
            brief(got.answer));
    log.debug("Leaving refused().");
  };

  if (which === 'optional') {
    // -----------------------------------------------------------------------
    // A1. THE CERTIFICATE BINDS ITS PERSON
    // -----------------------------------------------------------------------
    let got = await bindOnce(port, issued.alice, 'EXTERNAL');
    t.check(got.answer.status === 0,
            'A1. alice\'s certificate binds with SASL EXTERNAL and an empty ' +
            'name', brief(got.answer));
    const bound = ldap.boundConnections().filter(function (row) {
      return String(row.dn || '').toLowerCase() === aliceDn.toLowerCase();
    });
    t.check(bound.length === 1,
            'A1. the connection is bound as her entry, ' + aliceDn,
            JSON.stringify(ldap.boundConnections()));
    config.setOverride('global.mode', 'product');
    try {
      const read = await got.conn.send(baseSearch(aliceDn));
      t.check(read.status === 0 && read.entries.length === 1 &&
              read.entries[0].toLowerCase() === aliceDn.toLowerCase(),
              'A1. product: bound, a search of her own entry answers it',
              brief(read));
      const anon = await ldaps(port, issued.alice);
      const unbound = await anon.send(baseSearch(aliceDn));
      anon.end();
      t.check(unbound.status === 50,
              'A1. product: the same search unbound is refused (50)',
              brief(unbound));
    } finally {
      config.clearOverride('global.mode');
    }
    got.conn.end();
    got = await bindOnce(port, issued.alice, 'EXTERNAL', 'dn:' + aliceDn);
    got.conn.end();
    t.check(got.answer.status === 0, 'A1. with her own dn: authzId',
            brief(got.answer));
    got = await bindOnce(port, issued.alice, 'EXTERNAL', 'u:lsealice');
    got.conn.end();
    t.check(got.answer.status === 0, 'A1. with her own u: authzId',
            brief(got.answer));
    got = await bindOnce(port, issued.alice, 'EXTERNAL', undefined, aliceDn);
    got.conn.end();
    t.check(got.answer.status === 0, 'A1. with her own DN as the bind name',
            brief(got.answer));

    // -----------------------------------------------------------------------
    // A2. REFUSALS
    // -----------------------------------------------------------------------
    await refused('A2. an authzId naming bob (dn:)', issued.alice, 50,
                  'STS-LDAP-0189', { authzId: 'dn:' + bobDn });
    await refused('A2. an authzId naming bob (u:)', issued.alice, 50,
                  'STS-LDAP-0189', { authzId: 'u:lsebob' });
    await refused('A2. an authzId in neither form', issued.alice, 50,
                  'STS-LDAP-0189', { authzId: 'lsealice' });
    await refused('A2. a bind name naming bob', issued.alice, 49,
                  'STS-LDAP-0190', { name: bobDn });
    await refused('A2. EXTERNAL with no certificate', null, 48,
                  'STS-LDAP-0179');
    await refused('A2. a mechanism other than EXTERNAL', issued.alice, 7,
                  'STS-LDAP-0178', { mechanism: 'PLAIN',
                                     authzId: '\u0000lsealice\u0000x' });
    const onPlain = await plain(ready.port);
    const plainAnswer = await onPlain.send(saslBind('EXTERNAL'));
    onPlain.end();
    t.check(plainAnswer.status === 48 && coded('STS-LDAP-0180'),
            'A2. EXTERNAL on the plain listener (389) is refused with 48, ' +
            'STS-LDAP-0180', brief(plainAnswer));
    await refused('A2. an application\'s certificate', issued.svc, 49,
                  'STS-LDAP-0185');
    // AN OUTSIDE AUTHORITY'S CERTIFICATE (#1061): it binds as the one
    // person entry storing it in userCertificate, and as nobody else — not
    // as alice, whom its CN and urn:sts:person: name.
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lse-'));
    const dir2 = fs.mkdtempSync(path.join(os.tmpdir(), 'lse-'));
    try {
      const outside = outsideCertificate(dir, 'lsealice');
      const renewed = outsideCertificate(dir2, 'lsealice');
      const added = tlsServer.addAnchors(outside.caPem + renewed.caPem);
      t.check(added && added.added === 2,
              'precondition: two outside authorities are in the truststore',
              JSON.stringify(added));
      await refused('A2. a certificate from an outside authority, naming ' +
                    'alice and stored on no entry', outside, 49,
                    'STS-LDAP-0192');
      const nodeCryptoOut = require('crypto');
      const outsideDer = new nodeCryptoOut.X509Certificate(outside.cert).raw;
      const stored = ldap.changeStoredCertificate('person', 'lsefrank',
                                                  { add: outsideDer });
      t.check(stored && stored.ok && stored.changed,
              'precondition: the outside certificate is stored on frank',
              JSON.stringify(stored));
      const frankDn = ldap.existingUserEntry('lsefrank').dn;
      let viaStored = await bindOnce(port, outside, 'EXTERNAL');
      const boundAs = ldap.boundConnections().map(function (row) {
        return String(row.dn || '').toLowerCase();
      });
      viaStored.conn.end();
      t.check(viaStored.answer.status === 0,
              'A2b. stored on frank\'s entry, it binds — as frank',
              brief(viaStored.answer));
      t.check(boundAs.indexOf(frankDn.toLowerCase()) >= 0,
              'A2b. the connection is bound as frank\'s entry, not alice\'s',
              JSON.stringify(ldap.boundConnections()));
      viaStored = await bindOnce(port, outside, 'EXTERNAL', 'u:lsefrank');
      viaStored.conn.end();
      t.check(viaStored.answer.status === 0,
              'A2b. with frank\'s own u: authzId', brief(viaStored.answer));
      await refused('A2b. the stored certificate with an authzId naming ' +
                    'alice', outside, 50, 'STS-LDAP-0189',
                    { authzId: 'u:lsealice' });
      await refused('A2b. a renewed certificate with the same subject, not ' +
                    'stored', renewed, 49, 'STS-LDAP-0192');
      ldap.changeStoredCertificate('person', 'lsebob', { add: outsideDer });
      await refused('A2b. the certificate stored on two entries', outside,
                    49, 'STS-LDAP-0193');
      ldap.changeStoredCertificate('person', 'lsebob',
        { remove: nodeCryptoOut.createHash('sha256').update(outsideDer)
          .digest('hex') });
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
      fs.rmSync(dir2, { recursive: true, force: true });
    }
    await refused('A2. another realm\'s certificate held to this realm\'s ' +
                  'DN', issued.other, 49, 'STS-LDAP-0184',
                  { authzId: 'dn:' + aliceDn });
    got = await bindOnce(port, issued.other, 'EXTERNAL');
    got.conn.end();
    t.check(got.answer.status === 0,
            'A2. the same certificate with no name binds in its own realm',
            brief(got.answer));
    const deleted = await ldap.performOperation('del',
      { dn: daveDn, boundDn: '', channel: 'ldaps', remoteAddress: '' });
    t.check(deleted && deleted.ok,
            'precondition: dave\'s entry is deleted', JSON.stringify(deleted));
    await refused('A2. a person with no entry', issued.dave, 49,
                  'STS-LDAP-0187');
    const off = accountState.setDisabled('lsecarol', true);
    t.check(off && off.ok !== false, 'precondition: carol is disabled',
            JSON.stringify(off));
    await refused('A2. a disabled person', issued.carol, 49,
                  'STS-LDAP-0188');
    const revoked = tlsClient.revoke('', 'lsealice', issued.alice2.serialHex,
                                     'keyCompromise');
    t.check(revoked && revoked.ok, 'precondition: alice\'s second ' +
            'certificate is revoked', JSON.stringify(revoked));
    await refused('A2. a revoked certificate', issued.alice2, 49,
                  'STS-LDAP-0181');

    // -----------------------------------------------------------------------
    // A3. AS A REQUEST WORKER RUNS IT
    // -----------------------------------------------------------------------
    const status = require(ROOT + '/common/revocation_status');
    const nodeCrypto = require('crypto');
    const pems = issued.alice.cert.match(
      /-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/g);
    const ders = pems.map(function (pem) {
      return new nodeCrypto.X509Certificate(pem).raw;
    });
    const request = {
      dn: null, authentication: 'sasl',
      mechanism: 'EXTERNAL', saslCredentials: null, credentials: '',
      connection: { encrypted: true, remoteAddress: '127.0.0.1',
                    ldap: { bindDN: 'cn=anonymous' } },
      stsExternal: { certificate: { leaf: ders[0], chain: ders.slice(1),
                                    verified: true },
                     revocation: { refused: false, why: '', code: '' } }
    };
    const shape = ldap.operationRequest('bind', request);
    const viaShape = JSON.parse(JSON.stringify(shape));
    t.check(viaShape.sasl && viaShape.sasl.mechanism === 'EXTERNAL' &&
            viaShape.sasl.external && viaShape.sasl.external.certificate &&
            typeof viaShape.sasl.external.certificate.leaf === 'string',
            'A3. the dispatched bind carries the mechanism and the ' +
            'certificate', JSON.stringify(viaShape).slice(0, 300));
    const outcome = await ldap.performOperation('bind', viaShape);
    t.check(outcome && outcome.ok &&
            String(outcome.bindDN).toLowerCase() === aliceDn.toLowerCase(),
            'A3. a worker binds alice from the shape, and names her DN for ' +
            'the front process', JSON.stringify(outcome));
    const realRes = { ended: false, end: function () { this.ended = true; } };
    ldap.applyOperationResult('bind', { connection: null }, realRes,
                              function () {}, outcome);
    t.check(realRes.ended && realRes.bindDN === outcome.bindDN,
            'A3. the front process sets it on the real response, where ' +
            'node-ldapjs reads it', JSON.stringify(realRes));
    const revokedShape = JSON.parse(JSON.stringify(shape));
    revokedShape.sasl.external.revocation = { refused: true, why: 'test',
                                              code: '' };
    const refusedOutcome = await ldap.performOperation('bind', revokedShape);
    t.check(refusedOutcome && !refusedOutcome.ok &&
            refusedOutcome.errorName === 'InvalidCredentialsError',
            'A3. and the verdict read in the front process is the one the ' +
            'worker obeys', JSON.stringify(refusedOutcome));
    t.check(typeof status.fromSocket === 'function', 'A3. (the reader ' +
            'the front process uses is revocation_status.fromSocket())');
  } else if (which === 'required') {
    // -----------------------------------------------------------------------
    // B. REQUIRED
    // -----------------------------------------------------------------------
    const without = await bindOnce(port, null, 'EXTERNAL');
    without.conn.end();
    t.check(!!without.answer.closed,
            'B. required: a connection without a certificate is refused at ' +
            'the handshake', brief(without.answer));
    const got = await bindOnce(port, issued.alice, 'EXTERNAL');
    got.conn.end();
    t.check(got.answer.status === 0,
            'B. required: alice\'s certificate binds with SASL EXTERNAL',
            brief(got.answer));
  } else {
    // -----------------------------------------------------------------------
    // C. THE DEFAULTS
    // -----------------------------------------------------------------------
    await refused('C. at the defaults 636 asks for nothing, so EXTERNAL ' +
                  'with a certificate in hand', issued.alice, 48,
                  'STS-LDAP-0179');
  }
  log.debug("Leaving childBody().");
  return t.rows;
}

function spawnChild(which, env) {
  log.debug("Entering spawnChild(). " + which);
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(KRB5_|STS_|LDAP_|LDAPS_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const out = path.join(os.tmpdir(), 'lse-' + process.pid + '-' + which +
                        '-' + Date.now() + '.json');
  Object.assign(clean, env, { LSE_MODE: which, LSE_OUT: out,
                              LOG_LEVEL: 'fatal',
                              STS_LOG_LEVEL: 'fatal', STS_HOST: '127.0.0.1',
                              LDAP_PORT: '0', LDAPS_PORT: '0' });
  clean[CHILD_FLAG] = '1';
  const result = childProcess.spawnSync(process.execPath, [__filename], {
    cwd: ROOT, env: clean, encoding: 'utf8', timeout: 300000,
    maxBuffer: 64 * 1024 * 1024
  });
  let rows = null;
  try {
    rows = JSON.parse(fs.readFileSync(out, 'utf8'));
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in spawnChild(): " + ((e && e.message) || e));
    rows = null;
  }
  if (!rows) {
    log.debug("Leaving spawnChild(). No result.");
    return { error: 'the ' + which + ' child produced no result (exit ' +
                    result.status + '): ' +
                    String(result.stderr || '').slice(-1500) };
  }
  log.debug("Leaving spawnChild().");
  return { rows: rows };
}

function run(t) {
  log.debug("Entering run().");
  const children = [
    ['optional', { STS_LDAPS_DISABLE_OPTIONAL_CLIENT_CERT: 'false' }],
    ['required', { STS_LDAPS_REQUIRE_CLIENT_CERT: 'true' }],
    ['defaults', {}]
  ];
  children.forEach(function (one) {
    t.log.info('=== ' + one[0] + ' ===');
    const got = spawnChild(one[0], one[1]);
    if (!t.check(!got.error, one[0] + ': the child ran', got.error)) {
      return;
    }
    got.rows.forEach(function (row) {
      t.check(row.ok, one[0] + ': ' + row.what, row.detail);
    });
  });
  log.debug("Leaving run().");
}

if (process.env[CHILD_FLAG] === '1' && require.main === module) {
  childBody().then(function (rows) {
    fs.writeFileSync(process.env.LSE_OUT, JSON.stringify(rows));
    process.exit(0);
  }, function (e) {
    process.stderr.write('child failed: ' + String((e && e.stack) || e) +
                         '\n');
    process.exit(1);
  });
}

module.exports = {
  name: 'ldap_sasl_external',
  describe: 'LDAP: SASL EXTERNAL over LDAPS binds the person a certificate ' +
            'this service issued names, exactly when 636 asks for one, and ' +
            'refuses everything else with its own code (#1047)',
  run: run
};
