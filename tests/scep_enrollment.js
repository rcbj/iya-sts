'use strict';
//
// File: scep_enrollment.js
//
// ===========================================================================
// SCEP (RFC 8894), IN PROCESS: THE CMS CODEC, THE RA CERTIFICATE, THE HANDLER,
// THE CONSOLE MODEL AND THE STORES' REALM BOUNDARY (2026-09-13).
//
// `tests/vendored/sts_scep_enrollment.js` drives the protocol over HTTP with an
// independent client and holds everything a device can see. What is here is
// the half it cannot:
//
//   1. THE CODEC ONE STRUCTURE AT A TIME — a signed attribute changed after
//      signing, a messageDigest over other content, a trailing byte, a short
//      nonce, OAEP key transport (which the independent client, being forge,
//      cannot produce), and a garbled envelope answering exactly as a wrong
//      key does. Over HTTP each of those is one FAILURE among many; here each
//      is the one refusal code it must be.
//   2. THE RA CERTIFICATE'S LIFE — issued on demand, re-issued when
//      `scep.raKeyAlgorithm` changes, the one it replaces put on the SCEP
//      Issuing CA's list as superseded, and no private key in any view.
//   3. THE TRANSACTION STORE PER REALM — a transactionID completed in one realm
//      is unknown in another, which no single realm's HTTP view can show.
//   4. THE CONSOLE MODEL — the six actions' validation, a challenge shown once
//      and listed without its secret, the page's JSON being the view's, and
//      the OpenAPI request schema naming exactly the fields the zod schema
//      reads (the third statement of one shape, see scep_console.js).
//   5. THE failInfo EVERY CORE CODE MAPS TO.
//
// The messages are built with `tests/vendored/scep_client.js` — the protocol
// job's own client — rather than with `scep/scep_cms.ts`, for that job's
// reason: a codec checked against itself agrees with itself. It is one of the
// few requires from `tests/` into `tests/vendored/`, and the first of them is
// argued in `tests/saml_assertion_grant.js` on the same ground.
//
// The in-process server is `common/app.js` on an ephemeral port; the realm it
// creates is removed in a `finally`, and every setting it touches is cleared.
// ===========================================================================

delete process.env.CONFIG_FILE;

const http = require('http');
const nodeCrypto = require('crypto');
const forge = require('node-forge');

const app = require('../common/app');
const config = require('../common/config');
const errorCodes = require('../common/error_codes');
const pki = require('../common/pki');
const realms = require('../common/realms');
const ldap = require('../ldap/ldap_server');
const core = require('../common/cert_enrollment');
const revocation = require('../common/pki_revocation');
require('../scep/scep');
const cms = require('../scep/scep_cms');
const ra = require('../scep/scep_ra');
const scepModule = require('../scep/scep');
// Loading a module registers nothing since #50's R1; the composition root
// (`common/protocol_stack.ts`) does, so a test that loads one module
// registers its routes itself.
scepModule.registerRoutes(app);
require('../scep/scep_admin').registerRoutes(app);
const consoleModel = require('../scep/scep_console');
const api = require('../scep/scep_api');
const client = require('./vendored/scep_client');

const log = require('bunyan').createLogger({ name: 'scep_enrollment',
  level: process.env.LOG_LEVEL || 'info' });

const RUN = nodeCrypto.randomBytes(3).toString('hex');
const ALICE = 'scep-alice-' + RUN;
const REALM = 'scep-realm-' + RUN;

function inRealm(id, fn) {
  log.debug("Entering inRealm(). id=" + id);
  log.debug("Leaving inRealm().");
  return realms.run(realms.get(id), fn);
}

function withOverride(key, value, fn) {
  log.debug("Entering withOverride(). key=" + key);
  const set = config.setOverride(key, value);
  if (set && set.ok === false) {
    throw new Error('could not set ' + key + ': ' + JSON.stringify(set));
  }
  const done = function () {
    log.debug("Entering done().");
    config.clearOverride(key);
    log.debug("Leaving done().");
  };
  log.debug("Leaving withOverride().");
  return Promise.resolve().then(fn).then(function (out) {
    done();
    return out;
  }, function (error) {
    done();
    throw error;
  });
}

function device() {
  log.debug("Entering device().");
  const key = client.rsaKey(2048);
  log.debug("Leaving device().");
  return { key: key, certPem: client.selfSigned(key, ALICE) };
}

function message(dev, raPem, extra) {
  log.debug("Entering message().");
  const opts = extra || {};
  const nonce = opts.nonce || nodeCrypto.randomBytes(16);
  const content = opts.envelope ||
    client.envelope(opts.inner || client.csr(dev.key, { challenge: 'x.y' }),
                    raPem, opts.cipher);
  log.debug("Leaving message().");
  return {
    nonce: nonce,
    der: client.signedMessage({
      content: content, signerCertPem: dev.certPem,
      signerKeyPem: dev.key.privateKeyPem,
      messageType: opts.messageType || '19',
      transactionID: opts.txid || 'tx-' + RUN, senderNonce: nonce,
      digest: opts.digest })
  };
}

// ---------------------------------------------------------------------------
// 1. THE CODEC.
// ---------------------------------------------------------------------------
async function checkCodec(t, keys) {
  log.debug("Entering checkCodec().");
  t.log.info('=== 1. the CMS codec, one structure at a time ===');
  const dev = device();
  const built = message(dev, keys.certificatePem, { txid: 'codec-1' });
  const parsed = cms.parsePkiMessage(built.der);
  t.check(parsed.ok && parsed.transactionID === 'codec-1' &&
          parsed.messageType === 19 && parsed.senderNonce.equals(built.nonce),
          'a pkiMessage is read: transactionID, messageType and senderNonce',
          JSON.stringify({ ok: parsed.ok, why: parsed.why }));
  t.check(cms.verifySigner(parsed).ok, 'and its signature verifies');

  // A signed attribute changed after signing: the messageType "19" -> "18".
  const changed = Buffer.from(built.der);
  const at = changed.indexOf(Buffer.from([0x13, 0x02, 0x31, 0x39]));
  changed[at + 3] = 0x38;
  const reread = cms.parsePkiMessage(changed);
  t.equal(reread.ok && cms.verifySigner(reread).code, 'STS-SCEP-0023',
          'a signed attribute altered after signing is STS-SCEP-0023');

  const otherContent = client.signedMessage({
    content: Buffer.from('other'), signerCertPem: dev.certPem,
    signerKeyPem: dev.key.privateKeyPem, messageType: '19',
    transactionID: 'codec-2', senderNonce: built.nonce });
  const swapped = cms.parsePkiMessage(otherContent);
  swapped.content = Buffer.from('not what was digested');
  t.equal(cms.verifySigner(swapped).code, 'STS-SCEP-0022',
          'content that is not what the messageDigest names is STS-SCEP-0022');

  const sha1 = cms.parsePkiMessage(message(dev, keys.certificatePem,
                                           { digest: 'sha1' }).der);
  t.equal(cms.verifySigner(sha1).code, 'STS-SCEP-0020',
          'a SHA-1 digest is refused badAlg (STS-SCEP-0020)');
  t.equal(cms.parsePkiMessage(Buffer.concat([built.der, Buffer.from([0])]))
    .code, 'STS-SCEP-0010', 'a trailing byte after the message is refused');
  t.equal(cms.parsePkiMessage(Buffer.from('garbage')).stage, 'http',
          'bytes that are not CMS are an HTTP refusal, not a CertRep');
  const short = cms.parsePkiMessage(message(dev, keys.certificatePem,
    { nonce: nodeCrypto.randomBytes(8) }).der);
  t.check(short.code === 'STS-SCEP-0012' && short.stage === 'http',
          'an eight-byte senderNonce cannot be echoed and is an HTTP refusal');

  // The request message() sealed: the same key, the same challenge.
  const csrDer = client.csr(dev.key, { challenge: 'x.y' });
  const opened = cms.openEnvelope(parsed.content, keys.certificatePem,
                                  keys.privateKeyPem);
  t.check(opened.ok && opened.content.equals(csrDer) &&
          opened.transport === 'rsaEncryption',
          'the envelope opens to the PKCS#10 the client sealed (PKCS#1 v1.5)');
  const wrong = client.envelope(csrDer, dev.certPem);
  t.equal(cms.openEnvelope(wrong, keys.certificatePem, keys.privateKeyPem)
    .code, 'STS-SCEP-0027', 'an envelope for another recipient is 0027');
  t.equal(cms.openEnvelope(client.envelope(csrDer, keys.certificatePem,
                                           'des3'),
                           keys.certificatePem, keys.privateKeyPem).code,
          'STS-SCEP-0029', 'DES-EDE3-CBC is refused badAlg (0029)');

  // The encrypted key replaced by random bytes of the same length: PKCS#1
  // v1.5 unwrapping fails, and the answer must be the one a wrong key gives.
  const tree = forge.asn1.fromDer(
    client.envelope(csrDer, keys.certificatePem).toString('binary'));
  const recipient = tree.value[1].value[0].value[1].value[0];
  recipient.value[3].value = nodeCrypto.randomBytes(
    recipient.value[3].value.length).toString('binary');
  const garbled = Buffer.from(forge.asn1.toDer(tree).getBytes(), 'binary');
  const implicit = cms.openEnvelope(garbled, keys.certificatePem,
                                    keys.privateKeyPem);
  t.equal(implicit.code, 'STS-SCEP-0030',
          'a key that will not unwrap is "did not decrypt", never a padding ' +
          'error — the implicit rejection');

  // OAEP, which forge's envelope cannot make: the same envelope with the
  // content key re-wrapped under RSAES-OAEP (SHA-1 by default).
  const cek = forge.random.getBytesSync(32);
  const p7 = forge.pkcs7.createEnvelopedData();
  p7.addRecipient(forge.pki.certificateFromPem(keys.certificatePem));
  p7.content = forge.util.createBuffer(csrDer.toString('binary'));
  p7.encrypt(forge.util.createBuffer(cek), forge.pki.oids['aes256-CBC']);
  const oaepTree = p7.toAsn1();
  const rid = oaepTree.value[1].value[0].value[1].value[0];
  rid.value[2] = forge.asn1.create(forge.asn1.Class.UNIVERSAL,
    forge.asn1.Type.SEQUENCE, true, [
      forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false,
                        forge.asn1.oidToDer('1.2.840.113549.1.1.7').getBytes()),
      forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE,
                        true, [])]);
  rid.value[3].value = nodeCrypto.publicEncrypt({
    key: keys.certificatePem, padding: nodeCrypto.constants
      .RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha1' },
  Buffer.from(cek, 'binary')).toString('binary');
  const oaep = cms.openEnvelope(Buffer.from(forge.asn1.toDer(oaepTree)
    .getBytes(), 'binary'), keys.certificatePem, keys.privateKeyPem);
  t.check(oaep.ok && oaep.content.equals(csrDer) &&
          oaep.transport === 'rsaesOaep-sha1',
          'RSAES-OAEP key transport opens too', JSON.stringify(oaep.why));

  const inner = cms.certsOnly([keys.certificatePem]);
  const rep = cms.certRep({
    raCertificatePem: keys.certificatePem, raPrivateKeyPem: keys.privateKeyPem,
    transactionID: 'codec-1', recipientNonce: built.nonce,
    pkiStatus: cms.PKI_STATUS.SUCCESS,
    content: cms.envelope(inner, dev.certPem, '2.16.840.1.101.3.4.1.2') });
  const read = client.readCertRep(rep, keys.certificatePem);
  t.check(read.signatureVerifies && read.digestMatches &&
          read.pkiStatus === '0' && read.messageType === '3' &&
          read.recipientNonce.equals(built.nonce) &&
          read.transactionID === 'codec-1',
          'a CertRep the independent client reads, verifies and echoes');
  const openedReply = client.openReply(read.content, dev.key, dev.certPem);
  t.check(client.certsOnly(openedReply.inner).certificates[0] ===
          keys.certificatePem &&
          openedReply.cipher === '2.16.840.1.101.3.4.1.2',
          'and its envelope opens with the requester key, in the cipher asked');
  const failure = client.readCertRep(cms.certRep({
    raCertificatePem: keys.certificatePem, raPrivateKeyPem: keys.privateKeyPem,
    transactionID: 'codec-1', recipientNonce: built.nonce,
    pkiStatus: cms.PKI_STATUS.FAILURE, failInfo: cms.FAIL_INFO.badCertId }),
    keys.certificatePem);
  t.check(failure.pkiStatus === '2' && failure.failInfoName === 'badCertId' &&
          failure.content === null && failure.signatureVerifies,
          'a FAILURE CertRep carries its failInfo and no content');
  const ias = cms.readIssuerAndSerial(client.issuerAndSerial(
    keys.certificatePem));
  t.equal(ias && ias.serialHex.replace(/^0+/, ''),
          new nodeCrypto.X509Certificate(keys.certificatePem).serialNumber
            .toLowerCase().replace(/^0+/, ''),
          'an IssuerAndSerialNumber is read back to the serial');
  log.debug("Leaving checkCodec().");
}

// ---------------------------------------------------------------------------
// 2. THE RA CERTIFICATE.
// ---------------------------------------------------------------------------
async function checkRa(t) {
  log.debug("Entering checkRa().");
  t.log.info('=== 2. the RA certificate: on demand, re-issued, superseded ===');
  const realmId = realms.currentId();
  const first = await ra.ensure(realmId);
  const x = new nodeCrypto.X509Certificate(first.certificatePem);
  const chain = core.caChainOf('scep');
  t.check(first.ok && x.publicKey.asymmetricKeyType === 'rsa' &&
          x.verify(new nodeCrypto.X509Certificate(chain.issuingPem).publicKey),
          'the RA certificate is an RSA leaf of the SCEP Issuing CA');
  const again = await ra.ensure(realmId);
  t.equal(again.record.serialHex, first.record.serialHex,
          'and a second use serves the same one');
  const described = JSON.stringify(ra.describe(realmId));
  t.check(described.indexOf('PRIVATE KEY') < 0 &&
          described.indexOf(first.record.serialHex) >= 0,
          'describe() carries the certificate and no private key');
  await withOverride('scep.raKeyAlgorithm', 'rsa-3072', async function () {
    t.equal(ra.staleness(realmId, pki.certificateFor(realmId, 'scep',
                                                     ra.SLOT)),
            'algorithm', 'a different scep.raKeyAlgorithm makes it stale');
    const third = await ra.ensure(realmId);
    t.check(third.reissued === 'algorithm' &&
            new nodeCrypto.X509Certificate(third.certificatePem).publicKey
              .asymmetricKeyDetails.modulusLength === 3072,
            'and the next use re-issues it at 3072 bits');
    t.check(!!revocation.isRevoked(realmId, 'scep', first.record.serialHex),
            'the RA certificate it replaced is on the SCEP CA\'s list');
  });
  log.debug("Leaving checkRa().");
}

// ---------------------------------------------------------------------------
// 3. THE HANDLER, AND ITS STORE PER REALM.
// ---------------------------------------------------------------------------
async function listen() {
  log.debug("Entering listen().");
  const server = http.createServer(app).listen(0, '127.0.0.1');
  await new Promise(function (resolve) {
    server.on('listening', resolve);
  });
  log.debug("Leaving listen().");
  return server;
}

async function checkHandler(t, server) {
  log.debug("Entering checkHandler().");
  t.log.info('=== 3. the handler, and the transaction store per realm ===');
  const root = 'http://127.0.0.1:' + server.address().port;
  const url = root + '/enroll/scep';
  const caCert = await client.getCaCert(url);
  const made = core.createScepChallenge({
    target: { kind: 'person', id: ALICE }, profile: 'tls-client',
    createdBy: 'test' });
  const dev = device();
  const txid = 'handler-' + RUN;
  const built = message(dev, caCert.ra, { txid: txid,
    inner: client.csr(dev.key, { challenge: made.challenge }) });
  const r = await client.pkiOperation(url, built.der);
  const rep = client.readCertRep(r.body, caCert.ra);
  t.check(rep.pkiStatus === '0' && r.headers.get('cache-control') ===
          'no-store', 'a PKCSReq issues, no-store',
          rep.failInfoName + ' ' + r.status);
  const poll = message(dev, caCert.ra, { txid: txid, messageType: '20',
    inner: client.issuerAndSubject(caCert.certificates[1], ALICE) });
  const here = client.readCertRep((await client.pkiOperation(url, poll.der))
    .body, caCert.ra);
  t.equal(here.pkiStatus, '0', 'CertPoll for that transaction answers here');
  const bUrl = root + '/realm/' + REALM + '/enroll/scep';
  const bCa = await client.getCaCert(bUrl);
  const pollB = message(dev, bCa.ra, { txid: txid, messageType: '20',
    inner: client.issuerAndSubject(bCa.certificates[1], ALICE) });
  const there = client.readCertRep((await client.pkiOperation(bUrl, pollB.der))
    .body, bCa.ra);
  t.equal(there.failInfoName, 'badCertId',
          'and the same transactionID is unknown in another realm');
  t.check(bCa.ra !== caCert.ra, 'which has an RA certificate of its own');
  const caps = await client.getCaCaps(url);
  t.equal(caps.lines.join(','), scepModule.CAPABILITIES.join(','),
          'GetCACaps is the CAPABILITIES table');
  log.debug("Leaving checkHandler().");
}

// ---------------------------------------------------------------------------
// 4. THE CONSOLE MODEL AND THE API ROWS.
// ---------------------------------------------------------------------------
function fakeReq(query) {
  log.debug("Entering fakeReq().");
  log.debug("Leaving fakeReq().");
  return { query: query || {}, protocol: 'https', headers: { host: 'x.test' },
           get: function (name) {
             return String(name).toLowerCase() === 'host' ? 'x.test'
                                                          : undefined;
           } };
}

async function checkConsole(t) {
  log.debug("Entering checkConsole().");
  t.log.info('=== 4. the console model, the page JSON and the API rows ===');
  const unknown = await consoleModel.scepAction({ action: 'nope' }, {});
  t.equal(errorCodes.codeOf(unknown), 'STS-SCEP-0062',
          'an unknown action is STS-SCEP-0062');
  const bad = await consoleModel.scepAction(
    { action: 'create-challenge', kind: 'robot', identifier: ALICE }, {});
  t.equal(errorCodes.codeOf(bad), 'STS-SCEP-0061',
          'a body the schema refuses is STS-SCEP-0061');
  const refused = await consoleModel.scepAction(
    { action: 'create-challenge', kind: 'person', identifier: ALICE,
      profile: 'issuing-ca' }, { req: fakeReq() });
  t.equal(errorCodes.codeOf(refused), 'STS-ENROLL-0002',
          'a challenge for a refused profile is refused by the core');
  const made = await consoleModel.scepAction(
    { action: 'create-challenge', kind: 'person', identifier: ALICE,
      profile: 'email' }, { req: fakeReq(), actor: 'tester' });
  t.check(made.ok && /\.[A-Za-z0-9_-]{20,}$/.test(made.challenge) &&
          /sscep enroll -u https:\/\/x\.test\/enroll\/scep\/email/
            .test(made.hint),
          'create-challenge answers the challenge once with an sscep hint');
  const view = consoleModel.scepView(fakeReq({ per: '1000' }));
  const row = view.challenges.rows.filter(function (one) {
    return one.id === made.id;
  })[0];
  t.check(row && row.createdBy === 'tester' && row.profile === 'email' &&
          JSON.stringify(view).indexOf(made.challenge) < 0 &&
          JSON.stringify(view).indexOf('PRIVATE KEY') < 0,
          'the view lists it with no secret and no private key');
  t.check(view.profiles.length === 10 && view.refusedProfiles.length === 5 &&
          view.endpoints.getCaCert === 'https://x.test/enroll/scep' +
          '?operation=GetCACert', 'nine profiles and the device profile, five ' +
          'refused, absolute URLs');
  const route = (app._router || app.router).stack.filter(function (one) {
    return one.route && one.route.path === '/admin/scep' &&
           one.route.methods.get;
  })[0];
  let pageJson = null;
  const res = { headers: {}, locals: {},
    set: function (k, v) { res.headers[k] = v; return res; },
    status: function () { return res; },
    type: function () { return res; },
    send: function (body) { pageJson = body; return res; } };
  route.route.stack[0].handle(Object.assign(fakeReq({ format: 'json',
                                                      per: '1000' }),
                                            { path: '/admin/scep',
                                              originalUrl: '/admin/scep' }),
                              res, function () {});
  const page = JSON.parse(pageJson || '{}');
  delete page.protocolEndpoints;
  t.equal(JSON.stringify(Object.keys(page).sort()),
          JSON.stringify(Object.keys(view).sort()),
          'GET /admin/scep?format=json is the view the API answers with');
  const actionsRow = api.ROUTES.filter(function (one) {
    return one.actions;
  })[0];
  t.equal(actionsRow.actions.map(function (one) { return one.action; })
    .join(','), consoleModel.SCEP_ACTIONS.join(','),
          'the API documents exactly the six console actions');
  actionsRow.actions.forEach(function (one) {
    const documented = Object.keys(one.requestBody.properties || {}).sort();
    const read = Object.keys(consoleModel.ACTION_SCHEMAS[one.action].shape)
      .sort();
    t.equal(documented.join(','), read.join(','),
            one.action + ': the OpenAPI body names the fields the schema ' +
            'reads');
    t.check(one.requestBody.additionalProperties === false &&
            (one.requestBody.examples || []).length > 0,
            one.action + ': additionalProperties false, with an example');
  });
  const deleted = await consoleModel.scepAction(
    { action: 'delete-challenge', id: made.id }, {});
  t.check(deleted.ok && core.redeemScepChallenge(made.challenge).ok === false,
          'delete-challenge makes it unredeemable');
  log.debug("Leaving checkConsole().");
}

// ---------------------------------------------------------------------------
// 5. failInfo.
// ---------------------------------------------------------------------------
function checkFailInfo(t) {
  log.debug("Entering checkFailInfo().");
  t.log.info('=== 5. every core refusal as a failInfo ===');
  const expect = { 'STS-ENROLL-0033': '1', 'STS-ENROLL-0032': '0',
                   'STS-ENROLL-0031': '0', 'STS-ENROLL-0018': '1',
                   'STS-ENROLL-0021': '2', 'STS-ENROLL-0083': '2',
                   'STS-ENROLL-0003': '2', 'STS-ENROLL-0051': '2' };
  Object.keys(expect).forEach(function (code) {
    t.equal(scepModule.failInfoForCore(code), expect[code],
            code + ' is failInfo ' + expect[code]);
  });
  log.debug("Leaving checkFailInfo().");
}

async function run(t) {
  log.debug("Entering run().");
  if (!pki.hasRoot()) {
    await pki.start({});
  }
  await pki.ensureScope(realms.currentId());
  ldap.createUser(ALICE, { invent: false,
                           attributes: { mail: ALICE + '@example.com' } });
  const made = realms.create({ id: REALM, name: REALM,
                               description: 'Created by ' + __filename,
                               overrides: {} });
  if (!made.ok) {
    throw new Error('could not create the realm: ' +
                    JSON.stringify(made.errors));
  }
  const server = await listen();
  try {
    await inRealm(REALM, async function () {
      await pki.ensureScope(REALM);
    });
    const keys = await ra.ensure(realms.currentId());
    await checkCodec(t, keys);
    await checkRa(t);
    await checkHandler(t, server);
    await checkConsole(t);
    checkFailInfo(t);
  } finally {
    server.close();
    if (realms.get(REALM)) {
      realms.remove(REALM);
    }
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'scep_enrollment',
  describe: 'SCEP in process: the CMS codec structure by structure, the RA ' +
            'certificate\'s life, the transaction store per realm, the ' +
            'console model and the API rows, and the failInfo of every core ' +
            'refusal.',
  run: run
};
