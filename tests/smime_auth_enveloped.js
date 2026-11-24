// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: smime_auth_enveloped.js
//
// ===========================================================================
// S/MIME MAIL AS AuthEnvelopedData UNDER AES-256-GCM (#2124, ASVS 5.0.0
// 11.3.3; RFC 5083, RFC 5084, RFC 8551 section 2.7).
//
// What `common/crypto.js` `smimeEnvelope()` writes is checked here by a
// reader that shares none of its code: the DER is taken apart with asn1js
// field by field, the RSA recipient's content key is opened with node's
// own RSA-OAEP, and the content with node's `aes-256-gcm` and the tag the
// structure carries. `openssl cms -decrypt` is the second, independent
// reader, and the only one for the EC recipient (its RFC 5753 KDF is not
// worth a third copy here). Then:
//
//   A. an RSA certificate: ContentInfo id-ct-authEnvelopedData, version 0,
//      a KeyTransRecipientInfo under RSAES-OAEP, id-aes256-GCM with a
//      12-octet nonce and aes-ICVlen 16, the mac 16 octets; opened by node
//      and by openssl;
//   B. ONE FLIPPED OCTET of the ciphertext, and one of the tag, are refused
//      by node's GCM and by openssl — the property CBC did not have;
//   C. an EC certificate: the same structure, a KeyAgreeRecipientInfo,
//      opened by openssl, refused tampered;
//   D. `aes256-cbc` still writes the pkijs EnvelopedData (id-envelopedData,
//      aes256-CBC), which openssl opens, and the names: `smimeTypeFor()`
//      and `smimeContentEncryption()`, anything unknown read as GCM;
//   E. an ML-KEM recipient (a fixed share, as `tests/smime_pqc.js` does): a
//      KEMRecipientInfo inside an AuthEnvelopedData of version 0, the
//      content key unwrapped with a KEK derived here, the content opened,
//      and refused tampered; and CBC still writes the version 3
//      EnvelopedData;
//   F. the composer labels the part from the same reading of the setting:
//      `smime-type=authEnveloped-data` by default, `enveloped-data` when the
//      message carries `aes256-cbc`;
//   G. the setting's enum refuses anything else, and `/admin/mode` carries
//      ASVS 5.0.0 11.3.3 on `smime-authenticated-encryption` in product
//      while it is `aes256-cbc`, and nowhere else.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const nodeCrypto = require('crypto');
const asn1js = require('asn1js');
const pkijs = require('pkijs');

const log = require('bunyan').createLogger({ name: 'smime_auth_enveloped',
  level: process.env.LOG_LEVEL || 'info' });

const ID_AUTH_ENVELOPED = '1.2.840.113549.1.9.16.1.23';
const ID_ENVELOPED = '1.2.840.113549.1.7.3';
const ID_DATA = '1.2.840.113549.1.7.1';
const AES256_GCM = '2.16.840.1.101.3.4.1.46';
const AES256_CBC = '2.16.840.1.101.3.4.1.42';
const RSAES_OAEP = '1.2.840.113549.1.1.7';
const ORI_KEM = '1.2.840.113549.1.9.16.13.3';
const KEM_OID = '2.16.840.1.101.3.4.4.2';
const MIME = Buffer.from('Content-Type: text/plain; charset=utf-8\r\n\r\n' +
                         'the text of #2124\r\n');

function openssl(args, input) {
  log.debug("Entering openssl().");
  const out = childProcess.execFileSync('openssl', args, {
    input: input, stdio: ['pipe', 'pipe', 'pipe'] });
  log.debug("Leaving openssl().");
  return out;
}

// A self-signed S/MIME certificate, made now.
function certificate(dir, kind) {
  log.debug("Entering certificate(). " + kind);
  const key = path.join(dir, kind + '.key');
  const cert = path.join(dir, kind + '.pem');
  openssl(['req', '-x509', '-nodes', '-days', '2', '-subj', '/CN=2124 ' +
           kind, '-addext', 'subjectAltName=email:ada@example.org',
           '-addext', 'extendedKeyUsage=emailProtection',
           '-keyout', key, '-out', cert].concat(kind === 'rsa'
             ? ['-newkey', 'rsa:2048']
             : ['-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256']));
  const der = openssl(['x509', '-in', cert, '-outform', 'DER']);
  log.debug("Leaving certificate().");
  return { key: key, cert: cert, der: der };
}

// What `openssl cms -decrypt` makes of a DER, or null when it refuses.
function opensslOpen(c, der) {
  log.debug("Entering opensslOpen().");
  try {
    const out = openssl(['cms', '-decrypt', '-inform', 'DER', '-inkey', c.key,
                         '-recip', c.cert], der);
    log.debug("Leaving opensslOpen().");
    return out;
  } catch (e) {
    log.debug("Caught in opensslOpen(): " + ((e && e.message) || e));
    log.debug("Leaving opensslOpen(). Refused.");
    return null;
  }
}

function bytes(block) {
  log.debug("Entering bytes().");
  log.debug("Leaving bytes().");
  return Buffer.from(block.valueBlock.valueHexView);
}

function oidOf(block) {
  log.debug("Entering oidOf().");
  log.debug("Leaving oidOf().");
  return block.valueBlock.toString();
}

// The ContentInfo taken apart: its type and, for an AuthEnvelopedData, each
// field RFC 5083 section 2.1 names.
function parse(der) {
  log.debug("Entering parse().");
  const read = asn1js.fromBER(new Uint8Array(der));
  if (read.offset === -1) {
    log.debug("Leaving parse(). Not BER.");
    throw new Error('not BER');
  }
  const info = read.result.valueBlock.value;
  const type = oidOf(info[0]);
  const body = info[1].valueBlock.value[0].valueBlock.value;
  if (type !== ID_AUTH_ENVELOPED) {
    log.debug("Leaving parse(). " + type);
    return { type: type, body: body };
  }
  const eci = body[2].valueBlock.value;
  const alg = eci[1].valueBlock.value;
  const params = alg[1].valueBlock.value;
  const out = {
    type: type,
    count: body.length,
    version: body[0].valueBlock.valueDec,
    recipients: body[1].valueBlock.value,
    contentType: oidOf(eci[0]),
    algorithm: oidOf(alg[0]),
    nonce: bytes(params[0]),
    icvLen: params[1] ? params[1].valueBlock.valueDec : 12,
    contentTag: { cls: eci[2].idBlock.tagClass,
                  number: eci[2].idBlock.tagNumber,
                  constructed: eci[2].idBlock.isConstructed },
    ciphertext: bytes(eci[2]),
    mac: bytes(body[3])
  };
  log.debug("Leaving parse().");
  return out;
}

// RFC 5084 by hand: AES-256-GCM, no AAD, the tag from `mac`.
function gcmOpen(cek, parsed, ciphertext, tag) {
  log.debug("Entering gcmOpen().");
  const d = nodeCrypto.createDecipheriv('aes-256-gcm', cek, parsed.nonce,
    { authTagLength: 16 });
  d.setAuthTag(tag || parsed.mac);
  const out = Buffer.concat([d.update(ciphertext || parsed.ciphertext),
                             d.final()]);
  log.debug("Leaving gcmOpen().");
  return out;
}

function refuses(fn) {
  log.debug("Entering refuses().");
  try {
    fn();
    log.debug("Leaving refuses(). Opened.");
    return false;
  } catch (e) {
    log.debug("Caught in refuses(): " + ((e && e.message) || e));
    log.debug("Leaving refuses().");
    return true;
  }
}

function flipped(buf, at) {
  log.debug("Entering flipped().");
  const out = Buffer.from(buf);
  out[at] ^= 0x01;
  log.debug("Leaving flipped().");
  return out;
}

// The DER with one octet of `part` flipped where it sits.
function tamper(der, part, at) {
  log.debug("Entering tamper().");
  const where = der.indexOf(part);
  log.debug("Leaving tamper().");
  return where < 0 ? null : flipped(der, where + at);
}

function checkStructure(t, label, p) {
  log.debug("Entering checkStructure().");
  t.equal(p.type, ID_AUTH_ENVELOPED, label + '1. the ContentInfo is ' +
          'id-ct-authEnvelopedData');
  t.check(p.version === 0 && p.count === 4, label + '2. version 0, and ' +
          'no originatorInfo, authAttrs or unauthAttrs', JSON.stringify(
            { version: p.version, count: p.count }));
  t.check(p.contentType === ID_DATA && p.algorithm === AES256_GCM,
          label + '3. id-data under id-aes256-GCM', p.algorithm);
  t.check(p.nonce.length === 12 && p.icvLen === 16 && p.mac.length === 16,
          label + '4. a 12-octet nonce, aes-ICVlen 16 and a 16-octet mac',
          JSON.stringify({ nonce: p.nonce.length, icv: p.icvLen,
                           mac: p.mac.length }));
  t.check(p.contentTag.cls === 3 && p.contentTag.number === 0 &&
          !p.contentTag.constructed && p.ciphertext.length === MIME.length,
          label + '5. the ciphertext is an IMPLICIT [0] OCTET STRING, the ' +
          'tag not appended to it', JSON.stringify(p.contentTag));
  log.debug("Leaving checkStructure().");
}

async function partsAtoD(t, crypto, dir) {
  log.debug("Entering partsAtoD().");
  // --- A. RSA ---------------------------------------------------------------
  const rsa = certificate(dir, 'rsa');
  const der = await crypto.smimeEnvelope(MIME, rsa.der);
  const p = parse(der);
  checkStructure(t, 'A', p);
  const ktri = p.recipients[0].valueBlock.value;
  t.check(p.recipients.length === 1 && ktri[0].valueBlock.valueDec === 0 &&
          oidOf(ktri[2].valueBlock.value[0]) === RSAES_OAEP,
          'A6. one KeyTransRecipientInfo under RSAES-OAEP');
  const cek = nodeCrypto.privateDecrypt({
    key: fs.readFileSync(rsa.key), oaepHash: 'sha256',
    padding: nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING }, bytes(ktri[3]));
  t.equal(cek.length, 32, 'A7. RSA-OAEP SHA-256 opens a 32-octet key');
  t.check(gcmOpen(cek, p).equals(MIME), 'A8. node\'s AES-256-GCM opens ' +
          'the content with the tag the mac carries');
  const viaOpenssl = opensslOpen(rsa, der);
  t.check(viaOpenssl !== null && viaOpenssl.equals(MIME),
          'A9. openssl cms -decrypt opens it');
  // --- B. tampered ----------------------------------------------------------
  t.check(refuses(function () {
    gcmOpen(cek, p, flipped(p.ciphertext, 3));
  }) && refuses(function () {
    gcmOpen(cek, p, null, flipped(p.mac, 0));
  }), 'B1. node refuses a flipped ciphertext octet and a flipped tag octet');
  const badBody = tamper(der, p.ciphertext, 3);
  const badTag = tamper(der, p.mac, 15);
  t.check(badBody !== null && opensslOpen(rsa, badBody) === null,
          'B2. openssl refuses the message with one ciphertext octet ' +
          'flipped');
  t.check(badTag !== null && opensslOpen(rsa, badTag) === null,
          'B3. and with one tag octet flipped');
  const again = await crypto.smimeEnvelope(MIME, rsa.der);
  t.check(!parse(again).nonce.equals(p.nonce),
          'B4. each message has a fresh nonce');
  // --- C. EC ----------------------------------------------------------------
  const ec = certificate(dir, 'ec');
  const ecDer = await crypto.smimeEnvelope(MIME, ec.der, 'aes256-gcm');
  const q = parse(ecDer);
  checkStructure(t, 'C', q);
  t.check(q.recipients.length === 1 &&
          q.recipients[0].idBlock.tagClass === 3 &&
          q.recipients[0].idBlock.tagNumber === 1,
          'C6. one KeyAgreeRecipientInfo, [1]');
  const ecOpened = opensslOpen(ec, ecDer);
  t.check(ecOpened !== null && ecOpened.equals(MIME),
          'C7. openssl cms -decrypt opens it');
  t.check(opensslOpen(ec, tamper(ecDer, q.ciphertext, 0)) === null,
          'C8. and refuses it tampered');
  // --- D. CBC, and the names -----------------------------------------------
  for (const c of [rsa, ec]) {
    const cbc = await crypto.smimeEnvelope(MIME, c.der, 'aes256-cbc');
    const r = parse(cbc);
    const eci = r.body[2].valueBlock.value;
    t.check(r.type === ID_ENVELOPED &&
            oidOf(eci[1].valueBlock.value[0]) === AES256_CBC,
            'D1. aes256-cbc: ' + path.basename(c.key) + ' gets the ' +
            'EnvelopedData under AES-256-CBC', r.type);
    const opened = opensslOpen(c, cbc);
    t.check(opened !== null && opened.equals(MIME),
            'D2. and openssl opens it');
  }
  t.check(crypto.smimeTypeFor('aes256-gcm') === 'authEnveloped-data' &&
          crypto.smimeTypeFor('aes256-cbc') === 'enveloped-data' &&
          crypto.smimeTypeFor(undefined) === 'authEnveloped-data',
          'D3. smimeTypeFor() names authEnveloped-data, enveloped-data ' +
          'for CBC alone');
  t.check(crypto.smimeContentEncryption('aes128-gcm') === 'aes256-gcm' &&
          crypto.smimeContentEncryption('') === 'aes256-gcm' &&
          crypto.smimeContentEncryption(' AES256-CBC ') === 'aes256-cbc',
          'D4. anything but aes256-cbc is read as GCM');
  t.check(JSON.stringify(crypto.SMIME_CONTENT_ENCRYPTIONS) ===
          '["aes256-gcm","aes256-cbc"]', 'D5. the two names, GCM first');
  log.debug("Leaving partsAtoD().");
  return rsa;
}

// A certificate carrying an ML-KEM-768 key of fixed octets: only its
// issuer, serial and key are read.
function kemCertificate() {
  log.debug("Entering kemCertificate().");
  const cert = new pkijs.Certificate();
  cert.version = 2;
  cert.serialNumber = new asn1js.Integer({ value: 2124 });
  const name = new pkijs.RelativeDistinguishedNames({
    typesAndValues: [new pkijs.AttributeTypeAndValue({
      type: '2.5.4.3', value: new asn1js.Utf8String({ value: 'Ada' }) })]
  });
  cert.issuer = name;
  cert.subject = name;
  cert.subjectPublicKeyInfo = new pkijs.PublicKeyInfo();
  cert.subjectPublicKeyInfo.algorithm = new pkijs.AlgorithmIdentifier({
    algorithmId: KEM_OID });
  cert.subjectPublicKeyInfo.subjectPublicKey = new asn1js.BitString({
    valueHex: new Uint8Array(1184).fill(3).buffer });
  log.debug("Leaving kemCertificate().");
  return cert;
}

function partE(t, crypto) {
  log.debug("Entering partE().");
  const row = { name: 'ML-KEM-768', publicBytes: 1184, cipherBytes: 1088,
                kekBytes: 32, wrap: 'id-aes256-wrap',
                wrapOid: '2.16.840.1.101.3.4.1.45', kem: 'ml_kem768' };
  const shared = Buffer.alloc(32, 4);
  const cek = Buffer.alloc(32, 9);
  const nonce = Buffer.alloc(12, 0x22);
  const cert = kemCertificate();
  const der = crypto.smimeKemAssemble(MIME, cert, row, KEM_OID, {
    cipherText: Buffer.alloc(1088, 0x5a), sharedSecret: shared, cek: cek,
    iv: nonce }, 'aes256-gcm');
  const p = parse(der);
  checkStructure(t, 'E', p);
  const ori = p.recipients[0];
  const kemri = ori.valueBlock.value[1].valueBlock.value;
  t.check(ori.idBlock.tagClass === 3 && ori.idBlock.tagNumber === 4 &&
          oidOf(ori.valueBlock.value[0]) === ORI_KEM,
          'E6. the recipient is an implicit [4] OtherRecipientInfo, ' +
          'id-ori-kem');
  t.check(p.nonce.equals(nonce), 'E7. the nonce is the one handed in');
  // RFC 9629 by hand: HKDF-SHA-256 over the shared secret with
  // CMSORIforKEMOtherInfo { wrap, kekLength } as the info, then AES-KW.
  const info = Buffer.from(new asn1js.Sequence({ value: [
    new asn1js.Sequence({ value: [new asn1js.ObjectIdentifier({
      value: row.wrapOid })] }),
    new asn1js.Integer({ value: 32 })] }).toBER(false));
  const kek = Buffer.from(nodeCrypto.hkdfSync('sha256', shared,
    Buffer.alloc(32, 0), info, 32));
  const unwrap = nodeCrypto.createDecipheriv('id-aes256-wrap', kek,
                                             Buffer.alloc(8, 0xa6));
  const opened = Buffer.concat([unwrap.update(bytes(kemri[7])),
                                unwrap.final()]);
  t.check(opened.equals(cek), 'E8. the wrapped key unwraps to the ' +
          'content key');
  t.check(gcmOpen(opened, p).equals(MIME), 'E9. which opens the content');
  t.check(refuses(function () {
    gcmOpen(opened, p, flipped(p.ciphertext, 0));
  }), 'E10. and refuses it tampered');
  const cbc = parse(crypto.smimeKemAssemble(MIME, cert, row, KEM_OID, {
    cipherText: Buffer.alloc(1088, 0x5a), sharedSecret: shared, cek: cek,
    iv: Buffer.alloc(16, 0x11) }, 'aes256-cbc'));
  t.check(cbc.type === ID_ENVELOPED && cbc.body[0].valueBlock.valueDec === 3,
          'E11. aes256-cbc: the version 3 EnvelopedData, as before');
  t.check(refuses(function () {
    crypto.smimeKemAssemble(MIME, cert, row, KEM_OID, {
      cipherText: Buffer.alloc(1088, 0x5a), sharedSecret: shared, cek: cek,
      iv: Buffer.alloc(16, 0x11) }, 'aes256-gcm');
  }), 'E12. a 16-octet IV is not a GCM nonce');
  log.debug("Leaving partE().");
}

async function partF(t, rsa) {
  log.debug("Entering partF().");
  const transports = require('../common/mail_transports');
  const composer = new transports.MailTransports(
    transports.MailTransports.defaultDeps());
  const base = { from: 'idp@example.org', fromName: '2124',
                 to: 'ada@example.org', subject: 'the real subject',
                 text: 'the text', html: '<p>the html</p>',
                 messageId: '<2124@example.org>', date: new Date(),
                 lang: 'en' };
  for (const content of [undefined, 'aes256-cbc']) {
    const raw = (await composer.compose(Object.assign({}, base, {
      encryption: { kind: 'smime', certificate: rsa.der.toString('base64'),
                    contentEncryption: content,
                    outerSubject: 'A message' } }))).toString('binary');
    const at = raw.indexOf('\r\n\r\n');
    const head = raw.slice(0, at);
    const der = Buffer.from(raw.slice(at + 4).replace(/\s+/g, ''), 'base64');
    const want = content ? 'enveloped-data' : 'authEnveloped-data';
    const type = content ? ID_ENVELOPED : ID_AUTH_ENVELOPED;
    t.check(new RegExp('Content-Type: application/pkcs7-mime;\\s+' +
                       'smime-type=' + want + ';').test(head) &&
            parse(der).type === type,
            'F. ' + (content || 'the default') + ': smime-type=' + want +
            ' around a ' + (content ? 'EnvelopedData' : 'AuthEnvelopedData'),
            head.slice(0, 300));
    const opened = opensslOpen(rsa, der);
    t.check(opened !== null && /the text/.test(opened.toString('utf8')),
            'F. and openssl opens it to the message');
  }
  log.debug("Leaving partF().");
}

function partG(t) {
  log.debug("Entering partG().");
  const config = require('../common/config');
  const mode = require('../common/mode');
  const KEY = 'mail.smimeContentEncryption';
  const row = function () {
    return mode.report().requirements.filter(function (one) {
      return one.id === 'smime-authenticated-encryption';
    })[0];
  };
  try {
    t.equal(config.value(KEY), 'aes256-gcm', 'G1. the default is GCM');
    t.check(!config.setOverride(KEY, 'aes128-cbc').ok,
            'G2. a value outside the enum is refused');
    t.check(row() && !row().waived, 'G3. the row is described, and ' +
            'nothing is waived in development');
    t.check(config.setOverride(KEY, 'aes256-cbc').ok && !row().waived,
            'G4. development with aes256-cbc: still nothing reported');
    t.check(config.setOverride('global.mode', 'product').ok,
            'G5. product mode');
    const waived = row().waived || [];
    t.check(waived.length === 1 &&
            waived[0].requirement === 'authenticated-mail-encryption' &&
            waived[0].section === 'ASVS 5.0.0 11.3.3' &&
            waived[0].level === 'MUST' && waived[0].setting === KEY,
            'G6. product with aes256-cbc: ASVS 5.0.0 11.3.3 reported not ' +
            'met, naming the setting', JSON.stringify(waived));
    t.check(config.setOverride(KEY, 'aes256-gcm').ok && !row().waived,
            'G7. product with aes256-gcm: nothing');
  } finally {
    config.clearOverride(KEY);
    config.clearOverride('global.mode');
  }
  log.debug("Leaving partG().");
}

async function run(t) {
  log.debug("Entering run().");
  const crypto = require('../common/crypto');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'smime-2124-'));
  try {
    const rsa = await partsAtoD(t, crypto, dir);
    partE(t, crypto);
    await partF(t, rsa);
    partG(t);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'smime_auth_enveloped',
  describe: 'S/MIME mail is an RFC 5083 AuthEnvelopedData under AES-256-GCM, ' +
            'opened by an independent reader and refused tampered; CBC ' +
            'behind mail.smimeContentEncryption, reported by /admin/mode ' +
            'in product (#2124)',
  run: run
};
