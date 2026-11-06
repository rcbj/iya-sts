// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';

// ===========================================================================
// tests/vc_mdoc.js — THE VERIFIER'S ISO mdoc (#935, 2026-11-02).
//
// `oid4vc/vc_mdoc.ts` checks an `mso_mdoc` presentation (OpenID4VP 1.0
// Appendix B.2, ISO/IEC 18013-5 section 9.3.1). The mdoc here is made by an
// ISSUER AND A WALLET WRITTEN IN THIS FILE — their own CBOR encoder, node's
// own signatures, the session transcript computed from the specification's
// text — so a reading of the specification the module and this file shared
// would have to be wrong twice. What it holds:
//
//   1. the request: `mso_mdoc` asked for by `meta.doctype_value`
//      (`oid4vp.expectedDoctype`), each claim a `[namespace, element]` path
//      with birthdate as `birth_date`, and `vp_formats_supported.mso_mdoc`
//      offering COSE identifiers — ML-DSA among them, and not while
//      `keys.postQuantumSigning` is off or `oid4vc.walletCompatibility` on;
//   2. an mdoc answering a `direct_post.jwt` request, its device signature
//      over the transcript naming the ENCRYPTION KEY's thumbprint, accepted
//      through `verifyAnswer()` with its claims, and the same over
//      `direct_post` with a null thumbprint; a tagged issuerAuth and an
//      ESP256 device signature accepted too;
//   3. the refusals, each by its own check: another nonce, another
//      encryption key, another Response URI, a tampered element, an element
//      the issuer never signed, a forged issuer signature, no anchor, another
//      CA's anchor, another docType, an expired MSO, a deviceMac, a
//      device-signed element the issuer did not authorize, an algorithm not
//      offered, two Documents, and bytes that are not base64url CBOR;
//   4. the status rule: a foreign mdoc with no status reference refused
//      under `oid4vp.requireStatusReference` `all` and accepted under
//      `own-only`.
//
// In process: the verifier and its libraries register nothing that matters
// here, and the request is built with the realm's own function.
// ===========================================================================

delete process.env.CONFIG_FILE;

const path = require('path');
const nodeCrypto = require('crypto');
const config = require('../common/config');
const verifier = require('../oid4vc/vc_verifier');
const vpConfig = require('../oid4vc/vc_verifier_config');
const vcMdoc = require('../oid4vc/vc_mdoc');

const log = require('bunyan').createLogger({ name: 'vc_mdoc',
  level: process.env.LOG_LEVEL || 'info' });

const HOST = 'sts.test';
const DOCTYPE = 'org.iso.18013.5.1.mDL';
const NS = 'org.iso.18013.5.1';
const QUERY_ID = 'identity_credential';
const OVERRIDES = ['oid4vp.mdocTrustAnchors', 'oid4vp.requireStatusReference',
                   'oid4vp.expectedDoctype', 'keys.postQuantumSigning',
                   'oid4vp.claims', 'oid4vc.walletCompatibility',
                   'pki.paranoid', 'pki.paranoidVcIssuer',
                   'pki.revocationCheck'];

// --- this file's own CBOR (RFC 8949), encoding only -------------------------
class Tag {
  constructor(tag, value) {
    this.tag = tag;
    this.value = value;
  }
}

// Recursive and called per item, so no Entering/Leaving pair — the hot-path
// exception the code style allows, stated as it requires.
function head(major, n) {
  if (n < 24) {
    return Buffer.from([(major << 5) | n]);
  }
  if (n < 0x100) {
    return Buffer.from([(major << 5) | 24, n]);
  }
  if (n < 0x10000) {
    const b = Buffer.alloc(3);
    b[0] = (major << 5) | 25;
    b.writeUInt16BE(n, 1);
    return b;
  }
  const b = Buffer.alloc(5);
  b[0] = (major << 5) | 26;
  b.writeUInt32BE(n, 1);
  return b;
}

// See head(): recursive, so no Entering/Leaving pair.
function enc(v) {
  if (v === null) {
    return Buffer.from([0xf6]);
  }
  if (v === true || v === false) {
    return Buffer.from([v ? 0xf5 : 0xf4]);
  }
  if (typeof v === 'number') {
    return v >= 0 ? head(0, v) : head(1, -1 - v);
  }
  if (Buffer.isBuffer(v)) {
    return Buffer.concat([head(2, v.length), v]);
  }
  if (typeof v === 'string') {
    const b = Buffer.from(v, 'utf8');
    return Buffer.concat([head(3, b.length), b]);
  }
  if (Array.isArray(v)) {
    return Buffer.concat([head(4, v.length)].concat(v.map(enc)));
  }
  if (v instanceof Map) {
    const parts = [head(5, v.size)];
    v.forEach(function (value, key) {
      parts.push(enc(key), enc(value));
    });
    return Buffer.concat(parts);
  }
  if (v instanceof Tag) {
    return Buffer.concat([head(6, v.tag), enc(v.value)]);
  }
  throw new Error('this encoder does not write ' + typeof v);
}

// An already-encoded item, put in place as its bytes.
class Raw {
  constructor(bytes) {
    this.bytes = bytes;
  }
}

function encRaw(v) {
  log.debug("Entering encRaw().");
  log.debug("Leaving encRaw().");
  return v instanceof Raw ? v.bytes : enc(v);
}

// --- the issuing authority and the document signer ------------------------
async function authority(label, documentSigner) {
  log.debug("Entering authority(). " + label);
  const repo = path.join(__dirname, '..');
  const x509 = require(path.join(repo, 'common', 'crypto_impl', 'x509'));
  const keyMaterial = require(path.join(repo, 'common', 'crypto_impl',
                                        'key_material'));
  const now = Date.now();
  const caPair = await keyMaterial.generateKeyPair('ec-p256');
  const ca = await x509.issueCertificate({
    subject: [{ name: 'C', value: 'US' },
              { name: 'CN', value: label + ' IACA' }],
    subjectPublicKey: caPair.publicPem,
    issuerPrivateKey: caPair.privatePem,
    signatureAlg: 'sha256-ecdsa',
    serial: nodeCrypto.randomBytes(8).toString('hex'),
    notBefore: new Date(now - 3600000).toISOString(),
    notAfter: new Date(now + 30 * 86400000).toISOString(),
    extensions: {
      basicConstraints: { present: true, critical: true, ca: true,
                          pathLen: 0 },
      keyUsage: { present: true, critical: true,
                  usages: ['keyCertSign', 'cRLSign'] },
      subjectKeyIdentifier: { present: true }
    }
  });
  const dsPair = await keyMaterial.generateKeyPair('ec-p256');
  const ds = await x509.issueCertificate({
    subject: [{ name: 'C', value: 'US' },
              { name: 'CN', value: label + ' document signer' }],
    subjectPublicKey: dsPair.publicPem,
    issuer: { certificatePem: ca.pem, privateKeyPem: caPair.privatePem,
              keyAlg: 'ec-p256' },
    signatureAlg: 'sha256-ecdsa',
    serial: nodeCrypto.randomBytes(8).toString('hex'),
    notBefore: new Date(now - 3600000).toISOString(),
    notAfter: new Date(now + 30 * 86400000).toISOString(),
    extensions: Object.assign({
      keyUsage: { present: true, critical: true,
                  usages: ['digitalSignature'] },
      subjectKeyIdentifier: { present: true },
      authorityKeyIdentifier: { present: true }
    }, documentSigner ? { extKeyUsage: { present: true,
                                         usages: ['1.0.18013.5.1.2'] } } : {})
  });
  log.debug("Leaving authority().");
  return { caPem: ca.pem, dsPem: ds.pem,
           dsDer: Buffer.from(ds.pem.replace(/-----[^-]+-----|\s+/g, ''),
                              'base64'),
           dsKey: nodeCrypto.createPrivateKey(dsPair.privatePem) };
}

// ECDSA as COSE carries it: r||s (RFC 9053 section 2.1).
function sign(key, bytes, hash) {
  log.debug("Entering sign().");
  log.debug("Leaving sign().");
  return nodeCrypto.sign(hash || 'sha256', bytes,
                         { key: key, dsaEncoding: 'ieee-p1363' });
}

function coseSign1(key, alg, unprotectedHeader, payload, detached) {
  log.debug("Entering coseSign1().");
  const prot = enc(new Map([[1, alg]]));
  const tbs = enc(['Signature1', prot, Buffer.alloc(0), payload]);
  log.debug("Leaving coseSign1().");
  return [prot, unprotectedHeader, detached ? null : payload,
          sign(key, tbs)];
}

// OpenID4VP 1.0 Appendix B.2.6.1, read here from its text.
function transcript(clientId, nonce, thumbprint, responseUri) {
  log.debug("Entering transcript().");
  const info = enc([clientId, nonce, thumbprint, responseUri]);
  log.debug("Leaving transcript().");
  return [null, null, ['OpenID4VPHandover',
                       nodeCrypto.createHash('sha256').update(info)
                         .digest()]];
}

// RFC 7638 for an EC key, as bytes.
function thumbprint(jwk) {
  log.debug("Entering thumbprint().");
  const json = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x,
                                y: jwk.y });
  log.debug("Leaving thumbprint().");
  return nodeCrypto.createHash('sha256').update(json).digest();
}

// The whole mdoc: an issuer signing the elements, a wallet presenting them.
// `o` changes one thing, for a refusal.
function present(iss, wallet, ctx, o) {
  log.debug("Entering present().");
  const opts = o || {};
  const now = Date.now();
  const tdate = function (ms) {
    return new Tag(0, new Date(ms).toISOString().replace(/\.\d+Z$/, 'Z'));
  };
  const elements = [['given_name', 'Erika'], ['family_name', 'Mustermann'],
                    ['birth_date', new Tag(1004, '1971-09-01')]];
  const items = [];
  const digests = new Map();
  elements.forEach(function (pair, i) {
    const bytes = enc(new Tag(24, enc(new Map([
      ['digestID', i], ['random', nodeCrypto.randomBytes(16)],
      ['elementIdentifier', pair[0]], ['elementValue', pair[1]]]))));
    digests.set(i, nodeCrypto.createHash('sha256').update(bytes).digest());
    items.push(new Raw(bytes));
  });
  if (opts.tamper) {
    items[0] = new Raw(enc(new Tag(24, enc(new Map([
      ['digestID', 0], ['random', nodeCrypto.randomBytes(16)],
      ['elementIdentifier', 'given_name'], ['elementValue', 'Mallory']])))));
  }
  if (opts.unsigned) {
    items.push(new Raw(enc(new Tag(24, enc(new Map([
      ['digestID', 9], ['random', nodeCrypto.randomBytes(16)],
      ['elementIdentifier', 'age_over_18'], ['elementValue', true]]))))));
  }
  const devicePub = wallet.publicKey.export({ format: 'jwk' });
  const keyInfo = new Map([['deviceKey', new Map([
    [1, 2], [-1, 1], [-2, Buffer.from(devicePub.x, 'base64url')],
    [-3, Buffer.from(devicePub.y, 'base64url')]])]]);
  if (opts.authorize) {
    keyInfo.set('keyAuthorizations', new Map([['dataElements',
      new Map([[NS, ['nickname']]])]]));
  }
  const mso = new Map([
    ['version', '1.0'], ['digestAlgorithm', 'SHA-256'],
    ['valueDigests', new Map([[NS, digests]])],
    ['deviceKeyInfo', keyInfo],
    ['docType', opts.msoDocType || DOCTYPE],
    ['validityInfo', new Map([
      ['signed', tdate(now - 60000)], ['validFrom', tdate(now - 60000)],
      ['validUntil', tdate(opts.expired ? now - 1000 : now + 86400000)]])]]);
  const payload = enc(new Tag(24, enc(mso)));
  const issuerAuth = coseSign1(iss.dsKey, -7, new Map([[33, iss.dsDer]]),
                               payload);
  if (opts.forge) {
    issuerAuth[3] = Buffer.from(issuerAuth[3]);
    issuerAuth[3][5] ^= 0xff;
  }
  const deviceNames = opts.deviceElement
    ? new Map([[NS, new Map([['nickname', 'E']])]]) : new Map();
  const deviceNamesBytes = enc(new Tag(24, enc(deviceNames)));
  const st = transcript(ctx.clientId, opts.nonce || ctx.nonce,
                        opts.thumbprint !== undefined ? opts.thumbprint
                                                      : ctx.thumbprint,
                        opts.responseUri || ctx.responseUri);
  const auth = enc(new Tag(24, Buffer.concat([
    head(4, 4), enc('DeviceAuthentication'), enc(st), enc(DOCTYPE),
    deviceNamesBytes])));
  const deviceAlg = opts.deviceAlg || -7;
  const deviceSignature = coseSign1(wallet.privateKey, deviceAlg, new Map(),
                                    auth, true);
  const deviceAuth = opts.mac
    ? new Map([['deviceMac', [enc(new Map([[1, 5]])), new Map(), null,
                              nodeCrypto.randomBytes(32)]]])
    : new Map([['deviceSignature', deviceSignature]]);
  const issuerAuthItem = opts.tagged ? new Tag(18, issuerAuth) : issuerAuth;
  const nsBytes = Buffer.concat([head(4, items.length)]
    .concat(items.map(encRaw)));
  const document = Buffer.concat([
    head(5, 3), enc('docType'), enc(DOCTYPE),
    enc('issuerSigned'), head(5, 2), enc('nameSpaces'), head(5, 1), enc(NS),
    nsBytes, enc('issuerAuth'), enc(issuerAuthItem),
    enc('deviceSigned'), head(5, 2), enc('nameSpaces'), deviceNamesBytes,
    enc('deviceAuth'), enc(deviceAuth)]);
  const documents = opts.twoDocuments
    ? Buffer.concat([head(4, 2), document, document])
    : Buffer.concat([head(4, 1), document]);
  const response = Buffer.concat([
    head(5, 3), enc('version'), enc('1.0'), enc('documents'), documents,
    enc('status'), enc(0)]);
  log.debug("Leaving present().");
  return response.toString('base64url');
}

function fakeReq() {
  log.debug("Entering fakeReq().");
  log.debug("Leaving fakeReq().");
  return { protocol: 'https', headers: { host: HOST }, query: {},
           get: function (name) {
             return String(name).toLowerCase() === 'host' ? HOST : '';
           } };
}

// What the wallet reads off a request: its values, and the ECDH-ES key's
// thumbprint for direct_post.jwt.
function contextOf(record) {
  log.debug("Entering contextOf().");
  const keys = ((record.request.client_metadata || {}).jwks || {}).keys ||
               [];
  const ecdh = keys.filter(function (k) {
    return k.alg === 'ECDH-ES';
  })[0] || null;
  log.debug("Leaving contextOf().");
  return { clientId: record.clientId, nonce: record.nonce,
           responseUri: record.request.response_uri,
           thumbprint: ecdh ? thumbprint(ecdh) : null,
           kid: ecdh ? ecdh.kid : '' };
}

async function answer(record, token, kid) {
  log.debug("Entering answer().");
  const out = await verifier.verifyAnswer(record,
    JSON.stringify({ [QUERY_ID]: [token] }),
    { aud: record.clientId, kid: kid });
  log.debug("Leaving answer().");
  return out.verified;
}

function failed(verified, name) {
  log.debug("Entering failed(). " + name);
  log.debug("Leaving failed().");
  return !!verified && !verified.ok && (verified.checks || []).some(
    function (c) {
      return !c.ok && c.name === name;
    });
}

function failures(verified) {
  log.debug("Entering failures().");
  log.debug("Leaving failures().");
  return JSON.stringify((verified.checks || []).filter(function (c) {
    return !c.ok;
  })).slice(0, 400);
}

async function body(t) {
  log.debug("Entering body().");
  const iss = await authority('vc_mdoc test');
  const other = await authority('another authority');
  const wallet = nodeCrypto.generateKeyPairSync('ec',
                                                { namedCurve: 'P-256' });
  config.setOverride('oid4vp.mdocTrustAnchors', iss.caPem);
  config.setOverride('oid4vp.requireStatusReference', 'own-only');
  vpConfig.setRequested(['given_name', 'family_name', 'birthdate']);

  t.log.info('=== 1. the request ===');
  const jwtRecord = verifier.buildVpRequest(fakeReq(),
    { format: 'mso_mdoc', responseMode: 'direct_post.jwt' });
  const query = jwtRecord.request.dcql_query.credentials[0];
  t.check(query.format === 'mso_mdoc' && query.meta.doctype_value === DOCTYPE,
          '1a. an mso_mdoc query names the expected docType in ' +
          'meta.doctype_value', JSON.stringify(query.meta));
  t.check(JSON.stringify(query.claims) === JSON.stringify([
            { path: [NS, 'given_name'] }, { path: [NS, 'family_name'] },
            { path: [NS, 'birth_date'] }]),
          '1b. each claim is a [namespace, element] path, birthdate as ' +
          'ISO/IEC 18013-5\'s birth_date', JSON.stringify(query.claims));
  const offered = jwtRecord.request.client_metadata.vp_formats_supported
    .mso_mdoc;
  t.check(offered.issuerauth_alg_values.indexOf(-7) >= 0 &&
          offered.deviceauth_alg_values.indexOf(-9) >= 0 &&
          offered.issuerauth_alg_values.indexOf(-48) >= 0,
          '1c. vp_formats_supported.mso_mdoc offers COSE identifiers, ' +
          'ML-DSA among them', JSON.stringify(offered));
  config.setOverride('keys.postQuantumSigning', false);
  t.check(vcMdoc.vpFormat().issuerauth_alg_values.indexOf(-48) < 0 &&
          vcMdoc.vpFormat().issuerauth_alg_values.indexOf(-7) >= 0,
          '1d. and none of ML-DSA while keys.postQuantumSigning is off');
  config.clearOverride('keys.postQuantumSigning');
  config.setOverride('oid4vc.walletCompatibility', true);
  t.check(vcMdoc.vpFormat().deviceauth_alg_values.indexOf(-49) < 0 &&
          vcMdoc.vpFormat().deviceauth_alg_values.indexOf(-9) >= 0,
          '1e. nor while the wallet compatibility mode is on (#657)');
  config.clearOverride('oid4vc.walletCompatibility');

  t.log.info('=== 2. accepted ===');
  const jwtCtx = contextOf(jwtRecord);
  let v = await answer(jwtRecord, present(iss, wallet, jwtCtx), jwtCtx.kid);
  t.check(v.ok && v.claims.given_name === 'Erika' &&
          v.claims.birth_date === '1971-09-01' &&
          v.disclosed.length === 3,
          '2a. a direct_post.jwt answer, its transcript naming the ' +
          'encryption key\'s thumbprint, is accepted with its elements',
          failures(v) + ' ' + JSON.stringify(v.claims));
  const plainRecord = verifier.buildVpRequest(fakeReq(),
    { format: 'mso_mdoc', responseMode: 'direct_post' });
  const plainCtx = contextOf(plainRecord);
  v = await answer(plainRecord, present(iss, wallet, plainCtx), '');
  t.check(plainCtx.thumbprint === null && v.ok,
          '2b. a direct_post answer, its thumbprint null, is accepted',
          failures(v));
  v = await answer(plainRecord, present(iss, wallet, plainCtx,
                   { tagged: true, deviceAlg: -9 }), '');
  t.check(v.ok, '2c. a tagged (18) issuerAuth and an ESP256 device ' +
          'signature are accepted', failures(v));
  v = await answer(plainRecord, present(iss, wallet, plainCtx,
                   { deviceElement: true, authorize: true }), '');
  t.check(v.ok && v.claims.nickname === 'E',
          '2d. a device-signed element the issuer authorized is accepted',
          failures(v));

  t.log.info('=== 3. refused ===');
  const refusals = [
    ['3a. another nonce', { nonce: 'not-this-one' }, 'Device signature'],
    ['3b. another encryption key', { thumbprint: Buffer.alloc(32, 7) },
     'Device signature'],
    ['3c. another Response URI', { responseUri: 'https://rp.test/r' },
     'Device signature'],
    ['3d. a tampered element', { tamper: true }, 'Element digests'],
    ['3e. an element the issuer never signed', { unsigned: true },
     'Element digests'],
    ['3f. a forged issuer signature', { forge: true }, 'Issuer signature'],
    ['3g. another docType in the MSO', { msoDocType: 'org.example.other' },
     'Mobile Security Object'],
    ['3h. an expired MSO', { expired: true }, 'Validity window'],
    ['3i. a deviceMac', { mac: true }, 'Device signature'],
    ['3j. a device-signed element nobody authorized',
     { deviceElement: true }, 'Device signature'],
    ['3k. two Documents', { twoDocuments: true }, 'Format']
  ];
  for (let i = 0; i < refusals.length; i++) {
    const one = refusals[i];
    v = await answer(jwtRecord, present(iss, wallet, jwtCtx, one[1]),
                     jwtCtx.kid);
    t.check(failed(v, one[2]), one[0] + ' is refused by "' + one[2] + '"',
            failures(v));
  }
  v = await answer(jwtRecord, present(iss, wallet, jwtCtx), 'no-such-kid');
  t.check(failed(v, 'Response encryption key'),
          '3l. an answer naming no key the request offered is refused',
          failures(v));
  v = await answer(plainRecord, 'not!base64url', '');
  t.check(failed(v, 'Format'), '3m. bytes that are not base64url CBOR are ' +
          'refused', failures(v));
  config.setOverride('oid4vp.mdocTrustAnchors', other.caPem);
  v = await answer(plainRecord, present(iss, wallet, plainCtx), '');
  t.check(failed(v, 'Issuer certificate chain'),
          '3n. a document signer chaining to another authority is refused',
          failures(v));
  config.setOverride('oid4vp.mdocTrustAnchors', '');
  v = await answer(plainRecord, present(iss, wallet, plainCtx), '');
  t.check(failed(v, 'Issuer certificate chain'),
          '3o. with no anchor configured, no mdoc is trusted', failures(v));
  config.setOverride('oid4vp.mdocTrustAnchors', iss.caPem);
  config.setOverride('keys.postQuantumSigning', false);
  const narrowed = vcMdoc.coseAlgs();
  config.clearOverride('keys.postQuantumSigning');
  t.check(narrowed.indexOf(-9) >= 0 && narrowed.indexOf(-49) < 0,
          '3p. the accepted algorithms are the offered ones');
  config.setOverride('oid4vp.expectedDoctype', 'org.example.other');
  const otherRecord = verifier.buildVpRequest(fakeReq(),
    { format: 'mso_mdoc', responseMode: 'direct_post' });
  const otherCtx = contextOf(otherRecord);
  config.clearOverride('oid4vp.expectedDoctype');
  v = await answer(otherRecord, present(iss, wallet, otherCtx), '');
  t.check(failed(v, 'Document type (docType)'),
          '3q. an mdoc of another docType than the request asked for is ' +
          'refused', failures(v));

  t.log.info('=== 4. status ===');
  config.setOverride('oid4vp.requireStatusReference', 'all');
  v = await answer(plainRecord, present(iss, wallet, plainCtx), '');
  t.check(failed(v, 'Credential status'),
          '4a. under `all`, a foreign mdoc with no status reference is ' +
          'refused', failures(v));
  config.setOverride('oid4vp.requireStatusReference', 'own-only');
  v = await answer(plainRecord, present(iss, wallet, plainCtx), '');
  t.check(v.ok, '4b. under `own-only` it is accepted', failures(v));

  t.log.info('=== 5. paranoid PKI mode (#1360) ===');
  // A chain naming no list is another question, which `tests/certificate_trust`
  // asks. This section is about the document signer's profile.
  config.setOverride('pki.revocationCheck', 'soft-fail');
  config.setOverride('pki.paranoid', 'on');
  v = await answer(plainRecord, present(iss, wallet, plainCtx), '');
  t.check(failed(v, 'Issuer certificate chain'),
          '5a. a document signer without the ISO 18013-5 extendedKeyUsage is ' +
          'refused in force', failures(v));
  const marked = await authority('marked authority', true);
  config.setOverride('oid4vp.mdocTrustAnchors', marked.caPem);
  v = await answer(plainRecord, present(marked, wallet, plainCtx), '');
  t.check(v.ok, '5b. and one that carries it is accepted', failures(v));
  config.setOverride('oid4vp.mdocTrustAnchors', iss.caPem);
  config.setOverride('pki.paranoidVcIssuer', false);
  v = await answer(plainRecord, present(iss, wallet, plainCtx), '');
  t.check(v.ok, '5c. with the row off the first is accepted again',
          failures(v));
  log.debug("Leaving body().");
}

async function run(t) {
  log.debug("Entering run().");
  const before = vpConfig.requestedClaims();
  try {
    await body(t);
  } finally {
    vpConfig.setRequested(before);
    OVERRIDES.forEach(function (key) {
      config.clearOverride(key);
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'vc_mdoc',
  describe: 'the Verifier\'s ISO mdoc (#935): the mso_mdoc request, an ' +
            'mdoc made by an issuer and wallet written here accepted over ' +
            'direct_post.jwt and direct_post, and every refusal by its own ' +
            'check',
  run: run
};
