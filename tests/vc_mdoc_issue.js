// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';

// ===========================================================================
// tests/vc_mdoc_issue.js — AN mdoc THIS SERVICE ISSUES (#1862).
//
// `tests/vc_mdoc.js` builds its own mdoc and must keep doing so: that file
// is the verifier's reading of the specification, and this one is the
// issuer's. The credential is decoded with `vc_status_codec.ts` because a
// presentation has to carry the issuer's tag-24 bytes unchanged
// (`Tagged.raw`). The checks that would be vacuous if the issuer and the
// decoder shared a mistake are computed here with node: the SHA-256 of
// each item, the digest identifiers (never 0, 1 or 2), the salt length,
// and the device-key coordinates against the proof JWK.
//
// What it holds:
//
//   1. the Issuing Authority CA, minted on the first `ensure()` and the
//      same certificate the second time; `VcMdoc.verify` with no anchors
//      still trusts nobody after that mint;
//   2. the elements of a person with a birth date, and none invented;
//   3. an IssuerSigned whose maps are in RFC 8949 section 4.2.1's order,
//      whose digests match the tag-24 bytes, and whose device key is the
//      holder's;
//   4. a DeviceResponse of that credential accepted by `VcMdoc.verify`
//      against the IACA, including under paranoid PKI mode with revocation
//      soft-fail;
//   5. the mdoc Status List Token, signed by the document signer, chaining
//      to that IACA;
//   6. a holder key that is not P-256, refused as STS-VC-0187.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const config = require('../common/config');
const helpers = require('../common/helpers');
const stsCrypto = require('../common/crypto');
const authority = require('../oid4vc/mdoc_authority');
const issue = require('../oid4vc/vc_mdoc_issue');
const vcMdoc = require('../oid4vc/vc_mdoc');
const vcStatus = require('../oid4vc/vc_status');
const codec = require('../oid4vc/vc_status_codec');

const log = require('bunyan').createLogger({ name: 'vc_mdoc_issue',
  level: process.env.LOG_LEVEL || 'info' });

const ISSUER = 'https://sts.test';
const STATUS_URI = ISSUER + '/oid4vci/status-lists/mdoc';
const CLIENT = ISSUER + '/oid4vp';
const NONCE = 'nonce-1862';
const RESPONSE = ISSUER + '/oid4vp/response';
const MSO_KEYS = ['status', 'docType', 'version', 'validityInfo',
                  'valueDigests', 'deviceKeyInfo', 'digestAlgorithm'];
const ITEM_KEYS = ['random', 'digestID', 'elementValue',
                   'elementIdentifier'];
const OVERRIDES = ['global.publicBaseUrl', 'pki.paranoid',
                   'pki.revocationCheck'];

function namesOf(elements) {
  log.debug("Entering namesOf().");
  log.debug("Leaving namesOf().");
  return elements.map(function (one) {
    return one.name;
  });
}

function failedDetail(verified) {
  log.debug("Entering failedDetail().");
  const text = ((verified && verified.checks) || []).filter(function (c) {
    return !c.ok;
  }).map(function (c) {
    return c.name + ': ' + c.detail;
  }).join(' | ');
  log.debug("Leaving failedDetail().");
  return text;
}

function present(credential, pair, ctx) {
  log.debug("Entering present().");
  const issuerSigned = codec.cborDecode(Buffer.from(credential,
                                                     'base64url'));
  // DeviceNameSpacesBytes is a #6.24 item, not a bstr. The verifier
  // re-encodes the authentication from Tagged.raw, so this item carries
  // none and is both the nameSpaces value and the fourth element.
  const deviceNames = new codec.Tagged(24, codec.cborEncode(new Map()));
  const transcript = vcMdoc.sessionTranscript(ctx.clientId, ctx.nonce,
    null, ctx.responseUri);
  const authentication = codec.cborEncode(new codec.Tagged(24,
    codec.cborEncode(['DeviceAuthentication', transcript, ctx.doctype,
                      deviceNames])));
  const protectedBytes = codec.cborEncode(new Map([[1, -7]]));
  const signature = stsCrypto.coseSign1Sign(-7, pair.privateKey,
    protectedBytes, authentication);
  const deviceSigned = new Map([
    ['nameSpaces', deviceNames],
    ['deviceAuth', new Map([['deviceSignature',
      [protectedBytes, new Map(), null, signature]]])]
  ]);
  const document = new Map([
    ['docType', ctx.doctype],
    ['issuerSigned', issuerSigned],
    ['deviceSigned', deviceSigned]
  ]);
  const response = new Map([
    ['version', '1.0'],
    ['documents', [document]],
    ['status', 0]
  ]);
  const out = codec.cborEncode(response).toString('base64url');
  log.debug("Leaving present().");
  return out;
}

async function body(t) {
  log.debug("Entering body().");
  config.setOverride('global.publicBaseUrl', ISSUER);
  const before = String(authority.currentPem() || '');
  const pair = await authority.ensure(helpers.stsKeysFor(), ISSUER);
  const again = await authority.ensure(helpers.stsKeysFor(), ISSUER);
  t.check(!!pair.iacaPem && pair.iacaPem === again.iacaPem &&
          pair.iacaPem.indexOf('BEGIN CERTIFICATE') >= 0,
          '1a. ensure() mints one IACA and returns it again',
          before ? 'already held' : 'minted now');
  if (before) {
    t.check(pair.iacaPem === before,
            '1b. an IACA already held is the one ensure() returns');
  }
  const bare = await vcMdoc.verify('aa', {
    clientId: CLIENT, nonce: NONCE, responseUri: RESPONSE,
    jwkThumbprint: null, doctype: 'x', namespace: 'y', elements: [],
    anchorsPem: ''
  });
  t.check(bare && !bare.ok,
          '1c. VcMdoc.verify with no anchors still trusts nobody ' +
          'after the mint', failedDetail(bare));

  const now = Date.now();
  const from = now - 60000;
  const until = now + 365 * 24 * 60 * 60 * 1000;
  const elements = issue.elementsOf({
    given_name: 'Erika', family_name: 'Mustermann',
    birthdate: '1971-09-01'
  }, from, until);
  const names = namesOf(elements);
  t.check(names.indexOf('portrait') < 0 &&
          names.indexOf('driving_privileges') < 0 &&
          names.indexOf('document_number') < 0,
          '2a. a portrait, driving privileges and a document number ' +
          'are not invented', names.join(','));
  const birth = elements.filter(function (one) {
    return one.name === 'birth_date';
  })[0];
  const over18 = elements.filter(function (one) {
    return one.name === 'age_over_18';
  })[0];
  const over21 = elements.filter(function (one) {
    return one.name === 'age_over_21';
  })[0];
  t.check(birth && birth.value instanceof codec.Tagged &&
          birth.value.tag === 1004 && birth.value.value === '1971-09-01' &&
          over18 && over18.value === true && over21 &&
          over21.value === true,
          '2b. birth_date is a full-date (tag 1004) and both age ' +
          'thresholds are true');
  t.check(names.indexOf('issue_date') >= 0 &&
          names.indexOf('expiry_date') >= 0 &&
          names.indexOf('issuing_country') >= 0 &&
          names.indexOf('issuing_authority') >= 0,
          '2c. issue date, expiry, country and authority are always ' +
          'present', names.join(','));

  const wallet = nodeCrypto.generateKeyPairSync('ec',
    { namedCurve: 'P-256' });
  const holder = wallet.publicKey.export({ format: 'jwk' });
  const doctype = String(config.value('oid4vci.mdocDoctype'));
  const namespace = String(config.value('oid4vci.mdocNamespace'));
  const built = await issue.issue({
    holderJwk: holder, elements: elements, doctype: doctype,
    namespace: namespace, validFromMs: from, validUntilMs: until,
    signedMs: from, dsKey: pair.dsKey, dsDer: pair.dsDer, coseAlg: -7,
    status: { idx: 7, uri: STATUS_URI }
  });
  t.check(Array.isArray(built.disclosures) &&
          built.disclosures.length === 0,
          '3a. an mdoc carries no SD-JWT disclosures');
  const issuerSigned = codec.cborDecode(Buffer.from(built.credential,
                                                     'base64url'));
  const auth = issuerSigned.get('issuerAuth');
  t.check(built.recordCredential === Buffer.from(auth[2])
            .toString('base64url'),
          '3b. the register keys the MSO payload, not the presentation');
  const mso = codec.cborDecode(codec.cborDecode(auth[2]).value);
  t.equal(Array.from(mso.keys()).join(','), MSO_KEYS.join(','),
          '3c. the Mobile Security Object is in canonical key order');
  const info = mso.get('status').get('status_list');
  t.check(info.get('idx') === 7 && info.get('uri') === STATUS_URI &&
          Array.from(info.keys()).join(',') === 'idx,uri',
          '3d. status.status_list names idx 7 and the mdoc list URI');
  const items = issuerSigned.get('nameSpaces').get(namespace);
  const digests = mso.get('valueDigests').get(namespace);
  const salts = [];
  let digestOk = items.length > 0;
  let orderOk = true;
  let idsOk = true;
  items.forEach(function (item) {
    const inner = codec.cborDecode(item.value);
    if (Array.from(inner.keys()).join(',') !== ITEM_KEYS.join(',')) {
      orderOk = false;
    }
    const id = inner.get('digestID');
    if (id === 0 || id === 1 || id === 2 || !Number.isInteger(id) ||
        id < 24) {
      idsOk = false;
    }
    const salt = inner.get('random');
    salts.push(Buffer.isBuffer(salt) ? salt.toString('hex') : '');
    const hash = nodeCrypto.createHash('sha256').update(item.raw)
      .digest();
    const expected = digests.get(id);
    if (!Buffer.isBuffer(item.raw) || !Buffer.isBuffer(expected) ||
        !hash.equals(expected) || !Buffer.isBuffer(salt) ||
        salt.length < 16) {
      digestOk = false;
    }
  });
  t.check(orderOk, '3e. each IssuerSignedItem is in canonical key order');
  t.check(idsOk, '3f. digest identifiers are random and not 0, 1 or 2');
  t.check(digestOk && new Set(salts).size === salts.length,
          '3g. each salt is at least 16 bytes, unique, and SHA-256 of ' +
          'the tag-24 bytes is the digest the MSO carries');
  const deviceKey = mso.get('deviceKeyInfo').get('deviceKey');
  t.check(deviceKey.get(-2).equals(Buffer.from(holder.x, 'base64url')) &&
          deviceKey.get(-3).equals(Buffer.from(holder.y, 'base64url')) &&
          Array.from(deviceKey.keys()).join(',') === '1,-1,-2,-3',
          '3h. the device key is the proof key, COSE labels in order');

  const ctx = { clientId: CLIENT, nonce: NONCE, responseUri: RESPONSE,
                jwkThumbprint: null, doctype: doctype,
                namespace: namespace, elements: ['issuing_authority'],
                anchorsPem: pair.iacaPem };
  const verified = await vcMdoc.verify(present(built.credential, wallet,
                                                ctx), ctx);
  t.check(verified.ok, '4a. the presentation verifies against the IACA',
          failedDetail(verified));
  t.check(verified.holderJwk && verified.holderJwk.x === holder.x &&
          verified.holderJwk.y === holder.y &&
          !!verified.credentialJwt,
          '4b. a verified presentation names the holder key and the ' +
          'MSO payload');

  config.setOverride('pki.paranoid', 'on');
  config.setOverride('pki.revocationCheck', 'soft-fail');
  const forced = await vcMdoc.verify(present(built.credential, wallet,
                                              ctx), ctx);
  t.check(forced.ok,
          '4c. the same chain is accepted in paranoid mode with ' +
          'revocation soft-fail', failedDetail(forced));

  const cwt = await vcStatus.tslMdocCwt({ headers: {}, query: {} });
  let listed = null;
  let listProblem = '';
  try {
    listed = await vcMdoc.statusListKey(cwt, pair.iacaPem);
  } catch (e) {
    log.debug("Caught in body(): " + ((e && e.message) || e));
    listProblem = (e && e.message) || String(e);
  }
  t.check(!!listed && !listProblem,
          '5. the mdoc status list chains to the IACA', listProblem);

  let refused = null;
  try {
    await issue.issue({
      holderJwk: { kty: 'EC', crv: 'P-384', x: 'aa', y: 'bb' },
      elements: elements, doctype: doctype, namespace: namespace,
      validFromMs: from, validUntilMs: until, signedMs: from,
      dsKey: pair.dsKey, dsDer: pair.dsDer, coseAlg: -7
    });
  } catch (e) {
    log.debug("Caught in body(): " + ((e && e.message) || e));
    refused = e;
  }
  t.check(refused && refused.code === 'STS-VC-0187',
          '6. a holder key that is not P-256 is STS-VC-0187',
          refused ? refused.code : 'no throw');
  log.debug("Leaving body().");
}

async function run(t) {
  log.debug("Entering run().");
  try {
    await body(t);
  } finally {
    OVERRIDES.forEach(function (key) {
      config.clearOverride(key);
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'vc_mdoc_issue',
  describe: 'an mso_mdoc this realm issues (#1862): the IACA, the ' +
            'elements, canonical CBOR, a presentation the verifier ' +
            'accepts, the mdoc status list, and a non-P-256 refusal',
  run: run
};
