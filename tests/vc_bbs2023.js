// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// ===========================================================================
// tests/vc_bbs2023.js — bbs-2023 IS THE W3C CRYPTOSUITE (#1878, 2026-11-17).
//
// oid4vc/vc_bbs.ts implements W3C Data Integrity BBS Cryptosuites v1.0
// (CRD 10 September 2026), baseline. Until #1878 this service's bbs-2023 was
// a private format under the W3C name, and every test of it was a round trip
// through its own code — which is exactly how a private format passes. So
// every claim here is against something nobody here wrote:
//
//   A. the Multikey: the specification's BBS key encodes to the did:key
//      fragment its vectors name, and back; a `u` key is refused.
//   B. the specification's Appendix vectors, for the windsurf credential and
//      the permanent-resident-card one: the HMAC-shuffled canonical
//      statements, the mandatory group, the proof hash and mandatory hash,
//      the BASE proofValue byte for byte (BBS signing is deterministic), the
//      disclosure data (label map, mandatory and selective indexes, the
//      reveal document) and the DERIVED proofValue byte for byte around the
//      BBS proof; the vectors' own derived documents verify, and a changed
//      one, a wrong key, a base proof handed to a verifier and an at-risk
//      feature header do not.
//
//      THE ONE BYTE STRING NOT REPRODUCED is the BBS proof itself, which is
//      randomized: the vectors were made with the BBS draft's "mocked random
//      scalars" from their seed, and @digitalbazaar/bbs-signatures' mocked
//      ProofGen (its interface module, `mocked_random_scalars_options`) with
//      that seed and either DST the drafts name does not give the vector's
//      bytes. The vector's proof VERIFIES under the same library (B11), and
//      Digital Bazaar's derivations verify here (C), so what is unchecked is
//      only which random scalars produced it.
//   C. Digital Bazaar's @digitalbazaar/bbs-2023-cryptosuite, the version
//      w3c/vc-di-bbs-test-suite's lockfile pins (fetched into the tests image
//      by tests/vc-suites/fetch-suites.sh — test tooling, never a service
//      dependency): this service's base proof derived by that library and
//      verified here and there; that library's base proof checked, derived
//      and verified here, and the derivation verified there; this service's
//      derivation, with a presentation header, verified there.
//   D. the legacy door: the pre-1.1 format's reader exists only under the
//      non-standard label, and the key encoding it used is no longer read as
//      a Multikey.
//
// The vectors and the second implementation carry test key material and are
// never committed (tests/CLAUDE.md, *THE W3C VC AND DID SUITES*).
// ===========================================================================

const fs = require('fs');
const path = require('path');
const { pathToFileURL } = require('url');
const { createRequire } = require('module');

const log = require('bunyan').createLogger({ name: 'vc_bbs2023_test',
  level: process.env.LOG_LEVEL || 'info' });

const SUITES = process.env.STS_VC_SUITES_DIR || '/opt/vc-suites';
const BBS_SUITE = path.join(SUITES, 'vc-di-bbs-test-suite');
const VECTORS = process.env.STS_VC_DI_BBS_VECTORS ||
  path.join(BBS_SUITE, 'tests', 'input', 'vc-di-bbs', 'TestVectors');

function read(rel) {
  log.debug("Entering read(). " + rel);
  log.debug("Leaving read().");
  return fs.readFileSync(path.join(VECTORS, rel), 'utf8');
}

function json(rel) {
  log.debug("Entering json(). " + rel);
  log.debug("Leaving json().");
  return JSON.parse(read(rel));
}

function hex(bytes) {
  log.debug("Entering hex().");
  log.debug("Leaving hex().");
  return Buffer.from(bytes).toString('hex');
}

// Digital Bazaar's implementation, from the BBS test suite's install.
async function digitalBazaar() {
  log.debug("Entering digitalBazaar().");
  const nm = path.join(BBS_SUITE, 'node_modules');
  const req = createRequire(path.join(nm, 'index.js'));
  const lib = function (name) {
    return import(pathToFileURL(path.join(nm, name, 'lib',
                                          'index.js')).href);
  };
  const out = {
    jsigs: req('jsonld-signatures'),
    di: await lib('@digitalbazaar/data-integrity'),
    bbs: await lib('@digitalbazaar/bbs-2023-cryptosuite'),
    bls: await lib('@digitalbazaar/bls12-381-multikey'),
    version: JSON.parse(fs.readFileSync(path.join(nm, '@digitalbazaar',
      'bbs-2023-cryptosuite', 'package.json'), 'utf8')).version
  };
  log.debug("Leaving digitalBazaar().");
  return out;
}

// A loader for Digital Bazaar's library: this service's closed context set,
// and the one issuer key and its controller document.
function loaderFor(vcJsonLd, vmDoc, controller) {
  log.debug("Entering loaderFor().");
  const contexts = vcJsonLd.documentLoader();
  log.debug("Leaving loaderFor().");
  return async function (url) {
    if (url === vmDoc.id) {
      return { contextUrl: null, documentUrl: url, document: vmDoc };
    }
    if (url === controller.id) {
      return { contextUrl: null, documentUrl: url, document: controller };
    }
    return contexts(url);
  };
}

async function run(t) {
  log.debug("Entering run().");
  const vcBbs = require('../oid4vc/vc_bbs');
  const sd = require('../oid4vc/vc_ecdsa_sd');
  const vcJsonLd = require('../oid4vc/vc_jsonld');
  const stsCrypto = require('../common/crypto');
  const bbs2023 = require('../common/crypto_impl/bbs2023.js');

  t.log.info('=== A. the Multikey ===');
  const keys = json('BBSKeyMaterial.json');
  const publicKey = Buffer.from(keys.publicKeyHex, 'hex');
  const secretKey = new Uint8Array(Buffer.from(keys.privateKeyHex, 'hex'));
  const hmacKey = Buffer.from(keys.hmacKeyString, 'hex');
  const vm = json('addProofConfig.json').verificationMethod;
  const multikey = bbs2023.publicKeyMultibase(publicKey);
  t.check(vm === 'did:key:' + multikey + '#' + multikey,
          'A1. the specification\'s BBS key is the Multikey its did:key ' +
          'names (z, base58btc, 0xeb01)', multikey.slice(0, 24));
  t.check(Buffer.from(bbs2023.publicKeyFromMultibase(multikey))
            .equals(publicKey),
          'A2. and decodes back to the 96-byte key');
  let refused = '';
  try {
    bbs2023.publicKeyFromMultibase('u' + publicKey.toString('base64url'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    refused = String(e.message);
  }
  t.check(/starts with "z"/.test(refused),
          'A3. the pre-1.1 `u` + raw bytes encoding is not a Multikey',
          refused);
  // A4 (run #478): the Multikey's leading characters depend on the key. A
  // compressed G2 key's first byte is 0x80-0xbf, and one starting 0x80 0x0…
  // encodes to zUC6…, not the zUC7… every vector's key happens to give —
  // the cluster mode's ldp_vc jobs asserted the prefix and failed on a
  // sound key. Both ends of the range round-trip, and so do fresh keys.
  const low = Buffer.alloc(96, 0);
  low[0] = 0x80;
  const high = Buffer.alloc(96, 0xff);
  high[0] = 0xbf;
  const lowMk = bbs2023.publicKeyMultibase(low);
  const highMk = bbs2023.publicKeyMultibase(high);
  const fresh = [];
  for (let i = 0; i < 8; i++) {
    fresh.push((await stsCrypto.bbs.generateKeyPair()).publicKey);
  }
  t.check(/^zUC6/.test(lowMk) && /^zUC7/.test(highMk) &&
          Buffer.from(bbs2023.publicKeyFromMultibase(lowMk)).equals(low) &&
          Buffer.from(bbs2023.publicKeyFromMultibase(highMk)).equals(high) &&
          fresh.every(function (k) {
            return Buffer.from(bbs2023.publicKeyFromMultibase(
              bbs2023.publicKeyMultibase(k))).equals(Buffer.from(k));
          }),
          'A4. a key encodes to zUC6… or zUC7… by its first bytes, and ' +
          'every one decodes back — a Multikey is checked by decoding, ' +
          'never by its prefix', lowMk.slice(0, 6) + ' ' + highMk.slice(0, 6));

  t.log.info('=== B. the specification\'s vectors ===');
  const derive = json('BBSDeriveMaterial.json');
  const presentationHeader = Buffer.from(derive.presentationHeaderHex, 'hex');
  const plain = new vcBbs.VcBbs(vcBbs.VcBbs.defaultDeps());
  const codec = require('../oid4vc/vc_status_codec');
  // The unsigned document is the signed base one without its proof: the
  // `prc` set's prCredUnsigned.json at the top of TestVectors/ says
  // "Government of Utopia Permanent Resident Card." where every one of its
  // intermediate values, and its signed document, say "Permanent Resident
  // Card from Government of Utopia." — an edit to one file the others were
  // not regenerated after.
  const cases = [
    ['windsurf', '', 'windMandatory.json', 'windSelective.json'],
    ['prc', 'prc/', 'prCredMandatory.json', 'prCredSelective.json']];
  for (const c of cases) {
    const name = c[0];
    const dir = c[1];
    const unsigned = json(dir + 'addSignedSDBase.json');
    delete unsigned.proof;
    const mandatoryPointers = json(c[2]);
    const selectivePointers = json(c[3]);
    const grouped = await sd.canonicalizeAndGroup(unsigned,
      plain.shuffledLabelMapFactory(hmacKey),
      { mandatory: mandatoryPointers });
    t.check(JSON.stringify(grouped.nquads) ===
            JSON.stringify(json(dir + 'addBaseDocHMACCanon.json')),
            'B1. ' + name + ': the HMAC-shuffled canonical statements are ' +
            'the vector\'s');
    t.check(JSON.stringify(Array.from(grouped.groups.mandatory.matching
      .entries())) ===
            JSON.stringify(json(dir + 'addBaseTransform.json').mandatory
              .value),
            'B2. ' + name + ': the mandatory statements are the vector\'s');
    const config = json(dir + 'addProofConfig.json');
    const base = await plain.createBaseProof(unsigned, {
      secretKey: secretKey, publicKey: publicKey, hmacKey: hmacKey,
      created: config.created, verificationMethod: config.verificationMethod,
      proofPurpose: config.proofPurpose,
      mandatoryPointers: mandatoryPointers });
    const parsed = plain.parseBaseProofValue(base.proof.proofValue);
    const hashes = json(dir + 'addHashData.json');
    t.check(hex(parsed.bbsHeader) === hashes.proofHash + hashes.mandatoryHash,
            'B3. ' + name + ': the BBS header is the vector\'s proofHash ' +
            'and mandatoryHash', hex(parsed.bbsHeader).slice(0, 16));
    const signedBase = json(dir + 'addSignedSDBase.json');
    t.check(base.proof.proofValue === signedBase.proof.proofValue,
            'B4. ' + name + ': the base proofValue is the vector\'s byte ' +
            'for byte (0xd95d02, bbsSignature, bbsHeader, publicKey, ' +
            'hmacKey, mandatoryPointers)');
    const baseOk = await plain.verifyBaseProof(signedBase, publicKey);
    t.check(baseOk.ok, 'B5. ' + name + ': the vector\'s base proof checks ' +
            'here', baseOk.detail);
    const derived = await plain.deriveProof(signedBase, selectivePointers,
      { presentationHeader: presentationHeader });
    const wanted = json(dir + 'derivedRevealDocument.json');
    const dParsed = plain.parseDerivedProofValue(derived.proof.proofValue);
    const disclosure = json(dir + 'derivedDisclosureData.json');
    t.check(JSON.stringify(Array.from(dParsed.labelMap.entries())) ===
            JSON.stringify(disclosure.labelMap.value),
            'B6. ' + name + ': the label map is the vector\'s',
            JSON.stringify(Array.from(dParsed.labelMap.entries())));
    t.check(JSON.stringify(dParsed.mandatoryIndexes) ===
            JSON.stringify(disclosure.mandatoryIndexes) &&
            JSON.stringify(dParsed.selectiveIndexes) ===
            JSON.stringify(disclosure.adjSelectiveIndexes),
            'B7. ' + name + ': the mandatory and selective indexes are the ' +
            'vector\'s', JSON.stringify([dParsed.mandatoryIndexes,
                                         dParsed.selectiveIndexes]));
    const revealOnly = Object.assign({}, derived);
    delete revealOnly.proof;
    const wantedOnly = Object.assign({}, wanted);
    delete wantedOnly.proof;
    t.check(JSON.stringify(revealOnly) === JSON.stringify(wantedOnly),
            'B8. ' + name + ': the reveal document is the vector\'s');
    const ours = await plain.verifyDerivedProof(derived, publicKey);
    t.check(ours.ok, 'B9. ' + name + ': this derivation verifies',
            ours.detail);
    const compressed = new Map();
    dParsed.labelMap.forEach(function (v, k) {
      compressed.set(parseInt(k.slice(4), 10), parseInt(v.slice(1), 10));
    });
    const reserialized = 'u' + Buffer.concat([Buffer.from([0xd9, 0x5d, 0x03]),
      codec.cborEncode([Buffer.from(disclosure.bbsProof, 'hex'), compressed,
                        dParsed.mandatoryIndexes, dParsed.selectiveIndexes,
                        Buffer.from(dParsed.presentationHeader)])
    ]).toString('base64url');
    t.check(reserialized === wanted.proof.proofValue &&
            Object.keys(derived.proof).join() ===
            Object.keys(wanted.proof).join(),
            'B10. ' + name + ': the derived proofValue is the vector\'s ' +
            'byte for byte around the BBS proof (0xd95d03, compressed label ' +
            'map, mandatory and selective indexes, presentation header)');
    const verified = await plain.verifyDerivedProof(wanted, publicKey);
    t.check(verified.ok && hex(verified.presentationHeader) ===
            derive.presentationHeaderHex,
            'B11. ' + name + ': the vector\'s derived document verifies, ' +
            'its presentation header read back', verified.detail);
    const changed = JSON.parse(JSON.stringify(wanted));
    changed.credentialSubject = Object.assign({}, changed.credentialSubject);
    const k = Object.keys(changed.credentialSubject).filter(function (n) {
      return typeof changed.credentialSubject[n] === 'string' &&
        n !== 'id';
    })[0];
    changed.credentialSubject[k] = changed.credentialSubject[k] + 'X';
    t.check(!!k && !(await plain.verifyDerivedProof(changed, publicKey)).ok,
            'B12. ' + name + ': a revealed value changed does not verify');
    const otherKey = await stsCrypto.bbs.generateKeyPair();
    t.check(!(await plain.verifyDerivedProof(wanted, otherKey.publicKey)).ok,
            'B13. ' + name + ': under another issuer key it does not verify');
    const asBase = await plain.verifyDerivedProof(signedBase, publicKey);
    t.check(!asBase.ok && /BASE proof/.test(asBase.detail),
            'B14. ' + name + ': a base proof handed to a verifier is ' +
            'refused', asBase.detail);
  }
  const feature = 'u' + Buffer.concat([Buffer.from([0xd9, 0x5d, 0x05]),
    Buffer.from([0x80])]).toString('base64url');
  let featureRefusal = '';
  try {
    plain.parseDerivedProofValue(feature);
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    featureRefusal = String(e.message);
  }
  t.check(/anonymous_holder_binding/.test(featureRefusal),
          'B15. an at-risk feature option (0xd95d05) is refused by name',
          featureRefusal);
  let pointerRefusal = '';
  try {
    await plain.createBaseProof(json('windDoc.json'), {
      secretKey: secretKey, publicKey: publicKey,
      verificationMethod: vm, mandatoryPointers: ['/credentialSubject/none'] });
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    pointerRefusal = String(e.message);
  }
  t.check(/does not match/.test(pointerRefusal),
          'B16. a mandatory pointer to nothing refuses to sign',
          pointerRefusal);

  t.log.info('=== C. Digital Bazaar\'s bbs-2023-cryptosuite ===');
  const db = await digitalBazaar();
  t.log.info('@digitalbazaar/bbs-2023-cryptosuite ' + db.version);
  const purpose = new db.jsigs.purposes.AssertionProofPurpose();
  const doc = json('windDoc.json');
  // C1-C3: this service signs; Digital Bazaar derives and verifies.
  const own = await stsCrypto.bbs.generateKeyPair();
  const ownMultikey = bbs2023.publicKeyMultibase(own.publicKey);
  const ownVm = { '@context': 'https://w3id.org/security/multikey/v1',
                  id: 'did:example:sts#bbs-1', type: 'Multikey',
                  controller: 'did:example:sts',
                  publicKeyMultibase: ownMultikey };
  const ownController = { '@context': 'https://www.w3.org/ns/cid/v1',
                          id: 'did:example:sts', assertionMethod: [ownVm] };
  const ownLoader = loaderFor(vcJsonLd, ownVm, ownController);
  const ownBase = await plain.createBaseProof(doc, {
    secretKey: own.secretKey, publicKey: own.publicKey,
    verificationMethod: ownVm.id, mandatoryPointers: ['/issuer'] });
  const dbDerived = await db.jsigs.derive(ownBase, {
    suite: new db.di.DataIntegrityProof({
      cryptosuite: db.bbs.createDiscloseCryptosuite({
        selectivePointers: ['/credentialSubject/sailNumber',
                            '/credentialSubject/boards/1'] }) }),
    purpose: purpose, documentLoader: ownLoader });
  const hereOnTheirs = await plain.verifyDerivedProof(dbDerived,
                                                      own.publicKey);
  t.check(hereOnTheirs.ok, 'C1. this service\'s base proof, derived by ' +
          'Digital Bazaar\'s library, verifies here', hereOnTheirs.detail);
  const theirsOnTheirs = await db.jsigs.verify(dbDerived, {
    suite: new db.di.DataIntegrityProof({
      cryptosuite: db.bbs.createVerifyCryptosuite() }),
    purpose: purpose, documentLoader: ownLoader });
  t.check(theirsOnTheirs.verified, 'C2. and verifies there',
          JSON.stringify(((theirsOnTheirs.error || {}).errors || [])
            .map(function (e) { return e.message; })));
  const nonce = Buffer.from('n-' + Date.now(), 'utf8');
  const ownDerived = await plain.deriveProof(ownBase,
    ['/credentialSubject/sails/0'], { presentationHeader: nonce });
  const theirsOnOurs = await db.jsigs.verify(ownDerived, {
    suite: new db.di.DataIntegrityProof({
      cryptosuite: db.bbs.createVerifyCryptosuite() }),
    purpose: purpose, documentLoader: ownLoader });
  t.check(theirsOnOurs.verified, 'C3. this service\'s derivation, with a ' +
          'presentation header, verifies there',
          JSON.stringify(((theirsOnOurs.error || {}).errors || [])
            .map(function (e) { return e.message; })));
  const ownOnOurs = await plain.verifyDerivedProof(ownDerived, own.publicKey);
  t.check(ownOnOurs.ok && Buffer.from(ownOnOurs.presentationHeader)
            .equals(nonce),
          'C4. and here, its presentation header read back',
          ownOnOurs.detail);
  // C5-C7: Digital Bazaar signs; this service checks, derives and verifies.
  const theirKey = await db.bls.generateBbsKeyPair({
    algorithm: 'BBS-BLS12-381-SHA-256', id: 'did:example:db#k1',
    controller: 'did:example:db' });
  const theirVm = await theirKey.export({ publicKey: true,
                                         includeContext: true });
  const theirController = { '@context': 'https://www.w3.org/ns/cid/v1',
                            id: 'did:example:db',
                            assertionMethod: [theirVm] };
  const theirLoader = loaderFor(vcJsonLd, theirVm, theirController);
  const theirBase = await db.jsigs.sign(doc, {
    suite: new db.di.DataIntegrityProof({ signer: theirKey.signer(),
      cryptosuite: db.bbs.createSignCryptosuite({
        mandatoryPointers: ['/issuer', '/credentialSubject/sailNumber'] }) }),
    purpose: purpose, documentLoader: theirLoader });
  const theirPublic = bbs2023.publicKeyFromMultibase(
    theirVm.publicKeyMultibase);
  const theirBaseHere = await plain.verifyBaseProof(theirBase, theirPublic);
  t.check(theirBaseHere.ok, 'C5. Digital Bazaar\'s base proof checks here, ' +
          'its Multikey read by this service', theirBaseHere.detail);
  const ourOfTheirs = await plain.deriveProof(theirBase,
    ['/credentialSubject/boards/0/brand'], { presentationHeader: nonce });
  const c6 = await plain.verifyDerivedProof(ourOfTheirs, theirPublic);
  t.check(c6.ok, 'C6. derived here from Digital Bazaar\'s base proof, it ' +
          'verifies here', c6.detail);
  const c7 = await db.jsigs.verify(ourOfTheirs, {
    suite: new db.di.DataIntegrityProof({
      cryptosuite: db.bbs.createVerifyCryptosuite() }),
    purpose: purpose, documentLoader: theirLoader });
  t.check(c7.verified, 'C7. and there',
          JSON.stringify(((c7.error || {}).errors || [])
            .map(function (e) { return e.message; })));

  t.log.info('=== D. the legacy door ===');
  t.check(bbs2023.LEGACY_CRYPTOSUITE === 'iya-bbs-2023-legacy' &&
          bbs2023.LEGACY_CRYPTOSUITE !== vcBbs.CRYPTOSUITE &&
          typeof bbs2023.legacyVerifyDerived === 'function' &&
          bbs2023.issue === undefined && bbs2023.verifyBase === undefined,
          'D1. the pre-1.1 format is read only under ' +
          'iya-bbs-2023-legacy, and nothing makes it any more');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'vc_bbs2023',
  describe: 'bbs-2023 held to W3C Data Integrity BBS Cryptosuites v1.0: ' +
            'the specification\'s vectors byte for byte, and Digital ' +
            'Bazaar\'s implementation both ways',
  run: run
};
