'use strict';
// ===========================================================================
// tests/vc_rdfc_suites.js — THE RDFC CRYPTOSUITES AND ecdsa-sd-2023
// (#195, #196, 2026-09-26).
//
// oid4vc/vc_data_integrity.ts signs and verifies eddsa-rdfc-2022 and
// ecdsa-rdfc-2019 over vc_jsonld.ts's closed loader, and ecdsa-sd-2023
// through vc_ecdsa_sd.ts. The claims, each against a vector nobody here
// wrote where one exists:
//
//   A. ecdsa-rdfc-2019: the specification's combined hash for its P-256 and
//      P-384 vectors, and its signed credentials verify; a changed claim or
//      a flipped proof byte does not.
//   B. round trips: every RDFC suite and curve signs and verifies, VC 2.0
//      and 1.1 (the Data Integrity context added); a proof SET and a proof
//      CHAIN verify member by member, and a chain naming a proof the
//      document does not carry is refused; a context this service does not
//      hold refuses to sign.
//   C. ecdsa-sd-2023 against the specification's own intermediate values
//      (its TestVectors, the HMAC key fixed): the relabelled canonical
//      statements, a derived proof from its base proof byte for byte its
//      derived proof, its derived credential verifies, and a disclosed
//      statement changed does not; a base proof is refused by a verifier;
//      a pointer to nothing refuses to sign.
//   D. the defaults: a caller naming no suite still gets only the JCS four
//      (the sign-in's holder proof is unchanged), and ALL_CRYPTOSUITES
//      lists all seven.
//
// The vectors are fetched into the tests image with the W3C suites
// (tests/vc-suites/fetch-suites.sh): they carry private keys.
// ===========================================================================

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const log = require('bunyan').createLogger({ name: 'vc_rdfc_suites_test',
  level: process.env.LOG_LEVEL || 'info' });

const SUITES = process.env.STS_VC_SUITES_DIR || '/opt/vc-suites';
const VECTORS = path.join(SUITES, 'vc-di-ecdsa-test-suite', 'tests', 'input',
                          'vc-di-ecdsa', 'TestVectors');

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

function pair(curve) {
  log.debug("Entering pair(). " + curve);
  const made = curve === 'Ed25519'
    ? crypto.generateKeyPairSync('ed25519')
    : crypto.generateKeyPairSync('ec', { namedCurve: curve === 'P-256'
                                         ? 'prime256v1' : 'secp384r1' });
  const jwk = made.publicKey.export({ format: 'jwk' });
  log.debug("Leaving pair().");
  return { privateKey: made.privateKey, publicJwk: jwk };
}

const VERIFY = { expectedPurpose: 'assertionMethod', expectedChallenge: null,
                 expectedDomain: null, createdRequired: false };

async function run(t) {
  log.debug("Entering run().");
  const di = require('../oid4vc/vc_data_integrity');
  const sd = require('../oid4vc/vc_ecdsa_sd');
  const all = { allowedCryptosuites: di.ALL_CRYPTOSUITES };

  t.log.info('=== A. ecdsa-rdfc-2019, the specification\'s vectors ===');
  for (const curve of ['P256', 'P384']) {
    const base = 'ecdsa-rdfc-2019-' + curve.toLowerCase() + '/';
    const signed = json(base + 'signed' + 'ECDSA' + curve + '.json');
    const unsecured = Object.assign({}, signed);
    delete unsecured.proof;
    const config = Object.assign({}, signed.proof);
    delete config.proofValue;
    const suite = di.SUITES['ecdsa-rdfc-2019'];
    const hash = await di.hashDataAsync(suite,
      { kty: 'EC', crv: curve === 'P256' ? 'P-256' : 'P-384' }, config,
      unsecured);
    t.check(hash.toString('hex') === read(base + 'combinedHashECDSA' + curve +
                                          '.txt').trim(),
            'A1. the ' + curve + ' combined hash is the vector\'s');
    const r = await di.verifyAllProofs(signed, Object.assign({}, VERIFY,
                                                              all));
    t.check(r.ok, 'A2. the specification\'s ' + curve + ' credential ' +
            'verifies', JSON.stringify(r.results.map(function (x) {
              return x.checks.filter(function (c) { return !c.ok; });
            })));
    const changed = JSON.parse(JSON.stringify(signed));
    changed.credentialSubject.alumniOf = 'Another School';
    t.check(!(await di.verifyAllProofs(changed, Object.assign({}, VERIFY,
                                                               all))).ok,
            'A3. a changed claim does not verify (' + curve + ')');
  }

  t.log.info('=== B. round trips, sets and chains ===');
  const doc = { '@context': ['https://www.w3.org/ns/credentials/v2',
                             'https://www.w3.org/ns/credentials/examples/v2'],
                id: 'urn:uuid:' + crypto.randomUUID(),
                type: ['VerifiableCredential', 'ExampleCredential'],
                issuer: 'did:example:issuer',
                credentialSubject: { id: 'did:example:subject',
                                     name: 'Subject' } };
  const rows = [['eddsa-rdfc-2022', 'Ed25519'],
                ['ecdsa-rdfc-2019', 'P-256'], ['ecdsa-rdfc-2019', 'P-384']];
  for (const row of rows) {
    const key = pair(row[1]);
    const vm = di.didKeyOf(key.publicJwk) + '#' +
      di.didKeyOf(key.publicJwk).slice('did:key:'.length);
    const signed = await di.signDocument(doc, { cryptosuite: row[0],
      publicJwk: key.publicJwk, privateKey: key.privateKey,
      verificationMethod: vm, proofPurpose: 'assertionMethod' });
    const r = await di.verifyAllProofs(signed, Object.assign({}, VERIFY,
                                                              all));
    t.check(r.ok && signed.proof['@context'] === undefined,
            'B1. ' + row[0] + ' over ' + row[1] + ' signs and verifies, ' +
            'the proof carrying no @context');
    const flipped = JSON.parse(JSON.stringify(signed));
    const value = di.base58Decode(flipped.proof.proofValue.slice(1));
    value[3] ^= 1;
    flipped.proof.proofValue = 'z' + di.base58Encode(value);
    t.check(!(await di.verifyAllProofs(flipped, Object.assign({}, VERIFY,
                                                               all))).ok,
            'B2. a flipped signature byte does not verify (' + row[0] + ')');
  }
  const v11 = { '@context': ['https://www.w3.org/2018/credentials/v1',
                             'https://w3id.org/security/data-integrity/v2'],
                type: ['VerifiableCredential'], issuer: 'did:example:issuer',
                issuanceDate: '2024-01-01T00:00:00Z',
                credentialSubject: { id: 'did:example:subject' } };
  const edKey = pair('Ed25519');
  const edVm = di.didKeyOf(edKey.publicJwk) + '#' +
    di.didKeyOf(edKey.publicJwk).slice('did:key:'.length);
  const signed11 = await di.signDocument(v11, { cryptosuite:
    'eddsa-rdfc-2022', publicJwk: edKey.publicJwk,
    privateKey: edKey.privateKey, verificationMethod: edVm,
    proofPurpose: 'assertionMethod' });
  t.check((await di.verifyAllProofs(signed11, Object.assign({}, VERIFY,
                                                            all))).ok,
          'B3. a VC 1.1 credential with the Data Integrity context signs and ' +
          'verifies');
  const p256 = pair('P-256');
  const p256Vm = di.didKeyOf(p256.publicJwk) + '#' +
    di.didKeyOf(p256.publicJwk).slice('did:key:'.length);
  const first = await di.signDocument(doc, { cryptosuite: 'eddsa-rdfc-2022',
    publicJwk: edKey.publicJwk, privateKey: edKey.privateKey,
    verificationMethod: edVm, proofPurpose: 'assertionMethod',
    id: 'urn:uuid:first-proof' });
  const set = await di.signDocument(first, { cryptosuite: 'ecdsa-rdfc-2019',
    publicJwk: p256.publicJwk, privateKey: p256.privateKey,
    verificationMethod: p256Vm, proofPurpose: 'assertionMethod' });
  t.check(Array.isArray(set.proof) && set.proof.length === 2 &&
          (await di.verifyAllProofs(set, Object.assign({}, VERIFY,
                                                       all))).ok,
          'B4. a proof set of two verifies member by member');
  const chain = await di.signDocument(first, { cryptosuite:
    'ecdsa-rdfc-2019', publicJwk: p256.publicJwk,
    privateKey: p256.privateKey, verificationMethod: p256Vm,
    proofPurpose: 'assertionMethod', previousProof: 'urn:uuid:first-proof' });
  t.check((await di.verifyAllProofs(chain, Object.assign({}, VERIFY,
                                                         all))).ok,
          'B5. a proof chain verifies, the second over the first');
  const broken = JSON.parse(JSON.stringify(chain));
  broken.proof[1].previousProof = 'urn:uuid:no-such-proof';
  t.check(!(await di.verifyAllProofs(broken, Object.assign({}, VERIFY,
                                                           all))).ok,
          'B6. a chain naming a proof the document does not carry is refused');
  let refused = '';
  try {
    await di.signDocument(Object.assign({}, doc, { '@context':
      ['https://www.w3.org/ns/credentials/v2', 'https://example.com/ctx'] }),
      { cryptosuite: 'eddsa-rdfc-2022', publicJwk: edKey.publicJwk,
        privateKey: edKey.privateKey, verificationMethod: edVm });
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    refused = String(e.message);
  }
  t.check(/example\.com\/ctx/.test(refused),
          'B7. a context this service does not hold refuses to sign',
          refused);

  t.log.info('=== C. ecdsa-sd-2023, the specification\'s values ===');
  const material = json('ecdsa-sd-2023/SDKeyMaterial.json');
  const issuerJwk = di.jwkOfMultikey(material.baseKeyPair.publicKeyMultibase);
  const hmacKey = Buffer.from(material.hmacKeyString, 'hex');
  const cases = [['employ', 'employmentAuth.json', 'employMandatory.json',
                  'employSelective.json'],
                 ['prc', 'prCredUnsigned.json', 'prCredMandatory.json',
                  'prCredSelective.json']];
  for (const c of cases) {
    const dir = 'ecdsa-sd-2023/' + c[0] + '/';
    const inst = new sd.VcEcdsaSd(sd.VcEcdsaSd.defaultDeps());
    const grouped = await inst.canonicalizeAndGroup(json(c[1]),
      inst.hmacLabelMapFactory(hmacKey), { mandatory: json(c[2]) });
    t.check(JSON.stringify(grouped.nquads) ===
            JSON.stringify(json(dir + 'addBaseDocHMACCanon.json')),
            'C1. ' + c[0] + ': the HMAC-relabelled statements are the ' +
            'vector\'s');
    const wantMandatory = json(dir + 'addBaseTransform.json').mandatory;
    t.check(JSON.stringify(Array.from(grouped.groups.mandatory.matching
      .entries())) === JSON.stringify(wantMandatory.value),
            'C2. ' + c[0] + ': the mandatory statements are the vector\'s');
    const base = json(dir + 'addSignedSDBase.json');
    const derived = await inst.deriveProof(base, json(c[3]));
    const wanted = json(dir + 'derivedRevealDocument.json');
    t.check(derived.proof.proofValue === wanted.proof.proofValue,
            'C3. ' + c[0] + ': a derived proof from its base proof is its ' +
            'derived proof byte for byte');
    const r = await sd.verifyDerivedProof(wanted, issuerJwk);
    t.check(r.ok, 'C4. ' + c[0] + ': its derived credential verifies',
            r.detail);
    const changed = JSON.parse(JSON.stringify(wanted));
    const subject = changed.credentialSubject;
    const k = Object.keys(subject).filter(function (name) {
      return name !== 'id' && typeof subject[name] === 'string';
    })[0];
    if (k) {
      subject[k] = subject[k] + ' (changed)';
    }
    t.check(!!k && !(await sd.verifyDerivedProof(changed, issuerJwk)).ok,
            'C5. ' + c[0] + ': a disclosed statement changed does not ' +
            'verify');
    const asBase = await sd.verifyDerivedProof(base, issuerJwk);
    t.check(!asBase.ok && /BASE proof/.test(asBase.detail),
            'C6. ' + c[0] + ': a base proof is refused by a verifier',
            asBase.detail);
  }
  const sdKey = pair('P-256');
  let pointer = '';
  try {
    await sd.createBaseProof(doc, { publicJwk: sdKey.publicJwk,
      privateKey: sdKey.privateKey, verificationMethod: 'did:example:x#1',
      mandatoryPointers: ['/credentialSubject/nothing'] });
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    pointer = String(e.message);
  }
  t.check(/does not match/.test(pointer),
          'C7. a mandatory pointer to nothing refuses to sign', pointer);
  const sdVm = di.didKeyOf(sdKey.publicJwk) + '#' +
    di.didKeyOf(sdKey.publicJwk).slice('did:key:'.length);
  const ownBase = await di.signDocument(doc, { cryptosuite: 'ecdsa-sd-2023',
    publicJwk: sdKey.publicJwk, privateKey: sdKey.privateKey,
    verificationMethod: sdVm, mandatoryPointers: ['/issuer'] });
  const ownDerived = await di.deriveProof(ownBase, ['/credentialSubject/name']);
  const ownR = await di.verifyAllProofs(ownDerived, Object.assign({}, VERIFY,
                                                                  all));
  t.check(ownR.ok && ownDerived.credentialSubject.name === 'Subject',
          'C8. this service\'s own base proof derives and verifies through ' +
          'vc_data_integrity');

  t.log.info('=== D. the defaults ===');
  t.check(di.SUPPORTED_CRYPTOSUITES.join(',') ===
          'ecdsa-jcs-2019,eddsa-jcs-2022,mldsa44-jcs-2024,slhdsa128-jcs-2024',
          'D1. a caller naming no suite still gets the JCS four',
          di.SUPPORTED_CRYPTOSUITES.join(','));
  t.check(di.ALL_CRYPTOSUITES.length === 7 &&
          di.ALL_CRYPTOSUITES.indexOf('ecdsa-sd-2023') >= 0,
          'D2. ALL_CRYPTOSUITES lists all seven',
          di.ALL_CRYPTOSUITES.join(','));
  log.debug("Leaving run().");
}

module.exports = {
  name: 'vc_rdfc_suites',
  describe: 'eddsa-rdfc-2022, ecdsa-rdfc-2019 and ecdsa-sd-2023 held to the ' +
            'ECDSA specification\'s vectors, round trips, proof sets and ' +
            'chains, and the JCS default kept',
  run: run
};
