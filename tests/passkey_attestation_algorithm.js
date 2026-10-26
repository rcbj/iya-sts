// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/passkey_attestation_algorithm.js
//
// ===========================================================================
// WHAT A PASSKEY'S ATTESTATION IS SIGNED WITH, RECORDED AND ENFORCED (#941).
//
//   A. `pki.attestationSignatureAlgorithm()` names the algorithm a
//      certificate's ISSUER signed it with: ML-DSA-87 and ML-DSA-65 from the
//      post-quantum registry, `sha256-ecdsa` for a classical one, null for
//      something that is not a certificate.
//   B. `webauthn_attestation.assess()` records `algorithms` on the key's
//      attestation record: the statement's alg by its COSE name, each x5c
//      certificate leaf first, the anchor a trusted path reached, and
//      `postQuantum` only where every one is post-quantum — for an ML-DSA
//      packed attestation under an ML-DSA root, for a classical one, and
//      under the policy `off`, where it is the authenticator's claim.
//   C. The passkey policy's `attestationAlgorithms` demands a trusted
//      statement, and `credentials.addKey()`, the one writer, refuses a key
//      whose attestation is not signed with what the list allows
//      (STS-AUTHN-0411): classical under `post-quantum`, an ML-DSA-87
//      signature under `ml-dsa-65` alone, no attestation at all; and takes
//      the post-quantum one.
//   D. At sign-in the recorded algorithms are held to the list only while
//      `enforceAttestationAtSignIn` is on (STS-AUTHN-0412).
//   E. `passkey_rules.js`'s strict reading gives the same reason and code
//      as the issuance policy for each of those questions.
//   F. The console's and the API's key row carries the reading.
//
// THE ML-DSA CHAIN IS A FIXTURE MADE HERE, AT RUN TIME, with this service's
// own post-quantum certificate encoder (`common/crypto_impl/x509.js` over
// `pqc_x509.js`), and its statement is signed with an ML-DSA-65 key this
// file generates. NO REAL POST-QUANTUM AUTHENTICATOR'S ATTESTATION HAS BEEN
// TESTED: none was available when #941 was built, so what is shown is that
// this service reads, verifies, records and enforces a chain shaped as
// WebAuthn Level 3 section 8.2 and RFC 9881 describe one — not that any
// shipping authenticator produces such a chain. No key material is in this
// repository.
// ===========================================================================

delete process.env.CONFIG_FILE;

const asn1js = require('asn1js');
const config = require('../common/config');
const errorCodes = require('../common/error_codes');
const passkeyPolicy = require('../common/passkey_policy');
const passkeyRules = require('../common/passkey_rules');
const credentials = require('../common/credentials');
const pki = require('../common/pki');
const ldap = require('../ldap/ldap_server');
const x509 = require('../common/crypto_impl/x509');
const pqx = require('../common/crypto_impl/pqc_x509');
const webauthn = require('../authn/webauthn');
const webauthnPolicy = require('../authn/webauthn_policy');
const attestation = require('../authn/webauthn_attestation');
const kit = require('./webauthn_attestation_kit');

const log = require('bunyan').createLogger({
  name: 'passkey_attestation_algorithm',
  level: process.env.LOG_LEVEL || 'info' });

// An ML-DSA key pair as the encoder takes it, and its raw private key for
// signing a statement.
async function mldsa(name) {
  log.debug('Entering mldsa(). ' + name);
  const pair = await pqx.generateKeyPair(name);
  log.debug('Leaving mldsa().');
  return { name: name, priv: pair.priv,
           publicPem: pqx.publicPem(name, pair.pub),
           privatePem: pqx.privatePem(name, pair.priv) };
}

// An ML-DSA-87 root and an ML-DSA-65 attestation certificate under it,
// carrying what section 8.2.1 requires of a packed one and the AAGUID
// extension: `{ root, leaf, key }`.
async function mldsaChain(aaguid) {
  log.debug('Entering mldsaChain().');
  const rootKey = await mldsa('ML-DSA-87');
  const now = new Date();
  const later = new Date(now.getTime() + 86400000);
  const root = await x509.issueCertificate({
    subject: [{ name: 'CN', value: 'Synthetic PQ Attestation Root' }],
    subjectPublicKey: rootKey.publicPem,
    issuerPrivateKey: rootKey.privatePem,
    signatureAlg: 'ml-dsa-87',
    notBefore: new Date(now.getTime() - 3600000).toISOString(),
    notAfter: later.toISOString(),
    extensions: {
      basicConstraints: { present: true, critical: true, ca: true },
      keyUsage: { present: true, critical: true,
                  usages: ['keyCertSign', 'cRLSign'] },
      subjectKeyIdentifier: { present: true } } });
  const leafKey = await mldsa('ML-DSA-65');
  const aaguidDer = Buffer.from(new asn1js.OctetString({
    valueHex: new Uint8Array(aaguid).buffer }).toBER(false));
  const leaf = await x509.issueCertificate({
    subject: [{ name: 'C', value: 'US' },
              { name: 'O', value: 'Synthetic PQ Vendor' },
              { name: 'OU', value: 'Authenticator Attestation' },
              { name: 'CN', value: 'Synthetic PQ Attestation' }],
    subjectPublicKey: leafKey.publicPem,
    signatureAlg: 'ml-dsa-87',
    issuer: { certificatePem: root.pem, privateKeyPem: rootKey.privatePem,
              keyAlg: 'ml-dsa-87' },
    notBefore: new Date(now.getTime() - 3600000).toISOString(),
    notAfter: later.toISOString(),
    extensions: {
      basicConstraints: { present: true, critical: true, ca: false },
      keyUsage: { present: true, critical: true,
                  usages: ['digitalSignature'] },
      subjectKeyIdentifier: { present: true },
      authorityKeyIdentifier: { present: true },
      custom: [{ oid: '1.3.6.1.4.1.45724.1.1.4', critical: false,
                 value: aaguidDer.toString('base64') }] } });
  log.debug('Leaving mldsaChain().');
  return { root: { pem: root.pem, der: Buffer.from(root.der) },
           leaf: { pem: leaf.pem, der: Buffer.from(leaf.der) },
           key: leafKey };
}

// A packed attestation of the ceremony `ctx` under the ML-DSA chain: the
// statement signed with the ML-DSA-65 attestation key, alg -49.
async function packedMldsa(ctx, chain) {
  log.debug('Entering packedMldsa().');
  const signed = Buffer.concat([ctx.authData, ctx.clientDataHash]);
  const sig = Buffer.from(await pqx.sign('ML-DSA-65', new Uint8Array(signed),
                                         chain.key.priv));
  log.debug('Leaving packedMldsa().');
  return { fmt: 'packed',
           attStmt: { alg: -49, sig: sig, x5c: [chain.leaf.der] } };
}

function withRow(value, extra) {
  log.debug('Entering withRow().');
  log.debug('Leaving withRow().');
  return passkeyPolicy.save('default', Object.assign({},
    passkeyPolicy.DEFAULTS, { attestationAlgorithms: value }, extra || {}));
}

async function namesCertificates(t, chain) {
  log.debug('Entering namesCertificates().');
  const classical = await kit.root('Classical Vendor');
  const a = pki.attestationSignatureAlgorithm(chain.root.der);
  const b = pki.attestationSignatureAlgorithm(chain.leaf.der);
  const c = pki.attestationSignatureAlgorithm(classical.der);
  t.check(a && a.algorithm === 'ML-DSA-87' && a.postQuantum === true &&
          a.family === 'ML-DSA' && a.oid === '2.16.840.1.101.3.4.3.19' &&
          b && b.algorithm === 'ML-DSA-87' && b.postQuantum === true &&
          c && c.algorithm === 'sha256-ecdsa' && c.postQuantum === false &&
          pki.attestationSignatureAlgorithm(Buffer.from('nonsense')) === null,
          'A. a certificate is named by what its issuer signed it with: ' +
          'ML-DSA-87 for the root and the leaf under it, sha256-ecdsa for ' +
          'a classical one, null for no certificate',
          JSON.stringify([a, b, c]));
  log.debug('Leaving namesCertificates().');
}

async function records(t, chain, aaguid) {
  log.debug('Entering records().');
  config.setOverride('webauthn.attestationPolicy', 'verify-if-present');
  config.setOverride('webauthn.attestationTrustAnchors', chain.root.pem);
  const out = {};
  try {
    const pqCtx = await kit.ceremony({ alg: -49, aaguid: aaguid });
    const pqMade = await packedMldsa(pqCtx, chain);
    const pq = await attestation.assess(
      webauthn.verifyRegistration(pqCtx.input(pqMade)));
    const pa = pq.attestation && pq.attestation.algorithms;
    t.check(pq.ok && pq.attestation.trusted === true && pa &&
            pa.statement === 'ML-DSA-65' && pa.statementCoseAlg === -49 &&
            pa.certificates.length === 1 &&
            pa.certificates[0].algorithm === 'ML-DSA-87' &&
            pa.anchor && pa.anchor.algorithm === 'ML-DSA-87' &&
            pa.postQuantum === true,
            'B. an ML-DSA packed attestation under an ML-DSA root records ' +
            'its statement alg, its certificate and its anchor, all ' +
            'post-quantum (a synthetic chain: no real post-quantum ' +
            'authenticator was tested)',
            JSON.stringify([pq.ok, pq.why, pa]));
    out.pq = pq.attestation;
    const root = await kit.root('Classical Vendor');
    config.setOverride('webauthn.attestationTrustAnchors', root.pem);
    const ecCtx = await kit.ceremony({});
    const ec = await attestation.assess(
      webauthn.verifyRegistration(ecCtx.input(await kit.packed(ecCtx,
                                                               root))));
    const ea = ec.attestation && ec.attestation.algorithms;
    t.check(ec.ok && ea && ea.statement === 'ES256' &&
            ea.certificates[0].algorithm === 'sha256-ecdsa' &&
            ea.anchor && ea.anchor.algorithm === 'sha256-ecdsa' &&
            ea.postQuantum === false,
            'B2. a classical packed attestation records ES256 and ' +
            'sha256-ecdsa, and is not post-quantum', JSON.stringify(ea));
    out.ec = ec.attestation;
    config.setOverride('webauthn.attestationPolicy', 'off');
    const offCtx = await kit.ceremony({ alg: -49, aaguid: aaguid });
    const off = await attestation.assess(
      webauthn.verifyRegistration(offCtx.input(await packedMldsa(offCtx,
                                                                 chain))));
    const oa = off.attestation && off.attestation.algorithms;
    t.check(off.ok && off.attestation.verified === false && oa &&
            oa.statement === 'ML-DSA-65' &&
            oa.certificates[0].algorithm === 'ML-DSA-87' &&
            oa.anchor === null,
            'B3. under the policy off the algorithms are recorded as ' +
            'claimed, beside verified false, with no anchor',
            JSON.stringify(off.attestation));
    const none = await attestation.assess(
      webauthn.verifyRegistration(offCtx.input(kit.none())));
    t.check(none.attestation.algorithms.statement === '' &&
            none.attestation.algorithms.certificates.length === 0 &&
            none.attestation.algorithms.postQuantum === false,
            'B4. a none attestation records no algorithm and is never ' +
            'post-quantum attestation', JSON.stringify(none.attestation));
  } finally {
    config.clearOverride('webauthn.attestationPolicy');
    config.clearOverride('webauthn.attestationTrustAnchors');
  }
  log.debug('Leaving records().');
  return out;
}

function enforced(t, recorded) {
  log.debug('Entering enforced().');
  const name = 'paa-' + require('crypto').randomBytes(3).toString('hex');
  ldap.createUser(name, { invent: false });
  let n = 0;
  const add = function (att) {
    log.debug('Entering enforced() add().');
    n += 1;
    const out = credentials.addKey(name, {
      credentialId: 'paa-cred-' + n,
      publicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'AA', y: 'AA' },
      attestation: att }, 'mfa');
    log.debug('Leaving enforced() add().');
    return out;
  };
  try {
    t.check(add(recorded.ec).ok,
            'C. with the list at none, a classical attestation registers');
    withRow('post-quantum');
    const settings = webauthnPolicy.attestationSettings();
    t.check(settings.demandsTrust === true &&
            /attestationAlgorithms/.test(
              attestation.WebauthnAttestation.demandedBy(settings)),
            'C2. the list demands a trusted statement, and says so');
    const ec = add(recorded.ec);
    const bare = add(null);
    const pq = add(recorded.pq);
    t.check(!ec.ok && errorCodes.codeOf(ec) === 'STS-AUTHN-0411' &&
            ec.reason === 'attestation-algorithm' &&
            /attestationAlgorithms/.test((ec.errors || []).join(' ')),
            'C3. a classical attestation is refused under post-quantum ' +
            '(STS-AUTHN-0411)', JSON.stringify(ec));
    t.check(!bare.ok && errorCodes.codeOf(bare) === 'STS-AUTHN-0411',
            'C4. a key with no attestation is refused too',
            JSON.stringify(bare));
    t.check(pq.ok, 'C5. the post-quantum attestation registers',
            JSON.stringify(pq.errors));
    withRow('ml-dsa-65');
    const narrow = add(recorded.pq);
    t.check(!narrow.ok && errorCodes.codeOf(narrow) === 'STS-AUTHN-0411',
            'C6. ml-dsa-65 alone refuses a chain an ML-DSA-87 key signed',
            JSON.stringify(narrow));
    withRow('ml-dsa-65,ml-dsa-87');
    t.check(add(recorded.pq).ok,
            'C7. naming both parameter sets takes it');
  } finally {
    passkeyPolicy.reset('default');
  }
  log.debug('Leaving enforced().');
}

async function atSignIn(t, recorded) {
  log.debug('Entering atSignIn().');
  const ecKey = { credentialId: 'paa-sign-ec', attestation: recorded.ec };
  const pqKey = { credentialId: 'paa-sign-pq', attestation: recorded.pq };
  try {
    withRow('post-quantum', { enforceAttestationAtSignIn: true });
    const held = await attestation.signInVerdict(ecKey,
      { username: 'paa', enforced: true });
    const pq = await attestation.signInVerdict(pqKey,
      { username: 'paa', enforced: true });
    const loose = await attestation.signInVerdict(ecKey,
      { username: 'paa', enforced: false });
    t.check(!held.ok && errorCodes.codeOf(held) === 'STS-AUTHN-0412' &&
            held.reason === 'attestation-algorithm',
            'D. while sign-ins are held to the rules, a classical recorded ' +
            'attestation is refused (STS-AUTHN-0412)', JSON.stringify(held));
    t.check(pq.ok, 'D2. the post-quantum one signs in',
            JSON.stringify(pq));
    t.check(loose.ok, 'D3. with sign-ins not held to the rules, the list ' +
            'binds registration only', JSON.stringify(loose));
  } finally {
    passkeyPolicy.reset('default');
  }
  log.debug('Leaving atSignIn().');
}

function agrees(t, recorded) {
  log.debug('Entering agrees().');
  try {
    let same = 0;
    let asked = 0;
    const rows = ['post-quantum', 'ml-dsa-65', 'ml-dsa-65,ml-dsa-87',
                  'slh-dsa', 'composite-ml-dsa', 'none'];
    rows.forEach(function (row) {
      withRow(row, { enforceAttestationAtSignIn: true });
      [recorded.ec, recorded.pq, null].forEach(function (att) {
        ['registration', 'sign-in'].forEach(function (at) {
          const facts = { username: 'paa', attestationAlgorithms:
            attestation.recordedAlgorithms(att) };
          const document = passkeyPolicy.refusalFor(at, facts);
          const strict = passkeyRules.strictReading(
            passkeyPolicy.question(at, facts));
          asked += 1;
          if ((document ? document.reason : '') === strict.reason &&
              (document ? document.code : '') === strict.code) {
            same += 1;
          }
        });
      });
    });
    t.check(asked === 36 && same === asked,
            'E. the strict reading agrees with the issuance policy on all ' +
            asked + ' questions', same + ' of ' + asked);
  } finally {
    passkeyPolicy.reset('default');
  }
  log.debug('Leaving agrees().');
}

function shown(t, recorded) {
  log.debug('Entering shown().');
  const pq = credentials.attestationAlgorithms({ attestation: recorded.pq });
  const ec = credentials.attestationAlgorithms({ attestation: recorded.ec });
  const old = credentials.attestationAlgorithms({ attestation: {
    verified: true, trusted: true } });
  t.check(pq.recorded && pq.postQuantum === true &&
          pq.statement === 'ML-DSA-65' &&
          pq.certificates.map(function (c) {
            return c.algorithm;
          }).join(',') === 'ML-DSA-87,ML-DSA-87' &&
          ec.recorded && ec.postQuantum === false &&
          old.recorded === false && old.postQuantum === false,
          'F. the key row\'s reading: statement, chain leaf to anchor, ' +
          'post-quantum or not, and nothing recorded before #941',
          JSON.stringify([pq, ec, old]));
  log.debug('Leaving shown().');
}

module.exports = {
  name: 'passkey_attestation_algorithm',
  describe: 'what a passkey\'s attestation is signed with, recorded and ' +
            'enforced, over a synthetic ML-DSA chain (#941); no real ' +
            'post-quantum authenticator\'s attestation was tested',
  run: async function (t) {
    log.debug('Entering run().');
    const aaguid = require('crypto').randomBytes(16);
    const chain = await mldsaChain(aaguid);
    await namesCertificates(t, chain);
    const recorded = await records(t, chain, aaguid);
    enforced(t, recorded);
    await atSignIn(t, recorded);
    agrees(t, recorded);
    shown(t, recorded);
    log.debug('Leaving run().');
  }
};
