// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: pki_hybrid.js
//
// ===========================================================================
// THE HYBRID CERTIFICATE AUTHORITY (2026-09-26, #68 phase 1): every tier
// holds an alternative post-quantum key beside its classical one, every
// certificate it issues is signed twice, and a path in this service's own
// hierarchy is verified as hybrid or not at all.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS, WHICH IS THE QUESTION tests/CLAUDE.md ASKS FIRST.
//
// The claims that matter are about certificates no client can be made to
// send: a leaf under this realm's Issuing CA carrying NO alternative signature
// (the downgrade the policy exists for), and one whose alternative signature
// was made by the WRONG key. Both need the Issuing CA's classical private key,
// which nothing hands out — `issuerFor()` is an in-process door. And "the
// alternative private key is never in the public view" is an assertion about
// what a function dropped, which over HTTP is the absence of a string.
//
// What is NOT re-asserted is the encoder: `common/crypto_impl/x509.js`'s
// preTBSCertificate arithmetic is the parent project's file and is held to
// its own tests there. What is asserted is that `pki.js` REACHES it — each
// tier carries the key it was asked for and a signature its issuer's
// alternative key verifies — and what `pki.js` decides on top of it.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const tls = require('tls');
const config = require('../common/config');
const pki = require('../common/pki');
const keystore = require('../common/keystore');
const errorCodes = require('../common/error_codes');
const x509 = require('../common/crypto_impl/x509');
const keyMaterial = require('../common/crypto_impl/key_material');

const log = require('bunyan').createLogger({ name: 'pki_hybrid',
  level: process.env.LOG_LEVEL || 'info' });

// A realm id per section, for `tests/pki.js`'s reason: nothing below may pass
// because of what another section left behind.
const REALM = 'pki-hybrid';
const CLASSICAL = 'pki-hybrid-classical';
const REFUSED = 'pki-hybrid-refused';

// A leaf under `issuer` (an `issuerFor()` record), made directly with the
// encoder so that its alternative signature is whatever the CASE says: the
// issuer's (`alt: 'issuer'`), a stranger's (`alt: 'stranger'`), or none.
async function leafUnder(issuer, alt) {
  log.debug("Entering leafUnder(). alt=" + alt);
  const pair = await keyMaterial.generateKeyPair('ec-p256');
  const notBefore = new Date();
  notBefore.setUTCMilliseconds(0);
  const notAfter = new Date(notBefore.getTime() + 86400000);
  let altSignature;
  if (alt === 'issuer') {
    altSignature = { signatureAlg: issuer.altKeyAlg,
                     privateKeyPem: issuer.altPrivateKeyPem,
                     keyAlg: issuer.altKeyAlg };
  } else if (alt === 'stranger') {
    const stranger = await keyMaterial.generateKeyPair(issuer.altKeyAlg);
    altSignature = { signatureAlg: issuer.altKeyAlg,
                     privateKeyPem: stranger.privatePem,
                     keyAlg: issuer.altKeyAlg };
  }
  const issued = await x509.issueCertificate({
    subject: [{ name: 'CN', value: 'hybrid-probe-' + alt }],
    subjectPublicKey: pair.publicPem,
    signatureAlg: x509.defaultSignatureAlgorithm(
      keyMaterial.keyAlg(issuer.keyAlg)),
    profile: 'digital-signature',
    notBefore: notBefore.toISOString(),
    notAfter: notAfter.toISOString(),
    issuer: { certificatePem: issuer.certificatePem,
              privateKeyPem: issuer.privateKeyPem, keyAlg: issuer.keyAlg },
    altSignature: altSignature,
    extensions: {
      basicConstraints: { present: true, critical: true, ca: false },
      keyUsage: { present: true, critical: true,
                  usages: ['digitalSignature'] },
      subjectKeyIdentifier: { present: true },
      authorityKeyIdentifier: { present: true }
    }
  });
  log.debug("Leaving leafUnder().");
  return issued.pem;
}

function derOf(pem) {
  log.debug("Entering derOf().");
  log.debug("Leaving derOf().");
  return Buffer.from(new nodeCrypto.X509Certificate(pem).raw);
}

async function run(t) {
  log.debug("Entering run().");
  // THE ROOT ASSERTED ABOUT IS ONE THIS FILE BUILT — `tests/pki.js` gives the
  // reason at length: `run.js` runs every file in one process and a Root
  // left by an earlier file would be reused.
  if (keystore.pkiFor(pki.SERVICE_SCOPE)) {
    log.info('pki_hybrid test: a service Root was left by an earlier file; ' +
             'set aside so the Root asserted below is one this file built.');
    keystore.attachPki(pki.SERVICE_SCOPE, null);
  }
  // HYBRID IS OFF BY DEFAULT since 2026-09-26 (rcbj): `none` is the
  // setting's default, so this file turns it on for itself and puts it back.
  const set = config.setOverride('pki.alternativeKeyAlgorithm', 'ml-dsa-87');
  t.check(set && set.ok !== false,
          'pki.alternativeKeyAlgorithm is set to ml-dsa-87 for this file',
          JSON.stringify(set));
  try {
    await everyTierIsHybrid(t);
    await aLeafIsSignedTwiceAndVerified(t);
    await theDowngradeIsRefused(t);
    await aForeignPathRefusesOnlyAWrongSignature(t);
    await aClassicalBranchStillVerifies(t);
    await anAlgorithmThatCannotSignIsRefused(t);
    await aProcessBranchPastTheListenerLimitIsRefused(t);
    await aListenerChainKeyOpenSslCannotReadIsRefused(t);
  } finally {
    [REALM, CLASSICAL, REFUSED].forEach(function (id) {
      pki.clearChain(id);
    });
    config.clearOverride('pki.alternativeKeyAlgorithm');
  }
  log.debug("Leaving run().");
}

async function everyTierIsHybrid(t) {
  log.debug("Entering everyTierIsHybrid().");
  t.log.info('=== 1. every tier holds an ML-DSA-87 key, and is signed ' +
             'twice ===');
  const built = await pki.buildChain(REALM, { organisation: 'Hybrid' });
  t.check(built.ok, 'a hierarchy is built with the setting at ml-dsa-87',
          (built.errors || []).join(' '));
  const tiers = built.chain.tiers;
  t.check(tiers.every(function (one) {
            return one.altKeyAlg === 'ml-dsa-87';
          }),
          'EVERY tier — Root, Intermediate, Issuing — holds an ML-DSA-87 ' +
          'alternative key, the default rcbj chose for an authority (D4)',
          tiers.map(function (one) { return one.altKeyAlg; }).join(','));
  t.check(tiers.every(function (one) {
            return one.altSignatureAlg === 'ml-dsa-87';
          }),
          'and every tier carries an alternative signature, the Root\'s by ' +
          'its own key and each other\'s by its issuer\'s');
  t.check(JSON.stringify(built.chain).indexOf('PRIVATE KEY') < 0,
          'no PRIVATE KEY block — classical OR alternative — is anywhere in ' +
          'the public view');

  // The alternative signatures, checked link by link by the encoder's own
  // verifier: each against the key in its issuer's subjectAltPublicKeyInfo.
  const pems = tiers.slice().reverse().map(function (one) {
    return one.certificatePem;
  });
  const links = await x509.verifyChain(pems);
  t.check(links.every(function (link) {
            return link.alternative && link.alternative.present &&
                   link.alternative.valid === true;
          }),
          'each alternative signature verifies under its issuer\'s ' +
          'ALTERNATIVE key (the Root\'s under its own)',
          JSON.stringify(links.map(function (link) {
            return link.alternative;
          })));

  // AND A VALIDATOR THAT HAS NEVER HEARD OF CLAUSE 9.8 SEES A CLASSICAL
  // CHAIN, which is the whole migration argument for this shape. OpenSSL,
  // through node, is that validator: it parses each certificate and checks
  // the classical signature, the extensions being non-critical.
  const root = new nodeCrypto.X509Certificate(pems[2]);
  const intermediate = new nodeCrypto.X509Certificate(pems[1]);
  const issuing = new nodeCrypto.X509Certificate(pems[0]);
  t.check(intermediate.verify(root.publicKey) &&
          issuing.verify(intermediate.publicKey) &&
          root.verify(root.publicKey),
          'OpenSSL verifies every classical signature on the hybrid chain — ' +
          'a legacy validator is unaffected');
  t.check(issuing.checkIssued(intermediate) &&
          intermediate.checkIssued(root),
          'and builds the path, extensions and all');
  log.debug("Leaving everyTierIsHybrid().");
}

async function aLeafIsSignedTwiceAndVerified(t) {
  log.debug("Entering aLeafIsSignedTwiceAndVerified().");
  t.log.info('=== 2. a leaf the hierarchy issues is signed twice, and ' +
             'verifies ===');
  const issued = await pki.issueSigningKeyPair(REALM,
                                               { identifier: 'hybrid-app' });
  t.check(issued.ok, 'a key pair is issued', (issued.errors || []).join(' '));
  const leafPem = issued.issued.certificatePem;
  const issuer = pki.issuerFor(REALM, 'tier:issuing');
  const links = await x509.verifyChain([leafPem, issuer.certificatePem]);
  t.check(links[0].alternative && links[0].alternative.valid === true,
          'the leaf carries an alternative signature, made by the Issuing ' +
          'CA\'s ML-DSA-87 key (alternativeSignatureBy())',
          JSON.stringify(links[0].alternative));
  const verdict = await pki.verifyLeaf(REALM, leafPem, pki.chainPemFor(REALM));
  t.check(verdict.ok, 'and verifyLeaf() accepts the hybrid path',
          verdict.why || '');
  log.debug("Leaving aLeafIsSignedTwiceAndVerified().");
}

async function theDowngradeIsRefused(t) {
  log.debug("Entering theDowngradeIsRefused().");
  t.log.info('=== 3. classical-only and wrongly-signed leaves are REFUSED ===');
  const issuer = pki.issuerFor(REALM, 'tier:issuing');
  t.check(!!(issuer && issuer.altPrivateKeyPem),
          'the Issuing CA holds an alternative private key to test with');
  const chain = pki.chainPemFor(REALM);

  const control = await leafUnder(issuer, 'issuer');
  const accepted = await pki.verifyLeaf(REALM, control, chain);
  t.check(accepted.ok, 'CONTROL: a probe leaf signed with both of the ' +
          'Issuing CA\'s keys is accepted — so the refusals below are about ' +
          'the alternative signature and nothing else', accepted.why || '');

  const classical = await leafUnder(issuer, 'none');
  const stripped = await pki.verifyLeaf(REALM, classical, chain);
  t.check(!stripped.ok, 'a leaf with ONLY the classical signature is ' +
          'refused, although that signature verifies: accepting it would ' +
          'make the post-quantum half optional (the downgrade)');
  t.equal(errorCodes.codeOf(stripped), 'STS-PKI-0202',
          'as STS-PKI-0202, the missing alternative signature');

  const forged = await leafUnder(issuer, 'stranger');
  const wrong = await pki.verifyLeaf(REALM, forged, chain);
  t.check(!wrong.ok, 'a leaf whose alternative signature was made by a ' +
          'key that is NOT the issuer\'s is refused, although its classical ' +
          'signature verifies');
  t.equal(errorCodes.codeOf(wrong), 'STS-PKI-0201',
          'as STS-PKI-0201, the wrong alternative signature');
  log.debug("Leaving theDowngradeIsRefused().");
}

async function aForeignPathRefusesOnlyAWrongSignature(t) {
  log.debug("Entering aForeignPathRefusesOnlyAWrongSignature().");
  t.log.info('=== 4. a FOREIGN path: wrong is refused, absent is not ===');
  // The same certificates, presented to the door that checks somebody
  // else's hierarchy against configured anchors. Clause 9.8 lets a hybrid
  // CA issue a classical leaf, so absence is the issuer's business there.
  const issuer = pki.issuerFor(REALM, 'tier:issuing');
  const intermediate = pki.issuerFor(REALM, 'tier:intermediate');
  const root = pki.issuerFor(REALM, 'tier:root');
  const anchors = [pki.certificateFromDer(derOf(root.certificatePem))];
  const intermediates = [derOf(issuer.certificatePem),
                         derOf(intermediate.certificatePem)];
  const classical = await leafUnder(issuer, 'none');
  const absent = await pki.verifyPathToAnchors(derOf(classical),
                                               intermediates, anchors);
  t.check(absent.ok, 'a classical leaf under a foreign hybrid CA is ' +
          'accepted', absent.reason || '');
  const forged = await leafUnder(issuer, 'stranger');
  const wrong = await pki.verifyPathToAnchors(derOf(forged), intermediates,
                                              anchors);
  t.check(!wrong.ok && /alternative/.test(wrong.reason || ''),
          'and a WRONG alternative signature is refused everywhere',
          wrong.reason || '');
  log.debug("Leaving aForeignPathRefusesOnlyAWrongSignature().");
}

async function aClassicalBranchStillVerifies(t) {
  log.debug("Entering aClassicalBranchStillVerifies().");
  t.log.info('=== 5. altKeyAlg "none": a classical branch under the ' +
             'hybrid Root ===');
  const built = await pki.buildChain(CLASSICAL, { altKeyAlg: 'none' });
  t.check(built.ok, 'a branch is built with no alternative key',
          (built.errors || []).join(' '));
  const intermediate = built.chain.tiers[1];
  const issuing = built.chain.tiers[2];
  t.check(!intermediate.altKeyAlg && !issuing.altKeyAlg,
          'neither of its tiers holds an alternative key');
  t.equal(intermediate.altSignatureAlg, 'ml-dsa-87',
          'but the Intermediate still carries the hybrid ROOT\'s alternative ' +
          'signature — the signature is the issuer\'s to make');
  t.equal(pki.describeScope(CLASSICAL).altKeyAlg, 'none',
          'and the branch reports "none", not "never chosen"');
  const issued = await pki.issueSigningKeyPair(CLASSICAL,
                                               { identifier: 'classic-app' });
  t.check(issued.ok, 'a key pair is issued from it',
          (issued.errors || []).join(' '));
  const verdict = await pki.verifyLeaf(CLASSICAL,
                                       issued.issued.certificatePem,
                                       pki.chainPemFor(CLASSICAL));
  t.check(verdict.ok, 'and its classical leaf verifies — nothing above it ' +
          'holds an alternative key that could have signed it',
          verdict.why || '');
  log.debug("Leaving aClassicalBranchStillVerifies().");
}

async function anAlgorithmThatCannotSignIsRefused(t) {
  log.debug("Entering anAlgorithmThatCannotSignIsRefused().");
  t.log.info('=== 6. an alternative key that is not a PQ signature key is ' +
             'refused ===');
  ['ml-kem-768', 'mldsa65-ecdsa-p256-sha512', 'ec-p256'].forEach(
    function (bad) {
      t.check(pki.alternativeKeyAlgs().indexOf(bad) < 0,
              '"' + bad + '" is not offered as an alternative key algorithm');
    });
  const refused = await pki.buildChain(REFUSED, { altKeyAlg: 'ml-kem-768' });
  t.check(!refused.ok, 'a build naming ML-KEM — a KEM, which cannot sign — ' +
          'is refused');
  t.equal(errorCodes.codeOf(refused), 'STS-PKI-0200', 'as STS-PKI-0200');
  t.check(!pki.hasChain(REFUSED), 'and nothing was stored');
  log.debug("Leaving anAlgorithmThatCannotSignIsRefused().");
}

async function aProcessBranchPastTheListenerLimitIsRefused(t) {
  log.debug("Entering aProcessBranchPastTheListenerLimitIsRefused().");
  t.log.info('=== 7. a process branch whose signatures exceed a stock ' +
             'TLS client\'s certificate list is refused (#1421, #1432) ===');
  // Asked without building. ML-DSA-87 is the recommended hybrid and fits.
  // SLH-DSA-256f is 49856 bytes; the leaf and the TLS Issuing CA each carry
  // one, and that list is past OpenSSL's 102400-byte default. The same
  // size as the signing key is the same two signatures (#1432).
  t.equal(pki.processListenerAltSignatureProblem('ml-dsa-87'), null,
          'ML-DSA-87 still fits the process listener');
  t.equal(pki.processListenerAltSignatureProblem('slh-dsa-shake-128f'), null,
          'SLH-DSA-SHAKE-128f still fits the process listener');
  t.equal(pki.processListenerAltSignatureProblem(null), null,
          'a classical process branch is not a size refusal');
  t.equal(pki.processListenerAltSignatureProblem(null, 'ec-p256'), null,
          'a classical signing key adds nothing to the budget');
  t.equal(pki.processListenerAltSignatureProblem(
            null, 'slh-dsa-shake-256s'), null,
          'SLH-DSA-256s as the signing key still fits');
  t.equal(pki.processListenerAltSignatureProblem(
            null, 'mldsa87-ecdsa-p521-sha512'), null,
          'a composite ML-DSA-87 signing key still fits');
  ['slh-dsa-shake-256f', 'slh-dsa-sha2-256f'].forEach(function (id) {
    const problem = pki.processListenerAltSignatureProblem(id);
    t.equal(errorCodes.codeOf(problem), 'STS-PKI-0270',
            id + ' is refused as STS-PKI-0270');
    t.check(problem && !/STS-/.test((problem.errors || []).join(' ')),
            id + ' names no error code in the sentence',
            (problem && problem.errors || []).join(' '));
    const primary = pki.processListenerAltSignatureProblem(null, id);
    t.equal(errorCodes.codeOf(primary), 'STS-PKI-0270',
            id + ' as the signing key is refused as STS-PKI-0270');
    t.check(primary && !/STS-/.test((primary.errors || []).join(' ')),
            id + ' as the signing key names no error code',
            (primary && primary.errors || []).join(' '));
    t.check(primary && /signing key/.test((primary.errors || []).join(' ')),
            id + ' as the signing key says so');
  });
  const both = pki.processListenerAltSignatureProblem(
    'slh-dsa-shake-192f', 'slh-dsa-shake-192f');
  t.equal(errorCodes.codeOf(both), 'STS-PKI-0270',
          'a 192f signing key plus the same alternative key is refused');
  const before = pki.describeScope(pki.PROCESS_SCOPE);
  const refused = await pki.buildScope(pki.PROCESS_SCOPE, {
    keyAlg: 'ec-p256', altKeyAlg: 'slh-dsa-shake-256f'
  });
  t.check(!refused.ok, 'building the process branch with SLH-DSA-256f is ' +
          'refused before any key is made',
          (refused.errors || []).join(' '));
  t.equal(errorCodes.codeOf(refused), 'STS-PKI-0270',
          'and the build carries STS-PKI-0270');
  const pure = await pki.buildScope(pki.PROCESS_SCOPE, {
    keyAlg: 'slh-dsa-shake-256f', altKeyAlg: 'none'
  });
  t.check(!pure.ok, 'a pure SLH-DSA-256f process branch is refused before ' +
          'any key is made', (pure.errors || []).join(' '));
  t.equal(errorCodes.codeOf(pure), 'STS-PKI-0270',
          'and that build carries STS-PKI-0270');
  t.check(pure && /signing key/.test((pure.errors || []).join(' ')) &&
          !/alternative/.test((pure.errors || []).join(' ')),
          'the pure-key refusal names the signing key and no alternative',
          (pure.errors || []).join(' '));
  t.check(pure && !/STS-/.test((pure.errors || []).join(' ')),
          'the pure-key refusal names no error code',
          (pure.errors || []).join(' '));
  const after = pki.describeScope(pki.PROCESS_SCOPE);
  t.equal(after.built, before.built,
          'the refused build stored nothing');
  t.equal(after.altKeyAlg, before.altKeyAlg,
          'the process branch\'s alternative key is unchanged');
  t.equal(after.keyAlg, before.keyAlg,
          'the process branch\'s signing key is unchanged');
  log.debug("Leaving aProcessBranchPastTheListenerLimitIsRefused().");
}

// The PEM bundle a listener would present for a leaf from `useCaseId`'s
// Issuing CA in `scopeId` — the process branch's `tls`, or a realm's
// `spiffe`, `pep-tls` or `realm-tls` — with the Root after it (#1064),
// loaded the way `setSecureContext()` loads it. Answers the error's message,
// or '' when OpenSSL took it. `grpc` also binds a grpc-js server with it,
// the way `spiffe/spiffe_grpc.ts` binds the SPIRE Server API and the Broker
// API.
async function listenerContextProblem(scopeId, useCaseId, grpc) {
  log.debug("Entering listenerContextProblem(). " + scopeId + "/" +
            useCaseId);
  const pair = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const issued = await pki.issueUnder(scopeId || pki.PROCESS_SCOPE,
                                      useCaseId || 'tls', {
    publicKeyPem: pair.publicKey.export({ type: 'spki', format: 'pem' }),
    subject: 'CN=pki-hybrid listener',
    profile: useCaseId === 'spiffe' ? undefined : 'tls-server' });
  if (!issued.ok) {
    log.debug("Leaving listenerContextProblem(). No leaf.");
    return 'no leaf: ' + (issued.errors || []).join(' ');
  }
  const bundle = [issued.certificatePem].concat(issued.issuerChainPem)
    .concat([pki.serviceRoot().certificatePem])
    .map(function (pem) {
      return /\n$/.test(pem) ? pem : pem + '\n';
    }).join('');
  const key = pair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  try {
    tls.createSecureContext({ key: key, cert: bundle });
  } catch (e) {
    log.debug("Caught in listenerContextProblem(): " +
              ((e && e.message) || e));
    log.debug("Leaving listenerContextProblem(). Refused.");
    return String((e && e.message) || e);
  }
  if (grpc) {
    const bound = await grpcBindProblem(key, bundle);
    log.debug("Leaving listenerContextProblem(). grpc-js: " + bound);
    return bound;
  }
  log.debug("Leaving listenerContextProblem(). Loaded.");
  return '';
}

// A grpc-js server bound on a loopback port with `createSsl()` over that
// key and bundle, request-but-not-require as the SPIFFE listeners are, and
// shut at once. Answers the bind's error, or '' when it listened.
function grpcBindProblem(key, bundle) {
  log.debug("Entering grpcBindProblem().");
  const grpcJs = require('@grpc/grpc-js');
  const server = new grpcJs.Server();
  const credentials = grpcJs.ServerCredentials.createSsl(
    Buffer.from(pki.serviceRoot().certificatePem, 'utf8'),
    [{ private_key: Buffer.from(key, 'utf8'),
       cert_chain: Buffer.from(bundle, 'utf8') }], true);
  log.debug("Leaving grpcBindProblem().");
  return new Promise(function (resolve) {
    server.bindAsync('127.0.0.1:0', credentials, function (err) {
      server.forceShutdown();
      resolve(err ? String(err.message || err) : '');
    });
  });
}

async function aListenerChainKeyOpenSslCannotReadIsRefused(t) {
  log.debug("Entering aListenerChainKeyOpenSslCannotReadIsRefused().");
  t.log.info('=== 8. a composite ML-DSA key is refused for the Root, ' +
             'the process branch and a realm branch, which the listeners ' +
             'load (fuzz, 2026-11-12) ===');
  const composite = 'mldsa65-ecdsa-p256-sha512';
  t.check(pki.listenerUnreadableKeyAlg(composite) &&
          pki.listenerUnreadableKeyAlg('mldsa87-rsa4096-pss-sha512') &&
          !pki.listenerUnreadableKeyAlg('ml-dsa-65') &&
          !pki.listenerUnreadableKeyAlg('slh-dsa-shake-128f') &&
          !pki.listenerUnreadableKeyAlg('ec-p256'),
          'composites are the keys OpenSSL cannot read; ML-DSA, SLH-DSA ' +
          'and EC are not');
  const before = pki.describeScope(pki.PROCESS_SCOPE);
  const branch = await pki.buildScope(pki.PROCESS_SCOPE, {
    keyAlg: composite, altKeyAlg: 'none' });
  t.equal(errorCodes.codeOf(branch), 'STS-PKI-0272',
          'a composite process branch is refused as STS-PKI-0272');
  t.check(branch && !/STS-/.test((branch.errors || []).join(' ')),
          'and the sentence names no error code',
          (branch && branch.errors || []).join(' '));
  const after = pki.describeScope(pki.PROCESS_SCOPE);
  t.equal(after.built, before.built, 'and nothing was stored');
  const rootBefore = pki.serviceRoot();
  const root = await pki.buildRoot({ keyAlg: composite, altKeyAlg: 'none' });
  t.equal(errorCodes.codeOf(root), 'STS-PKI-0272',
          'a composite Root is refused as STS-PKI-0272');
  t.check(pki.serviceRoot() === rootBefore, 'and the Root is unchanged');
  // A REALM'S BRANCH IS ON LISTENER CHAINS TOO (after #1684): its
  // Intermediate is presented by the realm's SPIFFE gRPC listeners, its
  // Remote PEP listeners and its custom listeners, and OpenSSL cannot read a
  // composite Intermediate any more than a composite Root.
  const realmBefore = pki.describeScope(REFUSED);
  const realm = await pki.buildChain(REFUSED, { keyAlg: composite,
                                                altKeyAlg: 'none' });
  t.equal(errorCodes.codeOf(realm), 'STS-PKI-0274',
          'a composite realm branch is refused as STS-PKI-0274');
  t.check(realm && !/STS-/.test((realm.errors || []).join(' ')),
          'and the sentence names no error code',
          (realm && realm.errors || []).join(' '));
  t.equal(pki.describeScope(REFUSED).built, realmBefore.built,
          'and nothing was stored for the realm');
  t.check(!pki.describeIssuer(REFUSED, 'spiffe'),
          'and the realm has no SPIFFE authority to mint from');
  // THE SETTING NAMING ONE: the build is not refused (the startup build reads
  // it), it is made classical, and OpenSSL loads what it made.
  const pure = await pki.buildScope(pki.PROCESS_SCOPE, {
    keyAlg: 'ml-dsa-65', altKeyAlg: 'none' });
  t.check(pure && pure.ok, 'an ML-DSA-65 process branch is built',
          JSON.stringify(pure && pure.errors));
  t.equal(await listenerContextProblem(), '',
          'and OpenSSL loads the listener chain it makes');
  // An ML-DSA realm branch is the post-quantum one a realm may have, and
  // every listener chain under it loads.
  const realmPure = await pki.buildChain(REFUSED, { keyAlg: 'ml-dsa-65',
                                                    altKeyAlg: 'none' });
  t.check(realmPure && realmPure.ok, 'an ML-DSA-65 realm branch is built',
          JSON.stringify(realmPure && realmPure.errors));
  await realmListenerChainsLoad(t, 'ML-DSA-65');
  pki.clearChain(REFUSED);
  const set = config.setOverride('pki.keyAlgorithm', composite);
  try {
    t.check(set && set.ok !== false, 'pki.keyAlgorithm is set to a ' +
            'composite for this section', JSON.stringify(set));
    const fallback = await pki.buildScope(pki.PROCESS_SCOPE, {
      altKeyAlg: 'none' });
    t.check(fallback && fallback.ok, 'a process build naming no key with ' +
            'the setting composite is not refused',
            JSON.stringify(fallback && fallback.errors));
    t.check(!pki.listenerUnreadableKeyAlg(
              pki.describeScope(pki.PROCESS_SCOPE).keyAlg),
            'it was built with a key OpenSSL reads',
            pki.describeScope(pki.PROCESS_SCOPE).keyAlg);
    t.equal(await listenerContextProblem(), '',
            'and OpenSSL loads the listener chain it makes');
    // A realm branch built with no named key — what a new realm, a repair
    // and the startup build do — is not refused either: a deployment that
    // stored the setting still starts, with a classical branch.
    const realmFallback = await pki.buildChain(REFUSED, { altKeyAlg: 'none' });
    t.check(realmFallback && realmFallback.ok, 'a realm build naming no ' +
            'key with the setting composite is not refused',
            JSON.stringify(realmFallback && realmFallback.errors));
    t.check(!pki.listenerUnreadableKeyAlg(
              pki.describeScope(REFUSED).keyAlg) &&
            !pki.listenerUnreadableKeyAlg(
              (pki.describeIssuer(REFUSED, 'spiffe') || {}).keyAlg),
            'it was built with a key OpenSSL reads, its SPIFFE authority ' +
            'too', pki.describeScope(REFUSED).keyAlg);
    await realmListenerChainsLoad(t, 'the fallback');
  } finally {
    config.clearOverride('pki.keyAlgorithm');
    pki.clearChain(REFUSED);
  }
  log.debug("Leaving aListenerChainKeyOpenSslCannotReadIsRefused().");
}

// Every chain a realm branch puts on one of this service's listeners loads:
// the SPIFFE authority's (through grpc-js as well, which is how the SPIRE
// Server API and the Broker API bind it), the Remote PEP listeners' and the
// custom listeners'.
async function realmListenerChainsLoad(t, what) {
  log.debug("Entering realmListenerChainsLoad(). " + what);
  t.equal(await listenerContextProblem(REFUSED, 'spiffe', true), '',
          what + ': the SPIFFE listener chain loads, through grpc-js too');
  t.equal(await listenerContextProblem(REFUSED, 'pep-tls'), '',
          what + ': the Remote PEP listener chain loads');
  t.equal(await listenerContextProblem(REFUSED, 'realm-tls'), '',
          what + ': the custom listener chain loads');
  log.debug("Leaving realmListenerChainsLoad().");
}

module.exports = {
  name: 'pki_hybrid',
  describe: 'The hybrid certificate authority (#68): every tier holds an ' +
            'ML-DSA-87 alternative key (ITU-T X.509 clause 9.8) and signs ' +
            'what it issues twice; OpenSSL still verifies the classical ' +
            'chain; a leaf in this service\'s own hierarchy with a missing ' +
            'or wrong alternative signature is refused, a foreign one only ' +
            'when wrong; "none" builds a classical branch; a KEM is refused',
  run: run
};
