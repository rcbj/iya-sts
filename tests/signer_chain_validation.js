'use strict';

// ===========================================================================
// tests/signer_chain_validation.js — THE SIGNER CERTIFICATE'S WHOLE CHAIN,
// VALIDATED WHEREVER AN RFC 7523 OR RFC 7522 SIGNATURE IS (2026-09-13).
//
// Until that date two things were true and neither was visible at an endpoint:
//
//   1. `pki.verifyLeaf()` — the path check an assertion's `x5c` header is
//      believed on — walked signatures, issuer names and validity windows and
//      NOTHING ELSE. Every key pair this service issues is handed over with its
//      private half, so its holder could sign a certificate of their own and
//      present it under their own leaf: every link verified, the path anchored
//      in this realm, and a forged leaf naming no person may assert about
//      anybody. Section 1 builds exactly that from a PERSON's key pair.
//   2. A REGISTERED certificate — an `x5c` on a JWK in `oauthJwks`,
//      `oauthAssertionJwks` or `stsAssertionJwks`, and an RFC 7522
//      certificate — had its chain checked when it was registered and never
//      again. An expired certificate, an expired intermediate, a replaced
//      branch or a JWKS pasted by hand went on verifying assertions; the only
//      use-time check was revocation.
//
// `pki.verifySignerChain()` is the fix and this file is its guard. It is in
// process for the reason `tests/application_credentials.js` gives: every
// interesting input is a certificate hierarchy nobody would deploy — an
// end-entity certificate used as an issuer, a CA used as a signer, a chain with
// no root, a certificate that does not hold the key beside it — and over HTTP
// each one would be the test building a CA in a JSON body. The three verifiers
// are driven directly in section 4, with the SAME fixtures, because the claim
// is that a signature which VERIFIES is still refused when its chain does not
// hold — and that a bare key, which has no chain, is still accepted.
//
// It builds hierarchies under realm ids of its own, creates two applications
// in the default realm which it deletes in a `finally`, and leaves the
// certificate authority as it found it (`application_credentials.js`'s
// `restoreAuthority()` reason: `run.js` runs every file in one process).
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const pki = require('../common/pki');
const keystore = require('../common/keystore');
const applications = require('../common/applications');
// What fills the registry's directory slot; without it every application below
// is "not storable" and the grant section passes for the wrong reason.
require('../ldap/ldap_server');
const errorCodes = require('../common/error_codes');
const x509 = require('../common/vendored/x509');
const keyMaterial = require('../common/vendored/key_material');
const assertionGrant = require('../oauth-oidc/assertion_grant');
const clientAuth = require('../oauth-oidc/client_auth');
const samlGrant = require('../oauth-oidc/saml_assertion_grant');
// This suite's own XML Signature, for `tests/saml_assertion_grant.js`'s reason:
// a document built by the module that verifies it proves nothing.
const signer = require('./vendored/saml_xmldsig.js');

// This file's own logger, for the Entering/Leaving lines the code style asks
// for.
const log = require('bunyan').createLogger({ name: 'signer_chain_validation',
  level: process.env.LOG_LEVEL || 'info' });

const RUN = nodeCrypto.randomBytes(3).toString('hex');
const REALM = 'scv-realm-' + RUN;
const OTHER = 'scv-other-' + RUN;
const AUD = 'https://localhost:8081/oauth2/token';
const GRANT_APP = 'scv-grant-' + RUN;
const BARE_APP = 'scv-bare-' + RUN;
const GRANT_ISS = 'https://issuer.example.test/scv-' + RUN;
const BARE_ISS = 'https://issuer.example.test/scv-bare-' + RUN;
const DAY = 86400000;

function codeOf(result) {
  log.debug("Entering codeOf().");
  log.debug("Leaving codeOf().");
  return errorCodes.codeOf(result) || (result && result.errorCode) || '';
}

function sentence(result) {
  log.debug("Entering sentence().");
  log.debug("Leaving sentence().");
  return ((result && result.errors) || []).join(' ') ||
         String((result && (result.why || result.description)) || '');
}

async function pairOf(alg) {
  log.debug("Entering pairOf().");
  const pair = await keyMaterial.generateKeyPair(alg || 'rsa-2048');
  log.debug("Leaving pairOf().");
  return pair;
}

// A certificate. `issuer` omitted means SELF-SIGNED with `self`.
async function issue(spec) {
  log.debug("Entering issue(). cn=" + spec.cn);
  const extensions = {
    basicConstraints: { present: true, critical: true, ca: !!spec.ca,
                        pathLen: spec.ca
                          ? (spec.pathLen === undefined ? null : spec.pathLen)
                          : undefined },
    keyUsage: { present: true, critical: true,
                usages: spec.usages ||
                        (spec.ca ? ['keyCertSign', 'cRLSign']
                                 : ['digitalSignature']) }
  };
  if (!spec.ca) {
    delete extensions.basicConstraints.pathLen;
  }
  const issued = await x509.issueCertificate({
    subject: [{ name: 'CN', value: spec.cn }],
    subjectPublicKey: spec.subject.publicPem,
    signatureAlg: spec.signatureAlg || 'sha256-rsa',
    profile: spec.profile || (spec.ca ? 'intermediate-ca'
                                      : 'digital-signature'),
    notBefore: spec.notBefore,
    notAfter: spec.notAfter,
    issuer: spec.issuer
      ? { certificatePem: spec.issuer.pem,
          privateKeyPem: spec.issuer.pair.privatePem,
          keyAlg: spec.issuer.keyAlg || 'rsa-2048' }
      : { privateKeyPem: spec.subject.privatePem,
          keyAlg: spec.keyAlg || 'rsa-2048' },
    extensions: extensions
  });
  log.debug("Leaving issue().");
  return issued.pem;
}

function b64Of(pem) {
  log.debug("Entering b64Of().");
  log.debug("Leaving b64Of().");
  return String(pem).replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
}

// A JWK for `publicPem`, carrying `x5cPems` as its x5c.
function jwkFor(publicPem, x5cPems, kid) {
  log.debug("Entering jwkFor().");
  const jwk = nodeCrypto.createPublicKey(publicPem).export({ format: 'jwk' });
  jwk.kid = kid;
  jwk.use = 'sig';
  if (jwk.kty === 'EC') {
    jwk.alg = 'ES256';
  }
  if (x5cPems && x5cPems.length) {
    jwk.x5c = x5cPems.map(b64Of);
  }
  log.debug("Leaving jwkFor().");
  return jwk;
}

let jti = 0;
function jws(header, payload, privateKeyPem) {
  log.debug("Entering jws().");
  const b64u = function (value) {
    log.debug("Entering b64u().");
    log.debug("Leaving b64u().");
    return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
  };
  const signing = b64u(header) + '.' + b64u(payload);
  const es = /^ES/.test(header.alg);
  const sig = nodeCrypto.sign('sha256', Buffer.from(signing, 'ascii'),
    es ? { key: privateKeyPem, dsaEncoding: 'ieee-p1363' } : privateKeyPem);
  log.debug("Leaving jws().");
  return signing + '.' + sig.toString('base64url');
}

function claims(iss, sub) {
  log.debug("Entering claims().");
  jti += 1;
  const now = Math.floor(Date.now() / 1000);
  log.debug("Leaving claims().");
  return { iss: iss, sub: sub, aud: AUD, iat: now, exp: now + 120,
           jti: 'scv-' + RUN + '-' + jti };
}

function samlAssertion(iss, keyPem, certPem) {
  log.debug("Entering samlAssertion().");
  const built = signer.buildAssertion({ issuer: iss, subject: iss,
                                        audience: AUD, recipient: AUD });
  log.debug("Leaving samlAssertion().");
  return signer.b64u(signer.sign(built, keyPem, certPem || '', {}));
}

async function runBody(t) {
  log.debug("Entering runBody().");
  const built = await pki.buildChain(REALM, {});
  t.check(built.ok, 'a hierarchy is built for this file\'s realm',
          (built.errors || []).join(' '));

  // -------------------------------------------------------------------------
  t.log.info('=== 1. verifyLeaf(): who was ENTITLED to sign each link ===');
  const person = (await pki.issueSigningKeyPair(REALM, {
    identifier: 'scv-bob', subjectKind: 'person' })).issued;
  const good = await pki.verifyLeaf(REALM, person.certificatePem,
                                    person.chainPem);
  t.check(good.ok, 'the control: a person\'s own issued leaf builds a path',
          good.why);
  const forgedPair = await pairOf('rsa-2048');
  const forged = await issue({
    cn: 'scv-forged', subject: forgedPair,
    issuer: { pem: person.certificatePem,
              pair: { privatePem: person.privateKeyPem } }
  });
  const forgedVerdict = await pki.verifyLeaf(REALM, forged,
    [person.certificatePem].concat(person.chainPem));
  t.check(!forgedVerdict.ok && codeOf(forgedVerdict) === 'STS-PKI-0158' &&
          /scv-bob/.test(forgedVerdict.why),
          'A CERTIFICATE SIGNED BY A PERSON\'S OWN LEAF IS REFUSED — every ' +
          'link of that path verifies and it passes through this realm\'s ' +
          'Intermediate, and until this change it was accepted; the forged ' +
          'leaf names no person, so it could have asserted about anybody',
          sentence(forgedVerdict));
  const issuingPem = person.chainPem[0];
  const caAsSigner = await pki.verifyLeaf(REALM, issuingPem,
                                          person.chainPem.slice(1));
  t.check(!caAsSigner.ok && codeOf(caAsSigner) === 'STS-PKI-0159',
          'an ISSUING CA presented as the signer is refused — a CA\'s key ' +
          'signs certificates, not assertions', sentence(caAsSigner));

  // -------------------------------------------------------------------------
  t.log.info('=== 2. the three anchors ===');
  const realmLeaf = await pki.verifySignerChain(REALM, {
    certificate: person.certificatePem, source: 'the fixture' });
  t.check(realmLeaf.ok && realmLeaf.anchor === 'realm',
          'a leaf this realm issued, registered ALONE, is anchored in the ' +
          'realm — its tiers are filled in', sentence(realmLeaf));
  const realmB64 = await pki.verifySignerChain(REALM, {
    certificate: b64Of(person.certificatePem),
    chain: person.chainPem.map(b64Of) });
  t.check(realmB64.ok && realmB64.anchor === 'realm',
          'and the same leaf in x5c spelling (base64 DER) with its chain',
          sentence(realmB64));
  await pki.buildChain(OTHER, {});
  const elsewhere = await pki.verifySignerChain(OTHER, {
    certificate: person.certificatePem, chain: person.chainPem });
  t.check(!elsewhere.ok && codeOf(elsewhere) === 'STS-PKI-0021',
          'the same leaf WITH its branch is refused in another realm — the ' +
          'realm boundary is the Intermediate, and a registration cannot ' +
          'walk round it', sentence(elsewhere));

  const rootPair = await pairOf();
  const rootPem = await issue({ cn: 'SCV Foreign Root', subject: rootPair,
                                ca: true, profile: 'root-ca' });
  const root = { pem: rootPem, pair: rootPair };
  const interPair = await pairOf();
  const interPem = await issue({ cn: 'SCV Foreign Intermediate',
                                 subject: interPair, ca: true, pathLen: 0,
                                 issuer: root });
  const inter = { pem: interPem, pair: interPair };
  const leafPair = await pairOf('ec-p256');
  const leafPem = await issue({ cn: 'scv-external-leaf', subject: leafPair,
                                issuer: inter });
  const external = await pki.verifySignerChain(REALM, {
    certificate: leafPem, chain: [rootPem, interPem] });
  t.check(external.ok && external.anchor === 'registered-root' &&
          external.path.length === 3,
          'an external leaf with its WHOLE chain, root first, is anchored at ' +
          'the registered self-signed root — built by issuer, not by order',
          sentence(external));
  const noRoot = await pki.verifySignerChain(REALM, {
    certificate: leafPem, chain: [interPem] });
  t.check(!noRoot.ok && codeOf(noRoot) === 'STS-PKI-0156' &&
          /SCV Foreign Root/.test(noRoot.why),
          'WITHOUT ITS ROOT the chain is incomplete, naming the missing ' +
          'issuer — nothing is fetched to finish it', sentence(noRoot));
  const alone = await pki.verifySignerChain(REALM, { certificate: leafPem });
  t.equal(codeOf(alone), 'STS-PKI-0156',
          'and an external leaf alone is incomplete too');

  const selfPair = await pairOf('ec-p256');
  const selfPem = await issue({ cn: 'scv-pinned', subject: selfPair,
                                signatureAlg: 'sha256-ecdsa',
                                keyAlg: 'ec-p256' });
  const pinned = await pki.verifySignerChain(REALM, { certificate: selfPem });
  t.check(pinned.ok && pinned.anchor === 'pinned',
          'a SELF-SIGNED certificate registered by value is its own whole ' +
          'chain', sentence(pinned));
  const caSelfPair = await pairOf();
  const caSelf = await issue({ cn: 'scv-openssl-style', subject: caSelfPair,
                               ca: true, profile: 'root-ca',
                               usages: ['digitalSignature', 'keyCertSign'] });
  const pinnedCa = await pki.verifySignerChain(REALM, { certificate: caSelf });
  t.check(pinnedCa.ok && pinnedCa.anchor === 'pinned',
          'and one carrying cA=TRUE is still accepted when PINNED — every ' +
          '`openssl req -x509` certificate carries it, and a pinned key is ' +
          'not being asked to issue', sentence(pinnedCa));

  // -------------------------------------------------------------------------
  t.log.info('=== 3. what the chain must hold, every time it is used ===');
  const expiredLeaf = await issue({
    cn: 'scv-expired', subject: leafPair, issuer: inter,
    notBefore: new Date(Date.now() - 3 * DAY).toISOString(),
    notAfter: new Date(Date.now() - DAY).toISOString() });
  const expired = await pki.verifySignerChain(REALM, {
    certificate: expiredLeaf, chain: [interPem, rootPem] });
  t.check(!expired.ok && codeOf(expired) === 'STS-PKI-0157' &&
          /expired/.test(expired.why),
          'AN EXPIRED CERTIFICATE IS REFUSED AT USE — it was accepted when ' +
          'registered and nothing looked again', sentence(expired));
  const expiredSelf = await issue({
    cn: 'scv-pinned-expired', subject: selfPair, signatureAlg: 'sha256-ecdsa',
    keyAlg: 'ec-p256',
    notBefore: new Date(Date.now() - 3 * DAY).toISOString(),
    notAfter: new Date(Date.now() - DAY).toISOString() });
  t.equal(codeOf(await pki.verifySignerChain(REALM,
                                             { certificate: expiredSelf })),
          'STS-PKI-0157', 'and so is an expired PINNED certificate');

  const eePair = await pairOf();
  const endEntity = await issue({
    cn: 'SCV End Entity As Issuer', subject: eePair, issuer: root,
    usages: ['digitalSignature', 'keyCertSign'] });
  const underEe = await issue({ cn: 'scv-under-ee', subject: leafPair,
                                issuer: { pem: endEntity, pair: eePair } });
  const throughEe = await pki.verifySignerChain(REALM, {
    certificate: underEe, chain: [endEntity, rootPem] });
  t.check(!throughEe.ok && codeOf(throughEe) === 'STS-PKI-0158' &&
          /End Entity As Issuer/.test(throughEe.why),
          'A REGISTERED CHAIN THROUGH AN END-ENTITY CERTIFICATE IS REFUSED ' +
          'AT USE', sentence(throughEe));
  // A CA that may not sign certificates. cA=TRUE alone is not the entitlement:
  // the end-entity case above is refused on basicConstraints before KeyUsage is
  // read, so without this one a verifier that never looked at keyCertSign
  // passed every assertion in the file (the mutation round found it).
  const noCertSignPair = await pairOf();
  const noCertSign = await issue({ cn: 'SCV CA Without keyCertSign',
                                   subject: noCertSignPair, ca: true,
                                   issuer: root,
                                   usages: ['digitalSignature', 'cRLSign'] });
  const underNoCertSign = await issue({ cn: 'scv-under-no-cert-sign',
    subject: leafPair, issuer: { pem: noCertSign, pair: noCertSignPair } });
  const throughNoCertSign = await pki.verifySignerChain(REALM, {
    certificate: underNoCertSign, chain: [noCertSign, rootPem] });
  t.check(!throughNoCertSign.ok &&
          codeOf(throughNoCertSign) === 'STS-PKI-0158' &&
          /keyCertSign/.test(throughNoCertSign.why),
          'a CA whose KeyUsage does not permit keyCertSign may not sign the ' +
          'certificate below it', sentence(throughNoCertSign));
  const deepPair = await pairOf();
  const deepInter = await issue({ cn: 'SCV Too Deep', subject: deepPair,
                                  ca: true, pathLen: 0, issuer: inter });
  const deepLeaf = await issue({ cn: 'scv-too-deep', subject: leafPair,
                                 issuer: { pem: deepInter, pair: deepPair } });
  const tooDeep = await pki.verifySignerChain(REALM, {
    certificate: deepLeaf, chain: [deepInter, interPem, rootPem] });
  t.check(!tooDeep.ok && codeOf(tooDeep) === 'STS-PKI-0158' &&
          /SCV Foreign Intermediate/.test(tooDeep.why),
          'an intermediate below one whose pathLen is 0 is refused',
          sentence(tooDeep));
  const caAsLeaf = await pki.verifySignerChain(REALM, {
    certificate: interPem, chain: [rootPem] });
  t.check(!caAsLeaf.ok && codeOf(caAsLeaf) === 'STS-PKI-0159',
          'a CA registered as the signer is refused', sentence(caAsLeaf));
  const noSign = await issue({ cn: 'scv-no-signature', subject: leafPair,
                               issuer: inter, usages: ['keyAgreement'] });
  t.equal(codeOf(await pki.verifySignerChain(REALM, {
            certificate: noSign, chain: [interPem, rootPem] })),
          'STS-PKI-0159',
          'a leaf whose KeyUsage does not permit digitalSignature is refused');

  const otherPair = await pairOf('ec-p256');
  const mismatch = await pki.verifySignerChain(REALM, {
    certificate: leafPem, chain: [interPem, rootPem],
    key: jwkFor(otherPair.publicPem, [], 'other') });
  t.check(!mismatch.ok && codeOf(mismatch) === 'STS-PKI-0160',
          'A CERTIFICATE THAT DOES NOT HOLD THE KEY BESIDE IT IS REFUSED — ' +
          'RFC 7517 section 4.7; a valid chain about another key says ' +
          'nothing about this one', sentence(mismatch));
  const match = await pki.verifySignerChain(REALM, {
    certificate: leafPem, chain: [interPem, rootPem],
    key: jwkFor(leafPair.publicPem, [leafPem], 'leaf') });
  t.check(match.ok, 'and the same chain beside ITS key is accepted',
          sentence(match));
  t.equal(codeOf(await pki.verifySignerChain(REALM, {
            certificate: 'bm90IGEgY2VydGlmaWNhdGU=' })),
          'STS-PKI-0161', 'an unreadable certificate is refused as such');

  // A BRANCH REPLACED UNDER A REGISTERED LEAF. The leaf's stored chain still
  // names the old Issuing CA and Intermediate, whose issuer is the same Root —
  // so the path is internally consistent and ends at this service's Root,
  // which is exactly what makes the Intermediate boundary the check that fires.
  const rotated = (await pki.issueSigningKeyPair(OTHER, {
    identifier: 'scv-rotated' })).issued;
  t.check((await pki.verifySignerChain(OTHER, {
            certificate: rotated.certificatePem,
            chain: rotated.chainPem })).ok,
          'the control: a freshly issued leaf in that realm verifies');
  await pki.buildScope(OTHER, {});
  const afterRebuild = await pki.verifySignerChain(OTHER, {
    certificate: rotated.certificatePem, chain: rotated.chainPem });
  t.check(!afterRebuild.ok,
          'AND ONCE ITS REALM\'S BRANCH IS REBUILT, THE SAME REGISTERED LEAF ' +
          'NO LONGER VALIDATES — it did, at every use, until this change',
          sentence(afterRebuild));

  // -------------------------------------------------------------------------
  t.log.info('=== 4. the three verifiers ===');
  try {
    // --- RFC 7523 section 2.1 -----------------------------------------------
    applications.createApplication({ identifier: GRANT_APP,
                                     protocols: ['oauth2'] });
    applications.updateApplication(GRANT_APP,
      { attribute: 'oauthAssertionIssuer', mode: 'add', value: GRANT_ISS });
    const setJwks = function (app, keys) {
      log.debug("Entering setJwks().");
      applications.updateApplication(app, { attribute: 'oauthJwks',
        mode: 'set', value: JSON.stringify({ keys: keys }) });
      log.debug("Leaving setJwks().");
    };
    const grant = function (kid, iss) {
      log.debug("Entering grant().");
      log.debug("Leaving grant().");
      return assertionGrant.verify({
        assertion: jws({ alg: 'ES256', typ: 'JWT', kid: kid },
                       claims(iss || GRANT_ISS, 'alice'), leafPair.privatePem),
        audiences: [AUD] });
    };
    setJwks(GRANT_APP, [jwkFor(leafPair.publicPem,
                               [leafPem, interPem, rootPem], 'full')]);
    const grantOk = await grant('full');
    t.check(grantOk.ok && grantOk.keyChain &&
            grantOk.keyChain.anchor === 'registered-root',
            'RFC 7523 GRANT: a registered key whose x5c chain holds ' +
            'verifies, and the verdict says what it was anchored to',
            JSON.stringify(grantOk.keyChain) + ' ' + sentence(grantOk));
    setJwks(GRANT_APP, [jwkFor(leafPair.publicPem, [leafPem, interPem],
                               'noroot')]);
    const grantNoRoot = await grant('noroot');
    t.check(!grantNoRoot.ok && grantNoRoot.error === 'invalid_grant' &&
            grantNoRoot.errorCode === 'STS-PKI-0156',
            'the SAME signature, verified by the same key, is refused ' +
            'invalid_grant once the key\'s x5c lacks its root',
            sentence(grantNoRoot));
    setJwks(GRANT_APP, [jwkFor(leafPair.publicPem,
                               [expiredLeaf, interPem, rootPem], 'expired')]);
    t.equal((await grant('expired')).errorCode, 'STS-PKI-0157',
            'and refused when the certificate in its x5c has expired');
    const mismatched = jwkFor(leafPair.publicPem, [], 'mismatched');
    mismatched.x5c = [selfPem].map(b64Of);
    setJwks(GRANT_APP, [mismatched]);
    t.equal((await grant('mismatched')).errorCode, 'STS-PKI-0160',
            'and refused when the x5c certificate holds a different key');

    applications.createApplication({ identifier: BARE_APP,
                                     protocols: ['oauth2'] });
    applications.updateApplication(BARE_APP,
      { attribute: 'oauthAssertionIssuer', mode: 'add', value: BARE_ISS });
    setJwks(BARE_APP, [jwkFor(leafPair.publicPem, [], 'bare')]);
    const bare = await grant('bare', BARE_ISS);
    t.check(bare.ok && bare.keyChain === null,
            'A BARE REGISTERED KEY IS STILL ACCEPTED — it has no certificate ' +
            'and so no chain, which RFC 7523 permits', sentence(bare));

    // The x5c HEADER, carrying a certificate forged under a person's leaf. In
    // the DEFAULT realm, because the grant answers in the ambient one.
    await pki.buildChain(undefined, {});
    const ownPerson = (await pki.issueSigningKeyPair(undefined, {
      identifier: 'scv-carol', subjectKind: 'person' })).issued;
    const ownForged = await issue({
      cn: 'scv-forged-default', subject: forgedPair,
      issuer: { pem: ownPerson.certificatePem,
                pair: { privatePem: ownPerson.privateKeyPem } } });
    const forgedHeader = await assertionGrant.verify({
      assertion: jws({ alg: 'RS256', typ: 'JWT',
                       x5c: [ownForged, ownPerson.certificatePem]
                         .concat(ownPerson.chainPem).map(b64Of) },
                     claims('https://issuer.example.test/nobody-' + RUN,
                            'alice'),
                     forgedPair.privatePem),
      audiences: [AUD] });
    t.check(!forgedHeader.ok && forgedHeader.errorCode === 'STS-PKI-0158',
            'AND THE x5c HEADER PATH REFUSES THE FORGED CERTIFICATE AT THE ' +
            'GRANT — before this change that assertion was issued a token ' +
            'for "alice"', sentence(forgedHeader));

    // --- RFC 7523 section 2.2 -----------------------------------------------
    const clientAssertion = function (kid) {
      log.debug("Entering clientAssertion().");
      log.debug("Leaving clientAssertion().");
      return jws({ alg: 'ES256', typ: 'JWT', kid: kid },
                 claims('scv-client', 'scv-client'), leafPair.privatePem);
    };
    const authOk = await clientAuth.verify({ method: 'private_key_jwt',
      assertionType: clientAuth.ASSERTION_TYPE,
      assertion: clientAssertion('full'), clientId: 'scv-client',
      jwks: JSON.stringify({ keys: [jwkFor(leafPair.publicPem,
                                           [leafPem, interPem, rootPem],
                                           'full')] }),
      audiences: [AUD] });
    t.check(authOk.ok, 'RFC 7523 CLIENT AUTHENTICATION with a key whose ' +
            'chain holds succeeds', sentence(authOk));
    const authThroughEe = await clientAuth.verify({ method: 'private_key_jwt',
      assertionType: clientAuth.ASSERTION_TYPE,
      assertion: clientAssertion('ee'), clientId: 'scv-client',
      jwks: JSON.stringify({ keys: [jwkFor(leafPair.publicPem,
                                           [underEe, endEntity, rootPem],
                                           'ee')] }),
      audiences: [AUD] });
    t.check(!authThroughEe.ok && authThroughEe.errorCode === 'STS-PKI-0158',
            'and is refused when the registered chain runs through an ' +
            'end-entity certificate', sentence(authThroughEe));

    // --- RFC 7522 -----------------------------------------------------------
    const samlLeafPair = await pairOf('rsa-2048');
    const samlLeaf = await issue({ cn: 'scv-saml-leaf', subject: samlLeafPair,
                                   issuer: inter });
    const saml = function (registered, issued, issuedChain) {
      log.debug("Entering saml().");
      log.debug("Leaving saml().");
      return samlGrant.verify({
        assertion: samlAssertion('scv-saml', samlLeafPair.privatePem,
                                 samlLeaf),
        clientId: 'scv-saml', registeredCertificate: registered || '',
        issuedCertificate: issued || '',
        issuedCertificateChain: issuedChain || '', audiences: [AUD] });
    };
    const samlByValueAlone = await saml(samlLeaf);
    t.check(!samlByValueAlone.ok &&
            samlByValueAlone.errorCode === 'STS-PKI-0156',
            'RFC 7522: a CA-issued certificate registered BY VALUE with no ' +
            'chain beside it is refused although the signature verified',
            sentence(samlByValueAlone));
    const samlByValue = await saml(samlLeaf + interPem + rootPem);
    t.check(samlByValue.ok && samlByValue.certificateChain &&
            samlByValue.certificateChain.anchor === 'registered-root',
            'and accepted with its chain registered BESIDE it in the same ' +
            'value — the other blocks are candidate issuers',
            sentence(samlByValue));
    const samlIssued = await saml('', samlLeaf, [interPem, rootPem]);
    t.check(samlIssued.ok, 'and a managed (uploaded) certificate with its ' +
            'stored chain is accepted', sentence(samlIssued));
    const samlDeep = await samlGrant.verify({
      assertion: samlAssertion('scv-saml', samlLeafPair.privatePem, ''),
      clientId: 'scv-saml',
      issuedCertificate: await issue({ cn: 'scv-saml-deep',
                                       subject: samlLeafPair,
                                       issuer: { pem: deepInter,
                                                 pair: deepPair } }),
      issuedCertificateChain: [deepInter, interPem, rootPem],
      audiences: [AUD] });
    t.check(!samlDeep.ok && samlDeep.errorCode === 'STS-PKI-0158',
            'and a stored chain breaking a pathLen constraint is refused',
            sentence(samlDeep));
    const samlPinnedPair = await pairOf('rsa-2048');
    const samlPinned = await issue({ cn: 'scv-saml-pinned',
                                     subject: samlPinnedPair });
    const pinnedOk = await samlGrant.verify({
      assertion: samlAssertion('scv-saml', samlPinnedPair.privatePem,
                               samlPinned),
      clientId: 'scv-saml', registeredCertificate: samlPinned,
      audiences: [AUD] });
    t.check(pinnedOk.ok && pinnedOk.certificateChain.anchor === 'pinned',
            'and a self-signed certificate registered by value is pinned',
            sentence(pinnedOk));
  } finally {
    applications.deleteApplication(GRANT_APP);
    applications.deleteApplication(BARE_APP);
  }
  log.debug("Leaving runBody().");
}

// ---------------------------------------------------------------------------
// THE CERTIFICATE AUTHORITY THIS FILE FINDS IS THE ONE IT LEAVES, for
// `tests/application_credentials.js`'s reason: a service Root built here is
// the Root `tests/pki.js` meets next in the same process.
// ---------------------------------------------------------------------------
function heldAuthority() {
  log.debug("Entering heldAuthority().");
  log.debug("Leaving heldAuthority().");
  return { root: !!keystore.pkiFor(pki.SERVICE_SCOPE),
           chain: pki.hasChain() };
}

function restoreAuthority(before) {
  log.debug("Entering restoreAuthority().");
  pki.clearChain(REALM);
  pki.clearChain(OTHER);
  if (!before.chain && pki.hasChain()) {
    pki.clearChain(undefined);
  }
  if (!before.root && keystore.pkiFor(pki.SERVICE_SCOPE)) {
    keystore.attachPki(pki.SERVICE_SCOPE, null);
  }
  log.debug("Leaving restoreAuthority().");
}

async function run(t) {
  log.debug("Entering run().");
  const before = heldAuthority();
  try {
    await runBody(t);
  } finally {
    restoreAuthority(before);
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'signer_chain_validation',
  describe: 'The signer certificate\'s whole chain validated wherever an RFC ' +
            '7523 or RFC 7522 signature is: who may issue on a path, the ' +
            'three anchors, what must hold at every use, and the three ' +
            'verifiers refusing a signature that verified.',
  run: run
};
