// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';

// ===========================================================================
// tests/person_credentials.js — A PERSON'S RFC 7523 AND RFC 7522 KEY PAIRS,
// ISSUED OR REPLACED BY AN UPLOADED CERTIFICATE (2026-09-13).
//
// `tests/application_credentials.js` holds the chain rules an upload is judged
// by, and they are the same function for a person; what is here is what is
// DIFFERENT about a person, and most of it is a claim no request can make:
//
//   1. A PERSON MAY HOLD AN RFC 7522 KEY PAIR, ON A FOURTH ATTRIBUTE SET.
//      `stsSamlAssertion*` shares no name with `stsAssertion*`, so issuing one
//      profile writes nothing of the other, taking one off leaves the other,
//      and `issuerFor()` finds a person under one profile only while they hold
//      THAT profile's key pair — which is the crossing the sets exist to
//      prevent, asserted as a lookup rather than hoped for.
//   2. THE SAML BEARER GRANT READS IT, AND HOLDS THE PERSON TO THEMSELVES. An
//      assertion signed with the person's key about the person is accepted and
//      reported as the person's; the SAME key naming somebody else is refused
//      `STS-OAUTH-0242`; and the person's RFC 7523 key signing a SAML assertion
//      is refused, because nothing registered for RFC 7522 answers to them.
//   3. A CERTIFICATE MAY REPLACE A PERSON'S KEY PAIR — an external authority's
//      with its whole chain, or this realm's alone — and what it replaces goes
//      whole: the private key an earlier issue left is gone afterwards. The
//      replaced JWT key pair is then what the JWT grant verifies against.
//   4. A CERTIFICATE THIS REALM ISSUED TO SOMEBODY ELSE IS REFUSED FOR THIS
//      PERSON (`STS-PKI-0155`) — an application's leaf and another person's —
//      because the token endpoint reads the subjectAltName, and an entry and a
//      certificate disagreeing about whose key it is would make that reading
//      wrong in one direction or the other.
//   5. THE PAGE'S MODEL CARRIES NO PRIVATE KEY, either profile, and the two
//      codes this change retired stay registered as retired.
//
// It creates two people in the default realm and takes every key pair it put
// on them off again in a `finally`.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const pki = require('../common/pki');
const keystore = require('../common/keystore');
const personAssertions = require('../common/person_assertions');
const samlGrant = require('../oauth-oidc/saml_assertion_grant');
const assertionGrant = require('../oauth-oidc/assertion_grant');
const errorCodes = require('../common/error_codes');
const x509 = require('../common/crypto_impl/x509');
const keyMaterial = require('../common/crypto_impl/key_material');
// What fills `person_assertions.setDirectory()`. Without it every person is
// "not storable" and every assertion below passes for the wrong reason.
const ldap = require('../ldap/ldap_server');
const pkiAdmin = require('../admin-ui/pki_admin');
const adminViews = require('../admin-core/admin_views');
const admin = require('../admin-ui/admin');
// This suite's own XML Signature, for `tests/saml_assertion_grant.js`'s reason:
// a document built by the module that verifies it proves nothing.
const signer = require('./protocol/saml_xmldsig.js');

const log = require('bunyan').createLogger({ name: 'person_credentials',
  level: process.env.LOG_LEVEL || 'info' });

const RUN = nodeCrypto.randomBytes(3).toString('hex');
const ALICE = 'pc-alice-' + RUN;
const BOB = 'pc-bob-' + RUN;
const AUD = 'https://localhost:8081/oauth2/token';

// A console action carries its code under the symbol `mark()` uses; a grant's
// verdict carries it as a plain `errorCode` for the token endpoint to mark.
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

async function issue(spec) {
  log.debug("Entering issue().");
  const issued = await x509.issueCertificate({
    subject: [{ name: 'CN', value: spec.cn }],
    subjectPublicKey: spec.publicPem,
    signatureAlg: 'sha256-rsa',
    profile: spec.profile,
    issuer: spec.issuer,
    extensions: spec.extensions
  });
  log.debug("Leaving issue().");
  return issued.pem;
}

// A SAML 2.0 assertion from `iss` about `sub`, signed with `keyPem`. The
// certificate rides in <ds:KeyInfo>, which the verifier uses to CHOOSE among
// registered certificates and never as a key in its own right.
function samlAssertion(iss, sub, keyPem, certPem) {
  log.debug("Entering samlAssertion().");
  const built = signer.buildAssertion({ issuer: iss, subject: sub,
                                        audience: AUD, recipient: AUD });
  log.debug("Leaving samlAssertion().");
  return signer.b64u(signer.sign(built, keyPem, certPem || '', {}));
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

function jwtClaims(iss, sub) {
  log.debug("Entering jwtClaims().");
  jti += 1;
  const now = Math.floor(Date.now() / 1000);
  log.debug("Leaving jwtClaims().");
  return { iss: iss, sub: sub, aud: AUD, iat: now, exp: now + 120,
           jti: 'person-credentials-' + RUN + '-' + jti };
}

async function runBody(t) {
  log.debug("Entering runBody().");
  t.check(personAssertions.storable(),
          'the directory filled the person register\'s slot, so a person can ' +
          'hold a key pair at all');
  const built = pki.hasChain() ? { ok: true } : await pki.start({});
  t.check(built.ok, 'a certificate authority exists to issue from — ENSURED ' +
          'and not rebuilt, for `tests/rfc7523_person_issuer.js`\'s reason',
          (built.errors || []).join(' '));
  ldap.createUser(ALICE, {});
  ldap.createUser(BOB, {});

  try {
    // -----------------------------------------------------------------------
    t.log.info('=== 1. a person holds an RFC 7522 key pair on a set of its ' +
               'own ===');
    const samlIssued = await pkiAdmin.pkiAction({
      action: 'issue', target: 'person', purpose: 'saml', identifier: ALICE,
      leafKeyAlg: 'rsa-2048' });
    t.check(samlIssued.ok, 'an RFC 7522 key pair is issued to a PERSON — the ' +
            'refusal that stood here until 2026-09-13 is retired',
            sentence(samlIssued));
    t.check(/PRIVATE KEY/.test(String(samlIssued.privateKeyPem)),
            'and the private key comes back ONCE, in the reply to the act ' +
            'that made it');
    t.check(!samlIssued.jwks && !!samlIssued.thumbprint,
            'with a thumbprint and no JWKS — SAML has none');
    let alice = personAssertions.recordFor(ALICE);
    t.check(alice.hasSamlKeyPair && !alice.hasKeyPair,
            'THE SAML SET IS WRITTEN AND THE JWT SET IS NOT', JSON.stringify({
              saml: alice.hasSamlKeyPair, jwt: alice.hasKeyPair }));
    const samlHeld = alice.keys.saml[0] || {};
    t.equal(samlHeld.source, 'issued', 'and its provenance is recorded');
    t.equal(samlHeld.id, samlIssued.thumbprint,
            'the handle on the entry is the certificate\'s thumbprint');
    t.check(personAssertions.SEALED_ATTRIBUTES
              .indexOf('stsSamlAssertionPrivateKey') >= 0,
            'the SAML private key is on the sealed list beside the JWT one');
    // HELD, so that section 3's "it is gone" is about a key that was there.
    // Without this a write that never wrote the private key passes the file.
    t.check(/PRIVATE KEY/.test(samlHeld.privateKeyPem || ''),
            'and the issued private key IS on the entry, opened for this ' +
            'register');
    // THE MODEL WHILE A PRIVATE KEY IS HELD, which is the only state in which
    // it could leak one — asked here rather than only at the end, where every
    // key pair on the entry is an upload with no private key to leak.
    const heldState = adminViews.personCredentialsState(ALICE);
    t.check(heldState.purposes.some(function (p) {
              return p.id === 'saml' && p.keys.some(function (one) {
                return one.privateKeyHeld;
              });
            }) &&
            JSON.stringify(heldState.purposes).indexOf('PRIVATE KEY') < 0 &&
            JSON.stringify(heldState.json).indexOf('PRIVATE KEY') < 0,
            'THE PAGE\'S MODEL SAYS A PRIVATE KEY IS HELD AND CARRIES NONE — ' +
            'a person\'s private key has no read door');
    t.check(!!personAssertions.issuerFor(ALICE, 'saml') &&
            !personAssertions.issuerFor(ALICE, 'jwt'),
            'A PERSON IS AN ISSUER UNDER THE PROFILE THEY HOLD A KEY PAIR ' +
            'FOR, AND NOT UNDER THE OTHER — the crossing, as a lookup');
    t.check(!personAssertions.issuerFor(ALICE),
            'and a caller naming no profile asks about RFC 7523, which is ' +
            'what every caller written before the SAML set means');

    // -----------------------------------------------------------------------
    t.log.info('=== 2. the SAML bearer grant reads it ===');
    const samlKey = samlIssued.privateKeyPem;
    const samlCert = samlIssued.certificatePem;
    const self = await samlGrant.verify({
      assertion: samlAssertion(ALICE, ALICE, samlKey, samlCert),
      audiences: [AUD] });
    t.check(self.ok && self.issuerKind === 'person' && self.person === ALICE,
            'AN ASSERTION A PERSON SIGNED ABOUT THEMSELVES IS ACCEPTED, and ' +
            'reported as the person\'s rather than as an application\'s',
            sentence(self));
    t.equal(self.application, '',
            'no application is named for it — a person is not one');
    const other = await samlGrant.verify({
      assertion: samlAssertion(ALICE, BOB, samlKey, samlCert),
      audiences: [AUD] });
    t.check(!other.ok && codeOf(other) === 'STS-OAUTH-0242' &&
            /only be about themselves/.test(sentence(other)),
            'THE SAME KEY NAMING SOMEBODY ELSE AS <Subject> IS REFUSED, by ' +
            'the rule and not by a lookup that failed', sentence(other));

    const bobJwt = await pkiAdmin.pkiAction({
      action: 'issue', target: 'person', purpose: 'jwt', identifier: BOB,
      leafKeyAlg: 'rsa-2048' });
    t.check(bobJwt.ok, 'Bob is issued an RFC 7523 key pair and nothing else',
            sentence(bobJwt));
    const crossed = await samlGrant.verify({
      assertion: samlAssertion(BOB, BOB, bobJwt.privateKeyPem,
                               bobJwt.certificatePem),
      audiences: [AUD] });
    t.check(!crossed.ok && /STS-OAUTH-006[24]/.test(codeOf(crossed)),
            'HIS RFC 7523 KEY CANNOT SIGN A SAML ASSERTION — nothing ' +
            'registered for RFC 7522 answers to him', sentence(crossed));

    // -----------------------------------------------------------------------
    t.log.info('=== 3. a certificate replaces a person\'s key pair ===');
    const rootPair = await keyMaterial.generateKeyPair('rsa-2048');
    const rootPem = await issue({
      cn: 'Personcred Foreign Root ' + RUN, publicPem: rootPair.publicPem,
      profile: 'root-ca',
      issuer: { privateKeyPem: rootPair.privatePem, keyAlg: 'rsa-2048' },
      extensions: {
        basicConstraints: { present: true, critical: true, ca: true,
                            pathLen: null },
        keyUsage: { present: true, critical: true,
                    usages: ['keyCertSign', 'cRLSign'] } } });
    const interPair = await keyMaterial.generateKeyPair('rsa-2048');
    const interPem = await issue({
      cn: 'Personcred Foreign Intermediate ' + RUN,
      publicPem: interPair.publicPem, profile: 'intermediate-ca',
      issuer: { certificatePem: rootPem, privateKeyPem: rootPair.privatePem,
                keyAlg: 'rsa-2048' },
      extensions: {
        basicConstraints: { present: true, critical: true, ca: true,
                            pathLen: 0 },
        keyUsage: { present: true, critical: true,
                    usages: ['keyCertSign', 'cRLSign'] } } });
    const leafPair = await keyMaterial.generateKeyPair('rsa-2048');
    const leafPem = await issue({
      cn: 'personcred-external-leaf', publicPem: leafPair.publicPem,
      profile: 'digital-signature',
      issuer: { certificatePem: interPem, privateKeyPem: interPair.privatePem,
                keyAlg: 'rsa-2048' },
      extensions: {
        basicConstraints: { present: true, critical: true, ca: false },
        keyUsage: { present: true, critical: true,
                    usages: ['digitalSignature'] } } });

    const withKey = await pkiAdmin.pkiAction({
      action: 'upload-certificate', target: 'person', purpose: 'saml',
      identifier: ALICE, certificate: leafPem,
      chain: leafPair.privatePem + interPem + rootPem });
    t.equal(codeOf(withKey), 'STS-PKI-0141',
            'a person\'s upload carrying a private key is refused, as an ' +
            'application\'s is');
    const incomplete = await pkiAdmin.pkiAction({
      action: 'upload-certificate', target: 'person', purpose: 'saml',
      identifier: ALICE, certificate: leafPem, chain: interPem });
    t.equal(codeOf(incomplete), 'STS-PKI-0147',
            'and an external chain without its root is incomplete for a ' +
            'person too');
    t.equal(personAssertions.listFor(ALICE, 'saml').map(function (one) {
      return one.source;
    }).join(','), 'issued', 'neither refusal changed the entry');

    const nobody = await pkiAdmin.pkiAction({
      action: 'upload-certificate', target: 'person', purpose: 'saml',
      identifier: 'pc-nobody-' + RUN, certificate: leafPem,
      chain: interPem + rootPem });
    t.equal(codeOf(nobody), 'STS-PKI-0109',
            'an upload for a person nobody in this realm is, is refused ' +
            'rather than creating them');

    const samlUpload = await pkiAdmin.pkiAction({
      action: 'upload-certificate', target: 'person', purpose: 'saml',
      identifier: ALICE, certificate: leafPem, chain: rootPem + interPem });
    t.check(samlUpload.ok && samlUpload.source === 'uploaded-external-ca',
            'A FULL EXTERNAL CHAIN IS ADDED TO ALICE\'S RFC 7522 KEY PAIRS ' +
            '(#1290: it replaced the one held until then)',
            sentence(samlUpload));
    const samlRows = personAssertions.listFor(ALICE, 'saml');
    const uploadedRow = samlRows.filter(function (one) {
      return one.source === 'uploaded-external-ca';
    })[0] || {};
    t.equal(samlRows.length, 2,
            'she holds both now: the issued key pair and the upload');
    t.check(!uploadedRow.privateKeyHeld,
            'NO PRIVATE KEY IS HELD FOR THE UPLOAD — she keeps her own');
    t.check((String(uploadedRow.chainPem).match(/BEGIN CERT/g) ||
             []).length === 2,
            'the stored chain is the intermediate and the root');
    const oldKey = await samlGrant.verify({
      assertion: samlAssertion(ALICE, ALICE, samlKey, ''), audiences: [AUD] });
    t.check(oldKey.ok,
            'the key pair issued before the upload STILL signs for her',
            sentence(oldKey));
    const newKey = await samlGrant.verify({
      assertion: samlAssertion(ALICE, ALICE, leafPair.privatePem, leafPem),
      audiences: [AUD] });
    t.check(newKey.ok && newKey.issuerKind === 'person',
            'AND SO DOES THE KEY SHE HOLDS HERSELF, verified through the ' +
            'chain she uploaded — any valid one is matched by thumbprint',
            sentence(newKey));
    const revokeIssued = await pkiAdmin.pkiAction({
      action: 'revoke', target: 'person', purpose: 'saml', identifier: ALICE,
      handle: samlIssued.thumbprint, reason: 'keyCompromise' });
    t.check(revokeIssued.ok && revokeIssued.onList &&
            revokeIssued.remaining === 1,
            'REVOKING THE ISSUED ONE puts it on its authority\'s list and ' +
            'leaves the upload', sentence(revokeIssued));
    const oldRevoked = await samlGrant.verify({
      assertion: samlAssertion(ALICE, ALICE, samlKey, ''), audiences: [AUD] });
    t.check(!oldRevoked.ok, 'and the revoked key no longer signs for her',
            sentence(oldRevoked));
    const newStill = await samlGrant.verify({
      assertion: samlAssertion(ALICE, ALICE, leafPair.privatePem, leafPem),
      audiences: [AUD] });
    t.check(newStill.ok, 'while the uploaded one still does',
            sentence(newStill));

    const jwtUpload = await pkiAdmin.pkiAction({
      action: 'upload-certificate', target: 'person', purpose: 'jwt',
      identifier: BOB, certificate: leafPem, chain: interPem + rootPem });
    t.check(jwtUpload.ok && /^person-/.test(jwtUpload.kid || ''),
            'the same certificate is added to Bob\'s RFC 7523 key pairs, ' +
            'under a PERSON kid', sentence(jwtUpload));
    const bob = personAssertions.recordFor(BOB);
    const bobUpload = bob.keys.jwt.filter(function (one) {
      return one.id === jwtUpload.kid;
    })[0] || {};
    t.check(bob.hasKeyPair && !bobUpload.privateKeyPem &&
            bob.jwks.keys.some(function (one) {
              return one.kid === jwtUpload.kid;
            }),
            'his valid JWKS holds the uploaded key under its kid, and no ' +
            'private key is held for it');
    const jwtSelf = await assertionGrant.verify({
      assertion: jws({ alg: 'RS256', kid: jwtUpload.kid },
                     jwtClaims(BOB, BOB), leafPair.privatePem),
      audiences: [AUD] });
    t.check(jwtSelf.ok && jwtSelf.issuerKind === 'person',
            'THE JWT GRANT VERIFIES HIS ASSERTION WITH THE UPLOADED KEY',
            sentence(jwtSelf));
    const jwtOther = await assertionGrant.verify({
      assertion: jws({ alg: 'RS256', kid: jwtUpload.kid },
                     jwtClaims(BOB, ALICE), leafPair.privatePem),
      audiences: [AUD] });
    t.equal(codeOf(jwtOther), 'STS-OAUTH-0049',
            'and an uploaded key is no wider than an issued one: naming ' +
            'somebody else as `sub` is refused');

    // -----------------------------------------------------------------------
    t.log.info('=== 4. this realm\'s certificate, and whose it is ===');
    const appLeaf = await pki.issueSigningKeyPair(undefined, {
      identifier: 'pc-app-' + RUN, purpose: 'jwt' });
    const asApp = await pkiAdmin.pkiAction({
      action: 'upload-certificate', target: 'person', purpose: 'jwt',
      identifier: ALICE, certificate: appLeaf.issued.certificatePem });
    t.check(!asApp.ok && codeOf(asApp) === 'STS-PKI-0155' &&
            /urn:sts:application:/.test(sentence(asApp)),
            'AN APPLICATION\'S LEAF FROM THIS REALM IS REFUSED FOR A PERSON, ' +
            'naming the subject it was issued to', sentence(asApp));
    const bobsOwn = await pki.issueSigningKeyPair(undefined, {
      identifier: BOB, purpose: 'jwt', subjectKind: 'person' });
    const asBob = await pkiAdmin.pkiAction({
      action: 'upload-certificate', target: 'person', purpose: 'jwt',
      identifier: ALICE, certificate: bobsOwn.issued.certificatePem });
    t.equal(codeOf(asBob), 'STS-PKI-0155',
            'and so is ANOTHER PERSON\'S — a credential issued to Bob is not ' +
            'Alice\'s to register');
    const alicesOwn = await pki.issueSigningKeyPair(undefined, {
      identifier: ALICE, purpose: 'jwt', subjectKind: 'person' });
    const ownUpload = await pkiAdmin.pkiAction({
      action: 'upload-certificate', target: 'person', purpose: 'jwt',
      identifier: ALICE, certificate: alicesOwn.issued.certificatePem });
    t.check(ownUpload.ok && ownUpload.source === 'uploaded-realm-ca',
            'HER OWN LEAF FROM THIS REALM IS ACCEPTED ALONE — the service ' +
            'holds every tier above it', sentence(ownUpload));
    const appSide = await pki.registerCertificate(undefined, {
      identifier: 'pc-app-' + RUN, purpose: 'jwt',
      certificatePem: alicesOwn.issued.certificatePem });
    t.equal(codeOf(appSide), 'STS-PKI-0155',
            'and the rule holds the other way round: a person\'s leaf is not ' +
            'an application\'s');

    const selfPair = await keyMaterial.generateKeyPair('rsa-2048');
    const selfLeaf = await issue({
      cn: 'personcred-self', publicPem: selfPair.publicPem,
      profile: 'digital-signature',
      issuer: { privateKeyPem: selfPair.privatePem, keyAlg: 'rsa-2048' },
      extensions: {
        basicConstraints: { present: true, critical: true, ca: false },
        keyUsage: { present: true, critical: true,
                    usages: ['digitalSignature'] } } });
    const selfSigned = await pkiAdmin.pkiAction({
      action: 'upload-certificate', target: 'person', purpose: 'jwt',
      identifier: ALICE, certificate: selfLeaf });
    t.check(codeOf(selfSigned) === 'STS-PKI-0147' &&
            /no by-value registration/.test(sentence(selfSigned)) &&
            !/oauthJwks/.test(sentence(selfSigned)),
            'a SELF-SIGNED leaf is refused, and the refusal does not send a ' +
            'person to an application\'s by-value attribute',
            sentence(selfSigned));

    // -----------------------------------------------------------------------
    t.log.info('=== 5. revoked one at a time, and the page\'s model ===');
    const state = adminViews.personCredentialsState(ALICE);
    const byId = {};
    state.purposes.forEach(function (p) { byId[p.id] = p; });
    const samlKeys = byId.saml.keys || [];
    const external = samlKeys.filter(function (one) {
      return one.source === 'uploaded-external-ca';
    })[0] || {};
    t.check(state.found && byId.jwt.held && byId.saml.held &&
            samlKeys.length === 2 && external.chain.length === 2 &&
            !external.privateKeyHeld && external.state === 'valid' &&
            samlKeys.some(function (one) {
              return one.state === 'revoked';
            }),
            'the Credentials section reads every key pair of both profiles, ' +
            'each with its source, chain, state and absent private key',
            JSON.stringify(samlKeys.map(function (one) {
              return [one.source, one.state];
            })));
    t.check(JSON.stringify(state.json).indexOf('PRIVATE KEY') < 0 &&
            JSON.stringify(state.purposes).indexOf('PRIVATE KEY') < 0,
            'NO PRIVATE KEY IS IN THE MODEL, EITHER PROFILE — a person\'s ' +
            'has no read door, so the page says whether one is held and ' +
            'nothing more');

    const revokeSaml = await pkiAdmin.pkiAction({
      action: 'revoke', target: 'person', purpose: 'saml', identifier: ALICE,
      handle: external.handle });
    alice = personAssertions.recordFor(ALICE);
    t.check(revokeSaml.ok && !revokeSaml.onList && !alice.hasSamlKeyPair &&
            alice.hasKeyPair,
            'REVOKING THE LAST RFC 7522 KEY PAIR LEAVES THE RFC 7523 ONES — ' +
            'and an external authority\'s certificate is marked revoked ' +
            'here, on no list of ours', sentence(revokeSaml));
    const nothingLeft = await pkiAdmin.pkiAction({
      action: 'revoke', target: 'person', purpose: 'saml', identifier: ALICE,
      handle: 'not-a-handle-of-hers' });
    t.equal(codeOf(nothingLeft), 'STS-PKI-0224',
            'and a handle she holds nothing under is refused by name');
    const badPurpose = await pkiAdmin.pkiAction({
      action: 'revoke', target: 'person', purpose: 'pkcs7',
      identifier: ALICE });
    t.equal(codeOf(badPurpose), 'STS-PKI-0011',
            'a profile that does not exist is refused, not defaulted');

    t.check((errorCodes.describe('STS-PKI-0108') || {}).retired &&
            (errorCodes.describe('STS-PKI-0153') || {}).retired,
            'the two refusals this change reversed stay registered, RETIRED ' +
            '— a code is never reused');
  } finally {
    // Every key pair still valid is revoked: there is no take-off any
    // more (#1290), and a test leaves nothing that would sign.
    [ALICE, BOB].forEach(function (name) {
      personAssertions.PURPOSE_IDS.forEach(function (purpose) {
        personAssertions.activeFor(name, purpose).forEach(function (one) {
          personAssertions.revoke(name, purpose, one.id);
        });
      });
    });
  }
  log.debug("Leaving runBody().");
}

// ---------------------------------------------------------------------------
// THE CERTIFICATE AUTHORITY THIS FILE FINDS IS THE ONE IT LEAVES. `run.js`
// runs every file in ONE process, and a service Root built here is the Root
// `tests/pki.js` meets when it asks for one of its own — so its "the Root
// carries the organisation it was asked for" failed in the suite and passed
// alone. Whatever was absent on the way in is removed on the way out; what
// was already there is left exactly as it was.
// ---------------------------------------------------------------------------
function heldAuthority() {
  log.debug("Entering heldAuthority().");
  log.debug("Leaving heldAuthority().");
  return { root: !!keystore.pkiFor(pki.SERVICE_SCOPE),
           chain: pki.hasChain() };
}

function restoreAuthority(before) {
  log.debug("Entering restoreAuthority().");
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
  name: 'person_credentials',
  describe: 'A person\'s RFC 7523 and RFC 7522 key pairs — the SAML set, the ' +
            'SAML bearer grant holding them to themselves, a certificate ' +
            'replacing either key pair, and this realm\'s certificates ' +
            'refused for anybody they were not issued to.',
  run: run
};
