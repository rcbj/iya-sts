'use strict';

// ===========================================================================
// tests/application_credentials.js — AN APPLICATION'S KEY PAIR REPLACED BY AN
// UPLOADED CERTIFICATE, AND ITS CLIENT SECRET REGENERATED (2026-09-13).
//
// The over-HTTP half is `tests/vendored/sts_application_credentials.js`, which
// drives the two operations and then presents an assertion signed with the
// uploaded key at a real token endpoint. What is here is what a request cannot
// ask, and it is most of the CHAIN RULES, for one reason: every interesting
// input is a certificate hierarchy nobody would ever deploy — an intermediate
// that is an end-entity certificate, a root whose path length constraint the
// chain below it breaks, a leaf that is itself a CA, another realm's branch —
// and building each one over HTTP would be the test building a CA in a JSON
// body. Here they are built with the vendored encoder in a few lines each.
//
// Four claims beyond the chain rules:
//
//   1. THE CHAIN IS BUILT BY ISSUER, NOT BY ORDER. A full external chain pasted
//      root-first is accepted, and what is stored is the path that was checked.
//   2. A CHAIN THAT ENDS AT THIS SERVICE'S OWN ROOT IS NEVER "EXTERNAL".
//      Another realm's leaf, uploaded WITH its branch, builds a consistent
//      chain to the Root every realm shares — and is refused by the realm path
//      check rather than accepted as a foreign authority's, which would walk
//      the realm boundary through an upload form.
//   3. AN UPLOAD REPLACES AN ISSUED KEY PAIR WHOLE — the private key that was
//      on the entry is gone afterwards, and the provenance says `uploaded-…`.
//   4. A CLIENT SECRET IS NEVER QUOTED INTO THE AUDIT LOG, by the regenerate
//      action OR by the generic Set it sits beside — the second of those was a
//      leak this change found: `updateApplication()` put the value it wrote
//      into the audit summary while the comment beside the call said it did
//      not.
//
// It builds hierarchies in two realm ids of its own and creates one application
// in the default realm, which it deletes in a `finally`.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const pki = require('../common/pki');
const keystore = require('../common/keystore');
const applications = require('../common/applications');
require('../ldap/ldap_server');
const audit = require('../common/audit');
const errorCodes = require('../common/error_codes');
const x509 = require('../common/vendored/x509');
const keyMaterial = require('../common/vendored/key_material');
const pkiAdmin = require('../admin-ui/pki_admin');
const adminActions = require('../admin-core/admin_actions');
const adminViews = require('../admin-core/admin_views');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for.
const log = require('bunyan').createLogger({ name: 'application_credentials',
  level: process.env.LOG_LEVEL || 'info' });

const OTHER_REALM = 'appcred-other';
const APP = 'appcred-probe-' + nodeCrypto.randomBytes(4).toString('hex');

// A certificate authority that is nobody's: a root, an intermediate under it,
// and helpers for leaves. Built with the SAME encoder this service issues with,
// which is fine here — what is under test is the chain RULES, not whether the
// encoder writes correct DER, and that encoder is held to OpenSSL elsewhere.
async function caPair(alg) {
  log.debug("Entering caPair().");
  const pair = await keyMaterial.generateKeyPair(alg || 'rsa-2048');
  log.debug("Leaving caPair().");
  return pair;
}

async function issue(spec) {
  log.debug("Entering issue().");
  const issued = await x509.issueCertificate({
    subject: [{ name: 'CN', value: spec.cn }],
    subjectPublicKey: spec.publicPem,
    signatureAlg: spec.signatureAlg || 'sha256-rsa',
    profile: spec.profile,
    notBefore: spec.notBefore,
    notAfter: spec.notAfter,
    issuer: spec.issuer,
    extensions: spec.extensions
  });
  log.debug("Leaving issue().");
  return issued.pem;
}

function codeOf(result) {
  log.debug("Entering codeOf().");
  log.debug("Leaving codeOf().");
  return errorCodes.codeOf(result) || '';
}

function sentence(result) {
  log.debug("Entering sentence().");
  log.debug("Leaving sentence().");
  return ((result && result.errors) || []).join(' ') ||
         String((result && result.why) || '');
}

async function runBody(t) {
  log.debug("Entering runBody().");
  // -------------------------------------------------------------------------
  t.log.info('=== an external hierarchy, and the leaves it issues ===');
  const rootPair = await caPair();
  const rootPem = await issue({
    cn: 'Appcred Foreign Root', publicPem: rootPair.publicPem,
    profile: 'root-ca',
    issuer: { privateKeyPem: rootPair.privatePem, keyAlg: 'rsa-2048' },
    extensions: {
      basicConstraints: { present: true, critical: true, ca: true,
                          pathLen: null },
      keyUsage: { present: true, critical: true,
                  usages: ['keyCertSign', 'cRLSign'] }
    }
  });
  const interPair = await caPair();
  const interPem = await issue({
    cn: 'Appcred Foreign Intermediate', publicPem: interPair.publicPem,
    profile: 'intermediate-ca',
    issuer: { certificatePem: rootPem, privateKeyPem: rootPair.privatePem,
              keyAlg: 'rsa-2048' },
    extensions: {
      basicConstraints: { present: true, critical: true, ca: true,
                          pathLen: 0 },
      keyUsage: { present: true, critical: true,
                  usages: ['keyCertSign', 'cRLSign'] }
    }
  });
  const leafPair = await caPair('ec-p256');
  const leafPem = await issue({
    cn: 'appcred-external-leaf', publicPem: leafPair.publicPem,
    profile: 'digital-signature', signatureAlg: 'sha256-rsa',
    issuer: { certificatePem: interPem, privateKeyPem: interPair.privatePem,
              keyAlg: 'rsa-2048' },
    extensions: {
      basicConstraints: { present: true, critical: true, ca: false },
      keyUsage: { present: true, critical: true, usages: ['digitalSignature'] }
    }
  });

  // -------------------------------------------------------------------------
  t.log.info('=== what is refused before a chain is even walked ===');
  const withKey = await pki.registerCertificate(undefined, {
    identifier: APP, purpose: 'jwt', certificatePem: leafPem,
    chainPem: leafPair.privatePem + interPem + rootPem });
  t.check(!withKey.ok && codeOf(withKey) === 'STS-PKI-0141',
          'AN UPLOAD CARRYING A PRIVATE KEY IS REFUSED BY NAME rather than ' +
          'having the key quietly dropped — somebody who pasted a private ' +
          'key into a form has to be told', sentence(withKey));
  t.check(/treat it as exposed/.test(sentence(withKey)),
          'and the refusal says what to do about it', sentence(withKey));

  const nothing = await pki.registerCertificate(undefined, {
    identifier: APP, purpose: 'jwt', certificatePem: 'not a certificate' });
  t.equal(codeOf(nothing), 'STS-PKI-0142',
          'text with no PEM certificate in it is refused');

  const selfPair = await caPair('ec-p256');
  const selfLeaf = await issue({
    cn: 'appcred-self-signed', publicPem: selfPair.publicPem,
    signatureAlg: 'sha256-ecdsa', profile: 'digital-signature',
    issuer: { privateKeyPem: selfPair.privatePem, keyAlg: 'ec-p256' },
    extensions: {
      basicConstraints: { present: true, critical: true, ca: false },
      keyUsage: { present: true, critical: true, usages: ['digitalSignature'] }
    }
  });
  const selfSigned = await pki.registerCertificate(undefined, {
    identifier: APP, purpose: 'jwt', certificatePem: selfLeaf });
  t.check(!selfSigned.ok && codeOf(selfSigned) === 'STS-PKI-0147' &&
          /oauthJwks/.test(sentence(selfSigned)),
          'a SELF-SIGNED leaf is refused — nothing vouches for it — and the ' +
          'refusal names the attribute that registers a key by value',
          sentence(selfSigned));

  const caAsLeaf = await pki.registerCertificate(undefined, {
    identifier: APP, purpose: 'jwt', certificatePem: interPem,
    chainPem: rootPem });
  t.equal(codeOf(caAsLeaf), 'STS-PKI-0144',
          'a certificate AUTHORITY uploaded as the leaf is refused');

  // -------------------------------------------------------------------------
  t.log.info('=== an external chain must be complete ===');
  const alone = await pki.registerCertificate(undefined, {
    identifier: APP, purpose: 'jwt', certificatePem: leafPem });
  t.check(!alone.ok && codeOf(alone) === 'STS-PKI-0147',
          'an external leaf ALONE is refused as an incomplete chain',
          sentence(alone));
  t.check(/Appcred Foreign Intermediate/.test(sentence(alone)),
          'and the refusal names the issuer nothing uploaded vouched for',
          sentence(alone));
  const noRoot = await pki.registerCertificate(undefined, {
    identifier: APP, purpose: 'jwt', certificatePem: leafPem,
    chainPem: interPem });
  t.check(!noRoot.ok && codeOf(noRoot) === 'STS-PKI-0147' &&
          /Appcred Foreign Root/.test(sentence(noRoot)),
          'THE ROOT IS PART OF "THE FULL TRUST CHAIN": the leaf and its ' +
          'intermediate without the self-signed root are refused, naming the ' +
          'root', sentence(noRoot));

  const strayPair = await caPair('ec-p256');
  const stray = await issue({
    cn: 'appcred-unrelated', publicPem: strayPair.publicPem,
    signatureAlg: 'sha256-ecdsa', profile: 'root-ca',
    issuer: { privateKeyPem: strayPair.privatePem, keyAlg: 'ec-p256' },
    extensions: {
      basicConstraints: { present: true, critical: true, ca: true,
                          pathLen: null },
      keyUsage: { present: true, critical: true, usages: ['keyCertSign'] }
    }
  });
  const extra = await pki.registerCertificate(undefined, {
    identifier: APP, purpose: 'jwt', certificatePem: leafPem,
    chainPem: [interPem, rootPem, stray] });
  t.check(!extra.ok && codeOf(extra) === 'STS-PKI-0148' &&
          /appcred-unrelated/.test(sentence(extra)),
          'a certificate that is not on the path is refused, by name, so ' +
          'that what is stored is exactly the path that was checked',
          sentence(extra));

  // -------------------------------------------------------------------------
  t.log.info('=== every issuer must be allowed to issue ===');
  const eePair = await caPair();
  const endEntity = await issue({
    cn: 'Appcred End Entity As Issuer', publicPem: eePair.publicPem,
    profile: 'digital-signature',
    issuer: { certificatePem: rootPem, privateKeyPem: rootPair.privatePem,
              keyAlg: 'rsa-2048' },
    extensions: {
      basicConstraints: { present: true, critical: true, ca: false },
      keyUsage: { present: true, critical: true,
                  usages: ['digitalSignature', 'keyCertSign'] }
    }
  });
  const underEe = await issue({
    cn: 'appcred-under-end-entity', publicPem: leafPair.publicPem,
    profile: 'digital-signature',
    issuer: { certificatePem: endEntity, privateKeyPem: eePair.privatePem,
              keyAlg: 'rsa-2048' },
    extensions: {
      basicConstraints: { present: true, critical: true, ca: false },
      keyUsage: { present: true, critical: true, usages: ['digitalSignature'] }
    }
  });
  const throughEe = await pki.registerCertificate(undefined, {
    identifier: APP, purpose: 'jwt', certificatePem: underEe,
    chainPem: endEntity + rootPem });
  t.check(!throughEe.ok && codeOf(throughEe) === 'STS-PKI-0151' &&
          /End Entity As Issuer/.test(sentence(throughEe)),
          'A CHAIN THROUGH AN END-ENTITY CERTIFICATE IS REFUSED, although ' +
          'every signature on it verifies — the oldest chain-validation bug ' +
          'there is', sentence(throughEe));

  const tightPair = await caPair();
  const tightRoot = await issue({
    cn: 'Appcred Tight Root', publicPem: tightPair.publicPem,
    profile: 'root-ca',
    issuer: { privateKeyPem: tightPair.privatePem, keyAlg: 'rsa-2048' },
    extensions: {
      basicConstraints: { present: true, critical: true, ca: true,
                          pathLen: 0 },
      keyUsage: { present: true, critical: true, usages: ['keyCertSign'] }
    }
  });
  const tightInter = await issue({
    cn: 'Appcred Tight Intermediate', publicPem: interPair.publicPem,
    profile: 'intermediate-ca',
    issuer: { certificatePem: tightRoot, privateKeyPem: tightPair.privatePem,
              keyAlg: 'rsa-2048' },
    extensions: {
      basicConstraints: { present: true, critical: true, ca: true,
                          pathLen: 0 },
      keyUsage: { present: true, critical: true, usages: ['keyCertSign'] }
    }
  });
  const tightLeaf = await issue({
    cn: 'appcred-tight-leaf', publicPem: leafPair.publicPem,
    profile: 'digital-signature',
    issuer: { certificatePem: tightInter, privateKeyPem: interPair.privatePem,
              keyAlg: 'rsa-2048' },
    extensions: {
      basicConstraints: { present: true, critical: true, ca: false },
      keyUsage: { present: true, critical: true, usages: ['digitalSignature'] }
    }
  });
  const tooDeep = await pki.registerCertificate(undefined, {
    identifier: APP, purpose: 'jwt', certificatePem: tightLeaf,
    chainPem: tightInter + tightRoot });
  t.check(!tooDeep.ok && codeOf(tooDeep) === 'STS-PKI-0151' &&
          /Tight Root/.test(sentence(tooDeep)),
          'a root whose pathLen is 0 cannot have an intermediate below it',
          sentence(tooDeep));

  // -------------------------------------------------------------------------
  t.log.info('=== validity and key type ===');
  const expired = await issue({
    cn: 'appcred-expired', publicPem: leafPair.publicPem,
    profile: 'digital-signature',
    notBefore: new Date(Date.now() - 3 * 86400000).toISOString(),
    notAfter: new Date(Date.now() - 86400000).toISOString(),
    issuer: { certificatePem: interPem, privateKeyPem: interPair.privatePem,
              keyAlg: 'rsa-2048' },
    extensions: {
      basicConstraints: { present: true, critical: true, ca: false },
      keyUsage: { present: true, critical: true, usages: ['digitalSignature'] }
    }
  });
  t.equal(codeOf(await pki.registerCertificate(undefined, {
            identifier: APP, purpose: 'jwt', certificatePem: expired,
            chainPem: interPem + rootPem })),
          'STS-PKI-0145', 'an expired leaf is refused');

  const shortRsa = nodeCrypto.generateKeyPairSync('rsa',
                                                 { modulusLength: 1024 });
  const shortLeaf = await issue({
    cn: 'appcred-short-rsa',
    publicPem: shortRsa.publicKey.export({ type: 'spki', format: 'pem' }),
    profile: 'digital-signature',
    issuer: { certificatePem: interPem, privateKeyPem: interPair.privatePem,
              keyAlg: 'rsa-2048' },
    extensions: {
      basicConstraints: { present: true, critical: true, ca: false },
      keyUsage: { present: true, critical: true, usages: ['digitalSignature'] }
    }
  });
  t.equal(codeOf(await pki.registerCertificate(undefined, {
            identifier: APP, purpose: 'jwt', certificatePem: shortLeaf,
            chainPem: interPem + rootPem })),
          'STS-PKI-0146', 'a 1024-bit RSA key is refused');

  const edPair = await caPair('ed25519');
  const edLeaf = await issue({
    cn: 'appcred-ed25519', publicPem: edPair.publicPem,
    profile: 'digital-signature',
    issuer: { certificatePem: interPem, privateKeyPem: interPair.privatePem,
              keyAlg: 'rsa-2048' },
    extensions: {
      basicConstraints: { present: true, critical: true, ca: false },
      keyUsage: { present: true, critical: true, usages: ['digitalSignature'] }
    }
  });
  const edSaml = await pki.registerCertificate(undefined, {
    identifier: APP, purpose: 'saml', certificatePem: edLeaf,
    chainPem: interPem + rootPem });
  const edJwt = await pki.registerCertificate(undefined, {
    identifier: APP, purpose: 'jwt', certificatePem: edLeaf,
    chainPem: interPem + rootPem });
  const k1 = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
  const k1Leaf = await issue({
    cn: 'appcred-secp256k1',
    publicPem: k1.publicKey.export({ type: 'spki', format: 'pem' }),
    profile: 'digital-signature',
    issuer: { certificatePem: interPem, privateKeyPem: interPair.privatePem,
              keyAlg: 'rsa-2048' },
    extensions: {
      basicConstraints: { present: true, critical: true, ca: false },
      keyUsage: { present: true, critical: true, usages: ['digitalSignature'] }
    }
  });
  const k1Saml = await pki.registerCertificate(undefined, {
    identifier: APP, purpose: 'saml', certificatePem: k1Leaf,
    chainPem: interPem + rootPem });
  const k1Jwt = await pki.registerCertificate(undefined, {
    identifier: APP, purpose: 'jwt', certificatePem: k1Leaf,
    chainPem: interPem + rootPem });
  t.check(k1Saml.ok && k1Jwt.ok && k1Jwt.registered.jwsAlg === 'ES256K',
          'a secp256k1 key is ES256K for RFC 7523 and ACCEPTED for RFC 7522 ' +
          'since the #37 follow-up — its XML Signature verifier takes any ' +
          'curve node knows, and the ECDSA URIs name none',
          sentence(k1Saml) + ' / ' + sentence(k1Jwt));
  t.check(edSaml.ok && edJwt.ok,
          'and an Ed25519 key is accepted for BOTH — RFC 7523\'s verifier ' +
          'has EdDSA and, since the #37 follow-up, so does the XML ' +
          'Signature one (RFC 9231\'s eddsa-ed25519)',
          sentence(edSaml) + ' / ' + sentence(edJwt));

  // -------------------------------------------------------------------------
  t.log.info('=== a complete external chain, in the wrong order ===');
  const external = await pki.registerCertificate(undefined, {
    identifier: APP, purpose: 'jwt', certificatePem: leafPem,
    chainPem: rootPem + '\n' + interPem });
  t.check(external.ok, 'A FULL EXTERNAL CHAIN IS ACCEPTED, pasted root-first',
          sentence(external));
  const rec = external.registered || {};
  t.equal(rec.source, 'uploaded-external-ca',
          'and recorded as an external authority\'s');
  t.equal(rec.privateKeyPem, '', 'with NO private key in the record');
  t.equal((rec.chainPem || []).length, 2,
          'the stored chain is the intermediate AND the root — the root of a ' +
          'foreign authority is what makes the chain checkable, unlike this ' +
          'service\'s own');
  t.check(/Foreign Intermediate/.test(rec.chainSubjects[0] || '') &&
          /Foreign Root/.test(rec.chainSubjects[1] || ''),
          'in PATH order, whatever order it was pasted in',
          JSON.stringify(rec.chainSubjects));
  const jwk = (rec.jwks && rec.jwks.keys && rec.jwks.keys[0]) || {};
  t.check(/^app-/.test(jwk.kid || '') && jwk.alg === 'ES256' &&
          (jwk.x5c || []).length === 3 && !jwk.d,
          'the JWK is public, names the curve\'s alg, carries the whole path ' +
          'in x5c and an application kid', JSON.stringify(jwk).slice(0, 200));

  // -------------------------------------------------------------------------
  t.log.info('=== this realm\'s own authority, and another realm\'s ===');
  await pki.ensureScope('default', { organisation: 'Appcred' });
  const ownIssued = await pki.issueSigningKeyPair(undefined,
                                                  { identifier: APP });
  t.check(ownIssued.ok, 'this realm issues a key pair',
          sentence(ownIssued));
  const ownUpload = await pki.registerCertificate(undefined, {
    identifier: APP, purpose: 'jwt',
    certificatePem: ownIssued.issued.certificatePem });
  t.check(ownUpload.ok && ownUpload.registered.source === 'uploaded-realm-ca',
          'A LEAF FROM THIS REALM\'S OWN AUTHORITY MAY BE UPLOADED ALONE — ' +
          'the service holds every tier above it', sentence(ownUpload));
  t.check(ownUpload.ok && ownUpload.registered.chainPem.every(function (pem) {
            return pem.indexOf(pki.trustAnchorsFor(undefined)[0]
              .replace(/-----[^-]+-----/g, '').replace(/\s+/g, '')
              .slice(0, 40)) < 0;
          }),
          'and its stored chain leaves the service Root out, which is the ' +
          'issued convention');

  await pki.buildChain(OTHER_REALM, { organisation: 'Appcred Other' });
  const otherIssued = await pki.issueSigningKeyPair(OTHER_REALM,
                                                    { identifier: APP });
  const otherUpload = await pki.registerCertificate(undefined, {
    identifier: APP, purpose: 'jwt',
    certificatePem: otherIssued.issued.certificatePem,
    chainPem: otherIssued.issued.chainPem });
  t.check(!otherUpload.ok && codeOf(otherUpload) === 'STS-PKI-0021',
          'ANOTHER REALM\'S LEAF, UPLOADED WITH ITS BRANCH, IS REFUSED BY ' +
          'THE REALM PATH CHECK — it chains to the Root every realm shares, ' +
          'and accepting it as an external authority\'s would walk the realm ' +
          'boundary through an upload form', sentence(otherUpload));

  // -------------------------------------------------------------------------
  t.log.info('=== the action writes it over an issued key pair ===');
  const made = applications.createApplication({
    identifier: APP, name: 'Appcred Probe', protocols: ['oauth2'],
    fields: { oauthClientSecret: 'appcred-typed-secret' } });
  t.check(made.ok, 'an application to replace key pairs on',
          sentence(made));
  try {
    const issuedHere = await pkiAdmin.pkiAction({ action: 'issue',
                                                  identifier: APP });
    t.check(issuedHere.ok, 'a key pair is issued onto it first',
            sentence(issuedHere));
    let fields = applications.get(APP).fields;
    t.check(!!fields.oauthAssertionPrivateKey &&
            fields.oauthAssertionKeySource === 'issued',
            'and the entry holds its private key, marked `issued`');

    const uploaded = await pkiAdmin.pkiAction({
      action: 'upload-certificate', identifier: APP, purpose: 'jwt',
      certificate: leafPem, chain: interPem + rootPem });
    t.check(uploaded.ok && uploaded.source === 'uploaded-external-ca',
            'the upload action replaces it', sentence(uploaded));
    fields = applications.get(APP).fields;
    t.check(!fields.oauthAssertionPrivateKey,
            'THE ISSUED PRIVATE KEY IS GONE — an entry holding a key for a ' +
            'certificate it does not match would go on handing that key out');
    t.equal(fields.oauthAssertionKeySource, 'uploaded-external-ca',
            'the provenance says where the certificate came from');
    t.equal(new nodeCrypto.X509Certificate(fields.oauthAssertionCertificate)
              .fingerprint256,
            new nodeCrypto.X509Certificate(leafPem).fingerprint256,
            'the certificate on the entry is the uploaded one');
    t.check(JSON.parse(fields.oauthAssertionJwks).keys[0].kid ===
            fields.oauthAssertionKid,
            'and the kid written beside it is the JWKS key\'s');

    const person = await pkiAdmin.pkiAction({
      action: 'upload-certificate', identifier: APP, target: 'person',
      certificate: leafPem, chain: interPem + rootPem });
    // An upload for a person is allowed since 2026-09-13
    // (`tests/person_credentials.js`); what `target` changes is WHICH
    // register the name is looked up in, so an application's identifier
    // names nobody there.
    t.equal(codeOf(person), 'STS-PKI-0109',
            'target=person looks the name up among PEOPLE, where an ' +
            'application\'s identifier is nobody');

    const refusedWrite = await pkiAdmin.pkiAction({
      action: 'upload-certificate', identifier: APP, purpose: 'jwt',
      certificate: leafPem });
    t.check(!refusedWrite.ok && applications.get(APP).fields
              .oauthAssertionKeySource === 'uploaded-external-ca',
            'a REFUSED upload changes nothing on the entry');

    // ---------------------------------------------------------------------
    t.log.info('=== the page\'s model, and what its JSON leaves out ===');
    const view = adminViews.applicationDetailJson({ query: {} }, APP);
    const jwtPair = view.credentialsState.purposes.filter(function (one) {
      return one.id === 'jwt';
    })[0];
    t.check(jwtPair.held && jwtPair.source === 'uploaded-external-ca' &&
            !jwtPair.privateKeyHeld && jwtPair.chain.length === 2,
            'the Credentials section reads the source, the absent private ' +
            'key and the two-certificate chain', JSON.stringify({
              source: jwtPair.source, chain: jwtPair.chain.length }));
    const json = JSON.stringify(view.json.credentials);
    t.check(json.indexOf('appcred-typed-secret') < 0 &&
            json.indexOf('PRIVATE KEY') < 0,
            'THE CREDENTIALS JSON CARRIES NO SECRET AND NO PRIVATE KEY — ' +
            'both are already in `fields` for a caller holding admin:read, ' +
            'and a second copy would be one more place to pick them up');

    const taken = await pkiAdmin.pkiAction({ action: 'revoke',
                                             identifier: APP, purpose: 'jwt' });
    t.check(taken.ok && !applications.get(APP).fields.oauthAssertionKeySource,
            'taking the key pair off clears the provenance with it',
            sentence(taken));

    // ---------------------------------------------------------------------
    t.log.info('=== the provenance is a closed vocabulary ===');
    const bogus = applications.updateApplication(APP, {
      attribute: 'oauthAssertionKeySource', mode: 'set', value: 'trust-me' });
    t.equal(codeOf(bogus), 'STS-REG-0060',
            'a provenance nothing in this service produces is refused');

    // ---------------------------------------------------------------------
    t.log.info('=== the client secret ===');
    const typed = applications.updateApplication(APP, {
      attribute: 'oauthClientSecret', mode: 'set',
      value: 'appcred-second-typed-secret' });
    const auditText = JSON.stringify(audit.list({}));
    t.check(typed.ok &&
            String(typed.message).indexOf('appcred-second-typed-secret') < 0 &&
            auditText.indexOf('appcred-second-typed-secret') < 0,
            'A SECRET WRITTEN THROUGH THE GENERIC SET IS NOT QUOTED into the ' +
            'reply or the audit log — it was, into the summary, until this ' +
            'change', String(typed.message));

    const regenerated = adminActions.applicationsAction({
      action: 'regenerate-secret', application: APP });
    t.check(regenerated.ok && regenerated.replaced &&
            regenerated.clientSecret &&
            regenerated.clientSecret !== 'appcred-second-typed-secret' &&
            applications.get(APP).fields.oauthClientSecret ===
              regenerated.clientSecret,
            'regenerate-secret mints a new secret onto the entry and hands ' +
            'it back', sentence(regenerated));
    t.check(regenerated.clientSecret.length >= 32 &&
            /^[A-Za-z0-9_-]+$/.test(regenerated.clientSecret),
            'base64url, and long enough to be a registration\'s');
    t.check(JSON.stringify(audit.list({})).indexOf(regenerated.clientSecret) <
              0,
            'and the new value is nowhere in the audit log');

    const missing = adminActions.applicationsAction({
      action: 'regenerate-secret', application: APP + '-absent' });
    t.check(!missing.ok, 'a secret is not regenerated for an application ' +
            'that is not in the registry', sentence(missing));

    const saved = process.env.ADMIN_API_CLIENT_SECRET;
    process.env.ADMIN_API_CLIENT_SECRET = 'appcred-pinned-secret';
    try {
      const pinned = applications.regenerateClientSecret('sts-management-api');
      t.equal(codeOf(pinned), 'STS-REG-0061',
              'THE MANAGEMENT API\'S OWN SECRET IS NOT REGENERATED WHILE ' +
              'adminApi.clientSecret PINS IT — every /admin-api token is ' +
              'minted with that setting');
    } finally {
      if (saved === undefined) {
        delete process.env.ADMIN_API_CLIENT_SECRET;
      } else {
        process.env.ADMIN_API_CLIENT_SECRET = saved;
      }
    }
  } finally {
    applications.deleteApplication(APP);
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
  name: 'application_credentials',
  describe: 'An application\'s key pair replaced by an uploaded certificate ' +
            '— the chain rules, this realm\'s own authority against another ' +
            'realm\'s, the write over an issued pair — and the client secret ' +
            'regenerated without reaching the audit log.',
  run: run
};
