// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: service_account_certificate_names.js
//
// ===========================================================================
// A SERVICE ACCOUNT'S CERTIFICATES NAME IT `urn:sts:sa:<name>` (#1827).
//
// rcbj, 2026-11-16: "Instead of urn:sts:person:remote-pep-N use the format
// urn:sts:sa:blah for service accounts, but underneath, it's a regular user
// object." And: "Let's make these references more centrally defined and easy
// to change" — `common/subject_urn.ts`.
//
//   A. THE TABLE: `SubjectUrn` builds and reads both spellings of a person,
//      with or without `URI:`, and knows them for one person.
//   B. ISSUING: a service account's TLS client certificate and its RFC 7523
//      key pair carry `urn:sts:sa:<name>` and no `urn:sts:person:`; an
//      ordinary person's still carry `urn:sts:person:`.
//   C. THE TLS CLIENT GATE: `identityOf()` maps `urn:sts:sa:` to the person;
//      a leaf issued with `urn:sts:person:` to the service account still
//      works (backwards compatibility); `urn:sts:sa:` naming somebody who is
//      not a service account is refused, STS-TLS-0063.
//   D. THE ASSERTION GRANT: the service account's x5c asserts about itself
//      and is refused about anybody else (the person rule, STS-OAUTH-0049);
//      a `urn:sts:sa:` leaf of a person who is not one is refused,
//      STS-OAUTH-1011; the old spelling still asserts.
//   E. AN UPLOAD (`registerCertificate()`): the account's own leaf in either
//      spelling registers for it; a `urn:sts:sa:` leaf for a person who is
//      not one is refused, STS-PKI-0277; for an application it widens,
//      STS-PKI-0155.
//   F. ENROLLMENT: the entry's URI is spelt for a service account, both
//      spellings read as the person, and `urn:sts:sa:` of somebody who is
//      not one is refused, STS-ENROLL-0097.
//
// IN PROCESS, against the real directory, in a realm of its own that is
// removed at the end — `tests/service_accounts.js`'s arrangement, and
// `tests/rfc7523_person_issuer.js`'s for the hierarchy, which is ENSURED
// and not rebuilt because every file here shares it.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const realms = require('../common/realms');
const errorCodes = require('../common/error_codes');
const credentials = require('../common/credentials');
const serviceAccounts = require('../common/service_accounts');
const pki = require('../common/pki');
const SubjectUrn = require('../common/subject_urn');
const tlsClient = require('../common/tls_client_certificates');
const assertionGrant = require('../oauth-oidc/assertion_grant');
const core = require('../common/cert_enrollment');
const ldap = require('../ldap/ldap_server');

const log = require('bunyan').createLogger({
  name: 'service_account_certificate_names',
  level: process.env.LOG_LEVEL || 'info' });

const PASSWORD = 'Sv1c-Acc0unt-Pa55word!x';
const AUD = ['https://localhost:8081/oauth2/token'];
const SVC = 'sa-urn-svc';
const OWNER = 'sa-urn-owner';
const PERSON = 'sa-urn-person';

function b64u(buf) {
  log.debug("Entering b64u().");
  log.debug("Leaving b64u().");
  return Buffer.from(buf).toString('base64url');
}

// This file's own signer, for `tests/rfc7523_person_issuer.js`'s reason: the
// document under test is not built by the module that verifies it.
function signJws(header, payload, privateKeyPem) {
  log.debug("Entering signJws().");
  const head = b64u(Buffer.from(JSON.stringify(header), 'utf8'));
  const body = b64u(Buffer.from(JSON.stringify(payload), 'utf8'));
  const signing = head + '.' + body;
  const digest = { RS256: 'sha256', RS384: 'sha384', RS512: 'sha512',
                   ES256: 'sha256', ES384: 'sha384' }[header.alg];
  if (!digest) {
    log.debug("Leaving signJws(). Unsupported.");
    throw new Error('this file signs RS* and ES*; asked for ' + header.alg);
  }
  const options = /^ES/.test(header.alg)
    ? { key: privateKeyPem, dsaEncoding: 'ieee-p1363' } : privateKeyPem;
  const sig = nodeCrypto.sign(digest, Buffer.from(signing, 'ascii'), options);
  log.debug("Leaving signJws().");
  return signing + '.' + b64u(sig);
}

let counter = 0;
function claimsFor(iss, sub) {
  log.debug("Entering claimsFor().");
  counter += 1;
  const now = Math.floor(Date.now() / 1000);
  log.debug("Leaving claimsFor().");
  return { iss: iss, sub: sub, aud: AUD[0], iat: now, exp: now + 120,
           jti: 'sa-urn-' + counter + '-' +
                nodeCrypto.randomBytes(4).toString('hex') };
}

function person(name) {
  log.debug("Entering person().");
  ldap.createUser(name, { invent: false,
                          attributes: { givenName: 'Urn', sn: name,
                                        mail: name + '@example.test' } });
  credentials.setPassword(name, PASSWORD);
  log.debug("Leaving person().");
}

function sansOf(pem) {
  log.debug("Entering sansOf().");
  log.debug("Leaving sansOf().");
  return String(new nodeCrypto.X509Certificate(pem).subjectAltName || '');
}

function asInput(pem, chain) {
  log.debug("Entering asInput().");
  log.debug("Leaving asInput().");
  return { leaf: new nodeCrypto.X509Certificate(pem).raw,
           chain: (chain || []).map(function (one) {
             return new nodeCrypto.X509Certificate(one).raw;
           }),
           verified: true };
}

// A TLS client leaf from the realm's own `tls-client` Issuing CA naming its
// holder exactly as `uri` says, CN `name` — what `issue()` would have built
// before #1827 (for `urn:sts:person:`), or a leaf this service would not
// build at all (for `urn:sts:sa:` of somebody who is not a service account).
async function fixtureLeaf(realmId, name, uri) {
  log.debug("Entering fixtureLeaf().");
  const pair = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const made = await pki.certify(realmId, 'tls-client', {
    slot: 'person:' + name + ':' + nodeCrypto.randomBytes(6).toString('hex'),
    commonName: name, keyAlg: 'ec-p256',
    publicKeyPem: pair.publicKey.export({ type: 'spki', format: 'pem' }),
    keyUsage: ['digitalSignature'],
    extensions: {
      extKeyUsage: { present: true, critical: false, usages: ['clientAuth'] },
      subjectAltName: { present: true, critical: false,
                        names: [{ kind: 'uri', value: uri }] } } });
  log.debug("Leaving fixtureLeaf().");
  return made.record;
}

function sectionA(t) {
  log.debug("Entering sectionA().");
  t.equal(SubjectUrn.forPerson('x', true), 'urn:sts:sa:x',
          'A1. a service account is spelt urn:sts:sa:');
  t.equal(SubjectUrn.forPerson('x', false), 'urn:sts:person:x',
          'A2. anybody else urn:sts:person:');
  t.equal(SubjectUrn.forHolder('application', 'app'),
          'urn:sts:application:app', 'A3. an application urn:sts:application:');
  const sa = SubjectUrn.parse('URI:urn:sts:sa:svc');
  t.check(sa && sa.form === 'sa' && sa.kind === 'person' && sa.name === 'svc',
          'A4. a subjectAltName member urn:sts:sa: parses as a PERSON',
          JSON.stringify(sa));
  const bare = SubjectUrn.parse('urn:sts:person:bob');
  t.check(bare && bare.form === 'person' && bare.kind === 'person',
          'A5. so does a bare urn:sts:person:', JSON.stringify(bare));
  t.check(!SubjectUrn.parse('urn:sts:sa:') &&
          !SubjectUrn.parse('urn:sts:client:x') &&
          !SubjectUrn.parse('urn:sts:sa:x', ['person']),
          'A6. an empty name, a kind not in the table, and a form not asked ' +
          'for are none');
  t.check(SubjectUrn.sameHolder('urn:sts:sa:x', 'URI:urn:sts:person:x') &&
          !SubjectUrn.sameHolder('urn:sts:sa:x', 'urn:sts:application:x'),
          'A7. the two spellings are one person, and never an application');
  t.check(SubjectUrn.namesPerson('urn:sts:sa:x') &&
          SubjectUrn.isSubjectUrn('urn:sts:cell:c1') &&
          SubjectUrn.isServiceAccountForm('URI:urn:sts:sa:x') &&
          !SubjectUrn.isServiceAccountForm('urn:sts:person:x'),
          'A8. the predicates the readers ask');
  t.equal(SubjectUrn.namesIn('DNS:a.example, URI:urn:sts:sa:x, ' +
                             'email:x@example.test, URI:urn:sts:device:d')
            .map(function (one) { return one.form; }).join(','),
          'sa,device', 'A9. a node-style subjectAltName string is read');
  log.debug("Leaving sectionA().");
}

async function inRealm(t, realm) {
  log.debug("Entering inRealm().");
  const realmId = realm.id;
  person(SVC);
  person(OWNER);
  person(PERSON);
  const made = serviceAccounts.set(SVC, { serviceAccount: true,
                                          owners: [OWNER] });
  t.check(made.ok && serviceAccounts.isServiceAccountName(SVC) &&
          !serviceAccounts.isServiceAccountName(PERSON),
          'the fixture: one service account and one ordinary person',
          JSON.stringify(made.errors || ''));

  // -------------------------------------------------------------------------
  // B. ISSUING
  // -------------------------------------------------------------------------
  t.equal(tlsClient.holderUrn(realmId, 'person', SVC), 'urn:sts:sa:' + SVC,
          'B1. the name a service account\'s leaf would carry now');
  const svcTls = await tlsClient.issue(realmId, { username: SVC,
                                                  keyAlg: 'ec-p256' });
  t.check(svcTls.ok, 'B2. a TLS client certificate is issued to the ' +
          'service account', JSON.stringify(svcTls.errors || ''));
  const svcSans = svcTls.ok ? sansOf(svcTls.issued.certificatePem) : '';
  t.check(svcSans.indexOf('URI:urn:sts:sa:' + SVC) >= 0 &&
          svcSans.indexOf('urn:sts:person:') < 0,
          'B3. it names urn:sts:sa:<name> and no urn:sts:person:', svcSans);
  t.equal(svcTls.ok ? svcTls.issued.implicitName : '', 'urn:sts:sa:' + SVC,
          'B4. and the issue says so (implicitName)');
  const personTls = await tlsClient.issue(realmId, { username: PERSON,
                                                     keyAlg: 'ec-p256' });
  const personSans = personTls.ok
    ? sansOf(personTls.issued.certificatePem) : '';
  t.check(personTls.ok &&
          personSans.indexOf('URI:urn:sts:person:' + PERSON) >= 0 &&
          personSans.indexOf('urn:sts:sa:') < 0,
          'B5. an ordinary person\'s still names urn:sts:person:', personSans);
  const svcJwt = await pki.issueSigningKeyPair(realmId, {
    identifier: SVC, purpose: 'jwt', subjectKind: 'person' });
  t.check(svcJwt.ok && svcJwt.issued.subjectUri === 'urn:sts:sa:' + SVC &&
          sansOf(svcJwt.issued.certificatePem)
            .indexOf('urn:sts:person:') < 0,
          'B6. the service account\'s RFC 7523 key pair names urn:sts:sa:',
          svcJwt.ok ? svcJwt.issued.subjectUri : (svcJwt.errors || []));
  const personJwt = await pki.issueSigningKeyPair(realmId, {
    identifier: PERSON, purpose: 'jwt', subjectKind: 'person' });
  t.equal(personJwt.ok ? personJwt.issued.subjectUri : '',
          'urn:sts:person:' + PERSON,
          'B7. an ordinary person\'s key pair names urn:sts:person:');

  // -------------------------------------------------------------------------
  // C. THE TLS CLIENT GATE
  // -------------------------------------------------------------------------
  if (svcTls.ok) {
    const got = tlsClient.identityOf(asInput(svcTls.issued.certificatePem,
                                             svcTls.issued.chainPem));
    t.check(got.accepted && got.kind === 'person' && got.username === SVC &&
            got.realm === realmId,
            'C1. urn:sts:sa: is the person, in its realm', JSON.stringify(got));
  }
  const oldLeaf = await fixtureLeaf(realmId, SVC, 'urn:sts:person:' + SVC);
  const oldGot = oldLeaf ? tlsClient.identityOf(asInput(
    oldLeaf.certificatePem, oldLeaf.chainPem)) : {};
  t.check(oldGot.accepted && oldGot.kind === 'person' &&
          oldGot.username === SVC,
          'C2. BACKWARDS COMPATIBLE: a leaf issued with urn:sts:person: to ' +
          'the service account still is its identity', JSON.stringify(oldGot));
  const falseLeaf = await fixtureLeaf(realmId, PERSON, 'urn:sts:sa:' + PERSON);
  const falseGot = falseLeaf ? tlsClient.identityOf(asInput(
    falseLeaf.certificatePem, falseLeaf.chainPem)) : {};
  t.check(!falseGot.accepted && falseGot.error === 'NOT_A_SERVICE_ACCOUNT' &&
          errorCodes.codeOf(falseGot) === 'STS-TLS-0063',
          'C3. urn:sts:sa: naming somebody who is not a service account is ' +
          'refused, STS-TLS-0063', JSON.stringify(falseGot));
  const nobodyLeaf = await fixtureLeaf(realmId, 'sa-urn-nobody',
                                       'urn:sts:sa:sa-urn-nobody');
  const nobodyGot = nobodyLeaf ? tlsClient.identityOf(asInput(
    nobodyLeaf.certificatePem, nobodyLeaf.chainPem)) : {};
  t.check(!nobodyGot.accepted &&
          nobodyGot.error === 'NOT_A_SERVICE_ACCOUNT',
          'C4. and so is urn:sts:sa: naming nobody', JSON.stringify(nobodyGot));

  // -------------------------------------------------------------------------
  // D. THE ASSERTION GRANT
  // -------------------------------------------------------------------------
  const x5cOf = function (issued) {
    log.debug("Entering x5cOf().");
    log.debug("Leaving x5cOf().");
    return issued.jwks.keys[0].x5c;
  };
  const signWith = function (issued, claims) {
    log.debug("Entering signWith().");
    log.debug("Leaving signWith().");
    return signJws({ alg: issued.jwsAlg, typ: 'JWT', x5c: x5cOf(issued) },
                   claims, issued.privateKeyPem);
  };
  if (svcJwt.ok) {
    const self = await assertionGrant.verify({
      assertion: signWith(svcJwt.issued, claimsFor(SVC, SVC)),
      audiences: AUD });
    t.check(self.ok && self.keySource === 'x5c' &&
            self.issuerKind === 'person',
            'D1. the service account\'s urn:sts:sa: leaf asserts about ' +
            'itself, as a person', self.description);
    const other = await assertionGrant.verify({
      assertion: signWith(svcJwt.issued, claimsFor(SVC, PERSON)),
      audiences: AUD });
    t.check(!other.ok && other.errorCode === 'STS-OAUTH-0049',
            'D2. and is refused about anybody else: the person rule holds ' +
            'for urn:sts:sa:', JSON.stringify(other).slice(0, 200));
  }
  const forcedSa = await pki.issueSigningKeyPair(realmId, {
    identifier: PERSON, purpose: 'jwt', subjectKind: 'person',
    serviceAccount: true });
  if (forcedSa.ok) {
    const falseClaim = await assertionGrant.verify({
      assertion: signWith(forcedSa.issued, claimsFor(PERSON, PERSON)),
      audiences: AUD });
    t.check(!falseClaim.ok && falseClaim.errorCode === 'STS-OAUTH-1011',
            'D3. a urn:sts:sa: leaf of a person who is not a service account ' +
            'is refused, STS-OAUTH-1011', JSON.stringify(falseClaim)
              .slice(0, 200));
  } else {
    t.bad('D3. the fixture urn:sts:sa: key pair was not issued',
          JSON.stringify(forcedSa.errors || ''));
  }
  const oldJwt = await pki.issueSigningKeyPair(realmId, {
    identifier: SVC, purpose: 'jwt', subjectKind: 'person',
    serviceAccount: false });
  if (oldJwt.ok) {
    t.equal(oldJwt.issued.subjectUri, 'urn:sts:person:' + SVC,
            'D4. (the fixture: a key pair spelt as before #1827)');
    const oldSelf = await assertionGrant.verify({
      assertion: signWith(oldJwt.issued, claimsFor(SVC, SVC)),
      audiences: AUD });
    t.check(oldSelf.ok, 'D5. BACKWARDS COMPATIBLE: the service account\'s ' +
            'urn:sts:person: leaf still asserts about itself',
            oldSelf.description);
  }

  // -------------------------------------------------------------------------
  // E. AN UPLOAD
  // -------------------------------------------------------------------------
  if (svcJwt.ok) {
    const own = await pki.registerCertificate(realmId, {
      certificatePem: svcJwt.issued.certificatePem,
      chainPem: (svcJwt.issued.chainPem || []).join('\n'),
      identifier: SVC, subjectKind: 'person', purpose: 'jwt' });
    t.check(own.ok, 'E1. the service account\'s urn:sts:sa: leaf registers ' +
            'for it', JSON.stringify(own.errors || ''));
    const toApp = await pki.registerCertificate(realmId, {
      certificatePem: svcJwt.issued.certificatePem,
      chainPem: (svcJwt.issued.chainPem || []).join('\n'),
      identifier: 'sa-urn-app', subjectKind: 'application', purpose: 'jwt' });
    t.check(!toApp.ok && errorCodes.codeOf(toApp) === 'STS-PKI-0155',
            'E2. and widens an application: urn:sts:sa: is a person\'s name',
            JSON.stringify(toApp.errors || ''));
  }
  if (oldJwt.ok) {
    const oldOwn = await pki.registerCertificate(realmId, {
      certificatePem: oldJwt.issued.certificatePem,
      chainPem: (oldJwt.issued.chainPem || []).join('\n'),
      identifier: SVC, subjectKind: 'person', purpose: 'jwt' });
    t.check(oldOwn.ok, 'E3. its urn:sts:person: leaf registers for it too',
            JSON.stringify(oldOwn.errors || ''));
  }
  if (forcedSa.ok) {
    const falseUpload = await pki.registerCertificate(realmId, {
      certificatePem: forcedSa.issued.certificatePem,
      chainPem: (forcedSa.issued.chainPem || []).join('\n'),
      identifier: PERSON, subjectKind: 'person', purpose: 'jwt' });
    t.check(!falseUpload.ok &&
            errorCodes.codeOf(falseUpload) === 'STS-PKI-0277',
            'E4. a urn:sts:sa: leaf for a person who is not a service ' +
            'account is refused, STS-PKI-0277',
            JSON.stringify(falseUpload.errors || ''));
  }

  // -------------------------------------------------------------------------
  // F. ENROLLMENT
  // -------------------------------------------------------------------------
  t.equal(core.entryUri({ kind: 'person', id: SVC }), 'urn:sts:sa:' + SVC,
          'F1. an enrolled leaf names a service account urn:sts:sa:');
  t.equal(core.entryUri({ kind: 'person', id: PERSON }),
          'urn:sts:person:' + PERSON, 'F2. and anybody else as before');
  const readSa = core.entryFromUri('urn:sts:sa:' + SVC);
  const readOld = core.entryFromUri('urn:sts:person:' + SVC);
  t.check(readSa && readSa.kind === 'person' && readSa.id === SVC &&
          !!readOld && readOld.kind === readSa.kind &&
          readOld.id === readSa.id &&
          core.namesEntry('urn:sts:person:' + SVC, readSa),
          'F3. both spellings are the same person entry',
          JSON.stringify([readSa, readOld]));
  const refused = core.serviceAccountUriRefusal('urn:sts:sa:' + PERSON);
  t.check(refused && errorCodes.codeOf(refused) === 'STS-ENROLL-0097' &&
          core.serviceAccountUriRefusal('urn:sts:sa:' + SVC) === null &&
          core.serviceAccountUriRefusal('urn:sts:person:' + SVC) === null,
          'F4. urn:sts:sa: of somebody who is not one is refused, ' +
          'STS-ENROLL-0097; the account itself in either spelling is not',
          JSON.stringify(refused));
  const target = core.targetFromRequest({ uris: ['urn:sts:sa:' + PERSON] },
                                        '', { kind: 'person', id: PERSON });
  t.check(!target.ok && errorCodes.codeOf(target) === 'STS-ENROLL-0097',
          'F5. a request naming the person as a service account is refused',
          JSON.stringify(target));
  const names = core.namesFor({ entry: { kind: 'person', id: SVC },
                                hostNames: [] }, 'tls-client',
                              { uris: ['urn:sts:person:' + SVC] });
  t.check(names.ok && names.names[0].value === 'urn:sts:sa:' + SVC,
          'F6. a request asking for the account\'s old spelling is issued ' +
          'its own name, urn:sts:sa:', JSON.stringify(names));
  log.debug("Leaving inRealm().");
}

async function run(t) {
  log.debug("Entering run().");
  sectionA(t);
  const built = pki.hasChain() ? { ok: true } : await pki.start({});
  t.check(built.ok, 'a certificate authority exists to issue from — ' +
          'ensured, not rebuilt', (built.errors || []).join(' '));
  const id = 'sa-urn-' + nodeCrypto.randomBytes(3).toString('hex');
  const made = realms.create({ id: id, name: id,
                               description: 'Created by ' + __filename,
                               overrides: {} });
  if (!made.ok) {
    t.bad('could not create the realm "' + id + '"',
          (made.errors || []).join(' '));
    log.debug("Leaving run(). No realm.");
    return;
  }
  try {
    await pki.ensureScope(id);
    await realms.run(made.realm, function () {
      return inRealm(t, made.realm);
    });
  } finally {
    realms.remove(id);
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'service_account_certificate_names',
  describe: 'a service account\'s certificates name it urn:sts:sa:<name> ' +
            '(#1827): issued for every kind of leaf, read as the person by ' +
            'every door, refused where the entry is not a service account, ' +
            'and urn:sts:person: still accepted for one',
  run: run
};
