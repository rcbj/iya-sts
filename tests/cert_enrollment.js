'use strict';
//
// File: cert_enrollment.js
//
// ===========================================================================
// THE CERTIFICATE-ENROLLMENT CORE (2026-09-13), IN PROCESS.
//
// ACME, EST and SCEP each have an over-HTTP job of their own, driven by an
// independent client. What is here is what those three cannot see, because
// every one of them reaches `common/cert_enrollment.ts` through a protocol that
// has already made most of the interesting inputs impossible:
//
//   * THE PROFILE TABLE AS A TABLE — the nine issued, the five refused BY
//     DESIGN with a reason each, and the setting that narrows the nine. Over a
//     protocol a refused profile is one request per profile per protocol.
//   * THE PROOF OF POSSESSION, for every key family the vendored encoder makes
//     — RSA, ECDSA, Ed25519 and ML-DSA — and a CSR whose signature was made
//     with a DIFFERENT key, which no honest client library will produce.
//   * THE NAME RULES one by one: a URI, a DNS name, an address, an email and a
//     UPN the entry does not own, each refused BY NAME rather than dropped, and
//     the three profiles that add a name of their own.
//   * WHAT IS ON THE ENTRY AFTERWARDS — the record, the sealed private key when
//     this service made it and no private key when it did not, the subject DN
//     in `x509subject` — which no protocol response carries.
//   * THE CHAIN, verified by NODE'S OWN X509Certificate and not by
//     `pki.verifyLeaf()`, for `pki_hierarchy.js`'s reason: an assertion about a
//     chain that used the implementation under test would be that
//     implementation agreeing with itself.
//   * REALM ISOLATION of both credentials and of certificate authentication,
//     against a realm created here and removed in a `finally`.
//   * THE MODE HALF — a wrong password and a wrong client secret refused in a
//     product-mode realm and accepted in development, and plain HTTP refused
//     only in product.
//
// The administrator roster is STUBBED rather than written, for the reason
// `directory_write_authorization.js` gives at length: a member left in the
// default realm's `admin-write` group closes the console's empty-roster door
// for every later file in `run.js`'s one process.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const fs = require('fs');
const path = require('path');
const asn1js = require('asn1js');

const pki = require('../common/pki');
const realms = require('../common/realms');
const config = require('../common/config');
const errorCodes = require('../common/error_codes');
const keyMaterial = require('../common/vendored/key_material');
const x509 = require('../common/vendored/x509');
// What fills `cert_enrollment.setDirectory()`. Without it every entry is
// "no directory" and every assertion below passes for the wrong reason.
const ldap = require('../ldap/ldap_server');
const core = require('../common/cert_enrollment');
const monitor = require('../common/enrollment_monitor');
const adminRbac = require('../admin-ui/admin_rbac');
const revocation = require('../common/pki_revocation');

const log = require('bunyan').createLogger({ name: 'cert_enrollment',
  level: process.env.LOG_LEVEL || 'info' });

const RUN = nodeCrypto.randomBytes(3).toString('hex');
const ALICE = 'ce-alice-' + RUN;
const BOB = 'ce-bob-' + RUN;
const ADMIN = 'ce-admin-' + RUN;
const APP = 'ce-app-' + RUN;
const REALM = 'ce-realm-' + RUN;

function codeOf(result) {
  log.debug("Entering codeOf().");
  log.debug("Leaving codeOf().");
  return errorCodes.codeOf(result) || '';
}

function person(id, admin) {
  log.debug("Entering person().");
  log.debug("Leaving person().");
  return { kind: 'person', id: id, admin: !!admin, hasEntry: true,
           via: 'test' };
}

async function csrFor(alg, names, opts) {
  log.debug("Entering csrFor(). alg=" + alg);
  const options = opts || {};
  const pair = await keyMaterial.generateKeyPair(alg);
  const signer = options.signWith
    ? await keyMaterial.generateKeyPair(options.signWith) : pair;
  const csr = await x509.certificationRequest({
    subject: options.subject || 'CN=enrollment test',
    publicKeyPem: pair.publicPem,
    privateKeyPem: signer.privatePem,
    subjectAltName: names || []
  });
  log.debug("Leaving csrFor().");
  return { der: Buffer.from(csr.der), pair: pair };
}

// A leaf-first chain verified with node's own verifier. See the header.
function chainVerifies(leafPem, chainPems, rootPem) {
  log.debug("Entering chainVerifies().");
  const certs = [leafPem].concat(chainPems).concat([rootPem]).map(
    function (pem) {
      return new nodeCrypto.X509Certificate(pem);
    });
  for (let i = 0; i < certs.length - 1; i++) {
    if (!certs[i].checkIssued(certs[i + 1]) ||
        !certs[i].verify(certs[i + 1].publicKey)) {
      log.debug("Leaving chainVerifies(). Link " + i + " broken.");
      return false;
    }
  }
  const root = certs[certs.length - 1];
  log.debug("Leaving chainVerifies().");
  return root.verify(root.publicKey);
}

function withOverride(key, value, fn) {
  log.debug("Entering withOverride(). key=" + key);
  const set = config.setOverride(key, value);
  if (set && set.ok === false) {
    throw new Error('could not set ' + key + ': ' + JSON.stringify(set));
  }
  const done = function () {
    config.clearOverride(key);
  };
  let out;
  try {
    out = fn();
  } catch (e) {
    log.debug("Caught in withOverride(): " + ((e && e.message) || e));
    done();
    throw e;
  }
  if (out && typeof out.then === 'function') {
    log.debug("Leaving withOverride(). Asynchronous.");
    return out.then(function (value2) {
      done();
      return value2;
    }, function (error) {
      done();
      throw error;
    });
  }
  done();
  log.debug("Leaving withOverride().");
  return out;
}

function inRealm(id, fn) {
  log.debug("Entering inRealm(). id=" + id);
  log.debug("Leaving inRealm().");
  return realms.run(realms.get(id), fn);
}

// ---------------------------------------------------------------------------
// 1. THE PROFILE TABLE.
// ---------------------------------------------------------------------------
function checkProfiles(t) {
  log.debug("Entering checkProfiles().");
  t.log.info('=== 1. the nine issued profiles and the five refused ===');
  const vendored = x509.profileIds();
  t.equal(core.PROFILE_IDS.length + core.REFUSED_PROFILES.length,
          vendored.length,
          'the nine issued and the five refused are every profile /admin/pki ' +
          'offers — none is silently in neither list');
  vendored.forEach(function (id) {
    const issued = core.PROFILE_IDS.indexOf(id) >= 0;
    const refused = core.REFUSED_PROFILES.some(function (one) {
      return one.id === id;
    });
    t.check(issued !== refused, 'profile "' + id + '" is in exactly one list');
  });
  ['root-ca', 'intermediate-ca', 'issuing-ca', 'ocsp-responder', 'kdc']
    .forEach(function (id) {
      const answer = core.checkProfile('est', id);
      t.equal(codeOf(answer), 'STS-ENROLL-0002',
              '"' + id + '" is refused by design, with its reason');
      t.check(/never issued over an enrollment protocol/.test(answer.why),
              'and the refusal says so', answer.why);
    });
  t.equal(codeOf(core.checkProfile('acme', 'no-such-profile')),
          'STS-ENROLL-0001', 'an unknown profile is refused as unknown');
  core.PROFILE_IDS.forEach(function (id) {
    t.check(core.checkProfile('scep', id).ok,
            '"' + id + '" is issued by default');
  });
  withOverride('scep.allowedProfiles', 'tls-client,email', function () {
    t.equal(codeOf(core.checkProfile('scep', 'code-signing')),
            'STS-ENROLL-0003',
            'a profile left out of scep.allowedProfiles is refused there');
    t.check(core.checkProfile('acme', 'code-signing').ok,
            'and the setting is ACME\'s own, not SCEP\'s');
  });
  log.debug("Leaving checkProfiles().");
}

// ---------------------------------------------------------------------------
// 2. THE PROOF OF POSSESSION AND THE CSR GRAMMAR.
// ---------------------------------------------------------------------------
async function checkCsr(t) {
  log.debug("Entering checkCsr().");
  t.log.info('=== 2. PKCS#10: every key family, a forged signature, KEM ===');
  const names = [{ kind: 'dns', value: 'Host.Example.COM' },
                 { kind: 'ip', value: '192.0.2.7' },
                 { kind: 'ip', value: '2001:db8::1' },
                 { kind: 'email', value: 'a@example.com' },
                 { kind: 'uri', value: 'urn:sts:person:someone' },
                 { kind: 'upn', value: 'someone@example.com' }];
  for (const alg of ['rsa-2048', 'ec-p256', 'ec-p384', 'ed25519',
                     'ml-dsa-44']) {
    const built = await csrFor(alg, names);
    const parsed = await core.parseCsr(built.der);
    t.check(parsed.ok, alg + ': a well-formed request verifies',
            JSON.stringify(parsed.errors));
    if (!parsed.ok) {
      continue;
    }
    t.equal(parsed.keyAlg, alg, alg + ': the key is named as /admin/pki ' +
            'names it');
    t.equal(JSON.stringify(parsed.requested.dns), '["Host.Example.COM"]',
            alg + ': the DNS name is read as sent');
    t.equal(JSON.stringify(parsed.requested.ips),
            '["192.0.2.7","2001:db8::1"]',
            alg + ': both address families are read');
    t.equal(JSON.stringify(parsed.requested.upns), '["someone@example.com"]',
            alg + ': the UPN otherName is read');
    t.equal(JSON.stringify(parsed.requested.uris),
            '["urn:sts:person:someone"]', alg + ': the URI is read');
  }
  const forged = await csrFor('ec-p256', [], { signWith: 'ec-p256' });
  t.equal(codeOf(await core.parseCsr(forged.der)), 'STS-ENROLL-0033',
          'a request signed with a key other than the one it carries proves ' +
          'nothing and is refused');
  t.equal(codeOf(await core.parseCsr(Buffer.from('not a certificate ' +
                                                 'request'))),
          'STS-ENROLL-0030', 'bytes that are not DER are refused');
  const good = await csrFor('ec-p256', []);
  t.equal(codeOf(await core.parseCsr(Buffer.concat([good.der,
                                                    Buffer.from([0])]))),
          'STS-ENROLL-0030', 'a request with bytes after it is refused, not ' +
          'read as its first value');
  t.equal(codeOf(await core.parseCsr(Buffer.alloc(0))), 'STS-ENROLL-0030',
          'an empty body is refused');

  // A KEM key cannot sign, so no library will build such a request. Take a
  // good request and swap its SubjectPublicKeyInfo for an ML-KEM one: the key
  // check is made BEFORE the signature, which is what this reaches.
  const kem = await keyMaterial.generateKeyPair('ml-kem-768');
  // pkijs re-encodes a CertificationRequest from its CACHED TBS bytes, so the
  // swap is made on the ASN.1 tree instead: the SPKI is the third member of
  // the CertificationRequestInfo.
  const outer = asn1js.fromBER(new Uint8Array(good.der).buffer).result;
  const cri = outer.valueBlock.value[0];
  const spkiDer = Buffer.from(kem.publicPem.replace(/-----[^-]+-----/g, '')
    .replace(/\s+/g, ''), 'base64');
  cri.valueBlock.value[2] =
    asn1js.fromBER(new Uint8Array(spkiDer).buffer).result;
  const kemDer = Buffer.from(new asn1js.Sequence({ value: [
    new asn1js.Sequence({ value: cri.valueBlock.value }),
    outer.valueBlock.value[1], outer.valueBlock.value[2]] }).toBER(false));
  t.equal(codeOf(await core.parseCsr(kemDer)), 'STS-ENROLL-0032',
          'an ML-KEM key in a request is refused: it cannot prove possession');
  const template = await core.parseCsr(kemDer, { template: true });
  t.check(template.ok && template.keyAlg === 'ml-kem-768',
          'and accepted as a TEMPLATE, which is what EST /serverkeygen reads',
          JSON.stringify(template.errors));
  log.debug("Leaving checkCsr().");
}

// ---------------------------------------------------------------------------
// 3. THE IDENTITY RULE.
// ---------------------------------------------------------------------------
function checkIdentity(t) {
  log.debug("Entering checkIdentity().");
  t.log.info('=== 3. yourself, or anybody if you hold Admin Write ===');
  t.check(core.authorizeTarget(person(ALICE),
                               { kind: 'person', id: ALICE }).ok,
          'a person may have a certificate for themselves');
  t.equal(codeOf(core.authorizeTarget(person(ALICE),
                                      { kind: 'person', id: BOB })),
          'STS-ENROLL-0021', 'and not for somebody else');
  t.equal(codeOf(core.authorizeTarget(
    { kind: 'application', id: APP, hasEntry: true },
    { kind: 'person', id: ALICE })), 'STS-ENROLL-0021',
          'an application may not have one for a person');
  t.check(core.authorizeTarget(person(ADMIN, true),
                               { kind: 'person', id: BOB }).ok,
          'an administrator may have one for another person');
  t.check(core.authorizeTarget(person(ADMIN, true),
                               { kind: 'application', id: APP }).ok,
          'and for an application');
  t.equal(codeOf(core.authorizeTarget(
    { kind: 'person', id: 'nobody', admin: true, hasEntry: false },
    { kind: 'person', id: 'nobody' })) === '' ? 'allowed' : 'refused',
          'allowed',
          'an administrator with no entry of their own is still an ' +
          'administrator for a named target');
  const noEntry = core.targetFromRequest({ uris: [] }, '',
    { kind: 'person', id: 'nobody', admin: true, hasEntry: false });
  t.equal(codeOf(noEntry), 'STS-ENROLL-0023',
          'but must name the entry — a request naming nobody is refused');
  const two = core.targetFromRequest(
    { uris: ['urn:sts:person:' + ALICE, 'urn:sts:person:' + BOB] }, '',
    person(ADMIN, true));
  t.equal(codeOf(two), 'STS-ENROLL-0022',
          'a request naming two entries is refused: one certificate, one ' +
          'entry');
  const byCn = core.targetFromRequest({ uris: [] }, BOB, person(ADMIN, true));
  t.check(byCn.ok && byCn.target.id === BOB && byCn.by === 'common-name',
          'an administrator may name a person by the common name',
          JSON.stringify(byCn));
  const selfCn = core.targetFromRequest({ uris: [] }, BOB, person(ALICE));
  t.check(selfCn.ok && selfCn.target.id === ALICE,
          'a common name naming somebody else does not retarget a ' +
          'non-administrator — the request is for themselves, and the ' +
          'identity rule is checked on THAT');
  t.check(!core.wellFormedId('a\u0000b') && !core.wellFormedId(''),
          'an identifier with a control character, or none, is malformed');
  log.debug("Leaving checkIdentity().");
}

// ---------------------------------------------------------------------------
// 4. THE NAMES A CERTIFICATE MAY CARRY.
// ---------------------------------------------------------------------------
function checkNames(t) {
  log.debug("Entering checkNames().");
  t.log.info('=== 4. every name owned or the request refused ===');
  const alice = core.resolveEntry('person', ALICE);
  t.check(alice.ok, 'the test person resolves', JSON.stringify(alice.errors));
  const refusedBy = function (profile, requested) {
    return codeOf(core.namesFor(alice, profile, requested));
  };
  t.equal(refusedBy('tls-client', { uris: ['urn:sts:person:' + BOB] }),
          'STS-ENROLL-0050', 'another entry\'s URN is refused by name');
  t.equal(refusedBy('tls-client', { uris: ['https://evil.example'] }),
          'STS-ENROLL-0050', 'an arbitrary URI is refused');
  t.equal(refusedBy('tls-server', { dns: ['unregistered.example.com'] }),
          'STS-ENROLL-0051', 'an unregistered DNS name is refused');
  t.equal(refusedBy('tls-server', { ips: ['192.0.2.99'] }),
          'STS-ENROLL-0051', 'an unregistered address is refused');
  t.equal(refusedBy('email', { emails: ['someone-else@example.com'] }),
          'STS-ENROLL-0052', 'an address that is not the entry\'s mail is ' +
          'refused');
  t.equal(refusedBy('smartcard-logon', { upns: ['x@example.com'] }),
          'STS-ENROLL-0053', 'a UPN the entry does not hold is refused');
  t.equal(refusedBy('tls-server', {}), 'STS-ENROLL-0054',
          'a server certificate naming no host is refused');
  const email = core.namesFor(alice, 'email', {});
  t.check(email.ok && email.names.some(function (one) {
    return one.kind === 'email' && one.value === ALICE + '@example.com';
  }), 'an S/MIME certificate gets the entry\'s mail with nothing asked');
  const smart = core.namesFor(alice, 'smartcard-logon', {});
  t.check(smart.ok && smart.names.some(function (one) {
    return one.kind === 'upn' && one.value === ALICE + '@corp.example';
  }), 'a smartcard logon certificate gets the userPrincipalName');
  const bob = core.resolveEntry('person', BOB);
  t.equal(codeOf(core.namesFor(bob, 'email', {})), 'STS-ENROLL-0055',
          'an S/MIME certificate for somebody with no mail is refused');
  t.equal(codeOf(core.namesFor(bob, 'smartcard-logon', {})),
          'STS-ENROLL-0056',
          'a smartcard logon certificate for somebody with neither UPN nor ' +
          'mail is refused');

  t.log.info('=== 4b. host names ===');
  const entry = { kind: 'person', id: ALICE };
  t.check(core.addHostName(entry, 'Www.Example.COM.', 'test').ok,
          'a host name is registered');
  t.check(core.hostNamesOf(entry).indexOf('www.example.com') >= 0,
          'normalised to lower case without the trailing dot');
  t.check(core.addHostName(entry, 'www.example.com', 'test').unchanged,
          'registering it again changes nothing');
  t.equal(codeOf(core.addHostName(entry, 'not a host!', 'test')),
          'STS-ENROLL-0057', 'something that is not a name is refused');
  t.equal(codeOf(core.removeHostName(entry, 'absent.example.com', 'test')),
          'STS-ENROLL-0058', 'removing an unregistered name is refused');
  core.addHostName(entry, '*.wild.example.com', 'test');
  const refreshed = core.resolveEntry('person', ALICE);
  t.check(core.namesFor(refreshed, 'tls-server',
                        { dns: ['*.wild.example.com'] }).ok,
          'a wildcard is issued when it is registered literally');
  t.equal(codeOf(core.namesFor(refreshed, 'tls-server',
                               { dns: ['a.wild.example.com'] })),
          'STS-ENROLL-0051',
          'and a registered wildcard does not make a name under it ' +
          'registered');
  log.debug("Leaving checkNames().");
}

// ---------------------------------------------------------------------------
// 5. ISSUANCE: ALL NINE PROFILES, WHAT IS ON THE ENTRY, THE CHAIN.
// ---------------------------------------------------------------------------
const EKUS = {
  'tls-server': ['serverAuth'],
  'tls-client': ['clientAuth'],
  'tls-server-client': ['serverAuth', 'clientAuth'],
  'digital-signature': [],
  'key-encipherment': [],
  'code-signing': ['codeSigning'],
  'email': ['emailProtection'],
  'timestamping': ['timeStamping'],
  'smartcard-logon': ['clientAuth', 'msSmartcardLogon']
};

async function checkIssuance(t) {
  log.debug("Entering checkIssuance().");
  t.log.info('=== 5. every profile issued, kept on the entry, chained ===');
  const entry = { kind: 'person', id: ALICE };
  core.addHostName(entry, 'server.example.com', 'test');
  const root = pki.trustAnchorsFor(realms.currentId())[0];
  const issuedSerials = [];
  for (const profile of core.PROFILE_IDS) {
    const family = core.FAMILIES[issuedSerials.length % 3];
    const requested = (profile === 'tls-server' ||
                       profile === 'tls-server-client')
      ? { dns: ['server.example.com'] } : {};
    const built = await csrFor(profile === 'key-encipherment' ? 'rsa-2048'
                                                              : 'ec-p256', []);
    const issued = await core.issue({
      family: family, profile: profile, principal: person(ALICE),
      target: entry, publicKeyPem: built.pair.publicPem,
      requested: requested, via: 'test'
    });
    t.check(issued.ok, profile + ' over ' + family + ' is issued',
            JSON.stringify(issued.errors));
    if (!issued.ok) {
      continue;
    }
    issuedSerials.push(issued.record.serialHex);
    const cert = new nodeCrypto.X509Certificate(issued.record.certificatePem);
    const wanted = EKUS[profile].map(function (name) {
      return x509.EKU_OIDS[name];
    }).sort();
    t.equal(JSON.stringify((cert.keyUsage || []).slice().sort()),
            JSON.stringify(wanted),
            profile + ': the extended key usages are the profile\'s, read by ' +
            'OpenSSL');
    t.check(String(cert.subjectAltName).indexOf('URI:urn:sts:person:' +
                                                ALICE) >= 0,
            profile + ': the certificate names the entry in its SAN');
    t.check(!cert.ca, profile + ': the leaf is not a CA');
    t.check(chainVerifies(issued.record.certificatePem,
                          issued.record.chainPem, root),
            profile + ': the chain verifies to the service Root, link by ' +
            'link, by node\'s own verifier');
    const issuer = new nodeCrypto.X509Certificate(issued.record.chainPem[0]);
    t.check(new RegExp(core.FAMILY_LABELS[family] + ' Issuing CA')
      .test(issuer.subject),
            profile + ': it was signed by the ' + core.FAMILY_LABELS[family] +
            ' Issuing CA', issuer.subject);
    t.check(revocation.issuedHere(realms.currentId(), family,
                                  issued.record.serialHex),
            profile + ': OCSP knows this authority issued it');
  }
  const held = core.enrolledOf(entry);
  t.check(issuedSerials.every(function (serial) {
    return held.some(function (one) {
      return one.serialHex === serial;
    });
  }), 'every certificate issued is on the entry it names');
  t.check(held.every(function (one) {
    return one.privateKeyPem === undefined && one.keySource === 'client';
  }), 'and none carries a private key: the client made every one');
  const stored = core.resolveEntry('person', ALICE);
  t.check((stored.attributes.x509subject || []).length > 0,
          'the subject DN is on the entry\'s x509subject, where every ' +
          'certificate-to-entry lookup reads');

  t.log.info('=== 5b. a server-generated key is kept on the entry ===');
  const server = await core.issueWithServerKey({
    family: 'est', profile: 'tls-client', principal: person(ALICE),
    target: entry, keyAlg: 'ec-p384', via: 'test'
  });
  t.check(server.ok && /PRIVATE KEY/.test(server.privateKeyPem),
          'the private key is handed back once', JSON.stringify(server.errors));
  const kept = core.serverKeyOf(entry, server.record.serialHex);
  t.equal(kept, server.privateKeyPem,
          'and the same key is kept on the entry under its serial');
  const recorded = core.enrolledOf(entry).filter(function (one) {
    return one.serialHex === server.record.serialHex;
  })[0];
  t.check(recorded && recorded.keySource === 'server' &&
          recorded.privateKeyPem === undefined,
          'the record says the key was generated here and carries none');
  t.equal(codeOf(await core.issueWithServerKey({
    family: 'est', profile: 'tls-client', principal: person(ALICE),
    target: entry, keyAlg: 'nonsense', via: 'test' })), 'STS-ENROLL-0035',
          'an unknown key algorithm is refused');

  t.log.info('=== 5c. refusals that must leave nothing behind ===');
  const before = core.enrolledOf(entry).length;
  const other = await csrFor('ec-p256', []);
  const refusals = [
    [{ profile: 'kdc' }, 'STS-ENROLL-0002'],
    [{ principal: person(BOB) }, 'STS-ENROLL-0021'],
    [{ target: { kind: 'person', id: 'no-such-' + RUN } }, 'STS-ENROLL-0012'],
    [{ requested: { dns: ['nope.example.com'] }, profile: 'tls-server' },
     'STS-ENROLL-0051']
  ];
  for (const [change, code] of refusals) {
    const answer = await core.issue(Object.assign({
      family: 'acme', profile: 'tls-client', principal: person(ALICE),
      target: entry, publicKeyPem: other.pair.publicPem, requested: {},
      via: 'test'
    }, change));
    t.equal(codeOf(answer), code, 'refused ' + code + ' for ' +
            JSON.stringify(change));
  }
  t.equal(core.enrolledOf(entry).length, before,
          'and not one of those refusals wrote a record');

  t.log.info('=== 5d. the per-entry cap, and re-enrollment supersedes ===');
  const live = core.enrolledOf(entry).filter(function (one) {
    return one.status === 'valid';
  }).length;
  await withOverride('pki.enrollmentMaxCertificatesPerEntry', String(live),
    async function () {
      const capped = await core.issue({
        family: 'est', profile: 'tls-client', principal: person(ALICE),
        target: entry, publicKeyPem: other.pair.publicPem, requested: {},
        via: 'test'
      });
      t.equal(codeOf(capped), 'STS-ENROLL-0040',
              'a full entry is refused rather than an older certificate ' +
              'forgotten');
      const renewed = await core.issue({
        family: 'est', profile: 'tls-client', principal: person(ALICE),
        target: entry, publicKeyPem: other.pair.publicPem, requested: {},
        via: 'test', replaces: server.record.serialHex
      });
      t.check(renewed.ok, 'a re-enrollment replacing one does not count ' +
              'the certificate it replaces', JSON.stringify(renewed.errors));
    });
  t.check(revocation.isRevoked(realms.currentId(), 'est',
                               server.record.serialHex),
          'and the certificate it replaced is on the EST list as superseded');
  const superseded = core.enrolledOf(entry).filter(function (one) {
    return one.serialHex === server.record.serialHex;
  })[0];
  t.check(superseded && superseded.status === 'revoked',
          'and marked revoked on the entry');

  t.log.info('=== 5e. revocation ===');
  const target = issuedSerials[0];
  const revoked = await core.revokeEnrolled(target, 'keyCompromise', 'test');
  t.check(revoked.ok && revocation.isRevoked(realms.currentId(),
                                             revoked.family, target),
          'an enrolled certificate is revoked on its family\'s list',
          JSON.stringify(revoked.errors));
  t.equal(codeOf(await core.revokeEnrolled('00deadbeef', 'unspecified',
                                           'test')),
          'STS-ENROLL-0070', 'a serial nothing issued is refused');
  t.equal(codeOf(await core.revokeEnrolled(issuedSerials[1], 'unspecified',
                                           'test',
                                           { entry: { kind: 'person',
                                                      id: BOB } })),
          'STS-ENROLL-0071',
          'a revocation on behalf of an entry that does not hold it is ' +
          'refused');
  log.debug("Leaving checkIssuance().");
}

// ---------------------------------------------------------------------------
// 6. THE TWO CREDENTIALS.
// ---------------------------------------------------------------------------
function expireCredential(entry, key, id) {
  log.debug("Entering expireCredential().");
  const name = core.ATTRIBUTES[entry.kind][key];
  const resolved = core.resolveEntry(entry.kind, entry.id);
  const values = (resolved.attributes[name] || []).map(function (value) {
    const record = JSON.parse(value);
    if (record.kid === id || record.id === id) {
      record.expiresAt = new Date(Date.now() - 1000).toISOString();
    }
    return JSON.stringify(record);
  });
  // Through the same slot the core writes with.
  require('../common/cert_enrollment');
  const written = ldapWrite(entry, name, values);
  log.debug("Leaving expireCredential().");
  return written;
}

function ldapWrite(entry, name, values) {
  log.debug("Entering ldapWrite().");
  // The slot is private to the module; the one public door that writes an
  // arbitrary value is the host-name writer, so reach the directory the way
  // ldap_server.js exposes a person instead.
  const located = ldap.existingUserEntry(entry.id);
  const stored = located && (located.stored || located);
  if (!stored || !stored.attributes) {
    log.debug("Leaving ldapWrite(). No entry.");
    return false;
  }
  stored.attributes[String(name).toLowerCase()] = values;
  log.debug("Leaving ldapWrite().");
  return true;
}

function checkCredentials(t) {
  log.debug("Entering checkCredentials().");
  t.log.info('=== 6. EAB keys and SCEP challenges ===');
  const entry = { kind: 'person', id: ALICE };
  const eab = core.createEab({ target: entry, createdBy: 'test' });
  t.check(eab.ok && /^eab-p-/.test(eab.kid) &&
          Buffer.from(eab.hmacKey, 'base64url').length === 32,
          'an EAB key is a person-kid and 32 bytes of HMAC key');
  const found = core.findEab(eab.kid);
  t.check(found && found.hmacKey.toString('base64url') === eab.hmacKey &&
          found.entry.id === ALICE,
          'it is found by its kid alone, naming its entry');
  t.check(core.eabsOf(entry).every(function (one) {
    return one.hmacKey === undefined;
  }), 'a listing carries no key material');
  t.check(core.bindEab(eab.kid, 'thumb-1').ok, 'it binds one account');
  t.check(core.bindEab(eab.kid, 'thumb-1').ok,
          'the same account presenting it again is the idempotent case');
  t.equal(codeOf(core.bindEab(eab.kid, 'thumb-2')), 'STS-ENROLL-0081',
          'a second account is refused');
  const forged = eab.kid.replace(/-[0-9a-f]{16}$/, '-0000000000000000');
  t.check(core.findEab(forged) === null,
          'a kid with the right prefix and the wrong suffix finds nothing');
  // A NON-CANONICAL spelling that the regex accepts and that DECODES to the
  // same name: the last base64url character carries padding bits a decoder
  // ignores. Without the canonical check two kids would name one entry.
  // **RECORDED AS AN EQUIVALENT MUTANT, NOT A GAP**: removing the canonical
  // check in `entryOfCredentialId()` survives this assertion, because the
  // aliased kid still fails the exact comparison against the kid stored on the
  // entry. The check is belt and braces for a future lookup that trusts the
  // prefix alone; the assertion is kept because it states the behaviour.
  // BOB's name is 13 bytes, so its base64url spelling ends in a character
  // whose low bits are padding; ALICE's is 15 and has none to vary.
  const bobEab = core.createEab({ target: { kind: 'person', id: BOB },
                                  createdBy: 'test' });
  const canonical = Buffer.from(BOB).toString('base64url');
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz' +
                   '0123456789-_';
  let variant = '';
  alphabet.split('').some(function (c) {
    const tried = canonical.slice(0, -1) + c;
    if (tried !== canonical &&
        Buffer.from(tried, 'base64url').toString() === BOB) {
      variant = tried;
      return true;
    }
    return false;
  });
  t.check(!!variant && core.findEab(bobEab.kid) !== null,
          'the fixture has a real key and a non-canonical spelling of its ' +
          'name');
  const aliased = bobEab.kid.replace(canonical, variant);
  t.check(core.findEab(aliased) === null,
          'a non-canonical base64url prefix is not read as the entry, though ' +
          'it decodes to the same name');
  core.deleteEab(bobEab.kid, 'test');
  const late = core.createEab({ target: entry, createdBy: 'test' });
  expireCredential(entry, 'eab', late.kid);
  t.equal(codeOf(core.bindEab(late.kid, 'thumb-3')), 'STS-ENROLL-0082',
          'an expired key binds nothing');
  t.check(core.deleteEab(late.kid, 'test').ok && core.findEab(late.kid) ===
          null, 'a deleted key is gone');

  const ch = core.createScepChallenge({ target: entry, profile: 'email',
                                        createdBy: 'test' });
  t.check(ch.ok && ch.challenge.indexOf(ch.id + '.') === 0,
          'a challenge is its id and a secret');
  const stored = core.resolveEntry('person', ALICE)
    .attributes[core.ATTRIBUTES.person.challenge].join('\n');
  t.check(stored.indexOf(ch.challenge.split('.').pop()) < 0,
          'the secret is not on the entry, only its digest');
  t.check(core.redeemScepChallenge(ch.challenge, { peek: true }).ok &&
          core.redeemScepChallenge(ch.challenge, { peek: true }).ok,
          'peeking does not spend it');
  const redeemed = core.redeemScepChallenge(ch.challenge);
  t.check(redeemed.ok && redeemed.profile === 'email' &&
          redeemed.entry.id === ALICE,
          'redeeming it answers its entry and its profile');
  t.equal(codeOf(core.redeemScepChallenge(ch.challenge)), 'STS-ENROLL-0084',
          'a second redemption is refused');
  const wrong = core.createScepChallenge({ target: entry, profile: 'email',
                                           createdBy: 'test' });
  t.equal(codeOf(core.redeemScepChallenge(wrong.id + '.' + 'x'.repeat(32))),
          'STS-ENROLL-0083', 'a wrong secret is refused generically');
  t.check(core.redeemScepChallenge(wrong.challenge).ok,
          'and the wrong guess did not spend the real one');
  const old = core.createScepChallenge({ target: entry, profile: 'email',
                                         createdBy: 'test' });
  expireCredential(entry, 'challenge', old.id);
  t.equal(codeOf(core.redeemScepChallenge(old.challenge)), 'STS-ENROLL-0085',
          'an expired challenge is refused');
  t.equal(codeOf(core.createScepChallenge({ target: entry, profile: 'kdc',
                                            createdBy: 'test' })),
          'STS-ENROLL-0002', 'a challenge for a refused profile is not made');
  log.debug("Leaving checkCredentials().");
}

// ---------------------------------------------------------------------------
// 7. AUTHENTICATION, THE MODE, AND THE REALM BOUNDARY.
// ---------------------------------------------------------------------------
async function checkRealmsAndModes(t) {
  log.debug("Entering checkRealmsAndModes().");
  t.log.info('=== 7. development and product; realm A and realm B ===');
  const dev = await core.authenticatePerson(ALICE, 'anything', 'test');
  t.check(dev.ok && dev.principal.id === ALICE && !dev.principal.admin,
          'development checks no password (the credentials row)');
  t.equal(codeOf(await core.authenticatePerson('no-such-' + RUN, 'x', 'test')),
          'STS-ENROLL-0015', 'a name with no entry and no administrator ' +
          'standing is refused');
  t.check(core.transportRefusal({ socket: {}, protocol: 'http' }, 'est') ===
          null, 'development answers EST over plain HTTP');

  const made = realms.create({ id: REALM, name: REALM,
                               description: 'Created by ' + __filename,
                               overrides: {} });
  if (!made.ok) {
    t.bad('could not create the realm', JSON.stringify(made.errors));
    log.debug("Leaving checkRealmsAndModes().");
    return;
  }
  const eabHere = core.createEab({ target: { kind: 'person', id: ALICE },
                                   createdBy: 'test' });
  const challengeHere = core.createScepChallenge({
    target: { kind: 'person', id: ALICE }, profile: 'tls-client',
    createdBy: 'test' });
  const built = await csrFor('ec-p256', []);
  const here = await core.issue({
    family: 'est', profile: 'tls-client', principal: person(ALICE),
    target: { kind: 'person', id: ALICE }, publicKeyPem: built.pair.publicPem,
    requested: {}, via: 'test' });
  const der = new nodeCrypto.X509Certificate(here.record.certificatePem).raw;
  const fakeReq = { socket: { getPeerCertificate: function () {
    return { raw: der };
  } } };
  const atHome = await core.authenticateCertificate(fakeReq, 'test');
  t.check(atHome.ok && atHome.principal.id === ALICE,
          'a certificate this realm issued authenticates its entry here',
          JSON.stringify(atHome.errors));
  // The same certificate, taken off the entry that holds it: it still
  // verifies to this realm and still names Alice, and it is no longer hers.
  const held = core.resolveEntry('person', ALICE)
    .attributes[core.ATTRIBUTES.person.certificate].slice();
  ldapWrite({ kind: 'person', id: ALICE }, core.ATTRIBUTES.person.certificate,
            held.filter(function (value) {
              return JSON.parse(value).serialHex !== here.record.serialHex;
            }));
  t.equal(codeOf(await core.authenticateCertificate(fakeReq, 'test')),
          'STS-ENROLL-0019',
          'a certificate the entry does not hold is not that entry\'s ' +
          'credential, however well it verifies');
  ldapWrite({ kind: 'person', id: ALICE }, core.ATTRIBUTES.person.certificate,
            held);

  await inRealm(REALM, async function () {
    await pki.ensureScope(REALM);
    ldap.createUser(ALICE, { invent: false,
                             attributes: { mail: ALICE + '@example.com' } });
    t.check(core.resolveEntry('person', ALICE).ok,
            'the realm has a person of the same name');
    t.check(core.findEab(eabHere.kid) === null,
            'an EAB key from the default realm is not found in realm B, ' +
            'though a person of that name exists there');
    t.equal(codeOf(core.redeemScepChallenge(challengeHere.challenge)),
            'STS-ENROLL-0083',
            'and a challenge from the default realm is not redeemable there');
    const abroad = await core.authenticateCertificate(fakeReq, 'test');
    t.equal(codeOf(abroad), 'STS-ENROLL-0018',
            'a certificate the default realm issued does not authenticate in ' +
            'realm B — it does not pass through B\'s Intermediate');
    t.equal(codeOf(await core.revokeEnrolled(here.record.serialHex,
                                             'unspecified', 'test')),
            'STS-ENROLL-0070',
            'nor can realm B revoke it');
    const theirs = await core.issue({
      family: 'est', profile: 'tls-client', principal: person(ALICE),
      target: { kind: 'person', id: ALICE },
      publicKeyPem: built.pair.publicPem, requested: {}, via: 'test' });
    t.check(theirs.ok, 'realm B issues its own',
            JSON.stringify(theirs.errors));
    const intermediates = [here, theirs].map(function (one) {
      return new nodeCrypto.X509Certificate(one.record.chainPem[1])
        .fingerprint256;
    });
    t.check(intermediates[0] !== intermediates[1],
            'from an Intermediate of its own');

    config.setOverride('global.mode', 'product');
    try {
      t.equal(codeOf(await core.authenticatePerson(ALICE, 'wrong', 'test')),
              'STS-ENROLL-0014',
              'product mode verifies the password: a wrong one is refused');
      t.equal(codeOf(core.transportRefusal({ socket: {}, protocol: 'http' },
                                           'acme')),
              'STS-ENROLL-0060', 'product mode refuses ACME over plain HTTP');
      t.check(core.transportRefusal({ socket: { encrypted: true } }, 'acme') ===
              null, 'and answers it over TLS');
      t.equal(codeOf(await core.authenticateApplication('no-such-client-' +
                                                        RUN, 'x', 'test')),
              'STS-ENROLL-0016', 'an unknown client is refused');
      // A product realm in a process with no key-encryption key: the key is
      // meant to persist, nothing can seal it, and an EAB MAC key must not be
      // written in the clear because of that. Refused, and nothing written.
      const keystore = require('../common/keystore');
      const before = core.eabsOf({ kind: 'person', id: ALICE }).length;
      const sealed = core.createEab({ target: { kind: 'person', id: ALICE },
                                      createdBy: 'test' });
      if (keystore.persists() && !keystore.sealed()) {
        t.equal(codeOf(sealed), 'STS-ENROLL-0043',
                'product mode with no key-encryption key refuses to store an ' +
                'EAB key rather than store it in the clear');
        t.equal(core.eabsOf({ kind: 'person', id: ALICE }).length, before,
                'and writes nothing');
      } else {
        t.check(sealed.ok, 'an EAB key is made where it can be sealed',
                JSON.stringify(sealed.errors));
      }
    } finally {
      config.clearOverride('global.mode');
    }
  });
  log.debug("Leaving checkRealmsAndModes().");
}

// ---------------------------------------------------------------------------
// 8. THE ADMIN ROSTER, STUBBED. See the header for why it is not written.
// ---------------------------------------------------------------------------
async function checkAdmin(t) {
  log.debug("Entering checkAdmin().");
  t.log.info('=== 8. Admin Write, decided in the default realm ===');
  const real = adminRbac.rolesOf;
  try {
    adminRbac.rolesOf = function (name) {
      return { write: name === ADMIN, read: name === ADMIN, open: false };
    };
    const admin = await core.authenticatePerson(ADMIN, 'x', 'test');
    t.check(admin.ok && admin.principal.admin === true,
            'a holder of Admin Write authenticates as an administrator');
    const plain = await core.authenticatePerson(ALICE, 'x', 'test');
    t.check(plain.ok && plain.principal.admin === false,
            'and somebody else does not');
    t.check(core.sessionPrincipal(ADMIN, 'console').admin === true &&
            core.sessionPrincipal(ALICE, 'console').admin === false,
            'a console session asks the same roster');
    adminRbac.rolesOf = function () {
      return { write: true, read: true, open: true };
    };
    t.check(core.sessionPrincipal(ALICE, 'console').admin === false,
            'an EMPTY roster (everybody holds both roles on the console) ' +
            'makes nobody an administrator of certificate enrollment');
  } finally {
    adminRbac.rolesOf = real;
  }
  log.debug("Leaving checkAdmin().");
}

// ---------------------------------------------------------------------------
// 9. THE MONITOR, AND THE SECRET ATTRIBUTES AS SOURCE.
// ---------------------------------------------------------------------------
function checkMonitorAndSource(t) {
  log.debug("Entering checkMonitorAndSource().");
  t.log.info('=== 9. counters, and the directory withholds the secrets ===');
  monitor.resetForTests('est');
  monitor.record('est', { operation: 'simpleenroll', outcome: 'issued',
                          status: 200, profile: 'tls-client',
                          principal: ALICE, serialHex: 'aa' });
  monitor.record('est', { operation: 'simpleenroll', outcome: 'refused',
                          status: 403, errorCode: 'STS-ENROLL-0021',
                          principal: BOB });
  monitor.record('nonsense', { operation: 'x' });
  const snap = monitor.snapshot('est');
  t.check(snap.requests === 2 && snap.issued === 1 && snap.refused === 1 &&
          snap.codes['STS-ENROLL-0021'] === 1 && snap.recent.length === 2,
          'the EST counters count what was recorded, and nothing for an ' +
          'unknown family', JSON.stringify(snap));
  t.equal(monitor.snapshot('acme').requests, 0,
          'and ACME\'s are its own');

  const ldapSource = fs.readFileSync(path.join(__dirname, '..', 'ldap',
                                               'ldap_server.js'), 'utf8');
  const secretBlock = ldapSource.slice(
    ldapSource.indexOf('const SECRET_ATTRIBUTES = ['),
    ldapSource.indexOf('];', ldapSource.indexOf('const SECRET_ATTRIBUTES')));
  core.SECRET_ATTRIBUTES.forEach(function (name) {
    t.check(secretBlock.indexOf("'" + name.toLowerCase() + "'") >= 0,
            name + ' is withheld from every reader of the LDAP socket');
  });
  // The directory's own dump — what /admin/users?user= and
  // /admin-api/users?user= draw — in development mode, where the key is NOT
  // sealed: the value must be withheld and the name canonically spelled.
  const dumped = ldap.objectFor(ALICE).entry.attributes;
  const keyValues = dumped.stsEnrolledPrivateKey || [];
  t.check(keyValues.length > 0 && keyValues.every(function (value) {
    return /^\(withheld: certificate-enrollment credential/.test(value) &&
           !/PRIVATE KEY/.test(value);
  }), 'the directory dump withholds a server-generated private key in ' +
          'development, under its canonical name',
          JSON.stringify(Object.keys(dumped)));
  t.check((dumped.stsEnrolledCertificate || []).length > 0 &&
          /BEGIN CERTIFICATE/.test(dumped.stsEnrolledCertificate[0]),
          'and shows the certificates, which are public');
  const appSource = fs.readFileSync(path.join(__dirname, '..', 'common',
                                              'applications.js'), 'utf8');
  const withheld = appSource.slice(appSource.indexOf('const WITHHELD_FIELDS'),
    appSource.indexOf('];', appSource.indexOf('const WITHHELD_FIELDS')));
  ['appEnrolledPrivateKey', 'appAcmeEabKey', 'appScepChallenge']
    .forEach(function (name) {
      t.check(withheld.indexOf("'" + name + "'") >= 0,
              name + ' is withheld from every application view');
    });
  log.debug("Leaving checkMonitorAndSource().");
}

// `run.js` runs every file in ONE process, so a service Root this file builds
// is the Root `tests/pki.js` meets next — and that file asserts on the Root IT
// builds ("the Root carries the organisation it was asked for"), which passed
// alone and failed in the suite. What was not here before is taken away again,
// the arrangement `tests/application_credentials.js` records.
function heldAuthority() {
  log.debug("Entering heldAuthority().");
  const keystore = require('../common/keystore');
  log.debug("Leaving heldAuthority().");
  return { root: !!keystore.pkiFor(pki.SERVICE_SCOPE),
           chain: pki.hasChain() };
}

function restoreAuthority(before) {
  log.debug("Entering restoreAuthority().");
  const keystore = require('../common/keystore');
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

async function runBody(t) {
  log.debug("Entering runBody().");
  if (!pki.hasRoot()) {
    await pki.start({});
  }
  await pki.ensureScope(realms.currentId());
  ldap.createUser(ALICE, { invent: false, attributes: {
    mail: ALICE + '@example.com' } });
  // No door creates a person WITH a userPrincipalName — it is not in the
  // catalogue — so it is written onto the entry the way an ldapmodify would.
  ldapWrite({ kind: 'person', id: ALICE }, 'userPrincipalName',
            [ALICE + '@corp.example']);
  ldap.createUser(BOB, { invent: false, attributes: {} });
  ldap.createUser(ADMIN, { invent: false, attributes: {} });
  try {
    checkProfiles(t);
    await checkCsr(t);
    checkIdentity(t);
    checkNames(t);
    await checkIssuance(t);
    checkCredentials(t);
    await checkRealmsAndModes(t);
    await checkAdmin(t);
    checkMonitorAndSource(t);
  } finally {
    if (realms.get(REALM)) {
      realms.remove(REALM);
    }
  }
  log.debug("Leaving runBody().");
}

module.exports = {
  name: 'cert_enrollment',
  describe: 'The certificate-enrollment core ACME, EST and SCEP issue ' +
            'through: profiles, proof of possession, the identity and name ' +
            'rules, what is kept on the entry, the two credentials, realm ' +
            'isolation and the mode.',
  run: run
};
