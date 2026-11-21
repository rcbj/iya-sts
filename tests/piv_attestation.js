// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: piv_attestation.js
//
// ---------------------------------------------------------------------------
// YUBIKEY PIV KEY ATTESTATION, THE PIV SLOT PROFILES, ESCROW AND THE OUTSIDE
// CARD MAPPING (#1955 P2), in process, over `piv_attestation_kit.js`'s
// software YubiKey (every key made at run time).
//
//   1. THE EXTENSIONS AND THE ANCHORS: Yubico's four extensions decoded; the
//      shipped roots and intermediates load and match their pins.
//   2. THE CARRIERS: the request's id-aa-attestation attribute and the
//      form's two certificates both yield the statement; a malformed one is
//      refused.
//   3. VERIFY: a good attestation verifies; another key, another anchor, no
//      serial, another slot, a weaker PIN or touch policy are each refused
//      with their own code.
//   4. ISSUANCE: a piv-auth certificate from an attested request (EST) is
//      `attested-hardware`, records the YubiKey and earns hwk and sc; the
//      profiles' EKUs and names; piv.requireAttestation; piv-card-auth
//      refused for sign-in by default.
//   5. ESCROW (D7): off refuses a server key; on keeps it sealed, the holder
//      recovers it, an administrator without PIV_KEY_RECOVERY cannot, a
//      lost token revokes the attached certificate and the escrow stays.
//   6. THE OUTSIDE CARD (D8): a card certificate maps by its card UUID to
//      the one person holding it, and never by its CN; no holder, two
//      holders, no PIV policy, an unlisted issuer.
//
// The over-HTTP half (EST with an attested request) is
// `tests/protocol/sts_piv_attestation.js`.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const config = require('../common/config');
const realms = require('../common/realms');
const pki = require('../common/pki');
const stsCrypto = require('../common/crypto');
const errorCodes = require('../common/error_codes');
const ldap = require('../ldap/ldap_server');
const core = require('../common/cert_enrollment');
const piv = require('../common/piv_attestation');
const pivEnrolment = require('../common/piv_enrolment');
const tokens = require('../common/hardware_tokens');
const tlsClient = require('../common/tls_client_certificates');
const keyMaterial = require('../common/crypto_impl/key_material');
const pkivia = require('./piv_attestation_kit');

const log = require('bunyan').createLogger({ name: 'piv_attestation',
  level: process.env.LOG_LEVEL || 'info' });

const RUN = nodeCrypto.randomBytes(3).toString('hex');
const ALICE = 'piv-alice-' + RUN;
const BOB = 'piv-bob-' + RUN;
const CAROL = 'piv-carol-' + RUN;
const OVERRIDDEN = ['piv.attestationAnchors', 'piv.pinPolicy',
                    'piv.touchPolicy', 'piv.requireAttestation',
                    'piv.cardAuthSignIn', 'piv.keyEscrow',
                    'piv.externalIssuers', 'piv.externalPolicyOids',
                    'est.allowedProfiles', 'est.serverKeyGeneration',
                    'roles.pivKeyRecoveryGroup', 'xacml.enforceAccess'];
const PIV_AUTH_POLICY = '2.16.840.1.101.3.2.1.3.13';

function code(answer) {
  log.debug("Entering code().");
  log.debug("Leaving code().");
  return errorCodes.codeOf(answer) || '';
}

function person(id, admin) {
  log.debug("Entering person().");
  log.debug("Leaving person().");
  return { kind: 'person', id: id, admin: !!admin, hasEntry: true,
           via: 'test' };
}

// stsPivCardUuid written onto an entry the way an ldapmodify would: no door
// creates a person with one (`tests/cert_enrollment.js`'s ldapWrite()).
function holdCardUuid(username, uuid) {
  log.debug("Entering holdCardUuid().");
  const located = ldap.existingUserEntry(username);
  const stored = located && (located.stored || located);
  if (stored && stored.attributes) {
    stored.attributes.stspivcarduuid = [uuid];
  }
  log.debug("Leaving holdCardUuid().");
}

function checkExtensionsAndAnchors(t, dev, made) {
  log.debug("Entering checkExtensionsAndAnchors().");
  t.log.info('=== 1. the extensions and the anchors ===');
  const facts = stsCrypto.yubicoPivAttestationFacts(
    pki.attestationCertificateFacts(made.slotDer).extensions);
  t.check(facts.serial === made.serial && facts.firmware === '5.4.3' &&
          facts.pinPolicy === 'once' && facts.touchPolicy === 'always' &&
          facts.formFactorName === 'USB-C Keychain' && facts.shape === 'usb-c',
          '1a. Yubico\'s four extensions are decoded', JSON.stringify(facts));
  const shipped = pki.pivAttestationAnchors('');
  const described = pki.describePivAnchors();
  t.check(shipped.source === 'shipped' && shipped.anchors.length === 2 &&
          shipped.intermediates.length === 5 &&
          described.yubicoPivAttestation.every(function (r) {
            return r.used;
          }),
          '1b. Yubico\'s two PIV roots and five PIV intermediates are ' +
          'shipped and match their pins', JSON.stringify(described));
  const configured = pki.pivAttestationAnchors(dev.rootPem);
  t.check(configured.source === 'configured' &&
          configured.anchors.length === 1,
          '1c. a configured anchor replaces the shipped roots');
  log.debug("Leaving checkExtensionsAndAnchors().");
}

async function checkCarriers(t, dev) {
  log.debug("Entering checkCarriers().");
  t.log.info('=== 2. the carriers ===');
  const inReq = await pkivia.slotKey(dev, { inRequest: true });
  const csr = await core.parseCsr(inReq.csrDer, {});
  t.check(csr.ok && csr.attestations.length === 1,
          'precondition: the request carries one id-aa-attestation value',
          JSON.stringify(csr.errors));
  const found = piv.statementFromBundles(csr.attestations);
  t.check(found.ok && found.found && found.certs.length === 1,
          '2a. the request\'s attribute yields the slot certificate and ' +
          'the f9 certificate', JSON.stringify(found.errors));
  const form = piv.statementFromPem(inReq.slotPem, inReq.f9Pem);
  t.check(form.ok && form.found, '2b. the form\'s two certificates yield ' +
          'the same statement');
  t.equal(code(piv.statementFromPem(inReq.slotPem, '')), 'STS-PIV-0004',
          '2c. a form with one certificate is refused');
  t.equal(code(piv.statementFromBundles([Buffer.from([0x30, 0x00])])),
          'STS-PIV-0004', '2d. an attribute that is no AttestationBundle is ' +
          'refused');
  t.check(piv.statementFromPem('', '').found === false &&
          piv.statementFromBundles([]).found === false,
          '2e. nothing given is no statement, and no refusal');
  log.debug("Leaving checkCarriers().");
}

async function checkVerify(t, dev) {
  log.debug("Entering checkVerify().");
  t.log.info('=== 3. verify ===');
  const verifyOf = async function (made, profile) {
    return piv.verify({
      statement: piv.statementFromPem(made.slotPem, made.f9Pem),
      publicKeyPem: made.publicPem, profile: profile || 'piv-auth' });
  };
  const good = await pkivia.slotKey(dev, {});
  const ok = await verifyOf(good);
  t.check(ok.ok && ok.facts.serial === good.serial && ok.facts.slot ===
          '9a' && /configured/.test(ok.facts.anchor),
          '3a. a good attestation verifies to the configured anchor',
          JSON.stringify(ok.errors || ok.facts));
  t.equal(code(await verifyOf(await pkivia.slotKey(dev,
    { attestOther: true }))), 'STS-PIV-0005',
          '3b. an attestation of another key is refused');
  const other = await pkivia.device({ name: 'Another Vendor' });
  t.equal(code(await verifyOf(await pkivia.slotKey(other, {}))),
          'STS-PIV-0006', '3c. a chain to another anchor is refused');
  t.equal(code(await verifyOf(await pkivia.slotKey(dev,
    { noSerial: true }))), 'STS-PIV-0007',
          '3d. an attestation naming no serial is refused');
  t.equal(code(await verifyOf(good, 'piv-sign')), 'STS-PIV-0008',
          '3e. a 9a attestation does not buy a 9c certificate');
  config.setOverride('piv.pinPolicy', 'always');
  t.equal(code(await verifyOf(good)), 'STS-PIV-0011',
          '3f. a PIN policy of once is refused where always is required');
  config.clearOverride('piv.pinPolicy');
  config.setOverride('piv.touchPolicy', 'always');
  t.equal(code(await verifyOf(await pkivia.slotKey(dev,
    { touch: 'cached' }))), 'STS-PIV-0012',
          '3g. a cached touch policy is refused where always is required');
  t.check((await verifyOf(good)).ok, '3h. and an always touch policy meets ' +
          'it');
  config.clearOverride('piv.touchPolicy');
  log.debug("Leaving checkVerify().");
}

async function checkIssuance(t, dev) {
  log.debug("Entering checkIssuance().");
  t.log.info('=== 4. issuance and the profiles ===');
  const made = await pkivia.slotKey(dev, { inRequest: true });
  const csr = await core.parseCsr(made.csrDer, {});
  const issued = await core.issue({
    family: 'est', profile: 'piv-auth', principal: person(ALICE),
    target: { kind: 'person', id: ALICE }, publicKeyPem: csr.publicKeyPem,
    requested: csr.requested, keySource: 'client', keyAlg: csr.keyAlg,
    attestations: csr.attestations, via: 'test' });
  t.check(issued.ok && issued.record.keySource === 'attested-hardware' &&
          issued.record.attestation.serial === made.serial,
          '4a. an attested piv-auth request is issued and its row is ' +
          'attested-hardware', JSON.stringify(issued.errors));
  if (!issued.ok) {
    log.debug("Leaving checkIssuance(). Not issued.");
    return null;
  }
  const serialHex = issued.record.serialHex;
  t.equal(tokens.certificateAmr(serialHex).join(','), 'hwk,sc',
          '4b. the YubiKey is recorded and the certificate earns hwk and sc');
  const token = tokens.byKey('yubico/' + made.serial);
  t.check(token && token.holder === ALICE && token.firmware === '5.4.3' &&
          token.evidenceSources.indexOf('piv-attestation') >= 0,
          '4c. the token carries the attestation\'s facts',
          JSON.stringify(token));
  const facts = stsCrypto.certificateFacts(issued.record.certificatePem);
  t.check(['1.3.6.1.5.5.7.3.2', '1.3.6.1.5.2.3.4', '1.3.6.1.4.1.311.20.2.2']
    .every(function (oid) {
      return (facts.eku || []).indexOf(oid) >= 0;
    }), '4d. piv-auth carries clientAuth, id-pkinit-KPClientAuth and ' +
          'smart-card logon', JSON.stringify(facts.eku));
  // piv-sign: emailProtection and the mail address, no attestation given.
  const plain = await keyMaterial.generateKeyPair('ec-p256');
  const sign = await core.issue({
    family: 'est', profile: 'piv-sign', principal: person(ALICE),
    target: { kind: 'person', id: ALICE }, publicKeyPem: plain.publicPem,
    requested: {}, keySource: 'client', via: 'test' });
  const signFacts = sign.ok
    ? stsCrypto.certificateFacts(sign.record.certificatePem) : null;
  t.check(sign.ok && sign.record.keySource === 'client' &&
          signFacts.eku.indexOf('1.3.6.1.5.5.7.3.4') >= 0 &&
          signFacts.san.email.indexOf(ALICE + '@example.com') >= 0,
          '4e. piv-sign without an attestation is issued, with ' +
          'emailProtection and the mail address, and no evidence',
          JSON.stringify(sign.errors || signFacts));
  const km = await core.issue({
    family: 'est', profile: 'piv-key-management', principal: person(ALICE),
    target: { kind: 'person', id: ALICE },
    publicKeyPem: (await keyMaterial.generateKeyPair('rsa-2048')).publicPem,
    requested: {}, keySource: 'client', via: 'test' });
  const kmFacts = km.ok
    ? stsCrypto.certificateFacts(km.record.certificatePem) : null;
  t.check(km.ok && kmFacts.keyUsage.indexOf('keyEncipherment') >= 0 &&
          kmFacts.eku.indexOf('1.3.6.1.5.5.7.3.4') >= 0,
          '4e-ii. piv-key-management carries keyEncipherment and ' +
          'emailProtection', JSON.stringify(km.errors || kmFacts));
  t.equal(code(await core.issue({
    family: 'est', profile: 'piv-auth', principal: person(ALICE),
    target: { kind: 'application', id: 'no-such-app-' + RUN },
    publicKeyPem: plain.publicPem, requested: {}, keySource: 'client',
    via: 'test' })) !== '', true,
          '4e-iii. a PIV profile is not issued to an application');
  config.setOverride('piv.requireAttestation', true);
  t.equal(code(await core.issue({
    family: 'est', profile: 'piv-sign', principal: person(ALICE),
    target: { kind: 'person', id: ALICE }, publicKeyPem: plain.publicPem,
    requested: {}, keySource: 'client', via: 'test' })), 'STS-PIV-0010',
          '4f. piv.requireAttestation refuses a PIV profile without one');
  config.clearOverride('piv.requireAttestation');
  t.equal(code(await core.issue({
    family: 'est', profile: 'piv-auth', principal: person(ALICE),
    target: { kind: 'person', id: ALICE }, publicKeyPem: plain.publicPem,
    requested: {}, keySource: 'client', via: 'test',
    pivAttestation: { slotPem: made.slotPem, attestationPem: made.f9Pem } })),
          'STS-PIV-0005', '4g. the form\'s attestation of another key ' +
          'refuses the request: an attestation that does not verify is ' +
          'never issued without evidence');
  // piv-card-auth: refused for sign-in by default.
  const cardKey = await pkivia.slotKey(dev, { slot: '9e' });
  const card = await core.issue({
    family: 'est', profile: 'piv-card-auth', principal: person(ALICE),
    target: { kind: 'person', id: ALICE }, publicKeyPem: cardKey.publicPem,
    requested: {}, keySource: 'client', via: 'test',
    pivAttestation: { slotPem: cardKey.slotPem,
                      attestationPem: cardKey.f9Pem } });
  t.check(card.ok, 'precondition: a piv-card-auth certificate is issued',
          JSON.stringify(card.errors));
  if (card.ok) {
    t.equal(code(piv.signInRefusal(card.record.serialHex)), 'STS-PIV-0013',
            '4h. a piv-card-auth certificate does not sign in by default');
    config.setOverride('piv.cardAuthSignIn', true);
    t.check(piv.signInRefusal(card.record.serialHex) === null,
            '4i. and does with piv.cardAuthSignIn');
    config.clearOverride('piv.cardAuthSignIn');
  }
  t.check(piv.signInRefusal(serialHex) === null,
          '4j. a piv-auth certificate signs in');
  // X4: what the attestation said, recorded and handed to policy.
  const ev = tokens.evidenceFor('x509', serialHex);
  t.check(ev.pinPolicy === 'once' && ev.touchPolicy === 'always' &&
          ev.firmware === '5.4.3' && ev.formFactor === 'usb-c' &&
          ev.fips === false,
          '4k. the credential keeps the attested PIN and touch policy, the ' +
          'token its firmware and form factor', JSON.stringify(ev));
  const Authn = require('../authn/authn').Authn;
  const snap = Authn.hardwareTokenOf({ kind: 'certificate',
                                       serial: serialHex });
  const gate = require('../common/issuance_gate');
  const event = { authenticated: true, amr: ['hwk', 'sc'], acr: '1',
                  authority: { kind: 'local' },
                  context: { credential: { kind: 'certificate',
                                           hardwareToken: snap } } };
  const gated = gate.hardwareTokenFactsOf({ kind: gate.ISSUANCE.SESSION,
    authenticationEvent: event,
    subject: { kind: 'user', name: ALICE, authenticated: true } });
  t.check(snap && snap.touchPolicy === 'always' && gated.attested &&
          gated.pinPolicy === 'once' && gated.touchPolicy === 'always' &&
          gated.firmware === '5.4.3' && gated.formFactor === 'usb-c' &&
          gated.fips === undefined,
          '4l. the sign-in\'s snapshot and the gate\'s facts carry them, ' +
          'and FIPS only when true', JSON.stringify([snap, gated]));
  const H = require('../xacml/xacml_templates').HARDWARE_TOKEN_ATTRIBUTE;
  const rolePep = require('../xacml/xacml_role_pep');
  const text = JSON.stringify(rolePep.buildRequest({
    application: 'piv-app', kind: 'start-session',
    subject: { kind: 'user', name: ALICE, authenticated: true },
    hardwareToken: gated }, ['EVERYBODY'], [], ['EVERYBODY']));
  const fido = JSON.stringify(rolePep.buildRequest({
    application: 'piv-app', kind: 'start-session',
    subject: { kind: 'user', name: ALICE, authenticated: true },
    hardwareToken: { attested: true, key: 'yubico/1', status: 'active' } },
    ['EVERYBODY'], [], ['EVERYBODY']));
  t.check([H.PIN_POLICY, H.TOUCH_POLICY, H.FIRMWARE, H.FORM_FACTOR]
    .every(function (urn) {
      return text.indexOf(urn) >= 0;
    }) && text.indexOf(H.FIPS) < 0 &&
          [H.PIN_POLICY, H.TOUCH_POLICY].every(function (urn) {
            return fido.indexOf(urn) < 0;
          }),
          '4m. the PEP sends the PIN and touch policy, firmware and form ' +
          'factor of an attested PIV key, and none where the evidence said ' +
          'none');
  log.debug("Leaving checkIssuance().");
  return made;
}

async function checkEscrow(t, made) {
  log.debug("Entering checkEscrow().");
  t.log.info('=== 5. escrow ===');
  const server = await keyMaterial.generateKeyPair('rsa-2048');
  const spec = {
    family: 'est', profile: 'piv-key-management', principal: person(ALICE),
    target: { kind: 'person', id: ALICE }, publicKeyPem: server.publicPem,
    privateKeyPem: server.privatePem, requested: {}, keySource: 'server',
    keyAlg: 'rsa-2048', via: 'test' };
  config.setOverride('est.serverKeyGeneration', true);
  t.equal(code(await core.issue(spec)), 'STS-PIV-0021',
          '5a. a server-generated 9d key is refused while escrow is off');
  config.setOverride('piv.keyEscrow', true);
  const keystore = require('../common/keystore');
  if (!keystore.sealed()) {
    t.equal(code(await core.issue(spec)), 'STS-PIV-0020',
            '5b. escrow is refused with no key-encryption key to seal under');
    t.check(keystore.useEphemeralKek(nodeCrypto.randomBytes(32)
      .toString('hex')), 'precondition: a key-encryption key is installed');
  }
  const escrowed = await core.issue(spec);
  t.check(escrowed.ok && escrowed.record.escrowed === true &&
          escrowed.record.keySource === 'server',
          '5c. with escrow on the key is issued and kept, marked escrowed',
          JSON.stringify(escrowed.errors));
  if (!escrowed.ok) {
    log.debug("Leaving checkEscrow(). Not escrowed.");
    return;
  }
  const serialHex = escrowed.record.serialHex;
  t.check(pivEnrolment.escrowedOf(ALICE).some(function (r) {
    return r.serialHex === serialHex;
  }), '5d. it is listed among the person\'s escrowed certificates');
  t.equal(tokens.certificateAmr(serialHex).join(','), 'swk',
          '5e. an escrowed key is never hardware evidence');
  const mine = pivEnrolment.recover({ username: ALICE, actor: ALICE,
                                      door: 'portal', serialHex: serialHex });
  t.check(mine.ok && /PRIVATE KEY/.test(mine.privateKeyPem),
          '5f. the holder recovers their own escrowed key',
          JSON.stringify(mine.errors));
  t.equal(code(pivEnrolment.recover({ username: ALICE, actor: BOB,
                                      door: 'portal',
                                      serialHex: serialHex })),
          'STS-PIV-0022', '5g. the portal door is the holder\'s alone');
  t.equal(code(pivEnrolment.recover({ username: ALICE, actor: BOB,
                                      door: 'admin-api',
                                      serialHex: serialHex })),
          'STS-PIV-0023', '5h. an administrator the policy does not permit ' +
          '(no PIV_KEY_RECOVERY) cannot recover it');
  // THE POLICY'S ANSWER, read whole (`piv_enrolment.ts`): only a Permit
  // recovers. A gate of the test's own records what it was asked.
  const asked = [];
  const gateSaying = function (answer) {
    return Object.assign({}, require('../common/access_gate'), {
      deciderInstalled: function () {
        return true;
      },
      check: function (q) {
        asked.push(q);
        return answer;
      } });
  };
  const Cls = pivEnrolment.PivEnrolment;
  const withGate = function (answer) {
    return new Cls(Object.assign(Cls.defaultDeps(),
                                 { gate: gateSaying(answer) }));
  };
  const permitted = withGate({ allowed: true, decision: 'Permit' })
    .recover({ username: ALICE, actor: BOB, door: 'admin-api',
               serialHex: serialHex });
  t.check(permitted.ok && asked[0].resource === 'piv-key-escrow' &&
          asked[0].action === 'recover-key' &&
          asked[0].requiredRoles.join() === 'PIV_KEY_RECOVERY' &&
          asked[0].subject.name === BOB,
          '5h-ii. a Permit for PIV_KEY_RECOVERY on piv-key-escrow lets an ' +
          'administrator recover it', JSON.stringify(asked[0]));
  t.equal(code(withGate({ allowed: true, decision: 'NotApplicable' })
    .recover({ username: ALICE, actor: BOB, door: 'admin-api',
               serialHex: serialHex })), 'STS-PIV-0023',
          '5h-iii. "allowed" with no Permit (XACML off) does not');
  t.equal(code(withGate({ allowed: false, decision: 'Deny', why: 'no' })
    .recover({ username: ALICE, actor: BOB, door: 'admin-api',
               serialHex: serialHex })), 'STS-PIV-0023',
          '5h-iv. and a Deny does not');
  const roles = require('../common/roles');
  t.check(roles.rolesOf({ kind: 'user', name: BOB, authenticated: true,
                          groups: ['piv-key-recovery'] })
    .indexOf('PIV_KEY_RECOVERY') >= 0 &&
          roles.rolesOf({ kind: 'user', name: BOB, authenticated: true,
                          groups: [] }).indexOf('PIV_KEY_RECOVERY') < 0,
          '5h-v. PIV_KEY_RECOVERY is held through roles.pivKeyRecoveryGroup ' +
          'and only through it');
  // THE REAL BUILT-IN POLICY: the access PEP armed in this process, as
  // `xacml/xacml.ts` arms it at 23c (`tests/access_policy.js` does the
  // same), and BOB put in the group roles.pivKeyRecoveryGroup names.
  require('../xacml/xacml_access_pep');
  config.setOverride('xacml.enforceAccess', 'true');
  t.equal(code(pivEnrolment.recover({ username: ALICE, actor: BOB,
                                      door: 'admin-api',
                                      serialHex: serialHex })),
          'STS-PIV-0023', '5h-vi. the built-in policy refuses an ' +
          'administrator outside the group');
  ldap.createGroup('piv-key-recovery', {});
  const joined = ldap.addGroupMember('piv-key-recovery', BOB);
  const real = pivEnrolment.recover({ username: ALICE, actor: BOB,
                                      door: 'admin-api',
                                      serialHex: serialHex });
  t.check(real.ok && /PRIVATE KEY/.test(real.privateKeyPem),
          '5h-vii. and permits one holding PIV_KEY_RECOVERY through the ' +
          'group: the escrowed key is recovered', JSON.stringify(
            [joined && joined.ok, real.errors]));
  config.clearOverride('xacml.enforceAccess');
  // Attached to the YubiKey of section 4, then the YubiKey is lost.
  const key = 'yubico/' + made.serial;
  const attached = pivEnrolment.attach({ username: ALICE, actor: ALICE,
                                         serialHex: serialHex, key: key });
  t.check(attached.ok, '5i. the escrowed certificate is noted on the token',
          JSON.stringify(attached.errors));
  t.equal(code(pivEnrolment.attach({ username: BOB, actor: BOB,
                                     serialHex: serialHex, key: key })),
          'STS-PIV-0025', '5j. not by somebody else');
  const lost = await tokens.markLost({ key: key, actor: ALICE, via: 'test',
                                       onlyHolder: ALICE });
  t.check(lost.ok && lost.retired.some(function (r) {
    return r.ref === serialHex;
  }), '5k. reporting the token lost revokes the escrowed certificate',
          JSON.stringify(lost.notRetired || lost.errors));
  const after = pivEnrolment.recover({ username: ALICE, actor: ALICE,
                                       door: 'portal', serialHex: serialHex });
  t.check(after.ok && after.record.revoked === true,
          '5l. and the escrow is kept: the revoked certificate\'s key is ' +
          'still recovered', JSON.stringify(after.errors));
  log.debug("Leaving checkEscrow().");
}

async function checkOutsideCard(t) {
  log.debug("Entering checkOutsideCard().");
  t.log.info('=== 6. the outside PIV card ===');
  const uuid = nodeCrypto.randomUUID();
  const card = await pkivia.outsideCard({ uuids: [uuid],
    policies: [PIV_AUTH_POLICY], cn: BOB });
  const realmId = realms.currentId();
  t.check(piv.cardIdentityOf(card.leafDer, realmId) === null,
          '6a. with no outside issuer configured, nothing is mapped');
  config.setOverride('piv.externalIssuers', card.issuerPem);
  t.equal(piv.cardIdentityOf(card.leafDer, realmId).error, 'NOT_STORED',
          '6b. a UUID nobody holds names nobody');
  ldap.createUser(CAROL, { invent: false, attributes: {} });
  holdCardUuid(CAROL, uuid);
  const mapped = piv.cardIdentityOf(card.leafDer, realmId);
  t.check(mapped && mapped.accepted && mapped.username === CAROL,
          '6c. the card maps to the one person holding its UUID, and not ' +
          'to the person its CN names', JSON.stringify(mapped));
  const viaStore = tlsClient.storedIdentityOf(card.leafDer, realmId);
  t.check(viaStore.accepted && viaStore.username === CAROL &&
          viaStore.outside === true,
          '6c-ii. the sign-in doors\' stored-identity lookup answers the ' +
          'card\'s person when no entry stores the certificate',
          JSON.stringify(viaStore));
  ldap.createUser('piv-dave-' + RUN, { invent: false, attributes: {} });
  holdCardUuid('piv-dave-' + RUN, uuid);
  t.equal(piv.cardIdentityOf(card.leafDer, realmId).error, 'STORED_TWICE',
          '6d. a UUID two people hold names nobody');
  const noPolicy = await pkivia.outsideCard({ uuids: [uuid], policies: [] });
  config.setOverride('piv.externalIssuers', noPolicy.issuerPem);
  t.equal(piv.cardIdentityOf(noPolicy.leafDer, realmId).error, 'NOT_STORED',
          '6e. a card asserting no PIV Authentication policy is not mapped');
  const twoUuids = await pkivia.outsideCard({
    uuids: [uuid, nodeCrypto.randomUUID()], policies: [PIV_AUTH_POLICY] });
  config.setOverride('piv.externalIssuers', twoUuids.issuerPem);
  t.equal(piv.cardIdentityOf(twoUuids.leafDer, realmId).error, 'NOT_STORED',
          '6f. a card naming two UUIDs is not mapped');
  t.check(piv.cardIdentityOf(card.leafDer, realmId) === null,
          '6g. a card from an issuer not listed is not this mapping\'s');
  config.clearOverride('piv.externalIssuers');
  log.debug("Leaving checkOutsideCard().");
}

// 7. stsPivCardUuid ON EVERY WRITE: normalised, held to RFC 9562 and unique
// in the realm, through the console's editor (writePersonAttribute()) and a
// whole-entry write (putEntry(), which SCIM and the import use).
function checkCardUuidWrites(t) {
  log.debug("Entering checkCardUuidWrites().");
  t.log.info('=== 7. stsPivCardUuid writes ===');
  const editor = require('../ldap/person_editor');
  const uuid = nodeCrypto.randomUUID();
  const one = 'piv-erin-' + RUN;
  const two = 'piv-frank-' + RUN;
  ldap.createUser(one, { invent: false, attributes: {} });
  ldap.createUser(two, { invent: false, attributes: {} });
  const set = editor.update(one, { attribute: 'stsPivCardUuid', mode: 'set',
    value: 'URN:UUID:' + uuid.toUpperCase() }, { actor: 'test', via: 'test' });
  const stored = ldap.existingUserEntry(one);
  const held = ((stored && (stored.stored || stored).attributes) || {})
    .stspivcarduuid || [];
  t.check(set.ok && held.length === 1 && held[0] === uuid,
          '7a. the editor stores a card UUID normalised: prefix off, lower ' +
          'case', JSON.stringify([set.errors, held]));
  t.equal(code(editor.update(two, { attribute: 'stsPivCardUuid',
    mode: 'set', value: uuid }, { actor: 'test', via: 'test' })),
          'STS-PIV-0035', '7b. a second person given the same card UUID is ' +
          'refused');
  t.equal(code(editor.update(two, { attribute: 'stsPivCardUuid',
    mode: 'set', value: 'not-a-uuid' }, { actor: 'test', via: 'test' })),
          'STS-PIV-0034', '7c. a value that is no UUID is refused');
  t.equal(code(editor.update(two, { attribute: 'stsPivCardUuid',
    mode: 'set', value: '00000000-0000-0000-0000-000000000000' },
    { actor: 'test', via: 'test' })), 'STS-PIV-0034',
          '7d. the nil UUID names no card');
  const twoEntry = ldap.existingUserEntry(two);
  const dn = (twoEntry.stored || twoEntry).dn;
  const attrs = Object.assign({}, (twoEntry.stored || twoEntry).attributes,
                              { stspivcarduuid: [uuid] });
  t.equal(code(ldap.writePerson(dn, attrs)), 'STS-PIV-0035',
          '7e. a whole-entry write (SCIM, the import) holding it is refused ' +
          'too');
  t.check(editor.update(one, { attribute: 'stsPivCardUuid', mode: 'set',
    value: uuid }, { actor: 'test', via: 'test' }).ok,
          '7f. the holder writing their own value again is no conflict');
  log.debug("Leaving checkCardUuidWrites().");
}

async function run(t) {
  log.debug("Entering run().");
  try {
    if (!pki.hasRoot()) {
      await pki.start({});
    }
    await pki.ensureScope(realms.currentId());
    [ALICE, BOB].forEach(function (name) {
      ldap.createUser(name, { invent: false, attributes: {
        mail: name + '@example.com' } });
    });
    config.setOverride('est.allowedProfiles', 'tls-client,piv-auth,' +
                       'piv-sign,piv-key-management,piv-card-auth');
    const dev = await pkivia.device({});
    config.setOverride('piv.attestationAnchors', dev.rootPem);
    const first = await pkivia.slotKey(dev, {});
    checkExtensionsAndAnchors(t, dev, first);
    await checkCarriers(t, dev);
    await checkVerify(t, dev);
    const made = await checkIssuance(t, dev);
    if (made) {
      await checkEscrow(t, made);
    }
    await checkOutsideCard(t);
    checkCardUuidWrites(t);
  } finally {
    OVERRIDDEN.forEach(function (k) {
      config.clearOverride(k);
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'piv_attestation',
  describe: '#1955 P2: YubiKey PIV key attestation — the extensions, the ' +
            'carriers, verify and its refusals, the PIV slot profiles, ' +
            'escrow, and the outside card UUID mapping',
  run: run
};
