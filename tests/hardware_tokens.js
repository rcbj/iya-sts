// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: hardware_tokens.js
//
// ---------------------------------------------------------------------------
// THE HARDWARE TOKEN REGISTER (#1955 P1), in process.
//
//   1. THE ONE WRITER: a serial from anything but attestation is refused, and
//      so is one with no serial, an unknown credential kind and a person with
//      no entry; an attested one is recorded, and a second credential on the
//      same physical token joins the same record.
//   2. THE ATTESTATION WIRING: a passkey written by `credentials.addKey()`
//      whose trusted enterprise attestation named a serial makes a token, one
//      without a serial makes none, and removing the passkey drops it from
//      the record.
//   3. THE LOST-KEY ACT: the token is marked lost, its passkey is removed
//      even when it was the person's only way in, a certificate on it is
//      handed to the x509 retirer, a kind with no retirer is reported as not
//      retired, a second report is refused, and the portal's `onlyHolder`
//      cannot reach another person's token.
//   4. X3: a synthetic PIV evidence row earns `hwk` and `sc` for a
//      certificate sign-in, a lost token earns nothing, the PKINIT inference
//      follows `hardwareTokens.hardwareClaims`, and the KDC's
//      `pkinit-smartcard` indicator becomes `sc`.
//   5. REALM ISOLATION: a token recorded in one realm is unknown to another.
//
// The over-HTTP half — `/admin-api/hardware-tokens` and the account API's
// `/account-api/tokens` — is `tests/protocol/sts_hardware_tokens.js`.
// ---------------------------------------------------------------------------

const config = require('../common/config');
const realms = require('../common/realms');
const ldap = require('../ldap/ldap_server');
const credentials = require('../common/credentials');
const tokens = require('../common/hardware_tokens');
const errorCodes = require('../common/error_codes');
const krb5Tokens = require('../kerberos/krb5_tokens');
const mechanisms = require('../common/authn_mechanisms');
const gate = require('../common/issuance_gate');
const templates = require('../xacml/xacml_templates');
const rolePep = require('../xacml/xacml_role_pep');
const kit = require('./webauthn_attestation_kit');

const log = require('bunyan').createLogger({ name: 'hardware_tokens',
  level: process.env.LOG_LEVEL || 'info' });

const RUN = Date.now().toString(36);
const ALICE = 'hwt-alice-' + RUN;
const BOB = 'hwt-bob-' + RUN;
const SERIAL = String(10000000 + (Date.now() % 80000000));
const CAROL = 'hwt-carol-' + RUN;
const OVERRIDDEN = ['hardwareTokens.hardwareClaims', 'global.mode'];

function code(answer) {
  log.debug("Entering code().");
  log.debug("Leaving code().");
  return errorCodes.codeOf(answer) || '';
}

// A passkey record as the registration ceremony writes it, its attestation
// the enterprise one #532 reads a serial from.
async function attestedKey(serial) {
  log.debug("Entering attestedKey().");
  const cred = await kit.credential(-7);
  const attestation = { verified: true, trusted: true, format: 'packed',
    type: 'basic', anchor: 'configured', checkedAt: Date.now(),
    conveyance: 'enterprise', model: 'YubiKey 5 NFC',
    aaguid: '2fc0579f-8113-47ea-b116-bb5a8db9202a' };
  if (serial) {
    attestation.deviceSerial = serial;
    attestation.deviceSerialSource = 'yubico-extension';
  }
  log.debug("Leaving attestedKey().");
  return { credentialId: cred.id.toString('base64url'),
           publicKeyJwk: cred.pair.publicKey.export({ format: 'jwk' }),
           signCount: 0, label: 'work key', attachment: 'cross-platform',
           aaguid: attestation.aaguid, transports: ['usb', 'nfc'],
           attestation: attestation };
}

function checkWriter(t) {
  log.debug("Entering checkWriter().");
  t.log.info('=== 1. the one writer ===');
  const base = { username: ALICE, vendor: 'Yubico AB', serial: 'w-' + RUN,
                 credential: { kind: 'fido', ref: 'cred-w-' + RUN } };
  t.equal(code(tokens.recordAttested(Object.assign({}, base, {
    evidence: { source: 'self-declared' } }))), 'STS-HWTOKEN-0001',
          '1a. a serial from anything but attestation is refused');
  t.equal(code(tokens.recordAttested(Object.assign({}, base, {
    serial: '', evidence: { source: 'fido-enterprise-attestation' } }))),
          'STS-HWTOKEN-0002', '1b. no serial is refused');
  t.equal(code(tokens.recordAttested(Object.assign({}, base, {
    credential: { kind: 'telepathy', ref: 'x' },
    evidence: { source: 'fido-enterprise-attestation' } }))),
          'STS-HWTOKEN-0003', '1c. an unknown credential kind is refused');
  t.equal(code(tokens.recordAttested(Object.assign({}, base, {
    username: 'nobody-' + RUN,
    evidence: { source: 'fido-enterprise-attestation' } }))),
          'STS-HWTOKEN-0004', '1d. a person with no entry is refused');
  const made = tokens.recordAttested(Object.assign({}, base, {
    evidence: { source: 'fido-enterprise-attestation' } }));
  t.check(made.ok && made.created && made.token.key === 'yubico/w-' + RUN &&
          made.token.holder === ALICE && made.token.attested,
          '1e. an attested serial is recorded, the vendor read as yubico',
          JSON.stringify(made));
  const again = tokens.recordAttested(Object.assign({}, base, {
    credential: { kind: 'x509', ref: '00:AB:CD' },
    evidence: { source: 'piv-attestation', smartCard: true } }));
  t.check(again.ok && !again.created &&
          again.token.credentials.length === 2 &&
          again.token.credentials[1].ref === 'abcd',
          '1f. a second credential joins the same token, a certificate ' +
          'serial normalised to lower-case hex', JSON.stringify(again));
  log.debug("Leaving checkWriter().");
  return made.token.key;
}

async function checkWiring(t) {
  log.debug("Entering checkWiring().");
  t.log.info('=== 2. the attestation wiring ===');
  const key = await attestedKey(SERIAL);
  const stored = credentials.addKey(ALICE, key);
  t.check(stored && stored.ok !== false, 'precondition: the passkey is ' +
          'written', JSON.stringify(stored));
  const token = tokens.byKey('yubico/' + SERIAL);
  t.check(!!token && token.holder === ALICE && token.model ===
          'YubiKey 5 NFC' && token.credentials.some(function (c) {
            return c.kind === 'fido' && c.ref === key.credentialId &&
                   c.source === 'fido-enterprise-attestation';
          }), '2a. an enterprise-attested passkey naming a serial makes a ' +
          'token', JSON.stringify(token));
  const plain = await attestedKey('');
  credentials.addKey(ALICE, plain);
  t.check(!tokens.evidenceFor('fido', plain.credentialId).token,
          '2b. a passkey whose attestation names no serial makes none');
  const mine = await tokens.tokensOf(ALICE);
  t.check(mine.some(function (one) {
    return one.key === 'yubico/' + SERIAL;
  }), '2c. the person\'s tokens are found through the holder index',
          JSON.stringify(mine.map(function (one) { return one.key; })));
  const removed = credentials.removeKey(ALICE, plain.credentialId);
  t.check(removed.ok, 'precondition: a passkey can be removed',
          JSON.stringify(removed));
  // A key on a token, removed by the ordinary door: the token drops it.
  const second = await attestedKey(SERIAL);
  credentials.addKey(ALICE, second);
  credentials.removeKey(ALICE, second.credentialId);
  t.check(!tokens.byKey('yubico/' + SERIAL).credentials.some(function (c) {
    return c.ref === second.credentialId;
  }), '2d. a passkey removed by another door leaves the token\'s record');
  log.debug("Leaving checkWiring().");
  return key;
}

async function checkLost(t, key) {
  log.debug("Entering checkLost().");
  t.log.info('=== 3. the lost-key act ===');
  const tokenKey = 'yubico/' + SERIAL;
  // A certificate and a kind with no retirer on the same token.
  tokens.recordAttested({ username: ALICE, vendor: 'yubico', serial: SERIAL,
    credential: { kind: 'x509', ref: 'beef01' },
    evidence: { source: 'piv-attestation' } });
  tokens.recordAttested({ username: ALICE, vendor: 'yubico', serial: SERIAL,
    credential: { kind: 'openpgp', ref: 'pgp-' + RUN },
    evidence: { source: 'vendor-import' } });
  const revoked = [];
  const Cls = tokens.HardwareTokens;
  const own = new Cls(Object.assign(Cls.defaultDeps(), {
    loadEnrollment: function () {
      return { revokeEnrolled: function (serial, reason) {
        revoked.push(serial + ':' + reason);
        return Promise.resolve({ ok: true });
      } };
    }
  }));
  t.equal(code(await own.markLost({ key: tokenKey, actor: BOB, via: 'portal',
                                    onlyHolder: BOB })),
          'STS-HWTOKEN-0005', '3a. the portal cannot reach another ' +
          'person\'s token');
  const before = credentials.keysOf(ALICE).length;
  const done = await own.markLost({ key: tokenKey, actor: 'admin-' + RUN,
                                    via: 'api', initiatingEntity: 'admin' });
  t.check(done.ok && done.token.status === 'lost',
          '3b. the token is marked lost', JSON.stringify(done));
  t.check(!credentials.keysOf(ALICE).some(function (k) {
    return k.credentialId === key.credentialId;
  }) && credentials.keysOf(ALICE).length === before - 1,
          '3c. its passkey is removed, though it was the person\'s only ' +
          'way in', String(credentials.keysOf(ALICE).length));
  t.check(revoked.length === 1 && revoked[0] === 'beef01:keyCompromise',
          '3d. its certificate is handed to the x509 retirer for ' +
          'keyCompromise', JSON.stringify(revoked));
  t.check((done.notRetired || []).some(function (r) {
    return r.kind === 'openpgp' && r.errorCode === 'STS-HWTOKEN-0009';
  }), '3e. a kind with no retirer is reported as NOT retired',
          JSON.stringify(done.notRetired));
  t.equal(code(await own.markLost({ key: tokenKey, actor: 'admin-' + RUN })),
          'STS-HWTOKEN-0006', '3f. a second report is refused');
  t.check(!own.registerRetirer('telepathy', { label: 'x',
                                              retire: function () {} }) &&
          !own.registerRetirer('hotp', { retire: function () {} }) &&
          own.registerRetirer('hotp', { label: 'HOTP secret',
                                        retire: function () {
                                          return { ok: true };
                                        } }),
          '3g. a retirer is validated whole at installation');
  log.debug("Leaving checkLost().");
}

function checkClaims(t, writerKey) {
  log.debug("Entering checkClaims().");
  t.log.info('=== 4. evidence-based hwk and sc ===');
  t.equal(tokens.certificateAmr('ABCD').join(','), 'hwk,sc',
          '4a. a certificate a PIV evidence row covers, on a card, earns ' +
          'hwk and sc');
  t.equal(tokens.certificateAmr('beef01').join(','), 'swk',
          '4b. a certificate on a LOST token earns swk');
  t.equal(tokens.certificateAmr('0123456789').join(','), 'swk',
          '4c. a certificate with no evidence earns swk, as before');
  t.check(tokens.inferenceAllowed(), '4d. the PKINIT inference stands by ' +
          'default (hardwareTokens.hardwareClaims inference)');
  config.setOverride('hardwareTokens.hardwareClaims', 'evidence');
  t.check(!tokens.inferenceAllowed(), '4e. and not under evidence');
  config.clearOverride('hardwareTokens.hardwareClaims');
  const f = krb5Tokens.factorsFor(['hw-authent'],
    ['pkinit', 'pkinit-hardware', 'pkinit-smartcard'], true);
  const g = krb5Tokens.factorsFor(['hw-authent'],
    ['pkinit', 'pkinit-hardware'], true);
  t.check(f.amr.indexOf('sc') >= 0 && f.amr.indexOf('hwk') >= 0 &&
          g.amr.indexOf('sc') < 0,
          '4f. the KDC\'s pkinit-smartcard indicator becomes sc, and only ' +
          'it', JSON.stringify([f.amr, g.amr]));
  t.check(!!writerKey, 'precondition: the writer\'s token exists');
  log.debug("Leaving checkClaims().");
}

// 6. X4: what an authentication on a token says to policy — the event's
// snapshot, the `attested-hardware` mechanism, the gate's facts brought up
// to date against the register, and the PEP's attributes.
async function checkPolicyFacts(t) {
  log.debug("Entering checkPolicyFacts().");
  t.log.info('=== 6. X4: the token as policy facts ===');
  const serial = 'pf-' + RUN;
  const key = await attestedKey(serial);
  credentials.addKey(CAROL, key);
  const Authn = require('../authn/authn').Authn;
  const snap = Authn.hardwareTokenOf({ kind: 'webauthn',
                                       id: key.credentialId });
  t.check(!!snap && snap.key === 'yubico/' + serial &&
          snap.model === 'YubiKey 5 NFC' &&
          snap.source === 'fido-enterprise-attestation',
          '6a. a sign-in\'s credential on a token records a snapshot of it',
          JSON.stringify(snap));
  t.check(Authn.hardwareTokenOf({ kind: 'webauthn', id: 'nope' }) === null &&
          Authn.hardwareTokenOf({ kind: 'certificate', id: 'x' }) === null,
          '6b. and nothing for a credential no token lists');
  const event = { authenticated: true, amr: ['hwk'], acr: '1',
                  authority: { kind: 'local' },
                  context: { credential: { kind: 'webauthn',
                                           hardwareToken: snap } } };
  const plain = { authenticated: true, amr: ['hwk'], acr: '1',
                  authority: { kind: 'local' },
                  context: { credential: { kind: 'webauthn' } } };
  t.check(mechanisms.ofEvent(event).join(',') ===
          'webauthn,attested-hardware' &&
          mechanisms.ofEvent(plain).join(',') === 'webauthn',
          '6c. the event satisfies attested-hardware beside webauthn, and ' +
          'a key on no token only webauthn',
          JSON.stringify([mechanisms.ofEvent(event),
                          mechanisms.ofEvent(plain)]));
  const asked = function (who, ev) {
    return { kind: gate.ISSUANCE.SESSION, authenticationEvent: ev,
             subject: { kind: 'user', name: who, authenticated: true } };
  };
  const mine = gate.hardwareTokenFactsOf(asked(CAROL, event));
  const theirs = gate.hardwareTokenFactsOf(asked(BOB, event));
  const none = gate.hardwareTokenFactsOf(asked(CAROL, plain));
  t.check(mine.attested === true && mine.holderMatches === true &&
          mine.status === 'active' && theirs.holderMatches === false &&
          none.attested === false && !none.key,
          '6d. the gate\'s facts: attested and held by the subject, not ' +
          'held by another, and attested false with no token',
          JSON.stringify([mine, theirs, none]));
  t.check(gate.hardwareTokenFactsOf(Object.assign(asked(CAROL, event),
    { kind: gate.ISSUANCE.WSTRUST_TOKEN })) === null,
          '6e. nothing for an issuance that is not a browser sign-in');
  const H = templates.HARDWARE_TOKEN_ATTRIBUTE;
  const text = JSON.stringify(rolePep.buildRequest({
    application: 'hwt-app', kind: 'start-session',
    subject: { kind: 'user', name: CAROL, authenticated: true },
    hardwareToken: mine }, ['EVERYBODY'], [], ['EVERYBODY']));
  const bare = JSON.stringify(rolePep.buildRequest({
    application: 'hwt-app', kind: 'start-session',
    subject: { kind: 'user', name: CAROL, authenticated: true },
    hardwareToken: { attested: false } }, ['EVERYBODY'], [],
    ['EVERYBODY']));
  t.check([H.ATTESTED, H.KEY, H.VENDOR, H.MODEL, H.EVIDENCE, H.SMART_CARD,
           H.HOLDER_MATCHES, H.STATUS].every(function (urn) {
    return text.indexOf(urn) >= 0;
  }) && text.indexOf('YubiKey 5 NFC') >= 0 &&
          bare.indexOf(H.ATTESTED) >= 0 && bare.indexOf(H.MODEL) < 0,
          '6f. the PEP sends every hardware-token attribute for a token, ' +
          'and only ATTESTED without one');
  // 7. THE RECOVERY THE LOSS OWES (#724): Carol's only passkey is on it.
  config.setOverride('global.mode', 'product');
  const lost = await tokens.markLost({ key: 'yubico/' + serial,
    actor: CAROL, via: 'portal', onlyHolder: CAROL });
  const pending = credentials.recoveryPending(CAROL);
  t.check(lost.ok && (lost.recoveryNoted || []).indexOf(CAROL) >= 0 &&
          pending && pending.door === 'lost-key',
          '7a. a person whose every passkey was on the lost token is ' +
          'handed to the recovery path: a lost-key recovery is pending',
          JSON.stringify([lost.recoveryNoted, pending]));
  t.check(credentials.keysOf(CAROL).length === 0 &&
          credentials.holdsPasskey(CAROL) === true,
          '7b. with the key gone they are still covered by the passkey ' +
          'policy while the recovery is pending');
  credentials.setRecoveryPending(CAROL, 'password-reset');
  t.equal((credentials.recoveryPending(CAROL) || {}).door, 'lost-key',
          '7c. a later door\'s recovery does not replace the loss');
  credentials.setRecoveryPending(CAROL, '');
  t.check(!credentials.recoveryPending(CAROL) &&
          credentials.holdsPasskey(CAROL) === false,
          '7d. a passkey signing them in clears it, and the cover with it');
  t.check(gate.hardwareTokenFactsOf(asked(CAROL, event)).attested === false,
          '7e. a token reported lost since the sign-in is no longer attested');
  config.clearOverride('global.mode');
  log.debug("Leaving checkPolicyFacts().");
}

function checkIsolation(t, writerKey) {
  log.debug("Entering checkIsolation().");
  t.log.info('=== 5. realm isolation ===');
  const id = 'hwt-' + RUN;
  const made = realms.create({ id: id, name: id,
                               description: 'Created by ' + __filename });
  if (!made.ok) {
    t.bad('could not create the realm "' + id + '"',
          (made.errors || []).join(' '));
    log.debug("Leaving checkIsolation().");
    return;
  }
  try {
    const seen = realms.run(made.realm, function () {
      return { token: tokens.byKey(writerKey),
               evidence: tokens.evidenceFor('x509', 'abcd') };
    });
    t.check(seen.token === null && !seen.evidence.hardware,
            '5a. a token recorded in one realm is unknown to another',
            JSON.stringify(seen));
  } finally {
    realms.remove(id);
  }
  t.check(!!tokens.byKey(writerKey), '5b. and still known in its own');
  log.debug("Leaving checkIsolation().");
}

async function run(t) {
  log.debug("Entering run().");
  try {
    [ALICE, BOB, CAROL].forEach(function (name) {
      ldap.createUser(name, { invent: false, attributes: {} });
    });
    const writerKey = checkWriter(t);
    const key = await checkWiring(t);
    await checkLost(t, key);
    checkClaims(t, writerKey);
    await checkPolicyFacts(t);
    checkIsolation(t, writerKey);
  } finally {
    OVERRIDDEN.forEach(function (k) {
      config.clearOverride(k);
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'hardware_tokens',
  describe: '#1955 P1: the hardware token register — the attestation-only ' +
            'writer, the FIDO wiring, the lost-key fan-out by kind, ' +
            'evidence-based hwk/sc and realm isolation',
  run: run
};
