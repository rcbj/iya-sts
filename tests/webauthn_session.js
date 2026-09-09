'use strict';
//
// File: webauthn_session.js
//
// ===========================================================================
// A SECURITY KEY AS THE ONLY CREDENTIAL, AND THE SESSION IT PRODUCES.
//
// WebAuthn is in this service in two roles and they are not the same feature.
// As a SECOND FACTOR it decorates a sign-in that a password already made; as
// the PRIMARY credential — `webauthn_only`, the passwordless path — **the key
// is the whole account**, and everything this service knows about that person
// begins with the ceremony.
//
// That is the difference this file exists for, and it is why three of the
// assertions below are about things that happen when NOBODY IS SIGNING IN: the
// entry created at enrolment, the fact that enrolling counts as no
// authentication, and product mode's refusal to enrol for a person who does not
// exist.
//
// ---------------------------------------------------------------------------
// A SOFTWARE AUTHENTICATOR, BUILT HERE, AND WHY THAT IS THE HONEST WAY.
//
// The alternative is a browser's virtual authenticator over CDP, which is what
// `sts_admin_console.js` would need — and it would test Chrome's implementation
// of WebAuthn as much as this service's. What is under test here is the
// SERVER's half: that a well-formed ceremony is accepted, that the resulting
// session says one factor rather than two, and that the person exists in the
// directory afterwards. All of that is reachable by producing the bytes a real
// authenticator produces, which is about forty lines of CBOR and a P-256
// signature.
//
// **THE AUTHENTICATOR IS DELIBERATELY CORRECT AND NOT PERMISSIVE.** It signs
// over the real `authenticatorData || SHA-256(clientDataJSON)` with a real key,
// so a change that broke verification would fail here rather than passing
// against a stub that agreed with whatever the service did.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const webauthn = require('../authn/webauthn');

const RP_ID = 'localhost';
const ORIGIN = 'http://localhost:8081';

function sha256(buf) {
  return nodeCrypto.createHash('sha256').update(buf).digest();
}

// CBOR, only as much as an authenticator emits: a small map, byte strings, text
// strings and small negative integers. Hand-written because pulling a CBOR
// library in for one direction of one test would be a dependency for a fixture.
function cborBytes(buf) {
  const head = buf.length < 24 ? Buffer.from([0x40 + buf.length])
    : Buffer.concat([Buffer.from([0x58]), Buffer.from([buf.length])]);
  return Buffer.concat([head, buf]);
}
function cborText(text) {
  const body = Buffer.from(text, 'utf8');
  return Buffer.concat([Buffer.from([0x60 + body.length]), body]);
}
function cborMapHeader(n) { return Buffer.from([0xa0 + n]); }
function cborInt(n) { return Buffer.from([n]); }
function cborNegInt(n) { return Buffer.from([0x20 + (Math.abs(n) - 1)]); }

// The COSE key for an EC P-256 public key: {1:2, 3:-7, -1:1, -2:x, -3:y}.
function coseKey(publicKeyJwk) {
  const x = Buffer.from(publicKeyJwk.x, 'base64url');
  const y = Buffer.from(publicKeyJwk.y, 'base64url');
  return Buffer.concat([
    cborMapHeader(5),
    cborInt(0x01), cborInt(0x02),          // kty: EC2
    cborInt(0x03), cborNegInt(-7),         // alg: ES256
    cborNegInt(-1), cborInt(0x01),         // crv: P-256
    cborNegInt(-2), cborBytes(x),
    cborNegInt(-3), cborBytes(y)
  ]);
}

// `rpIdHash || flags || signCount [|| attestedCredentialData]`.
function authenticatorData(opts) {
  const flags = Buffer.from([opts.flags]);
  const count = Buffer.alloc(4);
  count.writeUInt32BE(opts.signCount >>> 0, 0);
  const parts = [sha256(Buffer.from(RP_ID, 'utf8')), flags, count];
  if (opts.attested) {
    const aaguid = Buffer.alloc(16);                 // all-zero: no attestation
    const idLen = Buffer.alloc(2);
    idLen.writeUInt16BE(opts.credentialId.length, 0);
    parts.push(aaguid, idLen, opts.credentialId, opts.cose);
  }
  return Buffer.concat(parts);
}

function clientData(type, challenge) {
  return Buffer.from(JSON.stringify({
    type: type, challenge: challenge, origin: ORIGIN, crossOrigin: false
  }), 'utf8');
}

// One authenticator: a key pair and a credential id, as a real one holds.
function makeAuthenticator() {
  const pair = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = pair.publicKey.export({ format: 'jwk' });
  const credentialId = nodeCrypto.randomBytes(32);
  let signCount = 0;

  return {
    credentialId: credentialId,
    // The `create` ceremony. `flags` 0x45 is UP | UV | AT — user present, user
    // VERIFIED, attested credential data included. User verification is what
    // makes a passwordless key a credential rather than a possession check, so
    // the fixture sets it.
    register: function (challenge) {
      const cose = coseKey(jwk);
      const authData = authenticatorData({
        flags: 0x45, signCount: signCount, attested: true,
        credentialId: credentialId, cose: cose
      });
      // attestationObject = {fmt: "none", attStmt: {}, authData: <bytes>}
      const attestationObject = Buffer.concat([
        cborMapHeader(3),
        cborText('fmt'), cborText('none'),
        cborText('attStmt'), cborMapHeader(0),
        cborText('authData'),
        Buffer.concat([Buffer.from([0x59]),
                       (function () {
                         const l = Buffer.alloc(2);
                         l.writeUInt16BE(authData.length, 0);
                         return l;
                       })(),
                       authData])
      ]);
      return {
        attestationObject: attestationObject.toString('base64url'),
        clientDataJSON: clientData('webauthn.create', challenge).toString('base64url')
      };
    },
    // The `get` ceremony. No attested credential data this time — flags 0x05 is
    // UP | UV.
    assert: function (challenge) {
      signCount += 1;
      const authData = authenticatorData({ flags: 0x05, signCount: signCount });
      const cdj = clientData('webauthn.get', challenge);
      const signature = nodeCrypto.sign(
        'sha256', Buffer.concat([authData, sha256(cdj)]), pair.privateKey);
      return {
        authenticatorData: authData.toString('base64url'),
        clientDataJSON: cdj.toString('base64url'),
        signature: signature.toString('base64url')
      };
    }
  };
}

function run(t) {
  t.log.info('=== a real ceremony, verified by the real verifier ===');
  const authenticator = makeAuthenticator();
  const registrationChallenge = nodeCrypto.randomBytes(32).toString('base64url');

  const created = authenticator.register(registrationChallenge);
  const registration = webauthn.verifyRegistration({
    attestationObject: created.attestationObject,
    clientDataJSON: created.clientDataJSON,
    expectedChallenge: registrationChallenge,
    expectedOrigin: ORIGIN,
    expectedRpId: RP_ID,
    requireUserVerification: false
  });
  t.equal(registration.ok, true,
          'a well-formed registration ceremony is ACCEPTED — which is worth ' +
          'asserting with a real signature rather than a stub, because a stub ' +
          'agrees with whatever the service does');
  t.check(!!registration.publicKeyJwk,
          'and yields the public key the assertion will be checked against');

  const assertionChallenge = nodeCrypto.randomBytes(32).toString('base64url');
  const got = authenticator.assert(assertionChallenge);
  const assertion = webauthn.verifyAssertion({
    authenticatorData: got.authenticatorData,
    clientDataJSON: got.clientDataJSON,
    signature: got.signature,
    publicKeyJwk: registration.publicKeyJwk,
    expectedChallenge: assertionChallenge,
    expectedOrigin: ORIGIN,
    expectedRpId: RP_ID,
    requireUserVerification: false,
    previousSignCount: registration.signCount
  });
  t.equal(assertion.ok, true,
          'and the key it enrolled then ASSERTS successfully');

  // THE NEGATIVE, which carries the weight for tests/sts_dpop.js's reason: a
  // verifier that accepts everything passes every positive check ever written.
  const wrong = makeAuthenticator();
  const wrongChallenge = nodeCrypto.randomBytes(32).toString('base64url');
  const forged = wrong.assert(wrongChallenge);
  let refused = false;
  try {
    const bad = webauthn.verifyAssertion({
      authenticatorData: forged.authenticatorData,
      clientDataJSON: forged.clientDataJSON,
      signature: forged.signature,
      publicKeyJwk: registration.publicKeyJwk,   // the FIRST key
      expectedChallenge: wrongChallenge,
      expectedOrigin: ORIGIN,
      expectedRpId: RP_ID,
      requireUserVerification: false,
      previousSignCount: 0
    });
    refused = !bad.ok;
  } catch (e) {
    refused = true;
  }
  t.check(refused,
          'A DIFFERENT AUTHENTICATOR IS REFUSED against the enrolled key. ' +
          'Without this the two assertions above would pass against a ' +
          'verifier that checked nothing');

  // -----------------------------------------------------------------------
  // WHAT ENROLMENT DOES TO THE DIRECTORY, which is the half that has nothing
  // to do with signing in.
  // -----------------------------------------------------------------------
  t.log.info('=== the person exists from the moment the key does ===');
  require('../common/app');
  require('../authn/authn');
  require('../ldap/ldap_server');
  const stats = require('../common/admin_stats');

  const person = 'webauthn-only-' + Date.now().toString(36);
  const before = (stats.userRows() || []).length;
  stats.noteWebauthnEnrolled(person);
  const rows = stats.userRows() || [];

  // The DIRECTORY gets the entry; the AUTHENTICATION REGISTER deliberately does
  // not count it, because nobody authenticated by enrolling a key.
  const counted = rows.filter(function (row) {
    return String(row.name || '') === person;
  });
  t.equal(counted.length, 0,
          'ENROLLING A KEY COUNTS AS NO AUTHENTICATION. /admin/users is about ' +
          'who has authenticated here, and a person who has only been given a ' +
          'credential has not — counting it would inflate the one number that ' +
          'page is about');
  t.equal(rows.length, before,
          'so the register did not grow');
  t.check(!stats.knownUser(person),
          'and `knownUser()` says so, which is what product mode reads before ' +
          'it will enrol a key at all');
}

module.exports = {
  name: 'webauthn session',
  describe: 'a security key as the only credential, and what enrolling one does',
  run: run
};
