'use strict';
//
// File: device_enrolment.js
//
// ===========================================================================
// #164 PHASE 2, IN PROCESS: A DEVICE REGISTERED BY PROVING A KEY, ITS
// ATTESTATION, AND WHICH DEVICE A REQUEST CAME FROM.
//
//   1. THE CHALLENGE: bound to the session and the person, answered once
//      (a replay refused), expired after devices.challengeTtlSeconds, one
//      per session and purpose.
//   2. A JWK PROOF with no attestation: registered self-asserted in
//      development, REFUSED in product (STS-DEVICE-0024); a wrong nonce,
//      aud or typ refused (STS-DEVICE-0017).
//   3. ANDROID KEY ATTESTATION built here: attested against a configured
//      test root; a software key, a foreign challenge refused
//      (STS-DEVICE-0018); a chain to no configured root self-asserted.
//   4. APPLE APP ATTEST built here: attested; an app not configured refused
//      (STS-DEVICE-0019).
//   5. A LINKED WEBAUTHN PLATFORM CREDENTIAL: a fresh assertion links it,
//      attested because its registration attestation was trusted; a
//      roaming key and a bad signature refused (STS-DEVICE-0022).
//   6. EST AND SCEP, THE `device` PROFILE, with a TPM key attestation in the
//      request (draft-ietf-lamps-csr-attestation, tcg-attest-tpm-certify):
//      a new device made and certified, attested; a renewal over the same
//      key replaces the key; the identity rule (STS-DEVICE-0023); ACME, a
//      server key and a re-enrolment refused (STS-DEVICE-0025); a spoiled
//      statement refused (STS-DEVICE-0020); two attributes refused
//      (STS-DEVICE-0021); product refuses no attestation (STS-DEVICE-0024).
//   7. RECOGNITION by each of the four ways — x509 (and a revoked
//      certificate not), webauthn, jwk (a DPoP jkt), native-sso — a
//      compromised device still recognised, the last use moved, and the
//      counters Monitoring → Devices draws.
//
// **EVERY KEY, CERTIFICATE AND ROOT IS MADE HERE, AT RUN TIME** (rcbj: no
// key material in git), with `webauthn_attestation_kit.js`'s builders.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const asn1js = require('asn1js');
const pkijs = require('pkijs');
const config = require('../common/config');
const realms = require('../common/realms');
const pki = require('../common/pki');
const ldap = require('../ldap/ldap_server');
const credentials = require('../common/credentials');
const devices = require('../common/devices');
const enrolment = require('../common/device_enrolment');
const recognition = require('../common/device_recognition');
const stsCrypto = require('../common/crypto');
const errorCodes = require('../common/error_codes');
const core = require('../common/cert_enrollment');
const kit = require('./webauthn_attestation_kit');

const log = require('bunyan').createLogger({ name: 'device_enrolment',
  level: process.env.LOG_LEVEL || 'info' });

const RUN = nodeCrypto.randomBytes(3).toString('hex');
const ALICE = 'de-alice-' + RUN;
const BOB = 'de-bob-' + RUN;
const ADMIN = 'de-admin-' + RUN;
const AUD = 'https://sts.test/portal/devices';
const APP_ID = 'TEAM123456.com.example.devices';
const OVERRIDDEN = ['global.mode', 'devices.androidAttestationTrustAnchors',
                    'devices.appleAppAttestTrustAnchors',
                    'devices.appleAppAttestAppIds', 'devices.tpmTrustAnchors',
                    'devices.lastUsedResolutionSeconds'];

function code(result) {
  log.debug("Entering code().");
  log.debug("Leaving code().");
  return errorCodes.codeOf(result) || '';
}

function set(key, value) {
  log.debug("Entering set(). " + key);
  const done = config.setOverride(key, value);
  if (done && done.ok === false) {
    throw new Error('could not set ' + key + ': ' + JSON.stringify(done));
  }
  log.debug("Leaving set().");
}

function b64u(value) {
  log.debug("Entering b64u().");
  log.debug("Leaving b64u().");
  return Buffer.from(typeof value === 'string' ? value : JSON.stringify(value))
    .toString('base64url');
}

function sha256(data) {
  log.debug("Entering sha256().");
  log.debug("Leaving sha256().");
  return nodeCrypto.createHash('sha256').update(data).digest();
}

// A compact ES256 JWS built by hand: a test must not lean on the signer the
// verifier shares a module with.
function es256(header, payload, privateKey) {
  log.debug("Entering es256().");
  const input = b64u(header) + '.' + b64u(payload);
  const sig = nodeCrypto.sign('sha256', Buffer.from(input), {
    key: privateKey, dsaEncoding: 'ieee-p1363' });
  log.debug("Leaving es256().");
  return input + '.' + sig.toString('base64url');
}

function ecPair() {
  log.debug("Entering ecPair().");
  const pair = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  log.debug("Leaving ecPair().");
  return { privateKey: pair.privateKey, publicKey: pair.publicKey,
           jwk: pair.publicKey.export({ format: 'jwk' }) };
}

// A key proof over `challenge`, optionally with `x5c`.
function proof(pair, challenge, opts) {
  log.debug("Entering proof().");
  const o = opts || {};
  const header = { alg: 'ES256', typ: o.typ || 'device-key-proof+jwt',
                   jwk: pair.jwk };
  if (o.x5c) {
    header.x5c = o.x5c;
  }
  log.debug("Leaving proof().");
  return es256(header, { nonce: o.nonce || challenge, aud: o.aud || AUD,
                         iat: Math.floor(Date.now() / 1000) },
               pair.privateKey);
}

function extension(oid, der, critical) {
  log.debug("Entering extension().");
  log.debug("Leaving extension().");
  return new pkijs.Extension({ extnID: oid, critical: !!critical,
    extnValue: new Uint8Array(Buffer.from(der)).buffer });
}

// Android's KeyDescription with `challenge` and a security level.
function keyDescription(challenge, level) {
  log.debug("Entering keyDescription().");
  const list = function (hardware) {
    log.debug("Entering list().");
    log.debug("Leaving list().");
    return new asn1js.Sequence({ value: hardware ? [
      new asn1js.Constructed({ idBlock: { tagClass: 3, tagNumber: 1 },
        value: [new asn1js.Set({ value: [new asn1js.Integer({ value: 2 })]
        })] }),
      new asn1js.Constructed({ idBlock: { tagClass: 3, tagNumber: 702 },
        value: [new asn1js.Integer({ value: 0 })] })] : [] });
  };
  log.debug("Leaving keyDescription().");
  return Buffer.from(new asn1js.Sequence({ value: [
    new asn1js.Integer({ value: 300 }), new asn1js.Enumerated({ value: level }),
    new asn1js.Integer({ value: 300 }), new asn1js.Enumerated({ value: level }),
    new asn1js.OctetString({ valueHex: new Uint8Array(
      Buffer.from(challenge, 'utf8')).buffer }),
    new asn1js.OctetString({ valueHex: new ArrayBuffer(0) }),
    list(false), list(true)] }).toBER(false));
}

// An Android attestation leaf certifying `pair`, under `anchor`.
async function androidLeaf(pair, challenge, anchor, level) {
  log.debug("Entering androidLeaf().");
  const cryptoKey = await nodeCrypto.webcrypto.subtle.importKey('jwk',
    pair.jwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
  const leaf = await kit.certificate({
    subject: [['2.5.4.3', 'Android Keystore Key']], publicKey: cryptoKey,
    issuer: anchor, ca: false,
    extensions: [extension('1.3.6.1.4.1.11129.2.1.17',
                           keyDescription(challenge, level))] });
  log.debug("Leaving androidLeaf().");
  return leaf;
}

// An Apple App Attest attestation object for a fresh P-256 key.
async function appAttestObject(challenge, anchor, appId) {
  log.debug("Entering appAttestObject().");
  const pair = await kit.keyPair('ec');
  const jwk = pair.publicKey.export({ format: 'jwk' });
  const point = Buffer.concat([Buffer.from([4]),
                               Buffer.from(jwk.x, 'base64url'),
                               Buffer.from(jwk.y, 'base64url')]);
  const keyId = sha256(point);
  const count = Buffer.alloc(4);
  const idLength = Buffer.alloc(2);
  idLength.writeUInt16BE(keyId.length, 0);
  const cose = new Map([[1, 2], [3, -7], [-1, 1],
                        [-2, Buffer.from(jwk.x, 'base64url')],
                        [-3, Buffer.from(jwk.y, 'base64url')]]);
  const authData = Buffer.concat([sha256(Buffer.from(appId, 'utf8')),
    Buffer.from([0x40]), count,
    Buffer.concat([Buffer.from('appattest'), Buffer.alloc(7)]), idLength,
    keyId, kit.cbor(cose)]);
  const nonce = sha256(Buffer.concat([authData,
                                      sha256(Buffer.from(challenge))]));
  const nonceExt = new asn1js.Sequence({ value: [new asn1js.Constructed({
    idBlock: { tagClass: 3, tagNumber: 1 },
    value: [new asn1js.OctetString({
      valueHex: new Uint8Array(nonce).buffer })] })] }).toBER(false);
  const leaf = await kit.certificate({
    subject: [['2.5.4.3', 'Synthetic App Attest key']],
    publicKey: pair.crypto.publicKey, issuer: anchor, ca: false,
    extensions: [extension('1.2.840.113635.100.8.2', Buffer.from(nonceExt))]
  });
  const object = kit.cbor(new Map([
    ['fmt', 'apple-appattest'],
    ['attStmt', new Map([['x5c', [leaf.der, anchor.der]],
                         ['receipt', Buffer.from('a receipt')]])],
    ['authData', authData]]));
  log.debug("Leaving appAttestObject().");
  return { keyId: keyId.toString('base64'),
           attestation: object.toString('base64'), jwk: jwk };
}

function u16(n) {
  log.debug("Entering u16().");
  const b = Buffer.alloc(2);
  b.writeUInt16BE(n, 0);
  log.debug("Leaving u16().");
  return b;
}

function u32(n) {
  log.debug("Entering u32().");
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0, 0);
  log.debug("Leaving u32().");
  return b;
}

function tpm2b(bytes) {
  log.debug("Entering tpm2b().");
  log.debug("Leaving tpm2b().");
  return Buffer.concat([u16(bytes.length), Buffer.from(bytes)]);
}

// A TPM key attestation (TPM2_Certify) of an EC P-256 key `jwk`, as an
// AttestationBundle's DER. spoil: 'name', 'attributes', 'signature'.
async function tpmBundle(jwk, anchor, spoil) {
  log.debug("Entering tpmBundle().");
  const pubArea = Buffer.concat([
    u16(0x0023), u16(0x000b),
    u32(spoil === 'attributes' ? 0x00060440 : 0x00060472),
    tpm2b(Buffer.alloc(0)), u16(0x0010), u16(0x0010), u16(0x0003),
    u16(0x0010), tpm2b(Buffer.from(jwk.x, 'base64url')),
    tpm2b(Buffer.from(jwk.y, 'base64url'))]);
  const name = Buffer.concat([u16(0x000b), spoil === 'name'
    ? nodeCrypto.randomBytes(32) : sha256(pubArea)]);
  const certInfo = Buffer.concat([
    u32(0xff544347), u16(0x8017),
    tpm2b(Buffer.concat([u16(0x000b), nodeCrypto.randomBytes(32)])),
    tpm2b(Buffer.from('freshness')), Buffer.alloc(17), Buffer.alloc(8),
    tpm2b(name),
    tpm2b(Buffer.concat([u16(0x000b), nodeCrypto.randomBytes(32)]))]);
  const ak = await kit.keyPair('rsa');
  const aik = await kit.certificate({
    subject: [], publicKey: ak.crypto.publicKey, issuer: anchor, ca: false,
    extensions: [
      extension('2.5.29.17', new pkijs.GeneralNames({ names: [
        new pkijs.GeneralName({ type: 4, value: (function () {
          log.debug("Entering the TPM's name.");
          const n = new pkijs.RelativeDistinguishedNames();
          n.typesAndValues.push(new pkijs.AttributeTypeAndValue({
            type: '2.23.133.2.1',
            value: new asn1js.Utf8String({ value: 'id:53594E54' }) }));
          log.debug("Leaving the TPM's name.");
          return n;
        })() })] }).toSchema().toBER(false), true),
      extension('2.5.29.37', new pkijs.ExtKeyUsage({
        keyPurposes: ['2.23.133.8.3'] }).toSchema().toBER(false))] });
  const raw = nodeCrypto.sign('sha256', spoil === 'signature'
    ? Buffer.from('not certInfo') : certInfo, ak.privateKey);
  const signature = Buffer.concat([u16(0x0014), u16(0x000b), tpm2b(raw)]);
  const octets = function (b) {
    log.debug("Entering octets().");
    log.debug("Leaving octets().");
    return new asn1js.OctetString({ valueHex: new Uint8Array(b).buffer });
  };
  const bundle = new asn1js.Sequence({ value: [
    new asn1js.Sequence({ value: [new asn1js.Sequence({ value: [
      new asn1js.ObjectIdentifier({ value: '2.23.133.20.1' }),
      new asn1js.Sequence({ value: [octets(tpm2b(certInfo)),
                                    octets(signature),
                                    octets(tpm2b(pubArea))] })] })] }),
    new asn1js.Sequence({ value: [asn1js.fromBER(new Uint8Array(aik.der)
      .buffer).result] })] });
  log.debug("Leaving tpmBundle().");
  return Buffer.from(bundle.toBER(false));
}

// A PKCS#10 request over an EC P-256 key, carrying `bundles` as
// id-aa-attestation attributes and `uris` as its subjectAltName.
async function deviceCsr(bundles, uris, pair) {
  log.debug("Entering deviceCsr().");
  const keys = pair || await kit.keyPair('ec');
  const csr = new pkijs.CertificationRequest();
  csr.subject.typesAndValues.push(new pkijs.AttributeTypeAndValue({
    type: '2.5.4.3', value: new asn1js.Utf8String({ value: 'a device' }) }));
  csr.attributes = (bundles || []).map(function (der) {
    return new pkijs.Attribute({ type: '1.2.840.113549.1.9.16.2.59',
      values: [asn1js.fromBER(new Uint8Array(der).buffer).result] });
  });
  if ((uris || []).length) {
    csr.attributes.push(new pkijs.Attribute({
      type: '1.2.840.113549.1.9.14',
      values: [new pkijs.Extensions({ extensions: [new pkijs.Extension({
        extnID: '2.5.29.17', critical: false,
        extnValue: new pkijs.GeneralNames({ names: uris.map(function (u) {
          return new pkijs.GeneralName({ type: 6, value: u });
        }) }).toSchema().toBER(false) })] }).toSchema()] }));
  }
  await csr.subjectPublicKeyInfo.importKey(keys.crypto.publicKey);
  await csr.sign(keys.crypto.privateKey, 'SHA-256');
  log.debug("Leaving deviceCsr().");
  return { der: Buffer.from(csr.toSchema().toBER(false)), pair: keys,
           jwk: keys.publicKey.export({ format: 'jwk' }) };
}

function person(id, admin) {
  log.debug("Entering person().");
  log.debug("Leaving person().");
  return { kind: 'person', id: id, admin: !!admin, hasEntry: true,
           via: 'test' };
}

// A request whose TLS connection presented `der`.
function presenting(der, revoked) {
  log.debug("Entering presenting().");
  log.debug("Leaving presenting().");
  return { socket: { authorized: false, getPeerCertificate: function () {
             return { raw: der };
           } },
           certificateRevocation: revoked ? { refused: true,
                                              status: 'revoked' } : null };
}

async function checkChallenges(t) {
  log.debug("Entering checkChallenges().");
  t.log.info('=== 1-2. the challenge, and a JWK proof ===');
  const pair = ecPair();
  const first = enrolment.issueChallenge({ sessionId: 's1-' + RUN,
    username: ALICE, purpose: 'key' });
  const second = enrolment.issueChallenge({ sessionId: 's1-' + RUN,
    username: ALICE, purpose: 'key' });
  t.check(first.ok && second.ok && first.challenge !== second.challenge &&
          enrolment.pendingFor('s1-' + RUN, 'key').challenge ===
            second.challenge,
          '1a. one challenge per session and purpose: a new one replaces ' +
          'the old');
  t.equal(code(await enrolment.proveKey({ username: ALICE,
    sessionId: 's1-' + RUN, challenge: first.challenge, audience: AUD,
    proof: proof(pair, first.challenge) })), 'STS-DEVICE-0016',
          '1b. the replaced challenge is refused');
  t.equal(code(await enrolment.proveKey({ username: BOB,
    sessionId: 's2-' + RUN, challenge: second.challenge, audience: AUD,
    proof: proof(pair, second.challenge) })), 'STS-DEVICE-0016',
          '1c. another session (and person) cannot answer it');
  const later = new enrolment.DeviceEnrolment(Object.assign(
    enrolment.DeviceEnrolment.defaultDeps(), { now: function () {
      return Date.now() + 3600 * 1000;
    } }));
  t.equal(code(await later.proveKey({ username: ALICE,
    sessionId: 's1-' + RUN, challenge: second.challenge, audience: AUD,
    proof: proof(pair, second.challenge) })), 'STS-DEVICE-0016',
          '1d. an expired challenge is refused');

  const c1 = enrolment.issueChallenge({ sessionId: 's1-' + RUN,
    username: ALICE, purpose: 'key' });
  t.equal(code(await enrolment.proveKey({ username: ALICE,
    sessionId: 's1-' + RUN, challenge: c1.challenge, audience: AUD,
    proof: proof(pair, c1.challenge, { nonce: 'not-it' }) })),
          'STS-DEVICE-0017', '2a. a proof over another nonce is refused');
  const c2 = enrolment.issueChallenge({ sessionId: 's1-' + RUN,
    username: ALICE, purpose: 'key' });
  t.equal(code(await enrolment.proveKey({ username: ALICE,
    sessionId: 's1-' + RUN, challenge: c2.challenge, audience: AUD,
    proof: proof(pair, c2.challenge, { typ: 'dpop+jwt' }) })),
          'STS-DEVICE-0017', '2b. a JWS of another typ (a DPoP proof) is ' +
          'refused');
  const c3 = enrolment.issueChallenge({ sessionId: 's1-' + RUN,
    username: ALICE, purpose: 'key' });
  const registered = await enrolment.proveKey({ username: ALICE,
    sessionId: 's1-' + RUN, challenge: c3.challenge, audience: AUD,
    proof: proof(pair, c3.challenge), label: 'Alice phone',
    platform: 'android' });
  const key = registered.ok ? registered.device.keys[0] : null;
  t.check(registered.ok && registered.device.enrolment.method === 'portal' &&
          key && key.kind === 'jwk' && key.proof === 'jwk-proof' &&
          key.attestation.level === 'self-asserted' &&
          key.thumbprint === stsCrypto.jwkThumbprint(pair.jwk),
          '2c. development registers an unattested JWK, self-asserted',
          JSON.stringify(registered).slice(0, 600));
  t.equal(code(await enrolment.proveKey({ username: ALICE,
    sessionId: 's1-' + RUN, challenge: c3.challenge, audience: AUD,
    proof: proof(pair, c3.challenge) })), 'STS-DEVICE-0016',
          '2d. the answered challenge is refused the second time');
  set('global.mode', 'product');
  try {
    const c4 = enrolment.issueChallenge({ sessionId: 's1-' + RUN,
      username: ALICE, purpose: 'key' });
    t.equal(code(await enrolment.proveKey({ username: ALICE,
      sessionId: 's1-' + RUN, challenge: c4.challenge, audience: AUD,
      proof: proof(ecPair(), c4.challenge) })), 'STS-DEVICE-0024',
            '2e. product refuses an unattested key');
  } finally {
    config.clearOverride('global.mode');
  }
  log.debug("Leaving checkChallenges().");
  return registered.ok ? { device: registered.device, pair: pair } : null;
}

async function checkAndroid(t) {
  log.debug("Entering checkAndroid().");
  t.log.info('=== 3. Android Key Attestation ===');
  const anchor = await kit.root('Synthetic Google', 'ec');
  const attempt = async function (level, spoil) {
    log.debug("Entering attempt().");
    const pair = ecPair();
    const c = enrolment.issueChallenge({ sessionId: 'sa-' + RUN,
      username: ALICE, purpose: 'key' });
    const leaf = await androidLeaf(pair, spoil === 'challenge'
      ? 'someone else\'s' : c.challenge, anchor, level);
    const out = await enrolment.proveKey({ username: ALICE,
      sessionId: 'sa-' + RUN, challenge: c.challenge, audience: AUD,
      proof: proof(pair, c.challenge, { x5c: [leaf.der.toString('base64'),
                                              anchor.der.toString('base64')] })
    });
    log.debug("Leaving attempt().");
    return out;
  };
  set('devices.androidAttestationTrustAnchors', anchor.pem);
  const tee = await attempt(1);
  const k = tee.ok ? tee.device.keys[0] : null;
  t.check(tee.ok && k.attestation.level === 'attested' &&
          k.attestation.format === 'android-key-attestation' &&
          /trusted-environment/.test(k.attestation.summary) &&
          tee.device.attestation === 'attested',
          '3a. a TEE key chained to the configured root is attested',
          JSON.stringify(tee).slice(0, 600));
  t.equal(code(await attempt(0)), 'STS-DEVICE-0018',
          '3b. a SOFTWARE key is never attested, and is refused');
  t.equal(code(await attempt(1, 'challenge')), 'STS-DEVICE-0018',
          '3c. an attestationChallenge that is not ours is refused');
  set('global.mode', 'product');
  try {
    const productTee = await attempt(2);
    t.check(productTee.ok &&
            productTee.device.keys[0].attestation.level === 'attested',
            '3d. product registers a StrongBox key attested by the root');
  } finally {
    config.clearOverride('global.mode');
  }
  config.clearOverride('devices.androidAttestationTrustAnchors');
  const unanchored = await attempt(1);
  t.check(unanchored.ok &&
          unanchored.device.keys[0].attestation.level === 'self-asserted' &&
          /does NOT chain/.test(unanchored.device.keys[0].attestation.summary),
          '3e. a statement chaining to no configured root (Google\'s ' +
          'shipped ones, here) is self-asserted', JSON.stringify(unanchored)
            .slice(0, 500));
  log.debug("Leaving checkAndroid().");
}

async function checkAppAttest(t) {
  log.debug("Entering checkAppAttest().");
  t.log.info('=== 4. Apple App Attest ===');
  const anchor = await kit.root('Synthetic Apple', 'ec');
  set('devices.appleAppAttestTrustAnchors', anchor.pem);
  set('devices.appleAppAttestAppIds', APP_ID);
  const c = enrolment.issueChallenge({ sessionId: 'sp-' + RUN,
    username: ALICE, purpose: 'key' });
  const made = await appAttestObject(c.challenge, anchor, APP_ID);
  const done = await enrolment.proveKey({ username: ALICE,
    sessionId: 'sp-' + RUN, challenge: c.challenge, audience: AUD,
    appAttest: { keyId: made.keyId, attestation: made.attestation } });
  const k = done.ok ? done.device.keys[0] : null;
  t.check(done.ok && k.attestation.level === 'attested' &&
          k.attestation.format === 'apple-app-attest' &&
          k.thumbprint === stsCrypto.jwkThumbprint({ kty: 'EC', crv: 'P-256',
                                                     x: made.jwk.x,
                                                     y: made.jwk.y }),
          '4a. an App Attest key for a configured app is attested',
          JSON.stringify(done).slice(0, 600));
  const c2 = enrolment.issueChallenge({ sessionId: 'sp-' + RUN,
    username: ALICE, purpose: 'key' });
  const other = await appAttestObject(c2.challenge, anchor, 'X.not.ours');
  t.equal(code(await enrolment.proveKey({ username: ALICE,
    sessionId: 'sp-' + RUN, challenge: c2.challenge, audience: AUD,
    appAttest: { keyId: other.keyId, attestation: other.attestation } })),
          'STS-DEVICE-0019', '4b. an app not in devices.appleAppAttestAppIds ' +
          'is refused');
  log.debug("Leaving checkAppAttest().");
}

async function checkWebauthn(t) {
  log.debug("Entering checkWebauthn().");
  t.log.info('=== 5. a linked WebAuthn platform credential ===');
  const cred = await kit.credential(-7);
  const credentialId = cred.id.toString('base64url');
  const jwk = cred.pair.publicKey.export({ format: 'jwk' });
  const stored = credentials.addKey(ALICE, { credentialId: credentialId,
    publicKeyJwk: jwk, signCount: 0, label: 'built in',
    attachment: 'platform', aaguid: '',
    attestation: { verified: true, trusted: true, format: 'packed',
                   type: 'basic', anchor: 'configured', checkedAt: Date.now() }
  }, 'mfa');
  const roaming = await kit.credential(-7);
  credentials.addKey(ALICE, { credentialId:
    roaming.id.toString('base64url'),
    publicKeyJwk: roaming.pair.publicKey.export({ format: 'jwk' }),
    signCount: 0, label: 'on my keyring', attachment: 'cross-platform' },
    'mfa');
  t.check(stored && stored.ok !== false, 'precondition: the credential is ' +
          'enrolled', JSON.stringify(stored));
  t.equal(code(enrolment.beginLink({ username: ALICE, sessionId: 'sw-' + RUN,
    credentialId: roaming.id.toString('base64url') })), 'STS-DEVICE-0022',
          '5a. a roaming key is refused: it identifies no device');
  t.equal(code(enrolment.beginLink({ username: BOB, sessionId: 'sw-' + RUN,
    credentialId: credentialId })), 'STS-DEVICE-0022',
          '5b. another person\'s credential is refused');
  const assertion = function (challenge, spoil) {
    log.debug("Entering assertion().");
    const count = Buffer.alloc(4);
    count.writeUInt32BE(spoil === 'counter' ? 0 : 5, 0);
    const authData = Buffer.concat([sha256(Buffer.from('localhost')),
                                    Buffer.from([0x05]), count]);
    const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.get',
      challenge: challenge, origin: 'https://localhost:8081' }));
    const signed = Buffer.concat([authData, sha256(clientData)]);
    const sig = cred.sign(spoil === 'signature'
      ? Buffer.concat([signed, Buffer.from([1])]) : signed);
    log.debug("Leaving assertion().");
    return { id: credentialId, rawId: credentialId, type: 'public-key',
             response: { authenticatorData: authData.toString('base64url'),
                         clientDataJSON: clientData.toString('base64url'),
                         signature: sig.toString('base64url') } };
  };
  const bad = enrolment.beginLink({ username: ALICE, sessionId: 'sw-' + RUN,
    credentialId: credentialId, label: 'Alice laptop' });
  t.equal(code(await enrolment.finishLink({ username: ALICE,
    sessionId: 'sw-' + RUN, challenge: bad.challenge,
    credential: assertion(bad.challenge, 'signature'),
    origin: 'https://localhost:8081', rpId: 'localhost' })),
          'STS-DEVICE-0022', '5c. an assertion that does not verify is ' +
          'refused');
  const begun = enrolment.beginLink({ username: ALICE, sessionId: 'sw-' + RUN,
    credentialId: credentialId, label: 'Alice laptop', platform: 'macos' });
  const linked = await enrolment.finishLink({ username: ALICE,
    sessionId: 'sw-' + RUN, challenge: begun.challenge,
    credential: assertion(begun.challenge),
    origin: 'https://localhost:8081', rpId: 'localhost' });
  const k = linked.ok ? linked.device.keys[0] : null;
  t.check(linked.ok && k.kind === 'webauthn' && k.proof === 'webauthn' &&
          k.attestation.level === 'attested' &&
          k.material.credentialId === credentialId &&
          linked.device.label === 'Alice laptop',
          '5d. a fresh assertion links it, attested by its registration\'s ' +
          'trusted attestation', JSON.stringify(linked).slice(0, 600));
  log.debug("Leaving checkWebauthn().");
  return linked.ok ? { device: linked.device, credentialId: credentialId }
                   : null;
}

async function checkCertificates(t) {
  log.debug("Entering checkCertificates().");
  t.log.info('=== 6. EST and SCEP: the device profile ===');
  const tpmRoot = await kit.root('Synthetic TPM Manufacturer', 'rsa');
  set('devices.tpmTrustAnchors', tpmRoot.pem);
  const first = await deviceCsr([]);
  const bundle = await tpmBundle(first.jwk, tpmRoot);
  const request = await deviceCsr([bundle], [], first.pair);
  const parsed = await core.parseCsr(request.der);
  t.check(parsed.ok && parsed.attestations.length === 1,
          '6a. parseCsr() reads the id-aa-attestation value',
          JSON.stringify(parsed.errors || parsed.attributeTypes));
  const issued = await core.issue({ family: 'est', profile: 'device',
    principal: person(ALICE), target: { kind: 'person', id: ALICE },
    publicKeyPem: parsed.publicKeyPem, requested: parsed.requested,
    attestations: parsed.attestations, keySource: 'client', via: 'test' });
  const device = issued.ok ? devices.byId(issued.device) : null;
  const key = device ? device.keys[0] : null;
  t.check(issued.ok && device && device.enrolment.method === 'est' &&
          key.kind === 'x509' && key.proof === 'est' &&
          key.attestation.level === 'attested' &&
          key.attestation.format === 'tcg-tpm2-key' &&
          new nodeCrypto.X509Certificate(issued.record.certificatePem)
            .subjectAltName === 'URI:urn:sts:device:' + device.id,
          '6b. EST issues a device certificate to a NEW device, attested by ' +
          'its TPM, naming urn:sts:device:<id>',
          JSON.stringify(issued.errors || (key && key.attestation)));
  if (!device) {
    log.debug("Leaving checkCertificates(). No device.");
    return null;
  }
  const urn = 'urn:sts:device:' + device.id;
  const again = await deviceCsr([await tpmBundle(first.jwk, tpmRoot)],
                                [urn], first.pair);
  const againParsed = await core.parseCsr(again.der);
  const renewed = await core.issue({ family: 'est', profile: 'device',
    principal: person(ALICE), target: { kind: 'person', id: ALICE },
    publicKeyPem: againParsed.publicKeyPem, requested: againParsed.requested,
    attestations: againParsed.attestations, via: 'test' });
  const after = devices.byId(device.id);
  t.check(renewed.ok && after.keys.length === 1 &&
          after.keys[0].id !== key.id &&
          after.keys[0].thumbprint === key.thumbprint,
          '6c. a request naming the device over the same key REPLACES that ' +
          'key\'s certificate', JSON.stringify(renewed.errors));
  t.equal(code(await core.issue({ family: 'est', profile: 'device',
    principal: person(BOB), target: { kind: 'person', id: BOB },
    publicKeyPem: againParsed.publicKeyPem, requested: againParsed.requested,
    attestations: againParsed.attestations, via: 'test' })),
          'STS-DEVICE-0023', '6d. Bob cannot have a certificate for Alice\'s ' +
          'device');
  const fresh = await deviceCsr([]);
  const freshParsed = await core.parseCsr((await deviceCsr([], [urn],
                                                            fresh.pair)).der);
  const byAdmin = await core.issue({ family: 'scep', profile: 'device',
    principal: person(ADMIN, true), target: { kind: 'person', id: ADMIN },
    publicKeyPem: freshParsed.publicKeyPem, requested: freshParsed.requested,
    attestations: [], via: 'test' });
  t.check(byAdmin.ok && devices.byId(device.id).keys.length === 2 &&
          devices.byId(device.id).keys[1].proof === 'scep' &&
          devices.byId(device.id).keys[1].attestation.level ===
            'self-asserted',
          '6e. an administrator adds a second key over SCEP, with no ' +
          'attestation: self-asserted in development',
          JSON.stringify(byAdmin.errors));
  t.equal(code(await core.issue({ family: 'acme', profile: 'device',
    principal: person(ALICE), target: { kind: 'person', id: ALICE },
    publicKeyPem: parsed.publicKeyPem, requested: {}, via: 'test' })),
          'STS-DEVICE-0025', '6f. ACME does not issue the device profile');
  t.equal(code(await core.issue({ family: 'est', profile: 'device',
    principal: person(ALICE), target: { kind: 'person', id: ALICE },
    publicKeyPem: parsed.publicKeyPem, requested: {}, keySource: 'server',
    via: 'test' })), 'STS-DEVICE-0025',
          '6g. nor over a key this service generated');
  t.equal(code(await core.issue({ family: 'est', profile: 'device',
    principal: person(ALICE), target: { kind: 'person', id: ALICE },
    publicKeyPem: parsed.publicKeyPem, requested: {}, replaces: 'ab',
    via: 'test' })), 'STS-DEVICE-0025', '6h. nor as a re-enrolment');
  const spoiledKey = await deviceCsr([]);
  for (const spoil of ['name', 'attributes', 'signature']) {
    const spoiled = await deviceCsr([await tpmBundle(spoiledKey.jwk, tpmRoot,
                                                     spoil)], [],
                                    spoiledKey.pair);
    const read = await core.parseCsr(spoiled.der);
    t.equal(code(await core.issue({ family: 'est', profile: 'device',
      principal: person(ALICE), target: { kind: 'person', id: ALICE },
      publicKeyPem: read.publicKeyPem, requested: {},
      attestations: read.attestations, via: 'test' })), 'STS-DEVICE-0020',
            '6i. a TPM statement spoiled (' + spoil + ') is refused');
  }
  const two = await deviceCsr([bundle, bundle], [], first.pair);
  const twoRead = await core.parseCsr(two.der);
  t.equal(code(await core.issue({ family: 'est', profile: 'device',
    principal: person(ALICE), target: { kind: 'person', id: ALICE },
    publicKeyPem: twoRead.publicKeyPem, requested: {},
    attestations: twoRead.attestations, via: 'test' })), 'STS-DEVICE-0021',
          '6j. two attestation attributes are refused (section 4.3)');
  set('global.mode', 'product');
  try {
    const plain = await deviceCsr([]);
    const plainRead = await core.parseCsr(plain.der);
    t.equal(code(await core.issue({ family: 'est', profile: 'device',
      principal: person(ALICE), target: { kind: 'person', id: ALICE },
      publicKeyPem: plainRead.publicKeyPem, requested: {}, attestations: [],
      via: 'test' })), 'STS-DEVICE-0024',
            '6k. product refuses a device key with no TPM attestation');
  } finally {
    config.clearOverride('global.mode');
  }
  log.debug("Leaving checkCertificates().");
  return { device: device, certificatePem: renewed.ok
    ? renewed.record.certificatePem : issued.record.certificatePem };
}

function checkRecognition(t, jwkDevice, linked, certified) {
  log.debug("Entering checkRecognition().");
  t.log.info('=== 7. recognition ===');
  set('devices.lastUsedResolutionSeconds', 0);
  const before = recognition.activity().recognitions;
  const byJwk = recognition.recognize({
    dpopJkt: stsCrypto.jwkThumbprint(jwkDevice.pair.jwk), subject: ALICE });
  t.check(byJwk && byJwk.id === jwkDevice.device.id && byJwk.via === 'jwk' &&
          byJwk.keyId === jwkDevice.device.keys[0].id &&
          byJwk.ownerMatches === true && byJwk.status === 'active',
          '7a. a DPoP jkt names its device, by the jwk key',
          JSON.stringify(byJwk));
  const byWebauthn = linked ? recognition.recognize({
    webauthnCredentialId: linked.credentialId }) : null;
  t.check(byWebauthn && byWebauthn.id === linked.device.id &&
          byWebauthn.via === 'webauthn' &&
          byWebauthn.keyAttestation === 'attested',
          '7b. a WebAuthn credential id names the device it is linked to',
          JSON.stringify(byWebauthn));
  const der = certified ? new nodeCrypto.X509Certificate(
    certified.certificatePem).raw : null;
  const byCert = der ? recognition.recognize({ request: presenting(der) })
                     : null;
  t.check(byCert && byCert.id === certified.device.id &&
          byCert.via === 'x509' && byCert.chainVerified === false,
          '7c. a client certificate names its device by its SPKI, and ' +
          'records that the chain was not verified', JSON.stringify(byCert));
  t.check(der && recognition.recognize({ request: presenting(der, true) }) ===
          null, '7d. a certificate refused on revocation is not recognised');
  const minted = devices.issueForSession({ username: ALICE,
    clientId: 'de-client-' + RUN, sessionId: 'sess-' + RUN,
    label: 'native' });
  const bySecret = minted.ok ? recognition.recognize({
    deviceSecret: minted.secret }) : null;
  t.check(bySecret && bySecret.id === minted.device.id &&
          bySecret.via === 'native-sso',
          '7e. a Native SSO device_secret names its device',
          JSON.stringify(bySecret));
  devices.setStatus(jwkDevice.device.id, 'compromised', 'test', 'lost');
  const compromised = recognition.recognize({
    dpopJkt: stsCrypto.jwkThumbprint(jwkDevice.pair.jwk) });
  t.check(compromised && compromised.status === 'compromised',
          '7f. a COMPROMISED device is still recognised, and says so');
  const both = der ? recognition.recognize({ request: presenting(der),
    dpopJkt: stsCrypto.jwkThumbprint(jwkDevice.pair.jwk) }) : null;
  t.check(both && both.via === 'x509' &&
          (both.conflict || []).indexOf(jwkDevice.device.id) >= 0,
          '7g. the strongest evidence wins, and a second device is kept as ' +
          'a conflict', JSON.stringify(both));
  t.check(Date.parse(devices.byId(jwkDevice.device.id).lastUsed) >=
          Date.now() - 60000, '7h. the recognised device\'s last use moved');
  const after = recognition.activity().recognitions;
  t.check(after.jwk > before.jwk && after.x509 > before.x509 &&
          after.webauthn > before.webauthn &&
          after['native-sso'] > before['native-sso'],
          '7i. every recognition is counted by the way it was made',
          JSON.stringify(after));
  t.check(recognition.recognize({ dpopJkt: 'no-such-key' }) === null &&
          recognition.recognize({}) === null,
          '7j. no device for evidence nobody registered, or none');
  log.debug("Leaving checkRecognition().");
}

async function run(t) {
  log.debug("Entering run().");
  try {
    if (!pki.hasRoot()) {
      await pki.start({});
    }
    await pki.ensureScope(realms.currentId());
    [ALICE, BOB, ADMIN].forEach(function (name) {
      ldap.createUser(name, { invent: false, attributes: {} });
    });
    const jwkDevice = await checkChallenges(t);
    await checkAndroid(t);
    await checkAppAttest(t);
    const linked = await checkWebauthn(t);
    const certified = await checkCertificates(t);
    if (jwkDevice) {
      checkRecognition(t, jwkDevice, linked, certified);
    }
  } finally {
    OVERRIDDEN.forEach(function (key) {
      config.clearOverride(key);
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'device_enrolment',
  describe: '#164 phase 2: a device registered by a key proof (JWK, ' +
            'Android Key Attestation, Apple App Attest), a linked WebAuthn ' +
            'credential and EST/SCEP with a TPM key attestation; the mode ' +
            'split; and recognition by x509, webauthn, jwk and native-sso',
  run: run
};
