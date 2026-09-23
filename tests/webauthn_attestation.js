'use strict';
//
// File: webauthn_attestation.js
//
// ===========================================================================
// A WEBAUTHN REGISTRATION'S ATTESTATION STATEMENT, VERIFIED (#105), in
// process. Every statement is made at run time by
// `tests/webauthn_attestation_kit.js` — generated keys, generated roots,
// generated attestation certificates; nothing captured and nothing committed.
//
//   A. SECTION 7.1's OTHER CHECKS: the credential's alg against what was
//      offered (STS-AUTHN-0228), a credential id over 1023 bytes (0229), BS
//      without BE (0230).
//   B. THE NEW ALGORITHMS: PS256 and ML-DSA-44 register and then ASSERT —
//      the stored JWK carries its algorithm, so the assertion is checked with
//      PSS and ML-DSA rather than PKCS#1 and SHA-256.
//   C. EACH OF THE EIGHT FORMATS, valid and then wrong in one way at a time,
//      under verify-if-present with the kit's roots as configured anchors.
//   D. THE POLICY: development's by-mode verifies nothing, product's
//      verifies; `off` is refused in product and read as by-mode;
//      require-trusted refuses none, self and an unanchored chain;
//      verify-if-present accepts the last as untrusted; a demand for trust
//      makes the ceremony ask for `direct`.
//   E. THE FIDO METADATA SERVICE: a synthetic BLOB (a test root, as
//      `tests/risk_mds.js` makes one) listing three models — a model's own
//      roots anchor its chain ('mds'), a listed model whose chain does not
//      reach them is refused (0235), a REVOKED model is refused (0237),
//      fido-u2f is found by its attestation key identifier, and the
//      certification level and FIPS are read from the status reports (0238).
//   F. THE AAGUID ALLOW-LIST (0236), and that it demands a trusted statement.
//   G. REVOCATION: a chain whose list is at an address this service will not
//      dial is refused in product (0239) and accepted in development; a
//      chain naming no list at all is accepted in both (sections 8.2.1 and
//      8.3.1 make it optional).
//   H. THE RECORD reaches the key: `credentials.addKey()` keeps it, and the
//      formats the report names are the formats the verifier knows.
//   I. THE DOWNLOAD JOB (`risk.mds-refresh`): registered, silent while
//      `risk.mdsUrl` is empty, a newer BLOB fetched through
//      `fetchPublished()` and imported, the same serial left alone, and a
//      failed download STS-RISK-0027.
//
// The console, `/portal/keys` and `/admin-api` drawing it are asserted over
// HTTP by `tests/vendored/sts_webauthn_attestation.js`.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const config = require('../common/config');
const webauthn = require('../authn/webauthn');
const policy = require('../authn/webauthn_policy');
const attestation = require('../authn/webauthn_attestation');
const errorCodes = require('../common/error_codes');
const credentials = require('../common/credentials');
const riskStore = require('../risk/risk_store');
const riskDatasets = require('../risk/risk_datasets');
const riskTerms = require('../risk/risk_terms');
const kit = require('./webauthn_attestation_kit');

const log = require('bunyan').createLogger({ name: 'webauthn_attestation',
  level: process.env.LOG_LEVEL || 'info' });

const DAY = 86400000;

function uuid(buf) {
  log.debug("Entering uuid().");
  const hex = Buffer.from(buf).toString('hex');
  log.debug("Leaving uuid().");
  return hex.slice(0, 8) + '-' + hex.slice(8, 12) + '-' + hex.slice(12, 16) +
    '-' + hex.slice(16, 20) + '-' + hex.slice(20);
}

// Register `made` (a kit format) over ceremony `c`: the verifier's own checks,
// then the attestation. `{ verdict, result, code }`.
async function register(c, made, offered) {
  log.debug("Entering register().");
  const input = c.input(made);
  if (offered) {
    input.expectedAlgorithms = offered;
  }
  const verdict = webauthn.verifyRegistration(input);
  if (!verdict.ok) {
    log.debug("Leaving register(). The ceremony failed.");
    return { verdict: verdict, result: null,
             code: policy.failureCodeFor(verdict) };
  }
  const result = await attestation.assess(verdict);
  log.debug("Leaving register().");
  return { verdict: verdict, result: result,
           code: result.ok ? '' : errorCodes.codeOf(result) };
}

function set(key, value) {
  log.debug("Entering set(). " + key);
  const done = config.setOverride(key, value);
  if (!done.ok) {
    throw new Error('setting ' + key + ' was refused: ' +
                    done.errors.join('; '));
  }
  log.debug("Leaving set().");
}

function clear(keys) {
  log.debug("Entering clear().");
  keys.forEach(function (k) {
    config.clearOverride(k);
  });
  log.debug("Leaving clear().");
}

const TOUCHED = ['global.mode', 'webauthn.attestationPolicy',
                 'webauthn.attestationTrustAnchors',
                 'webauthn.attestationAllowedAaguids',
                 'webauthn.attestationMinCertificationLevel',
                 'webauthn.attestationRequireFips',
                 'webauthn.attestationAllowSafetynet',
                 'webauthn.attestationAndroidSoftwareKeys',
                 'webauthn.attestation', 'webauthn.algorithms',
                 'risk.mdsTrustAnchors'];

// A synthetic MDS3 BLOB, signed by `signer` (a root and a signing
// certificate under it), as tests/risk_mds.js makes one.
async function mdsHierarchy() {
  log.debug("Entering mdsHierarchy().");
  const rootCa = await kit.root('Synthetic FIDO MDS', 'rsa');
  const signerPair = await kit.keyPair('rsa');
  const signer = await kit.certificate({
    subject: [['2.5.4.3', 'Synthetic MDS signer']],
    publicKey: signerPair.crypto.publicKey, issuer: rootCa, ca: false });
  log.debug("Leaving mdsHierarchy().");
  return { root: rootCa, signer: signer, key: signerPair.privateKey };
}

function blobOf(h, payload) {
  log.debug("Entering blobOf().");
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT',
    x5c: [h.signer.der.toString('base64'), h.root.der.toString('base64')] }))
    .toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = nodeCrypto.sign('sha256',
    Buffer.from(header + '.' + body), h.key).toString('base64url');
  log.debug("Leaving blobOf().");
  return header + '.' + body + '.' + signature;
}

async function run(t) {
  log.debug("Entering run().");
  clear(TOUCHED);
  riskStore.reset();
  riskDatasets.forget();

  // The vendors' roots, one per format family.
  const vendor = await kit.root('Synthetic Vendor');
  const tpmCa = await kit.root('Synthetic TPM Manufacturer', 'rsa');
  const google = await kit.root('Synthetic Google');
  const appleRoot = await kit.root('Synthetic Apple');
  const stranger = await kit.root('Nobody Anybody Trusts');
  const anchors = [vendor, tpmCa, google, appleRoot]
    .map(function (r) { return r.pem; }).join('');

  // =========================================================================
  t.log.info('=== A. section 7.1: alg offered, 1023 bytes, BE and BS ===');
  // =========================================================================
  let c = await kit.ceremony();
  let r = await register(c, kit.none(), [-257]);
  t.check(r.code === 'STS-AUTHN-0228' &&
          r.verdict.failed.indexOf('credential algorithm was offered') >= 0,
    'A1. an ES256 credential when only RS256 was offered is refused ' +
    '(STS-AUTHN-0228)', JSON.stringify(r.verdict.failed));
  r = await register(c, kit.none(), [-7, -257]);
  t.check(r.verdict.ok, 'A2. and accepted when ES256 was offered');
  c = await kit.ceremony();
  const long = await kit.credential(-7);
  long.id = nodeCrypto.randomBytes(1024);
  const longCeremony = await kit.ceremony();
  longCeremony.credential = long;
  // Rebuilt by hand: the kit's authenticator data is made once per ceremony.
  const longInput = longCeremony.input(kit.none());
  const decodedObject = webauthn.cborDecodeFirst(
    Buffer.from(longInput.attestationObject, 'base64url'))[0];
  const ad = decodedObject.get('authData');
  const idLength = Buffer.alloc(2);
  idLength.writeUInt16BE(1024, 0);
  const rebuilt = Buffer.concat([ad.subarray(0, 53), idLength, long.id,
                                 kit.cbor(long.cose)]);
  longInput.attestationObject = kit.cbor(new Map([['fmt', 'none'],
    ['attStmt', {}], ['authData', rebuilt]])).toString('base64url');
  const longVerdict = webauthn.verifyRegistration(longInput);
  t.check(!longVerdict.ok &&
          policy.failureCodeFor(longVerdict) === 'STS-AUTHN-0229',
    'A3. a credential id of 1024 bytes is refused (STS-AUTHN-0229)',
    JSON.stringify(longVerdict.failed));
  c = await kit.ceremony({ flags: 0x45 | 0x10 });
  r = await register(c, kit.none());
  t.check(r.code === 'STS-AUTHN-0230',
    'A4. BS set without BE is refused (STS-AUTHN-0230)', r.code);
  c = await kit.ceremony({ flags: 0x45 | 0x18 });
  r = await register(c, kit.none());
  t.check(r.verdict.ok, 'A5. and BS with BE is accepted');

  // =========================================================================
  t.log.info('=== B. PS256 and ML-DSA-44 register and assert ===');
  // =========================================================================
  for (const alg of [-37, -48, -8]) {
    c = await kit.ceremony({ alg: alg });
    r = await register(c, kit.packedSelf(c), [alg]);
    const jwk = r.verdict.publicKeyJwk || {};
    const authData = Buffer.concat([
      nodeCrypto.createHash('sha256').update('localhost').digest(),
      Buffer.from([0x05]), Buffer.from([0, 0, 0, 1])]);
    const clientDataJSON = Buffer.from(JSON.stringify({
      type: 'webauthn.get', challenge: 'abc',
      origin: 'https://localhost:8081' }));
    const signature = c.credential.sign(Buffer.concat([authData,
      nodeCrypto.createHash('sha256').update(clientDataJSON).digest()]));
    const asserted = webauthn.verifyAssertion({
      authenticatorData: authData.toString('base64url'),
      clientDataJSON: clientDataJSON.toString('base64url'),
      signature: signature.toString('base64url'), publicKeyJwk: jwk,
      expectedChallenge: 'abc', expectedOrigin: 'https://localhost:8081',
      expectedRpId: 'localhost', previousSignCount: 0 });
    const forged = webauthn.verifyAssertion({
      authenticatorData: authData.toString('base64url'),
      clientDataJSON: clientDataJSON.toString('base64url'),
      signature: Buffer.concat([signature.subarray(0, 8),
        Buffer.from([signature[8] ^ 1]), signature.subarray(9)])
        .toString('base64url'),
      publicKeyJwk: jwk, expectedChallenge: 'abc',
      expectedOrigin: 'https://localhost:8081', expectedRpId: 'localhost',
      previousSignCount: 0 });
    t.check(r.verdict.ok && r.result.ok && asserted.ok && !forged.ok &&
            jwk.alg === webauthn.COSE_ALGS[String(alg)],
      'B. ' + webauthn.COSE_ALGS[String(alg)] + ': a self-attested ' +
      'registration verifies, the stored JWK names its algorithm, an ' +
      'assertion verifies and a changed one does not',
      JSON.stringify({ reg: r.verdict.failed, alg: jwk.alg,
                       asserted: asserted.failed }));
  }

  // =========================================================================
  t.log.info('=== C. each format, valid and wrong in one way ===');
  // =========================================================================
  set('webauthn.attestationPolicy', 'verify-if-present');
  set('webauthn.attestationTrustAnchors', anchors);

  const expect = async function (label, build, wantCode, check) {
    log.debug("Entering expect(). " + label);
    const cc = await kit.ceremony(build.ceremony || {});
    const made = await build(cc);
    const got = await register(cc, made);
    const ok = wantCode ? got.code === wantCode
      : !!(got.result && got.result.ok && (!check || check(got.result)));
    t.check(ok, label, JSON.stringify({ code: got.code,
      failed: got.verdict.failed,
      why: got.result && got.result.why,
      attestation: got.result && got.result.attestation }));
    log.debug("Leaving expect().");
    return got;
  };
  const trustedAs = function (type, anchor) {
    return function (res) {
      return res.attestation.verified && res.attestation.trusted &&
             res.attestation.type === type &&
             res.attestation.anchor === (anchor || 'configured');
    };
  };
  const untrustedAs = function (type) {
    return function (res) {
      return res.attestation.verified && !res.attestation.trusted &&
             res.attestation.type === type;
    };
  };

  // packed
  await expect('C1. packed with x5c: Basic, trusted through the configured ' +
               'root', function (cc) { return kit.packed(cc, vendor); },
               '', trustedAs('basic'));
  await expect('C2. packed, the signature over something else (0233)',
               function (cc) { return kit.packed(cc, vendor, 'signature'); },
               'STS-AUTHN-0233');
  await expect('C3. packed, the subject OU is not "Authenticator ' +
               'Attestation" (0234)',
               function (cc) { return kit.packed(cc, vendor, 'ou'); },
               'STS-AUTHN-0234');
  await expect('C4. packed, the certificate\'s AAGUID extension names ' +
               'another model (0234)',
               function (cc) {
                 return kit.packed(cc, vendor, 'aaguid-extension');
               }, 'STS-AUTHN-0234');
  await expect('C5. packed, the attestation certificate is a CA (0234)',
               function (cc) { return kit.packed(cc, vendor, 'ca'); },
               'STS-AUTHN-0234');
  await expect('C6. packed self attestation: Self, untrusted',
               function (cc) { return kit.packedSelf(cc); },
               '', untrustedAs('self'));
  await expect('C7. packed self, alg not the credential\'s (0234)',
               function (cc) { return kit.packedSelf(cc, 'alg'); },
               'STS-AUTHN-0234');
  await expect('C8. packed self, the signature over something else (0233)',
               function (cc) { return kit.packedSelf(cc, 'signature'); },
               'STS-AUTHN-0233');
  await expect('C9. packed with a member the format does not define (0232)',
               async function (cc) {
                 const made = await kit.packed(cc, vendor);
                 made.attStmt.extra = Buffer.from([1]);
                 return made;
               }, 'STS-AUTHN-0232');

  // tpm
  await expect('C10. tpm: AttCA, trusted through the TPM manufacturer\'s ' +
                'root', function (cc) { return kit.tpm(cc, tpmCa); },
                '', trustedAs('attca'));
  await expect('C11. tpm with the bare signature Windows sends, not a ' +
                'TPMT_SIGNATURE: still verified',
                function (cc) { return kit.tpm(cc, tpmCa, 'bare-signature'); },
                '', trustedAs('attca'));
  for (const spoil of ['extra-data', 'name', 'magic', 'eku', 'subject',
                       'key']) {
    await expect('C12. tpm, ' + spoil + ' wrong (0234)',
                 function (cc) { return kit.tpm(cc, tpmCa, spoil); },
                 'STS-AUTHN-0234');
  }
  await expect('C13. tpm, the signature over something else (0233)',
               function (cc) { return kit.tpm(cc, tpmCa, 'signature'); },
               'STS-AUTHN-0233');

  // android-key
  await expect('C14. android-key: Basic, trusted',
               function (cc) { return kit.androidKey(cc, google); },
               '', trustedAs('basic'));
  await expect('C15. android-key, a certificate for another key: the ' +
               'signature is checked against the certificate first (0233)',
               function (cc) { return kit.androidKey(cc, google, 'key'); },
               'STS-AUTHN-0233');
  for (const spoil of ['challenge', 'all-applications', 'purpose',
                       'software-origin']) {
    await expect('C15. android-key, ' + spoil + ' (0234)',
                 function (cc) { return kit.androidKey(cc, google, spoil); },
                 'STS-AUTHN-0234');
  }
  set('webauthn.attestationAndroidSoftwareKeys', true);
  await expect('C16. and an origin only the software list states is ' +
               'accepted where webauthn.attestationAndroidSoftwareKeys says',
               function (cc) {
                 return kit.androidKey(cc, google, 'software-origin');
               }, '', trustedAs('basic'));
  clear(['webauthn.attestationAndroidSoftwareKeys']);

  // android-safetynet
  await expect('C17. android-safetynet: verified, and UNTRUSTED while ' +
               'webauthn.attestationAllowSafetynet is off',
               function (cc) { return kit.safetynet(cc, google); },
               '', untrustedAs('basic'));
  set('webauthn.attestationAllowSafetynet', true);
  await expect('C18. and trusted where it is on',
               function (cc) { return kit.safetynet(cc, google); },
               '', trustedAs('basic'));
  clear(['webauthn.attestationAllowSafetynet']);
  for (const spoil of ['nonce', 'cts', 'stale', 'host']) {
    await expect('C19. android-safetynet, ' + spoil + ' (0234)',
                 function (cc) { return kit.safetynet(cc, google, spoil); },
                 'STS-AUTHN-0234');
  }
  await expect('C20. android-safetynet, a changed signature (0233)',
               function (cc) {
                 return kit.safetynet(cc, google, 'signature');
               }, 'STS-AUTHN-0233');

  // fido-u2f
  const u2f = function (spoil) {
    const build = function (cc) { return kit.fidoU2f(cc, vendor, spoil); };
    build.ceremony = { aaguid: Buffer.alloc(16) };
    return build;
  };
  await expect('C21. fido-u2f: Basic, trusted', u2f(), '',
               trustedAs('basic'));
  await expect('C22. fido-u2f, the signature over another message (0233)',
               u2f('signature'), 'STS-AUTHN-0233');
  await expect('C23. fido-u2f with two certificates (0232)',
               u2f('two-certificates'), 'STS-AUTHN-0232');

  // none
  await expect('C24. none: None, untrusted', function () {
    return kit.none();
  }, '', untrustedAs('none'));
  await expect('C25. none carrying anything (0232)', function () {
    return { fmt: 'none', attStmt: { sig: Buffer.from([1]) } };
  }, 'STS-AUTHN-0232');

  // apple
  await expect('C26. apple: AnonCA, trusted',
               function (cc) { return kit.apple(cc, appleRoot); },
               '', trustedAs('anonca'));
  await expect('C27. apple, the nonce of another ceremony (0234)',
               function (cc) { return kit.apple(cc, appleRoot, 'nonce'); },
               'STS-AUTHN-0234');
  await expect('C28. apple, a certificate for another key (0234)',
               function (cc) { return kit.apple(cc, appleRoot, 'key'); },
               'STS-AUTHN-0234');

  // compound
  await expect('C29. compound of packed and tpm: both verified, trusted',
               async function (cc) {
                 const a = await kit.packed(cc, vendor);
                 const b = await kit.tpm(cc, tpmCa);
                 return { fmt: 'compound', attStmt: [
                   { fmt: a.fmt, attStmt: a.attStmt },
                   { fmt: b.fmt, attStmt: b.attStmt }] };
               }, '', function (res) {
                 return res.attestation.type === 'compound' &&
                        res.attestation.trusted;
               });
  await expect('C30. compound with one member that does not verify (0233)',
               async function (cc) {
                 const a = await kit.packed(cc, vendor);
                 const b = await kit.tpm(cc, tpmCa, 'signature');
                 return { fmt: 'compound', attStmt: [
                   { fmt: a.fmt, attStmt: a.attStmt },
                   { fmt: b.fmt, attStmt: b.attStmt }] };
               }, 'STS-AUTHN-0233');
  await expect('C31. compound of one statement (0232)',
               async function (cc) {
                 const a = await kit.packed(cc, vendor);
                 return { fmt: 'compound', attStmt: [
                   { fmt: a.fmt, attStmt: a.attStmt }] };
               }, 'STS-AUTHN-0232');
  await expect('C32. compound inside compound (0232)',
               async function (cc) {
                 const a = await kit.packed(cc, vendor);
                 return { fmt: 'compound', attStmt: [
                   { fmt: a.fmt, attStmt: a.attStmt },
                   { fmt: 'compound', attStmt: [] }] };
               }, 'STS-AUTHN-0232');
  await expect('C33. a format section 8 does not define (0231)',
               function () {
                 return { fmt: 'packed2', attStmt: {} };
               }, 'STS-AUTHN-0231');

  // =========================================================================
  t.log.info('=== D. the policy ===');
  // =========================================================================
  clear(['webauthn.attestationPolicy']);
  set('global.mode', 'development');
  t.check(policy.attestationSettings().policy === 'off',
    'D1. development\'s by-mode is off', policy.attestationSettings().policy);
  await expect('D2. and a statement that does not verify is ACCEPTED and ' +
               'recorded as unverified',
               function (cc) { return kit.packed(cc, vendor, 'signature'); },
               '', function (res) {
                 return !res.attestation.verified &&
                        res.attestation.format === 'packed' &&
                        res.attestation.policy === 'off';
               });
  set('global.mode', 'product');
  t.check(policy.attestationSettings().policy === 'verify-if-present',
    'D3. product\'s by-mode is verify-if-present');
  await expect('D4. so the same statement is refused in product (0233)',
               function (cc) { return kit.packed(cc, vendor, 'signature'); },
               'STS-AUTHN-0233');
  const offWrite = config.setOverride('webauthn.attestationPolicy', 'off');
  t.check(!offWrite.ok &&
          errorCodes.codeOf(offWrite) === 'STS-CORE-0103',
    'D5. writing off in product is refused (STS-CORE-0103)',
    JSON.stringify(offWrite));
  set('global.mode', 'development');
  set('webauthn.attestationPolicy', 'off');
  set('global.mode', 'product');
  t.check(policy.attestationSettings().policy === 'verify-if-present',
    'D6. and an off stored before the switch is read as by-mode');
  clear(['webauthn.attestationPolicy']);

  set('webauthn.attestationPolicy', 'require-trusted');
  await expect('D7. require-trusted refuses none (0240)',
               function () { return kit.none(); }, 'STS-AUTHN-0240');
  await expect('D8. and self attestation (0240)',
               function (cc) { return kit.packedSelf(cc); },
               'STS-AUTHN-0240');
  await expect('D9. and a chain to a root nobody configured (0235)',
               function (cc) { return kit.packed(cc, stranger); },
               'STS-AUTHN-0235');
  await expect('D10. and accepts one that chains to a configured root',
               function (cc) { return kit.packed(cc, vendor); },
               '', trustedAs('basic'));
  set('webauthn.attestation', 'none');
  t.check(policy.creationOptions('localhost').attestation === 'direct',
    'D11. a realm that requires a trusted statement ASKS for one: none ' +
    'is sent as direct');
  clear(['webauthn.attestation']);
  set('webauthn.attestationPolicy', 'verify-if-present');
  await expect('D12. verify-if-present accepts the unanchored chain, as ' +
               'untrusted (section 7.1 step 25\'s note)',
               function (cc) { return kit.packed(cc, stranger); },
               '', untrustedAs('basic'));

  // =========================================================================
  t.log.info('=== E. the FIDO Metadata Service ===');
  // =========================================================================
  // Imported in development: the synthetic MDS chain names no CRL, which
  // product's revocation policy refuses for the BLOB (#62's rule, not this
  // one's).
  set('global.mode', 'development');
  set('webauthn.attestationPolicy', 'verify-if-present');
  set('webauthn.attestationTrustAnchors', '');
  const mds = await mdsHierarchy();
  set('risk.mdsTrustAnchors', mds.root.pem);
  await riskTerms.accept({ provider: 'fido-mds3', acceptedBy: 'a test',
                           via: 'upload' });
  const listedVendor = await kit.root('Listed Vendor');
  const u2fVendor = await kit.root('Listed U2F Vendor');
  const certifiedAaguid = nodeCrypto.randomBytes(16);
  const revokedAaguid = nodeCrypto.randomBytes(16);
  const u2fCeremony = await kit.ceremony({ aaguid: Buffer.alloc(16) });
  const u2fMade = await kit.fidoU2f(u2fCeremony, u2fVendor);
  const acki = require('../common/pki').attestationKeyIdentifier(
    u2fMade.leaf.der);
  const blob = blobOf(mds, {
    legalHeader: 'A synthetic BLOB for a test.', no: 11,
    nextUpdate: new Date(Date.now() + 30 * DAY).toISOString().slice(0, 10),
    entries: [
      { aaguid: uuid(certifiedAaguid),
        metadataStatement: { description: 'Synthetic certified key',
          attestationRootCertificates: [listedVendor.der.toString('base64')] },
        statusReports: [
          { status: 'FIDO_CERTIFIED_L2', effectiveDate: '2024-01-01' },
          { status: 'FIPS140_CERTIFIED_L2', effectiveDate: '2024-02-01' }] },
      { aaguid: uuid(revokedAaguid),
        metadataStatement: { description: 'Synthetic key, since revoked',
          attestationRootCertificates: [listedVendor.der.toString('base64')] },
        statusReports: [
          { status: 'FIDO_CERTIFIED_L1', effectiveDate: '2021-01-01' },
          { status: 'REVOKED', effectiveDate: '2025-06-01' }] },
      { attestationCertificateKeyIdentifiers: [acki],
        metadataStatement: { description: 'Synthetic U2F key',
          attestationRootCertificates: [u2fVendor.der.toString('base64')] },
        statusReports: [
          { status: 'FIDO_CERTIFIED', effectiveDate: '2019-01-01' }] }] });
  const imported = await riskDatasets.importVersion({ dataset: 'fido.mds3',
    format: 'fido-mds3-jwt', content: blob, source: 'upload' });
  t.check(imported.ok && imported.activated,
    'E0. the synthetic BLOB is imported by #62\'s ingest',
    JSON.stringify(imported));
  set('global.mode', 'product');

  const listed = function (aaguid, root, spoil) {
    const build = function (cc) { return kit.packed(cc, root, spoil); };
    build.ceremony = { aaguid: aaguid };
    return build;
  };
  await expect('E1. a listed model chains to the root MDS lists for it: ' +
               'trusted through MDS, its name and certification recorded',
               listed(certifiedAaguid, listedVendor), '',
               function (res) {
                 return trustedAs('basic', 'mds')(res) &&
                        res.attestation.model === 'Synthetic certified key' &&
                        res.attestation.certificationLevel ===
                          'FIDO_CERTIFIED_L2' &&
                        res.attestation.mdsVersion === 'no-11';
               });
  await expect('E2. a listed model whose chain does NOT reach MDS\'s roots ' +
               'is refused, even under verify-if-present (0235)',
               listed(certifiedAaguid, stranger), 'STS-AUTHN-0235');
  await expect('E3. a model MDS reports REVOKED is refused (0237)',
               listed(revokedAaguid, listedVendor), 'STS-AUTHN-0237');
  const u2fResult = await register(u2fCeremony, u2fMade);
  t.check(u2fResult.result && u2fResult.result.ok &&
          u2fResult.result.attestation.trusted &&
          u2fResult.result.attestation.anchor === 'mds' &&
          u2fResult.result.attestation.model === 'Synthetic U2F key',
    'E4. fido-u2f, which has no AAGUID, is found by its attestation key ' +
    'identifier and trusted through the root MDS lists',
    JSON.stringify(u2fResult.result));
  set('webauthn.attestationMinCertificationLevel', 'L3');
  await expect('E5. a realm requiring L3 refuses an L2 model (0238)',
               listed(certifiedAaguid, listedVendor), 'STS-AUTHN-0238');
  set('webauthn.attestationMinCertificationLevel', 'L2');
  await expect('E6. and accepts it at L2',
               listed(certifiedAaguid, listedVendor), '',
               trustedAs('basic', 'mds'));
  set('webauthn.attestationMinCertificationLevel', 'L1plus');
  const u2fPlus = await register(u2fCeremony, u2fMade);
  set('webauthn.attestationMinCertificationLevel', 'L1');
  const u2fOne = await register(u2fCeremony, u2fMade);
  t.check(u2fPlus.code === 'STS-AUTHN-0238' && u2fOne.result &&
          u2fOne.result.ok,
    'E7. the retired FIDO_CERTIFIED counts as L1: refused at L1plus, ' +
    'accepted at L1', u2fPlus.code + ' / ' + JSON.stringify(u2fOne.result));
  clear(['webauthn.attestationMinCertificationLevel']);
  set('webauthn.attestationRequireFips', true);
  await expect('E8. FIPS required: the model with a FIPS140 report is ' +
               'accepted', listed(certifiedAaguid, listedVendor), '',
               trustedAs('basic', 'mds'));
  await expect('E9. and FIPS demands a trusted statement first: a chain ' +
               'nothing anchors is refused (0235)',
               function (cc) { return kit.packed(cc, stranger); },
               'STS-AUTHN-0235');
  set('webauthn.attestationTrustAnchors', vendor.pem);
  await expect('E10. and a trusted model MDS does not list is refused ' +
               '(0238), since nothing can say it is certified',
               function (cc) { return kit.packed(cc, vendor); },
               'STS-AUTHN-0238');
  set('webauthn.attestationTrustAnchors', '');
  clear(['webauthn.attestationRequireFips']);

  // =========================================================================
  t.log.info('=== F. the AAGUID allow-list ===');
  // =========================================================================
  set('webauthn.attestationAllowedAaguids', uuid(certifiedAaguid));
  await expect('F1. the listed model is accepted',
               listed(certifiedAaguid, listedVendor), '',
               trustedAs('basic', 'mds'));
  const unlistedAaguid = nodeCrypto.randomBytes(16);
  set('webauthn.attestationTrustAnchors', vendor.pem);
  await expect('F2. another model, trusted, is refused (0236)',
               listed(unlistedAaguid, vendor), 'STS-AUTHN-0236');
  await expect('F3. the list demands a trusted statement: none is refused ' +
               'whatever the policy (0240)', function () {
                 return kit.none();
               }, 'STS-AUTHN-0240');
  await expect('F4. and a claimed AAGUID on the list with only a self ' +
               'attestation is refused (0240)', function (cc) {
                 return kit.packedSelf(cc);
               }, 'STS-AUTHN-0240');
  clear(['webauthn.attestationAllowedAaguids']);

  // =========================================================================
  t.log.info('=== G. revocation ===');
  // =========================================================================
  const undialled = function (cc) {
    return kit.packed(cc, vendor, '', 'ldap://crl.invalid/cn=crl');
  };
  await expect('G1. product: a chain whose list is at an address this ' +
               'service will not dial is refused (0239)', undialled,
               'STS-AUTHN-0239');
  await expect('G2. product: a chain naming no list at all is accepted — ' +
               'sections 8.2.1 and 8.3.1 make it optional',
               function (cc) { return kit.packed(cc, vendor); }, '',
               trustedAs('basic'));
  set('global.mode', 'development');
  set('webauthn.attestationPolicy', 'verify-if-present');
  await expect('G3. development (soft-fail): the undialled list is ' +
               'accepted', undialled, '', trustedAs('basic'));

  // =========================================================================
  t.log.info('=== H. the record reaches the key ===');
  // =========================================================================
  c = await kit.ceremony();
  r = await register(c, await kit.packed(c, vendor));
  const who = 'attestation-record-' + nodeCrypto.randomBytes(3)
    .toString('hex');
  require('../ldap/ldap_server').createUser(who, {});
  const added = credentials.addKey(who, {
    credentialId: r.verdict.credentialId,
    publicKeyJwk: r.verdict.publicKeyJwk, signCount: 0,
    aaguid: r.verdict.aaguid, attestation: r.result.attestation }, 'mfa');
  const kept = credentials.keysOf(who)[0] || {};
  t.check(added.ok && kept.attestation &&
          kept.attestation.format === 'packed' &&
          kept.attestation.trusted === true,
    'H1. credentials.addKey() keeps the attestation record on the key',
    JSON.stringify(kept.attestation || added));
  t.check(JSON.stringify(policy.ATTESTATION_FORMATS) ===
          JSON.stringify(attestation.FORMATS),
    'H2. the formats the report names are the formats the verifier knows');
  t.check(policy.report().attestationFormats.length === 8,
    'H3. all eight');

  // =========================================================================
  t.log.info('=== I. the MDS download job ===');
  // =========================================================================
  const scheduler = require('../cluster/scheduler');
  t.check(!!scheduler.job(riskDatasets.MDS_JOB),
    'I1. risk.mds-refresh is registered with the scheduler');
  let served = { ok: true, status: 200,
                 body: Buffer.from(blobOf(mds, {
                   legalHeader: 'A synthetic BLOB for a test.', no: 12,
                   nextUpdate: new Date(Date.now() + 30 * DAY)
                     .toISOString().slice(0, 10),
                   entries: [{ aaguid: uuid(certifiedAaguid),
                     metadataStatement: { description: 'Twelfth' },
                     statusReports: [] }] })) };
  const asked = [];
  const downloader = new riskDatasets.RiskDatasets(Object.assign(
    riskDatasets.RiskDatasets.defaultDeps(), {
      federationHttp: function () {
        return { fetchPublished: function (url, opts) {
          asked.push({ url: url, maxBytes: opts && opts.maxBytes });
          return Promise.resolve(served);
        } };
      } }));
  const idle = await downloader.refreshMds();
  t.check(idle.fetched === false && asked.length === 0,
    'I2. with risk.mdsUrl empty nothing is dialled', JSON.stringify(idle));
  set('risk.mdsUrl', 'https://mds.example.test/');
  const first12 = await downloader.refreshMds();
  t.check(first12.imported === true && first12.serial === 12 &&
          asked[0].url === 'https://mds.example.test/' &&
          asked[0].maxBytes === Number(config.value('risk.mdsMaxBytes')),
    'I3. a newer BLOB is downloaded through fetchPublished() with ' +
    'risk.mdsMaxBytes, and imported', JSON.stringify(first12));
  const again12 = await downloader.refreshMds();
  t.check(again12.fetched === true && again12.imported === false,
    'I4. the same serial again is not imported — not a rollback worth a ' +
    'row', JSON.stringify(again12));
  served = { ok: false, status: 0, why: 'the host is unreachable' };
  let failure = null;
  try {
    await downloader.refreshMds();
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    failure = e;
  }
  t.check(failure && errorCodes.codeOf(failure) === 'STS-RISK-0027',
    'I5. a download that fails is a failed run (STS-RISK-0027), and the ' +
    'active BLOB stays', failure && failure.message);
  clear(['risk.mdsUrl']);

  clear(TOUCHED);
  riskStore.reset();
  riskDatasets.forget();
  log.debug("Leaving run().");
}

module.exports = {
  name: 'webauthn_attestation',
  describe: 'WebAuthn attestation (#105): section 7.1\'s alg, id-length ' +
            'and BE/BS checks, PS256 and ML-DSA, all eight section 8 ' +
            'formats valid and tampered, the policy by mode, the FIDO ' +
            'Metadata Service\'s roots and status reports, the AAGUID ' +
            'allow-list, revocation, and the record on the key',
  run: run
};
