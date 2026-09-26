'use strict';
//
// File: oidcc_conformance_findings.js
//
// ===========================================================================
// WHAT THE OPENID FOUNDATION'S CONFORMANCE SUITE FOUND BEYOND FAPI (#187,
// 2026-09-24), held in process so a regression is caught without the suite's
// three containers. `tests/vendored/sts_oidcc_conformance.js` and its
// siblings are the plans themselves; this file is the regression check for
// each service fix they led to, and `oauth-oidc/CLAUDE.md` 3bp is the record.
//
//   1. RFC 6749 SECTION 6 IN EVERY MODE. A refresh token presented by a
//      client other than the one it was issued to, or asking for scope its
//      grant never carried, is refused with both compliance modes off — the
//      suite's oidcc-refresh-token redeemed the second client's token as the
//      first and was given tokens.
//   2. RFC 6749 SECTION 4.1.2 IN EVERY MODE. A code presented twice is
//      refused and what it bought is revoked, unless the realm opts back in
//      to the old courtesy with `oauth2.codeReplayIdempotent` — which RFC
//      9700 mode ignores.
//   3. A request_uri's SHA-256 fragment is checked only while
//      `oauth2.requestUriFragmentCheck` is on (OpenID Connect Core 6.2 asks
//      no OP to).
//   4. OpenID Federation 1.1 section 12.1.1.1's claims, asked of every
//      request object from a relying party registered automatically.
//   5. ECDH-ES's Concat KDF with the header's apu and apv (RFC 7518 section
//      4.6.2), which the JWE decryption left out.
// ===========================================================================

delete process.env.CONFIG_FILE;

const log = require('bunyan').createLogger({
  name: 'oidcc_conformance_findings',
  level: process.env.LOG_LEVEL || 'info' });

const realms = require('../common/realms');
const bcp = require('../oauth-oidc/oauth2_bcp');

// ONE throwaway realm for the whole file, removed at the end: a realm left
// standing is a failure in a later file (tests/sender_constraints.js), and
// every realm made — even one removed again — leaves an OpenID Federation
// registration event in the default realm's directory, whose 2,000-entry cap
// the full in-process run reaches (tests/xacml_pep_realms.js found it when
// this file made six). The sections that need a setting set it for their
// own call and clear it after.
const REALM = 'occf';
let made = false;

function ensureRealm() {
  log.debug("Entering ensureRealm().");
  if (!realms.get(REALM)) {
    realms.create({ id: REALM, label: REALM });
    made = true;
  }
  log.debug("Leaving ensureRealm().");
}

// `fn` in the realm with `overrides` set, each cleared again afterwards.
function inRealm(overrides, fn) {
  log.debug("Entering inRealm().");
  ensureRealm();
  const keys = Object.keys(overrides || {});
  keys.forEach(function (key) {
    realms.setOverride(REALM, key, String(overrides[key]));
  });
  try {
    const answer = realms.run(realms.get(REALM), fn);
    log.debug("Leaving inRealm().");
    return answer;
  } finally {
    keys.forEach(function (key) {
      realms.clearOverride(REALM, key);
    });
  }
}

// ---------------------------------------------------------------------------
// 1. RFC 6749 SECTION 6.
// ---------------------------------------------------------------------------
function checkRefreshBinding(t) {
  log.debug("Entering checkRefreshBinding().");
  t.log.info('=== 1. a refresh token is its own client\'s, in every mode ===');
  const other = inRealm({}, function () {
    return bcp.checkRefreshRequest({
      claims: { jti: 'occf-1', client_id: 'client-two', scope: 'openid' },
      clientId: 'client-one', body: {} });
  });
  t.equal(other && other.errorCode, 'STS-OAUTH-0141',
          '1a. a refresh token issued to one client and presented by ' +
          'another is refused with RFC 9700 mode off (oidcc-refresh-token)');
  t.equal(other && other.error, 'invalid_grant', '1b. as invalid_grant');
  t.check(/RFC 6749 section 6/.test(String(other && other.description)),
          '1c. and the refusal cites RFC 6749, whose rule it is',
          other && other.description);

  const own = inRealm({}, function () {
    return bcp.checkRefreshRequest({
      claims: { jti: 'occf-2', client_id: 'client-one', scope: 'openid' },
      clientId: 'client-one', body: {} });
  });
  t.equal(own && own.ok, true, '1d. its own client redeems it');

  const wider = inRealm({}, function () {
    return bcp.checkRefreshRequest({
      claims: { jti: 'occf-3', client_id: 'client-one', scope: 'openid' },
      clientId: 'client-one', body: { scope: 'openid profile' } });
  });
  t.equal(wider && wider.errorCode, 'STS-OAUTH-0142',
          '1e. a refresh asking for more than its grant is refused, ' +
          'invalid_scope, in every mode');

  const narrower = inRealm({}, function () {
    return bcp.checkRefreshRequest({
      claims: { jti: 'occf-4', client_id: 'client-one',
                scope: 'openid profile' },
      clientId: 'client-one', body: { scope: 'openid' } });
  });
  t.equal(narrower && narrower.ok, true, '1f. and a narrower one is not');

  const unnamed = inRealm({}, function () {
    return bcp.checkRefreshRequest({
      claims: { jti: 'occf-5', client_id: 'client-one' },
      clientId: '', body: {} });
  });
  t.equal(unnamed && unnamed.ok, true,
          '1g. a refresh naming no client stays RFC 9700 mode\'s refusal ' +
          '(STS-OAUTH-0140): outside it there is nobody to compare');
  log.debug("Leaving checkRefreshBinding().");
}

// ---------------------------------------------------------------------------
// 2. RFC 6749 SECTION 4.1.2.
// ---------------------------------------------------------------------------
function checkCodeSingleUse(t) {
  log.debug("Entering checkCodeSingleUse().");
  t.log.info('=== 2. a code is single use, in every mode ===');
  const replay = function () {
    return bcp.checkCodeReplay({ clientId: 'client-one', secondsAgo: 3,
                                 issuedJtis: ['at-jti', 'rt-jti', ''] });
  };

  const plain = inRealm({}, replay);
  t.equal(plain && plain.errorCode, 'STS-OAUTH-0143',
          '2a. a code presented twice is refused with RFC 9700 mode off ' +
          '(oidcc-codereuse)');
  t.equal(plain && plain.error, 'invalid_grant', '2b. as invalid_grant');
  t.equal(JSON.stringify(plain && plain.revoke),
          JSON.stringify(['at-jti', 'rt-jti']),
          '2c. naming the tokens the first redemption bought, to revoke ' +
          '(oidcc-codereuse-30seconds)');

  t.equal(inRealm({ 'oauth2.codeReplayIdempotent': true }, replay).ok,
          true,
          '2d. oauth2.codeReplayIdempotent restores the old courtesy');
  t.equal(inRealm({ 'oauth2.codeReplayIdempotent': true,
                   'oauth2.rfc9700': true }, replay).errorCode,
          'STS-OAUTH-0143',
          '2e. and RFC 9700 mode ignores it');
  log.debug("Leaving checkCodeSingleUse().");
}

// ---------------------------------------------------------------------------
// 3. OPENID CONNECT CORE 6.2's FRAGMENT, CHECKED ONLY WHILE ASKED.
// ---------------------------------------------------------------------------
function checkFragmentSetting(t) {
  log.debug("Entering checkFragmentSetting().");
  t.log.info('=== 3. a request_uri fragment is checked while the realm ' +
             'says so ===');
  const ro = require('../oauth-oidc/request_object');
  // A fragment of the right shape that is the digest of something else —
  // what the suite's request_uri modules send.
  const other = require('crypto').createHash('sha256')
    .update('random bytes').digest('base64url');
  const uri = 'https://c.example/ro#' + other;
  t.check(/SHA-256 of a different/.test(inRealm({}, function () {
    return ro.fragmentProblem(uri, 'eyJhbGciOiJub25lIn0.eyJhIjoxfQ.');
  })), '3a. by default a digest fragment of other content is refused');
  t.equal(inRealm({ 'oauth2.requestUriFragmentCheck': false }, function () {
    return ro.fragmentProblem(uri, 'eyJhbGciOiJub25lIn0.eyJhIjoxfQ.');
  }), '', '3b. with oauth2.requestUriFragmentCheck off it is only a ' +
          'version name (oidcc-request-uri-*)');
  log.debug("Leaving checkFragmentSetting().");
}

// ---------------------------------------------------------------------------
// 4. OPENID FEDERATION 1.1 SECTION 12.1.1.1 ON EVERY REQUEST OBJECT.
// ---------------------------------------------------------------------------
function checkFederationRequestObject(t) {
  log.debug("Entering checkFederationRequestObject().");
  t.log.info('=== 4. an automatic RP\'s request object, every time ===');
  const reg = require('../oidfed/oidfed_registration').OidfedRegistration;
  const now = Math.floor(Date.now() / 1000);
  const rp = 'https://rp.example.org';
  const op = 'https://op.example.org';
  const good = { aud: op, iss: rp, client_id: rp, jti: 'j1', exp: now + 60 };
  t.equal(reg.proofClaimsProblem(good, 'request', rp, op, now, 0), '',
          '4a. the claims section 12.1.1.1 asks for pass');
  const cases = [
    ['a sub', Object.assign({}, good, { sub: rp }), /no sub/],
    ['no jti', Object.assign({}, good, { jti: undefined }), /no jti/],
    ['no exp', Object.assign({}, good, { exp: undefined }), /no exp/],
    ['no iss', Object.assign({}, good, { iss: undefined }), /iss must/],
    ['no aud', Object.assign({}, good, { aud: undefined }), /aud must/],
    ['another aud', Object.assign({}, good, { aud: [op, rp] }), /aud must/]
  ];
  cases.forEach(function (c, i) {
    t.check(c[2].test(reg.proofClaimsProblem(c[1], 'request', rp, op, now,
                                             0)),
            '4' + String.fromCharCode(98 + i) + '. a request object with ' +
            c[0] + ' is refused (openid-federation-automatic-client-' +
            'registration-invalid-*)');
  });
  log.debug("Leaving checkFederationRequestObject().");
}

// ---------------------------------------------------------------------------
// 5. ECDH-ES WITH apu AND apv (RFC 7518 section 4.6.2), against Appendix C's
// own worked example: Bob's key opens a JWE whose content key is the one the
// appendix derives with PartyUInfo "Alice" and PartyVInfo "Bob".
// ---------------------------------------------------------------------------
function checkEcdhPartyInfo(t) {
  log.debug("Entering checkEcdhPartyInfo().");
  t.log.info('=== 5. ECDH-ES honours apu and apv ===');
  const nodeCrypto = require('crypto');
  const stsCrypto = require('../common/crypto');
  const aliceEpk = { kty: 'EC', crv: 'P-256',
    x: 'gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0',
    y: 'SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps' };
  const bob = { kty: 'EC', crv: 'P-256',
    x: 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
    y: 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
    d: 'VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw' };
  // RFC 7518 Appendix C's derived key.
  const cek = Buffer.from('VqqN6vgjbSBcIijNcacQGg', 'base64url');
  const header = Buffer.from(JSON.stringify({
    alg: 'ECDH-ES', enc: 'A128GCM', apu: 'QWxpY2U', apv: 'Qm9i',
    epk: aliceEpk })).toString('base64url');
  const iv = nodeCrypto.randomBytes(12);
  const cipher = nodeCrypto.createCipheriv('aes-128-gcm', cek, iv);
  cipher.setAAD(Buffer.from(header, 'ascii'));
  const ciphertext = Buffer.concat([cipher.update('{"vp_token":{}}', 'utf8'),
                                    cipher.final()]);
  const compact = [header, '', iv.toString('base64url'),
                   ciphertext.toString('base64url'),
                   cipher.getAuthTag().toString('base64url')].join('.');
  let opened = null;
  try {
    opened = stsCrypto.decryptJweCompact(compact, {
      privateKey: nodeCrypto.createPrivateKey({ key: bob, format: 'jwk' }),
      allowedAlg: ['ECDH-ES'], allowedEnc: ['A128GCM'] });
  } catch (e) {
    log.debug("Caught in checkEcdhPartyInfo(): " + ((e && e.message) || e));
    opened = { plaintext: 'refused: ' + e.message };
  }
  t.equal(opened.plaintext, '{"vp_token":{}}',
          '5a. a JWE whose header carries apu and apv is opened with the ' +
          'key RFC 7518 Appendix C derives (the conformance suite\'s ' +
          'direct_post.jwt modules)');
  log.debug("Leaving checkEcdhPartyInfo().");
}

// ---------------------------------------------------------------------------
// 6. OPENID4VCI CREDENTIAL RESPONSE ENCRYPTION TO AN EC KEY (#187): the HAIP
// issuer plan asks for ECDH-ES to a P-256 key, which this issuer refused
// (RSA-OAEP-256 only). Each algorithm is taken with the key type it fits.
// ---------------------------------------------------------------------------
function checkCredentialResponseEcdh(t) {
  log.debug("Entering checkCredentialResponseEcdh().");
  t.log.info('=== 6. a Credential Response encrypted to an EC key ===');
  const nodeCrypto = require('crypto');
  const stsCrypto = require('../common/crypto');
  const issuer = require('../oid4vc/vc_issuer');
  const pair = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = Object.assign(pair.publicKey.export({ format: 'jwk' }),
                            { alg: 'ECDH-ES' });
  t.equal(issuer.encryptionProblem({ jwk: jwk, enc: 'A128GCM' }), '',
          '6a. an EC P-256 key with ECDH-ES is accepted');
  t.check(/ECDH-ES only/.test(issuer.encryptionProblem({
    jwk: Object.assign({}, jwk, { alg: 'RSA-OAEP-256' }), enc: 'A128GCM' })),
          '6b. but not with RSA-OAEP-256, which is an RSA key\'s');
  t.check(/EC public key on/.test(issuer.encryptionProblem({
    jwk: Object.assign({}, jwk, { crv: 'secp256k1' }), enc: 'A128GCM' })),
          '6c. and not on a curve outside P-256, P-384 and P-521');
  const compact = issuer.encryptToJwe('{"credentials":[]}',
                                      { jwk: jwk, enc: 'A128GCM' });
  let opened = null;
  try {
    opened = stsCrypto.decryptJweCompact(compact, {
      privateKey: pair.privateKey,
      allowedAlg: ['ECDH-ES'], allowedEnc: ['A128GCM'] });
  } catch (e) {
    log.debug("Caught in checkCredentialResponseEcdh(): " +
              ((e && e.message) || e));
    opened = { plaintext: 'refused: ' + e.message };
  }
  t.equal(opened.plaintext, '{"credentials":[]}',
          '6d. the response is an ECDH-ES JWE the wallet\'s key opens');
  log.debug("Leaving checkCredentialResponseEcdh().");
}

function removeRealms() {
  log.debug("Entering removeRealms().");
  if (made && realms.get(REALM)) {
    realms.remove(REALM);
  }
  made = false;
  log.debug("Leaving removeRealms().");
}

function run(t) {
  log.debug("Entering run().");
  try {
    checkRefreshBinding(t);
    checkCodeSingleUse(t);
    checkFragmentSetting(t);
    checkFederationRequestObject(t);
    checkEcdhPartyInfo(t);
    checkCredentialResponseEcdh(t);
  } finally {
    removeRealms();
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'oidcc_conformance_findings',
  describe: 'the service fixes the OpenID conformance suite\'s OpenID ' +
            'Connect plans led to (#187): RFC 6749 section 6 and section ' +
            '4.1.2 in every mode',
  run: run
};
