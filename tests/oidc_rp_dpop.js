'use strict';
//
// File: oidc_rp_dpop.js
//
// ===========================================================================
// THE CONSOLE AND THE PORTAL PROVE POSSESSION OF A KEY (#34, 2026-09-15).
//
// `oauth2.refreshTokenRequireDpop` refuses to issue a refresh token to a
// request carrying no proof. `/admin` and `/portal` are ordinary OpenID
// Connect clients of this service, so without a key of their own, turning that
// setting on would have meant nobody could sign in to the console — and the
// alternative, exempting them, is the kind of hole that becomes permanent.
//
// So `common/oidc_rp.js` makes a proof. This is the one place in the service
// that does, and `oauth-oidc/dpop.ts` is the one place that checks one; a
// signer and a verifier written from the same specification by the same hand
// agree with each other far more readily than either agrees with the
// specification. **So every assertion here puts the relying party's own proof
// through the SERVER's verifier**, which is the only comparison that means
// anything.
//
// The mutual TLS half has no equivalent: the two surfaces are EXEMPT from
// `oauth2.refreshTokenRequireMtls`, because their token requests are loopback
// calls from this process to itself. `tests/sender_constraints.js` section 2
// holds that exemption and its boundary.
// ===========================================================================

delete process.env.CONFIG_FILE;

const log = require('bunyan').createLogger({ name: 'oidc_rp_dpop',
  level: process.env.LOG_LEVEL || 'info' });

const realms = require('../common/realms');
const oidcRp = require('../common/oidc_rp');
const dpop = require('../oauth-oidc/dpop');

const URL = 'https://sts.example:8081/oauth2/token';

function run(t) {
  log.debug("Entering run().");

  t.log.info('=== 1. the key ===');
  const key = oidcRp.dpopKey();
  t.equal(key.publicJwk.kty, 'EC', '1a. the key is EC');
  t.equal(key.publicJwk.crv, 'P-256', '1b. on P-256');
  t.check(/BEGIN PRIVATE KEY/.test(key.privateKeyPem),
          '1c. and the private half stays a PEM in this process',
          key.privateKeyPem.split('\n')[0]);
  t.equal(Object.keys(key.publicJwk).sort().join(','), 'crv,kty,x,y',
          '1d. THE PUBLIC MEMBERS ONLY go in the header — a private member ' +
          'there would be this client publishing its own key, and ' +
          'verifyProof() refuses one');
  const second = oidcRp.dpopKey();
  t.check(second.publicJwk.x !== key.publicJwk.x,
          '1e. and every sign-in gets a key of its own', 'two keys differ');

  t.log.info('=== 2. the proof, through the server\'s own verifier ===');
  const proof = oidcRp.dpopProof(key, 'POST', URL, {});
  const checked = dpop.verifyProof(proof, { htm: 'POST', htu: URL });
  t.equal(checked.ok, true,
          '2a. a proof this relying party made verifies where every client\'s ' +
          'proof is checked',
          checked.ok ? '' : checked.errorCode + ' ' + checked.description);
  t.equal(checked.jkt, dpop.thumbprint(key.publicJwk),
          '2b. and names the key the tokens will be bound to');

  // The three ways a proof is wrong, asked of THIS signer rather than of a
  // hand-built one: a proof that only verified against the URL it was made for
  // is what makes replaying it somewhere else useless.
  const elsewhere = dpop.verifyProof(proof, { htm: 'POST',
    htu: 'https://sts.example:8081/oauth2/introspect' });
  t.equal(elsewhere.ok, false, '2c. the same proof is refused at another URL');
  t.equal(elsewhere.errorCode, 'STS-OAUTH-0106', '2d. naming htu');
  const otherMethod = dpop.verifyProof(
    oidcRp.dpopProof(key, 'POST', URL, {}), { htm: 'GET', htu: URL });
  t.equal(otherMethod.ok, false, '2e. and with another method');
  t.equal(otherMethod.errorCode, 'STS-OAUTH-0105', '2f. naming htm');

  // The same proof twice is a replay, and the verifier remembers by `jti`. A
  // signer that reused one would be refused on its second token request — the
  // renewal — which is exactly the failure that would only show up weeks
  // later, so it is asserted here.
  const replay = dpop.verifyProof(proof, { htm: 'POST', htu: URL });
  t.equal(replay.ok, false, '2g. and presenting the SAME proof twice is a ' +
                            'replay');
  const fresh = dpop.verifyProof(oidcRp.dpopProof(key, 'POST', URL, {}),
                                 { htm: 'POST', htu: URL });
  t.equal(fresh.ok, true,
          '2h. while a new proof from the same key is accepted — which is ' +
          'what a renewal makes, months after the sign-in',
          fresh.ok ? '' : fresh.errorCode);

  t.log.info('=== 3. the nonce, and the access-token hash ===');
  // RFC 9449 section 8. `tokenRequestWithProof()` retries once with the nonce
  // the refusal carried; what is asserted here is that a nonce asked for goes
  // into the proof, which is the half of that exchange this file can see.
  const withNonce = oidcRp.dpopProof(key, 'POST', URL, { nonce: 'n-123' });
  const nonceClaims = JSON.parse(
    Buffer.from(withNonce.split('.')[1], 'base64url').toString('utf8'));
  t.equal(nonceClaims.nonce, 'n-123', '3a. a nonce the server asked for is ' +
                                      'carried in the proof');
  const header = JSON.parse(
    Buffer.from(withNonce.split('.')[0], 'base64url').toString('utf8'));
  t.equal(header.typ, 'dpop+jwt', '3b. the header names the proof type');
  t.equal(header.alg, 'ES256', '3c. and the algorithm');
  t.check(!!header.jwk && !header.jwk.d,
          '3d. and carries the public key with no private member',
          JSON.stringify(header.jwk));

  const withAth = oidcRp.dpopProof(key, 'POST', URL,
                                   { accessToken: 'an-access-token' });
  const athClaims = JSON.parse(
    Buffer.from(withAth.split('.')[1], 'base64url').toString('utf8'));
  t.equal(athClaims.ath, dpop.athOf('an-access-token'),
          '3e. and `ath` is computed the way the verifier computes it');

  t.log.info('=== 4. the realm the proof is checked in ===');
  // The jti replay store is per realm, like every store here. A proof made for
  // one realm's token endpoint is not spent in another, which is what lets the
  // console sign in to two realms in the same browser.
  // Removed at the foot of this section: a throwaway realm left standing is a
  // failure in whichever file runs next and asserts there is only the default
  // one.
  const madeRealm = !realms.get('rpd-realm');
  if (madeRealm) {
    realms.create({ id: 'rpd-realm', label: 'rpd-realm' });
  }
  const shared = oidcRp.dpopProof(key, 'POST', URL, {});
  const inDefault = dpop.verifyProof(shared, { htm: 'POST', htu: URL });
  const inRealm = realms.run(realms.get('rpd-realm'), function () {
    return dpop.verifyProof(shared, { htm: 'POST', htu: URL });
  });
  t.equal(inDefault.ok, true, '4a. a proof verifies in the default realm');
  t.equal(inRealm.ok, true,
          '4b. and the same one verifies in another realm, because the ' +
          'replay store it is spent in is that realm\'s',
          inRealm.ok ? '' : inRealm.errorCode);
  if (madeRealm) {
    realms.remove('rpd-realm');
  }

  log.debug("Leaving run().");
}

module.exports = {
  name: 'oidc_rp_dpop',
  describe: 'the console and portal relying party makes DPoP proofs, and ' +
            'the server\'s own verifier accepts them',
  run: run
};
