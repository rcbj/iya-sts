'use strict';
//
// File: client_attestation.js
//
// ===========================================================================
// OAUTH 2.0 ATTESTATION-BASED CLIENT AUTHENTICATION, IN PROCESS (#229,
// draft-ietf-oauth-attestation-based-client-auth-11).
//
// `oauth-oidc/client_attestation.ts` against requests built here, with every
// key made at run time (a certificate authority and an attester by
// node-forge, client instance keys by node, a post-quantum one by
// `common/pq_jose.js`) and every JWT signed by THIS FILE's own signer rather
// than `common/crypto.js`, so the verifier is checked against an
// implementation that is not itself:
//
//   A. trust: a configured JWKS, an x5c path to a configured anchor, a
//      self-signed leaf and a stranger's chain refused, nobody trusted;
//   B. the attestation's own checks — typ, alg, claims, expiry, the
//      freshness window (use_fresh_attestation), a private cnf key, `sub`;
//   C. the PoP — typ, the attested key, audience, iat window, and a
//      post-quantum (ML-DSA-44) client instance key;
//   D. challenges and replay — required, unknown, spent once, the PoP's jti
//      spent once, a fresh challenge on every response;
//   E. the header fields — one each, token68;
//   F. the DPoP combined mode, and the two declared methods held to their
//      own proof;
//   G. `requestRefusal()`, `bindingRefusal()` and the metadata;
//   H. `client_auth.js` hands both methods to it, `oauth2_bcp.js` counts
//      them as a credential on file, and FAPI 2.0 lists them only behind
//      its setting.
//
// The whole flow over HTTP — challenge endpoint, PAR, token, refresh — is
// `tests/vendored/sts_client_attestation.js`.
// ===========================================================================

delete process.env.CONFIG_FILE;

const crypto = require('crypto');
const { EventEmitter } = require('events');
const forge = require('node-forge');

const config = require('../common/config');
const errorCodes = require('../common/error_codes');
const pqJose = require('../common/pq_jose');
const attestation = require('../oauth-oidc/client_attestation');
const clientAuth = require('../oauth-oidc/client_auth');
const bcp = require('../oauth-oidc/oauth2_bcp');
const fapi = require('../oauth-oidc/fapi');

const log = require('bunyan').createLogger({ name: 'client_attestation',
  level: process.env.LOG_LEVEL || 'info' });

const ISSUER = 'https://as.example.test';
const CLIENT = 'https://wallet.example.test';
const TYP = 'oauth-client-attestation+jwt';
const POP_TYP = 'oauth-client-attestation-pop+jwt';
const SETTINGS = ['oauth2.clientAttestationTrustAnchors',
                  'oauth2.clientAttestationTrustedKeys',
                  'oauth2.clientAttestationChallengeRequired',
                  'oauth2.clientAttestationMaxAgeS',
                  'oauth2.fapi', 'oauth2.fapiAllowClientAttestation'];

// ---------------------------------------------------------------------------
// THIS FILE'S OWN JWS SIGNER: ES256 as RFC 7518 section 3.4's r||s, RS256
// as PKCS#1 v1.5, and ML-DSA through the vendored engine the service also
// uses (there is only one ML-DSA here to use).
// ---------------------------------------------------------------------------
function b64u(value) {
  log.debug("Entering b64u().");
  log.debug("Leaving b64u().");
  return Buffer.from(typeof value === 'string' ? value
                                               : JSON.stringify(value))
    .toString('base64url');
}

function sign(header, claims, key) {
  log.debug("Entering sign(). alg=" + header.alg);
  const input = b64u(header) + '.' + b64u(claims);
  let signature;
  if (header.alg === 'ES256') {
    signature = crypto.sign('sha256', Buffer.from(input),
                            { key: key, dsaEncoding: 'ieee-p1363' });
  } else if (header.alg === 'RS256') {
    signature = crypto.sign('sha256', Buffer.from(input), key);
  } else if (header.alg === 'HS256') {
    // The MAC a refusal is asked about: keyed by anything, since nothing
    // here will verify it.
    signature = crypto.createHmac('sha256', 'a shared secret nobody holds')
      .update(input).digest();
  } else {
    signature = Buffer.from(pqJose.sign(header.alg, key, Buffer.from(input)));
  }
  log.debug("Leaving sign().");
  return input + '.' + signature.toString('base64url');
}

function ecKey() {
  log.debug("Entering ecKey().");
  const pair = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = pair.publicKey.export({ format: 'jwk' });
  log.debug("Leaving ecKey().");
  return { privateKey: pair.privateKey, jwk: jwk };
}

function now() {
  log.debug("Entering now().");
  log.debug("Leaving now().");
  return Math.floor(Date.now() / 1000);
}

// A certificate authority and an attester certificate it issued, both RSA
// (forge makes RSA certificates), and a stranger's authority beside them.
function certificate(subject, publicKey, issuer, signingKey, ca) {
  log.debug("Entering certificate(). " + subject);
  const cert = forge.pki.createCertificate();
  cert.publicKey = publicKey;
  cert.serialNumber = '0' + crypto.randomBytes(8).toString('hex');
  cert.validity.notBefore = new Date(Date.now() - 3600 * 1000);
  cert.validity.notAfter = new Date(Date.now() + 86400 * 1000);
  cert.setSubject([{ name: 'commonName', value: subject }]);
  cert.setIssuer([{ name: 'commonName', value: issuer }]);
  cert.setExtensions(ca
    ? [{ name: 'basicConstraints', cA: true, critical: true },
       { name: 'keyUsage', keyCertSign: true, cRLSign: true,
         critical: true }]
    : [{ name: 'basicConstraints', cA: false },
       { name: 'keyUsage', digitalSignature: true, critical: true }]);
  cert.sign(signingKey, forge.md.sha256.create());
  log.debug("Leaving certificate().");
  return cert;
}

function derB64(cert) {
  log.debug("Entering derB64().");
  log.debug("Leaving derB64().");
  return forge.util.encode64(forge.asn1.toDer(
    forge.pki.certificateToAsn1(cert)).getBytes());
}

function pki() {
  log.debug("Entering pki().");
  const caKeys = forge.pki.rsa.generateKeyPair(2048);
  const ca = certificate('attester root', caKeys.publicKey, 'attester root',
                         caKeys.privateKey, true);
  const leafKeys = forge.pki.rsa.generateKeyPair(2048);
  const leaf = certificate('wallet attester', leafKeys.publicKey,
                           'attester root', caKeys.privateKey, false);
  const strangerKeys = forge.pki.rsa.generateKeyPair(2048);
  const stranger = certificate('stranger root', strangerKeys.publicKey,
                               'stranger root', strangerKeys.privateKey, true);
  log.debug("Leaving pki().");
  return {
    caPem: forge.pki.certificateToPem(ca),
    caDer: derB64(ca),
    caKey: crypto.createPrivateKey(forge.pki.privateKeyToPem(
      caKeys.privateKey)),
    leafDer: derB64(leaf),
    leafKey: crypto.createPrivateKey(forge.pki.privateKeyToPem(
      leafKeys.privateKey)),
    strangerPem: forge.pki.certificateToPem(stranger)
  };
}

// A request as express hands one over, with a response whose finish settles
// the used-assertion claims.
function request(headers) {
  log.debug("Entering request().");
  const res = new EventEmitter();
  res.statusCode = 200;
  res.headersSent = false;
  res.sent = {};
  res.set = function (name, value) {
    res.sent[String(name).toLowerCase()] = value;
    return res;
  };
  const raw = [];
  const lower = {};
  (headers || []).forEach(function (pair) {
    raw.push(pair[0], pair[1]);
    const name = pair[0].toLowerCase();
    lower[name] = lower[name] === undefined ? pair[1]
                                            : lower[name] + ', ' + pair[1];
  });
  log.debug("Leaving request().");
  return { headers: lower, rawHeaders: raw, res: res };
}

function finish(req, status) {
  log.debug("Entering finish(). " + status);
  req.res.statusCode = status;
  req.res.emit('finish');
  log.debug("Leaving finish().");
}

function later() {
  log.debug("Entering later().");
  log.debug("Leaving later().");
  return new Promise(function (resolve) {
    setTimeout(resolve, 20);
  });
}

// An attestation by the JWKS-trusted attester (`opts.x5c` for the PKI one).
function attestationFor(world, instance, opts) {
  log.debug("Entering attestationFor().");
  const o = opts || {};
  const header = Object.assign({ typ: TYP, alg: o.x5c ? 'RS256' : 'ES256' },
    o.x5c ? { x5c: o.x5c } : { kid: 'attester-1' }, o.header || {});
  const claims = Object.assign({ iss: 'https://attester.example.test',
    sub: CLIENT, iat: now(), exp: now() + 600,
    cnf: { jwk: instance.jwk } }, o.claims || {});
  (o.drop || []).forEach(function (name) {
    delete claims[name];
  });
  log.debug("Leaving attestationFor().");
  return sign(header, claims, o.signWith ||
              (o.x5c ? world.pki.leafKey : world.attester.privateKey));
}

function popFor(instance, opts) {
  log.debug("Entering popFor().");
  const o = opts || {};
  const header = Object.assign({ typ: POP_TYP, alg: 'ES256' },
                               o.header || {});
  const claims = Object.assign({ aud: ISSUER, iat: now(),
    jti: crypto.randomUUID() }, o.claims || {});
  (o.drop || []).forEach(function (name) {
    delete claims[name];
  });
  log.debug("Leaving popFor().");
  return sign(header, claims, o.signWith || instance.privateKey);
}

function ask(req, method) {
  log.debug("Entering ask().");
  log.debug("Leaving ask().");
  return attestation.verifyRequest(req, { method: method || attestation.ATTEST,
                                          clientId: CLIENT, issuer: ISSUER });
}

function trustJwks(world) {
  log.debug("Entering trustJwks().");
  config.setOverride('oauth2.clientAttestationTrustedKeys', JSON.stringify({
    keys: [Object.assign({ kid: 'attester-1' }, world.attester.jwk)] }));
  log.debug("Leaving trustJwks().");
}

async function trust(t, world) {
  log.debug("Entering trust().");
  t.log.info('=== A. who is trusted ===');
  t.check(!attestation.configured(),
          'with both settings empty nobody is trusted', null);
  t.equal(JSON.stringify(attestation.metadata(ISSUER + '/oauth2/challenge')),
          '{}', 'and the metadata says nothing: no method, no challenge ' +
          'endpoint, no algorithm lists');
  const nobody = await ask(request([
    ['OAuth-Client-Attestation', attestationFor(world, world.instance)],
    ['OAuth-Client-Attestation-PoP', popFor(world.instance)]]));
  t.check(!nobody.ok && nobody.errorCode === 'STS-OAUTH-0724',
          'an attestation in a realm that trusts no attester is refused by ' +
          'name (STS-OAUTH-0724)', nobody);

  trustJwks(world);
  config.setOverride('oauth2.clientAttestationChallengeRequired', 'false');
  t.check(attestation.configured(), 'a configured JWKS trusts an attester',
          null);
  const byKey = await ask(request([
    ['OAuth-Client-Attestation', attestationFor(world, world.instance)],
    ['OAuth-Client-Attestation-PoP', popFor(world.instance)]]));
  t.check(byKey.ok && byKey.jkt, 'an attestation signed by the configured ' +
          'key and a PoP by the key it binds authenticate the client', byKey);

  const wrongKid = await ask(request([
    ['OAuth-Client-Attestation', attestationFor(world, world.instance,
      { header: { kid: 'nobody' } })],
    ['OAuth-Client-Attestation-PoP', popFor(world.instance)]]));
  t.check(!wrongKid.ok && wrongKid.errorCode === 'STS-OAUTH-0726',
          'a kid no configured key carries is refused (STS-OAUTH-0726)',
          wrongKid);
  const forged = await ask(request([
    ['OAuth-Client-Attestation', attestationFor(world, world.instance,
      { signWith: ecKey().privateKey })],
    ['OAuth-Client-Attestation-PoP', popFor(world.instance)]]));
  t.check(!forged.ok && forged.errorCode === 'STS-OAUTH-0726',
          'an attestation signed by another key under the trusted kid does ' +
          'not verify (STS-OAUTH-0726)', forged);

  config.setOverride('oauth2.clientAttestationTrustAnchors',
                     world.pki.caPem);
  const byPath = await ask(request([
    ['OAuth-Client-Attestation', attestationFor(world, world.instance,
      { x5c: [world.pki.leafDer] })],
    ['OAuth-Client-Attestation-PoP', popFor(world.instance)]]));
  t.check(byPath.ok, 'an attestation whose x5c leaf the configured anchor ' +
          'issued authenticates the client (section 10.8, HAIP 4.4.1)',
          byPath);
  const selfSigned = await ask(request([
    ['OAuth-Client-Attestation', attestationFor(world, world.instance,
      { x5c: [world.pki.caDer], signWith: world.pki.caKey })],
    ['OAuth-Client-Attestation-PoP', popFor(world.instance)]]));
  t.check(!selfSigned.ok && selfSigned.errorCode === 'STS-OAUTH-0725' &&
          /self-signed/.test(selfSigned.description),
          'a self-signed signing certificate is refused even when it IS the ' +
          'anchor (HAIP 1.0 section 4.4.1)', selfSigned);
  config.setOverride('oauth2.clientAttestationTrustAnchors',
                     world.pki.strangerPem);
  const stranger = await ask(request([
    ['OAuth-Client-Attestation', attestationFor(world, world.instance,
      { x5c: [world.pki.leafDer] })],
    ['OAuth-Client-Attestation-PoP', popFor(world.instance)]]));
  t.check(!stranger.ok && stranger.errorCode === 'STS-OAUTH-0725',
          'an x5c that does not chain to a configured anchor is refused ' +
          '(STS-OAUTH-0725)', stranger);
  config.setOverride('oauth2.clientAttestationTrustAnchors',
                     world.pki.caPem);
  log.debug("Leaving trust().");
}

async function attestationChecks(t, world) {
  log.debug("Entering attestationChecks().");
  t.log.info('=== B. the Client Attestation JWT ===');
  const cases = [
    { what: 'a typ other than oauth-client-attestation+jwt',
      opts: { header: { typ: 'JWT' } }, code: 'STS-OAUTH-0722' },
    { what: 'an HMAC alg', opts: { header: { alg: 'HS256' } },
      code: 'STS-OAUTH-0723' },
    { what: 'no sub', opts: { drop: ['sub'] }, code: 'STS-OAUTH-0727' },
    { what: 'no exp', opts: { drop: ['exp'] }, code: 'STS-OAUTH-0727' },
    { what: 'no cnf', opts: { drop: ['cnf'] }, code: 'STS-OAUTH-0727' },
    { what: 'an exp in the past',
      opts: { claims: { exp: now() - 3600 } }, code: 'STS-OAUTH-0728' },
    { what: 'an iat in the future',
      opts: { claims: { iat: now() + 3600 } }, code: 'STS-OAUTH-0728' },
    { what: 'a cnf.jwk carrying its private half',
      opts: { claims: { cnf: { jwk: Object.assign({ d: 'AAAA' },
        world.instance.jwk) } } }, code: 'STS-OAUTH-0729' },
    { what: 'a sub naming another client',
      opts: { claims: { sub: 'https://other.example.test' } },
      code: 'STS-OAUTH-0731' }
  ];
  for (const one of cases) {
    const r = await ask(request([
      ['OAuth-Client-Attestation', attestationFor(world, world.instance,
                                                  one.opts)],
      ['OAuth-Client-Attestation-PoP', popFor(world.instance)]]));
    t.check(!r.ok && r.errorCode === one.code && r.error === 'invalid_client',
            'an attestation with ' + one.what + ' is refused invalid_client (' +
            one.code + ')', r);
  }
  config.setOverride('oauth2.clientAttestationMaxAgeS', '600');
  const stale = await ask(request([
    ['OAuth-Client-Attestation', attestationFor(world, world.instance,
      { claims: { iat: now() - 3600, exp: now() + 3600 } })],
    ['OAuth-Client-Attestation-PoP', popFor(world.instance)]]));
  t.check(!stale.ok && stale.errorCode === 'STS-OAUTH-0730' &&
          stale.error === 'use_fresh_attestation' && stale.status === 400,
          'an attestation older than oauth2.clientAttestationMaxAgeS is ' +
          'answered 400 use_fresh_attestation (section 7.4)', stale);
  config.clearOverride('oauth2.clientAttestationMaxAgeS');
  log.debug("Leaving attestationChecks().");
}

async function popChecks(t, world) {
  log.debug("Entering popChecks().");
  t.log.info('=== C. the Client Attestation PoP JWT ===');
  const good = attestationFor(world, world.instance);
  const cases = [
    { what: 'a typ other than oauth-client-attestation-pop+jwt',
      opts: { header: { typ: 'JWT' } }, code: 'STS-OAUTH-0733' },
    { what: 'a signature by a key the attestation does not bind',
      opts: { signWith: ecKey().privateKey }, code: 'STS-OAUTH-0734' },
    { what: 'no jti', opts: { drop: ['jti'] }, code: 'STS-OAUTH-0735' },
    { what: 'no aud', opts: { drop: ['aud'] }, code: 'STS-OAUTH-0735' },
    { what: 'the token endpoint as its audience',
      opts: { claims: { aud: ISSUER + '/oauth2/token' } },
      code: 'STS-OAUTH-0736' },
    { what: 'two audiences',
      opts: { claims: { aud: [ISSUER, 'https://elsewhere.test'] } },
      code: 'STS-OAUTH-0736' },
    { what: 'an iat ten minutes old',
      opts: { claims: { iat: now() - 600 } }, code: 'STS-OAUTH-0737' },
    { what: 'an iat in the future',
      opts: { claims: { iat: now() + 600 } }, code: 'STS-OAUTH-0737' }
  ];
  for (const one of cases) {
    const r = await ask(request([
      ['OAuth-Client-Attestation', good],
      ['OAuth-Client-Attestation-PoP', popFor(world.instance, one.opts)]]));
    t.check(!r.ok && r.errorCode === one.code,
            'a PoP with ' + one.what + ' is refused (' + one.code + ')', r);
  }
  const oneAud = await ask(request([
    ['OAuth-Client-Attestation', good],
    ['OAuth-Client-Attestation-PoP', popFor(world.instance,
      { claims: { aud: [ISSUER] } })]]));
  t.check(oneAud.ok, 'an aud that is a one-member array naming the issuer ' +
          'is the single audience section 5.1 asks for', oneAud);

  // A POST-QUANTUM CLIENT INSTANCE KEY. The attestation binds an AKP key and
  // the PoP is signed with ML-DSA-44 — nothing in the method is classical.
  const pq = pqJose.generate('ML-DSA-44');
  const pqInstance = { jwk: pqJose.akpPublicJwk('ML-DSA-44', pq.pub),
                       privateKey: pq.priv };
  const pqAnswer = await ask(request([
    ['OAuth-Client-Attestation', attestationFor(world, pqInstance)],
    ['OAuth-Client-Attestation-PoP', popFor(pqInstance,
      { header: { alg: 'ML-DSA-44' } })]]));
  t.check(pqAnswer.ok, 'an ML-DSA-44 client instance key proves possession ' +
          'with an ML-DSA-44 PoP (post-quantum, end to end)', pqAnswer);
  log.debug("Leaving popChecks().");
}

async function challengesAndReplay(t, world) {
  log.debug("Entering challengesAndReplay().");
  t.log.info('=== D. challenges, and each PoP once ===');
  config.clearOverride('oauth2.clientAttestationChallengeRequired');
  t.check(attestation.challengeRequired(),
          'a challenge is REQUIRED by default', null);
  const good = attestationFor(world, world.instance);
  const none = request([['OAuth-Client-Attestation', good],
                        ['OAuth-Client-Attestation-PoP',
                         popFor(world.instance)]]);
  const noneAnswer = await ask(none);
  t.check(!noneAnswer.ok && noneAnswer.errorCode === 'STS-OAUTH-0738' &&
          noneAnswer.error === 'use_attestation_challenge' &&
          noneAnswer.status === 400,
          'a PoP without a challenge is 400 use_attestation_challenge ' +
          '(section 6.1)', noneAnswer);
  const offered = none.res.sent['oauth-client-attestation-challenge'];
  t.check(typeof offered === 'string' &&
          /^[A-Za-z0-9_-]{16,512}$/.test(offered),
          'and that refusal carries a fresh challenge in ' +
          'OAuth-Client-Attestation-Challenge', offered);
  finish(none, 400);

  const unknown = await ask(request([
    ['OAuth-Client-Attestation', good],
    ['OAuth-Client-Attestation-PoP', popFor(world.instance,
      { claims: { challenge: 'not-one-this-server-issued-ever' } })]]));
  t.check(!unknown.ok && unknown.errorCode === 'STS-OAUTH-0739' &&
          unknown.error === 'use_attestation_challenge',
          'a challenge this realm never issued is refused ' +
          '(STS-OAUTH-0739)', unknown);

  const challenge = attestation.issueChallenge();
  const pop = popFor(world.instance, { claims: { challenge: challenge } });
  const first = request([['OAuth-Client-Attestation', good],
                         ['OAuth-Client-Attestation-PoP', pop]]);
  const firstAnswer = await ask(first);
  t.check(firstAnswer.ok, 'a PoP carrying an issued challenge is accepted',
          firstAnswer);
  t.check(first.stsClientAttestation &&
          first.stsClientAttestation.jkt === firstAnswer.jkt,
          'and the verified instance key is left on the request for the ' +
          'bindings (sections 10.3 and 10.4)', first.stsClientAttestation);
  t.check(typeof first.res.sent['oauth-client-attestation-challenge'] ===
            'string' &&
          first.res.sent['oauth-client-attestation-challenge'] !== challenge,
          'a SUCCESS carries a fresh challenge too (section 6.2), so a ' +
          'single-use one never leaves the client without one', null);
  const again = await ask(first);
  t.check(again === firstAnswer || again.ok,
          'the same request asked twice (the RFC 9700 policy, then the ' +
          'observation) gets ONE answer, not a replay of itself', again);
  finish(first, 200);
  await later();

  const replay = await ask(request([['OAuth-Client-Attestation', good],
                                    ['OAuth-Client-Attestation-PoP', pop]]));
  t.check(!replay.ok && replay.errorCode === 'STS-OAUTH-0740',
          'the same PoP on another request is a replay (section 12.1)',
          replay);
  const reused = await ask(request([
    ['OAuth-Client-Attestation', good],
    ['OAuth-Client-Attestation-PoP', popFor(world.instance,
      { claims: { challenge: challenge } })]]));
  t.check(!reused.ok && reused.errorCode === 'STS-OAUTH-0739',
          'and a new PoP carrying the spent challenge is refused: each ' +
          'challenge is good for one request', reused);

  const released = attestation.issueChallenge();
  const failed = request([['OAuth-Client-Attestation', good],
                          ['OAuth-Client-Attestation-PoP', popFor(
                            world.instance,
                            { claims: { challenge: released } })]]);
  t.check((await ask(failed)).ok, 'a verified PoP on a request that then ' +
          'fails', null);
  finish(failed, 400);
  await later();
  const retried = await ask(request([
    ['OAuth-Client-Attestation', good],
    ['OAuth-Client-Attestation-PoP', popFor(world.instance,
      { claims: { challenge: released } })]]));
  t.check(retried.ok, 'leaves its challenge unspent: a request that bought ' +
          'nothing has not used it (the used-assertion history\'s rule)',
          retried);
  log.debug("Leaving challengesAndReplay().");
}

async function fields(t, world) {
  log.debug("Entering fields().");
  t.log.info('=== E. the header fields ===');
  const good = attestationFor(world, world.instance);
  const twice = await ask(request([
    ['OAuth-Client-Attestation', good], ['OAuth-Client-Attestation', good],
    ['OAuth-Client-Attestation-PoP', popFor(world.instance,
      { claims: { challenge: attestation.issueChallenge() } })]]));
  t.check(!twice.ok && twice.errorCode === 'STS-OAUTH-0720',
          'two OAuth-Client-Attestation fields are refused (section 7.1 ' +
          'item 1)', twice);
  const notToken68 = await ask(request([
    ['OAuth-Client-Attestation', good + ' x'],
    ['OAuth-Client-Attestation-PoP', popFor(world.instance)]]));
  t.check(!notToken68.ok && notToken68.errorCode === 'STS-OAUTH-0720',
          'a field value outside token68 is refused', notToken68);
  const pop = popFor(world.instance,
                     { claims: { challenge: attestation.issueChallenge() } });
  const twoPops = await ask(request([
    ['OAuth-Client-Attestation', good],
    ['OAuth-Client-Attestation-PoP', pop],
    ['OAuth-Client-Attestation-PoP', pop]]));
  t.check(!twoPops.ok && twoPops.errorCode === 'STS-OAUTH-0732',
          'two OAuth-Client-Attestation-PoP fields are refused (section 7.2 ' +
          'item 1)', twoPops);
  const noProof = await ask(request([['OAuth-Client-Attestation', good]]),
                            '');
  t.check(!noProof.ok && noProof.errorCode === 'STS-OAUTH-0743',
          'an attestation with neither a PoP nor a DPoP proof is refused',
          noProof);
  const absent = await ask(request([]));
  t.check(!absent.ok && absent.errorCode === 'STS-OAUTH-0751',
          'a declared attestation client sending no attestation is refused ' +
          '(STS-OAUTH-0751)', absent);
  log.debug("Leaving fields().");
}

async function combined(t, world) {
  log.debug("Entering combined().");
  t.log.info('=== F. the DPoP combined mode ===');
  const good = attestationFor(world, world.instance);
  const dpopOnly = function (jkt) {
    const req = request([['OAuth-Client-Attestation', good],
                         ['DPoP', 'a.proof.verified-by-the-endpoint']]);
    if (jkt) {
      req.stsDpopJkt = jkt;
    }
    return req;
  };
  const jkt = (await ask(request([
    ['OAuth-Client-Attestation', good],
    ['OAuth-Client-Attestation-PoP', popFor(world.instance, { claims: {
      challenge: attestation.issueChallenge() } })]]))).jkt;
  const unverified = await ask(dpopOnly(''), attestation.ATTEST_DPOP);
  t.check(!unverified.ok && unverified.errorCode === 'STS-OAUTH-0744',
          'combined mode where the endpoint verified no DPoP proof is ' +
          'refused (introspection, revocation, CIBA)', unverified);
  const otherKey = await ask(dpopOnly('another-key-thumbprint'),
                             attestation.ATTEST_DPOP);
  t.check(!otherKey.ok && otherKey.errorCode === 'STS-OAUTH-0745',
          'a DPoP key that is not the attested key is refused (section 7.3 ' +
          'item 4)', otherKey);
  const sameKey = await ask(dpopOnly(jkt), attestation.ATTEST_DPOP);
  t.check(sameKey.ok && sameKey.method === attestation.ATTEST_DPOP,
          'the attested key proving itself by DPoP authenticates the client ' +
          'with no PoP JWT and no challenge (section 5.2)', sameKey);
  const declaredNormal = await ask(dpopOnly(jkt), attestation.ATTEST);
  t.check(!declaredNormal.ok && declaredNormal.errorCode === 'STS-OAUTH-0746',
          'a client that declared attest_jwt_client_auth may not switch to ' +
          'the combined mode', declaredNormal);
  const declaredCombined = await ask(request([
    ['OAuth-Client-Attestation', good],
    ['OAuth-Client-Attestation-PoP', popFor(world.instance)]]),
    attestation.ATTEST_DPOP);
  t.check(!declaredCombined.ok &&
          declaredCombined.errorCode === 'STS-OAUTH-0746',
          'nor one that declared attest_jwt_client_auth_dpop send a PoP JWT',
          declaredCombined);
  log.debug("Leaving combined().");
}

async function policies(t, world) {
  log.debug("Entering policies().");
  t.log.info('=== G. the refusals the endpoints ask, and the bindings ===');
  const declared = await attestation.requestRefusal({
    registered: { token_endpoint_auth_method: attestation.ATTEST },
    observation: { authenticated: false, errorCode: 'STS-OAUTH-0738',
                   oauthError: 'use_attestation_challenge', status: 400,
                   why: 'no challenge.' },
    request: request([]), clientId: CLIENT, issuer: ISSUER });
  t.check(declared && declared.status === 400 &&
          declared.error === 'use_attestation_challenge' &&
          declared.errorCode === 'STS-OAUTH-0738',
          'a DECLARED attestation client that did not authenticate is ' +
          'refused with the verifier\'s own error and status, in every mode',
          declared);
  t.equal(await attestation.requestRefusal({
    registered: { token_endpoint_auth_method: attestation.ATTEST },
    observation: { authenticated: true }, request: request([]),
    clientId: CLIENT, issuer: ISSUER }), null,
  'and one that did is not');
  const signal = await attestation.requestRefusal({
    registered: { token_endpoint_auth_method: 'private_key_jwt' },
    observation: { authenticated: true },
    request: request([['OAuth-Client-Attestation',
      attestationFor(world, world.instance, { drop: ['cnf'] })],
                      ['OAuth-Client-Attestation-PoP',
                       popFor(world.instance)]]),
    clientId: CLIENT, issuer: ISSUER });
  t.check(signal && signal.errorCode === 'STS-OAUTH-0727',
          'an attestation sent as section 7.6\'s additional signal by a ' +
          'private_key_jwt client is verified, and refused if it does not ' +
          'hold', signal);
  t.equal(await attestation.requestRefusal({
    registered: { token_endpoint_auth_method: 'private_key_jwt' },
    observation: { authenticated: true }, request: request([]),
    clientId: CLIENT, issuer: ISSUER }), null,
  'and a request with no attestation is not asked about one');

  const req = request([]);
  req.stsClientAttestation = { jkt: 'instance-a' };
  t.equal(attestation.bindingRefusal(req, '', 'refresh token'), null,
          'an unbound refresh token needs no attestation');
  t.equal(attestation.bindingRefusal(req, 'instance-a', 'refresh token'),
          null, 'a bound one redeemed by the same instance key is allowed');
  const other = attestation.bindingRefusal(req, 'instance-b',
                                           'refresh token');
  t.check(other && other.errorCode === 'STS-OAUTH-0748' &&
          other.error === 'invalid_grant',
          'one bound to another instance key is refused (section 10.3)',
          other);
  const codeBound = attestation.bindingRefusal(request([]), 'instance-a',
                                               'authorization code');
  t.check(codeBound && codeBound.errorCode === 'STS-OAUTH-0749',
          'and a code bound through PAR, redeemed with no attestation, is ' +
          'refused (section 10.4)', codeBound);

  const metadata = attestation.metadata(ISSUER + '/oauth2/challenge');
  t.check(metadata.challenge_endpoint === ISSUER + '/oauth2/challenge' &&
          metadata.client_attestation_signing_alg_values_supported
            .indexOf('ES256') >= 0 &&
          metadata.client_attestation_signing_alg_values_supported
            .indexOf('HS256') < 0 &&
          metadata.client_attestation_pop_signing_alg_values_supported
            .indexOf('ML-DSA-44') >= 0 &&
          JSON.stringify(metadata.client_attestation_pop_methods_supported) ===
            JSON.stringify(['attestation_pop_jwt', 'dpop_combined', 'none']),
          'a realm that trusts an attester advertises the challenge ' +
          'endpoint and section 8\'s lists, asymmetric and post-quantum ' +
          'included', metadata);
  log.debug("Leaving policies().");
}

async function wiring(t, world) {
  log.debug("Entering wiring().");
  t.log.info('=== H. client_auth.js, oauth2_bcp.js and FAPI ===');
  t.check(clientAuth.METHODS.indexOf('attest_jwt_client_auth') >= 0 &&
          clientAuth.METHODS.indexOf('attest_jwt_client_auth_dpop') >= 0 &&
          clientAuth.isAsymmetric('attest_jwt_client_auth'),
          'both methods are ones client_auth.js verifies, and asymmetric',
          clientAuth.METHODS);
  t.check(bcp.credentialOnFile({ known: true,
    token_endpoint_auth_method: 'attest_jwt_client_auth' }),
          'a declared attestation client always has something to be ' +
          'checked against: the realm\'s attesters', null);
  const through = await clientAuth.verify({
    method: 'attest_jwt_client_auth', clientId: CLIENT, issuer: ISSUER,
    request: request([['OAuth-Client-Attestation',
                       attestationFor(world, world.instance)],
                      ['OAuth-Client-Attestation-PoP', popFor(
                        world.instance, { claims: {
                          challenge: attestation.issueChallenge() } })]]) });
  t.check(through.ok && through.method === 'attest_jwt_client_auth',
          'client_auth.verify() hands the method to the attestation ' +
          'verifier', through);

  // The profile is set AMBIENT here, as a named authorization server's is:
  // `oauth2.fapi` carries conditions on its write this file is not about.
  const underFapi2 = function () {
    return fapi.withProfile('2-security', function () {
      return fapi.clientAuthenticationRefusal('attest_jwt_client_auth');
    });
  };
  t.check(underFapi2(), 'FAPI 2.0 refuses attestation as written (section ' +
          '5.3.2.1 item 6)', null);
  config.setOverride('oauth2.fapiAllowClientAttestation', 'true');
  t.equal(underFapi2(), null,
          'and accepts it where the realm runs HAIP\'s arrangement ' +
          '(oauth2.fapiAllowClientAttestation)');
  t.check(fapi.withProfile('1-advanced', function () {
    return fapi.clientAuthenticationRefusal('attest_jwt_client_auth');
  }), 'FAPI 1.0 never does', null);
  config.clearOverride('oauth2.fapiAllowClientAttestation');

  ['STS-OAUTH-0720', 'STS-OAUTH-0730', 'STS-OAUTH-0738', 'STS-OAUTH-0745',
   'STS-OAUTH-0751'].forEach(function (code) {
    t.check(errorCodes.isKnown(code), code + ' is registered', null);
  });
  log.debug("Leaving wiring().");
}

async function run(t) {
  log.debug("Entering run().");
  const world = { pki: pki(), attester: ecKey(), instance: ecKey() };
  try {
    await trust(t, world);
    await attestationChecks(t, world);
    await popChecks(t, world);
    await challengesAndReplay(t, world);
    await fields(t, world);
    await combined(t, world);
    await policies(t, world);
    await wiring(t, world);
  } finally {
    SETTINGS.forEach(function (key) {
      config.clearOverride(key);
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'client_attestation',
  describe: 'OAuth 2.0 Attestation-Based Client Authentication ' +
            '(draft-ietf-oauth-attestation-based-client-auth-11): trusted ' +
            'attesters by JWKS and by x5c path, the attestation and PoP ' +
            'checks, single-use challenges and PoPs, the DPoP combined ' +
            'mode, the declared-method and additional-signal refusals, the ' +
            'bindings, the metadata and FAPI 2.0\'s HAIP allowance',
  run: run
};
