// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: siop.js
//
// ===========================================================================
// SELF-ISSUED OPENID PROVIDER v2, THE RELYING PARTY'S HALF (#129,
// 2026-09-23). rcbj's answers: this service is the relying party only; a
// self-issued subject is ENROLLED on a person's entry — by the person, by
// proving the key, or by an administrator — and only an enrolled subject
// signs in, in both modes; a signed request may name its Client Identifier
// by any of four prefixes.
//
// Held here, in process, against the real directory:
//
//   1. a subject in every spelling it may arrive in, and nothing else;
//   2. enrolment: one person per subject, the limit, removal;
//   3. section 11.1 on a JWK Thumbprint subject: a good token, and each rule
//      that refuses — iss, the thumbprint, a private sub_jwk, the signature,
//      aud, nonce, exp, iat, `none`;
//   4. a did:jwk subject, and a kid naming another DID;
//   5. a did:web subject: never fetched unenrolled; enrolled by value only
//      with its authentication keys fetched and pinned (#693); fetched, and
//      its kid held to the authentication relationship and the pin, once
//      enrolled; never fetched for a stale token; a changed key refused;
//   6. whom it signs in: the enrolled person, or nobody (STS-VC-0091);
//   7. the request the Verifier builds: id_token and vp_token id_token,
//      form_post, and the four Client Identifier prefixes — the DID URL kid,
//      the attestation in the `jwt` header, a configured attestation checked,
//      and the Entity Configuration;
//   8. provenance (#693): by value or proved, and a value from before it;
//   9. a did:web enrolled before the pin: product refuses, development pins
//      on first use;
//  10. a did:web enrolled by proof, inside its own enrolment only, once, and
//      proved again to re-pin a changed key;
//  11. what a fetch may reach: an internal address refused in product, and
//      a by-value did:web with no key to pin refused.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const config = require('../common/config');
const ldap = require('../ldap/ldap_server');
const stsCrypto = require('../common/crypto');
const helpers = require('../common/helpers');
const siop = require('../oid4vc/siop');
const vcDataIntegrity = require('../oid4vc/vc_data_integrity');
const verifier = require('../oid4vc/vc_verifier');

const log = require('bunyan').createLogger({ name: 'siop',
  level: process.env.LOG_LEVEL || 'info' });

const CLIENT = 'redirect_uri:https://sts.test/oid4vp/response';
const NONCE = 'n-0123456789';

function fakeReq() {
  log.debug("Entering fakeReq().");
  log.debug("Leaving fakeReq().");
  return { protocol: 'https', headers: { host: 'sts.test' }, query: {},
           get: function (name) {
             return String(name).toLowerCase() === 'host' ? 'sts.test' : '';
           } };
}

function keyPair() {
  log.debug("Entering keyPair().");
  const pair = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = pair.publicKey.export({ format: 'jwk' });
  log.debug("Leaving keyPair().");
  return { pem: pair.privateKey.export({ format: 'pem', type: 'pkcs8' }),
           jwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y } };
}

function idToken(pair, claims, header) {
  log.debug("Entering idToken().");
  const now = Math.floor(Date.now() / 1000);
  const payload = Object.assign({ aud: CLIENT, nonce: NONCE, iat: now,
                                  exp: now + 300 }, claims);
  log.debug("Leaving idToken().");
  return stsCrypto.signJws(payload, pair.pem,
                           { algorithm: 'ES256', header: header || {} });
}

// A did:web's document, naming one key as its authentication method `#k1`.
function didWebDoc(did, jwk) {
  log.debug("Entering didWebDoc().");
  log.debug("Leaving didWebDoc().");
  return { id: did,
           verificationMethod: [{ id: did + '#k1', type: 'JsonWebKey2020',
                                  controller: did, publicKeyJwk: jwk }],
           authentication: ['#k1'] };
}

// THE FOUR PREREQUISITES OF #693, in process: provenance, the pin (and an
// enrolment from before it, per mode), a did:web enrolled by proof inside
// its own enrolment transaction only, and the by-value refusal.
async function prerequisites(t, expect) {
  log.debug("Entering prerequisites().");
  const credentials = require('../common/credentials');
  const mode = require('../common/mode');
  const docs = {};
  let dials = 0;
  const audited = [];
  const stubbed = new siop.Siop(Object.assign(siop.Siop.defaultDeps(), {
    fetchDocument: function (url) {
      dials += 1;
      return docs[url] ? Promise.resolve(docs[url])
                       : Promise.reject(new Error('it answered 404'));
    },
    audit: function (event) {
      audited.push(event);
    } }));
  const tokenFor = function (pair, did, claims) {
    log.debug("Entering tokenFor().");
    log.debug("Leaving tokenFor().");
    return idToken(pair, Object.assign({ iss: did, sub: did }, claims || {}),
                   { kid: did + '#k1' });
  };
  // An enrolment transaction's expectation: one dial, counted.
  const enrolling = function (username) {
    log.debug("Entering enrolling().");
    const state = { dialled: 0 };
    log.debug("Leaving enrolling().");
    return { state: state, expect: Object.assign({}, expect, {
      enrolment: { username: username, mayDial: function () {
        state.dialled += 1;
        return state.dialled === 1;
      } } }) };
  };
  ['siop-carol', 'siop-dave'].forEach(function (name) {
    ldap.createUser(name, { invent: false,
      attributes: { givenName: name, sn: 'Self' } });
  });

  t.log.info('=== 8. provenance (#693) ===');
  t.check(siop.list('siop-alice').every(function (one) {
            return one.proof === 'admin';
          }) && siop.provenSubjectsOf('siop-alice').length === 0,
          '8a. what an administrator enrolled is by value, and not proved');
  const carolPair = keyPair();
  const carolDid = 'did:web:carol.test:wallet';
  const carolUrl = 'https://carol.test/wallet/did.json';
  docs[carolUrl] = didWebDoc(carolDid, carolPair.jwk);
  const carolPrint = stsCrypto.jwkThumbprint(keyPair().jwk);
  // Two values as they were written before #693: no `proof`, no pin.
  credentials.writeSelfIssuedSubjects('siop-carol', [
    JSON.stringify({ subject: 'urn:ietf:params:oauth:jwk-thumbprint:sha-256:' +
                              carolPrint, label: '',
                     enrolledAt: new Date().toISOString(),
                     by: 'self (SIOPv2)' }),
    JSON.stringify({ subject: carolDid, label: '',
                     enrolledAt: new Date().toISOString(), by: 'an-admin' })]);
  const carolHeld = siop.list('siop-carol');
  t.check(carolHeld[0].proof === 'wallet' && carolHeld[1].proof === 'admin' &&
          siop.provenSubjectsOf('siop-carol').length === 1,
          '8b. a value from before #693 reads as proved when the self path ' +
          'wrote it, and as by value otherwise', JSON.stringify(carolHeld));

  t.log.info('=== 9. an enrolment from before the pin, per mode ===');
  t.check(mode.pinsSelfIssuedKeysOnFirstUse() === true,
          '9a. development pins on first use');
  config.setOverride('global.mode', 'product');
  let legacy;
  try {
    t.check(mode.pinsSelfIssuedKeysOnFirstUse() === false,
            '9b. product does not');
    legacy = await stubbed.verifyIdToken(tokenFor(carolPair, carolDid),
                                         expect);
  } finally {
    config.clearOverride('global.mode');
  }
  t.check(!legacy.ok && legacy.errorCode === 'STS-VC-0127' &&
          !siop.list('siop-carol')[1].pinnedKeys &&
          audited.some(function (e) {
            return e.action === 'siop.key.refused' &&
                   e.errorCode === 'STS-VC-0127';
          }),
          '9c. product refuses an unpinned did:web (STS-VC-0127), audited, ' +
          'and pins nothing', JSON.stringify(legacy.checks));
  const tofu = await stubbed.verifyIdToken(tokenFor(carolPair, carolDid),
                                           expect);
  t.check(tofu.ok && JSON.stringify(siop.list('siop-carol')[1].pinnedKeys) ===
            JSON.stringify([stsCrypto.jwkThumbprint(carolPair.jwk)]) &&
          audited.some(function (e) {
            return e.action === 'siop.key.pinned' && e.actor === 'siop-carol';
          }),
          '9d. development signs it in and pins that key, audited',
          JSON.stringify(tofu.checks));
  const carolNew = keyPair();
  docs[carolUrl] = didWebDoc(carolDid, carolNew.jwk);
  const afterPin = await stubbed.verifyIdToken(tokenFor(carolNew, carolDid),
                                               expect);
  t.check(!afterPin.ok && afterPin.errorCode === 'STS-VC-0126',
          '9e. and once pinned, another key is refused in development too');

  t.log.info('=== 10. a did:web enrolled by proof ===');
  const davePair = keyPair();
  const daveDid = 'did:web:dave.test';
  docs['https://dave.test/.well-known/did.json'] =
    didWebDoc(daveDid, davePair.jwk);
  const daveEnrol = enrolling('siop-dave');
  let before = dials;
  const wrongNonce = await stubbed.verifyIdToken(tokenFor(davePair, daveDid,
    { nonce: 'not-this-one' }), daveEnrol.expect);
  t.check(!wrongNonce.ok && dials === before && daveEnrol.state.dialled === 0,
          '10a. an enrolment answered for another nonce dials nothing');
  const proved = await stubbed.verifyIdToken(tokenFor(davePair, daveDid),
                                             daveEnrol.expect);
  t.check(proved.ok && dials === before + 1 &&
          proved.keyThumbprint === stsCrypto.jwkThumbprint(davePair.jwk),
          '10b. inside its own enrolment an unenrolled did:web is fetched, ' +
          'once, and the key that signed the proof is named',
          JSON.stringify(proved.checks));
  before = dials;
  const twice = await stubbed.verifyIdToken(tokenFor(davePair, daveDid),
                                            daveEnrol.expect);
  t.check(!twice.ok && twice.errorCode === 'STS-VC-0128' && dials === before,
          '10c. one enrolment fetches one document (STS-VC-0128)');
  const daveIn = siop.enrol('siop-dave', daveDid, 'w', 'self (SIOPv2)',
    { proof: siop.PROOF_WALLET, pinnedKeys: [proved.keyThumbprint] });
  t.check(daveIn.ok && daveIn.enrolled.proof === 'wallet' &&
          siop.provenSubjectsOf('siop-dave').map(function (one) {
            return one.subject;
          }).join() === daveDid,
          '10d. enrolled as proved, its key pinned, and a proven subject',
          JSON.stringify(daveIn));
  const daveSignIn = await stubbed.verifyIdToken(tokenFor(davePair, daveDid),
                                                 expect);
  t.check(daveSignIn.ok && stubbed.signInOutcome(daveSignIn).username ===
            'siop-dave',
          '10e. and it signs its person in with the pinned key');
  // A changed document, proved again inside an enrolment: the re-pin.
  const carolAgain = enrolling('siop-carol');
  const reproved = await stubbed.verifyIdToken(tokenFor(carolNew, carolDid),
                                               carolAgain.expect);
  const repinned = siop.enrol('siop-carol', carolDid, '', 'self (SIOPv2)',
    { proof: siop.PROOF_WALLET, pinnedKeys: [reproved.keyThumbprint] });
  const carolNow = await stubbed.verifyIdToken(tokenFor(carolNew, carolDid),
                                               expect);
  t.check(reproved.ok && repinned.ok && repinned.again &&
          repinned.enrolled.proof === 'wallet' && carolNow.ok &&
          siop.list('siop-carol').length === 2,
          '10f. proving an enrolled did:web again re-pins it to the new key, ' +
          'proved, in place', JSON.stringify(repinned));
  t.check(/already enrolled/.test(siop.enrol('siop-carol', carolDid, '',
    'an-admin', { pinnedKeys: [reproved.keyThumbprint] }).error || ''),
          '10g. an administrator\'s second enrolment of it is still refused');

  t.log.info('=== 11. what a fetch may reach ===');
  const real = new siop.Siop(Object.assign(siop.Siop.defaultDeps(), {
    audit: function () {
      return null;
    } }));
  const insideDid = 'did:web:127.0.0.1%3A9:inside';
  const insidePair = keyPair();
  config.setOverride('global.mode', 'product');
  let inside;
  try {
    inside = await real.verifyIdToken(tokenFor(insidePair, insideDid),
                                      enrolling('siop-dave').expect);
  } finally {
    config.clearOverride('global.mode');
  }
  t.check(!inside.ok && inside.errorCode === 'STS-VC-0128' &&
          inside.checks.some(function (c) {
            return c.name === 'subject key' &&
                   /own network|internal|outbound/.test(c.detail);
          }),
          '11a. in product an enrolment\'s did:web at an internal address is ' +
          'refused by fetchPublished(), unfetched (STS-VC-0128)',
          JSON.stringify(inside.checks));
  before = dials;
  const unfetchable = await stubbed.enrolByValue('siop-dave',
    'did:web:nowhere.test', '', 'an-admin');
  t.check(!unfetchable.ok && unfetchable.code === 'STS-ADMIN-0871' &&
          dials === before + 1 && !siop.ownerOf('did:web:nowhere.test'),
          '11b. a by-value did:web whose document cannot be fetched is ' +
          'refused (STS-ADMIN-0871), not enrolled unpinned');
  docs['https://keyless.test/.well-known/did.json'] = {
    id: 'did:web:keyless.test', authentication: ['#k1'] };
  const keyless = await stubbed.enrolByValue('siop-dave',
    'did:web:keyless.test', '', 'an-admin');
  t.check(!keyless.ok && keyless.code === 'STS-ADMIN-0871',
          '11c. so is one whose document names no authentication key');
  before = dials;
  const taken = await stubbed.enrolByValue('siop-dave', carolDid, '',
                                           'an-admin');
  t.check(!taken.ok && dials === before,
          '11d. and one that is somebody else\'s is refused before any fetch');
  log.debug("Leaving prerequisites().");
}

async function run(t) {
  log.debug("Entering run().");
  try {
    await body(t);
  } finally {
    config.clearOverride('oid4vp.clientIdPrefix');
    config.clearOverride('oid4vp.verifierAttestation');
    config.clearOverride('global.mode');
  }
  log.debug("Leaving run().");
}

async function body(t) {
  log.debug("Entering body().");
  const alicePair = keyPair();
  const thumbprint = stsCrypto.jwkThumbprint(alicePair.jwk);
  const uri = 'urn:ietf:params:oauth:jwk-thumbprint:sha-256:' + thumbprint;

  t.log.info('=== 1. subjects ===');
  t.check(siop.normalise(thumbprint) === uri &&
          siop.normalise(uri) === uri &&
          siop.normalise(JSON.stringify(alicePair.jwk)) === uri,
          '1a. a bare thumbprint, the RFC 9278 URI and a public JWK are one ' +
          'subject');
  t.check(siop.normalise('did:jwk:abc#0') === 'did:jwk:abc' &&
          siop.normalise('did:example:123') === '' &&
          siop.normalise(JSON.stringify(Object.assign({ d: 'secret' },
            alicePair.jwk))) === '' &&
          siop.normalise('https://evil.test') === '',
          '1b. a DID loses its fragment; another method, a private JWK and ' +
          'a URL are not subjects');

  t.log.info('=== 2. enrolment ===');
  ldap.createUser('siop-alice', { invent: false,
    attributes: { givenName: 'Alice', sn: 'Self' } });
  ldap.createUser('siop-bob', { invent: false,
    attributes: { givenName: 'Bob', sn: 'Self' } });
  const enrolled = siop.enrol('siop-alice', thumbprint, 'phone', 'tester');
  t.check(enrolled.ok && enrolled.enrolled.subject === uri &&
          siop.ownerOf(uri) === 'siop-alice' &&
          siop.list('siop-alice').length === 1,
          '2a. enrolled, in its canonical spelling, and found by subject',
          JSON.stringify(enrolled));
  t.check(/another person/.test(siop.enrol('siop-bob', uri, '', 'x').error ||
                                '') &&
          /already enrolled for siop-alice/.test(
            siop.enrol('siop-alice', uri, '', 'x').error || ''),
          '2b. one subject belongs to one person');
  t.check(/no directory entry/.test(siop.enrol('siop-nobody', 'did:jwk:e30',
                                               '', 'x').error || ''),
          '2c. nobody without an entry');
  const extra = [];
  for (let i = 1; i < siop.MAX_SUBJECTS; i++) {
    extra.push(siop.enrol('siop-bob', stsCrypto.jwkThumbprint(
      keyPair().jwk), '', 'x').ok);
  }
  extra.push(siop.enrol('siop-bob', stsCrypto.jwkThumbprint(
    keyPair().jwk), '', 'x').ok);
  t.check(extra.filter(Boolean).length === siop.MAX_SUBJECTS &&
          !siop.enrol('siop-bob', stsCrypto.jwkThumbprint(keyPair().jwk), '',
                      'x').ok,
          '2d. at most ' + siop.MAX_SUBJECTS + ' each');

  t.log.info('=== 3. section 11.1, a JWK Thumbprint subject ===');
  const expect = { clientId: CLIENT, nonce: NONCE };
  const good = await siop.verifyIdToken(idToken(alicePair,
    { iss: thumbprint, sub: thumbprint, sub_jwk: alicePair.jwk }), expect);
  t.check(good.ok && good.subject === uri,
          '3a. a good token verifies, its subject the thumbprint URI',
          JSON.stringify(good.checks));
  const uriForm = await siop.verifyIdToken(idToken(alicePair,
    { iss: uri, sub: uri, sub_jwk: alicePair.jwk }), expect);
  t.check(uriForm.ok, '3b. and so does one whose sub is the URI form');
  const failed = async function (claims, header, why) {
    const got = await siop.verifyIdToken(idToken(alicePair,
      Object.assign({ iss: thumbprint, sub: thumbprint,
                      sub_jwk: alicePair.jwk }, claims), header), expect);
    return !got.ok && got.checks.some(function (c) {
      return !c.ok && why.test(c.name + ' ' + c.detail);
    });
  };
  const other = keyPair();
  t.check(await failed({ iss: 'someone-else' }, null, /iss equals sub/),
          '3c. iss other than sub is refused');
  t.check(await failed({ sub_jwk: other.jwk, iss: thumbprint }, null,
                       /not the SHA-256 JWK thumbprint/),
          '3d. a sub that is not sub_jwk\'s thumbprint is refused');
  t.check(await failed({ sub_jwk: Object.assign({ d: 'x' }, alicePair.jwk) },
                       null, /PRIVATE/),
          '3e. a private key in sub_jwk is refused');
  const forged = await siop.verifyIdToken(idToken(other,
    { iss: thumbprint, sub: thumbprint, sub_jwk: alicePair.jwk }), expect);
  t.check(!forged.ok && forged.checks.some(function (c) {
    return c.name === 'signature' && !c.ok;
  }), '3f. a token signed by another key is refused');
  t.check(await failed({ aud: 'redirect_uri:https://elsewhere.test/cb' },
                       null, /^aud/),
          '3g. another audience is refused');
  t.check(await failed({ nonce: 'replayed' }, null, /^nonce/),
          '3h. another nonce is refused');
  const now = Math.floor(Date.now() / 1000);
  t.check(await failed({ exp: now - 3600, iat: now - 3700 }, null, /^exp/),
          '3i. an expired token is refused');
  t.check(await failed({ iat: now - 3600 }, null, /^iat/),
          '3j. one older than oid4vp.siopIdTokenMaxAgeS is refused');
  const unsigned = Buffer.from(JSON.stringify({ alg: 'none' }))
    .toString('base64url') + '.' + Buffer.from(JSON.stringify({
      iss: thumbprint, sub: thumbprint, sub_jwk: alicePair.jwk, aud: CLIENT,
      nonce: NONCE, iat: now, exp: now + 60 })).toString('base64url') + '.';
  t.check(!(await siop.verifyIdToken(unsigned, expect)).ok,
          '3k. alg none is refused');

  t.log.info('=== 4. a did:jwk subject ===');
  const did = vcDataIntegrity.didJwkOf(alicePair.jwk);
  const byDid = await siop.verifyIdToken(idToken(alicePair,
    { iss: did, sub: did }, { kid: did + '#0' }), expect);
  t.check(byDid.ok && byDid.subject === did,
          '4a. a did:jwk subject verifies with the key in its identifier',
          JSON.stringify(byDid.checks));
  const otherDid = vcDataIntegrity.didJwkOf(other.jwk);
  t.check(!(await siop.verifyIdToken(idToken(other,
    { iss: did, sub: did }, { kid: otherDid + '#0' }), expect)).ok,
          '4b. a kid naming another DID is refused');

  t.log.info('=== 5. a did:web subject ===');
  const webDid = 'did:web:wallet.test%3A8443:alice';
  let fetched = [];
  let doc = { id: webDid,
    verificationMethod: [{ id: webDid + '#k1', type: 'JsonWebKey2020',
                           controller: webDid,
                           publicKeyJwk: alicePair.jwk },
                         { id: webDid + '#k2', type: 'JsonWebKey2020',
                           controller: webDid,
                           publicKeyJwk: other.jwk }],
    authentication: ['#k1'] };
  const audited = [];
  const stubbed = new siop.Siop(Object.assign(siop.Siop.defaultDeps(), {
    fetchDocument: function (url) {
      fetched.push(url);
      return Promise.resolve(doc);
    },
    audit: function (event) {
      audited.push(event);
    } }));
  const webToken = idToken(alicePair, { iss: webDid, sub: webDid },
                           { kid: webDid + '#k1' });
  const unenrolledWeb = await stubbed.verifyIdToken(webToken, expect);
  t.check(!unenrolledWeb.ok && fetched.length === 0,
          '5a. an unenrolled did:web is refused WITHOUT being fetched');
  t.check(/pinned/.test(siop.enrol('siop-alice', webDid, 'web wallet',
                                   'tester').error || ''),
          '5b. a did:web is not enrolled with no key to pin (#693)');
  const byValue = await stubbed.enrolByValue('siop-alice', webDid,
                                             'web wallet', 'tester');
  t.check(byValue.ok && fetched.length === 1 &&
          JSON.stringify(byValue.enrolled.pinnedKeys) ===
            JSON.stringify([stsCrypto.jwkThumbprint(alicePair.jwk)]) &&
          byValue.enrolled.proof === 'admin',
          '5c. enrolled by value: its document fetched once, and only its ' +
          'authentication key pinned, as unproven (#693)',
          JSON.stringify(byValue));
  const enrolledWeb = await stubbed.verifyIdToken(webToken, expect);
  t.check(enrolledWeb.ok && fetched[1] ===
          'https://wallet.test:8443/alice/did.json' &&
          enrolledWeb.checks.some(function (c) {
            return c.name === 'pinned key' && c.ok;
          }),
          '5d. then fetched from its did:web URL, verified, and its key the ' +
          'pinned one', JSON.stringify({ fetched: fetched,
                                         checks: enrolledWeb.checks }));
  const notAuth = await stubbed.verifyIdToken(idToken(other,
    { iss: webDid, sub: webDid }, { kid: webDid + '#k2' }), expect);
  t.check(!notAuth.ok && notAuth.checks.some(function (c) {
    return /authentication relationship/.test(c.detail);
  }), '5e. a key outside the authentication relationship is refused');
  const fetchedBefore = fetched.length;
  const stale = await stubbed.verifyIdToken(idToken(alicePair,
    { iss: webDid, sub: webDid, nonce: 'replayed' }, { kid: webDid + '#k1' }),
    expect);
  t.check(!stale.ok && fetched.length === fetchedBefore &&
          stale.checks.some(function (c) {
            return c.name === 'subject key' && /not fetched/.test(c.detail);
          }),
          '5f. a token for another nonce makes this service dial nothing ' +
          '(#693)', JSON.stringify(stale.checks));
  const moved = keyPair();
  const keptDoc = doc;
  doc = { id: webDid,
    verificationMethod: [{ id: webDid + '#k1', type: 'JsonWebKey2020',
                           controller: webDid, publicKeyJwk: moved.jwk }],
    authentication: ['#k1'] };
  const changed = await stubbed.verifyIdToken(idToken(moved,
    { iss: webDid, sub: webDid }, { kid: webDid + '#k1' }), expect);
  const changedOutcome = stubbed.signInOutcome(changed);
  t.check(!changed.ok && changed.errorCode === 'STS-VC-0126' &&
          !changedOutcome.ok &&
          changedOutcome.errorCode === 'STS-VC-0126' &&
          audited.some(function (e) {
            return e.action === 'siop.key.refused' &&
                   e.errorCode === 'STS-VC-0126' && e.actor === 'siop-alice';
          }),
          '5g. a document whose key changed is refused (STS-VC-0126), ' +
          'whoever controls the host now, and audited (#693)',
          JSON.stringify({ checks: changed.checks, audited: audited }));
  doc = keptDoc;
  t.log.info('=== 6. whom it signs in ===');
  const signsIn = siop.signInOutcome(good);
  t.check(signsIn.ok && signsIn.username === 'siop-alice',
          '6a. the enrolled person');
  const stranger = keyPair();
  const strangerPrint = stsCrypto.jwkThumbprint(stranger.jwk);
  const strangerToken = await siop.verifyIdToken(idToken(stranger,
    { iss: strangerPrint, sub: strangerPrint, sub_jwk: stranger.jwk }),
    expect);
  const nobody = siop.signInOutcome(strangerToken);
  t.check(strangerToken.ok && !nobody.ok &&
          nobody.errorCode === 'STS-VC-0091',
          '6b. a verified but unenrolled key signs nobody in');
  t.check(siop.remove('siop-alice', uri).ok && !siop.ownerOf(uri) &&
          !siop.signInOutcome(good).ok,
          '6c. removed, it signs nobody in');
  t.check(siop.sameHolder(alicePair.jwk, Object.assign({ kid: 'x' },
                                                       alicePair.jwk)) &&
          !siop.sameHolder(alicePair.jwk, other.jwk),
          '6d. a combined response\'s holder is compared by thumbprint');

  t.log.info('=== 7. the request the Verifier builds ===');
  const plain = verifier.buildVpRequest(fakeReq(), { responseType: 'id_token',
    responseMode: 'form_post' });
  t.check(plain.request.response_type === 'id_token' &&
          plain.request.scope === 'openid' &&
          plain.request.dcql_query === undefined &&
          plain.request.response_mode === 'form_post' &&
          /\/oid4vp\/response$/.test(plain.request.redirect_uri) &&
          plain.request.client_metadata.subject_syntax_types_supported
            .indexOf('did:jwk') >= 0 &&
          /^redirect_uri:/.test(plain.clientId),
          '7a. id_token alone: scope openid, no DCQL, section 8 metadata, ' +
          'form_post to a redirect_uri', JSON.stringify(plain.request));
  const combined = verifier.buildVpRequest(fakeReq(),
    { responseType: 'vp_token id_token' });
  t.check(combined.request.dcql_query && combined.request.scope === 'openid' &&
          combined.request.response_uri,
          '7b. vp_token id_token asks for both');
  const headerOf = function (jwt) {
    return JSON.parse(Buffer.from(jwt.split('.')[0], 'base64url')
      .toString());
  };
  const claimsOf = function (jwt) {
    return JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url')
      .toString());
  };
  config.setOverride('oid4vp.clientIdPrefix', 'decentralized_identifier');
  const byDidReq = verifier.buildVpRequest(fakeReq(),
    { byReference: true, responseType: 'id_token' });
  const didHeader = headerOf(byDidReq.requestObject);
  t.check(/^decentralized_identifier:did:web:sts\.test$/.test(
            byDidReq.clientId) &&
          didHeader.kid === 'did:web:sts.test#' + helpers.STS.kid,
          '7c. decentralized_identifier: the realm\'s did:web, and a DID URL ' +
          'kid', byDidReq.clientId + ' ' + didHeader.kid);
  config.setOverride('oid4vp.clientIdPrefix', 'verifier_attestation');
  const attested = verifier.buildVpRequest(fakeReq(),
    { byReference: true, responseType: 'id_token' });
  const attHeader = headerOf(attested.requestObject);
  const attestation = attHeader.jwt ? claimsOf(attHeader.jwt) : {};
  t.check(/^verifier_attestation:/.test(attested.clientId) &&
          headerOf(attHeader.jwt).typ === 'verifier-attestation+jwt' &&
          attested.clientId === 'verifier_attestation:' + attestation.sub &&
          attestation.cnf && attestation.cnf.jwk.n,
          '7d. verifier_attestation: a self-attestation in the jwt header, ' +
          'its sub the Client Identifier and its cnf the signing key');
  config.setOverride('oid4vp.verifierAttestation', idToken(other,
    { sub: 'x', cnf: { jwk: other.jwk } },
    { typ: 'verifier-attestation+jwt' }));
  let refused = null;
  try {
    verifier.buildVpRequest(fakeReq(), { byReference: true,
                                         responseType: 'id_token' });
  } catch (e) {
    refused = e;
  }
  t.check(refused && refused.code === 'STS-VC-0092',
          '7e. a configured attestation whose cnf is not this realm\'s key ' +
          'builds no request');
  config.clearOverride('oid4vp.verifierAttestation');
  config.setOverride('oid4vp.clientIdPrefix', 'openid_federation');
  const federated = verifier.buildVpRequest(fakeReq(),
    { byReference: true, responseType: 'id_token' });
  // The Entity Configuration itself moved to oidfed/ (#132) and is held by
  // tests/oidfed_entity.js; what is the verifier's is its entity type.
  const vm = verifier.federationVerifierMetadata(fakeReq());
  t.check(federated.clientId === 'openid_federation:https://sts.test' &&
          vm.jwks.keys.length === 1 && typeof vm.jwks.keys[0].kid ===
            'string' &&
          vm.response_uris[0] === 'https://sts.test/oid4vp/response',
          '7f. openid_federation: the realm\'s Entity Identifier, and the ' +
          'openid_credential_verifier metadata naming the request-signing ' +
          'key', JSON.stringify(vm).slice(0, 300));
  await prerequisites(t, expect);
  log.debug("Leaving body().");
}

module.exports = {
  name: 'siop',
  describe: 'SIOPv2 as the relying party (#129): subjects, enrolment, ' +
            'section 11.1, whom it signs in, the Client Identifier ' +
            'prefixes, and #693\'s did:web pin, provenance and enrolment ' +
            'by proof',
  run: run
};
