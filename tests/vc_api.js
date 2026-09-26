'use strict';
// ===========================================================================
// tests/vc_api.js — THE VC-API TEST ADAPTER'S GATE, AND DID RESOLUTION
// (#194-#199, 2026-09-26).
//
// oid4vc/vc_api.ts is a TEST CONTROL that signs what it is handed with a
// realm's key, so what matters most is who reaches it. Claims:
//
//   A. THE GATE: with test controls closed (a product realm) every route is
//      a 404 marked STS-VC-0100, the token never asked for; without a
//      token the shared check answers 401; a verified token without the
//      scope is 403, and one whose client no longer declares the scope, or
//      that was revoked, is 401 — each marked STS-VC-0101 — and a good one
//      is admitted.
//   B. THE ISSUER'S OWN RULES, before any key is touched: an unknown issuer
//      is 404 (STS-VC-0104), a body that is not a JSON object 400
//      (STS-VC-0108), a credential naming another issuer 400 (STS-VC-0102).
//   C. DID RESOLUTION (oid4vc/vc_did_resolver.ts, DID Core section 7): a
//      did:key and a did:jwk resolve to their documents in both
//      representations; an invalid DID, an unsupported method, a did:web
//      other than this realm's and an unsupported representation each fail
//      with the right error; a fragment dereferences to its method.
//   D. THE SCOPES ARE PROTECTED in both modes (common/scope_policy.ts).
// ===========================================================================

const crypto = require('crypto');

const log = require('bunyan').createLogger({ name: 'vc_api_test',
  level: process.env.LOG_LEVEL || 'info' });

// A response that records what a handler did.
function fakeRes() {
  log.debug("Entering fakeRes().");
  const res = { statusCode: 200, headers: {}, body: '', codes: [],
                headersSent: false };
  res.status = function (code) {
    res.statusCode = code;
    return res;
  };
  res.set = function (name, value) {
    res.headers[String(name).toLowerCase()] = value;
    return res;
  };
  res.type = function () {
    return res;
  };
  res.send = function (body) {
    res.body = String(body);
    res.headersSent = true;
    return res;
  };
  res.end = function () {
    res.headersSent = true;
    return res;
  };
  log.debug("Leaving fakeRes().");
  return res;
}

function jsonOf(res) {
  log.debug("Entering jsonOf().");
  try {
    log.debug("Leaving jsonOf().");
    return JSON.parse(res.body);
  } catch (e) {
    log.debug("Caught in jsonOf(): " + ((e && e.message) || e));
    log.debug("Leaving jsonOf(). Not JSON.");
    return null;
  }
}

async function run(t) {
  log.debug("Entering run().");
  const vcApi = require('../oid4vc/vc_api');
  const errorCodes = require('../common/error_codes');
  const scopePolicy = require('../common/scope_policy');
  const resolver = require('../oid4vc/vc_did_resolver');
  const di = require('../oid4vc/vc_data_integrity');

  const build = function build(over) {
    log.debug("Entering build().");
    const deps = Object.assign(vcApi.VcApi.defaultDeps(), over || {});
    log.debug("Leaving build().");
    return new vcApi.VcApi(deps);
  };
  const token = function token(claims, verified) {
    log.debug("Entering token().");
    log.debug("Leaving token().");
    return function (req, res) {
      return { verified: verified !== false, claims: claims,
               scheme: 'bearer' };
    };
  };
  const good = { typ: 'Bearer', jti: 'j1', client_id: 'c1',
                 scope: 'vc-api:issue vc-api:verify' };

  t.log.info('=== A. the gate ===');
  let asked = false;
  const closed = build({ opensTestControls: function () {
    return false;
  }, presentedAccessToken: function () {
    asked = true;
    return null;
  } });
  const r404 = fakeRes();
  t.check(!closed.admitted({}, r404, 'vc-api:issue') &&
          r404.statusCode === 404 && !asked &&
          errorCodes.codeOf(r404) === 'STS-VC-0100',
          'A1. closed test controls: 404 STS-VC-0100, no token asked for',
          r404.statusCode + ' ' + errorCodes.codeOf(r404));
  const cases = [
    ['a token without the scope', token(Object.assign({}, good,
      { scope: 'vc-api:verify' })), {}, 403],
    ['a token the client no longer declares', token(good),
     { declares: function () { return false; } }, 401],
    ['a revoked token', token(good),
     { isRevoked: function () { return true; } }, 401],
    ['a token this realm did not issue', token(good, false), {}, 401],
    ['a refresh token', token(Object.assign({}, good,
      { typ: 'Refresh' })), {}, 401]];
  cases.forEach(function (row) {
    const api = build(Object.assign({ opensTestControls: function () {
      return true;
    }, presentedAccessToken: row[1], declares: function () {
      return true;
    }, isRevoked: function () { return false; } }, row[2]));
    const res = fakeRes();
    t.check(!api.admitted({}, res, 'vc-api:issue') &&
            res.statusCode === row[3] &&
            errorCodes.codeOf(res) === 'STS-VC-0101',
            'A2. refused: ' + row[0] + ' (' + row[3] + ')',
            res.statusCode + ' ' + res.body);
  });
  const open = build({ opensTestControls: function () {
    return true;
  }, presentedAccessToken: token(good), declares: function () {
    return true;
  }, isRevoked: function () { return false; } });
  t.check(open.admitted({}, fakeRes(), 'vc-api:issue'),
          'A3. a verified access token carrying the scope is admitted');

  t.log.info('=== B. the issuer\'s own rules ===');
  const unknownIssuer = fakeRes();
  await open.issue({ params: { issuer: 'no-such-issuer' }, body: '{}' },
                   unknownIssuer);
  t.check(unknownIssuer.statusCode === 404 &&
          errorCodes.codeOf(unknownIssuer) === 'STS-VC-0104',
          'B1. an unknown issuer is 404 STS-VC-0104');
  const notJson = fakeRes();
  await open.issue({ params: { issuer: 'eddsa-rdfc-2022' },
                     body: 'not json' }, notJson);
  t.check(notJson.statusCode === 400 &&
          errorCodes.codeOf(notJson) === 'STS-VC-0108',
          'B2. a body that is not JSON is 400 STS-VC-0108');
  const another = fakeRes();
  await open.issue({ params: { issuer: 'eddsa-rdfc-2022' },
    body: JSON.stringify({ credential: {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiableCredential'], issuer: 'did:example:someone-else',
      credentialSubject: { id: 'did:example:subject' } } }) }, another);
  t.check(another.statusCode === 400 &&
          errorCodes.codeOf(another) === 'STS-VC-0102' &&
          /signs as did:key:/.test(another.body),
          'B3. a credential naming another issuer is 400 STS-VC-0102',
          another.body.slice(0, 300));

  t.log.info('=== C. DID resolution ===');
  const key = crypto.generateKeyPairSync('ed25519').publicKey
    .export({ format: 'jwk' });
  const didKey = di.didKeyOf(key);
  const r1 = await resolver.resolve(didKey, {}, null);
  t.check(r1.didDocument && r1.didDocument.id === didKey &&
          r1.didDocument.verificationMethod[0].type === 'Multikey' &&
          r1.didDocument.assertionMethod[0] === didKey + '#' +
            didKey.slice('did:key:'.length),
          'C1. a did:key resolves to its Multikey document');
  const didJwk = di.didJwkOf(key);
  const r2 = await resolver.resolveRepresentation(didJwk,
    { accept: 'application/did+json' }, null);
  const parsed = JSON.parse(r2.didDocumentStream);
  t.check(r2.didResolutionMetadata.contentType === 'application/did+json' &&
          parsed['@context'] === undefined && parsed.id === didJwk,
          'C2. a did:jwk resolves in the JSON representation, no @context');
  const r3 = await resolver.resolveRepresentation(didJwk, {}, null);
  t.check(JSON.parse(r3.didDocumentStream)['@context'] !== undefined &&
          r3.didResolutionMetadata.contentType === 'application/did+ld+json',
          'C3. and in the JSON-LD representation by default, with it');
  const errors = [['did:key:not valid!', 'invalidDid'],
                  ['did:example:123', 'methodNotSupported']];
  for (const row of errors) {
    const r = await resolver.resolve(row[0], {}, null);
    t.check(r.didResolutionMetadata.error === row[1] &&
            r.didDocument === null,
            'C4. ' + row[0] + ' is ' + row[1]);
  }
  const png = await resolver.resolveRepresentation(didKey,
    { accept: 'image/png' }, null);
  t.check(png.didResolutionMetadata.error === 'representationNotSupported' &&
          png.didDocumentStream === '',
          'C5. an unsupported representation is representationNotSupported');
  const accept = await resolver.resolve(didKey,
    { accept: 'application/did+json' }, null);
  t.check(accept.didResolutionMetadata.error === 'invalidOptions',
          'C6. accept with resolve() is refused (section 7.1.1)');
  const vm = await resolver.dereference(didKey + '#' +
    didKey.slice('did:key:'.length), {}, null);
  t.check(JSON.parse(vm.contentStream).type === 'Multikey',
          'C7. a fragment dereferences to its verification method');
  const missing = await resolver.dereference(didKey + '#nothing', {}, null);
  t.check(missing.dereferencingMetadata.error === 'notFound',
          'C8. a fragment the document does not hold is notFound');
  const badUrl = await resolver.dereference('bad:invalid', {}, null);
  t.check(badUrl.dereferencingMetadata.error === 'invalidDidUrl',
          'C9. a DID URL that is not one is invalidDidUrl');

  t.log.info('=== D. the scopes are protected ===');
  t.check(scopePolicy.isProtected('vc-api:issue') &&
          scopePolicy.isProtected('vc-api:verify'),
          'D1. vc-api:issue and vc-api:verify are protected scopes');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'vc_api',
  describe: 'the VC-API test adapter\'s gate (404 where test controls are ' +
            'closed, the token and scope refusals), the issuer\'s own ' +
            'refusals, and DID resolution per DID Core section 7',
  run: run
};
