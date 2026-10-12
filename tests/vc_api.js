// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// ===========================================================================
// tests/vc_api.js — THE W3C VC API'S GATE, ITS KEYS AND OPTIONS, THE
// STATUS-LIST PUBLISH, AND DID RESOLUTION (#194-#199, 2026-09-26; a product
// surface since #598, 2026-10-12).
//
// oid4vc/vc_api.ts signs what it is handed, so what matters most is who
// reaches it and with which key. Claims:
//
//   A. THE GATE: no route carries a demonstration mark (#598); off — the
//      default, `vcApi.enabled` — every route answers 501 STS-VC-0120
//      before a token is read; on, a verified token without the scope is
//      403, and one whose client no longer declares the scope, or that was
//      revoked, or that this realm did not issue, is 401 — each marked
//      STS-VC-0101 — a good one is admitted, and past `vcApi.maxPerWindow`
//      it is 429 STS-VC-0121 with Retry-After. No mode is asked.
//   B. THE ISSUER'S OWN RULES, before any key is touched: an unknown issuer
//      is 404 (STS-VC-0104), a body that is not a JSON object 400
//      (STS-VC-0108), a credential naming another issuer 400 (STS-VC-0102);
//      and THE OPTIONS (#598): one an endpoint does not understand — the
//      internal `securedByEnvelope` among them, which once skipped the proof
//      check — or a private key under `verificationMethod`, is 400
//      STS-VC-0122, and an unsigned credential does not verify.
//   B'. THE KEYS (#598): every issuer signs as a did:key of the VC API's own
//      keys, none of them a key this realm signs its tokens with.
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
  const app = require('../common/app');
  const config = require('../common/config');
  const helpers = require('../common/helpers');
  t.check(config.value('vcApi.enabled') === false,
          'A0. the VC API is off by default (vcApi.enabled)');
  const registered = [];
  const record = function (p) {
    registered.push({ path: p, handlers: Array.prototype.slice.call(
      arguments, 1) });
  };
  const allow = { presentedAccessToken: token(good),
                  declares: function () { return true; },
                  isRevoked: function () { return false; },
                  attemptShared: function () {
                    return Promise.resolve({ ok: true });
                  } };
  build().registerRoutes({ get: record, post: record });
  t.check(registered.length === 9 && registered.every(function (one) {
    return one.handlers.length === 1 && !one.handlers[0].stsDemo &&
      one.handlers[0] !== app.demoOnly;
  }) && registered.every(function (one) {
    return /^\/vc-api\//.test(one.path);
  }), 'A1. nine routes, all under /vc-api, none carrying a demonstration ' +
          'mark, and no status-list publish among them (#598)',
          registered.map(function (one) {
            return one.path;
          }).join(', '));
  let asked = false;
  const offRoutes = [];
  build({ enabled: function () { return false; },
          presentedAccessToken: function () {
            asked = true;
            return null;
          } }).registerRoutes({ get: function (p, h) {
            offRoutes.push(h);
          }, post: function (p, h) {
            offRoutes.push(h);
          } });
  const offAnswers = offRoutes.map(function (h) {
    const res = fakeRes();
    h({ params: {}, query: {}, body: '{}' }, res);
    return res;
  });
  t.check(!asked && offAnswers.every(function (res) {
    return res.statusCode === 501 &&
      errorCodes.codeOf(res) === 'STS-VC-0120';
  }), 'A2. off, every route answers 501 STS-VC-0120 and no token is read',
          offAnswers.map(function (res) {
            return res.statusCode;
          }).join(','));
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
  for (const row of cases) {
    const api = build(Object.assign({}, allow,
      { presentedAccessToken: row[1] }, row[2]));
    const res = fakeRes();
    const ok = await api.admitted({}, res, 'vc-api:issue');
    t.check(!ok && res.statusCode === row[3] &&
            errorCodes.codeOf(res) === 'STS-VC-0101',
            'A3. refused: ' + row[0] + ' (' + row[3] + ')',
            res.statusCode + ' ' + res.body);
  }
  const open = build(Object.assign({}, allow,
    { enabled: function () { return true; } }));
  t.check(await open.admitted({}, fakeRes(), 'vc-api:issue'),
          'A4. a verified access token carrying the scope is admitted');
  let limitedOn = '';
  const limited = build(Object.assign({}, allow, {
    attemptShared: function (what, req, identity, limit) {
      limitedOn = what + ' ' + identity + ' ' + limit;
      return Promise.resolve({ ok: false, kind: 'identity', limit: 3,
                               retryAfterS: 42, detail: 'Wait 42s.' });
    },
    maxPerWindow: function () { return 3; },
    realmId: function () { return 'r1'; } }));
  const tooMany = fakeRes();
  const tooManyOk = await limited.admitted({}, tooMany, 'vc-api:issue');
  t.check(!tooManyOk && tooMany.statusCode === 429 &&
          errorCodes.codeOf(tooMany) === 'STS-VC-0121' &&
          tooMany.headers['retry-after'] === '42' &&
          limitedOn === 'vc-api:r1 c1 3',
          'A5. past vcApi.maxPerWindow it is 429 STS-VC-0121 with ' +
          'Retry-After, counted per realm and per client',
          tooMany.statusCode + ' ' + limitedOn);
  const source = require('fs').readFileSync(require('path').join(__dirname,
    '..', 'oid4vc', 'vc_api.ts'), 'utf8');
  t.check(!/mode\.[a-zA-Z]+\(/.test(source) &&
          !/require\('\.\.\/common\/mode'\)/.test(source),
          'A6. no mode predicate is read: the gate is the same in both ' +
          'modes');

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
  const routes = {};
  open.registerRoutes({ get: function (p, h) {
    routes['GET ' + p] = h;
  }, post: function (p, h) {
    routes['POST ' + p] = h;
  } });
  const call = function call(key, body, params) {
    log.debug("Entering call(). " + key);
    const res = fakeRes();
    routes[key]({ params: params || {}, query: {},
                  body: JSON.stringify(body) }, res);
    log.debug("Leaving call().");
    return new Promise(function (resolve) {
      const wait = function () {
        if (res.headersSent) {
          resolve(res);
          return;
        }
        setImmediate(wait);
      };
      wait();
    });
  };
  const unsigned = { '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential'], issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:subject' } };
  const bypass = await call('POST /vc-api/credentials/verify', {
    verifiableCredential: unsigned,
    options: { securedByEnvelope: true } });
  t.check(bypass.statusCode === 400 &&
          errorCodes.codeOf(bypass) === 'STS-VC-0122' &&
          /securedByEnvelope/.test(bypass.body),
          'B4. the internal securedByEnvelope is not an option: 400 ' +
          'STS-VC-0122 (it once skipped the proof check)',
          bypass.statusCode + ' ' + bypass.body.slice(0, 200));
  const plain = await open.verifyCredentialDocument(unsigned, {});
  t.check(plain.verified === false,
          'B5. an unsigned credential does not verify',
          JSON.stringify(plain.errors).slice(0, 200));
  const secret = await call('POST /vc-api/credentials/verify', {
    verifiableCredential: unsigned, options: { verificationMethod: {
      publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: 'AA', d: 'AA' } } } });
  t.check(secret.statusCode === 400 &&
          errorCodes.codeOf(secret) === 'STS-VC-0122',
          'B6. a private member under verificationMethod is refused, not ' +
          'ignored', secret.statusCode + ' ' + secret.body.slice(0, 200));
  const unknownOption = await call(
    'POST /vc-api/issuers/:issuer/credentials/issue',
    { credential: unsigned, options: { frobnicate: true } },
    { issuer: 'eddsa-rdfc-2022' });
  t.check(unknownOption.statusCode === 400 &&
          errorCodes.codeOf(unknownOption) === 'STS-VC-0122',
          'B7. an option the issuer does not understand is 400 STS-VC-0122',
          unknownOption.statusCode + ' ' + unknownOption.body.slice(0, 200));

  t.log.info('=== B\'. the VC API\'s own keys ===');
  const tokenKids = (helpers.stsKeysFor().extraKeys || []).map(
    function (one) {
      return one.publicJwk.kid;
    });
  const realmDids = ['Ed25519', 'P-256', 'P-384'].map(function (curve) {
    return di.realmKeyFor(curve).did;
  });
  const issuers = open.issuers({ protocol: 'https', headers:
    { host: 'vc.test' }, get: function () { return 'vc.test'; } });
  t.check(issuers.length === Object.keys(vcApi.ISSUERS).length &&
          issuers.every(function (one) {
            const key = open.issuerFor(one.name).key;
            return realmDids.indexOf(one.id) < 0 &&
              tokenKids.indexOf(key.kid) < 0 &&
              /^sts-vcapi-/.test(key.kid);
          }),
          'B8. every issuer signs as a did:key of the VC API\'s own keys, ' +
          'none of them a key that signs this realm\'s tokens',
          issuers.map(function (one) {
            return one.name + ' ' + open.issuerFor(one.name).key.kid;
          }).join(', '));

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

  t.log.info('=== E. the status-list publish is an /admin-api act ===');
  const vcStatusAdmin = require('../admin-ui/vc_status_admin');
  const published = vcStatusAdmin.statusAction({ action: 'publish',
    purpose: 'revocation' }, 'tests/vc_api.js');
  t.check(published.ok === true && published.purpose === 'revocation',
          'E1. publish names a purpose and answers that the list is current',
          JSON.stringify(published));
  const badPurpose = vcStatusAdmin.statusAction({ action: 'publish',
    purpose: 'message' }, 'tests/vc_api.js');
  t.check(badPurpose.ok === false &&
          errorCodes.codeOf(badPurpose) === 'STS-VC-0082',
          'E2. a purpose this realm does not publish is refused STS-VC-0082',
          JSON.stringify(badPurpose));
  log.debug("Leaving run().");
}

module.exports = {
  name: 'vc_api',
  describe: 'the W3C VC API\'s gate (501 while vcApi.enabled is off, the ' +
            'token and scope refusals, the rate limit), the issuer\'s own ' +
            'refusals and its options, its own keys, the status-list ' +
            'publish on /admin-api, and DID resolution per DID Core 7',
  run: run
};
