'use strict';
//
// File: gnap_request.js
//
// ---------------------------------------------------------------------------
// WHAT A GNAP ENDPOINT WILL READ: THE JSON SCHEMAS, THE SANITISATION, THE
// REQUEST WALKERS, THE KEY DESCRIPTORS AND THE INTERACTION HASH.
//
// Every GNAP document is refused in three layers before a handler reads it —
// `validation.checkDocument()` bounds its depth and key count, an ajv 2020 JSON
// Schema (`gnap/gnap_schemas.js`) bounds every string, array and object and
// refuses a control character in any member, and the walker in
// `gnap/gnap_request.js` enforces what RFC 9635 and RFC 9767 require. The over-
// HTTP jobs assert that a refusal ARRIVES; this file asserts WHICH LAYER refused
// and why, because a schema that silently stopped applying would be invisible
// over HTTP for every request the walker also happens to refuse.
//
// It also holds two EXTERNAL answers, which are the only kind that mean
// anything about a derivation: RFC 9635 section 4.2.3's interaction hash
// examples (sha-256 and sha3-512), and RFC 7638 section 3.1's JWK thumbprint.
// ---------------------------------------------------------------------------

const nodeCrypto = require('crypto');
const errorCodes = require('../common/error_codes');
const schemas = require('../gnap/gnap_schemas');
const request = require('../gnap/gnap_request');
const keys = require('../gnap/gnap_keys');

const ED = { kty: 'OKP', crv: 'Ed25519', x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo' };

function grant(extra) {
  return Object.assign({
    access_token: { access: ['photos'] },
    client: { key: { proof: 'httpsig', jwk: ED } },
    interact: { start: ['redirect'], finish: { method: 'redirect', uri: 'https://c.example/cb', nonce: 'n1' } }
  }, extra || {});
}

function codeOf(result) {
  return errorCodes.codeOf(result) || result.errorCode;
}

function checkSchemas(t) {
  t.log.info('A. the JSON Schemas');
  ['grantRequest', 'continuation', 'modification', 'rotation', 'introspection', 'registration']
    .forEach(function (name) {
      t.check(schemas.SCHEMAS[name] && typeof schemas.SCHEMAS[name].$id === 'string',
              'the ' + name + ' schema is published with an $id');
    });
  t.check(!schemas.validate('nope', {}).ok, 'an unknown schema name validates nothing');
  t.check(schemas.validate('grantRequest', grant()).ok, 'a well-formed grant request passes its schema');

  let v = schemas.validate('grantRequest', grant({ access_token: { access: ['a'], label: 42 } }));
  t.check(!v.ok && /label/.test(v.path), 'a numeric label fails at its path', v.detail);
  v = schemas.validate('grantRequest', grant({ client: { key: { proof: 'httpsig', jwk: ED },
                                                         class_id: 'bad\u0007class' } }));
  t.check(!v.ok && /control character/.test(v.detail), 'a BEL in class_id is named as a control character',
          v.detail);
  v = schemas.validate('grantRequest', grant({ client: { key: { proof: 'httpsig', jwk: ED },
                                                         display: { name: 'x\u007fy' } } }));
  t.check(!v.ok && /control character/.test(v.detail), 'DEL is a control character too', v.detail);
  v = schemas.validate('grantRequest', grant({ client: { key: { proof: 'httpsig', jwk: ED },
                                                         display: { name: 'x'.repeat(100000) } } }));
  t.check(!v.ok, 'a display name of 100,000 characters exceeds its maxLength', v.detail);
  v = schemas.validate('grantRequest', grant({ access_token: { access: new Array(5000).fill('a') } }));
  t.check(!v.ok, 'five thousand access rights exceed the array bound', v.detail);
  v = schemas.validate('grantRequest', grant({ interact: { start: ['redirect'],
    finish: { method: 'redirect', uri: 'not a uri', nonce: 'n' } } }));
  t.check(!v.ok && /uri/.test(v.detail), 'a finish uri that is not a URI fails format "uri"', v.detail);
  v = schemas.validate('grantRequest', grant({ client: { key: { proof: 'httpsig', jwk: ED },
    display: { name: 'ok', logo_uri: 'data:image/png;base64,iVBORw0KGgo=' } } }));
  t.check(v.ok, 'a data: image logo is legitimate (section 2.3.2)', v.detail);
  v = schemas.validate('introspection', { access_token: 7, resource_server: 'rs' });
  t.check(!v.ok, 'a numeric access_token fails the introspection schema', v.detail);
  v = schemas.validate('registration', { access: ['x'], resource_server: 'rs',
                                         token_introspection_required: 'yes' });
  t.check(!v.ok, 'a string token_introspection_required fails the registration schema', v.detail);
  const wide = {};
  for (let i = 0; i < 200; i++) {
    wide['m' + i] = 'v';
  }
  v = schemas.validate('grantRequest', grant({ access_token: { access: [Object.assign({ type: 't' }, wide)] } }));
  t.check(!v.ok, 'an access right with two hundred members exceeds maxProperties', v.detail);
}

function checkEnvelope(t) {
  t.log.info('B. the envelope: which layer refuses');
  let r = request.parseGrantRequest('not an object');
  t.equal(codeOf(r), 'STS-GNAP-0052', 'a body that is not an object is refused before any schema');
  let deep = { v: 1 };
  for (let i = 0; i < 40; i++) {
    deep = { d: deep };
  }
  r = request.parseGrantRequest(grant({ access_token: { access: [{ type: 't', deep: deep }] } }));
  t.equal(codeOf(r), 'STS-GNAP-0053', 'a document nested forty deep is refused by the bound, not the schema');
  r = request.parseGrantRequest(grant({ access_token: { access: ['a'], label: 42 } }));
  t.equal(codeOf(r), 'STS-GNAP-0061', 'a type error is refused by the schema layer (0061)');
  t.check(/schema/.test(r.why), 'and the sentence says it was the schema', r.why);
  r = request.parseIntrospection({ resource_server: 'rs' });
  t.check(!r.ok && r.gnapError === 'invalid_request', 'introspection with no access_token is invalid_request');
  r = request.parseRegistration({ access: [], resource_server: 'rs' });
  t.check(!r.ok, 'a registration with no rights is refused');
  r = request.parseRegistration({ access: ['x'] });
  t.check(!r.ok && r.gnapError === 'invalid_resource_server', 'a registration naming no resource server is ' +
          'invalid_resource_server', JSON.stringify(r));
}

function checkWalkers(t) {
  t.log.info('C. the request walkers');
  let r = request.parseGrantRequest(grant());
  t.check(r.ok && r.request.tokens.length === 1 && !r.request.multiple, 'a single-token request parses');
  t.equal(r.request.interact.finish.hashMethod, 'sha-256', 'the hash method defaults to sha-256 (4.2.3)');
  r = request.parseGrantRequest(grant({ access_token: [{ label: 'a', access: ['x'] }, { label: 'b', access: ['y'] }] }));
  t.check(r.ok && r.request.multiple && r.request.tokens.length === 2, 'a labelled multiple-token request parses');
  r = request.parseGrantRequest(grant({ access_token: [{ label: 'a', access: ['x'] }, { access: ['y'] }] }));
  t.check(!r.ok && r.gnapError === 'invalid_request', 'an unlabelled token in a multiple request is refused');
  r = request.parseGrantRequest(grant({ access_token: [{ label: 'a', access: ['x'] }, { label: 'a', access: ['y'] }] }));
  t.check(!r.ok, 'two tokens with one label are refused');
  r = request.parseGrantRequest(grant({ access_token: { access: ['x'], flags: ['bearer', 'bearer'] } }));
  t.equal(r.gnapError, 'invalid_flag', 'a repeated flag is invalid_flag');
  r = request.parseGrantRequest(grant({ access_token: { access: ['x'], flags: ['durable'] } }));
  t.equal(r.gnapError, 'invalid_flag', 'the response-only durable flag is invalid_flag in a request');
  r = request.parseGrantRequest(grant({ interact_ref: 'abc' }));
  t.check(!r.ok, 'interact_ref on a new request is refused (5.1)');
  r = request.parseGrantRequest(grant({ existing_access_token: 'tok' }));
  t.check(r.ok && r.request.existingAccessToken === 'tok', 'existing_access_token is carried for derivation');
  r = request.parseGrantRequest(grant({ interact: { start: ['redirect'],
    finish: { method: 'redirect', uri: 'https://c.example/cb', nonce: 'n', hash_method: 'md5' } } }));
  t.check(!r.ok, 'a hash_method outside the Named Information registry is refused');
  r = request.parseGrantRequest(grant({ subject: { sub_id_formats: ['opaque', 'email'],
                                                   assertion_formats: ['id_token'] } }));
  t.check(r.ok && r.request.subject, 'a subject request with sub_id and assertion formats parses');
  r = request.parseContinuation({ interact_ref: 'ref-1' }, true);
  t.check(r.ok && r.interactRef === 'ref-1', 'a continuation carries its interact_ref');
  r = request.parseContinuation({ interact_ref: 7 }, true);
  t.check(!r.ok, 'a numeric interact_ref is refused');
  r = request.parseModification({ client: { key: { proof: 'httpsig', jwk: ED } } });
  t.check(!r.ok, 'a modification carrying client is refused (5.3)');
  t.check(request.checkSubId({ format: 'email', email: 'a@b.example' }, 'sub').ok, 'an email sub_id passes');
  t.check(!request.checkSubId({ format: 'email' }, 'sub').ok, 'an email sub_id with no email is refused');
  t.check(!request.checkSubId({ format: 'email', email: 'a@b.example', extra: 1 }, 'sub').ok,
          'a sub_id carrying a member its format does not define is refused (RFC 9493 closed sets)');
  t.check(!request.checkSubId({ format: 'nonsense' }, 'sub').ok, 'an unknown sub_id format is refused');
}

function checkKeys(t) {
  t.log.info('D. keys, and RFC 7638\'s published thumbprint');
  // RFC 7638 section 3.1.
  const rfcKey = { kty: 'RSA', e: 'AQAB', alg: 'RS256', kid: '2011-04-29',
    n: '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECP' +
       'ebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368' +
       'QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2Nc' +
       'Rwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw' };
  const described = keys.describe({ proof: 'httpsig', jwk: rfcKey });
  t.check(described.ok, 'a public RSA JWK describes', JSON.stringify(described).slice(0, 200));
  t.equal(described.thumbprint, 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs',
          'its thumbprint is RFC 7638 section 3.1\'s published value');
  t.equal(described.identity, 'jkt:NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs', 'and its identity is jkt:');
  t.check(!keys.describe({ proof: 'httpsig', jwk: Object.assign({ d: 'AAAA' }, ED) }).ok,
          'a JWK carrying a private member is refused (7.1)');
  t.check(!keys.describe({ proof: 'httpsig', jwk: ED, 'cert#S256': 'abc' }).ok, 'a key in two formats is refused');
  t.check(!keys.describe({ jwk: ED }).ok, 'a key with no proof method is refused');
  t.check(keys.normaliseProof('jwsd').ok &&
          keys.normaliseProof({ method: 'httpsig', alg: 'ecdsa-p256-sha256', 'content-digest-alg': 'sha-256' }).ok,
          'a proof may be a method name, or an httpsig object with alg and content-digest-alg (7.3.1)');
  t.check(!keys.normaliseProof({ method: 'httpsig' }).ok,
          'an httpsig object without its two REQUIRED parameters is refused');
  t.check(!keys.normaliseProof({ method: 'jwsd' }).ok,
          'an object form for a string-only method is refused (10.16)');
  t.check(!keys.normaliseProof('telepathy').ok, 'an unknown proof method is refused');
  const cnf = keys.confirmationOf(described);
  t.equal(JSON.stringify(cnf), JSON.stringify({ jkt: described.thumbprint }), 'a JWK key binds as cnf.jkt');
}

function checkInteractionHash(t) {
  t.log.info('E. RFC 9635 section 4.2.3\'s published interaction hashes');
  const grants = require('../gnap/gnap_grants');
  const args = ['VJLO6A4CATR0KRO', 'MBDOFXG4Y5CVJCX821LH', '4IFWWIKYB2PQ6U56NL1', 'https://server.example.com/tx'];
  t.equal(grants.interactionHash.apply(null, args.concat(['sha-256'])),
          'x-gguKWTj8rQf7d7i3w3UhzvuJ5bpOlKyAlVpLxBffY', 'sha-256 matches the RFC\'s example');
  t.equal(grants.interactionHash.apply(null, args.concat(['sha3-512'])),
          'pyUkVJSmpqSJMaDYsk5G8WCvgY91l-agUPe1wgn-cc5rUtN69gPI2-S_s-Eswed8iB4PJ_a5Hg6DNi7qGgKwSQ',
          'sha3-512 matches the RFC\'s example');
  t.equal(grants.interactionHash.apply(null, args),
          'x-gguKWTj8rQf7d7i3w3UhzvuJ5bpOlKyAlVpLxBffY', 'and no hash method means sha-256');
  const truncated = grants.interactionHash.apply(null, args.concat(['sha-256-128']));
  t.equal(Buffer.from(truncated, 'base64url').length, 16, 'a truncated method keeps its leftmost 128 bits');
  t.equal(truncated, nodeCrypto.createHash('sha256').update(args.join('\n')).digest().subarray(0, 16)
    .toString('base64url'), 'and those are the leftmost bits of the full digest');
}

module.exports = {
  name: 'gnap_request',
  describe: 'what a GNAP endpoint reads: the JSON Schemas and control-character sanitisation, which layer ' +
            'refuses what, the request walkers, key descriptors, and the RFC 9635 / RFC 7638 vectors',
  run: function (t) {
    checkSchemas(t);
    checkEnvelope(t);
    checkWalkers(t);
    checkKeys(t);
    checkInteractionHash(t);
  }
};
