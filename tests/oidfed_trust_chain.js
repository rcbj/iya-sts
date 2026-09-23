'use strict';
//
// File: oidfed_trust_chain.js
//
// ===========================================================================
// OPENID FEDERATION 1.1 TRUST CHAINS AND TRUST MARKS (#132, #133,
// 2026-09-23), in process, over a small federation built here with real keys
// and real signatures — a Trust Anchor, an Intermediate, a leaf, and a
// fourth entity reached through a stub fetcher rather than in process:
//
//   1. a presented chain validated (10.2): its expiry, its anchor and the
//      leaf's metadata read through the anchor's policy;
//   2. the refusals: an anchor that is not configured, a configured anchor
//      whose pinned key is not the one that signed, a statement signed by
//      the wrong superior, broken linkage, a statement typed otherwise, a
//      `kid` that names no key, and a `crit` claim not understood;
//   3. resolution by walking authority_hints (10.1), in process and through
//      the fetcher, with the media type checked;
//   4. a loop, too many hints and the fetch budget, each bounded (18.1);
//   5. a constraint in the anchor's statement refusing the chain;
//   6. Trust Marks (7.3): valid, issued to somebody else, from an issuer the
//      anchor does not trust for the type, and with and without the
//      delegation the anchor's `trust_mark_owners` demands (7.2.2).
// ===========================================================================

const nodeCrypto = require('crypto');
const stsCrypto = require('../common/crypto');
const EntityStatement = require('../oidfed/entity_statement');
const TrustChain = require('../oidfed/trust_chain');

const log = require('bunyan').createLogger({ name: 'oidfed_trust_chain',
  level: process.env.LOG_LEVEL || 'info' });

const ES = EntityStatement.TYP.ENTITY_STATEMENT;
const NOW = Math.floor(Date.now() / 1000);

// A Federation Entity Key: an ES256 pair, its public JWK under its RFC 7638
// thumbprint (the kid 3.1.1 recommends), and the signer the library takes.
function keyPair() {
  log.debug("Entering keyPair().");
  const pair = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = pair.publicKey.export({ format: 'jwk' });
  jwk.kid = stsCrypto.jwkThumbprint(jwk);
  log.debug("Leaving keyPair().");
  return { signer: { key: pair.privateKey, alg: 'ES256', kid: jwk.kid },
           jwks: { keys: [jwk] } };
}

function sign(payload, key, typ) {
  log.debug("Entering sign().");
  log.debug("Leaving sign().");
  return EntityStatement.sign(payload, typ || ES, key.signer);
}

// A small federation: TA above I1 above LEAF; REMOTE is a second leaf of I1
// served through the fetcher; LOOPA and LOOPB name each other.
function federation() {
  log.debug("Entering federation().");
  const ids = { ta: 'https://ta.test', i1: 'https://i1.test/fed',
                leaf: 'https://leaf.test', remote: 'https://remote.test',
                loopA: 'https://loop-a.test', loopB: 'https://loop-b.test',
                many: 'https://many.test' };
  const keys = {};
  Object.keys(ids).forEach(function (k) {
    keys[k] = keyPair();
  });
  // The owner of the `owned` Trust Mark type (7.2), named by the anchor.
  keys.owner = keyPair();
  const fedEntity = function (id) {
    log.debug("Entering fedEntity().");
    log.debug("Leaving fedEntity().");
    return { federation_entity: {
      federation_fetch_endpoint: id + '/fetch',
      federation_list_endpoint: id + '/list' } };
  };
  const statements = {
    configurations: {},
    // superior -> { sub -> jwt }
    subordinates: { [ids.ta]: {}, [ids.i1]: {}, [ids.loopA]: {},
                    [ids.loopB]: {} }
  };
  const ec = function (k, extra) {
    log.debug("Entering ec().");
    log.debug("Leaving ec().");
    return sign(Object.assign({ iss: ids[k], sub: ids[k], iat: NOW - 10,
                                exp: NOW + 3600, jwks: keys[k].jwks },
                              extra || {}), keys[k]);
  };
  statements.configurations[ids.ta] = ec('ta', {
    metadata: fedEntity(ids.ta),
    trust_mark_issuers: { 'https://ta.test/marks/good': [ids.ta],
                          'https://ta.test/marks/owned': [ids.i1] },
    trust_mark_owners: { 'https://ta.test/marks/owned':
                           { sub: 'https://owner.test',
                             jwks: keys.owner.jwks } } });
  statements.configurations[ids.i1] = ec('i1', {
    metadata: fedEntity(ids.i1), authority_hints: [ids.ta] });
  statements.configurations[ids.leaf] = ec('leaf', {
    authority_hints: [ids.i1],
    metadata: { openid_relying_party: {
      redirect_uris: ['https://leaf.test/cb'],
      token_endpoint_auth_method: 'private_key_jwt' } } });
  statements.configurations[ids.remote] = ec('remote', {
    authority_hints: [ids.i1], metadata: { openid_provider: {} } });
  statements.configurations[ids.loopA] = ec('loopA', {
    metadata: fedEntity(ids.loopA), authority_hints: [ids.loopB] });
  statements.configurations[ids.loopB] = ec('loopB', {
    metadata: fedEntity(ids.loopB), authority_hints: [ids.loopA] });
  statements.configurations[ids.many] = ec('many', {
    authority_hints: ['https://h1.test', 'https://h2.test', 'https://h3.test',
                      'https://h4.test', 'https://h5.test', 'https://h6.test',
                      'https://h7.test', ids.i1] });
  const ss = function (superior, subject, extra) {
    log.debug("Entering ss().");
    log.debug("Leaving ss().");
    return sign(Object.assign({ iss: ids[superior], sub: ids[subject],
                                iat: NOW - 10, exp: NOW + 1800,
                                jwks: keys[subject].jwks }, extra || {}),
                keys[superior]);
  };
  statements.subordinates[ids.ta][ids.i1] = ss('ta', 'i1', {
    metadata_policy: { openid_relying_party: {
      token_endpoint_auth_method: { one_of: ['private_key_jwt'],
                                    essential: true },
      contacts: { add: ['ops@ta.test'] } } } });
  statements.subordinates[ids.i1][ids.leaf] = ss('i1', 'leaf');
  statements.subordinates[ids.i1][ids.remote] = ss('i1', 'remote');
  statements.subordinates[ids.i1][ids.many] = ss('i1', 'many');
  // Each vouches for the other, so the walk reaches the loop itself.
  statements.subordinates[ids.loopA][ids.loopB] = ss('loopA', 'loopB');
  statements.subordinates[ids.loopB][ids.loopA] = ss('loopB', 'loopA');
  log.debug("Leaving federation().");
  return { ids: ids, keys: keys, statements: statements, ss: ss, ec: ec };
}

// The TrustChain under test: TA, I1, LEAF and the loop in process; REMOTE and
// MANY through the stub fetcher, which counts its calls.
function chainFor(fed, options) {
  log.debug("Entering chainFor().");
  const o = options || {};
  const calls = [];
  const local = new Set([fed.ids.ta, fed.ids.i1, fed.ids.leaf, fed.ids.loopA,
                         fed.ids.loopB]);
  const tc = new TrustChain({
    log: log,
    nowSec: function () {
      return NOW;
    },
    skewSec: function () {
      return 30;
    },
    limits: function () {
      return Object.assign({ maxHints: 3, maxDepth: 6, maxFetches: 20 },
                           o.limits || {});
    },
    local: function (entityId) {
      if (!local.has(entityId)) {
        return null;
      }
      return {
        configuration: function () {
          return fed.statements.configurations[entityId] || '';
        },
        subordinateStatement: function (sub) {
          return (fed.statements.subordinates[entityId] || {})[sub] || null;
        }
      };
    },
    fetch: function (url, accept) {
      calls.push(url);
      const u = new URL(url);
      const entity = u.origin + u.pathname.replace(
        /\/\.well-known\/openid-federation$/, '');
      const body = fed.statements.configurations[entity];
      if (body) {
        return Promise.resolve({ ok: true, status: 200, body: body,
          contentType: o.wrongType ? 'application/jwt' : accept, why: '' });
      }
      return Promise.resolve({ ok: false, status: 404, body: '',
                               contentType: '', why: 'not found' });
    }
  });
  log.debug("Leaving chainFor().");
  return { tc: tc, calls: calls };
}

async function run(t) {
  log.debug("Entering run().");
  const fed = federation();
  const ids = fed.ids;
  const anchors = [{ entityId: ids.ta, jwks: fed.keys.ta.jwks }];
  const presented = [fed.statements.configurations[ids.leaf],
                     fed.statements.subordinates[ids.i1][ids.leaf],
                     fed.statements.subordinates[ids.ta][ids.i1],
                     fed.statements.configurations[ids.ta]];
  const { tc } = chainFor(fed);

  t.log.info('=== 1. a presented chain ===');
  const good = tc.validate(presented, anchors);
  t.check(good.ok && good.anchor === ids.ta && good.exp === NOW + 1800 &&
          good.metadata.openid_relying_party.contacts[0] === 'ops@ta.test',
          '1a. validated to the anchor, expiring with its earliest ' +
          'statement, the leaf\'s metadata read through the anchor\'s policy',
          JSON.stringify({ ok: good.ok, why: good.why, exp: good.exp }));
  t.check(tc.validate(presented.slice(0, 3), anchors).ok,
          '1b. the anchor\'s own configuration may be left off (4)');

  t.log.info('=== 2. refusals ===');
  const other = keyPair();
  const wrongAnchor = tc.validate(presented,
    [{ entityId: 'https://elsewhere.test', jwks: fed.keys.ta.jwks }]);
  const wrongKey = tc.validate(presented,
    [{ entityId: ids.ta, jwks: other.jwks }]);
  t.check(!wrongAnchor.ok && wrongAnchor.error === 'invalid_trust_anchor' &&
          !wrongKey.ok && wrongKey.code === 'STS-OIDFED-0013',
          '2a. an anchor not configured, and a configured one whose pinned ' +
          'key did not sign', JSON.stringify([wrongAnchor.why, wrongKey.why]));
  const forged = fed.ss('i1', 'leaf');
  const forgedChain = presented.slice();
  forgedChain[1] = EntityStatement.sign(
    EntityStatement.decode(forged).claims, ES,
    { key: other.signer.key, alg: 'ES256',
      kid: fed.keys.i1.signer.kid });
  const broken = presented.slice();
  broken.splice(1, 1);
  t.check(tc.validate(forgedChain, anchors).code === 'STS-OIDFED-0014' &&
          tc.validate(broken, anchors).code === 'STS-OIDFED-0021',
          '2b. a statement signed by a key its superior does not name, and ' +
          'a chain with a link missing');
  const wrongTyp = presented.slice();
  wrongTyp[1] = EntityStatement.sign(
    EntityStatement.decode(presented[1]).claims, 'JWT', fed.keys.i1.signer);
  const critical = presented.slice();
  critical[0] = fed.ec('leaf', { authority_hints: [ids.i1], jti: 'x',
                                 crit: ['jti'] });
  t.check(tc.validate(wrongTyp, anchors).code === 'STS-OIDFED-0011' &&
          tc.validate(critical, anchors).code === 'STS-OIDFED-0017',
          '2c. a statement not typed entity-statement+jwt, and a crit claim ' +
          'this service does not understand');

  t.log.info('=== 3. resolution ===');
  const walked = chainFor(fed);
  const resolved = await walked.tc.resolve(ids.leaf, anchors);
  t.check(resolved.ok && resolved.chain.length === 4 &&
          walked.calls.length === 0,
          '3a. the leaf resolves in process: four statements, nothing ' +
          'fetched', JSON.stringify({ why: resolved.why }));
  const remote = await walked.tc.resolve(ids.remote, anchors);
  t.check(remote.ok && walked.calls.length === 1 &&
          walked.calls[0] ===
            'https://remote.test/.well-known/openid-federation',
          '3b. an entity elsewhere is fetched from its configuration ' +
          'endpoint and the rest resolved in process',
          JSON.stringify({ why: remote.why, calls: walked.calls }));
  const typed = await chainFor(fed, { wrongType: true }).tc
    .resolve(ids.remote, anchors);
  t.check(!typed.ok && /application\/entity-statement\+jwt/.test(typed.why),
          '3c. a configuration served as anything but ' +
          'application/entity-statement+jwt is not used', typed.why);

  t.log.info('=== 4. bounds ===');
  const loop = await chainFor(fed).tc.resolve(ids.loopA, anchors);
  t.check(!loop.ok && /loop/.test(loop.why),
          '4a. a loop of authority hints ends, unresolved', loop.why);
  const bounded = chainFor(fed, { limits: { maxHints: 3 } });
  const many = await bounded.tc.resolve(ids.many, anchors);
  t.check(!many.ok && /only the first 3/.test(many.why) &&
          bounded.calls.length <= 4,
          '4b. only oidfed.maxAuthorityHints hints are followed — here ' +
          'the one that leads anywhere is the eighth', many.why);
  const budget = await chainFor(fed, { limits: { maxFetches: 2 } }).tc
    .resolve(ids.leaf, anchors);
  t.check(!budget.ok && budget.code === 'STS-OIDFED-0028',
          '4c. and the fetch budget stops a resolution outright',
          budget.why);

  t.log.info('=== 5. constraints ===');
  const constrained = presented.slice();
  constrained[2] = fed.ss('ta', 'i1', { constraints: { max_path_length: 0 } });
  const refusedByPath = tc.validate(constrained, anchors);
  t.check(!refusedByPath.ok && refusedByPath.code === 'STS-OIDFED-0007',
          '5a. the anchor allows no Intermediate and the chain has one',
          refusedByPath.why);

  t.log.info('=== 6. Trust Marks ===');
  const taClaims = EntityStatement.decode(
    fed.statements.configurations[ids.ta]).claims;
  const mark = sign({ iss: ids.ta, sub: ids.leaf, iat: NOW - 5,
                      trust_mark_type: 'https://ta.test/marks/good' },
                    fed.keys.ta, EntityStatement.TYP.TRUST_MARK);
  t.check(tc.validateTrustMark(mark, ids.leaf, taClaims, fed.keys.ta.jwks,
                               true).ok &&
          !tc.validateTrustMark(mark, ids.remote, taClaims, fed.keys.ta.jwks,
                                true).ok,
          '6a. a mark validates for its subject and for nobody else');
  const untrusted = sign({ iss: ids.i1, sub: ids.leaf, iat: NOW - 5,
                           trust_mark_type: 'https://ta.test/marks/good' },
                         fed.keys.i1, EntityStatement.TYP.TRUST_MARK);
  t.check(tc.validateTrustMark(untrusted, ids.leaf, taClaims,
                               fed.keys.i1.jwks, true).code ===
            'STS-OIDFED-0030' &&
          tc.validateTrustMark(untrusted, ids.leaf, taClaims,
                               fed.keys.i1.jwks, false).ok,
          '6b. an issuer the anchor does not list for the type is refused ' +
          'where the federation must trust it, and not otherwise');
  const owner = fed.keys.owner;
  const ownedClaims = taClaims;
  const delegation = sign({ iss: 'https://owner.test', sub: ids.i1,
                            iat: NOW - 5,
                            trust_mark_type: 'https://ta.test/marks/owned' },
                          owner, EntityStatement.TYP.TRUST_MARK_DELEGATION);
  const delegated = sign({ iss: ids.i1, sub: ids.leaf, iat: NOW - 5,
                           trust_mark_type: 'https://ta.test/marks/owned',
                           delegation: delegation },
                         fed.keys.i1, EntityStatement.TYP.TRUST_MARK);
  const undelegated = sign({ iss: ids.i1, sub: ids.leaf, iat: NOW - 5,
                             trust_mark_type: 'https://ta.test/marks/owned' },
                           fed.keys.i1, EntityStatement.TYP.TRUST_MARK);
  const byOther = sign({ iss: 'https://owner.test', sub: ids.i1, iat: NOW - 5,
                         trust_mark_type: 'https://ta.test/marks/owned' },
                       other, EntityStatement.TYP.TRUST_MARK_DELEGATION);
  const forgedDelegation = sign({ iss: ids.i1, sub: ids.leaf, iat: NOW - 5,
                                  trust_mark_type:
                                    'https://ta.test/marks/owned',
                                  delegation: byOther },
                                fed.keys.i1, EntityStatement.TYP.TRUST_MARK);
  const v = function (m) {
    log.debug("Entering v().");
    log.debug("Leaving v().");
    return tc.validateTrustMark(m, ids.leaf, ownedClaims, fed.keys.i1.jwks,
                                true);
  };
  t.check(v(delegated).ok && v(undelegated).code === 'STS-OIDFED-0031' &&
          v(forgedDelegation).code === 'STS-OIDFED-0031',
          '6c. an owned type needs a delegation the owner signed (7.2.2)',
          JSON.stringify([v(delegated).why, v(undelegated).why]));
  log.debug("Leaving run().");
}

module.exports = {
  name: 'oidfed_trust_chain',
  describe: 'OpenID Federation trust chains and trust marks (#132): ' +
            'validation, resolution in process and by fetching, the 18.1 ' +
            'bounds, constraints, and 7.3 with delegation',
  run: run
};
