'use strict';
//
// File: oidfed_entity.js
//
// ===========================================================================
// THIS SERVICE AS AN OPENID FEDERATION (#132, #133, 2026-09-23), in process:
// the default realm a Trust Anchor and a realm made here its Subordinate —
// rcbj's answer 1, one service a whole federation.
//
//   1. the default realm's Entity Configuration: typed, signed by its own
//      Federation Entity Key, its issuer the Entity Identifier, the fetch
//      and list endpoints published because it vouches for a realm, no
//      authority_hints (a Trust Anchor);
//   2. the second realm: a Leaf naming the default realm and trusting it;
//   3. the fetch endpoint: the statement about the realm pins that realm's
//      own keys; itself and a stranger refused;
//   4. resolution in process — the realm to the anchor, three statements,
//      nothing fetched — and the signed resolve response; an entity
//      elsewhere is never walked for an unauthenticated resolve (18.1);
//   5. Trust Marks: a type registered, a mark issued to the realm and handed
//      to it, carried in its Entity Configuration, active, verified in the
//      resolution, then revoked and gone from it;
//   6. a registered subordinate with a metadata policy and the listing's
//      filters, and the acts that refuse bad input;
//   7. the keys: a rotation retires the key into the Historical Keys list
//      and keeps it published through the overlap, a revocation takes it out
//      with its reason, and the current key cannot be revoked by hand.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const config = require('../common/config');
const realms = require('../common/realms');
const stsCrypto = require('../common/crypto');
require('../ldap/ldap_server');
require('../oauth-oidc/oauth2');
const oidfed = require('../oidfed/oidfed');
const keys = require('../oidfed/federation_keys');
const EntityStatement = require('../oidfed/entity_statement');

const log = require('bunyan').createLogger({ name: 'oidfed_entity',
  level: process.env.LOG_LEVEL || 'info' });

const RUN = Date.now().toString(36);
const REALM = 'oidfed-' + RUN;
const TYPE = 'https://sts.test/marks/audited-' + RUN;

function fakeReq() {
  log.debug("Entering fakeReq().");
  log.debug("Leaving fakeReq().");
  return { protocol: 'https', headers: { host: 'sts.test' }, query: {},
           get: function (name) {
             return String(name).toLowerCase() === 'host' ? 'sts.test' : '';
           } };
}

function claimsOf(jwt) {
  log.debug("Entering claimsOf().");
  log.debug("Leaving claimsOf().");
  return EntityStatement.decode(jwt).claims;
}

function inRealm(id, fn) {
  log.debug("Entering inRealm(). " + id);
  log.debug("Leaving inRealm().");
  return realms.run(realms.get(id), fn);
}

async function run(t) {
  log.debug("Entering run().");
  realms.create({ id: REALM, name: 'OpenID Federation test' });
  try {
    await body(t);
  } finally {
    realms.remove(REALM);
  }
  log.debug("Leaving run().");
}

async function body(t) {
  log.debug("Entering body().");
  const req = fakeReq();
  const anchorId = oidfed.entityId(req);
  const leafId = inRealm(REALM, function () {
    return oidfed.entityId(req);
  });

  t.log.info('=== 1. the default realm, a Trust Anchor ===');
  const ec = await oidfed.configuration(req);
  const header = EntityStatement.decode(ec.jwt).header;
  const self = EntityStatement.verify(ec.jwt, ec.claims.jwks,
                                      'entity-statement+jwt');
  const fe = ec.claims.metadata.federation_entity;
  t.check(ec.ok && header.typ === 'entity-statement+jwt' && self.ok &&
          anchorId === 'https://sts.test' && ec.claims.iss === anchorId &&
          ec.claims.sub === anchorId &&
          ec.claims.metadata.openid_provider.issuer === anchorId &&
          !!ec.claims.metadata.oauth_authorization_server &&
          !!ec.claims.metadata.openid_credential_verifier &&
          fe.federation_fetch_endpoint === anchorId + '/oidfed/fetch' &&
          !ec.claims.authority_hints && oidfed.roleOf(req) === 'trust anchor',
          '1a. typed, self-signed, the issuer its Entity Identifier, fetch ' +
          'and list published, no authority_hints',
          JSON.stringify({ header: header, fe: fe }));
  const protocol = require('../common/helpers').stsKeysFor();
  const protocolKids = [protocol.kid].concat((protocol.extraKeys || [])
    .map(function (k) {
      return k.publicJwk.kid;
    }));
  t.check(ec.claims.jwks.keys.every(function (k) {
    return protocolKids.indexOf(k.kid) < 0 &&
           k.kid === stsCrypto.jwkThumbprint(k);
  }), '1b. its Federation Entity Keys are none of its protocol keys, each ' +
      'named by its RFC 7638 thumbprint (3.1.1)');

  t.log.info('=== 2. the realm, a Leaf ===');
  const leafEc = await inRealm(REALM, function () {
    return oidfed.configuration(req);
  });
  t.check(leafEc.ok && leafId === 'https://sts.test/realm/' + REALM &&
          leafEc.claims.authority_hints[0] === anchorId &&
          !leafEc.claims.metadata.federation_entity.federation_fetch_endpoint &&
          inRealm(REALM, function () {
            return oidfed.roleOf(req);
          }) === 'leaf' &&
          inRealm(REALM, function () {
            return oidfed.anchors(req).map(function (a) {
              return a.entityId;
            });
          }).indexOf(anchorId) >= 0,
          '2a. it names the default realm, publishes no fetch endpoint and ' +
          'trusts the default realm as its anchor',
          JSON.stringify(leafEc.claims && leafEc.claims.authority_hints));

  t.log.info('=== 3. the fetch endpoint ===');
  const ss = await oidfed.subordinateStatement(req, leafId);
  const selfSs = await oidfed.subordinateStatement(req, anchorId);
  const stranger = await oidfed.subordinateStatement(req, 'https://x.test');
  t.check(ss.ok && ss.claims.iss === anchorId && ss.claims.sub === leafId &&
          JSON.stringify(ss.claims.jwks) ===
            JSON.stringify(leafEc.claims.jwks) &&
          !selfSs.ok && selfSs.error === 'invalid_request' &&
          !stranger.ok && stranger.error === 'not_found',
          '3a. the statement pins the realm\'s own keys; itself is ' +
          'invalid_request and a stranger not_found',
          JSON.stringify([selfSs.why, stranger.why]));

  t.log.info('=== 4. resolution ===');
  const resolved = await oidfed.resolve(req, leafId, [], false);
  const response = await oidfed.resolveResponse(req, leafId, [anchorId], []);
  const rr = response.ok ? EntityStatement.verify(response.jwt,
    ec.claims.jwks, 'resolve-response+jwt') : {};
  t.check(resolved.ok && resolved.resolved.chain.length === 3 &&
          resolved.resolved.anchor === anchorId && rr.ok &&
          rr.claims.sub === leafId && rr.claims.trust_chain.length === 3 &&
          !!rr.claims.metadata.openid_provider,
          '4a. the realm resolves in process to the anchor, and the resolve ' +
          'response is signed by the anchor\'s key',
          JSON.stringify({ why: resolved.why, rwhy: response.why }));
  const remote = await oidfed.resolve(req, 'https://elsewhere.test', [],
                                      false);
  t.check(!remote.ok && remote.error === 'not_found' &&
          remote.code === 'STS-OIDFED-0036',
          '4b. an entity elsewhere is not walked for an unauthenticated ' +
          'resolve (18.1)', remote.why);

  t.log.info('=== 5. Trust Marks ===');
  const typed = await oidfed.act({ action: 'add-mark-type', type: TYPE,
                                   lifetimeS: 3600 }, { req: req });
  const issued = await oidfed.act({ action: 'issue-trust-mark', type: TYPE,
                                    sub: leafId }, { req: req });
  const carried = await inRealm(REALM, function () {
    return oidfed.configuration(req);
  });
  const marks = (carried.claims && carried.claims.trust_marks) || [];
  const policyEc = await oidfed.configuration(req);
  t.check(typed.ok && issued.ok &&
          marks.length === 1 && marks[0].trust_mark_type === TYPE &&
          oidfed.markStatusOf(issued.trustMark) === 'active' &&
          policyEc.claims.trust_mark_issuers[TYPE][0] === anchorId &&
          policyEc.claims.metadata.federation_entity
            .federation_trust_mark_status_endpoint ===
            anchorId + '/oidfed/trust-mark-status',
          '5a. a mark issued to the realm is carried in its Entity ' +
          'Configuration, active, and the anchor names itself its issuer',
          JSON.stringify({ typed: typed.errors, issued: issued.errors }));
  const withMark = await oidfed.resolve(req, leafId, [], false);
  t.check(withMark.ok && withMark.marks.length === 1,
          '5b. and the resolution verifies it (7.3)',
          JSON.stringify(withMark.marks));
  const revoked = await oidfed.act({ action: 'revoke-trust-mark',
                                     id: issued.id }, { req: req });
  const afterRevoke = await oidfed.resolve(req, leafId, [], false);
  t.check(revoked.ok && oidfed.markStatusOf(issued.trustMark) === 'revoked' &&
          afterRevoke.ok && afterRevoke.marks.length === 0,
          '5c. revoked, its status says so and the resolution drops it');

  t.log.info('=== 6. a registered subordinate ===');
  const pair = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = pair.publicKey.export({ format: 'jwk' });
  jwk.kid = stsCrypto.jwkThumbprint(jwk);
  const rpId = 'https://rp-' + RUN + '.test';
  const policy = { openid_relying_party: {
    token_endpoint_auth_method: { one_of: ['private_key_jwt'] } } };
  const added = await oidfed.act({ action: 'add-subordinate', entityId: rpId,
    jwks: JSON.stringify({ keys: [jwk] }),
    metadataPolicy: JSON.stringify(policy),
    entityTypes: 'openid_relying_party' }, { req: req });
  const rpSs = await oidfed.subordinateStatement(req, rpId);
  const listRp = await require('../oidfed/oidfed').subordinates(req);
  t.check(added.ok && rpSs.ok &&
          JSON.stringify(rpSs.claims.metadata_policy) ===
            JSON.stringify(policy) &&
          listRp.some(function (s) {
            return s.entityId === rpId;
          }),
          '6a. registered with keys and a policy, which its statement carries',
          JSON.stringify(added.errors));
  const refused = [
    await oidfed.act({ action: 'add-subordinate', entityId: 'http://rp.test',
                       jwks: JSON.stringify({ keys: [jwk] }) }, { req: req }),
    await oidfed.act({ action: 'add-subordinate', entityId: rpId,
                       jwks: '{"keys":[]}' }, { req: req }),
    await oidfed.act({ action: 'add-subordinate', entityId: rpId,
                       jwks: JSON.stringify({ keys: [jwk] }),
                       metadataPolicy: '{"t":{"p":{"one_of":["a"],' +
                                       '"add":["a"]}}}' }, { req: req })];
  t.check(refused.every(function (r) {
    return !r.ok;
  }), '6b. an http identifier, an empty JWK Set and a policy combining ' +
      'one_of with add are refused');

  t.log.info('=== 7. the keys ===');
  const before = keys.view().filter(function (k) {
    return k.state === 'current';
  })[0];
  const rotated = await keys.rotate({ reason: 'test' });
  const history = keys.historical();
  const published = keys.jwks().keys.map(function (k) {
    return k.kid;
  });
  t.check(rotated.ok && rotated.from === before.kid &&
          history.some(function (k) {
            return k.kid === before.kid && Number.isFinite(k.exp) &&
                   !k.revoked;
          }) && published.indexOf(before.kid) >= 0 &&
          published.indexOf(rotated.to) >= 0 &&
          published.indexOf(rotated.next) >= 0,
          '7a. rotated: the old key historical and still published through ' +
          'the overlap, beside the new current and next ones',
          JSON.stringify({ history: history.length, published: published }));
  const revokedKey = keys.revoke(before.kid, 'compromised');
  const current = keys.revoke(rotated.to, 'compromised');
  const afterKey = keys.historical().filter(function (k) {
    return k.kid === before.kid;
  })[0];
  t.check(revokedKey.ok && afterKey.revoked &&
          afterKey.revoked.reason === 'compromised' &&
          keys.jwks().keys.every(function (k) {
            return k.kid !== before.kid;
          }) && !current.ok && current.code === 'STS-OIDFED-0042',
          '7b. a revoked key leaves the published set with its reason in ' +
          'the history, and the current key cannot be revoked by hand');
  const hk = await oidfed.historicalKeysResponse(req);
  const hkClaims = hk.ok ? claimsOf(hk.jwt) : {};
  t.check(hk.ok && EntityStatement.decode(hk.jwt).header.typ ===
            'jwk-set+jwt' &&
          hkClaims.iss === anchorId && hkClaims.keys.some(function (k) {
            return k.kid === before.kid && k.revoked;
          }),
          '7c. the Historical Keys response is a signed jwk-set+jwt ' +
          'listing it');
  config.clearOverride('oidfed.signingAlg');
  log.debug("Leaving body().");
}

module.exports = {
  name: 'oidfed_entity',
  describe: 'OpenID Federation (#132): the default realm a Trust Anchor and ' +
            'a realm its subordinate, fetch, resolution, Trust Marks, the ' +
            'register and the keys, in process',
  run: run
};
