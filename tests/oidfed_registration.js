'use strict';
//
// File: oidfed_registration.js
//
// ===========================================================================
// A RELYING PARTY REGISTERED THROUGH THE FEDERATION (#134, 2026-09-23), in
// process. The default realm is the Trust Anchor, a realm made here is the
// OP, and a foreign RP is registered as the anchor's subordinate with a
// Federation Entity Key made here. Every chain is PRESENTED — a request
// object's trust_chain header, an application/trust-chain+json body — so
// nothing is fetched.
//
//   1. automatic registration (12.1): a request object signed by the RP's
//      protocol key, with its Trust Chain in the header, registers the RP
//      with its resolved metadata, `private_key_jwt`, the anchor and an
//      expiry no later than the chain's; `wants()` is then false;
//   2. the refusals: no proof, an aud naming somebody else or two
//      audiences, a `sub` on a request object, a key that is not the RP's,
//      a secret-based method, a chain about somebody else, a realm that
//      does not offer it;
//   3. the registration ends (12.3): past its expiry the client is unknown
//      to `clientConfigOf()`, and the job removes the entry;
//   4. explicit registration (12.2): a Trust Chain body whose configuration
//      names this OP answers a signed explicit-registration-response+jwt
//      with trust_anchor, authority_hints and the registered metadata, and
//      a secret-based method gets a secret that expires with it; a wrong
//      media type, a configuration without aud, and explicit turned off are
//      refused.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const config = require('../common/config');
const realms = require('../common/realms');
const stsCrypto = require('../common/crypto');
require('../ldap/ldap_server');
require('../oauth-oidc/oauth2');
const applications = require('../common/applications');
const oidfed = require('../oidfed/oidfed');
const registration = require('../oidfed/oidfed_registration');
const EntityStatement = require('../oidfed/entity_statement');

const log = require('bunyan').createLogger({ name: 'oidfed_registration',
  level: process.env.LOG_LEVEL || 'info' });

const RUN = Date.now().toString(36);
const REALM = 'oidfreg-' + RUN;

function fakeReq() {
  log.debug("Entering fakeReq().");
  log.debug("Leaving fakeReq().");
  return { protocol: 'https', headers: { host: 'sts.test' }, query: {},
           get: function (name) {
             return String(name).toLowerCase() === 'host' ? 'sts.test' : '';
           } };
}

function inRealm(id, fn) {
  log.debug("Entering inRealm(). " + id);
  log.debug("Leaving inRealm().");
  return realms.run(realms.get(id), fn);
}

// An EC key pair and its public JWK, named by its thumbprint.
function ecKey() {
  log.debug("Entering ecKey().");
  const pair = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = pair.publicKey.export({ format: 'jwk' });
  jwk.kid = stsCrypto.jwkThumbprint(jwk);
  jwk.alg = 'ES256';
  jwk.use = 'sig';
  log.debug("Leaving ecKey().");
  return { privateKey: pair.privateKey, jwk: jwk };
}

// A compact ES256 JWS with whatever header members the case needs.
function jws(header, payload, key) {
  log.debug("Entering jws().");
  const b64 = function (o) {
    return Buffer.from(JSON.stringify(o)).toString('base64url');
  };
  const input = b64(Object.assign({ alg: 'ES256' }, header)) + '.' +
                b64(payload);
  const sig = nodeCrypto.sign('sha256', Buffer.from(input),
    { key: key, dsaEncoding: 'ieee-p1363' }).toString('base64url');
  log.debug("Leaving jws().");
  return input + '.' + sig;
}

async function run(t) {
  log.debug("Entering run().");
  realms.create({ id: REALM, name: 'OpenID Federation registration test' });
  try {
    await body(t);
  } finally {
    config.clearOverride('oidfed.clientRegistrationTypes');
    config.clearOverride('oidfed.registrationLifetimeS');
    realms.remove(REALM);
  }
  log.debug("Leaving run().");
}

async function body(t) {
  log.debug("Entering body().");
  const req = fakeReq();
  const now = Math.floor(Date.now() / 1000);
  const anchorId = oidfed.entityId(req);
  const opId = inRealm(REALM, function () {
    return oidfed.entityId(req);
  });
  const anchorEc = await oidfed.configuration(req);

  // The RP: a Federation Entity Key, a protocol key, and the anchor's
  // statement about it.
  const fedKey = ecKey();
  const rpKey = ecKey();
  const rpId = 'https://rp-' + RUN + '.test';
  const added = await oidfed.act({ action: 'add-subordinate', entityId: rpId,
    jwks: JSON.stringify({ keys: [fedKey.jwk] }),
    entityTypes: 'openid_relying_party' }, { req: req });
  const ss = await oidfed.subordinateStatement(req, rpId);
  const rpMetadata = function (extra) {
    return { openid_relying_party: Object.assign({
      redirect_uris: [rpId + '/cb'], response_types: ['code'],
      grant_types: ['authorization_code'], client_name: 'Federated RP',
      jwks: { keys: [rpKey.jwk] } }, extra || {}) };
  };
  const rpConfiguration = function (extra, claims) {
    return EntityStatement.sign(Object.assign({
      iss: rpId, sub: rpId, iat: now, exp: now + 3600,
      jwks: { keys: [fedKey.jwk] }, authority_hints: [anchorId],
      metadata: rpMetadata(extra) }, claims || {}),
      'entity-statement+jwt',
      { key: fedKey.privateKey, alg: 'ES256', kid: fedKey.jwk.kid });
  };
  const chainFor = function (ec) {
    return [ec, ss.jwt, anchorEc.jwt];
  };
  const requestObject = function (claims, header, key) {
    return jws(Object.assign({ typ: 'oauth-authz-req+jwt',
                               kid: rpKey.jwk.kid,
                               trust_chain: chainFor(rpConfiguration()) },
                             header || {}),
               Object.assign({ iss: rpId, client_id: rpId, aud: opId,
                               jti: nodeCrypto.randomUUID(), iat: now,
                               exp: now + 300, response_type: 'code',
                               redirect_uri: rpId + '/cb',
                               scope: 'openid' }, claims || {}),
               key || rpKey.privateKey);
  };
  t.check(added.ok && ss.ok && anchorEc.ok,
          '0. the RP is the anchor\'s subordinate',
          JSON.stringify(added.errors || ss.why));

  t.log.info('=== 1. automatic registration ===');
  const wantedBefore = inRealm(REALM, function () {
    return registration.wants(req, rpId);
  });
  const auto = await inRealm(REALM, function () {
    return registration.automatic(req, rpId, { request: requestObject() });
  });
  const client = inRealm(REALM, function () {
    return applications.clientConfigOf(rpId);
  });
  const listed = inRealm(REALM, function () {
    return applications.federatedRegistrations();
  }).filter(function (r) {
    return r.identifier === rpId;
  })[0];
  t.check(wantedBefore && auto.ok && client.known &&
          client.token_endpoint_auth_method === 'private_key_jwt' &&
          JSON.stringify(client.redirect_uris) ===
            JSON.stringify([rpId + '/cb']) &&
          !!listed && listed.type === 'automatic' &&
          listed.trustAnchor === anchorId &&
          listed.expiresAt <= now + 3600 && !listed.expired &&
          !inRealm(REALM, function () {
            return registration.wants(req, rpId);
          }),
          '1a. registered from its resolved metadata, private_key_jwt, the ' +
          'anchor recorded and an expiry within the chain\'s',
          JSON.stringify({ auto: auto, listed: listed,
                           method: client.token_endpoint_auth_method }));
  t.check(!inRealm(REALM, function () {
    return registration.wants(req, 'webapp1');
  }), '1b. a client_id that is not an Entity Identifier is not a ' +
      'federation registration');

  t.log.info('=== 2. the refusals ===');
  inRealm(REALM, function () {
    return applications.deleteApplication(rpId, { actor: 'test' });
  });
  const other = ecKey();
  const cases = [
    ['no proof', {}, 'STS-OIDFED-0054'],
    ['aud another OP', { request: requestObject({ aud: anchorId }) },
     'STS-OIDFED-0054'],
    ['two audiences', { request: requestObject({ aud: [opId, anchorId] }) },
     'STS-OIDFED-0054'],
    ['a sub', { request: requestObject({ sub: rpId }) }, 'STS-OIDFED-0054'],
    ['no jti', { request: requestObject({ jti: undefined }) },
     'STS-OIDFED-0054'],
    ['another key', { request: requestObject({}, { kid: other.jwk.kid },
                                             other.privateKey) },
     'STS-OIDFED-0054'],
    ['a symmetric alg', { request: requestObject({}, { alg: 'HS256' }) },
     'STS-OIDFED-0054'],
    ['a secret method', { request: requestObject({}, { trust_chain:
      chainFor(rpConfiguration({ token_endpoint_auth_method:
                                 'client_secret_basic' })) }) },
     'STS-OIDFED-0055'],
    ['somebody else\'s chain', { request: requestObject({}, {
      trust_chain: [anchorEc.jwt] }) }, 'STS-OIDFED-0053']];
  for (let i = 0; i < cases.length; i++) {
    const c = cases[i];
    const got = await inRealm(REALM, function () {
      return registration.automatic(req, rpId, c[1]);
    });
    t.check(!got.ok && got.code === c[2] && !inRealm(REALM, function () {
      return applications.clientConfigOf(rpId).known;
    }), '2' + String.fromCharCode(97 + i) + '. refused: ' + c[0] + ' (' +
        c[2] + ')', JSON.stringify(got));
  }
  config.setOverride('oidfed.clientRegistrationTypes', 'explicit');
  const off = inRealm(REALM, function () {
    return registration.wants(req, rpId);
  });
  config.clearOverride('oidfed.clientRegistrationTypes');
  t.check(!off, '2j. a realm that offers only explicit registration does ' +
          'not register automatically');

  t.log.info('=== 3. the registration ends ===');
  // The expiry is derived and no form may write it, so the registration is
  // made by an instance whose clock is two hours behind, with the shortest
  // lifetime: it lands already over.
  const behind = new registration.OidfedRegistration(Object.assign(
    registration.OidfedRegistration.defaultDeps(), {
      now: function () {
        return Date.now() - 7200000;
      } }));
  config.setOverride('oidfed.registrationLifetimeS', '60');
  const again = await inRealm(REALM, function () {
    return behind.automatic(req, rpId, { request: requestObject() });
  });
  config.clearOverride('oidfed.registrationLifetimeS');
  const ended = inRealm(REALM, function () {
    return applications.clientConfigOf(rpId);
  });
  const swept = inRealm(REALM, function () {
    return registration.expireRegistrations();
  });
  const gone = inRealm(REALM, function () {
    return applications.federatedRegistrations().some(function (r) {
      return r.identifier === rpId;
    });
  });
  t.check(again.ok && !ended.known && swept.removed >= 1 && !gone,
          '3a. past its expiry the client is unknown, and the job removes ' +
          'the entry (12.3)',
          JSON.stringify({ again: again, swept: swept,
                           known: ended.known }));

  t.log.info('=== 4. explicit registration ===');
  const explicitChain = chainFor(rpConfiguration({
    token_endpoint_auth_method: 'client_secret_basic' }, { aud: opId }));
  const exp = await inRealm(REALM, function () {
    return registration.explicit(req, 'application/trust-chain+json',
                                 JSON.stringify(explicitChain));
  });
  const opEc = await inRealm(REALM, function () {
    return oidfed.configuration(req);
  });
  const answer = exp.ok ? EntityStatement.verify(exp.jwt, opEc.claims.jwks,
    'explicit-registration-response+jwt') : { ok: false };
  const md = answer.ok ? answer.claims.metadata.openid_relying_party : {};
  t.check(exp.ok && answer.ok && answer.claims.iss === opId &&
          answer.claims.sub === rpId && answer.claims.aud === rpId &&
          answer.claims.trust_anchor === anchorId &&
          answer.claims.authority_hints[0] === anchorId &&
          md.client_id === rpId && typeof md.client_secret === 'string' &&
          md.client_secret_expires_at === answer.claims.exp &&
          !md.registration_access_token,
          '4a. a signed explicit-registration-response+jwt: trust_anchor, ' +
          'authority_hints, the registered metadata, and a secret expiring ' +
          'with it (12.2.2)',
          JSON.stringify({ exp: exp, claims: answer.claims }));
  const refusedExplicit = [
    await inRealm(REALM, function () {
      return registration.explicit(req, 'application/json',
                                   JSON.stringify(explicitChain));
    }),
    await inRealm(REALM, function () {
      return registration.explicit(req, 'application/entity-statement+jwt',
                                   rpConfiguration());
    }),
    await inRealm(REALM, function () {
      return registration.explicit(req, 'application/entity-statement+jwt',
                                   rpConfiguration({}, { aud: anchorId }));
    })];
  config.setOverride('oidfed.clientRegistrationTypes', 'automatic');
  refusedExplicit.push(await inRealm(REALM, function () {
    return registration.explicit(req, 'application/trust-chain+json',
                                 JSON.stringify(explicitChain));
  }));
  config.clearOverride('oidfed.clientRegistrationTypes');
  t.check(refusedExplicit.every(function (r) {
    return !r.ok;
  }) && refusedExplicit[0].code === 'STS-OIDFED-0056' &&
          refusedExplicit[3].status === 404,
          '4b. refused: the wrong media type, a configuration naming no ' +
          'OP or another one, and a realm that does not offer it',
          JSON.stringify(refusedExplicit.map(function (r) {
            return [r.code, r.description];
          })));
  inRealm(REALM, function () {
    return applications.deleteApplication(rpId, { actor: 'test' });
  });
  log.debug("Leaving body().");
}

module.exports = {
  name: 'oidfed_registration',
  describe: 'OpenID Federation for OpenID Connect (#134): automatic and ' +
            'explicit registration of a relying party through a Trust ' +
            'Chain, their refusals and the end of a registration, in process',
  run: run
};
