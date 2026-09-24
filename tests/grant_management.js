'use strict';
//
// File: grant_management.js
//
// ===========================================================================
// GRANT MANAGEMENT FOR OAUTH 2.0 AND FAPI-CIBA (#142, 2026-09-24), in
// process — what the HTTP jobs (`sts_grant_management.js`,
// `sts_fapi_ciba.js`) cannot reach cheaply:
//
//   1. the request's own rules, each refusal and its code;
//   2. a plan: create, merge (carrying forward only what is still consented,
//      and the union of details and claims) and replace; another person's
//      grant refused;
//   3. the grant written only by apply(), expiring with its last token;
//      merge moving the generation and revoking the earlier refresh tokens;
//      refreshRefusal() by generation and after revocation;
//   4. revoke() revoking every recorded token; the resource's fields; the
//      console act; the purge;
//   5. FAPI-CIBA: push refused at registration and at the endpoint, a
//      binding message required, push dropped from the metadata and the
//      CIBA signing algorithms narrowed — under a profile and not without.
// ===========================================================================

delete process.env.CONFIG_FILE;

const realms = require('../common/realms');
const stats = require('../common/admin_stats');
const gm = require('../oauth-oidc/grant_management');
const fapi = require('../oauth-oidc/fapi');

const log = require('bunyan').createLogger({ name: 'grant_management',
  level: process.env.LOG_LEVEL || 'info' });

const RUN = Date.now().toString(36);
const CLIENT = 'gm-client-' + RUN;
const OTHER = 'gm-other-' + RUN;
const SUB = 'urn:uuid:gm-' + RUN;

// IN A REALM OF ITS OWN: the revocations below are real ones, and in the
// default realm they would be counted by every later test in this process
// (`realm_isolation.js` compares the default realm's count with a realm's).
async function run(t) {
  log.debug("Entering run().");
  const id = 'gm-' + RUN;
  realms.create({ id: id, name: 'Grant management test' });
  try {
    await realms.run(realms.get(id), function () {
      return body(t);
    });
  } finally {
    realms.remove(id);
  }
  log.debug("Leaving run().");
}

async function body(t) {
  log.debug("Entering body().");
  let clock = Date.now();
  const g = new gm.GrantManagement(Object.assign(
    gm.GrantManagement.defaultDeps(), {
      now: function () {
        return clock;
      }
    }));
  const codeOf = function (r) {
    log.debug("Entering codeOf().");
    log.debug("Leaving codeOf().");
    return r ? r.code : null;
  };

  t.log.info('=== 1. the request\'s own rules ===');
  const opts = { clientId: CLIENT, confidential: true,
                 responseTypes: ['code'] };
  t.check(g.requestRefusal({}, opts) === null &&
          codeOf(g.requestRefusal({ grant_id: 'x' }, opts)) ===
            'STS-OAUTH-0665' &&
          codeOf(g.requestRefusal({ grant_management_action: 'burn' },
                                  opts)) === 'STS-OAUTH-0665' &&
          codeOf(g.requestRefusal({ grant_management_action: 'create',
                                    grant_id: 'x' }, opts)) ===
            'STS-OAUTH-0665' &&
          codeOf(g.requestRefusal({ grant_management_action: 'merge' },
                                  opts)) === 'STS-OAUTH-0665' &&
          codeOf(g.requestRefusal({ grant_management_action: 'create' },
            Object.assign({}, opts, { confidential: false }))) ===
            'STS-OAUTH-0666' &&
          codeOf(g.requestRefusal({ grant_management_action: 'create' },
            Object.assign({}, opts, { responseTypes: ['code', 'token'] }))) ===
            'STS-OAUTH-0667' &&
          g.requestRefusal({ grant_management_action: 'merge',
                             grant_id: 'nobody' }, opts).error ===
            'invalid_grant_id' &&
          g.requestRefusal({ grant_management_action: 'create' },
                           opts) === null,
          '1a. an id alone, an unknown action, create with an id, merge ' +
          'without one, a public client, a token from the authorization ' +
          'endpoint and an unknown grant are each refused; create passes');

  t.log.info('=== 2. and 3. the plan, the grant, the generations ===');
  const created = g.planFor({ params: { grant_management_action: 'create' },
    clientId: CLIENT, sub: SUB, scope: 'openid profile',
    resources: ['https://rs.test/a'], authorizationDetails: null,
    claims: { userinfo: { email: null } } });
  const plan1 = created.plan;
  t.check(created.ok && plan1.action === 'create' && plan1.gen === 1 &&
          /^[A-Za-z0-9_-]{22}$/.test(plan1.id) &&
          g.current(plan1.id) === null,
          '2a. a create plans a new grant — and writes nothing yet');
  g.noteIssued(plan1.id, 1, 'at-1-' + RUN, 'access_token',
               Math.floor(clock / 1000) + 300);
  g.noteIssued(plan1.id, 1, 'rt-1-' + RUN, 'refresh_token',
               Math.floor(clock / 1000) + 3600);
  const record1 = g.apply(plan1);
  t.check(record1 && record1.gen === 1 &&
          record1.expiresAt === Math.floor(clock / 1000) + 3600 &&
          g.refreshRefusal(plan1.id, 1, CLIENT) === null &&
          codeOf(g.refreshRefusal(plan1.id, 1, OTHER)) === 'STS-OAUTH-0670',
          '3a. written once its tokens are claimed, expiring with the last ' +
          'of them; its refresh tokens pass, and not for another client');
  clock += 1000;
  const mergedPlan = g.planFor({
    params: { grant_management_action: 'merge', grant_id: plan1.id },
    clientId: CLIENT, sub: SUB, scope: 'email',
    resources: ['https://rs.test/b'],
    authorizationDetails: [{ type: 'account_information' }],
    claims: { id_token: { acr: null } },
    stillConsented: function (earlier) {
      return earlier.split(' ').filter(function (s) {
        return s !== 'profile';
      }).join(' ');
    } });
  const plan2 = mergedPlan.plan;
  t.check(mergedPlan.ok && plan2.gen === 2 && plan2.id === plan1.id &&
          plan2.scope === 'openid email' &&
          plan2.resources.length === 2 &&
          plan2.claims.userinfo && plan2.claims.id_token &&
          plan2.authorizationDetails.length === 1,
          '2b. a merge: the union of resources, details and claims, and the ' +
          'earlier scopes only while still consented (profile withdrawn)',
          JSON.stringify(plan2));
  const notMine = g.planFor({
    params: { grant_management_action: 'merge', grant_id: plan1.id },
    clientId: CLIENT, sub: 'urn:uuid:somebody-else', scope: 'email' });
  t.check(!notMine.ok && notMine.refusal.error === 'invalid_grant_id',
          '2c. another person\'s grant is invalid_grant_id');
  g.noteIssued(plan1.id, 2, 'rt-2-' + RUN, 'refresh_token',
               Math.floor(clock / 1000) + 7200);
  g.apply(plan2);
  t.check(stats.isRevoked('rt-1-' + RUN) && !stats.isRevoked('at-1-' + RUN) &&
          codeOf(g.refreshRefusal(plan1.id, 1, CLIENT)) === 'STS-OAUTH-0670' &&
          g.refreshRefusal(plan1.id, 2, CLIENT) === null &&
          g.current(plan1.id).updatedBy === 'client',
          '3b. a merge moves the generation: the earlier refresh token is ' +
          'revoked and refused, the new one passes');
  const replaced = g.planFor({
    params: { grant_management_action: 'replace', grant_id: plan1.id },
    clientId: CLIENT, sub: SUB, scope: 'openid', resources: [] });
  t.check(replaced.ok && replaced.plan.scope === 'openid' &&
          replaced.plan.gen === 3 && replaced.plan.resources.length === 0,
          '2d. a replace holds only the new request');

  t.log.info('=== 4. revoke, the resource, the act, the purge ===');
  const resource = g.resourceOf(g.current(plan1.id));
  t.check(resource.scopes[0].scope === 'openid email' &&
          resource.scopes[0].resource.length === 2 &&
          resource.claims.indexOf('email') >= 0 &&
          resource.claims.indexOf('acr') >= 0 &&
          resource.authorization_details.length === 1 &&
          resource.updated_by === 'client' &&
          Number.isInteger(resource.last_updated) &&
          resource.last_updated_at === undefined,
          '4a. the grant resource, with last_updated as the draft defines it',
          JSON.stringify(resource));
  t.check(g.redemptionRefusal(replaced.plan) === null,
          '4b. a replace whose grant still stands may be claimed');
  const done = g.revoke(plan1.id, 'test', 'client');
  t.check(done.ok && stats.isRevoked('at-1-' + RUN) &&
          stats.isRevoked('rt-2-' + RUN) &&
          codeOf(g.redemptionRefusal(replaced.plan)) === 'STS-OAUTH-0669' &&
          codeOf(g.refreshRefusal(plan1.id, 2, CLIENT)) === 'STS-OAUTH-0670' &&
          !g.revoke(plan1.id, 'test', 'client').ok,
          '4c. revoked: every recorded token revoked, a pending replace and ' +
          'a refresh refused, and nothing to revoke a second time');
  const second = g.planFor({ params: { grant_management_action: 'create' },
                             clientId: CLIENT, sub: SUB, scope: 'openid' });
  g.noteIssued(second.plan.id, 1, 'at-3-' + RUN, 'access_token',
               Math.floor(clock / 1000) + 60);
  g.apply(second.plan);
  const listed = g.list(CLIENT);
  const bad = g.act({ action: 'burn' }, {});
  const acted = g.act({ action: 'revoke-grant', grantId: second.plan.id },
                      { via: 'console', actor: 'tester' });
  t.check(listed.some(function (row) {
    return row.grantId === second.plan.id && row.tokens === 1;
  }) && !bad.ok && acted.ok && acted.revoked === 1,
          '4d. the console\'s list and its one act');
  const third = g.planFor({ params: { grant_management_action: 'create' },
                            clientId: CLIENT, sub: SUB, scope: 'openid' });
  g.noteIssued(third.plan.id, 1, 'at-4-' + RUN, 'access_token',
               Math.floor(clock / 1000) + 60);
  g.apply(third.plan);
  clock += 3600 * 1000;
  g.purge();
  t.check(g.current(third.plan.id) === null,
          '4e. the purge removes a grant past its last token');

  t.log.info('=== 5. FAPI-CIBA ===');
  const metadata = {
    backchannel_token_delivery_modes_supported: ['poll', 'ping', 'push'],
    backchannel_authentication_request_signing_alg_values_supported:
      ['RS256', 'PS256', 'ES256'],
    token_endpoint_auth_methods_supported: ['private_key_jwt'] };
  const plain = JSON.parse(JSON.stringify(metadata));
  fapi.applyToMetadata(plain);
  const advanced = fapi.withProfile('1-advanced', function () {
    return fapi.applyToMetadata(JSON.parse(JSON.stringify(metadata)));
  });
  const refusals = fapi.withProfile('1-baseline', function () {
    return [
      fapi.cibaRefusal({ mode: 'push', bindingMessage: 'x' }),
      fapi.cibaRefusal({ mode: 'poll', bindingMessage: '' }),
      fapi.cibaRefusal({ mode: 'ping', bindingMessage: 'x' }),
      fapi.registrationRefusal({
        token_endpoint_auth_method: 'private_key_jwt',
        backchannel_token_delivery_mode: 'push' })
    ];
  });
  t.check(plain.backchannel_token_delivery_modes_supported.length === 3 &&
          fapi.cibaRefusal({ mode: 'push', bindingMessage: '' }) === null &&
          advanced.backchannel_token_delivery_modes_supported.join() ===
            'poll,ping' &&
          advanced
            .backchannel_authentication_request_signing_alg_values_supported
            .indexOf('RS256') < 0 &&
          refusals[0].errorCode === 'STS-OAUTH-0662' &&
          refusals[1].errorCode === 'STS-OAUTH-0663' &&
          refusals[2] === null &&
          refusals[3].errorCode === 'STS-REG-0198',
          '5a. under a profile: push dropped and refused, a binding message ' +
          'required, the request algorithms narrowed; without one, nothing',
          JSON.stringify({ advanced: advanced, refusals: refusals }));
  log.debug("Leaving body(). realm=" + realms.current().id);
}

module.exports = {
  name: 'grant_management',
  describe: 'Grant Management for OAuth 2.0 and FAPI-CIBA (#142): the ' +
            'request rules, plans, generations, revocation, the purge and ' +
            'the profile rules, in process',
  run: run
};
