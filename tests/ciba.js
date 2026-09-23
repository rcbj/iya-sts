'use strict';
//
// File: ciba.js
//
// ===========================================================================
// OPENID CONNECT CIBA CORE 1.0 (#131, 2026-09-23), in process. rcbj's
// answers: the person approves on /portal/ciba; poll, ping and push; an
// approval as strong as acr_values asks; development relaxes nothing.
//
//   1. registration metadata: section 4's rules, and what a client
//      registered read back;
//   2. the request's life: made, the per-person bound, answered only by its
//      person and once, polled — pending, slow_down with the interval grown
//      — redeemed once, and expired;
//   3. the person's user code, hashed and matched;
//   4. ping and push: a delivery with the client's Bearer, retried after a
//      failure worth retrying, dead after its attempts, and a push carrying
//      tokens whose ID Token names the request (and rt_hash);
//   5. the sweep expiring what nobody answered.
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const ldap = require('../ldap/ldap_server');
const applications = require('../common/applications');
const ciba = require('../oauth-oidc/ciba');
require('../oauth-oidc/oauth2');

const log = require('bunyan').createLogger({ name: 'ciba',
  level: process.env.LOG_LEVEL || 'info' });

// A Ciba with a clock of the test's and an outbound door that records.
function instance(clock, sent, answers) {
  log.debug("Entering instance().");
  const deps = Object.assign(ciba.Ciba.defaultDeps(), {
    now: function () { return clock.now; },
    fedHttp: {
      deliverJson: function (record, attribute, body, headers) {
        sent.push({ uri: record[attribute], body: body, headers: headers });
        const answer = answers.length ? answers.shift() :
          { ok: true, status: 204 };
        return Promise.resolve(answer);
      }
    }
  });
  log.debug("Leaving instance().");
  return new ciba.Ciba(deps);
}

async function run(t) {
  log.debug("Entering run().");
  config.setOverride('oauth2.ciba', true);
  try {
    await body(t);
  } finally {
    config.clearOverride('oauth2.ciba');
    config.clearOverride('oauth2.cibaMaxPendingPerPerson');
  }
  log.debug("Leaving run().");
}

async function body(t) {
  log.debug("Entering body().");
  t.log.info('=== 1. registration metadata ===');
  const problem = function (meta) {
    const got = applications.cibaMetadataProblem(meta);
    return got ? got.member : '';
  };
  t.check(problem({ backchannel_token_delivery_mode: 'poll' }) === '' &&
          problem({ backchannel_token_delivery_mode: 'carrier-pigeon' }) ===
            'backchannel_token_delivery_mode' &&
          problem({ backchannel_token_delivery_mode: 'ping' }) ===
            'backchannel_client_notification_endpoint' &&
          problem({ backchannel_token_delivery_mode: 'push',
                    backchannel_client_notification_endpoint:
                      'http://rp.test/cb' }) ===
            'backchannel_client_notification_endpoint' &&
          problem({ backchannel_authentication_request_signing_alg:
                      'HS256' }) ===
            'backchannel_authentication_request_signing_alg' &&
          problem({ backchannel_user_code_parameter: 'yes' }) ===
            'backchannel_user_code_parameter',
          '1a. section 4: a known mode, an https endpoint for ping and ' +
          'push, an asymmetric algorithm, a boolean');
  applications.register('ciba-dcr-ping', {
    redirect_uris: ['https://rp.test/cb'],
    backchannel_token_delivery_mode: 'ping',
    backchannel_client_notification_endpoint: 'https://rp.test/notify',
    backchannel_user_code_parameter: true }, {});
  const read = applications.cibaOf('ciba-dcr-ping');
  t.check(read.mode === 'ping' && read.endpoint === 'https://rp.test/notify' &&
          read.userCode === true && applications.cibaOf('nobody').mode === '',
          '1b. a registration\'s members are read back', JSON.stringify(read));

  t.log.info('=== 2. a request\'s life ===');
  ldap.createUser('ciba-alice', { invent: false,
    attributes: { givenName: 'Alice', sn: 'Ciba' } });
  const clock = { now: 1000000000000 };
  const sent = [];
  const answers = [];
  const c = instance(clock, sent, answers);
  const made = c.create({ clientId: 'ciba-client', username: 'ciba-alice',
    scope: 'openid', mode: 'poll', bindingMessage: 'W4SCT',
    requestedExpiry: '60', base: 'https://sts.test' });
  t.check(made.ok && /^[A-Za-z0-9_-]{43}$/.test(made.record.id) &&
          made.expiresIn === 60 &&
          c.pendingFor('ciba-alice').length === 1,
          '2a. a request with a 256-bit id, its requested expiry, waiting');
  config.setOverride('oauth2.cibaMaxPendingPerPerson', 1);
  const second = c.create({ clientId: 'ciba-client', username: 'ciba-alice',
    scope: 'openid', mode: 'poll' });
  t.check(!second.ok && second.error === 'access_denied',
          '2b. past the per-person bound, access_denied');
  config.clearOverride('oauth2.cibaMaxPendingPerPerson');
  t.check(c.poll(made.record.id, 'other-client').state === 'unknown',
          '2c. another client\'s poll finds nothing');
  const first = c.poll(made.record.id, 'ciba-client').state;
  const fast = c.poll(made.record.id, 'ciba-client');
  t.check(first === 'pending' && fast.state === 'slow_down' &&
          fast.record.interval === 10,
          '2d. pending, then slow_down with the interval grown by five');
  t.check(!c.answer(made.record.id, 'ciba-mallory', true).ok,
          '2e. only the hinted person answers');
  const approved = c.answer(made.record.id, 'ciba-alice', true,
    { acr: 'mfa', amr: ['pwd', 'otp'], authTime: 12345 });
  t.check(approved.ok && approved.record.state === 'approved' &&
          approved.record.approval.acr === 'mfa' &&
          !c.answer(made.record.id, 'ciba-alice', false).ok,
          '2f. approved, with what the session proved, and once');
  t.check(c.poll(made.record.id, 'ciba-client').state === 'approved' &&
          await c.redeem(approved.record) &&
          c.poll(made.record.id, 'ciba-client').state === 'redeemed',
          '2g. approved, redeemed once');
  const late = c.create({ clientId: 'ciba-client', username: 'ciba-alice',
    scope: 'openid', mode: 'poll', requestedExpiry: '5' });
  clock.now += 6000;
  t.check(c.poll(late.record.id, 'ciba-client').state === 'expired',
          '2h. past its expiry, expired');

  t.log.info('=== 3. the user code ===');
  t.check(!ciba.hasUserCode('ciba-alice') &&
          !ciba.setUserCode('ciba-alice', 'abc').ok &&
          ciba.setUserCode('ciba-alice', 'blue-horse-7').ok &&
          ciba.hasUserCode('ciba-alice') &&
          ciba.userCodeMatches('ciba-alice', 'blue-horse-7') &&
          !ciba.userCodeMatches('ciba-alice', 'red-horse-7') &&
          ciba.setUserCode('ciba-alice', '').ok &&
          !ciba.hasUserCode('ciba-alice'),
          '3a. set (4 to 64 characters), matched, and cleared');

  t.log.info('=== 4. ping and push ===');
  const ping = c.create({ clientId: 'ciba-ping', username: 'ciba-alice',
    scope: 'openid', mode: 'ping', notificationToken: 'nt-ping',
    notificationEndpoint: 'https://rp.test/notify' });
  answers.push({ ok: false, status: 503, kind: 'status',
                 why: 'it answered 503' });
  await c.answerAndNotify(ping.record.id, 'ciba-alice', true, {});
  await new Promise(function (resolve) { setImmediate(resolve); });
  const views = c.deliveryViews(ping.record.id);
  t.check(sent.length === 1 && sent[0].headers.Authorization ===
            'Bearer nt-ping' && sent[0].body.auth_req_id === ping.record.id &&
          views[0].state === 'pending' && views[0].attempts === 1,
          '4a. the ping is sent with the client\'s Bearer; a 503 is kept ' +
          'for a retry', JSON.stringify(views));
  clock.now += 60000;
  await c.sweep();
  t.check(sent.length === 2 &&
          c.deliveryViews(ping.record.id)[0].state === 'sent',
          '4b. the sweep retries it, and it lands');
  const doomed = c.create({ clientId: 'ciba-ping', username: 'ciba-alice',
    scope: 'openid', mode: 'ping', notificationToken: 'nt-2',
    notificationEndpoint: 'https://rp.test/notify' });
  answers.push({ ok: false, status: 400, kind: 'status',
                 why: 'it answered 400' });
  await c.answerAndNotify(doomed.record.id, 'ciba-alice', false, {});
  await new Promise(function (resolve) { setImmediate(resolve); });
  t.check(c.deliveryViews(doomed.record.id)[0].state === 'dead',
          '4c. a 400 is not worth retrying: dead at once');
  applications.createApplication({ identifier: 'ciba-push', protocols:
    ['oauth2', 'oidc'], fields: { oauthClientId: 'ciba-push' } });
  const push = c.create({ clientId: 'ciba-push', username: 'ciba-alice',
    scope: 'openid', mode: 'push', notificationToken: 'nt-push',
    notificationEndpoint: 'https://rp.test/push',
    base: 'https://sts.test' });
  await c.answerAndNotify(push.record.id, 'ciba-alice', true,
    { acr: '1', amr: ['pwd'], authTime: 12345 });
  await new Promise(function (resolve) { setImmediate(resolve); });
  const pushed = sent[sent.length - 1];
  const idClaims = pushed && pushed.body.id_token
    ? JSON.parse(Buffer.from(pushed.body.id_token.split('.')[1],
                             'base64url').toString()) : {};
  t.check(pushed && pushed.headers.Authorization === 'Bearer nt-push' &&
          pushed.body.auth_req_id === push.record.id &&
          pushed.body.access_token &&
          idClaims['urn:openid:params:jwt:claim:auth_req_id'] ===
            push.record.id &&
          (!pushed.body.refresh_token || !!idClaims.rt_hash) &&
          c.get(push.record.id).state === 'redeemed',
          '4d. a push carries the tokens, and its ID Token names the ' +
          'request (and hashes a refresh token as rt_hash)',
          JSON.stringify(Object.keys((pushed && pushed.body) || {})));

  t.log.info('=== 5. the sweep ===');
  const unanswered = c.create({ clientId: 'ciba-push', username: 'ciba-alice',
    scope: 'openid', mode: 'push', notificationToken: 'nt-3',
    notificationEndpoint: 'https://rp.test/push', requestedExpiry: '5' });
  clock.now += 10000;
  const swept = await c.sweep();
  t.check(swept.expired >= 1 && c.get(unanswered.record.id).state ===
            'expired' &&
          sent[sent.length - 1].body.error === 'expired_token',
          '5a. the sweep expires an unanswered request, and a push client ' +
          'is sent expired_token', JSON.stringify(swept));
  log.debug("Leaving body().");
}

module.exports = {
  name: 'ciba',
  describe: 'OpenID Connect CIBA (#131): registration metadata, a ' +
            'request\'s life, the user code, ping and push, the sweep',
  run: run
};
