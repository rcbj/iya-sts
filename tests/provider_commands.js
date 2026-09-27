'use strict';
//
// File: provider_commands.js
//
// ===========================================================================
// OPENID PROVIDER COMMANDS 1.0 AND THE SHARED OUTBOUND QUEUE (#151,
// 2026-09-26), in process, against a fake outbound door and a test clock.
//
//   1. metadata: the Command Token's header and claims, and what the relying
//      party said it supports, recorded;
//   2. an account command: sub, the account's claims, the answer recorded in
//      the register, and the aud_sub it gave learned (#148);
//   3. incompatible_state: a dead letter with its code, the state it gave
//      recorded; a 503 retried by the sweep; a retry by hand;
//   4. _async: 202, then the callback — once — and a bad token refused;
//   5. automatic commands: a lock set is suspend, cleared is reactivate, a
//      profile change maintain, a sign-in's bookkeeping nothing; only to a
//      relying party that supports the command;
//   6. a tenant run whose stream drops is resumed with Last-Event-ID;
//   7. the console's acts refuse an unknown action by name;
//   8. command_endpoint registration: https, no fragment.
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const ldap = require('../ldap/ldap_server');
const applications = require('../common/applications');
const credentials = require('../common/credentials');
const commandsModule = require('../oauth-oidc/provider_commands');
require('../oauth-oidc/oauth2');

const log = require('bunyan').createLogger({ name: 'provider_commands',
  level: process.env.LOG_LEVEL || 'info' });

const ENDPOINT = 'https://rp.test/commands';

function decode(jwt) {
  log.debug("Entering decode().");
  const parts = String(jwt).split('.');
  log.debug("Leaving decode().");
  return { header: JSON.parse(Buffer.from(parts[0], 'base64url').toString()),
           claims: JSON.parse(Buffer.from(parts[1], 'base64url')
             .toString()) };
}

// A ProviderCommands with the test's clock, an outbound door that records and
// answers from a queue, and a claim store that is once.
function instance(clock, sent, answers, streams) {
  log.debug("Entering instance().");
  const taken = new Set();
  const deps = Object.assign(
    commandsModule.ProviderCommands.defaultDeps(), {
      now: function () {
        return clock.now;
      },
      later: function () {
        // No timers in a test: the sweep is the retry.
      },
      claims: {
        claim: function (opts) {
          const key = opts.scope + ' ' + opts.value;
          const ok = !taken.has(key);
          taken.add(key);
          return Promise.resolve(ok ? { ok: true, claimedAt: clock.now } :
                                      { ok: false, reason: 'taken' });
        }
      },
      fedHttp: {
        deliverForm: function (record, attribute, form) {
          sent.push({ uri: record[attribute], form: form });
          const answer = answers.length ? answers.shift() :
            { ok: false, status: 500, kind: 'status', why: 'no answer' };
          return Promise.resolve(answer);
        },
        streamEvents: function (record, attribute, form, opts) {
          sent.push({ uri: record[attribute], form: form, stream: true,
                      lastEventId: opts.lastEventId || '' });
          const plan = streams.shift();
          (plan.events || []).forEach(function (e) {
            opts.onEvent(e);
          });
          return Promise.resolve(plan.result);
        }
      }
    });
  log.debug("Leaving instance().");
  return new commandsModule.ProviderCommands(deps);
}

function json(status, body) {
  log.debug("Entering json().");
  log.debug("Leaving json().");
  return { ok: status >= 200 && status < 300, status: status,
           kind: status >= 200 && status < 300 ? '' : 'status',
           body: JSON.stringify(body), why: 'it answered ' + status };
}

async function settle() {
  log.debug("Entering settle().");
  for (let i = 0; i < 20; i++) {
    await new Promise(function (resolve) {
      setImmediate(resolve);
    });
  }
  log.debug("Leaving settle().");
}

async function run(t) {
  log.debug("Entering run().");
  config.setOverride('oauth2.providerCommands', true);
  config.setOverride('global.publicBaseUrl', 'https://sts.test');
  try {
    await body(t);
  } finally {
    config.clearOverride('oauth2.providerCommands');
    config.clearOverride('global.publicBaseUrl');
  }
  log.debug("Leaving run().");
}

async function body(t) {
  log.debug("Entering body().");
  applications.createApplication({ identifier: 'cmd-app',
    protocols: ['oauth2', 'oidc'],
    fields: { oauthClientId: 'cmd-app', oauthCommandEndpoint: ENDPOINT,
              appName: 'Command RP' } });
  ldap.createUser('cmd-alice', { invent: false, attributes: {
    givenName: 'Alice', sn: 'Commands', mail: 'alice@cmd.test' } });
  const clock = { now: 1000000000000 };
  const sent = [];
  const answers = [];
  const streams = [];
  const c = instance(clock, sent, answers, streams);
  const sub = c.subjectFor('cmd-app', 'cmd-alice');

  t.log.info('=== 1. metadata ===');
  answers.push(json(200, {
    context: { iss: 'https://sts.test', tenant: 'default' },
    commands_supported: ['metadata', 'activate', 'suspend', 'reactivate',
                         'maintain', 'invalidate', 'audit', 'suspend_async',
                         'audit_tenant'],
    command_endpoint: ENDPOINT, client_id: 'cmd-app',
    roles: [{ id: 'r', display: 'R' }] }));
  const meta = c.send('cmd-app', 'metadata', '', {});
  await settle();
  const m = decode(sent[0].form.command_token);
  t.check(meta.ok && m.header.typ === 'command+jwt' &&
          m.claims.command === 'metadata' && m.claims.aud === 'cmd-app' &&
          m.claims.client_id === 'cmd-app' && m.claims.tenant === 'default' &&
          m.claims.iss === 'https://sts.test' && m.claims.metadata &&
          m.claims.metadata.callback_endpoint ===
            'https://sts.test/oauth2/commands/callback' &&
          m.claims.callback_token && m.claims.sub === undefined &&
          m.claims.nonce === undefined &&
          m.claims.exp - m.claims.iat <= 120,
          '1a. section 5: typ command+jwt, the baseline claims, metadata ' +
          'with the callback endpoint, no sub and no nonce',
          JSON.stringify(m));
  const learned = c.learnedFor('cmd-app');
  t.check(learned && learned.commandsSupported.indexOf('suspend') >= 0 &&
          learned.roles.length === 1,
          '1b. what the relying party supports is recorded',
          JSON.stringify(learned));

  t.log.info('=== 2. an account command ===');
  answers.push(json(200, { sub: sub, account_state: 'active',
                           aud_sub: 'rp-7' }));
  c.send('cmd-app', 'activate', 'cmd-alice', {});
  await settle();
  const a = decode(sent[1].form.command_token).claims;
  t.check(a.sub === sub && a.command === 'activate' &&
          a.email === 'alice@cmd.test' && a.metadata === undefined &&
          c.accountFor('cmd-app', sub).state === 'active' &&
          credentials.audSubsOf('cmd-alice').indexOf('cmd-app rp-7') >= 0,
          '2a. sub and the account\'s claims sent; active recorded; the ' +
          'aud_sub learned', JSON.stringify(a));
  answers.push(json(200, { sub: sub, account_state: 'active' }));
  c.send('cmd-app', 'audit', 'cmd-alice', {});
  await settle();
  t.check(decode(sent[2].form.command_token).claims.aud_sub === 'rp-7',
          '2b. the learned aud_sub is sent back');

  t.log.info('=== 3. refusals and retries ===');
  answers.push(json(409, { error: 'incompatible_state', sub: sub,
                           account_state: 'active' }));
  const again = c.send('cmd-app', 'activate', 'cmd-alice', {});
  await settle();
  const deadRow = c.report({}).deliveries.filter(function (row) {
    return row.id === again.row.id;
  })[0];
  t.check(deadRow.state === 'dead' && deadRow.errorCode === 'STS-OAUTH-0771',
          '3a. incompatible_state is a dead letter with its code',
          JSON.stringify(deadRow));
  answers.push({ ok: false, status: 503, kind: 'status',
                 why: 'it answered 503' });
  answers.push(json(200, { sub: sub, account_state: 'active' }));
  const flaky = c.send('cmd-app', 'invalidate', 'cmd-alice', {});
  await settle();
  clock.now += 60000;
  await c.sweep();
  await settle();
  const retried = c.report({}).deliveries.filter(function (row) {
    return row.id === flaky.row.id;
  })[0];
  t.check(retried.state === 'sent' && retried.attempts === 2,
          '3b. a 503 is retried by the sweep, and lands',
          JSON.stringify(retried));
  answers.push(json(200, { sub: sub, account_state: 'active' }));
  const byHand = c.retryDelivery(again.row.id, 'tester');
  await settle();
  t.check(byHand.ok && byHand.row.generation === 2,
          '3c. a dead letter is retried by hand as a new generation',
          JSON.stringify(byHand));

  t.log.info('=== 4. _async and the callback ===');
  answers.push({ ok: true, status: 202, kind: '', body: '' });
  c.send('cmd-app', 'suspend_async', 'cmd-alice', {});
  await settle();
  const asyncClaims = decode(sent[sent.length - 1].form.command_token).claims;
  const bad = c.acceptCallback('nope', { sub: sub,
                                         account_state: 'suspended' });
  const good = c.acceptCallback(asyncClaims.callback_token,
                                { sub: sub, account_state: 'suspended' });
  const twice = c.acceptCallback(asyncClaims.callback_token,
                                 { sub: sub, account_state: 'suspended' });
  t.check(asyncClaims.callback_token && bad.status === 401 &&
          good.status === 204 && twice.status === 401 &&
          c.accountFor('cmd-app', sub).state === 'suspended',
          '4a. 202, then the result through the callback once; a bad ' +
          'token is 401', JSON.stringify([bad, good, twice]));

  t.log.info('=== 5. automatic commands ===');
  let before = sent.length;
  answers.push(json(200, { sub: sub, account_state: 'active' }));
  c.directoryChanged({ kind: 'updated', username: 'cmd-alice',
                       realm: 'default',
                       before: { pwdAccountLockedTime: ['000001010000Z'] },
                       after: {} });
  await settle();
  const reactivated = sent.slice(before).map(function (one) {
    return decode(one.form.command_token).claims.command;
  });
  before = sent.length;
  answers.push(json(200, { sub: sub, account_state: 'active' }));
  c.directoryChanged({ kind: 'updated', username: 'cmd-alice',
                       realm: 'default', before: { pwdFailureTime: [] },
                       after: { pwdFailureTime: ['x'] } });
  await settle();
  const bookkeeping = sent.length - before;
  c.directoryChanged({ kind: 'updated', username: 'cmd-alice',
                       realm: 'default', before: { mail: ['a@x'] },
                       after: { mail: ['b@x'] } });
  await settle();
  const maintained = sent.slice(before).map(function (one) {
    return decode(one.form.command_token).claims.command;
  });
  // A ROLE the person holds moving (#238's `roles` kind) is a change to
  // them, as a group's is: `maintain`.
  before = sent.length;
  answers.push(json(200, { sub: sub, account_state: 'active' }));
  c.directoryChanged({ kind: 'roles', username: 'cmd-alice',
                       realm: 'default', before: {}, after: {} });
  await settle();
  const roleMaintained = sent.slice(before).map(function (one) {
    return decode(one.form.command_token).claims.command;
  });
  t.check(roleMaintained.join() === 'maintain',
          '5b. a role moving is maintain, as a group is',
          JSON.stringify(roleMaintained));
  before = sent.length;
  answers.push(json(200, { sub: sub, account_state: 'suspended' }));
  c.directoryChanged({ kind: 'updated', username: 'cmd-alice',
                       realm: 'default', before: {},
                       after: { pwdAccountLockedTime: ['000001010000Z'] } });
  await settle();
  const suspended = sent.slice(before).map(function (one) {
    return decode(one.form.command_token).claims.command;
  });
  before = sent.length;
  c.directoryChanged({ kind: 'deleted:cmd-alice', username: 'cmd-alice',
                       realm: 'default', before: {}, after: {} });
  await settle();
  t.check(reactivated.join() === 'reactivate' && bookkeeping === 0 &&
          maintained.join() === 'maintain' &&
          suspended.join() === 'suspend' && sent.length === before,
          '5a. unlock reactivate, bookkeeping nothing, a profile change ' +
          'maintain, lock suspend; delete, which the RP did not list, ' +
          'nothing', JSON.stringify([reactivated, bookkeeping, maintained,
                                     suspended]));

  t.log.info('=== 6. a tenant run, resumed ===');
  streams.push({ events: [
    { id: '1', event: 'account-state',
      data: JSON.stringify({ sub: sub, account_state: 'suspended' }) },
    { id: '2', event: 'account-state',
      data: JSON.stringify({ sub: 'someone-else', account_state: 'active' }) }
  ], result: { ok: false, kind: 'network', lastEventId: '2',
               why: 'the stream closed before it ended' } });
  streams.push({ events: [
    { id: '3', event: 'command-complete',
      data: JSON.stringify({ total_accounts: 2 }) }
  ], result: { ok: true, status: 200, ended: true, lastEventId: '3' } });
  const started = c.startTenant('cmd-app', 'audit_tenant', {});
  await c.executeRun(started.run.id);
  const runRow = c.report({}).runs.filter(function (r) {
    return r.id === started.run.id;
  })[0];
  const streamCalls = sent.filter(function (one) {
    return one.stream;
  });
  t.check(runRow.state === 'complete' && runRow.resumes === 1 &&
          runRow.accounts === 2 && runRow.totalAccounts === 2 &&
          streamCalls[1].lastEventId === '2' &&
          c.accountFor('cmd-app', 'someone-else').state === 'active',
          '6a. the stream is resumed with Last-Event-ID, and every account ' +
          'it reported is recorded', JSON.stringify(runRow));

  t.log.info('=== 7. the acts ===');
  const unknown = c.act({ action: 'dance' }, {});
  t.check(!unknown.ok && /^Unknown action "dance"\. The 3 are: send-account, send-tenant and retry-delivery\.$/.test(unknown.message),
          '7a. an unknown action names the three', unknown.message);
  const noEndpoint = c.send('nobody', 'audit', 'cmd-alice', {});
  t.check(!noEndpoint.ok, '7b. a client with no command_endpoint is refused');

  t.log.info('=== 8. registration ===');
  t.check(applications.commandMetadataProblem({
            command_endpoint: 'http://rp.test/c' }) &&
          applications.commandMetadataProblem({
            command_endpoint: 'https://rp.test/c#x' }) &&
          !applications.commandMetadataProblem({
            command_endpoint: 'https://rp.test/c?q=1' }),
          '8a. command_endpoint is https with no fragment; a query is fine');
  log.debug("Leaving body().");
}

module.exports = {
  name: 'provider_commands',
  describe: 'OpenID Provider Commands (#151): Command Tokens, the register, ' +
            'retries and dead letters, callbacks, automatic commands, a ' +
            'resumed tenant run',
  run: run
};
