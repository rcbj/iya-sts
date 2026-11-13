// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

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

// A response model, as the service holds an answer to it.
function modelOf(operationId, status) {
  const spec = require('../mgmt-api/admin_api_spec');
  const adminApi = require('../mgmt-api/admin_api');
  const document = spec.buildSpec(adminApi.ROUTES, { authRequired: true });
  let found = null;
  Object.keys(document.paths).forEach(function (one) {
    Object.keys(document.paths[one]).forEach(function (method) {
      if (document.paths[one][method].operationId === operationId) {
        found = document.paths[one][method];
      }
    });
  });
  return { schema: found.responses[status].content['application/json'].schema,
           components: document.components };
}

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
          activity++;
          sent.push({ uri: record[attribute], form: form });
          const answer = answers.length ? answers.shift() :
            { ok: false, status: 500, kind: 'status', why: 'no answer' };
          return Promise.resolve(answer);
        },
        streamEvents: function (record, attribute, form, opts) {
          activity++;
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

// How often the stand-in relying party has been called; settle() watches it.
let activity = 0;
// How long settle() waits after the last call before it calls things done,
// and the longest it waits in all.
const QUIET_MS = 150;
const SETTLE_MAX_MS = 3000;

// A command is dispatched after the minted rows it hands out are committed
// (`afterMintedCommit()`), and that flush runs on a timer, so a send reaches
// the stand-in some milliseconds later, not within a few turns of the loop
// (#828: twenty turns saw nothing sent). So this waits until the stand-in
// has been quiet for QUIET_MS, and at most SETTLE_MAX_MS.
async function settle() {
  log.debug("Entering settle().");
  for (let i = 0; i < 20; i++) {
    await new Promise(function (resolve) {
      setImmediate(resolve);
    });
  }
  const startedAt = Date.now();
  let seen = activity;
  let quietSince = Date.now();
  while (Date.now() - quietSince < QUIET_MS &&
         Date.now() - startedAt < SETTLE_MAX_MS) {
    await new Promise(function (resolve) {
      setTimeout(resolve, 5);
    });
    if (activity !== seen) {
      seen = activity;
      quietSince = Date.now();
    }
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
  // startTenant() runs the stream itself once the minted rows it hands out
  // are committed; calling executeRun() here as well made a second run of
  // it race the first for the two planned streams (it failed in
  // single-node, where the commit is slower). So this waits for that run.
  const runStartedAt = Date.now();
  while (Date.now() - runStartedAt < SETTLE_MAX_MS) {
    const now = c.report({}).runs.filter(function (r) {
      return r.id === started.run.id;
    })[0];
    if (now && now.state !== 'running') {
      break;
    }
    await new Promise(function (resolve) {
      setTimeout(resolve, 10);
    });
  }
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

  t.log.info('=== 9. what a relying party wrote, against the closed model ===');
  // #1353: the integrator's run found `roles` modelled as scalars while every
  // role is an object, which refused the whole realm's report. This goes through
  // the real writer and the real report, with a relying party that also sends
  // what no role should be, so one partner cannot refuse every client's row.
  answers.push(json(200, {
    context: { iss: 'https://sts.test', tenant: 'default' },
    commands_supported: ['metadata', 'audit'],
    command_endpoint: ENDPOINT, client_id: 'cmd-app',
    roles: [{ id: 'reader', display: 'Reader' },
            { id: 'editor', display: 'Editor', description: 'Changes things',
              stray: { nested: true } },
            { id: 'bare' }, 'a string', 7, null, { display: 'no id' },
            { id: { not: 'a string' }, display: 'odd id' }] }));
  c.send('cmd-app', 'metadata', '', {});
  await settle();
  const said = c.learnedFor('cmd-app').roles;
  t.equal(JSON.stringify(said), JSON.stringify([
    { id: 'reader', display: 'Reader' },
    { id: 'editor', display: 'Editor', description: 'Changes things' },
    { id: 'bare', display: 'bare' }
  ]), '9a. a role is kept as section 2.2 defines one, and nothing else is');
  const P = commandsModule.ProviderCommands;
  t.check(P.lastAccessFrom(1700000000) === 1700000000 &&
          P.lastAccessFrom('2026-11-05T00:00:00Z') === '2026-11-05T00:00:00Z' &&
          P.lastAccessFrom({ at: 1 }) === null && P.lastAccessFrom([1]) === null,
          '9b. last_access is kept only where it is a time');
  const Ajv = require('ajv');
  const held = modelOf('getProviderCommands', '200');
  const validate = new Ajv({ strict: false, allErrors: true }).compile(
    { allOf: [held.schema], components: held.components });
  const report = c.report();
  const row = report.clients.filter(function (one) {
    return one.clientId === 'cmd-app';
  })[0];
  t.check(row && row.learned.roles.length === 3 && validate(report),
          '9c. the real report, with roles in it, meets the model it is held to',
          JSON.stringify(validate.errors || []).slice(0, 600));
  // A row stored before `lastAccessFrom()` was asked at the write, which only
  // the private writer can still make: it holds what a relying party wrote.
  c.noteAccount('cmd-app', 'stored-bad-row', 'cmd-alice', 'active', 'audit',
                { lastAccess: { at: 1 } });
  c.noteAccount('cmd-app', 'stored-good-row', 'cmd-alice', 'active', 'audit',
                { lastAccess: 1700000000 });
  const stored = c.report();
  const accountOf = function (sub) {
    return stored.accounts.filter(function (one) {
      return one.sub === sub;
    })[0];
  };
  t.check(accountOf('stored-bad-row') &&
          !('lastAccess' in accountOf('stored-bad-row')),
          '9d. a stored last_access that is not a time is left out of the row');
  t.equal(accountOf('stored-good-row').lastAccess, 1700000000,
          '9e. and one that is a time is reported');
  t.check(validate(stored), '9f. the report with such a row, and with a row ' +
          'that has no lastAccess, meets the model',
          JSON.stringify(validate.errors || []).slice(0, 600));

  // AN ACT ANSWERS A ROW WITH NO CODE, AT ANY DEPTH (#1355): this module sends
  // its own answers, so the strip in AdminApi.sendJson() never reached it, and
  // POST /admin-api/commands/send-tenant answered 500 for a row that had failed.
  const sentThrough = function (Api, body) {
    const answer = {};
    const res = {
      req: { method: 'POST' },
      status: function () {
        return res;
      },
      type: function () {
        return res;
      },
      set: function () {
        return res;
      },
      send: function (text) {
        answer.text = text;
      }
    };
    const api = Object.create(Api.prototype);
    api.deps = { log: t.log };
    api.sendJson(res, 200, body);
    return JSON.parse(answer.text);
  };
  const { ProviderCommandsApi } = require('../oauth-oidc/provider_commands_api');
  const heldAct = modelOf('sendTenantCommand', '200');
  const validateAct = new Ajv({ strict: false, allErrors: true })
    .compile({ allOf: [heldAct.schema], components: heldAct.components });
  const answered = sentThrough(ProviderCommandsApi, { ok: true, row: deadRow });
  t.check(deadRow.errorCode === 'STS-OAUTH-0771' && validateAct(answered),
          '9g. the real dead row, as this API sends it, meets the act\'s model',
          JSON.stringify(validateAct.errors || []).slice(0, 600));
  const { ScimClientsApi } = require('../mgmt-api/scim_clients_api');
  const client = sentThrough(ScimClientsApi, { ok: true, client: {
    id: 'x', deliveries: [{ errorCode: 'STS-SCIM-0001', why: 'y' }] } });
  t.check(JSON.stringify(client).indexOf('errorCode') < 0 &&
          client.client.deliveries[0].why === 'y',
          '9h. and the SCIM clients\' door takes it off a nested row too');

  t.log.info('=== 10. a token row a v1.0.0 build persisted ===');
  // #1579's review: v1.0.0's recordJwt() stored `client_id` as the token's
  // ARRAY `aud` when it named no client_id and no azp, and read it here with
  // String(); IssuedToken.clientId (a string) dropped it, so the person's
  // client stopped counting as one they were issued a token for. The row is
  // the shape v1.0.0 wrote it in, read back from a store as it was.
  const v100 = instance(clock, [], [], []);
  v100.deps.stats = function () {
    return {
      identityKeyOf: function (name) {
        return name;
      },
      tokenList: function () {
        return [{ jti: 'v100-aud', kind: 'access_token', sub: 's', iss: 'i',
          username: 'cmd-alice', client_id: ['cmd-app', 'other-aud'],
          audience: 'cmd-app other-aud', scope: '', exp: 2000000000,
          issuedAt: 1000, revoked: false, revocable: true },
        { jti: 'v100-objects', kind: 'access_token', sub: 's', iss: 'i',
          username: 'cmd-alice', client_id: [{ x: 1 }], exp: 2000000000,
          issuedAt: 1000, revoked: false, revocable: true }];
      }
    };
  };
  const issuedTo = v100.clientsIssuedTo('cmd-alice');
  t.equal(JSON.stringify(issuedTo), '{"cmd-app":true}',
          '10a. a v1.0.0 row\'s array client_id counts as its first ' +
          'audience, as the writer files it now; a list of no strings ' +
          'counts as no client');
  const DomainClasses = require('../common/domain_classes');
  t.equal(DomainClasses.IssuedToken.fromRecord({ client_id: ['a', 'b'] })
    .clientId, 'a', '10b. IssuedToken.clientId reads that list\'s first ' +
    'member (the sign-out inventory\'s "for <client>" reads the same field)');
  t.equal(DomainClasses.IssuedToken.fromRecord({ client_id: 'c' }).clientId,
          'c', '10c. and a string as it always did');
  log.debug("Leaving body().");
}

module.exports = {
  name: 'provider_commands',
  describe: 'OpenID Provider Commands (#151): Command Tokens, the register, ' +
            'retries and dead letters, callbacks, automatic commands, a ' +
            'resumed tenant run',
  run: run
};
