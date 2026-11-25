// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/subject_act_budgets.js
//
// ===========================================================================
// A SIGNED-IN SUBJECT'S OWN BUDGETS (#2167, ASVS 5.0.0 2.4.2). In process:
//
//   1. `/account-api`: the account API's own `run()`, its gate standing in
//      for a verified token, with `account.writesPerSubject` at 3 in a
//      600-second window. Three writes pass; the fourth is 429 with
//      Retry-After counted in the setting's window (not
//      `security.rateLimitWindowS`), coded STS-ACCOUNT-0024, its sentence a
//      catalog message, and its handler never run. Another person, and the
//      same `sub` in another realm, are unaffected; the same person's reads
//      still answer; 0 turns the budget off.
//   2. `/report-api`: which acts are the expensive four, and the budget at
//      `report.actsPerSubject` 2: the third act is 429 with Retry-After,
//      `too_many_requests`, STS-REPORT-0062 and the catalog message, and
//      another subject is unaffected.
//
// The token's own checks are `account_api.js`'s and
// `report_access_policy.js`'s; this holds what is counted after them.
// ===========================================================================

const log = require('bunyan').createLogger({ name: 'subject_act_budgets',
  level: process.env.LOG_LEVEL || 'info' });

const KEY = 'refusals.limits.tooManyActs';

// A response that records what was answered on it.
function fakeRes() {
  const res = {
    headers: {}, locals: {}, headersSent: false, statusCode: 200, body: '',
    status: function (n) {
      res.statusCode = n;
      return res;
    },
    set: function (name, value) {
      res.headers[String(name).toLowerCase()] = String(value);
      return res;
    },
    type: function () {
      return res;
    },
    send: function (body) {
      res.body = String(body);
      res.headersSent = true;
      return res;
    }
  };
  return res;
}

function parsed(res) {
  try {
    return JSON.parse(res.body || '{}');
  } catch (e) {
    log.debug("Caught in parsed(): " + ((e && e.message) || e));
    return {};
  }
}

function request(method, caller) {
  return { method: method, url: '/account-api/x',
           originalUrl: '/account-api/x',
           headers: method === 'GET' ? {}
             : { 'content-type': 'application/json' },
           body: method === 'GET' ? undefined : {}, query: {},
           socket: { remoteAddress: '192.0.2.7' }, caller: caller };
}

async function accountSections(t, config, websecurity, errorCodes) {
  log.debug("Entering accountSections().");
  const AccountApi = require('../account-api/account_api').AccountApi;
  const api = new AccountApi(AccountApi.defaultDeps());
  // THE GATE, STOOD IN FOR: the caller is the request's, as a verified
  // token would name it.
  api.authenticate = function (req) {
    return req.caller;
  };
  api.parametersFor = function () {
    return [];
  };
  let ran = 0;
  const handler = function (req, res) {
    ran += 1;
    return api.json(res, 200, { ok: true, message: 'done' });
  };
  const write = { method: 'POST', path: '/account-api/x', operationId: 'x',
                  access: 'person', handler: handler };
  const read = { method: 'GET', path: '/account-api/x', operationId: 'getX',
                 access: 'person', handler: handler };
  const alice = { username: 'sab-alice', sub: 'urn:uuid:sab-alice',
                  realm: 'default' };
  const bob = { username: 'sab-bob', sub: 'urn:uuid:sab-bob',
                realm: 'default' };
  const aliceElsewhere = Object.assign({}, alice, { realm: 'acme' });

  const one = async function (op, caller) {
    const res = fakeRes();
    await api.run(op, request(op.method, caller), res);
    return res;
  };

  const passed = [];
  for (let i = 0; i < 3; i++) {
    passed.push((await one(write, alice)).statusCode);
  }
  t.check(passed.join(',') === '200,200,200',
          '1a. three writes within account.writesPerSubject (3) pass',
          passed.join(','));
  const ranBefore = ran;
  const over = await one(write, alice);
  const body = parsed(over);
  const retry = Number(over.headers['retry-after']);
  t.check(over.statusCode === 429, '1b. the fourth write is 429',
          over.statusCode + ' ' + over.body);
  t.check(retry > 60 && retry <= 600,
          '1c. with Retry-After counted in account.writeWindowS (600), not ' +
          'the 60-second security.rateLimitWindowS', String(retry));
  t.check(errorCodes.codeOf(over) === 'STS-ACCOUNT-0024',
          '1d. coded STS-ACCOUNT-0024 on the response, not in the body',
          errorCodes.codeOf(over) + ' ' + over.body);
  t.check(body.ok === false && Array.isArray(body.errors) &&
          /Wait \d+ seconds/.test(String(body.errors[0])) &&
          Array.isArray(body.messages) && body.messages[0] &&
          body.messages[0].key === KEY &&
          Number(body.messages[0].params.seconds) === retry &&
          over.body.indexOf('STS-') < 0,
          '1e. the refusal is { ok: false, errors, messages } with the ' +
          'catalog message the portal draws in its own language',
          over.body);
  t.check(ran === ranBefore, '1f. the refused write\'s handler never ran',
          ran + ' vs ' + ranBefore);
  t.check((await one(write, bob)).statusCode === 200,
          '1g. another person\'s write is unaffected');
  t.check((await one(write, aliceElsewhere)).statusCode === 200,
          '1h. the same sub in another realm is another budget');
  const reads = [];
  for (let i = 0; i < 5; i++) {
    reads.push((await one(read, alice)).statusCode);
  }
  t.check(reads.every(function (s) {
    return s === 200;
  }), '1i. the same person\'s reads still answer, uncounted',
          reads.join(','));
  config.setOverride('account.writesPerSubject', 0);
  try {
    t.check((await one(write, alice)).statusCode === 200,
            '1j. account.writesPerSubject 0 counts nothing');
  } finally {
    config.setOverride('account.writesPerSubject', 3);
  }
  log.debug("Leaving accountSections().");
}

async function reportSections(t, errorCodes) {
  log.debug("Entering reportSections().");
  const reportApi = require('../report/report_api');
  const expensive = [
    ['POST', 'queries', '', ''], ['POST', 'jobs', '', ''],
    ['POST', 'definitions', 'd1', 'run'], ['GET', 'jobs', 'j1', 'result']];
  const cheap = [
    ['GET', 'jobs', 'j1', ''], ['GET', 'jobs', '', ''],
    ['GET', 'definitions', '', ''], ['POST', 'definitions', '', ''],
    ['POST', 'definitions', 'd1', 'share'], ['POST', 'jobs', 'j1', 'cancel'],
    ['GET', 'catalog', '', '']];
  t.check(expensive.every(function (a) {
    return reportApi.expensive(a[0], a[1], a[2], a[3]) === true;
  }) && cheap.every(function (a) {
    return reportApi.expensive(a[0], a[1], a[2], a[3]) === false;
  }), '2a. the expensive acts are a query, a job queued, a definition run ' +
      'and a result downloaded; status, lists and edits are not');
  const carol = { subject: 'urn:uuid:sab-carol', realm: '' };
  const dave = { subject: 'urn:uuid:sab-dave', realm: '' };
  const req = { headers: {}, socket: { remoteAddress: '192.0.2.8' } };
  const verdicts = [];
  for (let i = 0; i < 2; i++) {
    verdicts.push(await reportApi.overActBudget(req, fakeRes(), carol));
  }
  t.check(verdicts.join(',') === 'false,false',
          '2b. two acts within report.actsPerSubject (2) pass',
          verdicts.join(','));
  const res = fakeRes();
  const refused = await reportApi.overActBudget(req, res, carol);
  const body = parsed(res);
  const retry = Number(res.headers['retry-after']);
  t.check(refused === true && res.statusCode === 429 && retry > 60 &&
          retry <= 300,
          '2c. the third is 429 with Retry-After in report.actWindowS (300)',
          res.statusCode + ' ' + retry);
  t.check(errorCodes.codeOf(res) === 'STS-REPORT-0062' &&
          body.error === 'too_many_requests' &&
          /Wait \d+ seconds/.test(String(body.error_description)) &&
          Array.isArray(body.messages) && body.messages[0].key === KEY &&
          res.body.indexOf('STS-') < 0,
          '2d. coded STS-REPORT-0062, too_many_requests, with the catalog ' +
          'message', errorCodes.codeOf(res) + ' ' + res.body);
  t.check(await reportApi.overActBudget(req, fakeRes(), dave) === false,
          '2e. another subject is unaffected');
  log.debug("Leaving reportSections().");
}

async function run(t) {
  log.debug("Entering run().");
  const config = require('../common/config');
  const websecurity = require('../common/websecurity');
  const errorCodes = require('../common/error_codes');
  websecurity.reset();
  config.setOverride('account.writesPerSubject', 3);
  config.setOverride('account.writeWindowS', 600);
  config.setOverride('report.actsPerSubject', 2);
  config.setOverride('report.actWindowS', 300);
  try {
    t.log.info('=== 1. /account-api: the write budget ===');
    await accountSections(t, config, websecurity, errorCodes);
    t.log.info('=== 2. /report-api: the act budget ===');
    await reportSections(t, errorCodes);
  } finally {
    ['account.writesPerSubject', 'account.writeWindowS',
     'report.actsPerSubject', 'report.actWindowS'].forEach(function (key) {
      config.clearOverride(key);
    });
    websecurity.reset();
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'subject_act_budgets',
  describe: 'a signed-in subject\'s account writes and expensive report ' +
            'acts each count in a bucket keyed by the token\'s subject, ' +
            'refused 429 with Retry-After and a code past it; other ' +
            'subjects and reads are unaffected (#2167)',
  run: run
};
