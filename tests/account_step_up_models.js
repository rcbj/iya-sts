// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: account_step_up_models.js
//
// ===========================================================================
// THE "SIGN IN AGAIN" ANSWER MEETS EVERY MODEL IT IS SENT UNDER (#2289).
//
// `AccountApi.run()` answers an operation marked `recentAuth` with
// `200 { ok: false, stepUp: { prompt: 'login', maxAge } }` when the
// person's sign-in is older than `account.recentAuthMinutes`, before the
// operation's own handler runs. Every answer is held to the operation's
// model (rule 3dc), and `actOnTokens`' 200 model had no `stepUp`: the
// answer was refused and the person got a 500 (STS-API-0139), so the
// portal never sent them to sign in again. Found enrolling a YubiKey PIV
// certificate on 8081.
//
// The operations are read from the account API's own table, not listed
// here, so an operation marked `recentAuth` later is held too. For each,
// the gate's answer is checked against the published document with the
// validator the service runs (`ResponseModels.problemOf()`), and the
// gate's answer itself is read from `AccountApi.stepUpAnswer()`, the one
// place that builds it.
// ===========================================================================

delete process.env.CONFIG_FILE;

const log = require('bunyan').createLogger({ name: 'account_step_up_models',
  level: process.env.LOG_LEVEL || 'info' });

async function run(t) {
  log.debug("Entering run().");
  t.log.info('=== the "sign in again" answer meets every model it is ' +
             'sent under (#2289) ===');
  require('../common/protocol_stack');
  const accountApi = require('../account-api/account_api');
  const AccountApiSpec = require('../account-api/account_api_spec');
  const { ResponseModels } = require('../common/response_models');
  const models = new ResponseModels({
    log: { debug: function () {}, error: function () {} },
    mark: function () {}
  });
  const doc = AccountApiSpec.document({});
  const installed = models.installed(function () {
    return doc;
  });
  const ops = accountApi.operations().filter(function (op) {
    return op.recentAuth;
  });
  t.check(ops.length >= 14, 'the account API marks the operations that ' +
          'need a recent sign-in (' + ops.length + ')');
  const answer = accountApi.stepUpAnswer();
  t.check(answer && answer.ok === false && answer.stepUp &&
          answer.stepUp.prompt === 'login' &&
          typeof answer.stepUp.maxAge === 'number',
          'the gate answers ok false and a stepUp asking for a new sign-in',
          JSON.stringify(answer));
  const wrong = [];
  ops.forEach(function (op) {
    const base = '/account-api';
    const concrete = String(op.path).replace(/\{[^}]+\}/g, 'x')
      .replace(/:[A-Za-z]+/g, 'x');
    const problem = models.problemOf(installed,
      { method: op.method, baseUrl: '', path: concrete },
      { statusCode: 200, get: function () {
        return 'application/json';
      } }, JSON.stringify(answer));
    if (problem) {
      wrong.push(op.operationId + ' (' + op.method + ' ' + concrete + '): ' +
                 problem.where);
    }
    void base;
  });
  t.check(wrong.length === 0, 'every recentAuth operation\'s 200 model ' +
          'accepts the gate\'s answer, so it is sent rather than a 500',
          wrong.join('; '));
  log.debug("Leaving run().");
}

module.exports = {
  name: 'account_step_up_models',
  describe: 'Every /account-api operation marked recentAuth has a 200 model ' +
            'that accepts the gate\'s "sign in again" answer (#2289)',
  run: run
};
