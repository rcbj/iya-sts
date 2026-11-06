// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: admin_api_lazy_validators.js
//
// ===========================================================================
// THE MANAGEMENT API'S REQUEST SCHEMAS ARE COMPILED ON FIRST USE (#617).
//
// Every process compiled all of `/admin-api`'s request schemas with ajv when
// the management API was wired — about 1.2 s of each process's start on
// 8081, for validators almost none of which a given process ever reaches.
// `mgmt-api/admin_api.ts` now records each schema at wiring and compiles it
// the first time a request reaches its operation. This holds:
//
//   1. wiring compiles NOTHING: every schema is recorded, none compiled;
//   2. a request reaching an operation compiles that operation's validator
//      and is held to it — a member the schema does not name is refused, a
//      body it takes is accepted — and the validator is kept;
//   3. every recorded schema still compiles (`compileAllRequestSchemas()`),
//      so moving the compile out of the start did not move a broken schema
//      out of sight: STS-API-0010 is what a reader would otherwise only see
//      at that operation's first request.
//
// In process: each is about the instance this process wired.
// ===========================================================================

const perfHooks = require('perf_hooks');

const log = require('bunyan').createLogger({
  name: 'admin_api_lazy_validators', level: process.env.LOG_LEVEL || 'info' });

delete process.env.CONFIG_FILE;

// The first POST action row with a request schema, as a request reaches it.
function firstActionWithSchema(routes) {
  log.debug("Entering firstActionWithSchema().");
  for (let i = 0; i < routes.length; i++) {
    const entry = routes[i];
    if (entry.method !== 'POST' || !entry.route || entry.handlerOwnsBody) {
      continue;
    }
    const action = (entry.actions || []).filter(function (one) {
      return !!one.requestBody &&
        one.requestBody.additionalProperties === false;
    })[0];
    if (action) {
      log.debug("Leaving firstActionWithSchema().");
      return { route: entry.route, action: action.action,
               operationId: action.operationId };
    }
  }
  log.debug("Leaving firstActionWithSchema(). None.");
  return null;
}

function run(t) {
  log.debug("Entering run().");
  const adminApi = require('../mgmt-api/admin_api');
  const routes = adminApi.ROUTES;

  t.log.info('=== 1. wiring records every schema and compiles none ===');
  const wired = adminApi.validatorCounts();
  t.check(wired.recorded > 300 && wired.compiled === 0,
          'after wiring, every request schema is recorded and none is ' +
          'compiled — the ~1.2 s per process that compiling them all cost',
          JSON.stringify(wired));

  t.log.info('=== 2. a request compiles its own operation\'s validator ===');
  const target = firstActionWithSchema(routes);
  t.check(!!target, 'there is an action with a closed request schema',
          JSON.stringify(target));
  if (!target) {
    log.debug("Leaving run(). Nothing to ask.");
    return;
  }
  const ask = function (body) {
    return adminApi.checkRequestBody({
      __adminApiRoute: target.route,
      params: { action: target.action },
      body: JSON.stringify(body),
      headers: { 'content-type': 'application/json' } });
  };
  const refused = ask({ notAMemberOfAnySchema617: 1 });
  t.check(refused.ok === false && (refused.errors || []).length > 0,
          'a body with a member ' + target.operationId + '\'s schema does ' +
          'not name is refused by the validator compiled for it',
          JSON.stringify(refused));
  const afterOne = adminApi.validatorCounts();
  t.check(afterOne.compiled >= 1 && afterOne.compiled <= 2,
          'and only that operation\'s validator was compiled (the action ' +
          'row, and the route row when it has none of its own)',
          JSON.stringify(afterOne));
  const accepted = ask({});
  t.check(accepted.ok === true,
          'an empty body is accepted — `required` is the handler\'s, not ' +
          'the door\'s — so the check above is not one that cannot pass',
          JSON.stringify(accepted));
  t.equal(adminApi.validatorCounts().compiled, afterOne.compiled,
          'and the second request reused the validator rather than ' +
          'compiling another');

  t.log.info('=== 3. every recorded schema still compiles ===');
  const started = perfHooks.performance.now();
  const all = adminApi.compileAllRequestSchemas();
  const tookMs = Math.round(perfHooks.performance.now() - started);
  t.check(all.failed.length === 0 && all.built === wired.recorded,
          'every recorded request schema compiles (' + all.built + ' in ' +
          tookMs + ' ms — the work the start no longer does); none would ' +
          'be STS-API-0010 at its first request',
          all.failed.join(', ') || 'none failed');

  t.log.info('=== 4. an integer request property is bounded (#1347) ===');
  // The backstop bounds every request integer to ±Number.MAX_SAFE_INTEGER in
  // the ajv copy (`structureOnly()`), so a fuzzed or mistaken magnitude — the
  // 9.22e21 ttl the #1299 gate fed — is refused at the door rather than
  // reaching a handler that writes it to a bigint column and poisons a flush.
  // Find any operation with an integer request property that names no tighter
  // bound of its own and accepts a small value, then show the ceiling holds.
  const integerField = function (schema) {
    if (!schema || !schema.properties) {
      return null;
    }
    const names = Object.keys(schema.properties);
    for (let i = 0; i < names.length; i++) {
      const prop = schema.properties[names[i]];
      if (!prop) {
        continue;
      }
      const types = Array.isArray(prop.type) ? prop.type : [prop.type];
      if (types.indexOf('integer') >= 0 &&
          typeof prop.maximum !== 'number' &&
          (typeof prop.minimum !== 'number' || prop.minimum <= 1)) {
        return names[i];
      }
    }
    return null;
  };
  let intTarget = null;
  for (let i = 0; i < routes.length && !intTarget; i++) {
    const entry = routes[i];
    if (entry.method !== 'POST' || !entry.route || entry.handlerOwnsBody) {
      continue;
    }
    if (entry.requestBody &&
        entry.requestBody.additionalProperties === false) {
      const field = integerField(entry.requestBody);
      if (field) {
        intTarget = { route: entry.route, action: '', field: field };
        break;
      }
    }
    const actions = entry.actions || [];
    for (let j = 0; j < actions.length && !intTarget; j++) {
      const a = actions[j];
      if (a.requestBody && a.requestBody.additionalProperties === false) {
        const f = integerField(a.requestBody);
        if (f) {
          intTarget = { route: entry.route, action: a.action, field: f };
        }
      }
    }
  }
  t.check(!!intTarget,
          'there is an operation with a bounded integer request property',
          JSON.stringify(intTarget));
  if (intTarget) {
    const askInt = function (value) {
      const body = {};
      body[intTarget.field] = value;
      return adminApi.checkRequestBody({
        __adminApiRoute: intTarget.route,
        params: { action: intTarget.action },
        body: JSON.stringify(body),
        headers: { 'content-type': 'application/json' } });
    };
    t.check(askInt(10).ok === true,
            'a small integer in ' + intTarget.field + ' is accepted',
            JSON.stringify(askInt(10)));
    const over = askInt(Number.MAX_SAFE_INTEGER + 100000);
    t.check(over.ok === false && (over.errors || []).length > 0,
            'a value past Number.MAX_SAFE_INTEGER is refused at the door ' +
            '(the #1347 backstop) — the column it would poison never sees it',
            JSON.stringify(over));
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'admin_api_lazy_validators',
  describe: 'the management API compiles a request schema the first time a ' +
            'request reaches its operation, not all of them at start, and ' +
            'every one still compiles (#617)',
  run: run
};
