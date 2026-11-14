// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: risk_distinct_batch.js
//
// ===========================================================================
// THE RISK ENGINE ASKS ITS DISTINCT-VALUE COUNTS IN ONE STATEMENT
// (2026-10-22, #820).
//
// An assessment asked `riskDistinctValues()` once per feature level, awaited
// one after another: about seven round trips per sign-in on 8081, 8,310
// statements a minute.
//
//   B1. with the history in the database and a driver that batches,
//       `distinctValuesMany()` asks once and answers in the order asked;
//   B2. with a driver that does not batch, it asks one by one, as before;
//   B3. the engine's history asks the batch, not the per-level door.
// ===========================================================================

const fs = require('fs');
const path = require('path');

const log = require('bunyan').createLogger({
  name: 'risk_distinct_batch',
  level: process.env.LOG_LEVEL || 'info' });

// A driver holding every method the risk group needs, recording what it is
// asked; `batching` decides whether it offers the batched door.
function fakeDriver(asked, batching) {
  log.debug("Entering fakeDriver().");
  const named = {
    riskDistinctValues: function (realm, subject, feature, prefix) {
      asked.push('one:' + feature + ':' + prefix);
      return Promise.resolve(feature.length);
    }
  };
  if (batching) {
    named.riskDistinctValuesMany = function (realm, subject, asks) {
      asked.push('many:' + asks.length);
      return Promise.resolve(asks.map(function (one) {
        return one.feature.length;
      }));
    };
  }
  log.debug("Leaving fakeDriver().");
  return new Proxy(named, {
    get: function (target, name) {
      if (Object.prototype.hasOwnProperty.call(target, name)) {
        return target[name];
      }
      if (name === 'riskDistinctValuesMany') {
        return undefined;
      }
      return function () {
        return Promise.resolve([]);
      };
    }
  });
}

async function run(t) {
  log.debug("Entering run().");
  const store = require('../risk/risk_store');
  const asks = [{ feature: 'asn', prefix: '' },
                { feature: 'ip>asn', prefix: '10.0.0.1|' },
                { feature: 'country', prefix: '' }];
  const asked = [];
  store.setDriver(fakeDriver(asked, true), 'postgres');
  const batched = await store.distinctValuesMany('default', '*', asks, true);
  t.check(asked.join(',') === 'many:3' &&
          batched.join(',') === '3,6,7',
          'B1. one batched statement, answered in the order asked',
          JSON.stringify({ asked: asked, batched: batched }));

  asked.length = 0;
  store.setDriver(fakeDriver(asked, false), 'postgres');
  const single = await store.distinctValuesMany('default', '*', asks, true);
  t.check(asked.length === 3 && asked[0] === 'one:asn:' &&
          single.join(',') === '3,6,7',
          'B2. without a batching driver, one by one as before',
          JSON.stringify({ asked: asked, single: single }));
  if (typeof store.clearDriver === 'function') {
    store.clearDriver();
  }

  const source = fs.readFileSync(path.join(__dirname, '..', 'risk',
                                           'risk_engine.ts'), 'utf8');
  const at = source.indexOf('async historyOf(') >= 0
    ? source.indexOf('async historyOf(')
    : source.indexOf('historyOf(');
  const body = at < 0 ? '' : source.slice(at, source.indexOf('\n  }\n', at));
  t.check(/store\.distinctValuesMany\(/.test(body) &&
          !/store\.distinctValues\(/.test(body),
          'B3. the engine\'s history asks the batch, not one per level');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'risk_distinct_batch',
  describe: 'the risk engine asks its distinct-value counts in one ' +
            'statement (#820)',
  run: run
};
