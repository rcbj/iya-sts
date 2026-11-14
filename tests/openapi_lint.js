// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: openapi_lint.js
//
// ---------------------------------------------------------------------------
// THE GENERATED OPENAPI DOCUMENTS PASS SPECTRAL (#1390).
//
// Every document the model generates is linted against Spectral's OpenAPI
// rules. An error fails this file; a warning is a matter of taste and is
// only counted. A rule switched off here says why beside it.
// ---------------------------------------------------------------------------

const log = require('bunyan').createLogger({
  name: 'openapi_lint',
  level: process.env.LOG_LEVEL || 'info'
});

const ModelTables = require('../common/model_tables');

const DOCUMENTS = ['management', 'console', 'account', 'authn', 'report'];

async function run(t) {
  log.debug("Entering run().");
  const { Spectral } = require('@stoplight/spectral-core');
  const { oas } = require('@stoplight/spectral-rulesets');
  const spectral = new Spectral();
  spectral.setRuleset({ extends: [[oas, 'recommended']], rules: {} });
  for (const name of DOCUMENTS) {
    const results = await spectral.run(ModelTables.file('openapi.' + name +
      '.json'));
    // A response member that happens to be NAMED `example` is read by the rule
    // as an OpenAPI example of the wrong type. It is a member like any other.
    const errors = results.filter(function (one) {
      return one.severity === 0 && !(one.code === 'oas3-valid-media-example' &&
        one.path[one.path.length - 2] === 'properties');
    });
    t.equal(errors.slice(0, 5).map(function (one) {
      return one.code + ' at ' + one.path.join('/') + ': ' + one.message;
    }).join('\n'), '', 'the ' + name + ' document has no Spectral error (' +
      errors.length + ')');
    t.log.info(name + ': ' + (results.length - errors.length) +
      ' warning(s)');
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'openapi_lint',
  describe: 'the generated OpenAPI documents pass Spectral (#1390)',
  run: run
};
