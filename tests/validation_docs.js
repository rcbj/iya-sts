// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/validation_docs.js
// ===========================================================================
// docs/validation.md STATES THE LIMITS THE CODE ENFORCES (#1459, ASVS 5.0.0
// 2.1.1). Each row of its table of limits is compared with `CAP`, and the page
// must point at the per-operation reference that is generated from the same
// definitions the requests are validated against.
// ===========================================================================

const fs = require('fs');
const path = require('path');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'validation_docs',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

/**
 * Compares the page with the code.
 *
 * @param {object} t - the runner's checker
 * @returns {void}
 */
function run(t) {
  log.debug("Entering run().");
  const validation = require('../common/validation');
  const page = fs.readFileSync(path.join(ROOT, 'docs/validation.md'), 'utf8');
  const rows = { Identifier: 'IDENTIFIER', Name: 'NAME', Token: 'TOKEN',
                 URI: 'URI', Scope: 'SCOPE', Text: 'TEXT', Message: 'LARGE',
                 'Anything else': 'DEFAULT' };
  Object.keys(rows).forEach(function (label) {
    const cap = validation.CAP[rows[label]];
    t.check(page.indexOf('| ' + label + ' | ' + cap.toLocaleString('en-US') +
                         ' |') >= 0,
            label + ' is documented as ' + cap);
  });
  t.check(page.indexOf('](openapi/)') >= 0,
          'the page points at the per-operation reference');
  const nav = fs.readFileSync(path.join(ROOT, 'docs/_data/navigation.yml'),
                              'utf8');
  t.check(nav.indexOf('/validation.html') >= 0, 'and is in the sidebar');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'validation_docs',
  describe: 'docs/validation.md states the limits common/validation.js ' +
            'enforces (ASVS 5.0.0 2.1.1)',
  run: run
};
