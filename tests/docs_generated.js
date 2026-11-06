// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';

// ===========================================================================
// tests/docs_generated.js — A PAGE WRITTEN FROM THE CODE IS THE CODE'S (#1360).
//
// `docs/pki-use-cases.md` is written by `node common/certificate_trust.js
// --docs` from the purpose table, so the published table and the door cannot
// disagree: this is `tests/error_codes.js`'s check on `docs/error-codes.md`,
// for a second generated page.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const trust = require('../common/certificate_trust');

module.exports = {
  name: 'docs_generated',
  describe: 'docs/pki-use-cases.md is what the purpose table writes',
  run: function (t) {
    const page = fs.readFileSync(trust.docsPath(), 'utf8');
    t.check(page === trust.docsPage(),
            'docs/pki-use-cases.md is current; stale means run: node ' +
            'common/certificate_trust.js --docs (in the tests image)', '');
    trust.PURPOSES.forEach(function (one) {
      t.check(page.indexOf('| `' + one.id + '` |') !== -1 &&
              page.indexOf('`' + one.setting + '`') !== -1,
              one.id + ' and its setting are on the page', '');
    });
  }
};
