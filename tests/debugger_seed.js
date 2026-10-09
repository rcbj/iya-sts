// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: debugger_seed.js
//
// ===========================================================================
// THE DEBUGGER'S TWO APPLICATION ENTRIES ARE SEEDED IN EVERY INSTALL (#541,
// 2026-10-09).
//
// rcbj: "Add a debugger application object by default to new installs. Model
// it after the admin console application object." Until #541
// `sts-debugger-ui` and `sts-debugger-api` were seeded only where the process
// embedded the debugger, so a product install — `debugger.enabled` `auto` is
// off there — had neither. The claim: in product mode, the debugger OFF, a
// seed of the default realm still writes both, beside the console's entry,
// and the client carries a redirect URI.
//
// It removes the two entries, seeds, and puts back nothing else: the entries
// it re-creates are the ones that were there, as a start would write them.
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const realms = require('../common/realms');
const mode = require('../common/mode');
const applications = require('../common/applications');
// Fills the directory slots and seeds the internal applications.
require('../ldap/ldap_server');

const log = require('bunyan').createLogger({ name: 'debugger_seed',
  level: process.env.LOG_LEVEL || 'info' });

const DEBUGGER_ENTRIES = ['sts-debugger-api', 'sts-debugger-ui'];

function inDefault(fn) {
  log.debug("Entering inDefault().");
  log.debug("Leaving inDefault().");
  return realms.run(realms.get(realms.DEFAULT_ID), fn);
}

async function run(t) {
  log.debug("Entering run().");
  // PRODUCT MODE, the case #541 is about: `debugger.enabled` is read at a
  // start only, so its default `auto` — off in product — is how a running
  // process is made not to embed the debugger.
  config.setOverride('global.mode', 'product');
  try {
    t.check(mode.embedsProtocolDebugger() === false,
            'in product mode, under debugger.enabled auto, the process does ' +
            'not embed the debugger');
    inDefault(function () {
      log.debug("Entering run() default-realm seed.");
      DEBUGGER_ENTRIES.forEach(function (id) {
        applications.deleteApplication(id);
      });
      t.check(DEBUGGER_ENTRIES.every(function (id) {
        return !applications.get(id);
      }), 'the two entries are gone before the seed');
      applications.seedInternalApplications({ scope: 'default' });
      DEBUGGER_ENTRIES.concat(['sts-admin-console']).forEach(function (id) {
        t.check(!!applications.get(id), id + ' is seeded in the default ' +
                'realm although the debugger is off');
      });
      const ui = applications.clientConfigOf('sts-debugger-ui');
      t.check(!!ui && (ui.redirect_uris || []).length > 0,
              'and the client carries its redirect URI',
              JSON.stringify(ui && ui.redirect_uris));
      log.debug("Leaving run() default-realm seed.");
    });
  } finally {
    config.clearOverride('global.mode');
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'debugger_seed',
  describe: 'the embedded debugger\'s two application entries are seeded in ' +
            'every install, as the console\'s is, in product mode with the ' +
            'debugger off ' +
            '(#541)',
  run: run
};
