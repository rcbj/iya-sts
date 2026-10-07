// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: settings_restart_wording.js
//
// ---------------------------------------------------------------------------
// WHAT A SETTINGS WRITE SAYS ABOUT A RESTART, AND WHETHER IT IS TRUE (rcbj,
// 2026-10-07).
//
// Every reply of `configAction()`, `tokenLifetimesAction()` and
// `samlAssertionsAction()` ended "gone on restart", and Token lifetimes, SAML
// assertions and Configuration said "Changes are in memory and are gone on
// restart" — unconditionally. On 8081 (product, postgres)
// `POST /admin-api/config/set` said so while the store was holding the
// override. The settings block on every page has worded both cases from
// `persistsAppconfig` since 2026-08-27; these were the places that did not.
//
// What this pins, in process:
//
//   1. With no persistent store (this process's own `persistence.mode`,
//      memory) a `set`, a `set-many` and a token-lifetimes `set` say the
//      override is in memory and gone on restart, and how to keep it.
//   2. With a persisting store — `persistence` stubbed through the deps, the
//      way the composition root hands every dependency in — the same writes
//      say it is written to that store and kept across restarts.
//   3. A write while a non-default realm is ambient is asked about the REALM
//      (`persistsRealms`), because it lands on the realm row; a write naming
//      only a `realms.*` row is asked about the process.
//   4. The pages' sentence and the Source column's two words branch on the
//      settings block's `context` the same way.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

require('../common/applications');
require('../ldap/ldap_server');
const adminActions = require('../admin-core/admin_actions');
const SettingsForms = require('../admin-ui/web_settings');
const persistence = require('../persistence/persistence');

const log = require('bunyan').createLogger({
  name: 'settings_restart_wording',
  level: process.env.LOG_LEVEL || 'info' });

const KEY = 'groups.claimName';
const LIFETIME = 'oauth2.accessTokenTtlS';

// An AdminActions over the real modules, but with the persistence store's
// status and, when given, the realm module replaced.
function actionsWith(status, realms) {
  log.debug("Entering actionsWith().");
  const deps = adminActions.AdminActions.defaultDeps();
  deps.persistence = Object.assign({}, deps.persistence, {
    status: function () {
      return status;
    }
  });
  if (realms) {
    deps.realms = Object.assign({}, deps.realms, realms);
  }
  log.debug("Leaving actionsWith().");
  return new adminActions.AdminActions(deps);
}

// Puts both settings back, whichever case set them.
function putBack(actions) {
  log.debug("Entering putBack().");
  [KEY, LIFETIME].forEach(function (key) {
    actions.configAction({ action: 'reset', key: key });
  });
  log.debug("Leaving putBack().");
}

// One door's three writes, and what each one's message says.
function writesOf(actions, value) {
  log.debug("Entering writesOf().");
  const set = actions.configAction({ action: 'set', key: KEY,
                                     value: 'roles-' + value });
  const many = actions.configAction({ action: 'set-many',
                                      [KEY]: 'many-' + value });
  const life = actions.tokenLifetimesAction({ action: 'set',
                                              [LIFETIME]: value });
  log.debug("Leaving writesOf().");
  return { set: set, many: many, life: life };
}

function messagesOf(out) {
  log.debug("Entering messagesOf().");
  log.debug("Leaving messagesOf().");
  return [out.set, out.many, out.life].map(function (one) {
    return (one && one.ok && one.message) || '';
  });
}

function run(t) {
  log.debug("Entering run().");

  // --- 1. No persistent store ---------------------------------------------
  const memory = actionsWith({ mode: 'memory', persistsAppconfig: false,
                               persistsRealms: false });
  const lost = messagesOf(writesOf(memory, '600'));
  putBack(memory);
  t.check(lost.every(function (message) {
    return /in memory and gone on restart/.test(message) &&
           /appconfig file/.test(message) &&
           /persistence\.appconfig/.test(message) &&
           !/kept across restarts/.test(message);
  }), '1. with no persistent store, set, set-many and a token-lifetimes ' +
      'set say the override is in memory and gone on restart, and how to ' +
      'keep it', JSON.stringify(lost));

  // The default instance asks the REAL store. Which one that is depends on
  // what ran before this file in the same process (appconfig_persistence.js
  // leaves an ldif store open), so the claim is that the reply agrees with
  // the store's own status, whichever it is.
  const status = persistence.status();
  const real = adminActions.configAction({ action: 'set', key: KEY,
                                           value: 'roles-real' });
  adminActions.configAction({ action: 'reset', key: KEY });
  t.check(real && real.ok === true &&
          (status.persistsAppconfig
            ? new RegExp('written to the ' + status.mode + ' store and kept')
              .test(real.message)
            : /gone on restart/.test(real.message)),
          '1b. and the default instance words the real store\'s own status (' +
          status.mode + ', persistsAppconfig ' + status.persistsAppconfig +
          ')', JSON.stringify(real && (real.message || real.errors)));

  // --- 2. A persisting store ----------------------------------------------
  const stored = actionsWith({ mode: 'postgres', persistsAppconfig: true,
                               persistsRealms: true });
  const kept = messagesOf(writesOf(stored, '630'));
  putBack(stored);
  t.check(kept.every(function (message) {
    return /written to the postgres store and kept across restarts/
      .test(message) && !/gone on restart/i.test(message);
  }), '2. with a persisting store, the same three writes say the override is ' +
      'written to that store and kept across restarts', JSON.stringify(kept));

  // A set-many that changed nothing makes no claim about a restart.
  const again = stored.configAction({ action: 'set-many',
                                      [KEY]: stored.deps.config.text(KEY) });
  t.check(again && again.ok === true && /Nothing changed/.test(again.message) &&
          !/restart/.test(again.message),
          '2b. a set-many that changed nothing says nothing about a restart',
          JSON.stringify(again && again.message));

  // --- 3. Inside a realm --------------------------------------------------
  const realmOnly = { isDefault: function () {
    return false;
  }, currentId: function () {
    return 'acme';
  } };
  const inRealm = actionsWith({ mode: 'postgres', persistsAppconfig: true,
                                persistsRealms: false }, realmOnly);
  const realmLost = inRealm.overrideDurability([KEY]);
  const processKept = inRealm.overrideDurability(['realms.enabled']);
  const inRealmKept = actionsWith({ mode: 'ldif', persistsAppconfig: false,
                                    persistsRealms: true }, realmOnly)
    .overrideDurability([KEY]);
  t.check(/gone on restart/.test(realmLost) &&
          /persistence\.realms/.test(realmLost) &&
          /kept across restarts/.test(processKept) &&
          /ldif store with the "acme" realm and kept across restarts/
            .test(inRealmKept),
          '3. a write inside a realm is asked about persistsRealms, and one ' +
          'naming only a realms.* row about the process',
          JSON.stringify([realmLost, processKept, inRealmKept]));

  // --- 4. The pages -------------------------------------------------------
  const pageKept = SettingsForms.durability({
    persistsAppconfig: true, persistenceMode: 'postgres',
    configFile: 'env/<mine>.js' });
  const pageLost = SettingsForms.durability({ persistsAppconfig: false,
                                              configFile: null });
  t.check(/<code>persistence\.mode=postgres<\/code> store and kept across/
            .test(pageKept) &&
          pageKept.indexOf('env/&lt;mine&gt;.js') > 0 &&
          !/gone on restart/.test(pageKept) &&
          /in memory and are gone on restart/.test(pageLost) &&
          pageLost.indexOf('<code>env/local.js</code>') > 0 &&
          SettingsForms.overrideKept({ persistsAppconfig: true }) ===
            'kept in the store' &&
          SettingsForms.overrideKept(null) === 'in memory only',
          '4. the pages\' sentence and the Source column branch on the ' +
          'block\'s context the same way', JSON.stringify([pageKept,
                                                           pageLost]));
  log.debug("Leaving run().");
}

module.exports = {
  name: 'settings_restart_wording',
  describe: 'a settings write says it is kept across a restart where the ' +
            'store keeps it, and gone on restart only where it is not',
  run: run
};
