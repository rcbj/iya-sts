// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/hosted_session_bounds.js
//
// ---------------------------------------------------------------------------
// THE CONSOLE, THE PORTAL AND THE REPORTS APPLICATION KEEP A SESSION BOUND
// OF THEIR OWN (#825). The sign-on session is still one record per browser.
// What these three do not follow is a realm session or refresh setting
// raised above the number they shipped with. The shorter of that number and
// the realm is what is enforced. The debugger is not one of them.
//
// In process: the helpers both authorization-endpoint sites call, the
// refresh idle those sites' sibling reads, the upgrade that fills an absent
// bound once and never overwrites a stored number, and the confirm door
// that refuses a clear, a 0 and an unconfirmed change — including a save
// that also names another attribute, which writes nothing.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const realms = require('../common/realms');
const applications = require('../common/applications');
const audit = require('../common/audit');
const errorCodes = require('../common/error_codes');
const adminActions = require('../admin-core/admin_actions');
const stepUp = require('../oauth-oidc/step_up');
// Fills the directory and seeds the internal applications, bounds included.
require('../ldap/ldap_server');

const log = require('bunyan').createLogger({ name: 'hosted_session_bounds',
  level: process.env.LOG_LEVEL || 'info' });

const CONSOLE = 'sts-admin-console';
const PORTAL = 'sts-user-portal';
const REPORT = 'sts-report';
const DEBUGGER_UI = 'sts-debugger-ui';

function inDefault(fn) {
  log.debug("Entering inDefault().");
  const out = realms.run(realms.get(realms.DEFAULT_ID), fn);
  log.debug("Leaving inDefault().");
  return out;
}

function firstField(row, name) {
  log.debug("Entering firstField().");
  const value = row && row.fields ? row.fields[name] : undefined;
  const text = [].concat(value || [])[0];
  log.debug("Leaving firstField().");
  return text === undefined || text === null ? '' : String(text);
}

function ageOf(clientId) {
  log.debug("Entering ageOf().");
  const need = applications.applyClientMaxAge(clientId,
    { acrValues: [], maxAge: null, present: false }, config);
  log.debug("Leaving ageOf().");
  return need;
}

function copyAttributes(attributes) {
  log.debug("Entering copyAttributes().");
  const out = {};
  Object.keys(attributes || {}).forEach(function (name) {
    out[name] = [].concat(attributes[name] || []).map(String);
  });
  log.debug("Leaving copyAttributes().");
  return out;
}

// An ldapmodify past updateApplication(): the three bound attributes are
// taken off the entry the directory holds, which is the only way they
// become absent. The registry refuses a clear.
function withoutHostedBounds(attributes) {
  log.debug("Entering withoutHostedBounds().");
  const out = copyAttributes(attributes);
  Object.keys(out).forEach(function (name) {
    const base = String(name).split(';')[0].toLowerCase();
    if (base === 'oauthmaxauthages' ||
        base === 'oauthrefreshtokenttls' ||
        base === 'oauthrefreshidleseconds') {
      delete out[name];
    }
  });
  log.debug("Leaving withoutHostedBounds().");
  return out;
}

async function run(t) {
  log.debug("Entering run().");
  const overrides = ['authn.sessionLifetimeS', 'oauth2.maxAuthAgeS',
                     'oauth2.refreshTokenTtlS', 'oauth2.refreshIdleSeconds'];
  try {
    inDefault(function () {
      log.debug("Entering run() bounds.");
      const store = applications.directoryInstalled();
      const beforeEntry = store.readApplication(CONSOLE);
      const snapshot = copyAttributes(beforeEntry && beforeEntry.attributes);
      try {
        config.setOverride('authn.sessionLifetimeS', 2592000);
        config.setOverride('oauth2.maxAuthAgeS', 0);
        const consoleAge = ageOf(CONSOLE);
        t.equal(consoleAge.maxAge, 3600,
                '1. a 30-day realm session does not lengthen the console');
        t.equal(consoleAge.present, true,
                '1b. the bound is present when the request sent no max_age');
        const portalAge = ageOf(PORTAL);
        t.equal(portalAge.maxAge, 28800,
                '1c. the portal keeps eight hours');
        const reportAge = ageOf(REPORT);
        t.equal(reportAge.maxAge, 3600,
                '1d. reports keeps the console\'s hour');
        const now = Math.floor(Date.now() / 1000);
        const stale = stepUp.assessSession(consoleAge,
          { authTime: now - 3601 }, { now: now });
        t.equal(stale.met, false, '2. an hour-old console session is too old');
        t.equal(stale.reason, 'max_age', '2b. the reason is max_age');
        const fresh = stepUp.assessSession(consoleAge,
          { authTime: now - 10 }, { now: now });
        t.equal(fresh.met, true, '2c. a session ten seconds old is met');
        const askedShort = applications.applyClientMaxAge(CONSOLE,
          { acrValues: [], maxAge: 60, present: true }, config);
        t.equal(askedShort.maxAge, 60,
                '3. a request max_age shorter than the bound is kept');
        const askedLong = applications.applyClientMaxAge(CONSOLE,
          { acrValues: [], maxAge: 99999, present: true }, config);
        t.equal(askedLong.maxAge, 3600,
                '3b. a request max_age longer than the bound is capped');

        config.setOverride('authn.sessionLifetimeS', 600);
        t.equal(ageOf(CONSOLE).maxAge, 600,
                '4. lowering the realm session below the bound shortens it');
        config.setOverride('authn.sessionLifetimeS', 2592000);

        const ordinary = ageOf('hsb-ordinary');
        t.equal(ordinary.maxAge, null,
                '5. an ordinary client with realm max age 0 is unchanged');
        t.equal(ordinary.present, false,
                '5b. and the requirement stays absent');
        config.setOverride('oauth2.maxAuthAgeS', 1800);
        config.setOverride('authn.sessionLifetimeS', 600);
        const ordinaryCapped = ageOf('hsb-ordinary');
        t.equal(ordinaryCapped.maxAge, 1800,
                '5c. a positive realm max age applies, without the session ' +
                'lifetime minimum');
        t.equal(ageOf(DEBUGGER_UI).maxAge, 1800,
                '5d. the debugger follows the realm and not the hosted table');
        config.setOverride('oauth2.maxAuthAgeS', 0);
        config.setOverride('authn.sessionLifetimeS', 2592000);
        t.equal(ageOf(DEBUGGER_UI).maxAge, null,
                '5e. the debugger with realm max age 0 is not held to the ' +
                'hosted table');

        t.equal(applications.hostedEffective(REPORT,
                'oauth2.refreshIdleSeconds', config), 900,
                '6. reports idle is 15 minutes against the realm\'s day');
        config.setOverride('oauth2.refreshIdleSeconds', 0);
        t.equal(applications.hostedEffective(CONSOLE,
                'oauth2.refreshIdleSeconds', config), 900,
                '6b. a realm idle of 0 keeps the console\'s 15 minutes');
        config.clearOverride('oauth2.refreshIdleSeconds');
        config.setOverride('oauth2.refreshTokenTtlS', 120);
        t.equal(applications.hostedEffective(PORTAL,
                'oauth2.refreshTokenTtlS', config), 120,
                '6c. a shorter realm refresh lifetime shortens the portal');
        config.clearOverride('oauth2.refreshTokenTtlS');

        const custom = applications.updateApplication(CONSOLE, {
          mode: 'set', attribute: 'oauthMaxAuthAgeS', value: '7200',
          confirm: '1' });
        t.equal(custom.ok, true, '7. a confirmed different number is stored',
                JSON.stringify(custom.errors || custom));
        t.equal(applications.hostedEffective(CONSOLE, 'oauth2.maxAuthAgeS',
                config), 7200,
                '7b. 7200 is in force under a 30-day session');
        config.setOverride('authn.sessionLifetimeS', 600);
        t.equal(applications.hostedEffective(CONSOLE, 'oauth2.maxAuthAgeS',
                config), 600,
                '7c. the stored 7200 is still shortened by a 600s session');
        t.equal(firstField(applications.get(CONSOLE), 'oauthMaxAuthAgeS'),
                '7200', '7d. the stored number is not rewritten');
        config.setOverride('authn.sessionLifetimeS', 2592000);
        const restored = applications.updateApplication(CONSOLE, {
          mode: 'set', attribute: 'oauthMaxAuthAgeS', value: '3600',
          confirm: true });
        t.equal(restored.ok, true, '7e. the shipped hour is put back');

        const noConfirm = applications.updateApplication(CONSOLE, {
          mode: 'set', attribute: 'oauthRefreshTokenTtlS', value: '1800' });
        t.equal(noConfirm.ok, false, '8. an unconfirmed change is refused');
        t.equal(errorCodes.codeOf(noConfirm), 'STS-REG-0368',
                '8b. under STS-REG-0368');
        t.equal(firstField(applications.get(CONSOLE), 'oauthRefreshTokenTtlS'),
                '3600', '8c. and the stored hour is kept');
        const cleared = applications.updateApplication(CONSOLE, {
          mode: 'set', attribute: 'oauthRefreshIdleSeconds', value: '',
          confirm: '1' });
        t.equal(errorCodes.codeOf(cleared), 'STS-REG-0369',
                '8d. a confirmed clear is still refused');
        const zero = applications.updateApplication(REPORT, {
          mode: 'set', attribute: 'oauthMaxAuthAgeS', value: '0',
          confirm: 'on' });
        t.equal(errorCodes.codeOf(zero), 'STS-REG-0369',
                '8e. 0 is refused on reports');
        const garbage = applications.updateApplication(PORTAL, {
          mode: 'set', attribute: 'oauthRefreshIdleSeconds', value: 'nope',
          confirm: 'true' });
        t.equal(errorCodes.codeOf(garbage), 'STS-REG-0369',
                '8f. a value the setting will not parse is refused');
        const removed = applications.updateApplication(CONSOLE, {
          mode: 'remove', attribute: 'oauthRefreshTokenTtlS', value: '3600',
          confirm: '1' });
        t.equal(errorCodes.codeOf(removed), 'STS-REG-0369',
                '8g. removing the bound is refused, the same as clearing it');
        t.equal(firstField(applications.get(CONSOLE), 'oauthRefreshTokenTtlS'),
                '3600', '8h. and the stored hour is kept');

        const before = applications.get(CONSOLE);
        const oldDesc = String(before.description || '');
        const oldAge = firstField(before, 'oauthMaxAuthAgeS');
        const partial = adminActions.applicationsAction({
          action: 'update-fields', application: CONSOLE,
          fields: { oauthMaxAuthAgeS: '1800',
                    description: 'hosted bound partial apply' }
        });
        t.equal(partial.ok, false,
                '9. a mixed save without confirm is refused');
        t.equal(errorCodes.codeOf(partial), 'STS-REG-0368',
                '9b. under STS-REG-0368');
        const afterPartial = applications.get(CONSOLE);
        t.equal(String(afterPartial.description || ''), oldDesc,
                '9c. the description was not written');
        t.equal(firstField(afterPartial, 'oauthMaxAuthAgeS'), oldAge,
                '9d. and neither was the bound');
        const both = adminActions.applicationsAction({
          action: 'update-fields', application: CONSOLE, confirm: '1',
          fields: { oauthMaxAuthAgeS: '1800',
                    description: 'hosted bound confirmed' }
        });
        t.equal(both.ok, true, '9e. the same save with confirm writes both',
                JSON.stringify(both.errors || both));
        const afterBoth = applications.get(CONSOLE);
        t.equal(String(afterBoth.description || ''), 'hosted bound confirmed',
                '9f. the description changed');
        t.equal(firstField(afterBoth, 'oauthMaxAuthAgeS'), '1800',
                '9g. and the bound changed');
        const putBack = adminActions.applicationsAction({
          action: 'update-fields', application: CONSOLE, confirm: '1',
          fields: { oauthMaxAuthAgeS: oldAge, description: oldDesc }
        });
        t.equal(putBack.ok, true, '9h. both are put back');

        const rows = audit.list().filter(function (one) {
          return one.action === 'application.update' &&
                 one.detail && one.detail.hostedSessionBound === true &&
                 one.target === CONSOLE;
        });
        t.check(rows.length > 0,
                '10. a confirmed bound change is audited as a hosted bound',
                JSON.stringify(rows[0] && rows[0].detail));

        const live = store.readApplication(CONSOLE);
        const stripped = withoutHostedBounds(live && live.attributes);
        t.check(store.writeApplication(CONSOLE, stripped) === true,
                '11. an ldapmodify can take the three bounds off the console');
        t.equal(firstField(applications.get(CONSOLE), 'oauthMaxAuthAgeS'), '',
                '11b. the age attribute is absent');
        t.equal(applications.hostedEffective(CONSOLE, 'oauth2.maxAuthAgeS',
                config), 3600,
                '11c. an absent attribute still enforces the shipped hour');
        applications.seedInternalApplications({ scope: 'default' });
        t.equal(firstField(applications.get(CONSOLE), 'oauthMaxAuthAgeS'),
                '3600', '11d. the next start fills the shipped hour');
        t.equal(firstField(applications.get(CONSOLE),
                           'oauthRefreshIdleSeconds'), '900',
                '11e. and the shipped idle');
        const kept = applications.updateApplication(CONSOLE, {
          mode: 'set', attribute: 'oauthMaxAuthAgeS', value: '7200',
          confirm: '1' });
        t.check(kept.ok === true,
                '11f. a custom hour is stored after the fill',
                JSON.stringify(kept.errors || kept));
        applications.seedInternalApplications({ scope: 'default' });
        t.equal(firstField(applications.get(CONSOLE), 'oauthMaxAuthAgeS'),
                '7200', '11g. a later start does not overwrite it');
        const seeded = audit.list().filter(function (one) {
          return one.action === 'application.update' &&
                 one.target === CONSOLE &&
                 one.detail && one.detail.seeded === true &&
                 one.detail.hostedSessionBound === true;
        });
        t.check(seeded.length > 0,
                '11h. the fill is audited once, without the numbers',
                JSON.stringify(seeded[0] && seeded[0].detail));
        log.debug("Leaving run() bounds.");
      } finally {
        if (snapshot && Object.keys(snapshot).length) {
          store.writeApplication(CONSOLE, snapshot);
        }
      }
    });
  } finally {
    overrides.forEach(function (key) {
      config.clearOverride(key);
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'hosted_session_bounds',
  describe: 'the console, the portal and reports keep their own session ' +
            'bound, the shorter of it and the realm (#825)',
  run: run
};
