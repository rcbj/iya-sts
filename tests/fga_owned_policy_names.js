// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'fga_owned_policy_names',
  level: process.env.LOG_LEVEL || 'info' });
//
// File: fga_owned_policy_names.js
//
// ===========================================================================
// XACML → POLICIES WITH AN APPLICATION NAMED LIKE A PROPERTY OF EVERY OBJECT.
//
// The Schemathesis run of 2026-11-11 (run 14) had `GET /admin-api/xacml/
// policies` answer 500 in realm fuzz-base — "Cannot read properties of
// undefined (reading 'push')", STS-API-0140 — and pass in every other
// realm. Every application created gets a fine-grained policy of its own
// carrying its identifier (#564), and `FgaPolicies.ownedPolicies()` grouped
// those policies by identifier in a plain `{}`. An application identifier
// is any string a client_id may be, so one called `constructor` (or
// `toString`, `valueOf`, `hasOwnProperty`, ...) found Object.prototype's
// function in the group table, took it for an existing group, and pushed
// onto its `policies`, which a function does not have. The state is a
// legal one — `constructor` is a perfectly good client_id — so nothing is
// refused at the write; the grouping keys a table that has no prototype.
//
//   N1. applications named after Object.prototype's members are created;
//   N2. the repository view lists every one of them, grouped under its own
//       identifier, each with its one policy, referenced;
//   N3. `/admin-api/xacml/policies`' view (`adminViews.xacmlPoliciesView`)
//       answers the same, without throwing.
//
// In process, in a THROWAWAY REALM, as `fga_console.js` is.
// ===========================================================================

delete process.env.CONFIG_FILE;

// The names. `__proto__` is left out on purpose: it is refused as a member
// name across this service (`common/validation`), so it is not a state an
// application can reach; every other one here is.
const NAMES = ['constructor', 'toString', 'valueOf', 'hasOwnProperty',
               'isPrototypeOf', 'toLocaleString'];

/**
 * A request for a console view.
 *
 * @returns the request
 */
function request() {
  log.debug('Entering request().');
  log.debug('Leaving request().');
  return { query: {}, headers: { host: 'localhost:8081' }, protocol: 'https',
           get: function () {
             return '';
           } };
}

function run(t) {
  log.debug("Entering run().");
  require('../common/config');
  require('../common/app');
  require('../ldap/ldap_server');
  require('../common/i18n');
  const realms = require('../common/realms');
  const applications = require('../common/applications');
  const pap = require('../xacml/xacml_admin');
  // Loading it builds its default instance and fills the lifecycle slot.
  require('../xacml/fga_policies');
  // Loading xacml.ts fills the console's XACML slot the view forwards to.
  require('../xacml/xacml');
  const adminViews = require('../admin-core/admin_views');

  const id = 'fgan-' + Date.now().toString(36);
  const made = realms.create({ id: id, name: id,
                               description: 'Created by ' + __filename });
  t.check(made.ok, 'a trust realm to work in', (made.errors || []).join(' '));
  if (!made.ok) {
    log.debug("Leaving run(). No realm.");
    return;
  }
  try {
    const created = realms.run(made.realm, function () {
      return NAMES.map(function (name) {
        return applications.createApplication({
          identifier: name, name: 'Named ' + name, protocols: ['oauth2'] });
      });
    });
    t.check(created.every(function (one) {
      return one.ok;
    }), 'N1. applications named ' + NAMES.join(', ') + ' are created',
    JSON.stringify(created.map(function (one) {
      return one.errors || null;
    })));
    let view = null;
    let thrown = null;
    try {
      view = realms.run(made.realm, function () {
        return pap.policiesJson();
      });
    } catch (error) {
      log.debug("Caught in run(): " + ((error && error.message) || error));
      thrown = error;
    }
    const groups = (view && view.applicationPolicies) || [];
    t.check(!thrown && NAMES.every(function (name) {
      const group = groups.filter(function (one) {
        return one.application === name;
      })[0];
      return !!group && group.known === true &&
        Array.isArray(group.policies) && group.policies.length === 1 &&
        group.policies[0].referenced === true;
    }), 'N2. the repository lists each under its own identifier, one ' +
    'referenced policy each', thrown ? String(thrown.message)
      : JSON.stringify(groups));
    let answer = null;
    thrown = null;
    try {
      answer = realms.run(made.realm, function () {
        return adminViews.xacmlPoliciesView(request());
      });
    } catch (error) {
      log.debug("Caught in run(): " + ((error && error.message) || error));
      thrown = error;
    }
    t.check(!thrown && !!answer &&
            Array.isArray(answer.applicationPolicies) &&
            answer.applicationPolicies.length >= NAMES.length,
            'N3. GET /admin-api/xacml/policies\' view answers, without ' +
            'throwing', thrown ? String(thrown.message)
      : JSON.stringify(answer && answer.applicationPolicies).slice(0, 300));
  } finally {
    realms.remove(id);
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'fga owned policy names',
  describe: 'XACML → Policies groups the applications\' own policies in a ' +
            'table with no prototype, so an application called ' +
            '`constructor` cannot make GET /admin-api/xacml/policies a 500 ' +
            '(fuzz run 14)',
  run: run
};
