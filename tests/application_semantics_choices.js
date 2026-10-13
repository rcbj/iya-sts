// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/application_semantics_choices.js
//
// ---------------------------------------------------------------------------
// THE DELEGATION SEMANTICS ARE OFFERED AS THEIR TWO VALUES (2026-10-06).
//
// `appDelegationSemantics` (a list) and `appDefaultDelegationSemantics` (one
// value) each take `delegation` or `impersonation` and nothing else, and the
// Configuration tab drew both as free text boxes. They are choices now
// (`applications.js`'s ATTRIBUTE_CHOICES): a checkbox per value for the
// list, a choice of one — with "not set" — for the default. What is held:
//
//   1. both fields carry the two values as their choices;
//   2. on the application's page the list is a list from a closed set and the
//      default is typed `enum`, which is what draws the checkboxes and the
//      radio buttons (`WebKit.fieldGridCell()`);
//   3. a value outside the two is still refused at the write.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const applications = require('../common/applications');
require('../ldap/ldap_server');
const adminActions = require('../admin-core/admin_actions');
const adminViews = require('../admin-core/admin_views');

const log = require('bunyan').createLogger({
  name: 'application_semantics_choices',
  level: process.env.LOG_LEVEL || 'info' });

const ID = 'semantics-choices-' + process.pid;
const BOTH = '["delegation","impersonation"]';

function run(t) {
  log.debug("Entering run().");

  // --- 1. The choices ----------------------------------------------------
  const rows = applications.applicationFields();
  const rowOf = function (name) {
    log.debug("Entering rowOf().");
    log.debug("Leaving rowOf().");
    return rows.filter(function (one) { return one.attribute === name; })[0];
  };
  const list = rowOf('appDelegationSemantics');
  const single = rowOf('appDefaultDelegationSemantics');
  t.check(list && JSON.stringify(list.choices) === BOTH &&
          single && JSON.stringify(single.choices) === BOTH,
          '1. both fields offer delegation and impersonation as choices',
          JSON.stringify({ list: list && list.choices,
                           single: single && single.choices }));

  // --- 2. As the page draws them -----------------------------------------
  adminActions.applicationsAction({ action: 'create', identifier: ID }, []);
  const req = { query: {}, headers: { host: 'localhost:8081' },
                protocol: 'https', get: function () { return ''; } };
  const detail = adminViews.applicationDetailJson(req, ID);
  const fields = detail && detail.json && detail.json.page
    ? detail.json.page.config.fields : [];
  const typed = function (name) {
    log.debug("Entering typed().");
    log.debug("Leaving typed().");
    return fields.filter(function (one) { return one.attribute === name; })[0];
  };
  const pageList = typed('appDelegationSemantics');
  const pageSingle = typed('appDefaultDelegationSemantics');
  t.check(pageList && pageList.type === 'array' &&
          (pageList.choices || []).length === 2 &&
          pageSingle && pageSingle.type === 'enum',
          '2. on the page the list is a checkbox per value and the default ' +
          'a choice of one',
          JSON.stringify({ list: pageList && pageList.type,
                           single: pageSingle && pageSingle.type }));

  // --- 3. Still refused outside the two ----------------------------------
  const bad = adminActions.applicationsAction({ action: 'set',
    application: ID, attribute: 'appDefaultDelegationSemantics',
    value: 'proxying' });
  t.check(bad && bad.ok === false,
          '3. a value outside the two is refused at the write',
          JSON.stringify(bad && bad.errors));
  const good = adminActions.applicationsAction({ action: 'add',
    application: ID, attribute: 'appDelegationSemantics',
    value: 'impersonation' });
  t.check(good && good.ok === true,
          '3. and one of them is taken',
          JSON.stringify(good && (good.errors || good.ok)));

  adminActions.applicationsAction({ action: 'forget', application: ID });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'application semantics choices',
  describe: 'appDelegationSemantics and appDefaultDelegationSemantics ' +
            'offered as their two values on the Configuration tab',
  run: run
};
