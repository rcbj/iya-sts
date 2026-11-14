// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/application_description.js
//
// ---------------------------------------------------------------------------
// AN APPLICATION'S `description` IS ONE VALUE (#456).
//
// The Configuration tab's *Every protocol* sub-tab drew it as a list — a box
// per value, + to add one and a bin to delete one. It is one text box now,
// and single-valued end to end rather than only on the form, so nothing
// behind the box can turn it back into a list.
//
// What is held here, through the functions the console's forms post to
// (`adminActions.applicationsAction()`):
//
//   1. THE FIELD: `string` (one box), set rather than added to.
//   2. A CREATE keeps the description typed, and the registry's own note
//      (created from the console) does not join it.
//   3. A CREATE with none gets the registry's note as its one value.
//   4. THE GRID'S SAVE sets it, replacing rather than adding; an emptied box
//      clears it; and two values are refused.
//   5. The `add` action — the old list's + — is refused for it.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const applications = require('../common/applications');
require('../ldap/ldap_server');
const adminActions = require('../admin-core/admin_actions');

const log = require('bunyan').createLogger({ name: 'application_description',
  level: process.env.LOG_LEVEL || 'info' });

const ID = 'description-app-' + process.pid;

function save(value) {
  log.debug("Entering save().");
  const out = adminActions.applicationsAction({
    action: 'update-fields', application: ID, group: 'every',
    present: 'description', 'field.description': value });
  log.debug("Leaving save().");
  return out;
}

function run(t) {
  log.debug("Entering run().");

  // --- 1. The field ------------------------------------------------------
  const field = applications.applicationFields().filter(function (one) {
    return one.attribute === 'description';
  })[0];
  t.check(field && field.type === 'string' && field.editable === 'set' &&
          field.everyFamily === true,
          '1. description is ONE box on the Every protocol sub-tab, set ' +
          'rather than added to',
          JSON.stringify(field && { type: field.type,
                                    editable: field.editable,
                                    every: field.everyFamily }));

  // --- 2. A create keeps what was typed ----------------------------------
  const created = adminActions.applicationsAction({
    action: 'create', identifier: ID,
    'field.description': 'The payroll front end' }, []);
  const made = applications.get(ID);
  t.check(created && created.ok === true && made &&
          made.description === 'The payroll front end' &&
          made.fields.description === 'The payroll front end',
          '2. a create keeps the description typed, as its one value, and ' +
          'the registry\'s own note does not join it',
          JSON.stringify(made && { top: made.description,
                                   field: made.fields.description }));

  // --- 3. A create with none gets the note -------------------------------
  const BARE = ID + '-bare';
  adminActions.applicationsAction({ action: 'create', identifier: BARE }, []);
  const bare = applications.get(BARE);
  t.check(bare && typeof bare.description === 'string' &&
          /created from the console/.test(bare.description),
          '3. a create with no description gets the registry\'s note as its ' +
          'one value', JSON.stringify(bare && bare.description));

  // --- 4. The grid's save ------------------------------------------------
  const set = save('Payroll, renamed');
  t.check(set && set.ok === true &&
          applications.get(ID).description === 'Payroll, renamed',
          '4a. Save sets it, replacing the old value rather than adding one',
          JSON.stringify(set && (set.errors || applications.get(ID)
                                                .description)));
  const two = adminActions.applicationsAction({
    action: 'update-fields', application: ID, group: 'every',
    present: 'description', 'field.description.0': 'one',
    'field.description.1': 'two' });
  t.check(two && two.ok === false &&
          applications.get(ID).description === 'Payroll, renamed',
          '4b. two values are refused, and the one held is kept',
          JSON.stringify(two && two.errors));
  const cleared = save('');
  t.check(cleared && cleared.ok === true &&
          !applications.get(ID).description &&
          applications.get(ID).fields.description === undefined,
          '4c. an emptied box clears it',
          JSON.stringify(cleared && (cleared.errors || cleared.ok)));

  // --- 5. No + -----------------------------------------------------------
  const added = adminActions.applicationsAction({
    action: 'add', application: ID, attribute: 'description',
    value: 'a second line' });
  t.check(added && added.ok === false && !applications.get(ID).description,
          '5. the add action — the old list\'s + — is refused for it',
          JSON.stringify(added && added.errors));

  adminActions.applicationsAction({ action: 'forget', application: ID });
  adminActions.applicationsAction({ action: 'forget', application: BARE });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'application description',
  describe: 'an application\'s description is one value: one box on the ' +
            'Configuration tab, set and cleared, never a list (#456)',
  run: run
};
