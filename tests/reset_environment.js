// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: tests/reset_environment.js
//
// ===========================================================================
// WHAT deploy/aws/reset-environment.js MAY DELETE ON A REUSED ENVIRONMENT
// (#344, 2026-09-29).
//
// The script removes what earlier suite runs left in the default realm of a
// long-lived AWS environment, by NAME. Nothing but a live environment can
// test the deleting, and that costs money and interferes with whoever is
// using it; what CAN be held here is the choice, which is the half that
// would do harm if it were wrong:
//
//   1. every name the bulk-load jobs make — built by `bulk_load.js` itself,
//      for every door, so a change to how those names are made fails here
//      rather than leaving 15,000 entries a run behind again;
//   2. nothing else: the bootstrap administrator, an ordinary person, a
//      person whose name merely starts `bulk-`, a group that is not a bulk
//      group;
//   3. applications: the suite's registrations, and never one this service
//      seeded or one that merely turned up.
//
// Requiring the script runs nothing: it acts only as `require.main`.
// ===========================================================================

const path = require('path');

const log = require('bunyan').createLogger({ name: 'reset_environment',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const reset = require(path.join(ROOT, 'deploy/aws/reset-environment.js'));
const bulk = require(path.join(ROOT, 'tests/vendored/bulk_load.js'));

function bulkNames(t) {
  log.debug("Entering bulkNames().");
  reset.BULK_DOORS.forEach(function (door) {
    const stamp = bulk.stampFor(door);
    const person = bulk.personAt(stamp, 1).username;
    const last = bulk.personAt(stamp, 50000).username;
    const group = bulk.groupNameAt(stamp, 0);
    t.check(reset.isSuitePerson(person) && reset.isSuitePerson(last),
            'a ' + door + ' bulk-load person is the suite\'s', person);
    t.check(!reset.isSuiteGroup(person),
            'and is not taken for a group', person);
    t.check(reset.isSuiteGroup(group),
            'a ' + door + ' bulk-load group is the suite\'s', group);
    t.check(!reset.isSuitePerson(group),
            'and is not taken for a person', group);
  });
  // The LDAP job's bind identity, named outside the run's person prefix.
  const ldap = bulk.stampFor('ldap');
  t.check(reset.isSuitePerson('bulk-' + ldap.door + '-binder-' + ldap.run),
          'the LDAP bulk-load job\'s bind identity is the suite\'s');
  log.debug("Leaving bulkNames().");
}

function nothingElse(t) {
  log.debug("Entering nothingElse().");
  ['admin', 'alice', 'bulk', 'bulk-', 'bulk-loader', 'bulk-hr-2026-000001',
   'Bulk-scim-abc-000001', 'x-bulk-scim-abc-000001', 'bulk-scim-',
   'bulk-scim-abc 000001', 'bulk-scim-abc,ou=x', ''
  ].forEach(function (name) {
    t.check(!reset.isSuitePerson(name), 'person "' + name + '" is left alone');
    t.check(!reset.isSuiteGroup(name), 'group "' + name + '" is left alone');
  });
  ['admins', 'console-administrators', 'bulk-grp-001',
   'bulk-scim-abc-grp-', 'bulk-finance-abc-grp-001'
  ].forEach(function (name) {
    t.check(!reset.isSuiteGroup(name), 'group "' + name + '" is left alone');
  });
  log.debug("Leaving nothingElse().");
}

function applications(t) {
  log.debug("Entering applications().");
  ['sts-admin-console', 'sts-portal', 'sts-management-api'
  ].forEach(function (identifier) {
    t.check(!reset.isSuiteApplication({ identifier: identifier,
                                        registeredBy: 'startup' }),
            'the seeded application ' + identifier + ' is never removed');
  });
  t.check(!reset.isSuiteApplication({ identifier: 'bulk-scim-abc-000001',
                                      registeredBy: '' }),
          'an application that merely turned up is never removed');
  t.check(!reset.isSuiteApplication({ identifier: 'payroll',
                                      registeredBy: 'administrator' }),
          'an operator\'s application is left alone');
  t.check(!reset.isSuiteApplication(null), 'a missing row is left alone');
  log.debug("Leaving applications().");
}

function run(t) {
  log.debug("Entering run().");
  bulkNames(t);
  nothingElse(t);
  applications(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'reset_environment',
  describe: 'deploy/aws/reset-environment.js deletes the suite\'s bulk-load ' +
            'people and groups and its applications, and nothing an ' +
            'operator or this service made',
  run: run
};
