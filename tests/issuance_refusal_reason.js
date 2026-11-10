// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/issuance_refusal_reason.js
// ===========================================================================
// AN ISSUANCE DENY NAMES THE RULE KIND THAT MADE IT (2026-11-10).
//
// From 15:11:59 in fuzz run 8 (d96b74093), the fuzz person's console
// session was refused 130 times with "sts-admin-console requires EVERYBODY
// and fuzzer-… holds EVERYBODY, ALL_AUTHENTICATED_USERS, ADMIN_READ, …".
// That is the role sentence, and it named a requirement already met: some
// other rule had denied the session. `XacmlRolePep.reasonFor()` now says so
// when the subject holds a required role, and names the obligations the
// Deny carried.
//
// In process, through the method itself:
//
//   A. a Deny where a required role is held does not print the role
//      sentence: it says another rule refused and names the obligation;
//   B. a Deny of that kind carrying no obligation points at
//      /admin/xacml/decide;
//   C. a Deny where no required role is held still prints the role
//      sentence, unchanged.
// ===========================================================================

const bunyan = require('bunyan');

const log = bunyan.createLogger({
  name: 'issuance_refusal_reason',
  level: process.env.LOG_LEVEL || 'info' });

async function run(t) {
  log.debug("Entering run().");
  delete process.env.CONFIG_FILE;
  const model = require('../xacml/xacml_model');
  const rolePep = require('../xacml/xacml_role_pep');
  const pep = new rolePep.XacmlRolePep(rolePep.XacmlRolePep.defaultDeps());
  const asked = { application: 'sts-admin-console',
                  subject: { name: 'fuzzer-1' } };
  const held = ['EVERYBODY', 'ALL_AUTHENTICATED_USERS', 'ADMIN_WRITE'];

  t.log.info('=== A. a held role and another rule\'s Deny ===');
  const other = pep.reasonFor({ decision: model.DECISION.DENY,
    obligations: [{ id: 'urn:sts:xacml:obligation:example',
                    assignments: [] }] },
  held, ['EVERYBODY'], asked);
  t.check(/a rule other than the role requirement/.test(other) &&
          other.indexOf('urn:sts:xacml:obligation:example') >= 0 &&
          other.indexOf('holds EVERYBODY, ALL_AUTHENTICATED_USERS') < 0,
  'A1. it says another rule refused, names the obligation, and does not ' +
  'list the roles as though they fell short', other);

  t.log.info('=== B. the same with no obligation ===');
  const bare = pep.reasonFor({ decision: model.DECISION.DENY,
                               obligations: [] },
                             held, ['EVERYBODY'], asked);
  t.check(/a rule other than the role requirement/.test(bare) &&
          bare.indexOf('/admin/xacml/decide') >= 0,
  'B1. with no obligation it points at /admin/xacml/decide', bare);

  t.log.info('=== C. a role the subject does not hold ===');
  const role = pep.reasonFor({ decision: model.DECISION.DENY,
                               obligations: [] },
                             ['EVERYBODY'], ['staff'], asked);
  t.equal(role, '"sts-admin-console" requires staff and "fuzzer-1" holds ' +
          'EVERYBODY.', 'C1. the role sentence is unchanged where a ' +
          'required role is missing');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'issuance_refusal_reason',
  describe: 'an issuance Deny where a required role is held says another ' +
            'rule refused, and a role Deny keeps its sentence',
  run: run
};
