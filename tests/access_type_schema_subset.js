// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: access_type_schema_subset.js
//
// ===========================================================================
// AN RFC 9396 ACCESS TYPE'S SCHEMA IS HELD TO A SUBSET AT THE WRITE, AND ONE
// STORED BEFORE THE RULE KEEPS WORKING (#2220).
//
//   A. `authorizationDetailsTypeOf()` reads a definition outside the subset
//      as USABLE, with the sentence in `schemaProblem`: a combinator, a
//      `not`, a `pattern` of the exponential shape in the schema or in its
//      `limits`, `not`. A definition inside it has none.
//   B. THE WRITE: `authorizationDetailsAttributeProblem()` refuses each of
//      those STS-REG-0374, and does not refuse one the entry already holds;
//      `updateApplication()` refuses an add of one.
//   C. A DEFINITION STORED BEFORE THE RULE (written straight into the
//      directory): it is still declared, a detail of its type is still
//      validated against its schema, and `/admin/mode`'s
//      `access-type-schemas` row lists it.
// ===========================================================================

const applications = require('../common/applications');
const errorCodes = require('../common/error_codes');
const mode = require('../common/mode');

require('../ldap/ldap_server');

const details = require('../oauth-oidc/authorization_details');

const log = require('bunyan').createLogger({
  name: 'access_type_schema_subset',
  level: process.env.LOG_LEVEL || 'info' });

const ATTR = 'oauthAuthorizationDetailsType';

function definition(type, schema, limits) {
  log.debug("Entering definition().");
  const out = { type: type, schema: schema };
  if (limits) {
    out.limits = limits;
  }
  log.debug("Leaving definition().");
  return JSON.stringify(out);
}

const SAFE = definition('ats2220_safe', {
  type: 'object', required: ['ref'],
  properties: { ref: { type: 'string', pattern: '^[A-Z]{2}[0-9]+$' } } });
const COMBINATOR = definition('ats2220_any', {
  anyOf: [{ type: 'object' }, { type: 'string' }] });
const NOT = definition('ats2220_not', { type: 'object',
                                       not: { required: ['x'] } });
const EXPONENTIAL = definition('ats2220_legacy', {
  type: 'object',
  properties: { ref: { type: 'string', pattern: '^(a+)+$' } } });
const LIMITS = definition('ats2220_limits', { type: 'object' },
  { type: 'object', properties: { iban: { type: 'string',
                                          pattern: '(x|xy)*' } } });

function readings(t) {
  log.debug("Entering readings().");
  const of = applications.authorizationDetailsTypeOf;
  const safe = of(SAFE);
  t.check(safe.problem === '' && safe.schemaProblem === '',
          'A: a definition inside the subset reads with no schemaProblem',
          JSON.stringify(safe.schemaProblem));
  [[COMBINATOR, /anyOf/, 'a combinator (anyOf)'],
   [NOT, /"not"/, 'a conditional (not)'],
   [EXPONENTIAL, /schema\.properties\.ref\.pattern.*exponential/,
    'a pattern of the exponential shape'],
   [LIMITS, /limits\.properties\.iban\.pattern/,
    'a limits pattern of the exponential shape']].forEach(function (row) {
    const read = of(row[0]);
    t.check(read.problem === '' && row[1].test(read.schemaProblem),
            'A: ' + row[2] + ' is still USABLE, with the sentence in ' +
            'schemaProblem', JSON.stringify({ problem: read.problem,
                                              schemaProblem:
                                                read.schemaProblem }));
  });
  log.debug("Leaving readings().");
}

function writes(t) {
  log.debug("Entering writes().");
  const attr = applications.authorizationDetailsAttributeProblem;
  [COMBINATOR, NOT, EXPONENTIAL, LIMITS].forEach(function (value, i) {
    const refused = attr(ATTR, value);
    t.check(refused && refused.code === 'STS-REG-0374',
            'B' + i + ': a write of it is refused STS-REG-0374',
            JSON.stringify(refused));
  });
  t.equal(attr(ATTR, SAFE), null, 'B: a definition inside the subset is ' +
          'accepted');
  t.equal(attr(ATTR, EXPONENTIAL, [EXPONENTIAL]), null,
          'B: one the entry already holds is not refused');
  log.debug("Leaving writes().");
}

function stored(t) {
  log.debug("Entering stored().");
  const made = applications.createApplication({ identifier: 'ats2220',
    protocols: ['oauth2'],
    fields: { oauthClientId: 'ats2220',
              oauthPermissionBaseUri: 'https://ats2220.example/',
              oauthAudience: ['https://api.ats2220.example'],
              oauthAuthorizationDetailsType: [SAFE] } });
  if (!t.check(made && made.ok !== false, 'C: precondition: an application ' +
               'declaring a safe type is created', JSON.stringify(made))) {
    log.debug("Leaving stored(). Not created.");
    return;
  }
  const added = applications.updateApplication('ats2220', {
    attribute: ATTR, mode: 'add', value: EXPONENTIAL });
  t.check(!added.ok && errorCodes.codeOf(added) === 'STS-REG-0374',
          'C: the console\'s add of the exponential definition is refused',
          JSON.stringify(added));

  // AS A 1.1 DEPLOYMENT LEFT IT: straight into the directory.
  const directory = applications.directoryInstalled();
  const written = directory.writeApplication('ats2220',
    { oauthAuthorizationDetailsType: [SAFE, EXPONENTIAL] },
    { owned: [ATTR] });
  t.check(!!written, 'C: precondition: the definition is stored as a ' +
          'deployment before #2220 would hold it');
  const declared = details.declaredTypes();
  const legacy = declared.ats2220_legacy;
  t.check(!!legacy && legacy.identifier === 'ats2220',
          'C: the stored definition is still declared',
          JSON.stringify(Object.keys(declared)));
  const accepted = details.conformance({ type: 'ats2220_legacy',
                                         ref: 'aaaa' }, legacy || {}, 'd');
  const refused = details.conformance({ type: 'ats2220_legacy',
                                        ref: 'bbbb' }, legacy || {}, 'd');
  t.check(!accepted.kind && refused.kind === 'definition',
          'C: a detail of its type is still validated against its schema ' +
          '(one matching is accepted, one not matching is refused)',
          JSON.stringify({ accepted: accepted, refused: refused }));
  const row = mode.report().requirements.filter(function (one) {
    return one.id === 'access-type-schemas';
  })[0] || {};
  const waived = (row.waived || []).filter(function (one) {
    return one.setting === 'ats2220: ' + ATTR + ' ats2220_legacy';
  });
  t.check(waived.length === 1 && waived[0].section === 'ASVS 5.0.0 1.3.12',
          '/admin/mode: the access-type-schemas row lists the stored ' +
          'definition', JSON.stringify(row.waived || null));
  t.check(!(row.waived || []).some(function (one) {
    return /ats2220_safe/.test(one.setting);
  }), '/admin/mode: and not the safe one');
  applications.deleteApplication('ats2220');
  log.debug("Leaving stored().");
}

function run(t) {
  log.debug("Entering run().");
  readings(t);
  writes(t);
  stored(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'access_type_schema_subset',
  describe: 'RFC 9396: an access type\'s schema is held to the limits ' +
            'subset and its patterns to a backtracking bound at the write ' +
            '(STS-REG-0374), and one stored before the rule still works and ' +
            'is listed on /admin/mode (#2220)',
  run: run
};
