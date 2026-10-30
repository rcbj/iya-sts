// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/policy_selection.js
//
// ===========================================================================
// THE ONE SELECTION EVERY POLICY KIND SHARES (#1235, rule 3cx).
//
// rcbj's decisions on #1234 (2026-10-30): what a named policy covers names
// it — the application, the person and the group each in one single-valued
// attribute — and a named policy keeps its precedence. The candidates are
// the policy the application names, the policy the person names and the
// policy each of the person's groups names; the lowest precedence wins, ties
// by name, else `default`. What is held:
//
//   A. THE RANKING (`common/policy_selection.ts`, pure): application against
//      group against person on precedence; a tie broken by name; an
//      out-of-range or unreadable precedence ranked at the kind's default;
//      no reference, an empty one and `default` giving `default`; a name the
//      realm does not hold returned in `missing` and never chosen; no
//      entries (no directory) giving `default`; matching trimmed and in any
//      case.
//   B. THE CHECKS: a name, a precedence, a reference against its choices,
//      and the refusal of a delete something still names.
//   C. THE REGISTER of person and group references: declared, read with its
//      choices (`default` first), withdrawn.
//   D. THE DOORS, against the embedded directory: the group index answering
//      a person's groups' references and the groups naming a policy; the
//      group writer refusing an undeclared attribute (STS-LDAP-0194) and a
//      policy the realm does not hold (STS-LDAP-0195); the person editor
//      drawing a declared person reference on its Policies tab with its
//      choices and refusing another value (STS-LDAP-0106); the people naming
//      a policy, from the holders of the attribute; the applications naming
//      one, from the listing's index.
// ===========================================================================

delete process.env.CONFIG_FILE;

const ldap = require('../ldap/ldap_server');
const applications = require('../common/applications');
const errorCodes = require('../common/error_codes');
const personEditor = require('../ldap/person_editor');
const PolicySelection = require('../common/policy_selection');

const log = require('bunyan').createLogger({ name: 'policy_selection',
  level: process.env.LOG_LEVEL || 'info' });

const SPEC = { precedenceAttribute: 'stsTestPrecedence',
               defaultPrecedence: 100 };

/**
 * A named policy's entry as a directory hook answers it.
 *
 * @param name - the policy's name
 * @param precedence - its stored precedence, as a string, or undefined
 * @returns the entry
 */
function entry(name, precedence) {
  log.debug('Entering entry().');
  log.debug('Leaving entry().');
  return { name: name, dn: 'cn=' + name + ',ou=testPolicies',
           attributes: precedence === undefined ? {}
             : { stsTestPrecedence: [String(precedence)] } };
}

function ranking(t) {
  log.debug('Entering ranking().');
  const entries = [entry('default', 1), entry('app-strict', 50),
                   entry('group-admins', 20), entry('person-own', 30),
                   entry('tie-b', 40), entry('tie-a', 40),
                   entry('too-high', 1001), entry('not-a-number', 'x'),
                   entry('zero', 0)];
  const rank = function (refs) {
    return PolicySelection.rank(entries, SPEC, refs);
  };
  const app = { by: 'application', holder: 'web', value: 'app-strict' };
  const person = { by: 'person', holder: 'alice', value: 'person-own' };
  const group = { by: 'group', holder: 'admins', value: 'group-admins' };
  t.check(rank([app]).name === 'app-strict' &&
          rank([app]).by === 'application' &&
          rank([app, person]).name === 'person-own' &&
          rank([app, person, group]).name === 'group-admins' &&
          rank([app, person, group]).by === 'group' &&
          rank([app, person, group]).holder === 'admins' &&
          rank([app, group]).precedence === 20,
          'A1. the application\'s, the person\'s and a group\'s policies ' +
          'compete on precedence alone, the lowest winning, with what named ' +
          'it said');
  t.check(rank([{ by: 'group', value: 'tie-b' },
                { by: 'group', value: 'tie-a' }]).name === 'tie-a' &&
          rank([{ by: 'group', value: 'tie-a' },
                { by: 'group', value: 'tie-b' }]).name === 'tie-a',
          'A2. a tie is broken by name, whichever order they came in');
  const odd = rank([{ by: 'group', value: 'too-high' },
                    { by: 'group', value: 'not-a-number' },
                    { by: 'group', value: 'zero' }]);
  t.check(odd.name === 'not-a-number' && odd.precedence === 100 &&
          PolicySelection.named(entries, SPEC).every(function (one) {
            return one.name !== 'default';
          }) &&
          rank([{ by: 'group', value: 'zero' },
                { by: 'group', value: 'app-strict' }]).name === 'app-strict',
          'A3. a precedence out of 1..1000 or unreadable ranks at the ' +
          'kind\'s default (100), ties then by name; default is never a ' +
          'named policy', JSON.stringify(odd));
  const none = rank([]);
  const blanks = rank([{ by: 'application', value: '' },
                       { by: 'person', value: '  ' },
                       { by: 'group', value: 'DEFAULT' },
                       { by: 'group', value: null }]);
  t.check(none.name === 'default' && none.by === 'default' &&
          none.precedence === 0 && blanks.name === 'default' &&
          blanks.missing.length === 0 && rank(null).name === 'default',
          'A4. no reference, an empty one and `default` give default, and ' +
          'none of them is missing', JSON.stringify(blanks));
  const missing = rank([{ by: 'application', holder: 'web', value: 'gone' },
                        group]);
  t.check(missing.name === 'group-admins' && missing.missing.length === 1 &&
          missing.missing[0].name === 'gone' &&
          missing.missing[0].by === 'application' &&
          missing.missing[0].holder === 'web' &&
          rank([{ by: 'person', value: 'gone' }]).name === 'default',
          'A5. a name the realm does not hold is returned as missing and ' +
          'never chosen', JSON.stringify(missing));
  t.check(PolicySelection.rank(null, SPEC, [app]).name === 'default' &&
          PolicySelection.rank([], SPEC, [app]).missing.length === 1 &&
          PolicySelection.forReference(undefined, SPEC, 'x').applies ===
            'default',
          'A6. no entries — no directory — gives default, the reference ' +
          'then missing');
  t.check(rank([{ by: 'group', value: '  App-STRICT ' }]).name ===
            'app-strict',
          'A7. a reference is matched trimmed and in any case');
  const refs = PolicySelection.groupReferences([
    { cn: 'admins', dn: 'cn=admins', value: 'group-admins' },
    { cn: 'staff', dn: 'cn=staff', value: '' }]);
  const one = PolicySelection.forReference(entries, SPEC, 'APP-strict');
  t.check(refs.length === 1 && refs[0].by === 'group' &&
          refs[0].holder === 'admins' && one.named === 'app-strict' &&
          one.applies === 'app-strict' && one.precedence === 50 &&
          !one.missing &&
          PolicySelection.forReference(entries, SPEC, '').named ===
            'default',
          'A8. a person\'s groups become references, a group naming nothing ' +
          'left out; one holder\'s reference on its own says what it comes ' +
          'to', JSON.stringify([refs, one]));
  log.debug('Leaving ranking().');
}

function checks(t) {
  log.debug('Entering checks().');
  t.check(PolicySelection.nameProblem('admins-2', 'test policy', false) ===
            null &&
          PolicySelection.nameProblem('default', 'test policy', true) ===
            null &&
          !!PolicySelection.nameProblem('default', 'test policy', false) &&
          !!PolicySelection.nameProblem('Admins!', 'test policy', true) &&
          !!PolicySelection.nameProblem('', 'test policy', true),
          'B1. a name is lower-case letters, digits and hyphens; default only ' +
          'where the act takes it');
  const p = function (value) {
    return PolicySelection.checkPrecedence({ precedence: value }, SPEC);
  };
  t.check(p(undefined).precedence === 100 && !p(undefined).problems.length &&
          p('7').precedence === 7 && p(1000).precedence === 1000 &&
          p(0).problems.length === 1 && p(1001).problems.length === 1 &&
          p('1.5').problems.length === 1 && p('x').problems.length === 1 &&
          PolicySelection.MIN_PRECEDENCE === 1 &&
          PolicySelection.MAX_PRECEDENCE === 1000,
          'B2. a precedence is a whole number from 1 to 1000, the kind\'s ' +
          'default when omitted');
  const choices = ['default', 'strict'];
  t.check(PolicySelection.referenceProblem('', choices, 'x') === null &&
          PolicySelection.referenceProblem(' Strict ', choices, 'x') ===
            null &&
          /is neither/.test(PolicySelection.referenceProblem('ghost', choices,
                                                             'x')),
          'B3. a reference is empty, default or a policy the realm holds');
  const refused = PolicySelection.deleteProblem('test policy', 'strict',
    { applications: ['web'], groups: ['admins'], people: [] });
  t.check(PolicySelection.deleteProblem('test policy', 'strict', {}) ===
            null &&
          /web/.test(refused) && /admins/.test(refused),
          'B4. a delete is refused while anything names the policy, and the ' +
          'refusal names it', refused);
  log.debug('Leaving checks().');
}

function register(t) {
  log.debug('Entering register().');
  PolicySelection.declareReference('person', 'stsTestPolicy', 'test policy',
    function () {
      return ['Strict', 'default', 'loose'];
    });
  const read = PolicySelection.referenceOf('person', 'ststestpolicy');
  let thrown = false;
  try {
    PolicySelection.declareReference('device', 'x', 'y', function () {
      return [];
    });
  } catch (e) {
    log.debug('Caught in register(): ' + ((e && e.message) || e));
    thrown = true;
  }
  t.check(!!read && JSON.stringify(read.choices) ===
            '["default","strict","loose"]' &&
          PolicySelection.referenceOf('group', 'stsTestPolicy') === null &&
          thrown,
          'C1. a declared reference is read in any case, `default` first, ' +
          'on its own holder only; an unknown holder is refused',
          JSON.stringify(read));
  PolicySelection.withdrawReference('person', 'stsTestPolicy');
  t.check(PolicySelection.referenceOf('person', 'stsTestPolicy') === null,
          'C2. a withdrawn reference is gone');
  log.debug('Leaving register().');
}

async function doors(t) {
  log.debug('Entering doors().');
  const tag = 'psel' + process.pid;
  const group = tag + '-group';
  const other = tag + '-other';
  const member = tag + '-member';
  ldap.createUser(member, { invent: false });
  ldap.createGroup(group);
  ldap.createGroup(other);
  ldap.addGroupMember(group, member);
  ldap.addGroupMember(other, member);
  // A KIND THAT A PERSON AND A GROUP SELECT, declared for this test:
  // `employeeType` on the person, which the schema already gives a person,
  // and the attribute policy's group spelling on the group.
  PolicySelection.declareReference('person', 'employeeType', 'test policy',
    function () {
      return ['strict'];
    });
  PolicySelection.declareReference('group', 'stsAttributePolicy',
    'test policy', function () {
      return ['strict', 'loose'];
    });
  try {
    const named = ldap.setGroupPolicy(group, 'stsAttributePolicy', 'Strict');
    const again = ldap.setGroupPolicy(group, 'stsAttributePolicy', 'strict');
    const ghost = ldap.setGroupPolicy(group, 'stsAttributePolicy', 'gone');
    const undeclared = ldap.setGroupPolicy(group, 'stsPostLoginPolicy',
                                           'strict');
    t.check(named.ok && named.changed && !again.changed &&
            !ghost.ok && errorCodes.codeOf(ghost) === 'STS-LDAP-0195' &&
            !undeclared.ok &&
            errorCodes.codeOf(undeclared) === 'STS-LDAP-0194',
            'D1. a group names a declared policy, idempotently; a policy the ' +
            'realm does not hold and an undeclared attribute are refused',
            JSON.stringify([named, ghost.errors, undeclared.errors]));
    const refs = ldap.personGroupReferences(member, 'stsAttributePolicy');
    const mine = refs.filter(function (one) {
      return one.cn === group;
    })[0];
    const theirs = refs.filter(function (one) {
      return one.cn === other;
    })[0];
    t.check(!!mine && mine.value === 'strict' && !!theirs &&
            theirs.value === '' &&
            JSON.stringify(ldap.groupsNamingPolicy('stsAttributePolicy',
                                                   'STRICT')) ===
              JSON.stringify([group]),
            'D2. the group index answers the policy each of a person\'s ' +
            'groups names, and the groups naming a policy',
            JSON.stringify(refs));
    ldap.setGroupPolicy(group, 'stsAttributePolicy', '');
    t.check(ldap.groupsNamingPolicy('stsAttributePolicy', 'strict')
      .length === 0,
            'D3. cleared, the group names nothing');
    const editor = personEditor.editorFor(member);
    const row = editor.attributes.filter(function (one) {
      return one.name.toLowerCase() === 'employeetype';
    })[0];
    t.check(!!row && row.group === 'policies' && row.multi === false &&
            JSON.stringify(row.choices) === '["default","strict"]',
            'D4. a declared person reference is drawn on the Policies tab, ' +
            'one value from its choices', JSON.stringify(row));
    // An attribute in neither the schema's list nor the catalogue — a
    // kind's own, as `stsServiceAccountPolicy` will be — is put on the tab
    // by its declaration alone.
    PolicySelection.declareReference('person', 'stsTestOnlyPolicy',
      'test policy', function () {
        return ['loose'];
      });
    const own = personEditor.editorFor(member).attributes
      .filter(function (one) {
        return one.name === 'stsTestOnlyPolicy';
      })[0];
    PolicySelection.withdrawReference('person', 'stsTestOnlyPolicy');
    t.check(!!own && own.group === 'policies' &&
            JSON.stringify(own.choices) === '["default","loose"]' &&
            !personEditor.editorFor(member).attributes.some(function (one) {
              return one.name === 'stsTestOnlyPolicy';
            }),
            'D4b. a declared attribute the schema does not list is drawn ' +
            'there too, and gone once withdrawn', JSON.stringify(own));
    const set = personEditor.update(member, { attribute: 'employeeType',
                                              mode: 'set', value: 'strict' });
    const bad = personEditor.update(member, { attribute: 'employeeType',
                                              mode: 'set', value: 'gone' });
    t.check(set.ok && !bad.ok && errorCodes.codeOf(bad) === 'STS-LDAP-0106',
            'D5. the person editor writes a policy the realm holds and ' +
            'refuses another', JSON.stringify([set.errors, bad.errors]));
    const people = await ldap.peopleNamingPolicyAsync('employeeType',
                                                      ' Strict ', 10);
    t.check(people.complete === true &&
            people.people.indexOf(member) >= 0,
            'D6. the people naming a policy, from the holders of the ' +
            'attribute', JSON.stringify(people));
    applications.createApplication({ identifier: tag + '-app', protocols: [],
                                     fields: {} });
    t.check(JSON.stringify(applications.applicationsNamingPolicy(
      'appPasskeyPolicy', 'x')) === '[]' &&
            JSON.stringify(applications.applicationsNamingPolicy(
              'notAReference', 'x')) === '[]' &&
            applications.POLICY_REFERENCES.indexOf('appPasskeyPolicy') >= 0,
            'D7. the applications naming a policy come from the listing\'s ' +
            'index, and only for a reference attribute');
  } finally {
    PolicySelection.withdrawReference('person', 'employeeType');
    PolicySelection.withdrawReference('group', 'stsAttributePolicy');
  }
  log.debug('Leaving doors().');
}

async function run(t) {
  log.debug('Entering run().');
  ranking(t);
  checks(t);
  register(t);
  await doors(t);
  log.debug('Leaving run().');
}

module.exports = {
  name: 'policy_selection',
  describe: 'The one selection every policy kind shares: application, ' +
            'person and group references ranked by precedence, the checks, ' +
            'the register and the doors (#1235)',
  run: run
};
