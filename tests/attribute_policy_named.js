// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/attribute_policy_named.js
//
// ===========================================================================
// NAMED ATTRIBUTE POLICIES, NAMED BY THE PERSON AND BY THEIR GROUPS (#1241,
// part of #1234; rule 3cx).
//
// A realm keeps named attribute profiles beside `cn=default`, each a
// required list and a precedence; a person names one through
// `stsAttributePolicy` on their own entry, and a group through the same
// attribute; the lowest precedence of those named applies, else `default`.
// In a product realm and a development realm this file makes, and in the
// default realm for the LDAP socket, with everything it made removed:
//
//   A. Named profiles: saved with a precedence, listed after `default` in
//      precedence order, read as the realm's own and not another realm's; a
//      precedence out of range refused (STS-LDAP-0166).
//   B. THE PERSON'S REFERENCE at a real create door (`createUser()`, the
//      console's and the API's): a newcomer naming a profile is held to
//      its list (STS-LDAP-0162) and created once it is met; a reference to
//      a profile the realm does not hold is refused at the write
//      (STS-LDAP-0106).
//   C. THE GROUP'S REFERENCE at a real edit door (the person editor): a
//      member of a group naming a profile may not lose a value it requires
//      (STS-LDAP-0164), where a non-member may; the editor's required flags
//      follow the person; a group the create adds (`subject.groups`) is
//      read; the lowest precedence wins between the person's and the
//      group's.
//   D. A REFERENCE NO PROFILE ANSWERS selects nothing: `default` applies.
//   E. THE COUNT of people missing a required attribute judges each person
//      against their own profile (development realm, where nothing is
//      refused at the door).
//   F. A NAMED PROFILE SOMETHING NAMES IS NOT DELETED (STS-LDAP-0197): a
//      group, then a person, through the policies action; the API's
//      asynchronous view lists the people; deleted once nobody names it.
//      A custom attribute a named profile requires is not removed (0173).
//   G. The LDAP socket in product mode: an add naming a profile is held to
//      it (objectClassViolation, STS-LDAP-0162).
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const realms = require('../common/realms');
const errorCodes = require('../common/error_codes');
const audit = require('../common/audit');
const attributePolicy = require('../common/attribute_policy');
const ldap = require('../ldap/ldap_server');
const personEditor = require('../ldap/person_editor');
const adminRbac = require('../admin-ui/admin_rbac');
const adminViews = require('../admin-core/admin_views');
const adminActions = require('../admin-core/admin_actions');

const log = require('bunyan').createLogger({ name: 'attribute_policy_named',
  level: process.env.LOG_LEVEL || 'info' });

function inRealm(realm, fn) {
  log.debug('Entering inRealm().');
  log.debug('Leaving inRealm().');
  return realms.run(realm, fn);
}

function codeOf(result) {
  log.debug('Entering codeOf().');
  log.debug('Leaving codeOf().');
  return errorCodes.codeOf(result) || '';
}

// What every person here is asked for by default.
function full(given, sur) {
  log.debug('Entering full().');
  log.debug('Leaving full().');
  return { givenName: given, sn: sur,
           mail: given.toLowerCase() + '@attrn.example.test' };
}

async function run(t) {
  log.debug('Entering run().');
  const tag = require('crypto').randomBytes(3).toString('hex');
  const product = realms.create({ id: 'attrnp-' + tag, name: 'attrnp-' + tag,
                                  description: 'Created by ' + __filename,
                                  overrides: { 'global.mode': 'product' } });
  const dev = realms.create({ id: 'attrnd-' + tag, name: 'attrnd-' + tag,
                              description: 'Created by ' + __filename });
  // THE REALMS GO IN A finally: this file shares one process with every
  // other in-process test.
  try {
    t.check(product.ok !== false && dev.ok !== false, 'two realms were made',
            JSON.stringify([product.errors, dev.errors]));
    await inRealm(product.realm, function () {
      return productChecks(t, tag);
    });
    await inRealm(dev.realm, function () {
      return counted(t, tag);
    });
    await socket(t, tag);
  } finally {
    realms.remove(product.realm ? product.realm.id : 'attrnp-' + tag);
    realms.remove(dev.realm ? dev.realm.id : 'attrnd-' + tag);
  }
  log.debug('Leaving run().');
}

async function productChecks(t, tag) {
  log.debug('Entering productChecks().');
  // A.
  const contractors = attributePolicy.save('contractors',
    { requiredAttributes: ['givenName', 'mail', 'telephoneNumber'],
      precedence: 50 });
  const strict = attributePolicy.save('strict',
    { requiredAttributes: ['givenName', 'mail', 'title'], precedence: 10 });
  const badPrecedence = attributePolicy.save('loose',
    { requiredAttributes: [], precedence: 5000 });
  const names = attributePolicy.list().map(function (one) {
    return one.name + ':' + one.precedence;
  });
  t.check(contractors.ok && strict.ok &&
          contractors.profile.name === 'contractors' &&
          contractors.profile.required.indexOf('telephoneNumber') >= 0 &&
          JSON.stringify(names) ===
            '["default:0","strict:10","contractors:50"]' &&
          !badPrecedence.ok && codeOf(badPrecedence) === 'STS-LDAP-0166',
          'A. named profiles are saved with a precedence and listed after ' +
          'default in precedence order; a precedence out of range is ' +
          'refused (STS-LDAP-0166)',
          JSON.stringify([names, badPrecedence.errors]));
  t.check(realms.run(realms.DEFAULT_REALM, function () {
    return attributePolicy.read('contractors').name === 'default';
  }), 'A. a named profile is the realm\'s own: the default realm reads ' +
       'default for its name');

  // B.
  const lacking = ldap.createUser('np-lack-' + tag, { invent: false,
    attributes: Object.assign(full('Lacking', 'Person'),
                              { stsAttributePolicy: 'contractors' }) });
  const whole = ldap.createUser('np-whole-' + tag, { invent: false,
    attributes: Object.assign(full('Whole', 'Person'),
                              { stsAttributePolicy: 'Contractors',
                                telephoneNumber: '+1 555 0100' }) });
  const ghost = ldap.createUser('np-ghost-' + tag, { invent: false,
    attributes: Object.assign(full('Ghost', 'Person'),
                              { stsAttributePolicy: 'gone' }) });
  const plain = ldap.createUser('np-plain-' + tag, { invent: false,
    attributes: full('Plain', 'Person') });
  t.check(!lacking.ok && codeOf(lacking) === 'STS-LDAP-0162' &&
          JSON.stringify(lacking.missing) === '["telephoneNumber"]' &&
          /"contractors"/.test(lacking.errors[0]) &&
          whole.ok && plain.ok &&
          !ghost.ok && codeOf(ghost) === 'STS-LDAP-0106',
          'B. a newcomer naming a profile is held to its list at the ' +
          'create (0162) and made once it is met; a person naming none is ' +
          'held to default; a profile the realm does not hold is refused ' +
          'at the write (0106)',
          JSON.stringify([lacking.errors, whole.errors, ghost.errors]));

  // C.
  const group = 'np-group-' + tag;
  const member = 'np-member-' + tag;
  const outsider = 'np-outsider-' + tag;
  [member, outsider].forEach(function (name) {
    ldap.createUser(name, { invent: false,
      attributes: Object.assign(full('Titled', name),
                                { title: 'Engineer' }) });
  });
  ldap.createGroup(group);
  ldap.addGroupMember(group, member);
  const named = ldap.setGroupPolicy(group, 'stsAttributePolicy', 'strict');
  const flags = function (who) {
    log.debug('Entering flags().');
    log.debug('Leaving flags().');
    return personEditor.editorFor(who).attributes.filter(function (row) {
      return row.name === 'title';
    })[0].required;
  };
  const memberFlag = flags(member);
  const outsiderFlag = flags(outsider);
  const kept = personEditor.update(member, { attribute: 'title',
                                             mode: 'set', value: '' });
  const dropped = personEditor.update(outsider, { attribute: 'title',
                                                  mode: 'set', value: '' });
  t.check(named.ok && memberFlag === true && outsiderFlag === false &&
          !kept.ok && codeOf(kept) === 'STS-LDAP-0164' &&
          /"strict"/.test(kept.errors[0]) && dropped.ok,
          'C. a member of a group naming a profile may not lose a value it ' +
          'requires (0164), and its editor marks the row required; a ' +
          'non-member may',
          JSON.stringify([named.errors, kept.errors, dropped.errors]));
  const added = attributePolicy.createRefusal(
    Object.assign({ uid: ['np-added-' + tag] }, full('Added', 'Person')),
    { uid: 'np-added-' + tag, groups: [group] });
  t.check(!!added && added.policy === 'strict' &&
          JSON.stringify(added.missing) === '["title"]',
          'C. a group the same write adds is read at the create',
          JSON.stringify(added));
  // The member names `contractors` (50) too; the group's `strict` (10)
  // wins.
  const both = personEditor.update(member, { attribute: 'stsAttributePolicy',
                                             mode: 'set',
                                             value: 'contractors' });
  const chosen = attributePolicy.selectionFor({ uid: member,
    attributes: ldap.objectFor(member).entry.attributes });
  t.check(both.ok && chosen.name === 'strict' && chosen.by === 'group',
          'C. between the person\'s reference and their group\'s, the lowest ' +
          'precedence wins', JSON.stringify([both.errors, chosen]));

  // D.
  const dangling = attributePolicy.selectionFor({ uid: 'np-nobody-' + tag,
    attributes: { stsAttributePolicy: 'gone' } });
  t.check(dangling.name === 'default' && dangling.missing.length === 1 &&
          dangling.missing[0].name === 'gone',
          'D. a reference no profile answers selects nothing, and default ' +
          'applies', JSON.stringify(dangling));

  // F.
  const groupHeld = await adminActions.policiesAction(
    { action: 'reset-attributes-policy', profile: 'strict' },
    { via: 'api', actor: 'attribute_policy_named' });
  ldap.setGroupPolicy(group, 'stsAttributePolicy', '');
  const personHeld = await adminActions.policiesAction(
    { action: 'reset-attributes-policy', profile: 'contractors' },
    { via: 'api', actor: 'attribute_policy_named' });
  const view = await adminViews.policiesViewAsync({});
  const row = view.attributes.named.filter(function (one) {
    return one.name === 'contractors';
  })[0];
  t.check(!groupHeld.ok && codeOf(groupHeld) === 'STS-LDAP-0197' &&
          new RegExp(group).test(groupHeld.errors[0]) &&
          !personHeld.ok && codeOf(personHeld) === 'STS-LDAP-0197' &&
          !!row && row.namedBy.people.indexOf(member) >= 0 &&
          row.namedBy.people.indexOf('np-whole-' + tag) >= 0,
          'F. a named profile a group or a person names is not deleted ' +
          '(0197), and the API\'s view lists the people naming it',
          JSON.stringify([groupHeld.errors, personHeld.errors,
                          row && row.namedBy]));
  const defined = attributePolicy.define({ name: 'npBadge' + tag,
                                          label: 'Badge' });
  attributePolicy.save('strict', { requiredAttributes: ['npBadge' + tag],
                                   precedence: 10 });
  const required = attributePolicy.undefine('npBadge' + tag);
  attributePolicy.save('strict', { requiredAttributes: ['title'],
                                   precedence: 10 });
  const free = attributePolicy.undefine('npBadge' + tag);
  t.check(defined.ok && !required.ok &&
          codeOf(required) === 'STS-LDAP-0173' && free.ok,
          'F. a custom attribute a named profile requires is not removed ' +
          '(0173), and is once none does',
          JSON.stringify([defined.errors, required.errors, free.errors]));
  const gone = await attributePolicy.reset('strict');
  t.check(gone.ok && gone.removed === true &&
          attributePolicy.list().length === 2,
          'F. a named profile nobody names is deleted',
          JSON.stringify(gone.errors));
  log.debug('Leaving productChecks().');
}

// E. The count, in development mode, where a person lacking what their
// profile requires can be made.
function counted(t, tag) {
  log.debug('Entering counted().');
  const before = attributePolicy.peopleMissing();
  attributePolicy.save('phones', { requiredAttributes: ['telephoneNumber'],
                                   precedence: 20 });
  const group = 'nc-group-' + tag;
  ldap.createGroup(group);
  ldap.setGroupPolicy(group, 'stsAttributePolicy', 'phones');
  // Complete under default, each; the first two lack a telephone number.
  ldap.createUser('nc-own-' + tag, { invent: false,
    attributes: Object.assign(full('Own', 'Ref'),
                              { stsAttributePolicy: 'phones' }) });
  ldap.createUser('nc-grouped-' + tag, { invent: false,
    attributes: full('Grouped', 'Ref') });
  ldap.addGroupMember(group, 'nc-grouped-' + tag);
  ldap.createUser('nc-default-' + tag, { invent: false,
    attributes: full('Default', 'Ref') });
  const after = attributePolicy.peopleMissing();
  t.check(typeof before === 'number' && after === before + 2 &&
          attributePolicy.enforced() === false,
          'E. the count judges each person against their own profile: ' +
          'the one naming it and the group\'s member are counted, the one ' +
          'under default is not; development mode refuses nobody',
          JSON.stringify([before, after]));
  log.debug('Leaving counted().');
}

// G. The socket, in the default realm, with a named profile of its own for
// the length of the check.
function socket(t, tag) {
  log.debug('Entering socket().');
  const admin = 'attrn-admin-' + tag;
  let granted = false;
  const newDn = 'uid=attrn-ldap-' + tag + ',' + ldap.usersDn();
  try {
    ldap.createUser(admin, { invent: false,
                             attributes: full('Admin', admin) });
    const grant = adminRbac.grant(admin, 'write', { via: 'test' });
    granted = !!grant && grant.ok !== false;
    attributePolicy.save('socketprobe',
      { requiredAttributes: ['givenName', 'mail', 'title'], precedence: 30 });
    config.setOverride('global.mode', 'product');
    try {
      const adminDn = ldap.objectFor(admin).entry.dn;
      const add = function (extra) {
        log.debug('Entering add().');
        log.debug('Leaving add().');
        return ldap.performOperation('add', {
          dn: newDn, boundDn: adminDn, channel: 'ldaps',
          attributes: Object.entries(Object.assign({
            objectClass: ['top', 'person', 'organizationalPerson',
                          'inetOrgPerson'],
            uid: 'attrn-ldap-' + tag, cn: 'Ann Probe', sn: 'Probe',
            givenName: 'Ann', mail: 'ann@attrn.example.test',
            stsAttributePolicy: 'socketprobe' }, extra))
            .map(function (pair) {
              return { type: pair[0], values: [].concat(pair[1]) };
            })
        });
      };
      const partial = add({});
      const row = audit.list().filter(function (event) {
        return event.target === newDn && event.errorCode;
      })[0];
      const whole = add({ title: 'Probe' });
      t.check(partial.ok === false &&
              partial.errorName === 'ObjectclassViolationError' &&
              !!row && row.errorCode === 'STS-LDAP-0162' &&
              whole.ok === true,
              'G. an LDAP add naming a profile is held to it ' +
              '(objectClassViolation, STS-LDAP-0162), and succeeds with ' +
              'what it requires', JSON.stringify([partial, whole]));
    } finally {
      config.clearOverride('global.mode');
    }
  } finally {
    if (granted) {
      adminRbac.revoke(admin, 'write', { via: 'test' });
    }
    [newDn].concat([admin].map(function (name) {
      const found = ldap.objectFor(name);
      return found && found.entry ? found.entry.dn : '';
    })).filter(Boolean).forEach(function (dn) {
      ldap.performOperation('del', { dn: dn, boundDn: '', channel: 'ldaps' });
    });
  }
  // Deleted after the people naming it are gone.
  return Promise.resolve(attributePolicy.reset('socketprobe'));
}

module.exports = {
  name: 'attribute_policy_named',
  describe: 'named attribute policies, selected by the person\'s and their ' +
            'groups\' stsAttributePolicy at the create and edit doors, the ' +
            'count, and the delete refused while named (#1241)',
  run: run
};
