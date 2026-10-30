// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: attribute_policy.js
//
// ===========================================================================
// THE ATTRIBUTE POLICY AND THE CUSTOM ATTRIBUTE REGISTER (#396, 2026-10-19).
//
// rcbj: "Minimum user attributes that must be populated for a new user
// object. Default: first name, sn, email. Add a policy that defines what the
// required fields must be for a realm", and a page with "a list of all
// attributes, custom attributes, ability to add a new attribute, and require
// each individual attribute as needed". In two realms this test creates — one
// in product mode, one in development — and in the default realm for the
// LDAP socket, with the policy left as it found it:
//
//   A. The built-in default: uid, cn and sn always, givenName and mail; the
//      catalogue offers every attribute a person may be given, and neither
//      userPassword, memberOf nor an sts attribute.
//   B. A save replaces the list; a name nobody may be given, a profile name
//      a cn cannot be and a save without the field are refused under
//      their codes; a console form that ticks nothing saves an empty list;
//      a reset goes back to the built-in default.
//   C. Custom attributes: defined with a label, a syntax and a cardinality;
//      a bad name, an sts name, a known name and a second definition are
//      refused; the person editor offers it under Custom and checks its
//      values against its syntax; another realm does not see it.
//   D. Product mode: a create missing a required attribute is refused
//      (STS-LDAP-0162) naming what is missing, before anything is written;
//      a cn is made of the given name and surname; a required custom
//      attribute is asked for too; the bootstrap administrator is exempt.
//   E. An edit that would take a required value away is refused
//      (STS-LDAP-0164); one of an attribute nothing requires is not; a
//      person who never held a required attribute may still be edited.
//   F. A custom attribute is not removed while the profile requires it
//      (0173) or a person holds a value (0172), and is once neither holds.
//   G. Development mode enforces nothing, and says so.
//   H. The LDAP socket, in the default realm in product mode: an add
//      missing a required attribute and a modify taking one away are
//      objectClassViolation (65) under 0162 and 0164.
//   I. The policies view and the API's action rows carry the kind, its
//      two acts and the catalogue.
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
const policyKinds = require('../admin-core/policy_kinds');
const adminViews = require('../admin-core/admin_views');
const adminActions = require('../admin-core/admin_actions');

const log = require('bunyan').createLogger({ name: 'attribute_policy',
  level: process.env.LOG_LEVEL || 'info' });

function inRealm(realm, fn) {
  log.debug('Entering inRealm().');
  log.debug('Leaving inRealm().');
  return realms.run(realm, fn);
}

function withSettings(pairs, fn) {
  log.debug('Entering withSettings().');
  const keys = Object.keys(pairs);
  try {
    keys.forEach(function (key) {
      config.setOverride(key, String(pairs[key]));
    });
    log.debug('Leaving withSettings().');
    return fn();
  } finally {
    keys.forEach(function (key) {
      config.clearOverride(key);
    });
  }
}

// An attribute off the entry, whichever case the store handed it back in.
function attributeOf(name, attribute) {
  log.debug('Entering attributeOf().');
  const view = ldap.objectFor(name);
  const attributes = (view && view.entry && view.entry.attributes) || {};
  const key = Object.keys(attributes).filter(function (one) {
    return one.toLowerCase() === attribute.toLowerCase();
  })[0];
  log.debug('Leaving attributeOf().');
  return key ? [].concat(attributes[key]).map(String) : [];
}

function codeOf(result) {
  log.debug('Entering codeOf().');
  log.debug('Leaving codeOf().');
  return errorCodes.codeOf(result) || '';
}

// The code on the most recent refusal naming this target: the socket's code
// never reaches the client, so the audit row is where it is read back.
function lastCodeFor(target) {
  log.debug('Entering lastCodeFor().');
  const row = audit.list().filter(function (event) {
    return event.target === target && event.errorCode;
  })[0];
  log.debug('Leaving lastCodeFor().');
  return row ? row.errorCode : '';
}

function ldapAdd(boundDn, dn, attributes) {
  log.debug('Entering ldapAdd().');
  log.debug('Leaving ldapAdd().');
  return ldap.performOperation('add', {
    dn: dn, boundDn: boundDn, channel: 'ldaps',
    attributes: Object.keys(attributes).map(function (type) {
      return { type: type, values: [].concat(attributes[type]) };
    })
  });
}

function ldapModify(boundDn, dn, changes) {
  log.debug('Entering ldapModify().');
  log.debug('Leaving ldapModify().');
  return ldap.performOperation('modify', {
    dn: dn, boundDn: boundDn, channel: 'ldaps',
    changes: changes.map(function (one) {
      return { operation: one[0],
               modification: { type: one[1], values: one.slice(2) } };
    })
  });
}

// The three a person here is asked for by default, from a given name and a
// surname.
function full(given, sur) {
  log.debug('Entering full().');
  log.debug('Leaving full().');
  return { givenName: given, sn: sur,
           mail: given.toLowerCase() + '@attrp.example.test' };
}

async function run(t) {
  log.debug('Entering run().');
  const tag = require('crypto').randomBytes(3).toString('hex');
  const product = realms.create({ id: 'attrp-' + tag, name: 'attrp-' + tag,
                                  description: 'Created by ' + __filename,
                                  overrides: { 'global.mode': 'product' } });
  const dev = realms.create({ id: 'attrd-' + tag, name: 'attrd-' + tag,
                              description: 'Created by ' + __filename });
  // THE REALMS GO IN A finally, as locale_policy.js's do: this file shares
  // one process with every other in-process test.
  try {
    checks(t, product, dev, tag);
    socket(t, tag);
    view(t, product);
  } finally {
    realms.remove(product.realm ? product.realm.id : 'attrp-' + tag);
    realms.remove(dev.realm ? dev.realm.id : 'attrd-' + tag);
  }
  log.debug('Leaving run().');
}

function checks(t, product, dev, tag) {
  log.debug('Entering checks().');
  t.check(product.ok !== false && dev.ok !== false, 'two realms were made',
          JSON.stringify([product.errors, dev.errors]));

  inRealm(product.realm, function () {
    log.debug('Entering checks() in the product realm.');
    // A.
    const builtIn = attributePolicy.read('default');
    t.check(JSON.stringify(builtIn.required) ===
              JSON.stringify(['uid', 'cn', 'sn', 'givenName', 'mail']) &&
            builtIn.enforced === true,
            'A. the built-in default requires uid, cn, sn, givenName and ' +
            'mail, enforced in product mode',
            JSON.stringify([builtIn.required, builtIn.from,
                            builtIn.enforced]));
    const names = attributePolicy.catalogue().map(function (row) {
      return row.name.toLowerCase();
    });
    t.check(['uid', 'cn', 'sn', 'givenname', 'mail', 'telephonenumber',
             'employeenumber'].every(function (one) {
      return names.indexOf(one) >= 0;
    }) && ['userpassword', 'memberof', 'jpegphoto',
           'ststotpcredential'].every(function (one) {
      return names.indexOf(one) < 0;
    }) && attributePolicy.catalogue().filter(function (row) {
      return row.locked;
    }).map(function (row) {
      return row.name;
    }).sort().join(',') === 'cn,sn,uid',
            'A. the catalogue offers what a person may be given, locks uid, ' +
            'cn and sn, and never a credential, memberOf or a binary',
            names.join(','));

    // B.
    const saved = attributePolicy.save('default',
      { requiredAttributes: ['GIVENNAME', 'telephoneNumber'] });
    t.check(saved.ok && saved.profile.from === 'realm' &&
            JSON.stringify(saved.profile.required) === JSON.stringify(
              ['uid', 'cn', 'sn', 'givenName', 'telephoneNumber']),
            'B. a save replaces the list, in the canonical spelling',
            JSON.stringify(saved.errors || saved.profile.required));
    const password = attributePolicy.save('default',
      { requiredAttributes: 'givenName, userPassword' });
    const member = attributePolicy.save('default',
      { requiredAttributes: ['memberOf'] });
    // A NAME NO PROFILE MAY HAVE (#1241: named profiles exist since, so a
    // second name is no longer refused; one a cn cannot be is).
    const other = attributePolicy.save('Not A Name!',
      { requiredAttributes: ['mail'] });
    const none = attributePolicy.save('default', {});
    t.check(!password.ok && codeOf(password) === 'STS-LDAP-0166' &&
            !member.ok && codeOf(member) === 'STS-LDAP-0166' &&
            !other.ok && codeOf(other) === 'STS-LDAP-0165' &&
            !none.ok && codeOf(none) === 'STS-LDAP-0166',
            'B. userPassword, memberOf, a name no profile may have and a ' +
            'save with no list are refused under their codes',
            JSON.stringify([password.errors, member.errors, other.errors,
                            none.errors]));
    const ticked = attributePolicy.save('default', { form: 'console' });
    t.check(ticked.ok && JSON.stringify(ticked.profile.required) ===
              JSON.stringify(['uid', 'cn', 'sn']) &&
            ticked.profile.problems.length === 0,
            'B. a console form with nothing ticked saves an empty list, and ' +
            'uid, cn and sn are still required',
            JSON.stringify(ticked.profile));
    const reset = attributePolicy.reset('default');
    t.check(reset.ok && reset.removed === true &&
            JSON.stringify(attributePolicy.required()) ===
              JSON.stringify(['uid', 'cn', 'sn', 'givenName', 'mail']),
            'B. a reset goes back to the built-in default',
            JSON.stringify(attributePolicy.required()));

    // C.
    const badge = attributePolicy.define({ name: 'employeeBadge',
      label: 'Badge number', syntax: 'string', multiValued: 'single' });
    const level = attributePolicy.define({ name: 'clearanceLevel',
      label: 'Clearance', syntax: 'integer' });
    t.check(badge.ok && badge.definition.name === 'employeeBadge' &&
            badge.definition.multi === false && level.ok &&
            attributePolicy.definitions().length === 2,
            'C. two custom attributes are defined',
            JSON.stringify([badge.errors, level.errors]));
    const refusals = [
      [attributePolicy.define({ name: '9lives', label: 'x' }),
       'STS-LDAP-0169', 'a name not an RFC 4512 descr'],
      [attributePolicy.define({ name: 'okName', label: '' }),
       'STS-LDAP-0169', 'no label'],
      [attributePolicy.define({ name: 'okName', label: 'x',
                                syntax: 'blob' }),
       'STS-LDAP-0169', 'an unknown syntax'],
      [attributePolicy.define({ name: 'stsShadow', label: 'x' }),
       'STS-LDAP-0170', 'a name beginning sts'],
      [attributePolicy.define({ name: 'memberOf', label: 'x' }),
       'STS-LDAP-0170', 'memberOf'],
      [attributePolicy.define({ name: 'telephoneNumber', label: 'x' }),
       'STS-LDAP-0170', 'a name the schema already has'],
      [attributePolicy.define({ name: 'EMPLOYEEBADGE', label: 'x' }),
       'STS-LDAP-0170', 'a second definition, in another case']
    ];
    refusals.forEach(function (one) {
      t.check(one[0].ok === false && codeOf(one[0]) === one[1],
              'C. ' + one[2] + ' is refused as ' + one[1],
              JSON.stringify(one[0].errors));
    });
    const row = personEditor.editableAttributes().filter(function (one) {
      return one.name === 'clearanceLevel';
    })[0];
    t.check(!!row && row.custom === true && row.group === 'custom' &&
            row.format === 'integer' && row.multi === false,
            'C. the person editor offers a custom attribute under Custom ' +
            'with its syntax', JSON.stringify(row));
    const okValue = personEditor.checkCreateValues('clearanceLevel', ['3']);
    const badValue = personEditor.checkCreateValues('clearanceLevel',
                                                    ['three']);
    t.check(okValue && okValue.values[0] === '3' && badValue &&
            !!badValue.error,
            'C. a custom attribute\'s values are checked against its syntax',
            JSON.stringify([okValue, badValue]));

    // D.
    const bare = 'attrp-bare-' + tag;
    const refused = ldap.createUser(bare, { invent: false });
    t.check(refused.ok === false && codeOf(refused) === 'STS-LDAP-0162' &&
            JSON.stringify(refused.missing) ===
              JSON.stringify(['cn', 'sn', 'givenName', 'mail']) &&
            !(ldap.objectFor(bare) || {}).entry,
            'D. a create with nothing typed is refused as STS-LDAP-0162, ' +
            'naming what is missing, and nothing is written',
            JSON.stringify([refused.errors, refused.missing]));
    const whole = 'attrp-whole-' + tag;
    const made = ldap.createUser(whole, { invent: false,
                                         attributes: full('Ada', 'Lovelace') });
    t.check(made.ok === true &&
            attributeOf(whole, 'cn')[0] === 'Ada Lovelace',
            'D. a create with givenName, sn and mail succeeds, its cn made ' +
            'of the names', JSON.stringify(made.errors ||
                                           attributeOf(whole, 'cn')));
    attributePolicy.save('default', { requiredAttributes:
      ['givenName', 'mail', 'employeeBadge'] });
    const noBadge = ldap.createUser('attrp-nobadge-' + tag, { invent: false,
      attributes: full('Grace', 'Hopper') });
    const withBadge = ldap.createUser('attrp-badge-' + tag, { invent: false,
      attributes: Object.assign(full('Grace', 'Hopper'),
                                { employeeBadge: 'B-1' }) });
    t.check(noBadge.ok === false &&
            JSON.stringify(noBadge.missing) ===
              JSON.stringify(['employeeBadge']) && withBadge.ok === true,
            'D. a required custom attribute is asked for, and accepted ' +
            'once given', JSON.stringify([noBadge.missing, withBadge.errors]));
    const boot = ldap.createUser('attrp-boot-' + tag,
      { invent: false, requiredExempt: 'bootstrap administrator' });
    t.check(boot.ok === true,
            'D. the bootstrap administrator\'s create is exempt',
            JSON.stringify(boot.errors));

    // E.
    const emptied = personEditor.update(whole,
      { attribute: 'givenName', mode: 'set', value: '' },
      { actor: 'attribute_policy test', via: 'test' });
    t.check(emptied.ok === false && codeOf(emptied) === 'STS-LDAP-0164' &&
            attributeOf(whole, 'givenName')[0] === 'Ada',
            'E. an edit emptying a required attribute is refused as ' +
            'STS-LDAP-0164', JSON.stringify(emptied.errors));
    const phone = personEditor.update(whole,
      { attribute: 'telephoneNumber', mode: 'set', value: '+1 555 0100' },
      { actor: 'attribute_policy test', via: 'test' });
    const unphone = personEditor.update(whole,
      { attribute: 'telephoneNumber', mode: 'set', value: '' },
      { actor: 'attribute_policy test', via: 'test' });
    t.check(phone.ok === true && unphone.ok === true,
            'E. an attribute nothing requires is set and emptied freely',
            JSON.stringify([phone.errors, unphone.errors]));
    const lacking = personEditor.update('attrp-boot-' + tag,
      { attribute: 'title', mode: 'set', value: 'Administrator' },
      { actor: 'attribute_policy test', via: 'test' });
    t.check(lacking.ok === true,
            'E. a person who never held the required attributes may still ' +
            'be edited', JSON.stringify(lacking.errors));

    // F.
    const whileRequired = attributePolicy.undefine('employeeBadge');
    attributePolicy.save('default',
      { requiredAttributes: ['givenName', 'mail'] });
    const whileHeld = attributePolicy.undefine('employeeBadge');
    personEditor.update('attrp-badge-' + tag,
      { attribute: 'employeeBadge', mode: 'set', value: '' },
      { actor: 'attribute_policy test', via: 'test' });
    const nobodyHolds = attributePolicy.undefine('employeeBadge');
    const unknown = attributePolicy.undefine('neverDefined');
    t.check(whileRequired.ok === false &&
            codeOf(whileRequired) === 'STS-LDAP-0173' &&
            whileHeld.ok === false && codeOf(whileHeld) === 'STS-LDAP-0172' &&
            whileHeld.holders === 1 &&
            nobodyHolds.ok === true && nobodyHolds.removed === true &&
            !attributePolicy.definition('employeeBadge') &&
            unknown.ok === false && codeOf(unknown) === 'STS-LDAP-0174',
            'F. a custom attribute is removed only once nothing requires ' +
            'it and nobody holds a value',
            JSON.stringify([whileRequired.errors, whileHeld.errors,
                            nobodyHolds.errors, unknown.errors]));
    attributePolicy.undefine('clearanceLevel');
    attributePolicy.reset('default');
    log.debug('Leaving checks() in the product realm.');
  });

  // C, again, and G.
  inRealm(dev.realm, function () {
    log.debug('Entering checks() in the development realm.');
    attributePolicy.define({ name: 'devOnly', label: 'Dev only' });
    t.check(attributePolicy.enforced() === false &&
            attributePolicy.describe().some(function (one) {
              return /not enforced/.test(one);
            }),
            'G. development mode enforces nothing, and says so');
    const bare = ldap.createUser('attrd-bare-' + tag, { invent: false });
    t.check(bare.ok === true,
            'G. a create with nothing typed succeeds in development',
            JSON.stringify(bare.errors));
    attributePolicy.undefine('devOnly');
    log.debug('Leaving checks() in the development realm.');
  });
  inRealm(product.realm, function () {
    log.debug('Entering checks() back in the product realm.');
    t.check(attributePolicy.definitions().length === 0,
            'C. a realm does not see another realm\'s custom attributes');
    log.debug('Leaving checks() back in the product realm.');
  });
  log.debug('Leaving checks().');
}

// H. The socket, in the default realm, which holds no stored profile here:
// the built-in default is in force once the realm is put in product mode.
function socket(t, tag) {
  log.debug('Entering socket().');
  const admin = 'attrp-admin-' + tag;
  const person = 'attrp-sock-' + tag;
  const made = [];
  let granted = false;
  try {
    [admin, person].forEach(function (name) {
      ldap.createUser(name, { invent: false,
                              attributes: full('Sock', name) });
      made.push(name);
    });
    const grant = adminRbac.grant(admin, 'write', { via: 'test' });
    granted = !!grant && grant.ok !== false;
    const adminDn = ldap.objectFor(admin).entry.dn;
    const personDn = ldap.objectFor(person).entry.dn;
    const newDn = 'uid=attrp-ldap-' + tag + ',' + ldap.usersDn();
    withSettings({ 'global.mode': 'product' }, function () {
      log.debug('Entering socket() in product mode.');
      const partial = ldapAdd(adminDn, newDn, {
        objectClass: ['top', 'person', 'organizationalPerson',
                      'inetOrgPerson'],
        uid: 'attrp-ldap-' + tag, cn: 'Lin Partial', sn: 'Partial' });
      t.check(partial.ok === false &&
              partial.errorName === 'ObjectclassViolationError' &&
              lastCodeFor(newDn) === 'STS-LDAP-0162',
              'H. an LDAP add missing givenName and mail is ' +
              'objectClassViolation (65), recorded as STS-LDAP-0162',
              JSON.stringify(partial));
      const complete = ldapAdd(adminDn, newDn, {
        objectClass: ['top', 'person', 'organizationalPerson',
                      'inetOrgPerson'],
        uid: 'attrp-ldap-' + tag, cn: 'Lin Whole', sn: 'Whole',
        givenName: 'Lin', mail: 'lin@attrp.example.test' });
      t.check(complete.ok === true,
              'H. an LDAP add carrying them succeeds',
              JSON.stringify(complete));
      if (complete.ok) {
        made.push('attrp-ldap-' + tag);
      }
      const taken = ldapModify(adminDn, personDn, [['delete', 'mail']]);
      t.check(taken.ok === false &&
              taken.errorName === 'ObjectclassViolationError' &&
              lastCodeFor(personDn) === 'STS-LDAP-0164' &&
              attributeOf(person, 'mail').length === 1,
              'H. an LDAP modify deleting mail is objectClassViolation, ' +
              'recorded as STS-LDAP-0164, and changes nothing',
              JSON.stringify(taken));
      const other = ldapModify(adminDn, personDn,
                               [['replace', 'title', 'Engineer']]);
      t.check(other.ok === true,
              'H. an LDAP modify of an attribute nothing requires succeeds',
              JSON.stringify(other));
      log.debug('Leaving socket() in product mode.');
    });
  } finally {
    if (granted) {
      adminRbac.revoke(admin, 'write', { via: 'test' });
    }
    made.forEach(function (name) {
      const found = ldap.objectFor(name);
      if (found && found.entry) {
        ldap.performOperation('del', { dn: found.entry.dn, boundDn: '',
                                       channel: 'ldaps' });
      }
    });
  }
  log.debug('Leaving socket().');
}

// I. What the console draws and the API documents.
function view(t, product) {
  log.debug('Entering view().');
  const kind = policyKinds.byId('attributes');
  t.check(!!kind && policyKinds.actions().indexOf(
            'define-person-attribute') >= 0 &&
          policyKinds.forAction('remove-person-attribute').verb === 'act',
          'I. the kind is registered with its two acts');
  inRealm(product.realm, function () {
    log.debug('Entering view() in the product realm.');
    const answer = adminViews.policiesView({ missing: 'count' });
    const member = answer.attributes;
    t.check(!!member && member.enforced === true &&
            member.catalogue.length > 20 && member.missingAsked === true &&
            /^\(\|\(!\(uid=\*\)\)/.test(member.missingFilter) &&
            answer.kinds.filter(function (one) {
              return one.id === 'attributes';
            })[0].actions.length === 4,
            'I. the policies view carries the catalogue, the acts and the ' +
            'filter that finds the people who lack one',
            JSON.stringify(member && { filter: member.missingFilter,
                                       missing: member.missing }));
    const defined = adminActions.policiesAction(
      { action: 'define-person-attribute', name: 'viewProbe',
        label: 'View probe' }, { via: 'api', actor: 'attribute_policy' });
    const removed = adminActions.policiesAction(
      { action: 'remove-person-attribute', name: 'viewProbe' },
      { via: 'api', actor: 'attribute_policy' });
    t.check(defined.ok === true && removed.ok === true &&
            removed.removed === true,
            'I. the two acts reach the register through the policies ' +
            'action', JSON.stringify([defined.errors, removed.errors]));
    log.debug('Leaving view() in the product realm.');
  });
  log.debug('Leaving view().');
}

module.exports = {
  name: 'attribute_policy',
  describe: 'the attribute policy: the attributes every person must hold, ' +
            'enforced in product mode at create, edit and the LDAP socket, ' +
            'and the realm\'s custom attributes (#396)',
  run: run
};
