'use strict';
//
// File: directory_write_authorization.js
//
// ---------------------------------------------------------------------------
// WHO MAY WRITE THE DIRECTORY OVER ITS OWN SOCKET, IN PRODUCT MODE
// (2026-09-12).
//
// `ldap/ldap_server.js`'s `directoryWriteRefusal()` argues the rule: an
// anonymous connection writes nothing, a connection bound as somebody holding
// Admin Write in the DEFAULT realm writes anything, and anybody else may modify
// only the attributes `ldap.selfWritableAttributes` names on their OWN entry.
//
// **EVERY OPERATION HERE GOES THROUGH `performOperation()`**, which is the
// function a request worker runs a dispatched directory operation with. It
// builds the request out of a plain shape carrying the BOUND DN, so it is both
// the handler the socket runs and the proof that the one fact a worker cannot
// derive — who is on the connection — reaches the check.
//
// **THE ASSERTION THAT MATTERS MOST IS THE ESCALATION.**
// `admin-ui/admin_rbac.js` reads a person's own `memberOf` when it decides
// whether they hold a console role, so before this change `memberOf:
// cn=admin-write,…` written on your own entry made you an administrator of the
// service. Section 3 writes exactly that and then asks the role check, rather
// than trusting the refusal alone.
//
// In process because `global.mode` is a runtime override here and the
// directory's handlers are reachable without a socket; over HTTP the directory
// is not reachable at all, and over 389 the parent's stacks cannot reach it.
// Everything this file writes is taken back in a `finally`: a person left
// holding Admin Write would close the console's empty-roster door for every
// later file in `run.js`'s one process.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const audit = require('../common/audit');
const realms = require('../common/realms');
const ldap = require('../ldap/ldap_server');
const adminRbac = require('../admin-ui/admin_rbac');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log =
    require('bunyan').createLogger({ name: 'directory_write_authorization',
  level: process.env.LOG_LEVEL || 'info' });

const STAMP = Date.now().toString(36);
const PERSON = 'authz-person-' + STAMP;
const OTHER = 'authz-other-' + STAMP;
const ADMIN = 'authz-admin-' + STAMP;
const REALM = 'authz-' + STAMP;

function withSettings(pairs, fn) {
  log.debug("Entering withSettings().");
  const keys = Object.keys(pairs);
  try {
    keys.forEach(function (key) {
      config.setOverride(key, String(pairs[key]));
    });
    log.debug("Leaving withSettings().");
    return fn();
  } finally {
    keys.forEach(function (key) {
      config.clearOverride(key);
    });
  }
}

function product(fn) {
  log.debug("Entering product().");
  log.debug("Leaving product().");
  return withSettings({ 'global.mode': 'product' }, fn);
}

function dnOf(name) {
  log.debug("Entering dnOf().");
  log.debug("Leaving dnOf().");
  return 'uid=' + name + ',' + ldap.usersDn();
}

// An attribute off the entry, whichever case the store handed it back in.
function attributeOf(name, attribute) {
  log.debug("Entering attributeOf().");
  const view = ldap.objectFor(name);
  const attributes = (view && view.entry && view.entry.attributes) || {};
  const key = Object.keys(attributes).filter(function (one) {
    return one.toLowerCase() === attribute.toLowerCase();
  })[0];
  log.debug("Leaving attributeOf().");
  return key ? [].concat(attributes[key]).map(String) : [];
}

function modify(boundDn, dn, changes) {
  log.debug("Entering modify().");
  log.debug("Leaving modify().");
  return ldap.performOperation('modify', {
    dn: dn, boundDn: boundDn, channel: 'ldaps',
    changes: changes.map(function (one) {
      return { operation: one[0],
               modification: { type: one[1], values: one.slice(2) } };
    })
  });
}

function add(boundDn, dn, attributes) {
  log.debug("Entering add().");
  log.debug("Leaving add().");
  return ldap.performOperation('add', {
    dn: dn, boundDn: boundDn, channel: 'ldaps',
    attributes: Object.keys(attributes).map(function (type) {
      return { type: type, values: [].concat(attributes[type]) };
    })
  });
}

function del(boundDn, dn) {
  log.debug("Entering del().");
  log.debug("Leaving del().");
  return ldap.performOperation('del',
                               { dn: dn, boundDn: boundDn, channel: 'ldaps' });
}

function rename(boundDn, dn, newRdn) {
  log.debug("Entering rename().");
  log.debug("Leaving rename().");
  return ldap.performOperation('modifyDN', {
    dn: dn, boundDn: boundDn, channel: 'ldaps', newRdn: newRdn, newSuperior: ''
  });
}

// The code on the most recent refusal naming this target. The code is an
// operator's name for the condition and never reaches the client, so the audit
// row is the one place it can be read back.
function lastCodeFor(target) {
  log.debug("Entering lastCodeFor().");
  const row = audit.list().filter(function (event) {
    return event.target === target && event.errorCode;
  })[0];
  log.debug("Leaving lastCodeFor().");
  return row ? row.errorCode : '';
}

function refusedWith50(t, result, code, target, what) {
  log.debug("Entering refusedWith50().");
  t.check(result.ok === false &&
          result.errorName === 'InsufficientAccessRightsError',
          what + ' — refused with insufficientAccessRights (50)',
          JSON.stringify({ ok: result.ok, errorName: result.errorName,
                           error: result.error }));
  t.equal(lastCodeFor(target), code, what + ' — recorded as ' + code);
  log.debug("Leaving refusedWith50().");
}

function run(t) {
  log.debug("Entering run().");
  const made = [];
  let granted = false;
  let realmMade = false;
  try {
    [PERSON, OTHER, ADMIN].forEach(function (name) {
      ldap.createUser(name, { invent: false });
      made.push(name);
    });
    const personDn = ldap.objectFor(PERSON).entry.dn;
    const otherDn = ldap.objectFor(OTHER).entry.dn;
    const adminDn = ldap.objectFor(ADMIN).entry.dn;

    // -----------------------------------------------------------------------
    t.log.info('=== 1. development authorizes nothing, so nothing is refused ' +
               '===');
    const devWrite = modify('', otherDn,
                            [['replace', 'mail', 'dev@example.test']]);
    t.check(devWrite.ok === true,
            'in development an anonymous connection may still modify ' +
            'somebody else\'s entry',
            JSON.stringify(devWrite));

    product(function () {
      // ---------------------------------------------------------------------
      t.log.info('=== 2. the empty-roster rule does not make anybody an ' +
                 'administrator here ===');
      const roles = adminRbac.rolesOf(PERSON);
      t.check(roles.write === true && roles.open === true,
              'precondition: with no role group member, the console treats ' +
              'this person as holding Admin Write',
              JSON.stringify({ write: roles.write, open: roles.open }));
      refusedWith50(t,
                    modify(personDn, otherDn,
                           [['replace', 'mail', 'x@example.test']]),
                    'STS-LDAP-0053', otherDn,
                    'and still may not modify somebody else\'s entry over ' +
                    'LDAP');

      // ---------------------------------------------------------------------
      t.log.info('=== 3. anonymous, and the escalation through memberOf ===');
      refusedWith50(t,
                    modify('', personDn, [['replace', 'telephoneNumber', '1']]),
                    'STS-LDAP-0052', personDn,
                    'an anonymous connection may not modify even an ' +
                    'allowlisted attribute');
      const escalation = modify(personDn, personDn,
        [['add', 'memberOf', 'cn=admin-write,' + ldap.groupsDn()]]);
      refusedWith50(t, escalation, 'STS-LDAP-0054', personDn,
                    'a person may not write memberOf on their own entry');
      t.equal(attributeOf(PERSON, 'memberOf').length, 0,
              'and no memberOf value landed on the entry');

      // ---------------------------------------------------------------------
      t.log.info('=== 4. a person on their own entry ===');
      const own = modify(personDn, personDn,
        [['replace', 'telephoneNumber', '+1 555 0100'],
         ['replace', 'displayName', 'Probe']]);
      t.check(own.ok === true, 'a person may change allowlisted attributes ' +
                               'on their own entry',
              JSON.stringify(own));
      t.equal(attributeOf(PERSON, 'telephoneNumber').join(), '+1 555 0100',
              'and the value is stored');
      const mixed = modify(personDn, personDn,
        [['replace', 'telephoneNumber', '+1 555 0199'],
         ['replace', 'mail', 'me@example.test']]);
      refusedWith50(t, mixed, 'STS-LDAP-0054', personDn,
                    'a modify mixing an allowlisted attribute with mail');
      t.equal(attributeOf(PERSON, 'telephoneNumber').join(), '+1 555 0100',
              'and it is atomic: the allowlisted change in it was not ' +
              'applied either');
      withSettings({ 'ldap.selfWritableAttributes': 'mail' }, function () {
        const widened = modify(personDn, personDn,
                               [['replace', 'MAIL', 'me@example.test']]);
        t.check(widened.ok === true,
                'the list is the setting, matched case-insensitively: naming ' +
                'mail lets it through',
                JSON.stringify(widened));
        refusedWith50(t,
                      modify(personDn, personDn,
                             [['replace', 'telephoneNumber', '2']]),
                      'STS-LDAP-0054', personDn,
                      'and an attribute the edited list no longer names is ' +
                      'refused');
      });

      // ---------------------------------------------------------------------
      t.log.info('=== 5. a person may not add, delete or rename, nor touch ' +
                 'another entry ===');
      refusedWith50(t,
                    modify(personDn, otherDn,
                           [['replace', 'telephoneNumber', '3']]),
                    'STS-LDAP-0053', otherDn, 'a person modifying somebody ' +
                                              'else\'s entry');
      const newDn = dnOf('authz-new-' + STAMP);
      refusedWith50(t,
                    add(personDn, newDn,
                        { objectClass: ['top', 'person'], sn: 'x' }),
                    'STS-LDAP-0053', newDn, 'a person adding an entry');
      refusedWith50(t, del(personDn, personDn), 'STS-LDAP-0053', personDn,
                    'a person deleting their own entry');
      refusedWith50(t, rename(personDn, personDn, 'uid=renamed-' + STAMP),
                    'STS-LDAP-0053', personDn, 'a person renaming their own ' +
                                               'entry');
      t.check(!!ldap.objectFor(PERSON),
              'and their entry is still where it was');

      // ---------------------------------------------------------------------
      // userPassword is on the default list, and a password written through
      // this door has to reach `credentials.passwordWritten()` once it is
      // COMMITTED — that is what derives the person's Kerberos keys. Spied on
      // the exports object, which is what the handler calls through.
      t.log.info('=== 4b. a person changing their own password over LDAP ===');
      const credentials = require('../common/credentials');
      const announced = [];
      const realWritten = credentials.passwordWritten;
      credentials.passwordWritten = function (name, password) {
        log.debug("Entering passwordWritten().");
        announced.push({ name: name, password: password });
        log.debug("Leaving passwordWritten().");
      };
      try {
        const weak = modify(personDn, personDn,
                            [['replace', 'userPassword', 'short']]);
        t.check(weak.ok === false &&
                weak.errorName === 'ConstraintViolationError',
                'a self-service password that breaks the policy is still a ' +
                'constraint violation, not an authorization ' +
                'refusal', JSON.stringify(weak));
        t.equal(announced.length, 0, 'and a refused password is announced to ' +
                                     'nobody');
        const strong = modify(personDn, personDn,
          [['replace', 'userPassword', 'Self-Service-Passw0rd!' + STAMP]]);
        t.check(strong.ok === true, 'a person may set their own password ' +
                                    'over LDAP',
                JSON.stringify(strong));
        t.check(/^\$scrypt\$/.test(attributeOf(PERSON, 'userPassword').join()),
                'and it is stored as a hash');
        t.check(announced.length === 1 && announced[0].name === PERSON &&
                announced[0].password === 'Self-Service-Passw0rd!' + STAMP,
                'and it is announced once, after the commit, for the ' +
                'Kerberos key register',
                JSON.stringify(announced.map(function (a) { return a.name; })));
      } finally {
        credentials.passwordWritten = realWritten;
      }

      // ---------------------------------------------------------------------
      t.log.info('=== 6. an administrator ===');
      const grant = adminRbac.grant(ADMIN, 'write', { via: 'test' });
      granted = grant && grant.ok !== false;
      t.check(granted, 'precondition: the probe administrator was granted ' +
                       'Admin Write',
              JSON.stringify(grant));
      const adminModify = modify(adminDn, otherDn,
                                 [['replace', 'mail', 'set@example.test']]);
      t.check(adminModify.ok === true, 'an administrator may modify somebody ' +
                                       'else\'s mail',
              JSON.stringify(adminModify));
      const adminAdd = add(adminDn, newDn,
                           { objectClass: ['top', 'person'], sn: 'x' });
      t.check(adminAdd.ok === true, 'an administrator may add an entry',
              JSON.stringify(adminAdd));
      const adminDelete = del(adminDn, newDn);
      t.check(adminDelete.ok === true, 'an administrator may delete an entry',
              JSON.stringify(adminDelete));
      refusedWith50(t,
                    modify(personDn, otherDn,
                           [['replace', 'mail', 'y@example.test']]),
                    'STS-LDAP-0053', otherDn,
                    'a person is still refused once the roster has a member');

      // ---------------------------------------------------------------------
      t.log.info('=== 7. the same name in another realm is not an ' +
                 'administrator ===');
      const created = realms.create({ id: REALM, name: REALM });
      realmMade = created && created.ok !== false;
      t.check(realmMade, 'precondition: a throwaway realm was created',
              JSON.stringify(created));
      const foreignDn = realms.run(realms.get(REALM), function () {
        ldap.createUser(ADMIN, { invent: false });
        return ldap.objectFor(ADMIN).entry.dn;
      });
      t.check(foreignDn !== adminDn && /dc=authz-/.test(foreignDn),
              'precondition: that realm holds an entry with the ' +
              'administrator\'s name',
              foreignDn);
      refusedWith50(t,
                    modify(foreignDn, otherDn,
                           [['replace', 'mail', 'z@example.test']]),
                    'STS-LDAP-0053', otherDn,
                    'a DN in another realm bearing an administrator\'s name ' +
                    'writes nothing in the default');
    });
  } finally {
    if (granted) {
      adminRbac.revoke(ADMIN, 'write', { via: 'test' });
    }
    if (realmMade) {
      realms.remove(REALM);
    }
    made.forEach(function (name) {
      const view = ldap.objectFor(name);
      if (view && view.entry) {
        del('', view.entry.dn);
      }
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'directory_write_authorization',
  describe: 'product mode: who may add, modify, rename or delete a directory ' +
            'entry over LDAP',
  run: run
};
