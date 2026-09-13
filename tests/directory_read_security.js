'use strict';
//
// File: directory_read_security.js
//
// ---------------------------------------------------------------------------
// WHAT A CONNECTION TO THE DIRECTORY MAY READ, AND HOW IT MAY BIND, IN PRODUCT
// MODE (2026-09-12).
//
// node-ldapjs records the DN a bind named and decides nothing else, so every
// rule here is `ldap/ldap_server.js`'s — its *THE DIRECTORY'S READ AND BIND
// SECURITY* block argues them. `tests/directory_write_authorization.js` holds
// the write half; this holds the rest:
//
//   1. a bind: anonymous refused (48), a password on the plain listener refused
//      before it is read (13), a DN with no password refused (53);
//   2. failed binds are rate limited per DN and per address, a correct
//      password during a lockout is refused like a wrong one, and a successful
//      bind clears its own DN's counter but NEVER its address's;
//   3. a read on a connection that never bound is refused (50), the root DSE
//      excepted;
//   4. a credential attribute is never returned, is invisible to a FILTER, and
//      cannot be compared against — an administrator included;
//   5. createTimestamp, modifyTimestamp and entryDN cannot be written, an
//      administrator included (19);
//   6. the dispatched-operation codec carries the client's address, without
//      which every bind a request worker answered would share one bucket.
//
// **THE FILTER ASSERTION IS THE ONE TO READ FIRST.** Withholding an attribute
// from the RESULT and leaving it visible to the FILTER is the version of this
// that looks finished: `(userPassword=$scrypt$*)` then answers "is this a
// hash", and a substring filter walks a client secret out one character at a
// time off whether an entry came back. Section 4 asks the filter in both modes,
// so that the product-mode zero is a refusal rather than a filter that never
// matched anything.
//
// **EVERY OPERATION GOES THROUGH `performOperation()`**, the function a request
// worker runs a dispatched directory operation with, for
// `directory_write_authorization.js`'s reason: it is the handler the socket
// runs AND the proof that what a worker cannot derive — who is bound, on which
// listener, from which address — reaches the check.
//
// In process because `global.mode` is a runtime override here and over HTTP the
// directory is not reachable at all. Everything written is taken back in a
// `finally`, and the rate-limit buckets are emptied on the way in and out,
// because `run.js` runs every file in one process.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const audit = require('../common/audit');
const credentials = require('../common/credentials');
const websecurity = require('../common/websecurity');
const ldap = require('../ldap/ldap_server');
const adminRbac = require('../admin-ui/admin_rbac');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'directory_read_security',
  level: process.env.LOG_LEVEL || 'info' });

const STAMP = Date.now().toString(36);
const PERSON = 'readsec-person-' + STAMP;
const ADMIN = 'readsec-admin-' + STAMP;
// Long and mixed, so a product-mode password policy has nothing to refuse.
const PASSWORD = 'Rs-' + STAMP + '-Correct.Horse.Battery.Staple.42';
const ADDRESS = '203.0.113.' + (10 + (Date.now() % 200));

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

function bind(dn, password, channel, address) {
  log.debug("Entering bind().");
  log.debug("Leaving bind().");
  return ldap.performOperation('bind', {
    dn: dn, boundDn: '', channel: channel || 'ldaps', credentials: password,
    remoteAddress: address || ADDRESS
  });
}

function search(boundDn, base, filter, attributes, scope) {
  log.debug("Entering search().");
  log.debug("Leaving search().");
  return ldap.performOperation('search', {
    dn: base, boundDn: boundDn, channel: 'ldaps',
    scope: scope === undefined ? 2 : scope,
    filter: filter || '(objectclass=*)', attributes: attributes || [],
    sizeLimit: 0
  });
}

function compare(boundDn, dn, attribute, value) {
  log.debug("Entering compare().");
  log.debug("Leaving compare().");
  return ldap.performOperation('compare', {
    dn: dn, boundDn: boundDn, channel: 'ldaps', attribute: attribute,
    value: value
  });
}

// The code on the most recent row naming this target. A code never reaches the
// client, so the audit row is the one place it can be read back.
function lastCodeFor(target) {
  log.debug("Entering lastCodeFor().");
  const row = audit.list().filter(function (event) {
    return event.target === target && event.errorCode;
  })[0];
  log.debug("Leaving lastCodeFor().");
  return row ? row.errorCode : '';
}

function refused(t, result, errorName, code, target, what) {
  log.debug("Entering refused().");
  t.check(result.ok === false && result.errorName === errorName,
          what + ' — refused with ' + errorName,
          JSON.stringify({ ok: result.ok, errorName: result.errorName,
                           error: result.error }));
  t.equal(lastCodeFor(target), code, what + ' — recorded as ' + code);
  log.debug("Leaving refused().");
}

// Every attribute name on every returned entry, lower-cased.
function namesReturned(result) {
  log.debug("Entering namesReturned().");
  const names = {};
  (result.entries || []).forEach(function (entry) {
    (entry.attributes || []).forEach(function (attribute) {
      names[String(attribute.type).toLowerCase()] = true;
    });
  });
  log.debug("Leaving namesReturned().");
  return names;
}

function run(t) {
  log.debug("Entering run().");
  const made = [];
  let granted = false;
  websecurity.reset();
  try {
    [PERSON, ADMIN].forEach(function (name) {
      ldap.createUser(name, { invent: false });
      made.push(name);
    });
    const set = credentials.setPassword(PERSON, PASSWORD);
    t.check(set && set.ok !== false, 'precondition: the probe person has a ' +
                                     'password',
            JSON.stringify(set));
    const personDn = ldap.objectFor(PERSON).entry.dn;
    const adminDn = ldap.objectFor(ADMIN).entry.dn;
    const usersDn = ldap.usersDn();

    // -----------------------------------------------------------------------
    t.log.info('=== 0. development refuses none of it ===');
    t.check(bind('', '', 'ldap').ok === true,
            'in development an anonymous bind on the plain listener succeeds');
    const devRead = search('', usersDn, '(userPassword=*)', ['userPassword']);
    t.check(devRead.ok === true && devRead.entries.length >= 1 &&
            namesReturned(devRead).userpassword === true,
            'in development an unbound search may filter on and read ' +
            'userPassword — which is what makes the product-mode zero below ' +
            'a refusal',
            JSON.stringify({ ok: devRead.ok,
                             entries: devRead.entries.length }));

    product(function () {
      // ---------------------------------------------------------------------
      t.log.info('=== 1. the bind ===');
      refused(t, bind('', ''), 'InappropriateAuthenticationError',
              'STS-LDAP-0070',
              '(anonymous)', 'an anonymous bind');
      refused(t, bind(personDn, PASSWORD, 'ldap'),
              'ConfidentialityRequiredError',
              'STS-LDAP-0071', personDn,
              'a correct password on the plain listener, refused before it ' +
              'is read');
      refused(t, bind(personDn, ''), 'UnwillingToPerformError', 'STS-LDAP-0072',
              personDn,
              'a DN with an empty password (an unauthenticated bind)');
      t.check(bind(personDn, PASSWORD).ok === true,
              'the correct password over LDAPS binds');

      // ---------------------------------------------------------------------
      t.log.info('=== 2. failed binds are rate limited ===');
      websecurity.reset();
      withSettings({ 'security.rateLimitPerIdentity': 3,
                     'security.rateLimitPerAddress': 50 }, function () {
        for (let i = 0; i < 3; i++) {
          const wrong = bind(personDn, PASSWORD + '-wrong-' + i);
          t.check(wrong.ok === false &&
                  wrong.errorName === 'InvalidCredentialsError',
                  'wrong password ' + (i + 1) + ' of 3 is invalidCredentials',
                  JSON.stringify(wrong));
        }
        refused(t, bind(personDn, PASSWORD), 'UnwillingToPerformError',
                'STS-LDAP-0073',
                personDn, 'the CORRECT password once the DN is over its limit');
        t.check(bind(personDn, PASSWORD, 'ldaps', '198.51.100.9').ok === false,
                'and from another address too, since the DN bucket is what ' +
                'is full');
      });
      websecurity.reset();
      withSettings({ 'security.rateLimitPerIdentity': 50,
                     'security.rateLimitPerAddress': 3 }, function () {
        t.check(bind(adminDn, 'not-their-password-1').ok === false &&
                bind(adminDn, 'not-their-password-2').ok === false,
                'two failures from one address');
        t.check(bind(personDn, PASSWORD).ok === true,
                'a SUCCESSFUL bind from that address in between');
        t.check(bind(adminDn, 'not-their-password-3').ok === false,
                'a third failure from that address');
        refused(t, bind(personDn, PASSWORD), 'UnwillingToPerformError',
                'STS-LDAP-0073',
                personDn, 'the address is now blocked — the success did not ' +
                'reset it, or one working password would be a way to keep ' +
                'guessing everybody else\'s');
        t.check(bind(personDn, PASSWORD, 'ldaps', '198.51.100.23').ok === true,
                'while the same person from another address binds');
      });
      websecurity.reset();

      // ---------------------------------------------------------------------
      t.log.info('=== 3. a read requires a bind ===');
      refused(t, search('', usersDn), 'InsufficientAccessRightsError',
              'STS-LDAP-0074',
              usersDn, 'an unbound search');
      refused(t, compare('', personDn, 'mail', 'x'),
              'InsufficientAccessRightsError',
              'STS-LDAP-0074', personDn, 'an unbound compare');
      const nowhere = 'uid=nobody-' + STAMP + ',' + usersDn;
      refused(t, search('', nowhere), 'InsufficientAccessRightsError',
              'STS-LDAP-0074',
              nowhere, 'an unbound search of an entry that does not exist is ' +
              'refused the same way, so the refusal says nothing about the ' +
              'tree');
      const rootDse = search('', '', '(objectclass=*)', [], 0);
      t.check(rootDse.ok === true && rootDse.entries.length === 1,
              'the root DSE is still readable before a bind',
              JSON.stringify({ ok: rootDse.ok,
                               entries: (rootDse.entries || []).length }));
      const bound = search(personDn, usersDn, '(uid=' + PERSON + ')');
      t.check(bound.ok === true && bound.entries.length === 1,
              'a bound connection reads', JSON.stringify(bound));

      // ---------------------------------------------------------------------
      t.log.info('=== 4. credentials are withheld, from the result, the ' +
                 'filter and compare ===');
      const asked = search(personDn, usersDn, '(uid=' + PERSON + ')',
                           ['userPassword', 'pwdHistory', '*']);
      const names = namesReturned(asked);
      t.check(asked.ok === true && asked.entries.length === 1 &&
              !names.userpassword &&
              !names.pwdhistory,
              'userPassword and pwdHistory are not returned even when asked ' +
              'for by name',
              JSON.stringify(Object.keys(names)));
      t.check(!!names.uid, 'while the entry\'s ordinary attributes are',
              JSON.stringify(Object.keys(names)));
      const presence = search(personDn, usersDn, '(userPassword=*)');
      t.check(presence.ok === true && presence.entries.length === 0,
              'a filter cannot see userPassword: (userPassword=*) matches ' +
              'nobody',
              JSON.stringify({ entries: (presence.entries || []).length }));
      const substring = search(personDn, usersDn,
                               '(&(uid=' + PERSON +
                               ')(userPassword=$scrypt*))');
      t.check(substring.ok === true && substring.entries.length === 0,
              'nor can a substring filter, which is the ' +
              'one-character-at-a-time oracle',
              JSON.stringify({ entries: (substring.entries || []).length }));
      refused(t, compare(personDn, personDn, 'userPassword', PASSWORD),
              'InsufficientAccessRightsError', 'STS-LDAP-0075', personDn,
              'a compare against their OWN userPassword');
      t.check(compare(personDn, personDn, 'uid', PERSON).ok === true,
              'a compare against an ordinary attribute still answers');

      const grant = adminRbac.grant(ADMIN, 'write', { via: 'test' });
      granted = grant && grant.ok !== false;
      t.check(granted,
              'precondition: the probe administrator holds Admin Write',
              JSON.stringify(grant));
      const adminRead = search(adminDn, usersDn, '(uid=' + PERSON + ')',
                               ['*', 'userPassword']);
      t.check(adminRead.ok === true && adminRead.entries.length === 1 &&
              !namesReturned(adminRead).userpassword,
              'an administrator is not excepted: no userPassword for them ' +
              'either',
              JSON.stringify(Object.keys(namesReturned(adminRead))));

      // ---------------------------------------------------------------------
      t.log.info('=== 5. operational attributes are the directory\'s to ' +
                 'write ===');
      const stamp = ldap.performOperation('modify', {
        dn: personDn, boundDn: adminDn, channel: 'ldaps',
        changes: [{ operation: 'replace',
                    modification: { type: 'createTimestamp',
                                    values: ['19700101000000Z'] } }]
      });
      refused(t, stamp, 'ConstraintViolationError', 'STS-LDAP-0076', personDn,
              'an administrator writing createTimestamp');
      const addDn = 'uid=readsec-add-' + STAMP + ',' + usersDn;
      const addStamp = ldap.performOperation('add', {
        dn: addDn, boundDn: adminDn, channel: 'ldaps',
        attributes: [{ type: 'objectClass', values: ['top', 'person'] },
                     { type: 'sn', values: ['x'] },
                     { type: 'modifyTimestamp', values: ['19700101000000Z'] }]
      });
      refused(t, addStamp, 'ConstraintViolationError', 'STS-LDAP-0076', addDn,
              'an add carrying modifyTimestamp');
    });

    // -----------------------------------------------------------------------
    t.log.info('=== 6. the dispatched codec carries the client address ===');
    const shape = ldap.operationRequest('bind', {
      dn: personDn, credentials: 'x',
      connection: { encrypted: true, remoteAddress: ADDRESS,
                    ldap: { bindDN: 'cn=anonymous' } }
    });
    t.equal(shape.remoteAddress, ADDRESS,
            'operationRequest() carries remoteAddress, or every dispatched ' +
            'bind shares one bucket');
  } finally {
    websecurity.reset();
    if (granted) {
      adminRbac.revoke(ADMIN, 'write', { via: 'test' });
    }
    made.forEach(function (name) {
      const view = ldap.objectFor(name);
      if (view && view.entry) {
        ldap.performOperation('del',
                              { dn: view.entry.dn, boundDn: '',
                                channel: 'ldaps' });
      }
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'directory_read_security',
  describe: 'product mode: LDAP binds refused anonymous, in the clear and ' +
            'past a rate limit; reads need a bind; credentials never leave; ' +
            'operational attributes read-only',
  run: run
};
