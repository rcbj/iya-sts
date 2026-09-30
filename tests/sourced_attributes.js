// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
// File: sourced_attributes.js
// ===========================================================================
// WHAT AN OUTSIDE SOURCE MAY WRITE ONTO A PERSON, AND WHO HEARS OF IT (#94).
//
// Until #94 a federation relationship's `fedAttributeMap` could name any
// target, so a partner could be mapped onto `memberOf` (the console roles),
// `pwdAccountLockedTime` (a disable) or a credential attribute; the write was
// silent, so CAEP, RISC and the mail flow never heard a partner change a
// person; and the names nothing mapped were promised on /admin/federation and
// never shown there. This file holds all three:
//   A. `common/sourced_attributes.ts`: refused by prefix and by name, `mail`
//      writable;
//   B. `federation.update()` refuses a mapping onto a refused target, and
//      never refuses removing one;
//   C. `federation_map`'s mapIncoming() drops a refused target at sign-in, as
//      unmapped with the reason;
//   D. `applyFederatedAttributes()` never writes one either, and tells the
//      account observers when a value describing an existing person moved;
//   E. the names a partner sent and nothing wrote are recorded per
//      relationship for /admin/federation, and go with the relationship.
// In process: the directory and the federation register, in a throwaway
// realm.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const realms = require('../common/realms');
const ldap = require('../ldap/ldap_server');
const federation = require('../federation/federation');
const federationMap = require('../federation/federation_map');
const SourcedAttributes = require('../common/sourced_attributes');

const log = require('bunyan').createLogger({ name: 'sourced_attributes',
  level: process.env.LOG_LEVEL || 'info' });

const RUN = nodeCrypto.randomBytes(3).toString('hex');
const REL = 'sa-partner-' + RUN;
const PERSON = 'sa-person-' + RUN;

function theRule(t) {
  log.debug('Entering theRule().');
  t.log.info('=== A. the rule ===');
  const refused = ['memberOf', 'pwdAccountLockedTime', 'stsTotpCredential',
    'stsAssertionKey', 'userPassword', 'uid', 'objectClass', 'entryUUID',
    'federationLink', 'appRequiredRole', 'hobaPublicKey', 'modifyTimestamp'];
  const writable = ['mail', 'departmentNumber', 'title', 'costCenter',
    'employeeNumber', 'telephoneNumber'];
  t.check(refused.every(function (name) {
    return SourcedAttributes.refusal(name) !== '';
  }), 'A1. credentials, account state, membership, identity and ' +
      'provenance are refused', JSON.stringify(refused.filter(function (n) {
    return SourcedAttributes.refusal(n) === '';
  })));
  t.check(writable.every(function (name) {
    return SourcedAttributes.refusal(name) === '';
  }), 'A2. a person\'s own attributes — mail among them — are writable',
  JSON.stringify(writable.filter(function (n) {
    return SourcedAttributes.refusal(n) !== '';
  })));
  t.check(SourcedAttributes.refusal('STSNEWCREDENTIAL') !== '',
          'A3. by prefix, case-insensitively: a credential attribute added ' +
          'later is refused without an edit');
  log.debug('Leaving theRule().');
}

function theMapping(t) {
  log.debug('Entering theMapping().');
  t.log.info('=== B. a mapping onto a refused target ===');
  const made = federation.create({ fedId: REL, fedRole: 'service-provider',
                                   fedProtocol: 'oidc' });
  t.check(made && made.ok !== false, 'precondition: the relationship exists',
          JSON.stringify(made));
  const add = function (value) {
    return federation.update(REL, { field: 'fedAttributeMap', value: value,
                                    mode: 'add' });
  };
  const groups = add('groups=memberOf');
  t.check(groups.ok === false &&
          /may not write/.test((groups.errors || []).join(' ')),
          'B1. groups=memberOf is refused, and says why',
          JSON.stringify(groups));
  t.check(add('lock=pwdAccountLockedTime').ok === false &&
          add('otp=stsTotpCredential').ok === false,
          'B2. so are a disable and a second factor');
  t.check(add('not a mapping').ok === false,
          'B3. a value that is not <incoming>=<attribute> is refused');
  t.check(add('dept=departmentNumber').ok !== false &&
          add('email=mail').ok !== false,
          'B4. a person\'s own attribute is mapped, mail included');
  log.debug('Leaving theMapping().');
}

function atSignIn(t) {
  log.debug('Entering atSignIn().');
  t.log.info('=== C. mapIncoming() at sign-in ===');
  // A mapping written before #94 (or by an ldapmodify): the register is
  // handed one directly, as the store would.
  const record = { fedId: REL, fedAttributeMap: ['groups=memberOf',
                                                 'dept=departmentNumber'] };
  const mapped = federationMap.mapIncoming(record,
    { groups: ['admins'], dept: ['42'], shoeSize: ['9'] }, PERSON);
  const dropped = (mapped.unmapped || []).filter(function (one) {
    return one.incoming === 'groups';
  })[0];
  t.check(!mapped.attributes.memberOf && !mapped.attributes.memberof &&
          mapped.attributes.departmentNumber &&
          mapped.attributes.departmentNumber[0] === '42',
          'C1. the refused target is not among what is written; the other ' +
          'mapping is', JSON.stringify(mapped.attributes));
  t.check(!!dropped && /memberOf/.test(dropped.refused || ''),
          'C2. it is reported unmapped, with the reason',
          JSON.stringify(mapped.unmapped));
  log.debug('Leaving atSignIn().');
  return mapped.unmapped;
}

function theWrite(t) {
  log.debug('Entering theWrite().');
  t.log.info('=== D. the federated write ===');
  ldap.createUser(PERSON, { invent: false, attributes: {} });
  const seen = [];
  ldap.addAccountObserver(function (change) {
    if (change && change.username === PERSON) {
      seen.push(change);
    }
  });
  const signIn = function (attributes) {
    return ldap.autoCreateUser({ key: PERSON, federation: {
      id: REL, peer: 'https://partner.example', create: false,
      updateAttributes: true, attributes: attributes } });
  };
  signIn({ departmentNumber: ['7'], memberOf: ['admins'],
           stsTotpCredential: ['x'] });
  // Read case-insensitively: objectFor() answers canonical spellings.
  const held = ldap.objectFor(PERSON).entry.attributes;
  const entry = {};
  Object.keys(held).forEach(function (name) {
    entry[name.toLowerCase()] = held[name];
  });
  t.check([].concat(entry.departmentnumber || [])[0] === '7' &&
          !entry.memberof && !entry.ststotpcredential,
          'D1. the write keeps a person\'s own attribute and refuses the ' +
          'rest', JSON.stringify({ dept: entry.departmentnumber,
                                   memberOf: entry.memberof }));
  t.check(seen.length === 1 && seen[0].kind === 'updated' &&
          (seen[0].after.departmentnumber || [])[0] === '7',
          'D2. and the account observers were told, once',
          JSON.stringify(seen.map(function (one) { return one.kind; })));
  signIn({ departmentNumber: ['7'] });
  t.check(seen.length === 1,
          'D3. a sign-in that changed nothing describing the person tells ' +
          'nobody', String(seen.length));
  log.debug('Leaving theWrite().');
}

function theList(t, unmapped) {
  log.debug('Entering theList().');
  t.log.info('=== E. the names nothing wrote ===');
  t.check(federation.recordUnmapped(REL, unmapped) === true,
          'E1. a sign-in\'s unmapped names are recorded');
  t.check(federation.recordUnmapped(REL, unmapped) === false,
          'E2. and the same names again, within the hour, write nothing');
  const listed = federation.unmappedOf(REL);
  const names = listed.map(function (one) { return one.name; }).sort();
  t.check(names.join() === 'groups,shoeSize' &&
          listed.filter(function (one) {
            return one.name === 'groups';
          })[0].refused !== '',
          'E3. the relationship lists them, the refused one with its reason',
          JSON.stringify(listed));
  federation.remove(REL);
  t.check(federation.unmappedOf(REL).length === 0,
          'E4. and they go with the relationship');
  log.debug('Leaving theList().');
}

async function run(t) {
  log.debug('Entering run().');
  const realm = realms.create({ id: 'sa-' + RUN,
                                name: 'sourced attributes ' + RUN }).realm;
  try {
    await realms.run(realm, async function () {
      theRule(t);
      theMapping(t);
      const unmapped = atSignIn(t);
      theWrite(t);
      theList(t, unmapped);
    });
  } finally {
    realms.remove(realm.id);
  }
  log.debug('Leaving run().');
}

module.exports = {
  name: 'sourced_attributes',
  describe: 'What an outside source may write onto a person (#94): the ' +
            'refusal rule, a fedAttributeMap onto a refused target refused ' +
            'on write and dropped at sign-in, the federated write told to ' +
            'the account observers, and the names nothing wrote listed per ' +
            'relationship',
  run: run
};
