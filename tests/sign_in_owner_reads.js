// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: sign_in_owner_reads.js
//
// ===========================================================================
// A SCOPE DECISION DOES NOT ASK THE DIRECTORY FOR EVERY SERVICE ACCOUNT
// (#759).
//
// Under a sign-in load on 8081 the XACML scope decision asked
// `ownership.ownsAnything()` on every sign-in, and that walked the holders
// of the service-account flag through the store and built a view of every
// application: about 7% of a request worker. The service accounts are kept
// by a clock of their own (`serviceAccountsVersion`, moved on the group
// clock's rule) and the application owners are read off the kept listing.
//
//   A. THE CLOCK: the names are read once and kept across writes to an
//      ordinary person; flagging a person a service account, and taking the
//      flag away, is seen by the very next read.
//   B. OWNERSHIP IS STILL COMPUTED AT THE DECISION (rcbj's decision 2): an
//      owner named on a service account owns something at once, and
//      nothing once taken off.
//   C. THE LISTING: `applications.ownerValues()` answers the owners
//      `list()` would have, with no view built.
//
// In process, development mode, the directory in memory, every write
// through the LDAP modify handler a socket reaches.
// ===========================================================================

delete process.env.CONFIG_FILE;

const ldapServer = require('../ldap/ldap_server');
const ldapjs = require('ldapjs');
const applications = require('../common/applications');
const serviceAccounts = require('../common/service_accounts');
const ownership = require('../common/ownership');
const cacheRegistry = require('../common/cache_registry');

const log = require('bunyan').createLogger({ name: 'sign_in_owner_reads',
  level: process.env.LOG_LEVEL || 'info' });

const STAMP = Date.now().toString(36);
const ACCOUNT = 'owner-reads-svc-' + STAMP;
const PERSON = 'owner-reads-person-' + STAMP;
// The realm's service-account policy requires an owner: this one stands in
// whenever the probe person is not it.
const KEEPER = 'owner-reads-keeper-' + STAMP;

function counts() {
  log.debug("Entering counts().");
  const d = cacheRegistry.detail('ldap.service-accounts');
  const s = (d && d.summary) || {};
  log.debug("Leaving counts().");
  return { hits: Number(s.hits || 0), misses: Number(s.misses || 0) };
}

// An LDAP modify through the codec a worker runs; development mode
// authorizes no write, so the bound DN is decoration.
function modify(dn, changes) {
  log.debug("Entering modify().");
  const req = {
    connection: { encrypted: true,
                  ldap: { bindDN: 'cn=admin,dc=example,dc=com',
                          id: 'owner-reads' },
                  remoteAddress: '127.0.0.1', remotePort: 40000 },
    dn: ldapjs.parseDN(dn),
    changes: changes.map(function (one) {
      return new ldapjs.Change({
        operation: one[0],
        modification: new ldapjs.Attribute({ type: one[1],
                                             values: one.slice(2) })
      });
    })
  };
  const shape = ldapServer.operationRequest('modify', req);
  log.debug("Leaving modify().");
  return Promise.resolve(ldapServer.performOperation('modify',
    JSON.parse(JSON.stringify(shape))));
}

async function theClock(t, accountDn, personDn, keeperDn) {
  log.debug("Entering theClock().");
  t.log.info('=== A. the service accounts are kept by their own clock ===');
  t.check(cacheRegistry.has('ldap.service-accounts'),
          'A0. the kept names are described to /admin/caches');
  serviceAccounts.names();
  const before = counts();
  serviceAccounts.names();
  serviceAccounts.names();
  const kept = counts();
  t.check(kept.misses === before.misses && kept.hits === before.hits + 2,
          'A1. asked again, the names are answered from what is kept',
          JSON.stringify([before, kept]));
  let r = await modify(personDn, [['replace', 'description', 'not an owner']]);
  t.check(r.ok === true, 'A2. an ordinary person is modified', r.error || '');
  serviceAccounts.names();
  const after = counts();
  t.equal(after.misses, kept.misses,
          'A3. and the kept names survive it: the store is not asked again');
  t.check(serviceAccounts.names().indexOf(ACCOUNT) < 0,
          'A4. the probe is not a service account yet');
  r = await modify(accountDn, [['replace', 'stsServiceAccount', 'TRUE'],
                               ['replace', 'stsServiceAccountOwner',
                                keeperDn]]);
  t.check(r.ok === true, 'A5. the probe is flagged a service account',
          r.error || '');
  t.check(serviceAccounts.names().indexOf(ACCOUNT) >= 0,
          'A6. and the very next read lists it');
  r = await modify(accountDn, [['delete', 'stsServiceAccount'],
                               ['delete', 'stsServiceAccountOwner']]);
  t.check(r.ok === true, 'A7. the flag is taken away', r.error || '');
  t.check(serviceAccounts.names().indexOf(ACCOUNT) < 0,
          'A8. and the very next read does not list it');
  r = await modify(accountDn, [['replace', 'stsServiceAccount', 'TRUE'],
                               ['replace', 'stsServiceAccountOwner',
                                keeperDn]]);
  t.check(r.ok === true && serviceAccounts.names().indexOf(ACCOUNT) >= 0,
          'A9. flagged again, for B', r.error || '');
  log.debug("Leaving theClock().");
}

async function ownershipIsComputed(t, accountDn, personDn, keeperDn) {
  log.debug("Entering ownershipIsComputed().");
  t.log.info('=== B. ownership is still computed at the decision ===');
  t.equal(ownership.ownsAnything(PERSON), false,
          'B1. a person who owns nothing owns nothing');
  let r = await modify(accountDn,
                       [['replace', 'stsServiceAccountOwner', personDn]]);
  t.check(r.ok === true, 'B2. the person is named the service account\'s ' +
                         'owner', r.error || '');
  t.equal(ownership.ownsAnything(PERSON), true,
          'B3. and owns something at the very next decision');
  r = await modify(accountDn,
                   [['replace', 'stsServiceAccountOwner', keeperDn]]);
  t.check(r.ok === true, 'B4. the owner is taken off (another named in ' +
                         'their place, as the policy requires)',
          r.error || '');
  t.equal(ownership.ownsAnything(PERSON), false,
          'B5. and owns nothing at the very next decision');
  log.debug("Leaving ownershipIsComputed().");
}

function theListing(t) {
  log.debug("Entering theListing().");
  t.log.info('=== C. application owners come off the kept listing ===');
  const fromList = applications.list().map(function (app) {
    return [].concat((app.fields || {}).appOwner || []).map(String);
  }).filter(function (owners) {
    return owners.length > 0;
  });
  t.equal(JSON.stringify(applications.ownerValues()),
          JSON.stringify(fromList),
          'C1. ownerValues() answers the owners list() would have');
  log.debug("Leaving theListing().");
}

async function run(t) {
  log.debug("Entering run().");
  ldapServer.createUser(ACCOUNT, { invent: false });
  ldapServer.createUser(PERSON, { invent: false });
  ldapServer.createUser(KEEPER, { invent: false });
  const accountDn = ldapServer.objectFor(ACCOUNT).entry.dn;
  const personDn = ldapServer.objectFor(PERSON).entry.dn;
  const keeperDn = ldapServer.objectFor(KEEPER).entry.dn;
  try {
    await theClock(t, accountDn, personDn, keeperDn);
    await ownershipIsComputed(t, accountDn, personDn, keeperDn);
    theListing(t);
  } finally {
    // Tidied up: this directory is module-wide (tests/CLAUDE.md).
    [accountDn, personDn, keeperDn].forEach(function (dn) {
      ldapServer.performOperation('del', { dn: dn, boundDn: '',
                                           channel: 'ldaps' });
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'sign_in_owner_reads',
  describe: 'a scope decision does not ask the directory for every service ' +
            'account (#759): the names kept by their own clock, ownership ' +
            'still computed at the decision, application owners off the ' +
            'listing',
  run: run
};
