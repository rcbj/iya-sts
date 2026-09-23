'use strict';
//
// File: mail_address_sources.js
//
// ===========================================================================
// WHO WROTE AN ADDRESS DECIDES WHETHER IT IS VERIFIED (#64, 2026-09-23), in
// process against the embedded directory.
//
// rcbj's ticket: an address provided through federation, SCIM, LDAP, the
// management API or the console needs no validation; one a person provides
// must be proved by a link. `ldap/ldap_server.js`'s `verifyWrittenMail()`
// argues the rule; what is held here, door by door:
//
//   1. THE CONSOLE AND /admin-api: a typed address on a create is verified;
//      an address `namePlan()` INVENTED is not; set-mail is verified.
//   2. SCIM: a changed address is verified; the same entry rewritten with no
//      source (a HOBA key registration's rewrite) leaves an unverified
//      address unverified.
//   3. LDAP: a modify bound as an ADMINISTRATOR verifies; one bound as the
//      PERSON does not.
//   4. FEDERATION: a partner's address is verified — unless the partner said
//      `email_verified: false`.
// ===========================================================================

delete process.env.CONFIG_FILE;

const ldapjs = require('ldapjs');
const ldap = require('../ldap/ldap_server');
const mail = require('../common/mail');
const adminRbac = require('../admin-ui/admin_rbac');
const adminActions = require('../admin-core/admin_actions');

const log = require('bunyan').createLogger({ name: 'mail_address_sources',
  level: process.env.LOG_LEVEL || 'info' });

function verified(username) {
  log.debug('Entering verified().');
  const who = mail.recipient(username);
  log.debug('Leaving verified().');
  return !!(who && who.verified);
}

function addressOf(username) {
  log.debug('Entering addressOf().');
  const who = mail.recipient(username);
  log.debug('Leaving addressOf().');
  return who ? who.address : '';
}

function ldapModify(dn, changes, boundDn) {
  log.debug('Entering ldapModify().');
  const handler = ldap.localHandler('modify');
  const req = {
    dn: ldapjs.parseDN(dn),
    changes: changes.map(function (one) {
      return { operation: one[0],
               modification: { type: one[1], values: one.slice(2) } };
    }),
    connection: { encrypted: false,
                  ldap: { bindDN: boundDn || 'cn=anonymous',
                          id: 'mail-address-sources-test' },
                  remoteAddress: '127.0.0.1', remotePort: 40000 },
    logId: 'mail-address-sources-test'
  };
  const out = { ended: false, failure: null };
  handler(req, { end: function () {
    log.debug('Entering end().');
    out.ended = true;
    log.debug('Leaving end().');
  } }, function (err) {
    if (err) {
      out.failure = err;
    }
  });
  log.debug('Leaving ldapModify().');
  return out;
}

function consoleAndApi(t) {
  log.debug('Entering consoleAndApi().');
  const typed = ldap.createUser('mas-typed', {
    origin: 'console', attributes: { mail: 'typed@example.com' } });
  t.check(typed.ok && verified('mas-typed'),
          '1a. an address typed on the console\'s create is VERIFIED — an ' +
          'administrator is a trusted source', JSON.stringify(typed.errors));
  const invented = ldap.createUser('mas-invented', { origin: 'console' });
  t.check(invented.ok && !verified('mas-invented'),
          '1b. an address namePlan() INVENTED is not: nobody provided it',
          addressOf('mas-invented'));
  const set = adminActions.usersAction({ action: 'set-mail',
    user: 'mas-invented', mail: 'set@example.com' }, { via: 'api' });
  t.check(set.ok && addressOf('mas-invented') === 'set@example.com' &&
          verified('mas-invented'),
          '1c. set-mail writes the address, verified',
          JSON.stringify(set.errors));
  const bad = adminActions.usersAction({ action: 'set-mail',
    user: 'mas-invented', mail: 'not an address' }, { via: 'api' });
  t.check(!bad.ok && addressOf('mas-invented') === 'set@example.com',
          '1d. and refuses something that is not an address');
  log.debug('Leaving consoleAndApi().');
}

function scim(t) {
  log.debug('Entering scim().');
  ldap.createUser('mas-scim', { origin: 'scim' });
  const dn = ldap.objectFor('mas-scim').entry.dn;
  const attributes = function (address) {
    log.debug('Entering attributes().');
    const now = ldap.readPerson(dn) || {};
    const out = Object.assign({}, (now.attributes || now) || {});
    out.mail = [address];
    log.debug('Leaving attributes().');
    return out;
  };
  const scimWrite = ldap.writePerson(dn, attributes('scim@example.com'),
                                     { mailSource: 'scim' });
  t.check(scimWrite.ok && verified('mas-scim'),
          '2a. an address a SCIM client provisions is verified',
          JSON.stringify(scimWrite));
  const bySelf = ldap.writePerson(dn, attributes('changed@example.com'));
  t.check(bySelf.ok && !verified('mas-scim'),
          '2b. a rewrite that names no trusted source changes the address ' +
          'and leaves it UNVERIFIED');
  const again = ldap.writePerson(dn, attributes('changed@example.com'));
  t.check(again.ok && !verified('mas-scim'),
          '2c. and the same address written again proves nothing new');
  log.debug('Leaving scim().');
}

function ldapDoor(t) {
  log.debug('Entering ldapDoor().');
  ldap.createUser('mas-ldap', { invent: false });
  const dn = ldap.objectFor('mas-ldap').entry.dn;
  const self = ldapModify(dn, [['replace', 'mail', 'self@example.com']], dn);
  t.check(!self.failure && addressOf('mas-ldap') === 'self@example.com' &&
          !verified('mas-ldap'),
          '3a. a person changing their OWN address over LDAP is not verified ' +
          '— that is a user-provided address',
          self.failure && self.failure.message);
  ldap.createUser('mas-operator', { invent: false });
  const operator = ldap.objectFor('mas-operator').entry.dn;
  const granted = adminRbac.grant('mas-operator', 'write', { via: 'test' });
  try {
    const admin = ldapModify(dn, [['replace', 'mail', 'admin@example.com']],
                             operator);
    t.check(granted && !admin.failure &&
            addressOf('mas-ldap') === 'admin@example.com' &&
            verified('mas-ldap'),
            '3b. an administrator\'s LDAP write of it is verified',
            admin.failure && admin.failure.message);
  } finally {
    adminRbac.revoke('mas-operator', 'write', { via: 'test' });
  }
  log.debug('Leaving ldapDoor().');
}

function federation(t) {
  log.debug('Entering federation().');
  const made = ldap.autoCreateUser({ key: 'mas-fed', federation: {
    id: 'mas-partner', peer: 'https://partner.example', create: true,
    attributes: { mail: ['fed@example.com'] } } });
  t.check(!!made && addressOf('mas-fed') === 'fed@example.com' &&
          verified('mas-fed'),
          '4a. a federation partner\'s address is verified');
  const disowned = ldap.autoCreateUser({ key: 'mas-fed-no', federation: {
    id: 'mas-partner', peer: 'https://partner.example', create: true,
    mailVerified: false,
    attributes: { mail: ['fedno@example.com'] } } });
  t.check(!!disowned && addressOf('mas-fed-no') === 'fedno@example.com' &&
          !verified('mas-fed-no'),
          '4b. unless the partner said email_verified: false');
  log.debug('Leaving federation().');
}

module.exports = {
  name: 'mail address sources',
  describe: 'Whether an address is verified follows who wrote it (#64): the ' +
            'console and /admin-api, SCIM, an administrator\'s LDAP write ' +
            'and a federation partner verify it; a person\'s own LDAP write ' +
            'and an invented address do not',
  run: async function (t) {
    log.debug('Entering run().');
    consoleAndApi(t);
    scim(t);
    ldapDoor(t);
    federation(t);
    log.debug('Leaving run().');
  }
};
