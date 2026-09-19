'use strict';
//
// File: user_register_fan_in.js
//
// ===========================================================================
// THE USERS REGISTER IS EVERY PROCESS'S, NOT THE ONE ANSWERING (2026-09-19).
//
// `common/admin_stats.js`'s `users` is `merge: 'own'`: each process writes
// the authentications it saw, and what any OTHER process wrote — another node
// of a cluster, a request worker, or this node before its last restart, whose
// rows come back under an origin that is no longer its own — reaches this one
// as a CONTRIBUTION held by `persistence/persistence_replication.js`, never as
// a row of the Map. `nums`, `calls` and `artifacts` were fanned in where they
// are reported; `users` was not. After a redeploy of the three-node testidp
// cluster `/admin/users` held one authenticated row out of 423, and `abcapp1`
// — an OAuth client whose only trace was a client_credentials token — was
// drawn as a PERSON with no directory entry, because the `isClient` that said
// otherwise was on a contribution nothing read.
//
// Asserted:
//   1. a contribution alone makes a row, carrying its counts and `isClient`;
//   2. a record here and a contribution for the same person are ONE row, the
//      counts summed, first/last seen combined, the events merged in order;
//   3. `knownUser()` — what product mode's enrolment door asks — knows
//      somebody only another process saw;
//   4. reading the view edits neither the register nor the contribution;
//   5. a row built from a client_credentials TOKEN alone is a client, and one
//      built from a person's token is not;
//   6. a rename merges a protocol family both rows hold by adding its counts
//      (it kept the survivor's object whole and dropped the other's).
//   7. the USERS PAGE lists people only (2026-09-19): `peopleRows()` — what
//      `/admin/users`, `/admin-api/users` and `/admin-api/mfa` draw — drops a
//      client_credentials client, a `urn:sts:client:` subject, and a
//      registered application seen only as an artifact's subject, and keeps
//      the person beside them. On testidp the "Management API operations
//      test" realm listed `app-stsapi-client-…` among its users.
//
// WHY IN PROCESS: the defect needs a second origin, which is a second process
// or a restart — neither of which a request can choose, and every stack the
// suite starts is one process that has not restarted.
// ===========================================================================

delete process.env.CONFIG_FILE;

const stats = require('../common/admin_stats');
const helpers = require('../common/helpers');
const realms = require('../common/realms');
const replication = require('../persistence/persistence_replication');
// Required for its load-time effect: it fills the directory slot the
// applications registry keeps its entries in, which section 7 needs.
require('../ldap/ldap_server');
const applications = require('../common/applications');
const adminViews = require('../admin-core/admin_views');

const log = require('bunyan').createLogger({ name: 'user_register_fan_in',
  level: process.env.LOG_LEVEL || 'info' });

const DEFAULT = realms.DEFAULT_REALM.id;
const STAMP = Date.now().toString(36);

// A users-register record as another process would have written it.
function theirRecord(key, fields) {
  log.debug("Entering theirRecord(). key=" + key);
  log.debug("Leaving theirRecord().");
  return Object.assign({
    key: key, name: key, forms: {}, realms: {}, protocols: {}, events: [],
    eventsForgotten: 0, authentications: 0, firstAt: 0, lastAt: 0,
    isClient: false
  }, fields || {});
}

function rowOf(key) {
  log.debug("Entering rowOf(). key=" + key);
  log.debug("Leaving rowOf().");
  return stats.userRows().filter(function (r) {
    return r.key === key;
  })[0] || null;
}

module.exports = {
  name: 'user_register_fan_in',
  describe: 'the users register reads every process\'s records — another ' +
            'node\'s and this node\'s before a restart — and a ' +
            'client_credentials token makes a client, not a person',
  run: async function run(t) {
    log.debug("Entering run().");
    const client = 'fanin-client-' + STAMP;
    const person = 'fanin-person-' + STAMP;
    const elsewhere = 'fanin-elsewhere-' + STAMP;
    try {
      // --- 1. a contribution alone --------------------------------------
      replication.contribute('admin_stats.users', DEFAULT, client,
        'origin-before-restart', theirRecord(client, {
          forms: { [client]: 1 }, authentications: 1, firstAt: 1000,
          lastAt: 1000, isClient: true,
          protocols: { 'OAuth 2.0': { protocol: 'OAuth 2.0', count: 1,
            methods: { client_credentials: 1 }, firstAt: 1000,
            lastAt: 1000 } },
          events: [{ at: 1000, protocol: 'OAuth 2.0',
                     method: 'client_credentials' }]
        }));
      const alone = rowOf(client);
      t.check(alone && alone.isClient === true && alone.authentications === 1 &&
              alone.authenticated === true,
              '1. a record another process wrote is a row here, with its ' +
              'count and its isClient',
              JSON.stringify(alone && { isClient: alone.isClient,
                authentications: alone.authentications,
                authenticated: alone.authenticated }));

      // --- 2. one person, two processes ---------------------------------
      stats.recordAuthentication({ presented: person, protocol: 'OAuth 2.0',
                                   method: 'password' });
      replication.contribute('admin_stats.users', DEFAULT, person, 'node-b',
        theirRecord(person, {
          forms: { [person]: 2 }, authentications: 2, firstAt: 500,
          lastAt: 600,
          protocols: { 'OAuth 2.0': { protocol: 'OAuth 2.0', count: 2,
            methods: { password: 2 }, firstAt: 500, lastAt: 600 } },
          events: [{ at: 500, protocol: 'OAuth 2.0', method: 'password' },
                   { at: 600, protocol: 'OAuth 2.0', method: 'password' }]
        }));
      const both = rowOf(person);
      const family = both && both.protocols.filter(function (p) {
        return p.protocol === 'OAuth 2.0';
      })[0];
      t.check(both && both.authentications === 3 && both.firstAt === 500 &&
              both.events.length === 3 && both.events[0].at === 500 &&
              family && family.count === 3,
              '2. this process\'s record and another\'s for one person are ' +
              'ONE row: counts summed, the earliest first seen, the events ' +
              'merged in order',
              JSON.stringify(both && { authentications: both.authentications,
                firstAt: both.firstAt, events: both.events.length,
                family: family }));
      t.check(stats.userRows().filter(function (r) {
        return r.key === person;
      }).length === 1, '2b. and exactly one row, not one per process');

      // --- 3. knownUser --------------------------------------------------
      replication.contribute('admin_stats.users', DEFAULT, elsewhere,
        'node-c', theirRecord(elsewhere, { authentications: 1,
                                           firstAt: 700, lastAt: 700 }));
      t.check(stats.knownUser(elsewhere) === true,
              '3. knownUser() knows somebody only another process saw — ' +
              'product mode\'s enrolment door asks it');
      t.check(stats.knownUser('fanin-nobody-' + STAMP) === false,
              '3b. and still knows nobody nobody saw');

      // --- 4. the view is a copy ----------------------------------------
      rowOf(person);
      const theirs = replication.remoteRows('admin_stats.users', DEFAULT,
                                            person)[0];
      t.check(theirs.authentications === 2 && theirs.events.length === 2,
              '4. reading the merged view does not edit the other process\'s ' +
              'contribution',
              JSON.stringify({ authentications: theirs.authentications,
                               events: theirs.events.length }));
      t.check(rowOf(person).authentications === 3,
              '4b. nor this process\'s record: a second read gives the same ' +
              'sum, not a growing one');

      // --- 5. a client_credentials token --------------------------------
      const tokenClient = 'fanin-token-client-' + STAMP;
      const tokenPerson = 'fanin-token-person-' + STAMP;
      helpers.signJwt({ jti: 'fanin-cc-' + STAMP, typ: 'Bearer',
                        sub: 'urn:sts:client:' + tokenClient,
                        username: tokenClient, client_id: tokenClient,
                        exp: Math.floor(Date.now() / 1000) + 60 },
                      { grant: 'client_credentials' });
      helpers.signJwt({ jti: 'fanin-ac-' + STAMP, typ: 'Bearer',
                        sub: tokenPerson, username: tokenPerson,
                        client_id: 'some-client',
                        exp: Math.floor(Date.now() / 1000) + 60 },
                      { grant: 'authorization_code' });
      const tokenOnly = rowOf(tokenClient);
      t.check(tokenOnly && tokenOnly.isClient === true &&
              tokenOnly.authentications === 0,
              '5. a row built from a client_credentials token alone is a ' +
              'CLIENT — the users register need not have seen it',
              JSON.stringify(tokenOnly && { isClient: tokenOnly.isClient,
                tokens: tokenOnly.tokens }));
      const personToken = rowOf(tokenPerson);
      t.check(personToken && personToken.isClient === false,
              '5b. and one built from a person\'s authorization-code token ' +
              'is not', JSON.stringify(personToken && personToken.isClient));

      // --- 6. a rename folds a shared protocol family -------------------
      const from = 'fanin-rename-from-' + STAMP;
      const to = 'fanin-rename-to-' + STAMP;
      stats.recordAuthentication({ presented: from, protocol: 'SAML 2.0',
                                   method: 'sso' });
      stats.recordAuthentication({ presented: from, protocol: 'SAML 2.0',
                                   method: 'sso' });
      stats.recordAuthentication({ presented: to, protocol: 'SAML 2.0',
                                   method: 'sso' });
      stats.renameIdentity(from, to);
      const renamed = rowOf(to);
      const saml = renamed && renamed.protocols.filter(function (p) {
        return p.protocol === 'SAML 2.0';
      })[0];
      t.check(renamed && renamed.authentications === 3 && saml &&
              saml.count === 3,
              '6. a rename onto an existing row adds a protocol family\'s ' +
              'count rather than keeping one side\'s',
              JSON.stringify(saml));

      // --- 7. the users page is people ----------------------------------
      const registered = 'fanin-registered-app-' + STAMP;
      applications.createApplication({ identifier: registered,
        protocols: ['saml2'], fields: {} });
      stats.recordAssertion('2.0', { id: 'fanin-assertion-' + STAMP,
                                     subject: registered });
      const unflagged = rowOf(registered);
      t.check(unflagged && unflagged.isClient === false,
              '7. (precondition) an application seen only as an artifact\'s ' +
              'subject reaches the register with no client flag',
              JSON.stringify(unflagged && { isClient: unflagged.isClient }));
      const people = adminViews.peopleRows().rows.map(function (r) {
        return r.key;
      });
      t.check(people.indexOf(tokenClient) < 0,
              '7a. a client_credentials client is not on the users page',
              people.join(', '));
      t.check(people.indexOf(client) < 0,
              '7b. nor is a client another process flagged');
      t.check(people.indexOf(registered) < 0,
              '7c. nor is a REGISTERED application nothing flagged — the ' +
              'registry says what it is');
      t.check(people.indexOf(tokenPerson) >= 0 &&
              people.indexOf(person) >= 0,
              '7d. and the people beside them still are', people.join(', '));
      applications.deleteApplication(registered);
    } finally {
      [client, person, elsewhere].forEach(function (key) {
        ['origin-before-restart', 'node-b', 'node-c'].forEach(function (o) {
          replication.contribute('admin_stats.users', DEFAULT, key, o, null);
        });
      });
    }
    log.debug("Leaving run().");
  }
};
