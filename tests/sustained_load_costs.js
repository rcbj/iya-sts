// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: sustained_load_costs.js
//
// ===========================================================================
// WHAT A PASSWORD WRITE AND A SIGN-IN COST DOES NOT GROW WITH THE POPULATION
// (#754, 2026-10-20).
//
// A sustained load on 8081 — a million `userPassword` writes over LDAPS and
// the authorization code flow for a million people, both at once — lost
// half its pace in an hour on two request workers. Three costs grew with
// the population; this file holds the two that live in process (the third,
// `sts_sessions_surface`, is a schema object and `tests/postgres_schema.js`
// holds it).
//
//   A. THE HOT DIRECTORY WRITERS NAME THEIR DN. An LDAP modify and the
//      consent every authorization records (`Consent.noteApplied()` ->
//      `addValues()`) reach `persistence.directoryChanged()` with the
//      entry's DN. With none, the next flush in a windowed process is
//      `DirectoryWindow.collect(null)`, which serialises every entry the
//      window holds — per write, and more as the window fills.
//      A passkey's writes name theirs too (#908): the counter rewrite runs
//      on every passkey sign-in.
//   B. A REALM'S SESSION COUNT IS NOT ASKED PER SIGN-IN FAR FROM THE CAP.
//      `SessionWindow.countForAdmission()` asks the store's `session.count`
//      (a scan of the realm's index rows) once per 10 s while the count is
//      more than a margin below `authn.maxSessions`, every time within the
//      margin, and again once its answer is 10 s old.
//
// WHAT NEEDS A STACK: the pace itself, against postgres and a populated
// directory — the load that found it (`../load-users/sessions-1m`, outside
// this repository).
// ===========================================================================

delete process.env.CONFIG_FILE;

const persistence = require('../persistence/persistence');
const ldapServer = require('../ldap/ldap_server');
const consent = require('../common/consent');
const sessionWindow = require('../authn/session_window');

const log = require('bunyan').createLogger({ name: 'sustained_load_costs',
  level: process.env.LOG_LEVEL || 'info' });

const BASE = 'dc=example,dc=com';
const USERS = 'ou=users,' + BASE;

// Every DN `persistence.directoryChanged()` is handed while `fn` runs. The
// directory calls it through the module's export, so wrapping the export is
// what it reaches.
function changesDuring(fn) {
  log.debug("Entering changesDuring().");
  const seen = [];
  const original = persistence.directoryChanged;
  persistence.directoryChanged = function (dn) {
    log.debug("Entering the recording directoryChanged().");
    seen.push(dn);
    log.debug("Leaving the recording directoryChanged().");
    return original.apply(persistence, arguments);
  };
  return Promise.resolve()
    .then(fn)
    .then(function (answer) {
      persistence.directoryChanged = original;
      log.debug("Leaving changesDuring().");
      return { seen: seen, answer: answer };
    }, function (e) {
      log.debug("Caught in changesDuring(): " + ((e && e.message) || e));
      persistence.directoryChanged = original;
      log.debug("Leaving changesDuring(). Threw.");
      throw e;
    });
}

// A request as the socket presents one, through the codec a worker runs.
function operation(name, fields) {
  log.debug("Entering operation().");
  const ldap = require('ldapjs');
  const req = {
    connection: { encrypted: true,
                  ldap: { bindDN: 'cn=admin,' + BASE,
                          id: 'sustained-load-costs' },
                  remoteAddress: '127.0.0.1', remotePort: 40000 }
  };
  req.dn = ldap.parseDN(fields.dn);
  if (fields.attributes) {
    req.attributes = fields.attributes;
  }
  if (fields.changes) {
    req.changes = fields.changes;
  }
  const shape = ldapServer.operationRequest(name, req);
  log.debug("Leaving operation().");
  return Promise.resolve(ldapServer.performOperation(name,
    JSON.parse(JSON.stringify(shape))));
}

function unnamed(seen) {
  log.debug("Entering unnamed().");
  log.debug("Leaving unnamed().");
  return seen.filter(function (dn) {
    return dn === undefined || dn === null || dn === '';
  }).length;
}

async function directoryWritesNameTheirDn(t) {
  log.debug("Entering directoryWritesNameTheirDn().");
  t.log.info('=== A. the hot directory writers name their DN ===');
  const ldap = require('ldapjs');
  const uid = 'load-cost-probe';
  const dn = 'uid=' + uid + ',' + USERS;
  const added = await operation('add', {
    dn: dn,
    attributes: [{ type: 'objectClass', values: ['top', 'inetOrgPerson'] },
                 { type: 'uid', values: [uid] },
                 { type: 'cn', values: ['Load Cost Probe'] },
                 { type: 'sn', values: ['Probe'] }]
  });
  t.check(added.ok === true, 'A0. the probe person is added',
          added.error || '');

  const modified = await changesDuring(function () {
    return operation('modify', {
      dn: dn,
      changes: [new ldap.Change({
        operation: 'replace',
        modification: new ldap.Attribute({ type: 'description',
                                           values: ['written once'] })
      })]
    });
  });
  t.check(modified.answer.ok === true, 'A1. the modify succeeds',
          modified.answer.error || '');
  t.check(modified.seen.length > 0 && unnamed(modified.seen) === 0,
          'A2. every directory change an LDAP modify reports names a DN',
          JSON.stringify(modified.seen));
  t.check(modified.seen.some(function (one) {
    return String(one).toLowerCase() === dn.toLowerCase();
  }), 'A3. and one of them is the modified entry',
          JSON.stringify(modified.seen));

  const applied = await changesDuring(function () {
    return consent.noteApplied(uid, 'load-cost-client',
                               ['openid', 'profile']);
  });
  t.check(applied.answer && applied.answer.stored === true,
          'A4. the consent an authorization applied is recorded',
          JSON.stringify(applied.answer));
  t.check(applied.seen.length > 0 && unnamed(applied.seen) === 0,
          'A5. and every directory change it reports names a DN',
          JSON.stringify(applied.seen));
  t.check(applied.seen.every(function (one) {
    return String(one).toLowerCase() === dn.toLowerCase();
  }), 'A6. the person\'s own entry, and nothing else',
          JSON.stringify(applied.seen));

  // A passkey added, then rewritten — the rewrite is the one every passkey
  // sign-in makes to its signature counter (#908).
  const credentials = require('../common/credentials');
  const keyId = 'load-cost-key-' + process.pid;
  const keyAdded = await changesDuring(function () {
    return credentials.addKey(uid, {
      credentialId: keyId,
      publicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'a', y: 'b' },
      signCount: 0 });
  });
  t.check(keyAdded.answer && keyAdded.answer.ok === true,
          'A6a. a passkey is recorded for the probe person',
          JSON.stringify(keyAdded.answer));
  t.check(keyAdded.seen.length > 0 && unnamed(keyAdded.seen) === 0,
          'A6b. and every directory change it reports names a DN (#908)',
          JSON.stringify(keyAdded.seen));
  const keyRewritten = await changesDuring(function () {
    return credentials.renameKey(uid, keyId, 'Rewritten');
  });
  t.check(keyRewritten.seen.length > 0 && unnamed(keyRewritten.seen) === 0 &&
          keyRewritten.seen.every(function (one) {
            return String(one).toLowerCase() === dn.toLowerCase();
          }),
          'A6c. a rewrite of the key, as a sign-in\'s counter update makes, ' +
          'names the person\'s own entry and nothing else (#908)',
          JSON.stringify(keyRewritten.seen));

  // Tidied up: this directory is module-wide (tests/CLAUDE.md).
  const removed = await operation('del', { dn: dn });
  t.check(removed.ok === true, 'A7. the probe person is deleted again',
          removed.error || '');
  log.debug("Leaving directoryWritesNameTheirDn().");
}

// `session.count` answers `n`; every other question has nothing to say.
function countingQuery(state) {
  log.debug("Entering countingQuery().");
  log.debug("Leaving countingQuery().");
  return function (name) {
    if (name === 'session.count') {
      state.asked += 1;
      return { n: state.n };
    }
    return [];
  };
}

function admit(n, realm, cap) {
  log.debug("Entering admit().");
  let unread = 0;
  for (let i = 0; i < n; i++) {
    const size = sessionWindow.countForAdmission(realm, cap);
    if (size === null) {
      unread += 1;
    } else if (size < cap) {
      sessionWindow.noteAdmitted(realm);
    }
  }
  log.debug("Leaving admit().");
  return unread;
}

function sessionCountIsNotAskedPerSignIn(t) {
  log.debug("Entering sessionCountIsNotAskedPerSignIn().");
  t.log.info('=== B. a realm\'s session count is not asked per sign-in ' +
             'far from the cap ===');
  const realm = 'sustained-load-costs';
  const state = { asked: 0, n: 4500 };
  const realNow = Date.now;
  let now = realNow();
  Date.now = function () {
    return now;
  };
  try {
    sessionWindow.resetForTests();
    sessionWindow.setQuery(countingQuery(state));

    // Far from a cap of 1,100,000: one question for five hundred sign-ins.
    const unread = admit(500, realm, 1100000);
    t.equal(unread, 0, 'B0. every admission had an answer');
    t.equal(state.asked, 1,
            'B1. 500 admissions far from the cap ask session.count once');
    t.equal(sessionWindow.countForAdmission(realm, 1100000), 4500 + 500,
            'B2. and the answer is the store\'s count plus this process\'s ' +
            'admissions since');

    // Ten seconds on, the store is asked again.
    now += 10001;
    const before = state.asked;
    sessionWindow.countForAdmission(realm, 1100000);
    t.equal(state.asked, before + 1,
            'B3. an answer 10 s old is asked again');

    // Within the margin of a cap (the larger of 1,000 and 1%), every
    // admission asks, as before #754.
    sessionWindow.resetForTests();
    sessionWindow.setQuery(countingQuery(state));
    state.asked = 0;
    state.n = 99500;
    admit(5, realm, 100000);
    t.equal(state.asked, 5,
            'B4. 500 below a cap of 100,000 every admission asks');

    // Approaching the margin from outside: the cached answer serves until
    // count + admissions + margin reaches the cap, and then the store is
    // asked.
    sessionWindow.resetForTests();
    sessionWindow.setQuery(countingQuery(state));
    state.asked = 0;
    state.n = 98000;
    admit(1001, realm, 100000);
    t.equal(state.asked, 2,
            'B5. from 2,000 below a cap of 100,000, the 1,001st admission ' +
            'asks again (the margin is 1,000)');

    // Each realm has a count of its own.
    sessionWindow.resetForTests();
    sessionWindow.setQuery(countingQuery(state));
    state.asked = 0;
    state.n = 10;
    admit(3, realm, 1100000);
    admit(3, realm + '-other', 1100000);
    t.equal(state.asked, 2, 'B6. two realms, one question each');
  } finally {
    Date.now = realNow;
    sessionWindow.resetForTests();
  }
  log.debug("Leaving sessionCountIsNotAskedPerSignIn().");
}

async function run(t) {
  log.debug("Entering run().");
  await directoryWritesNameTheirDn(t);
  sessionCountIsNotAskedPerSignIn(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'sustained_load_costs',
  describe: 'a password write and a sign-in cost the same at any population ' +
            '(#754): the hot directory writers name their DN, and the ' +
            'realm\'s session count is not asked per admission far from ' +
            'the cap',
  run: run
};
