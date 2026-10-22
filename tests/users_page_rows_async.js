// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: users_page_rows_async.js
//
// ===========================================================================
// /admin-api/users DECORATES ITS PAGE WITHOUT A BLOCKING READ PER PERSON
// (#820, 2026-10-22).
//
// On 8081 (product, postgres, four request workers, ~660,000 people, a
// sign-in load) the console said `/admin/users` "could not be drawn". The log
// carried STS-AUTHN-0071, -0065 and -0080 wrapping STS-LDAP-0175 (the
// request's 5,000 ms store budget) and fourteen STS-OAUTH-0513 "Knex: Timeout
// acquiring a connection": `usersListJson()` decorated each shown row through
// `decoratePerson()` -> `credentials.factorHolderRow()` -> `mechanismsFor()`,
// about nine SYNCHRONOUS directory reads a row, plus `personDnOf()` — fifty
// rows' worth charged to one request.
//
// The API's two doors (`usersJsonAsync()`, `mfaRosterJsonAsync()`) now page
// with `deferDecoration` and hand the shown rows to `usersListRowsAsync()`,
// which reads every row's credentials and DN together and asynchronously
// (`credentials.factorHolderRowsAsync()`, `credentials.personDnsAsync()`).
//
// Asserted, in a realm of its own seeded with a mix of credentials:
//
//   1. each door, for page one, a later page, a `?factor=` filter and a
//      `?q=` filter, asks `mechanismsFor()` NOT ONCE and the device store's
//      `personDnOf` NOT ONCE — the per-row synchronous reads the old path
//      made — and asks the asynchronous doors instead;
//   2. it answers, member for member, what the synchronous view answers for
//      the same request (the console's page, which still decorates a row at
//      a time) — DNs, factors and live sessions included;
//   3. a store that refuses the batched read (STS-LDAP-0175) still draws the
//      page, each row's factors UNKNOWN (null) rather than "none", and its
//      DN empty; and a batched read that throws for any other reason is
//      asked one row at a time, giving the synchronous answer.
//
// WHY IN PROCESS: the claim is about which functions are CALLED per request,
// which only a spy inside the process can count.
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const realms = require('../common/realms');
const credentials = require('../common/credentials');
const errorCodes = require('../common/error_codes');
const ldap = require('../ldap/ldap_server');
const adminViews = require('../admin-core/admin_views');

const log = require('bunyan').createLogger({
  name: 'users_page_rows_async',
  level: process.env.LOG_LEVEL || 'info' });

const STAMP = Date.now().toString(36);
const REALM = 'upra' + STAMP.slice(-6);
const PEOPLE = 240;
const PER = 50;

// ---------------------------------------------------------------------------
// The spies: what the old path read one row at a time, and what the new one
// reads together. `failWith` makes the two batched hooks throw.
// ---------------------------------------------------------------------------
const counts = { mechanisms: 0, rowOne: 0, dnOne: 0, rowsAsync: 0,
                 dnsAsync: 0 };
const fault = { failWith: null };

function installSpies() {
  log.debug("Entering installSpies().");
  const proto = credentials.Credentials.prototype;
  const realMechanisms = proto.mechanismsFor;
  const realRow = proto.factorHolderRow;
  const realDeviceStore = proto.deviceStore;
  const realHook = proto.directoryHook;
  proto.mechanismsFor = function () {
    counts.mechanisms += 1;
    return realMechanisms.apply(this, arguments);
  };
  proto.factorHolderRow = function () {
    counts.rowOne += 1;
    return realRow.apply(this, arguments);
  };
  proto.deviceStore = function (name) {
    if (name === 'personDnOf') {
      counts.dnOne += 1;
    }
    return realDeviceStore.apply(this, arguments);
  };
  proto.directoryHook = function (name) {
    const hook = realHook.apply(this, arguments);
    if (!hook || (name !== 'credentialRowsAsync' &&
                  name !== 'personDnsAsync')) {
      return hook;
    }
    return async function () {
      if (name === 'credentialRowsAsync') {
        counts.rowsAsync += 1;
      } else {
        counts.dnsAsync += 1;
      }
      if (fault.failWith) {
        throw fault.failWith();
      }
      return hook.apply(this, arguments);
    };
  };
  log.debug("Leaving installSpies().");
  return function restore() {
    log.debug("Entering restore().");
    proto.mechanismsFor = realMechanisms;
    proto.factorHolderRow = realRow;
    proto.deviceStore = realDeviceStore;
    proto.directoryHook = realHook;
    log.debug("Leaving restore().");
  };
}

function reset() {
  log.debug("Entering reset().");
  Object.keys(counts).forEach(function (key) {
    counts[key] = 0;
  });
  log.debug("Leaving reset().");
}

// ---------------------------------------------------------------------------
// SEEDING: people through `createUser()`, their credential attributes then
// set on the stored entry in the shapes `credentials.ts` writes.
// ---------------------------------------------------------------------------
function nameOf(i) {
  log.debug("Entering nameOf().");
  log.debug("Leaving nameOf().");
  return 'upra-' + STAMP + '-' + String(i).padStart(4, '0');
}

function keyValue(id, role) {
  log.debug("Entering keyValue().");
  log.debug("Leaving keyValue().");
  return JSON.stringify({ credentialId: id, role: role, signCount: 0,
                          publicKeyJwk: { kty: 'EC', crv: 'P-256',
                                          x: 'AA', y: 'AA' } });
}

function seed(t) {
  log.debug("Entering seed().");
  for (let i = 0; i < PEOPLE; i++) {
    const name = nameOf(i);
    const made = ldap.createUser(name, { invent: false, origin: 'test' });
    if (!made || !made.ok) {
      t.bad('seeding ' + name, JSON.stringify(made && made.errors));
      log.debug("Leaving seed(). A create failed.");
      return false;
    }
    const a = ldap.existingUserEntry(name).attributes;
    if (i % 3 === 0) {
      a.userpassword = ['$scrypt$seeded-presence-only'];
    }
    const keys = [];
    if (i % 7 === 0) {
      keys.push(keyValue('mfa-' + i, 'mfa'));
    }
    if (i % 11 === 0) {
      keys.push(keyValue('primary-' + i, 'primary'));
    }
    if (i === 99) {
      keys.push('not json a client wrote');
    }
    if (keys.length) {
      a.stswebauthncredential = keys;
    }
    if (i % 17 === 0) {
      a.ststotpcredential = [JSON.stringify({
        secret: 'JBSWY3DPEHPK3PXP', sealed: false, algorithm: 'SHA1',
        digits: 6, period: 30, enrolledAt: 1000, lastUsedAt: 0 })];
    } else if (i === 31) {
      a.ststotpcredential = ['not json either'];
    }
    if (i % 23 === 0) {
      a.stsbackupcodes = [JSON.stringify({ version: 2, total: 0,
        remaining: 0, generatedAt: 1000, lastUsedAt: 0, sealed: false,
        hashed: true, vault: '[]' })];
    }
    if (i % 41 === 0) {
      a.mail = [name + '@example.org'];
      a.stsmailverified = [name + '@example.org'];
      a.stsmailfactor = ['code'];
    }
  }
  log.debug("Leaving seed().");
  return true;
}

// The whole answer, as JSON: the two must agree member for member.
function same(t, got, wanted, what) {
  log.debug("Entering same().");
  const a = JSON.stringify(got);
  const b = JSON.stringify(wanted);
  let at = 0;
  while (at < a.length && a[at] === b[at]) {
    at++;
  }
  t.check(a === b, what, a === b ? a.length + ' bytes alike'
    : 'first difference at ' + at + ': got …' + a.slice(at, at + 160) +
      '… wanted …' + b.slice(at, at + 160) + '…');
  log.debug("Leaving same().");
}

// ---------------------------------------------------------------------------
// 1 and 2: no per-row synchronous read, and the same answer.
// ---------------------------------------------------------------------------
async function doors(t) {
  log.debug("Entering doors().");
  const queries = [{}, { page: '3' }, { factor: 'totp' }, { factor: 'none' },
                   { q: '-' + STAMP + '-01' }];
  for (const query of queries) {
    const req = { query: Object.assign({ per: String(PER) }, query) };
    reset();
    const got = await adminViews.usersJsonAsync(req);
    const asked = Object.assign({}, counts);
    const shown = (got.users || []).length;
    t.check(shown > 0, '(precondition) usersJsonAsync(' +
            JSON.stringify(query) + ') shows rows', String(shown));
    t.equal(asked.mechanisms, 0, '1a. usersJsonAsync(' +
            JSON.stringify(query) + ') asks mechanismsFor() for no row');
    t.equal(asked.rowOne, 0, '1b. and factorHolderRow() for no row');
    t.equal(asked.dnOne, 0, '1c. and personDnOf for no row');
    t.check(asked.rowsAsync === 1 && asked.dnsAsync === 1,
            '1d. it asks the two batched doors once each',
            JSON.stringify(asked));
    t.check((got.users || []).every(function (row) {
      return !!row.dn;
    }), '1e. every shown row carries its DN');
    same(t, got, adminViews.usersJson(req),
         '2a. usersJsonAsync(' + JSON.stringify(query) + ') answers what ' +
         'usersJson() answers');
  }
  reset();
  const roster = await adminViews.mfaRosterJsonAsync({ query:
    { per: String(PER) } });
  const asked = Object.assign({}, counts);
  t.check(asked.mechanisms === 0 && asked.rowOne === 0 && asked.dnOne === 0,
          '1f. mfaRosterJsonAsync() makes no per-row synchronous read',
          JSON.stringify(asked));
  same(t, roster, adminViews.mfaRosterJson({ query: { per: String(PER) } }),
       '2b. mfaRosterJsonAsync() answers what mfaRosterJson() answers');
  log.debug("Leaving doors().");
}

// ---------------------------------------------------------------------------
// 3: a refusing store, and a store that throws otherwise.
// ---------------------------------------------------------------------------
async function failures(t) {
  log.debug("Entering failures().");
  const req = { query: { per: String(PER) } };
  fault.failWith = function () {
    return errorCodes.mark(new Error('the store budget was spent'),
                           'STS-LDAP-0175');
  };
  let refused = null;
  try {
    reset();
    refused = await adminViews.usersJsonAsync(req);
  } finally {
    fault.failWith = null;
  }
  const rows = (refused && refused.users) || [];
  t.equal(rows.length, PER, '3a. a refused store still draws the page');
  t.check(rows.every(function (row) {
    return row.factors === null;
  }), '3b. each row\'s factors are unknown (null), not "none"');
  t.check(rows.every(function (row) {
    return row.dn === '';
  }), '3c. and drawn without a DN');
  t.check(counts.mechanisms === 0 && counts.dnOne === 0,
          '3d. and nothing is asked one row at a time instead',
          JSON.stringify(counts));
  fault.failWith = function () {
    return new Error('not a store refusal');
  };
  let fallen = null;
  try {
    reset();
    fallen = await adminViews.usersJsonAsync(req);
  } finally {
    fault.failWith = null;
  }
  same(t, fallen, adminViews.usersJson(req),
       '3e. any other throw is asked one row at a time, giving the ' +
       'synchronous answer');
  log.debug("Leaving failures().");
}

async function run(t) {
  log.debug("Entering run().");
  const made = realms.create({ id: REALM, name: REALM,
                               description: 'Created by ' + __filename });
  if (!made.ok) {
    t.bad('could not create the realm', (made.errors || []).join(' '));
    log.debug("Leaving run().");
    return;
  }
  const restore = installSpies();
  try {
    await realms.run(made.realm, async function () {
      config.setOverride('ldap.maxEntries', '100000');
      try {
        if (seed(t)) {
          await doors(t);
          await failures(t);
        }
      } finally {
        config.clearOverride('ldap.maxEntries');
      }
    });
  } finally {
    restore();
    realms.remove(REALM);
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'users_page_rows_async',
  describe: '/admin-api/users and /admin-api/mfa decorate their page with ' +
            'no synchronous read per row (#820), and answer what the ' +
            'synchronous views answer',
  run: run
};
