// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
// File: attribute_sources.js
// ===========================================================================
// ATTRIBUTE SOURCES: PEOPLE'S ATTRIBUTES FROM AN OPERATOR'S DATABASE (#94
// part C).
//
// The register and the refresh, in process, with the DATABASE STUBBED: the
// driver (`attribute_source_drivers.ts`, Knex) is replaced by one that
// answers rows from a table held here, so what is held is everything this
// service decides — the protocol job against a real PostgreSQL is
// `tests/vendored/`'s. Held here:
//   A. a definition is refused for mail, an attribute this service keeps, a
//      name that is not an identifier, a dialect this step does not read, an
//      attribute another source writes, and a host
//      attributeSources.hostPatterns does not allow;
//   B. a sign-in writes the row onto the entry, with provenance, and tells
//      the account observers once; a NULL column removes the attribute;
//   C. a failure keeps what the entry holds, or refuses the sign-in where
//      the source says refuse (STS-ATTR-0012);
//   D. `once` reads a person the first time only;
//   E. the scheduled refresh pages through the realm's people after a
//      cursor;
//   F. refresh-person and test-source, and the sign-in gate in authn;
//   G. a source's own CA chain, set on the console: stored, described,
//      refused when it is not certificates or is expired, and trusted alone
//      unless the source also asks for the public roots. The certificates
//      are made here, at test time — no key material is committed.
// In a throwaway realm.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const realms = require('../common/realms');
const config = require('../common/config');
const errorCodes = require('../common/error_codes');
const ldap = require('../ldap/ldap_server');
const authn = require('../authn/authn');
const attributeSources = require('../attribute-sources/attribute_sources');
const stsCrypto = require('../common/crypto');
const OutboundTls = require('../common/outbound_tls');

const log = require('bunyan').createLogger({ name: 'attribute_sources',
  level: process.env.LOG_LEVEL || 'info' });

const RUN = nodeCrypto.randomBytes(3).toString('hex');
const ALICE = 'as-alice-' + RUN;
const BOB = 'as-bob-' + RUN;

// THE DATABASE: rows by key, and a switch to make it fail.
const table = {};
const calls = [];
let failing = null;
const drivers = {
  lookup: async function (realmId, source, key) {
    calls.push(source.id + ':' + key);
    if (failing) {
      throw errorCodes.mark(new Error('the database is down'), failing);
    }
    const row = table[key];
    if (!row) {
      return null;
    }
    const out = {};
    Object.keys(source.columns).forEach(function (column) {
      const value = row[column];
      out[column] = value === null || value === undefined ? []
        : [].concat(value).map(String);
    });
    return out;
  },
  close: function () {}
};

const register = new attributeSources.AttributeSources(Object.assign(
  attributeSources.AttributeSources.defaultDeps(), { drivers: drivers }));

function source(id, extra) {
  log.debug('Entering source(). ' + id);
  log.debug('Leaving source().');
  return Object.assign({ action: 'add-source', id: id, dialect: 'postgres',
    host: 'db.example.com', database: 'hr', user: 'reader',
    table: 'people', keyColumn: 'login', keyAttribute: 'uid',
    columns: { cost_center: 'costCenter' }, refresh: ['sign-in'] },
    extra || {});
}

function attributesOf(name) {
  log.debug('Entering attributesOf(). ' + name);
  const held = ldap.objectFor(name).entry.attributes;
  const out = {};
  Object.keys(held).forEach(function (key) {
    out[key.toLowerCase()] = [].concat(held[key]);
  });
  log.debug('Leaving attributesOf().');
  return out;
}

async function refusals(t) {
  log.debug('Entering refusals().');
  t.log.info('=== A. what a definition may not say ===');
  const cases = [
    ['mail', source('as-a1', { columns: { email: 'mail' } }),
     'STS-ATTR-0008'],
    ['a credential', source('as-a2', { columns: { x: 'stsTotpCredential' } }),
     'STS-ATTR-0008'],
    ['group membership', source('as-a3', { columns: { g: 'memberOf' } }),
     'STS-ATTR-0008'],
    ['an identifier', source('as-a4', { table: 'people; drop table x' }),
     'STS-ATTR-0005'],
    ['a dialect not read yet', source('as-a5', { dialect: 'mssql' }),
     'STS-ATTR-0005']
  ];
  for (const one of cases) {
    const result = await register.act(one[1], { actor: 'test' });
    t.check(result.ok === false && errorCodes.codeOf(result) === one[2],
            'A. ' + one[0] + ' is refused with ' + one[2],
            JSON.stringify(result) + ' ' + errorCodes.codeOf(result));
  }
  config.setOverride('attributeSources.hostPatterns', '*.internal.example');
  const host = await register.act(source('as-a6'), { actor: 'test' });
  config.clearOverride('attributeSources.hostPatterns');
  t.check(host.ok === false && errorCodes.codeOf(host) === 'STS-ATTR-0010',
          'A. a host the realm\'s patterns do not allow is refused',
          errorCodes.codeOf(host));
  log.debug('Leaving refusals().');
}

async function signIn(t) {
  log.debug('Entering signIn().');
  t.log.info('=== B. a sign-in writes the row ===');
  const made = await register.act(source('hr', {
    columns: { cost_center: 'costCenter', grade: 'employeeType' },
    refresh: ['sign-in', 'schedule', 'on-demand'] }), { actor: 'test' });
  t.check(made.ok === true, 'B1. a source is added', JSON.stringify(made));
  const clash = await register.act(source('as-clash', {
    columns: { cc: 'costCenter' } }), { actor: 'test' });
  t.check(clash.ok === false && errorCodes.codeOf(clash) === 'STS-ATTR-0009',
          'B2. a second source for the same attribute is refused',
          errorCodes.codeOf(clash));
  ldap.createUser(ALICE, { invent: false, attributes: {} });
  ldap.createUser(BOB, { invent: false, attributes: {} });
  table[ALICE] = { cost_center: 'CC-7', grade: 'A' };
  table[BOB] = { cost_center: 'CC-9', grade: null };
  const told = [];
  ldap.addAccountObserver(function (change) {
    if (change && change.username === ALICE) {
      told.push(change.kind);
    }
  });
  const outcome = await register.refreshAtSignIn(ALICE);
  const alice = attributesOf(ALICE);
  t.check(!outcome.refused && alice.costcenter[0] === 'CC-7' &&
          alice.employeetype[0] === 'A',
          'B3. the row is on the entry', JSON.stringify(alice.costcenter));
  t.check((alice.stsattributesourced || []).indexOf('hr:costCenter') >= 0 &&
          (alice.stsattributesourceseen || []).some(function (one) {
            return one.indexOf('hr=') === 0;
          }),
          'B4. with provenance: what the source wrote and when it read',
          JSON.stringify(alice.stsattributesourced));
  t.check(told.length === 1 && told[0] === 'updated',
          'B5. and the account observers were told once',
          JSON.stringify(told));
  await register.refreshAtSignIn(ALICE);
  t.check(told.length === 1,
          'B6. a sign-in that changes nothing tells nobody',
          JSON.stringify(told));
  table[ALICE] = { cost_center: 'CC-7', grade: null };
  await register.refreshPerson(ALICE, 'on-demand');
  t.check(!attributesOf(ALICE).employeetype,
          'B7. a NULL column removes the attribute');
  log.debug('Leaving signIn().');
}

async function failures(t) {
  log.debug('Entering failures().');
  t.log.info('=== C. a source that cannot be read ===');
  // A change to the source drops its rows from the burst cache, so this
  // sign-in asks the database.
  await register.act({ action: 'update-source', id: 'hr', timeoutMs: 2000 },
                     { actor: 'test' });
  failing = 'STS-ATTR-0002';
  const kept = await register.refreshAtSignIn(ALICE);
  t.check(kept.refused === false &&
          attributesOf(ALICE).costcenter[0] === 'CC-7',
          'C1. keep: the sign-in proceeds with what the entry holds',
          JSON.stringify(kept));
  const view = register.view().sources.filter(function (one) {
    return one.id === 'hr';
  })[0];
  t.check(view && view.status && view.status.lastCode === 'STS-ATTR-0002',
          'C2. and the source\'s status says why',
          JSON.stringify(view && view.status));
  await register.act({ action: 'update-source', id: 'hr',
                       onFailure: 'refuse' }, { actor: 'test' });
  const refused = await register.refreshAtSignIn(ALICE);
  t.check(refused.refused === true && refused.code === 'STS-ATTR-0012',
          'C3. refuse: the sign-in is refused, STS-ATTR-0012',
          JSON.stringify(refused));
  failing = null;
  await register.act({ action: 'update-source', id: 'hr',
                       onFailure: 'keep' }, { actor: 'test' });
  log.debug('Leaving failures().');
}

async function once(t) {
  log.debug('Entering once().');
  t.log.info('=== D. once ===');
  await register.act(source('badge', { keyColumn: 'login',
    columns: { badge: 'employeeNumber' }, refresh: ['once'] }),
    { actor: 'test' });
  table[BOB].badge = 'B-1';
  calls.length = 0;
  await register.refreshAtSignIn(BOB);
  await register.refreshAtSignIn(BOB);
  const reads = calls.filter(function (one) {
    return one.indexOf('badge:') === 0;
  });
  t.check(reads.length === 1 &&
          attributesOf(BOB).employeenumber[0] === 'B-1',
          'D1. a once source reads a person the first time only',
          JSON.stringify(reads));
  log.debug('Leaving once().');
}

async function scheduled(t) {
  log.debug('Entering scheduled().');
  t.log.info('=== E. the scheduled refresh ===');
  table[BOB].cost_center = 'CC-11';
  config.setOverride('attributeSources.refreshBatch', '1');
  const pages = [];
  let guard = 0;
  let run;
  do {
    run = await register.runScheduled({ params: { source: 'hr' },
                                        stillOwner: function () {
                                          return true;
                                        } });
    pages.push(run.sources.filter(function (one) {
      return one.source === 'hr';
    })[0]);
    guard++;
  } while (pages[pages.length - 1] && !pages[pages.length - 1].ended &&
           guard < 50);
  config.clearOverride('attributeSources.refreshBatch');
  t.check(pages.length >= 2 && pages[pages.length - 1].ended &&
          attributesOf(BOB).costcenter[0] === 'CC-11',
          'E1. the refresh pages through the people after a cursor and ' +
          'writes each', JSON.stringify(pages));
  log.debug('Leaving scheduled().');
}

async function acts(t) {
  log.debug('Entering acts().');
  t.log.info('=== F. the acts, and the sign-in gate ===');
  table[ALICE].cost_center = 'CC-8';
  const tested = await register.act({ action: 'test-source', id: 'hr',
                                      username: ALICE }, { actor: 'test' });
  t.check(tested.ok && tested.found && tested.row.cost_center[0] === 'CC-8' &&
          attributesOf(ALICE).costcenter[0] === 'CC-7',
          'F1. test-source reads the row and writes nothing',
          JSON.stringify(tested));
  const person = await register.act({ action: 'refresh-person',
                                      username: ALICE }, { actor: 'test' });
  t.check(person.ok && attributesOf(ALICE).costcenter[0] === 'CC-8',
          'F2. refresh-person writes it', JSON.stringify(person));
  const unknown = await register.act({ action: 'frob' }, { actor: 'test' });
  t.check(unknown.ok === false &&
          /The six are: add-source, update-source, remove-source, /.test(
            (unknown.errors || []).join(' ')),
          'F3. an unknown action names the six', JSON.stringify(unknown));
  let went = false;
  authn.afterSignIn({ locals: {} }, function () {
    went = true;
  }, function () {});
  t.check(went, 'F4. afterSignIn() goes on at once where no session was ' +
          'started');
  const removed = await register.act({ action: 'remove-source', id: 'badge' },
                                     { actor: 'test' });
  t.check(removed.ok && attributesOf(BOB).employeenumber[0] === 'B-1',
          'F5. removing a source keeps what it wrote', JSON.stringify(removed));
  log.debug('Leaving acts().');
}

async function trustChain(t) {
  log.debug('Entering trustChain().');
  t.log.info('=== G. the CA chain ===');
  const ca = stsCrypto.selfSignedRsaCertificate({ commonName: 'HR DB CA ' +
                                                  RUN, years: 1 });
  const made = await register.act(source('as-tls', {
    columns: { office: 'physicalDeliveryOfficeName' },
    caCertificates: ca.certPem }), { actor: 'test' });
  const row = register.view().sources.filter(function (one) {
    return one.id === 'as-tls';
  })[0];
  t.check(made.ok && row && row.trust.certificates.length === 1 &&
          /HR DB CA/.test(row.trust.certificates[0].subject) &&
          /^[0-9a-f:]+$/.test(row.trust.certificates[0].sha256) &&
          row.trust.publicRoots === false,
          'G1. a pasted chain is stored and described, and trusted alone',
          JSON.stringify(row && row.trust));
  await register.act({ action: 'update-source', id: 'as-tls',
                       trustPublicRoots: true }, { actor: 'test' });
  t.check(register.view().sources.filter(function (one) {
    return one.id === 'as-tls';
  })[0].trust.publicRoots === true,
          'G2. the public roots are added only when the source asks');
  const garbage = await register.act({ action: 'update-source', id: 'as-tls',
    caCertificates: '-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydA==\n' +
                    '-----END CERTIFICATE-----' }, { actor: 'test' });
  t.check(garbage.ok === false &&
          errorCodes.codeOf(garbage) === 'STS-ATTR-0015',
          'G3. a block that is not a certificate is refused, STS-ATTR-0015',
          errorCodes.codeOf(garbage));
  const later = new attributeSources.AttributeSources(Object.assign(
    attributeSources.AttributeSources.defaultDeps(), { drivers: drivers,
      now: function () {
        return Date.now() + 5 * 365 * 24 * 3600 * 1000;
      } }));
  const expired = await later.act(source('as-old', {
    columns: { room: 'roomNumber' }, caCertificates: ca.certPem }),
    { actor: 'test' });
  t.check(expired.ok === false &&
          errorCodes.codeOf(expired) === 'STS-ATTR-0015' &&
          /expired/.test((expired.errors || []).join(' ')),
          'G4. an expired certificate is refused', JSON.stringify(expired));
  const alone = OutboundTls.verifiedOptions(ca.certPem,
                                            { systemRoots: false });
  const beside = OutboundTls.verifiedOptions(ca.certPem);
  t.check(alone.ca.length === 1 && beside.ca.length > 1,
          'G5. the TLS options hold the chain alone, or with the public ' +
          'roots', alone.ca.length + ' / ' + beside.ca.length);
  await register.act({ action: 'remove-source', id: 'as-tls' },
                     { actor: 'test' });
  log.debug('Leaving trustChain().');
}

async function run(t) {
  log.debug('Entering run().');
  const realm = realms.create({ id: 'as-' + RUN,
                                name: 'attribute sources ' + RUN }).realm;
  try {
    await realms.run(realm, async function () {
      await refusals(t);
      await signIn(t);
      await failures(t);
      await once(t);
      await scheduled(t);
      await acts(t);
      await trustChain(t);
    });
  } finally {
    realms.remove(realm.id);
  }
  log.debug('Leaving run().');
}

module.exports = {
  name: 'attribute_sources',
  describe: 'Attribute sources (#94), with the database stubbed: the ' +
            'definition refusals, the sign-in write with provenance, keep ' +
            'and refuse on failure, once, the scheduled refresh\'s paging, ' +
            'test-source, refresh-person and the sign-in gate',
  run: run
};
