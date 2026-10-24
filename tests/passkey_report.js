// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: passkey_report.js
//
// ===========================================================================
// WHO HOLDS WHICH PASSKEY ALGORITHM, AND THE COUNT IS KEPT, NOT TAKEN (#942,
// 2026-10-23).
//
// `common/passkey_report.ts` answers Monitoring → Passkeys from a BASELINE
// the recount job writes and the CHANGES the directory's key-writing doors
// note as they write. What can go wrong with that is silent — a door that
// writes keys and notes nothing leaves the page wrong until the next
// recount, and nothing fails — so asserted here, in one throwaway realm:
//
//   A. A PERSON'S FACETS: the kind is the ALGORITHM (ML-DSA is
//      post-quantum), never the lane; a value that is not a key counts for
//      nothing; each key counts once under its algorithm and lane and once
//      under its AAGUID.
//   B. THE RECOUNT: the report after it equals a count of every person
//      made here, by kind, algorithm and model; before it there is no
//      baseline and the page says "not counted".
//   C. THE CHANGES: an enrolment, a removal, a rename and a person deleted
//      each move the report at once with no recount; a rename notes
//      nothing (it changes no facet).
//   D. THE TWO AGREE: a recount after the changes gives the numbers the
//      changes had already given.
//   E. NO COUNT READS THE DIRECTORY: the report with no list asks the
//      directory's scan nothing.
//   F. THE FILTERS: a group counts its members only; two filters, a profile
//      nobody named, the default profile and an unknown application are
//      refused with STS-AUTHN-0414.
//   G. THE LISTS: each kind's list is exactly its people; a list paged one
//      row at a time by the `from` cursor visits each of them once; one
//      algorithm, one model and the people with no passkey.
//   H. THE EXPORT: CSV with a header and a row per person, and a cell a
//      spreadsheet would read as a formula quoted.
//   I. THE JOB AND THE ACT: the recount is registered with the scheduler,
//      and an unknown action is refused with STS-AUTHN-0416.
//
// WHY IN PROCESS: what is asserted is which function the doors call and
// how often the report asks the directory, which only a spy inside the
// process can see; `tests/vendored/sts_passkey_report.js` drives the
// operation over HTTP.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const realms = require('../common/realms');
const errorCodes = require('../common/error_codes');
const credentials = require('../common/credentials');
const ldap = require('../ldap/ldap_server');
const report = require('../common/passkey_report');

const log = require('bunyan').createLogger({ name: 'passkey_report',
  level: process.env.LOG_LEVEL || 'info' });

const STAMP = nodeCrypto.randomBytes(3).toString('hex');
const REALM = 'pkr' + STAMP;
const MODEL = 'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4';
const JWK = { kty: 'EC', crv: 'P-256', x: 'a', y: 'b' };

// One key as `credentials.addKey()` takes it, with the algorithm recorded.
function key(id, algorithm, coseAlg, aaguid) {
  log.debug("Entering key().");
  log.debug("Leaving key().");
  return { credentialId: id, publicKeyJwk: JWK, signCount: 0,
           algorithm: algorithm, coseAlg: coseAlg,
           aaguid: aaguid ? aaguid.replace(/-/g, '') : undefined };
}

function nameOf(what) {
  log.debug("Entering nameOf().");
  log.debug("Leaving nameOf().");
  return 'pkr-' + STAMP + '-' + what;
}

function facets(t) {
  log.debug("Entering facets().");
  t.log.info('=== A. a person\'s facets ===');
  const values = [
    JSON.stringify(key('a1', 'ML-DSA-65', -49, MODEL)),
    JSON.stringify(Object.assign(key('a2', 'ES256', -7), { lane: 'pqc' })),
    'not json a client wrote'
  ];
  const f = report.facetsOfValues(values, 'someone');
  t.equal(f.kind, 'both', 'A1. an ML-DSA key and an ES256 key are both');
  t.equal(f.counts['k|ML-DSA-65|-49|classical'], 1,
          'A2. the ML-DSA key counts under its algorithm, in the lane its ' +
          'row records (none: classical)');
  t.equal(f.counts['k|ES256|-7|pqc'], 1,
          'A3. the ES256 key counts in the pqc lane its row names — and ' +
          'still as classical: the kind is the algorithm, not the lane');
  t.equal(f.counts['m|' + MODEL + '|ML-DSA-65|-49'], 1,
          'A4. and once under its AAGUID');
  t.equal(f.keys.length, 2, 'A5. a value that is not a key counts for ' +
          'nothing');
  t.equal(report.facetsOfValues([], 'nobody').kind, 'none',
          'A6. no key is the kind none, with no person facet');
  t.equal(report.attestationFacetOf({}), null,
          'A7. no attestation algorithm is read before #941 records one');
  log.debug("Leaving facets().");
}

// The people this test makes, and what each holds.
const PEOPLE = {
  pq: [key('pq-1', 'ML-DSA-65', -49, MODEL)],
  cl: [key('cl-1', 'ES256', -7)],
  both: [key('both-1', 'ML-DSA-44', -48, MODEL), key('both-2', 'RS256',
                                                     -257)],
  none: []
};

function seed(t) {
  log.debug("Entering seed().");
  Object.keys(PEOPLE).forEach(function (who) {
    const name = nameOf(who);
    const made = ldap.createUser(name, { invent: false, origin: 'test' });
    t.check(made && made.ok, 'seeded ' + name,
            JSON.stringify(made && made.errors));
    PEOPLE[who].forEach(function (k) {
      const added = credentials.addKey(name, k, 'primary');
      t.check(added && added.ok, 'enrolled ' + k.credentialId + ' for ' +
              name, JSON.stringify(added && added.errors));
    });
  });
  log.debug("Leaving seed().");
}

async function recount(t) {
  log.debug("Entering recount().");
  t.log.info('=== B. the recount ===');
  report.resetForTests();
  const before = await report.reportAsync({});
  t.equal(before.counted, null, 'B1. before a recount there is no ' +
          'baseline, and the page says so');
  const ran = await report.recountAsync({ stillOwner: function () {
    return true;
  }, trigger: 'test' });
  t.check(ran.holders >= 3, 'B2. the recount read every holder',
          JSON.stringify(ran));
  const v = await report.reportAsync({});
  t.equal(v.counted && v.counted.from, 'baseline', 'B3. the report is the ' +
          'baseline now');
  t.equal(v.people.postQuantumOnly, 1, 'B4. one post-quantum only');
  t.equal(v.people.classicalOnly, 1, 'B5. one classical only');
  t.equal(v.people.both, 1, 'B6. one with both');
  t.equal(v.people.total, ldap.personCount(), 'B7. the total is the ' +
          'directory\'s count of its people');
  t.equal(v.people.none, ldap.personCount() - 3, 'B8. and none is the ' +
          'rest');
  const mldsa = (v.keys.byAlgorithm || []).filter(function (r) {
    return r.algorithm === 'ML-DSA-65';
  })[0] || {};
  t.check(mldsa.count === 1 && mldsa.postQuantum === true,
          'B9. ML-DSA-65 is one post-quantum key', JSON.stringify(mldsa));
  t.equal(v.keys.total, 4, 'B10. four keys in all');
  const model = (v.models || []).filter(function (m) {
    return m.aaguid === MODEL;
  })[0] || {};
  t.check(model.total === 2 && model.postQuantum === true &&
          model.algorithms.length === 2,
          'B11. the model holds two keys of two algorithms',
          JSON.stringify(model));
  log.debug("Leaving recount().");
  return v;
}

async function changes(t) {
  log.debug("Entering changes().");
  t.log.info('=== C. the changes, noted as they are written ===');
  const noneName = nameOf('none');
  t.check(credentials.addKey(noneName, key('none-1', 'ML-DSA-87', -50),
                             'primary').ok, 'C0. none enrols an ML-DSA-87');
  let v = await report.reportAsync({});
  t.equal(v.people.postQuantumOnly, 2, 'C1. an enrolment moves the report ' +
          'at once, with no recount');
  t.check(v.counted.changesSince >= 1, 'C2. and is counted as a change ' +
          'since the baseline', JSON.stringify(v.counted));
  const notes = v.counted.changesSince;
  const renamed = credentials.renameKey(nameOf('cl'), 'cl-1', 'Work key');
  t.check(renamed && renamed.ok, 'C3. a rename is written',
          JSON.stringify(renamed));
  v = await report.reportAsync({});
  t.equal(v.counted.changesSince, notes, 'C4. and notes nothing: it moves ' +
          'no facet');
  const removed = credentials.removeKey(nameOf('both'), 'both-1');
  t.check(removed && removed.ok !== false, 'C5. a removal is written',
          JSON.stringify(removed));
  v = await report.reportAsync({});
  t.equal(v.people.both, 0, 'C6. the person who held both holds classical ' +
          'only now');
  t.equal(v.people.classicalOnly, 2, 'C7. and is counted there');
  const stored = ldap.existingUserEntry(nameOf('pq'));
  const gone = ldap.deletePerson(stored && stored.dn);
  t.check(gone && gone.ok, 'C8. a person is deleted',
          JSON.stringify(gone));
  v = await report.reportAsync({});
  t.equal(v.people.postQuantumOnly, 1, 'C9. and their passkey leaves the ' +
          'report with them');
  log.debug("Leaving changes().");
  return v;
}

async function agree(t, kept) {
  log.debug("Entering agree().");
  t.log.info('=== D. a recount agrees with the changes ===');
  await report.recountAsync({ stillOwner: function () {
    return true;
  }, trigger: 'test' });
  const fresh = await report.reportAsync({});
  ['postQuantumOnly', 'classicalOnly', 'both', 'none', 'holding']
    .forEach(function (name) {
      t.equal(fresh.people[name], kept.people[name], 'D. ' + name +
              ' is what the changes had made it');
    });
  t.equal(JSON.stringify(fresh.keys.byAlgorithm),
          JSON.stringify(kept.keys.byAlgorithm),
          'D. and every algorithm\'s count');
  t.equal(fresh.counted.changesSince, 0, 'D. and no change is noted since');
  log.debug("Leaving agree().");
}

async function noScan(t) {
  log.debug("Entering noScan().");
  t.log.info('=== E. no count reads the directory ===');
  let scans = 0;
  // The directory's three, counted through a wrapper installed on the
  // report's own slot, and put back after.
  const counted = {
    scanAsync: function (ask) {
      scans += 1;
      return ldap.passkeyScanAsync(ask);
    },
    populationAsync: function (selectors, limit) {
      return ldap.passkeyPopulationAsync(selectors, limit);
    },
    personCount: function () {
      return ldap.personCount();
    }
  };
  report.setDirectory(counted);
  try {
    await report.reportAsync({});
    t.equal(scans, 0, 'E1. the report reads no person: its counts are the ' +
            'aggregate');
    await report.reportAsync({ list: 'post-quantum-only' });
    t.check(scans >= 1, 'E2. a list does read holders, after a cursor',
            String(scans));
  } finally {
    report.setDirectory({ scanAsync: ldap.passkeyScanAsync,
                          populationAsync: ldap.passkeyPopulationAsync,
                          personCount: ldap.personCount });
  }
  log.debug("Leaving noScan().");
}

async function filters(t) {
  log.debug("Entering filters().");
  t.log.info('=== F. the filters ===');
  const group = 'pkr-group-' + STAMP;
  const made = ldap.createGroup(group, { origin: 'test' });
  t.check(made && made.ok, 'F0. a group is made', JSON.stringify(made));
  ldap.addGroupMember(group, nameOf('cl'), { origin: 'test' });
  ldap.addGroupMember(group, nameOf('none'), { origin: 'test' });
  const v = await report.reportAsync({ group: group });
  t.equal(v.filter.scope, 'group', 'F1. the scope is the group');
  t.equal(v.people.total, 2, 'F2. its two members are counted');
  t.equal(v.people.classicalOnly, 1, 'F3. one classical only');
  t.equal(v.people.postQuantumOnly, 1, 'F4. one post-quantum only');
  const missing = await report.reportAsync({ group: 'pkr-no-such-' + STAMP });
  t.check(missing.population && missing.population.groups[0] &&
          missing.population.groups[0].found === false,
          'F5. a group that is not here is counted as empty, and said',
          JSON.stringify(missing.population));
  [[{ group: group, profile: 'x' }, 'two filters'],
   [{ profile: 'pkr-no-such-' + STAMP }, 'a profile nobody named'],
   [{ profile: 'default' }, 'the default profile'],
   [{ application: 'pkr-no-such-' + STAMP }, 'an unknown application']]
    .forEach(function (pair) {
      const refused = report.filterOf(pair[0]);
      t.check(!refused.ok && errorCodes.codeOf(refused) === 'STS-AUTHN-0414',
              'F6. ' + pair[1] + ' is refused, coded STS-AUTHN-0414',
              JSON.stringify(refused));
    });
  log.debug("Leaving filters().");
}

async function lists(t) {
  log.debug("Entering lists().");
  t.log.info('=== G. the lists ===');
  const names = function (v) {
    return ((v.list && v.list.rows) || []).map(function (r) {
      return r.username;
    }).filter(function (n) {
      return n.indexOf('pkr-' + STAMP) === 0;
    }).sort();
  };
  const pq = await report.reportAsync({ list: 'post-quantum-only' });
  t.equal(JSON.stringify(names(pq)), JSON.stringify([nameOf('none')]),
          'G1. the post-quantum only list is exactly its people');
  const cl = await report.reportAsync({ list: 'classical-only' });
  t.equal(JSON.stringify(names(cl)),
          JSON.stringify([nameOf('both'), nameOf('cl')].sort()),
          'G2. and the classical only list');
  // One row a page, by the cursor, until the end.
  const seen = [];
  let from = '';
  for (let page = 1; page < 20; page++) {
    const v = await report.reportAsync({ list: 'holding', per: '1',
                                         page: String(page), from: from });
    (v.list.rows || []).forEach(function (r) {
      seen.push(r.username);
    });
    if (!v.list.paging.hasNext) {
      break;
    }
    from = v.list.paging.nextFrom;
  }
  const mine = seen.filter(function (n) {
    return n.indexOf('pkr-' + STAMP) === 0;
  });
  t.equal(mine.length, 3, 'G3. paged one at a time by the cursor, every ' +
          'holder is visited', JSON.stringify(seen));
  t.equal(new Set(seen).size, seen.length, 'G4. and none twice');
  const alg = await report.reportAsync({ list: 'algorithm',
                                         algorithm: 'ML-DSA-87' });
  t.equal(JSON.stringify(names(alg)), JSON.stringify([nameOf('none')]),
          'G5. one algorithm\'s list');
  const none = await report.reportAsync({ list: 'none', per: '500' });
  t.check(names(none).length === 0 &&
          (none.list.rows || []).every(function (r) {
            return r.kind === 'none';
          }), 'G6. the people with no passkey hold none',
          JSON.stringify(none.list.rows));
  log.debug("Leaving lists().");
}

async function exported(t) {
  log.debug("Entering exported().");
  t.log.info('=== H. the export ===');
  const file = await report.exportAsync({ list: 'holding', format: 'csv' });
  t.check(file.ok && /^username,dn,kind,passkeys,/.test(file.body),
          'H1. a CSV with its header', String(file.body).slice(0, 80));
  t.check(file.body.indexOf(nameOf('cl')) >= 0, 'H2. carrying the people');
  const cell = report.PasskeyReport['csvCell'];
  t.equal(cell('=HYPERLINK("x")'), '"\'=HYPERLINK(""x"")"',
          'H3. a formula is quoted with an apostrophe in front');
  const json = await report.exportAsync({ list: 'holding', format: 'json' });
  t.check(json.ok && JSON.parse(json.body).rows.length >= 3,
          'H4. and JSON with every row');
  log.debug("Leaving exported().");
}

function jobAndAct(t) {
  log.debug("Entering jobAndAct().");
  t.log.info('=== I. the job and the act ===');
  const scheduler = require('../cluster/scheduler');
  t.check(!!scheduler.job(report.RECOUNT_JOB), 'I1. the recount is a ' +
          'scheduler job');
  const refused = report.act({ action: 'nonsense' }, { actor: 'test' });
  t.check(!refused.ok && errorCodes.codeOf(refused) === 'STS-AUTHN-0416',
          'I2. an unknown action is refused, coded', JSON.stringify(refused));
  t.equal(report.noteKeysChanged({ not: 'an array' }, null, 'x'), false,
          'I3. a note handed nonsense notes nothing and throws nothing');
  log.debug("Leaving jobAndAct().");
}

async function run(t) {
  log.debug("Entering run().");
  facets(t);
  const made = realms.create({ id: REALM, name: REALM,
                               description: 'Created by ' + __filename });
  if (!made.ok) {
    t.bad('could not create the realm', (made.errors || []).join(' '));
    log.debug("Leaving run().");
    return;
  }
  try {
    await realms.run(made.realm, async function () {
      seed(t);
      await recount(t);
      const kept = await changes(t);
      await agree(t, kept);
      await noScan(t);
      await filters(t);
      await lists(t);
      await exported(t);
      jobAndAct(t);
    });
  } finally {
    realms.remove(REALM);
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'passkey_report',
  describe: 'the passkey report (#942): who holds which algorithm, counted ' +
            'by the recount and kept by the directory\'s key-writing doors, ' +
            'never by a scan per request; its filters, cursor-paged lists, ' +
            'export, job and act',
  run: run
};
