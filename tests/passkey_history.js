// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: passkey_history.js
//
// ===========================================================================
// THE PASSKEY HISTORY, AND THE SOURCE THAT READS IT (#1109, 2026-10-28).
//
// `common/passkey_report.ts`'s recount now writes one row of
// `passkey_report.history` per realm per UTC day, and removes the rows
// older than `webauthn.passkeyHistoryDays`; the reports application reads
// them as `passkeyHistory`. Asserted here:
//
//   A. THE ROW, over a `PasskeyReport` built on doubles and a clock this
//      file moves: a recount writes the day's row with people by kind,
//      passkeys by algorithm, lane and attestation algorithm, and each
//      named profile's bounded population (not the default profile, not a
//      profile with no group); a second recount the same day replaces the
//      row; the next day is a second row; a population that throws leaves
//      that profile uncounted and the row written; profiles past
//      HISTORY_PROFILES are named and not read; a run that stops being
//      this process's writes no row; a store that throws fails nothing.
//   B. THE RETENTION: the rows older than the setting are removed by the
//      next recount, the day itself counted as the first of the days; the
//      setting's default is 400.
//   C. THE CATALOG: the `passkeyHistory` source, its fields and three
//      predefined queries, each one the validator accepts and the New
//      Query form can draw.
//   D. THE SOURCE, over the real module in a throwaway realm: the rows a
//      real recount wrote (and one an earlier day wrote) projected by
//      scope, and the "post-quantum adoption by day" preset run through
//      `report/sources.ts`, one row a day, oldest first.
//   E. OVER /report-api, in a child process with the whole stack: the
//      catalog publishes the source and its presets, and the adoption
//      preset run over the API answers the realm's row for today.
//
// WHY IN PROCESS (A-D): the clock, the population double and a store that
// throws are only reachable inside the process; E is the API.
// ===========================================================================

delete process.env.CONFIG_FILE;

const path = require('path');
const os = require('os');
const fs = require('fs');
const childProcess = require('child_process');
const nodeCrypto = require('crypto');

const log = require('bunyan').createLogger({ name: 'passkey_history',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const DAY = 24 * 60 * 60 * 1000;
const T0 = Date.parse('2026-10-01T12:00:00.000Z');
const MODEL = 'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4';
const JWK = { kty: 'EC', crv: 'P-256', x: 'a', y: 'b' };

// One stored key value, as the directory holds it.
function keyValue(id, algorithm, coseAlg, extra) {
  log.debug("Entering keyValue().");
  log.debug("Leaving keyValue().");
  return JSON.stringify(Object.assign({ credentialId: id, publicKeyJwk: JWK,
    signCount: 0, algorithm: algorithm, coseAlg: coseAlg,
    aaguid: MODEL.replace(/-/g, '') }, extra || {}));
}

// The people of the double: name → values.
const HOLDERS = {
  'a-pq': [keyValue('k1', 'ML-DSA-65', -49, { lane: 'pqc' })],
  'b-cl': [keyValue('k2', 'ES256', -7, { attestation: { algorithms: {
    certificates: [{ algorithm: 'ML-DSA-87', postQuantum: true }] } } })],
  'c-both': [keyValue('k3', 'ML-DSA-44', -48, { lane: 'pqc' }),
             keyValue('k4', 'ES256', -7)],
  'd-cl': [keyValue('k5', 'RS256', -257)]
};
// Everybody the double's directory holds: the holders and two with none.
const PEOPLE = 6;

// A directory double with the three functions the slot asks for.
function directoryDouble(state) {
  log.debug("Entering directoryDouble().");
  const names = Object.keys(HOLDERS).sort();
  const out = {
    scanAsync: async function (ask) {
      let read = 0;
      let last = ask.after;
      const after = names.filter(function (n) {
        return n > ask.after;
      });
      for (let i = 0; i < after.length && read < ask.readLimit; i++) {
        ask.accept({ id: after[i], dn: 'uid=' + after[i],
                     values: HOLDERS[after[i]] });
        read += 1;
        last = after[i];
      }
      return { next: last, read: read, done: true };
    },
    populationAsync: async function (selectors, limit) {
      state.populations += 1;
      if (selectors.indexOf('broken') >= 0) {
        throw new Error('the group could not be read');
      }
      // The group `staff` is a-pq, c-both and one person with no passkey.
      const rows = [{ id: 'a-pq', dn: 'uid=a-pq', values: HOLDERS['a-pq'] },
        { id: 'c-both', dn: 'uid=c-both', values: HOLDERS['c-both'] },
        { id: 'e-none', dn: 'uid=e-none', values: [] }].slice(0, limit);
      return { groups: [{ asked: selectors[0], dn: 'cn=' + selectors[0],
                          found: true, members: 3 }],
               rows: rows, members: 3, complete: true };
    },
    personCount: function () {
      return PEOPLE;
    }
  };
  log.debug("Leaving directoryDouble().");
  return out;
}

// A PasskeyReport over Maps, a clock, the profiles and the directory above.
function built(profiles) {
  log.debug("Entering built().");
  const passkeyReport = require('../common/passkey_report');
  const helpers = require('../common/helpers');
  const state = { now: T0, days: 400, populations: 0, n: 0 };
  const history = new Map();
  const deps = Object.assign(passkeyReport.PasskeyReport.defaultDeps(), {
    baseline: new Map(), changes: new Map(), history: history,
    historyDays: function () {
      return state.days;
    },
    remoteRows: function () {
      return [];
    },
    refreshContributions: function () {
      return Promise.resolve(0);
    },
    passkeyPolicy: function () {
      return { list: function () {
        return profiles;
      } };
    },
    randomId: function () {
      state.n += 1;
      return 'epoch-' + state.n;
    },
    now: function () {
      return state.now;
    },
    log: helpers.log
  });
  const instance = new passkeyReport.PasskeyReport(deps);
  instance.setDirectory(directoryDouble(state));
  log.debug("Leaving built().");
  return { instance: instance, state: state, history: history };
}

const OWNER = { stillOwner: function () {
  return true;
}, trigger: 'test' };

const PROFILES = [
  { name: 'default', postQuantumRequired: 'off', selectGroups: [] },
  { name: 'staff', postQuantumRequired: 'warn', precedence: 10,
    selectGroups: ['staff'] },
  { name: 'apps-only', postQuantumRequired: 'off', precedence: 20,
    selectGroups: [], selectApplications: ['x'] },
  { name: 'broken', postQuantumRequired: 'off', precedence: 30,
    selectGroups: ['broken'] }
];

async function theRow(t) {
  log.debug("Entering theRow().");
  t.log.info('=== A. the day\'s row ===');
  const b = built(PROFILES);
  const ran = await b.instance.recountAsync(OWNER);
  const day = '2026-10-01';
  t.check(ran.history && ran.history.written === true &&
          ran.history.day === day, 'A1. the recount wrote the day\'s row',
          JSON.stringify(ran.history));
  t.check(/history row for 2026-10-01 was written/.test(ran.summary),
          'A2. and its summary says so', ran.summary);
  const row = b.history.get(day);
  t.check(!!row, 'A3. keyed by the UTC day');
  if (!row) {
    log.debug("Leaving theRow(). No row.");
    return;
  }
  t.equal(JSON.stringify([row.people.total, row.people.holding,
    row.people.postQuantumOnly, row.people.classicalOnly, row.people.both,
    row.people.none, row.people.withPostQuantum]),
    JSON.stringify([6, 4, 1, 2, 1, 2, 2]),
    'A4. people by kind: one post-quantum only, two classical only, one ' +
    'both, two with none of six');
  t.equal(row.keys.total, 5, 'A5. five passkeys');
  t.equal(row.keys.postQuantum, 2, 'A6. two of them ML-DSA');
  t.equal(JSON.stringify(row.keys.byLane), JSON.stringify({ classical: 3,
    pqc: 2 }), 'A7. by lane');
  const es256 = row.keys.byAlgorithm.filter(function (a) {
    return a.algorithm === 'ES256';
  })[0] || {};
  t.equal(es256.count, 2, 'A8. by algorithm: two ES256');
  t.equal(JSON.stringify(row.attestation), JSON.stringify([{
    algorithm: 'ML-DSA-87', coseAlg: -50, postQuantum: true, count: 1 }]),
    'A9. by attestation algorithm');
  t.equal(row.epoch, 'epoch-1', 'A10. under the baseline\'s epoch');
  t.check(row.models === undefined && JSON.stringify(row).indexOf(MODEL) <
          0, 'A11. and no model table');
  const names = row.profiles.map(function (p) {
    return p.name;
  });
  t.equal(names.join(','), 'staff,broken',
    'A12. the named profiles that select by group; not the default, not ' +
    'one with no group');
  const staff = row.profiles[0];
  t.equal(JSON.stringify([staff.counted, staff.members, staff.complete,
    staff.people.holding, staff.people.withPostQuantum, staff.people.none,
    staff.postQuantumRequired]),
    JSON.stringify([true, 3, true, 2, 2, 1, 'warn']),
    'A13. staff\'s population counted: three members, both holders with ' +
    'ML-DSA, one with none');
  t.equal(JSON.stringify([row.profiles[1].counted, row.profiles[1].why]),
    JSON.stringify([false, 'its population could not be read']),
    'A14. a population that throws leaves that profile uncounted ' +
    '(STS-AUTHN-0522) and the row written');

  b.state.now = T0 + 3 * 60 * 60 * 1000;
  await b.instance.recountAsync(OWNER);
  t.equal(b.history.size, 1, 'A15. a second recount the same day ' +
          'replaces the day\'s row');
  t.equal(b.history.get(day).epoch, 'epoch-2', 'A16. with its own count');
  b.state.now = T0 + DAY;
  await b.instance.recountAsync(OWNER);
  t.equal(Array.from(b.history.keys()).sort().join(','),
    '2026-10-01,2026-10-02', 'A17. the next day is a second row');
  t.equal(b.instance.historyRows().map(function (r) {
    return r.day;
  }).join(','), '2026-10-01,2026-10-02', 'A18. read oldest first');

  // Past HISTORY_PROFILES named profiles, the rest are named, not read.
  const report = require('../common/passkey_report');
  const many = [];
  for (let i = 0; i < report.HISTORY_PROFILES + 2; i++) {
    many.push({ name: 'p' + String(i).padStart(3, '0'),
                postQuantumRequired: 'off', selectGroups: ['staff'] });
  }
  const m = built(many);
  await m.instance.recountAsync(OWNER);
  const mrow = m.history.get('2026-10-01');
  t.equal(m.state.populations, report.HISTORY_PROFILES,
    'A19. at most ' + report.HISTORY_PROFILES + ' populations are read');
  t.equal(mrow && mrow.profiles.filter(function (p) {
    return !p.counted && /past the/.test(p.why);
  }).length, 2, 'A20. and the profiles past them are named as not counted');

  // A run that stops being this process's while the profiles are counted.
  const f = built(PROFILES);
  let asked = 0;
  const fenced = await f.instance.recountAsync({ stillOwner: function () {
    asked += 1;
    // The recount asks once before its slice; the profiles ask after.
    return asked < 2;
  } });
  t.check(fenced.history && fenced.history.written === false &&
          f.history.size === 0,
          'A21. a run fenced while counting the profiles writes no row',
          JSON.stringify(fenced.history));

  // A store that throws fails nothing.
  const s = built([]);
  s.history.set = function () {
    throw new Error('the store refused');
  };
  const failed = await s.instance.recountAsync(OWNER);
  t.check(failed.holders === 4 && failed.history.written === false,
    'A22. a history store that throws leaves the recount counted ' +
    '(STS-AUTHN-0520)', JSON.stringify(failed));
  log.debug("Leaving theRow().");
}

async function retention(t) {
  log.debug("Entering retention().");
  t.log.info('=== B. the retention ===');
  const b = built([]);
  for (let d = 0; d < 6; d++) {
    b.state.now = T0 + d * DAY;
    await b.instance.recountAsync(OWNER);
  }
  t.equal(b.history.size, 6, 'B1. six days, six rows');
  b.state.days = 3;
  b.state.now = T0 + 6 * DAY;
  const ran = await b.instance.recountAsync(OWNER);
  t.equal(Array.from(b.history.keys()).sort().join(','),
    '2026-10-05,2026-10-06,2026-10-07',
    'B2. keeping three days keeps today and the two before it');
  t.equal(ran.history.pruned, 4, 'B3. the recount removed four rows');
  t.check(/older one\(s\) removed/.test(ran.summary),
    'B4. and its summary says so', ran.summary);
  b.state.days = 1;
  t.equal(b.instance.pruneHistory(T0 + 6 * DAY), 2,
    'B5. one day keeps today alone');
  const passkeyReport = require('../common/passkey_report');
  t.equal(passkeyReport.PasskeyReport.defaultDeps().historyDays(), 400,
    'B6. webauthn.passkeyHistoryDays is 400 by default');
  const config = require('../common/config');
  const row = config.SETTINGS.filter(function (s) {
    return s.key === 'webauthn.passkeyHistoryDays';
  })[0] || {};
  t.equal(JSON.stringify([row.type, row.dflt, row.min, row.max,
    row.runtime]), JSON.stringify(['int', 400, 1, 3660, true]),
    'B7. a config.js row: an int, 1 to 3660, changeable while running');
  const tiers = require('../persistence/tiers');
  t.equal(tiers.mintedTierOf(passkeyReport.HISTORY_HANDLE), 'cell',
    'B8. the store is the cell tier\'s');
  log.debug("Leaving retention().");
}

function catalogChecks(t) {
  log.debug("Entering catalogChecks().");
  t.log.info('=== C. the catalog ===');
  const Catalog = require('../report/catalog');
  const Limits = require('../report/limits');
  const Query = require('../report/query');
  const catalog = new Catalog();
  const src = catalog.source('passkeyHistory');
  if (!t.check(!!src, 'C1. passkeyHistory is a source')) {
    log.debug("Leaving catalogChecks(). No source.");
    return;
  }
  const ids = src.fields.map(function (f) {
    return f.id;
  });
  ['day', 'countedAt', 'scope', 'name', 'coseAlg', 'lane', 'postQuantum',
   'count', 'people', 'holding', 'postQuantumOnly', 'classicalOnly', 'both',
   'none', 'withPostQuantum', 'postQuantumShare', 'postQuantumKeys',
   'postQuantumRequired', 'members', 'complete', 'counted']
    .forEach(function (id) {
      t.check(ids.indexOf(id) >= 0, 'C2. passkeyHistory has ' + id);
    });
  t.equal(JSON.stringify(catalog.field('passkeyHistory', 'scope').values),
    JSON.stringify(['realm', 'profile', 'algorithm', 'lane', 'attestation']),
    'C3. scope is one of five words');
  t.check(catalog.field('passkeyHistory', 'scope').group &&
          catalog.field('passkeyHistory', 'name').group,
          'C4. a count may group by scope and by name');
  t.equal(src.anchored, undefined, 'C5. not anchored: the history store, ' +
          'not the directory');
  const limits = Limits.fixed({ syncMaxRows: 1000, asyncMaxRows: 5000,
                                pdfMaxRows: 100 });
  const presets = src.presets || [];
  t.equal(presets.map(function (p) {
    return p.id;
  }).join(','), 'post-quantum-adoption-by-day,passkeys-by-algorithm-by-day,' +
    'profile-adoption-by-day', 'C6. the three predefined queries');
  t.equal(presets[0] && presets[0].name, 'Post-quantum adoption by day',
    'C7. the first is post-quantum adoption by day');
  presets.forEach(function (p) {
    const asked = new Query({ catalog: catalog, limits: limits })
      .validate(p.document);
    t.equal(asked.ok, true, 'C8. ' + p.id + ' validates', asked.description);
    const doc = p.document;
    t.check(!doc.where || (doc.where.op !== 'and' && doc.where.op !== 'or'),
      'C9. ' + p.id + ' has at most one filter leaf, so the form can draw ' +
      'it');
    t.check(!doc.orderBy || doc.orderBy.length <= 1,
      'C10. ' + p.id + ' orders by at most one field');
  });
  log.debug("Leaving catalogChecks().");
}

async function theSource(t) {
  log.debug("Entering theSource().");
  t.log.info('=== D. the source over the real module ===');
  const realms = require('../common/realms');
  const ldap = require('../ldap/ldap_server');
  const credentials = require('../common/credentials');
  const report = require('../common/passkey_report');
  const sources = require('../report/sources');
  const Catalog = require('../report/catalog');
  const Limits = require('../report/limits');
  const Query = require('../report/query');
  const stamp = nodeCrypto.randomBytes(3).toString('hex');
  const REALM = 'pkh' + stamp;
  const made = realms.create({ id: REALM, name: REALM,
                               description: 'Created by ' + __filename });
  if (!made.ok) {
    t.bad('D0. could not create the realm', (made.errors || []).join(' '));
    log.debug("Leaving theSource().");
    return;
  }
  const catalog = new Catalog();
  const limits = Limits.fixed({ syncMaxRows: 1000, asyncMaxRows: 5000,
                                pdfMaxRows: 100 });
  try {
    await realms.run(made.realm, async function () {
      const who = 'pkh-' + stamp;
      ldap.createUser(who, { invent: false, origin: 'test' });
      const added = credentials.addKey(who, JSON.parse(keyValue('d1',
        'ML-DSA-65', -49)), 'primary');
      t.check(added && added.ok, 'D1. a person with an ML-DSA passkey',
              JSON.stringify(added && added.errors));
      report.resetForTests();
      // An earlier day, written from a baseline of its own.
      const earlier = await report.writeHistoryAsync({
        countedAt: new Date(Date.now() - 2 * DAY).toISOString(),
        epoch: 'earlier', trigger: 'test', holders: 0, durationMs: 0,
        counts: {} }, OWNER);
      t.equal(earlier.written, true, 'D2. an earlier day\'s row');
      const ran = await report.recountAsync(OWNER);
      t.check(ran.history && ran.history.written,
              'D3. the real recount wrote today\'s row',
              JSON.stringify(ran.history));
      const flat = sources.passkeyHistoryRows(report.historyRows());
      const scopes = {};
      flat.forEach(function (r) {
        scopes[r.scope] = (scopes[r.scope] || 0) + 1;
      });
      t.equal(scopes.realm, 2, 'D4. one realm row a day');
      t.check(scopes.algorithm >= 1, 'D5. and the algorithm rows',
              JSON.stringify(scopes));
      const mldsa = flat.filter(function (r) {
        return r.scope === 'algorithm' && r.name === 'ML-DSA-65';
      })[0] || {};
      t.equal(JSON.stringify([mldsa.coseAlg, mldsa.postQuantum,
        mldsa.count]), JSON.stringify([-49, true, 1]),
        'D6. ML-DSA-65: one post-quantum passkey');
      const asked = new Query({ catalog: catalog, limits: limits })
        .validate(catalog.preset('passkeyHistory',
          'post-quantum-adoption-by-day').document);
      const answer = await sources.read(asked.plan, {
        startedMs: Date.now(), budgetMs: 5000, execution: 'sync' });
      const rows = (answer && answer.rows) || [];
      t.equal(rows.length, 2, 'D7. the adoption preset: one row a day',
              JSON.stringify(answer && answer.description));
      t.check(rows.length === 2 && rows[0].day < rows[1].day,
              'D8. oldest first');
      const today = rows[1] || {};
      t.check(today.withPostQuantum === 1 && today.postQuantumShare === 100 &&
              today.holding === 1 && today.postQuantumKeys === 1,
              'D9. today: the one holder holds ML-DSA, 100 percent',
              JSON.stringify(today));
      t.equal(rows[0] && rows[0].postQuantumShare, null,
              'D10. a day with no holder has no share, not 0');
    });
  } finally {
    realms.remove(REALM);
  }
  log.debug("Leaving theSource().");
}

// ---------------------------------------------------------------------------
// E. In a child process. Runs there, stringified, so it uses nothing from
// this file's scope and — code in a `node -e` child — is exempt from the
// Entering/Leaving rule (root CLAUDE.md, *Code style*).
// ---------------------------------------------------------------------------
function childMain() {
  const ROOT_DIR = process.env.PKH_ROOT;
  const OUT = process.env.PKH_OUT;
  const http = require('http');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  function call(port, method, urlPath, token, body) {
    return new Promise(function (resolve, reject) {
      const text = body === undefined ? null : JSON.stringify(body);
      const headers = { accept: 'application/json' };
      if (token) {
        headers.authorization = 'Bearer ' + token;
      }
      if (text) {
        headers['content-type'] = 'application/json';
        headers['content-length'] = Buffer.byteLength(text);
      }
      const req = http.request({ host: '127.0.0.1', port: port,
                                 path: urlPath, method: method,
                                 headers: headers }, function (res) {
        let raw = '';
        res.on('data', function (d) { raw += d; });
        res.on('end', function () {
          let json = null;
          try {
            json = JSON.parse(raw);
          } catch (e) {
            // Not JSON; the finding reports the text.
            json = null;
          }
          resolve({ status: res.statusCode, text: raw, json: json });
        });
      });
      req.on('error', reject);
      if (text) {
        req.write(text);
      }
      req.end();
    });
  }
  const brief = function (r) {
    return r.status + ' ' + (r.text || '').slice(0, 300);
  };

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    const realms = require(ROOT_DIR + '/common/realms');
    const oauth2 = require(ROOT_DIR + '/oauth-oidc/oauth2');
    const ldap = require(ROOT_DIR + '/ldap/ldap_server');
    const helpers = require(ROOT_DIR + '/common/helpers');
    const applications = require(ROOT_DIR + '/common/applications');
    const report = require(ROOT_DIR + '/common/passkey_report');
    const stamp = String(process.pid);
    const ADMIN = 'pkh-admin-' + stamp;
    const CLIENT = 'pkh-client-' + stamp;

    ldap.createUser(ADMIN, { invent: false });
    ldap.addGroupMember('report-admins', ADMIN, { actor: 'test' });
    applications.createApplication({ identifier: CLIENT,
      protocols: ['oauth2'],
      fields: { oauthClientId: CLIENT,
                oauthTokenEndpointAuthMethod: ['client_secret_basic'],
                oauthAllowedScope: ['openid', 'report:use',
                                    'report:admin'] } });
    const ran = await realms.run(realms.DEFAULT_REALM, function () {
      return report.recountAsync({ stillOwner: function () {
        return true;
      }, trigger: 'test' });
    });
    note(ran && ran.history && ran.history.written,
         'E1. a recount in the default realm wrote its history row',
         JSON.stringify(ran && ran.history));

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const base = 'http://127.0.0.1:' + port;
    const reporter = await oauth2.accessTokenAsync(base, {
      audience: base + '/report-api', client_id: CLIENT, username: ADMIN,
      sub: String(helpers.subjectForName(ADMIN) || ''),
      scope: 'report:admin' });

    let r = await call(port, 'GET', '/report-api/catalog/passkeyHistory',
                       reporter);
    const presets = r.json && r.json.source ? r.json.source.presets || []
                                            : [];
    note(r.status === 200 && presets.length === 3 &&
         presets[0].id === 'post-quantum-adoption-by-day',
         'E2. /report-api publishes the source and its three presets',
         brief(r));
    r = await call(port, 'GET', '/report-api/openapi.json', reporter);
    note(r.status === 200 && r.json && JSON.stringify(r.json)
           .indexOf('passkeyHistory') >= 0,
         'E3. the OpenAPI document names the source', r.status);
    if (presets.length) {
      r = await call(port, 'POST', '/report-api/queries', reporter,
        Object.assign({}, presets[0].document, { mode: 'sync' }));
      const rows = r.json && Array.isArray(r.json.rows) ? r.json.rows : [];
      const today = new Date().toISOString().slice(0, 10);
      note(r.status === 200 && rows.length >= 1 &&
           rows[rows.length - 1].day === today &&
           typeof rows[rows.length - 1].holding === 'number',
           'E4. the adoption preset runs over the API and answers today',
           brief(r));
    } else {
      note(false, 'E4. the adoption preset runs over the API', 'no presets');
    }

    server.close();
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    note(false, 'the child process ran to the end', e && e.stack);
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

async function overHttp(t) {
  log.debug("Entering overHttp().");
  t.log.info('=== E. over /report-api ===');
  const out = path.join(os.tmpdir(), 'pkh-' + process.pid + '-' +
                        Date.now() + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$|ADMIN_API_)/
        .test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal',
                                  PKH_ROOT: ROOT, PKH_OUT: out }),
      encoding: 'utf8', timeout: 240000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in overHttp(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in overHttp(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings),
               'the child process reported its findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-800))) {
    log.debug("Leaving overHttp().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving overHttp().");
}

async function run(t) {
  log.debug("Entering run().");
  await theRow(t);
  await retention(t);
  catalogChecks(t);
  await theSource(t);
  await overHttp(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'passkey_history',
  describe: 'the passkey history (#1109): the day\'s row the recount ' +
            'writes, its profiles, its retention, and the passkeyHistory ' +
            'source in /report with its predefined queries, in process ' +
            'and over /report-api',
  run: run
};
