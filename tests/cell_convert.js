// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: cell_convert.js
//
// ---------------------------------------------------------------------------
// THE ONE-TIME CONVERSION OF A SINGLE-CELL STORE INTO A CELL (#98,
// `persistence/cell_convert.js`), driven over two in-memory databases that
// keep the tool's own six operations and a transaction that rolls back. What
// it holds, each the kind of mistake that fails nothing on the day and loses
// a person or a realm key later:
//
//   1. The split is the tiered driver's: realms, settings, keys, the
//      used-assertion history, the cluster secrets and the global directory
//      entries move; a group is split into its two halves (and a group with
//      no person in it leaves the cell); a global minted store moves and a
//      cell one — and an unclassified one — stays; `scheduler.run.global`
//      claims move; every `sts_risk_*` table is untouched.
//   2. The routing index is backfilled with EXACTLY the rows the flush's
//      `indexPeople()` claims for the same people, and the service's one
//      digest is `cell_routing.ts`' digest.
//   3. A dry run changes nothing; a re-run changes nothing; a missing index
//      row is repaired on a re-run.
//   4. A failure at any step leaves the source rows in the cell, and a
//      re-run after a failed clean-up finishes the job.
//   5. A second source, an empty pair and a schema mismatch are refused,
//      each with its code, and nothing changes.
//   6. The SQL is built from the table map: every write an upsert on the
//      primary key, timestamps as UTC text, and the driver's dial options.
//   7. The one-off task it runs as in AWS (deploy/aws, the `cell-convert`
//      container): no TLS files, STS_CLUSTER_NODE_NAME=convert, and a risk
//      upload directory with no volume behind it. The command line, run as
//      that task in a child process against a database that is not there,
//      binds no listener, creates no risk upload directory, and fails with
//      its own code — it reaches the store only through its own pool, so it
//      joins no cluster and holds no claim.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const convertTool = require('../persistence/cell_convert');
const tiers = require('../persistence/tiers');
const tiered = require('../persistence/persistence_tiered');
const errorCodes = require('../common/error_codes');

const log = require('bunyan').createLogger({ name: 'cell_convert',
  level: process.env.LOG_LEVEL || 'info' });

const SCHEMA = 11;
const CELL = 'usw2';
const BASE = 'dc=example,dc=com';

// A deterministic stand-in for the keyed digest; section 2 checks the real
// one separately.
function fakeDigest(realm, kind, value) {
  log.debug("Entering fakeDigest().");
  log.debug("Leaving fakeDigest().");
  return 'd:' + realm + ':' + kind + ':' + value;
}

// ---------------------------------------------------------------------------
// ONE DATABASE IN MEMORY, with the store's interface. `hooks.fail(table, op)`
// throws inside a transaction (which then rolls back); `hooks.hide(table)`
// drops rows from a read, to make a read-back lie.
// ---------------------------------------------------------------------------
function memoryStore(name, version, hooks) {
  log.debug("Entering memoryStore().");
  const h = hooks || {};
  let data = {};
  let risk = {};
  // sts_cluster_nodes, which the conversion never copies — only its dead
  // rows are forgotten (forgetDeadMembers()) — so it is not in TABLES.
  let members = [];
  const keyOf = function (table, row) {
    return convertTool.TABLES[table].key.map(function (c) {
      return String(row[c] === undefined || row[c] === null ? '' : row[c]);
    }).join('\u0000');
  };
  const tableOf = function (d, table) {
    if (!d[table]) {
      d[table] = {};
    }
    return d[table];
  };
  const clone = function (v) {
    return JSON.parse(JSON.stringify(v));
  };
  const store = {
    name: name,
    version: version,
    put: function (table, rows) {
      rows.forEach(function (row) {
        tableOf(data, table)[keyOf(table, row)] = clone(row);
      });
    },
    setMembers: function (rows) {
      members = clone(rows);
    },
    members: function () {
      return clone(members);
    },
    setRisk: function (counts) {
      risk = clone(counts);
    },
    snapshot: function () {
      return convertTool.canonical({ data: data, risk: risk });
    },
    all: function (table) {
      return Object.keys(data[table] || {}).sort().map(function (k) {
        return clone(data[table][k]);
      });
    },
    schemaVersion: function () {
      return Promise.resolve(store.version);
    },
    rows: function (table, filter) {
      let out = store.all(table).filter(function (row) {
        return Object.keys(filter || {}).every(function (col) {
          const want = filter[col];
          return Array.isArray(want) ? want.indexOf(String(row[col])) >= 0
                                     : String(row[col]) === String(want);
        });
      });
      if (typeof h.hide === 'function') {
        out = h.hide(table, out);
      }
      return Promise.resolve(out);
    },
    count: function (table) {
      return Promise.resolve(Object.keys(data[table] || {}).length);
    },
    countBy: function (table, col) {
      const out = {};
      store.all(table).forEach(function (row) {
        out[String(row[col])] = (out[String(row[col])] || 0) + 1;
      });
      return Promise.resolve(out);
    },
    riskCounts: function () {
      return Promise.resolve(clone(risk));
    },
    transaction: async function (fn) {
      const work = clone(data);
      let workMembers = clone(members);
      const check = function (table, op) {
        if (typeof h.fail === 'function' && h.fail(table, op)) {
          throw new Error('injected failure: ' + op + ' ' + table);
        }
      };
      const ops = {
        upsert: async function (table, rows) {
          check(table, 'upsert');
          rows.forEach(function (row) {
            tableOf(work, table)[keyOf(table, row)] = clone(row);
          });
        },
        insertAbsent: async function (table, rows) {
          check(table, 'insertAbsent');
          let n = 0;
          rows.forEach(function (row) {
            const t = tableOf(work, table);
            if (!(keyOf(table, row) in t)) {
              t[keyOf(table, row)] = clone(row);
              n += 1;
            }
          });
          return n;
        },
        remove: async function (table, rows) {
          check(table, 'remove');
          let n = 0;
          rows.forEach(function (row) {
            const t = tableOf(work, table);
            if (keyOf(table, row) in t) {
              delete t[keyOf(table, row)];
              n += 1;
            }
          });
          return n;
        },
        forgetDeadMembers: async function () {
          check('sts_cluster_nodes', 'forgetDeadMembers');
          const now = Date.now();
          const before = workMembers.length;
          workMembers = workMembers.filter(function (row) {
            return !row.left_at && row.expires_at >= now;
          });
          return before - workMembers.length;
        }
      };
      const out = await fn(ops);
      data = work;
      members = workMembers;
      return out;
    },
    close: function () {
      return Promise.resolve();
    }
  };
  log.debug("Leaving memoryStore().");
  return store;
}

// A single-cell store as a deployment leaves it: two realms, their keys and
// a CA, settings, an application and its device, two people and a person's
// device, a group of a person and an application and a group of an
// application only, a global and a cell minted store and an unclassified
// one, a global and a cell claim, and risk history.
function singleCellStore(hooks) {
  log.debug("Entering singleCellStore().");
  const s = memoryStore('cell', SCHEMA, hooks);
  s.put('sts_realms', [
    { id: 'default', name: 'Default', description: '', created_at: null,
      overrides: {}, domain: 'example.com', retiring_at: null },
    { id: 'acme', name: 'Acme', description: 'a realm',
      created_at: '1790000000000', overrides: { 'oauth2.rfc9700': 'true' },
      domain: 'acme.example', retiring_at: null }]);
  s.put('sts_appconfig', [{ key: 'global.domain', value: { raw: 'x' } }]);
  s.put('sts_keys', [
    { realm: 'default', material: '$aesgcm$1$a', written_at:
      '2026-09-01T00:00:00.123456Z' },
    { realm: 'acme', material: '$aesgcm$1$b', written_at:
      '2026-09-02T00:00:00.000001Z' },
    { realm: 'pki:root', material: '$aesgcm$1$c', written_at:
      '2026-09-03T00:00:00.000000Z' }]);
  s.put('sts_used_assertions', [
    { realm: 'default', key: 'k1', format: 'jwt', used_as: 'grant',
      issuer: 'i', identifier: 'j', client_id: 'c', subject: 's',
      state: 'spent', reservation: 'r', origin: 'o', used_at: '1',
      spent_at: '2', expires_at: '3' }]);
  s.put('sts_cluster_secrets', [
    { name: 'tls.ticket', material: '$aesgcm$1$d', created_by: 'x',
      created_at: '5' }]);
  const entry = function (dnKey, attrs) {
    return { realm: 'default', dn_key: dnKey, dn: dnKey, attrs: attrs,
             origin: 'console', created_at: '2026-09-01T00:00:00Z',
             modified_at: '2026-09-02T00:00:00Z' };
  };
  const alice = 'uid=alice,ou=users,' + BASE;
  const bob = 'uid=bob,ou=users,' + BASE;
  const app = 'cn=app1,ou=applications,' + BASE;
  s.put('sts_ldap_entries', [
    entry(BASE, { objectClass: ['domain'], dc: ['example'] }),
    entry('ou=users,' + BASE, { ou: ['users'] }),
    entry(alice, { uid: ['alice'], entryUUID: ['AAAA-1111'],
                   cn: ['Alice'] }),
    entry(bob, { uid: ['Bob'], entryUUID: ['bbbb-2222'] }),
    entry(app, { cn: ['app1'] }),
    entry('cn=d1,ou=devices,' + BASE, { stsDeviceOwnerKind: ['person'] }),
    entry('cn=d2,ou=devices,' + BASE,
          { stsDeviceOwnerKind: ['application'] }),
    entry('cn=admins,ou=groups,' + BASE,
          { cn: ['admins'], objectClass: ['groupOfNames'],
            member: [alice, app] }),
    entry('cn=apps,ou=groups,' + BASE,
          { cn: ['apps'], objectClass: ['groupOfNames'], member: [app] })]);
  s.put('sts_minted', [
    { handle: 'dpop.seenJtis', realm: 'default', key: 'j1',
      body: '$aesgcm$1$e', written_at: '2026-09-05T00:00:00.000000Z' },
    { handle: 'authn.sessions', realm: 'default', key: 's1',
      body: '$aesgcm$1$f', written_at: '2026-09-05T00:00:00.000000Z' },
    { handle: 'retired.store', realm: '', key: 'x', body: '$aesgcm$1$g',
      written_at: '2026-09-05T00:00:00.000000Z' }]);
  s.put('sts_cluster_claims', [
    { scope: tiers.GLOBAL_RUN_SCOPE, realm: '', key: 'signing.rotate',
      reservation: 'r', origin: 'o', claimed_at: '1', expires_at: '2' },
    { scope: 'persistence.origin', realm: '', key: 'front',
      reservation: 'r', origin: 'o', claimed_at: '1', expires_at: '2' }]);
  s.setRisk({ sts_risk_assessments: 5, sts_risk_failures: 2,
              sts_risk_subjects: 1 });
  log.debug("Leaving singleCellStore().");
  return s;
}

function emptyGlobal(hooks) {
  log.debug("Entering emptyGlobal().");
  log.debug("Leaving emptyGlobal().");
  return memoryStore('global', SCHEMA, hooks);
}

function run1(cell, globalStore, extra) {
  log.debug("Entering run1().");
  log.debug("Leaving run1().");
  return convertTool.convert(Object.assign({
    cell: cell, global: globalStore, cellId: CELL, digest: fakeDigest,
    schemaVersion: SCHEMA, now: 1790000000000
  }, extra || {}));
}

async function refusedWith(promise) {
  log.debug("Entering refusedWith().");
  try {
    await promise;
  } catch (e) {
    log.debug("Caught in refusedWith(): " + ((e && e.message) || e));
    log.debug("Leaving refusedWith(). Refused.");
    return String((e && e.code) || '');
  }
  log.debug("Leaving refusedWith(). Not refused.");
  return '';
}

function dnsOf(rows) {
  log.debug("Entering dnsOf().");
  log.debug("Leaving dnsOf().");
  return rows.map(function (r) {
    return r.dn_key;
  }).sort();
}

// 1 and 2. The split, and the index against the tiered driver's own claims.
async function split(t) {
  log.debug("Entering split().");
  const cell = singleCellStore();
  const g = emptyGlobal();
  const before = cell.snapshot();
  const result = await run1(cell, g);
  t.equal(result.state, 'converted', 'a single-cell store is converted');
  ['sts_realms', 'sts_appconfig', 'sts_keys', 'sts_used_assertions',
   'sts_cluster_secrets'].forEach(function (table) {
    const was = JSON.parse(before).data[table];
    t.equal(convertTool.canonical(g.all(table)),
            convertTool.canonical(Object.keys(was).sort().map(function (k) {
              return was[k];
            })), table + ' moved to the global database row for row');
    t.equal(cell.all(table).length, 0, 'and left the cell database');
  });
  t.equal(convertTool.canonical(dnsOf(g.all('sts_ldap_entries'))),
          convertTool.canonical([
            'cn=admins,ou=groups,' + BASE, 'cn=app1,ou=applications,' + BASE,
            'cn=apps,ou=groups,' + BASE, 'cn=d2,ou=devices,' + BASE, BASE,
            'ou=users,' + BASE].sort()),
          'the global directory is the containers, the application, its ' +
          'device and both groups\' global halves');
  t.equal(convertTool.canonical(dnsOf(cell.all('sts_ldap_entries'))),
          convertTool.canonical([
            'cn=admins,ou=groups,' + BASE, 'cn=d1,ou=devices,' + BASE,
            'uid=alice,ou=users,' + BASE, 'uid=bob,ou=users,' + BASE].sort()),
          'the cell keeps the people, the person\'s device and the one ' +
          'group with a person in it');
  const gAdmins = g.all('sts_ldap_entries').filter(function (r) {
    return r.dn_key.indexOf('cn=admins') === 0;
  })[0];
  const cAdmins = cell.all('sts_ldap_entries').filter(function (r) {
    return r.dn_key.indexOf('cn=admins') === 0;
  })[0];
  t.equal(convertTool.canonical(gAdmins.attrs.member),
          convertTool.canonical(['cn=app1,ou=applications,' + BASE]),
          'the group\'s global half holds its application member');
  t.equal(convertTool.canonical(cAdmins.attrs),
          convertTool.canonical({ member: ['uid=alice,ou=users,' + BASE] }),
          'its cell half holds only its person member');
  const joined = tiers.joinGroup(gAdmins.attrs, cAdmins.attrs);
  t.equal(convertTool.canonical(joined.member.slice().sort()),
          convertTool.canonical(['cn=app1,ou=applications,' + BASE,
                                 'uid=alice,ou=users,' + BASE].sort()),
          'and joined at load the group has both members again');
  t.equal(cAdmins.origin + '|' + cAdmins.created_at, gAdmins.origin + '|' +
          gAdmins.created_at, 'both halves keep the entry\'s origin and times');
  t.equal(g.all('sts_minted').map(function (r) {
    return r.handle;
  }).join(','), 'dpop.seenJtis', 'the global minted store moved');
  t.equal(cell.all('sts_minted').map(function (r) {
    return r.handle;
  }).sort().join(','), 'authn.sessions,retired.store',
  'a cell store and an unclassified one stay where they were made');
  t.equal(g.all('sts_minted')[0].written_at, '2026-09-05T00:00:00.000000Z',
          'a minted row keeps its written_at');
  t.equal(g.all('sts_cluster_claims').map(function (r) {
    return r.scope;
  }).join(','), tiers.GLOBAL_RUN_SCOPE, 'the global run claim moved');
  t.equal(cell.all('sts_cluster_claims').map(function (r) {
    return r.scope;
  }).join(','), 'persistence.origin', 'the cell\'s own claim stayed');
  t.equal(convertTool.canonical(await cell.riskCounts()),
          convertTool.canonical({ sts_risk_assessments: 5,
                                  sts_risk_failures: 2,
                                  sts_risk_subjects: 1 }),
          'every sts_risk_* table is untouched');
  t.check(/sts_risk_assessments 5/.test(result.summary) &&
          /sts_keys 3/.test(result.summary) &&
          /2 people/.test(result.summary),
          'the summary line carries the counts per table and tier',
          result.summary);

  // The index: every row names this cell, and the rows are the flush's.
  const index = g.all('sts_cell_routing');
  t.equal(index.length, 4, 'two people, a name and a uuid each, indexed');
  t.check(index.every(function (r) {
    return r.cell === CELL;
  }), 'every index row names this cell');
  const claimed = [];
  const flush = tiered.create({
    cellId: CELL, digest: fakeDigest,
    global: { saveDirectory: function () {
      return Promise.resolve({ outcomes: [] });
    }, routeClaim: function (realm, kind, digest, cellId) {
      claimed.push([realm, kind, digest, cellId].join('|'));
      return Promise.resolve({ cell: cellId, claimed: true });
    } },
    cell: { saveDirectory: function () {
      return Promise.resolve({ outcomes: [] });
    } }
  });
  const people = JSON.parse(before).data.sts_ldap_entries;
  await flush.saveDirectory({ upserts: Object.keys(people).map(function (k) {
    const r = people[k];
    return { realm: r.realm, key: r.dn_key,
             entry: { dn: r.dn, attributes: r.attrs } };
  }).filter(function (r) {
    return tiers.isPersonDn(r.key);
  }), deletes: [] });
  t.equal(convertTool.canonical(index.map(function (r) {
    return [r.realm, r.kind, r.digest, r.cell].join('|');
  }).sort()), convertTool.canonical(claimed.sort()),
  'the backfill is exactly what the flush\'s indexPeople() claims');
  log.debug("Leaving split().");
  return { cell: cell, global: g };
}

// The service's one digest is the lookup's.
function oneDigest(t) {
  log.debug("Entering oneDigest().");
  const keystore = require('../common/keystore');
  const persistence = require('../persistence/persistence');
  const routing = require('../common/cell_routing');
  t.check(keystore.useEphemeralKek(require('crypto').randomBytes(32)
    .toString('hex')), 'a service key is installed');
  const mine = persistence.routingDigest('acme', 'name', 'alice');
  t.check(!!mine && mine === routing.digest('acme', 'name', 'Alice'),
          'persistence.routingDigest() is the digest cell_routing.ts ' +
          'looks a person up by');
  t.check(mine !== persistence.routingDigest('default', 'name', 'alice'),
          'and it is per realm');
  keystore.reset();
  log.debug("Leaving oneDigest().");
}

// 3. Dry run, re-run, and the repair of a missing index row.
async function reruns(t, converted) {
  log.debug("Entering reruns().");
  const cell = singleCellStore();
  const g = emptyGlobal();
  const cb = cell.snapshot();
  const gb = g.snapshot();
  const dry = await run1(cell, g, { dryRun: true });
  t.equal(dry.state, 'dry-run', 'a dry run answers what it would do');
  t.check(/would convert/.test(dry.summary) && /sts_keys 3/.test(dry.summary),
          'and says so with the counts', dry.summary);
  t.check(cell.snapshot() === cb && g.snapshot() === gb,
          'a dry run changes neither database');

  const c2 = converted.cell.snapshot();
  const g2 = converted.global.snapshot();
  const again = await run1(converted.cell, converted.global);
  t.equal(again.state, 'already-converted', 'a re-run finds it converted');
  t.check(converted.cell.snapshot() === c2 &&
          converted.global.snapshot() === g2 && again.routingAdded === 0,
          'and changes nothing', again.summary);
  const dryAgain = await run1(converted.cell, converted.global,
                              { dryRun: true });
  t.equal(dryAgain.state, 'already-converted',
          'a dry re-run says the same');

  // A missing index row is claimed again, and only that one.
  const rows = converted.global.all('sts_cell_routing');
  await converted.global.transaction(function (tx) {
    return tx.remove('sts_cell_routing', [rows[0]]);
  });
  const repaired = await run1(converted.cell, converted.global);
  t.equal(repaired.routingAdded, 1, 'a missing index row is claimed on a ' +
          're-run');
  t.check(converted.global.snapshot() === g2, 'and the index is whole again');
  log.debug("Leaving reruns().");
}

// 4. Failures leave the source in place; a re-run finishes.
async function failures(t) {
  log.debug("Entering failures().");
  // The copy fails half way: rolled back, the cell untouched.
  let cell = singleCellStore();
  let g = emptyGlobal({ fail: function (table) {
    return table === 'sts_minted';
  } });
  let cb = cell.snapshot();
  t.equal(await refusedWith(run1(cell, g)), 'STS-CELL-0204',
          'a failed copy is STS-CELL-0204');
  t.check(cell.snapshot() === cb, 'and the cell database is unchanged');
  t.equal(g.all('sts_realms').length + g.all('sts_keys').length, 0,
          'and the global database holds nothing of it (rolled back)');

  // The read-back lies: nothing is taken from the cell.
  cell = singleCellStore();
  g = emptyGlobal({ hide: function (table, rows) {
    return table === 'sts_keys' ? rows.slice(1) : rows;
  } });
  cb = cell.snapshot();
  t.equal(await refusedWith(run1(cell, g)), 'STS-CELL-0205',
          'a copy that does not read back is STS-CELL-0205');
  t.check(cell.snapshot() === cb, 'and the cell database is unchanged');

  // The clean-up fails: the copy stands, the cell is untouched, and a
  // re-run finds the copy and finishes.
  let failing = true;
  cell = singleCellStore({ fail: function (table, op) {
    return failing && op === 'remove' && table === 'sts_minted';
  } });
  g = emptyGlobal();
  cb = cell.snapshot();
  t.equal(await refusedWith(run1(cell, g)), 'STS-CELL-0206',
          'a failed clean-up is STS-CELL-0206');
  t.check(cell.snapshot() === cb, 'the cell database is unchanged');
  t.equal(g.all('sts_keys').length, 3, 'the global database holds the copy');
  failing = false;
  const resumed = await run1(cell, g);
  t.equal(resumed.state, 'converted', 'a re-run after it converts');
  t.equal(cell.all('sts_keys').length + cell.all('sts_realms').length, 0,
          'and finishes the clean-up');
  t.equal(g.all('sts_keys').length, 3, 'with the copy made once');
  log.debug("Leaving failures().");
}

// 5. The refusals.
async function refusals(t) {
  log.debug("Entering refusals().");
  // A second source: another key for a realm.
  let cell = singleCellStore();
  let g = emptyGlobal();
  g.put('sts_keys', [{ realm: 'default', material: '$aesgcm$1$other',
                       written_at: '2026-09-01T00:00:00.000000Z' }]);
  let cb = cell.snapshot();
  let gb = g.snapshot();
  t.equal(await refusedWith(run1(cell, g)), 'STS-CELL-0203',
          'a global database holding another source\'s keys is refused');
  t.check(cell.snapshot() === cb && g.snapshot() === gb,
          'and nothing changes');

  // A second source: the same keys and realms, but an index naming another
  // cell.
  cell = singleCellStore();
  g = emptyGlobal();
  g.put('sts_realms', cell.all('sts_realms'));
  g.put('sts_keys', cell.all('sts_keys'));
  g.put('sts_cell_routing', [{ realm: 'default', kind: 'name',
                               digest: 'x', cell: 'euw1',
                               written_at: '1' }]);
  t.equal(await refusedWith(run1(cell, g)), 'STS-CELL-0203',
          'an index naming another cell is a second source too');

  // Nothing to do.
  t.equal(await refusedWith(run1(memoryStore('cell', SCHEMA),
                                 emptyGlobal())), 'STS-CELL-0202',
          'an empty cell database beside an empty global one is refused');

  // A schema that is not this service's.
  cell = singleCellStore();
  g = memoryStore('global', SCHEMA - 1);
  cb = cell.snapshot();
  t.equal(await refusedWith(run1(cell, g)), 'STS-CELL-0201',
          'a global database at another schema version is refused');
  t.check(cell.snapshot() === cb, 'and nothing changes');
  t.equal(await refusedWith(run1(singleCellStore(), emptyGlobal(),
                                 { cellId: '' })), 'STS-CELL-0200',
          'no cell id is refused');
  for (let n = 200; n <= 209; n++) {
    const code = 'STS-CELL-0' + n;
    t.check(errorCodes.isKnown(code), code + ' is registered');
  }
  log.debug("Leaving refusals().");
}

// 6. The SQL, over a stubbed `pg`.
async function statements(t) {
  log.debug("Entering statements().");
  const postgres = require('../persistence/persistence_postgres');
  const dial = postgres.dialOptions(
    'postgres://sts_app:pw@db:5432/sts?sslmode=require', false);
  t.check(dial.wantsTls && !/sslmode/.test(dial.connectionString) &&
          dial.ssl && dial.ssl.rejectUnauthorized === false,
          'dialOptions() strips sslmode and configures TLS itself');
  t.check(!postgres.dialOptions('postgres://db/sts', true).ssl,
          'and a string asking for no TLS gets none');
  const seen = [];
  const pgPath = require.resolve('pg');
  const previous = require.cache[pgPath];
  function FakePool() {}
  FakePool.prototype.on = function () {};
  FakePool.prototype.query = function (sql, params) {
    seen.push({ sql: String(sql), params: params || [] });
    return Promise.resolve({ rows: [], rowCount: 1 });
  };
  FakePool.prototype.connect = function () {
    return Promise.resolve({ query: FakePool.prototype.query,
                             release: function () {} });
  };
  FakePool.prototype.end = function () {
    return Promise.resolve();
  };
  require.cache[pgPath] = { id: pgPath, filename: pgPath, loaded: true,
    exports: { Pool: FakePool, Client: function () {} } };
  let store;
  try {
    store = convertTool.sqlStore({ url: 'postgres://sts_app@db/sts',
                                   verifyTls: false, name: 'global' });
  } finally {
    if (previous) {
      require.cache[pgPath] = previous;
    } else {
      delete require.cache[pgPath];
    }
  }
  await store.rows('sts_keys');
  await store.rows('sts_minted', { handle: ['dpop.seenJtis'] });
  await store.transaction(async function (tx) {
    await tx.upsert('sts_minted', [{ handle: 'h', realm: '', key: 'k',
                                     body: 'b', written_at: 'w' }]);
    await tx.upsert('sts_ldap_entries', [{ realm: 'r', dn_key: 'k', dn: 'k',
                                           attrs: { a: ['1'] } }]);
    await tx.insertAbsent('sts_cell_routing', [{ realm: 'r', kind: 'name',
                                                 digest: 'd', cell: 'c',
                                                 written_at: '1' }]);
    await tx.remove('sts_realms', [{ id: 'x' }]);
    await tx.forgetDeadMembers();
  });
  const text = seen.map(function (s) {
    return s.sql;
  });
  t.check(/to_char\(written_at AT TIME ZONE 'UTC'/.test(text[0]),
          'a timestamp is read as UTC text', text[0]);
  t.check(/handle = ANY\(\$1::text\[\]\)/.test(text[1]),
          'a handle filter is one parameter', text[1]);
  t.check(text[2] === 'BEGIN' && text[text.length - 1] === 'COMMIT',
          'the writes are one transaction');
  t.check(text.some(function (s) {
    return /INSERT INTO sts_minted .*\$5::timestamptz\) ON CONFLICT \(handle, realm, key\) DO UPDATE SET body = EXCLUDED\.body, written_at = EXCLUDED\.written_at/
      .test(s);
  }), 'a minted row is an upsert on its primary key, its time cast back');
  t.check(seen.some(function (s) {
    return /\$4::jsonb/.test(s.sql) && s.params[3] === '{"a":["1"]}';
  }), 'an entry\'s attributes travel as jsonb');
  t.check(text.some(function (s) {
    return /INSERT INTO sts_cell_routing .* DO NOTHING$/.test(s);
  }), 'an index row is inserted only where none is');
  t.check(text.some(function (s) {
    return s === 'DELETE FROM sts_realms WHERE id = $1';
  }), 'a delete is by primary key');
  t.check(text.some(function (s) {
    return /^DELETE FROM sts_cluster_nodes WHERE left_at <> 0 OR expires_at < \(extract\(epoch from clock_timestamp\(\)\) \* 1000\)::bigint$/
      .test(s);
  }), 'the old deployment\'s membership is forgotten by the database clock, ' +
      'dead rows only');
  log.debug("Leaving statements().");
}

// 7. The AWS one-off task's environment. A child process, because the
// command line reads its settings at load; a preload records any listen()
// and any directory created, and the database refuses the connection.
async function asTheConvertTask(t) {
  log.debug("Entering asTheConvertTask().");
  const fs = require('fs');
  const os = require('os');
  const path = require('path');
  const childProcess = require('child_process');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cell-convert-task-'));
  const marks = path.join(dir, 'marks.log');
  const hook = path.join(dir, 'hook.js');
  fs.writeFileSync(hook, [
    '"use strict";',
    'const fs = require("fs");',
    'const net = require("net");',
    'const mark = function (what) {',
    '  fs.appendFileSync(' + JSON.stringify(marks) + ', what + "\\n");',
    '};',
    'const listen = net.Server.prototype.listen;',
    'net.Server.prototype.listen = function () {',
    '  mark("listen " + JSON.stringify(arguments[0]));',
    '  return listen.apply(this, arguments);',
    '};',
    'const mkdir = fs.mkdirSync;',
    'fs.mkdirSync = function (p) {',
    '  mark("mkdir " + p);',
    '  return mkdir.apply(this, arguments);',
    '};'
  ].join('\n'));
  const kek = path.join(dir, 'kek');
  fs.writeFileSync(kek, require('crypto').randomBytes(32).toString('hex'));
  const riskDir = path.join(dir, 'risk-uploads-not-mounted');
  const env = Object.assign({}, process.env, {
    STS_MODE: 'product', STS_PERSISTENCE_MODE: 'postgres',
    STS_KEYS_SOURCE: 'persisted', STS_KEYS_KEK_PROVIDER: 'file',
    STS_KEYS_KEK_REF: kek, STS_CELL_ID: 'usw2', STS_CELL_JURISDICTION: 'us',
    STS_PUBLIC_BASE_URL: 'https://sts.example.test',
    STS_DATABASE_URL: 'postgres://sts_app:x@127.0.0.1:1/sts',
    STS_GLOBAL_DATABASE_URL: 'postgres://sts_app:x@127.0.0.1:1/sts',
    STS_DATABASE_PASSWORD_PROVIDER: 'none',
    STS_GLOBAL_DATABASE_PASSWORD_PROVIDER: 'none',
    STS_CLUSTER_NODE_NAME: 'convert', STS_RISK_UPLOAD_DIRECTORY: riskDir,
    NODE_OPTIONS: '--require ' + hook
  });
  delete env.CONFIG_FILE;
  delete env.STS_TLS_CERT_FILE;
  delete env.STS_TLS_KEY_FILE;
  const run = childProcess.spawnSync(process.execPath,
    [path.join(__dirname, '..', 'persistence', 'cell_convert.js'),
     '--dry-run'], { env: env, encoding: 'utf8', timeout: 120000 });
  const said = String(run.stdout || '') + String(run.stderr || '');
  const marked = fs.existsSync(marks) ? fs.readFileSync(marks, 'utf8') : '';
  t.equal(run.status, 1, 'as the convert task, against no database, the ' +
          'tool exits 1', said.slice(-600));
  t.check(/STS-CELL-0208/.test(said), 'with its own code for a database ' +
          'it could not read', said.slice(-600));
  t.check(!/^listen /m.test(marked), 'it binds no listener', marked);
  t.check(!fs.existsSync(riskDir) && marked.indexOf(riskDir) < 0,
          'and never touches the risk upload directory', marked);
  t.check(!/STS-TLS-|STS_TLS_CERT_FILE/.test(said),
          'and asks for no TLS file');
  fs.rmSync(dir, { recursive: true, force: true });
  log.debug("Leaving asTheConvertTask().");
}

// 6b. The old deployment's membership (2026-09-30): the dead rows a restored
// database carries are forgotten in the clean-up, and a live one is kept.
async function deadMembers(t) {
  log.debug("Entering deadMembers().");
  const cell = singleCellStore();
  const now = Date.now();
  cell.setMembers([
    { node_id: 'left', name: 'node-a', left_at: now - 60000,
      expires_at: now + 60000 },
    { node_id: 'expired', name: 'node-b', left_at: 0,
      expires_at: now - 60000 },
    { node_id: 'live', name: 'node-c', left_at: 0,
      expires_at: now + 600000 }]);
  const r = await run1(cell, emptyGlobal());
  const ids = cell.members().map(function (row) {
    return row.node_id;
  });
  t.check(r.state === 'converted' && ids.join() === 'live',
          'a conversion forgets the dead member rows and keeps a live one',
          ids.join() || 'none');
  t.check(/2 dead cluster member row\(s\) of the old deployment forgotten/
            .test(r.summary), 'and says how many in its summary', r.summary);
  const failing = singleCellStore({
    fail: function (table) {
      return table === 'sts_cluster_nodes';
    }
  });
  failing.setMembers([{ node_id: 'x', name: 'n', left_at: 1,
                        expires_at: 1 }]);
  const refused = await refusedWith(run1(failing, emptyGlobal()));
  t.check(/STS-CELL-0206/.test(refused) && failing.members().length === 1,
          'a failure there rolls the whole clean-up back', refused);
  log.debug("Leaving deadMembers().");
}

async function run(t) {
  log.debug("Entering run().");
  const converted = await split(t);
  oneDigest(t);
  await reruns(t, converted);
  await failures(t);
  await refusals(t);
  await statements(t);
  await deadMembers(t);
  await asTheConvertTask(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'cell_convert',
  describe: 'The one-time conversion of a single-cell store into a cell ' +
            '(#98): the tiered driver\'s split, the routing backfill, ' +
            'idempotent re-runs, sources kept on failure, and the refusals',
  run: run
};
