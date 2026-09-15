'use strict';
//
// File: cluster_lww_stores.js
//
// ===========================================================================
// DATA LOSS FROM LAST-WRITER-WINS AND WHOLE-TABLE WRITES (2026-09-14, #46
// section 3): WHAT A SECOND NODE'S WRITE MUST NOT DESTROY.
//
// Every failure this file holds is silent in the process that causes it — the
// node that wrote answered correctly out of its own memory, and the damage is
// a row another node wrote, gone from the store:
//
//   A. two changes to one directory entry keep both (a group's two new
//      members), two adds of one DN keep the first, and a delete wins;
//   B. the postgres driver's directory flush writes that merge against the
//      row as it is NOW, and reports what the store decided;
//   C. saving the realm registry and the settings deletes no row this process
//      did not remove, and merges a realm's overrides key by key;
//   D. `persistence.js` itself — the shadows, the deltas, `removedHere` — run
//      against the real driver over a table another "node" also writes;
//   E. an ended session is not written back by a copy that is behind, and two
//      copies of one live session merge: the sign-in upgrade stays, and both
//      front-channel client lists survive.
//
// WHY IN PROCESS. The rules are decisions in three modules against the rows a
// driver reads, and a `pg` double holding a table in a Map can serve BOTH
// nodes' drivers at once — the arrangement a real database gives only with two
// containers and a race. The two-node run against a real postgres is recorded
// in `persistence/CLAUDE.md`.
//
// IN A CHILD PROCESS, for `minted_flush_order.js`'s reason: section D starts
// `persistence.js` and section E arms `persistence_minted.js`, one life of
// each per process, and the runner shares its process with every other file.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const nodeCrypto = require('crypto');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'cluster_lww_stores',
  level: process.env.LOG_LEVEL || 'info' });

const CHILD_FLAG = 'STS_TEST_CLUSTER_LWW_CHILD';
const TOMBSTONE = '$tombstone$1';
const QUIET = { debug: function () {}, info: function () {},
                warn: function () {}, error: function () {} };

// ---------------------------------------------------------------------------
// ONE DATABASE, AS A `pg` DOUBLE: the few statements the driver issues against
// the four tables this file is about, interpreted against Maps. Anything else
// answers no rows, which is what the rest of the driver's reads can live with.
// ---------------------------------------------------------------------------
function fakeDatabase() {
  log.debug("Entering fakeDatabase().");
  const db = { entries: new Map(), realms: new Map(), appconfig: new Map(),
               minted: new Map(), changes: 0, statements: [], log: [] };
  const eid = function (realm, key) {
    return String(realm) + '\n' + String(key);
  };
  const json = function (value) {
    return typeof value === 'string' ? JSON.parse(value) : value;
  };
  db.query = function (sql, params) {
    const text = String(sql).replace(/\s+/g, ' ').trim();
    const p = params || [];
    db.statements.push(text);
    const rows = function (list) {
      return Promise.resolve({ rows: list, rowCount: list.length });
    };
    if (/^(BEGIN|COMMIT|ROLLBACK)$/.test(text)) {
      return rows([]);
    }
    if (/^SELECT to_regclass/.test(text)) {
      const row = {};
      for (let i = 0; i < 200; i++) {
        row['o' + i] = 'present';
      }
      return rows([row]);
    }
    if (/^INSERT INTO sts_changes/.test(text)) {
      for (let i = 0; i + 3 < p.length; i += 4) {
        db.log.push({ seq: db.log.length + 1, origin: p[i], kind: p[i + 1],
                      realm: p[i + 2], key: p[i + 3] });
      }
      db.changes += 1;
      return rows([]);
    }
    if (/SELECT COALESCE\(MAX\(seq\), 0\) AS seq FROM sts_changes/
          .test(text)) {
      return rows([{ seq: db.log.length }]);
    }
    if (/^SELECT seq, origin, kind, realm, key FROM sts_changes WHERE seq > /
          .test(text)) {
      return rows(db.log.filter(function (row) {
        return row.seq > Number(p[0]);
      }).slice(0, Number(p[1]) || 500));
    }
    if (/^SELECT seq, origin, kind, realm, key FROM sts_changes WHERE seq = /
          .test(text)) {
      return rows(db.log.filter(function (row) {
        return p[0].map(Number).indexOf(row.seq) >= 0;
      }));
    }
    // ---- the directory ----------------------------------------------------
    if (/FROM sts_ldap_entries ORDER BY realm, dn_key$/.test(text)) {
      return rows(Array.from(db.entries.values()));
    }
    if (/FROM sts_ldap_entries WHERE \(realm, dn_key\) IN/.test(text)) {
      const wanted = new Set(p[0].map(function (r, i) {
        return eid(r, p[1][i]);
      }));
      return rows(Array.from(db.entries.keys()).filter(function (k) {
        return wanted.has(k);
      }).sort().map(function (k) { return db.entries.get(k); }));
    }
    if (/FROM sts_ldap_entries WHERE realm = \$1 AND dn_key = \$2/
          .test(text)) {
      const one = db.entries.get(eid(p[0], p[1]));
      return rows(one ? [one] : []);
    }
    if (/^INSERT INTO sts_ldap_entries/.test(text)) {
      const k = eid(p[0], p[1]);
      if (db.entries.has(k) && /DO NOTHING/.test(text)) {
        return Promise.resolve({ rows: [], rowCount: 0 });
      }
      db.entries.set(k, { realm: p[0], dn_key: p[1], dn: p[2],
                          attrs: json(p[3]), origin: p[4],
                          created_at: p[5], modified_at: p[6] });
      return Promise.resolve({ rows: [], rowCount: 1 });
    }
    if (/^UPDATE sts_ldap_entries/.test(text)) {
      const k = eid(p[0], p[1]);
      if (!db.entries.has(k)) {
        return Promise.resolve({ rows: [], rowCount: 0 });
      }
      db.entries.set(k, { realm: p[0], dn_key: p[1], dn: p[2],
                          attrs: json(p[3]), origin: p[4],
                          created_at: p[5], modified_at: p[6] });
      return Promise.resolve({ rows: [], rowCount: 1 });
    }
    if (/^DELETE FROM sts_ldap_entries WHERE realm = \$1 AND dn_key/
          .test(text)) {
      db.entries.delete(eid(p[0], p[1]));
      return rows([]);
    }
    if (/^DELETE FROM sts_ldap_entries WHERE realm = \$1$/.test(text)) {
      Array.from(db.entries.keys()).forEach(function (k) {
        if (k.indexOf(String(p[0]) + '\n') === 0) {
          db.entries.delete(k);
        }
      });
      return rows([]);
    }
    // ---- the realm registry -----------------------------------------------
    if (/^SELECT id, name, description, created_at, overrides FROM sts_realms/
          .test(text)) {
      return rows(Array.from(db.realms.values()));
    }
    if (/^DELETE FROM sts_realms WHERE NOT/.test(text)) {
      const keep = new Set(p[0]);
      Array.from(db.realms.keys()).forEach(function (id) {
        if (!keep.has(id)) {
          db.realms.delete(id);
        }
      });
      return rows([]);
    }
    if (/^DELETE FROM sts_realms WHERE id = \$1/.test(text)) {
      db.realms.delete(p[0]);
      return rows([]);
    }
    if (/^INSERT INTO sts_realms/.test(text)) {
      const had = db.realms.get(p[0]);
      if (!had || p.length < 10) {
        db.realms.set(p[0], { id: p[0], name: p[1], description: p[2],
                              created_at: p[3], overrides: json(p[4]) });
      } else {
        const overrides = p[9] ? json(p[4])
          : Object.assign({}, had.overrides || {});
        if (!p[9]) {
          p[7].forEach(function (key) { delete overrides[key]; });
          Object.assign(overrides, json(p[8]));
        }
        db.realms.set(p[0], { id: p[0], name: p[5] ? p[1] : had.name,
                              description: p[6] ? p[2] : had.description,
                              created_at: had.created_at || p[3],
                              overrides: overrides });
      }
      return rows([]);
    }
    // ---- the settings -----------------------------------------------------
    if (/^SELECT key, value FROM sts_appconfig/.test(text)) {
      return rows(Array.from(db.appconfig.keys()).map(function (key) {
        return { key: key, value: db.appconfig.get(key) };
      }));
    }
    if (/^DELETE FROM sts_appconfig WHERE NOT/.test(text)) {
      const keep = new Set(p[0]);
      Array.from(db.appconfig.keys()).forEach(function (key) {
        if (!keep.has(key)) {
          db.appconfig.delete(key);
        }
      });
      return rows([]);
    }
    if (/^DELETE FROM sts_appconfig WHERE key = ANY/.test(text)) {
      p[0].forEach(function (key) { db.appconfig.delete(key); });
      return rows([]);
    }
    if (/^INSERT INTO sts_appconfig/.test(text)) {
      db.appconfig.set(p[0], json(p[1]));
      return rows([]);
    }
    // ---- minted rows ------------------------------------------------------
    if (/^SELECT body FROM sts_minted/.test(text)) {
      const one = db.minted.get(eid(p[0], eid(p[1], p[2])));
      return rows(one ? [{ body: one.body }] : []);
    }
    if (/^INSERT INTO sts_minted/.test(text)) {
      const k = eid(p[0], eid(p[1], p[2]));
      const had = db.minted.get(k);
      if (had && /WHERE sts_minted.body <> \$5/.test(text) &&
          had.body === p[4]) {
        return Promise.resolve({ rows: [], rowCount: 0 });
      }
      db.minted.set(k, { handle: p[0], realm: p[1], key: p[2], body: p[3],
                         written_ms: Date.now() });
      return Promise.resolve({ rows: [], rowCount: 1 });
    }
    if (/^DELETE FROM sts_minted WHERE handle = \$1/.test(text)) {
      db.minted.delete(eid(p[0], eid(p[1], p[2])));
      return rows([]);
    }
    return rows([]);
  };
  log.debug("Leaving fakeDatabase().");
  return db;
}

function fakePg(db) {
  log.debug("Entering fakePg().");
  function FakeClient() {}
  FakeClient.prototype.query = function (sql, params) {
    return db.query(sql, params);
  };
  FakeClient.prototype.release = function () {};
  FakeClient.prototype.on = function () {};
  FakeClient.prototype.removeListener = function () {};
  FakeClient.prototype.connect = function () { return Promise.resolve(); };
  FakeClient.prototype.end = function () { return Promise.resolve(); };
  function FakePool() {}
  FakePool.prototype.on = function () {};
  FakePool.prototype.connect = function () {
    return Promise.resolve(new FakeClient());
  };
  FakePool.prototype.query = FakeClient.prototype.query;
  FakePool.prototype.end = function () { return Promise.resolve(); };
  log.debug("Leaving fakePg().");
  return { Pool: FakePool, Client: FakeClient };
}

// The `pg` double stays in the require cache for the child's whole life, so
// `persistence.js` finds it when it creates its own driver in section D.
function installFakePg(db) {
  log.debug("Entering installFakePg().");
  const pgPath = require.resolve('pg');
  require.cache[pgPath] = { id: pgPath, filename: pgPath, loaded: true,
                            exports: fakePg(db) };
  log.debug("Leaving installFakePg().");
}

function driverOver() {
  log.debug("Entering driverOver().");
  log.debug("Leaving driverOver().");
  return require('../persistence/persistence_postgres').create({
    url: 'postgres://sts_app@localhost:5432/sts', log: QUIET });
}

function entry(dn, attributes) {
  log.debug("Entering entry().");
  log.debug("Leaving entry().");
  return { dn: dn, attributes: attributes, createdAt: '20260914000000Z',
           modifiedAt: '20260914000000Z' };
}

// ---------------------------------------------------------------------------
// A. THE MERGE RULE.
// ---------------------------------------------------------------------------
function sectionA(t) {
  log.debug("Entering sectionA().");
  t.log.info('=== A. one entry changed on two nodes ===');
  const merge = require('../persistence/directory_merge');
  const group = entry('cn=ops,ou=groups,dc=example,dc=com',
                      { cn: ['ops'], entryuuid: ['g-1'],
                        member: ['uid=a,ou=users'] });
  const mine = entry(group.dn, Object.assign({}, group.attributes,
    { member: ['uid=a,ou=users', 'uid=x,ou=users'] }));
  const theirs = entry(group.dn, Object.assign({}, group.attributes,
    { member: ['uid=a,ou=users', 'uid=y,ou=users'] }));
  const both = merge.mergeEntry(group, mine, theirs);
  t.equal(JSON.stringify(both.entry.attributes.member),
          JSON.stringify(['uid=a,ou=users', 'uid=y,ou=users',
                          'uid=x,ou=users']),
          'TWO NODES EACH ADDING A MEMBER KEEP BOTH — the last writer used ' +
          'to write its copy of the group over the other\'s');
  t.equal(both.outcome, 'merged', 'and the merged entry is not this copy');

  const empty = entry(group.dn, { cn: ['ops'], entryuuid: ['g-1'] });
  const onlyX = merge.mergeEntry(empty,
    entry(group.dn, { cn: ['ops'], entryuuid: ['g-1'], member: ['x'] }),
    entry(group.dn, { cn: ['ops'], entryuuid: ['g-1'], member: ['y'] }));
  t.equal(JSON.stringify(onlyX.entry.attributes.member), '["y","x"]',
          'AND FROM A GROUP WITH NO MEMBERS, where every side holds at most ' +
          'one value — the case the more-than-one-value rule alone gets wrong');

  const removed = merge.mergeEntry(group,
    entry(group.dn, Object.assign({}, group.attributes, { member: [] })),
    theirs);
  t.equal(JSON.stringify(removed.entry.attributes.member),
          '["uid=y,ou=users"]',
          'a member removed here and one added there: both happen');

  const person = entry('uid=d,ou=users', { uid: ['d'], entryuuid: ['p-1'],
                                          userpassword: ['h0'] });
  const pw = merge.mergeEntry(person,
    entry(person.dn, { uid: ['d'], entryuuid: ['p-1'], userpassword: ['h1'] }),
    entry(person.dn, { uid: ['d'], entryuuid: ['p-1'], userpassword: ['h2'] }));
  t.equal(JSON.stringify(pw.entry.attributes.userpassword), '["h1"]',
          'A PASSWORD SET ON BOTH IS ONE PASSWORD, this copy\'s — never the ' +
          'union, which would be two that both work');

  const collide = merge.mergeEntry(null,
    entry(person.dn, { uid: ['d'], entryuuid: ['p-mine'],
                       userpassword: ['mine'] }),
    entry(person.dn, { uid: ['d'], entryuuid: ['p-theirs'],
                       userpassword: ['theirs'] }));
  t.equal(collide.outcome + ' ' + collide.entry.attributes.userpassword[0],
          'theirs theirs',
          'TWO ADDS OF ONE DN ARE TWO ENTRIES: the one committed first is ' +
          'kept whole, password hash included, and this copy is replaced');

  t.equal(merge.mergeEntry(person, entry(person.dn, { uid: ['d'],
            entryuuid: ['p-1'], cn: ['changed'] }), null).outcome, 'deleted',
          'a change to an entry another node deleted since is dropped: the ' +
          'delete wins');
  t.equal(merge.mergeEntry(person, entry(person.dn, { uid: ['d'],
            entryuuid: ['p-new'] }), null).outcome, 'mine',
          'unless it was deleted and created again HERE, which a new ' +
          'entryUUID says');
  log.debug("Leaving sectionA().");
}

// ---------------------------------------------------------------------------
// B. THE DRIVER'S DIRECTORY FLUSH, TWO NODES ON ONE TABLE.
// ---------------------------------------------------------------------------
async function sectionB(t, db) {
  log.debug("Entering sectionB().");
  t.log.info('=== B. the directory flush merges with the row as it is now ===');
  const nodeA = driverOver();
  const nodeB = driverOver();
  const dn = 'cn=ops,ou=groups,dc=example,dc=com';
  const base = entry(dn, { cn: ['ops'], entryuuid: ['g-1'],
                           member: ['uid=a'] });
  db.entries.set('default\n' + dn, { realm: 'default', dn_key: dn, dn: dn,
    attrs: base.attributes, origin: null, created_at: base.createdAt,
    modified_at: base.modifiedAt });
  const baseJson = JSON.stringify(base);
  const withX = entry(dn, { cn: ['ops'], entryuuid: ['g-1'],
                            member: ['uid=a', 'uid=x'] });
  const withY = entry(dn, { cn: ['ops'], entryuuid: ['g-1'],
                            member: ['uid=a', 'uid=y'] });
  await nodeA.saveDirectory({ upserts: [{ realm: 'default', key: dn,
    entry: withX, json: JSON.stringify(withX), base: baseJson }],
    deletes: [], touched: ['default'], removedRealms: [], all: null });
  const second = await nodeB.saveDirectory({ upserts: [{ realm: 'default',
    key: dn, entry: withY, json: JSON.stringify(withY), base: baseJson }],
    deletes: [], touched: ['default'], removedRealms: [], all: null });
  t.equal(JSON.stringify(db.entries.get('default\n' + dn).attrs.member),
          JSON.stringify(['uid=a', 'uid=x', 'uid=y']),
          'NODE B\'S FLUSH OF ITS MEMBER KEPT NODE A\'S — the stored group ' +
          'holds both');
  const decided = (second.outcomes || [])[0] || {};
  t.equal(decided.outcome, 'merged',
          'and node B is told the store holds more than its copy, to apply ' +
          'it here', JSON.stringify(second));

  const person = 'uid=dave,ou=users,dc=example,dc=com';
  const first = entry(person, { uid: ['dave'], entryuuid: ['u-first'],
                                userpassword: ['first'] });
  const later = entry(person, { uid: ['dave'], entryuuid: ['u-later'],
                                userpassword: ['later'] });
  await nodeA.saveDirectory({ upserts: [{ realm: 'default', key: person,
    entry: first, json: JSON.stringify(first), base: null }],
    deletes: [], touched: [], removedRealms: [], all: null });
  const collided = await nodeB.saveDirectory({ upserts: [{ realm: 'default',
    key: person, entry: later, json: JSON.stringify(later), base: null }],
    deletes: [], touched: [], removedRealms: [], all: null });
  t.equal(db.entries.get('default\n' + person).attrs.userpassword[0], 'first',
          'A SECOND ADD OF ONE DN DOES NOT REPLACE THE FIRST, password hash ' +
          'included');
  t.equal(((collided.outcomes || [])[0] || {}).outcome, 'theirs',
          'and the node that lost is told to take the stored entry');

  t.check(db.statements.some(function (s) {
    return /FOR UPDATE/.test(s) && /sts_ldap_entries/.test(s);
  }), 'the rows are read under FOR UPDATE inside the flush\'s transaction');
  log.debug("Leaving sectionB().");
}

// ---------------------------------------------------------------------------
// C. THE REGISTRY AND THE SETTINGS, AT THE DRIVER.
// ---------------------------------------------------------------------------
async function sectionC(t, db) {
  log.debug("Entering sectionC().");
  t.log.info('=== C. a save deletes nothing another node wrote ===');
  const nodeA = driverOver();
  db.realms.set('beta', { id: 'beta', name: 'Beta', description: '',
                          created_at: 1, overrides: { 'b.key': 1 } });
  db.realms.set('alpha', { id: 'alpha', name: 'Alpha', description: '',
                           created_at: 1, overrides: { 'from.b': 'x' } });
  const alpha = { id: 'alpha', name: 'Alpha', description: '', createdAt: 1,
                  overrides: { 'from.a': 'y' } };
  await nodeA.saveRealms([alpha], { upserts: [{ row: alpha, name: false,
    description: false, set: { 'from.a': 'y' }, cleared: [] }],
    removed: [] });
  t.check(db.realms.has('beta'),
          'A REALM ANOTHER NODE CREATED SURVIVES THIS NODE SAVING ITS OWN — ' +
          'the wholesale save deleted every realm this process did not hold');
  t.equal(JSON.stringify(db.realms.get('alpha').overrides),
          JSON.stringify({ 'from.b': 'x', 'from.a': 'y' }),
          'and a setting another node made on the same realm survives: ' +
          'overrides are merged key by key');
  await nodeA.saveRealms([alpha], { upserts: [], removed: ['beta'] });
  t.check(!db.realms.has('beta'),
          'a realm is deleted when this process says it removed it, and ' +
          'only then');

  db.appconfig.set('set.by.b', { raw: 'b' });
  db.appconfig.set('known.to.a', { raw: 'old' });
  await nodeA.saveOverrides({ 'new.from.a': 'a' },
                            { set: { 'new.from.a': 'a' },
                              cleared: ['known.to.a'] });
  t.check(db.appconfig.has('set.by.b'),
          'A SETTING ANOTHER NODE WROTE SURVIVES THIS NODE\'S SAVE');
  t.check(!db.appconfig.has('known.to.a') && db.appconfig.has('new.from.a'),
          'while what this process cleared is deleted and what it set is ' +
          'written');
  const source = fs.readFileSync(path.join(__dirname, '..', 'persistence',
    'persistence_postgres.js'), 'utf8');
  t.check(!/DELETE FROM sts_(realms|appconfig) WHERE NOT/.test(source),
          'and no statement in the driver deletes a row for being absent ' +
          'from a list');
  log.debug("Leaving sectionC().");
}

// ---------------------------------------------------------------------------
// D. `persistence.js` ITSELF, OVER THE SAME DOUBLE.
// ---------------------------------------------------------------------------
function tick(ms) {
  log.debug("Entering tick().");
  log.debug("Leaving tick().");
  return new Promise(function (resolve) { setTimeout(resolve, ms || 5); });
}

async function sectionD(t, db) {
  log.debug("Entering sectionD().");
  t.log.info('=== D. persistence.js writes deltas, never the whole table ===');
  const config = require('../common/config');
  const realms = require('../common/realms');
  const persistence = require('../persistence/persistence');
  process.env.STS_PERSISTENCE_MODE = 'postgres';
  process.env.STS_PERSISTENCE_COORDINATE = 'true';
  const dirs = new Map();
  persistence.setDirectory({
    realmEntries: function (realmId) {
      const held = dirs.get(realmId) || new Map();
      return Array.from(held.keys()).map(function (key) {
        return { key: key, entry: held.get(key) };
      });
    },
    replaceRealm: function (realmId, list) {
      const held = new Map();
      list.forEach(function (row) {
        held.set(String(row.dn).toLowerCase(), row);
      });
      dirs.set(realmId, held);
    },
    entryAt: function (realmId, key) {
      return (dirs.get(realmId) || new Map()).get(key) || null;
    },
    applyEntry: function (realmId, key, row) {
      const held = dirs.get(realmId) || new Map();
      held.set(key, row);
      dirs.set(realmId, held);
    },
    removeEntry: function (realmId, key) {
      (dirs.get(realmId) || new Map()).delete(key);
    }
  });
  await persistence.start();
  t.equal(persistence.activeMode(), 'postgres',
          'the store opened over the double', persistence.status().lastError);

  await persistence.coordinate();

  realms.create({ id: 'lwwa', name: 'A' });
  await persistence.flush();
  t.check(db.realms.has('lwwa'), 'a realm created here is written down');

  // NODE B CREATES A REALM, and its directory rows reach this process before
  // its registry row does — the order a flush commits them in.
  const ghostDn = 'cn=ghost,dc=ghost';
  db.entries.set('ghost\n' + ghostDn, { realm: 'ghost', dn_key: ghostDn,
    dn: ghostDn, attrs: { cn: ['ghost'], entryuuid: ['gh-1'] },
    origin: 'seed', created_at: '1', modified_at: '1' });
  db.log.push({ seq: db.log.length + 1, origin: 'node-b', kind: 'directory',
                realm: 'ghost', key: ghostDn });
  await persistence.syncNow();
  t.check(!!(dirs.get('ghost') || new Map()).get(ghostDn),
          'node B\'s entry for its new realm was applied here');

  // NODE B, writing straight into the table: a realm of its own and a
  // setting, neither of which this process has applied.
  db.realms.set('lwwb', { id: 'lwwb', name: 'B', description: '',
                          created_at: Date.now(), overrides: {} });
  db.appconfig.set('audit.maxEvents', { raw: '4321' });

  const runtimeKey = 'oauth2.consentRequired';
  realms.setOverride('lwwa', runtimeKey, 'false');
  await persistence.flush();
  t.check(db.realms.has('lwwb'),
          'A REALM CREATED ON ANOTHER NODE SURVIVES A REALM CHANGE SAVED ' +
          'HERE — the save that deleted it is gone');
  t.check(db.entries.has('ghost\n' + ghostDn),
          'AND ITS DIRECTORY SURVIVES THE FULL WALK THAT CHANGE FORCED: a ' +
          'realm whose entries are here and whose registry row is not yet ' +
          'is not a realm this process removed');
  t.equal(String((db.realms.get('lwwa').overrides || {})[runtimeKey]),
          'false', 'and the change itself was written');

  config.setOverride('oid4vci.batchSize', '7');
  await persistence.flush();
  t.check(db.appconfig.has('audit.maxEvents'),
          'A SETTING WRITTEN ON ANOTHER NODE SURVIVES A SETTING SAVED HERE');
  t.check(db.appconfig.has('oid4vci.batchSize'),
          'and the setting made here was written');
  config.clearAllOverrides();
  await persistence.flush();
  t.check(!db.appconfig.has('oid4vci.batchSize'),
          'a reset-all clears every setting this process knows is stored');
  t.check(db.appconfig.has('audit.maxEvents'),
          'and not the one it never saw, which is another node\'s to clear');

  realms.remove('lwwa');
  await persistence.flush();
  t.check(!db.realms.has('lwwa') && db.realms.has('lwwb'),
          'A REALM REMOVED HERE IS DELETED, AND ONLY THAT ONE');
  await persistence.stop();
  await tick(20);
  log.debug("Leaving sectionD().");
}

// ---------------------------------------------------------------------------
// E. SESSIONS: A TOMBSTONE AND A MERGE.
// ---------------------------------------------------------------------------
async function armKeystore(dir) {
  log.debug("Entering armKeystore().");
  const keystore = require('../common/keystore');
  const kekFile = path.join(dir, 'kek');
  fs.writeFileSync(kekFile, nodeCrypto.randomBytes(32).toString('base64'),
                   { encoding: 'utf8', mode: 0o600 });
  process.env.STS_KEYS_SOURCE = 'persisted';
  process.env.STS_KEYS_KEK_PROVIDER = 'file';
  process.env.STS_KEYS_KEK_FILE = kekFile;
  keystore.reset();
  keystore.setStore({
    loadKeys: function () { return Promise.resolve([]); },
    saveKeys: function () { return Promise.resolve(); },
    deleteKeys: function () { return Promise.resolve(); }
  });
  await keystore.start();
  log.debug("Leaving armKeystore().");
}

async function sectionE(t, db, dir) {
  log.debug("Entering sectionE().");
  t.log.info('=== E. an ended session stays ended; two copies merge ===');
  const authn = require('../authn/authn');
  const merge = authn.mergeSessionRows;
  const arrival = { id: 's1', chosen: false, authenticated: false,
                    authTime: 100, lastSeenAt: 1000, expires: 5000,
                    user: { username: 'anonymous' } };
  const signedIn = Object.assign({}, arrival, { chosen: true,
    authenticated: true, authTime: 200, expires: 90000,
    user: { username: 'alice' } });
  const stale = Object.assign({}, arrival, { lastSeenAt: 3000 });
  const upgraded = merge(stale, signedIn);
  t.equal(upgraded.user.username + ' ' + upgraded.chosen + ' ' +
          upgraded.lastSeenAt,
          'alice true 3000',
          'A STALE ARRIVAL COPY DOES NOT UNDO A SIGN-IN: the upgraded copy ' +
          'is the base, and only the later clock is taken from the stale one');
  t.equal(JSON.stringify(merge(signedIn, stale).user),
          JSON.stringify(upgraded.user), 'whichever side it arrives from');

  const a = Object.assign({}, signedIn, {
    oidcClients: { app1: { first: 1, last: 5, count: 2 } },
    wsfedRealms: { 'urn:rp:1': 'https://rp1/' } });
  const b = Object.assign({}, signedIn, {
    oidcClients: { app2: { first: 3, last: 4, count: 1 } },
    saml2ServiceProviders: { 'urn:sp:2': { at: 1 } } });
  const lists = merge(a, b);
  t.equal(Object.keys(lists.oidcClients).sort().join(','), 'app1,app2',
          'A CLIENT EITHER COPY SIGNED INTO IS ON THE FRONT-CHANNEL LIST — ' +
          'a client lost from it never gets its logout iframe');
  t.check(lists.wsfedRealms['urn:rp:1'] &&
          lists.saml2ServiceProviders['urn:sp:2'],
          'and so are the WS-Federation realms and SAML service providers');

  // The flush, over the real driver: the store declares a tombstone and the
  // session merge, and product mode arms minted persistence.
  await armKeystore(dir);
  const config = require('../common/config');
  const realms = require('../common/realms');
  const keystore = require('../common/keystore');
  const minted = require('../persistence/persistence_minted');
  config.setOverride('global.mode', 'product');
  config.setOverride('persistence.minted', true);
  const store = realms.map({ persist: 'test.lww.sessions', tombstone: true,
                             mergeRow: merge });
  minted.reset();
  const driver = driverOver();
  minted.setDriver(driver, 'postgres');

  store.set('ended', Object.assign({}, signedIn, { id: 'ended' }));
  await minted.flush();
  // NODE A signs the session out: its delete reaches the table first.
  db.minted.set('test.lww.sessions\ndefault\nended',
                { handle: 'test.lww.sessions', realm: 'default',
                  key: 'ended', body: TOMBSTONE, written_ms: Date.now() });
  // …and this node, a moment behind, touches its copy.
  const behind = store.get('ended');
  behind.lastSeenAt = Date.now();
  store.set('ended', behind);
  const result = await minted.flush();
  t.equal(db.minted.get('test.lww.sessions\ndefault\nended').body, TOMBSTONE,
          'A SESSION ANOTHER NODE ENDED IS NOT WRITTEN BACK BY A NODE ' +
          'HOLDING AN OLDER COPY — the tombstone refused the upsert in SQL',
          JSON.stringify(result));
  t.check(!store.has('ended'),
          'and the stale copy is dropped here, so this node stops honouring ' +
          'a session that was signed out');

  // A STORE WITH A TOMBSTONE AND NO MERGE — an authorization code's shape —
  // is refused by the upsert's own guard.
  const codes = realms.map({ persist: 'test.lww.codes', tombstone: true });
  codes.set('code-1', { client: 'app1' });
  await minted.flush();
  db.minted.set('test.lww.codes\ndefault\ncode-1',
                { handle: 'test.lww.codes', realm: 'default', key: 'code-1',
                  body: TOMBSTONE, written_ms: Date.now() });
  codes.set('code-1', { client: 'app1', touched: true });
  await minted.flush();
  t.equal(db.minted.get('test.lww.codes\ndefault\ncode-1').body, TOMBSTONE,
          'A CODE ANOTHER NODE SPENT IS NOT WRITTEN BACK EITHER — the ' +
          'guarded upsert did nothing');
  t.check(!codes.has('code-1'), 'and it is dropped here');

  store.set('merged', Object.assign({}, a, { id: 'merged' }));
  await minted.flush();
  // NODE B writes its copy of the same session with a different client.
  const theirs = Object.assign({}, b, { id: 'merged' });
  db.minted.get('test.lww.sessions\ndefault\nmerged').body =
    keystore.seal(JSON.stringify(theirs), 'minted-rows');
  const mine = store.get('merged');
  mine.lastSeenAt = Date.now();
  store.set('merged', mine);
  await minted.flush();
  const stored = JSON.parse(keystore.open(
    db.minted.get('test.lww.sessions\ndefault\nmerged').body, 'minted-rows'));
  t.equal(Object.keys(stored.oidcClients).sort().join(','), 'app1,app2',
          'TWO NODES\' COPIES OF ONE SESSION MERGE IN THE STORE: both ' +
          'relying parties are on the stored row');
  t.equal(Object.keys((store.get('merged') || {}).oidcClients || {}).sort()
            .join(','), 'app1,app2',
          'and on this node\'s copy, which took what the store holds');

  store.delete('merged');
  await minted.flush();
  t.equal(db.minted.get('test.lww.sessions\ndefault\nmerged').body, TOMBSTONE,
          'a delete of a tombstoned store leaves a tombstone, not an absence');
  const rows = await driver.loadMinted();
  t.check(!rows.some(function (row) { return row.body === TOMBSTONE; }),
          'and no reader ever sees one: a restore skips it');
  log.debug("Leaving sectionE().");
}

// ---------------------------------------------------------------------------
// THE CHILD, and a harness that records for the parent to replay.
// ---------------------------------------------------------------------------
function recordingHarness() {
  log.debug("Entering recordingHarness().");
  const seen = [];
  function check(condition, what, detail) {
    log.debug("Entering check().");
    seen.push({ ok: !!condition, what: what, detail: detail || '' });
    log.debug("Leaving check().");
    return !!condition;
  }
  log.debug("Leaving recordingHarness().");
  return {
    log: log,
    seen: seen,
    check: check,
    equal: function (actual, expected, what, detail) {
      log.debug("Entering equal().");
      log.debug("Leaving equal().");
      return check(actual === expected, what,
                   'expected ' + JSON.stringify(expected) + ', got ' +
                   JSON.stringify(actual) + (detail ? ' — ' + detail : ''));
    }
  };
}

async function childMain() {
  log.debug("Entering childMain().");
  delete process.env.CONFIG_FILE;
  const out = process.env.PROBE_OUT;
  const t = recordingHarness();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-lww-'));
  let threw = '';
  const db = fakeDatabase();
  installFakePg(db);
  try {
    sectionA(t);
    await sectionB(t, db);
    await sectionC(t, db);
    await sectionD(t, db);
    await sectionE(t, db, dir);
  } catch (e) {
    log.debug("Caught in childMain(): " + ((e && e.message) || e));
    threw = (e && e.stack) || String(e);
  } finally {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch (e) {
      log.debug("Caught in childMain(): " + ((e && e.message) || e));
    }
  }
  fs.writeFileSync(out, JSON.stringify({ seen: t.seen, threw: threw }));
  log.debug("Leaving childMain().");
  process.exit(0);
}

function run(t) {
  log.debug("Entering run().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-lww-out-'));
  const outFile = path.join(dir, 'out.json');
  const env = Object.assign({}, process.env, { PROBE_OUT: outFile,
                                               LOG_LEVEL: 'fatal' });
  env[CHILD_FLAG] = '1';
  delete env.CONFIG_FILE;
  const child = childProcess.spawnSync(process.execPath, [__filename],
    { cwd: path.join(__dirname, '..'), env: env, encoding: 'utf8',
      timeout: 120000 });
  let result = null;
  try {
    result = JSON.parse(fs.readFileSync(outFile, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    t.bad('the child process reported nothing',
          'status ' + child.status + ', signal ' + child.signal + ': ' +
          String(child.stderr || '').slice(-2000));
    log.debug("Leaving run().");
    return;
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  result.seen.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  if (result.threw) {
    t.bad('the child process threw', result.threw);
  }
  t.check(result.seen.length >= 30,
          'every section ran — a section that stopped being reached would ' +
          'take its assertions with it and still say "passed"',
          String(result.seen.length) + ' assertion(s) recorded');
  log.debug("Leaving run().");
}

if (require.main === module && process.env[CHILD_FLAG] === '1') {
  childMain();
}

module.exports = {
  name: 'cluster_lww_stores',
  describe: 'issue #46 section 3: directory merges, saves that delete ' +
            'nothing foreign, tombstoned and merged sessions',
  run: run
};
