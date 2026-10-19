// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/directory_create_cluster_claims.js
//
// ===========================================================================
// CHEAPER UNIQUENESS CLAIMS FOR DIRECTORY CREATES (#628, 2026-10-14).
//
// A directory create claims its DN and username before its door asks the
// directory (`ldap/directory_create_claims.ts`, #46 section 3). It was two
// INSERTs into `sts_cluster_claims`, a catch-up, the add and its flush, and
// two DELETEs after the commit, each a transaction of its own — under a bulk
// load the most frequent statements on the database. Three changes, each
// held here:
//
//   A. THE DRIVER'S STATEMENTS. `claimMany()` is ONE statement for every row
//      and answers all-or-none (a partial take is aborted inside the
//      statement and recognised); `releaseClaims()` is one statement; and
//      `saveDirectory()` sends a create's release as a statement of its own
//      transaction, before COMMIT.
//   B. THROUGH persistence.js, ACTIVE-ACTIVE (the store decides), over a
//      `pg` double that keeps the claims table and transactions:
//        B1  per add: ONE claim statement outside any transaction, and the
//            release INSIDE the transaction that writes the entry;
//        B2  CONTROL, the shape before #628 (a store with only `claimOnce()`
//            and `releaseClaim()`): two claims and two releases, each alone;
//        B3  a refused create gives its claim back AT ONCE, one statement,
//            no flush waited for;
//        B4  a flush that FAILS keeps the claim, so the name is refused as in
//            progress — until the claim expires, when it is taken over.
//        B5  one node (cluster off, workers dispatched): NO claim statement.
//   C. TWO PROCESSES, ONE STORE, ACTIVE-ACTIVE: concurrent creates of the
//      same names from two node processes through the store path — exactly
//      one created per name, the other the directory's own "exists".
//   D. ONE NODE, TWO WORKER THREADS, THE FRONT ARBITRATING IN MEMORY over the
//      worker channel: the same race, exactly one per name and no database
//      call; a refused create gives its claim back at once; a worker that
//      dies gives back what it held; and the pool is wired to the arbiter.
//
// WHY IN PROCESS (tests/CLAUDE.md's first question): a race between two
// processes on one claim, a COMMIT that fails on demand and a worker thread
// killed while it holds a claim cannot be arranged over HTTP. B, C and D run
// in CHILD PROCESSES because a store, the arbiter and the settings are
// process-wide.
// ===========================================================================

const storeDouble = require('./tools/store_double');
const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const workerThreads = require('worker_threads');

const log = require('bunyan').createLogger({
  name: 'directory_create_cluster_claims',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const ROLE_VAR = 'STS_DCC_ROLE';
const BASE = 'dc=example,dc=com';
const USERS = 'ou=users,' + BASE;
const NAMES = 24;

function dnOf(name) {
  log.debug("Entering dnOf().");
  log.debug("Leaving dnOf().");
  return 'uid=' + name + ',' + USERS;
}

function later(fn) {
  log.debug("Entering later().");
  log.debug("Leaving later().");
  return new Promise(function (resolve, reject) {
    setImmediate(function () {
      try {
        resolve(fn());
      } catch (e) {
        log.debug("Caught in later(): " + ((e && e.message) || e));
        reject(e);
      }
    });
  });
}

function pause(ms) {
  log.debug("Entering pause().");
  log.debug("Leaving pause().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

// ---------------------------------------------------------------------------
// A `pg` DOUBLE: the claims table with PostgreSQL's per-statement atomicity
// and the store's clock, transactions whose COMMIT can be made to fail, and
// enough of the directory and change log for persistence.js to start and
// flush. Every statement is logged with the transaction it ran in.
// ---------------------------------------------------------------------------
function fakeDatabase() {
  log.debug("Entering fakeDatabase().");
  const db = { claims: new Map(), entries: new Map(), changes: [],
               statements: [], skewMs: 0, failNextClaimCommit: false,
               txSeq: 0 };
  db.now = function () {
    return Date.now() + db.skewMs;
  };
  const claimKey = function (scope, realm, key) {
    return scope + '\n' + realm + '\n' + key;
  };
  const rows = function (list) {
    return Promise.resolve({ rows: list, rowCount: list.length });
  };
  const deleteClaims = function (p) {
    let removed = 0;
    for (let i = 0; i < p[0].length; i += 1) {
      const k = claimKey(p[0][i], p[1][i], p[2][i]);
      const row = db.claims.get(k);
      if (row && row.reservation === p[3][i]) {
        db.claims.delete(k);
        removed += 1;
      }
    }
    return removed;
  };
  db.query = function (client, sql, params) {
    const text = String(sql).replace(/\s+/g, ' ').trim();
    const p = params || [];
    const tx = client && client.tx ? client.tx : null;
    db.statements.push({ text: text, tx: tx ? tx.id : 0 });
    if (text === 'BEGIN') {
      db.txSeq += 1;
      client.tx = { id: db.txSeq, effects: [], releases: false };
      return rows([]);
    }
    if (text === 'COMMIT' || text === 'ROLLBACK') {
      const ending = client && client.tx;
      client.tx = null;
      if (text === 'ROLLBACK' || !ending) {
        return rows([]);
      }
      if (ending.releases && db.failNextClaimCommit) {
        db.failNextClaimCommit = false;
        return Promise.reject(new Error('the commit failed on purpose'));
      }
      ending.effects.forEach(function (effect) {
        effect();
      });
      return rows([]);
    }
    if (/^SELECT to_regclass/.test(text)) {
      const one = {};
      for (let i = 0; i < 200; i += 1) {
        one['o' + i] = 'present';
      }
      return rows([one]);
    }
    if (/^WITH wanted AS \(SELECT w\.scope, w\.key, w\.ord FROM unnest/
          .test(text)) {
      // claimMany(): ONE statement, every row or none.
      return later(function () {
        const now = db.now();
        const keys = p[0].map(function (scope, i) {
          return claimKey(scope, p[2], p[1][i]);
        });
        const free = keys.map(function (k) {
          const row = db.claims.get(k);
          return !row || row.expiresAt <= now;
        });
        const taken = free.filter(Boolean).length;
        const refused = free.indexOf(false) + 1;
        if (taken > 0 && taken < keys.length) {
          throw new Error('invalid input syntax for type integer: ' +
            '"sts_cluster_claims: a partial claim of ' + taken + ' of ' +
            keys.length + ' rows is rolled back; first refused row ' +
            refused + '"');
        }
        if (taken === keys.length) {
          keys.forEach(function (k) {
            db.claims.set(k, { reservation: p[3], expiresAt: now + p[5] });
          });
          return { rows: [{ n: taken, claimed_at: now, refused: null,
                            partial: 0 }], rowCount: 1 };
        }
        return { rows: [{ n: 0, claimed_at: null, refused: refused,
                          partial: 0 }], rowCount: 1 };
      });
    }
    if (/^DELETE FROM sts_cluster_claims c USING unnest/.test(text) ||
        /^WITH quiet AS .* DELETE FROM sts_cluster_claims c USING unnest/
          .test(text)) {
      if (tx) {
        tx.releases = true;
        tx.effects.push(function () {
          deleteClaims(p);
        });
        return rows([]);
      }
      return later(function () {
        const n = deleteClaims(p);
        return { rows: [], rowCount: n };
      });
    }
    if (/^INSERT INTO sts_cluster_claims \(scope, realm, key, reservation, origin, claimed_at, expires_at\) VALUES/
          .test(text)) {
      // claimOnce(), the control's shape. A process's own ORIGIN claim
      // (realm '') is granted and kept out of the table this file counts.
      return later(function () {
        const now = db.now();
        if (p[1] === '') {
          return { rows: [{ claimed_at: now, expires_at: now + p[5] }],
                   rowCount: 1 };
        }
        const k = claimKey(p[0], p[1], p[2]);
        const row = db.claims.get(k);
        if (row && row.expiresAt > now) {
          return { rows: [], rowCount: 0 };
        }
        db.claims.set(k, { reservation: p[3], expiresAt: now + p[5] });
        return { rows: [{ claimed_at: now, expires_at: now + p[5] }],
                 rowCount: 1 };
      });
    }
    if (/^DELETE FROM sts_cluster_claims WHERE scope = \$1 AND realm = \$2 AND key = \$3 AND reservation = \$4/
          .test(text)) {
      return later(function () {
        const k = claimKey(p[0], p[1], p[2]);
        const row = db.claims.get(k);
        if (row && row.reservation === p[3]) {
          db.claims.delete(k);
          return { rows: [], rowCount: 1 };
        }
        return { rows: [], rowCount: 0 };
      });
    }
    // The origin fence and its renewal: held.
    if (/^SELECT 1 FROM sts_cluster_claims WHERE scope = \$1 AND realm = '' /
          .test(text) ||
        /^UPDATE sts_cluster_claims SET expires_at = /.test(text)) {
      return Promise.resolve({ rows: [{ one: 1 }], rowCount: 1 });
    }
    if (/^INSERT INTO sts_changes/.test(text)) {
      for (let i = 0; i + 3 < p.length; i += 4) {
        db.changes.push({ seq: db.changes.length + 1, origin: p[i],
                          kind: p[i + 1], realm: p[i + 2], key: p[i + 3] });
      }
      return rows([]);
    }
    if (/SELECT COALESCE\(MAX\(seq\), 0\) AS seq FROM sts_changes/
          .test(text)) {
      return rows([{ seq: db.changes.length }]);
    }
    if (/^INSERT INTO sts_ldap_entries/.test(text)) {
      db.entries.set(p[0] + '\n' + p[1], { realm: p[0], dn_key: p[1] });
      return rows([]);
    }
    return rows([]);
  };
  log.debug("Leaving fakeDatabase().");
  return db;
}

function installFakePg(db) {
  log.debug("Entering installFakePg().");
  function FakeClient() {
    this.tx = null;
  }
  FakeClient.prototype.query = function (sql, params) {
    return db.query(this, sql, params);
  };
  FakeClient.prototype.release = function () {};
  FakeClient.prototype.on = function () {};
  FakeClient.prototype.removeListener = function () {};
  FakeClient.prototype.connect = function () {
    return Promise.resolve();
  };
  FakeClient.prototype.end = function () {
    return Promise.resolve();
  };
  function FakePool() {}
  FakePool.prototype.on = function () {};
  FakePool.prototype.connect = function () {
    return Promise.resolve(new FakeClient());
  };
  FakePool.prototype.query = function (sql, params) {
    return db.query(null, sql, params);
  };
  FakePool.prototype.end = function () {
    return Promise.resolve();
  };
  storeDouble.install({ Pool: FakePool, Client: FakeClient });
  log.debug("Leaving installFakePg().");
}

// The statements that touched the claims table since `from`, and, for each,
// whether it ran inside a transaction that also wrote a directory entry.
function claimStatements(db, from) {
  log.debug("Entering claimStatements().");
  const list = db.statements.slice(from);
  const entryTx = new Set(list.filter(function (s) {
    return /^INSERT INTO sts_ldap_entries/.test(s.text) && s.tx;
  }).map(function (s) {
    return s.tx;
  }));
  // A create's claims and releases — not this process's origin fence, which
  // every transaction checks and a timer renews.
  const out = list.filter(function (s) {
    return /^(WITH wanted AS|WITH quiet AS|DELETE FROM sts_cluster_claims|INSERT INTO sts_cluster_claims)/
      .test(s.text);
  }).map(function (s) {
    return { kind: /DELETE FROM sts_cluster_claims/.test(s.text) ? 'release'
      : 'claim',
             tx: s.tx, withEntry: entryTx.has(s.tx) };
  });
  log.debug("Leaving claimStatements().");
  return out;
}

// ===========================================================================
// B: persistence.js over the double, in a child.
// ===========================================================================
async function persistChild() {
  log.debug("Entering persistChild().");
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };
  const db = fakeDatabase();
  installFakePg(db);
  const persistence = require('../persistence/persistence');
  // The directory: one realm's entries, by normalised DN.
  const dir = new Map();
  persistence.setDirectory({
    realmEntries: function (realmId) {
      return realmId === 'default' ? Array.from(dir.keys()).map(function (k) {
        return { key: k, entry: dir.get(k) };
      }) : [];
    },
    entryAt: function (realmId, key) {
      return realmId === 'default' ? (dir.get(key) || null) : null;
    },
    replaceRealm: function () {
      return undefined;
    },
    applyEntry: function () {},
    removeEntry: function () {},
    forgetEntry: function () {}
  });
  await persistence.start();
  note(persistence.activeMode() === 'postgres',
       'B0. the store opened over the double', persistence.status().lastError);
  const Claims = require('../ldap/directory_create_claims');
  const DCC = Claims.DirectoryCreateClaims;
  const inStore = new DCC(Object.assign(DCC.defaultDeps(), {
    isActiveActive: function () { return true; },
    clusterMode: function () { return 'active-active'; }
  }));
  const create = async function (claimer, name, waitMs) {
    const dn = dnOf(name);
    const held = await claimer.claim({ realm: 'default', dns: [dn],
                                       usernames: [name], waitMs: waitMs });
    if (!held.ok) {
      return { refused: held.code };
    }
    if (dir.has(dn)) {
      const back = await held.settle(false);
      return { exists: true, released: back && back.released };
    }
    dir.set(dn, { dn: dn, attributes: { uid: [name],
                                        objectClass: ['inetOrgPerson'] },
                  createdAt: new Date().toISOString(),
                  modifiedAt: new Date().toISOString() });
    persistence.directoryChanged(dn);
    const released = await held.settle(true);
    return { created: true, released: released };
  };

  // B1. One add, the store deciding.
  let from = db.statements.length;
  const first = await create(inStore, 'ann');
  await pause(20);
  const b1 = claimStatements(db, from);
  note(first.created && first.released && first.released.released === true &&
       b1.length === 2 && b1[0].kind === 'claim' && b1[0].tx === 0 &&
       b1[1].kind === 'release' && b1[1].tx > 0 && b1[1].withEntry &&
       db.claims.size === 0,
       'B1. AN ADD, ACTIVE-ACTIVE: ONE claim statement for the DN and the ' +
       'username together, and the release a statement OF THE TRANSACTION ' +
       'THAT WRITES THE ENTRY — two statements on the claims table, one ' +
       'transaction of their own (it was four)',
       JSON.stringify({ result: first, statements: b1,
                        left: db.claims.size }));

  // B2. CONTROL: the shape before #628 — a store that has only the one-row
  // claim and release, asked as the module asked it.
  const driver = persistence.clusterStore();
  const oneRow = {
    claimOnce: driver.claimOnce.bind(driver),
    releaseClaim: driver.releaseClaim.bind(driver),
    claimHeld: driver.claimHeld.bind(driver),
    purgeClaims: driver.purgeClaims.bind(driver)
  };
  const realClusterStore = persistence.clusterStore;
  persistence.clusterStore = function () {
    return oneRow;
  };
  from = db.statements.length;
  const control = await create(inStore, 'bea');
  await pause(20);
  persistence.clusterStore = realClusterStore;
  const b2 = claimStatements(db, from);
  note(control.created &&
       b2.filter(function (s) { return s.kind === 'claim'; }).length === 2 &&
       b2.filter(function (s) {
         return s.kind === 'release' && s.tx === 0;
       }).length === 2 && db.claims.size === 0,
       'B2. CONTROL — the shape before #628: two claims and two releases, ' +
       'each a statement of its own outside any transaction (so B1 measures ' +
       'the change)', JSON.stringify(b2));

  // B3. A create refused by the directory's own check gives its claim back
  // at once: one statement, no flush awaited, and the next create of the
  // name is not refused as in progress.
  from = db.statements.length;
  const again = await create(inStore, 'ann', 0);
  const b3 = claimStatements(db, from);
  const between = db.statements.slice(from).map(function (s) {
    return s.text;
  });
  const releasedAt = between.findIndex(function (text) {
    return /DELETE FROM sts_cluster_claims/.test(text);
  });
  const transactionBefore = between.slice(0, Math.max(0, releasedAt))
    .indexOf('BEGIN') >= 0;
  const third = await create(inStore, 'ann', 0);
  note(again.exists && again.released === true && b3.length === 2 &&
       releasedAt >= 0 && /synchronous_commit/.test(between[releasedAt]) &&
       b3[1].kind === 'release' && b3[1].tx === 0 && !transactionBefore &&
       third.exists,
       'B3. A REFUSED CREATE GIVES ITS CLAIM BACK AT ONCE — one statement, ' +
       'no flush waited for — and the next create of the name meets the ' +
       'directory, not STS-LDAP-0092',
       JSON.stringify({ again: again, statements: b3, third: third }));

  // B4. A flush that fails keeps the claim until it expires.
  db.failNextClaimCommit = true;
  const failed = await create(inStore, 'cat');
  const heldAfter = db.claims.size;
  const blocked = await create(inStore, 'cat', 150);
  db.skewMs = Claims.CLAIM_TTL_MS + 1000;
  const afterExpiry = await inStore.claim({ realm: 'default',
                                            dns: [dnOf('cat')],
                                            usernames: ['cat'], waitMs: 0 });
  if (afterExpiry.ok) {
    await afterExpiry.settle(false);
  }
  db.skewMs = 0;
  note(failed.created && failed.released &&
       failed.released.released === false && heldAfter === 2 &&
       blocked.refused === 'STS-LDAP-0092' && afterExpiry.ok,
       'B4. A FLUSH THAT FAILS KEEPS THE CLAIM: its release rolled back with ' +
       'the entry, so the name is refused as in progress (STS-LDAP-0092) ' +
       'until the claim expires — and taken over after',
       JSON.stringify({ failed: failed, held: heldAfter, blocked: blocked,
                        afterExpiry: afterExpiry.ok }));

  // B5. One node: the front process decides, and the store is not asked.
  process.env.STS_WORKERS_REQUEST_COUNT = '1';
  process.env.STS_WORKERS_DISPATCH = '*';
  const onOneNode = new DCC(Object.assign(DCC.defaultDeps(), {
    isActiveActive: function () { return false; },
    clusterMode: function () { return 'off'; }
  }));
  from = db.statements.length;
  const local = await create(onOneNode, 'dan');
  await pause(20);
  const b5 = claimStatements(db, from);
  note(onOneNode.active() && onOneNode.arbitratedHere() && local.created &&
       local.released && local.released.released === true &&
       b5.length === 0,
       'B5. ONE NODE (cluster off, workers dispatched): the front process ' +
       'decides, and an add makes NO statement on the claims table',
       JSON.stringify({ local: local, statements: b5 }));
  const passive = new DCC(Object.assign(DCC.defaultDeps(), {
    isActiveActive: function () { return false; },
    clusterMode: function () { return 'active-passive'; }
  }));
  const unknown = new DCC(Object.assign(DCC.defaultDeps(), {
    isActiveActive: function () { return false; },
    clusterMode: function () { return 'something-new'; }
  }));
  note(passive.arbitratedHere() && !inStore.arbitratedHere() &&
       !unknown.arbitratedHere(),
       'B6. the line: off and active-passive are one node\'s to decide; ' +
       'active-active, and a mode this module does not know, are the ' +
       'store\'s');
  await persistence.stop();
  log.debug("Leaving persistChild().");
  return findings;
}

// ===========================================================================
// C: one of two node processes on one store, active-active. The store and
// the directory's committed entries are the PARENT's, over IPC.
// ===========================================================================
async function nodeChild() {
  log.debug("Entering nodeChild().");
  let nextId = 1;
  const waiting = new Map();
  process.on('message', function (message) {
    if (message && message.answer) {
      const resolve = waiting.get(message.id);
      waiting.delete(message.id);
      if (resolve) {
        resolve(message.value);
      }
    }
  });
  const ask = function (op, args) {
    return new Promise(function (resolve) {
      const id = nextId;
      nextId += 1;
      waiting.set(id, resolve);
      process.send({ ask: true, id: id, op: op, args: args });
    });
  };
  const local = new Set();
  let pending = [];
  let syncs = 0;
  const store = {
    claimMany: function (rows, realmId, opts) {
      return ask('claimMany', [rows, realmId, opts]);
    },
    releaseClaims: function (rows) {
      return ask('releaseClaims', [rows]);
    },
    claimOnce: function () {
      return Promise.reject(new Error('not this path'));
    },
    releaseClaim: function () {
      return Promise.resolve(false);
    },
    purgeClaims: function () {
      return Promise.resolve(0);
    }
  };
  const fakePersistence = {
    clusterStore: function () {
      return store;
    },
    flush: function () {
      const writing = pending;
      pending = [];
      return ask('write', [writing]).then(function () {
        return { written: true };
      });
    },
    syncNow: function () {
      syncs += 1;
      return ask('read', []).then(function (names) {
        names.forEach(function (name) {
          local.add(name);
        });
      });
    }
  };
  const persistence = require('../persistence/persistence');
  // What cluster_claims.js reaches: the store, and the flush its
  // after-the-flush release waits for.
  persistence.clusterStore = fakePersistence.clusterStore;
  persistence.flush = fakePersistence.flush;
  persistence.syncNow = fakePersistence.syncNow;
  const DCC = require('../ldap/directory_create_claims').DirectoryCreateClaims;
  const claimer = new DCC(Object.assign(DCC.defaultDeps(), {
    isActiveActive: function () { return true; },
    clusterMode: function () { return 'active-active'; },
    loadPersistence: function () { return fakePersistence; }
  }));
  const names = await new Promise(function (resolve) {
    process.on('message', function (message) {
      if (message && message.go) {
        resolve(message.names);
      }
    });
    process.send({ ready: true });
  });
  const outcomes = await Promise.all(names.map(async function (name) {
    const held = await claimer.claim({ realm: 'default', dns: [dnOf(name)],
                                       usernames: [name] });
    if (!held.ok) {
      return { name: name, outcome: 'refused:' + held.code };
    }
    if (local.has(name)) {
      await held.settle(false);
      return { name: name, outcome: 'exists' };
    }
    local.add(name);
    pending.push(name);
    await held.settle(true);
    return { name: name, outcome: 'created' };
  }));
  log.debug("Leaving nodeChild().");
  return { outcomes: outcomes, syncs: syncs };
}

// The parent's half of C: the claims table (one statement at a time, as the
// database runs them) and the committed entries, for two children.
function runTwoNodes() {
  log.debug("Entering runTwoNodes().");
  const claims = new Map();
  const committed = new Map();
  let duplicates = 0;
  let claimCalls = 0;
  const names = [];
  for (let i = 0; i < NAMES; i += 1) {
    names.push('aa' + i);
  }
  const answer = function (op, args, who) {
    if (op === 'claimMany') {
      claimCalls += 1;
      const rows = args[0];
      const realmId = args[1];
      const opts = args[2];
      const now = Date.now();
      const keys = rows.map(function (row) {
        return row.scope + '\n' + realmId + '\n' + row.key;
      });
      const held = keys.findIndex(function (k) {
        const row = claims.get(k);
        return !!row && row.expiresAt > now;
      });
      if (held >= 0) {
        return { claimed: false, refused: held };
      }
      keys.forEach(function (k) {
        claims.set(k, { reservation: opts.reservation,
                        expiresAt: now + opts.ttlMs });
      });
      return { claimed: true, claimedAt: now };
    }
    if (op === 'releaseClaims') {
      let n = 0;
      args[0].forEach(function (row) {
        const k = row.scope + '\n' + row.realm + '\n' + row.key;
        const kept = claims.get(k);
        if (kept && kept.reservation === row.reservation) {
          claims.delete(k);
          n += 1;
        }
      });
      return n;
    }
    if (op === 'write') {
      args[0].forEach(function (name) {
        if (committed.has(name)) {
          duplicates += 1;
        }
        committed.set(name, who);
      });
      return true;
    }
    if (op === 'read') {
      return Array.from(committed.keys());
    }
    return null;
  };
  return new Promise(function (resolve) {
    const children = [];
    const results = [];
    let ready = 0;
    let settled = false;
    const finish = function (outcome) {
      if (settled) {
        return;
      }
      settled = true;
      children.forEach(function (child) {
        try {
          child.kill();
        } catch (e) {
          log.debug("Caught in runTwoNodes(): " + ((e && e.message) || e));
        }
      });
      resolve(outcome);
    };
    const timer = setTimeout(function () {
      finish({ error: 'the two nodes did not finish in 60s' });
    }, 60000);
    [0, 1].forEach(function (index) {
      const env = Object.assign({}, process.env, { LOG_LEVEL: 'fatal',
                                                   STS_LOG_LEVEL: 'fatal' });
      env[ROLE_VAR] = 'node';
      delete env.CONFIG_FILE;
      const child = childProcess.fork(__filename, [], { env: env,
                                                       cwd: ROOT,
                                                       silent: true });
      children.push(child);
      child.on('message', function (message) {
        if (message && message.ask) {
          // EVERY ANSWER A MACROTASK LATER, as a round trip is.
          setImmediate(function () {
            const value = answer(message.op, message.args, index);
            try {
              child.send({ answer: true, id: message.id, value: value });
            } catch (e) {
              log.debug("Caught in runTwoNodes(): " + ((e && e.message) || e));
            }
          });
          return;
        }
        if (message && message.ready) {
          ready += 1;
          if (ready === 2) {
            children.forEach(function (one) {
              one.send({ go: true, names: names });
            });
          }
          return;
        }
        if (message && message.result) {
          results[index] = message.result;
          if (results.filter(Boolean).length === 2) {
            clearTimeout(timer);
            finish({ results: results, committed: committed.size,
                     duplicates: duplicates, claimCalls: claimCalls,
                     claimsLeft: claims.size });
          }
        }
      });
      child.on('exit', function (code) {
        if (!results[index]) {
          clearTimeout(timer);
          finish({ error: 'node ' + index + ' exited (' + code + ')' });
        }
      });
    });
    log.debug("Leaving runTwoNodes().");
  });
}

// ===========================================================================
// D: one node — this child is the FRONT, with the real arbiter, and starts
// two worker threads of this file.
// ===========================================================================
async function frontChild() {
  log.debug("Entering frontChild().");
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };
  process.env.STS_WORKERS_REQUEST_COUNT = '1';
  process.env.STS_WORKERS_DISPATCH = '*';
  const arbiter = require('../ldap/directory_create_arbiter').arbiter;
  const committed = new Map();
  let duplicates = 0;
  const workers = [];
  const answers = new Map();
  const start = function (index) {
    const worker = new workerThreads.Worker(__filename, {
      workerData: { role: 'worker', index: index },
      env: Object.assign({}, process.env, { [ROLE_VAR]: '' })
    });
    const entry = { pid: worker.threadId, child: {
      send: function (message) {
        worker.postMessage(message);
        return true;
      } } };
    worker.on('message', function (message) {
      if (message && message.createClaim) {
        arbiter.receive(entry, message);
        return;
      }
      if (message && message.store === 'write') {
        message.names.forEach(function (name) {
          if (committed.has(name)) {
            duplicates += 1;
          }
          committed.set(name, index);
        });
        worker.postMessage({ storeAnswer: true, id: message.id });
        return;
      }
      if (message && message.store === 'read') {
        worker.postMessage({ storeAnswer: true, id: message.id,
                             names: Array.from(committed.keys()) });
        return;
      }
      if (message && message.done) {
        const resolve = answers.get(message.id);
        answers.delete(message.id);
        if (resolve) {
          resolve(message.value);
        }
      }
    });
    const exited = new Promise(function (resolve) {
      worker.on('exit', function () {
        // What the pool's reap() does for a worker that has gone.
        resolve(arbiter.workerExited(entry));
      });
    });
    workers[index] = { worker: worker, exited: exited };
    return new Promise(function (resolve) {
      worker.once('online', resolve);
    });
  };
  let nextCommand = 1;
  const command = function (index, cmd, args) {
    return new Promise(function (resolve) {
      const id = nextCommand;
      nextCommand += 1;
      answers.set(id, resolve);
      workers[index].worker.postMessage({ command: true, id: id, cmd: cmd,
                                          args: args });
    });
  };
  await Promise.all([start(0), start(1)]);
  const names = [];
  for (let i = 0; i < NAMES; i += 1) {
    names.push('one' + i);
  }
  const raced = await Promise.all([command(0, 'run', names),
                                   command(1, 'run', names)]);
  const byName = {};
  raced.forEach(function (result) {
    result.outcomes.forEach(function (one) {
      (byName[one.name] = byName[one.name] || []).push(one.outcome);
    });
  });
  const wrong = Object.keys(byName).filter(function (name) {
    return byName[name].slice(0).sort().join(',') !== 'created,exists';
  });
  note(wrong.length === 0 && Object.keys(byName).length === NAMES &&
       committed.size === NAMES && duplicates === 0,
       'D1. ONE NODE, TWO WORKERS, THE SAME ' + NAMES + ' NAMES AT ONCE: ' +
       'exactly one created per name, and the other met the directory\'s own ' +
       '"exists" after waiting for the claim',
       JSON.stringify({ wrong: wrong.slice(0, 5).map(function (name) {
         return name + '=' + byName[name].join('/');
       }), committed: committed.size, duplicates: duplicates }));
  note(raced.every(function (result) { return result.storeCalls === 0; }),
       'D2. and not one claim reached the store: the front process decided ' +
       'every one in memory', JSON.stringify(raced.map(function (result) {
         return result.storeCalls;
       })));
  const syncs = raced.reduce(function (sum, result) {
    return sum + result.syncs;
  }, 0);
  note(syncs >= 1 && syncs <= NAMES,
       'D3. the winner of a claim another worker COMMITTED catches up before ' +
       'its door looks, and only then: ' + syncs + ' catch-up(s) for ' +
       NAMES + ' contested names, none for a name first claimed',
       String(syncs));
  const syncedBefore = raced[1].syncs;
  const fresh = [];
  for (let i = 0; i < 5; i += 1) {
    fresh.push('alone' + i);
  }
  const alone = await command(1, 'run', fresh);
  note(alone.outcomes.every(function (one) {
    return one.outcome === 'created';
  }) && alone.syncs === syncedBefore,
       'D3b. and a name nobody has created costs no catch-up at all — the ' +
       'store claim made every winner pull', JSON.stringify({
         before: syncedBefore, after: alone.syncs }));
  const left = arbiter.stats();
  note(left.live === 0, 'D4. every claim was given back',
       JSON.stringify(left));

  // A refused create gives its claim back at once.
  const DCC = require('../ldap/directory_create_claims').DirectoryCreateClaims;
  const fakePersistence = {
    clusterStore: function () { return {}; },
    flush: function () { return Promise.resolve({ written: false }); },
    syncNow: function () { return Promise.resolve(); }
  };
  const front = new DCC(Object.assign(DCC.defaultDeps(), {
    isActiveActive: function () { return false; },
    clusterMode: function () { return 'off'; },
    loadPersistence: function () { return fakePersistence; }
  }));
  const tryNow = async function (name) {
    const held = await front.claim({ realm: 'default', dns: [dnOf(name)],
                                     usernames: [name], waitMs: 0 });
    if (held.ok) {
      await held.settle(false);
    }
    return held.ok ? 'ok' : held.code;
  };
  const refusedThen = await command(1, 'refuse', ['yan']);
  const afterRefusal = await tryNow('yan');
  note(refusedThen === 'refused-and-released' && afterRefusal === 'ok',
       'D5. A CREATE A WORKER REFUSES GIVES ITS CLAIM BACK AT ONCE: the ' +
       'front can take the name with no wait', refusedThen + ' ' +
       afterRefusal);

  // One node, a flush that fails: the claim stays held.
  const failing = new DCC(Object.assign(DCC.defaultDeps(), {
    isActiveActive: function () { return false; },
    clusterMode: function () { return 'off'; },
    loadPersistence: function () {
      return {
        clusterStore: function () { return {}; },
        flush: function () {
          return Promise.resolve({ written: false,
                                   error: 'the flush failed on purpose' });
        },
        syncNow: function () { return Promise.resolve(); }
      };
    }
  }));
  const failedHeld = await failing.claim({ realm: 'default',
                                           dns: [dnOf('vic')],
                                           usernames: ['vic'], waitMs: 0 });
  const failedBack = failedHeld.ok ? await failedHeld.settle(true) : null;
  const meanwhile = await tryNow('vic');
  note(failedHeld.ok && failedBack && failedBack.released === false &&
       meanwhile === 'STS-LDAP-0092',
       'D8. ONE NODE, A FLUSH THAT FAILS KEEPS THE CLAIM, as a rolled-back ' +
       'release does in the store: the name is refused as in progress',
       JSON.stringify({ back: failedBack, meanwhile: meanwhile }));

  // The arbiter's own clock and memory, on an instance of its own.
  const Arbiter = require('../ldap/directory_create_arbiter')
    .DirectoryCreateArbiter;
  let clock = 1000000;
  const own = new Arbiter(Object.assign(Arbiter.defaultDeps(), {
    now: function () { return clock; }
  }));
  const firstGrant = own.decide('worker:1', ['k'], 1000);
  const whileLive = own.decide('worker:2', ['k'], 1000);
  clock += 1500;
  const afterLapse = own.decide('worker:2', ['k'], 1000);
  note(firstGrant.ok && !whileLive.ok && whileLive.reason === 'used' &&
       afterLapse.ok,
       'D9. a claim nobody gives back lapses after its lifetime and is ' +
       'taken over, as a row past expires_at is',
       JSON.stringify([firstGrant.ok, whileLive.reason, afterLapse.ok]));
  for (let i = 0; i <= Arbiter.MAX_SETTLED; i += 1) {
    const granted = own.decide('worker:1', ['m' + i], 60000);
    own.settle('worker:1', granted.reservation, ['m' + i], true);
  }
  const forgot = own.stats();
  const mustPull = own.decide('worker:3', ['fresh-1'], 60000);
  own.caughtUpTo('worker:3', mustPull.through);
  const afterPull = own.decide('worker:3', ['fresh-2'], 60000);
  note(forgot.settled === Arbiter.MAX_SETTLED && forgot.forgottenThrough > 0 &&
       mustPull.catchUp === true && afterPull.catchUp === false,
       'D10. BOUNDED: past ' + Arbiter.MAX_SETTLED + ' remembered creates the ' +
       'oldest is forgotten, and a holder that has not pulled since must ' +
       'pull once — then not again',
       JSON.stringify({ stats: forgot, mustPull: mustPull.catchUp,
                        afterPull: afterPull.catchUp }));

  // A holder is caught up only once its pull has FINISHED: a second create
  // granted while the first one's pull is still running must pull too.
  const gated = new Arbiter(Arbiter.defaultDeps());
  const other = gated.decide('worker:9', ['default\u0000directory.dn\u0000' +
    dnOf('p1'), 'default\u0000directory.username\u0000p1'], 60000);
  gated.settle('worker:9', other.reservation,
               ['default\u0000directory.dn\u0000' + dnOf('p1'),
                'default\u0000directory.username\u0000p1'], true);
  const another = gated.decide('worker:9', ['default\u0000directory.dn\u0000' +
    dnOf('p2'), 'default\u0000directory.username\u0000p2'], 60000);
  gated.settle('worker:9', another.reservation,
               ['default\u0000directory.dn\u0000' + dnOf('p2'),
                'default\u0000directory.username\u0000p2'], true);
  let openGate = null;
  const pulling = new Promise(function (resolve) {
    openGate = resolve;
  });
  const slow = new DCC(Object.assign(DCC.defaultDeps(), {
    isActiveActive: function () { return false; },
    clusterMode: function () { return 'off'; },
    loadArbiter: function () { return gated; },
    loadPersistence: function () {
      return { clusterStore: function () { return {}; },
               flush: function () { return Promise.resolve({}); },
               syncNow: function () { return pulling; } };
    }
  }));
  const firstPull = slow.claim({ realm: 'default', dns: [dnOf('p1')],
                                 usernames: ['p1'], waitMs: 0 });
  await pause(20);
  const secondPull = slow.claim({ realm: 'default', dns: [dnOf('p2')],
                                  usernames: ['p2'], waitMs: 0 });
  await pause(20);
  openGate();
  const pulls = await Promise.all([firstPull, secondPull]);
  note(pulls[0].catchUp === true && pulls[1].catchUp === true,
       'D11. A HOLDER IS CAUGHT UP ONLY WHEN ITS PULL HAS FINISHED: a second ' +
       'create granted while the first one\'s pull is still running is told ' +
       'to pull too (the first version said otherwise: 23 duplicates of 24)',
       JSON.stringify(pulls.map(function (one) { return one.catchUp; })));

  // A worker that dies gives back what it held.
  const holding = await command(0, 'hold', ['zed']);
  const whileHeld = await tryNow('zed');
  workers[0].worker.terminate();
  const dropped = await workers[0].exited;
  const afterDeath = await tryNow('zed');
  note(holding === 'held' && whileHeld === 'STS-LDAP-0092' && dropped === 2 &&
       afterDeath === 'ok',
       'D6. A WORKER THAT DIES GIVES BACK WHAT IT HELD: refused while it ' +
       'lived (STS-LDAP-0092), free the moment it exited — not after the ' +
       'claim\'s two minutes', JSON.stringify({ holding: holding,
                                                whileHeld: whileHeld,
                                                dropped: dropped,
                                                afterDeath: afterDeath }));
  await workers[1].worker.terminate();
  await workers[1].exited;

  // The pool is wired to it: a worker's message reaches receive(), and its
  // reap gives its claims back.
  const pool = fs.readFileSync(path.join(ROOT, 'common/request_pool.js'),
                               'utf8').replace(/\s+/g, ' ');
  const reapAt = pool.indexOf('function reap(entry, code, reason) {');
  const reapBody = reapAt >= 0 ? pool.slice(reapAt, reapAt + 1500) : '';
  note(/if \(message && message\.createClaim\) \{ createArbiter\(\)\.receive\(entry, message\); return; \}/
         .test(pool) &&
       reapBody.indexOf('createArbiter().workerExited(entry);') >= 0,
       'D7. request_pool.js hands a worker\'s { createClaim } message to the ' +
       'arbiter, and reap() gives a dead worker\'s claims back');
  log.debug("Leaving frontChild().");
  return findings;
}

// A worker thread of D.
function workerMain() {
  log.debug("Entering workerMain().");
  const port = workerThreads.parentPort;
  const local = new Set();
  let pending = [];
  let syncs = 0;
  let storeCalls = 0;
  let nextAsk = 1;
  const asking = new Map();
  const ask = function (message) {
    return new Promise(function (resolve) {
      const id = nextAsk;
      nextAsk += 1;
      asking.set(id, resolve);
      port.postMessage(Object.assign({ id: id }, message));
    });
  };
  const counting = function () {
    storeCalls += 1;
    return Promise.reject(new Error('the store was asked'));
  };
  const fakePersistence = {
    clusterStore: function () {
      return { claimMany: counting, claimOnce: counting,
               releaseClaims: counting, releaseClaim: counting };
    },
    flush: function () {
      const writing = pending;
      pending = [];
      return ask({ store: 'write', names: writing }).then(function () {
        return { written: true };
      });
    },
    syncNow: function () {
      syncs += 1;
      return ask({ store: 'read' }).then(function (answer) {
        answer.names.forEach(function (name) {
          local.add(name);
        });
      });
    }
  };
  const DCC = require('../ldap/directory_create_claims').DirectoryCreateClaims;
  const claimer = new DCC(Object.assign(DCC.defaultDeps(), {
    isActiveActive: function () { return false; },
    clusterMode: function () { return 'off'; },
    loadPersistence: function () { return fakePersistence; }
  }));
  const run = function (names) {
    return Promise.all(names.map(async function (name) {
      const held = await claimer.claim({ realm: 'default',
                                         dns: [dnOf(name)],
                                         usernames: [name] });
      if (!held.ok) {
        return { name: name, outcome: 'refused:' + held.code };
      }
      if (local.has(name)) {
        await held.settle(false);
        return { name: name, outcome: 'exists' };
      }
      local.add(name);
      pending.push(name);
      await held.settle(true);
      return { name: name, outcome: 'created' };
    })).then(function (outcomes) {
      return { outcomes: outcomes, syncs: syncs, storeCalls: storeCalls };
    });
  };
  port.on('message', function (message) {
    if (message && message.storeAnswer) {
      const resolve = asking.get(message.id);
      asking.delete(message.id);
      if (resolve) {
        resolve(message);
      }
      return;
    }
    if (!message || !message.command) {
      return;
    }
    const reply = function (value) {
      port.postMessage({ done: true, id: message.id, value: value });
    };
    if (message.cmd === 'run') {
      run(message.args).then(reply);
      return;
    }
    const name = message.args[0];
    claimer.claim({ realm: 'default', dns: [dnOf(name)], usernames: [name],
                    waitMs: 0 }).then(function (held) {
      if (!held.ok) {
        reply('refused:' + held.code);
        return;
      }
      if (message.cmd === 'refuse') {
        held.settle(false).then(function () {
          reply('refused-and-released');
        });
        return;
      }
      // 'hold': never settled; the worker is about to be ended.
      reply('held');
    });
  });
  log.debug("Leaving workerMain().");
}

// ===========================================================================
// A: the driver's statements, in this process.
// ===========================================================================
function recordingDriver(statements, reply) {
  log.debug("Entering recordingDriver().");
  const postgres = require('../persistence/persistence_postgres');
  function answer(sql, params) {
    statements.push({ text: String(sql).replace(/\s+/g, ' '),
                      params: params });
    return reply(String(sql), params);
  }
  function FakeClient() {}
  FakeClient.prototype.query = answer;
  FakeClient.prototype.release = function () {};
  FakeClient.prototype.on = function () {};
  FakeClient.prototype.removeListener = function () {};
  FakeClient.prototype.connect = function () {
    return Promise.resolve();
  };
  FakeClient.prototype.end = function () {
    return Promise.resolve();
  };
  function FakePool() {}
  FakePool.prototype.on = function () {};
  FakePool.prototype.connect = function () {
    return Promise.resolve(new FakeClient());
  };
  FakePool.prototype.query = answer;
  FakePool.prototype.end = function () {
    return Promise.resolve();
  };
  const restore = storeDouble.install({ Pool: FakePool,
                                        Client: FakeClient });
  const quiet = { debug: function () {}, info: function () {},
                  warn: function () {}, error: function () {} };
  try {
    log.debug("Leaving recordingDriver().");
    return postgres.create({ url: 'postgres://sts_app@localhost:5432/sts',
                             log: quiet });
  } finally {
    restore();
  }
}

async function driverStatements(t) {
  log.debug("Entering driverStatements().");
  t.log.info('=== A. the driver: one statement to claim, one to release ===');
  const seen = [];
  let next = { rows: [{ n: 2, claimed_at: 7, refused: null, partial: 0 }],
               rowCount: 1 };
  const driver = recordingDriver(seen, function () {
    return typeof next === 'function' ? next() : Promise.resolve(next);
  });
  const rows = [{ scope: 'directory.dn', key: 'k1' },
                { scope: 'directory.username', key: 'k2' }];
  const won = await driver.claimMany(rows, 'default',
                                     { ttlMs: 120000, reservation: 'r1' });
  t.check(won.claimed === true && seen.length === 1 &&
          /^WITH wanted AS .*INSERT INTO sts_cluster_claims .*ORDER BY w\.scope, w\.key ON CONFLICT/
            .test(seen[0].text) &&
          JSON.stringify(seen[0].params[0]) ===
            '["directory.dn","directory.username"]' &&
          seen[0].params[6] === 2,
          'A1. two claims are ONE statement, its rows in (scope, key) order, ' +
          'and both taken is a grant', JSON.stringify(won));
  t.check(/quiet AS \(SELECT set_config\('synchronous_commit', 'off', true\) AS was\)/
            .test(seen[0].text) && / FROM counted, quiet$/.test(seen[0].text),
          'A1b. and it commits without waiting for the WAL flush: ' +
          'synchronous_commit off for its own transaction, in a CTE the ' +
          'statement reads (so it runs)');
  t.check(/CASE WHEN n > 0 AND n < \$7::int THEN \('sts_cluster_claims: a partial claim of ' \|\| n/
            .test(seen[0].text),
          'A2. a PARTIAL take is turned into an error inside the statement, ' +
          'from the count the CTE returned (so it aborts, and is not folded ' +
          'at plan time)');
  next = { rows: [{ n: 0, claimed_at: null, refused: 2, partial: 0 }],
           rowCount: 1 };
  const lost = await driver.claimMany(rows, 'default',
                                      { ttlMs: 120000, reservation: 'r2' });
  t.check(lost.claimed === false && lost.refused === 1,
          'A3. none taken is a refusal naming the row somebody holds',
          JSON.stringify(lost));
  next = function () {
    return Promise.reject(new Error('invalid input syntax for type ' +
      'integer: "sts_cluster_claims: a partial claim of 1 of 2 rows is ' +
      'rolled back; first refused row 2"'));
  };
  const partial = await driver.claimMany(rows, 'default',
                                         { ttlMs: 120000, reservation: 'r3' });
  t.check(partial.claimed === false && partial.partial === true &&
          partial.refused === 1,
          'A4. the aborted partial take is recognised as a refusal of the ' +
          'row it names, not a store failure', JSON.stringify(partial));
  next = function () {
    return Promise.reject(new Error('connection terminated'));
  };
  let threw = '';
  await driver.claimMany(rows, 'default', { ttlMs: 1, reservation: 'r4' })
    .catch(function (e) {
      threw = e.message;
    });
  t.check(threw === 'connection terminated',
          'A5. any other error is the store\'s, and is thrown', threw);
  seen.length = 0;
  next = { rows: [], rowCount: 2 };
  const released = await driver.releaseClaims([
    { scope: 'directory.dn', realm: 'default', key: 'k1', reservation: 'r1' },
    { scope: 'directory.username', realm: 'default', key: 'k2',
      reservation: 'r1' }]);
  t.check(released === 2 && seen.length === 1 &&
          /^WITH quiet AS \(SELECT set_config\('synchronous_commit', 'off', true\) AS was\) DELETE FROM sts_cluster_claims c USING unnest\(.*\), quiet WHERE/
            .test(seen[0].text) &&
          seen[0].params[3].join(',') === 'r1,r1',
          'A6. two releases are ONE statement, each pinned to its reservation, ' +
          'committed without waiting for the WAL flush',
          JSON.stringify(seen.map(function (s) { return s.text; })));
  seen.length = 0;
  next = { rows: [], rowCount: 1 };
  await driver.saveDirectory({
    upserts: [{ realm: 'default', key: dnOf('a6'),
                entry: { dn: dnOf('a6'), attributes: { uid: ['a6'] } },
                json: '{}' }],
    deletes: [], touched: ['default'], removedRealms: [], all: null,
    releaseClaims: [{ scope: 'directory.dn', realm: 'default', key: 'k1',
                      reservation: 'r1' }]
  });
  const texts = seen.map(function (s) {
    return s.text;
  });
  const begin = texts.indexOf('BEGIN');
  const commit = texts.lastIndexOf('COMMIT');
  const insert = texts.findIndex(function (text) {
    return /^INSERT INTO sts_ldap_entries/.test(text);
  });
  const release = texts.findIndex(function (text) {
    return /^DELETE FROM sts_cluster_claims c USING unnest/.test(text);
  });
  t.check(begin >= 0 && insert > begin && release > insert &&
          commit > release && texts.every(function (text) {
            return text.indexOf('synchronous_commit') < 0;
          }),
          'A7. saveDirectory() gives a create\'s claims back BETWEEN the ' +
          'entry\'s INSERT and the COMMIT of the same transaction — which ' +
          'stays synchronous: nothing in it turns synchronous_commit off',
          JSON.stringify({ begin: begin, insert: insert, release: release,
                           commit: commit }));
  log.debug("Leaving driverStatements().");
}

// ===========================================================================
// THE PARENT.
// ===========================================================================
function runChild(role) {
  log.debug("Entering runChild(). role=" + role);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-dcc-'));
  const env = Object.assign({}, process.env, { LOG_LEVEL: 'fatal',
                                               STS_LOG_LEVEL: 'fatal' });
  env[ROLE_VAR] = role;
  delete env.CONFIG_FILE;
  if (role === 'persist') {
    env.STS_PERSISTENCE_MODE = 'postgres';
    env.STS_PERSISTENCE_COORDINATE = 'true';
  }
  const done = childProcess.spawnSync(process.execPath, [__filename],
    { cwd: ROOT, env: env, encoding: 'utf8', timeout: 120000,
      maxBuffer: 1 << 26 });
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch (e) {
    log.debug("Caught in runChild(): " + ((e && e.message) || e));
  }
  const line = String(done.stdout || '').split('\n').filter(function (one) {
    return one.indexOf('RESULT ') === 0;
  })[0];
  log.debug("Leaving runChild().");
  if (!line) {
    return { error: 'the ' + role + ' child printed no result (status ' +
             done.status + '): ' + String(done.stderr || '').slice(-3000) };
  }
  return JSON.parse(line.slice('RESULT '.length));
}

function report(t, got) {
  log.debug("Entering report().");
  if (got.error) {
    t.bad('the child could not run', got.error);
    log.debug("Leaving report(). It could not run.");
    return;
  }
  got.findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving report().");
}

async function run(t) {
  log.debug("Entering run().");
  await driverStatements(t);

  t.log.info('=== B. through persistence.js, active-active ===');
  report(t, runChild('persist'));

  t.log.info('=== C. two node processes on one store, active-active ===');
  const two = await runTwoNodes();
  if (two.error) {
    t.bad('the two nodes could not run', two.error);
  } else {
    const byName = {};
    two.results.forEach(function (result) {
      result.outcomes.forEach(function (one) {
        (byName[one.name] = byName[one.name] || []).push(one.outcome);
      });
    });
    const wrong = Object.keys(byName).filter(function (name) {
      return byName[name].slice(0).sort().join(',') !== 'created,exists';
    });
    t.check(wrong.length === 0 && Object.keys(byName).length === NAMES &&
            two.committed === NAMES && two.duplicates === 0 &&
            two.claimsLeft === 0,
            'C1. TWO NODES, ONE STORE, THE SAME ' + NAMES + ' NAMES AT ONCE: ' +
            'exactly one created per name and the other the directory\'s own ' +
            '"exists"; nothing left claimed',
            JSON.stringify({ wrong: wrong.slice(0, 5).map(function (name) {
              return name + '=' + byName[name].join('/');
            }), committed: two.committed, duplicates: two.duplicates,
            left: two.claimsLeft }));
    t.check(two.claimCalls >= 2 * NAMES,
            'C2. and every one of them asked the store (' + two.claimCalls +
            ' claim statements for ' + 2 * NAMES + ' creates and their ' +
            'retries)', String(two.claimCalls));
  }

  t.log.info('=== D. one node: the front process arbitrates its workers ===');
  report(t, runChild('front'));
  log.debug("Leaving run().");
}

module.exports = {
  name: 'directory_create_cluster_claims',
  describe: 'a directory create\'s claims (#628): one statement and a ' +
            'release inside the flush on a shared store, and the front ' +
            'process arbitrating in memory on one node',
  run: run
};

// ---------------------------------------------------------------------------
// THE CHILDREN AND THE WORKERS.
// ---------------------------------------------------------------------------
function childEntry() {
  log.debug("Entering childEntry().");
  const role = process.env[ROLE_VAR];
  const body = role === 'persist' ? persistChild
    : role === 'front' ? frontChild : nodeChild;
  body().then(function (result) {
    if (role === 'node') {
      process.send({ result: result });
      return;
    }
    process.stdout.write('RESULT ' + JSON.stringify({ findings: result }) +
                         '\n');
    process.exit(0);
  }, function (e) {
    log.debug("Caught in childEntry(): " + ((e && e.message) || e));
    if (role === 'node') {
      process.exit(3);
    }
    process.stdout.write('RESULT ' + JSON.stringify({
      error: (e && e.stack) || String(e) }) + '\n');
    process.exit(0);
  });
  log.debug("Leaving childEntry().");
}

if (!workerThreads.isMainThread && workerThreads.workerData &&
    workerThreads.workerData.role === 'worker') {
  workerMain();
} else if (require.main === module && process.env[ROLE_VAR]) {
  childEntry();
}
