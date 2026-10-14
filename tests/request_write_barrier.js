// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: request_write_barrier.js
//
// ===========================================================================
// A DISPATCHED LDAP WRITE SKIPS THE READ BARRIER'S PULL WHERE THE PULL COULD
// NOT CHANGE ITS ANSWER (#626), COUNTED.
//
// `common/request_pool.js`'s runOperation() sent every LDAP operation through
// the read barrier: the ticket wait and, when the worker was behind the
// generation, a sync round — `persistence.syncNow()`, a change-log pull — in
// that worker before its handler ran. Under a bulk add from several
// connections every add found another worker ahead and paid a pull. Since
// #626 a write (add, modify, delete, modifyDN) sent to a worker that is
// behind only on WINDOWED directory rows is sent without the pull, carrying
// the keys other processes wrote; the worker applies them first.
//
// Two halves, each driven where it runs:
//
//   A. THE FRONT PROCESS (this process): real worker THREADS running a stub
//      that counts the sync rounds it is asked for and echoes the keys each
//      operation carried — `tests/request_worker_replacement.js`'s
//      arrangement. With another worker ahead, an add asks for no sync and
//      waits for no ticket, and is handed exactly the keys it lacks; a
//      search on the same worker still syncs; a SHARED write since the
//      worker last synced, too many keys, or a key log that no longer
//      reaches back sends the add through the barrier after all.
//   B. THE WORKER (a child that loads the directory as a windowed request
//      worker, `tests/directory_window_requests.js`'s arrangement): a held
//      copy older than the store — an absence remembered, an entry another
//      worker changed or deleted — decides the answer wrongly when nothing
//      is applied (the hazard, asserted as such), and the answer the barrier
//      would give once the keys are (`persistence.applyStaleKeys()`): a
//      parent another worker created is found, a duplicate by DN or by a
//      name another worker gave an existing entry is refused, a delete or
//      modify of an entry another worker deleted is `noSuchObject`, a
//      rename onto a DN another worker created is refused.
//
// The writer's half — what a commit was (`persistence_postgres.js`'s counts
// by kind, `committedChangesSince()`) — is asserted in B too, over the
// window's own rule for which keys are windowed.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'request_write_barrier',
  level: process.env.LOG_LEVEL || 'info' });

const CHILD_FLAG = 'STS_TEST_REQUEST_WRITE_BARRIER_CHILD';

// ---------------------------------------------------------------------------
// A. THE FRONT PROCESS.
// ---------------------------------------------------------------------------

// The stub worker thread: `begin` in, `ready` out; a `sync` is counted and
// answered; an `operation` is answered with this thread's id, the syncs it
// has been asked for so far, and the keys the operation carried.
const STUB = [
  "'use strict';",
  "const http = require('http');",
  "const wt = require('worker_threads');",
  "let syncs = 0;",
  "wt.parentPort.on('message', function (m) {",
  "  if (m && m.stop) { process.exit(0); }",
  "  if (m && m.sync) {",
  "    syncs += 1;",
  "    wt.parentPort.postMessage({ sync: true, id: m.id, ok: true,",
  "                                applied: 0, caughtUp: true });",
  "    return;",
  "  }",
  "  if (m && m.operation) {",
  "    // ANNOUNCED BEFORE THE ANSWER, as a worker on a postgres store",
  "    // announces an operation it answered after its commit (#620).",
  "    wt.parentPort.postMessage({ committed: { wrote: false, through: 0,",
  "                                             tickets: [m.ticket] } });",
  "    wt.parentPort.postMessage({ operation: true, id: m.id, ok: true,",
  "      ran: true, result: { worker: wt.threadId, syncs: syncs,",
  "                           staleKeys: m.staleKeys || null } });",
  "    return;",
  "  }",
  "  if (!m || !m.begin) { return; }",
  "  const server = http.createServer(function (req, res) {",
  "    res.end(String(wt.threadId));",
  "  });",
  "  server.listen(m.socket, function () {",
  "    wt.parentPort.postMessage({ ready: true });",
  "  });",
  "});",
  ""
].join('\n');

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) { setTimeout(resolve, ms); });
}

// Polls `test` until it answers true or `ms` passes.
async function waitFor(test, ms) {
  log.debug("Entering waitFor().");
  const until = Date.now() + ms;
  while (Date.now() < until) {
    if (test()) {
      log.debug("Leaving waitFor(). Met.");
      return true;
    }
    await sleep(25);
  }
  log.debug("Leaving waitFor(). Timed out.");
  return !!test();
}

// The variables this half sets, put back as they were.
const FRONT_ENV = {
  STS_WORKERS_REQUEST_COUNT: '2',
  STS_WORKERS_READ_YOUR_WRITE: 'true',
  STS_WORKERS_DISPATCH: 'ldap'
};

async function withStubPool(pool, stubPath, fn) {
  log.debug("Entering withStubPool().");
  const had = {};
  Object.keys(FRONT_ENV).forEach(function (name) {
    had[name] = process.env[name];
    process.env[name] = FRONT_ENV[name];
  });
  pool.reset();
  pool.useWorkerModule(stubPath);
  try {
    await fn();
  } finally {
    await pool.stop(3000);
    pool.reset();
    Object.keys(had).forEach(function (name) {
      if (had[name] === undefined) {
        delete process.env[name];
      } else {
        process.env[name] = had[name];
      }
    });
  }
  log.debug("Leaving withStubPool().");
}

// A key of the default realm's `ou=users`, as an announcement names it.
function person(uid) {
  log.debug("Entering person().");
  log.debug("Leaving person().");
  return { realm: 'default',
           key: 'uid=' + uid + ',ou=users,dc=example,dc=com' };
}

function keyNames(keys) {
  log.debug("Entering keyNames().");
  log.debug("Leaving keyNames().");
  return (keys || []).map(function (one) {
    return one.key.split(',')[0].slice(4);
  }).sort().join(',');
}

async function frontProcess(t, stubPath) {
  log.debug("Entering frontProcess().");
  const pool = require('../common/request_pool');
  t.log.info('=== A. the front process: which writes skip the pull ===');
  await withStubPool(pool, stubPath, async function () {
    pool.fork(pool.PROTOCOL_POOL, 0);
    pool.fork(pool.PROTOCOL_POOL, 1);
    const up = await waitFor(function () {
      return pool.workerTable().filter(function (one) {
        return one.ready;
      }).length === 2;
    }, 10000);
    t.check(up, 'A0. two stub workers come up');
    if (!up) {
      log.debug("Leaving frontProcess(). No workers.");
      return;
    }
    const run = function (kind, affinity) {
      return pool.runOperation(kind, { dn: 'x' }, { affinity: affinity })
        .then(function (answer) {
          return answer && answer.result;
        });
    };
    // Two connections, one on each worker: the first is bound by load,
    // the next connections until one lands on the other worker.
    const first = await run('ldap.search', 'conn-a');
    let other = null;
    let otherName = '';
    for (let i = 0; i < 20 && !other; i++) {
      const answer = await run('ldap.search', 'conn-b' + i);
      if (answer && answer.worker !== first.worker) {
        other = answer;
        otherName = 'conn-b' + i;
      }
    }
    t.check(!!(first && other), 'A0. one connection on each worker',
            JSON.stringify({ first: first, other: other }));
    if (!first || !other) {
      log.debug("Leaving frontProcess(). One worker only.");
      return;
    }
    const entries = pool.workerTable();
    const a = entries.filter(function (one) {
      return one.pid === first.worker;
    })[0];
    const b = entries.filter(function (one) {
      return one.pid === other.worker;
    })[0];
    const announce = function (entry, keys) {
      pool.receiveCommitted(entry, { wrote: true, tickets: [],
                                     windowedKeys: keys });
    };
    // Both current, so that what follows starts from nothing.
    const settled = await run('ldap.search', 'conn-a');
    await run('ldap.search', otherName);

    // A1. ANOTHER WORKER AHEAD, ON WINDOWED ROWS ONLY: no sync, the keys.
    announce(b, [person('x1')]);
    let before = pool.stats();
    let added = await run('ldap.add', 'conn-a');
    let after = pool.stats();
    t.check(added.syncs === settled.syncs &&
            after.syncRounds === before.syncRounds &&
            after.writes.keyed === before.writes.keyed + 1 &&
            after.writes.synced === before.writes.synced &&
            after.tickets.waited === before.tickets.waited,
            'A1. WITH ANOTHER WORKER AHEAD, AN ADD ASKS FOR NO SYNC: no ' +
            'sync round started, none reached the worker, no reader held',
            JSON.stringify({ before: before.writes, after: after.writes,
                             rounds: [before.syncRounds, after.syncRounds],
                             workerSyncs: added.syncs }));
    t.equal(keyNames(added.staleKeys), 'x1',
            'A2. and it is handed exactly the key the other worker wrote');
    const syncsBeforeSearch = added.syncs;

    // A3. A SEARCH ON THE SAME WORKER STILL SYNCS: reads keep the barrier.
    before = pool.stats();
    const searched = await run('ldap.search', 'conn-a');
    after = pool.stats();
    t.check(searched.syncs === syncsBeforeSearch + 1 &&
            after.syncRounds === before.syncRounds + 1 &&
            !searched.staleKeys,
            'A3. A SEARCH on that worker still asks it to sync, and carries ' +
            'no keys', JSON.stringify({ searched: searched,
              rounds: [before.syncRounds, after.syncRounds] }));
    for (const kind of ['ldap.compare', 'ldap.bind']) {
      announce(b, [person('r-' + kind)]);
      const read = await run(kind, 'conn-a');
      t.check(read.syncs === searched.syncs +
              (kind === 'ldap.compare' ? 1 : 2) && !read.staleKeys,
              'A4. and so does ' + kind, JSON.stringify(read));
    }

    // A5. ONLY WHAT IS NEW: two adds in a row are each handed the keys
    // written since the one before, not again.
    announce(b, [person('y1'), person('y2')]);
    added = await run('ldap.add', 'conn-a');
    t.equal(keyNames(added.staleKeys), 'y1,y2',
            'A5. an add is handed the keys written since it last synced');
    announce(b, [person('z1')]);
    added = await run('ldap.add', 'conn-a');
    t.equal(keyNames(added.staleKeys), 'z1',
            'A6. and the next add only those written since the last add');

    // A7. ITS OWN WRITES ARE NOT HANDED BACK; this process's are.
    // This process's committed count is whatever the run has left it at
    // (the store is not open here, so runOperation() samples 0); a count
    // far above any it has seen is a write.
    const local = Date.now();
    announce(a, [person('own1')]);
    announce(b, [person('theirs1')]);
    pool.noteLocalWrites(local, { windowedKeys: [person('front1')] });
    before = pool.stats();
    added = await run('ldap.add', 'conn-a');
    after = pool.stats();
    t.equal(keyNames(added.staleKeys), 'front1,theirs1',
            'A7. a worker is not handed the keys it wrote itself, and is ' +
            'handed those this process wrote');
    t.check(after.syncRounds === before.syncRounds,
            'A8. and a write this process made of a windowed key is not ' +
            'a reason to pull', JSON.stringify(after.writes));

    // A9. EVERY WRITE KIND THAT MAY SKIP IT DOES.
    for (const kind of ['ldap.modify', 'ldap.del', 'ldap.modifyDN']) {
      announce(b, [person('k-' + kind)]);
      before = pool.stats();
      const wrote = await run(kind, 'conn-a');
      after = pool.stats();
      t.check(after.syncRounds === before.syncRounds &&
              keyNames(wrote.staleKeys) === 'k-' + kind,
              'A9. ' + kind + ' is sent without the pull, with the key',
              JSON.stringify({ wrote: wrote,
                               rounds: [before.syncRounds,
                                        after.syncRounds] }));
    }

    // A10. A SHARED WRITE since the worker last synced: the barrier.
    announce(b, undefined);
    before = pool.stats();
    added = await run('ldap.add', 'conn-a');
    after = pool.stats();
    t.check(after.syncRounds === before.syncRounds + 1 &&
            after.writes.synced === before.writes.synced + 1 &&
            !added.staleKeys,
            'A10. A SHARED WRITE (anything but windowed directory rows) ' +
            'sends the next add through the barrier', JSON.stringify({
              added: added, writes: after.writes }));
    pool.noteLocalWrites(local + 1);
    before = pool.stats();
    added = await run('ldap.add', 'conn-a');
    after = pool.stats();
    t.check(after.syncRounds === before.syncRounds + 1,
            'A11. and so does a write of this process\'s that it cannot ' +
            'classify', JSON.stringify(after.writes));

    // A12. TOO MANY KEYS: the pull is the cheaper catch-up.
    const many = [];
    for (let i = 0; i < 600; i++) {
      many.push(person('many' + i));
    }
    announce(b, many);
    before = pool.stats();
    added = await run('ldap.add', 'conn-a');
    after = pool.stats();
    t.check(after.syncRounds === before.syncRounds + 1 && !added.staleKeys,
            'A12. more keys than OPERATION_KEYS_LIMIT: the barrier',
            JSON.stringify(after.writes));

    // A13. A KEY LOG THAT NO LONGER REACHES BACK: the barrier. Worker b
    // writes past the bound while the other is behind; its oldest records
    // go and the floor passes the other worker's position.
    for (let round = 0; round < 9; round++) {
      const batch = [];
      for (let i = 0; i < 500; i++) {
        batch.push(person('floor' + round + '-' + i));
      }
      announce(b, batch);
    }
    const floorStats = pool.stats();
    before = floorStats;
    added = await run('ldap.add', 'conn-a');
    after = pool.stats();
    t.check(floorStats.writes.keyLog.keys <= 4096 &&
            after.syncRounds === before.syncRounds + 1 && !added.staleKeys,
            'A13. a worker behind the key log\'s floor goes through the ' +
            'barrier, and the log is bounded', JSON.stringify(
              floorStats.writes));

    // A14. CURRENT: nothing to catch up on, nothing sent, nothing asked.
    before = pool.stats();
    added = await run('ldap.add', 'conn-a');
    after = pool.stats();
    t.check(after.syncRounds === before.syncRounds && !added.staleKeys &&
            after.writes.current === before.writes.current + 1,
            'A14. a worker that is current is sent the add as it is',
            JSON.stringify(after.writes));
    t.log.info('A. writes sent: ' + JSON.stringify(after.writes) +
               ', sync rounds ' + after.syncRounds);
  });
  log.debug("Leaving frontProcess().");
}

// ---------------------------------------------------------------------------
// B. THE WORKER, AS A WINDOWED REQUEST WORKER.
// ---------------------------------------------------------------------------

async function windowedWorker(t) {
  log.debug("Entering windowedWorker().");
  const shared = require('./directory_window');
  const persistence = require('../persistence/persistence');
  const ldap = require('../ldap/ldap_server');
  const w = ldap.directoryWindow;
  t.check(!!w, 'B0. the directory is a window onto the store');
  if (!w) {
    log.debug("Leaving windowedWorker(). No window.");
    return;
  }
  const users = ldap.usersDn().toLowerCase();
  const rows = new Map();
  w.residentRows('default').forEach(function (one) {
    rows.set('default\n' + one.key, { realm: 'default', dn_key: one.key,
      dn: one.entry.dn, attrs: one.entry.attributes,
      origin: one.entry.origin || null, created_at: '1', modified_at: '1' });
  });
  const keyOf = function (uid) {
    return ('uid=' + uid + ',' + users).toLowerCase();
  };
  const put = function (uid, extra) {
    const dn = 'uid=' + uid + ',' + users;
    rows.set('default\n' + dn.toLowerCase(), shared.row('default', dn,
      Object.assign({ uid: [uid], objectclass: ['inetOrgPerson'],
                      cn: [uid], sn: ['Person'] }, extra || {})));
  };
  for (let i = 0; i < 50; i++) {
    put('p' + String(i).padStart(6, '0'));
  }
  const bridge = shared.fakeBridge(rows);
  bridge.queryAsync = function (name, args) {
    return Promise.resolve(bridge.query(name, args));
  };
  w.attach(bridge);
  // The store, as `persistence.applyStaleKeys()` reads it: one byKeys.
  let reads = 0;
  const reader = function (realmId, keys) {
    reads += 1;
    return Promise.resolve(bridge.query('byKeys', [realmId, keys]));
  };
  // A held copy, put in the window as a read would put it — and NOT handed
  // out, which a real worker's copy is not once its flush has run.
  const hold = function (key) {
    return w.warmAsync('default', [key]);
  };
  const apply = function (keys) {
    return persistence.applyStaleKeys(keys.map(function (key) {
      return { realm: 'default', key: key };
    }), reader);
  };
  const op = function (kind, shape) {
    return Promise.resolve(ldap.performOperation(kind, Object.assign({
      boundDn: '', channel: 'ldap', remoteAddress: '' }, shape)));
  };
  const addShape = function (dn, uid) {
    return { dn: dn, attributes: [
      { type: 'objectClass', values: ['inetOrgPerson'] },
      { type: 'uid', values: [uid] }, { type: 'cn', values: [uid] },
      { type: 'sn', values: ['Added'] }] };
  };

  // B1. A PARENT ANOTHER WORKER CREATED, which this one remembered absent.
  // The hazard first, on keys of its own, then the same with the key
  // applied.
  for (const which of ['stale', 'fresh']) {
    const parent = 'parent-' + which;
    await hold(keyOf(parent));
    put(parent);
    if (which === 'fresh') {
      t.check(await apply([keyOf(parent)]) === true,
              'B1. the parent\'s key is applied');
    }
    const child = await op('add', addShape('cn=phone,' + 'uid=' + parent +
                                           ',' + users, 'phone-' + which));
    if (which === 'stale') {
      t.check(child.ok === false && child.errorName === 'NoSuchObjectError',
              'B2. THE HAZARD: with nothing applied, the remembered absence ' +
              'answers noSuchObject for a parent the store holds',
              JSON.stringify(child));
    } else {
      t.check(child.ok === true,
              'B3. A PARENT CREATED AND ANSWERED ON ANOTHER WORKER IS FOUND ' +
              'once its key is applied — no false noSuchObject',
              JSON.stringify(child));
    }
  }

  // B4. A DUPLICATE BY DN another worker created, remembered absent here.
  await hold(keyOf('dup-dn'));
  put('dup-dn');
  await apply([keyOf('dup-dn')]);
  const dupDn = await op('add', addShape('uid=dup-dn,' + users, 'dup-dn'));
  t.check(dupDn.ok === false && dupDn.errorName === 'EntryAlreadyExistsError',
          'B4. A DUPLICATE ACROSS WORKERS IS REFUSED: the DN another ' +
          'worker created', JSON.stringify(dupDn));

  // B5. A DUPLICATE BY NAME: another worker gave an existing entry, held
  // here, a `uid` this add proposes. The store's index finds the entry;
  // the stale copy held here does not carry the name.
  for (const which of ['stale', 'fresh']) {
    const holder = which === 'stale' ? 'p000010' : 'p000011';
    const alias = 'alias-' + which;
    await hold(keyOf(holder));
    put(holder, { uid: [holder, alias] });
    if (which === 'fresh') {
      await apply([keyOf(holder)]);
    }
    const named = await op('add', addShape('uid=' + alias + ',' + users,
                                           alias));
    if (which === 'stale') {
      t.check(named.ok === true,
              'B5. THE HAZARD: with nothing applied, the held copy without ' +
              'the name lets a duplicate through', JSON.stringify(named));
    } else {
      t.check(named.ok === false &&
              named.errorName === 'EntryAlreadyExistsError',
              'B6. A NAME ANOTHER WORKER GAVE AN EXISTING ENTRY refuses the ' +
              'add once that entry\'s key is applied', JSON.stringify(named));
    }
  }

  // B7. A DELETE and B8. A MODIFY of an entry another worker deleted.
  for (const kind of ['del', 'modify']) {
    for (const which of ['stale', 'fresh']) {
      const uid = 'gone-' + kind + '-' + which;
      put(uid);
      await hold(keyOf(uid));
      rows.delete('default\n' + keyOf(uid));
      if (which === 'fresh') {
        await apply([keyOf(uid)]);
      }
      const shape = { dn: 'uid=' + uid + ',' + users };
      if (kind === 'modify') {
        shape.changes = [{ operation: 'replace',
          modification: { type: 'description', values: ['changed'] } }];
      }
      const answer = await op(kind, shape);
      if (which === 'stale') {
        t.check(answer.ok === true,
                'B7. THE HAZARD (' + kind + '): with nothing applied, the ' +
                'held copy of an entry another worker deleted is ' +
                (kind === 'del' ? 'deleted' : 'modified'),
                JSON.stringify(answer));
      } else {
        t.check(answer.ok === false &&
                answer.errorName === 'NoSuchObjectError',
                'B8. A ' + kind.toUpperCase() + ' of an entry another ' +
                'worker deleted is noSuchObject once its key is applied, as ' +
                'the barrier answers', JSON.stringify(answer));
      }
    }
  }

  // B9. A RENAME onto a DN another worker created, remembered absent here.
  for (const which of ['stale', 'fresh']) {
    const from = which === 'stale' ? 'p000041' : 'p000043';
    const to = 'renamed-' + which;
    await hold(keyOf(to));
    put(to);
    if (which === 'fresh') {
      await apply([keyOf(to)]);
    }
    const renamed = await op('modifyDN', { dn: 'uid=' + from + ',' + users,
      newRdn: 'uid=' + to, newSuperior: '', deleteOldRdn: true });
    if (which === 'stale') {
      t.check(renamed.ok === true,
              'B9. THE HAZARD (modifyDN): with nothing applied, a rename ' +
              'onto a DN another worker created goes through',
              JSON.stringify(renamed));
    } else {
      t.check(renamed.ok === false &&
              renamed.errorName === 'EntryAlreadyExistsError',
              'B10. A RENAME onto a DN another worker created is refused ' +
              'once its key is applied', JSON.stringify(renamed));
    }
  }

  // B11. WHAT CANNOT STAND IN FOR A PULL SAYS SO, and reads nothing.
  reads = 0;
  const resident = await persistence.applyStaleKeys(
    [{ realm: 'default', key: users }], reader);
  t.check(resident === false && reads === 0,
          'B11. a key that is not windowed here is not applied: the caller ' +
          'pulls instead', JSON.stringify({ resident: resident,
                                            reads: reads }));
  const failing = await persistence.applyStaleKeys(
    [{ realm: 'default', key: keyOf('p000001') }], function () {
      return Promise.reject(new Error('the store is down'));
    });
  t.check(failing === false,
          'B12. and a store that cannot be read is a pull, not a refusal');
  reads = 0;
  const many = [];
  for (let i = 20; i < 30; i++) {
    many.push(keyOf('p' + String(i).padStart(6, '0')));
  }
  t.check(await apply(many) === true && reads === 1,
          'B13. ten keys of one realm are one read of the store',
          String(reads));

  log.debug("Leaving windowedWorker().");
}

// C. THE WRITER'S CLASSIFICATION, in the windowed child: the driver's
// `committedSince()` answer (as section D's driver gives it), read by the
// window's rule for which keys are windowed.
function writerHalf(t) {
  log.debug("Entering writerHalf().");
  const persistence = require('../persistence/persistence');
  const ldap = require('../ldap/ldap_server');
  const users = ldap.usersDn().toLowerCase();
  const person = 'uid=writer1,' + users;
  t.check(persistence.committedChangesSince(null).windowedKeys === null,
          'C1. with no store that keeps counts, every commit is shared');
  const counts = function (answer) {
    return { committedSince: function () {
      return Object.assign({ mark: { other: 9, directory: 9 } }, answer);
    } };
  };
  const mark = { other: 0, directory: 0 };
  const windowed = persistence.committedChangesSince(mark, counts({
    other: false, directory: [{ realm: 'default', key: person },
                              { realm: 'default', key: person }] }));
  t.check(Array.isArray(windowed.windowedKeys) &&
          windowed.windowedKeys.length === 1 &&
          windowed.windowedKeys[0].key === person &&
          windowed.mark.directory === 9,
          'C2. a commit of people only is its windowed keys, once each',
          JSON.stringify(windowed));
  const resident = persistence.committedChangesSince(mark, counts({
    other: false, directory: [{ realm: 'default', key: person },
                              { realm: 'default', key: users }] }));
  t.check(resident.windowedKeys === null,
          'C3. a resident directory row (a container, a group, a policy) ' +
          'makes it shared', JSON.stringify(resident));
  const other = persistence.committedChangesSince(mark, counts({
    other: true, directory: [] }));
  t.check(other.windowedKeys === null,
          'C4. so does a row of any other kind', JSON.stringify(other));
  const lost = persistence.committedChangesSince(mark, counts({
    other: false, directory: null }));
  t.check(lost.windowedKeys === null,
          'C5. and so do directory rows the driver no longer keeps',
          JSON.stringify(lost));
  log.debug("Leaving writerHalf().");
}

// ---------------------------------------------------------------------------
// D. THE DRIVER'S COUNTS BY KIND, over a pg double: moved at COMMIT, a
// directory row's realm and key kept, any other kind but `minted-own`
// counted as `other`, and a mark that has fallen off the kept rows answered
// as unknown.
// ---------------------------------------------------------------------------
function fakePg() {
  log.debug("Entering fakePg().");
  function FakeClient() {}
  FakeClient.prototype.query = function () {
    return Promise.resolve({ rows: [], rowCount: 0 });
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

function driverOverFakePg() {
  log.debug("Entering driverOverFakePg().");
  const pgPath = require.resolve('pg');
  const previous = require.cache[pgPath];
  require.cache[pgPath] = { id: pgPath, filename: pgPath, loaded: true,
                            exports: fakePg() };
  try {
    log.debug("Leaving driverOverFakePg().");
    return require('../persistence/persistence_postgres').create({
      url: 'postgres://sts_app@localhost:5432/sts',
      log: { debug: function () {}, info: function () {},
             warn: function () {}, error: function () {} }
    });
  } finally {
    if (previous) {
      require.cache[pgPath] = previous;
    } else {
      delete require.cache[pgPath];
    }
  }
}

async function driverCounts(t) {
  log.debug("Entering driverCounts().");
  t.log.info('=== D. the driver\'s committed rows, by kind ===');
  const driver = driverOverFakePg();
  const users = 'ou=users,dc=example,dc=com';
  const start = driver.committedMark();
  await driver.saveDirectory({ upserts: [], removedRealms: [], deletes: [
    { realm: 'default', key: 'uid=gone1,' + users },
    { realm: 'default', key: 'uid=gone2,' + users }] });
  const people = driver.committedSince(start);
  t.check(people.other === false && Array.isArray(people.directory) &&
          people.directory.map(function (one) {
            return one.key;
          }).join('|') === 'uid=gone1,' + users + '|uid=gone2,' + users,
          'D1. a directory commit is its rows\' realm and key, and nothing ' +
          'of another kind', JSON.stringify(people));
  await driver.saveRealms([{ id: 'acme', name: 'Acme', description: '',
                             createdAt: new Date().toISOString(),
                             overrides: {} }]);
  const realm = driver.committedSince(people.mark);
  t.check(realm.other === true && realm.directory.length === 0,
          'D2. a realm row is another kind', JSON.stringify(realm));
  const many = [];
  for (let i = 0; i < 4200; i++) {
    many.push({ realm: 'default', key: 'uid=bulk' + i + ',' + users });
  }
  await driver.saveDirectory({ upserts: [], removedRealms: [],
                              deletes: many });
  const recent = driver.committedSince(realm.mark);
  const old = driver.committedSince(start);
  t.check(recent.directory === null && old.directory === null &&
          driver.committedSince(driver.committedMark()).directory.length ===
            0,
          'D3. past the rows kept, a mark is answered unknown (null), and ' +
          'a current one with nothing', JSON.stringify({
            recent: recent.directory === null, old: old.directory === null }));
  log.debug("Leaving driverCounts().");
}

async function childMain() {
  log.debug('Entering childMain().');
  const seen = [];
  const t = {
    log: log,
    check: function (ok, what, detail) {
      seen.push({ ok: !!ok, what: what, detail: detail || '' });
      return !!ok;
    },
    equal: function (a, b, what, detail) {
      return t.check(a === b, what, 'expected ' + JSON.stringify(b) +
                     ', got ' + JSON.stringify(a) +
                     (detail ? ' — ' + detail : ''));
    }
  };
  let threw = '';
  try {
    await windowedWorker(t);
    writerHalf(t);
  } catch (e) {
    log.debug('Caught in childMain(): ' + ((e && e.message) || e));
    threw = (e && e.stack) || String(e);
  }
  fs.writeFileSync(process.env.PROBE_OUT,
                   JSON.stringify({ seen: seen, threw: threw }));
  log.debug('Leaving childMain().');
  process.exit(0);
}

function inChild(t, minimum) {
  log.debug('Entering inChild().');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-rwb-'));
  const outFile = path.join(dir, 'out.json');
  const env = Object.assign({}, process.env, { PROBE_OUT: outFile,
                                               LOG_LEVEL: 'fatal' });
  env[CHILD_FLAG] = '1';
  delete env.CONFIG_FILE;
  env.STS_REQUEST_WORKER = '1';
  env.LDAP_WORKER_DIRECTORY = 'postgres-lru';
  env.STS_PERSISTENCE_MODE = 'postgres';
  env.LDAP_WORKER_CACHE_ENTRIES = '100';
  const child = childProcess.spawnSync(process.execPath, [__filename],
    { cwd: path.join(__dirname, '..'), env: env, encoding: 'utf8',
      timeout: 180000 });
  let result = null;
  try {
    result = JSON.parse(fs.readFileSync(outFile, 'utf8'));
  } catch (e) {
    log.debug('Caught in inChild(): ' + ((e && e.message) || e));
    t.bad('the windowed child reported nothing', 'status ' + child.status +
          ': ' + String(child.stderr || '').slice(-2000));
    log.debug('Leaving inChild().');
    return;
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  result.seen.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  if (result.threw) {
    t.bad('the windowed child threw', result.threw);
  }
  t.check(result.seen.length >= minimum, 'every assertion of the windowed ' +
          'child ran', String(result.seen.length));
  log.debug('Leaving inChild().');
}

async function run(t) {
  log.debug('Entering run().');
  const stubPath = path.join(os.tmpdir(), 'sts-write-barrier-stub-' +
                             process.pid + '.js');
  fs.writeFileSync(stubPath, STUB);
  try {
    await frontProcess(t, stubPath);
  } finally {
    try {
      fs.unlinkSync(stubPath);
    } catch (e) {
      log.debug('Caught in run(): ' + ((e && e.message) || e));
    }
  }
  await driverCounts(t);
  t.log.info('=== B, C. the worker: the keys applied, the answers ===');
  inChild(t, 21);
  log.debug('Leaving run().');
}

if (require.main === module && process.env[CHILD_FLAG] === '1') {
  childMain();
}

module.exports = {
  name: 'request_write_barrier',
  describe: 'a dispatched LDAP write skips the read barrier\'s change-log ' +
            'pull when its worker is behind only on windowed directory ' +
            'rows, and is handed their keys instead (#626): counted in the ' +
            'front process with stub workers, and the answers a windowed ' +
            'worker gives once the keys are applied',
  run: run
};
