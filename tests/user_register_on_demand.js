// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: user_register_on_demand.js
//
// ===========================================================================
// THE IDENTITY REGISTER READS A PERSON FROM THE STORE, NOT FROM A 2,000-RECORD
// WINDOW (#1001, 2026-10-27).
//
// rcbj: "It doesn't make any sense to have these stats based on an in-memory
// 2000 user limit. It has to be able to go back to the database and pull the
// original / permanent data." `admin_stats.users` is `onDemand` now: the cap
// bounds a cache, nothing is deleted on eviction, and a person not held is
// read back from the store — this process's own row by key, and every
// origin's rows through the index (`lookupEntries()`, #1001's addition to
// `realms.map()`). It is also the first store that is both `merge: 'own'`
// and on demand, so the reader had to learn that a row's stored name carries
// its origin.
//
// Two halves, in a child process (each installs a stand-in in a module the
// rest of the run shares):
//
//   A. The register over a stand-in READER (`realms.setOnDemandReader()`):
//      A1. a person held by nobody here is answered from the store, this
//          process's row and another origin's folded — 5 + 3 is 8;
//      A2. `knownUser()` knows them, and not a stranger;
//      A3. a sign-in continues this process's own row (6), so the figure the
//          portal and the console draw is 9; and for a person not held at
//          all the sign-in reads their row from the store first, so it
//          continues (2 to 3) rather than starting again at one;
//      A4. two thousand and more identities later the cache is bounded, and
//          the first person is read from the store again, not forgotten;
//      A5. the whole-register readers answer what is held, and say so.
//
//   B. The minted store's reader over a stand-in BRIDGE
//      (`minted.setDemandBridge()`), the real `onDemandRead()` and
//      `onDemandByIndex()`:
//      B1. a read of a bare key asks the store for `<key>.<origin>`, this
//          process's row of a per-origin store;
//      B2. an index answer is split per row into the person, the origin and
//          whether it is this process's.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'user_register_on_demand',
  level: process.env.LOG_LEVEL || 'info' });

// Runs in the child. Stringified, so it may use nothing from this file's scope.
function child() {
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };
  const OUT = process.env.ODS_OUT;
  const ROOT = process.env.ODS_ROOT;
  (async function () {
    const nodeFs = require('fs');
    const nodePath = require('path');
    const nodeOs = require('os');
    const nodeCrypto = require('crypto');
    const realms = require(ROOT + '/common/realms');
    const config = require(ROOT + '/common/config');
    const keystore = require(ROOT + '/common/keystore');
    const stats = require(ROOT + '/common/admin_stats');
    const minted = require(ROOT + '/persistence/persistence_minted');
    const HANDLE = 'admin_stats.users';
    const TAG = 'ondemand' + process.pid;
    const ALICE = TAG + '-alice';
    const STRANGER = TAG + '-stranger';

    // -----------------------------------------------------------------------
    // A. The register over a stand-in reader.
    // -----------------------------------------------------------------------
    const blank = function (key, n, at) {
      return { key: key, name: key, forms: {}, realms: {}, protocols: {},
               events: [], eventsForgotten: 0, authentications: n,
               firstAt: at, lastAt: at, isClient: false };
    };
    // What the store holds: this process's own rows by person, and other
    // origins' rows by person.
    const ownRows = new Map([[ALICE, blank(ALICE, 5, 1000)]]);
    const foreignRows = new Map([[ALICE, [{ origin: 'n:other:protocol-1',
                                            value: blank(ALICE, 3, 2000) }]]]);
    // A fresh copy per read, as a row opened from the store is.
    const copy = function (value) {
      return JSON.parse(JSON.stringify(value));
    };
    const asked = [];
    realms.setOnDemandReader({
      active: function (handle) {
        return handle === HANDLE;
      },
      read: function (handle, realmId, key) {
        asked.push('read:' + key);
        return ownRows.has(key)
          ? { present: true, value: copy(ownRows.get(key)) }
          : { present: false };
      },
      byIndex: function (handle, realmId, indexKey) {
        asked.push('index:' + indexKey);
        const out = [];
        if (ownRows.has(indexKey)) {
          out.push({ key: indexKey, origin: '', own: true,
                     value: copy(ownRows.get(indexKey)) });
        }
        (foreignRows.get(indexKey) || []).forEach(function (row) {
          out.push({ key: indexKey, origin: row.origin, own: false,
                     value: copy(row.value) });
        });
        return out;
      },
      journalled: function () {
        return false;
      }
    });

    note(stats.userRow && typeof stats.userDetail === 'function',
         'the register loaded');
    const detail = stats.userDetail(ALICE);
    note(detail && detail.user && detail.user.authentications === 8 &&
         asked.indexOf('index:' + ALICE) >= 0,
         'A1. a person held by nobody here is answered from the store: this ' +
         'process\'s row and another origin\'s, folded (5 + 3)',
         JSON.stringify({ authentications: detail && detail.user &&
                          detail.user.authentications, asked: asked }));
    const strangerDetail = stats.userDetail(STRANGER);
    note(stats.knownUser(ALICE) === true && stats.knownUser(STRANGER) === false
         && strangerDetail === null,
         'A2. knownUser() knows the person the store holds and not a ' +
         'stranger; a stranger has no row');

    asked.length = 0;
    stats.recordAuthentication({ presented: ALICE, protocol: 'test',
                                 method: 'password',
                                 sessionId: TAG + '-sid' });
    const partition = realms.handleFor(HANDLE)
      .partition(realms.currentId());
    const heldAlice = partition.get(ALICE);
    const after = stats.userDetail(ALICE);
    note(heldAlice && heldAlice.authentications === 6 && after && after.user &&
         after.user.authentications === 9,
         'A3. a sign-in continues this process\'s own row (5 to 6, held ' +
         'since the lookup above cached it) and the figure drawn is 9, ' +
         'not 1 + 3',
         JSON.stringify({ held: heldAlice && heldAlice.authentications,
                          authentications: after && after.user &&
                          after.user.authentications }));
    // And a person not held at all: the sign-in READS their own row back
    // from the store before counting.
    const CAROL = TAG + '-carol';
    ownRows.set(CAROL, blank(CAROL, 2, 500));
    asked.length = 0;
    stats.recordAuthentication({ presented: CAROL, protocol: 'test',
                                 method: 'password' });
    const heldCarol = partition.get(CAROL);
    const carol = stats.userDetail(CAROL);
    note(asked.indexOf('read:' + CAROL) >= 0 && heldCarol &&
         heldCarol.authentications === 3 && carol && carol.user &&
         carol.user.authentications === 3,
         'A3b. a sign-in by somebody not held reads their own row from the ' +
         'store first, so the count continues (2 to 3) rather than starting ' +
         'at one',
         JSON.stringify({ asked: asked, held: heldCarol &&
                          heldCarol.authentications }));

    const cap = stats.MAX_USERS;
    for (let i = 0; i < cap + 3; i++) {
      stats.recordAuthentication({ presented: TAG + '-many-' + i,
                                   protocol: 'test', method: 'password' });
    }
    asked.length = 0;
    const again = stats.userDetail(ALICE);
    const heldCount = realms.handleFor(HANDLE)
      .partition(realms.currentId()).size;
    note(heldCount <= cap && again && again.user &&
         again.user.authentications >= 8 &&
         asked.indexOf('index:' + ALICE) >= 0,
         'A4. past the cap the cache is bounded, nothing is forgotten: the ' +
         'first person is read from the store again',
         JSON.stringify({ held: heldCount, cap: cap,
                          authentications: again && again.user &&
                          again.user.authentications }));

    const rows = stats.userRows();
    const snap = stats.snapshot();
    note(Array.isArray(rows) && rows.length <= cap + 10 &&
         snap && snap.users && snap.users.heldOnly === true,
         'A5. the whole-register readers answer what is held and say ' +
         'heldOnly', JSON.stringify({ rows: rows.length,
                                      heldOnly: snap && snap.users &&
                                      snap.users.heldOnly }));

    // -----------------------------------------------------------------------
    // B. The minted store's reader over a stand-in bridge.
    // -----------------------------------------------------------------------
    const dir = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), 'urod-'));
    const kekFile = nodePath.join(dir, 'kek');
    nodeFs.writeFileSync(kekFile,
                         nodeCrypto.randomBytes(32).toString('base64'),
                         { encoding: 'utf8', mode: 0o600 });
    process.env.STS_KEYS_SOURCE = 'persisted';
    process.env.STS_KEYS_KEK_PROVIDER = 'file';
    process.env.STS_KEYS_KEK_FILE = kekFile;
    keystore.reset();
    keystore.setStore({
      loadKeys: function () {
        return Promise.resolve([]);
      },
      saveKeys: function () {
        return Promise.resolve();
      },
      deleteKeys: function () {
        return Promise.resolve();
      }
    });
    await keystore.start();
    config.setOverride('global.mode', 'product');
    config.setOverride('persistence.minted', true);
    minted.reset();
    const ORIGIN = 'process-a';
    minted.setDriver({
      origin: function () {
        return ORIGIN;
      },
      loadMinted: function () {
        return Promise.resolve([]);
      },
      saveMinted: function () {
        return Promise.resolve();
      },
      readMinted: function () {
        return Promise.resolve(null);
      },
      purgeMinted: function () {
        return Promise.resolve(0);
      },
      purgeExpiredMinted: function () {
        return Promise.resolve(0);
      }
    }, 'postgres');
    const b64 = function (text) {
      return Buffer.from(String(text), 'utf8').toString('base64url');
    };
    const BOB = TAG + '-bob';
    const REALM = 'default';
    const ownName = b64(BOB) + '.' + b64(ORIGIN);
    const foreignName = b64(BOB) + '.' + b64('n:other:protocol-1');
    const sealed = function (value) {
      return keystore.seal(JSON.stringify(value), 'minted-rows');
    };
    const queries = [];
    minted.setDemandBridge({
      query: function (name, args) {
        queries.push({ name: name, args: args });
        if (name === 'minted.read') {
          return args[2] === minted.keyColumnOf(HANDLE, REALM, ownName)
            ? { body: sealed(blank(BOB, 4, 3000)) } : null;
        }
        if (name === 'minted.byIndex') {
          return [{ key: ownName, keySealed: '',
                    body: sealed(blank(BOB, 4, 3000)) },
                  { key: foreignName, keySealed: '',
                    body: sealed(blank(BOB, 2, 4000)) }];
        }
        return null;
      }
    });
    const read = minted.onDemandRead(HANDLE, REALM, BOB);
    note(read && read.present === true && read.value &&
         read.value.authentications === 4 &&
         queries.length === 1 && queries[0].name === 'minted.read' &&
         queries[0].args[2] === minted.keyColumnOf(HANDLE, REALM, ownName),
         'B1. a read of a bare key asks the store for <key>.<origin>, this ' +
         'process\'s row of a per-origin store',
         JSON.stringify({ present: read && read.present,
                          queries: queries.length }));
    const indexed = minted.onDemandByIndex(HANDLE, REALM, BOB);
    const own = indexed.filter(function (r) {
      return r.own === true;
    });
    const other = indexed.filter(function (r) {
      return r.own === false;
    });
    note(indexed.length === 2 && own.length === 1 && other.length === 1 &&
         own[0].key === BOB && own[0].origin === ORIGIN &&
         own[0].value.authentications === 4 &&
         other[0].key === BOB && other[0].origin === 'n:other:protocol-1' &&
         other[0].value.authentications === 2,
         'B2. an index answer is split per row into the person, the origin ' +
         'and whether it is this process\'s',
         JSON.stringify(indexed.map(function (r) {
           return { key: r.key, origin: r.origin, own: r.own };
         })));
    nodeFs.rmSync(dir, { recursive: true, force: true });
  })().catch(function (e) {
    note(false, 'the child threw', (e && e.stack) || e);
  }).then(function () {
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function run(t) {
  log.debug("Entering run().");
  const root = path.join(__dirname, '..');
  const out = path.join(os.tmpdir(), 'sts-urod-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|CONFIG_FILE$)/.test(key)) {
      env[key] = process.env[key];
    }
  });
  Object.assign(env, { ODS_OUT: out, ODS_ROOT: root, LOG_LEVEL: 'fatal',
                       STS_LOG_LEVEL: 'fatal' });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + child.toString() + ')()'], {
      cwd: root, env: env, encoding: 'utf8', timeout: 180000 });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.rmSync(out, { force: true });
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (t.check(Array.isArray(findings),
              'the child process reported its findings',
              'status=' + result.status + ' ' +
              String(result.stderr || '').slice(-2000))) {
    findings.forEach(function (one) {
      t.check(one.ok, one.what, one.detail);
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'user_register_on_demand',
  describe: 'the identity register reads a person from the store, every ' +
            'origin\'s rows folded, and its cap bounds a cache (#1001)',
  run: run
};
