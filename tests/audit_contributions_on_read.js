// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: audit_contributions_on_read.js
//
// ===========================================================================
// OTHER PROCESSES' AUDIT EVENTS ARE READ WHEN THE PAGE IS DRAWN (2026-10-21,
// #820).
//
// `audit.events` and `audit.nums` are `contributionsOnRead`: another
// process's change to its row is noted by the applier, not read and opened,
// and `audit.fresh()` — which the audit and error-code operations wait for —
// reads every noted row in one batch.
//
//   R1. three changes to another process's segment read nothing, and it is
//       not in the list yet;
//   R2. `fresh()` reads it once, in one batch, and the list and the
//       summary then carry it;
//   R3. a segment that is gone by the time it is read leaves the list;
//   R4. a `merge: 'own'` store without the flag is still read at the change;
//   R5. a read that fails leaves the rows noted, and the next refresh reads
//       them;
//   R6. past the bound the refresh runs on its own, once.
//
// In a child process: it arms the keystore and installs a stand-in driver.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'audit_contributions_on_read',
  level: process.env.LOG_LEVEL || 'info' });

// Runs in the child. Stringified, so it may use nothing from this file's scope.
function child() {
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };
  const OUT = process.env.ACR_OUT;
  const ROOT = process.env.ACR_ROOT;
  const DIR = process.env.ACR_DIR;
  (async function () {
    const kekFile = require('path').join(DIR, 'kek');
    require('fs').writeFileSync(kekFile,
      require('crypto').randomBytes(32).toString('base64'),
      { encoding: 'utf8', mode: 0o600 });
    process.env.STS_KEYS_SOURCE = 'persisted';
    process.env.STS_KEYS_KEK_PROVIDER = 'file';
    process.env.STS_KEYS_KEK_FILE = kekFile;
    const keystore = require(ROOT + '/common/keystore');
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
    const realms = require(ROOT + '/common/realms');
    const audit = require(ROOT + '/common/audit');
    const replication = require(ROOT + '/persistence/persistence_replication');
    const minted = require(ROOT + '/persistence/persistence_minted');
    realms.obj(function () {
      return { n: 0 };
    }, { persist: 'test.acr.counters', merge: 'own' });
    const rows = new Map();
    const asked = { one: 0, many: [] };
    let failMany = false;
    const driver = {
      loadMinted: function () {
        return Promise.resolve([]);
      },
      saveMinted: function () {
        return Promise.resolve({});
      },
      readMinted: function (handle, realm, key) {
        asked.one++;
        return Promise.resolve(rows.get(handle + '|' + realm + '|' + key) ||
                               null);
      },
      readMintedMany: function (refs) {
        asked.many.push(refs.length);
        if (failMany) {
          return Promise.reject(new Error('the store is away'));
        }
        return Promise.resolve(refs.map(function (ref) {
          return rows.get(ref.handle + '|' + ref.realm + '|' + ref.key);
        }).filter(Boolean));
      }
    };
    minted.setDriver(driver, 'postgres');
    const realmId = realms.currentId();
    const b64 = function (text) {
      return Buffer.from(String(text), 'utf8').toString('base64url');
    };
    const storedName = function (key, origin) {
      return b64(key) + '.' + b64(origin);
    };
    // What the stand-in store holds, filed by key column as the real one is.
    const put = function (handle, name, value) {
      const column = minted.keyColumnOf
        ? minted.keyColumnOf(handle, realmId, name) : null;
      const key = column || name;
      rows.set(handle + '|' + realmId + '|' + key,
               { handle: handle, realm: realmId, key: key,
                 body: keystore.seal(JSON.stringify(value), 'minted-rows'),
                 writtenAt: Date.now() });
      return key;
    };
    const drop = function (handle, key) {
      rows.delete(handle + '|' + realmId + '|' + key);
    };
    const change = function (handle, name) {
      return { kind: 'minted-own', realm: realmId,
               key: b64(handle) + '.' + b64(name) };
    };
    const event = function (seq) {
      return { seq: seq, at: Date.now(), category: 'admin',
               action: 'acr.test', outcome: 'success', summary: 'b ' + seq,
               origin: 'process-b', actor: '', target: '' };
    };
    const theirEvents = function () {
      return realms.run(realms.get(realmId), function () {
        return audit.list().filter(function (row) {
          return row.action === 'acr.test';
        }).length;
      });
    };

    const segment = storedName('0', 'process-b');
    const segColumn = put('audit.events', segment,
                          { start: 0, rows: [event(1), event(2)] });
    const numsName = storedName('', 'process-b');
    put('audit.nums', numsName, { seq: 2, recorded: 40 });
    for (let i = 0; i < 3; i++) {
      await minted.applyChange(change('audit.events', segment));
    }
    await minted.applyChange(change('audit.nums', numsName));
    note(asked.one === 0 && asked.many.length === 0 &&
         replication.staleContributionCount('audit.events') === 1 &&
         theirEvents() === 0,
         'R1. three changes to another process\'s segment read nothing, and ' +
         'it is not listed yet', JSON.stringify({ asked: asked,
           noted: replication.staleContributionCount('audit.events'),
           listed: theirEvents() }));

    await audit.fresh();
    const summary = realms.run(realms.get(realmId), function () {
      return audit.summary();
    });
    note(asked.one === 0 && asked.many.join(',') === '2' &&
         theirEvents() === 2 && summary.processes === 2 &&
         summary.recorded >= 40 &&
         replication.staleContributionCount('audit.events') === 0,
         'R2. fresh() reads the noted rows once, in one batch, and the list ' +
         'and the summary carry them', JSON.stringify({ asked: asked,
           listed: theirEvents(), processes: summary.processes,
           recorded: summary.recorded }));

    drop('audit.events', segColumn);
    await minted.applyChange(change('audit.events', segment));
    await audit.fresh();
    note(theirEvents() === 0,
         'R3. a segment gone by the time it is read leaves the list',
         String(theirEvents()));

    asked.one = 0;
    const counterName = storedName('', 'process-b');
    put('test.acr.counters', counterName, { n: 5 });
    await minted.applyChange(change('test.acr.counters', counterName));
    const counted = realms.run(realms.get(realmId), function () {
      return replication.remoteRows('test.acr.counters', undefined, '');
    });
    note(asked.one === 1 && counted.length === 1 && counted[0].n === 5,
         'R4. a merge: \'own\' store without the flag is still read at the ' +
         'change', JSON.stringify({ one: asked.one, counted: counted }));

    put('audit.events', storedName('1', 'process-b'),
        { start: 32, rows: [event(33)] });
    await minted.applyChange(change('audit.events',
                                    storedName('1', 'process-b')));
    failMany = true;
    await audit.fresh();
    const stillNoted = replication.staleContributionCount('audit.events');
    failMany = false;
    await audit.fresh();
    note(stillNoted === 1 && theirEvents() === 1 &&
         replication.staleContributionCount('audit.events') === 0,
         'R5. a failed read leaves the rows noted, and the next refresh ' +
         'reads them', JSON.stringify({ stillNoted: stillNoted,
           listed: theirEvents() }));

    asked.many.length = 0;
    for (let i = 0; i < 5001; i++) {
      replication.contributionStale('audit.events', realmId, 'k' + i,
                                    'process-c', storedName('k' + i,
                                                            'process-c'));
    }
    await new Promise(function (resolve) {
      setTimeout(resolve, 200);
    });
    note(replication.staleContributionCount('audit.events') === 0 &&
         asked.many.reduce(function (a, b) {
           return a + b;
         }, 0) === 5001,
         'R6. past the bound the refresh runs on its own, once',
         JSON.stringify({ noted: replication
           .staleContributionCount('audit.events'), many: asked.many }));
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
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-acr-'));
  const out = path.join(dir, 'findings.json');
  const env = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|CONFIG_FILE$)/.test(key)) {
      env[key] = process.env[key];
    }
  });
  Object.assign(env, { ACR_OUT: out, ACR_ROOT: root, ACR_DIR: dir,
                       LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal' });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + child.toString() + ')()'], {
      cwd: root, env: env, encoding: 'utf8', timeout: 120000 });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.rmSync(dir, { recursive: true, force: true });
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
  name: 'audit_contributions_on_read',
  describe: 'other processes\' audit events are noted at the change and read ' +
            'in one batch when the page is drawn (#820)',
  run: run
};
