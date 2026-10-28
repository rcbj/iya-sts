// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: minted_unheld_dek.js
//
// ===========================================================================
// A MINTED CHANGE WHOSE NAME IS SEALED UNDER A DATA ENCRYPTION KEY THIS
// PROCESS HAS NOT READ YET IS APPLIED, NOT DROPPED (#1070).
//
// A request worker that defines a realm makes its data encryption keys and
// seeds its stores at once, every seed row's name sealed under the new key.
// The process pulling the change log met those names before it had read the
// key's row, `keystore.open()` answered null, and `applyChange()` reported
// each as "not the shape recordChanges() writes" (STS-STORE-0014, at error,
// ~1,400 lines a full run) and dropped it.
//
//   U1. a change under a key not held yet reads the data-key rows again,
//       opens, and lands in the store — no STS-STORE-0014;
//   U2. a page naming such a key reads the data-key rows ONCE, in
//       prefetch(), and its row is in the page's one batched read;
//   U3. a change under a key no row holds is skipped after FIVE fresh reads
//       (#1118), said ONCE at warn under STS-STORE-0089, and the next change
//       under it is skipped without another read;
//   U4. a name that is malformed — its key held, or no key at all — is still
//       STS-STORE-0014 at error;
//   U5. a key whose row a read does not bring yet — a read already in
//       flight, sent before the row committed — is read again, FRESH, and the
//       change applied, not skipped (#1118, run #7's STS-STORE-0089);
//   U6. a page whose one read in prefetch() misses such a key does not mark
//       it unheld: the change is applied once the key's row is read.
//
// In a child process: it installs a stand-in driver and stands in for the
// keystore's data-key questions, and reads the module's log on stdout.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'minted_unheld_dek',
  level: process.env.LOG_LEVEL || 'info' });

// Runs in the child. Stringified, so it may use nothing from this file's scope.
function child() {
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };
  const OUT = process.env.MUD_OUT;
  const ROOT = process.env.MUD_ROOT;
  const lines = [];
  const write = process.stdout.write.bind(process.stdout);
  process.stdout.write = function (chunk) {
    String(chunk).split('\n').forEach(function (one) {
      if (/STS-STORE-00(14|89)/.test(one)) {
        try {
          lines.push(JSON.parse(one));
        } catch (e) {
          lines.push({ level: -1, msg: one });
        }
      }
    });
    return write.apply(null, arguments);
  };
  const codes = function (code) {
    return lines.filter(function (line) {
      return String(line.msg || '').indexOf(code) >= 0;
    });
  };
  (async function () {
    const realms = require(ROOT + '/common/realms');
    const keystore = require(ROOT + '/common/keystore');
    const crypto = require(ROOT + '/common/crypto');
    const minted = require(ROOT + '/persistence/persistence_minted');
    const store = realms.map({ persist: 'test.mintedUnheldDek.map' });

    // THE DATA KEYS: a sealed name is `v2$<dek id>$<name>`. What `arriving`
    // holds is held once the data-key rows are read again — one key per case,
    // so one case's read does not bring the next case's key; `dekGone` never
    // is; `dekHeld` always is.
    const held = new Set(['dekHeld']);
    const arriving = new Set(['dekNew']);
    // A key whose row arrives only at the Nth read (#1118): the reads before
    // it are the stale ones.
    const late = new Map();
    let refreshes = 0;
    let freshAsked = 0;
    const dekOf = function (text) {
      const parts = String(text || '').split('$');
      return parts.length === 3 ? parts[1] : null;
    };
    crypto.dekIdOf = dekOf;
    keystore.namesUnheldDek = function (text) {
      const id = dekOf(text);
      return !!id && !held.has(id);
    };
    keystore.refreshDekRows = function (opts) {
      refreshes += 1;
      if (opts && opts.fresh) {
        freshAsked += 1;
      }
      arriving.forEach(function (id) {
        held.add(id);
      });
      late.forEach(function (at, id) {
        if (refreshes >= at) {
          held.add(id);
        }
      });
      return Promise.resolve(arriving.size);
    };
    keystore.sealed = function () {
      return true;
    };
    keystore.open = function (text, label) {
      if (label === 'minted-rows') {
        return JSON.stringify({ n: 7 });
      }
      const id = dekOf(text);
      if (!id || !held.has(id)) {
        return null;
      }
      // `dekHeld` names are the malformed ones: held, and still null.
      return id === 'dekHeld' ? null : text.split('$')[2];
    };

    const batched = [];
    const single = [];
    minted.reset();
    minted.setDriver({
      origin: function () { return 'unheld-dek-test'; },
      loadMinted: function () { return Promise.resolve([]); },
      saveMinted: function () { return Promise.resolve({}); },
      readMinted: function (handle, realm, key) {
        single.push(key);
        return Promise.resolve({ handle: handle, realm: realm, key: key,
                                 body: 'sealed-body', writtenAt: 1 });
      },
      readMintedMany: function (refs) {
        batched.push(refs.map(function (ref) {
          return ref.key;
        }));
        return Promise.resolve(refs.map(function (ref) {
          return { handle: ref.handle, realm: ref.realm, key: ref.key,
                   body: 'sealed-body', writtenAt: 1 };
        }));
      },
      purgeMinted: function () { return Promise.resolve(0); }
    }, 'postgres');
    const handle = Buffer.from('test.mintedUnheldDek.map', 'utf8')
      .toString('base64url');
    const change = function (dek, name) {
      return { kind: 'minted', realm: '', key: handle + '.v2$' + dek + '$' +
                                               name };
    };

    // U1.
    const applied = await minted.applyChange(change('dekNew', 'row-u1'));
    const u1 = store.get('row-u1');
    note(applied === true && refreshes === 1 && u1 && u1.n === 7 &&
         codes('STS-STORE-0014').length === 0,
         'U1. a change under a key not held yet reads the data-key rows ' +
         'again, opens and lands in the store, with no STS-STORE-0014',
         JSON.stringify({ applied: applied, refreshes: refreshes, u1: u1,
                          lines: lines }));

    // U2.
    refreshes = 0;
    arriving.clear();
    arriving.add('dekPage');
    single.length = 0;
    const paged = change('dekPage', 'row-u2');
    await minted.prefetch([paged, change('dekPage', 'row-u2b')]);
    const pagedApplied = await minted.applyChange(paged);
    minted.endPrefetch();
    const u2 = store.get('row-u2');
    note(refreshes === 1 && batched.length === 1 &&
         batched[0].length === 2 && single.length === 0 &&
         pagedApplied === true && u2 && u2.n === 7,
         'U2. a page naming a key not held yet reads the data-key rows once, ' +
         'in prefetch(), and its rows are in the one batched read',
         JSON.stringify({ refreshes: refreshes, batched: batched,
                          single: single, u2: u2 }));

    // U3.
    refreshes = 0;
    arriving.clear();
    const gone = await minted.applyChange(change('dekGone', 'row-u3'));
    const goneAgain = await minted.applyChange(change('dekGone', 'row-u3b'));
    const said = codes('STS-STORE-0089');
    note(gone === false && goneAgain === false && refreshes === 5 &&
         store.get('row-u3') === undefined,
         'U3. a change under a key no row holds is skipped after five ' +
         'fresh reads of the data-key rows, and the next is skipped ' +
         'without another',
         JSON.stringify({ gone: gone, goneAgain: goneAgain,
                          refreshes: refreshes }));
    note(said.length === 1 && said[0].level === 40 &&
         codes('STS-STORE-0014').length === 0,
         'U3. and it is said once, at warn, under STS-STORE-0089 — not ' +
         'STS-STORE-0014', JSON.stringify(lines));

    // U4.
    refreshes = 0;
    await minted.applyChange(change('dekHeld', 'row-u4'));
    await minted.applyChange({ kind: 'minted', realm: '',
                               key: handle + '.v2$not-an-envelope' });
    const malformed = codes('STS-STORE-0014');
    note(malformed.length === 2 && malformed.every(function (line) {
      return line.level === 50;
    }) && refreshes === 0,
         'U4. a malformed name is still STS-STORE-0014 at error, with no ' +
         'read of the data-key rows', JSON.stringify({ lines: malformed,
                                                       refreshes: refreshes }));

    // U5. The first read is stale; the key's row arrives at the second.
    refreshes = 0;
    freshAsked = 0;
    late.clear();
    late.set('dekLate', 2);
    const saidBefore = codes('STS-STORE-0089').length;
    const lateApplied = await minted.applyChange(change('dekLate', 'row-u5'));
    const u5 = store.get('row-u5');
    note(lateApplied === true && refreshes === 2 && freshAsked === 2 &&
         u5 && u5.n === 7 && codes('STS-STORE-0089').length === saidBefore,
         'U5. a key a stale read does not bring is read again, fresh, and ' +
         'the change is applied — not skipped under STS-STORE-0089',
         JSON.stringify({ lateApplied: lateApplied, refreshes: refreshes,
                          freshAsked: freshAsked, u5: u5 }));

    // U6. The page's one read misses the key; the applier waits for it.
    refreshes = 0;
    late.clear();
    late.set('dekPageLate', 2);
    const pageLate = change('dekPageLate', 'row-u6');
    await minted.prefetch([pageLate]);
    const pageLateApplied = await minted.applyChange(pageLate);
    minted.endPrefetch();
    const u6 = store.get('row-u6');
    note(pageLateApplied === true && refreshes === 2 && u6 && u6.n === 7 &&
         codes('STS-STORE-0089').length === saidBefore,
         'U6. a page whose read missed the key does not mark it unheld; ' +
         'the change is applied once the key is read',
         JSON.stringify({ pageLateApplied: pageLateApplied,
                          refreshes: refreshes, u6: u6 }));
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
  const out = path.join(os.tmpdir(), 'sts-mud-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|CONFIG_FILE$)/.test(key)) {
      env[key] = process.env[key];
    }
  });
  Object.assign(env, { MUD_OUT: out, MUD_ROOT: root, LOG_LEVEL: 'info',
                       STS_LOG_LEVEL: 'info' });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + child.toString() + ')()'], {
      cwd: root, env: env, encoding: 'utf8', timeout: 120000,
      maxBuffer: 64 * 1024 * 1024 });
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
  name: 'minted_unheld_dek',
  describe: 'a minted change sealed under a data encryption key not read ' +
            'yet is applied after a read of the data-key rows, not dropped',
  run: run
};
