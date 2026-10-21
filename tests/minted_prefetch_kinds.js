// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: minted_prefetch_kinds.js
//
// ===========================================================================
// A PAGE OF CHANGES OF BOTH MINTED KINDS IS READ IN ITS BATCHES, NOT ROW BY
// ROW (2026-10-21).
//
// Replication prepares every kind of a page before it applies any, and
// `minted` and `minted-own` each prepare through `persistence_minted.js`'s
// `prefetch()` — which began by dropping what the kind before it had read.
// Every `minted` row of a page was then read alone: on 8081 the front
// process alone asked 750 single-row reads a second.
//
//   K1. two kinds' prefetches of one page leave both kinds' rows in the
//       page's working set, each asked once, in its batch;
//   K2. a row asked for and absent is held as absent (null), not unknown;
//   K3. `endPrefetch()` drops the working set;
//   K4. a change's SEALED name is opened once for the page — by prefetch()
//       — and not again by applyChange(); endPrefetch() forgets it.
//
// In a child process: it installs a stand-in driver.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'minted_prefetch_kinds',
  level: process.env.LOG_LEVEL || 'info' });

// Runs in the child. Stringified, so it may use nothing from this file's scope.
function child() {
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };
  const OUT = process.env.MPK_OUT;
  const ROOT = process.env.MPK_ROOT;
  (async function () {
    const minted = require(ROOT + '/persistence/persistence_minted');
    const asked = [];
    const driver = {
      loadMinted: function () {
        return Promise.resolve([]);
      },
      saveMinted: function () {
        return Promise.resolve({});
      },
      readMinted: function () {
        return Promise.resolve(null);
      },
      readMintedMany: function (refs) {
        asked.push(refs.map(function (ref) {
          return ref.handle + '/' + ref.key;
        }));
        return Promise.resolve(refs.filter(function (ref) {
          return ref.key !== 'absent';
        }).map(function (ref) {
          return { handle: ref.handle, realm: ref.realm, key: ref.key,
                   body: 'body-of-' + ref.key, writtenAt: 1 };
        }));
      }
    };
    minted.setDriver(driver, 'postgres');
    const b64 = function (text) {
      return Buffer.from(text, 'utf8').toString('base64url');
    };
    const change = function (handle, name) {
      return { kind: 'x', realm: 'default', key: b64(handle) + '.' + b64(name) };
    };
    await minted.prefetch([change('authn.sessions', 's1'),
                           change('authn.sessions', 'absent')]);
    await minted.prefetch([change('oauth2.authzCodes', 'c1')]);
    const s1 = minted.prefetchedRow('authn.sessions', 'default', 's1');
    const c1 = minted.prefetchedRow('oauth2.authzCodes', 'default', 'c1');
    note(s1 && s1.body === 'body-of-s1' && c1 && c1.body === 'body-of-c1' &&
         asked.length === 2,
         'K1. two kinds\' prefetches of one page leave both kinds\' rows, ' +
         'each read in its batch', JSON.stringify({ asked: asked,
           s1: !!s1, c1: !!c1 }));
    note(minted.prefetchedRow('authn.sessions', 'default', 'absent') === null,
         'K2. a row asked for and absent is held as absent');
    minted.endPrefetch();
    note(minted.prefetchedRow('authn.sessions', 'default', 's1') === undefined,
         'K3. endPrefetch() drops the working set');

    const keystore = require(ROOT + '/common/keystore');
    const realOpen = keystore.open;
    const opened = [];
    keystore.open = function (text, label) {
      if (label !== 'minted-rows') {
        opened.push(text);
        return 'n1';
      }
      return null;
    };
    try {
      const sealed = { kind: 'x', realm: 'default',
                       key: b64('oauth2.authzCodes') + '.v1$sealed-n1' };
      await minted.prefetch([sealed]);
      await minted.applyChange(sealed);
      const once = opened.length;
      minted.endPrefetch();
      await minted.prefetch([sealed]);
      note(once === 1 && opened.length === 2,
           'K4. a sealed change name is opened once per page, and again ' +
           'after endPrefetch()', JSON.stringify({ once: once,
                                                    total: opened.length }));
    } finally {
      keystore.open = realOpen;
      minted.endPrefetch();
    }
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
  const out = path.join(os.tmpdir(), 'sts-mpk-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|CONFIG_FILE$)/.test(key)) {
      env[key] = process.env[key];
    }
  });
  Object.assign(env, { MPK_OUT: out, MPK_ROOT: root, LOG_LEVEL: 'fatal',
                       STS_LOG_LEVEL: 'fatal' });
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
  name: 'minted_prefetch_kinds',
  describe: 'a page of changes of both minted kinds is read in its batches, ' +
            'not row by row',
  run: run
};
