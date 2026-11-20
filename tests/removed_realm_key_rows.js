// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: removed_realm_key_rows.js
//
// ===========================================================================
// A REMOVED REALM'S LATE KEY ROW DOES NOT STOP A START (2026-11-18, GitHub
// Actions run #496, #1899).
//
// In the cluster mode a realm was removed at 17:51:23 while another process
// had a write of its key set in flight. The write landed after the purge,
// sealed under a data key the purge had destroyed, and from then on every
// start of every node refused — STS-KEYS-0029, "the key-encryption key is
// almost certainly not the one it was encrypted with" — so both of the
// mode's restarts left node A down. The two processes are played here by one
// keystore restarted over one store double, the way a restart reads the
// table another process wrote:
//
//   A. a realm's key rows are written, the realm is removed (its rows and
//      its data keys go), and then the other process's late copy of its
//      key-set row lands in the store;
//   B. a fresh start over that store SUCCEEDS: the row of a realm the store
//      no longer holds is set aside and deleted (STS-KEYS-0199);
//   C. the same row for a realm the store DOES hold still refuses the start
//      (STS-KEYS-0029): the protection against the wrong key-encryption key
//      is unchanged for a live realm;
//   D. a running process that removed the realm deletes the late row when
//      the change reaches it, rather than keeping it for a later start;
//   E. the internal scopes are not realms: a start beside a live realm and
//      a removed one deletes only the removed realm's row, and the
//      `*process` and `*service` rows are read — the process branch keeps
//      its Intermediate and Issuing CAs across the restart;
//   F. an arriving `*process` or `*service` row is adopted, never purged.
//
// In a CHILD PROCESS: it sets the keystore's process-wide state.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'removed_realm_key_rows',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function keyRowsChild() {
  const ROOT = process.env.RRK_ROOT;
  const OUT = process.env.RRK_OUT;
  const fs = require('fs');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  (async function () {
    const nodeCrypto = require('crypto');
    const kekFile = OUT + '.kek';
    fs.writeFileSync(kekFile, nodeCrypto.randomBytes(32).toString('base64'));
    process.env.STS_KEYS_SOURCE = 'persisted';
    process.env.STS_KEYS_KEK_PROVIDER = 'file';
    process.env.STS_SECRETS_ALLOW_LOCAL_SECRETS = 'true';
    process.env.STS_KEYS_KEK_FILE = kekFile;
    const realms = require(ROOT + '/common/realms');
    const keystore = require(ROOT + '/common/keystore');
    const helpers = require(ROOT + '/common/helpers');
    // The table, and the realm list the store holds (sts_realms).
    const held = new Set();
    const store = {
      rows: new Map(),
      loadKeys: function () {
        return Promise.resolve(Array.from(store.rows.entries())
          .map(function (e) {
            return { realm: e[0], material: e[1] };
          }));
      },
      saveKeys: function (realm, material) {
        store.rows.set(realm, material);
        return Promise.resolve();
      },
      loadKey: function (realm) {
        return Promise.resolve(store.rows.has(realm)
          ? store.rows.get(realm) : null);
      },
      deleteKeys: function (realm) {
        store.rows.delete(realm);
        return Promise.resolve();
      },
      storedRealmIds: function () {
        return Promise.resolve(Array.from(held));
      }
    };
    async function restart() {
      keystore.reset();
      helpers.resetStsKeys();
      keystore.setStore(store);
      return keystore.start();
    }
    try {
      keystore.setStore(store);
      await keystore.start();
      const ID = 'rrk-gone';
      realms.create({ id: ID, name: ID });
      held.add(ID);
      realms.run(realms.get(ID), function () {
        return helpers.stsKeysFor();
      });
      await keystore.settleAll();
      const late = store.rows.get(ID);
      note(!!late && Array.from(store.rows.keys()).some(function (k) {
        return /^dek:[^:]+:rrk-gone$/.test(k);
      }), '(the realm\'s key-set row and its data-key row are written)',
           Array.from(store.rows.keys()).join(','));
      realms.remove(ID);
      held.delete(ID);
      await new Promise(function (resolve) {
        setTimeout(resolve, 50);
      });
      store.rows.set(ID, late);
      note(!Array.from(store.rows.keys()).some(function (k) {
        return /^dek:[^:]+:rrk-gone$/.test(k);
      }), 'A. the removal deleted its data-key row, and the late key-set ' +
           'row is back in the store', Array.from(store.rows.keys()).join(','));

      let started = null;
      try {
        started = await restart();
      } catch (e) {
        started = { error: e.message };
      }
      note(started && !started.error && !store.rows.has(ID),
           'B. a fresh start over that store succeeds, and the removed ' +
           'realm\'s row is deleted', JSON.stringify(started).slice(0, 400));

      store.rows.set(ID, late);
      held.add(ID);
      let refused = '';
      try {
        await restart();
      } catch (e) {
        refused = e.message;
      }
      note(/STS-KEYS-0029/.test(refused) && store.rows.has(ID),
           'C. the same row for a realm the store still holds refuses the ' +
           'start, and is left alone', refused.slice(0, 200));
      store.rows.delete(ID);
      held.delete(ID);
      await restart();

      const LATE = 'rrk-late';
      realms.create({ id: LATE, name: LATE });
      held.add(LATE);
      realms.run(realms.get(LATE), function () {
        return helpers.stsKeysFor();
      });
      await keystore.settleAll();
      const lateRow = store.rows.get(LATE);
      realms.remove(LATE);
      held.delete(LATE);
      await new Promise(function (resolve) {
        setTimeout(resolve, 50);
      });
      store.rows.set(LATE, lateRow);
      const applied = await keystore.applyStoredChange(LATE);
      note(applied && applied.kind === 'purged' && !store.rows.has(LATE),
           'D. a process that removed the realm deletes its late row when ' +
           'the change arrives', JSON.stringify(applied));

      // E–F: THE INTERNAL SCOPES ARE NOT REALMS (2026-11-18, #1900's
      // regression). The process branch (`*process`) and the service Root
      // (`*service`) keep `pki:` and `dek:` rows no `sts_realms` row will
      // ever name; a start that called them orphans destroyed the process's
      // Intermediate and TLS Issuing CA on every restart of a product
      // instance, and each node of a cluster deleted the other's.
      const pki = require(ROOT + '/common/pki');
      const LIVE = 'rrk-live';
      realms.create({ id: LIVE, name: LIVE });
      held.add(LIVE);
      realms.run(realms.get(LIVE), function () {
        return helpers.stsKeysFor();
      });
      await pki.ensureScope(pki.PROCESS_SCOPE);
      await keystore.settleAll();
      const scopeRows = function () {
        return Array.from(store.rows.keys()).filter(function (k) {
          return k.indexOf('*') >= 0;
        }).sort();
      };
      const identity = function () {
        const row = pki.rawRowFor(pki.PROCESS_SCOPE);
        return row && row.intermediate
          ? JSON.stringify({
            intermediate: row.intermediate.certificatePem,
            issuing: Object.keys(row.issuing || {}).sort()
              .map(function (uc) {
                return uc + '=' + (row.issuing[uc].certificatePem || '');
              })
          })
          : '';
      };
      const scopesBefore = scopeRows();
      const caBefore = identity();
      note(scopesBefore.indexOf('pki:*process') >= 0 &&
           scopesBefore.indexOf('pki:*service') >= 0 &&
           scopesBefore.some(function (k) {
             return /^dek:[^:]+:\*process$/.test(k);
           }) && caBefore !== '',
           '(the process branch and the service Root are written, with ' +
           'their data-key rows)', scopesBefore.join(','));
      // A removed realm's late row beside them, so the start has an orphan
      // to delete in the same pass.
      const GONE = 'rrk-gone-2';
      store.rows.set(GONE, late);
      let again = null;
      try {
        again = await restart();
      } catch (e) {
        again = { error: e.message };
      }
      const scopesAfter = scopeRows();
      note(again && !again.error && !store.rows.has(GONE) &&
           store.rows.has(LIVE) &&
           JSON.stringify(scopesAfter) === JSON.stringify(scopesBefore),
           'E. a start deletes only the removed realm\'s row: the live ' +
           'realm\'s and every *process and *service row are kept',
           JSON.stringify(again).slice(0, 200) + ' ' + scopesAfter.join(','));
      note(identity() !== '' && identity() === caBefore,
           'E. the process branch keeps its Intermediate and Issuing CAs ' +
           'across the restart', identity() === '' ? 'no process branch'
             : 'a different one');
      const processDek = scopesAfter.filter(function (k) {
        return /^dek:[^:]+:\*process$/.test(k);
      });
      const arrivals = [];
      for (const rowKey of ['pki:*process', 'pki:*service']
        .concat(processDek)) {
        arrivals.push(await keystore.applyStoredChange(rowKey));
      }
      note(arrivals.every(function (a) {
        return !(a && a.kind === 'purged');
      }) && JSON.stringify(scopeRows()) === JSON.stringify(scopesBefore) &&
           identity() === caBefore,
           'F. an arriving *process or *service row is adopted, never purged',
           JSON.stringify(arrivals).slice(0, 400));
    } catch (e) {
      note(false, 'the child ran to the end', e && e.stack);
    }
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })();
}

async function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'removed-realm-key-rows-' + process.pid +
                        '-' + require('crypto').randomBytes(8)
                          .toString('hex') + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/
          .test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + keyRowsChild.toString() + ')()'],
    { env: Object.assign(clean, { LOG_LEVEL: 'fatal', RRK_ROOT: ROOT,
                                  RRK_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    // No report: the child died first; its status and stderr say why.
    log.debug("Caught in run(): " + ((e && e.message) || e));
    findings = null;
  }
  [out, out + '.kek'].forEach(function (file) {
    try {
      fs.unlinkSync(file);
    } catch (e) {
      // Never written, which the read above has already reported.
      log.debug("Caught in run(): " + ((e && e.message) || e));
    }
  });
  if (!t.check(Array.isArray(findings), 'the child process reported its ' +
               'findings', 'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-1500))) {
    log.debug("Leaving run().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'removed_realm_key_rows',
  describe: 'A removed realm\'s key row that lands after its purge is ' +
            'deleted where it arrives and skipped and deleted at a start, ' +
            'and a live realm\'s unopenable row still refuses the start ' +
            '(run #496)',
  run: run
};
