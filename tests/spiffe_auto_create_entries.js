// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/spiffe_auto_create_entries.js
// ===========================================================================
// `spiffe.autoCreateEntries` IS IGNORED IN PRODUCT (#415, 2026-10-02).
//
// On, the setting makes the Workload API invent a registration entry —
// `spiffe://<domain>/workload` — for a caller that matched none, and issue it
// an SVID: the mock's posture. `spiffe/spiffe_workload.ts`'s
// `entitledEntries()` asks TWO questions before it does, the setting and
// `mode.autoCreates()`, so a product realm invents nothing whatever the
// setting holds. Nothing asserted the second question (#113 item 11): the one
// test touching the setting turns it OFF.
//
// `entitledEntries()` is the one decision the Workload API's four issuing
// methods share, so asking it is asking what a caller would be issued. In a
// CHILD PROCESS with the stack, in a realm of this run's own whose registry is
// emptied first (development seeds demonstration entries, and a caller that
// matches one never reaches the invention):
//
//   1. development, the setting on: an unregistered caller is handed ONE
//      entry, the invented `/workload` one, and the registry now holds it —
//      the control, so the refusal below is about the mode;
//   2. the realm switched to product with the setting STILL ON (stored, and
//      read back as on): the same caller is handed nothing, and the registry
//      holds nothing new;
//   3. product with the setting off: nothing either;
//   4. and back in development, on: one is invented again.
//
// The realm is left standing, as every realm a test makes is.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'spiffe_auto_create_entries',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.SA_ROOT;
  const OUT = process.env.SA_OUT;
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  try {
    require(ROOT_DIR + '/common/protocol_stack');
    const config = require(ROOT_DIR + '/common/config');
    const realms = require(ROOT_DIR + '/common/realms');
    const registry = require(ROOT_DIR + '/spiffe/spiffe_registry');
    const workload = require(ROOT_DIR + '/spiffe/spiffe_workload');

    const id = 'sa-' + process.pid;
    const made = realms.create({ id: id });
    note(made && made.ok !== false, 'precondition: a realm is made',
         JSON.stringify(made && made.errors));
    const inRealm = function (fn) {
      return realms.run(realms.get(id), fn);
    };
    // An attested caller with a stable selector, which no entry selects.
    const caller = { selectors: [{ type: 'unix', value: 'uid:4242' }] };
    const empty = function () {
      inRealm(function () {
        registry.allEntries().forEach(function (entry) {
          registry.deleteEntry(entry.id, 'test');
        });
      });
      return inRealm(function () { return registry.allEntries().length; });
    };
    const ask = function () {
      return inRealm(function () {
        const handed = workload.entitledEntries(caller);
        return { handed: handed,
                 held: registry.allEntries().map(function (entry) {
                   return entry.spiffeId;
                 }) };
      });
    };

    // --- 1. development, on: the control ---------------------------------
    let w = realms.setOverride(id, 'spiffe.autoCreateEntries', 'true');
    note(w && w.ok !== false, 'precondition: spiffe.autoCreateEntries is on ' +
         'in the realm', JSON.stringify(w));
    note(empty() === 0, 'precondition: the realm\'s registry is empty', '');
    let got = ask();
    note(got.handed.length === 1 &&
         /\/workload$/.test(String(got.handed[0].spiffeId)) &&
         got.held.length === 1,
         '1. development, setting on: an unregistered caller is handed one ' +
         'invented /workload entry, and the registry holds it (the control)',
         JSON.stringify(got.held));

    // --- 2. product, the setting still on --------------------------------
    note(empty() === 0, 'precondition: the registry is emptied again', '');
    w = realms.setOverride(id, 'global.mode', 'product');
    note(w && w.ok !== false, 'precondition: the realm is switched to ' +
         'product', JSON.stringify(w));
    const stored = inRealm(function () {
      return config.value('spiffe.autoCreateEntries');
    });
    note(stored === true, 'precondition: the setting still reads on in the ' +
         'product realm', JSON.stringify(stored));
    got = ask();
    note(got.handed.length === 0,
         '2a. PRODUCT, setting on: the unregistered caller is handed nothing',
         JSON.stringify(got.handed));
    note(got.held.length === 0,
         '2b. PRODUCT, setting on: and no entry was created',
         JSON.stringify(got.held));

    // --- 3. product, off --------------------------------------------------
    realms.setOverride(id, 'spiffe.autoCreateEntries', 'false');
    got = ask();
    note(got.handed.length === 0 && got.held.length === 0,
         '3. PRODUCT, setting off: nothing handed, nothing created',
         JSON.stringify(got.held));

    // --- 4. back to development, on ---------------------------------------
    realms.setOverride(id, 'global.mode', 'development');
    realms.setOverride(id, 'spiffe.autoCreateEntries', 'true');
    got = ask();
    note(got.handed.length === 1 && got.held.length === 1,
         '4. development again, setting on: one is invented again',
         JSON.stringify(got.held));
  } catch (e) {
    note(false, 'the child process ran to the end', e && e.stack);
  }
  require('fs').writeFileSync(OUT, JSON.stringify(findings));
  process.exit(0);
}

async function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'sa-' + process.pid + '-' + Date.now() +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|LDAP_|LDAPS_|KRB5_|SPIFFE_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal',
                                  SA_ROOT: ROOT, SA_OUT: out }),
      encoding: 'utf8', timeout: 180000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    findings = null;
  }
  if (!t.check(Array.isArray(findings),
               'the child process reported its findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-800))) {
    log.debug("Leaving run().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'spiffe_auto_create_entries',
  describe: 'spiffe.autoCreateEntries invents an entry in development and is ' +
            'ignored in product (#415)',
  run: run
};
