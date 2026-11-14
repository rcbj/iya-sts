// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: console_devices_scale.js
//
// ===========================================================================
// MONITORING → DEVICES COUNTS FROM THE STORE AND ONE PAGE, NOT EVERY DEVICE
// (2026-10-22, #820).
//
// On 8081 `devices.counts()` read every row of `ou=devices` synchronously
// through the bridge on a request worker, and asked the liveness of every
// device's Native SSO session.
//
//   D1. with the two asynchronous hooks offered, `countsAsync()` lists no
//       device synchronously, takes the total from the store's count and
//       tallies one page;
//   D2. `prepare` sees that page before anything is tallied, and liveness is
//       asked of that page's devices only;
//   D3. the answer says it is partial (`windowed`, `counted`, `complete`);
//   D4. with the hooks absent, or answering nothing, it is `counts()`,
//       complete, exactly as before.
//
// In a child process, with a stand-in for the directory's device store.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'console_devices_scale',
  level: process.env.LOG_LEVEL || 'info' });

// Runs in the child. Stringified, so it may use nothing from this file's scope.
function child() {
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };
  const OUT = process.env.CDS_OUT;
  const ROOT = process.env.CDS_ROOT;
  (async function () {
    const devicesModule = require(ROOT + '/common/devices');
    const Devices = devicesModule.Devices;
    const entry = function (id, live) {
      const attributes = { cn: [id], owner: ['uid=alice,ou=users'] };
      if (live !== undefined) {
        attributes.stsdevicesecrethash = ['hash-' + id];
        attributes.stsdevicesession = ['session-' + id];
      }
      return { dn: 'cn=' + id + ',ou=devices', attributes: attributes };
    };
    const PAGE = [entry('d1', true), entry('d2', false), entry('d3')];
    const ALL = PAGE.concat([entry('d4', true), entry('d5')]);
    const build = function (mode) {
      const calls = { list: 0, count: 0, page: [] };
      const credentials = {
        deviceStore: function (operation, args) {
          if (operation === 'hasHook') {
            return mode !== 'absent';
          }
          if (operation === 'deviceCountAsync') {
            calls.count += 1;
            return mode === 'nothing' ? null : Promise.resolve(470000);
          }
          if (operation === 'deviceEntriesPageAsync') {
            calls.page.push(args);
            return Promise.resolve({ entries: PAGE });
          }
          if (operation === 'listDeviceEntries') {
            calls.list += 1;
            return ALL;
          }
          return null;
        }
      };
      const deps = Object.assign({}, Devices.defaultDeps(),
                                 { credentials: credentials });
      return { devices: new Devices(deps), calls: calls };
    };

    const windowed = build('windowed');
    const asked = [];
    let prepared = null;
    const counts = await windowed.devices.countsAsync(function (d) {
      asked.push(d.id);
      return d.id === 'd1';
    }, { prepare: async function (page) {
      prepared = page.map(function (d) { return d.id; });
      note(asked.length === 0, 'D2. prepare runs before anything is tallied',
           JSON.stringify(asked));
    } });
    note(windowed.calls.list === 0,
         'D1. no device is listed synchronously',
         'list=' + windowed.calls.list);
    note(counts.total === 470000, 'D1. the total is the store\'s count',
         counts.total);
    note(windowed.calls.page.length === 1 &&
         windowed.calls.page[0][0] === 0,
         'D1. one page is read, from the start',
         JSON.stringify(windowed.calls.page));
    note(JSON.stringify(prepared) === '["d1","d2","d3"]',
         'D2. prepare is handed the page', JSON.stringify(prepared));
    note(asked.indexOf('d4') === -1 && asked.indexOf('d5') === -1 &&
         asked.length <= 3,
         'D2. liveness is asked of the page\'s devices only',
         JSON.stringify(asked));
    note(counts.nativeSso.live === 1 && counts.nativeSso.ended === 1 &&
         counts.nativeSso.none === 1,
         'D2. the page is tallied', JSON.stringify(counts.nativeSso));
    note(counts.windowed === true && counts.counted === 3 &&
         counts.complete === false,
         'D3. the answer says it covers part of the register',
         JSON.stringify({ windowed: counts.windowed,
                          counted: counts.counted,
                          complete: counts.complete }));

    const whole = function (d) { return d.id === 'd1' || d.id === 'd4'; };
    for (const mode of ['absent', 'nothing']) {
      const built = build(mode);
      const before = built.devices.counts(whole);
      const listedBefore = built.calls.list;
      const after = await built.devices.countsAsync(whole);
      note(built.calls.list === listedBefore + 1 &&
           built.calls.page.length === 0,
           'D4. with the hooks ' + mode + ' the register is read whole',
           'list=' + built.calls.list + ' page=' + built.calls.page.length);
      note(after.complete === true && after.windowed === false &&
           after.counted === after.total && after.total === 5,
           'D4. with the hooks ' + mode + ' the answer is complete',
           JSON.stringify({ total: after.total, counted: after.counted }));
      const strip = function (c) {
        const copy = Object.assign({}, c);
        delete copy.windowed;
        delete copy.counted;
        delete copy.complete;
        return JSON.stringify(copy);
      };
      note(strip(after) === strip(before),
           'D4. with the hooks ' + mode + ' the counts are counts()\'s',
           strip(after));
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
  const out = path.join(os.tmpdir(), 'sts-cds-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|CONFIG_FILE$)/.test(key)) {
      env[key] = process.env[key];
    }
  });
  Object.assign(env, { CDS_OUT: out, CDS_ROOT: root, LOG_LEVEL: 'fatal',
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
  name: 'console_devices_scale',
  describe: 'Monitoring → Devices counts from the store and one page, not ' +
            'every device (#820)',
  run: run
};
