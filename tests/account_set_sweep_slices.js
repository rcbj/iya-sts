// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: account_set_sweep_slices.js
//
// ===========================================================================
// THE HOURLY ACCOUNT-SET SWEEP GIVES THE EVENT LOOP BACK BETWEEN SLICES, AND
// DOES WHAT THE WHOLE SWEEP DID (#780).
//
// `authn.account-set-expiry` checked every session of every browser's set
// synchronously, and with a set per sign-in it held a request worker for
// over a minute on 8081. `AccountSets.sweepInSlices()` is the same sweep,
// yielding every SWEEP_SLICE_MS of work.
//
//   S1. over 400 sets whose session check takes a millisecond, a callback
//       queued at the start runs long before the sweep ends, and the sweep
//       counts more than one slice;
//   S2. it ends, remembers and deletes exactly what sweep() does on the same
//       sets;
//   S3. a set removed by a request between two slices is not written back;
//   B1–B3 (#784). a run of the job does at most its budget, the runs resume
//       where the last stopped, every set of a pass is visited once, and a
//       finished pass is followed by a new one.
//
// In a child process: it fills the module-wide account-set store.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'account_set_sweep_slices',
  level: process.env.LOG_LEVEL || 'info' });

// Runs in the child. Stringified, so it may use nothing from this file's scope.
function child() {
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };
  const OUT = process.env.ASS_OUT;
  const ROOT = process.env.ASS_ROOT;
  const finish = function () {
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  };
  (async function () {
    const realms = require(ROOT + '/common/realms');
    const AccountSets = require(ROOT + '/authn/account_sets');
    const inRealm = function (fn) {
      return realms.run(realms.get(realms.DEFAULT_ID), fn);
    };
    // Sets with one session each; even-numbered sessions have ended.
    const fill = function (n, tag) {
      const ids = [];
      for (let i = 0; i < n; i++) {
        const row = AccountSets.fresh();
        AccountSets.addSession(row, tag + '-sid-' + i,
          { sub: 'urn:uuid:' + tag + '-' + i, username: tag + '-' + i,
            label: tag + '-' + i });
        AccountSets.save(row);
        ids.push(row.id);
      }
      return ids;
    };
    const live = function (sid) {
      const end = Date.now() + 1;
      while (Date.now() < end) {
        // A session check that costs a millisecond, as a store read does.
      }
      return Number(sid.split('-').pop()) % 2 === 1;
    };
    const left = function (ids) {
      return ids.map(function (id) {
        const row = AccountSets.byId(id);
        return row ? Object.keys(row.sessions || {}).length + ':' +
          Object.keys(row.remembered || {}).length : 'gone';
      });
    };

    // --- S1 ---------------------------------------------------------------
    const ids = inRealm(function () {
      return fill(400, 'sa');
    });
    let ranAt = 0;
    const started = Date.now();
    setImmediate(function () {
      ranAt = Date.now();
    });
    const swept = await inRealm(function () {
      return AccountSets.sweepInSlices(live);
    });
    const endedAt = Date.now();
    note(ranAt && ranAt - started < 200 && endedAt - started >= 350 &&
         swept.slices > 1,
         'S1. a callback queued at the start runs within a slice, long ' +
         'before the 400-set sweep ends, and the sweep took several slices',
         JSON.stringify({ ranAfterMs: ranAt - started,
                          sweepMs: endedAt - started, slices: swept.slices }));

    // --- S2 ---------------------------------------------------------------
    const idsB = inRealm(function () {
      return fill(60, 'sb');
    });
    const sliced = inRealm(function () {
      return left(ids);
    });
    const whole = inRealm(function () {
      return AccountSets.sweep(live);
    });
    note(swept.sets >= 400 && swept.ended >= 200 &&
         whole.ended === 30 && sliced.filter(function (v) {
           return v === '1:0';
         }).length === 200 && sliced.filter(function (v) {
           return v === '0:1';
         }).length === 200,
         'S2. the sliced sweep ends the 200 ended sessions and keeps the 200 ' +
         'live ones, as sweep() does (which then ends only the 30 new ones)',
         JSON.stringify({ sliced: swept, whole: whole }));
    void idsB;

    // --- S3 ---------------------------------------------------------------
    const idsC = inRealm(function () {
      return fill(200, 'sc');
    });
    const victim = idsC[199];
    let removedDuring = false;
    const slow = function (sid) {
      if (!removedDuring) {
        removedDuring = true;
        setImmediate(function () {
          inRealm(function () {
            AccountSets.remove(victim);
          });
        });
      }
      return live(sid);
    };
    await inRealm(function () {
      return AccountSets.sweepInSlices(slow);
    });
    note(!inRealm(function () {
      return AccountSets.byId(victim);
    }), 'S3. a set a request removed between two slices stays removed — ' +
         'the sweep reads each set again when its turn comes');

    // --- B (#784): a budgeted run, resuming --------------------------------
    // A pass over these 100 new sets and the 600 already there, at a 60 ms
    // budget with a 1 ms session check: several runs, each within budget,
    // that together visit every set once and then begin a new pass.
    inRealm(function () {
      return fill(100, 'sd');
    });
    const runs = [];
    let visited = 0;
    let of = 0;
    for (let i = 0; i < 40; i++) {
      const t0 = Date.now();
      const run = await inRealm(function () {
        return AccountSets.sweepBudgeted(live, 60);
      });
      runs.push({ ms: Date.now() - t0, sets: run.sets, at: run.at,
                  of: run.of });
      visited += run.sets;
      of = run.of;
      if (run.at >= run.of) {
        break;
      }
    }
    const last = runs[runs.length - 1];
    note(runs.length > 3 && runs.every(function (r) {
      return r.ms < 60 + 2 * 25 + 30;
    }), 'B1. each run stops near its budget, and a pass takes several runs',
         JSON.stringify({ runs: runs.length, slowest: Math.max.apply(null,
           runs.map(function (r) { return r.ms; })) }));
    note(last.at === last.of && visited === of && of > 0,
         'B2. the runs resume where the last stopped and visit every set of ' +
         'the pass exactly once', JSON.stringify({ visited: visited, of: of }));
    const next = await inRealm(function () {
      return AccountSets.sweepBudgeted(live, 60);
    });
    note(next.at > 0 && next.at < next.of && next.sets > 0,
         'B3. after a pass ends, the next run begins a new one',
         JSON.stringify(next));
    finish();
  })().catch(function (e) {
    note(false, 'the child threw', (e && e.stack) || e);
    finish();
  });
}

function run(t) {
  log.debug("Entering run().");
  const root = path.join(__dirname, '..');
  const out = path.join(os.tmpdir(), 'sts-ass-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|CONFIG_FILE$)/.test(key)) {
      env[key] = process.env[key];
    }
  });
  Object.assign(env, { ASS_OUT: out, ASS_ROOT: root, LOG_LEVEL: 'fatal',
                       STS_LOG_LEVEL: 'fatal' });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + child.toString() + ')()'], {
      cwd: root, env: env, encoding: 'utf8', timeout: 180000,
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
  name: 'account_set_sweep_slices',
  describe: 'the hourly account-set sweep gives the event loop back between ' +
            'slices and does what the whole sweep did (#780)',
  run: run
};
