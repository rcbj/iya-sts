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
//   A1–A4 (#780, reopened 2026-11-13: "a run holds no worker"). Given a
//       read-ahead, a run reads each batch's sessions asynchronously and
//       asks the synchronous check NOTHING; the event loop is never held
//       for long, and the pass ends what the parity rule ends (A1); a
//       session added to a set while its batch's read is out is kept (A2);
//       a read-ahead that fails decides nothing and the next run starts at
//       that batch again (A3); a run due while one is still reading is
//       skipped (A4).
//   W1–W3 (#780). `SessionWindow.readAsync()` answers a stored session
//       without admitting it, an absent row as absent, and a read that
//       failed as a failure — never as absence.
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

    // --- A (#780): the reads off the event loop ----------------------------
    // Runs the pass in progress to its end, with the synchronous check.
    const drain = async function () {
      for (let i = 0; i < 200; i++) {
        const run = await inRealm(function () {
          return AccountSets.sweepBudgeted(live, 1000);
        });
        if (run.at >= run.of) {
          return;
        }
      }
    };
    // The parity rule, answered after a 5 ms wait: a store's read pool.
    const parity = function (sid) {
      return Number(sid.split('-').pop()) % 2 === 1;
    };
    const slowRead = function (sids) {
      return new Promise(function (resolve) {
        setTimeout(function () {
          const answers = new Map();
          sids.forEach(function (sid) {
            answers.set(sid, parity(sid));
          });
          resolve(answers);
        }, 5);
      });
    };
    let syncAsked = 0;
    const never = function () {
      syncAsked++;
      return true;
    };
    await drain();
    inRealm(function () {
      return fill(100, 'se');
    });
    let lastTick = Date.now();
    let worstGap = 0;
    const ticker = setInterval(function () {
      const at = Date.now();
      worstGap = Math.max(worstGap, at - lastTick);
      lastTick = at;
    }, 2);
    // A2's session: added to the first set of the pass while the first
    // batch's read is out. Its number is even, so a check would end it.
    let lateAdded = false;
    const readAndAdd = function (sids) {
      if (!lateAdded) {
        lateAdded = true;
        inRealm(function () {
          const row = AccountSets.byId(ids[0]);
          AccountSets.addSession(row, 'late-sid-0',
            { sub: 'urn:uuid:late-0', username: 'late-0', label: 'late-0' });
          AccountSets.save(row);
        });
      }
      return slowRead(sids);
    };
    const aRuns = [];
    for (let i = 0; i < 200; i++) {
      const run = await inRealm(function () {
        return AccountSets.sweepBudgeted(never, 1000, readAndAdd);
      });
      aRuns.push(run);
      if (run.at >= run.of) {
        break;
      }
    }
    clearInterval(ticker);
    const aEnded = aRuns.reduce(function (n, r) {
      return n + r.ended;
    }, 0);
    const aReads = aRuns.reduce(function (n, r) {
      return n + (r.reads || 0);
    }, 0);
    const aLast = aRuns[aRuns.length - 1];
    note(syncAsked === 0 && aReads > 1 && aLast.at === aLast.of &&
         aEnded === 50 && worstGap < 60,
         'A1. with a read-ahead the pass asks the synchronous check nothing, ' +
         'reads in several batches, ends the 50 ended sessions of the 100 ' +
         'new sets, and never holds the loop for long',
         JSON.stringify({ syncAsked: syncAsked, reads: aReads,
                          ended: aEnded, worstGapMs: worstGap,
                          runs: aRuns.length }));
    const firstRow = inRealm(function () {
      return AccountSets.byId(ids[0]);
    });
    note(lateAdded && firstRow && firstRow.sessions &&
         firstRow.sessions['late-sid-0'],
         'A2. a session added to a set while its batch was being read is ' +
         'kept, for the next pass to decide');

    // A3: a read-ahead that fails.
    inRealm(function () {
      return fill(10, 'sf');
    });
    const failing = function () {
      return Promise.reject(new Error('the read pool is gone'));
    };
    const failed = await inRealm(function () {
      return AccountSets.sweepBudgeted(never, 1000, failing);
    });
    const after = await inRealm(function () {
      return AccountSets.sweepBudgeted(never, 1000, slowRead);
    });
    note(failed.at === 0 && failed.sets === 0 && failed.ended === 0 &&
         after.at > 0 && after.sets > 0 && syncAsked === 0,
         'A3. a read-ahead that fails decides nothing, and the next run ' +
         'starts that batch again', JSON.stringify({ failed: failed,
                                                    after: after }));

    // A4: a run due while one is still reading.
    let release = null;
    const held = function (sids) {
      if (release) {
        // Only the first batch's read is held; the rest answer as usual.
        return slowRead(sids);
      }
      return new Promise(function (resolve) {
        release = function () {
          slowRead(sids).then(resolve);
        };
      });
    };
    const first = inRealm(function () {
      return AccountSets.sweepBudgeted(never, 1000, held);
    });
    await new Promise(function (resolve) {
      setTimeout(resolve, 10);
    });
    const second = await inRealm(function () {
      return AccountSets.sweepBudgeted(never, 1000, slowRead);
    });
    if (release) {
      release();
    }
    const firstDone = await first;
    note(release && second.skipped === true && second.sets === 0 &&
         firstDone.sets > 0,
         'A4. a run due while another is still reading is skipped, and the ' +
         'first finishes', JSON.stringify({ second: second,
                                            first: firstDone }));

    // --- W (#780): SessionWindow.readAsync() --------------------------------
    const keystore = require(ROOT + '/common/keystore');
    keystore.sealed = function () {
      return true;
    };
    keystore.keyedDigest = function (label, text) {
      return 'digest:' + text;
    };
    const sessionWindow = require(ROOT + '/authn/session_window');
    const realmId = inRealm(function () {
      return realms.currentId();
    });
    const rows = { 'w-live': { session: { id: 'w-live', user: 'w' } },
                   'w-gone': null };
    sessionWindow.offerAsyncQuery(function (name, args) {
      const digest = String(args[1] || '');
      const sid = digest.split('\n').pop();
      if (sid === 'w-broken') {
        return Promise.reject(new Error('the read pool is gone'));
      }
      return new Promise(function (resolve) {
        setTimeout(function () {
          resolve(name === 'session.read' ? rows[sid] || null : null);
        }, 2);
      });
    });
    const wLive = await sessionWindow.readAsync(realmId, 'w-live');
    const wSlot = sessionWindow.slotState(realmId, 'w-live');
    note(wLive.ok && wLive.session && wLive.session.id === 'w-live' &&
         !wSlot.cached,
         'W1. a stored session is answered, and not admitted to the window',
         JSON.stringify({ read: wLive, slot: wSlot }));
    const wGone = await sessionWindow.readAsync(realmId, 'w-gone');
    note(!wGone.ok && wGone.absent === true && !wGone.error,
         'W2. an absent row is answered as absent', JSON.stringify(wGone));
    const wBroken = await sessionWindow.readAsync(realmId, 'w-broken');
    note(!wBroken.ok && wBroken.error === true && !wBroken.absent,
         'W3. a read that failed is answered as a failure, never as absence',
         JSON.stringify(wBroken));
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
            'slices, reads its sessions off the event loop, and does what ' +
            'the whole sweep did (#780)',
  run: run
};
