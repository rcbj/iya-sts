'use strict';
//
// File: cluster_observation_counters.js
//
// ===========================================================================
// TWO THINGS THE SUITE'S `cluster` MODE FOUND THAT `postgres` MODE CANNOT
// (2026-09-15, #46).
//
//   1. THE XACML MONITOR'S COUNTERS DISAGREED BETWEEN NODES. `record()` changed
//      its row IN PLACE and journalled it only when the row was first created,
//      so `sts_minted` held each process's FIRST decision and nothing after.
//      Each node's page adds its own live tally to the other node's frozen
//      row, so `sts_portal_sessions` read the issuance PEP at 126 on node A and
//      142 on node B around a page load that decided nothing (21 then 17 in a
//      run of that job alone — it went DOWN). Every decision is journalled
//      now, and the store is declared `observation: true` so that the access
//      PEP's decision on every console read does not make that read a
//      WRITING request the cluster barrier would hold — rcbj's decision 6 in
//      `cluster/CLAUDE.md`. Sections 1-3.
//   2. THE REMOTE PEP'S NUDGE LEFT BEFORE THE POLICY COMMITTED. It is fired
//      from inside `xacml_store.write()`; the PEP pulls at once, through the
//      balancer, and the other node answered the old sync token, so the PEP
//      converged on its next heartbeat instead (2018ms, 916ms, against tens of
//      milliseconds). A clustered node now nudges once
//      `persistence.commitThrough()` has resolved. Section 4.
//
// WHY IN PROCESS: both are an ORDER — a row journalled or not, a nudge before
// or after a commit — that two live nodes lose only sometimes. The live runs
// are in `cluster/CLAUDE.md`.
//
// IN A CHILD PROCESS, for `cluster_barrier_throughput.js`'s reason: the store
// modules are one per process, and this file installs stubs on them.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'cluster_observation_counters',
  level: process.env.LOG_LEVEL || 'info' });

const CHILD_FLAG = 'STS_CLUSTER_OBSERVATION_COUNTERS_CHILD';

function settle() {
  log.debug("Entering settle().");
  log.debug("Leaving settle().");
  return new Promise(function (resolve) {
    setImmediate(resolve);
  });
}

function recordingHarness() {
  log.debug("Entering recordingHarness().");
  const seen = [];
  function check(condition, what, detail) {
    log.debug("Entering check().");
    seen.push({ ok: !!condition, what: what,
                detail: detail === undefined ? '' : String(detail) });
    log.debug("Leaving check().");
    return !!condition;
  }
  log.debug("Leaving recordingHarness().");
  return {
    log: log,
    seen: seen,
    check: check,
    equal: function (actual, expected, what) {
      log.debug("Entering equal().");
      log.debug("Leaving equal().");
      return check(actual === expected, what,
                   'expected ' + JSON.stringify(expected) + ', got ' +
                   JSON.stringify(actual));
    }
  };
}

// ---------------------------------------------------------------------------
// 1. EVERY DECISION IS JOURNALLED, AND THE CONTROL THAT SHOWS WHY IT WAS NOT.
// ---------------------------------------------------------------------------
function everyDecisionJournalled(t) {
  log.debug("Entering everyDecisionJournalled().");
  t.log.info('=== 1. every decision counted is journalled ===');
  const realms = require('../common/realms');
  const monitor = require('../xacml/xacml_monitor');
  const notes = { monitor: 0, control: 0 };
  realms.setPersistObserver(function (handle) {
    if (handle === 'xacml_monitor.counters') {
      notes.monitor += 1;
    } else if (handle === 'test.observation.control') {
      notes.control += 1;
    }
  });

  // THE CONTROL: a row changed in place through `get()` is invisible to the
  // journal. This is what `record()` did after the row's first `set()`.
  const control = realms.map({ persist: 'test.observation.control',
                               merge: 'own' });
  control.set('row', { decisions: 0 });
  control.get('row').decisions += 1;
  control.get('row').decisions += 1;
  t.equal(notes.control, 1,
          'THE CONTROL: a realms.map() row incremented in place is ' +
          'journalled once, by its set(), and never again — so the stored ' +
          'row is frozen at the first value');

  monitor.resetForTests();
  // The first decision creates the row (`rowFor()`'s set) and sets it back;
  // the claim is about every decision AFTER that, which is where it failed.
  monitor.record('issuance', { decision: 'Permit', allowed: true });
  notes.monitor = 0;
  monitor.record('issuance', { decision: 'Permit', allowed: true });
  monitor.record('issuance', { decision: 'Deny', allowed: false });
  t.equal(notes.monitor, 2,
          'TWO LATER DECISIONS, TWO JOURNAL ENTRIES: record() sets the row ' +
          'back after changing it, so the row another node reads moves with ' +
          'every decision (it was 0 after the create before 2026-09-15)');
  const handle = realms.handleFor('xacml_monitor.counters');
  const DEFAULT = realms.DEFAULT_REALM.id;
  const stored = handle.read(DEFAULT, 'issuance');
  t.check(stored.present && stored.value.decisions === 3 &&
          stored.value.allowed === 2 && stored.value.refused === 1,
          'and what the flush reads for that key is the whole current tally',
          JSON.stringify(stored.value));
  t.equal(handle.observation, true,
          'the store is declared `observation: true`');
  t.equal(realms.handleFor('test.observation.control').observation, false,
          'and a store that does not say so is not one');
  monitor.resetForTests();
  control.clear();
  realms.setPersistObserver(null);
  log.debug("Leaving everyDecisionJournalled().");
}

// ---------------------------------------------------------------------------
// 2. THE MINTED JOURNAL COUNTS OBSERVATIONS APART.
// ---------------------------------------------------------------------------
function mintedCountsObservations(t) {
  log.debug("Entering mintedCountsObservations().");
  t.log.info('=== 2. the minted position counts observations apart ===');
  const realms = require('../common/realms');
  const minted = require('../persistence/persistence_minted');
  const persistence = require('../persistence/persistence');
  const monitor = require('../xacml/xacml_monitor');
  const driver = {
    origin: function () {
      log.debug("Entering origin().");
      log.debug("Leaving origin().");
      return 'process-a';
    },
    loadMinted: function () {
      log.debug("Entering loadMinted().");
      log.debug("Leaving loadMinted().");
      return Promise.resolve([]);
    },
    saveMinted: function () {
      log.debug("Entering saveMinted().");
      log.debug("Leaving saveMinted().");
      return Promise.resolve();
    }
  };
  minted.reset();
  t.check(minted.setDriver(driver, 'postgres'),
          'the minted store is installed, which arms the journal');
  const sessions = realms.map({ persist: 'test.observation.sessions' });

  // The first creates the row; see section 1.
  monitor.record('access', { decision: 'Permit', allowed: true });
  const g0 = minted.generation();
  const o0 = minted.observedGeneration();
  monitor.record('access', { decision: 'Permit', allowed: true });
  t.equal(minted.generation() - g0, 1,
          'a decision counted moves the minted position — it is written ' +
          'down like any other row');
  t.equal(minted.observedGeneration() - o0, 1,
          'AND IS COUNTED AS AN OBSERVATION');
  const position = persistence.writeGeneration();
  t.equal(position.observed, minted.observedGeneration(),
          'persistence.writeGeneration() carries the observed count beside ' +
          'the minted position');

  const g1 = minted.generation();
  const o1 = minted.observedGeneration();
  sessions.set('s1', { v: 1 });
  t.equal(minted.generation() - g1, 1, 'a session written moves it too');
  t.equal(minted.observedGeneration() - o1, 0,
          'and is NOT an observation');
  sessions.clear();
  monitor.resetForTests();
  minted.reset();
  realms.setPersistObserver(null);
  log.debug("Leaving mintedCountsObservations().");
}

// ---------------------------------------------------------------------------
// 3. THE BARRIER: A TALLY ALONE IS NOT HELD; A TALLY WITH A WRITE RIDES IT.
// ---------------------------------------------------------------------------
async function barrierAndObservations(t) {
  log.debug("Entering barrierAndObservations().");
  t.log.info('=== 3. the barrier does not hold a read for its tally ===');
  const persistence = require('../persistence/persistence');
  const barrier = require('../cluster/cluster_barrier');
  const saved = { writeGeneration: persistence.writeGeneration,
                  commitThrough: persistence.commitThrough,
                  keysPending: persistence.keysPending };
  const position = { directory: 0, minted: 0, observed: 0 };
  const commits = [];
  const reports = { observed: true };
  persistence.writeGeneration = function () {
    log.debug("Entering the stubbed writeGeneration().");
    log.debug("Leaving the stubbed writeGeneration().");
    const out = { directory: position.directory, minted: position.minted };
    if (reports.observed) {
      out.observed = position.observed;
    }
    return out;
  };
  persistence.keysPending = function () {
    log.debug("Entering the stubbed keysPending().");
    log.debug("Leaving the stubbed keysPending().");
    return false;
  };
  persistence.commitThrough = function (target) {
    log.debug("Entering the stubbed commitThrough().");
    log.debug("Leaving the stubbed commitThrough().");
    commits.push(target);
    return Promise.resolve([]);
  };
  function fakeResponse() {
    log.debug("Entering fakeResponse().");
    const res = { ended: 0 };
    res.end = function () {
      res.ended += 1;
      return res;
    };
    log.debug("Leaving fakeResponse().");
    return res;
  }
  try {
    // A READ WHOSE ONLY ROW IS A DECISION COUNTED.
    let res = fakeResponse();
    barrier.holdUntilCommitted(res, persistence.writeGeneration());
    position.minted += 1;
    position.observed += 1;
    res.end();
    await settle();
    t.equal(res.ended, 1,
            'A REQUEST WHOSE ONLY WRITE WAS A DECISION COUNTED IS ANSWERED ' +
            'AT ONCE — the access PEP decides on every console read, and ' +
            'decision 6 keeps reads unheld');
    t.equal(commits.length, 0, 'and no commit is asked for');

    // THE CONTROL: the same movement from a position with no observed count
    // (a store that is not declared an observation) is a write, and is held.
    reports.observed = false;
    res = fakeResponse();
    barrier.holdUntilCommitted(res, persistence.writeGeneration());
    position.minted += 1;
    position.observed += 1;
    res.end();
    t.equal(res.ended, 0, 'THE CONTROL is not answered at once');
    await settle();
    t.equal(commits.length, 1,
            'THE CONTROL: the same minted movement, not reported as an ' +
            'observation, holds the response for a commit — so the answer ' +
            'above is the observation count at work');
    await settle();
    await settle();
    t.equal(res.ended, 1, 'and it is answered once that commit lands');
    reports.observed = true;

    // A REQUEST THAT WROTE SOMETHING ELSE AS WELL.
    res = fakeResponse();
    barrier.holdUntilCommitted(res, persistence.writeGeneration());
    position.minted += 1;
    position.observed += 1;
    position.minted += 1;
    res.end();
    t.equal(res.ended, 0,
            'a request that counted a decision AND wrote a row is held');
    await settle();
    t.equal(commits.length, 2, 'for one commit');
    t.equal(commits[1].minted, position.minted,
            'WHOSE TARGET IS THE WHOLE POSITION, tally included — so the ' +
            'decision is in the store before the other node can be asked');
    await settle();
    await settle();
    t.equal(res.ended, 1, 'and answered after it');
  } finally {
    persistence.writeGeneration = saved.writeGeneration;
    persistence.commitThrough = saved.commitThrough;
    persistence.keysPending = saved.keysPending;
  }
  log.debug("Leaving barrierAndObservations().");
}

// ---------------------------------------------------------------------------
// 4. THE NUDGE WAITS FOR THE COMMIT ON AN ACTIVE-ACTIVE NODE, AND ONLY THERE.
// ---------------------------------------------------------------------------
async function nudgeAfterCommit(t) {
  log.debug("Entering nudgeAfterCommit().");
  t.log.info('=== 4. a clustered node nudges after the commit ===');
  const config = require('../common/config');
  const cluster = require('../cluster/cluster');
  const persistence = require('../persistence/persistence');
  const pepHttp = require('../xacml/xacml_pep_http');
  const peps = require('../xacml/xacml_pep_registry');
  const xacml = require('../xacml/xacml');
  const active = { value: false };
  const commits = [];
  const nudges = [];
  cluster.isActiveActive = function () {
    log.debug("Entering the stubbed isActiveActive().");
    log.debug("Leaving the stubbed isActiveActive().");
    return active.value;
  };
  cluster.enabled = function () {
    log.debug("Entering the stubbed enabled().");
    log.debug("Leaving the stubbed enabled().");
    return active.value;
  };
  persistence.writeGeneration = function () {
    log.debug("Entering the stubbed writeGeneration().");
    log.debug("Leaving the stubbed writeGeneration().");
    return { directory: 7, minted: 3, observed: 0 };
  };
  persistence.commitThrough = function (target) {
    log.debug("Entering the stubbed commitThrough().");
    log.debug("Leaving the stubbed commitThrough().");
    return new Promise(function (resolve) {
      commits.push({ target: target, resolve: resolve });
    });
  };
  config.setOverride('xacml.pepNotify', true);
  config.setOverride('xacml.remotePeps', true);
  peps.notifiable = function () {
    log.debug("Entering the stubbed notifiable().");
    log.debug("Leaving the stubbed notifiable().");
    return [{ name: 'pep-1', notifyUrl: 'https://pep.example.com/notify' }];
  };
  pepHttp.nudgeAll = function (rows) {
    log.debug("Entering the stubbed nudgeAll().");
    nudges.push(rows.map(function (row) { return row.name; }).join(','));
    log.debug("Leaving the stubbed nudgeAll().");
    return Promise.resolve(rows.map(function () { return { ok: true }; }));
  };

  // THE CONTROL, and the behaviour one node keeps: at once, no commit asked.
  xacml.nudgeRegisteredPeps('policy "p" was written');
  t.equal(nudges.length, 1,
          'NOT ACTIVE-ACTIVE: the nudge is dispatched synchronously, inside ' +
          'the write, exactly as before');
  t.equal(commits.length, 0, 'and no commit is waited for');

  active.value = true;
  xacml.nudgeRegisteredPeps('policy "p" was written');
  t.equal(nudges.length, 1,
          'ACTIVE-ACTIVE: nothing is dialled while the policy is only in ' +
          'this node\'s memory — the PEP would pull from a node that has not ' +
          'seen it');
  await settle();
  await settle();
  t.equal(commits.length, 1,
          'the commit of everything written so far is waited for');
  t.check(commits[0] && commits[0].target.directory === 7,
          'at the position taken after the write',
          JSON.stringify(commits[0] && commits[0].target));
  await settle();
  t.equal(nudges.length, 1, 'still not dialled while it has not landed');
  commits[0].resolve([]);
  await settle();
  await settle();
  t.equal(nudges.length, 2,
          'AND THE NUDGE GOES ONCE THE COMMIT LANDS, so a pull on any node ' +
          'sees the new sync token');

  xacml.nudgeRegisteredPeps('policy "p" was written');
  await settle();
  await settle();
  commits[1].resolve([{ error: 'the database went away' }]);
  await settle();
  await settle();
  t.equal(nudges.length, 3,
          'a commit that FAILED still nudges — the nudge is an optimisation ' +
          'and the PEP converges on its poll either way');
  active.value = false;
  log.debug("Leaving nudgeAfterCommit().");
}

async function childMain() {
  log.debug("Entering childMain().");
  delete process.env.CONFIG_FILE;
  const out = process.env.PROBE_OUT;
  const t = recordingHarness();
  let threw = '';
  try {
    everyDecisionJournalled(t);
    mintedCountsObservations(t);
    await barrierAndObservations(t);
    await nudgeAfterCommit(t);
  } catch (e) {
    log.debug("Caught in childMain(): " + ((e && e.message) || e));
    threw = (e && e.stack) || String(e);
  }
  fs.writeFileSync(out, JSON.stringify({ seen: t.seen, threw: threw }));
  log.debug("Leaving childMain().");
  // Timers from the app and the store may still be armed; the answer is out.
  process.exit(0);
}

function run(t) {
  log.debug("Entering run().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-observation-out-'));
  const outFile = path.join(dir, 'out.json');
  const env = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|CONFIG_FILE$)/.test(key)) {
      env[key] = process.env[key];
    }
  });
  Object.assign(env, { PROBE_OUT: outFile, LOG_LEVEL: 'fatal' });
  env[CHILD_FLAG] = '1';
  const child = childProcess.spawnSync(process.execPath, [__filename],
    { cwd: path.join(__dirname, '..'), env: env, encoding: 'utf8',
      timeout: 120000 });
  let result = null;
  try {
    result = JSON.parse(fs.readFileSync(outFile, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    t.bad('the child process reported nothing',
          'status ' + child.status + ', signal ' + child.signal + ': ' +
          String(child.stderr || '').slice(-2000));
    log.debug("Leaving run().");
    return;
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  result.seen.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  if (result.threw) {
    t.bad('the child process threw', result.threw);
  }
  t.check(result.seen.length >= 25,
          'every section ran — a section that stopped being reached would ' +
          'take its assertions with it and still say "passed"',
          String(result.seen.length) + ' assertion(s) recorded');
  log.debug("Leaving run().");
}

if (require.main === module && process.env[CHILD_FLAG] === '1') {
  childMain();
}

module.exports = {
  name: 'cluster_observation_counters',
  describe: 'issue #46 cluster mode: the XACML monitor journals every ' +
            'decision as an observation the barrier does not hold a read ' +
            'for, and a clustered node nudges remote PEPs only after the ' +
            'policy change commits',
  run: run
};
