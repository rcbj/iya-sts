'use strict';
//
// File: rate_limit_replication.js
//
// ===========================================================================
// EVERY FAILED ATTEMPT A RATE-LIMIT BUCKET COUNTS IS WRITTEN DOWN, SO EVERY
// REQUEST WORKER COUNTS THE SAME CALLER THE SAME WAY (2026-09-14).
//
// `common/websecurity.ts`'s buckets are `realms.sharedMap()`, which journals a
// `set()` and a `delete()`. `attempt()` set a bucket on its first failure and
// then did `row.count += 1` on the row it held — so only the FIRST failure ever
// reached the journal. In one process that is invisible. In the request-worker
// pool each worker kept its own count, and `sts_est_enrollment` in `dispatch`
// mode sent three wrong passwords and got 401, 401, 401 where the third must be
// 429 — in two runs in a row, and never in the two single-process modes.
//
// Two claims, the way a second process learns a write — the store's `restore`
// accessor, which `persistence_minted.js`'s `applyLocally()` calls:
//   1. the second and third failure each reach the persist observer as THAT
//      bucket's key;
//   2. a count another worker wrote is the count this one refuses on.
//
// In a CHILD PROCESS, because a persist observer cannot be put back and the
// buckets are process-wide.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'rate_limit_replication',
  level: process.env.LOG_LEVEL || 'info' });

// Runs in the child. Stringified, so it may use nothing from this file's scope.
function child() {
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what, detail: detail || '' });
  };
  const OUT = process.env.RATE_LIMIT_CHILD_OUT;
  const ROOT = process.env.RATE_LIMIT_CHILD_ROOT;
  try {
    const realms = require(ROOT + '/common/realms');
    const journal = [];
    realms.setPersistObserver(function (handle, realmId, key) {
      journal.push({ handle: handle, key: key });
    });
    const ws = require(ROOT + '/common/websecurity');
    const HANDLE = 'security.rateLimitBuckets';
    const req = { headers: {}, socket: { remoteAddress: '192.0.2.10' } };
    const idKey = 'enroll-est|id|throttled-person';
    const writesOf = function (key) {
      return journal.filter(function (row) {
        return row.handle === HANDLE && row.key === key;
      }).length;
    };

    // 1. EVERY FAILURE IS WRITTEN DOWN.
    ws.attempt('enroll-est', req, 'throttled-person', 2);
    ws.attempt('enroll-est', req, 'throttled-person', 2);
    ws.attempt('enroll-est', req, 'throttled-person', 2);
    note(writesOf(idKey) === 3,
         'THREE FAILURES ARE THREE JOURNALLED WRITES OF THE BUCKET — before ' +
         'the fix only the first was, so no other worker ever saw the count',
         writesOf(idKey) + ' write(s): ' + JSON.stringify(journal));

    // 2. ANOTHER WORKER'S COUNT IS THE ONE REFUSED ON.
    const handle = realms.handleFor(HANDLE);
    const other = 'enroll-est|id|counted-elsewhere';
    handle.restore('', other, { count: 2, until: Date.now() + 60000 });
    const decided = ws.attempt('enroll-est', req, 'counted-elsewhere', 2);
    note(decided && decided.ok === false && decided.kind === 'identity',
         'a bucket another worker filled to its limit refuses this worker\'s ' +
         'next attempt', JSON.stringify(decided));
    const read = handle.read('', other);
    note(read.present && read.value.count === 3,
         'and the count this worker wrote on top of it is the one held',
         JSON.stringify(read));
  } catch (e) {
    note(false, 'the child ran to the end', e && e.stack);
  }
  require('fs').writeFileSync(OUT, JSON.stringify(findings));
  process.exit(0);
}

function run(t) {
  log.debug("Entering run().");
  const root = path.join(__dirname, '..');
  const out = path.join(os.tmpdir(), 'sts-rate-limit-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = Object.assign({}, process.env, {
    RATE_LIMIT_CHILD_OUT: out, RATE_LIMIT_CHILD_ROOT: root,
    LOG_LEVEL: 'fatal' });
  delete env.CONFIG_FILE;
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + child.toString() + ')()'], {
      cwd: root, env: env, encoding: 'utf8', timeout: 120000,
      maxBuffer: 64 * 1024 * 1024 });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    // The child died before writing a report; said below with its status.
    findings = null;
  }
  try {
    fs.rmSync(out, { force: true });
  } catch (e) {
    // A temporary file left behind is not a failed assertion.
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (t.check(Array.isArray(findings),
              'the child process reported its findings',
              'status=' + result.status + ' ' +
              String(result.stderr || '').slice(-2000))) {
    findings.forEach(function (one) { t.check(one.ok, one.what, one.detail); });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'rate_limit_replication',
  describe: 'every failure a rate-limit bucket counts is journalled, so every ' +
            'request worker refuses the same caller at the same count',
  run: run
};
