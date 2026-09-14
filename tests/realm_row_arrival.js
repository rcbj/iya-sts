'use strict';
//
// File: realm_row_arrival.js
//
// ===========================================================================
// A ROW FOR A REALM THIS PROCESS HAS NOT HEARD OF YET WAITS IN THAT REALM'S
// PARTITION, AND NEVER IN THE DEFAULT REALM'S (2026-09-14).
//
// `realms.js`'s `partitionId()` read `(get(realmId) || DEFAULT_REALM).id`. It
// was written to make `''` mean the default realm, and it also sent every
// UNKNOWN id there. A second process of this service learns another's write
// through `persistence_minted.js`'s `applyLocally()`, which calls the store's
// `restore` accessor with the realm the row was written in — and in a
// dispatched service that row often arrives before the realm itself does,
// because a realm's first stream, session or token is minted milliseconds after
// the realm. So the row went into the DEFAULT partition, the next in-place edit
// there journalled it as a default-realm row, and every process adopted it.
//
// Measured on the 2026-09-14 dispatch run: the default realm held forty other
// realms' own Shared Signals receiver streams, every default-realm event was
// pushed forty-two times, forty of the pushes were refused and queued, and the
// SCIM bulk load stopped answering. The kept stack showed each leaked copy
// created 250ms BEFORE the realm's own copy, which is this path exactly.
//
// Four claims:
//   1. a row restored for an unknown realm is not in the default realm;
//   2. it is in that realm once the realm is defined — nothing is lost;
//   3. a row for a realm this process REMOVED is refused, so a realm defined
//      again under the same id does not inherit it (the purge's promise);
//   4. the empty string still means the default realm, which is what
//      `partitionId()` was written for.
//
// In a CHILD PROCESS: it creates and removes realms, and a realm left behind
// or a removal seen by another file changes what that file resolves.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'realm_row_arrival',
  level: process.env.LOG_LEVEL || 'info' });

// Runs in the child. Stringified, so it may use nothing from this file's scope.
function child() {
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what, detail: detail || '' });
  };
  const OUT = process.env.REALM_ROW_CHILD_OUT;
  const ROOT = process.env.REALM_ROW_CHILD_ROOT;
  try {
    const realms = require(ROOT + '/common/realms');
    // Three shapes, one declared store each — the three `restore` accessors a
    // replicated row can reach.
    const aMap = realms.map({ persist: 'test.realmRowArrival.map' });
    const anArr = realms.arr({ persist: 'test.realmRowArrival.arr' });
    const anObj = realms.obj(function () { return { seq: 0 }; },
                             { persist: 'test.realmRowArrival.obj' });
    const mapHandle = realms.handleFor('test.realmRowArrival.map');
    const arrHandle = realms.handleFor('test.realmRowArrival.arr');
    const objHandle = realms.handleFor('test.realmRowArrival.obj');
    const LATE = 'late-arrival';
    const inRealm = function (id, fn) {
      return realms.run(realms.get(id), fn);
    };

    // 1. BEFORE THE REALM EXISTS.
    mapHandle.restore(LATE, 'stream-1', { from: LATE });
    arrHandle.restore(LATE, '', [{ from: LATE }]);
    objHandle.restore(LATE, '', { seq: 7 });
    note(!inRealm(realms.DEFAULT_ID, function () {
      return aMap.has('stream-1');
    }),
         'A MAP ROW FOR A REALM THIS PROCESS HAS NOT HEARD OF IS NOT IN THE ' +
         'DEFAULT REALM — the leak that put forty realms\' receiver streams ' +
         'there');
    note(inRealm(realms.DEFAULT_ID, function () { return anArr.length; }) === 0,
         'nor is an array row');
    note(inRealm(realms.DEFAULT_ID, function () { return anObj.seq; }) === 0,
         'nor is an object row');

    // 2. THE REALM ARRIVES.
    realms.create({ id: LATE, name: 'late', restored: true });
    note(inRealm(LATE, function () {
      return aMap.get('stream-1') && aMap.get('stream-1').from;
    }) === LATE,
         'AND THE ROW IS THERE ONCE THE REALM IS DEFINED — it waited in the ' +
         'partition the realm uses, so nothing replicated early is lost');
    note(inRealm(LATE, function () { return anArr.length; }) === 1 &&
         inRealm(LATE, function () { return anObj.seq; }) === 7,
         'the array row and the object row too');

    // 3. REMOVED, THEN A LATE ROW, THEN DEFINED AGAIN.
    realms.remove(LATE);
    mapHandle.restore(LATE, 'stream-2', { from: 'after removal' });
    arrHandle.restore(LATE, '', [{ from: 'after removal' }]);
    objHandle.restore(LATE, '', { seq: 99 });
    realms.create({ id: LATE, name: 'late again' });
    note(inRealm(LATE, function () {
      return aMap.size === 0 && anArr.length === 0 && anObj.seq === 0;
    }),
         'A ROW ARRIVING FOR A REALM THIS PROCESS REMOVED IS REFUSED, so a ' +
         'realm defined again under the same id starts empty — the promise ' +
         'remove()\'s purges make',
         JSON.stringify(inRealm(LATE, function () {
           return { size: aMap.size, arr: anArr.length, seq: anObj.seq };
         })));
    mapHandle.restore(LATE, 'stream-3', { from: 'defined again' });
    note(inRealm(LATE, function () { return aMap.has('stream-3'); }),
         'and once it is defined again it takes rows again');

    // 4. THE EMPTY STRING.
    mapHandle.restore('', 'default-row', { from: 'default' });
    note(inRealm(realms.DEFAULT_ID, function () {
      return aMap.has('default-row');
    }),
         'the empty string still names the default realm, which is what ' +
         'partitionId() was written for');
    realms.remove(LATE);
  } catch (e) {
    note(false, 'the child ran to the end', e && e.stack);
  }
  require('fs').writeFileSync(OUT, JSON.stringify(findings));
  process.exit(0);
}

function run(t) {
  log.debug("Entering run().");
  const root = path.join(__dirname, '..');
  const out = path.join(os.tmpdir(), 'sts-realm-row-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = Object.assign({}, process.env, {
    REALM_ROW_CHILD_OUT: out, REALM_ROW_CHILD_ROOT: root, LOG_LEVEL: 'fatal' });
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
  name: 'realm_row_arrival',
  describe: 'a replicated row for a realm this process has not heard of yet ' +
            'waits in that realm\'s partition, never the default realm\'s',
  run: run
};
