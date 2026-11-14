// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: heap_collector.js
//
// ===========================================================================
// A FULL GARBAGE COLLECTION OF THE ISOLATE THAT ASKS, WITHOUT A STARTUP FLAG
// (#611, 2026-10-13).
//
// `common/heap_collector.ts` is what Monitoring → Node Health's Collect
// buttons run in the front process and in each worker thread. Four claims:
//
//   A. `gc` IS OBTAINED in a process started without `--expose-gc`, and the
//      same function is handed back the second time.
//   B. THE FLAG IS CLEARED AGAIN: no global `gc` here, and none in a context
//      made afterwards — left set, every `vm` sandbox and every worker thread
//      started later would carry one.
//   C. A COLLECTION REPORTS THE ISOLATE'S HEAP before and after, what it
//      freed (the difference) and the pause, and frees garbage made for it.
//   D. IN A WORKER THREAD, which is an isolate of its own, the same call
//      collects that thread's heap and reports it.
// ===========================================================================

const path = require('path');
const vm = require('vm');
const { Worker } = require('worker_threads');
const HeapCollector = require('../common/heap_collector');

const log = require('bunyan').createLogger({
  name: 'heap_collector',
  level: process.env.LOG_LEVEL || 'info' });

const MIB = 1024 * 1024;

// Garbage of roughly `count` small objects, made and dropped, so a
// collection has something to free.
function makeGarbage(count) {
  log.debug("Entering makeGarbage().");
  let junk = [];
  for (let i = 0; i < count; i++) {
    junk.push({ i: i, text: 'garbage ' + i });
  }
  const made = junk.length;
  junk = null;
  log.debug("Leaving makeGarbage().");
  return made;
}

// The figures every successful collection carries.
function wellFormed(c) {
  log.debug("Entering wellFormed().");
  const numbers = ['heapUsedBeforeBytes', 'heapTotalBeforeBytes',
                   'heapUsedAfterBytes', 'heapTotalAfterBytes',
                   'durationMs'].every(function (name) {
    return typeof c[name] === 'number' && isFinite(c[name]) && c[name] >= 0;
  });
  log.debug("Leaving wellFormed().");
  return c.ok === true && c.error === null && numbers &&
         c.freedBytes === c.heapUsedBeforeBytes - c.heapUsedAfterBytes;
}

function checkObtained(t) {
  log.debug("Entering checkObtained().");
  t.log.info('=== A. gc is obtained without --expose-gc, once ===');
  const startedWith = process.execArgv.some(function (a) {
    return /expose[-_]gc/.test(a);
  }) || /expose[-_]gc/.test(String(process.env.NODE_OPTIONS || ''));
  t.check(!startedWith && typeof global.gc !== 'function',
          'this process was started without --expose-gc', '');
  const first = HeapCollector.gcFunction(log);
  const second = HeapCollector.gcFunction(log);
  t.check(typeof first === 'function' && first === second,
          'gcFunction() hands back V8\'s gc, and the same one again', '');
  log.debug("Leaving checkObtained().");
}

function checkFlagCleared(t) {
  log.debug("Entering checkFlagCleared().");
  t.log.info('=== B. the flag is cleared again ===');
  t.check(typeof global.gc !== 'function',
          'no global gc in this context', typeof global.gc);
  t.check(vm.runInNewContext('typeof gc') === 'undefined',
          'and none in a context made after it was obtained',
          vm.runInNewContext('typeof gc'));
  log.debug("Leaving checkFlagCleared().");
}

function checkCollect(t) {
  log.debug("Entering checkCollect().");
  t.log.info('=== C. a collection reports the heap before and after ===');
  makeGarbage(300000);
  const c = HeapCollector.collect(log);
  t.check(wellFormed(c), 'ok, the four heap figures, the pause, and ' +
          'freedBytes the difference of the used figures', JSON.stringify(c));
  t.check(c.freedBytes > MIB,
          'it freed the garbage made for it (over a MiB)',
          (c.freedBytes / MIB).toFixed(1) + ' MiB');
  log.debug("Leaving checkCollect().");
}

// The worker's program: garbage, a collection, the answer posted back.
const WORKER = [
  "'use strict';",
  "const wt = require('worker_threads');",
  "const HeapCollector = require(wt.workerData.module);",
  "const quiet = { debug: function () {} };",
  "let junk = [];",
  "for (let i = 0; i < 300000; i++) { junk.push({ i: i, t: 'g' + i }); }",
  "junk = null;",
  "const before = typeof globalThis.gc;",
  "wt.parentPort.postMessage({ threadId: wt.threadId, globalGc: before,",
  "  collection: HeapCollector.collect(quiet) });",
  ""
].join('\n');

function inAWorker() {
  log.debug("Entering inAWorker().");
  log.debug("Leaving inAWorker().");
  return new Promise(function (resolve, reject) {
    const w = new Worker(WORKER, { eval: true, workerData: {
      module: path.join(__dirname, '..', 'common', 'heap_collector') } });
    w.once('message', function (m) {
      resolve(m);
      w.terminate();
    });
    w.once('error', reject);
  });
}

async function checkWorker(t) {
  log.debug("Entering checkWorker().");
  t.log.info('=== D. a worker thread collects its own isolate ===');
  const m = await inAWorker();
  const c = m.collection;
  t.check(m.threadId > 0 && m.globalGc === 'undefined',
          'a worker thread started after gc was obtained here has no ' +
          'global gc', JSON.stringify({ threadId: m.threadId,
                                         globalGc: m.globalGc }));
  t.check(wellFormed(c) && c.freedBytes > MIB,
          'and collects its own heap, reporting it and what it freed',
          JSON.stringify(c));
  log.debug("Leaving checkWorker().");
}

async function run(t) {
  log.debug("Entering run().");
  checkObtained(t);
  checkFlagCleared(t);
  checkCollect(t);
  await checkWorker(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'heap_collector',
  describe: 'Monitoring → Node Health\'s garbage collection (#611): gc ' +
            'obtained without --expose-gc and the flag cleared again, a ' +
            'collection reporting the heap before and after and its pause, ' +
            'in this thread and in a worker thread',
  run: run
};
