// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: sync_query_kit.js
//
// ===========================================================================
// A STAND-IN FOR THE DATABASE BEHIND `common/sync_query.ts` (#349 phase 3),
// loaded INSIDE the bridge's worker thread in place of `pg` by
// `tests/sync_query.js`. Not a test (`run.js`'s NOT_A_TEST names it).
//
//   echo(value)       answers the value
//   slow(ms, value)   answers after `ms`
//   fail(message)     rejects as a database error would
//   crash()           ends the thread, as a thread that died would
//
// Runs in a worker thread, with no logger (the thread's own exemption:
// `common/sync_query_thread.ts`'s header).
// ===========================================================================

function run(name, args) {
  if (name === 'echo') {
    return Promise.resolve(args[0]);
  }
  if (name === 'slow') {
    return new Promise(function (resolve) {
      setTimeout(function () {
        resolve(args[1]);
      }, Number(args[0]) || 0);
    });
  }
  if (name === 'fail') {
    const err = new Error(String(args[0]));
    err.code = '42P01';
    return Promise.reject(err);
  }
  if (name === 'crash') {
    // In a worker thread this ends the thread, not the process.
    process.exit(3);
  }
  return Promise.reject(new Error('the kit knows no ' + name));
}

module.exports = { run: run };
