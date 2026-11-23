// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: common/crypto_impl/pkcs11_thread.js
//
// ---------------------------------------------------------------------------
// A PKCS#11 MODULE'S CONTROL THREAD (#1955 P8 follow-up, 2026-11-23; rcbj:
// "I do not want this activity to block the main event loop").
//
// `pkcs11.js`'s `Pkcs11Control` starts this in a `worker_thread`, one per
// loaded module per thread that loaded it, to make the PKCS#11 calls the
// binding has no asynchronous form for — C_OpenSession and C_Login,
// C_FindObjects*, C_GetAttributeValue, every C_*Init, the key wrap's session
// object, C_Finalize and C_Initialize — so the thread that serves requests
// never waits on them. `pkcs11.js` argues why a thread (its *THE CALLS
// PKCS11JS HAS NO ASYNCHRONOUS FORM FOR*).
//
// It loads the binding again from the file the other side loaded it from
// (a binding object cannot cross a thread) and the module by its path;
// C_Initialize answers CKR_CRYPTOKI_ALREADY_INITIALIZED, which is expected
// (it is process-wide). Sessions and object handles are the process's, so
// a session opened here is used there. Each message is `{ id, op, args }`
// and answered `{ id, value }` or `{ id, error }`, where `op` names one of
// `pkcs11.js`'s `CONTROL_OPS` — the same functions it runs in place, so the
// two cannot disagree. Calls are answered in the order they came, one at a
// time. Every failure, including a binding that will not load, is an
// answer, never an exception out of the thread.
// ---------------------------------------------------------------------------

'use strict';

const workerThreads = require('worker_threads');
const engine = require('./pkcs11');

// A thread with no CONFIG_FILE (a test's) logs at info rather than failing
// to start.
let logLevelProblem = null;
const log = require('bunyan').createLogger({
  name: 'pkcs11_thread',
  level: (function () {
    try {
      return require(String(process.env.CONFIG_FILE)).logLevel || 'info';
    } catch (e) {
      // No logger exists yet; reported on the line after it does.
      logLevelProblem = (e && e.message) || String(e);
      return 'info';
    }
  })()
});
if (logLevelProblem) {
  log.debug('Caught in pkcs11_thread log level: ' + logLevelProblem);
}

const data = /** @type {any} */ (workerThreads.workerData) || {};
const port = workerThreads.parentPort;

// The module, loaded at the first call. A failure to load is answered to
// every call, so the other side refuses with the module's own words.
let lib = null;

function loaded() {
  log.debug('Entering loaded().');
  if (lib) {
    log.debug('Leaving loaded(). Held.');
    return lib;
  }
  const binding = require(String(data.bindingPath));
  const made = new binding.PKCS11();
  made.load(String(data.modulePath));
  engine.CONTROL_OPS.reinitialize(made, false);
  lib = made;
  log.debug('Leaving loaded(). Loaded.');
  return lib;
}

function answer(m) {
  log.debug('Entering answer(). ' + (m && m.op));
  const id = m && m.id;
  try {
    const op = engine.CONTROL_OPS[String(m.op)];
    if (typeof op !== 'function') {
      // error-code: none — a programming error: the other side names only
      // the calls `CONTROL_OPS` holds.
      throw new Error('pkcs11_thread: no call named "' + m.op + '"');
    }
    const args = engine.revive(Array.isArray(m.args) ? m.args : []);
    const value = op.apply(null, [loaded()].concat(args));
    port.postMessage({ id: id, value: value });
  } catch (e) {
    log.debug('Caught in answer(): ' + ((e && e.message) || e));
    port.postMessage({ id: id, error: engine.errorFields(e) });
  }
  log.debug('Leaving answer().');
}

if (port) {
  port.on('message', answer);
}
