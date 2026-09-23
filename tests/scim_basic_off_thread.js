'use strict';
//
// File: tests/scim_basic_off_thread.js
//
// ===========================================================================
// A SCIM BASIC PASSWORD IS HASHED IN THE WORKER POOL, NOT ON THE REQUEST
// THREAD (2026-09-21).
//
// `scim/scim_auth.ts`'s `attemptBasic()` is synchronous, so in product mode
// it verified the password with `credentials.verify()` — scrypt, about 70ms at
// the default cost — on the thread that answers every other request the
// worker holds. `authenticateSpent()`, the path `scim.ts` takes, now asks
// `credentials.verifyAsync()` first and leaves the verdict on the request for
// `attemptBasic()`.
//
// In process, with the two verifiers on the credentials module replaced by
// counters for the file and put back in a `finally`: which verifier ran is
// exactly what no request can observe — over HTTP both give the same answer,
// and the difference is only where the CPU was spent.
//
//   1. the asynchronous path verifies once, in the pool, and never on the
//      thread; the decision is the pool's verdict, accepted and refused;
//   2. the synchronous `authenticate()` still verifies on the thread;
//   3. a verdict reached for one password is not used for another;
//   4. with the Basic scheme turned off nothing is verified at all;
//   5. a pool that fails leaves no verdict, and the thread verifies as before.
// ===========================================================================

delete process.env.CONFIG_FILE;

const log = require('bunyan').createLogger({ name: 'scim_basic_off_thread',
  level: process.env.LOG_LEVEL || 'info' });

const credentials = require('../common/credentials');
const config = require('../common/config');
const scimAuth = require('../scim/scim_auth');

function basicRequest(username, password) {
  log.debug("Entering basicRequest().");
  const token = Buffer.from(username + ':' + password).toString('base64');
  log.debug("Leaving basicRequest().");
  return { method: 'GET', originalUrl: '/scim/v2/Users', url: '/scim/v2/Users',
           socket: { remoteAddress: '192.0.2.41' },
           headers: { authorization: 'Basic ' + token } };
}

async function run(t) {
  log.debug("Entering run().");
  const realVerify = credentials.verify;
  const realAsync = credentials.verifyAsync;
  const calls = { sync: [], pool: [] };
  let poolAnswer = { ok: true, reason: 'verified' };
  let poolFails = false;
  credentials.verify = function (username, password) {
    calls.sync.push(username + ':' + password);
    return { ok: password === 'right', reason: password === 'right'
      ? 'verified' : 'wrong-password' };
  };
  credentials.verifyAsync = function (username, password) {
    calls.pool.push(username + ':' + password);
    return poolFails ? Promise.reject(new Error('the pool is down'))
                     : Promise.resolve(poolAnswer);
  };
  const reset = function () {
    calls.sync.length = 0;
    calls.pool.length = 0;
  };
  try {
    // 1. THE ASYNCHRONOUS PATH.
    reset();
    const accepted = await scimAuth.authenticateSpent(
      basicRequest('scim-caller', 'right'), 'read');
    t.check(accepted.ok && accepted.scheme === 'basic',
            'authenticateSpent() accepts a Basic credential the pool verified',
            JSON.stringify({ ok: accepted.ok, scheme: accepted.scheme }));
    t.equal(calls.pool.length, 1, 'and verified it ONCE, in the pool');
    t.equal(calls.sync.length, 0,
            'and NEVER on the request thread — the whole point');
    reset();
    poolAnswer = { ok: false, reason: 'wrong-password' };
    const refused = await scimAuth.authenticateSpent(
      basicRequest('scim-caller', 'right'), 'read');
    t.check(!refused.ok && refused.status === 401,
            'the decision IS the pool\'s verdict: a refusal from the pool ' +
            'refuses, even for a password the thread would have accepted',
            JSON.stringify({ ok: refused.ok, status: refused.status }));
    t.equal(calls.sync.length, 0, 'still without a verification on the thread');
    poolAnswer = { ok: true, reason: 'verified' };

    // 2. THE SYNCHRONOUS PATH IS UNCHANGED.
    reset();
    const syncOk = scimAuth.authenticate(basicRequest('scim-caller', 'right'),
                                         'read');
    t.check(syncOk.ok, 'authenticate() still accepts on its own');
    t.check(calls.sync.length === 1 && calls.pool.length === 0,
            'by verifying on the thread, because its callers read the ' +
            'decision in one tick', JSON.stringify(calls));

    // 3. A VERDICT IS FOR THE CREDENTIAL IT WAS REACHED FOR.
    reset();
    const req = basicRequest('scim-caller', 'right');
    await scimAuth.authenticateSpent(req, 'read');
    req.headers.authorization = 'Basic ' +
      Buffer.from('scim-caller:wrong').toString('base64');
    const swapped = scimAuth.authenticate(req, 'read');
    t.check(!swapped.ok,
            'a request whose password changed after the pool\'s verdict is ' +
            'NOT accepted on that verdict');
    t.check(calls.sync.indexOf('scim-caller:wrong') >= 0,
            'it is verified afresh, for the password it now carries',
            JSON.stringify(calls));

    // 4. A DISABLED SCHEME VERIFIES NOTHING.
    reset();
    config.setOverride('scim.authBasic', false);
    try {
      await scimAuth.authenticateSpent(basicRequest('scim-caller', 'right'),
                                       'read');
    } finally {
      config.clearOverride('scim.authBasic');
    }
    t.check(calls.pool.length === 0 && calls.sync.length === 0,
            'with scim.authBasic off, no password is verified anywhere — a ' +
            'scheme that is off must cost nothing and record nothing',
            JSON.stringify(calls));

    // 5. A POOL THAT FAILS.
    reset();
    poolFails = true;
    const fallback = await scimAuth.authenticateSpent(
      basicRequest('scim-caller', 'right'), 'read');
    poolFails = false;
    t.check(fallback.ok && calls.sync.length === 1,
            'a pool that fails leaves no verdict, and the thread verifies as ' +
            'it always did', JSON.stringify({ ok: fallback.ok, calls: calls }));
  } finally {
    credentials.verify = realVerify;
    credentials.verifyAsync = realAsync;
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'scim_basic_off_thread',
  describe: 'a SCIM Basic password is verified in the worker pool on the ' +
            'asynchronous path, and only for the credential it was reached for',
  run: run
};
