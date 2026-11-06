// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/spiffe_join_token_ttl.js
//
// ---------------------------------------------------------------------------
// FUZZ REGRESSION (#1346): the SPIFFE join-token action bounds its `ttl` so
// the expiry it formats cannot overflow a Date.
//
// `admin-core/admin_actions.ts` spiffeAgentsAction()'s `join-token` arm built
// an ISO expiry from `nowSec() + ttl`, and a huge-but-finite `ttl` such as
// 1e308 overflowed the representable Date range -- `new Date(...).toISOString()`
// threw RangeError, which the fault boundary turned into an uncaught 500 at
// /admin-api. The Schemathesis gate (#1299) found it. `ttl` is now refused
// (STS-ADMIN-0858) unless it is a whole positive number within the range a
// Date can hold, MEASURED FROM NOW -- 8.64e12 seconds alone still overflows
// once `now` is added to it, so 8640000000000 is itself refused.
//
// IN PROCESS, and asserting only the REFUSED cases: a refused `ttl` returns at
// the validation before the action loads `spiffe/spiffe_api`, so this needs no
// SPIFFE store, no realm and no minting. The regression is that an overflowing
// `ttl` is REFUSED, not THROWN (which was the 500) -- the call returning at all
// is the proof it did not throw.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

require('../ldap/ldap_server');
const adminActions = require('../admin-core/admin_actions');
require('../common/app');
const errorCodes = require('../common/error_codes');

const log = require('bunyan').createLogger({
  name: 'spiffe_join_token_ttl',
  level: process.env.LOG_LEVEL || 'info' });

function joinToken(ttl) {
  log.debug("Entering joinToken(). ttl=" + String(ttl));
  let result = null;
  let threw = false;
  try {
    result = adminActions.spiffeAgentsAction(
      { action: 'join-token', ttl: ttl },
      { via: 'api', actor: 'regression' });
  } catch (e) {
    threw = true;
    log.debug("Caught in joinToken(): " + ((e && e.message) || e));
  }
  log.debug("Leaving joinToken(). threw=" + threw);
  return { result: result, threw: threw };
}

function run(t) {
  log.debug("Entering run().");

  // 1e308 is finite and positive but is not a safe integer, and would make
  // `new Date((now + 1e308) * 1000)` an Invalid Date. Before the fix this was
  // the RangeError the fault boundary turned into a 500.
  const huge = joinToken(1e308);
  t.check(!huge.threw && huge.result && huge.result.ok === false &&
          errorCodes.codeOf(huge.result) === 'STS-ADMIN-0858',
          '1. a ttl of 1e308 is refused (STS-ADMIN-0858), not thrown (no 500)',
          huge.threw ? 'THREW' : JSON.stringify(huge.result));

  // The maximum ECMAScript date is 8.64e12 seconds past the epoch, so the
  // upper bound is measured from now; 8.64e12 alone still overflows once now
  // is added, so it is refused. (This is the case iya-sts-60's correction to
  // #1346 added: the first bound compared ttl against 8.64e12 directly.)
  const atLimit = joinToken(8640000000000);
  t.check(!atLimit.threw && atLimit.result && atLimit.result.ok === false &&
          errorCodes.codeOf(atLimit.result) === 'STS-ADMIN-0858',
          '2. a ttl of exactly 8640000000000 is refused (the bound is ' +
          'measured from now), not thrown',
          atLimit.threw ? 'THREW' : JSON.stringify(atLimit.result));

  // The pre-existing refusals still hold and still carry the same code: a
  // non-numeric ttl (Number is NaN) and a non-positive one.
  const notNumeric = joinToken('abc');
  t.check(!notNumeric.threw && notNumeric.result &&
          notNumeric.result.ok === false &&
          errorCodes.codeOf(notNumeric.result) === 'STS-ADMIN-0858',
          '3. a non-numeric ttl is refused (STS-ADMIN-0858), not thrown',
          notNumeric.threw ? 'THREW' : JSON.stringify(notNumeric.result));

  const zero = joinToken(0);
  t.check(!zero.threw && zero.result && zero.result.ok === false &&
          errorCodes.codeOf(zero.result) === 'STS-ADMIN-0858',
          '4. a ttl of 0 is refused (STS-ADMIN-0858), not thrown',
          zero.threw ? 'THREW' : JSON.stringify(zero.result));

  log.debug("Leaving run().");
}

module.exports = {
  name: 'spiffe_join_token_ttl',
  describe: 'FUZZ REGRESSION (#1346): the SPIFFE join-token action refuses a ' +
            'ttl that would overflow a Date (1e308, and 8640000000000 since ' +
            'the bound is measured from now) rather than throwing an ' +
            'uncaught 500',
  run: run
};
