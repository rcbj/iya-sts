'use strict';
//
// File: rate_limiter.js
//
// ===========================================================================
// THE RATE LIMITER, WHICH NOTHING TESTED UNTIL 2026-09-06.
//
// `websecurity.attempt()` guarded three doors when this file was written — a
// sign-in, an activation link and a password change — and its whole job is to
// say NO. Nothing in either suite ever asserted that it does. The doors now
// reach it through `attemptShared()` (which is `attempt()` when no cluster
// store shares the windows), and there are many more of them: second-factor
// codes, password resets, LDAP binds, the enrollment protocols and others.
//
// **IT WAS BEING EXERCISED BY ACCIDENT AND THAT IS WHY THIS FILE EXISTS NOW.**
// The shipped limit is 20 attempts per address per 60s, every job in the suite
// comes from ONE address, and `sts_portal_sessions.js` and
// `sts_admin_console.js` each issue and open several activation links — so the
// suite tripped the limiter and failed with a 429 on a link the console had
// just handed over. That reads exactly like a broken handler and is not one.
//
// The fix is a raised limit in the three appconfig files the test stacks read
// (`env/local.js`, `env/test.js`, `env/docker-tests.js` — 500 per address,
// against a measured peak of 25). **Which turns the accidental coverage OFF.**
// A control that fires in no test and is configured never to fire is a control
// nobody would notice the removal of, so it gets a real test instead of an
// accidental one, and that is this file.
//
// WHY IN PROCESS. Every assertion here is about a counter: how many attempts it
// takes to be refused, which BUCKET refused, that the window expires, that a
// success clears it. Over HTTP each of those is minutes of waiting on a
// 60-second window, and the two buckets cannot be told apart from outside — the
// refusal deliberately names only one. `attempt()` takes its limit as an
// argument and `reset()` clears the table, so all of it is a function call.
//
// It is also the one file here that must NOT be affected by the appconfig
// change above: every limit below is passed EXPLICITLY, so a run under any
// configuration asserts the same thing.
// ===========================================================================

// Deleted rather than set, for the reason config_realm_layer.js gives.
delete process.env.CONFIG_FILE;

const websecurity = require('../common/websecurity');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'rate_limiter',
  level: process.env.LOG_LEVEL || 'info' });

// A stand-in for the `req` the limiter reads an address off. Through
// `common/client_address.js` it looks at `req.socket.remoteAddress` (and, with
// `global.trustProxy`, at `x-forwarded-for`), so this is the whole of what it
// needs.
function from(address) {
  log.debug("Entering from().");
  log.debug("Leaving from().");
  return { headers: {}, socket: { remoteAddress: address } };
}

// ---------------------------------------------------------------------------
// 1. IT REFUSES THE ATTEMPT AFTER THE LIMIT, AND NOT THE ONE ON IT.
//
// Off-by-one is the failure this whole control has: a limiter that refuses the
// Nth attempt when it was configured to allow N is a service that locks people
// out one try early, and nobody reports it as a bug — they try again.
// ---------------------------------------------------------------------------
function checkTheBoundary(t) {
  log.debug("Entering checkTheBoundary().");
  t.log.info('where the limit falls');
  websecurity.reset();

  const req = from('198.51.100.1');
  let refusedAt = 0;
  for (let n = 1; n <= 6; n += 1) {
    const answer = websecurity.attempt('rl-boundary', req, '', 3);
    if (!answer.ok && !refusedAt) {
      refusedAt = n;
    }
  }
  t.equal(refusedAt, 4,
          'with a limit of 3, the FOURTH attempt is the first refused — ' +
          'three are allowed, which is what "3 per window" means');

  const answer = websecurity.attempt('rl-boundary', req, '', 3);
  t.equal(answer.ok, false, 'and it stays refused');
  t.equal(answer.kind, 'address',
          'the refusal says WHICH bucket stopped it, so a message can be ' +
          'honest without naming the other one');
  t.check(Number(answer.retryAfterS) > 0 && Number(answer.retryAfterS) <= 60,
          'and how long to wait, within the window',
          String(answer.retryAfterS) + 's');
  log.debug("Leaving checkTheBoundary().");
}

// ---------------------------------------------------------------------------
// 2. THE TWO BUCKETS ARE SEPARATE, AND THE IDENTITY ONE IS THE POINT.
//
// This is the distinction the suite's own 429s were about: one ADDRESS making
// many attempts for many identities is a test runner, and one IDENTITY being
// attempted many times is credential guessing. A limiter that could not tell
// them apart would have to be set for the worse case and would then be useless
// for the other.
// ---------------------------------------------------------------------------
function checkTheTwoBuckets(t) {
  log.debug("Entering checkTheTwoBuckets().");
  t.log.info('the address bucket and the identity bucket');
  websecurity.reset();

  // ONE IDENTITY, MANY ADDRESSES. The identity bucket fills; the address ones
  // never do, because each is its own key.
  let refusal = null;
  for (let n = 1; n <= 5; n += 1) {
    const answer = websecurity.attempt('rl-buckets', from('203.0.113.' + n),
                                       'victim', 3);
    if (!answer.ok && !refusal) {
      refusal = answer;
    }
  }
  t.check(!!refusal, 'one identity attempted from five addresses is refused');
  t.equal(refusal && refusal.kind, 'identity',
          'BY THE IDENTITY BUCKET — which is the case this control exists ' +
          'for, and the one a per-address limit alone cannot see');

  // AND THE OTHER WAY ROUND. Many identities from one address: the identity
  // buckets stay empty and the address bucket is what fills.
  websecurity.reset();
  refusal = null;
  const req = from('203.0.113.200');
  for (let n = 1; n <= 5; n += 1) {
    const answer = websecurity.attempt('rl-buckets', req, 'person-' + n, 3);
    if (!answer.ok && !refusal) {
      refusal = answer;
    }
  }
  t.check(!!refusal, 'five identities attempted from one address is refused');
  t.equal(refusal && refusal.kind, 'address',
          'BY THE ADDRESS BUCKET — and this is the one the test suite fills, ' +
          'because every job in it comes from the runner');

  // AN ATTEMPT WITH NO IDENTITY IS STILL COUNTED, by address. A door reached
  // without a username — a malformed probe, an activation link with no user —
  // must not be a free pass.
  websecurity.reset();
  refusal = null;
  for (let n = 1; n <= 5; n += 1) {
    const answer = websecurity.attempt('rl-anon', req, '', 3);
    if (!answer.ok && !refusal) {
      refusal = answer;
    }
  }
  t.equal(refusal && refusal.kind, 'address',
          'an attempt naming nobody is counted by address rather than waved ' +
          'through');
  log.debug("Leaving checkTheTwoBuckets().");
}

// ---------------------------------------------------------------------------
// 3. THE BUCKETS ARE PER ACTION.
//
// The key is `what + '|' + kind + '|' + who`, so exhausting the sign-in
// allowance must not lock the activation door. Worth pinning because the
// obvious simplification — one bucket per caller — would make any one noisy
// endpoint close every other, which on this service means a test that hammers
// `/authn/login` would break `/portal/activate` for a minute.
// ---------------------------------------------------------------------------
function checkPerAction(t) {
  log.debug("Entering checkPerAction().");
  t.log.info('one bucket per action');
  websecurity.reset();

  const req = from('192.0.2.7');
  for (let n = 1; n <= 5; n += 1) {
    websecurity.attempt('rl-one', req, 'alice', 3);
  }
  t.equal(websecurity.attempt('rl-one', req, 'alice', 3).ok, false,
          'the first action is exhausted');
  t.equal(websecurity.attempt('rl-two', req, 'alice', 3).ok, true,
          'and a DIFFERENT action from the same address, for the same ' +
          'person, is untouched');
  log.debug("Leaving checkPerAction().");
}

// ---------------------------------------------------------------------------
// 4. A SUCCESS CLEARS IT, AND CLEARS BOTH.
//
// `succeeded()` is what a sign-in that WORKED calls, so somebody who mistyped
// their password four times is not still one attempt from being locked out.
// **It clears the address bucket too**, which is why `sign-in` never
// accumulated in the measurement that led to this file while `activation` —
// which has no such call — did.
// ---------------------------------------------------------------------------
function checkSuccessClears(t) {
  log.debug("Entering checkSuccessClears().");
  t.log.info('what a success forgets');
  websecurity.reset();

  const req = from('192.0.2.55');
  for (let n = 1; n <= 3; n += 1) {
    websecurity.attempt('rl-success', req, 'bob', 3);
  }
  t.equal(websecurity.attempt('rl-success', req, 'bob', 3).ok, false,
          'three attempts and the fourth is refused');

  websecurity.succeeded('rl-success', req, 'bob');
  t.equal(websecurity.attempt('rl-success', req, 'bob', 3).ok, true,
          'a success forgets the counters and the next attempt is allowed');

  // BOTH buckets, asserted separately: clearing only the identity one would
  // leave the address bucket full, so the person who just signed in could not
  // do it again from the same machine.
  websecurity.reset();
  for (let n = 1; n <= 3; n += 1) {
    websecurity.attempt('rl-success2', req, 'person-' + n, 3);
  }
  websecurity.succeeded('rl-success2', req, 'person-1');
  t.equal(websecurity.attempt('rl-success2', req, 'person-9', 3).ok, true,
          'and it clears the ADDRESS bucket as well as the identity one');
  log.debug("Leaving checkSuccessClears().");
}

// ---------------------------------------------------------------------------
// 5. THE WINDOW EXPIRES.
//
// A limiter that never forgets is a permanent lockout, which is the failure
// nobody notices until somebody is locked out. Driven with a one-second window
// so the assertion costs a second rather than a minute — the window is read
// from configuration on every call, so this is the real code path.
// ---------------------------------------------------------------------------
function checkTheWindowExpires(t) {
  log.debug("Entering checkTheWindowExpires().");
  t.log.info('the window expires');
  const config = require('../common/config');
  websecurity.reset();

  // `setOverride`/`clearOverride` and not a `set()`: an override is the layer
  // the console and `/admin-api/config/set` write, and `clearOverride()` is
  // how tests/CLAUDE.md says to put a setting back — by RESETTING it rather
  // than by writing the old value back, so a run leaves the setting sourced
  // where it found it rather than pinned to a value that happens to match.
  const set = config.setOverride('security.rateLimitWindowS', 1);
  if (!set || set.ok === false) {
    t.bad('could not narrow the rate-limit window to 1s',
          JSON.stringify(set));
    log.debug("Leaving checkTheWindowExpires().");
    return;
  }
  try {
    const req = from('192.0.2.99');
    for (let n = 1; n <= 3; n += 1) {
      websecurity.attempt('rl-window', req, '', 2);
    }
    t.equal(websecurity.attempt('rl-window', req, '', 2).ok, false,
            'refused inside the window');

    const deadline = Date.now() + 1500;
    while (Date.now() < deadline) {
      // A BUSY WAIT AND NOT A TIMER, because this harness runs a test as a
      // plain synchronous function — there is no `await` to hand control back
      // to. One and a half seconds once, in a suite that runs in under two.
    }
    t.equal(websecurity.attempt('rl-window', req, '', 2).ok, true,
            'and allowed again once the window has passed — a limiter that ' +
            'never forgets is a permanent lockout');
  } finally {
    config.clearOverride('security.rateLimitWindowS');
    websecurity.reset();
  }
  log.debug("Leaving checkTheWindowExpires().");
}

// ---------------------------------------------------------------------------
// 6. THE SETTINGS ARE WHAT IT READS WHEN NOBODY PASSES A LIMIT.
//
// Every assertion above passes its own limit, which is what makes them
// independent of configuration. This one is the opposite and is the reason the
// appconfig change that led to this file is SAFE: the limiter reads
// `security.rateLimitPerAddress` and `security.rateLimitPerIdentity` live, so
// a stack that raises them raises what the doors enforce, and nothing is
// compiled in.
// ---------------------------------------------------------------------------
function checkItReadsTheSettings(t) {
  log.debug("Entering checkItReadsTheSettings().");
  t.log.info('it reads the settings');
  const config = require('../common/config');
  websecurity.reset();

  config.setOverride('security.rateLimitPerAddress', 2);
  try {
    const req = from('192.0.2.123');
    t.equal(websecurity.attempt('rl-config', req, '').ok, true, 'one');
    t.equal(websecurity.attempt('rl-config', req, '').ok, true, 'two');
    t.equal(websecurity.attempt('rl-config', req, '').ok, false,
            'and the third is refused, from the SETTING rather than from an ' +
            'argument — which is what lets an appconfig file raise it for a ' +
            'test stack without touching the shipped default');
    const report = websecurity.report();
    t.equal(report.rateLimit.perAddress, 2,
            'and the report says the effective value rather than the default');
  } finally {
    config.clearOverride('security.rateLimitPerAddress');
    websecurity.reset();
  }
  log.debug("Leaving checkItReadsTheSettings().");
}

function run(t) {
  log.debug("Entering run().");
  checkTheBoundary(t);
  checkTheTwoBuckets(t);
  checkPerAction(t);
  checkSuccessClears(t);
  checkTheWindowExpires(t);
  checkItReadsTheSettings(t);
  websecurity.reset();
  log.debug("Leaving run().");
}

module.exports = {
  name: 'rate_limiter',
  describe: 'websecurity.attempt(): where the limit falls, which bucket ' +
            'refused, that a success clears it and that the window expires',
  run: run
};
