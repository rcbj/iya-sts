'use strict';
//
// File: worker_pool.js
//
// ===========================================================================
// THE POOL: THAT IT COMPUTES THE SAME BYTES, AND THAT IT LEAVES THE THREAD.
//
// Every protocol job in the parent project already proves that this service
// issues tokens a client can verify, and it proved that before common/worker.js
// existed. What none of them can see is the property the pool was built for,
// because it is not on the wire: WHETHER THIS PROCESS WAS ABLE TO ANSWER
// ANYBODY WHILE IT SIGNED. A token signed on the main thread and a token signed
// in a worker are the same bytes; the difference is that during the first one
// the KDC on port 88, the LDAP directory and every HTTP listener were dead for
// fourteen seconds and nothing anywhere said so.
//
// So this drives the modules in process and measures the thing:
//
//   * the signature a worker produces is BYTE-IDENTICAL to the one this
//     process produces, for a post-quantum algorithm and for a traditional
//     one — the pool must be an optimisation and never a difference;
//   * the EVENT LOOP KEEPS TICKING while a worker signs, which is the whole
//     claim and the only one that would have been false before;
//   * a session always routes to the same worker, and different sessions
//     spread across them;
//   * a worker that DIES is replaced, and the job it was holding fails rather
//     than hanging for ever — a promise nobody settles is worse than an error;
//   * `workers.count: 0` computes here, which is the documented way back and
//     the fallback every entry point takes when there is no pool.
//
// AND ONE SOURCE-INSPECTION CHECK, which is here because it caught a real bug
// in the commit that added it. Converting the ID Token path to async meant
// awaiting every call to `issue()` in oauth-oidc/oauth2.js, and two of them —
// `const issued = issue({` — were missed. An un-awaited promise does not throw:
// it is serialised into the token response as `{}`, and what the suite reported
// was "the access token should be a three-part JWS. Got: undefined", three
// steps from the cause. A regex over the FILE is the only thing that sees that
// class of mistake, because the code runs perfectly.
// ===========================================================================

const fs = require('fs');
const path = require('path');
const { createHarness } = require('./harness');

const ROOT = path.join(__dirname, '..');

// The names that MUST be awaited wherever they are called in oauth2.js,
// because each of them is async now. `issue` is the closure the grants mint
// through; the others are the chain behind it.
const MUST_AWAIT = ['issue', 'tokenSet', 'idToken', 'signUserinfo',
                    'protectUserinfo', 'issueAuthorizationResponse'];

// The one call that is deliberately NOT awaited: the `issue` closure returns
// tokenSet()'s promise for its callers to await, which is correct and is the
// only line of its kind.
const ALLOWED_BARE = 'return tokenSet(base, Object.assign({ request: req },' +
                    ' opts));'

function everyAsyncCallIsAwaited(t) {
  const file = path.join(ROOT, 'oauth-oidc', 'oauth2.js');
  const lines = fs.readFileSync(file, 'utf8').split('\n');
  const missed = [];
  lines.forEach(function (line, i) {
    // Comments AND string literals go first. Every one of these functions logs
    // its own name on the way in and out — `log.debug("Entering idToken().")`
    // — and a check that reads those finds a "call" on almost every line of
    // the file, which is a check that has to be switched off rather than read.
    const code = line
      .replace(/\/\/.*$/, '')
      .replace(/'(\\.|[^'\\])*'/g, "''")
      .replace(/"(\\.|[^"\\])*"/g, '""')
      .replace(/`(\\.|[^`\\])*`/g, '``');
    if (!code.trim() || line.indexOf(ALLOWED_BARE) !== -1) {
      return;
    }
    MUST_AWAIT.forEach(function (name) {
      // A CALL to it: the name, then `(`, not preceded by a word character or
      // a dot (which would be some other function whose name ends in this
      // one) and not part of its own declaration.
      const call = new RegExp('(^|[^\\w.])' + name + '\\s*\\(');
      if (!call.test(code)) {
        return;
      }
      if (/^\s*(async\s+)?function\s/.test(code) ||
          new RegExp('const\\s+' + name + '\\s*=').test(code)) {
        return;   // the declaration, not a call
      }
      if (/\bawait\s/.test(code)) {
        return;
      }
      missed.push((i + 1) + ': ' + code.trim().slice(0, 90));
    });
  });
  t.check(missed.length === 0,
    'every call to an async issuer in oauth2.js is awaited',
    missed.length ? missed.join(' | ')
      : MUST_AWAIT.length + ' name(s) checked, all awaited');
}

async function run(t) {
  process.env.CONFIG_FILE = process.env.CONFIG_FILE ||
    path.join(ROOT, 'env', 'defaults.js');
  const pq = require('../common/pq_jose');
  const wp = require('../common/worker_pool');
  const stsCrypto = require('../common/crypto');

  everyAsyncCallIsAwaited(t);

  wp.start();
  // The children are forked, not yet up. Nothing below depends on the timing —
  // a job submitted before a worker is ready is queued by the channel — but
  // the affinity checks read the live list, so they wait for it.
  await new Promise(function (r) { setTimeout(r, 700); });
  t.check(wp.available(), 'the pool is up',
    'workers.count resolved to ' + wp.resolveCount());

  // --- the same bytes ------------------------------------------------------
  // ML-DSA-44 rather than an SLH-DSA set: it is the fastest post-quantum
  // algorithm here and this assertion is about equality, not about time. The
  // slow one is measured once, below, where slowness is the point.
  const alg = 'ML-DSA-44';
  const pair = pq.generate(alg);
  const message = Buffer.from('the same bytes either way');
  const here = pq.sign(alg, pair.priv, message);
  const there = await pq.signAsync(alg, pair.priv, message);
  t.check(Buffer.compare(here, there) === 0,
    'a worker signs the same bytes this process does',
    alg + ', ' + here.length + ' bytes');
  t.check(await pq.verifyAsync(alg, pair.pub, message, here),
    'a worker verifies what this process signed');
  t.check(pq.verify(alg, pair.pub, message, there),
    'this process verifies what a worker signed');

  // A traditional algorithm must not go near a worker, and must still work.
  const rsa = require('crypto').generateKeyPairSync('rsa',
    { modulusLength: 2048 });
  const signed = await stsCrypto.signJwsAsync({ sub: 'probe' },
    rsa.privateKey, { algorithm: 'RS256' });
  t.check(String(signed).split('.').length === 3,
    'signJwsAsync() still produces a three-part JWS for a traditional alg',
    'RS256');

  // --- the whole point -----------------------------------------------------
  // SLH-DSA-SHAKE-128s, because it is the one that costs seconds. A 10ms timer
  // should fire about once per 10ms of wall clock IF the loop is free; if the
  // signature ran here it would fire once, at the end.
  const slow = 'SLH-DSA-SHAKE-128s';
  const slowPair = pq.generate(slow);
  let ticks = 0;
  const timer = setInterval(function () { ticks++; }, 10);
  const startedAt = Date.now();
  await pq.signAsync(slow, slowPair.priv, Buffer.from('off the main thread'));
  const took = Date.now() - startedAt;
  clearInterval(timer);
  const expected = Math.floor(took / 10);
  // Half of them is a wide margin on purpose: this asserts that the loop RAN,
  // not that a timer is accurate, and a loaded machine is the ordinary case.
  t.check(ticks > expected / 2,
    'the event loop keeps running while a worker signs',
    'a ' + took + 'ms ' + slow + ' signature, ' + ticks + ' tick(s) of a ' +
    '10ms timer (free gives about ' + expected + '; blocked gives 1)');

  // --- routing -------------------------------------------------------------
  const slots = new Set();
  for (let i = 0; i < 8; i++) {
    slots.add(wp.pool.pick('one-session').slot);
  }
  t.equal(slots.size, 1, 'one session always routes to one worker');

  if (wp.resolveCount() > 1) {
    const spread = new Set();
    ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'].forEach(function (s) {
      spread.add(wp.pool.pick(s).slot);
    });
    t.check(spread.size > 1, 'different sessions spread across the workers',
      spread.size + ' of ' + wp.resolveCount() + ' worker(s) for 8 sessions');
  }

  // --- a worker that dies --------------------------------------------------
  // Killed from under a job. What must NOT happen is a promise nobody settles:
  // the caller falls back and signs here, which is slow and correct.
  const victim = wp.pool.pick(null);
  const before = victim.child.pid;
  const inFlight = pq.signAsync(alg, pair.priv, Buffer.from('interrupted'));
  victim.child.kill('SIGKILL');
  const after = await inFlight;
  t.check(Buffer.isBuffer(after) && after.length > 0,
    'a job whose worker is killed still answers',
    'it fell back to this process rather than hanging');
  await new Promise(function (r) { setTimeout(r, 500); });
  const live = wp.pool.workers.filter(Boolean).length;
  t.equal(live, wp.resolveCount(), 'a worker that dies is replaced');
  t.check(wp.pool.workers.filter(Boolean)
    .every(function (e) { return e.child.pid !== before; }),
    'the replacement is a new process',
    'pid ' + before + ' was killed and is gone from the pool');

  wp.stop();
  t.check(!wp.available(), 'stop() takes the pool down');

  // --- and with no pool at all ---------------------------------------------
  const fallback = await pq.signAsync(alg, pair.priv, message);
  t.check(Buffer.compare(fallback, here) === 0,
    'with the pool stopped the same bytes are computed in this process',
    'which is what workers.count: 0 selects');
}

module.exports = {
  name: 'worker_pool',
  describe: 'that the worker pool computes identical bytes, leaves the event ' +
            'loop free, routes a session to one worker, survives a worker ' +
            'dying, and falls back to this process when there is none',
  run: run
};
