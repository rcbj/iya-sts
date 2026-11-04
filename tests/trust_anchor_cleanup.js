// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: trust_anchor_cleanup.js
//
// ===========================================================================
// THE CLEANUP OF A JOB'S CLIENT-CERTIFICATE TRUST ANCHORS (#1307, from #695's
// review of #682 and #335; the confirmed-anchor retry, the same ticket).
//
// Every protocol job that posts a suite CA to `POST /admin-api/tls/trust/add`
// removes it when it finishes, through `tests/tools/pep-credential.js`'s
// `settleAnchors()`. Until #1307 a job recorded its anchor only after the add
// answered 2xx, so an add the service APPLIED but answered after send()'s 15s
// timeout was never removed. The fix is in that file, once: `trustRecorded()`
// (and `recordAnchor()` for a job posting through its own door) record the
// anchor BEFORE the post, and `removeAnchor()` counts the service's "holds no
// anchor with the SHA-256 fingerprint" as a remove that is done. This file
// asserts those decisions against a FAKE `send` installed with `useSender()`,
// so no service is needed and every answer a service could give is reachable:
//
//   1. RECORD FIRST. The anchor is in the job's list when the post goes out,
//      and still there when the post times out; recorded once however often;
//      no list is a thrown error, not a silent skip.
//   2. THE REMOVE. It names the anchor by SHA-256 fingerprint at
//      `/admin-api/tls/trust/remove`; the real `tls/tls_server.js` refusal
//      sentence for a fingerprint not held, in a 400, is DONE (`absent`) for
//      an anchor whose add was never confirmed; any other 400, a timeout, or
//      a PEM that is not a certificate is a failure with its reason. For a
//      CONFIRMED anchor (its add answered 2xx: `trustRecorded()`, or a job's
//      own `confirmAnchor()`) "not held" is a cluster node behind: asked
//      again, five tries in all, then a failure saying so — and a node that
//      catches up on the third try is a remove that is done.
//   3. `forgetAnchors()`: one remove per anchor, in order, falsy entries
//      skipped, a failure not stopping the rest, the not-held one not a
//      problem.
//   4. `settleAnchors()`'s four outcomes — passed or failed, removes clean or
//      not — and a `send` that REJECTS, in both cases: a passing job fails on
//      a remove that failed, a failing job keeps its own error.
//   5. `useSender()` hands back what it replaced, and `null` restores the real
//      `send()`; this file restores what it found in a `finally`.
//
// `tls/tls_server.js` is required in this process for its `removeAnchor()`
// sentence, as `truststore_admin.js`'s claim 1 does; nothing is added to the
// truststore, and the fingerprint asked for is one nobody holds.
//
// MUTATION RECORD (2026-11-04). Each applied to `pep-credential.js`, run,
// seen red, and restored. Eight mutants, all caught:
//
//   * `trustRecorded()` recording after the post             — 1 red (1)
//   * `removeAnchor()` without the not-held branch           — 4 red (2, 3)
//   * the not-held branch accepting any 400                  — 1 red (2)
//   * `settleAnchors()` dropping a passing job's failure     — 1 red (4)
//   * `useSender(null)` keeping the fake                     — 2 red (5)
//   * "not held" done whether confirmed or not               — 5 red (2b)
//   * a confirmed "not held" failing on the first try        — 6 red (2b, 3)
//   * `trustRecorded()` never confirming                     — 1 red (1)
// ===========================================================================

const path = require('path');
const crypto = require('crypto');

const ROOT = path.join(__dirname, '..');
const log = require('bunyan').createLogger({
  name: 'trust_anchor_cleanup', level: process.env.LOG_LEVEL || 'info' });

const BASE = 'https://sts.invalid:8443';

// A fake with send()'s signature: `(where, type, body, headers, verify)` and
// a promise of `{ ok, status, body }` or `{ ok: false, why }`. `answer` is
// called with the parsed request and the call's index and decides the reply.
function fakeSender(calls, answer) {
  log.debug("Entering fakeSender().");
  log.debug("Leaving fakeSender().");
  return function fakeSend(where, type, body, headers, verify) {
    log.debug("Entering fakeSend().");
    let parsed = null;
    try {
      parsed = JSON.parse(body);
    } catch (e) {
      // Recorded as unparsed; the check on the body then fails visibly.
      log.debug("Caught in fakeSend(): " + ((e && e.message) || e));
      parsed = null;
    }
    const call = { where: where, type: type, body: parsed,
                   headers: headers, verify: verify };
    calls.push(call);
    log.debug("Leaving fakeSend().");
    return answer(call, calls.length - 1);
  };
}

function okAnswer() {
  log.debug("Entering okAnswer().");
  log.debug("Leaving okAnswer().");
  return Promise.resolve({ ok: true, status: 200,
                           body: '{"ok":true,"removed":1}' });
}

async function run(t) {
  log.debug("Entering run().");
  const credentials = require('./tools/pep-credential.js');
  const tls = require(path.join(ROOT, 'tls', 'tls_server.js'));
  const previous = credentials.useSender(null);
  const previousDelay = credentials.useRetryDelay(5);
  t.equal(previousDelay, 1000, 'a confirmed remove waits 1s between tries');
  try {
    await claims(t, credentials, tls);
  } finally {
    credentials.useSender(previous);
    credentials.useRetryDelay(previousDelay);
  }
  log.debug("Leaving run().");
}

async function claims(t, credentials, tls) {
  log.debug("Entering claims().");
  // Three distinct certificates from one chain: no CRL host, nothing posted.
  const minted = await credentials.mint({
    rootSubject: 'CN=trust-anchor-cleanup ' + process.pid + '-' + Date.now() +
                 ',O=iya-sts tests',
    subject: 'CN=trust-anchor-cleanup-leaf,O=iya-sts tests',
    crlBase: false });
  const one = minted.root.pem;
  const two = minted.issuing.pem;
  const three = minted.leaf.pem;
  const fingerprintOf = function (pem) {
    log.debug("Entering fingerprintOf().");
    log.debug("Leaving fingerprintOf().");
    return new crypto.X509Certificate(pem).fingerprint256;
  };

  // The service's own sentence for a fingerprint it does not hold, from the
  // real truststore, as the management API carries it in a 400's `errors`.
  const unheld = tls.removeAnchor('AB'.repeat(32));
  t.check(unheld.removed === 0 && /holds no anchor/.test(unheld.error || ''),
          'the real truststore refuses a fingerprint it does not hold',
          JSON.stringify(unheld));
  const notHeld = { ok: false, status: 400,
                    body: JSON.stringify({ ok: false,
                                           errors: [unheld.error] }) };

  // ---- 1. record first --------------------------------------------------
  {
    const added = [];
    const calls = [];
    let listedAtPost = null;
    credentials.useSender(fakeSender(calls, function () {
      log.debug("Entering the timing-out add.");
      listedAtPost = added.slice();
      log.debug("Leaving the timing-out add.");
      return Promise.resolve({ ok: false,
                               why: 'the mock did not answer within 15s' });
    }));
    const posted = await credentials.trustRecorded(BASE, one, added);
    t.check(listedAtPost !== null && listedAtPost.indexOf(one) >= 0,
            'the anchor is in the job\'s list when its add goes out');
    t.check(!posted.ok && /within 15s/.test(posted.why || ''),
            'the timed-out add is answered as a failure, with its reason',
            JSON.stringify(posted));
    t.check(added.length === 1 && added[0] === one,
            'and the anchor is still recorded for removal after the timeout');
    t.equal(calls.length && calls[0].where,
            BASE + '/admin-api/tls/trust/add',
            'the add went to the gated door');
    t.check(calls.length && calls[0].body &&
            calls[0].body.certificates === one && calls[0].verify === true,
            'with the PEM as `certificates`, verifying the connection');
    t.check(!credentials.isConfirmed(one),
            'an add that timed out leaves the anchor unconfirmed');
    credentials.useSender(fakeSender(calls, okAnswer));
    await credentials.trustRecorded(BASE + '/', one, added);
    t.check(credentials.isConfirmed(one),
            'an add answered 2xx confirms it');
    credentials.recordAnchor(added, one);
    credentials.recordAnchor(added, '');
    t.equal(added.length, 1, 'an anchor is recorded once, however often, ' +
            'and an empty one not at all');
    credentials.recordAnchor(added, two);
    t.check(added.length === 2 && added[1] === two,
            'recordAnchor() alone records for a job posting through its own ' +
            'door');
    t.check(!credentials.isConfirmed(two),
            'and leaves it unconfirmed until the job says otherwise');
    t.check(!credentials.confirmAnchor('not a PEM'),
            'confirming a PEM that is not a certificate confirms nothing');
    let threw = false;
    try {
      credentials.recordAnchor(null, one);
    } catch (e) {
      log.debug("Caught in claims(): " + ((e && e.message) || e));
      threw = true;
    }
    t.check(threw, 'recording into no list throws rather than skipping');
  }

  // ---- 2. the remove -----------------------------------------------------
  {
    const calls = [];
    credentials.useSender(fakeSender(calls, okAnswer));
    const removed = await credentials.removeAnchor(BASE, one);
    t.check(removed.ok && !removed.absent, 'a remove the service did is ok');
    t.equal(calls.length && calls[0].where,
            BASE + '/admin-api/tls/trust/remove',
            'the remove went to the gated door');
    t.equal(calls.length && calls[0].body && calls[0].body.fingerprint,
            fingerprintOf(one), 'naming the anchor by SHA-256 fingerprint');
    t.check(!credentials.isConfirmed(one),
            'a finished remove forgets the confirmation');

    credentials.useSender(fakeSender(calls, function () {
      log.debug("Entering the not-held remove.");
      log.debug("Leaving the not-held remove.");
      return Promise.resolve(notHeld);
    }));
    const absent = await credentials.removeAnchor(BASE, one);
    t.check(absent.ok && absent.absent === true,
            'an UNCONFIRMED anchor the service does not hold is a remove ' +
            'that is done', JSON.stringify(absent));
    t.equal(calls.length, 2, 'asked once, with no retry');

    credentials.useSender(fakeSender(calls, function () {
      log.debug("Entering the refused remove.");
      log.debug("Leaving the refused remove.");
      return Promise.resolve({ ok: false, status: 400, body: JSON.stringify(
        { ok: false, errors: ['Name the anchor by its SHA-256 fingerprint ' +
                              'in `fingerprint`. Nothing was removed.'] }) });
    }));
    const refused = await credentials.removeAnchor(BASE, one);
    t.check(!refused.ok && /trust\/remove answered 400/.test(refused.why),
            'any other 400 is a failure, with its reason',
            JSON.stringify(refused));

    credentials.useSender(fakeSender(calls, function () {
      log.debug("Entering the refused-by-gate remove.");
      log.debug("Leaving the refused-by-gate remove.");
      return Promise.resolve({ ok: false, status: 403,
                               body: String(unheld.error) });
    }));
    const forbidden = await credentials.removeAnchor(BASE, one);
    t.check(!forbidden.ok,
            'the sentence under a status other than 400 is not taken as done');

    const before = calls.length;
    const notCert = await credentials.removeAnchor(BASE, 'not a PEM');
    t.check(!notCert.ok && /not a certificate/.test(notCert.why || '') &&
            calls.length === before,
            'a PEM that is not a certificate fails without a request');
  }

  // ---- 2b. a CONFIRMED anchor not held: a node behind ---------------------
  {
    const calls = [];
    credentials.confirmAnchor(three);
    credentials.useSender(fakeSender(calls, function () {
      log.debug("Entering the never-held remove.");
      log.debug("Leaving the never-held remove.");
      return Promise.resolve(notHeld);
    }));
    const stuck = await credentials.removeAnchor(BASE, three);
    t.check(!stuck.ok && !stuck.absent &&
            /CONFIRMED and it is still not held after 5 tries/
              .test(stuck.why || ''),
            'a CONFIRMED anchor still not held fails, saying so',
            JSON.stringify(stuck));
    t.equal(calls.length, 5, 'after five tries, no more');
    t.check(credentials.isConfirmed(three),
            'and it stays confirmed, since nothing removed it');

    const later = [];
    credentials.confirmAnchor(two);
    credentials.useSender(fakeSender(later, function (call, index) {
      log.debug("Entering the catching-up remove.");
      log.debug("Leaving the catching-up remove.");
      return index < 2 ? Promise.resolve(notHeld) : okAnswer();
    }));
    const caught = await credentials.removeAnchor(BASE, two);
    t.check(caught.ok && !caught.absent,
            'a node that catches up within the tries is a remove that is done',
            JSON.stringify(caught));
    t.check(later.length === 3 && later.every(function (call) {
      return call.body && call.body.fingerprint === fingerprintOf(two);
    }), 'two "not held" answers, then the remove, of the same fingerprint');
    t.check(!credentials.isConfirmed(two),
            'and the confirmation is forgotten');
  }

  // ---- 3. forgetAnchors() -------------------------------------------------
  {
    const calls = [];
    credentials.useSender(fakeSender(calls, function (call, index) {
      log.debug("Entering the mixed removes.");
      log.debug("Leaving the mixed removes.");
      if (index === 0) {
        return Promise.resolve({ ok: false,
                                 why: 'the mock did not answer within 15s' });
      }
      if (index === 1) {
        return Promise.resolve(notHeld);
      }
      return okAnswer();
    }));
    const problems = await credentials.forgetAnchors(BASE,
                                                     [one, null, two, three]);
    t.equal(calls.length, 3, 'one remove per anchor, the falsy one skipped');
    t.check(calls.length === 3 &&
            calls[0].body.fingerprint === fingerprintOf(one) &&
            calls[1].body.fingerprint === fingerprintOf(two) &&
            calls[2].body.fingerprint === fingerprintOf(three),
            'in the order they were recorded');
    t.check(problems.length === 1 && /within 15s/.test(problems[0]),
            'a failure is reported and does not stop the rest; the ' +
            'not-held one is not a problem', JSON.stringify(problems));
    const none = await credentials.forgetAnchors(BASE, undefined);
    t.check(Array.isArray(none) && none.length === 0,
            'no list is nothing to remove');
  }

  // ---- 4. settleAnchors() -------------------------------------------------
  {
    const outcome = function (promise) {
      log.debug("Entering outcome().");
      log.debug("Leaving outcome().");
      return promise.then(function () {
        return { resolved: true };
      }, function (error) {
        log.debug("Caught in outcome(): " +
                  ((error && error.message) || error));
        return { resolved: false, error: error };
      });
    };
    const calls = [];
    const jobError = new Error('the job\'s own assertion');

    credentials.useSender(fakeSender(calls, function (call, index) {
      log.debug("Entering the clean removes.");
      log.debug("Leaving the clean removes.");
      return index === 0 ? Promise.resolve(notHeld) : okAnswer();
    }));
    let got = await outcome(credentials.settleAnchors(BASE, [one, two], null));
    t.check(got.resolved, 'a passing job with clean removes passes, a ' +
            'not-held one included');
    got = await outcome(credentials.settleAnchors(BASE, [one], jobError));
    t.check(!got.resolved && got.error === jobError,
            'a failing job with clean removes keeps its own error');

    credentials.useSender(fakeSender(calls, function () {
      log.debug("Entering the failing removes.");
      log.debug("Leaving the failing removes.");
      return Promise.resolve({ ok: false, status: 500, body: 'boom' });
    }));
    got = await outcome(credentials.settleAnchors(BASE, [one], null));
    t.check(!got.resolved && got.error !== jobError &&
            /were not removed/.test((got.error && got.error.message) || ''),
            'a passing job fails on a remove that failed',
            got.error && got.error.message);
    got = await outcome(credentials.settleAnchors(BASE, [one], jobError));
    t.check(!got.resolved && got.error === jobError,
            'a failing job keeps its own error over a failed remove');

    const broken = new Error('the sender itself broke');
    credentials.useSender(function () {
      log.debug("Entering the rejecting sender.");
      log.debug("Leaving the rejecting sender.");
      return Promise.reject(broken);
    });
    got = await outcome(credentials.settleAnchors(BASE, [one], null));
    t.check(!got.resolved && got.error === broken,
            'a passing job fails with a sender that rejects');
    got = await outcome(credentials.settleAnchors(BASE, [one], jobError));
    t.check(!got.resolved && got.error === jobError,
            'a failing job keeps its own error over a sender that rejects');
  }

  // ---- 5. useSender() -----------------------------------------------------
  {
    const mine = function mySend() {
      log.debug("Entering mySend().");
      log.debug("Leaving mySend().");
      return okAnswer();
    };
    credentials.useSender(mine);
    const handedBack = credentials.useSender(null);
    t.check(handedBack === mine, 'useSender() hands back what it replaced');
    const real = credentials.useSender(null);
    t.check(typeof real === 'function' && real !== mine,
            'and null restores the real send()');
    // The real send() refusing a URL that is not one answers without the
    // network, which tells it from any fake above.
    const answer = await credentials.removeAnchor('not a url', one);
    t.check(!answer.ok && /is not a URL/.test(answer.why || ''),
            'the real send() is the one in force again',
            JSON.stringify(answer));
  }
  log.debug("Leaving claims().");
}

module.exports = {
  name: 'trust_anchor_cleanup',
  describe: 'a job\'s trust anchors are recorded before they are posted, and ' +
            'settleAnchors() removes them, "not held" counted as done (#1307)',
  run: run
};
