'use strict';
//
// File: ssf_dead_letters.js
//
// ===========================================================================
// UNDELIVERABLE SETs GO TO A DEAD-LETTER QUEUE, A STREAM THAT ONLY FAILS IS
// DECLARED DEAD, AND PUSHES ARE CAPPED PER PROCESS (2026-09-14).
//
// A dispatch run's SCIM bulk load pushed every directory write's two events to
// forty-two streams at once, forty of them refusing; each refused SET stayed on
// the live queue for ever, was re-scanned on every later event, and wrote an
// audit row whose code put a line in the log — 30,698 in one second. The
// service stopped answering for fourteen minutes. What replaced it:
//
//   A. THE STORE. A dead letter keeps the SET, the reason, the code and the
//      receiver's status; the per-stream cap deletes the OLDEST; the sweep
//      deletes what is past retention and what belongs to no stream, and hands
//      back — and resets — what was dead-lettered since the last sweep, which
//      is the one summary line; removing a stream takes its letters.
//   B. DEAD, REVIVED, HALF-OPEN. A first failure starts the clock and does not
//      kill; a failure `ssf.deadStreamTimeoutS` later declares the stream dead
//      and moves what was waiting; a success revives it; `revive()` by hand
//      refuses a live stream; a half-open stream dies again on one failure.
//   C. THE PUSH CAP. `ssf.pushConcurrency` in flight, `ssf.pushBacklog`
//      waiting, and the next refused at once with STS-SSF-0092 — against a
//      real listener that holds its answers.
//   D. THROUGH `transmit()`. A failed push is dead-lettered and taken OFF the
//      live queue with no `ssf.event.refused` audit row; a SET for a dead
//      stream is dead-lettered UNSIGNED and nothing is pushed; the sweep's
//      probe signs and pushes the oldest letter, and a success revives the
//      stream — against a real listener that refuses, then accepts.
//
// In a CHILD PROCESS: it sets a dozen SSF settings, requires the whole SSF
// family, and listens on ports.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'ssf_dead_letters',
  level: process.env.LOG_LEVEL || 'info' });

// Runs in the child. Stringified, so it may use nothing from this file's scope.
function child() {
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what, detail: detail || '' });
  };
  const OUT = process.env.SSF_DLQ_CHILD_OUT;
  const ROOT = process.env.SSF_DLQ_CHILD_ROOT;
  const http = require('http');
  const finish = function () {
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  };
  (async function () {
    const config = require(ROOT + '/common/config');
    [['ssf.enabled', 'true'], ['ssf.pushDelivery', 'true'],
     ['ssf.pushAllowInsecure', 'true'], ['ssf.deadStreamTimeoutS', '300'],
     ['ssf.deadLetterMaxPerStream', '3'], ['ssf.pushConcurrency', '2'],
     ['ssf.pushBacklog', '1'], ['ssf.pushTimeoutMs', '2000']]
      .forEach(function (pair) {
      try {
        config.setOverride(pair[0], pair[1]);
      } catch (e) {
        note(false, 'setting ' + pair[0] + ' is accepted', e.message);
      }
    });
    require(ROOT + '/common/app');
    const streams = require(ROOT + '/ssf/ssf_streams');
    const transport = require(ROOT + '/ssf/ssf_http');
    const events = require(ROOT + '/ssf/ssf_events');
    const audit = require(ROOT + '/common/audit');
    const VERIFY = events.SSF_PREFIX + 'verification';

    const makeStream = function (url) {
      return streams.createStream({
        aud: 'https://receiver.test/dlq',
        events_requested: [VERIFY, events.SSF_PREFIX + 'stream-updated'],
        delivery: { method: streams.DELIVERY_PUSH, endpoint_url: url }
      }, { issuer: 'https://sts.test', principal: 'dlq-probe' }).stream;
    };
    const entry = function (jti) {
      return { jti: jti, token: 'token-' + jti, claims: { jti: jti },
               queuedAt: new Date().toISOString() };
    };

    // A. THE STORE.
    const a = makeStream('http://127.0.0.1:1/never');
    ['a1', 'a2', 'a3', 'a4', 'a5'].forEach(function (jti, i) {
      streams.addDeadLetter(a, entry(jti), { why: 'refused ' + i,
        errorCode: 'STS-SSF-0043', status: 400 });
    });
    const letters = streams.deadLettersOf(a);
    note(letters.map(function (one) { return one.jti; }).join(',') ===
         'a3,a4,a5',
         'THE PER-STREAM CAP DELETES THE OLDEST (ssf.deadLetterMaxPerStream=3)',
         JSON.stringify(letters.map(function (one) { return one.jti; })));
    note(letters[2].reason === 'refused 4' &&
         letters[2].errorCode === 'STS-SSF-0043' &&
         letters[2].status === 400 && letters[2].token === 'token-a5',
         'a dead letter keeps the SET, the reason, the code and the status',
         JSON.stringify(letters[2]));
    note(a.counters.deadLettered === 5,
         'and the stream counts every letter it was given',
         String(a.counters.deadLettered));
    const first = streams.sweepDeadLetters(Date.now());
    note(first.letters === 5 && first.byStream.length === 1 &&
         first.byCode[0][0] === 'STS-SSF-0043',
         'THE SWEEP HANDS BACK WHAT WAS DEAD-LETTERED SINCE THE LAST ONE, by ' +
         'stream and by code — the one summary line', JSON.stringify(first));
    const second = streams.sweepDeadLetters(Date.now());
    note(second.letters === 0 && second.held === 3,
         'and resets it, so the next line counts only what happened after',
         JSON.stringify(second));
    const aged = streams.sweepDeadLetters(Date.now() + 3601 * 1000);
    note(aged.expired === 3 && streams.deadLettersOf(a).length === 0,
         'LETTERS PAST ssf.deadLetterRetentionS ARE DELETED',
         JSON.stringify(aged));
    streams.addDeadLetter(a, entry('a6'), { why: 'x' });
    streams.removeStream(a.stream_id);
    note(streams.deadLettersOf(a).length === 0,
         'and removing a stream takes its letters with it');

    // B. DEAD, REVIVED, HALF-OPEN.
    const b = makeStream('http://127.0.0.1:1/never');
    streams.enqueue(b, entry('b1'));
    streams.enqueue(b, entry('b2'));
    const t0 = Date.now();
    const early = streams.notePushFailure(b, { why: 'refused' }, t0);
    note(!early.declaredDead && !streams.isDead(b) && b.failingSinceMs === t0,
         'A FIRST FAILURE STARTS THE CLOCK AND DOES NOT KILL THE STREAM');
    const late = streams.notePushFailure(b, { why: 'still refused' },
                                         t0 + 300 * 1000);
    note(late.declaredDead && late.moved === 2 && streams.isDead(b) &&
         streams.queueOf(b).length === 0 &&
         streams.deadLettersOf(b).length === 2,
         'A FAILURE ssf.deadStreamTimeoutS LATER DECLARES IT DEAD, and what ' +
         'was waiting moves to the dead-letter queue', JSON.stringify(late));
    note(streams.deadLettersOf(b)[0].errorCode === 'STS-SSF-0093',
         'with the dead-stream code on each');
    note(streams.notePushSuccess(b) && !streams.isDead(b) &&
         !(b.failingSinceMs > 0),
         'A SUCCESS REVIVES IT');
    note(!streams.revive(b, 'x'), 'reviving a live stream by hand is refused');
    streams.notePushFailure(b, { why: 'r' }, t0);
    streams.notePushFailure(b, { why: 'r' }, t0 + 300 * 1000);
    note(streams.isDead(b) && streams.revive(b, 'by hand') &&
         !streams.isDead(b), 'and a dead one is revived by hand');
    streams.notePushFailure(b, { why: 'r' }, t0);
    streams.notePushFailure(b, { why: 'r' }, t0 + 300 * 1000);
    streams.halfOpen(b, t0 + 600 * 1000);
    const again = streams.notePushFailure(b, { why: 'r' }, t0 + 600 * 1000);
    note(again.declaredDead,
         'A HALF-OPEN STREAM DIES AGAIN ON ONE FAILURE, not after a fresh ' +
         'timeout');

    // C. THE PUSH CAP, against a listener that holds its answers.
    const held = [];
    let arrived = 0;
    const slow = http.createServer(function (req, res) {
      arrived += 1;
      req.resume();
      held.push(res);
    });
    await new Promise(function (resolve) {
      slow.listen(0, '127.0.0.1', resolve);
    });
    const slowUrl = 'http://127.0.0.1:' + slow.address().port + '/push';
    const pushes = [1, 2, 3].map(function () {
      return transport.pushSetGated(slowUrl, 'a.b.c', {});
    });
    const fourth = await transport.pushSetGated(slowUrl, 'a.b.c', {});
    const gate = transport.pushGateState();
    note(gate.active === 2 && gate.waiting === 1,
         'TWO PUSHES IN FLIGHT AND ONE WAITING (ssf.pushConcurrency=2, ' +
         'ssf.pushBacklog=1)', JSON.stringify(gate));
    note(!fourth.ok && fourth.errorCode === 'STS-SSF-0092' &&
         !fourth.retryable,
         'AND THE NEXT IS NOT MADE, at once, with STS-SSF-0092',
         JSON.stringify(fourth));
    await new Promise(function (resolve) { setTimeout(resolve, 200); });
    note(arrived === 2, 'the listener saw only the two in flight',
         String(arrived));
    held.splice(0).forEach(function (res) { res.statusCode = 202; res.end(); });
    await new Promise(function (resolve) { setTimeout(resolve, 200); });
    held.splice(0).forEach(function (res) { res.statusCode = 202; res.end(); });
    const settled = await Promise.all(pushes);
    note(settled.every(function (one) { return one.ok; }) && arrived === 3 &&
         transport.pushGateState().active === 0,
         'the waiting push went out when a slot was free, and all three ' +
         'were delivered', JSON.stringify(settled.map(function (one) {
           return one.status;
         })));
    slow.close();

    // D. THROUGH transmit(), against a listener that refuses and then accepts.
    const ssf = require(ROOT + '/ssf/ssf');
    let accept = false;
    let received = 0;
    const receiver = http.createServer(function (req, res) {
      req.resume();
      received += 1;
      if (accept) {
        res.statusCode = 202;
        res.end();
        return;
      }
      res.statusCode = 400;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ err: 'invalid_request', description: 'no' }));
    });
    await new Promise(function (resolve) {
      receiver.listen(0, '127.0.0.1', resolve);
    });
    const url = 'http://127.0.0.1:' + receiver.address().port + '/receive';
    const d = makeStream(url);
    const refused = await ssf.transmit(d, { uri: VERIFY,
      payload: { state: 'one' } });
    note(!refused.ok && refused.deadLettered && received === 1,
         'A REFUSED PUSH IS DEAD-LETTERED', JSON.stringify(refused));
    note(streams.queueOf(d).length === 0 &&
         streams.deadLettersOf(d).length === 1 &&
         streams.deadLettersOf(d)[0].status === 400,
         'AND TAKEN OFF THE LIVE QUEUE — it stayed there for ever before');
    note(!audit.list().some(function (row) {
      return row.action === 'ssf.event.refused' && row.target === d.stream_id;
    }),
         'WITH NO AUDIT ROW OF ITS OWN — that row\'s code wrote a log line ' +
         'per undeliverable SET');
    d.failingSinceMs = Date.now() - 301 * 1000;
    await ssf.transmit(d, { uri: VERIFY, payload: { state: 'two' } });
    note(streams.isDead(d), 'a refusal after the timeout declares it dead');
    const pushedBefore = received;
    const deadSend = await ssf.transmit(d, {
      uri: events.SSF_PREFIX + 'stream-updated',
      payload: { status: 'enabled' } });
    // BY jti, not "the last one": two letters dead-lettered in the same
    // millisecond sort by jti, so the newest is not always last.
    const newest = streams.deadLettersOf(d).filter(function (one) {
      return one.jti === deadSend.jti;
    })[0];
    note(deadSend.deadLettered && received === pushedBefore &&
         newest && !newest.signed && newest.token === '' &&
         newest.errorCode === 'STS-SSF-0096',
         'A SET FOR A DEAD STREAM IS DEAD-LETTERED UNSIGNED AND NOTHING IS ' +
         'PUSHED', JSON.stringify({ deadSend: deadSend, newest: newest }));
    accept = true;
    d.nextProbeAtMs = 0;
    const held0 = streams.deadLettersOf(d).length;
    await ssf.sweepSignals();
    note(!streams.isDead(d) && received === pushedBefore + 1 &&
         streams.deadLettersOf(d).length === held0 - 1,
         'THE SWEEP PROBES A DEAD STREAM WITH ITS OLDEST LETTER, and a ' +
         'delivered probe revives the stream and takes that letter off',
         JSON.stringify({ dead: streams.isDead(d), received: received,
           held: streams.deadLettersOf(d).length }));
    receiver.close();
  })().catch(function (e) {
    note(false, 'the child ran to the end', e && e.stack);
  }).then(finish);
}

function run(t) {
  log.debug("Entering run().");
  const root = path.join(__dirname, '..');
  const out = path.join(os.tmpdir(), 'sts-ssf-dlq-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = Object.assign({}, process.env, {
    SSF_DLQ_CHILD_OUT: out, SSF_DLQ_CHILD_ROOT: root, LOG_LEVEL: 'fatal',
    // Restart-only, so set as the process starts: this file's streams are
    // its own and the console's and portal's would only add pushes to them.
    STS_SSF_INTERNAL_RECEIVERS: 'false' });
  delete env.CONFIG_FILE;
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + child.toString() + ')()'], {
      cwd: root, env: env, encoding: 'utf8', timeout: 180000,
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
  name: 'ssf_dead_letters',
  describe: 'undeliverable SETs go to a dead-letter queue with their reason, ' +
            'a stream that only fails is declared dead and probed, and ' +
            'pushes are capped per process',
  run: run
};
