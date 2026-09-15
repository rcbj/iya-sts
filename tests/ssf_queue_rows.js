'use strict';
//
// File: ssf_queue_rows.js
//
// ===========================================================================
// A STREAM'S QUEUE IS ONE ROW PER SET, AND EVERY CHANGE TO IT IS JOURNALLED.
//
// `ssf_streams.js` kept the queue as an array on the stream record, and
// nothing that changed it — queueing a SET, a poll's acknowledgement, a push
// taking one off — was ever reported to the persistence journal. In the
// request-worker pool that made the queue per PROCESS: in `dispatch` mode on
// 2026-09-13 `sts_ssf_allowed_events` polled a control stream straight after
// an emission and got `[]`, and `sts_gnap_signals` acknowledged a SET and was
// handed it again, which RFC 8936 section 2.4 forbids. Both passed in the two
// single-process modes and always would.
//
// ---------------------------------------------------------------------------
// WHAT IS ASSERTED, AND WHY NOT BY STARTING TWO PROCESSES.
//
// A second process of this service learns another's write in exactly one way:
// `persistence_minted.js`'s `applyLocally()` calls the store's `restore` or
// `remove` accessor with the row the other process committed. So "another
// worker wrote this" is those two calls, made here, and "this process wrote
// that" is what reached the persist observer. Nothing else about a second
// process takes part in either question.
//
//   1. Queueing a SET, acknowledging one and refusing one each reach the
//      journal as THAT SET'S KEY — a set, and a delete.
//   2. **A STALE RECORD FROM ANOTHER PROCESS CANNOT TAKE A SET AWAY OR PUT ONE
//      BACK.** That is the race a `touch()` on a whole-valued record would
//      have left open: a transmission that queues AFTER answering, on a
//      worker that has not yet applied an acknowledgement, writing the
//      acknowledged SET straight back. It is the reason the queue is a store
//      of its own rather than the one-line fix `caep.js` got.
//   3. A delete applied from another process is final here: a SET another
//      worker took an acknowledgement for is not delivered by this one.
//   4. A record edited IN PLACE reaches the journal, a record another process
//      has REPLACED is not written back, and `liveRecord()` answers the one
//      held.
//   5. A disable and a removal take the rows with them.
//
// In a CHILD PROCESS, for `tests/realm_isolation.js`'s reason: this needs a
// persist observer, and `realms.setPersistObserver()` cannot put back one
// another file in this run may have installed.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'ssf_queue_rows',
  level: process.env.LOG_LEVEL || 'info' });

// Runs in the child. Stringified, so it may use nothing from this file's scope.
function child() {
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what, detail: detail || '' });
  };
  const OUT = process.env.SSF_QUEUE_CHILD_OUT;
  const ROOT = process.env.SSF_QUEUE_CHILD_ROOT;
  try {
    const config = require(ROOT + '/common/config');
    const realms = require(ROOT + '/common/realms');
    const journal = [];
    realms.setPersistObserver(function (handle, realmId, key) {
      journal.push({ handle: handle, realm: realmId, key: key });
    });
    config.setOverride('ssf.enabled', 'true');
    const streams = require(ROOT + '/ssf/ssf_streams');
    const QUEUED = 'ssf_streams.queued';
    const STREAMS = 'ssf_streams.streams';
    const queuedHandle = realms.handleFor(QUEUED);
    const streamHandle = realms.handleFor(STREAMS);
    const realm = realms.create({ id: 'ssf-queue-rows', name: 'q' }).realm;
    const keysFor = function (handle) {
      return journal.filter(function (row) {
        return row.handle === handle;
      }).map(function (row) { return row.key; });
    };
    const entry = function (jti) {
      return { jti: jti, token: 'token-' + jti, claims: { jti: jti },
               queuedAt: new Date().toISOString(), deliveredAt: '',
               counted: false };
    };

    note(queuedHandle && queuedHandle.scope === 'realm',
         'the queue is a DECLARED, per-realm, persisted store of its own',
         queuedHandle ? queuedHandle.scope : '(not declared)');

    realms.run(realm, function () {
      const made = streams.createStream(
        { delivery: { method: streams.DELIVERY_POLL },
          aud: 'https://receiver.test/q' },
        { issuer: 'https://sts.test/realm/ssf-queue-rows',
          principal: 'queue-probe' });
      note(made.ok, 'a poll stream is created', JSON.stringify(made.errors));
      const record = made.stream;
      const id = record.stream_id;
      note(!Object.prototype.hasOwnProperty.call(record, 'queue'),
           'the record carries no `queue` member for a whole-record write ' +
           'to overwrite');
      const keyOf = function (jti) { return id + ' ' + jti; };

      // 1. QUEUEING.
      journal.length = 0;
      streams.enqueue(record, entry('j1'));
      streams.enqueue(record, entry('j2'));
      note(keysFor(QUEUED).indexOf(keyOf('j1')) >= 0 &&
           keysFor(QUEUED).indexOf(keyOf('j2')) >= 0,
           'queueing a SET journals THAT SET\'S ROW — before the fix it ' +
           'journalled nothing, so no other worker could poll it',
           JSON.stringify(journal));
      note(keysFor(STREAMS).indexOf(id) >= 0,
           'and the counter it moved on the record reaches the journal too',
           JSON.stringify(journal));

      // 2. A STALE RECORD FROM ANOTHER PROCESS, as `applyLocally()` puts it.
      const stale = JSON.parse(JSON.stringify(record));
      stale.queue = [];
      streamHandle.restore(realm.id, id, stale);
      note(streams.queueOf(streams.getStream(id)).length === 2,
           'A RECORD ANOTHER WORKER WROTE BEFORE THESE SETS EXISTED DOES NOT ' +
           'TAKE THEM AWAY — the lost-update half of the race',
           JSON.stringify(streams.queueOf(streams.getStream(id))
             .map(function (one) { return one.jti; })));

      // 1 again. THE POLL AND THE ACKNOWLEDGEMENT.
      const live = streams.getStream(id);
      journal.length = 0;
      const first = streams.poll(live, { maxEvents: 10 });
      note(Object.keys(first.sets).join(',') === 'j1,j2',
           'a poll hands out both, in the order they were queued',
           Object.keys(first.sets).join(','));
      journal.length = 0;
      const again = streams.poll(live, { maxEvents: 10 });
      note(Object.keys(again.sets).length === 2 &&
           keysFor(QUEUED).length === 0,
           'a REDELIVERY writes no SET row, so it cannot put back a SET ' +
           'another worker has just deleted', JSON.stringify(journal));
      journal.length = 0;
      streams.poll(live, { ack: ['j1'], setErrs: { j2: { err: 'x' } },
                           maxEvents: 0 });
      note(keysFor(QUEUED).indexOf(keyOf('j1')) >= 0 &&
           keysFor(QUEUED).indexOf(keyOf('j2')) >= 0 &&
           !queuedHandle.read(realm.id, keyOf('j1')).present &&
           !queuedHandle.read(realm.id, keyOf('j2')).present,
           'an acknowledgement and a refusal each journal a DELETE of that ' +
           'SET\'s row — before the fix an ack was per worker, and the next ' +
           'poll on another one delivered the SET again',
           JSON.stringify(journal));

      // 2 again. THE RESURRECTION HALF. A worker that has not applied the
      // acknowledgement above queues a third SET: what it writes is that SET's
      // row and nothing that names j1.
      journal.length = 0;
      streams.enqueue(stale, entry('j3'));
      note(keysFor(QUEUED).join(',') === keyOf('j3'),
           'A SET QUEUED FROM A STALE COPY WRITES ONLY ITS OWN ROW, so it ' +
           'cannot put back the one acknowledged a moment earlier',
           JSON.stringify(keysFor(QUEUED)));

      // 3. A DELETE FROM ANOTHER PROCESS IS FINAL HERE.
      queuedHandle.restore(realm.id, keyOf('j4'),
        Object.assign(entry('j4'), { stream_id: id, order: 1 }));
      const seen = streams.poll(live, { maxEvents: 10 });
      note(Object.keys(seen.sets).indexOf('j4') >= 0,
           'a SET another worker queued is delivered by this one',
           Object.keys(seen.sets).join(','));
      queuedHandle.remove(realm.id, keyOf('j4'));
      const after = streams.poll(live, { maxEvents: 10 });
      note(Object.keys(after.sets).indexOf('j4') < 0,
           'and once that worker\'s acknowledgement is applied here, it is ' +
           'not delivered again', Object.keys(after.sets).join(','));

      // 4. IN PLACE, AND REPLACED.
      journal.length = 0;
      streams.addSubject(id, { format: 'email', email: 'q@example.com' });
      note(keysFor(STREAMS).indexOf(id) >= 0,
           'a subject added to the record in place reaches the journal — a ' +
           'PATCH, a pause and a subject were written as the stream was ' +
           'CREATED until now', JSON.stringify(journal));
      const held = streams.getStream(id);
      const replacement = JSON.parse(JSON.stringify(held));
      streamHandle.restore(realm.id, id, replacement);
      journal.length = 0;
      note(streams.touch(held) === false && keysFor(STREAMS).length === 0,
           'a record another process has REPLACED is not written back over ' +
           'its write', JSON.stringify(journal));
      note(streams.liveRecord(held) === replacement,
           'and liveRecord() answers the one held now');
      const legacy = streams.getStream(id);
      legacy.queue = [entry('ancient')];
      streams.touch(legacy);
      note(!Object.prototype.hasOwnProperty.call(legacy, 'queue') &&
           streams.queueOf(legacy).every(function (one) {
             return one.jti !== 'ancient';
           }),
           'a `queue` member on a record from an earlier build is dropped ' +
           'at its first write and never delivered');

      // 5. A DISABLE, AND A REMOVAL.
      const waiting = streams.queueOf(streams.getStream(id)).length;
      journal.length = 0;
      streams.setStatus(id, 'disabled', 'test');
      note(waiting > 0 && streams.queueOf(streams.getStream(id)).length === 0 &&
           keysFor(QUEUED).length === waiting,
           'a disable drops what was waiting as one journalled delete per SET',
           waiting + ' waiting; ' + JSON.stringify(keysFor(QUEUED)));
      streams.setStatus(id, 'enabled', 'test');
      streams.enqueue(streams.getStream(id), entry('j5'));
      streams.removeStream(id);
      note(!queuedHandle.read(realm.id, keyOf('j5')).present,
           'and a removed stream leaves no SET row behind in any process');
    });
  } catch (e) {
    note(false, 'the child ran to the end', e && e.stack);
  }
  require('fs').writeFileSync(OUT, JSON.stringify(findings));
  process.exit(0);
}

// A STATIC GUARD, beside the behavioural ones: nothing in the family may go
// back to reading or writing the queue as a member of the record. A reader of
// `record.queue` would see `undefined` and throw at the first console page; a
// writer would put the array back for a whole-record write to overwrite.
function checkNoQueueMember(t) {
  log.debug("Entering checkNoQueueMember().");
  const root = path.join(__dirname, '..');
  ['ssf/ssf.js', 'ssf/ssf_streams.js', 'ssf/ssf_receivers.js', 'ssf/caep.js',
   'ssf/risc.js', 'gnap/gnap_signals.js'].forEach(function (rel) {
    const text = fs.readFileSync(path.join(root, rel), 'utf8')
      .split('\n').filter(function (line) {
        // The one legitimate mention: touch() dropping the member a record
        // written by an earlier build still carries.
        return !/^\s*\/\//.test(line) &&
               !/delete record\.queue;/.test(line);
      }).join('\n');
    t.check(!/\b(record|stream|row)\.queue\b/.test(text),
            rel + ' reads the queue through queueOf() and never as a member ' +
            'of the record');
  });
  log.debug("Leaving checkNoQueueMember().");
}

function run(t) {
  log.debug("Entering run().");
  const root = path.join(__dirname, '..');
  const out = path.join(os.tmpdir(), 'sts-ssf-queue-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = Object.assign({}, process.env, {
    SSF_QUEUE_CHILD_OUT: out, SSF_QUEUE_CHILD_ROOT: root, LOG_LEVEL: 'fatal' });
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
  checkNoQueueMember(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'ssf_queue_rows',
  describe: 'a Shared Signals stream\'s queue is one journalled row per SET, ' +
            'so a SET queued, acknowledged or refused by one request worker ' +
            'is what every other worker delivers',
  run: run
};
