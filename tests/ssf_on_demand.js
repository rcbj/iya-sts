// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: ssf_on_demand.js
//
// ===========================================================================
// INTERNAL SHARED SIGNALS STOP BEING APPLIED IN EVERY PROCESS (2026-10-21,
// #820, rcbj's decision: keep RFC 8936 internal delivery, stop replicating).
//
// `ssf_streams.queued` and `ssf_receivers.inbox` are on demand and filed by
// stream and by surface; a stream's record is written once for a burst of
// events, not at each.
//
//   F1. a stream's queue is read through the index — SETs this process does
//       not hold included — oldest first;
//   F2. queueing a SET does not read the queue (the cap is the poll's), and
//       the stream's record is written once for a burst, after a moment;
//   F3. a poll that acknowledges, refuses and newly delivers nothing writes
//       nothing;
//   F4. the queue's cap is kept by the poll: the oldest go.
//
// In a child process: it installs a stand-in reader in `common/realms.js`.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'ssf_on_demand',
  level: process.env.LOG_LEVEL || 'info' });

// Runs in the child. Stringified, so it may use nothing from this file's scope.
function child() {
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };
  const OUT = process.env.SOD_OUT;
  const ROOT = process.env.SOD_ROOT;
  (async function () {
    const realms = require(ROOT + '/common/realms');
    const config = require(ROOT + '/common/config');
    const streamsModule = require(ROOT + '/ssf/ssf_streams');
    const QUEUED = 'ssf_streams.queued';
    const stored = new Map();
    const asked = [];
    realms.setOnDemandReader({
      active: function (handle) {
        return handle === QUEUED;
      },
      read: function (handle, realmId, key) {
        asked.push('read:' + key);
        return stored.has(key) ? { present: true, value: stored.get(key) }
          : { present: false };
      },
      byIndex: function (handle, realmId, indexKey) {
        asked.push('index:' + indexKey);
        const out = [];
        stored.forEach(function (value, key) {
          if (value.stream_id === indexKey) {
            out.push({ key: key, value: value });
          }
        });
        return out;
      },
      journalled: function () {
        return false;
      }
    });
    const streamsHandle = realms.handleFor('ssf_streams.streams');
    let streamWrites = 0;
    realms.setPersistObserver(function (handle) {
      if (handle === 'ssf_streams.streams') {
        streamWrites++;
      }
    });
    const record = {
      stream_id: 'st-1', status: 'enabled', iss: 'x', aud: 'y',
      delivery: { method: streamsModule.DELIVERY_POLL },
      events_requested: [], events_delivered: [], log: [], subjects: [],
      counters: { queued: 0, delivered: 0, failed: 0, acknowledged: 0,
        pollCalls: 0, pushCalls: 0, receiverErrors: 0 },
      eventCounts: {}
    };
    streamsHandle.restore('default', 'st-1', record);
    // Two SETs another process queued: in the store, not held here.
    stored.set('st-1 jti-b', { jti: 'jti-b', token: 'tb', claims: {},
      queuedAt: new Date().toISOString(), stream_id: 'st-1', order: 2 });
    stored.set('st-1 jti-a', { jti: 'jti-a', token: 'ta', claims: {},
      queuedAt: new Date().toISOString(), stream_id: 'st-1', order: 1 });
    const order = realms.run(realms.get('default'), function () {
      return streamsModule.queueOf(record).map(function (one) {
        return one.jti;
      });
    });
    note(order.join(',') === 'jti-a,jti-b' && asked.indexOf('index:st-1') >= 0,
         'F1. a stream\'s queue is read through the index, oldest first',
         JSON.stringify({ order: order, asked: asked }));

    asked.length = 0;
    streamWrites = 0;
    realms.run(realms.get('default'), function () {
      for (let i = 0; i < 5; i++) {
        streamsModule.enqueue(record, { jti: 'new-' + i, token: 't',
          claims: {}, queuedAt: new Date().toISOString() });
      }
    });
    const rightAway = streamWrites;
    await new Promise(function (resolve) {
      setTimeout(resolve, 2300);
    });
    note(!asked.some(function (one) {
      return one.indexOf('index:') === 0;
    }) && rightAway === 0 && streamWrites === 1,
         'F2. queueing reads no queue, and five SETs write the stream once, ' +
         'a moment later', JSON.stringify({ asked: asked,
           rightAway: rightAway, after: streamWrites }));

    // Everything delivered once already (counted), nothing acknowledged.
    realms.run(realms.get('default'), function () {
      streamsModule.poll(record, { maxEvents: 50 });
    });
    streamWrites = 0;
    realms.run(realms.get('default'), function () {
      streamsModule.poll(record, { maxEvents: 50 });
    });
    note(streamWrites === 0,
         'F3. a poll that changes nothing writes nothing',
         String(streamWrites));

    config.setOverride('ssf.maxQueuedEvents', 3);
    let answer = null;
    realms.run(realms.get('default'), function () {
      answer = streamsModule.poll(record, { maxEvents: 50 });
    });
    const left = Object.keys((answer && answer.sets) || {});
    note(left.length === 3 && left.indexOf('jti-a') < 0,
         'F4. the poll keeps the queue\'s cap: the oldest go',
         JSON.stringify(left));
  })().catch(function (e) {
    note(false, 'the child threw', (e && e.stack) || e);
  }).then(function () {
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function run(t) {
  log.debug("Entering run().");
  const root = path.join(__dirname, '..');
  const out = path.join(os.tmpdir(), 'sts-sod-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|CONFIG_FILE$)/.test(key)) {
      env[key] = process.env[key];
    }
  });
  Object.assign(env, { SOD_OUT: out, SOD_ROOT: root, LOG_LEVEL: 'fatal',
                       STS_LOG_LEVEL: 'fatal' });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + child.toString() + ')()'], {
      cwd: root, env: env, encoding: 'utf8', timeout: 120000 });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.rmSync(out, { force: true });
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (t.check(Array.isArray(findings),
              'the child process reported its findings',
              'status=' + result.status + ' ' +
              String(result.stderr || '').slice(-2000))) {
    findings.forEach(function (one) {
      t.check(one.ok, one.what, one.detail);
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'ssf_on_demand',
  describe: 'internal Shared Signals queues and inboxes are on demand, and a ' +
            'stream\'s record is written once for a burst (#820)',
  run: run
};
