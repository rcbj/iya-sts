// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: internal_signals_poll.js
//
// ===========================================================================
// THIS SERVICE'S OWN TWO RECEIVERS COLLECT BY RFC 8936 POLL, MANY SETS TO A
// REQUEST, AND STILL CHECK EVERY ONE (#771).
//
// They were pushed one SET per request, and under a password-write load on
// 8081 that was forty loopback requests a second on the one worker the batch
// lane is confined to. Each surface now collects from this service's own
// `/ssf/poll` with the credential `ssf_receivers.ts` derives for it, from the
// `ssf.internal-poll` scheduler job.
//
//   P1. the seeded streams are poll streams; a stream a build before #771
//       seeded as push to this service's own receive path is moved, once, and
//       a push stream an operator pointed elsewhere is left alone;
//   P2. a push to a receive endpoint whose stream is poll is refused;
//   P3. forty-five queued SETs are collected in a handful of requests, each
//       verified and recorded as arrived by poll, and acknowledged — the
//       queue is empty after;
//   P4. a SET that fails a check (an unverifiable signature with signatures
//       required, an audience that is another surface's) is recorded, sent
//       back in setErrs and taken off the queue, not redelivered for ever;
//   P5. `/ssf/poll` for an internal stream takes that receiver's credential
//       and nothing else — not none, not the other surface's;
//   P6. an empty stream is not dialled; `pollOwn()` dials only this process;
//   P7. the scheduler job is registered on `ssf.internalPollMs`.
//
// In a CHILD PROCESS: it sets SSF settings, requires the family and listens
// on a port of its own, plain http, as `global.port`.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const net = require('net');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'internal_signals_poll',
  level: process.env.LOG_LEVEL || 'info' });

// Runs in the child. Stringified, so it may use nothing from this file's scope.
function child() {
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };
  const OUT = process.env.ISP_OUT;
  const ROOT = process.env.ISP_ROOT;
  const PORT = Number(process.env.STS_PORT);
  const http = require('http');
  const finish = function () {
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  };
  (async function () {
    const config = require(ROOT + '/common/config');
    config.setOverride('ssf.enabled', 'true');
    const app = require(ROOT + '/common/app');
    const realms = require(ROOT + '/common/realms');
    const streams = require(ROOT + '/ssf/ssf_streams');
    const events = require(ROOT + '/ssf/ssf_events');
    const transport = require(ROOT + '/ssf/ssf_http');
    const receivers = require(ROOT + '/ssf/ssf_receivers');
    const ssf = require(ROOT + '/ssf/ssf');
    const stsCrypto = require(ROOT + '/common/crypto');
    ssf.registerRoutes(app);
    let polls = 0;
    const server = http.createServer(function (req, res) {
      if (String(req.url).indexOf('/ssf/poll') === 0) {
        polls++;
      }
      app(req, res);
    });
    await new Promise(function (resolve) {
      server.listen(PORT, '127.0.0.1', resolve);
    });
    receivers.seedStreams();
    const ADMIN = receivers.ADMIN;
    const surface = receivers.surfaceOf(ADMIN);
    const portal = receivers.surfaceOf(receivers.PORTAL);
    let record = receivers.streamFor(ADMIN);

    // --- P1 ------------------------------------------------------------
    note(record && record.delivery.method === streams.DELIVERY_POLL &&
         receivers.streamFor(receivers.PORTAL).delivery.method ===
           streams.DELIVERY_POLL,
         'P1. both seeded streams are delivered by RFC 8936 poll',
         JSON.stringify(record && record.delivery));
    record.delivery = { method: streams.DELIVERY_PUSH,
      endpoint_url: receivers.endpointFor(surface),
      authorization_header: 'Bearer from-before-771' };
    streams.touch(record);
    receivers.seedStreams();
    record = receivers.streamFor(ADMIN);
    note(record.delivery.method === streams.DELIVERY_POLL &&
         !record.delivery.authorization_header &&
         record.log.some(function (line) {
           return line.kind === 'delivery';
         }),
         'P1. a stream seeded as push to this service\'s own receive path ' +
         'before #771 is moved to poll by the next seeding, and says so on ' +
         'its log', JSON.stringify(record.delivery));
    const portalRecord = receivers.streamFor(receivers.PORTAL);
    portalRecord.delivery = { method: streams.DELIVERY_PUSH,
      endpoint_url: 'https://receiver.example/events' };
    streams.touch(portalRecord);
    receivers.seedStreams();
    note(receivers.streamFor(receivers.PORTAL).delivery.method ===
           streams.DELIVERY_PUSH,
         'P1. a push stream an operator pointed somewhere else is left ' +
         'alone');
    portalRecord.delivery = { method: streams.DELIVERY_POLL };
    streams.touch(portalRecord);

    // --- P2 ------------------------------------------------------------
    const pushed = receivers.accept(ADMIN, {
      headers: { authorization: 'Bearer anything',
                 'content-type': 'application/secevent+jwt' },
      body: 'x.y.z', res: {} });
    note(pushed.status === 400 && pushed.body.err === 'invalid_request' &&
         /poll/.test(pushed.body.description),
         'P2. a push to the receive endpoint of a poll stream is refused',
         JSON.stringify(pushed));

    // --- P3 ------------------------------------------------------------
    const URI = events.CAEP_PREFIX + 'session-revoked';
    const sent = [];
    for (let i = 0; i < 45; i++) {
      const report = await ssf.transmit(receivers.streamFor(ADMIN), {
        uri: URI, subject: { format: 'opaque', id: 'isp-' + i },
        payload: { event_timestamp: Math.floor(Date.now() / 1000) } });
      if (report.ok) {
        sent.push(report.jti);
      }
    }
    record = receivers.streamFor(ADMIN);
    note(sent.length === 45 && streams.queueOf(record).length === 45,
         'P3. forty-five SETs are queued on the console\'s poll stream',
         sent.length + ' sent, ' + streams.queueOf(record).length + ' queued');
    polls = 0;
    const first = await receivers.pollAll();
    const inbox = receivers.listFor(ADMIN, {});
    const ours = inbox.filter(function (one) {
      return sent.indexOf(one.jti) >= 0;
    });
    note(first.received === 45 && first.acknowledged === 45 &&
         first.refused === 0,
         'P3. the poll collects all forty-five and acknowledges each',
         JSON.stringify(first));
    note(polls >= 3 && polls <= 5,
         'P3. IN A HANDFUL OF REQUESTS — ssf.pollMaxEvents to each, then one ' +
         'that only acknowledges — where a push made forty-five', polls);
    note(streams.queueOf(receivers.streamFor(ADMIN)).length === 0,
         'P3. and the queue is empty: an acknowledged SET is off it',
         streams.queueOf(receivers.streamFor(ADMIN)).length);
    note(ours.length === 45 && ours.every(function (one) {
      return one.via === 'poll' && one.verified === true &&
             one.audienceOk && one.issuerOk && one.typOk;
    }),
         'P3. every one was verified, its typ, issuer and audience checked, ' +
         'and recorded as arrived by poll', JSON.stringify(ours.slice(0, 1)));

    // --- P4 ------------------------------------------------------------
    config.setOverride('ssf.receiveRequireSignature', 'true');
    record = receivers.streamFor(ADMIN);
    const forgedClaims = events.buildSet({ uri: URI, issuer: record.iss,
      audience: surface.audience, subject: { format: 'opaque', id: 'f' },
      payload: { event_timestamp: Math.floor(Date.now() / 1000) } });
    let forged = events.signSetSync(forgedClaims);
    forged = forged.slice(0, -4) + (forged.slice(-4) === 'AAAA' ? 'BBBB'
                                                                : 'AAAA');
    const elsewhereClaims = events.buildSet({ uri: URI, issuer: record.iss,
      audience: portal.audience, subject: { format: 'opaque', id: 'e' },
      payload: { event_timestamp: Math.floor(Date.now() / 1000) } });
    [[forgedClaims, forged],
     [elsewhereClaims, events.signSetSync(elsewhereClaims)]]
      .forEach(function (pair) {
      streams.enqueue(record, { jti: pair[0].jti, token: pair[1],
        claims: pair[0], queuedAt: new Date().toISOString(), deliveredAt: '',
        counted: false });
    });
    const second = await receivers.pollAll();
    const after = receivers.listFor(ADMIN, {});
    const forgedRow = after.filter(function (one) {
      return one.jti === forgedClaims.jti;
    })[0];
    const elsewhereRow = after.filter(function (one) {
      return one.jti === elsewhereClaims.jti;
    })[0];
    note(second.received === 2 && second.refused === 2 &&
         streams.queueOf(receivers.streamFor(ADMIN)).length === 0,
         'P4. a SET failing a check is refused in setErrs and taken off the ' +
         'queue, not handed out again on every poll', JSON.stringify(second));
    note(forgedRow && forgedRow.verified === false &&
         elsewhereRow && elsewhereRow.audienceOk === false,
         'P4. and both are recorded with what was wrong — an unverifiable ' +
         'signature, another surface\'s audience',
         JSON.stringify([forgedRow && forgedRow.verified,
                         elsewhereRow && elsewhereRow.audienceOk]));
    note(receivers.streamFor(ADMIN).log.some(function (line) {
      return line.kind === 'error' &&
             line.text.indexOf(forgedClaims.jti) >= 0;
    }), 'P4. the refusal is on the stream\'s own log, where a person sees it');
    config.setOverride('ssf.receiveRequireSignature', 'false');

    // --- P5 ------------------------------------------------------------
    const url = transport.loopbackOrigin() + '/ssf/poll';
    const asked = { stream_id: record.stream_id, maxEvents: 0,
                    returnImmediately: true };
    const secret = process.env.STS_SSF_RECEIVER_SECRET;
    const tokenFor = function (id) {
      return 'Bearer ' + stsCrypto.deriveSharedCredential(secret,
        'ssf-internal-receiver', realms.currentId(), id);
    };
    const none = await transport.pollOwn(url, asked, '', 1);
    const other = await transport.pollOwn(url, asked,
                                          tokenFor(receivers.PORTAL), 1);
    const own = await transport.pollOwn(url, asked, tokenFor(ADMIN), 1);
    note(none.status === 401 && other.status === 401 && own.status === 200 &&
         own.json && typeof own.json.sets === 'object',
         'P5. /ssf/poll for the console\'s stream refuses no credential and ' +
         'the portal\'s, and answers the console\'s own',
         JSON.stringify([none.status, other.status, own.status]));

    // --- P6 ------------------------------------------------------------
    polls = 0;
    const idle = await receivers.pollAll();
    note(polls === 0 && idle.requests === 0,
         'P6. a stream with nothing waiting is not dialled', polls);
    const away = await transport.pollOwn('https://receiver.example/ssf/poll',
                                         asked, tokenFor(ADMIN), 1);
    note(!away.ok && away.status === 0 && away.errorCode === 'STS-SSF-0142',
         'P6. pollOwn() dials this process\'s own loopback origin and ' +
         'nothing else', JSON.stringify(away));

    // --- P7 ------------------------------------------------------------
    const scheduler = require(ROOT + '/cluster/scheduler');
    const job = scheduler.job('ssf.internal-poll');
    note(job && job.everySetting === 'ssf.internalPollMs' &&
         (job.kind || 'cluster') === 'cluster',
         'P7. the poll is the ssf.internal-poll cluster job, every ' +
         'ssf.internalPollMs', JSON.stringify(job && { every:
           job.everySetting, kind: job.kind }));

    server.close();
    finish();
  })().catch(function (e) {
    note(false, 'the child threw', (e && e.stack) || e);
    finish();
  });
}

// A port nothing holds, for the child's `global.port`.
function freePort() {
  log.debug("Entering freePort().");
  return new Promise(function (resolve) {
    const probe = net.createServer();
    probe.listen(0, '127.0.0.1', function () {
      const port = probe.address().port;
      probe.close(function () {
        log.debug("Leaving freePort().");
        resolve(port);
      });
    });
  });
}

async function run(t) {
  log.debug("Entering run().");
  const root = path.join(__dirname, '..');
  const out = path.join(os.tmpdir(), 'sts-isp-' + process.pid + '-' +
                                     Date.now() + '.json');
  const port = await freePort();
  const env = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|SSF_|CAEP_|RISC_|CONFIG_FILE$)/.test(key)) {
      env[key] = process.env[key];
    }
  });
  Object.assign(env, { ISP_OUT: out, ISP_ROOT: root, LOG_LEVEL: 'fatal',
    STS_LOG_LEVEL: 'fatal', STS_PORT: String(port), STS_HTTPS: 'false' });
  const result = await new Promise(function (resolve) {
    childProcess.execFile(process.execPath,
      ['-e', '(' + child.toString() + ')()'], {
        cwd: root, env: env, encoding: 'utf8', timeout: 180000,
        maxBuffer: 64 * 1024 * 1024 }, function (error, stdout, stderr) {
        resolve({ status: error ? error.code : 0, stderr: stderr });
      });
  });
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
  name: 'internal_signals_poll',
  describe: 'this service\'s own two receivers collect by RFC 8936 poll, ' +
            'many SETs to a request, and still check every one (#771)',
  run: run
};
