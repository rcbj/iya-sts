// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: ssf_application_settings.js
//
// ===========================================================================
// A SHARED SIGNALS STREAM IS SENT WITH ITS OWNING APPLICATION'S SETTINGS
// (2026-10-01).
//
// An application entry may override twenty caep.*, risc.* and ssf.* settings
// for the streams it creates at /ssf/stream (`common/applications.js`'s
// ssfCaep*, ssfRisc* and ssf* rows). A stream's owner is its `createdBy`,
// matched by identifier or by `ssfReceiverId`. What is asserted is that an
// override reaches the stream it is for, does not reach a stream it is not
// for, and is refused at the write when the setting could not hold it:
//
//   A. strictOverrideProblem(): a value the setting does not take, an
//      algorithm outside its enum and a reason language that is not a BCP 47
//      tag are refused, and a create or an update carrying one writes nothing;
//   B. ssfSettingFor(): the application's value by identifier and by receiver
//      id, the setting's for anybody else and for a key nobody overrides;
//   C. ssfOverrideRows() names every override row, each a real setting;
//   D. ssf.maxStreams per owner: one stream for the application, a second
//      refused as a LIMIT, while another receiver still gets the service's
//      (the count is per creating principal, as it always was);
//   E. ONE CAEP payload sent to two streams: the application's SET is signed
//      ES256, carries no event_timestamp and its reasons keyed "fr"; the
//      control's is the service's algorithm, timestamped and keyed "en"; the
//      payload handed in is untouched; ssf.pollMaxEvents caps the owner's poll;
//   F. ssf.pushRetries against a real receiver that always answers 500: the
//      owner's stream is pushed once, the control's three times.
//
// In a CHILD PROCESS: it sets SSF settings, requires the whole family and
// listens on a port.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'ssf_application_settings',
  level: process.env.LOG_LEVEL || 'info' });

// Runs in the child. Stringified, so it may use nothing from this file's scope.
function child() {
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };
  const OUT = process.env.SSF_APP_CHILD_OUT;
  const ROOT = process.env.SSF_APP_CHILD_ROOT;
  const http = require('http');
  const finish = function () {
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  };
  const decode = function (token) {
    const parts = String(token).split('.');
    return { header: JSON.parse(Buffer.from(parts[0], 'base64url')
                                  .toString('utf8')),
             claims: JSON.parse(Buffer.from(parts[1], 'base64url')
                                  .toString('utf8')) };
  };
  (async function () {
    const config = require(ROOT + '/common/config');
    [['ssf.enabled', 'true'], ['caep.enabled', 'true'],
     ['ssf.defaultSubjects', 'ALL'], ['ssf.maxStreams', '5'],
     ['ssf.minVerificationInterval', '0'], ['ssf.pollMaxEvents', '20'],
     ['ssf.signingAlgorithm', 'RS256'], ['caep.includeReasons', 'true'],
     ['caep.reasonLanguage', 'en'], ['caep.omitEventTimestamp', 'false'],
     ['ssf.pushDelivery', 'true'], ['ssf.pushAllowHttp', 'true'],
     ['ssf.pushRetries', '2'], ['ssf.pushRetryDelayMs', '10'],
     ['ssf.pushTimeoutMs', '3000']].forEach(function (pair) {
      try {
        config.setOverride(pair[0], pair[1]);
      } catch (e) {
        note(false, 'setting ' + pair[0] + ' is accepted', e.message);
      }
    });
    require(ROOT + '/common/app');
    require(ROOT + '/admin-ui/admin');
    require(ROOT + '/ldap/ldap_server');
    const applications = require(ROOT + '/common/applications');
    const streams = require(ROOT + '/ssf/ssf_streams');
    const events = require(ROOT + '/ssf/ssf_events');
    const caep = require(ROOT + '/ssf/caep');
    const ssf = require(ROOT + '/ssf/ssf');
    const REVOKED = events.CAEP_PREFIX + 'session-revoked';
    const ISSUER = 'https://sts.test';

    // =====================================================================
    // A. THE WRITE-TIME REFUSALS.
    // =====================================================================
    note(applications.strictOverrideProblem('ssfCaepReasonLanguage',
                                            'fr-CA') === '' &&
         applications.strictOverrideProblem('ssfSigningAlgorithm',
                                            'ES256') === '' &&
         applications.strictOverrideProblem('ssfMaxStreams', '3') === '' &&
         applications.strictOverrideProblem('ssfMaxStreams', '') === '',
         'A. a tag, an algorithm the setting takes, a number and a clear are ' +
         'allowed');
    note(/BCP 47/.test(applications.strictOverrideProblem(
           'ssfCaepReasonLanguage', 'not a tag')),
         'A. A REASON LANGUAGE THAT IS NOT A BCP 47 TAG IS REFUSED — it is ' +
         'the key of reason_admin and reason_user');
    note(applications.strictOverrideProblem('ssfSigningAlgorithm', 'HS256')
           !== '' &&
         applications.strictOverrideProblem('ssfMaxStreams', 'many') !== '' &&
         applications.strictOverrideProblem('ssfCaepIncludeReasons',
                                            'perhaps') !== '',
         'A. an algorithm outside the setting\'s enum, a number that is not ' +
         'one and a boolean that is not one are refused');
    const badCreate = applications.createApplication({
      identifier: 'ssfset-bad', protocols: ['ssf'],
      fields: { ssfSigningAlgorithm: 'none' } });
    note(!badCreate.ok && !applications.list().some(function (one) {
      return one.identifier === 'ssfset-bad';
    }), 'A. A CREATE CARRYING AN UNUSABLE OVERRIDE IS REFUSED AND NOTHING ' +
         'IS MADE', JSON.stringify(badCreate.errors));

    // =====================================================================
    // B. WHAT AN OWNER IS SENT WITH.
    // =====================================================================
    const made = applications.createApplication({
      identifier: 'ssfset-app', kinds: ['ssf-receiver'], protocols: ['ssf'],
      fields: { ssfReceiverId: ['ssfset-receiver'],
                ssfCaepReasonLanguage: 'fr',
                ssfCaepOmitEventTimestamp: 'TRUE',
                ssfSigningAlgorithm: 'ES256',
                ssfMaxStreams: '1', ssfPollMaxEvents: '1',
                ssfPushRetries: '0' } });
    note(made.ok, 'B. an application carrying seven overrides is created',
         JSON.stringify(made.errors));
    const badUpdate = applications.updateApplication('ssfset-app',
      { attribute: 'ssfCaepReasonLanguage', mode: 'set', value: '!!' });
    note(!badUpdate.ok &&
         applications.ssfSettingFor('ssfset-app', 'caep.reasonLanguage')
           .value === 'fr',
         'A. AN UPDATE TO AN UNUSABLE VALUE IS REFUSED AND THE STORED ONE ' +
         'STANDS', JSON.stringify(badUpdate.errors));
    const byId = applications.ssfSettingFor('ssfset-app',
                                            'ssf.signingAlgorithm');
    const byReceiver = applications.ssfSettingFor('ssfset-receiver',
                                                  'ssf.signingAlgorithm');
    note(byId.source === 'application' && byId.value === 'ES256' &&
         byReceiver.source === 'application' && byReceiver.value === 'ES256',
         'B. the application\'s value, by identifier and by ssfReceiverId',
         JSON.stringify([byId, byReceiver]));
    const omit = applications.ssfSettingFor('ssfset-app',
                                            'caep.omitEventTimestamp');
    note(omit.source === 'application' && omit.value === true,
         'B. a boolean override is read as a boolean', JSON.stringify(omit));
    const stranger = applications.ssfSettingFor('ssfset-nobody',
                                                'ssf.signingAlgorithm');
    const notOverridden = applications.ssfSettingFor('ssfset-app',
                                                     'ssf.inactivityAction');
    note(stranger.source === 'setting' && stranger.value === 'RS256' &&
         notOverridden.source === 'setting',
         'B. THE SETTING DECIDES for a principal no application answers to ' +
         'and for a key the application does not override',
         JSON.stringify([stranger, notOverridden]));

    // =====================================================================
    // C. THE ROWS.
    // =====================================================================
    const rows = applications.ssfOverrideRows();
    note(rows.length === 20 && rows.every(function (one) {
      let known = false;
      try {
        config.value(one.setting);
        known = true;
      } catch (e) {
        // An unknown key throws; it is reported below as the row failing.
        known = false;
      }
      return /^(caep|risc|ssf)\./.test(one.setting) && known &&
        /^ssf[A-Z]/.test(one.attribute);
    }), 'C. twenty override rows, each a real caep, risc or ssf setting',
         JSON.stringify(rows.map(function (one) { return one.setting; })));

    // =====================================================================
    // D. ssf.maxStreams PER OWNER.
    // =====================================================================
    const poll = { delivery: { method: streams.DELIVERY_POLL },
                   events_requested: [REVOKED] };
    const own1 = streams.createStream(poll, { issuer: ISSUER,
                                              principal: 'ssfset-app' });
    const own2 = streams.createStream(poll, { issuer: ISSUER,
                                              principal: 'ssfset-app' });
    const plain1 = streams.createStream(poll, { issuer: ISSUER,
                                                principal: 'ssfset-plain' });
    const plain2 = streams.createStream(poll, { issuer: ISSUER,
                                                principal: 'ssfset-plain' });
    note(own1.ok && !own2.ok && own2.limit && plain1.ok && plain2.ok,
         'D. THE OWNER\'S ssfMaxStreams OF 1 REFUSES ITS SECOND STREAM, ' +
         'while another receiver gets the service\'s five', JSON.stringify([own1.ok, own2.errors, plain1.ok,
                                            plain2.ok]));
    if (!own1.ok || !plain1.ok) {
      return finish();
    }
    const ownStream = own1.stream;
    const plainStream = plain1.stream;

    // =====================================================================
    // E. ONE PAYLOAD, TWO STREAMS.
    // =====================================================================
    const payload = caep.buildPayload(REVOKED, {}, {
      reasonAdmin: 'Session ended by policy', reasonUser: 'You were signed out',
      initiatingEntity: 'policy' });
    const before = JSON.stringify(payload);
    const subject = { format: 'opaque', id: 'ssfset-session' };
    const sentOwn = await ssf.transmit(streams.getStream(ownStream.stream_id),
      { uri: REVOKED, payload: payload, subject: subject });
    const sentPlain = await ssf.transmit(
      streams.getStream(plainStream.stream_id),
      { uri: REVOKED, payload: payload, subject: subject });
    note(sentOwn.ok && sentPlain.ok, 'E. both streams are sent the event',
         JSON.stringify([sentOwn.why, sentPlain.why]));
    note(JSON.stringify(payload) === before,
         'E. THE PAYLOAD HANDED IN IS UNTOUCHED — every other stream is sent ' +
         'it as it was built');
    const findSet = function (stream) {
      return streams.queueOf(streams.getStream(stream.stream_id))
        .map(function (one) { return one.token; })
        .map(decode).filter(function (one) {
          return one.claims.events && one.claims.events[REVOKED];
        })[0];
    };
    const ownSet = findSet(ownStream);
    const plainSet = findSet(plainStream);
    if (!ownSet || !plainSet) {
      note(false, 'E. each stream holds its session-revoked SET',
           JSON.stringify([!!ownSet, !!plainSet]));
      return finish();
    }
    const ownEvent = ownSet.claims.events[REVOKED];
    const plainEvent = plainSet.claims.events[REVOKED];
    note(ownSet.header.alg === 'ES256' && plainSet.header.alg === 'RS256',
         'E. THE OWNER\'S SET IS SIGNED ES256 AND THE CONTROL\'S RS256',
         ownSet.header.alg + ' / ' + plainSet.header.alg);
    note(ownEvent.event_timestamp === undefined &&
         typeof plainEvent.event_timestamp === 'number',
         'E. THE OWNER\'S EVENT CARRIES NO event_timestamp; the control\'s ' +
         'does', JSON.stringify([ownEvent.event_timestamp,
                                 plainEvent.event_timestamp]));
    note(ownEvent.reason_admin && ownEvent.reason_admin.fr ===
           'Session ended by policy' && !ownEvent.reason_admin.en &&
         ownEvent.reason_user && ownEvent.reason_user.fr ===
           'You were signed out',
         'E. THE OWNER\'S REASONS ARE OBJECTS KEYED "fr" (CAEP 1.0 section ' +
         '2: a language tag, never a bare string)',
         JSON.stringify([ownEvent.reason_admin, ownEvent.reason_user]));
    note(plainEvent.reason_admin && plainEvent.reason_admin.en ===
           'Session ended by policy' &&
         plainEvent.initiating_entity === 'policy' &&
         ownEvent.initiating_entity === 'policy',
         'E. the control\'s reasons are keyed "en", and initiating_entity is ' +
         'on both', JSON.stringify([plainEvent, ownEvent.initiating_entity]));
    await ssf.transmit(streams.getStream(ownStream.stream_id),
      { uri: REVOKED, payload: payload, subject: subject });
    const queued = streams.queueOf(streams.getStream(ownStream.stream_id))
      .length;
    const polled = streams.poll(streams.getStream(ownStream.stream_id),
                                { maxEvents: 10 });
    note(queued >= 2 && Object.keys(polled.sets).length === 1,
         'E. THE OWNER\'S ssfPollMaxEvents OF 1 CAPS A POLL ASKING FOR TEN',
         'queued=' + queued + ' handed=' + Object.keys(polled.sets).length);

    // =====================================================================
    // F. PUSH RETRIES, AGAINST A RECEIVER THAT ALWAYS FAILS.
    // =====================================================================
    const hits = { own: 0, plain: 0 };
    const server = http.createServer(function (req, res) {
      const which = req.url.indexOf('/own') === 0 ? 'own' : 'plain';
      req.on('data', function () {});
      req.on('end', function () {
        hits[which] += 1;
        res.writeHead(500);
        res.end();
      });
    });
    await new Promise(function (resolve) {
      server.listen(0, '127.0.0.1', resolve);
    });
    const base = 'http://127.0.0.1:' + server.address().port;
    const push = function (pathPart) {
      return { delivery: { method: streams.DELIVERY_PUSH,
                           endpoint_url: base + pathPart },
               events_requested: [REVOKED] };
    };
    // The application's one stream is the poll stream above; the push stream
    // is made by a second application carrying only the retry override.
    const pushApp = applications.createApplication({
      identifier: 'ssfset-push', protocols: ['ssf'],
      fields: { ssfPushRetries: '0', ssfPushRetryDelayMs: '10' } });
    note(pushApp.ok, 'F. an application overriding ssf.pushRetries is made',
         JSON.stringify(pushApp.errors));
    const ownPush = streams.createStream(push('/own'),
      { issuer: ISSUER, principal: 'ssfset-push' });
    const plainPush = streams.createStream(push('/plain'),
      { issuer: ISSUER, principal: 'ssfset-plain-push' });
    if (!ownPush.ok || !plainPush.ok) {
      note(false, 'F. both push streams are created',
           JSON.stringify([ownPush.errors, plainPush.errors]));
      server.close();
      return finish();
    }
    hits.own = 0;
    hits.plain = 0;
    await ssf.transmit(streams.getStream(ownPush.stream.stream_id),
      { uri: REVOKED, payload: payload, subject: subject });
    await ssf.transmit(streams.getStream(plainPush.stream.stream_id),
      { uri: REVOKED, payload: payload, subject: subject });
    note(hits.own === 1 && hits.plain === 3,
         'F. THE OWNER\'S ssfPushRetries OF 0 PUSHES ONCE; the control ' +
         'retries twice after the first', JSON.stringify(hits));
    server.close();
    finish();
  })().catch(function (e) {
    note(false, 'the child ran to the end', e && e.stack);
    finish();
  });
}

function run(t) {
  log.debug("Entering run().");
  const root = path.join(__dirname, '..');
  const out = path.join(os.tmpdir(), 'sts-ssf-app-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = Object.assign({}, process.env, {
    SSF_APP_CHILD_OUT: out, SSF_APP_CHILD_ROOT: root, LOG_LEVEL: 'fatal' });
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
  name: 'ssf_application_settings',
  describe: 'a Shared Signals stream is sent with its owning application\'s ' +
            'caep, risc and ssf overrides, and an unusable override is ' +
            'refused at the write',
  run: run
};
