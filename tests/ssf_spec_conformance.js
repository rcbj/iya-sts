'use strict';
//
// File: ssf_spec_conformance.js
//
// ===========================================================================
// THE SHARED SIGNALS FRAMEWORK 1.0 FINAL TEXT, HELD TO WHAT #144 FOUND
// (2026-09-22).
//
// A read of SSF 1.0 final and RFC 9493 against the code found the transmitter
// wrong in ways no test had asked about, because every test was written from
// the code:
//
//   A. THE SUBJECT GRAMMAR. RFC 9493's registered names are `iss_sub` and
//      `did`, not the drafts' `issuer_subject_id` and
//      `decentralized_identifier`; a complex subject carries
//      `"format": "complex"` and may carry `application` and additional
//      members (SSF 1.0 section 3.3); section 3.5 adds `jwt_id`,
//      `saml_assertion_id` and `ip-addresses`.
//   B. OWNERSHIP (section 8). A stream is its creator's; another's is not
//      found; a list is the caller's own; this service's own receiver streams
//      are nobody's, whatever they were created as; `ssf.maxStreams` is per
//      receiver.
//   C. `aud` IS TRANSMITTER-SUPPLIED (section 8.1.1): the receiver's own
//      identifier unless it names another it is associated with, and an update
//      may carry a Transmitter-Supplied member only unchanged — a refused one
//      changes nothing.
//   D. STATUS CHANGES IN SECTION 8.1.5's ORDER, against a real push receiver:
//      stream-updated BEFORE a stream stops and after it starts; a paused push
//      stream HOLDS (it pushed until #144) and delivers in order when enabled;
//      SSF's own two events go on a stream that did not agree them; every SET
//      carries a `txn`.
//   E. A STOPPED POLL STREAM hands out its stream-updated events and nothing
//      else, and a disable keeps them when it drops the rest.
//   F. STREAM MAINTENANCE: the inactivity timeout pauses and announces, a
//      transmitter-initiated verification carries no state, the timeout is
//      published, and the internal streams are left alone.
//
// In a CHILD PROCESS: it sets SSF settings, requires the whole family and
// listens on a port.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'ssf_spec_conformance',
  level: process.env.LOG_LEVEL || 'info' });

// Runs in the child. Stringified, so it may use nothing from this file's scope.
function child() {
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };
  const OUT = process.env.SSF_SPEC_CHILD_OUT;
  const ROOT = process.env.SSF_SPEC_CHILD_ROOT;
  const http = require('http');
  const finish = function () {
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  };
  const claimsOf = function (token) {
    const parts = String(token).split('.');
    return { header: JSON.parse(Buffer.from(parts[0], 'base64url')
                                  .toString('utf8')),
             claims: JSON.parse(Buffer.from(parts[1], 'base64url')
                                  .toString('utf8')) };
  };
  const typeOf = function (claims) {
    return Object.keys(claims.events || {})[0] || '';
  };
  (async function () {
    const config = require(ROOT + '/common/config');
    [['ssf.enabled', 'true'], ['ssf.pushDelivery', 'true'],
     ['ssf.pushAllowInsecure', 'true'], ['ssf.maxStreams', '2'],
     ['ssf.pushTimeoutMs', '3000'], ['ssf.minVerificationInterval', '0']]
      .forEach(function (pair) {
      try {
        config.setOverride(pair[0], pair[1]);
      } catch (e) {
        note(false, 'setting ' + pair[0] + ' is accepted', e.message);
      }
    });
    require(ROOT + '/common/app');
    const subjects = require(ROOT + '/ssf/ssf_subjects');
    const streams = require(ROOT + '/ssf/ssf_streams');
    const events = require(ROOT + '/ssf/ssf_events');
    const ssf = require(ROOT + '/ssf/ssf');
    const VERIFY = events.SSF_PREFIX + 'verification';
    const UPDATED = events.SSF_PREFIX + 'stream-updated';
    const CAEP_REVOKED = events.CAEP_PREFIX + 'session-revoked';
    const ISSUER = 'https://sts.test';

    // =====================================================================
    // A. THE SUBJECT GRAMMAR.
    // =====================================================================
    const ok = function (subject) {
      return subjects.validateSubjectId(subject, {}).ok;
    };
    note(ok({ format: 'iss_sub', iss: 'https://i.example', sub: '1' }) &&
         ok({ format: 'did', url: 'did:example:123' }),
         'A. RFC 9493\'s registered names — iss_sub and did — are accepted');
    note(!ok({ format: 'issuer_subject_id', iss: 'https://i.example',
               sub: '1' }) &&
         !ok({ format: 'decentralized_identifier', url: 'did:example:1' }),
         'A. AND THE DRAFTS\' NAMES ARE REFUSED — no receiver that follows ' +
         'the registry sends or takes them');
    const complexOk = { format: 'complex',
      user: { format: 'iss_sub', iss: 'https://i.example', sub: '1' },
      session: { format: 'opaque', id: 's' },
      application: { format: 'opaque', id: 'app-1' },
      custom_member: { format: 'email', email: 'a@b.example' } };
    const complexVerdict = subjects.validateSubjectId(complexOk, {});
    note(complexVerdict.ok && complexVerdict.complex,
         'A. a complex subject with "format": "complex", the seventh member ' +
         '(application) and an ADDITIONAL member name is accepted (SSF 1.0 ' +
         'section 3.3)', JSON.stringify(complexVerdict.errors));
    const draftComplex = subjects.validateSubjectId({
      user: { format: 'iss_sub', iss: 'https://i.example', sub: '1' },
      session: { format: 'opaque', id: 's' } }, {});
    note(!draftComplex.ok && /complex/.test(draftComplex.errors.join(' ')),
         'A. A COMPLEX SUBJECT WITHOUT ITS FORMAT IS REFUSED, naming the ' +
         'final text\'s shape — it was the only shape accepted until #144',
         JSON.stringify(draftComplex.errors));
    note(!ok({ format: 'complex', user: { format: 'complex',
      session: { format: 'opaque', id: 's' } } }),
         'A. a complex subject nested inside another is refused');
    note(ok({ format: 'jwt_id', iss: 'https://i.example', jti: 'j-1' }) &&
         ok({ format: 'saml_assertion_id', issuer: 'https://i.example',
              assertion_id: '_a1' }) &&
         ok({ format: 'ip-addresses',
              'ip-addresses': ['10.0.0.1', '2001:db8::1'] }),
         'A. section 3.5\'s three formats are accepted');
    note(!ok({ format: 'ip-addresses', 'ip-addresses': ['10.0.0.1/24'] }) &&
         !ok({ format: 'ip-addresses', 'ip-addresses': [] }) &&
         !ok({ format: 'jwt_id', iss: 'https://i.example' }),
         'A. and their rules hold: an address that is not one, an empty ' +
         'list and a missing jti are refused');
    const built = subjects.complexSubject({ user: { format: 'opaque',
      id: 'u' }, device: null });
    note(built.format === 'complex' && !('device' in built),
         'A. complexSubject() adds the format and drops an empty member',
         JSON.stringify(built));
    note(subjects.subjectForUser('alice', 'iss_sub', ISSUER).format ===
           'iss_sub' &&
         subjects.subjectForUser('alice', 'jwt_id', ISSUER).format ===
           'iss_sub',
         'A. subjectForUser() names a person in iss_sub, and never in a ' +
         'token\'s or an address\'s format');

    // =====================================================================
    // B. OWNERSHIP.
    // =====================================================================
    const poll = { delivery: { method: streams.DELIVERY_POLL } };
    const a1 = streams.createStream(poll, { issuer: ISSUER,
                                            principal: 'client-a' });
    const a2 = streams.createStream(poll, { issuer: ISSUER,
                                            principal: 'client-a' });
    const a3 = streams.createStream(poll, { issuer: ISSUER,
                                            principal: 'client-a' });
    const b1 = streams.createStream(poll, { issuer: ISSUER,
                                            principal: 'client-b' });
    note(a1.ok && a2.ok && !a3.ok && a3.limit && b1.ok,
         'B. ssf.maxStreams IS PER RECEIVER: a third stream for client-a is ' +
         'refused as a LIMIT while client-b can still create one',
         JSON.stringify([a1.ok, a2.ok, a3.errors, b1.ok]));
    note(streams.streamOwnedBy(a1.stream.stream_id, 'client-a') ===
           a1.stream &&
         streams.streamOwnedBy(a1.stream.stream_id, 'client-b') === null,
         'B. a stream is its creator\'s, and another receiver finds nothing');
    const listed = streams.streamsOwnedBy('client-a').map(function (one) {
      return one.stream_id;
    }).sort();
    note(JSON.stringify(listed) === JSON.stringify(
           [a1.stream.stream_id, a2.stream.stream_id].sort()),
         'B. a receiver\'s list is its own streams and nobody else\'s',
         JSON.stringify(listed));
    const internal = streams.createStream(poll, { issuer: ISSUER,
      principal: 'internal', audience: 'sts-admin-console',
      internalSurface: 'admin-console',
      streamId: 'ssf-internal-probe-admin-console' });
    note(internal.ok && streams.isInternal(internal.stream) &&
         streams.streamOwnedBy('ssf-internal-probe-admin-console',
                               'internal') === null &&
         streams.streamsOwnedBy('internal').length === 0,
         'B. THIS SERVICE\'S OWN STREAM IS NOBODY\'S — not even a caller ' +
         'authenticated as the principal it was created under, which any ' +
         'Basic username can be in development');
    note(streams.ownedBy(a1.stream, '') === false &&
         streams.ownedBy(a1.stream, '(unauthenticated)') === false,
         'B. and nobody unauthenticated owns anything');

    // =====================================================================
    // C. `aud`.
    // =====================================================================
    note(b1.stream.aud === 'client-b',
         'C. A STREAM\'S aud IS THE RECEIVER\'S OWN IDENTIFIER when it names ' +
         'none — Transmitter-Supplied (section 8.1.1)', b1.stream.aud);
    config.setOverride('ssf.maxStreams', '10');
    const foreign = streams.createStream(Object.assign({ aud:
      'https://someone-else.example' }, poll), { issuer: ISSUER,
                                                 principal: 'client-c' });
    note(!foreign.ok && /not associated/.test(foreign.errors.join(' ')),
         'C. AN aud THE RECEIVER IS NOT ASSOCIATED WITH IS REFUSED — ' +
         'otherwise one receiver could have events addressed to another',
         JSON.stringify(foreign.errors));
    const own = streams.createStream(Object.assign({ aud: ['client-c'] },
      poll), { issuer: ISSUER, principal: 'client-c' });
    note(own.ok && JSON.stringify(own.stream.aud) === '["client-c"]',
         'C. an aud naming only the receiver itself, as an array, is kept ' +
         'as sent', JSON.stringify(own.stream && own.stream.aud));
    const before = JSON.stringify(streams.streamConfiguration(b1.stream, {}));
    const changedAud = streams.updateStream(b1.stream.stream_id,
      { aud: 'client-z', description: 'changed' }, 'merge', {});
    note(!changedAud.ok &&
         /Transmitter-Supplied/.test(changedAud.errors.join(' ')) &&
         JSON.stringify(streams.streamConfiguration(b1.stream, {})) ===
           before,
         'C. A PATCH CHANGING aud IS REFUSED (section 8.1.1.3: it MUST match) ' +
         'AND CHANGES NOTHING — not even the description beside it',
         JSON.stringify(changedAud.errors));
    const sameAud = streams.updateStream(b1.stream.stream_id,
      { aud: 'client-b', description: 'changed' }, 'merge', {});
    note(sameAud.ok && sameAud.stream.description === 'changed',
         'C. while one carrying it unchanged is accepted');
    const wrongDelivered = streams.updateStream(b1.stream.stream_id,
      { events_delivered: ['urn:x'] }, 'merge', {});
    note(!wrongDelivered.ok,
         'C. and so is every other Transmitter-Supplied member: a mismatched ' +
         'events_delivered is refused');
    const put = streams.updateStream(b1.stream.stream_id,
      { stream_id: b1.stream.stream_id }, 'replace', {});
    note(put.ok && put.stream.aud === 'client-b',
         'C. a PUT omitting aud leaves it — it is not a Receiver-Supplied ' +
         'member, so omitting it is not asking for it to be deleted');

    // =====================================================================
    // D. STATUS CHANGES AND A PUSH RECEIVER.
    // =====================================================================
    const pushed = [];
    const receiver = http.createServer(function (req, res) {
      let body = '';
      req.on('data', function (c) { body += c; });
      req.on('end', function () {
        pushed.push(claimsOf(body.trim()));
        res.writeHead(202);
        res.end();
      });
    });
    await new Promise(function (resolve) {
      receiver.listen(0, '127.0.0.1', resolve);
    });
    const url = 'http://127.0.0.1:' + receiver.address().port + '/events';
    const push = streams.createStream({
      events_requested: [CAEP_REVOKED],
      delivery: { method: streams.DELIVERY_PUSH, endpoint_url: url } },
      { issuer: ISSUER, principal: 'client-d' });
    note(push.ok && push.stream.events_delivered.indexOf(VERIFY) < 0,
         'D. a push stream agreeing only session-revoked is created',
         JSON.stringify(push.errors));
    const p = push.stream;
    const v1 = await ssf.transmit(p, { uri: VERIFY, payload: {} });
    note(v1.delivered && pushed.length === 1 &&
         typeOf(pushed[0].claims) === VERIFY,
         'D. SSF\'S OWN VERIFICATION EVENT GOES ON A STREAM THAT DID NOT ' +
         'AGREE IT (section 8.1.4: MAY) — it was refused until #144',
         JSON.stringify(v1.why || ''));
    note(pushed[0].claims.txn && pushed[0].header.typ === 'secevent+jwt',
         'D. and the SET carries a txn (section 4.1.9, SHOULD) and is ' +
         'explicitly typed', JSON.stringify(pushed[0].header));
    note(JSON.stringify(pushed[0].claims.sub_id) === JSON.stringify(
           { format: 'opaque', id: p.stream_id }),
         'D. AND ITS sub_id NAMES THE STREAM, opaque (sections 8.1.4.1 and ' +
         '3.1) — SSF\'s own events carried no sub_id at all until #144',
         JSON.stringify(pushed[0].claims.sub_id));

    const paused = await ssf.changeStatus(p, 'paused', 'testing');
    const afterPause = pushed.slice(1);
    note(paused.ok && streams.getStream(p.stream_id).status === 'paused' &&
         afterPause.length === 1 && typeOf(afterPause[0].claims) === UPDATED &&
         afterPause[0].claims.events[UPDATED].status === 'paused',
         'D. PAUSING SENDS stream-updated (status paused) BEFORE THE STREAM ' +
         'STOPS, whether or not the stream agreed that type (section 8.1.5)',
         JSON.stringify(afterPause.map(function (one) {
           return one.claims.events;
         })));
    const heldReport = await ssf.transmit(streams.getStream(p.stream_id),
                                          { uri: VERIFY,
                                            payload: { state: 'held-1' } });
    note(heldReport.ok && heldReport.held && pushed.length === 2 &&
         streams.queueOf(streams.getStream(p.stream_id)).length === 1,
         'D. A PAUSED PUSH STREAM HOLDS WHAT IT IS GIVEN — nothing is pushed ' +
         '(section 8.1.2.1: MUST NOT transmit); until #144 it pushed anyway',
         JSON.stringify({ report: heldReport.why, pushed: pushed.length }));
    const unchanged = await ssf.changeStatus(streams.getStream(p.stream_id),
                                             'paused', 'again');
    note(unchanged.ok && unchanged.report === null && pushed.length === 2,
         'D. setting the status a stream already has announces nothing');
    const enabled = await ssf.changeStatus(streams.getStream(p.stream_id),
                                           'enabled', 'back');
    const afterEnable = pushed.slice(2).map(function (one) {
      return typeOf(one.claims) + (one.claims.events[UPDATED]
        ? ':' + one.claims.events[UPDATED].status
        : ':' + ((one.claims.events[VERIFY] || {}).state || ''));
    });
    note(enabled.ok &&
         JSON.stringify(afterEnable) === JSON.stringify(
           [UPDATED + ':enabled', VERIFY + ':held-1']) &&
         streams.queueOf(streams.getStream(p.stream_id)).length === 0,
         'D. ENABLING SENDS stream-updated (status enabled) AND THEN PUSHES ' +
         'WHAT WAS HELD, in that order', JSON.stringify(afterEnable));

    // =====================================================================
    // E. A STOPPED POLL STREAM.
    // =====================================================================
    const pollStream = streams.createStream({ delivery: {
      method: streams.DELIVERY_POLL }, events_requested: [CAEP_REVOKED] },
      { issuer: ISSUER, principal: 'client-e' }).stream;
    await ssf.transmit(pollStream, { uri: VERIFY, payload: { state: 'e1' } });
    await ssf.changeStatus(pollStream, 'paused', 'poll pause');
    const pollPaused = streams.poll(streams.getStream(pollStream.stream_id),
                                    { maxEvents: 10 });
    const pausedTypes = Object.keys(pollPaused.sets).map(function (jti) {
      return typeOf(claimsOf(pollPaused.sets[jti]).claims);
    });
    note(JSON.stringify(pausedTypes) === JSON.stringify([UPDATED]),
         'E. A PAUSED POLL STREAM HANDS OUT ITS stream-updated EVENT AND ' +
         'NOTHING ELSE — the verification queued before the pause waits',
         JSON.stringify(pausedTypes));
    await ssf.changeStatus(streams.getStream(pollStream.stream_id),
                           'disabled', 'poll disable');
    const disabledQueue = streams.queueOf(
      streams.getStream(pollStream.stream_id)).map(function (one) {
        return typeOf(one.claims) +
               (one.claims.events[UPDATED]
                 ? ':' + one.claims.events[UPDATED].status : '');
      });
    note(disabledQueue.indexOf(VERIFY) < 0 &&
         disabledQueue.indexOf(UPDATED + ':disabled') >= 0,
         'E. A DISABLE DROPS THE QUEUE BUT KEEPS THE stream-updated THAT ' +
         'ANNOUNCES IT — on poll, "sent before stopping" means collectable',
         JSON.stringify(disabledQueue));

    // =====================================================================
    // F. STREAM MAINTENANCE.
    // =====================================================================
    config.setOverride('ssf.inactivityTimeoutS', '100');
    config.setOverride('ssf.inactivityAction', 'pause');
    const idle = streams.createStream({ delivery: {
      method: streams.DELIVERY_POLL } },
      { issuer: ISSUER, principal: 'client-f' }).stream;
    note(streams.streamConfiguration(idle, {}).inactivity_timeout === 100 &&
         streams.streamConfiguration(internal.stream, {})
           .inactivity_timeout === undefined,
         'F. inactivity_timeout is published on a receiver\'s stream, and ' +
         'not on this service\'s own');
    idle.lastActivityAt = Math.floor(Date.now() / 1000) - 500;
    streams.touch(idle);
    const busy = streams.getStream(a1.stream.stream_id);
    busy.lastActivityAt = Math.floor(Date.now() / 1000);
    streams.touch(busy);
    const internalRecord = streams.getStream(internal.stream.stream_id);
    internalRecord.lastActivityAt = 0;
    streams.touch(internalRecord);
    const summary = await ssf.maintainStreams();
    const idleNow = streams.getStream(idle.stream_id);
    const idleQueue = streams.queueOf(idleNow).map(function (one) {
      return typeOf(one.claims);
    });
    note(idleNow.status === 'paused' && idleQueue.indexOf(UPDATED) >= 0 &&
         streams.getStream(a1.stream.stream_id).status === 'enabled' &&
         streams.getStream(internal.stream.stream_id).status === 'enabled',
         'F. AN INACTIVE STREAM IS PAUSED AND ANNOUNCED; an active one and ' +
         'this service\'s own are left alone',
         JSON.stringify({ summary: summary, idle: idleNow.status,
                          queue: idleQueue }));
    config.setOverride('ssf.inactivityTimeoutS', '0');
    config.setOverride('ssf.verificationEveryS', '60');
    const due = streams.getStream(a2.stream.stream_id);
    due.lastTransmitterVerificationAt = Math.floor(Date.now() / 1000) - 3600;
    streams.touch(due);
    const recent = streams.getStream(b1.stream.stream_id);
    recent.lastTransmitterVerificationAt = Math.floor(Date.now() / 1000);
    streams.touch(recent);
    await ssf.maintainStreams();
    const dueVerifications = streams.queueOf(streams.getStream(
      a2.stream.stream_id)).filter(function (one) {
        return typeOf(one.claims) === VERIFY;
      });
    const recentVerifications = streams.queueOf(streams.getStream(
      b1.stream.stream_id)).filter(function (one) {
        return typeOf(one.claims) === VERIFY;
      });
    note(dueVerifications.length === 1 &&
         JSON.stringify(dueVerifications[0].claims.events[VERIFY]) === '{}' &&
         recentVerifications.length === 0,
         'F. A TRANSMITTER-INITIATED VERIFICATION GOES TO A STREAM THAT IS ' +
         'DUE ONE, WITH NO state (section 8.1.4.2), and not to one that is ' +
         'not', JSON.stringify(dueVerifications.map(function (one) {
           return one.claims.events;
         })));
    receiver.close();
  })().catch(function (e) {
    note(false, 'the child ran to the end', e && e.stack);
  }).then(finish);
}

function run(t) {
  log.debug("Entering run().");
  const root = path.join(__dirname, '..');
  const out = path.join(os.tmpdir(), 'sts-ssf-spec-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = Object.assign({}, process.env, {
    SSF_SPEC_CHILD_OUT: out, SSF_SPEC_CHILD_ROOT: root, LOG_LEVEL: 'fatal',
    // Restart-only: the console's and portal's own streams would add pushes
    // and queue rows to what this file counts.
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
    findings.forEach(function (one) {
      t.check(one.ok, one.what, one.detail);
    });
    t.check(findings.length >= 30, 'every section ran (' + findings.length +
            ' findings)');
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'ssf_spec_conformance',
  describe: 'SSF 1.0 final against #144: the RFC 9493 names and the final ' +
            'complex subject, stream ownership and a per-receiver limit, a ' +
            'Transmitter-Supplied aud, stream-updated in section 8.1.5\'s ' +
            'order with a paused push stream holding, and stream maintenance',
  run: run
};
