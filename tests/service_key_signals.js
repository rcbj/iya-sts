'use strict';
//
// File: service_key_signals.js
//
// ===========================================================================
// THE OTHER KEYS A RELYING PARTY PINS ARE ANNOUNCED, AND A STREAM THIS
// TRANSMITTER DELETES IS TOLD FIRST (#245).
//
//   A. THE THREE EVENTS. `federation-key-rotated`, `spiffe-authority-rotated`
//      and `tls-certificate-changed` are this service's own (`family: sts`,
//      no subject), always offered, in #42's shape — and a generated payload
//      validates.
//   B. SHARED SIGNALS SENDS ONE to a stream that asked for it, with the
//      realm, the units as "<unit> <from> -> <to>" and the reason, and to no
//      stream that did not.
//   C. OPENID FEDERATION: a rotation, an emergency (the next key named
//      revoked with the current one) and a retired key revoked as
//      compromised are each announced; a next key merely published is not.
//   D. SPIFFE: a JWT authority rotation is announced, the bundle changed.
//   E. THE LISTENER: the first certificate a process takes over its
//      self-signed bootstrap is NOT announced; one it replaces after a
//      rebuilt branch IS, to every realm (`*`). And (#264) what the service
//      last announced is recorded, a start whose certificate differs from it
//      is announced from `listen()` as `restarted`, and a self-signed,
//      supplied or handed-in certificate is never recorded. The restart
//      itself, across two processes and a store, is
//      `tests/listener_certificate_restart.js`.
//   F. A STREAM DELETED from the console, and one deleted for inactivity
//      (`ssf.inactivityAction: delete`), is sent `stream-updated` with status
//      `disabled` and a reason BEFORE it is removed.
//
// In a child process with the whole stack: it builds a certificate authority
// and rebuilds the process branch under the listener, and `run.js` runs every
// file in one process.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'service_key_signals',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  const ROOT = process.env.SKS_ROOT;
  const OUT = process.env.SKS_OUT;
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  const j = JSON.stringify;
  const pause = function (ms) {
    return new Promise(function (resolve) {
      setTimeout(resolve, ms || 30);
    });
  };

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const realms = require(ROOT + '/common/realms');
    const config = require(ROOT + '/common/config');
    const pki = require(ROOT + '/common/pki');
    const tls = require(ROOT + '/tls/tls_server');
    const events = require(ROOT + '/ssf/ssf_events');
    const ssf = require(ROOT + '/ssf/ssf');
    const streams = require(ROOT + '/ssf/ssf_streams');
    const serviceSignals = require(ROOT + '/ssf/service_signals');
    const fedKeys = require(ROOT + '/oidfed/federation_keys');
    const spiffeCa = require(ROOT + '/spiffe/spiffe_ca');
    const DEFAULT = realms.get(realms.DEFAULT_ID);

    // Every key notice the three owners hand the library.
    const keyNotices = [];
    const realKeyChanged = serviceSignals.keyChanged;
    serviceSignals.keyChanged = function (kind, realmId, notice) {
      keyNotices.push({ kind: kind, realm: realmId,
                        reason: notice && notice.reason,
                        bundleChanged: notice && notice.bundleChanged,
                        rotated: ((notice && notice.rotated) || [])
                          .map(function (r) {
                            return r.unit + ' ' + r.from + ' -> ' + r.to;
                          }) });
      return Promise.resolve(0);
    };
    // Every SET transmitted, as `{ stream, uri, payload }`.
    const sent = [];
    const Cls = ssf.SharedSignals;
    const realTransmit = Cls.prototype.transmit;
    Cls.prototype.transmit = function (record, options) {
      sent.push({ stream: record.stream_id, uri: options.uri,
                  payload: options.payload,
                  present: !!streams.getStream(record.stream_id) });
      return Promise.resolve({ ok: true });
    };

    // --- A. the three events -------------------------------------------------
    const uris = [events.FEDERATION_KEY_ROTATED,
                  events.SPIFFE_AUTHORITY_ROTATED,
                  events.TLS_CERTIFICATE_CHANGED];
    const offered = events.supportedEventUris();
    const rows = uris.map(function (uri) {
      return events.EVENT_BY_URI[uri];
    });
    note(rows.every(function (row) {
      return row && row.family === 'sts' && row.subject === 'none' &&
             j(row.required) === j(['realm', 'rotated', 'reason']);
    }) && uris.every(function (uri) {
      return offered.indexOf(uri) >= 0;
    }), 'A1. the three are this service\'s own (family sts, no subject), ' +
        'require realm, rotated and reason as signing-key-rotated does, and ' +
        'are always offered', j(uris));
    const spiffeRow = events.EVENT_BY_URI[events.SPIFFE_AUTHORITY_ROTATED];
    const payload = spiffeRow.generate({ realm: 'r', rotated: 'a 1 -> 2',
      reason: 'scheduled', bundle_uri: 'https://x/spiffe/bundle',
      trust_domain: 'td.example', bundle_changed: false });
    const verdict = events.validateEvent(events.SPIFFE_AUTHORITY_ROTATED,
                                         payload);
    note(verdict.ok && payload.bundle_changed === false &&
         payload.trust_domain === 'td.example' &&
         spiffeRow.generate({ reason: 'whatever' }).reason === 'requested',
         'A2. a generated payload validates, bundle_changed is a boolean, and ' +
         'an unknown reason is "requested"', j([verdict, payload]));

    // --- B. Shared Signals sends one -----------------------------------------
    const ISSUER = 'https://sts.test';
    const poll = streams.DELIVERY_POLL;
    const wants = streams.createStream({ delivery: { method: poll },
      events_requested: [events.FEDERATION_KEY_ROTATED] },
      { issuer: ISSUER, principal: 'sks-client-a' });
    const other = streams.createStream({ delivery: { method: poll },
      events_requested: [events.SIGNING_KEY_ROTATED] },
      { issuer: ISSUER, principal: 'sks-client-b' });
    note(wants.ok && other.ok, 'B0. two poll streams',
         j([wants.errors, other.errors]));
    sent.length = 0;
    const told = await realms.run(DEFAULT, function () {
      return realKeyChanged('federation', realms.DEFAULT_ID, {
        rotated: [{ unit: 'federation-entity-key', from: 'k1', to: 'k2' }],
        reason: 'scheduled' });
    });
    const fedSent = sent.filter(function (one) {
      return one.uri === events.FEDERATION_KEY_ROTATED;
    });
    note(told === 1 && fedSent.length === 1 &&
         fedSent[0].stream === wants.stream.stream_id &&
         fedSent[0].payload.rotated === 'federation-entity-key k1 -> k2' &&
         fedSent[0].payload.reason === 'scheduled' &&
         fedSent[0].payload.realm === realms.DEFAULT_ID,
         'B1. federation-key-rotated goes to the stream that asked for it, ' +
         'and only that one, with the realm, the unit and the reason',
         j(fedSent));

    // --- C. OpenID Federation ------------------------------------------------
    keyNotices.length = 0;
    await realms.run(DEFAULT, function () {
      return fedKeys.ensure();
    });
    const afterEnsure = keyNotices.length;
    const rotated = await realms.run(DEFAULT, function () {
      return fedKeys.rotate({ reason: 'scheduled' });
    });
    await pause();
    const one = keyNotices[keyNotices.length - 1] || {};
    note(afterEnsure === 0 && one.kind === 'federation' &&
         one.reason === 'scheduled' &&
         one.rotated[0] === 'federation-entity-key ' + rotated.from + ' -> ' +
                            rotated.to,
         'C1. a scheduled rotation is announced, naming the key that stopped ' +
         'signing and the one that signs now; the first keys are not',
         j([afterEnsure, one, rotated]));
    const nextBefore = realms.run(DEFAULT, function () {
      return fedKeys.view().filter(function (k) {
        return k.state === 'next';
      })[0];
    });
    const emergency = await realms.run(DEFAULT, function () {
      return fedKeys.rotate({ emergency: true, reason: 'by hand' });
    });
    await pause();
    const two = keyNotices[keyNotices.length - 1] || {};
    note(two.reason === 'emergency' && two.rotated.length === 2 &&
         two.rotated[0] === 'federation-entity-key ' + emergency.from +
                            ' -> ' + emergency.to &&
         two.rotated[1] === 'federation-entity-key ' +
                            (nextBefore && nextBefore.kid) + ' -> revoked',
         'C2. an EMERGENCY is announced as one, and names the next key it ' +
         'revoked with the current one', j([two, nextBefore && nextBefore.kid]));
    const retired = realms.run(DEFAULT, function () {
      return fedKeys.view().filter(function (k) {
        return k.state === 'retired' && !k.revokedAt;
      })[0];
    });
    const revoked = retired ? realms.run(DEFAULT, function () {
      return fedKeys.revoke(retired.kid, 'compromised');
    }) : { ok: false };
    await pause();
    const three = keyNotices[keyNotices.length - 1] || {};
    note(revoked.ok && three.reason === 'emergency' &&
         three.rotated[0] === 'federation-entity-key ' + retired.kid +
                              ' -> revoked',
         'C3. a retired key revoked as compromised is announced, as an ' +
         'emergency', j([revoked, three]));

    // --- D. SPIFFE ------------------------------------------------------------
    keyNotices.length = 0;
    let jwt = null;
    try {
      jwt = await realms.run(DEFAULT, function () {
        return spiffeCa.rotateJwtAuthority(realms.DEFAULT_ID);
      });
    } catch (e) {
      jwt = { error: String(e && e.message) };
    }
    await pause();
    const four = keyNotices.filter(function (n) {
      return n.kind === 'spiffe';
    })[0] || {};
    note(jwt && jwt.id && four.reason === 'requested' &&
         four.bundleChanged === true &&
         /^jwt-authority .+ -> /.test(String(four.rotated[0])) &&
         String(four.rotated[0]).indexOf(' -> ' + jwt.id) > 0,
         'D1. a JWT authority rotated by hand is announced as ' +
         'spiffe-authority-rotated, the bundle changed', j([jwt && jwt.id,
                                                           four]));

    // --- E. the listener -------------------------------------------------------
    keyNotices.length = 0;
    await require(ROOT + '/common/keystore').start();
    await pki.start();
    await pause(100);
    const atStart = keyNotices.filter(function (n) {
      return n.kind === 'tls';
    }).length;
    const before = tls.serverCertificate().certPem;
    await pki.buildScope(pki.PROCESS_SCOPE, {});
    await tls.reconcileWithHierarchy();
    await pause(100);
    const tlsNotices = keyNotices.filter(function (n) {
      return n.kind === 'tls';
    });
    note(atStart === 0 && tls.serverCertificate().certPem !== before &&
         tlsNotices.length >= 1 && tlsNotices[0].realm === '*' &&
         /^\S+ \S+ -> \S+$/.test(String(tlsNotices[0].rotated[0])),
         'E1. the listener\'s first certificate over its bootstrap is not ' +
         'announced; the one that replaces it after a rebuilt branch is, to ' +
         'every realm', j([atStart, tlsNotices]));

    // --- E2-E6. what the service last announced, across a restart (#264) ----
    const fp = function (pem) {
      return String(new (require('crypto').X509Certificate)(pem)
        .fingerprint256).toUpperCase();
    };
    const nowFp = fp(tls.serverCertificate().certPem);
    const heldNow = tls.lastAnnouncedListenerCertificates();
    note(heldNow.rsa &&
         String(heldNow.rsa.fingerprint256).toUpperCase() === nowFp,
         'E2. a re-issued listener certificate is RECORDED as the one the ' +
         'service last announced, so the next start compares with it',
         j([heldNow, nowFp]));
    // A previous life of the service announced another certificate: plant
    // it through the comparison itself, as a start would have written it.
    tls.listenerChangesSinceAnnounced([{ algorithm: 'rsa', selfSigned: false,
                                         fingerprint256: 'AA:BB' }]);
    keyNotices.length = 0;
    tls.listen();
    await pause(50);
    const restartNotices = keyNotices.filter(function (n) {
      return n.kind === 'tls';
    });
    note(restartNotices.length === 1 && restartNotices[0].realm === '*' &&
         restartNotices[0].reason === 'restarted' &&
         restartNotices[0].rotated.some(function (r) {
           return String(r).toUpperCase() === 'RSA AA:BB -> ' + nowFp;
         }) &&
         String(tls.lastAnnouncedListenerCertificates().rsa.fingerprint256)
           .toUpperCase() === nowFp,
         'E3. A START THAT PRESENTS A CERTIFICATE OTHER THAN THE ONE LAST ' +
         'ANNOUNCED IS ANNOUNCED once the port is bound (listen()), to every ' +
         'realm, reason "restarted", from the recorded fingerprint — and ' +
         'the record moves to the new one', j(restartNotices));
    keyNotices.length = 0;
    tls.listen();
    await pause(50);
    note(keyNotices.filter(function (n) {
      return n.kind === 'tls';
    }).length === 0,
         'E4. a start presenting the certificate last announced announces ' +
         'nothing', j(keyNotices));
    const skipped = tls.listenerChangesSinceAnnounced([
      { algorithm: 'sks-self', fingerprint256: 'S1' },
      { algorithm: 'sks-self2', selfSigned: true, fingerprint256: 'S2' },
      { algorithm: 'supplied', selfSigned: false, fingerprint256: 'S3' },
      { algorithm: 'sks-handed', selfSigned: false, handedIn: true,
        fingerprint256: 'S4' }]);
    const heldAfter = tls.lastAnnouncedListenerCertificates();
    note(skipped.length === 0 && !heldAfter['sks-self'] &&
         !heldAfter['sks-self2'] && !heldAfter.supplied &&
         !heldAfter['sks-handed'],
         'E5. a self-signed bootstrap, a supplied and a handed-in ' +
         'certificate are never recorded and never announced',
         j([skipped, heldAfter]));
    const first = tls.listenerChangesSinceAnnounced([
      { algorithm: 'sks-new', selfSigned: false, fingerprint256: 'N1' }]);
    note(first.length === 0 &&
         (tls.lastAnnouncedListenerCertificates()['sks-new'] || {})
           .fingerprint256 === 'N1',
         'E6. a unit with nothing recorded (a first start, or a store that ' +
         'keeps nothing across a restart) is recorded and NOT announced',
         j(first));
    const tlsRow = events.EVENT_BY_URI[events.TLS_CERTIFICATE_CHANGED];
    const fedRow = events.EVENT_BY_URI[events.FEDERATION_KEY_ROTATED];
    const restartedPayload = tlsRow.generate({ realm: 'r',
                                               rotated: 'rsa a -> b',
                                               reason: 'restarted' });
    note(restartedPayload.reason === 'restarted' &&
         events.validateEvent(events.TLS_CERTIFICATE_CHANGED,
                              restartedPayload).ok &&
         fedRow.generate({ reason: 'restarted' }).reason === 'requested',
         'E7. "restarted" is a reason of tls-certificate-changed ONLY: it ' +
         'validates there, and another key event reads it as "requested"',
         j(restartedPayload));

    // --- F. a deleted stream is told first --------------------------------------
    const gone = streams.createStream({ delivery: { method: poll },
      events_requested: [events.SSF_PREFIX + 'stream-updated'] },
      { issuer: ISSUER, principal: 'sks-client-c' });
    sent.length = 0;
    const deleted = await realms.run(DEFAULT, function () {
      return ssf.consoleAction('delete',
                               { stream_id: gone.stream.stream_id });
    });
    const notice = sent.filter(function (s) {
      return s.stream === gone.stream.stream_id &&
             s.uri === events.SSF_PREFIX + 'stream-updated';
    })[0];
    note(deleted.ok && !!notice && notice.present === true &&
         notice.payload.status === 'disabled' &&
         /deleted/.test(String(notice.payload.reason)) &&
         !streams.getStream(gone.stream.stream_id),
         'F1. A STREAM DELETED FROM THE CONSOLE is sent stream-updated ' +
         '(disabled, with a reason) while it still exists, and then removed',
         j([deleted, notice]));
    const idle = streams.createStream({ delivery: { method: poll },
      events_requested: [events.SSF_PREFIX + 'stream-updated'] },
      { issuer: ISSUER, principal: 'sks-client-d' });
    config.setOverride('ssf.inactivityTimeoutS', 60);
    config.setOverride('ssf.inactivityAction', 'delete');
    sent.length = 0;
    await realms.run(DEFAULT, function () {
      return ssf.maintainStreams(Math.floor(Date.now() / 1000) + 3600);
    });
    config.clearOverride('ssf.inactivityTimeoutS');
    config.clearOverride('ssf.inactivityAction');
    const idleNotice = sent.filter(function (s) {
      return s.stream === idle.stream.stream_id;
    })[0];
    note(!!idleNotice && idleNotice.present === true &&
         idleNotice.payload.status === 'disabled' &&
         /No activity/.test(String(idleNotice.payload.reason)) &&
         !streams.getStream(idle.stream.stream_id),
         'F2. A STREAM DELETED FOR INACTIVITY is told the same way first',
         j(idleNotice));

    Cls.prototype.transmit = realTransmit;
    serviceSignals.keyChanged = realKeyChanged;
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child ran to the end',
                    detail: e && e.stack });
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function inAChild(t) {
  log.debug("Entering inAChild().");
  const out = path.join(os.tmpdir(), 'service-key-signals-' + process.pid +
                        '-' + require('crypto').randomBytes(8).toString('hex') +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', 'const fs = require("fs");\n(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', SKS_ROOT: ROOT,
                                  SKS_OUT: out, SPIFFE_GRPC_PORT: '0' }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
    // No report: the child died before writing one. Reported below with its
    // exit status and stderr, which is where the reason is.
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written, which the read above has already reported.
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings), 'the child process reported its ' +
                                        'findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-1200))) {
    log.debug("Leaving inAChild().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving inAChild().");
}

async function run(t) {
  log.debug("Entering run().");
  inAChild(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'service_key_signals',
  describe: 'The other keys a relying party pins are announced (#245): ' +
            'federation-key-rotated, spiffe-authority-rotated and ' +
            'tls-certificate-changed in #42\'s shape, from OpenID Federation ' +
            'rotations and revocations, SPIFFE rotations and a re-issued ' +
            'listener; and a stream this transmitter deletes is sent ' +
            'stream-updated (disabled) first.',
  run: run
};
