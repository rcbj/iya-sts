// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/webauthn_ceremony_log.js
//
// ===========================================================================
// WHAT A WEBAUTHN CEREMONY RECORDS FOR THE MOVE TO POST-QUANTUM KEYS (#943):
// `authn/webauthn_ceremonies.ts`.
//
//   A. The client is the browser and the operating system by family and
//      major version, read from the User-Agent and nothing finer; a missing
//      header names none.
//   B. The browser's error is a DOMException NAME from the allow-list, or
//      `other`: free text a page could send is never recorded.
//   C. A ceremony row carries what the header of that file lists — the
//      ceremony, door, role, lane, the algorithms offered in order, the one
//      used and whether it is post-quantum, the client, the transports and
//      attachment, the browser's error name — and NOT the error's message;
//      a refused one carries its code and is `summarised`, so it writes no
//      log line of its own.
//   D. A registration the browser declined at `/portal/keys` reaches the
//      row through `credentials.confirmKeyEnrolment()`, the door the page's
//      script posts the error name to: STS-AUTHN-0022, NotAllowedError, the
//      lane's algorithms offered ML-DSA first, and the message dropped.
//   E. The algorithm mismatch: a person holding an ML-DSA passkey who signs
//      in with an ES256 one gets a row of its own; nobody else does, and
//      not where post-quantum was required.
//
// AND SINCE #1108, the row's application, its duration and the device link:
//
//   F. The application the ceremony was for and `durationMs`, measured from
//      the issue instant the door hands over — none for an instant in the
//      future or none given — and the row still within `audit.js`'s twelve
//      fields: no `(more)`, and the registration's attestation, which the
//      thirteen-field row lost, kept in the folded `authenticator`.
//   G. `unfold()` reads the fold back exactly, and a row of the shape before
//      #1108 (separate `attachment`, `transports`, `attestation`,
//      `postQuantum`) the same way.
//   H. A device link (`device_enrolment.finishLink()`) writes the row: door
//      `device-link`, an assertion by the credential the challenge named,
//      a duration from the challenge's issue — refused when the browser
//      declined (its error name, the code), and completed with the key's
//      algorithm.
// ===========================================================================

delete process.env.CONFIG_FILE;

const audit = require('../common/audit');
const credentials = require('../common/credentials');
const ldap = require('../ldap/ldap_server');
const ceremonies = require('../authn/webauthn_ceremonies');
const enrolment = require('../common/device_enrolment');
const nodeCrypto = require('crypto');

const log = require('bunyan').createLogger({
  name: 'webauthn_ceremony_log', level: process.env.LOG_LEVEL || 'info' });

const CHROME_MAC = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) ' +
  'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.7390.54 ' +
  'Safari/537.36';
const FIREFOX_LINUX = 'Mozilla/5.0 (X11; Linux x86_64; rv:144.0) ' +
  'Gecko/20100101 Firefox/144.0.2';

function rowsOf(action, actor) {
  log.debug('Entering rowsOf().');
  log.debug('Leaving rowsOf().');
  return audit.list().filter(function (row) {
    return row.action === action && row.actor === actor;
  });
}

function client(t) {
  log.debug('Entering client().');
  const chrome = ceremonies.clientOf(CHROME_MAC);
  const firefox = ceremonies.clientOf(FIREFOX_LINUX);
  t.check(/^Chrome 141 on macOS 10$/.test(chrome) &&
          /^Firefox 144 on Linux$/.test(firefox) &&
          chrome.indexOf('7390') < 0 && firefox.indexOf('.2') < 0 &&
          ceremonies.clientOf('') === '' &&
          ceremonies.clientOf(undefined) === '',
          'A. the client is family and major version only, and none ' +
          'without a header', JSON.stringify([chrome, firefox]));
  log.debug('Leaving client().');
}

function errors(t) {
  log.debug('Entering errors().');
  t.check(ceremonies.clientErrorName('NotAllowedError') ===
            'NotAllowedError' &&
          ceremonies.clientErrorName('NotSupportedError') ===
            'NotSupportedError' &&
          ceremonies.clientErrorName('InvalidStateError') ===
            'InvalidStateError' &&
          ceremonies.clientErrorName('<script>alert(1)</script>') ===
            'other' &&
          ceremonies.clientErrorName('a sentence the page made up') ===
            'other' &&
          ceremonies.clientErrorName('') === '' &&
          ceremonies.clientErrorName(null) === '',
          'B. an error name is one of the allow-list, or other, or none');
  log.debug('Leaving errors().');
}

function row(t) {
  log.debug('Entering row().');
  const who = 'wcl-row-' + require('crypto').randomBytes(3).toString('hex');
  const req = { headers: { 'user-agent': CHROME_MAC } };
  ceremonies.record({
    ceremony: 'registration', door: 'sign-in-step', username: who,
    role: 'primary', lane: 'pqc', outcome: 'refused',
    errorCode: 'STS-AUTHN-0022', offered: [-49, -48, -50, -7],
    algorithm: '', req: req,
    posted: { error: 'NotSupportedError', message: 'SECRET FREE TEXT',
              authenticatorAttachment: 'platform',
              response: { transports: ['internal', 'hybrid', 'BAD!'] } } });
  ceremonies.record({
    ceremony: 'assertion', door: 'usernameless', username: who,
    role: 'primary', lane: 'pqc', outcome: 'success',
    offered: ['ML-DSA-65'], algorithm: 'ML-DSA-65', req: req,
    posted: { authenticatorAttachment: 'cross-platform' } });
  const rows = rowsOf('webauthn.ceremony', who);
  const refused = rows.filter(function (one) {
    return one.outcome === 'refused';
  })[0] || {};
  const done = rows.filter(function (one) {
    return one.outcome === 'success';
  })[0] || {};
  const d = refused.detail || {};
  t.check(rows.length === 2 && refused.errorCode === 'STS-AUTHN-0022' &&
          d.ceremony === 'registration' && d.door === 'sign-in-step' &&
          d.role === 'primary' && d.lane === 'pqc' &&
          d.offered === 'ML-DSA-65,ML-DSA-44,ML-DSA-87,ES256' &&
          d.clientError === 'NotSupportedError' &&
          d.client === 'Chrome 141 on macOS 10' &&
          d.authenticator === 'platform|internal,hybrid|' &&
          ceremonies.unfold(d).transports === 'internal,hybrid' &&
          ceremonies.unfold(d).attachment === 'platform' &&
          JSON.stringify(refused).indexOf('SECRET FREE TEXT') < 0,
          'C. a refused registration\'s row carries the offered order, the ' +
          'client, the transports, the attachment and the error NAME — ' +
          'never its message', JSON.stringify(refused));
  t.check((done.detail || {}).algorithm === 'ML-DSA-65' &&
          ceremonies.unfold(done.detail).postQuantum === true &&
          ceremonies.unfold(done.detail).attachment === 'cross-platform' &&
          !done.errorCode,
          'C2. a completed assertion\'s row names the algorithm used and ' +
          'that it is post-quantum', JSON.stringify(done));
  log.debug('Leaving row().');
}

async function declined(t) {
  log.debug('Entering declined().');
  const who = 'wcl-' + require('crypto').randomBytes(3).toString('hex');
  ldap.createUser(who, { invent: false });
  const begun = credentials.beginKeyEnrolment(who, {});
  const answer = await credentials.confirmKeyEnrolment(who,
    begun.enrolmentId,
    { error: 'NotAllowedError', message: 'The operation either timed ' +
      'out or was not allowed. SECRET FREE TEXT' },
    { origin: 'https://localhost:8081', rpId: 'localhost' });
  const rows = rowsOf('webauthn.ceremony', who);
  const d = (rows[0] || {}).detail || {};
  t.check(begun.ok && !answer.ok && answer.reason === 'browser' &&
          rows.length === 1 && rows[0].errorCode === 'STS-AUTHN-0022' &&
          d.ceremony === 'registration' && d.door === 'portal' &&
          d.clientError === 'NotAllowedError' && d.offered.length > 0 &&
          typeof d.durationMs === 'number' && d.durationMs >= 0 &&
          d.application === undefined &&
          JSON.stringify(rows[0]).indexOf('SECRET FREE TEXT') < 0,
          'D. a registration the browser declined at /portal/keys leaves ' +
          'one row: 0022, NotAllowedError, what was offered, no message, ' +
          'a duration from the enrolment\'s issue and no application',
          JSON.stringify([begun.ok, answer.reason, rows]));
  log.debug('Leaving declined().');
}

function mismatch(t) {
  log.debug('Entering mismatch().');
  const tag = require('crypto').randomBytes(3).toString('hex');
  const both = 'wcl-both-' + tag;
  const classical = 'wcl-ec-' + tag;
  const required = 'wcl-req-' + tag;
  ceremonies.algorithmMismatch({ username: both, used: 'ES256',
                                 held: ['ES256', 'ML-DSA-65'],
                                 door: 'sign-in' });
  ceremonies.algorithmMismatch({ username: both, used: 'ML-DSA-65',
                                 held: ['ES256', 'ML-DSA-65'],
                                 door: 'sign-in' });
  ceremonies.algorithmMismatch({ username: classical, used: 'ES256',
                                 held: ['ES256', 'RS256'], door: 'sign-in' });
  ceremonies.algorithmMismatch({ username: required, used: 'ES256',
                                 held: ['ES256', 'ML-DSA-87'],
                                 required: true, door: 'sign-in' });
  const rows = rowsOf('webauthn.algorithm-mismatch', both);
  t.check(rows.length === 1 && rows[0].detail.used === 'ES256' &&
          rows[0].detail.held === 'ML-DSA-65' && !rows[0].errorCode &&
          rowsOf('webauthn.algorithm-mismatch', classical).length === 0 &&
          rowsOf('webauthn.algorithm-mismatch', required).length === 0,
          'E. a classical sign-in by a person holding an ML-DSA passkey is ' +
          'an event of its own; a post-quantum sign-in, a person with no ' +
          'post-quantum key and a realm requiring one are not',
          JSON.stringify(rows));
  log.debug('Leaving mismatch().');
}

function applicationAndDuration(t) {
  log.debug('Entering applicationAndDuration().');
  const who = 'wcl-dur-' + nodeCrypto.randomBytes(3).toString('hex');
  const req = { headers: { 'user-agent': FIREFOX_LINUX } };
  ceremonies.record({
    ceremony: 'registration', door: 'sign-in-step', username: who,
    role: 'primary', lane: 'pqc', outcome: 'success',
    offered: [-49, -7], algorithm: 'ML-DSA-65', req: req,
    application: 'https://app.example/rp', issuedAt: Date.now() - 1500,
    attestation: { algorithms: { statement: 'ML-DSA-65',
      certificates: [{ algorithm: 'ML-DSA-65' }],
      anchor: { algorithm: 'ML-DSA-87' }, postQuantum: true } },
    posted: { authenticatorAttachment: 'cross-platform',
              capabilities: { hybridTransport: true },
              response: { transports: ['usb'] } } });
  ceremonies.record({
    ceremony: 'assertion', door: 'usernameless', username: who,
    outcome: 'success', algorithm: 'ES256', req: req,
    issuedAt: Date.now() + 60000 });
  ceremonies.record({
    ceremony: 'assertion', door: 'portal', username: who,
    outcome: 'refused', errorCode: 'STS-AUTHN-0022', req: req });
  const rows = rowsOf('webauthn.ceremony', who);
  const reg = rows.filter(function (one) {
    return one.detail.ceremony === 'registration';
  })[0] || { detail: {} };
  const d = reg.detail;
  const others = rows.filter(function (one) {
    return one !== reg;
  });
  t.check(rows.length === 3 && d.application === 'https://app.example/rp' &&
          typeof d.durationMs === 'number' && d.durationMs >= 1500 &&
          d.durationMs < 60000 && d.capabilities === 'hybridTransport' &&
          Object.keys(d).length <= 12 && !('(more)' in d) &&
          ceremonies.unfold(d).attestation ===
            'ML-DSA-65; ML-DSA-65 > ML-DSA-87 (PQ)' &&
          ceremonies.unfold(d).transports === 'usb' &&
          ceremonies.unfold(d).postQuantum === true &&
          others.every(function (one) {
            return one.detail.durationMs === undefined &&
                   one.detail.application === undefined &&
                   !('(more)' in one.detail);
          }),
          'F. the row names the application and the server-measured ' +
          'duration, none for a future or missing instant, within twelve ' +
          'fields with the attestation kept', JSON.stringify(rows));
  log.debug('Leaving applicationAndDuration().');
}

function unfolded(t) {
  log.debug('Entering unfolded().');
  const now = ceremonies.unfold({ algorithm: 'ES256',
    authenticator: 'platform|internal|ES256; ES256 > ES256' });
  const old = ceremonies.unfold({ algorithm: 'ML-DSA-44',
    attachment: 'cross-platform', transports: 'nfc,usb',
    attestation: 'ML-DSA-44 (PQ)', postQuantum: true });
  const between = ceremonies.unfold({ algorithm: 'ES256',
    client: 'Chrome 141 on macOS 15|conditionalGet,hybridTransport',
    attachment: 'platform', transports: 'internal' });
  const none = ceremonies.unfold({});
  t.check(now.attachment === 'platform' && now.transports === 'internal' &&
          now.attestation === 'ES256; ES256 > ES256' &&
          now.postQuantum === false &&
          old.attachment === 'cross-platform' && old.transports ===
            'nfc,usb' && old.attestation === 'ML-DSA-44 (PQ)' &&
          old.postQuantum === true &&
          none.attachment === '' && none.transports === '' &&
          none.attestation === '' && none.postQuantum === false &&
          between.client === 'Chrome 141 on macOS 15' &&
          between.capabilities === 'conditionalGet,hybridTransport' &&
          between.attachment === 'platform' && now.client === '' &&
          ceremonies.unfold({ client: 'Edge 141 on Windows 11',
                              capabilities: 'conditionalGet' })
            .capabilities === 'conditionalGet',
          'G. unfold() reads the folded field, a row of the shape before ' +
          '#1108 and one with #1114\'s capabilities on the client alike',
          JSON.stringify([now, old, between, none]));
  log.debug('Leaving unfolded().');
}

// An ES256 assertion over `challenge` by `pair`, as a browser posts it.
function assertionBy(pair, credentialId, challenge) {
  log.debug('Entering assertionBy().');
  const count = Buffer.alloc(4);
  count.writeUInt32BE(7, 0);
  const sha = function (data) {
    return nodeCrypto.createHash('sha256').update(data).digest();
  };
  const authData = Buffer.concat([sha(Buffer.from('localhost')),
                                  Buffer.from([0x05]), count]);
  const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.get',
    challenge: challenge, origin: 'https://localhost:8081' }));
  const sig = nodeCrypto.sign('sha256',
    Buffer.concat([authData, sha(clientData)]), pair.privateKey);
  log.debug('Leaving assertionBy().');
  return { id: credentialId, rawId: credentialId, type: 'public-key',
           authenticatorAttachment: 'platform',
           response: { authenticatorData: authData.toString('base64url'),
                       clientDataJSON: clientData.toString('base64url'),
                       signature: sig.toString('base64url') } };
}

async function deviceLink(t) {
  log.debug('Entering deviceLink().');
  const who = 'wcl-dev-' + nodeCrypto.randomBytes(3).toString('hex');
  const session = 'wcl-s-' + who;
  ldap.createUser(who, { invent: false });
  const pair = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const credentialId = nodeCrypto.randomBytes(16).toString('base64url');
  const stored = credentials.addKey(who, { credentialId: credentialId,
    publicKeyJwk: pair.publicKey.export({ format: 'jwk' }), signCount: 0,
    label: 'built in', attachment: 'platform', aaguid: '' });
  const declined = enrolment.beginLink({ username: who, sessionId: session,
    credentialId: credentialId, label: 'laptop', platform: 'macos' });
  const refused = await enrolment.finishLink({ username: who,
    sessionId: session, challenge: declined.challenge,
    credential: { error: 'NotAllowedError', message: 'SECRET FREE TEXT' },
    origin: 'https://localhost:8081', rpId: 'localhost' });
  const begun = enrolment.beginLink({ username: who, sessionId: session,
    credentialId: credentialId, label: 'laptop', platform: 'macos' });
  const linked = await enrolment.finishLink({ username: who,
    sessionId: session, challenge: begun.challenge,
    credential: assertionBy(pair, credentialId, begun.challenge),
    origin: 'https://localhost:8081', rpId: 'localhost' });
  const rows = rowsOf('webauthn.ceremony', who);
  const no = rows.filter(function (one) {
    return one.outcome === 'refused';
  })[0] || { detail: {} };
  const yes = rows.filter(function (one) {
    return one.outcome === 'success';
  })[0] || { detail: {} };
  t.check(stored && stored.ok !== false && declined.ok && begun.ok &&
          !refused.ok && rows.length === 2 &&
          no.errorCode === 'STS-DEVICE-0022' &&
          no.detail.door === 'device-link' &&
          no.detail.ceremony === 'assertion' &&
          no.detail.clientError === 'NotAllowedError' &&
          typeof no.detail.durationMs === 'number' &&
          no.detail.application === undefined &&
          JSON.stringify(no).indexOf('SECRET FREE TEXT') < 0,
          'H. a device link the browser declined writes a refused ' +
          'device-link row: the code, the error name, a duration',
          JSON.stringify([declined.ok, refused, no]));
  t.check(linked.ok && yes.detail.door === 'device-link' &&
          // No role since #1135: the key carries none, and a device link
          // answers no sign-in step.
          !yes.detail.role && !!yes.detail.algorithm &&
          yes.detail.offered === yes.detail.algorithm &&
          typeof yes.detail.durationMs === 'number' &&
          ceremonies.unfold(yes.detail).attachment === 'platform' &&
          !yes.errorCode,
          'H2. a completed device link writes a completed device-link row ' +
          'naming the key\'s algorithm', JSON.stringify([linked.ok, yes]));
  log.debug('Leaving deviceLink().');
}

module.exports = {
  name: 'webauthn_ceremony_log',
  describe: 'every WebAuthn ceremony\'s audit row and the algorithm ' +
            'mismatch event, for the post-quantum transition (#943), its ' +
            'application, duration and the device link\'s row (#1108)',
  run: async function (t) {
    log.debug('Entering run().');
    client(t);
    errors(t);
    row(t);
    await declined(t);
    mismatch(t);
    applicationAndDuration(t);
    unfolded(t);
    await deviceLink(t);
    log.debug('Leaving run().');
  }
};
