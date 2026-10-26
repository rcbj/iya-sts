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
// ===========================================================================

delete process.env.CONFIG_FILE;

const audit = require('../common/audit');
const credentials = require('../common/credentials');
const ldap = require('../ldap/ldap_server');
const ceremonies = require('../authn/webauthn_ceremonies');

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
          d.transports === 'internal,hybrid' && d.attachment === 'platform' &&
          JSON.stringify(refused).indexOf('SECRET FREE TEXT') < 0,
          'C. a refused registration\'s row carries the offered order, the ' +
          'client, the transports, the attachment and the error NAME — ' +
          'never its message', JSON.stringify(refused));
  t.check((done.detail || {}).algorithm === 'ML-DSA-65' &&
          (done.detail || {}).postQuantum === true &&
          (done.detail || {}).attachment === 'cross-platform' &&
          !done.errorCode,
          'C2. a completed assertion\'s row names the algorithm used and ' +
          'that it is post-quantum', JSON.stringify(done));
  log.debug('Leaving row().');
}

async function declined(t) {
  log.debug('Entering declined().');
  const who = 'wcl-' + require('crypto').randomBytes(3).toString('hex');
  ldap.createUser(who, { invent: false });
  const begun = credentials.beginKeyEnrolment(who, { role: 'mfa' });
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
          JSON.stringify(rows[0]).indexOf('SECRET FREE TEXT') < 0,
          'D. a registration the browser declined at /portal/keys leaves ' +
          'one row: 0022, NotAllowedError, what was offered, no message',
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

module.exports = {
  name: 'webauthn_ceremony_log',
  describe: 'every WebAuthn ceremony\'s audit row and the algorithm ' +
            'mismatch event, for the post-quantum transition (#943)',
  run: async function (t) {
    log.debug('Entering run().');
    client(t);
    errors(t);
    row(t);
    await declined(t);
    mismatch(t);
    log.debug('Leaving run().');
  }
};
