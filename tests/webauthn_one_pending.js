// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// ===========================================================================
// tests/webauthn_one_pending.js — ONE WEBAUTHN REQUEST AT A TIME IN THE
// SIGN-IN RUNTIME (#660, rcbj 2026-10-16: "OperationError: A request is already
// pending" on /authn/webauthn, in a loop).
//
// A document holds one WebAuthn request, and an aborted one is pending until
// its promise settles. The username screen's passkey autofill (conditional
// mediation) stayed pending after a password, because the passkey step is
// drawn in place, so every press of the step's button was refused. Against
// `authn/web_authn.ts` with a browser that keeps that rule:
//   1. a page drawn without the autofill aborts it;
//   2. the step's ceremony waits for the aborted autofill to settle, and is
//      not refused;
//   3. where the browser still refuses it just after the abort, it is asked
//      once more, and only once;
//   4. a second press while a ceremony is open starts nothing;
//   5. an autofill the browser refused is not left recorded as in flight.
// ===========================================================================
'use strict';
const WebSurface = require('../common/web_surface');
const AuthnSurface = require('../authn/web_authn');
const log = require('bunyan').createLogger({ name: 'webauthn_one_pending',
  level: process.env.LOG_LEVEL || 'info' });

function wait(ms) {
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

function bytes() {
  return new Uint8Array([1, 2, 3]).buffer;
}

function assertion() {
  return { id: 'cred', rawId: bytes(), type: 'public-key',
    response: { clientDataJSON: bytes(), authenticatorData: bytes(),
                signature: bytes(), userHandle: null } };
}

// A browser's credentials container with one pending request per document.
// An aborted request settles `settleMs` later, and the document is busy for
// `stickyMs` after that.
function fakeCredentials(settleMs, stickyMs) {
  log.debug("Entering fakeCredentials().");
  const c = { pending: false, busyUntil: 0, calls: [], refused: 0,
              answerConditional: null };
  const call = function (kind, ask) {
    c.calls.push({ kind: kind, mediation: ask.mediation || '' });
    if (c.pending || Date.now() < c.busyUntil) {
      c.refused++;
      const e = new Error('A request is already pending.');
      e.name = 'OperationError';
      return Promise.reject(e);
    }
    c.pending = true;
    if (ask.mediation !== 'conditional') {
      return new Promise(function (resolve) {
        setTimeout(function () {
          c.pending = false;
          resolve(assertion());
        }, 5);
      });
    }
    return new Promise(function (resolve, reject) {
      const done = function () {
        c.pending = false;
        c.busyUntil = Date.now() + stickyMs;
      };
      if (c.answerConditional) {
        const answer = c.answerConditional;
        setTimeout(function () {
          done();
          reject(answer);
        }, 1);
        return;
      }
      ask.signal.addEventListener('abort', function () {
        setTimeout(function () {
          done();
          const e = new Error('aborted');
          e.name = 'AbortError';
          reject(e);
        }, settleMs);
      });
    });
  };
  c.get = function (ask) {
    return call('get', ask);
  };
  c.create = function (ask) {
    return call('create', ask);
  };
  log.debug("Leaving fakeCredentials().");
  return c;
}

// The runtime over that browser, with its server calls answered here.
function surfaceWith(credentials) {
  log.debug("Entering surfaceWith().");
  const element = { getAttribute: function () {
    return null;
  } };
  const env = {
    location: { pathname: '/authn/webauthn', search: '?mfa=m1',
                href: 'https://sts.example/authn/webauthn?mfa=m1' },
    document: { documentElement: element, body: element,
                getElementById: function () {
                  return null;
                },
                querySelector: function () {
                  return null;
                } },
    window: { AbortController: AbortController, setTimeout: setTimeout,
              clearTimeout: clearTimeout },
    navigator: { languages: ['en'], credentials: credentials }
  };
  const s = new AuthnSurface(env);
  s.sent = [];
  s.walletFlow = { onPut: function () {
    return undefined;
  } };
  s.idHere = function () {
    return 'm1';
  };
  s.send = function (path, body) {
    s.sent.push(path);
    if (/\/options$/.test(path)) {
      return Promise.resolve({ status: 200, json: { ok: true, mode: 'get',
        rpId: 'localhost', challenge: 'AQID', allow: [], options: {} } });
    }
    return Promise.resolve({ status: 200, json: { ok: true, body: body } });
  };
  s.next = function () {
    return Promise.resolve();
  };
  s.armPasskey = function () {
    return Promise.resolve({ challenge: 'AQID', rpId: 'localhost',
                             options: {} });
  };
  s.sendPasskey = function () {
    return Promise.resolve();
  };
  log.debug("Leaving surfaceWith().");
  return s;
}

async function run(t) {
  log.debug("Entering run().");
  // The page itself is not drawn here: only what put() runs after it.
  const drawPage = WebSurface.prototype.put;
  WebSurface.prototype.put = function () {
    return undefined;
  };
  try {
    t.log.info('=== 1-2. the step after a password, the autofill pending ===');
    const browser = fakeCredentials(30, 0);
    const s = surfaceWith(browser);
    s.passkey(true);
    await wait(5);
    t.check(browser.pending && s.pendingAutofill,
            '1a. the username screen\'s autofill is pending');
    s.put('', '', { view: {} });
    t.check(!s.pendingAutofill,
            '1b. a page drawn without the autofill aborts it');
    await s.stepPasskey('');
    const step = browser.calls.filter(function (c) {
      return c.mediation === '';
    });
    t.check(browser.refused === 0 && step.length === 1 &&
            s.sent.indexOf('/authn-api/mfa/m1/webauthn') >= 0,
            '2. the step\'s ceremony waited for the abort to settle and ' +
            'was not refused as pending',
            JSON.stringify({ refused: browser.refused, calls: browser.calls,
                             sent: s.sent }));

    t.log.info('=== 3. refused once just after the abort ===');
    const sticky = fakeCredentials(5, 100);
    const s3 = surfaceWith(sticky);
    s3.passkey(true);
    await wait(5);
    await s3.stepPasskey('');
    const answered = s3.sent.indexOf('/authn-api/mfa/m1/webauthn') >= 0;
    t.check(sticky.refused === 1 && answered &&
            sticky.calls.filter(function (c) {
              return c.mediation === '';
            }).length === 2,
            '3. a ceremony refused as pending just after the abort is ' +
            'asked once more',
            JSON.stringify({ refused: sticky.refused, calls: sticky.calls }));

    t.log.info('=== 4. a second press ===');
    const plain = fakeCredentials(5, 0);
    const s4 = surfaceWith(plain);
    await Promise.all([s4.stepPasskey(''), s4.stepPasskey('')]);
    t.check(plain.calls.length === 1 && plain.refused === 0 &&
            s4.sent.filter(function (p) {
              return /\/options$/.test(p);
            }).length === 1,
            '4. a second press while a ceremony is open starts nothing',
            JSON.stringify({ calls: plain.calls, sent: s4.sent }));

    t.log.info('=== 5. a refused autofill ===');
    const refusing = fakeCredentials(5, 0);
    const declined = new Error('not allowed');
    declined.name = 'NotAllowedError';
    refusing.answerConditional = declined;
    const s5 = surfaceWith(refusing);
    await s5.passkey(true);
    t.check(!s5.pendingAutofill && !refusing.pending,
            '5. an autofill the browser refused is not left as in flight');
  } finally {
    WebSurface.prototype.put = drawPage;
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'webauthn_one_pending',
  describe: 'The sign-in runtime holds one WebAuthn request at a time: the ' +
            'autofill aborted when its page goes, the step\'s ceremony ' +
            'after it settles, one retry, one press',
  run: run
};
