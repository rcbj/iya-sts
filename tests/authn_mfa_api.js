// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/authn_mfa_api.js
// ===========================================================================
// THE STEPS AFTER THE SIGN-IN SCREEN ARE PAGES OF ITS SURFACE (#572, #573).
//
// The whole stack in a child process, over HTTP on 127.0.0.1, as
// `tests/authn_api.js` drives the screen:
//
//   1. THE SHELLS: every step's page answers the sign-in surface's shell
//      for a step it can be drawn for, and the 400 it always answered for
//      one it cannot; the old form POSTs and `/authn/webauthn.js` are gone.
//   2. THE INDEX AND THE OPENAPI DOCUMENT name every step operation.
//   3. THE VIEW (`GET /authn-api/mfa/{id}?page=`): facts and no markup, the
//      CSRF token of the cookie's session, the page's own refusals.
//   4. THE BINDING of a step's act: JSON, an Origin of this service, the
//      token; a malformed id, an unknown id and an unknown field refused.
//   5. THE ONE-TIME CODE: a wrong code refused and the step kept, the rate
//      limit (429), the right code signing in (`next: redirect`, the session
//      cookie set on that answer), the step spent.
//   6. THE RECOVERY CODE, reached by the code page's way round.
//   7. THE SET-UP STEP: Ignore refused on a required step, an authenticator
//      app begun (`next: mfa`, the secret's `otpauth:` URI in the view),
//      a wrong first code refused, the right one signing in.
//   8. THE PASSKEY STEP: its enrolment ceremony armed, a result with no
//      ceremony in it refused, the step kept.
//   9. A SESSION REFUSED AT THE END OF A STEP is drawn on the sign-in
//      screen: the answer names it, and its view carries the sentence.
//  10. THE STEP'S ID IS NEVER IN AN AUDIT ROW.
//  11. START OVER (rcbj, 2026-10-12): every step's Start over ends the
//      step, puts the pending sign-in back under its id, and answers the
//      sign-in screen for it; a second start over and the old step are
//      refused; signing in again completes the ORIGINAL request. And the
//      forced password change's own Start over, changing nothing.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'authn_mfa_api',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

/**
 * The child process: builds the stack, listens, and asks.
 *
 * @returns {void}
 */
function childMain() {
  const ROOT_DIR = process.env.AM_ROOT;
  const OUT = process.env.AM_OUT;
  const http = require('http');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    const authn = require(ROOT_DIR + '/authn/authn');
    const config = require(ROOT_DIR + '/common/config');
    const credentials = require(ROOT_DIR + '/common/credentials');
    const accountState = require(ROOT_DIR + '/common/account_state');
    const websecurity = require(ROOT_DIR + '/common/websecurity');
    const audit = require(ROOT_DIR + '/common/audit');
    const ldap = require(ROOT_DIR + '/ldap/ldap_server');
    const totp = require(ROOT_DIR + '/common/totp');
    const screen = require(ROOT_DIR + '/tests/tools/authn_screen');

    const server = http.createServer(app);
    await new Promise(function (r) {
      server.listen(0, '127.0.0.1', r);
    });
    const port = server.address().port;
    const begin = function () {
      return authn.beginAuthentication({ returnTo: '/am/after?x=1',
        protocol: 'am-probe', application: '' });
    };
    const codeFree = function (text) {
      return !/STS-[A-Z0-9]+-\d{4}/.test(String(text || ''));
    };
    const session = function (jar) {
      return String(jar.sts_session || '').split('.')[0];
    };
    // A person holding an authenticator app, and the secret.
    const withApp = function (who) {
      ldap.createUser(who, { invent: false });
      const begun = credentials.beginTotpEnrolment(who, {});
      credentials.confirmTotpEnrolment(who, totp.codeAt(begun.secret));
      return begun.secret;
    };
    // Signed in on a password, to the step's page: `{ jar, answer, opened }`.
    const toStep = async function (who, fields) {
      const jar = {};
      const answer = await screen.submit({ port: port, jar: jar, at: begin(),
        fields: Object.assign({ action: 'login', username: who,
                                password: 'x' }, fields || {}) });
      const opened = answer.next === 'mfa'
        ? await screen.openStep({ port: port, jar: jar, at: answer.location })
        : null;
      return { jar: jar, answer: answer, opened: opened };
    };
    const act = function (s, op, body, extra) {
      return screen.stepAct(Object.assign({ port: port, jar: s.jar,
        opened: s.opened, op: op, body: body || {} }, extra || {}));
    };

    // --- 1. the shells ---------------------------------------------------
    const secret = withApp('am-tom');
    let s = await toStep('am-tom');
    note(s.answer.next === 'mfa' && s.answer.step === 'totp' &&
         /^\/authn\/totp\?mfa=/.test(s.answer.location),
         '1a. a person holding an app is answered the code page\'s address',
         s.answer.text);
    // Every view a step's page is drawn from, for 11k.
    const drawn = [{ path: '/authn/totp', view: s.opened.view }];
    const shell = s.opened.shell;
    const csp = String(shell.headers['content-security-policy'] || '');
    note(shell.status === 200 &&
         shell.text.indexOf('<script src="/authn/signin.js" defer>' +
                            '</script>') > 0 &&
         !/<form/.test(shell.text) && !/name="mfa_id"/.test(shell.text) &&
         /frame-ancestors 'none'/.test(csp) &&
         /script-src 'self'(;|$)/.test(csp),
         '1b. /authn/totp answers the sign-in surface\'s shell, no form, ' +
         'frame-ancestors kept', shell.status + ' ' + csp);
    let r = await screen.call({ port: port, jar: {}, method: 'GET',
      path: '/authn/totp?mfa=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' });
    note(r.status === 400 && r.json && r.json.error === 'invalid_request' &&
         /expired/.test(r.json.error_description),
         '1c. a step that cannot be drawn is refused at the shell, as the ' +
         'page always was', r.status + ' ' + r.text.slice(0, 200));
    r = await screen.call({ port: port, jar: s.jar, method: 'GET',
      path: '/authn/webauthn?mfa=' + s.opened.id });
    note(r.status === 400 && /No passkey is registered/.test(r.text),
         '1d. the passkey page is refused to a step whose person holds no ' +
         'key and was not minted for an enrolment', r.status + ' ' +
         r.text.slice(0, 200));
    for (const p of ['/authn/totp', '/authn/backup-code', '/authn/webauthn',
                     '/authn/password-factor', '/authn/mfa-setup',
                     '/authn/email-code', '/authn/email-link',
                     '/authn/email-link/open']) {
      r = await screen.call({ port: port, jar: {}, method: 'POST', path: p,
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: 'mfa_id=' + s.opened.id + '&code=000000' });
      note(r.status === 404, '1e. POST ' + p + ' is gone', r.status);
    }
    r = await screen.call({ port: port, jar: {}, method: 'GET',
                            path: '/authn/webauthn.js' });
    note(r.status === 404 || !/javascript/.test(String(
           r.headers['content-type'] || '')),
         '1f. /authn/webauthn.js is no longer served', r.status);

    // --- 2. the index and the document -----------------------------------
    r = await screen.call({ port: port, jar: {}, method: 'GET',
                            path: '/authn-api' });
    const ops = ((r.json && r.json.operations) || []).map(function (op) {
      return op.method + ' ' + op.path;
    });
    note(['GET /authn-api/mfa/{id}', 'POST /authn-api/mfa/{id}/totp',
          'POST /authn-api/mfa/{id}/backup-code',
          'POST /authn-api/mfa/{id}/password',
          'POST /authn-api/mfa/{id}/webauthn/options',
          'POST /authn-api/mfa/{id}/webauthn',
          'POST /authn-api/mfa/{id}/setup/totp',
          'POST /authn-api/mfa/{id}/setup/confirm',
          'POST /authn-api/mfa/{id}/setup/webauthn',
          'POST /authn-api/mfa/{id}/skip',
          'POST /authn-api/mfa/{id}/email/send',
          'POST /authn-api/mfa/{id}/email/code',
          'POST /authn-api/mfa/{id}/email-link/open',
          'POST /authn-api/mfa/{id}/start-over']
           .every(function (one) {
             return ops.indexOf(one) >= 0;
           }), '2a. the index names every step operation', ops.join(', '));
    r = await screen.call({ port: port, jar: {}, method: 'GET',
                            path: '/authn-api/openapi.json' });
    const doc = (r.json && r.json.paths) || {};
    note(doc['/authn-api/mfa/{id}/totp'] &&
         doc['/authn-api/mfa/{id}/totp'].post.requestBody &&
         doc['/authn-api/mfa/{id}'] && doc['/authn-api/mfa/{id}'].get,
         '2b. the OpenAPI document carries them with their bodies');

    // --- 3. the view -----------------------------------------------------
    const v = s.opened.view || {};
    note(s.opened.status === 200 && v.page === 'totp' &&
         v.username === 'am-tom' && v.totp && v.totp.digits === 6 &&
         v.links && v.links.backup === false &&
         !/<[a-z]/.test(JSON.stringify(v)),
         '3a. the code page\'s view is facts and no markup', s.opened.text);
    note(s.opened.csrf && s.opened.csrf === websecurity.tokenFor(
           session(s.jar)),
         '3b. csrf is the token of the cookie\'s session', s.opened.csrf);
    r = await screen.call({ port: port, jar: s.jar, method: 'GET',
      path: '/authn-api/mfa/' + s.opened.id + '?page=password',
      headers: { accept: 'application/json' } });
    note(r.status === 400 && r.json && r.json.ok === false &&
         /password as its second factor/.test(r.text) && codeFree(r.text),
         '3c. a page its step cannot be drawn on is refused, code-free',
         r.status + ' ' + r.text.slice(0, 200));
    r = await screen.call({ port: port, jar: s.jar, method: 'GET',
      path: '/authn-api/mfa/' + s.opened.id + '?page=nonsense',
      headers: { accept: 'application/json' } });
    note(r.status === 400, '3d. a page that is not one is refused',
         r.status);
    r = await screen.call({ port: port, jar: s.jar, method: 'GET',
      path: '/authn-api/mfa/' + s.opened.id + '?page=email-code',
      headers: { accept: 'application/json' } });
    note(r.status === 400 && r.json && r.json.view &&
         r.json.view.state === 'end' &&
         r.json.view.title === 'This sign-in has expired',
         '3e. an emailed factor\'s page for a step that offers none is its ' +
         'end page (#573)', r.text.slice(0, 300));

    // --- 4. the binding --------------------------------------------------
    r = await act(s, 'totp', 'code=000000',
                  { contentType: 'application/x-www-form-urlencoded' });
    note(r.status === 415 && codeFree(r.text), '4a. not JSON (415)',
         r.status);
    r = await act(s, 'totp', { code: '000000' }, { origin: null });
    note(r.status === 403, '4b. no Origin (403)', r.status);
    r = await act(s, 'totp', { code: '000000' },
                  { origin: 'https://evil.example' });
    note(r.status === 403, '4c. another origin (403)', r.status);
    r = await act(s, 'totp', { code: '000000' },
                  { csrf: websecurity.tokenFor('another-session') });
    note(r.status === 403, '4d. another session\'s token (403)', r.status);
    r = await screen.act({ port: port, jar: s.jar, opened: s.opened,
      path: '/authn-api/mfa/not*an*id/totp', body: { code: '000000' } });
    note(r.status === 400, '4e. a malformed id (400)', r.status);
    r = await screen.act({ port: port, jar: s.jar, opened: s.opened,
      path: '/authn-api/mfa/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/totp',
      body: { code: '000000' } });
    note(r.status === 400 && /expired/.test(r.errors.join(' ')) &&
         codeFree(r.text), '4f. an unknown id (400)', r.text);
    r = await act(s, 'totp', { code: '000000', admin: '1' });
    note(r.status === 400, '4g. a field the operation does not take (400)',
         r.status);

    // --- 5. the one-time code --------------------------------------------
    const right = totp.codeAt(secret, Date.now() + 30000);
    const wrongCode = right === '000000' ? '111111' : '000000';
    r = await act(s, 'totp', { code: wrongCode });
    note(r.apiStatus === 400 && r.next === 'refused' && r.errors.length &&
         codeFree(r.text) &&
         !/sts_session=/.test(String(r.headers['set-cookie'] || '')),
         '5a. a wrong code is refused, English and code-free, with no ' +
         'session', r.text);
    r = await act(s, 'totp', { code: right });
    note(r.next === 'redirect' && r.location === '/am/after?x=1' &&
         /sts_session=/.test(String(r.headers['set-cookie'] || '')),
         '5b. the step survives a wrong code, and the right one signs in: ' +
         'next: redirect, the session cookie set on that answer', r.text);
    r = await act(s, 'totp', { code: right });
    note(r.apiStatus === 400, '5c. and the step is spent', r.apiStatus);
    config.setOverride('security.rateLimitPerIdentity', 2);
    withApp('am-rl');
    s = await toStep('am-rl');
    let last = null;
    for (let i = 0; i < 4; i++) {
      last = await act(s, 'totp', { code: '000000' });
    }
    note(last.apiStatus === 429 && last.next === 'refused' &&
         codeFree(last.text), '5d. the code\'s rate limit answers 429',
         last.text);
    config.clearOverride('security.rateLimitPerIdentity');

    // --- 6. the recovery code --------------------------------------------
    const rcSecret = withApp('am-rc');
    void rcSecret;
    const set = credentials.beginBackupCodes('am-rc');
    credentials.confirmBackupCodes('am-rc', set.handle);
    s = await toStep('am-rc');
    note(s.opened.view && s.opened.view.links.backup === true,
         '6a. the code page offers the recovery code as a way round',
         s.opened.text);
    const rc = await screen.openStep({ port: port, jar: s.jar,
      at: '/authn/backup-code?mfa=' + s.opened.id });
    note(rc.status === 200 && rc.view.page === 'backup-code' &&
         rc.view.backup.factor === 'app' &&
         rc.view.backup.remaining === set.codes.length,
         '6b. its page says what it stands in for and how many are left',
         rc.text);
    drawn.push({ path: '/authn/backup-code', view: rc.view });
    r = await screen.stepAct({ port: port, jar: s.jar, opened: rc,
      op: 'backup-code', body: { code: 'AAAAA-AAAAA' } });
    note(r.apiStatus === 400 && r.next === 'refused',
         '6c. a wrong recovery code is refused', r.text);
    r = await screen.stepAct({ port: port, jar: s.jar, opened: rc,
      op: 'backup-code', body: { code: set.codes[0] } });
    note(r.next === 'redirect' &&
         credentials.backupCodeStatus('am-rc').remaining ===
           set.codes.length - 1,
         '6d. a right one signs in and is spent', r.text);

    // --- 7. the set-up step ----------------------------------------------
    ldap.createUser('am-sue', { invent: false });
    credentials.setMfaRequired('am-sue', true);
    s = await toStep('am-sue');
    note(s.answer.next === 'mfa' && s.answer.step === 'enrol' &&
         s.opened.view.page === 'setup' &&
         s.opened.view.setup.state === 'choose' &&
         s.opened.view.setup.optional === false,
         '7a. a required second factor answers the set-up step\'s choice',
         s.opened.text);
    drawn.push({ path: '/authn/mfa-setup', view: s.opened.view });
    r = await act(s, 'skip', {});
    note(r.apiStatus === 400 && /cannot be ignored/.test(r.errors.join(' ')),
         '7b. Ignore is refused on a required step', r.text);
    r = await act(s, 'setup/totp', {});
    note(r.next === 'mfa' && r.step === 'enrol-totp' &&
         /^\/authn\/mfa-setup\?mfa=/.test(r.location),
         '7c. an authenticator app begun answers the set-up page again',
         r.text);
    const enrolling = await screen.openStep({ port: port, jar: s.jar,
                                              at: r.location });
    const k = (enrolling.view && enrolling.view.setup &&
               enrolling.view.setup.totp) || {};
    note(enrolling.view.setup.state === 'totp' &&
         /^otpauth:\/\/totp\//.test(String(k.uri)) && k.secret &&
         !/<svg|data:image/.test(enrolling.text),
         '7d. its view carries the otpauth: URI the browser draws, and no ' +
         'picture', enrolling.text.slice(0, 300));
    drawn.push({ path: '/authn/mfa-setup', view: enrolling.view });
    const uriSecret = new URL(String(k.uri)).searchParams.get('secret');
    const good = totp.codeAt(uriSecret);
    r = await act(s, 'setup/confirm',
                  { code: good === '000000' ? '111111' : '000000' });
    note(r.apiStatus === 400 && r.next === 'refused',
         '7e. a wrong first code is refused, the secret kept', r.text);
    r = await act(s, 'setup/confirm', { code: good });
    note(r.next === 'redirect' && r.location === '/am/after?x=1' &&
         credentials.mechanismsFor('am-sue').totp,
         '7f. the right one enrols the app and signs in', r.text);

    // --- 8. the passkey step ---------------------------------------------
    s = await toStep('am-kim', { use_webauthn: '1' });
    note(s.answer.next === 'mfa' && s.answer.step === 'webauthn' &&
         s.opened.view.webauthn.mode === 'create',
         '8a. ticking the passkey box answers its enrolment page',
         s.opened.text);
    drawn.push({ path: '/authn/webauthn', view: s.opened.view });
    r = await act(s, 'webauthn/options', {});
    const c = r.json || {};
    note(r.apiStatus === 200 && c.mode === 'create' && c.challenge &&
         c.rpId && c.user && c.user.name === 'am-kim' && c.user.id &&
         Array.isArray(c.exclude) && c.options,
         '8b. its ceremony is armed: challenge, RP ID, user and its handle, ' +
         'the policy\'s options', r.text.slice(0, 300));
    r = await act(s, 'webauthn', {});
    note(r.apiStatus === 400 &&
         /did not run the ceremony/.test(r.errors.join(' ')),
         '8c. a result with no ceremony in it is refused', r.text);
    r = await act(s, 'webauthn', { credential: '{"error":"NotAllowedError",' +
                                               '"message":"declined"}' });
    note(r.apiStatus === 400 && /NotAllowedError/.test(r.errors.join(' ')),
         '8d. the browser\'s refusal is said as given, the step kept',
         r.text);

    // --- 9. a session refused at the end of a step -----------------------
    const dSecret = withApp('am-dan');
    s = await toStep('am-dan');
    accountState.setDisabled('am-dan', true, { actor: 'test' });
    r = await act(s, 'totp', { code: totp.codeAt(dSecret,
                                                 Date.now() + 30000) });
    note(r.apiStatus === 400 && r.next === 'refused' &&
         /^\/authn\/login\?authn=/.test(String(r.json && r.json.location)),
         '9a. a session refused at the end of the step answers the sign-in ' +
         'screen\'s address', r.text);
    const back = await screen.open({ port: port, jar: s.jar,
      at: String(r.json && r.json.location) });
    note(back.status === 200 && back.view &&
         /Authentication failed/.test(String(back.view.error)),
         '9b. and the screen\'s view says why', JSON.stringify(back.view &&
                                                    back.view.error));

    // --- 11. start over ---------------------------------------------------
    const soSecret = withApp('am-sam');
    const soAt = begin();
    const soId = new URL(soAt, 'http://here.invalid').searchParams
      .get('authn');
    const soJar = {};
    const soAnswer = await screen.submit({ port: port, jar: soJar, at: soAt,
      fields: { action: 'login', username: 'am-sam', password: 'x' } });
    const soOpened = await screen.openStep({ port: port, jar: soJar,
                                             at: soAnswer.location });
    s = { jar: soJar, answer: soAnswer, opened: soOpened };
    note(soAnswer.next === 'mfa' && !authn.pendingFor(soId),
         '11a. while the step is open, the pending sign-in is the step\'s',
         soAnswer.text);
    r = await act(s, 'start-over', {});
    note(r.next === 'redirect' &&
         r.location === '/authn/login?authn=' + encodeURIComponent(soId) &&
         !/sts_session=/.test(String(r.headers['set-cookie'] || '')) &&
         codeFree(r.text),
         '11b. Start over answers the sign-in screen for the SAME request, ' +
         'and starts no session', r.text);
    note(!authn.mfaStepFor(soOpened.id) && !!authn.pendingFor(soId),
         '11c. the step is gone and the pending sign-in is back under its id');
    const soScreen = await screen.open({ port: port, jar: soJar,
                                         at: r.location });
    note(soScreen.status === 200 && soScreen.view &&
         !soScreen.view.error,
         '11d. the sign-in screen draws for it, with no sentence on it',
         soScreen.status + ' ' + JSON.stringify(soScreen.view &&
                                                soScreen.view.error));
    r = await act(s, 'start-over', {});
    note(r.apiStatus === 400 && r.next === 'refused' && codeFree(r.text),
         '11e. a second Start over from the ended step is refused', r.text);
    r = await act(s, 'totp', { code: totp.codeAt(soSecret,
                                                 Date.now() + 30000) });
    note(r.apiStatus === 400, '11f. and the old step takes no code',
         r.text);
    const again = await screen.submit({ port: port, jar: soJar,
      at: '/authn/login?authn=' + encodeURIComponent(soId), opened: soScreen,
      fields: { action: 'login', username: 'am-sam', password: 'x' } });
    const againStep = await screen.openStep({ port: port, jar: soJar,
                                              at: again.location });
    r = await screen.stepAct({ port: port, jar: soJar, opened: againStep,
      op: 'totp', body: { code: totp.codeAt(soSecret, Date.now() + 30000) } });
    note(again.next === 'mfa' && r.next === 'redirect' &&
         r.location === '/am/after?x=1' &&
         /sts_session=/.test(String(r.headers['set-cookie'] || '')),
         '11g. signing in again completes the ORIGINAL request',
         again.text + ' ' + r.text);
    note(audit.list().some(function (row) {
      return row.action === 'authn.sign-in.started-over' &&
             row.actor === 'am-sam';
    }), '11h. the audit log records the start over');
    // The set-up step and the emailed factor's pages are steps of the same
    // store; the passkey page's control is the same act.
    ldap.createUser('am-sid', { invent: false });
    credentials.setMfaRequired('am-sid', true);
    s = await toStep('am-sid');
    r = await act(s, 'start-over', {});
    note(s.answer.step === 'enrol' && r.next === 'redirect' &&
         /^\/authn\/login\?authn=/.test(r.location) &&
         !authn.mfaStepFor(s.opened.id),
         '11i. the set-up step starts over too', r.text);
    // The forced password change: nothing changed, the request kept.
    ldap.createUser('am-pat', { invent: false });
    credentials.setPasswordResetRequired('am-pat', true);
    const pcAt = begin();
    const pcId = new URL(pcAt, 'http://here.invalid').searchParams
      .get('authn');
    const pcJar = {};
    r = await screen.submit({ port: port, jar: pcJar, at: pcAt,
      fields: { action: 'login', username: 'am-pat', password: 'x' } });
    const pcOpened = await screen.open({ port: port, jar: pcJar,
                                         at: r.location });
    r = await screen.act({ port: port, jar: pcJar, opened: pcOpened,
      path: '/authn-api/password-change/' +
            encodeURIComponent(pcOpened.id) + '/start-over', body: {} });
    note(r.next === 'redirect' &&
         r.location === '/authn/login?authn=' + encodeURIComponent(pcId) &&
         !!authn.pendingFor(pcId) &&
         credentials.passwordResetRequired('am-pat') === true,
         '11j. the forced password change starts over, changing nothing',
         r.text);
    // Every page draws the control, a real button the runtime sends as the
    // start-over act (`web_authn.ts` reads `action`).
    drawn.push({ path: '/authn/password-change', view: pcOpened.view });
    const AuthnPages = require(ROOT_DIR + '/authn/web_authn_pages');
    const messages = require(ROOT_DIR + '/common/web_messages');
    const flat = {};
    ['authn', 'emailFactor'].forEach(function (ns) {
      const own = JSON.parse(fs.readFileSync(path.join(ROOT_DIR, 'common',
        'locales', ns, 'en.json'), 'utf8'));
      Object.keys(own).forEach(function (key) {
        flat[ns + '.' + key] = own[key];
      });
    });
    const tr = messages.WebTranslator.fromData({ catalogs: { en: flat },
      negotiated: { locale: 'en', chain: ['en'], catalog: 'en',
                    direction: 'ltr', matched: true } });
    const missing = drawn.filter(function (one) {
      const html = AuthnPages.render(one.path, one.view,
        { t: tr, error: '', notice: '', query: {} });
      return !/<button type="submit" class="secondary" id="start-over" name="action" value="start-over">Start over<\/button>/
        .test(html) || /<form[^>]*>(?:(?!<\/form>)[\s\S])*<form/.test(html);
    }).map(function (one) {
      return one.path + ' ' + ((one.view && one.view.setup &&
                                one.view.setup.state) || '');
    });
    note(drawn.length === 6 && missing.length === 0,
         '11k. every step page draws Start over, as a form of its own',
         missing.join(', '));

    // --- 10. the id in the audit log -------------------------------------
    const rows = audit.list().filter(function (row) {
      return /\/authn-api\/mfa\//.test(String(row.target || ''));
    });
    note(rows.length > 0 && rows.every(function (row) {
      return /\/authn-api\/mfa\/\(redacted\)/.test(String(row.target));
    }), '10. an audit row names the operation and never the step\'s id',
         rows.slice(0, 3).map(function (row) {
           return row.target;
         }).join(' '));

    server.close();
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    note(false, 'the child process ran to the end', e && e.stack);
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

/**
 * Runs the child and reports its findings.
 *
 * @param {object} t - the runner's assertion helper
 * @returns {Promise<void>} when done
 */
async function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'am-' + process.pid + '-' + Date.now() +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$|ADMIN_API_)/
        .test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal',
                                  AM_ROOT: ROOT, AM_OUT: out }),
      encoding: 'utf8', timeout: 180000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings),
               'the child process reported its findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-800))) {
    log.debug("Leaving run().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'authn_mfa_api',
  describe: 'the second-factor and emailed-factor steps are pages of the ' +
            'sign-in surface over /authn-api: the shells, the views, the ' +
            'CSRF binding, every act and its next step, and the step\'s id ' +
            'never in an audit row (#572, #573)',
  run: run
};
