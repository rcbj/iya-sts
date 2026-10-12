// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/authn_api.js
// ===========================================================================
// THE SIGN-IN SCREEN IS A STATIC SURFACE OVER `/authn-api` (#571).
//
// The whole stack in a child process, over HTTP on 127.0.0.1:
//
//   1. THE SHELL: `/authn/login?authn=<id>` answers the shell document —
//      the bundle, the card, the `<noscript>`, no form — with a policy that
//      keeps `frame-ancestors`, and mints the `sts_session` arrival cookie
//      for a browser without one; an unknown id is refused as it was.
//      The bundle is served.
//   2. THE INDEX AND THE OPENAPI DOCUMENT list every operation and the
//      control it mirrors.
//   3. THE VIEW: facts and no words, and `csrf` — the token of the
//      cookie's session.
//   4. THE BINDING of an act: JSON, an Origin of this service, the token;
//      a malformed id, an unknown id and an unknown field are refused; no
//      refusal carries an error code.
//   5. THE ACTS: a refused password (the pending sign-in kept, no session
//      cookie), a signed-in password (the session cookie set on the answer
//      that completes it, `next: redirect` to returnTo, the record spent),
//      Cancel (access_denied), Continue without signing in (on and off),
//      the rate limit (429), a second factor (`next: mfa`, its page drawn by
//      its own GET), the forced password change (`next: password-change`,
//      its view, a mismatch refused, the change continuing the sign-in), an
//      enrolment ceremony drawn by `GET /authn/webauthn`.
//   6. THE ID IS NEVER IN AN AUDIT ROW.
//   7. THE OLD FORM POSTS ARE GONE.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'authn_api',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

/**
 * The child process: builds the stack, listens, and asks.
 *
 * @returns {void}
 */
function childMain() {
  const ROOT_DIR = process.env.AA_ROOT;
  const OUT = process.env.AA_OUT;
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
    const authnApi = require(ROOT_DIR + '/authn/authn_api');
    const config = require(ROOT_DIR + '/common/config');
    const credentials = require(ROOT_DIR + '/common/credentials');
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
    const begin = function (extra) {
      return authn.beginAuthentication(Object.assign({
        returnTo: '/aa/after?x=1', protocol: 'aa-probe', application: '' },
        extra || {}));
    };
    const session = function (jar) {
      return String(jar.sts_session || '').split('.')[0];
    };
    const codeFree = function (text) {
      return !/STS-[A-Z0-9]+-\d{4}/.test(String(text || ''));
    };

    // --- 1. the shell ------------------------------------------------------
    let at = begin();
    const jar = {};
    let r = await screen.call({ port: port, jar: jar, method: 'GET',
                                path: at });
    const csp = String(r.headers['content-security-policy'] || '');
    note(/^\/authn\/login\?authn=/.test(at) && r.status === 200 &&
         /no-store/.test(String(r.headers['cache-control'])) &&
         r.text.indexOf('<script src="/authn/signin.js" defer></script>') >
           0 &&
         r.text.indexOf('<link rel="stylesheet" href="/web/card.css">') > 0 &&
         r.text.indexOf('<noscript>') > 0 && !/<form/.test(r.text) &&
         !/name="password"/.test(r.text),
         '1a. /authn/login answers the shell: the bundle, the card, the ' +
         'notice, and no form', r.status + ' ' + r.text.slice(0, 500));
    note(/frame-ancestors 'none'/.test(csp) &&
         /script-src 'self'(;|$)/.test(csp) &&
         /connect-src 'self'/.test(csp) && !/unsafe-inline/.test(csp),
         '1b. its policy keeps frame-ancestors and allows script and API ' +
         'from \'self\' only', csp);
    note(!!jar.sts_session,
         '1c. and it mints the arrival cookie for a browser without one',
         JSON.stringify(Object.keys(jar)));
    r = await screen.call({ port: port, jar: {}, method: 'GET',
                            path: '/authn/login?authn=nosuchsignin' });
    note(r.status === 400 && r.json && r.json.error === 'invalid_request',
         '1d. an unknown id is refused as it always was', r.status + ' ' +
         r.text.slice(0, 200));
    r = await screen.call({ port: port, jar: {}, method: 'GET',
                            path: '/authn/signin.js' });
    note(r.status === 200 && /javascript/.test(r.headers['content-type']) &&
         r.text.length > 1000 && r.text.indexOf('was not built') < 0,
         '1e. the bundle is served, built', r.status + ' ' + r.text.length);

    // --- 2. the index and the document ---------------------------------
    r = await screen.call({ port: port, jar: {}, method: 'GET',
                            path: '/authn-api' });
    const ops = (r.json && r.json.operations) || [];
    const mirror = function (m, action) {
      return ops.filter(function (op) {
        return op.mirrors === m && (!action || op.action === action);
      }).length === 1;
    };
    note(r.status === 200 && mirror('GET /authn/login') &&
         mirror('GET /authn/select-idp') &&
         mirror('GET /authn/password-change') &&
         mirror('POST /authn/password-change') &&
         ['login', 'cancel', 'anonymous', 'email', 'passkey-options',
          'passkey'].every(function (a) {
           return mirror('POST /authn/login', a);
         }),
         '2a. the index names the operation each page and control is',
         r.text.slice(0, 400));
    r = await screen.call({ port: port, jar: {}, method: 'GET',
                            path: '/authn-api/openapi.json' });
    note(r.status === 200 && r.json && r.json.openapi === '3.1.0' &&
         r.json.paths['/authn-api/pending/{id}/password'] &&
         r.json.paths['/authn-api/pending/{id}/password'].post.requestBody,
         '2b. the OpenAPI document is generated with the bodies',
         r.text.slice(0, 200));

    // --- 3. the view ---------------------------------------------------------
    let opened = await screen.open({ port: port, jar: jar, at: at });
    const v = opened.view || {};
    note(opened.status === 200 && v.screen === true &&
         typeof v.password === 'boolean' && v.keys && v.demands &&
         v.protocol === 'aa-probe' && Array.isArray(v.details) &&
         !/<[a-z]/.test(JSON.stringify(v)),
         '3a. the view is facts and no markup', JSON.stringify(v)
           .slice(0, 400));
    note(opened.csrf && opened.csrf === websecurity.tokenFor(session(jar)),
         '3b. csrf is the token of the cookie\'s session', opened.csrf);

    // --- 4. the binding ------------------------------------------------------
    const pw = '/authn-api/pending/' + opened.id + '/password';
    const tryAct = function (o) {
      return screen.act(Object.assign({ port: port, jar: jar,
        opened: opened, path: pw, body: { username: 'aa-x',
                                          password: 'p' } }, o));
    };
    r = await tryAct({ contentType: 'application/x-www-form-urlencoded',
                       body: 'username=aa-x' });
    note(r.status === 415 && codeFree(r.text),
         '4a. a body that is not JSON is refused (415)', r.status);
    r = await tryAct({ origin: null });
    note(r.status === 403, '4b. no Origin is refused (403)', r.status);
    r = await tryAct({ origin: 'https://evil.example' });
    note(r.status === 403, '4c. another origin is refused (403)', r.status);
    r = await tryAct({ csrf: '' });
    note(r.status === 403, '4d. no token is refused (403)', r.status);
    r = await tryAct({ csrf: websecurity.tokenFor('another-session') });
    note(r.status === 403 && codeFree(r.text),
         '4e. another session\'s token is refused (403)', r.status);
    r = await screen.act({ port: port, jar: {}, opened: opened, path: pw,
                           body: { username: 'aa-x' } });
    note(r.status === 403, '4f. a browser with no session is refused, ' +
         'whatever token it shows', r.status);
    r = await tryAct({ path: '/authn-api/pending/not*an*id/password' });
    note(r.status === 400, '4g. a malformed id is refused', r.status);
    r = await tryAct({ path: '/authn-api/pending/AAAAAAAAAAAAAAAAAAAAAAAA/' +
                             'password' });
    note(r.status === 400 && /no sign-in waiting/i.test(r.text) &&
         codeFree(r.text), '4h. an unknown id is refused', r.text);
    r = await tryAct({ body: { username: 'aa-x', admin: '1' } });
    note(r.status === 400, '4i. a field the operation does not take is ' +
         'refused', r.status + ' ' + r.text.slice(0, 200));

    // --- 5. the acts ---------------------------------------------------------
    // A refused password: the reserved one, refused in every mode.
    const before = jar.sts_session;
    r = await screen.submit({ port: port, jar: jar, at: at, opened: opened,
      fields: { action: 'login', username: 'aa-ann', password: 'invalid' } });
    note(r.apiStatus === 400 && r.next === 'refused' &&
         /Authentication failed for aa-ann/.test(r.errors.join(' ')) &&
         codeFree(r.text) && jar.sts_session === before &&
         !/sts_session=/.test(String(r.headers['set-cookie'] || '')),
         '5a. a refused password answers next: refused, English and ' +
         'code-free, and sets no session cookie', r.text);
    r = await screen.submit({ port: port, jar: jar, at: at, opened: opened,
      fields: { action: 'login', username: 'aa-ann', password: 'right' } });
    note(r.next === 'redirect' && r.location === '/aa/after?x=1' &&
         /sts_session=/.test(String(r.headers['set-cookie'] || '')),
         '5b. the pending sign-in survives a refusal, and a password signs ' +
         'in: next: redirect to returnTo, the session cookie set on that ' +
         'answer', r.text);
    const signedIn = authn.sessionsOf('aa-ann');
    note(signedIn.length >= 1, '5c. a session exists for the person',
         signedIn.length);
    r = await screen.submit({ port: port, jar: jar, at: at, opened: opened,
      fields: { action: 'login', username: 'aa-ann', password: 'right' } });
    note(r.apiStatus === 400, '5d. and the pending sign-in is spent',
         r.apiStatus);

    // Cancel.
    at = begin();
    r = await screen.submit({ port: port, jar: {}, at: at,
                              fields: { action: 'cancel' } });
    note(r.next === 'redirect' &&
         /authn_error=access_denied/.test(r.location),
         '5e. Cancel answers the caller access_denied', r.location);

    // Continue without signing in: off, then on.
    config.setOverride('authn.unauthenticatedSessions', false);
    at = begin();
    r = await screen.submit({ port: port, jar: {}, at: at,
                              fields: { action: 'anonymous' } });
    note(r.next === 'refused', '5f. anonymous with the setting off is not ' +
         'a session (the form asks for a name)', r.text);
    config.setOverride('authn.unauthenticatedSessions', true);
    at = begin();
    const anon = {};
    opened = await screen.open({ port: port, jar: anon, at: at });
    note(opened.view && opened.view.anonymous === true,
         '5g. the view offers it with the setting on', JSON.stringify(
           opened.view && opened.view.anonymous));
    r = await screen.submit({ port: port, jar: anon, at: at, opened: opened,
                              fields: { action: 'anonymous' } });
    note(r.next === 'redirect' && !!anon.sts_session,
         '5h. and it starts an unauthenticated session', r.text);
    config.setOverride('authn.unauthenticatedSessions', false);

    // The rate limit.
    config.setOverride('security.rateLimitPerIdentity', 2);
    at = begin();
    const rl = {};
    opened = await screen.open({ port: port, jar: rl, at: at });
    let last = null;
    for (let i = 0; i < 4; i++) {
      last = await screen.submit({ port: port, jar: rl, at: at,
        opened: opened, fields: { action: 'login', username: 'aa-rl',
                                  password: 'invalid' } });
    }
    note(last.apiStatus === 429 && last.next === 'refused' &&
         codeFree(last.text),
         '5i. the sign-in rate limit answers 429', last.text);
    config.clearOverride('security.rateLimitPerIdentity');

    // Arming the usernameless passkey ceremony is counted per address
    // (2026-10-12): it names nobody, and every arm mints a challenge.
    config.setOverride('security.rateLimitPerAddress', 2);
    at = begin();
    const pk = {};
    opened = await screen.open({ port: port, jar: pk, at: at });
    const arms = [];
    for (let i = 0; i < 4; i++) {
      arms.push(await screen.passkeyOptions({ port: port, jar: pk,
                                              opened: opened }));
    }
    const lastArm = arms[arms.length - 1];
    note(arms[0].apiStatus === 200 && lastArm.apiStatus === 429 &&
         lastArm.next === 'refused' && codeFree(lastArm.text) &&
         /^\d+$/.test(String(lastArm.headers &&
                              lastArm.headers['retry-after'] || '')),
         '5i-ii. arming the passkey ceremony is rate limited per address: ' +
         '429 with Retry-After', arms.map(function (a) {
           return a.apiStatus;
         }).join(',') + ' ' + lastArm.text);
    config.clearOverride('security.rateLimitPerAddress');

    // A second factor: an authenticator app.
    ldap.createUser('aa-tom', { invent: false });
    const begun = credentials.beginTotpEnrolment('aa-tom', {});
    credentials.confirmTotpEnrolment('aa-tom', totp.codeAt(begun.secret));
    at = begin();
    const tj = {};
    r = await screen.submit({ port: port, jar: tj, at: at,
      fields: { action: 'login', username: 'aa-tom', password: 'x' } });
    note(r.next === 'mfa' && r.step === 'totp' &&
         /^\/authn\/totp\?mfa=/.test(r.location) &&
         !/sts_session=/.test(String(r.headers['set-cookie'] || '')),
         '5j. a person holding an authenticator app is answered next: mfa, ' +
         'the code page\'s address', r.text);
    const page = await screen.openStep({ port: port, jar: tj,
                                         at: r.location });
    note(page.shell.status === 200 && page.status === 200 && page.view &&
         page.view.page === 'totp' && page.view.username === 'aa-tom',
         '5k. and that page is the surface\'s, drawn from its step\'s view ' +
         '(#572)', page.status + ' ' + page.text.slice(0, 200));

    // The forced password change.
    ldap.createUser('aa-pat', { invent: false });
    credentials.setPasswordResetRequired('aa-pat', true);
    at = begin();
    const pj = {};
    r = await screen.submit({ port: port, jar: pj, at: at,
      fields: { action: 'login', username: 'aa-pat', password: 'x' } });
    note(r.next === 'password-change' &&
         /^\/authn\/password-change\?change=/.test(r.location),
         '5l. pwdReset answers next: password-change', r.text);
    const changeAt = r.location;
    const pc = await screen.open({ port: port, jar: pj, at: changeAt });
    note(pc.status === 200 && pc.view && pc.view.username === 'aa-pat',
         '5m. its view names the person', JSON.stringify(pc.json));
    r = await screen.changePassword({ port: port, jar: pj, at: changeAt,
      fields: { new_password: 'One-New-Pass-123!',
                confirm_password: 'Another-123!' } });
    note(r.apiStatus === 400 && /not the same/.test(r.errors.join(' ')),
         '5n. a mismatch is refused, the step kept', r.text);
    r = await screen.changePassword({ port: port, jar: pj, at: changeAt,
      fields: { new_password: 'One-New-Pass-123!',
                confirm_password: 'One-New-Pass-123!' } });
    note(r.next === 'redirect' && r.location === '/aa/after?x=1' &&
         !credentials.passwordResetRequired('aa-pat'),
         '5o. a good change continues the sign-in and clears pwdReset',
         r.text);

    // A security key enrolled at the screen: the ceremony is drawn by GET.
    at = begin();
    const kj = {};
    r = await screen.submit({ port: port, jar: kj, at: at,
      fields: { action: 'login', username: 'aa-kim', password: 'x',
                use_webauthn: '1' } });
    note(r.next === 'mfa' && r.step === 'webauthn',
         '5p. ticking the passkey box answers the ceremony\'s step', r.text);
    const ceremony = await screen.openStep({ port: port, jar: kj,
                                             at: r.location });
    note(ceremony.status === 200 && ceremony.view &&
         ceremony.view.webauthn && ceremony.view.webauthn.mode === 'create',
         '5q. and the passkey page\'s view is its enrolment ceremony',
         ceremony.status + ' ' + ceremony.text.slice(0, 200));

    // --- 6. the id in the audit log ------------------------------------------
    const rows = audit.list().filter(function (row) {
      return /\/authn-api\//.test(String(row.target || ''));
    });
    note(rows.length > 0 && rows.every(function (row) {
      return /\/authn-api\/(pending|password-change)\/\(redacted\)/
        .test(String(row.target)) || !/\/(pending|password-change)\//
        .test(String(row.target));
    }), '6. an audit row names the operation and never the id',
         rows.slice(0, 3).map(function (row) {
           return row.target;
         }).join(' '));

    // --- 7. the old form posts -----------------------------------------------
    at = begin();
    r = await screen.call({ port: port, jar: {}, method: 'POST',
      path: '/authn/login', headers: { 'content-type':
        'application/x-www-form-urlencoded' },
      body: 'authn_id=' + encodeURIComponent(at.split('authn=')[1]) +
            '&username=aa-old&password=x&action=login' });
    note(r.status === 404 && !authn.sessionsOf('aa-old').length,
         '7. POST /authn/login is gone', r.status);
    note(typeof authnApi.operations === 'function' &&
         typeof authn.Authn.prototype.loginPage === 'undefined',
         '7b. and the server no longer draws the screen');

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
  const out = path.join(os.tmpdir(), 'aa-' + process.pid + '-' + Date.now() +
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
                                  AA_ROOT: ROOT, AA_OUT: out }),
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
  name: 'authn_api',
  describe: 'the sign-in screen is a static surface over /authn-api: the ' +
            'shell, the view, the CSRF binding, every act and its next ' +
            'step, and the pending id never in an audit row (#571)',
  run: run
};
