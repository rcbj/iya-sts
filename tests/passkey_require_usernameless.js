// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/passkey_require_usernameless.js
//
// ===========================================================================
// A PASSKEY SIGN-IN WITH NO USERNAME, REQUIRED (#608, rcbj 2026-10-13).
//
// The passkey policy's `requireUsernameless`, asserted against the sign-in
// screen a person reaches (`/oauth2/authorize` → `/authn-api`), in a CHILD
// PROCESS serving the stack on a loopback port (`passkey_discoverable.js`'s
// harness):
//
//   * a save requiring it without `allowUsernameless` is refused;
//   * where it is on, an application whose named authentication policy
//     (appAuthnPolicy, #1148) lists `webauthn` alone gets a view with
//     `usernameless` set, and a sign-in naming a person is refused with
//     STS-AUTHN-0333;
//   * an application with another mechanism beside it keeps its screen;
//   * the `default` profile never holds a hosted surface (the console, the
//     portal, the debugger) to it, and a named profile selecting one does;
//   * the renderer draws no username field and no Sign In for such a view,
//     and greys a box it disables.
// ===========================================================================

delete process.env.CONFIG_FILE;

const path = require('path');
const os = require('os');
const fs = require('fs');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'passkey_require_usernameless',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  const ROOT = process.env.PRU_ROOT;
  const OUT = process.env.PRU_OUT;
  const http = require('http');
  const nodeCrypto = require('crypto');
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const config = require(ROOT + '/common/config');
    const passkeyPolicy = require(ROOT + '/common/passkey_policy');
    const applications = require(ROOT + '/common/applications');
    const audit = require(ROOT + '/common/audit');
    const authn = require(ROOT + '/authn/authn');
    const WebAuthnLogin = require(ROOT + '/authn/web_authn_login');
    const authnScreen = require(ROOT + '/tests/tools/authn_screen');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const REDIRECT = 'https://rp.pru.example/cb';
    config.setOverride('oauth2.consentRequired', false);

    // The mechanisms are a named authentication policy's (#1148), one per
    // client here.
    const client = function (id, mechanisms) {
      require(ROOT + '/common/authn_policy').saveNamed('p-' + id,
        { mechanisms: mechanisms });
      applications.createApplication({ identifier: id,
        protocols: ['oauth2'],
        fields: { oauthClientId: id, oauthClientSecret: '',
                  oauthRedirectUri: [REDIRECT],
                  oauthTokenEndpointAuthMethod: 'none',
                  oauthGrantType: ['authorization_code'],
                  appAuthnPolicy: 'p-' + id } });
    };
    client('pru-passkey', ['webauthn']);
    client('pru-mixed', ['webauthn', 'password']);

    const policy = function (fields, name, selectors) {
      return passkeyPolicy.save(name || 'default', Object.assign({},
        passkeyPolicy.DEFAULTS, fields, selectors || {}));
    };
    const codeRecorded = function (code) {
      return audit.list().some(function (row) {
        return row.errorCode === code;
      });
    };
    const screenFor = async function (clientId) {
      const jar = {};
      const start = await new Promise(function (resolve) {
        const q = new URLSearchParams({ client_id: clientId,
          response_type: 'code', redirect_uri: REDIRECT, scope: 'openid',
          state: 's', nonce: 'n-' + nodeCrypto.randomBytes(8).toString('hex'),
          code_challenge: nodeCrypto.createHash('sha256')
            .update(nodeCrypto.randomBytes(32).toString('base64url'))
            .digest('base64url'),
          code_challenge_method: 'S256' }).toString();
        http.get({ host: '127.0.0.1', port: port,
                   path: '/oauth2/authorize?' + q }, function (res) {
          (res.headers['set-cookie'] || []).forEach(function (line) {
            const pair = line.split(';')[0];
            const eq = pair.indexOf('=');
            jar[pair.slice(0, eq)] = pair.slice(eq + 1);
          });
          res.resume();
          res.on('end', function () {
            resolve(res);
          });
        });
      });
      const opened = await authnScreen.open({ port: port, jar: jar,
        at: String(start.headers.location || '') });
      return { jar: jar, opened: opened, view: opened.view || {} };
    };
    // A pending sign-in's record, as beginAuthentication() makes one for
    // an application that allows a passkey alone.
    const recordFor = function (application) {
      return { forcePasswordless: true, mechanismSource: 'application',
               mechanism: 'webauthn', allowedMechanisms: ['webauthn'],
               application: application, lockedUsername: '' };
    };

    // 1. Off by default.
    let s = await screenFor('pru-passkey');
    note(s.opened.status === 200 && s.view.passkey === true &&
         s.view.usernameless === false,
         '1. off by default: the passkey-only application\'s screen asks ' +
         'for a username as before', JSON.stringify(
           { passkey: s.view.passkey, usernameless: s.view.usernameless }));

    // 2. Required without being allowed: refused.
    const bad = policy({ allowUsernameless: false,
                         requireUsernameless: true });
    note(bad && bad.ok === false &&
         /requireUsernameless/.test((bad.errors || []).join(' ')),
         '2. a save requiring a usernameless sign-in that does not allow ' +
         'one is refused', JSON.stringify(bad));

    // 3. On, for the default profile.
    const on = policy({ allowUsernameless: true,
                        requireUsernameless: true });
    note(on && on.ok === true, '3. requireUsernameless saved on the ' +
         'default profile', JSON.stringify(on && on.errors));
    s = await screenFor('pru-passkey');
    note(s.view.usernameless === true && s.view.passkey === true,
         '3a. an application signing in with a passkey alone: the view ' +
         'asks for no username', JSON.stringify(s.view.usernameless));
    const posted = await authnScreen.act({ port: port, jar: s.jar,
      opened: s.opened,
      path: '/authn-api/pending/' + encodeURIComponent(s.opened.id) +
            '/password',
      body: { username: 'pru-somebody', webauthn_only: '1' } });
    note(posted.apiStatus === 400 && posted.next === 'refused' &&
         codeRecorded('STS-AUTHN-0333'),
         '3b. and a sign-in naming a person is refused (STS-AUTHN-0333)',
         posted.apiStatus + ' ' + posted.text.slice(0, 200));
    const mixed = await screenFor('pru-mixed');
    note(mixed.view.usernameless === false,
         '3c. an application allowing a password too keeps its username ' +
         'field', JSON.stringify(mixed.view.usernameless));

    // 4. The hosted surfaces: never through `default`.
    const hosted = ['sts-admin-console', 'sts-user-portal',
                    'sts-debugger-ui'];
    hosted.forEach(function (id) {
      note(authn.usernamelessRequired(recordFor(id)) === false,
           '4a. the default profile does not hold ' + id + ' to it');
    });
    note(authn.usernamelessRequired(recordFor('pru-passkey')) === true,
         '4b. while it holds an ordinary passkey-only application');
    const named = policy({ allowUsernameless: true,
                           requireUsernameless: true }, 'console-strict',
                         { precedence: 5 });
    // The console names it (`appPasskeyPolicy`, #1235).
    const pointed = applications.updateApplication('sts-admin-console',
      { attribute: 'appPasskeyPolicy', mode: 'set',
        value: 'console-strict' });
    note(named && named.ok === true && pointed.ok === true, '4c. a named ' +
         'profile the console names saved',
         JSON.stringify([named && named.errors, pointed.errors]));
    note(authn.usernamelessRequired(recordFor('sts-admin-console')) === true &&
         authn.usernamelessRequired(recordFor('sts-user-portal')) === false,
         '4d. a named profile selecting the console holds the console, and ' +
         'only it');
    const mixedRecord = Object.assign(recordFor('sts-admin-console'),
      { allowedMechanisms: ['webauthn', 'password'] });
    note(authn.usernamelessRequired(mixedRecord) === false,
         '4e. and not while the console allows anything beside webauthn');
    applications.updateApplication('sts-admin-console',
      { attribute: 'appPasskeyPolicy', mode: 'set', value: 'default' });
    passkeyPolicy.reset('console-strict');
    passkeyPolicy.reset('default');
    note(authn.usernamelessRequired(recordFor('pru-passkey')) === false,
         '4f. reset: required of nobody');

    // 5. The renderer.
    const t = { html: function (key) { return '[' + key + ']'; },
                text: function (key) { return key; } };
    const view = { screen: true, passkey: true, usernameless: true,
                   keys: { enabled: true, mfaAllowed: true,
                           primaryAllowed: true },
                   demands: { passwordless: true } };
    const drawn = WebAuthnLogin.form(view, t, {});
    note(!/id="username"/.test(drawn) && !/id="kc-login"/.test(drawn) &&
         /id="wa-passkey-go"/.test(drawn) && /id="kc-cancel"/.test(drawn),
         '5a. no username field and no Sign In; the passkey button and ' +
         'Cancel', drawn);
    const boxes = WebAuthnLogin.keyBoxes(Object.assign({}, view,
      { usernameless: false }), t);
    note(/<label class="chk off"><input type="checkbox" id="use_webauthn"/
           .test(boxes) &&
         /<label class="chk"><input type="checkbox" id="webauthn_only"/
           .test(boxes),
         '5b. the unavailable second-step box is greyed; the box a demand ' +
         'checked is not', boxes);
  })().catch(function (e) {
    note(false, 'the child ran to the end', e && e.stack);
  }).then(function () {
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'sts-pru-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = Object.assign({}, process.env, { PRU_OUT: out,
    PRU_ROOT: ROOT, STS_HTTPS: 'false' });
  delete env.CONFIG_FILE;
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      cwd: ROOT, env: env, encoding: 'utf8', timeout: 180000,
      maxBuffer: 256 * 1024 * 1024 });
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
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'passkey_require_usernameless',
  describe: 'the passkey policy\'s requireUsernameless: no username field ' +
            'for a passkey-only application, the refusal, and the hosted ' +
            'surfaces held only by a named profile (#608)',
  run: run
};
