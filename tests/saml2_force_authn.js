'use strict';
//
// File: saml2_force_authn.js
//
// ===========================================================================
// ONE TRIP TO THE SIGN-IN SCREEN PER SAML 2.0 REQUEST (2026-09-14).
//
// THE LOOP. `/saml2/sso` holds an AuthnRequest while the person is at the
// sign-in screen, and the return address reads the request again from its XML.
// So `ForceAuthn="true"` was as true on the way back as on the way in, the
// fresh session the person had just made changed nothing, and they were sent
// to the screen again — for ever. Cancel looped too, for a different reason:
// the `authn_error` the screen reports was checked AFTER the session, and a
// person who cancels has no session, so they were sent back to the screen
// before the cancellation was read. A RequestedAuthnContext the sign-in could
// not meet had the same shape as ForceAuthn.
//
// An in-process probe drove all three and counted redirects: twelve hops and
// still going, for ForceAuthn and for Cancel. `saml/CLAUDE.md` records the fix;
// this file is its contract, over HTTP, against the whole stack:
//
//   1. ForceAuthn with no session: one trip, a Success Response.
//   2. ForceAuthn with a session: the screen IS shown (the attribute still
//      means something), one trip, Success, and a fresh AuthnInstant.
//   3. ForceAuthn, and the browser comes back WITHOUT authenticating again:
//      AuthnFailed (STS-SAML-0055), not the screen a second time.
//   4. Cancel at the screen with no session: AuthnFailed after one trip.
//   5. A multi-factor RequestedAuthnContext still unmet on the way back:
//      NoAuthnContext (STS-SAML-0056).
//   6. Unchanged: a plain request with a session is single sign-on with no
//      screen, and IsPassive with no session is NoPassive.
//
// WHY A CHILD PROCESS: it serves the whole protocol stack on a loopback port.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const log = require('bunyan').createLogger({ name: 'saml2_force_authn',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.FA_ROOT;
  const OUT = process.env.FA_OUT;
  const http = require('http');
  const zlib = require('zlib');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const realms = require(ROOT + '/common/realms');
    const audit = require(ROOT + '/common/audit');
    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const base = 'http://127.0.0.1:' + port;
    // One of the classes `saml2_sso.ts` reads as a demand for a second factor
    // (`AC_MFA_DEMANDS`).
    const MFA =
      'urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract';
    const authn = require(ROOT + '/authn/authn');

    let jar = {};
    function request(method, target, form) {
      const url = new URL(target, base);
      return new Promise(function (resolve) {
        const body = form ? new URLSearchParams(form).toString() : '';
        const headers = { cookie: Object.keys(jar).map(function (k) {
          return k + '=' + jar[k];
        }).join('; ') };
        if (form) {
          headers['content-type'] = 'application/x-www-form-urlencoded';
          headers['content-length'] = Buffer.byteLength(body);
        }
        const req = http.request({ host: '127.0.0.1', port: port,
          path: url.pathname + url.search, method: method, headers: headers },
        function (res) {
          [].concat(res.headers['set-cookie'] || []).forEach(function (line) {
            const pair = String(line).split(';')[0];
            const i = pair.indexOf('=');
            if (i > 0 && pair.slice(i + 1)) {
              jar[pair.slice(0, i)] = pair.slice(i + 1);
            }
          });
          let text = '';
          res.on('data', function (c) { text += c; });
          res.on('end', function () {
            resolve({ status: res.statusCode, location: res.headers.location,
                      text: text });
          });
        });
        req.end(body);
      });
    }

    function authnRequest(opts) {
      const o = opts || {};
      const xml = '<samlp:AuthnRequest ' +
        'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' +
        'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ' +
        'ID="_fa' + Date.now() + Math.random().toString(36).slice(2) + '" ' +
        'Version="2.0" IssueInstant="' + new Date().toISOString() + '" ' +
        'AssertionConsumerServiceURL="' + base + '/saml2/sp/acs"' +
        (o.force ? ' ForceAuthn="true"' : '') +
        (o.passive ? ' IsPassive="true"' : '') + '>' +
        '<saml:Issuer>urn:force-authn:sp</saml:Issuer>' +
        (o.context ? '<samlp:RequestedAuthnContext Comparison="exact">' +
          '<saml:AuthnContextClassRef>' + o.context +
          '</saml:AuthnContextClassRef></samlp:RequestedAuthnContext>' : '') +
        '</samlp:AuthnRequest>';
      return '/saml2/sso?SAMLRequest=' + encodeURIComponent(
        zlib.deflateRawSync(Buffer.from(xml)).toString('base64'));
    }

    // What came back: the decoded Response's status codes and AuthnInstant.
    function responseOf(r) {
      const m = /name="SAMLResponse" value="([^"]+)"/.exec(r.text);
      if (!m) {
        return null;
      }
      const xml = Buffer.from(m[1], 'base64').toString('utf8');
      const codes = [];
      const re = /StatusCode Value="([^"]+)"/g;
      let one;
      while ((one = re.exec(xml))) {
        codes.push(one[1].split(':').pop());
      }
      const instant = /AuthnInstant="([^"]+)"/.exec(xml);
      const message = /<samlp:StatusMessage>([^<]*)</.exec(xml);
      return { codes: codes, authnInstant: instant ? instant[1] : '',
               message: message ? message[1] : '' };
    }

    // Walks a flow. `atScreen` decides what happens at the sign-in screen:
    // 'login', 'cancel', or 'skip' — go straight to the return address, which
    // is what a browser that never authenticated would present.
    async function drive(start, atScreen, username) {
      let r = await request('GET', start);
      let screens = 0;
      let returnTo = '';
      for (let hop = 0; hop < 12; hop += 1) {
        if (r.status >= 300 && r.status < 400 && r.location) {
          if (/\/authn\/login/.test(r.location)) {
            screens += 1;
          } else if (/\/saml2\/sso\?rid=/.test(r.location)) {
            returnTo = r.location;
          }
          r = await request('GET', r.location);
          continue;
        }
        const authnId = /name="authn_id" value="([^"]+)"/.exec(r.text);
        if (r.status === 200 && authnId) {
          if (atScreen === 'skip') {
            // The return address the sign-in would have sent the browser to,
            // off the pending record — presented without authenticating.
            const pending = realms.run(realms.DEFAULT_REALM, function () {
              return authn.pendingFor(authnId[1]);
            });
            returnTo = pending ? pending.returnTo : '';
            r = await request('GET', returnTo);
            atScreen = 'done';
            continue;
          }
          r = await request('POST', '/authn/login', {
            authn_id: authnId[1], username: username || 'fa-alice',
            password: 'x', action: atScreen });
          continue;
        }
        break;
      }
      return { final: r, screens: screens, returnTo: returnTo,
               response: responseOf(r) };
    }
    function lastCode(code) {
      return realms.run(realms.DEFAULT_REALM, function () {
        return audit.list().some(function (event) {
          return event.errorCode === code;
        });
      });
    }

    // 1. ForceAuthn, no session
    jar = {};
    let f = await drive(authnRequest({ force: true }), 'login');
    note(f.screens === 1 && f.response &&
         f.response.codes[0] === 'Success',
         '1. ForceAuthn with no session: ONE trip to the sign-in screen and a ' +
         'Success Response — it looped for ever before',
         JSON.stringify({ screens: f.screens, response: f.response,
                          status: f.final.status }));

    // 6a. a plain request with that session is single sign-on
    let sso = await drive(authnRequest({}), 'login');
    note(sso.screens === 0 && sso.response &&
         sso.response.codes[0] === 'Success',
         '6a. unchanged: a plain request with a session is single sign-on, ' +
         'no screen', JSON.stringify({ screens: sso.screens }));

    // 2. ForceAuthn, with a session
    await new Promise(function (r) { setTimeout(r, 1100); });
    const before = f.response ? f.response.authnInstant : '';
    f = await drive(authnRequest({ force: true }), 'login');
    note(f.screens === 1 && f.response &&
         f.response.codes[0] === 'Success' &&
         f.response.authnInstant > before,
         '2. ForceAuthn WITH a session still shows the screen once, and the ' +
         'Response carries a FRESH AuthnInstant',
         JSON.stringify({ screens: f.screens, before: before,
                          after: f.response && f.response.authnInstant }));

    // 3. ForceAuthn, back without authenticating
    await new Promise(function (r) { setTimeout(r, 1100); });
    f = await drive(authnRequest({ force: true }), 'skip');
    note(f.screens === 1 && f.response &&
         f.response.codes.indexOf('AuthnFailed') >= 0 &&
         lastCode('STS-SAML-0055'),
         '3. ForceAuthn and the browser comes back WITHOUT authenticating ' +
         'again: AuthnFailed (STS-SAML-0055), not the screen a second time',
         JSON.stringify({ screens: f.screens, response: f.response,
                          status: f.final.status }));

    // 4. Cancel with no session
    jar = {};
    f = await drive(authnRequest({}), 'cancel');
    // Reported AS A CANCELLATION (STS-SAML-0009, the screen's own reason in
    // the StatusMessage) — the one-trip rule alone would also answer
    // AuthnFailed, as "came back with no session", which is a different fact.
    note(f.screens === 1 && f.response &&
         f.response.codes.indexOf('AuthnFailed') >= 0 &&
         !/no session/.test(f.response.message) && lastCode('STS-SAML-0009'),
         '4. Cancel at the screen with no session: AuthnFailed after ONE trip, ' +
         'reported as the cancellation it was — it was sent back to the ' +
         'screen before the cancellation was read',
         JSON.stringify({ screens: f.screens, response: f.response,
                          status: f.final.status }));

    // 5. an unmet multi-factor context on the way back
    jar = {};
    await drive(authnRequest({}), 'login', 'fa-bob');
    f = await drive(authnRequest({ context: MFA }), 'skip', 'fa-bob');
    note(f.screens === 1 && f.response &&
         f.response.codes.indexOf('NoAuthnContext') >= 0 &&
         lastCode('STS-SAML-0056'),
         '5. a multi-factor RequestedAuthnContext still unmet on the way back: ' +
         'NoAuthnContext (STS-SAML-0056), not another trip',
         JSON.stringify({ screens: f.screens, response: f.response,
                          status: f.final.status }));

    // 6b. IsPassive with no session
    jar = {};
    f = await drive(authnRequest({ passive: true }), 'login');
    note(f.screens === 0 && f.response &&
         f.response.codes.indexOf('NoPassive') >= 0,
         '6b. unchanged: IsPassive with no session is NoPassive and no screen',
         JSON.stringify({ screens: f.screens, response: f.response }));

    server.close();
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child ran to the end',
                    detail: e && e.stack });
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'saml2-force-authn-' + process.pid + '-' +
                        Math.random().toString(36).slice(2) + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|SAML|CONFIG_FILE$)/
        .test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', FA_ROOT: ROOT, FA_OUT: out }),
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
  if (t.check(Array.isArray(findings), 'the child process reported',
              'exit ' + result.status + ' ' +
              String(result.stderr || '').slice(-800))) {
    findings.forEach(function (one) {
      t.check(one.ok, one.what, one.detail);
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'saml2_force_authn',
  describe: 'a SAML 2.0 request makes one trip to the sign-in screen: ' +
            'ForceAuthn answered from a fresh authentication, AuthnFailed or ' +
            'NoAuthnContext when the trip did not achieve it, and Cancel read ' +
            'before the session',
  run: run
};
