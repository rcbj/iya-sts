// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: browser_devices.js
//
// ===========================================================================
// #265: A REMEMBERED BROWSER — A DEVICE KNOWN BY A SIGNED AND ENCRYPTED
// COOKIE — END TO END, IN A CHILD PROCESS.
//
// The whole stack is loaded in a child (it registers routes on the shared app
// and changes the authentication policy) and a person is signed in over HTTP
// with a password and an authenticator app, as a browser would:
//
//   A. the keys: a dedicated signing and encryption pair per realm, never
//      published; the `browser-devices` signer group and its use case.
//   B. "Remember this browser" at sign-in registers a `bearer` device
//      (method `browser`, generation 1, second factor given) and sets the
//      cookie.
//   C. the cookie is a JWE this service opens and a JWS it verifies; a
//      tampered one is refused (STS-DEVICE-0040).
//   D. a bearer device cannot be marked compliant (STS-DEVICE-0039).
//   E. with the skip off, a remembered browser is still asked for the second
//      factor, and the sign-in issues generation 2.
//   F. with the skip on, the password alone signs in, one factor, on the
//      audit log — and generation 3 is issued; the admin console still asks.
//   G. the cookie in ANOTHER browser is not skipped.
//   H. a COPY — generation 1 presented after 3 — marks the device
//      compromised, the sign-in is refused, and the cookie is cleared.
//   I. the pure halves: which browser a User-Agent names, and what counts
//      as a second factor in an amr.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'browser_devices',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.RD_ROOT;
  const OUT = process.env.RD_OUT;
  const http = require('http');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  function browser(port, userAgent, jarFrom) {
    const jar = Object.assign({}, jarFrom || {});
    const go = function (method, urlPath, opts) {
      const o = opts || {};
      return new Promise(function (resolve) {
        const body = o.form ? new URLSearchParams(o.form).toString() : '';
        const headers = { 'user-agent': userAgent };
        const names = Object.keys(jar).filter(function (k) {
          return jar[k] !== '';
        });
        if (names.length) {
          headers.cookie = names.map(function (k) {
            return k + '=' + jar[k];
          }).join('; ');
        }
        if (method !== 'GET') {
          headers['content-type'] = 'application/x-www-form-urlencoded';
          headers['content-length'] = Buffer.byteLength(body);
        }
        const req = http.request({ host: '127.0.0.1', port: port,
                                   path: String(urlPath).replace(
                                     /^https?:\/\/[^/]+/, ''),
                                   method: method, headers: headers },
                                 function (res) {
          let text = '';
          const set = res.headers['set-cookie'] || [];
          set.forEach(function (line) {
            const pair = line.split(';')[0];
            const eq = pair.indexOf('=');
            jar[pair.slice(0, eq)] = pair.slice(eq + 1);
          });
          res.on('data', function (c) { text += c; });
          res.on('end', function () {
            resolve({ status: res.statusCode, headers: res.headers,
                      text: text, setCookie: set });
          });
        });
        req.end(body);
      });
    };
    return { go: go, jar: jar };
  }
  const hiddenFields = function (html) {
    const form = {};
    (html.match(/<input type="hidden"[^>]*>/g) || []).forEach(function (tag) {
      const name = /name="([^"]+)"/.exec(tag);
      const value = /value="([^"]*)"/.exec(tag);
      if (name) {
        form[name[1]] = value ? value[1].replace(/&amp;/g, '&') : '';
      }
    });
    return form;
  };
  const pathOf = function (location) {
    const u = new URL(String(location || ''), 'http://127.0.0.1');
    return u.pathname + u.search;
  };

  const CHROME = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 ' +
    '(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36';
  const FIREFOX = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:141.0) ' +
    'Gecko/20100101 Firefox/141.0';

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const applications = require(ROOT + '/common/applications');
    const config = require(ROOT + '/common/config');
    const audit = require(ROOT + '/common/audit');
    const credentials = require(ROOT + '/common/credentials');
    const authnPolicy = require(ROOT + '/common/authn_policy');
    const totp = require(ROOT + '/common/totp');
    const helpers = require(ROOT + '/common/helpers');
    const devices = require(ROOT + '/common/devices');
    const browserDevices = require(ROOT + '/common/browser_devices');
    const signerGroups = require(ROOT + '/common/signer_groups');
    const errorCodes = require(ROOT + '/common/error_codes');
    const ldap = require(ROOT + '/ldap/ldap_server');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;

    config.setOverride('oauth2.consentRequired', false);
    // Three steps either side, so four sign-ins can each spend a later step
    // than the last (the accept-once rule, RFC 6238 section 5.2).
    config.setOverride('totp.window', 4);
    const REDIRECT = 'https://rp.browser-devices.example/cb';
    const CLIENT = 'bd-client';
    applications.createApplication({ identifier: CLIENT,
      protocols: ['oauth2'],
      fields: { oauthClientId: CLIENT,
                oauthClientSecret: 'browser-devices-secret-0123456789ab',
                oauthRedirectUri: [REDIRECT],
                oauthGrantType: ['authorization_code'],
                oauthAllowedScope: ['openid'],
                oauthTokenEndpointAuthMethod: 'client_secret_basic' } });
    const policyWith = function (fields) {
      const saved = authnPolicy.save('default',
        Object.assign({}, authnPolicy.DEFAULTS, fields));
      if (!saved.ok) {
        throw new Error('policy not saved: ' + JSON.stringify(saved.errors));
      }
    };
    const auditOf = function (action, actor) {
      return audit.list().filter(function (row) {
        return row.action === action && row.actor === actor;
      });
    };
    const authorizeAt = '/oauth2/authorize?' + new URLSearchParams({
      client_id: CLIENT, response_type: 'code', redirect_uri: REDIRECT,
      scope: 'openid', state: 's', nonce: 'n' }).toString();
    // The password step of a sign-in to `start`, as `username`, with the
    // "Remember this browser" box ticked or not.
    const passwordStep = async function (b, start, username, remember) {
      let at = await b.go('GET', start);
      for (let i = 0; i < 4 && at.status >= 300 && at.status < 400 &&
           !/\/authn\/login\?/.test(String(at.headers.location || ''));
           i++) {
        at = await b.go('GET', pathOf(at.headers.location));
      }
      const screen = pathOf(at.headers.location);
      const page = await b.go('GET', screen);
      const form = Object.assign(hiddenFields(page.text), {
        username: username, password: 'anything', action: 'login' });
      if (remember) {
        form.remember_browser = '1';
      }
      return { page: page, answer: await b.go('POST', screen.split('?')[0],
                                             { form: form }) };
    };
    const secret = { value: '' };
    const codeStep = function (b, answer, step) {
      const mfaId = (answer.text.match(/name="mfa_id" value="([^"]+)"/) ||
                     [])[1] || '';
      return b.go('POST', '/authn/totp', { form: {
        mfa_id: mfaId,
        code: totp.codeAt(secret.value, Date.now() + step * 30000),
        csrf_token: hiddenFields(answer.text).csrf_token || '' } });
    };
    const cookieName = browserDevices.cookieName();
    // A sign-in from a browser holding ONLY the remembered-browser cookie:
    // a jar that kept the sign-on session would be single sign-on and never
    // reach the password screen.
    const withCookie = function (userAgent, value) {
      const jar = {};
      if (value) {
        jar[cookieName] = value;
      }
      return browser(port, userAgent, jar);
    };
    const devicesOf = function (who) {
      return devices.listFor(who).filter(function (d) {
        return d.enrolment.method === 'browser';
      });
    };

    // --- A. the keys --------------------------------------------------------
    const keys = helpers.browserDeviceKeysFor();
    const signer = helpers.browserDeviceSigner();
    const jwks = (await browser(port, CHROME).go('GET', '/oauth2/jwks')).text;
    note(/^sts-bd-sig-/.test(keys.sign.publicJwk.kid) &&
         /^sts-bd-enc-/.test(keys.enc.publicJwk.kid) &&
         keys.sign.publicJwk.crv === 'P-256' &&
         signer.via === 'dedicated' && signer.kid === keys.sign.publicJwk.kid &&
         jwks.indexOf(keys.sign.publicJwk.kid) < 0,
         'A1. a dedicated ES256 signing key and P-256 encryption key per ' +
         'realm; the per-algorithm model signs with the dedicated key, which ' +
         'is published nowhere', JSON.stringify({ sign: keys.sign.publicJwk.kid,
                                                  via: signer.via }));
    const group = signerGroups.group('browser-devices');
    note(group && group.useCases.join(',') === 'browser-device-token' &&
         signerGroups.groupForUseCase('browser-device-token').id ===
         'browser-devices',
         'A2. the hybrid-groups model has a browser-devices group for the ' +
         'browser-device-token use case');

    // --- B. remembered at sign-in -----------------------------------------
    ldap.createUser('bd-alice', { invent: false });
    const begun = credentials.beginTotpEnrolment('bd-alice', {});
    secret.value = begun.secret;
    credentials.confirmTotpEnrolment('bd-alice',
      totp.codeAt(begun.secret, Date.now() - 4 * 30000));
    const b1 = browser(port, CHROME);
    const first = await passwordStep(b1, authorizeAt, 'bd-alice', true);
    note(/name="remember_browser"/.test(first.page.text),
         'B1. the sign-in screen offers "Remember this browser"');
    note(first.answer.status === 200 && /one-time code/i.test(first.answer.text),
         'B2. a person with an authenticator app is asked for the code',
         first.answer.status);
    const firstDone = await codeStep(b1, first.answer, -3);
    const remembered = devicesOf('bd-alice');
    const d1 = remembered[0] || {};
    note(remembered.length === 1 && d1.attestation === 'bearer' &&
         d1.browser && d1.browser.gen === 1 && !!d1.browser.mfaAt &&
         d1.browser.context.ua === 'Chrome on Linux' &&
         !!b1.jar[cookieName] && !d1.keys.length,
         'B3. the finished sign-in registered a bearer device (no keys, ' +
         'generation 1, second factor given, Chrome on Linux) and set the ' +
         'cookie ' + cookieName,
         firstDone.status + ' ' + JSON.stringify({ n: remembered.length,
           att: d1.attestation, browser: d1.browser,
           cookie: !!b1.jar[cookieName] }));
    note(auditOf('device.browser.remembered', 'bd-alice').length === 1,
         'B4. the audit log says the person asked for it');
    const setLine = (firstDone.setCookie || []).filter(function (l) {
      return l.indexOf(cookieName + '=') === 0;
    })[0] || '';
    note(/HttpOnly/.test(setLine) && /SameSite=Lax/.test(setLine) &&
         /Path=\//.test(setLine),
         'B5. the cookie is HttpOnly, SameSite=Lax, Path=/', setLine);

    // --- C. the token -----------------------------------------------------
    const gen1Cookie = b1.jar[cookieName];
    const claims = browserDevices.read(gen1Cookie);
    note(claims && claims.sub === d1.id && claims.owner === 'bd-alice' &&
         claims.gen === 1 && gen1Cookie.split('.').length === 5 &&
         gen1Cookie.length <= browserDevices.MAX_TOKEN_BYTES,
         'C1. the cookie is a compact JWE this service opens, naming the ' +
         'device, the owner and generation 1', JSON.stringify(claims));
    const parts = gen1Cookie.split('.');
    parts[3] = parts[3].slice(0, -2) + (parts[3].slice(-2) === 'AA'
                                          ? 'BB' : 'AA');
    note(browserDevices.read(parts.join('.')) === null,
         'C2. a tampered cookie is not read (STS-DEVICE-0040)');

    // --- D. never compliant -------------------------------------------------
    const compliant = devices.setCompliance(d1.id, 'compliant', 'admin',
                                            'test');
    note(!compliant.ok &&
         errorCodes.codeOf(compliant) === 'STS-DEVICE-0039',
         'D1. a bearer device cannot be marked compliant',
         JSON.stringify(compliant));

    // --- E. skip off: still asked ------------------------------------------
    const b1e = withCookie(CHROME, gen1Cookie);
    const second = await passwordStep(b1e, authorizeAt, 'bd-alice', false);
    note(second.answer.status === 200 &&
         /one-time code/i.test(second.answer.text),
         'E1. with the policy off, a remembered browser is still asked for ' +
         'the second factor', second.answer.status);
    await codeStep(b1e, second.answer, -2);
    const d2 = devices.byId(d1.id);
    const gen2Cookie = b1e.jar[cookieName];
    note(d2.browser.gen === 2 && gen2Cookie !== gen1Cookie &&
         (browserDevices.read(gen2Cookie) || {}).gen === 2 &&
         devicesOf('bd-alice').length === 1,
         'E2. the sign-in issued generation 2, onto the same device',
         JSON.stringify(d2.browser));

    // --- F. skip on ---------------------------------------------------------
    policyWith({ rememberedBrowserSkipsSecondFactor: true });
    const b1f = withCookie(CHROME, gen2Cookie);
    const third = await passwordStep(b1f, authorizeAt, 'bd-alice', false);
    let landed = third.answer;
    for (let i = 0; i < 5 && landed.status >= 300 && landed.status < 400 &&
         String(landed.headers.location || '').indexOf(REDIRECT) !== 0; i++) {
      landed = await b1f.go('GET', pathOf(landed.headers.location));
    }
    const gen3Cookie = b1f.jar[cookieName];
    note(String(landed.headers.location || '').indexOf(REDIRECT + '?code=') ===
         0 && auditOf('authn.second-factor.skipped', 'bd-alice').length === 1,
         'F1. with the policy on, the password alone signs in on the ' +
         'remembered browser, and the audit log says the factor was skipped',
         third.answer.status + ' ' + String(landed.headers.location || ''));
    note(devices.byId(d1.id).browser.gen === 3,
         'F2. and the token was issued again (generation 3)');
    const console1 = await passwordStep(withCookie(CHROME, gen3Cookie),
                                        '/admin', 'bd-alice', false);
    note(console1.answer.status === 200 &&
         /one-time code/i.test(console1.answer.text),
         'F3. the admin console always asks, remembered browser or not',
         console1.answer.status);

    // --- G. another browser -------------------------------------------------
    const b2 = withCookie(FIREFOX, gen3Cookie);
    const moved = await passwordStep(b2, authorizeAt, 'bd-alice', false);
    note(moved.answer.status === 200 &&
         /one-time code/i.test(moved.answer.text) &&
         devices.byId(d1.id).status === 'active',
         'G1. the current cookie in a different browser is not trusted to ' +
         'skip the second factor, and is not a copy',
         moved.answer.status);

    // --- H. a copy ----------------------------------------------------------
    const b3 = withCookie(CHROME, gen1Cookie);
    const copy = await passwordStep(b3, authorizeAt, 'bd-alice', false);
    note(devices.byId(d1.id).status === 'compromised',
         'H1. generation 1 presented after 3 is a copied cookie: the device ' +
         'is compromised (STS-DEVICE-0041)');
    const copyDone = copy.answer.status === 200 &&
                     /one-time code/i.test(copy.answer.text)
      ? await codeStep(b3, copy.answer, -1) : copy.answer;
    const clearedIn = function (answer) {
      return ((answer && answer.setCookie) || []).some(function (l) {
        return l.indexOf(cookieName + '=;') === 0 && /Max-Age=0/.test(l);
      });
    };
    const refusedAt = copyDone === copy.answer ? copy.answer : copyDone;
    note((clearedIn(copy.answer) || clearedIn(copyDone)) &&
         !String(refusedAt.headers.location || '').startsWith(REDIRECT),
         'H2. the sign-in on the compromised device does not reach the ' +
         'client, and the cookie is cleared so the next attempt is not ' +
         'refused on it', refusedAt.status + ' ' +
         JSON.stringify((copy.answer.setCookie || [])
           .concat(copyDone.setCookie || [])));

    // --- I. the pure halves ---------------------------------------------------
    note(browserDevices.browserOf(FIREFOX) === 'Firefox on Windows' &&
         browserDevices.browserOf(CHROME) === 'Chrome on Linux',
         'I1. a browser is named by its family and OS');
    note(browserDevices.hasSecondFactor(['pwd', 'otp']) &&
         browserDevices.hasSecondFactor(['mfa']) &&
         !browserDevices.hasSecondFactor(['hwk']) &&
         !browserDevices.hasSecondFactor(['pwd']),
         'I2. two factors are counted from amr, one factor is not');

    policyWith({});
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

function inAChild(t) {
  log.debug("Entering inAChild().");
  const out = path.join(os.tmpdir(), 'browser-devices-' + process.pid + '-' +
                        require('crypto').randomBytes(8).toString('hex') +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', RD_ROOT: ROOT, RD_OUT: out }),
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
  name: 'browser_devices',
  describe: '#265: a remembered browser — the dedicated keys, remembering at ' +
            'sign-in, the signed and encrypted cookie, never compliant, ' +
            'reissue, the second-factor skip (off, on, the console, another ' +
            'browser) and a copied cookie caught',
  run: run
};
