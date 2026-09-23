'use strict';
//
// File: risk_fingerprinting.js
//
// ===========================================================================
// THE OPTIONAL BROWSER FINGERPRINT (#62 P6, 2026-09-22), over HTTP in a
// child process. rcbj's decision: built, OFF BY DEFAULT, per realm.
//
//   A. OFF: the sign-in screen carries no script and keeps script-src
//      'none'; the script is not served (404).
//   B. ON: the screen carries the hidden field and ONE script, and relaxes
//      script-src to 'self' and nothing else — frame-ancestors kept; the
//      script is FingerprintJS with its usage ping off.
//   C. SCORED: a second sign-in from a browser with another fingerprint is
//      `new-device`; the fingerprint is kept only as a digest.
//
// The fingerprints here are strings this test sends — no browser runs.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'risk_fingerprinting',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.RF_ROOT;
  const OUT = process.env.RF_OUT;
  const http = require('http');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  const CHROME = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ' +
    'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36';
  function browser(port) {
    const jar = {};
    const go = function (method, urlPath, opts) {
      const o = opts || {};
      return new Promise(function (resolve) {
        const body = o.form ? new URLSearchParams(o.form).toString() : '';
        const headers = { 'user-agent': CHROME };
        if (Object.keys(jar).length) {
          headers.cookie = Object.keys(jar).map(function (k) {
            return k + '=' + jar[k];
          }).join('; ');
        }
        if (method !== 'GET') {
          headers['content-type'] = 'application/x-www-form-urlencoded';
          headers['content-length'] = Buffer.byteLength(body);
        }
        const req = http.request({ host: '127.0.0.1', port: port,
          path: String(urlPath).replace(/^https?:\/\/[^/]+/, ''),
          method: method, headers: headers }, function (res) {
          let text = '';
          (res.headers['set-cookie'] || []).forEach(function (line) {
            const pair = line.split(';')[0];
            const eq = pair.indexOf('=');
            jar[pair.slice(0, eq)] = pair.slice(eq + 1);
          });
          res.on('data', function (c) { text += c; });
          res.on('end', function () {
            resolve({ status: res.statusCode, headers: res.headers,
                      text: text });
          });
        });
        req.end(body);
      });
    };
    return { go: go };
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

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const applications = require(ROOT + '/common/applications');
    const config = require(ROOT + '/common/config');
    const ldap = require(ROOT + '/ldap/ldap_server');
    const helpers = require(ROOT + '/common/helpers');
    const riskEngine = require(ROOT + '/risk/risk_engine');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    config.setOverride('oauth2.consentRequired', false);
    // Scored from the second sign-in: this file is about the new-device
    // signal, which waits for risk.minimumHistory (5 by default).
    config.setOverride('risk.minimumHistory', 1);
    const CLIENT = 'rf-client';
    const REDIRECT = 'https://rp.fp.example/cb';
    applications.createApplication({ identifier: CLIENT,
      protocols: ['oauth2'],
      fields: { oauthClientId: CLIENT,
                oauthClientSecret: 'fp-secret-0123456789abcdef0123',
                oauthRedirectUri: [REDIRECT],
                oauthGrantType: ['authorization_code'],
                oauthAllowedScope: ['openid'],
                oauthTokenEndpointAuthMethod: 'client_secret_basic' } });
    const screen = async function (b) {
      const start = await b.go('GET', '/oauth2/authorize?' +
        new URLSearchParams({ client_id: CLIENT, response_type: 'code',
          redirect_uri: REDIRECT, scope: 'openid', state: 's',
          nonce: 'n-' + Date.now() }).toString());
      return b.go('GET', String(start.headers.location || ''));
    };

    // --- A. off ------------------------------------------------------------
    const off = await screen(browser(port));
    const offScript = await browser(port).go('GET', '/authn/fingerprint.js');
    note(!/fingerprint\.js/.test(off.text) &&
         !/name="device_fp"/.test(off.text) &&
         /script-src 'none'/.test(String(off.headers[
           'content-security-policy'] || '')) && offScript.status === 404,
         'A1. off (the default): no script, no field, script-src stays ' +
         '\'none\', and the script is not served',
         offScript.status + ' ' + off.headers['content-security-policy']);

    // --- B. on -------------------------------------------------------------
    config.setOverride('risk.fingerprinting', true);
    const on = await screen(browser(port));
    const csp = String(on.headers['content-security-policy'] || '');
    const scripts = on.text.match(/<script [^>]*>/g) || [];
    note(scripts.length === 1 &&
         /src="\/authn\/fingerprint\.js"/.test(scripts[0]) &&
         /name="device_fp"/.test(on.text) &&
         /script-src 'self'/.test(csp) && /frame-ancestors/.test(csp),
         'B1. on: the screen carries the field and ONE script, and relaxes ' +
         'script-src to \'self\' with frame-ancestors kept', csp);
    const script = await browser(port).go('GET', '/authn/fingerprint.js');
    note(script.status === 200 &&
         /javascript/.test(String(script.headers['content-type'])) &&
         /FingerprintJS\.load\(\{ monitoring: false \}\)/.test(script.text),
         'B2. the script is FingerprintJS with its usage ping turned off',
         script.status);

    // --- C. scored -----------------------------------------------------------
    ldap.createUser('rf-erin', { invent: false });
    const sub = helpers.subjectForName('rf-erin');
    const signInWith = async function (fp) {
      const b = browser(port);
      const page = await screen(b);
      return b.go('POST', '/authn/login', { form: Object.assign(
        hiddenFields(page.text), { username: 'rf-erin', password: 'x',
                                   action: 'login', device_fp: fp }) });
    };
    const FIRST = 'a1b2c3d4e5f60718293a4b5c6d7e8f90';
    const SECOND = 'ffeeddccbbaa99887766554433221100';
    await signInWith(FIRST);
    await signInWith(SECOND);
    let rows = [];
    for (let i = 0; i < 40 && rows.length < 2; i++) {
      rows = (await riskEngine.view('default', { subject: sub }))
        .assessments.rows;
      if (rows.length < 2) {
        await new Promise(function (r) { setTimeout(r, 50); });
      }
    }
    const newest = rows[0] || {};
    note(rows.length >= 2 && (newest.signals || []).some(function (s) {
      return s.signal === 'new-device';
    }),
         'C1. a second sign-in from another browser is new-device',
         JSON.stringify((newest.signals || []).map(function (s) {
           return s.signal;
         })));
    note(JSON.stringify(rows).indexOf(FIRST) < 0 &&
         JSON.stringify(rows).indexOf(SECOND) < 0,
         'C2. the fingerprint itself is kept nowhere — a digest only');

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
  const out = path.join(os.tmpdir(), 'risk-fingerprinting-' + process.pid +
                        '-' + Math.random().toString(36).slice(2) + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', RF_ROOT: ROOT, RF_OUT: out }),
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
  name: 'risk_fingerprinting',
  describe: 'the optional browser fingerprint (#62 P6): off by default with ' +
            'no script and the script not served; on, one script under ' +
            'script-src \'self\' with frame-ancestors kept; a second browser ' +
            'scored new-device; the fingerprint kept only as a digest',
  run: run
};
