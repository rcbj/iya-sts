// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/qualys_hardening.js
// ===========================================================================
// WHAT THE FIRST QUALYS WAS SCAN OF test-idp.iyasec.io ASKED FOR (2026-11-10).
//
// None of its findings was exploitable; these are the five it was worth
// answering. The whole stack in a child process, over HTTP on 127.0.0.1:
//
//   A. PERMISSIONS-POLICY (QID 150248) on every response: WebAuthn, the
//      Digital Credentials API, the clipboard and full screen for this origin
//      only, the camera and the rest for nobody.
//   B. A RESPONSE THAT IS NOT A PAGE (QID 150207): JSON, XML and plain text
//      carry a policy with no `style-src` and no `img-src`, and keep
//      `frame-ancestors`; an HTML page (Express's own 404 included) keeps the
//      base policy, whose inline styles its pages use.
//   C. THE STATIC APPLICATIONS (QIDs 531930, 531928): the console, the portal
//      and the reports application answer COOP `same-origin-allow-popups` and
//      CORP `same-origin`; a surface not asked to be isolated (the front door,
//      written like the sign-in screens a relying party may open in a popup)
//      answers neither.
//   D. THE BRANDING PREVIEW (QIDs 153006, 150112): its form is `method="post"`
//      and its password field `autocomplete="off"`.
//   E. THE REALM PREFIX IN A LINK (QID 150938): `WebPage.realmLinks()` escapes
//      it as the attribute value it becomes.
//   F. A CALLER'S NAME IN A REFUSAL (QID 150084): `ClosedSets.saidName()`
//      says an ordinary name as it was and percent-encodes markup.
//   G. THE FOUR SENTENCES THE SCAN FOUND (the published APIs' query refusal,
//      SAML 2.0's and 1.1's unregistered party, OpenID4VCI's unknown issuer)
//      refuse without repeating the probe.
//   H. A 501 FOR A SWITCHED-OFF FEATURE is audited `refused`, not `error`.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'qualys_hardening',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

/**
 * The child process: builds the stack, listens, and asks.
 *
 * @returns {void}
 */
function childMain() {
  const ROOT_DIR = process.env.QH_ROOT;
  const OUT = process.env.QH_OUT;
  const http = require('http');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    const server = http.createServer(app);
    await new Promise(function (r) {
      server.listen(0, '127.0.0.1', r);
    });
    const port = server.address().port;
    // One GET; the answer's status, headers and body.
    const get = function (p, headers) {
      return new Promise(function (resolve, reject) {
        const req = http.request({ host: '127.0.0.1', port: port, path: p,
          method: 'GET', headers: Object.assign({ accept: 'text/html' },
                                                headers || {}) },
        function (res) {
          const chunks = [];
          res.on('data', function (c) {
            chunks.push(c);
          });
          res.on('end', function () {
            resolve({ status: res.statusCode, headers: res.headers,
                      body: Buffer.concat(chunks).toString('utf8') });
          });
        });
        req.on('error', reject);
        req.end();
      });
    };
    const csp = function (r) {
      return String(r.headers['content-security-policy'] || '');
    };

    // A. Permissions-Policy.
    const discovery = await get('/.well-known/openid-configuration',
                                { accept: 'application/json' });
    const pp = String(discovery.headers['permissions-policy'] || '');
    note(pp.indexOf('publickey-credentials-get=(self)') >= 0 &&
         pp.indexOf('publickey-credentials-create=(self)') >= 0 &&
         pp.indexOf('digital-credentials-get=(self)') >= 0 &&
         pp.indexOf('clipboard-write=(self)') >= 0,
         'A1. Permissions-Policy allows WebAuthn, the Digital Credentials ' +
         'API and the clipboard for this origin', pp);
    note(/(^|, )camera=\(\)/.test(pp) && /(^|, )microphone=\(\)/.test(pp) &&
         /(^|, )geolocation=\(\)/.test(pp) && /(^|, )payment=\(\)/.test(pp),
         'A2. and the camera, microphone, geolocation and payment for nobody',
         pp);
    const missing = await get('/qualys-hardening-no-such-path');
    note(String(missing.headers['permissions-policy'] || '') === pp,
         'A3. an unrouted path carries the same Permissions-Policy',
         missing.headers['permissions-policy']);

    // B. Not a page.
    const json = csp(discovery);
    note(discovery.status === 200 &&
         /^application\/json/.test(String(discovery.headers['content-type'])),
         'B1. the discovery document is a JSON answer',
         discovery.status + ' ' + discovery.headers['content-type']);
    note(json.indexOf('style-src') < 0 && json.indexOf('img-src') < 0 &&
         json.indexOf("default-src 'none'") >= 0 &&
         json.indexOf("frame-ancestors 'none'") >= 0 &&
         json.indexOf("base-uri 'none'") >= 0,
         'B2. a JSON answer carries no style-src and no img-src, and keeps ' +
         'frame-ancestors and base-uri', json);
    const health = await get('/healthcheck', { accept: '*/*' });
    note(csp(health).indexOf('style-src') < 0 &&
         csp(health).indexOf('frame-ancestors') >= 0,
         'B3. so does /healthcheck, which the scan named',
         health.status + ' ' + health.headers['content-type'] + ' ' +
         csp(health));
    const html404 = csp(missing);
    note(/^text\/html/.test(String(missing.headers['content-type'])) &&
         html404.indexOf("style-src 'unsafe-inline'") >= 0 &&
         html404.indexOf("frame-ancestors 'none'") >= 0,
         'B4. an HTML page (Express\'s 404) keeps the base policy',
         missing.headers['content-type'] + ' ' + html404);

    // C. The static applications.
    for (const p of ['/admin', '/portal', '/report']) {
      const r = await get(p);
      note(r.status === 200 &&
           r.headers['cross-origin-opener-policy'] ===
             'same-origin-allow-popups' &&
           r.headers['cross-origin-resource-policy'] === 'same-origin',
           'C. ' + p + ' answers COOP same-origin-allow-popups and CORP ' +
           'same-origin', r.status + ' ' +
           r.headers['cross-origin-opener-policy'] + ' ' +
           r.headers['cross-origin-resource-policy']);
    }
    // A static surface that is not one of the three: the front door, served
    // through the same shell writer without `isolated`, as the sign-in
    // screens are.
    const front = await get('/');
    note(front.status === 200 &&
         /^text\/html/.test(String(front.headers['content-type'])) &&
         !front.headers['cross-origin-opener-policy'] &&
         !front.headers['cross-origin-resource-policy'],
         'C4. a surface not asked to be isolated (the front door) answers ' +
         'neither', front.status + ' ' +
         front.headers['cross-origin-opener-policy']);

    // D. The branding preview.
    const preview = await get('/web/branding/preview');
    const forms = preview.body.match(/<form\b[^>]*>/g) || [];
    note(preview.status === 200 && forms.length === 1 &&
         /method="post"/.test(forms[0]) && /autocomplete="off"/.test(forms[0]),
         'D1. the preview\'s one form is method="post" and ' +
         'autocomplete="off"', preview.status + ' ' + forms.join(' '));
    note(/<input type="password" id="pv-pass" autocomplete="off" disabled>/
           .test(preview.body),
         'D2. its password field is autocomplete="off" and disabled',
         (preview.body.match(/<input type="password"[^>]*>/) || [''])[0]);

    // E. The realm prefix, escaped where it becomes an attribute.
    const WebPage = require(ROOT_DIR + '/common/web_page');
    const drawn = WebPage.realmLinks('<a href="/x">x</a>',
                                     '/realm/a"><b>$&');
    note(drawn.indexOf('<b>') < 0 && drawn.indexOf('"><') < 0 &&
         drawn.indexOf('href="/realm/a&quot;&gt;&lt;b&gt;$&amp;/x"') === 0 +
         '<a '.length,
         'E1. realmLinks() escapes the prefix as an attribute value, `$` ' +
         'kept literal', drawn);
    note(WebPage.realmLinks('<a href="/x">x</a>', '/realm/acme') ===
         '<a href="/realm/acme/x">x</a>',
         'E2. an ordinary prefix is put on unchanged',
         WebPage.realmLinks('<a href="/x">x</a>', '/realm/acme'));

    // F. A caller's name in a refusal sentence (QID 150084).
    const ClosedSets = require(ROOT_DIR + '/common/closed_sets');
    note(ClosedSets.saidName('page') === '"page"' &&
         ClosedSets.saidName('filter[name]') === '"filter[name]"' &&
         ClosedSets.saidName('https://sp.example/md?x=1&y=%20') ===
           '"https://sp.example/md?x=1&y=%20"',
         'F1. an ordinary name, a URL with a query among them, is said as it ' +
         'was', ClosedSets.saidName('https://sp.example/md?x=1&y=%20'));
    note(ClosedSets.saidName('"><script>alert(81)</script>') ===
           '"%22%3E%3Cscript%3Ealert(81)%3C%2Fscript%3E"' &&
         ClosedSets.saidName('z--><qss>') === '"z--%3E%3Cqss%3E"',
         'F2. markup and quotes are percent-encoded',
         ClosedSets.saidName('"><script>alert(81)</script>'));

    // G. The four sentences the scan found reflecting its probes.
    const probes = [
      ['/account-api/locale?%22%3E%3Cscript%3Ealert(81)%3C/script%3E=',
       '<script>'],
      ['/saml2/metadata/z--%3E%3Cqss%3E', '<qss>'],
      ['/saml11/metadata/z--%3E%3Cqss%3E', '<qss>'],
      ['/.well-known/jwt-vc-issuer/z--%3E%3Cqss%3E', '<qss>']
    ];
    // SAML refuses an unregistered party in PRODUCT mode only (outside it,
    // it describes itself to anybody), so the mode is set for these two.
    const config = require(ROOT_DIR + '/common/config');
    for (const one of probes) {
      const saml = /^\/saml/.test(one[0]);
      if (saml) {
        config.setOverride('global.mode', 'product');
      }
      let r = null;
      try {
        r = await get(one[0], { accept: 'application/json' });
      } finally {
        if (saml) {
          config.clearOverride('global.mode');
        }
      }
      note(r.status >= 400 && r.status < 500 &&
           r.body.indexOf(one[1]) < 0 && /%3C/i.test(r.body),
           'G. ' + one[0].split('?')[0] + ' refuses without repeating the ' +
           'probe', r.status + ' ' + r.body.slice(0, 240));
    }

    // H. A 501 for a feature switched off is a refusal, not a failure.
    const audit = require(ROOT_DIR + '/common/audit');
    const vc = await get('/vc-api/issuers', { accept: 'application/json' });
    const row = audit.list().filter(function (one) {
      return String(one.target || '').indexOf('/vc-api/issuers') >= 0 ||
             String(one.summary || '').indexOf('/vc-api/issuers') >= 0;
    })[0];
    note(vc.status === 501 && row && row.outcome === 'refused',
         'H1. the switched-off VC API\'s 501 is audited as refused',
         vc.status + ' ' + JSON.stringify(row || null).slice(0, 300));

    server.close();
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child threw',
                    detail: String((e && e.stack) || e) });
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
  const out = path.join(os.tmpdir(), 'qh-' + process.pid + '-' + Date.now() +
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
                                  QH_ROOT: ROOT, QH_OUT: out }),
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
  name: 'qualys_hardening',
  describe: 'what the first Qualys WAS scan asked for: Permissions-Policy, ' +
            'no style or image source on a response that is not a page, ' +
            'COOP and CORP on the static applications, the branding ' +
            'preview\'s form, and the realm prefix escaped (2026-11-10)',
  run: run
};
