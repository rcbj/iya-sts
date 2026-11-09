// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/asvs_response_rules.js
// ===========================================================================
// THE RESPONSE RULES ASVS 5.0.0 LEVEL 1 ASKS OF EVERY PAGE (#1438, #1439,
// #1442), sign-out clearing the tab (#1440), and SECURITY.md's windows (#1458).
//
// The whole stack in a child process, over HTTP on 127.0.0.1. A TLS request is
// made by marking the socket, because the rule asks the socket:
//
//   1. HSTS: product over TLS, on a route and on an unrouted path; never over
//      cleartext (the revocation listener hands this app its requests), and
//      never in development.
//   2. CHARSET: named on text and XML types, left alone on JSON and JOSE.
//   3. A COOKIE WRITE FROM ANOTHER SITE: `POST /authn/language` and the JSON
//      `POST /logout` are refused for a foreign Origin, and for a `null` Origin
//      that Sec-Fetch-Site says is cross-site. A same-origin form (Origin
//      `null` under no-referrer) and a program (neither header) pass.
//   4. No refusal carries an error code.
//   5. THE WINDOWS: an advisory past its window is overdue, one within it is
//      not, and one whose date is unknown is overdue.
//   6. THE INSTALL: nothing floats, the images use npm ci, and SECURITY.md
//      states the windows the check enforces.
//   7. SIGN-OUT: each application clears its own tab before it leaves.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'asvs_response_rules',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

/**
 * The child process: builds the stack, listens, and asks.
 *
 * @returns {void}
 */
function childMain() {
  const ROOT_DIR = process.env.AR_ROOT;
  const OUT = process.env.AR_OUT;
  const http = require('http');
  const fs = require('fs');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    const mode = require(ROOT_DIR + '/common/mode');
    app.get('/asvs-probe/:kind', function (req, res) {
      res.setHeader('Content-Type', decodeURIComponent(req.params.kind));
      res.end('x');
    });
    const server = http.createServer(function (req, res) {
      req.socket.encrypted = req.headers['x-probe-tls'] === '1';
      app(req, res);
    });
    await new Promise(function (r) {
      server.listen(0, '127.0.0.1', r);
    });
    const port = server.address().port;
    const origin = 'http://127.0.0.1:' + port;
    const ask = function (method, p, headers, body) {
      return new Promise(function (resolve, reject) {
        const req = http.request({ port: port, host: '127.0.0.1', agent: false,
          method: method, path: p, headers: headers || {} }, function (res) {
          let text = '';
          res.on('data', function (d) {
            text += d;
          });
          res.on('end', function () {
            resolve({ status: res.statusCode, headers: res.headers,
                      text: text });
          });
        });
        req.on('error', reject);
        req.end(body || undefined);
      });
    };
    const HSTS = 'strict-transport-security';
    const real = mode.omitsStrictTransportSecurity;

    // --- 1. HSTS ------------------------------------------------------------
    mode.omitsStrictTransportSecurity = function () {
      return false;
    };
    let r = await ask('GET', '/healthcheck', { 'x-probe-tls': '1' });
    note(r.headers[HSTS] === 'max-age=31536000',
         'product over TLS sends HSTS', JSON.stringify(r.headers));
    r = await ask('GET', '/no/such/path', { 'x-probe-tls': '1' });
    note(r.status === 404 && r.headers[HSTS] === 'max-age=31536000',
         'and on the framework\'s own 404', r.status);
    r = await ask('GET', '/healthcheck', {});
    note(r.headers[HSTS] === undefined, 'never over cleartext',
         r.headers[HSTS]);
    mode.omitsStrictTransportSecurity = real;
    r = await ask('GET', '/healthcheck', { 'x-probe-tls': '1' });
    note(r.headers[HSTS] === undefined, 'never in development',
         r.headers[HSTS]);

    // --- 2. charset ---------------------------------------------------------
    const typed = async function (type) {
      const a = await ask('GET', '/asvs-probe/' + encodeURIComponent(type));
      return String(a.headers['content-type']);
    };
    const named = ['text/plain', 'text/html', 'application/xml',
      'application/samlmetadata+xml', 'application/soap+xml'];
    for (let i = 0; i < named.length; i++) {
      const got = await typed(named[i]);
      note(got === named[i] + '; charset=utf-8', named[i] + ' names utf-8',
           got);
    }
    const left = ['application/json', 'application/jrd+json', 'application/jwt',
      'application/jose', 'image/png'];
    for (let i = 0; i < left.length; i++) {
      const got = await typed(left[i]);
      note(got === left[i], left[i] + ' is left alone', got);
    }
    const kept = await typed('text/plain; charset=iso-8859-1');
    note(kept === 'text/plain; charset=iso-8859-1',
         'a charset already named is kept', kept);

    // --- 3. a cookie write from another site --------------------------------
    const form = 'application/x-www-form-urlencoded';
    const language = function (headers) {
      return ask('POST', '/authn/language',
                 Object.assign({ 'content-type': form }, headers),
                 'lang=fr&return=/');
    };
    const refusals = [];
    r = await language({ origin: 'https://evil.example' });
    refusals.push(r);
    note(r.status === 403, 'the language chooser refuses another Origin',
         r.status);
    r = await language({ origin: 'null', 'sec-fetch-site': 'cross-site' });
    refusals.push(r);
    note(r.status === 403, 'and a null Origin from another site', r.status);
    r = await language({ origin: 'null' });
    refusals.push(r);
    note(r.status === 403, 'and a null Origin nothing vouches for', r.status);
    r = await language({ origin: 'null', 'sec-fetch-site': 'same-origin' });
    note(r.status === 303, 'it takes this service\'s own form under ' +
         'no-referrer', r.status);
    r = await language({ origin: origin });
    note(r.status === 303, 'its own Origin', r.status);
    r = await language({});
    note(r.status === 303, 'and a program with neither header', r.status);

    const door = function (headers) {
      return ask('POST', '/logout', Object.assign(
        { 'content-type': 'application/json', accept: 'application/json' },
        headers), '{}');
    };
    r = await door({ origin: 'https://evil.example' });
    refusals.push(r);
    note(r.status === 403, 'the JSON sign-out refuses another Origin',
         r.status);
    r = await door({ 'sec-fetch-site': 'cross-site' });
    refusals.push(r);
    note(r.status === 403, 'and a cross-site fetch', r.status);
    r = await door({ origin: origin });
    note(r.status !== 403, 'it answers its own Origin', r.status);
    r = await door({});
    note(r.status !== 403, 'and a program', r.status);

    // --- 4. no code on a refusal --------------------------------------------
    note(refusals.every(function (one) {
      return !/STS-[A-Z0-9]+-\d{4}/.test(one.text);
    }), 'no refusal carries an error code');

    // --- 5. the windows -----------------------------------------------------
    const windows = require(ROOT_DIR + '/tests/tools/dependency-windows');
    // A TRIVY REPORT AND THE 90-DAY REVIEW (#1485).
    const DAY = 86400000;
    const NOW = Date.parse('2026-11-09T00:00:00Z');
    const daysAgo = function (days) {
      return new Date(NOW - days * DAY).toISOString();
    };
    const image = windows.imageFindings({ Results: [{ Vulnerabilities: [
      { VulnerabilityID: 'CVE-1', PkgName: 'openssl', Severity: 'CRITICAL',
        PublishedDate: daysAgo(30), FixedVersion: '3.1' },
      { VulnerabilityID: 'CVE-2', PkgName: 'zlib', Severity: 'MEDIUM',
        PublishedDate: daysAgo(10), FixedVersion: '1.3' },
      { VulnerabilityID: 'CVE-3', PkgName: 'tar', Severity: 'HIGH',
        PublishedDate: daysAgo(400), FixedVersion: '' },
      { VulnerabilityID: 'CVE-4', PkgName: 'bash', Severity: 'LOW',
        PublishedDate: daysAgo(400), FixedVersion: '5' }
    ] }] });
    const imageLate = windows.overdue(image.filter(function (one) {
      return one.fixed;
    }), NOW).map(function (one) {
      return one.id;
    });
    note(JSON.stringify(imageLate) === '["CVE-1"]',
         'an image finding past its window fails; one within it, one with no ' +
         'fix and a low one do not', JSON.stringify(imageLate));
    const row = function (name, waitingDays, locked) {
      return { package: name, locked: locked || '1.0.0',
               oldestNewerPublished: waitingDays === null ? ''
                 : daysAgo(waitingDays) };
    };
    const waiting = windows.updatesOverdue([row('old', 100),
      row('recent', 30), row('current', null), row('held', 100),
      row('expired', 100), row('future', 100), row('noreason', 100),
      row('moved', 100)], {
      held: { reviewed: daysAgo(5), version: '1.0.0',
              reason: 'the next major drops our runtime' },
      expired: { reviewed: daysAgo(95), version: '1.0.0', reason: 'stale' },
      future: { reviewed: daysAgo(-5), version: '1.0.0', reason: 'dated ahead' },
      noreason: { reviewed: daysAgo(5), version: '1.0.0', reason: ' ' },
      moved: { reviewed: daysAgo(5), version: '0.9.0', reason: 'another pin' }
    }, NOW).map(function (one) {
      return one.package;
    });
    note(JSON.stringify(waiting) ===
         '["old","expired","future","noreason","moved"]',
         'an update waiting past 90 days fails unless a current review of ' +
         'that version, with a reason, holds it', JSON.stringify(waiting));
    const times = { '1.0.0': daysAgo(500), '1.1.0': daysAgo(400),
      '2.0.0-beta.1': daysAgo(450), '2.0.0': daysAgo(5) };
    note(windows.oldestNewer(times, '1.0.0', '2.0.0') === daysAgo(400) &&
         windows.oldestNewer(times, '2.0.0', '2.0.0') === '',
         'the wait is from the first stable release after the pin, however ' +
         'recent the latest is');
    note(windows.oldestNewer({ '1.8.15': daysAgo(2000),
                               '2.0.5': daysAgo(1900) }, '1.8.15',
                             '1.8.15') === '',
         'a higher version not tagged latest is not an update');
    const now = Date.parse('2026-11-09T00:00:00Z');
    const when = function (days) {
      return new Date(now - days * 86400000).toISOString();
    };
    const overdue = windows.overdue([
      { id: 'in-critical', severity: 'critical', published: when(6) },
      { id: 'past-critical', severity: 'critical', published: when(8) },
      { id: 'in-high', severity: 'high', published: when(29) },
      { id: 'past-high', severity: 'high', published: when(31) },
      { id: 'in-moderate', severity: 'moderate', published: when(89) },
      { id: 'past-moderate', severity: 'moderate', published: when(91) },
      { id: 'low', severity: 'low', published: when(4000) },
      { id: 'undated', severity: 'moderate', published: '' }
    ], now).map(function (one) {
      return one.id;
    }).sort();
    note(JSON.stringify(overdue) === JSON.stringify(
      ['past-critical', 'past-high', 'past-moderate', 'undated']),
         'an advisory is overdue past its window, or with no date',
         JSON.stringify(overdue));

    // --- 6. the install is what the lockfile names (#1458) ------------------
    const read = function (name) {
      return fs.readFileSync(ROOT_DIR + '/' + name, 'utf8');
    };
    const manifest = JSON.parse(read('package.json'));
    const lock = JSON.parse(read('package-lock.json'));
    note(manifest.dependencies.bunyan === '1.8.15',
         'bunyan is pinned', manifest.dependencies.bunyan);
    note(Object.keys(manifest.dependencies).every(function (name) {
      return manifest.dependencies[name] !== 'latest';
    }), 'no dependency floats on latest');
    note(lock.packages[''].dependencies.bunyan ===
         manifest.dependencies.bunyan, 'and the lockfile agrees, or npm ci ' +
         'would refuse it');
    ['Dockerfile', 'tests/Dockerfile'].forEach(function (name) {
      const floats = read(name).split('\n').filter(function (line) {
        return /^RUN npm install (--omit=dev|--prefix \.\/tests)/.test(line);
      });
      note(floats.length === 0, name + ' installs with npm ci',
           floats.join(' / '));
    });
    const policy = read('SECURITY.md');
    note(/\| Critical \| 7 days \|/.test(policy) &&
         /\| High \| 30 days \|/.test(policy) &&
         /\| Moderate \| 90 days \|/.test(policy) &&
         windows.WINDOW_DAYS.critical === 7 &&
         windows.WINDOW_DAYS.high === 30 &&
         windows.WINDOW_DAYS.moderate === 90,
         'SECURITY.md and the check state the same windows');

    // --- 7. each application clears its own tab first (#1440) ----------------
    const leaves = function (name, marker) {
      const text = read(name);
      const start = text.indexOf(marker);
      const stop = text.indexOf("assign(this.url('/logout')", start);
      return start >= 0 && stop > start &&
        text.slice(start, stop).indexOf('sessionStorage.clear()') >= 0;
    };
    note(leaves('admin-ui/web_runtime.ts', 'signOut(): void {'),
         'the console clears its tab before it leaves for /logout');
    note(leaves('portal/web_portal_runtime.ts', 'signOut(): void {'),
         'and the portal');
    const report = read('report/web_report_pages.ts');
    note(/data-sign-out="1"/.test(report) &&
         /closest\('\[data-sign-out\]'\)[\s\S]{0,160}sessionStorage\.clear\(\)/
           .test(report), 'and the report application, on its sign-out link');

    // --- 8. secrets stay out of URLs (#1454) ---------------------------------
    const spa = read('common/web_spa_client.ts');
    note(/response_mode = 'fragment'/.test(spa) &&
         /callbackParameters\(\)/.test(spa),
         'the first-party clients ask for the code in the fragment');
    ['admin-ui/web_runtime.ts', 'portal/web_portal_runtime.ts',
      'report/web_report_pages.ts'].forEach(function (name) {
      note(/openAuthorizationResponse\(\s*this\.callbackParameters\(\)\)/
        .test(read(name)), name + ' reads the fragment on its callback');
    });
    ['common/mail_uses.ts', 'portal/portal_pseudonyms.ts',
      'admin-core/admin_actions.ts'].forEach(function (name) {
      const text = read(name);
      note(text.indexOf("'#token='") >= 0 && text.indexOf("'&token='") < 0,
           name + ' puts an emailed token in the fragment');
    });
    note(read('authn/email_factor.ts').indexOf("'#t='") >= 0 &&
         /X-Link-Token/.test(read('portal/web_portal_runtime.ts')),
         'a sign-in link too, and the portal sends its token in a header');
    const stepAddress = require(ROOT_DIR + '/common/step_address');
    const moved = function (location) {
      return stepAddress.hide(location, function () {
        return 'app-1';
      });
    };
    const realHides = mode.hidesStepIds;
    mode.hidesStepIds = function () {
      return true;
    };
    note(moved('/authn/login?authn=abc') === '/authn/login?app=app-1#authn=abc',
         'a redirect to a sign-in step carries its id in the fragment');
    note(moved('https://h/realm/r/oauth2/consent?consent=c1') ===
         'https://h/realm/r/oauth2/consent?app=app-1#consent=c1',
         'and so does the consent screen');
    note(moved('/authn/spnego?authn=abc') === '/authn/spnego?authn=abc',
         'SPNEGO keeps it: RFC 4559 has no script to read a fragment');
    note(moved('/oauth2/callback?code=x') === '/oauth2/callback?code=x',
         'a protocol redirect is untouched');
    mode.hidesStepIds = realHides;
    note(moved('/authn/login?authn=abc') === '/authn/login?authn=abc',
         'development is unchanged');
    const WebPage = require(ROOT_DIR + '/common/web_page');
    note(WebPage.stepToFragment('/authn/totp?mfa=m1') === '/authn/totp#mfa=m1',
         'a page\'s own link moves too');
    const pathOut = WebPage.stepToHeaders('/authn-api/mfa/m1/totp?page=x');
    note(pathOut.path === '/authn-api/mfa/-/totp?page=x' &&
         pathOut.headers['X-Step-Id'] === 'm1',
         'an API call carries the id in a header');
    const queryOut = WebPage.stepToHeaders('/authn-api/wallet?authn=a1&x=1');
    note(queryOut.path === '/authn-api/wallet?x=1' &&
         queryOut.headers['X-Step-Query'] === 'authn=a1',
         'and a query id too');
    const probeStep = await ask('GET', '/authn-api/mfa/-',
      { 'x-step-id': 'no-such-step', accept: 'application/json' });
    note(probeStep.status === 400 && !/Cannot GET/.test(probeStep.text),
         'the API restores an id from its header',
         probeStep.status + ' ' + probeStep.text.slice(0, 120));

    let probed = await ask('GET', '/account-api/reset-password?user=a&token=b');
    note(probed.status === 400, 'the API takes no token in the query',
         probed.status + ' ' + probed.text.slice(0, 160));

    fs.writeFileSync(OUT, JSON.stringify(findings));
    server.close();
    process.exit(0);
  })().catch(function (e) {
    note(false, 'the probe ran', (e && e.stack) || e);
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

/**
 * Runs the child and reports what it found.
 *
 * @param {object} t - the runner's checker
 * @returns {Promise<void>}
 */
async function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'ar-' + process.pid + '-' + Date.now() +
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
                                  AR_ROOT: ROOT, AR_OUT: out }),
      encoding: 'utf8', timeout: 180000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    findings = null;
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
  name: 'asvs_response_rules',
  describe: 'HSTS, the charset on text and XML, a cookie write from another ' +
            'site, and the advisory windows (ASVS 5.0.0 Level 1)',
  run: run
};
