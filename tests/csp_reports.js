// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/csp_reports.js
// ===========================================================================
// CONTENT SECURITY POLICY VIOLATION REPORTS (#2164, ASVS 5.0.0 3.4.7).
//
// The whole stack in a child process, over HTTP on 127.0.0.1:
//
//   A. EVERY KIND OF PAGE NAMES THE ENDPOINT: a static surface's shell (the
//      front door, the console), a route's own relaxation through
//      contentSecurityPolicy(), the framed door, a policy a route wrote out
//      without the framing clauses (put back at the flush), and Express's own
//      404 — each with `report-uri` and `report-to` and the
//      `Reporting-Endpoints` header, and `frame-ancestors` kept. A JSON
//      answer carries neither.
//   B. THE ENDPOINT: both formats answered 204 with no body and counted; a
//      body over 16 KiB refused 413, declared or streamed; a type that is no
//      report's, an encoding, and a body with no report refused; the 61st
//      report a minute from one address refused 429; nothing of a body
//      reflected.
//   C. WHAT IS RECORDED: no query or fragment of the document or of what was
//      blocked, a keyword kept, a strange directive `unknown`, a realm's
//      prefix in the path.
//   D. THE FORWARD IS OFF BY DEFAULT, and on it sends the record, never the
//      body; the setting is per process.
//   E. THE FRONT PROCESS ANSWERS BOTH PATHS, and `app.js`'s intake names the
//      module's path.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'csp_reports',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

/**
 * The child process: builds the stack, listens, and asks.
 *
 * @returns {void}
 */
function childMain() {
  const ROOT_DIR = process.env.CR_ROOT;
  const OUT = process.env.CR_OUT;
  const http = require('http');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    const config = require(ROOT_DIR + '/common/config');
    const cspReports = require(ROOT_DIR + '/common/csp_reports');
    // Three pages of the test's own, registered last: a relaxation through
    // the door, the framed door, and a policy written out by hand without
    // the framing clauses.
    app.get('/csp-test/relaxed', function (req, res) {
      res.set('Content-Security-Policy',
              app.contentSecurityPolicy({ 'script-src': "'self'" }));
      res.type('html').send('<p>relaxed</p>');
    });
    app.get('/csp-test/framed', function (req, res) {
      res.set('Content-Security-Policy',
              app.framedContentSecurityPolicy(['https://rp.example'], {}));
      res.type('html').send('<p>framed</p>');
    });
    app.get('/csp-test/hand', function (req, res) {
      res.set('Content-Security-Policy', "default-src 'none'");
      res.type('html').send('<p>hand</p>');
    });
    const server = http.createServer(app);
    await new Promise(function (r) {
      server.listen(0, '127.0.0.1', r);
    });
    const port = server.address().port;
    const ask = function (method, p, headers, body, chunked) {
      return new Promise(function (resolve, reject) {
        const req = http.request({ host: '127.0.0.1', port: port, path: p,
          method: method, headers: headers || {} }, function (res) {
          const chunks = [];
          res.on('data', function (c) {
            chunks.push(c);
          });
          res.on('end', function () {
            resolve({ status: res.statusCode, headers: res.headers,
                      body: Buffer.concat(chunks).toString('utf8') });
          });
        });
        req.on('error', function (e) {
          // A refusal answered before the body was all sent may reset the
          // connection; the answer, if it came, is what is asserted.
          resolve({ status: 0, headers: {}, body: '', error: e.message });
        });
        if (body !== undefined) {
          if (chunked) {
            const step = 4096;
            for (let i = 0; i < body.length; i += step) {
              req.write(body.slice(i, i + step));
            }
          } else {
            req.write(body);
          }
        }
        req.end();
      });
    };
    const csp = function (r) {
      return String(r.headers['content-security-policy'] || '');
    };
    const reports = function (r) {
      const policy = csp(r);
      return policy.indexOf('report-uri /web/csp-report') >= 0 &&
        policy.indexOf('report-to csp-endpoint') >= 0 &&
        policy.indexOf('frame-ancestors') >= 0 &&
        r.headers['reporting-endpoints'] ===
          'csp-endpoint="/web/csp-report"';
    };

    // A. Every page.
    const pages = [['/', 'A1. the front door (a static surface)'],
                   ['/admin', 'A2. the console\'s shell'],
                   ['/csp-test/relaxed',
                    'A3. a relaxation through contentSecurityPolicy()'],
                   ['/csp-test/framed', 'A4. the framed door'],
                   ['/csp-test/hand',
                    'A5. a policy a route wrote without frame-ancestors'],
                   ['/csp-reports-no-such-path', 'A6. Express\'s own 404']];
    for (const one of pages) {
      const r = await ask('GET', one[0], { accept: 'text/html' });
      note(reports(r), one[1] + ' names the report endpoint, with ' +
           'Reporting-Endpoints', r.status + ' ' + csp(r) + ' | ' +
           r.headers['reporting-endpoints']);
    }
    const framed = await ask('GET', '/csp-test/framed');
    note(csp(framed).indexOf('frame-ancestors https://rp.example') >= 0,
         'A7. the framed door still names its framer', csp(framed));
    const hand = await ask('GET', '/csp-test/hand');
    note(csp(hand).split('report-uri').length === 2,
         'A8. a policy put back at the flush names it once', csp(hand));
    const discovery = await ask('GET', '/.well-known/openid-configuration',
                                { accept: 'application/json' });
    note(discovery.status === 200 && csp(discovery).indexOf('report') < 0 &&
         !discovery.headers['reporting-endpoints'],
         'A9. a JSON answer, which is not a page, reports nothing',
         discovery.status + ' ' + csp(discovery));

    // B. The endpoint.
    cspReports.reset();
    const level2 = JSON.stringify({ 'csp-report': {
      'document-uri': 'https://idp.example/authn/login?code=SECRET#frag',
      'violated-directive': 'script-src-elem',
      'effective-directive': 'script-src-elem',
      'blocked-uri': 'https://evil.example/x.js?token=SECRET2',
      'original-policy': "default-src 'none'",
      'script-sample': '<b>SAMPLE</b>'
    } });
    const r2 = await ask('POST', '/web/csp-report',
                         { 'content-type': 'application/csp-report' },
                         level2);
    note(r2.status === 204 && r2.body === '',
         'B1. a CSP Level 2 report is answered 204 with no body',
         r2.status + ' ' + r2.body);
    const batch = JSON.stringify([
      { type: 'csp-violation', age: 1, url: 'https://idp.example/portal',
        body: { documentURL: 'https://idp.example/portal?x=1',
                effectiveDirective: 'style-src-attr', blockedURL: 'inline',
                disposition: 'enforce' } },
      { type: 'deprecation', body: { id: 'x' } },
      { type: 'csp-violation', body: {
        documentURL: 'https://idp.example/admin',
        effectiveDirective: 'img-src',
        blockedURL: 'https://cdn.example/a.png?sig=SECRET3',
        disposition: 'report' } }
    ]);
    const r3 = await ask('POST', '/web/csp-report',
                         { 'content-type': 'application/reports+json' },
                         batch);
    note(r3.status === 204 && r3.body === '',
         'B2. a Reporting API batch is answered 204 with no body',
         r3.status + ' ' + r3.body);
    const view = cspReports.view();
    const counted = {};
    view.directives.forEach(function (row) {
      counted[row.directive] = row.count;
    });
    note(view.total === 3 && counted['script-src-elem'] === 1 &&
         counted['style-src-attr'] === 1 && counted['img-src'] === 1,
         'B3. each report is counted under its directive, and the other ' +
         'report type is not', JSON.stringify(view.directives));
    note(view.path === '/web/csp-report' && view.forwarding === false &&
         view.maxBodyBytes === 16384 && view.perAddressPerMinute === 60,
         'B4. the view names the path, the limits and no forward',
         JSON.stringify(view));
    const big = JSON.stringify({ 'csp-report': {
      'document-uri': 'https://idp.example/' + 'a'.repeat(17000) } });
    const r4 = await ask('POST', '/web/csp-report',
                         { 'content-type': 'application/csp-report',
                           'content-length': String(Buffer.byteLength(big)) },
                         big);
    note(r4.status === 413 || r4.status === 0,
         'B5. a body declared over 16 KiB is refused 413',
         r4.status + ' ' + (r4.error || ''));
    const r5 = await ask('POST', '/web/csp-report',
                         { 'content-type': 'application/csp-report',
                           'transfer-encoding': 'chunked' }, big, true);
    note(r5.status === 413 || r5.status === 0,
         'B6. so is one streamed past it with no length',
         r5.status + ' ' + (r5.error || ''));
    const r6 = await ask('POST', '/web/csp-report',
                         { 'content-type': 'text/plain' }, level2);
    note(r6.status === 415 && r6.body === '',
         'B7. a type that is no report\'s is refused 415', r6.status);
    const r7 = await ask('POST', '/web/csp-report',
                         { 'content-type': 'application/csp-report',
                           'content-encoding': 'gzip' }, level2);
    note(r7.status === 415, 'B8. a Content-Encoding is refused, not inflated',
         r7.status);
    const r8 = await ask('POST', '/web/csp-report',
                         { 'content-type': 'application/json' },
                         '{"<script>":"x"}');
    note(r8.status === 400 && r8.body === '' &&
         r8.body.indexOf('script') < 0,
         'B9. a body with no report is refused 400 and not reflected',
         r8.status + ' ' + r8.body);
    const r9 = await ask('GET', '/web/csp-report');
    note(r9.status === 404, 'B10. GET is not answered', r9.status);
    cspReports.reset();
    let last = null;
    let firstRefused = 0;
    for (let i = 1; i <= 61; i++) {
      last = await ask('POST', '/web/csp-report',
                       { 'content-type': 'application/csp-report' }, level2);
      if (last.status !== 204 && !firstRefused) {
        firstRefused = i;
      }
    }
    note(firstRefused === 61 && last.status === 429 &&
         !!last.headers['retry-after'] && last.body === '',
         'B11. the 61st report a minute from one address is refused 429 ' +
         'with Retry-After', firstRefused + ' ' + last.status);
    note(cspReports.view().total === 60,
         'B12. and was not counted', cspReports.view().total);
    cspReports.reset();

    // C. What is recorded.
    const one = cspReports.parse(level2)[0];
    note(one.documentPath === '/authn/login' &&
         one.blocked === 'https://evil.example' &&
         one.directive === 'script-src-elem' &&
         JSON.stringify(one).indexOf('SECRET') < 0 &&
         JSON.stringify(one).indexOf('SAMPLE') < 0,
         'C1. the document\'s path and the blocked origin, no query, no ' +
         'fragment, no sample', JSON.stringify(one));
    const odd = cspReports.parse(JSON.stringify({ 'csp-report': {
      'document-uri': 'javascript:alert(1)',
      'effective-directive': 'script-src"><b>',
      'blocked-uri': 'eval' } }))[0];
    note(odd.documentPath === '' && odd.directive === 'unknown' &&
         odd.blocked === 'eval',
         'C2. a strange directive is unknown, a keyword is kept, a ' +
         'non-http document has no path', JSON.stringify(odd));
    const data = cspReports.parse(JSON.stringify({ 'csp-report': {
      'document-uri': 'https://idp.example/',
      'effective-directive': 'img-src',
      'blocked-uri': 'data:image/png;base64,SECRETDATA' } }))[0];
    note(data.blocked === 'data',
         'C3. a data: URL is recorded as its scheme alone',
         JSON.stringify(data));
    note(cspReports.directives('/realm/acme') ===
           'report-uri /realm/acme/web/csp-report; report-to csp-endpoint' &&
         cspReports.reportingEndpoints('/realm/acme') ===
           'csp-endpoint="/realm/acme/web/csp-report"',
         'C4. a realm\'s pages report to the realm\'s own path',
         cspReports.directives('/realm/acme'));

    // D. The forward.
    note(config.value('cspReports.forwardUrl') === '',
         'D1. cspReports.forwardUrl is empty by default', '');
    const row = config.SETTINGS.filter(function (s) {
      return s.key === 'cspReports.forwardUrl';
    })[0];
    note(!!row && row.perProcess === true,
         'D2. and per process, so a realm administrator cannot set it', '');
    const dialled = [];
    const spy = new cspReports.CspReports(Object.assign(
      cspReports.CspReports.defaultDeps(), {
        dial: function (url, options) {
          dialled.push({ url: url, options: options });
          return Promise.resolve({ ok: true, status: 204 });
        }
      }));
    spy.record(one);
    note(dialled.length === 0, 'D3. with it empty nothing is dialled',
         dialled.length);
    config.setOverride('cspReports.forwardUrl',
                       'https://collector.example/csp');
    try {
      spy.record(one);
    } finally {
      config.clearOverride('cspReports.forwardUrl');
    }
    const sent = dialled[0] || { options: {} };
    note(dialled.length === 1 && sent.url === 'https://collector.example/csp' &&
         sent.options.method === 'POST' &&
         String(sent.options.body).indexOf('"directive":"script-src-elem"') >=
           0 &&
         String(sent.options.body).indexOf('SECRET') < 0,
         'D4. set, the record is POSTed to it and nothing of the body',
         JSON.stringify(dialled));

    // E. The front process.
    const requestPool = require(ROOT_DIR + '/common/request_pool');
    config.setOverride('workers.dispatch', '*');
    let kept = false;
    try {
      kept = !requestPool.dispatched('/web/csp-report') &&
        !requestPool.dispatched('/realm/acme/web/csp-report') &&
        !requestPool.dispatched('/admin-api/csp-reports');
    } finally {
      config.clearOverride('workers.dispatch');
    }
    note(kept, 'E1. the report and its read are never dispatched', kept);
    const appText = require('fs').readFileSync(ROOT_DIR + '/common/app.js',
                                               'utf8');
    note(appText.indexOf("const CSP_REPORT_PATH = '" + cspReports.PATH +
                         "'") >= 0,
         'E2. app.js\'s intake names the module\'s path', cspReports.PATH);

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
  const out = path.join(os.tmpdir(), 'cr-' + process.pid + '-' + Date.now() +
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
                                  CR_ROOT: ROOT, CR_OUT: out }),
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
  name: 'csp_reports',
  describe: 'Content Security Policy violation reports (#2164): every page ' +
            'names the endpoint, which takes both formats, caps, limits, ' +
            'strips queries and counts; the forward is off by default',
  run: run
};
