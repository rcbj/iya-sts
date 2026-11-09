// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/cookie_wire.js
// ===========================================================================
// EVERY COOKIE IS `__Host-` OR `__Secure-` ON THE WIRE (#1441, ASVS 5.0.0
// 3.3.1), AND ONLY THE MAIN THREAD DOES IT.
//
//   1. A line: `__Host-` at the root with no Domain, `__Secure-` with one,
//      Secure added, the attributes kept, a foreign cookie left alone.
//   2. A header: both prefixes taken off where they are believed, an
//      unprefixed `sts_*` dropped, the pool pins and foreign cookies kept.
//   3. The stack, with a TLS socket and product's predicate: a real answer's
//      cookie is prefixed, a request's arrives under its inside name, and
//      neither happens on cleartext or in development.
//   4. A worker never translates: the code asks `isMainThread`.
//   5. Every cookie the service declares can be translated, and the OP iframe
//      script still finds its cookie when it is prefixed.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'cookie_wire',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

/**
 * The child process: builds the stack, listens, and asks.
 *
 * @returns {void}
 */
function childMain() {
  const ROOT_DIR = process.env.CW_ROOT;
  const OUT = process.env.CW_OUT;
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
    const wire = require(ROOT_DIR + '/common/cookie_wire');

    // --- 1. a line ----------------------------------------------------------
    const same = function (got, want, what) {
      note(got === want, what, got);
    };
    same(wire.wrapLine('sts_lang=fr; Path=/; Max-Age=9; Secure'),
         '__Host-sts_lang=fr; Path=/; Max-Age=9; Secure',
         'at the root with no Domain: __Host-');
    same(wire.wrapLine('sts_session=a.b; Path=/; HttpOnly; SameSite=Lax'),
         '__Host-sts_session=a.b; Path=/; HttpOnly; SameSite=Lax; Secure',
         'Secure is added, or a browser would refuse the prefix');
    same(wire.wrapLine('sts_session=a; Path=/; Domain=example.com; Secure'),
         '__Secure-sts_session=a; Path=/; Domain=example.com; Secure',
         'with a Domain: __Secure-');
    same(wire.wrapLine('sts_session=; Path=/; Max-Age=0; Secure'),
         '__Host-sts_session=; Path=/; Max-Age=0; Secure',
         'a clear goes by the same name, or it clears nothing');
    same(wire.wrapLine('__Host-sts_browser=x; Path=/; Secure'),
         '__Host-sts_browser=x; Path=/; Secure', 'already prefixed: untouched');
    same(wire.wrapLine('other=1; Path=/'), 'other=1; Path=/',
         'not this service\'s: untouched');

    // --- 2. a header --------------------------------------------------------
    same(wire.unwrapHeader('__Host-sts_session=a.b; other=1', false),
         'sts_session=a.b; other=1', '__Host- comes off');
    same(wire.unwrapHeader('__Secure-sts_session=a', true), 'sts_session=a',
         '__Secure- comes off where a shared domain writes it');
    same(wire.unwrapHeader('__Secure-sts_session=a', false), '',
         'and is not believed where nothing here writes it');
    same(wire.unwrapHeader('sts_session=a.b; __Host-sts_lang=fr', false),
         'sts_lang=fr', 'an unprefixed sts_ cookie is dropped');
    same(wire.unwrapHeader('sts_pool=7; sts_pool_surfaces=8', false),
         'sts_pool=7; sts_pool_surfaces=8', 'the pool pins are spared');
    same(wire.unwrapHeader('__Secure-sts_session_bound_x=1', false),
         'sts_session_bound_x=1', 'a DBSC site-scoped cookie comes off');

    same(wire.wrapLine('sts_claim_link=x; Path=/portal/cb; Secure'),
         '__Secure-sts_claim_link=x; Path=/portal/cb; Secure',
         'a narrower Path can only be __Secure-');
    ['sts_claim_link', 'sts_est_nonce'].forEach(function (name) {
      same(wire.unwrapHeader('__Host-' + name + '=1', false), name + '=1',
           name + ' comes back, or the feature it carries breaks');
    });

    // --- 3. the stack -------------------------------------------------------
    app.get('/cookie-probe', function (req, res) {
      res.json({ cookie: String(req.headers.cookie || '') });
    });
    const server = http.createServer(function (req, res) {
      req.socket.encrypted = req.headers['x-probe-tls'] === '1';
      app(req, res);
    });
    await new Promise(function (r) {
      server.listen(0, '127.0.0.1', r);
    });
    const port = server.address().port;
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
    const form = { 'content-type': 'application/x-www-form-urlencoded' };
    const choose = function (extra) {
      return ask('POST', '/authn/language', Object.assign({}, form, extra),
                 'lang=fr&return=/');
    };
    const echoed = function (extra) {
      return ask('GET', '/cookie-probe', Object.assign(
        { cookie: '__Host-sts_lang=fr; sts_session=forged.x' }, extra));
    };
    const real = mode.prefixesCookies;
    mode.prefixesCookies = function () {
      return true;
    };
    let r = await choose({ 'x-probe-tls': '1' });
    const line = String((r.headers['set-cookie'] || [])[0]);
    note(/^__Host-sts_lang=fr;/.test(line) && /; Secure/.test(line),
         'product over TLS: a real answer\'s cookie is prefixed', line);
    r = await echoed({ 'x-probe-tls': '1' });
    note(JSON.parse(r.text).cookie === 'sts_lang=fr',
         'and a request arrives under its inside name, the forgery gone',
         r.text);
    r = await choose({});
    note(/^sts_lang=fr;/.test(String((r.headers['set-cookie'] || [])[0])),
         'cleartext: not prefixed, or a browser would refuse it',
         String(r.headers['set-cookie']));
    mode.prefixesCookies = real;
    r = await choose({ 'x-probe-tls': '1' });
    note(/^sts_lang=fr;/.test(String((r.headers['set-cookie'] || [])[0])),
         'development: not prefixed', String(r.headers['set-cookie']));

    // --- 4 and 5. the source ------------------------------------------------
    const read = function (name) {
      return fs.readFileSync(ROOT_DIR + '/' + name, 'utf8');
    };
    note(/!workerThreads\.isMainThread/.test(read('common/cookie_wire.ts')),
         'a worker does not translate');
    const appText = read('common/app.js');
    note(appText.indexOf('app.use(enterRealm)') <
           appText.indexOf('cookieWire.middleware()') &&
         appText.indexOf('cookieWire.middleware()') <
           appText.indexOf('requestPool.middleware('),
         'the names are translated after the realm and before routing');
    const sm = read('oauth-oidc/session_management.js');
    note(sm.indexOf('__(?:Host|Secure)-') >= 0,
         'the OP iframe finds its cookie when it is prefixed');
    const declared = ['authn/authn.ts', 'authn/account_sets.ts',
      'authn/email_factor.ts', 'common/page_locale.ts',
      'common/realm_chooser.ts',
      'common/cell_placement.ts', 'common/request_pool.js',
      'federation/federation_sp.ts', 'est/est.ts', 'oid4vc/vc_signin.ts',
      'oauth-oidc/session_management.js', 'portal/portal_claim_sources.ts',
      'kerberos/spnego_exchange.js', 'authn/device_bound_sessions.ts'];
    const odd = [];
    declared.forEach(function (name) {
      (read(name).match(/_?COOKIE = '[^']+'/g) || []).forEach(function (one) {
        if (!/'sts_/.test(one)) {
          odd.push(name + ': ' + one);
        }
      });
    });
    note(odd.length === 0, 'every declared cookie is one the wire translates',
         odd.join(', '));

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
  const out = path.join(os.tmpdir(), 'cw-' + process.pid + '-' + Date.now() +
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
                                  CW_ROOT: ROOT, CW_OUT: out }),
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
  name: 'cookie_wire',
  describe: 'every cookie is __Host- or __Secure- on the wire in product ' +
            'over TLS, translated once by the process holding the socket',
  run: run
};
