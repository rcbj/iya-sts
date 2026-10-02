// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/admin_api_session_gate.js
// ===========================================================================
// WITH `adminApi.authRequired` OFF, PRODUCT MODE STILL GATES /admin-api — ON
// THE CONSOLE'S SESSION AND ROLES (#411, 2026-10-02).
//
// `adminApi.authRequired` (on by default) puts an OAuth 2.0 access token in
// front of the management API. Turned off — the recovery path when nobody can
// mint a token — development leaves the API open, and product falls back to
// the console's own gate: `mgmt-api/admin_api.ts` asks
// `mode.gatesManagementApi()`, then `adminViews.gateStateFor(req)` for the
// caller's console session and its two roles, a read needing Admin Read and a
// write Admin Write. Nothing exercised that branch (#113 item 4;
// `tests/vendored/sts_admin_api_auth.js` says so): every stack runs with the
// token required.
//
// In a CHILD PROCESS with the whole stack on an ephemeral port, three people
// in the default realm — one holding Admin Read, one Admin Write, one nothing
// — each with a console session made over a real sign-on session, as
// `tests/console_bootstrap_product.js` makes them; then, in product with the
// setting off:
//
//   1. no session: 401, recorded under STS-API-0007;
//   2. a session holding no role: 403, under STS-API-0008;
//   3. Admin Read reads, and is refused a write (403, STS-API-0008);
//   4. Admin Write writes;
//   5. and, the control, development with the setting off answers a caller
//      with no session at all — the open API this branch exists to close.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'admin_api_session_gate',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.AG_ROOT;
  const OUT = process.env.AG_OUT;
  const http = require('http');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  function call(port, method, urlPath, cookie, body) {
    return new Promise(function (resolve, reject) {
      const text = body === undefined ? null : JSON.stringify(body);
      const headers = { accept: 'application/json' };
      if (cookie) {
        headers.cookie = cookie;
      }
      if (text) {
        headers['content-type'] = 'application/json';
        headers['content-length'] = Buffer.byteLength(text);
      }
      const req = http.request({ host: '127.0.0.1', port: port,
                                 path: urlPath, method: method,
                                 headers: headers }, function (res) {
        let raw = '';
        res.on('data', function (d) { raw += d; });
        res.on('end', function () {
          let json = null;
          try {
            json = JSON.parse(raw);
          } catch (e) {
            // Not JSON; the finding reports the text.
            json = null;
          }
          resolve({ status: res.statusCode, text: raw, json: json });
        });
      });
      req.on('error', reject);
      if (text) {
        req.write(text);
      }
      req.end();
    });
  }
  // A response object that keeps what `setCookieHeader()` writes.
  function fakeRes() {
    const out = { cookie: '', req: null };
    out.set = function (name, value) {
      if (String(name).toLowerCase() === 'set-cookie') {
        out.cookie = String(value).split(';')[0];
      }
      return out;
    };
    return out;
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    const config = require(ROOT_DIR + '/common/config');
    const realms = require(ROOT_DIR + '/common/realms');
    const rbac = require(ROOT_DIR + '/admin-ui/admin_rbac');
    const authn = require(ROOT_DIR + '/authn/authn');
    const oidcRp = require(ROOT_DIR + '/common/oidc_rp');
    const ldap = require(ROOT_DIR + '/ldap/ldap_server');
    const audit = require(ROOT_DIR + '/common/audit');

    const stamp = String(process.pid);
    const READER = 'ag-reader-' + stamp;
    const WRITER = 'ag-writer-' + stamp;
    const NOBODY = 'ag-nobody-' + stamp;
    [READER, WRITER, NOBODY].forEach(function (name) {
      ldap.createUser(name, { invent: false });
    });
    const inDefault = function (fn) {
      return realms.run(realms.DEFAULT_REALM, fn);
    };
    inDefault(function () {
      rbac.grant(READER, 'read', { via: 'test' });
      rbac.grant(WRITER, 'write', { via: 'test' });
    });

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const consoleCookie = oidcRp.cookieFor('admin');
    // A sign-on session and the console's relying-party session over it, as
    // `oidc_rp.ts`'s callback makes them, both in the default realm.
    const consoleSessionAs = function (username) {
      const signOnRes = fakeRes();
      const signOn = inDefault(function () {
        return authn.startSession(signOnRes, username, ['pwd'], '1',
                                  'password', {});
      });
      if (!signOn) {
        return '';
      }
      const rpRes = fakeRes();
      inDefault(function () {
        return authn.startRelyingPartySession({
          res: rpRes, username: username,
          claims: { amr: ['pwd'], sid: signOn.id, auth_time: signOn.authTime },
          amr: ['pwd'], via: 'the admin console', parent: signOn.id,
          surface: 'admin', label: 'the admin console',
          clientId: 'sts-admin-console', cookie: consoleCookie,
          parentRealm: realms.DEFAULT_ID
        });
      });
      return rpRes.cookie;
    };
    const coded = function (code) {
      return audit.list().filter(function (event) {
        return /^\/admin-api\/config/.test(String(event.target || '')) &&
               event.errorCode === code;
      }).length;
    };
    const READ = '/admin-api/config';
    const WRITE = '/admin-api/config/set';
    // A write that changes nothing: the setting's own default, written back.
    const WRITE_BODY = { key: 'oauth2.parRequestUriLifetimeS', value: '60' };

    // --- 5 first: the CONTROL, in development ------------------------------
    config.setOverride('adminApi.authRequired', false);
    let r = await call(port, 'GET', READ, '');
    note(r.status === 200, '5. development, adminApi.authRequired off: the ' +
         'API answers a caller with no session (the open API, the control)',
         r.status + ' ' + r.text.slice(0, 160));

    config.setOverride('global.mode', 'product');
    try {
      const reader = consoleSessionAs(READER);
      const writer = consoleSessionAs(WRITER);
      const nobody = consoleSessionAs(NOBODY);
      note(!!reader && !!writer && !!nobody,
           'precondition: three console sessions were made',
           [!!reader, !!writer, !!nobody].join(','));

      // --- 1. no session --------------------------------------------------
      let before = coded('STS-API-0007');
      r = await call(port, 'GET', READ, '');
      await new Promise(function (res) { setTimeout(res, 30); });
      note(r.status === 401 && coded('STS-API-0007') === before + 1,
           '1. PRODUCT, setting off: no session is 401, recorded under ' +
           'STS-API-0007', r.status + ' ' + r.text.slice(0, 160));

      // --- 2. a session holding no role ------------------------------------
      before = coded('STS-API-0008');
      r = await call(port, 'GET', READ, nobody);
      await new Promise(function (res) { setTimeout(res, 30); });
      note(r.status === 403 && coded('STS-API-0008') === before + 1,
           '2. PRODUCT, setting off: a console session holding no role is ' +
           '403, recorded under STS-API-0008',
           r.status + ' ' + r.text.slice(0, 160));

      // --- 3. Admin Read ---------------------------------------------------
      r = await call(port, 'GET', READ, reader);
      note(r.status === 200, '3a. PRODUCT, setting off: Admin Read reads',
           r.status + ' ' + r.text.slice(0, 160));
      before = coded('STS-API-0008');
      r = await call(port, 'POST', WRITE, reader, WRITE_BODY);
      await new Promise(function (res) { setTimeout(res, 30); });
      note(r.status === 403 && coded('STS-API-0008') === before + 1,
           '3b. PRODUCT, setting off: Admin Read is refused a write (403, ' +
           'STS-API-0008)', r.status + ' ' + r.text.slice(0, 160));

      // --- 4. Admin Write --------------------------------------------------
      r = await call(port, 'POST', WRITE, writer, WRITE_BODY);
      note(r.status === 200, '4. PRODUCT, setting off: Admin Write writes',
           r.status + ' ' + r.text.slice(0, 160));
    } finally {
      config.clearOverride('global.mode');
      config.clearOverride('adminApi.authRequired');
    }
    server.close();
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    note(false, 'the child process ran to the end', e && e.stack);
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

async function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'ag-' + process.pid + '-' + Date.now() +
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
                                  AG_ROOT: ROOT, AG_OUT: out }),
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
  name: 'admin_api_session_gate',
  describe: 'with adminApi.authRequired off, product mode gates /admin-api ' +
            'on the console\'s session and roles (#411)',
  run: run
};
