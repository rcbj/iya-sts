// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/admin_api_auth_required_mode.js
// ===========================================================================
// `adminApi.authRequired=false` IS DEVELOPMENT MODE'S ALONE (#446,
// 2026-10-05). PRODUCT IGNORES IT, AND A CONSOLE SESSION OPENS NOTHING.
//
// `adminApi.authRequired` (on by default) puts an OAuth 2.0 access token in
// front of the management API. Turned off, development leaves the API open:
// what a test drives, and the way back in when nobody can mint a token.
// Until #446 product then fell back to the console's own session and its two
// roles (#411, and this file was `admin_api_session_gate.js`, which held
// that branch). The console is becoming a static application whose only gate
// is this API's, so the fallback is gone: the setting's row carries the
// `onlyWhile` marker on `mode.opensManagementApi()`, product reads a stored
// `false` as `true`, and refuses to store one.
//
// In a CHILD PROCESS with the whole stack on an ephemeral port, and one
// person holding Admin Write with a console session made over a real sign-on
// session, as `tests/console_bootstrap_product.js` makes them:
//
//   1. the control: development with the setting off answers a caller with
//      no credential at all;
//   2. product, the `false` still stored: no credential is 401, recorded
//      under STS-API-0001 — the token gate's own refusal, not a fallback's;
//   3. product: the Admin Write console session is 401 too, read and write —
//      a session is not this API's credential;
//   4. product: the value in force is `true` while the stored one is
//      `false`, and `/admin/mode`'s report lists the row as ignored;
//   5. product: storing `false` is refused, and the default may still be
//      written;
//   6. back in development the stored `false` opens the API again, so
//      nothing was changed by the product reading.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'admin_api_auth_required_mode',
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
    const mode = require(ROOT_DIR + '/common/mode');

    const stamp = String(process.pid);
    const WRITER = 'ag-writer-' + stamp;
    ldap.createUser(WRITER, { invent: false });
    const inDefault = function (fn) {
      return realms.run(realms.DEFAULT_REALM, fn);
    };
    inDefault(function () {
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
    const KEY = 'adminApi.authRequired';
    const READ = '/admin-api/config';
    const WRITE = '/admin-api/config/set';
    // A write that changes nothing: the setting's own default, written back.
    const WRITE_BODY = { key: 'oauth2.parRequestUriLifetimeS', value: '60' };

    // --- 1. the CONTROL, in development -----------------------------------
    const stored = config.setOverride(KEY, false);
    note(stored && stored.ok !== false, 'precondition: development stores ' +
         KEY + '=false', JSON.stringify(stored));
    let r = await call(port, 'GET', READ, '');
    note(r.status === 200, '1. development, ' + KEY + ' off: the API ' +
         'answers a caller with no credential (the open API, the control)',
         r.status + ' ' + r.text.slice(0, 160));

    config.setOverride('global.mode', 'product');
    try {
      const writer = consoleSessionAs(WRITER);
      note(!!writer, 'precondition: a console session was made', !!writer);

      // --- 2. no credential -------------------------------------------------
      const before = coded('STS-API-0001');
      r = await call(port, 'GET', READ, '');
      await new Promise(function (res) { setTimeout(res, 30); });
      note(r.status === 401 && coded('STS-API-0001') === before + 1,
           '2. PRODUCT, the false still stored: no credential is 401, ' +
           'recorded under STS-API-0001 (the token gate)',
           r.status + ' ' + r.text.slice(0, 160));

      // --- 3. a console session is not a credential here --------------------
      r = await call(port, 'GET', READ, writer);
      note(r.status === 401, '3a. PRODUCT: an Admin Write console session ' +
           'does not read (401)', r.status + ' ' + r.text.slice(0, 160));
      r = await call(port, 'POST', WRITE, writer, WRITE_BODY);
      note(r.status === 401, '3b. PRODUCT: an Admin Write console session ' +
           'does not write (401)', r.status + ' ' + r.text.slice(0, 160));

      // --- 4. stored against in force ---------------------------------------
      const row = (mode.report().developmentOnlySettings || [])
        .filter(function (one) { return one.key === KEY; })[0] || null;
      note(config.value(KEY) === false && mode.valueInForce(KEY) === true,
           '4a. PRODUCT: the stored value is false and the value in force ' +
           'is true', config.value(KEY) + ' / ' + mode.valueInForce(KEY));
      note(!!row && row.ignored === true && row.inForce === true &&
           row.predicate === 'opensManagementApi',
           '4b. PRODUCT: the mode report lists the row as ignored, in force ' +
           'true, on opensManagementApi', JSON.stringify(row));

      // --- 5. the write ------------------------------------------------------
      config.clearOverride(KEY);
      const refused = config.setOverride(KEY, false);
      note(!!refused && refused.ok === false,
           '5a. PRODUCT: storing false is refused', JSON.stringify(refused));
      note(config.value(KEY) === true, '5b. PRODUCT: the refused write ' +
           'stored nothing', String(config.value(KEY)));
      const allowed = config.setOverride(KEY, true);
      note(!allowed || allowed.ok !== false,
           '5c. PRODUCT: the default may still be written',
           JSON.stringify(allowed));
    } finally {
      config.clearOverride('global.mode');
    }

    // --- 6. development again ------------------------------------------------
    config.setOverride(KEY, false);
    r = await call(port, 'GET', READ, '');
    note(r.status === 200, '6. development again, ' + KEY + ' off: the API ' +
         'is open, so the product reading changed nothing stored',
         r.status + ' ' + r.text.slice(0, 160));
    config.clearOverride(KEY);
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
  name: 'admin_api_auth_required_mode',
  describe: 'adminApi.authRequired=false is development-only: product ' +
            'ignores it and a console session opens nothing (#446)',
  run: run
};
