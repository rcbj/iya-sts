// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/read_scope_gates.js
// ===========================================================================
// THE APIS THE THREE BROWSER APPLICATIONS CALL, WITH READ TOKENS AND WITH
// THE TOKENS OF BEFORE (#2168, ASVS 5.0.0 10.2.3).
//
// The console, the portal and the reports application sign in with read
// scopes and ask a write scope by a second authorization when a write needs
// it (`tests/spa_write_scope_step.js` drives that half). This is the
// server's half, in a CHILD PROCESS with the whole stack on an ephemeral
// port and tokens minted as the token endpoint mints them:
//
//   1. `/admin-api`: a read token reads; its write is refused 403 with an
//      RFC 6750 `insufficient_scope` challenge naming `admin:write`, the
//      code and body unchanged; `GET /admin-api/me`'s `holds` says what a
//      second authorization could add; a security change on an
//      `admin:write` token names `admin:security`; a subject without the
//      role is told no scope; an `admin:write` token writes as before;
//   1g. THE VIEWS DRAW WHAT THE PERSON HOLDS (#2200): on a read token, an
//      Admin Write holder's `/admin-api/logout` answers `canWrite` and
//      `/admin-api/rbac`'s `you.write` is true, a reader's is not — and the
//      end-session write itself is still refused `insufficient_scope`;
//   2. `/account-api`: `account:read` reads and does not write (the
//      challenge names `account:manage`); `account:manage` does both, as
//      before;
//   3. `/report-api`: `report:read` reads with the report role held, does
//      not write (the challenge names both report scopes), is refused for a
//      subject with no report role, and is not counted on a write beside
//      `report:use`; `report:use` writes as before;
//   4. issuance: `report:read` is role-gated — narrowed off a subject with
//      no report role, kept for one with it;
//   5. the seeds: `sts-user-portal` and `sts-report` declare the two read
//      scopes, and a grant taken off an existing entry comes back at the
//      next seed (the upgrade).
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'read_scope_gates',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.RS_ROOT;
  const OUT = process.env.RS_OUT;
  let dpopKit = null;
  const kit = function () {
    dpopKit = dpopKit || require(ROOT_DIR + '/tests/tools/console_dpop')
      .consoleDpop(ROOT_DIR);
    return dpopKit;
  };
  const http = require('http');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  function call(port, method, urlPath, token, body) {
    return new Promise(function (resolve, reject) {
      const text = body === undefined ? null : JSON.stringify(body);
      const headers = Object.assign({ accept: 'application/json' },
        kit().headers(method, 'http://127.0.0.1:' + port +
                      urlPath.split('?')[0], token));
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
          resolve({ status: res.statusCode, text: raw, json: json,
                    challenge: String(res.headers['www-authenticate'] || ''),
                    code: String(res.headers['x-sts-error-code'] || '') });
        });
      });
      req.on('error', reject);
      if (text) {
        req.write(text);
      }
      req.end();
    });
  }
  function brief(r) {
    return r.status + ' [' + r.challenge + '] ' +
      String(r.text || '').slice(0, 240);
  }
  function names(r, scope) {
    return r.status === 403 &&
      /error="insufficient_scope"/.test(r.challenge) &&
      r.challenge.indexOf('scope="' + scope + '"') >= 0;
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    const realms = require(ROOT_DIR + '/common/realms');
    const rbac = require(ROOT_DIR + '/admin-ui/admin_rbac');
    const oauth2 = require(ROOT_DIR + '/oauth-oidc/oauth2');
    const ldap = require(ROOT_DIR + '/ldap/ldap_server');
    const applications = require(ROOT_DIR + '/common/applications');
    const scopePolicy = require(ROOT_DIR + '/common/scope_policy');
    const rolePermissions = require(ROOT_DIR + '/common/role_permissions');

    const stamp = String(process.pid);
    const WRITER = 'rs-writer-' + stamp;
    const READER = 'rs-reader-' + stamp;
    const NOBODY = 'rs-nobody-' + stamp;
    [WRITER, READER, NOBODY].forEach(function (name) {
      ldap.createUser(name, { invent: false });
    });
    const inDefault = function (fn) {
      return realms.run(realms.DEFAULT_REALM, fn);
    };
    inDefault(function () {
      rbac.grant(WRITER, 'write', { via: 'test' });
      rbac.grant(WRITER, 'read', { via: 'test' });
      rbac.grant(READER, 'read', { via: 'test' });
    });

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const base = 'http://127.0.0.1:' + port;
    const mint = function (client, api, scope, who) {
      return inDefault(function () {
        return oauth2.accessTokenAsync(base, { jkt: kit().jkt,
          audience: base + api, scope: scope, client_id: client,
          username: who, sub: who });
      });
    };

    // --- 1. /admin-api --------------------------------------------------
    const CONSOLE = 'sts-admin-console';
    const read = await mint(CONSOLE, '/admin-api',
                            'openid admin:read admin:console', WRITER);
    const broad = await mint(CONSOLE, '/admin-api',
      'openid admin:read admin:write admin:console', WRITER);
    const readerBroad = await mint(CONSOLE, '/admin-api',
      'openid admin:read admin:write admin:console', READER);
    let r = await call(port, 'GET', '/admin-api/users', read);
    note(r.status === 200, '1a. a console read token reads', brief(r));
    r = await call(port, 'GET', '/admin-api/me', read);
    const me = r.json || {};
    note(r.status === 200 && me.write === false &&
         Array.isArray(me.holds) && me.holds.indexOf('ADMIN_WRITE') >= 0,
         '1b. /me: the read token does not write, and holds names ' +
         'ADMIN_WRITE, which a second authorization could add', brief(r));
    const WRITE = '/admin-api/users/update-fields';
    r = await call(port, 'POST', WRITE, read, { user: READER });
    note(names(r, 'admin:write') && /^DPoP /.test(r.challenge) &&
         r.json && r.json.error === 'forbidden',
         '1c. the read token\'s write: 403, the body unchanged, and a DPoP ' +
         'insufficient_scope challenge naming admin:write', brief(r));
    r = await call(port, 'POST', WRITE, broad, { user: READER });
    note(r.status !== 403 && r.status !== 401,
         '1d. an admin:write token of before writes as it always did',
         brief(r));
    r = await call(port, 'POST', WRITE, readerBroad, { user: WRITER });
    note(r.status === 403 && !/insufficient_scope/.test(r.challenge),
         '1e. a subject without the role is told no scope: a second ' +
         'authorization could not mend it', brief(r));
    r = await call(port, 'POST', '/admin-api/rbac/grant', broad,
                   { username: READER, role: 'security' });
    note(names(r, 'admin:security'),
         '1f. a security change on an admin:write token names ' +
         'admin:security', brief(r));
    // 1g. The views a write control is drawn from (#2200).
    r = await call(port, 'GET', '/admin-api/logout?user=' + READER, read);
    note(r.status === 200 && r.json && r.json.canWrite === true,
         '1g. on a read token, an Admin Write holder\'s /admin-api/logout ' +
         'answers canWrite: the end-session controls are drawn', brief(r));
    r = await call(port, 'GET', '/admin-api/rbac', read);
    note(r.status === 200 && r.json && r.json.you &&
         r.json.you.write === true,
         '1g. and /admin-api/rbac says the holder may write', brief(r));
    const readerRead = await mint(CONSOLE, '/admin-api',
                                  'openid admin:read admin:console', READER);
    r = await call(port, 'GET', '/admin-api/logout?user=' + WRITER,
                   readerRead);
    note(r.status === 200 && r.json && r.json.canWrite === false,
         '1g. a reader, who holds no Admin Write, is drawn none', brief(r));
    r = await call(port, 'POST', '/admin-api/logout/end', read,
                   { user: READER });
    note(names(r, 'admin:write'),
         '1g. and the end-session write on the read token is still ' +
         'refused insufficient_scope naming admin:write', brief(r));

    // --- 2. /account-api ------------------------------------------------
    const PORTAL = 'sts-user-portal';
    const accountRead = await mint(PORTAL, '/account-api',
                                   'openid account:read', WRITER);
    const accountManage = await mint(PORTAL, '/account-api',
                                     'openid account:manage', WRITER);
    r = await call(port, 'GET', '/account-api/me', accountRead);
    note(r.status === 200, '2a. account:read reads', brief(r));
    r = await call(port, 'POST', '/account-api/language', accountRead,
                   { lang: '' });
    note(names(r, 'account:manage'),
         '2b. account:read does not write: insufficient_scope naming ' +
         'account:manage', brief(r));
    r = await call(port, 'GET', '/account-api/me', accountManage);
    const manageRead = r.status;
    r = await call(port, 'POST', '/account-api/language', accountManage,
                   { lang: '' });
    note(manageRead === 200 && r.status !== 403 && r.status !== 401,
         '2c. an account:manage token of before reads and writes',
         manageRead + ' ' + brief(r));

    // --- 3. /report-api -------------------------------------------------
    const REPORT = 'sts-report';
    const reportRead = await mint(REPORT, '/report-api',
                                  'openid report:read', WRITER);
    r = await call(port, 'GET', '/report-api/definitions', reportRead);
    note(r.status === 200, '3a. report:read reads, with the report role ' +
         'its subject holds', brief(r));
    r = await call(port, 'POST', '/report-api/definitions', reportRead, {});
    note(names(r, 'report:use report:admin'),
         '3b. report:read does not write: insufficient_scope naming both ' +
         'report scopes', brief(r));
    const nobodyRead = await mint(REPORT, '/report-api',
                                  'openid report:read', NOBODY);
    r = await call(port, 'GET', '/report-api/definitions', nobodyRead);
    note(r.status === 403, '3c. report:read for a subject with no report ' +
         'role is refused', brief(r));
    const useToken = await mint(REPORT, '/report-api',
                                'openid report:use', WRITER);
    r = await call(port, 'POST', '/report-api/definitions', useToken, {});
    note(r.status !== 401 && !/insufficient_scope/.test(r.challenge),
         '3d. a report:use token of before passes the gate to write',
         brief(r));

    // --- 4. issuance ----------------------------------------------------
    const narrowed = inDefault(function () {
      return rolePermissions.narrowScope('openid report:read',
        { kind: 'user', name: NOBODY, authenticated: true },
        { clientId: REPORT, grant: 'authorization_code', record: false });
    });
    const kept = inDefault(function () {
      return rolePermissions.narrowScope('openid report:read',
        { kind: 'user', name: WRITER, authenticated: true },
        { clientId: REPORT, grant: 'authorization_code', record: false });
    });
    note(narrowed.removed.indexOf('report:read') >= 0 &&
         kept.removed.indexOf('report:read') < 0 &&
         rolePermissions.isGated('report:read'),
         '4. report:read is role-gated at issuance: narrowed off a subject ' +
         'with no report role, kept for one with it',
         JSON.stringify([narrowed.scope, kept.scope]));

    // --- 5. the seeds and the upgrade -----------------------------------
    const declared = inDefault(function () {
      return [scopePolicy.declares(PORTAL, 'account:read'),
              scopePolicy.declares(REPORT, 'report:read'),
              scopePolicy.declares(PORTAL, 'account:manage'),
              scopePolicy.declares(CONSOLE, 'account:read')];
    });
    note(declared[0] && declared[1] && declared[2] && !declared[3],
         '5a. the portal and the reports client declare the read scopes; ' +
         'the console does not', JSON.stringify(declared));
    const grantsOf = function () {
      const viewed = applications.get(PORTAL) || { fields: {} };
      return [].concat(viewed.fields.oauthDelegatedPermission || [])
        .map(String);
    };
    const GRANT = 'urn:sts:account-api:account:read';
    inDefault(function () {
      applications.updateApplication(PORTAL,
        { attribute: 'oauthDelegatedPermission', mode: 'remove',
          value: GRANT });
    });
    const taken = grantsOf().indexOf(GRANT) < 0;
    inDefault(function () {
      applications.seedInternalApplications({ scope: 'default' });
    });
    note(taken && grantsOf().indexOf(GRANT) >= 0,
         '5b. account:read taken off an existing sts-user-portal comes back ' +
         'at the next seed (the upgrade)', taken + ' ' + grantsOf().join(' '));

    server.close();
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    note(false, 'the child process ran to the end', e && e.stack);
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

async function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'rs-' + process.pid + '-' + Date.now() +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$|ADMIN_API_)/
        .test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', 'const fs = require("fs"); (' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal',
                                  RS_ROOT: ROOT, RS_OUT: out }),
      encoding: 'utf8', timeout: 240000, cwd: ROOT
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
  name: 'read_scope_gates',
  describe: 'the three APIs with read tokens and with the tokens of ' +
            'before: read scopes read, a write names its scope, an old ' +
            'token works (#2168)',
  run: run
};
