// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/admin_api_me.js
// ===========================================================================
// `GET /admin-api/me` ANSWERS WHAT THE GATE DECIDED FOR THE CALLER (#446,
// 2026-10-05).
//
// The admin console is becoming a static application whose only knowledge of
// its reader is the access token it presents. What the server-rendered
// console learned from `adminViews.gateStateFor(req)` — who is signed in,
// which authority they are, what they hold, which pages `admin_scope.ts`
// hides from them — this operation tells it, from what the gate left on the
// response rather than from a second reading of the roster.
//
// In a CHILD PROCESS with the whole stack on an ephemeral port, a person
// holding Admin Write and one holding Admin Read in the default realm, a
// person holding Admin Write in a realm of their own, and tokens minted as
// the token endpoint mints them:
//
//   1. Admin Write: a person, the `service` authority, both roles, read and
//      write, and every page — a service page among them;
//   2. Admin Read: reads and does not write, though the token carries both
//      scopes (held ∩ carried);
//   3. a role revoked after the token was minted shows on the next call;
//   4. a `client_credentials` token: an application, and no roster state;
//   5. a realm's own token, under that realm's prefix: the `realm`
//      authority, that realm, and NO service page among its pages;
//   6. the control, development with `adminApi.authRequired` off and no
//      token: no caller, and both read and write.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'admin_api_me',
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
  function call(port, method, urlPath, token, body) {
    return new Promise(function (resolve, reject) {
      const text = body === undefined ? null : JSON.stringify(body);
      const headers = { accept: 'application/json' };
      if (token) {
        headers.authorization = 'Bearer ' + token;
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
  function settle() {
    // The HTTP row is written when the response has finished.
    return new Promise(function (res) { setTimeout(res, 40); });
  }

  (async function () {
    require(ROOT_DIR + '/common/protocol_stack');
    const app = require(ROOT_DIR + '/common/app');
    const config = require(ROOT_DIR + '/common/config');
    const realms = require(ROOT_DIR + '/common/realms');
    const rbac = require(ROOT_DIR + '/admin-ui/admin_rbac');
    const oauth2 = require(ROOT_DIR + '/oauth-oidc/oauth2');
    const ldap = require(ROOT_DIR + '/ldap/ldap_server');
    const audit = require(ROOT_DIR + '/common/audit');

    const stamp = String(process.pid);
    const WRITER = 'am-writer-' + stamp;
    const READER = 'am-reader-' + stamp;
    const BOSS = 'am-boss-' + stamp;
    const CLIENT = 'sts-management-api';
    const R = 'am' + stamp;
    const SERVICE_PAGE = '/admin/persistence';
    const REALM_PAGE = '/admin/users';
    [WRITER, READER].forEach(function (name) {
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
    realms.create({ id: R, name: 'The me operation' });
    const bossGrant = rbac.grant(BOSS, 'write', { via: 'test', realm: R });
    note(bossGrant && bossGrant.ok, 'precondition: a realm of its own, with ' +
         'an administrator', JSON.stringify(bossGrant));

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const base = 'http://127.0.0.1:' + port;
    const SCOPE = 'admin:read admin:write';
    const mint = function (claims) {
      return inDefault(function () {
        return oauth2.accessTokenAsync(base, Object.assign({
          audience: base + '/admin-api', scope: SCOPE }, claims));
      });
    };
    const writer = await mint({ client_id: 'sts-admin-console',
                                username: WRITER, sub: WRITER });
    const reader = await mint({ client_id: 'sts-admin-console',
                                username: READER, sub: READER });
    const client = await mint({ client_id: CLIENT, sub: CLIENT });
    const realmBase = base + '/realm/' + R;
    const boss = await realms.run(realms.get(R), function () {
      return oauth2.accessTokenAsync(realmBase, {
        audience: realmBase + '/admin-api', scope: SCOPE,
        client_id: CLIENT, username: BOSS, sub: BOSS });
    });
    note(!!writer && !!reader && !!client && !!boss,
         'precondition: four access tokens were minted',
         [!!writer, !!reader, !!client, !!boss].join(','));
    const has = function (list, value) {
      return Array.isArray(list) && list.indexOf(value) >= 0;
    };
    const brief = function (r) {
      const j = r.json || {};
      return r.status + ' ' + JSON.stringify({
        caller: j.caller, authority: j.authority, realm: j.realm,
        roles: j.roles, scopes: j.scopes, read: j.read, write: j.write,
        tokenRequired: j.tokenRequired, pages: (j.pages || []).length,
        errors: j.errors });
    };

    // --- 1. Admin Write -----------------------------------------------------
    let r = await call(port, 'GET', '/admin-api/me', writer);
    let j = r.json || {};
    note(r.status === 200 && j.caller && j.caller.kind === 'person' &&
         j.caller.name === WRITER &&
         j.caller.clientId === 'sts-admin-console',
         '1a. Admin Write: the caller is the person the token names, and ' +
         'the client it was issued to', brief(r));
    note(j.authority === 'service' && j.realm === realms.DEFAULT_ID &&
         j.tokenRequired === true && j.mode === 'development' &&
         typeof j.expiresAt === 'number',
         '1b. a default-realm token is the service authority; the mode and ' +
         'the token\'s expiry are reported', brief(r) + ' ' + j.mode + ' ' +
         j.expiresAt);
    note(j.read === true && j.write === true &&
         has(j.roles, 'ADMIN_READ') && has(j.roles, 'ADMIN_WRITE') &&
         has(j.scopes, 'admin:read') && has(j.scopes, 'admin:write'),
         '1c. it holds both roles and may read and write', brief(r));
    note(has(j.pages, SERVICE_PAGE) && has(j.pages, REALM_PAGE),
         '1d. its pages include the service pages', brief(r));
    note(j.console && j.console.available === true &&
         j.console.open === false &&
         j.console.bootstrapPasswordRequired === false,
         '1e. the roster is reported: available, and not open to anybody',
         JSON.stringify(j.console));

    // --- 2. Admin Read ------------------------------------------------------
    r = await call(port, 'GET', '/admin-api/me', reader);
    j = r.json || {};
    note(r.status === 200 && j.read === true && j.write === false &&
         has(j.roles, 'ADMIN_READ') && !has(j.roles, 'ADMIN_WRITE'),
         '2. Admin Read: reads and does not write, though the token ' +
         'carries both scopes', brief(r));

    // --- 3. a role revoked after the token was minted ----------------------
    inDefault(function () {
      rbac.revoke(WRITER, 'write', { via: 'test' });
    });
    r = await call(port, 'GET', '/admin-api/me', writer);
    j = r.json || {};
    note(r.status === 200 && j.read === true && j.write === false,
         '3. Admin Write revoked after the token was minted: the same ' +
         'token no longer writes', brief(r));

    // --- 4. a client_credentials token ---------------------------------------
    r = await call(port, 'GET', '/admin-api/me', client);
    j = r.json || {};
    note(r.status === 200 && j.caller && j.caller.kind === 'application' &&
         j.caller.name === CLIENT && j.read === true && j.write === true &&
         j.authority === 'service' && j.console && j.console.open === false,
         '4. a client_credentials token: the caller is the application, ' +
         'with no roster state of its own', brief(r));

    // --- 5. a realm's own token ----------------------------------------------
    r = await call(port, 'GET', '/realm/' + R + '/admin-api/me', boss);
    j = r.json || {};
    note(r.status === 200 && j.authority === 'realm' && j.realm === R &&
         j.readingRealm === R && j.caller && j.caller.name === BOSS &&
         j.write === true,
         '5a. a realm\'s own token under its prefix: the realm authority, ' +
         'in that realm', brief(r));
    note(has(j.pages, REALM_PAGE) && !has(j.pages, SERVICE_PAGE),
         '5b. and no service page is among its pages', brief(r) + ' ' +
         has(j.pages, SERVICE_PAGE));

    // --- 6. the control ------------------------------------------------------
    config.setOverride('adminApi.authRequired', false);
    r = await call(port, 'GET', '/admin-api/me', '');
    config.clearOverride('adminApi.authRequired');
    j = r.json || {};
    note(r.status === 200 && j.caller === null && j.tokenRequired === false &&
         j.read === true && j.write === true && j.authority === null,
         '6. the control, no token required: no caller, and both read and ' +
         'write', brief(r));

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
  const out = path.join(os.tmpdir(), 'am-' + process.pid + '-' + Date.now() +
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
  name: 'admin_api_me',
  describe: 'GET /admin-api/me answers what the gate decided for the ' +
            'caller: who, which authority, which roles and pages (#446)',
  run: run
};
