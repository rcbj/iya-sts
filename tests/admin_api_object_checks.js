// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/admin_api_object_checks.js
// ===========================================================================
// THE MANAGEMENT API'S OBJECT CHECK, ASKED OF EVERY OPERATION (#1451, ASVS
// 5.0.0 8.2.2). The gate is one function in front of every route, so the check
// walks the route table rather than sampling it:
//
//   1. A token without the operation's scope is refused, on every operation.
//   2. A token of one realm is refused at another realm's address, and at the
//      default realm's, on every operation.
//   3. An object in a realm is visible to that realm's administrator and
//      absent from another realm's.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'admin_api_object_checks',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

/**
 * The child process: builds the stack, listens, and asks.
 *
 * @returns {void}
 */
function childMain() {
  const ROOT_DIR = process.env.OC_ROOT;
  const OUT = process.env.OC_OUT;
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
    const realms = require(ROOT_DIR + '/common/realms');
    const rbac = require(ROOT_DIR + '/admin-ui/admin_rbac');
    const ldap = require(ROOT_DIR + '/ldap/ldap_server');
    const oauth2 = require(ROOT_DIR + '/oauth-oidc/oauth2');
    const api = require(ROOT_DIR + '/mgmt-api/admin_api');

    const server = http.createServer(app);
    await new Promise(function (r) {
      server.listen(0, '127.0.0.1', r);
    });
    const port = server.address().port;
    const base = 'http://127.0.0.1:' + port;
    const call = function (method, target, token, body) {
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
        const req = http.request({ host: '127.0.0.1', port: port, agent: false,
          path: target, method: method, headers: headers }, function (res) {
          let raw = '';
          res.on('data', function (d) {
            raw += d;
          });
          res.on('end', function () {
            let json = null;
            try {
              json = JSON.parse(raw);
            } catch (e) {
              // Not JSON: the finding reports the status.
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
    };

    const stamp = String(process.pid);
    const A = 'oca' + stamp;
    const B = 'ocb' + stamp;
    const CLIENT = 'sts-api-client';
    realms.create({ id: A, name: 'Object checks A' });
    realms.create({ id: B, name: 'Object checks B' });
    const tokenIn = function (realm, who, scope) {
      const at = base + '/realm/' + realm;
      return realms.run(realms.get(realm), function () {
        return oauth2.accessTokenAsync(at, { audience: at + '/admin-api',
          scope: scope, client_id: CLIENT, username: who, sub: who });
      });
    };
    const ADMIN_A = 'oc-admin-a-' + stamp;
    const ADMIN_B = 'oc-admin-b-' + stamp;
    rbac.grant(ADMIN_A, 'write', { via: 'test', realm: A });
    rbac.grant(ADMIN_B, 'write', { via: 'test', realm: B });
    const full = 'admin:read admin:write admin:security admin:console';
    const adminA = await tokenIn(A, ADMIN_A, full);
    const adminB = await tokenIn(B, ADMIN_B, full);
    const noScope = await tokenIn(A, ADMIN_A, 'openid');

    // Every operation, a person's own path and action alike.
    const operations = [];
    api.ROUTES.forEach(function (entry) {
      const route = String(entry.route || entry.path || '');
      const concrete = route.replace(/:[A-Za-z_]+/g, 'probe')
        .replace(/\(.*?\)/g, '');
      if (entry.method) {
        operations.push({ method: entry.method.toUpperCase(), path: concrete });
      }
      (entry.actions || []).forEach(function (one) {
        operations.push({ method: 'POST',
                          path: concrete + '/' + one.action, body: {} });
      });
    });
    note(operations.length > 200, 'the route table was read',
         String(operations.length));

    const open = [];
    const noScopePassed = [];
    const crossedRealm = [];
    const crossedDefault = [];
    let gated = 0;
    for (let i = 0; i < operations.length; i++) {
      const one = operations[i];
      const at = '/realm/' + A + one.path;
      const anonymous = await call(one.method, at, null, one.body);
      if (anonymous.status !== 401) {
        open.push(one.method + ' ' + one.path + ' ' + anonymous.status);
        continue;
      }
      gated += 1;
      const lacking = await call(one.method, at, noScope, one.body);
      if (lacking.status !== 403) {
        noScopePassed.push(one.method + ' ' + one.path + ' ' + lacking.status);
      }
      const foreign = await call(one.method, '/realm/' + B + one.path, adminA,
                                 one.body);
      if (foreign.status !== 401 && foreign.status !== 403) {
        crossedRealm.push(one.method + ' ' + one.path + ' ' + foreign.status);
      }
      const dflt = await call(one.method, one.path, adminA, one.body);
      if (dflt.status !== 401 && dflt.status !== 403) {
        crossedDefault.push(one.method + ' ' + one.path + ' ' + dflt.status);
      }
    }
    note(gated > 200, 'nearly every operation requires a token',
         gated + ' gated; open: ' + open.slice(0, 12).join(', '));
    note(noScopePassed.length === 0,
         'a token without the scope is refused on every operation',
         noScopePassed.slice(0, 12).join(', '));
    note(crossedRealm.length === 0,
         'a realm\'s token is refused at another realm, on every operation',
         crossedRealm.slice(0, 12).join(', '));
    note(crossedDefault.length === 0,
         'and at the default realm, on every operation',
         crossedDefault.slice(0, 12).join(', '));

    // --- an object in one realm ---------------------------------------------
    const PERSON = 'oc-only-in-a-' + stamp;
    realms.run(realms.get(A), function () {
      ldap.createUser(PERSON, { invent: false });
    });
    const inA = await call('GET', '/realm/' + A + '/admin-api/users', adminA);
    note(inA.status === 200 && inA.text.indexOf(PERSON) >= 0,
         'a realm\'s administrator sees that realm\'s person',
         inA.status + ' ' + inA.text.slice(0, 160));
    const inB = await call('GET', '/realm/' + B + '/admin-api/users', adminB);
    note(inB.status === 200 && inB.text.indexOf(PERSON) < 0,
         'another realm\'s administrator does not', inB.status);

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
  const out = path.join(os.tmpdir(), 'oc-' + process.pid + '-' + Date.now() +
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
                                  OC_ROOT: ROOT, OC_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
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
  name: 'admin_api_object_checks',
  describe: 'every management API operation refuses a token without its ' +
            'scope and a token of another realm (ASVS 5.0.0 8.2.2)',
  run: run
};
