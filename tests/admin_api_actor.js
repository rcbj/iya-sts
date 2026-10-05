// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/admin_api_actor.js
// ===========================================================================
// THE AUDIT ACTOR OF A MANAGEMENT API CALL IS THE SUBJECT OF ITS ACCESS TOKEN
// (#446, 2026-10-05).
//
// Until #446 every row `/admin-api` wrote named nobody: the API authenticated
// clients, so its handlers passed an empty actor, the HTTP row asked the
// sign-on cookie's resolver (which a token caller has none of), and an action
// that reads `body.actor` found none, because an operation's schema refuses
// a member it does not define. The console is becoming a client of this API
// that presents the signed-in person's own token, so the subject the gate
// verifies is who did it.
//
// In a CHILD PROCESS with the whole stack on an ephemeral port, one person
// holding Admin Write, and two tokens minted as the token endpoint mints
// them — the person's, issued to `sts-admin-console`, and a
// `client_credentials` one for `sts-management-api`:
//
//   1. a read with the person's token: the HTTP row names the person;
//   2. a write whose action reads `body.actor` (a group create): the HTTP
//      row and the action's own row name the person; and the same write sent
//      with an `actor` of the caller's choosing is refused by the operation's
//      schema, so no row names it;
//   3. the same write with the client's token names the client;
//   4. a write whose action takes the actor as an argument (a role grant):
//      its row names the person;
//   5. the control, development with `adminApi.authRequired` off and no
//      token: nobody is named, on the HTTP row or on the action's own.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'admin_api_actor',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT_DIR = process.env.AG_ROOT;
  // The console's DPoP key, and the tokens minted bound to it (#446).
  // Made when first used, once the stack is built: requiring the key's
  // modules first would build their instances before the composition root.
  let dpopKit = null;
  const DPOP = {
    get jkt() {
      dpopKit = dpopKit || require(ROOT_DIR + '/tests/tools/console_dpop')
        .consoleDpop(ROOT_DIR);
      return dpopKit.jkt;
    },
    headers: function (method, url, token) {
      dpopKit = dpopKit || require(ROOT_DIR + '/tests/tools/console_dpop')
        .consoleDpop(ROOT_DIR);
      return dpopKit.headers(method, url, token);
    }
  };
  const BOUND = {};
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
      // A CONSOLE token is DPoP-bound since the cutover (#446) and goes
      // with its proof; any other is a Bearer token as it always was.
      if (token && BOUND[token]) {
        Object.assign(headers, DPOP.headers(method, 'http://127.0.0.1:' +
                                            port + urlPath.split('?')[0],
                                            token));
      } else if (token) {
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
    const WRITER = 'aa-writer-' + stamp;
    const OTHER = 'aa-other-' + stamp;
    const FALSE_NAME = 'aa-named-by-the-caller-' + stamp;
    const CLIENT = 'sts-management-api';
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
    const base = 'http://127.0.0.1:' + port;
    const mint = async function (claims) {
      const bound = claims.client_id === 'sts-admin-console';
      const token = await inDefault(function () {
        return oauth2.accessTokenAsync(base, Object.assign(bound
          ? { jkt: DPOP.jkt } : {}, {
          audience: base + '/admin-api', scope: 'admin:read admin:write'
        }, claims));
      });
      if (bound) {
        BOUND[token] = true;
      }
      return token;
    };
    const person = await mint({ client_id: 'sts-admin-console',
                                username: WRITER, sub: WRITER });
    const client = await mint({ client_id: CLIENT, sub: CLIENT });
    note(!!person && !!client, 'precondition: two access tokens were minted',
         [!!person, !!client].join(','));

    // The rows that mention `text` anywhere, newest first.
    const rowsAbout = function (text) {
      return audit.list().filter(function (event) {
        return JSON.stringify(event).indexOf(text) >= 0;
      });
    };
    const httpRow = function (action, target) {
      return audit.list().filter(function (event) {
        return event.action === action && event.target === target;
      })[0] || null;
    };
    const isHttp = function (event) {
      return /^api\./.test(String(event.action || ''));
    };
    const actorsOf = function (rows) {
      return rows.map(function (event) {
        return event.action + '=' + JSON.stringify(event.actor || '');
      }).join(' ');
    };

    // --- 1. a read ---------------------------------------------------------
    let r = await call(port, 'GET', '/admin-api/config', person);
    await settle();
    let row = httpRow('api.read', '/admin-api/config');
    note(r.status === 200 && !!row && row.actor === WRITER,
         '1. a read with the person\'s token: the HTTP row names the person',
         r.status + ' ' + JSON.stringify(row && row.actor));

    // --- 2. a write whose action reads body.actor ---------------------------
    const G1 = 'aa-g1-' + stamp;
    r = await call(port, 'POST', '/admin-api/groups/create', person,
                   { group: G1 });
    await settle();
    row = httpRow('api.change', '/admin-api/groups/create');
    let own = rowsAbout(G1).filter(function (e) { return !isHttp(e); });
    note(r.status === 200 && !!row && row.actor === WRITER,
         '2a. a group create with the person\'s token: the HTTP row names ' +
         'the person', r.status + ' ' + r.text.slice(0, 120) + ' ' +
         JSON.stringify(row && row.actor));
    note(own.some(function (e) { return e.actor === WRITER; }),
         '2b. and the action\'s own row names the person', actorsOf(own));
    r = await call(port, 'POST', '/admin-api/groups/create', person,
                   { group: 'aa-g1b-' + stamp, actor: FALSE_NAME });
    await settle();
    note(r.status === 400 && rowsAbout(FALSE_NAME).length === 0,
         '2c. an actor of the caller\'s choosing is refused by the schema, ' +
         'and no row names it', r.status + ' ' +
         actorsOf(rowsAbout(FALSE_NAME)));

    // --- 3. the client's token ----------------------------------------------
    const G2 = 'aa-g2-' + stamp;
    r = await call(port, 'POST', '/admin-api/groups/create', client,
                   { group: G2 });
    await settle();
    row = httpRow('api.change', '/admin-api/groups/create');
    own = rowsAbout(G2).filter(function (e) { return !isHttp(e); });
    note(r.status === 200 && !!row && row.actor === CLIENT &&
         own.some(function (e) { return e.actor === CLIENT; }),
         '3. the same write with a client_credentials token names the ' +
         'client on both rows', r.status + ' ' + r.text.slice(0, 120) + ' ' +
         JSON.stringify(row && row.actor) + ' ' + actorsOf(own));

    // --- 4. an action handed its actor --------------------------------------
    r = await call(port, 'POST', '/admin-api/rbac/grant', person,
                   { username: OTHER, role: 'read' });
    await settle();
    own = rowsAbout(OTHER).filter(function (e) { return !isHttp(e); });
    note(r.status === 200 &&
         own.some(function (e) { return e.actor === WRITER; }),
         '4. a role grant with the person\'s token: its row names the ' +
         'person', r.status + ' ' + r.text.slice(0, 120) + ' ' +
         actorsOf(own));

    // --- 5. the control: no token, development's open API --------------------
    config.setOverride('adminApi.authRequired', false);
    const G3 = 'aa-g3-' + stamp;
    r = await call(port, 'POST', '/admin-api/groups/create', '',
                   { group: G3 });
    await settle();
    config.clearOverride('adminApi.authRequired');
    row = httpRow('api.change', '/admin-api/groups/create');
    own = rowsAbout(G3).filter(function (e) { return !isHttp(e); });
    note(r.status === 200 && !!row && !row.actor,
         '5a. the control, no token: the HTTP row names nobody',
         r.status + ' ' + JSON.stringify(row && row.actor));
    note(own.length > 0 && own.every(function (e) { return !e.actor; }),
         '5b. and the action\'s own row names nobody either',
         actorsOf(own));

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
  const out = path.join(os.tmpdir(), 'aa-' + process.pid + '-' + Date.now() +
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
  name: 'admin_api_actor',
  describe: 'the audit actor of a management API call is the subject of ' +
            'its access token, never what the caller names (#446)',
  run: run
};
