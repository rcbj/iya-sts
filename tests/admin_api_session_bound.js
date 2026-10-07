// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/admin_api_session_bound.js
// ===========================================================================
// A MANAGEMENT API TOKEN DIES WITH THE SIGN-ON SESSION IT WAS ISSUED ON
// (#446, 2026-10-05).
//
// The server-rendered console held a session that ended with the sign-on
// session it came from. A console that is a client of `/admin-api` holds a
// token instead, so the API's gate asks the token registry which session the
// token was issued on, and `authn/` whether that session is still live.
//
// In a CHILD PROCESS with the whole stack on an ephemeral port, one person
// holding Admin Write, a real sign-on session, and tokens minted as the
// token endpoint mints them:
//
//   1. a token issued on a live session is accepted;
//   2. the session is ended, as any sign-out ends one, and the same token
//      is refused 401 `invalid_token`, recorded under STS-API-0126;
//   3. a token issued on a SECOND, still live, session of the same person
//      goes on working: it is the session that ended, not the person;
//   4. a token issued on no session at all (the API explorer's, a
//      `client_credentials` one) is not affected by any of it.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'admin_api_session_bound',
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

    const authn = require(ROOT_DIR + '/authn/authn');
    const stamp = String(process.pid);
    const WRITER = 'as-writer-' + stamp;
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
    // A response object for `startSession()`, which sets a cookie on it.
    const fakeRes = function () {
      const out = {};
      out.set = function () { return out; };
      out.append = function () { return out; };
      return out;
    };
    const signOn = function () {
      return inDefault(function () {
        return authn.startSession(fakeRes(), WRITER, ['pwd'], '1',
                                  'password', {});
      });
    };
    const mint = async function (sessionId) {
      const token = await inDefault(function () {
        return oauth2.accessTokenAsync(base, Object.assign({
          audience: base + '/admin-api', scope: 'admin:read admin:write',
          client_id: 'sts-admin-console', username: WRITER, sub: WRITER,
          jkt: DPOP.jkt },
          sessionId ? { session_id: sessionId } : {}));
      });
      BOUND[token] = true;
      return token;
    };
    const coded = function (code) {
      return audit.list().filter(function (event) {
        return event.errorCode === code;
      }).length;
    };
    const ME = '/admin-api/me';

    const first = signOn();
    const second = signOn();
    note(!!first && !!second && first.id !== second.id,
         'precondition: two sign-on sessions of one person',
         JSON.stringify([first && first.id, second && second.id]));
    const onFirst = await mint(first && first.id);
    const onSecond = await mint(second && second.id);
    const onNone = await mint('');

    // --- 1. a live session ---------------------------------------------------
    let r = await call(port, 'GET', ME, onFirst);
    note(r.status === 200 && r.json && r.json.caller &&
         r.json.caller.name === WRITER,
         '1. a token issued on a live session is accepted',
         r.status + ' ' + r.text.slice(0, 160));

    // --- 2. the session ends -------------------------------------------------
    const ended = inDefault(function () {
      return authn.endSessionById(first.id, 'a test signing out', 'admin');
    });
    const before = coded('STS-API-0126');
    r = await call(port, 'GET', ME, onFirst);
    await settle();
    note(!!ended && r.status === 401 && r.json &&
         r.json.error === 'invalid_token' &&
         coded('STS-API-0126') === before + 1,
         '2a. the session ended: the same token is refused 401 ' +
         'invalid_token, recorded under STS-API-0126',
         !!ended + ' ' + r.status + ' ' + r.text.slice(0, 200));
    note(r.text.indexOf('STS-API-') < 0,
         '2b. and the refusal carries no error code on the wire',
         r.text.slice(0, 200));

    // --- 3. the person's other session ---------------------------------------
    r = await call(port, 'GET', ME, onSecond);
    note(r.status === 200,
         '3. a token issued on the person\'s other, live, session goes on ' +
         'working', r.status + ' ' + r.text.slice(0, 160));

    // --- 4. no session at all ------------------------------------------------
    r = await call(port, 'GET', ME, onNone);
    note(r.status === 200,
         '4. a token issued on no session is not affected',
         r.status + ' ' + r.text.slice(0, 160));

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
  const out = path.join(os.tmpdir(), 'as-' + process.pid + '-' + Date.now() +
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
  name: 'admin_api_session_bound',
  describe: 'a management API token stops working when the sign-on ' +
            'session it was issued on ends (#446)',
  run: run
};
