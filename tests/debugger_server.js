'use strict';
//
// File: debugger_server.js
//
// ===========================================================================
// THE EMBEDDED DEBUGGER'S GATE, DRIVEN OVER HTTP IN PROCESS (2026-09-13).
//
// `debugger/debugger_server.js` builds an express app of its own, which the
// service binds on `debugger.port`. This file binds the same app on an
// ephemeral port and asks it the questions the gate exists to answer:
//
//   A. a browser with no session is sent to THIS service's authorization
//      endpoint as `sts-debugger-ui`, with its callback on the debugger's
//      origin; an api caller with none gets 401 and a Bearer challenge;
//   B. the four landing paths are not gated — a SAML response POSTed to
//      `/api/samlacs` reaches the forwarder — and the api paths beside them
//      are;
//   C. a bearer token is refused for each of its failures (typ, audience,
//      permission, expiry) and for a subject who holds no console role even
//      when the token carries the permission — a role revoked after a token
//      was minted;
//   D. an administrator's token opens the static site, with the service's own
//      base substituted for the placeholder, and a path outside the site or a
//      method other than GET is refused;
//   E. `/api/*` is forwarded with the prefix STRIPPED, Cookie and
//      Authorization DROPPED, `X-Forwarded-Prefix: /api` added, and a
//      `Location` naming the child's configured origin rewritten to the one
//      the request arrived at.
//
// WHY IN PROCESS: the parent suite runs against stacks with no debugger in
// them, and D and E need a built site and an api process this file can stand
// in for with a directory and a unix socket.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');

const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-dbg-test-'));
const uiDir = path.join(scratch, 'ui');
fs.mkdirSync(uiDir);
fs.writeFileSync(path.join(uiDir, 'index.html'),
                 '<html><body>STS=__STS_EMBED_STS_URL__</body></html>');
fs.writeFileSync(path.join(uiDir, 'app.js'),
                 'var sts = "__STS_EMBED_STS_URL__" + "/scim/v2";');
fs.writeFileSync(path.join(scratch, 'secret.txt'), 'outside the site');
process.env.STS_DEBUGGER_UI_DIRECTORY = uiDir;

const config = require('../common/config');
const realms = require('../common/realms');
const helpers = require('../common/helpers');
require('../ldap/ldap_server');
const adminRbac = require('../admin-ui/admin_rbac');
const access = require('../debugger/debugger_access');
const apiProcess = require('../debugger/debugger_api_process');
const debuggerServer = require('../debugger/debugger_server');

const log = require('bunyan').createLogger({ name: 'debugger_server',
  level: process.env.LOG_LEVEL || 'info' });

function request(port, options, body) {
  log.debug("Entering request().");
  log.debug("Leaving request().");
  return new Promise(function (resolve, reject) {
    const req = http.request(Object.assign({ host: '127.0.0.1', port: port },
                                           options),
      function (res) {
        let text = '';
        res.setEncoding('utf8');
        res.on('data', function (chunk) {
          text += chunk;
        });
        res.on('end', function () {
          resolve({ status: res.statusCode, headers: res.headers,
                    body: text });
        });
      });
    req.on('error', reject);
    if (body) {
      req.write(body);
    }
    req.end();
  });
}

function inDefault(fn) {
  log.debug("Entering inDefault().");
  log.debug("Leaving inDefault().");
  return realms.run(realms.get(realms.DEFAULT_ID), fn);
}

// An access token signed with the default realm's key, shaped as the
// authorization server shapes one, with whatever this test wants wrong.
function tokenFor(port, overrides, header) {
  log.debug("Entering tokenFor().");
  const now = Math.floor(Date.now() / 1000);
  const payload = Object.assign({
    iss: debuggerServer.authorizationBaseOf({
      headers: { host: '127.0.0.1:' + port } }),
    sub: 'alice', username: 'alice', aud: access.PERMISSION_BASE,
    scope: access.PERMISSION_NAME, iat: now, exp: now + 300,
    jti: 'test-' + Math.random().toString(36).slice(2)
  }, overrides || {});
  log.debug("Leaving tokenFor().");
  return inDefault(function () {
    return helpers.signJwt(payload, null,
                           { header: header || { typ: 'at+jwt' } });
  });
}

async function run(t) {
  log.debug("Entering run().");
  const server = http.createServer(debuggerServer.app);
  await new Promise(function (resolve) {
    server.listen(0, '127.0.0.1', resolve);
  });
  const port = server.address().port;
  const host = '127.0.0.1:' + port;
  // A stand-in api process on a unix socket, echoing what reached it.
  const socketFile = path.join(scratch, 'api.sock');
  const seen = [];
  const fakeApi = http.createServer(function (req, res) {
    seen.push({ method: req.method, url: req.url, headers: req.headers });
    if (req.url === '/samlacs') {
      res.writeHead(303, { Location: 'http://child.invalid:1/saml.html' });
      res.end();
      return;
    }
    res.writeHead(200, { 'Content-Type': 'application/json',
                         'Set-Cookie': 'child=1' });
    res.end(JSON.stringify({ ok: true }));
  });
  await new Promise(function (resolve) {
    fakeApi.listen(socketFile, resolve);
  });
  const saved = { ready: apiProcess.ready, socketPath: apiProcess.socketPath,
                  status: apiProcess.status };
  let granted = false;
  try {
    config.setOverride('admin.openWhenEmpty', 'false');
    // -----------------------------------------------------------------------
    t.log.info('=== A. no session ===');
    const home = await request(port, { method: 'GET', path: '/somepage.html',
                                       headers: { host: host,
                                                  accept: 'text/html' } });
    t.equal(home.status, 303, 'a browser with no session is redirected');
    const to = String(home.headers.location || '');
    t.check(to.indexOf(debuggerServer.authorizationBaseOf({
              headers: { host: host } }) + '/oauth2/authorize?') === 0,
            'to THIS service\'s authorization endpoint on its main port',
            to.slice(0, 100));
    t.check(to.indexOf('client_id=' + access.UI_CLIENT_ID) > 0 &&
            to.indexOf(encodeURIComponent('http://' + host +
                                          '/_sts/callback')) > 0 &&
            to.indexOf(encodeURIComponent(access.PERMISSION_ID)) > 0,
            'as the debugger client, back to the debugger origin\'s ' +
            'callback, asking for the permission', to);
    t.check(/frame-ancestors 'none'/.test(
              String(home.headers['content-security-policy'])),
            'and every answer carries frame-ancestors \'none\'');
    const anon = await request(port, { method: 'GET', path: '/api/healthcheck',
                                       headers: { host: host } });
    t.equal(anon.status, 401, 'an api call with no credential is 401');
    t.check(/^Bearer /.test(String(anon.headers['www-authenticate'])),
            'with a Bearer challenge naming the permission',
            anon.headers['www-authenticate']);
    t.check(anon.body.indexOf('STS-DBG') < 0,
            'and no error code in what the client reads');

    // -----------------------------------------------------------------------
    t.log.info('=== B. landing paths ===');
    apiProcess.ready = function () {
      return false;
    };
    const landing = await request(port, { method: 'POST', path: '/api/samlacs',
      headers: { host: host,
                 'content-type': 'application/x-www-form-urlencoded' } },
      'SAMLResponse=abc');
    t.equal(landing.status, 502,
            'a SAML response POSTed to /api/samlacs with no credential is ' +
            'NOT refused by the gate — it reaches the forwarder, which says ' +
            'the api is not running');
    const stashed = await request(port, { method: 'GET',
                                          path: '/api/samlresponse?id=1',
                                          headers: { host: host } });
    t.equal(stashed.status, 401,
            'while reading what was stashed IS gated');
    const cb = await request(port, { method: 'GET',
                                     path: '/callback?code=c1&state=s1',
                                     headers: { host: host } });
    t.check(cb.status === 303 && cb.headers.location ===
            'http://' + host + '/oauth2_oidc_2.html?code=c1&state=s1',
            'the OAuth landing forwards a GET to the results page on this ' +
            'origin', JSON.stringify(cb.headers.location));
    const posted = await request(port, { method: 'POST', path: '/callback',
      headers: { host: host,
                 'content-type': 'application/x-www-form-urlencoded' } },
      'code=c2&state=s%262');
    t.equal(posted.headers.location,
            'http://' + host + '/oauth2_oidc_2.html#code=c2&state=s%262',
            'and a form_post in the fragment, re-encoded');

    // -----------------------------------------------------------------------
    t.log.info('=== C. bearer refusals ===');
    // THE EMPTY ROSTER, with the console's rule on: a token carrying the
    // permission for somebody the console would let in is still refused,
    // because nobody is a member of either group yet.
    config.setOverride('admin.openWhenEmpty', 'true');
    try {
      const open = await request(port, { method: 'GET', path: '/index.html',
        headers: { host: host, authorization: 'Bearer ' + tokenFor(port, {}),
                   accept: 'application/json' } });
      t.equal(open.status, 403,
              'while neither console role group has a member the debugger ' +
              'refuses everybody, although the console is open to them');
    } finally {
      config.setOverride('admin.openWhenEmpty', 'false');
    }
    const grant = inDefault(function () {
      return adminRbac.grant('alice', 'read', { via: 'test', actor: 'test' });
    });
    granted = !grant || grant.ok !== false;
    t.check(granted, 'alice is a console administrator', JSON.stringify(grant));
    async function asked(token, what) {
      log.debug("Entering asked().");
      const answer = await request(port, { method: 'GET', path: '/index.html',
        headers: { host: host, authorization: 'Bearer ' + token,
                   accept: 'application/json' } });
      log.debug("Leaving asked(). " + what);
      return answer;
    }
    const idToken = await asked(tokenFor(port, {}, { typ: 'JWT' }), 'typ');
    t.equal(idToken.status, 401, 'a token whose typ is not at+jwt is refused');
    const elsewhere = await asked(tokenFor(port,
                                           { aud: 'https://other.example/' }),
                                  'aud');
    t.equal(elsewhere.status, 403, 'a token for another audience is refused');
    const noScope = await asked(tokenFor(port, { scope: 'openid' }), 'scope');
    t.equal(noScope.status, 403,
            'a token without the debugger permission is refused');
    const expired = await asked(tokenFor(port, { exp: 1000, iat: 900 }),
                                'exp');
    t.equal(expired.status, 401, 'an expired token is refused');
    const bob = await asked(tokenFor(port, { sub: 'bob', username: 'bob' }),
                            'bob');
    t.equal(bob.status, 403,
            'a token CARRYING the permission for somebody holding no console ' +
            'role is refused — the gate asks again, so a revoked role stops ' +
            'working before the token runs out');
    const forged = await asked(tokenFor(port, {}).slice(0, -4) + 'AAAA',
                               'signature');
    t.equal(forged.status, 401, 'a token whose signature fails is refused');

    // -----------------------------------------------------------------------
    t.log.info('=== D. the static site ===');
    const good = tokenFor(port, {});
    const page = await request(port, { method: 'GET', path: '/',
      headers: { host: host, authorization: 'Bearer ' + good } });
    const base = debuggerServer.authorizationBaseOf({ headers: { host: host } });
    t.equal(page.status, 200, 'an administrator\'s token opens the site');
    t.equal(page.body, '<html><body>STS=' + base + '</body></html>',
            'with this service\'s own base put where the placeholder was');
    const script = await request(port, { method: 'GET', path: '/app.js',
      headers: { host: host, authorization: 'Bearer ' + good } });
    t.check(script.body.indexOf(base) > 0 &&
            script.body.indexOf('__STS_EMBED') < 0 &&
            /javascript/.test(String(script.headers['content-type'])),
            'in a bundle too', script.body);
    const outside = await request(port, { method: 'GET',
      path: '/%2e%2e/secret.txt',
      headers: { host: host, authorization: 'Bearer ' + good } });
    t.check(outside.status === 404 && outside.body.indexOf('outside') < 0,
            'a path that climbs out of the site is not served',
            String(outside.status));
    const put = await request(port, { method: 'PUT', path: '/index.html',
      headers: { host: host, authorization: 'Bearer ' + good } });
    t.equal(put.status, 405, 'and the site is read with GET only');

    // -----------------------------------------------------------------------
    t.log.info('=== E. forwarding ===');
    apiProcess.ready = function () {
      return true;
    };
    apiProcess.socketPath = function () {
      return socketFile;
    };
    apiProcess.status = function () {
      return { state: 'running', uiUrl: 'http://child.invalid:1',
               allowList: false, allowedRanges: [] };
    };
    const fwd = await request(port, { method: 'GET',
      path: '/api/ssf/limits?x=1',
      headers: { host: host, authorization: 'Bearer ' + good,
                 cookie: 'sts_debugger=abc; sts_mock_session=def' } });
    const last = seen[seen.length - 1] || { headers: {} };
    t.equal(fwd.status, 200, 'an administrator\'s api call is forwarded');
    t.equal(last.url, '/ssf/limits?x=1', 'with the /api prefix stripped');
    t.check(!last.headers.cookie && !last.headers.authorization,
            'and with NO cookie and NO authorization reaching the api',
            JSON.stringify(Object.keys(last.headers)));
    t.check(last.headers['x-forwarded-prefix'] === '/api' &&
            last.headers['x-forwarded-host'] === host,
            'but the forwarded prefix and host it builds addresses from',
            JSON.stringify(last.headers));
    t.check(!fwd.headers['set-cookie'],
            'and the api cannot set a cookie on the debugger origin');
    const back = await request(port, { method: 'POST', path: '/api/samlacs',
      headers: { host: host,
                 'content-type': 'application/x-www-form-urlencoded' } },
      'SAMLResponse=abc');
    t.equal(back.headers.location, 'http://' + host + '/saml.html',
            'a Location naming the child\'s configured origin is rewritten ' +
            'to the one the browser is using');
  } finally {
    apiProcess.ready = saved.ready;
    apiProcess.socketPath = saved.socketPath;
    apiProcess.status = saved.status;
    config.clearOverride('admin.openWhenEmpty');
    if (granted) {
      inDefault(function () {
        adminRbac.revoke('alice', 'read', { via: 'test', actor: 'test' });
      });
    }
    await new Promise(function (resolve) {
      server.close(resolve);
    });
    await new Promise(function (resolve) {
      fakeApi.close(resolve);
    });
    fs.rmSync(scratch, { recursive: true, force: true });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'debugger_server',
  describe: 'the embedded debugger\'s gate: sign-in redirect, ungated ' +
            'landings, bearer refusals including a revoked role, the ' +
            'substituted static site and the forwarder\'s header hygiene',
  run: run
};
