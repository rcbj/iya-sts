// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: debugger_server.js
//
// ===========================================================================
// THE EMBEDDED DEBUGGER'S GATE, DRIVEN OVER HTTP IN PROCESS (2026-09-13).
//
// `debugger/debugger_server.ts` builds an express app of its own, which the
// service binds on `debugger.port`. This file binds the same app on an
// ephemeral port and asks it the questions the gate exists to answer:
//
//   A. a browser with no session is sent to THIS service's authorization
//      endpoint as `sts-debugger-ui`, with its callback on the debugger's
//      origin and no debugger api permission asked for; an api caller with
//      none gets 401 and NO challenge — and an access token on
//      `Authorization`, even one shaped exactly as the retired permission's
//      was, opens nothing (#1717): the gate does not read that header;
//   B. the four landing paths are not gated — a SAML response POSTed to
//      `/api/samlacs` reaches the forwarder — and the api paths beside them
//      are;
//   C. a session is refused while the roster is empty, for a person holding
//      no console role, and the moment a role is revoked from somebody already
//      signed in — the gate asks on every request;
//   D. an administrator's session opens the static site, with the service's
//      own base substituted for the placeholder, and a path outside the site
//      or a method other than GET is refused;
//   E. `/api/*` is forwarded with the prefix STRIPPED, Cookie DROPPED,
//      `Authorization` and `DPoP` passed through UNTOUCHED (#1717 — they are
//      the debugger's own), `X-Forwarded-Prefix: /api` added, and a `Location`
//      naming the child's configured origin rewritten to the one the request
//      arrived at.
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
const authn = require('../authn/authn');
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
// authorization server shaped one for the RETIRED debugger api permission —
// which the gate accepted on `Authorization` until #1717 and must now ignore.
function retiredToken(port) {
  log.debug("Entering retiredToken().");
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: debuggerServer.authorizationBaseOf({
      headers: { host: '127.0.0.1:' + port } }),
    sub: 'alice', username: 'alice', aud: 'urn:sts:debugger-api:',
    scope: 'debugger', iat: now, exp: now + 300,
    jti: 'test-' + require('crypto').randomBytes(8).toString('hex')
  };
  log.debug("Leaving retiredToken().");
  return inDefault(function () {
    return helpers.signJwt(payload, null, { header: { typ: 'at+jwt' } });
  });
}

// The debugger surface's relying-party session for `username`, as the code
// flow's callback makes one, and the `name=value` pair of the cookie it set.
function sessionCookieFor(username) {
  log.debug("Entering sessionCookieFor().");
  const headers = [];
  const res = {
    getHeader: function () {
      log.debug("Entering getHeader().");
      log.debug("Leaving getHeader().");
      return headers.slice();
    },
    setHeader: function (name, value) {
      log.debug("Entering setHeader().");
      headers.length = 0;
      [].concat(value).forEach(function (v) {
        headers.push(v);
      });
      log.debug("Leaving setHeader().");
    },
    req: null
  };
  inDefault(function () {
    return authn.startRelyingPartySession({
      res: res, username: username, claims: {}, via: 'Protocol debugger',
      surface: 'debugger', label: 'Protocol debugger',
      clientId: access.UI_CLIENT_ID, cookie: 'sts_debugger'
    });
  });
  const line = headers.filter(function (one) {
    return /sts_debugger=/.test(String(one));
  })[0] || headers[0] || '';
  log.debug("Leaving sessionCookieFor().");
  return String(line).split(';')[0];
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
                                          '/_sts/callback')) > 0,
            'as the debugger client, back to the debugger origin\'s ' +
            'callback', to);
    t.check(to.indexOf('debugger-api') < 0,
            'asking for no separate debugger api permission — the UI and ' +
            'its api are one client (#1717)', to);
    t.check(/frame-ancestors 'none'/.test(
              String(home.headers['content-security-policy'])),
            'and every answer carries frame-ancestors \'none\'');
    const anon = await request(port, { method: 'GET', path: '/api/healthcheck',
                                       headers: { host: host } });
    t.equal(anon.status, 401, 'an api call with no session is 401');
    t.check(!anon.headers['www-authenticate'],
            'with NO challenge: there is no scheme a caller could answer',
            anon.headers['www-authenticate']);
    t.check(anon.body.indexOf('STS-DBG') < 0,
            'and no error code in what the client reads');
    // THE INTERFERENCE #1717 REMOVED: the gate used to take this header as
    // its own credential. An administrator's token in the retired shape,
    // which it would have accepted, now opens nothing — and neither does a
    // Basic header, which it used to refuse as a malformed token.
    const granted0 = inDefault(function () {
      return adminRbac.grant('alice', 'read', { via: 'test', actor: 'test' });
    });
    granted = !granted0 || granted0.ok !== false;
    const viaHeader = await request(port, { method: 'GET',
      path: '/api/healthcheck',
      headers: { host: host, accept: 'application/json',
                 authorization: 'Bearer ' + retiredToken(port) } });
    t.equal(viaHeader.status, 401,
            'an access token on Authorization opens nothing — even one an ' +
            'administrator was issued for the retired permission');
    const viaBasic = await request(port, { method: 'GET',
      path: '/api/healthcheck',
      headers: { host: host, accept: 'application/json',
                 authorization: 'Basic ' +
                   Buffer.from('client:secret').toString('base64') } });
    t.equal(viaBasic.status, 401,
            'and a Basic header is not read either: 401 for want of a ' +
            'session, the same answer as no header at all');

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
    t.log.info('=== C. session refusals ===');
    const aliceCookie = sessionCookieFor('alice');
    t.check(/^[^=]+=.+/.test(aliceCookie), 'alice has a debugger session',
            aliceCookie);
    async function asked(cookie, what) {
      log.debug("Entering asked().");
      const answer = await request(port, { method: 'GET', path: '/index.html',
        headers: { host: host, cookie: cookie, accept: 'application/json' } });
      log.debug("Leaving asked(). " + what);
      return answer;
    }
    // THE EMPTY ROSTER, with the console's rule on: nobody is a member of
    // either group, so the console is open to everybody and the debugger is
    // still shut.
    if (granted) {
      inDefault(function () {
        adminRbac.revoke('alice', 'read', { via: 'test', actor: 'test' });
      });
      granted = false;
    }
    config.setOverride('admin.openWhenEmpty', 'true');
    try {
      const open = await asked(aliceCookie, 'empty roster');
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
    const allowed = await asked(aliceCookie, 'alice');
    t.equal(allowed.status, 200, 'and her session opens the debugger');
    const bobCookie = sessionCookieFor('bob');
    const bob = await asked(bobCookie, 'bob');
    t.equal(bob.status, 403,
            'a session for somebody holding no console role is refused');
    const bobPage = await request(port, { method: 'GET', path: '/index.html',
      headers: { host: host, cookie: bobCookie, accept: 'text/html' } });
    t.check(bobPage.status === 403 &&
            bobPage.body.indexOf('for administrators') >= 0 &&
            bobPage.body.indexOf('Sign out') >= 0,
            'drawn as a page that says so, with a way to sign out',
            String(bobPage.status));
    inDefault(function () {
      adminRbac.revoke('alice', 'read', { via: 'test', actor: 'test' });
    });
    const revoked = await asked(aliceCookie, 'revoked');
    t.equal(revoked.status, 403,
            'a role revoked from somebody ALREADY signed in stops working ' +
            'at their next request — the gate asks every time');
    const regrant = inDefault(function () {
      return adminRbac.grant('alice', 'read', { via: 'test', actor: 'test' });
    });
    granted = !regrant || regrant.ok !== false;

    t.log.info('=== D. the static site ===');
    const page = await request(port, { method: 'GET', path: '/',
      headers: { host: host, cookie: aliceCookie } });
    const base = debuggerServer.authorizationBaseOf({ headers: { host: host } });
    t.equal(page.status, 200, 'an administrator\'s session opens the site');
    t.equal(page.body, '<html><body>STS=' + base + '</body></html>',
            'with this service\'s own base put where the placeholder was');
    const script = await request(port, { method: 'GET', path: '/app.js',
      headers: { host: host, cookie: aliceCookie } });
    t.check(script.body.indexOf(base) > 0 &&
            script.body.indexOf('__STS_EMBED') < 0 &&
            /javascript/.test(String(script.headers['content-type'])),
            'in a bundle too', script.body);
    const outside = await request(port, { method: 'GET',
      path: '/%2e%2e/secret.txt',
      headers: { host: host, cookie: aliceCookie } });
    t.check(outside.status === 404 && outside.body.indexOf('outside') < 0,
            'a path that climbs out of the site is not served',
            String(outside.status));
    const put = await request(port, { method: 'PUT', path: '/index.html',
      headers: { host: host, cookie: aliceCookie } });
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
    // What the debugger's UserInfo call sends: an IdP's access token, which
    // this service did not issue and the gate must not judge.
    const idpBearer = 'Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.';
    const proof = 'eyJ0eXAiOiJkcG9wK2p3dCJ9.e30.sig';
    const fwd = await request(port, { method: 'GET',
      path: '/api/ssf/limits?x=1',
      headers: { host: host, authorization: idpBearer, dpop: proof,
                 cookie: aliceCookie + '; sts_mock_session=def' } });
    const last = seen[seen.length - 1] || { headers: {} };
    t.equal(fwd.status, 200,
            'an administrator\'s api call is forwarded, whatever ' +
            'Authorization it carries');
    t.equal(last.url, '/ssf/limits?x=1', 'with the /api prefix stripped');
    t.check(!last.headers.cookie,
            'with NO cookie reaching the api',
            JSON.stringify(Object.keys(last.headers)));
    t.equal(last.headers.authorization, idpBearer,
            'and the Authorization header the debugger sent reaching it ' +
            'UNTOUCHED (#1717)');
    t.equal(last.headers.dpop, proof,
            'and its DPoP proof likewise, unreserved and unread');
    const basic = 'Basic ' + Buffer.from('rp:pw').toString('base64');
    await request(port, { method: 'POST', path: '/api/introspection',
      headers: { host: host, authorization: basic, cookie: aliceCookie,
                 'content-type': 'application/json' } }, '{}');
    t.equal((seen[seen.length - 1] || { headers: {} }).headers.authorization,
            basic,
            'introspection\'s Basic client credentials reach the api too — ' +
            'the gate used to refuse them as a malformed token');
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
            'landings, Authorization never read, session refusals including ' +
            'a revoked role, the substituted static site and the ' +
            'forwarder passing Authorization and DPoP through',
  run: run
};
