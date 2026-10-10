// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: tests/token_exchange_declared_type.js
//
// AN RFC 8693 subject_token OR actor_token IS THE TYPE IT WAS DECLARED AS
// (#116). Every token this realm issues is signed with one key, so a
// signature says only that the token is ours — not that it is an access
// token. #130 held a VERIFIED subject_token to its declared type
// (STS-OAUTH-0628); #116 found it untested, and one case open: in
// DEVELOPMENT an actor_token was read unverified, so this realm's own ID
// Token declared an access token was exchanged as one. It is now verified
// when it can be and held to its type — a TYPE check, not a trust check, in
// both modes, as the subject_token already was. A token from anywhere is
// still read unverified there. (This realm's own encrypted refresh token is
// opened by `verifyOwnJws()`, so it was already held to its type; D6 keeps
// it that way.)
//
// In a CHILD PROCESS serving the stack on a loopback port, as
// token_exchange_jti.js does: every refusal beside a control that is
// accepted, so a refusal means the type and not a broken exchange; each
// refusal by its error and its STS-OAUTH-0628 on the audit log; and the
// same in product, switched at runtime, with a declared client.

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'token_exchange_declared_type',
  level: process.env.LOG_LEVEL || 'info' });

function child() {
  const ROOT = process.env.TXT_ROOT;
  const OUT = process.env.TXT_OUT;
  const http = require('http');
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };
  const post = function (port, form) {
    return new Promise(function (resolve) {
      const body = new URLSearchParams(form).toString();
      const req = http.request({ host: '127.0.0.1', port: port,
        path: '/oauth2/token', method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded',
                   'content-length': Buffer.byteLength(body) } },
      function (res) {
        let text = '';
        res.on('data', function (c) { text += c; });
        res.on('end', function () {
          let json = {};
          try {
            json = JSON.parse(text);
          } catch (e) {
            // A page rather than JSON; kept as text for the finding.
            json = { parseError: e.message };
          }
          resolve({ status: res.statusCode, json: json, text: text });
        });
      });
      req.end(body);
    });
  };
  const b64u = function (o) {
    return Buffer.from(JSON.stringify(o), 'utf8').toString('base64url');
  };
  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const config = require(ROOT + '/common/config');
    const applications = require(ROOT + '/common/applications');
    const audit = require(ROOT + '/common/audit');
    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;

    const EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange';
    const T = 'urn:ietf:params:oauth:token-type:';
    const SECRET = 'txt-confidential-secret-0123456789abcdef';
    applications.createApplication({ identifier: 'txt-client',
      protocols: ['oauth2', 'oidc'],
      fields: { oauthClientId: 'txt-client', oauthClientSecret: SECRET,
                oauthTokenEndpointAuthMethod: 'client_secret_post',
                oauthGrantType: ['password', 'client_credentials',
                                 'refresh_token', EXCHANGE] } });
    const auth = { client_id: 'txt-client', client_secret: SECRET };
    const marks = function () {
      return audit.list().filter(function (row) {
        return row.errorCode === 'STS-OAUTH-0628';
      }).length;
    };
    const exchange = function (subject, type, extra) {
      return post(port, Object.assign({ grant_type: EXCHANGE,
        subject_token: subject, subject_token_type: T + type }, auth,
      extra || {}));
    };
    // A refusal, and the code it recorded.
    const refused = async function (what, attempt, says) {
      const before = marks();
      const r = await attempt();
      note(r.status === 400 && r.json.error === 'invalid_request' &&
           !r.json.access_token &&
           String(r.json.error_description || '').indexOf(says) >= 0,
           what + ': refused invalid_request, naming ' + says,
           r.status + ' ' + r.text.slice(0, 300));
      note(marks() === before + 1, what + ': STS-OAUTH-0628 recorded');
    };
    const accepted = async function (what, attempt) {
      const r = await attempt();
      note(r.status === 200 && r.json.access_token, what + ': exchanged',
           r.status + ' ' + r.text.slice(0, 300));
    };

    // The tokens: an access token, an ID Token and a refresh token, all
    // this realm's own.
    const issued = await post(port, Object.assign({ grant_type: 'password',
      username: 'txt-alice', password: 'anything',
      scope: 'openid profile offline_access' }, auth));
    const access = String(issued.json.access_token || '');
    const idToken = String(issued.json.id_token || '');
    const refresh = String(issued.json.refresh_token || '');
    note(issued.status === 200 && access && idToken && refresh,
         'precondition: the password grant issued an access token, an ID ' +
         'Token and a refresh token', issued.status + ' ' +
         issued.text.slice(0, 300));
    const unsigned = b64u({ alg: 'none', typ: 'JWT' }) + '.' +
      b64u({ sub: 'txt-somebody', iat: Math.floor(Date.now() / 1000) }) + '.';

    // --- DEVELOPMENT -------------------------------------------------------
    await accepted('D1. dev: an access token declared access_token',
      function () { return exchange(access, 'access_token'); });
    await refused('D2. dev: an ID Token declared access_token',
      function () { return exchange(idToken, 'access_token'); },
      'is an ID Token');
    await refused('D3. dev: an access token declared id_token',
      function () { return exchange(access, 'id_token'); },
      'is an access token');
    await accepted('D4. dev: an ID Token declared id_token',
      function () { return exchange(idToken, 'id_token'); });
    await accepted('D5. dev: any signed token of ours declared jwt',
      function () { return exchange(idToken, 'jwt'); });
    await refused('D6. dev: our own REFRESH token declared access_token',
      function () { return exchange(refresh, 'access_token'); },
      'is a refresh token');
    await accepted('D7. dev: a token from anywhere is still exchanged ' +
      'unverified (mode.exchangesUnverifiedTokens())',
      function () { return exchange(unsigned, 'access_token'); });
    // The client's own client_credentials token: since #550 an actor_token
    // must be the exchanging client's own and addressed to it or to this
    // server, which a password-grant token for the default resource is not.
    const ownCc = await post(port, Object.assign(
      { grant_type: 'client_credentials' }, auth));
    const ownAccess = String(ownCc.json.access_token || '');
    await accepted('D8. dev: our access token as the actor_token declared ' +
      'access_token', function () {
      return exchange(access, 'access_token',
        { actor_token: ownAccess, actor_token_type: T + 'access_token' });
    });
    await refused('D9. dev (#116): our own ID Token as the actor_token ' +
      'declared access_token, which was read unverified and believed',
      function () {
        return exchange(access, 'access_token',
          { actor_token: idToken, actor_token_type: T + 'access_token' });
      }, 'actor_token was declared');
    // Read unverified, and held to #550's two rules all the same: one
    // naming this client is exchanged, one naming nobody is refused.
    const unsignedOwn = b64u({ alg: 'none', typ: 'JWT' }) + '.' +
      b64u({ sub: 'txt-somebody', client_id: auth.client_id,
             aud: auth.client_id,
             iat: Math.floor(Date.now() / 1000) }) + '.';
    await accepted('D10. dev: an actor_token from anywhere is still read ' +
      'unverified', function () {
      return exchange(access, 'access_token',
        { actor_token: unsignedOwn, actor_token_type: T + 'access_token' });
    });
    const unbound = await exchange(access, 'access_token',
      { actor_token: unsigned, actor_token_type: T + 'access_token' });
    note(unbound.status === 400 && unbound.json.error === 'invalid_request' &&
         /not issued to this client/.test(
           String(unbound.json.error_description || '')),
         'D10b. dev (#550): an unverified actor_token naming no client is ' +
         'refused all the same', unbound.status + ' ' +
         unbound.text.slice(0, 300));

    // --- PRODUCT -----------------------------------------------------------
    config.setOverride('oauth2.consentRequired', false);
    config.setOverride('global.mode', 'product');
    try {
      const cc = await post(port, Object.assign(
        { grant_type: 'client_credentials' }, auth));
      const own = String(cc.json.access_token || '');
      note(cc.status === 200 && own, 'precondition: product issues the ' +
           'client a token', cc.status + ' ' + cc.text.slice(0, 200));
      await accepted('P1. product: an access token declared access_token',
        function () { return exchange(own, 'access_token'); });
      await refused('P2. product: an ID Token declared access_token',
        function () { return exchange(idToken, 'access_token'); },
        'is an ID Token');
      await refused('P3. product: an access token declared id_token',
        function () { return exchange(own, 'id_token'); },
        'is an access token');
      await refused('P4. product: an ID Token as the actor_token declared ' +
        'access_token', function () {
        return exchange(own, 'access_token',
          { actor_token: idToken, actor_token_type: T + 'access_token' });
      }, 'actor_token was declared');
    } finally {
      config.clearOverride('global.mode');
      config.clearOverride('oauth2.consentRequired');
    }
    server.close();
  })().catch(function (e) {
    note(false, 'the child ran to the end', e && e.stack);
  }).then(function () {
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function run(t) {
  log.debug("Entering run().");
  const root = path.join(__dirname, '..');
  const out = path.join(os.tmpdir(), 'sts-txt-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = Object.assign({}, process.env, { TXT_OUT: out, TXT_ROOT: root,
    STS_HTTPS: 'false' });
  delete env.CONFIG_FILE;
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + child.toString() + ')()'], {
      cwd: root, env: env, encoding: 'utf8', timeout: 180000,
      maxBuffer: 256 * 1024 * 1024 });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    // The child died before writing a report; said below with its status.
    findings = null;
  }
  try {
    fs.rmSync(out, { force: true });
  } catch (e) {
    // A temporary file left behind is not a failed assertion.
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (!findings) {
    log.debug("Leaving run(). The child wrote no report.");
    throw new Error('the child process wrote no report (status ' +
                    result.status + '): ' +
                    String(result.stderr || '').slice(-2000));
  }
  findings.forEach(function (f) {
    t.check(f.ok, f.what, f.detail);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'token_exchange_declared_type',
  describe: 'an RFC 8693 subject_token or actor_token is the type it was ' +
            'declared as, in both modes (#116)',
  run: run
};
