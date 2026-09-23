'use strict';
//
// File: backchannel_logout_gaps.js
//
// ===========================================================================
// OPENID CONNECT BACK-CHANNEL LOGOUT 1.0: THE TWO GAPS #123 CLOSED
// (2026-09-23). `oauth-oidc/CLAUDE.md` 3aq carries the rest of the feature;
// `tests/backchannel_logout.js` and `tests/backchannel_durable.js` hold it.
//
//   1. SECTION 2.2's SCHEME RULE, at every door: an http
//      `backchannel_logout_uri` is refused for a public client
//      (STS-REG-0189), and for anybody while the outbound policy would not
//      dial it (STS-REG-0190) — at RFC 7591 registration, a create and an
//      attribute write; https is untouched, and http for a confidential
//      client is accepted where the policy sends over http.
//   2. SECTION 2.7 AT SIGN-OUT, IN DEVELOPMENT MODE (it was RFC 9700 mode
//      only): a refresh token issued on the session WITHOUT offline_access is
//      revoked (introspection says inactive), one WITH it survives, and
//      `oauthRevokeRefreshOnLogout: FALSE` on an entry keeps its online token.
//
// In a CHILD PROCESS, `tests/rfc9068_access_tokens.js`'s reason.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'backchannel_logout_gaps',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.BG_ROOT;
  const OUT = process.env.BG_OUT;
  const http = require('http');
  const crypto = require('crypto');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  let jar = {};
  function request(port, method, urlPath, opts) {
    const o = opts || {};
    return new Promise(function (resolve) {
      const body = o.json !== undefined ? JSON.stringify(o.json)
        : (o.form ? new URLSearchParams(o.form).toString() : '');
      const headers = Object.assign({}, o.headers || {});
      const live = Object.keys(jar).filter(function (k) {
        return jar[k] !== '';
      });
      if (live.length && o.cookies !== false) {
        headers.cookie = live.map(function (k) {
          return k + '=' + jar[k];
        }).join('; ');
      }
      if (method !== 'GET') {
        headers['content-type'] = o.json !== undefined ? 'application/json'
          : 'application/x-www-form-urlencoded';
        headers['content-length'] = Buffer.byteLength(body);
      }
      const req = http.request({ host: '127.0.0.1', port: port, path: urlPath,
                                 method: method, headers: headers },
                               function (res) {
        let text = '';
        (res.headers['set-cookie'] || []).forEach(function (line) {
          const pair = line.split(';')[0];
          const eq = pair.indexOf('=');
          jar[pair.slice(0, eq)] = /Max-Age=0/.test(line) ? ''
            : pair.slice(eq + 1);
        });
        res.on('data', function (c) { text += c; });
        res.on('end', function () {
          let parsed = null;
          try {
            parsed = JSON.parse(text);
          } catch (e) {
            parsed = null;
          }
          resolve({ status: res.statusCode, headers: res.headers, text: text,
                    json: parsed });
        });
      });
      req.end(method === 'GET' ? undefined : body);
    });
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const applications = require(ROOT + '/common/applications');
    const config = require(ROOT + '/common/config');
    const errorCodes = require(ROOT + '/common/error_codes');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    config.setOverride('oauth2.consentRequired', false);

    // --- 1. section 2.2 ----------------------------------------------------
    const HTTP_URI = 'http://rp.bcg.example/bc';
    const HTTPS_URI = 'https://rp.bcg.example/bc';
    const codeOf = function (found) {
      return found ? found.errorCode : '';
    };
    config.setOverride('federation.outboundAllowHttp', false);
    note(codeOf(applications.backchannelSchemeProblem(HTTPS_URI, true)) ===
           '' &&
         codeOf(applications.backchannelSchemeProblem(HTTP_URI, true)) ===
           'STS-REG-0189' &&
         codeOf(applications.backchannelSchemeProblem(HTTP_URI, false)) ===
           'STS-REG-0190',
         '1a. https passes; http is refused for a public client, and for a ' +
         'confidential one while the outbound policy will not dial it');
    const registerWith = function (members) {
      return request(port, 'POST', '/oauth2/register', { cookies: false,
        json: Object.assign({ redirect_uris: ['https://rp.bcg.example/cb'],
                              backchannel_logout_uri: HTTP_URI }, members) });
    };
    let r = await registerWith({ token_endpoint_auth_method: 'none' });
    note(r.status === 400 && r.json &&
           r.json.error === 'invalid_client_metadata' &&
           /confidential/.test(r.json.error_description || ''),
         '1b. registration: a public client\'s http URI is refused',
         r.status + ' ' + r.text.slice(0, 200));
    r = await registerWith({});
    note(r.status === 400 && r.json &&
           /dead-lettered/.test(r.json.error_description || ''),
         '1c. registration: a confidential client\'s http URI is refused ' +
         'while the outbound policy would not dial it, with its reason',
         r.status + ' ' + r.text.slice(0, 200));
    r = await registerWith({ backchannel_logout_uri: HTTPS_URI });
    note(r.status === 201, '1d. registration: https is accepted', r.status);
    config.setOverride('federation.outboundAllowHttp', true);
    r = await registerWith({});
    note(r.status === 201, '1e. registration: a confidential client\'s http ' +
         'URI is accepted where the policy sends over http',
         r.status + ' ' + r.text.slice(0, 200));
    r = await registerWith({ token_endpoint_auth_method: 'none' });
    note(r.status === 400, '1f. and a public client\'s still is not',
         r.status);
    config.setOverride('federation.outboundAllowHttp', false);

    let made = applications.createApplication({ identifier: 'bcg-public',
      protocols: ['oauth2'],
      fields: { oauthClientId: 'bcg-public',
                oauthRedirectUri: ['https://rp.bcg.example/cb'],
                oauthBackchannelLogoutUri: HTTP_URI } });
    note(!made.ok && errorCodes.codeOf(made) === 'STS-REG-0189',
         '1g. a create with no credential (a public client) and an http URI ' +
         'is refused', JSON.stringify(made).slice(0, 300));
    made = applications.createApplication({ identifier: 'bcg-conf',
      protocols: ['oauth2'],
      fields: { oauthClientId: 'bcg-conf', oauthClientSecret: 'x'.repeat(32),
                oauthRedirectUri: ['https://rp.bcg.example/cb'] } });
    let set = applications.updateApplication('bcg-conf', {
      attribute: 'oauthBackchannelLogoutUri', mode: 'set', value: HTTP_URI });
    note(made.ok !== false && !set.ok &&
           errorCodes.codeOf(set) === 'STS-REG-0190',
         '1h. an attribute write of an http URI on a confidential entry is ' +
         'refused while the policy would not dial it',
         JSON.stringify(set).slice(0, 300));
    set = applications.updateApplication('bcg-conf', {
      attribute: 'oauthBackchannelLogoutUri', mode: 'set',
      value: HTTPS_URI });
    note(set.ok !== false, '1i. and an https one is written',
         JSON.stringify(set).slice(0, 200));

    // --- 2. section 2.7 ----------------------------------------------------
    const REDIRECT = 'https://rp.bcg.example/cb';
    const SECRET = 'bcg-secret-0123456789abcdef0123456789';
    const makeRp = function (id, extra) {
      applications.createApplication({ identifier: id, protocols: ['oauth2'],
        fields: Object.assign({ oauthClientId: id, oauthClientSecret: SECRET,
          oauthRedirectUri: [REDIRECT],
          oauthTokenEndpointAuthMethod: 'client_secret_basic',
          oauthGlobalConsent: ['openid', 'offline_access'] }, extra || {}) });
    };
    makeRp('bcg-rp');
    makeRp('bcg-keeps', { oauthRevokeRefreshOnLogout: 'FALSE' });
    const basic = function (id) {
      return 'Basic ' + Buffer.from(id + ':' + SECRET).toString('base64');
    };
    const authorize = function (id, scope) {
      return '/oauth2/authorize?' + new URLSearchParams({
        client_id: id, response_type: 'code', redirect_uri: REDIRECT,
        scope: scope, state: 'st',
        nonce: 'n-' + crypto.randomBytes(4).toString('hex') }).toString();
    };
    const codeFrom = function (r) {
      const loc = String((r && r.headers && r.headers.location) || '');
      const at = loc.indexOf('?');
      return loc.indexOf(REDIRECT) === 0 && at > 0
        ? new URLSearchParams(loc.slice(at + 1)).get('code') : '';
    };
    const refreshFor = async function (id, scope) {
      let r = await request(port, 'GET', authorize(id, scope));
      const to = String(r.headers.location || '');
      if (/\/authn\/login/.test(to)) {
        const page = await request(port, 'GET',
                                   to.replace(/^https?:\/\/[^/]+/, ''));
        const form = {};
        (page.text.match(/<input type="hidden"[^>]*>/g) || []).forEach(
          function (tag) {
            const name = /name="([^"]+)"/.exec(tag);
            const value = /value="([^"]*)"/.exec(tag);
            if (name) {
              form[name[1]] = value ? value[1].replace(/&amp;/g, '&') : '';
            }
          });
        form.username = 'bcg-alice';
        form.password = 'anything';
        form.action = 'login';
        const posted = await request(port, 'POST', '/authn/login',
                                     { form: form });
        r = await request(port, 'GET', String(posted.headers.location || '')
          .replace(/^https?:\/\/[^/]+/, ''));
      }
      const code = codeFrom(r);
      const t = await request(port, 'POST', '/oauth2/token', {
        cookies: false, headers: { authorization: basic(id) },
        form: { grant_type: 'authorization_code', code: code,
                redirect_uri: REDIRECT } });
      return (t.json && t.json.refresh_token) || '';
    };
    const active = async function (token) {
      const r = await request(port, 'POST', '/oauth2/introspect', {
        cookies: false, form: { token: token } });
      return !!(r.json && r.json.active);
    };
    const offline = await refreshFor('bcg-rp', 'openid offline_access');
    const online = await refreshFor('bcg-rp', 'openid');
    const kept = await refreshFor('bcg-keeps', 'openid');
    note(offline && online && kept && await active(offline) &&
           await active(online) && await active(kept),
         '2a. three refresh tokens on one session, all active before the ' +
         'sign-out (RFC 9700 mode is off)');
    await request(port, 'GET', '/oauth2/logout');
    note(!(await active(online)),
         '2b. after the sign-out the online token is revoked, in ' +
         'development mode (section 2.7)');
    note(await active(offline),
         '2c. the offline_access token survives (OIDC Core section 11)');
    note(await active(kept),
         '2d. and oauthRevokeRefreshOnLogout: FALSE on an entry keeps its ' +
         'online token — the client that refreshes its way back');

    server.close();
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    note(false, 'the child threw', e && e.stack ? e.stack : e);
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function inAChild(t) {
  log.debug("Entering inAChild().");
  t.log.info('=== the two gaps, in a child process ===');
  const out = path.join(os.tmpdir(), 'backchannel-gaps-' + process.pid +
                        '-' + Math.random().toString(36).slice(2) + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', 'const fs = require("fs");\n(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', BG_ROOT: ROOT, BG_OUT: out }),
      encoding: 'utf8', timeout: 240000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
    // No report: the child died before writing one. Reported below with its
    // exit status and stderr, which is where the reason is.
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written, which the read above has already reported.
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings), 'the child process reported its ' +
                                        'findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-800))) {
    log.debug("Leaving inAChild().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  t.check(findings.length >= 13, 'the child ran every section',
          findings.length + ' finding(s)');
  log.debug("Leaving inAChild().");
}

async function run(t) {
  log.debug("Entering run().");
  inAChild(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'backchannel logout gaps',
  describe: 'Back-Channel Logout 1.0 (#123): section 2.2\'s http rule at ' +
            'every door, and section 2.7\'s refresh-token revocation at ' +
            'sign-out in every mode',
  run: run
};
