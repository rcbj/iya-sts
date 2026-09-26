'use strict';
//
// File: rp_initiated_logout.js
//
// ===========================================================================
// OPENID CONNECT RP-INITIATED LOGOUT 1.0 (#124, which folded #115 in,
// 2026-09-23). `oauth2.ts`'s `logoutEndpoint()` argues the order. Held here,
// in a CHILD PROCESS (`tests/rfc9068_access_tokens.js`'s reason), against
// real sign-ins in development mode:
//
//   a. VALIDATE BEFORE ENDING: a malformed request is a 400 page and the
//      session survives it; so does a POST that is not a form.
//   b. CONFIRMATION: no hint → the page, the session alive; "no" keeps it;
//      a forged or stale confirm_for is asked again; the page's own form ends
//      it. A cross-site POST (no cookie) is asked rather than answered with a
//      cookie clear.
//   c. THE HINT: a verified id_token_hint for THIS session signs out at once
//      and returns to the registered address WITH state, by GET and by POST;
//      a tampered hint, and a client_id it was not issued to, are refused
//      and the session survives; a logout_hint naming somebody else asks.
//   d. THE RETURN: a registered client is held to its own list exactly (an
//      unregistered address is not followed and the page says why), a
//      private-use address nobody registered is not followed, and
//      development still follows an http(s) address for a client that
//      registered none. No session at all: straight back, with state.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'rp_initiated_logout',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.RL_ROOT;
  const OUT = process.env.RL_OUT;
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
      const body = o.raw !== undefined ? o.raw
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
      if (method !== 'GET' && !headers['content-type']) {
        headers['content-type'] = 'application/x-www-form-urlencoded';
      }
      if (method !== 'GET') {
        headers['content-length'] = Buffer.byteLength(body);
      }
      const req = http.request({ host: '127.0.0.1', port: port,
                                 path: String(urlPath).replace(
                                   /^https?:\/\/[^/]+/, ''),
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

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    config.setOverride('oauth2.consentRequired', false);
    const REDIRECT = 'https://rp.rl.example/cb';
    const BACK = 'https://rp.rl.example/signed-out';
    const SECRET = 'rl-secret-0123456789abcdef0123456789';
    applications.createApplication({ identifier: 'rl-rp',
      protocols: ['oauth2'],
      fields: { oauthClientId: 'rl-rp', oauthClientSecret: SECRET,
                oauthRedirectUri: [REDIRECT],
                oauthPostLogoutRedirectUri: [BACK],
                oauthTokenEndpointAuthMethod: 'client_secret_basic' } });
    applications.createApplication({ identifier: 'rl-bare',
      protocols: ['oauth2'],
      fields: { oauthClientId: 'rl-bare', oauthClientSecret: SECRET,
                oauthRedirectUri: [REDIRECT],
                oauthTokenEndpointAuthMethod: 'client_secret_basic' } });

    // Sign in through the real screen; answers the ID Token.
    const signIn = async function (username) {
      jar = {};
      let r = await request(port, 'GET', '/oauth2/authorize?' +
        new URLSearchParams({ client_id: 'rl-rp', response_type: 'code',
          redirect_uri: REDIRECT, scope: 'openid', state: 'st',
          nonce: 'n-' + crypto.randomBytes(4).toString('hex') }).toString());
      const page = await request(port, 'GET', String(r.headers.location));
      const form = {};
      (page.text.match(/<input type="hidden"[^>]*>/g) || []).forEach(
        function (tag) {
          const name = /name="([^"]+)"/.exec(tag);
          const value = /value="([^"]*)"/.exec(tag);
          if (name) {
            form[name[1]] = value ? value[1].replace(/&amp;/g, '&') : '';
          }
        });
      form.username = username;
      form.password = 'anything';
      form.action = 'login';
      const posted = await request(port, 'POST', '/authn/login',
                                   { form: form });
      r = await request(port, 'GET', String(posted.headers.location));
      const loc = String(r.headers.location || '');
      const code = new URLSearchParams(loc.slice(loc.indexOf('?') + 1))
        .get('code');
      const t = await request(port, 'POST', '/oauth2/token', {
        cookies: false, headers: { authorization: 'Basic ' +
          Buffer.from('rl-rp:' + SECRET).toString('base64') },
        form: { grant_type: 'authorization_code', code: code,
                redirect_uri: REDIRECT } });
      return (t.json && t.json.id_token) || '';
    };
    // Is the session alive? prompt=none answers a code if so.
    const alive = async function () {
      const r = await request(port, 'GET', '/oauth2/authorize?' +
        new URLSearchParams({ client_id: 'rl-rp', response_type: 'code',
          redirect_uri: REDIRECT, scope: 'openid', state: 'st',
          prompt: 'none', nonce: 'n' }).toString());
      return /[?&]code=/.test(String(r.headers.location || ''));
    };
    const hiddenOf = function (text) {
      const form = {};
      (String(text).match(/<input type="hidden"[^>]*>/g) || []).forEach(
        function (tag) {
          const name = /name="([^"]+)"/.exec(tag);
          const value = /value="([^"]*)"/.exec(tag);
          if (name) {
            form[name[1]] = value ? value[1].replace(/&amp;/g, '&') : '';
          }
        });
      return form;
    };
    const logout = function (params) {
      return request(port, 'GET', '/oauth2/logout?' +
                     new URLSearchParams(params || {}).toString());
    };

    // --- a. validate before ending -----------------------------------------
    let idToken = await signIn('rl-alice');
    note(idToken && await alive(), 'a0. signed in, the session alive');
    let r = await logout({ post_logout_redirect_uri: 'javascript:alert(1)' });
    note(r.status === 400 && /text\/html/.test(r.headers['content-type']) &&
           await alive(),
         'a1. a malformed sign-out is a 400 PAGE, and the session survives it',
         r.status + ' ' + r.headers['content-type']);
    r = await request(port, 'POST', '/oauth2/logout', {
      raw: '{"id_token_hint":"x"}',
      headers: { 'content-type': 'application/json' } });
    note(r.status === 400 && await alive(),
         'a2. a POST that is not a form is refused, the session untouched',
         r.status);

    // --- b. confirmation -------------------------------------------------------
    r = await logout({ client_id: 'rl-rp', post_logout_redirect_uri: BACK,
                       state: 'st-b' });
    note(r.status === 200 && /name="confirm_for"/.test(r.text) &&
           /<button type="submit" name="confirm" value="yes"/.test(r.text) &&
           !/<script/i.test(r.text) && await alive(),
         'b1. no hint: a confirmation page with a real button and no script, ' +
         'and the session alive', r.status);
    const asked = hiddenOf(r.text);
    let d = await request(port, 'POST', '/oauth2/logout',
      { form: Object.assign({}, asked, { confirm: 'no' }) });
    note(d.status === 200 && /still signed in/i.test(d.text) &&
           await alive(), 'b2. "Stay signed in" keeps the session');
    d = await request(port, 'POST', '/oauth2/logout',
      { form: Object.assign({}, asked, { confirm: 'yes',
                                         confirm_for: 'forged' }) });
    note(d.status === 200 && /name="confirm_for"/.test(d.text) &&
           await alive(), 'b3. a forged confirm_for is asked again');
    const withCookie = Object.assign({}, jar);
    d = await request(port, 'POST', '/oauth2/logout', { cookies: false,
      form: { client_id: 'rl-rp' } });
    note(d.status === 200 && /name="confirm_for"/.test(d.text) &&
           !String(d.headers['set-cookie'] || '').includes('sts_session=;'),
         'b4. a cross-site POST (no cookie) is asked, and no cookie is cleared',
         JSON.stringify(d.headers['set-cookie'] || []));
    jar = withCookie;
    d = await request(port, 'POST', '/oauth2/logout',
      { form: Object.assign({}, asked, { confirm: 'yes' }) });
    const back = String(d.headers.location || '');
    note(d.status === 302 && back.indexOf(BACK) === 0 &&
           /[?&]state=st-b(&|$)/.test(back) && !(await alive()),
         'b5. the page\'s own form signs out and returns to the registered ' +
         'address WITH state', d.status + ' ' + back);

    // --- c. the hint ---------------------------------------------------------
    idToken = await signIn('rl-alice');
    r = await logout({ id_token_hint: idToken, post_logout_redirect_uri: BACK,
                       state: 'st-c' });
    note(r.status === 302 && String(r.headers.location).indexOf(BACK) === 0 &&
           /state=st-c/.test(String(r.headers.location)) && !(await alive()),
         'c1. a verified hint for this session signs out at once, with state',
         r.status + ' ' + r.headers.location);
    idToken = await signIn('rl-alice');
    const tampered = idToken.slice(0, -4) + (idToken.slice(-4) === 'AAAA'
      ? 'BBBB' : 'AAAA');
    r = await logout({ id_token_hint: tampered });
    note(r.status === 400 && await alive(),
         'c2. a hint that does not verify is refused, the session survives',
         r.status);
    r = await logout({ id_token_hint: idToken, client_id: 'rl-bare' });
    note(r.status === 400 && await alive(),
         'c3. a client_id the hint was not issued to is refused', r.status);
    r = await logout({ id_token_hint: idToken, logout_hint: 'somebody-else' });
    note(r.status === 200 && /name="confirm_for"/.test(r.text) &&
           await alive(),
         'c4. a logout_hint naming somebody else asks, even with the hint');
    r = await request(port, 'POST', '/oauth2/logout',
      { form: { id_token_hint: idToken, post_logout_redirect_uri: BACK } });
    note(r.status === 302 && !(await alive()),
         'c5. POST, section 2\'s other method, with the hint: signed out',
         r.status);

    // --- d. the return ---------------------------------------------------------
    idToken = await signIn('rl-alice');
    r = await logout({ id_token_hint: idToken,
                       post_logout_redirect_uri: 'https://evil.example/x' });
    note(r.status === 200 && !r.headers.location &&
           /not returned/.test(r.text) && !(await alive()),
         'd1. a registered client is held to its own list: an address it ' +
         'did not register is not followed, and the page says why',
         r.status + ' ' + r.headers.location);
    jar = {};
    r = await logout({ client_id: 'rl-bare',
                       post_logout_redirect_uri: 'https://rp.rl.example/any',
                       state: 's' });
    note(r.status === 302 &&
           String(r.headers.location) === 'https://rp.rl.example/any?state=s',
         'd2. no session, a client that registered none: development follows ' +
         'it straight back, with state', r.status + ' ' + r.headers.location);
    r = await logout({ post_logout_redirect_uri: 'com.example.rl:/out' });
    note(r.status === 200 && !r.headers.location,
         'd3. a private-use address nobody registered is not followed',
         r.status + ' ' + r.headers.location);
    // #187: neither an id_token_hint nor a client_id — section 2's MUST
    // NOT — so even development, which follows an address a NAMED client
    // never registered (d2), does not follow this one.
    r = await logout({ post_logout_redirect_uri: 'https://rp.rl.example/any',
                       state: 's' });
    note(r.status === 200 && !r.headers.location &&
           /neither an id_token_hint nor/.test(r.text),
         'd3b. an https address with no client named is not followed in ' +
         'development either (STS-OAUTH-0710), and the page says why',
         r.status + ' ' + r.headers.location);
    r = await logout({});
    note(r.status === 200 && /text\/html/.test(r.headers['content-type']) &&
           !/mock/i.test(r.text),
         'd4. with nowhere to return, a page — not text/plain "mock"',
         r.headers['content-type']);

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
  t.log.info('=== RP-Initiated Logout, in a child process ===');
  const out = path.join(os.tmpdir(), 'rp-logout-' + process.pid + '-' +
                        require('crypto').randomBytes(8).toString('hex') +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', 'const fs = require("fs");\n(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', RL_ROOT: ROOT, RL_OUT: out }),
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
  t.check(findings.length >= 17, 'the child ran every section',
          findings.length + ' finding(s)');
  log.debug("Leaving inAChild().");
}

async function run(t) {
  log.debug("Entering run().");
  inAChild(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'rp-initiated logout',
  describe: 'OpenID Connect RP-Initiated Logout 1.0 (#124, #115): validate ' +
            'before ending, the confirmation page, the id_token_hint, POST, ' +
            'state, and the registered return',
  run: run
};
