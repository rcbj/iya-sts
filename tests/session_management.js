'use strict';
//
// File: session_management.js
//
// ===========================================================================
// OPENID CONNECT SESSION MANAGEMENT 1.0 (#121, 2026-09-23).
//
// `oauth-oidc/CLAUDE.md` 3ax argues the design. What is held here:
//
//   1. THE LIBRARY: section 3's `session_state` formula, recomputed here by
//      hand; the cookie's attributes on each kind of port; which redirect
//      URIs have an origin; nothing owed while the setting is off.
//   2. THE OP IFRAME'S SCRIPT, run in a node vm with a fake window, cookie
//      and `postMessage` — rcbj's choice over a browser: `unchanged` for the
//      state it was given, `changed` for another origin, another browser
//      state, a tampered value, and `error` for a malformed message.
//   3. THE ENDPOINTS, in a child process: a real sign-in carrying
//      `session_state` and writing the browser state, `prompt=none` with and
//      without a session, a sign-out clearing the state (so the iframe says
//      `changed`), a new sign-in minting a new state, the iframe page's
//      narrowed `frame-ancestors`, discovery, and everything absent while the
//      setting is off.
//
// **THE CHILD** is `tests/rfc9068_access_tokens.js`'s reason: the protocol
// stack registers every route on the shared app.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const vm = require('vm');
const nodeCrypto = require('crypto');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'session_management',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// Runs the served script against one cookie value and asks it `message` from
// `origin`; answers what it posted back, and where.
async function askTheIframe(script, cookie, origin, message) {
  log.debug("Entering askTheIframe().");
  const answers = [];
  let handler = null;
  const window = {
    addEventListener: function (type, fn) {
      if (type === 'message') {
        handler = fn;
      }
    },
    crypto: nodeCrypto.webcrypto
  };
  const context = vm.createContext({
    window: window,
    document: { cookie: cookie },
    btoa: btoa,
    TextEncoder: TextEncoder,
    Uint8Array: Uint8Array,
    String: String
  });
  vm.runInContext(script, context);
  handler({ data: message, origin: origin,
            source: { postMessage: function (text, to) {
              answers.push({ text: text, to: to });
            } } });
  for (let i = 0; i < 20 && !answers.length; i++) {
    await new Promise(function (resolve) { setTimeout(resolve, 5); });
  }
  log.debug("Leaving askTheIframe().");
  return answers[0] || { text: '(no answer)', to: '' };
}

// ---------------------------------------------------------------------------
// 1 and 2. THE LIBRARY AND THE SCRIPT.
// ---------------------------------------------------------------------------
async function library(t) {
  log.debug("Entering library().");
  t.log.info('=== 1. the library ===');
  const config = require('../common/config');
  const stsCrypto = require('../common/crypto');
  const sm = require('../oauth-oidc/session_management');

  const made = stsCrypto.sessionStateHash('client 1', 'https://rp.example',
                                          'bs-value', 'salt-1');
  const byHand = nodeCrypto.createHash('sha256')
    .update('client 1 https://rp.example bs-value salt-1', 'utf8')
    .digest('base64url') + '.salt-1';
  t.check(made === byHand, '1a. session_state is section 3\'s formula: ' +
          'SHA-256 of "client_id origin browser_state salt", then .salt',
          made + ' vs ' + byHand);
  const fresh = stsCrypto.sessionStateHash('c', 'https://rp.example', '');
  const other = stsCrypto.sessionStateHash('c', 'https://rp.example', '');
  t.check(fresh !== other && /^[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]+$/
            .test(fresh),
          '1b. and a fresh salt each time', fresh + ' ' + other);

  t.check(sm.originOf('https://rp.example:8443/cb?x=1') ===
            'https://rp.example:8443' &&
          sm.originOf('com.example.app:/cb') === '' &&
          sm.originOf('not a url') === '',
          '1c. only an http(s) redirect URI has an origin');

  config.setOverride('oauth2.sessionManagement', false);
  t.check(sm.sessionStateFor('c', 'https://rp.example/cb', 'openid', null) ===
            '', '1d. off, nothing is owed');
  config.setOverride('oauth2.sessionManagement', true);
  try {
    t.check(sm.sessionStateFor('c', 'https://rp.example/cb', 'openid', null)
              !== '' &&
            sm.sessionStateFor('c', 'https://rp.example/cb', 'profile',
                               null) === '' &&
            sm.sessionStateFor('c', 'com.example.app:/cb', 'openid',
                               null) === '' &&
            sm.sessionStateFor('', 'https://rp.example/cb', 'openid',
                               null) === '',
            '1e. on, owed to an OpenID Connect request with a web origin ' +
            'and a client, and to nothing else');
  } finally {
    config.clearOverride('oauth2.sessionManagement');
  }
  t.check(sm.browserStateOf({ authenticated: true, browserState: 'x' }) ===
            'x' &&
          sm.browserStateOf({ authenticated: false, browserState: 'x' }) ===
            '' &&
          sm.browserStateOf(null) === '',
          '1f. an arrival session and no session have the empty state');

  const secure = sm.cookieLine('abc', true);
  const plain = sm.cookieLine('abc', false);
  t.check(/SameSite=None; Secure/.test(secure) && !/HttpOnly/.test(secure) &&
            /SameSite=Lax/.test(plain) && !/Secure/.test(plain) &&
            /Max-Age=0/.test(sm.cookieLine('')),
          '1g. the cookie: script-readable, SameSite=None and Secure on ' +
          'HTTPS, Lax on plain HTTP, and cleared for the empty state',
          secure + ' | ' + plain);

  t.log.info('=== 2. the OP iframe\'s script, in a vm ===');
  const RP = 'https://rp.example';
  const state = stsCrypto.sessionStateHash('c1', RP, 'BS1');
  const cookie = 'other=1; ' + sm.COOKIE + '=BS1; x=y';
  let a = await askTheIframe(sm.IFRAME_SCRIPT, cookie, RP, 'c1 ' + state);
  t.check(a.text === 'unchanged' && a.to === RP,
          '2a. the state it was given is unchanged, answered to that origin',
          JSON.stringify(a));
  a = await askTheIframe(sm.IFRAME_SCRIPT, cookie, 'https://evil.example',
                         'c1 ' + state);
  t.check(a.text === 'changed', '2b. from another origin it is changed',
          JSON.stringify(a));
  a = await askTheIframe(sm.IFRAME_SCRIPT, sm.COOKIE + '=BS2', RP,
                         'c1 ' + state);
  t.check(a.text === 'changed', '2c. another browser state is changed',
          JSON.stringify(a));
  a = await askTheIframe(sm.IFRAME_SCRIPT, '', RP, 'c1 ' + state);
  t.check(a.text === 'changed', '2d. no cookie (signed out) is changed',
          JSON.stringify(a));
  const signedOut = stsCrypto.sessionStateHash('c1', RP, '');
  a = await askTheIframe(sm.IFRAME_SCRIPT, '', RP, 'c1 ' + signedOut);
  t.check(a.text === 'unchanged', '2e. and a signed-out state stays ' +
          'unchanged while nobody signs in', JSON.stringify(a));
  const spaced = stsCrypto.sessionStateHash('my client', RP, 'BS1');
  a = await askTheIframe(sm.IFRAME_SCRIPT, cookie, RP, 'my client ' + spaced);
  t.check(a.text === 'unchanged', '2f. a client_id with a space parses ' +
          '(the last space divides)', JSON.stringify(a));
  a = await askTheIframe(sm.IFRAME_SCRIPT, cookie, RP, 'c1 ' +
                         state.replace(/^./, 'Z'));
  t.check(a.text === 'changed', '2g. a tampered value is changed',
          JSON.stringify(a));
  for (const bad of ['nospace', 'c1 nodot', 'c1 abc.', ' abc.def']) {
    a = await askTheIframe(sm.IFRAME_SCRIPT, cookie, RP, bad);
    t.check(a.text === 'error', '2h. "' + bad + '" is error',
            JSON.stringify(a));
  }
  a = await askTheIframe(sm.IFRAME_SCRIPT, cookie, RP, { not: 'a string' });
  t.check(a.text === 'error', '2i. a message that is not a string is error',
          JSON.stringify(a));
  log.debug("Leaving library().");
}

// ---------------------------------------------------------------------------
// 3. THE ENDPOINTS, IN A CHILD.
// ---------------------------------------------------------------------------
function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.SM_ROOT;
  const OUT = process.env.SM_OUT;
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
      const body = o.form ? new URLSearchParams(o.form).toString() : '';
      const headers = {};
      if (Object.keys(jar).length) {
        headers.cookie = Object.keys(jar).filter(function (k) {
          return jar[k] !== '';
        }).map(function (k) {
          return k + '=' + jar[k];
        }).join('; ');
      }
      if (method !== 'GET') {
        headers['content-type'] = 'application/x-www-form-urlencoded';
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
    const stsCrypto = require(ROOT + '/common/crypto');
    const sm = require(ROOT + '/oauth-oidc/session_management');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const BASE = 'http://127.0.0.1:' + port;
    const RP = 'https://rp.sm.example';
    const REDIRECT = RP + '/cb';
    config.setOverride('oauth2.consentRequired', false);
    applications.createApplication({ identifier: 'sm-rp',
      protocols: ['oauth2'],
      fields: { oauthClientId: 'sm-rp', oauthRedirectUri: [REDIRECT],
                oauthClientSecret: 'sm-secret-0123456789abcdef0123456789',
                oauthTokenEndpointAuthMethod: 'client_secret_basic' } });

    const query = function (extra) {
      return '/oauth2/authorize?' + new URLSearchParams(Object.assign({
        client_id: 'sm-rp', response_type: 'code', redirect_uri: REDIRECT,
        scope: 'openid', state: 's-' + crypto.randomBytes(4).toString('hex'),
        nonce: 'n-' + crypto.randomBytes(4).toString('hex')
      }, extra || {})).toString();
    };
    const paramsOf = function (r) {
      const loc = String((r && r.headers && r.headers.location) || '');
      const at = loc.indexOf('?');
      return loc.indexOf(REDIRECT) === 0 && at > 0
        ? new URLSearchParams(loc.slice(at + 1)) : new URLSearchParams();
    };
    const signIn = async function (username) {
      const first = await request(port, 'GET', query());
      const to = String(first.headers.location || '');
      if (!/\/authn\/login/.test(to)) {
        return first;
      }
      const page = await request(port, 'GET', to.replace(/^https?:\/\/[^/]+/,
                                                         ''));
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
      const back = String(posted.headers.location || '');
      return back ? request(port, 'GET', back.replace(/^https?:\/\/[^/]+/, ''))
                  : posted;
    };
    const holds = function (sessionState, browserState) {
      const salt = String(sessionState).split('.').pop();
      return stsCrypto.sessionStateHash('sm-rp', RP, browserState, salt) ===
             sessionState;
    };

    // --- off: nothing ------------------------------------------------------
    let r = await request(port, 'GET', sm.IFRAME_PATH);
    note(r.status === 404 && /oauth2\.sessionManagement/.test(r.text) &&
           !/Cannot GET/.test(r.text),
         '3a. off (the default), the OP iframe is a 404 naming the setting, ' +
         'not Express\'s', r.status + ' ' + r.text.slice(0, 120));
    r = await request(port, 'GET', sm.SCRIPT_PATH);
    note(r.status === 404, '3a. and so is its script', r.status);
    r = await request(port, 'GET', '/.well-known/openid-configuration');
    note(r.status === 200 && r.json &&
           r.json.check_session_iframe === undefined,
         '3a. and discovery does not name it');
    let flow = await signIn('sm-alice');
    note(paramsOf(flow).get('code') && !paramsOf(flow).get('session_state') &&
           jar[sm.COOKIE] === undefined,
         '3a. and an authentication response carries no session_state and ' +
         'writes no browser state', String(flow.headers.location || ''));
    jar = {};

    // --- on ----------------------------------------------------------------
    config.setOverride('oauth2.sessionManagement', true);
    r = await request(port, 'GET', '/.well-known/openid-configuration');
    note(r.json && r.json.check_session_iframe === BASE + sm.IFRAME_PATH,
         '3b. on, discovery names check_session_iframe',
         r.json && r.json.check_session_iframe);
    r = await request(port, 'GET', sm.IFRAME_PATH);
    const csp = String(r.headers['content-security-policy'] || '');
    const ancestors = (/frame-ancestors ([^;]*)/.exec(csp) || [])[1] || '';
    note(r.status === 200 && ancestors.split(' ').indexOf(RP) >= 0 &&
           ancestors.indexOf('*') < 0 && ancestors.indexOf("'none'") < 0 &&
           /script-src 'self'/.test(csp) && /base-uri 'none'/.test(csp) &&
           r.headers['x-frame-options'] === undefined &&
           /<script src="check_session\.js"><\/script>/.test(r.text),
         '3c. the OP iframe: frame-ancestors the registered relying ' +
         'parties, no *, script-src \'self\', no X-Frame-Options',
         csp + ' | xfo=' + r.headers['x-frame-options']);
    r = await request(port, 'GET', sm.SCRIPT_PATH);
    note(r.status === 200 && /javascript/.test(r.headers['content-type']) &&
           r.text === sm.IFRAME_SCRIPT,
         '3c. and its script is served beside it');
    note(/frame-ancestors 'none'/.test(app.framedContentSecurityPolicy([])) &&
           /frame-ancestors 'none'/.test(
             app.framedContentSecurityPolicy(['*', 'https:',
                                              'https://x.example/path'])),
         '3c. the framing door cannot be opened to everyone: no origin, or ' +
         'nothing but non-origins, is \'none\'');

    flow = await signIn('sm-alice');
    let p = paramsOf(flow);
    const first = jar[sm.COOKIE];
    note(p.get('code') && p.get('session_state') && first &&
           holds(p.get('session_state'), first),
         '3d. a sign-in: session_state over the browser state written beside ' +
         'it', String(flow.headers.location || '') + ' bs=' + first);
    const setLines = [].concat(flow.headers['set-cookie'] || []);
    note(setLines.some(function (line) {
      return line.indexOf(sm.COOKIE + '=') === 0 && !/HttpOnly/i.test(line);
    }), '3d. and that cookie is readable by script', setLines.join(' | '));
    r = await request(port, 'GET', query({ prompt: 'none' }));
    p = paramsOf(r);
    note(p.get('code') && holds(p.get('session_state'), first) &&
           jar[sm.COOKIE] === first,
         '3e. prompt=none on the same session: the same browser state',
         String(r.headers.location || ''));
    const heldState = p.get('session_state');

    const afterLogout = await request(port, 'GET', '/oauth2/logout');
    note(jar[sm.COOKIE] === '' || jar[sm.COOKIE] === undefined,
         '3f. a sign-out clears the browser state',
         afterLogout.status + ' bs=' + jar[sm.COOKIE] + ' ' +
         JSON.stringify(afterLogout.headers['set-cookie'] || []));
    note(!holds(heldState, jar[sm.COOKIE] || ''),
         '3f. so the relying party\'s session_state no longer holds (the ' +
         'iframe says changed)');
    r = await request(port, 'GET', query({ prompt: 'none' }));
    p = paramsOf(r);
    note(p.get('error') === 'login_required' && p.get('session_state') &&
           holds(p.get('session_state'), ''),
         '3g. prompt=none with no session: login_required, with a ' +
         'session_state over the empty state', String(r.headers.location));
    flow = await signIn('sm-alice');
    note(jar[sm.COOKIE] && jar[sm.COOKIE] !== first &&
           holds(paramsOf(flow).get('session_state'), jar[sm.COOKIE]),
         '3h. signing in again mints a new browser state',
         first + ' -> ' + jar[sm.COOKIE]);

    r = await request(port, 'GET', query({ scope: 'profile' }));
    note(paramsOf(r).get('code') && !paramsOf(r).get('session_state'),
         '3i. an OAuth request without openid gets no session_state',
         String(r.headers.location || ''));

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
  t.log.info('=== 3. the endpoints, in a child process ===');
  const out = path.join(os.tmpdir(), 'session-management-' + process.pid +
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
                         { LOG_LEVEL: 'fatal', SM_ROOT: ROOT, SM_OUT: out }),
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
  t.check(findings.length >= 16, 'the child ran every section',
          findings.length + ' finding(s)');
  log.debug("Leaving inAChild().");
}

async function run(t) {
  log.debug("Entering run().");
  await library(t);
  inAChild(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'session management',
  describe: 'OpenID Connect Session Management 1.0 (#121): session_state, ' +
            'the OP browser state, the OP iframe and its script',
  run: run
};
