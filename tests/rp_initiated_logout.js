// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

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
//      cookie clear. The page names WHY it asks, one sentence per case
//      (#1301): no id_token_hint (and, where the address will not be
//      followed, that the person is not sent on to it), no cookie, a hint
//      for another session, a logout_hint naming somebody else.
//   c. THE HINT: a verified id_token_hint for THIS session signs out at once
//      and returns to the registered address WITH state, by GET and by POST;
//      a tampered hint, and a client_id it was not issued to, are refused
//      and the session survives; a logout_hint naming somebody else asks.
//   d. THE RETURN: a registered client is held to its own list exactly (an
//      unregistered address is not followed, and the page says why in a
//      warning box beside the "signed out" one (#1302) — a query added to
//      the registered address too, in the page's language), a
//      private-use address nobody registered is not followed, and
//      development still follows an http(s) address for a client that
//      registered none. No session at all: straight back, with state.
//   e. THE AUTHORIZATION ENDPOINT'S OWN REFUSALS, read on the same server
//      and client (2026-11-04): a redirect_uri this client did not register
//      or none at all is a 400 that a browser reads as the error page and
//      anything else as JSON, with the same values; a request with no
//      redirect_uri says it has none (#1302), an empty or malformed one
//      keeps its own sentence; a request for an ID Token with no nonce says
//      it has no nonce.
//   f. THE SECOND SIGN-IN'S NOTICE (#1302): prompt=login, or a session
//      older than max_age, puts the reason in `/authn-api`'s view and one
//      line on the screen; a first sign-in and prompt=login with no
//      session draw none, prompt=select_account is the account picker and
//      a max_age the session meets is answered at once, as they were.
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
    const screen = require(ROOT + '/tests/tools/authn_screen');
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
      // THE SCREEN OVER `/authn-api` (#571): the shell, the view and the
      // act, this test's jar kept; read as the 303 the form answered.
      const posted = await screen.submit({ port: port, jar: jar,
        at: String(r.headers.location),
        fields: { action: 'login', username: username,
                  password: 'anything' } });
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
    // WHY IT ASKS, one sentence per case (#1301): what the request lacked,
    // and — where the address it named will not be followed — that the
    // person is not sent on to it. Read as the page's closing sentence.
    const whyOf = function (text) {
      return ((/<\/form><p class="sub">([\s\S]*?)<\/p>/.exec(String(text)) ||
               [])[1] || '');
    };
    const NO_HINT = 'This sign-out request carried no id_token_hint, so ' +
      'this service cannot tell which application sent it';
    const SECTION = ' (RP-Initiated Logout 1.0 section 2).';
    const emptyQuoted = function (text) {
      return /<code>\s*<\/code>|""|\(\s*\)/.test(String(text));
    };
    let why = whyOf(r.text);
    note(why === NO_HINT + SECTION && !emptyQuoted(why),
         'b1b. no hint, a client that registered the address: the page says ' +
         'the request carried no id_token_hint, and promises nothing about ' +
         'the return it will make', why);
    let w = await logout({ post_logout_redirect_uri:
                             'https://rp.rl.example/any', state: 's' });
    why = whyOf(w.text);
    note(w.status === 200 && !w.headers.location &&
           why === NO_HINT + ', and it will not send you on to <code>' +
             'https://rp.rl.example/any</code> afterwards' + SECTION &&
           await alive(),
         'b1c. no hint and an address no client vouches for: the page says ' +
         'what was missing and that the person will not be sent on to it',
         why);
    w = await logout({ client_id: 'rl-rp',
                       post_logout_redirect_uri: 'https://evil.example/x' });
    why = whyOf(w.text);
    note(why === NO_HINT + ', and it will not send you on to <code>' +
           'https://evil.example/x</code> afterwards' + SECTION,
         'b1d. no hint and an address the named client did not register: ' +
         'the same, naming that address', why);
    w = await logout({});
    why = whyOf(w.text);
    note(w.status === 200 && why === NO_HINT + SECTION &&
           !emptyQuoted(why) && await alive(),
         'b1e. no parameters at all: the page says the request carried no ' +
         'id_token_hint, and names no address', why);
    w = await logout({ state: 'only-state', client_id: 'rl-rp' });
    why = whyOf(w.text);
    note(why === NO_HINT + SECTION && !emptyQuoted(why),
         'b1f. only state and client_id: the same sentence', why);
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
    note(whyOf(d.text) === 'This sign-out request arrived without the ' +
           'sign-in cookie of this browser, as a form sent from another ' +
           'site does, so this service cannot tell which session it is for' +
           SECTION,
         'b4b. and the page says the request came without this browser\'s ' +
         'sign-in cookie', whyOf(d.text));
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
    // c2b/c2c (2026-11-04): the OpenID Foundation's
    // oidcc-rp-initiated-logout-modified-id-token-hint re-heads the hint as
    // alg none, and the refusal page must say THAT, not quote an empty key.
    const parts = idToken.split('.');
    const reheaded = function (header) {
      return Buffer.from(JSON.stringify(header)).toString('base64url') +
        '.' + parts[1] + '.';
    };
    r = await logout({ id_token_hint: reheaded({ alg: 'none' }) });
    note(r.status === 400 && await alive() &&
         /is unsigned \(alg none\)/.test(r.text) && !/key ""/.test(r.text),
         'c2b. an alg-none hint is refused as unsigned, naming no empty key',
         r.status + ' ' + (String(r.text).match(/<p>[^<]*/) || [''])[0]
           .slice(3, 220));
    const head = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
    delete head.kid;
    r = await logout({ id_token_hint: reheaded(head) + parts[2] });
    // An RS or PS hint is checked by signature against the realm's own RSA
    // key, never looked up by kid, so here it is refused as not verifying;
    // a kid-looked-up algorithm says it names no key. Either way no refusal
    // quotes an empty key name.
    note(r.status === 400 && await alive() && !/key ""/.test(r.text) &&
         !/\.\.(\s|<|$)/.test(r.text),
         'c2c. a signed hint with no kid is refused, quoting no empty key',
         r.status + ' ' + (String(r.text).match(/<p>[^<]*/) || [''])[0]
           .slice(3, 220));
    r = await logout({ id_token_hint: idToken, client_id: 'rl-bare' });
    note(r.status === 400 && await alive(),
         'c3. a client_id the hint was not issued to is refused', r.status);
    r = await logout({ id_token_hint: idToken, logout_hint: 'somebody-else' });
    note(r.status === 200 && /name="confirm_for"/.test(r.text) &&
           await alive(),
         'c4. a logout_hint naming somebody else asks, even with the hint');
    note(whyOf(r.text) === 'The logout_hint in this sign-out request ' +
           'names somebody other than the person signed in to this browser' +
           SECTION,
         'c4b. and the page says the logout_hint names somebody else',
         whyOf(r.text));
    // A hint for an EARLIER session: verified, and its sid not this one.
    const earlier = idToken;
    await signIn('rl-alice');
    r = await logout({ id_token_hint: earlier });
    note(r.status === 200 && /name="confirm_for"/.test(r.text) &&
           whyOf(r.text) === 'The id_token_hint in this sign-out request ' +
             'was issued to another session, not the one signed in to this ' +
             'browser' + SECTION && await alive(),
         'c4c. a hint for another session asks, and the page says so',
         whyOf(r.text));
    idToken = await signIn('rl-alice');
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
           /it was not followed/.test(r.text) && !(await alive()),
         'd1. a registered client is held to its own list: an address it ' +
         'did not register is not followed, and the page says why',
         r.status + ' ' + r.headers.location);
    // d1b (#1302): the refusal is a WARNING BOX beside the "signed out"
    // one, leading with what was wrong, then both addresses and the
    // section — where it was a grey sentence under a green banner.
    const warningOf = function (text) {
      return (String(text).match(
        /<div class="warn" role="alert" id="logout-not-registered">[\s\S]*?<\/div>/) ||
        [''])[0];
    };
    const warningFor = function (uri) {
      return '<div class="warn" role="alert" id="logout-not-registered">' +
        '<strong>The post_logout_redirect_uri in this sign-out request is ' +
        'not one this client registered, so it was not followed.</strong> ' +
        'The request named <code>' + uri + '</code>; this client ' +
        'registered <code>' + BACK + '</code> (RP-Initiated Logout 1.0 ' +
        'section 3).</div>';
    };
    const okAt = String(r.text).indexOf('<div class="ok">');
    note(warningOf(r.text) === warningFor('https://evil.example/x') &&
           okAt >= 0 && String(r.text).indexOf(warningOf(r.text)) > okAt &&
           !/You were not returned/.test(r.text) &&
           /\.warn\{background:#fff8e1;border-left:4px solid #b26a00;/
             .test(r.text) &&
           /<h1>Signed out<\/h1>/.test(r.text),
         'd1b. and the page says so in a warning box as prominent as the ' +
         '"signed out" banner, after it: not one this client registered, ' +
         'not followed, both addresses, the section', warningOf(r.text) ||
         r.text.slice(-700));
    // d1c (#1302): the suite's other case, the registered address with a
    // query added — the same box, naming the address as sent, and the
    // session still ended.
    idToken = await signIn('rl-alice');
    r = await logout({ id_token_hint: idToken,
                       post_logout_redirect_uri: BACK + '?extra=1' });
    note(r.status === 200 && !r.headers.location && !(await alive()) &&
           warningOf(r.text) === warningFor(BACK + '?extra=1'),
         'd1c. a query added to the registered address: not followed, the ' +
         'same box, the session ended', r.status + ' ' + warningOf(r.text));
    // d1d (#1302): in the page's language, the addresses unchanged.
    idToken = await signIn('rl-alice');
    r = await logout({ id_token_hint: idToken, ui_locales: 'fr',
                       post_logout_redirect_uri: 'https://evil.example/x' });
    note(r.status === 200 && !(await alive()) &&
           /^<div class="warn" role="alert" id="logout-not-registered"><strong>Le post_logout_redirect_uri de cette demande de déconnexion n’est pas l’un de ceux que ce client a enregistrés/
             .test(warningOf(r.text)) &&
           warningOf(r.text).indexOf('<code>https://evil.example/x</code>') >
             0 && warningOf(r.text).indexOf('<code>' + BACK + '</code>') > 0,
         'd1d. ui_locales=fr: the box in French, the addresses as they are',
         warningOf(r.text));
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
         'development either (STS-OAUTH-0785), and the page says why',
         r.status + ' ' + r.headers.location);
    r = await logout({});
    note(r.status === 200 && /text\/html/.test(r.headers['content-type']) &&
           !/mock/i.test(r.text),
         'd4. with nowhere to return, a page — not text/plain "mock"',
         r.headers['content-type']);

    // --- e. the authorization endpoint's own refusals ------------------------
    jar = {};
    const authorize = function (params, accept) {
      return request(port, 'GET', '/oauth2/authorize?' +
        new URLSearchParams(Object.assign({ client_id: 'rl-rp',
          response_type: 'code', scope: 'openid', state: 'st', nonce: 'n' },
          params)).toString(),
        { headers: accept ? { accept: accept } : {} });
    };
    const HTML = 'text/html,application/xhtml+xml,*/*;q=0.8';
    const WRONG = 'https://rp.rl.example/elsewhere';
    const SENTENCE = '\'' + WRONG + '\' is not the redirect URI registered ' +
      'for this client (' + REDIRECT + ')';
    const plain = await authorize({ redirect_uri: WRONG });
    const page = await authorize({ redirect_uri: WRONG }, HTML);
    const described = String((plain.json || {}).error_description || '');
    note(plain.status === 400 && !plain.headers.location &&
           plain.json && plain.json.error === 'invalid_request' &&
           described.indexOf(SENTENCE) >= 0 &&
           !/the 1 |\(s\)|ou=|oauthRedirectUri|none of/.test(described),
         'e1. an unregistered redirect_uri is a 400, never redirected, and ' +
         'says it is not the redirect URI registered for this client, with ' +
         'no directory detail', plain.status + ' ' + described);
    note(page.status === 400 && !page.headers.location &&
           /text\/html/.test(String(page.headers['content-type'])) &&
           /<h1>This request could not be completed<\/h1>/.test(page.text) &&
           page.text.indexOf('invalid_request') >= 0 &&
           page.text.replace(/&#39;|&#x27;|&apos;/g, '\'')
             .indexOf(SENTENCE) >= 0,
         'e2. and a browser is shown that refusal on the error page, with ' +
         'the same status, error and description',
         page.status + ' ' + page.headers['content-type'] + ' ' +
         page.text.slice(-500));
    const none = await authorize({}, HTML);
    const noneJson = await authorize({});
    // #1302: the sentence says the request HAS none; the status, the
    // error and the page are what they were.
    const NONE = 'This authorization request has no redirect_uri, and one ' +
      'is required: without it there is nowhere to send the response.';
    note(none.status === 400 && !none.headers.location &&
           /text\/html/.test(String(none.headers['content-type'])) &&
           /<h1>This request could not be completed<\/h1>/.test(none.text) &&
           none.text.indexOf('invalid_request') >= 0 &&
           none.text.indexOf(NONE) >= 0 &&
           noneJson.status === 400 && noneJson.json &&
           noneJson.json.error === 'invalid_request' &&
           noneJson.json.error_description === NONE,
         'e3. no redirect_uri: the error page for a browser, the JSON ' +
         'otherwise, both 400 invalid_request, saying the request has none',
         none.status + ' ' + noneJson.status + ' ' +
         noneJson.text.slice(0, 300));
    const empty = await authorize({ redirect_uri: '' });
    const bad = await authorize({ redirect_uri: 'not a uri' });
    note(empty.status === 400 && !empty.headers.location && empty.json &&
           empty.json.error === 'invalid_request' &&
           empty.json.error_description ===
             'A valid absolute redirect_uri is required.' &&
           bad.status === 400 && !bad.headers.location && bad.json &&
           bad.json.error === 'invalid_request' &&
           String(bad.json.error_description || '').indexOf(NONE) < 0 &&
           String(bad.json.error_description || '').length > 0,
         'e3b. one that is present and empty keeps "A valid absolute ' +
         'redirect_uri is required.", and a malformed one keeps the ' +
         'validator\'s sentence; neither says the request has none',
         empty.text.slice(0, 200) + ' | ' + bad.text.slice(0, 200));
    const noNonce = await request(port, 'GET', '/oauth2/authorize?' +
      new URLSearchParams({ client_id: 'rl-rp', response_type: 'id_token',
        redirect_uri: REDIRECT, scope: 'openid', state: 'st' }).toString());
    const noNonceAt = decodeURIComponent(
      String(noNonce.headers.location || '') + ' ' + noNonce.text)
      .replace(/\+/g, ' ');
    note(/this request has no nonce, and response_type .id_token. returns an ID Token from the authorization endpoint, for which OIDC Core makes nonce REQUIRED \(section 3\.2\.2\.1, the implicit flow\)/
           .test(noNonceAt),
         'e4. an implicit request with no nonce is told it has none',
         noNonce.status + ' ' + noNonceAt.slice(0, 400));

    // --- f. the second sign-in's notice (#1302) ------------------------------
    // The authorization endpoint's reason rides the pending sign-in into
    // `/authn-api`'s view, and the screen draws one line for it.
    const T = require(ROOT + '/common/i18n').translator(['en']);
    const WebAuthnLogin = require(ROOT + '/authn/web_authn_login');
    const PROMPT_LOGIN = 'The application asked you to sign in again ' +
      '(prompt=login).';
    const MAX_AGE = 'The application asked you to sign in again because ' +
      'your last sign-in is older than it allows (max_age).';
    const screenAfter = async function (extra) {
      const asked = await request(port, 'GET', '/oauth2/authorize?' +
        new URLSearchParams(Object.assign({ client_id: 'rl-rp',
          response_type: 'code', redirect_uri: REDIRECT, scope: 'openid',
          state: 'st', nonce: 'n-f' }, extra || {})).toString());
      const at = String(asked.headers.location || '');
      if (!/\/authn\/login\?/.test(at)) {
        return { at: at, view: null, drawn: '' };
      }
      const opened = await screen.open({ port: port, jar: jar, at: at });
      const view = opened.view || null;
      let drawn = '';
      try {
        drawn = view ? WebAuthnLogin.render(view, { t: T, error: '' }) : '';
      } catch (e) {
        drawn = 'render threw: ' + ((e && e.message) || e);
      }
      return { at: at, view: view, drawn: drawn };
    };
    const noticeOf = function (drawn) {
      return (String(drawn).match(
        /<div class="warn" id="authn-reauthentication">[\s\S]*?<\/div>/) ||
        [''])[0];
    };
    jar = {};
    let f = await screenAfter({});
    note(f.view && f.view.reauthentication === '' &&
           /<h1>/.test(f.drawn) && noticeOf(f.drawn) === '' &&
           WebAuthnLogin.reauthentication('', T) === '' &&
           WebAuthnLogin.reauthentication('select_account', T) === '',
         'f1. a first sign-in: no reason in the view, no notice on the screen',
         f.at + ' ' + JSON.stringify(f.view && f.view.reauthentication) +
         ' ' + f.drawn.slice(0, 200));
    f = await screenAfter({ prompt: 'login' });
    note(f.view && f.view.reauthentication === '' &&
           noticeOf(f.drawn) === '',
         'f1b. prompt=login with no session is a first sign-in too',
         JSON.stringify(f.view && f.view.reauthentication));
    await signIn('rl-alice');
    f = await screenAfter({ prompt: 'login' });
    note(f.view && f.view.reauthentication === 'prompt_login' &&
           T.text('authn.login.reauthPromptLogin') === PROMPT_LOGIN &&
           noticeOf(f.drawn) ===
             '<div class="warn" id="authn-reauthentication">' + PROMPT_LOGIN +
             '</div>' &&
           f.drawn.indexOf(noticeOf(f.drawn)) >
             f.drawn.indexOf('<p class="sub">'),
         'f2. prompt=login with a session: the screen says the application ' +
         'asked for a second sign-in, under the heading',
         f.at + ' ' + JSON.stringify(f.view && f.view.reauthentication) +
         ' ' + noticeOf(f.drawn));
    // `authn.multipleAccounts` is on by default, so select_account is the
    // account picker, as it was — never the screen with a notice.
    f = await screenAfter({ prompt: 'select_account' });
    note(!f.view && /\/authn\/accounts\?/.test(f.at),
         'f3. prompt=select_account: the account picker, as it was — not a ' +
         'reason the notice names', f.at);
    f = await screenAfter({ max_age: '3600' });
    note(!f.view && /[?&]code=/.test(f.at) && f.at.indexOf(REDIRECT) === 0,
         'f4. a max_age the session meets: answered at once, as it was',
         f.at.slice(0, 120));
    await new Promise(function (done) { setTimeout(done, 2100); });
    f = await screenAfter({ max_age: '1' });
    note(f.view && f.view.reauthentication === 'max_age' &&
           T.text('authn.login.reauthMaxAge') === MAX_AGE &&
           noticeOf(f.drawn) ===
             '<div class="warn" id="authn-reauthentication">' + MAX_AGE +
             '</div>',
         'f5. a session older than max_age: the screen says the last ' +
         'sign-in is older than the application allows',
         f.at + ' ' + JSON.stringify(f.view && f.view.reauthentication) +
         ' ' + noticeOf(f.drawn));
    const fr = require(ROOT + '/common/i18n').translator(['fr']);
    note(WebAuthnLogin.reauthentication('prompt_login', fr) ===
           '<div class="warn" id="authn-reauthentication">L’application ' +
           'vous a demandé de vous reconnecter (prompt=login).</div>',
         'f6. the notice is drawn in the page\'s language',
         WebAuthnLogin.reauthentication('prompt_login', fr));

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
