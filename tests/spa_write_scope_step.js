// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/spa_write_scope_step.js
//
// ---------------------------------------------------------------------------
// THE THREE BROWSER APPLICATIONS SIGN IN WITH READ SCOPES, AND A WRITE ASKS
// FOR ITS SCOPE BY A SECOND AUTHORIZATION (#2168, ASVS 5.0.0 10.2.3).
//
// rcbj's decision: the console, the portal and the reports application each
// sign in with read scopes only; the first time a page writes, the
// application gets the write scope through a second authorization, silent
// (`prompt=none`) while the sign-on session holds and a fresh sign-in for
// `admin:security`; the read token keeps being used for reading. Each
// runtime is driven here in process with stand-ins for the browser, the
// token endpoint and the API:
//
//   1. each application's first authorization request asks read scopes
//      only;
//   2. a write the API refuses `insufficient_scope` opens the second
//      authorization at once, `prompt=none`, for the read scopes and the
//      scope named, in a window whose state is a step's;
//   3. the window's callback hands the code back and redeems nothing;
//   4. the opener redeems it with its own verifier for the API's resource,
//      keeps no refresh token from it, and sends the write once more with
//      the write token — and a GET still goes with the read token;
//   5. the write token is not used past its life, and is never refreshed;
//   6. `admin:security` is asked silently only of a sign-in within
//      `max_age`, and otherwise with `prompt=login` and `max_age=0`, the
//      window waiting for the person's press;
//   7. another account coming back sends nothing, and the refusal is what
//      the page gets;
//   8. the portal steps to `account:manage` for `/account-api`, and the
//      reports application to whichever report scope the roles allow;
//   9. AFTER THE REALM SWITCHER (#2200): a service administrator signed in
//      at the default realm, on a realm's page, is stepped by the DEFAULT
//      realm's authorization server — its authorize URL, its token request,
//      its callback and its management API as the resource — while the
//      write itself still goes to the realm on screen; and the reports
//      application's step after its realm field moved the page likewise.
//      (The portal has no realm switcher: its prefix never moves.)
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const SpaClient = require('../common/web_spa_client');
const ConsoleRuntime = require('../admin-ui/web_runtime');
const PortalRuntime = require('../portal/web_portal_runtime');
const ReportRuntime = require('../report/web_report_pages');

const log = require('bunyan').createLogger({
  name: 'spa_write_scope_step',
  level: process.env.LOG_LEVEL || 'info' });

const ORIGIN = 'https://sts.example.com';

/**
 * The nonce a sign-in with this PKCE verifier sends.
 *
 * @param verifier - the PKCE verifier
 * @returns the nonce
 */
function nonceOf(verifier) {
  log.debug("Entering nonceOf().");
  log.debug("Leaving nonceOf().");
  return nodeCrypto.createHash('sha256').update('nonce:' + verifier)
    .digest('base64url');
}

/**
 * An unsigned JWT carrying a subject and a nonce, as the token endpoint's
 * ID Token.
 *
 * @param sub - the subject
 * @param nonce - the nonce
 * @returns the compact JWT
 */
function idTokenFor(sub, nonce) {
  log.debug("Entering idTokenFor().");
  const b64u = function (o) {
    return Buffer.from(JSON.stringify(o)).toString('base64url');
  };
  log.debug("Leaving idTokenFor().");
  return b64u({ alg: 'ES256' }) + '.' + b64u({
    sub: sub, nonce: nonce,
    aud: ['sts-admin-console', 'sts-user-portal', 'sts-report'] }) + '.sig';
}

/**
 * Waits until a condition holds, or ten seconds.
 *
 * @param fn - the condition
 * @returns nothing
 */
async function until(fn) {
  log.debug("Entering until().");
  const deadline = Date.now() + 10000;
  while (!fn() && Date.now() < deadline) {
    await new Promise(function (resolve) { setImmediate(resolve); });
  }
  log.debug("Leaving until().");
}

/**
 * A browser on one of the applications' pages, with stand-ins for the token
 * endpoint and the API.
 *
 * @param pathname - the page's path
 * @param api - `(method, url, token)` answering `{ status, challenge }`
 * @param answer - what the token endpoint's ID Token and scope are:
 *   `{ sub, scope }`
 * @returns `{ env, calls, channels, opened, elements, store, closed }`
 */
function browser(pathname, api, answer) {
  log.debug("Entering browser().");
  const calls = [];
  const channels = [];
  const opened = [];
  const store = {};
  const elements = {};
  const state = { closed: 0, now: Date.now() };
  const body = {
    appendChild: function (el) { elements[el.id] = el; el.parentNode = body; },
    removeChild: function (el) { delete elements[el.id]; }
  };
  class Channel {
    constructor(name) {
      this.name = name;
      this.posted = [];
      this.closed = false;
      this.onmessage = null;
      channels.push(this);
    }
    postMessage(data) {
      this.posted.push(data);
    }
    close() {
      this.closed = true;
    }
  }
  const location = { pathname: pathname, search: '', hash: '',
                     href: ORIGIN + pathname, origin: ORIGIN, assigned: '',
                     assign: function (u) { location.assigned = u; } };
  const env = {
    location: location,
    now: function () { return state.now; },
    history: { replaceState: function () {}, pushState: function () {} },
    crypto: globalThis.crypto,
    sessionStorage: {
      getItem: function (k) { return k in store ? store[k] : null; },
      setItem: function (k, v) { store[k] = String(v); },
      removeItem: function (k) { delete store[k]; }
    },
    navigator: { languages: ['en'] },
    document: {
      title: '', body: body,
      documentElement: { getAttribute: function () { return null; },
                         setAttribute: function () {} },
      createElement: function () {
        return { setAttribute: function () {}, innerHTML: '' };
      },
      getElementById: function (id) { return elements[id] || null; },
      querySelectorAll: function () { return []; },
      querySelector: function () { return null; }
    },
    window: {
      BroadcastChannel: Channel,
      open: function (url) { opened.push(url); return {}; },
      close: function () { state.closed++; }
    },
    fetch: async function (url, init) {
      const sent = init || {};
      calls.push({ url: String(url), init: sent });
      const headers = function (challenge) {
        return { get: function (n) {
          return n === 'WWW-Authenticate' ? (challenge || '') : '';
        } };
      };
      if (/\/oauth2\/token$/.test(String(url))) {
        const form = new URLSearchParams(String(sent.body || ''));
        const verifier = form.get('code_verifier') || '';
        return { status: 200, headers: headers(''),
                 json: async function () {
                   return { access_token: 'write-at', expires_in: 300,
                            refresh_token: 'write-rt',
                            scope: answer.scope,
                            id_token: idTokenFor(answer.sub,
                                                 nonceOf(verifier)) };
                 } };
      }
      if (/well-known|\/locales?\/|\/web\//.test(String(url))) {
        return { status: 404, headers: headers(''),
                 json: async function () { return {}; } };
      }
      const auth = String((sent.headers && sent.headers.Authorization) ||
                          '').replace(/^DPoP /, '');
      const said = api(String(sent.method || 'GET').toUpperCase(),
                       String(url), auth);
      return { status: said.status, headers: headers(said.challenge),
               json: async function () { return { ok: said.status === 200 }; },
               arrayBuffer: async function () { return new ArrayBuffer(0); } };
    }
  };
  log.debug("Leaving browser().");
  return { env: env, calls: calls, channels: channels, opened: opened,
           elements: elements, store: store, state: state };
}

/**
 * The API stand-in: a GET answers on any token, anything else only on the
 * write token, and the read token's write is refused `insufficient_scope`
 * naming `scope`.
 *
 * @param scope - the scope the refusal names
 * @returns the stand-in
 */
function apiNaming(scope) {
  log.debug("Entering apiNaming().");
  log.debug("Leaving apiNaming().");
  return function (method, url, token) {
    if (method === 'GET' || token === 'write-at') {
      return { status: 200 };
    }
    return { status: 403,
             challenge: 'DPoP error="insufficient_scope", scope="' + scope +
                        '"' };
  };
}

/**
 * Signs a runtime in, as a callback would have: the read token in hand.
 *
 * @param rt - the runtime
 * @returns nothing
 */
function signedIn(rt) {
  log.debug("Entering signedIn().");
  rt.subject = 'urn:uuid:alice';
  rt.accessToken = 'read-at';
  rt.refreshToken = 'read-rt';
  rt.expiresAt = Date.now() + 3600000;
  log.debug("Leaving signedIn().");
}

/**
 * The scope an authorization request asks for.
 *
 * @param url - the request's URL
 * @returns the scope values
 */
function scopeOf(url) {
  log.debug("Entering scopeOf().");
  log.debug("Leaving scopeOf().");
  return String(new URL(url).searchParams.get('scope') || '').split(' ');
}

/**
 * Answers a step's window on the opener's channel, as its callback does.
 *
 * @param b - the browser
 * @param url - the window's authorization request
 * @param data - what the callback hands back, beside the state
 * @returns nothing
 */
function answerStep(b, url, data) {
  log.debug("Entering answerStep().");
  const state = new URL(url).searchParams.get('state');
  b.channels.filter(function (c) {
    return c.name === SpaClient.STEP_CHANNEL && c.onmessage;
  }).forEach(function (c) {
    c.onmessage({ data: Object.assign({ state: state }, data) });
  });
  log.debug("Leaving answerStep().");
}

async function run(t) {
  log.debug("Entering run().");

  // 1. The first authorization request of each, read scopes only.
  const firsts = [
    { name: 'console', rt: ConsoleRuntime, path: '/admin/users',
      at: '/admin', want: ['openid', 'admin:read', 'admin:console'] },
    { name: 'portal', rt: PortalRuntime, path: '/portal',
      at: '/portal', want: ['openid', 'account:read', 'owner:read'] },
    { name: 'reports', rt: ReportRuntime, path: '/report',
      at: '/report', want: ['openid', 'profile', 'email', 'offline_access',
                            'report:read'] }];
  for (const one of firsts) {
    const b = browser(one.path, apiNaming(''), { sub: 'x', scope: '' });
    const rt = new one.rt(b.env);
    await rt.beginSignIn(one.at);
    const asked = b.env.location.assigned ? scopeOf(b.env.location.assigned)
                                          : [];
    t.check(asked.length === one.want.length &&
            one.want.every(function (s) { return asked.indexOf(s) >= 0; }) &&
            !asked.some(function (s) {
              return /:(write|security|manage|use|admin)$/.test(s);
            }),
            '1. the ' + one.name + '\'s first authorization request asks ' +
            'read scopes only', asked.join(' '));
  }

  // 2-4. The console's write, refused for admin:write, stepped silently.
  const a = browser('/admin/users', apiNaming('admin:write'),
    { sub: 'urn:uuid:alice',
      scope: 'openid admin:read admin:console admin:write' });
  const console1 = new ConsoleRuntime(a.env);
  signedIn(console1);
  const target = ORIGIN + '/admin-api/users/update-fields';
  const sending = console1.send('POST', target, { user: 'bob' });
  await until(function () { return a.opened.length > 0; });
  const stepUrl = a.opened[0] ? new URL(a.opened[0]) : null;
  t.check(stepUrl && stepUrl.pathname === '/oauth2/authorize' &&
          stepUrl.searchParams.get('prompt') === 'none' &&
          !stepUrl.searchParams.get('max_age') &&
          /^step\./.test(stepUrl.searchParams.get('state') || '') &&
          stepUrl.searchParams.get('client_id') === 'sts-admin-console' &&
          stepUrl.searchParams.get('code_challenge_method') === 'S256' &&
          stepUrl.searchParams.get('resource') === ORIGIN + '/admin-api' &&
          ['openid', 'admin:read', 'admin:console', 'admin:write']
            .every(function (s) {
              return scopeOf(a.opened[0]).indexOf(s) >= 0;
            }) && scopeOf(a.opened[0]).indexOf('admin:security') < 0,
          '2. a write refused insufficient_scope opens a second ' +
          'authorization at once: prompt=none, the read scopes and ' +
          'admin:write, a step\'s state', a.opened[0]);
  t.check(!!a.elements['step-bar'] &&
          /data-step="cancel"/.test(a.elements['step-bar'].innerHTML),
          '2. a bar says what is happening, with Cancel',
          a.elements['step-bar'] && a.elements['step-bar'].innerHTML);

  // 3. The step's window, at the console's callback.
  const w = browser('/admin/callback', apiNaming(''), { sub: '', scope: '' });
  w.env.location.search = '?code=step-code&state=' +
    encodeURIComponent(stepUrl ? stepUrl.searchParams.get('state') : '');
  const win = new ConsoleRuntime(w.env);
  await win.finishSignIn();
  const handed = w.channels.filter(function (c) {
    return c.name === SpaClient.STEP_CHANNEL;
  })[0];
  t.check(handed && handed.posted.length === 1 &&
          handed.posted[0].code === 'step-code' && handed.closed &&
          w.state.closed === 1 &&
          !w.calls.some(function (c) { return /oauth2\/token/.test(c.url); }),
          '3. the window\'s callback hands the code back, closes and ' +
          'redeems nothing', JSON.stringify(handed && handed.posted));

  // 4. The opener redeems it and sends the write once more.
  answerStep(a, a.opened[0], { code: 'step-code' });
  const res = await sending;
  const redeem = a.calls.filter(function (c) {
    return /oauth2\/token$/.test(c.url);
  })[0];
  const form = redeem ? new URLSearchParams(redeem.init.body) : null;
  const writes = a.calls.filter(function (c) {
    return c.url === target;
  }).map(function (c) { return c.init.headers.Authorization; });
  t.check(form && form.get('grant_type') === 'authorization_code' &&
          form.get('code') === 'step-code' && !!form.get('code_verifier') &&
          form.get('resource') === ORIGIN + '/admin-api' &&
          form.get('redirect_uri') === ORIGIN + '/admin/callback' &&
          !!(redeem.init.headers && redeem.init.headers.DPoP),
          '4. the code is redeemed with the opener\'s verifier and DPoP ' +
          'key, for the management API', redeem && redeem.init.body);
  t.check(res && res.status === 200 && writes.length === 2 &&
          writes[0] === 'DPoP read-at' && writes[1] === 'DPoP write-at' &&
          !a.elements['step-bar'],
          '4. the write is sent once more, with the write token, and the ' +
          'bar is gone', JSON.stringify(writes));
  t.check(console1.refreshToken === 'read-rt' &&
          console1.accessToken === 'read-at',
          '4. no refresh token is kept from the second authorization, and ' +
          'the read token is the one kept for reading',
          console1.refreshToken);
  await console1.send('GET', ORIGIN + '/admin-api/users');
  const lastGet = a.calls.filter(function (c) {
    return /\/admin-api\/users$/.test(c.url);
  }).pop();
  t.check(lastGet && lastGet.init.headers.Authorization === 'DPoP read-at',
          '4. a GET afterwards still goes with the read token',
          lastGet && lastGet.init.headers.Authorization);
  const before = a.opened.length;
  await console1.send('POST', target, { user: 'carol' });
  t.check(a.opened.length === before,
          '4. a second write while the write token lives steps nothing');

  // 5. Past its life the write token is not sent, and nothing refreshes it.
  a.state.now = Date.now() + SpaClient.WRITE_HOLD_MS + 1000;
  const refreshes = a.calls.filter(function (c) {
    return /oauth2\/token$/.test(c.url) &&
           /write-rt/.test(String(c.init.body || ''));
  }).length;
  t.check(console1.tokenFor('POST', console1.resource()) === 'read-at' &&
          refreshes === 0,
          '5. a write token past its life is not sent, and was never ' +
          'refreshed', console1.tokenFor('POST', console1.resource()));

  // 6. admin:security: silent only for a recent sign-in, a fresh one
  //    otherwise, opened by the person's press.
  const s = browser('/admin/policies', apiNaming('admin:security'),
    { sub: 'urn:uuid:alice',
      scope: 'openid admin:read admin:console admin:security' });
  const console2 = new ConsoleRuntime(s.env);
  signedIn(console2);
  const securing = console2.send('POST', ORIGIN + '/admin-api/policies/save',
                                 { kind: 'x' });
  await until(function () { return s.opened.length > 0; });
  const recentUrl = s.opened[0] ? new URL(s.opened[0]) : null;
  t.check(recentUrl && recentUrl.searchParams.get('prompt') === 'none' &&
          recentUrl.searchParams.get('max_age') ===
            String(SpaClient.FRESH_MAX_AGE_S) &&
          scopeOf(s.opened[0]).indexOf('admin:security') >= 0,
          '6. admin:security is asked silently only of a sign-in within ' +
          'max_age=' + SpaClient.FRESH_MAX_AGE_S, s.opened[0]);
  answerStep(s, s.opened[0], { error: 'login_required' });
  await until(function () {
    return !!(console2.stepActions && console2.stepActions.open);
  });
  t.check(s.opened.length === 1 && !!console2.stepActions &&
          /data-step="open"/.test(s.elements['step-bar'].innerHTML),
          '6. an older sign-in opens no window by itself: the bar offers ' +
          'the sign-in', s.elements['step-bar'] &&
          s.elements['step-bar'].innerHTML);
  console2.stepActions.open();
  const freshUrl = s.opened[1] ? new URL(s.opened[1]) : null;
  t.check(freshUrl && freshUrl.searchParams.get('prompt') === 'login' &&
          freshUrl.searchParams.get('max_age') === '0' &&
          scopeOf(s.opened[1]).indexOf('admin:security') >= 0,
          '6. and that sign-in is a fresh one: prompt=login, max_age=0',
          s.opened[1]);
  answerStep(s, s.opened[1], { code: 'fresh-code' });
  const secured = await securing;
  t.check(secured && secured.status === 200,
          '6. after the fresh sign-in the security change is sent with the ' +
          'write token', secured && secured.status);

  // 7. Another account coming back: nothing is sent, the refusal stands.
  const m = browser('/admin/users', apiNaming('admin:write'),
    { sub: 'urn:uuid:mallory',
      scope: 'openid admin:read admin:console admin:write' });
  const console3 = new ConsoleRuntime(m.env);
  signedIn(console3);
  const refused = console3.send('POST', target, { user: 'bob' });
  await until(function () { return m.opened.length > 0; });
  answerStep(m, m.opened[0], { code: 'other-code' });
  const answered = await refused;
  t.check(answered && answered.status === 403 &&
          m.calls.filter(function (c) { return c.url === target; })
            .length === 1 &&
          !console3.writeTokenFor(console3.resource()),
          '7. another account coming back keeps no write token and sends ' +
          'nothing; the refusal is the answer',
          answered && answered.status);

  // 7b. A silent step the session cannot answer offers a sign-in.
  const l = browser('/admin/users', apiNaming('admin:write'),
    { sub: 'urn:uuid:alice',
      scope: 'openid admin:read admin:console admin:write' });
  const console4 = new ConsoleRuntime(l.env);
  signedIn(console4);
  const waiting = console4.send('POST', target, { user: 'bob' });
  await until(function () { return l.opened.length > 0; });
  answerStep(l, l.opened[0], { error: 'login_required' });
  await until(function () {
    return !!(console4.stepActions && console4.stepActions.open);
  });
  console4.stepActions.open();
  const interactive = l.opened[1] ? new URL(l.opened[1]) : null;
  t.check(interactive && !interactive.searchParams.get('prompt') &&
          scopeOf(l.opened[1]).indexOf('admin:write') >= 0,
          '7b. login_required from the silent step offers a sign-in in the ' +
          'window, without prompt=none', l.opened[1]);
  answerStep(l, l.opened[1], { code: 'signed-code' });
  const afterSignIn = await waiting;
  t.check(afterSignIn && afterSignIn.status === 200,
          '7b. and the write is sent after it',
          afterSignIn && afterSignIn.status);

  // 8. The portal steps to account:manage for /account-api.
  const p = browser('/portal/profile', apiNaming('account:manage'),
    { sub: 'urn:uuid:alice',
      scope: 'openid account:read owner:read account:manage' });
  const portal = new PortalRuntime(p.env);
  signedIn(portal);
  const posting = portal.apiJson('POST', '/account-api/profile',
                                 { displayName: 'A' });
  await until(function () { return p.opened.length > 0; });
  const portalStep = p.opened[0] ? new URL(p.opened[0]) : null;
  t.check(portalStep && portalStep.searchParams.get('prompt') === 'none' &&
          scopeOf(p.opened[0]).indexOf('account:manage') >= 0 &&
          portalStep.searchParams.get('client_id') === 'sts-user-portal',
          '8. the portal\'s write asks account:manage, silently',
          p.opened[0]);
  answerStep(p, p.opened[0], { code: 'portal-code' });
  const portalAnswer = await posting;
  const portalRedeem = p.calls.filter(function (c) {
    return /oauth2\/token$/.test(c.url);
  })[0];
  t.check(portalAnswer && portalAnswer.status === 200 && portalRedeem &&
          new URLSearchParams(portalRedeem.init.body).get('resource') ===
            ORIGIN + '/account-api',
          '8. and sends the write once more with a token for /account-api',
          portalAnswer && portalAnswer.status);

  // 8b. The reports application: either report scope will do.
  const r = browser('/report', apiNaming('report:use report:admin'),
    { sub: 'urn:uuid:alice',
      scope: 'openid profile email offline_access report:read report:use' });
  const reports = new ReportRuntime(r.env);
  signedIn(reports);
  const defining = reports.call('POST', '/report-api/definitions',
                                { name: 'x' });
  await until(function () { return r.opened.length > 0; });
  t.check(r.opened[0] &&
          scopeOf(r.opened[0]).indexOf('report:use') >= 0 &&
          scopeOf(r.opened[0]).indexOf('report:admin') >= 0 &&
          new URL(r.opened[0]).searchParams.get('prompt') === 'none',
          '8b. the reports application\'s write asks both report scopes, ' +
          'silently', r.opened[0]);
  answerStep(r, r.opened[0], { code: 'report-code' });
  const reported = await defining;
  t.check(reported && reported.status === 200,
          '8b. a write token carrying report:use alone is enough, and the ' +
          'write is sent once more', reported && reported.status);

  await afterTheSwitcher(t);
  log.debug("Leaving run().");
}

/**
 * 9. The step after the realm switcher asks the realm that issued the
 * tokens (#2200).
 *
 * @param t - the harness
 * @returns nothing
 */
async function afterTheSwitcher(t) {
  log.debug("Entering afterTheSwitcher().");
  const REALM = '/realm/acme';
  const sw = browser('/admin/users', apiNaming('admin:write'),
    { sub: 'urn:uuid:alice',
      scope: 'openid admin:read admin:console admin:write' });
  const console5 = new ConsoleRuntime(sw.env);
  signedIn(console5);
  // What the callback records with the tokens: the realm signed in at.
  console5.issuerPrefix = '';
  // The switcher, as the shell offers it; the page drawn is not this test's.
  console5.shell = { realms: [{ id: 'acme', prefix: REALM }] };
  console5.go = async function () {
    log.debug("Entering go().");
    log.debug("Leaving go().");
  };
  await console5.switchRealm('acme', '/admin/users');
  const target = ORIGIN + REALM + '/admin-api/users/update-fields';
  const sending = console5.send('POST', target, { user: 'bob' });
  await until(function () { return sw.opened.length > 0; });
  const step = sw.opened[0] ? new URL(sw.opened[0]) : null;
  t.check(step && step.origin + step.pathname ===
            ORIGIN + '/oauth2/authorize' &&
          step.searchParams.get('resource') === ORIGIN + '/admin-api' &&
          step.searchParams.get('redirect_uri') ===
            ORIGIN + '/admin/callback',
          '9. after the switcher the console\'s step is the signing-in ' +
          'realm\'s: its authorize endpoint, its management API and its ' +
          'callback, not ' + REALM + '\'s', sw.opened[0]);
  t.check(console5.resource() === ORIGIN + '/admin-api' &&
          console5.callbackUrl() === ORIGIN + '/admin/callback',
          '9. resource() and callbackUrl() stay the signing-in realm\'s',
          console5.resource() + ' ' + console5.callbackUrl());
  answerStep(sw, sw.opened[0], { code: 'switched-code' });
  const res = await sending;
  const redeem = sw.calls.filter(function (c) {
    return /oauth2\/token$/.test(c.url);
  })[0];
  const form = redeem ? new URLSearchParams(redeem.init.body) : null;
  t.check(redeem && redeem.url === ORIGIN + '/oauth2/token' && form &&
          form.get('resource') === ORIGIN + '/admin-api' &&
          form.get('redirect_uri') === ORIGIN + '/admin/callback',
          '9. the step\'s code is redeemed at the signing-in realm\'s token ' +
          'endpoint, for its management API', redeem && redeem.url + ' ' +
          redeem.init.body);
  const writes = sw.calls.filter(function (c) {
    return c.url === target;
  }).map(function (c) { return c.init.headers.Authorization; });
  t.check(res && res.status === 200 && writes.length === 2 &&
          writes[1] === 'DPoP write-at',
          '9. and the write goes, with the write token, to the realm on ' +
          'screen', JSON.stringify(writes));
  await console5.refresh();
  const renewed = sw.calls.filter(function (c) {
    return /oauth2\/token$/.test(c.url) &&
           /refresh_token/.test(String(c.init.body || ''));
  }).pop();
  t.check(renewed && renewed.url === ORIGIN + '/oauth2/token',
          '9. a refresh after the switcher asks the signing-in realm too',
          renewed && renewed.url);

  // The reports application, its realm field having moved the page.
  const rs = browser('/report', apiNaming('report:use'),
    { sub: 'urn:uuid:alice',
      scope: 'openid profile email offline_access report:read report:use' });
  const reports = new ReportRuntime(rs.env);
  signedIn(reports);
  reports.issuerPrefix = '';
  reports.prefix = REALM;
  const defining = reports.call('POST', '/report-api/definitions',
                                { name: 'x' });
  await until(function () { return rs.opened.length > 0; });
  const rstep = rs.opened[0] ? new URL(rs.opened[0]) : null;
  t.check(rstep && rstep.origin + rstep.pathname ===
            ORIGIN + '/oauth2/authorize' &&
          rstep.searchParams.get('redirect_uri') ===
            ORIGIN + '/report/callback' &&
          rstep.searchParams.get('resource') === ORIGIN + '/report-api',
          '9. the reports application\'s step after its realm field moved ' +
          'the page is the issuing realm\'s, callback and resource ' +
          'included', rs.opened[0]);
  answerStep(rs, rs.opened[0], { code: 'report-switched' });
  const reported = await defining;
  const rredeem = rs.calls.filter(function (c) {
    return /oauth2\/token$/.test(c.url);
  })[0];
  t.check(reported && reported.status === 200 && rredeem &&
          rredeem.url === ORIGIN + '/oauth2/token' &&
          new URLSearchParams(rredeem.init.body).get('redirect_uri') ===
            ORIGIN + '/report/callback' &&
          rs.calls.some(function (c) {
            return c.url === ORIGIN + REALM + '/report-api/definitions';
          }),
          '9. its code is redeemed at the issuing realm, and the write goes ' +
          'to the realm on screen', reported && reported.status);
  log.debug("Leaving afterTheSwitcher().");
}

module.exports = {
  name: 'spa write scope step',
  describe: 'the console, the portal and the reports application sign in ' +
            'with read scopes and ask a write scope by a second ' +
            'authorization (#2168)',
  run: run
};
