// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/console_reauth.js
//
// ---------------------------------------------------------------------------
// THE CONSOLE SIGNS IN AGAIN WITHOUT LOSING THE PAGE (#508).
//
// rcbj: when the console's sign-on session ends, the person signs in again
// through the central sign-in — always — and the page they were working on
// is not lost. `admin-ui/web_runtime.ts` is driven here in process with
// stand-ins for every browser object; the token endpoint and the API are
// stand-ins too, so what is held is the runtime's own behaviour:
//
//   1. a request that meets an ended session WAITS: a bar is drawn over the
//      page, and the popup it opens is the realm's own authorization request
//      (PKCE S256, a state marked as a popup's) — nothing else signs in;
//   2. the popup's callback hands its answer back over the channel and
//      redeems nothing itself;
//   3. the code handed back is redeemed with this page's verifier, and the
//      waiting request is then sent, once, with the new token;
//   4. a different `sub` coming back sends nothing that was waiting, and the
//      page is drawn again;
//   5. signing in on the page instead keeps the forms' values (never a
//      password, a hidden field or a secret) and the tab, and they are put
//      back after for the same page and person, a different person's
//      sign-in putting back nothing;
//   6. an ID Token's `sub` is read from the token response.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const ConsoleRuntime = require('../admin-ui/web_runtime');

const log = require('bunyan').createLogger({
  name: 'console_reauth',
  level: process.env.LOG_LEVEL || 'info' });

const ORIGIN = 'https://sts.example.com';

/**
 * An unsigned JWT carrying a subject, as the token endpoint's ID Token.
 *
 * @param sub - the subject
 * @returns the compact JWT
 */
function idTokenFor(sub) {
  log.debug("Entering idTokenFor().");
  const b64u = function (o) {
    return Buffer.from(JSON.stringify(o)).toString('base64url');
  };
  log.debug("Leaving idTokenFor().");
  return b64u({ alg: 'ES256' }) + '.' + b64u({ sub: sub }) + '.sig';
}

/**
 * A form control stand-in.
 *
 * @param name - its name
 * @param type - its type
 * @param value - its value
 * @param checked - for a box, whether it is ticked
 * @returns the control
 */
function control(name, type, value, checked) {
  log.debug("Entering control().");
  log.debug("Leaving control().");
  return { name: name, type: type, value: value, checked: !!checked,
           disabled: false,
           getAttribute: function () { return null; } };
}

/**
 * A form stand-in.
 *
 * @param action - its action
 * @param elements - its controls
 * @returns the form
 */
function form(action, elements) {
  log.debug("Entering form().");
  log.debug("Leaving form().");
  return { elements: elements,
           getAttribute: function (n) {
             return n === 'action' ? action : null;
           } };
}

/**
 * A runtime on a page, with stand-ins for the browser, the token endpoint
 * and the API.
 *
 * @param tokenSub - the `sub` the token endpoint's ID Token names
 * @param forms - the forms the page holds
 * @returns `{ rt, env, calls, channels, opened, bar }`
 */
function onAPage(tokenSub, forms) {
  log.debug("Entering onAPage().");
  const calls = [];
  const channels = [];
  const opened = [];
  const store = {};
  const elements = {};
  const body = {
    appendChild: function (el) { elements[el.id] = el; el.parentNode = body; },
    removeChild: function (el) { delete elements[el.id]; }
  };
  class Channel {
    constructor(name) {
      this.name = name;
      this.posted = [];
      this.closed = false;
      channels.push(this);
    }
    postMessage(data) {
      this.posted.push(data);
    }
    close() {
      this.closed = true;
    }
  }
  const location = { pathname: '/admin/applications',
                     search: '?application=rcbj0002', hash: '#tab-config',
                     href: ORIGIN + '/admin/applications?application=' +
                           'rcbj0002#tab-config',
                     origin: ORIGIN, assigned: '',
                     assign: function (u) { location.assigned = u; } };
  const env = {
    location: location,
    history: { replaceState: function () {}, pushState: function () {} },
    crypto: globalThis.crypto,
    sessionStorage: {
      getItem: function (k) { return k in store ? store[k] : null; },
      setItem: function (k, v) { store[k] = String(v); },
      removeItem: function (k) { delete store[k]; }
    },
    document: {
      title: '', body: body,
      documentElement: { getAttribute: function () { return null; } },
      createElement: function () {
        return { setAttribute: function () {}, innerHTML: '' };
      },
      getElementById: function (id) { return elements[id] || null; },
      querySelectorAll: function (sel) { return sel === 'form' ? forms : []; },
      querySelector: function () { return null; }
    },
    window: {
      BroadcastChannel: Channel,
      open: function (url) { opened.push(url); return {}; },
      close: function () {}
    },
    fetch: async function (url, init) {
      calls.push({ url: String(url), init: init || {} });
      const empty = { get: function () { return ''; } };
      if (/\/oauth2\/token$/.test(String(url))) {
        return { status: 200, headers: empty,
                 json: async function () {
                   return { access_token: 'fresh-at', expires_in: 300,
                            refresh_token: 'fresh-rt',
                            id_token: idTokenFor(tokenSub) };
                 } };
      }
      // The API: refused while the token is the ended one.
      const auth = String((init && init.headers &&
                           init.headers.Authorization) || '');
      if (auth !== 'DPoP fresh-at') {
        return { status: 401,
                 headers: { get: function (n) {
                   return n === 'WWW-Authenticate'
                     ? 'DPoP error="invalid_token"' : '';
                 } },
                 json: async function () { return {}; } };
      }
      return { status: 200, headers: empty,
               json: async function () { return { ok: true }; } };
    }
  };
  const rt = new ConsoleRuntime(env);
  // ON A PAGE, signed in as `alice`, with a token the API now refuses and
  // no refresh token left: the session has ended.
  rt.view = { page: { path: '/admin/applications' }, json: {}, query: {} };
  rt.subject = 'urn:uuid:alice';
  rt.accessToken = 'ended-at';
  rt.expiresAt = Date.now() + 600000;
  rt.refreshToken = '';
  log.debug("Leaving onAPage().");
  return { rt: rt, env: env, calls: calls, channels: channels,
           opened: opened, elements: elements, store: store };
}

/**
 * Waits until a condition holds, or a short while.
 *
 * @param fn - the condition
 * @returns nothing
 */
async function until(fn) {
  log.debug("Entering until().");
  // A TIME BOUND, NOT A COUNT OF TURNS (2026-10-07). The runtime's PKCE and
  // DPoP work is WebCrypto, which runs on libuv's thread pool; under the
  // suite's parallel unit pool 200 turns passed before it finished, and the
  // bar was asked for before it was drawn (memory mode, 200ac246's second
  // run). Ten seconds, a turn at a time, is generous and still ends.
  const deadline = Date.now() + 10000;
  while (!fn() && Date.now() < deadline) {
    await new Promise(function (resolve) { setImmediate(resolve); });
  }
  log.debug("Leaving until().");
}

async function run(t) {
  log.debug("Entering run().");
  // 6. The subject of an ID Token.
  t.check(ConsoleRuntime.subjectOf(idTokenFor('urn:uuid:alice')) ===
          'urn:uuid:alice' && ConsoleRuntime.subjectOf('nonsense') === '',
          '6. the ID Token\'s sub is read, and nonsense reads as none');

  // 1-3. A Save that meets the ended session waits, the popup signs in, and
  // the Save is then sent once.
  const a = onAPage('urn:uuid:alice', []);
  const sent = a.rt.send('POST', ORIGIN + '/admin-api/applications/' +
                         'update-fields', { application: 'rcbj0002' });
  await until(function () {
    return !!a.elements['reauth-bar'] && a.rt.reauth && a.rt.reauth.url;
  });
  const bar = a.elements['reauth-bar'];
  t.check(bar && /Your session has ended/.test(bar.innerHTML) &&
          /data-reauth="popup"/.test(bar.innerHTML) &&
          /data-reauth="page"/.test(bar.innerHTML),
          '1. the request waits, under a bar offering both ways back',
          bar && bar.innerHTML);
  a.rt.onClick({ defaultPrevented: false, button: 0,
                 target: { getAttribute: function (n) {
                   return n === 'data-reauth' ? 'popup' : null;
                 } },
                 preventDefault: function () {} });
  const url = a.opened[0] ? new URL(a.opened[0]) : null;
  t.check(url && url.pathname === '/oauth2/authorize' &&
          url.searchParams.get('client_id') === 'sts-admin-console' &&
          url.searchParams.get('code_challenge_method') === 'S256' &&
          /^popup\./.test(url.searchParams.get('state') || '') &&
          url.searchParams.get('resource') === ORIGIN + '/admin-api',
          '1. the popup is the realm\'s own authorization request, PKCE ' +
          'S256, a popup\'s state', a.opened[0]);
  const state = url ? url.searchParams.get('state') : '';

  // 2. The popup's callback hands the answer back and redeems nothing.
  const p = onAPage('urn:uuid:alice', []);
  p.env.location.pathname = '/admin/callback';
  p.env.location.search = '?code=the-code&state=' +
                          encodeURIComponent(state);
  await p.rt.finishSignIn();
  const handed = p.channels[0];
  t.check(handed && handed.posted.length === 1 &&
          handed.posted[0].code === 'the-code' &&
          handed.posted[0].state === state && handed.closed &&
          !p.calls.some(function (c) { return /oauth2\/token/.test(c.url); }),
          '2. the popup\'s callback hands the code back and redeems nothing',
          JSON.stringify(handed && handed.posted));

  // 3. The opener redeems it with its own verifier and sends the request.
  a.channels[0].onmessage({ data: handed.posted[0] });
  const res = await sent;
  const token = a.calls.filter(function (c) {
    return /oauth2\/token$/.test(c.url);
  })[0];
  const form3 = token ? new URLSearchParams(token.init.body) : null;
  const after = a.calls.filter(function (c) {
    return /update-fields/.test(c.url) &&
           c.init.headers.Authorization === 'DPoP fresh-at';
  });
  t.check(form3 && form3.get('grant_type') === 'authorization_code' &&
          form3.get('code') === 'the-code' &&
          !!form3.get('code_verifier') && res && res.status === 200 &&
          after.length === 1 && !a.elements['reauth-bar'],
          '3. the code is redeemed with this page\'s verifier, and the ' +
          'waiting request is sent once with the new token',
          JSON.stringify({ status: res && res.status, after: after.length }));

  // 4. A different person: nothing waiting is sent.
  const b = onAPage('urn:uuid:mallory', []);
  let routed = 0;
  b.rt.route = async function () { routed++; };
  const waiting = b.rt.send('POST', ORIGIN + '/admin-api/users/' +
                            'update-fields', { user: 'alice' });
  await until(function () { return b.rt.reauth && b.rt.reauth.url; });
  await b.rt.onPopupAnswer({ state: b.rt.reauth.state, code: 'c2' });
  const answered = await waiting;
  t.check(answered === null && routed === 1 &&
          !b.calls.some(function (c) {
            return /update-fields/.test(c.url) &&
                   c.init.headers.Authorization === 'DPoP fresh-at';
          }),
          '4. a different person signing in sends nothing that was waiting');

  // 5. On this page instead: the forms are kept, safely, and put back.
  const kept = [form('/admin/applications/edit#cfg-oauth', [
    control('field.oauthClientId', 'text', 'rcbj0002'),
    control('view', 'radio', 'simple', false),
    control('view', 'radio', 'advanced', true),
    control('present', 'hidden', 'oauthClientId'),
    control('password', 'password', 'hunter2'),
    control('field.oauthClientSecret', 'text', 's3cret')])];
  const c = onAPage('urn:uuid:alice', kept);
  c.rt.submitting = kept[0];
  await c.rt.leaveToSignIn();
  const savedText = c.store['sts-console-restore'] || '';
  const signin = JSON.parse(c.store['sts-console-signin'] || '{}');
  t.check(/rcbj0002/.test(savedText) && !/hunter2|s3cret/.test(savedText) &&
          !/"present"/.test(savedText) && /"pending":true/.test(savedText) &&
          signin.returnTo === '/admin/applications?application=rcbj0002' +
                              '#tab-config' &&
          /\/oauth2\/authorize\?/.test(c.env.location.assigned),
          '5. signing in on the page keeps the values, never a password, a ' +
          'hidden field or a secret, and comes back to the tab', savedText);
  const fresh = [form('/admin/applications/edit#cfg-oauth', [
    control('field.oauthClientId', 'text', ''),
    control('view', 'radio', 'simple', true),
    control('view', 'radio', 'advanced', false),
    control('present', 'hidden', 'oauthClientId')])];
  const d = onAPage('urn:uuid:alice', fresh);
  d.store['sts-console-restore'] = savedText;
  d.env.location.hash = '';
  d.rt.restorePageState();
  t.check(fresh[0].elements[0].value === 'rcbj0002' &&
          fresh[0].elements[2].checked === true &&
          !('sts-console-restore' in d.store),
          '5. and they are put back after, for the same page and person, ' +
          'and the kept copy is spent');
  const other = [form('/admin/applications/edit#cfg-oauth', [
    control('field.oauthClientId', 'text', '')])];
  const e = onAPage('urn:uuid:alice', other);
  e.rt.subject = 'urn:uuid:mallory';
  e.store['sts-console-restore'] = savedText;
  e.rt.restorePageState();
  t.check(other[0].elements[0].value === '',
          '5. a different person\'s sign-in puts nothing back');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'console reauth',
  describe: 'the console signs in again through the central sign-in ' +
            'without losing the page (#508)',
  run: run
};
