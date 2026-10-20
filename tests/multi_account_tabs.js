// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/multi_account_tabs.js
//
// ---------------------------------------------------------------------------
// ONE ACCOUNT PER TAB IN THE CONSOLE AND THE PORTAL, AND SIGN IN WITH ANOTHER
// ACCOUNT ON EVERY STATIC SURFACE (#561, delivery steps 5 and 6).
//
// The runtimes are driven here in process with stand-ins for every browser
// object — two runtime instances with separate sessionStorage stand-ins are
// two tabs — and the token endpoint, the APIs and `GET /authn-api/accounts`
// are stand-ins too, so what is held is the runtimes' own behaviour
// (`tests/console_reauth.js`'s arrangement):
//
//   1. TWO TABS, TWO ACCOUNTS: each tab's sign-in names its own account as
//      `login_hint`, and a switch in one changes nothing in the other.
//   2. A SWITCH aborts the request in flight (its answer is not drawn),
//      discards every view this tab held, the tokens and the DPoP key, and
//      asks first over unsaved changes — declining leaves the tab as it was.
//   3. AN ANSWER FOR ANOTHER SUBJECT than the one switched to is refused and
//      its tokens are not kept; the console's popup refuses one too.
//   4. A RELOAD, AND A DUPLICATED TAB, keep the tab's account: the sign-in
//      they start names it.
//   5. THE CHANGE SIGNAL: messages out of order and messages that never
//      arrive cost at most a stale menu, change no tab's account, and a
//      message of another kind is ignored.
//   6. SETTING OFF: nothing kept, no hint, no prompt, the frames and the
//      sign-out address to the byte what they were, `accounts=another`
//      dropped, and — the shell carrying no `data-sts-accounts` — the list
//      never fetched.
//   7. THE PORTAL: the same switch, abort (the owner token's request too)
//      and subject check, and `?accounts=another` from another page becomes
//      its authorization request with `prompt=login`; the device page names
//      the account an approval is, with more than one signed in.
//   8. A STATIC SURFACE: the control is drawn beside the chooser with the
//      setting on — its words fetched only then — never under
//      `/authn/spnego` or on the picker, and a change an act made is
//      announced with nothing about whose.
//   9. SWITCH USER (#751): both menus draw the group whether or not another
//      account is signed in — with none, a line saying so — with Sign in
//      with another account and the line that the account left stays
//      signed in; a switch is a whole-page sign-in naming the account, never
//      the popup, and once it lands the popup's sign-in again (#731) asks
//      for the account switched TO and refuses the one left; and an account
//      the console's shell answer refuses gets a page with the Switch user
//      group and Sign out (Sign out alone with the setting off), not a
//      blank tab.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const ConsoleRuntime = require('../admin-ui/web_runtime');
const WebShell = require('../admin-ui/web_shell');
const PortalRuntime = require('../portal/web_portal_runtime');
const PortalShell = require('../portal/web_portal_shell');
const DevicePages = require('../portal/web_device');
const WebSurface = require('../common/web_surface');
const WebAccounts = require('../common/web_accounts');
const WebMessages = require('../common/web_messages');
// Node's English default for a renderer handed no translator, which this
// module installs as it loads (`common/i18n.ts`).
const i18n = require('../common/i18n');

const log = require('bunyan').createLogger({
  name: 'multi_account_tabs',
  level: process.env.LOG_LEVEL || 'info' });

const ORIGIN = 'https://sts.example.com';

// THE BROWSER'S ACCOUNTS as the server answers them: alice and bob signed in.
const ALICE = { key: 'urn:uuid:alice', sub: 'urn:uuid:alice',
                username: 'alice', displayName: 'Alice', state: 'signed-in',
                current: true };
const BOB = { key: 'urn:uuid:bob', sub: 'urn:uuid:bob', username: 'bob',
              displayName: 'Bob', state: 'signed-in', current: false };
const CAROL = { key: 'urn:uuid:carol', sub: 'urn:uuid:carol',
                username: 'carol', displayName: 'Carol',
                state: 'signed-in', current: false };

/**
 * A list as `GET /authn-api/accounts` answers it.
 *
 * @param accounts - the accounts
 * @returns the answer
 */
function listOf(accounts) {
  log.debug("Entering listOf().");
  log.debug("Leaving listOf().");
  return { ok: true, enabled: true, accounts: accounts, max: 10,
           csrf: 'c', anotherAccount: ORIGIN + '/portal?accounts=another' };
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
  return b64u({ alg: 'ES256' }) + '.' + b64u({ sub: sub, nonce: nonce }) +
    '.sig';
}

/**
 * The nonce a sign-in with this PKCE verifier sends.
 *
 * @param verifier - the verifier
 * @returns the nonce
 */
function nonceOf(verifier) {
  log.debug("Entering nonceOf().");
  log.debug("Leaving nonceOf().");
  return nodeCrypto.createHash('sha256').update('nonce:' + verifier)
    .digest('base64url');
}

/**
 * A sessionStorage stand-in: one per tab.
 *
 * @param seed - what it starts with
 * @returns the storage, its contents on `store`
 */
function storageOf(seed) {
  log.debug("Entering storageOf().");
  const store = Object.assign({}, seed || {});
  log.debug("Leaving storageOf().");
  return {
    store: store,
    getItem: function (k) {
      return k in store ? store[k] : null;
    },
    setItem: function (k, v) {
      store[k] = String(v);
    },
    removeItem: function (k) {
      delete store[k];
    }
  };
}

/**
 * A browser for one tab: the location, the storage, the document, the
 * channels, and a fetch whose answers the test sets.
 *
 * @param pathname - where the tab is
 * @param storage - its sessionStorage stand-in
 * @param server - `{ list, tokenSub, hang }`: the account list answered
 *   (null for a 404), the `sub` the token endpoint names, and a path whose
 *   request hangs until it is aborted
 * @returns `{ env, calls, channels, elements, assigned }`
 */
function browser(pathname, storage, server) {
  log.debug("Entering browser().");
  const calls = [];
  const channels = [];
  const elements = {};
  const listeners = {};
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
                     href: ORIGIN + pathname, origin: ORIGIN,
                     assigned: [],
                     assign: function (u) {
                       location.assigned.push(String(u));
                     } };
  const body = { innerHTML: '',
                 appendChild: function (el) {
                   elements[el.id] = el;
                   el.parentNode = body;
                 },
                 removeChild: function (el) {
                   delete elements[el.id];
                 } };
  const env = {
    location: location,
    history: { replaceState: function (s, t, u) {
                 const at = new URL(String(u), ORIGIN);
                 location.pathname = at.pathname;
                 location.search = at.search;
               },
               pushState: function () {} },
    crypto: globalThis.crypto,
    sessionStorage: storage,
    navigator: { languages: ['en'] },
    document: {
      title: '', body: body,
      // THE SHELL'S `data-sts-accounts` (#561): `on` where the server's
      // list is on, as `ShellDocument` draws it, unless a case names it.
      documentElement: { getAttribute: function (attr) {
                           if (attr !== 'data-sts-accounts') {
                             return null;
                           }
                           if (server.attribute !== undefined) {
                             return server.attribute;
                           }
                           return server.list && server.list.enabled
                             ? 'on' : null;
                         },
                         setAttribute: function () {} },
      createElement: function () {
        return { setAttribute: function () {}, innerHTML: '' };
      },
      getElementById: function (id) {
        return elements[id] || null;
      },
      querySelectorAll: function () {
        return [];
      },
      querySelector: function () {
        return null;
      },
      addEventListener: function (type, fn) {
        listeners[type] = fn;
      }
    },
    window: { BroadcastChannel: Channel, AbortController: AbortController,
              confirm: function () {
                return server.confirm !== false;
              },
              open: function () {
                return {};
              },
              addEventListener: function () {} },
    fetch: async function (url, init) {
      const u = String(url);
      calls.push({ url: u, init: init || {} });
      const empty = { get: function () { return ''; } };
      const answer = function (status, json) {
        return { status: status, headers: empty,
                 json: async function () { return json; } };
      };
      if (server.hang && u.indexOf(server.hang) >= 0) {
        // IN FLIGHT until it is aborted, as a slow API would be.
        return new Promise(function (resolve, reject) {
          const signal = init && init.signal;
          if (signal) {
            signal.addEventListener('abort', function () {
              const e = new Error('The operation was aborted.');
              e.name = 'AbortError';
              reject(e);
            });
          }
        });
      }
      // A PATH THE CASE ANSWERS ITSELF (#751): `{ status, json }`.
      const named = server.answers && Object.keys(server.answers)
        .filter(function (path) {
          return u.indexOf(path) >= 0;
        })[0];
      if (named) {
        return answer(server.answers[named].status,
                      server.answers[named].json);
      }
      if (/\/authn-api\/accounts$/.test(u)) {
        return server.list ? answer(200, server.list)
                           : answer(404, { error: 'not here' });
      }
      if (/\/oauth2\/token$/.test(u)) {
        const sent = new URLSearchParams(String((init && init.body) || ''));
        return answer(200, { access_token: 'at-' + server.tokenSub,
          expires_in: 300, refresh_token: 'rt',
          id_token: idTokenFor(server.tokenSub,
                               nonceOf(sent.get('code_verifier') || '')) });
      }
      return answer(404, {});
    }
  };
  log.debug("Leaving browser().");
  return { env: env, calls: calls, channels: channels, elements: elements,
           location: location, listeners: listeners };
}

/**
 * Waits until a condition holds, or ten seconds (`console_reauth.js`'s
 * reason: WebCrypto runs on libuv's pool).
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
 * The authorization request a tab was last sent to, as a URL.
 *
 * @param b - the browser
 * @returns the URL, or null
 */
function lastAuthorize(b) {
  log.debug("Entering lastAuthorize().");
  const all = b.location.assigned.filter(function (u) {
    return /\/oauth2\/authorize\?/.test(u);
  });
  log.debug("Leaving lastAuthorize().");
  return all.length ? new URL(all[all.length - 1]) : null;
}

/**
 * A console tab, signed in as a subject, with the browser's list read.
 *
 * @param server - the browser's server stand-in
 * @param storage - its sessionStorage
 * @param sub - the subject signed in, or ''
 * @returns `{ rt, b }`
 */
async function consoleTab(server, storage, sub) {
  log.debug("Entering consoleTab().");
  const b = browser('/admin/users', storage, server);
  const rt = new ConsoleRuntime(b.env);
  if (sub) {
    rt.subject = sub;
    rt.accessToken = 'at-' + sub;
    rt.expiresAt = Date.now() + 600000;
    await rt.readAccounts('');
  }
  log.debug("Leaving consoleTab().");
  return { rt: rt, b: b };
}

/**
 * Finishes a sign-in the tab started, as its callback would.
 *
 * @param tab - `{ rt, b }`
 * @param base - the callback's path
 * @returns nothing
 */
async function callback(tab, base) {
  log.debug("Entering callback().");
  const url = lastAuthorize(tab.b);
  tab.b.location.pathname = base;
  tab.b.location.search = '?code=c&state=' +
    encodeURIComponent(url.searchParams.get('state'));
  // The page after the sign-in reads the list again, as the shell does.
  tab.rt.route = async function () {
    await tab.rt.readAccounts('');
  };
  await tab.rt.finishSignIn();
  log.debug("Leaving callback().");
}

async function consoleChecks(t) {
  log.debug("Entering consoleChecks().");
  // --- 1. Two tabs, two accounts ------------------------------------------
  const server = { list: listOf([ALICE, BOB]), tokenSub: 'urn:uuid:alice' };
  const a = await consoleTab(server, storageOf(), 'urn:uuid:alice');
  const bServer = { list: listOf([ALICE, BOB]), tokenSub: 'urn:uuid:bob' };
  const b = await consoleTab(bServer, storageOf(), 'urn:uuid:bob');
  t.check(JSON.parse(a.b.env.sessionStorage.store['sts-console-account'])
            .username === 'alice' &&
          JSON.parse(b.b.env.sessionStorage.store['sts-console-account'])
            .username === 'bob' &&
          !/token|sid|key/i.test(JSON.stringify(Object.keys(JSON.parse(
            a.b.env.sessionStorage.store['sts-console-account'])))),
          '1. each tab keeps its own { sub, username }, and nothing else');
  await a.rt.beginSignIn('/admin');
  await b.rt.beginSignIn('/admin');
  t.check(lastAuthorize(a.b).searchParams.get('login_hint') === 'alice' &&
          lastAuthorize(b.b).searchParams.get('login_hint') === 'bob',
          '1. each tab\'s sign-in names its own account as login_hint');

  // --- 2. A switch: abort, discard, ask first ------------------------------
  server.hang = '/admin-api/users';
  const inFlight = a.rt.send('GET', ORIGIN + '/admin-api/users');
  await until(function () {
    return a.b.calls.some(function (c) {
      return /admin-api\/users/.test(c.url);
    });
  });
  a.rt.shell = { gate: { session: true } };
  a.rt.me = { write: true };
  a.rt.formTable = {};
  a.rt.spec = {};
  a.rt.view = { page: { path: '/admin/users' }, json: {}, query: {} };
  a.b.env.sessionStorage.setItem('sts-console-restore', '{"forms":[]}');
  await a.rt.ensureKey();
  // The metadata read for the old identity; the switch's own sign-in reads
  // it again (a 404 here, so `{}`), which is not the one discarded.
  a.rt.metadata = { issuer: 'read before the switch' };
  const identityBefore = a.rt.identity;
  // Declining over unsaved changes leaves the tab as it was.
  a.rt.dirty = true;
  server.confirm = false;
  const assignedBefore = a.b.location.assigned.length;
  await a.rt.switchAccount(BOB.key);
  t.check(a.b.location.assigned.length === assignedBefore &&
          a.rt.identity === identityBefore && a.rt.view !== null,
          '2. a switch asks first over unsaved changes, and declining ' +
          'changes nothing');
  server.confirm = true;
  await a.rt.switchAccount(BOB.key);
  const flown = await inFlight;
  const hung = a.b.calls.filter(function (c) {
    return /admin-api\/users/.test(c.url);
  })[0];
  t.check(flown === null && hung && hung.init.signal &&
          hung.init.signal.aborted === true,
          '2. the request in flight is aborted and its answer not drawn');
  t.check(a.rt.shell === null && a.rt.me === null &&
          a.rt.formTable === null && a.rt.spec === null &&
          a.rt.view === null && a.rt.reauth === null &&
          a.rt.accessToken === '' && a.rt.refreshToken === '' &&
          a.rt.key === null && !(a.rt.metadata && a.rt.metadata.issuer) &&
          !('sts-console-restore' in a.b.env.sessionStorage.store),
          '2. the switch discards the shell, me, the form table, the ' +
          'schemas, the view, the restore record, the tokens and the key');
  const switched = lastAuthorize(a.b);
  t.check(switched.searchParams.get('login_hint') === 'bob' &&
          !switched.searchParams.get('prompt') &&
          JSON.parse(a.b.env.sessionStorage.store['sts-console-signin'])
            .expect === BOB.sub,
          '2. the switch signs in naming the account and the subject asked ' +
          'for', switched && switched.toString());
  t.check(JSON.parse(b.b.env.sessionStorage.store['sts-console-account'])
            .username === 'bob' && b.rt.accessToken === 'at-urn:uuid:bob' &&
          b.b.location.assigned.length === 1,
          '1. the switch in one tab changes nothing in the other');

  // --- 3. Another subject's answer is refused ------------------------------
  server.hang = '';
  server.tokenSub = 'urn:uuid:alice';
  await callback(a, '/admin/callback');
  t.check(/Switching accounts was refused/.test(a.b.env.document.body
            .innerHTML) && a.rt.accessToken === '' &&
          JSON.parse(a.b.env.sessionStorage.store['sts-console-account'])
            .username === 'alice',
          '3. an answer for another subject than the one switched to is ' +
          'refused, and the tab stays its account');
  // The subject it asked for is taken, and the tab is that account.
  await a.rt.switchAccount(BOB.key);
  server.tokenSub = 'urn:uuid:bob';
  await callback(a, '/admin/callback');
  t.check(a.rt.subject === 'urn:uuid:bob' &&
          JSON.parse(a.b.env.sessionStorage.store['sts-console-account'])
            .username === 'bob',
          '3. the subject asked for is taken, and the tab keeps it');

  // --- 4. A reload and a duplicated tab keep the account -------------------
  const dup = await consoleTab(server,
    storageOf(a.b.env.sessionStorage.store), '');
  await dup.rt.beginSignIn('/admin');
  t.check(lastAuthorize(dup.b).searchParams.get('login_hint') === 'bob',
          '4. a reload or a duplicated tab signs in as the tab\'s account');
  const fresh = await consoleTab(server, storageOf(), '');
  await fresh.rt.beginSignIn('/admin');
  t.check(lastAuthorize(fresh.b).searchParams.get('login_hint') === null,
          '4. a new tab with nothing kept names nobody');

  // --- 3. The popup asks for the tab's account, and refuses another --------
  const p = await consoleTab({ list: listOf([ALICE, BOB]),
                               tokenSub: 'urn:uuid:bob' },
                             storageOf(), 'urn:uuid:alice');
  p.rt.view = { page: { path: '/admin/users' }, json: {}, query: {} };
  p.rt.accessToken = '';
  p.rt.refreshToken = '';
  const waiting = p.rt.signInAgain();
  await until(function () { return p.rt.reauth && p.rt.reauth.url; });
  const popupUrl = new URL(p.rt.reauth.url);
  await p.rt.onPopupAnswer({ state: p.rt.reauth.state, code: 'c' });
  t.check(popupUrl.searchParams.get('login_hint') === 'alice' &&
          p.rt.subject === 'urn:uuid:alice' && p.rt.accessToken === '' &&
          p.rt.reauth && /another account/.test(
            (p.b.elements['reauth-bar'] || {}).innerHTML || ''),
          '3. the popup names the tab\'s account, and an answer for another ' +
          'is refused with the bar saying so');
  void waiting;

  // --- 5. The change signal ------------------------------------------------
  const sig = await consoleTab({ list: listOf([ALICE, BOB]) }, storageOf(),
                               'urn:uuid:alice');
  let redrawn = 0;
  sig.rt.listenForAccounts(function () {
    redrawn++;
  });
  const channel = sig.b.channels.filter(function (c) {
    return c.name === 'sts-accounts';
  })[0];
  // The server's list moves on twice; the messages arrive in reverse order.
  const s5 = { list: listOf([ALICE, CAROL, Object.assign({}, BOB,
    { state: 'signed-out' })]) };
  sig.b.env.fetch = browser('/admin', storageOf(), s5).env.fetch;
  channel.onmessage({ data: { type: WebAccounts.MESSAGE,
                              change: 'signed-out' } });
  channel.onmessage({ data: { type: WebAccounts.MESSAGE, change: 'added' } });
  channel.onmessage({ data: { type: 'something-else' } });
  await until(function () { return redrawn >= 2; });
  t.check(redrawn === 2 &&
          WebAccounts.live(sig.rt.accounts).map(function (o) {
            return o.username;
          }).join(',') === 'alice,carol' &&
          sig.rt.subject === 'urn:uuid:alice' &&
          JSON.parse(sig.b.env.sessionStorage.store['sts-console-account'])
            .username === 'alice' && channel.posted.length === 0,
          '5. messages out of order end at the server\'s list, change no ' +
          'tab\'s account, are never echoed, and another kind is ignored');
  s5.list = listOf([ALICE]);
  t.check(WebAccounts.live(sig.rt.accounts).length === 2,
          '5. a message that never arrives leaves the menu stale');
  await sig.rt.readAccounts('');
  t.check(WebAccounts.live(sig.rt.accounts).length === 1,
          '5. and the next read of the list is current again');

  // --- 6. Setting off ------------------------------------------------------
  const offStore = storageOf({ 'sts-console-account':
    JSON.stringify({ sub: 'urn:uuid:alice', username: 'alice' }) });
  const off = await consoleTab({ list: { ok: true, enabled: false,
                                         accounts: [], max: 0 } },
                               offStore, 'urn:uuid:alice');
  await off.rt.beginSignIn('/admin');
  const offUrl = lastAuthorize(off.b);
  const record = JSON.parse(offStore.store['sts-console-signin']);
  t.check(!('sts-console-account' in offStore.store) &&
          offUrl.searchParams.get('login_hint') === null &&
          offUrl.searchParams.get('prompt') === null &&
          Object.keys(record).sort().join(',') ===
            'prefix,returnTo,state,verifier',
          '6. off: nothing kept, no hint, no prompt, the sign-in\'s record ' +
          'as it was');
  const shell = { gate: { session: true, username: 'alice' }, sections: [],
                  realm: { id: '', name: 'Default' }, navLabels: {},
                  version: {}, persistence: {}, portalHref: '/portal' };
  const page = { title: 'Users', active: '/admin/users', up: null,
                 inner: '<p>x</p>', path: '/admin/users' };
  t.check(WebShell.frame(shell, Object.assign({}, page,
            { accounts: off.rt.accounts, subject: 'urn:uuid:alice' })) ===
          WebShell.frame(shell, page) &&
          WebShell.frame(shell, Object.assign({}, page,
            { accounts: listOf([ALICE, BOB]), subject: 'urn:uuid:alice' }))
            .indexOf('data-account-key="urn:uuid:bob"') > 0,
          '6. off, the console\'s frame is the one it was; on, its menu ' +
          'offers the other account');
  // THE SHELL SAYS OFF, so the list is never asked for — not even of a
  // server that would answer it on: no extra request on any page load.
  const quiet = await consoleTab({ list: listOf([ALICE, BOB]),
                                   attribute: null }, storageOf(),
                                 'urn:uuid:alice');
  t.check(quiet.rt.accounts.enabled === false &&
          !quiet.b.calls.some(function (c) {
            return /\/authn-api\/accounts$/.test(c.url);
          }) &&
          !off.b.calls.some(function (c) {
            return /\/authn-api\/accounts$/.test(c.url);
          }),
          '6. off in the shell, the account list is never fetched',
          JSON.stringify(quiet.b.calls.map(function (c) { return c.url; })));
  off.rt.signOut();
  t.check(off.b.location.assigned[off.b.location.assigned.length - 1] ===
          ORIGIN + '/logout',
          '6. off, Sign out goes to /logout as it always did');
  const on = await consoleTab({ list: listOf([ALICE, BOB]) }, storageOf(),
                              'urn:uuid:alice');
  on.rt.signOut();
  t.check(on.b.location.assigned[on.b.location.assigned.length - 1] ===
          ORIGIN + '/logout?login_hint=alice',
          '1. on, Sign out tells /logout the tab\'s account');
  log.debug("Leaving consoleChecks().");
}

async function portalChecks(t) {
  log.debug("Entering portalChecks().");
  // --- 7. The portal: switch, abort, subject check -------------------------
  const server = { list: listOf([ALICE, BOB]), tokenSub: 'urn:uuid:alice' };
  const b = browser('/portal/consents', storageOf(), server);
  const rt = new PortalRuntime(b.env);
  rt.subject = 'urn:uuid:alice';
  rt.accessToken = 'at';
  rt.refreshToken = 'rt';
  rt.expiresAt = Date.now() + 600000;
  rt.ownerToken = 'owner';
  rt.ownerExpiresAt = Date.now() + 600000;
  await rt.readAccounts('alice');
  t.check(JSON.parse(b.env.sessionStorage.store['sts-portal-account'])
            .username === 'alice',
          '7. the portal tab keeps its account');
  server.hang = '/admin-api/roles';
  const owned = rt.ownerJson('GET', '/admin-api/roles/list');
  const b2 = browser('/portal', storageOf(), Object.assign({}, server,
    { hang: '/account-api/me' }));
  const rt2 = new PortalRuntime(b2.env);
  rt2.accessToken = 'at';
  rt2.expiresAt = Date.now() + 600000;
  rt2.accounts = listOf([ALICE, BOB]);
  const mine = rt2.apiJson('GET', '/account-api/me');
  await until(function () {
    return b.calls.some(function (c) {
      return /admin-api\/roles/.test(c.url);
    }) &&
      b2.calls.some(function (c) { return /account-api\/me/.test(c.url); });
  });
  rt.me = { user: { username: 'alice' } };
  rt.nobody = {};
  rt.formTable = {};
  rt.view = { page: { path: '/portal/consents' }, json: {}, query: {} };
  rt.flash = { message: 'x' };
  await rt.switchAccount(BOB.key);
  await rt2.switchAccount(BOB.key);
  t.check(await owned === null && await mine === null &&
          rt.me === null && rt.nobody === null && rt.formTable === null &&
          rt.view === null && rt.flash === null && rt.ownerToken === '' &&
          rt.accessToken === '' && rt.key === null,
          '7. a portal switch aborts the owner\'s and the account API\'s ' +
          'requests and discards me, nobody, the form table, the view, the ' +
          'flash, the owner token and the client\'s tokens');
  t.check(lastAuthorize(b).searchParams.get('login_hint') === 'bob' &&
          JSON.parse(b.env.sessionStorage.store['sts-portal-signin'])
            .expect === BOB.sub &&
          lastAuthorize(b).searchParams.get('expect') === null,
          '7. the portal\'s switch names the account; `expect` stays in the ' +
          'tab');
  server.hang = '';
  server.tokenSub = 'urn:uuid:carol';
  await callback({ rt: rt, b: b }, '/portal/callback');
  t.check(/Switching accounts was refused/.test(b.env.document.body
            .innerHTML) && rt.accessToken === '',
          '7. the portal refuses an answer for another subject');

  // ?accounts=another, from another page.
  const another = browser('/portal', storageOf({ 'sts-portal-account':
    JSON.stringify({ sub: 'urn:uuid:alice', username: 'alice' }) }),
    { list: listOf([ALICE, BOB]) });
  another.location.search = '?accounts=another';
  const art = new PortalRuntime(another.env);
  await art.route();
  const au = lastAuthorize(another);
  t.check(au && au.searchParams.get('prompt') === 'login' &&
          au.searchParams.get('login_hint') === null &&
          another.location.search === '' &&
          JSON.parse(another.env.sessionStorage.store['sts-portal-signin'])
            .another === true,
          '7. accounts=another becomes the portal\'s request with ' +
          'prompt=login and no hint, and leaves the address',
          au && au.toString());
  // Off: the marker is dropped, and the sign-in is today's.
  const offB = browser('/portal', storageOf(), { list: null });
  offB.location.search = '?accounts=another';
  const ort = new PortalRuntime(offB.env);
  await ort.route();
  const ou = lastAuthorize(offB);
  t.check(ou && ou.searchParams.get('prompt') === null &&
          ou.searchParams.get('login_hint') === null &&
          offB.location.search === '' &&
          !('sts-portal-account' in offB.env.sessionStorage.store),
          '6. off, accounts=another is dropped and the sign-in is today\'s',
          ou && ou.toString());
  // The frame, off and on.
  const T = { html: function (k) { return k; }, text: function (k) {
    return k; }, has: function () { return true; }, locale: 'en' };
  const me = { user: { username: 'alice' }, locale: { offered: [] },
               version: {} };
  const page = { active: '/portal/consents', query: {}, message: '',
                 error: '', cards: '<div class="card"></div>', prefix: '',
                 t: T };
  t.check(PortalShell.frame(me, Object.assign({}, page,
            { accounts: WebAccounts.off(), subject: 'urn:uuid:alice' })) ===
          PortalShell.frame(me, page) &&
          PortalShell.frame(me, Object.assign({}, page,
            { accounts: listOf([ALICE, BOB]), subject: 'urn:uuid:alice' }))
            .indexOf('data-account-key="urn:uuid:bob"') > 0,
          '6. off, the portal\'s frame is the one it was; on, its menu ' +
          'offers the other account');
  // THE DEVICE PAGE names the account an approval is this tab's, with more
  // than one signed in; otherwise it is the page it was.
  const deviceView = { enabled: true, typed: 'ABCD-EFGH',
    record: { clientId: 'tv', userCode: 'ABCD-EFGH', scope: 'openid',
              expiresAt: Date.now() + 60000 } };
  const deviceCtx = function (accounts) {
    return Object.assign({}, page, { me: me, accounts: accounts,
      t: Object.assign({}, T, { date: function () {
        return 'soon';
      } }) });
  };
  const plain = DevicePages.render(deviceView, deviceCtx(undefined));
  t.check(DevicePages.render(deviceView, deviceCtx(WebAccounts.off())) ===
            plain &&
          DevicePages.render(deviceView, deviceCtx(listOf([ALICE]))) ===
            plain && !/device-as/.test(plain) &&
          /id="device-as"/.test(DevicePages.render(deviceView,
            deviceCtx(listOf([ALICE, BOB])))),
          '7. the device page names the approving account with two signed ' +
          'in, and is the page it was otherwise');
  log.debug("Leaving portalChecks().");
}

/**
 * A static surface on a path, its account list as given.
 *
 * @param base - the surface's base
 * @param pathname - the page's path
 * @param list - the account list answered, or null for none
 * @returns `{ s, b }`
 */
function surfaceAt(base, pathname, list) {
  log.debug("Entering surfaceAt().");
  const b = browser(pathname, storageOf(), { list: list });
  const s = new WebSurface(b.env, { base: base, api: '',
    pages: [{ path: pathname, operation: '/x',
              render: function () { return '<p>body</p>'; } }],
    namespaces: [] });
  log.debug("Leaving surfaceAt().");
  return { s: s, b: b };
}

async function surfaceChecks(t) {
  log.debug("Entering surfaceChecks().");
  // --- 8. The control on a static surface ----------------------------------
  const draw = async function (base, pathname, list) {
    const one = surfaceAt(base, pathname, list);
    await one.s.loadAccounts();
    one.s.t = await one.s.i18n.load({});
    one.s.put('Page', '<p>body</p>', one.s.context({}));
    return one;
  };
  const on = await draw('/logout', '/logout', listOf([ALICE, BOB]));
  const html = on.b.env.document.body.innerHTML;
  t.check(/class="sts-accounts"/.test(html) && /Alice/.test(html) &&
          /Bob/.test(html) &&
          html.indexOf('href="' + ORIGIN + '/portal?accounts=another"') > 0 &&
          on.b.calls.some(function (c) {
            return /\/web\/locales\/accounts\//.test(c.url);
          }),
          '8. on, the control lists the signed-in accounts and links the ' +
          'portal\'s sign-in as another account, its words fetched', html);
  const off = await draw('/logout', '/logout', null);
  const offOff = await draw('/logout', '/logout',
                            { ok: true, enabled: false, accounts: [] });
  t.check(off.b.env.document.body.innerHTML ===
            offOff.b.env.document.body.innerHTML &&
          !/sts-accounts/.test(off.b.env.document.body.innerHTML) &&
          !offOff.b.calls.some(function (c) {
            return /\/web\/locales\/accounts\//.test(c.url);
          }) &&
          ![off, offOff].some(function (one) {
            return one.b.calls.some(function (c) {
              return /\/authn-api\/accounts$/.test(c.url);
            });
          }),
          '8. off, the page is the one it was, and neither the list nor ' +
          'the words are fetched',
          offOff.b.env.document.body.innerHTML);
  const spnego = await draw('/authn', '/authn/spnego', listOf([ALICE, BOB]));
  const picker = await draw('/authn', '/authn/accounts', listOf([ALICE]));
  t.check(!/sts-accounts/.test(spnego.b.env.document.body.innerHTML) &&
          !/sts-accounts/.test(picker.b.env.document.body.innerHTML),
          '8. never on RFC 4559\'s exchange or on the account picker');
  // An act that changed the list announces it, saying nothing of whose.
  on.b.env.fetch = browser('/logout', storageOf(),
    { list: listOf([ALICE]) }).env.fetch;
  on.b.elements['sts-accounts-slot'] = { innerHTML: '' };
  on.s.put('Page', '<p>after</p>', on.s.context({}));
  const channel = on.b.channels.filter(function (c) {
    return c.name === 'sts-accounts';
  })[0];
  await until(function () { return channel && channel.posted.length > 0; });
  t.check(channel && channel.posted.length === 1 &&
          Object.keys(channel.posted[0]).sort().join(',') === 'change,type' &&
          !/alice|bob/i.test(JSON.stringify(channel.posted[0])) &&
          !/Bob/.test(on.b.elements['sts-accounts-slot'].innerHTML),
          '8. a change an act made is announced with nothing about whose, ' +
          'and the control drawn again', JSON.stringify(channel &&
                                                        channel.posted));
  log.debug("Leaving surfaceChecks().");
}

async function switchUserChecks(t) {
  log.debug("Entering switchUserChecks().");
  // --- 9. Switch user (#751) -----------------------------------------------
  const shell = { gate: { session: true, username: 'alice' }, sections: [],
                  realm: { id: '', name: 'Default' }, navLabels: {},
                  version: {}, persistence: {}, portalHref: '/portal' };
  const page = { title: 'Users', active: '/admin/users', up: null,
                 inner: '<p>x</p>', path: '/admin/users' };
  const alone = WebShell.frame(shell, Object.assign({}, page,
    { accounts: listOf([ALICE]), subject: ALICE.sub }));
  const two = WebShell.frame(shell, Object.assign({}, page,
    { accounts: listOf([ALICE, BOB]), subject: ALICE.sub }));
  t.check(/Switch user/.test(alone) && /data-account-none/.test(alone) &&
          /No other account is signed in/.test(alone) &&
          /data-account-action="another"/.test(alone) &&
          /stays signed in/.test(alone) &&
          !/data-account-action="switch"/.test(alone),
          '9. the console\'s Switch user group is drawn with no other ' +
          'account, saying so, with Sign in with another account and what ' +
          'a switch keeps', alone);
  t.check(/Switch user/.test(two) && !/data-account-none/.test(two) &&
          two.indexOf('data-account-key="urn:uuid:bob"') > 0 &&
          two.indexOf('data-account-key="urn:uuid:alice"') < 0 &&
          /stays signed in/.test(two),
          '9. with another account, the console\'s group offers it and not ' +
          'the tab\'s own');
  const T = { html: function (k) { return k; }, text: function (k) {
    return k; }, has: function () { return true; }, locale: 'en' };
  const me = { user: { username: 'alice' }, locale: { offered: [] },
               version: {} };
  const ppage = { active: '/portal/consents', query: {}, message: '',
                  error: '', cards: '<div class="card"></div>', prefix: '',
                  t: T };
  const palone = PortalShell.frame(me, Object.assign({}, ppage,
    { accounts: listOf([ALICE]), subject: ALICE.sub }));
  const ptwo = PortalShell.frame(me, Object.assign({}, ppage,
    { accounts: listOf([ALICE, BOB]), subject: ALICE.sub }));
  t.check(/portal\.accounts\.menu/.test(palone) &&
          /data-account-none/.test(palone) &&
          /portal\.accounts\.none/.test(palone) &&
          /portal\.accounts\.kept/.test(palone) &&
          /data-account-action="another"/.test(palone) &&
          !/data-account-none/.test(ptwo) &&
          ptwo.indexOf('data-account-key="urn:uuid:bob"') > 0 &&
          /portal\.accounts\.kept/.test(ptwo),
          '9. the portal\'s menu is drawn with no other account, saying so, ' +
          'and offers another where there is one; both say what a switch ' +
          'keeps', palone);
  // THE ENGLISH the portal's catalog gives those keys.
  const en = i18n.translator(['en']);
  t.check(en.text('portal.accounts.menu') === 'Switch user' &&
          en.text('console.shell.menu.switch') === 'Switch user' &&
          /stays signed in/.test(en.text('portal.accounts.kept')),
          '9. both menus read Switch user in English');

  // A SWITCH IS NOT THE POPUP, and once it lands the popup's sign-in again
  // protects the account switched to (#731's rule, unchanged).
  const server = { list: listOf([ALICE, BOB]), tokenSub: BOB.sub };
  const tab = await consoleTab(server, storageOf(), ALICE.sub);
  await tab.rt.switchAccount(BOB.key);
  const switched = lastAuthorize(tab.b);
  t.check(switched && switched.searchParams.get('login_hint') === 'bob' &&
          !/^popup\./.test(switched.searchParams.get('state') || '') &&
          !tab.rt.reauth,
          '9. a switch is a whole-page sign-in naming the account, never ' +
          'the sign-in-again popup', switched && switched.toString());
  await callback(tab, '/admin/callback');
  t.check(tab.rt.subject === BOB.sub &&
          JSON.parse(tab.b.env.sessionStorage.store['sts-console-account'])
            .username === 'bob',
          '9. the switch lands: the tab is the account switched to');
  tab.rt.view = { page: { path: '/admin/users' }, json: {}, query: {} };
  tab.rt.accessToken = '';
  tab.rt.refreshToken = '';
  server.tokenSub = ALICE.sub;
  void tab.rt.signInAgain();
  await until(function () { return tab.rt.reauth && tab.rt.reauth.url; });
  const popupUrl = new URL(tab.rt.reauth.url);
  await tab.rt.onPopupAnswer({ state: tab.rt.reauth.state, code: 'c' });
  t.check(popupUrl.searchParams.get('login_hint') === 'bob' &&
          tab.rt.subject === BOB.sub && tab.rt.accessToken === '' &&
          /another account/.test(
            (tab.b.elements['reauth-bar'] || {}).innerHTML || ''),
          '9. after a switch, the popup asks for the account switched to and ' +
          'refuses the account left (#731), which stays signed in');

  // AN ACCOUNT THE CONSOLE REFUSES: the page says so and keeps the way
  // back.
  const refusedAnswer = { status: 403, json: { error: 'insufficient_role',
    error_description: 'This console is not claimed yet.' } };
  const refused = await consoleTab({ list: listOf([ALICE, BOB]),
    answers: { '/admin-api/console': refusedAnswer } }, storageOf(),
    BOB.sub);
  await refused.rt.ensureKey();
  await refused.rt.route();
  const body = refused.b.env.document.body.innerHTML;
  t.check(/will not open for this account/.test(body) && /403/.test(body) &&
          /not claimed yet/.test(body) &&
          body.indexOf('id="' + WebShell.ACCOUNTS_ID + '"') > 0 &&
          body.indexOf('data-account-key="urn:uuid:alice"') > 0 &&
          /data-account-action="another"/.test(body) &&
          body.indexOf('action="' + WebShell.SIGNOUT_PATH + '"') > 0,
          '9. an account the console refuses gets a page saying so, with ' +
          'Switch user and Sign out, not a blank tab', body);
  const refusedOff = await consoleTab({ list: null, attribute: null,
    answers: { '/admin-api/console': refusedAnswer } }, storageOf(),
    BOB.sub);
  await refusedOff.rt.ensureKey();
  await refusedOff.rt.route();
  const offBody = refusedOff.b.env.document.body.innerHTML;
  t.check(/will not open for this account/.test(offBody) &&
          !/data-account-action/.test(offBody) &&
          offBody.indexOf('action="' + WebShell.SIGNOUT_PATH + '"') > 0,
          '9. off, that page offers Sign out alone', offBody);
  log.debug("Leaving switchUserChecks().");
}

async function run(t) {
  log.debug("Entering run().");
  await consoleChecks(t);
  await portalChecks(t);
  await switchUserChecks(t);
  try {
    await surfaceChecks(t);
  } finally {
    // A SURFACE'S TRANSLATOR IS THE PROCESS'S DEFAULT once it loads
    // (`WebI18n.load()`), and here it has no catalogs: put back node's own
    // English one, as `common/i18n.ts` installs it, or every test after
    // this one in the process draws keys.
    WebMessages.WebTranslator.setDefault(function () {
      return i18n.translator(['en']);
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'multi account tabs',
  describe: 'one account per tab in the console and the portal, and Sign ' +
            'in with another account on every static surface (#561)',
  run: run
};
