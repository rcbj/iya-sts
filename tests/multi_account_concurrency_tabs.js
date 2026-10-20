// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/multi_account_concurrency_tabs.js
//
// ---------------------------------------------------------------------------
// SEVERAL SIGNED-IN ACCOUNTS IN ONE BROWSER, WHEN THINGS HAPPEN AT ONCE OR
// GO WRONG: THE BROWSER RUNTIMES' HALF (#561's TR-2, #731).
//
// `tests/multi_account_tabs.js`'s arrangement: the runtimes driven in
// process with a stand-in for every browser object, two runtime instances
// with separate sessionStorage stand-ins being two tabs, and a fetch whose
// answers the test sets — here also one that REJECTS, as fetch does when
// the network is gone, and one that answers late, ignoring the abort:
//
//   1. AT ONCE: a switch in one tab while the other renews its tokens —
//      the switching tab's request in flight is aborted, the other's
//      renewal is its own, and neither tab's account moves;
//   2. A NETWORK FAILURE DURING A SWITCH: the metadata unreachable, the
//      switch still names the account; a pushed request unreachable, the
//      tab says the switch failed and still keeps its account (the blank
//      tab this file found, fixed in both runtimes);
//   3. DURING A RENEWAL: the renewal fails, the refresh token, the subject
//      and the account are kept, and the next renewal works; an answer
//      that arrives after a switch is not kept;
//   4. DURING A SIGN-OUT: the sign-out surface's act that cannot reach the
//      service says nothing was signed out and announces nothing (the
//      unhandled rejection this file found, fixed in `web_signout.ts`);
//   5. BROADCASTS that arrive late, out of order, not at all, or whose
//      read fails: the menu ends at the server's list, a dropped read
//      keeps the list in hand (fixed in `web_spa_client.ts`), and no tab's
//      account changes;
//   6. A SESSION REVOKED WHILE A REQUEST IS IN FLIGHT: its 401 and the
//      refused renewal clear the tokens, never the tab's account, so the
//      sign-in that follows names the same account;
//   7. A FAILURE IN ONE TAB leaves the other tab's tokens and account as
//      they were.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const ConsoleRuntime = require('../admin-ui/web_runtime');
const PortalRuntime = require('../portal/web_portal_runtime');
const SignoutSurface = require('../logout/web_signout');
const WebAccounts = require('../common/web_accounts');
const WebMessages = require('../common/web_messages');
const i18n = require('../common/i18n');

const log = require('bunyan').createLogger({
  name: 'multi_account_concurrency_tabs',
  level: process.env.LOG_LEVEL || 'info' });

const ORIGIN = 'https://sts.example.com';

const ALICE = { key: 'urn:uuid:alice', sub: 'urn:uuid:alice',
                username: 'alice', displayName: 'Alice', state: 'signed-in',
                current: true };
const BOB = { key: 'urn:uuid:bob', sub: 'urn:uuid:bob', username: 'bob',
              displayName: 'Bob', state: 'signed-in', current: false };
const CAROL = { key: 'urn:uuid:carol', sub: 'urn:uuid:carol',
                username: 'carol', displayName: 'Carol',
                state: 'signed-in', current: false };

function listOf(accounts) {
  log.debug("Entering listOf().");
  log.debug("Leaving listOf().");
  return { ok: true, enabled: true, accounts: accounts, max: 10,
           csrf: 'c', anotherAccount: ORIGIN + '/portal?accounts=another' };
}

function idTokenFor(sub, nonce) {
  log.debug("Entering idTokenFor().");
  const b64u = function (o) {
    return Buffer.from(JSON.stringify(o)).toString('base64url');
  };
  log.debug("Leaving idTokenFor().");
  return b64u({ alg: 'ES256' }) + '.' + b64u({ sub: sub, nonce: nonce }) +
    '.sig';
}

function nonceOf(verifier) {
  log.debug("Entering nonceOf().");
  log.debug("Leaving nonceOf().");
  return nodeCrypto.createHash('sha256').update('nonce:' + verifier)
    .digest('base64url');
}

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
 * A browser for one tab. `server` decides every answer:
 *   `list`    the account list (null for a 404);
 *   `tokenSub` the subject the token endpoint names, `tokenStatus` its
 *             status (200 by default);
 *   `fail`    a pattern: a request whose URL matches REJECTS, as fetch does
 *             with the network gone;
 *   `hang`    a pattern: such a request waits until it is aborted;
 *   `late`    a pattern: such a request waits for `server.release()`,
 *             ignoring the abort, and then answers;
 *   `meta`    the authorization server's metadata;
 *   `api`     `{ status, challenge }` for `/admin-api` and `/account-api`.
 *
 * @param pathname - where the tab is
 * @param storage - its sessionStorage stand-in
 * @param server - as above
 * @returns `{ env, calls, channels, elements, location }`
 */
function browser(pathname, storage, server) {
  log.debug("Entering browser().");
  const calls = [];
  const channels = [];
  const elements = {};
  class Channel {
    constructor(name) {
      this.name = name;
      this.posted = [];
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
                     href: ORIGIN + pathname, origin: ORIGIN, assigned: [],
                     assign: function (u) {
                       location.assigned.push(String(u));
                     } };
  const body = { innerHTML: '',
                 appendChild: function (el) {
                   elements[el.id] = el;
                 },
                 removeChild: function (el) {
                   delete elements[el.id];
                 } };
  const answer = function (status, json, challenge) {
    return { status: status,
             headers: { get: function (name) {
               return /www-authenticate/i.test(name) ? (challenge || '') : '';
             } },
             json: async function () {
               return json;
             } };
  };
  const respond = function (u, init) {
    if (/\/authn-api\/accounts$/.test(u)) {
      return server.list ? answer(200, server.list)
                         : answer(404, { error: 'not here' });
    }
    if (/\/\.well-known\/oauth-authorization-server$/.test(u)) {
      return answer(200, server.meta || {});
    }
    if (/\/oauth2\/token$/.test(u)) {
      if (server.tokenStatus && server.tokenStatus !== 200) {
        return answer(server.tokenStatus, { error: 'invalid_grant' });
      }
      const sent = new URLSearchParams(String((init && init.body) || ''));
      return answer(200, { access_token: 'at-' + server.tokenSub +
                             '-' + calls.length,
        expires_in: 300, refresh_token: 'rt-' + calls.length,
        id_token: idTokenFor(server.tokenSub,
                             nonceOf(sent.get('code_verifier') || '')) });
    }
    if (/\/(admin|account)-api\//.test(u) && server.api) {
      return answer(server.api.status, {}, server.api.challenge);
    }
    return answer(404, {});
  };
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
      documentElement: { getAttribute: function (attr) {
                           return attr === 'data-sts-accounts' &&
                             server.list && server.list.enabled
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
      addEventListener: function () {}
    },
    window: { BroadcastChannel: Channel, AbortController: AbortController,
              confirm: function () {
                return true;
              },
              open: function () {
                return {};
              },
              addEventListener: function () {} },
    fetch: async function (url, init) {
      const u = String(url);
      calls.push({ url: u, init: init || {} });
      if (server.fail && server.fail.test(u)) {
        throw new TypeError('Failed to fetch');
      }
      if (server.hang && server.hang.test(u)) {
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
      if (server.late && server.late.test(u)) {
        // ANSWERED LATE, whatever the abort says: a response already on
        // its way when the tab moved on.
        return new Promise(function (resolve) {
          server.release = function () {
            resolve(respond(u, init));
          };
        });
      }
      return respond(u, init);
    }
  };
  log.debug("Leaving browser().");
  return { env: env, calls: calls, channels: channels, elements: elements,
           location: location };
}

async function until(fn) {
  log.debug("Entering until().");
  const deadline = Date.now() + 10000;
  while (!fn() && Date.now() < deadline) {
    await new Promise(function (resolve) { setImmediate(resolve); });
  }
  log.debug("Leaving until().");
}

// A few turns of the event loop, for a read whose answer changes nothing
// that `until()` could wait on.
async function settle() {
  log.debug("Entering settle().");
  for (let i = 0; i < 50; i++) {
    await new Promise(function (resolve) { setImmediate(resolve); });
  }
  log.debug("Leaving settle().");
}

function lastAuthorize(b) {
  log.debug("Entering lastAuthorize().");
  const all = b.location.assigned.filter(function (u) {
    return /\/oauth2\/authorize\?/.test(u);
  });
  log.debug("Leaving lastAuthorize().");
  return all.length ? new URL(all[all.length - 1]) : null;
}

function keptAccount(b, key) {
  log.debug("Entering keptAccount().");
  let kept = null;
  try {
    kept = JSON.parse(b.env.sessionStorage.store[key || 'sts-console-account']
                      || 'null');
  } catch (e) {
    log.debug("Caught in keptAccount(): " + ((e && e.message) || e));
    kept = null;
  }
  log.debug("Leaving keptAccount().");
  return kept ? kept.username : '';
}

// A console tab signed in as a subject, its list read.
async function consoleTab(server, sub) {
  log.debug("Entering consoleTab().");
  const b = browser('/admin/users', storageOf(), server);
  const rt = new ConsoleRuntime(b.env);
  rt.subject = sub;
  rt.accessToken = 'at-' + sub;
  rt.refreshToken = 'rt-' + sub;
  rt.expiresAt = Date.now() + 600000;
  await rt.readAccounts('');
  log.debug("Leaving consoleTab().");
  return { rt: rt, b: b };
}

async function partAtOnce(t) {
  log.debug("Entering partAtOnce().");
  // --- 1. A switch in one tab while the other renews ----------------------
  const s1 = { list: listOf([ALICE, BOB]), tokenSub: 'urn:uuid:alice',
               hang: /\/admin-api\/users/ };
  const a = await consoleTab(s1, 'urn:uuid:alice');
  const s2 = { list: listOf([ALICE, BOB]), tokenSub: 'urn:uuid:bob' };
  const b = await consoleTab(s2, 'urn:uuid:bob');
  // Tab b's token is about to run out, so its next request renews first.
  b.rt.expiresAt = Date.now() + 1000;
  const inFlight = a.rt.send('GET', ORIGIN + '/admin-api/users');
  await until(function () {
    return a.b.calls.some(function (c) {
      return /admin-api\/users/.test(c.url);
    });
  });
  const both = await Promise.all([
    a.rt.switchAccount(BOB.key),
    b.rt.send('GET', ORIGIN + '/admin-api/roles'),
    inFlight
  ]);
  t.check(both[2] === null && a.rt.accessToken === '' &&
          lastAuthorize(a.b).searchParams.get('login_hint') === 'bob',
          '1. the switching tab\'s request in flight is aborted and it ' +
          'signs in naming bob');
  t.check(/^at-urn:uuid:bob-/.test(b.rt.accessToken) &&
          b.rt.subject === 'urn:uuid:bob' && keptAccount(b.b) === 'bob' &&
          !lastAuthorize(b.b),
          '1. the other tab renewed its own tokens at the same moment, and ' +
          'stayed bob', b.rt.accessToken);
  t.equal(keptAccount(a.b), 'alice', '1. and the switching tab keeps alice ' +
          'until the sign-in it started comes back as bob');
  log.debug("Leaving partAtOnce().");
}

async function partSwitchFailure(t) {
  log.debug("Entering partSwitchFailure().");
  // --- 2. The network gone during a switch -------------------------------
  const s = { list: listOf([ALICE, BOB]), tokenSub: 'urn:uuid:alice',
              fail: /\.well-known/ };
  const a = await consoleTab(s, 'urn:uuid:alice');
  await a.rt.switchAccount(BOB.key);
  t.check(lastAuthorize(a.b) &&
          lastAuthorize(a.b).searchParams.get('login_hint') === 'bob',
          '2. the metadata unreachable, a switch still signs in naming the ' +
          'account');
  const par = { list: listOf([ALICE, BOB]), tokenSub: 'urn:uuid:alice',
                meta: { require_pushed_authorization_requests: true,
                        pushed_authorization_request_endpoint:
                          ORIGIN + '/oauth2/par' },
                fail: /\/oauth2\/par$/ };
  const c = await consoleTab(par, 'urn:uuid:alice');
  let threw = '';
  try {
    await c.rt.switchAccount(BOB.key);
  } catch (e) {
    log.debug("Caught in partSwitchFailure(): " + ((e && e.message) || e));
    threw = String((e && e.message) || e);
  }
  t.check(!threw && !lastAuthorize(c.b) &&
          /Switching accounts failed/.test(c.b.env.document.body.innerHTML) &&
          keptAccount(c.b) === 'alice' && c.rt.accessToken === '',
          '2. a pushed request unreachable: the console says the switch ' +
          'failed, keeps alice as the tab\'s account and holds no token',
          threw || c.b.env.document.body.innerHTML.slice(0, 200));
  // The portal, the same.
  const pb = browser('/portal', storageOf(), par);
  const prt = new PortalRuntime(pb.env);
  prt.subject = 'urn:uuid:alice';
  prt.accessToken = 'at';
  prt.expiresAt = Date.now() + 600000;
  await prt.readAccounts('alice');
  let pthrew = '';
  try {
    await prt.switchAccount(BOB.key);
  } catch (e) {
    log.debug("Caught in partSwitchFailure(): " + ((e && e.message) || e));
    pthrew = String((e && e.message) || e);
  }
  t.check(!pthrew &&
          /Switching accounts failed/.test(pb.env.document.body.innerHTML) &&
          keptAccount(pb, 'sts-portal-account') === 'alice',
          '2. and the portal says so too, keeping alice',
          pthrew || pb.env.document.body.innerHTML.slice(0, 200));
  log.debug("Leaving partSwitchFailure().");
}

async function partRenewal(t) {
  log.debug("Entering partRenewal().");
  // --- 3. The network gone during a renewal ------------------------------
  const s = { list: listOf([ALICE, BOB]), tokenSub: 'urn:uuid:alice',
              fail: /\/oauth2\/token$/ };
  const a = await consoleTab(s, 'urn:uuid:alice');
  let threw = '';
  try {
    await a.rt.refresh();
  } catch (e) {
    log.debug("Caught in partRenewal(): " + ((e && e.message) || e));
    threw = String((e && e.message) || e);
  }
  t.check(!!threw && a.rt.refreshToken === 'rt-urn:uuid:alice' &&
          a.rt.subject === 'urn:uuid:alice' && keptAccount(a.b) === 'alice' &&
          !lastAuthorize(a.b),
          '3. a renewal the network failed keeps the refresh token, the ' +
          'subject and the account, and signs nobody in', threw);
  s.fail = null;
  t.check(await a.rt.refresh() === true &&
          /^at-urn:uuid:alice-/.test(a.rt.accessToken),
          '3. and the next renewal works');
  // AN ANSWER AFTER A SWITCH.
  const late = { list: listOf([ALICE, BOB]), tokenSub: 'urn:uuid:alice',
                 late: /\/oauth2\/token$/ };
  const l = await consoleTab(late, 'urn:uuid:alice');
  const renewing = l.rt.refresh();
  await until(function () {
    return typeof late.release === 'function';
  });
  await l.rt.switchAccount(BOB.key);
  late.release();
  const renewed = await renewing;
  t.check(renewed === false && l.rt.accessToken === '' &&
          l.rt.refreshToken === '' && l.rt.subject === '',
          '3. a renewal answered after a switch is not kept',
          JSON.stringify({ renewed: renewed, at: l.rt.accessToken }));
  log.debug("Leaving partRenewal().");
}

async function partSignOut(t) {
  log.debug("Entering partSignOut().");
  // --- 4. The network gone during a sign-out -----------------------------
  const s = { list: listOf([ALICE, BOB]), fail: /\/authn-api\/logout/ };
  const b = browser('/logout', storageOf(), s);
  const surface = new SignoutSurface(b.env);
  await surface.loadAccounts();
  surface.formTable = {
    'POST /logout': { path: '/authn-api/logout' },
    'POST /logout/accounts': { path: '/authn-api/logout/accounts' } };
  const flashes = [];
  surface.redraw = function () {
    flashes.push(surface.flash);
  };
  const steps = [
    { label: 'the account step', form: 'accounts',
      fields: { account: BOB.key } },
    { label: 'one account\'s global sign-out', form: '',
      fields: { scope: 'global', account: BOB.key } }];
  for (let i = 0; i < steps.length; i++) {
    const one = steps[i];
    const form = { getAttribute: function (name) {
      return name === 'data-sts-step' ? one.form || null : null;
    } };
    surface.formFields = function () {
      return Object.assign({}, one.fields);
    };
    let threw = '';
    try {
      await surface.submit(form, null);
    } catch (e) {
      log.debug("Caught in partSignOut(): " + ((e && e.message) || e));
      threw = String((e && e.message) || e);
    }
    const said = flashes[flashes.length - 1] || {};
    t.check(!threw && /could not be reached, so nothing was signed out/
              .test(String(said.error)),
            '4. ' + one.label + ' with the network gone says nothing was ' +
            'signed out', threw || JSON.stringify(said));
  }
  const channel = b.channels.filter(function (c) {
    return c.name === 'sts-accounts';
  })[0];
  t.check(!channel || channel.posted.length === 0,
          '4. and announces nothing to the other tabs');
  log.debug("Leaving partSignOut().");
}

async function partBroadcasts(t) {
  log.debug("Entering partBroadcasts().");
  // --- 5. Broadcasts: late, out of order, never, a read that fails -------
  const server = { list: listOf([ALICE, BOB]), tokenSub: 'urn:uuid:alice' };
  const a = await consoleTab(server, 'urn:uuid:alice');
  let redrawn = 0;
  a.rt.listenForAccounts(function () {
    redrawn++;
  });
  const channel = a.b.channels.filter(function (c) {
    return c.name === 'sts-accounts';
  })[0];
  // A READ THE NETWORK DROPS keeps the list in hand.
  server.fail = /\/authn-api\/accounts$/;
  channel.onmessage({ data: { type: WebAccounts.MESSAGE, change: 'added' } });
  await until(function () {
    return a.b.calls.filter(function (c) {
      return /\/authn-api\/accounts$/.test(c.url);
    }).length >= 2;
  });
  await settle();
  t.check(a.rt.accounts.enabled === true &&
          WebAccounts.live(a.rt.accounts).length === 2 && redrawn === 0,
          '5. a message whose read the network drops keeps the menu as it ' +
          'was, not off', JSON.stringify(a.rt.accounts).slice(0, 200));
  a.rt.accessToken = '';
  a.rt.signOut();
  t.check(a.b.location.assigned[a.b.location.assigned.length - 1] ===
          ORIGIN + '/logout?login_hint=alice',
          '5. so its sign-out still names the tab\'s account');
  // A MESSAGE THAT ARRIVES LATE, after the tab switched.
  server.fail = null;
  a.rt.subject = 'urn:uuid:alice';
  await a.rt.switchAccount(BOB.key);
  server.list = listOf([ALICE, BOB, CAROL]);
  channel.onmessage({ data: { type: WebAccounts.MESSAGE, change: 'added' } });
  await until(function () { return redrawn >= 1; });
  t.check(WebAccounts.live(a.rt.accounts).length === 3 &&
          keptAccount(a.b) === 'alice' && channel.posted.length === 0 &&
          JSON.parse(a.b.env.sessionStorage.store['sts-console-signin'])
            .expect === BOB.sub,
          '5. a message arriving after a switch redraws the list and changes ' +
          'neither the account the tab is nor the one it is switching to');
  // OUT OF ORDER, the later list read first: the menu ends at the server's.
  server.list = listOf([ALICE]);
  channel.onmessage({ data: { type: WebAccounts.MESSAGE,
                              change: 'signed-out' } });
  channel.onmessage({ data: { type: WebAccounts.MESSAGE, change: 'added' } });
  await until(function () { return redrawn >= 3; });
  t.check(WebAccounts.live(a.rt.accounts).length === 1,
          '5. messages out of order end at the server\'s list');
  log.debug("Leaving partBroadcasts().");
}

async function partRevoked(t) {
  log.debug("Entering partRevoked().");
  // --- 6. Revoked while a request is in flight ---------------------------
  const server = { list: listOf([ALICE, BOB]), tokenSub: 'urn:uuid:alice',
                   api: { status: 401,
                          challenge: 'DPoP error="invalid_token"' },
                   tokenStatus: 400 };
  const a = await consoleTab(server, 'urn:uuid:alice');
  const res = await a.rt.sendOnce('GET', ORIGIN + '/admin-api/users');
  t.check(res && res.needsSignIn === true && a.rt.accessToken === '' &&
          a.rt.refreshToken === '' && keptAccount(a.b) === 'alice',
          '6. a request whose session was revoked meanwhile, and whose ' +
          'renewal is refused, clears the tokens and keeps the account');
  await a.rt.beginSignIn('/admin/users');
  t.equal(lastAuthorize(a.b).searchParams.get('login_hint'), 'alice',
          '6. so the sign-in that follows names alice, never bob');
  log.debug("Leaving partRevoked().");
}

async function partIsolated(t) {
  log.debug("Entering partIsolated().");
  // --- 7. A failure in one tab leaves the other ---------------------------
  const sa = { list: listOf([ALICE, BOB]), tokenSub: 'urn:uuid:alice',
               fail: /./ };
  const sb = { list: listOf([ALICE, BOB]), tokenSub: 'urn:uuid:bob' };
  const a = await consoleTab(Object.assign({}, sa, { fail: null }),
                             'urn:uuid:alice');
  a.b.env.fetch = browser('/admin', storageOf(), sa).env.fetch;
  const b = await consoleTab(sb, 'urn:uuid:bob');
  const before = JSON.stringify([b.rt.accessToken, b.rt.refreshToken,
                                 b.rt.subject, keptAccount(b.b)]);
  let threw = '';
  try {
    await a.rt.refresh();
  } catch (e) {
    log.debug("Caught in partIsolated(): " + ((e && e.message) || e));
    threw = String((e && e.message) || e);
  }
  t.check(!!threw && JSON.stringify([b.rt.accessToken, b.rt.refreshToken,
                                     b.rt.subject, keptAccount(b.b)]) ===
            before && keptAccount(a.b) === 'alice',
          '7. one tab\'s failed renewal leaves the other tab\'s tokens and ' +
          'account, and its own account, as they were', before);
  log.debug("Leaving partIsolated().");
}

async function run(t) {
  log.debug("Entering run().");
  try {
    await partAtOnce(t);
    await partSwitchFailure(t);
    await partRenewal(t);
    await partSignOut(t);
    await partBroadcasts(t);
    await partRevoked(t);
    await partIsolated(t);
  } finally {
    // A surface's translator becomes the process's default when it loads;
    // put back node's English one, as `multi_account_tabs.js` does.
    WebMessages.WebTranslator.setDefault(function () {
      return i18n.translator(['en']);
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'multi account concurrency tabs',
  describe: 'several signed-in accounts in one browser, the runtimes under ' +
            'concurrency and failure (#561 TR-2, #731): two tabs at once, ' +
            'the network gone during a switch, a renewal and a sign-out, ' +
            'broadcasts late, out of order, lost or unreadable, a session ' +
            'revoked in flight, one tab\'s failure leaving the other',
  run: run
};
