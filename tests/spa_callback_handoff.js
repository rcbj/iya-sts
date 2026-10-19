// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/spa_callback_handoff.js
//
// ---------------------------------------------------------------------------
// A SAME-DEVICE WALLET RETURNS IN A NEW TAB. The passkey finishes there, and
// the authorization server sends that tab to `/portal/callback`. The PKCE
// record is in the tab that opened the portal, still sitting on the wallet
// wait page. The return tab offers the callback; the waiting tab loads it
// and redeems the code. The console is the same shape.
// ---------------------------------------------------------------------------

const nodeCrypto = require('crypto');
const SpaClient = require('../common/web_spa_client');
const PortalRuntime = require('../portal/web_portal_runtime');
const ConsoleRuntime = require('../admin-ui/web_runtime');
const WalletFlow = require('../oid4vc/web_vc_signin').Flow;

const log = require('bunyan').createLogger({
  name: 'spa_callback_handoff',
  level: process.env.LOG_LEVEL || 'info' });

const ORIGIN = 'https://localhost:8081';
const STATE = 'state-from-the-portal';
const CODE = 'code-from-the-server';
const VERIFIER = 'verifier-kept-in-the-first-tab';

/**
 * The nonce a sign-in with this PKCE verifier sends.
 *
 * @param verifier - the PKCE verifier
 * @returns the nonce
 */
function nonceOf(verifier) {
  log.debug('Entering nonceOf().');
  log.debug('Leaving nonceOf().');
  return nodeCrypto.createHash('sha256').update('nonce:' + verifier)
    .digest('base64url');
}

/**
 * An unsigned JWT carrying a subject and a nonce.
 *
 * @param sub - the subject
 * @param nonce - the nonce
 * @returns the compact JWT
 */
function idTokenFor(sub, nonce) {
  log.debug('Entering idTokenFor().');
  const b64u = function (value) {
    return Buffer.from(JSON.stringify(value)).toString('base64url');
  };
  log.debug('Leaving idTokenFor().');
  return b64u({ alg: 'none' }) + '.' +
    b64u({ sub: sub, nonce: nonce }) + '.sig';
}

/**
 * One BroadcastChannel shared by every tab in the test.
 *
 * @param name - the channel name
 * @param bus - the open channels, by name
 */
function Channel(name, bus) {
  this.name = name;
  this.onmessage = null;
  this.closed = false;
  this.posted = [];
  this.bus = bus;
  (bus[name] = bus[name] || []).push(this);
}

Channel.prototype.postMessage = function (data) {
  this.posted.push(data);
  const peers = (this.bus[this.name] || []).slice();
  for (let i = 0; i < peers.length; i++) {
    const peer = peers[i];
    if (peer !== this && !peer.closed && peer.onmessage) {
      peer.onmessage({ data: data });
    }
  }
};

Channel.prototype.close = function () {
  this.closed = true;
};

/**
 * A browser stand-in. `store` is its sessionStorage.
 *
 * @param pathname - the path
 * @param search - the query, including `?`
 * @param store - the sessionStorage contents
 * @param bus - the shared channels
 * @param calls - token and other fetches, pushed here
 * @returns `{ env, location, body }`
 */
function browser(pathname, search, store, bus, calls) {
  log.debug('Entering browser().');
  const location = {
    origin: ORIGIN, pathname: pathname, search: search, hash: '',
    assigned: '',
    assign: function (url) { location.assigned = String(url); }
  };
  const body = { innerHTML: '' };
  const env = {
    crypto: globalThis.crypto,
    location: location,
    history: {
      replaceState: function (_s, _t, url) {
        const u = new URL(url, ORIGIN);
        location.pathname = u.pathname;
        location.search = u.search;
        location.hash = u.hash;
      },
      pushState: function () {}
    },
    document: {
      title: '', body: body,
      documentElement: {},
      querySelectorAll: function () { return []; },
      getElementById: function () { return null; },
      addEventListener: function () {}
    },
    sessionStorage: {
      getItem: function (key) {
        return Object.prototype.hasOwnProperty.call(store, key)
          ? store[key] : null;
      },
      setItem: function (key, value) { store[key] = String(value); },
      removeItem: function (key) { delete store[key]; }
    },
    navigator: {},
    window: {
      BroadcastChannel: function (name) { return new Channel(name, bus); },
      setTimeout: function (fn, ms) { return setTimeout(fn, ms); },
      clearTimeout: function (id) { clearTimeout(id); },
      focus: function () { env.window.focused = true; },
      focused: false
    },
    fetch: async function (url) {
      calls.push(String(url));
      const headers = { get: function () { return ''; } };
      if (/\/oauth2\/token$/.test(String(url))) {
        return { status: 200, headers: headers, json: async function () {
          return { access_token: 'at', expires_in: 300, refresh_token: 'rt',
                   id_token: idTokenFor('urn:uuid:rcbj', nonceOf(VERIFIER)) };
        } };
      }
      return { status: 500, headers: headers,
               json: async function () { return {}; } };
    }
  };
  log.debug('Leaving browser().');
  return { env: env, location: location, body: body };
}

/**
 * The record `beginSignIn` writes.
 *
 * @param state - the state
 * @param returnTo - where to land
 * @returns the JSON
 */
function record(state, returnTo) {
  log.debug('Entering record().');
  log.debug('Leaving record().');
  return JSON.stringify({ verifier: VERIFIER, state: state,
                          returnTo: returnTo, prefix: '' });
}

/**
 * A wallet wait page.
 *
 * @param env - the browser
 * @param query - the page's query
 * @returns the flow
 */
function waiting(env, query) {
  log.debug('Entering waiting().');
  const flow = new WalletFlow({
    env: env,
    ensureIndex: async function () { return false; },
    refused: function () {},
    showView: function () {},
    send: async function () { return { status: 200, json: {} }; }
  });
  flow.arm({ state: 'wallet-tx', qr: '' }, query || {});
  log.debug('Leaving waiting().');
  return flow;
}

async function run(t) {
  log.debug('Entering run().');
  t.equal(WalletFlow.CALLBACK_CHANNEL, SpaClient.CALLBACK_CHANNEL,
          'the wait page listens on the channel the callback offers');
  t.equal(WalletFlow.SIGNIN_KEYS.join(' '), SpaClient.SIGNIN_KEYS.join(' '),
          'the wait page knows both applications\' sign-in records');

  // The return tab has the code and no record. The waiting tab has the
  // record. It loads the callback, and the code is not on the offer.
  const bus = {};
  const calls = [];
  const waitingStore = { 'sts-portal-signin': record(STATE, '/portal') };
  const held = browser('/authn/wallet/wait', '?authn=1&state=wallet-tx',
                       waitingStore, bus, calls);
  const back = browser('/portal/callback',
                       '?code=' + CODE + '&state=' + STATE, {}, bus, calls);
  waiting(held.env, {});
  const portal = new PortalRuntime(back.env);
  await portal.finishSignIn();
  t.check(/Continue in your other tab/.test(back.body.innerHTML) &&
          !/does not belong/.test(back.body.innerHTML),
          'the return tab says the sign-in continues in the first tab',
          back.body.innerHTML.slice(0, 180));
  t.equal(back.location.pathname + back.location.search, '/portal/callback',
          'the code leaves the return tab\'s address');
  t.equal(held.location.assigned,
          '/portal/callback?code=' + CODE + '&state=' + STATE,
          'the waiting tab is sent the callback');
  t.check(held.env.window.focused === true,
          'the waiting tab is asked to come forward');
  const offered = (bus[SpaClient.CALLBACK_CHANNEL] || [])
    .reduce(function (all, ch) { return all.concat(ch.posted); }, []);
  const offer = offered.filter(function (m) { return m.type === 'continue'; });
  t.check(offer.length === 1 && !offer[0].location && !offer[0].code,
          'the offer names the state and not the code',
          JSON.stringify(offer));
  t.equal(calls.length, 0, 'the return tab redeems nothing');

  // That address, loaded in the tab that holds the record, redeems it.
  const again = [];
  const finisher = browser('/portal/callback',
    '?code=' + CODE + '&state=' + STATE, waitingStore, {}, again);
  await new PortalRuntime(finisher.env).finishSignIn();
  t.check(again.some(function (url) { return /\/oauth2\/token$/.test(url); }) &&
          !/does not belong/.test(finisher.body.innerHTML),
          'the tab that holds the record redeems the code',
          finisher.body.innerHTML.slice(0, 180));

  // A record for a different sign-in does not take this callback.
  const wrongBus = {};
  const wrongCalls = [];
  const wrong = browser('/authn/wallet/wait', '', {
    'sts-portal-signin': record('some-other-state', '/portal')
  }, wrongBus, wrongCalls);
  const refused = browser('/portal/callback',
    '?code=' + CODE + '&state=' + STATE, {}, wrongBus, wrongCalls);
  waiting(wrong.env, {});
  await new PortalRuntime(refused.env).finishSignIn();
  t.check(/does not belong/.test(refused.body.innerHTML),
          'no matching record, and the return tab says so',
          refused.body.innerHTML.slice(0, 180));
  t.equal(wrong.location.assigned, '',
          'a different sign-in\'s tab stays where it is');

  // The tab the wallet opened collects the response and does not listen.
  const returnBus = {};
  const returnCalls = [];
  const opened = browser('/authn/wallet/wait', '?response_code=once', {
    'sts-portal-signin': record(STATE, '/portal')
  }, returnBus, returnCalls);
  const openedFlow = waiting(opened.env, { response_code: 'once' });
  t.equal(openedFlow.channel, null,
          'the return tab does not listen for the callback');
  const poke = new Channel(SpaClient.CALLBACK_CHANNEL, returnBus);
  poke.postMessage({ type: 'continue', state: STATE, nonce: 'n' });
  poke.postMessage({ type: 'go', state: STATE, nonce: 'n',
                     location: '/portal/callback?code=' + CODE +
                               '&state=' + STATE });
  t.equal(opened.location.assigned, '',
          'a response_code tab does not take the callback');

  // An authorization error is the refusal, not a handoff.
  const errBus = {};
  const err = browser('/portal/callback',
    '?error=access_denied&state=' + STATE, {}, errBus, []);
  await new PortalRuntime(err.env).finishSignIn();
  t.check(/Signing in was refused/.test(err.body.innerHTML) &&
          !(errBus[SpaClient.CALLBACK_CHANNEL] || []).length,
          'an authorization error is not offered to another tab',
          err.body.innerHTML.slice(0, 120));

  // The console's callback is the same handoff, on its own record.
  const consoleBus = {};
  const consoleStore = { 'sts-console-signin': record(STATE, '/admin') };
  const consoleWait = browser('/authn/wallet/wait', '', consoleStore,
                             consoleBus, []);
  const consoleBack = browser('/admin/callback',
    '?code=' + CODE + '&state=' + STATE, {}, consoleBus, []);
  waiting(consoleWait.env, {});
  await new ConsoleRuntime(consoleBack.env).finishSignIn();
  t.check(/opened the console/.test(consoleBack.body.innerHTML),
          'the console\'s return tab points at the tab that opened it',
          consoleBack.body.innerHTML.slice(0, 180));
  t.equal(consoleWait.location.assigned,
          '/admin/callback?code=' + CODE + '&state=' + STATE,
          'the waiting tab is sent the console callback');

  log.debug('Leaving run().');
}

module.exports = {
  name: 'spa_callback_handoff',
  describe: 'a same-device wallet\'s callback is finished by the tab that ' +
            'started the sign-in',
  run: run
};
