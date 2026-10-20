// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/multi_account_concurrency.js
//
// ===========================================================================
// SEVERAL SIGNED-IN ACCOUNTS IN ONE BROWSER, WHEN THINGS HAPPEN AT ONCE OR
// GO WRONG: THE SERVER'S HALF (#561's TR-2, #731).
//
// `tests/multi_account_sessions.js` holds the contract one request at a
// time. This file holds it when two tabs of ONE browser act at once — each
// request built from the cookie jar as it was before either answer arrived,
// the answers then taken in either order, which is what two tabs' requests
// in flight together are — and when a session ends under a request that
// chose it:
//
//   1. two sign-ins at once: every session that signed in is live, nobody
//      is answered as another account, and the stale set cookie opens
//      nothing (the lost place is the measured cost, `authn/CLAUDE.md`);
//   2. two selections at once, in two flows: each flow resumes as the
//      account its own tab chose, whichever answer wrote the default last;
//   3. two sign-outs at once: both accounts are signed out, the third is
//      untouched and is then the browser's only account;
//   4. a session revoked while a flow that chose it is in flight: the
//      resumed request acts as NOBODY and goes to sign in as that account
//      — never on as the other account live in the browser (the bug this
//      file found, fixed in `authn.ts`'s `spendAccountTicket()`) — and the
//      same account signed in again meanwhile is taken; a picker drawn
//      before the revocation sends a select to the sign-in;
//   5. conflicting updates to one set on two nodes, through the store's
//      own `mergeRow`: either flush order gives one answer, an ended
//      session and a forgotten account are not brought back, a key live
//      again is not remembered, and a later sign-out survives an earlier
//      forget;
//   6. a failure in one session leaves the others as they were: an
//      administrator ending one, a row that cannot be pruned on the
//      clean-up job, a set gone from under a session that ends;
//   7. `/admin/sessions` and `GET /admin-api/sessions` (#731): each row of
//      a set names it, `?q=` with the id lists that browser's sessions and
//      no other, no answer carries the cookie's handle, and the counters
//      moved by what this file did are answered and drawn.
//
// WHY IN PROCESS: which session a request acted as and what a row holds
// are facts about the stores; over HTTP the races are not reproducible.
// The browser runtimes' half is `tests/multi_account_concurrency_tabs.js`.
// ===========================================================================

delete process.env.CONFIG_FILE;

const realms = require('../common/realms');
const config = require('../common/config');
require('../common/app');
const authn = require('../authn/authn');
const AccountSets = require('../authn/account_sets');
const stats = require('../common/admin_stats');
const logout = require('../logout/logout');
const adminViews = require('../admin-core/admin_views');
const WebKit = require('../admin-ui/web_kit');
const SessionsPage = require('../logout/web_sessions');
const i18n = require('../common/i18n');

const log = require('bunyan').createLogger({
  name: 'multi_account_concurrency',
  level: process.env.LOG_LEVEL || 'info' });

// ---------------------------------------------------------------------------
// A browser, as `multi_account_sessions.js` has it: a cookie jar, and a
// response whose `set()` replaces every Set-Cookie and `append()` adds one,
// as express's do. `req()` reads the jar AS IT IS NOW, so two requests built
// before either answer is taken are two tabs' requests in flight together.
// ---------------------------------------------------------------------------
function fakeRes() {
  log.debug("Entering fakeRes().");
  const res = { cookies: [], locals: {}, headersSent: false,
                statusCode: 200, body: null, where: '' };
  res.set = function (name, value) {
    if (String(name).toLowerCase() === 'set-cookie') {
      res.cookies = [String(value)];
    }
    return res;
  };
  res.append = function (name, value) {
    if (String(name).toLowerCase() === 'set-cookie') {
      res.cookies.push(String(value));
    }
    return res;
  };
  res.status = function (code) {
    res.statusCode = code;
    return res;
  };
  res.type = function () {
    return res;
  };
  res.send = function (body) {
    res.body = body;
    res.headersSent = true;
    return res;
  };
  res.location = function (url) {
    res.where = String(url);
    return res;
  };
  res.get = function (name) {
    return String(name).toLowerCase() === 'location' ? res.where : undefined;
  };
  res.removeHeader = function () {
    res.where = '';
  };
  res.redirect = function (code, url) {
    res.statusCode = code;
    res.where = String(url);
  };
  log.debug("Leaving fakeRes().");
  return res;
}

function browser() {
  log.debug("Entering browser().");
  const jar = {};
  const b = {
    jar: jar,
    req: function (url) {
      const res = fakeRes();
      const header = Object.keys(jar).map(function (k) {
        return k + '=' + jar[k];
      }).join('; ');
      const query = {};
      const at = String(url || '/').indexOf('?');
      if (at >= 0) {
        String(url).slice(at + 1).split('&').forEach(function (part) {
          const i = part.indexOf('=');
          if (i > 0) {
            query[part.slice(0, i)] = decodeURIComponent(part.slice(i + 1));
          }
        });
      }
      const req = { headers: { cookie: header }, query: query,
                    url: String(url || '/'), originalUrl: String(url || '/'),
                    method: 'GET', res: res };
      res.req = req;
      return req;
    },
    take: function (res) {
      (res.cookies || []).forEach(function (line) {
        const pair = String(line).split(';')[0];
        const i = pair.indexOf('=');
        if (i <= 0) {
          return;
        }
        const name = pair.slice(0, i).trim();
        const value = pair.slice(i + 1).trim();
        if (!value || /Max-Age=0/i.test(line)) {
          delete jar[name];
        } else {
          jar[name] = value;
        }
      });
    }
  };
  log.debug("Leaving browser().");
  return b;
}

// Every session this file made, ended when it is done (the suite shares one
// process, and `scheduler_jobs.js` counts what one sweep ends).
const made = [];

// A sign-in on a request already built (a tab's request in flight).
function signInOn(req, username) {
  log.debug("Entering signInOn(). " + username);
  const detail = { request: req };
  const session = authn.startSession(req.res, username, ['pwd'], '1',
                                     'OAuth 2.0 / OIDC', detail);
  if (session) {
    made.push(session.id);
  }
  log.debug("Leaving signInOn().");
  return session;
}

function signIn(b, username) {
  log.debug("Entering signIn(). " + username);
  const req = b.req('/authn-api/pending/x/password');
  const session = signInOn(req, username);
  b.take(req.res);
  log.debug("Leaving signIn().");
  return session;
}

function withSettings(pairs, fn) {
  log.debug("Entering withSettings().");
  const keys = Object.keys(pairs);
  try {
    keys.forEach(function (key) {
      config.setOverride(key, String(pairs[key]));
    });
    log.debug("Leaving withSettings().");
    return fn();
  } finally {
    keys.forEach(function (key) {
      config.clearOverride(key);
    });
  }
}

function setOf(b) {
  log.debug("Entering setOf().");
  const value = String(b.jar[AccountSets.cookieName()] || '');
  log.debug("Leaving setOf().");
  return value ? AccountSets.byId(value.split('.')[0]) : null;
}

function answerOf(res) {
  log.debug("Entering answerOf().");
  let json = null;
  try {
    json = JSON.parse(String(res.body || 'null'));
  } catch (e) {
    log.debug("Caught in answerOf(): " + ((e && e.message) || e));
    json = null;
  }
  log.debug("Leaving answerOf().");
  return json;
}

// Which session a request from this browser acts as, with a hint or none.
function actsAs(b, url, hint) {
  log.debug("Entering actsAs().");
  const req = b.req(url || '/oauth2/authorize');
  if (hint) {
    authn.hintAccount(req, hint);
  }
  const s = authn.sessionOf(req);
  log.debug("Leaving actsAs().");
  return s ? s.id : '';
}

function keyOf(session, username) {
  log.debug("Entering keyOf().");
  log.debug("Leaving keyOf().");
  return AccountSets.keyOf({ sub: ((session && session.user) || {}).sub,
                             username: username });
}

// A picker opened on this browser for a flow returning to `returnTo`.
function picker(b, returnTo) {
  log.debug("Entering picker().");
  const path = authn.beginAuthentication({
    returnTo: returnTo, details: [], protocol: 'OAuth 2.0 / OIDC',
    application: '', request: b.req(returnTo) });
  const m = /[?&]authn=([^&]+)/.exec(String(path));
  const id = m ? decodeURIComponent(m[1]) : '';
  log.debug("Leaving picker().");
  return { path: path, id: id, record: id ? authn.pendingForAccounts(id)
                                          : null };
}

// ---------------------------------------------------------------------------
// 1. TWO SIGN-INS AT ONCE.
// ---------------------------------------------------------------------------
function partSignIns(t) {
  log.debug("Entering partSignIns().");
  t.log.info('=== 1. two sign-ins at once, in two tabs ===');
  const b = browser();
  const alice = signIn(b, 'mac-alice');
  const before = String(b.jar[AccountSets.cookieName()] || '');
  // Both tabs' requests leave with the jar as it is now.
  const tab1 = b.req('/authn-api/pending/1/password');
  const tab2 = b.req('/authn-api/pending/2/password');
  const bob = signInOn(tab1, 'mac-bob');
  const carol = signInOn(tab2, 'mac-carol');
  t.check(!!bob && !!carol && bob.id !== carol.id &&
          !!authn.sessions.get(alice.id),
          '1. both sign-ins made a session of their own, and neither ended ' +
          'the session already there');
  // The answers arrive: tab1's, then tab2's.
  b.take(tab1.res);
  b.take(tab2.res);
  const set = setOf(b);
  t.check(!!set && !!set.sessions[carol.id] && !!set.sessions[alice.id],
          '1. the browser\'s set holds the session of the answer it took ' +
          'last and the session it already had',
          JSON.stringify(set && Object.keys(set.sessions)));
  t.equal(actsAs(b, '', { loginHint: 'mac-alice' }), alice.id,
          '1. a request naming alice acts as alice');
  t.equal(actsAs(b, '', { loginHint: 'mac-carol' }), carol.id,
          '1. a request naming carol acts as carol');
  const forBob = actsAs(b, '', { loginHint: 'mac-bob' });
  t.equal(forBob, set.sessions[bob.id] ? bob.id : '',
          '1. a request naming bob acts as bob where the set kept him, and ' +
          'otherwise as NOBODY — never as alice or carol');
  // THE STALE COOKIE: the set cookie both tabs left with no longer opens
  // the set (its handle rotated), so a request presenting it alone is a
  // browser with no set.
  const stale = browser();
  stale.jar[AccountSets.cookieName()] = before;
  t.equal(actsAs(stale), '', '1. the set cookie from before the sign-ins ' +
          'opens nothing: a request presenting it alone acts as nobody');
  // Signing bob in again, one request at a time, puts him in the set.
  const bobAgain = signIn(b, 'mac-bob');
  t.check(!!bobAgain && !!setOf(b).sessions[bobAgain.id] &&
          actsAs(b, '', { loginHint: 'mac-bob' }) === bobAgain.id,
          '1. signing in again as the account the race left out puts it in ' +
          'the browser\'s set');
  log.debug("Leaving partSignIns().");
}

// ---------------------------------------------------------------------------
// 2. TWO SELECTIONS AT ONCE, IN TWO FLOWS.
// ---------------------------------------------------------------------------
function partSelections(t) {
  log.debug("Entering partSelections().");
  t.log.info('=== 2. two selections at once, in two flows ===');
  [false, true].forEach(function (reversed) {
    const b = browser();
    const alice = signIn(b, 'mac-sel-alice' + (reversed ? '-r' : ''));
    const bob = signIn(b, 'mac-sel-bob' + (reversed ? '-r' : ''));
    const one = picker(b, '/oauth2/authorize?client_id=one');
    const two = picker(b, '/oauth2/authorize?client_id=two');
    t.check(!!one.record && !!two.record, '2. two flows, two pickers' +
            (reversed ? ' (answers taken in reverse)' : ''),
            one.path + ' ' + two.path);
    const actOne = b.req('/authn-api/pending/' + one.id + '/accounts/select');
    const actTwo = b.req('/authn-api/pending/' + two.id + '/accounts/select');
    authn.accountsAct(actOne, actOne.res, one.record,
                      { action: 'select', account: keyOf(alice, '') });
    authn.accountsAct(actTwo, actTwo.res, two.record,
                      { action: 'select', account: keyOf(bob, '') });
    const a1 = answerOf(actOne.res) || {};
    const a2 = answerOf(actTwo.res) || {};
    if (reversed) {
      b.take(actTwo.res);
      b.take(actOne.res);
    } else {
      b.take(actOne.res);
      b.take(actTwo.res);
    }
    const resume = function (location) {
      const req = b.req(location);
      authn.spendAccountTicket(req);
      const s = authn.sessionOf(req);
      return s ? s.id : '';
    };
    t.check(/client_id=one/.test(String(a1.location)) &&
            /client_id=two/.test(String(a2.location)),
            '2. each select answers its own flow', JSON.stringify([a1, a2]));
    t.equal(resume(a1.location), alice.id, '2. the first flow resumes as ' +
            'alice, the account its tab chose' +
            (reversed ? ' (reverse)' : ''));
    t.equal(resume(a2.location), bob.id, '2. the second flow resumes as ' +
            'bob, the account its tab chose' + (reversed ? ' (reverse)' : ''));
    t.equal(actsAs(b), '', '2. and a request of neither flow names nobody: ' +
            'a choice is a flow\'s, never the browser\'s');
  });
  log.debug("Leaving partSelections().");
}

// ---------------------------------------------------------------------------
// 3. TWO SIGN-OUTS AT ONCE.
// ---------------------------------------------------------------------------
function partSignOuts(t) {
  log.debug("Entering partSignOuts().");
  t.log.info('=== 3. two sign-outs at once ===');
  const b = browser();
  const alice = signIn(b, 'mac-out-alice');
  const bob = signIn(b, 'mac-out-bob');
  const carol = signIn(b, 'mac-out-carol');
  // What bob's session IS — its subject, clocks and events. Its cookie
  // handle may be minted again, where his becomes the browser's default.
  const facts = function (session) {
    return JSON.stringify(session ? { user: session.user,
      expires: session.expires, authTime: session.authTime,
      events: (session.events || []).length, amr: session.amr } : null);
  };
  const bobBefore = facts(authn.sessions.get(bob.id));
  const tab1 = b.req('/logout');
  const tab2 = b.req('/logout');
  authn.endSession(tab1, tab1.res, alice.id);
  // Carol is the browser's default: the second tab's sign-out ends it.
  authn.endSession(tab2, tab2.res, carol.id);
  b.take(tab2.res);
  b.take(tab1.res);
  t.check(!authn.sessions.get(alice.id) && !authn.sessions.get(carol.id),
          '3. both sign-outs ended their sessions');
  t.equal(facts(authn.sessions.get(bob.id)), bobBefore,
          '3. bob\'s session is as it was: the same person, clocks and ' +
          'events');
  const set = setOf(b);
  t.check(!!set && !!set.sessions[bob.id] && !set.sessions[alice.id] &&
          !set.sessions[carol.id] &&
          !!set.remembered[keyOf(alice, 'mac-out-alice')] &&
          !!set.remembered[keyOf(carol, 'mac-out-carol')],
          '3. the set holds bob, and remembers alice and carol as signed out',
          JSON.stringify(set));
  t.equal(actsAs(b), bob.id, '3. a request naming nobody acts as bob, the ' +
          'browser\'s one account left, whichever answer came last');
  t.equal(actsAs(b, '', { loginHint: 'mac-out-carol' }), '',
          '3. and one naming carol acts as nobody');
  log.debug("Leaving partSignOuts().");
}

// ---------------------------------------------------------------------------
// 4. A SESSION REVOKED WHILE A FLOW THAT CHOSE IT IS IN FLIGHT.
// ---------------------------------------------------------------------------
function partRevoked(t) {
  log.debug("Entering partRevoked().");
  t.log.info('=== 4. a session revoked while a request is in flight ===');
  const b = browser();
  const alice = signIn(b, 'mac-rev-alice');
  const bob = signIn(b, 'mac-rev-bob');
  const flow = picker(b, '/oauth2/authorize?client_id=rev');
  const act = b.req('/authn-api/pending/' + flow.id + '/accounts/select');
  authn.accountsAct(act, act.res, flow.record,
                    { action: 'select', account: keyOf(alice, '') });
  b.take(act.res);
  const answer = answerOf(act.res) || {};
  t.check(/sts_account=/.test(String(answer.location)),
          '4. alice was chosen, and the flow resumes with a ticket',
          JSON.stringify(answer));
  // An administrator ends alice's session before the resumed request lands.
  authn.endSessionById(alice.id, 'multi_account_concurrency 4');
  const resumed = b.req(answer.location);
  authn.spendAccountTicket(resumed);
  t.equal(authn.sessionOf(resumed), null, '4. the resumed request acts as ' +
          'NOBODY — not as bob, the one account still live in the browser');
  const need = authn.accountChoiceNeeded(resumed) || {};
  t.check(need.reason === 'hint-unmatched' && need.hint === 'mac-rev-alice',
          '4. it is a hint naming nobody here, and the name is alice\'s',
          JSON.stringify(need));
  const where = authn.beginAuthentication({
    returnTo: '/oauth2/authorize?client_id=rev', details: [],
    protocol: 'OAuth 2.0 / OIDC', application: '', request: resumed });
  const id = decodeURIComponent((/[?&]authn=([^&]+)/.exec(where) || [])[1] ||
                                '');
  const record = id ? authn.pendingFor(id) : null;
  t.check(/^\/authn\/login\?/.test(where) && !!record &&
          record.hint === 'mac-rev-alice',
          '4. and the flow goes to sign in as alice, her name filled in',
          where + ' ' + JSON.stringify(record && record.hint));
  t.check(!!authn.sessions.get(bob.id), '4. bob\'s session is untouched');

  // THE SAME ACCOUNT SIGNED IN AGAIN MEANWHILE is what was chosen.
  const set = setOf(b);
  const carol = signIn(b, 'mac-rev-carol');
  const ticket = AccountSets.mintTicket(set.id, carol.id,
                                        '/oauth2/authorize', 'p-rev');
  authn.endSessionById(carol.id, 'multi_account_concurrency 4');
  const carolAgain = signIn(b, 'mac-rev-carol');
  const later = b.req('/oauth2/authorize?sts_account=' + ticket);
  authn.spendAccountTicket(later);
  t.equal((authn.sessionOf(later) || {}).id, carolAgain.id,
          '4. a ticket whose session ended, its account signed in again ' +
          'meanwhile, acts as that account\'s new session');

  // A PICKER DRAWN BEFORE THE REVOCATION.
  const drawn = picker(b, '/oauth2/authorize?client_id=rev2');
  const view = authn.accountsView(b.req('/authn-api/pending/' + drawn.id +
                                        '/accounts'), drawn.record);
  t.check(view.accounts.some(function (one) {
    return one.username === 'mac-rev-bob' && one.state === 'signed-in';
  }), '4. the picker lists bob as signed in');
  authn.endSessionById(bob.id, 'multi_account_concurrency 4');
  const pick = b.req('/authn-api/pending/' + drawn.id + '/accounts/select');
  authn.accountsAct(pick, pick.res, drawn.record,
                    { action: 'select', account: keyOf(bob, '') });
  const picked = answerOf(pick.res) || {};
  t.check(picked.next === 'redirect' &&
          /^\/authn\/login\?authn=/.test(String(picked.location)) &&
          !/sts_account=/.test(String(picked.location)),
          '4. choosing bob, revoked after the picker was drawn, goes to the ' +
          'sign-in with no ticket', JSON.stringify(picked));
  log.debug("Leaving partRevoked().");
}

// ---------------------------------------------------------------------------
// 5. CONFLICTING UPDATES TO ONE SET, ON TWO NODES.
// ---------------------------------------------------------------------------
function same(a, b) {
  log.debug("Entering same().");
  const norm = function (row) {
    return JSON.stringify({ sessions: Object.keys(row.sessions || {}).sort(),
      remembered: Object.keys(row.remembered || {}).sort(),
      handleHash: row.handleHash, lastActiveSid: row.lastActiveSid });
  };
  log.debug("Leaving same().");
  return norm(a) === norm(b);
}

function partMerge(t) {
  log.debug("Entering partMerge().");
  t.log.info('=== 5. conflicting updates to one set, on two nodes ===');
  const handle = realms.handleFor('authn.accountSets');
  const mergeRow = handle && handle.mergeRow;
  t.check(typeof mergeRow === 'function', '5. the store declares a ' +
          'mergeRow, which a flush on another node calls');
  if (typeof mergeRow !== 'function') {
    log.debug("Leaving partMerge(). No merge.");
    return;
  }
  const at = 1760000000000;
  const base = { id: 'mac-merge', handleHash: 'h0', handleIssuedAt: at,
    createdAt: at, updatedAt: at, lastActiveSid: 's-alice',
    sessions: { 's-alice': { sub: 'urn:alice', username: 'alice' },
                's-bob': { sub: 'urn:bob', username: 'bob' } },
    remembered: { 'urn:carol': { sub: 'urn:carol', username: 'carol',
                                 signedOutAt: at - 1000 },
                  'urn:erin': { sub: 'urn:erin', username: 'erin',
                                signedOutAt: at - 5000 } },
    endedSids: {}, forgotten: {} };
  const copy = function (row) {
    return JSON.parse(JSON.stringify(row));
  };
  // NODE A: dave signs in (a rotation), and carol signs in again.
  const nodeA = copy(base);
  nodeA.sessions['s-dave'] = { sub: 'urn:dave', username: 'dave' };
  nodeA.sessions['s-carol'] = { sub: 'urn:carol', username: 'carol' };
  delete nodeA.remembered['urn:carol'];
  nodeA.handleHash = 'hA';
  nodeA.handleIssuedAt = at + 2000;
  nodeA.lastActiveSid = 's-dave';
  // NODE B, from the same base: alice signs out, erin is forgotten, and a
  // stale copy still remembers carol.
  const nodeB = copy(base);
  delete nodeB.sessions['s-alice'];
  nodeB.endedSids['s-alice'] = at + 1000;
  nodeB.remembered['urn:alice'] = { sub: 'urn:alice', username: 'alice',
                                    signedOutAt: at + 1000 };
  delete nodeB.remembered['urn:erin'];
  nodeB.forgotten['urn:erin'] = at + 1500;
  nodeB.lastActiveSid = '';
  // Two flush orders: A's write then B's merged over it, and the reverse.
  const aThenB = mergeRow(copy(nodeB), mergeRow(copy(nodeA), copy(base)));
  const bThenA = mergeRow(copy(nodeA), mergeRow(copy(nodeB), copy(base)));
  t.check(same(aThenB, bThenA), '5. either flush order gives one answer',
          JSON.stringify([aThenB, bThenA]));
  t.check(!aThenB.sessions['s-alice'] && !!aThenB.remembered['urn:alice'],
          '5. alice\'s ended session is not brought back by A\'s copy, and ' +
          'she is remembered as signed out');
  t.check(!!aThenB.sessions['s-dave'] && !!aThenB.sessions['s-bob'] &&
          !!aThenB.sessions['s-carol'],
          '5. dave\'s new session and carol\'s are kept, and bob\'s');
  t.check(!aThenB.remembered['urn:carol'], '5. carol, live again, is not ' +
          'remembered as signed out because B\'s stale copy said so');
  t.check(!aThenB.remembered['urn:erin'], '5. erin, forgotten on B, is not ' +
          'brought back by A\'s copy');
  t.check(aThenB.handleHash === 'hA' && aThenB.lastActiveSid === 's-dave',
          '5. the handle is the later rotation\'s, and so is the last ' +
          'active session');
  t.check(same(mergeRow(copy(aThenB), copy(aThenB)), aThenB) &&
          same(mergeRow(copy(aThenB), copy(nodeA)), aThenB) &&
          same(mergeRow(copy(nodeB), copy(aThenB)), aThenB),
          '5. merging the answer again with itself or with either side ' +
          'changes nothing');
  // A LATER SIGN-OUT SURVIVES AN EARLIER FORGET.
  const nodeC = copy(aThenB);
  delete nodeC.sessions['s-bob'];
  nodeC.endedSids['s-bob'] = at + 3000;
  nodeC.remembered['urn:bob'] = { sub: 'urn:bob', username: 'bob',
                                  signedOutAt: at + 3000 };
  const nodeD = copy(aThenB);
  nodeD.forgotten['urn:bob'] = at + 2500;
  const cd = mergeRow(copy(nodeD), mergeRow(copy(nodeC), copy(aThenB)));
  t.check(!!cd.remembered['urn:bob'] && !cd.sessions['s-bob'],
          '5. bob signed out on one node after he was forgotten on another ' +
          'is remembered', JSON.stringify(cd.remembered));
  log.debug("Leaving partMerge().");
}

// ---------------------------------------------------------------------------
// 6. A FAILURE IN ONE SESSION LEAVES THE OTHERS AS THEY WERE.
// ---------------------------------------------------------------------------
function partIsolation(t) {
  log.debug("Entering partIsolation().");
  t.log.info('=== 6. a failure in one session leaves the others ===');
  const b = browser();
  const alice = signIn(b, 'mac-iso-alice');
  const bob = signIn(b, 'mac-iso-bob');
  const aliceBefore = JSON.stringify(authn.sessions.get(alice.id));
  const cookieBefore = String(b.jar[AccountSets.cookieName()]);
  authn.endSessionById(bob.id, 'multi_account_concurrency 6');
  t.check(JSON.stringify(authn.sessions.get(alice.id)) === aliceBefore &&
          !!setOf(b) && !!setOf(b).sessions[alice.id] &&
          String(b.jar[AccountSets.cookieName()]) === cookieBefore,
          '6. an administrator ending bob\'s session leaves alice\'s ' +
          'session, her place in the set and the set\'s cookie as they were');
  t.equal(actsAs(b), alice.id, '6. and the browser acts as alice');

  // A ROW THE CLEAN-UP JOB CANNOT PRUNE costs that row, never the others.
  const good = browser();
  const carol = signIn(good, 'mac-iso-carol');
  signIn(good, 'mac-iso-dave');
  authn.sessions.get(carol.id).expires = Date.now() - 1;
  const bad = AccountSets.fresh();
  bad.remembered = { broken: null };
  AccountSets.save(bad);
  let swept = null;
  let threw = '';
  try {
    swept = authn.sweepAccountSets();
  } catch (e) {
    log.debug("Caught in partIsolation(): " + ((e && e.message) || e));
    threw = String((e && e.message) || e);
  }
  t.check(!threw && !!swept && swept.ended >= 1 &&
          !setOf(good).sessions[carol.id] &&
          !!setOf(good).remembered[keyOf(carol, 'mac-iso-carol')],
          '6. a set the job cannot prune does not stop it pruning another: ' +
          'carol, expired, is remembered', threw || JSON.stringify(swept));
  AccountSets.remove(bad.id);

  // A SET GONE FROM UNDER A SESSION THAT ENDS.
  const gone = browser();
  const erin = signIn(gone, 'mac-iso-erin');
  const frank = signIn(gone, 'mac-iso-frank');
  AccountSets.remove(setOf(gone).id);
  let failed = '';
  try {
    authn.endSessionById(erin.id, 'multi_account_concurrency 6');
  } catch (e) {
    log.debug("Caught in partIsolation(): " + ((e && e.message) || e));
    failed = String((e && e.message) || e);
  }
  t.check(!failed && !authn.sessions.get(erin.id) &&
          !!authn.sessions.get(frank.id),
          '6. a session whose set is gone still ends, and the other session ' +
          'of that browser is left live', failed);
  log.debug("Leaving partIsolation().");
}

// ---------------------------------------------------------------------------
// 7. /admin/sessions AND GET /admin-api/sessions (#731).
// ---------------------------------------------------------------------------
function partConsole(t, countsBefore) {
  log.debug("Entering partConsole().");
  t.log.info('=== 7. the account set and the counters on /admin/sessions ===');
  let view = adminViews.sessionsView({ query: {} });
  if (!view.installed) {
    adminViews.setLogoutReader({ FAMILIES: logout.FAMILIES,
      inventoryFor: logout.inventoryFor, terminate: logout.terminate,
      liveSessions: logout.liveSessions,
      SESSION_EXPIRY_RULES: logout.SESSION_EXPIRY_RULES });
  }
  const b = browser();
  const alice = signIn(b, 'mac-con-alice');
  const bob = signIn(b, 'mac-con-bob');
  const other = browser();
  const carol = signIn(other, 'mac-con-carol');
  const setId = setOf(b).id;
  const handle = String(b.jar[AccountSets.cookieName()]).split('.')[1];
  view = adminViews.sessionsView({ query: { q: setId, per: '50' } });
  const ids = view.json.sessions.map(function (row) {
    return row.sessionId;
  }).sort();
  t.check(view.installed && ids.join(',') ===
            [alice.id, bob.id].sort().join(','),
          '7. ?q= with the set\'s id lists the sessions of that browser and ' +
          'no other', JSON.stringify(ids));
  t.check(view.json.sessions.every(function (row) {
    return row.accountSet === setId;
  }), '7. each of those rows names its set');
  const all = adminViews.sessionsView({ query: { q: 'mac-con-carol',
                                                 per: '50' } });
  const carolRow = all.json.sessions.filter(function (row) {
    return row.sessionId === carol.id;
  })[0];
  t.check(!!carolRow && carolRow.accountSet === setOf(other).id &&
          carolRow.accountSet !== setId,
          '7. a session of another browser names its own set');
  t.check(JSON.stringify(view.json).indexOf(handle) < 0,
          '7. no answer carries the set cookie\'s handle');
  const counts = (view.json.accountChoices || {}).counts || {};
  t.check(view.json.accountChoices.enabled === true &&
          Object.keys(counts).sort().join(',') ===
            'added,ambiguous,expired,forgotten,selectFailed,selected,' +
            'switched',
          '7. accountChoices answers the setting and the seven counters',
          JSON.stringify(view.json.accountChoices));
  t.check(counts.selected > countsBefore.selected &&
          counts.added > countsBefore.added &&
          counts.ambiguous > countsBefore.ambiguous &&
          counts.selectFailed > countsBefore.selectFailed,
          '7. and they moved with what this file did',
          JSON.stringify({ before: countsBefore, after: counts }));
  const t8 = i18n.translator(['en']);
  const html = SessionsPage.body(WebKit.context({}, true, t8), view.json);
  t.check(html.indexOf('data-tab="accounts"') >= 0 &&
          html.indexOf('Several accounts in one browser') >= 0 &&
          html.indexOf('/admin/sessions?q=' + encodeURIComponent(setId)) >=
            0 &&
          html.indexOf('<code>' + setId.slice(0, 8) + '</code>') >= 0 &&
          html.indexOf(handle) < 0,
          '7. the page draws the set as a short id linked to that browser\'s ' +
          'sessions, and the counters as a tab of their own', '');
  log.debug("Leaving partConsole().");
}

function partOffRow(t) {
  log.debug("Entering partOffRow().");
  t.log.info('=== 7. with the setting off, a row names no set ===');
  const b = browser();
  const solo = signIn(b, 'mac-off-solo');
  const row = logout.liveSessions().filter(function (one) {
    return one.sessionId === solo.id;
  })[0];
  const t8 = i18n.translator(['en']);
  t.check(!!row && row.accountSet === '' &&
          SessionsPage.accountSetLine(t8, row) === '',
          '7. off, a session is in no set, and its row draws none');
  log.debug("Leaving partOffRow().");
}

function run(t) {
  log.debug("Entering run().");
  realms.run(realms.DEFAULT_REALM, function () {
    partOffRow(t);
    withSettings({ 'authn.multipleAccounts': true }, function () {
      const before = stats.accountChoiceCounts();
      partSignIns(t);
      partSelections(t);
      partSignOuts(t);
      partRevoked(t);
      partMerge(t);
      partIsolation(t);
      // Something ambiguous and something refused, for the counters.
      const b = browser();
      signIn(b, 'mac-cnt-alice');
      signIn(b, 'mac-cnt-bob');
      const p = picker(b, '/oauth2/authorize?client_id=cnt');
      const refused = b.req('/authn-api/pending/' + p.id + '/accounts/select');
      authn.accountsAct(refused, refused.res, p.record,
                        { action: 'select', account: 'urn:uuid:nobody' });
      partConsole(t, before);
    });
    made.forEach(function (sid) {
      if (authn.sessionById(sid)) {
        authn.endSessionById(sid, 'the end of multi_account_concurrency.js');
      }
    });
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'multi_account_concurrency',
  describe: 'several signed-in accounts in one browser (#561 TR-2, #731): ' +
            'two tabs signing in, selecting and signing out at once, a ' +
            'session revoked under a flow that chose it, two nodes\' ' +
            'copies of one set merged, a failure in one session leaving ' +
            'the others, and the set and the counters on /admin/sessions',
  run: run
};
