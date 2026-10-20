// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: multi_account_sessions.js
//
// ===========================================================================
// SEVERAL SIGNED-IN ACCOUNTS IN ONE BROWSER (#561): THE ACCOUNT SET AND
// WHICH SESSION A REQUEST ACTS AS.
//
// `authn/CLAUDE.md`, *Several signed-in accounts in one browser*, is the
// design; this file is the contract of its first two delivery steps — the
// plan's *Tests* row for this file:
//
//   1. with `authn.multipleAccounts` OFF, a different person signing in
//      ends the browser's session exactly as before, and nothing of the set
//      exists (no cookie, no row);
//   2. ON, two people in one cookie jar both stay live, and a request that
//      names neither is answered nobody, with `accountChoiceNeeded()`
//      saying `ambiguous`;
//   3. a hint chooses silently, and a hint naming nobody here NEVER falls
//      back to another account;
//   4. the same person signing in again re-authenticates the session the
//      set holds for them, whichever session the cookie names;
//   5. a selection ticket is spent once, only for its own set and path, and
//      is taken off the request;
//   6. the picker: ambiguity routes there, select resumes the flow with a
//      ticket and makes the account the default, a dead account is refused;
//   7. a sign-out, an expiry and the clean-up job move an account to
//      remembered; forget takes only a remembered one;
//   8. the full-set rule: the oldest remembered is dropped, and a set of
//      live accounts refuses (STS-AUTHN-0340);
//   9. a browser holding a session and no set gets one around it (D12);
//  10. the account list and the audit actor name no sid but the session.
//
// WHY IN PROCESS. Which row a session is, what the set holds and whether a
// ticket was spent are facts about the stores; an HTTP caller sees cookies
// that work or do not. The protocols' own paths through this — the OIDC
// authorization endpoint, SAML, the sign-out — are the `local: true` job
// the plan names for later steps.
// ===========================================================================

delete process.env.CONFIG_FILE;

const realms = require('../common/realms');
const config = require('../common/config');
const authn = require('../authn/authn');
const AccountSets = require('../authn/account_sets');

// This file's own logger, for the Entering/Leaving lines the code style asks
// for. Its level is LOG_LEVEL, which is also what the harness reads.
const log = require('bunyan').createLogger({ name: 'multi_account_sessions',
  level: process.env.LOG_LEVEL || 'info' });

// ---------------------------------------------------------------------------
// A browser: a cookie jar, and the requests and responses it makes. A
// response's Set-Cookie behaves as express's does — `set()` REPLACES every
// Set-Cookie on it, `append()` adds one — because the order the session
// cookie and the set's cookie are written in is part of what is asserted.
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
    // A request from this browser, for `url`, with its own response.
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
    // What a response told the browser to keep.
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

// A sign-in by this browser, as the sign-in screen's acts make one.
function signIn(b, username, extra) {
  log.debug("Entering signIn(). " + username);
  const req = b.req('/authn-api/pending/x/password');
  const detail = Object.assign({ request: req }, extra || {});
  const session = authn.startSession(req.res, username, ['pwd'], '1',
                                     'OAuth 2.0 / OIDC', detail);
  b.take(req.res);
  log.debug("Leaving signIn().");
  return { session: session, res: req.res, req: req, detail: detail };
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

// The set a browser's cookie names, read from the store.
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

function ticketIn(location) {
  log.debug("Entering ticketIn().");
  const m = /[?&]sts_account=([^&]+)/.exec(String(location || ''));
  log.debug("Leaving ticketIn().");
  return m ? decodeURIComponent(m[1]) : '';
}

function partOff(t) {
  log.debug("Entering partOff().");
  t.log.info('=== 1. off: a different person still ends the session ===');
  const b = browser();
  const alice = signIn(b, 'mas-off-alice').session;
  t.check(!!alice, 'alice signed in');
  t.check(!b.jar[AccountSets.cookieName()],
          'no sts_accounts cookie is written with the setting off');
  const bob = signIn(b, 'mas-off-bob').session;
  t.check(!!bob && bob.id !== alice.id, 'bob signed in with a session of ' +
          'his own');
  t.check(!authn.sessions.get(alice.id), 'and alice\'s session was ENDED — ' +
          'today\'s dropSession(\'a new sign-in in the same browser\')');
  t.check(!bob.accountSetId && !b.jar[AccountSets.cookieName()],
          'nothing of an account set exists');
  const req = b.req('/oauth2/authorize');
  authn.hintAccount(req, { loginHint: 'mas-off-alice' });
  t.equal(authn.sessionOf(req) && authn.sessionOf(req).id, bob.id,
          'and a hint changes nothing: the cookie alone decides');
  t.equal(authn.accountChoiceNeeded(req), null,
          'accountChoiceNeeded() is null with the setting off');
  log.debug("Leaving partOff().");
}

function partOn(t) {
  log.debug("Entering partOn().");
  // -------------------------------------------------------------------------
  t.log.info('=== 2. on: two people in one cookie jar both stay live ===');
  const b = browser();
  const alice = signIn(b, 'mas-alice').session;
  t.check(!!b.jar[AccountSets.cookieName()], 'the first sign-in wrote ' +
          'the sts_accounts cookie');
  const firstSet = b.jar[AccountSets.cookieName()];
  const bob = signIn(b, 'mas-bob').session;
  t.check(!!authn.sessions.get(alice.id), 'alice\'s session is still live ' +
          'after bob signed in');
  t.check(!!bob && bob.id !== alice.id, 'bob has a session of his own');
  const set = setOf(b);
  t.check(!!(set && set.sessions[alice.id] && set.sessions[bob.id]),
          'the browser\'s set holds both sessions');
  t.check(b.jar[AccountSets.cookieName()] !== firstSet &&
          b.jar[AccountSets.cookieName()].split('.')[0] ===
            firstSet.split('.')[0],
          'the set\'s handle rotated on the sign-in and its id did not');
  t.check(b.jar[authn.SESSION_COOKIE].split('.')[0] === bob.id,
          'sts_session names the most recent sign-in, the browser\'s default');
  const ambiguous = b.req('/oauth2/authorize');
  t.equal(authn.sessionOf(ambiguous), null, 'a request naming neither is ' +
          'answered NOBODY — not the default cookie\'s session');
  const need = authn.accountChoiceNeeded(ambiguous);
  t.check(!!need && need.reason === 'ambiguous' && need.accounts === 2,
          'and accountChoiceNeeded() says ambiguous, two accounts',
          JSON.stringify(need));

  // -------------------------------------------------------------------------
  t.log.info('=== 3. a hint chooses, and never falls back ===');
  const byName = b.req('/oauth2/authorize');
  authn.hintAccount(byName, { loginHint: 'mas-alice' });
  t.equal((authn.sessionOf(byName) || {}).id, alice.id,
          'login_hint "mas-alice" chooses alice\'s session');
  const bySid = b.req('/oauth2/authorize');
  authn.hintAccount(bySid, { sid: bob.id });
  t.equal((authn.sessionOf(bySid) || {}).id, bob.id,
          'an id_token_hint sid chooses bob\'s session');
  const nobody = b.req('/oauth2/authorize');
  authn.hintAccount(nobody, { loginHint: 'mas-carol' });
  t.equal(authn.sessionOf(nobody), null, 'a hint naming nobody here ' +
          'answers nobody, never another account');
  t.equal((authn.accountChoiceNeeded(nobody) || {}).reason, 'hint-unmatched',
          'and accountChoiceNeeded() says hint-unmatched');

  // -------------------------------------------------------------------------
  t.log.info('=== 4. the same person again re-authenticates their session ===');
  const eventsBefore = (authn.sessions.get(alice.id).events || []).length;
  const again = signIn(b, 'mas-alice').session;
  t.equal(again && again.id, alice.id, 'alice signing in again (the cookie ' +
          'naming bob) re-authenticated alice\'s session, the same sid');
  t.equal((again.events || []).length, eventsBefore + 1,
          'one more authentication event on it');
  t.check(!!authn.sessions.get(bob.id), 'bob\'s session is untouched');
  t.equal(Object.keys(setOf(b).sessions).length, 2,
          'the set still holds two sessions, not three');

  // -------------------------------------------------------------------------
  t.log.info('=== 5. a selection ticket: once, its own set and path ===');
  const ticket = AccountSets.mintTicket(set.id, bob.id, '/oauth2/authorize',
                                        'pending-1');
  const spent = b.req('/oauth2/authorize?client_id=c&sts_account=' + ticket);
  authn.spendAccountTicket(spent);
  t.check(!/sts_account/.test(spent.url) && !/sts_account/
            .test(spent.originalUrl) && spent.query.sts_account === undefined,
          'the ticket is taken off the request before any route sees it',
          spent.url);
  t.equal(spent.query.client_id, 'c', 'and the rest of the query is kept');
  t.equal((authn.sessionOf(spent) || {}).id, bob.id,
          'the request acts as the session the ticket names');
  const replay = b.req('/oauth2/authorize?sts_account=' + ticket);
  authn.spendAccountTicket(replay);
  t.equal(authn.sessionOf(replay), null, 'a spent ticket chooses nothing');
  const other = browser();
  signIn(other, 'mas-dave');
  const foreign = AccountSets.mintTicket(set.id, bob.id, '/oauth2/authorize',
                                         'pending-2');
  const crossed = other.req('/oauth2/authorize?sts_account=' + foreign);
  authn.spendAccountTicket(crossed);
  t.check((authn.sessionOf(crossed) || {}).id !== bob.id,
          'a ticket for another browser\'s set never chooses its session');
  const wrongPath = AccountSets.mintTicket(set.id, alice.id, '/saml2/sso',
                                           'pending-3');
  const elsewhere = b.req('/oauth2/authorize?sts_account=' + wrongPath);
  authn.spendAccountTicket(elsewhere);
  t.equal(authn.sessionOf(elsewhere), null,
          'a ticket minted for another address chooses nothing');

  // -------------------------------------------------------------------------
  t.log.info('=== 6. the picker ===');
  const start = b.req('/oauth2/authorize?client_id=c');
  const path = authn.beginAuthentication({
    returnTo: '/oauth2/authorize?client_id=c', details: [],
    protocol: 'OAuth 2.0 / OIDC', application: '', request: start });
  t.check(/^\/authn\/accounts\?authn=/.test(path), 'an ambiguous request ' +
          'is sent to the account picker', path);
  const id = decodeURIComponent(path.split('authn=')[1]);
  const record = authn.pendingForAccounts(id);
  t.check(!!record && record.accountChoice === true,
          'its pending record waits on an account choice');
  const pick = b.req('/authn-api/pending/' + id + '/accounts');
  const view = authn.accountsView(pick, record);
  const keys = view.accounts.map(function (one) {
    return one.state + ':' + one.username;
  }).sort();
  t.equal(keys.join(','), 'signed-in:mas-alice,signed-in:mas-bob',
          'the picker lists both signed-in accounts');
  t.check(JSON.stringify(view).indexOf(alice.id) < 0 &&
          JSON.stringify(view).indexOf(bob.id) < 0,
          'the view names no sid');
  t.check(view.another && view.another.open === true,
          'Use another account is open');
  const aliceKey = view.accounts.filter(function (one) {
    return one.username === 'mas-alice';
  })[0].key;
  const bobPick = view.accounts.filter(function (one) {
    return one.username === 'mas-bob';
  })[0].key;
  t.check(b.jar[authn.SESSION_COOKIE].split('.')[0] === alice.id,
          'alice is the browser\'s default before the choice (her ' +
          're-authentication made her so)');
  const act = b.req('/authn-api/pending/' + id + '/accounts/select');
  authn.accountsAct(act, act.res, record, { action: 'select',
                                            account: bobPick });
  const answer = answerOf(act.res);
  t.check(!!answer && answer.next === 'redirect' &&
          /^\/oauth2\/authorize\?client_id=c&sts_account=/
            .test(answer.location),
          'select answers the flow\'s own address with a ticket on it',
          JSON.stringify(answer));
  b.take(act.res);
  t.check(b.jar[authn.SESSION_COOKIE].split('.')[0] === bob.id,
          'and bob became the browser\'s default (sts_session): a switch');
  t.equal(authn.pendingForAccounts(id), null, 'the pending record is spent');
  const resumed = b.req(answer.location);
  authn.spendAccountTicket(resumed);
  t.equal((authn.sessionOf(resumed) || {}).id, bob.id,
          'the resumed request acts as bob');
  const ambiguousAgain = b.req('/oauth2/authorize');
  t.equal(authn.sessionOf(ambiguousAgain), null,
          'and the next request that names nobody is ambiguous again: the ' +
          'choice was the flow\'s, never the browser\'s');
  // An expired account between the page and the click, and one that was
  // never here.
  const path2 = authn.beginAuthentication({
    returnTo: '/oauth2/authorize?client_id=c', details: [],
    protocol: 'OAuth 2.0 / OIDC', application: '',
    request: b.req('/oauth2/authorize') });
  const id2 = decodeURIComponent(path2.split('authn=')[1]);
  const record2 = authn.pendingForAccounts(id2);
  const bobKey = AccountSets.keyOf({ sub: (bob.user || {}).sub,
                                     username: 'mas-bob' });
  authn.sessions.get(bob.id).expires = Date.now() - 1;
  const dead = b.req('/authn-api/pending/' + id2 + '/accounts/select');
  authn.accountsAct(dead, dead.res, record2, { action: 'select',
                                               account: bobKey });
  const deadAnswer = answerOf(dead.res) || {};
  t.check(deadAnswer.next === 'redirect' &&
          /^\/authn\/login\?authn=/.test(String(deadAnswer.location)) &&
          !ticketIn(deadAnswer.location),
          'choosing bob, whose session ran out meanwhile, does not continue ' +
          'as him: it goes to the sign-in, with no ticket',
          JSON.stringify(deadAnswer));
  t.equal(record2.hint, 'mas-bob', 'his name filled in there');
  const bobAfter = authn.sessions.get(bob.id);
  t.check((!bobAfter || !!authn.sessionEnded(bobAfter)) &&
          !!setOf(b).remembered[bobKey] && !setOf(b).sessions[bob.id],
          'and his account is remembered as signed out (the session itself ' +
          'is ended by its own clocks, wherever it is next presented)');
  const path3 = authn.beginAuthentication({
    returnTo: '/oauth2/authorize?client_id=c', details: [],
    protocol: 'OAuth 2.0 / OIDC', application: '',
    request: b.req('/oauth2/authorize') });
  t.check(/^\/authn\/login\?/.test(path3), 'with one live account left, ' +
          'a sign-in that has to happen goes to the screen, not the picker',
          path3);
  const erin = signIn(b, 'mas-erin').session;
  const path4 = authn.beginAuthentication({
    returnTo: '/oauth2/authorize?client_id=c', details: [],
    protocol: 'OAuth 2.0 / OIDC', application: '',
    request: b.req('/oauth2/authorize') });
  const id4 = decodeURIComponent(path4.split('authn=')[1]);
  const record4 = authn.pendingForAccounts(id4);
  const stranger = b.req('/authn-api/pending/' + id4 + '/accounts/select');
  authn.accountsAct(stranger, stranger.res, record4,
                    { action: 'select', account: 'urn:uuid:nobody' });
  t.equal(stranger.res.statusCode, 409, 'choosing an account the browser ' +
          'does not hold is refused (409, STS-AUTHN-0337)');
  t.check(!!authn.pendingForAccounts(id4), 'and the picker can be drawn ' +
          'again');

  // -------------------------------------------------------------------------
  t.log.info('=== 7. remembered: sign-out, expiry, the job, forget ===');
  const erinKey = AccountSets.keyOf({ sub: (erin.user || {}).sub,
                                      username: 'mas-erin' });
  authn.endSessionById(erin.id, 'a test');
  let now = setOf(b);
  t.check(!now.sessions[erin.id] && !!now.remembered[erinKey],
          'erin signed out: she is remembered as signed out',
          JSON.stringify(Object.keys(now.remembered)));
  const only = b.req('/oauth2/authorize');
  t.equal((authn.sessionOf(only) || {}).id, alice.id,
          'with one live account left, a request acts as it: single ' +
          'sign-on');
  const forgetLive = b.req('/authn-api/pending/' + id4 + '/accounts/forget');
  authn.accountsAct(forgetLive, forgetLive.res, record4,
                    { action: 'forget', account: aliceKey });
  t.equal(forgetLive.res.statusCode, 409, 'a signed-in account cannot be ' +
          'forgotten (STS-AUTHN-0339)');
  const forget = b.req('/authn-api/pending/' + id4 + '/accounts/forget');
  authn.accountsAct(forget, forget.res, record4,
                    { action: 'forget', account: erinKey });
  t.equal((answerOf(forget.res) || {}).next, 'stay', 'a remembered account ' +
          'is forgotten');
  now = setOf(b);
  t.check(!now.remembered[erinKey] && !!now.sessions[alice.id],
          'erin is gone from the set and alice\'s session is untouched');
  // An expiry, found by the job.
  const carol = signIn(b, 'mas-carol').session;
  authn.sessions.get(carol.id).expires = Date.now() - 1;
  const swept = authn.sweepAccountSets();
  now = setOf(b);
  t.check(swept.ended >= 1 && !now.sessions[carol.id] &&
          !!now.remembered[AccountSets.keyOf({ sub: (carol.user || {}).sub,
                                               username: 'mas-carol' })],
          'the clean-up job moved carol, whose session expired, to ' +
          'remembered', JSON.stringify(swept));
  // An old remembered account is dropped by the job.
  const old = setOf(b);
  Object.keys(old.remembered).forEach(function (key) {
    old.remembered[key].signedOutAt = Date.now() -
      40 * 24 * 60 * 60 * 1000;
  });
  AccountSets.save(old);
  const aged = authn.sweepAccountSets();
  t.check(aged.expired >= 1 && !Object.keys(setOf(b).remembered).length,
          'a remembered account past authn.rememberedAccountDays is dropped',
          JSON.stringify(aged));

  // -------------------------------------------------------------------------
  t.log.info('=== 8. the full-set rule ===');
  withSettings({ 'authn.maxBrowserAccounts': 2 }, function () {
    const full = browser();
    const a = signIn(full, 'mas-full-a').session;
    signIn(full, 'mas-full-b');
    const refused = signIn(full, 'mas-full-c');
    t.equal(refused.session, null, 'a third account in a set of two live ' +
            'ones is refused');
    t.equal(refused.detail.refusedWith, 'STS-AUTHN-0340',
            'under STS-AUTHN-0340');
    authn.endSessionById(a.id, 'a test');
    const room = signIn(full, 'mas-full-c').session;
    t.check(!!room, 'with one signed out, the remembered account is ' +
            'dropped to make room');
    const s = setOf(full);
    t.equal(Object.keys(s.sessions).length + Object.keys(s.remembered).length,
            2, 'and the set holds no more than authn.maxBrowserAccounts');
  });

  // -------------------------------------------------------------------------
  t.log.info('=== 10. the account list and the audit actor ===');
  const list = authn.browserAccounts(b.req('/authn-api/accounts'));
  t.check(list.enabled === true && list.accounts.length >= 1,
          'GET /authn-api/accounts lists the browser\'s accounts');
  t.check(JSON.stringify(list).indexOf(alice.id) < 0,
          'and names no sid');
  const audited = b.req('/oauth2/authorize');
  authn.hintAccount(audited, { loginHint: 'mas-alice' });
  t.equal(authn.auditActorSessionOf(audited), alice.id,
          'the audit actor\'s session is the one the request resolved to');
  log.debug("Leaving partOn().");
}

function partAdopt(t) {
  log.debug("Entering partAdopt().");
  t.log.info('=== 9. a session from before the setting gets a set (D12) ===');
  const b = browser();
  const alice = signIn(b, 'mas-early-alice').session;
  t.check(!b.jar[AccountSets.cookieName()], 'signed in with the setting off');
  withSettings({ 'authn.multipleAccounts': true }, function () {
    const req = b.req('/oauth2/authorize');
    t.equal((authn.sessionOf(req) || {}).id, alice.id,
            'turned on, the browser is still signed in — nothing ended');
    b.take(req.res);
    const set = setOf(b);
    t.check(!!(set && set.sessions[alice.id]), 'and its session became the ' +
            'first account of a new set, its cookie on that response');
    const bob = signIn(b, 'mas-early-bob').session;
    t.check(!!authn.sessions.get(alice.id) && !!bob,
            'so a second person now adds a session rather than ending hers');
  });
  log.debug("Leaving partAdopt().");
}

function run(t) {
  log.debug("Entering run().");
  realms.run(realms.DEFAULT_REALM, function () {
    partOff(t);
    partAdopt(t);
    withSettings({ 'authn.multipleAccounts': true }, function () {
      partOn(t);
    });
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'multi_account_sessions',
  describe: 'several signed-in accounts in one browser (#561): the account ' +
            'set, sessionOf() resolution by ticket, hint and the only live ' +
            'session, ambiguity, the picker, remembered accounts, forget, ' +
            'the full-set rule, D12 adoption, and the setting off unchanged',
  run: run
};
