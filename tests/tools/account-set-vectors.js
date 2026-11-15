// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: account-set-vectors.js
//
// ---------------------------------------------------------------------------
// A BROWSER'S ACCOUNT SET (#561; #444, phase 5, the `accounts` slice): what
// `authn/authn.ts` and `authn/account_sets.ts` do with several signed-in
// accounts in one browser — a sign-in joining the set rather than replacing
// the session, the same person re-authenticating their own session, the
// full set refused, which session a request acts as (a ticket, a hint, the
// only live one, nobody), the tickets, the picker's view and acts, signing
// one out and then the default, D12's set made around a session, the
// clean-up job — door by door, for `sts-authn` to reproduce. Called by
// `tests/tools/crypto-vectors.js`'s `account-sets-node.json` row, in a
// process of its own.
//
// THE METHOD IS `session-vectors.js`'s, over its harness: the real `Authn`
// with every port recorded, `authn.multipleAccounts` ON. `account_sets.ts`
// reaches `helpers.randomId()` and `helpers.cookieDomainAttribute()` through
// the module rather than `Authn`'s deps, so both are recorded on the module
// here. Each step also records the two account stores (`sets`, `tickets`)
// as the session store is recorded, row for row.
// ---------------------------------------------------------------------------

const path = require('path');
const sessionVectors = require('./session-vectors.js');

/**
 * Builds the vectors.
 *
 * @param {string} ROOT - the repository root
 * @returns {Promise<any>} the vector document
 */
async function build(ROOT) {
  const h = sessionVectors.harness(ROOT, {
    overrides: { 'authn.multipleAccounts': true,
                 'authn.maxBrowserAccounts': 3,
                 'authn.rememberedAccountDays': 30 },
    people: { gil: '5e4d3c2b-1a09-4f8e-9d7c-6b5a4e3d2c55' }
  });
  const { rec, clock, authn, step, steps, overrides, smState } = h;
  const helpers = require(path.join(ROOT, 'common', 'helpers'));
  const realRandom = helpers.randomId;
  const realDomain = helpers.cookieDomainAttribute;
  const random = h.randomId;
  helpers.randomId = random;
  helpers.cookieDomainAttribute = rec.fn('helpers', 'cookieDomainAttribute',
    function () {
      return '';
    });
  const AccountSets = require(path.join(ROOT, 'authn', 'account_sets'));
  const realms = require(path.join(ROOT, 'common', 'realms'));
  const dump = function (handle) {
    const out = {};
    realms.handleFor(handle).dump('default').forEach(function (one) {
      out[one.key] = rec.copy(one.value);
    });
    return out;
  };
  // Every step also records the two account stores.
  const run = function (name, door, input, fn) {
    const out = step(name, door, input, fn);
    const row = steps[steps.length - 1];
    row.sets = dump('authn.accountSets');
    row.tickets = dump('authn.accountTickets');
    return out;
  };

  // ---- the browser's cookie jar -------------------------------------------
  const jar = function () {
    const held = {};
    return {
      held: held,
      take: function (res) {
        (res.cookies || []).forEach(function (line) {
          const first = String(line).split(';')[0];
          const at = first.indexOf('=');
          const name = first.slice(0, at);
          const value = first.slice(at + 1);
          if (/Max-Age=0/.test(line) || !value) {
            delete held[name];
          } else {
            held[name] = value;
          }
        });
      },
      header: function () {
        return Object.keys(held).map(function (k) {
          return k + '=' + held[k];
        }).join('; ');
      }
    };
  };
  const request = function (cookie, url, open) {
    const r = h.request(cookie);
    r.url = url || '/';
    r.originalUrl = r.url;
    r.query = {};
    rec.opaque.push({ value: r, name: '[request]' });
    return r;
  };
  // A request whose own response can take a cookie (D12).
  const opened = function (r, res) {
    r.res = res;
    return r;
  };

  const start = function (name, b, username, amr, acr, via, detail) {
    const cookie = b.header();
    const r = request(cookie);
    const d = Object.assign({ request: r }, detail || {});
    const out = run(name, 'startSession',
      { username: username, amr: amr, acr: acr, via: via,
        detail: Object.assign({}, d, { request: undefined }),
        cookie: cookie }, function (res) {
        res.req = r;
        const s = authn.startSession(res, username, amr, acr, via, d);
        return { session: s,
                 detail: Object.assign({}, d, { request: undefined }) };
      });
    b.take(out.res);
    return out;
  };
  const pwd = function (app) {
    return { application: app || 'app-one',
             credential: { kind: 'password' } };
  };
  const at = function (name, door, b, more, fn) {
    const cookie = b.header();
    const r = request(cookie, more && more.url, more && more.open);
    const input = Object.assign({ cookie: cookie, url: r.url,
                                  open: !!(more && more.open) },
                                (more && more.input) || {});
    const out = run(name, door, input, function (res) {
      if (more && more.open) {
        opened(r, res);
      }
      return fn(r, res);
    });
    if (!(more && more.keepJar)) {
      b.take(out.res);
    }
    return out;
  };
  const sessionOf = function (name, b, more) {
    return at(name, 'sessionOf', b, more, function (r) {
      if (more && more.hint) {
        authn.hintAccount(r, more.hint);
      }
      return { session: authn.sessionOf(r) };
    });
  };
  const keyOf = function (who) {
    return 'urn:uuid:' + h.people[who];
  };

  // ---- a sign-in, then another person: the set holds both -----------------
  const browser = jar();
  const dora = start('dora signs in and a set is made', browser, 'dora',
                     ['pwd'], '1', 'OAuth 2.0 / OIDC', pwd());
  const doraId = dora.answer.session.id;
  sessionOf('one account is the only live one', browser);
  clock.now += 1000;
  const emil = start('emil signs in beside her', browser, 'emil', ['pwd'],
                     '1', 'SAML 2.0', pwd('sp-one'));
  const emilId = emil.answer.session.id;
  sessionOf('two accounts and nothing chooses', browser);
  at('why nobody', 'accountChoiceNeeded', browser, {}, function (r) {
    return { need: authn.accountChoiceNeeded(r) };
  });
  sessionOf('a login hint chooses dora', browser,
            { hint: { loginHint: 'DORA' }, input: { hint:
                                                    { loginHint: 'DORA' } } });
  sessionOf('a subject hint chooses emil', browser,
            { hint: { sub: keyOf('emil') },
              input: { hint: { sub: keyOf('emil') } } });
  sessionOf('a hint naming nobody here', browser,
            { hint: { loginHint: 'fay' },
              input: { hint: { loginHint: 'fay' } } });
  at('a hint naming nobody, why', 'accountChoiceNeeded', browser,
     { input: { hint: { username: 'fay' } } }, function (r) {
       authn.hintAccount(r, { username: 'fay' });
       return { need: authn.accountChoiceNeeded(r) };
     });
  sessionOf('a soft hint naming nobody is no hint', browser,
            { hint: { loginHint: 'fay', soft: true },
              input: { hint: { loginHint: 'fay', soft: true } } });
  at('an account key as the hint', 'hintAccountKey', browser,
     { input: { key: 'name:emil' } }, function (r) {
       authn.hintAccountKey(r, 'name:emil');
       return { session: authn.sessionOf(r) };
     });

  // ---- the same person again re-authenticates their own session ----------
  clock.now += 1000;
  start('dora again re-authenticates hers', browser, 'dora', ['pwd', 'otp'],
        'mfa', 'OAuth 2.0 / OIDC',
        { application: 'app-two', credential: { kind: 'totp' } });

  // ---- tickets --------------------------------------------------------------
  const minted = at('a ticket for emil', 'accountTicketFor', browser,
    { input: { target: '/oauth2/authorize?client_id=c1',
               hint: { loginHint: 'emil' } } }, function (r) {
      return { target: authn.accountTicketFor(r,
        '/oauth2/authorize?client_id=c1', { loginHint: 'emil' }) };
    }).answer.target;
  const ticketUrl = minted;
  const spend = function (name, url, b) {
    return at(name, 'spendThenSessionOf', b || browser, { url: url },
      function (r) {
        authn.spendAccountTicket(r);
        return { url: r.url, session: authn.sessionOf(r) };
      });
  };
  spend('the ticket chooses emil', ticketUrl);
  spend('a ticket spent twice chooses nothing', ticketUrl);
  const other = at('a ticket for another address', 'accountTicketFor',
    browser, { input: { target: '/saml2/sso', hint: { sub: keyOf('dora') } } },
    function (r) {
      return { target: authn.accountTicketFor(r, '/saml2/sso',
                                              { sub: keyOf('dora') }) };
    }).answer.target;
  spend('a ticket on the wrong address chooses nobody',
        other.replace('/saml2/sso', '/wsfed'));
  run('a finished sign-in returns with a ticket', 'ticketedReturn',
      { locals: { stsAccountSession: doraId,
                  stsAccountSet: dora.res.locals.stsAccountSet },
        recordId: 'rec-1', target: '/wsfed?wa=wsignin1.0' }, function () {
        const res = { locals: {
          stsAccountSession: doraId,
          stsAccountSet: dora.res.locals.stsAccountSet } };
        return { target: authn.ticketedReturn(res, { id: 'rec-1' },
                                              '/wsfed?wa=wsignin1.0') };
      });

  // ---- what the browser holds -----------------------------------------------
  at('the accounts this browser holds', 'browserAccounts', browser, {},
     function (r) {
       return { listed: authn.browserAccounts(r) };
     });
  at('the signed-in accounts for a sign-out', 'signedInAccounts', browser,
     {}, function (r) {
       return { accounts: authn.signedInAccounts(r),
                sessions: authn.accountSessionsOf(r).map(function (s) {
                  return s.id;
                }) };
     });
  at('the audit actor, ambiguous', 'auditActor', browser, {}, function (r) {
    return { actor: authn.auditActorOf(r),
             sid: authn.auditActorSessionOf(r) };
  });
  at('the audit actor, hinted', 'auditActor', browser,
     { input: { hint: { loginHint: 'emil' } } }, function (r) {
       authn.hintAccount(r, { loginHint: 'emil' });
       return { actor: authn.auditActorOf(r),
                sid: authn.auditActorSessionOf(r) };
     });
  at('a binding request picks its account', 'bindingSessionOf', browser,
     { input: { sid: emilId } }, function (r) {
       const found = authn.bindingSessionOf(r, function (s) {
         return s.id === emilId;
       });
       return { found: found, names: authn.sessionCookieNames(r, emilId) };
     });
  at('a binding request that picks none', 'bindingSessionOf', browser,
     { input: { sid: 'none' } }, function (r) {
       return { found: authn.bindingSessionOf(r, function () {
         return false;
       }), names: authn.sessionCookieNames(r, 'none') };
     });
  at('a request names no account', 'noteAccountAmbiguous', browser,
     { input: { via: 'OAuth 2.0 / OIDC',
                answer: 'account_selection_required was answered' } },
     function (r) {
       authn.noteAccountAmbiguous(r, 'OAuth 2.0 / OIDC',
                                  'account_selection_required was answered');
       return { noted: true };
     });

  // ---- beginAuthentication()'s choice, and the picker's record ------------
  const begin = function (name, choice, hinted, more) {
    return at(name, 'beginAccountChoice', browser,
      { input: Object.assign({ accountChoice: choice, hinted: hinted },
                             (more && more.input) || {}) },
      function (r) {
        if (more && more.hint) {
          authn.hintAccount(r, more.hint);
        }
        return { choice: beginChoiceOf(authn, r, choice, hinted) };
      });
  };
  begin('ambiguous: the picker', '', false);
  begin('select_account: the picker', 'always', false);
  begin('prompt=login: no picker', 'never', false);
  begin('a hint naming nobody: its name filled in', '', false,
        { hint: { loginHint: 'fay' },
          input: { hint: { loginHint: 'fay' } } });
  begin('one chosen by hint: its name filled in', '', false,
        { hint: { loginHint: 'emil' },
          input: { hint: { loginHint: 'emil' } } });
  const opts = { returnTo: '/oauth2/authorize?client_id=c1',
                 protocol: 'OAuth 2.0 / OIDC', application: 'app-one',
                 details: [{ label: 'Client', value: 'c1' }],
                 uiLocales: 'en' };
  at('the picker gets a record of its own', 'routeToAccounts', browser,
     { input: { existing: null, opts: opts, target: '/federation/x',
                why: 'ambiguous' } }, function (r) {
       return { routed: routeOf(authn, null, opts, '/federation/x',
                                'ambiguous', r) };
     });
  const existing = { id: 'pend-1', returnTo: '/oauth2/authorize?x=1',
                     protocol: 'SAML 2.0', application: 'sp-one',
                     expires: clock.now + 600000 };
  at('the sign-in\'s record is the picker\'s', 'routeToAccounts', browser,
     { input: { existing: existing, opts: opts,
                target: '/authn/login?authn=pend-1',
                why: 'select_account' } }, function (r) {
       return { routed: routeOf(authn, Object.assign({}, existing), opts,
                                '/authn/login?authn=pend-1',
                                'select_account', r) };
     });

  // ---- the full set refuses a fourth account --------------------------------
  clock.now += 1000;
  const fay = start('fay is the third', browser, 'fay', ['pwd'], '1',
                    'OAuth 2.0 / OIDC', pwd());
  const fayId = fay.answer.session.id;
  start('gil would be the fourth: refused', browser, 'gil', ['pwd'], '1',
        'WS-Federation', pwd('rp-one'));

  // ---- the picker -----------------------------------------------------------
  const record = { id: 'pend-2', returnTo: '/oauth2/authorize?client_id=c2',
                   protocol: 'OAuth 2.0 / OIDC', application: 'app-one',
                   accountChoice: true, accountChoiceReason: 'ambiguous',
                   afterAccounts: '/authn/login?authn=pend-2',
                   details: [{ label: 'Client', value: 'c2', note: 'n' },
                             { label: 'Scope', value: null }],
                   expires: clock.now + 600000 };
  const act = function (name, b, rec0, body, more) {
    return at(name, 'accountsAct', b,
      Object.assign({ input: { record: rec0, body: body } }, more || {}),
      function (r, res) {
        return { outcome: actOf(authn, r, res, Object.assign({}, rec0),
                                body) };
      });
  };
  at('the picker\'s view', 'accountsView', browser,
     { input: { record: record } }, function (r) {
       return { view: authn.accountsView(r, record) };
     });
  act('another account, with every place taken', browser, record,
      { action: 'another', account: '' });
  act('forget a live account', browser, record,
      { action: 'forget', account: keyOf('emil') });
  act('forget one never remembered', browser, record,
      { action: 'forget', account: 'name:nobody' });
  act('select one not here', browser, record,
      { action: 'select', account: 'name:nobody' });
  const before = browser.header();
  act('select dora: she becomes the default', browser, record,
      { action: 'select', account: keyOf('dora') });
  const stale = jar();
  before.split('; ').forEach(function (kv) {
    const i = kv.indexOf('=');
    stale.held[kv.slice(0, i)] = kv.slice(i + 1);
  });
  act('a stale set cookie, another tab chose', stale, record,
      { action: 'select', account: keyOf('emil') }, { keepJar: true });
  act('two factors demanded of a one-factor session', browser,
      Object.assign({}, record, { forceMfa: true }),
      { action: 'select', account: keyOf('emil') });

  // ---- signing one out, then the default ------------------------------------
  at('emil signs out by sid; dora stays the default', 'endSession', browser,
     { input: { sid: emilId } }, function (r, res) {
       return { session: authn.endSession(r, res, emilId) };
     });
  act('select emil, signed out: sign in as him again', browser, record,
      { action: 'select', account: keyOf('emil') });
  act('forget emil', browser, record,
      { action: 'forget', account: keyOf('emil') });
  act('another account, now with room', browser,
      Object.assign({}, record, { accountsOnly: true }),
      { action: 'another', account: '' });
  smState.enabled = true;
  at('dora signs out: fay becomes the default', 'endSession', browser,
     { input: { sid: '' } }, function (r, res) {
       return { session: authn.endSession(r, res) };
     });
  smState.enabled = false;
  at('who is left', 'browserAccounts', browser, {}, function (r) {
    return { listed: authn.browserAccounts(r) };
  });
  at('Clear-Site-Data with an account left', 'clearSiteData', browser, {},
     function (r, res) {
       res.setHeader = function (k, v) {
         res.clearSiteData = String(v);
       };
       authn.clearSiteDataAfterSignOut(r, res);
       return { cleared: !!res.clearSiteData };
     });

  // ---- D12: a session with no set gets one around it ------------------------
  overrides['authn.multipleAccounts'] = false;
  const lone = jar();
  start('a sign-in with the setting off', lone, 'gil', ['pwd'], '1',
        'OAuth 2.0 / OIDC', pwd());
  overrides['authn.multipleAccounts'] = true;
  sessionOf('a set is made around it where the response is open', lone,
            { open: true });
  at('and its accounts', 'browserAccounts', lone, {}, function (r) {
    return { listed: authn.browserAccounts(r) };
  });

  // ---- an unreadable set is a 503 at the picker -----------------------------
  run('a set that cannot be read', 'refuseAccountsUnread',
      { cookie: 'x=%E0%A4%A; ' + browser.header() }, function (res) {
        const r = request('x=%E0%A4%A; ' + browser.header());
        res.status = function () {
          return res;
        };
        res.headersSent = true;
        return { refused: authn.refuseAccountsUnread(r, res) };
      });

  // ---- running out ----------------------------------------------------------
  clock.now += 3601 * 1000;
  sessionOf('fay ran out: read lazily', browser);
  run('the clean-up moves what ended to remembered', 'sweepAccountSets', {},
      function () {
        return { done: authn.sweepAccountSets() };
      });
  clock.now += 31 * 24 * 3600 * 1000;
  rec.calls = [];
  const budgeted = await authn.sweepAccountSetsBudgeted();
  const calls = rec.calls;
  rec.calls = null;
  steps.push({ name: 'a month later the remembered are dropped',
               door: 'sweepAccountSetsBudgeted', now: clock.now, input: {},
               answer: { done: rec.copy(budgeted) }, cookies: [], locals: {},
               calls: calls, store: h.storeOf(),
               sets: dump('authn.accountSets'),
               tickets: dump('authn.accountTickets') });

  // ---- the pure functions ---------------------------------------------------
  const pure = [];
  mergeCases(clock.now).forEach(function (one) {
    pure.push({ fn: 'merge', name: one.name, args: [one.mine, one.theirs],
                answer: rec.copy(AccountSets.merge(rec.copy(one.mine),
                                                   rec.copy(one.theirs))) });
  });
  ['/a', '/a?x=1', '/a?sts_account=T', '/a?x=1&sts_account=T%2Bq&y=2',
   '/a?sts_account=%E0', '/a?sts_account=&b=1'].forEach(function (url) {
    const r = { url: url, originalUrl: url, query: {} };
    const ticket = AccountSets.stripTicket(r);
    pure.push({ fn: 'stripTicket', args: [url],
                answer: { url: r.url, ticket: ticket } });
  });
  [['/a', 't'], ['/a?x', 't/+='], ['', 'x']].forEach(function (pair) {
    pure.push({ fn: 'withTicket', args: pair,
                answer: AccountSets.withTicket(pair[0], pair[1]) });
  });
  [{ sub: 's1' }, { sub: '', username: 'u' }, {}].forEach(function (one) {
    pure.push({ fn: 'keyOf', args: [one], answer: AccountSets.keyOf(one) });
  });

  helpers.randomId = realRandom;
  helpers.cookieDomainAttribute = realDomain;
  Date.now = h.realNow;
  return { steps: steps, pure: pure, people: h.people,
           ids: { dora: doraId, emil: emilId, fay: fayId } };
}

/**
 * `beginAuthentication()`'s account half, as the Rust crate exposes it:
 * what the wrapper decides before it calls `beginAuthenticationHere()`.
 * Node has no function of its own for it, so this drives the wrapper with
 * `beginAuthenticationHere()` and `routeToAccounts()` replaced by recorders
 * of what they were handed.
 *
 * @param {any} authn - the instance
 * @param {any} r - the request
 * @param {string} choice - `accountChoice`
 * @param {boolean} hinted - whether the options carry a hint
 * @returns {any} `{ pick, hint }`
 */
function beginChoiceOf(authn, r, choice, hinted) {
  const here = authn.beginAuthenticationHere;
  const route = authn.routeToAccounts;
  const seen = { pick: '', hint: null };
  authn.beginAuthenticationHere = function (given) {
    seen.hint = given.hint && !hinted ? String(given.hint) : null;
    return '/authn/login?authn=x';
  };
  authn.routeToAccounts = function (given, target, why) {
    seen.pick = why;
    return '/authn/accounts?authn=x';
  };
  try {
    authn.beginAuthentication({ request: r, accountChoice: choice,
                                hint: hinted ? 'given' : '',
                                returnTo: '/x' });
  } finally {
    authn.beginAuthenticationHere = here;
    authn.routeToAccounts = route;
  }
  return seen;
}

/**
 * `authn.pending`, the sign-in's store, through its declared handle: the
 * picker's record is put there and read back, so what the doors did to it
 * is answered rather than kept.
 *
 * @returns {any} the handle row
 */
function pendingStore() {
  return require(path.join(__dirname, '..', '..', 'common', 'realms'))
    .handleFor('authn.pending');
}

/**
 * `routeToAccounts()`, with the record the target names in the pending
 * store first, and the record it left there answered.
 *
 * @param {any} authn - the instance
 * @param {any} existing - the record the target names, or null
 * @param {any} opts - the options
 * @param {string} target - the sign-in address
 * @param {string} why - the reason
 * @param {any} r - the request
 * @returns {any} `{ record, location }`
 */
function routeOf(authn, existing, opts, target, why, r) {
  const store = pendingStore();
  if (existing) {
    store.restore('default', existing.id, existing);
  }
  const location = authn.routeToAccounts(opts, target, why, r);
  const id = decodeURIComponent(location.split('authn=')[1] || '');
  const kept = store.read('default', id);
  store.remove('default', id);
  return { record: kept.present ? JSON.parse(JSON.stringify(kept.value))
                                : null,
           location: location };
}

/**
 * `accountsAct()` with its answer captured, and what it did to the pending
 * record read from the store it was put in.
 *
 * @param {any} authn - the instance
 * @param {any} r - the request
 * @param {any} res - the response
 * @param {any} record - the pending sign-in
 * @param {any} body - `{ action, account }`
 * @returns {any} `{ answer, record }`
 */
function actOf(authn, r, res, record, body) {
  const store = pendingStore();
  const before = JSON.stringify(record);
  store.restore('default', record.id, JSON.parse(before));
  const answer = { status: 0, body: null, code: '', retryAfter: false };
  res.status = function (s) {
    answer.status = s;
    return res;
  };
  res.type = function () {
    return res;
  };
  const realSet = res.set;
  res.set = function (k, v) {
    if (String(k).toLowerCase() === 'set-cookie') {
      realSet.call(res, k, v);
      return res;
    }
    if (String(k) === 'Retry-After') {
      answer.retryAfter = true;
    }
    return res;
  };
  res.send = function (text) {
    answer.body = JSON.parse(text);
    return res;
  };
  res.location = function (target) {
    res.locationWas = target;
  };
  res.get = function () {
    return res.locationWas;
  };
  res.removeHeader = function () {};
  authn.accountsAct(r, res, record, body);
  const after = store.read('default', record.id);
  store.remove('default', record.id);
  const change = !after.present ? { kind: 'delete', id: record.id }
    : JSON.stringify(after.value) === before ? { kind: 'keep' }
    : { kind: 'set', record: JSON.parse(JSON.stringify(after.value)) };
  answer.code = String(res[Symbol.for('iya-sts.errorCode')] || '');
  return { answer: answer, record: change };
}

/**
 * Pairs of account sets for `AccountSets.merge()`, each a rule it holds.
 *
 * @param {number} now - the instant the rows are stamped around
 * @returns {any[]} the cases
 */
function mergeCases(now) {
  const base = function (more) {
    return Object.assign({ id: 'set1', handleHash: 'h1', createdAt: now - 50,
                           updatedAt: now - 10, lastActiveSid: 's1',
                           sessions: { s1: { sub: 'u1', username: 'dora',
                                             displayName: 'dora',
                                             addedAt: now - 40 } },
                           remembered: {}, endedSids: {}, forgotten: {},
                           handleIssuedAt: now - 40 }, more);
  };
  return [
    { name: 'nothing of mine', mine: null, theirs: base({}) },
    { name: 'nothing stored', mine: base({}), theirs: null },
    { name: 'the later handle is the base',
      mine: base({ handleHash: 'h2', handleIssuedAt: now }),
      theirs: base({ updatedAt: now }) },
    { name: 'sessions are a union less what either ended',
      mine: base({ sessions: { s1: { sub: 'u1', username: 'dora' },
                               s2: { sub: 'u2', username: 'emil' } } }),
      theirs: base({ sessions: { s3: { sub: 'u3', username: 'fay' } },
                     endedSids: { s1: now - 5 } }) },
    { name: 'remembered keeps the latest sign-out and drops the forgotten',
      mine: base({ remembered: { u2: { sub: 'u2', signedOutAt: 5 },
                                 u4: { sub: 'u4', signedOutAt: 9 } },
                   forgotten: { u4: 10 } }),
      theirs: base({ remembered: { u2: { sub: 'u2', signedOutAt: 7 },
                                   u1: { sub: 'u1', signedOutAt: 3 } } }) },
    { name: 'a last active session that ended is cleared',
      mine: base({ lastActiveSid: 's9' }),
      theirs: base({ handleIssuedAt: 1 }) },
    { name: 'a row with no merge memory',
      mine: { id: 'set1', handleIssuedAt: 1, sessions: {} },
      theirs: { id: 'set1', handleIssuedAt: 2, updatedAt: 3 } }
  ];
}

/**
 * THE ACCOUNT SETS `sts-authn` WROTE, read back by Node's own `Authn`: each
 * browser's cookies are presented to the doors a browser meets, and the
 * set its `sts_accounts` cookie names must open, list the accounts Rust
 * listed, and resolve the request as Rust resolved it — so a set this
 * runtime writes is one the Node service honours (D11).
 *
 * @param {string} ROOT - the repository root
 * @param {any} v - account-sets-rust.json
 * @param {function(boolean, string, string=): void} check - the collector
 */
function checkRust(ROOT, v, check) {
  const authnModule = require(path.join(ROOT, 'authn', 'authn'));
  const AccountSets = require(path.join(ROOT, 'authn', 'account_sets'));
  const config = require(path.join(ROOT, 'common', 'config'));
  const realms = require(path.join(ROOT, 'common', 'realms'));
  const realValue = config.value.bind(config);
  const realNow = Date.now;
  config.value = function (key) {
    if (key === 'authn.multipleAccounts') {
      return true;
    }
    if (key === 'authn.sessionWindow') {
      return 'off';
    }
    return realValue.apply(null, arguments);
  };
  const sets = realms.handleFor('authn.accountSets');
  try {
    (v.browsers || []).forEach(function (one) {
      Date.now = function () {
        return Number(one.now);
      };
      Object.keys(one.sessions).forEach(function (sid) {
        authnModule.sessions.set(sid, JSON.parse(JSON.stringify(
          one.sessions[sid])));
      });
      sets.restore('default', one.set.id, JSON.parse(JSON.stringify(
        one.set)));
      const req = { headers: { cookie: one.cookie }, url: '/' };
      const opened = AccountSets.setOf(authnModule.cookiesOf(req));
      check(!!opened && opened.id === one.set.id &&
            JSON.stringify(opened) === JSON.stringify(one.set),
            'account-sets-rust: the sts_accounts cookie sts-authn wrote ' +
            'opens its set in Node (' + one.name + ')');
      const listed = authnModule.browserAccounts(req);
      check(JSON.stringify(listed.accounts) ===
            JSON.stringify(one.accounts),
            'account-sets-rust: Node lists the accounts sts-authn listed (' +
            one.name + ')', JSON.stringify(listed.accounts) + ' vs ' +
            JSON.stringify(one.accounts));
      const chosen = authnModule.sessionOf({ headers: { cookie: one.cookie },
                                             url: '/' });
      check(String((chosen && chosen.id) || '') === String(one.actsAs || ''),
            'account-sets-rust: Node resolves the request as sts-authn did (' +
            one.name + ')');
      Object.keys(one.sessions).forEach(function (sid) {
        authnModule.sessions.delete(sid);
      });
      sets.remove('default', one.set.id);
    });
  } finally {
    config.value = realValue;
    Date.now = realNow;
  }
}

module.exports = { build: build, checkRust: checkRust };

if (require.main === module) {
  build(path.join(__dirname, '..', '..')).then(function (out) {
    process.stdout.write(JSON.stringify(out, null, 1) + '\n');
  });
}
