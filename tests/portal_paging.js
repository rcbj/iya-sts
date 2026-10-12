// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/portal_paging.js
//
// ---------------------------------------------------------------------------
// THE USER PORTAL'S UNBOUNDED LISTS, PAGED (#313's sweep, 2026-10-12).
//
// Three portal lists drew either everything or a silent first slice: the
// realm's Claims Providers on `/portal/claim-sources` (everything), the
// person's sign-ins on `/portal/sign-ins` (the risk engine's default fifty)
// and the mail sent to them on `/portal/email` (the newest twenty). Each is
// now a page of twenty with a paging member beside it, and this file holds
// the three account API views and the control to it:
//
//   1. ONE PAGE, the totals over the whole list.
//   2. A PAGE PAST THE END CLAMPED to the last.
//   3. A WALK OF EVERY PAGE seeing every row once.
//   4. SIGN-INS PAGED IN THE STORE: the engine is asked for `limit` and
//      `offset`, never for everything.
//   5. `PortalKit.pageNav()` moving its own parameter, carrying the others
//      and dropping `notice` / `problem`, and drawing nothing for one page.
//
// In process, each module built over stub dependencies — its own instance,
// so nothing process-wide is replaced.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const claimSources = require('../portal/portal_claim_sources');
const signIns = require('../portal/portal_sign_ins');
const portalMail = require('../portal/portal_mail');
const kit = require('../portal/web_portal_kit');

const log = require('bunyan').createLogger({ name: 'portal_paging',
  level: process.env.LOG_LEVEL || 'info' });

const quiet = { debug: function () {}, info: function () {} };

function walk(read) {
  log.debug("Entering walk().");
  const seen = [];
  for (let page = 1; page <= 50; page++) {
    const one = read(page);
    seen.push.apply(seen, one.ids);
    if (page >= one.pages) {
      break;
    }
  }
  log.debug("Leaving walk().");
  return seen;
}

function distinct(ids) {
  return ids.filter(function (id, i) {
    return ids.indexOf(id) === i;
  }).length;
}

async function run(t) {
  log.debug("Entering run().");

  // --- Claim sources ------------------------------------------------------
  const PROVIDERS = 47;
  const providers = [];
  for (let i = 0; i < PROVIDERS; i++) {
    providers.push({ id: 'cp' + String(i).padStart(2, '0'), name: 'P' + i,
                     issuer: 'https://cp' + i + '.example', claims: ['x'],
                     delivery: 'aggregated' });
  }
  const cs = new claimSources.PortalClaimSources({
    log: quiet,
    claimsProviders: {
      list: function () {
        return providers;
      },
      linksOf: function () {
        return [{ provider: 'cp03', linkedAt: '20261012000000Z' },
                { provider: 'cp44', linkedAt: '20261012000000Z' }];
      }
    }
  });
  const first = cs.view('alice');
  t.check(first.providers.length === 20 && first.paging.page === 1 &&
          first.paging.pages === 3 && first.paging.total === PROVIDERS &&
          first.linked === 2,
          '1a. claim sources: one page of twenty, the totals over every ' +
          'provider', JSON.stringify({ paging: first.paging,
                                       linked: first.linked }));
  const past = cs.view('alice', 99);
  t.check(past.paging.page === 3 && past.providers.length === 7 &&
          past.providers[4].id === 'cp44' &&
          past.providers[4].link !== null &&
          past.providers[6].link === null,
          '2a. claim sources: a page past the end is the last, links kept',
          JSON.stringify(past.paging));
  const csSeen = walk(function (page) {
    const one = cs.view('alice', page);
    return { pages: one.paging.pages, ids: one.providers.map(function (p) {
      return p.id;
    }) };
  });
  t.check(csSeen.length === PROVIDERS && distinct(csSeen) === PROVIDERS,
          '3a. claim sources: walking every page reads every provider once',
          String(csSeen.length));

  // --- Sign-ins -----------------------------------------------------------
  const SIGN_INS = 53;
  const asked = [];
  const assessments = [];
  for (let i = 0; i < SIGN_INS; i++) {
    assessments.push({ id: 'a' + String(i).padStart(2, '0'), at: 1000 - i,
                       subject: 'sub-alice', level: 'LOW' });
  }
  const si = new signIns.PortalSignIns({
    log: quiet,
    realms: function () {
      return { currentId: function () {
        return '';
      } };
    },
    riskEngine: function () {
      return { view: function (realm, opts) {
        asked.push({ limit: opts.limit, offset: opts.offset,
                     subject: opts.subject });
        return Promise.resolve({ assessments: {
          total: assessments.length,
          rows: assessments.slice(opts.offset, opts.offset + opts.limit) } });
      } };
    }
  });
  const caller = { sub: 'sub-alice', username: 'alice',
                   session: { risk: { assessmentId: 'a00' } } };
  const siFirst = await si.view(caller);
  t.check(siFirst.rows.length === 20 && siFirst.paging.total === SIGN_INS &&
          siFirst.paging.pages === 3 && siFirst.thisSession === 'a00',
          '1b. sign-ins: one page of twenty, the total over thirty days',
          JSON.stringify(siFirst.paging));
  t.check(asked.length === 1 && asked[0].limit === 20 &&
          asked[0].offset === 0 && asked[0].subject === 'sub-alice',
          '4. sign-ins: the store is asked for one page, never for all',
          JSON.stringify(asked));
  const siPast = await si.view(caller, 9);
  t.check(siPast.paging.page === 3 && siPast.rows.length === SIGN_INS % 20 &&
          siPast.rows[0].id === 'a40',
          '2b. sign-ins: a page past the end is the last page',
          JSON.stringify(siPast.paging));
  const siSeen = [];
  for (let page = 1; page <= 3; page++) {
    const one = await si.view(caller, page);
    siSeen.push.apply(siSeen, one.rows.map(function (a) {
      return a.id;
    }));
  }
  t.check(siSeen.length === SIGN_INS && distinct(siSeen) === SIGN_INS,
          '3b. sign-ins: walking every page reads every sign-in once',
          String(siSeen.length));

  // --- Mail sent ----------------------------------------------------------
  const SENT = 45;
  const outbox = [];
  for (let i = 0; i < SENT; i++) {
    outbox.push({ id: 'm' + i, queuedAt: 5000 - i, subject: 'S' + i,
                  to: 'alice@example.com', state: 'sent' });
  }
  const pm = new portalMail.PortalMail({
    log: quiet, mailUses: {}, realms: {},
    mail: {
      recipient: function () {
        return { address: 'alice@example.com', verified: true };
      },
      available: function () {
        return true;
      },
      directory: function () {
        return null;
      },
      declined: function () {
        return [];
      },
      CATEGORIES: [],
      list: function (opts) {
        return opts && opts.username === 'alice' ? outbox.slice() : [];
      }
    }
  });
  const mFirst = pm.emailView('alice');
  t.check(mFirst.sent.length === 20 && mFirst.sentPaging.total === SENT &&
          mFirst.sentPaging.pages === 3 && mFirst.sent[0].subject === 'S0',
          '1c. sent mail: one page of twenty, the total over the outbox',
          JSON.stringify(mFirst.sentPaging));
  const mPast = pm.emailView('alice', 40);
  t.check(mPast.sentPaging.page === 3 && mPast.sent.length === 5,
          '2c. sent mail: a page past the end is the last page',
          JSON.stringify(mPast.sentPaging));
  const mSeen = walk(function (page) {
    const one = pm.emailView('alice', page);
    return { pages: one.sentPaging.pages, ids: one.sent.map(function (m) {
      return m.subject;
    }) };
  });
  t.check(mSeen.length === SENT && distinct(mSeen) === SENT,
          '3c. sent mail: walking every page reads every message once',
          String(mSeen.length));

  // --- The control --------------------------------------------------------
  const tr = {
    html: function (key, params) {
      return key + (params ? JSON.stringify(params) : '');
    }
  };
  const nav = kit.pageNav('/portal/email',
    { sentPage: '2', other: 'kept', notice: 'Saved.', problem: 'x' },
    { page: 2, pages: 3 }, 'sentPage', tr);
  t.check(nav.indexOf('href="/portal/email?other=kept"') >= 0 &&
          nav.indexOf('href="/portal/email?sentPage=3&amp;other=kept"') >= 0 &&
          nav.indexOf('notice') < 0 && nav.indexOf('problem') < 0 &&
          nav.indexOf('id="pager-sentPage"') >= 0,
          '5a. pageNav moves its own parameter, carries the others, drops ' +
          'notice and problem', nav);
  t.check(kit.pageNav('/portal/email', {}, { page: 1, pages: 1 },
                      'sentPage', tr) === '' &&
          kit.pageNav('/portal/email', {}, null, 'sentPage', tr) === '',
          '5b. pageNav draws nothing for a list on one page', '');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'portal paging',
  describe: 'The user portal\'s claim sources, sign-ins and sent mail ' +
            'paged twenty a page: totals, clamped, walked, sign-ins paged ' +
            'in the store, and the shared pager',
  run: run
};
