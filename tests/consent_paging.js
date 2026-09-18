'use strict';
//
// File: tests/consent_paging.js
//
// ---------------------------------------------------------------------------
// MONITORING -> CONSENT, BOTH HALVES PAGED THROUGH BOTH DOORS (2026-09-18).
//
// The consent register grows without a bound in both halves — a global
// override per (application, scope), and a recorded consent per (person,
// application, scope). `/admin/consent` paged both tables, but
// `GET /admin-api/consent` answered `consentView()` whole, so the door a
// script reads was the one that grew for ever. Both now read
// `adminViews.consentPageView()`, and this file holds that function to what
// the page and the API document:
//
//   1. ONE PAGE OF EACH HALF, never the whole list beside it, with `counts`
//      still carrying the totals.
//   2. TWO PAGERS THAT DO NOT MOVE EACH OTHER — `globalsPage` moves `globals`
//      and `usersPage` moves `users` — and `per` sizing both.
//   3. EACH PAGER NAMED AFTER ITS ARRAY, the management API's rule for a reply
//      holding several lists: `globalsPaging`, `usersPaging`.
//   4. A PAGE PAST THE END CLAMPED to the last, as every list here is.
//   5. `q` NARROWING THE RECORDED HALF ONLY, with `matched` and the paging
//      counting the narrowed list.
//   6. A WALK OF EVERY PAGE seeing every row once — the reading
//      `tests/vendored/sts_consent.js` now does.
//
// In process, through the function both doors call: filling the register over
// HTTP would be a sign-in and a consent screen per row. The markup — that the
// console's links carry the other half's page — was checked by rendering the
// page; the API's parameters and reply are `admin_api.js`'s and
// `sts_admin_api_operations.js`'s over HTTP.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const applications = require('../common/applications');
const ldap = require('../ldap/ldap_server');
const consent = require('../common/consent');
const adminViews = require('../admin-core/admin_views');

const log = require('bunyan').createLogger({ name: 'consent_paging',
  level: process.env.LOG_LEVEL || 'info' });

const TAG = 'cpg' + process.pid;
const CLIENT = TAG + '-client';
const PEOPLE = 4;
const SCOPES_EACH = 6;
const GLOBALS = 13;

function run(t) {
  log.debug("Entering run().");

  // --- The register, filled ---------------------------------------------
  applications.createApplication({ identifier: CLIENT, protocols: ['oauth2'],
    fields: { oauthClientId: CLIENT } });
  for (let g = 0; g < GLOBALS; g++) {
    consent.grantGlobal(CLIENT, TAG + '-global-' + String(g).padStart(2, '0'),
                        'consent_paging');
  }
  for (let p = 0; p < PEOPLE; p++) {
    const person = TAG + '-person-' + p;
    ldap.createUser(person, { invent: false });
    const scopes = [];
    for (let s = 0; s < SCOPES_EACH; s++) {
      scopes.push(TAG + '-scope-' + s);
    }
    consent.record(person, CLIENT, scopes, 'consent_paging');
  }
  const whole = adminViews.consentView();
  const myGlobals = whole.globals.filter(function (one) {
    return one.client === CLIENT;
  }).length;
  const myUsers = whole.users.filter(function (one) {
    return one.client === CLIENT;
  }).length;
  t.check(myGlobals === GLOBALS && myUsers === PEOPLE * SCOPES_EACH,
          '0. the register holds what this file wrote',
          JSON.stringify({ globals: myGlobals, users: myUsers }));

  // --- 1. One page of each half -----------------------------------------
  const first = adminViews.consentPageView({ per: '5' }).json;
  t.check(first.globals.length === Math.min(5, whole.globals.length) &&
          first.users.length === Math.min(5, whole.users.length),
          '1a. the reply is ONE PAGE of each half, not the whole register',
          JSON.stringify({ globals: first.globals.length,
                           users: first.users.length }));
  t.check(first.counts.globals === whole.globals.length &&
          first.counts.consents === whole.users.length,
          '1b. and `counts` still carries both totals',
          JSON.stringify(first.counts));
  t.check(first.globalsPaging.total === whole.globals.length &&
          first.usersPaging.total === whole.users.length &&
          first.globalsPaging.pages ===
            Math.ceil(whole.globals.length / 5) &&
          first.usersPaging.pages === Math.ceil(whole.users.length / 5),
          '1c. and each half\'s paging says how many pages there are',
          JSON.stringify({ g: first.globalsPaging, u: first.usersPaging }));

  // --- 2 and 3. Two pagers, named after their arrays --------------------
  t.check(!('consentsPaging' in first) && 'usersPaging' in first &&
          'globalsPaging' in first,
          '3a. each pager is named after the array it pages ' +
          '(globalsPaging, usersPaging)');
  const movedGlobals = adminViews.consentPageView(
    { per: '5', globalsPage: '2' }).json;
  t.check(movedGlobals.globalsPaging.page === 2 &&
          movedGlobals.usersPaging.page === 1 &&
          JSON.stringify(movedGlobals.users) === JSON.stringify(first.users) &&
          JSON.stringify(movedGlobals.globals) !==
            JSON.stringify(first.globals),
          '2a. globalsPage moves the overrides and NOT the recorded consents');
  const movedUsers = adminViews.consentPageView(
    { per: '5', usersPage: '3' }).json;
  t.check(movedUsers.usersPaging.page === 3 &&
          movedUsers.globalsPaging.page === 1 &&
          JSON.stringify(movedUsers.globals) ===
            JSON.stringify(first.globals) &&
          movedUsers.usersPaging.firstRow === 11,
          '2b. usersPage moves the recorded consents and NOT the overrides',
          JSON.stringify(movedUsers.usersPaging));
  const oldName = adminViews.consentPageView(
    { per: '5', consentsPage: '3' }).json;
  t.check(oldName.usersPaging.page === 1,
          '2c. the old `consentsPage` name moves nothing any more');
  const bigger = adminViews.consentPageView({ per: '7' }).json;
  t.check(bigger.globalsPaging.perPage === 7 &&
          bigger.usersPaging.perPage === 7,
          '2d. `per` sizes both halves');

  // --- 4. Clamped ---------------------------------------------------------
  const past = adminViews.consentPageView(
    { per: '5', globalsPage: '9999', usersPage: '9999' }).json;
  t.check(past.globalsPaging.page === past.globalsPaging.pages &&
          past.usersPaging.page === past.usersPaging.pages &&
          past.users.length > 0,
          '4a. a page past the end is the last page, and says so');

  // --- 5. The search ------------------------------------------------------
  const person = TAG + '-person-2';
  const searched = adminViews.consentPageView({ per: '4', q: person }).json;
  t.check(searched.matched === SCOPES_EACH &&
          searched.usersPaging.total === SCOPES_EACH &&
          searched.usersPaging.pages === 2 &&
          searched.users.every(function (one) {
            return one.username === person;
          }),
          '5a. q narrows the recorded consents, and the paging counts the ' +
          'narrowed list', JSON.stringify(searched.usersPaging));
  t.check(searched.globalsPaging.total === whole.globals.length,
          '5b. and leaves the overrides alone — they are paged, not searched');
  t.check(searched.query && searched.query.q === person,
          '5c. and the reply says what it searched for');

  // --- 6. A walk of every page ------------------------------------------
  const seen = { globals: [], users: [] };
  for (let page = 1; ; page++) {
    const one = adminViews.consentPageView(
      { per: '5', globalsPage: String(page), usersPage: String(page) }).json;
    if (page <= one.globalsPaging.pages) {
      seen.globals = seen.globals.concat(one.globals);
    }
    if (page <= one.usersPaging.pages) {
      seen.users = seen.users.concat(one.users);
    }
    if (page >= one.globalsPaging.pages && page >= one.usersPaging.pages) {
      break;
    }
  }
  const keyOf = function (one) {
    return [one.username || '', one.client, one.scope].join('|');
  };
  const distinct = function (rows) {
    return rows.map(keyOf).filter(function (k, i, all) {
      return all.indexOf(k) === i;
    }).length;
  };
  t.check(seen.globals.length === whole.globals.length &&
          seen.users.length === whole.users.length &&
          distinct(seen.globals) === whole.globals.length &&
          distinct(seen.users) === whole.users.length,
          '6a. walking every page reads every row exactly once',
          JSON.stringify({ globals: seen.globals.length,
                           users: seen.users.length }));

  // --- Tidy up: the register is process-wide ------------------------------
  for (let p = 0; p < PEOPLE; p++) {
    consent.forget(TAG + '-person-' + p, 'consent_paging');
  }
  for (let g = 0; g < GLOBALS; g++) {
    consent.revokeGlobal(CLIENT,
                         TAG + '-global-' + String(g).padStart(2, '0'),
                         'consent_paging');
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'consent paging',
  describe: 'Monitoring -> Consent: one page of each half through both ' +
            'doors, two pagers named after their arrays, clamped, searched, ' +
            'and walked',
  run: run
};
