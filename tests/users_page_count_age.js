// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: users_page_count_age.js
//
// ===========================================================================
// /admin/users SAYS WHICH NUMBER IS WHICH, AND HOW OLD ITS COUNT IS (#684).
//
// Two leftovers of #353. `known` is the length of the CAPPED list — at most
// `credentials.factorScanLimit` directory people united with the register —
// and the footer printed it as "known in total" with nothing beside it, so
// on a realm past the cap it stood still while people outside the slice
// were deleted and disagreed with SCIM's `totalResults` by thousands. And
// the directory's tiles are kept, in a windowed process, for up to ten
// seconds against another process's writes, with nothing on the page saying
// the figure had an age.
//
// Asserted:
//
//   1. the view answers `directoryCountedAt` (ISO 8601, when the directory
//      counted) and `directoryCountsKeptFor` (null here: a directory in
//      memory has no other process to lag), and `directoryCounts` stays the
//      tiles alone;
//   2. a repeat is the kept count, with the same `directoryCountedAt`, and a
//      person created ends it: a new count, one more person, no earlier;
//   3. `/admin-api/mfa` carries the same two members;
//   4. the directory's tally, as `credentials.directoryFactorCounts()` hands
//      it on, carries `countedAt` and `keptForSeconds`;
//   5. the page: past the cap the footer says the total is the capped list
//      and draws the directory's count beside it; under the cap it draws
//      the count with the other sentence; with no directory count, neither;
//   6. the page: with a bound, a note under the tiles draws the counting
//      time, the age and the bound; with none (in memory), no note.
//
// WHY IN PROCESS: the windowed bound needs a store and a second process to
// show a lag, which no job here stages for one sentence; what the page and
// the view SAY about it is what this file holds, against the real view and
// the real renderer.
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const realms = require('../common/realms');
const ldap = require('../ldap/ldap_server');
const credentials = require('../common/credentials');
const adminViews = require('../admin-core/admin_views');
require('../common/i18n');
// Requiring i18n installs the English translator the console renderer uses
// when a test draws a page (#539).
const page = require('../admin-ui/web_users');
const kit = require('../admin-ui/web_kit');

const log = require('bunyan').createLogger({
  name: 'users_page_count_age',
  level: process.env.LOG_LEVEL || 'info' });

const STAMP = Date.now().toString(36);
const REALM = 'upca' + STAMP.slice(-6);
const PEOPLE = 30;
// Below PEOPLE, so the list is capped.
const SCAN_LIMIT = 10;

function draw(json) {
  log.debug("Entering draw().");
  const html = page.body(kit.context({}), json);
  log.debug("Leaving draw().");
  return html;
}

function body(t) {
  log.debug("Entering body().");
  for (let i = 0; i < PEOPLE; i++) {
    ldap.createUser('upca-' + STAMP + '-' + i,
                    { invent: false, origin: 'test' });
  }
  // The realm is created with its own seeded people, so the count asserted
  // is the directory's own, not PEOPLE.
  const defined = ldap.personCount();
  const before = Date.now();
  const first = adminViews.usersJson({ query: {} });
  const at = Date.parse(first.directoryCountedAt);
  t.check(typeof first.directoryCountedAt === 'string' &&
          Number.isFinite(at) && at <= Date.now() &&
          first.directoryCountsKeptFor === null &&
          defined >= PEOPLE && first.directoryPeople === defined,
          '1a. the view says when the directory counted, and keeps for ' +
          'no bound in memory',
          JSON.stringify({ defined: defined, at: first.directoryCountedAt,
                           keptFor: first.directoryCountsKeptFor,
                           people: first.directoryPeople,
                           before: new Date(before).toISOString() }));
  t.check(!!first.directoryCounts &&
          !('countedAt' in first.directoryCounts) &&
          !('keptForSeconds' in first.directoryCounts),
          '1b. directoryCounts stays the tiles alone',
          Object.keys(first.directoryCounts || {}).join(','));

  const again = adminViews.usersJson({ query: {} });
  t.equal(again.directoryCountedAt, first.directoryCountedAt,
          '2a. a repeat answers the kept count, counted at the same time');
  ldap.createUser('upca-' + STAMP + '-extra',
                  { invent: false, origin: 'test' });
  const after = adminViews.usersJson({ query: {} });
  t.check(after.directoryPeople === defined + 1 &&
          Date.parse(after.directoryCountedAt) >= at,
          '2b. a person created ends the kept count: counted again, ' +
          'no earlier', JSON.stringify({ people: after.directoryPeople,
                                         at: after.directoryCountedAt }));

  const roster = adminViews.mfaRosterJson({ query: {} });
  t.check(roster.directoryCountedAt === after.directoryCountedAt &&
          roster.directoryCountsKeptFor === null,
          '3. /admin-api/mfa carries the same two members',
          JSON.stringify({ at: roster.directoryCountedAt,
                           keptFor: roster.directoryCountsKeptFor }));

  const tally = credentials.directoryFactorCounts();
  t.check(!!tally && typeof tally.countedAt === 'number' &&
          tally.countedAt === Date.parse(after.directoryCountedAt) &&
          tally.keptForSeconds === null,
          '4. the directory\'s tally carries countedAt and keptForSeconds',
          JSON.stringify(tally && { countedAt: tally.countedAt,
                                    keptForSeconds: tally.keptForSeconds }));

  // --- 5. the footer ----------------------------------------------------
  const capped = draw(after);
  t.check(after.capped === true &&
          capped.indexOf('is the length of the capped list') >= 0 &&
          capped.indexOf('The directory holds ' + (defined + 1)) >= 0 &&
          capped.indexOf('first ' + SCAN_LIMIT + ' of the directory') >= 0,
          '5a. past the cap the footer says the total is the capped list ' +
          'and draws the directory\'s count beside it',
          'capped=' + after.capped);
  const uncapped = draw(Object.assign({}, after, { capped: false }));
  t.check(uncapped.indexOf('is the length of the capped list') < 0 &&
          uncapped.indexOf('unites the directory') >= 0 &&
          uncapped.indexOf('The directory holds ' + (defined + 1)) >= 0,
          '5b. under the cap it draws the count with the other sentence');
  const uncounted = draw(Object.assign({}, after,
                                       { directoryPeople: null }));
  // The capped warning above the table says "The directory holds" too, so
  // the footer's sentence is told apart by its SCIM comparison.
  t.check(capped.indexOf('the figure to compare with') >= 0 &&
          uncounted.indexOf('the figure to compare with') < 0,
          '5c. with no directory count, neither sentence');

  // --- 6. the age -------------------------------------------------------
  t.check(capped.indexOf('before this page was drawn') < 0,
          '6a. in memory (no bound) no age note is drawn');
  const counted = new Date(Date.now() - 3000).toISOString();
  const windowed = draw(Object.assign({}, after, {
    directoryCountedAt: counted, directoryCountsKeptFor: 10 }));
  const ageShown = windowed.indexOf('UTC, 3 s before') >= 0 ||
                   windowed.indexOf('UTC, 4 s before') >= 0;
  t.check(ageShown &&
          windowed.indexOf(counted.slice(11, 19) + ' UTC') >= 0 &&
          windowed.indexOf('at most 10 s') >= 0,
          '6b. with a bound, the note draws the counting time, the age ' +
          'and the bound', counted);
  log.debug("Leaving body().");
}

async function run(t) {
  log.debug("Entering run().");
  const made = realms.create({ id: REALM, name: REALM,
                               description: 'Created by ' + __filename });
  if (!made.ok) {
    t.bad('could not create the realm', (made.errors || []).join(' '));
    log.debug("Leaving run().");
    return;
  }
  try {
    await realms.run(made.realm, async function () {
      config.setOverride('credentials.factorScanLimit', String(SCAN_LIMIT));
      try {
        body(t);
      } finally {
        config.clearOverride('credentials.factorScanLimit');
      }
    });
  } finally {
    realms.remove(REALM);
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'users_page_count_age',
  describe: '/admin/users says its total is the capped list beside the ' +
            'directory\'s count, and how old the directory\'s count is ' +
            '(#684)',
  run: run
};
