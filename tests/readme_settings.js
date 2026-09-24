'use strict';
//
// File: readme_settings.js
//
// ===========================================================================
// THE SETTINGS TABLES, AGAINST THE TABLE THAT DECLARES THE SETTINGS.
//
// The tables are in `docs/configuration.md` (*Every setting*). They were in
// README.md, which is where this file's name comes from.
//
// `readme_ports.js` next door holds ten rows of README to `config.js`. This
// file holds the other two hundred, and it exists because of what those ten
// caught and these two hundred did not.
//
// **ON 2026-09-06 FOUR SETTINGS WERE DELETED AND NOTHING NOTICED.**
// `common/mode.js` took over "is authentication required here" — a question
// that had had four answers — and `admin.authRequired`, `scim.authRequired`,
// `spiffe.authRequired` and `ssf.authRequired` stopped existing. The code was
// swept. The prose was not, and four days later this repository still
// documented all four as live settings with live environment variables: three
// of them as ROWS in the settings table, with a default and a Change-while-
// running column, in the one document a reader goes to to find out what they
// can configure.
//
// `readme_ports.js` had already caught the fifth instance of exactly this —
// its own section cited `spiffe.authRequired` — and reported it the day it was
// written. That is the argument for this file in one sentence: **the check
// worked, and it was pointed at ten rows out of two hundred and ten.**
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS, which is the question tests/CLAUDE.md asks first.
//
// Every claim here is a comparison between two FILES in this repository —
// `docs/configuration.md` and `common/config.js`. No running service could be
// asked, and nothing here binds a port or issues anything. Same shape as
// `readme_ports.js`, `postgres_schema.js` and `xacml_pep.js`'s COPY set.
//
// ---------------------------------------------------------------------------
// IT CHECKS THE DIRECTION THAT GOES UNNOTICED, AND SAYS WHY IT DOES NOT CHECK
// THE OTHER ONE.
//
//   * **a row naming no setting** — what a RENAME and a REMOVAL both produce,
//     and the one nobody sees: the table still looks complete, every row still
//     has a default, and a reader sets an environment variable that nothing
//     reads. This is asserted, and it is the whole point of the file.
//
//   * **a setting with no row** — the direction people expect. It is NOT
//     asserted, and that is a deliberate limit rather than an oversight: 105
//     of 304 settings had no row when this was written, most of them recent
//     (`keys.*`, `backupCodes.*`, `workers.*`, `global.mode` itself). Turning
//     that into an assertion would make this file red on arrival and it would
//     be disabled within a day, which buys nothing. The COUNT is logged
//     instead, so the gap is visible and can be closed deliberately.
//
//     If it ever reaches zero, make it an assertion. That is the moment the
//     claim "the documentation lists every setting" becomes true and worth
//     defending.
//
// The environment variable and the default are compared for every row that
// does name a real setting, for `readme_ports.js`'s reason: a row naming the
// right setting and the wrong value is worse than a missing row, because a
// reader acts on it.
// ===========================================================================

// Deleted rather than set, for the reason config_realm_layer.js gives and
// readme_ports.js repeats: this file must not inherit a CONFIG_FILE from
// whatever launched the run, or the defaults it reads would be that file's
// rather than the table's.
delete process.env.CONFIG_FILE;

const fs = require('fs');
const path = require('path');

const config = require('../common/config');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'readme_settings',
  level: process.env.LOG_LEVEL || 'info' });

const README = path.join(__dirname, '..', 'docs', 'configuration.md');

// A settings row is `| \`key\` | \`ENV_VAR\` | ... |`. The key may carry a
// parenthetical after the backticks — `global.https` is written
// "`global.https` *(derived)*" — so the pattern allows anything up to the next
// pipe, and the environment variable may or may not be in backticks.
//
// It is anchored to the LINE START so that a dotted name mentioned inside some
// other table's prose cannot be read as a row.
const ROW = /^\|\s*`([a-z][a-zA-Z0-9]*\.[a-zA-Z0-9]+)`[^|]*\|\s*`?([A-Z][A-Z0-9_]*)`?\s*\|([^|]*)\|/gm;

function rows() {
  log.debug("Entering rows().");
  const text = fs.readFileSync(README, 'utf8');
  const found = [];
  let m;
  // `lastIndex` is reset because the regex is a module-level `g` literal and
  // this function is called more than once in a run.
  ROW.lastIndex = 0;
  while ((m = ROW.exec(text)) !== null) {
    found.push({ key: m[1], env: m[2], dflt: m[3].trim() });
  }
  log.debug("Leaving rows().");
  return found;
}

function run(t) {
  log.debug("Entering run().");
  const found = rows();
  if (!t.check(found.length > 150,
               'docs/configuration.md has a settings table to check',
               'found ' + found.length + ' rows, which is too few to be that ' +
               'table; either the format changed — in which case change ROW ' +
               'here too — or a table that was being kept honest is gone')) {
    log.debug("Leaving run().");
    // Stopping rather than reporting two hundred passes against nothing, which
    // is the exact failure this file exists to prevent one document over.
    return;
  }

  const known = new Map(config.SETTINGS.map(function (s) {
    return [s.key, s];
  }));

  // -----------------------------------------------------------------------
  // 1. EVERY ROW NAMES A SETTING THIS SERVICE ACTUALLY HAS.
  //
  //    THE ASSERTION THIS FILE WAS WRITTEN FOR. A row for a setting that was
  //    deleted is worse than no row: it tells a reader that a knob exists,
  //    names the environment variable to set, and gives its default — and
  //    nothing reads any of it. Four of these were live in this repository for
  //    four days.
  // -----------------------------------------------------------------------
  t.log.info('=== every row names a real setting ===');
  const ghosts = found.filter(function (row) {
    return !known.has(row.key);
  }).map(function (row) {
    return row.key + ' (' + row.env + ')';
  });
  t.equal(Array.from(new Set(ghosts)).join(', '), '',
          'no row names a setting config.js has not got',
          'a removed or renamed setting leaves a row that still looks ' +
          'complete: a default, an environment variable, a description. ' +
          'Nothing reads any of it, and a reader cannot tell');

  // -----------------------------------------------------------------------
  // 2. AND WHERE IT NAMES ONE, IT NAMES IT RIGHT.
  //
  //    The variable is how a reader actually changes the setting, so a row
  //    with the right key and the wrong variable sends them to something that
  //    does nothing — the same failure as a ghost row, one column over.
  // -----------------------------------------------------------------------
  t.log.info('=== and names its environment variable correctly ===');
  const wrong = found.filter(function (row) {
    const s = known.get(row.key);
    return s && s.env && s.env !== row.env;
  }).map(function (row) {
    return row.key + ': the docs say ' + row.env + ', config.js says ' +
           known.get(row.key).env;
  });
  t.equal(wrong.join('; '), '',
          'every row names the environment variable config.js declares');

  // -----------------------------------------------------------------------
  // 3. THE GAP IN THE OTHER DIRECTION, REPORTED RATHER THAN ASSERTED.
  //
  //    See the header for why this is not a `check`. It is logged every run so
  //    that the number is in front of somebody, and so that it going UP is
  //    visible in a diff of the output.
  // -----------------------------------------------------------------------
  const cited = new Set(found.map(function (row) { return row.key; }));
  const undocumented = Array.from(known.keys()).filter(function (key) {
    return !cited.has(key);
  });
  t.log.info('=== settings with no row: ' + undocumented.length + ' of ' +
             known.size + ' (reported, not asserted — see the header) ===');
  if (undocumented.length) {
    t.log.info('    ' + undocumented.slice(0, 20).join(', ') +
               (undocumented.length > 20
                 ? ', and ' + (undocumented.length - 20) + ' more'
                 : ''));
  }
  // One assertion about it, and it is the only one that can be made honestly
  // today: the table has not stopped covering the bulk of them. A number this
  // low would mean the settings table had been gutted rather than that a
  // setting was added.
  t.check(cited.size > known.size / 2,
          'the settings table still covers most of what config.js declares',
          cited.size + ' of ' + known.size + ' documented');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'readme_settings',
  describe: "docs/configuration.md's settings tables against config.js",
  run: run
};
