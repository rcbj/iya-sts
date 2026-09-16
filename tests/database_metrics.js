'use strict';
//
// File: database_metrics.js
//
// ===========================================================================
// THE DATABASE REPORT'S CONTRACTS (2026-09-11), AND NOT ITS NUMBERS.
//
// **NOTHING IN THIS FILE CONNECTS TO A DATABASE**, which is the whole of why
// it is in process and cheap. `npm test` has no PostgreSQL and must not need
// one; what it can assert is everything about `/admin/database` that is
// decided by this repository rather than by a server:
//
//   * **THE PROBE TABLE AND THE PAGE'S SECTIONS AGREE.** Every probe names a
//     group and the page draws a section per group — and a probe whose group
//     has no section is COLLECTED ON EVERY RENDER AND SHOWN TO NOBODY, while
//     a section with no probe is an empty heading that reads as a broken
//     feature. Neither is an error anywhere. This is `pki_authoring.js`'s
//     field-table argument, one layer out, and it is the reason both lists
//     are exported.
//   * **EVERY STATEMENT IS A READ, AND A LITERAL.** The role this service
//     dials with can INSERT, UPDATE and DELETE on every table in its schema
//     (`postgres/schema.sql`), so the one thing this page could get
//     catastrophically wrong is sending it something else. Asserted against
//     the SQL rather than trusted: no probe may contain a write verb, and none
//     may be built by concatenation from anything but constants.
//   * **THE THREE "NO DATABASE" ANSWERS ARE DIFFERENT SENTENCES.** The
//     commonest state of this page by a wide margin is that there is nothing
//     to report, and *not configured*, *configured and not open* and *open
//     with no metrics function* are three different things to do something
//     about.
//
// **WHAT IS DELIBERATELY NOT HERE**: whether the queries are VALID SQL and
// whether a given server answers them. No in-process test can know that —
// they are PostgreSQL's grammar and PostgreSQL's catalog — and pretending
// otherwise is how a test comes to assert a stale column list. They were run
// against PostgreSQL 18 and 16 by hand when they were written, and the
// over-HTTP half is `tests/vendored/sts_database_metrics.js`, which drives
// them against the stack's real database.
// ===========================================================================

// Deleted rather than set, for the reason `config_realm_layer.js` gives.
delete process.env.CONFIG_FILE;

// ---------------------------------------------------------------------------
// AND THE STORE'S OWN VARIABLES WITH IT (2026-09-12), FOR THE SAME REASON ONE
// LAYER DOWN.
//
// Section E asserts the three sentences this page gives when there is NO
// DATABASE, and it reaches that state by starting no store — which was the
// whole of it for as long as this file was only ever run by `npm test`.
// `./local-run-tests.sh` runs the suite once per mode and exports each mode's
// environment into the runner, which hands `process.env` to every in-process
// job: so in the `postgres` and `dispatch` modes this file read
// `persistence.mode` as `postgres` while having opened nothing, asserted
// `memory`, and failed twice — in two modes, about a page that was correct,
// naming a mismatch that is this line's absence and not a defect anywhere.
//
// **DELETED RATHER THAN SET, AND THAT IS THE SAME ARGUMENT AS THE LINE ABOVE**:
// the state this file wants is the DEFAULT, so it removes what is overriding
// the default rather than writing the default back over it — which would be a
// second place stating what `env/defaults.js` already says.
// ---------------------------------------------------------------------------
delete process.env.STS_PERSISTENCE_MODE;
delete process.env.STS_DATABASE_URL;

const postgres = require('../persistence/persistence_postgres');
const persistence = require('../persistence/persistence');
const database = require('../admin-ui/database_admin');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'database_metrics',
  level: process.env.LOG_LEVEL || 'info' });

// The verbs a probe may never contain. **MATCHED AS WHOLE WORDS**, because
// `UPDATE` is a substring of `pg_stat_user_tables`'s `n_tup_upd` and of
// `last_autoanalyze`'s neighbours — a naive `indexOf` fails on the very
// columns this page exists to draw, which is how a check like this comes to
// be deleted for being wrong rather than fixed.
const FORBIDDEN = ['INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 'ALTER',
                   'TRUNCATE', 'GRANT', 'REVOKE', 'COPY', 'CALL', 'DO'];

async function run(t) {
  log.debug("Entering run().");
  t.log.info('=== A. every probe is a READ, and a literal ===');

  const probes = postgres.METRIC_PROBES;
  t.check(probes.length >= 15,
          'the probe table is published, and it is the page\'s only source ' +
          'of SQL', probes.length + ' probe(s)');

  probes.forEach(function (probe) {
    t.check(/^\s*SELECT\b/i.test(probe.sql),
            'the "' + probe.id + '" probe begins with SELECT');
    const upper = probe.sql.toUpperCase();
    const found = FORBIDDEN.filter(function (verb) {
      return new RegExp('\\b' + verb + '\\b').test(upper);
    });
    t.equal(found.join(','), '',
            'and the "' + probe.id + '" probe contains no write verb. The ' +
            'role this service dials with can INSERT, UPDATE and DELETE on ' +
            'six tables, so this is the one thing this page could get ' +
            'catastrophically wrong');
    t.check(probe.sql.indexOf(';') < 0,
            'and carries no statement separator, so it cannot be two ' +
            'statements wearing the shape of one — which is what makes ' +
            '"every statement is a literal" checkable rather than a claim ' +
            'about how it was written');
    t.check(probe.sql.indexOf('$') < 0,
            'and takes no parameter, because nothing a request carries ' +
            'reaches any of this: the statements are constants and the only ' +
            'thing that varies is which of them ran');
  });

  t.log.info('=== B. the probe table and the page\'s sections agree ===');

  const sections = database.sections();
  const sectionGroups = sections.map(function (one) { return one.group; });
  const probeGroups = probes.map(function (one) { return one.group; });

  probes.forEach(function (probe) {
    t.check(sectionGroups.indexOf(probe.group) >= 0,
            'the "' + probe.id + '" probe is in a group the page has a ' +
            'section for. A probe in a group with no section is run on every ' +
            'render, costs a round trip, and is shown to nobody — and that ' +
            'is an error NOWHERE: the page renders perfectly without it',
            probe.group);
  });
  sections.forEach(function (section) {
    t.check(probeGroups.indexOf(section.group) >= 0,
            'the "' + section.group + '" section has at least one probe. An ' +
            'empty heading reads as a feature that broke rather than as one ' +
            'that was never there');
    t.check(String(section.heading).length > 3 &&
            String(section.blurb).length > 40,
            'and it says what it is, which is this console\'s standing rule ' +
            'about a page explaining itself');
  });

  const ids = probes.map(function (one) { return one.id; });
  t.equal(ids.length, new Set(ids).size,
          'no probe id appears twice — the report is keyed by id, so a ' +
          'duplicate would silently be one probe overwriting another\'s ' +
          'result rather than two rows');

  probes.forEach(function (probe) {
    t.check(probe.shape === 'row' || probe.shape === 'rows',
            'the "' + probe.id + '" probe declares a shape the renderer ' +
            'knows', probe.shape);
    t.check(String(probe.what).length > 20,
            'and says what it would show, which the page prints under it and ' +
            'the failure table prints INSTEAD of it when it could not be ' +
            'collected — so a reader of a refusal learns what they are ' +
            'missing');
  });

  t.log.info('=== C. "pull everything available" is a property of the SQL ===');

  // **THE CLAIM THAT MAKES THIS PAGE SURVIVE A MAJOR VERSION**, asserted
  // rather than left in a comment: the statistics views are asked for ALL
  // their columns. Measured when this was written: `pg_stat_bgwriter` has
  // eleven columns on PostgreSQL 16 and four on 18, `pg_stat_wal` nine and
  // five, `pg_stat_database` twenty-eight and thirty. A probe naming its
  // columns would be wrong on every server but the one somebody tested.
  const statViews = probes.filter(function (probe) {
    return /FROM\s+pg_stat/i.test(probe.sql);
  });
  t.check(statViews.length >= 5,
          'several probes read pg_stat_* views', statViews.length + ' of them');
  const wholeRow = statViews.filter(function (probe) {
    return /SELECT\s+\*/i.test(probe.sql);
  });
  t.check(wholeRow.length >= 5,
          'and the ones whose SHAPE is the server\'s ask for every column. ' +
          'That is what lets the page be right on a version nobody tested it ' +
          'against — and the alternative fails SILENTLY, because a column ' +
          'this build named and that server does not have reads as a blank ' +
          'cell rather than as an error',
          wholeRow.map(function (one) { return one.id; }).join(', '));

  // The three that deliberately name columns do it because they COMPOSE —
  // they join, they cast, they filter — and a `SELECT *` there would be a
  // different answer rather than more of the same one.
  const composed = statViews.filter(function (probe) {
    return !/SELECT\s+\*/i.test(probe.sql);
  });
  composed.forEach(function (probe) {
    t.check(/JOIN|count\(|CASE|FILTER|date_trunc/i.test(probe.sql),
            'the "' + probe.id + '" probe names its columns because it ' +
            'COMPOSES rather than reports — a SELECT * there would be a ' +
            'different question, not a wider answer');
  });

  t.log.info('=== D. the version-gated probes say so ===');

  const gated = probes.filter(function (one) { return one.expected; });
  t.check(gated.length >= 2,
          'some probes are marked with the PostgreSQL version they arrived ' +
          'in', gated.map(function (one) {
            return one.id + '>=' + one.expected;
          }).join(', '));
  gated.forEach(function (probe) {
    t.check(Number(probe.expected) >= 10 && Number(probe.expected) < 100,
            'and "' + probe.id + '" names a major version rather than a ' +
            'version string');
  });
  // **THE MARKER IS NOT A GUARD, AND THAT IS THE DECISION IT RECORDS.**
  // Nothing asks the server its version and then decides whether to run
  // these — that would be two round trips and a second thing to get wrong.
  // They are run, and a `42P01` is reported as the ordinary answer it is.
  t.check(!probes.some(function (one) {
            return /server_version_num.*>=|current_setting.*>=/i.test(one.sql);
          }),
          'and NO probe guards itself on the server version. Asking whether ' +
          'the server is at least 17 and then asking for the view is two ' +
          'round trips; asking for the view and reporting "does not exist" ' +
          'is one, and says the same thing more honestly');

  t.log.info('=== E. with no database, three different sentences ===');

  // `persistence.mode` is `memory` here — this file sets no CONFIG_FILE and
  // starts no store — which is the state of every `npm test` run and of most
  // deployments.
  const report = await persistence.databaseMetrics();
  t.check(!report.available,
          'with no database configured there are no metrics');
  t.equal(report.mode, 'memory',
          'and the report names the mode rather than reporting an absence');
  t.check(/memory/.test(report.why) && /ldif/.test(report.why),
          'and the sentence says what BOTH storeless modes are, because a ' +
          'reader who has one of them wants to know which it is',
          report.why);
  t.check(/restart-only/.test(report.why) ||
          /before the listener/.test(report.why),
          'and that switching to postgres needs a restart — which it does, ' +
          'and a reader who changed the setting and reloaded this page ' +
          'would otherwise conclude the page was broken');

  const view = await database.databaseView();
  t.check(!view.available && String(view.why).length > 40,
          'and the PAGE carries the same sentence rather than drawing empty ' +
          'tables, which is rule 7 read at the level of a refusal: the ' +
          'console and /admin-api/database answer out of one function');
  t.check(view.probes === undefined,
          'and there is no probes member at all, so a client cannot read an ' +
          'empty object as "everything is zero"');

  t.log.info('=== F. nothing in the report is a credential ===');

  // The one thing this page must never print. `describeDatabase()` parses the
  // connection string rather than regexing it, so a password containing an
  // '@' cannot fool it into reporting half of itself — and this asserts the
  // CONSUMER's side of that: whatever it answers, no member of the report is
  // the URL.
  const serialised = JSON.stringify(view);
  t.check(serialised.indexOf('password') < 0,
          'no member of the report is named or contains a password');
  t.check(serialised.indexOf('postgres://') < 0,
          'and no connection string is in it. The target is reported as ' +
          'host, port, database and user — four fields — and never as the ' +
          'string they were parsed out of');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'database_metrics',
  describe: 'The /admin/database contracts that do not need a database: ' +
            'every probe is a SELECT with no write verb, no statement ' +
            'separator and no parameter; the probe table and the page\'s ' +
            'sections agree in both directions; the statistics views are ' +
            'asked for ALL their columns, which is what makes the page right ' +
            'on a major version nobody tested it against; the version-gated ' +
            'probes are marked and deliberately not guarded; and with no ' +
            'database the answer is a sentence rather than empty tables',
  run: run
};
