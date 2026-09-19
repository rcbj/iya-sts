'use strict';
//
// File: realm_support.js
//
// ===========================================================================
// THE TRUST REALMS TABLE ANSWERS FOR EVERY PROTOCOL FAMILY.
//
// `/admin/realms` draws *What is separated, and what is shared* out of
// `realms.realmSupport()`, and `GET /realms` answers the same rows. The page
// says the table is the whole list. On 2026-09-18 it was short by ten — GNAP,
// Shared Signals, XACML, federation, the certificate authority, ACME, EST,
// SCEP, the portal and logout — and nothing anywhere said so, because a
// hand-written list of families has nothing to be compared with unless
// somebody compares it.
//
// The list it is compared with is `sts_metadata.ts`'s PROTOCOLS, which is
// already held to the router (`tests/vendored/sts_metadata.js`) and to
// `/admin/crypto-metadata` (`tests/vendored/admin_api.js`). Each realm row
// names the cards it answers for in `cards`, and this file checks:
//
//   A. every PROTOCOLS card is named by exactly ONE row — none missing, which
//      is how a new family is caught, and none twice, which would be two
//      answers to one question;
//   B. every name in `cards` is a card — the direction a RENAME breaks;
//   C. the rows are well formed: a unique family, a state the page can draw,
//      and a discriminator on every row that is separated.
//
// WHY IN A CHILD: PROTOCOLS is in `sts_metadata.ts`, which requires the
// console and the app, and a stack loaded into the runner would be shared
// with every file after this one — `protocol_endpoints.js`'s arrangement.
// ===========================================================================

const path = require('path');
const os = require('os');
const fs = require('fs');
const childProcess = require('child_process');
const log = require('bunyan').createLogger({ name: 'realm_support',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// The states `admin.ts`'s realmSupportTable() knows how to draw.
const STATES = ['full', 'partial', 'none'];

// ---------------------------------------------------------------------------
// The child. Everything it needs is required inside, so the function can be
// shipped as source with `node -e`. It reports the two tables and nothing
// else; every judgement is made in the parent, where it is reported.
// ---------------------------------------------------------------------------
function childMain() {
  /* eslint-disable no-console */
  const fs = require('fs');
  const ROOT_DIR = process.env.RS_ROOT;
  const OUT = process.env.RS_OUT;
  const report = { error: null, protocols: null, support: null };
  try {
    const realms = require(ROOT_DIR + '/common/realms');
    const metadata = require(ROOT_DIR + '/sts_metadata');
    report.protocols = metadata.PROTOCOLS.map(function (p) {
      return { name: p.name, notAProtocol: !!p.notAProtocol };
    });
    report.support = realms.realmSupport();
  } catch (e) {
    // Carried on the report: the parent says what went wrong.
    report.error = String((e && e.stack) || e);
  }
  fs.writeFileSync(OUT, JSON.stringify(report));
  process.exit(0);
}

function loadTables() {
  log.debug("Entering loadTables().");
  const out = path.join(os.tmpdir(), 'rs-' + process.pid + '-' +
                        Math.random().toString(36).slice(2) + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', STS_LOG_LEVEL: 'fatal',
                                  RS_ROOT: ROOT, RS_OUT: out }),
      encoding: 'utf8', timeout: 180000, cwd: ROOT
    });
  let report = null;
  try {
    report = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in loadTables(): " + ((e && e.message) || e));
    // No report: the child died before writing one; the caller says so.
    report = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written, which the read above has already reported.
    log.debug("Caught in loadTables(): " + ((e && e.message) || e));
  }
  log.debug("Leaving loadTables().");
  return { report: report, result: result };
}

function run(t) {
  log.debug("Entering run().");
  const loaded = loadTables();
  const report = loaded.report;
  if (!t.check(!!report && !report.error &&
               Array.isArray(report.protocols) &&
               Array.isArray(report.support),
               'the child loaded PROTOCOLS and realmSupport()',
               report && report.error ? report.error.slice(0, 800) :
               'exit ' + loaded.result.status + ' ' +
               String(loaded.result.stderr || '').slice(-800))) {
    log.debug("Leaving run().");
    // Every assertion below reads both tables.
    return;
  }
  const cardNames = report.protocols.map(function (p) {
    return p.name;
  });
  const rows = report.support;

  // -----------------------------------------------------------------------
  // C. THE ROWS ARE WELL FORMED. First, because A and B read `cards`.
  // -----------------------------------------------------------------------
  t.log.info('=== every row is one the page can draw ===');
  const families = {};
  rows.forEach(function (row) {
    const name = String(row.family || '(no family)');
    t.check(!families[name], name + ' is the only row of that name',
            'two rows answering one family is two answers to one question');
    families[name] = true;
    t.check(STATES.indexOf(row.state) >= 0,
            name + ' has a state the page draws (' + row.state + ')',
            'realmSupportTable() knows ' + STATES.join(', '));
    t.check(typeof row.by === 'string' && row.by.length > 0,
            name + ' says what tells one realm from another',
            'the Separated column prints it');
    t.check(typeof row.note === 'string' && row.note.length > 0,
            name + ' says what that means', 'the third column is the note');
    t.check(Array.isArray(row.cards),
            name + ' names the PROTOCOLS cards it answers for',
            'an empty list is allowed for a row that is not a protocol ' +
            'family; a missing one is a row nobody decided about');
  });

  // -----------------------------------------------------------------------
  // A. EVERY CARD HAS EXACTLY ONE ROW. The direction a new family breaks.
  // -----------------------------------------------------------------------
  t.log.info('=== every PROTOCOLS card is answered by exactly one row ===');
  const claimedBy = {};
  rows.forEach(function (row) {
    (Array.isArray(row.cards) ? row.cards : []).forEach(function (card) {
      (claimedBy[card] = claimedBy[card] || []).push(row.family);
    });
  });
  cardNames.forEach(function (card) {
    const by = claimedBy[card] || [];
    t.check(by.length === 1,
            'the ' + card + ' card has one row on /admin/realms',
            by.length === 0 ?
              'a protocol family with no row in realms.realmSupport(): add ' +
              'one saying whether a realm separates it and how, and name ' +
              'this card in its `cards`' :
              'named by ' + by.join(' and '));
  });

  // -----------------------------------------------------------------------
  // B. EVERY NAME IS A CARD. The direction a rename breaks: a row still
  //    naming the old card passes A only because the new card is reported
  //    missing, which is the wrong half of what happened.
  // -----------------------------------------------------------------------
  t.log.info('=== and every card a row names exists ===');
  const unknown = Object.keys(claimedBy).filter(function (card) {
    return cardNames.indexOf(card) < 0;
  });
  t.equal(unknown.join(', '), '',
          'every name in a row\'s `cards` is a card in sts_metadata.ts\'s ' +
          'PROTOCOLS');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'realm_support',
  describe: 'the Trust realms table on /admin/realms answers for every ' +
            'protocol family sts_metadata.ts lists, and names no other',
  run: run
};
