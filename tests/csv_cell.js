// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: csv_cell.js
//
// ===========================================================================
// ONE CSV CELL, SAFE TO OPEN IN A SPREADSHEET (#2138, ASVS 5.0.0 1.2.10).
//
// `common/csv_cell.ts` is the one helper every CSV this service writes goes
// through. Asserted here:
//
//   A. THE TABLE: each cell OWASP's CSV injection guidance names (a first
//      `=`, `+`, `-`, `@`, tab, CR or NUL) gets a single quote in front, and
//      RFC 4180 quoting still applies after it; ordinary cells, nulls and
//      booleans are as before.
//   B. A JAVASCRIPT NUMBER IS LEFT ALONE, negative or not (and a bigint);
//      the STRING "-5" is prefixed.
//   C. THE REPORT'S CSV goes through it: `Formats.csv()` neutralises a
//      formula in a value and leaves a negative number a number.
//
// The passkey report's export is asserted in tests/passkey_report.js (H3a).
// ===========================================================================

const CsvCell = require('../common/csv_cell');
const Formats = require('../report/formats');

const log = require('bunyan').createLogger({ name: 'csv_cell',
  level: process.env.LOG_LEVEL || 'info' });

// [value, the cell expected, what it is]
const TABLE = [
  ['plain', 'plain', 'an ordinary string'],
  ['', '', 'the empty string'],
  [null, '', 'null is the empty cell'],
  [undefined, '', 'undefined is the empty cell'],
  [true, 'true', 'a boolean'],
  ['a,b', '"a,b"', 'a comma is quoted'],
  ['say "hi"', '"say ""hi"""', 'a quotation mark is doubled'],
  ['a\nb', '"a\nb"', 'a line feed is quoted'],
  ['=1+1', '\'=1+1', 'a leading = is prefixed'],
  ['+1', '\'+1', 'a leading + is prefixed'],
  ['-1', '\'-1', 'a leading - in a STRING is prefixed'],
  ['@SUM(A1)', '\'@SUM(A1)', 'a leading @ is prefixed'],
  ['\t=1', '\'\t=1', 'a leading tab is prefixed'],
  ['\r=1', '"\'\r=1"', 'a leading CR is prefixed, then quoted'],
  ['\0=1', '\'\0=1', 'a leading NUL is prefixed'],
  ['=HYPERLINK("http://x","y")', '"\'=HYPERLINK(""http://x"",""y"")"',
   'a prefixed formula holding quotes and a comma is quoted after'],
  ['a=1', 'a=1', 'an = not first is left alone'],
  [' =1', ' =1', 'a leading space is not a formula lead'],
  [-5, '-5', 'a negative NUMBER is left alone'],
  [5, '5', 'a number'],
  [-1.5, '-1.5', 'a negative fraction is left alone'],
  [BigInt(-7), '-7', 'a negative bigint is left alone']
];

function table(t) {
  log.debug("Entering table().");
  t.log.info('=== A, B. the table of cells ===');
  for (let i = 0; i < TABLE.length; i++) {
    const row = TABLE[i];
    t.equal(CsvCell.of(row[0]), row[1],
            'A' + (i + 1) + '. ' + row[2]);
  }
  log.debug("Leaving table().");
}

function report(t) {
  log.debug("Entering report().");
  t.log.info('=== C. the report\'s CSV ===');
  const plan = { source: 'users', fields: ['name', 'delta'], locale: null };
  const body = Formats.csv(plan, [{ name: '=cmd|"/c calc"!A1', delta: -3 },
                                  { name: '-2', delta: 4 }]).toString('utf8');
  const lines = body.split('\r\n');
  t.equal(lines[0], 'name,delta', 'C1. the header');
  t.equal(lines[1], '"\'=cmd|""/c calc""!A1",-3',
          'C2. a formula is neutralised, a negative number is not');
  t.equal(lines[2], '\'-2,4', 'C3. the string "-2" is prefixed');
  const pieces = Array.from(Formats.csvParts(plan,
    [{ name: '@x', delta: 0 }])).join('');
  t.equal(pieces, 'name,delta\r\n\'@x,0\r\n',
          'C4. the streamed pieces go through the same helper');
  log.debug("Leaving report().");
}

async function run(t) {
  log.debug("Entering run().");
  table(t);
  report(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'csv_cell',
  describe: 'a CSV cell a spreadsheet would read as a formula gets a single ' +
    'quote in front, a number does not, and both CSV writers use it (#2138)',
  run: run
};
