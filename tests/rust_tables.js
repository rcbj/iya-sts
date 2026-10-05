// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: rust_tables.js
//
// ---------------------------------------------------------------------------
// THE RUST CRATES' COPY OF THIS SERVICE'S TABLES IS THE TABLES (#444).
//
// `sts-core` builds its error codes, its settings and its mode from
// `rust/crates/sts-core/tables/`, JSON exports of `common/error_codes.js`,
// `common/config.js`'s SETTINGS and `common/mode.js`'s predicate names and
// tables, which `tests/tools/export-rust-tables.js` writes. The JavaScript is the one that is edited until the cutover, so the
// export is a second copy, and a second copy is a chance to drift: a code
// added to the table and not exported would be one the Rust runtime cannot
// name, and a summary changed on one side would document two things. This
// regenerates every export in memory and fails on any difference.
// ---------------------------------------------------------------------------

const bunyan = require('bunyan');
const exporter = require('./tools/export-rust-tables.js');

const log = bunyan.createLogger({ name: 'rust_tables',
  level: process.env.STS_LOG_LEVEL || 'info' });

/**
 * @param {any} t - the runner's check collector
 */
function run(t) {
  log.debug("Entering run().");
  const exports = exporter.rendered();
  t.check(exports.length > 0, 'there is at least one Rust table export',
          String(exports.length));
  const stale = exporter.stale();
  t.check(stale.length === 0,
          'every Rust table export matches the table it was written from',
          stale.join(', ') + ' — run node tests/tools/export-rust-tables.js');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'rust_tables',
  describe: 'the Rust crates\' JSON exports of the error-code, settings ' +
            'and mode tables are current',
  run: run
};
