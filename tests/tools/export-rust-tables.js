#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: export-rust-tables.js
//
// ---------------------------------------------------------------------------
// THE RUST RUNTIME'S COPY OF THIS SERVICE'S TABLES (#444, rust/DESIGN.md
// section 4.4), WRITTEN FROM THE ONE TABLE AND NEVER BY HAND.
//
// Until the cutover the Node service runs, so its tables stay the ones that
// are edited — `common/error_codes.js` above all. The Rust crates read a JSON
// export of each, which `sts-core`'s `build.rs` turns into code (a constant
// per error code, so a code missing from the table does not compile). Two
// copies are a chance to drift, so `tests/rust_tables.js` regenerates the
// export in memory and fails when the committed file differs: edit the table,
// run this, commit both.
//
//   node tests/tools/export-rust-tables.js           write the files
//   node tests/tools/export-rust-tables.js --check   exit 1 when stale
//
// At the cutover the direction reverses: the JSON becomes the table and the
// JavaScript is deleted.
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..', '..');
const DATA = path.join(ROOT, 'rust', 'crates', 'sts-core', 'tables');

// Each export: the file it writes and the document it holds. Key order is
// the table's, so a diff of the export reads like a diff of the table.
function errorCodes() {
  const table = require(path.join(ROOT, 'common', 'error_codes.js'));
  return {
    subsystems: table.SUBSYSTEMS.map(function (one) {
      return { id: one.id, label: one.label, where: one.where || '',
               what: one.what || '' };
    }),
    codes: table.CODES.map(function (one) {
      const row = { code: one.code, summary: one.summary,
                    spec: one.spec || '' };
      if (one.retired) {
        row.retired = true;
      }
      return row;
    })
  };
}

const EXPORTS = [
  { file: 'error_codes.json', build: errorCodes }
];

// The text each export should hold.
function rendered() {
  return EXPORTS.map(function (one) {
    return { file: path.join(DATA, one.file),
             text: JSON.stringify(one.build(), null, 1) + '\n' };
  });
}

// The exports whose committed file differs from what the table says.
function stale() {
  return rendered().filter(function (one) {
    let current = null;
    try {
      current = fs.readFileSync(one.file, 'utf8');
    } catch (error) {
      // A missing export is a stale one; the caller names the file.
      current = null;
    }
    return current !== one.text;
  }).map(function (one) {
    return path.relative(ROOT, one.file);
  });
}

if (require.main === module) {
  if (process.argv.indexOf('--check') >= 0) {
    const out = stale();
    if (out.length) {
      console.error('stale: ' + out.join(', ') +
                    ' — run node tests/tools/export-rust-tables.js');
      process.exit(1);
    }
    console.log('the Rust tables are current');
  } else {
    fs.mkdirSync(DATA, { recursive: true });
    rendered().forEach(function (one) {
      fs.writeFileSync(one.file, one.text);
      console.log('wrote ' + path.relative(ROOT, one.file));
    });
  }
}

module.exports = { stale: stale, rendered: rendered };
