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

// The settings table (`common/config.js`'s SETTINGS) and the keys it
// refuses by name because they were replaced (REPLACED_SETTINGS). A row is
// data except for the four `derived` defaults, which are FUNCTIONS of other
// settings: those export `dflt: null` and `derivedDefault: true`, and
// `sts-core::settings` computes them in Rust (a function cannot be data).
// Loading config.js needs its npm dependencies, so this export runs where
// they are installed — the tests image, or a checkout after `npm install`.
function settings() {
  const config = require(path.join(ROOT, 'common', 'config.js'));
  return {
    settings: config.SETTINGS.map(function (row) {
      const out = {};
      Object.keys(row).forEach(function (key) {
        if (typeof row[key] === 'function') {
          out[key] = null;
          if (key === 'dflt') {
            out.derivedDefault = true;
          }
          return;
        }
        out[key] = row[key];
      });
      return out;
    }),
    replaced: config.REPLACED_SETTINGS
  };
}

// The mode (`common/mode.js`): the names of its predicates — each is a
// method of `sts-core::mode::Mode`, and a Rust test fails on a name it does
// not answer — the sentence each one's write refusal ends with, and the two
// tables `/admin/mode` draws, REQUIREMENTS and NOT_YET.
const MODE_HELPERS = ['current', 'isProduct', 'isDevelopment', 'allowsValue',
                      'valueInForce', 'inForce', 'writeRefusalReason',
                      'report'];

function modeTable() {
  const mode = require(path.join(ROOT, 'common', 'mode.js'));
  const predicates = Object.keys(mode).filter(function (name) {
    return typeof mode[name] === 'function' &&
      MODE_HELPERS.indexOf(name) < 0;
  });
  const fallback = mode.writeRefusalReason('');
  const writeRefusals = {};
  predicates.forEach(function (name) {
    const reason = mode.writeRefusalReason(name);
    if (reason !== fallback) {
      writeRefusals[name] = reason;
    }
  });
  return {
    predicates: predicates,
    writeRefusalFallback: fallback,
    writeRefusals: writeRefusals,
    requirements: mode.REQUIREMENTS,
    notYet: mode.NOT_YET
  };
}

const EXPORTS = [
  { file: 'error_codes.json', build: errorCodes },
  { file: 'settings.json', build: settings },
  { file: 'mode.json', build: modeTable }
];

// THE APPCONFIG LAYERS (#444, rust/DESIGN.md section 8): `env/*.js` are data,
// and the Rust runtime reads them as `env/*.json`, which are exported here
// beside the tables and checked the same way. `defaults.js` is not among
// them: it is the settings table's `dflt` column, which the runtime compiles
// in from settings.json.
const APPCONFIG = ['local', 'test', 'docker-tests'];

function appconfig(name) {
  return function () {
    const file = path.join(ROOT, 'env', name + '.js');
    delete require.cache[require.resolve(file)];
    return require(file);
  };
}

// The text each export should hold.
function rendered() {
  return EXPORTS.map(function (one) {
    return { file: path.join(DATA, one.file),
             text: JSON.stringify(one.build(), null, 1) + '\n' };
  }).concat(APPCONFIG.map(function (name) {
    return { file: path.join(ROOT, 'env', name + '.json'),
             text: JSON.stringify(appconfig(name)(), null, 2) + '\n' };
  }));
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
    // A file under env/ is written only where its directory exists.
    rendered().forEach(function (one) {
      fs.writeFileSync(one.file, one.text);
      console.log('wrote ' + path.relative(ROOT, one.file));
    });
  }
}

module.exports = { stale: stale, rendered: rendered };
