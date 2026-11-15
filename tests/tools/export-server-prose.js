#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: export-server-prose.js
//
// ---------------------------------------------------------------------------
// THE SERVER'S PROSE SOURCES, FOR `sts-mgmt-api` (#444, phase 5, the
// `apis5` slice; #543's `common/server_prose.ts`).
//
// `/admin-api` translates the prose a view carries when the request names
// a language (`translateView()`, after the answer is built, BY EXACT
// MATCH). The English it matches is already a file —
// `common/prose_locales/<ns>/en.json`, generated from the source and held
// to it by `tests/server_prose_catalogs.js` — and so are the translations
// beside it. What is NOT a file is which kind each namespace is (the
// settings source recognises a described setting by its `key`; every other
// is a phrase source, matched string by string) and the routes a phrase
// source is scoped to (the union of its modules' `PROSE_ROUTES`), and the
// members whose strings are never translated. Those are exported here,
// into `rust/crates/sts-mgmt-api/tables/server_prose.json`, which the Rust
// matcher reads beside the catalogs.
//
// It loads the whole stack, so it runs where TypeScript is compiled: the
// tests image.
//
//   node tests/tools/export-server-prose.js           write the file
//   node tests/tools/export-server-prose.js --check   exit 1 when stale
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'export-server-prose',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..', '..');
const FILE = path.join(ROOT, 'rust', 'crates', 'sts-mgmt-api', 'tables',
                       'server_prose.json');

/**
 * The tables, as the Rust crate reads them.
 *
 * @returns {any} the export
 */
function tables() {
  log.debug("Entering tables().");
  require(path.join(ROOT, 'common', 'protocol_stack'));
  const prose = require(path.join(ROOT, 'common', 'server_prose'));
  const common = path.join(ROOT, 'common');
  const namespaces = {};
  prose.namespaces().forEach(function (ns) {
    const modules = prose.PHRASE_MODULES[ns];
    if (!modules) {
      namespaces[ns] = { kind: 'settings' };
      return;
    }
    const routes = [];
    modules.forEach(function (entry) {
      const spec = typeof entry === 'string'
        ? { path: entry, routes: 'PROSE_ROUTES' } : entry;
      const mod = require(path.resolve(common, spec.path));
      (mod[spec.routes] || []).forEach(function (route) {
        routes.push(route);
      });
    });
    namespaces[ns] = { kind: 'phrases', routes: routes };
  });
  log.debug("Leaving tables().");
  return { source: prose.SOURCE, separator: prose.SEP,
           never: prose.NEVER_TRANSLATED.slice(0), namespaces: namespaces };
}

/**
 * The text the file should hold.
 *
 * @returns {string} the text
 */
function rendered() {
  log.debug("Entering rendered().");
  const text = JSON.stringify(tables(), null, 1) + '\n';
  log.debug("Leaving rendered().");
  return text;
}

if (require.main === module) {
  const text = rendered();
  if (process.argv.indexOf('--check') >= 0) {
    let current = null;
    try {
      current = fs.readFileSync(FILE, 'utf8');
    } catch (e) {
      log.debug("Caught in export-server-prose.js: " +
                ((e && e.message) || e));
      current = null;
    }
    if (current !== text) {
      console.error('stale: ' + path.relative(ROOT, FILE) +
                    ' — run node tests/tools/export-server-prose.js');
      process.exit(1);
    }
    console.log('the server prose tables are current');
    process.exit(0);
  }
  const out = process.argv[2] || FILE;
  fs.mkdirSync(path.dirname(out), { recursive: true });
  fs.writeFileSync(out, text);
  console.log('wrote ' + out);
  process.exit(0);
}

module.exports = { tables: tables, rendered: rendered };
