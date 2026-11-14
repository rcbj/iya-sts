// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: openapi_pages.js
//
// ---------------------------------------------------------------------------
// docs/openapi/ IS EXACTLY WHAT THE DOCUMENTS PRODUCE (rcbj, 2026-11-06), the
// rule `docs/error-codes.md` has for its table: a second copy of 833 operations
// is otherwise wrong within a week. tests/tools/openapi_pages.js writes them.
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');

const log = require('bunyan').createLogger({
  name: 'openapi_pages', level: process.env.LOG_LEVEL || 'info' });

const { documents } = require('./openapi_response_models');
const { pagesOf, APIS } = require('./tools/openapi_pages');

const DIR = path.join(__dirname, '..', 'docs', 'openapi');
const FIX = 'run tests/tools/regenerate-openapi-pages.sh';

function run(t) {
  log.debug("Entering run().");
  const pages = pagesOf(documents());
  const held = fs.readdirSync(DIR).filter(function (name) {
    return /\.md$/.test(name);
  });
  const names = Object.keys(pages);
  t.equal(held.slice().sort().join(' '), names.slice().sort().join(' '),
          'the same pages are committed: ' + FIX);
  const stale = names.filter(function (name) {
    return held.indexOf(name) < 0 ||
      fs.readFileSync(path.join(DIR, name), 'utf8') !== pages[name];
  });
  t.equal(stale.join(' '), '', 'each page is what its document produces: ' + FIX);
  APIS.forEach(function (api) {
    t.check(!!pages[api.file + '.md'], api.title + ' has a page');
  });
  const all = names.map(function (name) {
    return pages[name];
  }).join('\n');
  t.check(all.indexOf('{% endraw %}\n---') < 0 && !/\{%(?! raw| endraw)/.test(all),
          'no text a Jekyll build would read as Liquid');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'openapi_pages',
  describe: 'docs/openapi/ is exactly what the OpenAPI documents produce',
  run: run
};
