// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: csp_through_the_helper.js
//
// ---------------------------------------------------------------------------
// NO LITERAL POLICY THAT `app.js` WOULD THROW AWAY (#1337).
//
// `app.js` replaces a Content-Security-Policy with no `frame-ancestors` as the
// response is sent (root CLAUDE.md), and says nothing. So a route that writes
// its policy by hand and forgets that clause keeps working and loses what it
// asked for: the sign-in logo's `sandbox` was gone for its whole life, under a
// test that passed over a mock response.
//
//   A. The scanner itself refuses the logo's old line and takes the helper's,
//      so a scanner that stopped matching fails here rather than passing.
//   B. Nothing in the service sets a literal policy lacking the clause.
//
// It reads a STATEMENT, not a line (root CLAUDE.md, code style). It sees a
// literal at the call: a policy held in a variable is not read, and the
// protocol jobs that fetch a route are what hold that.
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');

const log = require('bunyan').createLogger({ name: 'csp_through_the_helper',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

const SKIP = ['node_modules', 'tests', 'docs', 'node-ldapjs', 'rust', 'embedded',
              'types', '.git', '.claude', 'deploy', 'apidocs'];

// The header's name, then a value that opens with a quote: a literal.
const LITERAL = /['"]Content-Security-Policy['"]\s*,\s*["'`]/gi;

/**
 * Finds the literal policies in one file that lack `frame-ancestors`.
 *
 * @param text - the source
 * @returns the statements refused
 */
function refusedIn(text) {
  log.debug('Entering refusedIn().');
  const out = [];
  let found = LITERAL.exec(text);
  while (found) {
    const end = text.indexOf(';\n', found.index);
    const statement = text.slice(found.index, end < 0 ? text.length : end);
    if (statement.indexOf('frame-ancestors') < 0) {
      out.push(statement.replace(/\s+/g, ' ').slice(0, 120));
    }
    found = LITERAL.exec(text);
  }
  log.debug('Leaving refusedIn(). ' + out.length);
  return out;
}

function sources(dir, into) {
  log.debug('Entering sources().');
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  const names = entries.map(function (one) { return one.name; });
  entries.forEach(function (one) {
    const full = path.join(dir, one.name);
    if (one.isDirectory()) {
      if (SKIP.indexOf(one.name) < 0) {
        sources(full, into);
      }
    } else if (/\.ts$/.test(one.name) && !/\.d\.ts$/.test(one.name)) {
      into.push(full);
    } else if (/\.js$/.test(one.name) &&
               !/(\.bundle|-spa)\.js$/.test(one.name) &&
               names.indexOf(one.name.replace(/\.js$/, '.ts')) < 0) {
      into.push(full);
    }
  });
  log.debug('Leaving sources().');
  return into;
}

function run(t) {
  log.debug('Entering run().');
  t.equal(refusedIn(
    ".set('Content-Security-Policy', \"default-src 'none'; sandbox\")\n" +
    "  .set('Cache-Control', 'no-cache');\n").length, 1,
          'A1. the logo\'s old line is refused');
  t.equal(refusedIn(
    "res.set('Content-Security-Policy',\n" +
    "        app.contentSecurityPolicy({ sandbox: '' }));\n").length, 0,
          'A2. a policy through the helper is not');
  t.equal(refusedIn(
    "res.set('Content-Security-Policy', \"default-src 'none'; \" +\n" +
    "        \"frame-ancestors 'none'\");\n").length, 0,
          'A3. nor is a literal carrying the clause on a later line');
  const files = sources(ROOT, []);
  const refused = [];
  files.forEach(function (file) {
    refusedIn(fs.readFileSync(file, 'utf8')).forEach(function (one) {
      refused.push(path.relative(ROOT, file) + ': ' + one);
    });
  });
  t.check(files.length > 200,
          'B1. the scan reads the service\'s sources', String(files.length));
  t.check(refused.length === 0,
          'B2. no literal policy in the service lacks frame-ancestors, which ' +
          'app.js would replace as the response is sent', refused.join('; '));
  log.debug('Leaving run().');
}

module.exports = {
  name: 'csp_through_the_helper',
  describe: 'no route sets a literal Content-Security-Policy that app.js ' +
            'would replace as the response is sent (#1337)',
  run: run
};
