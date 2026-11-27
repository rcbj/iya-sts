// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: doc_version_status.js
//
// ===========================================================================
// THE 1.2.0 DOCUMENTATION TAB SAYS PRERELEASE (#2307).
//
// 1.2.0 is the development line. The version switcher draws a row's
// `status` beside its label, and that row's status is Prerelease. The
// shipped versions have none. The landing page and the line on an older
// version's pages use the same word.
//
// WHY IN PROCESS: it reads the site's source. The Pages build is what
// renders it.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const path = require('path');

const log = require('bunyan').createLogger({ name: 'doc_version_status',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const DOCS = path.join(ROOT, 'docs');

function read(rel) {
  log.debug("Entering read().");
  const text = fs.readFileSync(path.join(DOCS, rel), 'utf8');
  log.debug("Leaving read().");
  return text;
}

function row(text, folder) {
  log.debug("Entering row().");
  const found = text.split('\n').filter(function (line) {
    return line.indexOf('folder: ' + folder) >= 0 &&
      /^\s*-\s*\{/.test(line);
  });
  log.debug("Leaving row().");
  return found[0] || '';
}

function run(t) {
  log.debug("Entering run().");
  const versions = read('_data/versions.yml');
  const current = row(versions, 'v1.2.0');
  t.check(/status:\s*"Prerelease"/.test(current),
          'the 1.2.0 row carries status Prerelease', current);
  t.check(!/status:/.test(row(versions, 'v1.1.0')) &&
          !/status:/.test(row(versions, 'v1.0.0')),
          'a shipped version has no status');
  const header = read('_includes/header.html');
  t.check(header.indexOf('v.status') >= 0 &&
          header.indexOf('version-status') >= 0,
          'the version switcher draws a row\'s status beside its label');
  const sidebar = read('_includes/sidebar.html');
  t.check(sidebar.indexOf('v.status') >= 0,
          'the landing version list draws the same status');
  const layout = read('_layouts/default.html');
  t.check(layout.indexOf('doc_latest.status') >= 0,
          'an older version\'s page names the latest with its status');
  const landing = read('index.md');
  t.check(landing.indexOf('**Prerelease.**') >= 0 &&
          landing.indexOf('[1.2.0](v1.2.0/index.md)') >= 0,
          'the landing page marks 1.2.0 Prerelease');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'doc_version_status',
  describe: 'the 1.2.0 documentation tab shows Prerelease, from the ' +
            'version row\'s status',
  run: run
};
