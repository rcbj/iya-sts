// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: long_unreleased_packages.js
//
// ===========================================================================
// A PACKAGE THAT HAS STOPPED RELEASING IS NOTICED (#2220, ASVS 5.0.0 15.1.4
// and 15.2.4).
//
// The 90-day review in tests/tools/dependency-windows.js fires only when a
// newer release exists, so a package whose upstream has stopped (macaroon,
// busboy, dbus-next, dtrace-provider) was never flagged, and the node-ldapjs
// fork, which is no registry package, was never reviewed at all. rcbj
// narrowed the DAILY review to security advisories (#2219), so the answer
// here is a RECORD rather than a second daily check: every package the
// images install that has had no release for more than three years is
// listed in docs/v1.2.0/risky-components.md, *Packages with no release in
// three years*, with its last release, why it is kept and what would replace
// it — and so is the fork, with the commit its pin names.
//
// In process and with no network: the dates are in
// tests/package_release_dates.json, which tests/tools/release-dates.js
// writes from the npm registry. This test holds:
//
//   1. the dates file knows every registry package of the two lockfiles the
//      images install from (the root's and sdk/'s), so a lockfile change
//      without a refresh fails here rather than going unseen;
//   2. every such package whose last release is more than three years
//      before the file's `asOf` — the day release-dates.js read the
//      registry — is listed on the page. Measured from `asOf` and never from
//      the day the test runs, so CI never turns red because of time alone:
//      the verdict moves only when somebody refreshes the file on purpose
//      (#2220's review, in the spirit of rcbj narrowing the daily review to
//      advisories, #2219);
//   3. every package the page lists is still installed, and the date the
//      page gives is the date the file has, so the list cannot go stale in
//      either direction;
//   4. the fork's row names the commit the dates file recorded and the
//      version the submodule declares, and where git can read the
//      checkout's submodule pin, that the file recorded THAT pin.
//
// The packages within ninety days of the line (from `asOf`) are logged, not
// failed, so whoever next refreshes the file sees which ones it will add.
// ===========================================================================

const childProcess = require('child_process');
const fs = require('fs');
const path = require('path');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'long_unreleased_packages',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const PAGE = path.join(ROOT, 'docs', 'v1.2.0', 'risky-components.md');
const HEADING = '## Packages with no release in three years';
const DAY_MS = 86400000;
// Three years, counting the leap day one of them has.
const LIMIT_MS = Math.round(3 * 365.25 * DAY_MS);
const SOON_MS = 90 * DAY_MS;
const REFRESH = 'run `node tests/tools/release-dates.js` and commit ' +
  'tests/package_release_dates.json';

// The page's section, from its heading to the next one.
function section() {
  log.debug("Entering section().");
  const text = fs.readFileSync(PAGE, 'utf8');
  const start = text.indexOf('\n' + HEADING + '\n');
  if (start < 0) {
    log.debug("Leaving section().");
    return '';
  }
  const rest = text.slice(start + HEADING.length + 2);
  const end = rest.search(/\n## /);
  log.debug("Leaving section().");
  return end < 0 ? rest : rest.slice(0, end);
}

// Every `name` (YYYY-MM-DD) the section lists, by name.
function listed(text) {
  log.debug("Entering listed().");
  const out = {};
  const pattern = /`((?:@[a-z0-9._-]+\/)?[a-z0-9._-]+)` \((\d{4}-\d{2}-\d{2})\)/g;
  let match = pattern.exec(text);
  while (match) {
    out[match[1]] = match[2];
    match = pattern.exec(text);
  }
  log.debug("Leaving listed().");
  return out;
}

// The submodule pin as git records it, or '' where there is no git (the
// tests image carries no .git).
function gitPin() {
  log.debug("Entering gitPin().");
  try {
    const tree = childProcess.execFileSync('git',
      ['ls-tree', 'HEAD', 'node-ldapjs'],
      { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
    log.debug("Leaving gitPin().");
    return String(tree.split(/\s+/)[2] || '');
  } catch (e) {
    log.debug("Caught in gitPin(): " + ((e && e.message) || e));
    log.debug("Leaving gitPin().");
    return '';
  }
}

function run(t) {
  log.debug("Entering run().");
  const tool = require(path.join(ROOT, 'tests', 'tools', 'release-dates.js'));
  const dates = JSON.parse(fs.readFileSync(tool.OUT, 'utf8'));
  const packages = dates.packages || {};
  // Three years are counted back from the day the dates were read.
  const asOf = Date.parse(String(dates.asOf || '') + 'T00:00:00Z');

  t.log.info('=== 1. the dates file covers both lockfiles ===');
  t.equal(JSON.stringify(dates.lockfiles), JSON.stringify(tool.LOCKFILES),
          'the dates were read from the lockfiles the images install from');
  t.check(/^\d{4}-\d{2}-\d{2}$/.test(String(dates.asOf)) && !isNaN(asOf),
          'the dates file says the day it read them (asOf ' + dates.asOf +
          '), which every age below is measured from');
  const names = tool.lockedNames();
  const undated = names.filter(function (name) {
    return !packages[name] || !/^\d{4}-\d{2}-\d{2}$/
      .test(String(packages[name].lastRelease));
  });
  t.equal(undated.join(', '), '',
          'each of the ' + names.length + ' registry packages installed ' +
          'has a last-release date (if not, ' + REFRESH + ')');

  t.log.info('=== 2. every package past three years is on the page ===');
  const text = section();
  t.check(text.length > 0, 'the page has the section "' + HEADING + '"');
  const onPage = listed(text);
  const old = names.filter(function (name) {
    return packages[name] &&
      asOf - Date.parse(packages[name].lastRelease) > LIMIT_MS;
  });
  const unlisted = old.filter(function (name) {
    return !onPage[name];
  });
  t.equal(unlisted.map(function (name) {
    return name + ' (' + packages[name].lastRelease + ')';
  }).join(', '), '',
  'each of the ' + old.length + ' packages with no release in the three ' +
  'years before ' + dates.asOf + ' is listed with its date, why it is ' +
  'kept and its replacement plan');
  const soon = names.filter(function (name) {
    const age = packages[name] ?
      asOf - Date.parse(packages[name].lastRelease) : 0;
    return age <= LIMIT_MS && age > LIMIT_MS - SOON_MS;
  });
  t.log.info('within 90 days of three years as of ' + dates.asOf + ': ' +
             (soon.map(function (name) {
               return name + ' (' + packages[name].lastRelease + ')';
             }).join(', ') || 'none'));

  t.log.info('=== 3. the list is not stale ===');
  const gone = Object.keys(onPage).filter(function (name) {
    return names.indexOf(name) < 0;
  });
  t.equal(gone.join(', '), '',
          'every package the page lists is still installed');
  const wrongDate = Object.keys(onPage).filter(function (name) {
    return packages[name] && packages[name].lastRelease !== onPage[name];
  });
  t.equal(wrongDate.map(function (name) {
    return name + ' is ' + onPage[name] + ' on the page and ' +
      packages[name].lastRelease + ' in the dates file';
  }).join('; '), '', 'and the page gives each the date the file has');
  const young = Object.keys(onPage).filter(function (name) {
    return packages[name] &&
      asOf - Date.parse(packages[name].lastRelease) <= LIMIT_MS;
  });
  t.equal(young.join(', '), '',
          'and none of them released in the three years before asOf');

  t.log.info('=== 4. the node-ldapjs fork ===');
  const fork = dates.fork || {};
  const manifest = JSON.parse(fs.readFileSync(
    path.join(ROOT, 'node-ldapjs', 'package.json'), 'utf8'));
  t.check(/^[0-9a-f]{40}$/.test(String(fork.commit)) &&
          /^\d{4}-\d{2}-\d{2}$/.test(String(fork.committed)),
          'the dates file records the fork\'s pin and its date',
          JSON.stringify(fork));
  t.equal(fork.version, manifest.version,
          'the version it recorded is the one the submodule declares');
  const forkRow = text.split('\n').filter(function (line) {
    return /^\| \*\*node-ldapjs\*\*/.test(line);
  })[0] || '';
  t.check(forkRow.indexOf('`' + String(fork.commit).slice(0, 12) + '`') >= 0 &&
          forkRow.indexOf(String(fork.committed)) >= 0,
          'the page\'s fork row names that commit and its date', forkRow);
  const pin = gitPin();
  if (pin) {
    t.equal(fork.commit, pin,
            'and the commit recorded is the submodule pin of this checkout');
  } else {
    t.log.info('no git here (the tests image carries no .git): the pin ' +
               'is checked on a checkout');
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'long_unreleased_packages',
  describe: 'every package with no release in three years, and the ' +
            'node-ldapjs fork, is recorded on the risky components page',
  run: run
};
