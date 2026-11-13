// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: upgrade_script_release.js
//
// ===========================================================================
// AN UPGRADE SCRIPT IS NEVER A PATCH RELEASE (rcbj, 2026-11-13).
//
// "I definitely don't want users to have to run an upgrade script to go
// from v1.0.0 to v1.0.1." A file `postgres/upgrade-X.Y.Z.sql` or
// `mariadb/upgrade-X.Y.Z.sql` upgrades a store from release X.Y.Z, so the
// release it upgrades TO is at least the next minor one. This holds the
// repo-root VERSION to that: its major.minor must be above X.Y for every
// such script. Every build of main is the next patch of VERSION
// (`tests/tools/release-number.js`), so a VERSION left at X.Y.Z would ship
// the script as X.Y.(Z+1).
//
// It does not ask whether a script is still needed: a script stays for as
// long as a store of its release may still be upgraded, and later releases
// keep its requirement (VERSION only grows).
// ===========================================================================
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');

// This file's own logger, for the Entering/Leaving lines the code style asks
// for; its level is LOG_LEVEL, which the harness's logger reads too.
const log = require('bunyan').createLogger({ name: 'upgrade_script_release',
  level: process.env.LOG_LEVEL || 'info' });

// Every upgrade script in the two database directories, with the release
// its name says it upgrades from.
function upgradeScripts() {
  log.debug("Entering upgradeScripts().");
  const out = [];
  ['postgres', 'mariadb'].forEach(function (dir) {
    const full = path.join(ROOT, dir);
    if (!fs.existsSync(full)) {
      return;
    }
    fs.readdirSync(full).forEach(function (name) {
      const m = /^upgrade-(\d+)\.(\d+)\.(\d+)\.sql$/.exec(name);
      if (m) {
        out.push({ file: dir + '/' + name,
                   from: [Number(m[1]), Number(m[2]), Number(m[3])] });
      }
    });
  });
  log.debug("Leaving upgradeScripts(). " + out.length);
  return out;
}

// Whether release a's major.minor is above b's.
function minorAbove(a, b) {
  return a[0] > b[0] || (a[0] === b[0] && a[1] > b[1]);
}

module.exports = {
  name: 'upgrade_script_release',
  describe: 'a release that needs an upgrade script is a minor or major ' +
            'release: VERSION is above the major.minor of every ' +
            'upgrade-X.Y.Z.sql it ships with',
  run: function (t) {
    log.debug("Entering run().");
    const raw = fs.readFileSync(path.join(ROOT, 'VERSION'), 'utf8').trim();
    const m = /^(\d+)\.(\d+)\.(\d+)$/.exec(raw);
    t.check(!!m, '1. VERSION is M.N.O', raw);
    if (!m) {
      log.debug("Leaving run(). No VERSION.");
      return;
    }
    const version = [Number(m[1]), Number(m[2]), Number(m[3])];
    const scripts = upgradeScripts();
    t.check(scripts.length > 0, '2. the upgrade scripts are found',
            'postgres/ and mariadb/ were read');
    scripts.forEach(function (one) {
      t.check(minorAbove(version, one.from),
              '3. ' + one.file + ' upgrades from ' + one.from.join('.') +
              ', so VERSION (' + raw + ') is a later minor or major release',
              'a patch release must never need an upgrade script');
    });
    // The rule itself, so it cannot pass by reading nothing.
    t.check(!minorAbove([1, 0, 1], [1, 0, 0]) &&
            minorAbove([1, 1, 0], [1, 0, 0]) &&
            minorAbove([2, 0, 0], [1, 9, 9]),
            '4. a patch is not above its release; a minor or a major is');
    log.debug("Leaving run().");
  }
};
