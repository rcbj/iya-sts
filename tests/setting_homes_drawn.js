// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: setting_homes_drawn.js
//
// ===========================================================================
// EVERY PAGE SETTING_HOMES NAMES DRAWS ITS GROUPS (#2049, 2026-11-23).
//
// `checkSettingHomes()` (admin-ui/admin.ts) holds the table to three things
// at start-up: every group config.js declares has exactly one row, every row
// names a group that exists, and every page a row names is in the console's
// SECTIONS. It cannot hold the fourth, which is the one that matters to a
// reader: that the page actually DRAWS the group. The OpenPGP group was homed
// on Directory → OpenPGP keys, a page whose renderer draws a person's key and
// no settings form, so `/admin/config` sent a reader there and none of the
// eight `openpgp.*` settings could be changed in the console. Every check
// passed.
//
// So this draws each page as the static console draws it — its `/admin-api`
// operation's answer, rendered by its renderer (`tests/tools/console_page`)
// — and requires a control for every setting of every group homed on it:
// `name="<key>"`, or `name="<key>.ordered"` for an ordered choice. A page
// the drawer cannot reach is a failure too, named with what it threw.
//
//   1. the table names at least the pages it is known to;
//   2. every page draws a control for every setting of each group it homes;
//   3. the six #2049 pages draw their groups, and Directory → OpenPGP keys
//      and Directory → Hardware tokens are named by no row.
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const admin = require('../admin-ui/admin');
const consolePage = require('./tools/console_page')
  .consolePage(require('path').join(__dirname, '..'));

const log = require('bunyan').createLogger({
  name: 'setting_homes_drawn',
  level: process.env.LOG_LEVEL || 'info' });

// A control for the setting, in each shape `web_settings.ts` draws one.
function drawsControl(html, key) {
  log.debug("Entering drawsControl().");
  const drawn = html.indexOf('name="' + key + '"') >= 0 ||
                html.indexOf('name="' + key + '.ordered"') >= 0;
  log.debug("Leaving drawsControl(). " + drawn);
  return drawn;
}

// page → the groups SETTING_HOMES draws on it.
function groupsByPage() {
  log.debug("Entering groupsByPage().");
  const out = {};
  admin.settingHomes().forEach(function (row) {
    row.pages.forEach(function (page) {
      out[page] = (out[page] || []).concat([row.group]);
    });
  });
  log.debug("Leaving groupsByPage(). " + Object.keys(out).length);
  return out;
}

// group → its keys, in config.js's order.
function keysOf(group) {
  log.debug("Entering keysOf().");
  const keys = config.SETTINGS.filter(function (row) {
    return row.group === group;
  }).map(function (row) { return row.key; });
  log.debug("Leaving keysOf(). " + keys.length);
  return keys;
}

async function runBody(t) {
  log.debug("Entering runBody().");
  const pages = groupsByPage();
  const paths = Object.keys(pages).sort();

  t.log.info('=== 1. the table names the pages ===');
  t.check(paths.length >= 20,
          '1. SETTING_HOMES names at least twenty pages', paths.join(', '));

  t.log.info('=== 2. every page draws every group it homes ===');
  const undrawn = [];
  const unreachable = [];
  for (const page of paths) {
    let html = null;
    try {
      const drawn = await consolePage.draw(page, {});
      html = drawn.status === 200 ? drawn.html : null;
      if (html === null) {
        unreachable.push(page + ' (' + drawn.status + ')');
      }
    } catch (e) {
      log.debug("Caught in runBody(): " + ((e && e.message) || e));
      unreachable.push(page + ' (' + ((e && e.message) || e) + ')');
    }
    if (html === null) {
      continue;
    }
    pages[page].forEach(function (group) {
      const missing = keysOf(group).filter(function (key) {
        return !drawsControl(html, key);
      });
      if (missing.length) {
        undrawn.push(page + ' [' + group + ']: ' + missing.join(', '));
      }
    });
  }
  t.check(unreachable.length === 0,
          '2. every page SETTING_HOMES names can be drawn',
          unreachable.join('; '));
  t.check(undrawn.length === 0,
          '2. and each draws a control for every setting of every group ' +
          'homed on it (' + paths.length + ' page(s))',
          undrawn.join('; '));

  t.log.info('=== 3. the #2049 pages ===');
  const expected = {
    '/admin/openpgp-settings': 'OpenPGP',
    '/admin/hardware-tokens-settings': 'Hardware tokens',
    '/admin/piv': 'PIV',
    '/admin/yubiotp': 'YubiKey OTP',
    '/admin/oath-tokens': 'OATH tokens',
    '/admin/ssh-user-ca': 'SSH user certificates'
  };
  Object.keys(expected).forEach(function (page) {
    t.check((pages[page] || []).indexOf(expected[page]) >= 0 &&
            keysOf(expected[page]).length > 0,
            '3. ' + page + ' homes the ' + expected[page] + ' group',
            JSON.stringify(pages[page] || null));
  });
  t.check(!pages['/admin/openpgp'] && !pages['/admin/hardware-tokens'],
          '3. the two Directory pages home no settings group',
          JSON.stringify([pages['/admin/openpgp'] || null,
                          pages['/admin/hardware-tokens'] || null]));
  t.check(keysOf('OpenPGP').length === 8 && keysOf('PIV').length === 8 &&
          keysOf('YubiKey OTP').length === 3 &&
          keysOf('OATH tokens').length === 4 &&
          keysOf('SSH user certificates').length === 7 &&
          keysOf('Hardware tokens').join(',') ===
            'hardwareTokens.hardwareClaims',
          '3. the groups hold the settings they were given',
          ['OpenPGP', 'PIV', 'YubiKey OTP', 'OATH tokens',
           'SSH user certificates', 'Hardware tokens'].map(function (g) {
            return g + '=' + keysOf(g).join('|');
          }).join(' '));
  log.debug("Leaving runBody().");
}

module.exports = {
  name: 'setting_homes_drawn',
  describe: 'every console page SETTING_HOMES names draws a control for ' +
            'every setting of the groups homed on it (#2049)',
  run: runBody
};
