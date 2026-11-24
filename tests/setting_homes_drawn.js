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
//   2. every page draws a control for every setting of each group it homes,
//      but for the rows OWED names, which must still be undrawn;
//   3. the six #2049 pages draw their groups, and Directory → OpenPGP keys
//      and Directory → Hardware tokens are named by no row;
//   4. the #2070 pages: the rest of the per-client group on Token
//      lifetimes, Profile photos on a Users tab, and the Cluster status
//      block.
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const admin = require('../admin-ui/admin');
const consolePage = require('./tools/console_page')
  .consolePage(require('path').join(__dirname, '..'));

// THE XACML PAGES ARRIVE WITH THE FAMILY: `xacml/xacml_admin` fills the
// console's slot for them when it loads (a running service loads it at 23c),
// and without it `GET /admin-api/xacml` answers the no-XACML view, which
// carries no settings block.
require('../xacml/xacml_admin');
// The same for Signing keys: `GET /admin-api/keys` answers 503 until
// `admin-ui/crypto_metadata` fills the crypto reporter (it does at 20a).
require('../admin-ui/crypto_metadata');

// WHAT THIS FOUND AND #2049 DID NOT FIX, each named with its reason so the
// table can only shrink: every entry is asserted to be STILL undrawn, so a
// fix fails this file until its row is removed. Fixed on #2049 itself:
// `/admin/cluster` (never converted by #446, so "not a console page"),
// `/admin/vc` (`Person DIDs` left out of the tab's group list) and
// `/admin/saml2` (two assertion rows outside `SAML_ASSERTION_SETTINGS`).
// EMPTY SINCE #2070: `/admin/token-lifetimes` draws the rest of its group
// from the answer's `otherSettings`, and Directory → Users draws
// `Profile photos` on a Settings tab from its answer's `settings`.
const OWED = {};

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
  const stillOwed = [];
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
      const name = page + ' [' + group + ']';
      const owed = OWED[name] || [];
      if (owed.length) {
        stillOwed.push(name + ': ' + (missing.join(',') === owed.join(',')
          ? 'still undrawn' : 'NOW ' + (missing.join(', ') || 'drawn')));
      }
      const unexpected = missing.filter(function (key) {
        return owed.indexOf(key) < 0;
      });
      if (unexpected.length) {
        undrawn.push(name + ': ' + unexpected.join(', '));
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

  t.check(stillOwed.length === Object.keys(OWED).length &&
          stillOwed.every(function (line) {
            return /still undrawn$/.test(line);
          }),
          '2. and each page OWED names still leaves exactly those rows ' +
          'undrawn (remove its row once it draws them)',
          stillOwed.join('; '));

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

  t.log.info('=== 4. the #2070 pages ===');
  // The two groups #2070 drew, each on its page; the Users page as tabs
  // in the Directory pages' shape; and Platform → Cluster's status block,
  // which had no browser renderer from #446 until #2070.
  const tokenPage = await consolePage.draw('/admin/token-lifetimes', {});
  t.check(tokenPage.status === 200 &&
          ['oauth2.refreshTokenMaxChainS',
           'oauth2.consentAlwaysForPublicClients',
           'oauth2.maxAuthAgeS'].every(function (key) {
            return (tokenPage.html.split('name="' + key + '"').length - 1) ===
              1;
          }),
          '4. /admin/token-lifetimes draws one control for each of the ' +
          'three rows that are not lifetimes',
          String(tokenPage.status));
  const usersPage = await consolePage.draw('/admin/users', {});
  t.check(usersPage.status === 200 &&
          usersPage.html.indexOf('id="users-tab-metadata"') >= 0 &&
          usersPage.html.indexOf('id="users-tab-metadata"') <
            usersPage.html.indexOf('id="users-tab-people"') &&
          usersPage.html.indexOf('id="users-tab-people"') <
            usersPage.html.indexOf('id="users-tab-settings"') &&
          usersPage.html.indexOf('name="profilePhoto.selfService"') >
            usersPage.html.indexOf('id="users-tab-settings"'),
          '4. /admin/users is tabs: Metadata, the people, and the ' +
          'Profile photos settings',
          String(usersPage.status));
  const clusterPage = await consolePage.draw('/admin/cluster', {});
  t.check(clusterPage.status === 200 &&
          ['Right now', 'Members', 'What active-active depends on',
           'Shared secrets'].every(function (heading) {
            return clusterPage.html.indexOf('<h2>' + heading + '</h2>') >= 0;
          }) &&
          clusterPage.html.indexOf('consoleCluster.') < 0,
          '4. /admin/cluster draws its status block, every word from the ' +
          'catalog',
          String(clusterPage.status));
  log.debug("Leaving runBody().");
}

module.exports = {
  name: 'setting_homes_drawn',
  describe: 'every console page SETTING_HOMES names draws a control for ' +
            'every setting of the groups homed on it (#2049)',
  run: runBody
};
