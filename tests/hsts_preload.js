// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/hsts_preload.js
//
// #2165 (ASVS 5.0.0 3.7.4): `security.hstsPreload` adds `preload` to the
// Strict-Transport-Security header `common/cookie_wire.ts` sends over TLS in
// product mode, only while `includeSubDomains` is sent too, and `/admin/mode`
// says so on the `strict-transport-security` row where it is withheld. Each
// check drives the middleware itself with a request marked as arriving over
// TLS; every setting is put back.

const path = require('path');

delete process.env.CONFIG_FILE;

const ROOT = path.join(__dirname, '..');

async function run(t) {
  const config = require(ROOT + '/common/config');
  const mode = require(ROOT + '/common/mode');
  const CookieWire = require(ROOT + '/common/cookie_wire');
  const errorCodes = require(ROOT + '/common/error_codes');
  const keys = ['global.mode', 'security.hstsPreload',
                'security.hstsIncludeSubDomains'];
  // The header one response over TLS carries, under these overrides.
  const headerWith = function (overrides) {
    keys.forEach(function (key) {
      config.clearOverride(key);
    });
    Object.keys(overrides).forEach(function (key) {
      config.setOverride(key, String(overrides[key]));
    });
    const req = { headers: {}, socket: { encrypted: true } };
    const set = {};
    const res = {
      setHeader: function (name, value) {
        set[name.toLowerCase()] = value;
      },
      getHeader: function (name) {
        return set[name.toLowerCase()];
      },
      writeHead: function () {
        return 'flushed';
      }
    };
    let nexted = false;
    CookieWire.middleware()(req, res, function () {
      nexted = true;
    });
    res.writeHead(200);
    return { header: set['strict-transport-security'], nexted: nexted };
  };
  const restore = function () {
    keys.forEach(function (key) {
      config.clearOverride(key);
    });
  };
  try {
    t.equal(config.value('security.hstsPreload'), false,
            'security.hstsPreload is off by default');
    t.equal(errorCodes.isKnown('STS-CORE-0181'), true,
            'STS-CORE-0181 is in the table');
    const dev = headerWith({ 'security.hstsPreload': true });
    t.equal(dev.nexted, true, 'the middleware passes the request on');
    t.equal(dev.header, undefined,
            'development still sends no HSTS, preload or not');
    const plain = headerWith({ 'global.mode': 'product' });
    t.equal(plain.header, 'max-age=31536000; includeSubDomains',
            'product sends the header without preload by default');
    const preloaded = headerWith({ 'global.mode': 'product',
                                   'security.hstsPreload': true });
    t.equal(preloaded.header,
            'max-age=31536000; includeSubDomains; preload',
            'with the setting on, product asks to be preloaded');
    t.equal(CookieWire.HSTS_MAX_AGE >= 31536000, true,
            'the max-age meets the preload list\'s year');
    t.equal(mode.hstsPreloadWaivers().length, 0,
            'nothing is withheld, so the mode row carries no waiver');
    const withheld = headerWith({ 'global.mode': 'product',
                                  'security.hstsPreload': true,
                                  'security.hstsIncludeSubDomains': false });
    t.equal(withheld.header, 'max-age=31536000',
            'without includeSubDomains preload is withheld');
    const waivers = mode.hstsPreloadWaivers();
    t.equal(waivers.length === 1 &&
            waivers[0].requirement === 'hsts-preload' &&
            waivers[0].section === 'ASVS 5.0.0 3.7.4' &&
            waivers[0].setting === 'security.hstsIncludeSubDomains', true,
            'and the waiver names the setting to change: ' +
            JSON.stringify(waivers));
    const row = mode.report().requirements.filter(function (one) {
      return one.id === 'strict-transport-security';
    })[0];
    t.equal(!!row && Array.isArray(row.waived) &&
            row.waived[0].requirement === 'hsts-preload', true,
            '/admin/mode carries it on the strict-transport-security row');
    const back = headerWith({ 'global.mode': 'product',
                              'security.hstsIncludeSubDomains': false });
    t.equal(back.header, 'max-age=31536000',
            'with preload off, includeSubDomains off is max-age alone');
    config.clearOverride('global.mode');
    config.setOverride('security.hstsPreload', 'true');
    config.setOverride('security.hstsIncludeSubDomains', 'false');
    const devRow = mode.report().requirements.filter(function (one) {
      return one.id === 'strict-transport-security';
    })[0];
    t.equal(!!devRow && !devRow.waived, true,
            'development, which sends no header, shows no waiver');
  } finally {
    restore();
  }
}

module.exports = {
  name: 'hsts_preload',
  describe: 'security.hstsPreload and the header it changes (#2165)',
  run: run
};
