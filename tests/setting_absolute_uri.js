// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: setting_absolute_uri.js
//
// ===========================================================================
// A SAML NameID FORMAT IS AN ABSOLUTE URI (2026-11-12).
//
// The fuzz stage of run 17 saved `saml2.nameIdFormat` as `,]` through
// /admin-api/config/set. The row was plain text, so it was taken, and every
// SAML 2.0 Response the realms sent afterwards carried
// `<saml:NameID Format=",]">`, which the assertion schema (xs:anyURI)
// refuses — sts_xml_schema_validation's 32 failures. This file holds:
//
//   A. both NameID format rows refuse text that is not an absolute URI at
//      the write door (STS-CORE-0006), and accept the URNs and URLs a
//      format is;
//   B. a row without `absoluteUri` is unchanged;
//   C. the startup check (`opts.startup`) does not refuse it, so a
//      deployment configured with one before this rule still starts.
//
// WHY IN PROCESS: the door is the registry's, and the startup half is a
// claim about how the process starts.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const path = require('path');
const config = require('../common/config');

const KEYS = ['saml2.nameIdFormat', 'saml11.nameIdFormat'];
const GOOD = [
  'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
  'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
  'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
  'https://example.com/formats/one'
];
const BAD = [',]', '', 'no scheme', 'urn:', 'urn:a b', 'x:\u0007y',
             '1urn:x'];

module.exports = {
  name: 'setting_absolute_uri',
  describe: 'a SAML NameID format setting is an absolute URI at the write ' +
            'door, and only warned about at startup',
  run: function (t) {
    t.log.debug("Entering run().");
    KEYS.forEach(function (key) {
      GOOD.forEach(function (value) {
        t.check(config.checkOverride(key, value, true) === null,
                key + ' accepts ' + value,
                config.checkOverride(key, value, true));
      });
      BAD.forEach(function (value) {
        const problem = config.checkOverride(key, value, true);
        t.check(typeof problem === 'string' &&
                /absolute URI/.test(problem),
                key + ' refuses ' + JSON.stringify(value), problem);
        t.equal(config.checkOverrideCode(key, value, true), 'STS-CORE-0006',
                key + ' refuses ' + JSON.stringify(value) +
                ' as STS-CORE-0006');
      });
      const row = config.SETTINGS.filter(function (s) {
        return s.key === key;
      })[0];
      t.check(row && row.absoluteUri === true, key + ' is marked absoluteUri');
    });
    // C. A CHILD STARTED WITH THE VALUE IN ITS ENVIRONMENT: config.js's
    // startup check exits 1 on a value the write door would refuse, so this
    // is the case that would stop a deployment configured before the rule.
    const child = childProcess.spawnSync(process.execPath, ['-e',
      'require(' + JSON.stringify(path.join(__dirname, '..', 'common',
        'config')) + '); process.stdout.write("started")'],
      { env: Object.assign({}, process.env, {
        CONFIG_FILE: '', STS_SAML2_NAMEID_FORMAT: ',]' }),
        encoding: 'utf8', timeout: 60000 });
    t.equal(child.status, 0, 'a process whose environment sets ' +
            'STS_SAML2_NAMEID_FORMAT=",]" still starts');
    t.check(/started/.test(child.stdout || ''), 'its config loaded',
            String(child.stderr || '').slice(0, 300));
    t.check(/STS-CORE-0176/.test((child.stdout || '') +
            (child.stderr || '')), 'and it warned under STS-CORE-0176',
            String(child.stdout || '').slice(0, 300));
    t.check(config.checkOverride('branding.displayName', ',]', true) ===
            null || !/absolute URI/.test(String(
              config.checkOverride('branding.displayName', ',]', true))),
            'a string row without absoluteUri is not held to it');
    t.log.debug("Leaving run().");
  }
};
