#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: export-realm-seed.js
//
// ---------------------------------------------------------------------------
// WHAT A NEW REALM IS BUILT WITH, FOR THE RUST RUNTIME (#444, phase 5, the
// `apis4` slice).
//
// `realms.create()` runs `ldap_server.js`'s realm builder: `seed()` (the
// realm's containers, and in development the demonstration people and
// groups), `populateVcAttributes()` (the seeded people's invented claim
// values), `applications.seedInternalApplications({ scope: 'every' })` and
// `roles.seedNativeRoles()`. The last is ported in `sts-registers`; the
// first two are DATA — prose and fixed values, one shape per mode — and the
// third is a list of specs the registry writes. They are read here off the
// running Node code rather than copied by hand, the way
// `export-admin-api-tables.js` reads the route table:
//
//   * `seed`: every entry the builder wrote BEFORE the applications, in a
//     development realm and in a product one, as `putEntry()` was handed
//     it (`attributes`) and as the vc-attribute sweep then added to it
//     (`after`). The realm's base DN and its domain are written as
//     `@@BASE@@` and `@@DOMAIN@@`; the operational attributes `putEntry()`
//     adds itself (the two timestamps, `entryUUID`, the population
//     language) are left out, because the Rust `put_entry()` adds them the
//     same way. A group named by a `roles.*` setting carries that key
//     (`setting`), so a realm overriding it gets its own name.
//   * `applications`: `internalApplications()` in a non-default realm,
//     filtered to `realmScope: 'every'`, with the realm's base URL written
//     as `@@BASE@@`, `client_id_issued_at` as `@@ISSUED@@` and every
//     `randomId(24)` as `@@RANDOM@@`. `internalApplications()` is not
//     exported, so this process appends an export to the module's source
//     as node compiles it — nothing else about the module changes.
//
// It loads the whole stack, so it runs where TypeScript is compiled: the
// tests image, with `global.publicBaseUrl` set (the base it reads).
//
//   node tests/tools/export-realm-seed.js [--out FILE]   write the file
//   node tests/tools/export-realm-seed.js --check        exit 1 when stale
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');
const Module = require('module');
const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'export-realm-seed',
  level: process.env.STS_LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..', '..');
const FILE = path.join(ROOT, 'rust', 'bins', 'sts-runtime', 'tables',
                       'realm_seed.json');
const BASE_URL = 'https://realm-seed.invalid';

// The settings whose value names a group `seed()` makes.
const ROLE_GROUP_SETTINGS = ['roles.remotePepGroup', 'roles.xacmlUserGroup',
                             'roles.authzenPepGroup'];

// The attributes `putEntry()` adds itself.
const OPERATIONAL = ['createtimestamp', 'modifytimestamp', 'entryuuid',
                     'preferredlanguage', 'stspreferredlanguagepopulated'];

/**
 * Makes `internalApplications()` reachable: one export appended to
 * `common/applications.js`'s source as it is compiled.
 */
function exposeInternalApplications() {
  log.debug("Entering exposeInternalApplications().");
  const wanted = path.join(ROOT, 'common', 'applications.js');
  const compile = Module.prototype._compile;
  Module.prototype._compile = function (content, filename) {
    if (filename === wanted) {
      content = content + '\nmodule.exports.__internalApplications = ' +
        'internalApplications;\n';
    }
    return compile.call(this, content, filename);
  };
  log.debug("Leaving exposeInternalApplications().");
}

/**
 * One realm's text with its own names written as markers.
 *
 * @param {string} text - the text
 * @param {any} names - `{ base, domain, url }`
 * @returns {string} the text
 */
function marked(text, names) {
  log.debug("Entering marked().");
  const out = String(text).split(names.url).join('@@BASE@@')
    .split(names.base).join('@@BASE@@')
    .split(names.domain).join('@@DOMAIN@@');
  log.debug("Leaving marked().");
  return out;
}

/**
 * One entry the realm builder wrote, as a row of the table.
 *
 * @param {any} stored - the stored entry
 * @param {any} names - the realm's names
 * @param {any} groups - lower-cased DN to the setting naming that group
 * @returns {any} the row
 */
function seedRow(stored, names, groups) {
  log.debug("Entering seedRow().");
  const order = Object.keys(stored.attributes);
  const at = order.indexOf('createtimestamp');
  const put = at >= 0 ? order.slice(0, at) : order;
  const attributes = {};
  const after = {};
  order.forEach(function (name) {
    if (OPERATIONAL.indexOf(name) >= 0) {
      return;
    }
    // The root entry's `dc` is the base DN's first value (`seed()`'s
    // `dcValue`), written as `@@DC@@`.
    const root = stored.dn.toLowerCase() === names.base.toLowerCase();
    const values = stored.attributes[name].map(function (v) {
      return root && name === 'dc' ? '@@DC@@' : marked(v, names);
    });
    if (put.indexOf(name) >= 0) {
      attributes[name] = values;
    } else {
      after[name] = values;
    }
  });
  const row = { dn: marked(stored.dn, names), attributes: attributes };
  if (Object.keys(after).length) {
    row.after = after;
  }
  const setting = groups[stored.dn.toLowerCase()];
  if (setting) {
    row.setting = setting;
  }
  log.debug("Leaving seedRow().");
  return row;
}

/**
 * Replaces the volatile values of a spec with markers.
 *
 * @param {any} value - a spec, or a part of one
 * @param {any} names - the realm's names
 * @param {number} issued - the instant the specs were made at
 * @param {string} key - the member's name
 * @returns {any} the spec
 */
function specOf(value, names, issued, key) {
  if (Array.isArray(value)) {
    return value.map(function (one) {
      return specOf(one, names, issued, '');
    });
  }
  if (value && typeof value === 'object') {
    const out = {};
    Object.keys(value).forEach(function (k) {
      out[k] = specOf(value[k], names, issued, k);
    });
    return out;
  }
  if (key === 'client_id_issued_at') {
    return '@@ISSUED@@';
  }
  if ((key === 'registration_access_token' || key === 'client_secret') &&
      typeof value === 'string') {
    return '@@RANDOM@@';
  }
  if (typeof value === 'string') {
    return marked(value, names);
  }
  return value;
}

/**
 * The export.
 *
 * @returns {Promise<any>} the tables
 */
async function tables() {
  log.debug("Entering tables().");
  exposeInternalApplications();
  require(path.join(ROOT, 'common', 'protocol_stack'));
  const realms = require(path.join(ROOT, 'common', 'realms'));
  const config = require(path.join(ROOT, 'common', 'config'));
  const ldap = require(path.join(ROOT, 'ldap', 'ldap_server'));
  const applications = require(path.join(ROOT, 'common', 'applications'));
  const firsts = {};
  const out = { seed: {}, applications: [] };
  const made = {
    development: { id: 'seedx', overrides: {} },
    product: { id: 'seedp', overrides: { 'global.mode': 'product' } }
  };
  for (const mode of Object.keys(made)) {
    const one = made[mode];
    const names = { domain: one.id + '.example.test',
                    base: 'dc=' + one.id + ',dc=example,dc=test',
                    url: BASE_URL + '/realm/' + one.id };
    // Every entry the builder wrote, in the order it wrote them, read
    // back once it had finished: an entry written by the seed is
    // `origin: seed` and was written before the applications.
    const created = realms.create({ id: one.id, name: one.id,
                                    domain: names.domain,
                                    overrides: one.overrides });
    if (!created.ok) {
      throw new Error(JSON.stringify(created));
    }
    const rows = realms.run(realms.get(one.id), function () {
      const groups = {};
      ROLE_GROUP_SETTINGS.forEach(function (key) {
        const name = String(config.value(key) || '').trim();
        if (name) {
          groups[('cn=' + name + ',ou=groups,' + names.base)
            .toLowerCase()] = key;
        }
      });
      const found = [];
      ldap.entries.forEach(function (stored) {
        if (stored.origin === 'seed') {
          found.push(seedRow(stored, names, groups));
        }
      });
      return found;
    });
    firsts[mode] = rows;
    if (mode === 'product') {
      out.applications = realms.run(realms.get(one.id), function () {
        const issued = Math.floor(Date.now() / 1000);
        return applications.__internalApplications().filter(function (s) {
          return s.realmScope === 'every';
        }).map(function (s) {
          return specOf(s, names, issued, '');
        });
      });
    }
  }
  // The native roles' groups are `seedNativeRoles()`'s (ported), and are
  // left out: they come after the applications.
  Object.keys(firsts).forEach(function (mode) {
    out.seed[mode] = firsts[mode].filter(function (row) {
      return !/^cn=(ssf-read|ssf-manage|report-users|report-admins),ou=groups,/
        .test(row.dn);
    });
  });
  out.roleGroupSettings = ROLE_GROUP_SETTINGS.slice();
  log.debug("Leaving tables().");
  return out;
}

/**
 * Writes the file, or checks it.
 *
 * @returns {Promise<void>} when done
 */
async function main() {
  log.debug("Entering main().");
  const at = process.argv.indexOf('--out');
  const file = at >= 0 ? process.argv[at + 1] : FILE;
  const text = JSON.stringify(await tables(), null, 2) + '\n';
  if (process.argv.indexOf('--check') >= 0) {
    const have = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '';
    if (have !== text) {
      log.error('export-realm-seed: ' + file + ' is stale; run ' +
                'node tests/tools/export-realm-seed.js in the tests image.');
      log.debug("Leaving main(). Stale.");
      process.exit(1);
    }
    log.info('export-realm-seed: ' + file + ' is current.');
    log.debug("Leaving main(). Current.");
    process.exit(0);
  }
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, text);
  log.info('export-realm-seed: wrote ' + file + '.');
  log.debug("Leaving main().");
  process.exit(0);
}

main().catch(function (e) {
  log.error('export-realm-seed: ' + ((e && e.stack) || e));
  process.exit(1);
});
