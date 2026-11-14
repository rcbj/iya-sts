// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/tools/store-interop.js
//
// ---------------------------------------------------------------------------
// NODE'S HALF OF THE STORE'S TWO-WAY PROOF (#444, phase 2b). rcbj decided on
// 2026-11-14 that the Rust runtime upgrades a 1.x install IN PLACE, so the
// Rust store must read the rows Node wrote and write rows Node reads: the
// tables, the columns, the sealed entry blob, the keyed lookups, `dek_keys`,
// the data-key rows, the signing key sets, the realm registry and the
// overrides. This tool is Node's side of that, against a real PostgreSQL
// with `postgres/schema.sql` applied; the Rust side is
// `rust/crates/sts-store/tests/interop.rs`.
//
//   node tests/tools/store-interop.js write <dir>
//     Clears the store, then writes it as Node does — the keystore started
//     over a durable key-encryption key in <dir>/interop-kek.txt (made here
//     when absent), the default realm's signing key set, directory entries
//     in two realms sealed under their `directory` keys, the realm registry
//     and an override — and records what it wrote, and the raw columns it
//     stored, in <dir>/interop-node.json.
//
//   node tests/tools/store-interop.js read <dir>
//     Opens a store the Rust runtime wrote (<dir>/interop-rust.json says
//     what it wrote) with the same key-encryption key and checks every
//     entry, every lookup column, `dek_keys`, the realms, the overrides, the
//     key set and the sealed values against it. Exits 1 on a difference.
//
// The database is STS_TEST_DATABASE_URL; its server certificate is not
// verified (a throwaway container's). <dir> is never committed: it holds a
// key-encryption key.
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');
const nodeCrypto = require('crypto');

const ROOT = path.join(__dirname, '..', '..');
const MODE = process.argv[2];
const DIR = process.argv[3];
const URL = process.env.STS_TEST_DATABASE_URL || '';
const KEK_FILE = DIR ? path.join(DIR, 'interop-kek.txt') : '';

// The key settings are read from the environment once per process, so they
// are set before anything of the service is required.
if (KEK_FILE && !fs.existsSync(KEK_FILE) && MODE === 'write') {
  fs.writeFileSync(KEK_FILE, nodeCrypto.randomBytes(32).toString('base64') +
                   '\n', { mode: 0o600 });
}
process.env.STS_KEYS_SOURCE = 'persisted';
process.env.STS_KEYS_KEK_PROVIDER = 'file';
process.env.STS_KEYS_KEK_FILE = KEK_FILE;
process.env.STS_DATABASE_TLS_REJECT_UNAUTHORIZED = 'false';
process.env.STS_LOG_LEVEL = process.env.STS_LOG_LEVEL || 'fatal';

const bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'store-interop',
                                  level: process.env.STS_LOG_LEVEL });

// The tables a run clears: the ones this proof writes, and the change log
// and data-key rows that come with them.
const TABLES = ['sts_ldap_entries', 'sts_realms', 'sts_appconfig', 'sts_keys',
                'sts_changes'];

/**
 * A query against the store, outside the driver, for the raw columns.
 *
 * @param {string} sql - the statement
 * @param {Array<any>} [params] - its parameters
 * @returns {Promise<any>} the result
 */
async function raw(sql, params) {
  log.debug('Entering raw().');
  const pg = require('pg');
  const client = new pg.Client({ connectionString: URL,
                                 ssl: { rejectUnauthorized: false } });
  await client.connect();
  try {
    const out = await client.query(sql, params || []);
    log.debug('Leaving raw().');
    return out;
  } finally {
    await client.end();
  }
}

/**
 * The Node driver and keystore over the store, started.
 *
 * @returns {Promise<any>} `{ driver, keystore, codec }`
 */
async function started() {
  log.debug('Entering started().');
  const driver = require(path.join(ROOT, 'persistence',
                                   'persistence_postgres.js'))
    .create({ url: URL, log: log });
  await driver.open();
  const keystore = require(path.join(ROOT, 'common', 'keystore.js'));
  keystore.setStore(driver);
  await keystore.start();
  const codec = require(path.join(ROOT, 'persistence', 'directory_codec.js'))
    .create('cell');
  log.debug('Leaving started().');
  return { driver: driver, keystore: keystore, codec: codec };
}

/**
 * Every stored entry row, its raw columns as the database holds them.
 *
 * @returns {Promise<Array<any>>} the rows
 */
async function storedRows() {
  log.debug('Entering storedRows().');
  const result = await raw(
    'SELECT realm, dn_key, dn, attrs, origin, created_at, modified_at, ' +
    'name_keys, mail_keys, uuid_keys, class_keys, value_keys, attr_names, ' +
    'dek_keys FROM sts_ldap_entries ORDER BY realm, dn_key');
  log.debug('Leaving storedRows().');
  return result.rows;
}

/**
 * The entries a run writes, in two realms, built to reach every rule of the
 * codec: a pseudonym, mail in upper case, an alias, a group class and a
 * person's, a stored certificate, granting attributes as a name and as a DN,
 * a value sealed inside an attribute, unicode, and an empty value.
 *
 * @param {any} keystore - the started keystore
 * @param {string} certB64 - a certificate's DER, base64
 * @returns {Array<any>} `{ realm, key, entry }`
 */
function entriesToWrite(keystore, certB64) {
  log.debug('Entering entriesToWrite().');
  const totp = keystore.seal('JBSWY3DPEHPK3PXP', 'totp-secret', 'cell',
                             { realm: '' });
  const out = [
    { realm: 'default', key: 'dc=example,dc=com',
      entry: { dn: 'dc=example,dc=com', origin: 'seed',
               attributes: { objectClass: ['top', 'domain'], dc: ['example'] },
               createdAt: '20260101000000Z', modifiedAt: '20260101000000Z' } },
    { realm: 'default', key: 'uid=alice,ou=people,dc=example,dc=com',
      entry: { dn: 'uid=alice,ou=people,dc=example,dc=com',
               attributes: {
                 objectClass: ['top', 'person', 'organizationalPerson',
                               'inetOrgPerson'],
                 uid: ['alice'], cn: ['Alice Ünïcode'], sn: ['Example'],
                 mail: ['Alice@Example.COM'],
                 entryUUID: ['0F8A2C6E-1111-4222-8333-944455556666'],
                 stsEntryUuidAlias: ['AAAA-alias'],
                 stsPseudonym: ['Al1ce'],
                 'userCertificate;binary': [certB64],
                 stsTotpCredential: [totp],
                 description: [' leading', 'trailing ', '', 'line\nbreak'],
                 didSubject: ['did:web:example.com:alice'],
                 createTimestamp: ['20260102000000Z']
               },
               createdAt: '20260102000000Z', modifiedAt: '20260103000000Z' } },
    { realm: 'default', key: 'cn=admins,ou=groups,dc=example,dc=com',
      entry: { dn: 'cn=admins,ou=groups,dc=example,dc=com',
               attributes: {
                 objectClass: ['top', 'groupOfNames'], cn: ['admins'],
                 member: ['uid=alice,ou=people,dc=example,dc=com'],
                 owner: [' UID=Alice, OU=People,dc=example,dc=com '],
                 roleMemberGroup: ['Operators']
               } } },
    { realm: 'acme', key: 'uid=bob,ou=people,dc=acme,dc=example',
      entry: { dn: 'uid=bob,ou=people,dc=acme,dc=example', origin: 'scim',
               attributes: { objectClass: ['top', 'inetOrgPerson'],
                             uid: ['bob'], mail: ['bob@acme.example'],
                             cn: ['Bob'], sn: ['B'] },
               createdAt: '20260104000000Z' } }
  ];
  log.debug('Leaving entriesToWrite().');
  return out;
}

/**
 * The comparable form of a stored row: what it says of the entry, and the
 * columns a reader looks it up by.
 *
 * @param {any} row - a raw row
 * @returns {any} the form
 */
function columnsOf(row) {
  log.debug('Entering columnsOf().');
  log.debug('Leaving columnsOf().');
  return { realm: row.realm, key: row.dn_key, dn: row.dn,
           origin: row.origin, createdAt: row.created_at,
           modifiedAt: row.modified_at, sealed: typeof row.attrs === 'string',
           nameKeys: row.name_keys, mailKeys: row.mail_keys,
           uuidKeys: row.uuid_keys, classKeys: row.class_keys,
           valueKeys: row.value_keys, attrNames: row.attr_names,
           dekKeys: row.dek_keys };
}

/**
 * Writes the store as Node does, and records it.
 *
 * @returns {Promise<void>}
 */
async function write() {
  log.debug('Entering write().');
  for (const table of TABLES) {
    await raw('DELETE FROM ' + table);
  }
  const s = await started();
  const helpers = require(path.join(ROOT, 'common', 'helpers.js'));
  const set = helpers.stsKeysFor();
  const certB64 = set.selfSignedCertB64 || set.certB64;
  const entries = entriesToWrite(s.keystore, certB64);
  const realmIds = Array.from(new Set(entries.map(function (e) {
    return e.realm;
  })));
  s.codec.prepareKeys(realmIds);
  await s.keystore.settleDeks();
  await s.driver.saveDirectory({ upserts: entries, deletes: [],
                                 touched: realmIds, removedRealms: [] });
  const realms = [{ id: 'acme', name: 'Acme', description: 'a realm',
                    createdAt: 1767225600000, domain: 'acme.example',
                    overrides: { 'saml.organizationName': 'Acme Org',
                                 'oauth2.accessTokenTtlS': 900 },
                    retiringSince: null }];
  await s.driver.saveRealms(realms);
  const overrides = { 'saml.organizationDisplayName': 'Node wrote this',
                      'scheduler.tickS': 20 };
  await s.driver.saveOverrides(overrides);
  const sealed = [['minted-rows', ''], ['authn-sessions', 'acme'],
                  ['totp-secret', '']].map(function (pair) {
    const text = 'sealed by Node for ' + pair[0] + ' in [' + pair[1] + '] é';
    return { label: pair[0], realm: pair[1], text: text,
             cipher: s.keystore.seal(text, pair[0], 'cell',
                                     { realm: pair[1] }) };
  });
  const digests = ['directory-index', 'cluster-fingerprint'].map(function (l) {
    return { label: l, text: 'name\nalice',
             digest: s.keystore.keyedDigest(l, 'name\nalice') };
  });
  await s.keystore.settleDeks();
  await s.keystore.settleAll();
  const rows = await storedRows();
  const keyRows = await raw('SELECT realm FROM sts_keys ORDER BY realm');
  const out = { entries: entries, realms: realms, overrides: overrides,
                signing: { kid: set.kid, certB64: certB64 },
                sealed: sealed, digests: digests,
                columns: rows.map(columnsOf),
                keyRows: keyRows.rows.map(function (r) { return r.realm; }) };
  fs.writeFileSync(path.join(DIR, 'interop-node.json'),
                   JSON.stringify(out, null, 1) + '\n');
  await s.driver.close();
  console.log('store-interop: Node wrote ' + rows.length + ' entries, ' +
              realms.length + ' realm(s), ' + Object.keys(overrides).length +
              ' override(s) and ' + out.keyRows.length + ' key row(s).');
  log.debug('Leaving write().');
}

/**
 * Reads a store the Rust runtime wrote, and checks it against what Rust
 * says it wrote.
 *
 * @returns {Promise<number>} how many checks failed
 */
async function read() {
  log.debug('Entering read().');
  const want = JSON.parse(fs.readFileSync(path.join(DIR, 'interop-rust.json'),
                                          'utf8'));
  const s = await started();
  const failures = [];
  let checked = 0;
  const check = function (ok, what) {
    log.debug('Entering check().');
    checked += 1;
    if (!ok) {
      failures.push(what);
    }
    log.debug('Leaving check().');
  };
  const same = function (a, b) {
    log.debug('Entering same().');
    log.debug('Leaving same().');
    return JSON.stringify(a) === JSON.stringify(b);
  };
  // Key order aside, which jsonb does not keep.
  const canonical = function (v) {
    log.debug('Entering canonical().');
    let out;
    if (Array.isArray(v)) {
      out = '[' + v.map(canonical).join(',') + ']';
    } else if (v && typeof v === 'object') {
      out = '{' + Object.keys(v).sort().map(function (k) {
        return JSON.stringify(k) + ':' + canonical(v[k]);
      }).join(',') + '}';
    } else {
      out = JSON.stringify(v);
    }
    log.debug('Leaving canonical().');
    return out;
  };
  const directory = await s.driver.loadDirectory() || {};
  want.entries.forEach(function (one) {
    const got = (directory[one.realm] || []).filter(function (e) {
      return e.dn === one.entry.dn;
    })[0];
    check(!!got && same(got.attributes, one.entry.attributes) &&
          (got.origin || null) === (one.entry.origin || null),
          'the entry ' + one.key + ' in "' + one.realm + '" reads back ' +
          'as Rust wrote it: ' + JSON.stringify(got));
  });
  const rows = await storedRows();
  check(rows.length === want.entries.length,
        rows.length + ' rows stored, ' + want.entries.length + ' written');
  rows.forEach(function (row) {
    const attrs = s.codec.openAttributes(row.dn_key, row.attrs);
    check(typeof row.attrs === 'string',
          row.dn_key + ' is sealed, as a durable key requires');
    if (!attrs) {
      check(false, row.dn_key + ' opens in Node');
      return;
    }
    const index = s.codec.index(attrs);
    const mine = { nameKeys: index.nameKeys, mailKeys: index.mailKeys,
                   uuidKeys: index.uuidKeys, classKeys: index.classKeys,
                   valueKeys: index.valueKeys, attrNames: index.attrNames,
                   dekKeys: s.codec.dekKeys(attrs, row.attrs) };
    const theirs = columnsOf(row);
    Object.keys(mine).forEach(function (k) {
      // `dek_keys` is an object, and jsonb keeps no key order.
      check(k === 'dekKeys' ? canonical(mine[k]) === canonical(theirs[k])
        : same(mine[k], theirs[k]),
            row.dn_key + ' ' + k + ': Rust stored ' +
            JSON.stringify(theirs[k]) + ', Node computes ' +
            JSON.stringify(mine[k]));
    });
  });
  const realms = await s.driver.loadRealms() || [];
  check(canonical(realms) === canonical(want.realms),
        'the realms read back as Rust wrote them: ' + JSON.stringify(realms));
  const overrides = await s.driver.loadOverrides() || {};
  check(canonical(overrides) === canonical(want.overrides),
        'the overrides read back: ' + JSON.stringify(overrides));
  want.sealed.forEach(function (one) {
    check(s.keystore.open(one.cipher, one.label) === one.text,
          'a "' + one.label + '" value Rust sealed opens in Node');
  });
  want.digests.forEach(function (one) {
    check(s.keystore.keyedDigest(one.label, one.text) === one.digest,
          'the "' + one.label + '" digest is Node\'s');
  });
  // The default realm's set as the service asks for it: the stored one
  // where it opens (a new one would carry another kid).
  const set = require(path.join(ROOT, 'common', 'helpers.js')).stsKeysFor();
  check(!!set && set.kid === want.signing.kid,
        'the signing key set Rust stored is the one Node reads: ' +
        (set ? set.kid : 'none'));
  await s.driver.close();
  failures.forEach(function (f) {
    console.error('store-interop: DIFFERS: ' + f);
  });
  console.log('store-interop: Node read what Rust wrote; ' +
              (checked - failures.length) + ' of ' + checked + ' agree.');
  log.debug('Leaving read().');
  return failures.length;
}

if (require.main === module) {
  if (!URL || !DIR || (MODE !== 'write' && MODE !== 'read')) {
    console.error('usage: STS_TEST_DATABASE_URL=… node ' +
                  'tests/tools/store-interop.js write|read <dir>');
    process.exitCode = 2;
  } else {
    (MODE === 'write' ? write().then(function () { return 0; }) : read())
      .then(function (failed) {
        process.exitCode = failed ? 1 : 0;
        // The keystore's purge timers would keep a finished run alive.
        setImmediate(function () {
          process.exit(process.exitCode);
        });
      }, function (e) {
        console.error(e);
        process.exit(1);
      });
  }
}
