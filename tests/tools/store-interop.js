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
// BOTH ENGINES AND THE SIDE TABLES (#444, phase 3): the store is either
// engine, by the URL's scheme (`postgres://`, or `mariadb://` for #677), and
// each half also writes and checks what a minted flush keeps beside the
// sealed bodies — `sts_sessions` (#350) computed from the session the way
// `authn.ts`'s sessionIndexOf() computes it, `sts_minted_index` (#820) and
// its sort row, the change log's minted keys, the directory's kept counts
// (`sts_ldap_counts`, `sts_ldap_dek_counts`: the triggers on PostgreSQL,
// the writer on MariaDB), MariaDB's `sts_ldap_entry_keys`, and the stable
// origin claim with its fence lock (#617) — each field for field against
// what the other side computes from the same plaintext.
//
// The database is STS_TEST_DATABASE_URL; its server certificate is not
// verified (a throwaway container's). <dir> is never committed: it holds a
// key-encryption key. On MariaDB `mysql2` is the tests' (NODE_PATH=
// tests/node_modules).
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
const ENGINE = /^(mariadb|mysql):/i.test(URL) ? 'mariadb' : 'postgres';
const TABLES = ['sts_ldap_entries', 'sts_realms', 'sts_appconfig', 'sts_keys',
                'sts_changes', 'sts_minted', 'sts_sessions',
                'sts_minted_index', 'sts_ldap_counts', 'sts_ldap_dek_counts',
                'sts_cluster_claims', 'sts_cluster_locks']
  .concat(ENGINE === 'mariadb' ? ['sts_ldap_entry_keys'] : []);

// The minted rows a run writes beside the directory: two sign-on sessions
// (one a relying party's, one keyed and partnered), one session written
// and then ended, and a row of an on-demand store with lookups and a sort
// value.
const SESSIONS = 'authn.sessions';
const INDEXED = 'interop.indexed';
// The stable names each half adopts and leaves held (#617).
const NODE_ORIGIN = 'interop-node';
const RUST_ORIGIN = 'interop-rust';

/**
 * A query against the store, outside the driver, for the raw columns.
 *
 * @param {string} sql - the statement
 * @param {Array<any>} [params] - its parameters
 * @returns {Promise<any>} the result
 */
async function raw(sql, params) {
  log.debug('Entering raw().');
  if (ENGINE === 'mariadb') {
    const mysql = require('mysql2/promise');
    const u = new globalThis.URL(URL.replace(/^(mariadb|mysql):/i, 'http:'));
    const connection = await mysql.createConnection({
      host: u.hostname, port: Number(u.port) || 3306,
      user: decodeURIComponent(u.username),
      password: decodeURIComponent(u.password),
      database: decodeURIComponent(u.pathname.slice(1)),
      ssl: { rejectUnauthorized: false }, timezone: 'Z',
      supportBigNumbers: true, bigNumberStrings: true });
    try {
      const [rows] = await connection.query(sql.replace(/\$\d+/g, '?'),
                                            params || []);
      log.debug('Leaving raw().');
      return { rows: Array.isArray(rows) ? rows : [] };
    } finally {
      await connection.end();
    }
  }
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
 * A JSON column as a value: MariaDB answers its text.
 *
 * @param {any} v - the column
 * @returns {any} the value
 */
function json(v) {
  log.debug('Entering json().');
  if (ENGINE !== 'mariadb' || typeof v !== 'string') {
    log.debug('Leaving json().');
    return v;
  }
  try {
    log.debug('Leaving json(). Parsed.');
    return JSON.parse(v);
  } catch (e) {
    log.debug('Caught in json(): ' + ((e && e.message) || e));
    log.debug('Leaving json().');
    return v;
  }
}

/**
 * A column holding a number, as a number or null.
 *
 * @param {any} v - the column
 * @returns {number|null} the number
 */
function num(v) {
  log.debug('Entering num().');
  log.debug('Leaving num().');
  return v === null || v === undefined ? null : Number(v);
}

/**
 * `authn/authn.ts`'s sessionIndexOf(), which that module does not export:
 * the columns `sts_sessions` holds for one session. Copied as it stands;
 * a change there is a change here.
 *
 * @param {any} keystore - the started keystore
 * @param {any} value - the session
 * @returns {any} the columns, or null
 */
function sessionIndexOf(keystore, value) {
  log.debug('Entering sessionIndexOf().');
  if (!value || typeof value !== 'object') {
    log.debug('Leaving sessionIndexOf(). Not a session.');
    return null;
  }
  const subjectId = value.subjectId == null ? '' : String(value.subjectId);
  const subjectKey = keystore.keyedDigest('session-subject', subjectId);
  let username = '';
  if (value.user && typeof value.user === 'object' &&
      value.user.username != null) {
    username = String(value.user.username);
  }
  const usernameKey = keystore.keyedDigest('session-username', username);
  const parentSid = value.derivedFrom ? String(value.derivedFrom) : '';
  const parentKey = parentSid
    ? keystore.keyedDigest('session-parent', parentSid) : '';
  if (!subjectKey || !usernameKey || parentKey === null) {
    log.debug('Leaving sessionIndexOf(). No digest.');
    return null;
  }
  const credentialKey = value.credentialKey ? String(value.credentialKey)
    : '';
  let kind = 'sign-on';
  if (parentSid) {
    kind = 'relying-party';
  } else if (credentialKey) {
    kind = 'keyed';
  } else if (value.chosen === false) {
    kind = 'arrival';
  }
  const partner = value.fedPartnerSession;
  let relationship = '';
  if (partner && typeof partner === 'object' && partner.relationship) {
    relationship = String(partner.relationship);
  }
  const expires = Number(value.expires);
  const lastSeen = Number(value.lastSeenAt);
  const started = Number(value.startedAt);
  log.debug('Leaving sessionIndexOf().');
  return {
    expiresAt: Number.isFinite(expires) && expires > 0
      ? Math.floor(expires) : null,
    lastSeenAt: Number.isFinite(lastSeen) ? Math.max(0, Math.floor(lastSeen))
      : 0,
    startedAt: Number.isFinite(started) ? Math.max(0, Math.floor(started))
      : 0,
    subjectKey: subjectKey, usernameKey: usernameKey,
    chosen: value.chosen !== false,
    authenticated: value.authenticated !== false, kind: kind,
    rpSurface: value.rpSurface ? String(value.rpSurface) : '',
    parentKey: parentKey, backsConsole: value.backsConsole === true,
    credentialKey: credentialKey, partnerRelationship: relationship
  };
}

/**
 * The minted rows a run writes, as plaintext: the sessions, the session
 * ended after it was written, and the indexed row.
 *
 * @param {string} who - 'Node' or 'Rust', inside the values
 * @returns {any} `{ sessions, ended, indexed }`
 */
function mintedToWrite(who) {
  log.debug('Entering mintedToWrite().');
  const out = {
    sessions: [
      { realm: 'default', key: 'sid-' + who + '-1', value: {
        subjectId: 'urn:uuid:0f8a2c6e-1111-4222-8333-944455556666',
        user: { username: 'alice' }, expires: 1893456000123.9,
        lastSeenAt: 1767225600456, startedAt: 1767225600000,
        authenticated: true, rpSurface: 'portal', backsConsole: true,
        written: who } },
      { realm: 'acme', key: 'sid-' + who + '-2', value: {
        subjectId: 'urn:uuid:7d9e0000-1111-4222-8333-944455556666',
        user: { username: 'Dave Ünïcode' }, derivedFrom: 'sid-parent',
        credentialKey: 'cred-1', chosen: false,
        fedPartnerSession: { relationship: 'partner-1' },
        lastSeenAt: '1767225600789', written: who } }
    ],
    ended: { realm: 'default', key: 'sid-' + who + '-ended',
             value: { subjectId: 'urn:uuid:ended', user: { username: 'x' },
                      written: who } },
    indexed: { realm: 'acme', key: 'row-' + who, value: { who: who },
               lookups: ['alpha', 'Béta', 'alpha'],
               sortAt: 1767225600123 }
  };
  log.debug('Leaving mintedToWrite().');
  return out;
}

/**
 * The side tables as the database holds them, normalised across engines.
 *
 * @returns {Promise<any>} the rows
 */
async function sideRows() {
  log.debug('Entering sideRows().');
  const sessions = (await raw('SELECT * FROM sts_sessions ORDER BY realm, ' +
    (ENGINE === 'mariadb' ? '`key`' : 'key'))).rows.map(function (r) {
    return { realm: r.realm, key: r.key, expiresAt: num(r.expires_at),
             lastSeenAt: num(r.last_seen_at), startedAt: num(r.started_at),
             subjectKey: r.subject_key, usernameKey: r.username_key,
             chosen: !!Number(r.chosen === true ? 1 : r.chosen),
             authenticated: !!Number(r.authenticated === true ? 1
               : r.authenticated),
             kind: r.kind, rpSurface: r.rp_surface, parentKey: r.parent_key,
             backsConsole: !!Number(r.backs_console === true ? 1
               : r.backs_console),
             credentialKey: r.credential_key,
             partnerRelationship: r.partner_relationship };
  });
  const index = (await raw('SELECT * FROM sts_minted_index')).rows
    .map(function (r) {
      return [r.handle, r.realm, r.index_key, r.key,
              num(r.sort_at)].join('|');
    }).sort();
  const counts = {};
  (await raw('SELECT realm, base_key, attribute, n FROM sts_ldap_counts'))
    .rows.forEach(function (r) {
      const id = [r.realm, r.base_key, r.attribute].join('|');
      counts[id] = (counts[id] || 0) + Number(r.n);
    });
  Object.keys(counts).forEach(function (id) {
    if (!counts[id]) {
      delete counts[id];
    }
  });
  const dekCounts = {};
  (await raw('SELECT dek_id, n FROM sts_ldap_dek_counts')).rows
    .forEach(function (r) {
      dekCounts[r.dek_id] = (dekCounts[r.dek_id] || 0) + Number(r.n);
    });
  Object.keys(dekCounts).forEach(function (id) {
    if (!dekCounts[id]) {
      delete dekCounts[id];
    }
  });
  const entryKeys = ENGINE === 'mariadb'
    ? (await raw('SELECT realm, kind, k, dn_key FROM sts_ldap_entry_keys'))
      .rows.map(function (r) {
        return [r.realm, r.kind, r.k, r.dn_key].join('|');
      }).sort()
    : [];
  const changes = (await raw('SELECT kind, realm, ' +
    (ENGINE === 'mariadb' ? '`key`' : 'key') + ' AS k FROM sts_changes ' +
    'WHERE kind LIKE \'minted%\' ORDER BY seq')).rows.map(function (r) {
    return [r.kind, r.realm, r.k].join('|');
  });
  const claims = (await raw('SELECT ' +
    (ENGINE === 'mariadb' ? '`key`' : 'key') + ' AS k, reservation, ' +
    'origin FROM sts_cluster_claims WHERE scope = \'persistence.origin\''))
    .rows.map(function (r) {
      return { key: r.k, reservation: r.reservation, origin: r.origin };
    });
  const locks = (await raw('SELECT name FROM sts_cluster_locks')).rows
    .map(function (r) {
      return r.name;
    }).sort();
  log.debug('Leaving sideRows().');
  return { sessions: sessions, index: index, counts: counts,
           dekCounts: dekCounts, entryKeys: entryKeys, changes: changes,
           claims: claims, locks: locks };
}

/**
 * The counts the stored entries call for (`directory_portable.js`'s
 * contribute() over every row; the triggers' sum on PostgreSQL).
 *
 * @param {Array<any>} rows - storedRows()
 * @returns {any} `{ counts, dekCounts }`
 */
function countsCalledFor(rows) {
  log.debug('Entering countsCalledFor().');
  const queries = require(path.join(ROOT, 'persistence',
                                    'directory_queries.js'));
  const portable = require(path.join(ROOT, 'persistence',
                                     'directory_portable.js'));
  const counts = {};
  const dekCounts = {};
  rows.forEach(function (row) {
    const names = row.attr_names || [];
    const held = queries.COUNTED_ATTRIBUTES.filter(function (a) {
      return names.indexOf(a) >= 0;
    });
    portable.basesOf(queries.parentOf(row.dn_key)).forEach(function (base) {
      [''].concat(held).forEach(function (attribute) {
        const id = [row.realm, base, attribute].join('|');
        counts[id] = (counts[id] || 0) + 1;
      });
    });
    Object.keys(row.dek_keys || {}).forEach(function (id) {
      dekCounts[id] = (dekCounts[id] || 0) + Number(row.dek_keys[id]);
    });
  });
  log.debug('Leaving countsCalledFor().');
  return { counts: counts, dekCounts: dekCounts };
}

/**
 * MariaDB's key rows the stored entries call for (`entryWrite()`).
 *
 * @param {any} codec - the directory codec
 * @param {Array<any>} rows - storedRows()
 * @returns {Array<string>} `realm|kind|k|dn_key`, sorted
 */
function keyRowsCalledFor(codec, rows) {
  log.debug('Entering keyRowsCalledFor().');
  const queries = require(path.join(ROOT, 'persistence',
                                    'directory_queries.js'));
  const mariadbQueries = require(path.join(ROOT, 'persistence',
                                           'directory_queries_mariadb.js'));
  const out = new Set();
  rows.forEach(function (row) {
    const attrs = codec.openAttributes(row.dn_key, row.attrs) || {};
    const index = codec.index(attrs);
    const add = function (kind, k) {
      out.add([row.realm, kind, mariadbQueries.tableKey(k),
               row.dn_key].join('|'));
    };
    [['name', index.nameKeys], ['mail', index.mailKeys],
     ['uuid', index.uuidKeys], ['class', index.classKeys],
     ['value', index.valueKeys]].forEach(function (pair) {
      (pair[1] || []).forEach(function (k) {
        add(pair[0], k);
      });
    });
    (index.attrNames || []).forEach(function (name) {
      if (queries.ASKED_ATTRIBUTES.indexOf(name) >= 0) {
        add('attr', name);
      }
    });
    Object.keys(row.dek_keys || {}).forEach(function (id) {
      add('dek', id);
    });
  });
  log.debug('Leaving keyRowsCalledFor().');
  return Array.from(out).sort();
}

/**
 * The index rows an indexed row calls for (`indexKeyOf()`, its sort row).
 *
 * @param {any} keystore - the started keystore
 * @param {any} one - mintedToWrite().indexed
 * @param {string} key - its key column
 * @returns {Array<string>} `handle|realm|index_key|key|sort_at`, sorted
 */
function indexRowsCalledFor(keystore, one, key) {
  log.debug('Entering indexRowsCalledFor().');
  const out = new Set();
  one.lookups.forEach(function (v) {
    out.add([INDEXED, one.realm, keystore.keyedDigest('minted-index',
      INDEXED + '\n' + one.realm + '\n' + v), key, null].join('|'));
  });
  out.add([INDEXED, one.realm, '$sort$', key, one.sortAt].join('|'));
  log.debug('Leaving indexRowsCalledFor().');
  return Array.from(out).sort();
}

/**
 * `mintedChangeRow()`'s key for a row.
 *
 * @param {string} handle - the store
 * @param {string} key - the key column
 * @returns {string} the change log's key
 */
function mintedChangeKey(handle, key) {
  log.debug('Entering mintedChangeKey().');
  log.debug('Leaving mintedChangeKey().');
  return Buffer.from(handle, 'utf8').toString('base64url') + '.' +
    Buffer.from(key, 'utf8').toString('base64url');
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
    .create({ url: URL, log: log, engine: ENGINE });
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
  return result.rows.map(function (row) {
    ['attrs', 'name_keys', 'mail_keys', 'uuid_keys', 'class_keys',
     'value_keys', 'attr_names', 'dek_keys'].forEach(function (c) {
      row[c] = json(row[c]);
    });
    return row;
  });
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
  // THE STABLE ORIGIN, held while Node writes, so every write below passes
  // its fence, and left held for Rust to find (#617).
  const adopted = await s.driver.adoptOrigin({ name: NODE_ORIGIN,
                                               ttlMs: 120000, waitMs: 0 });
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
  // THE MINTED ROWS AND THEIR SIDE TABLES, as persistence_minted.js hands
  // them to the driver: the session index from sessionIndexOf(), the
  // indexed row's lookups digested by indexKeyOf(), and an ended session.
  const minted = mintedToWrite('Node');
  const upsertOf = function (handle, one, extra) {
    return Object.assign({ handle: handle, realm: one.realm, key: one.key,
      keySealed: '', journalKey: one.key,
      body: s.keystore.seal(JSON.stringify(one.value), 'minted-rows',
                            'cell', { realm: one.realm }),
      expiresAt: null, own: false, tombstone: handle === SESSIONS }, extra);
  };
  await s.driver.saveMinted(minted.sessions.concat([minted.ended])
    .map(function (one) {
      return upsertOf(SESSIONS, one,
                      { index: sessionIndexOf(s.keystore, one.value) });
    }).concat([upsertOf(INDEXED, minted.indexed, {
      lookups: Array.from(new Set(minted.indexed.lookups)).map(function (v) {
        return s.keystore.keyedDigest('minted-index', INDEXED + '\n' +
                                      minted.indexed.realm + '\n' + v);
      }), sortAt: minted.indexed.sortAt })]), []);
  await s.driver.saveMinted([], [{ handle: SESSIONS,
    realm: minted.ended.realm, key: minted.ended.key, keySealed: '',
    journalKey: minted.ended.key, own: false, tombstone: true }]);
  const rows = await storedRows();
  const keyRows = await raw('SELECT realm FROM sts_keys ORDER BY realm');
  const out = { engine: ENGINE, entries: entries, realms: realms,
                overrides: overrides,
                signing: { kid: set.kid, certB64: certB64 },
                sealed: sealed, digests: digests,
                columns: rows.map(columnsOf),
                keyRows: keyRows.rows.map(function (r) { return r.realm; }),
                minted: minted, origin: adopted,
                side: await sideRows() };
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
  // THE SIDE TABLES RUST KEPT, against what Node computes from the same
  // plaintext.
  const side = await sideRows();
  const minted = want.minted;
  const sessions = minted.sessions;
  const bodies = await s.driver.readMintedMany(sessions.map(function (one) {
    return { handle: SESSIONS, realm: one.realm, key: one.key };
  }).concat([{ handle: SESSIONS, realm: minted.ended.realm,
               key: minted.ended.key }]));
  check(bodies.length === sessions.length,
        bodies.length + ' live sessions read back, ' + sessions.length +
        ' written (the ended one is a tombstone)');
  sessions.forEach(function (one) {
    const body = bodies.filter(function (b) {
      return b.realm === one.realm && b.key === one.key;
    })[0];
    const opened = body ? s.keystore.open(body.body, 'minted-rows') : null;
    check(!!opened && canonical(JSON.parse(opened)) ===
          canonical(one.value), 'the session ' + one.key + ' opens in Node');
    const row = side.sessions.filter(function (r) {
      return r.realm === one.realm && r.key === one.key;
    })[0];
    const mine = Object.assign({ realm: one.realm, key: one.key },
                               sessionIndexOf(s.keystore, one.value));
    check(!!row && canonical(row) === canonical(mine),
          'sts_sessions ' + one.key + ': Rust stored ' + JSON.stringify(row) +
          ', Node computes ' + JSON.stringify(mine));
  });
  check(side.sessions.length === sessions.length,
        'sts_sessions holds ' + side.sessions.length + ' rows, the ended ' +
        'session\'s gone');
  const filedIndex = indexRowsCalledFor(s.keystore, minted.indexed,
                                        minted.indexed.key);
  check(same(side.index, filedIndex), 'sts_minted_index: Rust filed ' +
        JSON.stringify(side.index) + ', Node computes ' +
        JSON.stringify(filedIndex));
  const changeKeys = sessions.concat([minted.ended]).map(function (one) {
    return 'minted|' + one.realm + '|' + mintedChangeKey(SESSIONS, one.key);
  }).concat(['minted|' + minted.indexed.realm + '|' +
             mintedChangeKey(INDEXED, minted.indexed.key)]);
  changeKeys.forEach(function (k) {
    check(side.changes.indexOf(k) >= 0, 'the change log names ' + k);
  });
  const called = countsCalledFor(rows);
  check(canonical(side.counts) === canonical(called.counts),
        'sts_ldap_counts: the store holds ' + JSON.stringify(side.counts) +
        ', the entries call for ' + JSON.stringify(called.counts));
  check(canonical(side.dekCounts) === canonical(called.dekCounts),
        'sts_ldap_dek_counts: ' + JSON.stringify(side.dekCounts) + ' vs ' +
        JSON.stringify(called.dekCounts));
  if (ENGINE === 'mariadb') {
    const keyed = keyRowsCalledFor(s.codec, rows);
    check(same(side.entryKeys, keyed), 'sts_ldap_entry_keys: Rust wrote ' +
          side.entryKeys.length + ' rows, Node computes ' + keyed.length +
          ': ' + JSON.stringify(side.entryKeys.filter(function (k) {
            return keyed.indexOf(k) < 0;
          })) + ' / ' + JSON.stringify(keyed.filter(function (k) {
            return side.entryKeys.indexOf(k) < 0;
          })));
  }
  // THE ORIGIN RUST HOLDS: its claim and the fence lock named with its
  // reservation, in Node's form, and refused to Node while it is held.
  const held = side.claims.filter(function (c) {
    return c.key === 'n:' + RUST_ORIGIN;
  })[0];
  check(!!held && side.locks.indexOf('fence:origin:n:' + RUST_ORIGIN + ':' +
                                     held.reservation) >= 0,
        'Rust\'s origin claim and its fence lock: ' + JSON.stringify(held) +
        ' ' + JSON.stringify(side.locks));
  const refused = await s.driver.adoptOrigin({ name: RUST_ORIGIN,
                                               ttlMs: 30000, waitMs: 0 });
  check(!refused.adopted, 'Node is refused the origin Rust holds: ' +
        JSON.stringify(refused));
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
